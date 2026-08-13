//! Mission-scoped pending plugin approval projection and decision seam.
//!
//! The projection is deliberately content-free. It binds one durable request
//! event to the exact Project/Mission, plugin identity, invocation, Effect
//! approval digest, and source revisions that were read before the user
//! decision. The provider only reads the existing Application event spine.
//! The consumer owns lifecycle and selection state, while the Application
//! command calls the existing Effect/Consent authorities and commits the
//! resulting Mission mutation plus Event/Outbox in one fenced transaction.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ActorId, Approval, ApprovalDecision, ApprovalId, EffectId, EffectStatus, Mission, MissionError,
    ProjectId, TenantId,
};
use hartevo_effect_broker::{BrokerError, EffectBroker};
use hartevo_storage::{
    ApplicationSourceKind, ApplicationSourceRevisionFence, DomainEventRecord, PendingEvent,
    ProjectStore, StorageError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ApplicationService;

pub const PENDING_PLUGIN_APPROVAL_REQUEST_EVENT: &str = "plugin.approval.requested";
pub const PENDING_PLUGIN_APPROVAL_DECISION_EVENT: &str = "plugin.approval.decided";

const REQUEST_SCHEMA: &str = "hartevo.pending-plugin-approval-request/v1";
const DECISION_SCHEMA: &str = "hartevo.pending-plugin-approval-decision/v1";
const DIGEST_HEX_LENGTH: usize = 64;

const REQUEST_KEYS: &[&str] = &[
    "schema",
    "tenantId",
    "projectId",
    "missionId",
    "pluginId",
    "pluginVersion",
    "pluginDigest",
    "invocationId",
    "invocationDigest",
    "effectId",
    "effectDigest",
    "expectedMissionRevision",
    "expectedEffectRevision",
    "expectedConsentRevision",
    "requestDigest",
];

const DECISION_KEYS: &[&str] = &[
    "schema",
    "requestEventSequence",
    "requestDigest",
    "decision",
    "actorId",
    "resultMissionRevision",
    "resultEffectStatus",
    "decisionDigest",
];

#[allow(
    clippy::struct_field_names,
    reason = "the scope contract deliberately names each exact identity dimension"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingPluginApprovalScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: hartevo_domain_kernel::MissionId,
}

impl PendingPluginApprovalScope {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: hartevo_domain_kernel::MissionId,
    ) -> Result<Self, PendingPluginApprovalError> {
        let scope = Self {
            tenant_id,
            project_id,
            mission_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &hartevo_domain_kernel::MissionId {
        &self.mission_id
    }

    fn validate(&self) -> Result<(), PendingPluginApprovalError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
        {
            return Err(PendingPluginApprovalError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingPluginApprovalLifecycle {
    Mounted,
    Unmounted,
    Revoked,
}

impl PendingPluginApprovalLifecycle {
    const fn is_active(self) -> bool {
        matches!(self, Self::Mounted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingPluginApprovalState {
    Pending,
    Approved,
    Denied,
    Stale,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingPluginApprovalDecision {
    Approve,
    Deny,
}

impl PendingPluginApprovalDecision {
    const fn effect_status(self) -> EffectStatus {
        match self {
            Self::Approve => EffectStatus::Approved,
            Self::Deny => EffectStatus::Rejected,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }

    fn parse(value: &str) -> Result<Self, PendingPluginApprovalError> {
        match value {
            "approve" => Ok(Self::Approve),
            "deny" => Ok(Self::Deny),
            _ => Err(PendingPluginApprovalError::TamperedDecisionEvent),
        }
    }
}

/// Exact source revisions captured by the read projection.
///
/// Effects are children of the Mission aggregate and do not have an
/// independent normalized revision in the current Domain contract. Therefore
/// `effect_revision` is the Mission revision at which this Effect approval
/// request was observed; the transaction fences that aggregate revision and
/// the immutable invocation event sequence together.
#[allow(
    clippy::struct_field_names,
    reason = "the read contract deliberately exposes each exact source revision"
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingPluginApprovalRevisions {
    mission_revision: u64,
    effect_revision: u64,
    invocation_revision: u64,
    consent_revision: Option<u64>,
}

impl PendingPluginApprovalRevisions {
    pub const fn mission_revision(self) -> u64 {
        self.mission_revision
    }

    pub const fn effect_revision(self) -> u64 {
        self.effect_revision
    }

    pub const fn invocation_revision(self) -> u64 {
        self.invocation_revision
    }

    pub const fn consent_revision(self) -> Option<u64> {
        self.consent_revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingPluginApprovalProjection {
    scope: PendingPluginApprovalScope,
    state: PendingPluginApprovalState,
    plugin_id: String,
    plugin_version: String,
    plugin_digest: String,
    invocation_id: String,
    invocation_digest: String,
    effect_id: EffectId,
    effect_digest: String,
    request_digest: String,
    request_event_sequence: u64,
    revisions: PendingPluginApprovalRevisions,
    current_mission_revision: u64,
    projection_digest: String,
}

impl PendingPluginApprovalProjection {
    pub fn scope(&self) -> &PendingPluginApprovalScope {
        &self.scope
    }

    pub const fn state(&self) -> PendingPluginApprovalState {
        self.state
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn plugin_digest(&self) -> &str {
        &self.plugin_digest
    }

    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    pub fn effect_id(&self) -> &EffectId {
        &self.effect_id
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn request_event_sequence(&self) -> u64 {
        self.request_event_sequence
    }

    pub const fn revisions(&self) -> PendingPluginApprovalRevisions {
        self.revisions
    }

    pub const fn current_mission_revision(&self) -> u64 {
        self.current_mission_revision
    }

    pub fn projection_digest(&self) -> &str {
        &self.projection_digest
    }

    fn command(
        &self,
        decision: PendingPluginApprovalDecision,
        actor_id: ActorId,
    ) -> PendingPluginApprovalDecisionCommand {
        PendingPluginApprovalDecisionCommand {
            scope: self.scope.clone(),
            plugin_id: self.plugin_id.clone(),
            plugin_version: self.plugin_version.clone(),
            plugin_digest: self.plugin_digest.clone(),
            invocation_id: self.invocation_id.clone(),
            invocation_digest: self.invocation_digest.clone(),
            effect_id: self.effect_id.clone(),
            effect_digest: self.effect_digest.clone(),
            request_digest: self.request_digest.clone(),
            request_event_sequence: self.request_event_sequence,
            expected_mission_revision: self.revisions.mission_revision,
            expected_effect_revision: self.revisions.effect_revision,
            expected_consent_revision: self.revisions.consent_revision,
            decision,
            actor_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPluginApprovalRequest {
    pub scope: PendingPluginApprovalScope,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_digest: String,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub effect_id: EffectId,
    pub effect_digest: String,
    pub expected_mission_revision: u64,
    pub expected_effect_revision: u64,
    pub expected_consent_revision: Option<u64>,
}

impl PendingPluginApprovalRequest {
    pub fn request_digest(&self) -> Result<String, PendingPluginApprovalError> {
        self.validate_shape()?;
        digest_json(&self.canonical_value())
    }

    fn validate_shape(&self) -> Result<(), PendingPluginApprovalError> {
        self.scope.validate()?;
        if self.plugin_id.trim().is_empty()
            || self.plugin_version.trim().is_empty()
            || self.invocation_id.trim().is_empty()
            || self.effect_id.as_str().trim().is_empty()
            || self.expected_mission_revision == 0
            || self.expected_effect_revision == 0
            || self.expected_mission_revision != self.expected_effect_revision
            || !is_digest(&self.plugin_digest)
            || !is_digest(&self.invocation_digest)
            || !is_digest(&self.effect_digest)
            || self
                .expected_consent_revision
                .is_some_and(|revision| revision == 0)
        {
            return Err(PendingPluginApprovalError::InvalidRequest);
        }
        Ok(())
    }

    fn canonical_value(&self) -> Value {
        serde_json::json!({
            "schema": REQUEST_SCHEMA,
            "tenantId": &self.scope.tenant_id,
            "projectId": &self.scope.project_id,
            "missionId": &self.scope.mission_id,
            "pluginId": &self.plugin_id,
            "pluginVersion": &self.plugin_version,
            "pluginDigest": &self.plugin_digest,
            "invocationId": &self.invocation_id,
            "invocationDigest": &self.invocation_digest,
            "effectId": &self.effect_id,
            "effectDigest": &self.effect_digest,
            "expectedMissionRevision": self.expected_mission_revision,
            "expectedEffectRevision": self.expected_effect_revision,
            "expectedConsentRevision": self.expected_consent_revision,
        })
    }

    fn event_payload(&self, request_digest: &str) -> Value {
        let mut payload = self.canonical_value();
        payload["requestDigest"] = Value::String(request_digest.to_owned());
        payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPluginApprovalDecisionCommand {
    pub scope: PendingPluginApprovalScope,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_digest: String,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub effect_id: EffectId,
    pub effect_digest: String,
    pub request_digest: String,
    pub request_event_sequence: u64,
    pub expected_mission_revision: u64,
    pub expected_effect_revision: u64,
    pub expected_consent_revision: Option<u64>,
    pub decision: PendingPluginApprovalDecision,
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPluginApprovalDecisionResult {
    pub projection: PendingPluginApprovalProjection,
    pub committed_mission_revision: u64,
    pub decision_event_sequence: u64,
    pub decision_outbox_sequence: Option<i64>,
    pub replayed: bool,
}

/// Mission-scoped service handle. It contains no Store or Effect authority;
/// those are supplied only to the provider/decision command at the boundary.
#[derive(Clone)]
pub struct PendingPluginApprovalService {
    scope: PendingPluginApprovalScope,
    request_event_sequence: u64,
    request_digest: String,
    lifecycle: PendingPluginApprovalLifecycle,
}

impl fmt::Debug for PendingPluginApprovalService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPluginApprovalService")
            .field("scope", &self.scope)
            .field("request_event_sequence", &self.request_event_sequence)
            .field("request_digest", &self.request_digest)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

impl PendingPluginApprovalService {
    fn from_record(record: &RequestRecord) -> Self {
        Self {
            scope: record.request.scope.clone(),
            request_event_sequence: record.event_sequence,
            request_digest: record.request_digest.clone(),
            lifecycle: PendingPluginApprovalLifecycle::Mounted,
        }
    }

    pub fn scope(&self) -> &PendingPluginApprovalScope {
        &self.scope
    }

    pub const fn request_event_sequence(&self) -> u64 {
        self.request_event_sequence
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn lifecycle(&self) -> PendingPluginApprovalLifecycle {
        self.lifecycle
    }

    pub const fn is_active(&self) -> bool {
        self.lifecycle.is_active()
    }

    pub fn provider<'a>(
        &'a self,
        application: &'a ApplicationService,
    ) -> PendingPluginApprovalProvider<'a> {
        PendingPluginApprovalProvider {
            application,
            service: self,
        }
    }

    pub fn into_mission_shell_consumer(self) -> PendingPluginApprovalMissionShellConsumer {
        PendingPluginApprovalMissionShellConsumer {
            service: self,
            active_projection: None,
        }
    }
}

/// Read-only provider for one exact request event.
pub struct PendingPluginApprovalProvider<'a> {
    application: &'a ApplicationService,
    service: &'a PendingPluginApprovalService,
}

impl fmt::Debug for PendingPluginApprovalProvider<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPluginApprovalProvider")
            .field("scope", &self.service.scope)
            .field(
                "request_event_sequence",
                &self.service.request_event_sequence,
            )
            .finish()
    }
}

impl PendingPluginApprovalProvider<'_> {
    pub fn scope(&self) -> &PendingPluginApprovalScope {
        &self.service.scope
    }

    pub fn read(&self) -> Result<PendingPluginApprovalProjection, crate::ApplicationError> {
        self.application
            .pending_plugin_approval_projection(self.service)
    }
}

/// On-demand Mission-shell consumer. It owns only lifecycle and the latest
/// content-free projection; it cannot mint an approval without Application's
/// typed, revision-fenced command.
pub struct PendingPluginApprovalMissionShellConsumer {
    service: PendingPluginApprovalService,
    active_projection: Option<PendingPluginApprovalProjection>,
}

impl fmt::Debug for PendingPluginApprovalMissionShellConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPluginApprovalMissionShellConsumer")
            .field("service", &self.service)
            .field("has_active_projection", &self.active_projection.is_some())
            .finish()
    }
}

impl PendingPluginApprovalMissionShellConsumer {
    pub fn scope(&self) -> &PendingPluginApprovalScope {
        self.service.scope()
    }

    pub const fn lifecycle(&self) -> PendingPluginApprovalLifecycle {
        self.service.lifecycle
    }

    pub const fn is_active(&self) -> bool {
        self.service.is_active()
    }

    pub const fn has_active_projection(&self) -> bool {
        self.active_projection.is_some()
    }

    pub fn project(
        &mut self,
        application: &ApplicationService,
    ) -> Result<PendingPluginApprovalProjection, crate::ApplicationError> {
        if !self.service.is_active() {
            return Err(PendingPluginApprovalError::LifecycleInactive {
                lifecycle: self.service.lifecycle,
            }
            .into());
        }
        let projection = self.service.provider(application).read()?;
        self.active_projection = Some(projection.clone());
        Ok(projection)
    }

    pub fn decide(
        &mut self,
        application: &mut ApplicationService,
        broker: &EffectBroker,
        actor_id: ActorId,
        decision: PendingPluginApprovalDecision,
        now: DateTime<Utc>,
    ) -> Result<PendingPluginApprovalDecisionResult, crate::ApplicationError> {
        if !self.service.is_active() {
            return Err(PendingPluginApprovalError::LifecycleInactive {
                lifecycle: self.service.lifecycle,
            }
            .into());
        }
        let projection = self
            .active_projection
            .as_ref()
            .ok_or(PendingPluginApprovalError::ProjectionNotSelected)?;
        let command = projection.command(decision, actor_id);
        let result = application.decide_pending_plugin_approval(broker, &command, now)?;
        self.active_projection = Some(result.projection.clone());
        Ok(result)
    }

    pub fn unmount(&mut self) {
        self.service.lifecycle = PendingPluginApprovalLifecycle::Unmounted;
        self.active_projection = None;
    }

    pub fn revoke(&mut self) {
        self.service.lifecycle = PendingPluginApprovalLifecycle::Revoked;
        self.active_projection = None;
    }

    /// Reselecting clears the in-memory selection. The next projection read
    /// must reconstruct the exact request from the durable event spine.
    pub fn reselect(&mut self) {
        if self.service.is_active() {
            self.active_projection = None;
        }
    }
}

#[derive(Debug, Error)]
pub enum PendingPluginApprovalError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Broker(#[from] BrokerError),
    #[error(transparent)]
    Mission(#[from] MissionError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("pending plugin approval scope is empty or malformed")]
    InvalidScope,
    #[error("pending plugin approval request is malformed")]
    InvalidRequest,
    #[error("pending plugin approval request is not present in the exact Mission")]
    RequestNotFound,
    #[error("pending plugin approval request is already terminal")]
    RequestAlreadyTerminal,
    #[error("pending plugin approval request or Effect binding changed")]
    BindingMismatch,
    #[error(
        "pending plugin approval request has a stale Mission, Effect, invocation, or Consent revision"
    )]
    StaleRevision,
    #[error("pending plugin approval request is duplicated with a different digest")]
    DuplicateRequest,
    #[error("duplicate pending plugin approval decision event")]
    DuplicateDecision,
    #[error("pending plugin approval decision does not match the selected request")]
    DecisionMismatch,
    #[error("pending plugin approval durable request event is tampered or content-bearing")]
    TamperedRequestEvent,
    #[error("pending plugin approval durable decision event is tampered")]
    TamperedDecisionEvent,
    #[error("pending plugin approval lifecycle is inactive: {lifecycle:?}")]
    LifecycleInactive {
        lifecycle: PendingPluginApprovalLifecycle,
    },
    #[error("pending plugin approval must be selected before a decision")]
    ProjectionNotSelected,
}

#[derive(Clone, Debug)]
struct RequestRecord {
    request: PendingPluginApprovalRequest,
    request_digest: String,
    event_sequence: u64,
}

#[derive(Clone, Debug)]
struct DecisionRecord {
    request_event_sequence: u64,
    request_digest: String,
    decision: PendingPluginApprovalDecision,
    actor_id: ActorId,
    result_mission_revision: u64,
    result_effect_status: EffectStatus,
    event_sequence: u64,
}

impl ApplicationService {
    /// Persist a typed plugin approval request event for an already-proposed
    /// Effect. The event and its Outbox row are committed with a CAS on the
    /// exact Mission revision; an exact replay returns the existing request.
    #[allow(
        clippy::too_many_lines,
        reason = "request admission keeps exact Effect binding, idempotency re-read, and Event/Outbox CAS visibly ordered"
    )]
    pub fn record_pending_plugin_approval(
        &mut self,
        request: PendingPluginApprovalRequest,
        now: DateTime<Utc>,
    ) -> Result<PendingPluginApprovalProjection, crate::ApplicationError> {
        request
            .validate_shape()
            .map_err(crate::ApplicationError::from)?;
        let request_digest = request
            .request_digest()
            .map_err(crate::ApplicationError::from)?;
        let mission = self
            .store
            .load_mission(request.scope.project_id(), request.scope.mission_id())
            .map_err(crate::ApplicationError::from)?;
        validate_mission_scope(&mission, &request.scope)?;
        if mission.revision != request.expected_mission_revision {
            return Err(PendingPluginApprovalError::StaleRevision.into());
        }
        let effect = mission
            .effects
            .iter()
            .find(|effect| effect.id == request.effect_id)
            .ok_or(PendingPluginApprovalError::BindingMismatch)?;
        if effect.status != EffectStatus::Proposed
            || effect.approval_digest() != request.effect_digest
        {
            return Err(PendingPluginApprovalError::BindingMismatch.into());
        }
        let consent_revision = consent_revision(&self.store, &mission, &request.effect_id)?;
        if consent_revision != request.expected_consent_revision {
            return Err(PendingPluginApprovalError::StaleRevision.into());
        }

        let events = self
            .store
            .events_for_mission(&request.scope.project_id, &request.scope.mission_id)
            .map_err(crate::ApplicationError::from)?;
        let records = request_records(&events).map_err(crate::ApplicationError::from)?;
        if let Some(existing) = records.iter().find(|record| {
            record.request.invocation_id == request.invocation_id
                || record.request.effect_id == request.effect_id
        }) {
            if existing.request_digest == request_digest {
                return self
                    .pending_plugin_approval_projection_for_record(&mission, &events, existing)
                    .map_err(crate::ApplicationError::from);
            }
            return Err(PendingPluginApprovalError::DuplicateRequest.into());
        }

        let request_event = PendingEvent::new(
            PENDING_PLUGIN_APPROVAL_REQUEST_EVENT,
            request.event_payload(&request_digest),
            now,
        );
        let mutation = match self.store.append_mission_event_if_absent_atomic(
            &request.scope.project_id,
            &request.scope.mission_id,
            request.expected_mission_revision,
            &request_event,
        ) {
            Ok(mutation) => mutation,
            Err(StorageError::OptimisticConflict { .. }) => {
                let refreshed_mission = self
                    .store
                    .load_mission(request.scope.project_id(), request.scope.mission_id())
                    .map_err(crate::ApplicationError::from)?;
                let refreshed_events = self
                    .store
                    .events_for_mission(request.scope.project_id(), request.scope.mission_id())
                    .map_err(crate::ApplicationError::from)?;
                let refreshed_records =
                    request_records(&refreshed_events).map_err(crate::ApplicationError::from)?;
                if let Some(existing) = refreshed_records
                    .iter()
                    .find(|record| record.request_digest == request_digest)
                {
                    return self
                        .pending_plugin_approval_projection_for_record(
                            &refreshed_mission,
                            &refreshed_events,
                            existing,
                        )
                        .map_err(crate::ApplicationError::from);
                }
                return Err(PendingPluginApprovalError::StaleRevision.into());
            }
            Err(error) => return Err(PendingPluginApprovalError::Storage(error).into()),
        };
        let event_sequence = mutation.event_sequences.first().copied().ok_or(
            PendingPluginApprovalError::Storage(StorageError::DomainDecode(
                "pending approval request event sequence missing".into(),
            )),
        )?;
        let event_sequence = u64::try_from(event_sequence).map_err(|_| {
            PendingPluginApprovalError::Storage(StorageError::DomainDecode(
                "pending approval request event sequence is invalid".into(),
            ))
        })?;
        let record = RequestRecord {
            request,
            request_digest,
            event_sequence,
        };
        let mut updated_events = events;
        updated_events.push(DomainEventRecord {
            sequence: i64::try_from(event_sequence).map_err(|_| {
                PendingPluginApprovalError::Storage(StorageError::DomainDecode(
                    "pending approval request sequence overflow".into(),
                ))
            })?,
            project_id: record.request.scope.project_id.clone(),
            mission_id: Some(record.request.scope.mission_id.clone()),
            event_type: PENDING_PLUGIN_APPROVAL_REQUEST_EVENT.into(),
            payload: request_event.payload.clone(),
            recorded_at: now,
        });
        self.pending_plugin_approval_projection_for_record(&mission, &updated_events, &record)
            .map_err(crate::ApplicationError::from)
    }

    /// Return all durable request services for one Project/Mission. Terminal
    /// requests are omitted; stale requests remain visible as content-free
    /// handles so the next command fails closed instead of silently selecting
    /// a different invocation.
    pub fn pending_plugin_approval_services(
        &self,
        project_id: &ProjectId,
        mission_id: &hartevo_domain_kernel::MissionId,
    ) -> Result<Vec<PendingPluginApprovalService>, crate::ApplicationError> {
        let mission = self
            .store
            .load_mission(project_id, mission_id)
            .map_err(crate::ApplicationError::from)?;
        let events = self
            .store
            .events_for_mission(project_id, mission_id)
            .map_err(crate::ApplicationError::from)?;
        let records = request_records(&events).map_err(crate::ApplicationError::from)?;
        let mut services = Vec::new();
        for record in &records {
            if decision_records(&events, record.event_sequence)
                .map_err(crate::ApplicationError::from)?
                .is_empty()
            {
                validate_mission_scope(&mission, &record.request.scope)?;
                services.push(PendingPluginApprovalService::from_record(record));
            }
        }
        Ok(services)
    }

    /// Read one exact request through the Application-owned projection.
    pub fn pending_plugin_approval_projection(
        &self,
        service: &PendingPluginApprovalService,
    ) -> Result<PendingPluginApprovalProjection, crate::ApplicationError> {
        if !service.is_active() {
            return Err(PendingPluginApprovalError::LifecycleInactive {
                lifecycle: service.lifecycle,
            }
            .into());
        }
        let mission = self
            .store
            .load_mission(service.scope.project_id(), service.scope.mission_id())
            .map_err(crate::ApplicationError::from)?;
        let events = self
            .store
            .events_for_mission(service.scope.project_id(), service.scope.mission_id())
            .map_err(crate::ApplicationError::from)?;
        let record = request_records(&events)
            .map_err(crate::ApplicationError::from)?
            .into_iter()
            .find(|record| {
                record.event_sequence == service.request_event_sequence
                    && record.request_digest == service.request_digest
            })
            .ok_or(PendingPluginApprovalError::RequestNotFound)?;
        validate_mission_scope(&mission, &service.scope)?;
        self.pending_plugin_approval_projection_for_record(&mission, &events, &record)
            .map_err(crate::ApplicationError::from)
    }

    /// Execute the typed user decision. Approval reuses EffectBroker's live
    /// permission authority; denial uses the existing Domain
    /// `Mission::approve_effect` rejection transition. Both paths persist the
    /// Mission mutation, decision Event, and Outbox row under the exact source
    /// fences in one transaction.
    #[allow(
        clippy::too_many_lines,
        reason = "the decision boundary keeps request validation, authority revalidation, and one transactional CAS visibly ordered"
    )]
    pub fn decide_pending_plugin_approval(
        &mut self,
        broker: &EffectBroker,
        command: &PendingPluginApprovalDecisionCommand,
        now: DateTime<Utc>,
    ) -> Result<PendingPluginApprovalDecisionResult, crate::ApplicationError> {
        command
            .validate_shape()
            .map_err(crate::ApplicationError::from)?;
        let mission = self
            .store
            .load_mission(command.scope.project_id(), command.scope.mission_id())
            .map_err(crate::ApplicationError::from)?;
        validate_mission_scope(&mission, &command.scope)?;
        let events = self
            .store
            .events_for_mission(command.scope.project_id(), command.scope.mission_id())
            .map_err(crate::ApplicationError::from)?;
        let record = request_records(&events)
            .map_err(crate::ApplicationError::from)?
            .into_iter()
            .find(|record| record.event_sequence == command.request_event_sequence)
            .ok_or(PendingPluginApprovalError::RequestNotFound)?;
        validate_command_against_request(command, &record)?;
        let existing_decisions = decision_records(&events, record.event_sequence)
            .map_err(crate::ApplicationError::from)?;
        if existing_decisions.len() > 1 {
            return Err(PendingPluginApprovalError::DuplicateDecision.into());
        }
        if let Some(existing) = existing_decisions.first() {
            if existing.decision != command.decision || existing.actor_id != command.actor_id {
                return Err(PendingPluginApprovalError::DecisionMismatch.into());
            }
            let projection = self
                .pending_plugin_approval_projection_for_record(&mission, &events, &record)
                .map_err(crate::ApplicationError::from)?;
            return Ok(PendingPluginApprovalDecisionResult {
                committed_mission_revision: existing.result_mission_revision,
                decision_event_sequence: existing.event_sequence,
                decision_outbox_sequence: None,
                projection,
                replayed: true,
            });
        }

        let projection = self
            .pending_plugin_approval_projection_for_record(&mission, &events, &record)
            .map_err(crate::ApplicationError::from)?;
        if projection.state != PendingPluginApprovalState::Pending
            || projection.current_mission_revision != command.expected_mission_revision
        {
            return Err(PendingPluginApprovalError::StaleRevision.into());
        }
        if projection.revisions.effect_revision != command.expected_effect_revision
            || projection.revisions.consent_revision != command.expected_consent_revision
        {
            return Err(PendingPluginApprovalError::StaleRevision.into());
        }

        let expected_mission_revision = mission.revision;
        let mut next_mission = mission;
        match command.decision {
            PendingPluginApprovalDecision::Approve => {
                broker
                    .approve(
                        &mut next_mission,
                        &command.effect_id,
                        command.actor_id.clone(),
                        &self.store,
                        now,
                    )
                    .map_err(PendingPluginApprovalError::from)?;
            }
            PendingPluginApprovalDecision::Deny => {
                reject_effect(
                    &mut next_mission,
                    &command.effect_id,
                    command.actor_id.clone(),
                    &command.request_digest,
                    now,
                )?;
            }
        }
        let result_effect_status = command.decision.effect_status();
        let decision_digest = decision_digest(
            &record,
            command.decision,
            &command.actor_id,
            next_mission.revision,
            result_effect_status.clone(),
        )?;
        let decision_event = PendingEvent::new(
            PENDING_PLUGIN_APPROVAL_DECISION_EVENT,
            serde_json::json!({
                "schema": DECISION_SCHEMA,
                "requestEventSequence": command.request_event_sequence,
                "requestDigest": command.request_digest,
                "decision": command.decision.as_str(),
                "actorId": command.actor_id,
                "resultMissionRevision": next_mission.revision,
                "resultEffectStatus": effect_status_name(&result_effect_status),
                "decisionDigest": decision_digest,
            }),
            now,
        );
        let consent_fence = match record.request.expected_consent_revision {
            Some(revision) => Some(ApplicationSourceRevisionFence::present(
                ApplicationSourceKind::ConsentRecord,
                consent_record_id(&next_mission, &command.effect_id)?
                    .ok_or(PendingPluginApprovalError::BindingMismatch)?
                    .as_str()
                    .to_owned(),
                revision,
            )),
            None => None,
        };
        let invocation_fence = ApplicationSourceRevisionFence::present(
            ApplicationSourceKind::DomainEvent,
            command.request_event_sequence.to_string(),
            command.request_event_sequence,
        );
        let source_fences = consent_fence
            .into_iter()
            .chain(std::iter::once(invocation_fence))
            .collect::<Vec<_>>();
        let mutation = match self
            .store
            .update_mission_atomic_with_application_source_fences(
                &next_mission,
                expected_mission_revision,
                None,
                &source_fences,
                &[decision_event],
            ) {
            Ok(mutation) => mutation,
            Err(StorageError::OptimisticConflict { .. }) => {
                return Err(PendingPluginApprovalError::StaleRevision.into());
            }
            Err(error) => return Err(PendingPluginApprovalError::Storage(error).into()),
        };
        let decision_event_sequence = mutation.event_sequences.first().copied().ok_or(
            PendingPluginApprovalError::Storage(StorageError::DomainDecode(
                "pending approval decision event sequence missing".into(),
            )),
        )?;
        let decision_outbox_sequence = mutation.outbox_sequences.first().copied();
        let mut committed_events = events;
        committed_events.push(DomainEventRecord {
            sequence: decision_event_sequence,
            project_id: command.scope.project_id.clone(),
            mission_id: Some(command.scope.mission_id.clone()),
            event_type: PENDING_PLUGIN_APPROVAL_DECISION_EVENT.into(),
            payload: serde_json::json!({
                "schema": DECISION_SCHEMA,
                "requestEventSequence": command.request_event_sequence,
                "requestDigest": command.request_digest,
                "decision": command.decision.as_str(),
                "actorId": command.actor_id,
                "resultMissionRevision": next_mission.revision,
                "resultEffectStatus": effect_status_name(&result_effect_status),
                "decisionDigest": decision_digest,
            }),
            recorded_at: now,
        });
        let request_record = record;
        let projection = self
            .pending_plugin_approval_projection_for_record(
                &next_mission,
                &committed_events,
                &request_record,
            )
            .map_err(crate::ApplicationError::from)?;
        Ok(PendingPluginApprovalDecisionResult {
            projection,
            committed_mission_revision: mutation.state_revision,
            decision_event_sequence: positive_sequence(decision_event_sequence)?,
            decision_outbox_sequence,
            replayed: false,
        })
    }

    fn pending_plugin_approval_projection_for_record(
        &self,
        mission: &Mission,
        events: &[DomainEventRecord],
        record: &RequestRecord,
    ) -> Result<PendingPluginApprovalProjection, PendingPluginApprovalError> {
        validate_mission_scope(mission, &record.request.scope)?;
        let effect = mission
            .effects
            .iter()
            .find(|effect| effect.id == record.request.effect_id)
            .ok_or(PendingPluginApprovalError::BindingMismatch)?;
        if effect.approval_digest() != record.request.effect_digest {
            return Err(PendingPluginApprovalError::BindingMismatch);
        }
        let consent_revision = consent_revision(&self.store, mission, &record.request.effect_id)?;
        if consent_revision != record.request.expected_consent_revision {
            return build_projection(
                &record.request,
                record.event_sequence,
                PendingPluginApprovalState::Stale,
                mission.revision,
            );
        }
        let decisions = decision_records(events, record.event_sequence)?;
        if decisions.len() > 1 {
            return Err(PendingPluginApprovalError::DuplicateDecision);
        }
        let state = if let Some(decision) = decisions.first() {
            if decision.request_digest != record.request_digest
                || decision.result_mission_revision > mission.revision
                || decision.result_effect_status != effect.status
                || effect
                    .approval
                    .as_ref()
                    .is_none_or(|approval| approval.decided_by != decision.actor_id)
                || decision.result_effect_status != decision.decision.effect_status()
            {
                return Err(PendingPluginApprovalError::TamperedDecisionEvent);
            }
            match decision.decision {
                PendingPluginApprovalDecision::Approve => PendingPluginApprovalState::Approved,
                PendingPluginApprovalDecision::Deny => PendingPluginApprovalState::Denied,
            }
        } else if mission.revision != record.request.expected_mission_revision
            || effect.status != EffectStatus::Proposed
        {
            PendingPluginApprovalState::Stale
        } else {
            PendingPluginApprovalState::Pending
        };
        build_projection(
            &record.request,
            record.event_sequence,
            state,
            mission.revision,
        )
    }
}

impl PendingPluginApprovalDecisionCommand {
    fn validate_shape(&self) -> Result<(), PendingPluginApprovalError> {
        self.scope.validate()?;
        if self.plugin_id.trim().is_empty()
            || self.plugin_version.trim().is_empty()
            || self.invocation_id.trim().is_empty()
            || self.effect_id.as_str().trim().is_empty()
            || self.request_event_sequence == 0
            || self.expected_mission_revision == 0
            || self.expected_effect_revision == 0
            || self.expected_mission_revision != self.expected_effect_revision
            || !is_digest(&self.plugin_digest)
            || !is_digest(&self.invocation_digest)
            || !is_digest(&self.effect_digest)
            || !is_digest(&self.request_digest)
            || self
                .expected_consent_revision
                .is_some_and(|revision| revision == 0)
            || self.actor_id.as_str().trim().is_empty()
        {
            return Err(PendingPluginApprovalError::InvalidRequest);
        }
        Ok(())
    }
}

fn validate_command_against_request(
    command: &PendingPluginApprovalDecisionCommand,
    record: &RequestRecord,
) -> Result<(), PendingPluginApprovalError> {
    let request = &record.request;
    if command.scope != request.scope
        || command.plugin_id != request.plugin_id
        || command.plugin_version != request.plugin_version
        || command.plugin_digest != request.plugin_digest
        || command.invocation_id != request.invocation_id
        || command.invocation_digest != request.invocation_digest
        || command.effect_id != request.effect_id
        || command.effect_digest != request.effect_digest
        || command.request_digest != record.request_digest
        || command.expected_mission_revision != request.expected_mission_revision
        || command.expected_effect_revision != request.expected_effect_revision
        || command.expected_consent_revision != request.expected_consent_revision
    {
        return Err(PendingPluginApprovalError::BindingMismatch);
    }
    Ok(())
}

fn validate_mission_scope(
    mission: &Mission,
    scope: &PendingPluginApprovalScope,
) -> Result<(), PendingPluginApprovalError> {
    if mission.tenant_id != scope.tenant_id
        || mission.project_id != scope.project_id
        || mission.id != scope.mission_id
    {
        return Err(PendingPluginApprovalError::InvalidScope);
    }
    Ok(())
}

fn request_records(
    events: &[DomainEventRecord],
) -> Result<Vec<RequestRecord>, PendingPluginApprovalError> {
    let mut records = Vec::new();
    let mut identities = BTreeSet::new();
    for event in events {
        if event.event_type != PENDING_PLUGIN_APPROVAL_REQUEST_EVENT {
            continue;
        }
        let record = parse_request_event(event)?;
        let identity = (
            record.request.invocation_id.clone(),
            record.request.effect_id.clone(),
        );
        if !identities.insert(identity) {
            return Err(PendingPluginApprovalError::DuplicateRequest);
        }
        records.push(record);
    }
    Ok(records)
}

fn parse_request_event(
    event: &DomainEventRecord,
) -> Result<RequestRecord, PendingPluginApprovalError> {
    let sequence = positive_sequence(event.sequence)?;
    require_exact_keys(&event.payload, REQUEST_KEYS)?;
    let request = PendingPluginApprovalRequest {
        scope: PendingPluginApprovalScope::new(
            TenantId::from_stable(required_string(&event.payload, "tenantId")?),
            ProjectId::from_stable(required_string(&event.payload, "projectId")?),
            hartevo_domain_kernel::MissionId::from_stable(required_string(
                &event.payload,
                "missionId",
            )?),
        )?,
        plugin_id: required_string(&event.payload, "pluginId")?,
        plugin_version: required_string(&event.payload, "pluginVersion")?,
        plugin_digest: required_string(&event.payload, "pluginDigest")?,
        invocation_id: required_string(&event.payload, "invocationId")?,
        invocation_digest: required_string(&event.payload, "invocationDigest")?,
        effect_id: EffectId::from_stable(required_string(&event.payload, "effectId")?),
        effect_digest: required_string(&event.payload, "effectDigest")?,
        expected_mission_revision: required_u64(&event.payload, "expectedMissionRevision")?,
        expected_effect_revision: required_u64(&event.payload, "expectedEffectRevision")?,
        expected_consent_revision: nullable_u64(&event.payload, "expectedConsentRevision")?,
    };
    if required_string(&event.payload, "schema")? != REQUEST_SCHEMA {
        return Err(PendingPluginApprovalError::TamperedRequestEvent);
    }
    let request_digest = required_string(&event.payload, "requestDigest")?;
    if !is_digest(&request_digest) || request.request_digest()? != request_digest {
        return Err(PendingPluginApprovalError::TamperedRequestEvent);
    }
    if event.project_id != *request.scope.project_id()
        || event.mission_id.as_ref() != Some(request.scope.mission_id())
    {
        return Err(PendingPluginApprovalError::InvalidScope);
    }
    Ok(RequestRecord {
        request,
        request_digest,
        event_sequence: sequence,
    })
}

fn decision_records(
    events: &[DomainEventRecord],
    request_event_sequence: u64,
) -> Result<Vec<DecisionRecord>, PendingPluginApprovalError> {
    let mut records = Vec::new();
    for event in events {
        if event.event_type != PENDING_PLUGIN_APPROVAL_DECISION_EVENT {
            continue;
        }
        let record = parse_decision_event(event)?;
        if record.request_event_sequence == request_event_sequence {
            records.push(record);
        }
    }
    Ok(records)
}

fn parse_decision_event(
    event: &DomainEventRecord,
) -> Result<DecisionRecord, PendingPluginApprovalError> {
    require_exact_keys(&event.payload, DECISION_KEYS)?;
    if required_string(&event.payload, "schema")? != DECISION_SCHEMA {
        return Err(PendingPluginApprovalError::TamperedDecisionEvent);
    }
    let request_event_sequence = required_u64(&event.payload, "requestEventSequence")?;
    let request_digest = required_string(&event.payload, "requestDigest")?;
    let decision =
        PendingPluginApprovalDecision::parse(&required_string(&event.payload, "decision")?)?;
    let actor_id = ActorId::from_stable(required_string(&event.payload, "actorId")?);
    let result_mission_revision = required_u64(&event.payload, "resultMissionRevision")?;
    let result_effect_status =
        parse_effect_status(&required_string(&event.payload, "resultEffectStatus")?)?;
    let decision_digest = required_string(&event.payload, "decisionDigest")?;
    let record = DecisionRecord {
        request_event_sequence,
        request_digest,
        decision,
        actor_id,
        result_mission_revision,
        result_effect_status,
        event_sequence: positive_sequence(event.sequence)?,
    };
    if !is_digest(&decision_digest) {
        return Err(PendingPluginApprovalError::TamperedDecisionEvent);
    }
    let expected = decision_digest_from_record(&record)?;
    if expected != decision_digest {
        return Err(PendingPluginApprovalError::TamperedDecisionEvent);
    }
    Ok(record)
}

fn build_projection(
    request: &PendingPluginApprovalRequest,
    event_sequence: u64,
    state: PendingPluginApprovalState,
    current_mission_revision: u64,
) -> Result<PendingPluginApprovalProjection, PendingPluginApprovalError> {
    let revisions = PendingPluginApprovalRevisions {
        mission_revision: request.expected_mission_revision,
        effect_revision: request.expected_effect_revision,
        invocation_revision: event_sequence,
        consent_revision: request.expected_consent_revision,
    };
    let mut projection = PendingPluginApprovalProjection {
        scope: request.scope.clone(),
        state,
        plugin_id: request.plugin_id.clone(),
        plugin_version: request.plugin_version.clone(),
        plugin_digest: request.plugin_digest.clone(),
        invocation_id: request.invocation_id.clone(),
        invocation_digest: request.invocation_digest.clone(),
        effect_id: request.effect_id.clone(),
        effect_digest: request.effect_digest.clone(),
        request_digest: request.request_digest()?,
        request_event_sequence: event_sequence,
        revisions,
        current_mission_revision,
        projection_digest: String::new(),
    };
    projection.projection_digest = digest_json(&serde_json::to_value(&projection)?)?;
    Ok(projection)
}

fn decision_digest(
    request: &RequestRecord,
    decision: PendingPluginApprovalDecision,
    actor_id: &ActorId,
    result_mission_revision: u64,
    result_effect_status: EffectStatus,
) -> Result<String, PendingPluginApprovalError> {
    decision_digest_from_record(&DecisionRecord {
        request_event_sequence: request.event_sequence,
        request_digest: request.request_digest.clone(),
        decision,
        actor_id: actor_id.clone(),
        result_mission_revision,
        result_effect_status,
        event_sequence: 0,
    })
}

fn decision_digest_from_record(
    record: &DecisionRecord,
) -> Result<String, PendingPluginApprovalError> {
    digest_json(&serde_json::json!({
        "schema": DECISION_SCHEMA,
        "requestEventSequence": record.request_event_sequence,
        "requestDigest": &record.request_digest,
        "decision": record.decision.as_str(),
        "actorId": &record.actor_id,
        "resultMissionRevision": record.result_mission_revision,
        "resultEffectStatus": effect_status_name(&record.result_effect_status),
    }))
}

fn reject_effect(
    mission: &mut Mission,
    effect_id: &EffectId,
    actor_id: ActorId,
    request_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), PendingPluginApprovalError> {
    let valid_until = mission.approval_valid_until(effect_id, now)?;
    let effect = mission.effect(effect_id)?;
    let scope_digest = effect.approval_digest();
    let permission_digest = digest_text(&format!("pending-plugin-deny:{request_digest}"));
    mission.approve_effect(
        effect_id,
        Approval {
            id: ApprovalId::from_stable(format!("approval-{scope_digest}")),
            decision: ApprovalDecision::Rejected,
            decided_by: actor_id,
            decided_at: now,
            valid_until,
            scope_digest,
            permission_digest,
        },
    )?;
    Ok(())
}

fn consent_revision(
    store: &ProjectStore,
    mission: &Mission,
    effect_id: &EffectId,
) -> Result<Option<u64>, PendingPluginApprovalError> {
    let Some(record_id) = consent_record_id(mission, effect_id)? else {
        return Ok(None);
    };
    Ok(Some(
        store
            .load_consent_record(&mission.project_id, &record_id)?
            .revision,
    ))
}

fn consent_record_id(
    mission: &Mission,
    effect_id: &EffectId,
) -> Result<Option<hartevo_domain_kernel::ConsentRecordId>, PendingPluginApprovalError> {
    Ok(mission
        .effects
        .iter()
        .find(|effect| &effect.id == effect_id)
        .ok_or(PendingPluginApprovalError::BindingMismatch)?
        .consent_record_id
        .clone())
}

fn positive_sequence(sequence: i64) -> Result<u64, PendingPluginApprovalError> {
    u64::try_from(sequence).map_err(|_| PendingPluginApprovalError::TamperedRequestEvent)
}

fn required_string(payload: &Value, key: &str) -> Result<String, PendingPluginApprovalError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or(PendingPluginApprovalError::TamperedRequestEvent)
}

fn required_u64(payload: &Value, key: &str) -> Result<u64, PendingPluginApprovalError> {
    payload
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(PendingPluginApprovalError::TamperedRequestEvent)
}

fn nullable_u64(payload: &Value, key: &str) -> Result<Option<u64>, PendingPluginApprovalError> {
    match payload.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .filter(|revision| *revision > 0)
            .map(Some)
            .ok_or(PendingPluginApprovalError::TamperedRequestEvent),
        _ => Err(PendingPluginApprovalError::TamperedRequestEvent),
    }
}

fn require_exact_keys(payload: &Value, allowed: &[&str]) -> Result<(), PendingPluginApprovalError> {
    let Value::Object(object) = payload else {
        return Err(PendingPluginApprovalError::TamperedRequestEvent);
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || allowed.iter().any(|key| !object.contains_key(*key))
    {
        return Err(PendingPluginApprovalError::TamperedRequestEvent);
    }
    Ok(())
}

fn parse_effect_status(value: &str) -> Result<EffectStatus, PendingPluginApprovalError> {
    match value {
        "approved" => Ok(EffectStatus::Approved),
        "rejected" => Ok(EffectStatus::Rejected),
        _ => Err(PendingPluginApprovalError::TamperedDecisionEvent),
    }
}

fn effect_status_name(status: &EffectStatus) -> &'static str {
    match status {
        EffectStatus::Approved => "approved",
        EffectStatus::Rejected => "rejected",
        _ => "invalid",
    }
}

fn digest_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn digest_json(value: &Value) -> Result<String, PendingPluginApprovalError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn is_digest(value: &str) -> bool {
    value.len() == DIGEST_HEX_LENGTH && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ActorId, ConsentState, CurrencyCode, EffectClass, Money, StorageMode, TaskId,
    };
    use hartevo_effect_broker::{EffectPolicy, EffectRateLimit};
    use hartevo_storage::DatabaseKey;
    use tempfile::TempDir;

    use super::*;
    use crate::{CreateProject, ProposePreviewEffect, StartMission};

    struct Fixture {
        service: ApplicationService,
        _workspace: TempDir,
        project_id: ProjectId,
        mission_id: hartevo_domain_kernel::MissionId,
        effect_id: EffectId,
        now: DateTime<Utc>,
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 14, 0, 0)
            .single()
            .expect("valid fixture time")
    }

    fn fixture() -> Fixture {
        let now = now();
        let workspace = tempfile::tempdir().expect("workspace");
        fixture_with_store(ProjectStore::in_memory().expect("store"), workspace, now)
    }

    fn fixture_with_store(store: ProjectStore, workspace: TempDir, now: DateTime<Utc>) -> Fixture {
        let project_id = ProjectId::from("pending-plugin-project");
        let mission_id = hartevo_domain_kernel::MissionId::from("pending-plugin-mission");
        let mut service = ApplicationService::new(store);
        service
            .create_project(
                CreateProject {
                    tenant_id: TenantId::from("pending-plugin-tenant"),
                    id: project_id.clone(),
                    name: "Pending plugin fixture".into(),
                    description: String::new(),
                    workspace_root: workspace.path().to_path_buf(),
                    storage_mode: StorageMode::LocalNew,
                },
                now,
            )
            .expect("project");
        service
            .start_mission(
                StartMission {
                    id: mission_id.clone(),
                    research_task_id: TaskId::from("pending-plugin-task"),
                    project_id: project_id.clone(),
                    title: Some("Pending plugin Mission".into()),
                    prompt: "Propose one bounded plugin Effect".into(),
                },
                now,
            )
            .expect("Mission");
        let effect_id = EffectId::from("pending-plugin-effect");
        service
            .propose_preview_effect(
                &project_id,
                &mission_id,
                ProposePreviewEffect {
                    effect_id: effect_id.clone(),
                    actor_id: ActorId::from("plugin-actor"),
                    capability: "research.discover".into(),
                    provider: "fixture-provider".into(),
                    connection_id: None,
                    account_id: None,
                    required_scopes: BTreeSet::new(),
                    description: "private effect body never crosses projection".into(),
                    target_resource: "fixture://private-target".into(),
                    audience_digest: None,
                    payload_digest: digest_text("fixture-payload"),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "UTC".into(),
                    consent: ConsentState::NotRequired,
                    consent_record_id: None,
                    consent_requirement: None,
                    policy_version: "fixture-policy-v1".into(),
                    amount: Money::zero(CurrencyCode::parse("USD").expect("currency")),
                    idempotency_key: "pending-plugin-effect-key".into(),
                    expires_in: Duration::minutes(5),
                },
                now,
            )
            .expect("Effect");
        Fixture {
            service,
            _workspace: workspace,
            project_id,
            mission_id,
            effect_id,
            now,
        }
    }

    fn request(fixture: &Fixture) -> PendingPluginApprovalRequest {
        let mission = fixture
            .service
            .load_mission(&fixture.project_id, &fixture.mission_id)
            .expect("Mission");
        let effect = mission.effect(&fixture.effect_id).expect("Effect");
        let scope = PendingPluginApprovalScope::new(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
        )
        .expect("scope");
        PendingPluginApprovalRequest {
            scope,
            plugin_id: "fixture.plugin".into(),
            plugin_version: "1.0.0".into(),
            plugin_digest: digest_text("fixture.plugin@1.0.0"),
            invocation_id: "invocation-1".into(),
            invocation_digest: digest_text("invocation-1"),
            effect_id: effect.id.clone(),
            effect_digest: effect.approval_digest(),
            expected_mission_revision: mission.revision,
            expected_effect_revision: mission.revision,
            expected_consent_revision: None,
        }
    }

    fn broker() -> EffectBroker {
        EffectBroker::new(
            EffectPolicy {
                version: "fixture-policy-v1".into(),
                allowed_capabilities: BTreeSet::from(["research.discover".into()]),
                allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
                max_amounts_minor: BTreeMap::from([(
                    CurrencyCode::parse("USD").expect("currency"),
                    0,
                )]),
                rate_limits: vec![EffectRateLimit {
                    rule_id: "fixture-rate".into(),
                    provider: "fixture-provider".into(),
                    capability: "research.discover".into(),
                    max_executions: 10,
                    window_seconds: 60,
                }],
            },
            "fixture-worker",
        )
    }

    fn register(fixture: &mut Fixture) -> PendingPluginApprovalProjection {
        fixture
            .service
            .record_pending_plugin_approval(request(fixture), fixture.now)
            .expect("pending request")
    }

    #[test]
    fn projection_is_content_free_and_exactly_bound() {
        let mut fixture = fixture();
        let projection = register(&mut fixture);
        assert_eq!(projection.state(), PendingPluginApprovalState::Pending);
        assert_eq!(projection.plugin_id(), "fixture.plugin");
        assert_eq!(projection.plugin_version(), "1.0.0");
        assert_eq!(
            projection.revisions().effect_revision(),
            projection.revisions().mission_revision()
        );
        let serialized = serde_json::to_string(&projection).expect("projection JSON");
        assert!(!serialized.contains("private effect body"));
        assert!(!serialized.contains("private-target"));
        assert!(serialized.contains(projection.effect_digest()));
    }

    #[test]
    fn approve_commits_effect_decision_and_event_outbox_atomically_and_replays_without_growth() {
        let mut fixture = fixture();
        let projection = register(&mut fixture);
        let service = fixture
            .service
            .pending_plugin_approval_services(&fixture.project_id, &fixture.mission_id)
            .expect("services")
            .pop()
            .expect("service");
        let mut consumer = service.into_mission_shell_consumer();
        assert_eq!(
            consumer.project(&fixture.service).expect("projection"),
            projection
        );
        let before_events = fixture
            .service
            .mission_events(&fixture.project_id, &fixture.mission_id)
            .expect("events")
            .len();
        let result = consumer
            .decide(
                &mut fixture.service,
                &broker(),
                ActorId::from("human-operator"),
                PendingPluginApprovalDecision::Approve,
                fixture.now,
            )
            .expect("approve");
        assert!(!result.replayed);
        assert_eq!(
            result.projection.state(),
            PendingPluginApprovalState::Approved
        );
        assert!(result.decision_outbox_sequence.is_some());
        let approved = fixture
            .service
            .load_mission(&fixture.project_id, &fixture.mission_id)
            .expect("approved Mission");
        assert_eq!(
            approved.effect(&fixture.effect_id).expect("Effect").status,
            EffectStatus::Approved
        );
        let after_events = fixture
            .service
            .mission_events(&fixture.project_id, &fixture.mission_id)
            .expect("events")
            .len();
        assert_eq!(after_events, before_events + 1);
        let replay = consumer
            .decide(
                &mut fixture.service,
                &broker(),
                ActorId::from("human-operator"),
                PendingPluginApprovalDecision::Approve,
                fixture.now,
            )
            .expect("replay");
        assert!(replay.replayed);
        assert_eq!(
            fixture
                .service
                .mission_events(&fixture.project_id, &fixture.mission_id)
                .expect("events")
                .len(),
            after_events
        );
    }

    #[test]
    fn exact_request_replay_returns_the_same_projection_without_event_or_outbox_growth() {
        let mut fixture = fixture();
        let first = register(&mut fixture);
        let before = fixture
            .service
            .mission_events(&fixture.project_id, &fixture.mission_id)
            .expect("events")
            .len();
        let replay = fixture
            .service
            .record_pending_plugin_approval(request(&fixture), fixture.now)
            .expect("exact request replay");
        assert_eq!(replay, first);
        assert_eq!(
            fixture
                .service
                .mission_events(&fixture.project_id, &fixture.mission_id)
                .expect("events")
                .len(),
            before
        );
    }

    #[test]
    fn durable_request_projection_reopens_from_the_event_spine() {
        let database_dir = tempfile::tempdir().expect("database directory");
        let database_path = database_dir.path().join("pending-plugin.sqlite");
        let key = DatabaseKey::new([7; 32]).expect("database key");
        let mut first = fixture_with_store(
            ProjectStore::open(&database_path, &key).expect("first store"),
            tempfile::tempdir().expect("workspace"),
            now(),
        );
        let expected = register(&mut first);
        drop(first.service);

        let reopened = ApplicationService::new(
            ProjectStore::open(&database_path, &key).expect("reopened store"),
        );
        let service = reopened
            .pending_plugin_approval_services(&first.project_id, &first.mission_id)
            .expect("reopened services")
            .pop()
            .expect("reopened service");
        let actual = service
            .provider(&reopened)
            .read()
            .expect("reopened projection");
        assert_eq!(actual, expected);
    }

    #[test]
    fn deny_uses_domain_rejection_and_stale_or_revoked_inputs_fail_closed() {
        let mut fixture = fixture();
        let projection = register(&mut fixture);
        let service = fixture
            .service
            .pending_plugin_approval_services(&fixture.project_id, &fixture.mission_id)
            .expect("services")
            .pop()
            .expect("service");
        let mut consumer = service.into_mission_shell_consumer();
        consumer.project(&fixture.service).expect("projection");
        consumer.revoke();
        let error = consumer
            .decide(
                &mut fixture.service,
                &broker(),
                ActorId::from("human-operator"),
                PendingPluginApprovalDecision::Deny,
                fixture.now,
            )
            .expect_err("revoked consumer must be blocked");
        assert!(error.to_string().contains("inactive"));

        let service = fixture
            .service
            .pending_plugin_approval_services(&fixture.project_id, &fixture.mission_id)
            .expect("service still durable")
            .pop()
            .expect("service");
        let mut consumer = service.into_mission_shell_consumer();
        consumer.project(&fixture.service).expect("projection");
        let mut mission = fixture
            .service
            .load_mission(&fixture.project_id, &fixture.mission_id)
            .expect("Mission");
        mission
            .cancel_effect(&fixture.effect_id, fixture.now)
            .expect("cancel Effect");
        fixture
            .service
            .store
            .update_mission_atomic(
                &mission,
                projection.current_mission_revision(),
                &[PendingEvent::new(
                    "mission.reselected",
                    serde_json::json!({"missionRevision": mission.revision}),
                    fixture.now,
                )],
            )
            .expect("advance Mission");
        let error = consumer
            .decide(
                &mut fixture.service,
                &broker(),
                ActorId::from("human-operator"),
                PendingPluginApprovalDecision::Deny,
                fixture.now,
            )
            .expect_err("stale consumer must be blocked");
        assert!(error.to_string().contains("stale"));
    }

    #[test]
    fn tampered_or_cross_scope_request_is_not_projected() {
        let mut fixture = fixture();
        let request = request(&fixture);
        let digest = request.request_digest().expect("digest");
        fixture
            .service
            .store
            .append_mission_events_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                request.expected_mission_revision,
                &[PendingEvent::new(
                    PENDING_PLUGIN_APPROVAL_REQUEST_EVENT,
                    serde_json::json!({
                        "schema": REQUEST_SCHEMA,
                        "tenantId": request.scope.tenant_id,
                        "projectId": request.scope.project_id,
                        "missionId": request.scope.mission_id,
                        "pluginId": request.plugin_id,
                        "pluginVersion": request.plugin_version,
                        "pluginDigest": request.plugin_digest,
                        "invocationId": request.invocation_id,
                        "invocationDigest": request.invocation_digest,
                        "effectId": request.effect_id,
                        "effectDigest": request.effect_digest,
                        "expectedMissionRevision": request.expected_mission_revision,
                        "expectedEffectRevision": request.expected_effect_revision,
                        "expectedConsentRevision": request.expected_consent_revision,
                        "requestDigest": digest,
                        "privateBody": "must be rejected",
                    }),
                    fixture.now,
                )],
            )
            .expect("append tampered event");
        let error = fixture
            .service
            .pending_plugin_approval_services(&fixture.project_id, &fixture.mission_id)
            .expect_err("tampered event must fail closed");
        assert!(error.to_string().contains("tampered"));
    }

    #[test]
    fn cross_scope_decision_is_rejected_without_a_write() {
        let mut source = fixture();
        let projection = register(&mut source);
        let mut command = projection.command(
            PendingPluginApprovalDecision::Deny,
            ActorId::from("human-operator"),
        );
        command.scope = PendingPluginApprovalScope::new(
            TenantId::from("other-tenant"),
            ProjectId::from("other-project"),
            hartevo_domain_kernel::MissionId::from("other-mission"),
        )
        .expect("other scope");
        let before = source
            .service
            .mission_events(&source.project_id, &source.mission_id)
            .expect("events")
            .len();
        let error = source
            .service
            .decide_pending_plugin_approval(&broker(), &command, source.now)
            .expect_err("cross-scope command");
        assert!(error.to_string().contains("not found"));
        assert_eq!(
            source
                .service
                .mission_events(&source.project_id, &source.mission_id)
                .expect("events")
                .len(),
            before
        );
    }

    #[test]
    fn unmount_and_reselect_do_not_leak_selection() {
        let mut fixture = fixture();
        register(&mut fixture);
        let service = fixture
            .service
            .pending_plugin_approval_services(&fixture.project_id, &fixture.mission_id)
            .expect("services")
            .pop()
            .expect("service");
        let mut consumer = service.into_mission_shell_consumer();
        consumer.project(&fixture.service).expect("projection");
        assert!(consumer.has_active_projection());
        consumer.reselect();
        assert!(!consumer.has_active_projection());
        consumer.project(&fixture.service).expect("reselect read");
        consumer.unmount();
        assert!(!consumer.has_active_projection());
        assert!(
            consumer
                .project(&fixture.service)
                .expect_err("unmounted")
                .to_string()
                .contains("inactive")
        );
    }
}

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AccountId, Connection, ConnectionId, ConnectionStatus, Mission, MissionId, Project,
    ProjectDataCell, ProjectId, StorageMode, TenantId,
};
use hartevo_effect_broker::ProviderAdapterRegistry;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::aggregate::{PendingEvent, append_events};
use crate::normalized::{load_project_normalized, update_project_normalized_cas};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectCloudRegistrationStatus {
    Prepared,
    Applied,
    Conflict,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProjectCloudRegistration {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub cell: String,
    pub encryption_mode: String,
    pub remote_execution_opt_in: bool,
    pub idempotency_key_digest: String,
    pub intent_digest: String,
    pub request_digest: String,
    pub key_version: u64,
    pub content_digest: String,
    pub request: Value,
    pub authorized_by: String,
    pub authorization_evidence_digest: String,
    pub status: ProjectCloudRegistrationStatus,
    pub remote_revision: Option<u64>,
    pub remote_duplicate: bool,
    pub last_error_code: Option<String>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl LocalProjectCloudRegistration {
    pub fn validate(&self) -> Result<(), StorageError> {
        let state_valid = match self.status {
            ProjectCloudRegistrationStatus::Prepared => {
                self.remote_revision.is_none()
                    && !self.remote_duplicate
                    && self.last_error_code.is_none()
            }
            ProjectCloudRegistrationStatus::Applied => {
                self.remote_revision == Some(1) && self.last_error_code.is_none()
            }
            ProjectCloudRegistrationStatus::Conflict => {
                self.remote_revision.is_none()
                    && !self.remote_duplicate
                    && self
                        .last_error_code
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
            }
        };
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || !matches!(self.cell.as_str(), "us" | "eu")
            || !matches!(
                self.encryption_mode.as_str(),
                "personal_e2ee" | "team_envelope"
            )
            || !is_sha256(&self.idempotency_key_digest)
            || !is_sha256(&self.intent_digest)
            || !is_sha256(&self.request_digest)
            || self.request_digest
                != format!("{:x}", Sha256::digest(serde_json::to_vec(&self.request)?))
            || self.key_version == 0
            || !is_sha256(&self.content_digest)
            || self.authorized_by.trim().is_empty()
            || !is_sha256(&self.authorization_evidence_digest)
            || self.revision == 0
            || self.created_at > self.updated_at
            || !state_valid
        {
            return Err(StorageError::DomainDecode(
                "invalid local project cloud registration".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalProjectCloudRegistrationPrepareOutcome {
    pub registration: LocalProjectCloudRegistration,
    pub duplicate: bool,
    pub event_sequence: Option<i64>,
    pub outbox_sequence: Option<i64>,
}

impl ProjectStore {
    pub fn prepare_project_cloud_registration(
        &mut self,
        selected_project: &Project,
        expected_project_revision: u64,
        registration: &LocalProjectCloudRegistration,
        now: DateTime<Utc>,
    ) -> Result<LocalProjectCloudRegistrationPrepareOutcome, StorageError> {
        registration.validate()?;
        if registration.revision != 1
            || registration.status != ProjectCloudRegistrationStatus::Prepared
        {
            return Err(StorageError::InvalidInitialRevision(registration.revision));
        }
        validate_project_scope(selected_project, registration)?;
        let transaction = self.connection.transaction()?;
        let stored_project = load_project_normalized(&transaction, &selected_project.id)?
            .ok_or_else(|| StorageError::ProjectNotFound(selected_project.id.clone()))?;
        if let Some(existing) = load_registration(&transaction, &selected_project.id)? {
            if existing.idempotency_key_digest != registration.idempotency_key_digest
                || existing.intent_digest != registration.intent_digest
            {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "project cloud registration intent",
                    id: selected_project.id.to_string(),
                });
            }
            transaction.commit()?;
            return Ok(LocalProjectCloudRegistrationPrepareOutcome {
                registration: existing,
                duplicate: true,
                event_sequence: None,
                outbox_sequence: None,
            });
        }
        persist_cell_selection(
            &transaction,
            &stored_project,
            selected_project,
            expected_project_revision,
        )?;
        insert_registration(&transaction, registration)?;
        let (events, outbox) = append_events(
            &transaction,
            registration.tenant_id.as_str(),
            registration.project_id.as_str(),
            None,
            "project_cloud_registration",
            registration.project_id.as_str(),
            &[PendingEvent::new(
                "project.cloud_registration.prepared",
                event_payload(registration),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(LocalProjectCloudRegistrationPrepareOutcome {
            registration: registration.clone(),
            duplicate: false,
            event_sequence: events.first().copied(),
            outbox_sequence: outbox.first().copied(),
        })
    }

    pub fn load_project_cloud_registration(
        &self,
        project_id: &ProjectId,
    ) -> Result<LocalProjectCloudRegistration, StorageError> {
        load_registration(&self.connection, project_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "project cloud registration",
                project_id: project_id.clone(),
                id: project_id.to_string(),
            }
        })
    }

    pub fn record_project_cloud_registration_applied(
        &mut self,
        project_id: &ProjectId,
        expected_revision: u64,
        remote_revision: u64,
        remote_duplicate: bool,
        now: DateTime<Utc>,
    ) -> Result<LocalProjectCloudRegistration, StorageError> {
        if remote_revision != 1 {
            return Err(StorageError::DomainDecode(
                "project cloud registration remote revision must be one".into(),
            ));
        }
        self.finish_project_cloud_registration(
            project_id,
            expected_revision,
            ProjectRegistrationFinish::Applied {
                remote_revision,
                remote_duplicate,
            },
            now,
        )
    }

    pub fn record_project_cloud_registration_conflict(
        &mut self,
        project_id: &ProjectId,
        expected_revision: u64,
        error_code: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalProjectCloudRegistration, StorageError> {
        if error_code.trim().is_empty() {
            return Err(StorageError::DomainDecode(
                "project cloud registration conflict requires a stable code".into(),
            ));
        }
        self.finish_project_cloud_registration(
            project_id,
            expected_revision,
            ProjectRegistrationFinish::Conflict(error_code.trim().into()),
            now,
        )
    }

    fn finish_project_cloud_registration(
        &mut self,
        project_id: &ProjectId,
        expected_revision: u64,
        finish: ProjectRegistrationFinish,
        now: DateTime<Utc>,
    ) -> Result<LocalProjectCloudRegistration, StorageError> {
        let transaction = self.connection.transaction()?;
        let mut registration = load_registration_required(&transaction, project_id)?;
        if let ProjectRegistrationFinish::Applied {
            remote_revision,
            remote_duplicate,
        } = finish
            && registration.status == ProjectCloudRegistrationStatus::Applied
        {
            if registration.remote_revision == Some(remote_revision)
                && registration.remote_duplicate == remote_duplicate
            {
                transaction.commit()?;
                return Ok(registration);
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "applied project cloud registration",
                id: project_id.to_string(),
            });
        }
        if registration.status != ProjectCloudRegistrationStatus::Prepared
            || registration.revision != expected_revision
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("project_cloud_registration:{project_id}"),
                expected_revision,
            });
        }
        match finish {
            ProjectRegistrationFinish::Applied {
                remote_revision,
                remote_duplicate,
            } => {
                registration.status = ProjectCloudRegistrationStatus::Applied;
                registration.remote_revision = Some(remote_revision);
                registration.remote_duplicate = remote_duplicate;
            }
            ProjectRegistrationFinish::Conflict(error_code) => {
                registration.status = ProjectCloudRegistrationStatus::Conflict;
                registration.last_error_code = Some(error_code);
            }
        }
        registration.revision = next_revision(expected_revision)?;
        registration.updated_at = now;
        update_registration(&transaction, &registration, expected_revision)?;
        append_events(
            &transaction,
            registration.tenant_id.as_str(),
            registration.project_id.as_str(),
            None,
            "project_cloud_registration",
            registration.project_id.as_str(),
            &[PendingEvent::new(
                match registration.status {
                    ProjectCloudRegistrationStatus::Applied => "project.cloud_registration.applied",
                    ProjectCloudRegistrationStatus::Conflict => {
                        "project.cloud_registration.conflict"
                    }
                    ProjectCloudRegistrationStatus::Prepared => unreachable!(),
                },
                event_payload(&registration),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(registration)
    }
}

#[derive(Clone, Debug)]
enum ProjectRegistrationFinish {
    Applied {
        remote_revision: u64,
        remote_duplicate: bool,
    },
    Conflict(String),
}

/// A Mission-scoped provider request. User objectives are represented only by
/// their digest at this boundary; the objective text never enters the
/// registration or Mission event log.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionConnectionRequest {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    connection_id: ConnectionId,
    provider: String,
    account_id: AccountId,
    consumer_id: String,
    objective_digest: String,
    required_capabilities: BTreeSet<String>,
}

impl MissionConnectionRequest {
    pub fn for_mission(
        mission: &Mission,
        connection_id: ConnectionId,
        provider: impl Into<String>,
        account_id: AccountId,
        consumer_id: impl Into<String>,
        objective_digest: impl Into<String>,
        required_capabilities: impl IntoIterator<Item = String>,
    ) -> Result<Self, ConnectionPluginError> {
        let request = Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            mission_revision: mission.revision,
            connection_id,
            provider: provider.into().trim().to_owned(),
            account_id,
            consumer_id: consumer_id.into().trim().to_owned(),
            objective_digest: objective_digest.into().trim().to_owned(),
            required_capabilities: normalize_capabilities(required_capabilities),
        };
        request.validate_for_mission(mission)?;
        Ok(request)
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub fn objective_digest(&self) -> &str {
        &self.objective_digest
    }

    pub fn required_capabilities(&self) -> &BTreeSet<String> {
        &self.required_capabilities
    }

    fn validate_for_mission(&self, mission: &Mission) -> Result<(), ConnectionPluginError> {
        self.validate()?;
        if self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
        {
            return Err(ConnectionPluginError::MissionScopeMismatch);
        }
        if self.mission_revision != mission.revision {
            return Err(ConnectionPluginError::MissionRevisionChanged);
        }
        if mission.stage.is_terminal() {
            return Err(ConnectionPluginError::MissionNotReusable);
        }
        if !mission
            .contract
            .enabled_capabilities
            .is_superset(&self.required_capabilities)
        {
            return Err(ConnectionPluginError::CapabilityNotEnabled);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConnectionPluginError> {
        if !valid_identifier(self.tenant_id.as_str())
            || !valid_identifier(self.project_id.as_str())
            || !valid_identifier(self.mission_id.as_str())
            || !valid_identifier(self.connection_id.as_str())
            || !valid_identifier(self.provider.as_str())
            || !valid_identifier(self.account_id.as_str())
            || !valid_identifier(&self.consumer_id)
            || !is_sha256(&self.objective_digest)
            || self.required_capabilities.is_empty()
            || self
                .required_capabilities
                .iter()
                .any(|capability| !valid_identifier(capability))
            || self.mission_revision == 0
        {
            return Err(ConnectionPluginError::InvalidRequest);
        }
        Ok(())
    }

    fn scope(&self) -> ConnectionPluginScope {
        ConnectionPluginScope {
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            mission_id: self.mission_id.clone(),
            mission_revision: self.mission_revision,
            connection_id: self.connection_id.clone(),
            provider: self.provider.clone(),
            account_id: self.account_id.clone(),
        }
    }
}

/// The exact tenant/project/Mission/account boundary delivered to a consumer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionPluginScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    connection_id: ConnectionId,
    provider: String,
    account_id: AccountId,
}

impl ConnectionPluginScope {
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn validate(&self) -> Result<(), ConnectionPluginError> {
        if !valid_identifier(self.tenant_id.as_str())
            || !valid_identifier(self.project_id.as_str())
            || !valid_identifier(self.mission_id.as_str())
            || !valid_identifier(self.connection_id.as_str())
            || !valid_identifier(&self.provider)
            || !valid_identifier(self.account_id.as_str())
            || self.mission_revision == 0
        {
            return Err(ConnectionPluginError::InvalidScope);
        }
        Ok(())
    }
}

/// Non-secret capability evidence released with a mounted provider handle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionCapabilitySnapshot {
    connection_id: ConnectionId,
    provider: String,
    account_id: AccountId,
    required_capabilities: BTreeSet<String>,
    granted_capabilities: BTreeSet<String>,
    connection_revision: u64,
    probed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    credential_expires_at: DateTime<Utc>,
    evidence_digest: String,
    snapshot_digest: String,
}

impl ConnectionCapabilitySnapshot {
    fn from_connection(
        connection: &Connection,
        required_capabilities: &BTreeSet<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, ConnectionPluginError> {
        if required_capabilities.is_empty()
            || !connection.permits_scopes(required_capabilities, now)
        {
            return Err(ConnectionPluginError::NotConnected(
                connection.effective_status(now),
            ));
        }
        let probe = connection
            .live_probe(now)
            .ok_or_else(|| ConnectionPluginError::NotConnected(connection.effective_status(now)))?;
        let snapshot = Self {
            connection_id: connection.id().clone(),
            provider: connection.provider().to_owned(),
            account_id: connection.account_id().clone(),
            required_capabilities: required_capabilities.clone(),
            granted_capabilities: connection.granted_scopes().clone(),
            connection_revision: connection.revision(),
            probed_at: probe.probed_at,
            valid_until: probe.valid_until,
            credential_expires_at: probe.credential_expires_at,
            evidence_digest: probe.evidence_digest.clone(),
            snapshot_digest: String::new(),
        };
        let snapshot_digest = digest_json(&(
            &snapshot.connection_id,
            &snapshot.provider,
            &snapshot.account_id,
            &snapshot.required_capabilities,
            &snapshot.granted_capabilities,
            snapshot.connection_revision,
            snapshot.probed_at,
            snapshot.valid_until,
            snapshot.credential_expires_at,
            &snapshot.evidence_digest,
        ))?;
        let snapshot = Self {
            snapshot_digest,
            ..snapshot
        };
        snapshot.validate(now)?;
        Ok(snapshot)
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn required_capabilities(&self) -> &BTreeSet<String> {
        &self.required_capabilities
    }

    pub fn granted_capabilities(&self) -> &BTreeSet<String> {
        &self.granted_capabilities
    }

    pub const fn connection_revision(&self) -> u64 {
        self.connection_revision
    }

    pub const fn probed_at(&self) -> DateTime<Utc> {
        self.probed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn credential_expires_at(&self) -> DateTime<Utc> {
        self.credential_expires_at
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    fn validate(&self, now: DateTime<Utc>) -> Result<(), ConnectionPluginError> {
        if !valid_identifier(self.connection_id.as_str())
            || !valid_identifier(&self.provider)
            || !valid_identifier(self.account_id.as_str())
            || self.required_capabilities.is_empty()
            || self
                .required_capabilities
                .iter()
                .any(|capability| !valid_identifier(capability))
            || self.granted_capabilities.is_empty()
            || !self
                .required_capabilities
                .is_subset(&self.granted_capabilities)
            || self.connection_revision == 0
            || self.probed_at > now
            || self.valid_until <= now
            || self.credential_expires_at <= now
            || !is_sha256(&self.evidence_digest)
            || !is_sha256(&self.snapshot_digest)
        {
            return Err(ConnectionPluginError::InvalidCapabilitySnapshot);
        }
        Ok(())
    }
}

/// An opaque host-owned authorization handle. It is deliberately not
/// serializable and its Debug representation never includes its identifier.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ConnectionAuthHandle(ConnectionId);

impl ConnectionAuthHandle {
    fn new() -> Self {
        Self(ConnectionId::new())
    }
}

impl fmt::Debug for ConnectionAuthHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionAuthHandle([REDACTED])")
    }
}

/// The only value handed from the host provider to a Mission consumer before
/// the provider result is accepted: opaque handle, exact scope, and a live
/// capability snapshot. No credential or provider payload is present.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectionPluginDelivery {
    handle: ConnectionAuthHandle,
    scope: ConnectionPluginScope,
    capability_snapshot: ConnectionCapabilitySnapshot,
}

impl ConnectionPluginDelivery {
    pub fn handle(&self) -> &ConnectionAuthHandle {
        &self.handle
    }

    pub fn scope(&self) -> &ConnectionPluginScope {
        &self.scope
    }

    pub fn capability_snapshot(&self) -> &ConnectionCapabilitySnapshot {
        &self.capability_snapshot
    }
}

impl fmt::Debug for ConnectionPluginDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionPluginDelivery")
            .field("handle", &self.handle)
            .field("scope", &self.scope)
            .field("capability_snapshot", &self.capability_snapshot)
            .finish()
    }
}

/// A composable, content-free connection result. A provider never returns a
/// token, secret, or raw response through this receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionReceipt {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    connection_id: ConnectionId,
    provider: String,
    account_id: AccountId,
    capability_snapshot_digest: String,
    capabilities: BTreeSet<String>,
    connection_revision: u64,
    issued_at: DateTime<Utc>,
    receipt_digest: String,
}

impl ConnectionReceipt {
    fn issue(
        scope: &ConnectionPluginScope,
        snapshot: &ConnectionCapabilitySnapshot,
        issued_at: DateTime<Utc>,
    ) -> Result<Self, ConnectionPluginError> {
        if scope.connection_id != *snapshot.connection_id()
            || scope.provider != snapshot.provider
            || scope.account_id != *snapshot.account_id()
        {
            return Err(ConnectionPluginError::ConnectionScopeMismatch);
        }
        let receipt = Self {
            tenant_id: scope.tenant_id.clone(),
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
            connection_id: scope.connection_id.clone(),
            provider: scope.provider.clone(),
            account_id: scope.account_id.clone(),
            capability_snapshot_digest: snapshot.snapshot_digest.clone(),
            capabilities: snapshot.required_capabilities.clone(),
            connection_revision: snapshot.connection_revision,
            issued_at,
            receipt_digest: String::new(),
        };
        let receipt_digest = digest_json(&(
            &receipt.tenant_id,
            &receipt.project_id,
            &receipt.mission_id,
            receipt.mission_revision,
            &receipt.connection_id,
            &receipt.provider,
            &receipt.account_id,
            &receipt.capability_snapshot_digest,
            &receipt.capabilities,
            receipt.connection_revision,
            receipt.issued_at,
        ))?;
        Ok(Self {
            receipt_digest,
            ..receipt
        })
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn capability_snapshot_digest(&self) -> &str {
        &self.capability_snapshot_digest
    }

    pub fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }

    pub const fn connection_revision(&self) -> u64 {
        self.connection_revision
    }

    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConnectionState {
    Disconnected,
    PendingAuth,
    Probing,
    Connected,
    Degraded,
    Expired,
    Revoked,
    WrongAccount,
    MissingScopes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionConnectionStatus {
    state: MissionConnectionState,
    registration_count: usize,
    live_probe_count: usize,
}

impl MissionConnectionStatus {
    pub const fn state(&self) -> MissionConnectionState {
        self.state
    }

    pub const fn registration_count(&self) -> usize {
        self.registration_count
    }

    pub const fn live_probe_count(&self) -> usize {
        self.live_probe_count
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConnectionPluginError {
    #[error("Mission connection request is invalid")]
    InvalidRequest,
    #[error("Mission connection scope is invalid")]
    InvalidScope,
    #[error("Mission connection scope does not match the current Mission")]
    MissionScopeMismatch,
    #[error("Mission revision changed; the old Mission cannot reuse this handle")]
    MissionRevisionChanged,
    #[error("a terminal Mission cannot reuse a connection handle")]
    MissionNotReusable,
    #[error("the requested capability is not enabled by the Mission")]
    CapabilityNotEnabled,
    #[error("the provider registration is missing; status is Disconnected")]
    ProviderRegistrationMissing,
    #[error("the provider registration registry is invalid")]
    InvalidProviderRegistry,
    #[error("the provider connection is not live: {0:?}")]
    NotConnected(ConnectionStatus),
    #[error("the provider connection scope changed")]
    ConnectionScopeMismatch,
    #[error("the capability snapshot is invalid or stale")]
    InvalidCapabilitySnapshot,
    #[error("the opaque connection handle is not mounted")]
    HandleNotMounted,
    #[error("the connection provider rejected the transition")]
    TransitionRejected,
    #[error("the connection plugin persistence boundary failed")]
    Persistence,
}

/// Provider boundary exposed to Mission consumers. The provider can release
/// only a content-free receipt after rechecking Mission and Connection scope.
#[allow(
    dead_code,
    reason = "the provider trait is the stable consumer boundary for future adapters"
)]
pub trait ConnectionPluginProvider {
    fn provide_connection_receipt(
        &mut self,
        handle: &ConnectionAuthHandle,
        now: DateTime<Utc>,
    ) -> Result<ConnectionReceipt, ConnectionPluginError>;
}

/// Consumer boundary: a consumer receives a delivery and retains only the
/// composable receipt returned by the host provider.
#[allow(
    dead_code,
    reason = "the consumer trait is the stable provider boundary for future adapters"
)]
pub trait ConnectionPluginConsumer {
    fn consume_connection(
        &mut self,
        provider: &mut dyn ConnectionPluginProvider,
        delivery: &ConnectionPluginDelivery,
        now: DateTime<Utc>,
    ) -> Result<ConnectionReceipt, ConnectionPluginError>;
}

#[derive(Clone, Debug)]
struct MountedConnection {
    consumer_id: String,
    scope: ConnectionPluginScope,
    required_capabilities: BTreeSet<String>,
    capability_snapshot: ConnectionCapabilitySnapshot,
}

/// Host-owned Mission-scoped Connection service. Handles are process-local:
/// dropping this service drops every mounted capability, which is the crash
/// cleanup boundary. Reopening the service cannot revive an old handle.
#[derive(Debug)]
pub struct MissionConnectionService<'a> {
    store: &'a mut ProjectStore,
    provider_registry: Option<ProviderAdapterRegistry>,
    mounted: HashMap<ConnectionAuthHandle, MountedConnection>,
}

impl ProjectStore {
    pub fn connection_plugin_service(&mut self) -> MissionConnectionService<'_> {
        MissionConnectionService::new(self)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the request binds every Mission, provider, account, consumer, objective, and capability scope"
    )]
    pub fn connection_plugin_request(
        &self,
        mission: &Mission,
        connection_id: ConnectionId,
        provider: impl Into<String>,
        account_id: AccountId,
        consumer_id: impl Into<String>,
        objective_digest: impl Into<String>,
        required_capabilities: impl IntoIterator<Item = String>,
    ) -> Result<MissionConnectionRequest, ConnectionPluginError> {
        MissionConnectionRequest::for_mission(
            mission,
            connection_id,
            provider,
            account_id,
            consumer_id,
            objective_digest,
            required_capabilities,
        )
    }

    pub fn connection_plugin_consumer(
        &self,
        mission: &Mission,
        consumer_id: impl Into<String>,
    ) -> Result<MissionConnectionConsumer, ConnectionPluginError> {
        MissionConnectionConsumer::new(mission, consumer_id)
    }

    pub fn connection_plugin_service_with_registry(
        &mut self,
        provider_registry: ProviderAdapterRegistry,
    ) -> Result<MissionConnectionService<'_>, ConnectionPluginError> {
        MissionConnectionService::with_registry(self, provider_registry)
    }
}

impl<'a> MissionConnectionService<'a> {
    pub fn new(store: &'a mut ProjectStore) -> Self {
        Self {
            store,
            provider_registry: None,
            mounted: HashMap::new(),
        }
    }

    pub fn with_registry(
        store: &'a mut ProjectStore,
        provider_registry: ProviderAdapterRegistry,
    ) -> Result<Self, ConnectionPluginError> {
        provider_registry
            .validate()
            .map_err(|_| ConnectionPluginError::InvalidProviderRegistry)?;
        Ok(Self {
            store,
            provider_registry: Some(provider_registry),
            mounted: HashMap::new(),
        })
    }

    pub fn active_handle_count(&self) -> usize {
        self.mounted.len()
    }

    pub fn status_for(
        &self,
        project_id: &ProjectId,
        provider: &str,
        account_id: Option<&AccountId>,
        now: DateTime<Utc>,
    ) -> Result<MissionConnectionStatus, ConnectionPluginError> {
        if !self.registry_supports_provider(provider) {
            return Ok(MissionConnectionStatus {
                state: MissionConnectionState::Disconnected,
                registration_count: 0,
                live_probe_count: 0,
            });
        }
        let connections = self
            .store
            .list_connections(project_id)
            .map_err(|_| ConnectionPluginError::Persistence)?;
        let matching = connections
            .iter()
            .filter(|connection| {
                connection.provider() == provider
                    && account_id.is_none_or(|account| connection.account_id() == account)
            })
            .collect::<Vec<_>>();
        let live_probe_count = matching
            .iter()
            .filter(|connection| connection.is_connected(now))
            .count();
        let state = matching
            .iter()
            .map(|connection| connection_state(&connection.effective_status(now)))
            .max_by_key(|state| connection_state_rank(*state))
            .unwrap_or(MissionConnectionState::Disconnected);
        Ok(MissionConnectionStatus {
            state,
            registration_count: matching.len(),
            live_probe_count,
        })
    }

    pub fn request_connection(
        &mut self,
        request: &MissionConnectionRequest,
        now: DateTime<Utc>,
    ) -> Result<ConnectionPluginDelivery, ConnectionPluginError> {
        request.validate()?;
        if !self.registry_supports_capabilities(request.provider(), request.required_capabilities())
        {
            return Err(ConnectionPluginError::ProviderRegistrationMissing);
        }
        let mission = self
            .store
            .load_mission(request.project_id(), request.mission_id())
            .map_err(|_| ConnectionPluginError::MissionScopeMismatch)?;
        request.validate_for_mission(&mission)?;

        let registrations = self
            .store
            .list_connections(request.project_id())
            .map_err(|_| ConnectionPluginError::Persistence)?;
        if registrations.is_empty() {
            return Err(ConnectionPluginError::ProviderRegistrationMissing);
        }
        let connection = self
            .store
            .load_connection(request.project_id(), request.connection_id())
            .map_err(|error| match error {
                StorageError::ScopedRecordNotFound { .. } => {
                    ConnectionPluginError::ProviderRegistrationMissing
                }
                _ => ConnectionPluginError::Persistence,
            })?;
        validate_connection_request_scope(request, &connection)?;
        let capability_snapshot = ConnectionCapabilitySnapshot::from_connection(
            &connection,
            request.required_capabilities(),
            now,
        )?;
        let scope = request.scope();
        scope.validate()?;
        let handle = ConnectionAuthHandle::new();
        self.record_plugin_event(
            &scope,
            "connection.plugin.requested",
            &json!({
                "provider": scope.provider,
                "accountId": scope.account_id,
                "connectionId": scope.connection_id,
                "consumerId": request.consumer_id,
                "objectiveDigest": request.objective_digest,
                "capabilitySnapshotDigest": capability_snapshot.snapshot_digest,
                "connectionRevision": capability_snapshot.connection_revision,
            }),
            now,
        )?;
        self.mounted.insert(
            handle.clone(),
            MountedConnection {
                consumer_id: request.consumer_id.clone(),
                scope: scope.clone(),
                required_capabilities: request.required_capabilities.clone(),
                capability_snapshot: capability_snapshot.clone(),
            },
        );
        Ok(ConnectionPluginDelivery {
            handle,
            scope,
            capability_snapshot,
        })
    }

    pub fn provide_connection_receipt(
        &mut self,
        handle: &ConnectionAuthHandle,
        now: DateTime<Utc>,
    ) -> Result<ConnectionReceipt, ConnectionPluginError> {
        let mounted = self
            .mounted
            .get(handle)
            .cloned()
            .ok_or(ConnectionPluginError::HandleNotMounted)?;
        let Ok(mission) = self
            .store
            .load_mission(&mounted.scope.project_id, &mounted.scope.mission_id)
        else {
            self.mounted.remove(handle);
            return Err(ConnectionPluginError::MissionScopeMismatch);
        };
        if let Err(error) = validate_mounted_mission(&mounted.scope, &mission) {
            self.mounted.remove(handle);
            return Err(error);
        }
        let Ok(connection) = self
            .store
            .load_connection(&mounted.scope.project_id, &mounted.scope.connection_id)
        else {
            self.mounted.remove(handle);
            return Err(ConnectionPluginError::ProviderRegistrationMissing);
        };
        if let Err(error) = validate_mounted_connection(&mounted, &connection) {
            self.mounted.remove(handle);
            return Err(error);
        }
        let capability_snapshot = match ConnectionCapabilitySnapshot::from_connection(
            &connection,
            &mounted.required_capabilities,
            now,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.mounted.remove(handle);
                return Err(error);
            }
        };
        let receipt = ConnectionReceipt::issue(&mounted.scope, &capability_snapshot, now)?;
        self.record_plugin_event(
            &mounted.scope,
            "connection.plugin.receipt_issued",
            &json!({
                "provider": mounted.scope.provider,
                "accountId": mounted.scope.account_id,
                "connectionId": mounted.scope.connection_id,
                "consumerId": mounted.consumer_id,
                "receiptDigest": receipt.receipt_digest,
                "capabilitySnapshotDigest": receipt.capability_snapshot_digest,
            }),
            now,
        )?;
        self.mounted.remove(handle);
        Ok(receipt)
    }

    pub fn disconnect(
        &mut self,
        handle: &ConnectionAuthHandle,
        now: DateTime<Utc>,
    ) -> Result<(), ConnectionPluginError> {
        let mounted = self
            .mounted
            .remove(handle)
            .ok_or(ConnectionPluginError::HandleNotMounted)?;
        self.record_plugin_event(
            &mounted.scope,
            "connection.plugin.disconnected",
            &plugin_event_payload(&mounted, "disconnected"),
            now,
        )
    }

    pub fn revoke(
        &mut self,
        handle: &ConnectionAuthHandle,
        now: DateTime<Utc>,
    ) -> Result<(), ConnectionPluginError> {
        let mounted = self
            .mounted
            .remove(handle)
            .ok_or(ConnectionPluginError::HandleNotMounted)?;
        let mut connection = self
            .store
            .load_connection(&mounted.scope.project_id, &mounted.scope.connection_id)
            .map_err(|_| ConnectionPluginError::ProviderRegistrationMissing)?;
        validate_mounted_connection(&mounted, &connection)?;
        let expected_revision = connection.revision();
        if connection.effective_status(now) != ConnectionStatus::Revoked {
            connection
                .revoke(now)
                .map_err(|_| ConnectionPluginError::TransitionRejected)?;
            self.store
                .update_connection(
                    &connection,
                    expected_revision,
                    "connection.plugin.revoked",
                    &json!({
                        "reason": "mission_connection_plugin",
                        "connectionId": mounted.scope.connection_id,
                    }),
                    now,
                )
                .map_err(|_| ConnectionPluginError::Persistence)?;
        }
        self.remove_connection_handles(&mounted.scope.project_id, &mounted.scope.connection_id);
        self.record_plugin_event(
            &mounted.scope,
            "connection.plugin.revoked",
            &plugin_event_payload(&mounted, "revoked"),
            now,
        )
    }

    pub fn reclaim_crashed_consumer(
        &mut self,
        consumer_id: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, ConnectionPluginError> {
        if !valid_identifier(consumer_id) {
            return Err(ConnectionPluginError::InvalidRequest);
        }
        let handles = self
            .mounted
            .iter()
            .filter(|(_, mounted)| mounted.consumer_id == consumer_id)
            .map(|(handle, _)| handle.clone())
            .collect::<Vec<_>>();
        let reclaimed = handles
            .into_iter()
            .filter_map(|handle| self.mounted.remove(&handle))
            .collect::<Vec<_>>();
        for mounted in &reclaimed {
            self.record_plugin_event(
                &mounted.scope,
                "connection.plugin.handle_reclaimed",
                &plugin_event_payload(mounted, "crash_reclaimed"),
                now,
            )?;
        }
        Ok(reclaimed.len())
    }

    fn remove_connection_handles(&mut self, project_id: &ProjectId, connection_id: &ConnectionId) {
        self.mounted.retain(|_, mounted| {
            mounted.scope.project_id != *project_id || mounted.scope.connection_id != *connection_id
        });
    }

    fn registry_supports_provider(&self, provider: &str) -> bool {
        self.provider_registry.as_ref().is_some_and(|registry| {
            !registry.is_empty()
                && registry
                    .registrations()
                    .iter()
                    .any(|registration| registration.key().provider_id() == provider)
        })
    }

    fn registry_supports_capabilities(
        &self,
        provider: &str,
        capabilities: &BTreeSet<String>,
    ) -> bool {
        self.provider_registry.as_ref().is_some_and(|registry| {
            !registry.is_empty()
                && capabilities.iter().all(|capability| {
                    registry.registrations().iter().any(|registration| {
                        registration.key().provider_id() == provider
                            && registration.key().capability_id() == capability
                    })
                })
        })
    }

    fn record_plugin_event(
        &mut self,
        scope: &ConnectionPluginScope,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), ConnectionPluginError> {
        self.store
            .append_event(
                &scope.project_id,
                Some(&scope.mission_id),
                event_type,
                payload,
                recorded_at,
            )
            .map(|_| ())
            .map_err(|_| ConnectionPluginError::Persistence)
    }
}

impl Drop for MissionConnectionService<'_> {
    fn drop(&mut self) {
        self.mounted.clear();
    }
}

impl ConnectionPluginProvider for MissionConnectionService<'_> {
    fn provide_connection_receipt(
        &mut self,
        handle: &ConnectionAuthHandle,
        now: DateTime<Utc>,
    ) -> Result<ConnectionReceipt, ConnectionPluginError> {
        self.provide_connection_receipt(handle, now)
    }
}

/// A Mission consumer that stores only connection receipts. It cannot retain
/// a host handle or reach the ProjectStore directly.
#[derive(Clone, Debug)]
#[allow(
    dead_code,
    reason = "the consumer is intentionally exposed through the connection registration seam"
)]
pub struct MissionConnectionConsumer {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    consumer_id: String,
    receipts: BTreeMap<ConnectionId, ConnectionReceipt>,
}

#[allow(
    dead_code,
    reason = "consumer accessors are part of the provider/consumer seam"
)]
impl MissionConnectionConsumer {
    pub fn new(
        mission: &Mission,
        consumer_id: impl Into<String>,
    ) -> Result<Self, ConnectionPluginError> {
        let consumer_id = consumer_id.into().trim().to_owned();
        if !valid_identifier(&consumer_id)
            || !valid_identifier(mission.tenant_id.as_str())
            || !valid_identifier(mission.project_id.as_str())
            || !valid_identifier(mission.id.as_str())
            || mission.revision == 0
        {
            return Err(ConnectionPluginError::InvalidRequest);
        }
        Ok(Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            mission_revision: mission.revision,
            consumer_id,
            receipts: BTreeMap::new(),
        })
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub fn receipt(&self, connection_id: &ConnectionId) -> Option<&ConnectionReceipt> {
        self.receipts.get(connection_id)
    }

    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    pub fn composed_receipt_digest(&self) -> Result<Option<String>, ConnectionPluginError> {
        if self.receipts.is_empty() {
            return Ok(None);
        }
        digest_json(&self.receipts.values().collect::<Vec<_>>()).map(Some)
    }

    pub fn consume_with_service(
        &mut self,
        provider: &mut MissionConnectionService<'_>,
        delivery: &ConnectionPluginDelivery,
        now: DateTime<Utc>,
    ) -> Result<ConnectionReceipt, ConnectionPluginError> {
        self.consume_connection(provider, delivery, now)
    }
}

impl ConnectionPluginConsumer for MissionConnectionConsumer {
    fn consume_connection(
        &mut self,
        provider: &mut dyn ConnectionPluginProvider,
        delivery: &ConnectionPluginDelivery,
        now: DateTime<Utc>,
    ) -> Result<ConnectionReceipt, ConnectionPluginError> {
        let scope = delivery.scope();
        if scope.tenant_id != self.tenant_id
            || scope.project_id != self.project_id
            || scope.mission_id != self.mission_id
            || scope.mission_revision != self.mission_revision
        {
            return Err(ConnectionPluginError::MissionScopeMismatch);
        }
        let receipt = provider.provide_connection_receipt(delivery.handle(), now)?;
        if receipt.tenant_id != self.tenant_id
            || receipt.project_id != self.project_id
            || receipt.mission_id != self.mission_id
            || receipt.mission_revision != self.mission_revision
            || receipt.connection_id != *scope.connection_id()
            || receipt.provider != scope.provider
            || receipt.account_id != *scope.account_id()
        {
            return Err(ConnectionPluginError::ConnectionScopeMismatch);
        }
        if let Some(existing) = self.receipts.get(&receipt.connection_id) {
            if existing != &receipt {
                return Err(ConnectionPluginError::ConnectionScopeMismatch);
            }
        } else {
            self.receipts
                .insert(receipt.connection_id.clone(), receipt.clone());
        }
        Ok(receipt)
    }
}

fn validate_connection_request_scope(
    request: &MissionConnectionRequest,
    connection: &Connection,
) -> Result<(), ConnectionPluginError> {
    if connection.tenant_id() != request.tenant_id()
        || connection.project_id() != request.project_id()
        || connection.id() != request.connection_id()
        || connection.provider() != request.provider()
        || connection.account_id() != request.account_id()
    {
        return Err(ConnectionPluginError::ConnectionScopeMismatch);
    }
    Ok(())
}

fn validate_mounted_mission(
    scope: &ConnectionPluginScope,
    mission: &Mission,
) -> Result<(), ConnectionPluginError> {
    if scope.tenant_id != mission.tenant_id
        || scope.project_id != mission.project_id
        || scope.mission_id != mission.id
    {
        return Err(ConnectionPluginError::MissionScopeMismatch);
    }
    if scope.mission_revision != mission.revision {
        return Err(ConnectionPluginError::MissionRevisionChanged);
    }
    if mission.stage.is_terminal() {
        return Err(ConnectionPluginError::MissionNotReusable);
    }
    Ok(())
}

fn validate_mounted_connection(
    mounted: &MountedConnection,
    connection: &Connection,
) -> Result<(), ConnectionPluginError> {
    if connection.tenant_id() != &mounted.scope.tenant_id
        || connection.project_id() != &mounted.scope.project_id
        || connection.id() != &mounted.scope.connection_id
        || connection.provider() != mounted.scope.provider
        || connection.account_id() != &mounted.scope.account_id
        || connection.revision() != mounted.capability_snapshot.connection_revision
    {
        return Err(ConnectionPluginError::ConnectionScopeMismatch);
    }
    Ok(())
}

fn plugin_event_payload(mounted: &MountedConnection, status: &str) -> Value {
    json!({
        "provider": mounted.scope.provider,
        "accountId": mounted.scope.account_id,
        "connectionId": mounted.scope.connection_id,
        "consumerId": mounted.consumer_id,
        "status": status,
        "capabilitySnapshotDigest": mounted.capability_snapshot.snapshot_digest,
        "connectionRevision": mounted.capability_snapshot.connection_revision,
    })
}

fn connection_state(status: &ConnectionStatus) -> MissionConnectionState {
    match status {
        ConnectionStatus::PendingAuth => MissionConnectionState::PendingAuth,
        ConnectionStatus::Probing => MissionConnectionState::Probing,
        ConnectionStatus::Connected => MissionConnectionState::Connected,
        ConnectionStatus::Degraded => MissionConnectionState::Degraded,
        ConnectionStatus::Expired => MissionConnectionState::Expired,
        ConnectionStatus::Revoked => MissionConnectionState::Revoked,
        ConnectionStatus::WrongAccount => MissionConnectionState::WrongAccount,
        ConnectionStatus::MissingScopes => MissionConnectionState::MissingScopes,
    }
}

const fn connection_state_rank(state: MissionConnectionState) -> u8 {
    match state {
        MissionConnectionState::Disconnected => 0,
        MissionConnectionState::Revoked => 1,
        MissionConnectionState::WrongAccount => 2,
        MissionConnectionState::MissingScopes => 3,
        MissionConnectionState::Expired => 4,
        MissionConnectionState::PendingAuth => 5,
        MissionConnectionState::Degraded => 6,
        MissionConnectionState::Probing => 7,
        MissionConnectionState::Connected => 8,
    }
}

fn normalize_capabilities(values: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 128
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, ConnectionPluginError> {
    let encoded = serde_json::to_vec(value).map_err(|_| ConnectionPluginError::Persistence)?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn validate_project_scope(
    project: &Project,
    registration: &LocalProjectCloudRegistration,
) -> Result<(), StorageError> {
    let cell = match project.data_cell {
        Some(ProjectDataCell::Us) => "us",
        Some(ProjectDataCell::Eu) => "eu",
        None => "",
    };
    if project.tenant_id != registration.tenant_id
        || project.id != registration.project_id
        || project.storage_mode != StorageMode::LocalEncryptedSync
        || cell != registration.cell
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn persist_cell_selection(
    transaction: &Transaction<'_>,
    stored: &Project,
    selected: &Project,
    expected_revision: u64,
) -> Result<(), StorageError> {
    if stored.revision != expected_revision {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("project:{}", selected.id),
            expected_revision,
        });
    }
    if selected.revision == stored.revision && selected == stored {
        return Ok(());
    }
    if selected.revision != next_revision(stored.revision)?
        || stored.data_cell.is_some()
        || selected.data_cell.is_none()
    {
        return Err(StorageError::UnexpectedNewerRevision {
            expected_revision: stored.revision,
            actual: selected.revision,
        });
    }
    update_project_normalized_cas(transaction, selected, stored.revision)
}

fn insert_registration(
    transaction: &Transaction<'_>,
    registration: &LocalProjectCloudRegistration,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO project_cloud_registrations
           (tenant_id, project_id, cell, encryption_mode, remote_execution_opt_in,
            idempotency_key_digest, intent_digest, request_digest, key_version,
            content_digest, request_json, authorized_by, authorization_evidence_digest,
            status, remote_revision, remote_duplicate, last_error_code, revision, created_at,
            updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 'prepared', NULL, 0, NULL, ?14, ?15, ?15)",
        params![
            registration.tenant_id.as_str(),
            registration.project_id.as_str(),
            registration.cell,
            registration.encryption_mode,
            i64::from(registration.remote_execution_opt_in),
            registration.idempotency_key_digest,
            registration.intent_digest,
            registration.request_digest,
            to_sql_u64(registration.key_version)?,
            registration.content_digest,
            serde_json::to_string(&registration.request)?,
            registration.authorized_by,
            registration.authorization_evidence_digest,
            to_sql_u64(registration.revision)?,
            registration.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn update_registration(
    transaction: &Transaction<'_>,
    registration: &LocalProjectCloudRegistration,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE project_cloud_registrations
         SET status = ?3, remote_revision = ?4, remote_duplicate = ?5,
             last_error_code = ?6, revision = ?7, updated_at = ?8
         WHERE project_id = ?1 AND revision = ?2",
        params![
            registration.project_id.as_str(),
            to_sql_u64(expected_revision)?,
            status_name(registration.status),
            registration.remote_revision.map(to_sql_u64).transpose()?,
            i64::from(registration.remote_duplicate),
            registration.last_error_code,
            to_sql_u64(registration.revision)?,
            registration.updated_at.to_rfc3339(),
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("project_cloud_registration:{}", registration.project_id),
            expected_revision,
        });
    }
    Ok(())
}

fn load_registration_required(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
) -> Result<LocalProjectCloudRegistration, StorageError> {
    load_registration(transaction, project_id)?.ok_or_else(|| StorageError::ScopedRecordNotFound {
        kind: "project cloud registration",
        project_id: project_id.clone(),
        id: project_id.to_string(),
    })
}

fn load_registration(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
) -> Result<Option<LocalProjectCloudRegistration>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, cell, encryption_mode, remote_execution_opt_in,
                    idempotency_key_digest, intent_digest, request_digest, key_version,
                    content_digest, request_json, authorized_by, authorization_evidence_digest,
                    status, remote_revision, remote_duplicate, last_error_code, revision,
                    created_at, updated_at
             FROM project_cloud_registrations WHERE project_id = ?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, Option<String>>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let registration = LocalProjectCloudRegistration {
            tenant_id: TenantId::from_stable(row.0),
            project_id: project_id.clone(),
            cell: row.1,
            encryption_mode: row.2,
            remote_execution_opt_in: parse_bool(row.3)?,
            idempotency_key_digest: row.4,
            intent_digest: row.5,
            request_digest: row.6,
            key_version: from_sql_u64(row.7, "registration key version")?,
            content_digest: row.8,
            request: serde_json::from_str(&row.9)?,
            authorized_by: row.10,
            authorization_evidence_digest: row.11,
            status: decode_status(&row.12)?,
            remote_revision: row
                .13
                .map(|value| from_sql_u64(value, "registration remote revision"))
                .transpose()?,
            remote_duplicate: parse_bool(row.14)?,
            last_error_code: row.15,
            revision: from_sql_u64(row.16, "registration revision")?,
            created_at: parse_time(&row.17)?,
            updated_at: parse_time(&row.18)?,
        };
        registration.validate()?;
        Ok(registration)
    })
    .transpose()
}

fn event_payload(registration: &LocalProjectCloudRegistration) -> Value {
    json!({
        "cell": registration.cell,
        "encryptionMode": registration.encryption_mode,
        "remoteExecutionOptIn": registration.remote_execution_opt_in,
        "idempotencyKeyDigest": registration.idempotency_key_digest,
        "intentDigest": registration.intent_digest,
        "requestDigest": registration.request_digest,
        "keyVersion": registration.key_version,
        "contentDigest": registration.content_digest,
        "authorizedBy": registration.authorized_by,
        "authorizationEvidenceDigest": registration.authorization_evidence_digest,
        "status": registration.status,
        "remoteRevision": registration.remote_revision,
        "remoteDuplicate": registration.remote_duplicate,
        "lastErrorCode": registration.last_error_code,
    })
}

const fn status_name(status: ProjectCloudRegistrationStatus) -> &'static str {
    match status {
        ProjectCloudRegistrationStatus::Prepared => "prepared",
        ProjectCloudRegistrationStatus::Applied => "applied",
        ProjectCloudRegistrationStatus::Conflict => "conflict",
    }
}

fn decode_status(value: &str) -> Result<ProjectCloudRegistrationStatus, StorageError> {
    match value {
        "prepared" => Ok(ProjectCloudRegistrationStatus::Prepared),
        "applied" => Ok(ProjectCloudRegistrationStatus::Applied),
        "conflict" => Ok(ProjectCloudRegistrationStatus::Conflict),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid project cloud registration status: {value}"
        ))),
    }
}

fn parse_bool(value: i64) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid project cloud registration boolean: {value}"
        ))),
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| StorageError::DomainDecode(format!("invalid timestamp: {value}")))
}

fn next_revision(value: u64) -> Result<u64, StorageError> {
    value
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(value))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::{Duration, TimeZone};
    use proptest::prelude::*;

    use super::*;
    use crate::PendingEvent;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 16, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup() -> (ProjectStore, Project) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-registration"),
            ProjectId::from("project-registration"),
            "Private launch strategy",
            "private customer and campaign metadata",
            PathBuf::from("/tmp/hartevo-project-registration"),
            StorageMode::LocalEncryptedSync,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), now())],
            )
            .expect("persist project");
        (store, project)
    }

    fn registration(project: &Project) -> LocalProjectCloudRegistration {
        let request = json!({
            "scope": {"cell": "eu", "tenantId": project.tenant_id},
            "projectId": project.id,
            "encryptionMode": "team_envelope",
            "remoteExecutionOptIn": false,
            "metadataDigest": "c".repeat(64),
            "initialPayload": {
                "keyVersion": 1,
                "nonce": vec![7; 12],
                "ciphertext": vec![9; 32],
                "aadDigest": "a".repeat(64),
                "contentDigest": "c".repeat(64),
            },
            "idempotencyKeyDigest": "d".repeat(64),
            "createdAt": now(),
        });
        LocalProjectCloudRegistration {
            tenant_id: project.tenant_id.clone(),
            project_id: project.id.clone(),
            cell: "eu".into(),
            encryption_mode: "team_envelope".into(),
            remote_execution_opt_in: false,
            idempotency_key_digest: "d".repeat(64),
            intent_digest: "e".repeat(64),
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            key_version: 1,
            content_digest: "c".repeat(64),
            request,
            authorized_by: "owner-device".into(),
            authorization_evidence_digest: "f".repeat(64),
            status: ProjectCloudRegistrationStatus::Prepared,
            remote_revision: None,
            remote_duplicate: false,
            last_error_code: None,
            revision: 1,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    fn provider_registry() -> ProviderAdapterRegistry {
        use hartevo_effect_broker::{
            ProviderAdapterIdentity, ProviderAdapterOperation, ProviderCapabilityKey,
            ProviderCapabilitySupport, ProviderEvidenceClass, ProviderEvidenceSupport,
            ProviderProvenanceClass,
        };

        let key = ProviderCapabilityKey::new("google-search-console", "sites.read")
            .expect("provider capability");
        let adapter = ProviderAdapterIdentity::new("google-search-console.adapter", 1)
            .expect("provider adapter");
        let support = ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Probe,
            ProviderEvidenceClass::ProbeObservation,
            ProviderProvenanceClass::ControlledProvider,
        )
        .expect("provider support");
        ProviderAdapterRegistry::new(
            "connection-plugin-test",
            [ProviderCapabilitySupport::new(key, adapter, [support]).expect("registration")],
        )
        .expect("provider registry")
    }

    fn connection_plugin_fixture() -> (ProjectStore, Project, Mission, Connection) {
        let (mut store, project) = setup();
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-connection-plugin"),
            project.id.clone(),
            "Use the connected search provider",
            hartevo_domain_kernel::MissionContract::bootstrap(
                "Find the latest search performance",
                ["sites.read".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new("mission.created", json!({}), now())],
            )
            .expect("persist mission");

        let mut connection = Connection::register(
            ConnectionId::from("connection-plugin"),
            project.tenant_id.clone(),
            project.id.clone(),
            "google-search-console",
            AccountId::from("account-plugin"),
            "owner@example.com",
            ["sites.read".into()],
            now(),
        )
        .expect("connection");
        store
            .create_connection(&connection, "connection.registered", &json!({}), now())
            .expect("persist connection");
        connection.begin_probe(now()).expect("begin probe");
        store
            .update_connection(
                &connection,
                1,
                "connection.probe_started",
                &json!({}),
                now(),
            )
            .expect("persist probe start");
        connection
            .apply_probe(
                hartevo_domain_kernel::ConnectionProbe {
                    outcome: hartevo_domain_kernel::ProbeOutcome::Successful,
                    observed_external_account_id: "owner@example.com".into(),
                    granted_scopes: BTreeSet::from(["sites.read".into()]),
                    probed_at: now(),
                    valid_until: now() + Duration::minutes(30),
                    credential_expires_at: now() + Duration::hours(1),
                    evidence_digest: "a".repeat(64),
                },
                now(),
            )
            .expect("apply probe");
        store
            .update_connection(&connection, 2, "connection.probed", &json!({}), now())
            .expect("persist probe");
        (store, project, mission, connection)
    }

    fn connection_plugin_request(
        mission: &Mission,
        connection: &Connection,
        consumer_id: &str,
    ) -> MissionConnectionRequest {
        MissionConnectionRequest::for_mission(
            mission,
            connection.id().clone(),
            connection.provider(),
            connection.account_id().clone(),
            consumer_id,
            digest("user objective contains secret-token-but-only-digest-is-stored"),
            ["sites.read".into()],
        )
        .expect("connection request")
    }

    #[test]
    fn mission_connection_delivery_returns_only_a_scoped_receipt_and_redacts_logs() {
        let (mut store, project, mission, connection) = connection_plugin_fixture();
        let request = connection_plugin_request(&mission, &connection, "consumer-search");
        let mut consumer =
            MissionConnectionConsumer::new(&mission, "consumer-search").expect("consumer");
        let (delivery_debug, receipt) = {
            let mut service = store
                .connection_plugin_service_with_registry(provider_registry())
                .expect("provider registry");
            let delivery = service
                .request_connection(&request, now())
                .expect("mount connection");
            let delivery_debug = format!("{delivery:?}");
            let receipt = consumer
                .consume_connection(&mut service, &delivery, now())
                .expect("consume connection");
            assert_eq!(service.active_handle_count(), 0);
            (delivery_debug, receipt)
        };
        assert_eq!(receipt.tenant_id(), &project.tenant_id);
        assert_eq!(receipt.project_id(), &project.id);
        assert_eq!(receipt.mission_id(), &mission.id);
        assert_eq!(receipt.provider(), connection.provider());
        assert!(receipt.supports("sites.read"));
        assert!(!delivery_debug.contains("secret-token"));
        assert!(delivery_debug.contains("REDACTED"));
        assert_eq!(consumer.receipt_count(), 1);
        assert!(
            consumer
                .composed_receipt_digest()
                .expect("composition")
                .is_some()
        );

        let events = store
            .events_for_mission(&project.id, &mission.id)
            .expect("mission events");
        let events_json = serde_json::to_string(&events).expect("event JSON");
        assert!(events_json.contains("connection.plugin.requested"));
        assert!(events_json.contains("connection.plugin.receipt_issued"));
        assert!(!events_json.contains("secret-token"));
        assert!(!events_json.contains("access-token"));
        assert!(!format!("{receipt:?}").contains("secret-token"));
    }

    #[test]
    fn reopened_service_reclaims_old_handle_and_rejects_a_stale_mission_revision() {
        let (mut store, _project, mission, connection) = connection_plugin_fixture();
        let request = connection_plugin_request(&mission, &connection, "consumer-reopen");
        let old_handle = {
            let mut service = store
                .connection_plugin_service_with_registry(provider_registry())
                .expect("provider registry");
            service
                .request_connection(&request, now())
                .expect("mount before restart")
                .handle()
                .clone()
        };
        {
            let mut reopened = store
                .connection_plugin_service_with_registry(provider_registry())
                .expect("provider registry");
            assert_eq!(
                reopened.provide_connection_receipt(&old_handle, now()),
                Err(ConnectionPluginError::HandleNotMounted)
            );
            let fresh = reopened
                .request_connection(&request, now())
                .expect("new handle after restart");
            assert_ne!(fresh.handle(), &old_handle);
            reopened
                .disconnect(fresh.handle(), now())
                .expect("disconnect fresh handle");
        }

        let mut revised_mission = mission.clone();
        revised_mission
            .start_research([], now() + Duration::seconds(1))
            .expect("advance mission revision");
        store
            .save_mission(&revised_mission)
            .expect("persist revision");
        let mut reopened = store
            .connection_plugin_service_with_registry(provider_registry())
            .expect("provider registry");
        assert_eq!(
            reopened.request_connection(&request, now() + Duration::seconds(1)),
            Err(ConnectionPluginError::MissionRevisionChanged)
        );
    }

    #[test]
    fn empty_registrations_are_disconnected_and_cross_scope_requests_fail_closed() {
        let (mut empty_store, empty_project) = setup();
        let empty_status = {
            let service = empty_store.connection_plugin_service();
            service
                .status_for(&empty_project.id, "google-search-console", None, now())
                .expect("empty status")
        };
        assert_eq!(empty_status.state(), MissionConnectionState::Disconnected);
        assert_eq!(empty_status.registration_count(), 0);
        assert_eq!(empty_status.live_probe_count(), 0);

        let (mut live_store, live_project, _live_mission, live_connection) =
            connection_plugin_fixture();
        let no_registry_status = {
            let service = live_store.connection_plugin_service();
            service
                .status_for(
                    &live_project.id,
                    live_connection.provider(),
                    Some(live_connection.account_id()),
                    now(),
                )
                .expect("no registry status")
        };
        assert_eq!(
            no_registry_status.state(),
            MissionConnectionState::Disconnected
        );
        assert_eq!(no_registry_status.registration_count(), 0);

        let (mut store, _project, mission, connection) = connection_plugin_fixture();
        let mut cross_scope = connection_plugin_request(&mission, &connection, "consumer-cross");
        cross_scope.tenant_id = TenantId::from("tenant-other");
        let mut service = store
            .connection_plugin_service_with_registry(provider_registry())
            .expect("provider registry");
        assert_eq!(
            service.request_connection(&cross_scope, now()),
            Err(ConnectionPluginError::MissionScopeMismatch)
        );

        let mut cross_account = connection_plugin_request(&mission, &connection, "consumer-cross");
        cross_account.account_id = AccountId::from("account-other");
        assert_eq!(
            service.request_connection(&cross_account, now()),
            Err(ConnectionPluginError::ConnectionScopeMismatch)
        );
    }

    #[test]
    fn revoke_and_crash_reclaim_remove_handles_and_revoke_the_provider_connection() {
        let (mut store, project, mission, connection) = connection_plugin_fixture();
        let request = connection_plugin_request(&mission, &connection, "consumer-crash");
        let (crashed_handle, revoked_handle) = {
            let mut service = store
                .connection_plugin_service_with_registry(provider_registry())
                .expect("provider registry");
            let crashed = service
                .request_connection(&request, now())
                .expect("crashed consumer handle");
            let revoked = service
                .request_connection(&request, now())
                .expect("revoked consumer handle");
            assert_eq!(
                service.reclaim_crashed_consumer("consumer-crash", now()),
                Ok(2)
            );
            let new_handle = service
                .request_connection(&request, now())
                .expect("handle to revoke");
            assert_eq!(
                service.reclaim_crashed_consumer("consumer-other", now()),
                Ok(0)
            );
            service
                .revoke(new_handle.handle(), now())
                .expect("revoke connection");
            (crashed.handle().clone(), revoked.handle().clone())
        };
        let mut service = store
            .connection_plugin_service_with_registry(provider_registry())
            .expect("provider registry");
        assert_eq!(
            service.provide_connection_receipt(&crashed_handle, now()),
            Err(ConnectionPluginError::HandleNotMounted)
        );
        assert_eq!(
            service.provide_connection_receipt(&revoked_handle, now()),
            Err(ConnectionPluginError::HandleNotMounted)
        );
        drop(service);
        let stored = store
            .load_connection(&project.id, &connection.id().clone())
            .expect("revoked connection");
        assert_eq!(stored.effective_status(now()), ConnectionStatus::Revoked);
        let status = {
            let service = store
                .connection_plugin_service_with_registry(provider_registry())
                .expect("provider registry");
            service
                .status_for(
                    &project.id,
                    connection.provider(),
                    Some(connection.account_id()),
                    now(),
                )
                .expect("revoked status")
        };
        assert_eq!(status.state(), MissionConnectionState::Revoked);
    }

    #[derive(Clone, Copy, Debug)]
    enum RegistrationAction {
        ReplayExact,
        ReplayChangedIntent,
        Apply {
            expected_revision: u8,
            remote_revision: u8,
            duplicate: bool,
        },
        Conflict {
            expected_revision: u8,
            valid_code: bool,
        },
    }

    fn registration_action() -> impl Strategy<Value = RegistrationAction> {
        prop_oneof![
            Just(RegistrationAction::ReplayExact),
            Just(RegistrationAction::ReplayChangedIntent),
            (0_u8..4, 0_u8..3, any::<bool>()).prop_map(
                |(expected_revision, remote_revision, duplicate)| RegistrationAction::Apply {
                    expected_revision,
                    remote_revision,
                    duplicate,
                }
            ),
            (0_u8..4, any::<bool>()).prop_map(|(expected_revision, valid_code)| {
                RegistrationAction::Conflict {
                    expected_revision,
                    valid_code,
                }
            }),
        ]
    }

    #[test]
    fn cell_selection_and_exact_registration_are_one_restart_safe_saga() {
        let (mut store, project) = setup();
        let mut selected = project.clone();
        selected
            .select_data_cell(ProjectDataCell::Eu)
            .expect("select EU");
        let prepared = registration(&selected);
        let first = store
            .prepare_project_cloud_registration(&selected, 1, &prepared, now())
            .expect("prepare registration");
        assert!(!first.duplicate);
        assert_eq!(
            store.load_project(&project.id).expect("selected project"),
            selected
        );
        let replay = store
            .prepare_project_cloud_registration(&selected, 2, &prepared, now())
            .expect("exact replay");
        assert!(replay.duplicate);
        assert_eq!(replay.registration.request, prepared.request);

        let mut changed = prepared.clone();
        changed.intent_digest = "a".repeat(64);
        assert!(matches!(
            store.prepare_project_cloud_registration(&selected, 2, &changed, now()),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "project cloud registration intent",
                ..
            })
        ));
        assert!(
            store
                .record_project_cloud_registration_applied(&project.id, 1, 2, false, now())
                .is_err()
        );
        let applied = store
            .record_project_cloud_registration_applied(&project.id, 1, 1, false, now())
            .expect("record remote project");
        assert_eq!(
            (applied.status, applied.revision, applied.remote_revision),
            (ProjectCloudRegistrationStatus::Applied, 2, Some(1))
        );
        assert_eq!(
            store
                .record_project_cloud_registration_applied(&project.id, 1, 1, false, now())
                .expect("applied replay"),
            applied
        );

        let audit: String = store
            .connection
            .query_row(
                "SELECT group_concat(payload_json, '') FROM domain_events
                 WHERE project_id = ?1 AND event_type LIKE 'project.cloud_registration.%'",
                [project.id.as_str()],
                |row| row.get(0),
            )
            .expect("project registration audit");
        assert!(!audit.contains("Private launch strategy"));
        assert!(!audit.contains("private customer"));
        assert!(!audit.contains("ciphertext"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn registration_saga_is_exactly_once_and_terminal_under_arbitrary_replays(
            actions in prop::collection::vec(registration_action(), 1..64),
        ) {
            let (mut store, project) = setup();
            let mut selected = project.clone();
            selected.select_data_cell(ProjectDataCell::Eu)?;
            let prepared = registration(&selected);
            let first = store.prepare_project_cloud_registration(
                &selected,
                project.revision,
                &prepared,
                now(),
            )?;
            prop_assert!(!first.duplicate);
            let mut model = prepared.clone();

            for action in actions {
                let before = model.clone();
                match action {
                    RegistrationAction::ReplayExact => {
                        let replay = store.prepare_project_cloud_registration(
                            &selected,
                            selected.revision,
                            &prepared,
                            now(),
                        )?;
                        prop_assert!(replay.duplicate);
                        prop_assert_eq!(replay.registration, model.clone());
                    }
                    RegistrationAction::ReplayChangedIntent => {
                        let mut changed = prepared.clone();
                        changed.intent_digest = "a".repeat(64);
                        let result = store.prepare_project_cloud_registration(
                            &selected,
                            selected.revision,
                            &changed,
                            now(),
                        );
                        let immutable_intent = matches!(
                            result,
                            Err(StorageError::ImmutableRecordMismatch {
                                kind: "project cloud registration intent",
                                ..
                            })
                        );
                        prop_assert!(immutable_intent);
                    }
                    RegistrationAction::Apply {
                        expected_revision,
                        remote_revision,
                        duplicate,
                    } => {
                        let result = store.record_project_cloud_registration_applied(
                            &project.id,
                            u64::from(expected_revision),
                            u64::from(remote_revision),
                            duplicate,
                            now(),
                        );
                        if remote_revision != 1 {
                            let invalid_revision = matches!(result, Err(StorageError::DomainDecode(_)));
                            prop_assert!(invalid_revision);
                        } else if model.status == ProjectCloudRegistrationStatus::Applied {
                            if model.remote_duplicate == duplicate {
                                prop_assert_eq!(result?, model.clone());
                            } else {
                                let immutable_applied = matches!(
                                    result,
                                    Err(StorageError::ImmutableRecordMismatch {
                                        kind: "applied project cloud registration",
                                        ..
                                    })
                                );
                                prop_assert!(immutable_applied);
                            }
                        } else if model.status == ProjectCloudRegistrationStatus::Prepared
                            && u64::from(expected_revision) == model.revision
                        {
                            model.status = ProjectCloudRegistrationStatus::Applied;
                            model.remote_revision = Some(1);
                            model.remote_duplicate = duplicate;
                            model.revision += 1;
                            prop_assert_eq!(result?, model.clone());
                        } else {
                            let optimistic_conflict =
                                matches!(result, Err(StorageError::OptimisticConflict { .. }));
                            prop_assert!(optimistic_conflict);
                        }
                    }
                    RegistrationAction::Conflict {
                        expected_revision,
                        valid_code,
                    } => {
                        let code = if valid_code { "remote_scope_conflict" } else { "" };
                        let result = store.record_project_cloud_registration_conflict(
                            &project.id,
                            u64::from(expected_revision),
                            code,
                            now(),
                        );
                        if !valid_code {
                            let invalid_code = matches!(result, Err(StorageError::DomainDecode(_)));
                            prop_assert!(invalid_code);
                        } else if model.status == ProjectCloudRegistrationStatus::Prepared
                            && u64::from(expected_revision) == model.revision
                        {
                            model.status = ProjectCloudRegistrationStatus::Conflict;
                            model.last_error_code = Some(code.into());
                            model.revision += 1;
                            prop_assert_eq!(result?, model.clone());
                        } else {
                            let optimistic_conflict =
                                matches!(result, Err(StorageError::OptimisticConflict { .. }));
                            prop_assert!(optimistic_conflict);
                        }
                    }
                }

                let stored = store.load_project_cloud_registration(&project.id)?;
                prop_assert_eq!(&stored, &model);
                prop_assert!(stored.revision >= before.revision);
                prop_assert!(stored.revision <= before.revision + 1);
                if before.status != ProjectCloudRegistrationStatus::Prepared {
                    prop_assert_eq!(stored.status, before.status);
                }
            }
        }
    }
}

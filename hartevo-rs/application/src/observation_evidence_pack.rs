//! Mission-scoped Runtime observation intake.
//!
//! The provider and consumer seams are deliberately typed and authority-free:
//! a provider receives only the exact binding requested by Application, while
//! a consumer receives a Pack only after the Mission snapshot, Evidence,
//! Domain Event, and Outbox row have committed.  The durable Event is the
//! model-visible boundary; neither seam receives Store or Effect authority.

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Evidence, EvidenceId, EvidenceStatus, Mission, MissionId, ProjectId, TenantId,
};
use hartevo_storage::{PendingEvent, StorageError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ApplicationService;

pub const OBSERVATION_EVIDENCE_PACK_SCHEMA_VERSION: u32 = 1;
const MAX_OBSERVATION_CONTENT_BYTES: usize = 128 * 1024;
const OBSERVATION_COMMITTED_EVENT: &str = "application.runtime_observation_committed";
const OBSERVATION_STOPPED_EVENT: &str = "application.runtime_observation_stopped";

/// Truth provenance is part of the intake binding, not a UI label.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSourceKind {
    Public,
    FirstParty,
    Provider,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationClassification {
    Confirmed,
    Candidate,
    ProviderEstimate,
    Inference,
    Conflict,
}

impl ObservationClassification {
    fn evidence_status(self) -> EvidenceStatus {
        match self {
            Self::Confirmed => EvidenceStatus::Confirmed,
            Self::Conflict => EvidenceStatus::Conflicted,
            Self::Candidate | Self::ProviderEstimate | Self::Inference => EvidenceStatus::Candidate,
        }
    }

    fn confidence(self) -> f32 {
        match self {
            Self::Confirmed => 1.0,
            Self::Candidate => 0.5,
            Self::ProviderEstimate => 0.4,
            Self::Inference => 0.3,
            Self::Conflict => 0.0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationPlanBinding {
    pub plan_id: String,
    pub revision: u64,
    pub version: u64,
    pub digest: String,
}

impl ObservationPlanBinding {
    pub fn validate(&self) -> Result<(), ObservationPipelineError> {
        if self.plan_id.trim().is_empty()
            || self.revision == 0
            || self.version == 0
            || !is_sha256(&self.digest)
        {
            return Err(ObservationPipelineError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationSourceBinding {
    pub source_id: String,
    pub uri: String,
    pub revision: u64,
    pub version: String,
    pub digest: String,
    pub kind: ObservationSourceKind,
}

impl ObservationSourceBinding {
    pub fn validate(&self) -> Result<(), ObservationPipelineError> {
        if self.source_id.trim().is_empty()
            || self.uri.trim().is_empty()
            || self.revision == 0
            || self.version.trim().is_empty()
            || !is_sha256(&self.digest)
        {
            return Err(ObservationPipelineError::InvalidRequest);
        }
        Ok(())
    }

    fn stable_identity_matches(&self, other: &Self) -> bool {
        self.source_id == other.source_id
            && self.uri == other.uri
            && self.version == other.version
            && self.digest == other.digest
            && self.kind == other.kind
    }
}

/// Exact Application input handed to a provider.  The provider cannot obtain
/// the Store, an Effect broker, or any ambient authority from this value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationPipelineRequest {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub expected_mission_revision: u64,
    pub contract_version: u64,
    pub contract_digest: String,
    pub plan: ObservationPlanBinding,
    pub source: ObservationSourceBinding,
    pub observation_id: String,
}

impl ObservationPipelineRequest {
    pub fn validate(&self) -> Result<(), ObservationPipelineError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.expected_mission_revision == 0
            || self.contract_version == 0
            || !is_sha256(&self.contract_digest)
            || self.observation_id.trim().is_empty()
        {
            return Err(ObservationPipelineError::InvalidRequest);
        }
        self.plan.validate()?;
        self.source.validate()
    }
}

pub type ObservationProviderRequest = ObservationPipelineRequest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TypedRuntimeObservation {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub observation_id: String,
    pub plan: ObservationPlanBinding,
    pub source: ObservationSourceBinding,
    pub observed_at: DateTime<Utc>,
    pub content: String,
    pub content_digest: String,
    pub classification: ObservationClassification,
}

impl TypedRuntimeObservation {
    pub fn observation_digest(&self) -> Result<String, ObservationPipelineError> {
        canonical_digest(&serde_json::json!({
            "tenantId": self.tenant_id,
            "projectId": self.project_id,
            "missionId": self.mission_id,
            "observationId": self.observation_id,
            "plan": self.plan,
            "source": self.source,
            "observedAt": self.observed_at,
            "contentDigest": self.content_digest,
            "classification": self.classification,
        }))
    }

    fn validate_shape(&self) -> Result<(), ObservationPipelineError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.observation_id.trim().is_empty()
            || self.content.trim().is_empty()
            || self.content.len() > MAX_OBSERVATION_CONTENT_BYTES
            || !is_sha256(&self.content_digest)
            || self.content_digest != digest_bytes(self.content.as_bytes())
        {
            return Err(ObservationPipelineError::InvalidObservation);
        }
        self.plan.validate()?;
        self.source.validate()?;
        if self.classification == ObservationClassification::Confirmed
            && self.source.kind != ObservationSourceKind::FirstParty
        {
            return Err(ObservationPipelineError::ClassificationMismatch);
        }
        Ok(())
    }

    fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ObservationPipelineError> {
        self.validate_shape()?;
        if self.observed_at > now {
            return Err(ObservationPipelineError::TimeDrift);
        }
        Ok(())
    }
}

/// The committed, model-visible result.  `pack_digest` binds all scope,
/// revision, source, classification, and content fields, including the raw
/// model-visible observation text that was logged before the consumer call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationEvidencePack {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub expected_mission_revision: u64,
    pub mission_revision: u64,
    pub contract_version: u64,
    pub contract_digest: String,
    pub plan: ObservationPlanBinding,
    pub source: ObservationSourceBinding,
    pub pack_revision: u64,
    pub observation_id: String,
    pub evidence_id: EvidenceId,
    pub observed_at: DateTime<Utc>,
    pub classification: ObservationClassification,
    pub content_digest: String,
    pub observation_digest: String,
    pub model_visible_content: String,
    pub pack_digest: String,
}

impl ObservationEvidencePack {
    pub fn seal(mut self) -> Result<Self, ObservationPipelineError> {
        self.pack_digest.clear();
        self.pack_digest = self.calculate_digest()?;
        self.validate()?;
        Ok(self)
    }

    pub fn calculate_digest(&self) -> Result<String, ObservationPipelineError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or(ObservationPipelineError::PackMismatch)?
            .insert("packDigest".into(), Value::String(String::new()));
        canonical_digest_value(&value)
    }

    pub fn validate(&self) -> Result<(), ObservationPipelineError> {
        if self.schema_version != OBSERVATION_EVIDENCE_PACK_SCHEMA_VERSION
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.expected_mission_revision == 0
            || self.mission_revision <= self.expected_mission_revision
            || self.contract_version == 0
            || !is_sha256(&self.contract_digest)
            || self.pack_revision == 0
            || self.observation_id.trim().is_empty()
            || self.evidence_id.as_str().trim().is_empty()
            || self.model_visible_content.trim().is_empty()
            || self.model_visible_content.len() > MAX_OBSERVATION_CONTENT_BYTES
            || !is_sha256(&self.content_digest)
            || self.content_digest != digest_bytes(self.model_visible_content.as_bytes())
            || !is_sha256(&self.observation_digest)
            || !is_sha256(&self.pack_digest)
            || self.pack_digest != self.calculate_digest()?
        {
            return Err(ObservationPipelineError::PackMismatch);
        }
        self.plan.validate()?;
        self.source.validate()?;
        if self.classification == ObservationClassification::Confirmed
            && self.source.kind != ObservationSourceKind::FirstParty
        {
            return Err(ObservationPipelineError::ClassificationMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationPipelineResult {
    pub pack: ObservationEvidencePack,
    pub replayed: bool,
    pub event_sequences: Vec<i64>,
    pub outbox_sequences: Vec<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationStopCommand {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub expected_mission_revision: u64,
    pub contract_version: u64,
    pub contract_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationStopResult {
    pub mission_revision: u64,
    pub replayed: bool,
    pub event_sequences: Vec<i64>,
    pub outbox_sequences: Vec<i64>,
}

#[derive(Debug, Error)]
pub enum ObservationPipelineError {
    #[error("observation request is malformed")]
    InvalidRequest,
    #[error("observation payload is malformed")]
    InvalidObservation,
    #[error("observation does not match the exact Project, Mission, or tenant scope")]
    ScopeMismatch,
    #[error("observation Mission revision changed: expected {expected}, actual {actual}")]
    MissionRevisionMismatch { expected: u64, actual: u64 },
    #[error("observation contract version changed: expected {expected}, actual {actual}")]
    ContractVersionMismatch { expected: u64, actual: u64 },
    #[error("observation contract digest does not match the current Mission contract")]
    ContractDigestMismatch,
    #[error("observation plan binding is stale or swapped")]
    PlanMismatch,
    #[error("observation source identity, version, or digest drifted")]
    SourceDrift,
    #[error("observation source revision is stale or reused")]
    SourceRevisionStale,
    #[error("observation idempotency replay does not match the original payload")]
    ReplayMismatch,
    #[error("observation intake is stopped or the Mission is terminal")]
    IntakeStopped,
    #[error("public or provider observation cannot be upgraded to first-party Confirmed")]
    ClassificationMismatch,
    #[error("observation time is in the future")]
    TimeDrift,
    #[error("provider response does not match the exact Application request")]
    ProviderResponseMismatch,
    #[error("persisted observation Evidence Pack is malformed or tampered")]
    PackMismatch,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("observation provider failed: {0}")]
    Provider(String),
    #[error("observation consumer failed after durable commit: {0}")]
    Consumer(String),
}

/// Provider-neutral Application seam.  The provider has no Store or Effect
/// authority and can only return typed output for this exact request.
pub trait RuntimeObservationProvider {
    type Error: fmt::Display;

    fn observe(
        &mut self,
        request: &ObservationProviderRequest,
    ) -> Result<TypedRuntimeObservation, Self::Error>;
}

/// Consumer-neutral Application seam.  This callback is invoked only after
/// the durable Mission/Evidence/Event/Outbox/Pack transaction succeeds.
pub trait ObservationPackConsumer {
    type Error: fmt::Display;

    fn consume(&mut self, pack: &ObservationEvidencePack) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PersistedObservationCommit {
    schema_version: u32,
    request: ObservationPipelineRequest,
    observation: TypedRuntimeObservation,
    evidence: Evidence,
    pack: ObservationEvidencePack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PersistedObservationStop {
    schema_version: u32,
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    expected_mission_revision: u64,
    mission_revision: u64,
    contract_version: u64,
    contract_digest: String,
}

impl ApplicationService {
    /// Runs the typed provider and then delivers the durable Pack to a
    /// consumer.  The consumer is deliberately after `accept_runtime_observation`:
    /// model-visible output can never precede the durable log.
    pub fn run_runtime_observation<P, C>(
        &mut self,
        provider: &mut P,
        consumer: &mut C,
        request: &ObservationPipelineRequest,
        now: DateTime<Utc>,
    ) -> Result<ObservationPipelineResult, ObservationPipelineError>
    where
        P: RuntimeObservationProvider,
        C: ObservationPackConsumer,
    {
        let observation = provider
            .observe(request)
            .map_err(|error| ObservationPipelineError::Provider(error.to_string()))?;
        let result = self.accept_runtime_observation(request, observation, now)?;
        consumer
            .consume(&result.pack)
            .map_err(|error| ObservationPipelineError::Consumer(error.to_string()))?;
        Ok(result)
    }

    pub fn accept_runtime_observation(
        &mut self,
        request: &ObservationPipelineRequest,
        observation: TypedRuntimeObservation,
        now: DateTime<Utc>,
    ) -> Result<ObservationPipelineResult, ObservationPipelineError> {
        validate_observation_input(request, &observation, now)?;
        let (mission, commits) = self.load_observation_context(request)?;
        let observation_digest = observation.observation_digest()?;
        if let Some(replay) =
            replayed_observation(&commits, request, &observation, &observation_digest)?
        {
            return Ok(replay);
        }
        validate_observation_fence(&mission, &commits, request, now)?;
        let commit =
            build_observation_commit(&mission, &commits, request, observation, observation_digest)?;
        let mut next_mission = mission;
        next_mission.evidence.push(commit.evidence.clone());
        next_mission.revision = commit.pack.mission_revision;
        next_mission.updated_at = now;
        let mutation = self.store.update_mission_atomic(
            &next_mission,
            request.expected_mission_revision,
            &[PendingEvent::new(
                OBSERVATION_COMMITTED_EVENT,
                serde_json::to_value(&commit)?,
                now,
            )],
        )?;
        Ok(ObservationPipelineResult {
            pack: commit.pack,
            replayed: false,
            event_sequences: mutation.event_sequences,
            outbox_sequences: mutation.outbox_sequences,
        })
    }

    pub fn stop_runtime_observation_intake(
        &mut self,
        command: &ObservationStopCommand,
        now: DateTime<Utc>,
    ) -> Result<ObservationStopResult, ObservationPipelineError> {
        validate_stop_command(command)?;
        let project = self.store.load_project(&command.project_id)?;
        let mission = self
            .store
            .load_mission(&command.project_id, &command.mission_id)?;
        ensure_stop_scope(command, &project.tenant_id, &mission)?;
        let events = self
            .store
            .events_for_mission(&command.project_id, &command.mission_id)?;
        for event in events {
            if event.event_type != OBSERVATION_STOPPED_EVENT {
                continue;
            }
            let stopped: PersistedObservationStop = serde_json::from_value(event.payload)?;
            validate_persisted_stop(&stopped)?;
            if stop_matches_command(&stopped, command) {
                return Ok(ObservationStopResult {
                    mission_revision: stopped.mission_revision,
                    replayed: true,
                    event_sequences: Vec::new(),
                    outbox_sequences: Vec::new(),
                });
            }
            return Err(ObservationPipelineError::IntakeStopped);
        }
        if mission.revision != command.expected_mission_revision {
            return Err(ObservationPipelineError::MissionRevisionMismatch {
                expected: command.expected_mission_revision,
                actual: mission.revision,
            });
        }
        if mission.stage.is_terminal() {
            return Err(ObservationPipelineError::IntakeStopped);
        }
        if mission.contract.version != command.contract_version {
            return Err(ObservationPipelineError::ContractVersionMismatch {
                expected: command.contract_version,
                actual: mission.contract.version,
            });
        }
        if canonical_digest(&mission.contract)? != command.contract_digest {
            return Err(ObservationPipelineError::ContractDigestMismatch);
        }
        let next_revision = mission
            .revision
            .checked_add(1)
            .ok_or(ObservationPipelineError::InvalidRequest)?;
        let stopped = PersistedObservationStop {
            schema_version: OBSERVATION_EVIDENCE_PACK_SCHEMA_VERSION,
            tenant_id: command.tenant_id.clone(),
            project_id: command.project_id.clone(),
            mission_id: command.mission_id.clone(),
            expected_mission_revision: command.expected_mission_revision,
            mission_revision: next_revision,
            contract_version: command.contract_version,
            contract_digest: command.contract_digest.clone(),
        };
        let mut next_mission = mission;
        next_mission.revision = next_revision;
        next_mission.updated_at = now;
        let mutation = self.store.update_mission_atomic(
            &next_mission,
            command.expected_mission_revision,
            &[PendingEvent::new(
                OBSERVATION_STOPPED_EVENT,
                serde_json::to_value(stopped)?,
                now,
            )],
        )?;
        Ok(ObservationStopResult {
            mission_revision: next_revision,
            replayed: false,
            event_sequences: mutation.event_sequences,
            outbox_sequences: mutation.outbox_sequences,
        })
    }

    fn load_observation_context(
        &self,
        request: &ObservationPipelineRequest,
    ) -> Result<(Mission, Vec<PersistedObservationCommit>), ObservationPipelineError> {
        let project = self.store.load_project(&request.project_id)?;
        let mission = self
            .store
            .load_mission(&request.project_id, &request.mission_id)?;
        ensure_scope(request, &project.tenant_id, &mission)?;
        let (commits, stopped) =
            self.observation_history(&request.project_id, &request.mission_id)?;
        if stopped {
            return Err(ObservationPipelineError::IntakeStopped);
        }
        Ok((mission, commits))
    }

    fn observation_history(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<(Vec<PersistedObservationCommit>, bool), ObservationPipelineError> {
        let mut commits = Vec::new();
        let mut stopped = false;
        for event in self.store.events_for_mission(project_id, mission_id)? {
            match event.event_type.as_str() {
                OBSERVATION_COMMITTED_EVENT => {
                    let commit: PersistedObservationCommit = serde_json::from_value(event.payload)?;
                    validate_persisted_commit(&commit)?;
                    if commit.request.project_id != *project_id
                        || commit.request.mission_id != *mission_id
                    {
                        return Err(ObservationPipelineError::ScopeMismatch);
                    }
                    commits.push(commit);
                }
                OBSERVATION_STOPPED_EVENT => {
                    let stop: PersistedObservationStop = serde_json::from_value(event.payload)?;
                    validate_persisted_stop(&stop)?;
                    if stop.project_id != *project_id || stop.mission_id != *mission_id {
                        return Err(ObservationPipelineError::ScopeMismatch);
                    }
                    stopped = true;
                }
                _ => {}
            }
        }
        Ok((commits, stopped))
    }
}

fn validate_observation_input(
    request: &ObservationPipelineRequest,
    observation: &TypedRuntimeObservation,
    now: DateTime<Utc>,
) -> Result<(), ObservationPipelineError> {
    request.validate()?;
    observation.validate_at(now)?;
    if !observation_matches_request(request, observation) {
        return Err(ObservationPipelineError::ProviderResponseMismatch);
    }
    Ok(())
}

fn replayed_observation(
    commits: &[PersistedObservationCommit],
    request: &ObservationPipelineRequest,
    observation: &TypedRuntimeObservation,
    observation_digest: &str,
) -> Result<Option<ObservationPipelineResult>, ObservationPipelineError> {
    for commit in commits {
        let same_identity = commit.observation.observation_id == observation.observation_id;
        let same_digest = commit.observation.observation_digest()? == observation_digest;
        if same_identity || same_digest {
            if commit.request == *request && commit.observation == *observation {
                commit.pack.validate()?;
                return Ok(Some(ObservationPipelineResult {
                    pack: commit.pack.clone(),
                    replayed: true,
                    event_sequences: Vec::new(),
                    outbox_sequences: Vec::new(),
                }));
            }
            return Err(ObservationPipelineError::ReplayMismatch);
        }
    }
    Ok(None)
}

fn validate_observation_fence(
    mission: &Mission,
    commits: &[PersistedObservationCommit],
    request: &ObservationPipelineRequest,
    now: DateTime<Utc>,
) -> Result<(), ObservationPipelineError> {
    if mission.revision != request.expected_mission_revision {
        return Err(ObservationPipelineError::MissionRevisionMismatch {
            expected: request.expected_mission_revision,
            actual: mission.revision,
        });
    }
    if mission.stage.is_terminal() {
        return Err(ObservationPipelineError::IntakeStopped);
    }
    if now < mission.updated_at {
        return Err(ObservationPipelineError::TimeDrift);
    }
    if mission.contract.version != request.contract_version {
        return Err(ObservationPipelineError::ContractVersionMismatch {
            expected: request.contract_version,
            actual: mission.contract.version,
        });
    }
    if canonical_digest(&mission.contract)? != request.contract_digest {
        return Err(ObservationPipelineError::ContractDigestMismatch);
    }
    validate_history_bindings(commits, request)
}

fn build_observation_commit(
    mission: &Mission,
    commits: &[PersistedObservationCommit],
    request: &ObservationPipelineRequest,
    observation: TypedRuntimeObservation,
    observation_digest: String,
) -> Result<PersistedObservationCommit, ObservationPipelineError> {
    let evidence_id = EvidenceId::from_stable(format!(
        "runtime-observation-evidence-{}",
        request.observation_id
    ));
    if mission
        .evidence
        .iter()
        .any(|evidence| evidence.id == evidence_id)
    {
        return Err(ObservationPipelineError::ReplayMismatch);
    }
    let next_revision = mission
        .revision
        .checked_add(1)
        .ok_or(ObservationPipelineError::InvalidRequest)?;
    let pack_revision = commits
        .iter()
        .map(|commit| commit.pack.pack_revision)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(ObservationPipelineError::InvalidRequest)?;
    let evidence = Evidence {
        id: evidence_id.clone(),
        title: format!("Runtime observation {}", request.observation_id),
        source_uri: request.source.uri.clone(),
        observed_at: observation.observed_at,
        confidence: observation.classification.confidence(),
        status: observation.classification.evidence_status(),
        content_digest: observation.content_digest.clone(),
    };
    let pack = ObservationEvidencePack {
        schema_version: OBSERVATION_EVIDENCE_PACK_SCHEMA_VERSION,
        tenant_id: request.tenant_id.clone(),
        project_id: request.project_id.clone(),
        mission_id: request.mission_id.clone(),
        expected_mission_revision: request.expected_mission_revision,
        mission_revision: next_revision,
        contract_version: request.contract_version,
        contract_digest: request.contract_digest.clone(),
        plan: request.plan.clone(),
        source: request.source.clone(),
        pack_revision,
        observation_id: request.observation_id.clone(),
        evidence_id,
        observed_at: observation.observed_at,
        classification: observation.classification,
        content_digest: observation.content_digest.clone(),
        observation_digest,
        model_visible_content: observation.content.clone(),
        pack_digest: String::new(),
    }
    .seal()?;
    Ok(PersistedObservationCommit {
        schema_version: OBSERVATION_EVIDENCE_PACK_SCHEMA_VERSION,
        request: request.clone(),
        observation,
        evidence,
        pack,
    })
}

fn observation_matches_request(
    request: &ObservationPipelineRequest,
    observation: &TypedRuntimeObservation,
) -> bool {
    observation.tenant_id == request.tenant_id
        && observation.project_id == request.project_id
        && observation.mission_id == request.mission_id
        && observation.observation_id == request.observation_id
        && observation.plan == request.plan
        && observation.source == request.source
}

fn ensure_scope(
    request: &ObservationPipelineRequest,
    project_tenant_id: &TenantId,
    mission: &hartevo_domain_kernel::Mission,
) -> Result<(), ObservationPipelineError> {
    if request.tenant_id != *project_tenant_id
        || mission.tenant_id != *project_tenant_id
        || mission.project_id != request.project_id
        || mission.id != request.mission_id
    {
        return Err(ObservationPipelineError::ScopeMismatch);
    }
    Ok(())
}

fn validate_history_bindings(
    commits: &[PersistedObservationCommit],
    request: &ObservationPipelineRequest,
) -> Result<(), ObservationPipelineError> {
    if let Some(first) = commits.first()
        && first.request.plan != request.plan
    {
        return Err(ObservationPipelineError::PlanMismatch);
    }
    for commit in commits {
        if commit.request.plan != request.plan {
            return Err(ObservationPipelineError::PlanMismatch);
        }
        if !commit
            .observation
            .source
            .stable_identity_matches(&request.source)
        {
            return Err(ObservationPipelineError::SourceDrift);
        }
        if request.source.revision <= commit.observation.source.revision {
            return Err(ObservationPipelineError::SourceRevisionStale);
        }
    }
    Ok(())
}

fn validate_persisted_commit(
    commit: &PersistedObservationCommit,
) -> Result<(), ObservationPipelineError> {
    if commit.schema_version != OBSERVATION_EVIDENCE_PACK_SCHEMA_VERSION {
        return Err(ObservationPipelineError::PackMismatch);
    }
    commit.request.validate()?;
    commit.observation.validate_shape()?;
    if !observation_matches_request(&commit.request, &commit.observation) {
        return Err(ObservationPipelineError::PackMismatch);
    }
    let observation_digest = commit.observation.observation_digest()?;
    let expected_evidence_id = EvidenceId::from_stable(format!(
        "runtime-observation-evidence-{}",
        commit.request.observation_id
    ));
    let expected_mission_revision = commit
        .request
        .expected_mission_revision
        .checked_add(1)
        .ok_or(ObservationPipelineError::PackMismatch)?;
    if observation_digest != commit.pack.observation_digest
        || commit.evidence.id != expected_evidence_id
        || commit.evidence.id != commit.pack.evidence_id
        || commit.evidence.title != format!("Runtime observation {}", commit.request.observation_id)
        || commit.evidence.observed_at != commit.observation.observed_at
        || commit.evidence.confidence.to_bits()
            != commit.observation.classification.confidence().to_bits()
        || commit.evidence.status != commit.observation.classification.evidence_status()
        || commit.evidence.content_digest != commit.observation.content_digest
        || commit.evidence.source_uri != commit.observation.source.uri
        || commit.pack.tenant_id != commit.request.tenant_id
        || commit.pack.project_id != commit.request.project_id
        || commit.pack.mission_id != commit.request.mission_id
        || commit.pack.expected_mission_revision != commit.request.expected_mission_revision
        || commit.pack.mission_revision != expected_mission_revision
        || commit.pack.plan != commit.request.plan
        || commit.pack.source != commit.request.source
        || commit.pack.contract_version != commit.request.contract_version
        || commit.pack.contract_digest != commit.request.contract_digest
        || commit.pack.observation_id != commit.request.observation_id
        || commit.pack.observed_at != commit.observation.observed_at
        || commit.pack.classification != commit.observation.classification
        || commit.pack.model_visible_content != commit.observation.content
    {
        return Err(ObservationPipelineError::PackMismatch);
    }
    commit.pack.validate()?;
    Ok(())
}

fn validate_stop_command(command: &ObservationStopCommand) -> Result<(), ObservationPipelineError> {
    if command.tenant_id.as_str().trim().is_empty()
        || command.project_id.as_str().trim().is_empty()
        || command.mission_id.as_str().trim().is_empty()
        || command.expected_mission_revision == 0
        || command.contract_version == 0
        || !is_sha256(&command.contract_digest)
    {
        return Err(ObservationPipelineError::InvalidRequest);
    }
    Ok(())
}

fn ensure_stop_scope(
    command: &ObservationStopCommand,
    project_tenant_id: &TenantId,
    mission: &hartevo_domain_kernel::Mission,
) -> Result<(), ObservationPipelineError> {
    if command.tenant_id != *project_tenant_id
        || mission.tenant_id != *project_tenant_id
        || mission.project_id != command.project_id
        || mission.id != command.mission_id
    {
        return Err(ObservationPipelineError::ScopeMismatch);
    }
    Ok(())
}

fn validate_persisted_stop(
    stop: &PersistedObservationStop,
) -> Result<(), ObservationPipelineError> {
    if stop.schema_version != OBSERVATION_EVIDENCE_PACK_SCHEMA_VERSION
        || stop.tenant_id.as_str().trim().is_empty()
        || stop.project_id.as_str().trim().is_empty()
        || stop.mission_id.as_str().trim().is_empty()
        || stop.expected_mission_revision == 0
        || stop.mission_revision <= stop.expected_mission_revision
        || stop.contract_version == 0
        || !is_sha256(&stop.contract_digest)
    {
        return Err(ObservationPipelineError::PackMismatch);
    }
    let expected_mission_revision = stop
        .expected_mission_revision
        .checked_add(1)
        .ok_or(ObservationPipelineError::PackMismatch)?;
    if stop.mission_revision != expected_mission_revision {
        return Err(ObservationPipelineError::PackMismatch);
    }
    Ok(())
}

fn stop_matches_command(stop: &PersistedObservationStop, command: &ObservationStopCommand) -> bool {
    stop.tenant_id == command.tenant_id
        && stop.project_id == command.project_id
        && stop.mission_id == command.mission_id
        && stop.expected_mission_revision == command.expected_mission_revision
        && stop.contract_version == command.contract_version
        && stop.contract_digest == command.contract_digest
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ObservationPipelineError> {
    canonical_digest_value(&serde_json::to_value(value)?)
}

fn canonical_digest_value(value: &Value) -> Result<String, ObservationPipelineError> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        Mission, MissionContract, Project, StorageMode, Task, TaskId, TaskStatus,
    };
    use hartevo_storage::{PendingEvent, ProjectStore};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("valid fixture time")
    }

    fn setup() -> (ApplicationService, Project, Mission) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-observation"),
            ProjectId::from("project-observation"),
            "Observation project",
            "",
            "/tmp/hartevo-observation",
            StorageMode::LocalExisting,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new(
                    "project.created",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("project event");
        let mut mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-observation"),
            project.id.clone(),
            "Observation mission",
            MissionContract::bootstrap("Read exact observations", ["research.read".into()], now()),
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("observation-task"),
                    title: "Observe".into(),
                    status: TaskStatus::Running,
                    capability: "research.read".into(),
                }],
                now(),
            )
            .expect("start mission");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new(
                    "mission.started",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("mission event");
        (ApplicationService::new(store), project, mission)
    }

    fn event_count(
        application: &ApplicationService,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> usize {
        application
            .store
            .events_for_mission(project_id, mission_id)
            .expect("events")
            .len()
    }

    fn plan() -> ObservationPlanBinding {
        ObservationPlanBinding {
            plan_id: "plan-de-market".into(),
            revision: 1,
            version: 1,
            digest: digest_bytes(b"plan-v1"),
        }
    }

    fn source(
        kind: ObservationSourceKind,
        revision: u64,
        digest: &str,
    ) -> ObservationSourceBinding {
        ObservationSourceBinding {
            source_id: "source-public-market".into(),
            uri: "https://example.test/market".into(),
            revision,
            version: "provider-1".into(),
            digest: digest.to_owned(),
            kind,
        }
    }

    fn request(
        mission: &Mission,
        observation_id: &str,
        source: ObservationSourceBinding,
    ) -> ObservationPipelineRequest {
        ObservationPipelineRequest {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            expected_mission_revision: mission.revision,
            contract_version: mission.contract.version,
            contract_digest: canonical_digest(&mission.contract).expect("contract digest"),
            plan: plan(),
            source,
            observation_id: observation_id.into(),
        }
    }

    fn observation(
        request: &ObservationPipelineRequest,
        classification: ObservationClassification,
    ) -> TypedRuntimeObservation {
        let content = format!("durable observation for {}", request.observation_id);
        TypedRuntimeObservation {
            tenant_id: request.tenant_id.clone(),
            project_id: request.project_id.clone(),
            mission_id: request.mission_id.clone(),
            observation_id: request.observation_id.clone(),
            plan: request.plan.clone(),
            source: request.source.clone(),
            observed_at: now(),
            content_digest: digest_bytes(content.as_bytes()),
            content,
            classification,
        }
    }

    #[derive(Debug)]
    struct FakeProvider {
        response: TypedRuntimeObservation,
        calls: Cell<usize>,
    }

    impl RuntimeObservationProvider for FakeProvider {
        type Error = fmt::Error;

        fn observe(
            &mut self,
            _request: &ObservationProviderRequest,
        ) -> Result<TypedRuntimeObservation, Self::Error> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.response.clone())
        }
    }

    #[derive(Debug, Default)]
    struct FakeConsumer {
        packs: Vec<ObservationEvidencePack>,
    }

    impl ObservationPackConsumer for FakeConsumer {
        type Error = fmt::Error;

        fn consume(&mut self, pack: &ObservationEvidencePack) -> Result<(), Self::Error> {
            self.packs.push(pack.clone());
            Ok(())
        }
    }

    #[test]
    fn fake_provider_journey_commits_observation_evidence_event_outbox_and_pack_before_consumer() {
        let (mut application, _project, mission) = setup();
        let request = request(
            &mission,
            "observation-1",
            source(
                ObservationSourceKind::FirstParty,
                1,
                &digest_bytes(b"provider-1"),
            ),
        );
        let response = observation(&request, ObservationClassification::Confirmed);
        let mut provider = FakeProvider {
            response,
            calls: Cell::new(0),
        };
        let mut consumer = FakeConsumer::default();

        let result = application
            .run_runtime_observation(&mut provider, &mut consumer, &request, now())
            .expect("journey");

        assert!(!result.replayed);
        assert_eq!(result.event_sequences.len(), 1);
        assert_eq!(result.outbox_sequences.len(), 1);
        assert_eq!(result.pack.pack_revision, 1);
        assert_eq!(consumer.packs, vec![result.pack.clone()]);
        assert_eq!(provider.calls.get(), 1);
        assert_eq!(
            application
                .store
                .load_mission(&request.project_id, &request.mission_id)
                .expect("mission")
                .evidence
                .len(),
            1
        );
        let committed = application
            .store
            .events_for_mission(&request.project_id, &request.mission_id)
            .expect("events")
            .into_iter()
            .filter(|event| event.event_type == OBSERVATION_COMMITTED_EVENT)
            .count();
        assert_eq!(committed, 1);
    }

    #[test]
    fn exact_replay_after_restart_has_zero_event_outbox_or_pack_growth() {
        let (mut application, _project, mission) = setup();
        let request = request(
            &mission,
            "observation-replay",
            source(
                ObservationSourceKind::Provider,
                1,
                &digest_bytes(b"provider-1"),
            ),
        );
        let response = observation(&request, ObservationClassification::ProviderEstimate);
        let mut provider = FakeProvider {
            response,
            calls: Cell::new(0),
        };
        let mut first_consumer = FakeConsumer::default();
        let first = application
            .run_runtime_observation(&mut provider, &mut first_consumer, &request, now())
            .expect("first");
        let event_count = application
            .store
            .events_for_mission(&request.project_id, &request.mission_id)
            .expect("events")
            .len();
        let store = application.store;
        let mut restarted = ApplicationService::new(store);
        let mut replay_consumer = FakeConsumer::default();
        let replay = restarted
            .run_runtime_observation(
                &mut provider,
                &mut replay_consumer,
                &request,
                now() + Duration::seconds(1),
            )
            .expect("replay");

        assert!(replay.replayed);
        assert_eq!(replay.pack, first.pack);
        assert!(replay.event_sequences.is_empty());
        assert!(replay.outbox_sequences.is_empty());
        assert_eq!(
            restarted
                .store
                .events_for_mission(&request.project_id, &request.mission_id)
                .expect("events after replay")
                .len(),
            event_count
        );
        assert_eq!(replay_consumer.packs, vec![first.pack]);
    }

    #[test]
    fn tampered_durable_pack_fails_closed_without_new_event() {
        let (mut application, project, mission) = setup();
        let request = request(
            &mission,
            "observation-tamper",
            source(
                ObservationSourceKind::Provider,
                1,
                &digest_bytes(b"provider-1"),
            ),
        );
        application
            .accept_runtime_observation(
                &request,
                observation(&request, ObservationClassification::ProviderEstimate),
                now(),
            )
            .expect("baseline observation");
        let event = application
            .store
            .events_for_mission(&project.id, &mission.id)
            .expect("events")
            .into_iter()
            .find(|event| event.event_type == OBSERVATION_COMMITTED_EVENT)
            .expect("committed event");
        let mut tampered = event.payload;
        tampered["pack"]["modelVisibleContent"] = Value::String("tampered".into());
        application
            .store
            .append_event(
                &project.id,
                Some(&mission.id),
                OBSERVATION_COMMITTED_EVENT,
                &tampered,
                now() + Duration::seconds(1),
            )
            .expect("tampered fixture event");
        let before = event_count(&application, &project.id, &mission.id);

        assert!(matches!(
            application.accept_runtime_observation(
                &request,
                observation(&request, ObservationClassification::ProviderEstimate),
                now() + Duration::seconds(2),
            ),
            Err(ObservationPipelineError::PackMismatch)
        ));
        assert_eq!(event_count(&application, &project.id, &mission.id), before);
    }

    #[test]
    fn exact_project_plan_source_revision_and_classification_fences_fail_closed() {
        let (mut application, project, mission) = setup();
        let baseline = request(
            &mission,
            "observation-fences",
            source(
                ObservationSourceKind::Provider,
                1,
                &digest_bytes(b"provider-1"),
            ),
        );
        let before = event_count(&application, &project.id, &mission.id);

        let mut foreign = baseline.clone();
        foreign.project_id = ProjectId::from("foreign-project");
        let foreign_observation = observation(&foreign, ObservationClassification::Candidate);
        assert!(matches!(
            application.accept_runtime_observation(&foreign, foreign_observation, now()),
            Err(ObservationPipelineError::Storage(
                StorageError::ProjectNotFound(_)
            ))
        ));
        assert_eq!(event_count(&application, &project.id, &mission.id), before);

        application
            .accept_runtime_observation(
                &baseline,
                observation(&baseline, ObservationClassification::Candidate),
                now(),
            )
            .expect("baseline observation");
        let baseline_mission = application
            .store
            .load_mission(&project.id, &mission.id)
            .expect("baseline mission");
        let before = event_count(&application, &project.id, &mission.id);

        let mut public_confirmed = baseline.clone();
        public_confirmed.observation_id = "public-confirmed".into();
        public_confirmed.expected_mission_revision = baseline_mission.revision;
        public_confirmed.source = source(
            ObservationSourceKind::Public,
            1,
            &digest_bytes(b"provider-1"),
        );
        let public_observation =
            observation(&public_confirmed, ObservationClassification::Confirmed);
        assert!(matches!(
            application.accept_runtime_observation(&public_confirmed, public_observation, now()),
            Err(ObservationPipelineError::ClassificationMismatch)
        ));
        assert_eq!(event_count(&application, &project.id, &mission.id), before);

        let mut swapped_plan = baseline.clone();
        swapped_plan.observation_id = "swapped-plan".into();
        swapped_plan.expected_mission_revision = baseline_mission.revision;
        swapped_plan.plan.digest = digest_bytes(b"swapped-plan");
        let swapped_plan_observation =
            observation(&swapped_plan, ObservationClassification::Candidate);
        assert!(matches!(
            application.accept_runtime_observation(&swapped_plan, swapped_plan_observation, now(),),
            Err(ObservationPipelineError::PlanMismatch)
        ));
        assert_eq!(event_count(&application, &project.id, &mission.id), before);

        let mut swapped_source = baseline.clone();
        swapped_source.observation_id = "swapped-source".into();
        swapped_source.expected_mission_revision = baseline_mission.revision;
        swapped_source.source.source_id = "different-source".into();
        let swapped_source_observation =
            observation(&swapped_source, ObservationClassification::Candidate);
        assert!(matches!(
            application.accept_runtime_observation(
                &swapped_source,
                swapped_source_observation,
                now(),
            ),
            Err(ObservationPipelineError::SourceDrift)
        ));
        assert_eq!(event_count(&application, &project.id, &mission.id), before);

        let mut stale_source_revision = baseline.clone();
        stale_source_revision.observation_id = "stale-source-revision".into();
        stale_source_revision.expected_mission_revision = baseline_mission.revision;
        let stale_source_revision_observation =
            observation(&stale_source_revision, ObservationClassification::Candidate);
        assert!(matches!(
            application.accept_runtime_observation(
                &stale_source_revision,
                stale_source_revision_observation,
                now(),
            ),
            Err(ObservationPipelineError::SourceRevisionStale)
        ));
        assert_eq!(event_count(&application, &project.id, &mission.id), before);

        let mut stale_source = baseline.clone();
        stale_source.observation_id = "stale-source".into();
        stale_source.expected_mission_revision = baseline_mission.revision;
        stale_source.source.digest = digest_bytes(b"drifted-provider");
        let stale_observation = observation(&stale_source, ObservationClassification::Candidate);
        assert!(matches!(
            application.accept_runtime_observation(&stale_source, stale_observation, now()),
            Err(ObservationPipelineError::SourceDrift)
        ));
        assert_eq!(event_count(&application, &project.id, &mission.id), before);
    }

    #[test]
    fn stale_reselect_and_post_stop_inputs_write_nothing() {
        let (mut application, project, mission) = setup();
        let request = request(
            &mission,
            "observation-stop",
            source(
                ObservationSourceKind::Provider,
                1,
                &digest_bytes(b"provider-1"),
            ),
        );
        let mut provider = FakeProvider {
            response: observation(&request, ObservationClassification::ProviderEstimate),
            calls: Cell::new(0),
        };
        let mut consumer = FakeConsumer::default();
        application
            .run_runtime_observation(&mut provider, &mut consumer, &request, now())
            .expect("first");
        let stored_mission = application
            .store
            .load_mission(&project.id, &mission.id)
            .expect("stored mission");

        let mut stale = request.clone();
        stale.observation_id = "stale-new-observation".into();
        let stale_observation = observation(&stale, ObservationClassification::Candidate);
        let before_stale = application
            .store
            .events_for_mission(&project.id, &mission.id)
            .expect("events")
            .len();
        assert!(matches!(
            application.accept_runtime_observation(&stale, stale_observation, now()),
            Err(ObservationPipelineError::MissionRevisionMismatch { .. })
        ));
        assert_eq!(
            application
                .store
                .events_for_mission(&project.id, &mission.id)
                .expect("events")
                .len(),
            before_stale
        );

        let stop = ObservationStopCommand {
            tenant_id: stored_mission.tenant_id.clone(),
            project_id: project.id.clone(),
            mission_id: mission.id.clone(),
            expected_mission_revision: stored_mission.revision,
            contract_version: stored_mission.contract.version,
            contract_digest: canonical_digest(&stored_mission.contract).expect("contract digest"),
        };
        let stopped = application
            .stop_runtime_observation_intake(&stop, now() + Duration::seconds(1))
            .expect("stop");
        assert!(!stopped.replayed);
        let after_stop = application
            .store
            .events_for_mission(&project.id, &mission.id)
            .expect("events")
            .len();

        let mut post_stop = request;
        post_stop.expected_mission_revision = stopped.mission_revision;
        post_stop.observation_id = "post-stop".into();
        let post_stop_observation = observation(&post_stop, ObservationClassification::Candidate);
        assert!(matches!(
            application.accept_runtime_observation(
                &post_stop,
                post_stop_observation,
                now() + Duration::seconds(2),
            ),
            Err(ObservationPipelineError::IntakeStopped)
        ));
        assert_eq!(
            application
                .store
                .events_for_mission(&project.id, &mission.id)
                .expect("events after stop")
                .len(),
            after_stop
        );
    }
}

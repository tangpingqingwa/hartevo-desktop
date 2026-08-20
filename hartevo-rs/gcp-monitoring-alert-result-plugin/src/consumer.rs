use std::{borrow::Borrow, collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::error::GcpMonitoringAlertError;
use crate::model::{
    Digest, GcpMonitoringAlertScope, MissionId, ProjectScopeId, RegistrationState, Revision,
};
use crate::service::{
    GcpMonitoringAlertProposal, GcpMonitoringAlertRegistration, ResultProjection,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission GCP Monitoring alert consumer is inactive")]
    Inactive,
    #[error("registration does not match the Mission/Project scope")]
    RegistrationMismatch,
    #[error("proposal does not match the Mission/Project evidence fence")]
    FenceMismatch,
    #[error("proposal failed deterministic integrity validation")]
    InvalidProposal,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("record idempotency key conflicts with another proposal")]
    RecordingConflict,
    #[error("recorded read-back failed deterministic validation")]
    ReadBackMismatch,
    #[error(transparent)]
    Model(#[from] GcpMonitoringAlertError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    PendingMissionDecision,
    Layer2ReviewRequired,
}

impl From<ResultProjection> for ProposalDisposition {
    fn from(value: ResultProjection) -> Self {
        match value {
            ResultProjection::Complete => Self::PendingMissionDecision,
            ResultProjection::Partial(_)
            | ResultProjection::AccessLost
            | ResultProjection::ProviderUnknown
            | ResultProjection::FinalError
            | ResultProjection::RegistrationReversed => Self::Layer2ReviewRequired,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGcpMonitoringAlertResult {
    pub service_id: String,
    pub consumer_id: String,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub project_scope_id: ProjectScopeId,
    pub project_revision: Revision,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub projection: ResultProjection,
    pub disposition: ProposalDisposition,
    pub evidence: crate::service::AlertEvidenceProjection,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub causal_incident_claim: bool,
    pub outcome_adopted: bool,
}

impl MissionGcpMonitoringAlertResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), ConsumerError> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.causal_incident_claim
            || self.outcome_adopted
            || !self.evidence.redaction_complete
            || self.evidence.raw_telemetry_retained
            || self.evidence.raw_log_labels_retained
        {
            return Err(ConsumerError::InvalidProposal);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedGcpMonitoringAlertResult {
    pub idempotency_key_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub projection: ResultProjection,
    pub disposition: ProposalDisposition,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub causal_incident_claim: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
    pub read_back_digest: Digest,
}

impl RecordedGcpMonitoringAlertResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &GcpMonitoringAlertProposal,
        replayed: bool,
    ) -> Self {
        let projection = proposal.projection;
        let disposition = projection.into();
        let mut result = Self {
            idempotency_key_digest,
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            projection,
            disposition,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            causal_incident_claim: false,
            outcome_adopted: false,
            recording_digest: Digest::from_text("unsealed-gcp-monitoring-recording"),
            read_back_digest: Digest::from_text("unsealed-gcp-monitoring-read-back"),
        };
        result.recording_digest = recording_digest(&result);
        result.read_back_digest = read_back_digest(&result);
        result
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), ConsumerError> {
        if self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.causal_incident_claim
            || self.outcome_adopted
            || self.recording_digest != recording_digest(self)
            || self.read_back_digest != read_back_digest(self)
        {
            return Err(ConsumerError::ReadBackMismatch);
        }
        Ok(())
    }
}

fn recording_digest(result: &RecordedGcpMonitoringAlertResult) -> Digest {
    Digest::from_parts(
        "gcp-monitoring-alert-recording/v1",
        &[
            (
                "idempotency",
                result.idempotency_key_digest.as_str().to_owned(),
            ),
            (
                "registration",
                result.registration_digest.as_str().to_owned(),
            ),
            ("scope", result.scope_digest.as_str().to_owned()),
            ("proposal", result.proposal_digest.as_str().to_owned()),
            ("evidence", result.evidence_digest.as_str().to_owned()),
            ("projection", format!("{:?}", result.projection)),
            ("disposition", format!("{:?}", result.disposition)),
            ("replayed", result.replayed.to_string()),
        ],
    )
}

fn read_back_digest(result: &RecordedGcpMonitoringAlertResult) -> Digest {
    Digest::from_parts(
        "gcp-monitoring-alert-read-back/v1",
        &[
            ("recording", result.recording_digest.as_str().to_owned()),
            ("proposal", result.proposal_digest.as_str().to_owned()),
            ("scope", result.scope_digest.as_str().to_owned()),
            ("replayed", result.replayed.to_string()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadBackReceipt {
    pub idempotency_key_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub recording_digest: Digest,
    pub read_back_digest: Digest,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_provider_receipt: bool,
    pub causal_incident_claim: bool,
}

impl From<&RecordedGcpMonitoringAlertResult> for ReadBackReceipt {
    fn from(value: &RecordedGcpMonitoringAlertResult) -> Self {
        Self {
            idempotency_key_digest: value.idempotency_key_digest.clone(),
            registration_digest: value.registration_digest.clone(),
            scope_digest: value.scope_digest.clone(),
            proposal_digest: value.proposal_digest.clone(),
            recording_digest: value.recording_digest.clone(),
            read_back_digest: value.read_back_digest.clone(),
            replayed: value.replayed,
            connected: false,
            native: false,
            durable_provider_receipt: false,
            causal_incident_claim: false,
        }
    }
}

pub struct MissionGcpMonitoringAlertConsumer {
    scope: GcpMonitoringAlertScope,
    registration: GcpMonitoringAlertRegistration,
    active: bool,
    records: BTreeMap<Digest, RecordedGcpMonitoringAlertResult>,
}

impl fmt::Debug for MissionGcpMonitoringAlertConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpMonitoringAlertConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .field("active", &self.active)
            .finish()
    }
}

impl MissionGcpMonitoringAlertConsumer {
    pub fn new(
        scope: GcpMonitoringAlertScope,
        registration: &GcpMonitoringAlertRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        registration
            .validate()
            .map_err(|_| ConsumerError::RegistrationMismatch)?;
        if !registration.is_active() || registration.scope_digest != scope.scope_digest() {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            active: true,
            records: BTreeMap::new(),
        })
    }

    pub fn new_owned(
        scope: GcpMonitoringAlertScope,
        registration: GcpMonitoringAlertRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        Self::new(scope, &registration)
    }

    pub fn registration(&self) -> &GcpMonitoringAlertRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &GcpMonitoringAlertScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke(&mut self) -> std::result::Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::Inactive)
        } else {
            self.active = false;
            self.registration.state = RegistrationState::Reversed;
            Ok(())
        }
    }

    pub fn consume<T: Borrow<GcpMonitoringAlertProposal>>(
        &self,
        proposal: T,
    ) -> std::result::Result<MissionGcpMonitoringAlertResult, ConsumerError> {
        if !self.active || !self.registration.is_active() {
            return Err(ConsumerError::Inactive);
        }
        let proposal = proposal.borrow();
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::InvalidProposal)?;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.scope_digest != self.scope.scope_digest()
            || proposal.mission_id != self.scope.mission_id().as_str()
            || proposal.mission_revision != self.scope.mission_revision()
            || proposal.project_scope_id != self.scope.project_scope_id().as_str()
            || proposal.project_revision != self.scope.project_revision()
            || proposal.evidence.fence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.fence.consent_digest != *self.scope.consent_digest()
        {
            return Err(ConsumerError::FenceMismatch);
        }
        Ok(MissionGcpMonitoringAlertResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            mission_id: self.scope.mission.mission_id.clone(),
            mission_revision: self.scope.mission_revision(),
            project_scope_id: self.scope.hartevo_project.project_id.clone(),
            project_revision: self.scope.project_revision(),
            scope_digest: self.scope.scope_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            projection: proposal.projection,
            disposition: proposal.projection.into(),
            evidence: proposal.evidence.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            causal_incident_claim: false,
            outcome_adopted: false,
        })
    }

    pub fn record<T: Borrow<GcpMonitoringAlertProposal>>(
        &mut self,
        proposal: T,
        idempotency_key: impl AsRef<str>,
    ) -> std::result::Result<RecordedGcpMonitoringAlertResult, ConsumerError> {
        let proposal = proposal.borrow();
        let _ = self.consume(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.read_back_digest = read_back_digest(&replay);
            return Ok(replay);
        }
        let result = RecordedGcpMonitoringAlertResult::new(key_digest.clone(), proposal, false);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn read_back(
        &self,
        idempotency_key: impl AsRef<str>,
    ) -> std::result::Result<ReadBackReceipt, ConsumerError> {
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key);
        let record = self
            .records
            .get(&key_digest)
            .ok_or(ConsumerError::ReadBackMismatch)?;
        record.validate_integrity()?;
        Ok(ReadBackReceipt::from(record))
    }
}

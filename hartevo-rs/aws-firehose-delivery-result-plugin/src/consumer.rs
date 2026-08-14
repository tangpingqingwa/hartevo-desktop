use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::error::{AwsFirehoseError, Result};
use crate::model::{
    AwsFirehoseDeliveryScope, DestinationHealth, Digest, MissionProjection, ProjectProjection,
    StreamStatus, TransportProvenance, WorkProductProjection,
};
use crate::service::{
    AwsFirehoseDeliveryProposal, AwsFirehoseEvidenceState, AwsFirehoseRegistration,
    RegistrationState, api_digest, contract_digest,
};
use crate::{CONSUMER_ID, MAX_IDENTIFIER_BYTES, PLUGIN_VERSION, SERVICE_ID};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Firehose consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS Firehose consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission AWS Firehose consumer Project/Mission/Work Product scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS Firehose consumer permission or provider scope fence is stale")]
    FenceMismatch,
    #[error("Mission AWS Firehose proposal is tampered or invalid")]
    ProposalTampered,
    #[error("Mission AWS Firehose recording key conflicts with a previous proposal")]
    RecordingConflict,
    #[error(transparent)]
    Service(#[from] AwsFirehoseError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsFirehoseDecisionState {
    ReviewRequired,
    Creating,
    Deleting,
    CreatingFailed,
    DeletingFailed,
    NotFound,
    Partial,
    AccessLoss,
    Throttled,
    Timeout,
    ProviderUnknown,
    RegistrationRevoked,
}

impl MissionAwsFirehoseDecisionState {
    fn from_evidence(state: AwsFirehoseEvidenceState) -> Self {
        match state {
            AwsFirehoseEvidenceState::Complete => Self::ReviewRequired,
            AwsFirehoseEvidenceState::Creating => Self::Creating,
            AwsFirehoseEvidenceState::Deleting => Self::Deleting,
            AwsFirehoseEvidenceState::CreatingFailed => Self::CreatingFailed,
            AwsFirehoseEvidenceState::DeletingFailed => Self::DeletingFailed,
            AwsFirehoseEvidenceState::NotFound => Self::NotFound,
            AwsFirehoseEvidenceState::Partial => Self::Partial,
            AwsFirehoseEvidenceState::AccessLoss => Self::AccessLoss,
            AwsFirehoseEvidenceState::Throttled => Self::Throttled,
            AwsFirehoseEvidenceState::Timeout => Self::Timeout,
            AwsFirehoseEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            AwsFirehoseEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsFirehoseResult {
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub decision_state: MissionAwsFirehoseDecisionState,
    pub observed_evidence_state: AwsFirehoseEvidenceState,
    pub provenance: TransportProvenance,
    pub stream_status: Option<StreamStatus>,
    pub destination_health: Option<DestinationHealth>,
    pub accepted_for_review: bool,
    pub requires_human_review: bool,
    pub data_handoff_verified: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsFirehoseResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub decision_state: MissionAwsFirehoseDecisionState,
    pub observed_evidence_state: AwsFirehoseEvidenceState,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsFirehoseResult {
    fn new(
        idempotency_key_digest: Digest,
        result: &MissionAwsFirehoseResult,
        replayed: bool,
    ) -> Self {
        let mut recorded = Self {
            idempotency_key_digest,
            proposal_digest: result.proposal_digest.clone(),
            evidence_digest: result.evidence_digest.clone(),
            decision_state: result.decision_state,
            observed_evidence_state: result.observed_evidence_state,
            provenance: result.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("pending-firehose-recording"),
        };
        recorded.recording_digest = recorded.compute_digest();
        recorded
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-recording/v1",
            &[
                ("idempotency", self.idempotency_key_digest.to_string()),
                ("proposal", self.proposal_digest.to_string()),
                ("evidence", self.evidence_digest.to_string()),
                ("decision", format!("{:?}", self.decision_state)),
                ("state", format!("{:?}", self.observed_evidence_state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.compute_digest()
        {
            return Err(AwsFirehoseError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionAwsFirehoseConsumer {
    scope: AwsFirehoseDeliveryScope,
    registration: AwsFirehoseRegistration,
    active: bool,
    records: BTreeMap<Digest, RecordedAwsFirehoseResult>,
}

impl fmt::Debug for MissionAwsFirehoseConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsFirehoseConsumer")
            .field("scope_digest", self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("active", &self.active)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsFirehoseConsumer {
    pub fn new(
        scope: AwsFirehoseDeliveryScope,
        registration: AwsFirehoseRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        registration.validate()?;
        if registration.state() != RegistrationState::Active
            || registration.scope_digest != *scope.digest()
            || registration.provider_scope_digest != *scope.provider_scope().digest()
            || registration.permission_digest != *scope.permission_snapshot().digest()
            || registration.source_revision != scope.provider_scope().source_revision()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration,
            active: true,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsFirehoseDeliveryScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsFirehoseRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke(&mut self) -> std::result::Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::RegistrationRevoked)
        } else {
            self.active = false;
            Ok(())
        }
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsFirehoseDeliveryProposal,
    ) -> std::result::Result<(), ConsumerError> {
        self.ensure_active()?;
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        self.validate_bindings(proposal)
    }

    pub fn consume(
        &self,
        proposal: &AwsFirehoseDeliveryProposal,
    ) -> std::result::Result<MissionAwsFirehoseResult, ConsumerError> {
        self.verify_proposal(proposal)?;
        let decision_state = MissionAwsFirehoseDecisionState::from_evidence(proposal.state);
        let stream_status = proposal
            .evidence
            .stream
            .as_ref()
            .map(|stream| stream.status);
        let destination_health = proposal
            .evidence
            .stream
            .as_ref()
            .map(|stream| stream.destination.health);
        let accepted_for_review = proposal.state == AwsFirehoseEvidenceState::Complete;
        let mut result = MissionAwsFirehoseResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: self.scope.digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            decision_state,
            observed_evidence_state: proposal.state,
            provenance: proposal.provenance,
            stream_status,
            destination_health,
            accepted_for_review,
            requires_human_review: true,
            data_handoff_verified: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            decision_digest: Digest::from_text("pending-firehose-decision"),
        };
        result.decision_digest = Digest::from_parts(
            "aws-firehose-mission-decision/v1",
            &[
                ("scope", result.scope_digest.to_string()),
                ("registration", result.registration_digest.to_string()),
                ("proposal", result.proposal_digest.to_string()),
                ("evidence", result.evidence_digest.to_string()),
                ("state", format!("{:?}", result.decision_state)),
                ("accepted", result.accepted_for_review.to_string()),
                ("handoff_verified", "false".to_owned()),
            ],
        );
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &AwsFirehoseDeliveryProposal,
        idempotency_key: impl AsRef<str>,
    ) -> std::result::Result<RecordedAwsFirehoseResult, ConsumerError> {
        let result = self.consume(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty()
            || idempotency_key.len() > MAX_IDENTIFIER_BYTES
            || idempotency_key.trim() != idempotency_key
        {
            return Err(ConsumerError::Service(AwsFirehoseError::InvalidRequest));
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.compute_digest();
            return Ok(replay);
        }
        let recorded = RecordedAwsFirehoseResult::new(key_digest.clone(), &result, false);
        self.records.insert(key_digest, recorded.clone());
        Ok(recorded)
    }

    fn ensure_active(&self) -> std::result::Result<(), ConsumerError> {
        if self.active && self.registration.state() == RegistrationState::Active {
            Ok(())
        } else {
            Err(ConsumerError::RegistrationRevoked)
        }
    }

    fn validate_bindings(
        &self,
        proposal: &AwsFirehoseDeliveryProposal,
    ) -> std::result::Result<(), ConsumerError> {
        if proposal.service_id != SERVICE_ID || proposal.consumer_id != CONSUMER_ID {
            return Err(ConsumerError::ProposalTampered);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.registration_revision != self.registration.registration_revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != *self.scope.digest()
            || proposal.evidence.digests.scope_digest != *self.scope.digest()
            || proposal.evidence.digests.provider_scope_digest
                != *self.scope.provider_scope().digest()
            || proposal.mission != MissionProjection::from(self.scope.mission())
            || proposal.project != ProjectProjection::from(self.scope.project())
            || proposal.work_product != WorkProductProjection::from(self.scope.work_product())
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.provider_definition_digest != *self.registration.provider_digest()
            || proposal.evidence.digests.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.digests.contract_digest != contract_digest()
            || proposal.evidence.digests.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || proposal.evidence.digests.api_digest != api_digest()
        {
            return Err(ConsumerError::FenceMismatch);
        }
        if proposal.evidence.digests.permission_digest != *self.scope.permission_snapshot().digest()
            || proposal.evidence.digests.stream_version_digest
                != self.scope.provider_scope().stream_version_id().digest()
            || proposal.evidence.digests.source_revision_digest
                != Digest::from_text(
                    self.scope
                        .provider_scope()
                        .source_revision()
                        .get()
                        .to_string(),
                )
        {
            return Err(ConsumerError::FenceMismatch);
        }
        Ok(())
    }
}

pub type MissionAwsFirehoseDeliveryConsumer = MissionAwsFirehoseConsumer;
pub type MissionAwsFirehoseDeliveryResult = MissionAwsFirehoseResult;
pub type MissionAwsFirehoseConsumerError = ConsumerError;

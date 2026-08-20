//! Mission-scoped review projection and idempotent below-kernel recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::error::AwsS3BucketError;
use crate::model::{
    AwsS3BucketScope, BucketDurabilityPosture, Digest, MissionProjection, ProjectProjection,
    TransportProvenance, WorkProductProjection,
};
use crate::service::{AwsS3EvidenceState, AwsS3Proposal, AwsS3Registration, RegistrationState};
use crate::{
    CONSUMER_ID, MAX_IDENTIFIER_BYTES, PLUGIN_VERSION, SERVICE_ID, api_digest, contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS S3 bucket consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS S3 bucket consumer registration does not match")]
    RegistrationMismatch,
    #[error("Mission AWS S3 bucket consumer Project/Mission/Work Product scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS S3 bucket consumer provider, permission or API fence is stale")]
    FenceMismatch,
    #[error("Mission AWS S3 bucket proposal is tampered or invalid")]
    ProposalTampered,
    #[error("Mission AWS S3 recording key conflicts with a previous proposal")]
    RecordingConflict,
    #[error(transparent)]
    Service(#[from] AwsS3BucketError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsS3DecisionState {
    ReviewRequired,
    ConfigurationUnknown,
    RegionDrift,
    Partial,
    Expired,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest,
    Throttled,
    Timeout,
    ProviderUnknown,
    RegistrationRevoked,
}

impl MissionAwsS3DecisionState {
    fn from_evidence(state: AwsS3EvidenceState) -> Self {
        match state {
            AwsS3EvidenceState::Complete => Self::ReviewRequired,
            AwsS3EvidenceState::ConfigurationUnknown => Self::ConfigurationUnknown,
            AwsS3EvidenceState::RegionDrift => Self::RegionDrift,
            AwsS3EvidenceState::Partial => Self::Partial,
            AwsS3EvidenceState::Expired => Self::Expired,
            AwsS3EvidenceState::AccessLoss => Self::AccessLoss,
            AwsS3EvidenceState::Unauthorized => Self::Unauthorized,
            AwsS3EvidenceState::Forbidden => Self::Forbidden,
            AwsS3EvidenceState::NotFound => Self::NotFound,
            AwsS3EvidenceState::BadRequest => Self::BadRequest,
            AwsS3EvidenceState::Throttled => Self::Throttled,
            AwsS3EvidenceState::Timeout => Self::Timeout,
            AwsS3EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            AwsS3EvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsS3BucketResult {
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AwsS3EvidenceState,
    pub decision_state: MissionAwsS3DecisionState,
    pub posture: BucketDurabilityPosture,
    pub provenance: TransportProvenance,
    pub requires_human_review: bool,
    pub accepted_for_review: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub decision_digest: Digest,
}

pub type MissionAwsS3Result = MissionAwsS3BucketResult;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsS3BucketResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: AwsS3EvidenceState,
    pub decision_state: MissionAwsS3DecisionState,
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

impl RecordedAwsS3BucketResult {
    fn new(
        idempotency_key_digest: Digest,
        result: &MissionAwsS3BucketResult,
        replayed: bool,
    ) -> Self {
        let mut value = Self {
            idempotency_key_digest,
            proposal_digest: result.proposal_digest.clone(),
            evidence_digest: result.evidence_digest.clone(),
            state: result.state,
            decision_state: result.decision_state,
            provenance: result.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::zero(),
        };
        value.recording_digest = value.recomputed_digest();
        value
    }

    pub fn validate_integrity(&self) -> Result<(), ConsumerError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.recomputed_digest()
        {
            Err(ConsumerError::ProposalTampered)
        } else {
            Ok(())
        }
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-recording/v1",
            &[
                ("idempotency", self.idempotency_key_digest.to_string()),
                ("proposal", self.proposal_digest.to_string()),
                ("evidence", self.evidence_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                ("decision", format!("{:?}", self.decision_state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

pub struct MissionAwsS3BucketConsumer {
    scope: AwsS3BucketScope,
    registration: AwsS3Registration,
    active: bool,
    records: BTreeMap<Digest, RecordedAwsS3BucketResult>,
}

impl fmt::Debug for MissionAwsS3BucketConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsS3BucketConsumer")
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

impl MissionAwsS3BucketConsumer {
    pub fn new(
        scope: AwsS3BucketScope,
        registration: AwsS3Registration,
    ) -> Result<Self, ConsumerError> {
        registration.validate()?;
        if registration.state() != RegistrationState::Active
            || registration.scope_digest != *scope.digest()
            || registration.provider_scope_digest != *scope.provider_scope().digest()
            || registration.bucket_digest != scope.bucket_digest()
            || registration.resource_revision != scope.resource_revision()
            || registration.permission_digest != *scope.permission_snapshot().digest()
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

    pub fn scope(&self) -> &AwsS3BucketScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsS3Registration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.active {
            self.active = false;
            Ok(())
        } else {
            Err(ConsumerError::RegistrationRevoked)
        }
    }

    pub fn verify_proposal(&self, proposal: &AwsS3Proposal) -> Result<(), ConsumerError> {
        self.ensure_active()?;
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        self.validate_bindings(proposal)
    }

    pub fn consume(
        &self,
        proposal: &AwsS3Proposal,
    ) -> Result<MissionAwsS3BucketResult, ConsumerError> {
        self.verify_proposal(proposal)?;
        let decision_state = MissionAwsS3DecisionState::from_evidence(proposal.state);
        let accepted_for_review = proposal.state == AwsS3EvidenceState::Complete;
        let mut result = MissionAwsS3BucketResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: self.scope.digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            decision_state,
            posture: proposal.posture.clone(),
            provenance: proposal.provenance,
            requires_human_review: true,
            accepted_for_review,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            decision_digest: Digest::zero(),
        };
        result.decision_digest = Digest::from_parts(
            "aws-s3-mission-decision/v1",
            &[
                ("scope", result.scope_digest.to_string()),
                ("registration", result.registration_digest.to_string()),
                ("proposal", result.proposal_digest.to_string()),
                ("evidence", result.evidence_digest.to_string()),
                ("state", format!("{:?}", result.decision_state)),
                ("accepted", result.accepted_for_review.to_string()),
            ],
        );
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &AwsS3Proposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsS3BucketResult, ConsumerError> {
        let result = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > MAX_IDENTIFIER_BYTES || key.trim() != key {
            return Err(ConsumerError::Service(AwsS3BucketError::InvalidRequest(
                "idempotency key".to_owned(),
            )));
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let replay = RecordedAwsS3BucketResult::new(key_digest, &result, true);
            return Ok(replay);
        }
        let recorded = RecordedAwsS3BucketResult::new(key_digest.clone(), &result, false);
        self.records.insert(key_digest, recorded.clone());
        Ok(recorded)
    }

    fn ensure_active(&self) -> Result<(), ConsumerError> {
        if self.active && self.registration.is_active() {
            Ok(())
        } else {
            Err(ConsumerError::RegistrationRevoked)
        }
    }

    fn validate_bindings(&self, proposal: &AwsS3Proposal) -> Result<(), ConsumerError> {
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
            || proposal.evidence.digests.bucket_digest != self.scope.bucket_digest()
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
            || proposal.evidence.digests.permission_digest
                != *self.scope.permission_snapshot().digest()
            || proposal.evidence.digests.resource_revision_digest
                != Digest::from_text(self.scope.resource_revision().get().to_string())
        {
            return Err(ConsumerError::FenceMismatch);
        }
        Ok(())
    }
}

pub type MissionAwsS3Consumer = MissionAwsS3BucketConsumer;
pub type MissionAwsS3BucketConsumerError = ConsumerError;
pub type MissionAwsS3BucketRecording = RecordedAwsS3BucketResult;

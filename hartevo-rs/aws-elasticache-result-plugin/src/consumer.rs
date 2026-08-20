//! Mission-scoped, non-authoritative AWS ElastiCache proposal consumption.

use std::{collections::BTreeMap, fmt};

use chrono::Utc;
use serde::Serialize;
use thiserror::Error;

use crate::error::AwsElastiCacheError;
use crate::model::{AwsElastiCacheScope, Digest, EvidenceState, TransportProvenance};
use crate::service::{
    AwsElastiCacheEvidence, AwsElastiCacheProposal, AwsElastiCacheRegistration,
    RecordedAwsElastiCacheResult, RegistrationStatus,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionAwsElastiCacheConsumerError {
    #[error("Mission AWS ElastiCache consumer registration is inactive")]
    RegistrationInactive,
    #[error("Mission AWS ElastiCache consumer scope or revision does not match")]
    ScopeMismatch,
    #[error("Mission AWS ElastiCache proposal was tampered with")]
    ProposalTampered,
    #[error("Mission AWS ElastiCache service validation failed: {0}")]
    Service(#[from] AwsElastiCacheError),
    #[error("Mission AWS ElastiCache idempotency key conflicts with a prior proposal")]
    RecordingConflict,
}

pub type ConsumerError = MissionAwsElastiCacheConsumerError;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsElastiCacheDecisionState {
    Healthy,
    Creating,
    Modifying,
    Failing,
    Replication,
    Degraded,
    Unavailable,
    FailoverInProgress,
    UpdateRequired,
    Stale,
    Partial,
    Expired,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<EvidenceState> for MissionAwsElastiCacheDecisionState {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Healthy => Self::Healthy,
            EvidenceState::Creating => Self::Creating,
            EvidenceState::Modifying => Self::Modifying,
            EvidenceState::Failing => Self::Failing,
            EvidenceState::Replication => Self::Replication,
            EvidenceState::Degraded => Self::Degraded,
            EvidenceState::Unavailable => Self::Unavailable,
            EvidenceState::FailoverInProgress => Self::FailoverInProgress,
            EvidenceState::UpdateRequired => Self::UpdateRequired,
            EvidenceState::Stale => Self::Stale,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::Expired => Self::Expired,
            EvidenceState::NotFound => Self::NotFound,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::Throttled => Self::Throttled,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsElastiCacheResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: EvidenceState,
    pub decision_state: MissionAwsElastiCacheDecisionState,
    pub evidence: crate::model::EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub requires_human_review: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub certification_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub decision_digest: Digest,
}

impl MissionAwsElastiCacheResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionAwsElastiCacheConsumer {
    scope: AwsElastiCacheScope,
    registration: AwsElastiCacheRegistration,
    records: BTreeMap<Digest, RecordedAwsElastiCacheResult>,
}

impl fmt::Debug for MissionAwsElastiCacheConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsElastiCacheConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsElastiCacheConsumer {
    pub fn new(
        scope: AwsElastiCacheScope,
        registration: AwsElastiCacheRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(ConsumerError::RegistrationInactive);
        }
        registration.validate_at(Utc::now())?;
        if registration.scope_digest() != &scope.digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsElastiCacheScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsElastiCacheRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsElastiCacheProposal,
    ) -> std::result::Result<MissionAwsElastiCacheResult, ConsumerError> {
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if !self.registration.is_active()
            || self.registration.status() != RegistrationStatus::Active
        {
            return Err(ConsumerError::RegistrationInactive);
        }
        self.registration.validate_at(Utc::now())?;
        if proposal.expires_at <= Utc::now() {
            return Err(ConsumerError::Service(AwsElastiCacheError::ConsentExpired));
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != *self.registration.permission_digest()
            || proposal.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.api_digest != *self.registration.api_digest()
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_state = proposal.state.into();
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-elasticache-decision/v1",
            &[
                ("consumer", CONSUMER_ID.to_owned()),
                (
                    "registration",
                    self.registration.registration_digest().to_string(),
                ),
                ("scope", self.scope.digest().to_string()),
                ("proposal", proposal.proposal_digest.to_string()),
                ("evidence", proposal.evidence.evidence_digest().to_string()),
                ("state", format!("{decision_state:?}")),
            ],
        );
        Ok(MissionAwsElastiCacheResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: crate::model::MissionProjection {
                id_digest: self.scope.mission.id.digest(),
                revision: self.scope.mission.revision,
            },
            project: crate::model::ProjectProjection {
                id_digest: self.scope.project.id.digest(),
                revision: self.scope.project.revision,
            },
            work_product: crate::model::WorkProductProjection {
                id_digest: self.scope.work_product.id.digest(),
                revision: self.scope.work_product.revision,
            },
            state: proposal.state,
            decision_state,
            evidence: proposal.evidence.digests.clone(),
            provenance: proposal.provenance.clone(),
            review_only: true,
            requires_human_review: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            decision_digest,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsElastiCacheProposal,
        idempotency_key: impl AsRef<str>,
    ) -> std::result::Result<RecordedAwsElastiCacheResult, ConsumerError> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::Service(AwsElastiCacheError::InvalidRequest));
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            // Replay is itself a deterministic redacted projection. The
            // original durable/native receipt boundary remains outside Layer 1.
            return Ok(existing.replayed());
        }
        let result = RecordedAwsElastiCacheResult::new_for_consumer(key_digest.clone(), proposal);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn verify_evidence(
        &self,
        evidence: &AwsElastiCacheEvidence,
    ) -> std::result::Result<(), ConsumerError> {
        evidence
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if evidence.expires_at <= Utc::now() {
            return Err(ConsumerError::Service(AwsElastiCacheError::ConsentExpired));
        }
        if evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != *self.registration.permission_digest()
            || evidence.provider_digest != *self.registration.provider_digest()
            || evidence.api_digest != *self.registration.api_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(())
    }
}

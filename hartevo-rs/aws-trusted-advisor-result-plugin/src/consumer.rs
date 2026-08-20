use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{AwsTrustedAdvisorScope, Digest, RecommendationStatus, TransportProvenance};
use crate::provider::AwsTrustedAdvisorTransport;
use crate::service::{
    AwsTrustedAdvisorObservationReceipt, AwsTrustedAdvisorProposal, AwsTrustedAdvisorService,
    AwsTrustedAdvisorServiceError, AwsTrustedAdvisorVerificationReport, EvidenceState,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionAwsTrustedAdvisorConsumerError {
    #[error("Mission AWS Trusted Advisor consumer is revoked")]
    Revoked,
    #[error("Mission AWS Trusted Advisor proposal was already consumed")]
    ReplayDetected,
    #[error("Mission AWS Trusted Advisor recording key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("Mission AWS Trusted Advisor proposal is invalid or out of scope")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] AwsTrustedAdvisorServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsTrustedAdvisorResultState {
    DecisionReady,
    RecommendationWarning,
    RecommendationError,
    NeedsMoreEvidence,
    UnsupportedSupportPlan,
    RefreshStale,
    RefreshInProgress,
    RefreshFailed,
    AccessLost,
    Throttled,
    CheckNotFound,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsTrustedAdvisorResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: crate::ProjectBinding,
    pub mission: crate::MissionBinding,
    pub work_product: crate::WorkProductBinding,
    pub evidence: crate::AwsTrustedAdvisorEvidence,
    pub state: MissionAwsTrustedAdvisorResultState,
    pub status: RecommendationStatus,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsTrustedAdvisorResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsTrustedAdvisorResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: MissionAwsTrustedAdvisorResultState,
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

impl RecordedAwsTrustedAdvisorResult {
    fn from_receipt(
        receipt: &AwsTrustedAdvisorObservationReceipt,
        result_state: MissionAwsTrustedAdvisorResultState,
    ) -> Self {
        let recording_digest = Digest::from_fields(
            "aws-trusted-advisor-recorded-result/v1",
            &[
                receipt.idempotency_key_digest.as_str().to_owned(),
                receipt.proposal_digest.as_str().to_owned(),
                format!("{result_state:?}"),
                receipt.provenance.as_str().to_owned(),
                receipt.replayed.to_string(),
            ],
        );
        Self {
            idempotency_key_digest: receipt.idempotency_key_digest.clone(),
            proposal_digest: receipt.proposal_digest.clone(),
            state: result_state,
            provenance: receipt.provenance,
            replayed: receipt.replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest,
        }
    }

    pub fn validate_integrity(&self) -> Result<(), MissionAwsTrustedAdvisorConsumerError> {
        let expected = Digest::from_fields(
            "aws-trusted-advisor-recorded-result/v1",
            &[
                self.idempotency_key_digest.as_str().to_owned(),
                self.proposal_digest.as_str().to_owned(),
                format!("{:?}", self.state),
                self.provenance.as_str().to_owned(),
                self.replayed.to_string(),
            ],
        );
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != expected
        {
            Err(MissionAwsTrustedAdvisorConsumerError::InvalidProposal)
        } else {
            Ok(())
        }
    }
}

pub struct MissionAwsTrustedAdvisorConsumer<T: AwsTrustedAdvisorTransport> {
    service: AwsTrustedAdvisorService<T>,
    active: bool,
    consumed_proposals: BTreeMap<Digest, MissionAwsTrustedAdvisorResult>,
    receipts: BTreeMap<Digest, AwsTrustedAdvisorObservationReceipt>,
}

impl<T: AwsTrustedAdvisorTransport> fmt::Debug for MissionAwsTrustedAdvisorConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsTrustedAdvisorConsumer")
            .field("scope_digest", self.service.scope().scope_digest())
            .field(
                "registration_digest",
                self.service.registration().registration_digest(),
            )
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .field("receipts", &self.receipts.len())
            .finish()
    }
}

impl<T: AwsTrustedAdvisorTransport> MissionAwsTrustedAdvisorConsumer<T> {
    pub fn new(
        service: AwsTrustedAdvisorService<T>,
    ) -> Result<Self, MissionAwsTrustedAdvisorConsumerError> {
        if !service.registration().is_active() {
            return Err(MissionAwsTrustedAdvisorConsumerError::Revoked);
        }
        Ok(Self {
            service,
            active: true,
            consumed_proposals: BTreeMap::new(),
            receipts: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn service(&self) -> &AwsTrustedAdvisorService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut AwsTrustedAdvisorService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &AwsTrustedAdvisorScope {
        self.service.scope()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active && self.service.registration().is_active()
    }

    pub fn read(
        &mut self,
    ) -> Result<crate::AwsTrustedAdvisorProposal, MissionAwsTrustedAdvisorConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<crate::AwsTrustedAdvisorProposal, MissionAwsTrustedAdvisorConsumerError> {
        self.read()
    }

    pub fn compile_proposal_at(
        &mut self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::AwsTrustedAdvisorProposal, MissionAwsTrustedAdvisorConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal_at(now)?)
    }

    pub fn consume(
        &mut self,
        proposal: &AwsTrustedAdvisorProposal,
    ) -> Result<MissionAwsTrustedAdvisorResult, MissionAwsTrustedAdvisorConsumerError> {
        self.ensure_active()?;
        proposal.validate_integrity(self.service.scope())?;
        if proposal.registration_digest != *self.service.registration().registration_digest() {
            return Err(MissionAwsTrustedAdvisorConsumerError::InvalidProposal);
        }
        if self
            .consumed_proposals
            .contains_key(&proposal.proposal_digest)
        {
            return Err(MissionAwsTrustedAdvisorConsumerError::ReplayDetected);
        }
        let result = MissionAwsTrustedAdvisorResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            work_product: proposal.work_product.clone(),
            evidence: proposal.evidence.clone(),
            state: result_state(proposal),
            status: proposal.evidence.status,
            provenance: proposal.evidence.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        self.consumed_proposals
            .insert(proposal.proposal_digest.clone(), result.clone());
        Ok(result)
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &AwsTrustedAdvisorProposal,
    ) -> Result<MissionAwsTrustedAdvisorResult, MissionAwsTrustedAdvisorConsumerError> {
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AwsTrustedAdvisorProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsTrustedAdvisorResult, MissionAwsTrustedAdvisorConsumerError> {
        self.ensure_active()?;
        let key_digest = Digest::from_text(idempotency_key.as_ref());
        if let Some(existing) = self.receipts.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(MissionAwsTrustedAdvisorConsumerError::RecordingConflict);
            }
            let replayed = existing.as_replayed();
            return Ok(RecordedAwsTrustedAdvisorResult::from_receipt(
                &replayed,
                result_state(proposal),
            ));
        }
        let result = if let Some(existing) = self.consumed_proposals.get(&proposal.proposal_digest)
        {
            proposal.validate_integrity(self.service.scope())?;
            if proposal.registration_digest != *self.service.registration().registration_digest() {
                return Err(MissionAwsTrustedAdvisorConsumerError::InvalidProposal);
            }
            existing.clone()
        } else {
            self.consume(proposal)?
        };
        let receipt = self
            .service
            .record_observation_receipt(proposal, idempotency_key)?;
        let recorded = RecordedAwsTrustedAdvisorResult::from_receipt(&receipt, result.state);
        self.receipts.insert(key_digest, receipt);
        Ok(recorded)
    }

    pub fn verify(
        &self,
        proposal: &AwsTrustedAdvisorProposal,
    ) -> Result<AwsTrustedAdvisorVerificationReport, MissionAwsTrustedAdvisorConsumerError> {
        self.ensure_active()?;
        Ok(self.service.verify_proposal(proposal)?)
    }

    pub fn revoke(&mut self) -> Result<(), MissionAwsTrustedAdvisorConsumerError> {
        self.ensure_active()?;
        self.service.revoke_registration()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionAwsTrustedAdvisorConsumerError> {
        if self.active {
            return Err(MissionAwsTrustedAdvisorConsumerError::InvalidProposal);
        }
        self.service.restore_registration()?;
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionAwsTrustedAdvisorConsumerError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(MissionAwsTrustedAdvisorConsumerError::Revoked)
        }
    }
}

fn result_state(proposal: &AwsTrustedAdvisorProposal) -> MissionAwsTrustedAdvisorResultState {
    if proposal.evidence.failure.is_none() {
        return match proposal.evidence.status {
            RecommendationStatus::Ok => MissionAwsTrustedAdvisorResultState::DecisionReady,
            RecommendationStatus::Warning => {
                MissionAwsTrustedAdvisorResultState::RecommendationWarning
            }
            RecommendationStatus::Error => MissionAwsTrustedAdvisorResultState::RecommendationError,
            RecommendationStatus::NotAvailable | RecommendationStatus::Unknown => {
                MissionAwsTrustedAdvisorResultState::NeedsMoreEvidence
            }
        };
    }
    match proposal.state() {
        EvidenceState::Complete => MissionAwsTrustedAdvisorResultState::DecisionReady,
        EvidenceState::Partial => MissionAwsTrustedAdvisorResultState::NeedsMoreEvidence,
        EvidenceState::UnsupportedSupportPlan => {
            MissionAwsTrustedAdvisorResultState::UnsupportedSupportPlan
        }
        EvidenceState::RefreshStale => MissionAwsTrustedAdvisorResultState::RefreshStale,
        EvidenceState::RefreshInProgress => MissionAwsTrustedAdvisorResultState::RefreshInProgress,
        EvidenceState::RefreshFailed => MissionAwsTrustedAdvisorResultState::RefreshFailed,
        EvidenceState::AccessLost => MissionAwsTrustedAdvisorResultState::AccessLost,
        EvidenceState::Throttled => MissionAwsTrustedAdvisorResultState::Throttled,
        EvidenceState::CheckNotFound => MissionAwsTrustedAdvisorResultState::CheckNotFound,
        EvidenceState::ProviderUnknown => MissionAwsTrustedAdvisorResultState::ProviderUnknown,
        EvidenceState::Tampered => MissionAwsTrustedAdvisorResultState::Tampered,
        EvidenceState::Revoked => MissionAwsTrustedAdvisorResultState::Revoked,
    }
}

pub type MissionAwsTrustedAdvisorResultConsumer<T> = MissionAwsTrustedAdvisorConsumer<T>;

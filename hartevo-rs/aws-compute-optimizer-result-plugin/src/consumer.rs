//! Mission-scoped evidence consumer. It can review and record proposals but
//! can never adopt an Outcome or execute a capacity effect.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AwsComputeOptimizerObservationReceipt, AwsComputeOptimizerProposal,
    AwsComputeOptimizerVerificationReport, Digest, EvidenceState, RecommendationStatus,
    TransportProvenance,
};
use crate::provider::AwsComputeOptimizerTransport;
use crate::service::{AwsComputeOptimizerService, AwsComputeOptimizerServiceError};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionAwsComputeOptimizerConsumerError {
    #[error("Mission AWS Compute Optimizer consumer is revoked")]
    Revoked,
    #[error("Mission AWS Compute Optimizer proposal was already consumed")]
    ReplayDetected,
    #[error("Mission AWS Compute Optimizer recording key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("Mission AWS Compute Optimizer proposal is invalid or out of scope")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] AwsComputeOptimizerServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsComputeOptimizerResultState {
    DecisionReady,
    RecommendationWarning,
    RecommendationUnderprovisioned,
    RecommendationOverprovisioned,
    NeedsMoreEvidence,
    Stale,
    Partial,
    ResourceNotFound,
    AccessLost,
    Throttled,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsComputeOptimizerResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: crate::ProjectBinding,
    pub mission: crate::MissionBinding,
    pub work_product: crate::WorkProductBinding,
    pub evidence: crate::AwsComputeOptimizerEvidence,
    pub state: MissionAwsComputeOptimizerResultState,
    pub status: RecommendationStatus,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub savings_guarantee: bool,
    pub resource_resize: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsComputeOptimizerResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsComputeOptimizerResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: MissionAwsComputeOptimizerResultState,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub savings_guarantee: bool,
    pub resource_resize: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsComputeOptimizerResult {
    fn from_receipt(
        receipt: &AwsComputeOptimizerObservationReceipt,
        state: MissionAwsComputeOptimizerResultState,
    ) -> Self {
        let recording_digest = Digest::from_fields(
            "aws-compute-optimizer-recorded-result/v1",
            &[
                receipt.idempotency_key_digest.as_str().to_owned(),
                receipt.proposal_digest.as_str().to_owned(),
                format!("{state:?}"),
                receipt.provenance.as_str().to_owned(),
                receipt.replayed.to_string(),
            ],
        );
        Self {
            idempotency_key_digest: receipt.idempotency_key_digest.clone(),
            proposal_digest: receipt.proposal_digest.clone(),
            state,
            provenance: receipt.provenance,
            replayed: receipt.replayed,
            connected: false,
            native: false,
            provider_receipt: false,
            savings_guarantee: false,
            resource_resize: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest,
        }
    }

    pub fn validate_integrity(&self) -> Result<(), MissionAwsComputeOptimizerConsumerError> {
        let expected = Digest::from_fields(
            "aws-compute-optimizer-recorded-result/v1",
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
            || self.provider_receipt
            || self.savings_guarantee
            || self.resource_resize
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != expected
        {
            Err(MissionAwsComputeOptimizerConsumerError::InvalidProposal)
        } else {
            Ok(())
        }
    }
}

pub struct MissionAwsComputeOptimizerConsumer<T: AwsComputeOptimizerTransport> {
    service: AwsComputeOptimizerService<T>,
    active: bool,
    consumed_proposals: BTreeMap<Digest, MissionAwsComputeOptimizerResult>,
    receipts: BTreeMap<Digest, AwsComputeOptimizerObservationReceipt>,
}

impl<T: AwsComputeOptimizerTransport> fmt::Debug for MissionAwsComputeOptimizerConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsComputeOptimizerConsumer")
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

impl<T: AwsComputeOptimizerTransport> MissionAwsComputeOptimizerConsumer<T> {
    pub fn new(
        service: AwsComputeOptimizerService<T>,
    ) -> Result<Self, MissionAwsComputeOptimizerConsumerError> {
        if !service.registration().is_active() {
            return Err(MissionAwsComputeOptimizerConsumerError::Revoked);
        }
        Ok(Self {
            service,
            active: true,
            consumed_proposals: BTreeMap::new(),
            receipts: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn service(&self) -> &AwsComputeOptimizerService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut AwsComputeOptimizerService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &crate::AwsComputeOptimizerScope {
        self.service.scope()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active && self.service.registration().is_active()
    }

    pub fn read(
        &mut self,
    ) -> Result<crate::AwsComputeOptimizerProposal, MissionAwsComputeOptimizerConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<crate::AwsComputeOptimizerProposal, MissionAwsComputeOptimizerConsumerError> {
        self.read()
    }

    pub fn compile_proposal_at(
        &mut self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::AwsComputeOptimizerProposal, MissionAwsComputeOptimizerConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal_at(now)?)
    }

    pub fn consume(
        &mut self,
        proposal: &AwsComputeOptimizerProposal,
    ) -> Result<MissionAwsComputeOptimizerResult, MissionAwsComputeOptimizerConsumerError> {
        self.ensure_active()?;
        proposal
            .validate_integrity(self.service.scope())
            .map_err(|_| MissionAwsComputeOptimizerConsumerError::InvalidProposal)?;
        if proposal.registration_digest != *self.service.registration().registration_digest() {
            return Err(MissionAwsComputeOptimizerConsumerError::InvalidProposal);
        }
        if self
            .consumed_proposals
            .contains_key(&proposal.proposal_digest)
        {
            return Err(MissionAwsComputeOptimizerConsumerError::ReplayDetected);
        }
        let result = MissionAwsComputeOptimizerResult {
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
            provider_receipt: false,
            savings_guarantee: false,
            resource_resize: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        self.consumed_proposals
            .insert(proposal.proposal_digest.clone(), result.clone());
        Ok(result)
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &AwsComputeOptimizerProposal,
    ) -> Result<MissionAwsComputeOptimizerResult, MissionAwsComputeOptimizerConsumerError> {
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AwsComputeOptimizerProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsComputeOptimizerResult, MissionAwsComputeOptimizerConsumerError> {
        self.ensure_active()?;
        let key_digest = Digest::from_text(idempotency_key.as_ref());
        if let Some(existing) = self.receipts.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(MissionAwsComputeOptimizerConsumerError::RecordingConflict);
            }
            let replayed = existing.as_replayed();
            return Ok(RecordedAwsComputeOptimizerResult::from_receipt(
                &replayed,
                result_state(proposal),
            ));
        }
        let result = if let Some(existing) = self.consumed_proposals.get(&proposal.proposal_digest)
        {
            existing.clone()
        } else {
            self.consume(proposal)?
        };
        let receipt = self
            .service
            .record_observation_receipt(proposal, idempotency_key)?;
        let recorded = RecordedAwsComputeOptimizerResult::from_receipt(&receipt, result.state);
        self.receipts.insert(key_digest, receipt);
        Ok(recorded)
    }

    pub fn verify(
        &self,
        proposal: &AwsComputeOptimizerProposal,
    ) -> Result<AwsComputeOptimizerVerificationReport, MissionAwsComputeOptimizerConsumerError>
    {
        self.ensure_active()?;
        Ok(self.service.verify_proposal(proposal)?)
    }

    pub fn revoke(&mut self) -> Result<(), MissionAwsComputeOptimizerConsumerError> {
        self.ensure_active()?;
        self.service.revoke_registration()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionAwsComputeOptimizerConsumerError> {
        if self.active {
            return Err(MissionAwsComputeOptimizerConsumerError::InvalidProposal);
        }
        self.service.restore_registration()?;
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionAwsComputeOptimizerConsumerError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(MissionAwsComputeOptimizerConsumerError::Revoked)
        }
    }
}

fn result_state(proposal: &AwsComputeOptimizerProposal) -> MissionAwsComputeOptimizerResultState {
    match proposal.state() {
        EvidenceState::Complete => match proposal.evidence.status {
            RecommendationStatus::Optimized => MissionAwsComputeOptimizerResultState::DecisionReady,
            RecommendationStatus::Underprovisioned => {
                MissionAwsComputeOptimizerResultState::RecommendationUnderprovisioned
            }
            RecommendationStatus::Overprovisioned => {
                MissionAwsComputeOptimizerResultState::RecommendationOverprovisioned
            }
            RecommendationStatus::NotOptimized => {
                MissionAwsComputeOptimizerResultState::RecommendationWarning
            }
            RecommendationStatus::NotAvailable | RecommendationStatus::Unknown => {
                MissionAwsComputeOptimizerResultState::NeedsMoreEvidence
            }
        },
        EvidenceState::Partial => MissionAwsComputeOptimizerResultState::Partial,
        EvidenceState::Stale => MissionAwsComputeOptimizerResultState::Stale,
        EvidenceState::ResourceNotFound => MissionAwsComputeOptimizerResultState::ResourceNotFound,
        EvidenceState::AccessLost => MissionAwsComputeOptimizerResultState::AccessLost,
        EvidenceState::Throttled => MissionAwsComputeOptimizerResultState::Throttled,
        EvidenceState::ProviderUnknown => MissionAwsComputeOptimizerResultState::ProviderUnknown,
        EvidenceState::Tampered => MissionAwsComputeOptimizerResultState::Tampered,
        EvidenceState::Revoked => MissionAwsComputeOptimizerResultState::Revoked,
    }
}

pub type AwsComputeOptimizerConsumer<T> = MissionAwsComputeOptimizerConsumer<T>;
pub type AwsComputeOptimizerResult = MissionAwsComputeOptimizerResult;
pub type AwsComputeOptimizerResultState = MissionAwsComputeOptimizerResultState;
pub type AwsComputeOptimizerRecordedResult = RecordedAwsComputeOptimizerResult;

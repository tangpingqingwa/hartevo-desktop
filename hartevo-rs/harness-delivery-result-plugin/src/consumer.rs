//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use zeroize::Zeroize;

use crate::error::{HarnessDeliveryResultError, Result};
use crate::model::{
    Digest, HarnessDeliveryScope, HarnessEvidenceState, MissionProjection, ProjectProjection,
    TransportProvenance, WorkProductProjection,
};
use crate::service::{HarnessDeliveryProposal, HarnessDeliveryRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    BlockedEnv,
    Tampered,
    AccessLoss,
    RegistrationRevoked,
}

impl From<HarnessEvidenceState> for ProposalDisposition {
    fn from(state: HarnessEvidenceState) -> Self {
        match state {
            HarnessEvidenceState::Queued => Self::Queued,
            HarnessEvidenceState::Running => Self::Running,
            HarnessEvidenceState::Succeeded => Self::Succeeded,
            HarnessEvidenceState::Failed => Self::Failed,
            HarnessEvidenceState::Cancelled => Self::Cancelled,
            HarnessEvidenceState::Partial => Self::Partial,
            HarnessEvidenceState::Denied => Self::Denied,
            HarnessEvidenceState::RateLimited => Self::RateLimited,
            HarnessEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            HarnessEvidenceState::BlockedEnv => Self::BlockedEnv,
            HarnessEvidenceState::Tampered => Self::Tampered,
            HarnessEvidenceState::AccessLoss => Self::AccessLoss,
            HarnessEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionHarnessDeliveryResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: HarnessEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: crate::model::EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionHarnessDeliveryResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedHarnessDeliveryResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: HarnessEvidenceState,
    pub disposition: ProposalDisposition,
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

impl RecordedHarnessDeliveryResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &HarnessDeliveryProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-harness-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "harness-delivery-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", format!("{:?}", self.provenance)),
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
            || self.recording_digest != self.calculate_digest()
        {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Consumer scoped to one exact Harness registration and Mission fence.
pub struct MissionHarnessDeliveryConsumer {
    scope: HarnessDeliveryScope,
    registration: HarnessDeliveryRegistration,
    records: BTreeMap<Digest, RecordedHarnessDeliveryResult>,
}

impl fmt::Debug for MissionHarnessDeliveryConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionHarnessDeliveryConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionHarnessDeliveryConsumer {
    pub fn new(
        scope: HarnessDeliveryScope,
        registration: HarnessDeliveryRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(HarnessDeliveryResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &HarnessDeliveryRegistration {
        &self.registration
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &HarnessDeliveryProposal,
    ) -> Result<MissionHarnessDeliveryResult> {
        proposal.validate_integrity()?;
        proposal.evidence.validate_integrity(&self.scope)?;
        if !self.registration.is_active() {
            return Err(HarnessDeliveryResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.mission != *self.scope.mission()
            || proposal.project != *self.scope.project()
            || proposal.work_product != *self.scope.work_product()
        {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        Ok(MissionHarnessDeliveryResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.evidence.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &HarnessDeliveryProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<RecordedHarnessDeliveryResult> {
        let _ = self.consume(proposal)?;
        let mut idempotency_key = idempotency_key.into();
        if idempotency_key.is_empty()
            || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES
            || idempotency_key.trim() != idempotency_key
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(HarnessDeliveryResultError::InvalidRequest);
        }
        let idempotency_key_digest = Digest::from_parts(
            "harness-idempotency-key/v1",
            &[("key", idempotency_key.clone())],
        );
        idempotency_key.zeroize();
        if let Some(existing) = self.records.get(&idempotency_key_digest) {
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let result =
            RecordedHarnessDeliveryResult::new(idempotency_key_digest.clone(), proposal, false);
        result.validate_integrity()?;
        self.records.insert(idempotency_key_digest, result.clone());
        Ok(result)
    }

    pub fn record_proposal(
        &mut self,
        proposal: &HarnessDeliveryProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<RecordedHarnessDeliveryResult> {
        self.record(proposal, idempotency_key)
    }
}

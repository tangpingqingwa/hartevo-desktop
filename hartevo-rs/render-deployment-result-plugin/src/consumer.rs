use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{RenderDeploymentError, Result};
use crate::model::{
    Digest, MissionProjection, ProjectProjection, ProviderProvenance, RenderDeploymentScope,
    RenderResultState, WorkProductProjection,
};
use crate::service::{
    RegistrationTransitionEvidence, RenderDeploymentEvidence, RenderDeploymentProposal,
    RenderDeploymentRegistration,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Ready,
    InProgress,
    Failed,
    Canceled,
    Partial,
    AccessLoss,
    RateLimited,
    Timeout,
    NotFound,
    Conflict,
    Tampered,
    StaleRevision,
    PaginationBound,
    PaginationLoop,
    ProviderUnknown,
    RegistrationRevoked,
    ConsentDenied,
    HealthUnknown,
}

impl From<RenderResultState> for ProposalDisposition {
    fn from(value: RenderResultState) -> Self {
        match value {
            RenderResultState::Ready => Self::Ready,
            RenderResultState::InProgress => Self::InProgress,
            RenderResultState::Failed => Self::Failed,
            RenderResultState::Canceled => Self::Canceled,
            RenderResultState::Partial => Self::Partial,
            RenderResultState::AccessLoss => Self::AccessLoss,
            RenderResultState::RateLimited => Self::RateLimited,
            RenderResultState::Timeout => Self::Timeout,
            RenderResultState::NotFound => Self::NotFound,
            RenderResultState::Conflict => Self::Conflict,
            RenderResultState::Tampered => Self::Tampered,
            RenderResultState::StaleRevision => Self::StaleRevision,
            RenderResultState::PaginationBound => Self::PaginationBound,
            RenderResultState::PaginationLoop => Self::PaginationLoop,
            RenderResultState::ProviderUnknown => Self::ProviderUnknown,
            RenderResultState::RegistrationRevoked => Self::RegistrationRevoked,
            RenderResultState::ConsentDenied => Self::ConsentDenied,
            RenderResultState::HealthUnknown => Self::HealthUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionRenderDeploymentResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub state: RenderResultState,
    pub disposition: ProposalDisposition,
    pub evidence: RenderDeploymentEvidence,
    pub provenance: ProviderProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub health_verified: bool,
}

impl MissionRenderDeploymentResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.health_verified
        {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        self.evidence.validate_integrity()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRenderDeploymentResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: RenderResultState,
    pub disposition: ProposalDisposition,
    pub provenance: ProviderProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedRenderDeploymentResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &RenderDeploymentProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::pending(),
        };
        result.recording_digest = result.compute_digest();
        result
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
            Err(RenderDeploymentError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.recording_digest = Digest::pending();
        let bytes = serde_json::to_vec(&value).expect("bounded Render recording serializes");
        Digest::from_bytes(&bytes)
    }
}

/// Mission consumer scoped to one exact Project/Mission/Work Product and
/// provider registration. It projects only redacted proposals and maintains
/// an in-memory idempotency fence.
pub struct MissionRenderDeploymentConsumer {
    scope: RenderDeploymentScope,
    registration: RenderDeploymentRegistration,
    records: BTreeMap<Digest, RecordedRenderDeploymentResult>,
}

impl fmt::Debug for MissionRenderDeploymentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionRenderDeploymentConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionRenderDeploymentConsumer {
    pub fn new(
        scope: RenderDeploymentScope,
        registration: RenderDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(RenderDeploymentError::RegistrationInactive);
        }
        if registration.scope().digest() != scope.digest() {
            return Err(RenderDeploymentError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &RenderDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut RenderDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &RenderDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn consume(
        &self,
        proposal: &RenderDeploymentProposal,
    ) -> Result<MissionRenderDeploymentResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(RenderDeploymentError::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.registration_revision != self.registration.registration_revision()
        {
            return Err(RenderDeploymentError::InvalidProposal);
        }
        let result = MissionRenderDeploymentResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project: proposal.evidence.project.clone(),
            mission: proposal.evidence.mission.clone(),
            work_product: proposal.evidence.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            health_verified: false,
        };
        result.validate_integrity()?;
        Ok(result)
    }

    pub fn project(
        &self,
        proposal: &RenderDeploymentProposal,
    ) -> Result<MissionRenderDeploymentResult> {
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &RenderDeploymentProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedRenderDeploymentResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::model::MAX_IDENTIFIER_BYTES {
            return Err(RenderDeploymentError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(RenderDeploymentError::RecordingConflict);
            }
            let replay = RecordedRenderDeploymentResult::new(key_digest, proposal, true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedRenderDeploymentResult::new(key_digest.clone(), proposal, false);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::error::{HerokuDeploymentError, Result};
use crate::model::{
    Digest, HerokuDeploymentScope, HerokuDeploymentState, MissionProjection, ProjectProjection,
    RegistrationStatus, WorkProductProjection, idempotency_digest,
};
use crate::service::{
    HerokuDeploymentProposal, HerokuDeploymentRegistration, RegistrationTransitionEvidence,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReleasedForReview,
    BuildingForReview,
    FailedForReview,
    BoundedFailureForReview,
}

impl From<HerokuDeploymentState> for ProposalDisposition {
    fn from(value: HerokuDeploymentState) -> Self {
        match value {
            HerokuDeploymentState::Released => Self::ReleasedForReview,
            HerokuDeploymentState::Building => Self::BuildingForReview,
            HerokuDeploymentState::Failed => Self::FailedForReview,
            HerokuDeploymentState::Unknown
            | HerokuDeploymentState::Partial
            | HerokuDeploymentState::Denied
            | HerokuDeploymentState::RateLimited
            | HerokuDeploymentState::ProviderUnknown
            | HerokuDeploymentState::Tampered
            | HerokuDeploymentState::StaleRevision
            | HerokuDeploymentState::PaginationLoop
            | HerokuDeploymentState::PaginationBound
            | HerokuDeploymentState::RegistrationRevoked
            | HerokuDeploymentState::ConsentDenied
            | HerokuDeploymentState::NotFound
            | HerokuDeploymentState::Conflict
            | HerokuDeploymentState::Replay => Self::BoundedFailureForReview,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionHerokuDeploymentResult {
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub account_id_digest: Digest,
    pub team_id_digest: Digest,
    pub app_id_digest: Digest,
    pub build_id_digest: Digest,
    pub release_id_digest: Digest,
    pub slug_id_digest: Digest,
    pub dyno_id_digest: Digest,
    pub state: HerokuDeploymentState,
    pub disposition: ProposalDisposition,
    pub review_only: bool,
    pub can_be_adopted: bool,
    pub evidence_digest: Digest,
    pub result_digest: Digest,
}

impl MissionHerokuDeploymentResult {
    fn from_proposal(proposal: &HerokuDeploymentProposal, scope: &HerokuDeploymentScope) -> Self {
        let mut result = Self {
            project: proposal.evidence.project.clone(),
            mission: proposal.evidence.mission.clone(),
            work_product: proposal.evidence.work_product.clone(),
            account_id_digest: scope.account_id().digest(),
            team_id_digest: scope.team_id().digest(),
            app_id_digest: proposal.evidence.app.as_ref().map_or_else(
                || scope.app_id().digest(),
                |value| value.app_id_digest.clone(),
            ),
            build_id_digest: proposal.evidence.build.as_ref().map_or_else(
                || scope.build_id().digest(),
                |value| value.build_id_digest.clone(),
            ),
            release_id_digest: proposal.evidence.release.as_ref().map_or_else(
                || scope.release_id().digest(),
                |value| value.release_id_digest.clone(),
            ),
            slug_id_digest: proposal.evidence.slug.as_ref().map_or_else(
                || scope.slug_id().digest(),
                |value| value.slug_id_digest.clone(),
            ),
            dyno_id_digest: proposal.evidence.dyno.as_ref().map_or_else(
                || scope.dyno_id().digest(),
                |value| value.dyno_id_digest.clone(),
            ),
            state: proposal.state,
            disposition: proposal.state.into(),
            review_only: true,
            can_be_adopted: false,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            result_digest: Digest::pending(),
        };
        result.result_digest = canonical_digest(&result);
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.review_only || self.can_be_adopted || self.result_digest != self.compute_digest() {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.result_digest = Digest::pending();
        canonical_digest(&value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedHerokuDeploymentResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub recorded_at: u64,
    pub replayed: bool,
    pub review_only: bool,
    pub provider_receipt: bool,
    pub result_digest: Digest,
}

impl RecordedHerokuDeploymentResult {
    fn new(
        proposal: &HerokuDeploymentProposal,
        idempotency_key_digest: Digest,
        recorded_at: u64,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            recorded_at,
            replayed,
            review_only: true,
            provider_receipt: false,
            result_digest: Digest::pending(),
        };
        result.result_digest = result.compute_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.review_only || self.provider_receipt || self.result_digest != self.compute_digest()
        {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.result_digest = Digest::pending();
        canonical_digest(&value)
    }
}

/// Mission-facing, review-only consumer. It projects exact scope and result
/// evidence without adopting an Outcome or Work Product.
pub struct MissionHerokuDeploymentConsumer {
    scope: HerokuDeploymentScope,
    registration: HerokuDeploymentRegistration,
    records: BTreeMap<Digest, Digest>,
}

impl fmt::Debug for MissionHerokuDeploymentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionHerokuDeploymentConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionHerokuDeploymentConsumer {
    pub fn new(
        scope: HerokuDeploymentScope,
        registration: HerokuDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope().digest() != scope.digest() {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &HerokuDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut HerokuDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &HerokuDeploymentScope {
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
        proposal: &HerokuDeploymentProposal,
    ) -> Result<MissionHerokuDeploymentResult> {
        self.registration.validate()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.registration_revision != self.registration.registration_revision()
        {
            return Err(HerokuDeploymentError::InvalidProposal);
        }
        let result = MissionHerokuDeploymentResult::from_proposal(proposal, &self.scope);
        result.validate_integrity()?;
        Ok(result)
    }

    pub fn project(
        &self,
        proposal: &HerokuDeploymentProposal,
    ) -> Result<MissionHerokuDeploymentResult> {
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &HerokuDeploymentProposal,
        idempotency_key: impl AsRef<str>,
        recorded_at: u64,
    ) -> Result<RecordedHerokuDeploymentResult> {
        let _ = self.consume(proposal)?;
        let key_digest = idempotency_digest(idempotency_key)?;
        let replayed = match self.records.get(&key_digest) {
            Some(existing) if existing == &proposal.proposal_digest => true,
            Some(_) => return Err(HerokuDeploymentError::RecordingConflict),
            None => false,
        };
        self.records
            .entry(key_digest.clone())
            .or_insert_with(|| proposal.proposal_digest.clone());
        let result =
            RecordedHerokuDeploymentResult::new(proposal, key_digest, recorded_at, replayed);
        result.validate_integrity()?;
        Ok(result)
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.registration.status(), RegistrationStatus::Active)
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("Layer-1 values serialize"))
}

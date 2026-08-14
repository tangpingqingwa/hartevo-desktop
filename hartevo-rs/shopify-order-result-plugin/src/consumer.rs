//! Mission-bound, evidence-only Shopify order-result consumer.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Digest, ProjectionState, Revision, ShopifyOrderResultScope};
use crate::provider::ShopifyOrderEvidence;
use crate::service::{RegistrationState, ShopifyAdoptionProposal, ShopifyRegistration};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("consumer registration is revoked")]
    Revoked,
    #[error("consumer registration does not match the Mission scope")]
    RegistrationMismatch,
    #[error("consumer scope fence does not match the proposal")]
    ScopeMismatch,
    #[error("adoption proposal is tampered or stale")]
    ProposalTampered,
    #[error("source evidence is tampered or stale")]
    EvidenceTampered,
    #[error("Layer 1 adoption proposal must remain evidence-only")]
    AuthorityEscalation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionShopifyOrderResultState {
    EvidenceReady,
    PartialEvidence,
    AccessLost,
    Deleted,
    Expired,
    Conflict,
    RateLimited,
    ProviderUnknown,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionShopifyOrderResult {
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub work_product_revision: Revision,
    pub projection_state: ProjectionState,
    pub state: MissionShopifyOrderResultState,
    pub evidence: ShopifyOrderEvidence,
    pub source_evidence_digest: Digest,
    pub result_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_work_product: bool,
}

#[derive(Clone, Debug)]
pub struct MissionShopifyOrderConsumer {
    scope: ShopifyOrderResultScope,
    registration_digest: Digest,
    registration_revision: Revision,
    active: bool,
}

impl MissionShopifyOrderConsumer {
    pub fn new(
        scope: ShopifyOrderResultScope,
        registration: &ShopifyRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != *scope.scope_digest()
            || registration.permission_digest != scope.permission_digest()
            || registration.mission_id != scope.mission().id().as_str()
            || registration.mission_revision != scope.mission().revision()
            || registration.project_id != scope.project().id().as_str()
            || registration.project_revision != scope.project().revision()
            || registration.work_product_id != scope.work_product().id().as_str()
            || registration.work_product_revision != scope.work_product().revision()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            active: true,
        })
    }

    pub fn scope(&self) -> &ShopifyOrderResultScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: ShopifyAdoptionProposal,
    ) -> Result<MissionShopifyOrderResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if !proposal.verify_digest() || !proposal.is_evidence_only() {
            return Err(ConsumerError::ProposalTampered);
        }
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.permission_digest != self.scope.permission_digest()
            || proposal.registration_digest != self.registration_digest
            || proposal.work_product_id != self.scope.work_product().id().as_str()
            || proposal.work_product_revision != self.scope.work_product().revision()
            || proposal.mission_id != self.scope.mission().id().as_str()
            || proposal.project_id != self.scope.project().id().as_str()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if !proposal.evidence.verify_digest()
            || proposal.evidence.evidence_digest != proposal.source_evidence_digest
            || proposal.evidence.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.permission_digest != self.scope.permission_digest()
            || proposal.evidence.registration_digest != self.registration_digest
        {
            return Err(ConsumerError::EvidenceTampered);
        }
        let state = mission_state(proposal.projection_state);
        let result_digest = Digest::from_serializable(&ResultFingerprint {
            mission_id: &proposal.mission_id,
            project_id: &proposal.project_id,
            work_product_id: &proposal.work_product_id,
            work_product_revision: proposal.work_product_revision,
            projection_state: proposal.projection_state,
            state,
            evidence_digest: &proposal.evidence.evidence_digest,
            registration_revision: self.registration_revision,
        });
        Ok(MissionShopifyOrderResult {
            mission_id: proposal.mission_id,
            project_id: proposal.project_id,
            work_product_id: proposal.work_product_id,
            work_product_revision: proposal.work_product_revision,
            projection_state: proposal.projection_state,
            state,
            evidence: proposal.evidence,
            source_evidence_digest: proposal.source_evidence_digest,
            result_digest,
            connected: false,
            native: false,
            first_party: false,
            adopts_work_product: false,
        })
    }
}

fn mission_state(state: ProjectionState) -> MissionShopifyOrderResultState {
    match state {
        ProjectionState::Complete => MissionShopifyOrderResultState::EvidenceReady,
        ProjectionState::Partial => MissionShopifyOrderResultState::PartialEvidence,
        ProjectionState::AccessLost => MissionShopifyOrderResultState::AccessLost,
        ProjectionState::Deleted => MissionShopifyOrderResultState::Deleted,
        ProjectionState::Expired => MissionShopifyOrderResultState::Expired,
        ProjectionState::Conflict => MissionShopifyOrderResultState::Conflict,
        ProjectionState::RateLimited => MissionShopifyOrderResultState::RateLimited,
        ProjectionState::ProviderUnknown | ProjectionState::BlockedEnv => {
            MissionShopifyOrderResultState::ProviderUnknown
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ResultFingerprint<'a> {
    mission_id: &'a str,
    project_id: &'a str,
    work_product_id: &'a str,
    work_product_revision: Revision,
    projection_state: ProjectionState,
    state: MissionShopifyOrderResultState,
    evidence_digest: &'a Digest,
    registration_revision: Revision,
}

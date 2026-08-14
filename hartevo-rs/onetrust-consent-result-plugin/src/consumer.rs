//! Mission/Project/Consent/Work Product projection for OneTrust evidence.
//!
//! The consumer creates only a canonical, non-mutating adoption proposal. It
//! does not adopt a Work Product, change Consent, issue an Effect, or grant
//! kernel Truth/Outcome authority.

use std::fmt;

use thiserror::Error;

use crate::model::{
    ConsentEvidenceStatus, Digest, OneTrustConsentScope, OneTrustEvidenceProposal,
    OneTrustRegistration, RegistrationState, Revision,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OneTrustConsumerError {
    #[error("Mission OneTrust consent consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Project/Consent/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    StaleProposal,
    #[error("proposal was not produced by the governed OneTrust service")]
    InvalidProposal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionConsentDecision {
    PendingDecision,
    Layer2AdoptionRequired,
    FailClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneTrustConsentAdoptionProposal {
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub consent_id: crate::ConsentId,
    pub consent_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub status: ConsentEvidenceStatus,
    pub decision: MissionConsentDecision,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub source_proposal_digest: Digest,
    pub canonical_digest: Digest,
    pub adopted: bool,
    pub mutates_consent: bool,
    pub creates_effect: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
}

pub struct MissionOneTrustConsentConsumer {
    scope: OneTrustConsentScope,
    registration_digest: Digest,
    registration_revision: Revision,
    active: bool,
}

impl fmt::Debug for MissionOneTrustConsentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionOneTrustConsentConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionOneTrustConsentConsumer {
    pub fn new(
        scope: OneTrustConsentScope,
        registration: &OneTrustRegistration,
    ) -> Result<Self, OneTrustConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.scope_digest()
        {
            return Err(OneTrustConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            active: true,
        })
    }

    pub fn scope(&self) -> &OneTrustConsentScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), OneTrustConsumerError> {
        if !self.active {
            return Err(OneTrustConsumerError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    /// Compile the canonical non-mutating adoption proposal. A later host
    /// layer may decide whether to adopt it; this method itself never does.
    pub fn propose_adoption(
        &self,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<OneTrustConsentAdoptionProposal, OneTrustConsumerError> {
        self.validate_proposal(proposal)?;
        let status = proposal.projection.status;
        let decision = match status {
            ConsentEvidenceStatus::Granted
            | ConsentEvidenceStatus::Denied
            | ConsentEvidenceStatus::Pending => MissionConsentDecision::PendingDecision,
            ConsentEvidenceStatus::Partial
            | ConsentEvidenceStatus::AccessLost
            | ConsentEvidenceStatus::Stale
            | ConsentEvidenceStatus::ProviderUnknown => MissionConsentDecision::FailClosed,
            ConsentEvidenceStatus::Withdrawn
            | ConsentEvidenceStatus::Expired
            | ConsentEvidenceStatus::NoRecord => MissionConsentDecision::Layer2AdoptionRequired,
        };
        let canonical_digest = Digest::from_fields([
            "hartevo-onetrust-adoption-proposal-v1".to_owned(),
            self.scope.mission.id.as_str().to_owned(),
            self.scope.mission.revision.get().to_string(),
            self.scope.project.id.as_str().to_owned(),
            self.scope.project.revision.get().to_string(),
            self.scope.consent.id.as_str().to_owned(),
            self.scope.consent.revision.get().to_string(),
            self.scope.work_product.id.as_str().to_owned(),
            self.scope.work_product.revision.get().to_string(),
            format!("{status:?}"),
            format!("{decision:?}"),
            proposal.scope_digest.as_str().to_owned(),
            proposal.registration_digest.as_str().to_owned(),
            proposal.evidence.evidence_digest.as_str().to_owned(),
            proposal.proposal_digest.as_str().to_owned(),
            "adopted:false".to_owned(),
            "mutates_consent:false".to_owned(),
            "creates_effect:false".to_owned(),
            "kernel_authority:false".to_owned(),
            "outcome_authority:false".to_owned(),
        ]);
        Ok(OneTrustConsentAdoptionProposal {
            mission_id: self.scope.mission.id.clone(),
            mission_revision: self.scope.mission.revision,
            project_id: self.scope.project.id.clone(),
            project_revision: self.scope.project.revision,
            consent_id: self.scope.consent.id.clone(),
            consent_revision: self.scope.consent.revision,
            work_product_id: self.scope.work_product.id.clone(),
            work_product_revision: self.scope.work_product.revision,
            status,
            decision,
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            source_proposal_digest: proposal.proposal_digest.clone(),
            canonical_digest,
            adopted: false,
            mutates_consent: false,
            creates_effect: false,
            kernel_authority: false,
            outcome_authority: false,
        })
    }

    pub fn consume(
        &self,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<OneTrustConsentAdoptionProposal, OneTrustConsumerError> {
        self.propose_adoption(proposal)
    }

    fn validate_proposal(
        &self,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<(), OneTrustConsumerError> {
        if !self.active {
            return Err(OneTrustConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration_digest
            || proposal.registration_revision != self.registration_revision
        {
            return Err(OneTrustConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != self.scope.scope_digest()
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.subject_reference != self.scope.subject_reference
            || proposal.permission_digest != self.scope.permission_digest
            || proposal.mission_revision != self.scope.mission.revision
            || proposal.project_revision != self.scope.project.revision
            || proposal.consent_revision != self.scope.consent.revision
            || proposal.work_product_revision != self.scope.work_product.revision
        {
            return Err(OneTrustConsumerError::ScopeMismatch);
        }
        if proposal.proposal_digest
            != proposal
                .recompute_digest()
                .map_err(|_| OneTrustConsumerError::StaleProposal)?
            || proposal.native
            || proposal.connected
            || proposal.adopted_by_kernel
        {
            return Err(OneTrustConsumerError::InvalidProposal);
        }
        if proposal.consent_receipt_created
            || proposal.consent_withdrawn
            || proposal.preference_updated
            || !proposal.read_only
            || !proposal.proposal_only
        {
            return Err(OneTrustConsumerError::InvalidProposal);
        }
        Ok(())
    }
}

//! Mission/Project/Consent-bound SailPoint certification evidence consumer.
//! The consumer emits an adoption proposal only; it never adopts kernel
//! Consent, Outcome, Effect, or access-safety authority.

use std::fmt;

use thiserror::Error;

use crate::{
    CampaignState, DecisionState, Digest, SailPointCertificationResultError,
    SailPointCertificationScope, SailPointEvidenceProposal, SailPointRegistration,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SailPointConsumerError {
    #[error("SailPoint consumer scope does not match the Mission/Project/Consent binding")]
    ScopeMismatch,
    #[error("SailPoint consumer registration is revoked")]
    RegistrationRevoked,
    #[error("SailPoint consumer proposal is stale, duplicated, or tampered")]
    StaleProposal,
    #[error("SailPoint consumer proposal violates Layer-1 authority")]
    AuthorityViolation,
    #[error("SailPoint consumer registration drifted: {0}")]
    RegistrationDrift(String),
}

impl From<SailPointCertificationResultError> for SailPointConsumerError {
    fn from(error: SailPointCertificationResultError) -> Self {
        match error {
            SailPointCertificationResultError::RegistrationRevoked => Self::RegistrationRevoked,
            SailPointCertificationResultError::RegistrationDrift(detail) => {
                Self::RegistrationDrift(detail)
            }
            SailPointCertificationResultError::Model(_)
            | SailPointCertificationResultError::StaleProposal
            | SailPointCertificationResultError::StaleEvidence => Self::StaleProposal,
            _ => Self::ScopeMismatch,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SailPointCertificationAdoptionProposal {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub campaign_state: CampaignState,
    pub decision_state: DecisionState,
    pub evidence_digest: Digest,
    pub adopted: bool,
    pub mutates_consent: bool,
    pub creates_effect: bool,
    pub access_safety_authority: bool,
    pub kernel_consent_authority: bool,
    pub kernel_outcome_authority: bool,
    pub certification_decision_authority: bool,
    pub raw_identity_payload_retained: bool,
    pub raw_access_payload_retained: bool,
}

/// Mission consumer for one exact SailPoint certification scope.
#[derive(Clone, Debug)]
pub struct MissionSailPointCertificationConsumer {
    scope: SailPointCertificationScope,
    registration_digest: Digest,
    active: bool,
}

impl MissionSailPointCertificationConsumer {
    pub fn new(
        scope: SailPointCertificationScope,
        registration: &SailPointRegistration,
    ) -> Result<Self, SailPointConsumerError> {
        if !registration.is_active() {
            return Err(SailPointConsumerError::RegistrationRevoked);
        }
        registration
            .validate(&scope)
            .map_err(|error| SailPointConsumerError::RegistrationDrift(error.to_string()))?;
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            active: true,
        })
    }

    pub fn scope(&self) -> &SailPointCertificationScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), SailPointConsumerError> {
        if !self.active {
            return Err(SailPointConsumerError::RegistrationRevoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn propose_adoption(
        &self,
        proposal: &SailPointEvidenceProposal,
    ) -> Result<SailPointCertificationAdoptionProposal, SailPointConsumerError> {
        self.consume(proposal)
    }

    pub fn consume(
        &self,
        proposal: &SailPointEvidenceProposal,
    ) -> Result<SailPointCertificationAdoptionProposal, SailPointConsumerError> {
        if !self.active {
            return Err(SailPointConsumerError::RegistrationRevoked);
        }
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.registration_digest != self.registration_digest
            || proposal.campaign_revision != self.scope.campaign_revision()
            || proposal.proposal_digest
                != proposal
                    .recompute_digest()
                    .map_err(|_| SailPointConsumerError::StaleProposal)?
            || proposal.evidence.evidence_digest
                != proposal
                    .evidence
                    .recompute_digest()
                    .map_err(|_| SailPointConsumerError::StaleProposal)?
        {
            return Err(SailPointConsumerError::ScopeMismatch);
        }
        if !proposal.read_only
            || !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.first_party
            || proposal.certification_approved
            || proposal.certification_revoked
            || proposal.certification_finalized
            || proposal.access_request_submitted
            || proposal.identity_mutated
            || proposal.entitlement_mutated
            || proposal.adopted_by_kernel
            || proposal.projection.access_safety_claim
            || proposal.evidence.raw_identity_payload_retained
            || proposal.evidence.raw_access_payload_retained
            || proposal.evidence.reviewer_pii_retained
            || proposal.evidence.identity_pii_retained
            || proposal.evidence.entitlement_descriptions_retained
            || proposal.evidence.reviewer_comments_retained
        {
            return Err(SailPointConsumerError::AuthorityViolation);
        }
        Ok(SailPointCertificationAdoptionProposal {
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            campaign_state: proposal.campaign_state(),
            decision_state: proposal.decision_state(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            adopted: false,
            mutates_consent: false,
            creates_effect: false,
            access_safety_authority: false,
            kernel_consent_authority: false,
            kernel_outcome_authority: false,
            certification_decision_authority: false,
            raw_identity_payload_retained: false,
            raw_access_payload_retained: false,
        })
    }
}

impl fmt::Display for SailPointCertificationAdoptionProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SailPointCertificationAdoptionProposal({:?}/{:?}, evidence={})",
            self.campaign_state, self.decision_state, self.evidence_digest
        )
    }
}

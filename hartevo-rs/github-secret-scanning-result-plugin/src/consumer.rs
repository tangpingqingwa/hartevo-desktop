//! Mission-facing proposal consumer.
//!
//! This consumer can bind a complete Layer-1 proposal to one exact Mission
//! scope. It cannot adopt Truth, Consent, Effect, Receipt, Verification,
//! Outcome, or security-certification authority.

use serde::Serialize;
use thiserror::Error;

use crate::model::{AlertNumber, AlertState, Digest, GithubSecretScanningScope, ValidityClass};
use crate::service::{
    GithubSecretScanningProposal, GithubSecretScanningRegistration, RegistrationState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionGithubSecretScanningDecisionState {
    UnresolvedAlert,
    ResolvedAlert,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission GitHub secret-scanning scope does not match the proposal")]
    ScopeMismatch,
    #[error("Mission GitHub secret-scanning registration is inactive or revoked")]
    RegistrationRevoked,
    #[error("Mission GitHub secret-scanning proposal is stale, duplicated, or tampered")]
    StaleProposal,
    #[error("Mission GitHub secret-scanning proposal violates Layer-1 authority")]
    AuthorityViolation,
    #[error("Mission GitHub secret-scanning evidence is partial or access was lost")]
    IncompleteEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGithubSecretScanningDecision {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub alert_number: AlertNumber,
    pub alert_state: AlertState,
    pub validity: ValidityClass,
    pub state: MissionGithubSecretScanningDecisionState,
    pub unresolved: bool,
    pub adopted: bool,
    pub creates_effect: bool,
    pub mutates_consent: bool,
    pub truth_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub security_certification_authority: bool,
}

pub type MissionGithubSecretScanningResult = MissionGithubSecretScanningDecision;

#[derive(Clone, Debug)]
pub struct MissionGithubSecretScanningConsumer {
    scope: GithubSecretScanningScope,
    registration_digest: Digest,
    active: bool,
}

impl MissionGithubSecretScanningConsumer {
    pub fn new(
        scope: GithubSecretScanningScope,
        registration: &GithubSecretScanningRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active() || registration.state == RegistrationState::Revoked {
            return Err(ConsumerError::RegistrationRevoked);
        }
        registration
            .validate_integrity()
            .map_err(|_| ConsumerError::StaleProposal)?;
        if registration.scope_digest != *scope.digest()
            || registration.query_digest != *scope.query_digest()
            || registration.permission_digest != *scope.permissions.digest()
            || registration.evidence_policy_digest != scope.evidence_policy_digest
            || registration.evidence_digest != scope.evidence_binding_digest()
            || registration.registration_digest.is_zero()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            active: true,
        })
    }

    pub fn scope(&self) -> &GithubSecretScanningScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: &GithubSecretScanningProposal,
    ) -> Result<MissionGithubSecretScanningDecision, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if proposal.scope_digest != *self.scope.digest()
            || proposal.registration_digest != self.registration_digest
            || proposal.proposal_digest != proposal.recomputed_digest_for_consumer()
        {
            return Err(ConsumerError::StaleProposal);
        }
        if !proposal.read_only
            || !proposal.proposal_only
            || proposal.connected
            || proposal.native
            || proposal.first_party
            || proposal.adopts_kernel_outcome
        {
            return Err(ConsumerError::AuthorityViolation);
        }
        proposal
            .evidence
            .validate(&self.scope)
            .map_err(|_| ConsumerError::IncompleteEvidence)?;
        let alert = &proposal.evidence.alert;
        let unresolved = alert.unresolved();
        Ok(MissionGithubSecretScanningDecision {
            scope_digest: self.scope.digest().clone(),
            registration_digest: self.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            alert_number: alert.number,
            alert_state: alert.state,
            validity: alert.validity,
            state: if unresolved {
                MissionGithubSecretScanningDecisionState::UnresolvedAlert
            } else {
                MissionGithubSecretScanningDecisionState::ResolvedAlert
            },
            unresolved,
            adopted: false,
            creates_effect: false,
            mutates_consent: false,
            truth_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            security_certification_authority: false,
        })
    }

    pub fn propose_adoption(
        &self,
        proposal: &GithubSecretScanningProposal,
    ) -> Result<MissionGithubSecretScanningDecision, ConsumerError> {
        self.consume(proposal)
    }
}

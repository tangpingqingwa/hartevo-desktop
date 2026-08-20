//! Mission/Project/Work Product/Consent-bound Chargebee result consumer.
//!
//! The consumer emits a proposal for a Mission's next customer/product
//! decision. It never adopts Consent, Work Product, Truth, Outcome, Effect,
//! billing, or financial-advice authority.

use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    ChargebeeObservationState, ChargebeeRegistration, ChargebeeSubscriptionResultError,
    ChargebeeSubscriptionResultProposal, ChargebeeSubscriptionScope, Digest,
};

/// Mission consumer failures.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionChargebeeConsumerError {
    #[error("Mission Chargebee consumer scope does not match the exact binding")]
    ScopeMismatch,
    #[error("Mission Chargebee consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission Chargebee proposal is stale, duplicated, or tampered")]
    StaleProposal,
    #[error("Mission Chargebee proposal violates the Layer-1 authority boundary")]
    AuthorityViolation,
    #[error("Mission Chargebee registration drifted: {0}")]
    RegistrationDrift(String),
}

impl From<ChargebeeSubscriptionResultError> for MissionChargebeeConsumerError {
    fn from(error: ChargebeeSubscriptionResultError) -> Self {
        match error {
            ChargebeeSubscriptionResultError::RegistrationRevoked => Self::RegistrationRevoked,
            ChargebeeSubscriptionResultError::RegistrationDrift(detail) => {
                Self::RegistrationDrift(detail)
            }
            ChargebeeSubscriptionResultError::ProposalTampered
            | ChargebeeSubscriptionResultError::ResponseTampered
            | ChargebeeSubscriptionResultError::DuplicateIdentifier
            | ChargebeeSubscriptionResultError::IdempotencyConflict => Self::StaleProposal,
            _ => Self::ScopeMismatch,
        }
    }
}

/// Mission-facing proposal. `accepted` means structurally accepted by this
/// consumer, not adopted as Truth/Outcome or a billing decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionChargebeeSubscriptionResult {
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
    pub overall_state: ChargebeeObservationState,
    pub accepted: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub financial_advice: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub result_digest_binding: Digest,
}

/// Mission consumer for one exact Chargebee scope.
#[derive(Clone, Debug)]
pub struct MissionChargebeeSubscriptionConsumer {
    scope: ChargebeeSubscriptionScope,
    registration_digest: Digest,
    active: bool,
}

impl MissionChargebeeSubscriptionConsumer {
    pub fn new(
        scope: ChargebeeSubscriptionScope,
        registration: &ChargebeeRegistration,
    ) -> Result<Self, MissionChargebeeConsumerError> {
        if !registration.is_active() {
            return Err(MissionChargebeeConsumerError::RegistrationRevoked);
        }
        registration
            .validate(&scope)
            .map_err(|error| MissionChargebeeConsumerError::RegistrationDrift(error.to_string()))?;
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            active: true,
        })
    }

    pub fn from_registration(
        scope: ChargebeeSubscriptionScope,
        registration: &ChargebeeRegistration,
    ) -> Result<Self, MissionChargebeeConsumerError> {
        Self::new(scope, registration)
    }

    pub fn scope(&self) -> &ChargebeeSubscriptionScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), MissionChargebeeConsumerError> {
        if !self.active {
            return Err(MissionChargebeeConsumerError::RegistrationRevoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn propose_adoption(
        &self,
        proposal: &ChargebeeSubscriptionResultProposal,
    ) -> Result<MissionChargebeeSubscriptionResult, MissionChargebeeConsumerError> {
        self.consume(proposal)
    }

    pub fn consume(
        &self,
        proposal: &ChargebeeSubscriptionResultProposal,
    ) -> Result<MissionChargebeeSubscriptionResult, MissionChargebeeConsumerError> {
        if !self.active {
            return Err(MissionChargebeeConsumerError::RegistrationRevoked);
        }
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.registration_digest != self.registration_digest
        {
            return Err(MissionChargebeeConsumerError::ScopeMismatch);
        }
        proposal
            .validate()
            .map_err(|_| MissionChargebeeConsumerError::StaleProposal)?;
        if proposal.evidence.scope.validate().is_err()
            || !proposal.evidence.redaction.is_safe()
            || proposal.native
            || proposal.connected
            || proposal.first_party
            || proposal.subscription_mutation
            || proposal.plan_mutation
            || proposal.entitlement_mutation
            || proposal.invoice_mutation
            || proposal.refund
            || proposal.payment_instruments
            || proposal.raw_customer_pii
            || proposal.financial_advice
            || proposal.kernel_authority
        {
            return Err(MissionChargebeeConsumerError::AuthorityViolation);
        }
        let result_digest_binding = Digest::from_fields([
            proposal.scope_digest.as_str(),
            proposal.registration_digest.as_str(),
            proposal.result_digest.as_str(),
            proposal.evidence_digest.as_str(),
        ]);
        Ok(MissionChargebeeSubscriptionResult {
            consumer_id: crate::CONSUMER_ID.to_owned(),
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            result_digest: proposal.result_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            overall_state: proposal.overall_state,
            accepted: true,
            adopted_outcome: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            financial_advice: false,
            connected: false,
            native: false,
            first_party: false,
            result_digest_binding,
        })
    }
}

impl fmt::Display for MissionChargebeeSubscriptionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MissionChargebeeSubscriptionResult({:?}, result={})",
            self.overall_state, self.result_digest
        )
    }
}

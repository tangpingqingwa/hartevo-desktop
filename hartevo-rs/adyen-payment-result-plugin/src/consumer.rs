use serde::{Deserialize, Serialize};

use crate::error::{AdyenPaymentResultError, Result};
use crate::model::{
    AdyenPaymentRegistration, AdyenPaymentResultProposal, AdyenPaymentResultState,
    AdyenPaymentScope, Digest, PluginVersion, RegistrationStatus, deterministic_idempotency_key,
};

/// Mission-facing consumer bound to one exact Adyen registration and payment
/// scope. It can project a verified proposal but cannot create a durable
/// Outcome or Work Product.
#[derive(Clone, Debug)]
pub struct MissionAdyenPaymentConsumer {
    scope: AdyenPaymentScope,
    provider_version: PluginVersion,
    registration_digest: Digest,
}

impl MissionAdyenPaymentConsumer {
    pub fn new(
        scope: AdyenPaymentScope,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self> {
        scope.validate()?;
        if provider_version != crate::PROVIDER_VERSION {
            return Err(AdyenPaymentResultError::ProviderVersionMismatch);
        }
        registration_digest.validate()?;
        Ok(Self {
            scope,
            provider_version,
            registration_digest,
        })
    }

    pub fn from_registration(registration: &AdyenPaymentRegistration) -> Result<Self> {
        registration.validate()?;
        if registration.status != RegistrationStatus::Active || !registration.is_active() {
            return Err(AdyenPaymentResultError::RegistrationRevoked);
        }
        Self::new(
            registration.scope.clone(),
            registration.provider_version,
            registration.registration_digest().clone(),
        )
    }

    pub fn scope(&self) -> &AdyenPaymentScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn consume(
        &self,
        proposal: &AdyenPaymentResultProposal,
    ) -> Result<AdyenPaymentResultProposal> {
        if proposal.scope != self.scope
            || proposal.registration_digest != self.registration_digest
            || proposal.result_state != AdyenPaymentResultState::DecisionReady
            || proposal.payment.status != crate::AdyenPaymentStatus::Authorised
            || proposal.idempotency_key
                != deterministic_idempotency_key(&proposal.scope, &proposal.payment)
            || !proposal.non_mutating
            || proposal.external_effect_created
            || proposal.durable_adoption
            || proposal.kernel_authority
            || proposal.financial_advice
            || proposal.native_connected
            || proposal.proposal_digest != proposal.compute_digest()
        {
            return Err(AdyenPaymentResultError::InvalidEvidence);
        }
        Ok(proposal.clone())
    }

    pub fn consume_result(
        &self,
        proposal: &AdyenPaymentResultProposal,
    ) -> Result<MissionAdyenPaymentResult> {
        let proposal = self.consume(proposal)?;
        MissionAdyenPaymentResult::from_proposal(
            proposal,
            self.provider_version,
            self.registration_digest.clone(),
        )
    }

    pub fn project(
        &self,
        proposal: &AdyenPaymentResultProposal,
    ) -> Result<AdyenPaymentResultProposal> {
        self.consume(proposal)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAdyenPaymentResult {
    pub proposal: AdyenPaymentResultProposal,
    pub result_digest: Digest,
    pub provider_version: PluginVersion,
    pub registration_digest: Digest,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub financial_advice: bool,
}

impl MissionAdyenPaymentResult {
    fn from_proposal(
        proposal: AdyenPaymentResultProposal,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self> {
        let result = Self {
            proposal,
            result_digest: Digest::pending(),
            provider_version,
            registration_digest,
            durable_adoption: false,
            kernel_authority: false,
            financial_advice: false,
        };
        let result = Self {
            result_digest: result.compute_digest(),
            ..result
        };
        result.validate()?;
        Ok(result)
    }

    pub fn computed_digest(&self) -> Digest {
        self.compute_digest()
    }

    pub fn validate(&self) -> Result<()> {
        if self.proposal.registration_digest != self.registration_digest
            || self.provider_version != crate::PROVIDER_VERSION
            || !self.proposal.non_mutating
            || self.durable_adoption
            || self.kernel_authority
            || self.financial_advice
            || self.result_digest != self.compute_digest()
        {
            return Err(AdyenPaymentResultError::InvalidEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let proposal_digest = self.proposal.proposal_digest.as_str().to_owned();
        Digest::from_parts(
            "hartevo-adyen-mission-payment-result/v1",
            &[
                ("proposal", proposal_digest),
                (
                    "provider_version",
                    self.provider_version.as_str().to_owned(),
                ),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("durable_adoption", self.durable_adoption.to_string()),
                ("kernel_authority", self.kernel_authority.to_string()),
                ("financial_advice", self.financial_advice.to_string()),
            ],
        )
    }
}

use serde::{Deserialize, Serialize};

use crate::error::{Result, SageMakerEndpointResultError};
use crate::model::{
    Digest, PluginVersion, RegistrationStatus, ResultVerificationStatus,
    SageMakerModelDeploymentProposal, SageMakerRegistration, SageMakerScope,
};

/// Mission-facing consumer for a provider-fingerprint-matched deployment
/// proposal. It never adopts a kernel Outcome or creates a durable Work
/// Product.
#[derive(Clone, Debug)]
pub struct MissionSageMakerDeploymentConsumer {
    scope: SageMakerScope,
    provider_version: PluginVersion,
    registration_digest: Digest,
}

impl MissionSageMakerDeploymentConsumer {
    pub fn new(
        scope: SageMakerScope,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self> {
        scope.validate()?;
        provider_version.validate()?;
        registration_digest.validate()?;
        if provider_version != crate::PROVIDER_VERSION {
            return Err(SageMakerEndpointResultError::InvalidRegistration);
        }
        Ok(Self {
            scope,
            provider_version,
            registration_digest,
        })
    }

    pub fn from_registration(registration: &SageMakerRegistration) -> Result<Self> {
        registration.validate()?;
        if registration.status != RegistrationStatus::Active {
            return Err(SageMakerEndpointResultError::RegistrationRevoked);
        }
        Self::new(
            registration.scope.clone(),
            registration.provider_version,
            registration.registration_digest.clone(),
        )
    }

    pub fn scope(&self) -> &SageMakerScope {
        &self.scope
    }

    pub fn provider_version(&self) -> PluginVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn consume(
        &self,
        proposal: &SageMakerModelDeploymentProposal,
    ) -> Result<SageMakerModelDeploymentProposal> {
        proposal.validate_for_registration(&self.registration_digest)?;
        if proposal.scope != self.scope
            || proposal.registration_digest != self.registration_digest
            || proposal.verification_status != ResultVerificationStatus::ProviderFingerprintMatch
            || proposal.native_connected
            || proposal.first_party
            || proposal.external_effect_performed
            || proposal.durable_adoption
            || proposal.kernel_authority
        {
            return Err(SageMakerEndpointResultError::InvalidEvidence);
        }
        Ok(proposal.clone())
    }

    pub fn project(
        &self,
        proposal: &SageMakerModelDeploymentProposal,
    ) -> Result<SageMakerModelDeploymentProposal> {
        self.consume(proposal)
    }

    pub fn consume_result(
        &self,
        proposal: &SageMakerModelDeploymentProposal,
    ) -> Result<MissionSageMakerDeploymentResult> {
        let proposal = self.consume(proposal)?;
        MissionSageMakerDeploymentResult::from_proposal(
            proposal,
            self.provider_version,
            self.registration_digest.clone(),
        )
    }
}

/// A typed Mission proposal below kernel Outcome authority. The result is
/// intentionally not a Connected/native claim and has no durable adoption.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionSageMakerDeploymentResult {
    pub proposal: SageMakerModelDeploymentProposal,
    pub result_digest: Digest,
    pub provider_version: PluginVersion,
    pub registration_digest: Digest,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
}

impl MissionSageMakerDeploymentResult {
    fn from_proposal(
        proposal: SageMakerModelDeploymentProposal,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self> {
        let mut result = Self {
            proposal,
            result_digest: Digest::pending(),
            provider_version,
            registration_digest,
            durable_adoption: false,
            kernel_authority: false,
        };
        result.result_digest = result.computed_digest();
        result.validate()?;
        Ok(result)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.result_digest = Digest::pending();
        crate::model::canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<()> {
        self.proposal
            .validate_for_registration(&self.registration_digest)?;
        self.provider_version.validate()?;
        self.registration_digest.validate()?;
        if self.provider_version != crate::PROVIDER_VERSION
            || self.registration_digest != self.proposal.registration_digest
            || self.durable_adoption
            || self.kernel_authority
            || self.result_digest != self.computed_digest()
        {
            return Err(SageMakerEndpointResultError::InvalidEvidence);
        }
        Ok(())
    }
}

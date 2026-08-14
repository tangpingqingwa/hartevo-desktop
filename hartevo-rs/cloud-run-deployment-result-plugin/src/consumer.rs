use serde::{Deserialize, Serialize};

use crate::error::CloudRunDeploymentResultError;
use crate::model::{
    CloudRunDeploymentResultProposal, CloudRunRegistration, CloudRunScope, Digest, PluginVersion,
    RegistrationStatus, ResultVerificationStatus,
};

/// Mission-facing consumer for a provider-fingerprint-matched deployment
/// result proposal. It never adopts a kernel Outcome or creates a durable Work
/// Product.
#[derive(Clone, Debug)]
pub struct MissionCloudRunDeploymentConsumer {
    scope: CloudRunScope,
    provider_version: PluginVersion,
    registration_digest: Digest,
}

impl MissionCloudRunDeploymentConsumer {
    pub fn new(
        scope: CloudRunScope,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        scope.validate()?;
        provider_version.validate()?;
        registration_digest.validate()?;
        if provider_version != crate::PROVIDER_VERSION {
            return Err(CloudRunDeploymentResultError::ProviderVersionMismatch);
        }
        Ok(Self {
            scope,
            provider_version,
            registration_digest,
        })
    }

    pub fn from_registration(
        registration: &CloudRunRegistration,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        registration.validate()?;
        if registration.status != RegistrationStatus::Active {
            return Err(CloudRunDeploymentResultError::RegistrationRevoked);
        }
        Self::new(
            registration.scope.clone(),
            registration.provider_version,
            registration.registration_digest.clone(),
        )
    }

    pub fn scope(&self) -> &CloudRunScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn consume(
        &self,
        proposal: &CloudRunDeploymentResultProposal,
    ) -> Result<CloudRunDeploymentResultProposal, CloudRunDeploymentResultError> {
        proposal.validate_for_registration(&self.registration_digest)?;
        if proposal.scope != self.scope
            || proposal.registration_digest != self.registration_digest
            || proposal.verification_status != ResultVerificationStatus::ProviderFingerprintMatch
            || proposal.native_connected
            || proposal.external_effect_performed
            || proposal.durable_adoption
            || proposal.kernel_authority
        {
            return Err(CloudRunDeploymentResultError::InvalidEvidence);
        }
        Ok(proposal.clone())
    }

    pub fn project(
        &self,
        proposal: &CloudRunDeploymentResultProposal,
    ) -> Result<CloudRunDeploymentResultProposal, CloudRunDeploymentResultError> {
        self.consume(proposal)
    }

    pub fn consume_result(
        &self,
        proposal: &CloudRunDeploymentResultProposal,
    ) -> Result<MissionCloudRunDeploymentResult, CloudRunDeploymentResultError> {
        let proposal = self.consume(proposal)?;
        MissionCloudRunDeploymentResult::from_proposal(
            proposal,
            self.provider_version,
            self.registration_digest.clone(),
        )
    }
}

/// Mission result envelope below kernel Outcome authority. It is a typed
/// proposal for composition, not a Connected/native or durable adoption claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCloudRunDeploymentResult {
    pub proposal: CloudRunDeploymentResultProposal,
    pub result_digest: Digest,
    pub provider_version: PluginVersion,
    pub registration_digest: Digest,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
}

impl MissionCloudRunDeploymentResult {
    fn from_proposal(
        proposal: CloudRunDeploymentResultProposal,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let mut result = Self {
            result_digest: Digest::pending(),
            proposal,
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
        crate::canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.proposal
            .validate_for_registration(&self.registration_digest)?;
        self.provider_version.validate()?;
        if self.provider_version != crate::PROVIDER_VERSION
            || self.registration_digest != self.proposal.registration_digest
            || self.durable_adoption
            || self.kernel_authority
            || self.result_digest != self.computed_digest()
        {
            return Err(CloudRunDeploymentResultError::InvalidEvidence);
        }
        Ok(())
    }
}

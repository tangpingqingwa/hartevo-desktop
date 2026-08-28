use serde::{Deserialize, Serialize};

use crate::error::TerraformCloudRunError;
use crate::model::{
    Digest, MissionWorkProductBinding, PROVIDER_VERSION, PluginVersion, ResultVerificationStatus,
    TerraformCloudRunRegistration, TerraformCloudScope, TerraformRunResultProposal,
};

/// Mission-facing consumer for a provider-fingerprint-matched run proposal.
/// It never adopts a kernel Outcome or creates a durable Work Product.
#[derive(Clone, Debug)]
pub struct MissionTerraformRunConsumer {
    scope: TerraformCloudScope,
    provider_version: PluginVersion,
    registration_digest: Digest,
}

impl MissionTerraformRunConsumer {
    pub fn new(
        scope: TerraformCloudScope,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self, TerraformCloudRunError> {
        scope.validate()?;
        provider_version.validate()?;
        registration_digest.validate()?;
        if provider_version != PROVIDER_VERSION {
            return Err(TerraformCloudRunError::ProviderVersionMismatch);
        }
        Ok(Self {
            scope,
            provider_version,
            registration_digest,
        })
    }

    pub fn from_registration(
        registration: &TerraformCloudRunRegistration,
    ) -> Result<Self, TerraformCloudRunError> {
        registration.validate()?;
        if registration.status != crate::RegistrationStatus::Active {
            return Err(TerraformCloudRunError::RegistrationRevoked);
        }
        Self::new(
            registration.scope.clone(),
            registration.plugin_version,
            registration.registration_digest.clone(),
        )
    }

    pub fn scope(&self) -> &TerraformCloudScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    /// Validate and pass through a proposal for Mission composition. The
    /// returned value remains a proposal and is not a kernel Outcome.
    pub fn consume(
        &self,
        proposal: &TerraformRunResultProposal,
    ) -> Result<TerraformRunResultProposal, TerraformCloudRunError> {
        proposal.validate_for_registration(&self.registration_digest)?;
        if proposal.scope != self.scope
            || proposal.registration_digest != self.registration_digest
            || proposal.verification_status != ResultVerificationStatus::ProviderFingerprintMatch
            || proposal.native_connected
            || proposal.external_effect_performed
            || proposal.durable_adoption
            || proposal.kernel_authority
        {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        Ok(proposal.clone())
    }

    pub fn project(
        &self,
        proposal: &TerraformRunResultProposal,
    ) -> Result<TerraformRunResultProposal, TerraformCloudRunError> {
        self.consume(proposal)
    }

    pub fn consume_result(
        &self,
        proposal: &TerraformRunResultProposal,
    ) -> Result<MissionTerraformRunResult, TerraformCloudRunError> {
        let proposal = self.consume(proposal)?;
        MissionTerraformRunResult::from_proposal(
            proposal,
            self.provider_version,
            self.registration_digest.clone(),
        )
    }
}

/// A Mission result envelope that intentionally remains below kernel Outcome
/// authority. It is useful for UI/next-Mission composition, not adoption.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionTerraformRunResult {
    pub proposal: TerraformRunResultProposal,
    pub result_digest: Digest,
    pub provider_version: PluginVersion,
    pub registration_digest: Digest,
    pub binding: MissionWorkProductBinding,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
}

impl MissionTerraformRunResult {
    fn from_proposal(
        proposal: TerraformRunResultProposal,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self, TerraformCloudRunError> {
        let result_digest = crate::canonical_digest(&(
            &proposal.result_digest,
            &provider_version,
            &registration_digest,
        ));
        let result = Self {
            binding: proposal.binding.clone(),
            proposal,
            result_digest,
            provider_version,
            registration_digest,
            durable_adoption: false,
            kernel_authority: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        self.proposal
            .validate_for_registration(&self.registration_digest)?;
        self.binding.validate_for(&self.proposal.scope)?;
        if self.provider_version != PROVIDER_VERSION
            || self.registration_digest != self.proposal.registration_digest
            || self.durable_adoption
            || self.kernel_authority
            || self.result_digest
                != crate::canonical_digest(&(
                    &self.proposal.result_digest,
                    &self.provider_version,
                    &self.registration_digest,
                ))
        {
            return Err(TerraformCloudRunError::InvalidEvidence);
        }
        Ok(())
    }
}

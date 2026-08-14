use serde::{Deserialize, Serialize};

use crate::{
    CONSUMER_ID, Digest, PluginVersion, PulumiDeploymentResultError,
    PulumiDeploymentResultProposal, PulumiDeploymentResultRegistration, PulumiDeploymentScope,
    ResultVerificationStatus,
};

/// Mission-facing consumer for a registration- and provider-fingerprint-bound
/// deployment-result proposal. It creates no kernel Outcome and has no effect
/// or mutation authority.
#[derive(Clone, Debug)]
pub struct MissionPulumiDeploymentConsumer {
    scope: PulumiDeploymentScope,
    provider_version: PluginVersion,
    registration_digest: Digest,
}

impl MissionPulumiDeploymentConsumer {
    pub fn new(
        scope: PulumiDeploymentScope,
        registration: &PulumiDeploymentResultRegistration,
    ) -> Result<Self, PulumiDeploymentResultError> {
        scope.validate()?;
        if !registration.is_active()
            || registration.scope != scope
            || registration.scope_digest != scope.digest()
            || registration.provider_version != crate::PROVIDER_VERSION
            || registration.registration_digest.validate().is_err()
        {
            return Err(PulumiDeploymentResultError::MissionScopeMismatch);
        }
        Ok(Self {
            scope,
            provider_version: registration.provider_version,
            registration_digest: registration.registration_digest.clone(),
        })
    }

    pub fn from_registration(
        registration: &PulumiDeploymentResultRegistration,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::new(registration.scope.clone(), registration)
    }

    pub fn consumer_id() -> &'static str {
        CONSUMER_ID
    }

    pub fn scope(&self) -> &PulumiDeploymentScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    /// Validate and pass through a result proposal for Mission composition.
    /// The value remains below kernel Outcome authority.
    pub fn consume(
        &self,
        proposal: &PulumiDeploymentResultProposal,
    ) -> Result<PulumiDeploymentResultProposal, PulumiDeploymentResultError> {
        proposal.validate()?;
        if proposal.scope != self.scope
            || proposal.registration_digest != self.registration_digest
            || proposal.connected
            || proposal.native
            || proposal.external_effect_performed
            || proposal.durable_adoption
            || proposal.kernel_authority
            || proposal.outcome_adoption
        {
            return Err(PulumiDeploymentResultError::MissionScopeMismatch);
        }
        Ok(proposal.clone())
    }

    pub fn project(
        &self,
        proposal: &PulumiDeploymentResultProposal,
    ) -> Result<PulumiDeploymentResultProposal, PulumiDeploymentResultError> {
        self.consume(proposal)
    }

    pub fn consume_result(
        &self,
        proposal: &PulumiDeploymentResultProposal,
    ) -> Result<MissionPulumiDeploymentResult, PulumiDeploymentResultError> {
        let proposal = self.consume(proposal)?;
        MissionPulumiDeploymentResult::from_proposal(
            proposal,
            self.provider_version,
            self.registration_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionPulumiDeploymentResult {
    pub proposal: PulumiDeploymentResultProposal,
    pub result_digest: Digest,
    pub provider_version: PluginVersion,
    pub registration_digest: Digest,
    pub mission_id: String,
    pub verification_status: ResultVerificationStatus,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl MissionPulumiDeploymentResult {
    fn from_proposal(
        proposal: PulumiDeploymentResultProposal,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self, PulumiDeploymentResultError> {
        let result_digest = Digest::from_serializable(&(
            &proposal.result_digest,
            provider_version,
            &registration_digest,
        ));
        let result = Self {
            mission_id: proposal.scope.mission_id.clone(),
            verification_status: proposal.verification_status,
            proposal,
            result_digest,
            provider_version,
            registration_digest,
            durable_adoption: false,
            kernel_authority: false,
            outcome_adoption: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), PulumiDeploymentResultError> {
        self.proposal.validate()?;
        if self.provider_version != crate::PROVIDER_VERSION
            || self.registration_digest != self.proposal.registration_digest
            || self.mission_id != self.proposal.scope.mission_id
            || self.verification_status != self.proposal.verification_status
            || self.durable_adoption
            || self.kernel_authority
            || self.outcome_adoption
            || self.result_digest
                != Digest::from_serializable(&(
                    &self.proposal.result_digest,
                    self.provider_version,
                    &self.registration_digest,
                ))
        {
            return Err(PulumiDeploymentResultError::OutcomeAdoptionForbidden);
        }
        Ok(())
    }
}

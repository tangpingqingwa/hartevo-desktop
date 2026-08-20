use serde::{Deserialize, Serialize};

use crate::{
    CONSUMER_ID, PLUGIN_VERSION, canonical_digest,
    error::AwsCodeDeployDeploymentResultError,
    model::{
        CodeDeployDeploymentResultProposal, CodeDeployRegistration, CodeDeployScope, Digest,
        MissionWorkProductBinding, PluginVersion,
    },
};

/// Mission consumer for a below-kernel deployment proposal. It has no Truth,
/// Effect, Receipt, Verification, Outcome, or Work Product adoption authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsCodeDeployDeploymentConsumer {
    binding: MissionWorkProductBinding,
    scope_digest: Digest,
    registration_digest: Digest,
}

impl MissionAwsCodeDeployDeploymentConsumer {
    pub fn new(
        scope: &CodeDeployScope,
        registration_digest: Digest,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        scope.validate()?;
        registration_digest.validate()?;
        Ok(Self {
            binding: MissionWorkProductBinding::from_scope(scope),
            scope_digest: scope.digest(),
            registration_digest,
        })
    }

    pub fn from_registration(
        registration: &CodeDeployRegistration,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        registration.validate()?;
        Self::new(
            &registration.scope,
            registration.registration_digest.clone(),
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn binding(&self) -> &MissionWorkProductBinding {
        &self.binding
    }

    pub fn consume(
        &self,
        proposal: &CodeDeployDeploymentResultProposal,
    ) -> Result<MissionAwsCodeDeployDeploymentResult, AwsCodeDeployDeploymentResultError> {
        proposal.validate_for_registration(&self.registration_digest)?;
        if proposal.scope.digest() != self.scope_digest || proposal.binding != self.binding {
            return Err(AwsCodeDeployDeploymentResultError::ConsumerScopeMismatch);
        }
        MissionAwsCodeDeployDeploymentResult::from_proposal(proposal)
    }

    pub fn consume_result(
        &self,
        proposal: &CodeDeployDeploymentResultProposal,
    ) -> Result<MissionAwsCodeDeployDeploymentResult, AwsCodeDeployDeploymentResultError> {
        self.consume(proposal)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsCodeDeployDeploymentResult {
    pub consumer_id: String,
    pub proposal: CodeDeployDeploymentResultProposal,
    pub result_digest: Digest,
    pub provider_version: PluginVersion,
    pub registration_digest: Digest,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl MissionAwsCodeDeployDeploymentResult {
    fn from_proposal(
        proposal: &CodeDeployDeploymentResultProposal,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let mut value = Self {
            consumer_id: CONSUMER_ID.to_owned(),
            proposal: proposal.clone(),
            result_digest: Digest::pending(),
            provider_version: PLUGIN_VERSION,
            registration_digest: proposal.registration_digest.clone(),
            durable_adoption: false,
            kernel_authority: false,
            outcome_adoption: false,
        };
        value.result_digest = value.computed_digest();
        value.validate()?;
        Ok(value)
    }

    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            &self.consumer_id,
            &self.proposal,
            &self.provider_version,
            &self.registration_digest,
            self.durable_adoption,
            self.kernel_authority,
            self.outcome_adoption,
        ))
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.consumer_id != CONSUMER_ID
            || self.provider_version != PLUGIN_VERSION
            || self.durable_adoption
            || self.kernel_authority
            || self.outcome_adoption
            || self.registration_digest != self.proposal.registration_digest
            || self.result_digest != self.computed_digest()
        {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        self.registration_digest.validate()?;
        self.proposal
            .validate_for_registration(&self.registration_digest)
    }
}

pub type MissionAwsCodeDeployConsumer = MissionAwsCodeDeployDeploymentConsumer;
pub type MissionAwsCodeDeployResult = MissionAwsCodeDeployDeploymentResult;
pub type MissionAwsCodeDeployDeploymentProposal = CodeDeployDeploymentResultProposal;

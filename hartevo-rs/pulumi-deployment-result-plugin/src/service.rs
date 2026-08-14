#![allow(clippy::struct_excessive_bools)]

use serde::{Deserialize, Serialize};

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, Digest, PLUGIN_ID, PROVIDER_ID, PluginVersion,
    PulumiCloudProvider, PulumiCloudTransport, PulumiCredentialResolver, PulumiDeploymentEvidence,
    PulumiDeploymentReceipt, PulumiDeploymentResultError, PulumiDeploymentResultProposal,
    PulumiDeploymentScope, PulumiStackDescription, RegistrationRevocation, SCHEMA_VERSION,
    SERVICE_ID,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PulumiDeploymentResultServiceOperation {
    DescribeStack,
    ReadDeploymentEvidence,
    RecordDeploymentReceipt,
    VerifyDeploymentResult,
    MissionResultProposal,
    Registration,
    Revocation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PulumiDeploymentResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub operations: Vec<PulumiDeploymentResultServiceOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl PulumiDeploymentResultServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: crate::PLUGIN_VERSION,
            operations: vec![
                PulumiDeploymentResultServiceOperation::DescribeStack,
                PulumiDeploymentResultServiceOperation::ReadDeploymentEvidence,
                PulumiDeploymentResultServiceOperation::RecordDeploymentReceipt,
                PulumiDeploymentResultServiceOperation::VerifyDeploymentResult,
                PulumiDeploymentResultServiceOperation::MissionResultProposal,
                PulumiDeploymentResultServiceOperation::Registration,
                PulumiDeploymentResultServiceOperation::Revocation,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<(), PulumiDeploymentResultError> {
        if self.schema_version != SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != crate::PLUGIN_VERSION
            || self.operations.len() != 7
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_writes
            || self.kernel_authority
            || self.outcome_adoption
        {
            return Err(PulumiDeploymentResultError::MutationForbidden {
                operation: "invalid service definition",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Typed Mission-facing facade for the Pulumi deployment-result seam.
#[derive(Debug)]
pub struct PulumiDeploymentResultService<T, R>
where
    T: PulumiCloudTransport,
    R: PulumiCredentialResolver,
{
    provider: PulumiCloudProvider<T, R>,
    definition: PulumiDeploymentResultServiceDefinition,
}

impl<T, R> PulumiDeploymentResultService<T, R>
where
    T: PulumiCloudTransport,
    R: PulumiCredentialResolver,
{
    pub fn new(provider: PulumiCloudProvider<T, R>) -> Result<Self, PulumiDeploymentResultError> {
        let definition = PulumiDeploymentResultServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &PulumiDeploymentResultServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &PulumiCloudProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut PulumiCloudProvider<T, R> {
        &mut self.provider
    }

    pub fn scope(&self) -> &PulumiDeploymentScope {
        self.provider.scope()
    }

    pub fn registration(&self) -> &crate::PulumiDeploymentResultRegistration {
        self.provider.registration()
    }

    pub fn describe_stack(
        &mut self,
    ) -> Result<PulumiStackDescription, PulumiDeploymentResultError> {
        self.provider.describe_stack()
    }

    pub fn read_deployment_evidence(
        &mut self,
    ) -> Result<PulumiDeploymentEvidence, PulumiDeploymentResultError> {
        self.provider.read_deployment_evidence()
    }

    pub fn read_deployment(
        &mut self,
    ) -> Result<PulumiDeploymentEvidence, PulumiDeploymentResultError> {
        self.provider.read_deployment_evidence()
    }

    pub fn record_deployment_receipt(
        &mut self,
        evidence: &PulumiDeploymentEvidence,
    ) -> Result<PulumiDeploymentReceipt, PulumiDeploymentResultError> {
        self.provider.record_deployment_receipt(evidence)
    }

    pub fn verify_deployment_result(
        &self,
        evidence: &PulumiDeploymentEvidence,
        receipt: &PulumiDeploymentReceipt,
    ) -> Result<PulumiDeploymentResultProposal, PulumiDeploymentResultError> {
        self.provider.verify_deployment_result(evidence, receipt)
    }

    pub fn compile_deployment_result_proposal(
        &self,
        evidence: &PulumiDeploymentEvidence,
        receipt: &PulumiDeploymentReceipt,
    ) -> Result<PulumiDeploymentResultProposal, PulumiDeploymentResultError> {
        self.provider
            .compile_deployment_result_proposal(evidence, receipt)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, PulumiDeploymentResultError> {
        self.provider.revoke()
    }

    pub fn reject_mutation(
        &self,
        operation: &'static str,
    ) -> Result<(), PulumiDeploymentResultError> {
        self.provider.reject_mutation(operation)
    }
}

pub type PulumiDeploymentResultReadOnlyService<T, R> = PulumiDeploymentResultService<T, R>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_is_layer_one_read_only_and_complete() {
        let definition = PulumiDeploymentResultServiceDefinition::layer1();
        definition.validate().expect("valid service definition");
        assert_eq!(definition.operations.len(), 7);
        assert!(definition.read_only);
        assert!(definition.proposal_only);
        assert!(definition.recording_only);
        assert!(!definition.external_writes);
        assert!(!definition.kernel_authority);
        assert!(!definition.outcome_adoption);
    }
}

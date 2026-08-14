use serde::{Deserialize, Serialize};

use crate::error::{Result, SageMakerEndpointResultError};
use crate::model::{
    Digest, PluginVersion, SageMakerDeploymentEvidence, SageMakerDeploymentReceipt,
    SageMakerEndpointConfigDescription, SageMakerEndpointDescription,
    SageMakerModelDeploymentProposal, SageMakerReadRequest, SageMakerScope,
    SageMakerServiceOperation, VerificationReport,
};
use crate::provider::{SageMakerProvider, SageMakerProviderState};
use crate::transport::{SageMakerTransport, SigV4CredentialResolver};

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub operations: Vec<SageMakerServiceOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub durable_receipts: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl SageMakerServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION.to_owned(),
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            service_id: crate::SERVICE_ID.to_owned(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            plugin_id: crate::PLUGIN_ID.to_owned(),
            plugin_version: crate::PLUGIN_VERSION,
            operations: vec![
                SageMakerServiceOperation::DescribeEndpoint,
                SageMakerServiceOperation::DescribeEndpointConfig,
                SageMakerServiceOperation::ReadDeploymentEvidence,
                SageMakerServiceOperation::CompileModelDeploymentProposal,
                SageMakerServiceOperation::RecordDeploymentReceipt,
                SageMakerServiceOperation::VerifyDeploymentResult,
                SageMakerServiceOperation::MissionDeploymentProposal,
                SageMakerServiceOperation::Registration,
                SageMakerServiceOperation::Revocation,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            durable_receipts: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::SCHEMA_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.service_id != crate::SERVICE_ID
            || self.provider_id != crate::PROVIDER_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.plugin_id != crate::PLUGIN_ID
            || self.plugin_version != crate::PLUGIN_VERSION
            || self.operations.len() != 9
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_writes
            || self.durable_receipts
            || self.kernel_authority
            || self.outcome_adoption
        {
            return Err(SageMakerEndpointResultError::MutationForbidden {
                operation: "invalid service definition",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        crate::model::canonical_digest(self)
    }
}

/// Typed Layer-1 SageMaker endpoint-result service. It owns no Store, keyring,
/// desktop, application, domain, catalog, or kernel authority.
pub struct SageMakerEndpointResultService<T, R>
where
    T: SageMakerTransport,
    R: SigV4CredentialResolver,
{
    provider: SageMakerProvider<T, R>,
    definition: SageMakerServiceDefinition,
}

impl<T, R> std::fmt::Debug for SageMakerEndpointResultService<T, R>
where
    T: SageMakerTransport,
    R: SigV4CredentialResolver,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SageMakerEndpointResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T, R> SageMakerEndpointResultService<T, R>
where
    T: SageMakerTransport,
    R: SigV4CredentialResolver,
{
    pub fn new(provider: SageMakerProvider<T, R>) -> Result<Self> {
        let definition = SageMakerServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &SageMakerServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &SageMakerProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SageMakerProvider<T, R> {
        &mut self.provider
    }

    pub fn state(&self) -> SageMakerProviderState {
        self.provider.state()
    }

    pub fn scope(&self) -> &SageMakerScope {
        &self.provider.registration().scope
    }

    pub fn describe_endpoint(&mut self) -> Result<SageMakerEndpointDescription> {
        self.provider.describe_endpoint()
    }

    pub fn describe_endpoint_config(&mut self) -> Result<SageMakerEndpointConfigDescription> {
        self.provider.describe_endpoint_config()
    }

    pub fn read_deployment_evidence(
        &mut self,
        request: &SageMakerReadRequest,
    ) -> Result<SageMakerDeploymentEvidence> {
        self.provider.read_deployment_evidence(request)
    }

    pub fn read_evidence(&mut self) -> Result<SageMakerDeploymentEvidence> {
        self.provider.read_evidence()
    }

    pub fn compile_model_deployment_proposal(
        &self,
        evidence: &SageMakerDeploymentEvidence,
    ) -> Result<SageMakerModelDeploymentProposal> {
        self.provider.compile_model_deployment_proposal(evidence)
    }

    pub fn compile_deployment_result_proposal(
        &self,
        evidence: &SageMakerDeploymentEvidence,
    ) -> Result<SageMakerModelDeploymentProposal> {
        self.compile_model_deployment_proposal(evidence)
    }

    pub fn record_deployment_receipt(
        &mut self,
        evidence: &SageMakerDeploymentEvidence,
    ) -> Result<SageMakerDeploymentReceipt> {
        self.provider.record_deployment_receipt(evidence)
    }

    pub fn verify_deployment_result(
        &self,
        proposal: &SageMakerModelDeploymentProposal,
        evidence: &SageMakerDeploymentEvidence,
        receipt: &SageMakerDeploymentReceipt,
    ) -> Result<SageMakerModelDeploymentProposal> {
        self.provider
            .verify_deployment_result(proposal, evidence, receipt)
    }

    pub fn verify_deployment_result_report(
        &self,
        proposal: &SageMakerModelDeploymentProposal,
        evidence: &SageMakerDeploymentEvidence,
        receipt: &SageMakerDeploymentReceipt,
    ) -> VerificationReport {
        self.provider
            .verify_deployment_result_report(proposal, evidence, receipt)
    }

    pub fn revoke(&mut self) -> Result<crate::model::RegistrationRevocation> {
        self.provider.revoke()
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        self.provider.reject_write(operation)
    }
}

pub type SageMakerReadOnlyService<T, R> = SageMakerEndpointResultService<T, R>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_is_complete_and_read_only() {
        let definition = SageMakerServiceDefinition::layer1();
        definition.validate().expect("valid definition");
        assert_eq!(definition.operations.len(), 9);
        assert!(definition.read_only);
        assert!(definition.proposal_only);
        assert!(definition.recording_only);
        assert!(!definition.external_writes);
        assert!(!definition.durable_receipts);
        assert!(!definition.kernel_authority);
        assert!(!definition.outcome_adoption);
    }
}

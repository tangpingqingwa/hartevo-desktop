use serde::{Deserialize, Serialize};

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SCHEMA_VERSION,
    SERVICE_ID,
    error::AwsCodeDeployDeploymentResultError,
    model::{
        CodeDeployDeploymentEvidence, CodeDeployDeploymentReceipt,
        CodeDeployDeploymentResultProposal, CodeDeployReadRequest, CodeDeployRegistration,
        CodeDeployScope, Digest, PluginVersion, RegistrationRevocation, SecretReference,
    },
    provider::CodeDeployProvider,
    transport::CodeDeployTransport,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeDeployServiceOperation {
    DescribeService,
    ReadDeploymentEvidence,
    CompileDeploymentResultProposal,
    RecordDeploymentReceipt,
    VerifyDeploymentResult,
    MissionDeploymentResultProposal,
    Registration,
    Revocation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub operations: Vec<CodeDeployServiceOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub durable_provider_receipt: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl CodeDeployServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            operations: vec![
                CodeDeployServiceOperation::DescribeService,
                CodeDeployServiceOperation::ReadDeploymentEvidence,
                CodeDeployServiceOperation::CompileDeploymentResultProposal,
                CodeDeployServiceOperation::RecordDeploymentReceipt,
                CodeDeployServiceOperation::VerifyDeploymentResult,
                CodeDeployServiceOperation::MissionDeploymentResultProposal,
                CodeDeployServiceOperation::Registration,
                CodeDeployServiceOperation::Revocation,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            durable_provider_receipt: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.schema_version != SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.operations.len() != 8
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_writes
            || self.durable_provider_receipt
            || self.kernel_authority
            || self.outcome_adoption
        {
            return Err(AwsCodeDeployDeploymentResultError::MutationForbidden {
                operation: "invalid service definition",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        crate::canonical_digest(self)
    }
}

/// Mission-facing service facade. It exposes only bounded reads, proposals,
/// redacted recording, verification, and registration lifecycle.
pub struct CodeDeployDeploymentResultService<T>
where
    T: CodeDeployTransport,
{
    provider: CodeDeployProvider<T>,
    definition: CodeDeployServiceDefinition,
}

impl<T> std::fmt::Debug for CodeDeployDeploymentResultService<T>
where
    T: CodeDeployTransport,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodeDeployDeploymentResultService")
            .field("definition", &self.definition)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T> CodeDeployDeploymentResultService<T>
where
    T: CodeDeployTransport,
{
    pub fn new(
        provider: CodeDeployProvider<T>,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let definition = CodeDeployServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &CodeDeployServiceDefinition {
        &self.definition
    }

    pub fn definition_digest(&self) -> Digest {
        self.definition.digest()
    }

    pub fn provider(&self) -> &CodeDeployProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut CodeDeployProvider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &CodeDeployScope {
        &self.provider.registration().scope
    }

    pub fn describe_service(&self) -> &CodeDeployServiceDefinition {
        &self.definition
    }

    pub fn read_deployment_evidence(
        &mut self,
        request: &CodeDeployReadRequest,
    ) -> Result<CodeDeployDeploymentEvidence, AwsCodeDeployDeploymentResultError> {
        self.provider.read_deployment_evidence(request)
    }

    pub fn read_evidence(
        &mut self,
    ) -> Result<CodeDeployDeploymentEvidence, AwsCodeDeployDeploymentResultError> {
        self.provider.read_evidence()
    }

    pub fn compile_deployment_result_proposal(
        &self,
        evidence: &CodeDeployDeploymentEvidence,
    ) -> Result<CodeDeployDeploymentResultProposal, AwsCodeDeployDeploymentResultError> {
        self.provider.compile_deployment_result_proposal(evidence)
    }

    pub fn propose(
        &self,
        evidence: &CodeDeployDeploymentEvidence,
    ) -> Result<CodeDeployDeploymentResultProposal, AwsCodeDeployDeploymentResultError> {
        self.compile_deployment_result_proposal(evidence)
    }

    pub fn record_deployment_receipt(
        &mut self,
        evidence: &CodeDeployDeploymentEvidence,
    ) -> Result<CodeDeployDeploymentReceipt, AwsCodeDeployDeploymentResultError> {
        self.provider.record_deployment_receipt(evidence)
    }

    pub fn record(
        &mut self,
        evidence: &CodeDeployDeploymentEvidence,
    ) -> Result<CodeDeployDeploymentReceipt, AwsCodeDeployDeploymentResultError> {
        self.record_deployment_receipt(evidence)
    }

    pub fn verify_deployment_result(
        &self,
        proposal: &CodeDeployDeploymentResultProposal,
        evidence: &CodeDeployDeploymentEvidence,
        receipt: &CodeDeployDeploymentReceipt,
    ) -> Result<CodeDeployDeploymentResultProposal, AwsCodeDeployDeploymentResultError> {
        self.provider
            .verify_deployment_result(proposal, evidence, receipt)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, AwsCodeDeployDeploymentResultError> {
        self.provider.revoke()
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, AwsCodeDeployDeploymentResultError> {
        self.revoke_registration()
    }

    pub fn reject_write(
        &self,
        operation: &'static str,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        self.provider.reject_write(operation)
    }

    pub fn register(
        scope: CodeDeployScope,
        secret_reference: SecretReference,
        adapter_revision: u64,
    ) -> Result<CodeDeployRegistration, AwsCodeDeployDeploymentResultError> {
        CodeDeployRegistration::new(scope, secret_reference, adapter_revision)
    }
}

pub type AwsCodeDeployDeploymentResultService<T> = CodeDeployDeploymentResultService<T>;
pub type AwsCodeDeployReadOnlyService<T> = CodeDeployDeploymentResultService<T>;
pub type CodeDeployReadOnlyService<T> = CodeDeployDeploymentResultService<T>;
pub type AwsCodeDeployService<T> = CodeDeployDeploymentResultService<T>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_definition_is_read_proposal_and_recording_only() {
        let definition = CodeDeployServiceDefinition::layer1();
        definition.validate().expect("valid Layer-1 definition");
        assert_eq!(definition.operations.len(), 8);
        assert!(definition.read_only);
        assert!(definition.proposal_only);
        assert!(definition.recording_only);
        assert!(!definition.external_writes);
        assert!(!definition.durable_provider_receipt);
        assert!(!definition.kernel_authority);
        assert!(!definition.outcome_adoption);
    }
}

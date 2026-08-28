use serde::{Deserialize, Serialize};

use crate::error::TerraformCloudRunError;
use crate::model::{
    ApplyProposal, ApplyProposalRequest, CONSUMER_ID, CONTRACT_VERSION, ConfigurationProposal,
    ConfigurationProposalRequest, Digest, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, PluginVersion,
    RunEvidence, RunProposal, RunProposalRequest, RunReceipt, SERVICE_ID, TerraformCloudScope,
    TerraformRunResultProposal, WorkspaceDescription,
};
use crate::provider::{TerraformCloudCredentialResolver, TerraformCloudRunProvider};
use crate::transport::TerraformCloudRunTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerraformCloudRunServiceOperation {
    DescribeWorkspace,
    ReadRunEvidence,
    CompileConfigurationProposal,
    CompileRunProposal,
    CompileApplyProposal,
    RecordRunReceipt,
    VerifyRunResult,
    MissionRunResultProposal,
    Registration,
    Revocation,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerraformCloudRunServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub operations: Vec<TerraformCloudRunServiceOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub durable_readback: bool,
    pub kernel_authority: bool,
}

impl TerraformCloudRunServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            operations: vec![
                TerraformCloudRunServiceOperation::DescribeWorkspace,
                TerraformCloudRunServiceOperation::ReadRunEvidence,
                TerraformCloudRunServiceOperation::CompileConfigurationProposal,
                TerraformCloudRunServiceOperation::CompileRunProposal,
                TerraformCloudRunServiceOperation::CompileApplyProposal,
                TerraformCloudRunServiceOperation::RecordRunReceipt,
                TerraformCloudRunServiceOperation::VerifyRunResult,
                TerraformCloudRunServiceOperation::MissionRunResultProposal,
                TerraformCloudRunServiceOperation::Registration,
                TerraformCloudRunServiceOperation::Revocation,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            durable_readback: false,
            kernel_authority: false,
        }
    }

    pub fn validate(&self) -> Result<(), TerraformCloudRunError> {
        if self.schema_version != crate::SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.operations.len() != 10
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_writes
            || self.durable_readback
            || self.kernel_authority
        {
            return Err(TerraformCloudRunError::MutationForbidden {
                operation: "invalid service definition",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        crate::canonical_digest(self)
    }
}

/// Typed Mission-facing facade. It owns no external effect capability; all
/// transport calls remain within the provider's read-only trait.
#[derive(Debug)]
pub struct TerraformCloudRunService<T, R>
where
    T: TerraformCloudRunTransport,
    R: TerraformCloudCredentialResolver,
{
    provider: TerraformCloudRunProvider<T, R>,
    definition: TerraformCloudRunServiceDefinition,
}

impl<T, R> TerraformCloudRunService<T, R>
where
    T: TerraformCloudRunTransport,
    R: TerraformCloudCredentialResolver,
{
    pub fn new(provider: TerraformCloudRunProvider<T, R>) -> Result<Self, TerraformCloudRunError> {
        let definition = TerraformCloudRunServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &TerraformCloudRunServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &TerraformCloudRunProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut TerraformCloudRunProvider<T, R> {
        &mut self.provider
    }

    pub fn scope(&self) -> &TerraformCloudScope {
        &self.provider.registration().scope
    }

    pub fn describe_workspace(&mut self) -> Result<WorkspaceDescription, TerraformCloudRunError> {
        self.provider.describe_workspace()
    }

    pub fn read_run_evidence(&mut self) -> Result<RunEvidence, TerraformCloudRunError> {
        self.provider.read_run_evidence()
    }

    pub fn compile_configuration_proposal(
        &self,
        request: ConfigurationProposalRequest,
    ) -> Result<ConfigurationProposal, TerraformCloudRunError> {
        self.provider.compile_configuration_proposal(request)
    }

    pub fn compile_run_proposal(
        &self,
        request: RunProposalRequest,
    ) -> Result<RunProposal, TerraformCloudRunError> {
        self.provider.compile_run_proposal(request)
    }

    pub fn compile_apply_proposal(
        &self,
        request: ApplyProposalRequest,
    ) -> Result<ApplyProposal, TerraformCloudRunError> {
        self.provider.compile_apply_proposal(request)
    }

    pub fn record_run_receipt(
        &mut self,
        evidence: &RunEvidence,
    ) -> Result<RunReceipt, TerraformCloudRunError> {
        self.provider.record_run_receipt(evidence)
    }

    pub fn verify_run_result(
        &self,
        run_proposal: &RunProposal,
        evidence: &RunEvidence,
        receipt: &RunReceipt,
    ) -> Result<TerraformRunResultProposal, TerraformCloudRunError> {
        self.provider
            .verify_run_result(run_proposal, evidence, receipt)
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationRevocation, TerraformCloudRunError> {
        self.provider.revoke()
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<(), TerraformCloudRunError> {
        self.provider.reject_write(operation)
    }
}

pub type TerraformCloudRunReadOnlyService<T, R> = TerraformCloudRunService<T, R>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_is_complete_and_read_only() {
        let definition = TerraformCloudRunServiceDefinition::layer1();
        definition.validate().expect("valid definition");
        assert_eq!(definition.operations.len(), 10);
        assert!(definition.read_only);
        assert!(definition.proposal_only);
        assert!(definition.recording_only);
        assert!(!definition.external_writes);
        assert!(!definition.durable_readback);
        assert!(!definition.kernel_authority);
    }
}

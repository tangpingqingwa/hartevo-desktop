use serde::{Deserialize, Serialize};

use crate::error::CloudRunDeploymentResultError;
use crate::model::{
    CloudRunDeploymentEvidence, CloudRunDeploymentReceipt, CloudRunDeploymentResultProposal,
    CloudRunReadRequest, CloudRunScope, CloudRunServiceDescription, Digest, PluginVersion,
};
use crate::provider::{CloudRunCredentialResolver, CloudRunProvider};
use crate::transport::CloudRunTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRunServiceOperation {
    DescribeService,
    ReadDeploymentEvidence,
    CompileDeploymentResultProposal,
    RecordDeploymentReceipt,
    VerifyDeploymentResult,
    MissionDeploymentResultProposal,
    Registration,
    Revocation,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub operations: Vec<CloudRunServiceOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub durable_readback: bool,
    pub kernel_authority: bool,
}

impl CloudRunServiceDefinition {
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
                CloudRunServiceOperation::DescribeService,
                CloudRunServiceOperation::ReadDeploymentEvidence,
                CloudRunServiceOperation::CompileDeploymentResultProposal,
                CloudRunServiceOperation::RecordDeploymentReceipt,
                CloudRunServiceOperation::VerifyDeploymentResult,
                CloudRunServiceOperation::MissionDeploymentResultProposal,
                CloudRunServiceOperation::Registration,
                CloudRunServiceOperation::Revocation,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            durable_readback: false,
            kernel_authority: false,
        }
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        if self.schema_version != crate::SCHEMA_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.service_id != crate::SERVICE_ID
            || self.provider_id != crate::PROVIDER_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.plugin_id != crate::PLUGIN_ID
            || self.plugin_version != crate::PLUGIN_VERSION
            || self.operations.len() != 8
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_writes
            || self.durable_readback
            || self.kernel_authority
        {
            return Err(CloudRunDeploymentResultError::MutationForbidden {
                operation: "invalid service definition",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        crate::canonical_digest(self)
    }
}

/// Typed Mission-facing facade. The service contains no external effect
/// capability; all provider calls remain bounded and read-only.
#[derive(Debug)]
pub struct CloudRunDeploymentResultService<T, R>
where
    T: CloudRunTransport,
    R: CloudRunCredentialResolver,
{
    provider: CloudRunProvider<T, R>,
    definition: CloudRunServiceDefinition,
}

impl<T, R> CloudRunDeploymentResultService<T, R>
where
    T: CloudRunTransport,
    R: CloudRunCredentialResolver,
{
    pub fn new(provider: CloudRunProvider<T, R>) -> Result<Self, CloudRunDeploymentResultError> {
        let definition = CloudRunServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &CloudRunServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &CloudRunProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut CloudRunProvider<T, R> {
        &mut self.provider
    }

    pub fn scope(&self) -> &CloudRunScope {
        &self.provider.registration().scope
    }

    pub fn describe_service(
        &mut self,
    ) -> Result<CloudRunServiceDescription, CloudRunDeploymentResultError> {
        self.provider.describe_service()
    }

    pub fn read_deployment_evidence(
        &mut self,
        request: &CloudRunReadRequest,
    ) -> Result<CloudRunDeploymentEvidence, CloudRunDeploymentResultError> {
        self.provider.read_deployment_evidence(request)
    }

    pub fn read_evidence(
        &mut self,
    ) -> Result<CloudRunDeploymentEvidence, CloudRunDeploymentResultError> {
        self.provider.read_evidence()
    }

    pub fn compile_deployment_result_proposal(
        &self,
        evidence: &CloudRunDeploymentEvidence,
    ) -> Result<CloudRunDeploymentResultProposal, CloudRunDeploymentResultError> {
        self.provider.compile_deployment_result_proposal(evidence)
    }

    pub fn record_deployment_receipt(
        &mut self,
        evidence: &CloudRunDeploymentEvidence,
    ) -> Result<CloudRunDeploymentReceipt, CloudRunDeploymentResultError> {
        self.provider.record_deployment_receipt(evidence)
    }

    pub fn verify_deployment_result(
        &self,
        proposal: &CloudRunDeploymentResultProposal,
        evidence: &CloudRunDeploymentEvidence,
        receipt: &CloudRunDeploymentReceipt,
    ) -> Result<CloudRunDeploymentResultProposal, CloudRunDeploymentResultError> {
        self.provider
            .verify_deployment_result(proposal, evidence, receipt)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocation, CloudRunDeploymentResultError> {
        self.provider.revoke()
    }

    pub fn reject_write(
        &self,
        operation: &'static str,
    ) -> Result<(), CloudRunDeploymentResultError> {
        self.provider.reject_write(operation)
    }
}

pub type CloudRunReadOnlyService<T, R> = CloudRunDeploymentResultService<T, R>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_is_complete_and_read_only() {
        let definition = CloudRunServiceDefinition::layer1();
        definition.validate().expect("valid definition");
        assert_eq!(definition.operations.len(), 8);
        assert!(definition.read_only);
        assert!(definition.proposal_only);
        assert!(definition.recording_only);
        assert!(!definition.external_writes);
        assert!(!definition.durable_readback);
        assert!(!definition.kernel_authority);
    }
}

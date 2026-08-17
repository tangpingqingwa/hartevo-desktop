use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::provider::{
    DeploymentEventsProjection, DeploymentListProjection, VercelApiTransport,
    VercelCredentialResolver,
};
use crate::{
    CONSUMER_ID, CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, DeploymentEnvironment, DeploymentState,
    MissionScope, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, PreviewDeploymentProposal,
    ProviderProvenance, SERVICE_ID, SourceCommit, TargetProjection, VercelDeliveryError,
    VercelDeploymentProvider, VercelProviderError, VercelTarget, digest_parts,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOperation {
    ProbeTeamProject,
    ReadDeployments,
    ReadDeployment,
    ReadDeploymentEvents,
    ProposePreview,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub operations: Vec<ServiceOperation>,
    pub read_only: bool,
    pub external_writes: bool,
    pub target_environment: DeploymentEnvironment,
    pub deployment_states: Vec<DeploymentState>,
}

impl DeploymentServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            operations: vec![
                ServiceOperation::ProbeTeamProject,
                ServiceOperation::ReadDeployments,
                ServiceOperation::ReadDeployment,
                ServiceOperation::ReadDeploymentEvents,
                ServiceOperation::ProposePreview,
            ],
            read_only: true,
            external_writes: false,
            target_environment: DeploymentEnvironment::Preview,
            deployment_states: vec![
                DeploymentState::Queued,
                DeploymentState::Building,
                DeploymentState::Ready,
                DeploymentState::Error,
                DeploymentState::Cancelled,
            ],
        }
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        if self.schema_version != CONTRACT_SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.operations.len() != 5
            || !self.read_only
            || self.external_writes
            || self.target_environment != DeploymentEnvironment::Preview
        {
            return Err(VercelDeliveryError::MutationForbidden);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        digest_parts([
            self.schema_version.as_str(),
            self.contract_version.as_str(),
            self.service_id.as_str(),
            self.provider_id.as_str(),
            self.consumer_id.as_str(),
            self.plugin_id.as_str(),
            self.plugin_version.as_str(),
            &serde_json::to_string(self.operations.as_slice())
                .expect("service operation definitions serialize"),
        ])
    }
}

/// Typed Mission-facing service facade. The provider is the only object that
/// sees credential resolution and the service never gains a write operation.
#[derive(Debug)]
pub struct DeploymentService<P> {
    provider: P,
    definition: DeploymentServiceDefinition,
}

impl<T, R> DeploymentService<VercelDeploymentProvider<T, R>>
where
    T: VercelApiTransport,
    R: VercelCredentialResolver,
{
    pub fn new(provider: VercelDeploymentProvider<T, R>) -> Self {
        Self {
            provider,
            definition: DeploymentServiceDefinition::layer1(),
        }
    }

    pub fn definition(&self) -> &DeploymentServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &VercelDeploymentProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut VercelDeploymentProvider<T, R> {
        &mut self.provider
    }

    pub fn probe_team_project(&mut self) -> Result<TargetProjection, VercelProviderError> {
        self.provider.probe_team_project()
    }

    pub fn read_deployments(&mut self) -> Result<DeploymentListProjection, VercelProviderError> {
        self.provider.read_deployments()
    }

    pub fn read_deployment(
        &mut self,
        deployment_id_or_url: &str,
    ) -> Result<crate::DeploymentProjection, VercelProviderError> {
        self.provider.read_deployment(deployment_id_or_url)
    }

    pub fn read_deployment_events(
        &mut self,
        deployment_id_or_url: &str,
    ) -> Result<DeploymentEventsProjection, VercelProviderError> {
        self.provider.read_deployment_events(deployment_id_or_url)
    }

    pub fn propose_preview(
        &mut self,
        input: crate::PreviewDeploymentProposalInput,
    ) -> Result<PreviewDeploymentProposal, VercelProviderError> {
        self.provider.propose_preview(input)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MissionSelectedResultConsumer;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedResultStatus {
    Proposed,
}

/// Mission adoption record for the Layer 1 proposal. It is deliberately a
/// selected proposal, not a deployment receipt or a verification claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedPreviewResult {
    pub result_id: String,
    pub result_digest: String,
    pub status: SelectedResultStatus,
    pub scope: MissionScope,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub target: VercelTarget,
    pub target_projection: TargetProjection,
    pub source_commit: SourceCommit,
    pub artifact_digest: String,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub external_effect_created: bool,
    pub verification_status: String,
    pub deployment_id: Option<String>,
    pub deployment_url: Option<String>,
}

impl MissionSelectedResultConsumer {
    pub fn adopt(
        self,
        proposal: PreviewDeploymentProposal,
    ) -> Result<SelectedPreviewResult, ConsumerError> {
        proposal
            .validate()
            .map_err(|error| ConsumerError::NotAdoptable {
                detail: error.to_string(),
            })?;
        if proposal.target.environment != DeploymentEnvironment::Preview
            || proposal.external_effect_created
            || !proposal.non_mutating
        {
            return Err(ConsumerError::NotAdoptable {
                detail: "only a non-mutating Preview proposal can be selected".to_owned(),
            });
        }
        let result_digest = digest_parts([
            "selected-preview-result/v1",
            proposal.proposal_digest.as_str(),
            proposal.scope.digest().as_str(),
        ]);
        let result = SelectedPreviewResult {
            result_id: format!("selected-preview-{}", &result_digest[..24]),
            result_digest,
            status: SelectedResultStatus::Proposed,
            scope: proposal.scope.clone(),
            proposal_id: proposal.proposal_id,
            proposal_digest: proposal.proposal_digest,
            target: proposal.target,
            target_projection: proposal.target_projection.clone(),
            source_commit: proposal.source_commit,
            artifact_digest: proposal.artifact_digest,
            provenance: proposal.target_projection.provenance,
            native: proposal.target_projection.native,
            external_effect_created: false,
            verification_status: "not_performed_layer_1".to_owned(),
            deployment_id: None,
            deployment_url: None,
        };
        result.validate()?;
        Ok(result)
    }
}

impl SelectedPreviewResult {
    pub fn validate(&self) -> Result<(), ConsumerError> {
        if self.status != SelectedResultStatus::Proposed
            || self.target.environment != DeploymentEnvironment::Preview
            || self.external_effect_created
            || self.deployment_id.is_some()
            || self.deployment_url.is_some()
            || self.verification_status != "not_performed_layer_1"
            || self.target_projection.team_id != self.target.team_id
            || self.target_projection.project_id != self.target.project_id
            || self.target_projection.scope_digest
                != crate::registration_scope_digest(&self.scope, &self.target)
        {
            return Err(ConsumerError::NotAdoptable {
                detail: "selected result contains a forbidden Layer 2 field".to_owned(),
            });
        }
        if crate::validate_digest(&self.result_digest, "result_digest").is_err()
            || self.result_digest
                != digest_parts([
                    "selected-preview-result/v1",
                    self.proposal_digest.as_str(),
                    self.scope.digest().as_str(),
                ])
            || self.result_id
                != self
                    .result_digest
                    .get(..24)
                    .map_or(String::new(), |digest| format!("selected-preview-{digest}"))
        {
            return Err(ConsumerError::NotAdoptable {
                detail: "selected result digest is not canonical".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("selected result is not adoptable: {detail}")]
    NotAdoptable { detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_definition_is_a_complete_read_only_surface() {
        let definition = DeploymentServiceDefinition::layer1();
        definition.validate().expect("valid definition");
        assert_eq!(definition.operations.len(), 5);
        assert!(definition.read_only);
        assert!(!definition.external_writes);
        assert_eq!(
            definition.target_environment,
            DeploymentEnvironment::Preview
        );
    }
}

//! Typed, read-only service descriptor for the Azure DevOps Work slice.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::{AZURE_DEVOPS_WORK_SERVICE_ID, AZURE_DEVOPS_WORK_SERVICE_SCHEMA, AzureDevOpsWorkError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureDevOpsWorkOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadWorkItemGraph,
    ReadPullRequest,
    ReadBuildTimelineArtifacts,
    ConsumeObservation,
}

impl AzureDevOpsWorkOperation {
    pub const ALL: [Self; 7] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadWorkItemGraph,
        Self::ReadPullRequest,
        Self::ReadBuildTimelineArtifacts,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsCapability {
    pub capability_id: String,
    pub operation: AzureDevOpsWorkOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureDevOpsWorkService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<AzureDevOpsCapability>,
}

impl Default for AzureDevOpsWorkService {
    fn default() -> Self {
        Self::new()
    }
}

impl AzureDevOpsWorkService {
    pub fn new() -> Self {
        let capability_names = [
            (
                "azure-devops.work.register",
                AzureDevOpsWorkOperation::Register,
            ),
            (
                "azure-devops.work.revoke_registration",
                AzureDevOpsWorkOperation::RevokeRegistration,
            ),
            (
                "azure-devops.work.read_work_item_graph",
                AzureDevOpsWorkOperation::ReadWorkItemGraph,
            ),
            (
                "azure-devops.work.read_pull_request",
                AzureDevOpsWorkOperation::ReadPullRequest,
            ),
            (
                "azure-devops.work.read_build_timeline_artifacts",
                AzureDevOpsWorkOperation::ReadBuildTimelineArtifacts,
            ),
            (
                "azure-devops.work.consume_observation",
                AzureDevOpsWorkOperation::ConsumeObservation,
            ),
        ];
        let capabilities = capability_names
            .into_iter()
            .map(|(capability_id, operation)| AzureDevOpsCapability {
                capability_id: capability_id.to_owned(),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
            })
            .collect();
        Self {
            service_id: AZURE_DEVOPS_WORK_SERVICE_ID.to_owned(),
            service_name: crate::AZURE_DEVOPS_WORK_SERVICE_NAME.to_owned(),
            version: PluginVersion::new(1, 0, 0),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[AzureDevOpsCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<AzureDevOpsCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, AzureDevOpsWorkError> {
        let service_id =
            ServiceId::new(self.service_id.clone()).map_err(AzureDevOpsWorkError::Plugin)?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(AZURE_DEVOPS_WORK_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(AzureDevOpsWorkError::Plugin)
    }

    pub fn validate(&self) -> Result<(), AzureDevOpsWorkError> {
        if self.service_id != AZURE_DEVOPS_WORK_SERVICE_ID
            || self.service_name != crate::AZURE_DEVOPS_WORK_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(AzureDevOpsWorkError::InvalidInput(
                "Azure DevOps Work service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

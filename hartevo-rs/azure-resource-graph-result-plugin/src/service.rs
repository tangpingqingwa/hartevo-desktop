//! Typed read-only service definition for the Azure Resource Graph result.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::{
    AZURE_RESOURCE_GRAPH_SERVICE_ID, AZURE_RESOURCE_GRAPH_SERVICE_NAME,
    AZURE_RESOURCE_GRAPH_SERVICE_SCHEMA, AzureResourceGraphError, AzureResourceGraphQueryAst,
    AzureResourceGraphScope,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureResourceGraphOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    RestoreRegistration,
    ProposeQuery,
    ReadInventory,
    RecordObservationReceipt,
    VerifyProposal,
    ConsumeResult,
}

impl AzureResourceGraphOperation {
    pub const ALL: [Self; 9] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::RestoreRegistration,
        Self::ProposeQuery,
        Self::ReadInventory,
        Self::RecordObservationReceipt,
        Self::VerifyProposal,
        Self::ConsumeResult,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeCapabilities => "describe_capabilities",
            Self::Register => "register",
            Self::RevokeRegistration => "revoke_registration",
            Self::RestoreRegistration => "restore_registration",
            Self::ProposeQuery => "propose_query",
            Self::ReadInventory => "read_inventory",
            Self::RecordObservationReceipt => "record_observation_receipt",
            Self::VerifyProposal => "verify_proposal",
            Self::ConsumeResult => "consume_result",
        }
    }

    #[must_use]
    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphCapability {
    pub capability_id: String,
    pub operation: AzureResourceGraphOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureResourceGraphService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<AzureResourceGraphCapability>,
}

impl Default for AzureResourceGraphService {
    fn default() -> Self {
        Self::new()
    }
}

impl AzureResourceGraphService {
    #[must_use]
    pub fn new() -> Self {
        let capabilities = AzureResourceGraphOperation::ALL
            .into_iter()
            .map(|operation| AzureResourceGraphCapability {
                capability_id: format!("{AZURE_RESOURCE_GRAPH_SERVICE_ID}.{}", operation.as_str()),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
            })
            .collect();
        Self {
            service_id: AZURE_RESOURCE_GRAPH_SERVICE_ID.to_owned(),
            service_name: AZURE_RESOURCE_GRAPH_SERVICE_NAME.to_owned(),
            version: crate::plugin_version(),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[must_use]
    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    #[must_use]
    pub fn capabilities(&self) -> &[AzureResourceGraphCapability] {
        &self.capabilities
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Vec<AzureResourceGraphCapability> {
        self.capabilities.clone()
    }

    pub fn propose_query(
        &self,
        scope: &AzureResourceGraphScope,
    ) -> Result<AzureResourceGraphQueryAst, AzureResourceGraphError> {
        scope.validate().map_err(AzureResourceGraphError::from)?;
        Ok(scope.query_ast())
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, AzureResourceGraphError> {
        let service_id =
            ServiceId::new(self.service_id.clone()).map_err(AzureResourceGraphError::Plugin)?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(AZURE_RESOURCE_GRAPH_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(AzureResourceGraphError::Plugin)
    }

    pub fn validate(&self) -> Result<(), AzureResourceGraphError> {
        if self.service_id != AZURE_RESOURCE_GRAPH_SERVICE_ID
            || self.service_name != AZURE_RESOURCE_GRAPH_SERVICE_NAME
            || self.version != crate::plugin_version()
            || !self.read_only
            || self.native_connected
            || self.capabilities.len() != AzureResourceGraphOperation::ALL.len()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.native_evidence
                    || !capability.operation.is_read_only()
            })
        {
            return Err(AzureResourceGraphError::InvalidInput(
                "Azure Resource Graph service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

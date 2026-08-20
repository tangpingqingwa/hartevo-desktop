//! Typed, read-only service descriptor for the GCP Security Command Center
//! finding-result slice.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginError, PluginVersion as RuntimeVersion,
    ProviderCardinality, ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GCP_SECURITY_CENTER_RESULT_SERVICE_ID, GCP_SECURITY_CENTER_RESULT_SERVICE_NAME,
    GCP_SECURITY_CENTER_RESULT_SERVICE_SCHEMA,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpSecurityCenterOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    FindingsListRead,
    FindingsListPropose,
    FindingsListRecord,
    FindingsListVerify,
    FindingsGroupRead,
    FindingsGroupPropose,
    FindingsGroupRecord,
    FindingsGroupVerify,
    ConsumeObservation,
}

impl GcpSecurityCenterOperation {
    pub const ALL: [Self; 12] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::FindingsListRead,
        Self::FindingsListPropose,
        Self::FindingsListRecord,
        Self::FindingsListVerify,
        Self::FindingsGroupRead,
        Self::FindingsGroupPropose,
        Self::FindingsGroupRecord,
        Self::FindingsGroupVerify,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }

    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::DescribeCapabilities => "gcp.security-command-center.describe_capabilities",
            Self::Register => "gcp.security-command-center.register",
            Self::RevokeRegistration => "gcp.security-command-center.revoke_registration",
            Self::FindingsListRead => "gcp.security-command-center.findings.list.read",
            Self::FindingsListPropose => "gcp.security-command-center.findings.list.propose",
            Self::FindingsListRecord => "gcp.security-command-center.findings.list.record",
            Self::FindingsListVerify => "gcp.security-command-center.findings.list.verify",
            Self::FindingsGroupRead => "gcp.security-command-center.findings.group.read",
            Self::FindingsGroupPropose => "gcp.security-command-center.findings.group.propose",
            Self::FindingsGroupRecord => "gcp.security-command-center.findings.group.record",
            Self::FindingsGroupVerify => "gcp.security-command-center.findings.group.verify",
            Self::ConsumeObservation => "gcp.security-command-center.consume_observation",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpSecurityCenterCapability {
    pub capability_id: String,
    pub operation: GcpSecurityCenterOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("GCP Security Command Center service descriptor drifted")]
    DescriptorDrift,
    #[error("plugin runtime rejected the service descriptor: {0}")]
    Plugin(#[from] PluginError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpSecurityCenterService {
    service_id: String,
    service_name: String,
    version: RuntimeVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<GcpSecurityCenterCapability>,
}

impl Default for GcpSecurityCenterService {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpSecurityCenterService {
    pub fn new() -> Self {
        let capabilities = GcpSecurityCenterOperation::ALL
            .into_iter()
            .map(|operation| GcpSecurityCenterCapability {
                capability_id: operation.capability_id().to_owned(),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
            })
            .collect();
        Self {
            service_id: GCP_SECURITY_CENTER_RESULT_SERVICE_ID.to_owned(),
            service_name: GCP_SECURITY_CENTER_RESULT_SERVICE_NAME.to_owned(),
            version: RuntimeVersion::new(1, 0, 0),
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

    pub const fn version(&self) -> RuntimeVersion {
        self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[GcpSecurityCenterCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<GcpSecurityCenterCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, ServiceError> {
        let service_id = ServiceId::new(self.service_id.clone())?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(GCP_SECURITY_CENTER_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(ServiceError::from)
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        let expected = Self::new();
        if self != &expected
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(ServiceError::DescriptorDrift);
        }
        Ok(())
    }
}

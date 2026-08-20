//! Typed read-only service descriptor for the OCI DevOps result seam.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::{
    OCI_DEVOPS_RESULT_SERVICE_ID, OCI_DEVOPS_RESULT_SERVICE_NAME, OCI_DEVOPS_RESULT_SERVICE_SCHEMA,
    OciDevopsError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciDevopsOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ListDeployments,
    GetDeployment,
    ListBuildRuns,
    GetBuildRun,
    ListWorkRequests,
    GetWorkRequest,
    ConsumeObservation,
    ProposeDeliveryDecision,
    RecordDeliveryDecision,
    VerifyReadback,
}

impl OciDevopsOperation {
    pub const ALL: [Self; 13] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ListDeployments,
        Self::GetDeployment,
        Self::ListBuildRuns,
        Self::GetBuildRun,
        Self::ListWorkRequests,
        Self::GetWorkRequest,
        Self::ConsumeObservation,
        Self::ProposeDeliveryDecision,
        Self::RecordDeliveryDecision,
        Self::VerifyReadback,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciCapability {
    pub capability_id: String,
    pub operation: OciDevopsOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciDevopsResultService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<OciCapability>,
}

impl Default for OciDevopsResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl OciDevopsResultService {
    pub fn new() -> Self {
        let capability_names = [
            (
                "oci.devops.describe_capabilities",
                OciDevopsOperation::DescribeCapabilities,
            ),
            ("oci.devops.register", OciDevopsOperation::Register),
            (
                "oci.devops.revoke_registration",
                OciDevopsOperation::RevokeRegistration,
            ),
            (
                "oci.devops.list_deployments",
                OciDevopsOperation::ListDeployments,
            ),
            (
                "oci.devops.get_deployment",
                OciDevopsOperation::GetDeployment,
            ),
            (
                "oci.devops.list_build_runs",
                OciDevopsOperation::ListBuildRuns,
            ),
            ("oci.devops.get_build_run", OciDevopsOperation::GetBuildRun),
            (
                "oci.devops.list_work_requests",
                OciDevopsOperation::ListWorkRequests,
            ),
            (
                "oci.devops.get_work_request",
                OciDevopsOperation::GetWorkRequest,
            ),
            (
                "oci.devops.consume_observation",
                OciDevopsOperation::ConsumeObservation,
            ),
            (
                "oci.devops.propose_delivery_decision",
                OciDevopsOperation::ProposeDeliveryDecision,
            ),
            (
                "oci.devops.record_delivery_decision",
                OciDevopsOperation::RecordDeliveryDecision,
            ),
            (
                "oci.devops.verify_readback",
                OciDevopsOperation::VerifyReadback,
            ),
        ];
        let capabilities = capability_names
            .into_iter()
            .map(|(capability_id, operation)| OciCapability {
                capability_id: capability_id.to_owned(),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
            })
            .collect();
        Self {
            service_id: OCI_DEVOPS_RESULT_SERVICE_ID.to_owned(),
            service_name: OCI_DEVOPS_RESULT_SERVICE_NAME.to_owned(),
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

    pub fn capabilities(&self) -> &[OciCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<OciCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, OciDevopsError> {
        let service_id = ServiceId::new(self.service_id.clone()).map_err(OciDevopsError::Plugin)?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(OCI_DEVOPS_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(OciDevopsError::Plugin)
    }

    pub fn validate(&self) -> Result<(), OciDevopsError> {
        if self.service_id != OCI_DEVOPS_RESULT_SERVICE_ID
            || self.service_name != OCI_DEVOPS_RESULT_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.len() != OciDevopsOperation::ALL.len()
            || self
                .capabilities
                .iter()
                .map(|capability| capability.operation)
                .collect::<Vec<_>>()
                != OciDevopsOperation::ALL
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(OciDevopsError::InvalidInput(
                "OCI DevOps result service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

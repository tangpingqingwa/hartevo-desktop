//! Typed read-only Macie discovery-result service descriptor and seams.

use hartevo_plugin_runtime::{PluginVersion, ServiceDefinition, ServiceId};
use serde::{Deserialize, Serialize};

use crate::model::{
    MacieDiscoveryEvidence, MacieDiscoveryProposal, MacieDiscoveryRecord,
    MacieDiscoveryVerification,
};
use crate::{
    AWS_MACIE_DISCOVERY_SERVICE_ID, AWS_MACIE_DISCOVERY_SERVICE_NAME, AWS_MACIE_SERVICE_SCHEMA,
    MacieDiscoveryResultError, Result,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacieDiscoveryResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadListFindings,
    ReadGetFindings,
    Propose,
    Record,
    Verify,
}

impl MacieDiscoveryResultOperation {
    pub const ALL: [Self; 8] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadListFindings,
        Self::ReadGetFindings,
        Self::Propose,
        Self::Record,
        Self::Verify,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacieCapability {
    pub capability_id: String,
    pub operation: MacieDiscoveryResultOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
    pub connected: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacieDiscoveryResultService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    first_party: bool,
    capabilities: Vec<MacieCapability>,
}

impl Default for MacieDiscoveryResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl MacieDiscoveryResultService {
    pub fn new() -> Self {
        let capabilities = MacieDiscoveryResultOperation::ALL
            .into_iter()
            .map(|operation| MacieCapability {
                capability_id: format!(
                    "aws.macie.discovery-result.{}",
                    serde_json::to_string(&operation)
                        .expect("Macie operation serializes")
                        .trim_matches('"')
                ),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
                connected: false,
                first_party: false,
            })
            .collect();
        Self {
            service_id: AWS_MACIE_DISCOVERY_SERVICE_ID.to_owned(),
            service_name: AWS_MACIE_DISCOVERY_SERVICE_NAME.to_owned(),
            version: PluginVersion::new(1, 0, 0),
            read_only: true,
            native_connected: false,
            first_party: false,
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

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub fn capabilities(&self) -> &[MacieCapability] {
        &self.capabilities
    }

    pub fn definition(&self) -> Result<ServiceDefinition> {
        let id = ServiceId::new(self.service_id.clone())?;
        ServiceDefinition::read_only(
            id,
            self.version,
            hartevo_plugin_runtime::Digest::from_text(AWS_MACIE_SERVICE_SCHEMA),
            hartevo_plugin_runtime::ProviderCardinality::Singleton,
            hartevo_plugin_runtime::CompatibilityPolicy::SameMajor,
        )
        .map_err(MacieDiscoveryResultError::from)
    }

    pub fn validate(&self) -> Result<()> {
        if self.service_id != AWS_MACIE_DISCOVERY_SERVICE_ID
            || self.service_name != AWS_MACIE_DISCOVERY_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.first_party
            || self.capabilities.len() != MacieDiscoveryResultOperation::ALL.len()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.native_evidence
                    || capability.connected
                    || capability.first_party
            })
        {
            return Err(MacieDiscoveryResultError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn propose(&self, evidence: MacieDiscoveryEvidence) -> Result<MacieDiscoveryProposal> {
        self.validate()?;
        MacieDiscoveryProposal::new(evidence)
            .map_err(|_| MacieDiscoveryResultError::TamperedEvidence)
    }

    pub fn record(&self, proposal: &MacieDiscoveryProposal) -> Result<MacieDiscoveryRecord> {
        self.validate()?;
        MacieDiscoveryRecord::new(proposal).map_err(MacieDiscoveryResultError::from)
    }

    pub fn verify(
        &self,
        record: &MacieDiscoveryRecord,
        evidence: &MacieDiscoveryEvidence,
    ) -> Result<MacieDiscoveryVerification> {
        self.validate()?;
        evidence
            .validate()
            .map_err(|_| MacieDiscoveryResultError::TamperedEvidence)?;
        if record.evidence_digest != evidence.evidence_digest
            || record.scope_digest != evidence.scope_digest
            || record.registration_digest != evidence.registration_digest
        {
            return Err(MacieDiscoveryResultError::TamperedEvidence);
        }
        MacieDiscoveryVerification::from_record(record, evidence)
            .map_err(MacieDiscoveryResultError::from)
    }
}

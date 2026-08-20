//! Typed read-only service descriptor and evidence seams.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::model::{FindingsEvidence, FindingsProposal, FindingsRecord, FindingsVerification};
use crate::{
    AWS_SECURITY_HUB_FINDING_SERVICE_ID, AWS_SECURITY_HUB_FINDING_SERVICE_NAME,
    AWS_SECURITY_HUB_FINDING_SERVICE_SCHEMA, AwsSecurityHubError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsSecurityHubFindingOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadGetFindings,
    ReadGetFindingsV2,
    Propose,
    Record,
    Verify,
}

impl AwsSecurityHubFindingOperation {
    pub const ALL: [Self; 8] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadGetFindings,
        Self::ReadGetFindingsV2,
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
pub struct AwsSecurityHubCapability {
    pub capability_id: String,
    pub operation: AwsSecurityHubFindingOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsSecurityHubFindingService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<AwsSecurityHubCapability>,
}

impl Default for AwsSecurityHubFindingService {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsSecurityHubFindingService {
    pub fn new() -> Self {
        let capabilities = AwsSecurityHubFindingOperation::ALL
            .into_iter()
            .map(|operation| AwsSecurityHubCapability {
                capability_id: format!(
                    "aws-security-hub.finding-result.{}",
                    serde_json::to_string(&operation)
                        .expect("operation serializes")
                        .trim_matches('"')
                ),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
            })
            .collect();
        Self {
            service_id: AWS_SECURITY_HUB_FINDING_SERVICE_ID.to_owned(),
            service_name: AWS_SECURITY_HUB_FINDING_SERVICE_NAME.to_owned(),
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

    pub fn capabilities(&self) -> &[AwsSecurityHubCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<AwsSecurityHubCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, AwsSecurityHubError> {
        let service_id = ServiceId::new(self.service_id.clone())?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(AWS_SECURITY_HUB_FINDING_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(AwsSecurityHubError::from)
    }

    pub fn validate(&self) -> Result<(), AwsSecurityHubError> {
        if self.service_id != AWS_SECURITY_HUB_FINDING_SERVICE_ID
            || self.service_name != AWS_SECURITY_HUB_FINDING_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.len() != AwsSecurityHubFindingOperation::ALL.len()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(AwsSecurityHubError::ContractDrift);
        }
        Ok(())
    }

    pub fn propose(
        &self,
        evidence: FindingsEvidence,
    ) -> Result<FindingsProposal, AwsSecurityHubError> {
        FindingsProposal::new(evidence).map_err(AwsSecurityHubError::from)
    }

    pub fn record(
        &self,
        proposal: &FindingsProposal,
    ) -> Result<FindingsRecord, AwsSecurityHubError> {
        proposal
            .evidence
            .validate()
            .map_err(|_| AwsSecurityHubError::TamperedEvidence)?;
        FindingsRecord::new(proposal).map_err(|_| AwsSecurityHubError::TamperedEvidence)
    }

    pub fn verify(
        &self,
        record: &FindingsRecord,
        evidence: &FindingsEvidence,
    ) -> Result<FindingsVerification, AwsSecurityHubError> {
        evidence
            .validate()
            .map_err(|_| AwsSecurityHubError::TamperedEvidence)?;
        let expected_record = FindingsRecord::new(&FindingsProposal::new(evidence.clone())?)?;
        if expected_record.record_digest != record.record_digest
            || record.evidence_digest != evidence.evidence_digest
            || record.scope_digest != evidence.scope_digest
            || record.registration_digest != evidence.registration_digest
        {
            return Err(AwsSecurityHubError::TamperedEvidence);
        }
        FindingsVerification::from_record(record, evidence)
            .map_err(|_| AwsSecurityHubError::TamperedEvidence)
    }
}

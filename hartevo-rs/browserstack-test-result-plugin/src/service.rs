//! Typed read-only service descriptor for BrowserStack test-result evidence.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::provider::{BrowserStackRegistration, RegistrationRevocation};
use crate::{
    BROWSERSTACK_SERVICE_ID, BROWSERSTACK_SERVICE_NAME, BROWSERSTACK_SERVICE_SCHEMA,
    BrowserStackTestResultError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserStackTestResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ProposeBuildSessionRead,
    ReadBuildMetadata,
    ReadSessionPages,
    ReadSessionDetail,
    RecordEvidence,
    ConsumeObservation,
}

impl BrowserStackTestResultOperation {
    pub const ALL: [Self; 9] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ProposeBuildSessionRead,
        Self::ReadBuildMetadata,
        Self::ReadSessionPages,
        Self::ReadSessionDetail,
        Self::RecordEvidence,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackCapability {
    pub capability_id: String,
    pub operation: BrowserStackTestResultOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserStackTestResultService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<BrowserStackCapability>,
}

impl Default for BrowserStackTestResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserStackTestResultService {
    pub fn new() -> Self {
        let capability_ids = [
            (
                "browserstack.test-result.register",
                BrowserStackTestResultOperation::Register,
            ),
            (
                "browserstack.test-result.revoke_registration",
                BrowserStackTestResultOperation::RevokeRegistration,
            ),
            (
                "browserstack.test-result.propose_build_session_read",
                BrowserStackTestResultOperation::ProposeBuildSessionRead,
            ),
            (
                "browserstack.test-result.read_build_metadata",
                BrowserStackTestResultOperation::ReadBuildMetadata,
            ),
            (
                "browserstack.test-result.read_session_pages",
                BrowserStackTestResultOperation::ReadSessionPages,
            ),
            (
                "browserstack.test-result.read_session_detail",
                BrowserStackTestResultOperation::ReadSessionDetail,
            ),
            (
                "browserstack.test-result.record_evidence",
                BrowserStackTestResultOperation::RecordEvidence,
            ),
            (
                "browserstack.test-result.consume_observation",
                BrowserStackTestResultOperation::ConsumeObservation,
            ),
        ];
        let capabilities = capability_ids
            .into_iter()
            .map(|(capability_id, operation)| BrowserStackCapability {
                capability_id: capability_id.to_owned(),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
            })
            .collect();
        Self {
            service_id: BROWSERSTACK_SERVICE_ID.to_owned(),
            service_name: BROWSERSTACK_SERVICE_NAME.to_owned(),
            version: crate::plugin_version(),
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

    pub fn capabilities(&self) -> &[BrowserStackCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<BrowserStackCapability> {
        self.capabilities.clone()
    }

    pub fn revoke_registration(
        &self,
        registration: &mut BrowserStackRegistration,
    ) -> Result<RegistrationRevocation, BrowserStackTestResultError> {
        self.validate()?;
        registration.revoke()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, BrowserStackTestResultError> {
        let service_id =
            ServiceId::new(self.service_id.clone()).map_err(BrowserStackTestResultError::Plugin)?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(BROWSERSTACK_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(BrowserStackTestResultError::Plugin)
    }

    pub fn validate(&self) -> Result<(), BrowserStackTestResultError> {
        if self.service_id != BROWSERSTACK_SERVICE_ID
            || self.service_name != BROWSERSTACK_SERVICE_NAME
            || self.version != crate::plugin_version()
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.len() != BrowserStackTestResultOperation::ALL.len() - 1
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(BrowserStackTestResultError::InvalidInput(
                "BrowserStack test-result service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

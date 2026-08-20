//! Layer-1 AWS Security Hub finding-result plugin.
//!
//! The crate is a standalone read-only vertical slice. It contributes typed
//! descriptors, a scope-bound provider seam, normalized finding evidence, and
//! a Mission consumer. It does not resolve credentials, retain raw Security
//! Hub JSON, claim Connected/native authority, or perform finding mutations.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use thiserror::Error;

pub mod model;
pub mod transport;

pub const AWS_SECURITY_HUB_SCHEMA_VERSION: &str =
    "hartevo.aws-security-hub-finding-result-contract/v1";
pub const AWS_SECURITY_HUB_CONTRACT_VERSION: &str = "aws-security-hub-finding-result/v1";
pub const AWS_SECURITY_HUB_PLUGIN_ID: &str = "aws-security-hub-finding-result";
pub const AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AWS_SECURITY_HUB_API_VERSION: &str = "2018-10-26";
pub const AWS_SECURITY_HUB_PROVIDER_REVISION: &str = "aws-security-hub-2018-10-26-r1";
pub const AWS_SECURITY_HUB_IAM_PERMISSION: &str = "securityhub:GetFindings";
pub const AWS_SECURITY_HUB_FINDING_SERVICE_ID: &str = "aws-security-hub.finding-result";
pub const AWS_SECURITY_HUB_FINDING_SERVICE_NAME: &str = "AwsSecurityHubFindingService";
pub const AWS_SECURITY_HUB_PROVIDER_ID: &str = "aws-security-hub.findings";
pub const AWS_SECURITY_HUB_PROVIDER_NAME: &str = "AwsSecurityHubProvider";
pub const MISSION_AWS_SECURITY_HUB_CONSUMER_ID: &str = "mission.aws-security-hub-finding-result";
pub const MISSION_AWS_SECURITY_HUB_CONSUMER_NAME: &str = "MissionAwsSecurityHubConsumer";
pub const AWS_SECURITY_HUB_FINDING_SERVICE_SCHEMA: &str =
    "hartevo.aws-security-hub-finding-service/v1";
pub const AWS_SECURITY_HUB_PROVIDER_SCHEMA: &str = "hartevo.aws-security-hub-provider/v1";
pub const MISSION_AWS_SECURITY_HUB_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-security-hub-finding-result-consumer/v1";
pub const AWS_SECURITY_HUB_MAX_RESPONSE_BYTES: usize = 1_048_576;

pub const AWS_SECURITY_HUB_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-security-hub-finding-result/aws-security-hub-finding-result.v1.json"
);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsSecurityHubError {
    #[error(transparent)]
    Model(#[from] model::ModelError),
    #[error(transparent)]
    Plugin(#[from] PluginError),
    #[error(transparent)]
    Transport(#[from] transport::AwsSecurityHubTransportError),
    #[error("the provider registration is missing")]
    RegistrationMissing,
    #[error("the provider registration has been revoked")]
    RegistrationRevoked,
    #[error("the registration is invalid or drifted")]
    InvalidRegistration,
    #[error("the registration scope does not match the consumer scope")]
    ScopeMismatch,
    #[error("the provider revision or digest drifted")]
    ProviderDrift,
    #[error("the contract version or digest drifted")]
    ContractDrift,
    #[error("the permission digest drifted")]
    PermissionDrift,
    #[error("the finding is outside the registered scope or filter")]
    FindingOutOfScope,
    #[error("the finding page binding drifted")]
    PageBindingMismatch,
    #[error("the provider returned a repeated page token")]
    PageLoop,
    #[error("the bounded finding response exceeded its limit")]
    ResponseBoundExceeded,
    #[error("the evidence digest or normalized finding was tampered with")]
    TamperedEvidence,
    #[error("the evidence is stale for this registration")]
    StaleEvidence,
    #[error("the contract document is invalid: {0}")]
    InvalidContract(String),
}

pub type Result<T> = std::result::Result<T, AwsSecurityHubError>;

pub fn contract_digest() -> model::Digest {
    model::sha256_digest(AWS_SECURITY_HUB_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Validates the machine-readable contract's immutable identity and the
/// Layer-1 authority boundary without making it a second source of runtime
/// behavior.
pub fn validate_contract_document() -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(AWS_SECURITY_HUB_CONTRACT_JSON)
        .map_err(|error| AwsSecurityHubError::InvalidContract(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| AwsSecurityHubError::InvalidContract("root is not an object".to_owned()))?;
    let string_field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AwsSecurityHubError::InvalidContract(format!("missing {name}")))
    };
    if string_field("schemaVersion")? != AWS_SECURITY_HUB_SCHEMA_VERSION
        || string_field("contractVersion")? != AWS_SECURITY_HUB_CONTRACT_VERSION
    {
        return Err(AwsSecurityHubError::InvalidContract(
            "contract identity drifted".to_owned(),
        ));
    }
    if object.get("layer").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(AwsSecurityHubError::InvalidContract(
            "contract layer is not 1".to_owned(),
        ));
    }
    let authority = object
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AwsSecurityHubError::InvalidContract("missing authority".to_owned()))?;
    for field in [
        "connected",
        "nativeProvider",
        "liveCredentialResolution",
        "rawFindingJson",
        "durableReceipt",
        "verificationAuthority",
        "outcomeAuthority",
        "workProductAdoption",
    ] {
        if authority.get(field).and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(AwsSecurityHubError::InvalidContract(format!(
                "authority.{field} must be false"
            )));
        }
    }
    Ok(())
}

/// Builds the plugin-runtime contribution set for one exact Project/Mission
/// generation. The runtime mount remains host-owned and reversible.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition> {
    let plugin_id = PluginId::new(AWS_SECURITY_HUB_PLUGIN_ID)?;
    let service_id = ServiceId::new(AWS_SECURITY_HUB_FINDING_SERVICE_ID)?;
    let provider_id = ProviderId::new(AWS_SECURITY_HUB_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_AWS_SECURITY_HUB_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AWS_SECURITY_HUB_FINDING_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AWS_SECURITY_HUB_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_AWS_SECURITY_HUB_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        version,
        scope,
        contributions,
    )?)
}

pub mod consumer;
pub mod provider;
pub mod service;

pub use consumer::{MissionAwsSecurityHubConsumer, MissionAwsSecurityHubReadResult};
pub use model::*;
pub use provider::{
    AwsSecurityHubProvider, AwsSecurityHubRegistration, AwsSecurityHubRegistrationRequest,
    RegistrationState, provider_digest,
};
pub use service::{
    AwsSecurityHubCapability, AwsSecurityHubFindingOperation, AwsSecurityHubFindingService,
};
pub use transport::{
    AwsSecurityHubTransport, AwsSecurityHubTransportError, BlockedEnvAwsSecurityHubTransport,
    BlockedEnvTransport, FakeAwsSecurityHubTransport, FixtureAwsSecurityHubTransport,
    LoopbackAwsSecurityHubTransport, LoopbackTransport, RecordingAwsSecurityHubTransport,
    RecordingTransport,
};

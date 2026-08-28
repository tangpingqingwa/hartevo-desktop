//! Standalone Layer-1 Amazon Macie discovery-result plugin.
//!
//! The crate owns a bounded, normalized read/proposal/record/verify seam. It
//! never resolves credentials, retains raw Macie findings, downloads samples,
//! mutates Macie/S3/IAM, claims Connected/native/first-party evidence, or
//! adopts Hartevo Truth, Consent, Effect, Receipt, Verification, or Outcome
//! authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MacieDiscoveryObservation, MacieDiscoveryReadResult, MissionMacieDiscoveryConsumer,
};
pub use model::*;
pub use provider::{
    MacieProvider, MacieRegistration, MacieRegistrationRequest, ProviderRegistrationState,
    provider_digest,
};
pub use service::{MacieCapability, MacieDiscoveryResultOperation, MacieDiscoveryResultService};
pub use transport::{
    BlockedEnvMacieTransport, BlockedEnvTransport, FakeMacieTransport, FixtureMacieTransport,
    LoopbackMacieTransport, LoopbackTransport, MacieTransport, MacieTransportError,
    RecordedMacieRequest, RecordingMacieTransport, RecordingTransport,
};

pub const AWS_MACIE_SCHEMA_VERSION: &str = "hartevo.aws-macie-discovery-result-contract/v1";
pub const AWS_MACIE_CONTRACT_VERSION: &str = "aws-macie-discovery-result/v1";
pub const AWS_MACIE_PLUGIN_ID: &str = "aws-macie-discovery-result";
pub const AWS_MACIE_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AWS_MACIE_API_VERSION: &str = "2017-12-19";
pub const AWS_MACIE_PROVIDER_REVISION: &str = "macie2-list-findings-get-findings-r1";
pub const AWS_MACIE_LIST_FINDINGS_PERMISSION: &str = "macie2:ListFindings";
pub const AWS_MACIE_GET_FINDINGS_PERMISSION: &str = "macie2:GetFindings";
pub const AWS_MACIE_PROVIDER_ID: &str = "aws.macie.discovery-findings";
pub const AWS_MACIE_PROVIDER_NAME: &str = "MacieProvider";
pub const AWS_MACIE_DISCOVERY_SERVICE_ID: &str = "aws.macie.discovery-result";
pub const AWS_MACIE_DISCOVERY_SERVICE_NAME: &str = "MacieDiscoveryResultService";
pub const MISSION_AWS_MACIE_CONSUMER_ID: &str = "mission.aws-macie-discovery-result";
pub const MISSION_AWS_MACIE_CONSUMER_NAME: &str = "MissionMacieDiscoveryConsumer";
pub const AWS_MACIE_SERVICE_SCHEMA: &str = "hartevo.aws-macie-discovery-result-service/v1";
pub const AWS_MACIE_PROVIDER_SCHEMA: &str = "hartevo.aws-macie-provider/v1";
pub const MISSION_AWS_MACIE_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-macie-discovery-result-consumer/v1";
pub const AWS_MACIE_MAX_RESPONSE_BYTES: usize = 1_048_576;

pub const AWS_MACIE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-macie-discovery-result/aws-macie-discovery-result.v1.json"
);

/// Errors are intentionally coarse at the provider boundary so raw AWS error
/// messages cannot become retained evidence.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MacieDiscoveryResultError {
    #[error(transparent)]
    Model(#[from] model::ModelError),
    #[error(transparent)]
    Plugin(#[from] PluginError),
    #[error(transparent)]
    Transport(#[from] transport::MacieTransportError),
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
    #[error("the finding is outside the registered scope, filter, or allowlist")]
    FindingOutOfScope,
    #[error("the ListFindings/GetFindings page binding drifted")]
    PageBindingMismatch,
    #[error("the provider returned a repeated opaque page token")]
    PageLoop,
    #[error("the bounded Macie response exceeded its limit")]
    ResponseBoundExceeded,
    #[error("the evidence digest or normalized finding was tampered with")]
    TamperedEvidence,
    #[error("the evidence is stale for this registration")]
    StaleEvidence,
    #[error("the provider returned an unknown projection")]
    ProviderUnknown,
    #[error("the contract document is invalid: {0}")]
    InvalidContract(String),
}

pub type Result<T> = std::result::Result<T, MacieDiscoveryResultError>;

pub fn contract_digest() -> model::Digest {
    model::sha256_digest(AWS_MACIE_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Validate the checked-in contract's identity and hard authority boundary.
/// Runtime behavior remains typed in the crate; the JSON is a machine-readable
/// companion rather than a second executable implementation.
pub fn validate_contract_document() -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(AWS_MACIE_CONTRACT_JSON)
        .map_err(|error| MacieDiscoveryResultError::InvalidContract(error.to_string()))?;
    let object = value.as_object().ok_or_else(|| {
        MacieDiscoveryResultError::InvalidContract("root is not an object".to_owned())
    })?;
    let string_field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| MacieDiscoveryResultError::InvalidContract(format!("missing {name}")))
    };
    if string_field("schemaVersion")? != AWS_MACIE_SCHEMA_VERSION
        || string_field("contractVersion")? != AWS_MACIE_CONTRACT_VERSION
        || string_field("pluginVersion")? != AWS_MACIE_PLUGIN_VERSION_TEXT
    {
        return Err(MacieDiscoveryResultError::InvalidContract(
            "contract identity drifted".to_owned(),
        ));
    }
    if object.get("layer").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(MacieDiscoveryResultError::InvalidContract(
            "contract layer is not 1".to_owned(),
        ));
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| MacieDiscoveryResultError::InvalidContract("missing provider".to_owned()))?;
    for field in [
        "native",
        "connected",
        "firstParty",
        "liveCredentialResolution",
        "externalWrites",
    ] {
        if provider.get(field).and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(MacieDiscoveryResultError::InvalidContract(format!(
                "provider.{field} must be false"
            )));
        }
    }
    let authority = object
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            MacieDiscoveryResultError::InvalidContract("missing authority".to_owned())
        })?;
    for field in [
        "jobCreation",
        "archiveFindings",
        "suppressFindings",
        "s3Mutation",
        "iamMutation",
        "sampleDownload",
        "rawPii",
        "truthAuthority",
        "consentAuthority",
        "effectAuthority",
        "receiptAuthority",
        "verificationAuthority",
        "outcomeAuthority",
        "workProductAdoption",
        "connected",
        "native",
        "firstParty",
    ] {
        if authority.get(field).and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(MacieDiscoveryResultError::InvalidContract(format!(
                "authority.{field} must be false"
            )));
        }
    }
    Ok(())
}

/// Build host-mountable runtime contribution descriptors for one exact
/// Project/Mission generation. Mounting and adoption remain host-owned.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition> {
    let plugin_id = PluginId::new(AWS_MACIE_PLUGIN_ID)?;
    let service_id = ServiceId::new(AWS_MACIE_DISCOVERY_SERVICE_ID)?;
    let provider_id = ProviderId::new(AWS_MACIE_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_AWS_MACIE_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AWS_MACIE_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AWS_MACIE_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_AWS_MACIE_CONSUMER_SCHEMA),
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

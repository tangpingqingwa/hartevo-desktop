//! Standalone Layer-1 AWS CodeBuild build-result evidence boundary.
//!
//! The crate is intentionally below native connector, Truth, Receipt, Outcome,
//! and Work Product authority. It exposes typed account/region/project/build/
//! source/commit/artifact/Mission/Project/Work Product fences and bounded
//! read/proposal/record/verify seams. Only fixture, recording, loopback, and
//! `BLOCKED_ENV` transports are available; none is Connected or native.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AwsCodeBuildReadRequest, MissionAwsCodeBuildConsumer, MissionAwsCodeBuildObservation,
    MissionAwsCodeBuildReadResult,
};
pub use model::*;
pub use provider::{
    AwsCodeBuildApiOperation, AwsCodeBuildProvider, AwsCodeBuildRegistration,
    AwsCodeBuildRegistrationRequest, AwsCodeBuildTransport, AwsCodeBuildTransportError,
    BatchGetBuildsPage, BatchGetBuildsRequest, BatchGetProjectsPage, BatchGetProjectsRequest,
    BlockedEnvAwsCodeBuildTransport, BlockedEnvTransport, CodeBuildApiOperation,
    FakeAwsCodeBuildTransport, FixtureAwsCodeBuildTransport, ListBuildsForProjectPage,
    ListBuildsForProjectRequest, LoopbackAwsCodeBuildTransport, OpaquePageToken, PageBinding,
    RecordedAwsCodeBuildRequest, RecordedBatchGetBuildsRequest, RecordedBatchGetProjectsRequest,
    RecordedListBuildsForProjectRequest, RecordingAwsCodeBuildTransport, RecordingTransport,
    RegistrationState,
};
pub use service::{
    AwsCodeBuildCapability, AwsCodeBuildObservationReceipt, AwsCodeBuildProposal,
    AwsCodeBuildRecord, AwsCodeBuildResultOperation, AwsCodeBuildResultProposal,
    AwsCodeBuildResultReceipt, AwsCodeBuildResultRecord, AwsCodeBuildResultService,
    AwsCodeBuildResultVerification, AwsCodeBuildVerification, VerificationStatus,
};

pub type AwsCodeBuildEvidence = CodeBuildEvidence;
pub type AwsCodeBuildReadProposal = AwsCodeBuildProposal;
pub type AwsCodeBuildReadRecord = AwsCodeBuildRecord;
pub type AwsCodeBuildReadReceipt = AwsCodeBuildObservationReceipt;
pub type AwsCodeBuildReadVerification = AwsCodeBuildVerification;

pub const AWS_CODEBUILD_SCHEMA_VERSION: &str = "hartevo.aws-codebuild-build-result-contract/v1";
pub const AWS_CODEBUILD_CONTRACT_VERSION: &str = "aws-codebuild-build-result/v1";
pub const AWS_CODEBUILD_PLUGIN_ID: &str = "aws-codebuild-build-result";
pub const AWS_CODEBUILD_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_CODEBUILD_SERVICE_ID: &str = "aws.codebuild.build-result";
pub const AWS_CODEBUILD_SERVICE_NAME: &str = "AwsCodeBuildResultService";
pub const AWS_CODEBUILD_SERVICE_SCHEMA: &str = "hartevo.aws-codebuild-result-service/v1";
pub const AWS_CODEBUILD_PROVIDER_ID: &str = "aws.codebuild.builds";
pub const AWS_CODEBUILD_PROVIDER_NAME: &str = "AwsCodeBuildProvider";
pub const AWS_CODEBUILD_PROVIDER_SCHEMA: &str = "hartevo.aws-codebuild-provider/v1";
pub const AWS_CODEBUILD_CONSUMER_ID: &str = "mission.aws-codebuild-build-result";
pub const AWS_CODEBUILD_CONSUMER_NAME: &str = "MissionAwsCodeBuildConsumer";
pub const AWS_CODEBUILD_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-codebuild-build-result-consumer/v1";
pub const MISSION_AWS_CODEBUILD_CONSUMER_ID: &str = AWS_CODEBUILD_CONSUMER_ID;
pub const MISSION_AWS_CODEBUILD_CONSUMER_SCHEMA: &str = AWS_CODEBUILD_CONSUMER_SCHEMA;
pub const AWS_CODEBUILD_API_VERSION: &str = "2016-10-06";
pub const AWS_CODEBUILD_API_REVISION: &str =
    "aws-codebuild-2016-10-06-list-builds-for-project-batch-get-builds-projects-r1";
pub const AWS_CODEBUILD_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_CODEBUILD_IAM_PERMISSIONS: [&str; 3] = [
    "codebuild:ListBuildsForProject",
    "codebuild:BatchGetBuilds",
    "codebuild:BatchGetProjects",
];
pub const AWS_CODEBUILD_MAX_IDENTIFIER_LENGTH: usize = 256;
pub const AWS_CODEBUILD_MAX_PAGE_SIZE: u16 = 100;
pub const AWS_CODEBUILD_MAX_PAGES: u16 = 4;
pub const AWS_CODEBUILD_MAX_BUILDS: usize = 400;
pub const AWS_CODEBUILD_MAX_PROJECTS: usize = 100;
pub const AWS_CODEBUILD_MAX_BUILDS_PER_REQUEST: usize = 100;
pub const AWS_CODEBUILD_MAX_PROJECTS_PER_REQUEST: usize = 100;
pub const AWS_CODEBUILD_MAX_ARTIFACTS_PER_BUILD: usize = 16;
pub const AWS_CODEBUILD_MAX_BATCH_METADATA: usize = 16;

pub const CONTRACT_SCHEMA: &str = AWS_CODEBUILD_SCHEMA_VERSION;
pub const CONTRACT_VERSION: &str = AWS_CODEBUILD_CONTRACT_VERSION;
pub const PLUGIN_VERSION: &str = AWS_CODEBUILD_PLUGIN_VERSION;
pub const SERVICE_ID: &str = AWS_CODEBUILD_SERVICE_ID;
pub const PROVIDER_ID: &str = AWS_CODEBUILD_PROVIDER_ID;
pub const CONSUMER_ID: &str = AWS_CODEBUILD_CONSUMER_ID;
pub const PROVIDER_API_REVISION: &str = AWS_CODEBUILD_API_REVISION;
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-codebuild-build-result/contract.v1.json");

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AwsCodeBuildError {
    #[error(transparent)]
    Model(#[from] model::ModelError),
    #[error(transparent)]
    Plugin(#[from] hartevo_plugin_runtime::PluginError),
    #[error(transparent)]
    Transport(#[from] provider::AwsCodeBuildTransportError),
    #[error("the provider registration is missing")]
    RegistrationMissing,
    #[error("the provider registration has been revoked")]
    RegistrationRevoked,
    #[error("the provider registration is invalid or drifted")]
    InvalidRegistration,
    #[error("the Project/Mission/Work Product or AWS CodeBuild scope does not match")]
    ScopeMismatch,
    #[error("the provider implementation or API revision drifted")]
    ProviderDrift,
    #[error("the contract or plugin version drifted")]
    ContractDrift,
    #[error("the permission digest drifted")]
    PermissionDrift,
    #[error("the source or commit fence drifted")]
    SourceDrift,
    #[error("the build fence drifted")]
    BuildMismatch,
    #[error("the artifact fence drifted")]
    ArtifactDrift,
    #[error("the provider page binding drifted")]
    PageBindingMismatch,
    #[error("the provider returned a repeated opaque page token")]
    PageLoop,
    #[error("the bounded AWS CodeBuild response exceeded its limit")]
    ResponseBoundExceeded,
    #[error("the evidence is partial and cannot be accepted as complete")]
    PartialEvidence,
    #[error("the evidence was tampered with")]
    TamperedEvidence,
    #[error("the evidence is stale for this registration")]
    StaleEvidence,
    #[error("the evidence or request was replayed")]
    ReplayDetected,
    #[error("the contract document is invalid: {0}")]
    InvalidContract(String),
}

pub type Result<T> = std::result::Result<T, AwsCodeBuildError>;

#[must_use]
pub fn contract_digest() -> model::Digest {
    model::Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn version_digest() -> model::Digest {
    model::Digest::from_text(AWS_CODEBUILD_PLUGIN_VERSION)
}

#[must_use]
pub fn api_digest() -> model::Digest {
    model::Digest::from_fields(
        "hartevo.aws-codebuild-api/v1",
        &[
            AWS_CODEBUILD_API_VERSION.to_owned(),
            "ListBuildsForProject".to_owned(),
            "BatchGetBuilds".to_owned(),
            "BatchGetProjects".to_owned(),
            AWS_CODEBUILD_API_REVISION.to_owned(),
        ],
    )
}

#[must_use]
pub fn permission_digest() -> model::Digest {
    model::Digest::from_fields(
        "hartevo.aws-codebuild-permissions/v1",
        &AWS_CODEBUILD_IAM_PERMISSIONS.map(str::to_owned),
    )
}

#[must_use]
pub fn evidence_schema_digest() -> model::Digest {
    model::Digest::from_fields(
        "hartevo.aws-codebuild-evidence-schema/v1",
        &[
            AWS_CODEBUILD_SCHEMA_VERSION.to_owned(),
            "complete".to_owned(),
            "partial".to_owned(),
            "access_lost".to_owned(),
            "bounded-redacted-no-native-receipt".to_owned(),
        ],
    )
}

/// Validates the checked-in contract's immutable identity and authority
/// boundary. This is local and deterministic; it never consults AWS.
pub fn validate_contract_document() -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| AwsCodeBuildError::InvalidContract(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| AwsCodeBuildError::InvalidContract("root is not an object".to_owned()))?;
    let string_field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AwsCodeBuildError::InvalidContract(format!("missing {name}")))
    };
    if string_field("schemaVersion")? != AWS_CODEBUILD_SCHEMA_VERSION
        || string_field("contractVersion")? != AWS_CODEBUILD_CONTRACT_VERSION
        || string_field("pluginVersion")? != AWS_CODEBUILD_PLUGIN_VERSION
    {
        return Err(AwsCodeBuildError::InvalidContract(
            "contract identity drifted".to_owned(),
        ));
    }
    if object.get("layer").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(AwsCodeBuildError::InvalidContract(
            "contract layer is not 1".to_owned(),
        ));
    }
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AwsCodeBuildError::InvalidContract("missing service".to_owned()))?;
    if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_CODEBUILD_SERVICE_NAME)
        || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        || service.get("outcomeAuthority") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsCodeBuildError::InvalidContract(
            "service authority drifted".to_owned(),
        ));
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AwsCodeBuildError::InvalidContract("missing provider".to_owned()))?;
    if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_CODEBUILD_PROVIDER_NAME)
        || provider.get("native") != Some(&serde_json::Value::Bool(false))
        || provider.get("connected") != Some(&serde_json::Value::Bool(false))
        || provider.get("liveCredentialResolution") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsCodeBuildError::InvalidContract(
            "provider authority drifted".to_owned(),
        ));
    }
    let authority = object
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AwsCodeBuildError::InvalidContract("missing authority".to_owned()))?;
    for field in [
        "externalWrites",
        "connected",
        "nativeProvider",
        "liveCredentialResolution",
        "nativeSigV4",
        "rawCommandArguments",
        "rawEnvironment",
        "rawSecrets",
        "rawLogs",
        "rawSourceBytes",
        "rawArtifactBytes",
        "durableNativeReceipt",
        "independentArtifactReadback",
        "verificationAuthority",
        "workloadCorrectnessAuthority",
        "outcomeAuthority",
        "workProductAdoption",
        "blockedEnvironmentIsNative",
        "fixtureIsNative",
        "recordingIsNative",
        "loopbackIsNative",
    ] {
        if authority.get(field).and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(AwsCodeBuildError::InvalidContract(format!(
                "authority.{field} must be false"
            )));
        }
    }
    Ok(())
}

/// Builds one runtime descriptor for an exact Project/Mission generation.
/// Mounting and unmounting remain host-owned and reversible.
pub fn plugin_definition(
    scope: hartevo_plugin_runtime::PluginScope,
) -> Result<hartevo_plugin_runtime::PluginDefinition> {
    use hartevo_plugin_runtime::{
        CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
        PluginContributions, PluginDefinition, PluginId, PluginVersion, ProviderCardinality,
        ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
    };

    let version = PluginVersion::new(1, 0, 0);
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            ServiceId::new(SERVICE_ID)?,
            version,
            RuntimeDigest::from_text(AWS_CODEBUILD_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            ProviderId::new(PROVIDER_ID)?,
            ServiceId::new(SERVICE_ID)?,
            version,
            RuntimeDigest::from_text(AWS_CODEBUILD_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            ConsumerId::new(CONSUMER_ID)?,
            ServiceId::new(SERVICE_ID)?,
            version,
            RuntimeDigest::from_text(AWS_CODEBUILD_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        PluginId::new(AWS_CODEBUILD_PLUGIN_ID)?,
        version,
        scope,
        contributions,
    )?)
}

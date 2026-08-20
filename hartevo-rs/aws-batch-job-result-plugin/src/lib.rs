//! Layer-1 bounded AWS Batch execution evidence.
//!
//! The crate is deliberately a standalone, read-only vertical slice. It
//! exposes typed scope, provider, service, and Mission-consumer seams for
//! `DescribeJobs` and `ListJobs`, including array and multi-node parallel
//! projections. It does not resolve credentials, sign native SigV4 requests,
//! submit/cancel/terminate work, retain raw provider payloads, or adopt a
//! kernel Truth, Receipt, Outcome, or Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AwsBatchReadRequest, MissionAwsBatchConsumer, MissionAwsBatchObservation,
    MissionAwsBatchReadResult,
};
pub use model::*;
pub use provider::{
    AwsBatchApiOperation, AwsBatchProvider, AwsBatchRegistration, AwsBatchRegistrationRequest,
    AwsBatchTransport, AwsBatchTransportError, BatchApiOperation, BatchFilter,
    BlockedEnvAwsBatchTransport, BlockedEnvTransport, DescribeJobsPage, DescribeJobsRequest,
    FakeAwsBatchTransport, FixtureAwsBatchTransport, ListJobsPage, ListJobsRequest, ListJobsTarget,
    LoopbackAwsBatchTransport, OpaquePageToken, PageBinding, RecordedAwsBatchRequest,
    RecordedDescribeJobsRequest, RecordedListJobsRequest, RecordingAwsBatchTransport,
    RecordingTransport, RegistrationState, provider_digest, provider_digest_for_revision,
};
pub use service::{
    AwsBatchCapability, AwsBatchJobResultOperation, AwsBatchJobResultProposal,
    AwsBatchJobResultReceipt, AwsBatchJobResultRecord, AwsBatchJobResultService,
    AwsBatchJobResultVerification, AwsBatchObservationReceipt, AwsBatchProposal, AwsBatchRecord,
    AwsBatchVerification, VerificationStatus,
};

pub const AWS_BATCH_JOB_RESULT_SCHEMA_VERSION: &str = "hartevo.aws-batch-job-result-contract/v1";
pub const AWS_BATCH_JOB_RESULT_CONTRACT_VERSION: &str = "aws-batch-job-result/v1";
pub const AWS_BATCH_JOB_RESULT_PLUGIN_ID: &str = "aws-batch-job-result";
pub const AWS_BATCH_JOB_RESULT_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_BATCH_JOB_RESULT_SERVICE_ID: &str = "aws.batch.job-result";
pub const AWS_BATCH_JOB_RESULT_SERVICE_NAME: &str = "AwsBatchJobResultService";
pub const AWS_BATCH_JOB_RESULT_SERVICE_SCHEMA: &str = "hartevo.aws-batch-job-result-service/v1";
pub const AWS_BATCH_JOB_RESULT_PROVIDER_ID: &str = "aws.batch.jobs";
pub const AWS_BATCH_JOB_RESULT_PROVIDER_NAME: &str = "AwsBatchProvider";
pub const AWS_BATCH_JOB_RESULT_PROVIDER_SCHEMA: &str = "hartevo.aws-batch-provider/v1";
pub const AWS_BATCH_JOB_RESULT_CONSUMER_ID: &str = "mission.aws-batch-job-result";
pub const AWS_BATCH_JOB_RESULT_CONSUMER_NAME: &str = "MissionAwsBatchConsumer";
pub const AWS_BATCH_JOB_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-batch-job-result-consumer/v1";
pub const MISSION_AWS_BATCH_CONSUMER_ID: &str = AWS_BATCH_JOB_RESULT_CONSUMER_ID;
pub const MISSION_AWS_BATCH_CONSUMER_SCHEMA: &str = AWS_BATCH_JOB_RESULT_CONSUMER_SCHEMA;
pub const AWS_BATCH_JOB_RESULT_API_VERSION: &str = "2016-08-10";
pub const AWS_BATCH_JOB_RESULT_API_REVISION: &str = "aws-batch-2016-08-10-describe-list-jobs-r1";
pub const AWS_BATCH_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_SCHEMA: &str = AWS_BATCH_JOB_RESULT_SCHEMA_VERSION;
pub const CONTRACT_VERSION: &str = AWS_BATCH_JOB_RESULT_CONTRACT_VERSION;
pub const PLUGIN_VERSION: &str = AWS_BATCH_JOB_RESULT_PLUGIN_VERSION;
pub const SERVICE_ID: &str = AWS_BATCH_JOB_RESULT_SERVICE_ID;
pub const PROVIDER_ID: &str = AWS_BATCH_JOB_RESULT_PROVIDER_ID;
pub const CONSUMER_ID: &str = AWS_BATCH_JOB_RESULT_CONSUMER_ID;
pub const PROVIDER_API_REVISION: &str = AWS_BATCH_JOB_RESULT_API_REVISION;
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-batch-job-result/aws-batch-job-result.v1.json");

pub const AWS_BATCH_IAM_PERMISSIONS: [&str; 2] = ["batch:DescribeJobs", "batch:ListJobs"];
pub const AWS_BATCH_MAX_DESCRIBE_JOBS: usize = 100;
pub const AWS_BATCH_MAX_PAGE_SIZE: u16 = 100;
pub const AWS_BATCH_MAX_PAGES: u16 = 4;
pub const AWS_BATCH_MAX_JOBS: usize = 400;
pub const AWS_BATCH_MAX_CHILDREN: usize = 400;
pub const AWS_BATCH_MAX_ATTEMPTS: usize = 16;
pub const AWS_BATCH_MAX_IDENTIFIER_LENGTH: usize = 256;

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum AwsBatchError {
    #[error(transparent)]
    Model(#[from] model::ModelError),
    #[error(transparent)]
    Plugin(#[from] hartevo_plugin_runtime::PluginError),
    #[error(transparent)]
    Transport(#[from] provider::AwsBatchTransportError),
    #[error("the provider registration is missing")]
    RegistrationMissing,
    #[error("the provider registration has been revoked")]
    RegistrationRevoked,
    #[error("the provider registration is invalid or drifted")]
    InvalidRegistration,
    #[error("the Project/Mission/Work Product or AWS scope does not match")]
    ScopeMismatch,
    #[error("the provider implementation or API revision drifted")]
    ProviderDrift,
    #[error("the contract or plugin version drifted")]
    ContractDrift,
    #[error("the permission digest drifted")]
    PermissionDrift,
    #[error("the job or attempt fence drifted")]
    JobAttemptMismatch,
    #[error("the provider page binding drifted")]
    PageBindingMismatch,
    #[error("the provider returned a repeated opaque page token")]
    PageLoop,
    #[error("the bounded AWS Batch response exceeded its limit")]
    ResponseBoundExceeded,
    #[error("the evidence is partial and cannot be accepted as complete")]
    PartialEvidence,
    #[error("the evidence was tampered with")]
    TamperedEvidence,
    #[error("the evidence is stale for this registration")]
    StaleEvidence,
    #[error("the contract document is invalid: {0}")]
    InvalidContract(String),
}

pub type Result<T> = std::result::Result<T, AwsBatchError>;

#[must_use]
pub fn contract_digest() -> model::Digest {
    model::Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn version_digest() -> model::Digest {
    model::Digest::from_text(AWS_BATCH_JOB_RESULT_PLUGIN_VERSION)
}

#[must_use]
pub fn api_digest() -> model::Digest {
    model::Digest::from_fields(
        "hartevo.aws-batch-api/v1",
        &[
            AWS_BATCH_JOB_RESULT_API_VERSION.to_owned(),
            "DescribeJobs".to_owned(),
            "ListJobs".to_owned(),
        ],
    )
}

#[must_use]
pub fn permission_digest() -> model::Digest {
    model::Digest::from_fields(
        "hartevo.aws-batch-permissions/v1",
        &AWS_BATCH_IAM_PERMISSIONS.map(str::to_owned),
    )
}

/// Validates the checked-in contract's immutable identity and its authority
/// boundary. This is intentionally local and deterministic; it does not fetch
/// a schema or consult a native AWS endpoint.
pub fn validate_contract_document() -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| AwsBatchError::InvalidContract(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| AwsBatchError::InvalidContract("root is not an object".to_owned()))?;
    let string_field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AwsBatchError::InvalidContract(format!("missing {name}")))
    };
    if string_field("schemaVersion")? != AWS_BATCH_JOB_RESULT_SCHEMA_VERSION
        || string_field("contractVersion")? != AWS_BATCH_JOB_RESULT_CONTRACT_VERSION
        || string_field("pluginVersion")? != AWS_BATCH_JOB_RESULT_PLUGIN_VERSION
    {
        return Err(AwsBatchError::InvalidContract(
            "contract identity drifted".to_owned(),
        ));
    }
    if object.get("layer").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(AwsBatchError::InvalidContract(
            "contract layer is not 1".to_owned(),
        ));
    }
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AwsBatchError::InvalidContract("missing service".to_owned()))?;
    if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_BATCH_JOB_RESULT_SERVICE_NAME)
        || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        || service.get("outcomeAuthority") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsBatchError::InvalidContract(
            "service authority drifted".to_owned(),
        ));
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AwsBatchError::InvalidContract("missing provider".to_owned()))?;
    if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_BATCH_JOB_RESULT_PROVIDER_NAME)
        || provider.get("native") != Some(&serde_json::Value::Bool(false))
        || provider.get("connected") != Some(&serde_json::Value::Bool(false))
        || provider.get("liveCredentialResolution") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsBatchError::InvalidContract(
            "provider authority drifted".to_owned(),
        ));
    }
    let authority = object
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AwsBatchError::InvalidContract("missing authority".to_owned()))?;
    for field in [
        "connected",
        "nativeProvider",
        "liveCredentialResolution",
        "rawCommandArguments",
        "rawEnvironment",
        "rawLogs",
        "rawImages",
        "rawDataOutputs",
        "durableProviderReceipt",
        "independentOutputReadback",
        "verificationAuthority",
        "workloadCorrectnessAuthority",
        "outcomeAuthority",
        "workProductAdoption",
        "blockedEnvironmentIsNative",
    ] {
        if authority.get(field).and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(AwsBatchError::InvalidContract(format!(
                "authority.{field} must be false"
            )));
        }
    }
    Ok(())
}

/// Builds the plugin-runtime descriptor for one exact Project/Mission
/// generation. Mounting and unmounting remain host-owned and reversible.
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
            RuntimeDigest::from_text(AWS_BATCH_JOB_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            ProviderId::new(PROVIDER_ID)?,
            ServiceId::new(SERVICE_ID)?,
            version,
            RuntimeDigest::from_text(AWS_BATCH_JOB_RESULT_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            ConsumerId::new(CONSUMER_ID)?,
            ServiceId::new(SERVICE_ID)?,
            version,
            RuntimeDigest::from_text(AWS_BATCH_JOB_RESULT_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        PluginId::new(AWS_BATCH_JOB_RESULT_PLUGIN_ID)?,
        version,
        scope,
        contributions,
    )?)
}

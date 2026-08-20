//! Standalone Layer-1 governed Jenkins build-result plugin.
//!
//! This crate exposes typed, bounded, GET-only Remote Access JSON reads for
//! controller/folder/job/branch/build/commit/test-summary/artifact metadata.
//! It is proposal-only and has no native credential resolution, native HTTPS,
//! Connected claim, provider mutation, console-log authority, raw-artifact or
//! source authority, kernel receipt, Outcome authority, or Work Product
//! adoption.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde::Deserialize;
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionJenkinsBuildConsumer, MissionJenkinsBuildConsumerError, MissionJenkinsBuildResult,
    MissionJenkinsBuildResultConsumer, MissionJenkinsBuildResultState, MissionResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvJenkinsTransport, BlockedEnvTransport, FixtureJenkinsTransport, FixtureTransport,
    JenkinsHttpMethod, JenkinsHttpRequest, JenkinsHttpResponse, JenkinsPayload, JenkinsProvider,
    JenkinsProviderDefinition, JenkinsProviderError, JenkinsProviderRead, JenkinsReadRequest,
    JenkinsTransport, JenkinsTransportError, LoopbackJenkinsTransport, LoopbackTransport,
    RecordingJenkinsTransport, RecordingTransport,
};
pub use service::{
    JenkinsBuildResultCapability, JenkinsBuildResultOperation, JenkinsBuildResultProposal,
    JenkinsBuildResultReadRequest, JenkinsBuildResultRegistration,
    JenkinsBuildResultRegistration as JenkinsRegistration, JenkinsBuildResultRequest,
    JenkinsBuildResultService, JenkinsBuildResultServiceDefinition, JenkinsBuildResultServiceError,
    JenkinsProposal, JenkinsRegistrationTransition, JenkinsVerificationFailure,
    JenkinsVerificationReport,
};

pub const JENKINS_BUILD_RESULT_SCHEMA_VERSION: &str = "hartevo.jenkins-build-result/v1";
pub const JENKINS_BUILD_RESULT_CONTRACT_VERSION: &str = "jenkins-build-result-e1/v1";
pub const JENKINS_BUILD_RESULT_PLUGIN_ID: &str = "jenkins-build-result";
pub const JENKINS_BUILD_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const JENKINS_BUILD_RESULT_SERVICE_ID: &str = "jenkins.build-result";
pub const JENKINS_BUILD_RESULT_SERVICE_NAME: &str = "JenkinsBuildResultService";
pub const JENKINS_PROVIDER_ID: &str = "jenkins.remote-access";
pub const JENKINS_PROVIDER_IMPLEMENTATION: &str = "JenkinsProvider";
pub const JENKINS_PROVIDER_VERSION: &str = "1.0.0";
pub const JENKINS_PROVIDER_REVISION: &str = "jenkins-remote-access-json-r1";
pub const MISSION_JENKINS_BUILD_CONSUMER_ID: &str = "mission.jenkins-build-result";
pub const MISSION_JENKINS_BUILD_CONSUMER_NAME: &str = "MissionJenkinsBuildConsumer";
pub const JENKINS_BUILD_RESULT_SERVICE_SCHEMA: &str = "hartevo.jenkins-build-result-service/v1";
pub const JENKINS_PROVIDER_SCHEMA: &str = "hartevo.jenkins-provider/v1";
pub const MISSION_JENKINS_BUILD_CONSUMER_SCHEMA: &str = "hartevo.mission-jenkins-build-consumer/v1";
pub const JENKINS_API_REVISION: &str = JENKINS_PROVIDER_REVISION;
pub const JENKINS_EVIDENCE_POLICY_SCHEMA: &str = "hartevo.jenkins-build-result-evidence-policy/v1";
pub const JENKINS_BUILD_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/jenkins-build-result/jenkins-build-result.v1.json";
pub const JENKINS_BUILD_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/jenkins-build-result/jenkins-build-result.v1.json");

pub fn contract_digest() -> Digest {
    sha256_digest(JENKINS_BUILD_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(0, 1, 0)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum JenkinsBuildResultPluginError {
    #[error("Jenkins plugin runtime rejected the definition: {0}")]
    Plugin(#[from] PluginError),
    #[error("Jenkins contract validation failed: {0}")]
    Contract(String),
}

pub type JenkinsBuildResultError = JenkinsBuildResultPluginError;

/// Builds one inert plugin-runtime contribution set for an exact
/// Project/Mission generation. Mounting remains a host/runtime decision.
pub fn plugin_definition(
    scope: PluginScope,
) -> Result<PluginDefinition, JenkinsBuildResultPluginError> {
    let plugin_id = PluginId::new(JENKINS_BUILD_RESULT_PLUGIN_ID)?;
    let service_id = ServiceId::new(JENKINS_BUILD_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(JENKINS_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_JENKINS_BUILD_CONSUMER_ID)?;
    let service_version = PluginVersion::new(1, 0, 0);
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            service_version,
            RuntimeDigest::from_text(JENKINS_BUILD_RESULT_CONTRACT_JSON),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            service_version,
            RuntimeDigest::from_text(JENKINS_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            service_version,
            RuntimeDigest::from_text(MISSION_JENKINS_BUILD_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        plugin_version(),
        scope,
        contributions,
    )?)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

fn contract_is(value: bool, field: &'static str) -> Result<(), ContractValidationError> {
    if value {
        Ok(())
    } else {
        Err(ContractValidationError::FrozenField(field))
    }
}

/// Validates the checked-in contract and the authority/allowlist pins that
/// protect the implementation from silently becoming a broader connector.
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(JENKINS_BUILD_RESULT_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    contract_is(
        contract["schemaVersion"] == JENKINS_BUILD_RESULT_SCHEMA_VERSION,
        "schemaVersion",
    )?;
    contract_is(
        contract["contractVersion"] == JENKINS_BUILD_RESULT_CONTRACT_VERSION,
        "contractVersion",
    )?;
    contract_is(
        contract["pluginVersion"] == JENKINS_BUILD_RESULT_PLUGIN_VERSION,
        "pluginVersion",
    )?;
    contract_is(
        contract["pluginId"] == JENKINS_BUILD_RESULT_PLUGIN_ID,
        "pluginId",
    )?;
    contract_is(contract["layer"] == "Layer-1", "layer")?;
    contract_is(
        contract["officialReferences"]
            == serde_json::json!(["https://www.jenkins.io/doc/book/using/remote-access-api/"]),
        "officialReferences",
    )?;
    contract_is(
        contract["authority"]
            == serde_json::json!({
                "readOnly": true,
                "proposalOnly": true,
                "connected": false,
                "native": false,
                "externalWrites": false,
                "kernelAuthority": false,
                "truthAuthority": false,
                "outcomeAuthority": false,
                "workProductAdoption": false,
                "credentialAuthority": false,
                "consoleLogAuthority": false,
                "rawArtifactAuthority": false,
                "sourceAuthority": false
            }),
        "authority",
    )?;
    contract_is(
        contract["service"]["id"] == JENKINS_BUILD_RESULT_SERVICE_ID
            && contract["service"]["name"] == JENKINS_BUILD_RESULT_SERVICE_NAME
            && contract["service"]["version"] == "1.0.0"
            && contract["service"]["access"] == "read_only"
            && contract["service"]["operations"]
                == serde_json::json!([
                    "describe_capabilities",
                    "read_controller",
                    "read_folder",
                    "read_job",
                    "read_build",
                    "read_branch",
                    "read_commit",
                    "read_test_summary",
                    "read_artifact_metadata",
                    "compile_proposal",
                    "verify_proposal",
                    "revoke_registration",
                    "restore_registration",
                    "consume_observation"
                ])
            && contract["service"]["externalWrites"] == false,
        "service",
    )?;
    contract_is(
        contract["provider"]["id"] == JENKINS_PROVIDER_ID
            && contract["provider"]["name"] == JENKINS_PROVIDER_IMPLEMENTATION
            && contract["provider"]["version"] == JENKINS_PROVIDER_VERSION
            && contract["provider"]["apiRevision"] == JENKINS_PROVIDER_REVISION
            && contract["provider"]["allowedMethods"] == serde_json::json!(["GET"])
            && contract["provider"]["native"] == false
            && contract["provider"]["connected"] == false
            && contract["provider"]["externalWrites"] == false,
        "provider",
    )?;
    contract_is(
        contract["provider"]["allowlistedReads"]
            .as_array()
            .is_some_and(|reads| reads.len() == 8),
        "provider.allowlistedReads",
    )?;
    contract_is(
        contract["provider"]["allowlistedReads"]
            == serde_json::json!([
                {"operation": "read_controller", "path": "/api/json", "method": "GET"},
                {"operation": "read_folder", "path": "/job/{folder}/api/json", "method": "GET"},
                {"operation": "read_job", "path": "/job/{folder...}/{job}/api/json", "method": "GET"},
                {"operation": "read_build", "path": "/job/{folder...}/{job}/{branch?}/{build}/api/json", "method": "GET"},
                {"operation": "read_branch", "path": "/job/{folder...}/{job}/{branch}/api/json", "method": "GET"},
                {"operation": "read_commit", "path": "/job/{folder...}/{job}/{branch?}/{build}/api/json", "method": "GET"},
                {"operation": "read_test_summary", "path": "/job/{folder...}/{job}/{branch?}/{build}/testReport/api/json", "method": "GET"},
                {"operation": "read_artifact_metadata", "path": "/job/{folder...}/{job}/{branch?}/{build}/api/json", "method": "GET"}
            ]),
        "provider.allowlistedReads.exact",
    )?;
    contract_is(
        contract["provider"]["permissions"]
            == serde_json::json!([
                "jenkins.controller.read",
                "jenkins.folder.read",
                "jenkins.job.read",
                "jenkins.branch.read",
                "jenkins.build.read",
                "jenkins.commit.read",
                "jenkins.test-summary.read",
                "jenkins.artifact-metadata.read"
            ])
            && contract["provider"]["transportProvenance"]
                == serde_json::json!(["fixture", "recording", "loopback", "BLOCKED_ENV"]),
        "provider.permissions-and-provenance",
    )?;
    contract_is(
        contract["provider"]["forbiddenOperations"]
            == serde_json::json!([
                "trigger_build",
                "stop_build",
                "replay_build",
                "rebuild_build",
                "create_job",
                "delete_job",
                "configure_job",
                "install_plugin",
                "plugin_manager_mutation",
                "console_log",
                "progressive_console_text",
                "raw_artifact_download",
                "source_export",
                "script_output",
                "credential_resolution",
                "kernel_authority"
            ])
            && contract["provider"]["rawResponseBody"] == false
            && contract["provider"]["rawArtifacts"] == false
            && contract["provider"]["rawSource"] == false
            && contract["provider"]["rawScripts"] == false
            && contract["provider"]["credentials"] == "opaque_non_serializing_reference",
        "provider.fences",
    )?;
    contract_is(
        contract["consumer"]["id"] == MISSION_JENKINS_BUILD_CONSUMER_ID
            && contract["consumer"]["name"] == MISSION_JENKINS_BUILD_CONSUMER_NAME
            && contract["consumer"]["replayFence"] == true
            && contract["consumer"]["scope"]
                == serde_json::json!([
                    "controller",
                    "folder_path",
                    "job_name",
                    "build_number",
                    "branch_name",
                    "commit_sha",
                    "project_id",
                    "project_revision",
                    "mission_id",
                    "mission_revision",
                    "work_product_id",
                    "work_product_revision",
                    "registration_digest",
                    "evidence_digest"
                ])
            && contract["exactScope"]["required"]
                == serde_json::json!([
                    "controller",
                    "folder_path",
                    "job_name",
                    "build_number",
                    "branch_name",
                    "commit_sha",
                    "project_id",
                    "project_revision",
                    "mission_id",
                    "mission_revision",
                    "work_product_id",
                    "work_product_revision"
                ]),
        "consumer-and-scope",
    )?;
    contract_is(
        contract["registration"]["reversible"] == true
            && contract["registration"]["revocable"] == true
            && contract["registration"]["versionDigestBound"] == true
            && contract["registration"]["contractDigestBound"] == true
            && contract["registration"]["providerDigestBound"] == true
            && contract["registration"]["permissionDigestBound"] == true
            && contract["registration"]["scopeDigestBound"] == true
            && contract["registration"]["evidenceDigestBound"] == true,
        "registration",
    )?;
    contract_is(
        contract["bounds"]["maxResponseBytes"] == model::MAX_RESPONSE_BYTES
            && contract["bounds"]["maxOperations"] == model::MAX_OPERATIONS
            && contract["bounds"]["maxFolderDepth"] == model::MAX_FOLDER_DEPTH
            && contract["bounds"]["maxJobs"] == model::MAX_JOBS
            && contract["bounds"]["maxArtifacts"] == model::MAX_ARTIFACTS
            && contract["bounds"]["maxRequestsPerMinute"] == model::MAX_REQUESTS_PER_MINUTE
            && contract["bounds"]["maxCursorBytes"] == model::MAX_CURSOR_BYTES
            && contract["bounds"]["maxCursorPage"] == model::MAX_CURSOR_PAGE
            && contract["bounds"]["maxDiagnosticBytes"] == model::MAX_DIAGNOSTIC_BYTES,
        "bounds",
    )?;
    contract_is(
        contract["exactScope"]["projectMissionWorkProductExact"] == true
            && contract["consumer"]["proposalOnly"] == true
            && contract["consumer"]["adoptsOutcome"] == false
            && contract["consumer"]["adoptsWorkProduct"] == false
            && contract["consumer"]["kernelAuthority"] == false,
        "scope-and-consumer-authority",
    )?;
    let statuses = contract["statuses"]
        .as_array()
        .ok_or(ContractValidationError::FrozenField("statuses"))?;
    let expected_statuses = model::JenkinsBuildResultStatus::ALL
        .into_iter()
        .map(|status| serde_json::Value::String(status.as_str().to_owned()))
        .collect::<Vec<_>>();
    contract_is(
        statuses.as_slice() == expected_statuses.as_slice(),
        "statuses",
    )?;
    contract_is(
        contract["honesty"]["nativeHttpsTransport"] == "layer_2_gap"
            && contract["honesty"]["nativeCredentialResolution"] == "layer_2_gap"
            && contract["honesty"]["rawArtifactOrLogAuthority"] == false
            && contract["honesty"]["kernelOutcomeAuthority"] == false,
        "honesty",
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn native() -> bool {
        false
    }

    pub const fn connected() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsContractMetadata {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub plugin_id: String,
    pub layer: String,
}

pub fn contract_metadata() -> Result<JenkinsContractMetadata, ContractValidationError> {
    validate_contract()?;
    let value: serde_json::Value = serde_json::from_str(JENKINS_BUILD_RESULT_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let string_field = |name: &'static str| {
        value[name]
            .as_str()
            .map(str::to_owned)
            .ok_or(ContractValidationError::FrozenField(name))
    };
    Ok(JenkinsContractMetadata {
        schema_version: string_field("schemaVersion")?,
        contract_version: string_field("contractVersion")?,
        plugin_version: string_field("pluginVersion")?,
        plugin_id: string_field("pluginId")?,
        layer: string_field("layer")?,
    })
}

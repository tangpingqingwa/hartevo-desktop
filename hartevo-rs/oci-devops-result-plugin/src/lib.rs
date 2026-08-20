//! Governed OCI DevOps delivery-result evidence for a standalone Layer-1 root.
//!
//! This crate exposes a bounded, read-only OCI DevOps seam: list and get
//! deployments, build runs, and work requests, then normalize their state,
//! stage, revision, artifact-metadata, and log-metadata evidence. It has no
//! run/cancel/approve/redeploy method, stores no raw provider payload, and
//! never claims native Connected authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use std::collections::BTreeMap;

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    DeliveryDecisionProposal, DeliveryDecisionRecord, MissionOciDevopsConsumer,
    MissionOciDevopsReadResult, OciDeliveryReadbackVerification, OciDevopsObservation,
};
pub use model::*;
pub use provider::{
    BlockedEnvSigningKeyResolver, CredentialLease, EnvironmentSigningKeyResolver,
    OciAccessCredential, OciCredentialError, OciDevopsProvider, OciNativeProbe,
    OciNativeProbeStatus, OciRegistration, OciRegistrationRequest, OciRegistrationState,
    OciSigningKeyResolver, native_probe_from_environment,
};
pub use service::{OciCapability, OciDevopsOperation, OciDevopsResultService};
pub use transport::{
    BlockedEnvOciDevopsTransport, FakeOciDevopsTransport, LoopbackOciDevopsTransport,
    OciDevopsEndpoint, OciDevopsHttpRequest, OciDevopsHttpResponse, OciDevopsTransport,
    OciTransportError, RecordingOciDevopsTransport, RequestBounds, UreqOciDevopsTransport,
};

pub const OCI_DEVOPS_RESULT_SCHEMA_VERSION: &str = "hartevo.oci-devops-result-contract/v1";
pub const OCI_DEVOPS_RESULT_CONTRACT_VERSION: &str = "oci-devops-result/v1";
pub const OCI_DEVOPS_RESULT_PLUGIN_ID: &str = "oci-devops-result";
pub const OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const OCI_DEVOPS_API_VERSION: &str = "20210630";
pub const OCI_DEVOPS_API_ORIGIN_PATTERN: &str = "https://devops.{region}.oci.oraclecloud.com";
pub const OCI_DEVOPS_RESULT_SERVICE_ID: &str = "oci.devops-result";
pub const OCI_DEVOPS_RESULT_SERVICE_NAME: &str = "OciDevopsResultService";
pub const OCI_DEVOPS_PROVIDER_ID: &str = "oci.devops";
pub const OCI_DEVOPS_PROVIDER_NAME: &str = "OciDevopsProvider";
pub const MISSION_OCI_DEVOPS_CONSUMER_ID: &str = "mission.oci-devops-result";
pub const MISSION_OCI_DEVOPS_CONSUMER_NAME: &str = "MissionOciDevopsConsumer";
pub const OCI_DEVOPS_RESULT_SERVICE_SCHEMA: &str = "hartevo.oci-devops-result-service/v1";
pub const OCI_DEVOPS_PROVIDER_SCHEMA: &str = "hartevo.oci-devops-provider/v1";
pub const MISSION_OCI_DEVOPS_CONSUMER_SCHEMA: &str = "hartevo.mission-oci-devops-consumer/v1";
pub const OCI_DEVOPS_PROVIDER_REVISION: &str = "oci-devops-rest-20210630-r1";
pub const OCI_DEVOPS_NATIVE_PROBE_ENV: &str = "HARTEVO_OCI_DEVOPS_NATIVE_PROBE";
pub const OCI_DEVOPS_NATIVE_PROBE_GATE: &str = "HARTEVO_OCI_DEVOPS_NATIVE_PROBE=1";
pub const OCI_DEVOPS_SIGNING_KEY_ENV: &str = "HARTEVO_OCI_DEVOPS_SIGNING_KEY";
pub const OCI_DEVOPS_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const OCI_DEVOPS_MAX_RESULTS: u16 = 50;
pub const OCI_DEVOPS_MAX_PAGES: u16 = 4;
pub const OCI_DEVOPS_MAX_DEPLOYMENTS: usize = 64;
pub const OCI_DEVOPS_MAX_BUILD_RUNS: usize = 64;
pub const OCI_DEVOPS_MAX_WORK_REQUESTS: usize = 64;
pub const OCI_DEVOPS_MAX_STAGES: usize = 64;
pub const OCI_DEVOPS_MAX_ARTIFACT_METADATA: usize = 128;
pub const OCI_DEVOPS_MAX_NEXT_PAGE_TOKEN_BYTES: usize = 2_048;
pub const OCI_DEVOPS_MAX_STATE_BYTES: usize = 128;

pub const OCI_DEVOPS_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/oci-devops-result/oci-devops-result.v1.json");

pub fn contract_digest() -> Digest {
    model::sha256_digest(OCI_DEVOPS_RESULT_CONTRACT_JSON.as_bytes())
}

/// Digest of the bounded evidence policy bound into every registration.
pub fn evidence_policy_digest() -> Digest {
    Digest::from_fields(
        "hartevo-oci-devops-evidence-policy/v1",
        &[
            OCI_DEVOPS_RESULT_CONTRACT_VERSION.to_owned(),
            OCI_DEVOPS_API_VERSION.to_owned(),
            OCI_DEVOPS_MAX_RESPONSE_BYTES.to_string(),
            OCI_DEVOPS_MAX_RESULTS.to_string(),
            OCI_DEVOPS_MAX_PAGES.to_string(),
            OCI_DEVOPS_MAX_DEPLOYMENTS.to_string(),
            OCI_DEVOPS_MAX_BUILD_RUNS.to_string(),
            OCI_DEVOPS_MAX_WORK_REQUESTS.to_string(),
            OCI_DEVOPS_MAX_STAGES.to_string(),
            OCI_DEVOPS_MAX_ARTIFACT_METADATA.to_string(),
            "raw-logs-artifacts-environment-secrets-excluded".to_owned(),
        ],
    )
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Build the reversible plugin-runtime contribution set for one exact
/// Project/Mission generation. Mounting is still a host decision.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, OciDevopsError> {
    let plugin_id = PluginId::new(OCI_DEVOPS_RESULT_PLUGIN_ID)?;
    let service_id = ServiceId::new(OCI_DEVOPS_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(OCI_DEVOPS_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_OCI_DEVOPS_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(OCI_DEVOPS_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(OCI_DEVOPS_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_OCI_DEVOPS_CONSUMER_SCHEMA),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciDevopsResultContract {
    pub schema_version: String,
    pub contract_version: String,
    pub layer: u8,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_version: String,
    pub api_origin_pattern: String,
    pub api_paths: BTreeMap<String, String>,
    pub transport_provenance: Vec<String>,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub mutating_provider_operations: Vec<String>,
    pub authority: OciAuthorityContract,
    pub registration: OciRegistrationContract,
    pub scope_fence: Vec<String>,
    pub bounds: OciBoundsContract,
    pub redaction: OciRedactionContract,
    pub receipts: OciReceiptsContract,
    pub native_gap: OciNativeGapContract,
    pub honest_native_gap: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OciAuthorityContract {
    pub external_writes: bool,
    pub run: bool,
    pub cancel: bool,
    pub approve: bool,
    pub redeploy: bool,
    pub raw_logs: bool,
    pub raw_artifacts: bool,
    pub raw_environment: bool,
    pub raw_secrets: bool,
    pub connected: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciRegistrationContract {
    pub bound_fields: Vec<String>,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciBoundsContract {
    pub max_response_bytes: usize,
    pub max_results: u16,
    pub max_pages: u16,
    pub max_deployments: usize,
    pub max_build_runs: usize,
    pub max_work_requests: usize,
    pub max_stages: usize,
    pub max_artifact_metadata: usize,
    pub max_next_page_token_bytes: usize,
    pub max_state_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciRedactionContract {
    pub retained: Vec<String>,
    pub redacted: Vec<String>,
    pub explicit_read_projection_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OciReceiptsContract {
    pub request_path_and_query: bool,
    pub request_body: bool,
    pub response_status: bool,
    pub response_size: bool,
    pub response_digest: bool,
    pub provider_revision: bool,
    pub api_version: bool,
    pub page_token_digest: bool,
    pub raw_provider_payload: bool,
    pub raw_logs: bool,
    pub raw_artifacts: bool,
    pub credential_material: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciNativeGapContract {
    pub status: String,
    pub deferred_to: String,
    pub fail_closed_cases: Vec<String>,
}

impl OciDevopsResultContract {
    pub fn baseline() -> Result<Self, OciDevopsError> {
        let contract = serde_json::from_str::<Self>(OCI_DEVOPS_RESULT_CONTRACT_JSON)
            .map_err(|error| OciDevopsError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), OciDevopsError> {
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "list_deployments",
            "get_deployment",
            "list_build_runs",
            "get_build_run",
            "list_work_requests",
            "get_work_request",
            "consume_observation",
            "propose_delivery_decision",
            "record_delivery_decision",
            "verify_readback",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_paths = BTreeMap::from([
            (
                "getBuildRun".to_owned(),
                "/20210630/buildRuns/{buildRunId}".to_owned(),
            ),
            (
                "getDeployment".to_owned(),
                "/20210630/deployments/{deploymentId}".to_owned(),
            ),
            (
                "getWorkRequest".to_owned(),
                "/20210630/workRequests/{workRequestId}".to_owned(),
            ),
            ("listBuildRuns".to_owned(), "/20210630/buildRuns".to_owned()),
            (
                "listDeployments".to_owned(),
                "/20210630/deployments".to_owned(),
            ),
            (
                "listWorkRequests".to_owned(),
                "/20210630/workRequests".to_owned(),
            ),
        ]);
        let expected_transport_provenance = [
            "fixture",
            "recording",
            "loopback",
            "blocked_env",
            "production_read",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_bound_fields = [
            "pluginVersion",
            "providerVersion",
            "contractVersion",
            "contractDigest",
            "permissionDigest",
            "region",
            "tenancyId",
            "compartmentId",
            "ociProjectId",
            "pipelineId",
            "buildId",
            "deploymentId",
            "workRequestId",
            "missionScope",
            "hartevoProjectScope",
            "workProductScope",
            "secretReferenceDigest",
            "credentialRevision",
            "scopeDigest",
            "evidenceDigest",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_scope_fence = [
            "region",
            "tenancyId",
            "compartmentId",
            "ociProjectId",
            "pipelineId",
            "buildId",
            "deploymentId",
            "workRequestId",
            "missionIdAndRevision",
            "projectIdAndRevision",
            "workProductIdAndRevision",
            "deploymentRevision",
            "buildRevision",
            "workRequestRevision",
            "stageIdAndStateAndRevision",
            "reconcileResourceIdAndRevision",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_retained = [
            "ocid",
            "lifecycleState",
            "stageState",
            "revision",
            "timestamps",
            "boundedCounts",
            "contentFingerprints",
            "artifactMetadataFingerprint",
            "logMetadataFingerprint",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_redacted = [
            "rawLogs",
            "rawArtifacts",
            "artifactDownloadUrls",
            "environmentVariables",
            "secretMaterial",
            "userPii",
            "rawProviderBody",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        if self.schema_version != OCI_DEVOPS_RESULT_SCHEMA_VERSION
            || self.contract_version != OCI_DEVOPS_RESULT_CONTRACT_VERSION
            || self.layer != 1
            || self.service_id != OCI_DEVOPS_RESULT_SERVICE_ID
            || self.provider_id != OCI_DEVOPS_PROVIDER_ID
            || self.consumer_id != MISSION_OCI_DEVOPS_CONSUMER_ID
            || self.api_version != OCI_DEVOPS_API_VERSION
            || self.api_origin_pattern != OCI_DEVOPS_API_ORIGIN_PATTERN
            || self.api_paths != expected_paths
            || self.transport_provenance != expected_transport_provenance
            || self.operations != expected_operations
            || !self.read_only
            || !self.mutating_provider_operations.is_empty()
            || self.authority.external_writes
            || self.authority.run
            || self.authority.cancel
            || self.authority.approve
            || self.authority.redeploy
            || self.authority.raw_logs
            || self.authority.raw_artifacts
            || self.authority.raw_environment
            || self.authority.raw_secrets
            || self.authority.connected
            || self.authority.effect
            || self.authority.receipt
            || self.authority.verification
            || self.authority.outcome
            || self.authority.work_product_adoption
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || self.registration.bound_fields != expected_bound_fields
            || self.scope_fence != expected_scope_fence
            || self.bounds.max_response_bytes != OCI_DEVOPS_MAX_RESPONSE_BYTES
            || self.bounds.max_results != OCI_DEVOPS_MAX_RESULTS
            || self.bounds.max_pages != OCI_DEVOPS_MAX_PAGES
            || self.bounds.max_deployments != OCI_DEVOPS_MAX_DEPLOYMENTS
            || self.bounds.max_build_runs != OCI_DEVOPS_MAX_BUILD_RUNS
            || self.bounds.max_work_requests != OCI_DEVOPS_MAX_WORK_REQUESTS
            || self.bounds.max_stages != OCI_DEVOPS_MAX_STAGES
            || self.bounds.max_artifact_metadata != OCI_DEVOPS_MAX_ARTIFACT_METADATA
            || self.bounds.max_next_page_token_bytes != OCI_DEVOPS_MAX_NEXT_PAGE_TOKEN_BYTES
            || self.bounds.max_state_bytes != OCI_DEVOPS_MAX_STATE_BYTES
            || self.redaction.retained != expected_retained
            || self.redaction.redacted != expected_redacted
            || !self.redaction.explicit_read_projection_required
            || !self.receipts.request_path_and_query
            || self.receipts.request_body
            || !self.receipts.response_status
            || !self.receipts.response_size
            || !self.receipts.response_digest
            || !self.receipts.provider_revision
            || !self.receipts.api_version
            || !self.receipts.page_token_digest
            || self.receipts.raw_provider_payload
            || self.receipts.raw_logs
            || self.receipts.raw_artifacts
            || self.receipts.credential_material
            || self.native_gap.status != "BLOCKED_ENV"
            || self.native_gap.deferred_to != "layer_2_native_oci_signing_and_connected"
            || !self.honest_native_gap.contains("Native OCI signing")
            || !self
                .honest_native_gap
                .contains("raw logs and artifact bytes")
        {
            return Err(OciDevopsError::Contract(
                "OCI DevOps Result contract does not match the checked-in Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OciDevopsError {
    #[error("BLOCKED_ENV: native OCI signing authority is unavailable")]
    BlockedEnv,
    #[error("OCI DevOps input is invalid: {0}")]
    InvalidInput(String),
    #[error("OCI DevOps contract is invalid: {0}")]
    Contract(String),
    #[error("OCI DevOps scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("OCI DevOps plugin version mismatch")]
    VersionMismatch,
    #[error("OCI DevOps provider version mismatch")]
    ProviderVersionMismatch,
    #[error("OCI DevOps contract digest mismatch")]
    ContractDigestMismatch,
    #[error("OCI DevOps permission digest mismatch")]
    PermissionDigestMismatch,
    #[error("OCI DevOps registration is revoked")]
    RegistrationRevoked,
    #[error("OCI DevOps registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("OCI DevOps credential lease is invalid or expired")]
    CredentialExpired,
    #[error("OCI DevOps credential resolution failed: {0}")]
    Credential(String),
    #[error("OCI DevOps API version drifted from {expected}: {actual}")]
    ApiVersionDrift { expected: String, actual: String },
    #[error("OCI DevOps region or tenancy drifted")]
    RegionOrTenancyDrift,
    #[error("OCI DevOps response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("OCI DevOps returned unexpected HTTP status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("OCI DevOps response could not be decoded: {0}")]
    Decode(String),
    #[error("OCI DevOps transport failed: {0}")]
    Transport(String),
    #[error("OCI DevOps deployment was not returned")]
    DeploymentNotFound,
    #[error("OCI DevOps build run was not returned")]
    BuildRunNotFound,
    #[error("OCI DevOps work request was not returned")]
    WorkRequestNotFound,
    #[error("OCI DevOps work request was ambiguous")]
    WorkRequestAmbiguous,
    #[error("OCI DevOps compartment or project fence mismatch")]
    CompartmentProjectMismatch,
    #[error("OCI DevOps pipeline fence mismatch")]
    PipelineMismatch,
    #[error("OCI DevOps resource id fence mismatch")]
    ResourceIdMismatch,
    #[error(
        "OCI DevOps resource revision fence mismatch for {resource}: expected {expected}, observed {observed}"
    )]
    RevisionMismatch {
        resource: String,
        expected: u64,
        observed: u64,
    },
    #[error("OCI DevOps stage state fence mismatch")]
    StageStateMismatch,
    #[error("OCI DevOps pagination is invalid or exceeded its bound: {0}")]
    Pagination(String),
    #[error("OCI DevOps response contained duplicate resources")]
    DuplicateResource,
    #[error("OCI DevOps response receipt retained forbidden material")]
    ForbiddenPayloadRetention,
    #[error("OCI DevOps evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("OCI DevOps proposal or record is stale or tampered")]
    ProposalTamper,
    #[error("OCI DevOps evidence is stale for this consumer")]
    StaleEvidence,
    #[error("OCI DevOps plugin runtime rejected the definition: {0}")]
    Plugin(PluginError),
}

impl From<PluginError> for OciDevopsError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<model::ModelError> for OciDevopsError {
    fn from(error: model::ModelError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

impl From<transport::OciTransportError> for OciDevopsError {
    fn from(error: transport::OciTransportError) -> Self {
        match error {
            transport::OciTransportError::BlockedEnv => Self::BlockedEnv,
            transport::OciTransportError::Status(status) => Self::UnexpectedStatus { status },
            transport::OciTransportError::Timeout => Self::Transport("timeout".to_owned()),
            other => Self::Transport(other.to_string()),
        }
    }
}

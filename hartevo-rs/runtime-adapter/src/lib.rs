//! Stable, pinned boundary to the OpenInterpreter App Server.
//!
//! Hartevo deliberately speaks the pinned App Server newline-delimited request protocol over
//! child-process stdio. The upstream v2 wire format uses `id`/`method`/`params` envelopes without
//! a JSON-RPC `jsonrpc` member. No local listening port is opened and experimental methods are
//! disabled.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use command_group::{CommandGroup, GroupChild};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, bounded, select};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind};
use thiserror::Error;
use zeroize::Zeroizing;

mod control_plane;
mod plugin;
mod provider;

pub use control_plane::{
    CONTROL_PLANE_CONTRACT_SHA256, ResolvedSecret, RuntimeBudget, RuntimeCapabilities,
    RuntimeCatalog, RuntimeDataBoundary, RuntimeEndpointClass, RuntimeExecutionConfig,
    RuntimeHarnessDescriptor, RuntimeHarnessDiscovery, RuntimeModelDescriptor,
    RuntimeModelDiscovery, RuntimeProviderDescriptor, RuntimeRecoveryAction, RuntimeRecoveryHint,
    RuntimeServiceTier, RuntimeWireApi, SecretBinding, SecretReference, SecretResolver,
    control_plane_contract_digest,
};
pub use plugin::{
    RUNTIME_PLUGIN_MOUNT_SCHEMA, RUNTIME_PLUGIN_SCOPE_SCHEMA, RUNTIME_SERVICE_DEFINITION_SCHEMA,
    RUNTIME_SERVICE_PROVIDER_MANIFEST_SCHEMA, RuntimePluginError, RuntimePluginMount,
    RuntimePluginMountState, RuntimePluginRegistration, RuntimePluginRegistrationKind,
    RuntimePluginRegistrationStopper, RuntimePluginScope, RuntimePluginTeardownReceipt,
    RuntimeServiceCapability, RuntimeServiceDefinition, RuntimeServiceProviderManifest,
};
pub use provider::{
    DurableModelVisibleEvent, DurableModelVisibleEventKind, MissionSessionLog, NativeProbeStatus,
    OpenInterpreterRuntimeProvider, ProviderRestartReceipt, RuntimeProviderError,
    RuntimeProviderPolicy, RuntimeProviderSession, RuntimeProviderStreamEvent,
    RuntimeProviderTeardown,
};

pub const OPENINTERPRETER_COMMIT: &str = "52a31019714294add53cafbc5268e1467b471263";
pub const OPENINTERPRETER_RELEASE: &str = "rust-v0.0.34";
pub const APP_SERVER_SCHEMA_SHA256: &str =
    "f5d28066430a14cb5f7b98545fbff3683734ea6112a1e9944bf7f268afe9e896";
pub const PROTOCOL_VERSION: &str = "hartevo-runtime-protocol/v1";
pub const RUNTIME_LAUNCH_TOKEN_ENV: &str = "HARTEVO_RUNTIME_LAUNCH_TOKEN";

static RUNTIME_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(1);

const CONTRACT_METHODS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/openinterpreter/app-server-v2.methods.json"
));
const ARTIFACT_CATALOG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../third_party/openinterpreter/ARTIFACTS.json"
));

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedRuntimeArtifact {
    pub target: String,
    pub product_support: String,
    pub archive: String,
    pub archive_sha256: String,
    pub entrypoint: String,
    pub entrypoint_sha256: Option<String>,
    pub package_metadata_sha256: Option<String>,
    pub distribution_signature_evidence: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRuntimeArtifact {
    pub target: String,
    pub product_support: String,
    pub release: String,
    pub tag_commit: String,
    pub program: PathBuf,
    pub program_sha256: String,
    pub package_root: PathBuf,
    pub distribution_signature_evidence: String,
}

impl fmt::Debug for VerifiedRuntimeArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRuntimeArtifact")
            .field("target", &self.target)
            .field("product_support", &self.product_support)
            .field("release", &self.release)
            .field("tag_commit", &self.tag_commit)
            .field("program_digest", &path_digest(&self.program))
            .field("program_sha256", &self.program_sha256)
            .field("package_root_digest", &path_digest(&self.package_root))
            .field(
                "distribution_signature_evidence",
                &self.distribution_signature_evidence,
            )
            .finish_non_exhaustive()
    }
}

impl VerifiedRuntimeArtifact {
    pub fn distribution_ready(&self) -> bool {
        self.distribution_signature_evidence == "verified_for_distribution"
    }

    pub fn runtime_command(
        &self,
        current_dir: &Path,
        openinterpreter_home: &Path,
    ) -> Result<RuntimeCommand, AdapterError> {
        let current_dir = current_dir.canonicalize()?;
        let openinterpreter_home = openinterpreter_home.canonicalize()?;
        if !current_dir.is_dir() {
            return Err(AdapterError::WorkingDirectoryNotDirectory);
        }
        if !openinterpreter_home.is_dir() {
            return Err(AdapterError::RuntimeHomeNotDirectory);
        }
        let path_dir = self.package_root.join("codex-path").canonicalize()?;
        if !path_dir.is_dir() {
            return Err(AdapterError::RuntimePackageInvalid);
        }
        let mut search_paths = vec![path_dir];
        if let Some(inherited) = std::env::var_os("PATH") {
            search_paths.extend(std::env::split_paths(&inherited));
        }
        let search_path = std::env::join_paths(search_paths)
            .map_err(|_| AdapterError::RuntimePackageInvalid)?
            .to_string_lossy()
            .into_owned();
        let mut command = RuntimeCommand::new(&self.program, current_dir);
        command.expected_program_sha256 = Some(self.program_sha256.clone());
        command.args = vec!["app-server".to_owned(), "--stdio".to_owned()];
        command.openinterpreter_home = Some(openinterpreter_home.clone());
        command.environment.insert(
            "INTERPRETER_HOME".to_owned(),
            openinterpreter_home.to_string_lossy().into_owned(),
        );
        command.environment.insert("PATH".to_owned(), search_path);
        Ok(command)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeArtifactCatalog {
    schema: String,
    release: String,
    tag_commit: String,
    checksum_manifest_sha256: String,
    package_layout_version: u32,
    package_version: String,
    variant: String,
    artifacts: Vec<RuntimeArtifactRecord>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeArtifactRecord {
    target: String,
    product_support: String,
    archive: String,
    archive_sha256: String,
    entrypoint: String,
    #[serde(default)]
    entrypoint_sha256: Option<String>,
    #[serde(default)]
    package_metadata_sha256: Option<String>,
    distribution_signature_evidence: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimePackageMetadata {
    layout_version: u32,
    version: String,
    target: String,
    variant: String,
    entrypoint: String,
    resources_dir: String,
    path_dir: String,
}

pub fn host_openinterpreter_target() -> Result<&'static str, AdapterError> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("windows", "aarch64") => Ok("aarch64-pc-windows-msvc"),
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-musl"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        _ => Err(AdapterError::RuntimeHostUnsupported),
    }
}

pub fn pinned_runtime_artifact(target: &str) -> Result<PinnedRuntimeArtifact, AdapterError> {
    let catalog = parse_artifact_catalog()?;
    let mut matches = catalog
        .artifacts
        .into_iter()
        .filter(|artifact| artifact.target == target);
    let artifact = matches
        .next()
        .ok_or(AdapterError::RuntimeArtifactUnavailable)?;
    if matches.next().is_some() {
        return Err(AdapterError::RuntimeArtifactCatalogInvalid);
    }
    validate_artifact_record(&artifact)?;
    Ok(PinnedRuntimeArtifact {
        target: artifact.target,
        product_support: artifact.product_support,
        archive: artifact.archive,
        archive_sha256: artifact.archive_sha256,
        entrypoint: artifact.entrypoint,
        entrypoint_sha256: artifact.entrypoint_sha256,
        package_metadata_sha256: artifact.package_metadata_sha256,
        distribution_signature_evidence: artifact.distribution_signature_evidence,
    })
}

pub fn verify_pinned_runtime_artifact(
    program: &Path,
    target: &str,
) -> Result<VerifiedRuntimeArtifact, AdapterError> {
    let catalog = parse_artifact_catalog()?;
    let pinned = pinned_runtime_artifact(target)?;
    let entrypoint_sha256 = pinned
        .entrypoint_sha256
        .as_deref()
        .ok_or(AdapterError::RuntimeArtifactEvidenceMissing)?;
    let package_metadata_sha256 = pinned
        .package_metadata_sha256
        .as_deref()
        .ok_or(AdapterError::RuntimeArtifactEvidenceMissing)?;
    let program = program.canonicalize()?;
    let package_root = program
        .parent()
        .and_then(Path::parent)
        .ok_or(AdapterError::RuntimePackageInvalid)?
        .to_path_buf();
    let expected_program = package_root.join(&pinned.entrypoint).canonicalize()?;
    if program != expected_program {
        return Err(AdapterError::RuntimePackageInvalid);
    }
    let actual_program_sha256 = sha256_file(&program)?;
    if actual_program_sha256 != entrypoint_sha256 {
        return Err(AdapterError::RuntimeProgramDigestMismatch {
            expected_digest: entrypoint_sha256.to_owned(),
            actual_digest: actual_program_sha256,
        });
    }
    validate_runtime_package_metadata(&package_root, &catalog, &pinned, package_metadata_sha256)?;
    Ok(VerifiedRuntimeArtifact {
        target: pinned.target,
        product_support: pinned.product_support,
        release: catalog.release,
        tag_commit: catalog.tag_commit,
        program,
        program_sha256: entrypoint_sha256.to_owned(),
        package_root,
        distribution_signature_evidence: pinned.distribution_signature_evidence,
    })
}

fn parse_artifact_catalog() -> Result<RuntimeArtifactCatalog, AdapterError> {
    let catalog: RuntimeArtifactCatalog = serde_json::from_str(ARTIFACT_CATALOG)?;
    if catalog.schema != "hartevo.openinterpreter-artifacts/v1"
        || catalog.release != OPENINTERPRETER_RELEASE
        || catalog.tag_commit != OPENINTERPRETER_COMMIT
        || !is_sha256(&catalog.checksum_manifest_sha256)
        || catalog.package_layout_version != 1
        || catalog.package_version != "0.0.34"
        || catalog.variant != "open-interpreter"
        || catalog.artifacts.len() != 6
    {
        return Err(AdapterError::RuntimeArtifactCatalogInvalid);
    }
    Ok(catalog)
}

fn validate_artifact_record(artifact: &RuntimeArtifactRecord) -> Result<(), AdapterError> {
    let entrypoint = Path::new(&artifact.entrypoint);
    if artifact.target.is_empty()
        || artifact.product_support.is_empty()
        || artifact.archive.is_empty()
        || !is_sha256(&artifact.archive_sha256)
        || entrypoint.is_absolute()
        || entrypoint
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || artifact.distribution_signature_evidence.is_empty()
        || artifact
            .entrypoint_sha256
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
        || artifact
            .package_metadata_sha256
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
    {
        return Err(AdapterError::RuntimeArtifactCatalogInvalid);
    }
    Ok(())
}

fn validate_runtime_package_metadata(
    package_root: &Path,
    catalog: &RuntimeArtifactCatalog,
    pinned: &PinnedRuntimeArtifact,
    expected_digest: &str,
) -> Result<(), AdapterError> {
    let metadata_path = package_root.join("codex-package.json");
    if sha256_file(&metadata_path)? != expected_digest {
        return Err(AdapterError::RuntimePackageInvalid);
    }
    let metadata: RuntimePackageMetadata = serde_json::from_slice(&std::fs::read(metadata_path)?)?;
    if metadata.layout_version != catalog.package_layout_version
        || metadata.version != catalog.package_version
        || metadata.target != pinned.target
        || metadata.variant != catalog.variant
        || metadata.entrypoint != pinned.entrypoint
        || metadata.resources_dir != "codex-resources"
        || metadata.path_dir != "codex-path"
    {
        return Err(AdapterError::RuntimePackageInvalid);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(u64),
    String(String),
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct JsonRpcRequest {
    pub id: RequestId,
    pub method: String,
    pub params: Value,
}

impl fmt::Debug for JsonRpcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcRequest")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params_digest", &json_digest(&self.params))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct JsonRpcResponse {
    pub id: RequestId,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<Value>,
}

impl fmt::Debug for JsonRpcResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcResponse")
            .field("id", &self.id)
            .field("result_digest", &self.result.as_ref().map(json_digest))
            .field("error_digest", &self.error.as_ref().map(json_digest))
            .finish()
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct JsonRpcNotification {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl fmt::Debug for JsonRpcNotification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcNotification")
            .field("method", &self.method)
            .field("params_digest", &json_digest(&self.params))
            .finish()
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct JsonRpcServerRequest {
    pub id: RequestId,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl fmt::Debug for JsonRpcServerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcServerRequest")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params_digest", &json_digest(&self.params))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMapping {
    pub project_id: String,
    pub mission_id: String,
    pub runtime_generation: u64,
    pub runtime_instance_digest: String,
    pub runtime_model: String,
    pub runtime_model_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_config: Option<RuntimeExecutionConfig>,
    pub runtime_thread_id: String,
    pub runtime_turn_id: Option<String>,
    pub schema_digest: String,
}

impl RuntimeMapping {
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        runtime_generation: u64,
        runtime_instance_digest: impl Into<String>,
        runtime_model: impl Into<String>,
        runtime_model_provider: impl Into<String>,
        runtime_thread_id: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        let value = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            runtime_generation,
            runtime_instance_digest: runtime_instance_digest.into(),
            runtime_model: runtime_model.into(),
            runtime_model_provider: runtime_model_provider.into(),
            runtime_config: None,
            runtime_thread_id: runtime_thread_id.into(),
            runtime_turn_id: None,
            schema_digest: format!("sha256:{APP_SERVER_SCHEMA_SHA256}"),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn new_with_config(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        runtime_generation: u64,
        runtime_instance_digest: impl Into<String>,
        runtime_config: RuntimeExecutionConfig,
        runtime_thread_id: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        let value = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            runtime_generation,
            runtime_instance_digest: runtime_instance_digest.into(),
            runtime_model: runtime_config.model_id.clone(),
            runtime_model_provider: runtime_config.provider_id.clone(),
            runtime_config: Some(runtime_config),
            runtime_thread_id: runtime_thread_id.into(),
            runtime_turn_id: None,
            schema_digest: format!("sha256:{APP_SERVER_SCHEMA_SHA256}"),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        if !is_bounded_identifier(&self.project_id)
            || !is_bounded_identifier(&self.mission_id)
            || self.runtime_generation == 0
            || !is_sha256(&self.runtime_instance_digest)
            || !is_bounded_identifier(&self.runtime_model)
            || !is_bounded_identifier(&self.runtime_model_provider)
            || self.runtime_config.as_ref().is_some_and(|config| {
                config.validate().is_err()
                    || config.model_id != self.runtime_model
                    || config.provider_id != self.runtime_model_provider
            })
            || !is_bounded_identifier(&self.runtime_thread_id)
            || self
                .runtime_turn_id
                .as_ref()
                .is_some_and(|value| !is_bounded_identifier(value))
            || self.schema_digest != format!("sha256:{APP_SERVER_SCHEMA_SHA256}")
        {
            return Err(AdapterError::InvalidRuntimeMapping);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, AdapterError> {
        self.validate()?;
        Ok(digest_hex(&serde_json::to_vec(self)?))
    }
}

impl fmt::Debug for RuntimeMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeMapping")
            .field("project_digest", &digest_bytes(self.project_id.as_bytes()))
            .field("mission_digest", &digest_bytes(self.mission_id.as_bytes()))
            .field("runtime_generation", &self.runtime_generation)
            .field("runtime_instance_digest", &self.runtime_instance_digest)
            .field(
                "runtime_model_digest",
                &digest_bytes(self.runtime_model.as_bytes()),
            )
            .field(
                "runtime_model_provider_digest",
                &digest_bytes(self.runtime_model_provider.as_bytes()),
            )
            .field(
                "runtime_config_digest",
                &self
                    .runtime_config
                    .as_ref()
                    .and_then(|config| config.digest().ok()),
            )
            .field(
                "runtime_thread_digest",
                &digest_bytes(self.runtime_thread_id.as_bytes()),
            )
            .field(
                "runtime_turn_digest",
                &self
                    .runtime_turn_id
                    .as_ref()
                    .map(|value| digest_bytes(value.as_bytes())),
            )
            .field("schema_digest", &self.schema_digest)
            .finish()
    }
}

struct RuntimeThreadBinding {
    thread_id: String,
    model: String,
    model_provider: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeEventKind {
    ThreadStarted,
    TurnStarted,
    ItemStarted,
    AgentMessageDelta,
    ItemCompleted,
    TurnCompleted,
    LocalApprovalRequested,
    Unknown(String),
}

impl RuntimeEventKind {
    pub fn from_method(method: &str) -> Self {
        match method {
            "thread/started" => Self::ThreadStarted,
            "turn/started" => Self::TurnStarted,
            "item/started" => Self::ItemStarted,
            "item/agentMessage/delta" => Self::AgentMessageDelta,
            "item/completed" => Self::ItemCompleted,
            "turn/completed" => Self::TurnCompleted,
            "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                Self::LocalApprovalRequested
            }
            other => Self::Unknown(other.to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTurnCompletionStatus {
    Completed,
    Interrupted,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLocalApprovalKind {
    CommandExecution,
    FileChange,
}

#[derive(Clone, PartialEq)]
pub struct RuntimeLocalApprovalRequest {
    pub request_id: RequestId,
    pub kind: RuntimeLocalApprovalKind,
    pub request_digest: String,
}

impl fmt::Debug for RuntimeLocalApprovalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeLocalApprovalRequest")
            .field(
                "request_id_digest",
                &digest_hex(&serde_json::to_vec(&self.request_id).unwrap_or_default()),
            )
            .field("kind", &self.kind)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MappedTurnEventKind {
    TurnStarted,
    ItemStarted,
    AgentMessageDelta,
    ItemCompleted,
    TurnCompleted(RuntimeTurnCompletionStatus),
    LocalApprovalRequested(RuntimeLocalApprovalKind),
    Diagnostic,
    Other,
}

#[derive(Clone, PartialEq)]
pub struct RuntimeAgentMessage {
    text: Zeroizing<String>,
    pub item_id_digest: String,
    pub content_digest: String,
    pub byte_count: u64,
}

impl RuntimeAgentMessage {
    fn new(item_id: &str, text: &str) -> Result<Option<Self>, AdapterError> {
        if text.is_empty() {
            return Ok(None);
        }
        if text.len() > MAX_AGENT_MESSAGE_BYTES {
            return Err(AdapterError::AgentMessageTooLarge {
                byte_count: text.len(),
                maximum: MAX_AGENT_MESSAGE_BYTES,
            });
        }
        Ok(Some(Self {
            text: Zeroizing::new(text.to_owned()),
            item_id_digest: digest_hex(item_id.as_bytes()),
            content_digest: digest_hex(text.as_bytes()),
            byte_count: u64::try_from(text.len()).map_err(|_| {
                AdapterError::AgentMessageTooLarge {
                    byte_count: text.len(),
                    maximum: MAX_AGENT_MESSAGE_BYTES,
                }
            })?,
        }))
    }

    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }
}

impl fmt::Debug for RuntimeAgentMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeAgentMessage")
            .field("item_id_digest", &self.item_id_digest)
            .field("content_digest", &self.content_digest)
            .field("byte_count", &self.byte_count)
            .finish_non_exhaustive()
    }
}

/// One content-bearing assistant text increment from the pinned App Server v2
/// protocol. The text is deliberately transient and zeroized; only its
/// digests may enter content-free evidence and diagnostics.
#[derive(Clone, PartialEq)]
pub struct RuntimeAgentMessageDelta {
    text: Zeroizing<String>,
    pub item_id_digest: String,
    pub content_digest: String,
    pub byte_count: u64,
}

impl RuntimeAgentMessageDelta {
    fn new(item_id: &str, text: &str) -> Result<Self, AdapterError> {
        if item_id.is_empty() || text.is_empty() {
            return Err(AdapterError::InvalidTurnNotification {
                notification_digest: digest_hex(format!("{item_id}:{}", text.len()).as_bytes()),
            });
        }
        if text.len() > MAX_AGENT_MESSAGE_BYTES {
            return Err(AdapterError::AgentMessageTooLarge {
                byte_count: text.len(),
                maximum: MAX_AGENT_MESSAGE_BYTES,
            });
        }
        Ok(Self {
            text: Zeroizing::new(text.to_owned()),
            item_id_digest: digest_hex(item_id.as_bytes()),
            content_digest: digest_hex(text.as_bytes()),
            byte_count: u64::try_from(text.len()).map_err(|_| {
                AdapterError::AgentMessageTooLarge {
                    byte_count: text.len(),
                    maximum: MAX_AGENT_MESSAGE_BYTES,
                }
            })?,
        })
    }

    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }
}

impl fmt::Debug for RuntimeAgentMessageDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeAgentMessageDelta")
            .field("item_id_digest", &self.item_id_digest)
            .field("content_digest", &self.content_digest)
            .field("byte_count", &self.byte_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq)]
pub struct MappedTurnEvent {
    pub kind: MappedTurnEventKind,
    pub event_digest: String,
    pub approval_request: Option<RuntimeLocalApprovalRequest>,
    pub recovery_hint: Option<RuntimeRecoveryHint>,
    /// Incremental user-facing assistant text. It is transient, zeroized on
    /// drop, and omitted from content-free evidence.
    pub agent_message_delta: Option<RuntimeAgentMessageDelta>,
    /// Completed user-facing agent output only. It is transient, zeroized on
    /// drop, and omitted from persistent Runtime evidence.
    pub agent_message: Option<RuntimeAgentMessage>,
}

impl fmt::Debug for MappedTurnEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MappedTurnEvent")
            .field("kind", &self.kind)
            .field("event_digest", &self.event_digest)
            .field("approval_request", &self.approval_request)
            .field("recovery_hint", &self.recovery_hint)
            .field("agent_message_delta", &self.agent_message_delta)
            .field("agent_message", &self.agent_message)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct RuntimeTurnDispatch {
    pub mapping: RuntimeMapping,
    pub request_digest: String,
    pub response_digest: String,
    pub elapsed: Duration,
}

impl fmt::Debug for RuntimeTurnDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTurnDispatch")
            .field("mapping", &self.mapping)
            .field("request_digest", &self.request_digest)
            .field("response_digest", &self.response_digest)
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

pub const RUNTIME_RESULT_PACKET_SCHEMA: &str = "hartevo.runtime-result-packet/v1";

/// The only authority a completed runtime item can carry across the adapter boundary.
///
/// This is local execution evidence. It is deliberately not a provider receipt, an external
/// effect receipt, a business Outcome, or Release evidence. The packet is separate from
/// `RuntimeMapping`, so business content is never inserted into Runtime identity or process
/// state merely because it is eligible for adoption.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeResultAuthority {
    LocalExecutionEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeResultKind {
    AgentMessage,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeResultPacket {
    pub schema: String,
    pub authority: RuntimeResultAuthority,
    pub result_kind: RuntimeResultKind,
    pub project_id: String,
    pub mission_id: String,
    pub runtime_generation: u64,
    pub runtime_instance_digest: String,
    pub runtime_commit: String,
    pub runtime_release: String,
    pub mapping_digest: String,
    pub runtime_thread_id_digest: String,
    pub runtime_turn_id_digest: String,
    pub app_server_schema_digest: String,
    pub runtime_config_digest: String,
    pub catalog_digest: String,
    pub source_item_id_digest: String,
    pub source_event_digest: String,
    pub content_digest: String,
    pub content_byte_count: u64,
    pub content: String,
}

impl RuntimeResultPacket {
    /// Convert exactly one bounded completed agent item into an adoptable packet.
    ///
    /// Non-content events and completed items without a supported agent message are not
    /// errors; they simply are not result packets.
    pub fn from_mapped_event(
        mapping: &RuntimeMapping,
        event: &MappedTurnEvent,
    ) -> Result<Option<Self>, AdapterError> {
        if !matches!(&event.kind, MappedTurnEventKind::ItemCompleted) {
            return Ok(None);
        }
        let Some(message) = event.agent_message.as_ref() else {
            return Ok(None);
        };
        mapping.validate()?;
        let config = mapping
            .runtime_config
            .as_ref()
            .ok_or(AdapterError::InvalidRuntimeResultPacket)?;
        config.validate()?;
        let turn_id = mapping
            .runtime_turn_id
            .as_deref()
            .ok_or(AdapterError::InvalidRuntimeResultPacket)?;
        let packet = Self {
            schema: RUNTIME_RESULT_PACKET_SCHEMA.to_owned(),
            authority: RuntimeResultAuthority::LocalExecutionEvidence,
            result_kind: RuntimeResultKind::AgentMessage,
            project_id: mapping.project_id.clone(),
            mission_id: mapping.mission_id.clone(),
            runtime_generation: mapping.runtime_generation,
            runtime_instance_digest: mapping.runtime_instance_digest.clone(),
            runtime_commit: OPENINTERPRETER_COMMIT.to_owned(),
            runtime_release: OPENINTERPRETER_RELEASE.to_owned(),
            mapping_digest: mapping.digest()?,
            runtime_thread_id_digest: digest_hex(mapping.runtime_thread_id.as_bytes()),
            runtime_turn_id_digest: digest_hex(turn_id.as_bytes()),
            app_server_schema_digest: mapping.schema_digest.clone(),
            runtime_config_digest: config.digest()?,
            catalog_digest: config.catalog_digest.clone(),
            source_item_id_digest: message.item_id_digest.clone(),
            source_event_digest: event.event_digest.clone(),
            content_digest: message.content_digest.clone(),
            content_byte_count: message.byte_count,
            content: message.as_str().to_owned(),
        };
        packet.validate()?;
        Ok(Some(packet))
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        let content_byte_count = u64::try_from(self.content.len())
            .map_err(|_| AdapterError::InvalidRuntimeResultPacket)?;
        if self.schema != RUNTIME_RESULT_PACKET_SCHEMA
            || self.authority != RuntimeResultAuthority::LocalExecutionEvidence
            || self.result_kind != RuntimeResultKind::AgentMessage
            || !is_bounded_identifier(&self.project_id)
            || !is_bounded_identifier(&self.mission_id)
            || self.runtime_generation == 0
            || !is_sha256(&self.runtime_instance_digest)
            || self.runtime_commit != OPENINTERPRETER_COMMIT
            || self.runtime_release != OPENINTERPRETER_RELEASE
            || !is_sha256(&self.mapping_digest)
            || !is_sha256(&self.runtime_thread_id_digest)
            || !is_sha256(&self.runtime_turn_id_digest)
            || self.app_server_schema_digest != format!("sha256:{APP_SERVER_SCHEMA_SHA256}")
            || !is_sha256(&self.runtime_config_digest)
            || !is_sha256(&self.catalog_digest)
            || !is_sha256(&self.source_item_id_digest)
            || !is_sha256(&self.source_event_digest)
            || !is_sha256(&self.content_digest)
            || self.content.is_empty()
            || self.content.len() > MAX_AGENT_MESSAGE_BYTES
            || self.content_byte_count != content_byte_count
            || self.content_digest != digest_hex(self.content.as_bytes())
        {
            return Err(AdapterError::InvalidRuntimeResultPacket);
        }
        Ok(())
    }
}

impl fmt::Debug for RuntimeResultPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeResultPacket")
            .field("schema", &self.schema)
            .field("authority", &self.authority)
            .field("result_kind", &self.result_kind)
            .field("project_digest", &digest_hex(self.project_id.as_bytes()))
            .field("mission_digest", &digest_hex(self.mission_id.as_bytes()))
            .field("runtime_generation", &self.runtime_generation)
            .field("runtime_instance_digest", &self.runtime_instance_digest)
            .field("runtime_commit", &self.runtime_commit)
            .field("runtime_release", &self.runtime_release)
            .field("mapping_digest", &self.mapping_digest)
            .field("runtime_thread_id_digest", &self.runtime_thread_id_digest)
            .field("runtime_turn_id_digest", &self.runtime_turn_id_digest)
            .field("app_server_schema_digest", &self.app_server_schema_digest)
            .field("runtime_config_digest", &self.runtime_config_digest)
            .field("catalog_digest", &self.catalog_digest)
            .field("source_item_id_digest", &self.source_item_id_digest)
            .field("source_event_digest", &self.source_event_digest)
            .field("content_digest", &self.content_digest)
            .field("content_byte_count", &self.content_byte_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProtocolWriteReceipt {
    pub request_digest: String,
    pub response_digest: String,
    pub elapsed: Duration,
}

#[derive(Debug)]
pub struct AppServerContract;

impl AppServerContract {
    pub fn initialize(id: RequestId) -> JsonRpcRequest {
        request(
            id,
            "initialize",
            json!({
                "clientInfo": {
                    "name": "hartevo-desktop",
                    "title": "Hartevo Desktop",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": {
                    "experimentalApi": false
                }
            }),
        )
    }

    pub fn thread_start(
        id: RequestId,
        workspace_root: &Path,
        model: Option<&str>,
    ) -> JsonRpcRequest {
        request(
            id,
            "thread/start",
            json!({
                "cwd": workspace_root,
                "model": model,
                "approvalPolicy": "on-request",
                "sandbox": "workspace-write",
                "baseInstructions": "Work only inside the current Hartevo project scope. Business effects must be proposed through the Hartevo capability gateway."
            }),
        )
    }

    pub fn thread_resume(id: RequestId, thread_id: &str, workspace_root: &Path) -> JsonRpcRequest {
        request(
            id,
            "thread/resume",
            json!({
                "threadId": thread_id,
                "cwd": workspace_root
            }),
        )
    }

    pub fn turn_start(id: RequestId, thread_id: &str, prompt: &str) -> JsonRpcRequest {
        Self::turn_start_with_client_message_id(id, thread_id, None, prompt)
    }

    pub fn turn_start_with_client_message_id(
        id: RequestId,
        thread_id: &str,
        client_user_message_id: Option<&str>,
        prompt: &str,
    ) -> JsonRpcRequest {
        request(
            id,
            "turn/start",
            json!({
                "threadId": thread_id,
                "clientUserMessageId": client_user_message_id,
                "input": [{
                    "type": "text",
                    "text": prompt
                }]
            }),
        )
    }

    pub fn turn_steer(
        id: RequestId,
        thread_id: &str,
        expected_turn_id: &str,
        client_user_message_id: &str,
        prompt: &str,
    ) -> JsonRpcRequest {
        request(
            id,
            "turn/steer",
            json!({
                "threadId": thread_id,
                "expectedTurnId": expected_turn_id,
                "clientUserMessageId": client_user_message_id,
                "input": [{
                    "type": "text",
                    "text": prompt
                }]
            }),
        )
    }

    pub fn turn_interrupt(id: RequestId, thread_id: &str, turn_id: &str) -> JsonRpcRequest {
        request(
            id,
            "turn/interrupt",
            json!({
                "threadId": thread_id,
                "turnId": turn_id
            }),
        )
    }

    pub fn provider_list(id: RequestId, include_unconfigured: bool) -> JsonRpcRequest {
        request(
            id,
            "interpreter/provider/list",
            json!({
                "includeUnconfigured": include_unconfigured
            }),
        )
    }

    pub fn provider_set(id: RequestId, provider_id: &str) -> JsonRpcRequest {
        request(
            id,
            "interpreter/provider/set",
            json!({
                "providerId": provider_id,
                "profile": null
            }),
        )
    }

    pub fn model_list(
        id: RequestId,
        model_provider: Option<&str>,
        include_hidden: bool,
    ) -> JsonRpcRequest {
        request(
            id,
            "interpreter/model/list",
            json!({
                "modelProvider": model_provider,
                "includeHidden": include_hidden
            }),
        )
    }

    pub fn model_set(id: RequestId, model: &str, reasoning_effort: Option<&str>) -> JsonRpcRequest {
        request(
            id,
            "interpreter/model/set",
            json!({
                "model": model,
                "reasoningEffort": reasoning_effort,
                "profile": null
            }),
        )
    }

    pub fn harness_list(id: RequestId, provider_id: &str, model: Option<&str>) -> JsonRpcRequest {
        request(
            id,
            "interpreter/harness/list",
            json!({
                "providerId": provider_id,
                "model": model
            }),
        )
    }

    pub fn harness_set(id: RequestId, harness: Option<&str>) -> JsonRpcRequest {
        request(
            id,
            "interpreter/harness/set",
            json!({
                "harness": harness,
                "profile": null
            }),
        )
    }

    pub fn local_approval_response(id: RequestId, approved: bool) -> JsonRpcResponse {
        JsonRpcResponse {
            id,
            result: Some(json!({
                "decision": if approved { "accept" } else { "decline" }
            })),
            error: None,
        }
    }

    pub fn contract_subset_digest() -> String {
        hex::encode(Sha256::digest(CONTRACT_METHODS.as_bytes()))
    }

    pub fn stable_methods() -> Result<Vec<String>, AdapterError> {
        let document: Value = serde_json::from_str(CONTRACT_METHODS)?;
        document["stableMethods"]
            .as_array()
            .ok_or(AdapterError::InvalidContract)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or(AdapterError::InvalidContract)
            })
            .collect()
    }

    pub fn stable_server_requests() -> Result<Vec<String>, AdapterError> {
        let document: Value = serde_json::from_str(CONTRACT_METHODS)?;
        document["stableServerRequests"]
            .as_array()
            .ok_or(AdapterError::InvalidContract)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or(AdapterError::InvalidContract)
            })
            .collect()
    }
}

fn request(id: RequestId, method: &str, params: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        id,
        method: method.to_owned(),
        params,
    }
}

const DEFAULT_STDOUT_CAPACITY: usize = 32;
const DEFAULT_STDERR_CAPACITY: usize = 16;
const DEFAULT_DEFERRED_CAPACITY: usize = 128;
const DEFAULT_MAX_LINE_BYTES: usize = 1024 * 1024;
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const MAX_CHANNEL_CAPACITY: usize = 4096;
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENVIRONMENT_VARIABLES: usize = 128;
const MAX_ARGUMENTS: usize = 512;
const MAX_OS_VALUE_BYTES: usize = 32 * 1024;
const MAX_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const MAX_AGENT_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct RuntimeCommand {
    pub program: PathBuf,
    /// Optional release-manifest pin. Real OpenInterpreter commands must set this; fake test
    /// runtimes may leave it unset while still binding their observed digest into the intent.
    pub expected_program_sha256: Option<String>,
    pub args: Vec<String>,
    pub current_dir: PathBuf,
    pub environment: BTreeMap<String, String>,
    /// Opaque credential bindings resolved only for a child-process spawn.  The secret material
    /// itself is never part of this command or its digest.
    pub secret_bindings: Vec<SecretBinding>,
    /// Exact isolated state root expected back from OpenInterpreter `initialize`.
    ///
    /// When set, `INTERPRETER_HOME` must resolve to this already-created directory and the
    /// runtime must echo the same canonical path as `codexHome`. This prevents silently reading
    /// a user's global `~/.openinterpreter` state.
    pub openinterpreter_home: Option<PathBuf>,
    pub stdout_capacity: usize,
    pub stderr_capacity: usize,
    pub deferred_capacity: usize,
    pub max_line_bytes: usize,
    pub shutdown_grace: Duration,
}

impl RuntimeCommand {
    pub fn new(program: impl Into<PathBuf>, current_dir: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            expected_program_sha256: None,
            args: Vec::new(),
            current_dir: current_dir.into(),
            environment: BTreeMap::new(),
            secret_bindings: Vec::new(),
            openinterpreter_home: None,
            stdout_capacity: DEFAULT_STDOUT_CAPACITY,
            stderr_capacity: DEFAULT_STDERR_CAPACITY,
            deferred_capacity: DEFAULT_DEFERRED_CAPACITY,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }

    pub fn intent_digest(&self) -> Result<String, AdapterError> {
        let validated = validate_runtime_command(self)?;
        Ok(self.intent_digest_with(&validated))
    }

    pub fn add_secret_binding(
        &mut self,
        environment_key: impl Into<String>,
        reference: SecretReference,
    ) -> Result<(), AdapterError> {
        let binding = SecretBinding::new(environment_key, reference)?;
        let mut candidate = self.secret_bindings.clone();
        candidate.push(binding);
        control_plane::validate_secret_bindings(&candidate)?;
        self.secret_bindings = candidate;
        Ok(())
    }

    pub fn program_sha256(&self) -> Result<String, AdapterError> {
        Ok(validate_runtime_command(self)?.program_sha256)
    }

    fn intent_digest_with(&self, validated: &ValidatedRuntimeCommand) -> String {
        let mut hasher = Sha256::new();
        hash_length_prefixed(&mut hasher, validated.program.to_string_lossy().as_bytes());
        hash_length_prefixed(&mut hasher, validated.program_sha256.as_bytes());
        hash_length_prefixed(
            &mut hasher,
            if self.expected_program_sha256.is_some() {
                b"program-digest-pinned"
            } else {
                b"program-digest-observed"
            },
        );
        hash_length_prefixed(
            &mut hasher,
            validated.current_dir.to_string_lossy().as_bytes(),
        );
        for argument in &self.args {
            hash_length_prefixed(&mut hasher, argument.as_bytes());
        }
        for (key, value) in &self.environment {
            hash_length_prefixed(&mut hasher, key.as_bytes());
            hash_length_prefixed(&mut hasher, value.as_bytes());
        }
        for binding in &self.secret_bindings {
            hash_length_prefixed(&mut hasher, binding.environment_key.as_bytes());
            hash_length_prefixed(
                &mut hasher,
                binding
                    .reference
                    .digest()
                    .unwrap_or_else(|_| "invalid".to_owned())
                    .as_bytes(),
            );
        }
        match &validated.openinterpreter_home {
            Some(home) => {
                hash_length_prefixed(&mut hasher, b"openinterpreter-home");
                hash_length_prefixed(&mut hasher, home.to_string_lossy().as_bytes());
            }
            None => hash_length_prefixed(&mut hasher, b"no-openinterpreter-home"),
        }
        hash_length_prefixed(&mut hasher, &self.stdout_capacity.to_le_bytes());
        hash_length_prefixed(&mut hasher, &self.stderr_capacity.to_le_bytes());
        hash_length_prefixed(&mut hasher, &self.deferred_capacity.to_le_bytes());
        hash_length_prefixed(&mut hasher, &self.max_line_bytes.to_le_bytes());
        hash_length_prefixed(&mut hasher, &self.shutdown_grace.as_nanos().to_le_bytes());
        hex::encode(hasher.finalize())
    }
}

impl fmt::Debug for RuntimeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeCommand")
            .field("program_digest", &path_digest(&self.program))
            .field(
                "expected_program_sha256",
                &self.expected_program_sha256.as_ref().map(|_| "configured"),
            )
            .field("argument_count", &self.args.len())
            .field("current_dir_digest", &path_digest(&self.current_dir))
            .field(
                "environment_keys",
                &self.environment.keys().collect::<Vec<_>>(),
            )
            .field("secret_binding_count", &self.secret_bindings.len())
            .field(
                "secret_binding_keys",
                &self
                    .secret_bindings
                    .iter()
                    .map(|binding| binding.environment_key.as_str())
                    .collect::<Vec<_>>(),
            )
            .field(
                "openinterpreter_home_digest",
                &self
                    .openinterpreter_home
                    .as_ref()
                    .map(|path| path_digest(path)),
            )
            .field("stdout_capacity", &self.stdout_capacity)
            .field("stderr_capacity", &self.stderr_capacity)
            .field("deferred_capacity", &self.deferred_capacity)
            .field("max_line_bytes", &self.max_line_bytes)
            .field("shutdown_grace", &self.shutdown_grace)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDiagnostic {
    pub stream: RuntimeStream,
    pub category: String,
    pub byte_count: u64,
    pub digest: String,
    pub truncated: bool,
}

#[derive(Clone, PartialEq)]
pub enum RuntimeEvent {
    CorrelatedResponse {
        id: RequestId,
        method: String,
        request_digest: String,
        response: JsonRpcResponse,
        elapsed: Duration,
    },
    ServerRequest {
        kind: RuntimeEventKind,
        request: JsonRpcServerRequest,
    },
    Notification {
        kind: RuntimeEventKind,
        notification: JsonRpcNotification,
    },
    Diagnostic(RuntimeDiagnostic),
    ProtocolViolation(RuntimeDiagnostic),
    StdoutClosed,
    StderrClosed,
}

impl fmt::Debug for RuntimeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorrelatedResponse {
                id,
                method,
                request_digest,
                response,
                elapsed,
            } => formatter
                .debug_struct("CorrelatedResponse")
                .field("id", id)
                .field("method", method)
                .field("request_digest", request_digest)
                .field("response", response)
                .field("elapsed", elapsed)
                .finish(),
            Self::ServerRequest { kind, request } => formatter
                .debug_struct("ServerRequest")
                .field("kind", kind)
                .field("request", request)
                .finish(),
            Self::Notification { kind, notification } => formatter
                .debug_struct("Notification")
                .field("kind", kind)
                .field("notification", notification)
                .finish(),
            Self::Diagnostic(diagnostic) => formatter
                .debug_tuple("Diagnostic")
                .field(diagnostic)
                .finish(),
            Self::ProtocolViolation(diagnostic) => formatter
                .debug_tuple("ProtocolViolation")
                .field(diagnostic)
                .finish(),
            Self::StdoutClosed => formatter.write_str("StdoutClosed"),
            Self::StderrClosed => formatter.write_str("StderrClosed"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHealth {
    pub process_id: u32,
    pub runtime_instance_digest: String,
    pub round_trip: Duration,
    pub protocol_version: &'static str,
    pub schema_digest: String,
    pub runtime_home_digest: Option<String>,
    pub program_sha256: String,
    pub program_integrity_pinned: bool,
}

impl RuntimeHealth {
    pub fn evidence_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hash_length_prefixed(&mut hasher, &self.process_id.to_le_bytes());
        hash_length_prefixed(&mut hasher, self.runtime_instance_digest.as_bytes());
        hash_length_prefixed(&mut hasher, &self.round_trip.as_nanos().to_le_bytes());
        hash_length_prefixed(&mut hasher, self.protocol_version.as_bytes());
        hash_length_prefixed(&mut hasher, self.schema_digest.as_bytes());
        if let Some(runtime_home_digest) = &self.runtime_home_digest {
            hash_length_prefixed(&mut hasher, runtime_home_digest.as_bytes());
        }
        hash_length_prefixed(&mut hasher, self.program_sha256.as_bytes());
        hash_length_prefixed(
            &mut hasher,
            if self.program_integrity_pinned {
                b"program-integrity-pinned"
            } else {
                b"program-integrity-observed"
            },
        );
        hex::encode(hasher.finalize())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedRuntimeProcessIdentity {
    pub process_id: u32,
    pub started_at_epoch_seconds: u64,
    pub executable_path_digest: String,
    pub runtime_instance_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessCleanupDisposition {
    Terminated,
    AlreadyExited,
    InspectionBlocked,
    TerminationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProcessCleanupReport {
    pub disposition: ProcessCleanupDisposition,
    pub matched_process_count: usize,
    pub signalled_process_count: usize,
    pub remaining_process_count: usize,
    pub evidence_digest: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeProcessCleanupTarget {
    launch_token: String,
    launch_executable_path: PathBuf,
    launch_executable_path_digest: String,
    program_sha256: String,
    pub identity: Option<ObservedRuntimeProcessIdentity>,
}

impl fmt::Debug for RuntimeProcessCleanupTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProcessCleanupTarget")
            .field(
                "launch_token_digest",
                &digest_bytes(self.launch_token.as_bytes()),
            )
            .field(
                "launch_executable_path_digest",
                &self.launch_executable_path_digest,
            )
            .field("program_sha256", &self.program_sha256)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl RuntimeProcessCleanupTarget {
    pub fn new(
        launch_token: String,
        launch_executable_path: PathBuf,
        launch_executable_path_digest: String,
        program_sha256: String,
        identity: Option<ObservedRuntimeProcessIdentity>,
    ) -> Result<Self, AdapterError> {
        validate_runtime_launch_token(&launch_token)?;
        if !launch_executable_path.is_absolute()
            || !is_sha256(&launch_executable_path_digest)
            || !is_sha256(&program_sha256)
            || digest_hex(launch_executable_path.to_string_lossy().as_bytes())
                != launch_executable_path_digest
            || launch_executable_path
                .parent()
                .and_then(Path::file_name)
                .and_then(|value| value.to_str())
                != Some(digest_hex(launch_token.as_bytes()).as_str())
            || identity.as_ref().is_some_and(|identity| {
                identity.process_id == 0
                    || identity.started_at_epoch_seconds == 0
                    || !is_sha256(&identity.executable_path_digest)
                    || !is_sha256(&identity.runtime_instance_digest)
            })
        {
            return Err(AdapterError::RuntimeProcessIdentityInvalid);
        }
        Ok(Self {
            launch_token,
            launch_executable_path,
            launch_executable_path_digest,
            program_sha256,
            identity,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeLaunchSpec {
    launch_token: String,
    executable_path: PathBuf,
    executable_path_digest: String,
    program_sha256: String,
}

impl fmt::Debug for RuntimeLaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeLaunchSpec")
            .field(
                "launch_token_digest",
                &digest_bytes(self.launch_token.as_bytes()),
            )
            .field("executable_path_digest", &self.executable_path_digest)
            .field("program_sha256", &self.program_sha256)
            .finish_non_exhaustive()
    }
}

impl RuntimeLaunchSpec {
    pub fn launch_token(&self) -> &str {
        &self.launch_token
    }

    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    pub fn executable_path_digest(&self) -> &str {
        &self.executable_path_digest
    }

    pub fn program_sha256(&self) -> &str {
        &self.program_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    pub forced: bool,
    pub success: bool,
    pub exit_code: Option<i32>,
}

#[derive(Debug)]
struct PendingRequest {
    method: String,
    request_digest: String,
    sent_at: Instant,
}

struct BoundedFrame {
    bytes: Vec<u8>,
    byte_count: u64,
    digest: String,
    truncated: bool,
}

enum ReaderMessage {
    Frame(BoundedFrame),
    Failure { category: String, digest: String },
    Closed,
}

pub struct StdioRuntime {
    child: Option<GroupChild>,
    stdin: Option<ChildStdin>,
    stdout_rx: Option<Receiver<ReaderMessage>>,
    stderr_rx: Option<Receiver<ReaderMessage>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    next_id: u64,
    pending: HashMap<RequestId, PendingRequest>,
    server_requests: HashSet<RequestId>,
    deferred: VecDeque<RuntimeEvent>,
    deferred_capacity: usize,
    max_line_bytes: usize,
    shutdown_grace: Duration,
    config_digest: String,
    instance_digest: String,
    process_identity: ObservedRuntimeProcessIdentity,
    launch_token: Zeroizing<String>,
    launch_executable_path: PathBuf,
    launch_executable_path_digest: String,
    expected_runtime_home: Option<PathBuf>,
    program_sha256: String,
    program_integrity_pinned: bool,
    last_control_plane_provider_id: Option<String>,
    poisoned: bool,
}

impl fmt::Debug for StdioRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdioRuntime")
            .field("process_id", &self.child.as_ref().map(GroupChild::id))
            .field("pending_request_count", &self.pending.len())
            .field("server_request_count", &self.server_requests.len())
            .field("deferred_event_count", &self.deferred.len())
            .field("config_digest", &self.config_digest)
            .field("instance_digest", &self.instance_digest)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl StdioRuntime {
    pub fn spawn(config: &RuntimeCommand) -> Result<Self, AdapterError> {
        let launch_token = generate_runtime_launch_token(config)?;
        let launch = prepare_runtime_launch(config, &launch_token)?;
        Self::spawn_prepared(config, &launch)
    }

    /// Resolve opaque credentials at the last possible boundary and inject them only into the
    /// isolated child environment. The resolver and material are not retained by the runtime.
    pub fn spawn_with_secret_resolver(
        config: &RuntimeCommand,
        resolver: &dyn SecretResolver,
    ) -> Result<Self, AdapterError> {
        let launch_token = generate_runtime_launch_token(config)?;
        let launch = prepare_runtime_launch(config, &launch_token)?;
        Self::spawn_prepared_with_secret_resolver(config, &launch, resolver)
    }

    pub fn spawn_with_launch_token(
        config: &RuntimeCommand,
        launch_token: &str,
    ) -> Result<Self, AdapterError> {
        let launch = prepare_runtime_launch(config, launch_token)?;
        Self::spawn_prepared(config, &launch)
    }

    pub fn spawn_with_launch_token_and_secret_resolver(
        config: &RuntimeCommand,
        launch_token: &str,
        resolver: &dyn SecretResolver,
    ) -> Result<Self, AdapterError> {
        let launch = prepare_runtime_launch(config, launch_token)?;
        Self::spawn_prepared_with_secret_resolver(config, &launch, resolver)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the spawn boundary keeps executable identity, environment, pipe readers, process-group ownership, and cleanup rollback in one auditable sequence"
    )]
    pub fn spawn_prepared(
        config: &RuntimeCommand,
        launch: &RuntimeLaunchSpec,
    ) -> Result<Self, AdapterError> {
        if !config.secret_bindings.is_empty() {
            return Err(AdapterError::SecretResolverRequired);
        }
        Self::spawn_prepared_with_resolved_secrets(config, launch, &[])
    }

    pub fn spawn_prepared_with_secret_resolver(
        config: &RuntimeCommand,
        launch: &RuntimeLaunchSpec,
        resolver: &dyn SecretResolver,
    ) -> Result<Self, AdapterError> {
        let resolved_bindings =
            control_plane::resolve_secret_bindings(&config.secret_bindings, resolver)?;
        Self::spawn_prepared_with_resolved_secrets(config, launch, &resolved_bindings)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the spawn boundary keeps executable identity, environment, pipe readers, process-group ownership, and cleanup rollback in one auditable sequence"
    )]
    fn spawn_prepared_with_resolved_secrets(
        config: &RuntimeCommand,
        launch: &RuntimeLaunchSpec,
        resolved_secrets: &[control_plane::ResolvedSecretBinding],
    ) -> Result<Self, AdapterError> {
        if &prepare_runtime_launch(config, launch.launch_token())? != launch {
            return Err(AdapterError::RuntimeProcessIdentityInvalid);
        }
        let validated = validate_runtime_command(config)?;
        let isolated_launch = config.expected_program_sha256.is_some();
        let mut launch_artifact = isolated_launch
            .then(|| materialize_runtime_launch(&validated, launch))
            .transpose()?;
        let config_digest = config.intent_digest_with(&validated);
        let launch_program = if isolated_launch {
            launch.executable_path()
        } else {
            validated.program.as_path()
        };
        let mut command = Command::new(launch_program);
        command
            .args(&config.args)
            .current_dir(&validated.current_dir)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        apply_minimal_environment(&mut command, &config.environment);
        for binding in resolved_secrets {
            command.env(&binding.environment_key, binding.secret.as_str());
        }
        command.env(RUNTIME_LAUNCH_TOKEN_ENV, launch.launch_token());

        let mut child = spawn_process_group(&mut command)?;
        if let Some(launch_artifact) = &mut launch_artifact {
            launch_artifact.preserve = true;
        }
        let post_spawn_digest = match sha256_file(launch_program) {
            Ok(digest) => digest,
            Err(error) => {
                terminate_group_best_effort(&mut child);
                return Err(error);
            }
        };
        if post_spawn_digest != validated.program_sha256 {
            terminate_group_best_effort(&mut child);
            return Err(AdapterError::RuntimeProgramChangedDuringSpawn);
        }
        let instance_digest = runtime_instance_digest(child.id(), &config_digest)?;
        let process_identity = match observe_runtime_process_identity(child.id(), &instance_digest)
        {
            Ok(identity) => identity,
            Err(error) => {
                terminate_group_best_effort(&mut child);
                return Err(error);
            }
        };
        if isolated_launch
            && process_identity.executable_path_digest != launch.executable_path_digest
        {
            terminate_group_best_effort(&mut child);
            return Err(AdapterError::RuntimeProcessIdentityInvalid);
        }
        let stdin = child.inner().stdin.take();
        let stdout = child.inner().stdout.take();
        let stderr = child.inner().stderr.take();
        let Some(stdin) = stdin else {
            terminate_group_best_effort(&mut child);
            return Err(AdapterError::MissingStdin);
        };
        let Some(stdout) = stdout else {
            terminate_group_best_effort(&mut child);
            return Err(AdapterError::MissingStdout);
        };
        let Some(stderr) = stderr else {
            terminate_group_best_effort(&mut child);
            return Err(AdapterError::MissingStderr);
        };

        let (stdout_tx, stdout_rx) = bounded(config.stdout_capacity);
        let (stderr_tx, stderr_rx) = bounded(config.stderr_capacity);
        let stdout_thread = match spawn_reader_thread(
            "hartevo-runtime-stdout",
            stdout,
            stdout_tx,
            config.max_line_bytes,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                terminate_group_best_effort(&mut child);
                return Err(AdapterError::Io(error));
            }
        };
        let stderr_thread = match spawn_reader_thread(
            "hartevo-runtime-stderr",
            stderr,
            stderr_tx,
            config.max_line_bytes,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                terminate_group_best_effort(&mut child);
                drop(stdout_rx);
                let _ = stdout_thread.join();
                return Err(AdapterError::Io(error));
            }
        };

        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            stdout_rx: Some(stdout_rx),
            stderr_rx: Some(stderr_rx),
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
            next_id: 1,
            pending: HashMap::new(),
            server_requests: HashSet::new(),
            deferred: VecDeque::new(),
            deferred_capacity: config.deferred_capacity,
            max_line_bytes: config.max_line_bytes,
            shutdown_grace: config.shutdown_grace,
            config_digest,
            instance_digest,
            process_identity,
            launch_token: Zeroizing::new(launch.launch_token().to_owned()),
            launch_executable_path: launch.executable_path.clone(),
            launch_executable_path_digest: launch.executable_path_digest.clone(),
            expected_runtime_home: validated.openinterpreter_home,
            program_sha256: validated.program_sha256,
            program_integrity_pinned: config.expected_program_sha256.is_some(),
            last_control_plane_provider_id: None,
            poisoned: false,
        })
    }

    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    pub fn instance_digest(&self) -> &str {
        &self.instance_digest
    }

    pub fn process_identity(&self) -> &ObservedRuntimeProcessIdentity {
        &self.process_identity
    }

    pub fn launch_token_digest(&self) -> String {
        digest_bytes(self.launch_token.as_bytes())
    }

    pub fn next_request_id(&mut self) -> Result<RequestId, AdapterError> {
        let next = self
            .next_id
            .checked_add(1)
            .ok_or(AdapterError::RequestIdExhausted)?;
        let id = self.next_id;
        self.next_id = next;
        Ok(RequestId::Number(id))
    }

    pub fn send_request(&mut self, request: &JsonRpcRequest) -> Result<(), AdapterError> {
        self.ensure_writable()?;
        if !is_stable_client_method(&request.method) {
            return Err(AdapterError::UnsupportedClientMethod(
                request.method.clone(),
            ));
        }
        if self.pending.contains_key(&request.id) {
            return Err(AdapterError::DuplicateRequestId(request.id.clone()));
        }
        let payload = serde_json::to_vec(request)?;
        let request_digest = digest_bytes(&payload);
        let sent_at = Instant::now();
        self.write_payload(&payload, &request_digest)?;
        self.pending.insert(
            request.id.clone(),
            PendingRequest {
                method: request.method.clone(),
                request_digest,
                sent_at,
            },
        );
        Ok(())
    }

    pub fn send_response(&mut self, response: &JsonRpcResponse) -> Result<(), AdapterError> {
        self.ensure_writable()?;
        if !has_exactly_one_result(response) {
            return Err(AdapterError::InvalidJsonRpcEnvelope);
        }
        if !self.server_requests.contains(&response.id) {
            return Err(AdapterError::ServerRequestNotPending(response.id.clone()));
        }
        let payload = serde_json::to_vec(response)?;
        let response_digest = digest_bytes(&payload);
        self.write_payload(&payload, &response_digest)?;
        self.server_requests.remove(&response.id);
        Ok(())
    }

    pub fn next_event(&mut self, timeout: Duration) -> Result<RuntimeEvent, AdapterError> {
        if let Some(event) = self.deferred.pop_front() {
            return Ok(event);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(AdapterError::TimeoutOutOfRange)?;
        if let Some(event) = self.try_ready_event() {
            return Ok(event);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(AdapterError::NextEventTimedOut);
        }
        let stdout_rx = self.stdout_rx.clone();
        let stderr_rx = self.stderr_rx.clone();
        let selected = match (stdout_rx, stderr_rx) {
            (Some(stdout_rx), Some(stderr_rx)) => {
                select! {
                    recv(stdout_rx) -> message => Some((RuntimeStream::Stdout, message)),
                    recv(stderr_rx) -> message => Some((RuntimeStream::Stderr, message)),
                    default(remaining) => None,
                }
            }
            (Some(stdout_rx), None) => match stdout_rx.recv_timeout(remaining) {
                Ok(message) => Some((RuntimeStream::Stdout, Ok(message))),
                Err(RecvTimeoutError::Disconnected) => {
                    Some((RuntimeStream::Stdout, Err(crossbeam_channel::RecvError)))
                }
                Err(RecvTimeoutError::Timeout) => None,
            },
            (None, Some(stderr_rx)) => match stderr_rx.recv_timeout(remaining) {
                Ok(message) => Some((RuntimeStream::Stderr, Ok(message))),
                Err(RecvTimeoutError::Disconnected) => {
                    Some((RuntimeStream::Stderr, Err(crossbeam_channel::RecvError)))
                }
                Err(RecvTimeoutError::Timeout) => None,
            },
            (None, None) => return Err(AdapterError::RuntimeStreamsClosed),
        };
        let Some((stream, message)) = selected else {
            return Err(AdapterError::NextEventTimedOut);
        };
        Ok(match message {
            Ok(message) => self.handle_reader_message(stream, message),
            Err(_) => self.handle_reader_disconnect(stream),
        })
    }

    pub fn health_check(&mut self, timeout: Duration) -> Result<RuntimeHealth, AdapterError> {
        let id = self.next_request_id()?;
        let request = AppServerContract::initialize(id.clone());
        self.send_request(&request)?;
        let (response, elapsed) = match self.await_response(&id, "initialize", timeout) {
            Err(AdapterError::RequestTimedOut { request_digest, .. }) => {
                return Err(AdapterError::HealthCheckTimedOut { request_digest });
            }
            other => other?,
        };
        if let Some(error) = response.error {
            self.poisoned = true;
            return Err(AdapterError::HealthCheckRejected {
                error_digest: json_digest(&error),
            });
        }
        let runtime_home_digest = self.validate_initialize_home(response.result.as_ref())?;
        Ok(RuntimeHealth {
            process_id: self.child.as_ref().map_or(0, GroupChild::id),
            runtime_instance_digest: self.instance_digest.clone(),
            round_trip: elapsed,
            protocol_version: PROTOCOL_VERSION,
            schema_digest: format!("sha256:{APP_SERVER_SCHEMA_SHA256}"),
            runtime_home_digest,
            program_sha256: self.program_sha256.clone(),
            program_integrity_pinned: self.program_integrity_pinned,
        })
    }

    fn validate_initialize_home(
        &mut self,
        result: Option<&Value>,
    ) -> Result<Option<String>, AdapterError> {
        let Some(expected) = self.expected_runtime_home.as_ref() else {
            return Ok(None);
        };
        let reported = result
            .and_then(|value| value.get("codexHome"))
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .and_then(|path| path.canonicalize().ok());
        if reported.as_deref() != Some(expected.as_path()) {
            self.poisoned = true;
            return Err(AdapterError::RuntimeHomeMismatch {
                expected_digest: path_digest(expected),
                actual_digest: reported
                    .as_deref()
                    .map_or_else(|| "sha256:missing".to_owned(), path_digest),
            });
        }
        Ok(Some(path_digest(expected)))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_mapped_thread(
        &mut self,
        project_id: &str,
        mission_id: &str,
        runtime_generation: u64,
        workspace_root: &Path,
        model: Option<&str>,
        timeout: Duration,
    ) -> Result<RuntimeMapping, AdapterError> {
        validate_mapping_scope(project_id, mission_id, runtime_generation)?;
        validate_model(model)?;
        let workspace_root = canonical_runtime_workspace(workspace_root)?;
        let id = self.next_request_id()?;
        let request = AppServerContract::thread_start(id.clone(), &workspace_root, model);
        self.send_request(&request)?;
        let (response, _) = self.await_response(&id, "thread/start", timeout)?;
        let binding =
            self.extract_thread_binding(response, "thread/start", &workspace_root, model, None)?;
        RuntimeMapping::new(
            project_id,
            mission_id,
            runtime_generation,
            self.instance_digest.clone(),
            binding.model,
            binding.model_provider,
            binding.thread_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resume_mapped_thread(
        &mut self,
        project_id: &str,
        mission_id: &str,
        runtime_generation: u64,
        runtime_thread_id: &str,
        workspace_root: &Path,
        timeout: Duration,
    ) -> Result<RuntimeMapping, AdapterError> {
        validate_mapping_scope(project_id, mission_id, runtime_generation)?;
        if !is_bounded_identifier(runtime_thread_id) {
            return Err(AdapterError::InvalidRuntimeMapping);
        }
        let workspace_root = canonical_runtime_workspace(workspace_root)?;
        let id = self.next_request_id()?;
        let request =
            AppServerContract::thread_resume(id.clone(), runtime_thread_id, &workspace_root);
        self.send_request(&request)?;
        let (response, _) = self.await_response(&id, "thread/resume", timeout)?;
        let binding = self.extract_thread_binding(
            response,
            "thread/resume",
            &workspace_root,
            None,
            Some(runtime_thread_id),
        )?;
        RuntimeMapping::new(
            project_id,
            mission_id,
            runtime_generation,
            self.instance_digest.clone(),
            binding.model,
            binding.model_provider,
            binding.thread_id,
        )
    }

    pub fn start_mapped_turn(
        &mut self,
        mapping: &RuntimeMapping,
        client_user_message_id: &str,
        prompt: &str,
        timeout: Duration,
    ) -> Result<RuntimeTurnDispatch, AdapterError> {
        self.validate_live_mapping(mapping, false)?;
        if !is_bounded_identifier(client_user_message_id) || prompt.trim().is_empty() {
            return Err(AdapterError::InvalidTurnRequest);
        }
        let id = self.next_request_id()?;
        let request = AppServerContract::turn_start_with_client_message_id(
            id.clone(),
            &mapping.runtime_thread_id,
            Some(client_user_message_id),
            prompt,
        );
        let request_digest = digest_hex(&serde_json::to_vec(&request)?);
        self.send_request(&request)?;
        let (response, elapsed) = self.await_response(&id, "turn/start", timeout)?;
        let response_digest = digest_hex(&serde_json::to_vec(&response)?);
        if let Some(error) = response.error {
            return Err(AdapterError::TurnRequestRejected {
                error_digest: json_digest(&error),
            });
        }
        let turn_id =
            extract_turn_id_with_status(response.result.as_ref(), "inProgress", &response_digest)?;
        let mut next_mapping = mapping.clone();
        next_mapping.runtime_turn_id = Some(turn_id);
        next_mapping.validate()?;
        Ok(RuntimeTurnDispatch {
            mapping: next_mapping,
            request_digest,
            response_digest,
            elapsed,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one protocol boundary maps every scoped turn notification, private text carrier, approval request, and terminal failure without leaking content"
    )]
    pub fn next_mapped_turn_event(
        &mut self,
        mapping: &RuntimeMapping,
        timeout: Duration,
    ) -> Result<MappedTurnEvent, AdapterError> {
        self.validate_live_mapping(mapping, true)?;
        let event = self.next_event(timeout)?;
        match event {
            RuntimeEvent::ServerRequest {
                kind: RuntimeEventKind::LocalApprovalRequested,
                request,
            } => {
                let approval_kind = match request.method.as_str() {
                    "item/commandExecution/requestApproval" => {
                        RuntimeLocalApprovalKind::CommandExecution
                    }
                    "item/fileChange/requestApproval" => RuntimeLocalApprovalKind::FileChange,
                    _ => return self.turn_protocol_violation("unsupported_turn_approval"),
                };
                self.validate_turn_scope_fields(mapping, &request.params, false)?;
                let request_digest = digest_hex(&serde_json::to_vec(&request)?);
                Ok(MappedTurnEvent {
                    kind: MappedTurnEventKind::LocalApprovalRequested(approval_kind),
                    event_digest: request_digest.clone(),
                    approval_request: Some(RuntimeLocalApprovalRequest {
                        request_id: request.id,
                        kind: approval_kind,
                        request_digest,
                    }),
                    recovery_hint: None,
                    agent_message_delta: None,
                    agent_message: None,
                })
            }
            RuntimeEvent::Notification { kind, notification } => {
                let event_digest = digest_hex(&serde_json::to_vec(&notification)?);
                let mut agent_message = None;
                let mut agent_message_delta = None;
                let mut recovery_hint = None;
                let mapped_kind = match kind {
                    RuntimeEventKind::TurnStarted => {
                        self.validate_turn_scope_fields(mapping, &notification.params, true)?;
                        validate_turn_status(&notification.params, "inProgress")?;
                        MappedTurnEventKind::TurnStarted
                    }
                    RuntimeEventKind::ItemStarted => {
                        self.validate_turn_scope_fields(mapping, &notification.params, false)?;
                        MappedTurnEventKind::ItemStarted
                    }
                    RuntimeEventKind::AgentMessageDelta => {
                        self.validate_turn_scope_fields(mapping, &notification.params, false)?;
                        agent_message_delta =
                            Some(match parse_agent_message_delta(&notification.params) {
                                Ok(delta) => delta,
                                Err(_) => {
                                    return self
                                        .turn_protocol_violation("invalid_agent_message_delta");
                                }
                            });
                        MappedTurnEventKind::AgentMessageDelta
                    }
                    RuntimeEventKind::ItemCompleted => {
                        self.validate_turn_scope_fields(mapping, &notification.params, false)?;
                        recovery_hint = notification
                            .params
                            .get("item")
                            .and_then(control_plane::recovery_hint_for_item);
                        agent_message = match completed_agent_message(&notification.params) {
                            Ok(message) => message,
                            Err(_) => {
                                return self
                                    .turn_protocol_violation("invalid_completed_agent_message");
                            }
                        };
                        MappedTurnEventKind::ItemCompleted
                    }
                    RuntimeEventKind::TurnCompleted => {
                        self.validate_turn_scope_fields(mapping, &notification.params, true)?;
                        let status = extract_terminal_turn_status(&notification.params)?;
                        MappedTurnEventKind::TurnCompleted(status)
                    }
                    RuntimeEventKind::ThreadStarted | RuntimeEventKind::Unknown(_) => {
                        MappedTurnEventKind::Other
                    }
                    RuntimeEventKind::LocalApprovalRequested => {
                        return self.turn_protocol_violation("approval_as_notification");
                    }
                };
                Ok(MappedTurnEvent {
                    kind: mapped_kind,
                    event_digest,
                    approval_request: None,
                    recovery_hint,
                    agent_message_delta,
                    agent_message,
                })
            }
            RuntimeEvent::Diagnostic(diagnostic) => Ok(MappedTurnEvent {
                kind: MappedTurnEventKind::Diagnostic,
                event_digest: digest_hex(format!("{diagnostic:?}").as_bytes()),
                approval_request: None,
                recovery_hint: None,
                agent_message_delta: None,
                agent_message: None,
            }),
            RuntimeEvent::StderrClosed => Ok(MappedTurnEvent {
                kind: MappedTurnEventKind::Diagnostic,
                event_digest: digest_hex(b"runtime-stderr-closed"),
                approval_request: None,
                recovery_hint: None,
                agent_message_delta: None,
                agent_message: None,
            }),
            RuntimeEvent::ProtocolViolation(diagnostic) => Err(AdapterError::ProtocolViolation {
                category: diagnostic.category,
                digest: diagnostic.digest,
            }),
            RuntimeEvent::StdoutClosed => Err(self.runtime_exited_error()),
            RuntimeEvent::CorrelatedResponse { .. } | RuntimeEvent::ServerRequest { .. } => {
                self.turn_protocol_violation("unexpected_turn_event")
            }
        }
    }

    pub fn respond_to_mapped_turn_approval(
        &mut self,
        mapping: &RuntimeMapping,
        request: &RuntimeLocalApprovalRequest,
        approved: bool,
    ) -> Result<String, AdapterError> {
        self.validate_live_mapping(mapping, true)?;
        if !is_sha256(&request.request_digest) {
            return Err(AdapterError::InvalidTurnRequest);
        }
        let response =
            AppServerContract::local_approval_response(request.request_id.clone(), approved);
        let response_digest = digest_hex(&serde_json::to_vec(&response)?);
        self.send_response(&response)?;
        Ok(response_digest)
    }

    pub fn interrupt_mapped_turn(
        &mut self,
        mapping: &RuntimeMapping,
        timeout: Duration,
    ) -> Result<RuntimeProtocolWriteReceipt, AdapterError> {
        self.validate_live_mapping(mapping, true)?;
        let turn_id = mapping
            .runtime_turn_id
            .as_deref()
            .ok_or(AdapterError::InvalidRuntimeMapping)?;
        let id = self.next_request_id()?;
        let request =
            AppServerContract::turn_interrupt(id.clone(), &mapping.runtime_thread_id, turn_id);
        let request_digest = digest_hex(&serde_json::to_vec(&request)?);
        self.send_request(&request)?;
        let (response, elapsed) = self.await_response(&id, "turn/interrupt", timeout)?;
        let response_digest = digest_hex(&serde_json::to_vec(&response)?);
        if let Some(error) = response.error {
            return Err(AdapterError::TurnInterruptRejected {
                error_digest: json_digest(&error),
            });
        }
        if response
            .result
            .as_ref()
            .and_then(Value::as_object)
            .is_none_or(|result| !result.is_empty())
        {
            self.poisoned = true;
            return Err(AdapterError::InvalidTurnResponse { response_digest });
        }
        Ok(RuntimeProtocolWriteReceipt {
            request_digest,
            response_digest,
            elapsed,
        })
    }

    pub fn poll_exit(&mut self) -> Result<Option<ExitStatus>, AdapterError> {
        self.child
            .as_mut()
            .ok_or(AdapterError::RuntimeAlreadyShutdown)?
            .try_wait()
            .map_err(AdapterError::Io)
    }

    pub fn shutdown(mut self) -> Result<ShutdownReport, AdapterError> {
        self.shutdown_inner()
    }

    fn ensure_writable(&self) -> Result<(), AdapterError> {
        if self.poisoned {
            return Err(AdapterError::RuntimePoisoned);
        }
        if self.stdin.is_none() || self.child.is_none() {
            return Err(AdapterError::RuntimeAlreadyShutdown);
        }
        Ok(())
    }

    fn validate_live_mapping(
        &self,
        mapping: &RuntimeMapping,
        require_turn: bool,
    ) -> Result<(), AdapterError> {
        mapping.validate()?;
        if mapping.runtime_instance_digest != self.instance_digest
            || mapping.runtime_turn_id.is_some() != require_turn
        {
            return Err(AdapterError::InvalidRuntimeMapping);
        }
        Ok(())
    }

    fn validate_turn_scope_fields(
        &mut self,
        mapping: &RuntimeMapping,
        params: &Value,
        turn_nested: bool,
    ) -> Result<(), AdapterError> {
        let thread_id = params.get("threadId").and_then(Value::as_str);
        let turn_id = if turn_nested {
            params
                .get("turn")
                .and_then(|turn| turn.get("id"))
                .and_then(Value::as_str)
        } else {
            params.get("turnId").and_then(Value::as_str)
        };
        if thread_id != Some(mapping.runtime_thread_id.as_str())
            || turn_id != mapping.runtime_turn_id.as_deref()
        {
            return self.turn_protocol_violation("turn_identity_mismatch");
        }
        Ok(())
    }

    fn turn_protocol_violation<T>(&mut self, category: &str) -> Result<T, AdapterError> {
        self.poisoned = true;
        Err(AdapterError::ProtocolViolation {
            category: category.to_owned(),
            digest: digest_bytes(category.as_bytes()),
        })
    }

    fn write_payload(&mut self, payload: &[u8], digest: &str) -> Result<(), AdapterError> {
        if payload.len() + 1 > self.max_line_bytes {
            return Err(AdapterError::OutboundMessageTooLarge {
                byte_count: payload.len() + 1,
                maximum: self.max_line_bytes,
            });
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or(AdapterError::RuntimeAlreadyShutdown)?;
        if let Err(error) = stdin
            .write_all(payload)
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
        {
            self.poisoned = true;
            return Err(AdapterError::WriteOutcomeUncertain {
                digest: digest.to_owned(),
                kind: error.kind(),
            });
        }
        Ok(())
    }

    fn await_response(
        &mut self,
        id: &RequestId,
        method: &str,
        timeout: Duration,
    ) -> Result<(JsonRpcResponse, Duration), AdapterError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(AdapterError::TimeoutOutOfRange)?;
        let mut held = VecDeque::new();
        let outcome = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.poisoned = true;
                break Err(self.request_timeout_error(id, method));
            }
            match self.next_event(remaining) {
                Ok(RuntimeEvent::CorrelatedResponse {
                    id: response_id,
                    method: response_method,
                    request_digest: _,
                    response,
                    elapsed,
                }) if response_id == *id && response_method == method => {
                    break Ok((response, elapsed));
                }
                Ok(RuntimeEvent::ProtocolViolation(diagnostic)) => {
                    break Err(AdapterError::ProtocolViolation {
                        category: diagnostic.category,
                        digest: diagnostic.digest,
                    });
                }
                Ok(RuntimeEvent::StdoutClosed) => break Err(self.runtime_exited_error()),
                Ok(event) => {
                    if held.len() >= self.deferred_capacity {
                        self.poisoned = true;
                        break Err(AdapterError::DeferredEventOverflow);
                    }
                    held.push_back(event);
                }
                Err(AdapterError::NextEventTimedOut) => {
                    self.poisoned = true;
                    break Err(self.request_timeout_error(id, method));
                }
                Err(error) => break Err(error),
            }
        };
        held.append(&mut self.deferred);
        self.deferred = held;
        outcome
    }

    fn extract_thread_binding(
        &mut self,
        response: JsonRpcResponse,
        method: &str,
        expected_workspace: &Path,
        expected_model: Option<&str>,
        expected_thread_id: Option<&str>,
    ) -> Result<RuntimeThreadBinding, AdapterError> {
        if let Some(error) = response.error {
            return Err(AdapterError::ThreadRequestRejected {
                method: method.to_owned(),
                error_digest: json_digest(&error),
            });
        }
        let result = response.result.as_ref().unwrap_or(&Value::Null);
        let response_digest = json_digest(result);
        let thread_id = result
            .get("thread")
            .and_then(|thread| thread.get("id"))
            .and_then(Value::as_str)
            .filter(|value| is_bounded_identifier(value))
            .map(ToOwned::to_owned);
        let response_workspace = result
            .get("cwd")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .and_then(|path| path.canonicalize().ok());
        let response_model = result
            .get("model")
            .and_then(Value::as_str)
            .filter(|value| is_bounded_identifier(value))
            .map(ToOwned::to_owned);
        let response_provider = result
            .get("modelProvider")
            .and_then(Value::as_str)
            .filter(|value| is_bounded_identifier(value))
            .map(ToOwned::to_owned);
        let required_policy_fields = ["approvalPolicy", "approvalsReviewer", "sandbox"]
            .iter()
            .all(|field| result.get(*field).is_some_and(|value| !value.is_null()));
        let valid = thread_id.is_some()
            && response_workspace.as_deref() == Some(expected_workspace)
            && response_model.is_some()
            && expected_model.is_none_or(|model| response_model.as_deref() == Some(model))
            && response_provider.is_some()
            && required_policy_fields;
        if !valid {
            self.poisoned = true;
            return Err(AdapterError::InvalidThreadResponse {
                method: method.to_owned(),
                response_digest,
            });
        }
        let Some(thread_id) = thread_id else {
            self.poisoned = true;
            return Err(AdapterError::InvalidThreadResponse {
                method: method.to_owned(),
                response_digest,
            });
        };
        if let Some(expected_thread_id) = expected_thread_id
            && thread_id != expected_thread_id
        {
            self.poisoned = true;
            return Err(AdapterError::ThreadIdentityMismatch {
                expected_digest: digest_hex(expected_thread_id.as_bytes()),
                actual_digest: digest_hex(thread_id.as_bytes()),
            });
        }
        let (Some(model), Some(model_provider)) = (response_model, response_provider) else {
            self.poisoned = true;
            return Err(AdapterError::InvalidThreadResponse {
                method: method.to_owned(),
                response_digest,
            });
        };
        Ok(RuntimeThreadBinding {
            thread_id,
            model,
            model_provider,
        })
    }

    fn try_ready_event(&mut self) -> Option<RuntimeEvent> {
        if let Some(receiver) = self.stdout_rx.as_ref() {
            match receiver.try_recv() {
                Ok(message) => {
                    return Some(self.handle_reader_message(RuntimeStream::Stdout, message));
                }
                Err(TryRecvError::Disconnected) => {
                    return Some(self.handle_reader_disconnect(RuntimeStream::Stdout));
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        if let Some(receiver) = self.stderr_rx.as_ref() {
            match receiver.try_recv() {
                Ok(message) => {
                    return Some(self.handle_reader_message(RuntimeStream::Stderr, message));
                }
                Err(TryRecvError::Disconnected) => {
                    return Some(self.handle_reader_disconnect(RuntimeStream::Stderr));
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        None
    }

    fn handle_reader_message(
        &mut self,
        stream: RuntimeStream,
        message: ReaderMessage,
    ) -> RuntimeEvent {
        match (stream, message) {
            (RuntimeStream::Stdout, ReaderMessage::Frame(frame)) => {
                self.decode_stdout_frame(&frame)
            }
            (RuntimeStream::Stderr, ReaderMessage::Frame(frame)) => RuntimeEvent::Diagnostic(
                diagnostic_from_frame(RuntimeStream::Stderr, "stderr_line", &frame),
            ),
            (RuntimeStream::Stdout, ReaderMessage::Failure { category, digest }) => {
                self.poisoned = true;
                RuntimeEvent::ProtocolViolation(RuntimeDiagnostic {
                    stream,
                    category,
                    byte_count: 0,
                    digest,
                    truncated: false,
                })
            }
            (RuntimeStream::Stderr, ReaderMessage::Failure { category, digest }) => {
                RuntimeEvent::Diagnostic(RuntimeDiagnostic {
                    stream,
                    category,
                    byte_count: 0,
                    digest,
                    truncated: false,
                })
            }
            (_, ReaderMessage::Closed) => self.handle_reader_disconnect(stream),
        }
    }

    fn handle_reader_disconnect(&mut self, stream: RuntimeStream) -> RuntimeEvent {
        match stream {
            RuntimeStream::Stdout => {
                self.stdout_rx = None;
                self.poisoned = true;
                RuntimeEvent::StdoutClosed
            }
            RuntimeStream::Stderr => {
                self.stderr_rx = None;
                RuntimeEvent::StderrClosed
            }
        }
    }

    fn decode_stdout_frame(&mut self, frame: &BoundedFrame) -> RuntimeEvent {
        if frame.truncated {
            return self.protocol_violation("stdout_line_too_large", frame);
        }
        let value: Value = match serde_json::from_slice(&frame.bytes) {
            Ok(value) => value,
            Err(_) => return self.protocol_violation("invalid_json", frame),
        };
        let method_present = value.get("method").is_some();
        if method_present && value.get("method").and_then(Value::as_str).is_none() {
            return self.protocol_violation("invalid_method", frame);
        }
        let has_id = value.get("id").is_some();
        match (method_present, has_id) {
            (true, true) => {
                let request: JsonRpcServerRequest = match serde_json::from_value(value) {
                    Ok(request) => request,
                    Err(_) => return self.protocol_violation("invalid_server_request", frame),
                };
                if !is_stable_server_method(&request.method) {
                    return self.protocol_violation("unsupported_server_request", frame);
                }
                if !self.server_requests.insert(request.id.clone()) {
                    return self.protocol_violation("duplicate_server_request_id", frame);
                }
                RuntimeEvent::ServerRequest {
                    kind: RuntimeEventKind::from_method(&request.method),
                    request,
                }
            }
            (true, false) => {
                let notification: JsonRpcNotification = match serde_json::from_value(value) {
                    Ok(notification) => notification,
                    Err(_) => return self.protocol_violation("invalid_notification", frame),
                };
                RuntimeEvent::Notification {
                    kind: RuntimeEventKind::from_method(&notification.method),
                    notification,
                }
            }
            (false, true) => {
                let response: JsonRpcResponse = match serde_json::from_value(value) {
                    Ok(response) => response,
                    Err(_) => return self.protocol_violation("invalid_response", frame),
                };
                if !has_exactly_one_result(&response) {
                    return self.protocol_violation("invalid_response_envelope", frame);
                }
                let Some(pending) = self.pending.remove(&response.id) else {
                    return self.protocol_violation("unmatched_response", frame);
                };
                RuntimeEvent::CorrelatedResponse {
                    id: response.id.clone(),
                    method: pending.method,
                    request_digest: pending.request_digest,
                    response,
                    elapsed: pending.sent_at.elapsed(),
                }
            }
            (false, false) => self.protocol_violation("unclassified_message", frame),
        }
    }

    fn protocol_violation(&mut self, category: &str, frame: &BoundedFrame) -> RuntimeEvent {
        self.poisoned = true;
        RuntimeEvent::ProtocolViolation(diagnostic_from_frame(
            RuntimeStream::Stdout,
            category,
            frame,
        ))
    }

    fn request_timeout_error(&mut self, id: &RequestId, method: &str) -> AdapterError {
        if let Some(status) = self
            .child
            .as_mut()
            .and_then(|child| child.try_wait().ok().flatten())
        {
            return AdapterError::RuntimeExited {
                exit_code: status.code(),
            };
        }
        let request_digest = self.pending.get(id).map_or_else(
            || "sha256:missing".to_owned(),
            |pending| pending.request_digest.clone(),
        );
        AdapterError::RequestTimedOut {
            method: method.to_owned(),
            request_digest,
        }
    }

    fn runtime_exited_error(&mut self) -> AdapterError {
        let exit_code = self
            .child
            .as_mut()
            .and_then(|child| child.try_wait().ok().flatten())
            .and_then(|status| status.code());
        AdapterError::RuntimeExited { exit_code }
    }

    fn shutdown_inner(&mut self) -> Result<ShutdownReport, AdapterError> {
        self.stdin.take();
        let mut child = self
            .child
            .take()
            .ok_or(AdapterError::RuntimeAlreadyShutdown)?;
        let deadline = Instant::now()
            .checked_add(self.shutdown_grace)
            .ok_or(AdapterError::TimeoutOutOfRange)?;
        let mut status = child.try_wait()?;
        while status.is_none() && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(remaining.min(Duration::from_millis(5)));
            status = child.try_wait()?;
        }
        let forced = status.is_none();
        if forced {
            if let Err(error) = child.kill() {
                if let Some(exited) = child.try_wait()? {
                    status = Some(exited);
                } else {
                    self.child = Some(child);
                    return Err(AdapterError::Io(error));
                }
            }
            if status.is_none() {
                status = Some(child.wait()?);
            }
        }
        let status = status.ok_or(AdapterError::RuntimeExitStatusMissing)?;
        self.drop_receivers_and_join()?;
        cleanup_runtime_launch_artifact(
            &self.launch_executable_path,
            &self.launch_executable_path_digest,
            &self.program_sha256,
        )?;
        Ok(ShutdownReport {
            forced,
            success: status.success(),
            exit_code: status.code(),
        })
    }

    fn drop_receivers_and_join(&mut self) -> Result<(), AdapterError> {
        self.stdout_rx.take();
        self.stderr_rx.take();
        let stdout_panicked = self
            .stdout_thread
            .take()
            .is_some_and(|handle| handle.join().is_err());
        let stderr_panicked = self
            .stderr_thread
            .take()
            .is_some_and(|handle| handle.join().is_err());
        if stdout_panicked || stderr_panicked {
            return Err(AdapterError::ReaderThreadPanicked);
        }
        Ok(())
    }
}

fn completed_agent_message(params: &Value) -> Result<Option<RuntimeAgentMessage>, AdapterError> {
    let Some(item) = params.get("item") else {
        return Ok(None);
    };
    let item_type = item.get("type").and_then(Value::as_str).ok_or_else(|| {
        AdapterError::InvalidTurnNotification {
            notification_digest: json_digest(item),
        }
    })?;
    if item_type != "agentMessage" {
        return Ok(None);
    }
    let item_id = item.get("id").and_then(Value::as_str).ok_or_else(|| {
        AdapterError::InvalidTurnNotification {
            notification_digest: json_digest(item),
        }
    })?;
    let text = item.get("text").and_then(Value::as_str).ok_or_else(|| {
        AdapterError::InvalidTurnNotification {
            notification_digest: json_digest(item),
        }
    })?;
    RuntimeAgentMessage::new(item_id, text)
}

fn parse_agent_message_delta(params: &Value) -> Result<RuntimeAgentMessageDelta, AdapterError> {
    let item_id = params
        .get("itemId")
        .and_then(Value::as_str)
        .ok_or_else(|| AdapterError::InvalidTurnNotification {
            notification_digest: json_digest(params),
        })?;
    let delta = params.get("delta").and_then(Value::as_str).ok_or_else(|| {
        AdapterError::InvalidTurnNotification {
            notification_digest: json_digest(params),
        }
    })?;
    RuntimeAgentMessageDelta::new(item_id, delta)
}

impl Drop for StdioRuntime {
    fn drop(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            terminate_group_best_effort(&mut child);
        }
        let _ = self.drop_receivers_and_join();
        let _ = cleanup_runtime_launch_artifact(
            &self.launch_executable_path,
            &self.launch_executable_path_digest,
            &self.program_sha256,
        );
    }
}

struct ValidatedRuntimeCommand {
    program: PathBuf,
    program_sha256: String,
    current_dir: PathBuf,
    openinterpreter_home: Option<PathBuf>,
}

#[allow(
    clippy::too_many_lines,
    reason = "command validation keeps path, environment, credential, and release-pin checks at one process boundary"
)]
fn validate_runtime_command(
    config: &RuntimeCommand,
) -> Result<ValidatedRuntimeCommand, AdapterError> {
    if !config.program.is_absolute() {
        return Err(AdapterError::ProgramNotAbsolute);
    }
    if !config.current_dir.is_absolute() {
        return Err(AdapterError::WorkingDirectoryNotAbsolute);
    }
    validate_bounded_value(
        "stdout_capacity",
        config.stdout_capacity,
        1,
        MAX_CHANNEL_CAPACITY,
    )?;
    validate_bounded_value(
        "stderr_capacity",
        config.stderr_capacity,
        1,
        MAX_CHANNEL_CAPACITY,
    )?;
    validate_bounded_value(
        "deferred_capacity",
        config.deferred_capacity,
        1,
        MAX_CHANNEL_CAPACITY,
    )?;
    validate_bounded_value("max_line_bytes", config.max_line_bytes, 64, MAX_LINE_BYTES)?;
    if config.shutdown_grace > MAX_SHUTDOWN_GRACE {
        return Err(AdapterError::ConfigurationOutOfRange("shutdown_grace"));
    }
    if config.args.len() > MAX_ARGUMENTS {
        return Err(AdapterError::ConfigurationOutOfRange("args"));
    }
    for (index, argument) in config.args.iter().enumerate() {
        if argument.len() > MAX_OS_VALUE_BYTES || argument.contains('\0') {
            return Err(AdapterError::InvalidArgument { index });
        }
    }
    if config.environment.len() > MAX_ENVIRONMENT_VARIABLES {
        return Err(AdapterError::ConfigurationOutOfRange("environment"));
    }
    control_plane::validate_secret_bindings(&config.secret_bindings)?;
    for (key, value) in &config.environment {
        validate_environment_pair(key, value)?;
    }
    if config
        .secret_bindings
        .iter()
        .any(|binding| config.environment.contains_key(&binding.environment_key))
    {
        return Err(AdapterError::SecretEnvironmentCollision);
    }

    let program = config.program.canonicalize().map_err(AdapterError::Io)?;
    if !program.is_file() {
        return Err(AdapterError::ProgramNotFile);
    }
    let program_sha256 = sha256_file(&program)?;
    if let Some(expected) = config.expected_program_sha256.as_deref() {
        if !is_sha256(expected) {
            return Err(AdapterError::RuntimeProgramDigestInvalid);
        }
        if !program_sha256.eq_ignore_ascii_case(expected) {
            return Err(AdapterError::RuntimeProgramDigestMismatch {
                expected_digest: expected.to_ascii_lowercase(),
                actual_digest: program_sha256,
            });
        }
    }
    let current_dir = config
        .current_dir
        .canonicalize()
        .map_err(AdapterError::Io)?;
    if !current_dir.is_dir() {
        return Err(AdapterError::WorkingDirectoryNotDirectory);
    }
    let openinterpreter_home = if let Some(home) = &config.openinterpreter_home {
        if !home.is_absolute() {
            return Err(AdapterError::RuntimeHomeNotAbsolute);
        }
        let canonical = home.canonicalize().map_err(AdapterError::Io)?;
        if !canonical.is_dir() {
            return Err(AdapterError::RuntimeHomeNotDirectory);
        }
        let configured = config
            .environment
            .get("INTERPRETER_HOME")
            .map(PathBuf::from)
            .and_then(|path| path.canonicalize().ok());
        if configured.as_deref() != Some(canonical.as_path()) {
            return Err(AdapterError::RuntimeHomeEnvironmentMismatch);
        }
        Some(canonical)
    } else {
        if config.environment.contains_key("INTERPRETER_HOME") {
            return Err(AdapterError::RuntimeHomeUnverified);
        }
        None
    };
    Ok(ValidatedRuntimeCommand {
        program,
        program_sha256,
        current_dir,
        openinterpreter_home,
    })
}

fn sha256_file(path: &Path) -> Result<String, AdapterError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_bounded_value(
    name: &'static str,
    value: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), AdapterError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(AdapterError::ConfigurationOutOfRange(name));
    }
    Ok(())
}

fn validate_environment_pair(key: &str, value: &str) -> Result<(), AdapterError> {
    let valid_key = !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
    if !valid_key {
        return Err(AdapterError::InvalidEnvironmentKey {
            key_digest: digest_bytes(key.as_bytes()),
        });
    }
    let upper = key.to_ascii_uppercase();
    let forbidden = upper.starts_with("DYLD_")
        || upper == RUNTIME_LAUNCH_TOKEN_ENV
        || matches!(
            upper.as_str(),
            "LD_PRELOAD"
                | "LD_LIBRARY_PATH"
                | "PYTHONPATH"
                | "PYTHONHOME"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "NODE_OPTIONS"
                | "BASH_ENV"
                | "ENV"
                | "SHELLOPTS"
                | "PROMPT_COMMAND"
        );
    if forbidden {
        return Err(AdapterError::ForbiddenEnvironmentKey { key: upper });
    }
    if value.len() > MAX_OS_VALUE_BYTES || value.contains('\0') {
        return Err(AdapterError::InvalidEnvironmentValue {
            key_digest: digest_bytes(key.as_bytes()),
        });
    }
    Ok(())
}

fn apply_minimal_environment(command: &mut Command, explicit: &BTreeMap<String, String>) {
    #[cfg(unix)]
    const INHERITED_KEYS: &[&str] = &["PATH", "LANG", "LC_ALL", "TMPDIR"];
    #[cfg(windows)]
    const INHERITED_KEYS: &[&str] = &[
        "PATH",
        "LANG",
        "LC_ALL",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
    ];
    for key in INHERITED_KEYS {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.envs(explicit);
}

fn spawn_reader_thread<R>(
    name: &str,
    reader: R,
    sender: Sender<ReaderMessage>,
    maximum: usize,
) -> std::io::Result<JoinHandle<()>>
where
    R: std::io::Read + Send + 'static,
{
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || reader_loop(reader, &sender, maximum))
}

fn reader_loop<R>(reader: R, sender: &Sender<ReaderMessage>, maximum: usize)
where
    R: std::io::Read,
{
    let mut reader = BufReader::new(reader);
    loop {
        match read_bounded_frame(&mut reader, maximum) {
            Ok(Some(frame)) => {
                if sender.send(ReaderMessage::Frame(frame)).is_err() {
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(ReaderMessage::Closed);
                return;
            }
            Err(error) => {
                let rendered = error.to_string();
                let _ = sender.send(ReaderMessage::Failure {
                    category: format!("io_{:?}", error.kind()).to_ascii_lowercase(),
                    digest: digest_bytes(rendered.as_bytes()),
                });
                return;
            }
        }
    }
}

fn read_bounded_frame<R: BufRead>(
    reader: &mut R,
    maximum: usize,
) -> std::io::Result<Option<BoundedFrame>> {
    let mut retained = Vec::with_capacity(maximum.min(8192));
    let mut byte_count = 0_u64;
    let mut hasher = Sha256::new();
    let mut truncated = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if byte_count == 0 {
                return Ok(None);
            }
            return Ok(Some(BoundedFrame {
                bytes: retained,
                byte_count,
                digest: format!("sha256:{}", hex::encode(hasher.finalize())),
                truncated,
            }));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let chunk = &available[..consumed];
        byte_count = byte_count.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        hasher.update(chunk);
        let remaining = maximum.saturating_sub(retained.len());
        retained.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        truncated |= chunk.len() > remaining;
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(BoundedFrame {
                bytes: retained,
                byte_count,
                digest: format!("sha256:{}", hex::encode(hasher.finalize())),
                truncated,
            }));
        }
    }
}

fn diagnostic_from_frame(
    stream: RuntimeStream,
    category: &str,
    frame: &BoundedFrame,
) -> RuntimeDiagnostic {
    RuntimeDiagnostic {
        stream,
        category: category.to_owned(),
        byte_count: frame.byte_count,
        digest: frame.digest.clone(),
        truncated: frame.truncated,
    }
}

fn terminate_group_best_effort(child: &mut GroupChild) {
    if child.try_wait().ok().flatten().is_none() && child.kill().is_err() {
        return;
    }
    let _ = child.wait();
}

#[cfg(windows)]
fn spawn_process_group(command: &mut Command) -> std::io::Result<GroupChild> {
    command.group().kill_on_drop(true).spawn()
}

#[cfg(not(windows))]
fn spawn_process_group(command: &mut Command) -> std::io::Result<GroupChild> {
    command.group_spawn()
}

pub fn generate_runtime_launch_token(config: &RuntimeCommand) -> Result<String, AdapterError> {
    let wall_clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AdapterError::SystemClockBeforeUnixEpoch)?;
    let counter = RUNTIME_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hash_length_prefixed(&mut hasher, config.intent_digest()?.as_bytes());
    hash_length_prefixed(&mut hasher, &std::process::id().to_le_bytes());
    hash_length_prefixed(&mut hasher, &wall_clock.as_nanos().to_le_bytes());
    hash_length_prefixed(&mut hasher, &counter.to_le_bytes());
    Ok(hex::encode(hasher.finalize()))
}

pub fn prepare_runtime_launch(
    config: &RuntimeCommand,
    launch_token: &str,
) -> Result<RuntimeLaunchSpec, AdapterError> {
    validate_runtime_launch_token(launch_token)?;
    let validated = validate_runtime_command(config)?;
    let launch_base = validated
        .openinterpreter_home
        .as_ref()
        .unwrap_or(&validated.current_dir);
    let launch_directory = launch_base
        .join(".hartevo-runtime-launches")
        .join(digest_hex(launch_token.as_bytes()));
    let file_name = validated
        .program
        .file_name()
        .ok_or(AdapterError::RuntimeLaunchArtifactInvalid)?;
    let executable_path = launch_directory.join(file_name);
    Ok(RuntimeLaunchSpec {
        launch_token: launch_token.to_owned(),
        executable_path_digest: digest_hex(executable_path.to_string_lossy().as_bytes()),
        executable_path,
        program_sha256: validated.program_sha256,
    })
}

struct RuntimeLaunchArtifactGuard {
    path: PathBuf,
    path_digest: String,
    program_sha256: String,
    preserve: bool,
}

impl Drop for RuntimeLaunchArtifactGuard {
    fn drop(&mut self) {
        if !self.preserve {
            let _ = cleanup_runtime_launch_artifact(
                &self.path,
                &self.path_digest,
                &self.program_sha256,
            );
        }
    }
}

fn materialize_runtime_launch(
    validated: &ValidatedRuntimeCommand,
    launch: &RuntimeLaunchSpec,
) -> Result<RuntimeLaunchArtifactGuard, AdapterError> {
    if launch.program_sha256 != validated.program_sha256
        || !launch.executable_path.is_absolute()
        || launch.executable_path_digest
            != digest_hex(launch.executable_path.to_string_lossy().as_bytes())
    {
        return Err(AdapterError::RuntimeLaunchArtifactInvalid);
    }
    let launch_directory = launch
        .executable_path
        .parent()
        .ok_or(AdapterError::RuntimeLaunchArtifactInvalid)?;
    let launch_root = launch_directory
        .parent()
        .ok_or(AdapterError::RuntimeLaunchArtifactInvalid)?;
    let launch_base = validated
        .openinterpreter_home
        .as_ref()
        .unwrap_or(&validated.current_dir);
    if launch_root.parent() != Some(launch_base.as_path())
        || launch_root.file_name().and_then(|value| value.to_str())
            != Some(".hartevo-runtime-launches")
        || launch_directory
            .file_name()
            .and_then(|value| value.to_str())
            != Some(digest_hex(launch.launch_token.as_bytes()).as_str())
    {
        return Err(AdapterError::RuntimeLaunchArtifactInvalid);
    }
    create_private_runtime_directory(launch_root)?;
    if launch_directory.exists() {
        return Err(AdapterError::RuntimeLaunchArtifactExists);
    }
    fs::create_dir(launch_directory)?;
    set_private_runtime_permissions(launch_directory, true)?;
    let mut source = fs::File::open(&validated.program)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&launch.executable_path)?;
    std::io::copy(&mut source, &mut destination)?;
    destination.sync_all()?;
    set_private_runtime_permissions(&launch.executable_path, false)?;
    if sha256_file(&launch.executable_path)? != validated.program_sha256 {
        return Err(AdapterError::RuntimeProgramChangedDuringSpawn);
    }
    Ok(RuntimeLaunchArtifactGuard {
        path: launch.executable_path.clone(),
        path_digest: launch.executable_path_digest.clone(),
        program_sha256: launch.program_sha256.clone(),
        preserve: false,
    })
}

fn create_private_runtime_directory(path: &Path) -> Result<(), AdapterError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AdapterError::RuntimeLaunchArtifactInvalid);
            }
        }
        Err(error) => return Err(error.into()),
    }
    set_private_runtime_permissions(path, true)
}

#[cfg(unix)]
fn set_private_runtime_permissions(path: &Path, directory: bool) -> Result<(), AdapterError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if directory { 0o700 } else { 0o500 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_runtime_permissions(_path: &Path, _directory: bool) -> Result<(), AdapterError> {
    Ok(())
}

fn cleanup_runtime_launch_artifact(
    path: &Path,
    path_digest: &str,
    program_sha256: &str,
) -> Result<bool, AdapterError> {
    if !path.is_absolute()
        || !is_sha256(path_digest)
        || !is_sha256(program_sha256)
        || digest_hex(path.to_string_lossy().as_bytes()) != path_digest
    {
        return Err(AdapterError::RuntimeLaunchArtifactInvalid);
    }
    if !path.exists() {
        cleanup_runtime_launch_directories(path)?;
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || sha256_file(path)? != program_sha256
    {
        return Err(AdapterError::RuntimeLaunchArtifactInvalid);
    }
    fs::remove_file(path)?;
    cleanup_runtime_launch_directories(path)?;
    Ok(true)
}

fn cleanup_runtime_launch_directories(path: &Path) -> Result<(), AdapterError> {
    let Some(directory) = path.parent() else {
        return Err(AdapterError::RuntimeLaunchArtifactInvalid);
    };
    for candidate in [Some(directory), directory.parent()].into_iter().flatten() {
        match fs::remove_dir(candidate) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => return Err(AdapterError::Io(error)),
        }
    }
    Ok(())
}

fn validate_runtime_launch_token(value: &str) -> Result<(), AdapterError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AdapterError::InvalidRuntimeLaunchToken);
    }
    Ok(())
}

fn runtime_process_refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_environ(UpdateKind::Always)
        .with_exe(UpdateKind::Always)
        .without_tasks()
}

fn refreshed_process_system() -> System {
    System::new_with_specifics(
        RefreshKind::nothing().with_processes(runtime_process_refresh_kind()),
    )
}

fn refresh_process_system(system: &mut System) {
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        runtime_process_refresh_kind(),
    );
}

fn observe_runtime_process_identity(
    process_id: u32,
    runtime_instance_digest: &str,
) -> Result<ObservedRuntimeProcessIdentity, AdapterError> {
    let pid = Pid::from_u32(process_id);
    for _ in 0..20 {
        let system = refreshed_process_system();
        if let Some(process) = system.process(pid)
            && let Some(executable) = process.exe()
            && process.start_time() > 0
        {
            return Ok(ObservedRuntimeProcessIdentity {
                process_id,
                started_at_epoch_seconds: process.start_time(),
                executable_path_digest: digest_hex(executable.to_string_lossy().as_bytes()),
                runtime_instance_digest: runtime_instance_digest.to_owned(),
            });
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(AdapterError::RuntimeProcessInspectionUnavailable)
}

#[allow(
    clippy::too_many_lines,
    reason = "the cleanup boundary keeps exact identity inspection, marker verification, descendant ordering, bounded termination, and evidence generation together"
)]
pub fn cleanup_runtime_process(
    target: &RuntimeProcessCleanupTarget,
    grace: Duration,
) -> Result<RuntimeProcessCleanupReport, AdapterError> {
    if grace > MAX_SHUTDOWN_GRACE {
        return Err(AdapterError::ConfigurationOutOfRange(
            "runtime_process_cleanup_grace",
        ));
    }
    if !sysinfo::IS_SUPPORTED_SYSTEM {
        return Ok(runtime_process_cleanup_report(
            target,
            ProcessCleanupDisposition::InspectionBlocked,
            0,
            0,
            0,
        ));
    }

    let mut system = refreshed_process_system();
    let mut matched = processes_for_runtime_claim(&system, target);
    if let Some(expected) = &target.identity {
        let root = system.process(Pid::from_u32(expected.process_id));
        let root_matches_identity = root.is_some_and(|process| {
            process.start_time() == expected.started_at_epoch_seconds
                && process.exe().is_some_and(|path| {
                    digest_hex(path.to_string_lossy().as_bytes()) == expected.executable_path_digest
                })
        });
        let root_has_token = matched
            .iter()
            .any(|pid| pid.as_u32() == expected.process_id);
        if root_has_token && !root_matches_identity {
            return Ok(runtime_process_cleanup_report(
                target,
                ProcessCleanupDisposition::InspectionBlocked,
                matched.len(),
                0,
                matched.len(),
            ));
        }
        if matched.is_empty() {
            if !root_matches_identity {
                cleanup_runtime_launch_artifact(
                    &target.launch_executable_path,
                    &target.launch_executable_path_digest,
                    &target.program_sha256,
                )?;
            }
            return Ok(runtime_process_cleanup_report(
                target,
                if root_matches_identity {
                    ProcessCleanupDisposition::InspectionBlocked
                } else {
                    ProcessCleanupDisposition::AlreadyExited
                },
                0,
                0,
                0,
            ));
        }
    } else if matched.is_empty() {
        cleanup_runtime_launch_artifact(
            &target.launch_executable_path,
            &target.launch_executable_path_digest,
            &target.program_sha256,
        )?;
        return Ok(runtime_process_cleanup_report(
            target,
            ProcessCleanupDisposition::AlreadyExited,
            0,
            0,
            0,
        ));
    }

    let initial_count = matched.len();
    sort_processes_child_first(&system, &mut matched);
    let mut signalled = signal_processes(&system, &matched);
    let deadline = Instant::now()
        .checked_add(grace)
        .ok_or(AdapterError::TimeoutOutOfRange)?;
    loop {
        refresh_process_system(&mut system);
        matched = processes_for_runtime_claim(&system, target);
        if matched.is_empty() || Instant::now() >= deadline {
            break;
        }
        thread::sleep(
            Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    if !matched.is_empty() {
        sort_processes_child_first(&system, &mut matched);
        signalled = signalled.saturating_add(signal_processes(&system, &matched));
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(5));
            refresh_process_system(&mut system);
            matched = processes_for_runtime_claim(&system, target);
            if matched.is_empty() {
                break;
            }
        }
    }
    let disposition = if matched.is_empty() {
        cleanup_runtime_launch_artifact(
            &target.launch_executable_path,
            &target.launch_executable_path_digest,
            &target.program_sha256,
        )?;
        ProcessCleanupDisposition::Terminated
    } else {
        ProcessCleanupDisposition::TerminationFailed
    };
    Ok(runtime_process_cleanup_report(
        target,
        disposition,
        initial_count,
        signalled,
        matched.len(),
    ))
}

fn process_has_launch_token(process: &sysinfo::Process, launch_token: &str) -> bool {
    process.environ().iter().any(|entry| {
        entry.to_str().and_then(|value| value.split_once('='))
            == Some((RUNTIME_LAUNCH_TOKEN_ENV, launch_token))
    })
}

fn processes_for_runtime_claim(system: &System, target: &RuntimeProcessCleanupTarget) -> Vec<Pid> {
    let marker_processes = system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let executable_matches = process.exe().is_some_and(|path| {
                digest_hex(path.to_string_lossy().as_bytes())
                    == target.launch_executable_path_digest
            });
            (executable_matches || process_has_launch_token(process, &target.launch_token))
                .then_some(*pid)
        })
        .collect::<HashSet<_>>();
    let mut selected = marker_processes.clone();
    for pid in system.processes().keys() {
        let mut cursor = Some(*pid);
        let mut depth = 0_u32;
        while let Some(current) = cursor {
            if marker_processes.contains(&current) {
                selected.insert(*pid);
                break;
            }
            cursor = system.process(current).and_then(sysinfo::Process::parent);
            depth = depth.saturating_add(1);
            if depth > 1_024 {
                break;
            }
        }
    }
    selected.into_iter().collect()
}

fn sort_processes_child_first(system: &System, processes: &mut [Pid]) {
    processes.sort_by_key(|pid| {
        let mut depth = 0_u32;
        let mut cursor = Some(*pid);
        while let Some(current) = cursor {
            cursor = system.process(current).and_then(sysinfo::Process::parent);
            depth = depth.saturating_add(1);
            if depth > 1_024 {
                break;
            }
        }
        std::cmp::Reverse(depth)
    });
}

fn signal_processes(system: &System, processes: &[Pid]) -> usize {
    processes
        .iter()
        .filter(|pid| system.process(**pid).is_some_and(sysinfo::Process::kill))
        .count()
}

fn runtime_process_cleanup_report(
    target: &RuntimeProcessCleanupTarget,
    disposition: ProcessCleanupDisposition,
    matched_process_count: usize,
    signalled_process_count: usize,
    remaining_process_count: usize,
) -> RuntimeProcessCleanupReport {
    let mut hasher = Sha256::new();
    hash_length_prefixed(
        &mut hasher,
        match disposition {
            ProcessCleanupDisposition::Terminated => b"terminated",
            ProcessCleanupDisposition::AlreadyExited => b"already-exited",
            ProcessCleanupDisposition::InspectionBlocked => b"inspection-blocked",
            ProcessCleanupDisposition::TerminationFailed => b"termination-failed",
        },
    );
    hash_length_prefixed(
        &mut hasher,
        digest_bytes(target.launch_token.as_bytes()).as_bytes(),
    );
    hash_length_prefixed(&mut hasher, target.launch_executable_path_digest.as_bytes());
    hash_length_prefixed(&mut hasher, target.program_sha256.as_bytes());
    if let Some(identity) = &target.identity {
        hash_length_prefixed(&mut hasher, &identity.process_id.to_le_bytes());
        hash_length_prefixed(
            &mut hasher,
            &identity.started_at_epoch_seconds.to_le_bytes(),
        );
        hash_length_prefixed(&mut hasher, identity.executable_path_digest.as_bytes());
        hash_length_prefixed(&mut hasher, identity.runtime_instance_digest.as_bytes());
    }
    hash_length_prefixed(&mut hasher, &matched_process_count.to_le_bytes());
    hash_length_prefixed(&mut hasher, &signalled_process_count.to_le_bytes());
    hash_length_prefixed(&mut hasher, &remaining_process_count.to_le_bytes());
    RuntimeProcessCleanupReport {
        disposition,
        matched_process_count,
        signalled_process_count,
        remaining_process_count,
        evidence_digest: hex::encode(hasher.finalize()),
    }
}

fn is_stable_client_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "thread/start"
            | "thread/resume"
            | "turn/start"
            | "turn/steer"
            | "turn/interrupt"
            | "interpreter/provider/list"
            | "interpreter/provider/set"
            | "interpreter/model/list"
            | "interpreter/model/set"
            | "interpreter/harness/list"
            | "interpreter/harness/set"
    )
}

fn is_stable_server_method(method: &str) -> bool {
    matches!(
        method,
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval"
    )
}

fn has_exactly_one_result(response: &JsonRpcResponse) -> bool {
    response.result.is_some() != response.error.is_some()
}

fn validate_mapping_scope(
    project_id: &str,
    mission_id: &str,
    runtime_generation: u64,
) -> Result<(), AdapterError> {
    if runtime_generation == 0
        || !is_bounded_identifier(project_id)
        || !is_bounded_identifier(mission_id)
    {
        return Err(AdapterError::InvalidRuntimeMapping);
    }
    Ok(())
}

fn extract_turn_id_with_status(
    result: Option<&Value>,
    expected_status: &str,
    response_digest: &str,
) -> Result<String, AdapterError> {
    let Some(turn) = result.and_then(|value| value.get("turn")) else {
        return Err(AdapterError::InvalidTurnResponse {
            response_digest: response_digest.to_owned(),
        });
    };
    let Some(turn_id) = turn.get("id").and_then(Value::as_str) else {
        return Err(AdapterError::InvalidTurnResponse {
            response_digest: response_digest.to_owned(),
        });
    };
    if !is_bounded_identifier(turn_id)
        || turn.get("status").and_then(Value::as_str) != Some(expected_status)
    {
        return Err(AdapterError::InvalidTurnResponse {
            response_digest: response_digest.to_owned(),
        });
    }
    Ok(turn_id.to_owned())
}

fn validate_turn_status(params: &Value, expected_status: &str) -> Result<(), AdapterError> {
    if params
        .get("turn")
        .and_then(|turn| turn.get("status"))
        .and_then(Value::as_str)
        != Some(expected_status)
    {
        return Err(AdapterError::InvalidTurnNotification {
            notification_digest: json_digest(params),
        });
    }
    Ok(())
}

fn extract_terminal_turn_status(
    params: &Value,
) -> Result<RuntimeTurnCompletionStatus, AdapterError> {
    match params
        .get("turn")
        .and_then(|turn| turn.get("status"))
        .and_then(Value::as_str)
    {
        Some("completed") => Ok(RuntimeTurnCompletionStatus::Completed),
        Some("interrupted") => Ok(RuntimeTurnCompletionStatus::Interrupted),
        Some("failed") => Ok(RuntimeTurnCompletionStatus::Failed),
        _ => Err(AdapterError::InvalidTurnNotification {
            notification_digest: json_digest(params),
        }),
    }
}

fn validate_model(model: Option<&str>) -> Result<(), AdapterError> {
    if model.is_some_and(|value| !is_bounded_identifier(value)) {
        return Err(AdapterError::InvalidRuntimeModel);
    }
    Ok(())
}

fn canonical_runtime_workspace(path: &Path) -> Result<PathBuf, AdapterError> {
    if !path.is_absolute() {
        return Err(AdapterError::WorkingDirectoryNotAbsolute);
    }
    let canonical = path.canonicalize()?;
    if !canonical.is_dir() {
        return Err(AdapterError::WorkingDirectoryNotDirectory);
    }
    Ok(canonical)
}

fn is_bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn runtime_instance_digest(process_id: u32, config_digest: &str) -> Result<String, AdapterError> {
    let wall_clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AdapterError::SystemClockBeforeUnixEpoch)?;
    let counter = RUNTIME_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hash_length_prefixed(&mut hasher, &process_id.to_le_bytes());
    hash_length_prefixed(&mut hasher, config_digest.as_bytes());
    hash_length_prefixed(&mut hasher, &wall_clock.as_nanos().to_le_bytes());
    hash_length_prefixed(&mut hasher, &counter.to_le_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(value.len().to_le_bytes());
    hasher.update(value);
}

fn json_digest(value: &Value) -> String {
    serde_json::to_vec(value).map_or_else(
        |_| "sha256:serialization-failed".to_owned(),
        |payload| digest_bytes(&payload),
    )
}

fn path_digest(path: &Path) -> String {
    digest_bytes(path.to_string_lossy().as_bytes())
}

fn digest_bytes(payload: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(payload)))
}

fn digest_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("runtime program must be an absolute path")]
    ProgramNotAbsolute,
    #[error("runtime program must resolve to a file")]
    ProgramNotFile,
    #[error("runtime program SHA-256 pin is invalid")]
    RuntimeProgramDigestInvalid,
    #[error("runtime program does not match the release-manifest SHA-256 pin")]
    RuntimeProgramDigestMismatch {
        expected_digest: String,
        actual_digest: String,
    },
    #[error("runtime program changed while the child process was being spawned")]
    RuntimeProgramChangedDuringSpawn,
    #[error("the current host has no pinned OpenInterpreter artifact")]
    RuntimeHostUnsupported,
    #[error("the requested OpenInterpreter target is absent from the artifact catalog")]
    RuntimeArtifactUnavailable,
    #[error("the OpenInterpreter artifact catalog is invalid or inconsistent")]
    RuntimeArtifactCatalogInvalid,
    #[error("the OpenInterpreter artifact lacks entrypoint or package evidence")]
    RuntimeArtifactEvidenceMissing,
    #[error("the OpenInterpreter package layout or metadata is invalid")]
    RuntimePackageInvalid,
    #[error("runtime working directory must be an absolute path")]
    WorkingDirectoryNotAbsolute,
    #[error("runtime working directory must resolve to a directory")]
    WorkingDirectoryNotDirectory,
    #[error("OpenInterpreter state home must be an absolute path")]
    RuntimeHomeNotAbsolute,
    #[error("OpenInterpreter state home must resolve to a directory")]
    RuntimeHomeNotDirectory,
    #[error("INTERPRETER_HOME must resolve to the exact declared OpenInterpreter state home")]
    RuntimeHomeEnvironmentMismatch,
    #[error("INTERPRETER_HOME cannot be supplied without an exact expected state home")]
    RuntimeHomeUnverified,
    #[error("OpenInterpreter initialized against an unexpected state home")]
    RuntimeHomeMismatch {
        expected_digest: String,
        actual_digest: String,
    },
    #[error("runtime configuration field is outside its allowed range: {0}")]
    ConfigurationOutOfRange(&'static str),
    #[error("runtime budget is invalid")]
    InvalidRuntimeBudget,
    #[error("runtime argument {index} is invalid")]
    InvalidArgument { index: usize },
    #[error("runtime environment key is invalid ({key_digest})")]
    InvalidEnvironmentKey { key_digest: String },
    #[error("runtime environment key is forbidden: {key}")]
    ForbiddenEnvironmentKey { key: String },
    #[error("runtime environment value is invalid for key {key_digest}")]
    InvalidEnvironmentValue { key_digest: String },
    #[error("runtime launch token is invalid")]
    InvalidRuntimeLaunchToken,
    #[error("runtime process identity is invalid")]
    RuntimeProcessIdentityInvalid,
    #[error("runtime process identity could not be observed safely")]
    RuntimeProcessInspectionUnavailable,
    #[error("runtime launch artifact path, type, scope, or digest is invalid")]
    RuntimeLaunchArtifactInvalid,
    #[error("runtime launch artifact already exists and requires reconciliation")]
    RuntimeLaunchArtifactExists,
    #[error("runtime child did not expose stdin")]
    MissingStdin,
    #[error("runtime child did not expose stdout")]
    MissingStdout,
    #[error("runtime child did not expose stderr")]
    MissingStderr,
    #[error("runtime request identifier space is exhausted")]
    RequestIdExhausted,
    #[error("runtime request uses an unsupported stable method: {0}")]
    UnsupportedClientMethod(String),
    #[error("runtime request identifier is already pending: {0:?}")]
    DuplicateRequestId(RequestId),
    #[error("runtime server request identifier is not pending: {0:?}")]
    ServerRequestNotPending(RequestId),
    #[error("runtime JSON-RPC envelope is invalid")]
    InvalidJsonRpcEnvelope,
    #[error("runtime outbound message has {byte_count} bytes; maximum is {maximum}")]
    OutboundMessageTooLarge { byte_count: usize, maximum: usize },
    #[error("runtime write outcome is uncertain for {digest} ({kind:?})")]
    WriteOutcomeUncertain {
        digest: String,
        kind: std::io::ErrorKind,
    },
    #[error("runtime is protocol-poisoned and must be restarted")]
    RuntimePoisoned,
    #[error("runtime has already been shut down")]
    RuntimeAlreadyShutdown,
    #[error("runtime stdout and stderr are closed")]
    RuntimeStreamsClosed,
    #[error("runtime event wait timed out")]
    NextEventTimedOut,
    #[error("runtime timeout is outside the supported instant range")]
    TimeoutOutOfRange,
    #[error("runtime protocol violation {category} ({digest})")]
    ProtocolViolation { category: String, digest: String },
    #[error("runtime deferred event buffer reached its configured bound")]
    DeferredEventOverflow,
    #[error("runtime health check timed out ({request_digest})")]
    HealthCheckTimedOut { request_digest: String },
    #[error("runtime request {method} timed out ({request_digest})")]
    RequestTimedOut {
        method: String,
        request_digest: String,
    },
    #[error("runtime health check was rejected ({error_digest})")]
    HealthCheckRejected { error_digest: String },
    #[error("runtime thread request {method} was rejected ({error_digest})")]
    ThreadRequestRejected {
        method: String,
        error_digest: String,
    },
    #[error("runtime thread response for {method} is invalid ({response_digest})")]
    InvalidThreadResponse {
        method: String,
        response_digest: String,
    },
    #[error("runtime turn request is empty, malformed, or outside the active mapping")]
    InvalidTurnRequest,
    #[error("runtime turn request was rejected ({error_digest})")]
    TurnRequestRejected { error_digest: String },
    #[error("runtime turn interrupt was rejected ({error_digest})")]
    TurnInterruptRejected { error_digest: String },
    #[error("runtime turn response is invalid ({response_digest})")]
    InvalidTurnResponse { response_digest: String },
    #[error("runtime turn notification is invalid ({notification_digest})")]
    InvalidTurnNotification { notification_digest: String },
    #[error("runtime turn steer was rejected ({error_digest})")]
    TurnSteerRejected { error_digest: String },
    #[error("runtime agent message has {byte_count} bytes; maximum is {maximum}")]
    AgentMessageTooLarge { byte_count: usize, maximum: usize },
    #[error("runtime result packet is invalid")]
    InvalidRuntimeResultPacket,
    #[error("runtime resumed a different thread ({expected_digest} != {actual_digest})")]
    ThreadIdentityMismatch {
        expected_digest: String,
        actual_digest: String,
    },
    #[error("runtime mapping is invalid")]
    InvalidRuntimeMapping,
    #[error("runtime model identifier is invalid")]
    InvalidRuntimeModel,
    #[error("runtime secret reference is invalid")]
    InvalidSecretReference,
    #[error("resolved runtime secret material is invalid")]
    InvalidSecretMaterial,
    #[error("runtime secret binding is invalid")]
    InvalidSecretBinding,
    #[error("runtime secret resolution failed for {reference_digest}")]
    SecretResolutionFailed { reference_digest: String },
    #[error("runtime has too many secret bindings")]
    TooManySecretBindings,
    #[error("runtime secret environment keys must be unique")]
    DuplicateSecretEnvironmentKey,
    #[error("runtime secret binding collides with an explicit environment key")]
    SecretEnvironmentCollision,
    #[error("runtime secret bindings require an explicit secret resolver")]
    SecretResolverRequired,
    #[error("runtime catalog is invalid")]
    InvalidRuntimeCatalog,
    #[error("runtime catalog contains a duplicate provider, model, or harness")]
    DuplicateRuntimeCatalogEntry,
    #[error("runtime catalog response is malformed")]
    InvalidRuntimeCatalogResponse,
    #[error("runtime control-plane contract is invalid")]
    InvalidControlPlaneContract,
    #[error("runtime provider is not present in the pinned catalog")]
    RuntimeProviderUnavailable,
    #[error("runtime model is not present in the pinned catalog")]
    RuntimeModelUnavailable,
    #[error("runtime harness is not present in the pinned catalog")]
    RuntimeHarnessUnavailable,
    #[error("runtime catalog drift detected ({expected_digest} != {actual_digest})")]
    RuntimeCatalogDrift {
        expected_digest: String,
        actual_digest: String,
    },
    #[error("runtime configuration drift detected for {field}")]
    RuntimeConfigDrift { field: &'static str },
    #[error("runtime App Server schema drift detected ({expected_digest} != {actual_digest})")]
    RuntimeSchemaDrift {
        expected_digest: String,
        actual_digest: String,
    },
    #[error("runtime capability was not negotiated: {capability}")]
    CapabilityNotNegotiated { capability: &'static str },
    #[error("runtime execution configuration is invalid")]
    InvalidRuntimeExecutionConfig,
    #[error("runtime configuration request {method} was rejected ({error_digest})")]
    RuntimeConfigRequestRejected {
        method: String,
        error_digest: String,
    },
    #[error("runtime configuration response for {method} is invalid")]
    InvalidRuntimeConfigResponse { method: String },
    #[error("system clock is before the Unix epoch")]
    SystemClockBeforeUnixEpoch,
    #[error("runtime exited before completing the protocol operation: {exit_code:?}")]
    RuntimeExited { exit_code: Option<i32> },
    #[error("runtime exit status was not available after shutdown")]
    RuntimeExitStatusMissing,
    #[error("runtime reader thread panicked")]
    ReaderThreadPanicked,
    #[error("OpenInterpreter contract subset is invalid")]
    InvalidContract,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn shell_runtime(script: &str) -> RuntimeCommand {
        let mut command = RuntimeCommand::new(
            PathBuf::from("/bin/sh"),
            std::env::current_dir().expect("current directory"),
        );
        command.args = vec!["-c".to_owned(), script.to_owned()];
        command.shutdown_grace = Duration::from_millis(50);
        command
    }

    #[cfg(unix)]
    fn next_correlated_response(runtime: &mut StdioRuntime) -> JsonRpcResponse {
        for _ in 0..8 {
            if let RuntimeEvent::CorrelatedResponse { response, .. } = runtime
                .next_event(Duration::from_secs(1))
                .expect("runtime event")
            {
                return response;
            }
        }
        panic!("correlated response was not observed")
    }

    #[cfg(unix)]
    fn pinned_cleanup_fixture_runtime() -> RuntimeCommand {
        let program = std::env::current_exe().expect("current test executable");
        let mut command = RuntimeCommand::new(
            &program,
            std::env::current_dir().expect("current directory"),
        );
        command.expected_program_sha256 = Some(sha256_file(&program).expect("test binary digest"));
        command.args = vec![
            "--exact".into(),
            "tests::runtime_process_cleanup_fixture".into(),
            "--nocapture".into(),
        ];
        command.environment.insert(
            "HARTEVO_RUNTIME_PROCESS_CLEANUP_FIXTURE".into(),
            "run".into(),
        );
        command.shutdown_grace = Duration::from_millis(25);
        command
    }

    #[cfg(unix)]
    #[test]
    fn runtime_process_cleanup_fixture() {
        if std::env::var("HARTEVO_RUNTIME_PROCESS_CLEANUP_FIXTURE").as_deref() != Ok("run") {
            return;
        }
        loop {
            thread::sleep(Duration::from_mins(1));
        }
    }

    #[test]
    fn initialize_explicitly_disables_experimental_api() {
        let request = AppServerContract::initialize(RequestId::Number(1));
        assert_eq!(request.method, "initialize");
        assert_eq!(request.params["capabilities"]["experimentalApi"], false);
        let wire = serde_json::to_value(request).expect("wire request");
        assert!(wire.get("jsonrpc").is_none());
        let response: JsonRpcResponse = serde_json::from_value(json!({
            "id": 1,
            "result": {"codexHome": "/isolated/runtime/home"}
        }))
        .expect("upstream response without JSON-RPC member");
        assert_eq!(response.id, RequestId::Number(1));
    }

    #[test]
    fn stable_lifecycle_methods_are_pinned() {
        assert_eq!(
            AppServerContract::stable_methods().expect("contract"),
            vec![
                "initialize",
                "thread/start",
                "thread/resume",
                "turn/start",
                "turn/steer",
                "turn/interrupt",
                "interpreter/provider/list",
                "interpreter/provider/set",
                "interpreter/model/list",
                "interpreter/model/set",
                "interpreter/harness/list",
                "interpreter/harness/set",
            ]
        );
        assert_eq!(APP_SERVER_SCHEMA_SHA256.len(), 64);
        assert_eq!(AppServerContract::contract_subset_digest().len(), 64);
    }

    #[test]
    fn result_packet_is_schema_bound_and_debug_redacts_content() {
        let content = "private adopted result";
        let mut packet = RuntimeResultPacket {
            schema: RUNTIME_RESULT_PACKET_SCHEMA.to_owned(),
            authority: RuntimeResultAuthority::LocalExecutionEvidence,
            result_kind: RuntimeResultKind::AgentMessage,
            project_id: "project-result-packet".to_owned(),
            mission_id: "mission-result-packet".to_owned(),
            runtime_generation: 1,
            runtime_instance_digest: "a".repeat(64),
            runtime_commit: OPENINTERPRETER_COMMIT.to_owned(),
            runtime_release: OPENINTERPRETER_RELEASE.to_owned(),
            mapping_digest: digest_hex(b"mapping"),
            runtime_thread_id_digest: digest_hex(b"thread"),
            runtime_turn_id_digest: digest_hex(b"turn"),
            app_server_schema_digest: format!("sha256:{APP_SERVER_SCHEMA_SHA256}"),
            runtime_config_digest: digest_hex(b"config"),
            catalog_digest: digest_hex(b"catalog"),
            source_item_id_digest: digest_hex(b"item"),
            source_event_digest: digest_hex(b"event"),
            content_digest: digest_hex(content.as_bytes()),
            content_byte_count: content.len() as u64,
            content: content.to_owned(),
        };
        packet.validate().expect("valid result packet");
        let rendered = format!("{packet:?}");
        assert!(!rendered.contains(content));
        let wire = serde_json::to_value(&packet).expect("packet wire value");
        assert_eq!(wire["authority"], "local_execution_evidence");
        assert_eq!(wire["content"], content);

        packet.content_digest = digest_hex(b"drifted-content");
        assert!(matches!(
            packet.validate(),
            Err(AdapterError::InvalidRuntimeResultPacket)
        ));
    }

    #[test]
    fn artifact_catalog_covers_the_declared_desktop_matrix_without_fake_evidence() {
        let required = [
            ("aarch64-apple-darwin", "full"),
            ("x86_64-apple-darwin", "full"),
            ("aarch64-pc-windows-msvc", "full"),
            ("x86_64-pc-windows-msvc", "full"),
            ("x86_64-unknown-linux-musl", "compatibility"),
        ];
        for (target, support) in required {
            let artifact = pinned_runtime_artifact(target).expect("pinned artifact");
            assert_eq!(artifact.target, target);
            assert_eq!(artifact.product_support, support);
            assert!(is_sha256(&artifact.archive_sha256));
            if target != "aarch64-apple-darwin" {
                assert!(artifact.entrypoint_sha256.is_none());
                assert!(artifact.package_metadata_sha256.is_none());
            }
        }
        assert!(pinned_runtime_artifact("unsupported-target").is_err());
        assert!(host_openinterpreter_target().is_ok());
    }

    #[test]
    fn turn_contract_uses_v2_input_shape() {
        let request = AppServerContract::turn_start(
            RequestId::String("turn-request".into()),
            "runtime-thread-1",
            "Research the launch market",
        );
        assert_eq!(request.method, "turn/start");
        assert_eq!(request.params["threadId"], "runtime-thread-1");
        assert_eq!(request.params["input"][0]["type"], "text");
    }

    #[test]
    fn control_plane_contract_uses_exact_pinned_wire_keys() {
        let steer = AppServerContract::turn_steer(
            RequestId::Number(1),
            "thread-1",
            "turn-1",
            "message-1",
            "Continue with the bounded task.",
        );
        assert_eq!(steer.method, "turn/steer");
        assert_eq!(steer.params["expectedTurnId"], "turn-1");
        assert_eq!(steer.params["input"][0]["type"], "text");

        let provider = AppServerContract::provider_list(RequestId::Number(2), true);
        assert_eq!(provider.params["includeUnconfigured"], true);
        let model = AppServerContract::model_list(RequestId::Number(3), Some("openai"), false);
        assert_eq!(model.params["modelProvider"], "openai");
        let harness =
            AppServerContract::harness_list(RequestId::Number(4), "openai", Some("gpt-5.6"));
        assert_eq!(harness.params["providerId"], "openai");
        assert_eq!(harness.params["model"], "gpt-5.6");
        assert_eq!(
            AppServerContract::stable_server_requests().expect("server contract"),
            vec![
                "item/commandExecution/requestApproval",
                "item/fileChange/requestApproval"
            ]
        );
    }

    #[test]
    fn runtime_approval_is_not_a_business_effect_approval() {
        let response = AppServerContract::local_approval_response(RequestId::Number(9), true);
        assert_eq!(response.result.expect("result")["decision"], "accept");
        // The response intentionally has no Project, Effect, cost, consent, or policy fields.
        // Those belong to hartevo-effect-broker and cannot be inferred here.
    }

    #[test]
    fn notifications_are_classified_without_exposing_private_ids() {
        assert_eq!(
            RuntimeEventKind::from_method("item/completed"),
            RuntimeEventKind::ItemCompleted
        );
        assert_eq!(
            RuntimeEventKind::from_method("item/agentMessage/delta"),
            RuntimeEventKind::AgentMessageDelta
        );
        assert_eq!(
            RuntimeEventKind::from_method("future/event"),
            RuntimeEventKind::Unknown("future/event".into())
        );
    }

    #[test]
    fn command_debug_and_validation_do_not_expose_secrets() {
        let mut command = RuntimeCommand::new(
            PathBuf::from("/absolute/runtime"),
            PathBuf::from("/absolute/workspace"),
        );
        command.args.push("argument-secret-92bf".to_owned());
        command.environment.insert(
            "HARTEVO_TOKEN".to_owned(),
            "environment-secret-a15c".to_owned(),
        );
        let rendered = format!("{command:?}");
        assert!(!rendered.contains("argument-secret-92bf"));
        assert!(!rendered.contains("environment-secret-a15c"));
        assert!(rendered.contains("HARTEVO_TOKEN"));

        command
            .environment
            .insert("LD_PRELOAD".to_owned(), "/private/injection".to_owned());
        assert!(matches!(
            validate_runtime_command(&command),
            Err(AdapterError::ForbiddenEnvironmentKey { key }) if key == "LD_PRELOAD"
        ));
    }

    #[test]
    fn bounded_line_reader_never_retains_more_than_the_configured_limit() {
        let payload = vec![b'x'; 4096];
        let mut reader = BufReader::new(std::io::Cursor::new(payload));
        let frame = read_bounded_frame(&mut reader, 64)
            .expect("bounded read")
            .expect("frame");
        assert_eq!(frame.bytes.len(), 64);
        assert_eq!(frame.byte_count, 4096);
        assert!(frame.truncated);
        assert_eq!(frame.digest.len(), 71);
    }

    #[cfg(unix)]
    #[test]
    fn health_check_uses_exact_request_correlation() {
        let command = shell_runtime(
            r#"IFS= read -r request
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"fake-runtime"}}}'"#,
        );
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        let health = runtime
            .health_check(Duration::from_secs(1))
            .expect("health check");
        assert_ne!(health.process_id, 0);
        assert_eq!(health.runtime_instance_digest.len(), 64);
        assert_eq!(health.evidence_digest().len(), 64);
        assert_eq!(health.protocol_version, PROTOCOL_VERSION);
        assert_eq!(health.schema_digest.len(), 71);
        assert_eq!(runtime.config_digest().len(), 64);
        assert_eq!(runtime.instance_digest(), health.runtime_instance_digest);
        let report = runtime.shutdown().expect("shutdown");
        assert!(!report.forced);
        assert!(report.success);
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fake contract test intentionally exercises the complete credentialed lifecycle in one deterministic script"
    )]
    fn fake_credentialed_control_plane_lifecycle_is_exact_and_streamed() {
        struct FakeResolver;

        impl SecretResolver for FakeResolver {
            fn resolve(
                &self,
                _reference: &SecretReference,
            ) -> Result<ResolvedSecret, AdapterError> {
                ResolvedSecret::new("fake-secret")
            }
        }

        let workspace = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical workspace");
        let workspace_json =
            serde_json::to_string(&workspace.to_string_lossy()).expect("workspace json");
        let script = r#"
while IFS= read -r request; do
    case "$request" in
        *'"method":"initialize"'*)
            if [ "$OPENAI_API_KEY" != "fake-secret" ]; then exit 42; fi
            printf '%s\n' '{"jsonrpc":"2.0","id":'"$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"',"result":{"serverInfo":{"name":"fake-runtime"}}}'
            ;;
        *'"method":"interpreter/provider/list"'*)
            case "$request" in
                *'"id":2,'*|*'"id":6,'*|*'"id":9,'*)
                    printf '%s\n' '{"jsonrpc":"2.0","id":'"$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"',"result":{"data":[{"id":"openai","wireApi":"responses","envKey":"OPENAI_API_KEY","configured":true}]}}'
                    ;;
            esac
            ;;
        *'"method":"interpreter/model/list"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'"$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"',"result":{"data":[{"model":"gpt-5.6","supportedReasoningEfforts":[{"reasoningEffort":"medium"}],"serviceTiers":[{"id":"default"}]}]}}'
            ;;
        *'"method":"interpreter/harness/list"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'"$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"',"result":{"data":[{"id":null,"label":"Native","description":"","isRecommended":true}]}}'
            ;;
        *'"method":"interpreter/provider/set"'*|*'"method":"interpreter/model/set"'*|*'"method":"interpreter/harness/set"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'"$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"',"result":{}}'
            ;;
        *'"method":"thread/start"'*|*'"method":"thread/resume"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'"$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"',"result":{"thread":{"id":"thread-1"},"cwd":__WORKSPACE_JSON__,"model":"gpt-5.6","modelProvider":"openai","approvalPolicy":"on-request","approvalsReviewer":"user","sandbox":"workspace-write"}}'
            ;;
        *'"method":"turn/start"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'"$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"',"result":{"turn":{"id":"turn-1","status":"inProgress"}}}'
            printf '%s\n' '{"jsonrpc":"2.0","method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"inProgress"}}}'
            printf '%s\n' '{"jsonrpc":"2.0","method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","item":{"id":"item-1","type":"error","error":{"code":"rate_limit","message":"private runtime detail"}}}}'
            printf '%s\n' '{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turnId":"turn-1","turn":{"id":"turn-1","status":"failed"}}}'
            ;;
        *'"method":"turn/steer"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'"$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"',"result":{"turnId":"turn-1"}}'
            ;;
    esac
done
"#.replace("__WORKSPACE_JSON__", &workspace_json);
        let reference = SecretReference::new(
            "openai",
            "fake-account",
            "keyring/openai/fake",
            "f".repeat(64),
            1,
        )
        .expect("secret reference");
        let mut command = shell_runtime(&script);
        command
            .add_secret_binding("OPENAI_API_KEY", reference.clone())
            .expect("secret binding");
        let mut runtime =
            StdioRuntime::spawn_with_secret_resolver(&command, &FakeResolver).expect("runtime");

        let capabilities = runtime
            .negotiate_capabilities(Duration::from_secs(1))
            .expect("capability negotiation");
        assert!(capabilities.provider_catalog);
        assert!(capabilities.model_catalog);
        assert!(capabilities.harness_catalog);
        assert!(capabilities.steer);

        let catalog = runtime
            .discover_runtime_catalog("fake-runtime-catalog-v1", Duration::from_secs(1))
            .expect("runtime catalog");
        let provider = catalog.provider("openai").expect("provider");
        let model = catalog.model("openai", "gpt-5.6").expect("model");
        let harness = catalog
            .harness("openai", "gpt-5.6", "native")
            .expect("harness");
        let config = RuntimeExecutionConfig::new(
            provider.id.clone(),
            provider.revision.clone(),
            model.id.clone(),
            model.revision.clone(),
            "native",
            harness.revision.clone(),
            Some("medium".to_owned()),
            Some("default".to_owned()),
            RuntimeEndpointClass::Responses,
            RuntimeBudget::new(8_192, 4_096, 8, 60_000).expect("budget"),
            RuntimeDataBoundary::ProviderDeclared,
            reference,
            catalog.digest().expect("catalog digest"),
        )
        .expect("execution config");
        assert!(
            catalog
                .secret_binding(&config)
                .expect("secret binding")
                .is_some()
        );

        let mapping = runtime
            .start_mapped_thread_with_config(
                "project-fake-control-plane",
                "mission-fake-control-plane",
                1,
                &workspace,
                &capabilities,
                &catalog,
                &config,
                Duration::from_secs(1),
            )
            .expect("configured thread");
        let mapping = runtime
            .resume_mapped_thread_with_config(
                "project-fake-control-plane",
                "mission-fake-control-plane",
                1,
                &mapping.runtime_thread_id,
                &workspace,
                &capabilities,
                &catalog,
                &config,
                Duration::from_secs(1),
            )
            .expect("configured resume");
        let dispatch = runtime
            .start_mapped_turn_with_config(
                &mapping,
                &config,
                "message-fake-control-plane",
                "Return a short readiness response.",
                Duration::from_secs(1),
            )
            .expect("configured turn");
        runtime
            .steer_mapped_turn(
                &dispatch.mapping,
                "steer-fake-control-plane",
                "Stop and report the current state.",
                Duration::from_secs(1),
            )
            .expect("typed steer");

        assert!(matches!(
            runtime
                .next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(1))
                .expect("turn started"),
            MappedTurnEvent {
                kind: MappedTurnEventKind::TurnStarted,
                ..
            }
        ));
        let item = runtime
            .next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(1))
            .expect("item completed");
        assert_eq!(
            item.recovery_hint.expect("recovery hint").action,
            RuntimeRecoveryAction::ReconcileBeforeRetry
        );
        assert!(matches!(
            runtime
                .next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(1))
                .expect("turn completed")
                .kind,
            MappedTurnEventKind::TurnCompleted(RuntimeTurnCompletionStatus::Failed)
        ));
        runtime.shutdown().expect("shutdown");
    }

    #[cfg(unix)]
    #[test]
    fn async_stdout_and_stderr_are_bounded_correlated_and_redacted() {
        let command = shell_runtime(
            r#"IFS= read -r request
printf '%s\n' 'stderr-private-token-7d91' >&2
printf '%s\n' '{"jsonrpc":"2.0","method":"thread/started","params":{"private":"notification-secret-bb13"}}'
printf '%s\n' '{"jsonrpc":"2.0","id":41,"result":{"thread":{"id":"runtime-thread"}}}'"#,
        );
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        runtime
            .send_request(&AppServerContract::initialize(RequestId::Number(41)))
            .expect("send initialize");

        let mut saw_response = false;
        let mut saw_notification = false;
        let mut saw_stderr = false;
        for _ in 0..8 {
            let event = runtime
                .next_event(Duration::from_secs(1))
                .expect("runtime event");
            let rendered = format!("{event:?}");
            assert!(!rendered.contains("stderr-private-token-7d91"));
            assert!(!rendered.contains("notification-secret-bb13"));
            match event {
                RuntimeEvent::CorrelatedResponse {
                    id,
                    method,
                    request_digest,
                    ..
                } => {
                    assert_eq!(id, RequestId::Number(41));
                    assert_eq!(method, "initialize");
                    assert_eq!(request_digest.len(), 71);
                    saw_response = true;
                }
                RuntimeEvent::Notification { kind, .. } => {
                    assert_eq!(kind, RuntimeEventKind::ThreadStarted);
                    saw_notification = true;
                }
                RuntimeEvent::Diagnostic(diagnostic) => {
                    assert_eq!(diagnostic.stream, RuntimeStream::Stderr);
                    assert_eq!(diagnostic.digest.len(), 71);
                    saw_stderr = true;
                }
                RuntimeEvent::StdoutClosed | RuntimeEvent::StderrClosed => {}
                other => panic!("unexpected event: {other:?}"),
            }
            if saw_response && saw_notification && saw_stderr {
                break;
            }
        }
        assert!(saw_response && saw_notification && saw_stderr);
        runtime.shutdown().expect("shutdown");
    }

    #[cfg(unix)]
    #[test]
    fn cleared_environment_only_adds_valid_explicit_values() {
        let command_script = r#"IFS= read -r request
clean=false
if [ -z "${HOME+x}" ] && [ "$HARTEVO_RUNTIME_TEST" = "allowed" ]; then clean=true; fi
printf '{"jsonrpc":"2.0","id":3,"result":{"clean":%s}}\n' "$clean""#;
        let mut command = shell_runtime(command_script);
        command
            .environment
            .insert("HARTEVO_RUNTIME_TEST".to_owned(), "allowed".to_owned());
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        runtime
            .send_request(&AppServerContract::initialize(RequestId::Number(3)))
            .expect("send initialize");
        let response = next_correlated_response(&mut runtime);
        assert_eq!(response.result.expect("result")["clean"], true);
        runtime.shutdown().expect("shutdown");
    }

    #[cfg(unix)]
    #[test]
    fn isolated_runtime_home_is_declared_echoed_and_digest_only() {
        let sandbox = tempfile::tempdir().expect("runtime sandbox");
        let runtime_home = sandbox.path().join("runtime-home");
        std::fs::create_dir(&runtime_home).expect("runtime home");
        let reported_home = runtime_home
            .canonicalize()
            .expect("canonical runtime home")
            .to_string_lossy()
            .into_owned();
        let response = json!({"id": 1, "result": {"codexHome": reported_home}});
        let script = format!("IFS= read -r initialize\nprintf '%s\\n' '{response}'\nsleep 20");
        let mut command = shell_runtime(&script);
        command.openinterpreter_home = Some(runtime_home.clone());
        command.environment.insert(
            "INTERPRETER_HOME".to_owned(),
            runtime_home.to_string_lossy().into_owned(),
        );
        let mut runtime = StdioRuntime::spawn(&command).expect("isolated runtime");
        let health = runtime
            .health_check(Duration::from_secs(1))
            .expect("isolated health");
        assert_eq!(
            health.runtime_home_digest.as_deref().map(str::len),
            Some(71)
        );
        assert!(!format!("{health:?}").contains(&reported_home));
        assert!(runtime.shutdown().expect("shutdown").forced);

        let mut undeclared = shell_runtime("exit 0");
        undeclared.environment.insert(
            "INTERPRETER_HOME".to_owned(),
            runtime_home.to_string_lossy().into_owned(),
        );
        assert!(matches!(
            validate_runtime_command(&undeclared),
            Err(AdapterError::RuntimeHomeUnverified)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_home_mismatch_poisoning_fails_closed() {
        let sandbox = tempfile::tempdir().expect("runtime sandbox");
        let expected = sandbox.path().join("expected");
        let foreign = sandbox.path().join("foreign");
        std::fs::create_dir(&expected).expect("expected home");
        std::fs::create_dir(&foreign).expect("foreign home");
        let response = json!({
            "id": 1,
            "result": {"codexHome": foreign.canonicalize().expect("foreign canonical")}
        });
        let script = format!("IFS= read -r initialize\nprintf '%s\\n' '{response}'\nsleep 20");
        let mut command = shell_runtime(&script);
        command.openinterpreter_home = Some(expected.clone());
        command.environment.insert(
            "INTERPRETER_HOME".to_owned(),
            expected.to_string_lossy().into_owned(),
        );
        let mut runtime = StdioRuntime::spawn(&command).expect("runtime");
        assert!(matches!(
            runtime.health_check(Duration::from_secs(1)),
            Err(AdapterError::RuntimeHomeMismatch { .. })
        ));
        assert!(matches!(
            runtime.send_request(&AppServerContract::initialize(RequestId::Number(2))),
            Err(AdapterError::RuntimePoisoned)
        ));
        assert!(runtime.shutdown().expect("shutdown").forced);
    }

    #[test]
    #[ignore = "requires the pinned HARTEVO_TEST_OPENINTERPRETER_BIN package and an isolated writable HARTEVO_TEST_OPENINTERPRETER_HOME"]
    fn real_openinterpreter_isolated_credentialless_turn_fails_closed() {
        let program = std::env::var_os("HARTEVO_TEST_OPENINTERPRETER_BIN")
            .map(PathBuf::from)
            .expect("HARTEVO_TEST_OPENINTERPRETER_BIN");
        let runtime_home = std::env::var_os("HARTEVO_TEST_OPENINTERPRETER_HOME")
            .map(PathBuf::from)
            .expect("HARTEVO_TEST_OPENINTERPRETER_HOME");
        let workspace = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical workspace");
        let verified = verify_pinned_runtime_artifact(
            &program,
            host_openinterpreter_target().expect("host target"),
        )
        .expect("verified release package");
        assert!(!verified.distribution_ready());
        let command = verified
            .runtime_command(&workspace, &runtime_home)
            .expect("isolated pinned command");
        let mut runtime = StdioRuntime::spawn(&command).expect("real app server");
        let health = runtime
            .health_check(Duration::from_secs(10))
            .expect("real app-server initialize");
        assert_eq!(
            health.schema_digest,
            format!("sha256:{APP_SERVER_SCHEMA_SHA256}")
        );
        assert!(health.runtime_home_digest.is_some());
        assert!(health.program_integrity_pinned);
        let mapping = runtime
            .start_mapped_thread(
                "project-real-runtime-smoke",
                "mission-real-runtime-smoke",
                1,
                &workspace,
                None,
                Duration::from_secs(10),
            )
            .expect("real thread/start");
        assert_eq!(mapping.project_id, "project-real-runtime-smoke");
        assert_eq!(mapping.mission_id, "mission-real-runtime-smoke");
        assert_eq!(mapping.runtime_generation, 1);
        assert_eq!(mapping.schema_digest, health.schema_digest);
        let rendered = format!("{mapping:?}");
        assert!(!rendered.contains(&mapping.runtime_thread_id));
        assert!(!rendered.contains(&mapping.runtime_model));
        let dispatch = runtime
            .start_mapped_turn(
                &mapping,
                "hartevo-real-runtime-credentialless-turn",
                "Return a short plain-text readiness response without using tools.",
                Duration::from_secs(10),
            )
            .expect("credentialless turn accepted into runtime");
        let mut terminal = None;
        for _ in 0..64 {
            let event = runtime
                .next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(10))
                .expect("credentialless turn event");
            if let MappedTurnEventKind::TurnCompleted(status) = event.kind {
                terminal = Some(status);
                break;
            }
        }
        assert_eq!(terminal, Some(RuntimeTurnCompletionStatus::Failed));
        runtime.shutdown().expect("real runtime shutdown");
    }

    #[cfg(unix)]
    #[test]
    fn unmatched_response_poisoning_fails_closed() {
        let command = shell_runtime(
            r#"printf '%s\n' '{"jsonrpc":"2.0","id":999,"result":{}}'
sleep 20"#,
        );
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        let event = runtime
            .next_event(Duration::from_secs(1))
            .expect("protocol event");
        assert!(matches!(
            event,
            RuntimeEvent::ProtocolViolation(RuntimeDiagnostic { category, .. })
                if category == "unmatched_response"
        ));
        assert!(matches!(
            runtime.send_request(&AppServerContract::initialize(RequestId::Number(1))),
            Err(AdapterError::RuntimePoisoned)
        ));
        assert!(runtime.shutdown().expect("shutdown").forced);
    }

    #[cfg(unix)]
    #[test]
    fn local_runtime_approval_requires_a_pending_server_request() {
        let command = shell_runtime(
            r#"IFS= read -r initialize
printf '%s\n' '{"jsonrpc":"2.0","id":5,"result":{}}'
printf '%s\n' '{"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"command":"private-command"}}'
IFS= read -r approval
case "$approval" in *'"decision":"accept"'*) approved=true ;; *) approved=false ;; esac
printf '{"jsonrpc":"2.0","method":"turn/completed","params":{"approved":%s}}\n' "$approved""#,
        );
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        runtime
            .send_request(&AppServerContract::initialize(RequestId::Number(5)))
            .expect("send initialize");
        let _ = next_correlated_response(&mut runtime);
        let request_id = loop {
            match runtime
                .next_event(Duration::from_secs(1))
                .expect("server request")
            {
                RuntimeEvent::ServerRequest { kind, request } => {
                    assert_eq!(kind, RuntimeEventKind::LocalApprovalRequested);
                    assert!(!format!("{request:?}").contains("private-command"));
                    break request.id;
                }
                RuntimeEvent::Diagnostic(_) | RuntimeEvent::StderrClosed => {}
                other => panic!("unexpected event: {other:?}"),
            }
        };
        runtime
            .send_response(&AppServerContract::local_approval_response(
                request_id.clone(),
                true,
            ))
            .expect("approval response");
        assert!(matches!(
            runtime.send_response(&AppServerContract::local_approval_response(
                request_id, true
            )),
            Err(AdapterError::ServerRequestNotPending(_))
        ));
        let event = runtime
            .next_event(Duration::from_secs(1))
            .expect("completion notification");
        assert!(matches!(
            event,
            RuntimeEvent::Notification {
                kind: RuntimeEventKind::TurnCompleted,
                ..
            }
        ));
        runtime.shutdown().expect("shutdown");
    }

    #[cfg(unix)]
    #[test]
    fn oversized_stdout_is_digest_only_and_poisoned() {
        let mut command = shell_runtime("printf '%0100d\\n' 0; sleep 20");
        command.max_line_bytes = 64;
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        let event = runtime
            .next_event(Duration::from_secs(1))
            .expect("protocol event");
        assert!(matches!(
            event,
            RuntimeEvent::ProtocolViolation(RuntimeDiagnostic {
                category,
                byte_count: 101,
                truncated: true,
                ..
            }) if category == "stdout_line_too_large"
        ));
        assert!(runtime.shutdown().expect("shutdown").forced);
    }

    #[cfg(unix)]
    #[test]
    fn health_timeout_is_poisoned_and_process_group_shutdown_kills_descendants() {
        let command = shell_runtime(
            r#"IFS= read -r request
sleep 20 &
descendant=$!
printf '{"jsonrpc":"2.0","id":8,"result":{"descendant":%s}}\n' "$descendant"
wait"#,
        );
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        runtime
            .send_request(&AppServerContract::initialize(RequestId::Number(8)))
            .expect("send initialize");
        let response = next_correlated_response(&mut runtime);
        let descendant = response.result.expect("result")["descendant"]
            .as_u64()
            .expect("descendant pid")
            .to_string();
        let report = runtime.shutdown().expect("shutdown process group");
        assert!(report.forced);

        let mut gone = false;
        for _ in 0..20 {
            let status = Command::new("/bin/kill")
                .args(["-0", &descendant])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("probe descendant");
            if !status.success() {
                gone = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(gone, "descendant process survived process-group shutdown");

        let timeout_command = shell_runtime("IFS= read -r request; sleep 20");
        let mut timeout_runtime =
            StdioRuntime::spawn(&timeout_command).expect("spawn timeout runtime");
        assert!(matches!(
            timeout_runtime.health_check(Duration::from_millis(25)),
            Err(AdapterError::HealthCheckTimedOut { .. })
        ));
        assert!(timeout_runtime.shutdown().expect("shutdown timeout").forced);
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_launch_root_is_parallel_idempotent_and_rejects_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::sync::{Arc, Barrier};

        let directory = tempfile::tempdir().expect("temporary launch base");
        let launch_root = Arc::new(directory.path().join(".hartevo-runtime-launches"));
        let barrier = Arc::new(Barrier::new(8));
        let workers = (0..8)
            .map(|_| {
                let launch_root = Arc::clone(&launch_root);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    create_private_runtime_directory(&launch_root)
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker
                .join()
                .expect("directory creator thread")
                .expect("parallel directory creation");
        }
        let metadata = fs::symlink_metadata(launch_root.as_path()).expect("launch root metadata");
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

        let symlink_path = directory.path().join("forged-runtime-launches");
        symlink(launch_root.as_path(), &symlink_path).expect("symlink fixture");
        assert!(matches!(
            create_private_runtime_directory(&symlink_path),
            Err(AdapterError::RuntimeLaunchArtifactInvalid)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn exact_launch_token_cleanup_reaps_forgotten_runtime_without_pid_reuse_risk() {
        let token = "9".repeat(64);
        let command = pinned_cleanup_fixture_runtime();
        let launch = prepare_runtime_launch(&command, &token).expect("launch spec");
        let runtime =
            StdioRuntime::spawn_prepared(&command, &launch).expect("spawn token-bound runtime");
        let identity = runtime.process_identity().clone();
        let rendered = format!("{runtime:?}");
        assert!(!rendered.contains(&token));
        std::mem::forget(runtime);

        let target = RuntimeProcessCleanupTarget::new(
            token,
            launch.executable_path().to_path_buf(),
            launch.executable_path_digest().to_owned(),
            launch.program_sha256().to_owned(),
            Some(identity),
        )
        .expect("exact cleanup target");
        let report = cleanup_runtime_process(&target, Duration::from_millis(250))
            .expect("cleanup forgotten runtime");
        assert_eq!(report.disposition, ProcessCleanupDisposition::Terminated);
        assert!(report.matched_process_count >= 1);
        assert!(report.signalled_process_count >= 1);
        assert_eq!(report.remaining_process_count, 0);
        assert_eq!(report.evidence_digest.len(), 64);

        let replay = cleanup_runtime_process(&target, Duration::from_millis(50))
            .expect("idempotent cleanup replay");
        assert_eq!(replay.disposition, ProcessCleanupDisposition::AlreadyExited);
        assert_eq!(replay.signalled_process_count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn forged_launch_token_never_kills_an_identity_matching_live_runtime() {
        let token = "a".repeat(64);
        let command = pinned_cleanup_fixture_runtime();
        let launch = prepare_runtime_launch(&command, &token).expect("launch spec");
        let mut runtime =
            StdioRuntime::spawn_prepared(&command, &launch).expect("spawn token-bound runtime");
        let forged_launch =
            prepare_runtime_launch(&command, &"b".repeat(64)).expect("forged launch spec");
        let forged = RuntimeProcessCleanupTarget::new(
            "b".repeat(64),
            forged_launch.executable_path().to_path_buf(),
            forged_launch.executable_path_digest().to_owned(),
            forged_launch.program_sha256().to_owned(),
            Some(runtime.process_identity().clone()),
        )
        .expect("forged target shape");
        let report = cleanup_runtime_process(&forged, Duration::from_millis(25))
            .expect("fail-closed inspection");
        assert_eq!(
            report.disposition,
            ProcessCleanupDisposition::InspectionBlocked
        );
        assert!(runtime.poll_exit().expect("live runtime poll").is_none());
        assert!(runtime.shutdown().expect("exact owner shutdown").forced);
    }

    #[cfg(unix)]
    #[test]
    fn mapped_thread_start_validates_schema_scope_and_preserves_stream_events() {
        let workspace = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical workspace");
        let binding = json!({
            "thread": {"id": "runtime-thread-private-1"},
            "cwd": workspace,
            "model": "fake-model",
            "modelProvider": "fake-provider",
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandbox": "workspace-write"
        });
        let script = format!(
            "IFS= read -r initialize\nprintf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{}}}}'\nIFS= read -r start\nprintf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"thread/started\",\"params\":{{\"private\":\"stream-secret\"}}}}'\nprintf '%s\\n' '{}'\nsleep 20",
            json!({"jsonrpc": "2.0", "id": 2, "result": binding})
        );
        let command = shell_runtime(&script);
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        runtime
            .health_check(Duration::from_secs(1))
            .expect("health check");
        let mapping = runtime
            .start_mapped_thread(
                "project-runtime-1",
                "mission-runtime-1",
                7,
                &workspace,
                Some("fake-model"),
                Duration::from_secs(1),
            )
            .expect("start mapped thread");
        assert_eq!(mapping.runtime_generation, 7);
        assert_eq!(mapping.runtime_thread_id, "runtime-thread-private-1");
        assert_eq!(mapping.runtime_model, "fake-model");
        assert_eq!(mapping.runtime_model_provider, "fake-provider");
        assert_eq!(mapping.runtime_instance_digest, runtime.instance_digest());
        assert_eq!(mapping.digest().expect("mapping digest").len(), 64);
        assert!(!format!("{mapping:?}").contains("runtime-thread-private-1"));
        assert!(!format!("{mapping:?}").contains("fake-provider"));
        let deferred = runtime
            .next_event(Duration::from_secs(1))
            .expect("deferred notification");
        assert!(matches!(
            deferred,
            RuntimeEvent::Notification {
                kind: RuntimeEventKind::ThreadStarted,
                ..
            }
        ));
        assert!(!format!("{deferred:?}").contains("stream-secret"));
        assert!(runtime.shutdown().expect("shutdown").forced);
    }

    #[cfg(unix)]
    #[test]
    fn resumed_thread_identity_mismatch_poisoning_fails_closed() {
        let workspace = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical workspace");
        let binding = json!({
            "thread": {"id": "wrong-runtime-thread"},
            "cwd": workspace,
            "model": "fake-model",
            "modelProvider": "fake-provider",
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandbox": "workspace-write"
        });
        let script = format!(
            "IFS= read -r resume\nprintf '%s\\n' '{}'\nsleep 20",
            json!({"jsonrpc": "2.0", "id": 1, "result": binding})
        );
        let command = shell_runtime(&script);
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        assert!(matches!(
            runtime.resume_mapped_thread(
                "project-runtime-1",
                "mission-runtime-1",
                8,
                "expected-runtime-thread",
                &workspace,
                Duration::from_secs(1),
            ),
            Err(AdapterError::ThreadIdentityMismatch { .. })
        ));
        assert!(matches!(
            runtime.send_request(&AppServerContract::initialize(RequestId::Number(2))),
            Err(AdapterError::RuntimePoisoned)
        ));
        assert!(runtime.shutdown().expect("shutdown").forced);
    }

    #[cfg(unix)]
    #[test]
    fn mapped_turn_lifecycle_is_identity_checked_streamed_and_redacted() {
        let script = r#"IFS= read -r turn
case "$turn" in *'"clientUserMessageId":"application-turn-private"'*'runtime-context-private'*) ;; *) exit 41 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","method":"turn/started","params":{"threadId":"runtime-thread-private","turn":{"id":"runtime-turn-private","status":"inProgress"}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"turn":{"id":"runtime-turn-private","status":"inProgress"}}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"item/started","params":{"threadId":"runtime-thread-private","turnId":"runtime-turn-private","item":{"id":"private-item","type":"agentMessage","text":"private-stream"}}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"item/agentMessage/delta","params":{"threadId":"runtime-thread-private","turnId":"runtime-turn-private","itemId":"private-item","delta":"private-"}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"item/agentMessage/delta","params":{"threadId":"runtime-thread-private","turnId":"runtime-turn-private","itemId":"private-item","delta":"result"}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"item/completed","params":{"threadId":"runtime-thread-private","turnId":"runtime-turn-private","item":{"id":"private-item","type":"agentMessage","text":"private-result"}}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"runtime-thread-private","turn":{"id":"runtime-turn-private","status":"completed","items":[]}}}'
sleep 20"#;
        let command = shell_runtime(script);
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        let mapping = RuntimeMapping::new(
            "project-runtime-turn",
            "mission-runtime-turn",
            4,
            runtime.instance_digest(),
            "fake-model",
            "fake-provider",
            "runtime-thread-private",
        )
        .expect("mapping");
        let dispatch = runtime
            .start_mapped_turn(
                &mapping,
                "application-turn-private",
                "runtime-context-private",
                Duration::from_secs(1),
            )
            .expect("dispatch turn");
        assert_eq!(
            dispatch.mapping.runtime_turn_id.as_deref(),
            Some("runtime-turn-private")
        );
        assert_eq!(dispatch.request_digest.len(), 64);
        assert_eq!(dispatch.response_digest.len(), 64);
        let debug = format!("{dispatch:?}");
        assert!(!debug.contains("runtime-context-private"));
        assert!(!debug.contains("runtime-thread-private"));
        assert!(!debug.contains("runtime-turn-private"));

        let expected = [
            MappedTurnEventKind::TurnStarted,
            MappedTurnEventKind::ItemStarted,
            MappedTurnEventKind::AgentMessageDelta,
            MappedTurnEventKind::AgentMessageDelta,
            MappedTurnEventKind::ItemCompleted,
            MappedTurnEventKind::TurnCompleted(RuntimeTurnCompletionStatus::Completed),
        ];
        for kind in expected {
            let event = runtime
                .next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(1))
                .expect("mapped event");
            assert_eq!(event.kind, kind);
            assert_eq!(event.event_digest.len(), 64);
            if event.kind == MappedTurnEventKind::ItemCompleted {
                let message = event.agent_message.as_ref().expect("transient result");
                assert_eq!(message.as_str(), "private-result");
                assert_eq!(message.byte_count, 14);
                assert_eq!(message.item_id_digest, digest_hex(b"private-item"));
                assert_eq!(message.content_digest, digest_hex(b"private-result"));
                assert!(event.agent_message_delta.is_none());
            } else if event.kind == MappedTurnEventKind::AgentMessageDelta {
                let delta = event
                    .agent_message_delta
                    .as_ref()
                    .expect("transient text delta");
                assert_eq!(delta.item_id_digest, digest_hex(b"private-item"));
                assert!(!delta.as_str().is_empty());
                assert_eq!(delta.content_digest, digest_hex(delta.as_str().as_bytes()));
                assert!(event.agent_message.is_none());
            } else {
                assert!(event.agent_message_delta.is_none());
                assert!(event.agent_message.is_none());
            }
            let debug = format!("{event:?}");
            assert!(!debug.contains("private-stream"));
            assert!(!debug.contains("private-result"));
        }
        assert!(runtime.shutdown().expect("shutdown").forced);
    }

    #[cfg(unix)]
    #[test]
    fn mapped_turn_local_approval_and_interrupt_are_exactly_correlated() {
        let script = r#"IFS= read -r turn
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"turn":{"id":"runtime-turn-approval","status":"inProgress"}}}'
printf '%s\n' '{"id":"approval-private","method":"item/commandExecution/requestApproval","params":{"threadId":"runtime-thread-approval","turnId":"runtime-turn-approval","itemId":"private-item","command":"private-command"}}'
IFS= read -r approval
case "$approval" in *'"id":"approval-private"'*'"decision":"accept"'*) ;; *) exit 42 ;; esac
IFS= read -r interrupt
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"runtime-thread-approval","turn":{"id":"runtime-turn-approval","status":"interrupted"}}}'
sleep 20"#;
        let command = shell_runtime(script);
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        let mapping = RuntimeMapping::new(
            "project-runtime-approval",
            "mission-runtime-approval",
            3,
            runtime.instance_digest(),
            "fake-model",
            "fake-provider",
            "runtime-thread-approval",
        )
        .expect("mapping");
        let dispatch = runtime
            .start_mapped_turn(
                &mapping,
                "application-turn-approval",
                "approval-safe-context",
                Duration::from_secs(1),
            )
            .expect("dispatch");
        let approval = runtime
            .next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(1))
            .expect("approval event");
        assert_eq!(
            approval.kind,
            MappedTurnEventKind::LocalApprovalRequested(RuntimeLocalApprovalKind::CommandExecution)
        );
        let request = approval.approval_request.expect("approval request");
        assert!(!format!("{request:?}").contains("approval-private"));
        assert_eq!(
            runtime
                .respond_to_mapped_turn_approval(&dispatch.mapping, &request, true)
                .expect("approval response")
                .len(),
            64
        );
        let interrupt = runtime
            .interrupt_mapped_turn(&dispatch.mapping, Duration::from_secs(1))
            .expect("interrupt");
        assert_eq!(interrupt.request_digest.len(), 64);
        assert_eq!(interrupt.response_digest.len(), 64);
        let completed = runtime
            .next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(1))
            .expect("completion");
        assert_eq!(
            completed.kind,
            MappedTurnEventKind::TurnCompleted(RuntimeTurnCompletionStatus::Interrupted)
        );
        assert!(runtime.shutdown().expect("shutdown").forced);
    }

    #[cfg(unix)]
    #[test]
    fn mismatched_turn_notification_poisoning_fails_closed() {
        let script = r#"IFS= read -r turn
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"turn":{"id":"runtime-turn-expected","status":"inProgress"}}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"turn/started","params":{"threadId":"runtime-thread-foreign","turn":{"id":"runtime-turn-expected","status":"inProgress"}}}'
sleep 20"#;
        let command = shell_runtime(script);
        let mut runtime = StdioRuntime::spawn(&command).expect("spawn fake runtime");
        let mapping = RuntimeMapping::new(
            "project-runtime-mismatch",
            "mission-runtime-mismatch",
            2,
            runtime.instance_digest(),
            "fake-model",
            "fake-provider",
            "runtime-thread-expected",
        )
        .expect("mapping");
        let dispatch = runtime
            .start_mapped_turn(
                &mapping,
                "application-turn-mismatch",
                "bounded-context",
                Duration::from_secs(1),
            )
            .expect("dispatch");
        assert!(matches!(
            runtime.next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(1)),
            Err(AdapterError::ProtocolViolation { category, .. })
                if category == "turn_identity_mismatch"
        ));
        assert!(matches!(
            runtime.interrupt_mapped_turn(&dispatch.mapping, Duration::from_secs(1)),
            Err(AdapterError::RuntimePoisoned)
        ));
        assert!(runtime.shutdown().expect("shutdown").forced);
    }
}

//! OpenInterpreter as a Runtime service-provider plugin.
//!
//! The provider owns only the Runtime-facing composition boundary. A Mission supplies an exact
//! catalog/configuration, scope, policy, secret resolver, and durable session-log implementation;
//! this module never becomes the authority for Mission state or external effects.

use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    AdapterError, MappedTurnEvent, MappedTurnEventKind, OPENINTERPRETER_COMMIT,
    OPENINTERPRETER_RELEASE, RuntimeCapabilities, RuntimeCatalog, RuntimeCommand,
    RuntimeExecutionConfig, RuntimeLocalApprovalKind, RuntimeMapping, RuntimePluginMount,
    RuntimePluginMountState, RuntimePluginRegistrationKind, RuntimePluginRegistrationStopper,
    RuntimePluginScope, RuntimePluginTeardownReceipt, RuntimeProtocolWriteReceipt,
    RuntimeRecoveryHint, RuntimeResultPacket, RuntimeServiceCapability, RuntimeServiceDefinition,
    RuntimeServiceProviderManifest, RuntimeTurnCompletionStatus, RuntimeTurnDispatch,
    SecretResolver, ShutdownReport, StdioRuntime, VerifiedRuntimeArtifact,
};

pub const OPENINTERPRETER_RUNTIME_SERVICE_ID: &str = "runtime.execution";
pub const OPENINTERPRETER_RUNTIME_SERVICE_REVISION: &str = "v1";
pub const OPENINTERPRETER_PROVIDER_ID: &str = "openinterpreter";
pub const RUNTIME_MODEL_VISIBLE_EVENT_SCHEMA: &str = "hartevo.runtime-model-visible-event/v1";
const MAX_POLICY_CURRENCY_BYTES: usize = 8;
const MAX_DURABLE_CONTENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SESSION_IDENTIFIER_BYTES: usize = 1_024;

/// A bounded policy attached to one provider session.
///
/// max_cost_microunits is a policy ceiling, not a fabricated charge or provider receipt. A real
/// Mission ledger remains responsible for reconciling provider usage and cost.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeProviderPolicy {
    pub max_stream_events: u32,
    pub max_stream_bytes: u64,
    pub max_cost_microunits: u64,
    pub cost_currency: String,
}

impl RuntimeProviderPolicy {
    pub fn new(
        max_stream_events: u32,
        max_stream_bytes: u64,
        max_cost_microunits: u64,
        cost_currency: impl Into<String>,
    ) -> Result<Self, RuntimeProviderError> {
        let policy = Self {
            max_stream_events,
            max_stream_bytes,
            max_cost_microunits,
            cost_currency: cost_currency.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), RuntimeProviderError> {
        if self.max_stream_events == 0
            || self.max_stream_events > 1_000_000
            || self.max_stream_bytes == 0
            || self.max_stream_bytes > 64 * 1024 * 1024
            || self.cost_currency.is_empty()
            || self.cost_currency.len() > MAX_POLICY_CURRENCY_BYTES
            || !self
                .cost_currency
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(RuntimeProviderError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, RuntimeProviderError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(AdapterError::from)?;
        Ok(super::digest_hex(&bytes))
    }
}

/// The content-bearing events this consumer commits to the Mission/session log.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableModelVisibleEventKind {
    Input,
    AssistantDelta,
    AssistantResult,
}

/// An exact-scope model-visible event. The body is private-session content; Debug is redacted.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DurableModelVisibleEvent {
    pub schema: String,
    pub sequence: u64,
    pub scope_digest: String,
    pub provider_manifest_digest: String,
    pub runtime_config_digest: String,
    pub catalog_digest: String,
    pub policy_digest: String,
    pub kind: DurableModelVisibleEventKind,
    pub source_item_id_digest: String,
    pub source_event_digest: String,
    pub content_digest: String,
    pub content_byte_count: u64,
    pub content: String,
    pub event_digest: String,
}

impl fmt::Debug for DurableModelVisibleEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableModelVisibleEvent")
            .field("schema", &self.schema)
            .field("sequence", &self.sequence)
            .field("scope_digest", &self.scope_digest)
            .field("provider_manifest_digest", &self.provider_manifest_digest)
            .field("runtime_config_digest", &self.runtime_config_digest)
            .field("catalog_digest", &self.catalog_digest)
            .field("policy_digest", &self.policy_digest)
            .field("kind", &self.kind)
            .field("source_item_id_digest", &self.source_item_id_digest)
            .field("source_event_digest", &self.source_event_digest)
            .field("content_digest", &self.content_digest)
            .field("content_byte_count", &self.content_byte_count)
            .field("content", &"<redacted>")
            .field("event_digest", &self.event_digest)
            .finish()
    }
}

impl DurableModelVisibleEvent {
    pub fn validate(&self) -> Result<(), RuntimeProviderError> {
        let content_byte_count = u64::try_from(self.content.len())
            .map_err(|_| RuntimeProviderError::InvalidDurableEvent)?;
        if self.schema != RUNTIME_MODEL_VISIBLE_EVENT_SCHEMA
            || self.sequence == 0
            || !is_digest(&self.scope_digest)
            || !is_digest(&self.provider_manifest_digest)
            || !is_digest(&self.runtime_config_digest)
            || !is_digest(&self.catalog_digest)
            || !is_digest(&self.policy_digest)
            || !is_digest(&self.source_item_id_digest)
            || !is_digest(&self.source_event_digest)
            || !is_digest(&self.content_digest)
            || !is_digest(&self.event_digest)
            || self.content.is_empty()
            || self.content.len() > MAX_DURABLE_CONTENT_BYTES
            || self.content_byte_count != content_byte_count
            || self.content_digest != super::digest_hex(self.content.as_bytes())
            || self.event_digest != self.computed_digest()?
        {
            return Err(RuntimeProviderError::InvalidDurableEvent);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the durable event constructor binds every identity and content digest explicitly"
    )]
    fn new(
        sequence: u64,
        scope_digest: &str,
        provider_manifest_digest: &str,
        runtime_config_digest: &str,
        catalog_digest: &str,
        policy_digest: &str,
        kind: DurableModelVisibleEventKind,
        source_item_id_digest: String,
        source_event_digest: String,
        content: String,
    ) -> Result<Self, RuntimeProviderError> {
        let content_byte_count =
            u64::try_from(content.len()).map_err(|_| RuntimeProviderError::InvalidDurableEvent)?;
        let mut event = Self {
            schema: RUNTIME_MODEL_VISIBLE_EVENT_SCHEMA.to_owned(),
            sequence,
            scope_digest: scope_digest.to_owned(),
            provider_manifest_digest: provider_manifest_digest.to_owned(),
            runtime_config_digest: runtime_config_digest.to_owned(),
            catalog_digest: catalog_digest.to_owned(),
            policy_digest: policy_digest.to_owned(),
            kind,
            source_item_id_digest,
            source_event_digest,
            content_digest: super::digest_hex(content.as_bytes()),
            content_byte_count,
            content,
            event_digest: String::new(),
        };
        event.event_digest = event.computed_digest()?;
        event.validate()?;
        Ok(event)
    }

    fn computed_digest(&self) -> Result<String, RuntimeProviderError> {
        let material = DurableModelVisibleEventDigestMaterial {
            schema: &self.schema,
            sequence: self.sequence,
            scope_digest: &self.scope_digest,
            provider_manifest_digest: &self.provider_manifest_digest,
            runtime_config_digest: &self.runtime_config_digest,
            catalog_digest: &self.catalog_digest,
            policy_digest: &self.policy_digest,
            kind: self.kind,
            source_item_id_digest: &self.source_item_id_digest,
            source_event_digest: &self.source_event_digest,
            content_digest: &self.content_digest,
            content_byte_count: self.content_byte_count,
        };
        let bytes = serde_json::to_vec(&material).map_err(AdapterError::from)?;
        Ok(super::digest_hex(&bytes))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableModelVisibleEventDigestMaterial<'a> {
    schema: &'a str,
    sequence: u64,
    scope_digest: &'a str,
    provider_manifest_digest: &'a str,
    runtime_config_digest: &'a str,
    catalog_digest: &'a str,
    policy_digest: &'a str,
    kind: DurableModelVisibleEventKind,
    source_item_id_digest: &'a str,
    source_event_digest: &'a str,
    content_digest: &'a str,
    content_byte_count: u64,
}

/// Implementations must durably commit the event before returning Ok. This is the boundary to
/// Mission/session storage; the Runtime service does not import business storage.
pub trait MissionSessionLog {
    fn append_model_visible_event(&mut self, event: DurableModelVisibleEvent)
    -> Result<(), String>;
}

impl<F> MissionSessionLog for F
where
    F: FnMut(DurableModelVisibleEvent) -> Result<(), String>,
{
    fn append_model_visible_event(
        &mut self,
        event: DurableModelVisibleEvent,
    ) -> Result<(), String> {
        self(event)
    }
}

/// A typed stream item returned by one mounted provider session.
#[derive(Clone, PartialEq)]
pub enum RuntimeProviderStreamEvent {
    TurnStarted {
        event_digest: String,
    },
    ItemStarted {
        event_digest: String,
    },
    AgentMessageDelta {
        event_digest: String,
        item_id_digest: String,
        content: String,
    },
    ItemCompleted {
        event_digest: String,
        result: Option<Box<RuntimeResultPacket>>,
        recovery_hint: Option<RuntimeRecoveryHint>,
    },
    TurnCompleted {
        event_digest: String,
        status: RuntimeTurnCompletionStatus,
    },
    LocalApprovalRequested {
        event_digest: String,
        kind: RuntimeLocalApprovalKind,
        request: super::RuntimeLocalApprovalRequest,
    },
    Diagnostic {
        event_digest: String,
    },
    Other {
        event_digest: String,
    },
}

impl fmt::Debug for RuntimeProviderStreamEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RuntimeProviderStreamEvent");
        match self {
            Self::TurnStarted { event_digest }
            | Self::ItemStarted { event_digest }
            | Self::Diagnostic { event_digest }
            | Self::Other { event_digest } => {
                debug.field("event_digest", event_digest);
            }
            Self::AgentMessageDelta {
                event_digest,
                item_id_digest,
                content,
            } => {
                debug
                    .field("event_digest", event_digest)
                    .field("item_id_digest", item_id_digest)
                    .field("content_digest", &super::digest_hex(content.as_bytes()))
                    .field("content_byte_count", &content.len());
            }
            Self::ItemCompleted {
                event_digest,
                result,
                recovery_hint,
            } => {
                debug
                    .field("event_digest", event_digest)
                    .field("result", result)
                    .field("recovery_hint", recovery_hint);
            }
            Self::TurnCompleted {
                event_digest,
                status,
            } => {
                debug
                    .field("event_digest", event_digest)
                    .field("status", status);
            }
            Self::LocalApprovalRequested {
                event_digest,
                kind,
                request,
            } => {
                debug
                    .field("event_digest", event_digest)
                    .field("kind", kind)
                    .field("request", request);
            }
        }
        debug.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRestartReceipt {
    pub previous_instance_digest: String,
    pub new_instance_digest: String,
    pub runtime_generation: u64,
    pub old_mount_digest: String,
    pub new_mount_digest: String,
    pub automatic_replay_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProviderTeardown {
    pub plugin: RuntimePluginTeardownReceipt,
    pub shutdown: ShutdownReport,
}

#[derive(Debug, Error)]
pub enum RuntimeProviderError {
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    #[error(transparent)]
    Plugin(#[from] super::RuntimePluginError),
    #[error("runtime provider policy is invalid")]
    InvalidPolicy,
    #[error("runtime provider durable event is invalid")]
    InvalidDurableEvent,
    #[error("required Runtime capability was not negotiated: {capability}")]
    CapabilityNotNegotiated { capability: &'static str },
    #[error("runtime provider durable Mission/session log rejected {event_digest}: {reason}")]
    DurableLog {
        event_digest: String,
        reason: String,
    },
    #[error("runtime provider stream quota was exceeded")]
    StreamQuotaExceeded,
    #[error("runtime provider session is poisoned and must be restarted")]
    SessionPoisoned,
    #[error("runtime provider session is closed")]
    SessionClosed,
    #[error("runtime item did not contain the expected model-visible content")]
    MissingModelVisibleContent,
    #[error("runtime approval event did not contain a request")]
    MissingApprovalRequest,
}

/// The concrete OpenInterpreter provider. The Mission consumer only sees the generic service
/// manifest and RuntimeProviderSession; it does not branch on a vendor enum.
#[derive(Clone, Debug)]
pub struct OpenInterpreterRuntimeProvider {
    manifest: RuntimeServiceProviderManifest,
}

impl OpenInterpreterRuntimeProvider {
    pub fn new() -> Result<Self, RuntimeProviderError> {
        let definition = RuntimeServiceDefinition::new(
            OPENINTERPRETER_RUNTIME_SERVICE_ID,
            OPENINTERPRETER_RUNTIME_SERVICE_REVISION,
            vec![
                RuntimeServiceCapability::Initialize,
                RuntimeServiceCapability::Thread,
                RuntimeServiceCapability::Turn,
                RuntimeServiceCapability::ItemStream,
                RuntimeServiceCapability::Interrupt,
                RuntimeServiceCapability::Resume,
                RuntimeServiceCapability::Steer,
                RuntimeServiceCapability::TypedResultPacket,
                RuntimeServiceCapability::ModelVisibleSessionLog,
            ],
        )?;
        let provider_revision = format!("{OPENINTERPRETER_RELEASE}@{OPENINTERPRETER_COMMIT}");
        let manifest = RuntimeServiceProviderManifest::new(
            OPENINTERPRETER_PROVIDER_ID,
            provider_revision,
            &definition,
        )?;
        Ok(Self { manifest })
    }

    pub fn manifest(&self) -> &RuntimeServiceProviderManifest {
        &self.manifest
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mount(
        &self,
        command: RuntimeCommand,
        workspace_root: &Path,
        scope: RuntimePluginScope,
        catalog: RuntimeCatalog,
        config: RuntimeExecutionConfig,
        policy: RuntimeProviderPolicy,
        resolver: &dyn SecretResolver,
        log: Box<dyn MissionSessionLog>,
        runtime_generation: u64,
        timeout: Duration,
    ) -> Result<RuntimeProviderSession, RuntimeProviderError> {
        self.manifest.validate()?;
        scope.validate()?;
        policy.validate()?;
        if runtime_generation == 0 {
            return Err(AdapterError::InvalidRuntimeMapping.into());
        }
        let policy_digest = policy.digest()?;
        let (runtime, capabilities, mapping) = launch_runtime(
            command,
            workspace_root,
            &scope,
            &catalog,
            &config,
            runtime_generation,
            resolver,
            timeout,
        )?;
        let mut mount = RuntimePluginMount::new(self.manifest.clone(), scope.clone())?;
        let stream_registration_digest =
            mount.register(RuntimePluginRegistrationKind::Stream, &scope.session_id)?;
        Ok(RuntimeProviderSession {
            manifest: self.manifest.clone(),
            scope,
            catalog,
            config,
            policy,
            policy_digest,
            capabilities,
            workspace_root: workspace_root.to_owned(),
            runtime: Some(runtime),
            mapping,
            mount,
            stream_registration_digest,
            log,
            next_log_sequence: 1,
            stream_event_count: 0,
            stream_byte_count: 0,
            poisoned: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mount_from_verified_artifact(
        &self,
        artifact: &VerifiedRuntimeArtifact,
        workspace_root: &Path,
        runtime_home: &Path,
        scope: RuntimePluginScope,
        catalog: RuntimeCatalog,
        config: RuntimeExecutionConfig,
        policy: RuntimeProviderPolicy,
        resolver: &dyn SecretResolver,
        log: Box<dyn MissionSessionLog>,
        runtime_generation: u64,
        timeout: Duration,
    ) -> Result<RuntimeProviderSession, RuntimeProviderError> {
        let command = artifact.runtime_command(workspace_root, runtime_home)?;
        self.mount(
            command,
            workspace_root,
            scope,
            catalog,
            config,
            policy,
            resolver,
            log,
            runtime_generation,
            timeout,
        )
    }
}

/// A mounted, exact Mission/session provider instance.
pub struct RuntimeProviderSession {
    manifest: RuntimeServiceProviderManifest,
    scope: RuntimePluginScope,
    catalog: RuntimeCatalog,
    config: RuntimeExecutionConfig,
    policy: RuntimeProviderPolicy,
    policy_digest: String,
    capabilities: RuntimeCapabilities,
    workspace_root: PathBuf,
    runtime: Option<StdioRuntime>,
    mapping: RuntimeMapping,
    mount: RuntimePluginMount,
    stream_registration_digest: String,
    log: Box<dyn MissionSessionLog>,
    next_log_sequence: u64,
    stream_event_count: u32,
    stream_byte_count: u64,
    poisoned: bool,
}

impl fmt::Debug for RuntimeProviderSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProviderSession")
            .field("manifest_digest", &self.manifest.manifest_digest)
            .field("scope", &self.scope)
            .field("catalog_digest", &self.catalog.digest().ok())
            .field("runtime_config_digest", &self.config.digest().ok())
            .field("policy_digest", &self.policy_digest)
            .field("capabilities", &self.capabilities)
            .field("mapping", &self.mapping)
            .field("mount", &self.mount)
            .field(
                "stream_registration_digest",
                &self.stream_registration_digest,
            )
            .field("next_log_sequence", &self.next_log_sequence)
            .field("stream_event_count", &self.stream_event_count)
            .field("stream_byte_count", &self.stream_byte_count)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl RuntimeProviderSession {
    pub fn manifest(&self) -> &RuntimeServiceProviderManifest {
        &self.manifest
    }

    pub fn scope(&self) -> &RuntimePluginScope {
        &self.scope
    }

    pub fn catalog(&self) -> &RuntimeCatalog {
        &self.catalog
    }

    pub fn config(&self) -> &RuntimeExecutionConfig {
        &self.config
    }

    pub fn policy(&self) -> &RuntimeProviderPolicy {
        &self.policy
    }

    pub fn capabilities(&self) -> &RuntimeCapabilities {
        &self.capabilities
    }

    pub fn mapping(&self) -> &RuntimeMapping {
        &self.mapping
    }

    pub fn mount_digest(&self) -> &str {
        &self.mount.mount_digest
    }

    pub fn mount_state(&self) -> RuntimePluginMountState {
        self.mount.state
    }

    pub fn start_turn(
        &mut self,
        client_user_message_id: &str,
        prompt: &str,
        timeout: Duration,
    ) -> Result<RuntimeTurnDispatch, RuntimeProviderError> {
        self.ensure_active()?;
        if !bounded_identifier(client_user_message_id) || prompt.trim().is_empty() {
            return Err(AdapterError::InvalidTurnRequest.into());
        }
        let config_digest = self.config.digest()?;
        let input_event = DurableModelVisibleEvent::new(
            self.next_log_sequence,
            &self.scope.scope_digest,
            &self.manifest.manifest_digest,
            &config_digest,
            &self.config.catalog_digest,
            &self.policy_digest,
            DurableModelVisibleEventKind::Input,
            super::digest_hex(client_user_message_id.as_bytes()),
            super::digest_hex(format!("turn-input:{client_user_message_id}").as_bytes()),
            prompt.to_owned(),
        )?;
        self.append_durable(input_event)?;
        let mapping = self.mapping.clone();
        let config = self.config.clone();
        let result = self
            .runtime_mut()?
            .start_mapped_turn_with_config(
                &mapping,
                &config,
                client_user_message_id,
                prompt,
                timeout,
            )
            .map_err(|error| {
                self.poisoned = true;
                RuntimeProviderError::Adapter(error)
            })?;
        self.mapping = result.mapping.clone();
        Ok(result)
    }

    pub fn stream_next(
        &mut self,
        timeout: Duration,
    ) -> Result<RuntimeProviderStreamEvent, RuntimeProviderError> {
        self.ensure_active()?;
        let mapping = self.mapping.clone();
        let mapped = self
            .runtime_mut()?
            .next_mapped_turn_event(&mapping, timeout)
            .map_err(|error| {
                self.poisoned = true;
                RuntimeProviderError::Adapter(error)
            })?;
        self.map_event(mapped)
    }

    pub fn respond_to_approval(
        &mut self,
        request: &super::RuntimeLocalApprovalRequest,
        approved: bool,
    ) -> Result<String, RuntimeProviderError> {
        self.ensure_active()?;
        let mapping = self.mapping.clone();
        self.runtime_mut()?
            .respond_to_mapped_turn_approval(&mapping, request, approved)
            .map_err(|error| {
                self.poisoned = true;
                RuntimeProviderError::Adapter(error)
            })
    }

    pub fn interrupt(
        &mut self,
        timeout: Duration,
    ) -> Result<RuntimeProtocolWriteReceipt, RuntimeProviderError> {
        self.ensure_active()?;
        let mapping = self.mapping.clone();
        self.runtime_mut()?
            .interrupt_mapped_turn(&mapping, timeout)
            .map_err(|error| {
                self.poisoned = true;
                RuntimeProviderError::Adapter(error)
            })
    }

    /// Restart after a poisoned/crashed process. The old mount is revoked first, no uncertain
    /// turn is replayed, and the new mapping receives a fresh Runtime generation.
    pub fn restart(
        &mut self,
        command: RuntimeCommand,
        resolver: &dyn SecretResolver,
        timeout: Duration,
    ) -> Result<ProviderRestartReceipt, RuntimeProviderError> {
        if self.runtime.is_none() {
            return Err(RuntimeProviderError::SessionClosed);
        }
        let previous_instance_digest = self.mapping.runtime_instance_digest.clone();
        let old_mount_digest = self.mount.mount_digest.clone();
        let mut stopper = SessionRegistrationStopper::default();
        self.mount.revoke(&mut stopper)?;
        let old_runtime = self
            .runtime
            .take()
            .ok_or(RuntimeProviderError::SessionClosed)?;
        old_runtime.shutdown()?;
        let runtime_generation = self
            .mapping
            .runtime_generation
            .checked_add(1)
            .ok_or(AdapterError::InvalidRuntimeMapping)?;
        let (runtime, capabilities, mapping) = match launch_runtime(
            command,
            &self.workspace_root,
            &self.scope,
            &self.catalog,
            &self.config,
            runtime_generation,
            resolver,
            timeout,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let mut mount = match RuntimePluginMount::new(self.manifest.clone(), self.scope.clone()) {
            Ok(mount) => mount,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        let stream_registration_digest = match mount.register(
            RuntimePluginRegistrationKind::Stream,
            &self.scope.session_id,
        ) {
            Ok(digest) => digest,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        let new_instance_digest = mapping.runtime_instance_digest.clone();
        let new_mount_digest = mount.mount_digest.clone();
        self.runtime = Some(runtime);
        self.capabilities = capabilities;
        self.mapping = mapping;
        self.mount = mount;
        self.stream_registration_digest = stream_registration_digest;
        self.poisoned = false;
        Ok(ProviderRestartReceipt {
            previous_instance_digest,
            new_instance_digest,
            runtime_generation,
            old_mount_digest,
            new_mount_digest,
            automatic_replay_allowed: false,
        })
    }

    pub fn unmount(self) -> Result<RuntimeProviderTeardown, RuntimeProviderError> {
        self.teardown(false)
    }

    pub fn revoke(self) -> Result<RuntimeProviderTeardown, RuntimeProviderError> {
        self.teardown(true)
    }

    fn teardown(mut self, revoke: bool) -> Result<RuntimeProviderTeardown, RuntimeProviderError> {
        let mut stopper = SessionRegistrationStopper::default();
        let plugin = if revoke {
            self.mount.revoke(&mut stopper)?
        } else {
            self.mount.unmount(&mut stopper)?
        };
        let runtime = self
            .runtime
            .take()
            .ok_or(RuntimeProviderError::SessionClosed)?;
        let shutdown = runtime.shutdown()?;
        Ok(RuntimeProviderTeardown { plugin, shutdown })
    }

    fn ensure_active(&self) -> Result<(), RuntimeProviderError> {
        if self.runtime.is_none() {
            return Err(RuntimeProviderError::SessionClosed);
        }
        if self.poisoned {
            return Err(RuntimeProviderError::SessionPoisoned);
        }
        Ok(())
    }

    fn runtime_mut(&mut self) -> Result<&mut StdioRuntime, RuntimeProviderError> {
        self.runtime
            .as_mut()
            .ok_or(RuntimeProviderError::SessionClosed)
    }

    fn append_durable(
        &mut self,
        event: DurableModelVisibleEvent,
    ) -> Result<(), RuntimeProviderError> {
        event.validate()?;
        let event_digest = event.event_digest.clone();
        if let Err(reason) = self.log.append_model_visible_event(event) {
            self.poisoned = true;
            return Err(RuntimeProviderError::DurableLog {
                event_digest,
                reason,
            });
        }
        self.next_log_sequence = self
            .next_log_sequence
            .checked_add(1)
            .ok_or(RuntimeProviderError::InvalidDurableEvent)?;
        Ok(())
    }

    fn append_output(
        &mut self,
        kind: DurableModelVisibleEventKind,
        item_id_digest: String,
        source_event_digest: String,
        content: String,
    ) -> Result<(), RuntimeProviderError> {
        let byte_count =
            u64::try_from(content.len()).map_err(|_| RuntimeProviderError::StreamQuotaExceeded)?;
        let next_count = self
            .stream_event_count
            .checked_add(1)
            .ok_or(RuntimeProviderError::StreamQuotaExceeded)?;
        let next_bytes = self
            .stream_byte_count
            .checked_add(byte_count)
            .ok_or(RuntimeProviderError::StreamQuotaExceeded)?;
        if next_count > self.policy.max_stream_events || next_bytes > self.policy.max_stream_bytes {
            self.poisoned = true;
            return Err(RuntimeProviderError::StreamQuotaExceeded);
        }
        let config_digest = self.config.digest()?;
        let event = DurableModelVisibleEvent::new(
            self.next_log_sequence,
            &self.scope.scope_digest,
            &self.manifest.manifest_digest,
            &config_digest,
            &self.config.catalog_digest,
            &self.policy_digest,
            kind,
            item_id_digest,
            source_event_digest,
            content,
        )?;
        self.append_durable(event)?;
        self.stream_event_count = next_count;
        self.stream_byte_count = next_bytes;
        Ok(())
    }

    fn map_event(
        &mut self,
        mapped: MappedTurnEvent,
    ) -> Result<RuntimeProviderStreamEvent, RuntimeProviderError> {
        let event_digest = mapped.event_digest.clone();
        match mapped.kind.clone() {
            MappedTurnEventKind::TurnStarted => {
                Ok(RuntimeProviderStreamEvent::TurnStarted { event_digest })
            }
            MappedTurnEventKind::ItemStarted => {
                Ok(RuntimeProviderStreamEvent::ItemStarted { event_digest })
            }
            MappedTurnEventKind::AgentMessageDelta => {
                let delta = mapped
                    .agent_message_delta
                    .as_ref()
                    .ok_or(RuntimeProviderError::MissingModelVisibleContent)?;
                let item_id_digest = delta.item_id_digest.clone();
                let content = delta.as_str().to_owned();
                self.append_output(
                    DurableModelVisibleEventKind::AssistantDelta,
                    item_id_digest.clone(),
                    event_digest.clone(),
                    content.clone(),
                )?;
                Ok(RuntimeProviderStreamEvent::AgentMessageDelta {
                    event_digest,
                    item_id_digest,
                    content,
                })
            }
            MappedTurnEventKind::ItemCompleted => {
                let result =
                    RuntimeResultPacket::from_mapped_event(&self.mapping, &mapped)?.map(Box::new);
                if let Some(packet) = result.as_deref() {
                    self.append_output(
                        DurableModelVisibleEventKind::AssistantResult,
                        packet.source_item_id_digest.clone(),
                        packet.source_event_digest.clone(),
                        packet.content.clone(),
                    )?;
                }
                Ok(RuntimeProviderStreamEvent::ItemCompleted {
                    event_digest,
                    result,
                    recovery_hint: mapped.recovery_hint,
                })
            }
            MappedTurnEventKind::TurnCompleted(status) => {
                Ok(RuntimeProviderStreamEvent::TurnCompleted {
                    event_digest,
                    status,
                })
            }
            MappedTurnEventKind::LocalApprovalRequested(kind) => {
                let request = mapped
                    .approval_request
                    .ok_or(RuntimeProviderError::MissingApprovalRequest)?;
                Ok(RuntimeProviderStreamEvent::LocalApprovalRequested {
                    event_digest,
                    kind,
                    request,
                })
            }
            MappedTurnEventKind::Diagnostic => {
                Ok(RuntimeProviderStreamEvent::Diagnostic { event_digest })
            }
            MappedTurnEventKind::Other => Ok(RuntimeProviderStreamEvent::Other { event_digest }),
        }
    }
}

impl Drop for RuntimeProviderSession {
    fn drop(&mut self) {
        let mut stopper = SessionRegistrationStopper::default();
        let _ = self.mount.revoke(&mut stopper);
        let _ = self.runtime.take();
    }
}

#[derive(Default)]
struct SessionRegistrationStopper {
    streams: BTreeSet<String>,
    tools: BTreeSet<String>,
    hooks: BTreeSet<String>,
}

impl RuntimePluginRegistrationStopper for SessionRegistrationStopper {
    fn stop_stream(&mut self, registration_digest: &str) -> Result<(), super::RuntimePluginError> {
        self.streams.insert(registration_digest.to_owned());
        Ok(())
    }

    fn unregister_tool(
        &mut self,
        registration_digest: &str,
    ) -> Result<(), super::RuntimePluginError> {
        self.tools.insert(registration_digest.to_owned());
        Ok(())
    }

    fn remove_hook(&mut self, registration_digest: &str) -> Result<(), super::RuntimePluginError> {
        self.hooks.insert(registration_digest.to_owned());
        Ok(())
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the launch boundary keeps exact scope, catalog, config, resolver, generation, and timeout explicit"
)]
fn launch_runtime(
    command: RuntimeCommand,
    workspace_root: &Path,
    scope: &RuntimePluginScope,
    catalog: &RuntimeCatalog,
    config: &RuntimeExecutionConfig,
    runtime_generation: u64,
    resolver: &dyn SecretResolver,
    timeout: Duration,
) -> Result<(StdioRuntime, RuntimeCapabilities, RuntimeMapping), RuntimeProviderError> {
    scope.validate()?;
    catalog.validate_config(config)?;
    let command = bind_configured_secret(command, catalog, config)?;
    let mut runtime = StdioRuntime::spawn_with_secret_resolver(&command, resolver)?;
    let capabilities = runtime.negotiate_capabilities(timeout)?;
    require_capabilities(&capabilities)?;
    let observed_catalog =
        runtime.discover_runtime_catalog(catalog.catalog_version.clone(), timeout)?;
    let expected_digest = catalog.digest()?;
    let actual_digest = observed_catalog.digest()?;
    if expected_digest != actual_digest {
        return Err(AdapterError::RuntimeCatalogDrift {
            expected_digest,
            actual_digest,
        }
        .into());
    }
    let mapping = runtime.start_mapped_thread_with_config(
        &scope.project_id,
        &scope.mission_id,
        runtime_generation,
        workspace_root,
        &capabilities,
        catalog,
        config,
        timeout,
    )?;
    Ok((runtime, capabilities, mapping))
}

fn bind_configured_secret(
    mut command: RuntimeCommand,
    catalog: &RuntimeCatalog,
    config: &RuntimeExecutionConfig,
) -> Result<RuntimeCommand, RuntimeProviderError> {
    let expected = catalog.secret_binding(config)?;
    match expected {
        Some(expected) => {
            if let Some(existing) = command
                .secret_bindings
                .iter()
                .find(|binding| binding.environment_key == expected.environment_key)
            {
                if existing != &expected {
                    return Err(AdapterError::RuntimeConfigDrift {
                        field: "credential_binding",
                    }
                    .into());
                }
            } else {
                command.add_secret_binding(expected.environment_key, expected.reference)?;
            }
        }
        None if !command.secret_bindings.is_empty() => {
            return Err(AdapterError::RuntimeConfigDrift {
                field: "credential_binding",
            }
            .into());
        }
        None => {}
    }
    Ok(command)
}

fn require_capabilities(capabilities: &RuntimeCapabilities) -> Result<(), RuntimeProviderError> {
    for capability in [
        "provider-catalog",
        "model-catalog",
        "harness-catalog",
        "interrupt",
        "steer",
        "bounded-stream",
    ] {
        if !capabilities.supports(capability) {
            return Err(RuntimeProviderError::CapabilityNotNegotiated { capability });
        }
    }
    Ok(())
}

/// This is deliberately a readiness report, not a native PASS. A real probe still needs a
/// verified artifact, isolated home, exact catalog/configuration, a SecretResolver, and an
/// external account; missing host configuration remains BLOCKED_ENV.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeProbeStatus {
    ReadyForCredentialedProbe {
        program: PathBuf,
        runtime_home: PathBuf,
        provider: String,
        model: String,
    },
    BlockedEnv {
        missing: Vec<String>,
    },
}

#[allow(
    dead_code,
    reason = "the public native probe is consumed by host integration outside this runtime crate"
)]
pub fn native_probe_status() -> NativeProbeStatus {
    let required = [
        "HARTEVO_OPENINTERPRETER_BIN",
        "HARTEVO_TEST_OPENINTERPRETER_HOME",
        "HARTEVO_RUNTIME_PROVIDER",
        "HARTEVO_RUNTIME_MODEL",
    ];
    let missing = required
        .iter()
        .filter(|name| env::var_os(name).is_none())
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return NativeProbeStatus::BlockedEnv { missing };
    }
    NativeProbeStatus::ReadyForCredentialedProbe {
        program: PathBuf::from(env::var_os(required[0]).expect("checked above")),
        runtime_home: PathBuf::from(env::var_os(required[1]).expect("checked above")),
        provider: env::var(required[2]).expect("checked above"),
        model: env::var(required[3]).expect("checked above"),
    }
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SESSION_IDENTIFIER_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::super::control_plane::{RuntimeHarnessDiscovery, RuntimeModelDiscovery};
    use super::*;
    use std::sync::{Arc, Mutex};

    struct FakeResolver;

    impl SecretResolver for FakeResolver {
        fn resolve(
            &self,
            _reference: &super::super::SecretReference,
        ) -> Result<super::super::ResolvedSecret, AdapterError> {
            super::super::ResolvedSecret::new("provider-plugin-test-secret")
        }
    }

    #[derive(Clone, Default)]
    struct RecordingLog {
        events: Arc<Mutex<Vec<DurableModelVisibleEvent>>>,
    }

    impl MissionSessionLog for RecordingLog {
        fn append_model_visible_event(
            &mut self,
            event: DurableModelVisibleEvent,
        ) -> Result<(), String> {
            event.validate().map_err(|error| error.to_string())?;
            self.events
                .lock()
                .map_err(|_| "recording log lock poisoned".to_owned())?
                .push(event);
            Ok(())
        }
    }

    #[cfg(unix)]
    fn shell_runtime(script: &str) -> RuntimeCommand {
        let mut command = RuntimeCommand::new(
            std::path::PathBuf::from("/bin/sh"),
            std::env::current_dir().expect("current directory"),
        );
        command.args = vec!["-c".to_owned(), script.to_owned()];
        command.shutdown_grace = Duration::from_millis(50);
        command
    }

    fn catalog_fixture() -> RuntimeCatalog {
        let schema_digest = format!("sha256:{}", super::super::APP_SERVER_SCHEMA_SHA256);
        RuntimeCatalog::from_app_server_discovery(
            "provider-plugin-test-v1",
            schema_digest,
            &serde_json::json!({
                "data": [{
                    "id": "openai",
                    "wireApi": "responses",
                    "envKey": "OPENAI_API_KEY",
                    "configured": true
                }]
            }),
            &[RuntimeModelDiscovery {
                provider_id: "openai".to_owned(),
                response: serde_json::json!({
                    "data": [{
                        "model": "gpt-5.6",
                        "supportedReasoningEfforts": [{"reasoningEffort": "medium"}],
                        "serviceTiers": [{"id": "default"}]
                    }]
                }),
            }],
            &[RuntimeHarnessDiscovery {
                provider_id: "openai".to_owned(),
                model_id: Some("gpt-5.6".to_owned()),
                response: serde_json::json!({
                    "data": [{"id": null, "isRecommended": true}]
                }),
            }],
        )
        .expect("catalog")
    }

    fn config_fixture(catalog: &RuntimeCatalog) -> RuntimeExecutionConfig {
        let provider = catalog.provider("openai").expect("provider");
        let model = catalog.model("openai", "gpt-5.6").expect("model");
        let harness = catalog
            .harness("openai", "gpt-5.6", "native")
            .expect("harness");
        RuntimeExecutionConfig::new(
            provider.id.clone(),
            provider.revision.clone(),
            model.id.clone(),
            model.revision.clone(),
            "native",
            harness.revision.clone(),
            Some("medium".to_owned()),
            Some("default".to_owned()),
            super::super::RuntimeEndpointClass::Responses,
            super::super::RuntimeBudget::new(8_192, 4_096, 8, 60_000).expect("budget"),
            super::super::RuntimeDataBoundary::ProviderDeclared,
            super::super::SecretReference::new(
                "openai",
                "fake-account",
                "keyring/provider-plugin-test",
                "f".repeat(64),
                1,
            )
            .expect("reference"),
            catalog.digest().expect("digest"),
        )
        .expect("config")
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fake provider contract covers spawn, negotiation, exact dispatch, durable stream, restart, and teardown in one adversarial path"
    )]
    fn fake_provider_mount_streams_and_durably_logs_exact_session_content() {
        let workspace = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("workspace");
        let workspace_json =
            serde_json::to_string(&workspace.to_string_lossy()).expect("workspace json");
        let script = r#"
while IFS= read -r request; do
    id=$(printf '%s' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
    case "$request" in
        *'"method":"initialize"'*)
            if [ "$OPENAI_API_KEY" != "provider-plugin-test-secret" ]; then exit 42; fi
            printf '%s\n' '{"jsonrpc":"2.0","id":'$id',"result":{"serverInfo":{"name":"fake-provider-runtime"}}}'
            ;;
        *'"method":"interpreter/provider/list"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'$id',"result":{"data":[{"id":"openai","wireApi":"responses","envKey":"OPENAI_API_KEY","configured":true}]}}'
            ;;
        *'"method":"interpreter/model/list"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'$id',"result":{"data":[{"model":"gpt-5.6","supportedReasoningEfforts":[{"reasoningEffort":"medium"}],"serviceTiers":[{"id":"default"}]}]}}'
            ;;
        *'"method":"interpreter/harness/list"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'$id',"result":{"data":[{"id":null,"isRecommended":true}]}}'
            ;;
        *'"method":"interpreter/provider/set"'*|*'"method":"interpreter/model/set"'*|*'"method":"interpreter/harness/set"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'$id',"result":{}}'
            ;;
        *'"method":"thread/start"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'$id',"result":{"thread":{"id":"provider-thread-1"},"cwd":__WORKSPACE__,"model":"gpt-5.6","modelProvider":"openai","approvalPolicy":"on-request","approvalsReviewer":"user","sandbox":"workspace-write"}}'
            ;;
        *'"method":"turn/start"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'$id',"result":{"turn":{"id":"provider-turn-1","status":"inProgress"}}}'
            printf '%s\n' '{"jsonrpc":"2.0","method":"turn/started","params":{"threadId":"provider-thread-1","turn":{"id":"provider-turn-1","status":"inProgress"}}}'
            printf '%s\n' '{"jsonrpc":"2.0","method":"item/agentMessage/delta","params":{"threadId":"provider-thread-1","turnId":"provider-turn-1","itemId":"provider-item-1","delta":"hello "}}'
            printf '%s\n' '{"jsonrpc":"2.0","method":"item/agentMessage/delta","params":{"threadId":"provider-thread-1","turnId":"provider-turn-1","itemId":"provider-item-1","delta":"from provider"}}'
            printf '%s\n' '{"jsonrpc":"2.0","method":"item/completed","params":{"threadId":"provider-thread-1","turnId":"provider-turn-1","item":{"id":"provider-item-1","type":"agentMessage","text":"hello from provider"}}}'
            printf '%s\n' '{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"provider-thread-1","turnId":"provider-turn-1","turn":{"id":"provider-turn-1","status":"completed"}}}'
            ;;
        *'"method":"turn/interrupt"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":'$id',"result":{}}'
            ;;
    esac
done
"#;
        let script = script.replace("__WORKSPACE__", &workspace_json);
        let catalog = catalog_fixture();
        let config = config_fixture(&catalog);
        let scope = super::super::RuntimePluginScope::new(
            "project-provider-plugin",
            "mission-provider-plugin",
            "session-provider-plugin",
        )
        .expect("scope");
        let log = RecordingLog::default();
        let events = log.events.clone();
        let provider = OpenInterpreterRuntimeProvider::new().expect("provider");
        let mut session = provider
            .mount(
                shell_runtime(&script),
                &workspace,
                scope,
                catalog,
                config,
                RuntimeProviderPolicy::new(16, 4_096, 10_000, "USD").expect("policy"),
                &FakeResolver,
                Box::new(log),
                1,
                Duration::from_secs(1),
            )
            .expect("mounted session");
        assert_eq!(session.mount_state(), RuntimePluginMountState::Mounted);
        assert_eq!(session.config().provider_id, "openai");
        assert_eq!(session.config().model_id, "gpt-5.6");
        assert_eq!(session.config().harness_id, "native");
        session
            .start_turn(
                "provider-message-1",
                "Return the provider result.",
                Duration::from_secs(1),
            )
            .expect("turn");
        assert!(matches!(
            session
                .stream_next(Duration::from_secs(1))
                .expect("started"),
            RuntimeProviderStreamEvent::TurnStarted { .. }
        ));
        let first_delta = session.stream_next(Duration::from_secs(1)).expect("delta");
        assert!(matches!(
            first_delta,
            RuntimeProviderStreamEvent::AgentMessageDelta {
                ref content, ..
            } if content == "hello "
        ));
        let second_delta = session.stream_next(Duration::from_secs(1)).expect("delta");
        assert!(matches!(
            second_delta,
            RuntimeProviderStreamEvent::AgentMessageDelta {
                ref content, ..
            } if content == "from provider"
        ));
        let completed = session
            .stream_next(Duration::from_secs(1))
            .expect("completed item");
        assert!(matches!(
            completed,
            RuntimeProviderStreamEvent::ItemCompleted {
                result: Some(ref packet),
                ..
            } if packet.content == "hello from provider"
        ));
        assert!(matches!(
            session
                .stream_next(Duration::from_secs(1))
                .expect("completed turn"),
            RuntimeProviderStreamEvent::TurnCompleted {
                status: RuntimeTurnCompletionStatus::Completed,
                ..
            }
        ));
        let events = events.lock().expect("events");
        assert_eq!(
            events.iter().map(|event| event.kind).collect::<Vec<_>>(),
            vec![
                DurableModelVisibleEventKind::Input,
                DurableModelVisibleEventKind::AssistantDelta,
                DurableModelVisibleEventKind::AssistantDelta,
                DurableModelVisibleEventKind::AssistantResult,
            ]
        );
        assert_eq!(events[0].content, "Return the provider result.");
        assert_eq!(events[1].content, "hello ");
        assert_eq!(events[2].content, "from provider");
        assert_eq!(events[3].content, "hello from provider");
        assert!(
            events
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
        drop(events);
        let previous_instance = session.mapping().runtime_instance_digest.clone();
        let restart = session
            .restart(
                shell_runtime(&script),
                &FakeResolver,
                Duration::from_secs(1),
            )
            .expect("restart");
        assert_eq!(restart.runtime_generation, 2);
        assert_eq!(restart.previous_instance_digest, previous_instance);
        assert_ne!(restart.new_instance_digest, previous_instance);
        assert!(!restart.automatic_replay_allowed);
        assert!(session.mapping().runtime_turn_id.is_none());
        let teardown = session.unmount().expect("unmount");
        assert_eq!(teardown.plugin.stopped_registration_count, 1);
        assert_eq!(teardown.plugin.residual_registration_count, 0);
        assert_eq!(teardown.plugin.state, RuntimePluginMountState::Unmounted);
    }

    #[test]
    fn durable_event_debug_redacts_model_content_and_binds_policy() {
        let event = DurableModelVisibleEvent::new(
            1,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
            &"e".repeat(64),
            DurableModelVisibleEventKind::Input,
            "f".repeat(64),
            "0".repeat(64),
            "secret model prompt".to_owned(),
        )
        .expect("event");
        let debug = format!("{event:?}");
        assert!(!debug.contains("secret model prompt"));
        assert!(debug.contains("<redacted>"));
        assert!(event.validate().is_ok());
    }

    #[test]
    fn native_probe_is_an_explicit_environment_state() {
        assert!(matches!(
            native_probe_status(),
            NativeProbeStatus::BlockedEnv { .. }
                | NativeProbeStatus::ReadyForCredentialedProbe { .. }
        ));
    }
}

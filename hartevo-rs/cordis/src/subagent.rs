//! Named provider registry for child-agent delegation.
//!
//! This module owns provider selection plus the provider-neutral one-shot
//! descriptor and lifecycle seam. Provider backends still own child
//! construction and durable descriptor seeding; later slices add continuation
//! and model-facing tools.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use thiserror::Error;

use crate::{
    AgentRef, Context, Emit, EventKey, EventReentry, EventSchemaId, LifecycleCancellation,
    RegistrationHandle, SessionCallConfig, SessionContentBlock, SessionId,
};

/// DeepSeek Harness descriptor format implemented by this slice.
pub const SUBAGENT_DESCRIPTOR_VERSION: u32 = 3;

/// Supported lifecycle mode of a child descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubagentDescriptorMode {
    OneShot,
}

/// Detached durable identity passed to a one-shot provider before child work.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotSubagentDescriptor {
    pub version: u32,
    pub mode: SubagentDescriptorMode,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl OneShotSubagentDescriptor {
    #[must_use]
    pub fn new(provider: impl Into<String>, label: Option<String>) -> Self {
        Self {
            version: SUBAGENT_DESCRIPTOR_VERSION,
            mode: SubagentDescriptorMode::OneShot,
            provider: provider.into(),
            label,
        }
    }
}

/// Opaque identity shared by one run's start/end lifecycle pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubagentRunId(String);

impl SubagentRunId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubagentRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Observable facts published after a provider has established one run.
#[derive(Debug, Clone)]
pub struct SubagentRunInfo {
    pub run_id: SubagentRunId,
    pub provider: String,
    pub id: SessionId,
    pub local: bool,
    pub parent: AgentRef,
}

/// Observable terminal facts published exactly once for an established run.
#[derive(Debug, Clone)]
pub struct SubagentRunEndInfo {
    pub run_id: SubagentRunId,
    pub provider: String,
    pub id: SessionId,
    pub local: bool,
    pub parent: AgentRef,
    pub stop_reason: SubagentStopReason,
    pub last_assistant_message: Option<Vec<SessionContentBlock>>,
}

/// Typed lifecycle events emitted by the Cordis subagent service.
pub mod events {
    use super::{Emit, EventKey, EventSchemaId, SubagentRunEndInfo, SubagentRunInfo};

    pub const SUBAGENT_START: EventKey<Emit, SubagentRunInfo, ()> = EventKey::new(
        EventSchemaId::new("hartevo.subagent.start.v1"),
        "subagent/start",
    );
    pub const SUBAGENT_END: EventKey<Emit, SubagentRunEndInfo, ()> = EventKey::new(
        EventSchemaId::new("hartevo.subagent.end.v1"),
        "subagent/end",
    );
}

/// Start-time features a provider can honor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubagentCapabilities(u8);

impl SubagentCapabilities {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self((1 << 5) - 1);

    #[must_use]
    pub const fn with(self, capability: SubagentCapability) -> Self {
        Self(self.0 | capability.bit())
    }

    #[must_use]
    pub const fn supports(self, capability: SubagentCapability) -> bool {
        self.0 & capability.bit() != 0
    }
}

/// Stable name of one optional start-time feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubagentCapability {
    AgentOptions,
    OutputSchema,
    DepthLimit,
    ToolFilter,
    Persona,
}

impl SubagentCapability {
    const fn bit(self) -> u8 {
        match self {
            Self::AgentOptions => 1,
            Self::OutputSchema => 1 << 1,
            Self::DepthLimit => 1 << 2,
            Self::ToolFilter => 1 << 3,
            Self::Persona => 1 << 4,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentOptions => "agentOptions",
            Self::OutputSchema => "outputSchema",
            Self::DepthLimit => "depthLimit",
            Self::ToolFilter => "toolFilter",
            Self::Persona => "persona",
        }
    }
}

impl fmt::Display for SubagentCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Detached child tool visibility restriction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubagentToolFilter {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// One provider-neutral request for a one-shot child.
#[derive(Debug, Clone)]
pub struct SubagentStartRequest {
    pub label: Option<String>,
    pub prompt: Vec<SessionContentBlock>,
    pub parent: AgentRef,
    pub cancellation: LifecycleCancellation,
    pub agent_options: Option<SessionCallConfig>,
    pub output_schema: Option<serde_json::Map<String, serde_json::Value>>,
    pub max_depth: Option<u32>,
    pub tool_filter: Option<SubagentToolFilter>,
    pub persona: Option<String>,
}

impl SubagentStartRequest {
    #[must_use]
    pub fn new(parent: AgentRef, prompt: Vec<SessionContentBlock>) -> Self {
        Self {
            label: None,
            prompt,
            parent,
            cancellation: LifecycleCancellation::default(),
            agent_options: None,
            output_schema: None,
            max_depth: None,
            tool_filter: None,
            persona: None,
        }
    }
}

/// Provider-facing request after Cordis has detached the durable descriptor.
#[derive(Debug, Clone)]
pub struct ResolvedSubagentStartRequest {
    pub label: Option<String>,
    pub prompt: Vec<SessionContentBlock>,
    pub parent: AgentRef,
    pub cancellation: LifecycleCancellation,
    pub agent_options: Option<SessionCallConfig>,
    pub output_schema: Option<serde_json::Map<String, serde_json::Value>>,
    pub max_depth: Option<u32>,
    pub tool_filter: Option<SubagentToolFilter>,
    pub persona: Option<String>,
    pub descriptor: OneShotSubagentDescriptor,
}

impl ResolvedSubagentStartRequest {
    fn one_shot(provider: &str, request: SubagentStartRequest) -> Self {
        let descriptor = OneShotSubagentDescriptor::new(provider, request.label.clone());
        Self {
            label: request.label,
            prompt: request.prompt,
            parent: request.parent,
            cancellation: request.cancellation,
            agent_options: request.agent_options,
            output_schema: request.output_schema,
            max_depth: request.max_depth,
            tool_filter: request.tool_filter,
            persona: request.persona,
            descriptor,
        }
    }
}

/// Why a child run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubagentStopReason {
    Completed,
    Aborted,
    Error,
    MaxTokens,
    Refusal,
}

impl SubagentStopReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Aborted => "aborted",
            Self::Error => "error",
            Self::MaxTokens => "max-tokens",
            Self::Refusal => "refusal",
        }
    }
}

/// Provider-authored terminal result for one published child run.
#[derive(Clone, PartialEq)]
pub struct SubagentResult {
    pub output: Vec<SessionContentBlock>,
    pub structured: Option<serde_json::Value>,
    pub diagnostic: Option<String>,
    pub stop_reason: SubagentStopReason,
}

impl SubagentResult {
    #[must_use]
    pub fn new(output: Vec<SessionContentBlock>, stop_reason: SubagentStopReason) -> Self {
        Self {
            output,
            structured: None,
            diagnostic: None,
            stop_reason,
        }
    }
}

impl fmt::Debug for SubagentResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubagentResult")
            .field("output_blocks", &self.output.len())
            .field("has_structured", &self.structured.is_some())
            .field("diagnostic", &self.diagnostic)
            .field("stop_reason", &self.stop_reason)
            .finish()
    }
}

/// Typed failure at the provider-selection seam.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SubagentError {
    #[error("subagent provider name must not be blank")]
    InvalidProviderName,
    #[error("a subagent provider named `{name}` is already registered")]
    DuplicateProvider { name: String },
    #[error("no subagent provider registered for `{name}`")]
    NoProvider { name: String },
    #[error("subagent provider `{provider}` does not support `{capability}`")]
    UnsupportedCapability {
        provider: String,
        capability: SubagentCapability,
    },
    #[error("the Cordis subagent runtime is unavailable")]
    RuntimeUnavailable,
    #[error("the subagent provider registry is unavailable")]
    RegistryPoisoned,
    #[error("subagent provider registration identity overflowed")]
    ProviderIdentityOverflow,
    #[error("subagent run identity overflowed")]
    RunIdentityOverflow,
    #[error("subagent provider `{provider}` failed to start: {detail}")]
    ProviderStart { provider: String, detail: String },
}

impl SubagentError {
    /// Stable Harness-aligned machine code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidProviderName => "INVALID_PROVIDER",
            Self::DuplicateProvider { .. } => "DUPLICATE_PROVIDER",
            Self::NoProvider { .. } => "NO_PROVIDER",
            Self::UnsupportedCapability { .. } => "UNSUPPORTED_CAPABILITY",
            Self::RuntimeUnavailable => "RUNTIME_UNAVAILABLE",
            Self::RegistryPoisoned => "INVARIANT",
            Self::ProviderIdentityOverflow => "PROVIDER_IDENTITY_OVERFLOW",
            Self::RunIdentityOverflow => "RUN_ID_OVERFLOW",
            Self::ProviderStart { .. } => "PROVIDER_START_FAILED",
        }
    }
}

/// Caller-held published child. Provider removal never revokes this object.
pub trait SubagentRun: Send + Sync + 'static {
    fn id(&self) -> &SessionId;
    fn local_agent(&self) -> Option<AgentRef>;
    fn result(&self) -> BoxFuture<'static, Result<SubagentResult, SubagentError>>;
    fn dispose(&self) -> BoxFuture<'static, Result<(), SubagentError>>;
}

/// Trusted backend for one-shot child creation.
pub trait SubagentProvider: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn capabilities(&self) -> SubagentCapabilities;
    fn inherits_parent_context(&self) -> bool;
    fn start(
        &self,
        request: ResolvedSubagentStartRequest,
    ) -> BoxFuture<'static, Result<Arc<dyn SubagentRun>, SubagentError>>;
}

type SharedSubagentResult = Shared<BoxFuture<'static, Result<SubagentResult, SubagentError>>>;

struct ObservedSubagentRun {
    inner: Arc<dyn SubagentRun>,
    result: SharedSubagentResult,
}

impl SubagentRun for ObservedSubagentRun {
    fn id(&self) -> &SessionId {
        self.inner.id()
    }

    fn local_agent(&self) -> Option<AgentRef> {
        self.inner.local_agent()
    }

    fn result(&self) -> BoxFuture<'static, Result<SubagentResult, SubagentError>> {
        self.result.clone().boxed()
    }

    fn dispose(&self) -> BoxFuture<'static, Result<(), SubagentError>> {
        self.inner.dispose()
    }
}

struct ProviderRegistration {
    id: u64,
    provider: Arc<dyn SubagentProvider>,
}

#[derive(Default)]
struct RegistryState {
    last_registration_id: u64,
    providers: Vec<ProviderRegistration>,
}

/// Cordis service implementing exact-name provider selection.
pub struct SubagentRuntime {
    state: Mutex<RegistryState>,
    events: EventReentry,
    next_run_id: AtomicU64,
}

impl SubagentRuntime {
    #[must_use]
    pub fn new(events: EventReentry) -> Self {
        Self {
            state: Mutex::new(RegistryState::default()),
            events,
            next_run_id: AtomicU64::new(0),
        }
    }

    fn allocate_run_id(&self) -> Result<SubagentRunId, SubagentError> {
        let previous = self
            .next_run_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| SubagentError::RunIdentityOverflow)?;
        Ok(SubagentRunId(format!("subagent-run-{}", previous + 1)))
    }

    fn register_provider(&self, provider: Arc<dyn SubagentProvider>) -> Result<u64, SubagentError> {
        let name = provider.name();
        if name.trim().is_empty() {
            return Err(SubagentError::InvalidProviderName);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| SubagentError::RegistryPoisoned)?;
        if state
            .providers
            .iter()
            .any(|registered| registered.provider.name() == name)
        {
            return Err(SubagentError::DuplicateProvider {
                name: name.to_owned(),
            });
        }
        let id = state
            .last_registration_id
            .checked_add(1)
            .ok_or(SubagentError::ProviderIdentityOverflow)?;
        state.last_registration_id = id;
        state.providers.push(ProviderRegistration { id, provider });
        Ok(id)
    }

    fn unregister_provider(&self, registration_id: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .providers
            .retain(|registered| registered.id != registration_id);
    }

    /// Registered provider names in insertion order.
    pub fn list(&self) -> Result<Vec<String>, SubagentError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| SubagentError::RegistryPoisoned)?
            .providers
            .iter()
            .map(|registered| registered.provider.name().to_owned())
            .collect())
    }

    /// Resolve the exact registered provider object.
    pub fn get_provider(
        &self,
        name: &str,
    ) -> Result<Option<Arc<dyn SubagentProvider>>, SubagentError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| SubagentError::RegistryPoisoned)?
            .providers
            .iter()
            .find(|registered| registered.provider.name() == name)
            .map(|registered| Arc::clone(&registered.provider)))
    }

    /// Select a provider, fail closed on unsupported options, and start it.
    pub async fn start(
        &self,
        name: &str,
        request: SubagentStartRequest,
    ) -> Result<Arc<dyn SubagentRun>, SubagentError> {
        let provider = self
            .get_provider(name)?
            .ok_or_else(|| SubagentError::NoProvider {
                name: name.to_owned(),
            })?;
        let capabilities = provider.capabilities();
        let requested = [
            (
                request.agent_options.is_some(),
                SubagentCapability::AgentOptions,
            ),
            (
                request.output_schema.is_some(),
                SubagentCapability::OutputSchema,
            ),
            (request.max_depth.is_some(), SubagentCapability::DepthLimit),
            (
                request.tool_filter.is_some(),
                SubagentCapability::ToolFilter,
            ),
            (request.persona.is_some(), SubagentCapability::Persona),
        ];
        if let Some((_, capability)) = requested
            .into_iter()
            .find(|(present, capability)| *present && !capabilities.supports(*capability))
        {
            return Err(SubagentError::UnsupportedCapability {
                provider: provider.name().to_owned(),
                capability,
            });
        }
        let run_id = self.allocate_run_id()?;
        let request = ResolvedSubagentStartRequest::one_shot(provider.name(), request);
        let parent = request.parent.clone();
        let run = provider.start(request).await?;
        let info = SubagentRunInfo {
            run_id,
            provider: provider.name().to_owned(),
            id: run.id().clone(),
            local: run.local_agent().is_some(),
            parent,
        };
        let terminal_info = info.clone();
        let terminal_events = self.events.clone();
        let result = run.result();
        let result = async move {
            let outcome = result.await;
            let (stop_reason, last_assistant_message) = match &outcome {
                Ok(result) => (
                    result.stop_reason,
                    (!result.output.is_empty()).then(|| result.output.clone()),
                ),
                Err(_) => (SubagentStopReason::Error, None),
            };
            let ended = SubagentRunEndInfo {
                run_id: terminal_info.run_id,
                provider: terminal_info.provider,
                id: terminal_info.id,
                local: terminal_info.local,
                parent: terminal_info.parent,
                stop_reason,
                last_assistant_message,
            };
            let _ = terminal_events.emit_contained(events::SUBAGENT_END, &ended);
            outcome
        }
        .boxed()
        .shared();
        let observed: Arc<dyn SubagentRun> = Arc::new(ObservedSubagentRun {
            inner: run,
            result: result.clone(),
        });
        let _ = self.events.emit_contained(events::SUBAGENT_START, &info);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move {
                drop(result.await);
            }));
        }
        Ok(observed)
    }
}

impl fmt::Debug for SubagentRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubagentRuntime")
            .finish_non_exhaustive()
    }
}

/// Register one Fiber-owned provider. Disposal blocks later selection only.
pub fn register_subagent_provider(
    ctx: &mut Context,
    provider: Arc<dyn SubagentProvider>,
) -> Result<RegistrationHandle, SubagentError> {
    let runtime = ctx
        .subagents::<SubagentRuntime>()
        .ok_or(SubagentError::RuntimeUnavailable)?;
    let registration_id = runtime.register_provider(provider)?;
    Ok(ctx.effect(move || {
        runtime.unregister_provider(registration_id);
    }))
}

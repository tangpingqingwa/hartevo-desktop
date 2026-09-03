//! Named provider registry for child-agent delegation.
//!
//! This module owns provider selection, the provider-neutral one-shot lifecycle,
//! and the first host-driven fresh-Session provider. Detached backends retain
//! their own transports; later slices add continuation and model-facing tools.

use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use thiserror::Error;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::agent::run_authorized_runtime_agent_turn;
use crate::service::Service;
use crate::session::{
    SessionError, SessionEventKind, SessionHandle, SessionMessage, SessionMessageRole,
    SessionMessageSource, SessionStore, SessionToolSchema, TurnEndReason,
    validate_agent_request_config,
};
use crate::surface::{
    AgentPreStepDecision, AgentPublicationCommit, AgentStatus, AgentStatusChange, AgentsSurface,
    HostToolExecutor, ToolDefinition, ToolRunContext, events as agent_events,
    register_tool_definition,
};
use crate::{
    AgentRef, Context, CordisError, Emit, EventKey, EventReentry, EventSchemaId,
    LifecycleCancellation, RegistrationHandle, SessionCallConfig, SessionContentBlock, SessionId,
    keys,
};

/// DeepSeek Harness descriptor format implemented by this slice.
pub const SUBAGENT_DESCRIPTOR_VERSION: u32 = 3;

/// Host-plane id of the first in-process one-shot provider plugin.
pub const SUBAGENT_SPAWN_IN_PROCESS_PLUGIN_ID: &str = "subagent-spawn-in-process";

/// Default registry name of the in-process fresh-session provider.
pub const SPAWN_SUBAGENT_PROVIDER_NAME: &str = "spawn";

/// Model-visible name of the first bounded foreground delegation tool.
pub const SUBAGENT_TOOL_NAME: &str = "subagent";

/// Absolute recursion cap for the built-in delegation tool. A top-level Agent
/// is depth zero, so depths one through three are admitted.
pub const DEFAULT_SUBAGENT_MAX_DEPTH: u32 = 3;

/// Services required by the host-plane in-process provider.
pub const SUBAGENT_SPAWN_IN_PROCESS_KEYS: &[&str] = &[keys::SUBAGENTS, keys::TOOLS];

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
    pub parent_session: Option<SessionId>,
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
            parent_session: None,
            cancellation: LifecycleCancellation::default(),
            agent_options: None,
            output_schema: None,
            max_depth: None,
            tool_filter: None,
            persona: None,
        }
    }

    /// Bind the exact parent Session when a provider creates a local child.
    #[must_use]
    pub fn with_parent_session(mut self, parent_session: SessionId) -> Self {
        self.parent_session = Some(parent_session);
        self
    }
}

/// Provider-facing request after Cordis has detached the durable descriptor.
#[derive(Debug, Clone)]
pub struct ResolvedSubagentStartRequest {
    pub label: Option<String>,
    pub prompt: Vec<SessionContentBlock>,
    pub parent: AgentRef,
    pub parent_session: Option<SessionId>,
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
            parent_session: request.parent_session,
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
    #[error("subagent provider `{provider}` requires the local Cordis host driver")]
    HostDriverRequired { provider: String },
    #[error("subagent provider `{provider}` requires an exact parent Session")]
    ParentSessionRequired { provider: String },
    #[error("subagent provider `{provider}` was cancelled before child publication")]
    AbortedBeforePublication { provider: String },
    #[error("subagent depth {attempted} exceeds max depth {max}")]
    DepthExceeded { attempted: u32, max: u32 },
    #[error("subagent child depth overflowed")]
    DepthOverflow,
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
            Self::HostDriverRequired { .. } => "HOST_DRIVER_REQUIRED",
            Self::ParentSessionRequired { .. } => "PARENT_SESSION_REQUIRED",
            Self::AbortedBeforePublication { .. } => "ABORTED",
            Self::DepthExceeded { .. } => "DEPTH_EXCEEDED",
            Self::DepthOverflow => "DEPTH_OVERFLOW",
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

    /// Resolve a same-Context child call before the host borrows its Context.
    ///
    /// Detached providers return `None`. A local provider returns the frozen
    /// config the host must drive, optionally replacing inherited parent
    /// options with the request's explicit `agent_options`.
    fn local_agent_config(
        &self,
        _request: &ResolvedSubagentStartRequest,
        _inherited: &SessionCallConfig,
    ) -> Option<SessionCallConfig> {
        None
    }
}

/// First host-plane provider: a fresh child Session on the same Cordis Context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnInProcessSubagent {
    provider_name: String,
}

impl SpawnInProcessSubagent {
    #[must_use]
    pub fn new(provider_name: impl Into<String>) -> Self {
        Self {
            provider_name: provider_name.into(),
        }
    }
}

impl Default for SpawnInProcessSubagent {
    fn default() -> Self {
        Self::new(SPAWN_SUBAGENT_PROVIDER_NAME)
    }
}

impl Service for SpawnInProcessSubagent {
    fn inject() -> &'static [&'static str] {
        SUBAGENT_SPAWN_IN_PROCESS_KEYS
    }

    fn apply(self, ctx: &mut Context) -> Result<(), CordisError> {
        let provider_name = self.provider_name.clone();
        let provider: Arc<dyn SubagentProvider> = Arc::new(self);
        let provider_registration = register_subagent_provider(ctx, provider)?;
        if let Err(error) =
            register_tool_definition(ctx, foreground_subagent_tool_definition(provider_name))
        {
            provider_registration.dispose();
            return Err(error);
        }
        Ok(())
    }
}

fn foreground_subagent_tool_definition(provider: String) -> ToolDefinition {
    let parameters = serde_json::Map::from_iter([
        ("type".into(), serde_json::json!("object")),
        ("additionalProperties".into(), serde_json::json!(false)),
        (
            "properties".into(),
            serde_json::json!({
                "prompt": {
                    "type": "string",
                    "description": "The complete, self-contained task for the subagent. It does not share this conversation's context, so include everything it needs."
                }
            }),
        ),
        ("required".into(), serde_json::json!(["prompt"])),
    ]);
    ToolDefinition::new_host(
        SessionToolSchema {
            name: SUBAGENT_TOOL_NAME.into(),
            description: "Delegate a self-contained task to a fresh subagent working in its own context. The call waits for the result and returns only the final answer; the child does not see this conversation, so provide a complete standalone prompt."
                .into(),
            parameters,
        },
        HostToolExecutor::ForegroundSubagent { provider },
    )
    .with_output_renderer(|_, value| render_foreground_subagent_output(value))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ForegroundSubagentArguments {
    prompt: String,
}

/// Execute the one bounded model-facing provider binding. The caller is the
/// sealed host-tool dispatcher, so the exact Agent and Session identities come
/// from the durable tool input instead of model-authored arguments.
pub(crate) async fn run_foreground_subagent_tool(
    ctx: &mut Context,
    tool: &ToolRunContext,
    provider: String,
    inherited_config: SessionCallConfig,
) -> Result<serde_json::Value, String> {
    let arguments: ForegroundSubagentArguments =
        serde_json::from_value(tool.arguments().clone())
            .map_err(|error| format!("invalid subagent arguments: {error}"))?;
    if arguments.prompt.trim().is_empty() {
        return Err("subagent prompt must not be blank".into());
    }
    let runtime = ctx
        .subagents::<SubagentRuntime>()
        .ok_or_else(|| "the Cordis subagent runtime is unavailable".to_string())?;
    let mut request = SubagentStartRequest::new(
        tool.agent().clone(),
        vec![SessionContentBlock::Text {
            text: arguments.prompt,
        }],
    )
    .with_parent_session(tool.session_id().clone());
    request.cancellation = tool.cancellation().clone();
    request.max_depth = Some(DEFAULT_SUBAGENT_MAX_DEPTH);
    let run = runtime
        .start_local(ctx, &provider, request, inherited_config)
        .await
        .map_err(|error| error.to_string())?;
    settle_foreground_subagent_run(run).await
}

async fn settle_foreground_subagent_run(
    run: Arc<dyn SubagentRun>,
) -> Result<serde_json::Value, String> {
    let run_id = run.id().as_str().to_owned();
    let result_run = Arc::clone(&run);
    let execution = match AssertUnwindSafe(async move {
        let result = result_run
            .result()
            .await
            .map_err(|error| error.to_string())?;
        foreground_subagent_result(&run_id, result)
    })
    .catch_unwind()
    .await
    {
        Ok(result) => result,
        Err(_) => Err("subagent result collection panicked".into()),
    };
    let disposal =
        match AssertUnwindSafe(
            async move { run.dispose().await.map_err(|error| error.to_string()) },
        )
        .catch_unwind()
        .await
        {
            Ok(result) => result,
            Err(_) => Err("subagent disposal panicked".into()),
        };
    match (execution, disposal) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(dispose)) => Err(dispose),
        (Err(error), Err(dispose)) => Err(format!(
            "subagent run failed: {error}; dispose failed: {dispose}"
        )),
    }
}

fn foreground_subagent_result(
    run_id: &str,
    result: SubagentResult,
) -> Result<serde_json::Value, String> {
    if result.stop_reason != SubagentStopReason::Completed {
        return Err(subagent_stop_error(&result));
    }
    let output = serde_json::to_value(result.output)
        .map_err(|error| format!("subagent output could not be encoded: {error}"))?;
    Ok(serde_json::json!({
        "kind": "foreground",
        "runId": run_id,
        "output": output,
    }))
}

fn subagent_stop_error(result: &SubagentResult) -> String {
    let headline = match result.stop_reason {
        SubagentStopReason::Completed => "subagent run completed",
        SubagentStopReason::Aborted => "subagent run was cancelled",
        SubagentStopReason::Error => "subagent run failed",
        SubagentStopReason::MaxTokens => "subagent run hit its token limit before finishing",
        SubagentStopReason::Refusal => "subagent declined the task",
    };
    let diagnostic = result
        .diagnostic
        .as_ref()
        .map_or_else(String::new, |detail| format!("\nDiagnostic: {detail}"));
    let partial = result
        .output
        .iter()
        .filter_map(|block| match block {
            SessionContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<String>();
    let partial = if partial.is_empty() {
        String::new()
    } else {
        format!("\nPartial output before the run ended:\n{partial}")
    };
    format!("{headline}{diagnostic}{partial}")
}

fn render_foreground_subagent_output(
    value: &serde_json::Value,
) -> Result<Vec<SessionContentBlock>, String> {
    let output = value
        .get("output")
        .cloned()
        .ok_or_else(|| "foreground subagent result has no output".to_string())?;
    let output: Vec<SessionContentBlock> = serde_json::from_value(output)
        .map_err(|error| format!("foreground subagent output is invalid: {error}"))?;
    let text = output
        .iter()
        .filter_map(|block| match block {
            SessionContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<String>();
    Ok(vec![SessionContentBlock::Text { text }])
}

impl SubagentProvider for SpawnInProcessSubagent {
    fn name(&self) -> &str {
        &self.provider_name
    }

    fn capabilities(&self) -> SubagentCapabilities {
        SubagentCapabilities::NONE
            .with(SubagentCapability::AgentOptions)
            .with(SubagentCapability::DepthLimit)
    }

    fn inherits_parent_context(&self) -> bool {
        false
    }

    fn start(
        &self,
        _request: ResolvedSubagentStartRequest,
    ) -> BoxFuture<'static, Result<Arc<dyn SubagentRun>, SubagentError>> {
        let provider = self.provider_name.clone();
        async move { Err(SubagentError::HostDriverRequired { provider }) }.boxed()
    }

    fn local_agent_config(
        &self,
        request: &ResolvedSubagentStartRequest,
        inherited: &SessionCallConfig,
    ) -> Option<SessionCallConfig> {
        Some(
            request
                .agent_options
                .clone()
                .unwrap_or_else(|| inherited.clone()),
        )
    }
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

struct PreparedSubagentStart {
    run_id: SubagentRunId,
    provider_name: String,
    provider: Arc<dyn SubagentProvider>,
    request: ResolvedSubagentStartRequest,
}

struct LocalSubagentRunState {
    result: Option<Result<SubagentResult, SubagentError>>,
    publication: Option<AgentPublicationCommit>,
}

struct LocalSubagentRun {
    id: SessionId,
    agent: AgentRef,
    events: EventReentry,
    state: Arc<Mutex<LocalSubagentRunState>>,
    settled: Arc<Notify>,
}

impl LocalSubagentRun {
    fn new(
        id: SessionId,
        agent: AgentRef,
        events: EventReentry,
        publication: AgentPublicationCommit,
    ) -> Self {
        Self {
            id,
            agent,
            events,
            state: Arc::new(Mutex::new(LocalSubagentRunState {
                result: None,
                publication: Some(publication),
            })),
            settled: Arc::new(Notify::new()),
        }
    }

    fn settle(&self, result: Result<SubagentResult, SubagentError>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.result.is_some() {
            return;
        }
        let became_idle = state
            .publication
            .as_ref()
            .is_some_and(AgentPublicationCommit::mark_idle);
        state.result = Some(result);
        drop(state);
        if became_idle {
            let _ = self.events.emit_contained(
                agent_events::AGENT_STATUS,
                &AgentStatusChange::new(self.agent.clone(), AgentStatus::Idle),
            );
        }
        self.settled.notify_waiters();
    }

    fn release_publication(&self) {
        let publication = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .publication
            .take();
        if publication.is_some() {
            drop(publication);
            let _ = self
                .events
                .emit_contained(agent_events::AGENT_DISPOSED, &self.agent);
        }
    }
}

impl SubagentRun for LocalSubagentRun {
    fn id(&self) -> &SessionId {
        &self.id
    }

    fn local_agent(&self) -> Option<AgentRef> {
        Some(self.agent.clone())
    }

    fn result(&self) -> BoxFuture<'static, Result<SubagentResult, SubagentError>> {
        let state = Arc::clone(&self.state);
        let settled = Arc::clone(&self.settled);
        async move {
            loop {
                let notified = settled.notified();
                if let Some(result) = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .result
                    .clone()
                {
                    return result;
                }
                notified.await;
            }
        }
        .boxed()
    }

    fn dispose(&self) -> BoxFuture<'static, Result<(), SubagentError>> {
        let state = Arc::clone(&self.state);
        let events = self.events.clone();
        let agent = self.agent.clone();
        async move {
            let publication = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .publication
                .take();
            if publication.is_some() {
                drop(publication);
                let _ = events.emit_contained(agent_events::AGENT_DISPOSED, &agent);
            }
            Ok(())
        }
        .boxed()
    }
}

struct LocalSubagentDriveGuard {
    run: Arc<LocalSubagentRun>,
    child: SessionHandle,
    provider: String,
    descriptor_listener: Option<crate::ListenerHandle>,
    finished: bool,
}

impl LocalSubagentDriveGuard {
    fn new(
        run: Arc<LocalSubagentRun>,
        child: SessionHandle,
        provider: String,
        descriptor_listener: crate::ListenerHandle,
    ) -> Self {
        Self {
            run,
            child,
            provider,
            descriptor_listener: Some(descriptor_listener),
            finished: false,
        }
    }

    fn finish(mut self, result: Result<SubagentResult, SubagentError>) {
        if let Some(listener) = self.descriptor_listener.take() {
            listener.dispose();
        }
        self.run.settle(result);
        self.finished = true;
    }
}

impl Drop for LocalSubagentDriveGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(listener) = self.descriptor_listener.take() {
            listener.dispose();
        }
        let output = final_assistant_output(&self.child).unwrap_or_default();
        let mut result = SubagentResult::new(output, SubagentStopReason::Aborted);
        result.diagnostic = Some(format!(
            "subagent provider `{}` host drive was dropped before settlement",
            self.provider
        ));
        self.run.settle(Ok(result));
        self.run.release_publication();
    }
}

struct LocalSessionEstablishment {
    sessions: Arc<SessionStore>,
    child: Option<SessionHandle>,
}

impl LocalSessionEstablishment {
    fn new(sessions: Arc<SessionStore>, child: SessionHandle) -> Self {
        Self {
            sessions,
            child: Some(child),
        }
    }

    fn commit(mut self) {
        self.child.take();
    }
}

impl Drop for LocalSessionEstablishment {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            let _ = self.sessions.remove_exact(&child);
        }
    }
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

    fn prepare_start(
        &self,
        name: &str,
        request: SubagentStartRequest,
    ) -> Result<PreparedSubagentStart, SubagentError> {
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
        let provider_name = provider.name().to_owned();
        let request = ResolvedSubagentStartRequest::one_shot(&provider_name, request);
        Ok(PreparedSubagentStart {
            run_id,
            provider_name,
            provider,
            request,
        })
    }

    fn observe_run(
        &self,
        run_id: SubagentRunId,
        provider: String,
        parent: AgentRef,
        run: Arc<dyn SubagentRun>,
    ) -> Arc<dyn SubagentRun> {
        let info = SubagentRunInfo {
            run_id,
            provider,
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
        observed
    }

    /// Select a provider, fail closed on unsupported options, and start it.
    pub async fn start(
        &self,
        name: &str,
        request: SubagentStartRequest,
    ) -> Result<Arc<dyn SubagentRun>, SubagentError> {
        let prepared = self.prepare_start(name, request)?;
        let parent = prepared.request.parent.clone();
        let run = prepared.provider.start(prepared.request).await?;
        Ok(self.observe_run(prepared.run_id, prepared.provider_name, parent, run))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one ordered host transaction keeps child establishment, publication, drive, and settlement adjacent"
    )]
    pub(crate) async fn start_local(
        &self,
        ctx: &mut Context,
        name: &str,
        request: SubagentStartRequest,
        inherited_config: SessionCallConfig,
    ) -> Result<Arc<dyn SubagentRun>, SubagentError> {
        let prepared = self.prepare_start(name, request)?;
        let provider = prepared.provider_name.clone();
        let config = prepared
            .provider
            .local_agent_config(&prepared.request, &inherited_config)
            .ok_or_else(|| SubagentError::HostDriverRequired {
                provider: provider.clone(),
            })?;
        validate_agent_request_config(&config)
            .map_err(|error| provider_start_failure(&provider, error))?;
        if prepared.request.cancellation.is_cancelled() {
            return Err(SubagentError::AbortedBeforePublication { provider });
        }
        let parent_session = prepared.request.parent_session.clone().ok_or_else(|| {
            SubagentError::ParentSessionRequired {
                provider: provider.clone(),
            }
        })?;
        let sessions = ctx
            .sessions::<SessionStore>()
            .ok_or_else(|| provider_start_failure(&provider, "SessionStore is unavailable"))?;
        let parent = sessions
            .get(&parent_session)
            .map_err(|error| provider_start_failure(&provider, error))?
            .ok_or_else(|| provider_start_failure(&provider, "parent Session is unavailable"))?;
        let attempted_depth = parent
            .header()
            .map_err(|error| provider_start_failure(&provider, error))?
            .delegation_depth
            .checked_add(1)
            .ok_or(SubagentError::DepthOverflow)?;
        if let Some(max_depth) = prepared.request.max_depth
            && attempted_depth > max_depth
        {
            return Err(SubagentError::DepthExceeded {
                attempted: attempted_depth,
                max: max_depth,
            });
        }
        let child_id = SessionId::new(Uuid::now_v7().to_string())
            .map_err(|error| provider_start_failure(&provider, error))?;
        let child = sessions
            .spawn_child(&parent_session, child_id.clone())
            .map_err(|error| provider_start_failure(&provider, error))?;
        let establishment = LocalSessionEstablishment::new(Arc::clone(&sessions), child.clone());
        child
            .inbox()
            .append_next_turn(SessionMessage {
                id: format!("subagent:{}:prompt", child_id.as_str()),
                role: SessionMessageRole::User,
                content: prepared.request.prompt.clone(),
                source: SessionMessageSource::User,
            })
            .map_err(|error| provider_start_failure(&provider, error))?;

        let child_agent = AgentRef::new(child_id.as_str());
        let descriptor_appended = Arc::new(AtomicBool::new(false));
        let descriptor_failure = Arc::new(Mutex::new(None::<String>));
        let descriptor_listener = ctx
            .on_waterfall(agent_events::AGENT_PRE_STEP, {
                let child_agent = child_agent.clone();
                let child = child.clone();
                let descriptor = prepared.request.descriptor.clone();
                let descriptor_appended = Arc::clone(&descriptor_appended);
                let descriptor_failure = Arc::clone(&descriptor_failure);
                move |proposal, next| {
                    let proposal = next(proposal);
                    if proposal.agent().is_same_lifecycle(&child_agent)
                        && matches!(proposal.decision(), AgentPreStepDecision::Enter { .. })
                        && !descriptor_appended.swap(true, Ordering::AcqRel)
                        && let Err(error) = child.append_subagent_descriptor(descriptor.clone())
                    {
                        *descriptor_failure
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(error.to_string());
                        return proposal.reject();
                    }
                    proposal
                }
            })
            .map_err(|error| provider_start_failure(&provider, error))?;
        let agents = ctx
            .agents::<AgentsSurface>()
            .ok_or_else(|| provider_start_failure(&provider, "AgentsSurface is unavailable"))?;
        let publication = agents
            .prepare_publication(child_agent.clone())
            .commit()
            .map_err(|error| provider_start_failure(&provider, error))?;
        let local = Arc::new(LocalSubagentRun::new(
            child_id.clone(),
            child_agent.clone(),
            self.events.clone(),
            publication,
        ));
        let _ = self
            .events
            .emit_contained(agent_events::AGENT_CREATED, &child_agent);
        let _ = self.events.emit_contained(
            agent_events::AGENT_STATUS,
            &AgentStatusChange::new(child_agent.clone(), AgentStatus::Running),
        );
        let erased: Arc<dyn SubagentRun> = local.clone();
        let observed = self.observe_run(
            prepared.run_id,
            prepared.provider_name,
            prepared.request.parent,
            erased,
        );
        let drive = LocalSubagentDriveGuard::new(
            Arc::clone(&local),
            child.clone(),
            provider.clone(),
            descriptor_listener,
        );
        establishment.commit();

        let outcome = Box::pin(run_authorized_runtime_agent_turn(
            ctx,
            &child_agent,
            &child_id,
            config,
            &prepared.request.cancellation,
        ))
        .await;
        let descriptor_failure = descriptor_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drive.finish(local_result(&child, outcome, descriptor_failure, &provider));
        Ok(observed)
    }
}

fn provider_start_failure(provider: &str, error: impl fmt::Display) -> SubagentError {
    SubagentError::ProviderStart {
        provider: provider.to_owned(),
        detail: error.to_string(),
    }
}

fn local_result(
    child: &SessionHandle,
    outcome: Result<crate::AgentTurnOutcome, CordisError>,
    descriptor_failure: Option<String>,
    provider: &str,
) -> Result<SubagentResult, SubagentError> {
    let output =
        final_assistant_output(child).map_err(|error| provider_start_failure(provider, error))?;
    if let Some(diagnostic) = descriptor_failure {
        let mut result = SubagentResult::new(output, SubagentStopReason::Error);
        result.diagnostic = Some(diagnostic);
        return Ok(result);
    }
    match outcome {
        Ok(outcome) => Ok(SubagentResult::new(
            output,
            subagent_stop_reason(outcome.reason()),
        )),
        Err(error) => {
            let mut result = SubagentResult::new(output, SubagentStopReason::Error);
            result.diagnostic = Some(error.to_string());
            Ok(result)
        }
    }
}

fn final_assistant_output(child: &SessionHandle) -> Result<Vec<SessionContentBlock>, SessionError> {
    Ok(child
        .events()?
        .into_iter()
        .rev()
        .find_map(|event| match event.kind {
            SessionEventKind::AssistantMessage { message, .. } => Some(message.content),
            _ => None,
        })
        .unwrap_or_default())
}

const fn subagent_stop_reason(reason: TurnEndReason) -> SubagentStopReason {
    match reason {
        TurnEndReason::Completed => SubagentStopReason::Completed,
        TurnEndReason::Aborted(_) => SubagentStopReason::Aborted,
        TurnEndReason::Blocked => SubagentStopReason::Refusal,
        TurnEndReason::MaxTokens => SubagentStopReason::MaxTokens,
        TurnEndReason::Error | TurnEndReason::Interrupted => SubagentStopReason::Error,
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

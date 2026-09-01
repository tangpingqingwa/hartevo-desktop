//! Map Hartevo surfaces onto Cordis service keys.
//!
//! Practice mapping, not a second runtime. Plugins look up `ctx.tools`,
//! `ctx.llm`, `ctx.agents`, plus Hartevo-owned `ctx.domain`,
//! `ctx.effect_broker`, `ctx.runtime`, and `ctx.desktop`. Registrations
//! reverse through the existing `effect()` / `on()` disposer stack.
//! OpenInterpreter is never provided on those Hartevo-owned keys.

use std::collections::HashSet;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

use futures_core::Stream;

use crate::context::{Context, CordisError, keys};
use crate::effect::RegistrationHandle;
use crate::event::{DispatchMode, EventKey, EventModeMarker};
use crate::session::{
    SessionCallConfig, SessionCallConfigAdapterDefaults, SessionFinishReason, SessionId,
    SessionLlmFailure, SessionMessage, SessionStore, SessionStreamChunk, SessionToolCall,
    SessionToolSchema, events as session_events, validate_agent_request_config,
};

/// Cordis keys this mapping provides and looks up.
pub const MAPPED_KEYS: &[&str] = &[
    keys::TOOLS,
    keys::SYSTEM_PROMPT,
    keys::LLM,
    keys::SESSIONS,
    keys::AGENTS,
    keys::DOMAIN,
    keys::EFFECT_BROKER,
    keys::RUNTIME,
    keys::DESKTOP,
];

/// Primer event names owned by the mapped surfaces.
pub mod events {
    use crate::event::{Emit, EventKey, EventSchemaId, Waterfall};

    use super::{AgentPreStep, AgentRef, AgentRequest, LlmStream, PromptAssembly, ToolCall};

    /// Replace or wrap one detached system-prompt/tool-schema assembly.
    pub const SYSTEM_PROMPT_ASSEMBLE: EventKey<Waterfall, PromptAssembly, PromptAssembly> =
        EventKey::new(
            EventSchemaId::new("hartevo.system-prompt.assemble.v1"),
            "system-prompt/assemble",
        );

    /// Allow / deny / ask waterfall before a tool body runs.
    pub const TOOLS_PRE_EXECUTE: EventKey<Waterfall, ToolCall, ToolCall> = EventKey::new(
        EventSchemaId::new("hartevo.tools.pre-execute.v1"),
        "tools/pre-execute",
    );
    /// Around-dispatch waterfall wrapping the tool body.
    pub const TOOLS_EXECUTE: EventKey<Waterfall, ToolCall, ToolCall> = EventKey::new(
        EventSchemaId::new("hartevo.tools.execute.v1"),
        "tools/execute",
    );
    /// Inspect / replace waterfall after a tool body.
    pub const TOOLS_POST_EXECUTE: EventKey<Waterfall, ToolCall, ToolCall> = EventKey::new(
        EventSchemaId::new("hartevo.tools.post-execute.v1"),
        "tools/post-execute",
    );
    /// Observe-only notification of the frozen tool outcome.
    pub const TOOLS_RESULT: EventKey<Emit, ToolCall, ()> = EventKey::new(
        EventSchemaId::new("hartevo.tools.result.v1"),
        "tools/result",
    );
    /// Intercept / wrap every streaming model call.
    pub const LLM_STREAM: EventKey<Waterfall, LlmStream, LlmStream> =
        EventKey::new(EventSchemaId::new("hartevo.llm.stream.v1"), "llm/stream");
    /// Live agent published after scoped setup.
    pub const AGENT_CREATED: EventKey<Emit, AgentRef, ()> = EventKey::new(
        EventSchemaId::new("hartevo.agent.created.v1"),
        "agent/created",
    );
    /// Live agent left the registry.
    pub const AGENT_DISPOSED: EventKey<Emit, AgentRef, ()> = EventKey::new(
        EventSchemaId::new("hartevo.agent.disposed.v1"),
        "agent/disposed",
    );
    /// Reject or replace the exact message batch proposed for one agent step.
    pub const AGENT_PRE_STEP: EventKey<Waterfall, AgentPreStep, AgentPreStep> = EventKey::new(
        EventSchemaId::new("hartevo.agent.pre-step.v1"),
        "agent/pre-step",
    );
    /// Replace only the call config for one exact open agent step.
    pub const AGENT_REQUEST: EventKey<Waterfall, AgentRequest, AgentRequest> = EventKey::new(
        EventSchemaId::new("hartevo.agent.request.v1"),
        "agent/request",
    );
}

/// Who currently owns a mapped surface. OpenInterpreter never owns Mission,
/// Truth, or Effect, and is not a valid owner for domain / effect_broker /
/// runtime / desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SurfaceOwner {
    #[default]
    Hartevo,
    OpenInterpreter,
}

impl SurfaceOwner {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hartevo => "hartevo",
            Self::OpenInterpreter => "openinterpreter",
        }
    }
}

/// One reversible static system-prompt contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptSection {
    pub name: String,
    pub order: i64,
    pub text: String,
}

impl PromptSection {
    #[must_use]
    pub fn new(name: impl Into<String>, order: i64, text: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            order,
            text: text.into(),
        }
    }
}

/// Frozen model-visible system text and tool schemas for one agent step.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PromptAssembly {
    system: Option<String>,
    tools: Vec<SessionToolSchema>,
}

impl PromptAssembly {
    #[must_use]
    pub fn new(system: Option<String>, tools: Vec<SessionToolSchema>) -> Self {
        Self { system, tools }
    }

    #[must_use]
    pub fn system(&self) -> Option<&str> {
        self.system.as_deref()
    }

    #[must_use]
    pub fn tools(&self) -> &[SessionToolSchema] {
        &self.tools
    }

    #[must_use]
    pub fn with_system(mut self, system: Option<String>) -> Self {
        self.system = system;
        self
    }

    #[must_use]
    pub fn with_tools(mut self, tools: Vec<SessionToolSchema>) -> Self {
        self.tools = tools;
        self
    }

    fn validated(mut self) -> Result<Self, PromptError> {
        if self.system.as_ref().is_some_and(String::is_empty) {
            self.system = None;
        }
        let mut names = HashSet::new();
        for tool in &self.tools {
            if tool.name.is_empty() {
                return Err(PromptError::InvalidToolName);
            }
            if !names.insert(tool.name.clone()) {
                return Err(PromptError::DuplicateTool {
                    name: tool.name.clone(),
                });
            }
        }
        Ok(self)
    }
}

/// Fail-closed prompt and model-visible tool registration failures.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PromptError {
    #[error("system prompt section name must be non-empty")]
    InvalidSectionName,
    #[error("system prompt section `{name}` is already registered")]
    DuplicateSection { name: String },
    #[error("model-visible tool name must be non-empty")]
    InvalidToolName,
    #[error("model-visible tool `{name}` is already registered")]
    DuplicateTool { name: String },
    #[error("system prompt registry mutex is poisoned")]
    RegistryPoisoned,
    #[error("tools registry mutex is poisoned")]
    ToolsRegistryPoisoned,
}

/// Cordis-owned registry for deterministic prompt-section assembly.
#[derive(Debug, Clone, Default)]
pub struct SystemPromptSurface {
    sections: Arc<Mutex<Vec<PromptSection>>>,
}

impl SystemPromptSurface {
    fn register(&self, section: PromptSection) -> Result<(), PromptError> {
        if section.name.is_empty() {
            return Err(PromptError::InvalidSectionName);
        }
        let mut sections = self
            .sections
            .lock()
            .map_err(|_| PromptError::RegistryPoisoned)?;
        if sections
            .iter()
            .any(|existing| existing.name == section.name)
        {
            return Err(PromptError::DuplicateSection { name: section.name });
        }
        sections.push(section);
        Ok(())
    }

    fn unregister(&self, name: &str) {
        let mut sections = self
            .sections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sections.retain(|section| section.name != name);
    }

    fn assemble(&self, tools: Vec<SessionToolSchema>) -> Result<PromptAssembly, PromptError> {
        let mut sections = self
            .sections
            .lock()
            .map_err(|_| PromptError::RegistryPoisoned)?
            .clone();
        sections.sort_by(|left, right| {
            left.order
                .cmp(&right.order)
                .then_with(|| left.name.cmp(&right.name))
        });
        let system = sections
            .into_iter()
            .map(|section| section.text)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        PromptAssembly::new(Some(system), tools).validated()
    }
}

/// One tool pipeline call. Policy may rewrite [`ToolCall::decision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// Exact model call identity when one exists. The legacy constructor leaves
    /// this empty so the AgentLoop can assign a deterministic step-local id.
    pub call_id: String,
    pub name: String,
    pub arguments: String,
    pub decision: String,
    pub result: String,
    execution_input: Option<ToolExecutionInput>,
}

impl ToolCall {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        arguments: impl Into<String>,
        decision: impl Into<String>,
    ) -> Self {
        Self {
            call_id: String::new(),
            name: name.into(),
            arguments: arguments.into(),
            decision: decision.into(),
            result: String::new(),
            execution_input: None,
        }
    }

    /// Preserve an exact model-provided id through policy and execution.
    #[must_use]
    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Self {
        self.call_id = call_id.into();
        self
    }

    /// Exact durable input when this call is traversing the N52 pre-execute
    /// boundary. Legacy pipeline calls have no durable input attached.
    #[must_use]
    pub const fn execution_input(&self) -> Option<&ToolExecutionInput> {
        self.execution_input.as_ref()
    }

    fn from_execution_input(input: &ToolExecutionInput) -> Self {
        Self {
            call_id: input.call_id().to_string(),
            name: input.name().to_string(),
            arguments: input.raw_arguments().to_string(),
            decision: "allow".into(),
            result: String::new(),
            execution_input: Some(input.clone()),
        }
    }
}

/// One durable model tool call materialized for the execution pipeline.
///
/// Raw arguments remain available for exact replay while [`Self::arguments`]
/// follows Harness parsing: empty input is `{}`, valid JSON is decoded, and
/// malformed JSON remains its original string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionInput {
    call_seq: u64,
    turn: u64,
    step: u64,
    call_id: String,
    name: String,
    raw_arguments: String,
    arguments: serde_json::Value,
}

impl ToolExecutionInput {
    pub(crate) fn from_session_call(call: &SessionToolCall) -> Self {
        Self {
            call_seq: call.seq,
            turn: call.turn,
            step: call.step,
            call_id: call.call_id.clone(),
            name: call.name.clone(),
            raw_arguments: call.arguments.clone(),
            arguments: parse_tool_arguments(&call.arguments),
        }
    }

    #[must_use]
    pub const fn call_seq(&self) -> u64 {
        self.call_seq
    }

    #[must_use]
    pub const fn turn(&self) -> u64 {
        self.turn
    }

    #[must_use]
    pub const fn step(&self) -> u64 {
        self.step
    }

    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn raw_arguments(&self) -> &str {
        &self.raw_arguments
    }

    #[must_use]
    pub const fn arguments(&self) -> &serde_json::Value {
        &self.arguments
    }
}

fn parse_tool_arguments(raw: &str) -> serde_json::Value {
    if raw.is_empty() {
        return serde_json::Value::Object(serde_json::Map::new());
    }
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_string()))
}

/// Live scheduling mode for one not-yet-started tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolExecutionMode {
    Parallel,
    Exclusive,
}

/// One call admitted through ordered policy and guards for later dispatch.
///
/// The registration identity is intentionally opaque. A later dispatch stage
/// must revalidate it through [`ToolsSurface::preparation_is_current`] before
/// invoking a tool body.
pub struct PreparedToolExecution {
    input: ToolExecutionInput,
    mode: ToolExecutionMode,
    registration_identity: Arc<()>,
}

impl fmt::Debug for PreparedToolExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedToolExecution")
            .field("input", &self.input)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl PreparedToolExecution {
    #[must_use]
    pub const fn input(&self) -> &ToolExecutionInput {
        &self.input
    }

    #[must_use]
    pub const fn mode(&self) -> ToolExecutionMode {
        self.mode
    }
}

/// One call stopped before dispatch with a model-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedToolExecution {
    input: ToolExecutionInput,
    reason: String,
}

impl DeniedToolExecution {
    #[must_use]
    pub const fn input(&self) -> &ToolExecutionInput {
        &self.input
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Ordered pre-execution outcome. Neither variant has invoked a tool body or
/// mutated the durable session.
#[derive(Debug)]
pub enum ToolExecutionPreparation {
    Dispatch(PreparedToolExecution),
    Denied(DeniedToolExecution),
}

impl ToolExecutionPreparation {
    #[must_use]
    pub const fn input(&self) -> &ToolExecutionInput {
        match self {
            Self::Dispatch(prepared) => prepared.input(),
            Self::Denied(denied) => denied.input(),
        }
    }
}

/// Fully assembled provider-neutral request presented to one LLM adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmGenerateRequest {
    config: SessionCallConfig,
    messages: Vec<SessionMessage>,
    system: Option<String>,
    tools: Option<Vec<SessionToolSchema>>,
    session_id: Option<SessionId>,
}

impl LlmGenerateRequest {
    #[must_use]
    pub fn new(config: SessionCallConfig, messages: Vec<SessionMessage>) -> Self {
        Self {
            config,
            messages,
            system: None,
            tools: None,
            session_id: None,
        }
    }

    #[must_use]
    pub const fn config(&self) -> &SessionCallConfig {
        &self.config
    }

    #[must_use]
    pub fn messages(&self) -> &[SessionMessage] {
        &self.messages
    }

    #[must_use]
    pub fn system(&self) -> Option<&str> {
        self.system.as_deref()
    }

    #[must_use]
    pub fn tools(&self) -> Option<&[SessionToolSchema]> {
        self.tools.as_deref()
    }

    #[must_use]
    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    #[must_use]
    pub fn with_system(mut self, system: Option<String>) -> Self {
        self.system = system.filter(|value| !value.is_empty());
        self
    }

    #[must_use]
    pub fn with_tools(mut self, tools: Vec<SessionToolSchema>) -> Self {
        self.tools = (!tools.is_empty()).then_some(tools);
        self
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

/// Raw adapter stream. An item error is normalized into one terminal chunk.
pub type LlmAdapterStream =
    Pin<Box<dyn Stream<Item = Result<SessionStreamChunk, SessionLlmFailure>> + Send + 'static>>;

/// Provider-neutral stream exposed after Cordis middleware and normalization.
pub type LlmChunkStream = Pin<Box<dyn Stream<Item = SessionStreamChunk> + Send + 'static>>;

type LlmStreamFactory = Box<dyn FnOnce() -> LlmChunkStream + Send + 'static>;

#[derive(Clone, Default)]
struct LlmStreamSource {
    factory: Arc<Mutex<Option<LlmStreamFactory>>>,
}

impl LlmStreamSource {
    fn new(factory: LlmStreamFactory) -> Self {
        Self {
            factory: Arc::new(Mutex::new(Some(factory))),
        }
    }

    fn replace(&self, factory: LlmStreamFactory) {
        *self
            .factory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(factory);
    }

    fn take(&self) -> Option<LlmStreamFactory> {
        self.factory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn is_available(&self) -> bool {
        self.factory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
}

/// One model stream dispatch. Legacy callers use the public string fields;
/// generated calls carry an immutable request and a lazy typed chunk source.
#[derive(Clone)]
pub struct LlmStream {
    pub model: String,
    pub prompt: String,
    pub body: String,
    request: Option<LlmGenerateRequest>,
    source: LlmStreamSource,
}

impl LlmStream {
    #[must_use]
    pub fn new(model: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            prompt: prompt.into(),
            body: String::new(),
            request: None,
            source: LlmStreamSource::default(),
        }
    }

    fn generated(request: LlmGenerateRequest, factory: LlmStreamFactory) -> Self {
        Self {
            model: request.config.model.clone(),
            prompt: String::new(),
            body: String::new(),
            request: Some(request),
            source: LlmStreamSource::new(factory),
        }
    }

    /// Return the immutable generated request, or `None` for the legacy path.
    #[must_use]
    pub const fn request(&self) -> Option<&LlmGenerateRequest> {
        self.request.as_ref()
    }

    /// Short-circuit downstream adapter dispatch with a middleware-owned stream.
    #[must_use]
    pub fn with_chunk_stream(self, stream: LlmChunkStream) -> Self {
        self.source.replace(Box::new(move || stream));
        self
    }

    /// Lazily wrap the downstream typed stream without starting adapter work.
    pub fn map_chunk_stream<F>(self, wrap: F) -> Result<Self, LlmError>
    where
        F: FnOnce(LlmChunkStream) -> LlmChunkStream + Send + 'static,
    {
        let factory = self.source.take().ok_or(LlmError::InvalidStreamDispatch {
            expected: "one unconsumed typed chunk source",
        })?;
        self.source.replace(Box::new(move || wrap(factory())));
        Ok(self)
    }

    fn into_chunk_stream(self) -> Result<LlmChunkStream, LlmError> {
        self.source
            .take()
            .map(|factory| factory())
            .ok_or(LlmError::InvalidStreamDispatch {
                expected: "one unconsumed typed chunk source",
            })
    }
}

impl fmt::Debug for LlmStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmStream")
            .field("model", &self.model)
            .field("prompt", &self.prompt)
            .field("body", &self.body)
            .field("request", &self.request)
            .field("has_chunk_stream", &self.source.is_available())
            .finish()
    }
}

impl PartialEq for LlmStream {
    fn eq(&self, other: &Self) -> bool {
        self.model == other.model
            && self.prompt == other.prompt
            && self.body == other.body
            && self.request == other.request
    }
}

impl Eq for LlmStream {}

/// Adapter-owned selectable reasoning metadata for one exact model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmModelReasoning {
    efforts: Vec<String>,
    default_effort: Option<String>,
}

impl LlmModelReasoning {
    #[must_use]
    pub fn new(efforts: Vec<String>, default_effort: Option<String>) -> Self {
        Self {
            efforts,
            default_effort,
        }
    }

    #[must_use]
    pub fn efforts(&self) -> &[String] {
        &self.efforts
    }

    #[must_use]
    pub fn default_effort(&self) -> Option<&str> {
        self.default_effort.as_deref()
    }
}

/// Exact provider/model metadata returned by one adapter preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmResolvedModel {
    provider: String,
    model: String,
    context_window: Option<u64>,
    default_max_tokens: Option<u64>,
    reasoning: Option<LlmModelReasoning>,
}

impl LlmResolvedModel {
    #[must_use]
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            context_window: None,
            default_max_tokens: None,
            reasoning: None,
        }
    }

    #[must_use]
    pub fn with_context_window(mut self, context_window: u64) -> Self {
        self.context_window = Some(context_window);
        self
    }

    #[must_use]
    pub fn with_default_max_tokens(mut self, default_max_tokens: u64) -> Self {
        self.default_max_tokens = Some(default_max_tokens);
        self
    }

    #[must_use]
    pub fn with_reasoning(mut self, reasoning: LlmModelReasoning) -> Self {
        self.reasoning = Some(reasoning);
        self
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    #[must_use]
    pub const fn context_window(&self) -> Option<u64> {
        self.context_window
    }

    #[must_use]
    pub const fn default_max_tokens(&self) -> Option<u64> {
        self.default_max_tokens
    }

    #[must_use]
    pub const fn reasoning(&self) -> Option<&LlmModelReasoning> {
        self.reasoning.as_ref()
    }
}

/// Exact-model preparation implemented by one provider adapter.
pub trait LlmAdapter: Send + Sync + 'static {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError>;

    /// Start one adapter-owned stream. The default preserves preparation-only
    /// adapters while failing closed at dispatch time.
    fn stream(&self, request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        Err(SessionLlmFailure {
            message: format!(
                "LLM adapter for `{}/{}` does not implement stream dispatch",
                request.config.provider, request.config.model
            ),
            code: "NO_STREAM".into(),
            status: None,
            provider_retry_after_ms: None,
            request_id: None,
        })
    }
}

impl<F> LlmAdapter for F
where
    F: Fn(&str, &str) -> Result<LlmResolvedModel, LlmError> + Send + Sync + 'static,
{
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        self(provider, model)
    }
}

/// Fail-closed adapter registration and exact-model preparation errors.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum LlmError {
    #[error("LLM adapter must have {expected}")]
    InvalidAdapter { expected: &'static str },
    #[error("LLM provider `{provider}` already has an adapter")]
    DuplicateAdapter { provider: String },
    #[error("LLM adapter registration identity overflowed")]
    AdapterIdentityOverflow,
    #[error("LLM adapter registry mutex is poisoned")]
    RegistryPoisoned,
    #[error("no LLM adapter is registered for provider `{provider}`")]
    NoAdapter { provider: String },
    #[error("LLM adapter model `{provider}/{model}` must have {expected}")]
    InvalidModelInfo {
        provider: String,
        model: String,
        expected: &'static str,
    },
    #[error(
        "LLM provider `{provider}` model `{model}` does not support reasoning effort `{effort}`"
    )]
    UnsupportedReasoningEffort {
        provider: String,
        model: String,
        effort: String,
    },
    #[error("prepared LLM call must retain {expected}")]
    InvalidPreparedCall { expected: &'static str },
    #[error("LLM stream dispatch must retain {expected}")]
    InvalidStreamDispatch { expected: &'static str },
    #[error("LLM stream protocol must retain {expected}")]
    InvalidStreamProtocol { expected: &'static str },
}

impl LlmError {
    /// Stable Harness-aligned machine code for this failure class.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidAdapter { .. } => "INVALID_ADAPTER",
            Self::DuplicateAdapter { .. } => "DUPLICATE_ADAPTER",
            Self::AdapterIdentityOverflow => "ADAPTER_IDENTITY_OVERFLOW",
            Self::RegistryPoisoned => "INVARIANT",
            Self::NoAdapter { .. } => "NO_ADAPTER",
            Self::InvalidModelInfo { .. } => "INVALID_MODEL_INFO",
            Self::UnsupportedReasoningEffort { .. } => "UNSUPPORTED_REASONING_EFFORT",
            Self::InvalidPreparedCall { .. } => "INVALID_PREPARED_CALL",
            Self::InvalidStreamDispatch { .. } => "INVALID_STREAM_DISPATCH",
            Self::InvalidStreamProtocol { .. } => "INVALID_STREAM_PROTOCOL",
        }
    }
}

struct LlmAdapterRegistration {
    id: u64,
    adapter: Arc<dyn LlmAdapter>,
}

struct LlmAdapterRoute {
    provider: String,
    registration: Arc<LlmAdapterRegistration>,
}

#[derive(Default)]
struct LlmAdapterState {
    last_registration_id: u64,
    routes: Vec<LlmAdapterRoute>,
}

/// One resolved call retaining the exact adapter registration generation.
#[derive(Clone)]
pub struct PreparedLlmCall {
    registration: Arc<LlmAdapterRegistration>,
    config: SessionCallConfig,
    adapter_defaults: SessionCallConfigAdapterDefaults,
    context_window: Option<u64>,
    dispatched: Arc<AtomicBool>,
}

impl PreparedLlmCall {
    #[must_use]
    pub fn registration_id(&self) -> u64 {
        self.registration.id
    }

    #[must_use]
    pub const fn config(&self) -> &SessionCallConfig {
        &self.config
    }

    #[must_use]
    pub const fn adapter_defaults(&self) -> &SessionCallConfigAdapterDefaults {
        &self.adapter_defaults
    }

    #[must_use]
    pub const fn context_window(&self) -> Option<u64> {
        self.context_window
    }
}

impl fmt::Debug for PreparedLlmCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedLlmCall")
            .field("registration_id", &self.registration.id)
            .field("config", &self.config)
            .field("adapter_defaults", &self.adapter_defaults)
            .field("context_window", &self.context_window)
            .field("dispatched", &self.dispatched.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Live agent identity registered on `ctx.agents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRef {
    pub id: String,
}

impl AgentRef {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Authoritative outcome of the `agent/pre-step` waterfall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPreStepDecision {
    Reject,
    Enter {
        messages: Vec<SessionMessage>,
        starts_request_series: bool,
    },
}

/// Immutable agent/turn/step scope plus the replaceable pre-step decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPreStep {
    agent: AgentRef,
    turn: u64,
    step: u64,
    decision: AgentPreStepDecision,
    assembly: PromptAssembly,
}

impl AgentPreStep {
    pub(crate) fn enter(
        agent: AgentRef,
        turn: u64,
        step: u64,
        messages: Vec<SessionMessage>,
        assembly: PromptAssembly,
    ) -> Self {
        Self {
            agent,
            turn,
            step,
            decision: AgentPreStepDecision::Enter {
                messages,
                starts_request_series: false,
            },
            assembly,
        }
    }

    #[must_use]
    pub const fn agent(&self) -> &AgentRef {
        &self.agent
    }

    #[must_use]
    pub const fn turn(&self) -> u64 {
        self.turn
    }

    #[must_use]
    pub const fn step(&self) -> u64 {
        self.step
    }

    #[must_use]
    pub const fn decision(&self) -> &AgentPreStepDecision {
        &self.decision
    }

    #[must_use]
    pub const fn assembly(&self) -> &PromptAssembly {
        &self.assembly
    }

    #[must_use]
    pub fn into_decision(self) -> AgentPreStepDecision {
        self.decision
    }

    #[must_use]
    pub fn with_decision(mut self, decision: AgentPreStepDecision) -> Self {
        self.decision = decision;
        self
    }

    #[must_use]
    pub fn reject(self) -> Self {
        self.with_decision(AgentPreStepDecision::Reject)
    }

    /// Replace only admitted messages, preserving request-series ownership.
    #[must_use]
    pub fn replace_messages(mut self, messages: Vec<SessionMessage>) -> Self {
        if let AgentPreStepDecision::Enter {
            messages: admitted, ..
        } = &mut self.decision
        {
            *admitted = messages;
        }
        self
    }

    /// Mark an Enter decision as the start of a distinct request series.
    #[must_use]
    pub fn with_starts_request_series(mut self) -> Self {
        if let AgentPreStepDecision::Enter {
            starts_request_series,
            ..
        } = &mut self.decision
        {
            *starts_request_series = true;
        }
        self
    }
}

/// Immutable agent/turn/step scope plus the replaceable model call config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRequest {
    agent: AgentRef,
    turn: u64,
    step: u64,
    config: SessionCallConfig,
}

impl AgentRequest {
    pub(crate) fn new(agent: AgentRef, turn: u64, step: u64, config: SessionCallConfig) -> Self {
        Self {
            agent,
            turn,
            step,
            config,
        }
    }

    #[must_use]
    pub const fn agent(&self) -> &AgentRef {
        &self.agent
    }

    #[must_use]
    pub const fn turn(&self) -> u64 {
        self.turn
    }

    #[must_use]
    pub const fn step(&self) -> u64 {
        self.step
    }

    #[must_use]
    pub const fn config(&self) -> &SessionCallConfig {
        &self.config
    }

    #[must_use]
    pub fn into_config(self) -> SessionCallConfig {
        self.config
    }

    /// Replace only model-call configuration while retaining exact scope.
    #[must_use]
    pub fn with_config(mut self, config: SessionCallConfig) -> Self {
        self.config = config;
        self
    }
}

/// Tools pipeline service provided at `ctx.tools`.
type ToolConcurrencyClassifier =
    Arc<dyn Fn(&serde_json::Value) -> Result<bool, String> + Send + Sync>;
type ToolExecutionGuard = Arc<dyn Fn(&ToolExecutionInput) -> Option<String> + Send + Sync>;

#[derive(Clone)]
struct ToolRegistration {
    name: String,
    identity: Arc<()>,
    classifier: Option<ToolConcurrencyClassifier>,
}

impl fmt::Debug for ToolRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolRegistration")
            .field("name", &self.name)
            .field("has_classifier", &self.classifier.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct ToolGuardRegistration {
    identity: Arc<()>,
    guard: ToolExecutionGuard,
}

impl fmt::Debug for ToolGuardRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolGuardRegistration")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct ToolsState {
    names: Vec<ToolRegistration>,
    schemas: Vec<SessionToolSchema>,
    guards: Vec<ToolGuardRegistration>,
}

#[derive(Debug, Clone)]
pub struct ToolsSurface {
    state: Arc<Mutex<ToolsState>>,
}

impl ToolsSurface {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ToolsState::default())),
        }
    }

    fn register_name(&self, name: String) -> Arc<()> {
        self.register_name_with_classifier(name, None)
    }

    fn register_name_with_classifier(
        &self,
        name: String,
        classifier: Option<ToolConcurrencyClassifier>,
    ) -> Arc<()> {
        let identity = Arc::new(());
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .names
            .push(ToolRegistration {
                name,
                identity: Arc::clone(&identity),
                classifier,
            });
        identity
    }

    fn register_schema(&self, schema: SessionToolSchema) -> Result<Arc<()>, PromptError> {
        let name = schema.name.clone();
        if name.is_empty() {
            return Err(PromptError::InvalidToolName);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| PromptError::ToolsRegistryPoisoned)?;
        if state.schemas.iter().any(|existing| existing.name == name) {
            return Err(PromptError::DuplicateTool { name });
        }
        let identity = Arc::new(());
        state.names.push(ToolRegistration {
            name,
            identity: Arc::clone(&identity),
            classifier: None,
        });
        state.schemas.push(schema);
        Ok(identity)
    }

    fn unregister_name(&self, identity: &Arc<()>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = state
            .names
            .iter()
            .position(|registered| Arc::ptr_eq(&registered.identity, identity))
        {
            state.names.remove(index);
        }
    }

    fn unregister_schema(&self, identity: &Arc<()>, name: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = state
            .names
            .iter()
            .position(|registered| Arc::ptr_eq(&registered.identity, identity))
        {
            state.names.remove(index);
            state.schemas.retain(|schema| schema.name != name);
        }
    }

    fn register_guard(&self, guard: ToolExecutionGuard) -> Arc<()> {
        let identity = Arc::new(());
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .guards
            .push(ToolGuardRegistration {
                identity: Arc::clone(&identity),
                guard,
            });
        identity
    }

    fn unregister_guard(&self, identity: &Arc<()>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = state
            .guards
            .iter()
            .position(|registered| Arc::ptr_eq(&registered.identity, identity))
        {
            state.guards.remove(index);
        }
    }

    fn registration(&self, name: &str) -> Result<Option<ToolRegistration>, PromptError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| PromptError::ToolsRegistryPoisoned)?
            .names
            .iter()
            .rfind(|registered| registered.name == name)
            .cloned())
    }

    fn registration_is_current(&self, name: &str, identity: &Arc<()>) -> bool {
        self.state.lock().is_ok_and(|state| {
            state
                .names
                .iter()
                .rfind(|registered| registered.name == name)
                .is_some_and(|registered| Arc::ptr_eq(&registered.identity, identity))
        })
    }

    fn classify_registration(
        input: &ToolExecutionInput,
        registered: &ToolRegistration,
    ) -> ToolExecutionMode {
        let Some(classifier) = &registered.classifier else {
            return ToolExecutionMode::Exclusive;
        };
        if catch_unwind(AssertUnwindSafe(|| classifier(input.arguments())))
            .ok()
            .and_then(Result::ok)
            == Some(true)
        {
            ToolExecutionMode::Parallel
        } else {
            ToolExecutionMode::Exclusive
        }
    }

    fn guard_reason(&self, input: &ToolExecutionInput) -> Option<String> {
        let guards = match self.state.lock() {
            Ok(state) => state.guards.clone(),
            Err(_) => return Some("tool registry is unavailable".into()),
        };
        for registered in guards {
            let live = match self.state.lock() {
                Ok(state) => state
                    .guards
                    .iter()
                    .any(|candidate| Arc::ptr_eq(&candidate.identity, &registered.identity)),
                Err(_) => return Some("tool registry is unavailable".into()),
            };
            if !live {
                continue;
            }
            match catch_unwind(AssertUnwindSafe(|| (registered.guard)(input))) {
                Ok(Some(reason)) => return Some(reason),
                Ok(None) => {}
                Err(_) => return Some(format!("tool guard panicked for \"{}\"", input.name())),
            }
        }
        None
    }

    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .names
            .iter()
            .map(|registered| registered.name.clone())
            .collect()
    }

    /// Classify one unstarted call against the current visible registry.
    /// Only an exact successful `true` opts into overlap; every other outcome
    /// remains an exclusive barrier.
    #[must_use]
    pub fn execution_mode(&self, input: &ToolExecutionInput) -> ToolExecutionMode {
        let Ok(Some(registered)) = self.registration(input.name()) else {
            return ToolExecutionMode::Exclusive;
        };
        let mode = Self::classify_registration(input, &registered);
        if !self.registration_is_current(input.name(), &registered.identity) {
            return ToolExecutionMode::Exclusive;
        }
        mode
    }

    /// Revalidate that a dispatch preparation still names the exact visible
    /// registration admitted by pre-execution policy.
    #[must_use]
    pub fn preparation_is_current(&self, prepared: &PreparedToolExecution) -> bool {
        self.registration_is_current(prepared.input.name(), &prepared.registration_identity)
    }

    fn schemas(&self) -> Result<Vec<SessionToolSchema>, PromptError> {
        let mut schemas = self
            .state
            .lock()
            .map_err(|_| PromptError::ToolsRegistryPoisoned)?
            .schemas
            .clone();
        schemas.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(schemas)
    }
}

/// Model stream service provided at `ctx.llm`.
#[derive(Clone)]
pub struct LlmSurface {
    streams: Arc<Mutex<Vec<String>>>,
    adapters: Arc<Mutex<LlmAdapterState>>,
}

impl LlmSurface {
    fn new() -> Self {
        Self {
            streams: Arc::new(Mutex::new(Vec::new())),
            adapters: Arc::new(Mutex::new(LlmAdapterState::default())),
        }
    }

    pub fn register_stream(&self, model: impl Into<String>) {
        self.streams.lock().expect("llm streams").push(model.into());
    }

    pub fn unregister_stream(&self, model: &str) {
        self.streams
            .lock()
            .expect("llm streams")
            .retain(|registered| registered != model);
    }

    #[must_use]
    pub fn streams(&self) -> Vec<String> {
        self.streams.lock().expect("llm streams").clone()
    }

    fn register_adapter(
        &self,
        providers: Vec<String>,
        adapter: Arc<dyn LlmAdapter>,
    ) -> Result<u64, LlmError> {
        if providers.is_empty() {
            return Err(LlmError::InvalidAdapter {
                expected: "at least one provider",
            });
        }
        let mut state = self
            .adapters
            .lock()
            .map_err(|_| LlmError::RegistryPoisoned)?;
        let mut candidates = HashSet::new();
        for provider in &providers {
            if provider.is_empty() {
                return Err(LlmError::InvalidAdapter {
                    expected: "non-empty provider names",
                });
            }
            if !candidates.insert(provider.as_str())
                || state.routes.iter().any(|route| route.provider == *provider)
            {
                return Err(LlmError::DuplicateAdapter {
                    provider: provider.clone(),
                });
            }
        }
        let id = state
            .last_registration_id
            .checked_add(1)
            .ok_or(LlmError::AdapterIdentityOverflow)?;
        let registration = Arc::new(LlmAdapterRegistration { id, adapter });
        state
            .routes
            .extend(providers.into_iter().map(|provider| LlmAdapterRoute {
                provider,
                registration: Arc::clone(&registration),
            }));
        state.last_registration_id = id;
        Ok(id)
    }

    fn unregister_adapter(&self, registration_id: u64) {
        if let Ok(mut state) = self.adapters.lock() {
            state
                .routes
                .retain(|route| route.registration.id != registration_id);
        }
    }

    pub fn providers(&self) -> Result<Vec<String>, LlmError> {
        Ok(self
            .adapters
            .lock()
            .map_err(|_| LlmError::RegistryPoisoned)?
            .routes
            .iter()
            .map(|route| route.provider.clone())
            .collect())
    }

    fn prepare_call(&self, config: &SessionCallConfig) -> Result<PreparedLlmCall, LlmError> {
        let registration =
            self.registration(&config.provider)?
                .ok_or_else(|| LlmError::NoAdapter {
                    provider: config.provider.clone(),
                })?;
        let model = registration
            .adapter
            .prepare_model(&config.provider, &config.model)?;
        resolve_prepared_call(registration, config, &model)
    }

    fn registration(
        &self,
        provider: &str,
    ) -> Result<Option<Arc<LlmAdapterRegistration>>, LlmError> {
        Ok(self
            .adapters
            .lock()
            .map_err(|_| LlmError::RegistryPoisoned)?
            .routes
            .iter()
            .find(|route| route.provider == provider)
            .map(|route| Arc::clone(&route.registration)))
    }
}

impl fmt::Debug for LlmSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("LlmSurface").finish_non_exhaustive()
    }
}

fn resolve_prepared_call(
    registration: Arc<LlmAdapterRegistration>,
    proposed: &SessionCallConfig,
    model: &LlmResolvedModel,
) -> Result<PreparedLlmCall, LlmError> {
    let invalid = |expected| LlmError::InvalidModelInfo {
        provider: proposed.provider.clone(),
        model: proposed.model.clone(),
        expected,
    };
    if model.provider != proposed.provider || model.model != proposed.model {
        return Err(invalid("the exact requested provider/model identity"));
    }
    if model.context_window == Some(0) {
        return Err(invalid("a positive optional context window"));
    }
    if model.default_max_tokens == Some(0) {
        return Err(invalid("a positive optional default maxTokens"));
    }
    if let Some(reasoning) = &model.reasoning {
        let mut efforts = HashSet::new();
        if reasoning.efforts.is_empty()
            || reasoning
                .efforts
                .iter()
                .any(|effort| effort.is_empty() || !efforts.insert(effort.as_str()))
            || reasoning
                .default_effort
                .as_ref()
                .is_some_and(|default| !efforts.contains(default.as_str()))
        {
            return Err(invalid(
                "non-empty unique reasoning efforts and an in-set optional default",
            ));
        }
    }

    let mut config = proposed.clone();
    let mut adapter_defaults = SessionCallConfigAdapterDefaults {
        reasoning_effort: false,
        max_tokens: false,
    };
    if config.max_tokens.is_none()
        && let Some(default) = model.default_max_tokens
    {
        config.max_tokens = Some(default);
        adapter_defaults.max_tokens = true;
    }
    match (&model.reasoning, config.reasoning_effort.as_ref()) {
        (None, Some(effort)) => {
            return Err(LlmError::UnsupportedReasoningEffort {
                provider: proposed.provider.clone(),
                model: proposed.model.clone(),
                effort: effort.clone(),
            });
        }
        (Some(reasoning), requested) => {
            let effective = requested.or(reasoning.default_effort.as_ref());
            if let Some(effort) = effective {
                if !reasoning.efforts.contains(effort) {
                    return Err(LlmError::UnsupportedReasoningEffort {
                        provider: proposed.provider.clone(),
                        model: proposed.model.clone(),
                        effort: effort.clone(),
                    });
                }
                if requested.is_none() {
                    config.reasoning_effort = Some(effort.clone());
                    adapter_defaults.reasoning_effort = true;
                }
            }
        }
        (None, None) => {}
    }

    Ok(PreparedLlmCall {
        registration,
        config,
        adapter_defaults,
        context_window: model.context_window,
        dispatched: Arc::new(AtomicBool::new(false)),
    })
}

/// Live agent coordination provided at `ctx.agents`.
#[derive(Debug, Clone)]
pub struct AgentsSurface {
    live: Arc<Mutex<Vec<AgentRef>>>,
}

impl AgentsSurface {
    fn new() -> Self {
        Self {
            live: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn register(&self, agent: AgentRef) {
        self.live.lock().expect("agents").push(agent);
    }

    pub fn unregister(&self, id: &str) {
        self.live
            .lock()
            .expect("agents")
            .retain(|agent| agent.id != id);
    }

    #[must_use]
    pub fn list(&self) -> Vec<AgentRef> {
        self.live.lock().expect("agents").clone()
    }
}

/// Hartevo Domain Kernel handle. OpenInterpreter never owns this key.
///
/// Cordis does not reimplement Domain Kernel. These flags are the host-side
/// fail-closed view of consent, approval, local-first, SQLCipher, and eval.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainSurface {
    pub(crate) owner: SurfaceOwner,
    pub(crate) consent: bool,
    pub(crate) approved: bool,
    pub(crate) local_first: bool,
    pub(crate) sqlcipher: bool,
    pub(crate) eval_gate: bool,
}

impl DomainSurface {
    #[must_use]
    pub const fn owner(&self) -> SurfaceOwner {
        self.owner
    }

    #[must_use]
    pub const fn consent(&self) -> bool {
        self.consent
    }

    #[must_use]
    pub const fn approved(&self) -> bool {
        self.approved
    }

    #[must_use]
    pub const fn local_first(&self) -> bool {
        self.local_first
    }

    #[must_use]
    pub const fn sqlcipher(&self) -> bool {
        self.sqlcipher
    }

    #[must_use]
    pub const fn eval_gate(&self) -> bool {
        self.eval_gate
    }
}

impl Default for DomainSurface {
    fn default() -> Self {
        Self {
            owner: SurfaceOwner::Hartevo,
            consent: false,
            approved: false,
            local_first: true,
            sqlcipher: true,
            eval_gate: true,
        }
    }
}

/// Hartevo Effect Broker handle. The only external-write path.
///
/// `receipt_is_verification` stays false: Receipt ≠ Verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EffectBrokerSurface {
    pub(crate) owner: SurfaceOwner,
    pub(crate) receipt_is_verification: bool,
}

impl EffectBrokerSurface {
    #[must_use]
    pub const fn owner(&self) -> SurfaceOwner {
        self.owner
    }

    #[must_use]
    pub const fn receipt_is_verification(&self) -> bool {
        self.receipt_is_verification
    }
}

/// Optional runtime plugin slot. OpenInterpreter may sit here as an adapter
/// plugin; it still does not own Mission, Truth, or Effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSurface {
    pub(crate) owner: SurfaceOwner,
    pub(crate) plugin: Option<&'static str>,
}

impl RuntimeSurface {
    #[must_use]
    pub const fn owner(&self) -> SurfaceOwner {
        self.owner
    }

    #[must_use]
    pub const fn plugin(&self) -> Option<&'static str> {
        self.plugin
    }
}

/// Desktop shell handle. Hartevo-owned; not an OpenInterpreter surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopSurface {
    pub(crate) owner: SurfaceOwner,
}

impl DesktopSurface {
    #[must_use]
    pub const fn owner(&self) -> SurfaceOwner {
        self.owner
    }
}

/// Bundle of Hartevo-owned surfaces. Mapping, not a second host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HartevoSurfaces {
    pub(crate) domain: DomainSurface,
    pub(crate) effect_broker: EffectBrokerSurface,
    pub(crate) runtime: RuntimeSurface,
    pub(crate) desktop: DesktopSurface,
}

/// Non-forgeable crate-internal authority for Hartevo surface registration.
/// The public owner label on [`HartevoSurfaces`] is configuration data only;
/// it never creates this token.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HartevoSurfaceAuthority {
    marker: AuthorityMarker,
}

#[derive(Debug, Clone, Copy)]
struct AuthorityMarker;

impl HartevoSurfaceAuthority {
    pub(crate) const fn is_valid(self) -> bool {
        let _ = self.marker;
        true
    }
}

fn trusted_surface_authority() -> HartevoSurfaceAuthority {
    HartevoSurfaceAuthority {
        marker: AuthorityMarker,
    }
}

impl Default for HartevoSurfaces {
    fn default() -> Self {
        Self {
            domain: DomainSurface::default(),
            effect_broker: EffectBrokerSurface::default(),
            runtime: RuntimeSurface {
                owner: SurfaceOwner::Hartevo,
                plugin: None,
            },
            desktop: DesktopSurface {
                owner: SurfaceOwner::Hartevo,
            },
        }
    }
}

/// Provide mapped services and lock primer event names to one dispatch mode.
///
/// Tools pipeline: three waterfalls plus observe-only `tools/result`.
/// LLM streams use `llm/stream`; agent coordination exposes created/disposed
/// emits plus the authoritative `agent/pre-step` and `agent/request`
/// waterfalls. Domain /
/// effect_broker / runtime / desktop are Hartevo-owned lookups and never go
/// through OpenInterpreter.
pub(crate) fn map_surfaces(
    ctx: &mut Context,
    surfaces: HartevoSurfaces,
) -> Result<(), CordisError> {
    let authority = trusted_surface_authority();
    if !authority.is_valid() {
        return Err(CordisError::ReservedServiceKey {
            key: keys::DOMAIN.to_string(),
        });
    }
    require_hartevo_owned("domain", surfaces.domain.owner)?;
    require_hartevo_owned("effect_broker", surfaces.effect_broker.owner)?;
    require_hartevo_owned("runtime", surfaces.runtime.owner)?;
    require_hartevo_owned("desktop", surfaces.desktop.owner)?;
    if let Some(key) = MAPPED_KEYS.iter().copied().find(|key| ctx.has(key)) {
        return Err(CordisError::SurfaceAlreadyMapped { key });
    }
    validate_mapped_events(ctx)?;

    let session_dispatcher = ctx.event_reentry()?;
    ctx.provide(keys::TOOLS, ToolsSurface::new())?;
    ctx.provide(keys::SYSTEM_PROMPT, SystemPromptSurface::default())?;
    ctx.provide(keys::LLM, LlmSurface::new())?;
    ctx.provide(
        keys::SESSIONS,
        SessionStore::with_event_dispatcher(session_dispatcher),
    )?;
    ctx.provide(keys::AGENTS, AgentsSurface::new())?;
    ctx.provide_reserved(authority, keys::DOMAIN, surfaces.domain)?;
    ctx.provide_reserved(authority, keys::EFFECT_BROKER, surfaces.effect_broker)?;
    ctx.provide_reserved(authority, keys::RUNTIME, surfaces.runtime)?;
    ctx.provide_reserved(authority, keys::DESKTOP, surfaces.desktop)?;
    lock_mapped_events(ctx)
}

fn validate_mapped_events(ctx: &Context) -> Result<(), CordisError> {
    validate_mapped_event(ctx, events::SYSTEM_PROMPT_ASSEMBLE)?;
    validate_mapped_event(ctx, events::TOOLS_PRE_EXECUTE)?;
    validate_mapped_event(ctx, events::TOOLS_EXECUTE)?;
    validate_mapped_event(ctx, events::TOOLS_POST_EXECUTE)?;
    validate_mapped_event(ctx, events::TOOLS_RESULT)?;
    validate_mapped_event(ctx, events::LLM_STREAM)?;
    validate_mapped_event(ctx, events::AGENT_CREATED)?;
    validate_mapped_event(ctx, events::AGENT_DISPOSED)?;
    validate_mapped_event(ctx, events::AGENT_PRE_STEP)?;
    validate_mapped_event(ctx, events::AGENT_REQUEST)?;
    validate_mapped_event(ctx, session_events::SESSION_EVENT)?;
    validate_mapped_event(ctx, session_events::SESSION_FLUSH)?;
    Ok(())
}

fn validate_mapped_event<M, P, Output>(
    ctx: &Context,
    key: EventKey<M, P, Output>,
) -> Result<(), CordisError>
where
    M: EventModeMarker,
    P: 'static,
    Output: 'static,
{
    let requested = key.descriptor();
    if let Some(locked) = ctx.event_descriptor(key)
        && locked != requested
    {
        return Err(CordisError::SchemaConflict {
            name: key.name().to_string(),
            locked,
            requested,
        });
    }
    Ok(())
}

/// Rebind only the Hartevo Domain provider in place. Its provider identity and
/// owner stay stable while generation/notification advance exactly once.
pub(crate) fn rebind_hartevo_domain(
    ctx: &mut Context,
    domain: DomainSurface,
) -> Result<(), CordisError> {
    let _ = ctx.replace_hartevo_domain(trusted_surface_authority(), domain)?;
    Ok(())
}

fn lock_mapped_events(ctx: &mut Context) -> Result<(), CordisError> {
    ctx.lock_event_key(events::SYSTEM_PROMPT_ASSEMBLE)?;
    ctx.lock_event_key(events::TOOLS_PRE_EXECUTE)?;
    ctx.lock_event_key(events::TOOLS_EXECUTE)?;
    ctx.lock_event_key(events::TOOLS_POST_EXECUTE)?;
    ctx.lock_event_key(events::TOOLS_RESULT)?;
    ctx.lock_event_key(events::LLM_STREAM)?;
    ctx.lock_event_key(events::AGENT_CREATED)?;
    ctx.lock_event_key(events::AGENT_DISPOSED)?;
    ctx.lock_event_key(events::AGENT_PRE_STEP)?;
    ctx.lock_event_key(events::AGENT_REQUEST)?;
    ctx.lock_event_key(session_events::SESSION_EVENT)?;
    ctx.lock_event_key(session_events::SESSION_FLUSH)?;
    Ok(())
}

fn require_hartevo_owned(key: &'static str, owner: SurfaceOwner) -> Result<(), CordisError> {
    if owner != SurfaceOwner::Hartevo {
        return Err(CordisError::InvalidSurfaceOwner {
            key,
            owner: owner.as_str(),
        });
    }
    Ok(())
}

/// Register a tool name on `ctx.tools` and reverse it on teardown.
pub fn register_tool(ctx: &mut Context, name: impl Into<String>) -> Result<(), CordisError> {
    let Some(tools) = ctx.tools::<ToolsSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::TOOLS.to_string(),
        ]));
    };
    let name = name.into();
    let identity = tools.register_name(name);
    ctx.effect(move || tools.unregister_name(&identity));
    Ok(())
}

/// Register one model-visible tool schema and reverse it with its Cordis owner.
pub fn register_tool_schema(
    ctx: &mut Context,
    schema: SessionToolSchema,
) -> Result<RegistrationHandle, CordisError> {
    let Some(tools) = ctx.tools::<ToolsSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::TOOLS.to_string(),
        ]));
    };
    let name = schema.name.clone();
    let identity = tools.register_schema(schema)?;
    let registered = Arc::clone(&tools);
    Ok(ctx.effect(move || registered.unregister_schema(&identity, &name)))
}

/// Register one visible tool with its argument-sensitive parallel-safety
/// classifier and reverse both with the owning Cordis effect.
pub fn register_tool_concurrency<F>(
    ctx: &mut Context,
    name: impl Into<String>,
    classifier: F,
) -> Result<RegistrationHandle, CordisError>
where
    F: Fn(&serde_json::Value) -> Result<bool, String> + Send + Sync + 'static,
{
    let Some(tools) = ctx.tools::<ToolsSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::TOOLS.to_string(),
        ]));
    };
    let name = name.into();
    let identity = tools.register_name_with_classifier(name, Some(Arc::new(classifier)));
    let registered = Arc::clone(&tools);
    Ok(ctx.effect(move || registered.unregister_name(&identity)))
}

/// Register one monotonic pre-execution guard and reverse it with its Cordis
/// owner. Returning any string denies the call; no guard can force-allow it.
pub fn register_tool_guard<F>(
    ctx: &mut Context,
    guard: F,
) -> Result<RegistrationHandle, CordisError>
where
    F: Fn(&ToolExecutionInput) -> Option<String> + Send + Sync + 'static,
{
    let Some(tools) = ctx.tools::<ToolsSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::TOOLS.to_string(),
        ]));
    };
    let identity = tools.register_guard(Arc::new(guard));
    let registered = Arc::clone(&tools);
    Ok(ctx.effect(move || registered.unregister_guard(&identity)))
}

/// Register one ordered static system-prompt section with exact teardown.
pub fn register_prompt_section(
    ctx: &mut Context,
    section: PromptSection,
) -> Result<RegistrationHandle, CordisError> {
    let Some(prompt) = ctx.system_prompt::<SystemPromptSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::SYSTEM_PROMPT.to_string(),
        ]));
    };
    let name = section.name.clone();
    prompt.register(section)?;
    let registered = Arc::clone(&prompt);
    Ok(ctx.effect(move || registered.unregister(&name)))
}

/// Freeze current Cordis prompt and model-visible tool contributions, then run
/// the authoritative assembly Waterfall over that detached value.
pub fn assemble_system_prompt(ctx: &mut Context) -> Result<PromptAssembly, CordisError> {
    let prompt = ctx
        .system_prompt::<SystemPromptSurface>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::SYSTEM_PROMPT.to_string()]))?;
    let tools = ctx
        .tools::<ToolsSurface>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::TOOLS.to_string()]))?;
    let assembly = prompt.assemble(tools.schemas()?)?;
    ctx.waterfall(events::SYSTEM_PROMPT_ASSEMBLE, assembly)?
        .validated()
        .map_err(Into::into)
}

/// Register a model stream on `ctx.llm` and reverse it on teardown.
pub fn register_llm_stream(ctx: &mut Context, model: impl Into<String>) -> Result<(), CordisError> {
    let Some(llm) = ctx.llm::<LlmSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::LLM.to_string(),
        ]));
    };
    let model = model.into();
    llm.register_stream(model.clone());
    ctx.effect(move || llm.unregister_stream(&model));
    Ok(())
}

/// Register exact provider routes and reverse them with the current lifecycle.
pub fn register_llm_adapter<A, I, S>(
    ctx: &mut Context,
    providers: I,
    adapter: A,
) -> Result<RegistrationHandle, CordisError>
where
    A: LlmAdapter,
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let Some(llm) = ctx.llm::<LlmSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::LLM.to_string(),
        ]));
    };
    let registration_id = llm.register_adapter(
        providers.into_iter().map(Into::into).collect(),
        Arc::new(adapter),
    )?;
    let registered = Arc::clone(&llm);
    Ok(ctx.effect(move || registered.unregister_adapter(registration_id)))
}

/// Resolve one call under the exact current provider registration.
pub fn prepare_llm_call(
    ctx: &Context,
    config: &SessionCallConfig,
) -> Result<PreparedLlmCall, CordisError> {
    ctx.llm::<LlmSurface>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::LLM.to_string()]))?
        .prepare_call(config)
        .map_err(Into::into)
}

/// Dispatch one full request through the exact adapter generation retained by
/// a prepared call. The prepared handle is one-shot across all clones.
pub fn stream_prepared_llm(
    ctx: &mut Context,
    prepared: &PreparedLlmCall,
    request: LlmGenerateRequest,
) -> Result<LlmChunkStream, CordisError> {
    if ctx.llm::<LlmSurface>().is_none() {
        return Err(CordisError::MissingDependencies(vec![
            keys::LLM.to_string(),
        ]));
    }
    validate_agent_request_config(request.config())?;
    if prepared.dispatched.load(Ordering::Acquire) {
        return Err(LlmError::InvalidPreparedCall {
            expected: "one dispatch only",
        }
        .into());
    }
    if request.config != prepared.config {
        return Err(LlmError::InvalidPreparedCall {
            expected: "the exact prepared call config",
        }
        .into());
    }
    prepared
        .dispatched
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| LlmError::InvalidPreparedCall {
            expected: "one dispatch only",
        })?;
    let registration = Arc::clone(&prepared.registration);
    let adapter_request = request.clone();
    dispatch_llm_stream(
        ctx,
        request,
        Box::new(move || adapter_chunk_stream(&registration, adapter_request)),
    )
}

/// Dispatch an unprepared full request. Middleware may serve an unregistered
/// route; otherwise the missing adapter is normalized into a terminal chunk.
pub fn stream_llm_request(
    ctx: &mut Context,
    request: LlmGenerateRequest,
) -> Result<LlmChunkStream, CordisError> {
    validate_agent_request_config(request.config())?;
    let llm = ctx
        .llm::<LlmSurface>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::LLM.to_string()]))?;
    let provider = request.config.provider.clone();
    let adapter_request = request.clone();
    dispatch_llm_stream(
        ctx,
        request,
        Box::new(move || match llm.registration(&provider) {
            Ok(Some(registration)) => adapter_chunk_stream(&registration, adapter_request),
            Ok(None) => terminal_failure_stream(llm_failure(&LlmError::NoAdapter { provider })),
            Err(error) => terminal_failure_stream(llm_failure(&error)),
        }),
    )
}

fn dispatch_llm_stream(
    ctx: &mut Context,
    request: LlmGenerateRequest,
    factory: LlmStreamFactory,
) -> Result<LlmChunkStream, CordisError> {
    let expected = request.clone();
    let dispatch = LlmStream::generated(request, factory);
    let dispatch = ctx.waterfall(events::LLM_STREAM, dispatch)?;
    if dispatch.request() != Some(&expected) {
        return Err(LlmError::InvalidStreamDispatch {
            expected: "the exact immutable generated request",
        }
        .into());
    }
    dispatch.into_chunk_stream().map_err(Into::into)
}

fn adapter_chunk_stream(
    registration: &LlmAdapterRegistration,
    request: LlmGenerateRequest,
) -> LlmChunkStream {
    match registration.adapter.stream(request) {
        Ok(stream) => Box::pin(NormalizedAdapterStream::new(stream)),
        Err(failure) => terminal_failure_stream(failure),
    }
}

fn llm_failure(error: &LlmError) -> SessionLlmFailure {
    SessionLlmFailure {
        message: error.to_string(),
        code: error.code().into(),
        status: None,
        provider_retry_after_ms: None,
        request_id: None,
    }
}

fn terminal_failure_stream(failure: SessionLlmFailure) -> LlmChunkStream {
    Box::pin(futures_util::stream::once(async move {
        terminal_failure_chunk(failure)
    }))
}

fn terminal_failure_chunk(failure: SessionLlmFailure) -> SessionStreamChunk {
    let reason = if failure.code == "ABORTED" {
        SessionFinishReason::Aborted { failure }
    } else {
        SessionFinishReason::Error { failure }
    };
    SessionStreamChunk::Finish {
        reason,
        replay_state: None,
    }
}

struct NormalizedAdapterStream {
    source: LlmAdapterStream,
    terminated: bool,
}

impl NormalizedAdapterStream {
    const fn new(source: LlmAdapterStream) -> Self {
        Self {
            source,
            terminated: false,
        }
    }
}

impl Stream for NormalizedAdapterStream {
    type Item = SessionStreamChunk;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        if self.terminated {
            return Poll::Ready(None);
        }
        match self.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(chunk)),
            Poll::Ready(Some(Err(failure))) => {
                self.terminated = true;
                Poll::Ready(Some(terminal_failure_chunk(failure)))
            }
            Poll::Ready(None) => {
                self.terminated = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Register live agent coordination on `ctx.agents` and reverse it on teardown.
pub fn register_agent(ctx: &mut Context, agent: AgentRef) -> Result<(), CordisError> {
    let Some(agents) = ctx.agents::<AgentsSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::AGENTS.to_string(),
        ]));
    };
    let id = agent.id.clone();
    agents.register(agent);
    ctx.effect(move || agents.unregister(&id));
    Ok(())
}

/// Dispatch one tools pipeline call through the locked event names.
pub fn run_tools_pipeline(ctx: &mut Context, mut call: ToolCall) -> Result<ToolCall, CordisError> {
    let call_id = call.call_id.clone();
    call = ctx.waterfall(events::TOOLS_PRE_EXECUTE, call)?;
    call.call_id.clone_from(&call_id);
    if call.decision != "allow" {
        ctx.emit(events::TOOLS_RESULT, &call)?;
        return Ok(call);
    }
    call = ctx.waterfall(events::TOOLS_EXECUTE, call)?;
    call.call_id.clone_from(&call_id);
    call = ctx.waterfall(events::TOOLS_POST_EXECUTE, call)?;
    call.call_id = call_id;
    ctx.emit(events::TOOLS_RESULT, &call)?;
    Ok(call)
}

/// Run one immutable durable call through ordered pre-execute policy and
/// monotonic guards without invoking a tool body or mutating the session.
pub fn prepare_tool_execution(
    ctx: &mut Context,
    input: ToolExecutionInput,
) -> Result<ToolExecutionPreparation, CordisError> {
    let tools = ctx
        .tools::<ToolsSurface>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::TOOLS.to_string()]))?;
    let Ok(registered) = tools.registration(input.name()) else {
        return Ok(denied_tool_execution(input, "tool registry is unavailable"));
    };
    let proposal = ToolCall::from_execution_input(&input);
    let decided = ctx.waterfall(events::TOOLS_PRE_EXECUTE, proposal)?;
    if decided.call_id != input.call_id()
        || decided.name != input.name()
        || decided.arguments != input.raw_arguments()
        || decided.execution_input.as_ref() != Some(&input)
    {
        return Ok(denied_tool_execution(
            input,
            "tools/pre-execute cannot rewrite durable tool identity or arguments",
        ));
    }
    match decided.decision.as_str() {
        "deny" => {
            let reason = if decided.result.is_empty() {
                format!("tool \"{}\" was denied by pre-execute policy", input.name())
            } else {
                decided.result
            };
            return Ok(denied_tool_execution(input, reason));
        }
        "ask" => {
            let reason = if decided.result.is_empty() {
                format!(
                    "tool \"{}\" requires approval, but no approval channel is available",
                    input.name()
                )
            } else {
                decided.result
            };
            return Ok(denied_tool_execution(input, reason));
        }
        "allow" => {}
        decision => {
            return Ok(denied_tool_execution(
                input,
                format!("invalid tools/pre-execute decision \"{decision}\""),
            ));
        }
    }
    if let Some(reason) = tools.guard_reason(&input) {
        return Ok(denied_tool_execution(input, reason));
    }
    let Some(registered) = registered else {
        let name = input.name().to_string();
        return Ok(denied_tool_execution(
            input,
            format!("unknown tool \"{name}\""),
        ));
    };
    let mode = ToolsSurface::classify_registration(&input, &registered);
    if !tools.registration_is_current(input.name(), &registered.identity) {
        return Ok(denied_tool_execution(
            input,
            "tool registration changed during pre-execution",
        ));
    }
    Ok(ToolExecutionPreparation::Dispatch(PreparedToolExecution {
        input,
        mode,
        registration_identity: registered.identity,
    }))
}

fn denied_tool_execution(
    input: ToolExecutionInput,
    reason: impl Into<String>,
) -> ToolExecutionPreparation {
    ToolExecutionPreparation::Denied(DeniedToolExecution {
        input,
        reason: reason.into(),
    })
}

/// Dispatch one model stream through `llm/stream`.
pub fn stream_llm(ctx: &mut Context, request: LlmStream) -> Result<LlmStream, CordisError> {
    ctx.waterfall(events::LLM_STREAM, request)
}

/// Primer dispatch mode for each mapped event name.
#[must_use]
pub fn expected_mode(name: impl AsRef<str>) -> Option<DispatchMode> {
    match name.as_ref() {
        "system-prompt/assemble"
        | "tools/pre-execute"
        | "tools/execute"
        | "tools/post-execute"
        | "llm/stream"
        | "agent/pre-step"
        | "agent/request" => Some(DispatchMode::Waterfall),
        "tools/result" | "agent/created" | "agent/disposed" | "session/event" => {
            Some(DispatchMode::Emit)
        }
        "session/flush" => Some(DispatchMode::Parallel),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Emit;

    #[test]
    fn sealed_mapping_rejects_forged_owner_with_typed_error_before_mount() {
        let mut ctx = Context::new();
        let mut surfaces = HartevoSurfaces::default();
        surfaces.domain.owner = SurfaceOwner::OpenInterpreter;
        assert_eq!(
            map_surfaces(&mut ctx, surfaces).unwrap_err(),
            CordisError::InvalidSurfaceOwner {
                key: "domain",
                owner: "openinterpreter",
            }
        );
        assert!(MAPPED_KEYS.iter().all(|key| !ctx.has(key)));
    }

    #[test]
    fn duplicate_sealed_mapping_is_typed_and_keeps_original_authority() {
        let mut ctx = Context::new();
        map_surfaces(&mut ctx, HartevoSurfaces::default()).unwrap();
        assert!(matches!(
            map_surfaces(&mut ctx, HartevoSurfaces::default()),
            Err(CordisError::SurfaceAlreadyMapped { key }) if key == keys::TOOLS
        ));
        assert_eq!(
            ctx.domain::<DomainSurface>().unwrap().owner(),
            SurfaceOwner::Hartevo
        );
    }

    #[test]
    fn all_ten_surface_event_descriptors_preflight_before_any_provider_mutation() {
        let mut ctx = Context::new();
        let incompatible_last_key = EventKey::<Emit, AgentRef, ()>::new(
            events::AGENT_REQUEST.schema_id(),
            events::AGENT_REQUEST.name(),
        );
        ctx.lock_event_key(incompatible_last_key).unwrap();
        let descriptor_before = ctx.event_descriptor(events::AGENT_REQUEST).unwrap();

        let error = map_surfaces(&mut ctx, HartevoSurfaces::default()).unwrap_err();

        assert!(matches!(
            error,
            CordisError::SchemaConflict { ref name, ref locked, ref requested }
                if name == events::AGENT_REQUEST.name()
                    && locked == &descriptor_before
                    && requested == &events::AGENT_REQUEST.descriptor()
        ));
        assert!(MAPPED_KEYS.iter().all(|key| !ctx.has(key)));
        assert_eq!(
            ctx.event_descriptor(events::AGENT_REQUEST),
            Some(descriptor_before)
        );
        for name in [
            events::SYSTEM_PROMPT_ASSEMBLE.name(),
            events::TOOLS_PRE_EXECUTE.name(),
            events::TOOLS_EXECUTE.name(),
            events::TOOLS_POST_EXECUTE.name(),
            events::TOOLS_RESULT.name(),
            events::LLM_STREAM.name(),
            events::AGENT_CREATED.name(),
            events::AGENT_DISPOSED.name(),
            events::AGENT_PRE_STEP.name(),
        ] {
            assert_eq!(
                ctx.event_descriptor(name),
                None,
                "{name} must stay untouched"
            );
        }
    }

    #[test]
    fn authorized_domain_rebind_preserves_identity_and_never_touches_broker() {
        let mut ctx = Context::new();
        map_surfaces(&mut ctx, HartevoSurfaces::default()).unwrap();
        let domain_before = ctx.provider_snapshot(keys::DOMAIN).unwrap();
        let broker_before = ctx.provider_snapshot(keys::EFFECT_BROKER).unwrap();
        let bound = DomainSurface {
            consent: true,
            approved: true,
            ..DomainSurface::default()
        };

        rebind_hartevo_domain(&mut ctx, bound).unwrap();
        let domain_after = ctx.provider_snapshot(keys::DOMAIN).unwrap();
        let broker_after = ctx.provider_snapshot(keys::EFFECT_BROKER).unwrap();
        assert_eq!(domain_after.provider_id, domain_before.provider_id);
        assert_eq!(domain_after.owner_uid, domain_before.owner_uid);
        assert_eq!(domain_after.generation, domain_before.generation + 1);
        assert_eq!(domain_after.notify_count, domain_before.notify_count + 1);
        assert_eq!(domain_after.disposer_count, domain_before.disposer_count);
        assert_eq!(broker_after, broker_before);
        assert!(ctx.domain::<DomainSurface>().unwrap().consent());
        assert!(ctx.domain::<DomainSurface>().unwrap().approved());
    }
}

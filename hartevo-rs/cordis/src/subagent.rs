//! Named provider registry for child-agent delegation.
//!
//! This module owns only the provider-selection seam. Provider backends own
//! child construction and caller-held runs; later slices add descriptors,
//! lifecycle observation, continuation, and model-facing tools.

use std::fmt;
use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use thiserror::Error;

use crate::{
    AgentRef, Context, LifecycleCancellation, RegistrationHandle, SessionCallConfig,
    SessionContentBlock, SessionId,
};

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
        request: SubagentStartRequest,
    ) -> BoxFuture<'static, Result<Arc<dyn SubagentRun>, SubagentError>>;
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
#[derive(Default)]
pub struct SubagentRuntime {
    state: Mutex<RegistryState>,
}

impl SubagentRuntime {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        provider.start(request).await
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

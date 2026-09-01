//! Rust Cordis kernel: service container, plugin inject/apply, reversible
//! effects, typed events, loader/overlay interpolation, Hartevo surface mapping,
//! a Cordis-hosted agent loop, a fail-closed Domain Kernel invariant gate, and
//! the desktop host that mounts those three services.
//!
//! Typed events integrate with synchronous [`Context`], its borrowed
//! [`ContextView`], Desktop prepared lifecycle notifications, and an N2B
//! lifecycle-owned typed-Emit bridge for repeatable plugins. The owned bridge
//! deliberately does not yet claim Parallel, Serial, Bail, Waterfall, or
//! Accumulate parity.
//!
//! Typed [`ServiceHandle`] values make Cordis caller/shadow tracing explicit
//! in Rust, preserve isolate lookup boundaries, provide opt-in callable
//! services, and resolve Fiber-owned dotted associations and ordered service
//! config interception without changing the consuming [`Service`] adapter.

mod agent;
mod authority;
mod config;
mod context;
mod effect;
mod event;
mod fiber;
mod host;
mod inbox;
mod invariants;
mod kernel;
mod loader;
mod registry;
mod service;
mod session;
mod surface;

pub use agent::{
    AGENT_LOOP_KEYS, AgentBuildAdmission, AgentCallAdmission, AgentLoop, AgentRequestAdmission,
    AgentRequestLogState, AgentStep, AgentStepResult, AgentStreamCommit, AgentToolBatchOutcome,
    AgentTurnOutcome, DEFAULT_MAX_PARALLEL_TOOL_CALLS, LoggedAgentCall, PreparedAgentCall,
    PreparedAgentRequest, RecordedAgentStream, admit_agent_request, admit_agent_step,
    build_agent_call, commit_agent_stream, commit_agent_tool_results, dispatch_agent_call,
    log_agent_call, prepare_agent_call, prepare_agent_step, prepare_agent_tool_calls,
    prepare_agent_tool_executions, record_agent_stream, run_agent_step, run_agent_tool_batch,
    run_agent_tool_batch_outcome, run_agent_tool_batch_with_limit,
    run_agent_tool_batch_with_limit_and_cancellation,
    run_agent_tool_batch_with_limit_and_cancellation_outcome, run_agent_turn,
    schedule_agent_tool_calls,
};
pub use authority::{
    AuthorityDispatchError, AuthorityDispatchFailures, AuthorityScope, DomainCommandAuthority,
    DomainCommandBinding, DomainCommandKind, DomainCommandPermit, EffectExecutionAuthority,
    EffectExecutionBinding, EffectExecutionPermit, EffectReconciliationAuthority,
    EffectReconciliationBinding, EffectReconciliationPermit, EffectVerificationAuthority,
    EffectVerificationBinding, EffectVerificationPermit, RuntimeAuthority, RuntimeBinding,
    RuntimeDispatchCompletion, RuntimeDispatchPermit, RuntimeRecordBinding,
};
pub use config::{ConfigValue, InterpolateError};
pub use context::{
    Context, ContextView, CordisError, EventReentry, PendingHandle, ProviderHandle, ProviderId,
    keys,
};
pub use effect::{
    Disposer, IntoLifecycleEffect, LifecycleDisposeFuture, LifecycleDisposer,
    LifecycleDisposerFuture, LifecycleDisposerStream, LifecycleEffect, RegistrationHandle,
};
pub use event::{
    Accumulate, Bail, BailOutcome, DispatchMode, Emit, EventDescriptor, EventError, EventErrors,
    EventKey, EventModeMarker, EventOptions, EventSchemaId, EventSourceFingerprint, ListenerHandle,
    NonBail, Parallel, Serial, SharedEventSource, TryWaterfallNext, Waterfall, WaterfallFailure,
    WaterfallNext,
};
pub use fiber::{
    ActivationEpoch, Fiber, FiberSnapshot, FiberState, FiberUid, LifecycleCancellation,
    ProviderFingerprint, TransitionTicket,
};
pub use host::{
    CordisHost, HOST_PLUGIN_IDS, OPENINTERPRETER_PLUGIN_ID, host_is_cordis_loop, host_plugin_ids,
};
pub use inbox::{AgentInbox, AgentInboxOutcome, AgentInboxTarget};
pub use invariants::{
    InvariantGate, OPENINTERPRETER, apply_effect, enforce_invariants, enforce_runtime_invariants,
    missing as invariant_missing,
};
pub use kernel::{
    KernelApproval, KernelApprovalDecision, KernelConsentRecord, KernelConsentState,
    KernelConsentStatus, bind_domain_kernel_facts,
};
pub use loader::{
    EnvironmentOverlay, IntoPluginResult, LoadReport, Loader, LoaderContext, OverlayAction,
    OverlayLayer, PluginEntry, PluginFactory, PluginFactoryId, PluginId, PluginSpec,
    ResolvedPlugin, interpolate_plugin_config, load_plugins, load_plugins_pending,
};
pub use registry::{
    LifecycleContextView, LifecycleEventDispatcher, LifecycleHandle, LifecycleProviderHandle,
    LifecycleRegistry,
};
pub use service::{
    AssociatedAccessor, AssociatedAccessorHandle, CallableService, Service, ServiceAssociation,
    ServiceCall, ServiceCaller, ServiceHandle, ServiceOptions, ServiceOrigin, ServiceShadow,
    ServiceViewKind, associated_key, merge_service_config,
};
pub use session::{
    SESSION_FORMAT_VERSION, SessionAssistantChunk, SessionCallConfig,
    SessionCallConfigAdapterDefaults, SessionCancelCause, SessionCheckpoint, SessionContentBlock,
    SessionEpochHeader, SessionError, SessionEvent, SessionEventKind, SessionEventRecord,
    SessionFinishReason, SessionHandle, SessionHeader, SessionId, SessionLlmFailure, SessionLog,
    SessionMessage, SessionMessageRole, SessionMessageSource, SessionReplayEnvelope,
    SessionRequestContext, SessionRequestHeader, SessionRequestHeaderReason, SessionStore,
    SessionStreamBlockType, SessionStreamChunk, SessionSurface, SessionSurfaceIntent,
    SessionSurfaceOp, SessionTokenUsage, SessionToolCall, SessionToolError, SessionToolSchema,
    TOOL_NOT_STARTED, TOOL_OUTCOME_UNKNOWN, TurnEndReason, events as session_events,
};
pub use surface::{
    AgentPreStep, AgentPreStepDecision, AgentRef, AgentRequest, AgentTurnStopping, AgentsSurface,
    DeniedToolExecution, DesktopSurface, DomainSurface, EffectBrokerSurface, LlmAdapter,
    LlmAdapterStream, LlmChunkStream, LlmError, LlmGenerateRequest, LlmModelReasoning,
    LlmResolvedModel, LlmStream, LlmSurface, MAPPED_KEYS, PreparedLlmCall, PreparedToolExecution,
    PromptAssembly, PromptError, PromptSection, RuntimeSurface, SurfaceOwner, SystemPromptSurface,
    TOOL_ABORTED_BEFORE_DISPATCH, ToolCall, ToolDefinition, ToolDispatchExecution,
    ToolDispatchOutcome, ToolDispatchResult, ToolExecutionInput, ToolExecutionMode,
    ToolExecutionPreparation, ToolExecutionResult, ToolPostExecution, ToolRunContext, ToolsSurface,
    assemble_system_prompt, dispatch_tool_execution, events, expected_mode,
    finalize_tool_execution, post_tool_execution, prepare_llm_call, prepare_tool_execution,
    register_agent, register_llm_adapter, register_llm_stream, register_prompt_section,
    register_tool, register_tool_concurrency, register_tool_definition, register_tool_guard,
    register_tool_schema, run_tools_pipeline, stream_llm, stream_llm_request, stream_prepared_llm,
};

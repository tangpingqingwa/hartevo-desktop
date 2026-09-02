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
mod approval;
mod authority;
mod compaction;
mod compaction_automation;
mod compaction_policy;
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
mod retry;
mod sandbox;
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
pub use approval::{
    ApprovalError, ApprovalOutcome, ApprovalPolicy, ApprovalPolicySource, ApprovalPrompt,
    ApprovalRequest, ApprovalRequestId, ApprovalSurface, SessionApprovalAsked,
    SessionApprovalDecided, SessionApprovalPolicy, events as approval_events, request_approval,
    set_approval_policy,
};
pub use authority::{
    AuthorityDispatchError, AuthorityDispatchFailures, AuthorityScope, DomainCommandAuthority,
    DomainCommandBinding, DomainCommandKind, DomainCommandPermit, EffectExecutionAuthority,
    EffectExecutionBinding, EffectExecutionPermit, EffectReconciliationAuthority,
    EffectReconciliationBinding, EffectReconciliationPermit, EffectVerificationAuthority,
    EffectVerificationBinding, EffectVerificationPermit, RuntimeAuthority, RuntimeBinding,
    RuntimeDispatchCompletion, RuntimeDispatchPermit, RuntimeRecordBinding,
    RuntimeStatusCompletion,
};
pub use compaction::{
    COMPACTION_CHECKPOINT_PLUGIN, CompactionCheckpoint, CompactionId, CompactionLease,
    CompactionRange, CompactionRegion, CompactionResult, CompactionSummaryDraft,
    SessionCompactionEnd, SessionCompactionStart, SessionCompactionSummary,
    compact_checkpoint_source, is_compact_checkpoint_source, tool_pairing_balanced_after,
    tool_pairing_balanced_before,
};
pub use compaction_automation::{
    COMPACTION_AUTOMATION_KEYS, CompactionAutomation, CompactionAutomationError,
    ContextOverflowRecovery, ManualCompactionError, ManualCompactionErrorCode,
    compact_before_agent_step, compact_now, recover_context_overflow,
};
pub use compaction_policy::{
    CHECKPOINT_PREAMBLE, COMPACTION_INSTRUCTION, CompactionMeasurement, CompactionNodeMeasurement,
    CompactionPlan, CompactionPolicyConfig, CompactionPolicyError, CompactionRetention,
    CompactionTarget, CompactionTrigger, DEFAULT_COMPACTION_RETRIES,
    DEFAULT_COMPACTION_THRESHOLD_RATIO, DEFAULT_MAX_OVERFLOW_RETRIES, DEFAULT_RETAIN_RATIO,
    DEFAULT_SUMMARY_MAX_TOKENS, ModelCompactionPolicyConfig, PreparedCompactionSummary,
    ResolvedCompactionConfig, ResolvedCompactionPolicy, ResolvedCompactionSpec, SUMMARY_CLOSE_TAG,
    SUMMARY_OPEN_TAG, estimate_content_tokens, estimate_message_tokens, execute_compaction_plan,
    frame_compaction_summary, measure_compaction_session, plan_compaction,
    resolve_compaction_config, resolve_compaction_policy, resolve_compaction_spec,
    select_compactable_range, summarize_compaction,
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
    CordisHost, CordisHostTeardown, HOST_PLUGIN_IDS, OPENINTERPRETER_PLUGIN_ID,
    host_is_cordis_loop, host_plugin_ids,
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
pub use retry::{LLM_RETRY_KEYS, LlmRetry};
pub use sandbox::{
    ConfinedArgv, ConfinedSandboxMode, ConfinedSandboxPolicy, SANDBOX_ESCALATION_TARGETS,
    SANDBOX_MODES, SANDBOX_UNAVAILABLE, SandboxEnforcement, SandboxError,
    SandboxEscalationApproval, SandboxEscalationGrant, SandboxEscalationRequest,
    SandboxExecutionEnvironment, SandboxExecutionPlan, SandboxExecutionPolicy, SandboxMode,
    SandboxModeSource, SandboxPolicyRequest, SandboxPolicyService, SandboxProcessClassification,
    SandboxProvider, SandboxProviderService, SandboxProviderUnavailable, SandboxRunnerFailureRule,
    SessionSandboxMode, approve_sandbox_escalation, classify_sandbox_process,
    consume_sandbox_escalation_approval, plan_sandbox_escalation_approval,
    prepare_sandbox_execution, register_sandbox_provider, resolve_sandbox_policy, set_sandbox_mode,
    validate_sandbox_escalation_args,
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
    SessionFinishReason, SessionHandle, SessionHeader, SessionId, SessionLlmFailure,
    SessionLlmRetry, SessionLlmRetryMode, SessionLlmRetryStarted, SessionLog, SessionMessage,
    SessionMessageRole, SessionMessageSource, SessionReplayEnvelope, SessionRequestContext,
    SessionRequestHeader, SessionRequestHeaderReason, SessionStore, SessionStreamBlockType,
    SessionStreamChunk, SessionSurface, SessionSurfaceIntent, SessionSurfaceOp, SessionTokenUsage,
    SessionToolCall, SessionToolError, SessionToolSchema, TOOL_NOT_STARTED, TOOL_OUTCOME_UNKNOWN,
    TurnEndReason, events as session_events,
};
pub use surface::{
    AgentPreStep, AgentPreStepDecision, AgentRef, AgentRequest, AgentRequestError,
    AgentRequestErrorAction, AgentRetrySchedule, AgentStatus, AgentStatusChange, AgentTurnStopping,
    AgentsSurface, CONTEXT_WINDOW_EXCEEDED_CODE, DeniedToolExecution, DesktopSurface,
    DomainSurface, EffectBrokerSurface, LlmAdapter, LlmAdapterStream, LlmChunkStream, LlmError,
    LlmGenerateRequest, LlmModelReasoning, LlmRequestPurpose, LlmResolvedModel, LlmRetryPolicy,
    LlmRetryPolicyMode, LlmStream, LlmSurface, MAPPED_KEYS, MAX_LLM_RETRY_DELAY_MS,
    PreparedLlmCall, PreparedToolExecution, PromptAssembly, PromptError, PromptSection,
    RuntimeSurface, SurfaceOwner, SystemPromptSurface, TOOL_ABORTED_BEFORE_DISPATCH,
    ToolApprovalRequirement, ToolCall, ToolDefinition, ToolDispatchExecution, ToolDispatchOutcome,
    ToolDispatchResult, ToolExecutionInput, ToolExecutionMode, ToolExecutionPreparation,
    ToolExecutionResult, ToolPostExecution, ToolRunContext, ToolsSurface, assemble_system_prompt,
    dispatch_tool_execution, events, expected_mode, finalize_tool_execution, post_tool_execution,
    prepare_llm_call, prepare_tool_execution, register_agent, register_llm_adapter,
    register_llm_stream, register_prompt_section, register_tool, register_tool_concurrency,
    register_tool_definition, register_tool_guard, register_tool_schema, run_tools_pipeline,
    stream_llm, stream_llm_request, stream_prepared_llm,
};

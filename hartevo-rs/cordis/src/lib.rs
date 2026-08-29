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
mod invariants;
mod kernel;
mod loader;
mod registry;
mod service;
mod surface;

pub use agent::{AGENT_LOOP_KEYS, AgentLoop, AgentStep, AgentStepResult, run_agent_step};
pub use authority::{
    AuthorityDispatchError, AuthorityDispatchFailures, AuthorityScope, DomainCommandAuthority,
    DomainCommandBinding, DomainCommandKind, DomainCommandPermit, EffectExecutionAuthority,
    EffectExecutionBinding, EffectExecutionPermit, RuntimeAuthority, RuntimeBinding,
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
pub use surface::{
    AgentRef, AgentsSurface, DesktopSurface, DomainSurface, EffectBrokerSurface, LlmStream,
    LlmSurface, MAPPED_KEYS, RuntimeSurface, SurfaceOwner, ToolCall, ToolsSurface, events,
    expected_mode, register_agent, register_llm_stream, register_tool, run_tools_pipeline,
    stream_llm,
};

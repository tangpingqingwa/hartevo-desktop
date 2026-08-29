//! Rust Cordis kernel: service container, plugin inject/apply, reversible
//! effects, typed events, loader/overlay interpolation, Hartevo surface mapping,
//! a Cordis-hosted agent loop, a fail-closed Domain Kernel invariant gate, and
//! the desktop host that mounts those three services.

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
    AuthorityDispatchError, AuthorityScope, RuntimeAuthority, RuntimeBinding,
    RuntimeDispatchCompletion, RuntimeDispatchPermit, RuntimeRecordBinding,
};
pub use config::{ConfigValue, InterpolateError};
pub use context::{
    Context, ContextView, CordisError, PendingHandle, ProviderHandle, ProviderId, keys,
};
pub use effect::{Disposer, RegistrationHandle};
pub use event::{DispatchMode, WaterfallNext};
pub use fiber::{Fiber, FiberState, FiberUid};
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
pub use service::Service;
pub use surface::{
    AgentRef, AgentsSurface, DesktopSurface, DomainSurface, EffectBrokerSurface, LlmStream,
    LlmSurface, MAPPED_KEYS, RuntimeSurface, SurfaceOwner, ToolCall, ToolsSurface, events,
    expected_mode, register_agent, register_llm_stream, register_tool, run_tools_pipeline,
    stream_llm,
};

//! Rust Cordis kernel: service container, plugin inject/apply, reversible
//! effects, typed events, loader/overlay interpolation, Hartevo surface mapping,
//! a Cordis-hosted agent loop, a fail-closed Domain Kernel invariant gate, and
//! the desktop host that mounts those three services.

mod agent;
mod config;
mod context;
mod effect;
mod event;
mod host;
mod invariants;
mod kernel;
mod loader;
mod service;
mod surface;

pub use agent::{AGENT_LOOP_KEYS, AgentLoop, AgentStep, AgentStepResult, run_agent_step};
pub use config::{ConfigValue, InterpolateError};
pub use context::{Context, CordisError, keys};
pub use effect::Disposer;
pub use event::{DispatchMode, WaterfallNext};
pub use host::{
    CordisHost, HOST_PLUGIN_IDS, OPENINTERPRETER_PLUGIN_ID, desktop_surfaces, host_is_cordis_loop,
    host_plugin_ids,
};
pub use invariants::{
    InvariantGate, OPENINTERPRETER, apply_effect, enforce_invariants, missing as invariant_missing,
};
pub use kernel::{
    KernelApproval, KernelApprovalDecision, KernelConsentRecord, KernelConsentState,
    KernelConsentStatus, bind_domain_kernel_facts,
};
pub use loader::{
    EnvironmentOverlay, LoadReport, Loader, LoaderContext, OverlayAction, OverlayLayer,
    PluginEntry, PluginId, PluginSpec, ResolvedPlugin, interpolate_plugin_config, load_plugins,
};
pub use service::Service;
pub use surface::{
    AgentRef, AgentsSurface, DesktopSurface, DomainSurface, EffectBrokerSurface, HartevoSurfaces,
    LlmStream, LlmSurface, MAPPED_KEYS, RuntimeSurface, SurfaceMapping, SurfaceOwner, ToolCall,
    ToolsSurface, events, expected_mode, map_surfaces, register_agent, register_llm_stream,
    register_tool, run_tools_pipeline, stream_llm,
};

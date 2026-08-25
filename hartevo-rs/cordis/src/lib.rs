//! Rust Cordis kernel: service container, plugin inject/apply, reversible
//! effects, typed events, loader/overlay interpolation, Hartevo surface
//! mapping, and a Cordis-hosted Rust agent loop.

mod agent;
mod config;
mod context;
mod effect;
mod event;
mod loader;
mod service;
mod surface;

pub use agent::{
    AgentLoop, AgentLoopError, AgentTurn, OpenInterpreterPresence, OpenInterpreterRuntimePlugin,
    agent_loop_plugin, assert_host_owns_domain, expected_loop_mode, install_agent_loop,
    loop_events, openinterpreter_runtime_plugin, run_agent_turn, surface_mapping_plugin,
    surface_mapping_with_openinterpreter_slot,
};
pub use config::{ConfigValue, InterpolateError};
pub use context::{Context, CordisError, keys};
pub use effect::Disposer;
pub use event::{DispatchMode, WaterfallNext};
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

//! Rust Cordis kernel: service container, plugin inject/apply, reversible
//! effects, typed events, primer loader/overlay interpolation, and Hartevo
//! surface mapping onto Cordis services.

mod config;
mod context;
mod effect;
mod event;
mod loader;
mod mapping;
mod service;

pub use config::{ConfigValue, InterpolateError};
pub use context::{Context, CordisError, keys};
pub use effect::Disposer;
pub use event::{DispatchMode, WaterfallNext};
pub use loader::{
    EnvironmentOverlay, LoadReport, Loader, LoaderContext, OverlayAction, OverlayLayer,
    PluginEntry, PluginId, PluginSpec, ResolvedPlugin, interpolate_plugin_config, load_plugins,
};
pub use mapping::{
    AgentHandle, AgentsService, DesktopSurface, DomainKernelSurface, EffectBrokerSurface,
    LlmRequest, LlmService, MappingError, OpenInterpreterRuntimePlugin, RuntimeAdapterSurface,
    SurfaceMap, ToolCall, ToolResult, ToolsService, assert_openinterpreter_does_not_own_domain,
    assert_pipeline_locked, events, map_hartevo_surfaces, openinterpreter_runtime_plugin,
};
pub use service::Service;

//! Rust Cordis kernel: service container, plugin inject/apply, reversible
//! effects, typed events, and primer loader/overlay interpolation.

mod config;
mod context;
mod effect;
mod event;
mod loader;
mod service;

pub use config::{ConfigValue, InterpolateError};
pub use context::{Context, CordisError, keys};
pub use effect::Disposer;
pub use event::{DispatchMode, WaterfallNext};
pub use loader::{
    EnvironmentOverlay, LoadReport, Loader, LoaderContext, OverlayAction, OverlayLayer,
    PluginEntry, PluginId, PluginSpec, ResolvedPlugin, interpolate_plugin_config, load_plugins,
};
pub use service::Service;

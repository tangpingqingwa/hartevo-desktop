//! Rust Cordis kernel: service container, plugin inject/apply, reversible
//! effects, and typed events with exactly one dispatch mode each.

mod context;
mod effect;
mod event;
mod service;

pub use context::{Context, CordisError, keys};
pub use effect::Disposer;
pub use event::{DispatchMode, WaterfallNext};
pub use service::Service;

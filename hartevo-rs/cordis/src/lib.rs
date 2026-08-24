//! Rust Cordis kernel: service container, plugin inject/apply, reversible effects.
//!
//! Event dispatch (`emit` / `waterfall` / `parallel` / `serial`) is out of scope
//! for this crate revision; [`Context::on`] stores listeners only.

mod context;
mod effect;
mod service;

pub use context::{Context, CordisError, keys};
pub use effect::Disposer;
pub use service::Service;

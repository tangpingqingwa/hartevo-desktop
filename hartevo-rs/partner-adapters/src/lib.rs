//! Provider-specific partner adapters.
//!
//! The package is intentionally outside the desktop workspace until the
//! connector/plugin composition layer owns its registration point.  It is
//! therefore testable as a standalone, scoped plugin package without changing
//! the shared Cargo root or desktop/application surfaces.

pub mod awin;

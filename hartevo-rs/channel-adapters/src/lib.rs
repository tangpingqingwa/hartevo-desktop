//! Provider-specific channel contracts.
//!
//! This crate intentionally stops at read-only request planning, probe/read
//! parsing, and provider observation models. It does not implement the
//! generic Connector SDK lifecycle from CONN-01 and it contains no publish or
//! reply effect path.

pub mod identity;
pub mod reddit;
pub mod testkit;
pub mod tiktok;
pub mod transport;
pub mod webhook;
pub mod youtube;

pub use identity::{
    AccountIdentity, ChannelIdentity, ContentIdentity, ProviderId, RevisionIdentity,
};
pub use transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOnlyTransport, ReadOperation, ScopeName, TransportError,
};

//! YouTube read-only channel contracts.
//!
//! This root owns the shared typed channel request/identity boundary and the
//! YouTube Data API/Analytics vertical. It intentionally does not implement
//! the generic Connector SDK lifecycle from CONN-01, a central registry, or
//! any publish/reply effect path. TikTok and Reddit adapters are independent
//! sibling roots.

pub mod identity;
pub mod testkit;
pub mod transport;
pub mod youtube;
pub mod youtube_read;

pub use identity::{
    AccountIdentity, ChannelIdentity, ContentIdentity, ProviderId, RevisionIdentity,
};
pub use transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOnlyTransport, ReadOperation, ScopeName, TransportError,
};

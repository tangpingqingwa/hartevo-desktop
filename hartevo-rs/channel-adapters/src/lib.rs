//! Provider-specific channel contracts.
//!
//! This crate contains provider-specific request planning, probe/read parsing,
//! observations, and the controlled Reddit post/reply effect boundary. It does
//! not implement the generic Connector SDK lifecycle from CONN-01.

pub mod identity;
pub mod reddit;
pub mod reddit_effect;
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

pub use reddit_effect::{ChannelPublishService, MissionRedditEffectConsumer};

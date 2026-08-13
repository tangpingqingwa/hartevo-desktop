//! Provider-specific, read-only growth intelligence adapters.
//!
//! This crate deliberately does not define a second cross-provider connector
//! interface. Each provider owns its request, response, transport, cursor,
//! quota, cost, and replay types until the Connector SDK exposes its stable
//! public contract.

pub mod attribution;
mod common;
pub mod dataforseo;
pub mod dataforseo_canary;
pub mod google_ads;
pub mod google_analytics;
pub mod sdk;
pub mod search_console;

pub use common::{
    CalendarDateRange, EvidenceClassification, Freshness, LanguageCode, MarketCode,
    ProviderReceiptReference, ReadScope, canonical_digest, parse_date,
};

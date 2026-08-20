//! Standalone Layer-1 New Relic observability result contract and provider seam.
//!
//! This crate prepares bounded, digest-bound NerdGraph read proposals and
//! redacted recording evidence. It does not resolve credentials, make live
//! network requests, mutate New Relic, or provide Hartevo kernel authority.

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionNewRelicObservabilityConsumer, MissionNewRelicObservabilityResult,
};
pub use error::ModelError;
pub use model::*;
pub use provider::*;
pub use service::*;

pub const PLUGIN_VERSION: &str = "1.0.0";
pub const CONTRACT_VERSION: &str = "EXT-NEWRELIC-01-L1/v1";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.newrelic-observability-result/v1";
pub const SERVICE_ID: &str = "newrelic.observability.result.read";
pub const PROVIDER_ID: &str = "newrelic.nerdgraph.observability.recording";
pub const CONSUMER_ID: &str = "mission.newrelic-observability.consumer";
pub const API_REVISION: &str = "nerdgraph-entities-aiissues-nrql-conditions-r1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.newrelic-observability-result/v1|layer=1|service=newrelic.observability.result.read|provider=newrelic.nerdgraph.observability.recording|consumer=mission.newrelic-observability.consumer|api=nerdgraph-entities-aiissues-nrql-conditions-r1";

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[cfg(test)]
mod adversarial_tests;

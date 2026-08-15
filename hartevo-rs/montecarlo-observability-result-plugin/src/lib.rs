//! Standalone Layer-1 Monte Carlo data-observability result contract.
//!
//! The crate prepares bounded, digest-bound incident, freshness, lineage, and
//! monitor read proposals and redacted recording evidence. It never resolves
//! credentials, makes live network requests, queries a warehouse, mutates a
//! monitor, claims `Connected`/native execution, or grants kernel authority.

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, DataQualityDecision, MissionMonteCarloObservabilityConsumer,
    MissionMonteCarloObservabilityResult,
};
pub use error::ModelError;
pub use model::*;
pub use provider::*;
pub use service::*;

pub type MonteCarloScope = MonteCarloObservabilityScope;
pub type MonteCarloObservabilityService<T> = MonteCarloObservabilityResultService<T>;
pub type MonteCarloObservabilityResult = ObservabilityResult;
pub type MonteCarloObservabilityResultProposal = ObservabilityResultProposal;
pub type MonteCarloObservabilityResultReceipt = MonteCarloObservabilityReceipt;

pub const PLUGIN_VERSION: &str = "1.0.0";
pub const CONTRACT_VERSION: &str = "EXT-MONTECARLO-01-L1/v1";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.montecarlo-observability-result/v1";
pub const SERVICE_ID: &str = "montecarlo.observability.result.read";
pub const PROVIDER_ID: &str = "montecarlo.observability.recording";
pub const CONSUMER_ID: &str = "mission.montecarlo-observability.consumer";
pub const API_REVISION: &str = "montecarlo-incidents-freshness-lineage-monitors-r1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.montecarlo-observability-result/v1|layer=1|service=montecarlo.observability.result.read|provider=montecarlo.observability.recording|consumer=mission.montecarlo-observability.consumer|api=montecarlo-incidents-freshness-lineage-monitors-r1";

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

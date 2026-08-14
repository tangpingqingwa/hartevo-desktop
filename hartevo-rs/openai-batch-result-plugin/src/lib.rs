//! Layer-1 OpenAI Batch lifecycle/result-metadata read proposal.
//!
//! This crate is intentionally standalone.  It models the official
//! `GET /v1/batches` and `GET /v1/batches/{batch_id}` shapes through a typed
//! transport seam, but ships no native credential resolver or HTTPS client.
//! Fixture, recording, loopback, and `BLOCKED_ENV` evidence are never
//! Connected/native evidence and never become kernel Truth, Effect, Receipt,
//! Verification, or Work Product adoption authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::{MissionOpenAiBatchConsumer, MissionOpenAiBatchResult, MissionResultState};
pub use error::{OpenAiBatchProviderError, OpenAiBatchResultError, Result};
pub use model::*;
pub use provider::{
    BatchGetResponse, BatchListResponse, OpenAiBatchProvider, OpenAiBatchProviderDefinition,
};
pub use service::{
    OpenAiBatchCapabilities, OpenAiBatchReadProposal, OpenAiBatchResultProposal,
    OpenAiBatchResultService, OpenAiBatchServicePolicy,
};
pub use transport::{
    BlockedEnvOpenAiBatchTransport, FakeOpenAiBatchTransport, FixtureOpenAiBatchTransport,
    GetRequest, HttpMethod, LoopbackOpenAiBatchTransport, OpenAiBatchHttpResponse,
    OpenAiBatchTransport, OpenAiBatchTransportError, RecordingOpenAiBatchTransport,
};

pub const SCHEMA_VERSION: &str = "hartevo.openai-batch-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-OPENAI-BATCH-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.openai-batch-result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const PROVIDER_ID: &str = "openai.batch.read";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "OpenAiBatchResultService";
pub const CONSUMER_ID: &str = "MissionOpenAiBatchConsumer";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native API-key resolution, bounded live OpenAI HTTPS reads, durable native receipt, independent file metadata/content readback, and verified Work Product adoption remain Layer-2 gaps";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/openai-batch-result/openai-batch-result.v1.json");

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

/// Compile-time authority marker for audits and adversarial tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn external_writes() -> bool {
        false
    }

    pub const fn batch_creation() -> bool {
        false
    }

    pub const fn file_upload() -> bool {
        false
    }

    pub const fn batch_cancellation() -> bool {
        false
    }

    pub const fn file_download() -> bool {
        false
    }

    pub const fn prompt_retention() -> bool {
        false
    }

    pub const fn output_retention() -> bool {
        false
    }

    pub const fn model_execution() -> bool {
        false
    }

    pub const fn tool_execution() -> bool {
        false
    }

    pub const fn generic_model_registry() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn embedded_contract_is_exactly_layer_one_and_read_only() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["plugin"]["id"], PLUGIN_ID);
        assert_eq!(document["plugin"]["version"], PLUGIN_VERSION);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["type"], SERVICE_ID);
        assert_eq!(document["provider"]["type"], "OpenAiBatchProvider");
        assert_eq!(document["consumer"]["type"], CONSUMER_ID);
        assert_eq!(document["service"]["readOnly"], true);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["native"], false);
        assert_eq!(document["authority"]["kernelAuthority"], false);
        assert_eq!(document["authority"]["promptRetention"], false);
        assert_eq!(document["authority"]["outputRetention"], false);
        assert_eq!(document["provider"]["nativeStatus"], BLOCKED_ENV);
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(!ReadOnlyAuthority::external_writes());
        assert!(!ReadOnlyAuthority::batch_creation());
        assert!(!ReadOnlyAuthority::file_upload());
        assert!(!ReadOnlyAuthority::batch_cancellation());
        assert!(!ReadOnlyAuthority::file_download());
        assert!(!ReadOnlyAuthority::prompt_retention());
        assert!(!ReadOnlyAuthority::output_retention());
        assert!(!ReadOnlyAuthority::model_execution());
        assert!(!ReadOnlyAuthority::tool_execution());
        assert!(!ReadOnlyAuthority::generic_model_registry());
        assert!(!ReadOnlyAuthority::kernel_authority());
        assert!(!ReadOnlyAuthority::connected());
        assert!(!ReadOnlyAuthority::native());
    }
}

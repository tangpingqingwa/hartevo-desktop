//! Standalone Layer-1 Dagger pipeline result evidence boundary.
//!
//! The crate only models bounded read/proposal/recording seams. It never
//! resolves native credentials, executes or cancels a pipeline, mutates a
//! registry, retains logs or artifact bytes, or claims Connected/native,
//! durable-provider, Truth, Effect, Work Product, or Outcome authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionDaggerPipelineConsumer, MissionDaggerPipelineResult, RecordedDaggerPipelineResult,
};
pub use error::{DaggerPipelineResultError, DaggerTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, DaggerPipelineReadRequest, DaggerPipelineResultResponse, DaggerProvider,
    DaggerProviderDefinition, DaggerProviderError, DaggerTransport, FixtureTransport,
    LoopbackTransport, RecordedDaggerRequest, RecordingTransport,
};
pub use service::{
    CapabilityDescription, DaggerPipelineResultService, DaggerPipelineResultServiceError,
    VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.dagger-pipeline-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-DAGGER-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.dagger-pipeline-result/v1|layer=1|service=dagger.pipeline-result.read|provider=dagger.pipeline-result.recording|consumer=mission.dagger-pipeline-result.consumer";
pub const PLUGIN_ID: &str = "dagger.pipeline-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "dagger.pipeline-result.read";
pub const PROVIDER_ID: &str = "dagger.pipeline-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "dagger-api-v0.16-module-pipeline-function-container-result-artifact-read-1";
pub const CONSUMER_ID: &str = "mission.dagger-pipeline-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/dagger-pipeline-result/dagger-pipeline-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_METADATA_ITEMS: usize = 64;
pub const MAX_PAGE_SIZE: u16 = 64;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::parse(sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes()))
        .expect("SHA-256 output is a valid digest")
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], contract_digest().as_str());
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert!(contract["service"]["readOnly"].as_bool().unwrap_or(false));
        assert!(
            contract["service"]["proposalOnly"]
                .as_bool()
                .unwrap_or(false)
        );
        assert!(
            !contract["service"]["externalWrites"]
                .as_bool()
                .unwrap_or(true)
        );
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert!(
            !contract["provider"]["connectedEvidence"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !contract["provider"]["nativeEvidence"]
                .as_bool()
                .unwrap_or(true)
        );
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert!(
            !contract["consumer"]["adoptsOutcome"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !contract["consumer"]["adoptsWorkProduct"]
                .as_bool()
                .unwrap_or(true)
        );
    }
}

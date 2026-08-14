//! Layer-1 Vertex AI Gemini generation-result seam.
//!
//! This crate is intentionally standalone and local-first. It models one
//! regional Google Cloud `generateContent` route, compiles a bounded input
//! proposal, and turns a fixture/recording/loopback/BLOCKED_ENV frame into
//! redacted, digest-fenced evidence. It never resolves credentials, invokes a
//! native transport, retains raw prompts or outputs, executes tools, performs
//! grounding, issues a kernel Receipt, independently reads back a provider
//! result, verifies a Work Product, or adopts an Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

pub mod mission;
pub mod model;
pub mod provider;
pub mod service;

pub use mission::{MissionResultProjection, MissionVertexAiResult, MissionVertexAiResultConsumer};
pub use model::*;
pub use provider::{
    BlockedEnvCode, ProviderResponseOutcome, RecordedProviderResponse, RecordedVertexAiResponse,
    VertexAiGenerationProvider, VertexAiResponseFrame,
};
pub use service::VertexAiGenerationResultService;

pub const VERTEX_AI_GENERATION_SCHEMA_VERSION: &str =
    "hartevo.vertex-ai-generation-result.contract/v1";
pub const VERTEX_AI_GENERATION_CONTRACT_VERSION: &str = "vertex-ai-generation-result/v1";
pub const VERTEX_AI_GENERATION_PLUGIN_VERSION: &str = "0.1.0";
pub const VERTEX_AI_GENERATION_SERVICE_ID: &str = "hartevo.vertex-ai.generation.result";
pub const VERTEX_AI_GENERATION_PROVIDER_ID: &str = "google.vertex-ai.gemini.generate-content";
pub const VERTEX_AI_GENERATION_CONSUMER_ID: &str = "mission.vertex-ai.generation.result";
pub const VERTEX_AI_GENERATION_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/vertex-ai-generation-result/vertex-ai-generation-result.v1.json"
);

pub(crate) fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_hex(Sha256::digest(bytes))
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("contract values are serializable");
    digest_bytes(&bytes)
}

pub(crate) fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        VERTEX_AI_GENERATION_CONTRACT_JSON, VERTEX_AI_GENERATION_CONTRACT_VERSION,
        VERTEX_AI_GENERATION_PLUGIN_VERSION, VERTEX_AI_GENERATION_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_keeps_layer_one_honest() {
        let contract: Value =
            serde_json::from_str(VERTEX_AI_GENERATION_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            VERTEX_AI_GENERATION_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            VERTEX_AI_GENERATION_CONTRACT_VERSION
        );
        assert_eq!(
            contract["pluginVersion"],
            VERTEX_AI_GENERATION_PLUGIN_VERSION
        );
        assert_eq!(contract["layer"], "Layer-1");
        assert_eq!(contract["endpoint"]["regional"], true);
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["durableReceipt"], false);
        assert_eq!(contract["authority"]["independentReadBack"], false);
        assert_eq!(contract["authority"]["kernelOutcomeAdoption"], false);
        assert_eq!(contract["allowlist"]["tools"], false);
        assert_eq!(contract["allowlist"]["grounding"], false);
        assert_eq!(contract["registration"]["reversible"], true);
        assert_eq!(contract["registration"]["revocable"], true);
    }
}

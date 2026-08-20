//! Layer-1 Cohere inference-result evidence seam.
//!
//! This crate is deliberately standalone and local-first. It can bind a
//! pinned Cohere model, endpoint, task, account, consent, Project, Mission,
//! and Work Product to a bounded proposal and a redacted recording. It never
//! resolves a secret, performs native HTTP, retains prompts or outputs,
//! executes tools, mutates a model, issues a kernel Receipt, performs kernel
//! Verification, or adopts a Work Product Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

pub mod mission;
pub mod model;
pub mod provider;
pub mod service;

pub use mission::{
    MissionCohereInferenceConsumer, MissionCohereInferenceProjection, MissionResultProjection,
};
pub use model::*;
pub use provider::{
    BlockedEnvCode, CohereProvider, ProviderResponseOutcome, RecordedCohereResponse,
    RecordedProviderResponse,
};
pub use service::CohereInferenceResultService;

pub const COHERE_INFERENCE_SCHEMA_VERSION: &str = "hartevo.cohere-inference-result.contract/v1";
pub const COHERE_INFERENCE_CONTRACT_VERSION: &str = "cohere-inference-result/v1";
pub const COHERE_INFERENCE_PLUGIN_VERSION: &str = "0.1.0";
pub const COHERE_INFERENCE_SERVICE_ID: &str = "hartevo.cohere.inference.result";
pub const COHERE_INFERENCE_PROVIDER_ID: &str = "cohere";
pub const COHERE_INFERENCE_CONSUMER_ID: &str = "mission.cohere.inference.result";
pub const COHERE_INFERENCE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/cohere-inference-result/cohere-inference-result.v1.json"
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
        COHERE_INFERENCE_CONTRACT_JSON, COHERE_INFERENCE_CONTRACT_VERSION,
        COHERE_INFERENCE_PLUGIN_VERSION, COHERE_INFERENCE_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract: Value =
            serde_json::from_str(COHERE_INFERENCE_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], COHERE_INFERENCE_SCHEMA_VERSION);
        assert_eq!(
            contract["contractVersion"],
            COHERE_INFERENCE_CONTRACT_VERSION
        );
        assert_eq!(contract["pluginVersion"], COHERE_INFERENCE_PLUGIN_VERSION);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["firstParty"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["authority"]["modelMutation"], false);
        assert_eq!(contract["authority"]["toolExecution"], false);
        assert_eq!(contract["provider"]["id"], "cohere");
        assert_eq!(contract["consumer"]["proposalOnly"], true);
    }
}

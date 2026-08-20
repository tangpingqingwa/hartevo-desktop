//! Layer-1 Mistral inference-result evidence seam.
//!
//! This crate is deliberately standalone and local-first. It can describe a
//! pinned Mistral model/task/route, compile a bounded non-mutating proposal,
//! and project a recording into redacted evidence. It never resolves a key,
//! performs native HTTP, retains prompts or outputs, executes tools, uploads
//! files, mutates a model, issues a kernel Receipt, performs kernel
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
    MissionMistralInferenceConsumer, MissionMistralInferenceProjection, MissionResultProjection,
};
pub use model::*;
pub use provider::{
    BlockedEnvCode, MistralModelListResponse, MistralProvider, ProviderResponseOutcome,
    RecordedMistralResponse, RecordedProviderResponse,
};
pub use service::MistralInferenceResultService;

pub const MISTRAL_INFERENCE_SCHEMA_VERSION: &str = "hartevo.mistral-inference-result.contract/v1";
pub const MISTRAL_INFERENCE_CONTRACT_VERSION: &str = "mistral-inference-result/v1";
pub const MISTRAL_INFERENCE_PLUGIN_VERSION: &str = "0.1.0";
pub const MISTRAL_INFERENCE_SERVICE_ID: &str = "hartevo.mistral.inference.result";
pub const MISTRAL_INFERENCE_PROVIDER_ID: &str = "mistral";
pub const MISTRAL_INFERENCE_CONSUMER_ID: &str = "mission.mistral.inference.result";
pub const MISTRAL_INFERENCE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/mistral-inference-result/mistral-inference-result.v1.json"
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
        MISTRAL_INFERENCE_CONTRACT_JSON, MISTRAL_INFERENCE_CONTRACT_VERSION,
        MISTRAL_INFERENCE_PLUGIN_VERSION, MISTRAL_INFERENCE_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_keeps_layer_one_honest() {
        let contract: Value =
            serde_json::from_str(MISTRAL_INFERENCE_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], MISTRAL_INFERENCE_SCHEMA_VERSION);
        assert_eq!(
            contract["contractVersion"],
            MISTRAL_INFERENCE_CONTRACT_VERSION
        );
        assert_eq!(contract["pluginVersion"], MISTRAL_INFERENCE_PLUGIN_VERSION);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["firstParty"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["authority"]["durableNativeReceipt"], false);
        assert_eq!(contract["authority"]["independentReadBack"], false);
        assert_eq!(contract["authority"]["kernelOutcomeAdoption"], false);
        assert_eq!(contract["allowlist"]["chat"]["tools"], false);
        assert_eq!(contract["allowlist"]["files"]["upload"], false);
        assert_eq!(contract["provider"]["id"], "mistral");
    }
}

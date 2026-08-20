//! Layer-1 Hugging Face Inference Providers result seam.
//!
//! The crate is deliberately standalone and local-first.  It can describe a
//! pinned Hub model, compile a bounded request proposal, and consume a
//! fixture/recording/loopback response into redacted evidence.  It does not
//! resolve secrets, make HTTP calls, create Hub resources, execute tools,
//! issue a kernel Receipt, perform business Verification, or adopt an
//! Outcome.  Those are explicit Layer-2 or kernel-owned boundaries.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

pub mod mission;
pub mod model;
pub mod provider;
pub mod service;

pub use mission::{MissionHuggingFaceResultConsumer, MissionResultProjection};
pub use model::*;
pub use provider::{
    BlockedEnvCode, HuggingFaceInferenceProvider, ProviderResponseOutcome, RecordedProviderResponse,
};
pub use service::HuggingFaceInferenceResultService;

pub const HUGGINGFACE_INFERENCE_SCHEMA_VERSION: &str = "hartevo.huggingface-inference.contract/v1";
pub const HUGGINGFACE_INFERENCE_CONTRACT_VERSION: &str = "hf-inference-result/v1";
pub const HUGGINGFACE_INFERENCE_PLUGIN_VERSION: &str = "0.1.0";
pub const HUGGINGFACE_INFERENCE_SERVICE_ID: &str = "hartevo.huggingface.inference.result";
pub const HUGGINGFACE_INFERENCE_PROVIDER_ID: &str = "huggingface.inference-providers";
pub const HUGGINGFACE_INFERENCE_CONSUMER_ID: &str = "mission.huggingface.inference.result";
pub const HUGGINGFACE_INFERENCE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/huggingface-inference/huggingface-inference.v1.json");

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
        HUGGINGFACE_INFERENCE_CONTRACT_JSON, HUGGINGFACE_INFERENCE_CONTRACT_VERSION,
        HUGGINGFACE_INFERENCE_PLUGIN_VERSION, HUGGINGFACE_INFERENCE_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_keeps_layer_one_honest() {
        let contract: Value =
            serde_json::from_str(HUGGINGFACE_INFERENCE_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            HUGGINGFACE_INFERENCE_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            HUGGINGFACE_INFERENCE_CONTRACT_VERSION
        );
        assert_eq!(
            contract["pluginVersion"],
            HUGGINGFACE_INFERENCE_PLUGIN_VERSION
        );
        assert_eq!(contract["layer"], "Layer-1");
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["authority"]["durableNativeReceipt"], false);
        assert_eq!(contract["authority"]["independentReadBack"], false);
        assert_eq!(contract["authority"]["kernelOutcomeAdoption"], false);
        assert_eq!(contract["allowlist"]["chatCompletion"]["tools"], false);
        assert_eq!(
            contract["allowlist"]["providerSelection"],
            "one_explicit_route_no_silent_failover"
        );
    }
}

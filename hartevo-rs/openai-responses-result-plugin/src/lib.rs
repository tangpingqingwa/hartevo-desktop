//! Standalone Layer-1 direct `OpenAI` Responses result plugin.
//!
//! This crate is intentionally local-first and non-native. It binds one
//! organization/project, immutable model snapshot, bounded input policy,
//! optional strict JSON schema, disabled tool policy, Mission/Work Product,
//! and explicit Consent into a reversible registration. Fixture, recording,
//! loopback, and `BLOCKED_ENV` frames become redacted digest-fenced evidence.
//! Native credential resolution, live HTTPS inference, durable receipts,
//! independent readback, and verified adoption remain Layer-2 seams.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

pub mod mission;
pub mod model;
pub mod provider;
pub mod service;

pub use mission::{MissionOpenAIResponsesConsumer, MissionResponseProjection};
pub use model::*;
pub use provider::{
    ModelDescription, OpenAIResponsesProvider, ProviderResponseOutcome, RecordedResponseFrame,
};
pub use service::OpenAIResponsesResultService;

pub const OPENAI_RESPONSES_RESULT_SCHEMA_VERSION: &str =
    "hartevo.openai-responses-result.contract/v1";
pub const OPENAI_RESPONSES_RESULT_CONTRACT_VERSION: &str = "openai-responses-result/v1";
pub const OPENAI_RESPONSES_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const OPENAI_RESPONSES_RESULT_SERVICE_ID: &str = "hartevo.openai.responses.result";
pub const OPENAI_RESPONSES_RESULT_PROVIDER_ID: &str = "openai.responses";
pub const OPENAI_RESPONSES_RESULT_CONSUMER_ID: &str = "mission.openai.responses.result";
pub const OPENAI_RESPONSES_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/openai-responses-result/openai-responses-result.v1.json"
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
        OPENAI_RESPONSES_RESULT_CONTRACT_JSON, OPENAI_RESPONSES_RESULT_CONTRACT_VERSION,
        OPENAI_RESPONSES_RESULT_PLUGIN_VERSION, OPENAI_RESPONSES_RESULT_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_keeps_direct_responses_layer_one_honest() {
        let contract: Value =
            serde_json::from_str(OPENAI_RESPONSES_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            OPENAI_RESPONSES_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            OPENAI_RESPONSES_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            contract["pluginVersion"],
            OPENAI_RESPONSES_RESULT_PLUGIN_VERSION
        );
        assert_eq!(contract["layer"], "Layer-1");
        assert_eq!(contract["api"], "responses.create");
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["batchLifecycle"], false);
        assert_eq!(contract["toolPolicy"]["default"], "disabled");
        assert_eq!(contract["inputAllowlist"]["rawFileBytes"], false);
        assert_eq!(contract["structuredOutputs"]["strict"], true);
    }
}

//! Standalone Layer-1 `OpenAI` Moderation classification evidence.
//!
//! This crate is deliberately a bounded proposal/read/record/verify seam. It
//! hashes supplied content before retaining anything, keeps only typed
//! category projections, and has no credential resolver, HTTP client, native
//! authority, automatic enforcement, or kernel integration.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

pub mod mission;
pub mod model;
pub mod provider;
pub mod service;

pub use mission::{MissionModerationProjection, MissionOpenAiModerationConsumer};
pub use model::*;
pub use provider::{
    ModerationFrameOutcome, ModerationPayload, OpenAiModerationProvider,
    OpenAiModerationProviderRead, RecordedModerationFrame,
};
pub use service::OpenAiModerationService;

pub const OPENAI_MODERATION_RESULT_SCHEMA_VERSION: &str =
    "hartevo.openai-moderation-result.contract/v1";
pub const OPENAI_MODERATION_RESULT_CONTRACT_VERSION: &str = "openai-moderation-result/v1";
pub const OPENAI_MODERATION_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const OPENAI_MODERATION_RESULT_SERVICE_ID: &str = "hartevo.openai.moderation.result";
pub const OPENAI_MODERATION_RESULT_PROVIDER_ID: &str = "openai.moderation";
pub const OPENAI_MODERATION_RESULT_CONSUMER_ID: &str = "mission.openai.moderation.result";
pub const OPENAI_MODERATION_API_HOST: &str = "https://api.openai.com";
pub const OPENAI_MODERATION_API_PATH: &str = "/v1/moderations";
pub const OPENAI_MODERATION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/openai-moderation-result/openai-moderation-result.v1.json"
);

pub(crate) fn digest_bytes(bytes: &[u8]) -> model::Digest {
    model::Digest::from_hex(Sha256::digest(bytes))
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> model::Digest {
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
        OPENAI_MODERATION_RESULT_CONTRACT_JSON, OPENAI_MODERATION_RESULT_CONTRACT_VERSION,
        OPENAI_MODERATION_RESULT_PLUGIN_VERSION, OPENAI_MODERATION_RESULT_SCHEMA_VERSION,
    };

    #[test]
    fn contract_is_layer_one_and_non_native() {
        let contract: Value =
            serde_json::from_str(OPENAI_MODERATION_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            OPENAI_MODERATION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            OPENAI_MODERATION_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            contract["pluginVersion"],
            OPENAI_MODERATION_RESULT_PLUGIN_VERSION
        );
        assert_eq!(contract["layer"], "Layer-1");
        assert_eq!(contract["api"], "moderations.create");
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["firstParty"], false);
        assert_eq!(contract["enforcement"]["automaticBlocking"], false);
        assert_eq!(contract["enforcement"]["notification"], false);
    }
}

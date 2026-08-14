//! Layer-1 governed LangSmith evaluation-evidence boundary.
//!
//! This crate is deliberately standalone and local-first. It binds exact
//! workspace/project/run/trace/dataset/evaluator/experiment/Mission scope,
//! projects bounded evaluation evidence, and emits a redacted proposal. It
//! does not resolve credentials, make native HTTPS calls, mutate LangSmith,
//! export arbitrary traces, retain prompt/output/PII, execute tools, provide a
//! model registry, create durable kernel receipts, or adopt an Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

pub mod mission;
pub mod model;
pub mod provider;
pub mod service;

pub use mission::{
    MissionEvaluationRequest, MissionEvaluationResult, MissionLangSmithEvaluationConsumer,
};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, CredentialResolutionError, EvidenceSource,
    LangSmithAuthenticationPlan, LangSmithCredentialResolver, LangSmithProvider,
    LangSmithProviderCall, LangSmithProviderError, LangSmithProviderManifest, NativeStatus,
    ProviderState, SecretMaterial, StaticCredentialResolver,
};
pub use service::{
    LangSmithCapabilities, LangSmithEvaluationService, LangSmithEvaluationServiceConfig,
    LangSmithReadProposal,
};

pub const LANGSMITH_EVALUATION_SCHEMA_VERSION: &str = "hartevo.langsmith-evaluation/v1";
pub const LANGSMITH_EVALUATION_CONTRACT_VERSION: &str = "EXT-LANGSMITH-01-L1/v1";
pub const LANGSMITH_EVALUATION_PLUGIN_VERSION: &str = "0.1.0";
pub const LANGSMITH_EVALUATION_CONTRACT_PATH: &str =
    "contracts/plugins/langsmith-evaluation/langsmith-evaluation.v1.json";
pub const LANGSMITH_EVALUATION_SERVICE_ID: &str = "hartevo.langsmith.evaluation";
pub const LANGSMITH_EVALUATION_PROVIDER_ID: &str = "langsmith.evaluation.read";
pub const LANGSMITH_EVALUATION_CONSUMER_ID: &str = "mission.langsmith.evaluation";
pub const LANGSMITH_EVALUATION_CONTRACT_DIGEST_INPUT: &str = "hartevo.langsmith-evaluation/v1|layer=1|service=hartevo.langsmith.evaluation|provider=langsmith.evaluation.read|consumer=mission.langsmith.evaluation|scope=host,workspace,project,run,trace,dataset,evaluator,experiment,mission";
pub const LANGSMITH_EVALUATION_CONTRACT_DIGEST: &str =
    "38abe161e26fb582570b875b2bccb5e4bfc52b182fb4f35a8aff8e8187900a71";
pub const LANGSMITH_EVALUATION_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/langsmith-evaluation/langsmith-evaluation.v1.json");

/// Return a lower-case SHA-256 digest.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_hex(Sha256::digest(bytes))
}

/// Hash a serializable value in its canonical declared field order.
#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed LangSmith values serialize");
    sha256_digest(&bytes)
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
        LANGSMITH_EVALUATION_CONTRACT_DIGEST, LANGSMITH_EVALUATION_CONTRACT_DIGEST_INPUT,
        LANGSMITH_EVALUATION_CONTRACT_JSON, LANGSMITH_EVALUATION_CONTRACT_VERSION,
        LANGSMITH_EVALUATION_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract: Value =
            serde_json::from_str(LANGSMITH_EVALUATION_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            LANGSMITH_EVALUATION_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            LANGSMITH_EVALUATION_CONTRACT_VERSION
        );
        assert_eq!(
            contract["contractDigestInput"],
            LANGSMITH_EVALUATION_CONTRACT_DIGEST_INPUT
        );
        assert_eq!(
            contract["contractDigest"],
            LANGSMITH_EVALUATION_CONTRACT_DIGEST
        );
        assert_eq!(contract["layer"], "Layer-1");
        assert_eq!(contract["provider"]["connected"], false);
        assert_eq!(contract["provider"]["native"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["authority"]["traceExport"], false);
        assert_eq!(contract["authority"]["toolExecution"], false);
        assert_eq!(contract["authority"]["modelRegistry"], false);
    }
}

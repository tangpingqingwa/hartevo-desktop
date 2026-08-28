//! Layer-1 governed Weights & Biases evaluation-result boundary.
//!
//! This crate is deliberately standalone and local-first.  It binds one exact
//! W&B host/entity/project/run, an allowlist of summary metrics and sampled
//! history, config/artifact/commit fingerprints, and exact Hartevo
//! Mission/Project/Work Product scope.  It emits bounded redacted proposals
//! from fixture, recording, loopback, or `BLOCKED_ENV` seams.  It never
//! resolves an API token, performs native HTTPS, writes metrics, uploads or
//! downloads artifacts, launches sweeps, exports raw history/datasets/media,
//! catalogs generic telemetry, renders UI, or exercises kernel authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

pub mod mission;
pub mod model;
pub mod provider;
pub mod service;

pub use mission::{
    MissionWandbEvaluationConsumer, MissionWandbEvaluationRequest, MissionWandbEvaluationResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, CredentialResolutionError, SecretMaterial,
    StaticCredentialResolver, WandbApiManifest, WandbAuthenticationPlan, WandbCredentialResolver,
    WandbProvider, WandbProviderCall, WandbProviderError, WandbProviderManifest,
};
pub use service::{
    WandbCapabilities, WandbEvaluationResultService, WandbEvaluationServiceConfig,
    WandbReadProposal,
};

pub const WANDB_EVALUATION_RESULT_SCHEMA_VERSION: &str = "hartevo.wandb-evaluation-result/v1";
pub const WANDB_EVALUATION_RESULT_CONTRACT_VERSION: &str = "EXT-WANDB-01-L1/v1";
pub const WANDB_EVALUATION_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const WANDB_EVALUATION_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/wandb-evaluation-result/wandb-evaluation-result.v1.json";
pub const WANDB_EVALUATION_RESULT_SERVICE_ID: &str = "hartevo.wandb.evaluation-result";
pub const WANDB_EVALUATION_RESULT_PROVIDER_ID: &str = "wandb.evaluation.result.read";
pub const WANDB_PROVIDER_ID: &str = WANDB_EVALUATION_RESULT_PROVIDER_ID;
pub const WANDB_EVALUATION_RESULT_CONSUMER_ID: &str = "mission.wandb.evaluation.result";
pub const MISSION_WANDB_EVALUATION_CONSUMER_ID: &str = WANDB_EVALUATION_RESULT_CONSUMER_ID;
pub const WANDB_EVALUATION_RESULT_API_VERSION: &str = "public_api/v1";
pub const WANDB_EVALUATION_RESULT_CONTRACT_DIGEST_INPUT: &str = "hartevo.wandb-evaluation-result/v1|layer=1|service=hartevo.wandb.evaluation-result|provider=wandb.evaluation.result.read|consumer=mission.wandb.evaluation.result|scope=host,entity,wandbProject,run,metricAllowlist,config,artifactAllowlist,commit,mission,hartevoProject,workProduct";
pub const WANDB_EVALUATION_RESULT_CONTRACT_DIGEST: &str =
    "2c0dd792525496fa3c2a4e02721c4afe079402efe28abdf52d1a3e6533f353c4";
pub const WANDB_EVALUATION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/wandb-evaluation-result/wandb-evaluation-result.v1.json"
);

pub type WandbEvaluationResult = WandbEvaluationEvidence;
pub type WandbEvaluationResultPage = WandbEvaluationPage;
pub type WandbEvaluationResultScope = WandbEvaluationScope;
pub type WandbEvaluationResultError = WandbEvaluationError;
pub type WandbEvaluationPermission = WandbPermission;
pub type WandbEvaluationRegistration = WandbPluginRegistration;
pub type WandbEvaluationReadProposal = WandbReadProposal;

/// Return a lower-case SHA-256 digest.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_hex(Sha256::digest(bytes))
}

/// Hash a serializable value in its declared canonical field order.
#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed W&B values serialize");
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
        WANDB_EVALUATION_RESULT_CONTRACT_DIGEST, WANDB_EVALUATION_RESULT_CONTRACT_DIGEST_INPUT,
        WANDB_EVALUATION_RESULT_CONTRACT_JSON, WANDB_EVALUATION_RESULT_CONTRACT_VERSION,
        WANDB_EVALUATION_RESULT_PLUGIN_VERSION, WANDB_EVALUATION_RESULT_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract: Value =
            serde_json::from_str(WANDB_EVALUATION_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            WANDB_EVALUATION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            WANDB_EVALUATION_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            contract["pluginVersion"],
            WANDB_EVALUATION_RESULT_PLUGIN_VERSION
        );
        assert_eq!(
            contract["contractDigestInput"],
            WANDB_EVALUATION_RESULT_CONTRACT_DIGEST_INPUT
        );
        assert_eq!(
            contract["contractDigest"],
            WANDB_EVALUATION_RESULT_CONTRACT_DIGEST
        );
        assert_eq!(contract["layer"], "Layer-1");
        assert_eq!(contract["provider"]["connected"], false);
        assert_eq!(contract["provider"]["native"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["authority"]["metricWrites"], false);
        assert_eq!(contract["authority"]["artifactUpload"], false);
        assert_eq!(contract["authority"]["artifactDownload"], false);
        assert_eq!(contract["authority"]["sweepLaunch"], false);
        assert_eq!(contract["authentication"]["serialized"], false);
    }
}

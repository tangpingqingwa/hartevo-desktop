//! Standalone Layer-1 governed GitHub artifact-attestation result boundary.
//!
//! The crate exposes one official, bounded subject-digest listing seam and a
//! Mission-scoped proposal/record/verify surface. It never resolves App/OAuth
//! credentials, opens native HTTPS, downloads artifacts or attestation bundles,
//! deletes attestations, mutates trust roots, approves releases, emits a
//! durable provider receipt, or adopts a kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AdoptionAvailability, ConsumerError, ConsumerRegistration, MissionAttestationDecisionState,
    MissionGithubArtifactAttestationConsumer, MissionGithubArtifactAttestationResult,
    MissionGithubAttestationConsumer, MissionGithubAttestationResult,
};
pub use model::*;
pub use provider::*;
pub use service::*;

pub const CONTRACT_SCHEMA: &str = "hartevo.github-artifact-attestation-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-GITHUB-ATTESTATION-01-L1/v1";
pub const PLUGIN_ID: &str = "github.artifact-attestation.result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "github.artifact-attestation.result.read";
pub const PROVIDER_ID: &str = "github.artifact-attestation.result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const API_REVISION: &str = "github-artifact-attestations-rest-v1";
pub const CONSUMER_ID: &str = "mission.github-artifact-attestation.consumer";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.github-artifact-attestation-result/v1|EXT-GITHUB-ATTESTATION-01-L1/v1|github.artifact-attestation.result|github.artifact-attestation.result.read|github.artifact-attestation.result.recording|mission.github-artifact-attestation.consumer";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/github-artifact-attestation-result/contract.v1.json");

#[must_use]
pub fn contract_digest() -> String {
    sha256_digest(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[must_use]
pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[must_use]
pub fn metadata_digest_bounded(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    sha256_digest(&bytes[..end])
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

pub fn validate_contract() -> std::result::Result<(), ContractValidationError> {
    let document: serde_json::Value = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let check = |field: &'static str, condition: bool| {
        if condition {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(field))
        }
    };
    check(
        "schemaVersion",
        document["schemaVersion"] == CONTRACT_SCHEMA,
    )?;
    check(
        "contractVersion",
        document["contractVersion"] == CONTRACT_VERSION,
    )?;
    check("pluginId", document["pluginId"] == PLUGIN_ID)?;
    check("pluginVersion", document["pluginVersion"] == PLUGIN_VERSION)?;
    check(
        "contractDigestInput",
        document["contractDigestInput"] == CONTRACT_DIGEST_INPUT,
    )?;
    check(
        "contractDigest",
        document["contractDigest"] == contract_digest(),
    )?;
    check("layer", document["layer"] == 1)?;
    check(
        "evidenceLevel",
        document["evidenceLevel"] == "L1_PROVIDER_CONTRACT",
    )?;
    check(
        "service.type",
        document["service"]["type"] == "GithubArtifactAttestationService",
    )?;
    check("service.id", document["service"]["id"] == SERVICE_ID)?;
    check(
        "provider.type",
        document["provider"]["type"] == "GithubArtifactAttestationProvider",
    )?;
    check("provider.id", document["provider"]["id"] == PROVIDER_ID)?;
    check(
        "provider.apiRevision",
        document["provider"]["apiRevision"] == API_REVISION,
    )?;
    check(
        "consumer.type",
        document["consumer"]["type"] == "MissionGithubAttestationConsumer",
    )?;
    check("consumer.id", document["consumer"]["id"] == CONSUMER_ID)?;
    for field in [
        "connected",
        "nativeProvider",
        "durableReceipt",
        "kernelAuthority",
        "outcomeAuthority",
        "externalWrites",
    ] {
        check(field, document["authority"][field] == false)?;
    }
    check("provider.native", document["provider"]["native"] == false)?;
    check(
        "provider.connected",
        document["provider"]["connected"] == false,
    )?;
    check(
        "provider.rawBundle",
        document["provider"]["rawBundle"] == false,
    )?;
    check(
        "consumer.adoptsOutcome",
        document["consumer"]["adoptsOutcome"] == false,
    )?;
    check(
        "authentication.serialized",
        document["authentication"]["serialized"] == false,
    )?;
    check(
        "authentication.rawMaterialAccepted",
        document["authentication"]["rawMaterialAccepted"] == false,
    )?;
    check(
        "registration.reversible",
        document["registration"]["reversible"] == true,
    )?;
    check(
        "registration.revocable",
        document["registration"]["revocable"] == true,
    )?;
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        validate_contract().expect("contract validates");
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Capabilities::connected());
        assert!(!Layer1Capabilities::native_provider());
        assert!(!Layer1Capabilities::durable_receipt());
        assert!(!Layer1Capabilities::outcome_authority());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Capabilities;

impl Layer1Capabilities {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }
}

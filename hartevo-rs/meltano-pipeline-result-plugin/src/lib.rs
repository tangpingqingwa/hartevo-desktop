//! Standalone Layer-1 Meltano Cloud/Singer pipeline result evidence boundary.
//!
//! The crate models bounded metadata reads, proposals, verification, and
//! recording only. It never resolves native credentials, executes, stops, or
//! deletes a job, installs a plugin, mutates a project or environment, reads
//! raw logs/rows/state, or claims Connected/native/first-party evidence.

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
    MissionMeltanoPipelineConsumer, MissionMeltanoPipelineResult, RecordedMeltanoPipelineResult,
};
pub use error::{MeltanoPipelineResultError, MeltanoTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, FixtureTransport, LoopbackTransport, MeltanoPipelineReadRequest,
    MeltanoPipelineResultResponse, MeltanoProvider, MeltanoProviderDefinition,
    MeltanoProviderError, MeltanoReadOperation, MeltanoTransport, RecordedMeltanoRequest,
    RecordingTransport,
};
pub use service::{
    CapabilityDescription, MeltanoPipelineResultService, MeltanoPipelineResultServiceError,
    VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.meltano-pipeline-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-MELTANO-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.meltano-pipeline-result/v1|layer=1|service=meltano.pipeline-result.read|provider=meltano.pipeline-result.recording|consumer=mission.meltano-pipeline-result.consumer";
pub const PLUGIN_ID: &str = "meltano.pipeline-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "meltano.pipeline-result.read";
pub const PROVIDER_ID: &str = "meltano.pipeline-result.recording";
pub const PROVIDER_API_REVISION: &str = "meltano-cloud-api-v1-pipeline-job-state-config-read-1";
pub const CONSUMER_ID: &str = "mission.meltano-pipeline-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/meltano-pipeline-result/meltano-pipeline-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_METADATA_ITEMS: usize = 64;
pub const MAX_PAGE_SIZE: u16 = 64;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_TASKS: u16 = 64;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::parse(sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes()))
        .expect("SHA-256 output is a valid digest")
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validates the checked-in contract document and its Layer-1 honesty pins.
#[allow(clippy::too_many_lines)]
pub fn validate_contract() -> std::result::Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let is = |path: &'static str, actual: bool| {
        if actual {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(path))
        }
    };
    is(
        "schemaVersion",
        contract["schemaVersion"] == CONTRACT_SCHEMA,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == CONTRACT_VERSION,
    )?;
    is("pluginId", contract["pluginId"] == PLUGIN_ID)?;
    is("pluginVersion", contract["pluginVersion"] == PLUGIN_VERSION)?;
    is("layer", contract["layer"] == 1)?;
    is("evidenceLevel", contract["evidenceLevel"] == EVIDENCE_LEVEL)?;
    is(
        "digestInput",
        contract["digestInput"] == CONTRACT_DIGEST_INPUT,
    )?;
    is(
        "contractDigest",
        contract["contractDigest"] == contract_digest().as_str(),
    )?;
    is("service.id", contract["service"]["id"] == SERVICE_ID)?;
    is("service.readOnly", contract["service"]["readOnly"] == true)?;
    is(
        "service.proposalOnly",
        contract["service"]["proposalOnly"] == true,
    )?;
    is(
        "service.recordingOnly",
        contract["service"]["recordingOnly"] == true,
    )?;
    is(
        "service.externalWrites",
        contract["service"]["externalWrites"] == false,
    )?;
    is("provider.id", contract["provider"]["id"] == PROVIDER_ID)?;
    is(
        "provider.connectedEvidence",
        contract["provider"]["connectedEvidence"] == false,
    )?;
    is(
        "provider.nativeEvidence",
        contract["provider"]["nativeEvidence"] == false,
    )?;
    is(
        "provider.firstPartyEvidence",
        contract["provider"]["firstPartyEvidence"] == false,
    )?;
    is(
        "provider.providerReceipt",
        contract["provider"]["providerReceipt"] == false,
    )?;
    is("consumer.id", contract["consumer"]["id"] == CONSUMER_ID)?;
    is(
        "consumer.adoptsOutcome",
        contract["consumer"]["adoptsOutcome"] == false,
    )?;
    is(
        "consumer.adoptsWorkProduct",
        contract["consumer"]["adoptsWorkProduct"] == false,
    )?;
    is(
        "credentials.serialized",
        contract["credentials"]["serialized"] == false,
    )?;
    is("scope.rawLogs", contract["scope"]["rawLogs"] == false)?;
    is("scope.rawRows", contract["scope"]["rawRows"] == false)?;
    is(
        "scope.rawStateBlobs",
        contract["scope"]["rawStateBlobs"] == false,
    )?;
    is("scope.rawSecrets", contract["scope"]["rawSecrets"] == false)?;
    is(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    is(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    is(
        "registration.evidenceDigestBound",
        contract["registration"]["evidenceDigestBound"] == true,
    )?;
    is(
        "provenance.connectedClaim",
        contract["provenance"]["connectedClaim"] == false,
    )?;
    is(
        "provenance.nativeClaim",
        contract["provenance"]["nativeClaim"] == false,
    )?;
    is(
        "provenance.firstPartyClaim",
        contract["provenance"]["firstPartyClaim"] == false,
    )?;
    Ok(())
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
        super::validate_contract().expect("contract validates");
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
        assert!(
            !contract["provider"]["firstPartyEvidence"]
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

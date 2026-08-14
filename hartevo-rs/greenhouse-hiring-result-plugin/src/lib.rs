//! Standalone Layer-1 Greenhouse Harvest hiring-result evidence contract.
//!
//! The crate exposes bounded application, stage, scorecard-aggregate, and
//! offer evidence for a Mission proposal.  It deliberately has no live
//! credential resolver, native HTTPS transport, recruiting mutation, raw PII
//! model, Hartevo kernel authority, or Outcome adoption path.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
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

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{MissionGreenhouseHiringConsumer, MissionHiringRequest, MissionHiringResult};
pub use error::{GreenhouseError, TransportError};
pub use model::{
    ApplicationId, ApplicationState, BoundedTimestamp, CandidateReference, CandidateReferenceId,
    Capability, CapabilitySet, ConsentField, ConsentReceipt, ConsentScope, ConsentStatus, Digest,
    EffectIntent, EffectOperation, EvidenceCompleteness, EvidenceReceipt, GreenhouseHiringEvidence,
    GreenhouseScope, HiringDecision, HiringObjective, JobId, Layer1Recording, MissionId,
    OfferEvidence, OfferId, OfferState, OrganizationId, ProjectId, ProposalRequest, ProposalResult,
    ProviderId, ProviderRevision, ReadBackRequest, ReadBackResult, RedactionSummary,
    RegistrationState, Revision, ScorecardAggregate, ScorecardId, SecretKind, SecretReference,
    StageId, StageTransition, TransportProvenance, WorkProductId,
};
pub use provider::{
    BlockedEnvTransport, FixtureTransport, GreenhouseHarvestProvider,
    GreenhouseHarvestProviderDefinition, HarvestEndpoint, HarvestExchange, HarvestHttpRequest,
    HarvestHttpResponse, HarvestRequestReceipt, HarvestTransport, LinkHeader, LoopbackTransport,
    ProviderReadResult, RateLimitPolicy, RecordingTransport, RetryPolicy,
};
pub use service::{
    GreenhouseHiringResultService, GreenhouseHiringResultServiceDefinition, GreenhouseRegistration,
    ServiceOperation,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.greenhouse-hiring-result-contract/v1";
pub const CONTRACT_VERSION: &str = "greenhouse-hiring-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.greenhouse-hiring-result-contract/v1|layer=1|service=greenhouse.hiring-result.read|provider=greenhouse.harvest.hiring-result|consumer=mission.greenhouse-hiring-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "b76beeb8f667c03dabaced07c0a2eace8fed438dd92fe62b2a6af556e01587ee";
pub const PLUGIN_ID: &str = "greenhouse.hiring-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "greenhouse.hiring-result.read";
pub const PROVIDER_ID: &str = "greenhouse.harvest.hiring-result";
pub const PROVIDER_API_REVISION: &str = "harvest-hiring-result-read-1";
pub const CONSUMER_ID: &str = "mission.greenhouse-hiring-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_PAGES: usize = 16;
pub const MAX_STAGE_TRANSITIONS: usize = 64;
pub const MAX_SCORECARDS: usize = 32;
pub const MAX_OFFERS: usize = 16;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TEXT_BYTES: usize = 512;

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/greenhouse-hiring-result/greenhouse-hiring-result.v1.json"
);

#[cfg(test)]
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest as Sha2Digest, Sha256};

    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("contract values must serialize"))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), GreenhouseError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(GreenhouseError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<(), GreenhouseError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(GreenhouseError::InvalidIdentifier { field })
    }
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), GreenhouseError> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(GreenhouseError::InvalidDigest { field })
    }
}

pub(crate) fn validate_timestamp(value: &str) -> Result<(), GreenhouseError> {
    validate_text(value, "timestamp", 64)
}

/// Layer-1 authority flags are all intentionally negative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn external_write() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn independent_read_back() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
        CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, Layer1Authority, PLUGIN_ID, PROVIDER_ID,
        SERVICE_ID, sha256_hex,
    };

    #[test]
    fn contract_document_is_layer_one_and_honest() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert_eq!(
            document["provider"]["allowedMethods"],
            serde_json::json!(["GET"])
        );
        assert_eq!(document["provider"]["mutations"]["advanceStage"], false);
        assert_eq!(document["credentials"]["serialized"], false);
        assert_eq!(
            document["redaction"]["missingScorecardIsHiringSuccess"],
            false
        );
        assert_eq!(document["provenance"]["nativeConnectedClaim"], false);
        assert_eq!(
            document["consentEffectReceiptReadBack"]["nativeReceipt"],
            false
        );
        assert!(document["honestNativeGap"].is_string());
        assert_eq!(CONTRACT_DIGEST, document["contractDigest"]);
        assert_eq!(
            sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes()),
            CONTRACT_DIGEST
        );
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::external_write());
        assert!(!Layer1Authority::durable_native_receipt());
        assert!(!Layer1Authority::independent_read_back());
        assert!(!Layer1Authority::adopted_outcome());
    }
}

#[cfg(test)]
mod adversarial_tests;

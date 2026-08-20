//! Standalone Layer-1 governed Crossref research metadata result plugin.
//!
//! The crate exposes typed bounded read seams for
//! [`CrossrefResearchResultService`], [`CrossrefProvider`], and
//! [`MissionCrossrefResearchConsumer`]. It never resolves native credentials,
//! opens HTTPS, emits raw Crossref metadata, claims Connected/native/
//! first-party, mutates Crossref, creates a kernel receipt, or adopts an
//! Outcome/Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::result_large_err)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionCrossrefResearchConsumer, MissionCrossrefResearchConsumerError,
    MissionCrossrefResearchResult, MissionCrossrefResearchResultState, MissionResultState,
};
pub use model::{
    ConsentScope, CrossrefEvidenceState, CrossrefObservationReceipt, CrossrefOperation,
    CrossrefPermission, CrossrefQuery, CrossrefReadReceipt, CrossrefRegistration,
    CrossrefResearchEvidence, CrossrefResearchProposal, CrossrefResearchScope,
    CrossrefWorkProjection, Digest, IdentityBinding, MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES,
    MAX_METADATA_AUTHORS, MAX_QUERY_BYTES, MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES,
    MAX_RESULTS, MAX_RETRY_AFTER_SECONDS, MAX_TITLE_BYTES, MissionBinding, ModelError,
    ProjectBinding, ProjectId, RateLimitReceipt, RecommendationDisposition, RegistrationState,
    RegistrationTransitionReceipt, Revision, SecretReference, TransportProvenance,
    WorkProductBinding, WorkProductId, canonical_digest, sha256_digest,
};
pub use provider::{
    BlockedEnvCrossrefTransport, CROSSREF_API_REVISION, CROSSREF_BASE_URL,
    CROSSREF_METADATA_PERMISSION, CROSSREF_PROVIDER_ID, CROSSREF_PROVIDER_VERSION,
    CrossrefFixtureAuthor, CrossrefFixtureMessage, CrossrefFixturePayload,
    CrossrefFixturePublished, CrossrefFixtureWork, CrossrefHttpMethod, CrossrefProvider,
    CrossrefProviderDefinition, CrossrefProviderError, CrossrefProviderRead, CrossrefRequest,
    CrossrefResponse, CrossrefTransport, CrossrefTransportError, FixtureCrossrefTransport,
    LoopbackCrossrefTransport, RecordingCrossrefTransport,
};
pub use service::{
    CROSSREF_RESEARCH_RESULT_SERVICE_ID, CrossrefResearchResultService,
    CrossrefResearchResultServiceDefinition, CrossrefResearchResultServiceError,
};

pub const CROSSREF_RESEARCH_RESULT_SCHEMA_VERSION: &str = "hartevo.crossref-research-result/v1";
pub const CROSSREF_RESEARCH_RESULT_CONTRACT_VERSION: &str = "crossref-research-result-e1/v1";
pub const CROSSREF_RESEARCH_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const MISSION_CROSSREF_RESEARCH_CONSUMER_ID: &str = "mission.crossref-research-result";
pub const CROSSREF_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CROSSREF_RESEARCH_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/crossref-research-result/crossref-research-result.v1.json";
pub const CROSSREF_RESEARCH_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/crossref-research-result/crossref-research-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(CROSSREF_RESEARCH_RESULT_CONTRACT_JSON.as_bytes())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn truth_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn consent_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn verification_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validates the checked-in contract and its immutable Layer-1 honesty pins.
#[allow(clippy::too_many_lines)]
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(CROSSREF_RESEARCH_RESULT_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let is = |path: &'static str, condition: bool| {
        if condition {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(path))
        }
    };
    is(
        "schemaVersion",
        contract["schemaVersion"] == CROSSREF_RESEARCH_RESULT_SCHEMA_VERSION,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == CROSSREF_RESEARCH_RESULT_CONTRACT_VERSION,
    )?;
    is(
        "pluginVersion",
        contract["pluginVersion"] == CROSSREF_RESEARCH_RESULT_PLUGIN_VERSION,
    )?;
    is("layer", contract["layer"] == 1)?;
    is(
        "service.id",
        contract["service"]["id"] == CROSSREF_RESEARCH_RESULT_SERVICE_ID,
    )?;
    is(
        "provider.id",
        contract["provider"]["id"] == CROSSREF_PROVIDER_ID,
    )?;
    is(
        "provider.baseUrl",
        contract["provider"]["baseUrl"] == CROSSREF_BASE_URL,
    )?;
    is(
        "provider.requiredPermission",
        contract["provider"]["requiredPermission"] == CROSSREF_METADATA_PERMISSION,
    )?;
    is(
        "consumer.id",
        contract["consumer"]["id"] == MISSION_CROSSREF_RESEARCH_CONSUMER_ID,
    )?;
    is(
        "authority.connected",
        contract["authority"]["connected"] == false,
    )?;
    is(
        "authority.nativeProvider",
        contract["authority"]["nativeProvider"] == false,
    )?;
    is(
        "authority.firstParty",
        contract["authority"]["firstParty"] == false,
    )?;
    is(
        "authority.externalWrites",
        contract["authority"]["externalWrites"] == false,
    )?;
    is(
        "authority.kernelAuthority",
        contract["authority"]["kernelAuthority"] == false,
    )?;
    is("provider.native", contract["provider"]["native"] == false)?;
    is(
        "provider.connected",
        contract["provider"]["connected"] == false,
    )?;
    is(
        "provider.firstParty",
        contract["provider"]["firstParty"] == false,
    )?;
    is(
        "provider.maxResults",
        contract["provider"]["maxResults"] == MAX_RESULTS,
    )?;
    is(
        "provider.maxResponseBytes",
        contract["provider"]["maxResponseBytes"] == MAX_RESPONSE_BYTES,
    )?;
    is(
        "allowlist.writes",
        contract["allowlist"]["writes"]
            .as_array()
            .is_some_and(Vec::is_empty),
    )?;
    is(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    is(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    is(
        "honesty.blockedEnvConnected",
        contract["honesty"]["blockedEnvConnected"] == false,
    )?;
    is(
        "honesty.blockedEnvNative",
        contract["honesty"]["blockedEnvNative"] == false,
    )?;
    is(
        "honesty.blockedEnvFirstParty",
        contract["honesty"]["blockedEnvFirstParty"] == false,
    )?;
    Ok(())
}

pub type CrossrefService<T> = CrossrefResearchResultService<T>;
pub type CrossrefServiceError = CrossrefResearchResultServiceError;
pub type CrossrefEvidence = CrossrefResearchEvidence;
pub type CrossrefProposal = CrossrefResearchProposal;
pub type CrossrefReceipt = CrossrefObservationReceipt;

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_valid_and_layer_one_is_honest() {
        validate_contract().expect("Crossref contract validates");
        assert_eq!(contract_digest(), contract_digest());
        assert!(!CROSSREF_RESEARCH_RESULT_CONTRACT_JSON.is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::consent_authority());
        assert!(!Layer1Authority::verification_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}

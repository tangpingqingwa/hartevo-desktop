//! Standalone Layer-1 governed PubMed biomedical research evidence result
//! plugin.
//!
//! The crate exposes typed bounded read seams for
//! [`PubMedResearchResultService`], [`NcbiEutilsProvider`], and
//! [`MissionPubMedResearchConsumer`]. It never resolves native credentials,
//! opens HTTPS, emits abstracts/full text, gives clinical or citation-quality
//! advice, claims Connected/native/first-party, mutates NCBI, creates a
//! kernel receipt, or adopts an Outcome/Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_lines)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionPubMedResearchConsumer, MissionPubMedResearchConsumerError,
    MissionPubMedResearchResult, MissionPubMedResearchResultState, MissionResultState,
};
pub use model::{
    ConsentScope, Digest, HistoryReference, IdentityBinding, MAX_CURSOR_BYTES,
    MAX_DIAGNOSTIC_BYTES, MAX_HISTORY_BYTES, MAX_IDENTIFIER_BYTES, MAX_IDENTIFIER_LIST,
    MAX_JOURNAL_BYTES, MAX_MESH_TERM_BYTES, MAX_QUERY_BYTES, MAX_REQUESTS_PER_MINUTE,
    MAX_RESPONSE_BYTES, MAX_RESULTS, MAX_RETRY_AFTER_SECONDS, MAX_TITLE_BYTES, MissionBinding,
    MissionId, ModelError, OpaqueCursor, OpaqueHistory, ProjectBinding, ProjectId,
    PubMedArticleProjection, PubMedDatabase, PubMedEvidenceState, PubMedLinkProjection,
    PubMedObservationReceipt, PubMedOperation, PubMedPermission, PubMedQuery, PubMedReadReceipt,
    PubMedRegistration, PubMedResearchEvidence, PubMedResearchProposal, PubMedResearchScope,
    RateLimitReceipt, RecommendationDisposition, RegistrationState, RegistrationTransitionReceipt,
    Revision, SecretReference, TransportProvenance, WorkProductBinding, WorkProductId,
    canonical_digest, sha256_digest,
};
pub use provider::{
    BlockedEnvNcbiEutilsTransport, BlockedEnvPubMedTransport, FakeNcbiEutilsTransport,
    FakePubMedTransport, FixtureNcbiEutilsTransport, FixturePubMedTransport,
    LoopbackNcbiEutilsTransport, LoopbackPubMedTransport, NCBI_EUTILS_API_REVISION,
    NCBI_EUTILS_PROVIDER_ID, NCBI_EUTILS_PROVIDER_VERSION, NcbiEutilsProvider,
    NcbiEutilsProviderDefinition, NcbiEutilsProviderError, NcbiEutilsProviderRead,
    NcbiEutilsTransport, NcbiEutilsTransportError, NcbiHttpMethod, PUBMED_BASE_URL,
    PUBMED_METADATA_PERMISSION, PubMedProvider, PubMedProviderDefinition, PubMedProviderRead,
    PubMedRequest, PubMedResponse, PubMedTransport, PubMedTransportError,
    RecordingNcbiEutilsTransport, RecordingPubMedTransport,
};
pub use service::{
    PUBMED_RESEARCH_RESULT_SERVICE_ID, PubMedEvidence, PubMedProposal, PubMedReceipt,
    PubMedResearchResultService, PubMedResearchResultServiceDefinition,
    PubMedResearchResultServiceError, PubMedService, PubMedServiceError,
};

pub const PUBMED_RESEARCH_RESULT_SCHEMA_VERSION: &str = "hartevo.pubmed-research-result/v1";
pub const PUBMED_RESEARCH_RESULT_CONTRACT_VERSION: &str = "pubmed-research-result-e1/v1";
pub const PUBMED_RESEARCH_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const MISSION_PUBMED_RESEARCH_CONSUMER_ID: &str = "mission.pubmed-research-result";
pub const PUBMED_RESEARCH_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const PUBMED_BLOCKED_ENV: &str = PUBMED_RESEARCH_RESULT_BLOCKED_ENV;
pub const PUBMED_RESEARCH_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/pubmed-research-result/pubmed-research-result.v1.json";
pub const PUBMED_RESEARCH_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/pubmed-research-result/pubmed-research-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(PUBMED_RESEARCH_RESULT_CONTRACT_JSON.as_bytes())
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
    let contract: serde_json::Value = serde_json::from_str(PUBMED_RESEARCH_RESULT_CONTRACT_JSON)
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
        contract["schemaVersion"] == PUBMED_RESEARCH_RESULT_SCHEMA_VERSION,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == PUBMED_RESEARCH_RESULT_CONTRACT_VERSION,
    )?;
    is(
        "pluginVersion",
        contract["pluginVersion"] == PUBMED_RESEARCH_RESULT_PLUGIN_VERSION,
    )?;
    is("layer", contract["layer"] == 1)?;
    is(
        "service.id",
        contract["service"]["id"] == PUBMED_RESEARCH_RESULT_SERVICE_ID,
    )?;
    is(
        "provider.id",
        contract["provider"]["id"] == NCBI_EUTILS_PROVIDER_ID,
    )?;
    is(
        "provider.baseUrl",
        contract["provider"]["baseUrl"] == PUBMED_BASE_URL,
    )?;
    is(
        "provider.requiredPermission",
        contract["provider"]["requiredPermission"] == PUBMED_METADATA_PERMISSION,
    )?;
    is(
        "consumer.id",
        contract["consumer"]["id"] == MISSION_PUBMED_RESEARCH_CONSUMER_ID,
    )?;
    for (path, value) in [
        ("authority.connected", &contract["authority"]["connected"]),
        (
            "authority.nativeProvider",
            &contract["authority"]["nativeProvider"],
        ),
        ("authority.firstParty", &contract["authority"]["firstParty"]),
        (
            "authority.externalWrites",
            &contract["authority"]["externalWrites"],
        ),
        (
            "authority.kernelAuthority",
            &contract["authority"]["kernelAuthority"],
        ),
        ("provider.native", &contract["provider"]["native"]),
        ("provider.connected", &contract["provider"]["connected"]),
        ("provider.firstParty", &contract["provider"]["firstParty"]),
        (
            "honesty.blockedEnvConnected",
            &contract["honesty"]["blockedEnvConnected"],
        ),
        (
            "honesty.blockedEnvNative",
            &contract["honesty"]["blockedEnvNative"],
        ),
        (
            "honesty.blockedEnvFirstParty",
            &contract["honesty"]["blockedEnvFirstParty"],
        ),
    ] {
        is(path, value == &serde_json::Value::Bool(false))?;
    }
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
        "honesty.absenceIsSuccess",
        contract["honesty"]["absenceIsSuccess"] == false,
    )?;
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_valid_and_layer_one_is_honest() {
        validate_contract().expect("PubMed contract validates");
        assert_eq!(contract_digest(), contract_digest());
        assert!(!PUBMED_RESEARCH_RESULT_CONTRACT_JSON.is_empty());
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

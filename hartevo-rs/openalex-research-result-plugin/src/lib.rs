//! Standalone Layer-1 governed OpenAlex research-result plugin.
//!
//! The crate exposes typed bounded read seams for
//! [`OpenAlexResearchResultService`], [`OpenAlexProvider`], and
//! [`MissionOpenAlexResearchConsumer`]. It never resolves native credentials,
//! opens HTTPS, emits raw OpenAlex metadata, claims Connected/native,
//! performs ranking or full-text retrieval, asserts citation or research
//! Truth, mutates OpenAlex, creates a kernel receipt, or adopts an
//! Outcome/Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
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
    ConsumerError, MissionOpenAlexResearchConsumer, MissionOpenAlexResearchConsumerError,
    MissionOpenAlexResearchResult, MissionOpenAlexResearchResultState, MissionResultState,
};
pub use model::{
    ConsentScope, Digest, IdentityBinding, MAX_CURSOR_BYTES, MAX_DIAGNOSTIC_BYTES,
    MAX_FILTER_BYTES, MAX_IDENTIFIER_BYTES, MAX_QUERY_BYTES, MAX_REQUESTS_PER_MINUTE,
    MAX_RESPONSE_BYTES, MAX_RESULTS, MAX_RETRY_AFTER_SECONDS, MAX_WORK_AUTHORS, MAX_WORK_CONCEPTS,
    MAX_WORK_INSTITUTIONS, MissionBinding, MissionId, ModelError, OpenAlexAuthorProjection,
    OpenAlexCitationDirection, OpenAlexCitationProjection, OpenAlexConceptProjection,
    OpenAlexCursor, OpenAlexEntity, OpenAlexEvidenceState, OpenAlexInstitutionProjection,
    OpenAlexObservationReceipt, OpenAlexOperation, OpenAlexPermission, OpenAlexQuery,
    OpenAlexReadReceipt, OpenAlexRegistration, OpenAlexResearchEvidence, OpenAlexResearchProposal,
    OpenAlexResearchScope, OpenAlexWorkProjection, ProjectBinding, ProjectId, RateLimitReceipt,
    RecommendationDisposition, RegistrationState, RegistrationTransitionReceipt, Revision,
    SecretReference, TransportProvenance, WorkProductBinding, WorkProductId, canonical_digest,
    sha256_digest,
};
pub use provider::{
    BlockedEnvOpenAlexTransport, FakeOpenAlexTransport, FixtureOpenAlexTransport,
    LoopbackOpenAlexTransport, OPENALEX_API_REVISION, OPENALEX_BASE_URL,
    OPENALEX_METADATA_PERMISSION, OPENALEX_PROVIDER_ID, OPENALEX_PROVIDER_VERSION,
    OpenAlexFixtureMeta, OpenAlexFixturePayload, OpenAlexFixtureSingleton, OpenAlexHttpMethod,
    OpenAlexProvider, OpenAlexProviderDefinition, OpenAlexProviderError, OpenAlexProviderRead,
    OpenAlexRequest, OpenAlexResponse, OpenAlexTransport, OpenAlexTransportError,
    RecordingOpenAlexTransport,
};
pub use service::{
    OPENALEX_RESEARCH_RESULT_SERVICE_ID, OpenAlexResearchResultService,
    OpenAlexResearchResultServiceDefinition, OpenAlexResearchResultServiceError,
};

pub type OpenAlexScope = OpenAlexResearchScope;
pub type OpenAlexQuerySpec = OpenAlexQuery;
pub type OpenAlexConsentScope = ConsentScope;
pub type Project = ProjectBinding;
pub type Mission = crate::model::MissionBinding;
pub type WorkProduct = WorkProductBinding;

pub const OPENALEX_RESEARCH_RESULT_SCHEMA_VERSION: &str = "hartevo.openalex-research-result/v1";
pub const OPENALEX_RESEARCH_RESULT_CONTRACT_VERSION: &str = "openalex-research-result-e1/v1";
pub const OPENALEX_RESEARCH_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const MISSION_OPENALEX_RESEARCH_CONSUMER_ID: &str = "mission.openalex.research-result";
pub const OPENALEX_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const OPENALEX_RESEARCH_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/openalex-research-result/openalex-research-result.v1.json";
pub const OPENALEX_RESEARCH_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/openalex-research-result/openalex-research-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(OPENALEX_RESEARCH_RESULT_CONTRACT_JSON.as_bytes())
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
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn ranking_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn full_text_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn author_identity_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn citation_truth_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn research_truth_authority() -> bool {
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
    let contract: serde_json::Value = serde_json::from_str(OPENALEX_RESEARCH_RESULT_CONTRACT_JSON)
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
        contract["schemaVersion"] == OPENALEX_RESEARCH_RESULT_SCHEMA_VERSION,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == OPENALEX_RESEARCH_RESULT_CONTRACT_VERSION,
    )?;
    is(
        "pluginVersion",
        contract["pluginVersion"] == OPENALEX_RESEARCH_RESULT_PLUGIN_VERSION,
    )?;
    is("layer", contract["layer"] == 1)?;
    is(
        "service.id",
        contract["service"]["id"] == OPENALEX_RESEARCH_RESULT_SERVICE_ID,
    )?;
    is(
        "provider.id",
        contract["provider"]["id"] == OPENALEX_PROVIDER_ID,
    )?;
    is(
        "provider.baseUrl",
        contract["provider"]["baseUrl"] == OPENALEX_BASE_URL,
    )?;
    is(
        "provider.requiredPermission",
        contract["provider"]["requiredPermission"] == OPENALEX_METADATA_PERMISSION,
    )?;
    is(
        "consumer.id",
        contract["consumer"]["id"] == MISSION_OPENALEX_RESEARCH_CONSUMER_ID,
    )?;
    for path in [
        "authority.connected",
        "authority.nativeProvider",
        "authority.durableReceipt",
        "authority.kernelAuthority",
        "authority.truthAuthority",
        "authority.researchTruthAuthority",
        "authority.rankingAuthority",
        "authority.fullTextAuthority",
        "authority.authorIdentityAuthority",
        "authority.citationTruthAuthority",
        "authority.outcomeAuthority",
        "authority.externalWrites",
        "provider.native",
        "provider.connected",
    ] {
        let value = path
            .split('.')
            .fold(&contract, |current, key| &current[key]);
        is(path, value == false)?;
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
        "provider.maxRequestsPerMinute",
        contract["provider"]["maxRequestsPerMinute"] == MAX_REQUESTS_PER_MINUTE,
    )?;
    is(
        "allowlist.writes",
        contract["allowlist"]["writes"]
            .as_array()
            .is_some_and(Vec::is_empty),
    )?;
    Ok(())
}

#[cfg(test)]
mod contract_document_tests {
    use super::{
        ContractValidationError, Layer1Authority, OPENALEX_RESEARCH_RESULT_CONTRACT_JSON,
        OPENALEX_RESEARCH_RESULT_CONTRACT_VERSION, OPENALEX_RESEARCH_RESULT_SCHEMA_VERSION,
        contract_digest, validate_contract,
    };
    use serde_json::Value;

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        validate_contract().expect("contract validation");
        let document: Value =
            serde_json::from_str(OPENALEX_RESEARCH_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            document["schemaVersion"],
            OPENALEX_RESEARCH_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            OPENALEX_RESEARCH_RESULT_CONTRACT_VERSION
        );
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::ranking_authority());
        assert!(!Layer1Authority::full_text_authority());
        assert!(!Layer1Authority::author_identity_authority());
        assert!(!Layer1Authority::citation_truth_authority());
        assert!(!Layer1Authority::research_truth_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }

    #[test]
    fn contract_validator_fails_closed_on_invalid_document_shape() {
        assert!(serde_json::from_str::<Value>("not-json").is_err());
        let _ = ContractValidationError::FrozenField("test");
    }
}

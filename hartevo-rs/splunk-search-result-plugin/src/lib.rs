//! Standalone Layer-1 governed Splunk saved-search result plugin.
//!
//! The crate exposes typed status and bounded aggregate projections for one
//! already-running, explicitly scoped job. It never dispatches or mutates a
//! search, accepts arbitrary SPL, retains raw events, resolves credentials,
//! opens native HTTPS, creates a kernel receipt, or adopts an Outcome.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::float_cmp)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionSplunkSearchConsumer, MissionSplunkSearchConsumerError, MissionSplunkSearchResult,
    MissionSplunkSearchResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvSplunkTransport, FixtureSplunkTransport, LoopbackSplunkTransport,
    RecordingSplunkTransport, SplunkHttpMethod, SplunkHttpResponse, SplunkProvider,
    SplunkProviderDefinition, SplunkProviderError, SplunkProviderOperation, SplunkProviderRead,
    SplunkProviderRequest, SplunkTransport, SplunkTransportError,
};
pub use service::{
    SplunkSavedSearchResultService, SplunkSavedSearchResultServiceDefinition,
    SplunkSavedSearchResultServiceError,
};

pub const SPLUNK_SEARCH_RESULT_SCHEMA_VERSION: &str = "hartevo.splunk-search-result/v1";
pub const SPLUNK_SEARCH_RESULT_CONTRACT_VERSION: &str = "splunk-search-result-e1/v1";
pub const SPLUNK_SEARCH_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const SPLUNK_SEARCH_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/splunk-search-result/splunk-search-result.v1.json";
pub const SPLUNK_SEARCH_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/splunk-search-result/splunk-search-result.v1.json");
pub const SPLUNK_SEARCH_RESULT_SERVICE_ID: &str = "hartevo.splunk.search-result";
pub const SPLUNK_SEARCH_RESULT_SERVICE_NAME: &str = "SplunkSavedSearchResultService";
pub const SPLUNK_PROVIDER_ID: &str = "splunk.search.saved-search-result";
pub const SPLUNK_PROVIDER_NAME: &str = "SplunkProvider";
pub const SPLUNK_PROVIDER_VERSION: &str = "1.0.0";
pub const SPLUNK_API_REVISION: &str = "splunk-search-job-read-v1";
pub const MISSION_SPLUNK_SEARCH_CONSUMER_ID: &str = "mission.splunk.search-result";
pub const MISSION_SPLUNK_SEARCH_CONSUMER_NAME: &str = "MissionSplunkSearchConsumer";
pub const SPLUNK_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(SPLUNK_SEARCH_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 deliberately reports no native, first-party, or kernel authority.
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
    pub const fn first_party_evidence() -> bool {
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
    pub const fn effect_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn receipt_authority() -> bool {
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

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        Layer1Authority, MISSION_SPLUNK_SEARCH_CONSUMER_ID, SPLUNK_API_REVISION,
        SPLUNK_PROVIDER_ID, SPLUNK_SEARCH_RESULT_CONTRACT_JSON,
        SPLUNK_SEARCH_RESULT_CONTRACT_VERSION, SPLUNK_SEARCH_RESULT_SCHEMA_VERSION,
        SPLUNK_SEARCH_RESULT_SERVICE_ID, contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value =
            serde_json::from_str(SPLUNK_SEARCH_RESULT_CONTRACT_JSON).expect("Splunk contract JSON");
        assert_eq!(
            document["schemaVersion"],
            SPLUNK_SEARCH_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            SPLUNK_SEARCH_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], SPLUNK_SEARCH_RESULT_SERVICE_ID);
        assert_eq!(document["provider"]["id"], SPLUNK_PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], SPLUNK_API_REVISION);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_SPLUNK_SEARCH_CONSUMER_ID
        );
        for key in [
            "connected",
            "nativeProvider",
            "firstPartyEvidence",
            "kernelTruthAuthority",
            "kernelConsentAuthority",
            "kernelEffectAuthority",
            "kernelReceiptAuthority",
            "kernelVerificationAuthority",
            "kernelOutcomeAuthority",
            "outcomeAdoption",
        ] {
            assert_eq!(document["authority"][key], false, "authority.{key}");
        }
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(
            document["allowlist"]["forbidden"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == "arbitrary_spl"))
        );
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party_evidence());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::consent_authority());
        assert!(!Layer1Authority::effect_authority());
        assert!(!Layer1Authority::receipt_authority());
        assert!(!Layer1Authority::verification_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}

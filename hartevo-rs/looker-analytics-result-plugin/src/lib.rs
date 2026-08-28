//! Standalone Layer-1 governed Looker analytics metadata result plugin.
//!
//! The crate exposes typed read-only seams for [`LookerAnalyticsResultService`],
//! [`LookerProvider`], and [`MissionLookerAnalyticsConsumer`]. It does not
//! resolve credentials, open native HTTPS, run queries, return warehouse rows,
//! mutate dashboards, schedule work, claim causality, or adopt a kernel
//! Outcome/Work Product.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::struct_excessive_bools
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionLookerAnalyticsConsumer, MissionLookerAnalyticsConsumerError,
    MissionLookerAnalyticsResult, MissionLookerAnalyticsResultState, MissionResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvLookerTransport, FakeLookerTransport, FixtureLookerTransport, LookerHttpMethod,
    LookerHttpResponse, LookerProvider, LookerProviderDefinition, LookerProviderError,
    LookerProviderRead, LookerProviderRequest, LookerRequest, LookerResponse, LookerTransport,
    LookerTransportError, LoopbackLookerTransport, RecordingLookerTransport,
};
pub use service::{
    LookerAnalyticsEvidence, LookerAnalyticsResultProposal, LookerAnalyticsResultReceipt,
    LookerAnalyticsResultService, LookerAnalyticsResultServiceDefinition,
    LookerAnalyticsResultServiceError, mutation_forbidden,
};

pub const LOOKER_ANALYTICS_RESULT_SCHEMA_VERSION: &str = "hartevo.looker-analytics-result/v1";
pub const LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION: &str = "EXT-LOOKER-01-L1/v1";
pub const LOOKER_ANALYTICS_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const LOOKER_ANALYTICS_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/looker-analytics-result/looker-analytics-result.v1.json";
pub const LOOKER_ANALYTICS_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/looker-analytics-result/looker-analytics-result.v1.json"
);
pub const LOOKER_ANALYTICS_RESULT_SERVICE_ID: &str = "looker.analytics-result.read";
pub const LOOKER_PROVIDER_ID: &str = "looker.analytics.metadata";
pub const LOOKER_PROVIDER_VERSION: &str = "1.0.0";
pub const LOOKER_PROVIDER_API_REVISION: &str = "looker-api-4.0.26.14-read-metadata";
pub const LOOKER_API_DOCUMENTATION_URL: &str =
    "https://docs.cloud.google.com/looker/docs/reference/looker-api/latest";
pub const MISSION_LOOKER_ANALYTICS_CONSUMER_ID: &str = "mission.looker-analytics-result.consumer";
pub const LOOKER_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LOOKER_LAYER2_GAP: &str = "BLOCKED_ENV: native client-secret resolution, live Looker API transport, durable provider receipts, independent reread, consented dashboard/look/query effects, scheduled delivery, causal attribution, and verified Work Product/Outcome adoption remain Layer 2 gaps";

pub type LookerScope = LookerAnalyticsScope;
pub type LookerScopeSpec = LookerAnalyticsScopeSpec;
pub type LookerDateWindow = DateWindow;
pub type LookerSecretReference = SecretReference;
pub type LookerAnalyticsResult = LookerAnalyticsResultProposal;
pub type LookerProviderRegistration = LookerRegistration;

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(LOOKER_ANALYTICS_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 deliberately reports no native, connected, first-party, kernel,
/// Outcome, or external-write authority.
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
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
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

    use super::*;

    #[test]
    fn contract_is_machine_readable_and_honest_about_layer_one() {
        let document: Value = serde_json::from_str(LOOKER_ANALYTICS_RESULT_CONTRACT_JSON)
            .expect("Looker contract JSON");
        assert_eq!(
            document["schemaVersion"],
            LOOKER_ANALYTICS_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            LOOKER_ANALYTICS_RESULT_SERVICE_ID
        );
        assert_eq!(document["provider"]["id"], LOOKER_PROVIDER_ID);
        assert_eq!(
            document["provider"]["apiRevision"],
            LOOKER_PROVIDER_API_REVISION
        );
        assert_eq!(
            document["provider"]["documentation"],
            LOOKER_API_DOCUMENTATION_URL
        );
        assert_eq!(
            document["consumer"]["id"],
            MISSION_LOOKER_ANALYTICS_CONSUMER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["firstParty"], false);
        assert_eq!(document["authority"]["outcomeAuthority"], false);
        assert_eq!(
            document["provider"]["readAllowlist"]
                .as_array()
                .map(Vec::len),
            Some(9)
        );
        assert!(contract_digest().len() == 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}

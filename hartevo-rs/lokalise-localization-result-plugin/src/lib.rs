//! Standalone Layer-1 governed Lokalise localization-result plugin.
//!
//! The crate exposes bounded, redacted seams for
//! [`LokaliseLocalizationResultService`], [`LokaliseProvider`], and
//! [`MissionLokaliseLocalizationConsumer`]. It never resolves native
//! credentials, mutates Lokalise keys/translations/tasks, downloads translated
//! bytes, publishes OTA bundles, creates kernel receipts, or adopts an Outcome.

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
    MissionLokaliseLocalizationConsumer, MissionLokaliseLocalizationConsumerError,
    MissionLokaliseLocalizationResult, MissionLokaliseLocalizationResultState,
    MissionLokaliseResultState,
};
pub use model::{
    BranchName, BuildId, ConsentScope, Digest, FileId, KeyId, LanguageId, LanguageIso,
    LokaliseBuildStatus, LokaliseBuildSummary, LokaliseCounts, LokaliseEvidenceClassification,
    LokaliseEvidenceDigests, LokaliseEvidenceState, LokaliseFilePayload, LokaliseFileSummary,
    LokaliseHttpMethod, LokaliseLanguage, LokaliseLanguagePayload, LokaliseLanguageSummary,
    LokaliseLocalizationAggregate, LokaliseLocalizationPayload, LokaliseLocalizationResultEvidence,
    LokaliseLocalizationResultProposal, LokaliseLocalizationResultRecommendation,
    LokaliseLocalizationScope, LokaliseLocalizationScopeSpec, LokaliseObservationReceipt,
    LokalisePermission, LokalisePermissionSet, LokaliseProcessPayload, LokaliseProjectPayload,
    LokaliseProjectSummary, LokaliseRateLimitReceipt, LokaliseReadOperation, LokaliseReadReceipt,
    LokaliseReadbackReceipt, LokaliseRecommendationDisposition, LokaliseRegistration,
    LokaliseTaskLanguagePayload, LokaliseTaskPayload, LokaliseTaskStatus, LokaliseTaskSummary,
    LokaliseTranslationPayload, LokaliseTranslationState, LokaliseTranslationSummary, MAX_BUILDS,
    MAX_CURSOR_BYTES, MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE,
    MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS, MAX_TASKS,
    MAX_TRANSLATIONS, Mission, MissionBinding, MissionId, ModelError, ObservationReceipt, Project,
    ProjectBinding, ProjectId, RegistrationRevocationReceipt, RegistrationState, Revision,
    SecretReference, TaskId, TeamId, TranslationId, TransportProvenance, WorkProduct,
    WorkProductBinding, WorkProductId, canonical_digest, sha256_digest,
};
pub use provider::{
    BlockedEnvLokaliseTransport, FixtureLokaliseTransport, LOKALISE_API_HOST, LokaliseApiResponse,
    LokaliseLocalizationResultProvider, LokaliseProvider, LokaliseProviderDefinition,
    LokaliseProviderError, LokaliseProviderRead, LokaliseProviderReadResult,
    LokaliseProviderTransportError, LokaliseRequest, LokaliseResponse, LokaliseTransport,
    LokaliseTransportError, LoopbackLokaliseTransport, RecordingLokaliseTransport,
};
pub use service::{
    LokaliseLocalizationResultService, LokaliseLocalizationResultServiceDefinition,
    LokaliseLocalizationResultServiceError, LokaliseLocalizationService, LokaliseServiceError,
};

pub const LOKALISE_LOCALIZATION_RESULT_SCHEMA_VERSION: &str =
    "hartevo.lokalise-localization-result/v1";
pub const LOKALISE_LOCALIZATION_RESULT_CONTRACT_VERSION: &str =
    "lokalise-localization-result-e1/v1";
pub const LOKALISE_LOCALIZATION_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const LOKALISE_LOCALIZATION_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/lokalise-localization-result/lokalise-localization-result.v1.json";
pub const LOKALISE_LOCALIZATION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/lokalise-localization-result/lokalise-localization-result.v1.json"
);
pub const LOKALISE_LOCALIZATION_RESULT_SERVICE_ID: &str = "lokalise.localization-result";
pub const LOKALISE_PROVIDER_ID: &str = "lokalise.localization-result";
pub const LOKALISE_PROVIDER_VERSION: &str = "1.0.0";
pub const LOKALISE_PROVIDER_API_REVISION: &str = "lokalise-rest-api-v2";
pub const MISSION_LOKALISE_LOCALIZATION_CONSUMER_ID: &str = "mission.lokalise.localization-result";
pub const LOKALISE_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(LOKALISE_LOCALIZATION_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 deliberately reports no native, first-party, connected or kernel
/// authority.
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
        LOKALISE_LOCALIZATION_RESULT_CONTRACT_JSON, LOKALISE_LOCALIZATION_RESULT_CONTRACT_VERSION,
        LOKALISE_LOCALIZATION_RESULT_SCHEMA_VERSION, LOKALISE_LOCALIZATION_RESULT_SERVICE_ID,
        LOKALISE_PROVIDER_API_REVISION, LOKALISE_PROVIDER_ID, Layer1Authority,
        MISSION_LOKALISE_LOCALIZATION_CONSUMER_ID, contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value = serde_json::from_str(LOKALISE_LOCALIZATION_RESULT_CONTRACT_JSON)
            .expect("Lokalise contract JSON");
        assert_eq!(
            document["schemaVersion"],
            LOKALISE_LOCALIZATION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            LOKALISE_LOCALIZATION_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            LOKALISE_LOCALIZATION_RESULT_SERVICE_ID
        );
        assert_eq!(document["provider"]["id"], LOKALISE_PROVIDER_ID);
        assert_eq!(
            document["provider"]["apiRevision"],
            LOKALISE_PROVIDER_API_REVISION
        );
        assert_eq!(
            document["consumer"]["id"],
            MISSION_LOKALISE_LOCALIZATION_CONSUMER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["firstParty"], false);
        assert_eq!(document["authority"]["externalWrites"], false);
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(document["provider"]["maxPageSize"], 100);
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}

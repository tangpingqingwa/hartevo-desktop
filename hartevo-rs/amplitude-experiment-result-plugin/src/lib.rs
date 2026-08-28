//! Standalone Layer-1 Amplitude experiment-result evidence plugin.
//!
//! The crate exposes three typed seams: [`AmplitudeExperimentResultService`],
//! [`AmplitudeProvider`], and [`MissionAmplitudeExperimentConsumer`]. It is a
//! bounded read/proposal/recording seam for saved Amplitude experiment-result
//! charts. It never resolves native credentials, sends an Amplitude mutation,
//! exports arbitrary events, retains raw user identifiers, creates a kernel
//! receipt, or adopts a Mission Outcome.

#![forbid(unsafe_code)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::float_cmp)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionAmplitudeExperimentConsumer, MissionAmplitudeExperimentConsumerError,
    MissionExperimentResultProjection,
};
pub use model::{
    AmplitudeApiDefinition, AmplitudeCapability, AmplitudeEffectIntent, AmplitudeEffectReceipt,
    AmplitudeEffectReceiptStatus, AmplitudeExperimentResultProposal, AmplitudeExperimentResultRead,
    AmplitudeExperimentScope, AmplitudeExperimentScopeSpec, AmplitudeMetricPage,
    AmplitudeMetricResult, AmplitudePermission, AmplitudePermissionSnapshot, AmplitudeReadConsent,
    AmplitudeReadbackReceipt, AmplitudeRegion, AmplitudeRegistration, AmplitudeRegistrationState,
    AmplitudeResultError, AmplitudeResultEvidence, AmplitudeResultPage, AmplitudeResultProjection,
    AmplitudeResultState, AmplitudeTransportError, AmplitudeVariantPage, AmplitudeVariantResult,
    ConfidenceMetadata, DecisionMetadata, Digest, EvidenceClassification, ExperimentBinding,
    ExposureWindow, FreshnessReceipt, IdentityBinding, MAX_CONFIDENCE_METADATA,
    MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES, MAX_METRICS, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_SEGMENTS, MAX_VARIANTS, MetricDefinition, MetricDirection,
    MissionBinding, PluginVersion, ProjectBinding, ProviderDecision, ProviderDecisionState,
    ReadReceipt, ReadbackStatus, RecordingReceipt, RegistrationRevocationReceipt, ResponseReceipt,
    ResultRecommendation, ResultRecommendationDisposition, SecretKind, SecretReference,
    SegmentBinding, TransportProvenance, TransportStatus, VariantBinding, WorkProductBinding,
    canonical_digest, sha256_digest,
};
pub use provider::{
    AmplitudeHttpMethod, AmplitudeHttpRequest, AmplitudeHttpResponse, AmplitudeProvider,
    AmplitudeProviderRead, AmplitudeTransport, BlockedEnvAmplitudeTransport,
    FakeAmplitudeTransport, FixtureAmplitudeTransport, LoopbackAmplitudeTransport,
    RecordedAmplitudeTransport,
};
pub use service::AmplitudeExperimentResultService;

pub const AMPLITUDE_EXPERIMENT_RESULT_SCHEMA_VERSION: &str =
    "hartevo.amplitude-experiment-result/v1";
pub const AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_VERSION: &str = "amplitude-experiment-result-e1/v1";
pub const AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/amplitude-experiment-result/amplitude-experiment-result.v1.json";
pub const AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/amplitude-experiment-result/amplitude-experiment-result.v1.json"
);
pub const AMPLITUDE_EXPERIMENT_RESULT_PLUGIN_ID: &str = "amplitude-experiment-result";
pub const AMPLITUDE_EXPERIMENT_RESULT_SERVICE_ID: &str = "amplitude.experiment-result";
pub const AMPLITUDE_EXPERIMENT_RESULT_SERVICE_NAME: &str = "AmplitudeExperimentResultService";
pub const AMPLITUDE_PROVIDER_ID: &str = "amplitude.experiment-result";
pub const AMPLITUDE_PROVIDER_NAME: &str = "AmplitudeProvider";
pub const MISSION_AMPLITUDE_EXPERIMENT_CONSUMER_ID: &str = "mission.amplitude-experiment-result";
pub const MISSION_AMPLITUDE_EXPERIMENT_CONSUMER_NAME: &str = "MissionAmplitudeExperimentConsumer";
pub const AMPLITUDE_PROVIDER_REVISION: &str = "amplitude-experiment-result-provider-v1";
pub const AMPLITUDE_DASHBOARD_REST_REVISION: &str = "amplitude-dashboard-rest-v1";
pub const AMPLITUDE_EXPERIMENT_RESULT_CAPABILITY: &str = "amplitude.experiment-result.read";

/// Returns the lowercase SHA-256 digest of the checked-in contract.
#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_JSON.as_bytes())
}

/// Returns the plugin version bound into registrations.
#[must_use]
pub const fn plugin_version() -> PluginVersion {
    PluginVersion::V1
}

/// Layer-1 authority is intentionally false for every native or kernel claim.
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
    pub const fn durable_native_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_JSON, AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_VERSION,
        AMPLITUDE_EXPERIMENT_RESULT_SCHEMA_VERSION, AMPLITUDE_EXPERIMENT_RESULT_SERVICE_ID,
        AMPLITUDE_EXPERIMENT_RESULT_SERVICE_NAME, AMPLITUDE_PROVIDER_ID, AMPLITUDE_PROVIDER_NAME,
        Layer1Authority, MISSION_AMPLITUDE_EXPERIMENT_CONSUMER_ID,
        MISSION_AMPLITUDE_EXPERIMENT_CONSUMER_NAME,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value = serde_json::from_str(AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_JSON)
            .expect("Amplitude experiment-result contract JSON");
        assert_eq!(
            document["schemaVersion"],
            AMPLITUDE_EXPERIMENT_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            AMPLITUDE_EXPERIMENT_RESULT_SERVICE_ID
        );
        assert_eq!(
            document["service"]["name"],
            AMPLITUDE_EXPERIMENT_RESULT_SERVICE_NAME
        );
        assert_eq!(document["provider"]["id"], AMPLITUDE_PROVIDER_ID);
        assert_eq!(document["provider"]["name"], AMPLITUDE_PROVIDER_NAME);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_AMPLITUDE_EXPERIMENT_CONSUMER_ID
        );
        assert_eq!(
            document["consumer"]["name"],
            MISSION_AMPLITUDE_EXPERIMENT_CONSUMER_NAME
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["genericAnalyticsEngine"], false);
        assert_eq!(document["authority"]["kernelAuthority"], false);
        assert_eq!(document["authority"]["outcomeAdoption"], false);
        assert_eq!(document["authentication"]["rawCredentialSerialized"], false);
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_native_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_adoption());
    }

    #[test]
    fn contract_keeps_experiment_result_distinct_from_neighboring_evidence() {
        let document: Value = serde_json::from_str(AMPLITUDE_EXPERIMENT_RESULT_CONTRACT_JSON)
            .expect("Amplitude experiment-result contract JSON");
        assert_eq!(document["distinction"]["notPostHogOutcome"], true);
        assert_eq!(document["distinction"]["notLaunchDarklyFlagEvidence"], true);
        assert_eq!(document["distinction"]["notSentryRuntimeEvidence"], true);
        assert_eq!(document["distinction"]["notDatadogSloEvidence"], true);
        assert_eq!(document["normalization"]["emptyIsSuccess"], false);
    }
}

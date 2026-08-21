//! Layer-1 governed MLflow experiment and evaluation-result evidence.
//!
//! This crate is intentionally standalone. It exposes a typed, bounded read
//! proposal service, a provider seam for fixture/recording/loopback/
//! `BLOCKED_ENV` provenance, and a Mission consumer that carries redacted
//! evidence into a later decision. It never performs native MLflow I/O, logs
//! or mutates runs, downloads artifacts, mutates the model registry, exposes a
//! dashboard, or claims Connected, Truth, Outcome, or kernel authority.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod filter;
mod model;
mod provider;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    ConsumerError, ConsumerRegistration, MissionMlflowEvaluationConsumer,
    MissionMlflowEvaluationResult, MissionMlflowResultState,
};
pub use filter::{
    FilterClause, FilterCompileError, FilterField, FilterOperator, FilterValue, MlflowFilter,
};
pub use model::{
    AdoptionAvailability, DatasetDigest, DatasetReference, Digest, ErrorSeverity, EvidenceDigests,
    ExperimentId, ExperimentLifecycle, ExperimentRecord, LiveRevocationFence, MetricHistoryPoint,
    MetricKey, MetricValue, MissionId, MlflowAuthKind, MlflowAuthority, MlflowOperation,
    MlflowRegistration, MlflowScope, ModelError, OpaquePageToken, ParamKey, PartialReason,
    PermissionFence, ProjectId, ProviderErrorEvidence, ProviderErrorKind, ProviderId,
    ProviderProvenance, RedactedAttribute, RegistrationRevocation, RegistrationState, ResultBounds,
    ResultStatus, Revision, RunId, RunRecord, RunStatus, ScopeRevisions, SecretReference,
    ServiceId, TagKey, WorkProductId,
};
pub use provider::{
    BlockedEnvMlflowProvider, FakeMlflowProvider, FixtureMlflowProvider, LoopbackMlflowProvider,
    MlflowProvider, MlflowProviderDefinition, MlflowResponsePage, ProviderCall,
    ProviderDefinitionError, RecordingMlflowProvider, TransportError,
};
pub use service::{
    MlflowEvaluationResultService, MlflowEvidence, MlflowReadProposal, MlflowReadRequest,
    MlflowResultProposal, MlflowServiceDefinition, RetryPolicy, ServiceError,
};

pub const MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION: &str =
    "hartevo-mlflow-evaluation-result-contract/v1";
pub const MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION: &str = "mlflow-evaluation-result-e1/v1";
pub const MLFLOW_EVALUATION_RESULT_SERVICE_VERSION: &str = "1.0.0";
pub const MLFLOW_EVALUATION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/mlflow-evaluation-result/mlflow-evaluation-result.v1.json"
);
pub const MLFLOW_EVALUATION_RESULT_SERVICE_ID: &str = "mlflow.evaluation.result";
pub const MLFLOW_EVALUATION_RESULT_PROVIDER_ID: &str = "mlflow.tracking.read";
pub const MLFLOW_EVALUATION_RESULT_CONSUMER_ID: &str = "mission.mlflow.evaluation.result.consumer";
pub const MLFLOW_EVALUATION_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const MLFLOW_EVALUATION_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        MLFLOW_EVALUATION_RESULT_BLOCKED_ENV, MLFLOW_EVALUATION_RESULT_CONSUMER_ID,
        MLFLOW_EVALUATION_RESULT_CONTRACT_JSON, MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION,
        MLFLOW_EVALUATION_RESULT_EVIDENCE_LEVEL, MLFLOW_EVALUATION_RESULT_PROVIDER_ID,
        MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION, MLFLOW_EVALUATION_RESULT_SERVICE_ID,
        MLFLOW_EVALUATION_RESULT_SERVICE_VERSION,
    };

    #[test]
    fn contract_document_is_versioned_bounded_and_honest() {
        let document = serde_json::from_str::<Value>(MLFLOW_EVALUATION_RESULT_CONTRACT_JSON)
            .expect("MLflow contract JSON");
        assert_eq!(
            document["schemaVersion"],
            MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            document["evidenceLevel"],
            MLFLOW_EVALUATION_RESULT_EVIDENCE_LEVEL
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            MLFLOW_EVALUATION_RESULT_SERVICE_ID
        );
        assert_eq!(
            document["service"]["version"],
            MLFLOW_EVALUATION_RESULT_SERVICE_VERSION
        );
        assert!(document["service"]["readOnly"].as_bool().unwrap_or(false));
        assert!(
            !document["service"]["liveExecution"]
                .as_bool()
                .unwrap_or(true)
        );
        assert_eq!(
            document["provider"]["id"],
            MLFLOW_EVALUATION_RESULT_PROVIDER_ID
        );
        assert!(!document["provider"]["native"].as_bool().unwrap_or(true));
        assert_eq!(
            document["consumer"]["id"],
            MLFLOW_EVALUATION_RESULT_CONSUMER_ID
        );
        assert!(
            !document["consumer"]["adoptsOutcome"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !document["consumer"]["truthAuthority"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !document["nativeClaims"]["connected"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !document["nativeClaims"]["nativeProvider"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !document["nativeClaims"]["durableReceipt"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !document["nativeClaims"]["adoptedOutcome"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !document["nativeClaims"]["truthAuthority"]
                .as_bool()
                .unwrap_or(true)
        );
        assert_eq!(
            document["service"]["exactCardinality"]["getRun"],
            "exactly_one_expected_identity"
        );
        assert_eq!(
            document["registration"]["revocationFence"],
            "live_monotonic_generation_in_memory_only"
        );
        assert!(
            !document["registration"]["restartDurable"]
                .as_bool()
                .unwrap_or(true)
        );
        let accepted_provenance = document["provider"]["acceptedProvenance"]
            .as_array()
            .expect("provenance list");
        for provenance in ["fixture", "recording", "loopback", "blocked_env"] {
            assert!(accepted_provenance.iter().any(|value| value == provenance));
        }
        let denied = document["queryPolicy"]["deny"]
            .as_array()
            .expect("deny list");
        for operation in [
            "run_creation",
            "run_update",
            "run_delete",
            "metric_logging",
            "param_logging",
            "tag_logging",
            "artifact_download",
            "model_registry_mutation",
            "dashboard_authority",
            "kernel_truth_authority",
            "outcome_adoption",
        ] {
            assert!(denied.iter().any(|value| value == operation));
        }
        assert_eq!(
            document["states"],
            serde_json::json!([
                "complete",
                "stale",
                "partial",
                "access_loss",
                "provider_unknown",
                "final_error"
            ])
        );
        assert_eq!(MLFLOW_EVALUATION_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
    }
}

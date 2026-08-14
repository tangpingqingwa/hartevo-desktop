//! Standalone Layer-1 Qualtrics survey-feedback result plugin.
//!
//! The crate exposes typed, bounded, read-only evidence proposals. It has no
//! native HTTP client, credential resolver, survey mutation, response import,
//! export-file download, Connected claim, kernel receipt, or Outcome authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::return_self_not_must_use,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

use thiserror::Error;

pub use consumer::{
    AdoptionAvailability, ConsumerError, MissionQualtricsSurveyConsumer,
    MissionQualtricsSurveyResult,
};
pub use model::{
    AnswerPage, BoundedAnswer, BoundedNumeric, ChoiceId, ConsentId, ConsentScope, ConsentStatus,
    ConsumerId, DatacenterId, Digest, DistributionId, DivisionId, ExportProgressState, MissionId,
    ModelError, OpaqueExportReference, OpaquePageToken, OrganizationId, ProjectId,
    QualtricsPayload, QualtricsResultBounds, QualtricsScope, QuestionId, QuestionKind,
    QuestionMetadata, RegistrationState, ResponseExportProgress, ResponseId, ResponseMetadata,
    ResponseStatus, ResponseStatusEvidence, Revision, SecretReference, ServiceId, SurveyAnswer,
    SurveyId, SurveyLifecycle, SurveyMetadata,
};
pub use provider::{
    BlockedEnvTransport, FixtureQualtricsTransport, FixtureTransport, LoopbackQualtricsTransport,
    LoopbackTransport, ProviderDefinitionError, ProviderObservation, ProviderProvenance,
    QualtricsGetRequest, QualtricsGetTransport, QualtricsProvider, QualtricsProviderDefinition,
    QualtricsProviderError, QualtricsProviderProvenance, QualtricsReadOperation,
    QualtricsReadReceipt, QualtricsRequestReceipt, QualtricsResponseReceipt,
    QualtricsRetryEvidence, QualtricsTransportError, QualtricsTransportResponse,
    RecordingQualtricsTransport, RecordingTransport, TransportError,
};
pub use service::{
    MissionResultState, PartialReason, QualtricsAuthority, QualtricsRegistration,
    QualtricsRegistrationError, QualtricsResultState, QualtricsServiceError,
    QualtricsSurveyResultEvidence, QualtricsSurveyResultProposal, QualtricsSurveyResultRequest,
    QualtricsSurveyResultService, ResultProjection,
};

pub const QUALTRICS_SURVEY_RESULT_SCHEMA_VERSION: &str =
    "hartevo.qualtrics-survey-result-contract/v1";
pub const QUALTRICS_SURVEY_RESULT_CONTRACT_VERSION: &str = "qualtrics-survey-result/v1";
pub const QUALTRICS_SURVEY_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const QUALTRICS_API_VERSION: &str = "v3";
pub const QUALTRICS_PROVIDER_REVISION: &str = "qualtrics-rest-v3-r1";
pub const QUALTRICS_PROVIDER_ID: &str = "qualtrics.rest";
pub const QUALTRICS_PROVIDER_NAME: &str = "QualtricsProvider";
pub const QUALTRICS_SURVEY_RESULT_PROVIDER_ID: &str = QUALTRICS_PROVIDER_ID;
pub const QUALTRICS_SURVEY_RESULT_SERVICE_ID: &str = "qualtrics.survey-result";
pub const QUALTRICS_SURVEY_RESULT_SERVICE_NAME: &str = "QualtricsSurveyResultService";
pub const MISSION_QUALTRICS_SURVEY_CONSUMER_ID: &str = "mission.qualtrics-survey-result";
pub const MISSION_QUALTRICS_SURVEY_CONSUMER_NAME: &str = "MissionQualtricsSurveyConsumer";
pub const QUALTRICS_SURVEY_RESULT_CONSUMER_ID: &str = MISSION_QUALTRICS_SURVEY_CONSUMER_ID;
pub const QUALTRICS_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const QUALTRICS_SURVEY_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/qualtrics-survey-result/qualtrics-survey-result.v1.json"
);

/// Layer 1's authority is intentionally all-false. It returns evidence for a
/// later host decision; it is not a Connected/native provider or Truth source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualtricsSurveyResultContract {
    document: serde_json::Value,
}

impl QualtricsSurveyResultContract {
    pub fn baseline() -> Result<Self, ContractError> {
        validate_contract()?;
        let document = serde_json::from_str(QUALTRICS_SURVEY_RESULT_CONTRACT_JSON)
            .map_err(|_| ContractError::InvalidJson)?;
        Ok(Self { document })
    }

    pub fn document(&self) -> &serde_json::Value {
        &self.document
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    #[error("Qualtrics contract JSON is invalid")]
    InvalidJson,
    #[error("Qualtrics contract is missing a required Layer-1 boundary")]
    InvalidBoundary,
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(QUALTRICS_SURVEY_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn contract_json() -> &'static str {
    QUALTRICS_SURVEY_RESULT_CONTRACT_JSON
}

pub fn validate_contract() -> Result<(), ContractError> {
    if !model::expected_service_ids_are_stable() {
        return Err(ContractError::InvalidBoundary);
    }
    let document: serde_json::Value = serde_json::from_str(QUALTRICS_SURVEY_RESULT_CONTRACT_JSON)
        .map_err(|_| ContractError::InvalidJson)?;
    let object = document.as_object().ok_or(ContractError::InvalidBoundary)?;
    let string_const = |key: &str, expected: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == expected)
    };
    let bool_at = |path: &[&str], expected: bool| {
        path.iter()
            .try_fold(&document, |value, key| value.get(*key))
            .and_then(serde_json::Value::as_bool)
            .is_some_and(|value| value == expected)
    };
    let array_contains_all = |path: &[&str], expected: &[&str]| {
        let Some(array) = path
            .iter()
            .try_fold(&document, |value, key| value.get(*key))
            .and_then(serde_json::Value::as_array)
        else {
            return false;
        };
        expected.iter().all(|item| {
            array
                .iter()
                .any(|value| value.as_str().is_some_and(|candidate| candidate == *item))
        })
    };
    if !string_const("schemaVersion", QUALTRICS_SURVEY_RESULT_SCHEMA_VERSION)
        || !string_const("contractVersion", QUALTRICS_SURVEY_RESULT_CONTRACT_VERSION)
        || !string_const("pluginVersion", QUALTRICS_SURVEY_RESULT_PLUGIN_VERSION)
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
        || !bool_at(&["service", "readOnly"], true)
        || !bool_at(&["service", "liveExecution"], false)
        || !bool_at(&["service", "proposalOnly"], true)
        || !bool_at(&["provider", "native"], false)
        || !bool_at(&["provider", "connected"], false)
        || !bool_at(&["provider", "externalWrites"], false)
        || !bool_at(&["consumer", "adoptsOutcome"], false)
        || !bool_at(&["consumer", "truthAuthority"], false)
        || !bool_at(&["getAllowlist", "arbitraryQuery"], false)
        || !bool_at(&["getAllowlist", "postPutPatchDelete"], false)
        || !bool_at(&["getAllowlist", "exportStart"], false)
        || !bool_at(&["getAllowlist", "exportFileDownload"], false)
        || !bool_at(&["redaction", "secretReferenceOpaque"], true)
        || !bool_at(&["redaction", "rawApiTokenSerialized"], false)
        || !bool_at(&["redaction", "rawFreeTextSerialized"], false)
        || !bool_at(&["redaction", "rawPiiSerialized"], false)
        || !bool_at(&["redaction", "rawExportBytesSerialized"], false)
        || !bool_at(&["nativeGap", "blockedEnvironmentIsNative"], false)
        || !array_contains_all(
            &["provider", "transportProvenance"],
            &["recording", "fixture", "loopback", "BLOCKED_ENV"],
        )
        || !array_contains_all(
            &["projections", "states"],
            &[
                "completed",
                "in_progress",
                "partial",
                "expired",
                "consent_blocked",
                "access_lost",
                "provider_unknown",
            ],
        )
        || !array_contains_all(&["answers", "allow"], &["numeric", "choice"])
        || !array_contains_all(
            &["answers", "deny"],
            &[
                "free_text",
                "name",
                "email",
                "location",
                "respondent_identity",
            ],
        )
    {
        return Err(ContractError::InvalidBoundary);
    }
    Ok(())
}

pub fn validate_contract_document() -> Result<(), ContractError> {
    validate_contract()
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_valid_and_layer_one_is_honest() {
        let contract = QualtricsSurveyResultContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(contract.document()["layer"], 1);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::external_writes());
    }
}

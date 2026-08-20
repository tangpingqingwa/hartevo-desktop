//! Standalone Layer-1 governed AWS Health event result plugin.
//!
//! The crate prepares bounded, typed evidence and proposal seams for
//! `DescribeEvents`, `DescribeEventDetails`, and `DescribeAffectedEntities`.
//! It never resolves a native SigV4 credential, calls AWS, retains raw event
//! descriptions or metadata maps, exposes raw entity identifiers, claims
//! outage causality, adopts a kernel Outcome, or reports operational Truth.

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
    MissionAwsHealthConsumer, MissionAwsHealthConsumerError, MissionAwsHealthResult,
    MissionAwsHealthResultState, MissionResultState,
};
pub use model::*;
pub use provider::{
    AwsHealthProvider, AwsHealthProviderDefinition, AwsHealthProviderError, AwsHealthProviderRead,
    AwsHealthTransport, BlockedEnvAwsHealthTransport, DescribeAffectedEntitiesRequest,
    DescribeAffectedEntitiesResponse, DescribeEventDetailsRequest, DescribeEventDetailsResponse,
    DescribeEventsRequest, DescribeEventsResponse, FixtureAwsHealthTransport,
    LoopbackAwsHealthTransport, ProviderDefinitionError, ProviderProvenance,
    RecordingAwsHealthTransport, TransportCall, TransportError,
};
pub use service::{
    AwsHealthEventProposal, AwsHealthEventService, AwsHealthEventServiceDefinition,
    AwsHealthEventServiceError, AwsHealthObservationReceipt, AwsHealthReadbackReceipt,
};

pub const AWS_HEALTH_EVENT_RESULT_SCHEMA_VERSION: &str = "hartevo.aws-health-event-result/v1";
pub const AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION: &str = "aws-health-event-result-e1/v1";
pub const AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const AWS_HEALTH_EVENT_RESULT_SERVICE_ID: &str = "aws.health.event.result";
pub const AWS_HEALTH_EVENT_RESULT_PROVIDER_ID: &str = "aws.health.events";
pub const AWS_HEALTH_EVENT_RESULT_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_HEALTH_EVENT_RESULT_API_REVISION: &str = "aws-health-api-2016-08-04";
pub const AWS_HEALTH_EVENT_RESULT_CONSUMER_ID: &str = "mission.aws-health.event.result";
pub const AWS_HEALTH_EVENT_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/aws-health-event-result/aws-health-event-result.v1.json";
pub const AWS_HEALTH_EVENT_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-health-event-result/aws-health-event-result.v1.json"
);
pub const AWS_HEALTH_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[must_use]
pub fn plugin_version() -> &'static str {
    AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION
}

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_HEALTH_EVENT_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 intentionally exposes no native or kernel authority.
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
    pub const fn outage_causality() -> bool {
        false
    }

    #[must_use]
    pub const fn operational_truth() -> bool {
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
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validates the checked-in contract's identity, operations and authority
/// boundary. This is a contract check, not a JSON Schema network lookup.
#[allow(clippy::too_many_lines)]
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let contract: serde_json::Value =
        serde_json::from_str(AWS_HEALTH_EVENT_RESULT_CONTRACT_JSON)
            .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let require = |path: &'static str, condition: bool| {
        if condition {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(path))
        }
    };

    require(
        "schemaVersion",
        contract["schemaVersion"] == AWS_HEALTH_EVENT_RESULT_SCHEMA_VERSION,
    )?;
    require(
        "contractVersion",
        contract["contractVersion"] == AWS_HEALTH_EVENT_RESULT_CONTRACT_VERSION,
    )?;
    require(
        "pluginVersion",
        contract["pluginVersion"] == AWS_HEALTH_EVENT_RESULT_PLUGIN_VERSION,
    )?;
    require("layer", contract["layer"] == 1)?;
    require(
        "service.id",
        contract["service"]["id"] == AWS_HEALTH_EVENT_RESULT_SERVICE_ID,
    )?;
    require(
        "provider.id",
        contract["provider"]["id"] == AWS_HEALTH_EVENT_RESULT_PROVIDER_ID,
    )?;
    require(
        "consumer.id",
        contract["typedSurface"]["consumer"] == "MissionAwsHealthConsumer",
    )?;
    require(
        "service.operations",
        contract["service"]["operations"]
            == serde_json::json!([
                "describe_events",
                "describe_event_details",
                "describe_affected_entities",
                "compile_proposal",
                "record_observation",
                "verify_proposal",
                "revoke_registration",
                "restore_registration"
            ]),
    )?;
    require(
        "provider.operations",
        contract["provider"]["operations"]
            == serde_json::json!([
                "DescribeEvents",
                "DescribeEventDetails",
                "DescribeAffectedEntities"
            ]),
    )?;
    require(
        "provider.transportProvenance",
        contract["provider"]["transportProvenance"]
            == serde_json::json!(["fixture", "recording", "loopback", "BLOCKED_ENV"]),
    )?;
    require("provider.native", contract["provider"]["native"] == false)?;
    require(
        "provider.connected",
        contract["provider"]["connected"] == false,
    )?;
    require(
        "authority.outageCausality",
        contract["authority"]["outageCausality"] == false,
    )?;
    require(
        "authority.operationalTruth",
        contract["authority"]["operationalTruth"] == false,
    )?;
    require(
        "authority.externalWrites",
        contract["authority"]["externalWrites"] == false,
    )?;
    require(
        "nativeClaims.blockedEnvironmentIsNative",
        contract["nativeClaims"]["blockedEnvironmentIsNative"] == false,
    )?;
    require(
        "evidence.partialFailure",
        contract["evidence"]["partialFailure"] == "fail_closed",
    )?;
    require(
        "evidence.entityRetention",
        contract["bounds"]["entityRetention"] == "digest_only",
    )?;
    require(
        "registration.eventFilterDigestBound",
        contract["registration"]["eventFilterDigestBound"] == true,
    )?;
    require(
        "registration.evidencePolicyDigestBound",
        contract["registration"]["evidencePolicyDigestBound"] == true,
    )?;
    require(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    require(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_valid_and_layer_one_is_honest() {
        validate_contract().expect("AWS Health contract validates");
        assert_eq!(plugin_version(), "0.1.0");
        assert_eq!(contract_digest(), contract_digest());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::outage_causality());
        assert!(!Layer1Authority::operational_truth());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
    }
}

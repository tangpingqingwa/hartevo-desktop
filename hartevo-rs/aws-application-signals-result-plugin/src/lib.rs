//! Standalone Layer-1 AWS Application Signals result plugin.
//!
//! The crate owns a typed, bounded, read-only seam for Application Signals
//! service and SLO list/get observations. It deliberately stops at normalized
//! proposal/record/verify evidence. No code in this crate resolves credentials,
//! performs native SigV4, exports telemetry, pages alerts, writes SLO/metric
//! state, makes causal claims, or adopts a kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, MissionAwsApplicationSignalsConsumer, MissionAwsApplicationSignalsResult,
};
pub use model::*;
pub use provider::{
    AwsApplicationSignalsProvider, AwsApplicationSignalsProviderDefinition,
    AwsApplicationSignalsReadRecord, AwsApplicationSignalsReadRequest,
    AwsApplicationSignalsRecordPage, AwsApplicationSignalsTransport,
    AwsApplicationSignalsTransportError, BlockedEnvAwsApplicationSignalsTransport,
    BlockedEnvTransport, FixtureAwsApplicationSignalsTransport, GetServiceLevelObjectiveRequest,
    GetServiceLevelObjectiveResponse, GetServiceRequest, GetServiceResponse,
    ListServiceLevelObjectivesPage, ListServiceLevelObjectivesRequest, ListServicesPage,
    ListServicesRequest, LoopbackAwsApplicationSignalsTransport, ProviderError, ProviderProvenance,
    RecordingAwsApplicationSignalsTransport, TransportCall, TransportError, TransportFailure,
};
pub use service::{
    AuthorityBoundary, AwsApplicationSignalsEvidence, AwsApplicationSignalsProposal,
    AwsApplicationSignalsReadResult, AwsApplicationSignalsReceipt, AwsApplicationSignalsService,
    ContractDocumentError, EvidenceVerification, PaginationEvidence, ServiceDefinition,
    ServiceError,
};

pub const AWS_APPLICATION_SIGNALS_SCHEMA_VERSION: &str =
    "hartevo-aws-application-signals-result-contract/v1";
pub const AWS_APPLICATION_SIGNALS_CONTRACT_VERSION: &str = "aws-application-signals-result-e1/v1";
pub const AWS_APPLICATION_SIGNALS_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AWS_APPLICATION_SIGNALS_API_VERSION: &str = "2020-07-22";
pub const AWS_APPLICATION_SIGNALS_PROVIDER_REVISION: &str = "aws-application-signals-2020-07-22-r1";
pub const AWS_APPLICATION_SIGNALS_PLUGIN_ID: &str = "aws-application-signals-result";
pub const AWS_APPLICATION_SIGNALS_SERVICE_ID: &str = "aws.application-signals.result";
pub const AWS_APPLICATION_SIGNALS_PROVIDER_ID: &str = "aws.application-signals.read";
pub const MISSION_AWS_APPLICATION_SIGNALS_CONSUMER_ID: &str =
    "mission.aws-application-signals-result";
pub const AWS_APPLICATION_SIGNALS_SERVICE_NAME: &str = "AwsApplicationSignalsService";
pub const AWS_APPLICATION_SIGNALS_PROVIDER_NAME: &str = "AwsApplicationSignalsProvider";
pub const MISSION_AWS_APPLICATION_SIGNALS_CONSUMER_NAME: &str =
    "MissionAwsApplicationSignalsConsumer";
pub const AWS_APPLICATION_SIGNALS_SERVICE_SCHEMA: &str =
    "hartevo.aws-application-signals-service/v1";
pub const AWS_APPLICATION_SIGNALS_PROVIDER_SCHEMA: &str =
    "hartevo.aws-application-signals-provider/v1";
pub const MISSION_AWS_APPLICATION_SIGNALS_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-application-signals-result-consumer/v1";
pub const AWS_APPLICATION_SIGNALS_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const AWS_APPLICATION_SIGNALS_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-application-signals-result/aws-application-signals-result.v1.json"
);

/// SHA-256 of the exact checked-in contract bytes.
#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_APPLICATION_SIGNALS_CONTRACT_JSON.as_bytes())
}

/// The plugin version used by registration and proposal fences.
#[must_use]
pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Layer-1 authority is intentionally false for every native/authority claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn live_credential_resolution() -> bool {
        false
    }

    pub const fn durable_request_receipt() -> bool {
        false
    }

    pub const fn cost_receipt() -> bool {
        false
    }

    pub const fn independent_closed_window_readback() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
        false
    }
}

/// Validate immutable identity and authority claims in the machine contract.
pub fn validate_contract_document() -> Result<(), ContractDocumentError> {
    let value: serde_json::Value = serde_json::from_str(AWS_APPLICATION_SIGNALS_CONTRACT_JSON)
        .map_err(|error| ContractDocumentError::InvalidJson(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| ContractDocumentError::Invalid("root is not an object".to_owned()))?;
    let string_field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ContractDocumentError::Invalid(format!("missing {name}")))
    };
    if string_field("schemaVersion")? != AWS_APPLICATION_SIGNALS_SCHEMA_VERSION
        || string_field("contractVersion")? != AWS_APPLICATION_SIGNALS_CONTRACT_VERSION
    {
        return Err(ContractDocumentError::Invalid(
            "contract identity drifted".to_owned(),
        ));
    }
    if object.get("layer").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(ContractDocumentError::Invalid(
            "contract layer is not 1".to_owned(),
        ));
    }
    let authority = object
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| ContractDocumentError::Invalid("missing authority".to_owned()))?;
    for field in [
        "connected",
        "nativeProvider",
        "liveCredentialResolution",
        "rawProviderPayload",
        "rawSecretMaterial",
        "telemetryExport",
        "sloWrites",
        "metricWrites",
        "alertPaging",
        "causalClaims",
        "durableRequestReceipt",
        "costReceipt",
        "independentClosedWindowReadback",
        "outcomeAuthority",
        "workProductAdoption",
    ] {
        if authority.get(field).and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(ContractDocumentError::Invalid(format!(
                "authority.{field} must be false"
            )));
        }
    }
    Ok(())
}

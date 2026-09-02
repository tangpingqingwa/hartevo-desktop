//! Layer-1 governed Samsara fleet-operations result plugin.
//!
//! This crate is intentionally standalone and local-first. It describes a
//! bounded read proposal and consumes only recording, fixture, loopback, or
//! `BLOCKED_ENV` evidence. It never resolves a native secret, performs live
//! HTTP, claims Connected/native authority, retains raw provider payloads,
//! issues fleet effects, or adopts a kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]

use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, ConsumerRegistration, MissionResultState, MissionSamsaraFleetConsumer,
    MissionSamsaraFleetResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, LoopbackTransport, ProviderDefinitionError, ProviderProvenance,
    RecordingSamsaraTransport, ResponseReceipt, SamsaraEndpoint, SamsaraEndpointKind,
    SamsaraHttpRequest, SamsaraHttpResponse, SamsaraProvider, SamsaraProviderDefinition,
    SamsaraReadOptions, SamsaraReadResponse, SamsaraResponseBody, SamsaraTransport, TransportError,
    TransportErrorKind,
};
pub use service::{
    RegistrationRevocation, SamsaraAuthorityEvidence, SamsaraFleetResultEvidence,
    SamsaraFleetResultProposal, SamsaraFleetResultRequest, SamsaraFleetResultService,
    SamsaraFleetResultServiceDefinition, SamsaraProviderErrorEvidence, SamsaraRegistration,
    SamsaraRetryEvidence, ServiceError,
};

pub const SAMSARA_FLEET_RESULT_SCHEMA_VERSION: &str = "hartevo.samsara-fleet-result-contract/v1";
pub const SAMSARA_FLEET_RESULT_CONTRACT_VERSION: &str = "samsara-fleet-result/v1";
pub const SAMSARA_FLEET_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const SAMSARA_FLEET_RESULT_SERVICE_ID: &str = "hartevo.samsara.fleet.result";
pub const SAMSARA_FLEET_RESULT_PROVIDER_ID: &str = "samsara.fleet";
pub const SAMSARA_FLEET_RESULT_CONSUMER_ID: &str = "mission.samsara.fleet.result";
pub const SAMSARA_FLEET_RESULT_PROVIDER_VERSION: &str = "0.1.0";
pub const SAMSARA_FLEET_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/samsara-fleet-result/samsara-fleet-result.v1.json";
pub const SAMSARA_FLEET_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/samsara-fleet-result/samsara-fleet-result.v1.json");
pub const SAMSARA_FLEET_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const SAMSARA_API_VERSION: &str = "2026-05-06";
pub const SAMSARA_API_ORIGIN: &str = "https://api.samsara.com";

/// The Layer-1 authority boundary is deliberately all false.
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

    pub const fn effect() -> bool {
        false
    }

    pub const fn verification() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

/// Return a lowercase SHA-256 digest.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes))
}

/// Hash a serializable typed value without retaining its raw representation.
#[must_use]
pub fn canonical_digest<T: serde::Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed Samsara value serializes");
    sha256_digest(&bytes)
}

/// Validate the checked-in contract document against the public constants and
/// the Layer-1 honesty boundary.
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let document = serde_json::from_str::<Value>(SAMSARA_FLEET_RESULT_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::InvalidJson(error.to_string()))?;
    let expected_reads = [
        ("vehicles", "GET", "/fleet/vehicles"),
        ("vehicle_trips", "GET", "/trips/stream"),
        ("safety_signals", "GET", "/safety-events/stream"),
        ("maintenance_status", "GET", "/v1/fleet/maintenance/list"),
        ("dvir_status", "GET", "/fleet/dvirs/history"),
        ("bounded_alerts", "GET", "/alerts/incidents/stream"),
    ];
    let reads = document
        .get("reads")
        .and_then(Value::as_array)
        .ok_or(ContractValidationError::MissingField("reads"))?;
    if reads.len() != expected_reads.len() {
        return Err(ContractValidationError::UnexpectedReads);
    }
    for ((id, method, path), read) in expected_reads.iter().zip(reads) {
        if read.get("id").and_then(Value::as_str) != Some(*id)
            || read.get("method").and_then(Value::as_str) != Some(*method)
            || read.get("path").and_then(Value::as_str) != Some(*path)
            || read.get("bounded").and_then(Value::as_bool) != Some(true)
            || read.get("writes").and_then(Value::as_bool) != Some(false)
        {
            return Err(ContractValidationError::UnexpectedReads);
        }
    }
    if document.get("schemaVersion").and_then(Value::as_str)
        != Some(SAMSARA_FLEET_RESULT_SCHEMA_VERSION)
        || document.get("contractVersion").and_then(Value::as_str)
            != Some(SAMSARA_FLEET_RESULT_CONTRACT_VERSION)
        || document.get("pluginVersion").and_then(Value::as_str)
            != Some(SAMSARA_FLEET_RESULT_PLUGIN_VERSION)
        || document.get("layer").and_then(Value::as_str) != Some("Layer-1")
        || document.pointer("/service/id").and_then(Value::as_str)
            != Some(SAMSARA_FLEET_RESULT_SERVICE_ID)
        || document.pointer("/provider/id").and_then(Value::as_str)
            != Some(SAMSARA_FLEET_RESULT_PROVIDER_ID)
        || document
            .pointer("/provider/apiVersion")
            .and_then(Value::as_str)
            != Some(SAMSARA_API_VERSION)
        || document.pointer("/consumer/id").and_then(Value::as_str)
            != Some(SAMSARA_FLEET_RESULT_CONSUMER_ID)
    {
        return Err(ContractValidationError::IdentityMismatch);
    }
    for pointer in [
        "/service/readOnly",
        "/service/proposalOnly",
        "/provider/native",
        "/provider/connected",
        "/consumer/adoptsOutcome",
        "/consumer/truthAuthority",
        "/projections/absenceOfAlertsIsHealthy",
        "/projections/absenceOfAlertsIsAvailable",
        "/transport/rawSecretSerialized",
        "/transport/externalWrites",
        "/transport/nativeHttpExecution",
        "/authority/connected",
        "/authority/nativeProvider",
        "/authority/durableNativeReceipt",
        "/authority/effect",
        "/authority/verification",
        "/authority/adoptedOutcome",
        "/authority/truthAuthority",
    ] {
        if document.pointer(pointer).and_then(Value::as_bool) != Some(false)
            && !matches!(pointer, "/service/readOnly" | "/service/proposalOnly")
        {
            return Err(ContractValidationError::AuthorityMismatch(pointer));
        }
    }
    if document
        .pointer("/service/readOnly")
        .and_then(Value::as_bool)
        != Some(true)
        || document
            .pointer("/service/proposalOnly")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(ContractValidationError::AuthorityMismatch(
            "/service/readOnly",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractValidationError {
    #[error("Samsara contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("Samsara contract is missing {0}")]
    MissingField(&'static str),
    #[error("Samsara contract identity does not match the crate constants")]
    IdentityMismatch,
    #[error("Samsara contract read allowlist is invalid")]
    UnexpectedReads,
    #[error("Samsara contract authority flag is invalid at {0}")]
    AuthorityMismatch(&'static str),
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_valid() {
        validate_contract().expect("Samsara contract validation");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::effect());
        assert!(!Layer1Authority::verification());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
        assert_eq!(SAMSARA_FLEET_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(SAMSARA_API_ORIGIN, "https://api.samsara.com");
    }
}

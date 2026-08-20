//! Standalone Layer-1 HashiCorp Boundary session-result plugin.
//!
//! This crate exposes the typed `BoundarySessionResultService`,
//! `BoundaryProvider`, and `MissionBoundarySessionConsumer` seam. It is
//! bounded to exact session list/read and target metadata GET projections.
//! It never resolves credentials, authorizes/connects/cancels sessions,
//! mutates Boundary resources, executes SSH/RDP, downloads recordings, or
//! claims Truth, Consent, Effect, Receipt, Verification, or Outcome authority.

#![forbid(unsafe_code)]
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
#![allow(clippy::type_complexity)]

mod consumer;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::{
    MissionBoundarySessionConsumer, MissionBoundarySessionConsumerError,
    MissionBoundarySessionObservation, MissionBoundarySessionResult,
};
pub use model::*;
pub use provider::{BoundaryProvider, BoundaryProviderDefinition, BoundaryProviderError};
pub use service::{
    BoundaryCapability, BoundaryService, BoundaryServiceError, BoundaryServiceOperation,
    BoundarySessionResultService, BoundarySessionResultServiceError,
};
pub use transport::{
    BlockedEnvBoundaryTransport, BlockedEnvTransport, BoundaryHttpRequest, BoundaryJsonResponse,
    BoundaryTransport, BoundaryTransportError, FakeBoundaryTransport, FixtureBoundaryTransport,
    LoopbackBoundaryTransport, ProviderProvenance, RecordingBoundaryTransport, response_from_json,
};

pub const BOUNDARY_SCHEMA_VERSION: &str = "hartevo.boundary-session-result.contract/v1";
pub const BOUNDARY_CONTRACT_VERSION: &str = "boundary-session-result/v1";
pub const BOUNDARY_PLUGIN_ID: &str = "boundary-session-result";
pub const BOUNDARY_PLUGIN_VERSION: &str = "1.0.0";
pub const BOUNDARY_SERVICE_ID: &str = "boundary.session.result";
pub const BOUNDARY_SERVICE_IMPLEMENTATION: &str = "BoundarySessionResultService";
pub const BOUNDARY_PROVIDER_ID: &str = "hashicorp.boundary.session";
pub const BOUNDARY_PROVIDER_IMPLEMENTATION: &str = "BoundaryProvider";
pub const BOUNDARY_PROVIDER_API_VERSION: &str = "v1";
pub const BOUNDARY_PROVIDER_REVISION: &str = "boundary-session-api-v1-read-r1";
pub const MISSION_BOUNDARY_SESSION_CONSUMER_ID: &str = "mission.boundary-session-result";
pub const MISSION_BOUNDARY_SESSION_CONSUMER_IMPLEMENTATION: &str = "MissionBoundarySessionConsumer";
pub const BOUNDARY_EVIDENCE_POLICY_SCHEMA: &str =
    "hartevo.boundary-session-result-evidence-allowlist/v1";
pub const BOUNDARY_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const BOUNDARY_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const BOUNDARY_MAX_IDENTIFIER_BYTES: usize = 128;
pub const BOUNDARY_MAX_LIST_TOKEN_BYTES: usize = 256;
pub const BOUNDARY_MAX_PAGES: u16 = 4;
pub const BOUNDARY_MAX_SESSIONS_PER_PAGE: usize = 64;
pub const BOUNDARY_MAX_SESSIONS_TOTAL: usize = 256;
pub const BOUNDARY_MAX_CONNECTIONS: u16 = 64;
pub const BOUNDARY_MAX_TIMESTAMP_BYTES: usize = 64;
pub const BOUNDARY_DEFAULT_PAGE_SIZE: u16 = 25;

pub const BOUNDARY_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/boundary-session-result/boundary-session-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(BOUNDARY_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version_digest() -> Digest {
    Digest::from_fields([
        "boundary-session-result-plugin-version",
        BOUNDARY_PLUGIN_VERSION,
    ])
}

#[must_use]
pub fn provider_digest() -> Digest {
    Digest::from_fields([
        "boundary-provider",
        BOUNDARY_PROVIDER_ID,
        BOUNDARY_PROVIDER_IMPLEMENTATION,
        BOUNDARY_PLUGIN_VERSION,
        BOUNDARY_PROVIDER_API_VERSION,
        BOUNDARY_PROVIDER_REVISION,
        "GET /v1/sessions",
        "GET /v1/sessions/{id}",
        "GET /v1/targets/{id}",
        "fixture|recording|fake|loopback|BLOCKED_ENV",
    ])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn authorize() -> bool {
        false
    }

    pub const fn connect() -> bool {
        false
    }

    pub const fn cancel() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BoundaryContractError {
    #[error("Boundary contract JSON is invalid: {0}")]
    Json(String),
    #[error("Boundary contract field drifted: {0}")]
    Invalid(&'static str),
}

/// A checked-in machine-readable view of the exact Layer-1 contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundarySessionResultContract {
    value: serde_json::Value,
}

impl BoundarySessionResultContract {
    pub fn baseline() -> Result<Self, BoundaryContractError> {
        let value = serde_json::from_str::<serde_json::Value>(BOUNDARY_CONTRACT_JSON)
            .map_err(|error| BoundaryContractError::Json(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), BoundaryContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(BoundaryContractError::Invalid("top-level object"))?;
        for key in [
            "$schema",
            "$id",
            "title",
            "description",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "service",
            "provider",
            "consumer",
            "scope",
            "registration",
            "bounds",
            "evidence",
            "projections",
            "authority",
            "redaction",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(BoundaryContractError::Invalid("top-level field"));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(BOUNDARY_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(BOUNDARY_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(BOUNDARY_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(BoundaryContractError::Invalid("contract identity"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(BoundaryContractError::Invalid("service"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(BOUNDARY_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some(BOUNDARY_SERVICE_IMPLEMENTATION)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        {
            return Err(BoundaryContractError::Invalid("service authority"));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(BoundaryContractError::Invalid("provider"))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(BOUNDARY_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some(BOUNDARY_PROVIDER_IMPLEMENTATION)
            || provider
                .get("apiVersion")
                .and_then(serde_json::Value::as_str)
                != Some(BOUNDARY_PROVIDER_API_VERSION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("allowlistedMethods") != Some(&serde_json::json!(["GET"]))
        {
            return Err(BoundaryContractError::Invalid("provider authority"));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(BoundaryContractError::Invalid("consumer"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(MISSION_BOUNDARY_SESSION_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some(MISSION_BOUNDARY_SESSION_CONSUMER_IMPLEMENTATION)
        {
            return Err(BoundaryContractError::Invalid("consumer identity"));
        }
        for field in [
            "truthAuthority",
            "consentAuthority",
            "effectAuthority",
            "receiptAuthority",
            "verificationAuthority",
            "outcomeAuthority",
        ] {
            if consumer.get(field) != Some(&serde_json::Value::Bool(false)) {
                return Err(BoundaryContractError::Invalid("consumer authority"));
            }
        }
        let bounds = object
            .get("bounds")
            .and_then(serde_json::Value::as_object)
            .ok_or(BoundaryContractError::Invalid("bounds"))?;
        for (key, value) in [
            ("maxResponseBytes", BOUNDARY_MAX_RESPONSE_BYTES as u64),
            ("maxIdentifierBytes", BOUNDARY_MAX_IDENTIFIER_BYTES as u64),
            ("maxListTokenBytes", BOUNDARY_MAX_LIST_TOKEN_BYTES as u64),
            ("maxPages", u64::from(BOUNDARY_MAX_PAGES)),
            ("maxSessionsPerPage", BOUNDARY_MAX_SESSIONS_PER_PAGE as u64),
            ("maxConnections", u64::from(BOUNDARY_MAX_CONNECTIONS)),
            ("maxTimestampBytes", BOUNDARY_MAX_TIMESTAMP_BYTES as u64),
        ] {
            if bounds.get(key).and_then(serde_json::Value::as_u64) != Some(value) {
                return Err(BoundaryContractError::Invalid("bounds value"));
            }
        }
        let projections = object
            .get("projections")
            .and_then(serde_json::Value::as_object)
            .ok_or(BoundaryContractError::Invalid("projections"))?;
        let expected_states = serde_json::json!([
            "PENDING",
            "ACTIVE",
            "CANCELING",
            "TERMINATED",
            "EXPIRED",
            "PARTIAL",
            "ACCESS_LOST",
            "PROVIDER_UNKNOWN",
            "TAMPERED",
            "REVOKED"
        ]);
        if projections.get("states") != Some(&expected_states)
            || projections.get("failClosed") != Some(&serde_json::Value::Bool(true))
            || projections.get("lifecycleMonotonic") != Some(&serde_json::Value::Bool(true))
        {
            return Err(BoundaryContractError::Invalid("projection safety"));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(BoundaryContractError::Invalid("authority"))?;
        for (key, value) in authority {
            if key == "readOnly" || key == "proposalOnly" {
                if value != &serde_json::Value::Bool(true) {
                    return Err(BoundaryContractError::Invalid(
                        "authority read-only boundary",
                    ));
                }
                continue;
            }
            if value.is_boolean() && value != &serde_json::Value::Bool(false) {
                return Err(BoundaryContractError::Invalid(
                    "authority is not fail-closed",
                ));
            }
        }
        let honesty = object
            .get("honesty")
            .and_then(serde_json::Value::as_object)
            .ok_or(BoundaryContractError::Invalid("honesty"))?;
        if honesty
            .get("nativeStatus")
            .and_then(serde_json::Value::as_str)
            != Some("BLOCKED_ENV")
            || honesty.get("blockedEnvironmentIsNative") != Some(&serde_json::Value::Bool(false))
            || honesty.get("connectedClaim") != Some(&serde_json::Value::Bool(false))
            || honesty.get("firstPartyClaim") != Some(&serde_json::Value::Bool(false))
            || honesty.get("durableProviderReceiptClaim") != Some(&serde_json::Value::Bool(false))
        {
            return Err(BoundaryContractError::Invalid("honesty boundary"));
        }
        Ok(())
    }
}

#[must_use]
pub fn contract_bounds_tripwire() -> bool {
    BoundarySessionResultContract::baseline().is_ok()
}

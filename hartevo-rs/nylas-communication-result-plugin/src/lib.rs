//! Standalone Layer-1 governed Nylas communication metadata evidence.
//!
//! The crate exposes typed, exact-scope, read-only seams for
//! [`NylasCommunicationResultService`], [`NylasProvider`], and
//! [`MissionNylasCommunicationConsumer`]. It never resolves credentials,
//! opens native HTTPS, sends or mutates messages/events, registers webhooks,
//! downloads attachments, retains raw bodies or recipient PII, creates a
//! durable provider receipt, or asserts kernel authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use serde_json::Value;

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionNylasCommunicationConsumer, MissionNylasCommunicationConsumerError,
    MissionNylasCommunicationResult, MissionNylasCommunicationResultState,
    MissionNylasCommunicationResultStateProjection, MissionNylasCommunicationState,
    MissionResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvNylasProviderTransport, BlockedEnvNylasTransport, FakeNylasTransport,
    FixtureNylasProviderTransport, FixtureNylasTransport, LoopbackNylasProviderTransport,
    LoopbackNylasTransport, NylasCommunicationProvider, NylasHttpMethod, NylasPageCursor,
    NylasProvider, NylasProviderDefinition, NylasProviderError, NylasProviderFailureMetadata,
    NylasProviderFieldSelection, NylasProviderPermission, NylasProviderRead, NylasProviderRequest,
    NylasProviderResource, NylasResponse, NylasTransport, NylasTransportError,
    RecordingNylasProviderTransport, RecordingNylasTransport,
};
pub use service::{
    NylasCommunicationEvidence, NylasCommunicationEvidenceResult, NylasCommunicationProposal,
    NylasCommunicationRecord, NylasCommunicationRecordReceipt, NylasCommunicationResult,
    NylasCommunicationResultProposal, NylasCommunicationResultReceipt,
    NylasCommunicationResultService, NylasCommunicationResultServiceDefinition,
    NylasCommunicationResultServiceError, NylasCommunicationServiceError, NylasSecretReference,
    NylasVerificationFailure, NylasVerificationReport, ServiceDefinitionError,
};

pub const SCHEMA_VERSION: &str = "hartevo.nylas-communication-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-NYLAS-01-L1/v1";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const PLUGIN_ID: &str = "nylas.communication-result";
pub const SERVICE_ID: &str = "nylas.communication.result.read";
pub const PROVIDER_ID: &str = "nylas.communication.metadata.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const PROVIDER_API_REVISION: &str =
    "nylas-v3-unified-grant-message-thread-calendar-metadata-r1";
pub const CONSUMER_ID: &str = "mission.nylas.communication-result.consumer";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const NYLAS_API_DOCUMENTATION_URL: &str = "https://developer.nylas.com/docs/reference/api/";
pub const NYLAS_MESSAGES_DOCUMENTATION_URL: &str =
    "https://developer.nylas.com/docs/reference/api/messages/";
pub const NYLAS_THREADS_DOCUMENTATION_URL: &str =
    "https://developer.nylas.com/docs/reference/api/threads/";
pub const NYLAS_CALENDAR_DOCUMENTATION_URL: &str = "https://developer.nylas.com/docs/v3/calendar/";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.nylas-communication-result/v1|layer=1|service=nylas.communication.result.read|provider=nylas.communication.metadata.recording|consumer=mission.nylas.communication-result.consumer|api=nylas-v3-unified-grant-message-thread-calendar-metadata-r1";
pub const CONTRACT_DIGEST: &str =
    "1be9ca8119fcf51c15a4fc941c0e23e898d63c23907f74a6b7703c33cabee9f9";
pub const API_DIGEST: &str = "295a2109bf3eac397b7d4e414f88e4892f3d09294424203fe7a7ee912849014b";

pub use model::{
    MAX_ATTEMPTS, MAX_BACKOFF_SECONDS, MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES, MAX_ITEMS,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS,
};

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[must_use]
pub fn plugin_version_digest() -> Digest {
    canonical_digest(&PLUGIN_VERSION)
}

#[must_use]
pub fn api_digest() -> Digest {
    canonical_digest(&PROVIDER_API_REVISION)
}

/// Layer 1 deliberately reports no native, connected, first-party, durable,
/// or kernel authority, including for BLOCKED_ENV.
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
    pub const fn https_transport() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn independent_native_readback() -> bool {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NylasCommunicationResultContract {
    value: Value,
}

impl NylasCommunicationResultContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let value =
            serde_json::from_str::<Value>(CONTRACT_JSON).map_err(|_| ContractError::Malformed)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub const fn schema_version() -> &'static str {
        SCHEMA_VERSION
    }

    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let object = self.value.as_object().ok_or(ContractError::Drift)?;
        for key in [
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "exactScope",
            "bounds",
            "allowlist",
            "pagination",
            "projection",
            "fences",
            "receipts",
            "states",
            "honesty",
        ] {
            if !object.contains_key(key) {
                return Err(ContractError::Drift);
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str) != Some(SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str) != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(Value::as_str) != Some("Layer-1")
            || object.get("evidenceLevel").and_then(Value::as_str) != Some("L1_PROVIDER_CONTRACT")
            || object.get("digestInput").and_then(Value::as_str) != Some(CONTRACT_DIGEST_INPUT)
            || object.get("contractDigest").and_then(Value::as_str) != Some(CONTRACT_DIGEST)
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(ContractError::Drift);
        }
        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or(ContractError::Drift)?;
        if service.get("id").and_then(Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("externalWrites") != Some(&Value::Bool(false))
            || service.get("kernelAuthority") != Some(&Value::Bool(false))
        {
            return Err(ContractError::Drift);
        }
        let provider = object
            .get("provider")
            .and_then(Value::as_object)
            .ok_or(ContractError::Drift)?;
        if provider.get("id").and_then(Value::as_str) != Some(PROVIDER_ID)
            || provider.get("apiRevision").and_then(Value::as_str) != Some(PROVIDER_API_REVISION)
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("firstParty") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
        {
            return Err(ContractError::Drift);
        }
        let consumer = object
            .get("consumer")
            .and_then(Value::as_object)
            .ok_or(ContractError::Drift)?;
        if consumer.get("id").and_then(Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&Value::Bool(false))
            || consumer.get("kernelAuthority") != Some(&Value::Bool(false))
        {
            return Err(ContractError::Drift);
        }
        let forbidden = object
            .get("allowlist")
            .and_then(Value::as_object)
            .and_then(|allowlist| allowlist.get("forbidden"))
            .and_then(Value::as_array)
            .ok_or(ContractError::Drift)?;
        for name in [
            "send_message",
            "schedule_message",
            "delete_message",
            "update_message",
            "webhook_registration",
            "attachment_download",
            "raw_message_body",
            "raw_recipient_pii",
            "native_https_transport",
            "durable_provider_receipt",
            "kernel_outcome",
        ] {
            if !forbidden.iter().any(|value| value.as_str() == Some(name)) {
                return Err(ContractError::Drift);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    Malformed,
    Drift,
}

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/nylas-communication-result/nylas-communication-result.v1.json"
);

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = NylasCommunicationResultContract::baseline().expect("contract");
        assert_eq!(contract.value()["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::https_transport());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::independent_native_readback());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
        NylasProviderDefinition::layer1(NylasTransportProvenance::Fixture)
            .validate()
            .expect("provider definition");
    }
}

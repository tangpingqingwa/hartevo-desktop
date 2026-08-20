//! Standalone Layer-1 governed Mailgun delivery-result boundary.
//!
//! This crate exposes typed, bounded delivery/event evidence and redacted
//! proposal, record, and verification seams. It never sends or deletes
//! messages, mutates suppressions, exposes message bodies or recipient PII,
//! resolves native credentials, creates a kernel receipt, or adopts an
//! Outcome or Work Product.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
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

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionMailgunDeliveryConsumer, MissionMailgunDeliveryResult,
    MissionMailgunDeliveryResultState, MissionResultState,
};
pub use error::{
    ContractError, MailgunDeliveryResultServiceError, MailgunProviderError, MailgunTransportError,
    MissionMailgunDeliveryConsumerError, ModelError, ModelResult, ProviderResult, ServiceResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvMailgunTransport, FakeMailgunTransport, FixtureMailgunTransport,
    LoopbackMailgunTransport, MailgunEventPage, MailgunEventsRequest, MailgunOperation,
    MailgunProvider, MailgunProviderDefinition, MailgunSuppressionRequest, MailgunTransport,
    RecordingMailgunTransport, WebhookVerificationRequest,
};
pub use service::{
    MailgunDeliveryResultRequest, MailgunDeliveryResultService, MailgunServiceDefinition,
};

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.mailgun-delivery-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-MAILGUN-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const PLUGIN_ID: &str = "mailgun.delivery-result";
pub const SERVICE_ID: &str = "mailgun.delivery.result.read";
pub const PROVIDER_ID: &str = "mailgun.delivery.result.recording";
pub const PROVIDER_API_REVISION: &str = "mailgun-events-v3-delivery-status-retry-suppression-r1";
pub const CONSUMER_ID: &str = "mission.mailgun.delivery-result.consumer";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.mailgun-delivery-result/v1|layer=1|service=mailgun.delivery.result.read|provider=mailgun.delivery.result.recording|consumer=mission.mailgun.delivery-result.consumer|api=mailgun-events-v3-delivery-status-retry-suppression-r1";
pub const CONTRACT_DIGEST: &str =
    "f995274c726fbcae122c7dc1fc22cca24c06212a3cf16da5871665804771dbfd";
pub const API_DIGEST: &str = "1d24249ec9ade18613b979d35878d598b3630e90fb03ca63aac01f21bfbcaa5c";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TAG_BYTES: usize = 128;
pub const MAX_TAGS: usize = 16;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_EVENTS_PER_PAGE: usize = 100;
pub const MAX_TOTAL_EVENTS: usize = MAX_PAGES as usize * MAX_EVENTS_PER_PAGE;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 86_400;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_WEBHOOK_AGE_SECONDS: u64 = 900;
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/mailgun-delivery-result/mailgun-delivery-result.v1.json"
);

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

/// Layer 1 deliberately reports no native or kernel authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native() -> bool {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailgunDeliveryResultContract {
    value: Value,
}

impl MailgunDeliveryResultContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let value =
            serde_json::from_str::<Value>(CONTRACT_JSON).map_err(|_| ContractError::Malformed)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub const fn schema_version() -> &'static str {
        CONTRACT_SCHEMA_VERSION
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
        if object.get("schemaVersion").and_then(Value::as_str) != Some(CONTRACT_SCHEMA_VERSION)
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
            "delete_message",
            "suppress_recipient",
            "raw_message_body",
            "raw_recipient_pii",
            "native_https_transport",
            "outcome_adoption",
        ] {
            if !forbidden.iter().any(|value| value.as_str() == Some(name)) {
                return Err(ContractError::Drift);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = MailgunDeliveryResultContract::baseline().expect("contract");
        assert_eq!(contract.value()["schemaVersion"], CONTRACT_SCHEMA_VERSION);
        assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::outcome_authority());
    }
}

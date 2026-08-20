//! Standalone Layer-1 governed Adyen payment outcome evidence.
//!
//! The crate exposes only bounded, read-only payment metadata, digest-bound
//! proposals, recording/read-back verification, and reversible registration.
//! It does not authorise, capture, refund, cancel, receive webhooks, retain
//! PII/payment instruments, offer financial advice, or adopt a kernel Outcome.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{MissionAdyenPaymentConsumer, MissionAdyenPaymentResult};
pub use error::{AdyenPaymentResultError, AdyenPaymentTransportError, Result};
pub use model::*;
pub use provider::{
    ADYEN_API_KEY_ENVIRONMENT_VARIABLE, AdyenPaymentsProvider, AdyenProviderState,
    AdyenRecordingProvider, BlockedEnvCredentialResolver, EnvironmentAdyenCredentialResolver,
    StaticAdyenCredentialResolver,
};
pub use service::{
    AdyenPaymentResultService, AdyenReadOnlyService, AdyenServiceDefinition, AdyenServiceOperation,
};
pub use transport::{
    AdyenApiTransport, AdyenPaymentTransport, AdyenRecordingTransport, AdyenTransportOperation,
    FakeAdyenTransport, LoopbackAdyenTransport, RetryPolicy, SecretMaterial, UreqAdyenTransport,
};

pub const SCHEMA_VERSION: &str = "hartevo.adyen-payment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-ADYEN-PAYMENT-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.adyen-payment-result";
pub const SERVICE_ID: &str = "AdyenPaymentResultService";
pub const PROVIDER_ID: &str = "adyen-payments";
pub const CONSUMER_ID: &str = "MissionAdyenPaymentConsumer";
pub const API_REVISION: &str = "checkout-v72-read-payment-link-session-r1";
pub const ADYEN_TEST_API_BASE_URL: &str = "https://checkout-test.adyen.com/v72";
pub const ADYEN_LIVE_API_BASE_URL: &str = "https://{PREFIX}-checkout-live.adyen.com/checkout/v72";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/adyen-payment-result/adyen-payment-result.v1.json");
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::V1;
pub const PROVIDER_VERSION: PluginVersion = PluginVersion::V1;

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

pub fn api_digest() -> Digest {
    Digest::from_parts(
        "hartevo-adyen-api/v1",
        &[
            ("revision", API_REVISION.to_owned()),
            ("test_base_url", ADYEN_TEST_API_BASE_URL.to_owned()),
            ("live_base_url", ADYEN_LIVE_API_BASE_URL.to_owned()),
            ("read_methods", "GET".to_owned()),
            (
                "payment_link_path",
                "/paymentLinks/{payment_reference}".to_owned(),
            ),
            ("session_path", "/sessions/{payment_reference}".to_owned()),
        ],
    )
}

pub fn provider_digest() -> Digest {
    Digest::from_parts(
        "hartevo-adyen-provider/v1",
        &[
            ("provider_id", PROVIDER_ID.to_owned()),
            ("provider_version", PROVIDER_VERSION.as_str().to_owned()),
        ],
    )
}

pub fn evidence_schema_digest() -> Digest {
    Digest::from_parts(
        "hartevo-adyen-payment-evidence-schema/v1",
        &[
            ("schema", SCHEMA_VERSION.to_owned()),
            ("contract", CONTRACT_VERSION.to_owned()),
            ("api_revision", API_REVISION.to_owned()),
            ("pii", "false".to_owned()),
            ("payment_instruments", "false".to_owned()),
            ("financial_advice", "false".to_owned()),
        ],
    )
}

/// Validate the checked-in contract's machine-readable safety boundary.
pub fn validate_contract() -> Result<()> {
    let document: serde_json::Value =
        serde_json::from_str(CONTRACT_JSON).map_err(|_| AdyenPaymentResultError::ContractDrift)?;
    let object = document
        .as_object()
        .ok_or(AdyenPaymentResultError::ContractDrift)?;
    for key in [
        "$schema",
        "$id",
        "schemaVersion",
        "contractVersion",
        "layer",
        "plugin",
        "service",
        "provider",
        "scope",
        "evidence",
        "semantics",
        "forbiddenAuthorities",
        "nativeGaps",
    ] {
        if !object.contains_key(key) {
            return Err(AdyenPaymentResultError::ContractDrift);
        }
    }
    if object
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        != Some(SCHEMA_VERSION)
        || object
            .get("contractVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_VERSION)
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
    {
        return Err(AdyenPaymentResultError::ContractDrift);
    }
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(AdyenPaymentResultError::ContractDrift)?;
    if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service.get("provider").and_then(serde_json::Value::as_str)
            != Some("AdyenPaymentsProvider")
        || service.get("consumer").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
        || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
        || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        || service.get("financialAdvice") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AdyenPaymentResultError::ContractDrift);
    }
    let registration = object
        .get("plugin")
        .and_then(serde_json::Value::as_object)
        .and_then(|plugin| plugin.get("registration"))
        .and_then(serde_json::Value::as_object)
        .ok_or(AdyenPaymentResultError::ContractDrift)?;
    let digest_bindings = registration
        .get("digestBindingFields")
        .and_then(serde_json::Value::as_array)
        .ok_or(AdyenPaymentResultError::ContractDrift)?;
    let expected_digest_bindings = [
        "api_digest",
        "provider_digest",
        "contract_digest",
        "permission_digest",
        "scope_digest",
        "evidence_digest",
    ];
    if digest_bindings.len() != expected_digest_bindings.len()
        || !digest_bindings
            .iter()
            .zip(expected_digest_bindings)
            .all(|(actual, expected)| actual.as_str() == Some(expected))
    {
        return Err(AdyenPaymentResultError::ContractDrift);
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(AdyenPaymentResultError::ContractDrift)?;
    if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
        || provider
            .get("nativeStatus")
            .and_then(serde_json::Value::as_str)
            != Some("BLOCKED_ENV")
    {
        return Err(AdyenPaymentResultError::ContractDrift);
    }
    let evidence = object
        .get("evidence")
        .and_then(serde_json::Value::as_object)
        .ok_or(AdyenPaymentResultError::ContractDrift)?;
    if evidence.get("rawPaymentMethod") != Some(&serde_json::Value::Bool(false))
        || evidence.get("rawCustomerFields") != Some(&serde_json::Value::Bool(false))
        || evidence.get("rawBodies") != Some(&serde_json::Value::Bool(false))
        || evidence.get("financialAdvice") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AdyenPaymentResultError::ContractDrift);
    }
    Ok(())
}

/// Compile-time authority marker used by audits and adversarial tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn store() -> bool {
        false
    }

    pub const fn keyring() -> bool {
        false
    }

    pub const fn browser_profile() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn authorise() -> bool {
        false
    }

    pub const fn capture() -> bool {
        false
    }

    pub const fn refund() -> bool {
        false
    }

    pub const fn cancel() -> bool {
        false
    }

    pub const fn webhooks() -> bool {
        false
    }

    pub const fn payment_instruments() -> bool {
        false
    }

    pub const fn customer_pii() -> bool {
        false
    }

    pub const fn financial_advice() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_contract_is_read_only_and_redacted() {
        validate_contract().expect("contract validates");
        let value: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(value["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(value["layer"], 1);
        assert_eq!(value["service"]["externalWrites"], false);
        assert_eq!(value["service"]["financialAdvice"], false);
        assert_eq!(value["provider"]["connectedEvidence"], false);
        assert_eq!(value["evidence"]["rawCustomerFields"], false);
        assert!(!ReadOnlyAuthority::authorise());
        assert!(!ReadOnlyAuthority::capture());
        assert!(!ReadOnlyAuthority::refund());
        assert!(!ReadOnlyAuthority::cancel());
        assert!(!ReadOnlyAuthority::webhooks());
        assert!(!ReadOnlyAuthority::payment_instruments());
        assert!(!ReadOnlyAuthority::customer_pii());
        assert!(!ReadOnlyAuthority::financial_advice());
        assert_eq!(contract_digest().as_str().len(), 64);
    }
}

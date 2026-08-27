//! Standalone Layer-1 governed Chargebee subscription result plugin.
//!
//! This root exposes only bounded, redacted GET observations, digest-bound
//! proposals, local record/verify seams, and reversible registration. It does
//! not resolve native credentials, use live Chargebee HTTPS, mutate billing
//! resources, expose payment instruments or raw customer PII, provide
//! financial advice, or adopt kernel Consent/Outcome/Effect authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::items_after_statements,
    clippy::large_enum_variant,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde_json::Value;
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionChargebeeConsumerError, MissionChargebeeSubscriptionConsumer,
    MissionChargebeeSubscriptionResult,
};
pub use model::*;
pub use provider::{
    ChargebeeProvider, ChargebeeProviderDefinition, ChargebeeProviderError, NativeProbe,
    NativeProbeStatus, native_probe_from_environment, provider_has_mutation_authority,
};
pub use service::{
    ChargebeeCapability, ChargebeeEvidenceProposalRequest, ChargebeeServiceOperation,
    ChargebeeSubscriptionResultService,
};
pub use transport::{
    BlockedEnvChargebeeTransport, ChargebeeTransport, ChargebeeTransportError,
    FakeChargebeeTransport, FixtureChargebeeTransport, LoopbackChargebeeTransport,
    QueueChargebeeTransport, RecordingChargebeeTransport, response_from_json,
};

/// Machine-readable contract schema identity.
pub const SCHEMA_VERSION: &str = "hartevo.chargebee-subscription-result.contract/v1";
/// Layer-1 contract version.
pub const CONTRACT_VERSION: &str = "EXT-CHARGEBEE-01-L1/v1";
/// Stable plugin identifier.
pub const PLUGIN_ID: &str = "hartevo.chargebee-subscription-result";
/// Stable typed service identifier.
pub const SERVICE_ID: &str = "ChargebeeSubscriptionResultService";
/// Stable typed provider identifier.
pub const PROVIDER_ID: &str = "chargebee";
/// Stable typed provider implementation name.
pub const PROVIDER_IMPLEMENTATION: &str = "ChargebeeProvider";
/// Stable Mission consumer identifier.
pub const CONSUMER_ID: &str = "MissionChargebeeSubscriptionConsumer";
/// API compatibility revision represented by this bounded contract.
pub const PROVIDER_API_REVISION: &str = "chargebee-api-v2-read-r1";
/// Provider revision bound into registration.
pub const PROVIDER_REVISION_TEXT: &str = "chargebee-read-v2-r1";
/// Human-readable plugin version bound into the contract.
pub const PLUGIN_VERSION_TEXT: &str = "1.0.0";
/// Maximum sanitized provider response bytes.
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
/// Maximum identifier bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 128;
/// Maximum records retained from one bounded list response.
pub const MAX_RECORDS: usize = 128;
/// Maximum page size.
pub const MAX_PAGE_SIZE: u16 = 50;
/// Maximum pages per deterministic query.
pub const MAX_PAGES: u16 = 4;
/// Maximum provider requests in a one-minute local budget.
pub const MAX_REQUESTS_PER_MINUTE: u8 = 5;
/// Maximum opaque cursor digest payload budget.
pub const MAX_CURSOR_BYTES: usize = 512;
/// Evidence schema policy digest input.
pub const EVIDENCE_SCHEMA: &str = "hartevo.chargebee-subscription-result.evidence/v1";
/// Embedded machine-readable contract.
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/chargebee-subscription-result/chargebee-subscription-result.v1.json"
);

/// Errors shared by service, provider, and Mission consumer boundaries.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChargebeeSubscriptionResultError {
    #[error("invalid Chargebee subscription result input: {0}")]
    InvalidInput(String),
    #[error("Chargebee subscription result contract drifted: {0}")]
    ContractDrift(String),
    #[error("Chargebee subscription result scope mismatch")]
    ScopeMismatch,
    #[error("Chargebee subscription result registration is revoked")]
    RegistrationRevoked,
    #[error("Chargebee subscription result registration drifted: {0}")]
    RegistrationDrift(String),
    #[error("Chargebee subscription result secret reference is revoked")]
    SecretRevoked,
    #[error("Chargebee subscription result provider is incompatible")]
    ProviderMismatch,
    #[error("Chargebee subscription result provider revision drifted")]
    ProviderRevisionMismatch,
    #[error("Chargebee subscription result resource revision is stale")]
    StaleRevision,
    #[error("Chargebee subscription result cursor is stale or tampered")]
    CursorMismatch,
    #[error("Chargebee subscription result pagination drifted")]
    PaginationDrift,
    #[error("Chargebee subscription result contained a duplicate immutable identifier")]
    DuplicateIdentifier,
    #[error("Chargebee subscription result idempotency key conflicts with an existing record")]
    IdempotencyConflict,
    #[error(
        "Chargebee subscription result was rate limited; retry after {retry_after_seconds} seconds"
    )]
    RateLimited { retry_after_seconds: u64 },
    #[error("Chargebee subscription result access was lost")]
    AccessLost,
    #[error("Chargebee subscription result read was denied")]
    Denied,
    #[error("Chargebee subscription result resource was absent")]
    Absent,
    #[error("Chargebee subscription result observation was expired")]
    Expired,
    #[error("Chargebee subscription result provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Chargebee subscription result response was tampered")]
    ResponseTampered,
    #[error("Chargebee subscription result proposal is stale or tampered")]
    ProposalTampered,
    #[error("Chargebee subscription result read-back did not match")]
    ReadBackMismatch,
    #[error("Chargebee subscription result value error: {0}")]
    Model(String),
    #[error("Chargebee subscription result provider error: {0}")]
    Provider(String),
    #[error("Chargebee subscription result transport error: {0}")]
    Transport(String),
    #[error("Hartevo plugin runtime error: {0}")]
    Plugin(#[from] PluginError),
}

impl From<ChargebeeModelError> for ChargebeeSubscriptionResultError {
    fn from(error: ChargebeeModelError) -> Self {
        match error {
            ChargebeeModelError::ScopeMismatch => Self::ScopeMismatch,
            ChargebeeModelError::CursorMismatch => Self::CursorMismatch,
            ChargebeeModelError::DuplicateIdentifier => Self::DuplicateIdentifier,
            ChargebeeModelError::StaleRevision => Self::StaleRevision,
            ChargebeeModelError::Contract(message) => Self::ContractDrift(message),
            other => Self::Model(other.to_string()),
        }
    }
}

/// SHA-256 digest of the exact checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

/// Version descriptor for the plugin runtime composition seam.
pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Build runtime contribution descriptors for one exact Project/Mission
/// generation. Mounting remains host-owned and outside Layer 1.
pub fn plugin_definition(
    scope: PluginScope,
) -> Result<PluginDefinition, ChargebeeSubscriptionResultError> {
    let plugin_id = PluginId::new(PLUGIN_ID)?;
    let service_id = ServiceId::new(SERVICE_ID)?;
    let provider_id = ProviderId::new(PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text("hartevo.chargebee-subscription-result-service/v1"),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text("hartevo.chargebee-provider/v1"),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text("hartevo.mission-chargebee-subscription-result/v1"),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        version,
        scope,
        contributions,
    )?)
}

/// Checked-in contract parsed and checked against the typed implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChargebeeSubscriptionResultContract {
    value: Value,
}

impl ChargebeeSubscriptionResultContract {
    pub fn baseline() -> Result<Self, ChargebeeSubscriptionResultError> {
        let value = serde_json::from_str::<Value>(CONTRACT_JSON)
            .map_err(|error| ChargebeeSubscriptionResultError::ContractDrift(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), ChargebeeSubscriptionResultError> {
        let object = self.value.as_object().ok_or_else(|| {
            ChargebeeSubscriptionResultError::ContractDrift("contract is not an object".to_owned())
        })?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "plugin",
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
                return Err(ChargebeeSubscriptionResultError::ContractDrift(format!(
                    "missing top-level field {key}"
                )));
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str) != Some(SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str) != Some(PLUGIN_VERSION_TEXT)
            || object.get("layer").and_then(Value::as_u64) != Some(1)
        {
            return Err(ChargebeeSubscriptionResultError::ContractDrift(
                "top-level identity drifted".to_owned(),
            ));
        }
        let plugin = object
            .get("plugin")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ChargebeeSubscriptionResultError::ContractDrift("plugin missing".to_owned())
            })?;
        if plugin.get("id").and_then(Value::as_str) != Some(PLUGIN_ID)
            || plugin.get("version").and_then(Value::as_str) != Some(PLUGIN_VERSION_TEXT)
        {
            return Err(ChargebeeSubscriptionResultError::ContractDrift(
                "plugin identity drifted".to_owned(),
            ));
        }
        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ChargebeeSubscriptionResultError::ContractDrift("service missing".to_owned())
            })?;
        if service.get("id").and_then(Value::as_str) != Some(SERVICE_ID)
            || service.get("implementation").and_then(Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
            || service.get("externalWrites") != Some(&Value::Bool(false))
            || service.get("financialAdvice") != Some(&Value::Bool(false))
        {
            return Err(ChargebeeSubscriptionResultError::ContractDrift(
                "service authority drifted".to_owned(),
            ));
        }
        let provider = object
            .get("provider")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ChargebeeSubscriptionResultError::ContractDrift("provider missing".to_owned())
            })?;
        if provider.get("id").and_then(Value::as_str) != Some(PROVIDER_ID)
            || provider.get("implementation").and_then(Value::as_str)
                != Some(PROVIDER_IMPLEMENTATION)
            || provider.get("apiRevision").and_then(Value::as_str) != Some(PROVIDER_API_REVISION)
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("firstParty") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
            || provider.get("subscriptionWrites") != Some(&Value::Bool(false))
            || provider.get("planWrites") != Some(&Value::Bool(false))
            || provider.get("entitlementWrites") != Some(&Value::Bool(false))
            || provider.get("invoiceWrites") != Some(&Value::Bool(false))
            || provider.get("refunds") != Some(&Value::Bool(false))
            || provider.get("paymentInstrumentAccess") != Some(&Value::Bool(false))
            || provider.get("rawCustomerPii") != Some(&Value::Bool(false))
        {
            return Err(ChargebeeSubscriptionResultError::ContractDrift(
                "provider authority drifted".to_owned(),
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ChargebeeSubscriptionResultError::ContractDrift("consumer missing".to_owned())
            })?;
        if consumer.get("id").and_then(Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("implementation").and_then(Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("consentAuthority") != Some(&Value::Bool(false))
            || consumer.get("financialAdvice") != Some(&Value::Bool(false))
        {
            return Err(ChargebeeSubscriptionResultError::ContractDrift(
                "consumer authority drifted".to_owned(),
            ));
        }
        let bounds = object
            .get("bounds")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ChargebeeSubscriptionResultError::ContractDrift("bounds missing".to_owned())
            })?;
        if bounds.get("maxResponseBytes").and_then(Value::as_u64) != Some(MAX_RESPONSE_BYTES as u64)
            || bounds.get("maxPageSize").and_then(Value::as_u64) != Some(u64::from(MAX_PAGE_SIZE))
            || bounds.get("maxPages").and_then(Value::as_u64) != Some(u64::from(MAX_PAGES))
            || bounds.get("maxRequestsPerMinute").and_then(Value::as_u64)
                != Some(u64::from(MAX_REQUESTS_PER_MINUTE))
            || bounds.get("maxRecords").and_then(Value::as_u64) != Some(MAX_RECORDS as u64)
            || bounds.get("maxCursorBytes").and_then(Value::as_u64) != Some(MAX_CURSOR_BYTES as u64)
        {
            return Err(ChargebeeSubscriptionResultError::ContractDrift(
                "contract bounds drifted".to_owned(),
            ));
        }
        let authority = object
            .get("authority")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ChargebeeSubscriptionResultError::ContractDrift("authority missing".to_owned())
            })?;
        for key in [
            "subscriptionCreate",
            "subscriptionUpdate",
            "subscriptionCancel",
            "planMutation",
            "entitlementMutation",
            "invoiceMutation",
            "refund",
            "externalWrites",
            "paymentInstrumentAccess",
            "rawCustomerPii",
            "financialAdvice",
            "receiptAuthority",
            "verificationAuthority",
            "truthAuthority",
            "outcomeAuthority",
            "workProductAdoption",
            "consentAuthority",
            "effectAuthority",
            "connected",
            "native",
            "firstParty",
        ] {
            if authority.get(key) != Some(&Value::Bool(false)) {
                return Err(ChargebeeSubscriptionResultError::ContractDrift(format!(
                    "authority field {key} is not fail-closed"
                )));
            }
        }
        let honesty = object
            .get("honesty")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ChargebeeSubscriptionResultError::ContractDrift("honesty missing".to_owned())
            })?;
        if honesty.get("nativeStatus").and_then(Value::as_str) != Some("BLOCKED_ENV")
            || honesty.get("connectedClaim") != Some(&Value::Bool(false))
            || honesty.get("firstPartyEvidenceClaim") != Some(&Value::Bool(false))
        {
            return Err(ChargebeeSubscriptionResultError::ContractDrift(
                "honesty boundary drifted".to_owned(),
            ));
        }
        let redaction = object
            .get("redaction")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ChargebeeSubscriptionResultError::ContractDrift("redaction missing".to_owned())
            })?;
        for key in [
            "rawProviderPayload",
            "rawCustomerPii",
            "rawCustomerEmail",
            "rawCustomerName",
            "paymentInstruments",
            "invoiceLineItems",
            "invoiceAmounts",
            "planDescription",
            "entitlementDescription",
            "rawSecretReference",
            "rawProviderError",
            "financialAdvice",
        ] {
            if redaction.get(key) != Some(&Value::Bool(false)) {
                return Err(ChargebeeSubscriptionResultError::ContractDrift(format!(
                    "redaction field {key} is not fail-closed"
                )));
            }
        }
        Ok(())
    }
}

/// Contract validation tripwire for external contract checks.
pub fn contract_bounds_tripwire() -> bool {
    ChargebeeSubscriptionResultContract::baseline().is_ok()
}

/// Compile-time authority markers used by audits and adversarial tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn subscription_create() -> bool {
        false
    }
    pub const fn subscription_update() -> bool {
        false
    }
    pub const fn subscription_cancel() -> bool {
        false
    }
    pub const fn plan_mutation() -> bool {
        false
    }
    pub const fn entitlement_mutation() -> bool {
        false
    }
    pub const fn invoice_mutation() -> bool {
        false
    }
    pub const fn refund() -> bool {
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

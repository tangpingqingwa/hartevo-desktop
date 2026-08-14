//! Hartevo Xero Accounting Result Layer-1 plugin.
//!
//! This crate is intentionally a standalone nested workspace. It contributes
//! a typed, mission-scoped, read-only projection of one Xero invoice-or-bill,
//! one payment, one account, and an optional contact. It does not resolve
//! native OAuth2 credentials, claim Connected/native status, mutate Xero,
//! provide financial advice, own a dashboard/UI, or adopt kernel Outcomes.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use thiserror::Error;

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionXeroAccountingConsumer, MissionXeroAccountingObservation,
    MissionXeroAccountingReadResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, CredentialLease, FixtureCredentialResolver, NativeProbe,
    NativeProbeStatus, OAuth2CredentialResolver, XeroCredentialError, XeroProvider,
};
pub use service::{
    XeroAccountingCapability, XeroAccountingOperation, XeroAccountingResultService,
    XeroAccountingServiceDefinition,
};
pub use transport::{
    BlockedEnvXeroTransport, FixtureXeroTransport, LoopbackXeroTransport, RecordingXeroTransport,
    XeroHttpRequest, XeroHttpResponse, XeroResponsePayload, XeroTransport, XeroTransportError,
};

pub const XERO_ACCOUNTING_RESULT_SCHEMA_VERSION: &str =
    "hartevo.xero-accounting-result.contract/v1";
pub const XERO_ACCOUNTING_RESULT_CONTRACT_VERSION: &str = "xero-accounting-result/v1";
pub const XERO_ACCOUNTING_RESULT_PLUGIN_VERSION: &str = "1.0.0";
pub const XERO_ACCOUNTING_RESULT_SERVICE_ID: &str = "xero.accounting.result";
pub const XERO_ACCOUNTING_RESULT_PROVIDER_ID: &str = "xero.accounting";
pub const MISSION_XERO_ACCOUNTING_RESULT_CONSUMER_ID: &str = "mission.xero.accounting.result";
pub const XERO_ACCOUNTING_RESULT_SERVICE_SCHEMA: &str = "hartevo.xero-accounting-result-service/v1";
pub const XERO_ACCOUNTING_RESULT_PROVIDER_SCHEMA: &str =
    "hartevo.xero-accounting-result-provider/v1";
pub const MISSION_XERO_ACCOUNTING_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-xero-accounting-result-consumer/v1";
pub const XERO_ACCOUNTING_API_ORIGIN: &str = "https://api.xero.com";
pub const XERO_ACCOUNTING_API_REVISION: &str = "xero-accounting-api-2.0-r1";
pub const XERO_ACCOUNTING_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/xero-accounting-result/xero-accounting-result.v1.json"
);

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum XeroAccountingError {
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("Xero Accounting contract is invalid: {0}")]
    ContractInvalid(String),
    #[error("Xero Accounting contract digest does not match the checked-in contract")]
    ContractDigestMismatch,
    #[error("Xero Accounting scope mismatch: {0}")]
    ScopeMismatch(&'static str),
    #[error("Xero Accounting permission digest drifted")]
    PermissionDrift,
    #[error("Xero Accounting provider or API revision drifted")]
    ProviderRevisionDrift,
    #[error("Xero Accounting updated revision drifted")]
    UpdatedRevisionMismatch,
    #[error("Xero Accounting registration was tampered with")]
    RegistrationTampered,
    #[error("Xero Accounting registration was revoked")]
    RegistrationRevoked,
    #[error("Xero Accounting OAuth2 SecretReference was revoked")]
    SecretRevoked,
    #[error("Xero Accounting evidence was tampered with or is stale")]
    EvidenceTampered,
    #[error("Xero Accounting evidence is stale for this Mission consumer")]
    StaleEvidence,
    #[error("Xero Accounting access was lost")]
    AccessLost,
    #[error("Xero Accounting native execution is BLOCKED_ENV")]
    BlockedEnv,
    #[error("Xero Accounting target was not returned")]
    NotFound,
    #[error("Xero Accounting response exceeded its configured bound")]
    ResponseTooLarge,
    #[error("Xero Accounting page bound was exceeded")]
    PageBoundExceeded,
    #[error("Xero Accounting record bound was exceeded")]
    RecordBoundExceeded,
    #[error("Xero Accounting response contained an out-of-scope record")]
    OutOfScopeRecord,
    #[error("Xero Accounting currency mismatch in {field}")]
    CurrencyMismatch { field: &'static str },
    #[error("Xero Accounting amount inconsistency in {field}")]
    AmountMismatch { field: &'static str },
    #[error("Xero Accounting status is unsupported")]
    UnsupportedStatus,
    #[error("Xero Accounting provider response could not be decoded: {0}")]
    Decode(String),
    #[error("Xero Accounting transport failed: {0}")]
    Transport(String),
    #[error("Xero Accounting credential resolution failed: {0}")]
    Credential(String),
    #[error("Xero Accounting returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    #[error("Xero Accounting operation is not allowed by the Layer-1 contract")]
    UnsupportedOperation,
    #[error("plugin runtime rejected the Xero Accounting definition: {0}")]
    Plugin(PluginError),
}

impl From<PluginError> for XeroAccountingError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

pub fn contract_digest() -> model::Digest {
    model::Digest::from_bytes(XERO_ACCOUNTING_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn api_digest() -> model::Digest {
    model::Digest::from_serializable(&(
        XERO_ACCOUNTING_API_ORIGIN,
        XERO_ACCOUNTING_API_REVISION,
        [
            ("GET", "/api.xro/2.0/Invoices", model::INVOICE_FIELDS),
            ("GET", "/api.xro/2.0/Payments", model::PAYMENT_FIELDS),
            ("GET", "/api.xro/2.0/Contacts", model::CONTACT_FIELDS),
        ],
        [
            "exact_target_where",
            "date_bounds",
            "page",
            "pageSize",
            "fixed_order",
        ],
    ))
}

/// Parsed, checked-in contract handle used by tests and host validation.
#[derive(Clone, Debug)]
pub struct XeroAccountingContract {
    value: serde_json::Value,
}

impl XeroAccountingContract {
    pub fn baseline() -> Result<Self, XeroAccountingError> {
        let value = serde_json::from_str::<serde_json::Value>(XERO_ACCOUNTING_RESULT_CONTRACT_JSON)
            .map_err(|error| XeroAccountingError::ContractInvalid(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> model::Digest {
        contract_digest()
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), XeroAccountingError> {
        let expected = [
            (
                "/schemaVersion",
                serde_json::json!(XERO_ACCOUNTING_RESULT_SCHEMA_VERSION),
            ),
            (
                "/contractVersion",
                serde_json::json!(XERO_ACCOUNTING_RESULT_CONTRACT_VERSION),
            ),
            (
                "/pluginVersion",
                serde_json::json!(XERO_ACCOUNTING_RESULT_PLUGIN_VERSION),
            ),
            ("/layer", serde_json::json!("Layer-1")),
            (
                "/service/id",
                serde_json::json!(XERO_ACCOUNTING_RESULT_SERVICE_ID),
            ),
            (
                "/provider/id",
                serde_json::json!(XERO_ACCOUNTING_RESULT_PROVIDER_ID),
            ),
            (
                "/consumer/id",
                serde_json::json!(MISSION_XERO_ACCOUNTING_RESULT_CONSUMER_ID),
            ),
            (
                "/api/baseUrl",
                serde_json::json!(XERO_ACCOUNTING_API_ORIGIN),
            ),
            (
                "/api/revision",
                serde_json::json!(XERO_ACCOUNTING_API_REVISION),
            ),
            ("/api/method", serde_json::json!("GET")),
            (
                "/bounds/maxResponseBytes",
                serde_json::json!(model::MAX_RESPONSE_BYTES),
            ),
            (
                "/bounds/maxPageSize",
                serde_json::json!(model::MAX_PAGE_SIZE),
            ),
            ("/bounds/maxPages", serde_json::json!(model::MAX_PAGES)),
            ("/bounds/maxRecords", serde_json::json!(model::MAX_RECORDS)),
            (
                "/bounds/maxDateRangeDays",
                serde_json::json!(model::MAX_DATE_RANGE_DAYS),
            ),
        ];
        for (pointer, expected_value) in expected {
            if self.value.pointer(pointer) != Some(&expected_value) {
                return Err(XeroAccountingError::ContractInvalid(format!(
                    "contract field {pointer} does not match the Layer-1 baseline"
                )));
            }
        }
        let authority = self
            .value
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                XeroAccountingError::ContractInvalid("authority is missing".to_owned())
            })?;
        for key in [
            "connected",
            "native",
            "externalWrites",
            "financialAdvice",
            "durableReceipt",
            "independentReadBack",
            "kernelAuthority",
            "outcomeAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(XeroAccountingError::ContractInvalid(format!(
                    "authority.{key} must be false"
                )));
            }
        }
        if self.value.pointer("/authority/readOnly") != Some(&serde_json::Value::Bool(true))
            || self.value.pointer("/api/queryPolicy/writes")
                != Some(&serde_json::Value::Bool(false))
        {
            return Err(XeroAccountingError::ContractInvalid(
                "contract must be read-only".to_owned(),
            ));
        }
        let paths = self
            .value
            .pointer("/api/endpoints")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                XeroAccountingError::ContractInvalid("API endpoints are missing".to_owned())
            })?;
        let expected_paths = [
            "/api.xro/2.0/Invoices",
            "/api.xro/2.0/Payments",
            "/api.xro/2.0/Contacts",
        ];
        if paths.len() != expected_paths.len()
            || paths.iter().zip(expected_paths).any(|(endpoint, path)| {
                endpoint.get("path") != Some(&serde_json::Value::String(path.to_owned()))
                    || endpoint.get("method") != Some(&serde_json::Value::String("GET".to_owned()))
            })
        {
            return Err(XeroAccountingError::ContractInvalid(
                "API endpoint allowlist is not exactly the three bounded GET endpoints".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Builds only runtime descriptors. Mounting and host authority remain the
/// responsibility of the later integration layer.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, XeroAccountingError> {
    let plugin_id = PluginId::new("xero-accounting-result")?;
    let service_id = ServiceId::new(XERO_ACCOUNTING_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(XERO_ACCOUNTING_RESULT_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_XERO_ACCOUNTING_RESULT_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(XERO_ACCOUNTING_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(XERO_ACCOUNTING_RESULT_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_XERO_ACCOUNTING_RESULT_CONSUMER_SCHEMA),
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

//! Standalone Layer-1 Shippo fulfillment-result plugin.
//!
//! The root exposes a typed, bounded read graph for shipment, transaction,
//! carrier, and tracking metadata.  It intentionally stops before shipping
//! effects: no label purchase/download, object creation, address or parcel
//! mutation, webhook registration, payment, carrier command, raw provider
//! payload, recipient PII, or kernel Outcome authority is represented here.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use std::collections::BTreeMap;

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionShippoFulfillmentConsumer, MissionShippoFulfillmentObservation,
    MissionShippoFulfillmentReadResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, CredentialError, CredentialLease, EnvironmentCredentialResolver,
    NativeProbe, NativeProbeStatus, SecretReferenceResolver, ShippoCredential, ShippoProvider,
    ShippoRegistration, ShippoRegistrationRequest, ShippoRegistrationState,
    native_probe_from_environment,
};
pub use service::{
    ShippoCapability, ShippoFulfillmentResultOperation, ShippoFulfillmentResultService,
};
pub use transport::{
    BlockedEnvTransport, FakeShippoTransport, LoopbackShippoTransport, ProductionShippoTransport,
    RecordingShippoTransport, RequestBounds, ShippoEndpoint, ShippoHttpRequest, ShippoHttpResponse,
    ShippoResponseBody, ShippoTransport, ShippoTransportError, TransportProvenance,
};

pub const SHIPPO_FULFILLMENT_RESULT_SCHEMA_VERSION: &str =
    "hartevo.shippo-fulfillment-result-contract/v1";
pub const SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION: &str = "shippo-fulfillment-result/v1";
pub const SHIPPO_FULFILLMENT_RESULT_PLUGIN_ID: &str = "shippo-fulfillment-result";
pub const SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const SHIPPO_API_VERSION: &str = "2018-02-08";
pub const SHIPPO_API_ORIGIN: &str = "https://api.goshippo.com";
pub const SHIPPO_FULFILLMENT_RESULT_SERVICE_ID: &str = "shippo.fulfillment-result";
pub const SHIPPO_FULFILLMENT_RESULT_SERVICE_NAME: &str = "ShippoFulfillmentResultService";
pub const SHIPPO_PROVIDER_ID: &str = "shippo.provider";
pub const SHIPPO_PROVIDER_NAME: &str = "ShippoProvider";
pub const MISSION_SHIPPO_FULFILLMENT_CONSUMER_ID: &str = "mission.shippo-fulfillment-result";
pub const MISSION_SHIPPO_FULFILLMENT_CONSUMER_NAME: &str = "MissionShippoFulfillmentConsumer";
pub const SHIPPO_FULFILLMENT_RESULT_SERVICE_SCHEMA: &str =
    "hartevo.shippo-fulfillment-result-service/v1";
pub const SHIPPO_PROVIDER_SCHEMA: &str = "hartevo.shippo-provider/v1";
pub const MISSION_SHIPPO_FULFILLMENT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-shippo-fulfillment-consumer/v1";
pub const SHIPPO_PROVIDER_REVISION: &str = "shippo-rest-2018-02-08-r1";
pub const SHIPPO_NATIVE_PROBE_ENV: &str = "HARTEVO_SHIPPO_NATIVE_PROBE";
pub const SHIPPO_NATIVE_PROBE_GATE: &str = "HARTEVO_SHIPPO_NATIVE_PROBE=1";
pub const SHIPPO_API_TOKEN_ENV: &str = "HARTEVO_SHIPPO_API_TOKEN";
pub const SHIPPO_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const SHIPPO_MAX_TRACKING_EVENTS: usize = 128;
pub const SHIPPO_MAX_CARRIER_EVIDENCE: usize = 32;
pub const SHIPPO_MAX_PAGES: u16 = 1;
pub const SHIPPO_MAX_CURSOR_BYTES: usize = 256;
pub const SHIPPO_MAX_WINDOW_DAYS: i64 = 366;
pub const SHIPPO_MAX_RETRIES: u8 = 2;

pub const SHIPPO_FULFILLMENT_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/shippo-fulfillment-result/shippo-fulfillment-result.v1.json"
);

/// Returns the SHA-256 digest of the immutable checked-in contract bytes.
pub fn contract_digest() -> Digest {
    model::sha256_digest(SHIPPO_FULFILLMENT_RESULT_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Builds the runtime contribution set for one exact Project/Mission
/// generation.  The definition is inert until a host mounts it.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, ShippoFulfillmentError> {
    let plugin_id = PluginId::new(SHIPPO_FULFILLMENT_RESULT_PLUGIN_ID)?;
    let service_id = ServiceId::new(SHIPPO_FULFILLMENT_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(SHIPPO_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_SHIPPO_FULFILLMENT_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(SHIPPO_FULFILLMENT_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(SHIPPO_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_SHIPPO_FULFILLMENT_CONSUMER_SCHEMA),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoFulfillmentResultContract {
    pub schema_version: String,
    pub contract_version: String,
    pub layer: u8,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_version: String,
    pub api_origin: String,
    pub api_areas: BTreeMap<String, String>,
    pub transport_provenance: Vec<String>,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub mutating_provider_operations: Vec<String>,
    pub allowlisted_methods: Vec<String>,
    pub forbidden_operations: Vec<String>,
    pub authority: ShippoAuthorityContract,
    pub registration: ShippoRegistrationContract,
    pub scope_fence: Vec<String>,
    pub bounds: ShippoBoundsContract,
    pub redaction: ShippoRedactionContract,
    pub receipts: ShippoReceiptsContract,
    pub status_vocabulary: Vec<String>,
    pub native_gap: ShippoNativeGapContract,
    pub honest_native_gap: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ShippoAuthorityContract {
    pub external_writes: bool,
    pub label_purchase: bool,
    pub label_download: bool,
    pub recipient_pii: bool,
    pub raw_labels: bool,
    pub raw_tracking_payload: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoRegistrationContract {
    pub bound_fields: Vec<String>,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoBoundsContract {
    pub max_response_bytes: usize,
    pub max_tracking_events: usize,
    pub max_carrier_evidence: usize,
    pub max_pages: u16,
    pub max_cursor_bytes: usize,
    pub max_window_days: i64,
    pub max_retries: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ShippoRedactionContract {
    pub recipient_addresses: bool,
    pub recipient_names: bool,
    pub recipient_phones_and_emails: bool,
    pub customs_data: bool,
    pub raw_labels: bool,
    pub raw_tracking_payload: bool,
    pub credential_material: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ShippoReceiptsContract {
    pub request_method_and_path: bool,
    pub api_version: bool,
    pub response_status: bool,
    pub response_size: bool,
    pub response_digest: bool,
    pub provider_revision: bool,
    pub raw_provider_payload: bool,
    pub raw_labels: bool,
    pub raw_tracking_payload: bool,
    pub recipient_pii: bool,
    pub credential_material: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoNativeGapContract {
    pub status: String,
    pub deferred_to: String,
    pub fail_closed_cases: Vec<String>,
}

impl ShippoFulfillmentResultContract {
    pub fn baseline() -> Result<Self, ShippoFulfillmentError> {
        let contract = serde_json::from_str::<Self>(SHIPPO_FULFILLMENT_RESULT_CONTRACT_JSON)
            .map_err(|error| ShippoFulfillmentError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ShippoFulfillmentError> {
        let expected_areas = BTreeMap::from([
            ("shipments".to_owned(), "shipments/{shipment_id}".to_owned()),
            (
                "transactions".to_owned(),
                "transactions/{transaction_id}".to_owned(),
            ),
            (
                "tracking".to_owned(),
                "tracks/{carrier}/{tracking_number}".to_owned(),
            ),
        ]);
        let expected_operations = vec![
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_shipment",
            "read_transaction",
            "read_tracking",
            "compile_proposal",
            "consume_observation",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_provenance = vec![
            "fixture",
            "recording",
            "loopback",
            "blocked_env",
            "production_read",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_bound_fields = vec![
            "pluginVersion",
            "contractVersion",
            "contractDigest",
            "providerId",
            "providerRevision",
            "providerDigest",
            "accountId",
            "secretReference",
            "shipmentId",
            "transactionId",
            "carrier",
            "trackingNumber",
            "projectIdAndRevision",
            "missionIdAndRevision",
            "workProductIdAndRevision",
            "consentScopeAndRevision",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_scope_fence = vec![
            "pluginVersion",
            "contractVersion",
            "contractDigest",
            "providerId",
            "providerRevision",
            "providerDigest",
            "accountId",
            "organizationId",
            "shipmentId",
            "transactionId",
            "carrier",
            "trackingNumber",
            "projectIdAndRevision",
            "missionIdAndRevision",
            "workProductIdAndRevision",
            "consentScopeAndRevision",
            "shipmentRevision",
            "transactionRevision",
            "trackingRevision",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_fail_closed_cases = vec![
            "missing_native_secret_resolution",
            "missing_native_api_token",
            "api_version_drift",
            "provider_or_account_scope_drift",
            "shipment_transaction_tracking_revision_drift",
            "project_mission_work_product_consent_scope_drift",
            "raw_label_or_recipient_pii_request",
            "create_purchase_download_mutation_webhook_payment_request",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_forbidden = vec![
            "create_shipment",
            "create_transaction",
            "purchase_label",
            "download_label",
            "mutate_address",
            "mutate_parcel",
            "register_webhook",
            "payment_or_refund",
            "carrier_command",
            "generic_fulfillment_registry",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_statuses = vec![
            "label_created",
            "in_transit",
            "delivered",
            "exception",
            "returned",
            "unknown",
            "partial",
            "retention_gap",
            "access_lost",
            "provider_unknown",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        if self.schema_version != SHIPPO_FULFILLMENT_RESULT_SCHEMA_VERSION
            || self.contract_version != SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION
            || self.layer != 1
            || self.service_id != SHIPPO_FULFILLMENT_RESULT_SERVICE_ID
            || self.provider_id != SHIPPO_PROVIDER_ID
            || self.consumer_id != MISSION_SHIPPO_FULFILLMENT_CONSUMER_ID
            || self.api_version != SHIPPO_API_VERSION
            || self.api_origin != SHIPPO_API_ORIGIN
            || self.api_areas != expected_areas
            || self.transport_provenance != expected_provenance
            || self.operations != expected_operations
            || !self.read_only
            || !self.mutating_provider_operations.is_empty()
            || self.allowlisted_methods != ["GET"]
            || self.forbidden_operations != expected_forbidden
            || self.registration.bound_fields != expected_bound_fields
            || self.scope_fence != expected_scope_fence
            || self.authority.external_writes
            || self.authority.label_purchase
            || self.authority.label_download
            || self.authority.recipient_pii
            || self.authority.raw_labels
            || self.authority.raw_tracking_payload
            || self.authority.connected
            || self.authority.native_provider
            || self.authority.effect
            || self.authority.receipt
            || self.authority.verification
            || self.authority.outcome
            || self.authority.work_product_adoption
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || self.bounds.max_response_bytes != SHIPPO_MAX_RESPONSE_BYTES
            || self.bounds.max_tracking_events != SHIPPO_MAX_TRACKING_EVENTS
            || self.bounds.max_carrier_evidence != SHIPPO_MAX_CARRIER_EVIDENCE
            || self.bounds.max_pages != SHIPPO_MAX_PAGES
            || self.bounds.max_cursor_bytes != SHIPPO_MAX_CURSOR_BYTES
            || self.bounds.max_window_days != SHIPPO_MAX_WINDOW_DAYS
            || self.bounds.max_retries != SHIPPO_MAX_RETRIES
            || !self.redaction.recipient_addresses
            || !self.redaction.recipient_names
            || !self.redaction.recipient_phones_and_emails
            || !self.redaction.customs_data
            || !self.redaction.raw_labels
            || !self.redaction.raw_tracking_payload
            || !self.redaction.credential_material
            || !self.receipts.request_method_and_path
            || !self.receipts.api_version
            || !self.receipts.response_status
            || !self.receipts.response_size
            || !self.receipts.response_digest
            || !self.receipts.provider_revision
            || self.receipts.raw_provider_payload
            || self.receipts.raw_labels
            || self.receipts.raw_tracking_payload
            || self.receipts.recipient_pii
            || self.receipts.credential_material
            || self.status_vocabulary != expected_statuses
            || self.native_gap.status != "BLOCKED_ENV"
            || self.native_gap.deferred_to
                != "layer_2_native_shippo_credential_and_receipt_authority"
            || self.native_gap.fail_closed_cases != expected_fail_closed_cases
            || !self.honest_native_gap.contains("never Connected")
            || !self.honest_native_gap.contains("raw tracking payloads")
            || !self.honest_native_gap.contains("recipient PII")
        {
            return Err(ShippoFulfillmentError::Contract(
                "Shippo fulfillment-result contract does not match the checked-in Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ShippoFulfillmentError {
    #[error("BLOCKED_ENV: native Shippo credential authority is unavailable")]
    BlockedEnv,
    #[error("Shippo fulfillment-result input is invalid: {0}")]
    InvalidInput(String),
    #[error("Shippo fulfillment-result contract is invalid: {0}")]
    Contract(String),
    #[error("Shippo fulfillment-result scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Shippo fulfillment-result plugin version mismatch")]
    VersionMismatch,
    #[error("Shippo fulfillment-result contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Shippo provider id mismatch")]
    ProviderIdMismatch,
    #[error("Shippo provider revision mismatch")]
    ProviderRevisionMismatch,
    #[error("Shippo registration is revoked")]
    RegistrationRevoked,
    #[error("Shippo registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("Shippo credential lease is invalid or expired")]
    CredentialExpired,
    #[error("Shippo credential resolution failed: {0}")]
    Credential(String),
    #[error("Shippo API version drifted from REST {expected}: {actual}")]
    ApiVersionDrift { expected: String, actual: String },
    #[error("Shippo response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Shippo returned unexpected HTTP status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("Shippo response could not be decoded: {0}")]
    Decode(String),
    #[error("Shippo transport failed: {0}")]
    Transport(String),
    #[error("Shippo request bound is invalid: {0}")]
    RequestBound(String),
    #[error("Shippo shipment id fence mismatch")]
    ShipmentIdMismatch,
    #[error("Shippo transaction id fence mismatch")]
    TransactionIdMismatch,
    #[error("Shippo carrier fence mismatch")]
    CarrierMismatch,
    #[error("Shippo tracking number fence mismatch")]
    TrackingNumberMismatch,
    #[error("Shippo account fence mismatch")]
    AccountMismatch,
    #[error(
        "Shippo response revision fence mismatch for {resource}: expected {expected}, observed {observed}"
    )]
    RevisionMismatch {
        resource: String,
        expected: u64,
        observed: u64,
    },
    #[error("Shippo tracking event bound exceeded")]
    TrackingEventBoundExceeded,
    #[error("Shippo carrier evidence bound exceeded")]
    CarrierEvidenceBoundExceeded,
    #[error("Shippo response retained forbidden payload material")]
    ForbiddenPayloadRetention,
    #[error("Shippo evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("Shippo proposal digest mismatch")]
    ProposalDigestMismatch,
    #[error("Shippo evidence is stale for this Mission consumer")]
    StaleEvidence,
    #[error("Shippo access was lost while reading the provider")]
    AccessLost,
    #[error("Shippo provider returned an unsupported rate limit")]
    RateLimitExceeded,
    #[error("Shippo fulfillment-result plugin runtime rejected the definition: {0}")]
    Plugin(PluginError),
}

impl From<PluginError> for ShippoFulfillmentError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<model::ModelError> for ShippoFulfillmentError {
    fn from(error: model::ModelError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

impl From<transport::ShippoTransportError> for ShippoFulfillmentError {
    fn from(error: transport::ShippoTransportError) -> Self {
        match error {
            transport::ShippoTransportError::BlockedEnv => Self::BlockedEnv,
            transport::ShippoTransportError::ResponseTooLarge { size } => {
                Self::ResponseTooLarge { size }
            }
            transport::ShippoTransportError::AccessLost => Self::AccessLost,
            transport::ShippoTransportError::RateLimited { .. } => Self::RateLimitExceeded,
            other => Self::Transport(other.to_string()),
        }
    }
}

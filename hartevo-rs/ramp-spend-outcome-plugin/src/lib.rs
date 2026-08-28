//! Layer 1 Ramp spend and audit outcome-evidence plugin.
//!
//! This standalone crate is deliberately bounded to read, proposal, and
//! recording seams.  It does not resolve native credentials, make provider
//! writes, configure webhooks, or register any Hartevo kernel authority.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::use_self)]

mod consumer;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::{MissionRampSpendAdoptionProposal, MissionRampSpendConsumer};
pub use model::{
    ActorClass, AmountBucket, AuditEventEvidence, BoundIdentifier, Capabilities, DateWindow,
    DeploymentBinding, Digest, EvidenceReceipt, EvidenceStatus, EvidenceVerification,
    IdentityBinding, MerchantEvidence, MissionBinding, OutcomeProposal, PermissionSnapshot,
    ProjectBinding, RampReadScope, RampSpendScope, RampSpendScopeSpec, RefundState,
    RegistrationReceipt, RegistrationStatus, ReleaseBinding, ReplayFenceDurability, ResourceKind,
    RevocationReceipt, SecretKind, SecretReference, SourceEnvelopeStatus, SpendConstraints,
    SpendEvidence, TransactionEvidence, TransactionState, TransportProvenance, WorkProductBinding,
    canonical_digest, sha256_digest,
};
pub use provider::RampProvider;
pub use service::RampSpendOutcomeService;
pub use transport::{
    BlockedEnvRampTransport, FixtureRampTransport, LoopbackRampTransport,
    OfficialRampApiResponseSpec, OfficialRampApiTransport, RampApiPage, RampAuditEventInput,
    RampAuditEventInputSpec, RampEndpoint, RampMerchantInput, RampMerchantInputSpec,
    RampReadRequest, RampTransactionInput, RampTransactionInputSpec, RampTransport,
    RampTransportError, ReadOperation, RecordingRampTransport, RetryPolicy,
    parse_official_json_page,
};

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const RAMP_SPEND_OUTCOME_SCHEMA_VERSION: &str = "hartevo.ramp-spend-outcome/v1";
pub const RAMP_SPEND_OUTCOME_CONTRACT_PATH: &str =
    "contracts/plugins/ramp-spend-outcome/ramp-spend-outcome.v1.json";
pub const RAMP_SPEND_OUTCOME_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/ramp-spend-outcome/ramp-spend-outcome.v1.json");
pub const RAMP_SPEND_OUTCOME_SERVICE_ID: &str = "ramp.spend-outcome-evidence.read";
pub const RAMP_PROVIDER_ID: &str = "ramp.spend.outcome";
pub const RAMP_PROVIDER_IMPLEMENTATION: &str = "RampProvider";
pub const MISSION_RAMP_SPEND_CONSUMER_ID: &str = "mission.ramp-spend-outcome.consumer";
pub const RAMP_PLUGIN_VERSION: &str = "1.0.0";
pub const RAMP_API_BASE_URL: &str = "https://api.ramp.com";

pub const MAX_DATE_WINDOW_SECONDS: i64 = 7_776_000;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_PAGES: usize = 100;
pub const MAX_TRANSACTIONS: usize = 1_000;
pub const MAX_MERCHANTS: usize = 500;
pub const MAX_AUDIT_EVENTS: usize = 1_000;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_EVENT_TYPE_BYTES: usize = 128;
pub const MAX_CATEGORY_VALUES: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGE_BYTES: usize = 1_048_576;
pub const MAX_RECORD_BYTES: usize = 65_536;
pub const MAX_NESTED_REFERENCES: usize = 32;
pub const MAX_TOTAL_RESPONSE_BYTES: usize = 4_194_304;
pub const MAX_TOTAL_RECORD_BYTES: usize = 1_048_576;
pub const MAX_SPEND_TOTAL_MINOR: i64 = 9_000_000_000_000;
pub const MAX_REPLAY_SCOPES: usize = 256;
pub const MAX_REPLAY_IDENTITIES: usize = MAX_TRANSACTIONS + MAX_MERCHANTS + MAX_AUDIT_EVENTS;
pub const MAX_REPLAY_RECEIPTS: usize = MAX_PAGES;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RampSpendOutcomeError {
    #[error("{field} is empty, invalid, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("the opaque Ramp SecretReference is invalid")]
    InvalidSecretReference,
    #[error("the requested/granted Ramp scope snapshot is invalid or over-privileged")]
    InvalidPermissionSnapshot,
    #[error("the Ramp read scope is missing required permission {scope}")]
    MissingReadScope { scope: &'static str },
    #[error("the date window is not closed, positive, and bounded")]
    InvalidDateWindow,
    #[error("the requested page size is outside the bounded contract")]
    InvalidPageSize,
    #[error("the retry policy is invalid or exceeds the bounded contract")]
    InvalidRetryPolicy,
    #[error("the read attempt number is invalid")]
    InvalidAttempt,
    #[error("the Ramp scope is invalid")]
    InvalidScope,
    #[error("the Ramp date window does not match the registered window")]
    DateWindowMismatch,
    #[error("the Ramp provider/contract/scope registration is required or mismatched")]
    RegistrationMismatch,
    #[error("the Ramp registration has been revoked")]
    RegistrationRevoked,
    #[error("the Ramp registration mutex or deterministic transport was poisoned")]
    TransportPoisoned,
    #[error("the bounded collection {field} exceeded {maximum} items")]
    BoundExceeded { field: &'static str, maximum: usize },
    #[error("Ramp pagination repeated a cursor")]
    CursorLoop,
    #[error("Ramp high-water mark drifted during a bounded read")]
    HighWaterMarkDrift,
    #[error("Ramp evidence was empty")]
    EmptyEvidence,
    #[error("Ramp evidence was partial or not a complete observational result")]
    PartialEvidence,
    #[error("Ramp retention was insufficient for the exact bound")]
    RetentionGap,
    #[error("Ramp access was lost for the exact bound")]
    AccessLost,
    #[error("Ramp provider returned an unknown state or actor/resource class")]
    ProviderUnknown,
    #[error("Ramp response or evidence fingerprint was tampered")]
    ResponseTampered,
    #[error("Ramp request fingerprint was tampered")]
    RequestTampered,
    #[error("Ramp evidence receipt was tampered")]
    ReceiptTampered,
    #[error("Ramp scope or Mission consumer binding did not match")]
    ScopeMismatch,
    #[error("Mission consumer binding is invalid")]
    ConsumerBindingMismatch,
    #[error("the Layer-1 transport cannot claim native or Connected evidence")]
    NativeClassificationMismatch,
    #[error("Ramp provider response is invalid")]
    InvalidResponse,
    #[error("Ramp evidence contains contradictory currency, category, or spend totals")]
    ContradictoryEvidence,
    #[error("Ramp evidence or receipt record identity was replayed")]
    ReplayDetected,
    #[error("independently validated provider/evidence state is required")]
    EvidenceStateRequired,
    #[error("Ramp transport failed: {0}")]
    Transport(#[from] RampTransportError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };
}

impl std::fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    ReadOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceDefinition {
    pub id: String,
    pub version: PluginVersion,
    pub access: AccessMode,
    pub contract_digest: Digest,
    pub authority: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub implementation: String,
    pub scope: Vec<String>,
    pub authentication: Vec<String>,
    pub permissions: Vec<String>,
    pub transport: Vec<String>,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub kind: String,
    pub binding: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RampSpendOutcomePluginDefinition {
    pub schema_version: String,
    pub plugin_id: String,
    pub version: PluginVersion,
    pub contract_digest: Digest,
    pub service: ServiceDefinition,
    pub provider: ProviderDefinition,
    pub consumer: ConsumerDefinition,
    pub reversible: bool,
    pub writes: bool,
    pub arbitrary_queries: bool,
    pub native: bool,
}

impl RampSpendOutcomePluginDefinition {
    pub fn layer1() -> Result<Self, RampSpendOutcomeError> {
        let contract_digest = contract_digest();
        let definition = Self {
            schema_version: RAMP_SPEND_OUTCOME_SCHEMA_VERSION.to_owned(),
            plugin_id: RAMP_PROVIDER_ID.to_owned(),
            version: PluginVersion::V1,
            contract_digest: contract_digest.clone(),
            service: ServiceDefinition {
                id: RAMP_SPEND_OUTCOME_SERVICE_ID.to_owned(),
                version: PluginVersion::V1,
                access: AccessMode::ReadOnly,
                contract_digest,
                authority: "read_only_observational_spend_evidence".to_owned(),
            },
            provider: ProviderDefinition {
                id: RAMP_PROVIDER_ID.to_owned(),
                service_id: RAMP_SPEND_OUTCOME_SERVICE_ID.to_owned(),
                version: PluginVersion::V1,
                implementation: RAMP_PROVIDER_IMPLEMENTATION.to_owned(),
                scope: vec![
                    "business_id_digest".to_owned(),
                    "entity_id_digest".to_owned(),
                    "spend_program_id_digest".to_owned(),
                    "card_id_digest".to_owned(),
                    "vendor_id_digest".to_owned(),
                    "transaction_id_digest".to_owned(),
                    "audit_event_id_digest".to_owned(),
                    "date_window".to_owned(),
                    "project_id".to_owned(),
                    "project_revision".to_owned(),
                    "mission_id".to_owned(),
                    "mission_revision".to_owned(),
                    "work_product_id".to_owned(),
                    "work_product_revision".to_owned(),
                    "deployment_id".to_owned(),
                    "deployment_revision".to_owned(),
                    "release_id".to_owned(),
                    "release_revision".to_owned(),
                    "policy_revision".to_owned(),
                    "currency_code_constraint".to_owned(),
                    "category_id_constraint".to_owned(),
                    "category_name_constraint".to_owned(),
                    "max_spend_total_minor".to_owned(),
                    "expected_spend_total_minor".to_owned(),
                    "requested_read_scopes".to_owned(),
                    "permission_digest".to_owned(),
                    "secret_reference_digest".to_owned(),
                    "registration_digest".to_owned(),
                    "replay_fence_durability".to_owned(),
                ],
                authentication: vec![
                    "oauth_secret_reference".to_owned(),
                    "client_credentials_secret_reference".to_owned(),
                ],
                permissions: vec![
                    "business:read".to_owned(),
                    "entities:read".to_owned(),
                    "spend_programs:read".to_owned(),
                    "funds:read".to_owned(),
                    "cards:read".to_owned(),
                    "merchants:read".to_owned(),
                    "vendors:read".to_owned(),
                    "transactions:read".to_owned(),
                    "audit_logs:read".to_owned(),
                ],
                transport: vec![
                    "official_api_parser".to_owned(),
                    "recording".to_owned(),
                    "fixture".to_owned(),
                    "loopback".to_owned(),
                    "blocked_env".to_owned(),
                ],
                reversible: true,
                revocable: true,
            },
            consumer: ConsumerDefinition {
                id: MISSION_RAMP_SPEND_CONSUMER_ID.to_owned(),
                service_id: RAMP_SPEND_OUTCOME_SERVICE_ID.to_owned(),
                version: PluginVersion::V1,
                kind: "mission_non_mutating_evidence_adoption_proposal".to_owned(),
                binding: vec![
                    "project_id".to_owned(),
                    "project_revision".to_owned(),
                    "mission_id".to_owned(),
                    "mission_revision".to_owned(),
                    "work_product_id".to_owned(),
                    "work_product_revision".to_owned(),
                    "scope_digest".to_owned(),
                    "registration_digest".to_owned(),
                    "provider_digest".to_owned(),
                    "contract_digest".to_owned(),
                    "evidence_digest".to_owned(),
                    "spend_constraints_digest".to_owned(),
                    "verification_digest".to_owned(),
                    "policy_revision".to_owned(),
                ],
            },
            reversible: true,
            writes: false,
            arbitrary_queries: false,
            native: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), RampSpendOutcomeError> {
        let expected_provider_scope = vec![
            "business_id_digest",
            "entity_id_digest",
            "spend_program_id_digest",
            "card_id_digest",
            "vendor_id_digest",
            "transaction_id_digest",
            "audit_event_id_digest",
            "date_window",
            "project_id",
            "project_revision",
            "mission_id",
            "mission_revision",
            "work_product_id",
            "work_product_revision",
            "deployment_id",
            "deployment_revision",
            "release_id",
            "release_revision",
            "policy_revision",
            "currency_code_constraint",
            "category_id_constraint",
            "category_name_constraint",
            "max_spend_total_minor",
            "expected_spend_total_minor",
            "requested_read_scopes",
            "permission_digest",
            "secret_reference_digest",
            "registration_digest",
            "replay_fence_durability",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_consumer_binding = vec![
            "project_id",
            "project_revision",
            "mission_id",
            "mission_revision",
            "work_product_id",
            "work_product_revision",
            "scope_digest",
            "registration_digest",
            "provider_digest",
            "contract_digest",
            "evidence_digest",
            "spend_constraints_digest",
            "verification_digest",
            "policy_revision",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        if self.schema_version != RAMP_SPEND_OUTCOME_SCHEMA_VERSION
            || self.plugin_id != RAMP_PROVIDER_ID
            || self.version != PluginVersion::V1
            || !is_sha256(&self.contract_digest)
            || self.service.id != RAMP_SPEND_OUTCOME_SERVICE_ID
            || self.service.version != PluginVersion::V1
            || self.service.access != AccessMode::ReadOnly
            || self.service.contract_digest != self.contract_digest
            || self.service.authority != "read_only_observational_spend_evidence"
            || self.provider.id != RAMP_PROVIDER_ID
            || self.provider.service_id != self.service.id
            || self.provider.version != PluginVersion::V1
            || self.provider.implementation != RAMP_PROVIDER_IMPLEMENTATION
            || self.provider.authentication.len() != 2
            || self.provider.transport.len() != 5
            || self.provider.scope != expected_provider_scope
            || !self.provider.reversible
            || !self.provider.revocable
            || self.consumer.id != MISSION_RAMP_SPEND_CONSUMER_ID
            || self.consumer.service_id != self.service.id
            || self.consumer.version != PluginVersion::V1
            || self.consumer.binding != expected_consumer_binding
            || !self.reversible
            || self.writes
            || self.arbitrary_queries
            || self.native
        {
            return Err(RampSpendOutcomeError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        canonical_digest(&self.provider)
    }
}

#[must_use]
pub fn contract_digest() -> Digest {
    format!(
        "{:x}",
        Sha256::digest(RAMP_SPEND_OUTCOME_CONTRACT_JSON.as_bytes())
    )
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Minimal contract validation used by the scoped gate and crate tests.  The
/// JSON document is also intentionally checked for valid JSON and frozen
/// identity values without introducing a dependency on a global schema crate.
pub fn validate_contract_document() -> Result<(), RampSpendOutcomeError> {
    let document: serde_json::Value = serde_json::from_str(RAMP_SPEND_OUTCOME_CONTRACT_JSON)
        .map_err(|_| RampSpendOutcomeError::InvalidResponse)?;
    let properties = document
        .get("properties")
        .ok_or(RampSpendOutcomeError::InvalidResponse)?;
    let schema_version = properties
        .get("schemaVersion")
        .and_then(|value| value.get("const"))
        .and_then(serde_json::Value::as_str);
    let layer = properties
        .get("layer")
        .and_then(|value| value.get("const"))
        .and_then(serde_json::Value::as_str);
    let authority = properties
        .get("authority")
        .and_then(|value| value.get("const"))
        .and_then(serde_json::Value::as_str);
    if schema_version != Some(RAMP_SPEND_OUTCOME_SCHEMA_VERSION)
        || layer != Some("ramp_spend_outcome_layer_1")
        || authority != Some("read_only_observational_spend_evidence")
    {
        return Err(RampSpendOutcomeError::InvalidResponse);
    }
    let bound_const = |name: &str| {
        properties
            .get("bounds")
            .and_then(|bounds| bounds.get("properties"))
            .and_then(|bounds| bounds.get(name))
            .and_then(|bound| bound.get("const"))
            .and_then(serde_json::Value::as_u64)
    };
    let expected_bounds = [
        ("maxCategoryValues", MAX_CATEGORY_VALUES as u64),
        ("maxNestedReferences", MAX_NESTED_REFERENCES as u64),
        ("maxResponseBytes", MAX_RESPONSE_BYTES as u64),
        ("maxPageBytes", MAX_PAGE_BYTES as u64),
        ("maxRecordBytes", MAX_RECORD_BYTES as u64),
        ("maxTotalResponseBytes", MAX_TOTAL_RESPONSE_BYTES as u64),
        ("maxTotalRecordBytes", MAX_TOTAL_RECORD_BYTES as u64),
        ("maxSpendTotalMinor", MAX_SPEND_TOTAL_MINOR as u64),
        ("maxReplayScopes", MAX_REPLAY_SCOPES as u64),
        ("maxReplayIdentities", MAX_REPLAY_IDENTITIES as u64),
        ("maxReplayReceipts", MAX_REPLAY_RECEIPTS as u64),
    ];
    if expected_bounds
        .iter()
        .any(|(name, expected)| bound_const(name) != Some(*expected))
    {
        return Err(RampSpendOutcomeError::InvalidResponse);
    }
    let section_true = |section: &str, name: &str| {
        properties
            .get(section)
            .and_then(|value| value.get("properties"))
            .and_then(|value| value.get(name))
            .and_then(|value| value.get("const"))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    };
    if !section_true("scope", "currencyCategoryTotalBound")
        || !section_true("scope", "ingressByteAccountingBound")
        || !section_true("scope", "sourceEnvelopeCompletenessBound")
        || !section_true("transport", "rawResponseBodyBounds")
        || !section_true("transport", "rawRecordBounds")
        || !section_true("transport", "globalByteBudget")
        || !section_true("transport", "processSharedReplayFence")
        || !section_true("transport", "authenticatedIngressByteAccounting")
        || !section_true("transport", "preRetentionCardinalityBounds")
        || !section_true("transport", "missingEnvelopeFailClosed")
        || !section_true("projections", "byteAccountingExplicit")
        || !section_true("projections", "sourceEnvelopeCompletenessExplicit")
    {
        return Err(RampSpendOutcomeError::InvalidResponse);
    }
    let replay_durability = properties
        .get("honesty")
        .and_then(|value| value.get("properties"))
        .and_then(|value| value.get("replayFenceDurability"))
        .and_then(|value| value.get("const"))
        .and_then(serde_json::Value::as_str);
    if replay_durability != Some("process_shared_non_durable") {
        return Err(RampSpendOutcomeError::InvalidResponse);
    }
    RampSpendOutcomePluginDefinition::layer1().map(|_| ())
}

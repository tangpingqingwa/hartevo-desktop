//! Standalone Layer-1 BrowserStack Automate/App Automate test-result plugin.
//!
//! The root is deliberately bounded to typed build/session metadata and
//! recording evidence. It has no upload, launch, mark-pass/fail, rename,
//! delete, debugging-media, arbitrary-capability, or kernel-authority seam.

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
    BrowserStackObservation, MissionBrowserStackResultState, MissionBrowserStackTestConsumer,
    MissionBrowserStackTestResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, BrowserStackCredentialError, BrowserStackCredentialLease,
    BrowserStackCredentialResolver, BrowserStackProvider, BrowserStackProviderDefinition,
    BrowserStackRegistration, BrowserStackRegistrationRequest, FixtureCredentialResolver,
    RegistrationRevocation, RegistrationState,
};
pub use service::{
    BrowserStackCapability, BrowserStackTestResultOperation, BrowserStackTestResultService,
};
pub use transport::{
    BlockedEnvTransport, BrowserStackEndpoint, BrowserStackHttpRequest, BrowserStackHttpResponse,
    BrowserStackTransport, BrowserStackTransportAttestation, BrowserStackTransportError,
    FakeBrowserStackTransport, LoopbackBrowserStackTransport, RecordingBrowserStackTransport,
};

pub const BROWSERSTACK_SCHEMA_VERSION: &str = "hartevo.browserstack-test-result.contract/v1";
pub const BROWSERSTACK_CONTRACT_VERSION: &str = "browserstack-test-result/v1";
pub const BROWSERSTACK_PLUGIN_ID: &str = "browserstack-test-result";
pub const BROWSERSTACK_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const BROWSERSTACK_SERVICE_ID: &str = "browserstack.test-result";
pub const BROWSERSTACK_SERVICE_NAME: &str = "BrowserStackTestResultService";
pub const BROWSERSTACK_PROVIDER_ID: &str = "browserstack.automate-test-result";
pub const BROWSERSTACK_PROVIDER_NAME: &str = "BrowserStackProvider";
pub const MISSION_BROWSERSTACK_CONSUMER_ID: &str = "mission.browserstack-test-result";
pub const MISSION_BROWSERSTACK_CONSUMER_NAME: &str = "MissionBrowserStackTestConsumer";
pub const BROWSERSTACK_SERVICE_SCHEMA: &str = "hartevo.browserstack-test-result-service/v1";
pub const BROWSERSTACK_PROVIDER_SCHEMA: &str = "hartevo.browserstack-provider/v1";
pub const MISSION_BROWSERSTACK_CONSUMER_SCHEMA: &str =
    "hartevo.mission-browserstack-test-consumer/v1";
pub const BROWSERSTACK_PROVIDER_REVISION: &str = "browserstack-rest-automate-app-automate-r1";
pub const BROWSERSTACK_AUTOMATE_API_ORIGIN: &str = "https://api.browserstack.com";
pub const BROWSERSTACK_APP_AUTOMATE_API_ORIGIN: &str = "https://api-cloud.browserstack.com";
pub const BROWSERSTACK_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const BROWSERSTACK_MAX_PAGES: u16 = 4;
pub const BROWSERSTACK_MAX_PAGE_SIZE: u16 = 100;
pub const BROWSERSTACK_MAX_SESSIONS: usize = 128;
pub const BROWSERSTACK_MAX_OUTCOME_COUNT: u32 = 10_000;
pub const BROWSERSTACK_MAX_RECEIPTS: usize = 32;

pub const BROWSERSTACK_TEST_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/browserstack-test-result/browserstack-test-result.v1.json"
);

/// Returns the digest of the checked-in contract bytes, not a digest of a
/// parsed or reserialized JSON value.
pub fn contract_digest() -> Digest {
    model::sha256_digest(BROWSERSTACK_TEST_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Builds inert plugin-runtime contributions. Mounting and native authority
/// remain host responsibilities outside this standalone Layer-1 root.
pub fn plugin_definition(
    scope: PluginScope,
) -> Result<PluginDefinition, BrowserStackTestResultError> {
    let plugin_id = PluginId::new(BROWSERSTACK_PLUGIN_ID)?;
    let service_id = ServiceId::new(BROWSERSTACK_SERVICE_ID)?;
    let provider_id = ProviderId::new(BROWSERSTACK_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_BROWSERSTACK_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(BROWSERSTACK_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(BROWSERSTACK_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_BROWSERSTACK_CONSUMER_SCHEMA),
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
pub struct BrowserStackTestResultContract {
    #[serde(rename = "$schema", default)]
    pub json_schema: Option<String>,
    #[serde(rename = "$id", default)]
    pub json_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub layer: u8,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub products: Vec<String>,
    pub official_rest_apis: BTreeMap<String, String>,
    pub transport_provenance: Vec<String>,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub mutating_provider_operations: Vec<String>,
    pub scope: Vec<String>,
    pub digests: Vec<String>,
    pub authority: BrowserStackAuthorityContract,
    pub registration: BrowserStackRegistrationContract,
    pub bounds: BrowserStackBoundsContract,
    pub evidence: BrowserStackEvidenceContract,
    pub replay_fence: BrowserStackReplayFenceContract,
    pub forbidden: Vec<String>,
    pub native_gap: BrowserStackNativeGapContract,
    pub honest_native_gap: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct BrowserStackAuthorityContract {
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub upload: bool,
    pub test_launch: bool,
    pub mark_pass_fail: bool,
    pub rename_delete: bool,
    pub raw_logs: bool,
    pub raw_network: bool,
    pub raw_har: bool,
    pub raw_video: bool,
    pub raw_screenshots: bool,
    pub arbitrary_capabilities: bool,
    pub truth: bool,
    pub consent: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackRegistrationContract {
    pub version_bound: bool,
    pub contract_digest_bound: bool,
    pub provider_digest_bound: bool,
    pub scope_digest_bound: bool,
    pub permission_digest_bound: bool,
    pub secret_reference_digest_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackBoundsContract {
    pub max_response_bytes: usize,
    pub max_pages: u16,
    pub max_page_size: u16,
    pub max_sessions: usize,
    pub max_outcome_count: u32,
    pub max_receipts: usize,
    pub max_identifier_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackEvidenceContract {
    pub build_metadata: Vec<String>,
    pub session_metadata: Vec<String>,
    pub outcome_counts: Vec<String>,
    pub pagination: String,
    pub rate_limits: Vec<u16>,
    pub response_digest: bool,
    pub raw_provider_payload_retained: bool,
    pub credential_material_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackNativeGapContract {
    pub status: String,
    pub deferred_to: String,
    pub fixture_recording_loopback_blocked_env_are_native: bool,
    pub connected_claim: bool,
    pub fail_closed_cases: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStackReplayFenceContract {
    pub scope: String,
    pub shared_across_sibling_consumers: bool,
    pub monotonic_use_revision: bool,
    pub restart_persistence: bool,
}

impl BrowserStackTestResultContract {
    pub fn baseline() -> Result<Self, BrowserStackTestResultError> {
        let contract = serde_json::from_str::<Self>(BROWSERSTACK_TEST_RESULT_CONTRACT_JSON)
            .map_err(|error| BrowserStackTestResultError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    fn authority_is_empty(&self) -> bool {
        let authority = &self.authority;
        [
            authority.connected,
            authority.native,
            authority.external_writes,
            authority.upload,
            authority.test_launch,
            authority.mark_pass_fail,
            authority.rename_delete,
            authority.raw_logs,
            authority.raw_network,
            authority.raw_har,
            authority.raw_video,
            authority.raw_screenshots,
            authority.arbitrary_capabilities,
            authority.truth,
            authority.consent,
            authority.effect,
            authority.receipt,
            authority.verification,
            authority.outcome,
            authority.work_product_adoption,
        ]
        .into_iter()
        .all(|flag| !flag)
    }

    fn registration_is_bound(&self) -> bool {
        self.registration.version_bound
            && self.registration.contract_digest_bound
            && self.registration.provider_digest_bound
            && self.registration.scope_digest_bound
            && self.registration.permission_digest_bound
            && self.registration.secret_reference_digest_bound
            && self.registration.reversible
            && self.registration.revocable
            && self.registration.fail_closed_on
                == vec![
                    "provider_revision_drift".to_owned(),
                    "scope_drift".to_owned(),
                    "build_revision_drift".to_owned(),
                    "session_revision_drift".to_owned(),
                    "commit_mismatch".to_owned(),
                    "artifact_mismatch".to_owned(),
                    "permission_drift".to_owned(),
                    "registration_tamper".to_owned(),
                    "registration_revocation".to_owned(),
                    "evidence_replay".to_owned(),
                    "service_revocation".to_owned(),
                    "bounds_drift".to_owned(),
                    "matrix_invalid".to_owned(),
                    "unattested_transport".to_owned(),
                    "provenance_override".to_owned(),
                    "response_integrity".to_owned(),
                    "serde_invalid".to_owned(),
                ]
    }

    fn evidence_is_bounded(&self) -> bool {
        self.bounds.max_response_bytes == BROWSERSTACK_MAX_RESPONSE_BYTES
            && self.bounds.max_pages == BROWSERSTACK_MAX_PAGES
            && self.bounds.max_page_size == BROWSERSTACK_MAX_PAGE_SIZE
            && self.bounds.max_sessions == BROWSERSTACK_MAX_SESSIONS
            && self.bounds.max_outcome_count == BROWSERSTACK_MAX_OUTCOME_COUNT
            && self.bounds.max_receipts == BROWSERSTACK_MAX_RECEIPTS
            && self.bounds.max_identifier_bytes == model::MAX_IDENTIFIER_BYTES
            && self.evidence.pagination == "bounded_offset_loop_with_repeat_detection"
            && self.evidence.rate_limits == vec![401, 403, 404, 409, 429, 500, 502, 503, 504]
            && self.evidence.response_digest
            && !self.evidence.raw_provider_payload_retained
            && !self.evidence.credential_material_retained
    }

    fn replay_and_native_gap_are_fenced(&self) -> bool {
        self.replay_fence.scope == "process_local"
            && self.replay_fence.shared_across_sibling_consumers
            && self.replay_fence.monotonic_use_revision
            && !self.replay_fence.restart_persistence
            && self.native_gap.status == "BLOCKED_ENV"
            && self.native_gap.fail_closed_cases
                == vec![
                    "missing_secret_authority".to_owned(),
                    "scope_or_revision_drift".to_owned(),
                    "artifact_or_commit_mismatch".to_owned(),
                    "provider_deletion_or_access_loss".to_owned(),
                    "retention_expiry".to_owned(),
                    "partial_page_or_rate_limit".to_owned(),
                    "tampered_or_unredacted_recording".to_owned(),
                    "evidence_replay".to_owned(),
                    "service_revocation".to_owned(),
                    "external_write_request".to_owned(),
                    "unattested_transport".to_owned(),
                    "provenance_override".to_owned(),
                    "response_integrity".to_owned(),
                    "serde_invalid".to_owned(),
                ]
            && !self
                .native_gap
                .fixture_recording_loopback_blocked_env_are_native
            && !self.native_gap.connected_claim
            && self.honest_native_gap.contains("never claims Connected")
            && self.honest_native_gap.contains("raw provider payloads")
            && self.honest_native_gap.contains("attested")
            && self.honest_native_gap.contains("process-local")
    }

    pub fn validate(&self) -> Result<(), BrowserStackTestResultError> {
        let expected_products = vec!["automate".to_owned(), "app_automate".to_owned()];
        let expected_apis = BTreeMap::from([
            (
                "appAutomate".to_owned(),
                BROWSERSTACK_APP_AUTOMATE_API_ORIGIN.to_owned() + "/app-automate",
            ),
            (
                "automate".to_owned(),
                BROWSERSTACK_AUTOMATE_API_ORIGIN.to_owned() + "/automate",
            ),
        ]);
        if self.schema_version != BROWSERSTACK_SCHEMA_VERSION
            || self.contract_version != BROWSERSTACK_CONTRACT_VERSION
            || self.plugin_version != BROWSERSTACK_PLUGIN_VERSION_TEXT
            || self.layer != 1
            || self.service_id != BROWSERSTACK_SERVICE_ID
            || self.provider_id != BROWSERSTACK_PROVIDER_ID
            || self.consumer_id != MISSION_BROWSERSTACK_CONSUMER_ID
            || self.products != expected_products
            || self.official_rest_apis != expected_apis
            || self.transport_provenance
                != vec![
                    "fixture".to_owned(),
                    "recording".to_owned(),
                    "loopback".to_owned(),
                    "BLOCKED_ENV".to_owned(),
                ]
            || !self.read_only
            || !self.mutating_provider_operations.is_empty()
            || !self.authority_is_empty()
            || !self.registration_is_bound()
            || !self.evidence_is_bounded()
            || !self.replay_and_native_gap_are_fenced()
        {
            return Err(BrowserStackTestResultError::Contract(
                "BrowserStack test-result contract does not match the checked-in Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BrowserStackTestResultError {
    #[error("BrowserStack test-result input is invalid: {0}")]
    InvalidInput(String),
    #[error("BrowserStack test-result contract is invalid: {0}")]
    Contract(String),
    #[error("BrowserStack test-result scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("BrowserStack test-result registration is revoked")]
    RegistrationRevoked,
    #[error("BrowserStack test-result registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("BrowserStack test-result registration digest mismatch")]
    RegistrationDigestMismatch,
    #[error("BrowserStack SecretReference is revoked")]
    SecretRevoked,
    #[error("BrowserStack credential lease is invalid or expired")]
    CredentialExpired,
    #[error("BrowserStack credential resolution failed: {0}")]
    Credential(String),
    #[error("BLOCKED_ENV: BrowserStack native credential/transport authority is unavailable")]
    BlockedEnv,
    #[error("BrowserStack provider revision drifted: expected {expected}, actual {actual}")]
    ProviderRevisionDrift { expected: String, actual: String },
    #[error("BrowserStack response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("BrowserStack returned unexpected HTTP status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("BrowserStack response could not be decoded: {0}")]
    Decode(String),
    #[error("BrowserStack transport failed: {0}")]
    Transport(String),
    #[error("BrowserStack transport is unattested for Layer 1")]
    UnattestedTransport,
    #[error("BrowserStack pagination exceeded its bound or repeated an offset")]
    PaginationLoop,
    #[error("BrowserStack session bound exceeded")]
    SessionBoundExceeded,
    #[error("BrowserStack outcome-count bound exceeded")]
    OutcomeBoundExceeded,
    #[error("BrowserStack build was not returned")]
    BuildNotFound,
    #[error("BrowserStack session was not returned")]
    SessionNotFound,
    #[error("BrowserStack build revision fence mismatch")]
    BuildRevisionMismatch,
    #[error("BrowserStack session revision fence mismatch")]
    SessionRevisionMismatch,
    #[error("BrowserStack product or project fence mismatch")]
    ProductOrProjectMismatch,
    #[error("BrowserStack commit fence mismatch")]
    CommitMismatch,
    #[error("BrowserStack artifact fence mismatch")]
    ArtifactMismatch,
    #[error("BrowserStack response retained forbidden payload or credential material")]
    ForbiddenPayloadRetention,
    #[error("BrowserStack evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("BrowserStack evidence is stale or tampered")]
    StaleEvidence,
    #[error("BrowserStack evidence has already been consumed for this registration")]
    EvidenceReplay,
    #[error("BrowserStack consumer is revoked")]
    ConsumerRevoked,
    #[error("BrowserStack consumer registration mismatch")]
    ConsumerRegistrationMismatch,
    #[error("BrowserStack plugin runtime rejected the definition: {0}")]
    Plugin(PluginError),
}

impl From<PluginError> for BrowserStackTestResultError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<model::ModelError> for BrowserStackTestResultError {
    fn from(error: model::ModelError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

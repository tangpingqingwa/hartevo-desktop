//! Standalone Layer-1 Workday business-process result plugin.
//!
//! The root contributes bounded Events, RaaS, and WQL read evidence to a
//! Mission decision proposal. It is deliberately not a Workday credential,
//! Connected/native provider, effect authority, receipt authority, Truth
//! authority, or Work Product adoption authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]

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
    AdoptionAvailability, ConsumerError, ConsumerRegistration,
    MissionWorkdayBusinessProcessConsumer, MissionWorkdayBusinessProcessResult,
};
pub use model::{
    ApiVersion, BusinessObjectId, BusinessObjectReference, BusinessProcessEventId,
    BusinessProcessId, BusinessProcessStatus, ConsentScope, ConsentState, Digest, EvidenceQuality,
    MissionId, MissionResultState, ModelError, ProjectId, ProviderErrorKind, ProviderRevision,
    ReadBounds, ReadKind, RedactionSummary, RegistrationState, ReportId, Revision, SecretReference,
    StepId, StepReference, StepView, TenantId, TenantRegion, TimeWindow, TransportProvenance,
    WorkProductId, WorkdayAttachmentPayload, WorkdayBusinessProcessResultEvidence, WorkdayEndpoint,
    WorkdayEventPayload, WorkdayEventProjection, WorkdayField, WorkdayReadRequest,
    WorkdayResponseReceipt, WorkdayScope, WorkdayScopeInput, WorkdayStepPayload,
    WorkdayStepProjection, WorkdayWorkerPayload, WorkerReference, WorkerReferenceKind,
    WqlDataSource,
};
pub use provider::{
    ProviderDefinitionError, ProviderProvenance, WorkdayProvider, WorkdayProviderDefinition,
    WorkdayRegistration,
};
pub use service::{
    EffectAvailability, Layer1AuthorityView, ReadBackAvailability, ReceiptAvailability,
    WorkdayBusinessProcessResultOperation, WorkdayBusinessProcessResultProposal,
    WorkdayBusinessProcessResultService, WorkdayCapability, WorkdayDecisionAction,
    WorkdayDecisionProposal, WorkdayEffectKind, WorkdayEffectProposal, WorkdayReadBackProposal,
};
pub use transport::{
    BlockedEnvWorkdayTransport, FakeWorkdayTransport, FixtureWorkdayTransport,
    LoopbackWorkdayTransport, RecordingWorkdayTransport, TransportError, WorkdayHttpRequest,
    WorkdayHttpResponse, WorkdayTransport,
};

pub const WORKDAY_BUSINESS_PROCESS_RESULT_SCHEMA_VERSION: &str =
    "hartevo.workday-business-process-result-contract/v1";
pub const WORKDAY_BUSINESS_PROCESS_RESULT_CONTRACT_VERSION: &str =
    "workday-business-process-result/v1";
pub const WORKDAY_BUSINESS_PROCESS_RESULT_PLUGIN_ID: &str = "workday-business-process-result";
pub const WORKDAY_BUSINESS_PROCESS_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const WORKDAY_API_VERSION: &str = "v1";
pub const WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_ID: &str = "workday.business-process.result";
pub const WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_NAME: &str =
    "WorkdayBusinessProcessResultService";
pub const WORKDAY_PROVIDER_ID: &str = "workday.events-raas-wql";
pub const WORKDAY_PROVIDER_NAME: &str = "WorkdayProvider";
pub const MISSION_WORKDAY_BUSINESS_PROCESS_RESULT_CONSUMER_ID: &str =
    "mission.workday-business-process-result";
pub const MISSION_WORKDAY_BUSINESS_PROCESS_RESULT_CONSUMER_NAME: &str =
    "MissionWorkdayBusinessProcessConsumer";
pub const WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_SCHEMA: &str =
    "hartevo.workday-business-process-result-service/v1";
pub const WORKDAY_PROVIDER_SCHEMA: &str = "hartevo.workday-provider/v1";
pub const MISSION_WORKDAY_BUSINESS_PROCESS_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-workday-business-process-result-consumer/v1";
pub const WORKDAY_PROVIDER_REVISION: &str = "workday-rest-events-raas-wql-v1-r1";
pub const WORKDAY_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const WORKDAY_MAX_EVENTS: u16 = 16;
pub const WORKDAY_MAX_STEPS: u16 = 128;
pub const WORKDAY_MAX_ROWS: u32 = 500;
pub const WORKDAY_MAX_PAGES: u16 = 4;
pub const WORKDAY_PAGE_SIZE: u16 = 50;
pub const WORKDAY_MAX_WINDOW_DAYS: i64 = 31;

pub const WORKDAY_BUSINESS_PROCESS_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/workday-business-process-result/workday-business-process-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_bytes(WORKDAY_BUSINESS_PROCESS_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// The authority exposed by this Layer-1 root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn effect() -> bool {
        false
    }

    pub const fn native_receipt() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn exact_read_back() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, WorkdayError> {
    let plugin_id = PluginId::new(WORKDAY_BUSINESS_PROCESS_RESULT_PLUGIN_ID)?;
    let service_id = ServiceId::new(WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(WORKDAY_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_WORKDAY_BUSINESS_PROCESS_RESULT_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(WORKDAY_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_WORKDAY_BUSINESS_PROCESS_RESULT_CONSUMER_SCHEMA),
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
pub struct WorkdayContract {
    pub schema_version: String,
    pub contract_version: String,
    pub layer: u8,
    pub service: WorkdayServiceContract,
    pub provider: WorkdayProviderContract,
    pub consumer: WorkdayConsumerContract,
    pub api_version: String,
    pub transport_provenance: Vec<String>,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub mutating_provider_operations: Vec<String>,
    pub authority: WorkdayAuthorityContract,
    pub registration: WorkdayRegistrationContract,
    pub scope_fence: Vec<String>,
    pub bounds: WorkdayBoundsContract,
    pub redaction: WorkdayRedactionContract,
    pub receipts: WorkdayReceiptsContract,
    pub seams: BTreeMap<String, String>,
    pub native_gap: WorkdayNativeGapContract,
    pub honest_native_gap: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayServiceContract {
    pub id: String,
    pub name: String,
    pub read_only: bool,
    pub live_execution: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayProviderContract {
    pub id: String,
    pub name: String,
    pub native: bool,
    pub capabilities: Vec<String>,
    pub mutating_operations: Vec<String>,
    pub official_api_seams: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayConsumerContract {
    pub id: String,
    pub name: String,
    pub adopts_outcome: bool,
    pub truth_authority: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayAuthorityContract {
    pub external_writes: bool,
    pub payroll_compensation: bool,
    pub raw_worker_pii: bool,
    pub raw_comments: bool,
    pub raw_attachments: bool,
    pub connected: bool,
    pub effect: bool,
    pub receipt: bool,
    pub read_back: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayRegistrationContract {
    pub bound_fields: Vec<String>,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayBoundsContract {
    pub max_response_bytes: usize,
    pub max_events: u16,
    pub max_steps: u16,
    pub max_rows: u32,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_window_days: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayRedactionContract {
    pub worker_pii: bool,
    pub comments: bool,
    pub attachments: bool,
    pub payroll_and_compensation: bool,
    pub raw_provider_payload: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayReceiptsContract {
    pub request_path_and_query: bool,
    pub api_version: bool,
    pub response_status: bool,
    pub response_size: bool,
    pub response_digest: bool,
    pub provider_revision: bool,
    pub freshness: bool,
    pub raw_provider_payload: bool,
    pub credential_material: bool,
    pub native_receipt: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayNativeGapContract {
    pub status: String,
    pub deferred_to: String,
    pub fail_closed_cases: Vec<String>,
}

impl WorkdayContract {
    pub fn baseline() -> Result<Self, WorkdayError> {
        let contract = serde_json::from_str::<Self>(WORKDAY_BUSINESS_PROCESS_RESULT_CONTRACT_JSON)
            .map_err(|error| WorkdayError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), WorkdayError> {
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_events",
            "read_raas",
            "read_wql",
            "consume_result",
            "prepare_effect",
            "prepare_read_back",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_provenance = ["recording", "fixture", "loopback", "blocked_env"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if self.schema_version != WORKDAY_BUSINESS_PROCESS_RESULT_SCHEMA_VERSION
            || self.contract_version != WORKDAY_BUSINESS_PROCESS_RESULT_CONTRACT_VERSION
            || self.layer != 1
            || self.service.id != WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_ID
            || self.service.name != WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_NAME
            || !self.service.read_only
            || self.service.live_execution
            || self.provider.id != WORKDAY_PROVIDER_ID
            || self.provider.name != WORKDAY_PROVIDER_NAME
            || self.provider.native
            || self.provider.capabilities
                != vec![
                    "events_read".to_owned(),
                    "raas_read".to_owned(),
                    "wql_read".to_owned(),
                ]
            || !self.provider.mutating_operations.is_empty()
            || self.provider.official_api_seams
                != vec![
                    "businessProcess/events".to_owned(),
                    "RaaS".to_owned(),
                    "WQL".to_owned(),
                ]
            || self.consumer.id != MISSION_WORKDAY_BUSINESS_PROCESS_RESULT_CONSUMER_ID
            || self.consumer.name != MISSION_WORKDAY_BUSINESS_PROCESS_RESULT_CONSUMER_NAME
            || self.consumer.adopts_outcome
            || self.consumer.truth_authority
            || self.consumer.work_product_adoption
            || self.api_version != WORKDAY_API_VERSION
            || self.transport_provenance != expected_provenance
            || self.operations != expected_operations
            || !self.read_only
            || !self.mutating_provider_operations.is_empty()
            || self.authority.external_writes
            || self.authority.payroll_compensation
            || self.authority.raw_worker_pii
            || self.authority.raw_comments
            || self.authority.raw_attachments
            || self.authority.connected
            || self.authority.effect
            || self.authority.receipt
            || self.authority.read_back
            || self.authority.verification
            || self.authority.outcome
            || self.authority.work_product_adoption
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || self.bounds.max_response_bytes != WORKDAY_MAX_RESPONSE_BYTES
            || self.bounds.max_events != WORKDAY_MAX_EVENTS
            || self.bounds.max_steps != WORKDAY_MAX_STEPS
            || self.bounds.max_rows != WORKDAY_MAX_ROWS
            || self.bounds.max_pages != WORKDAY_MAX_PAGES
            || self.bounds.page_size != WORKDAY_PAGE_SIZE
            || self.bounds.max_window_days != WORKDAY_MAX_WINDOW_DAYS
            || !self.redaction.worker_pii
            || !self.redaction.comments
            || !self.redaction.attachments
            || !self.redaction.payroll_and_compensation
            || self.redaction.raw_provider_payload
            || self.receipts.raw_provider_payload
            || self.receipts.credential_material
            || self.receipts.native_receipt
            || self.native_gap.status != "BLOCKED_ENV"
            || !self
                .honest_native_gap
                .contains("does not resolve Workday OAuth")
            || !self
                .honest_native_gap
                .contains("claim Connected/native status")
            || !self
                .honest_native_gap
                .contains("mint a native Effect or Receipt")
            || !self.honest_native_gap.contains("adopt a kernel Outcome")
        {
            return Err(WorkdayError::Contract(
                "Workday business-process result contract does not match the checked-in Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WorkdayError {
    #[error("BLOCKED_ENV: native Workday credential authority is unavailable")]
    BlockedEnv,
    #[error("Workday input is invalid: {0}")]
    InvalidInput(String),
    #[error("Workday contract is invalid: {0}")]
    Contract(String),
    #[error("Workday scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Workday plugin version mismatch")]
    VersionMismatch,
    #[error("Workday contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Workday registration is revoked")]
    RegistrationRevoked,
    #[error("Workday registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("Workday consent is expired or not allowlisted")]
    ConsentMismatch,
    #[error("Workday API version drifted from {expected}: {actual}")]
    ApiVersionDrift { expected: String, actual: String },
    #[error("Workday response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Workday returned unexpected HTTP status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("Workday response could not be decoded: {0}")]
    Decode(String),
    #[error("Workday transport failed: {0}")]
    Transport(String),
    #[error("Workday evidence fence is invalid: {0}")]
    FenceMismatch(String),
    #[error("Workday evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("Mission Workday consumer rejected the proposal: {0}")]
    Consumer(String),
    #[error("Workday provider definition is invalid: {0}")]
    ProviderDefinition(String),
    #[error("Workday plugin runtime rejected the definition: {0}")]
    Plugin(PluginError),
}

impl From<PluginError> for WorkdayError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<ModelError> for WorkdayError {
    fn from(error: ModelError) -> Self {
        match error {
            ModelError::ConsentMismatch => Self::ConsentMismatch,
            ModelError::ScopeMismatch => {
                Self::ScopeMismatch("model scope fence rejected read".to_owned())
            }
            ModelError::FenceMismatch => {
                Self::FenceMismatch("model revision fence rejected response".to_owned())
            }
            ModelError::DigestMismatch => Self::EvidenceDigestMismatch,
            other => Self::InvalidInput(other.to_string()),
        }
    }
}

impl From<ProviderDefinitionError> for WorkdayError {
    fn from(error: ProviderDefinitionError) -> Self {
        Self::ProviderDefinition(error.to_string())
    }
}

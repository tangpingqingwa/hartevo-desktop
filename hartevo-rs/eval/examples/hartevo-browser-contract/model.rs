use std::fmt;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ExecutionStatus {
    #[serde(rename = "IMPLEMENTED_DEFAULT_TEST")]
    ImplementedDefaultTest,
    #[serde(rename = "IMPLEMENTED_IGNORED_ENV_TEST")]
    ImplementedIgnoredEnvTest,
    #[serde(rename = "NOT_IMPLEMENTED")]
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EvidenceCeiling {
    #[serde(rename = "E2_LOCAL")]
    E2Local,
    #[serde(rename = "NONE")]
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignKind {
    SingleCase,
    #[serde(rename = "journey_30")]
    Journey30,
    Race,
    ProcessKill,
    #[serde(rename = "soak_8h")]
    Soak8h,
    ResourceCost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogRegistryBinding {
    pub snapshot_schema_version: String,
    pub snapshot_digest: String,
    pub route_graph_contract_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseEvidenceContractBinding {
    pub schema_version: String,
    pub mapping_authority: String,
    pub writes_release_evidence: bool,
    pub clears_evaluation_run_result_references: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogMetadataReferencePolicy {
    pub allowed_suite_ids: Vec<String>,
    pub authority: String,
    pub increments_executed_cross_cutting_case_count: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct BrowserEvidencePolicy {
    pub allowed_dispositions: Vec<String>,
    pub zero_executed_cases_can_pass: bool,
    pub ignored_can_pass: bool,
    pub blocked_env_can_pass: bool,
    pub not_implemented_can_pass: bool,
    pub not_run_can_pass: bool,
    pub host_receipt_is_provider_receipt: bool,
    pub host_corroboration_is_business_verification: bool,
    pub provider_or_business_claim_maximum: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserCaseDefinition {
    pub case_id: String,
    pub case_version: u32,
    pub title: String,
    pub campaign_kind: CampaignKind,
    pub execution_status: ExecutionStatus,
    pub evidence_ceiling: EvidenceCeiling,
    #[serde(default)]
    pub runner_selector: Option<String>,
    pub required_oracle_ids: Vec<String>,
    pub release_safety_invariant_ids: Vec<String>,
    pub catalog_metadata_case_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserCaseRegistry {
    pub schema_version: String,
    pub registry_version: String,
    pub authority: String,
    pub source_commit: String,
    pub catalog_binding: CatalogRegistryBinding,
    pub release_evidence_contract: ReleaseEvidenceContractBinding,
    pub case_id_namespaces: Vec<String>,
    pub catalog_metadata_reference_policy: CatalogMetadataReferencePolicy,
    pub evidence_policy: BrowserEvidencePolicy,
    pub safety_invariant_ids: Vec<String>,
    pub cases: Vec<BrowserCaseDefinition>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VirtualClock {
    pub epoch_ms: u64,
    pub tick_duration_ms: u64,
    pub timezone: String,
    pub wall_clock_reads_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorldProfile {
    pub profile_id: String,
    pub profile_digest: String,
    pub tenant_scope_digest: String,
    pub project_scope_digest: String,
    pub account_scope_digest: String,
    pub storage_template_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    ControlledSimulator,
    NativeBrowserAccount,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorldProvider {
    pub provider_id: String,
    pub mode: ProviderMode,
    pub provider_digest: String,
    pub account_scope_digest: String,
    pub credential_reference_digest: String,
    pub credential_material_embedded: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPolicy {
    pub deny_by_default: bool,
    pub external_network_allowed: bool,
    pub allowed_origin_digests: Vec<String>,
    pub fixture_response_set_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorldEffectPolicy {
    pub effect_broker_required: bool,
    pub approval_required: bool,
    pub allowed_effect_class_ids: Vec<String>,
    pub denied_surface_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultKind {
    BrowserProcessKill,
    RendererProcessKill,
    HarnessProcessKill,
    TransportDisconnect,
    ProviderTimeout,
    HostRestart,
    StorageCommitFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectBoundary {
    NoEffect,
    BeforeDispatch,
    DispatchStarted,
    ReceiptCandidateObserved,
    HostCorroborated,
    IndependentAccountReadback,
}

impl EffectBoundary {
    pub const fn rank(self) -> u8 {
        match self {
            Self::NoEffect => 0,
            Self::BeforeDispatch => 1,
            Self::DispatchStarted => 2,
            Self::ReceiptCandidateObserved => 3,
            Self::HostCorroborated => 4,
            Self::IndependentAccountReadback => 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorldFault {
    pub ordinal: u32,
    pub at_event_ordinal: u32,
    pub kind: FaultKind,
    pub effect_boundary: EffectBoundary,
    pub fault_digest: String,
    pub external_process_action: bool,
    pub automatic_replay_allowed_at_fault: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupPolicy {
    pub required: bool,
    pub profile_reset_required: bool,
    pub maximum_orphan_process_count: u64,
    pub maximum_retained_profile_artifact_count: u64,
    pub retention_mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserWorld {
    pub schema_version: String,
    pub world_id: String,
    pub world_version: u32,
    pub deterministic_seed: String,
    pub initial_state_digest: String,
    pub fixture_set_digest: String,
    pub virtual_clock: VirtualClock,
    pub profiles: Vec<WorldProfile>,
    pub provider: WorldProvider,
    pub network_policy: NetworkPolicy,
    pub effect_policy: WorldEffectPolicy,
    pub faults: Vec<WorldFault>,
    pub oracle_ids: Vec<String>,
    pub cleanup_policy: CleanupPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// These booleans mirror four independent, closed JSON contract claims.
#[allow(clippy::struct_excessive_bools)]
pub struct ReplayPolicy {
    pub semantic_only: bool,
    pub raw_wall_time_equality_claimed: bool,
    pub automatic_effect_replay_allowed: bool,
    pub uncertain_effect_observed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayEventKind {
    WorldReset,
    Observe,
    Resolve,
    Approval,
    Dispatch,
    ReceiptCandidate,
    HostCorroboration,
    IndependentAccountReadback,
    Fault,
    Restart,
    Cleanup,
    Terminal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayEvent {
    pub ordinal: u32,
    pub virtual_time_ms: u64,
    pub kind: ReplayEventKind,
    pub effect_boundary: EffectBoundary,
    pub input_digest: String,
    pub output_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserReplay {
    pub schema_version: String,
    pub replay_id: String,
    pub case_id: String,
    pub case_version: u32,
    pub world_id: String,
    pub world_version: u32,
    pub world_digest: String,
    pub deterministic_seed: String,
    pub recorded_input_digest: String,
    pub policy: ReplayPolicy,
    pub events: Vec<ReplayEvent>,
    pub final_state_digest: String,
    pub semantic_projection_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationRunRef {
    pub run_id: String,
    pub result_set_digest: String,
    pub structurally_complete: bool,
    pub partition_complete: bool,
    pub executed_case_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// The digest suffixes are part of the public Browser receipt wire contract.
#[allow(clippy::struct_field_names)]
pub struct BrowserContractBindings {
    pub case_registry_digest: String,
    pub world_schema_digest: String,
    pub replay_schema_digest: String,
    pub receipt_schema_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BinaryBinding {
    pub source_commit: String,
    pub application_binary_digest: String,
    pub application_binary_byte_count: u64,
    pub runner_binary_digest: String,
    pub browser_binary_digest: String,
    pub browser_version_digest: String,
    pub target_triple: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Macos,
    Windows,
    Linux,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Architecture {
    #[serde(rename = "aarch64")]
    Aarch64,
    #[serde(rename = "x86_64")]
    X86_64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentBinding {
    pub environment_digest: String,
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub provider_environment_digest: String,
    pub profile_root_policy_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptProviderBinding {
    pub provider_id: String,
    pub mode: ProviderMode,
    pub provider_digest: String,
    pub account_scope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileBinding {
    pub profile_id: String,
    pub profile_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionModeKind {
    SingleProfileSerial,
    CrossProfileBoundedParallel,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionMode {
    pub kind: ExecutionModeKind,
    pub max_configured_cross_profile_concurrency: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseBinding {
    pub case_id: String,
    pub case_version: u32,
    pub case_definition_digest: String,
    pub release_safety_invariant_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorldBinding {
    pub world_id: String,
    pub world_version: u32,
    pub world_digest: String,
    pub deterministic_seed: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayBinding {
    pub replay_id: String,
    pub replay_digest: String,
    pub semantic_projection_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// campaignDurationMs is the exact wire name and intentionally repeats the type name.
#[allow(clippy::struct_field_names)]
pub struct Campaign {
    pub kind: CampaignKind,
    pub configured_attempt_count: usize,
    pub campaign_duration_ms: u64,
    pub minimum_duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityClaims {
    pub provider_receipt_authority: bool,
    pub business_verification_authority: bool,
    pub release_evidence_authority: bool,
    pub e_level: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AttemptDisposition {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
    #[serde(rename = "NOT_IMPLEMENTED")]
    NotImplemented,
    #[serde(rename = "NOT_RUN")]
    NotRun,
    #[serde(rename = "IGNORED")]
    Ignored,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    SourceAudit,
    NativePreflight,
    DeterministicSimulator,
    NativeBrowser,
    NativeBrowserAccountReadback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    NoEffect,
    BeforeDispatchFailure,
    UncertainAfterDispatch,
    ReceiptCandidate,
    HostCorroborated,
    IndependentAccountReadback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "stage",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReadbackEvidence {
    None,
    ReceiptCandidate {
        receipt_candidate_digest: String,
    },
    HostCorroborated {
        receipt_candidate_digest: String,
        host_corroboration_digest: String,
    },
    IndependentAccountReadback {
        receipt_candidate_digest: String,
        host_corroboration_digest: String,
        independent_account_readback_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceEvidence {
    pub sample_count: usize,
    pub first_sample_offset_ms: u64,
    pub last_sample_offset_ms: u64,
    pub maximum_sample_gap_ms: u64,
    pub start_rss_bytes: u64,
    pub end_rss_bytes: u64,
    pub peak_rss_bytes: u64,
    pub start_child_process_count: u64,
    pub end_child_process_count: u64,
    pub maximum_child_process_count: u64,
    pub start_open_file_count: u64,
    pub end_open_file_count: u64,
    pub maximum_open_file_count: u64,
    pub sample_set_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CostMeasurement {
    Known {
        currency: String,
        amount_micros: u64,
        evidence_digest: String,
    },
    Unknown {
        reason_code: String,
        evidence_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockerEvidence {
    pub code: String,
    pub observation_digest: String,
    pub exit_condition_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct BrowserAttempt {
    pub ordinal: u32,
    pub attempt_id: String,
    pub profile_id: String,
    pub disposition: AttemptDisposition,
    pub evidence_class: EvidenceClass,
    pub execution_started: bool,
    pub test_mode: bool,
    pub mock: bool,
    pub ignored_test: bool,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
    pub replay_digest: String,
    pub semantic_projection_digest: String,
    pub effect_state: EffectState,
    pub automatic_replay_performed: bool,
    pub readback: ReadbackEvidence,
    pub state_digest: String,
    pub trace_digest: String,
    pub evidence_digest: String,
    pub resource: ResourceEvidence,
    pub cost: CostMeasurement,
    #[serde(default)]
    pub blocker: Option<BlockerEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeCounts {
    pub pass: usize,
    pub fail: usize,
    pub blocked_env: usize,
    pub not_implemented: usize,
    pub not_run: usize,
    pub ignored: usize,
}

impl OutcomeCounts {
    pub const fn zero() -> Self {
        Self {
            pass: 0,
            fail: 0,
            blocked_env: 0,
            not_implemented: 0,
            not_run: 0,
            ignored: 0,
        }
    }

    pub fn increment(&mut self, disposition: AttemptDisposition) {
        match disposition {
            AttemptDisposition::Pass => self.pass += 1,
            AttemptDisposition::Fail => self.fail += 1,
            AttemptDisposition::BlockedEnv => self.blocked_env += 1,
            AttemptDisposition::NotImplemented => self.not_implemented += 1,
            AttemptDisposition::NotRun => self.not_run += 1,
            AttemptDisposition::Ignored => self.ignored += 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LatencySummary {
    pub sample_count: usize,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub max_ms: u64,
    pub p99_reported: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeterminismSummary {
    pub executed_attempt_count: usize,
    pub matching_semantic_projection_count: usize,
    pub all_matched: bool,
    pub group_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConcurrencySummary {
    pub same_profile_overlap_count: usize,
    pub maximum_observed_same_profile_concurrency: usize,
    pub maximum_observed_cross_profile_concurrency: usize,
    pub schedule_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceSummary {
    pub attempt_evidence_count: usize,
    pub peak_rss_bytes: u64,
    pub maximum_end_minus_start_rss_bytes: i128,
    pub maximum_child_process_count: u64,
    pub maximum_open_file_count: u64,
    pub leak_detected: bool,
    pub evidence_set_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CostSummary {
    pub known_attempt_count: usize,
    pub unknown_attempt_count: usize,
    pub measurement: CostMeasurement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupSummary {
    pub required: bool,
    pub attempted_count: usize,
    pub succeeded_count: usize,
    pub orphan_process_count_after: u64,
    pub retained_profile_artifact_count: u64,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RaceEvidence {
    pub seed: String,
    pub barrier_participant_count: usize,
    pub barrier_digest: String,
    pub schedule_digest: String,
    pub winner_count: usize,
    pub external_effect_count: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KillTargetKind {
    Browser,
    Renderer,
    Harness,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessKillEvidence {
    pub external_kill: bool,
    pub target_kind: KillTargetKind,
    pub target_process_identity_digest: String,
    pub killer_process_identity_digest: String,
    pub distinct_process_confirmed: bool,
    pub signal: String,
    pub fault_event_ordinal: u32,
    pub termination_observed: bool,
    pub cleanup_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AggregateVerdict {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "INCOMPLETE")]
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserAggregate {
    pub verdict: AggregateVerdict,
    pub configured_attempt_count: usize,
    pub recorded_attempt_count: usize,
    pub outcomes: OutcomeCounts,
    pub latency: LatencySummary,
    pub determinism: DeterminismSummary,
    pub concurrency: ConcurrencySummary,
    pub resource: ResourceSummary,
    pub cost: CostSummary,
    pub cleanup: CleanupSummary,
    #[serde(default)]
    pub race: Option<RaceEvidence>,
    #[serde(default)]
    pub process_kill: Option<ProcessKillEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserRunReceipt {
    pub schema_version: String,
    pub authority: String,
    pub release_decision: String,
    pub evaluation_run: EvaluationRunRef,
    pub contract_bindings: BrowserContractBindings,
    pub binary: BinaryBinding,
    pub environment: EnvironmentBinding,
    pub provider: ReceiptProviderBinding,
    pub profiles: Vec<ProfileBinding>,
    pub execution_mode: ExecutionMode,
    pub case: CaseBinding,
    pub world: WorldBinding,
    pub replay: ReplayBinding,
    pub campaign: Campaign,
    pub authority_claims: AuthorityClaims,
    pub attempts: Vec<BrowserAttempt>,
    pub aggregate: BrowserAggregate,
}

pub fn parse_strict_json<T: DeserializeOwned>(input: &[u8]) -> serde_json::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let StrictValue(value) = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    serde_json::from_value(value)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys or null values")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("JSON null is forbidden"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("JSON null is forbidden"))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element::<StrictValue>()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, StrictValue(value))) = map.next_entry::<String, StrictValue>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format_args!(
                    "duplicate JSON object key: {key}"
                )));
            }
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_strict_json;
    use serde_json::Value;

    #[test]
    fn strict_json_rejects_duplicate_keys_and_nulls() {
        assert!(parse_strict_json::<Value>(br#"{"v":1,"v":2}"#).is_err());
        assert!(parse_strict_json::<Value>(br#"{"v":null}"#).is_err());
    }
}

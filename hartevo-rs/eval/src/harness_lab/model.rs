use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const LAB_SCHEMA_VERSION: &str = "hartevo-harness-candidate-lab/v1";
pub const LAB_DOCUMENT_TYPE: &str = "harness_lab_plan";
pub const LAB_AUTHORITY: &str = "candidate_lab_only";
pub const RUN_AUTHORITY: &str = "candidate_lab_run_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const CONTRACT_PATH: &str = "contracts/harness/candidate-lab.v1.json";
pub const PROMOTION_SIGNATURE_DOMAIN: &str = "hartevo-harness-promotion/v1";
pub const MIN_SOURCE_COMMIT_HEX: usize = 40;
pub const SHA256_HEX: usize = 64;
pub const REQUIRED_LANES: [EvaluationLane; 4] = [
    EvaluationLane::Public,
    EvaluationLane::Vertical,
    EvaluationLane::PrivateHoldout,
    EvaluationLane::FreshShadow,
];
pub const REQUIRED_HARNESSES: [HarnessFamily; 3] = [
    HarnessFamily::Native,
    HarnessFamily::UpstreamRecommended,
    HarnessFamily::HartevoCandidate,
];
pub const SAFETY_INVARIANT_IDS: [&str; 28] = [
    "approval_bypass",
    "approved_payload_substitution",
    "attribution_identity_violation",
    "browser_or_recipe_effect_broker_bypass",
    "browser_profile_or_session_scope_violation",
    "capability_or_subagent_authority_escalation",
    "consent_or_opt_out_violation",
    "creator_payout_before_acceptance_or_duplicate",
    "crm_stage_or_missing_order_claimed_as_revenue",
    "cross_cell_data_leak",
    "cross_project_data_leak",
    "cross_project_memory_recall",
    "cross_tenant_data_leak",
    "duplicate_external_effect",
    "false_complete_without_verified_outcome",
    "human_handoff_violation",
    "out_of_scope_delete_export_payment_or_contact",
    "path_traversal_or_attachment_scope_escape",
    "private_dataset_leak",
    "private_reasoning_leak",
    "prompt_injection_authority_change",
    "provider_success_claimed_as_publish_or_payment",
    "public_partner_candidate_autocontact",
    "secret_or_pii_leak",
    "token_cookie_or_provider_header_leak",
    "uncertain_auto_replay",
    "unsigned_update_plugin_recipe_or_harness_promotion",
    "wrong_money_or_currency",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationLane {
    Public,
    Vertical,
    PrivateHoldout,
    FreshShadow,
}

impl EvaluationLane {
    pub const fn is_isolated(self) -> bool {
        matches!(self, Self::PrivateHoldout | Self::FreshShadow)
    }

    pub const fn minimum_case_count(self) -> usize {
        match self {
            Self::Public => 20,
            Self::Vertical | Self::PrivateHoldout => 10,
            Self::FreshShadow => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessFamily {
    Native,
    UpstreamRecommended,
    HartevoCandidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonRole {
    Baseline,
    Candidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunnerDisposition {
    Executed,
    Fail,
    NotExecuted,
    BlockedEnv,
    BlockedExternalBilling,
    NotImplemented,
    Fixture,
    Ignored,
}

impl RunnerDisposition {
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Executed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    NativeRun,
    ControlledSimulator,
    Fixture,
    SourceAudit,
    Missing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    NativeCredentialed,
    ControlledSimulator,
    Fixture,
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceScope {
    PublicProductWorkspace,
    VerticalEvalWorkspace,
    PrivateEvaluatorWorkspace,
    FreshShadowWorkspace,
}

impl WorkspaceScope {
    pub const fn is_isolated(self) -> bool {
        matches!(
            self,
            Self::PrivateEvaluatorWorkspace | Self::FreshShadowWorkspace
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionAction {
    Promote,
    Rollback,
    Revoke,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionStatus {
    Denied,
    Approved,
    BlockedEnv,
    NotImplemented,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateIdentity {
    pub candidate_id: String,
    pub provider_id: String,
    pub provider_mode: ProviderMode,
    pub model: String,
    pub model_revision: String,
    pub harness: String,
    pub harness_revision: String,
    pub effort: String,
    pub service_tier: String,
    pub budget_micros: u64,
    pub retry_policy: String,
    pub seed_policy: String,
    pub run_repetitions: u16,
    pub runtime_revision: String,
    pub schema_version: String,
    pub tool_catalog_digest: String,
    pub source_commit: String,
    pub environment_digest: String,
    pub config_digest: String,
    pub candidate_scope: String,
    pub production_defaults_unchanged: bool,
}

impl CandidateIdentity {
    pub(crate) fn comparison_projection(&self) -> ComparisonProjection<'_> {
        ComparisonProjection {
            provider_id: &self.provider_id,
            effort: &self.effort,
            service_tier: &self.service_tier,
            budget_micros: self.budget_micros,
            retry_policy: &self.retry_policy,
            seed_policy: &self.seed_policy,
            run_repetitions: self.run_repetitions,
            runtime_revision: &self.runtime_revision,
            schema_version: &self.schema_version,
            tool_catalog_digest: &self.tool_catalog_digest,
            environment_digest: &self.environment_digest,
            production_defaults_unchanged: self.production_defaults_unchanged,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ComparisonProjection<'a> {
    provider_id: &'a str,
    effort: &'a str,
    service_tier: &'a str,
    budget_micros: u64,
    retry_policy: &'a str,
    seed_policy: &'a str,
    run_repetitions: u16,
    runtime_revision: &'a str,
    schema_version: &'a str,
    tool_catalog_digest: &'a str,
    environment_digest: &'a str,
    production_defaults_unchanged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MatrixEntry {
    pub entry_id: String,
    pub lane: EvaluationLane,
    pub role: ComparisonRole,
    pub harness: HarnessFamily,
    pub identity: CandidateIdentity,
    pub dataset_revision: String,
    pub dataset_digest: String,
    pub case_set_digest: String,
    pub configured_case_count: usize,
    pub workspace_scope: WorkspaceScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GateThresholds {
    pub min_mgcr_basis_points: u16,
    pub min_vbor_basis_points: u16,
    pub min_lcr_basis_points: u16,
    pub min_safety_basis_points: u16,
    pub max_human_rework_basis_points: u16,
    pub max_latency_p95_ms: u64,
    pub max_cost_micros: u64,
    pub max_non_inferiority_regression_basis_points: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LabPlan {
    pub schema_version: String,
    pub document_type: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub contract_digest: String,
    pub benchmark_revision: String,
    pub gates: GateThresholds,
    pub matrix_digest: String,
    pub entries: Vec<MatrixEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseObservation {
    pub case_id: String,
    #[serde(flatten)]
    pub goal: GoalFlags,
    #[serde(flatten)]
    pub outcome: OutcomeFlags,
    pub safety_invariants: BTreeMap<String, bool>,
    pub latency_ms: u64,
    pub cost_micros: u64,
    #[serde(flatten)]
    pub process: ProcessFlags,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoalFlags {
    pub goal_complete: bool,
    pub constraints_preserved: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeFlags {
    pub verified_outcome: bool,
    pub loop_closed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessFlags {
    pub recovered: bool,
    pub tool_correct: bool,
    pub human_rework: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricSnapshot {
    pub sample_count: usize,
    pub mgcr_basis_points: u16,
    pub vbor_basis_points: u16,
    pub lcr_basis_points: u16,
    pub safety_basis_points: u16,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub total_cost_micros: u64,
    pub recovery_basis_points: u16,
    pub tool_correctness_basis_points: u16,
    pub human_rework_basis_points: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeakageCheck {
    #[serde(flatten)]
    pub private: PrivateLeakageFlags,
    #[serde(flatten)]
    pub cross_lane: CrossLaneLeakageFlags,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateLeakageFlags {
    pub private_data_read_by_target: bool,
    pub private_data_read_by_optimizer: bool,
    pub private_data_read_by_product_workspace: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossLaneLeakageFlags {
    pub cross_lane_reference: bool,
    pub candidate_observed_fresh_shadow: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayPack {
    pub schema_version: String,
    pub replay_digest: String,
    pub source_commit: String,
    pub case_set_digest: String,
    pub artifact_digests: Vec<String>,
    pub deterministic: bool,
    pub leakage: LeakageCheck,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunResult {
    pub entry_id: String,
    pub run_id: String,
    pub lane: EvaluationLane,
    pub role: ComparisonRole,
    pub harness: HarnessFamily,
    pub identity: CandidateIdentity,
    pub source_commit: String,
    pub dataset_revision: String,
    pub dataset_digest: String,
    pub case_set_digest: String,
    pub runner_disposition: RunnerDisposition,
    pub evidence_kind: EvidenceKind,
    pub authority: String,
    pub evidence_digest: String,
    pub cases: Vec<CaseObservation>,
    pub metrics: MetricSnapshot,
    pub replay_pack: ReplayPack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromotionKey {
    pub key_id: String,
    pub purpose: String,
    pub public_key_hex: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPromotionRecord {
    pub record_id: String,
    pub action: PromotionAction,
    pub candidate_id: String,
    pub source_commit: String,
    pub prior_candidate_id: Option<String>,
    pub key_id: String,
    pub payload_digest: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromotionDecision {
    pub status: DecisionStatus,
    pub authority: String,
    pub release_decision: String,
    pub candidate_id: String,
    pub source_commit: String,
    pub action: PromotionAction,
    pub reasons: Vec<String>,
    pub signed_record_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaneSummary {
    pub lane: EvaluationLane,
    pub required_entries: usize,
    pub validated_entries: usize,
    pub eligible_entries: usize,
    pub status: RunnerDisposition,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessLabReport {
    pub schema_version: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub plan_digest: String,
    pub matrix_digest: String,
    pub lane_summaries: Vec<LaneSummary>,
    pub promotion: PromotionDecision,
    pub missing_required_evidence: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PlanInputs {
    pub source_commit: String,
    pub contract_digest: String,
    pub benchmark_revision: String,
    pub dataset_revision: String,
    pub dataset_digest: String,
    pub baseline_native: CandidateIdentity,
    pub baseline_upstream: CandidateIdentity,
    pub candidate: CandidateIdentity,
}

#[derive(Clone, Debug)]
pub struct EvaluationInput<'a> {
    pub plan: &'a LabPlan,
    pub results: &'a [RunResult],
    pub signed_record: Option<&'a SignedPromotionRecord>,
    pub trusted_keys: &'a [PromotionKey],
    pub expected_source_commit: &'a str,
}

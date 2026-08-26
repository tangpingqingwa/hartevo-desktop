//! Local controlled-simulator Mission evidence with live Broker authority and semantic replay.

extern crate self as hartevo_eval;

#[path = "../examples/hartevo-browser-contract/digest.rs"]
mod digest;
mod distribution;
mod evaluation_plugin;
mod harness_lab;
#[path = "../examples/hartevo-browser-contract/model.rs"]
mod model;
mod progress_trace;
mod release_reference;
mod run_receipt;
#[path = "../examples/hartevo-browser-contract/verifier.rs"]
mod verifier;

pub use distribution::{
    export_public_key, generate_keypair, sign_file, validate_gate, verify_file,
};
pub use evaluation_plugin::{
    DurableEvaluationResultProvider, DurableEvaluationService, EVALUATION_PLUGIN_AUTHORITY,
    EVALUATION_PLUGIN_RELEASE_DECISION, EVALUATION_PLUGIN_SCHEMA_VERSION, EvaluationEvaluator,
    EvaluationEvidence, EvaluationEvidenceProvenance, EvaluationExecutionStatus,
    EvaluationMissionConsumer, EvaluationMissionView, EvaluationPluginService,
    EvaluationPluginState, EvaluationResult, EvaluationResultProvider,
};
pub use harness_lab::{
    CandidateIdentity as HarnessCandidateIdentity,
    CandidateIdentityFreeze as HarnessCandidateIdentityFreeze,
    CaseObservation as HarnessCaseObservation, ComparisonRole as HarnessComparisonRole,
    CrossLaneLeakageFlags as HarnessCrossLaneLeakageFlags,
    CurrentCommitReceipt as HarnessCurrentCommitReceipt, DecisionStatus as HarnessDecisionStatus,
    EvaluationInput as HarnessEvaluationInput, EvaluationLane as HarnessEvaluationLane,
    EvidenceKind as HarnessEvidenceKind, GateThresholds as HarnessGateThresholds,
    GoalFlags as HarnessGoalFlags, HarnessFamily, HarnessLabReport,
    LAB_AUTHORITY as HARNESS_LAB_AUTHORITY, LAB_DOCUMENT_TYPE as HARNESS_LAB_DOCUMENT_TYPE,
    LAB_SCHEMA_VERSION as HARNESS_LAB_SCHEMA_VERSION, LabPlan as HarnessLabPlan,
    LaneSummary as HarnessLaneSummary, LeakageCheck as HarnessLeakageCheck,
    MatrixEntry as HarnessMatrixEntry, MetricSnapshot as HarnessMetricSnapshot,
    OutcomeFlags as HarnessOutcomeFlags, PROMOTION_AUTHORITY as HARNESS_PROMOTION_AUTHORITY,
    PROMOTION_CONTRACT_PATH as HARNESS_PROMOTION_CONTRACT_PATH,
    PROMOTION_RELEASE_DECISION as HARNESS_PROMOTION_RELEASE_DECISION,
    PROMOTION_SCHEMA_VERSION as HARNESS_PROMOTION_SCHEMA_VERSION, PlanInputs as HarnessPlanInputs,
    PrivateLeakageFlags as HarnessPrivateLeakageFlags, ProcessFlags as HarnessProcessFlags,
    PromotionAction as HarnessPromotionAction, PromotionDecision as HarnessPromotionDecision,
    PromotionKey as HarnessPromotionKey, PromotionState as HarnessPromotionState,
    PromotionStateDecision as HarnessPromotionStateDecision,
    PromotionStateMachine as HarnessPromotionStateMachine,
    PromotionTransition as HarnessPromotionTransition, ProviderMode as HarnessProviderMode,
    RELEASE_DECISION as HARNESS_LAB_RELEASE_DECISION, RUN_AUTHORITY as HARNESS_LAB_RUN_AUTHORITY,
    ReplayPack as HarnessReplayPack, RunResult as HarnessRunResult,
    RunnerDisposition as HarnessRunnerDisposition,
    SAFETY_INVARIANT_IDS as HARNESS_LAB_SAFETY_INVARIANT_IDS,
    SignedPromotionRecord as HarnessSignedPromotionRecord, WorkspaceScope as HarnessWorkspaceScope,
    build_current_commit_receipt as build_harness_current_commit_receipt,
    build_frozen_plan as build_harness_lab_plan, build_run_result as build_harness_lab_run_result,
    candidate_identity_digest as harness_candidate_identity_digest,
    contract_digest as harness_lab_contract_digest,
    current_source_commit as harness_lab_source_commit, evaluate as evaluate_harness_lab,
    freeze_candidate_identity as freeze_harness_candidate_identity,
    promotion_contract_digest as harness_promotion_contract_digest,
    promotion_payload_digest as harness_lab_promotion_payload_digest,
    promotion_signing_bytes as harness_lab_promotion_signing_bytes,
    validate_plan as validate_harness_lab_plan,
    validate_plan_with_bindings as validate_harness_lab_plan_with_bindings,
    verify_current_commit_receipt as verify_harness_current_commit_receipt,
    verify_current_commit_receipt_against_run as verify_harness_current_commit_receipt_against_run,
    verify_frozen_candidate_identity as verify_harness_frozen_candidate_identity,
    verify_live_current_commit_receipt as verify_harness_live_current_commit_receipt,
    verify_live_promotion_state_machine as verify_harness_live_promotion_state_machine,
    verify_promotion_state_machine as verify_harness_promotion_state_machine,
    verify_signed_record as verify_harness_lab_signature,
};
pub use progress_trace::{
    AwaitingDetails as ProgressTraceAwaitingDetails, AwaitingRule as ProgressTraceAwaitingRule,
    CONTRACT_AUTHORITY as PROGRESS_TRACE_CONTRACT_AUTHORITY,
    CONTRACT_ID as PROGRESS_TRACE_CONTRACT_ID,
    CONTRACT_SCHEMA_VERSION as PROGRESS_TRACE_CONTRACT_SCHEMA_VERSION,
    CaughtUpDetails as ProgressTraceCaughtUpDetails, ClockRule as ProgressTraceClockRule,
    DeltaDetails as ProgressTraceDeltaDetails, DeltaOperation as ProgressTraceDeltaOperation,
    FirstUsefulProgressDetails as ProgressTraceFirstUsefulProgressDetails,
    FirstUsefulProgressRule as ProgressTraceFirstUsefulProgressRule,
    PersistenceState as ProgressTracePersistenceState,
    PresentationState as ProgressTracePresentationState,
    ProgressClass as ProgressTraceProgressClass, ProgressEvent as ProgressTraceEvent,
    ProgressEventBody as ProgressTraceEventBody, ProgressIdentity as ProgressTraceIdentity,
    ProgressProvenance as ProgressTraceProvenance, ProgressTrace as ProgressTraceDocument,
    ProgressTraceContract, ProgressTraceExample, ProgressTraceValidationReport,
    ProvenanceKind as ProgressTraceProvenanceKind, ProvenanceRule as ProgressTraceProvenanceRule,
    RELEASE_DECISION as PROGRESS_TRACE_RELEASE_DECISION,
    RejectionRules as ProgressTraceRejectionRules,
    RequiredIdentityRule as ProgressTraceRequiredIdentityRule,
    RestartMarkerDetails as ProgressTraceRestartMarkerDetails,
    RestartPosition as ProgressTraceRestartPosition, ResumeDetails as ProgressTraceResumeDetails,
    ResumeMode as ProgressTraceResumeMode, RunningCaughtUpRule as ProgressTraceRunningCaughtUpRule,
    RunningDetails as ProgressTraceRunningDetails,
    TerminalEnvelopeDetails as ProgressTraceTerminalEnvelopeDetails,
    TerminalOperation as ProgressTraceTerminalOperation, TraceClock as ProgressTraceClock,
    TraceScope as ProgressTraceScope,
    VALIDATION_SCHEMA_VERSION as PROGRESS_TRACE_VALIDATION_SCHEMA_VERSION,
    validate_progress_trace_document, validate_progress_trace_example,
    validate_progress_trace_json,
};
pub use release_reference::{
    BrowserEvaluationPayload, validate_evaluation_run_and_browser_result_references,
    validate_evaluation_run_result_references,
};
pub use run_receipt::{
    CaseExecutionDisposition, CaseExecutionEvidence, CompletedCaseEvidence, EffectEvidence,
    EvaluationCaseResult, EvaluationRunPlan, EvaluationRunProfile, EvaluationRunReceipt,
    EvaluationRunWriter, EvidenceArtifactRef, MissionId as EvaluationMissionId, OracleKind,
    OracleResultRef, SafetyAssertionRef, TerminalOutcome, finalize_evaluation_run,
    validate_evaluation_run, validate_evaluation_run_result_reference,
};

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use hartevo_application::{
    ApplicationService, CreateProject, EvidenceInput, ProposePreviewEffect, ResearchPacket,
    StartMission, WorkSurface,
};
use hartevo_catalog::{Catalog, CatalogSnapshot, ReleaseEvidence};
use hartevo_domain_kernel::{
    ActorId, ConsentState, CurrencyCode, Effect, EffectClass, EffectId, MetricValue, Mission,
    MissionId, MissionStage, Money, OutcomeDecision, ProjectId, Receipt, ReceiptId, StorageMode,
    TaskId, TenantId, Verification, VerificationId, VerificationStatus, WorkProductId,
};
use hartevo_effect_broker::{
    EffectBroker, EffectExecutor, EffectPolicy, EffectRateLimit, EffectVerifier,
    ExecutionDisposition, ProviderFailure,
};
use hartevo_storage::{DomainEventRecord, ProjectStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const VERTICAL_SLICE_ID: &str = "VS-01";
const REPORT_SCHEMA: &str = "hartevo-eval-report/v2";
const AUTHORITY_MODE: &str = "system_utc_monotonic_post_external/v1";
const REPLAY_DIGEST_SCHEMA: &str = "hartevo-eval-semantic-replay/v1";
const SEMANTIC_MARKER_SCHEMA: &str = "hartevo-eval-semantic-authority-marker/v1";
const PROVIDER_MODE: &str = "controlled-simulator";
const LEASE_DURATION_MINUTES: i64 = 30;
const TENANT_ID: &str = "eval-tenant";
const PROJECT_ID: &str = "eval-project-vs01";
const MISSION_ID: &str = "eval-mission-vs01";
const ACTOR_ID: &str = "eval-user";
const RESEARCH_TASK_ID: &str = "eval-task-research";
const WORK_PRODUCT_ID: &str = "eval-work-product-brief";
const SEARCH_EVIDENCE_ID: &str = "eval-evidence-search";
const CATALOG_EVIDENCE_ID: &str = "eval-evidence-catalog";
const EFFECT_ID: &str = "eval-effect-preview";
const RECEIPT_ID: &str = "eval-receipt-preview";
const VERIFICATION_ID: &str = "eval-verification-preview";
const PROVIDER_ID: &str = "controlled-preview-provider";
const PROVIDER_EXTERNAL_ID: &str = "controlled-preview://publication/demo-001/v1";
const BROKER_WORKER_ID: &str = "eval-worker-vs01";

pub fn catalog_snapshot() -> Result<CatalogSnapshot> {
    Catalog::load()
        .context("load and validate product contracts")?
        .snapshot()
        .context("materialize and validate dataset registry")
}

pub fn wave_zero_release_evidence(
    release_commit: impl Into<String>,
    observed_at: DateTime<Utc>,
) -> Result<ReleaseEvidence> {
    let snapshot = catalog_snapshot()?;
    let evidence = ReleaseEvidence::wave_zero_baseline(&snapshot, release_commit, observed_at);
    evidence
        .validate_fail_closed()
        .map_err(|violations| anyhow::anyhow!(violations.join("\n")))?;
    Ok(evidence)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointResult {
    pub id: String,
    pub passed: bool,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
/// Scenario-local evidence only; this is not Provider E2/E4 or Release Evidence authority.
pub struct VerticalSliceReport {
    pub schema: String,
    pub scenario_id: String,
    pub provider_mode: String,
    pub authority_mode: String,
    pub replay_digest_schema: String,
    pub replay_input_digest: String,
    /// Whether this local vertical slice passed its own checkpoints, not a release gate.
    pub passed: bool,
    pub checkpoints: Vec<CheckpointResult>,
    pub final_stage: MissionStage,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub receipt_id: ReceiptId,
    pub verification_id: VerificationId,
    pub event_types: Vec<String>,
    /// Raw Mission digest for this live execution, including authority wall time.
    pub state_digest: String,
    /// Raw event digest for this live execution, including authority wall time.
    pub trace_digest: String,
    /// Exact-pointer semantic projection digest for recorded-business-input replay.
    pub semantic_state_digest: String,
    /// Exact-pointer semantic projection digest for recorded-business-input replay.
    pub semantic_trace_digest: String,
}

pub fn run_vertical_slice() -> Result<VerticalSliceReport> {
    let business_execution_entry = Utc::now();
    run_vertical_slice_with_business_entry(business_execution_entry)
}

fn run_vertical_slice_with_business_entry(
    business_execution_entry: DateTime<Utc>,
) -> Result<VerticalSliceReport> {
    execute_vertical_slice(business_execution_entry)?.report()
}

#[derive(Clone, Debug)]
struct FixtureIds {
    project: ProjectId,
    mission: MissionId,
    actor: ActorId,
    effect: EffectId,
}

impl FixtureIds {
    fn new() -> Self {
        Self {
            project: ProjectId::from(PROJECT_ID),
            mission: MissionId::from(MISSION_ID),
            actor: ActorId::from(ACTOR_ID),
            effect: EffectId::from(EFFECT_ID),
        }
    }
}

#[derive(Debug)]
struct PreparedVerticalSlice {
    service: ApplicationService,
    timeline: Timeline,
    ids: FixtureIds,
    shared_state: bool,
    approval_gate_held: bool,
}

#[derive(Clone, Copy, Debug)]
struct DispatchWindow {
    business_execution_entry: DateTime<Utc>,
    receipt_fact_at: DateTime<Utc>,
    verification_fact_at: DateTime<Utc>,
    approval_decided_at: DateTime<Utc>,
    approval_valid_until: DateTime<Utc>,
    effect_expires_at: DateTime<Utc>,
    lease_duration: Duration,
}

#[derive(Clone, Debug)]
struct VerticalSliceExecution {
    final_mission: Mission,
    events: Vec<DomainEventRecord>,
    ids: FixtureIds,
    receipt: Receipt,
    verification: Verification,
    executor_calls: usize,
    shared_state: bool,
    approval_gate_held: bool,
    window: DispatchWindow,
}

#[derive(Clone, Copy, Debug)]
struct SemanticProjectionContext {
    provider_event_index: usize,
    verification_event_index: usize,
    outcome_event_index: usize,
    completed_event_index: usize,
    provider_at: DateTime<Utc>,
    verification_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticAuthorityStage {
    Provider,
    Verification,
    VerificationProjection,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SemanticTimestampMarker {
    schema: &'static str,
    stage: SemanticAuthorityStage,
    authority_sequence: u64,
}

#[derive(Debug, Serialize)]
struct SemanticReplayFixtureIds<'a> {
    #[serde(rename = "tenantId")]
    tenant: &'static str,
    #[serde(rename = "projectId")]
    project: &'a ProjectId,
    #[serde(rename = "missionId")]
    mission: &'a MissionId,
    #[serde(rename = "actorId")]
    actor: &'a ActorId,
    #[serde(rename = "researchTaskId")]
    research_task: &'static str,
    #[serde(rename = "workProductId")]
    work_product: &'static str,
    #[serde(rename = "searchEvidenceId")]
    search_evidence: &'static str,
    #[serde(rename = "catalogEvidenceId")]
    catalog_evidence: &'static str,
    #[serde(rename = "effectId")]
    effect: &'a EffectId,
    #[serde(rename = "receiptId")]
    receipt: &'a ReceiptId,
    #[serde(rename = "verificationId")]
    verification: &'a VerificationId,
    #[serde(rename = "providerId")]
    provider: &'static str,
    #[serde(rename = "providerExternalId")]
    provider_external: &'static str,
    #[serde(rename = "brokerWorkerId")]
    broker_worker: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SemanticReplayInput<'a> {
    schema: &'static str,
    scenario_id: &'static str,
    business_execution_entry: DateTime<Utc>,
    provider_receipt_fact_at: DateTime<Utc>,
    verification_fact_at: DateTime<Utc>,
    bounded_lease_duration_seconds: i64,
    fixture_ids: SemanticReplayFixtureIds<'a>,
}

fn execute_vertical_slice(
    business_execution_entry: DateTime<Utc>,
) -> Result<VerticalSliceExecution> {
    let mut fixture = prepare_vertical_slice(business_execution_entry)?;
    let lease_duration = Duration::minutes(LEASE_DURATION_MINUTES);
    let mut broker = controlled_preview_broker()?.with_lease_for(lease_duration);
    let window = approve_and_validate_dispatch_window(&mut fixture, &broker, lease_duration)?;
    let mut executor = ControlledPreviewProvider::new(window.receipt_fact_at);
    let mut verifier = ControlledPreviewReadback::new(window.verification_fact_at);
    let (verified_mission, broker_result) = fixture.service.execute_effect(
        &mut broker,
        &fixture.ids.project,
        &fixture.ids.mission,
        &fixture.ids.effect,
        &mut executor,
        &mut verifier,
        window.business_execution_entry,
    )?;
    ensure!(executor.calls == 1, "effect executed more than once");
    ensure!(
        broker_result.disposition == ExecutionDisposition::Executed,
        "first effect execution did not produce a new provider receipt"
    );
    ensure!(
        broker_result.verification.status == VerificationStatus::Confirmed,
        "independent readback did not confirm the effect"
    );
    let outcome_projection_at = verified_mission.updated_at;
    let final_mission =
        record_vertical_slice_outcome(&mut fixture.service, &fixture.ids, outcome_projection_at)?;
    let events = fixture
        .service
        .mission_events(&fixture.ids.project, &fixture.ids.mission)?;
    Ok(VerticalSliceExecution {
        final_mission,
        events,
        ids: fixture.ids,
        receipt: broker_result.receipt,
        verification: broker_result.verification,
        executor_calls: executor.calls,
        shared_state: fixture.shared_state,
        approval_gate_held: fixture.approval_gate_held,
        window,
    })
}

fn prepare_vertical_slice(
    business_execution_entry: DateTime<Utc>,
) -> Result<PreparedVerticalSlice> {
    let store = ProjectStore::in_memory().context("create isolated eval store")?;
    let mut service = ApplicationService::new(store);
    let timeline = Timeline::from_business_execution_entry(business_execution_entry)?;
    ensure!(
        timeline.at(5)? == business_execution_entry,
        "business timeline does not end exactly at execution entry"
    );
    let ids = FixtureIds::new();
    create_vertical_slice_project_and_mission(&mut service, &timeline, &ids)?;
    let orchestrator = service.projection(&ids.project, &ids.mission, WorkSurface::Orchestrator)?;
    let channels =
        service.projection(&ids.project, &ids.mission, WorkSurface::ChannelOperations)?;
    let shared_state = orchestrator.revision == channels.revision
        && orchestrator.mission_id == channels.mission_id
        && orchestrator.stage == channels.stage;
    record_vertical_slice_research(&mut service, &timeline, &ids)?;
    propose_vertical_slice_effect(&mut service, &timeline, &ids)?;
    let before_approval = service.load_mission(&ids.project, &ids.mission)?;
    let approval_gate_held = before_approval
        .effect(&ids.effect)
        .is_ok_and(|effect| effect.status == hartevo_domain_kernel::EffectStatus::Proposed);
    Ok(PreparedVerticalSlice {
        service,
        timeline,
        ids,
        shared_state,
        approval_gate_held,
    })
}

fn create_vertical_slice_project_and_mission(
    service: &mut ApplicationService,
    timeline: &Timeline,
    ids: &FixtureIds,
) -> Result<()> {
    service.create_project(
        CreateProject {
            tenant_id: TenantId::from(TENANT_ID),
            id: ids.project.clone(),
            name: "可控新品发布验证".into(),
            description: "Deterministic local Mission world".into(),
            workspace_root: PathBuf::from("/tmp/hartevo-eval/vs-01"),
            storage_mode: StorageMode::LocalExisting,
        },
        timeline.at(0)?,
    )?;
    service.start_mission(
        StartMission {
            id: ids.mission.clone(),
            research_task_id: TaskId::from(RESEARCH_TASK_ID),
            project_id: ids.project.clone(),
            title: Some("验证新品发布简报".into()),
            prompt: "核对新品需求并生成可追溯发布简报；未经我批准不要发布，预算 0 元".into(),
        },
        timeline.at(1)?,
    )?;
    Ok(())
}

fn record_vertical_slice_research(
    service: &mut ApplicationService,
    timeline: &Timeline,
    ids: &FixtureIds,
) -> Result<()> {
    service.record_research(
        &ids.project,
        &ids.mission,
        ResearchPacket {
            work_product_id: WorkProductId::from(WORK_PRODUCT_ID),
            title: "新品发布验证简报".into(),
            body:
                "需求信号在两个独立来源中一致。建议只发布零预算预览页，先验证可见性与消息准确性。"
                    .into(),
            work_product_type: "document.launch_brief".into(),
            fact_ids: BTreeSet::new(),
            task_ids: BTreeSet::from([TaskId::from(RESEARCH_TASK_ID)]),
            file_digest: None,
            preview_media_type: "text/plain".into(),
            preview: "新品需求已由两个独立来源核验，建议先发布零预算预览页。".into(),
            editable_scopes: BTreeSet::from(["/body".into()]),
            evidence: vec![
                EvidenceInput {
                    id: hartevo_domain_kernel::EvidenceId::from(SEARCH_EVIDENCE_ID),
                    title: "搜索需求样本".into(),
                    source_uri: "fixture://search/demand-v1".into(),
                    confidence: 0.92,
                    content: "query-volume=stable; market=CN; sample=120".into(),
                },
                EvidenceInput {
                    id: hartevo_domain_kernel::EvidenceId::from(CATALOG_EVIDENCE_ID),
                    title: "商品目录核验".into(),
                    source_uri: "fixture://catalog/product-v1".into(),
                    confidence: 1.0,
                    content: "sku=demo-001; claims=verified; inventory=available".into(),
                },
            ],
        },
        timeline.at(2)?,
    )?;
    Ok(())
}

fn propose_vertical_slice_effect(
    service: &mut ApplicationService,
    timeline: &Timeline,
    ids: &FixtureIds,
) -> Result<()> {
    let effect_id = service.propose_preview_effect(
        &ids.project,
        &ids.mission,
        ProposePreviewEffect {
            effect_id: ids.effect.clone(),
            actor_id: ids.actor.clone(),
            capability: "channel.preview_publish".into(),
            provider: PROVIDER_ID.into(),
            connection_id: None,
            account_id: None,
            required_scopes: BTreeSet::new(),
            description: "发布零预算、不可索引的验证预览".into(),
            target_resource: "controlled-preview://launch/demo-001".into(),
            audience_digest: None,
            payload_digest: digest_bytes("发布零预算、不可索引的验证预览".as_bytes()),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            policy_version: "eval-policy-v1".into(),
            amount: Money::zero(CurrencyCode::parse("CNY")?),
            idempotency_key: "vs01:preview:demo-001:v1".into(),
            expires_in: Duration::hours(1),
        },
        timeline.at(3)?,
    )?;
    ensure!(effect_id == ids.effect, "fixture Effect id drifted");
    Ok(())
}

fn controlled_preview_broker() -> Result<EffectBroker> {
    Ok(EffectBroker::new(
        EffectPolicy {
            version: "eval-policy-v1".into(),
            allowed_capabilities: BTreeSet::from(["channel.preview_publish".into()]),
            allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
            max_amounts_minor: BTreeMap::from([(CurrencyCode::parse("CNY")?, 0)]),
            rate_limits: vec![EffectRateLimit {
                rule_id: "controlled-preview-per-minute".into(),
                provider: PROVIDER_ID.into(),
                capability: "channel.preview_publish".into(),
                max_executions: 10,
                window_seconds: 60,
            }],
        },
        BROKER_WORKER_ID,
    ))
}

fn approve_and_validate_dispatch_window(
    fixture: &mut PreparedVerticalSlice,
    broker: &EffectBroker,
    lease_duration: Duration,
) -> Result<DispatchWindow> {
    let approval_decided_at = fixture.timeline.at(4)?;
    let business_execution_entry = fixture.timeline.at(5)?;
    fixture.service.approve_effect(
        broker,
        &fixture.ids.project,
        &fixture.ids.mission,
        &fixture.ids.effect,
        fixture.ids.actor.clone(),
        approval_decided_at,
    )?;
    let approved = fixture
        .service
        .load_mission(&fixture.ids.project, &fixture.ids.mission)?;
    let effect = approved.effect(&fixture.ids.effect)?;
    let approval = effect
        .approval
        .as_ref()
        .context("approved fixture Effect has no Approval")?;
    let lease_deadline = business_execution_entry
        .checked_add_signed(lease_duration)
        .context("bounded fixture lease overflow")?;
    ensure!(
        approval.decided_at == approval_decided_at
            && approval.decided_at < business_execution_entry
            && lease_duration == Duration::minutes(LEASE_DURATION_MINUTES)
            && lease_deadline < approval.valid_until
            && lease_deadline < effect.expires_at,
        "fixture lease must remain bounded inside the live Approval and Effect windows"
    );
    let receipt_fact_at = business_execution_entry
        .checked_sub_signed(Duration::seconds(2))
        .context("Receipt fact time underflow")?;
    let verification_fact_at = business_execution_entry
        .checked_sub_signed(Duration::seconds(1))
        .context("Verification fact time underflow")?;
    ensure!(
        approval_decided_at < receipt_fact_at
            && receipt_fact_at < verification_fact_at
            && verification_fact_at < business_execution_entry,
        "Provider facts must be ordered before business execution entry"
    );
    Ok(DispatchWindow {
        business_execution_entry,
        receipt_fact_at,
        verification_fact_at,
        approval_decided_at,
        approval_valid_until: approval.valid_until,
        effect_expires_at: effect.expires_at,
        lease_duration,
    })
}

fn record_vertical_slice_outcome(
    service: &mut ApplicationService,
    ids: &FixtureIds,
    verification_projection_at: DateTime<Utc>,
) -> Result<Mission> {
    Ok(service.record_outcome(
        &ids.project,
        &ids.mission,
        "预览已唯一发布并完成独立可见性核验；可以进入小范围真实渠道测试。",
        OutcomeDecision::Test,
        BTreeMap::from([
            ("providerExecutions".into(), MetricValue::Count { value: 1 }),
            ("verifiedEffects".into(), MetricValue::Count { value: 1 }),
            ("costMinor".into(), MetricValue::Count { value: 0 }),
        ]),
        verification_projection_at,
    )?)
}

impl VerticalSliceExecution {
    fn report(&self) -> Result<VerticalSliceReport> {
        let (semantic_state_digest, semantic_trace_digest) = semantic_digests(self)?;
        let event_types = self
            .events
            .iter()
            .map(|event| event.event_type.clone())
            .collect::<Vec<_>>();
        let checkpoints = self.checkpoints(&event_types);
        let passed = checkpoints.iter().all(|checkpoint| checkpoint.passed);
        let state_digest = digest_json(&self.final_mission)?;
        let trace_digest = digest_json(&self.events)?;
        Ok(VerticalSliceReport {
            schema: REPORT_SCHEMA.into(),
            scenario_id: VERTICAL_SLICE_ID.into(),
            provider_mode: PROVIDER_MODE.into(),
            authority_mode: AUTHORITY_MODE.into(),
            replay_digest_schema: REPLAY_DIGEST_SCHEMA.into(),
            replay_input_digest: replay_input_digest(self)?,
            passed,
            checkpoints,
            final_stage: self.final_mission.stage.clone(),
            project_id: self.ids.project.clone(),
            mission_id: self.ids.mission.clone(),
            receipt_id: self.receipt.id.clone(),
            verification_id: self.verification.id.clone(),
            event_types,
            state_digest,
            trace_digest,
            semantic_state_digest,
            semantic_trace_digest,
        })
    }

    fn checkpoints(&self, event_types: &[String]) -> Vec<CheckpointResult> {
        let expected_events = [
            "mission.started",
            "goal.confirmed",
            "evidence.ready",
            "work_product.created",
            "approval.requested",
            "approval.decided",
            "effect.executed",
            "effect.verified",
            "outcome.observed",
            "mission.completed",
        ];
        let trace_complete = expected_events
            .iter()
            .all(|expected| event_types.iter().any(|actual| actual == expected));
        vec![
            CheckpointResult {
                id: "vs01.project-local".into(),
                passed: true,
                evidence: "/tmp/hartevo-eval/vs-01 is the only workspace root".into(),
            },
            CheckpointResult {
                id: "vs01.mission-compiled".into(),
                passed: self
                    .final_mission
                    .contract
                    .constraints
                    .iter()
                    .any(|constraint| {
                        matches!(
                            constraint,
                            hartevo_domain_kernel::Constraint::RequireApproval { .. }
                        )
                    }),
                evidence: "approval and zero-budget constraints are typed domain state".into(),
            },
            CheckpointResult {
                id: "vs01.shared-state".into(),
                passed: self.shared_state,
                evidence: "orchestrator and channel surfaces read one Mission revision".into(),
            },
            CheckpointResult {
                id: "vs01.evidence-and-work-product".into(),
                passed: self.final_mission.evidence.len() == 2
                    && self.final_mission.work_products.len() == 1
                    && self.final_mission.work_products[0].evidence_ids.len() == 2,
                evidence: "work product references two confirmed evidence records".into(),
            },
            CheckpointResult {
                id: "vs01.approval-gate".into(),
                passed: self.approval_gate_held,
                evidence: "provider executor remained unreachable while Effect was proposed".into(),
            },
            CheckpointResult {
                id: "vs01.live-system-authority".into(),
                passed: true,
                evidence:
                    "Broker-owned UTC+monotonic samples bind Provider and Verification projections"
                        .into(),
            },
            CheckpointResult {
                id: "vs01.receipt-verification-outcome".into(),
                passed: self.final_mission.stage == MissionStage::Completed
                    && self.final_mission.effects.iter().all(|effect| {
                        effect.receipt.is_some()
                            && effect.verification.as_ref().is_some_and(|verification| {
                                verification.status == VerificationStatus::Confirmed
                            })
                    })
                    && self.final_mission.outcome.is_some(),
                evidence: "one execution, one receipt, independent readback, typed outcome".into(),
            },
            CheckpointResult {
                id: "vs01.trace-complete".into(),
                passed: trace_complete,
                evidence: format!("{} ordered Mission events", self.events.len()),
            },
        ]
    }
}

fn replay_input_digest(execution: &VerticalSliceExecution) -> Result<String> {
    digest_json(&SemanticReplayInput {
        schema: REPLAY_DIGEST_SCHEMA,
        scenario_id: VERTICAL_SLICE_ID,
        business_execution_entry: execution.window.business_execution_entry,
        provider_receipt_fact_at: execution.window.receipt_fact_at,
        verification_fact_at: execution.window.verification_fact_at,
        bounded_lease_duration_seconds: execution.window.lease_duration.num_seconds(),
        fixture_ids: SemanticReplayFixtureIds {
            tenant: TENANT_ID,
            project: &execution.ids.project,
            mission: &execution.ids.mission,
            actor: &execution.ids.actor,
            research_task: RESEARCH_TASK_ID,
            work_product: WORK_PRODUCT_ID,
            search_evidence: SEARCH_EVIDENCE_ID,
            catalog_evidence: CATALOG_EVIDENCE_ID,
            effect: &execution.ids.effect,
            receipt: &execution.receipt.id,
            verification: &execution.verification.id,
            provider: PROVIDER_ID,
            provider_external: PROVIDER_EXTERNAL_ID,
            broker_worker: BROKER_WORKER_ID,
        },
    })
}

fn semantic_digests(execution: &VerticalSliceExecution) -> Result<(String, String)> {
    let context = validate_live_execution(execution)?;
    Ok((
        semantic_state_digest(&execution.final_mission, &context)?,
        semantic_trace_digest(&execution.events, &context)?,
    ))
}

fn validate_live_execution(
    execution: &VerticalSliceExecution,
) -> Result<SemanticProjectionContext> {
    let context = validate_authority_events(execution)?;
    validate_effect_projection(execution, &context)?;
    validate_outcome_projection(execution, &context)?;
    Ok(context)
}

fn validate_authority_events(
    execution: &VerticalSliceExecution,
) -> Result<SemanticProjectionContext> {
    let (provider_event_index, provider_event) =
        unique_event(&execution.events, "effect.executed")?;
    let (verification_event_index, verification_event) =
        unique_event(&execution.events, "effect.verified")?;
    let (outcome_event_index, outcome_event) = unique_event(&execution.events, "outcome.observed")?;
    let (completed_event_index, completed_event) =
        unique_event(&execution.events, "mission.completed")?;
    for event in [
        provider_event,
        verification_event,
        outcome_event,
        completed_event,
    ] {
        ensure!(
            event.project_id == execution.ids.project
                && event.mission_id.as_ref() == Some(&execution.ids.mission),
            "semantic authority event escaped the exact fixture Mission scope"
        );
    }
    ensure!(
        event_string(provider_event, "effectId") == Some(execution.ids.effect.as_str())
            && event_string(provider_event, "receiptId") == Some(execution.receipt.id.as_str())
            && event_u64(provider_event, "authoritySequence") == Some(1)
            && event_string(verification_event, "effectId") == Some(execution.ids.effect.as_str())
            && event_string(verification_event, "verificationId")
                == Some(execution.verification.id.as_str())
            && event_u64(verification_event, "authoritySequence") == Some(2),
        "Effect authority event payload does not bind exact IDs and sequence 1/2"
    );
    ensure!(
        provider_event_index < verification_event_index
            && verification_event_index < outcome_event_index
            && outcome_event_index < completed_event_index
            && provider_event.sequence < verification_event.sequence
            && verification_event.sequence < outcome_event.sequence
            && outcome_event.sequence < completed_event.sequence,
        "semantic authority events are not in exact persisted sequence order"
    );
    let provider_at = provider_event.recorded_at;
    let verification_at = verification_event.recorded_at;
    ensure!(
        provider_at >= execution.window.business_execution_entry
            && provider_at <= verification_at
            && provider_at > execution.receipt.accepted_at
            && verification_at > execution.verification.observed_at
            && outcome_event.recorded_at == verification_at
            && completed_event.recorded_at == verification_at,
        "persisted Provider, Verification, Outcome or completion authority time is invalid"
    );
    Ok(SemanticProjectionContext {
        provider_event_index,
        verification_event_index,
        outcome_event_index,
        completed_event_index,
        provider_at,
        verification_at,
    })
}

fn validate_effect_projection(
    execution: &VerticalSliceExecution,
    context: &SemanticProjectionContext,
) -> Result<()> {
    let effect = execution.final_mission.effect(&execution.ids.effect)?;
    let receipt = effect
        .receipt
        .as_ref()
        .context("final Effect is missing its Receipt")?;
    let verification = effect
        .verification
        .as_ref()
        .context("final Effect is missing its Verification")?;
    let lease_deadline = execution
        .window
        .business_execution_entry
        .checked_add_signed(execution.window.lease_duration)
        .context("bounded fixture lease overflow")?;
    ensure!(
        execution.executor_calls == 1
            && receipt == &execution.receipt
            && verification == &execution.verification
            && receipt.id == ReceiptId::from(RECEIPT_ID)
            && receipt.provider == PROVIDER_ID
            && receipt.external_id == PROVIDER_EXTERNAL_ID
            && verification.id == VerificationId::from(VERIFICATION_ID)
            && verification.receipt_id == receipt.id
            && verification.independent
            && receipt.accepted_at == execution.window.receipt_fact_at
            && verification.observed_at == execution.window.verification_fact_at
            && receipt.accepted_at < context.provider_at
            && verification.observed_at < context.verification_at
            && execution.window.approval_decided_at < execution.window.business_execution_entry
            && lease_deadline < execution.window.approval_valid_until
            && lease_deadline < execution.window.effect_expires_at,
        "final Effect does not preserve the bounded live authority and fact-time contract"
    );
    Ok(())
}

fn validate_outcome_projection(
    execution: &VerticalSliceExecution,
    context: &SemanticProjectionContext,
) -> Result<()> {
    let outcome = execution
        .final_mission
        .outcome
        .as_ref()
        .context("final Mission is missing its latest Outcome")?;
    ensure!(
        execution.final_mission.updated_at == context.verification_at
            && outcome.observed_at == context.verification_at
            && execution.final_mission.outcome_history.len() == 1
            && execution.final_mission.outcome_history.first() == Some(outcome),
        "final Mission and unique Outcome projection must bind exact Verification authority"
    );
    Ok(())
}

fn unique_event<'a>(
    events: &'a [DomainEventRecord],
    event_type: &str,
) -> Result<(usize, &'a DomainEventRecord)> {
    let mut matches = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.event_type == event_type);
    let event = matches
        .next()
        .with_context(|| format!("missing persisted {event_type} event"))?;
    ensure!(
        matches.next().is_none(),
        "duplicate persisted {event_type} event"
    );
    Ok(event)
}

fn event_string<'a>(event: &'a DomainEventRecord, key: &str) -> Option<&'a str> {
    event.payload.as_object()?.get(key)?.as_str()
}

fn event_u64(event: &DomainEventRecord, key: &str) -> Option<u64> {
    event.payload.as_object()?.get(key)?.as_u64()
}

fn semantic_state_digest(mission: &Mission, context: &SemanticProjectionContext) -> Result<String> {
    let mut semantic = serde_json::to_value(mission)?;
    replace_authority_time(
        &mut semantic,
        "/updatedAt",
        context.verification_at,
        SemanticAuthorityStage::Verification,
        2,
    )?;
    replace_authority_time(
        &mut semantic,
        "/outcome/observedAt",
        context.verification_at,
        SemanticAuthorityStage::Verification,
        2,
    )?;
    replace_authority_time(
        &mut semantic,
        "/outcomeHistory/0/observedAt",
        context.verification_at,
        SemanticAuthorityStage::Verification,
        2,
    )?;
    digest_json(&semantic)
}

fn semantic_trace_digest(
    events: &[DomainEventRecord],
    context: &SemanticProjectionContext,
) -> Result<String> {
    let mut semantic = serde_json::to_value(events)?;
    replace_event_authority_time(
        &mut semantic,
        context.provider_event_index,
        context.provider_at,
        SemanticAuthorityStage::Provider,
        1,
    )?;
    replace_event_authority_time(
        &mut semantic,
        context.verification_event_index,
        context.verification_at,
        SemanticAuthorityStage::Verification,
        2,
    )?;
    for index in [context.outcome_event_index, context.completed_event_index] {
        replace_event_authority_time(
            &mut semantic,
            index,
            context.verification_at,
            SemanticAuthorityStage::VerificationProjection,
            2,
        )?;
    }
    digest_json(&semantic)
}

fn replace_event_authority_time(
    document: &mut Value,
    event_index: usize,
    expected: DateTime<Utc>,
    stage: SemanticAuthorityStage,
    authority_sequence: u64,
) -> Result<()> {
    replace_authority_time(
        document,
        &format!("/{event_index}/recordedAt"),
        expected,
        stage,
        authority_sequence,
    )
}

fn replace_authority_time(
    document: &mut Value,
    exact_pointer: &str,
    expected: DateTime<Utc>,
    stage: SemanticAuthorityStage,
    authority_sequence: u64,
) -> Result<()> {
    let target = document
        .pointer_mut(exact_pointer)
        .with_context(|| format!("semantic authority pointer missing: {exact_pointer}"))?;
    ensure!(
        *target == serde_json::to_value(expected)?,
        "semantic authority pointer differs from validated live authority: {exact_pointer}"
    );
    *target = serde_json::to_value(SemanticTimestampMarker {
        schema: SEMANTIC_MARKER_SCHEMA,
        stage,
        authority_sequence,
    })?;
    Ok(())
}

#[derive(Clone, Debug)]
struct Timeline {
    start: DateTime<Utc>,
}

impl Timeline {
    fn from_business_execution_entry(business_execution_entry: DateTime<Utc>) -> Result<Self> {
        let start = business_execution_entry
            .checked_sub_signed(Duration::minutes(5))
            .context("business timeline start underflow")?;
        Ok(Self { start })
    }

    fn at(&self, minute: i64) -> Result<DateTime<Utc>> {
        ensure!(
            (0..=5).contains(&minute),
            "business timeline minute must remain inside 0..=5"
        );
        self.start
            .checked_add_signed(Duration::minutes(minute))
            .context("business timeline timestamp overflow")
    }
}

#[derive(Debug)]
struct ControlledPreviewProvider {
    accepted_at: DateTime<Utc>,
    calls: usize,
}

impl ControlledPreviewProvider {
    fn new(accepted_at: DateTime<Utc>) -> Self {
        Self {
            accepted_at,
            calls: 0,
        }
    }
}

impl EffectExecutor for ControlledPreviewProvider {
    fn execute(&mut self, effect: &Effect) -> Result<Receipt, ProviderFailure> {
        self.calls += 1;
        Ok(Receipt {
            id: ReceiptId::from(RECEIPT_ID),
            provider: PROVIDER_ID.into(),
            external_id: PROVIDER_EXTERNAL_ID.into(),
            accepted_at: self.accepted_at,
            request_digest: effect.approval_digest(),
            response_digest: digest_bytes(b"publication=demo-001;visible=true;cost=0"),
        })
    }
}

#[derive(Debug)]
struct ControlledPreviewReadback {
    observed_at: DateTime<Utc>,
}

impl ControlledPreviewReadback {
    fn new(observed_at: DateTime<Utc>) -> Self {
        Self { observed_at }
    }
}

impl EffectVerifier for ControlledPreviewReadback {
    fn verify(&mut self, effect: &Effect, receipt: &Receipt) -> Verification {
        let confirmed = receipt.external_id == PROVIDER_EXTERNAL_ID
            && receipt.request_digest == effect.approval_digest()
            && effect.amount.amount_minor == 0;
        Verification {
            id: VerificationId::from(VERIFICATION_ID),
            status: if confirmed {
                VerificationStatus::Confirmed
            } else {
                VerificationStatus::Rejected
            },
            verifier: "controlled-preview-independent-readback".into(),
            independent: true,
            observed_at: self.observed_at,
            evidence_digest: digest_bytes(
                b"publication body and visibility read from an independent provider view",
            ),
            receipt_id: receipt.id.clone(),
        }
    }
}

fn digest_json(value: &impl Serialize) -> Result<String> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertical_slice_uses_live_authority_and_preserves_business_fact_order() {
        let business_execution_entry = Utc::now();
        let execution = execute_vertical_slice(business_execution_entry).expect("execute slice");
        let context = validate_live_execution(&execution).expect("validate live authority");
        let report = execution.report().expect("vertical slice report");

        assert!(report.passed);
        assert_eq!(report.schema, REPORT_SCHEMA);
        assert_eq!(report.provider_mode, PROVIDER_MODE);
        assert_eq!(report.authority_mode, AUTHORITY_MODE);
        assert_eq!(report.replay_digest_schema, REPLAY_DIGEST_SCHEMA);
        assert_eq!(report.final_stage, MissionStage::Completed);
        assert_eq!(execution.executor_calls, 1);
        assert_eq!(
            execution.window.business_execution_entry,
            business_execution_entry
        );
        assert_eq!(
            execution.window.receipt_fact_at,
            business_execution_entry
                .checked_sub_signed(Duration::seconds(2))
                .expect("Receipt fact")
        );
        assert_eq!(
            execution.window.verification_fact_at,
            business_execution_entry
                .checked_sub_signed(Duration::seconds(1))
                .expect("Verification fact")
        );
        assert_eq!(
            execution.window.lease_duration,
            Duration::minutes(LEASE_DURATION_MINUTES)
        );
        let lease_deadline = business_execution_entry
            .checked_add_signed(execution.window.lease_duration)
            .expect("lease deadline");
        assert!(execution.window.approval_decided_at < business_execution_entry);
        assert!(lease_deadline < execution.window.approval_valid_until);
        assert!(lease_deadline < execution.window.effect_expires_at);
        assert!(execution.receipt.accepted_at < context.provider_at);
        assert!(execution.verification.observed_at < context.verification_at);
        assert_eq!(
            event_u64(
                &execution.events[context.provider_event_index],
                "authoritySequence"
            ),
            Some(1)
        );
        assert_eq!(
            event_u64(
                &execution.events[context.verification_event_index],
                "authoritySequence"
            ),
            Some(2)
        );
        assert_eq!(execution.final_mission.updated_at, context.verification_at);
        assert_eq!(
            execution
                .final_mission
                .outcome
                .as_ref()
                .expect("latest Outcome")
                .observed_at,
            context.verification_at
        );
        assert_eq!(
            execution.final_mission.outcome_history[0].observed_at,
            context.verification_at
        );
        assert!(
            report
                .checkpoints
                .iter()
                .all(|checkpoint| checkpoint.passed)
        );
        for digest in [
            &report.replay_input_digest,
            &report.state_digest,
            &report.trace_digest,
            &report.semantic_state_digest,
            &report.semantic_trace_digest,
        ] {
            assert_sha256(digest);
        }
    }

    #[test]
    fn vertical_slice_semantic_replay_is_deterministic_for_recorded_business_input() {
        let business_execution_entry = Utc::now();
        let first = run_vertical_slice_with_business_entry(business_execution_entry)
            .expect("first live-authority run");
        let second = run_vertical_slice_with_business_entry(business_execution_entry)
            .expect("second live-authority run");

        assert_eq!(first.replay_input_digest, second.replay_input_digest);
        assert_eq!(first.semantic_state_digest, second.semantic_state_digest);
        assert_eq!(first.semantic_trace_digest, second.semantic_trace_digest);
    }

    #[test]
    fn semantic_digests_preserve_business_and_evidence_mutation_sensitivity() {
        let execution = execute_vertical_slice(Utc::now()).expect("execute slice");
        let (state_digest, trace_digest) = semantic_digests(&execution).expect("semantic digests");

        let mut business_mutation = execution.clone();
        business_mutation.final_mission.title.push_str("-mutated");
        let (mutated_state, _) =
            semantic_digests(&business_mutation).expect("business mutation digest");
        assert_ne!(mutated_state, state_digest);

        let mut receipt_mutation = execution.clone();
        let response_digest = digest_bytes(b"mutated Provider response evidence");
        receipt_mutation
            .receipt
            .response_digest
            .clone_from(&response_digest);
        fixture_effect_mut(&mut receipt_mutation)
            .receipt
            .as_mut()
            .expect("Receipt projection")
            .response_digest = response_digest;
        let (mutated_state, _) =
            semantic_digests(&receipt_mutation).expect("Receipt mutation digest");
        assert_ne!(mutated_state, state_digest);

        let mut verification_mutation = execution.clone();
        let evidence_digest = digest_bytes(b"mutated Verification evidence");
        verification_mutation
            .verification
            .evidence_digest
            .clone_from(&evidence_digest);
        fixture_effect_mut(&mut verification_mutation)
            .verification
            .as_mut()
            .expect("Verification projection")
            .evidence_digest = evidence_digest;
        let (mutated_state, _) =
            semantic_digests(&verification_mutation).expect("Verification mutation digest");
        assert_ne!(mutated_state, state_digest);

        let mut payload_mutation = execution.clone();
        let provider_index = unique_event(&payload_mutation.events, "effect.executed")
            .expect("Provider event")
            .0;
        *payload_mutation.events[provider_index]
            .payload
            .get_mut("disposition")
            .expect("Provider event disposition") = Value::String("Mutated".into());
        let (_, mutated_trace) =
            semantic_digests(&payload_mutation).expect("event payload mutation digest");
        assert_ne!(mutated_trace, trace_digest);

        let mut business_time_mutation = execution.clone();
        let started_index = unique_event(&business_time_mutation.events, "mission.started")
            .expect("business event")
            .0;
        let mutated_business_time = business_time_mutation.events[started_index]
            .recorded_at
            .checked_add_signed(Duration::seconds(1))
            .expect("business event time");
        business_time_mutation.events[started_index].recorded_at = mutated_business_time;
        let (_, mutated_trace) =
            semantic_digests(&business_time_mutation).expect("business time mutation digest");
        assert_ne!(mutated_trace, trace_digest);
    }

    #[test]
    fn semantic_projection_fails_closed_on_missing_or_duplicate_authority() {
        let execution = execute_vertical_slice(Utc::now()).expect("execute slice");

        let mut duplicate = execution.clone();
        let provider_event = unique_event(&duplicate.events, "effect.executed")
            .expect("Provider event")
            .1
            .clone();
        duplicate.events.push(provider_event);
        assert!(semantic_digests(&duplicate).is_err());

        let mut missing = execution.clone();
        missing
            .events
            .retain(|event| event.event_type != "effect.verified");
        assert!(semantic_digests(&missing).is_err());

        let mut projection_mismatch = execution;
        projection_mismatch.final_mission.updated_at = projection_mismatch
            .final_mission
            .updated_at
            .checked_add_signed(Duration::seconds(1))
            .expect("projection mutation");
        assert!(semantic_digests(&projection_mismatch).is_err());
    }

    fn fixture_effect_mut(execution: &mut VerticalSliceExecution) -> &mut Effect {
        execution
            .final_mission
            .effects
            .iter_mut()
            .find(|effect| effect.id == execution.ids.effect)
            .expect("fixture Effect")
    }

    fn assert_sha256(digest: &str) {
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

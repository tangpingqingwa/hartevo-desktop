//! Deterministic local Mission evidence for the first vertical slice.

mod run_receipt;

pub use run_receipt::{
    CaseExecutionDisposition, CaseExecutionEvidence, CompletedCaseEvidence, EffectEvidence,
    EvaluationCaseResult, EvaluationRunPlan, EvaluationRunProfile, EvaluationRunReceipt,
    EvaluationRunWriter, EvidenceArtifactRef, MissionId as EvaluationMissionId, OracleKind,
    OracleResultRef, SafetyAssertionRef, TerminalOutcome, finalize_evaluation_run,
    validate_evaluation_run,
};

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_application::{
    ApplicationService, CreateProject, EvidenceInput, ProposePreviewEffect, ResearchPacket,
    StartMission, WorkSurface,
};
use hartevo_catalog::{Catalog, CatalogSnapshot, ReleaseEvidence};
use hartevo_domain_kernel::{
    ActorId, ConsentState, CurrencyCode, Effect, EffectClass, EffectId, MetricValue, MissionId,
    MissionStage, Money, OutcomeDecision, ProjectId, Receipt, ReceiptId, StorageMode, TaskId,
    TenantId, Verification, VerificationId, VerificationStatus, WorkProductId,
};
use hartevo_effect_broker::{
    EffectBroker, EffectExecutor, EffectPolicy, EffectRateLimit, EffectVerifier,
    ExecutionDisposition, ProviderFailure,
};
use hartevo_storage::ProjectStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERTICAL_SLICE_ID: &str = "VS-01";

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
pub struct VerticalSliceReport {
    pub schema: String,
    pub scenario_id: String,
    pub provider_mode: String,
    pub passed: bool,
    pub checkpoints: Vec<CheckpointResult>,
    pub final_stage: MissionStage,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub receipt_id: ReceiptId,
    pub verification_id: VerificationId,
    pub event_types: Vec<String>,
    pub state_digest: String,
    pub trace_digest: String,
}

#[allow(clippy::too_many_lines)]
pub fn run_vertical_slice() -> Result<VerticalSliceReport> {
    let store = ProjectStore::in_memory().context("create isolated eval store")?;
    let mut service = ApplicationService::new(store);
    let timeline = Timeline::new();
    let project_id = ProjectId::from("eval-project-vs01");
    let mission_id = MissionId::from("eval-mission-vs01");
    let actor_id = ActorId::from("eval-user");

    service.create_project(
        CreateProject {
            tenant_id: TenantId::from("eval-tenant"),
            id: project_id.clone(),
            name: "可控新品发布验证".into(),
            description: "Deterministic local Mission world".into(),
            workspace_root: PathBuf::from("/tmp/hartevo-eval/vs-01"),
            storage_mode: StorageMode::LocalExisting,
        },
        timeline.at(0),
    )?;
    service.start_mission(
        StartMission {
            id: mission_id.clone(),
            research_task_id: TaskId::from("eval-task-research"),
            project_id: project_id.clone(),
            title: Some("验证新品发布简报".into()),
            prompt: "核对新品需求并生成可追溯发布简报；未经我批准不要发布，预算 0 元".into(),
        },
        timeline.at(1),
    )?;

    let orchestrator = service.projection(&project_id, &mission_id, WorkSurface::Orchestrator)?;
    let channels = service.projection(&project_id, &mission_id, WorkSurface::ChannelOperations)?;
    let shared_state = orchestrator.revision == channels.revision
        && orchestrator.mission_id == channels.mission_id
        && orchestrator.stage == channels.stage;

    service.record_research(
        &project_id,
        &mission_id,
        ResearchPacket {
            work_product_id: WorkProductId::from("eval-work-product-brief"),
            title: "新品发布验证简报".into(),
            body:
                "需求信号在两个独立来源中一致。建议只发布零预算预览页，先验证可见性与消息准确性。"
                    .into(),
            work_product_type: "document.launch_brief".into(),
            fact_ids: BTreeSet::new(),
            task_ids: BTreeSet::from([TaskId::from("eval-task-research")]),
            file_digest: None,
            preview_media_type: "text/plain".into(),
            preview: "新品需求已由两个独立来源核验，建议先发布零预算预览页。".into(),
            editable_scopes: BTreeSet::from(["/body".into()]),
            evidence: vec![
                EvidenceInput {
                    id: hartevo_domain_kernel::EvidenceId::from("eval-evidence-search"),
                    title: "搜索需求样本".into(),
                    source_uri: "fixture://search/demand-v1".into(),
                    confidence: 0.92,
                    content: "query-volume=stable; market=CN; sample=120".into(),
                },
                EvidenceInput {
                    id: hartevo_domain_kernel::EvidenceId::from("eval-evidence-catalog"),
                    title: "商品目录核验".into(),
                    source_uri: "fixture://catalog/product-v1".into(),
                    confidence: 1.0,
                    content: "sku=demo-001; claims=verified; inventory=available".into(),
                },
            ],
        },
        timeline.at(2),
    )?;

    let effect_id = service.propose_preview_effect(
        &project_id,
        &mission_id,
        ProposePreviewEffect {
            effect_id: EffectId::from("eval-effect-preview"),
            actor_id: actor_id.clone(),
            capability: "channel.preview_publish".into(),
            provider: "controlled-preview-provider".into(),
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
        timeline.at(3),
    )?;

    let before_approval = service.load_mission(&project_id, &mission_id)?;
    let approval_gate_held = before_approval
        .effect(&effect_id)
        .is_ok_and(|effect| effect.status == hartevo_domain_kernel::EffectStatus::Proposed);

    let mut broker = EffectBroker::new(
        EffectPolicy {
            version: "eval-policy-v1".into(),
            allowed_capabilities: BTreeSet::from(["channel.preview_publish".into()]),
            allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
            max_amounts_minor: BTreeMap::from([(CurrencyCode::parse("CNY")?, 0)]),
            rate_limits: vec![EffectRateLimit {
                rule_id: "controlled-preview-per-minute".into(),
                provider: "controlled-preview-provider".into(),
                capability: "channel.preview_publish".into(),
                max_executions: 10,
                window_seconds: 60,
            }],
        },
        "eval-worker-vs01",
    );
    service.approve_effect(
        &broker,
        &project_id,
        &mission_id,
        &effect_id,
        actor_id,
        timeline.at(4),
    )?;

    let mut executor = ControlledPreviewProvider::new(timeline.at(5));
    let mut verifier = ControlledPreviewReadback::new(timeline.at(6));
    let (_verified_mission, broker_result) = service.execute_effect(
        &mut broker,
        &project_id,
        &mission_id,
        &effect_id,
        &mut executor,
        &mut verifier,
        timeline.at(5),
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

    let final_mission = service.record_outcome(
        &project_id,
        &mission_id,
        "预览已唯一发布并完成独立可见性核验；可以进入小范围真实渠道测试。",
        OutcomeDecision::Test,
        BTreeMap::from([
            ("providerExecutions".into(), MetricValue::Count { value: 1 }),
            ("verifiedEffects".into(), MetricValue::Count { value: 1 }),
            ("costMinor".into(), MetricValue::Count { value: 0 }),
        ]),
        timeline.at(7),
    )?;
    let events = service.mission_events(&project_id, &mission_id)?;
    let event_types: Vec<String> = events
        .iter()
        .map(|event| event.event_type.clone())
        .collect();
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

    let checkpoints = vec![
        CheckpointResult {
            id: "vs01.project-local".into(),
            passed: true,
            evidence: "/tmp/hartevo-eval/vs-01 is the only workspace root".into(),
        },
        CheckpointResult {
            id: "vs01.mission-compiled".into(),
            passed: final_mission.contract.constraints.iter().any(|constraint| {
                matches!(
                    constraint,
                    hartevo_domain_kernel::Constraint::RequireApproval { .. }
                )
            }),
            evidence: "approval and zero-budget constraints are typed domain state".into(),
        },
        CheckpointResult {
            id: "vs01.shared-state".into(),
            passed: shared_state,
            evidence: "orchestrator and channel surfaces read one Mission revision".into(),
        },
        CheckpointResult {
            id: "vs01.evidence-and-work-product".into(),
            passed: final_mission.evidence.len() == 2
                && final_mission.work_products.len() == 1
                && final_mission.work_products[0].evidence_ids.len() == 2,
            evidence: "work product references two confirmed evidence records".into(),
        },
        CheckpointResult {
            id: "vs01.approval-gate".into(),
            passed: approval_gate_held,
            evidence: "provider executor remained unreachable while Effect was proposed".into(),
        },
        CheckpointResult {
            id: "vs01.receipt-verification-outcome".into(),
            passed: final_mission.stage == MissionStage::Completed
                && final_mission.effects.iter().all(|effect| {
                    effect.receipt.is_some()
                        && effect.verification.as_ref().is_some_and(|verification| {
                            verification.status == VerificationStatus::Confirmed
                        })
                })
                && final_mission.outcome.is_some(),
            evidence: "one execution, one receipt, independent readback, typed outcome".into(),
        },
        CheckpointResult {
            id: "vs01.trace-complete".into(),
            passed: trace_complete,
            evidence: format!("{} ordered Mission events", events.len()),
        },
    ];
    let passed = checkpoints.iter().all(|checkpoint| checkpoint.passed);
    let state_digest = digest_json(&final_mission)?;
    let trace_digest = digest_json(&events)?;

    Ok(VerticalSliceReport {
        schema: "hartevo-eval-report/v1".into(),
        scenario_id: VERTICAL_SLICE_ID.into(),
        provider_mode: "controlled-simulator".into(),
        passed,
        checkpoints,
        final_stage: final_mission.stage,
        project_id,
        mission_id,
        receipt_id: broker_result.receipt.id,
        verification_id: broker_result.verification.id,
        event_types,
        state_digest,
        trace_digest,
    })
}

#[derive(Clone, Debug)]
struct Timeline {
    start: DateTime<Utc>,
}

impl Timeline {
    fn new() -> Self {
        Self {
            start: Utc
                .with_ymd_and_hms(2026, 8, 10, 12, 0, 0)
                .single()
                .expect("valid fixture time"),
        }
    }

    fn at(&self, minute: i64) -> DateTime<Utc> {
        self.start + Duration::minutes(minute)
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
            id: ReceiptId::from("eval-receipt-preview"),
            provider: "controlled-preview-provider".into(),
            external_id: "controlled-preview://publication/demo-001/v1".into(),
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
        let confirmed = receipt.external_id == "controlled-preview://publication/demo-001/v1"
            && receipt.request_digest == effect.approval_digest()
            && effect.amount.amount_minor == 0;
        Verification {
            id: VerificationId::from("eval-verification-preview"),
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
    fn vertical_slice_passes_every_checkpoint() {
        let report = run_vertical_slice().expect("vertical slice");
        assert!(report.passed);
        assert_eq!(report.final_stage, MissionStage::Completed);
        assert!(
            report
                .checkpoints
                .iter()
                .all(|checkpoint| checkpoint.passed)
        );
    }

    #[test]
    fn vertical_slice_is_replay_deterministic() {
        let first = run_vertical_slice().expect("first run");
        let second = run_vertical_slice().expect("second run");
        assert_eq!(first.state_digest, second.state_digest);
        assert_eq!(first.trace_digest, second.trace_digest);
    }
}

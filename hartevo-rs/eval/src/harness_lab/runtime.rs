use std::collections::BTreeSet;
use std::env;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::digest::digest_json;
use super::model::{
    CandidateIdentity, ComparisonRole, DecisionStatus, EvaluationInput, EvaluationLane,
    EvidenceKind, HarnessFamily, LabPlan, MetricSnapshot, PromotionDecision, RunResult,
    RunnerDisposition,
};
use super::promotion::{
    CandidateIdentityFreeze, CurrentCommitReceipt, build_current_commit_receipt,
    candidate_identity_digest, freeze_candidate_identity, promotion_contract_digest,
    verify_current_commit_receipt_against_run, verify_frozen_candidate_identity,
};
use super::verifier::{
    build_run_result, contract_digest, current_source_commit, evaluate, validate_plan_with_bindings,
};

pub const RUNTIME_SCHEMA_VERSION: &str = "hartevo-harness-runtime-runner/v1";
pub const RUNTIME_AUTHORITY: &str = "candidate_lab_only";
pub const RUNTIME_RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const RUNTIME_CONTRACT_PATH: &str = "contracts/harness/runtime-runner.v1.json";
const PLAN_DIGEST_DOMAIN: &str = "hartevo-harness-lab-plan/v1";
const REPLAY_PACK_DIGEST_DOMAIN: &str = "hartevo-harness-runtime-replay-pack/v1";
const CREDENTIAL_ENV: &str = "HARTEVO_HARNESS_NATIVE_CREDENTIALS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeExecutionMode {
    FakeDeterministic,
    NativeCredentialed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeQualityStatus {
    Green,
    NotEvaluated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeMetricRow {
    pub entry_id: String,
    pub lane: EvaluationLane,
    pub role: ComparisonRole,
    pub harness: HarnessFamily,
    pub candidate_identity_digest: String,
    pub metrics: MetricSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeReplayPack {
    pub schema_version: String,
    pub pack_digest: String,
    pub source_commit: String,
    pub candidate_identity_digest: String,
    pub plan_digest: String,
    pub matrix_digest: String,
    pub run_ids: Vec<String>,
    pub replay_digests: Vec<String>,
    pub deterministic: bool,
    pub isolated_lanes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeMatrixReport {
    pub schema_version: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub execution_mode: RuntimeExecutionMode,
    pub execution_status: RunnerDisposition,
    pub quality_status: RuntimeQualityStatus,
    pub plan: LabPlan,
    pub plan_digest: String,
    pub matrix_digest: String,
    pub candidate_freeze: CandidateIdentityFreeze,
    pub candidate_identity_digest: String,
    pub results: Vec<RunResult>,
    pub metrics: Vec<RuntimeMetricRow>,
    pub candidate_receipts: Vec<CurrentCommitReceipt>,
    pub replay_pack: RuntimeReplayPack,
    pub promotion: PromotionDecision,
    pub missing_required_evidence: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCandidateRunner {
    mode: RuntimeExecutionMode,
}

impl RuntimeCandidateRunner {
    pub const fn fake_deterministic() -> Self {
        Self {
            mode: RuntimeExecutionMode::FakeDeterministic,
        }
    }

    pub const fn native_credentialed() -> Self {
        Self {
            mode: RuntimeExecutionMode::NativeCredentialed,
        }
    }

    pub const fn mode(self) -> RuntimeExecutionMode {
        self.mode
    }

    pub fn run(&self, plan: &LabPlan) -> Result<RuntimeMatrixReport> {
        let source_commit = current_source_commit()?;
        self.run_with_expected_commit(plan, &source_commit)
    }

    pub fn run_with_expected_commit(
        &self,
        plan: &LabPlan,
        expected_source_commit: &str,
    ) -> Result<RuntimeMatrixReport> {
        let (plan_digest, candidate_freeze) = prepare_runtime_plan(plan, expected_source_commit)?;
        let credentials_available = self.native_credentials_available();
        let results = plan
            .entries
            .iter()
            .map(|entry| self.run_entry(entry, credentials_available))
            .collect::<Result<Vec<_>>>()?;
        assemble_runtime_report(
            self.mode,
            credentials_available,
            plan,
            expected_source_commit,
            plan_digest,
            candidate_freeze,
            results,
        )
    }

    fn native_credentials_available(self) -> bool {
        self.mode == RuntimeExecutionMode::FakeDeterministic
            || env::var_os(CREDENTIAL_ENV).is_some_and(|value| !value.is_empty())
    }

    fn run_entry(
        self,
        entry: &super::model::MatrixEntry,
        credentials_available: bool,
    ) -> Result<RunResult> {
        match self.mode {
            RuntimeExecutionMode::FakeDeterministic => build_run_result(
                entry,
                RunnerDisposition::Executed,
                EvidenceKind::DeterministicFake,
                fake_cases(entry),
            ),
            RuntimeExecutionMode::NativeCredentialed if !credentials_available => build_run_result(
                entry,
                RunnerDisposition::BlockedEnv,
                EvidenceKind::Missing,
                Vec::new(),
            ),
            RuntimeExecutionMode::NativeCredentialed => build_run_result(
                entry,
                RunnerDisposition::NotImplemented,
                EvidenceKind::Missing,
                Vec::new(),
            ),
        }
    }
}

fn prepare_runtime_plan(
    plan: &LabPlan,
    expected_source_commit: &str,
) -> Result<(String, CandidateIdentityFreeze)> {
    let expected_contract_digest = contract_digest()?;
    validate_plan_with_bindings(plan, expected_source_commit, &expected_contract_digest)?;
    let plan_digest = digest_json(PLAN_DIGEST_DOMAIN, plan)?;
    let candidate_entries = plan
        .entries
        .iter()
        .filter(|entry| entry.role == ComparisonRole::Candidate)
        .collect::<Vec<_>>();
    ensure!(
        candidate_entries.len() == 4,
        "runtime runner requires one candidate entry per evaluation lane"
    );
    let candidate_identity = candidate_entries[0].identity.clone();
    ensure!(
        candidate_entries
            .iter()
            .all(|entry| entry.identity == candidate_identity),
        "candidate identity differs across runtime lanes"
    );
    let freeze = freeze_candidate_identity(
        candidate_identity,
        expected_source_commit,
        &plan_digest,
        &plan.matrix_digest,
        &promotion_contract_digest()?,
    )?;
    Ok((plan_digest, freeze))
}

fn assemble_runtime_report(
    mode: RuntimeExecutionMode,
    credentials_available: bool,
    plan: &LabPlan,
    expected_source_commit: &str,
    plan_digest: String,
    candidate_freeze: CandidateIdentityFreeze,
    results: Vec<RunResult>,
) -> Result<RuntimeMatrixReport> {
    let evaluation = evaluate(&EvaluationInput {
        plan,
        results: &results,
        signed_record: None,
        trusted_keys: &[],
        expected_source_commit,
    })?;
    let candidate_receipts = results
        .iter()
        .filter(|result| result.role == ComparisonRole::Candidate)
        .filter_map(|result| {
            build_current_commit_receipt(result, &plan_digest, &plan.matrix_digest).ok()
        })
        .collect::<Vec<_>>();
    let metrics = derive_metric_rows(&results)?;
    let replay_pack = build_replay_pack(
        mode,
        expected_source_commit,
        &candidate_freeze,
        &plan_digest,
        &plan.matrix_digest,
        &results,
    )?;
    let (execution_status, quality_status) = derive_runtime_status(&results, &evaluation);
    let mut missing_required_evidence = evaluation.missing_required_evidence;
    if mode == RuntimeExecutionMode::NativeCredentialed && !credentials_available {
        missing_required_evidence.push(format!("native_credentials:{CREDENTIAL_ENV}"));
    }
    missing_required_evidence.sort();
    missing_required_evidence.dedup();
    Ok(RuntimeMatrixReport {
        schema_version: RUNTIME_SCHEMA_VERSION.into(),
        authority: RUNTIME_AUTHORITY.into(),
        release_decision: RUNTIME_RELEASE_DECISION.into(),
        source_commit: expected_source_commit.into(),
        execution_mode: mode,
        execution_status,
        quality_status,
        plan: plan.clone(),
        plan_digest,
        matrix_digest: plan.matrix_digest.clone(),
        candidate_identity_digest: candidate_freeze.candidate_identity_digest.clone(),
        candidate_freeze,
        results,
        metrics,
        candidate_receipts,
        replay_pack,
        promotion: evaluation.promotion,
        missing_required_evidence,
    })
}

fn derive_runtime_status(
    results: &[RunResult],
    evaluation: &super::model::HarnessLabReport,
) -> (RunnerDisposition, RuntimeQualityStatus) {
    let execution_status = results
        .iter()
        .find(|result| result.runner_disposition != RunnerDisposition::Executed)
        .map_or(RunnerDisposition::Executed, |result| {
            result.runner_disposition
        });
    let quality_status = if execution_status == RunnerDisposition::Executed
        && evaluation
            .lane_summaries
            .iter()
            .all(|summary| summary.status == RunnerDisposition::Executed)
    {
        RuntimeQualityStatus::Green
    } else {
        RuntimeQualityStatus::NotEvaluated
    };
    (execution_status, quality_status)
}

pub fn validate_runtime_matrix_report(
    report: &RuntimeMatrixReport,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        report.schema_version == RUNTIME_SCHEMA_VERSION,
        "runtime matrix report schema is unknown"
    );
    ensure!(
        report.authority == RUNTIME_AUTHORITY,
        "runtime report authority is not candidate-only"
    );
    ensure!(
        report.release_decision == RUNTIME_RELEASE_DECISION,
        "runtime report cannot issue a release decision"
    );
    ensure!(
        report.source_commit == expected_source_commit,
        "runtime report is stale"
    );
    let expected_contract_digest = contract_digest()?;
    let plan = &report.plan;
    validate_plan_with_bindings(plan, expected_source_commit, &expected_contract_digest)?;
    let expected_plan_digest = digest_json(PLAN_DIGEST_DOMAIN, plan)?;
    ensure!(
        report.plan_digest == expected_plan_digest,
        "runtime plan digest is not derived"
    );
    ensure!(
        report.matrix_digest == plan.matrix_digest,
        "runtime matrix digest is stale"
    );
    verify_frozen_candidate_identity(
        &report.candidate_freeze,
        &candidate_identity_from_plan(plan)?,
    )?;
    ensure!(
        report.candidate_identity_digest == report.candidate_freeze.candidate_identity_digest,
        "runtime candidate identity digest differs from freeze"
    );
    validate_runtime_result_set(plan, &report.results)?;
    let evaluation = evaluate(&EvaluationInput {
        plan,
        results: &report.results,
        signed_record: None,
        trusted_keys: &[],
        expected_source_commit,
    })?;
    ensure!(
        report.promotion == evaluation.promotion,
        "runtime promotion decision is not derived"
    );
    ensure!(
        report.metrics == derive_metric_rows(&report.results)?,
        "runtime metrics are not derived from results"
    );
    validate_runtime_derived_fields(report, &evaluation, expected_source_commit)
}

fn validate_runtime_result_set(plan: &LabPlan, results: &[RunResult]) -> Result<()> {
    ensure!(
        results.len() == plan.entries.len(),
        "runtime result set is not the exact configured matrix"
    );
    let expected = plan
        .entries
        .iter()
        .map(|entry| entry.entry_id.as_str())
        .collect::<BTreeSet<_>>();
    let observed = results
        .iter()
        .map(|result| result.entry_id.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        observed == expected,
        "runtime result set differs from configured entries"
    );
    Ok(())
}

fn validate_runtime_derived_fields(
    report: &RuntimeMatrixReport,
    evaluation: &super::model::HarnessLabReport,
    expected_source_commit: &str,
) -> Result<()> {
    let expected_candidate_receipts = report
        .results
        .iter()
        .filter(|result| result.role == ComparisonRole::Candidate)
        .filter_map(|result| {
            build_current_commit_receipt(result, &report.plan_digest, &report.matrix_digest).ok()
        })
        .collect::<Vec<_>>();
    ensure!(
        report.candidate_receipts == expected_candidate_receipts,
        "runtime candidate receipts are not the exact derived set"
    );
    for receipt in &report.candidate_receipts {
        let result = report
            .results
            .iter()
            .find(|result| result.run_id == receipt.run_id)
            .context("runtime receipt references an unknown run")?;
        verify_current_commit_receipt_against_run(
            receipt,
            result,
            &report.candidate_freeze,
            expected_source_commit,
        )?;
    }
    let expected_replay_pack = build_replay_pack(
        report.execution_mode,
        expected_source_commit,
        &report.candidate_freeze,
        &report.plan_digest,
        &report.matrix_digest,
        &report.results,
    )?;
    ensure!(
        report.replay_pack == expected_replay_pack,
        "runtime replay pack is not derived"
    );
    let expected_quality = if report
        .results
        .iter()
        .all(|result| result.runner_disposition == RunnerDisposition::Executed)
        && evaluation
            .lane_summaries
            .iter()
            .all(|summary| summary.status == RunnerDisposition::Executed)
    {
        RuntimeQualityStatus::Green
    } else {
        RuntimeQualityStatus::NotEvaluated
    };
    ensure!(
        report.quality_status == expected_quality,
        "runtime quality status is not derived"
    );
    let expected_execution_status = report
        .results
        .iter()
        .find(|result| result.runner_disposition != RunnerDisposition::Executed)
        .map_or(RunnerDisposition::Executed, |result| {
            result.runner_disposition
        });
    ensure!(
        report.execution_status == expected_execution_status,
        "runtime execution status is not derived"
    );
    ensure!(
        report.promotion.status != DecisionStatus::Approved,
        "runtime runner cannot approve promotion without a trusted signed record"
    );
    Ok(())
}

fn candidate_identity_from_plan(plan: &LabPlan) -> Result<CandidateIdentity> {
    let candidates = plan
        .entries
        .iter()
        .filter(|entry| entry.role == ComparisonRole::Candidate)
        .map(|entry| &entry.identity)
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() == 4,
        "runtime plan has no exact candidate lane set"
    );
    ensure!(
        candidates.windows(2).all(|window| window[0] == window[1]),
        "candidate identity differs across lanes"
    );
    Ok(candidates[0].clone())
}

fn derive_metric_rows(results: &[RunResult]) -> Result<Vec<RuntimeMetricRow>> {
    results
        .iter()
        .map(|result| {
            Ok(RuntimeMetricRow {
                entry_id: result.entry_id.clone(),
                lane: result.lane,
                role: result.role,
                harness: result.harness,
                candidate_identity_digest: candidate_identity_digest(&result.identity)?,
                metrics: result.metrics.clone(),
            })
        })
        .collect()
}

fn build_replay_pack(
    mode: RuntimeExecutionMode,
    source_commit: &str,
    freeze: &CandidateIdentityFreeze,
    plan_digest: &str,
    matrix_digest: &str,
    results: &[RunResult],
) -> Result<RuntimeReplayPack> {
    let run_ids = results
        .iter()
        .map(|result| result.run_id.clone())
        .collect::<Vec<_>>();
    let replay_digests = results
        .iter()
        .map(|result| result.replay_pack.replay_digest.clone())
        .collect::<Vec<_>>();
    let mut lanes = BTreeSet::new();
    let leakage_free = results.iter().all(|result| {
        lanes.insert(result.lane);
        !result
            .replay_pack
            .leakage
            .private
            .private_data_read_by_target
            && !result
                .replay_pack
                .leakage
                .private
                .private_data_read_by_optimizer
            && !result
                .replay_pack
                .leakage
                .private
                .private_data_read_by_product_workspace
            && !result.replay_pack.leakage.cross_lane.cross_lane_reference
            && !result
                .replay_pack
                .leakage
                .cross_lane
                .candidate_observed_fresh_shadow
    });
    let isolated_lanes = lanes.len() == 4;
    let deterministic = mode == RuntimeExecutionMode::FakeDeterministic
        && results
            .iter()
            .all(|result| result.runner_disposition == RunnerDisposition::Executed)
        && leakage_free
        && isolated_lanes;
    let pack_digest = digest_json(
        REPLAY_PACK_DIGEST_DOMAIN,
        &json!({
            "schemaVersion": RUNTIME_SCHEMA_VERSION,
            "sourceCommit": source_commit,
            "candidateIdentityDigest": freeze.candidate_identity_digest,
            "planDigest": plan_digest,
            "matrixDigest": matrix_digest,
            "runIds": run_ids,
            "replayDigests": replay_digests,
            "deterministic": deterministic,
            "isolatedLanes": isolated_lanes,
        }),
    )?;
    Ok(RuntimeReplayPack {
        schema_version: RUNTIME_SCHEMA_VERSION.into(),
        pack_digest,
        source_commit: source_commit.into(),
        candidate_identity_digest: freeze.candidate_identity_digest.clone(),
        plan_digest: plan_digest.into(),
        matrix_digest: matrix_digest.into(),
        run_ids,
        replay_digests,
        deterministic,
        isolated_lanes,
    })
}

fn fake_cases(entry: &super::model::MatrixEntry) -> Vec<super::model::CaseObservation> {
    (0..entry.configured_case_count)
        .map(|index| super::model::CaseObservation {
            case_id: format!("{}-{index:04}", entry.entry_id),
            goal: super::model::GoalFlags {
                goal_complete: true,
                constraints_preserved: true,
            },
            outcome: super::model::OutcomeFlags {
                verified_outcome: true,
                loop_closed: true,
            },
            safety_invariants: super::model::SAFETY_INVARIANT_IDS
                .into_iter()
                .map(|id| (id.to_owned(), true))
                .collect(),
            latency_ms: 100,
            cost_micros: 100,
            process: super::model::ProcessFlags {
                recovered: true,
                tool_correct: true,
                human_rework: false,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value;

    use super::super::model::{CandidateIdentity, EvidenceKind, PlanInputs, ProviderMode};
    use super::super::verifier::{build_frozen_plan, contract_digest};
    use super::{
        RUNTIME_SCHEMA_VERSION, RuntimeCandidateRunner, RuntimeExecutionMode, RuntimeMatrixReport,
        RuntimeQualityStatus, validate_runtime_matrix_report,
    };

    const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const DATASET_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const AUX_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn identity(id: &str, scope: &str, harness: &str) -> CandidateIdentity {
        CandidateIdentity {
            candidate_id: id.into(),
            provider_id: "provider-route-v1".into(),
            provider_mode: ProviderMode::NativeCredentialed,
            model: "model-under-test".into(),
            model_revision: "model-revision-v1".into(),
            harness: harness.into(),
            harness_revision: "harness-revision-v1".into(),
            effort: "balanced".into(),
            service_tier: "standard".into(),
            budget_micros: 500_000,
            retry_policy: "read_only_bounded_v1".into(),
            seed_policy: "frozen_seed_v1".into(),
            run_repetitions: 1,
            runtime_revision: "runtime-v1".into(),
            schema_version: "schema-v1".into(),
            tool_catalog_digest: AUX_DIGEST.into(),
            source_commit: SOURCE_COMMIT.into(),
            environment_digest: AUX_DIGEST.into(),
            config_digest: AUX_DIGEST.into(),
            candidate_scope: scope.into(),
            production_defaults_unchanged: true,
        }
    }

    fn plan() -> super::super::model::LabPlan {
        build_frozen_plan(PlanInputs {
            source_commit: SOURCE_COMMIT.into(),
            contract_digest: contract_digest().expect("candidate lab digest"),
            benchmark_revision: "frozen-benchmark-v1".into(),
            dataset_revision: "dataset-v1".into(),
            dataset_digest: DATASET_DIGEST.into(),
            baseline_native: identity("baseline-native", "baseline", "native"),
            baseline_upstream: identity("baseline-upstream", "baseline", "upstream"),
            candidate: identity("candidate-v1", "candidate_only", "hartevo-candidate"),
        })
        .expect("plan")
    }

    #[test]
    fn fake_matrix_is_deterministic_green_and_promotion_denied() {
        let plan = plan();
        let runner = RuntimeCandidateRunner::fake_deterministic();
        let first = runner
            .run_with_expected_commit(&plan, SOURCE_COMMIT)
            .expect("fake matrix");
        let second = runner
            .run_with_expected_commit(&plan, SOURCE_COMMIT)
            .expect("fake matrix replay");
        assert_eq!(first, second);
        assert_eq!(
            first.execution_mode,
            RuntimeExecutionMode::FakeDeterministic
        );
        assert_eq!(first.schema_version, RUNTIME_SCHEMA_VERSION);
        assert_eq!(
            first.execution_status,
            super::super::model::RunnerDisposition::Executed
        );
        assert_eq!(first.quality_status, RuntimeQualityStatus::Green);
        assert_eq!(first.results.len(), 12);
        assert_eq!(first.metrics.len(), 12);
        assert!(first.candidate_receipts.is_empty());
        assert!(
            first
                .results
                .iter()
                .all(|result| result.evidence_kind == EvidenceKind::DeterministicFake)
        );
        assert!(first.replay_pack.deterministic);
        assert!(first.replay_pack.isolated_lanes);
        assert_ne!(
            first.promotion.status,
            super::super::model::DecisionStatus::Approved
        );
        assert_eq!(first.promotion.release_decision, "NOT_EVALUATED");
        validate_runtime_matrix_report(&first, SOURCE_COMMIT).expect("valid fake report");
        let mut missing_result = first.clone();
        missing_result.results.pop();
        assert!(validate_runtime_matrix_report(&missing_result, SOURCE_COMMIT).is_err());
        let mut tampered_replay = first;
        tampered_replay.replay_pack.pack_digest =
            "3333333333333333333333333333333333333333333333333333333333333333".into();
        assert!(validate_runtime_matrix_report(&tampered_replay, SOURCE_COMMIT).is_err());
    }

    #[test]
    fn native_missing_credentials_is_blocked_and_not_evaluated() {
        let report = RuntimeCandidateRunner::native_credentialed()
            .run_with_expected_commit(&plan(), SOURCE_COMMIT)
            .expect("blocked native report");
        assert_eq!(
            report.execution_mode,
            RuntimeExecutionMode::NativeCredentialed
        );
        assert_eq!(
            report.execution_status,
            super::super::model::RunnerDisposition::BlockedEnv
        );
        assert_eq!(report.quality_status, RuntimeQualityStatus::NotEvaluated);
        assert!(report.candidate_receipts.is_empty());
        assert_ne!(
            report.promotion.status,
            super::super::model::DecisionStatus::Approved
        );
        assert!(
            report
                .missing_required_evidence
                .iter()
                .any(|item| item.contains("native_credentials"))
        );
        validate_runtime_matrix_report(&report, SOURCE_COMMIT).expect("valid blocked report");
    }

    #[test]
    fn runtime_contract_has_exact_report_keys_and_rejects_injection() {
        let report = RuntimeCandidateRunner::fake_deterministic()
            .run_with_expected_commit(&plan(), SOURCE_COMMIT)
            .expect("fake report");
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/harness/runtime-runner.v1.json");
        let schema: Value =
            serde_json::from_slice(&fs::read(path).expect("schema bytes")).expect("schema json");
        let expected = schema["$defs"]["runtimeMatrixReport"]["properties"]
            .as_object()
            .expect("report properties")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let actual = serde_json::to_value(&report)
            .expect("report json")
            .as_object()
            .expect("report object")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
        let mut unknown = serde_json::to_value(report).expect("report json");
        unknown["unexpected"] = Value::String("injected".into());
        assert!(serde_json::from_value::<RuntimeMatrixReport>(unknown).is_err());
    }
}

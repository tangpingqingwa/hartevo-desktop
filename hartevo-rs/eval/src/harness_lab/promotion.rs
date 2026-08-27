use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::digest::{digest_json, is_lower_hex, sha256_hex};
use super::model::{
    CandidateIdentity, ComparisonRole, DecisionStatus, EvaluationLane, EvidenceKind, HarnessFamily,
    LAB_AUTHORITY, PromotionAction, PromotionKey, ProviderMode, RELEASE_DECISION, RUN_AUTHORITY,
    RunResult, RunnerDisposition, SignedPromotionRecord,
};
use super::verifier::{current_source_commit, verify_signed_record};

pub const PROMOTION_SCHEMA_VERSION: &str = "hartevo-harness-promotion-state/v1";
pub const PROMOTION_CONTRACT_PATH: &str = "contracts/harness/promotion-state.v1.json";
pub const PROMOTION_AUTHORITY: &str = LAB_AUTHORITY;
pub const PROMOTION_RELEASE_DECISION: &str = RELEASE_DECISION;

const IDENTITY_DIGEST_DOMAIN: &str = "hartevo-harness-candidate-identity/v1";
const RECEIPT_ID_DOMAIN: &str = "hartevo-harness-current-commit-receipt-id/v1";
const RECEIPT_DIGEST_DOMAIN: &str = "hartevo-harness-current-commit-receipt/v1";
const TRANSITION_DIGEST_DOMAIN: &str = "hartevo-harness-promotion-transition/v1";
const TRANSITION_CHAIN_DOMAIN: &str = "hartevo-harness-promotion-transition-chain/v1";
const EMPTY_TRANSITION_CHAIN_DOMAIN: &str = "hartevo-harness-promotion-empty-chain/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionState {
    CandidateFrozen,
    CanaryPending,
    CanaryAccepted,
    Promoted,
    RolledBack,
    Revoked,
    BlockedEnv,
    NotEvaluated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateIdentityFreeze {
    pub schema_version: String,
    pub authority: String,
    pub release_decision: String,
    pub candidate: CandidateIdentity,
    pub candidate_identity_digest: String,
    pub source_commit: String,
    pub plan_digest: String,
    pub matrix_digest: String,
    pub contract_digest: String,
    pub freeze_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentCommitReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub candidate_id: String,
    pub candidate_identity_digest: String,
    pub source_commit: String,
    pub plan_digest: String,
    pub matrix_digest: String,
    pub run_id: String,
    pub lane: EvaluationLane,
    pub role: ComparisonRole,
    pub harness: HarnessFamily,
    pub runner_disposition: RunnerDisposition,
    pub evidence_kind: EvidenceKind,
    pub provider_mode: ProviderMode,
    pub authority: String,
    pub evidence_digest: String,
    pub replay_digest: String,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromotionTransition {
    pub schema_version: String,
    pub transition_id: String,
    pub sequence: u64,
    pub action: PromotionAction,
    pub state_before: PromotionState,
    pub state_after: PromotionState,
    pub candidate_id: String,
    pub source_commit: String,
    pub receipt_id: Option<String>,
    pub signed_record_digest: String,
    pub transition_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromotionStateMachine {
    pub schema_version: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub freeze: CandidateIdentityFreeze,
    pub state: PromotionState,
    pub active_candidate_id: String,
    pub prior_candidate_id: Option<String>,
    pub receipts: Vec<CurrentCommitReceipt>,
    pub transitions: Vec<PromotionTransition>,
    pub revoked_candidate_ids: Vec<String>,
    pub transition_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromotionStateDecision {
    pub status: DecisionStatus,
    pub state: PromotionState,
    pub authority: String,
    pub release_decision: String,
    pub candidate_id: String,
    pub source_commit: String,
    pub action: PromotionAction,
    pub reasons: Vec<String>,
    pub transition_digest: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptDigestPayload<'a> {
    schema_version: &'a str,
    receipt_id: &'a str,
    candidate_id: &'a str,
    candidate_identity_digest: &'a str,
    source_commit: &'a str,
    plan_digest: &'a str,
    matrix_digest: &'a str,
    run_id: &'a str,
    lane: EvaluationLane,
    role: ComparisonRole,
    harness: HarnessFamily,
    runner_disposition: RunnerDisposition,
    evidence_kind: EvidenceKind,
    provider_mode: ProviderMode,
    authority: &'a str,
    evidence_digest: &'a str,
    replay_digest: &'a str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransitionDigestPayload<'a> {
    schema_version: &'a str,
    transition_id: &'a str,
    sequence: u64,
    action: PromotionAction,
    state_before: PromotionState,
    state_after: PromotionState,
    candidate_id: &'a str,
    source_commit: &'a str,
    receipt_id: &'a Option<String>,
    signed_record_digest: &'a str,
}

pub fn candidate_identity_digest(identity: &CandidateIdentity) -> Result<String> {
    Ok(digest_json(IDENTITY_DIGEST_DOMAIN, identity)?)
}

pub fn freeze_candidate_identity(
    candidate: CandidateIdentity,
    source_commit: &str,
    plan_digest: &str,
    matrix_digest: &str,
    contract_digest: &str,
) -> Result<CandidateIdentityFreeze> {
    validate_source_commit(source_commit)?;
    validate_digest(plan_digest, "plan digest")?;
    validate_digest(matrix_digest, "matrix digest")?;
    validate_digest(contract_digest, "promotion contract digest")?;
    validate_candidate_identity(&candidate, source_commit)?;
    ensure!(
        candidate.candidate_scope == "candidate_only",
        "only candidate_only identities may be frozen for promotion"
    );
    let identity_digest = candidate_identity_digest(&candidate)?;
    Ok(CandidateIdentityFreeze {
        schema_version: PROMOTION_SCHEMA_VERSION.into(),
        authority: PROMOTION_AUTHORITY.into(),
        release_decision: PROMOTION_RELEASE_DECISION.into(),
        candidate,
        candidate_identity_digest: identity_digest,
        source_commit: source_commit.into(),
        plan_digest: plan_digest.into(),
        matrix_digest: matrix_digest.into(),
        contract_digest: contract_digest.into(),
        freeze_sequence: 1,
    })
}

pub fn verify_frozen_candidate_identity(
    freeze: &CandidateIdentityFreeze,
    candidate: &CandidateIdentity,
) -> Result<()> {
    ensure!(
        freeze.schema_version == PROMOTION_SCHEMA_VERSION,
        "candidate identity freeze schema is unknown"
    );
    ensure!(
        freeze.authority == PROMOTION_AUTHORITY,
        "freeze authority is not candidate-only"
    );
    ensure!(
        freeze.release_decision == PROMOTION_RELEASE_DECISION,
        "candidate identity freeze cannot issue a release decision"
    );
    validate_source_commit(&freeze.source_commit)?;
    validate_digest(
        &freeze.candidate_identity_digest,
        "candidate identity digest",
    )?;
    validate_digest(&freeze.plan_digest, "plan digest")?;
    validate_digest(&freeze.matrix_digest, "matrix digest")?;
    validate_digest(&freeze.contract_digest, "promotion contract digest")?;
    ensure!(
        freeze.contract_digest == promotion_contract_digest()?,
        "candidate identity freeze is bound to a stale promotion contract"
    );
    ensure!(
        freeze.freeze_sequence == 1,
        "candidate identity freeze sequence is not immutable"
    );
    validate_candidate_identity(&freeze.candidate, &freeze.source_commit)?;
    ensure!(
        freeze.candidate_identity_digest == candidate_identity_digest(&freeze.candidate)?,
        "frozen candidate identity digest is not derived"
    );
    ensure!(
        freeze.candidate == *candidate,
        "candidate identity differs from the frozen identity"
    );
    Ok(())
}

pub fn build_current_commit_receipt(
    result: &RunResult,
    plan_digest: &str,
    matrix_digest: &str,
) -> Result<CurrentCommitReceipt> {
    validate_digest(plan_digest, "plan digest")?;
    validate_digest(matrix_digest, "matrix digest")?;
    validate_receipt_run_inputs(result)?;
    let identity_digest = candidate_identity_digest(&result.identity)?;
    let receipt_id = digest_json(
        RECEIPT_ID_DOMAIN,
        &json!({
            "candidateId": result.identity.candidate_id,
            "candidateIdentityDigest": identity_digest,
            "sourceCommit": result.source_commit,
            "planDigest": plan_digest,
            "matrixDigest": matrix_digest,
            "runId": result.run_id,
            "lane": result.lane,
        }),
    )?;
    let mut receipt = CurrentCommitReceipt {
        schema_version: PROMOTION_SCHEMA_VERSION.into(),
        receipt_id,
        candidate_id: result.identity.candidate_id.clone(),
        candidate_identity_digest: identity_digest,
        source_commit: result.source_commit.clone(),
        plan_digest: plan_digest.into(),
        matrix_digest: matrix_digest.into(),
        run_id: result.run_id.clone(),
        lane: result.lane,
        role: result.role,
        harness: result.harness,
        runner_disposition: result.runner_disposition,
        evidence_kind: result.evidence_kind,
        provider_mode: result.identity.provider_mode,
        authority: RUN_AUTHORITY.into(),
        evidence_digest: result.evidence_digest.clone(),
        replay_digest: result.replay_pack.replay_digest.clone(),
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = receipt_digest(&receipt)?;
    Ok(receipt)
}

fn validate_receipt_run_inputs(result: &RunResult) -> Result<()> {
    ensure!(
        result.role == ComparisonRole::Candidate,
        "only candidate results can become promotion receipts"
    );
    ensure!(
        result.harness == HarnessFamily::HartevoCandidate,
        "only Hartevo candidate results can become promotion receipts"
    );
    ensure!(
        result.runner_disposition == RunnerDisposition::Executed,
        "only executed results can become promotion receipts"
    );
    ensure!(
        result.evidence_kind == EvidenceKind::NativeRun,
        "only native evidence can become promotion receipts"
    );
    ensure!(
        result.identity.provider_mode == ProviderMode::NativeCredentialed,
        "simulator or fixture results cannot become promotion receipts"
    );
    ensure!(
        result.authority == RUN_AUTHORITY,
        "run result authority is not candidate-lab-only"
    );
    ensure!(
        result.identity.source_commit == result.source_commit,
        "run result identity is bound to a different commit"
    );
    ensure!(
        result.replay_pack.source_commit == result.source_commit,
        "run replay pack is bound to a different commit"
    );
    ensure!(
        result.replay_pack.case_set_digest == result.case_set_digest,
        "run replay pack case partition differs from the result"
    );
    ensure!(
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
                .candidate_observed_fresh_shadow,
        "run replay pack violates partition isolation"
    );
    ensure!(
        result.replay_pack.deterministic
            && !result.cases.is_empty()
            && result.metrics.sample_count == result.cases.len(),
        "run result is not a complete deterministic native observation"
    );
    validate_source_commit(&result.source_commit)?;
    validate_digest(&result.run_id, "run id")?;
    validate_digest(&result.evidence_digest, "evidence digest")?;
    validate_digest(&result.replay_pack.replay_digest, "replay digest")?;
    Ok(())
}

pub fn verify_current_commit_receipt(
    receipt: &CurrentCommitReceipt,
    freeze: &CandidateIdentityFreeze,
    expected_source_commit: &str,
    expected_plan_digest: &str,
    expected_matrix_digest: &str,
) -> Result<()> {
    validate_source_commit(expected_source_commit)?;
    validate_digest(expected_plan_digest, "plan digest")?;
    validate_digest(expected_matrix_digest, "matrix digest")?;
    ensure!(
        receipt.schema_version == PROMOTION_SCHEMA_VERSION,
        "current-commit receipt schema is unknown"
    );
    ensure!(
        receipt.authority == RUN_AUTHORITY,
        "receipt authority is not candidate-lab-only"
    );
    ensure!(
        receipt.source_commit == expected_source_commit,
        "receipt is bound to a stale commit"
    );
    ensure!(
        receipt.source_commit == freeze.source_commit,
        "receipt commit differs from frozen candidate"
    );
    ensure!(
        receipt.plan_digest == expected_plan_digest,
        "receipt plan digest is stale"
    );
    ensure!(
        receipt.matrix_digest == expected_matrix_digest,
        "receipt matrix digest is stale"
    );
    ensure!(
        receipt.candidate_id == freeze.candidate.candidate_id,
        "receipt candidate differs from freeze"
    );
    ensure!(
        receipt.candidate_identity_digest == freeze.candidate_identity_digest,
        "receipt candidate identity digest differs from freeze"
    );
    ensure!(
        receipt.role == ComparisonRole::Candidate,
        "receipt is not a candidate partition result"
    );
    ensure!(
        receipt.harness == HarnessFamily::HartevoCandidate,
        "receipt harness is not the candidate harness"
    );
    ensure!(
        receipt.runner_disposition == RunnerDisposition::Executed,
        "non-executed receipt cannot satisfy promotion"
    );
    ensure!(
        receipt.evidence_kind == EvidenceKind::NativeRun,
        "receipt is not native evidence"
    );
    ensure!(
        receipt.provider_mode == ProviderMode::NativeCredentialed,
        "receipt provider is not native credentialed evidence"
    );
    validate_source_commit(&receipt.source_commit)?;
    validate_digest(&receipt.receipt_id, "receipt id")?;
    validate_digest(
        &receipt.candidate_identity_digest,
        "candidate identity digest",
    )?;
    validate_digest(&receipt.run_id, "run id")?;
    validate_digest(&receipt.evidence_digest, "evidence digest")?;
    validate_digest(&receipt.replay_digest, "replay digest")?;
    validate_digest(&receipt.receipt_digest, "receipt digest")?;
    let expected_receipt_id = receipt_id(receipt)?;
    ensure!(
        receipt.receipt_id == expected_receipt_id,
        "receipt id is not derived"
    );
    ensure!(
        receipt.receipt_digest == receipt_digest(receipt)?,
        "receipt digest is not derived"
    );
    Ok(())
}

pub fn verify_live_current_commit_receipt(
    receipt: &CurrentCommitReceipt,
    freeze: &CandidateIdentityFreeze,
) -> Result<()> {
    let source_commit = current_source_commit()?;
    verify_current_commit_receipt(
        receipt,
        freeze,
        &source_commit,
        &freeze.plan_digest,
        &freeze.matrix_digest,
    )
}

pub fn verify_current_commit_receipt_against_run(
    receipt: &CurrentCommitReceipt,
    result: &RunResult,
    freeze: &CandidateIdentityFreeze,
    expected_source_commit: &str,
) -> Result<()> {
    let expected =
        build_current_commit_receipt(result, &freeze.plan_digest, &freeze.matrix_digest)?;
    ensure!(
        receipt == &expected,
        "current-commit receipt does not match its verified run result"
    );
    verify_current_commit_receipt(
        receipt,
        freeze,
        expected_source_commit,
        &freeze.plan_digest,
        &freeze.matrix_digest,
    )
}

pub fn verify_promotion_state_machine(
    machine: &PromotionStateMachine,
    expected_source_commit: &str,
) -> Result<()> {
    validate_state_machine_header(machine, expected_source_commit)?;
    validate_state_machine_receipts(machine, expected_source_commit)?;
    let expected_state = validate_state_machine_transitions(machine, expected_source_commit)?;
    validate_transition_chain_digest(machine)?;
    validate_revocations(machine)?;
    validate_terminal_state(machine, expected_state)
}

pub fn verify_live_promotion_state_machine(machine: &PromotionStateMachine) -> Result<()> {
    let source_commit = current_source_commit()?;
    verify_promotion_state_machine(machine, &source_commit)
}

fn validate_state_machine_header(
    machine: &PromotionStateMachine,
    expected_source_commit: &str,
) -> Result<()> {
    validate_source_commit(expected_source_commit)?;
    ensure!(
        machine.schema_version == PROMOTION_SCHEMA_VERSION,
        "promotion state schema is unknown"
    );
    ensure!(
        machine.authority == PROMOTION_AUTHORITY,
        "promotion state authority is not candidate-only"
    );
    ensure!(
        machine.release_decision == PROMOTION_RELEASE_DECISION,
        "promotion state cannot issue a release decision"
    );
    ensure!(
        machine.source_commit == expected_source_commit,
        "promotion state is bound to a stale source commit"
    );
    verify_frozen_candidate_identity(&machine.freeze, &machine.freeze.candidate)?;
    ensure!(
        machine.freeze.source_commit == machine.source_commit,
        "promotion state and candidate freeze commits differ"
    );
    ensure!(
        machine.active_candidate_id == machine.freeze.candidate.candidate_id,
        "promotion state active candidate differs from the frozen identity"
    );
    Ok(())
}

fn validate_state_machine_receipts(
    machine: &PromotionStateMachine,
    expected_source_commit: &str,
) -> Result<()> {
    let mut receipt_ids = BTreeSet::new();
    let mut run_ids = BTreeSet::new();
    let mut lanes = BTreeSet::new();
    for receipt in &machine.receipts {
        verify_current_commit_receipt(
            receipt,
            &machine.freeze,
            expected_source_commit,
            &machine.freeze.plan_digest,
            &machine.freeze.matrix_digest,
        )?;
        ensure!(
            receipt_ids.insert(receipt.receipt_id.as_str()),
            "duplicate receipt id"
        );
        ensure!(run_ids.insert(receipt.run_id.as_str()), "duplicate run id");
        ensure!(lanes.insert(receipt.lane), "duplicate receipt partition");
    }
    Ok(())
}

fn validate_state_machine_transitions(
    machine: &PromotionStateMachine,
    expected_source_commit: &str,
) -> Result<PromotionState> {
    let mut expected_state = if machine.receipts.is_empty() {
        PromotionState::CandidateFrozen
    } else {
        PromotionState::CanaryPending
    };
    let mut transition_ids = BTreeSet::new();
    for (index, transition) in machine.transitions.iter().enumerate() {
        ensure!(
            transition_ids.insert(transition.transition_id.as_str()),
            "duplicate promotion transition"
        );
        expected_state = validate_transition(
            machine,
            transition,
            index,
            expected_state,
            expected_source_commit,
        )?;
    }
    Ok(expected_state)
}

fn validate_transition(
    machine: &PromotionStateMachine,
    transition: &PromotionTransition,
    index: usize,
    expected_state: PromotionState,
    expected_source_commit: &str,
) -> Result<PromotionState> {
    ensure!(
        transition.schema_version == PROMOTION_SCHEMA_VERSION,
        "promotion transition schema is unknown"
    );
    ensure!(
        transition.sequence == u64::try_from(index).unwrap_or(u64::MAX) + 1,
        "promotion transition sequence is not contiguous"
    );
    ensure!(
        transition.state_before == expected_state,
        "promotion transition state chain is broken"
    );
    ensure!(
        transition.candidate_id == machine.active_candidate_id,
        "promotion transition candidate differs from active candidate"
    );
    ensure!(
        transition.source_commit == expected_source_commit,
        "promotion transition is bound to a stale source commit"
    );
    validate_digest(&transition.signed_record_digest, "signed record digest")?;
    validate_digest(&transition.transition_digest, "transition digest")?;
    ensure!(
        transition.transition_digest == transition_digest(transition)?,
        "promotion transition digest is not derived"
    );
    match transition.action {
        PromotionAction::Canary => {
            ensure!(
                expected_state == PromotionState::CandidateFrozen
                    || expected_state == PromotionState::CanaryPending,
                "canary transition state is invalid"
            );
            let receipt_id = transition
                .receipt_id
                .as_deref()
                .context("canary transition has no receipt reference")?;
            ensure!(
                machine
                    .receipts
                    .iter()
                    .any(|receipt| receipt.receipt_id == receipt_id),
                "canary transition references an unknown receipt"
            );
            ensure!(
                transition.state_after == PromotionState::CanaryAccepted,
                "canary state is invalid"
            );
        }
        PromotionAction::Promote => {
            ensure!(
                expected_state == PromotionState::CanaryAccepted,
                "promotion state is invalid"
            );
            ensure!(
                transition.state_after == PromotionState::Promoted,
                "promotion state is invalid"
            );
        }
        PromotionAction::Rollback => {
            ensure!(
                expected_state == PromotionState::Promoted,
                "rollback state is invalid"
            );
            ensure!(
                transition.state_after == PromotionState::RolledBack,
                "rollback state is invalid"
            );
        }
        PromotionAction::Revoke => {
            ensure!(
                expected_state != PromotionState::Revoked,
                "duplicate revocation transition"
            );
            ensure!(
                transition.state_after == PromotionState::Revoked,
                "revocation state is invalid"
            );
        }
    }
    Ok(transition.state_after)
}

fn validate_transition_chain_digest(machine: &PromotionStateMachine) -> Result<()> {
    let expected_transition_digest = if machine.transitions.is_empty() {
        digest_json(EMPTY_TRANSITION_CHAIN_DOMAIN, &Vec::<()>::new())?
    } else {
        digest_json(TRANSITION_CHAIN_DOMAIN, &machine.transitions)?
    };
    ensure!(
        machine.transition_digest == expected_transition_digest,
        "promotion transition chain digest is not derived"
    );
    Ok(())
}

fn validate_revocations(machine: &PromotionStateMachine) -> Result<()> {
    ensure!(
        machine
            .revoked_candidate_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == machine.revoked_candidate_ids.len(),
        "promotion state contains duplicate revoked candidates"
    );
    ensure!(
        machine
            .revoked_candidate_ids
            .iter()
            .all(|id| id == &machine.active_candidate_id),
        "promotion state contains a cross-candidate revocation"
    );
    if !machine.revoked_candidate_ids.is_empty() {
        ensure!(
            machine
                .transitions
                .iter()
                .any(|transition| transition.action == PromotionAction::Revoke),
            "revocation list has no signed revocation transition"
        );
    }
    Ok(())
}

fn validate_terminal_state(
    machine: &PromotionStateMachine,
    expected_state: PromotionState,
) -> Result<()> {
    if machine.prior_candidate_id.is_some() {
        let prior = machine.prior_candidate_id.as_deref().unwrap_or_default();
        ensure!(!prior.trim().is_empty(), "rollback pointer is empty");
        ensure!(
            prior != machine.active_candidate_id,
            "rollback pointer targets active candidate"
        );
        ensure!(
            machine
                .transitions
                .iter()
                .any(|transition| transition.action == PromotionAction::Rollback),
            "rollback pointer has no signed rollback transition"
        );
    }
    let receipt_pending = machine.state == PromotionState::CanaryPending
        && expected_state == PromotionState::CandidateFrozen
        && !machine.receipts.is_empty();
    if !receipt_pending
        && machine.state != PromotionState::BlockedEnv
        && machine.state != PromotionState::NotEvaluated
    {
        ensure!(
            machine.state == expected_state,
            "promotion state does not match transition chain"
        );
    }
    Ok(())
}

impl PromotionStateMachine {
    pub fn new(freeze: CandidateIdentityFreeze) -> Result<Self> {
        verify_frozen_candidate_identity(&freeze, &freeze.candidate)?;
        let transition_digest = digest_json(EMPTY_TRANSITION_CHAIN_DOMAIN, &Vec::<()>::new())?;
        Ok(Self {
            schema_version: PROMOTION_SCHEMA_VERSION.into(),
            authority: PROMOTION_AUTHORITY.into(),
            release_decision: PROMOTION_RELEASE_DECISION.into(),
            source_commit: freeze.source_commit.clone(),
            active_candidate_id: freeze.candidate.candidate_id.clone(),
            prior_candidate_id: None,
            freeze,
            state: PromotionState::CandidateFrozen,
            receipts: Vec::new(),
            transitions: Vec::new(),
            revoked_candidate_ids: Vec::new(),
            transition_digest,
        })
    }

    pub fn new_at_current_commit(freeze: CandidateIdentityFreeze) -> Result<Self> {
        let source_commit = current_source_commit()?;
        ensure!(
            freeze.source_commit == source_commit,
            "candidate identity freeze is not bound to the current commit"
        );
        Self::new(freeze)
    }

    pub fn observe_receipt(
        &mut self,
        receipt: CurrentCommitReceipt,
        expected_source_commit: &str,
    ) -> Result<()> {
        ensure!(
            self.state != PromotionState::Revoked,
            "revoked candidate cannot accept receipts"
        );
        verify_current_commit_receipt(
            &receipt,
            &self.freeze,
            expected_source_commit,
            &self.freeze.plan_digest,
            &self.freeze.matrix_digest,
        )?;
        ensure!(
            !self
                .receipts
                .iter()
                .any(|item| item.receipt_id == receipt.receipt_id),
            "duplicate current-commit receipt"
        );
        ensure!(
            !self
                .receipts
                .iter()
                .any(|item| item.run_id == receipt.run_id),
            "duplicate current-commit run id"
        );
        ensure!(
            !self.receipts.iter().any(|item| item.lane == receipt.lane),
            "duplicate current-commit partition receipt"
        );
        self.receipts.push(receipt);
        if matches!(
            self.state,
            PromotionState::CandidateFrozen | PromotionState::BlockedEnv
        ) {
            self.state = PromotionState::CanaryPending;
        } else if self.state == PromotionState::NotEvaluated
            && self.transitions.iter().any(|item| {
                item.action == PromotionAction::Canary
                    && item.state_after == PromotionState::CanaryAccepted
            })
        {
            self.state = PromotionState::CanaryAccepted;
        }
        Ok(())
    }

    pub fn apply_signed_transition(
        &mut self,
        record: &SignedPromotionRecord,
        trusted_keys: &[PromotionKey],
        expected_source_commit: &str,
    ) -> Result<PromotionStateDecision> {
        validate_source_commit(expected_source_commit)?;
        ensure!(
            expected_source_commit == self.source_commit,
            "promotion transition is bound to a stale source commit"
        );
        ensure!(
            record.candidate_id == self.active_candidate_id,
            "promotion transition candidate differs from active candidate"
        );
        ensure!(
            !self
                .revoked_candidate_ids
                .iter()
                .any(|id| id == &record.candidate_id)
                || record.action == PromotionAction::Revoke,
            "revoked candidate cannot transition"
        );
        ensure!(
            !self
                .transitions
                .iter()
                .any(|item| item.transition_id == record.record_id),
            "duplicate promotion transition"
        );
        if trusted_keys.is_empty() {
            self.state = PromotionState::BlockedEnv;
            return Ok(self.decision(
                DecisionStatus::BlockedEnv,
                record.action,
                vec!["trusted promotion key registry is empty".into()],
            ));
        }
        verify_signed_record(record, trusted_keys, expected_source_commit)?;
        let decision = match record.action {
            PromotionAction::Canary => self.apply_canary(record),
            PromotionAction::Promote => self.apply_promote(record),
            PromotionAction::Rollback => self.apply_rollback(record),
            PromotionAction::Revoke => self.apply_revoke(record),
        }?;
        Ok(decision)
    }

    fn apply_canary(&mut self, record: &SignedPromotionRecord) -> Result<PromotionStateDecision> {
        ensure!(
            matches!(
                self.state,
                PromotionState::CandidateFrozen
                    | PromotionState::CanaryPending
                    | PromotionState::BlockedEnv
                    | PromotionState::NotEvaluated
            ),
            "canary transition is not valid from the current state"
        );
        let canary_receipts = self
            .receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.lane,
                    EvaluationLane::Public | EvaluationLane::Vertical
                )
            })
            .collect::<Vec<_>>();
        if canary_receipts.len() != 1 {
            self.state = PromotionState::NotEvaluated;
            return Ok(self.decision(
                DecisionStatus::NotImplemented,
                record.action,
                vec!["canary requires exactly one public or vertical receipt".into()],
            ));
        }
        let receipt = canary_receipts[0];
        let state_before = self.state;
        self.state = PromotionState::CanaryAccepted;
        self.append_transition(record, state_before, receipt.receipt_id.clone())?;
        Ok(self.decision(DecisionStatus::Approved, record.action, Vec::new()))
    }

    fn apply_promote(&mut self, record: &SignedPromotionRecord) -> Result<PromotionStateDecision> {
        ensure!(
            self.state == PromotionState::CanaryAccepted,
            "promotion requires an accepted signed canary"
        );
        let required = [
            EvaluationLane::Public,
            EvaluationLane::Vertical,
            EvaluationLane::PrivateHoldout,
            EvaluationLane::FreshShadow,
        ];
        let missing = required
            .into_iter()
            .filter(|lane| !self.receipts.iter().any(|receipt| receipt.lane == *lane))
            .map(|lane| format!("missing current-commit {lane:?} receipt"))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            self.state = PromotionState::NotEvaluated;
            return Ok(self.decision(DecisionStatus::NotImplemented, record.action, missing));
        }
        let state_before = self.state;
        self.state = PromotionState::Promoted;
        self.append_transition(record, state_before, String::new())?;
        Ok(self.decision(DecisionStatus::Approved, record.action, Vec::new()))
    }

    fn apply_rollback(&mut self, record: &SignedPromotionRecord) -> Result<PromotionStateDecision> {
        ensure!(
            self.state == PromotionState::Promoted,
            "rollback requires a promoted candidate"
        );
        let prior_candidate_id = record
            .prior_candidate_id
            .clone()
            .context("rollback record does not identify the prior candidate")?;
        ensure!(
            prior_candidate_id != self.active_candidate_id,
            "rollback prior candidate equals active candidate"
        );
        let state_before = self.state;
        self.prior_candidate_id = Some(prior_candidate_id);
        self.state = PromotionState::RolledBack;
        self.append_transition(record, state_before, String::new())?;
        Ok(self.decision(DecisionStatus::Approved, record.action, Vec::new()))
    }

    fn apply_revoke(&mut self, record: &SignedPromotionRecord) -> Result<PromotionStateDecision> {
        ensure!(
            self.state != PromotionState::Revoked,
            "candidate is already revoked"
        );
        let state_before = self.state;
        self.revoked_candidate_ids.push(record.candidate_id.clone());
        self.state = PromotionState::Revoked;
        self.append_transition(record, state_before, String::new())?;
        Ok(self.decision(DecisionStatus::Approved, record.action, Vec::new()))
    }

    fn append_transition(
        &mut self,
        record: &SignedPromotionRecord,
        state_before: PromotionState,
        receipt_id: String,
    ) -> Result<()> {
        let signed_record_digest = digest_json(TRANSITION_DIGEST_DOMAIN, record)?;
        let sequence = u64::try_from(self.transitions.len())
            .context("promotion transition sequence overflow")?
            .checked_add(1)
            .context("promotion transition sequence overflow")?;
        let mut transition = PromotionTransition {
            schema_version: PROMOTION_SCHEMA_VERSION.into(),
            transition_id: record.record_id.clone(),
            sequence,
            action: record.action,
            state_before,
            state_after: self.state,
            candidate_id: record.candidate_id.clone(),
            source_commit: record.source_commit.clone(),
            receipt_id: (!receipt_id.is_empty()).then_some(receipt_id),
            signed_record_digest,
            transition_digest: String::new(),
        };
        transition.transition_digest = transition_digest(&transition)?;
        self.transitions.push(transition);
        self.transition_digest = digest_json(TRANSITION_CHAIN_DOMAIN, &self.transitions)?;
        Ok(())
    }

    fn decision(
        &self,
        status: DecisionStatus,
        action: PromotionAction,
        reasons: Vec<String>,
    ) -> PromotionStateDecision {
        PromotionStateDecision {
            status,
            state: self.state,
            authority: PROMOTION_AUTHORITY.into(),
            release_decision: PROMOTION_RELEASE_DECISION.into(),
            candidate_id: self.active_candidate_id.clone(),
            source_commit: self.source_commit.clone(),
            action,
            reasons,
            transition_digest: self.transition_digest.clone(),
        }
    }
}

fn receipt_id(receipt: &CurrentCommitReceipt) -> Result<String> {
    Ok(digest_json(
        RECEIPT_ID_DOMAIN,
        &json!({
            "candidateId": receipt.candidate_id,
            "candidateIdentityDigest": receipt.candidate_identity_digest,
            "sourceCommit": receipt.source_commit,
            "planDigest": receipt.plan_digest,
            "matrixDigest": receipt.matrix_digest,
            "runId": receipt.run_id,
            "lane": receipt.lane,
        }),
    )?)
}

fn receipt_digest(receipt: &CurrentCommitReceipt) -> Result<String> {
    let payload = ReceiptDigestPayload {
        schema_version: &receipt.schema_version,
        receipt_id: &receipt.receipt_id,
        candidate_id: &receipt.candidate_id,
        candidate_identity_digest: &receipt.candidate_identity_digest,
        source_commit: &receipt.source_commit,
        plan_digest: &receipt.plan_digest,
        matrix_digest: &receipt.matrix_digest,
        run_id: &receipt.run_id,
        lane: receipt.lane,
        role: receipt.role,
        harness: receipt.harness,
        runner_disposition: receipt.runner_disposition,
        evidence_kind: receipt.evidence_kind,
        provider_mode: receipt.provider_mode,
        authority: &receipt.authority,
        evidence_digest: &receipt.evidence_digest,
        replay_digest: &receipt.replay_digest,
    };
    Ok(digest_json(RECEIPT_DIGEST_DOMAIN, &payload)?)
}

fn transition_digest(transition: &PromotionTransition) -> Result<String> {
    let payload = TransitionDigestPayload {
        schema_version: &transition.schema_version,
        transition_id: &transition.transition_id,
        sequence: transition.sequence,
        action: transition.action,
        state_before: transition.state_before,
        state_after: transition.state_after,
        candidate_id: &transition.candidate_id,
        source_commit: &transition.source_commit,
        receipt_id: &transition.receipt_id,
        signed_record_digest: &transition.signed_record_digest,
    };
    Ok(digest_json(TRANSITION_DIGEST_DOMAIN, &payload)?)
}

fn validate_candidate_identity(identity: &CandidateIdentity, source_commit: &str) -> Result<()> {
    validate_source_commit(source_commit)?;
    for (label, value) in [
        ("candidate id", &identity.candidate_id),
        ("provider id", &identity.provider_id),
        ("model", &identity.model),
        ("model revision", &identity.model_revision),
        ("harness", &identity.harness),
        ("harness revision", &identity.harness_revision),
        ("effort", &identity.effort),
        ("service tier", &identity.service_tier),
        ("retry policy", &identity.retry_policy),
        ("seed policy", &identity.seed_policy),
        ("runtime revision", &identity.runtime_revision),
        ("schema version", &identity.schema_version),
    ] {
        ensure!(!value.trim().is_empty(), "{label} is empty");
    }
    ensure!(
        identity.source_commit == source_commit,
        "candidate identity is bound to a stale commit"
    );
    ensure!(
        identity.production_defaults_unchanged,
        "candidate changes production defaults"
    );
    validate_digest(&identity.tool_catalog_digest, "tool catalog digest")?;
    validate_digest(&identity.environment_digest, "environment digest")?;
    validate_digest(&identity.config_digest, "candidate config digest")?;
    ensure!(identity.budget_micros > 0, "candidate budget is zero");
    ensure!(
        identity.run_repetitions > 0,
        "candidate repetitions are zero"
    );
    Ok(())
}

fn validate_source_commit(value: &str) -> Result<()> {
    ensure!(
        is_lower_hex(value, 20),
        "source commit is not a 40-character lowercase Git SHA"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        is_lower_hex(value, 32),
        "{label} is not a canonical SHA-256 digest"
    );
    Ok(())
}

pub fn promotion_contract_digest() -> Result<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join(PROMOTION_CONTRACT_PATH);
    let bytes = fs::read(&path)
        .with_context(|| format!("read promotion state contract {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::Value;

    use super::super::digest::digest_json;
    use super::super::model::{
        CaseObservation, GoalFlags, HarnessFamily, LabPlan, OutcomeFlags, PlanInputs, ProcessFlags,
        PromotionAction, PromotionKey, ProviderMode, RunnerDisposition, SAFETY_INVARIANT_IDS,
        SignedPromotionRecord,
    };
    use super::super::verifier::{
        build_frozen_plan, build_run_result, contract_digest, promotion_payload_digest,
        promotion_signing_bytes,
    };
    use super::{
        CandidateIdentityFreeze, DecisionStatus, EvaluationLane, EvidenceKind, PromotionState,
        PromotionStateMachine, build_current_commit_receipt, candidate_identity_digest,
        freeze_candidate_identity, promotion_contract_digest, verify_current_commit_receipt,
        verify_frozen_candidate_identity, verify_promotion_state_machine,
    };

    const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const DATASET_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const AUX_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn candidate_identity() -> super::super::model::CandidateIdentity {
        super::super::model::CandidateIdentity {
            candidate_id: "candidate-v1".into(),
            provider_id: "provider-route-v1".into(),
            provider_mode: ProviderMode::NativeCredentialed,
            model: "model-under-test".into(),
            model_revision: "model-revision-v1".into(),
            harness: "hartevo-candidate".into(),
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
            candidate_scope: "candidate_only".into(),
            production_defaults_unchanged: true,
        }
    }

    fn plan() -> LabPlan {
        let baseline = candidate_identity();
        let mut upstream = baseline.clone();
        upstream.candidate_id = "baseline-upstream".into();
        upstream.candidate_scope = "baseline".into();
        let mut native = baseline.clone();
        native.candidate_id = "baseline-native".into();
        native.candidate_scope = "baseline".into();
        build_frozen_plan(PlanInputs {
            source_commit: SOURCE_COMMIT.into(),
            contract_digest: contract_digest().expect("candidate contract digest"),
            benchmark_revision: "frozen-benchmark-v1".into(),
            dataset_revision: "dataset-v1".into(),
            dataset_digest: DATASET_DIGEST.into(),
            baseline_native: native,
            baseline_upstream: upstream,
            candidate: baseline,
        })
        .expect("frozen plan")
    }

    fn safe_case(case_id: &str) -> CaseObservation {
        let safety_invariants = SAFETY_INVARIANT_IDS
            .into_iter()
            .map(|id| (id.to_owned(), true))
            .collect::<BTreeMap<_, _>>();
        CaseObservation {
            case_id: case_id.into(),
            goal: GoalFlags {
                goal_complete: true,
                constraints_preserved: true,
            },
            outcome: OutcomeFlags {
                verified_outcome: true,
                loop_closed: true,
            },
            safety_invariants,
            latency_ms: 100,
            cost_micros: 100,
            process: ProcessFlags {
                recovered: true,
                tool_correct: true,
                human_rework: false,
            },
        }
    }

    fn freeze_and_plan() -> (CandidateIdentityFreeze, LabPlan) {
        let plan = plan();
        let plan_digest = digest_json("hartevo-harness-lab-plan/v1", &plan).expect("plan digest");
        let freeze = freeze_candidate_identity(
            candidate_identity(),
            SOURCE_COMMIT,
            &plan_digest,
            &plan.matrix_digest,
            &promotion_contract_digest().expect("promotion contract digest"),
        )
        .expect("candidate freeze");
        (freeze, plan)
    }

    fn candidate_receipt(plan: &LabPlan, lane: EvaluationLane) -> super::CurrentCommitReceipt {
        let entry = plan
            .entries
            .iter()
            .find(|entry| entry.lane == lane && entry.harness == HarnessFamily::HartevoCandidate)
            .expect("candidate entry");
        let cases = (0..entry.configured_case_count)
            .map(|index| safe_case(&format!("{}-{index:02}", entry.entry_id)))
            .collect();
        let result = build_run_result(
            entry,
            RunnerDisposition::Executed,
            EvidenceKind::NativeRun,
            cases,
        )
        .expect("run result");
        let plan_digest = digest_json("hartevo-harness-lab-plan/v1", plan).expect("plan digest");
        build_current_commit_receipt(&result, &plan_digest, &plan.matrix_digest)
            .expect("current commit receipt")
    }

    fn signed_record(
        action: PromotionAction,
        record_id: &str,
    ) -> (SignedPromotionRecord, PromotionKey, Ed25519KeyPair) {
        let signer = Ed25519KeyPair::from_seed_unchecked(&[41; 32]).expect("test signer");
        let key = PromotionKey {
            key_id: "lab-key-01".into(),
            purpose: "harness_promotion".into(),
            public_key_hex: hex::encode(signer.public_key().as_ref()),
            revoked: false,
        };
        let mut record = SignedPromotionRecord {
            record_id: record_id.into(),
            action,
            candidate_id: "candidate-v1".into(),
            source_commit: SOURCE_COMMIT.into(),
            prior_candidate_id: None,
            key_id: key.key_id.clone(),
            payload_digest: String::new(),
            signature_hex: String::new(),
        };
        record.payload_digest = promotion_payload_digest(&record).expect("payload digest");
        record.signature_hex = hex::encode(
            signer
                .sign(&promotion_signing_bytes(&record).expect("signing bytes"))
                .as_ref(),
        );
        (record, key, signer)
    }

    #[test]
    fn freeze_digest_rejects_identity_mutation() {
        let (freeze, _) = freeze_and_plan();
        verify_frozen_candidate_identity(&freeze, &freeze.candidate).expect("frozen identity");
        let mut mutated = freeze.candidate.clone();
        mutated.config_digest =
            "3333333333333333333333333333333333333333333333333333333333333333".into();
        assert!(verify_frozen_candidate_identity(&freeze, &mutated).is_err());
        assert_eq!(
            freeze.candidate_identity_digest,
            candidate_identity_digest(&freeze.candidate).unwrap()
        );
    }

    #[test]
    fn stale_simulator_and_tampered_receipts_fail_closed() {
        let (freeze, plan) = freeze_and_plan();
        let receipt = candidate_receipt(&plan, EvaluationLane::Public);
        assert!(
            verify_current_commit_receipt(
                &receipt,
                &freeze,
                "fedcba9876543210fedcba9876543210fedcba98",
                &freeze.plan_digest,
                &freeze.matrix_digest,
            )
            .is_err()
        );
        let mut tampered = receipt.clone();
        tampered.provider_mode = ProviderMode::ControlledSimulator;
        assert!(
            verify_current_commit_receipt(
                &tampered,
                &freeze,
                SOURCE_COMMIT,
                &freeze.plan_digest,
                &freeze.matrix_digest,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_trust_registry_is_blocked_env_and_never_approved() {
        let (freeze, _) = freeze_and_plan();
        let mut machine = PromotionStateMachine::new(freeze).expect("state machine");
        let (record, _, _) = signed_record(PromotionAction::Canary, "canary-01");
        let decision = machine
            .apply_signed_transition(&record, &[], SOURCE_COMMIT)
            .expect("blocked decision");
        assert_eq!(decision.status, DecisionStatus::BlockedEnv);
        assert_eq!(decision.state, PromotionState::BlockedEnv);
        assert_eq!(decision.release_decision, "NOT_EVALUATED");
    }

    #[test]
    fn canary_then_exact_four_partitions_is_required_for_promotion() {
        let (freeze, plan) = freeze_and_plan();
        let mut machine = PromotionStateMachine::new(freeze).expect("state machine");
        machine
            .observe_receipt(
                candidate_receipt(&plan, EvaluationLane::Public),
                SOURCE_COMMIT,
            )
            .expect("public receipt");
        let (canary, key, _) = signed_record(PromotionAction::Canary, "canary-01");
        let decision = machine
            .apply_signed_transition(&canary, std::slice::from_ref(&key), SOURCE_COMMIT)
            .expect("canary decision");
        assert_eq!(decision.status, DecisionStatus::Approved);
        assert_eq!(decision.state, PromotionState::CanaryAccepted);
        let (promote, _, _) = signed_record(PromotionAction::Promote, "promote-01");
        let incomplete = machine
            .apply_signed_transition(&promote, std::slice::from_ref(&key), SOURCE_COMMIT)
            .expect("incomplete decision");
        assert_eq!(incomplete.status, DecisionStatus::NotImplemented);
        assert_eq!(incomplete.state, PromotionState::NotEvaluated);
        for lane in [
            EvaluationLane::Vertical,
            EvaluationLane::PrivateHoldout,
            EvaluationLane::FreshShadow,
        ] {
            machine
                .observe_receipt(candidate_receipt(&plan, lane), SOURCE_COMMIT)
                .expect("partition receipt");
        }
        let complete = machine
            .apply_signed_transition(&promote, std::slice::from_ref(&key), SOURCE_COMMIT)
            .expect("promotion decision");
        assert_eq!(complete.status, DecisionStatus::Approved);
        assert_eq!(complete.state, PromotionState::Promoted);
        assert_eq!(machine.receipts.len(), 4);
        assert_eq!(machine.transitions.len(), 2);
        verify_promotion_state_machine(&machine, SOURCE_COMMIT).expect("valid state chain");
        let mut tampered = machine.clone();
        tampered.transition_digest =
            "3333333333333333333333333333333333333333333333333333333333333333".into();
        assert!(verify_promotion_state_machine(&tampered, SOURCE_COMMIT).is_err());
    }

    #[test]
    fn rollback_requires_current_signed_pointer_and_revocation_is_terminal() {
        let (freeze, plan) = freeze_and_plan();
        let mut machine = PromotionStateMachine::new(freeze).expect("state machine");
        machine
            .observe_receipt(
                candidate_receipt(&plan, EvaluationLane::Public),
                SOURCE_COMMIT,
            )
            .expect("public receipt");
        let (canary, key, _) = signed_record(PromotionAction::Canary, "canary-01");
        machine
            .apply_signed_transition(&canary, std::slice::from_ref(&key), SOURCE_COMMIT)
            .expect("canary");
        for lane in [
            EvaluationLane::Vertical,
            EvaluationLane::PrivateHoldout,
            EvaluationLane::FreshShadow,
        ] {
            machine
                .observe_receipt(candidate_receipt(&plan, lane), SOURCE_COMMIT)
                .expect("partition receipt");
        }
        let (promote, _, _) = signed_record(PromotionAction::Promote, "promote-01");
        machine
            .apply_signed_transition(&promote, std::slice::from_ref(&key), SOURCE_COMMIT)
            .expect("promotion");

        let (mut rollback, _, signer) = signed_record(PromotionAction::Rollback, "rollback-01");
        rollback.prior_candidate_id = Some("previous-candidate".into());
        rollback.payload_digest = promotion_payload_digest(&rollback).expect("rollback payload");
        rollback.signature_hex = hex::encode(
            signer
                .sign(&promotion_signing_bytes(&rollback).expect("rollback signing bytes"))
                .as_ref(),
        );
        let decision = machine
            .apply_signed_transition(&rollback, std::slice::from_ref(&key), SOURCE_COMMIT)
            .expect("rollback");
        assert_eq!(decision.status, DecisionStatus::Approved);
        assert_eq!(decision.state, PromotionState::RolledBack);
        assert_eq!(
            machine.prior_candidate_id.as_deref(),
            Some("previous-candidate")
        );

        let (mut revoke, _, signer) = signed_record(PromotionAction::Revoke, "revoke-01");
        revoke.payload_digest = promotion_payload_digest(&revoke).expect("revoke payload");
        revoke.signature_hex = hex::encode(
            signer
                .sign(&promotion_signing_bytes(&revoke).expect("revoke signing bytes"))
                .as_ref(),
        );
        let revoke_decision = machine
            .apply_signed_transition(&revoke, std::slice::from_ref(&key), SOURCE_COMMIT)
            .expect("revocation");
        assert_eq!(revoke_decision.status, DecisionStatus::Approved);
        assert_eq!(revoke_decision.state, PromotionState::Revoked);
        assert!(
            machine
                .apply_signed_transition(&revoke, std::slice::from_ref(&key), SOURCE_COMMIT)
                .is_err()
        );
    }

    #[test]
    fn duplicate_partition_and_revoked_candidate_are_rejected() {
        let (freeze, plan) = freeze_and_plan();
        let mut machine = PromotionStateMachine::new(freeze).expect("state machine");
        let receipt = candidate_receipt(&plan, EvaluationLane::Public);
        machine
            .observe_receipt(receipt.clone(), SOURCE_COMMIT)
            .expect("receipt");
        assert!(machine.observe_receipt(receipt, SOURCE_COMMIT).is_err());
        let (revoke, key, _) = signed_record(PromotionAction::Revoke, "revoke-01");
        machine
            .apply_signed_transition(&revoke, std::slice::from_ref(&key), SOURCE_COMMIT)
            .expect("revocation");
        assert_eq!(machine.state, PromotionState::Revoked);
        assert!(
            machine
                .observe_receipt(
                    candidate_receipt(&plan, EvaluationLane::Vertical),
                    SOURCE_COMMIT
                )
                .is_err()
        );
    }

    #[test]
    fn promotion_contract_serializes_exact_state_and_receipt_keys() {
        let (freeze, plan) = freeze_and_plan();
        let machine = PromotionStateMachine::new(freeze).expect("state machine");
        let receipt = candidate_receipt(&plan, EvaluationLane::Public);
        let schema_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/harness/promotion-state.v1.json");
        let schema: Value = serde_json::from_slice(&fs::read(schema_path).expect("schema bytes"))
            .expect("schema json");
        let machine_keys = schema["$defs"]["promotionStateMachine"]["properties"]
            .as_object()
            .expect("machine schema properties")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let actual_machine_keys = serde_json::to_value(machine)
            .expect("machine json")
            .as_object()
            .expect("machine object")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual_machine_keys, machine_keys);
        let receipt_keys = schema["$defs"]["currentCommitReceipt"]["properties"]
            .as_object()
            .expect("receipt schema properties")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let actual_receipt_keys = serde_json::to_value(receipt)
            .expect("receipt json")
            .as_object()
            .expect("receipt object")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual_receipt_keys, receipt_keys);
    }

    #[test]
    fn promotion_receipt_rejects_unknown_and_missing_fields() {
        let (_freeze, plan) = freeze_and_plan();
        let receipt = candidate_receipt(&plan, EvaluationLane::Public);
        let mut unknown = serde_json::to_value(&receipt).expect("receipt json");
        unknown["unexpected"] = Value::String("injected".into());
        assert!(serde_json::from_value::<super::CurrentCommitReceipt>(unknown).is_err());
        let mut missing = serde_json::to_value(receipt).expect("receipt json");
        missing
            .as_object_mut()
            .expect("receipt object")
            .remove("receiptDigest");
        assert!(serde_json::from_value::<super::CurrentCommitReceipt>(missing).is_err());
    }
}

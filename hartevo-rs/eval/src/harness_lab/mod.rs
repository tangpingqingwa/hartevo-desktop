mod digest;
mod model;
mod promotion;
mod runtime;
mod verifier;

pub use model::{
    CandidateIdentity, CaseObservation, ComparisonRole, CrossLaneLeakageFlags, DecisionStatus,
    EvaluationInput, EvaluationLane, EvidenceKind, GateThresholds, GoalFlags, HarnessFamily,
    HarnessLabReport, LAB_AUTHORITY, LAB_DOCUMENT_TYPE, LAB_SCHEMA_VERSION, LabPlan, LaneSummary,
    LeakageCheck, MatrixEntry, MetricSnapshot, OutcomeFlags, PlanInputs, PrivateLeakageFlags,
    ProcessFlags, PromotionAction, PromotionDecision, PromotionKey, ProviderMode, RELEASE_DECISION,
    RUN_AUTHORITY, ReplayPack, RunResult, RunnerDisposition, SAFETY_INVARIANT_IDS,
    SignedPromotionRecord, WorkspaceScope,
};
pub use promotion::{
    CandidateIdentityFreeze, CurrentCommitReceipt, PROMOTION_AUTHORITY, PROMOTION_CONTRACT_PATH,
    PROMOTION_RELEASE_DECISION, PROMOTION_SCHEMA_VERSION, PromotionState, PromotionStateDecision,
    PromotionStateMachine, PromotionTransition, build_current_commit_receipt,
    candidate_identity_digest, freeze_candidate_identity, promotion_contract_digest,
    verify_current_commit_receipt, verify_current_commit_receipt_against_run,
    verify_frozen_candidate_identity, verify_live_current_commit_receipt,
    verify_live_promotion_state_machine, verify_promotion_state_machine,
};
pub use runtime::{
    RUNTIME_AUTHORITY, RUNTIME_CONTRACT_PATH, RUNTIME_RELEASE_DECISION, RUNTIME_SCHEMA_VERSION,
    RuntimeCandidateRunner, RuntimeExecutionMode, RuntimeMatrixReport, RuntimeMetricRow,
    RuntimeQualityStatus, RuntimeReplayPack, validate_runtime_matrix_report,
};
pub use verifier::{
    build_frozen_plan, build_run_result, contract_digest, current_source_commit, evaluate,
    promotion_payload_digest, promotion_signing_bytes, validate_plan, validate_plan_with_bindings,
    verify_signed_record,
};

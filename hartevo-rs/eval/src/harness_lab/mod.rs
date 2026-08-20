mod digest;
mod model;
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
pub use verifier::{
    build_frozen_plan, build_run_result, contract_digest, current_source_commit, evaluate,
    promotion_payload_digest, promotion_signing_bytes, validate_plan, validate_plan_with_bindings,
    verify_signed_record,
};

//! Bounded, read-only Runtime execution for the exact VM-07 contract.
//!
//! This module is deliberately narrower than the general Runtime protocol. It
//! compiles the persisted Mission definition into a content-free plan and can
//! emit only typed observation requests. Provider payloads and private
//! research text never become part of the plan, cursor, or durable progress
//! identity.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_context_fabric::{
    DurableUsefulProgressIdentity, VM07_MISSION_ID, VM07_MISSION_VERSION,
    VM07_PACK_CONTRACT_VERSION, Vm07ContractFence, Vm07ObservationSourceClass,
    Vm07ProgressCursor, Vm07ProgressIdentityError,
};
use hartevo_domain_kernel::{
    ContextBudget, ContextError, Mission, MissionCheckpointCompletionPolicy,
    MissionCheckpointExecutor, MissionError, OperatingContractError, OperatingMode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const VM07_PLAN_SCHEMA: &str = "hartevo.vm07-read-only-plan/v1";
pub const VM07_PLAN_SCHEMA_VERSION: u32 = 1;
pub const VM07_OBSERVATION_REQUEST_SCHEMA: &str = "hartevo.vm07-observation-request/v1";
pub const VM07_OBSERVATION_REQUEST_SCHEMA_VERSION: u32 = 1;
pub const VM07_OBSERVATION_RECEIPT_SCHEMA: &str = "hartevo.vm07-observation-receipt/v1";
pub const VM07_NO_OBSERVATION_SCHEMA: &str = "hartevo.vm07-no-observation/v1";

const VM07_CAPABILITIES: [&str; 6] = [
    "research.discover",
    "search.measure",
    "ground_truth.measure",
    "marketplace.read",
    "decision.evaluate",
    "outcome.review",
];
const VM07_ARTIFACTS: [&str; 5] = [
    "market_evidence_pack",
    "truth_uncertainty_map",
    "market_decision",
    "counterevidence",
    "budgeted_experiment_plan",
];
const VM07_ORACLES: [&str; 6] = [
    "goal",
    "truth",
    "decision",
    "work_product",
    "operating_state",
    "outcome",
];
const VM07_STOP_CONDITIONS: [Vm07StopCondition; 4] = [
    Vm07StopCondition::UserCancelled,
    Vm07StopCondition::BudgetExhausted,
    Vm07StopCondition::ContractExpired,
    Vm07StopCondition::RequiredConnectionRevoked,
];
const VM07_COMPLETION_CONDITIONS: [Vm07CompletionCondition; 3] = [
    Vm07CompletionCondition::CheckpointDagCompleted,
    Vm07CompletionCondition::DeterministicOraclesSatisfied,
    Vm07CompletionCondition::OutcomeReviewedOrValidTerminalRecorded,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07RequiredSection {
    Claims,
    TruthUncertaintyMap,
    Counterevidence,
    Recommendation,
    ExperimentPlan,
}

impl Vm07RequiredSection {
    const fn all() -> [Self; 5] {
        [
            Self::Claims,
            Self::TruthUncertaintyMap,
            Self::Counterevidence,
            Self::Recommendation,
            Self::ExperimentPlan,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07StopCondition {
    UserCancelled,
    BudgetExhausted,
    ContractExpired,
    RequiredConnectionRevoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07CompletionCondition {
    CheckpointDagCompleted,
    DeterministicOraclesSatisfied,
    OutcomeReviewedOrValidTerminalRecorded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07PlanBounds {
    pub max_requests_per_step: u32,
    pub max_total_requests: u32,
    pub max_response_bytes: u64,
    pub max_total_response_bytes: u64,
}

impl Default for Vm07PlanBounds {
    fn default() -> Self {
        Self {
            max_requests_per_step: 4,
            max_total_requests: 16,
            max_response_bytes: 256 * 1024,
            max_total_response_bytes: 4 * 1024 * 1024,
        }
    }
}

impl Vm07PlanBounds {
    pub fn validate(&self) -> Result<(), Vm07PlanError> {
        if self.max_requests_per_step == 0
            || self.max_total_requests == 0
            || self.max_total_requests < self.max_requests_per_step
            || self.max_response_bytes == 0
            || self.max_total_response_bytes < self.max_response_bytes
        {
            return Err(Vm07PlanError::InvalidBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ReadOnlyStep {
    pub ordinal: u32,
    pub checkpoint_id: String,
    pub capability_id: String,
    pub source_class: Vm07ObservationSourceClass,
    pub max_requests: u32,
    pub max_response_bytes: u64,
    pub completion_policy: MissionCheckpointCompletionPolicy,
    pub oracle_ids: BTreeSet<String>,
}

impl Vm07ReadOnlyStep {
    fn validate(&self, bounds: &Vm07PlanBounds) -> Result<(), Vm07PlanError> {
        if self.ordinal == 0
            || self.checkpoint_id.trim().is_empty()
            || self.capability_id != self.source_class.capability_id()
            || self.checkpoint_id != self.source_class.checkpoint_id()
            || self.max_requests == 0
            || self.max_requests > bounds.max_requests_per_step
            || self.max_response_bytes == 0
            || self.max_response_bytes > bounds.max_response_bytes
            || self.completion_policy != MissionCheckpointCompletionPolicy::WorkProduct
            || self.oracle_ids.is_empty()
            || self
                .oracle_ids
                .iter()
                .any(|oracle| oracle.trim().is_empty())
        {
            return Err(Vm07PlanError::InvalidStep);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ReadOnlyPlan {
    pub schema: String,
    pub schema_version: u32,
    pub contract_version: String,
    pub mission_version: u32,
    pub scope: Vm07ContractFence,
    pub plan_id: String,
    pub plan_digest: String,
    pub market: String,
    pub language: String,
    pub goal_digest: String,
    pub stop_conditions: Vec<Vm07StopCondition>,
    pub completion_conditions: Vec<Vm07CompletionCondition>,
    pub budget: ContextBudget,
    pub bounds: Vm07PlanBounds,
    pub required_sections: BTreeSet<Vm07RequiredSection>,
    pub steps: Vec<Vm07ReadOnlyStep>,
    pub runtime_authority: bool,
    pub release_authority: bool,
    pub external_writes: bool,
}

impl Vm07ReadOnlyPlan {
    /// Compiles only the exact versioned VM-07 Mission definition. A plan is
    /// content-free with respect to the research body: the goal is represented
    /// by a digest and no provider or private text is copied into it.
    pub fn compile(
        mission: &Mission,
        budget: ContextBudget,
        pack_revision: u64,
        bounds: Vm07PlanBounds,
        now: DateTime<Utc>,
    ) -> Result<Self, Vm07PlanError> {
        mission.contract.validate(now)?;
        budget.validate_at(now)?;
        bounds.validate()?;
        if mission.revision == 0
            || pack_revision == 0
            || mission.contract.version != 1
            || mission.contract.mode != OperatingMode::OneOffDecision
            || budget.cost_limit.currency != mission.contract.budget.currency
            || budget.cost_limit.amount_minor > mission.contract.budget.amount_minor
            || budget.deadline_at > mission.contract.valid_until
        {
            return Err(Vm07PlanError::ContractMismatch);
        }

        let definition = mission
            .definition
            .as_ref()
            .ok_or(Vm07PlanError::MissingDefinition)?;
        validate_exact_definition(definition)?;
        validate_exact_contract(mission)?;

        let contract_digest = digest_json(&mission.contract)?;
        let scope = Vm07ContractFence::new(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            contract_digest,
            mission.revision,
            pack_revision,
        )?;
        let required_sections = Vm07RequiredSection::all().into_iter().collect();
        let steps = Vm07ObservationSourceClass::all()
            .into_iter()
            .map(|source_class| {
                let checkpoint = definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == source_class.checkpoint_id())
                    .ok_or(Vm07PlanError::MissingDefinition)?;
                let route = checkpoint
                    .route
                    .as_ref()
                    .ok_or(Vm07PlanError::InvalidDefinition)?;
                Ok(Vm07ReadOnlyStep {
                    ordinal: source_class.ordinal(),
                    checkpoint_id: source_class.checkpoint_id().into(),
                    capability_id: source_class.capability_id().into(),
                    source_class,
                    max_requests: bounds.max_requests_per_step,
                    max_response_bytes: bounds.max_response_bytes,
                    completion_policy: route
                        .completion_policy
                        .ok_or(Vm07PlanError::InvalidDefinition)?,
                    oracle_ids: route.oracle_ids.clone(),
                })
            })
            .collect::<Result<Vec<_>, Vm07PlanError>>()?;

        let mut plan = Self {
            schema: VM07_PLAN_SCHEMA.into(),
            schema_version: VM07_PLAN_SCHEMA_VERSION,
            contract_version: VM07_PACK_CONTRACT_VERSION.into(),
            mission_version: VM07_MISSION_VERSION,
            scope,
            plan_id: String::new(),
            plan_digest: String::new(),
            market: mission.contract.market.clone(),
            language: mission.contract.language.clone(),
            goal_digest: digest_json(&mission.contract.goal)?,
            stop_conditions: VM07_STOP_CONDITIONS.into(),
            completion_conditions: VM07_COMPLETION_CONDITIONS.into(),
            budget,
            bounds,
            required_sections,
            steps,
            runtime_authority: false,
            release_authority: false,
            external_writes: false,
        };
        let plan_digest = plan.calculate_plan_digest()?;
        plan.plan_id = format!("vm07-plan-{}", &plan_digest[..16]);
        plan.plan_digest = plan_digest;
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), Vm07PlanError> {
        self.scope.validate()?;
        if self.schema != VM07_PLAN_SCHEMA
            || self.schema_version != VM07_PLAN_SCHEMA_VERSION
            || self.contract_version != VM07_PACK_CONTRACT_VERSION
            || self.mission_version != VM07_MISSION_VERSION
            || !is_bounded_text(&self.market)
            || !is_bounded_text(&self.language)
            || !is_bounded_identifier(&self.plan_id)
            || !is_sha256(&self.plan_digest)
            || !is_sha256(&self.goal_digest)
            || self.stop_conditions != VM07_STOP_CONDITIONS
            || self.completion_conditions != VM07_COMPLETION_CONDITIONS
            || self.required_sections
                != Vm07RequiredSection::all().into_iter().collect::<BTreeSet<_>>()
            || self.runtime_authority
            || self.release_authority
            || self.external_writes
        {
            return Err(Vm07PlanError::InvalidPlan);
        }
        self.budget
            .validate_at(self.budget.deadline_at - chrono::Duration::nanoseconds(1))?;
        self.bounds.validate()?;
        if self.steps.len() != Vm07ObservationSourceClass::all().len() {
            return Err(Vm07PlanError::InvalidStep);
        }
        for (index, step) in self.steps.iter().enumerate() {
            step.validate(&self.bounds)?;
            if step.ordinal != u32::try_from(index + 1).unwrap_or_default()
                || step.source_class != Vm07ObservationSourceClass::all()[index]
            {
                return Err(Vm07PlanError::InvalidStep);
            }
        }
        if self.plan_digest != self.calculate_plan_digest()? {
            return Err(Vm07PlanError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), Vm07PlanError> {
        self.validate()?;
        self.budget.validate_at(now)?;
        if self.scope.mission_id.as_str() != VM07_MISSION_ID {
            return Err(Vm07PlanError::ContractMismatch);
        }
        Ok(())
    }

    fn calculate_plan_digest(&self) -> Result<String, Vm07PlanError> {
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or(Vm07PlanError::InvalidPlan)?;
        object.insert("planId".into(), Value::String(String::new()));
        object.insert("planDigest".into(), Value::String(String::new()));
        digest_json(&value).map_err(Vm07PlanError::from)
    }
}

fn validate_exact_definition(
    definition: &hartevo_domain_kernel::MissionDefinition,
) -> Result<(), Vm07PlanError> {
    if definition.manifest_id != VM07_MISSION_ID
        || definition.manifest_version != VM07_MISSION_VERSION
        || !is_sha256(&definition.catalog_digest)
        || definition.operating_mode != OperatingMode::OneOffDecision
        || definition.capability_ids != VM07_CAPABILITIES.into_iter().map(str::to_owned).collect()
        || definition.required_artifact_types
            != VM07_ARTIFACTS.into_iter().map(str::to_owned).collect()
        || definition.oracle_ids != VM07_ORACLES.into_iter().map(str::to_owned).collect()
        || definition.checkpoints.len() != 8
    {
        return Err(Vm07PlanError::InvalidDefinition);
    }
    let expected = [
        (
            "product_market_budget_constraints",
            "decision.evaluate",
            MissionCheckpointExecutor::Human,
            MissionCheckpointCompletionPolicy::HumanConfirmation,
            ["goal", "truth", "decision", "operating_state"].as_slice(),
        ),
        (
            "evidence_plan",
            "research.discover",
            MissionCheckpointExecutor::Runtime,
            MissionCheckpointCompletionPolicy::WorkProduct,
            ["truth", "decision", "work_product", "operating_state"].as_slice(),
        ),
        (
            "scoped_collection",
            "search.measure",
            MissionCheckpointExecutor::Runtime,
            MissionCheckpointCompletionPolicy::WorkProduct,
            ["truth", "decision", "work_product", "operating_state"].as_slice(),
        ),
        (
            "confirmed_estimated_inferred_unknown_conflict",
            "ground_truth.measure",
            MissionCheckpointExecutor::Runtime,
            MissionCheckpointCompletionPolicy::WorkProduct,
            ["truth", "work_product", "operating_state"].as_slice(),
        ),
        (
            "scenarios_risks_counterevidence",
            "marketplace.read",
            MissionCheckpointExecutor::Runtime,
            MissionCheckpointCompletionPolicy::WorkProduct,
            ["truth", "decision", "work_product", "operating_state"].as_slice(),
        ),
        (
            "go_no_go_need_more_evidence",
            "decision.evaluate",
            MissionCheckpointExecutor::Human,
            MissionCheckpointCompletionPolicy::HumanConfirmation,
            ["goal", "truth", "decision", "operating_state"].as_slice(),
        ),
        (
            "prioritized_experiments",
            "outcome.review",
            MissionCheckpointExecutor::Application,
            MissionCheckpointCompletionPolicy::DeterministicEvidence,
            ["decision", "work_product", "operating_state", "outcome"].as_slice(),
        ),
        (
            "replan_or_terminal",
            "outcome.review",
            MissionCheckpointExecutor::Application,
            MissionCheckpointCompletionPolicy::DeterministicEvidence,
            ["goal", "decision", "operating_state", "outcome"].as_slice(),
        ),
    ];
    for (checkpoint, expected) in definition.checkpoints.iter().zip(expected) {
        let Some(route) = checkpoint.route.as_ref() else {
            return Err(Vm07PlanError::InvalidDefinition);
        };
        if checkpoint.id != expected.0
            || route.capability_id != expected.1
            || route.executor != expected.2
            || route.completion_policy != Some(expected.3)
            || route.oracle_ids != expected.4.iter().map(|value| (*value).to_owned()).collect()
        {
            return Err(Vm07PlanError::InvalidDefinition);
        }
    }
    Ok(())
}

fn validate_exact_contract(mission: &Mission) -> Result<(), Vm07PlanError> {
    let contract = &mission.contract;
    let expected_stops = [
        "user_cancelled",
        "budget_exhausted",
        "contract_expired",
        "required_connection_revoked",
    ];
    let expected_completion = [
        "checkpoint_dag_completed",
        "deterministic_oracles_satisfied",
        "outcome_reviewed_or_valid_terminal_recorded",
    ];
    if contract.stop_conditions
        != expected_stops
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
        || contract.completion_conditions
            != expected_completion
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        || VM07_CAPABILITIES
            .iter()
            .any(|capability| !contract.enabled_capabilities.contains(*capability))
        || VM07_CAPABILITIES
            .iter()
            .any(|capability| contract.forbidden_capabilities.contains(*capability))
    {
        return Err(Vm07PlanError::ContractMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum Vm07PlanError {
    #[error("VM-07 Mission definition is missing")]
    MissingDefinition,
    #[error("VM-07 Mission definition is not the exact versioned contract")]
    InvalidDefinition,
    #[error("VM-07 operating contract does not match the exact read-only plan")]
    ContractMismatch,
    #[error("VM-07 read-only plan bounds are invalid")]
    InvalidBounds,
    #[error("VM-07 read-only plan is invalid")]
    InvalidPlan,
    #[error("VM-07 read-only plan step is invalid")]
    InvalidStep,
    #[error("VM-07 read-only plan digest does not match its fields")]
    DigestMismatch,
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    Contract(#[from] OperatingContractError),
    #[error(transparent)]
    Mission(#[from] MissionError),
    #[error(transparent)]
    Progress(#[from] Vm07ProgressIdentityError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

fn is_bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.bytes().any(|byte| byte.is_ascii_control() || byte == 0)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ObservationRequest {
    pub schema: String,
    pub schema_version: u32,
    pub scope: Vm07ContractFence,
    pub plan_id: String,
    pub plan_digest: String,
    pub request_id: String,
    pub request_sequence: u32,
    pub step_ordinal: u32,
    pub checkpoint_id: String,
    pub capability_id: String,
    pub source_class: Vm07ObservationSourceClass,
    pub market: String,
    pub language: String,
    pub issued_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub max_response_bytes: u64,
    pub remaining_token_budget: u64,
    pub remaining_cost_minor: i64,
    pub cost_currency: hartevo_domain_kernel::CurrencyCode,
    pub remaining_request_budget: u32,
    pub read_only: bool,
    pub external_writes: bool,
}

impl Vm07ObservationRequest {
    pub fn validate(&self) -> Result<(), Vm07ResearchError> {
        self.scope.validate()?;
        if self.schema != VM07_OBSERVATION_REQUEST_SCHEMA
            || self.schema_version != VM07_OBSERVATION_REQUEST_SCHEMA_VERSION
            || self.plan_id.trim().is_empty()
            || !is_sha256(&self.plan_digest)
            || !is_bounded_identifier(&self.request_id)
            || self.request_sequence == 0
            || self.step_ordinal == 0
            || self.checkpoint_id != self.source_class.checkpoint_id()
            || self.capability_id != self.source_class.capability_id()
            || !is_bounded_text(&self.market)
            || !is_bounded_text(&self.language)
            || self.deadline_at <= self.issued_at
            || self.max_response_bytes == 0
            || self.remaining_token_budget == 0
            || self.remaining_cost_minor < 0
            || self.remaining_request_budget == 0
            || !self.read_only
            || self.external_writes
        {
            return Err(Vm07ResearchError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07ObservationClassification {
    ConfirmedFact,
    ProviderEstimate,
    Inference,
    Unknown,
    Conflict,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ObservationReceipt {
    pub schema: String,
    pub schema_version: u32,
    pub scope: Vm07ContractFence,
    pub plan_id: String,
    pub plan_digest: String,
    pub request_id: String,
    pub observation_id: String,
    pub source_class: Vm07ObservationSourceClass,
    pub source_id: String,
    pub source_uri: String,
    pub observed_at: DateTime<Utc>,
    pub payload_digest: String,
    pub byte_count: u64,
    pub token_count: u64,
    pub cost_minor: i64,
    pub cost_currency: hartevo_domain_kernel::CurrencyCode,
    pub classification: Vm07ObservationClassification,
}

impl fmt::Debug for Vm07ObservationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Vm07ObservationReceipt")
            .field("scope", &self.scope)
            .field("plan_id", &self.plan_id)
            .field("request_id", &self.request_id)
            .field("observation_id", &self.observation_id)
            .field("source_class", &self.source_class)
            .field("source_id_digest", &short_digest(&self.source_id))
            .field("source_uri", &"<protected-source-boundary>")
            .field("observed_at", &self.observed_at)
            .field("payload_digest", &self.payload_digest)
            .field("byte_count", &self.byte_count)
            .field("token_count", &self.token_count)
            .field("cost_minor", &self.cost_minor)
            .field("cost_currency", &self.cost_currency)
            .field("classification", &self.classification)
            .finish()
    }
}

impl Vm07ObservationReceipt {
    pub fn validate(&self) -> Result<(), Vm07ResearchError> {
        self.scope.validate()?;
        if self.schema != VM07_OBSERVATION_RECEIPT_SCHEMA
            || self.schema_version != VM07_PLAN_SCHEMA_VERSION
            || !is_bounded_identifier(&self.plan_id)
            || !is_sha256(&self.plan_digest)
            || !is_bounded_identifier(&self.request_id)
            || !is_bounded_identifier(&self.observation_id)
            || self.source_class.capability_id().is_empty()
            || !is_bounded_identifier(&self.source_id)
            || !self.source_uri.starts_with("https://")
            || self.source_uri.len() > 2048
            || self.source_uri.bytes().any(|byte| byte.is_ascii_control() || byte == 0)
            || !is_sha256(&self.payload_digest)
            || self.cost_minor < 0
        {
            return Err(Vm07ResearchError::InvalidReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07NoObservationReason {
    NoMatch,
    SourceUnavailable,
    AlreadyObserved,
    NotUseful,
    ProviderRejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07NoObservation {
    pub schema: String,
    pub schema_version: u32,
    pub scope: Vm07ContractFence,
    pub plan_id: String,
    pub plan_digest: String,
    pub request_id: String,
    pub reason: Vm07NoObservationReason,
    pub reason_digest: String,
}

impl Vm07NoObservation {
    pub fn new(
        scope: Vm07ContractFence,
        plan_id: impl Into<String>,
        plan_digest: impl Into<String>,
        request_id: impl Into<String>,
        reason: Vm07NoObservationReason,
    ) -> Result<Self, Vm07ResearchError> {
        let mut result = Self {
            schema: VM07_NO_OBSERVATION_SCHEMA.into(),
            schema_version: VM07_PLAN_SCHEMA_VERSION,
            scope,
            plan_id: plan_id.into(),
            plan_digest: plan_digest.into(),
            request_id: request_id.into(),
            reason,
            reason_digest: String::new(),
        };
        result.reason_digest = digest_json(&result.reason)?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), Vm07ResearchError> {
        self.scope.validate()?;
        if self.schema != VM07_NO_OBSERVATION_SCHEMA
            || self.schema_version != VM07_PLAN_SCHEMA_VERSION
            || !is_bounded_identifier(&self.plan_id)
            || !is_sha256(&self.plan_digest)
            || !is_bounded_identifier(&self.request_id)
            || !is_sha256(&self.reason_digest)
            || self.reason_digest != digest_json(&self.reason)?
        {
            return Err(Vm07ResearchError::InvalidNoObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Vm07ObservationResult {
    Useful { receipt: Vm07ObservationReceipt },
    Empty { result: Vm07NoObservation },
}

impl Vm07ObservationResult {
    pub fn validate(&self) -> Result<(), Vm07ResearchError> {
        match self {
            Self::Useful { receipt } => receipt.validate(),
            Self::Empty { result } => result.validate(),
        }
    }

    fn request_id(&self) -> &str {
        match self {
            Self::Useful { receipt } => &receipt.request_id,
            Self::Empty { result } => &result.request_id,
        }
    }

    fn scope(&self) -> &Vm07ContractFence {
        match self {
            Self::Useful { receipt } => &receipt.scope,
            Self::Empty { result } => &result.scope,
        }
    }

    fn plan_id(&self) -> &str {
        match self {
            Self::Useful { receipt } => &receipt.plan_id,
            Self::Empty { result } => &result.plan_id,
        }
    }

    fn plan_digest(&self) -> &str {
        match self {
            Self::Useful { receipt } => &receipt.plan_digest,
            Self::Empty { result } => &result.plan_digest,
        }
    }

    fn digest(&self) -> Result<String, Vm07ResearchError> {
        Ok(digest_json(self)?)
    }
}

fn short_digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))[..16].to_owned()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07ResearchStatus {
    Active,
    Complete,
    Cancelled,
    DeadlineExceeded,
    BudgetExhausted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ObservationEmission {
    pub request: Vm07ObservationRequest,
    pub progress: DurableUsefulProgressIdentity,
}

impl Vm07ObservationEmission {
    fn validate(&self) -> Result<(), Vm07ResearchError> {
        self.request.validate()?;
        self.progress.validate()?;
        if self.request.request_id != self.progress.request_id
            || self.request.request_sequence != self.progress.request_sequence
            || self.request.step_ordinal != self.progress.step_ordinal
            || self.request.source_class != self.progress.source_class
            || self.progress.kind
                != hartevo_context_fabric::Vm07UsefulProgressKind::ObservationRequestIssued
        {
            return Err(Vm07ResearchError::InvalidEmission);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Vm07NextObservation {
    Emit { emission: Vm07ObservationEmission },
    Replay { emission: Vm07ObservationEmission },
    Complete {
        progress: DurableUsefulProgressIdentity,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ProgressUpdate {
    pub cursor: Vm07ProgressCursor,
    pub identity: Option<DurableUsefulProgressIdentity>,
    pub request_completed: bool,
    pub useful: bool,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Vm07CompletedRequest {
    result_digest: String,
    progress: Option<DurableUsefulProgressIdentity>,
    cursor: Vm07ProgressCursor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ResearchCoordinator {
    pub plan: Vm07ReadOnlyPlan,
    pub cursor: Vm07ProgressCursor,
    pub status: Vm07ResearchStatus,
    pub last_progress: Option<DurableUsefulProgressIdentity>,
    pub terminal_progress: Option<DurableUsefulProgressIdentity>,
    pub consumed_tokens: u64,
    pub consumed_bytes: u64,
    pub consumed_cost_minor: i64,
    #[serde(default)]
    in_flight: Option<Vm07ObservationEmission>,
    #[serde(default)]
    completed_requests: BTreeMap<String, Vm07CompletedRequest>,
}

impl Vm07ResearchCoordinator {
    pub fn new(plan: Vm07ReadOnlyPlan) -> Result<Self, Vm07ResearchError> {
        plan.validate()?;
        let coordinator = Self {
            plan,
            cursor: Vm07ProgressCursor {
                next_step_ordinal: 1,
                next_request_sequence: 1,
                ..Vm07ProgressCursor::default()
            },
            status: Vm07ResearchStatus::Active,
            last_progress: None,
            terminal_progress: None,
            consumed_tokens: 0,
            consumed_bytes: 0,
            consumed_cost_minor: 0,
            in_flight: None,
            completed_requests: BTreeMap::new(),
        };
        coordinator.validate()?;
        Ok(coordinator)
    }

    pub fn validate(&self) -> Result<(), Vm07ResearchError> {
        self.plan.validate()?;
        self.cursor.validate()?;
        if self.consumed_tokens > self.plan.budget.token_limit
            || self.consumed_bytes > self.plan.bounds.max_total_response_bytes
            || self.consumed_cost_minor < 0
            || self.consumed_cost_minor > self.plan.budget.cost_limit.amount_minor
            || self.cursor.requests_issued > self.plan.bounds.max_total_requests
            || self.cursor.requests_completed > self.cursor.requests_issued
            || self.completed_requests.len() as u32 > self.cursor.requests_completed
        {
            return Err(Vm07ResearchError::InvalidCoordinator);
        }
        if self
            .last_progress
            .as_ref()
            .is_some_and(|progress| progress.validate().is_err())
            || self
                .terminal_progress
                .as_ref()
                .is_some_and(|progress| progress.validate().is_err())
        {
            return Err(Vm07ResearchError::InvalidCoordinator);
        }
        if let Some(progress) = &self.last_progress {
            if progress.scope != self.plan.scope
                || progress.plan_id != self.plan.plan_id
                || progress.plan_digest != self.plan.plan_digest
            {
                return Err(Vm07ResearchError::InvalidCoordinator);
            }
        }
        if let Some(progress) = &self.terminal_progress {
            if progress.scope != self.plan.scope
                || progress.plan_id != self.plan.plan_id
                || progress.plan_digest != self.plan.plan_digest
                || progress.kind
                    != hartevo_context_fabric::Vm07UsefulProgressKind::PlanCompleted
            {
                return Err(Vm07ResearchError::InvalidCoordinator);
            }
        }
        if let Some(emission) = &self.in_flight {
            emission.validate()?;
            if emission.request.scope != self.plan.scope
                || emission.request.plan_id != self.plan.plan_id
                || emission.request.plan_digest != self.plan.plan_digest
                || emission.request.request_sequence >= self.cursor.next_request_sequence
                || emission.request.request_sequence == 0
            {
                return Err(Vm07ResearchError::InvalidCoordinator);
            }
        }
        for (request_id, completed) in &self.completed_requests {
            if !is_bounded_identifier(request_id)
                || !is_sha256(&completed.result_digest)
                || completed.cursor.validate().is_err()
                || completed.cursor.requests_completed == 0
            {
                return Err(Vm07ResearchError::InvalidCoordinator);
            }
            if let Some(progress) = &completed.progress {
                progress.validate()?;
                if progress.scope != self.plan.scope
                    || progress.plan_id != self.plan.plan_id
                    || progress.plan_digest != self.plan.plan_digest
                    || progress.request_id != *request_id
                {
                    return Err(Vm07ResearchError::InvalidCoordinator);
                }
            }
        }
        if matches!(self.status, Vm07ResearchStatus::Complete)
            && self.terminal_progress.is_none()
        {
            return Err(Vm07ResearchError::InvalidCoordinator);
        }
        if !matches!(self.status, Vm07ResearchStatus::Active)
            && self.in_flight.is_some()
        {
            return Err(Vm07ResearchError::InvalidCoordinator);
        }
        Ok(())
    }

    pub fn next_observation(
        &mut self,
        fence: &Vm07ContractFence,
        now: DateTime<Utc>,
    ) -> Result<Vm07NextObservation, Vm07ResearchError> {
        self.ensure_fence(fence)?;
        self.enforce_deadline(now)?;
        match self.status {
            Vm07ResearchStatus::Complete => {
                return self
                    .terminal_progress
                    .clone()
                    .map(|progress| Vm07NextObservation::Complete { progress })
                    .ok_or(Vm07ResearchError::InvalidCoordinator);
            }
            Vm07ResearchStatus::Cancelled => return Err(Vm07ResearchError::Cancelled),
            Vm07ResearchStatus::DeadlineExceeded => {
                return Err(Vm07ResearchError::DeadlineExceeded);
            }
            Vm07ResearchStatus::BudgetExhausted => {
                return Err(Vm07ResearchError::BudgetExhausted);
            }
            Vm07ResearchStatus::Active => {}
        }
        if let Some(emission) = &self.in_flight {
            return Ok(Vm07NextObservation::Replay {
                emission: emission.clone(),
            });
        }
        self.advance_exhausted_steps()?;
        if self.cursor.next_step_ordinal > self.plan.steps.len() as u32 {
            let progress = self.complete_internal(now)?;
            return Ok(Vm07NextObservation::Complete { progress });
        }
        if self.cursor.requests_issued >= self.plan.bounds.max_total_requests
            || self.consumed_tokens >= self.plan.budget.token_limit
            || self.consumed_cost_minor >= self.plan.budget.cost_limit.amount_minor
        {
            return Err(self.mark_budget_exhausted());
        }

        let step = self.current_step()?.clone();
        let sequence = self.cursor.next_request_sequence;
        let request_id = self.request_id(sequence, step.ordinal)?;
        if self.completed_requests.contains_key(&request_id) {
            return Err(Vm07ResearchError::DuplicateRequestState);
        }
        let request = Vm07ObservationRequest {
            schema: VM07_OBSERVATION_REQUEST_SCHEMA.into(),
            schema_version: VM07_OBSERVATION_REQUEST_SCHEMA_VERSION,
            scope: self.plan.scope.clone(),
            plan_id: self.plan.plan_id.clone(),
            plan_digest: self.plan.plan_digest.clone(),
            request_id,
            request_sequence: sequence,
            step_ordinal: step.ordinal,
            checkpoint_id: step.checkpoint_id,
            capability_id: step.capability_id,
            source_class: step.source_class,
            market: self.plan.market.clone(),
            language: self.plan.language.clone(),
            issued_at: now,
            deadline_at: self.plan.budget.deadline_at,
            max_response_bytes: step.max_response_bytes,
            remaining_token_budget: self.plan.budget.token_limit - self.consumed_tokens,
            remaining_cost_minor: self.plan.budget.cost_limit.amount_minor
                - self.consumed_cost_minor,
            cost_currency: self.plan.budget.cost_limit.currency.clone(),
            remaining_request_budget: self.plan.bounds.max_total_requests
                - self.cursor.requests_issued,
            read_only: true,
            external_writes: false,
        };
        request.validate()?;
        let mut next_cursor = self.cursor.clone();
        next_cursor.next_request_sequence = next_cursor
            .next_request_sequence
            .checked_add(1)
            .ok_or(Vm07ResearchError::CounterOverflow)?;
        next_cursor.requests_issued = next_cursor
            .requests_issued
            .checked_add(1)
            .ok_or(Vm07ResearchError::CounterOverflow)?;
        next_cursor.requests_issued_in_step = next_cursor
            .requests_issued_in_step
            .checked_add(1)
            .ok_or(Vm07ResearchError::CounterOverflow)?;
        let progress = DurableUsefulProgressIdentity::issue_request(
            self.plan.scope.clone(),
            self.plan.plan_id.clone(),
            self.plan.plan_digest.clone(),
            request.request_id.clone(),
            request.request_sequence,
            request.step_ordinal,
            request.source_class,
            next_cursor.clone(),
            now,
        )?;
        let emission = Vm07ObservationEmission { request, progress };
        emission.validate()?;
        self.cursor = next_cursor;
        self.last_progress = Some(emission.progress.clone());
        self.in_flight = Some(emission.clone());
        self.validate()?;
        Ok(Vm07NextObservation::Emit { emission })
    }

    pub fn record_observation(
        &mut self,
        fence: &Vm07ContractFence,
        result: Vm07ObservationResult,
        now: DateTime<Utc>,
    ) -> Result<Vm07ProgressUpdate, Vm07ResearchError> {
        self.ensure_fence(fence)?;
        self.enforce_deadline(now)?;
        result.validate()?;
        if result.scope() != &self.plan.scope
            || result.plan_id() != self.plan.plan_id
            || result.plan_digest() != self.plan.plan_digest
        {
            return Err(Vm07ResearchError::StaleContract);
        }
        let request_id = result.request_id().to_owned();
        let result_digest = result.digest()?;
        if let Some(completed) = self.completed_requests.get(&request_id) {
            if completed.result_digest != result_digest {
                return Err(Vm07ResearchError::DuplicateRequestConflict);
            }
            return Ok(Vm07ProgressUpdate {
                cursor: completed.cursor.clone(),
                identity: completed.progress.clone(),
                request_completed: true,
                useful: completed.progress.is_some(),
                replayed: true,
            });
        }
        let emission = self
            .in_flight
            .clone()
            .ok_or(Vm07ResearchError::RequestNotInFlight)?;
        if emission.request.request_id != request_id {
            return Err(Vm07ResearchError::RequestNotInFlight);
        }
        match &result {
            Vm07ObservationResult::Useful { receipt } => {
                if receipt.source_class != emission.request.source_class
                    || receipt.observed_at > now
                    || receipt.byte_count > emission.request.max_response_bytes
                    || receipt.cost_currency != self.plan.budget.cost_limit.currency
                    || receipt.cost_minor > emission.request.remaining_cost_minor
                    || receipt.token_count > emission.request.remaining_token_budget
                {
                    return Err(self.mark_budget_exhausted());
                }
                self.consumed_tokens = self
                    .consumed_tokens
                    .checked_add(receipt.token_count)
                    .ok_or(Vm07ResearchError::CounterOverflow)?;
                self.consumed_bytes = self
                    .consumed_bytes
                    .checked_add(receipt.byte_count)
                    .ok_or(Vm07ResearchError::CounterOverflow)?;
                self.consumed_cost_minor = self
                    .consumed_cost_minor
                    .checked_add(receipt.cost_minor)
                    .ok_or(Vm07ResearchError::CounterOverflow)?;
                if self.consumed_tokens > self.plan.budget.token_limit
                    || self.consumed_bytes > self.plan.bounds.max_total_response_bytes
                    || self.consumed_cost_minor > self.plan.budget.cost_limit.amount_minor
                {
                    return Err(self.mark_budget_exhausted());
                }
                let mut completed_cursor = self.cursor.clone();
                completed_cursor.requests_completed = completed_cursor
                    .requests_completed
                    .checked_add(1)
                    .ok_or(Vm07ResearchError::CounterOverflow)?;
                completed_cursor.useful_observation_count = completed_cursor
                    .useful_observation_count
                    .checked_add(1)
                    .ok_or(Vm07ResearchError::CounterOverflow)?;
                let progress = DurableUsefulProgressIdentity::record_observation(
                    self.plan.scope.clone(),
                    self.plan.plan_id.clone(),
                    self.plan.plan_digest.clone(),
                    request_id.clone(),
                    emission.request.request_sequence,
                    emission.request.step_ordinal,
                    emission.request.source_class,
                    receipt.observation_id.clone(),
                    completed_cursor.clone(),
                    now,
                )?;
                self.finish_request(
                    request_id,
                    result_digest,
                    Some(progress.clone()),
                    completed_cursor.clone(),
                )?;
                Ok(Vm07ProgressUpdate {
                    cursor: completed_cursor,
                    identity: Some(progress),
                    request_completed: true,
                    useful: true,
                    replayed: false,
                })
            }
            Vm07ObservationResult::Empty { .. } => {
                let mut completed_cursor = self.cursor.clone();
                completed_cursor.requests_completed = completed_cursor
                    .requests_completed
                    .checked_add(1)
                    .ok_or(Vm07ResearchError::CounterOverflow)?;
                let identity = self.last_progress.clone();
                self.finish_request(
                    request_id,
                    result_digest,
                    None,
                    completed_cursor.clone(),
                )?;
                Ok(Vm07ProgressUpdate {
                    cursor: completed_cursor,
                    identity,
                    request_completed: true,
                    useful: false,
                    replayed: false,
                })
            }
        }
    }

    pub fn cancel(
        &mut self,
        fence: &Vm07ContractFence,
        now: DateTime<Utc>,
    ) -> Result<(), Vm07ResearchError> {
        self.ensure_fence(fence)?;
        self.enforce_deadline(now)?;
        match self.status {
            Vm07ResearchStatus::Active => {
                self.status = Vm07ResearchStatus::Cancelled;
                self.in_flight = None;
                self.validate()?;
                Ok(())
            }
            Vm07ResearchStatus::Cancelled => Ok(()),
            Vm07ResearchStatus::Complete => Err(Vm07ResearchError::AlreadyComplete),
            Vm07ResearchStatus::DeadlineExceeded => Err(Vm07ResearchError::DeadlineExceeded),
            Vm07ResearchStatus::BudgetExhausted => Err(Vm07ResearchError::BudgetExhausted),
        }
    }

    pub fn complete(
        &mut self,
        fence: &Vm07ContractFence,
        now: DateTime<Utc>,
    ) -> Result<DurableUsefulProgressIdentity, Vm07ResearchError> {
        self.ensure_fence(fence)?;
        self.enforce_deadline(now)?;
        if self.status == Vm07ResearchStatus::Complete {
            return self
                .terminal_progress
                .clone()
                .ok_or(Vm07ResearchError::InvalidCoordinator);
        }
        if self.status != Vm07ResearchStatus::Active {
            return Err(Vm07ResearchError::NotActive);
        }
        self.advance_exhausted_steps()?;
        if self.in_flight.is_some() || self.cursor.next_step_ordinal <= self.plan.steps.len() as u32
        {
            return Err(Vm07ResearchError::CompletionNotReady);
        }
        self.complete_internal(now)
    }

    fn finish_request(
        &mut self,
        request_id: String,
        result_digest: String,
        progress: Option<DurableUsefulProgressIdentity>,
        cursor: Vm07ProgressCursor,
    ) -> Result<(), Vm07ResearchError> {
        self.in_flight = None;
        self.cursor = cursor.clone();
        self.completed_requests.insert(
            request_id,
            Vm07CompletedRequest {
                result_digest,
                progress: progress.clone(),
                cursor,
            },
        );
        if let Some(progress) = progress {
            self.last_progress = Some(progress);
        }
        self.validate()
    }

    fn complete_internal(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<DurableUsefulProgressIdentity, Vm07ResearchError> {
        let request_sequence = self.cursor.next_request_sequence;
        let request_id = format!(
            "vm07-complete-{}",
            &self.terminal_digest(request_sequence)?[..24]
        );
        let progress = DurableUsefulProgressIdentity::complete_plan(
            self.plan.scope.clone(),
            self.plan.plan_id.clone(),
            self.plan.plan_digest.clone(),
            request_id,
            request_sequence,
            self.plan.steps.len() as u32 + 1,
            self.cursor.clone(),
            now,
        )?;
        self.status = Vm07ResearchStatus::Complete;
        self.terminal_progress = Some(progress.clone());
        self.last_progress = Some(progress.clone());
        self.validate()?;
        Ok(progress)
    }

    fn current_step(&self) -> Result<&Vm07ReadOnlyStep, Vm07ResearchError> {
        let index = usize::try_from(self.cursor.next_step_ordinal - 1)
            .map_err(|_| Vm07ResearchError::InvalidCoordinator)?;
        self.plan
            .steps
            .get(index)
            .ok_or(Vm07ResearchError::CompletionNotReady)
    }

    fn advance_exhausted_steps(&mut self) -> Result<(), Vm07ResearchError> {
        while self.cursor.next_step_ordinal <= self.plan.steps.len() as u32 {
            let step = self.current_step()?;
            if self.cursor.requests_issued_in_step < step.max_requests {
                break;
            }
            self.cursor.next_step_ordinal = self
                .cursor
                .next_step_ordinal
                .checked_add(1)
                .ok_or(Vm07ResearchError::CounterOverflow)?;
            self.cursor.requests_issued_in_step = 0;
        }
        Ok(())
    }

    fn request_id(&self, sequence: u32, step_ordinal: u32) -> Result<String, Vm07ResearchError> {
        let digest = digest_json(&("vm07-observation", &self.plan.plan_digest, sequence, step_ordinal))?;
        Ok(format!("vm07-request-{}", &digest[..24]))
    }

    fn terminal_digest(&self, sequence: u32) -> Result<String, Vm07ResearchError> {
        Ok(digest_json(&("vm07-complete", &self.plan.plan_digest, sequence))?)
    }

    fn ensure_fence(&self, fence: &Vm07ContractFence) -> Result<(), Vm07ResearchError> {
        fence.validate()?;
        if fence != &self.plan.scope {
            return Err(Vm07ResearchError::StaleContract);
        }
        Ok(())
    }

    fn enforce_deadline(&mut self, now: DateTime<Utc>) -> Result<(), Vm07ResearchError> {
        if now >= self.plan.budget.deadline_at {
            self.status = Vm07ResearchStatus::DeadlineExceeded;
            self.in_flight = None;
            return Err(Vm07ResearchError::DeadlineExceeded);
        }
        Ok(())
    }

    fn mark_budget_exhausted(&mut self) -> Vm07ResearchError {
        self.status = Vm07ResearchStatus::BudgetExhausted;
        self.in_flight = None;
        Vm07ResearchError::BudgetExhausted
    }
}

#[derive(Debug, Error)]
pub enum Vm07ResearchError {
    #[error("VM-07 request or result belongs to a stale contract revision")]
    StaleContract,
    #[error("VM-07 research deadline has expired")]
    DeadlineExceeded,
    #[error("VM-07 research budget or request bound is exhausted")]
    BudgetExhausted,
    #[error("VM-07 research was cancelled")]
    Cancelled,
    #[error("VM-07 research is already complete")]
    AlreadyComplete,
    #[error("VM-07 research coordinator is not active")]
    NotActive,
    #[error("VM-07 completion requires all bounded observation steps to be consumed")]
    CompletionNotReady,
    #[error("VM-07 observation request is invalid")]
    InvalidRequest,
    #[error("VM-07 observation receipt is invalid")]
    InvalidReceipt,
    #[error("VM-07 empty observation result is invalid")]
    InvalidNoObservation,
    #[error("VM-07 observation emission is invalid")]
    InvalidEmission,
    #[error("VM-07 observation request is not in flight")]
    RequestNotInFlight,
    #[error("VM-07 replay payload conflicts with the already recorded request")]
    DuplicateRequestConflict,
    #[error("VM-07 request identity is already present in coordinator state")]
    DuplicateRequestState,
    #[error("VM-07 coordinator state is invalid")]
    InvalidCoordinator,
    #[error("VM-07 bounded counter overflowed")]
    CounterOverflow,
    #[error(transparent)]
    Plan(#[from] Vm07PlanError),
    #[error(transparent)]
    Progress(#[from] Vm07ProgressIdentityError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

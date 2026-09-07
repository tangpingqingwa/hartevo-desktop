//! Long-running Mission control, inspired by LoopX's control-plane contracts.
//!
//! This module owns bounded work, claims, gates and compute accounting. The
//! existing Mission owns business lifecycle and evidence; a loop receipt never
//! completes a Mission or grants permission to execute an external Effect.

mod decision;
#[cfg(test)]
mod tests;
mod transition;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ActorId, EvidenceId, Mission, MissionId, ProjectId, TaskId, TenantId};

pub use decision::{LoopDecision, LoopMode, LoopUserChannel, LoopWake};

pub const LOOP_SCHEMA_VERSION: u32 = 1;
pub const LOOP_HISTORY_LIMIT: usize = 32;
pub const LOOP_FRONTIER_LIMIT: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopPolicy {
    pub operator_id: ActorId,
    pub max_slots: u32,
    pub max_parallel: u16,
    pub lease_seconds: u32,
    pub stall_limit: u16,
}

impl LoopPolicy {
    pub fn validate(&self) -> Result<(), LoopError> {
        if self.operator_id.as_str().trim().is_empty()
            || !(1..=64).contains(&self.max_parallel)
            || !(1..=900).contains(&self.lease_seconds)
            || !(1..=100).contains(&self.stall_limit)
        {
            return Err(LoopError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Registration establishes identity and capacity, never Effect authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopPeer {
    pub id: String,
    pub capabilities: BTreeSet<String>,
    pub workspace_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopHost {
    pub agent_id: String,
    pub available_capabilities: BTreeSet<String>,
    pub workspace_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum LoopActor {
    Operator(ActorId),
    Agent(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopWorkKind {
    Advancement,
    Repair,
    Replan,
    Monitor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopMonitor {
    pub target_digest: String,
    pub next_due_at: DateTime<Utc>,
    pub interval_seconds: u32,
    pub expires_at: DateTime<Utc>,
}

/// A bounded slice within an existing Mission Task. Repair/replan can be local
/// control work without a Task. Titles and scopes stay in encrypted storage.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopTodoSpec {
    pub id: String,
    pub title: String,
    pub task_id: Option<TaskId>,
    pub capability: Option<String>,
    pub kind: LoopWorkKind,
    pub priority: u16,
    pub depends_on: BTreeSet<String>,
    pub eligible_agents: BTreeSet<String>,
    pub required_decisions: BTreeSet<String>,
    pub workspace_digest: String,
    /// Canonical relative paths, or "." for the entire workspace.
    pub write_scopes: BTreeSet<String>,
    pub monitor: Option<LoopMonitor>,
}

impl fmt::Debug for LoopTodoSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopTodoSpec")
            .field("kind", &self.kind)
            .field("private_fields", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopTodoStatus {
    Open,
    Claimed,
    Uncertain,
    Completed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopTodo {
    pub spec: LoopTodoSpec,
    pub status: LoopTodoStatus,
    pub claim: Option<LoopClaim>,
    pub execution_started: bool,
    pub no_progress_attempts: u16,
    pub last_observation_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum LoopGateScope {
    Mission,
    Agent(String),
    Todo(String),
    Decision(String),
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopUserGate {
    pub id: String,
    pub question: String,
    pub scope: LoopGateScope,
}

impl fmt::Debug for LoopUserGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoopUserGate([PRIVATE])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopClaim {
    pub todo_id: String,
    pub agent_id: String,
    pub token_digest: String,
    pub generation: u64,
    pub steering_generation: u64,
    pub authority_digest: String,
    pub claimed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl LoopClaim {
    /// A runtime may follow a persisted heartbeat, but never a replacement
    /// claim. The full immutable execution identity must remain unchanged.
    pub fn is_renewal_of(&self, previous: &Self) -> bool {
        self.todo_id == previous.todo_id
            && self.agent_id == previous.agent_id
            && self.token_digest == previous.token_digest
            && self.generation == previous.generation
            && self.steering_generation == previous.steering_generation
            && self.authority_digest == previous.authority_digest
            && self.claimed_at == previous.claimed_at
            && self.expires_at >= previous.expires_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum LoopContinuation {
    NextTodo(String),
    UserGate(String),
    Replan,
    NoFollowup,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoopTurnResult {
    Progress {
        evidence_ids: BTreeSet<EvidenceId>,
        continuation: LoopContinuation,
    },
    MonitorObservation {
        observation_digest: String,
    },
    NoProgress {
        reason_digest: String,
    },
    Failed {
        evidence_digest: String,
        uncertain: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopRunSummary {
    pub sequence: u64,
    pub todo_id: String,
    pub agent_id: String,
    pub evidence_digest: String,
    pub spent_slot: bool,
    pub notify: bool,
    pub continuation: Option<LoopContinuation>,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoopAction {
    RegisterPeer {
        peer: LoopPeer,
    },
    AddTodo {
        todo: LoopTodoSpec,
    },
    OpenGate {
        gate: LoopUserGate,
    },
    ResolveGate {
        gate_id: String,
        decision_digest: String,
    },
    Pause {
        paused: bool,
    },
    SetQuota {
        max_slots: u32,
    },
    /// Invalidates claims and preserves ambiguous attempts for reconciliation.
    Steer {
        rationale_digest: String,
    },
    Claim {
        host: LoopHost,
        todo_id: String,
        token_digest: String,
    },
    BeginExecution {
        claim: LoopClaim,
        host: LoopHost,
    },
    Heartbeat {
        claim: LoopClaim,
    },
    Settle {
        claim: LoopClaim,
        result: LoopTurnResult,
    },
    /// Operator attests readback proving that an abandoned slice can be retried.
    ReconcileRetry {
        todo_id: String,
        evidence_digest: String,
    },
    /// Settle already persisted work after a crash, without invoking its host.
    ReconcileSettlement {
        claim: LoopClaim,
        result: LoopTurnResult,
        readback_digest: String,
    },
    CancelTodo {
        todo_id: String,
        rationale_digest: String,
    },
    AcknowledgeNotice {
        notification_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopCommand {
    pub operation_id: String,
    pub expected_revision: u64,
    pub expected_mission_revision: u64,
    pub actor: LoopActor,
    pub action: LoopAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopReceipt {
    pub revision: u64,
    pub claim: Option<LoopClaim>,
    pub run: Option<LoopRunSummary>,
    pub replayed: bool,
}

/// Content-free Desktop projection; these counts confer no runtime authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopAccounting {
    pub revision: u64,
    pub slot_limit: u32,
    pub spent_slots: u32,
    pub reserved_slots: usize,
    pub claimed_slices: usize,
    /// Persistently marked uncertainty. Expiry and changed authority also need
    /// reconciliation; read a current LoopDecision for those live conditions.
    pub uncertain_slices: usize,
    pub open_slices: usize,
    pub open_gates: usize,
    pub paused: bool,
}

/// The caller supplies only durable Domain facts, never a model's completion
/// assessment. `steering_digest` is derived from persisted user messages.
#[derive(Clone, Copy, Debug)]
pub struct LoopMissionFacts<'a> {
    pub mission: &'a Mission,
    pub steering_digest: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MissionLoop {
    schema_version: u32,
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    policy: LoopPolicy,
    revision: u64,
    steering_generation: u64,
    claim_generation: u64,
    paused: bool,
    spent_slots: u32,
    no_progress_streak: u16,
    peers: BTreeMap<String, LoopPeer>,
    todos: BTreeMap<String, LoopTodo>,
    gates: BTreeMap<String, LoopUserGate>,
    accepted_evidence: BTreeSet<EvidenceId>,
    recent_runs: VecDeque<LoopRunSummary>,
    run_sequence: u64,
    acknowledged_notices: BTreeSet<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl MissionLoop {
    pub fn accounting(&self) -> LoopAccounting {
        LoopAccounting {
            revision: self.revision,
            slot_limit: self.policy.max_slots,
            spent_slots: self.spent_slots,
            reserved_slots: self
                .todos
                .values()
                .filter(|todo| todo.claim.is_some() && todo.spec.kind != LoopWorkKind::Monitor)
                .count(),
            claimed_slices: self
                .todos
                .values()
                .filter(|todo| todo.status == LoopTodoStatus::Claimed)
                .count(),
            uncertain_slices: self
                .todos
                .values()
                .filter(|todo| todo.status == LoopTodoStatus::Uncertain)
                .count(),
            open_slices: self
                .todos
                .values()
                .filter(|todo| todo.status == LoopTodoStatus::Open)
                .count(),
            open_gates: self.gates.len(),
            paused: self.paused || self.policy.max_slots == 0,
        }
    }

    pub fn new(
        mission: &Mission,
        policy: LoopPolicy,
        now: DateTime<Utc>,
    ) -> Result<Self, LoopError> {
        policy.validate()?;
        if mission.stage.is_terminal() || mission.contract.validate(now).is_err() {
            return Err(LoopError::MissionUnavailable);
        }
        Ok(Self {
            schema_version: LOOP_SCHEMA_VERSION,
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            policy,
            revision: 1,
            steering_generation: 1,
            claim_generation: 0,
            paused: false,
            spent_slots: 0,
            no_progress_streak: 0,
            peers: BTreeMap::new(),
            todos: BTreeMap::new(),
            gates: BTreeMap::new(),
            accepted_evidence: BTreeSet::new(),
            recent_runs: VecDeque::new(),
            run_sequence: 0,
            acknowledged_notices: BTreeSet::new(),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn spent_slots(&self) -> u32 {
        self.spent_slots
    }
    pub fn policy(&self) -> &LoopPolicy {
        &self.policy
    }
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }
    pub fn todos(&self) -> &BTreeMap<String, LoopTodo> {
        &self.todos
    }
    pub fn gates(&self) -> &BTreeMap<String, LoopUserGate> {
        &self.gates
    }
    pub fn recent_runs(&self) -> &VecDeque<LoopRunSummary> {
        &self.recent_runs
    }

    pub fn validate_for(&self, mission: &Mission) -> Result<(), LoopError> {
        self.policy.validate()?;
        if self.schema_version != LOOP_SCHEMA_VERSION
            || self.revision == 0
            || self.steering_generation == 0
            || self.updated_at < self.created_at
            || self.todos.len() > LOOP_FRONTIER_LIMIT
            || self.gates.len() > LOOP_FRONTIER_LIMIT
            || self.peers.len() > 64
            || self.recent_runs.len() > LOOP_HISTORY_LIMIT
            || self.acknowledged_notices.len() > self.peers.len()
            || self
                .acknowledged_notices
                .iter()
                .any(|notice| !digest(notice))
        {
            return Err(LoopError::InvalidState);
        }
        if self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
        {
            return Err(LoopError::ScopeMismatch);
        }
        for (id, peer) in &self.peers {
            if id != &peer.id
                || !token(id)
                || !digest(&peer.workspace_digest)
                || peer.capabilities.iter().any(|cap| !token(cap))
            {
                return Err(LoopError::InvalidState);
            }
        }
        for (id, todo) in &self.todos {
            if id != &todo.spec.id {
                return Err(LoopError::InvalidState);
            }
            self.validate_todo_spec(&todo.spec)?;
            if matches!(
                todo.status,
                LoopTodoStatus::Claimed | LoopTodoStatus::Uncertain
            ) != todo.claim.is_some()
            {
                return Err(LoopError::InvalidState);
            }
            if todo.execution_started && todo.claim.is_none() {
                return Err(LoopError::InvalidState);
            }
            if let Some(claim) = &todo.claim
                && (claim.todo_id != *id
                    || !self.peers.contains_key(&claim.agent_id)
                    || !digest(&claim.token_digest)
                    || !digest(&claim.authority_digest)
                    || claim.generation == 0
                    || claim.generation > self.claim_generation
                    || claim.steering_generation > self.steering_generation
                    || claim.expires_at <= claim.claimed_at)
            {
                return Err(LoopError::InvalidState);
            }
        }
        for (id, gate) in &self.gates {
            if id != &gate.id {
                return Err(LoopError::InvalidState);
            }
            self.validate_gate(gate)?;
        }
        Ok(())
    }
}

pub fn loop_digest(value: &impl Serialize) -> Result<String, LoopError> {
    let bytes = serde_json::to_vec(value).map_err(|_| LoopError::InvalidState)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn authority_digest(facts: LoopMissionFacts<'_>) -> Result<String, LoopError> {
    if !digest(facts.steering_digest) {
        return Err(LoopError::InvalidState);
    }
    loop_digest(&(
        &facts.mission.tenant_id,
        &facts.mission.project_id,
        &facts.mission.id,
        &facts.mission.contract,
        facts.steering_digest,
    ))
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:/".contains(&b))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn relative_scope(value: &str) -> bool {
    value == "."
        || (!value.is_empty()
            && value.len() <= 512
            && !value.contains(['\\', '\0', ':'])
            && !value.chars().any(char::is_control)
            && value
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."))
}

fn scopes_overlap(a: &str, b: &str) -> bool {
    a == "."
        || b == "."
        || a == b
        || a.starts_with(&format!("{b}/"))
        || b.starts_with(&format!("{a}/"))
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LoopError {
    #[error("invalid Mission loop policy")]
    InvalidPolicy,
    #[error("invalid or inconsistent Mission loop state")]
    InvalidState,
    #[error("Mission loop scope mismatch")]
    ScopeMismatch,
    #[error("Mission loop or Mission revision changed")]
    RevisionConflict,
    #[error("Mission cannot currently execute automatic work")]
    MissionUnavailable,
    #[error("registered peer identity is required")]
    UnknownAgent,
    #[error("this operation requires the configured operator")]
    OperatorRequired,
    #[error("actor and peer claim identity differ")]
    ActorMismatch,
    #[error("invalid, duplicate, or missing bounded work item")]
    InvalidTodo,
    #[error("invalid, duplicate, or missing concrete user gate")]
    InvalidGate,
    #[error("the bounded frontier is full")]
    FrontierFull,
    #[error("work is not currently eligible: {0:?}")]
    NotRunnable(LoopMode),
    #[error("claim is expired, replaced, or invalidated by steering")]
    ClaimLost,
    #[error("this claim has already started execution")]
    ExecutionAlreadyStarted,
    #[error("validated fresh Mission evidence is required")]
    EvidenceRequired,
    #[error("invalid continuation; referenced next work or gate must exist")]
    InvalidContinuation,
    #[error("arithmetic or timestamp overflow")]
    Overflow,
    #[error("clock moved behind durable state")]
    ClockRegression,
}

use super::{
    LoopClaim, LoopError, LoopGateScope, LoopHost, LoopMissionFacts, LoopPeer, LoopTodo,
    LoopTodoSpec, LoopTodoStatus, LoopUserGate, LoopWorkKind, Mission, MissionLoop,
    authority_digest, loop_digest, scopes_overlap,
};
use crate::{MissionStage, TaskStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopMode {
    BoundedDelivery,
    MonitorPoll,
    Repair,
    Replan,
    UserActionRequired,
    Wait,
    QuotaExhausted,
    Paused,
    ReconcileRequired,
    CapabilityUnavailable,
    WorkspaceMismatch,
    Terminal,
    ContractExpired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "at", rename_all = "snake_case")]
pub enum LoopWake {
    Now,
    At(DateTime<Utc>),
    OnStateChange,
    Stop,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopUserChannel {
    pub gate_ids: Vec<String>,
    pub notification_digest: Option<String>,
    pub notify: bool,
}

/// A read-only decision. Selection is advisory; `claim` revalidates the exact
/// chosen todo against the entire authoritative frontier in its transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoopDecision {
    pub loop_revision: u64,
    pub mission_revision: u64,
    pub mode: LoopMode,
    pub selected_todo: Option<String>,
    pub user: LoopUserChannel,
    pub wake: LoopWake,
    pub remaining_slots: u32,
    pub reserved_slots: u32,
    pub reconciliation_required: bool,
}

impl LoopDecision {
    pub fn should_run(&self) -> bool {
        self.selected_todo.is_some()
    }
    pub fn spend_after_validation(&self) -> bool {
        self.should_run() && self.mode != LoopMode::MonitorPoll
    }
}

impl MissionLoop {
    pub fn should_run(
        &self,
        facts: LoopMissionFacts<'_>,
        host: &LoopHost,
        now: DateTime<Utc>,
    ) -> Result<LoopDecision, LoopError> {
        self.decision(facts, host, None, now)
    }

    /// Allows a peer to choose any eligible item, including one outside a UI's
    /// bounded suggestions. Priority never becomes an implicit authority grant.
    pub fn decision_for_todo(
        &self,
        facts: LoopMissionFacts<'_>,
        host: &LoopHost,
        todo_id: &str,
        now: DateTime<Utc>,
    ) -> Result<LoopDecision, LoopError> {
        if !self.todos.contains_key(todo_id) {
            return Err(LoopError::InvalidTodo);
        }
        self.decision(facts, host, Some(todo_id), now)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep the ordered decision precedence and its scheduler result auditable together"
    )]
    fn decision(
        &self,
        facts: LoopMissionFacts<'_>,
        host: &LoopHost,
        selected: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<LoopDecision, LoopError> {
        self.validate_for(facts.mission)?;
        if now < self.updated_at {
            return Err(LoopError::ClockRegression);
        }
        let peer = self
            .peers
            .get(&host.agent_id)
            .ok_or(LoopError::UnknownAgent)?;
        let authority = authority_digest(facts)?;
        let claims: Vec<_> = self
            .todos
            .values()
            .filter(|todo| todo.claim.is_some())
            .collect();
        let reserved_slots = u32::try_from(
            claims
                .iter()
                .filter(|todo| todo.spec.kind != LoopWorkKind::Monitor)
                .count(),
        )
        .map_err(|_| LoopError::Overflow)?;
        let reconciliation_required = claims.iter().any(|todo| {
            todo.status == LoopTodoStatus::Uncertain
                || todo.claim.as_ref().is_some_and(|claim| {
                    claim.expires_at <= now || claim.authority_digest != authority
                })
        });
        let mut result = LoopDecision {
            loop_revision: self.revision,
            mission_revision: facts.mission.revision,
            mode: LoopMode::Wait,
            selected_todo: None,
            user: self.user_channel(&host.agent_id)?,
            wake: LoopWake::OnStateChange,
            remaining_slots: self
                .policy
                .max_slots
                .saturating_sub(self.spent_slots)
                .saturating_sub(reserved_slots),
            reserved_slots,
            reconciliation_required,
        };
        if let Some(mode) = self.hard_stop(facts.mission, now) {
            result.mode = mode;
            if mode != LoopMode::UserActionRequired {
                result.user.notify = false;
            }
            if matches!(mode, LoopMode::Terminal | LoopMode::ContractExpired) {
                result.wake = LoopWake::Stop;
            }
            return Ok(result);
        }
        if host.workspace_digest != peer.workspace_digest {
            result.mode = LoopMode::WorkspaceMismatch;
            return Ok(result);
        }
        if let Some(todo) = claims.iter().find(|todo| {
            todo.claim
                .as_ref()
                .is_some_and(|claim| claim.agent_id == host.agent_id)
        }) {
            let claim = todo.claim.as_ref().ok_or(LoopError::InvalidState)?;
            result.mode = if todo.status == LoopTodoStatus::Uncertain
                || claim.expires_at <= now
                || claim.authority_digest != authority
            {
                LoopMode::ReconcileRequired
            } else {
                result.wake = LoopWake::At(claim.expires_at);
                LoopMode::Wait
            };
            return Ok(result);
        }
        if claims.len() >= usize::from(self.policy.max_parallel) {
            result.wake = claims
                .iter()
                .filter_map(|todo| todo.claim.as_ref())
                .map(|claim| claim.expires_at)
                .filter(|at| *at > now)
                .min()
                .map_or(LoopWake::OnStateChange, LoopWake::At);
            return Ok(result);
        }
        let mut candidates: Vec<_> = self
            .todos
            .values()
            .filter(|todo| selected.is_none_or(|id| todo.spec.id == id))
            .collect();
        candidates.sort_by_key(|todo| (todo.spec.priority, &todo.spec.id));
        let mut reasons = Vec::new();
        let mut next_due = None;
        for todo in candidates {
            if todo.status != LoopTodoStatus::Open {
                continue;
            }
            if let Some(monitor) = &todo.spec.monitor {
                if now >= monitor.expires_at {
                    continue;
                }
                if now < monitor.next_due_at {
                    next_due = Some(next_due.map_or(monitor.next_due_at, |at: DateTime<Utc>| {
                        at.min(monitor.next_due_at)
                    }));
                    continue;
                }
            }
            if let Some(reason) = self.ineligible_reason(facts.mission, peer, host, todo) {
                reasons.push(reason);
                continue;
            }
            if self.no_progress_streak >= self.policy.stall_limit
                && !matches!(todo.spec.kind, LoopWorkKind::Repair | LoopWorkKind::Replan)
            {
                reasons.push(LoopMode::Repair);
                continue;
            }
            if result.remaining_slots == 0 && todo.spec.kind != LoopWorkKind::Monitor {
                reasons.push(LoopMode::QuotaExhausted);
                continue;
            }
            result.mode = match todo.spec.kind {
                LoopWorkKind::Advancement => LoopMode::BoundedDelivery,
                LoopWorkKind::Repair => LoopMode::Repair,
                LoopWorkKind::Replan => LoopMode::Replan,
                LoopWorkKind::Monitor => LoopMode::MonitorPoll,
            };
            result.selected_todo = Some(todo.spec.id.clone());
            result.wake = LoopWake::Now;
            return Ok(result);
        }
        result.mode = if reasons.contains(&LoopMode::UserActionRequired) {
            LoopMode::UserActionRequired
        } else if let Some(reason) = reasons.first() {
            *reason
        } else if next_due.is_some() || !claims.is_empty() {
            LoopMode::Wait
        } else if !result.user.gate_ids.is_empty() {
            LoopMode::UserActionRequired
        } else {
            LoopMode::Replan
        };
        result.wake = next_due.map_or(LoopWake::OnStateChange, LoopWake::At);
        Ok(result)
    }

    fn hard_stop(&self, mission: &Mission, now: DateTime<Utc>) -> Option<LoopMode> {
        if mission.stage.is_terminal() {
            return Some(LoopMode::Terminal);
        }
        if now >= mission.contract.valid_until {
            return Some(LoopMode::ContractExpired);
        }
        if self.paused || self.policy.max_slots == 0 {
            return Some(LoopMode::Paused);
        }
        if matches!(
            mission.stage,
            MissionStage::WaitingUser | MissionStage::WaitingApproval
        ) {
            return Some(LoopMode::UserActionRequired);
        }
        if !matches!(
            mission.stage,
            MissionStage::Ready | MissionStage::Running | MissionStage::Verifying
        ) || mission.contract.validate(now).is_err()
        {
            return Some(LoopMode::Wait);
        }
        None
    }

    pub(super) fn ineligible_reason(
        &self,
        mission: &Mission,
        peer: &LoopPeer,
        host: &LoopHost,
        todo: &LoopTodo,
    ) -> Option<LoopMode> {
        if !todo.spec.eligible_agents.is_empty() && !todo.spec.eligible_agents.contains(&peer.id) {
            return Some(LoopMode::Wait);
        }
        if todo.spec.depends_on.iter().any(|id| {
            self.todos
                .get(id)
                .is_none_or(|item| item.status != LoopTodoStatus::Completed)
        }) {
            return Some(LoopMode::Wait);
        }
        if self
            .gates
            .values()
            .any(|gate| gate_blocks(gate, &peer.id, &todo.spec))
        {
            return Some(LoopMode::UserActionRequired);
        }
        if todo.spec.workspace_digest != host.workspace_digest {
            return Some(LoopMode::WorkspaceMismatch);
        }
        if let Some(capability) = &todo.spec.capability
            && (!peer.capabilities.contains(capability)
                || !host.available_capabilities.contains(capability)
                || !mission.contract.enabled_capabilities.contains(capability)
                || mission.contract.forbidden_capabilities.contains(capability))
        {
            return Some(LoopMode::CapabilityUnavailable);
        }
        if let Some(id) = &todo.spec.task_id
            && !mission.tasks.iter().any(|task| {
                task.id == *id
                    && matches!(task.status, TaskStatus::Ready | TaskStatus::Running)
                    && todo.spec.capability.as_ref() == Some(&task.capability)
            })
        {
            return Some(LoopMode::Replan);
        }
        if self.todos.values().any(|other| {
            other.spec.id != todo.spec.id
                && other.claim.is_some()
                && other.spec.workspace_digest == todo.spec.workspace_digest
                && other
                    .spec
                    .write_scopes
                    .iter()
                    .any(|a| todo.spec.write_scopes.iter().any(|b| scopes_overlap(a, b)))
        }) {
            return Some(LoopMode::Wait);
        }
        None
    }

    pub(super) fn user_channel(&self, agent: &str) -> Result<LoopUserChannel, LoopError> {
        let gates: Vec<_> = self
            .gates
            .values()
            .filter(|gate| match &gate.scope {
                LoopGateScope::Agent(id) => id == agent,
                LoopGateScope::Todo(id) => self.todos.get(id).is_some_and(|todo| {
                    todo.spec.eligible_agents.is_empty()
                        || todo.spec.eligible_agents.contains(agent)
                }),
                LoopGateScope::Mission | LoopGateScope::Decision(_) => true,
            })
            .collect();
        let notification_digest = if gates.is_empty() {
            None
        } else {
            Some(loop_digest(&gates)?)
        };
        Ok(LoopUserChannel {
            gate_ids: gates.iter().map(|gate| gate.id.clone()).collect(),
            notify: notification_digest
                .as_ref()
                .is_some_and(|digest| !self.acknowledged_notices.contains(digest)),
            notification_digest,
        })
    }

    /// Rechecked immediately before dispatch/heartbeat/settlement. New gates,
    /// pause, capability withdrawal and user steering invalidate old permission.
    pub fn require_claim(
        &self,
        facts: LoopMissionFacts<'_>,
        claim: &LoopClaim,
        now: DateTime<Utc>,
    ) -> Result<(), LoopError> {
        self.validate_for(facts.mission)?;
        let todo = self.todos.get(&claim.todo_id).ok_or(LoopError::ClaimLost)?;
        if todo.status != LoopTodoStatus::Claimed
            || todo.claim.as_ref() != Some(claim)
            || claim.expires_at <= now
            || now < self.updated_at
            || now < claim.claimed_at
            || claim.steering_generation != self.steering_generation
            || claim.authority_digest != authority_digest(facts)?
            || self.hard_stop(facts.mission, now).is_some()
            || self
                .gates
                .values()
                .any(|gate| gate_blocks(gate, &claim.agent_id, &todo.spec))
        {
            return Err(LoopError::ClaimLost);
        }
        Ok(())
    }

    /// Model steps additionally require that the bound Task still accepts work.
    /// Settlement may record already finished evidence after a Task advances.
    pub fn require_execution(
        &self,
        facts: LoopMissionFacts<'_>,
        claim: &LoopClaim,
        now: DateTime<Utc>,
    ) -> Result<(), LoopError> {
        self.require_claim(facts, claim, now)?;
        let todo = self.todos.get(&claim.todo_id).ok_or(LoopError::ClaimLost)?;
        if !todo.execution_started
            || todo.spec.task_id.as_ref().is_some_and(|id| {
                !facts.mission.tasks.iter().any(|task| {
                    task.id == *id
                        && matches!(task.status, TaskStatus::Ready | TaskStatus::Running)
                        && todo.spec.capability.as_ref() == Some(&task.capability)
                })
            })
        {
            return Err(LoopError::ClaimLost);
        }
        Ok(())
    }
}

fn gate_blocks(gate: &LoopUserGate, agent: &str, todo: &LoopTodoSpec) -> bool {
    match &gate.scope {
        LoopGateScope::Mission => true,
        LoopGateScope::Agent(id) => id == agent,
        LoopGateScope::Todo(id) => id == &todo.id,
        LoopGateScope::Decision(scope) => todo
            .required_decisions
            .iter()
            .any(|required| required == scope || required.starts_with(&format!("{scope}:"))),
    }
}

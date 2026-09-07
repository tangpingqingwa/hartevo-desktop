use super::{
    LOOP_FRONTIER_LIMIT, LOOP_HISTORY_LIMIT, LoopAction, LoopActor, LoopClaim, LoopCommand,
    LoopContinuation, LoopError, LoopGateScope, LoopMissionFacts, LoopMode, LoopReceipt,
    LoopRunSummary, LoopTodo, LoopTodoSpec, LoopTodoStatus, LoopTurnResult, LoopUserGate,
    LoopWorkKind, Mission, MissionLoop, authority_digest, digest, loop_digest, relative_scope,
    token,
};
use crate::EvidenceStatus;
use chrono::Duration;
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;

impl MissionLoop {
    /// A failed command leaves the complete aggregate unchanged. Persistent
    /// command replay is handled by Storage's transactional operation ledger.
    pub fn apply(
        &mut self,
        facts: LoopMissionFacts<'_>,
        command: &LoopCommand,
        now: DateTime<Utc>,
    ) -> Result<LoopReceipt, LoopError> {
        self.validate_for(facts.mission)?;
        if !token(&command.operation_id) {
            return Err(LoopError::InvalidState);
        }
        if command.expected_revision != self.revision
            || command.expected_mission_revision != facts.mission.revision
        {
            return Err(LoopError::RevisionConflict);
        }
        if now < self.updated_at {
            return Err(LoopError::ClockRegression);
        }
        self.validate_actor(&command.actor)?;
        let mut next = self.clone();
        let mut receipt = LoopReceipt {
            revision: self.revision.checked_add(1).ok_or(LoopError::Overflow)?,
            claim: None,
            run: None,
            replayed: false,
        };
        next.transition(facts, &command.actor, &command.action, &mut receipt, now)?;
        next.revision = receipt.revision;
        next.updated_at = now;
        next.validate_for(facts.mission)?;
        *self = next;
        Ok(receipt)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one exhaustive command table makes operator and peer authority boundaries explicit"
    )]
    fn transition(
        &mut self,
        facts: LoopMissionFacts<'_>,
        actor: &LoopActor,
        action: &LoopAction,
        receipt: &mut LoopReceipt,
        now: DateTime<Utc>,
    ) -> Result<(), LoopError> {
        match action {
            LoopAction::RegisterPeer { peer } => {
                self.require_operator(actor)?;
                if self.peers.len() >= 64 {
                    return Err(LoopError::FrontierFull);
                }
                if !token(&peer.id)
                    || !digest(&peer.workspace_digest)
                    || peer.capabilities.iter().any(|cap| !token(cap))
                    || self.peers.contains_key(&peer.id)
                {
                    return Err(LoopError::InvalidState);
                }
                self.peers.insert(peer.id.clone(), peer.clone());
            }
            LoopAction::AddTodo { todo } => {
                if self.todos.len() >= LOOP_FRONTIER_LIMIT {
                    return Err(LoopError::FrontierFull);
                }
                if self.todos.contains_key(&todo.id) {
                    return Err(LoopError::InvalidTodo);
                }
                self.validate_todo_spec(todo)?;
                Self::validate_task_binding(todo, facts.mission)?;
                self.todos.insert(
                    todo.id.clone(),
                    LoopTodo {
                        spec: todo.clone(),
                        status: LoopTodoStatus::Open,
                        claim: None,
                        execution_started: false,
                        last_observation_digest: None,
                    },
                );
            }
            LoopAction::OpenGate { gate } => {
                if self.gates.len() >= LOOP_FRONTIER_LIMIT {
                    return Err(LoopError::FrontierFull);
                }
                self.validate_gate(gate)?;
                if self.gates.contains_key(&gate.id) {
                    return Err(LoopError::InvalidGate);
                }
                if let LoopActor::Agent(agent) = actor {
                    match &gate.scope {
                        LoopGateScope::Mission => return Err(LoopError::OperatorRequired),
                        LoopGateScope::Agent(id) if id != agent => {
                            return Err(LoopError::ActorMismatch);
                        }
                        _ => {}
                    }
                }
                self.gates.insert(gate.id.clone(), gate.clone());
                self.prune_notice_acknowledgements()?;
            }
            LoopAction::ResolveGate {
                gate_id,
                decision_digest,
            } => {
                self.require_operator(actor)?;
                if !digest(decision_digest) || self.gates.remove(gate_id).is_none() {
                    return Err(LoopError::InvalidGate);
                }
                self.prune_notice_acknowledgements()?;
            }
            LoopAction::Pause { paused } => {
                self.require_operator(actor)?;
                self.paused = *paused;
                if *paused {
                    self.invalidate_claims()?;
                }
            }
            LoopAction::SetQuota { max_slots } => {
                self.require_operator(actor)?;
                if *max_slots < self.policy.max_slots {
                    self.invalidate_claims()?;
                }
                self.policy.max_slots = *max_slots;
            }
            LoopAction::Steer { rationale_digest } => {
                self.require_operator(actor)?;
                if !digest(rationale_digest) {
                    return Err(LoopError::InvalidState);
                }
                self.invalidate_claims()?;
            }
            LoopAction::Claim {
                host,
                todo_id,
                token_digest,
            } => {
                require_agent(actor, &host.agent_id)?;
                if !digest(token_digest) {
                    return Err(LoopError::InvalidState);
                }
                let decision = self.decision_for_todo(facts, host, todo_id, now)?;
                if decision.selected_todo.as_ref() != Some(todo_id) {
                    return Err(LoopError::NotRunnable(decision.mode));
                }
                self.claim_generation = self
                    .claim_generation
                    .checked_add(1)
                    .ok_or(LoopError::Overflow)?;
                let todo = self.todos.get_mut(todo_id).ok_or(LoopError::InvalidTodo)?;
                let mut expires_at = now
                    .checked_add_signed(Duration::seconds(i64::from(self.policy.lease_seconds)))
                    .ok_or(LoopError::Overflow)?
                    .min(facts.mission.contract.valid_until);
                if let Some(monitor) = &todo.spec.monitor {
                    expires_at = expires_at.min(monitor.expires_at);
                }
                let claim = LoopClaim {
                    todo_id: todo_id.clone(),
                    agent_id: host.agent_id.clone(),
                    token_digest: token_digest.clone(),
                    generation: self.claim_generation,
                    steering_generation: self.steering_generation,
                    authority_digest: authority_digest(facts)?,
                    claimed_at: now,
                    expires_at,
                };
                todo.status = LoopTodoStatus::Claimed;
                todo.claim = Some(claim.clone());
                todo.execution_started = false;
                receipt.claim = Some(claim);
            }
            LoopAction::BeginExecution { claim, host } => {
                require_agent(actor, &claim.agent_id)?;
                if host.agent_id != claim.agent_id {
                    return Err(LoopError::ActorMismatch);
                }
                self.require_claim(facts, claim, now)?;
                let peer = self
                    .peers
                    .get(&claim.agent_id)
                    .ok_or(LoopError::UnknownAgent)?;
                if host.workspace_digest != peer.workspace_digest {
                    return Err(LoopError::NotRunnable(LoopMode::WorkspaceMismatch));
                }
                let todo = self.todos.get(&claim.todo_id).ok_or(LoopError::ClaimLost)?;
                if todo.execution_started {
                    return Err(LoopError::ExecutionAlreadyStarted);
                }
                if let Some(reason) = self.ineligible_reason(facts.mission, peer, host, todo) {
                    return Err(LoopError::NotRunnable(reason));
                }
                self.todos
                    .get_mut(&claim.todo_id)
                    .ok_or(LoopError::ClaimLost)?
                    .execution_started = true;
                receipt.claim = Some(claim.clone());
            }
            LoopAction::Heartbeat { claim } => {
                require_agent(actor, &claim.agent_id)?;
                self.require_claim(facts, claim, now)?;
                let todo = self
                    .todos
                    .get_mut(&claim.todo_id)
                    .ok_or(LoopError::ClaimLost)?;
                let mut renewed = claim.clone();
                renewed.expires_at = now
                    .checked_add_signed(Duration::seconds(i64::from(self.policy.lease_seconds)))
                    .ok_or(LoopError::Overflow)?
                    .min(facts.mission.contract.valid_until);
                if let Some(monitor) = &todo.spec.monitor {
                    renewed.expires_at = renewed.expires_at.min(monitor.expires_at);
                }
                todo.claim = Some(renewed.clone());
                receipt.claim = Some(renewed);
            }
            LoopAction::Settle { claim, result } => {
                require_agent(actor, &claim.agent_id)?;
                receipt.run = Some(self.settle(facts, claim, result, false, now)?);
            }
            LoopAction::ReconcileSettlement {
                claim,
                result,
                readback_digest,
            } => {
                self.require_operator(actor)?;
                if !digest(readback_digest) {
                    return Err(LoopError::EvidenceRequired);
                }
                if claim.steering_generation != self.steering_generation
                    || claim.authority_digest != authority_digest(facts)?
                {
                    return Err(LoopError::ClaimLost);
                }
                receipt.run = Some(self.settle(facts, claim, result, true, now)?);
            }
            LoopAction::ReconcileRetry {
                todo_id,
                evidence_digest,
            } => {
                self.require_operator(actor)?;
                if !digest(evidence_digest) {
                    return Err(LoopError::EvidenceRequired);
                }
                let todo = self.todos.get_mut(todo_id).ok_or(LoopError::InvalidTodo)?;
                let claim = todo.claim.as_ref().ok_or(LoopError::ClaimLost)?;
                if todo.status != LoopTodoStatus::Uncertain
                    && claim.expires_at > now
                    && claim.authority_digest == authority_digest(facts)?
                {
                    return Err(LoopError::ClaimLost);
                }
                todo.claim = None;
                todo.execution_started = false;
                todo.status = LoopTodoStatus::Open;
            }
            LoopAction::CancelTodo {
                todo_id,
                rationale_digest,
            } => {
                self.require_operator(actor)?;
                if !digest(rationale_digest) {
                    return Err(LoopError::InvalidState);
                }
                let todo = self.todos.get_mut(todo_id).ok_or(LoopError::InvalidTodo)?;
                if todo.status != LoopTodoStatus::Open || todo.claim.is_some() {
                    return Err(LoopError::ClaimLost);
                }
                todo.status = LoopTodoStatus::Cancelled;
            }
            LoopAction::AcknowledgeNotice {
                notification_digest,
            } => {
                if !digest(notification_digest) {
                    return Err(LoopError::InvalidState);
                }
                let known = match actor {
                    LoopActor::Agent(agent) => {
                        self.user_channel(agent)?.notification_digest.as_ref()
                            == Some(notification_digest)
                    }
                    LoopActor::Operator(_) => self.peers.keys().any(|agent| {
                        self.user_channel(agent).is_ok_and(|channel| {
                            channel.notification_digest.as_ref() == Some(notification_digest)
                        })
                    }),
                };
                if !known {
                    return Err(LoopError::InvalidGate);
                }
                self.acknowledged_notices
                    .insert(notification_digest.clone());
            }
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "each typed outcome binds claim, evidence, accounting, history and continuation atomically"
    )]
    fn settle(
        &mut self,
        facts: LoopMissionFacts<'_>,
        claim: &LoopClaim,
        result: &LoopTurnResult,
        reconciled: bool,
        now: DateTime<Utc>,
    ) -> Result<LoopRunSummary, LoopError> {
        // Ambiguous failure can still be recorded after revocation. It cannot
        // release a reservation or authorize another execution.
        if reconciled
            || matches!(
                result,
                LoopTurnResult::Failed {
                    uncertain: true,
                    ..
                }
            )
        {
            if self
                .todos
                .get(&claim.todo_id)
                .and_then(|todo| todo.claim.as_ref())
                != Some(claim)
            {
                return Err(LoopError::ClaimLost);
            }
        } else {
            self.require_claim(facts, claim, now)?;
        }
        let mut todo = self
            .todos
            .get(&claim.todo_id)
            .cloned()
            .ok_or(LoopError::ClaimLost)?;
        if !todo.execution_started && !matches!(result, LoopTurnResult::Failed { .. }) {
            return Err(LoopError::ClaimLost);
        }
        let sequence = self
            .run_sequence
            .checked_add(1)
            .ok_or(LoopError::Overflow)?;
        let mut run = LoopRunSummary {
            sequence,
            todo_id: claim.todo_id.clone(),
            agent_id: claim.agent_id.clone(),
            evidence_digest: String::new(),
            spent_slot: false,
            notify: false,
            continuation: None,
            recorded_at: now,
        };
        match result {
            LoopTurnResult::Progress {
                evidence_ids,
                continuation,
            } => {
                if todo.spec.kind == LoopWorkKind::Monitor {
                    return Err(LoopError::InvalidState);
                }
                self.validate_continuation(&todo.spec.id, continuation)?;
                if evidence_ids.is_empty() {
                    return Err(LoopError::EvidenceRequired);
                }
                let mut evidence = Vec::new();
                for id in evidence_ids {
                    let item = facts
                        .mission
                        .evidence
                        .iter()
                        .find(|item| item.id == *id)
                        .ok_or(LoopError::EvidenceRequired)?;
                    if item.status != EvidenceStatus::Confirmed
                        || self.accepted_evidence.contains(id)
                        || item.observed_at < claim.claimed_at
                        || item.observed_at > now
                        || !digest(&item.content_digest)
                    {
                        return Err(LoopError::EvidenceRequired);
                    }
                    evidence.push((&item.id, &item.content_digest, item.observed_at));
                }
                run.evidence_digest = loop_digest(&evidence)?;
                run.spent_slot = true;
                run.notify = true;
                run.continuation = Some(continuation.clone());
                self.spent_slots = self.spent_slots.checked_add(1).ok_or(LoopError::Overflow)?;
                self.accepted_evidence.extend(evidence_ids.iter().cloned());
                self.no_progress_streak = 0;
                todo.status = LoopTodoStatus::Completed;
            }
            LoopTurnResult::MonitorObservation { observation_digest } => {
                if !digest(observation_digest) {
                    return Err(LoopError::InvalidState);
                }
                let monitor = todo.spec.monitor.as_mut().ok_or(LoopError::InvalidState)?;
                run.evidence_digest.clone_from(observation_digest);
                run.notify = todo
                    .last_observation_digest
                    .as_ref()
                    .is_some_and(|previous| previous != observation_digest);
                todo.last_observation_digest = Some(observation_digest.clone());
                let interval = i64::from(monitor.interval_seconds);
                let elapsed = (now - monitor.next_due_at).num_seconds().max(0);
                let advance = (elapsed / interval)
                    .checked_add(1)
                    .and_then(|ticks| ticks.checked_mul(interval))
                    .ok_or(LoopError::Overflow)?;
                monitor.next_due_at = monitor
                    .next_due_at
                    .checked_add_signed(Duration::seconds(advance))
                    .ok_or(LoopError::Overflow)?;
                todo.status = if monitor.next_due_at >= monitor.expires_at {
                    LoopTodoStatus::Completed
                } else {
                    LoopTodoStatus::Open
                };
            }
            LoopTurnResult::NoProgress { reason_digest } => {
                if !digest(reason_digest) || todo.spec.kind == LoopWorkKind::Monitor {
                    return Err(LoopError::InvalidState);
                }
                run.evidence_digest.clone_from(reason_digest);
                self.no_progress_streak = self.no_progress_streak.saturating_add(1);
                todo.status = LoopTodoStatus::Open;
            }
            LoopTurnResult::Failed {
                evidence_digest,
                uncertain,
            } => {
                if !digest(evidence_digest) {
                    return Err(LoopError::InvalidState);
                }
                run.evidence_digest.clone_from(evidence_digest);
                run.notify = true;
                self.no_progress_streak = self.no_progress_streak.saturating_add(1);
                todo.status = if *uncertain {
                    LoopTodoStatus::Uncertain
                } else {
                    LoopTodoStatus::Open
                };
            }
        }
        if todo.status != LoopTodoStatus::Uncertain {
            todo.claim = None;
            todo.execution_started = false;
        }
        self.todos.insert(todo.spec.id.clone(), todo);
        self.run_sequence = sequence;
        self.recent_runs.push_back(run.clone());
        while self.recent_runs.len() > LOOP_HISTORY_LIMIT {
            self.recent_runs.pop_front();
        }
        Ok(run)
    }

    fn validate_continuation(
        &self,
        current: &str,
        continuation: &LoopContinuation,
    ) -> Result<(), LoopError> {
        match continuation {
            LoopContinuation::NextTodo(id)
                if id == current
                    || self.todos.get(id).is_none_or(|todo| {
                        !matches!(todo.status, LoopTodoStatus::Open | LoopTodoStatus::Claimed)
                    }) =>
            {
                Err(LoopError::InvalidContinuation)
            }
            LoopContinuation::UserGate(id) if !self.gates.contains_key(id) => {
                Err(LoopError::InvalidContinuation)
            }
            _ => Ok(()),
        }
    }

    pub(super) fn validate_todo_spec(&self, todo: &LoopTodoSpec) -> Result<(), LoopError> {
        if !token(&todo.id)
            || todo.title.trim().is_empty()
            || todo.title.len() > 4096
            || !digest(&todo.workspace_digest)
            || todo.capability.as_ref().is_some_and(|cap| !token(cap))
            || todo.write_scopes.iter().any(|scope| !relative_scope(scope))
            || todo.required_decisions.iter().any(|scope| !token(scope))
            || todo.depends_on.contains(&todo.id)
            || todo
                .depends_on
                .iter()
                .any(|id| !self.todos.contains_key(id))
            || todo
                .eligible_agents
                .iter()
                .any(|id| !self.peers.contains_key(id))
            || (todo.kind == LoopWorkKind::Monitor) != todo.monitor.is_some()
            || (matches!(todo.kind, LoopWorkKind::Advancement | LoopWorkKind::Monitor)
                && (todo.task_id.is_none() || todo.capability.is_none()))
            || (todo.task_id.is_some() != todo.capability.is_some())
        {
            return Err(LoopError::InvalidTodo);
        }
        if let Some(monitor) = &todo.monitor
            && (!digest(&monitor.target_digest)
                || !(1..=2_592_000).contains(&monitor.interval_seconds)
                || monitor.expires_at <= self.created_at
                || !todo.write_scopes.is_empty())
        {
            return Err(LoopError::InvalidTodo);
        }
        Ok(())
    }

    fn validate_task_binding(todo: &LoopTodoSpec, mission: &Mission) -> Result<(), LoopError> {
        if let Some(id) = &todo.task_id
            && (!mission
                .tasks
                .iter()
                .any(|task| task.id == *id && todo.capability.as_ref() == Some(&task.capability))
                || todo.capability.as_ref().is_none_or(|cap| {
                    !mission.contract.enabled_capabilities.contains(cap)
                        || mission.contract.forbidden_capabilities.contains(cap)
                }))
        {
            return Err(LoopError::InvalidTodo);
        }
        Ok(())
    }

    pub(super) fn validate_gate(&self, gate: &LoopUserGate) -> Result<(), LoopError> {
        if !token(&gate.id) || gate.question.trim().is_empty() || gate.question.len() > 4096 {
            return Err(LoopError::InvalidGate);
        }
        match &gate.scope {
            LoopGateScope::Agent(id) if !self.peers.contains_key(id) => Err(LoopError::InvalidGate),
            LoopGateScope::Todo(id) if !self.todos.contains_key(id) => Err(LoopError::InvalidGate),
            LoopGateScope::Decision(id) if !token(id) => Err(LoopError::InvalidGate),
            _ => Ok(()),
        }
    }

    fn validate_actor(&self, actor: &LoopActor) -> Result<(), LoopError> {
        match actor {
            LoopActor::Operator(_) => self.require_operator(actor),
            LoopActor::Agent(id) if self.peers.contains_key(id) => Ok(()),
            LoopActor::Agent(_) => Err(LoopError::UnknownAgent),
        }
    }

    fn prune_notice_acknowledgements(&mut self) -> Result<(), LoopError> {
        let mut current = BTreeSet::new();
        for agent in self.peers.keys() {
            if let Some(digest) = self.user_channel(agent)?.notification_digest {
                current.insert(digest);
            }
        }
        self.acknowledged_notices
            .retain(|digest| current.contains(digest));
        Ok(())
    }

    fn require_operator(&self, actor: &LoopActor) -> Result<(), LoopError> {
        if *actor == LoopActor::Operator(self.policy.operator_id.clone()) {
            Ok(())
        } else {
            Err(LoopError::OperatorRequired)
        }
    }

    fn invalidate_claims(&mut self) -> Result<(), LoopError> {
        self.steering_generation = self
            .steering_generation
            .checked_add(1)
            .ok_or(LoopError::Overflow)?;
        for todo in self.todos.values_mut().filter(|todo| todo.claim.is_some()) {
            todo.status = LoopTodoStatus::Uncertain;
        }
        Ok(())
    }
}

fn require_agent(actor: &LoopActor, agent: &str) -> Result<(), LoopError> {
    if *actor == LoopActor::Agent(agent.to_owned()) {
        Ok(())
    } else {
        Err(LoopError::ActorMismatch)
    }
}

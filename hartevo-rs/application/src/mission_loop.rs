//! Application seam for bounded, durable Mission loops. The supplied runner
//! uses the existing Cordis/runtime/Capability services; this is not a model
//! loop, tool executor or alternate business-state store.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::mission_loop::{
    LoopAction, LoopActor, LoopClaim, LoopCommand, LoopDecision, LoopError, LoopHost, LoopPolicy,
    LoopReceipt, LoopRunSummary, LoopTodoSpec, LoopTurnResult, LoopUserGate, MissionLoop,
    loop_digest,
};
use hartevo_domain_kernel::{MissionId, ProjectId};
use hartevo_storage::{MissionLoopSnapshot, StorageError};
use thiserror::Error;

use crate::ApplicationService;

#[path = "mission_loop_cordis.rs"]
mod cordis;
pub use cordis::{MissionLoopCordisBinding, bind_cordis_mission_loop_guard};

#[cfg(test)]
#[path = "mission_loop_tests.rs"]
mod tests;

#[derive(Clone, Debug)]
pub struct RunMissionLoopSlice {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub operation_id: String,
    pub host: LoopHost,
    /// Omit to accept the deterministic priority suggestion.
    pub todo_id: Option<String>,
}

/// Private handoff to a runtime, reconstructed from current durable facts.
/// Callers must use existing scoped Application/Effect Broker authorization.
#[derive(Clone)]
pub struct MissionLoopHandoff {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub objective: String,
    pub non_goals: Vec<String>,
    pub todo: LoopTodoSpec,
    pub user_gates: Vec<LoopUserGate>,
    pub recent_runs: Vec<LoopRunSummary>,
    pub claim: LoopClaim,
}

impl fmt::Debug for MissionLoopHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MissionLoopHandoff")
            .field("mission_revision", &self.mission_revision)
            .field("kind", &self.todo.kind)
            .finish_non_exhaustive()
    }
}

/// Runtime failures carry bounded diagnostic identity, never raw model text.
#[derive(Debug)]
pub struct MissionLoopRunnerFailure {
    pub code: &'static str,
}

#[derive(Debug, Error)]
pub enum MissionLoopApplicationError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Domain(#[from] LoopError),
    #[error("the Mission has no configured long-running loop")]
    NotConfigured,
    #[error("the Mission has no runnable slice: {0:?}")]
    Deferred(Box<LoopDecision>),
    #[error("a committed dispatch must be reconciled; execution replay is suppressed")]
    ExecutionReplaySuppressed,
}

impl ApplicationService {
    pub fn configure_mission_loop(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        policy: LoopPolicy,
        expected_mission_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<MissionLoop, MissionLoopApplicationError> {
        Ok(self.store.create_mission_loop(
            project_id,
            mission_id,
            policy,
            expected_mission_revision,
            now,
        )?)
    }

    pub fn mission_loop_snapshot(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<Option<MissionLoopSnapshot>, MissionLoopApplicationError> {
        Ok(self
            .store
            .mission_loop_snapshot(project_id, mission_id, now)?)
    }

    pub fn mission_loop_decision(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        host: &LoopHost,
        now: DateTime<Utc>,
    ) -> Result<LoopDecision, MissionLoopApplicationError> {
        let snapshot = self.require_loop_snapshot(project_id, mission_id, now)?;
        Ok(snapshot.state.should_run(snapshot.facts(), host, now)?)
    }

    /// Called by a trusted operator/registered-peer adapter. An Agent cannot
    /// resolve gates, change quota, pause, register peers or attest safe replay.
    pub fn apply_mission_loop_command(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        command: &LoopCommand,
        now: DateTime<Utc>,
    ) -> Result<LoopReceipt, MissionLoopApplicationError> {
        Ok(self
            .store
            .apply_mission_loop_command(project_id, mission_id, command, now)?)
    }

    pub fn mission_loop_handoff(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        claim: &LoopClaim,
        now: DateTime<Utc>,
    ) -> Result<MissionLoopHandoff, MissionLoopApplicationError> {
        let snapshot = self.require_loop_snapshot(project_id, mission_id, now)?;
        snapshot.state.require_claim(snapshot.facts(), claim, now)?;
        let todo = snapshot
            .state
            .todos()
            .get(&claim.todo_id)
            .ok_or(LoopError::ClaimLost)?;
        if todo.execution_started {
            snapshot
                .state
                .require_execution(snapshot.facts(), claim, now)?;
        }
        let handoff = MissionLoopHandoff {
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            mission_revision: snapshot.mission.revision,
            objective: snapshot.mission.contract.goal.clone(),
            non_goals: snapshot.mission.contract.non_goals.clone(),
            todo: todo.spec.clone(),
            user_gates: snapshot.state.gates().values().cloned().collect(),
            recent_runs: snapshot.state.recent_runs().iter().cloned().collect(),
            claim: claim.clone(),
        };
        Ok(handoff)
    }

    /// One bounded host invocation: decide -> durable claim -> durable dispatch
    /// marker -> runtime -> validated writeback+spend. No-progress and monitor
    /// observations never spend a slot. A crash leaves a claim to reconcile.
    ///
    /// The callback may use existing Application APIs to persist evidence and
    /// work products. Its result must reference that confirmed Mission evidence;
    /// model output or a provider receipt alone cannot settle progress.
    pub fn run_mission_loop_slice<R, C>(
        &mut self,
        request: &RunMissionLoopSlice,
        clock: C,
        runner: R,
    ) -> Result<LoopReceipt, MissionLoopApplicationError>
    where
        R: FnOnce(
            &mut Self,
            &MissionLoopHandoff,
        ) -> Result<LoopTurnResult, MissionLoopRunnerFailure>,
        C: Fn() -> DateTime<Utc>,
    {
        let started_at = clock();
        let snapshot =
            self.require_loop_snapshot(&request.project_id, &request.mission_id, started_at)?;
        let decision = if let Some(todo) = &request.todo_id {
            snapshot
                .state
                .decision_for_todo(snapshot.facts(), &request.host, todo, started_at)?
        } else {
            snapshot
                .state
                .should_run(snapshot.facts(), &request.host, started_at)?
        };
        let todo_id = decision
            .selected_todo
            .clone()
            .ok_or_else(|| MissionLoopApplicationError::Deferred(Box::new(decision)))?;
        let claim_command = LoopCommand {
            operation_id: format!("{}/claim", request.operation_id),
            expected_revision: snapshot.state.revision(),
            expected_mission_revision: snapshot.mission.revision,
            actor: LoopActor::Agent(request.host.agent_id.clone()),
            action: LoopAction::Claim {
                host: request.host.clone(),
                todo_id,
                token_digest: loop_digest(&(
                    &request.operation_id,
                    &request.project_id,
                    &request.mission_id,
                    snapshot.state.revision(),
                ))?,
            },
        };
        let receipt = self.apply_mission_loop_command(
            &request.project_id,
            &request.mission_id,
            &claim_command,
            started_at,
        )?;
        if receipt.replayed {
            return Err(MissionLoopApplicationError::ExecutionReplaySuppressed);
        }
        let claim = receipt.claim.ok_or(LoopError::ClaimLost)?;
        let mut handoff =
            self.mission_loop_handoff(&request.project_id, &request.mission_id, &claim, clock())?;
        let dispatch_command = LoopCommand {
            operation_id: format!("{}/dispatch", request.operation_id),
            expected_revision: receipt.revision,
            expected_mission_revision: handoff.mission_revision,
            actor: LoopActor::Agent(request.host.agent_id.clone()),
            action: LoopAction::BeginExecution {
                claim: claim.clone(),
                host: request.host.clone(),
            },
        };
        let dispatch = self.apply_mission_loop_command(
            &request.project_id,
            &request.mission_id,
            &dispatch_command,
            clock(),
        )?;
        if dispatch.replayed {
            return Err(MissionLoopApplicationError::ExecutionReplaySuppressed);
        }
        // Re-read authority after dispatch persistence and before the host body.
        handoff =
            self.mission_loop_handoff(&request.project_id, &request.mission_id, &claim, clock())?;
        let result = match catch_unwind(AssertUnwindSafe(|| runner(self, &handoff))) {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => LoopTurnResult::Failed {
                evidence_digest: loop_digest(&error.code)?,
                uncertain: true,
            },
            Err(_) => LoopTurnResult::Failed {
                evidence_digest: loop_digest(&"runtime_panicked")?,
                uncertain: true,
            },
        };
        let finished_at = clock();
        let latest =
            self.require_loop_snapshot(&request.project_id, &request.mission_id, finished_at)?;
        // A host may have renewed its lease while running. Only follow that
        // exact execution; a replacement claim can never settle this result.
        let claim = latest
            .state
            .todos()
            .get(&claim.todo_id)
            .and_then(|todo| todo.claim.as_ref())
            .filter(|current| current.is_renewal_of(&claim))
            .cloned()
            .ok_or(LoopError::ClaimLost)?;
        let command = LoopCommand {
            operation_id: format!("{}/settle", request.operation_id),
            expected_revision: latest.state.revision(),
            expected_mission_revision: latest.mission.revision,
            actor: LoopActor::Agent(request.host.agent_id.clone()),
            action: LoopAction::Settle { claim, result },
        };
        self.apply_mission_loop_command(
            &request.project_id,
            &request.mission_id,
            &command,
            finished_at,
        )
    }

    fn require_loop_snapshot(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<MissionLoopSnapshot, MissionLoopApplicationError> {
        self.mission_loop_snapshot(project_id, mission_id, now)?
            .ok_or(MissionLoopApplicationError::NotConfigured)
    }
}

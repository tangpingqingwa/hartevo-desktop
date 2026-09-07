use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use hartevo_cordis::{Context, CordisError, ListenerHandle, events};
use hartevo_domain_kernel::mission_loop::LoopClaim;
use hartevo_domain_kernel::{MissionId, ProjectId};
use hartevo_storage::ProjectStore;

#[derive(Clone, Debug)]
pub struct MissionLoopCordisBinding {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    /// Exact live Cordis Agent id; the peer identity is bound by `claim`.
    pub runtime_agent_id: String,
    pub claim: LoopClaim,
}

/// Mount in the bound Agent's Cordis lifecycle before starting its turn. Every
/// `agent/pre-step` re-reads SQLCipher, so pause, steering, gate changes, expired
/// claims, or a failed read reject the next model step. Other Agents keep their
/// own lifecycle. This guard grants neither consent nor Effect approval.
///
/// Use a dedicated connection to the same encrypted database for the reader.
/// The mutex is acquired without waiting to avoid reentrant runtime deadlocks.
pub fn bind_cordis_mission_loop_guard<C>(
    context: &mut Context,
    binding: MissionLoopCordisBinding,
    reader: Arc<Mutex<ProjectStore>>,
    clock: C,
) -> Result<ListenerHandle, CordisError>
where
    C: Fn() -> DateTime<Utc> + Send + Sync + 'static,
{
    context.on_waterfall(events::AGENT_PRE_STEP, move |proposal, next| {
        if proposal.agent().id != binding.runtime_agent_id {
            return next(proposal);
        }
        let at = clock();
        let permitted = reader
            .try_lock()
            .ok()
            .and_then(|store| {
                store
                    .mission_loop_snapshot(&binding.project_id, &binding.mission_id, at)
                    .ok()
                    .flatten()
            })
            .is_some_and(|snapshot| {
                snapshot
                    .state
                    .todos()
                    .get(&binding.claim.todo_id)
                    .and_then(|todo| todo.claim.as_ref())
                    .filter(|current| current.is_renewal_of(&binding.claim))
                    .is_some_and(|current| {
                        snapshot
                            .state
                            .require_execution(snapshot.facts(), current, at)
                            .is_ok()
                    })
            });
        if permitted {
            next(proposal)
        } else {
            proposal.reject()
        }
    })
}

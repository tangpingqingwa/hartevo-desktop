use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ContextBranch, ContextBranchMerge, ContextBranchMergeId, ContextCapsule,
    ContextWorkerMailboxId, ContextWorkerMessage, ContextWorkspaceId, ContinuationLedger,
    MissionId, ProjectId, RuntimeRecoveryAttempt, RuntimeRecoveryStatus, RuntimeTurnAttempt,
    RuntimeTurnStatus, WorkerHandle, WorkerId, WorkerLease, WorkerMailbox,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::context_store::{update_context_capsule_row, update_worker_lease_row};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    /// Atomically fences a complete Context generation even when coordinator
    /// failure happened before a Runtime turn ledger could be inserted. The
    /// caller must resolve the exact Mission/generation; this transaction
    /// independently revalidates every linked authority aggregate and its
    /// mailbox before committing the terminal projection.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the no-turn fencing transaction must bind every independently versioned authority aggregate"
    )]
    pub fn retire_context_generation_authority(
        &mut self,
        mission_id: &MissionId,
        generation: u64,
        branch: &ContextBranch,
        expected_branch_revision: u64,
        lease: &WorkerLease,
        expected_lease_revision: u64,
        capsule: &ContextCapsule,
        expected_capsule_revision: u64,
        handle: &WorkerHandle,
        expected_handle_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() || generation == 0 {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous_branch = self.load_context_branch(&branch.project_id, &branch.id)?;
        let previous_lease = self.load_worker_lease(&lease.project_id, &lease.id)?;
        let previous_capsule = self.load_context_capsule(&capsule.project_id, &capsule.id)?;
        let previous_handle =
            self.load_worker_handle(&handle.project_id, &handle.workspace_id, &handle.worker_id)?;
        if previous_branch.revision != expected_branch_revision
            || previous_lease.revision != expected_lease_revision
            || previous_capsule.revision != expected_capsule_revision
            || previous_handle.revision != expected_handle_revision
            || !branch.follows(&previous_branch)?
            || !lease.follows(&previous_lease)?
            || !capsule.follows(&previous_capsule)?
            || !handle.follows(&previous_handle)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!(
                    "context_generation_authority_retirement:{}",
                    handle.worker_id
                ),
                expected_revision: expected_handle_revision,
            });
        }
        if handle.mission_id != *mission_id
            || handle.generation != generation
            || branch.project_id != handle.project_id
            || branch.workspace_id != handle.workspace_id
            || branch.generation != generation
            || lease.project_id != handle.project_id
            || lease.workspace_id != handle.workspace_id
            || lease.worker_id != handle.worker_id
            || lease.generation != generation
            || capsule.project_id != handle.project_id
            || capsule.mission_id != *mission_id
            || capsule.workspace_id != handle.workspace_id
            || capsule.worker_id != handle.worker_id
            || capsule.worker_generation != generation
            || handle.branch_id != branch.id
            || handle.lease_id != lease.id
            || handle.capsule_id != capsule.id
        {
            return Err(StorageError::DomainDecode(
                "Context generation authority retirement scope mismatch".into(),
            ));
        }
        let workspace = self.load_context_workspace(&handle.project_id, &handle.workspace_id)?;
        let mission = self.load_mission(&handle.project_id, mission_id)?;
        let facts = self.load_context_capsule_facts(&capsule.project_id, &capsule.id)?;
        let parent = handle
            .parent_worker_id
            .as_ref()
            .map(|worker_id| {
                self.load_worker_handle(&handle.project_id, &handle.workspace_id, worker_id)
            })
            .transpose()?;
        let mailbox = self.load_worker_mailbox_for_handle(
            &handle.project_id,
            &handle.workspace_id,
            &handle.worker_id,
        )?;
        mailbox.validate_for(&previous_handle, now)?;
        if mailbox.unsettled_count() != 0 {
            return Err(StorageError::DomainDecode(
                "Context generation authority has unsettled mailbox messages".into(),
            ));
        }
        if workspace.mission_id != *mission_id || workspace.generation != generation {
            return Err(StorageError::DomainDecode(
                "Context generation workspace scope mismatch".into(),
            ));
        }
        branch.validate_for_workspace(&workspace, now)?;
        lease.validate_for(&workspace, branch, now)?;
        capsule.validate_for(&workspace, branch, lease, &mission, &facts, now)?;
        handle.validate_for(&workspace, branch, lease, capsule, parent.as_ref(), now)?;

        let transaction = self.connection.transaction()?;
        update_context_branch_row(&transaction, branch, expected_branch_revision)?;
        update_worker_lease_row(&transaction, lease, expected_lease_revision)?;
        update_context_capsule_row(&transaction, capsule, expected_capsule_revision)?;
        update_worker_handle_row(&transaction, handle, expected_handle_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            handle.tenant_id.as_str(),
            handle.project_id.as_str(),
            Some(mission_id.as_str()),
            "context_generation_authority_retirement",
            handle.worker_id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: handle.revision,
        })
    }

    /// Atomically fences every local execution-authority aggregate for a
    /// definitive or explicitly uncertain Runtime turn. The uncertain turn
    /// itself remains uncertain and is never converted into success or
    /// replayed; only its now-dead local process authority is revoked.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the fencing transaction must bind every independently versioned authority aggregate"
    )]
    pub fn retire_runtime_turn_authority(
        &mut self,
        turn: &RuntimeTurnAttempt,
        branch: &ContextBranch,
        expected_branch_revision: u64,
        lease: &WorkerLease,
        expected_lease_revision: u64,
        capsule: &ContextCapsule,
        expected_capsule_revision: u64,
        handle: &WorkerHandle,
        expected_handle_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty()
            || !matches!(
                turn.status,
                RuntimeTurnStatus::Completed
                    | RuntimeTurnStatus::Interrupted
                    | RuntimeTurnStatus::Failed
                    | RuntimeTurnStatus::Uncertain
            )
        {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let stored_turn = self.load_runtime_turn_attempt(&turn.scope.project_id, &turn.id)?;
        if stored_turn != *turn {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "Runtime turn authority retirement",
                id: turn.id.to_string(),
            });
        }
        let previous_branch = self.load_context_branch(&branch.project_id, &branch.id)?;
        let previous_lease = self.load_worker_lease(&lease.project_id, &lease.id)?;
        let previous_capsule = self.load_context_capsule(&capsule.project_id, &capsule.id)?;
        let previous_handle =
            self.load_worker_handle(&handle.project_id, &handle.workspace_id, &handle.worker_id)?;
        if previous_branch.revision != expected_branch_revision
            || previous_lease.revision != expected_lease_revision
            || previous_capsule.revision != expected_capsule_revision
            || previous_handle.revision != expected_handle_revision
            || !branch.follows(&previous_branch)?
            || !lease.follows(&previous_lease)?
            || !capsule.follows(&previous_capsule)?
            || !handle.follows(&previous_handle)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_turn_authority_retirement:{}", turn.id),
                expected_revision: expected_handle_revision,
            });
        }
        if turn.scope.project_id != handle.project_id
            || turn.scope.mission_id != handle.mission_id
            || turn.scope.workspace_id != handle.workspace_id
            || turn.scope.worker_id != handle.worker_id
            || turn.scope.worker_generation != handle.generation
            || turn.scope.capsule_id != capsule.id
            || turn.scope.branch_id != branch.id
            || turn.scope.worker_lease_id != lease.id
            || branch.project_id != handle.project_id
            || branch.workspace_id != handle.workspace_id
            || lease.project_id != handle.project_id
            || lease.workspace_id != handle.workspace_id
            || lease.worker_id != handle.worker_id
            || capsule.project_id != handle.project_id
            || capsule.workspace_id != handle.workspace_id
            || capsule.worker_id != handle.worker_id
        {
            return Err(StorageError::DomainDecode(
                "Runtime turn authority retirement scope mismatch".into(),
            ));
        }
        let workspace = self.load_context_workspace(&handle.project_id, &handle.workspace_id)?;
        let mission = self.load_mission(&handle.project_id, &handle.mission_id)?;
        let facts = self.load_context_capsule_facts(&capsule.project_id, &capsule.id)?;
        let parent = handle
            .parent_worker_id
            .as_ref()
            .map(|worker_id| {
                self.load_worker_handle(&handle.project_id, &handle.workspace_id, worker_id)
            })
            .transpose()?;
        let mailbox = self.load_worker_mailbox_for_handle(
            &handle.project_id,
            &handle.workspace_id,
            &handle.worker_id,
        )?;
        mailbox.validate_for(&previous_handle, now)?;
        if mailbox.unsettled_count() != 0 {
            return Err(StorageError::DomainDecode(
                "Runtime turn authority has unsettled mailbox messages".into(),
            ));
        }
        branch.validate_for_workspace(&workspace, now)?;
        lease.validate_for(&workspace, branch, now)?;
        capsule.validate_for(&workspace, branch, lease, &mission, &facts, now)?;
        handle.validate_for(&workspace, branch, lease, capsule, parent.as_ref(), now)?;

        let transaction = self.connection.transaction()?;
        update_context_branch_row(&transaction, branch, expected_branch_revision)?;
        update_worker_lease_row(&transaction, lease, expected_lease_revision)?;
        update_context_capsule_row(&transaction, capsule, expected_capsule_revision)?;
        update_worker_handle_row(&transaction, handle, expected_handle_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            handle.tenant_id.as_str(),
            handle.project_id.as_str(),
            Some(handle.mission_id.as_str()),
            "runtime_turn_authority_retirement",
            turn.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: handle.revision,
        })
    }

    pub fn update_worker_handle(
        &mut self,
        handle: &WorkerHandle,
        expected_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous =
            self.load_worker_handle(&handle.project_id, &handle.workspace_id, &handle.worker_id)?;
        if previous.revision != expected_revision || !handle.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("worker_handle:{}", handle.worker_id),
                expected_revision,
            });
        }
        self.validate_worker_handle(handle, now)?;
        let transaction = self.connection.transaction()?;
        update_worker_handle_row(&transaction, handle, expected_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            handle.tenant_id.as_str(),
            handle.project_id.as_str(),
            Some(handle.mission_id.as_str()),
            "context_worker_handle",
            handle.worker_id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: handle.revision,
        })
    }

    pub fn update_worker_mailbox(
        &mut self,
        mailbox: &WorkerMailbox,
        expected_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous = self.load_worker_mailbox(&mailbox.project_id, &mailbox.id)?;
        if previous.revision != expected_revision || !mailbox.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("worker_mailbox:{}", mailbox.id),
                expected_revision,
            });
        }
        let handle = self.load_worker_handle(
            &mailbox.project_id,
            &mailbox.workspace_id,
            &mailbox.worker_id,
        )?;
        mailbox.validate_for(&handle, now)?;
        let transaction = self.connection.transaction()?;
        update_worker_mailbox_row(&transaction, mailbox, expected_revision)?;
        project_worker_message_changes(&transaction, &previous, mailbox)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mailbox.tenant_id.as_str(),
            mailbox.project_id.as_str(),
            Some(mailbox.mission_id.as_str()),
            "context_worker_mailbox",
            mailbox.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mailbox.revision,
        })
    }

    pub fn update_worker_handle_and_mailbox(
        &mut self,
        handle: &WorkerHandle,
        expected_handle_revision: u64,
        mailbox: &WorkerMailbox,
        expected_mailbox_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous_handle =
            self.load_worker_handle(&handle.project_id, &handle.workspace_id, &handle.worker_id)?;
        let previous_mailbox = self.load_worker_mailbox(&mailbox.project_id, &mailbox.id)?;
        if previous_handle.revision != expected_handle_revision
            || previous_mailbox.revision != expected_mailbox_revision
            || !handle.follows(&previous_handle)?
            || !mailbox.follows(&previous_mailbox)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("worker_handle_mailbox:{}", handle.worker_id),
                expected_revision: expected_handle_revision,
            });
        }
        self.validate_worker_handle(handle, now)?;
        mailbox.validate_for(handle, now)?;
        let transaction = self.connection.transaction()?;
        update_worker_handle_row(&transaction, handle, expected_handle_revision)?;
        update_worker_mailbox_row(&transaction, mailbox, expected_mailbox_revision)?;
        project_worker_message_changes(&transaction, &previous_mailbox, mailbox)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            handle.tenant_id.as_str(),
            handle.project_id.as_str(),
            Some(handle.mission_id.as_str()),
            "context_worker_handle",
            handle.worker_id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: handle.revision,
        })
    }

    /// Atomically retires every authority-bearing aggregate for a Runtime
    /// generation whose bounded recovery attempts are definitively exhausted.
    /// A new generation may only be issued after this commit succeeds.
    #[allow(
        clippy::too_many_arguments,
        reason = "the retirement CAS must name every independently revisioned authority aggregate"
    )]
    pub fn retire_failed_runtime_generation(
        &mut self,
        recovery: &RuntimeRecoveryAttempt,
        branch: &ContextBranch,
        expected_branch_revision: u64,
        lease: &WorkerLease,
        expected_lease_revision: u64,
        capsule: &ContextCapsule,
        expected_capsule_revision: u64,
        handle: &WorkerHandle,
        expected_handle_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() || recovery.status != RuntimeRecoveryStatus::Failed {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous_branch = self.load_context_branch(&branch.project_id, &branch.id)?;
        let previous_lease = self.load_worker_lease(&lease.project_id, &lease.id)?;
        let previous_capsule = self.load_context_capsule(&capsule.project_id, &capsule.id)?;
        let previous_handle =
            self.load_worker_handle(&handle.project_id, &handle.workspace_id, &handle.worker_id)?;
        if previous_branch.revision != expected_branch_revision
            || previous_lease.revision != expected_lease_revision
            || previous_capsule.revision != expected_capsule_revision
            || previous_handle.revision != expected_handle_revision
            || !branch.follows(&previous_branch)?
            || !lease.follows(&previous_lease)?
            || !capsule.follows(&previous_capsule)?
            || !handle.follows(&previous_handle)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_generation_retirement:{}", handle.worker_id),
                expected_revision: expected_handle_revision,
            });
        }
        let checkpoint =
            self.load_context_checkpoint(&recovery.project_id, &recovery.checkpoint_id)?;
        recovery.validate_for(&previous_handle, &checkpoint, now)?;
        if recovery.project_id != handle.project_id
            || recovery.mission_id != handle.mission_id
            || recovery.workspace_id != handle.workspace_id
            || recovery.worker_id != handle.worker_id
            || recovery.worker_generation != handle.generation
            || branch.project_id != handle.project_id
            || branch.workspace_id != handle.workspace_id
            || lease.project_id != handle.project_id
            || lease.workspace_id != handle.workspace_id
            || lease.worker_id != handle.worker_id
            || capsule.project_id != handle.project_id
            || capsule.workspace_id != handle.workspace_id
            || capsule.worker_id != handle.worker_id
        {
            return Err(StorageError::DomainDecode(
                "failed Runtime generation retirement scope mismatch".into(),
            ));
        }
        let workspace = self.load_context_workspace(&handle.project_id, &handle.workspace_id)?;
        let mission = self.load_mission(&handle.project_id, &handle.mission_id)?;
        let facts = self.load_context_capsule_facts(&capsule.project_id, &capsule.id)?;
        let parent = handle
            .parent_worker_id
            .as_ref()
            .map(|worker_id| {
                self.load_worker_handle(&handle.project_id, &handle.workspace_id, worker_id)
            })
            .transpose()?;
        branch.validate_for_workspace(&workspace, now)?;
        lease.validate_for(&workspace, branch, now)?;
        capsule.validate_for(&workspace, branch, lease, &mission, &facts, now)?;
        handle.validate_for(&workspace, branch, lease, capsule, parent.as_ref(), now)?;
        let mailbox = self.load_worker_mailbox_for_handle(
            &handle.project_id,
            &handle.workspace_id,
            &handle.worker_id,
        )?;
        mailbox.validate_for(handle, now)?;
        if mailbox.unsettled_count() != 0 {
            return Err(StorageError::DomainDecode(
                "failed Runtime generation has unsettled mailbox messages".into(),
            ));
        }

        let transaction = self.connection.transaction()?;
        update_context_branch_row(&transaction, branch, expected_branch_revision)?;
        update_worker_lease_row(&transaction, lease, expected_lease_revision)?;
        update_context_capsule_row(&transaction, capsule, expected_capsule_revision)?;
        update_worker_handle_row(&transaction, handle, expected_handle_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            handle.tenant_id.as_str(),
            handle.project_id.as_str(),
            Some(handle.mission_id.as_str()),
            "runtime_recovery",
            recovery.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: handle.revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_context_capsule_and_complete_branch(
        &mut self,
        capsule: &ContextCapsule,
        expected_capsule_revision: u64,
        branch: &ContextBranch,
        expected_branch_revision: u64,
        handle: &WorkerHandle,
        expected_handle_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous_capsule = self.load_context_capsule(&capsule.project_id, &capsule.id)?;
        let previous_branch = self.load_context_branch(&branch.project_id, &branch.id)?;
        let previous_handle =
            self.load_worker_handle(&handle.project_id, &handle.workspace_id, &handle.worker_id)?;
        let mailbox = self.load_worker_mailbox_for_handle(
            &handle.project_id,
            &handle.workspace_id,
            &handle.worker_id,
        )?;
        if previous_capsule.revision != expected_capsule_revision
            || previous_branch.revision != expected_branch_revision
            || previous_handle.revision != expected_handle_revision
            || !capsule.follows(&previous_capsule)?
            || !branch.follows(&previous_branch)?
            || !handle.follows(&previous_handle)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_capsule_branch:{}", capsule.id),
                expected_revision: expected_capsule_revision,
            });
        }
        let workspace = self.load_context_workspace(&capsule.project_id, &capsule.workspace_id)?;
        let mission = self.load_mission(&capsule.project_id, &capsule.mission_id)?;
        let lease = self.load_worker_lease(&capsule.project_id, &capsule.worker_lease_id)?;
        let facts = self.load_context_capsule_facts(&capsule.project_id, &capsule.id)?;
        mailbox.validate_for(&previous_handle, now)?;
        if mailbox.unsettled_count() != 0 {
            return Err(StorageError::DomainDecode(
                "cannot complete a context worker with unsettled mailbox messages".into(),
            ));
        }
        capsule.validate_for(&workspace, branch, &lease, &mission, &facts, now)?;
        branch.validate_for_workspace(&workspace, now)?;
        let parent = handle
            .parent_worker_id
            .as_ref()
            .map(|id| self.load_worker_handle(&handle.project_id, &handle.workspace_id, id))
            .transpose()?;
        handle.validate_for(&workspace, branch, &lease, capsule, parent.as_ref(), now)?;

        let transaction = self.connection.transaction()?;
        update_context_capsule_row(&transaction, capsule, expected_capsule_revision)?;
        update_context_branch_row(&transaction, branch, expected_branch_revision)?;
        update_worker_handle_row(&transaction, handle, expected_handle_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            capsule.tenant_id.as_str(),
            capsule.project_id.as_str(),
            Some(capsule.mission_id.as_str()),
            "context_capsule",
            capsule.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: capsule.revision,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the atomic merge binds the source and continuation CAS revisions plus their shared audit unit"
    )]
    pub fn apply_context_branch_merge(
        &mut self,
        merge: &ContextBranchMerge,
        source: &ContextBranch,
        expected_source_revision: u64,
        continuation: &ContinuationLedger,
        expected_continuation_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous_source = self.load_context_branch(&source.project_id, &source.id)?;
        let target = self.load_context_branch(&source.project_id, &merge.target_branch_id)?;
        let capsule = self.load_context_capsule(&source.project_id, &merge.capsule_id)?;
        let workspace = self.load_context_workspace(&source.project_id, &source.workspace_id)?;
        let mission = self.load_mission(&source.project_id, &merge.mission_id)?;
        let previous_continuation =
            self.load_context_continuation_ledger(&continuation.project_id, &continuation.id)?;
        if previous_source.revision != expected_source_revision
            || previous_continuation.revision != expected_continuation_revision
            || !source.follows(&previous_source)?
            || !continuation.follows(&previous_continuation)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_branch_merge:{}", source.id),
                expected_revision: expected_source_revision,
            });
        }
        merge.validate_for(
            &workspace,
            &mission,
            &previous_source,
            &target,
            &capsule,
            now,
        )?;
        continuation.validate_for(&workspace, Some(&mission), now)?;
        let entry = continuation.entries.last().ok_or_else(|| {
            StorageError::DomainDecode("branch merge continuation has no new entry".into())
        })?;

        let transaction = self.connection.transaction()?;
        update_context_branch_row(&transaction, source, expected_source_revision)?;
        insert_context_branch_merge(&transaction, merge)?;
        update_continuation_row(&transaction, continuation, expected_continuation_revision)?;
        insert_continuation_entry(&transaction, continuation, entry)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            merge.tenant_id.as_str(),
            merge.project_id.as_str(),
            Some(merge.mission_id.as_str()),
            "context_branch_merge",
            merge.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: source.revision,
        })
    }

    pub fn load_worker_handle(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
        worker_id: &WorkerId,
    ) -> Result<WorkerHandle, StorageError> {
        load_record_three(
            &self.connection,
            "SELECT record_json FROM context_worker_handles
             WHERE project_id = ?1 AND workspace_id = ?2 AND worker_id = ?3",
            project_id,
            workspace_id.as_str(),
            worker_id.as_str(),
            "context worker handle",
        )
    }

    pub fn load_worker_mailbox(
        &self,
        project_id: &ProjectId,
        mailbox_id: &ContextWorkerMailboxId,
    ) -> Result<WorkerMailbox, StorageError> {
        let mailbox: WorkerMailbox = load_record_two(
            &self.connection,
            "SELECT record_json FROM context_worker_mailboxes WHERE project_id = ?1 AND id = ?2",
            project_id,
            mailbox_id.as_str(),
            "context worker mailbox",
        )?;
        let messages = load_worker_messages(&self.connection, project_id, mailbox_id)?;
        if messages != mailbox.messages {
            return Err(StorageError::DomainDecode(
                "worker mailbox message projection does not match its header".into(),
            ));
        }
        Ok(mailbox)
    }

    pub fn load_worker_mailbox_for_handle(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
        worker_id: &WorkerId,
    ) -> Result<WorkerMailbox, StorageError> {
        let id = self.connection.query_row(
            "SELECT id FROM context_worker_mailboxes
             WHERE project_id = ?1 AND workspace_id = ?2 AND worker_id = ?3",
            params![
                project_id.as_str(),
                workspace_id.as_str(),
                worker_id.as_str()
            ],
            |row| row.get::<_, String>(0),
        )?;
        self.load_worker_mailbox(project_id, &ContextWorkerMailboxId::from_stable(id))
    }

    pub fn load_context_branch_merge(
        &self,
        project_id: &ProjectId,
        id: &ContextBranchMergeId,
    ) -> Result<ContextBranchMerge, StorageError> {
        load_record_two(
            &self.connection,
            "SELECT record_json FROM context_branch_merges WHERE project_id = ?1 AND id = ?2",
            project_id,
            id.as_str(),
            "context branch merge",
        )
    }

    pub(crate) fn validate_worker_handle(
        &self,
        handle: &WorkerHandle,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let workspace = self.load_context_workspace(&handle.project_id, &handle.workspace_id)?;
        let branch = self.load_context_branch(&handle.project_id, &handle.branch_id)?;
        let lease = self.load_worker_lease(&handle.project_id, &handle.lease_id)?;
        let capsule = self.load_context_capsule(&handle.project_id, &handle.capsule_id)?;
        let parent = handle
            .parent_worker_id
            .as_ref()
            .map(|id| self.load_worker_handle(&handle.project_id, &handle.workspace_id, id))
            .transpose()?;
        handle.validate_for(&workspace, &branch, &lease, &capsule, parent.as_ref(), now)?;
        Ok(())
    }
}

pub(crate) fn insert_worker_handle(
    transaction: &Transaction<'_>,
    handle: &WorkerHandle,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_worker_handles
           (tenant_id, project_id, mission_id, workspace_id, branch_id, capsule_id,
            lease_id, worker_id, parent_worker_id, generation, attachment_epoch,
            status, cursor, revision, created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17)",
        params![
            handle.tenant_id.as_str(),
            handle.project_id.as_str(),
            handle.mission_id.as_str(),
            handle.workspace_id.as_str(),
            handle.branch_id.as_str(),
            handle.capsule_id.as_str(),
            handle.lease_id.as_str(),
            handle.worker_id.as_str(),
            handle.parent_worker_id.as_ref().map(WorkerId::as_str),
            to_sql_u64(handle.generation)?,
            to_sql_u64(handle.attachment_epoch)?,
            json_enum(&handle.status)?,
            to_sql_u64(handle.cursor)?,
            to_sql_u64(handle.revision)?,
            handle.created_at.to_rfc3339(),
            handle.updated_at.to_rfc3339(),
            serde_json::to_string(handle)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn insert_worker_mailbox(
    transaction: &Transaction<'_>,
    mailbox: &WorkerMailbox,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_worker_mailboxes
           (tenant_id, project_id, id, mission_id, workspace_id, worker_id,
            generation, max_pending, next_sequence, acknowledged_cursor,
            revision, created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            mailbox.tenant_id.as_str(),
            mailbox.project_id.as_str(),
            mailbox.id.as_str(),
            mailbox.mission_id.as_str(),
            mailbox.workspace_id.as_str(),
            mailbox.worker_id.as_str(),
            to_sql_u64(mailbox.generation)?,
            i64::from(mailbox.max_pending),
            to_sql_u64(mailbox.next_sequence)?,
            to_sql_u64(mailbox.acknowledged_cursor)?,
            to_sql_u64(mailbox.revision)?,
            mailbox.created_at.to_rfc3339(),
            mailbox.updated_at.to_rfc3339(),
            serde_json::to_string(mailbox)?,
        ],
    )?;
    for message in &mailbox.messages {
        insert_worker_message(transaction, mailbox, message)?;
    }
    Ok(())
}

pub(crate) fn update_worker_handle_row(
    transaction: &Transaction<'_>,
    handle: &WorkerHandle,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE context_worker_handles
         SET attachment_epoch = ?1, status = ?2, cursor = ?3, revision = ?4,
             updated_at = ?5, record_json = ?6
         WHERE project_id = ?7 AND workspace_id = ?8 AND worker_id = ?9 AND revision = ?10",
        params![
            to_sql_u64(handle.attachment_epoch)?,
            json_enum(&handle.status)?,
            to_sql_u64(handle.cursor)?,
            to_sql_u64(handle.revision)?,
            handle.updated_at.to_rfc3339(),
            serde_json::to_string(handle)?,
            handle.project_id.as_str(),
            handle.workspace_id.as_str(),
            handle.worker_id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    require_one(
        changed,
        "worker_handle",
        &handle.worker_id.to_string(),
        expected_revision,
    )
}

pub(crate) fn update_worker_mailbox_row(
    transaction: &Transaction<'_>,
    mailbox: &WorkerMailbox,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE context_worker_mailboxes
         SET next_sequence = ?1, acknowledged_cursor = ?2, revision = ?3,
             updated_at = ?4, record_json = ?5
         WHERE project_id = ?6 AND id = ?7 AND revision = ?8",
        params![
            to_sql_u64(mailbox.next_sequence)?,
            to_sql_u64(mailbox.acknowledged_cursor)?,
            to_sql_u64(mailbox.revision)?,
            mailbox.updated_at.to_rfc3339(),
            serde_json::to_string(mailbox)?,
            mailbox.project_id.as_str(),
            mailbox.id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    require_one(
        changed,
        "worker_mailbox",
        &mailbox.id.to_string(),
        expected_revision,
    )
}

pub(crate) fn project_worker_message_changes(
    transaction: &Transaction<'_>,
    previous: &WorkerMailbox,
    current: &WorkerMailbox,
) -> Result<(), StorageError> {
    for (index, message) in current.messages.iter().enumerate() {
        if let Some(old) = previous.messages.get(index) {
            if old == message {
                continue;
            }
            let changed = transaction.execute(
                "UPDATE context_worker_messages
                 SET status = ?1, claim_epoch = ?2, result_digest = ?3,
                     updated_at = ?4, record_json = ?5
                 WHERE project_id = ?6 AND mailbox_id = ?7 AND message_id = ?8
                   AND status = ?9 AND updated_at = ?10",
                params![
                    json_enum(&message.status)?,
                    message.claim_epoch.map(to_sql_u64).transpose()?,
                    message.result_digest,
                    message.updated_at.to_rfc3339(),
                    serde_json::to_string(message)?,
                    current.project_id.as_str(),
                    current.id.as_str(),
                    message.id.as_str(),
                    json_enum(&old.status)?,
                    old.updated_at.to_rfc3339(),
                ],
            )?;
            require_one(
                changed,
                "worker_message",
                &message.id.to_string(),
                previous.revision,
            )?;
        } else {
            insert_worker_message(transaction, current, message)?;
        }
    }
    Ok(())
}

fn insert_worker_message(
    transaction: &Transaction<'_>,
    mailbox: &WorkerMailbox,
    message: &ContextWorkerMessage,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_worker_messages
           (tenant_id, project_id, mailbox_id, message_id, sequence,
            sender_worker_id, target_worker_id, message_kind, status, claim_epoch,
            payload_digest, result_digest, enqueued_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            mailbox.tenant_id.as_str(),
            mailbox.project_id.as_str(),
            mailbox.id.as_str(),
            message.id.as_str(),
            to_sql_u64(message.sequence)?,
            message.sender_worker_id.as_ref().map(WorkerId::as_str),
            message.target_worker_id.as_str(),
            json_enum(&message.kind)?,
            json_enum(&message.status)?,
            message.claim_epoch.map(to_sql_u64).transpose()?,
            message.payload_digest,
            message.result_digest,
            message.enqueued_at.to_rfc3339(),
            message.updated_at.to_rfc3339(),
            serde_json::to_string(message)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn update_context_branch_row(
    transaction: &Transaction<'_>,
    branch: &ContextBranch,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE context_branches
         SET status = ?1, revision = ?2, updated_at = ?3, record_json = ?4
         WHERE project_id = ?5 AND id = ?6 AND revision = ?7",
        params![
            json_enum(&branch.status)?,
            to_sql_u64(branch.revision)?,
            branch.updated_at.to_rfc3339(),
            serde_json::to_string(branch)?,
            branch.project_id.as_str(),
            branch.id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    require_one(
        changed,
        "context_branch",
        &branch.id.to_string(),
        expected_revision,
    )
}

fn insert_context_branch_merge(
    transaction: &Transaction<'_>,
    merge: &ContextBranchMerge,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_branch_merges
           (tenant_id, project_id, id, mission_id, workspace_id, source_branch_id,
            source_branch_revision, target_branch_id, target_branch_revision,
            generation, capsule_id, capsule_revision, result_digest,
            mission_revision, disposition, conflict_digest, recorded_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17, ?18)",
        params![
            merge.tenant_id.as_str(),
            merge.project_id.as_str(),
            merge.id.as_str(),
            merge.mission_id.as_str(),
            merge.workspace_id.as_str(),
            merge.source_branch_id.as_str(),
            to_sql_u64(merge.source_branch_revision)?,
            merge.target_branch_id.as_str(),
            to_sql_u64(merge.target_branch_revision)?,
            to_sql_u64(merge.generation)?,
            merge.capsule_id.as_str(),
            to_sql_u64(merge.capsule_revision)?,
            merge.result_digest,
            to_sql_u64(merge.mission_revision)?,
            json_enum(&merge.disposition)?,
            merge.conflict_digest,
            merge.recorded_at.to_rfc3339(),
            serde_json::to_string(merge)?,
        ],
    )?;
    Ok(())
}

fn update_continuation_row(
    transaction: &Transaction<'_>,
    ledger: &ContinuationLedger,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE context_continuation_ledgers
         SET revision = ?1, updated_at = ?2, record_json = ?3
         WHERE project_id = ?4 AND id = ?5 AND revision = ?6",
        params![
            to_sql_u64(ledger.revision)?,
            ledger.updated_at.to_rfc3339(),
            serde_json::to_string(ledger)?,
            ledger.project_id.as_str(),
            ledger.id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    require_one(
        changed,
        "continuation",
        &ledger.id.to_string(),
        expected_revision,
    )
}

fn insert_continuation_entry(
    transaction: &Transaction<'_>,
    ledger: &ContinuationLedger,
    entry: &hartevo_domain_kernel::ContinuationEntry,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_continuation_entries
           (tenant_id, project_id, ledger_id, sequence, mission_revision,
            entry_kind, subject_id, payload_ref, payload_digest, recorded_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            ledger.id.as_str(),
            to_sql_u64(entry.sequence)?,
            to_sql_u64(entry.mission_revision)?,
            json_enum(&entry.kind)?,
            entry.subject_id,
            entry.payload_ref,
            entry.payload_digest,
            entry.recorded_at.to_rfc3339(),
            serde_json::to_string(entry)?,
        ],
    )?;
    Ok(())
}

fn load_worker_messages(
    connection: &Connection,
    project_id: &ProjectId,
    mailbox_id: &ContextWorkerMailboxId,
) -> Result<Vec<ContextWorkerMessage>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT record_json FROM context_worker_messages
         WHERE project_id = ?1 AND mailbox_id = ?2 ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(params![project_id.as_str(), mailbox_id.as_str()], |row| {
        row.get::<_, String>(0)
    })?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

fn load_record_two<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    project_id: &ProjectId,
    id: &str,
    kind: &'static str,
) -> Result<T, StorageError> {
    let value = connection
        .query_row(sql, params![project_id.as_str(), id], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    decode_scoped(value, project_id, id, kind)
}

fn load_record_three<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    project_id: &ProjectId,
    second: &str,
    third: &str,
    kind: &'static str,
) -> Result<T, StorageError> {
    let value = connection
        .query_row(sql, params![project_id.as_str(), second, third], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    decode_scoped(value, project_id, third, kind)
}

fn decode_scoped<T: serde::de::DeserializeOwned>(
    value: Option<String>,
    project_id: &ProjectId,
    id: &str,
    kind: &'static str,
) -> Result<T, StorageError> {
    let value = value.ok_or_else(|| StorageError::ScopedRecordNotFound {
        kind,
        project_id: project_id.clone(),
        id: id.to_owned(),
    })?;
    Ok(serde_json::from_str(&value)?)
}

fn require_one(
    changed: usize,
    aggregate: &str,
    id: &str,
    expected_revision: u64,
) -> Result<(), StorageError> {
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("{aggregate}:{id}"),
            expected_revision,
        });
    }
    Ok(())
}

fn json_enum(value: &impl serde::Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as text".into()))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ApprovalPolicy, AutonomyLevel, ContextBranchId, ContextBudget, ContextCapsuleId,
        ContextDataPolicy, ContextInputRefs, ContextMergePolicy, ContextReturnContract,
        ContextWorkerMessageId, ContextWorkerMessageKind, ContextWorkerMessageStatus,
        ContextWorkingSet, ContextWorkingSetId, CurrencyCode, EffectClass, MissionContract,
        MissionId, Money, OperatingMode, Project, StorageMode, Task, TaskId, TaskStatus, TenantId,
        WorkerLease, WorkerLeaseId,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the failure-injection test proves handle, mailbox, normalized message, and audit rollback as one atomic acknowledgement narrative"
    )]
    fn mailbox_update_failure_rolls_back_worker_cursor_message_and_events() {
        let tenant = TenantId::from("tenant-context-collaboration-atomicity");
        let project = Project::create_local(
            tenant.clone(),
            ProjectId::from("project-context-collaboration-atomicity"),
            "Context collaboration atomicity",
            "",
            "/tmp/project-context-collaboration-atomicity",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let contract = MissionContract {
            version: 1,
            mode: OperatingMode::BuildOnce,
            goal: "Acknowledge one bounded worker message".into(),
            non_goals: vec![],
            market: "US".into(),
            language: "en".into(),
            audience: "operator".into(),
            kpis: BTreeMap::new(),
            budget: Money::new(2_000, CurrencyCode::parse("USD").expect("USD")),
            timezone: "UTC".into(),
            cadence: None,
            autonomy_by_capability: BTreeMap::from([(
                "market.analyze".into(),
                AutonomyLevel::ApprovalRequired,
            )]),
            consent_requirements: BTreeSet::new(),
            approval_policy: ApprovalPolicy {
                required_effect_classes: BTreeSet::from([EffectClass::ExternalWrite]),
                validity_seconds: 3_600,
                exact_scope_required: true,
            },
            stop_conditions: vec!["user_cancelled".into()],
            completion_conditions: vec!["message_acknowledged".into()],
            valid_from: now(),
            valid_until: now() + Duration::hours(2),
            constraints: vec![],
            enabled_capabilities: BTreeSet::from(["market.analyze".into()]),
            forbidden_capabilities: BTreeSet::new(),
        };
        let mut mission = hartevo_domain_kernel::Mission::compile(
            tenant,
            MissionId::from("mission-context-collaboration-atomicity"),
            project.id.clone(),
            "Context collaboration atomicity",
            contract,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-context-collaboration-atomicity"),
                    title: "Analyze".into(),
                    status: TaskStatus::Ready,
                    capability: "market.analyze".into(),
                }],
                now(),
            )
            .expect("task");
        let workspace = hartevo_domain_kernel::ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-context-collaboration-atomicity"),
            &mission,
            1,
            "context-policy/v1",
            BTreeSet::from(["market.analyze".into()]),
            ContextBudget {
                token_limit: 10_000,
                cost_limit: Money::new(2_000, CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::hours(1),
                max_depth: 2,
                max_concurrency: 2,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let working_set = ContextWorkingSet::create(
            ContextWorkingSetId::from("working-context-collaboration-atomicity"),
            &workspace,
            now(),
        )
        .expect("working set");
        let continuation = ContinuationLedger::create(
            hartevo_domain_kernel::ContextContinuationLedgerId::from(
                "continuation-context-collaboration-atomicity",
            ),
            &workspace,
            now(),
        )
        .expect("continuation");
        let branch = ContextBranch::create(
            ContextBranchId::from("branch-context-collaboration-atomicity"),
            &workspace,
            None,
            "bounded worker",
            "1".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("branch");
        let lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-context-collaboration-atomicity"),
            &workspace,
            &branch,
            WorkerId::from("worker-context-collaboration-atomicity"),
            1,
            "2".repeat(64),
            Some("3".repeat(64)),
            now() + Duration::minutes(30),
            now(),
        )
        .expect("lease");
        let mut capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-context-collaboration-atomicity"),
            &workspace,
            &branch,
            &lease,
            &mission,
            "Return one typed finding",
            TaskId::from("task-context-collaboration-atomicity"),
            BTreeSet::new(),
            &[],
            BTreeSet::from(["market.analyze".into()]),
            ContextBudget {
                token_limit: 1_000,
                cost_limit: Money::new(500, CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::minutes(20),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs::default(),
            ContextReturnContract {
                schema_id: "hartevo.context.finding".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["finding".into()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: false,
                uncertainty_required: true,
                max_result_bytes: 4_096,
            },
            now() + Duration::minutes(20),
            now(),
        )
        .expect("capsule");
        let handle = WorkerHandle::create(&workspace, &branch, &lease, &capsule, None, now())
            .expect("handle");
        let mailbox_id = ContextWorkerMailboxId::from("mailbox-context-collaboration-atomicity");
        let mailbox =
            WorkerMailbox::create(mailbox_id.clone(), &handle, 2, now()).expect("mailbox");

        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("persist project");
        store.save_mission(&mission).expect("persist mission");
        store
            .create_context_workspace(
                &workspace,
                &working_set,
                &continuation,
                &[PendingEvent::new(
                    "context.workspace_created",
                    serde_json::json!({"workspaceId": workspace.id}),
                    now(),
                )],
                now(),
            )
            .expect("persist workspace");
        store
            .issue_context_capsule_bundle(
                &workspace,
                std::slice::from_ref(&branch),
                &lease,
                &capsule,
                &handle,
                &mailbox,
                &[],
                &[PendingEvent::new(
                    "context.capsule_issued",
                    serde_json::json!({"capsuleId": capsule.id}),
                    now(),
                )],
                now(),
            )
            .expect("persist capsule bundle");
        capsule
            .claim(1, now() + Duration::seconds(1))
            .expect("claim capsule before worker execution");
        store
            .update_context_capsule(
                &capsule,
                1,
                &[PendingEvent::new(
                    "context.capsule_claimed",
                    serde_json::json!({"capsuleId": capsule.id}),
                    now() + Duration::seconds(1),
                )],
                now() + Duration::seconds(1),
            )
            .expect("persist capsule claim");

        let mut pending = mailbox;
        let message = pending
            .enqueue(
                &handle,
                ContextWorkerMessageId::from("message-context-collaboration-atomicity"),
                None,
                ContextWorkerMessageKind::Data,
                format!("cas://{}", "4".repeat(64)),
                "5".repeat(64),
                now() + Duration::seconds(1),
            )
            .expect("enqueue");
        store
            .update_worker_mailbox(
                &pending,
                1,
                &[PendingEvent::new(
                    "context.worker_message_enqueued",
                    serde_json::json!({"messageId": message.id}),
                    now() + Duration::seconds(1),
                )],
                now() + Duration::seconds(1),
            )
            .expect("persist enqueue");
        pending
            .claim_next(&handle, &capsule, 1, now() + Duration::seconds(2))
            .expect("claim")
            .expect("message");
        store
            .update_worker_mailbox(
                &pending,
                2,
                &[PendingEvent::new(
                    "context.worker_message_claimed",
                    serde_json::json!({"messageId": message.id}),
                    now() + Duration::seconds(2),
                )],
                now() + Duration::seconds(2),
            )
            .expect("persist claim");
        let mut acknowledged_handle = handle;
        let mut acknowledged_mailbox = pending;
        acknowledged_mailbox
            .acknowledge(
                &mut acknowledged_handle,
                &capsule,
                &message.id,
                1,
                "6".repeat(64),
                now() + Duration::seconds(3),
            )
            .expect("acknowledge in memory");

        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_worker_mailbox_update_failure
                 BEFORE UPDATE ON context_worker_mailboxes
                 BEGIN
                   SELECT RAISE(ABORT, 'injected mailbox update failure');
                 END;",
            )
            .expect("failure trigger");
        let event_count_before: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM domain_events", [], |row| row.get(0))
            .expect("event count");
        assert!(
            store
                .update_worker_handle_and_mailbox(
                    &acknowledged_handle,
                    1,
                    &acknowledged_mailbox,
                    3,
                    &[PendingEvent::new(
                        "context.worker_message_acknowledged",
                        serde_json::json!({"messageId": message.id}),
                        now() + Duration::seconds(3),
                    )],
                    now() + Duration::seconds(3),
                )
                .is_err()
        );
        let persisted_handle = store
            .load_worker_handle(&project.id, &workspace.id, &acknowledged_handle.worker_id)
            .expect("rolled-back handle");
        let persisted_mailbox = store
            .load_worker_mailbox(&project.id, &mailbox_id)
            .expect("rolled-back mailbox");
        assert_eq!((persisted_handle.revision, persisted_handle.cursor), (1, 0));
        assert_eq!(
            (
                persisted_mailbox.revision,
                persisted_mailbox.acknowledged_cursor
            ),
            (3, 0)
        );
        assert_eq!(
            persisted_mailbox.messages[0].status,
            ContextWorkerMessageStatus::InFlight
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM domain_events", [], |row| row
                    .get::<_, i64>(0))
                .expect("event count after rollback"),
            event_count_before
        );

        store
            .connection
            .execute_batch("DROP TRIGGER inject_worker_mailbox_update_failure;")
            .expect("remove failure trigger");
        store
            .update_worker_handle_and_mailbox(
                &acknowledged_handle,
                1,
                &acknowledged_mailbox,
                3,
                &[PendingEvent::new(
                    "context.worker_message_acknowledged",
                    serde_json::json!({"messageId": message.id}),
                    now() + Duration::seconds(3),
                )],
                now() + Duration::seconds(3),
            )
            .expect("retry full atomic acknowledgement");
        let persisted_handle = store
            .load_worker_handle(&project.id, &workspace.id, &acknowledged_handle.worker_id)
            .expect("acknowledged handle");
        let persisted_mailbox = store
            .load_worker_mailbox(&project.id, &mailbox_id)
            .expect("acknowledged mailbox");
        assert_eq!((persisted_handle.revision, persisted_handle.cursor), (2, 1));
        assert_eq!(
            (
                persisted_mailbox.revision,
                persisted_mailbox.acknowledged_cursor
            ),
            (4, 1)
        );
        assert_eq!(
            persisted_mailbox.messages[0].status,
            ContextWorkerMessageStatus::Acknowledged
        );
    }
}

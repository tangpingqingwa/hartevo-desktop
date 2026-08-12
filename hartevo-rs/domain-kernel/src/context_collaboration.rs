//! Context branch integration and bounded worker-to-worker collaboration.
//!
//! A branch merge only imports a typed, accepted capsule result into the parent
//! continuation stream. It cannot mutate Mission Truth, Work Products, Effects,
//! approvals, or provider state. Worker mailboxes use attachment epochs so a
//! detached runtime can never acknowledge work after reattachment.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContextBranch, ContextBranchId, ContextBranchMergeId, ContextBranchStatus, ContextBudget,
    ContextCapsule, ContextCapsuleId, ContextCapsuleStatus, ContextError, ContextMergePolicy,
    ContextWorkerMailboxId, ContextWorkerMessageId, ContextWorkspace, ContextWorkspaceId,
    CurrencyCode, EvidenceId, Mission, MissionId, Money, ProjectId, TenantId, WorkerId,
    WorkerLease, WorkerLeaseId,
};

const MAX_MAILBOX_CAPACITY: u32 = 1_024;
const MAX_MESSAGE_REFERENCE_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextBranchMergeDisposition {
    Applied,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextBranchMerge {
    pub id: ContextBranchMergeId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: ContextWorkspaceId,
    pub source_branch_id: ContextBranchId,
    pub source_branch_revision: u64,
    pub target_branch_id: ContextBranchId,
    pub target_branch_revision: u64,
    pub generation: u64,
    pub merge_policy: ContextMergePolicy,
    pub capsule_id: ContextCapsuleId,
    pub capsule_revision: u64,
    pub result_digest: String,
    pub artifact_digests: BTreeSet<String>,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub mission_revision: u64,
    pub disposition: ContextBranchMergeDisposition,
    pub conflict_digest: Option<String>,
    pub recorded_at: DateTime<Utc>,
}

impl ContextBranchMerge {
    pub fn apply(
        id: ContextBranchMergeId,
        workspace: &ContextWorkspace,
        mission: &Mission,
        source: &ContextBranch,
        target: &ContextBranch,
        capsule: &ContextCapsule,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let result = capsule
            .result
            .as_ref()
            .ok_or(ContextError::InvalidBranchTransition)?;
        let value = Self {
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            source_branch_id: source.id.clone(),
            source_branch_revision: source.revision,
            target_branch_id: target.id.clone(),
            target_branch_revision: target.revision,
            generation: workspace.generation,
            merge_policy: source.merge_policy,
            capsule_id: capsule.id.clone(),
            capsule_revision: capsule.revision,
            result_digest: result.result_digest.clone(),
            artifact_digests: result.artifact_digests.clone(),
            evidence_ids: result.evidence_ids.clone(),
            mission_revision: mission.revision,
            disposition: ContextBranchMergeDisposition::Applied,
            conflict_digest: None,
            recorded_at: now,
        };
        value.validate_for(workspace, mission, source, target, capsule, now)?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reject(
        id: ContextBranchMergeId,
        workspace: &ContextWorkspace,
        mission: &Mission,
        source: &ContextBranch,
        target: &ContextBranch,
        capsule: &ContextCapsule,
        conflict_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let mut value = Self::apply(id, workspace, mission, source, target, capsule, now)?;
        value.disposition = ContextBranchMergeDisposition::Rejected;
        value.conflict_digest = Some(conflict_digest);
        value.validate_for(workspace, mission, source, target, capsule, now)?;
        Ok(value)
    }

    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        mission: &Mission,
        source: &ContextBranch,
        target: &ContextBranch,
        capsule: &ContextCapsule,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        let result = capsule
            .result
            .as_ref()
            .ok_or(ContextError::InvalidBranchTransition)?;
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != mission.id
            || self.workspace_id != workspace.id
            || source.workspace_id != workspace.id
            || target.workspace_id != workspace.id
            || source.parent_branch_id.as_ref() != Some(&target.id)
            || source.status != ContextBranchStatus::Completed
            || target.status != ContextBranchStatus::Active
            || self.source_branch_id != source.id
            || self.source_branch_revision != source.revision
            || self.target_branch_id != target.id
            || self.target_branch_revision != target.revision
            || self.generation != workspace.generation
            || source.generation != self.generation
            || target.generation != self.generation
            || self.merge_policy != source.merge_policy
            || self.capsule_id != capsule.id
            || self.capsule_revision != capsule.revision
            || capsule.branch_id != source.id
            || capsule.workspace_id != workspace.id
            || capsule.mission_id != mission.id
            || capsule.status != ContextCapsuleStatus::Accepted
            || self.result_digest != result.result_digest
            || self.artifact_digests != result.artifact_digests
            || self.evidence_ids != result.evidence_ids
            || self.mission_revision != mission.revision
            || match self.disposition {
                ContextBranchMergeDisposition::Applied => self.conflict_digest.is_some(),
                ContextBranchMergeDisposition::Rejected => self
                    .conflict_digest
                    .as_ref()
                    .is_none_or(|value| !is_sha256(value)),
            }
            || !is_sha256(&self.result_digest)
            || self.artifact_digests.iter().any(|value| !is_sha256(value))
            || self.recorded_at < capsule.updated_at
            || self.recorded_at > now
        {
            return Err(ContextError::InvalidBranchTransition);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ContextError> {
        digest_json(self)
    }
}

impl ContextBranch {
    pub fn complete_for_capsule(
        &mut self,
        capsule: &ContextCapsule,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != ContextBranchStatus::Active
            || capsule.branch_id != self.id
            || capsule.workspace_id != self.workspace_id
            || capsule.worker_generation != self.generation
            || capsule.status != ContextCapsuleStatus::Accepted
            || capsule.result.is_none()
            || now < self.updated_at
            || now < capsule.updated_at
        {
            return Err(ContextError::InvalidBranchTransition);
        }
        let previous_status = self.status;
        self.status = ContextBranchStatus::Completed;
        if let Err(error) = self.touch_branch(now) {
            self.status = previous_status;
            return Err(error);
        }
        Ok(())
    }

    pub fn apply_merge(
        &mut self,
        merge: &ContextBranchMerge,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != ContextBranchStatus::Completed
            || merge.source_branch_id != self.id
            || merge.source_branch_revision != self.revision
            || merge.generation != self.generation
            || merge.disposition != ContextBranchMergeDisposition::Applied
            || now < self.updated_at
            || now < merge.recorded_at
        {
            return Err(ContextError::InvalidBranchTransition);
        }
        let previous_status = self.status;
        self.status = ContextBranchStatus::Merged;
        if let Err(error) = self.touch_branch(now) {
            self.status = previous_status;
            return Err(error);
        }
        Ok(())
    }

    pub fn abandon(
        &mut self,
        conflict_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if !matches!(
            self.status,
            ContextBranchStatus::Active | ContextBranchStatus::Completed
        ) || !is_sha256(conflict_digest)
            || now < self.updated_at
        {
            return Err(ContextError::InvalidBranchTransition);
        }
        let previous_status = self.status;
        self.status = ContextBranchStatus::Abandoned;
        if let Err(error) = self.touch_branch(now) {
            self.status = previous_status;
            return Err(error);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        let allowed = matches!(
            (previous.status, self.status),
            (ContextBranchStatus::Active, ContextBranchStatus::Completed)
                | (
                    ContextBranchStatus::Active | ContextBranchStatus::Completed,
                    ContextBranchStatus::Abandoned
                )
                | (ContextBranchStatus::Completed, ContextBranchStatus::Merged)
        );
        Ok(self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.workspace_id == previous.workspace_id
            && self.parent_branch_id == previous.parent_branch_id
            && self.depth == previous.depth
            && self.fork_reason == previous.fork_reason
            && self.scope_digest == previous.scope_digest
            && self.merge_policy == previous.merge_policy
            && self.generation == previous.generation
            && self.created_at == previous.created_at
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.updated_at >= previous.updated_at
            && allowed)
    }

    fn touch_branch(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerUsage {
    pub tokens: u64,
    pub cost: Money,
    pub tool_calls: u64,
    pub runtime_millis: u64,
}

impl WorkerUsage {
    fn zero(currency: CurrencyCode) -> Self {
        Self {
            tokens: 0,
            cost: Money::zero(currency),
            tool_calls: 0,
            runtime_millis: 0,
        }
    }

    fn record(
        &mut self,
        token_delta: u64,
        cost_delta: &Money,
        tool_call_delta: u64,
        runtime_millis_delta: u64,
        budget: &ContextBudget,
    ) -> Result<(), ContextError> {
        if cost_delta.amount_minor < 0 || cost_delta.currency != self.cost.currency {
            return Err(ContextError::WorkerBudgetExceeded);
        }
        let next_tokens = self
            .tokens
            .checked_add(token_delta)
            .ok_or(ContextError::WorkerBudgetExceeded)?;
        let next_cost = self
            .cost
            .amount_minor
            .checked_add(cost_delta.amount_minor)
            .ok_or(ContextError::WorkerBudgetExceeded)?;
        let next_tool_calls = self
            .tool_calls
            .checked_add(tool_call_delta)
            .ok_or(ContextError::WorkerBudgetExceeded)?;
        let next_runtime_millis = self
            .runtime_millis
            .checked_add(runtime_millis_delta)
            .ok_or(ContextError::WorkerBudgetExceeded)?;
        if next_tokens > budget.token_limit
            || next_cost > budget.cost_limit.amount_minor
            || budget.cost_limit.currency != self.cost.currency
        {
            return Err(ContextError::WorkerBudgetExceeded);
        }
        self.tokens = next_tokens;
        self.cost.amount_minor = next_cost;
        self.tool_calls = next_tool_calls;
        self.runtime_millis = next_runtime_millis;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHandleStatus {
    Attached,
    Detached,
    Completed,
    Failed,
    Cancelled,
}

impl WorkerHandleStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerHandle {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: ContextWorkspaceId,
    pub branch_id: ContextBranchId,
    pub capsule_id: ContextCapsuleId,
    pub lease_id: WorkerLeaseId,
    pub worker_id: WorkerId,
    pub parent_worker_id: Option<WorkerId>,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub runtime_mapping_digest: Option<String>,
    pub capabilities: BTreeSet<String>,
    pub budget: ContextBudget,
    pub usage: WorkerUsage,
    pub cursor: u64,
    pub status: WorkerHandleStatus,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WorkerHandle {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        workspace: &ContextWorkspace,
        branch: &ContextBranch,
        lease: &WorkerLease,
        capsule: &ContextCapsule,
        parent: Option<&Self>,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let value = Self {
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            branch_id: branch.id.clone(),
            capsule_id: capsule.id.clone(),
            lease_id: lease.id.clone(),
            worker_id: capsule.worker_id.clone(),
            parent_worker_id: parent.map(|value| value.worker_id.clone()),
            generation: capsule.worker_generation,
            attachment_epoch: 1,
            runtime_mapping_digest: lease.runtime_mapping_digest.clone(),
            capabilities: capsule.capabilities.clone(),
            budget: capsule.budget.clone(),
            usage: WorkerUsage::zero(capsule.budget.cost_limit.currency.clone()),
            cursor: 0,
            status: WorkerHandleStatus::Attached,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        value.validate_for(workspace, branch, lease, capsule, parent, now)?;
        Ok(value)
    }

    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        branch: &ContextBranch,
        lease: &WorkerLease,
        capsule: &ContextCapsule,
        parent: Option<&Self>,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        let parent_matches = match (parent, &self.parent_worker_id) {
            (None, None) => true,
            (Some(parent), Some(parent_id)) => {
                parent_id == &parent.worker_id
                    && parent.workspace_id == self.workspace_id
                    && parent.generation == self.generation
                    && (!parent.status.is_terminal() || self.status.is_terminal())
                    && self.capabilities.is_subset(&parent.capabilities)
                    && self.budget.is_subset_of(&parent.budget)
            }
            _ => false,
        };
        let lifecycle_matches = match self.status {
            WorkerHandleStatus::Attached | WorkerHandleStatus::Detached => {
                branch.status == ContextBranchStatus::Active
                    && matches!(
                        capsule.status,
                        ContextCapsuleStatus::Issued
                            | ContextCapsuleStatus::Claimed
                            | ContextCapsuleStatus::ResultSubmitted
                    )
            }
            WorkerHandleStatus::Completed => {
                matches!(
                    branch.status,
                    ContextBranchStatus::Completed | ContextBranchStatus::Merged
                ) && capsule.status == ContextCapsuleStatus::Accepted
            }
            WorkerHandleStatus::Cancelled => {
                branch.status == ContextBranchStatus::Abandoned
                    && capsule.status == ContextCapsuleStatus::Cancelled
            }
            WorkerHandleStatus::Failed => {
                branch.status == ContextBranchStatus::Abandoned
                    && capsule.status == ContextCapsuleStatus::Expired
            }
        };
        if self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.workspace_id != workspace.id
            || self.branch_id != branch.id
            || self.capsule_id != capsule.id
            || self.lease_id != lease.id
            || self.worker_id != capsule.worker_id
            || self.worker_id != lease.worker_id
            || self.generation != workspace.generation
            || self.generation != branch.generation
            || self.generation != lease.generation
            || self.generation != capsule.worker_generation
            || self.attachment_epoch == 0
            || !parent_matches
            || !lifecycle_matches
            || self.capabilities != capsule.capabilities
            || self.budget != capsule.budget
            || self.usage.cost.currency != self.budget.cost_limit.currency
            || self.usage.tokens > self.budget.token_limit
            || self.usage.cost.amount_minor > self.budget.cost_limit.amount_minor
            || self.usage.cost.amount_minor < 0
            || self.revision == 0
            || self.created_at < capsule.issued_at
            || self.created_at > now
            || self.updated_at < self.created_at
            || self.updated_at > now
            || match self.status {
                WorkerHandleStatus::Attached => self
                    .runtime_mapping_digest
                    .as_ref()
                    .is_none_or(|value| !is_sha256(value)),
                WorkerHandleStatus::Detached
                | WorkerHandleStatus::Completed
                | WorkerHandleStatus::Failed
                | WorkerHandleStatus::Cancelled => self.runtime_mapping_digest.is_some(),
            }
        {
            return Err(ContextError::InvalidWorkerHandle);
        }
        Ok(())
    }

    pub fn detach(
        &mut self,
        attachment_epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != WorkerHandleStatus::Attached
            || self.attachment_epoch != attachment_epoch
            || now < self.updated_at
        {
            return Err(ContextError::InvalidWorkerHandle);
        }
        let previous = self.clone();
        self.status = WorkerHandleStatus::Detached;
        self.runtime_mapping_digest = None;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn reattach(
        &mut self,
        attachment_epoch: u64,
        runtime_mapping_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != WorkerHandleStatus::Detached
            || self.attachment_epoch != attachment_epoch
            || !is_sha256(&runtime_mapping_digest)
            || now < self.updated_at
        {
            return Err(ContextError::InvalidWorkerHandle);
        }
        let previous = self.clone();
        self.attachment_epoch = self
            .attachment_epoch
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        self.status = WorkerHandleStatus::Attached;
        self.runtime_mapping_digest = Some(runtime_mapping_digest);
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_usage(
        &mut self,
        capsule: &ContextCapsule,
        attachment_epoch: u64,
        token_delta: u64,
        cost_delta: &Money,
        tool_call_delta: u64,
        runtime_millis_delta: u64,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if !self.execution_authorized(capsule, attachment_epoch)
            || (token_delta == 0
                && cost_delta.amount_minor == 0
                && tool_call_delta == 0
                && runtime_millis_delta == 0)
            || now < self.updated_at
            || now > self.budget.deadline_at
        {
            return Err(ContextError::InvalidWorkerHandle);
        }
        let previous = self.usage.clone();
        self.usage.record(
            token_delta,
            cost_delta,
            tool_call_delta,
            runtime_millis_delta,
            &self.budget,
        )?;
        if let Err(error) = self.touch(now) {
            self.usage = previous;
            return Err(error);
        }
        Ok(())
    }

    fn execution_authorized(&self, capsule: &ContextCapsule, attachment_epoch: u64) -> bool {
        self.status == WorkerHandleStatus::Attached
            && self.attachment_epoch == attachment_epoch
            && capsule.id == self.capsule_id
            && capsule.worker_id == self.worker_id
            && capsule.worker_generation == self.generation
            && matches!(
                capsule.status,
                ContextCapsuleStatus::Claimed | ContextCapsuleStatus::ResultSubmitted
            )
    }

    pub fn complete(
        &mut self,
        capsule: &ContextCapsule,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if !matches!(
            self.status,
            WorkerHandleStatus::Attached | WorkerHandleStatus::Detached
        ) || capsule.id != self.capsule_id
            || capsule.status != ContextCapsuleStatus::Accepted
            || now < self.updated_at
        {
            return Err(ContextError::InvalidWorkerHandle);
        }
        let previous = self.clone();
        self.status = WorkerHandleStatus::Completed;
        self.runtime_mapping_digest = None;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Terminates a generation that was explicitly cancelled before it could
    /// produce an accepted result. Both attached and detached handles are
    /// accepted so a failed Runtime recovery cannot strand the worker.
    pub fn cancel(
        &mut self,
        capsule: &ContextCapsule,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if !matches!(
            self.status,
            WorkerHandleStatus::Attached | WorkerHandleStatus::Detached
        ) || capsule.id != self.capsule_id
            || capsule.status != ContextCapsuleStatus::Cancelled
            || now < self.updated_at
        {
            return Err(ContextError::InvalidWorkerHandle);
        }
        let previous = self.clone();
        self.status = WorkerHandleStatus::Cancelled;
        self.runtime_mapping_digest = None;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Terminates an expired generation without converting Runtime failure
    /// into a successful completion.
    pub fn fail(
        &mut self,
        capsule: &ContextCapsule,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if !matches!(
            self.status,
            WorkerHandleStatus::Attached | WorkerHandleStatus::Detached
        ) || capsule.id != self.capsule_id
            || capsule.status != ContextCapsuleStatus::Expired
            || now < self.updated_at
        {
            return Err(ContextError::InvalidWorkerHandle);
        }
        let previous = self.clone();
        self.status = WorkerHandleStatus::Failed;
        self.runtime_mapping_digest = None;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        let immutable = self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.workspace_id == previous.workspace_id
            && self.branch_id == previous.branch_id
            && self.capsule_id == previous.capsule_id
            && self.lease_id == previous.lease_id
            && self.worker_id == previous.worker_id
            && self.parent_worker_id == previous.parent_worker_id
            && self.generation == previous.generation
            && self.capabilities == previous.capabilities
            && self.budget == previous.budget
            && self.created_at == previous.created_at;
        let usage_unchanged = self.usage == previous.usage;
        let usage_advanced = self.usage.tokens >= previous.usage.tokens
            && self.usage.cost.currency == previous.usage.cost.currency
            && self.usage.cost.amount_minor >= previous.usage.cost.amount_minor
            && self.usage.tool_calls >= previous.usage.tool_calls
            && self.usage.runtime_millis >= previous.usage.runtime_millis
            && !usage_unchanged;
        let cursor_unchanged = self.cursor == previous.cursor;
        let cursor_advanced = previous.cursor.checked_add(1) == Some(self.cursor);
        let allowed = match (previous.status, self.status) {
            (WorkerHandleStatus::Detached, WorkerHandleStatus::Attached) => {
                previous.attachment_epoch.checked_add(1) == Some(self.attachment_epoch)
                    && self.runtime_mapping_digest.is_some()
                    && cursor_unchanged
                    && usage_unchanged
            }
            (WorkerHandleStatus::Attached, WorkerHandleStatus::Attached) => {
                self.attachment_epoch == previous.attachment_epoch
                    && self.runtime_mapping_digest == previous.runtime_mapping_digest
                    && ((cursor_unchanged && usage_advanced)
                        || (cursor_advanced && usage_unchanged))
            }
            (
                WorkerHandleStatus::Attached,
                WorkerHandleStatus::Detached
                | WorkerHandleStatus::Completed
                | WorkerHandleStatus::Failed
                | WorkerHandleStatus::Cancelled,
            )
            | (
                WorkerHandleStatus::Detached,
                WorkerHandleStatus::Completed
                | WorkerHandleStatus::Failed
                | WorkerHandleStatus::Cancelled,
            ) => {
                self.attachment_epoch == previous.attachment_epoch
                    && self.runtime_mapping_digest.is_none()
                    && cursor_unchanged
                    && usage_unchanged
            }
            _ => false,
        };
        Ok(immutable
            && allowed
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.updated_at >= previous.updated_at)
    }

    fn advance_cursor(
        &mut self,
        attachment_epoch: u64,
        sequence: u64,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != WorkerHandleStatus::Attached
            || self.attachment_epoch != attachment_epoch
            || self.cursor.checked_add(1) != Some(sequence)
            || now < self.updated_at
        {
            return Err(ContextError::InvalidWorkerMessage);
        }
        let previous_cursor = self.cursor;
        self.cursor = sequence;
        if let Err(error) = self.touch(now) {
            self.cursor = previous_cursor;
            return Err(error);
        }
        Ok(())
    }

    fn touch(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextWorkerMessageKind {
    Data,
    Steer,
    FollowUp,
    Completion,
    Redirect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextWorkerMessageStatus {
    Pending,
    InFlight,
    Acknowledged,
    DeadLetter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextWorkerMessage {
    pub id: ContextWorkerMessageId,
    pub sequence: u64,
    pub sender_worker_id: Option<WorkerId>,
    pub target_worker_id: WorkerId,
    pub kind: ContextWorkerMessageKind,
    pub payload_ref: String,
    pub payload_digest: String,
    pub status: ContextWorkerMessageStatus,
    pub claim_epoch: Option<u64>,
    pub result_digest: Option<String>,
    pub enqueued_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ContextWorkerMessage {
    fn validate(&self, mailbox: &WorkerMailbox, now: DateTime<Utc>) -> Result<(), ContextError> {
        if self.id.as_str().trim().is_empty()
            || self.sequence == 0
            || self.target_worker_id != mailbox.worker_id
            || !is_safe_message_ref(&self.payload_ref)
            || !is_sha256(&self.payload_digest)
            || self.enqueued_at < mailbox.created_at
            || self.enqueued_at > now
            || self.updated_at < self.enqueued_at
            || self.updated_at > now
            || match self.status {
                ContextWorkerMessageStatus::Pending => {
                    self.claim_epoch.is_some() || self.result_digest.is_some()
                }
                ContextWorkerMessageStatus::InFlight => {
                    self.claim_epoch.is_none() || self.result_digest.is_some()
                }
                ContextWorkerMessageStatus::Acknowledged => {
                    self.claim_epoch.is_none()
                        || self
                            .result_digest
                            .as_ref()
                            .is_none_or(|value| !is_sha256(value))
                }
                ContextWorkerMessageStatus::DeadLetter => self.result_digest.is_none(),
            }
        {
            return Err(ContextError::InvalidWorkerMessage);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerMailbox {
    pub id: ContextWorkerMailboxId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: ContextWorkspaceId,
    pub worker_id: WorkerId,
    pub generation: u64,
    pub max_pending: u32,
    pub next_sequence: u64,
    pub acknowledged_cursor: u64,
    pub messages: Vec<ContextWorkerMessage>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WorkerMailbox {
    pub fn create(
        id: ContextWorkerMailboxId,
        handle: &WorkerHandle,
        max_pending: u32,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let value = Self {
            id,
            tenant_id: handle.tenant_id.clone(),
            project_id: handle.project_id.clone(),
            mission_id: handle.mission_id.clone(),
            workspace_id: handle.workspace_id.clone(),
            worker_id: handle.worker_id.clone(),
            generation: handle.generation,
            max_pending,
            next_sequence: 1,
            acknowledged_cursor: 0,
            messages: Vec::new(),
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        value.validate_for(handle, now)?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue(
        &mut self,
        handle: &WorkerHandle,
        id: ContextWorkerMessageId,
        sender_worker_id: Option<WorkerId>,
        kind: ContextWorkerMessageKind,
        payload_ref: String,
        payload_digest: String,
        now: DateTime<Utc>,
    ) -> Result<ContextWorkerMessage, ContextError> {
        self.validate_for(handle, now)?;
        if handle.status.is_terminal()
            || now < self.updated_at
            || self.messages.iter().any(|message| message.id == id)
            || self.unsettled_count() >= self.max_pending
        {
            return if self.unsettled_count() >= self.max_pending {
                Err(ContextError::ContextBackpressure)
            } else {
                Err(ContextError::InvalidWorkerMessage)
            };
        }
        let message = ContextWorkerMessage {
            id,
            sequence: self.next_sequence,
            sender_worker_id,
            target_worker_id: self.worker_id.clone(),
            kind,
            payload_ref,
            payload_digest,
            status: ContextWorkerMessageStatus::Pending,
            claim_epoch: None,
            result_digest: None,
            enqueued_at: now,
            updated_at: now,
        };
        message.validate(self, now)?;
        let previous = self.clone();
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        self.next_sequence = next_sequence;
        self.messages.push(message.clone());
        if let Err(error) = self
            .touch(now)
            .and_then(|()| self.validate_for(handle, now))
        {
            *self = previous;
            return Err(error);
        }
        Ok(message)
    }

    pub fn claim_next(
        &mut self,
        handle: &WorkerHandle,
        capsule: &ContextCapsule,
        attachment_epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<ContextWorkerMessage>, ContextError> {
        self.validate_for(handle, now)?;
        if !handle.execution_authorized(capsule, attachment_epoch)
            || self
                .messages
                .iter()
                .any(|message| message.status == ContextWorkerMessageStatus::InFlight)
        {
            return Err(ContextError::InvalidWorkerMessage);
        }
        let expected = self
            .acknowledged_cursor
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        let Some(index) = self.messages.iter().position(|message| {
            message.sequence == expected && message.status == ContextWorkerMessageStatus::Pending
        }) else {
            return Ok(None);
        };
        let previous = self.clone();
        self.messages[index].status = ContextWorkerMessageStatus::InFlight;
        self.messages[index].claim_epoch = Some(attachment_epoch);
        self.messages[index].updated_at = now;
        let claimed = self.messages[index].clone();
        if let Err(error) = self
            .touch(now)
            .and_then(|()| self.validate_for(handle, now))
        {
            *self = previous;
            return Err(error);
        }
        Ok(Some(claimed))
    }

    pub fn acknowledge(
        &mut self,
        handle: &mut WorkerHandle,
        capsule: &ContextCapsule,
        message_id: &ContextWorkerMessageId,
        attachment_epoch: u64,
        result_digest: String,
        now: DateTime<Utc>,
    ) -> Result<ContextWorkerMessage, ContextError> {
        self.validate_for(handle, now)?;
        if !handle.execution_authorized(capsule, attachment_epoch)
            || !is_sha256(&result_digest)
            || now < self.updated_at
        {
            return Err(ContextError::InvalidWorkerMessage);
        }
        let index = self
            .messages
            .iter()
            .position(|message| &message.id == message_id)
            .ok_or(ContextError::InvalidWorkerMessage)?;
        let message_before = self.messages[index].clone();
        let handle_before = handle.clone();
        let mailbox_before = self.clone();
        if message_before.status != ContextWorkerMessageStatus::InFlight
            || message_before.claim_epoch != Some(attachment_epoch)
            || message_before.sequence != self.acknowledged_cursor.saturating_add(1)
        {
            return Err(ContextError::InvalidWorkerMessage);
        }
        handle.advance_cursor(attachment_epoch, message_before.sequence, now)?;
        self.messages[index].status = ContextWorkerMessageStatus::Acknowledged;
        self.messages[index].result_digest = Some(result_digest);
        self.messages[index].updated_at = now;
        self.acknowledged_cursor = message_before.sequence;
        if let Err(error) = self
            .touch(now)
            .and_then(|()| self.validate_for(handle, now))
        {
            *self = mailbox_before;
            *handle = handle_before;
            return Err(error);
        }
        Ok(self.messages[index].clone())
    }

    /// Requeues only the message held by the detached epoch. Old workers retain
    /// no acknowledgement authority after the new attachment epoch is issued.
    pub fn recover_after_reattach(
        &mut self,
        handle: &WorkerHandle,
        now: DateTime<Utc>,
    ) -> Result<bool, ContextError> {
        if handle.status != WorkerHandleStatus::Attached
            || handle.attachment_epoch <= 1
            || now < self.updated_at
        {
            return Err(ContextError::InvalidWorkerMessage);
        }
        self.validate_for(handle, now)?;
        let previous = self.clone();
        let mut changed = false;
        for message in &mut self.messages {
            if message.status == ContextWorkerMessageStatus::InFlight
                && message
                    .claim_epoch
                    .is_some_and(|epoch| epoch < handle.attachment_epoch)
            {
                message.status = ContextWorkerMessageStatus::Pending;
                message.claim_epoch = None;
                message.updated_at = now;
                changed = true;
            }
        }
        if changed
            && let Err(error) = self
                .touch(now)
                .and_then(|()| self.validate_for(handle, now))
        {
            *self = previous;
            return Err(error);
        }
        Ok(changed)
    }

    pub fn validate_for(
        &self,
        handle: &WorkerHandle,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        let unsettled = self.unsettled_count();
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != handle.tenant_id
            || self.project_id != handle.project_id
            || self.mission_id != handle.mission_id
            || self.workspace_id != handle.workspace_id
            || self.worker_id != handle.worker_id
            || self.generation != handle.generation
            || self.max_pending == 0
            || self.max_pending > MAX_MAILBOX_CAPACITY
            || unsettled > self.max_pending
            || self.next_sequence != u64::try_from(self.messages.len()).unwrap_or(u64::MAX) + 1
            || self.acknowledged_cursor != handle.cursor
            || self.revision == 0
            || self.created_at < handle.created_at
            || self.created_at > now
            || self.updated_at < self.created_at
            || self.updated_at > now
        {
            return Err(ContextError::InvalidWorkerMessage);
        }
        for (index, message) in self.messages.iter().enumerate() {
            if message.sequence != u64::try_from(index).unwrap_or(u64::MAX) + 1 {
                return Err(ContextError::InvalidWorkerMessage);
            }
            message.validate(self, now)?;
            if message.sequence <= self.acknowledged_cursor
                && message.status != ContextWorkerMessageStatus::Acknowledged
            {
                return Err(ContextError::InvalidWorkerMessage);
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the mailbox transition proof keeps immutable fields and all four exact commands together"
    )]
    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        if self.id != previous.id
            || self.tenant_id != previous.tenant_id
            || self.project_id != previous.project_id
            || self.mission_id != previous.mission_id
            || self.workspace_id != previous.workspace_id
            || self.worker_id != previous.worker_id
            || self.generation != previous.generation
            || self.max_pending != previous.max_pending
            || self.created_at != previous.created_at
            || previous.revision.checked_add(1) != Some(self.revision)
            || self.messages.len() < previous.messages.len()
            || self.updated_at < previous.updated_at
        {
            return Ok(false);
        }
        let mut claimed = 0_u32;
        let mut recovered = 0_u32;
        let mut acknowledged = 0_u32;
        let mut acknowledged_sequence = None;
        for (old, new) in previous.messages.iter().zip(&self.messages) {
            if old.id != new.id
                || old.sequence != new.sequence
                || old.sender_worker_id != new.sender_worker_id
                || old.target_worker_id != new.target_worker_id
                || old.kind != new.kind
                || old.payload_ref != new.payload_ref
                || old.payload_digest != new.payload_digest
                || old.enqueued_at != new.enqueued_at
            {
                return Ok(false);
            }
            match (old.status, new.status) {
                (old_status, new_status) if old_status == new_status => {
                    if old != new {
                        return Ok(false);
                    }
                }
                (ContextWorkerMessageStatus::Pending, ContextWorkerMessageStatus::InFlight) => {
                    if old.claim_epoch.is_some()
                        || old.result_digest.is_some()
                        || new.claim_epoch.is_none()
                        || new.result_digest.is_some()
                        || new.updated_at < old.updated_at
                    {
                        return Ok(false);
                    }
                    claimed = claimed.saturating_add(1);
                }
                (ContextWorkerMessageStatus::InFlight, ContextWorkerMessageStatus::Pending) => {
                    if old.claim_epoch.is_none()
                        || new.claim_epoch.is_some()
                        || new.result_digest.is_some()
                        || new.updated_at < old.updated_at
                    {
                        return Ok(false);
                    }
                    recovered = recovered.saturating_add(1);
                }
                (
                    ContextWorkerMessageStatus::InFlight,
                    ContextWorkerMessageStatus::Acknowledged,
                ) => {
                    if old.claim_epoch.is_none()
                        || new.claim_epoch != old.claim_epoch
                        || new
                            .result_digest
                            .as_ref()
                            .is_none_or(|value| !is_sha256(value))
                        || new.updated_at < old.updated_at
                    {
                        return Ok(false);
                    }
                    acknowledged = acknowledged.saturating_add(1);
                    acknowledged_sequence = Some(new.sequence);
                }
                _ => return Ok(false),
            }
        }
        let appended = self.messages.len() - previous.messages.len();
        let transition_count = claimed
            .saturating_add(recovered)
            .saturating_add(acknowledged);
        let enqueue = appended == 1
            && transition_count == 0
            && previous.next_sequence.checked_add(1) == Some(self.next_sequence)
            && self.acknowledged_cursor == previous.acknowledged_cursor
            && self.messages.last().is_some_and(|message| {
                message.sequence == previous.next_sequence
                    && message.status == ContextWorkerMessageStatus::Pending
                    && message.claim_epoch.is_none()
                    && message.result_digest.is_none()
            });
        let claim = appended == 0
            && claimed == 1
            && recovered == 0
            && acknowledged == 0
            && self.next_sequence == previous.next_sequence
            && self.acknowledged_cursor == previous.acknowledged_cursor;
        let recovery = appended == 0
            && claimed == 0
            && recovered == 1
            && acknowledged == 0
            && self.next_sequence == previous.next_sequence
            && self.acknowledged_cursor == previous.acknowledged_cursor;
        let acknowledgement = appended == 0
            && claimed == 0
            && recovered == 0
            && acknowledged == 1
            && self.next_sequence == previous.next_sequence
            && previous.acknowledged_cursor.checked_add(1) == Some(self.acknowledged_cursor)
            && acknowledged_sequence == Some(self.acknowledged_cursor);
        Ok(enqueue || claim || recovery || acknowledgement)
    }

    pub fn unsettled_count(&self) -> u32 {
        u32::try_from(
            self.messages
                .iter()
                .filter(|message| {
                    matches!(
                        message.status,
                        ContextWorkerMessageStatus::Pending | ContextWorkerMessageStatus::InFlight
                    )
                })
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    fn touch(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        self.updated_at = now;
        Ok(())
    }
}

fn digest_json(value: &impl Serialize) -> Result<String, ContextError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ContextError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_safe_message_ref(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_MESSAGE_REFERENCE_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains("..")
        || value.contains(['\\', '?', '#', '@'])
    {
        return false;
    }
    let Some((scheme, target)) = value.split_once("://") else {
        return false;
    };
    matches!(scheme, "cas" | "artifact" | "mission" | "trace") && !target.is_empty()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};
    use proptest::prelude::*;

    use super::*;
    use crate::{
        ApprovalPolicy, AutonomyLevel, ContextDataPolicy, ContextInputRefs, ContextReturnContract,
        ContextReturnReceipt, EffectClass, MissionContract, OperatingMode, Task, TaskId,
        TaskStatus,
    };

    struct Fixture {
        workspace: ContextWorkspace,
        mission: Mission,
        root: ContextBranch,
        child: ContextBranch,
        lease: WorkerLease,
        capsule: ContextCapsule,
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the collaboration fixture constructs one complete typed Mission/Workspace/Branch/Capsule authority chain"
    )]
    fn fixture() -> Fixture {
        let contract = MissionContract {
            version: 1,
            mode: OperatingMode::BuildOnce,
            goal: "Return a bounded finding".into(),
            non_goals: vec![],
            market: "DE".into(),
            language: "de".into(),
            audience: "owner".into(),
            kpis: BTreeMap::new(),
            budget: Money::new(2_000, CurrencyCode::parse("EUR").expect("EUR")),
            timezone: "Europe/Berlin".into(),
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
            completion_conditions: vec!["finding_returned".into()],
            valid_from: now(),
            valid_until: now() + Duration::hours(2),
            constraints: vec![],
            enabled_capabilities: BTreeSet::from(["market.analyze".into()]),
            forbidden_capabilities: BTreeSet::new(),
        };
        let mut mission = Mission::compile(
            TenantId::from("tenant-context-c1"),
            MissionId::from("mission-context-c1"),
            ProjectId::from("project-context-c1"),
            "Context C1",
            contract,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-context-c1"),
                    title: "Analyze".into(),
                    status: TaskStatus::Ready,
                    capability: "market.analyze".into(),
                }],
                now(),
            )
            .expect("task");
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-context-c1"),
            &mission,
            1,
            "context-policy/v1",
            BTreeSet::from(["market.analyze".into()]),
            ContextBudget {
                token_limit: 10_000,
                cost_limit: Money::new(2_000, CurrencyCode::parse("EUR").expect("EUR")),
                deadline_at: now() + Duration::hours(1),
                max_depth: 4,
                max_concurrency: 2,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let root = ContextBranch::create(
            ContextBranchId::from("branch-root-c1"),
            &workspace,
            None,
            "root coordination",
            "1".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("root");
        let child = ContextBranch::create(
            ContextBranchId::from("branch-child-c1"),
            &workspace,
            Some(&root),
            "bounded child",
            "2".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("child");
        let lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-context-c1"),
            &workspace,
            &child,
            WorkerId::from("worker-context-c1"),
            1,
            "3".repeat(64),
            Some("4".repeat(64)),
            now() + Duration::minutes(30),
            now(),
        )
        .expect("lease");
        let mut capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-context-c1"),
            &workspace,
            &child,
            &lease,
            &mission,
            "Return typed finding",
            TaskId::from("task-context-c1"),
            BTreeSet::new(),
            &[],
            BTreeSet::from(["market.analyze".into()]),
            ContextBudget {
                token_limit: 1_000,
                cost_limit: Money::new(500, CurrencyCode::parse("EUR").expect("EUR")),
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
        capsule
            .claim(1, now() + Duration::seconds(1))
            .expect("claim");
        capsule
            .submit_result(
                1,
                ContextReturnReceipt {
                    schema_id: "hartevo.context.finding".into(),
                    schema_version: 1,
                    result_digest: "5".repeat(64),
                    result_size_bytes: 256,
                    evidence_ids: BTreeSet::new(),
                    artifact_digests: BTreeSet::new(),
                    uncertainty_digest: "6".repeat(64),
                    next_recommendation_digest: None,
                    submitted_at: now() + Duration::seconds(2),
                },
                now() + Duration::seconds(2),
            )
            .expect("result");
        Fixture {
            workspace,
            mission,
            root,
            child,
            lease,
            capsule,
        }
    }

    #[test]
    fn typed_branch_merge_is_single_use_and_cannot_mutate_mission_authority() {
        let mut fixture = fixture();
        let mission_before = fixture.mission.clone();
        fixture
            .capsule
            .accept_result(now() + Duration::seconds(3))
            .expect("accept");
        fixture
            .child
            .complete_for_capsule(&fixture.capsule, now() + Duration::seconds(4))
            .expect("complete branch");
        let merge = ContextBranchMerge::apply(
            ContextBranchMergeId::from("merge-context-c1"),
            &fixture.workspace,
            &fixture.mission,
            &fixture.child,
            &fixture.root,
            &fixture.capsule,
            now() + Duration::seconds(5),
        )
        .expect("typed merge");
        fixture
            .child
            .apply_merge(&merge, now() + Duration::seconds(5))
            .expect("apply once");
        assert_eq!(fixture.child.status, ContextBranchStatus::Merged);
        assert!(
            fixture
                .child
                .apply_merge(&merge, now() + Duration::seconds(6))
                .is_err()
        );
        assert_eq!(fixture.mission, mission_before);
    }

    #[test]
    fn mailbox_backpressure_and_reattach_epoch_fence_old_worker_ack() {
        let fixture = fixture();
        let mut handle = WorkerHandle::create(
            &fixture.workspace,
            &fixture.child,
            &fixture.lease,
            &fixture.capsule,
            None,
            now(),
        )
        .expect("handle");
        let mut mailbox = WorkerMailbox::create(
            ContextWorkerMailboxId::from("mailbox-context-c1"),
            &handle,
            2,
            now(),
        )
        .expect("mailbox");
        for index in 1..=2 {
            mailbox
                .enqueue(
                    &handle,
                    ContextWorkerMessageId::from_stable(format!("message-{index}")),
                    None,
                    ContextWorkerMessageKind::FollowUp,
                    format!("cas://{}", index.to_string().repeat(64)),
                    "7".repeat(64),
                    now() + Duration::seconds(index),
                )
                .expect("bounded enqueue");
        }
        assert_eq!(
            mailbox.enqueue(
                &handle,
                ContextWorkerMessageId::from("message-overflow"),
                None,
                ContextWorkerMessageKind::Data,
                format!("cas://{}", "8".repeat(64)),
                "9".repeat(64),
                now() + Duration::seconds(3),
            ),
            Err(ContextError::ContextBackpressure)
        );
        let claimed = mailbox
            .claim_next(&handle, &fixture.capsule, 1, now() + Duration::seconds(3))
            .expect("claim")
            .expect("message");
        handle
            .detach(1, now() + Duration::seconds(4))
            .expect("detach");
        handle
            .reattach(1, "a".repeat(64), now() + Duration::seconds(5))
            .expect("reattach");
        mailbox
            .recover_after_reattach(&handle, now() + Duration::seconds(5))
            .expect("requeue old claim");
        assert!(
            mailbox
                .acknowledge(
                    &mut handle,
                    &fixture.capsule,
                    &claimed.id,
                    1,
                    "b".repeat(64),
                    now() + Duration::seconds(6),
                )
                .is_err()
        );
        let reclaimed = mailbox
            .claim_next(&handle, &fixture.capsule, 2, now() + Duration::seconds(6))
            .expect("new epoch claim")
            .expect("message");
        mailbox
            .acknowledge(
                &mut handle,
                &fixture.capsule,
                &reclaimed.id,
                2,
                "c".repeat(64),
                now() + Duration::seconds(7),
            )
            .expect("new epoch ack");
        assert_eq!((handle.cursor, mailbox.acknowledged_cursor), (1, 1));
    }

    #[test]
    fn worker_usage_cannot_exceed_inherited_token_or_money_budget() {
        let fixture = fixture();
        let mut handle = WorkerHandle::create(
            &fixture.workspace,
            &fixture.child,
            &fixture.lease,
            &fixture.capsule,
            None,
            now(),
        )
        .expect("handle");
        handle
            .record_usage(
                &fixture.capsule,
                1,
                900,
                &Money::new(400, CurrencyCode::parse("EUR").expect("EUR")),
                3,
                2_000,
                now() + Duration::seconds(1),
            )
            .expect("usage");
        let before = handle.clone();
        assert_eq!(
            handle.record_usage(
                &fixture.capsule,
                1,
                101,
                &Money::new(101, CurrencyCode::parse("EUR").expect("EUR")),
                1,
                100,
                now() + Duration::seconds(2),
            ),
            Err(ContextError::WorkerBudgetExceeded)
        );
        assert_eq!(handle, before);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_worker_mailbox_sequences_are_atomic_epoch_fenced_and_budget_bounded(
            actions in prop::collection::vec((0_u8..9, 0_u16..2_000, any::<bool>()), 1..64),
        ) {
            let fixture = fixture();
            let mut handle = WorkerHandle::create(
                &fixture.workspace,
                &fixture.child,
                &fixture.lease,
                &fixture.capsule,
                None,
                now(),
            )
            .expect("handle");
            let mut mailbox = WorkerMailbox::create(
                ContextWorkerMailboxId::from("mailbox-context-c1-proptest"),
                &handle,
                4,
                now(),
            )
            .expect("mailbox");
            let initial_handle = handle.clone();
            let initial_mailbox = mailbox.clone();
            let mut cursor = now() + Duration::seconds(10);
            let mut next_message = 0_u64;

            for (action, value, current_epoch) in actions {
                cursor += Duration::seconds(1);
                let handle_before = handle.clone();
                let mailbox_before = mailbox.clone();
                let epoch = if current_epoch {
                    handle.attachment_epoch
                } else {
                    handle.attachment_epoch.saturating_sub(1)
                };
                let result = match action {
                    0 => {
                        next_message = next_message.saturating_add(1);
                        mailbox
                            .enqueue(
                                &handle,
                                ContextWorkerMessageId::from_stable(format!(
                                    "message-context-c1-proptest-{next_message}"
                                )),
                                None,
                                ContextWorkerMessageKind::Data,
                                format!("cas://{}", "8".repeat(64)),
                                "9".repeat(64),
                                cursor,
                            )
                            .map(|_| ())
                    }
                    1 => mailbox
                        .claim_next(&handle, &fixture.capsule, epoch, cursor)
                        .map(|_| ()),
                    2 => {
                        let message_id = mailbox
                            .messages
                            .iter()
                            .find(|message| {
                                message.status == ContextWorkerMessageStatus::InFlight
                            })
                            .map_or_else(
                                || ContextWorkerMessageId::from("message-missing"),
                                |message| message.id.clone(),
                            );
                        mailbox
                            .acknowledge(
                                &mut handle,
                                &fixture.capsule,
                                &message_id,
                                epoch,
                                "a".repeat(64),
                                cursor,
                            )
                            .map(|_| ())
                    }
                    3 => handle.detach(epoch, cursor),
                    4 => {
                        let reattached = handle.reattach(epoch, "b".repeat(64), cursor);
                        if reattached.is_ok() {
                            mailbox
                                .recover_after_reattach(&handle, cursor)
                                .map(|_| ())
                        } else {
                            reattached
                        }
                    }
                    5 => handle.record_usage(
                        &fixture.capsule,
                        epoch,
                        u64::from(value),
                        &Money::new(
                            i64::from(value % 250),
                            CurrencyCode::parse("EUR").expect("EUR"),
                        ),
                        u64::from(value % 7),
                        u64::from(value) * 10,
                        cursor,
                    ),
                    6 => {
                        let message_id = mailbox.messages.first().map_or_else(
                            || ContextWorkerMessageId::from("message-context-c1-duplicate"),
                            |message| message.id.clone(),
                        );
                        mailbox
                            .enqueue(
                                &handle,
                                message_id,
                                None,
                                ContextWorkerMessageKind::FollowUp,
                                format!("cas://{}", "c".repeat(64)),
                                "d".repeat(64),
                                cursor,
                            )
                            .map(|_| ())
                    }
                    7 => mailbox
                        .recover_after_reattach(&handle, cursor)
                        .map(|_| ()),
                    _ => handle.record_usage(
                        &fixture.capsule,
                        epoch,
                        u64::from(value).saturating_add(1_001),
                        &Money::new(
                            i64::from(value).saturating_add(501),
                            CurrencyCode::parse("EUR").expect("EUR"),
                        ),
                        1,
                        1,
                        cursor,
                    ),
                };

                if result.is_err() {
                    prop_assert_eq!(handle.clone(), handle_before.clone());
                    prop_assert_eq!(mailbox.clone(), mailbox_before.clone());
                } else {
                    if handle != handle_before {
                        prop_assert!(handle.follows(&handle_before).expect("handle transition"));
                    }
                    if mailbox != mailbox_before {
                        prop_assert!(mailbox.follows(&mailbox_before).expect("mailbox transition"));
                    }
                }
                prop_assert!(handle
                    .validate_for(
                        &fixture.workspace,
                        &fixture.child,
                        &fixture.lease,
                        &fixture.capsule,
                        None,
                        cursor,
                    )
                    .is_ok());
                prop_assert!(mailbox.validate_for(&handle, cursor).is_ok());
                prop_assert_eq!(mailbox.acknowledged_cursor, handle.cursor);
                prop_assert_eq!(handle.worker_id.clone(), initial_handle.worker_id.clone());
                prop_assert_eq!(mailbox.id.clone(), initial_mailbox.id.clone());
                prop_assert!(mailbox.unsettled_count() <= mailbox.max_pending);
            }
        }
    }
}

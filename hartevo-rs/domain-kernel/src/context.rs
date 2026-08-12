use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    Constraint, ContextBranchId, ContextCapsuleId, ContextWorkspaceId, EvidenceId, FactId, Mission,
    Money, ProjectId, TaskId, TenantId, TruthFact, WorkProductId, WorkerId, WorkerLeaseId,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDataClass {
    Public,
    Business,
    RedactedPersonal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDataPolicy {
    PublicOnly,
    BusinessOnly,
    BusinessAndRedactedPersonal,
}

impl ContextDataPolicy {
    /// Returns the highest data classification this policy may disclose.
    ///
    /// Context projection and provider-boundary crates use this value to
    /// enforce the same domain policy without duplicating its ordering.
    pub fn maximum_class(self) -> ContextDataClass {
        match self {
            Self::PublicOnly => ContextDataClass::Public,
            Self::BusinessOnly => ContextDataClass::Business,
            Self::BusinessAndRedactedPersonal => ContextDataClass::RedactedPersonal,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextBudget {
    pub token_limit: u64,
    pub cost_limit: Money,
    pub deadline_at: DateTime<Utc>,
    pub max_depth: u32,
    pub max_concurrency: u32,
}

impl ContextBudget {
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ContextError> {
        if self.token_limit == 0
            || self.cost_limit.amount_minor < 0
            || self.deadline_at <= now
            || self.max_depth == 0
            || self.max_concurrency == 0
        {
            return Err(ContextError::InvalidBudget);
        }
        Ok(())
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.cost_limit.currency == parent.cost_limit.currency
            && self.token_limit <= parent.token_limit
            && self.cost_limit.amount_minor <= parent.cost_limit.amount_minor
            && self.deadline_at <= parent.deadline_at
            && self.max_depth <= parent.max_depth
            && self.max_concurrency <= parent.max_concurrency
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextWorkspace {
    pub id: ContextWorkspaceId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: crate::MissionId,
    pub generation: u64,
    pub contract_version: u64,
    pub policy_version: String,
    pub capability_authority: BTreeSet<String>,
    pub constraint_digest: String,
    pub budget: ContextBudget,
    pub data_policy: ContextDataPolicy,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ContextWorkspace {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: ContextWorkspaceId,
        mission: &Mission,
        generation: u64,
        policy_version: impl Into<String>,
        capability_authority: BTreeSet<String>,
        budget: ContextBudget,
        data_policy: ContextDataPolicy,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let workspace = Self {
            id,
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            generation,
            contract_version: mission.contract.version,
            policy_version: policy_version.into().trim().to_owned(),
            capability_authority,
            constraint_digest: digest_json(&mission.contract.constraints)?,
            budget,
            data_policy,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        workspace.validate_for(mission, now)?;
        Ok(workspace)
    }

    pub fn validate_for(&self, mission: &Mission, now: DateTime<Utc>) -> Result<(), ContextError> {
        self.budget.validate_at(self.created_at)?;
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
            || self.generation == 0
            || self.contract_version != mission.contract.version
            || self.policy_version.is_empty()
            || self.capability_authority.is_empty()
            || self
                .capability_authority
                .iter()
                .any(|capability| capability.trim().is_empty())
            || !self
                .capability_authority
                .is_subset(&mission.contract.enabled_capabilities)
            || !self
                .capability_authority
                .is_disjoint(&mission.contract.forbidden_capabilities)
            || self.constraint_digest != digest_json(&mission.contract.constraints)?
            || self.budget.cost_limit.currency != mission.contract.budget.currency
            || self.budget.cost_limit.amount_minor > mission.contract.budget.amount_minor
            || self.budget.deadline_at > mission.contract.valid_until
            || self.revision == 0
            || self.created_at > now
            || self.updated_at < self.created_at
            || self.updated_at > now
        {
            return Err(ContextError::InvalidWorkspace);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextBranchStatus {
    Active,
    Completed,
    Merged,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextMergePolicy {
    TypedResultOnly,
    ManualReview,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextBranch {
    pub id: ContextBranchId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub workspace_id: ContextWorkspaceId,
    pub parent_branch_id: Option<ContextBranchId>,
    pub depth: u32,
    pub fork_reason: String,
    pub scope_digest: String,
    pub merge_policy: ContextMergePolicy,
    pub status: ContextBranchStatus,
    pub generation: u64,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ContextBranch {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: ContextBranchId,
        workspace: &ContextWorkspace,
        parent: Option<&Self>,
        fork_reason: impl Into<String>,
        scope_digest: impl Into<String>,
        merge_policy: ContextMergePolicy,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let branch = Self {
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            workspace_id: workspace.id.clone(),
            parent_branch_id: parent.map(|value| value.id.clone()),
            depth: parent.map_or(0, |value| value.depth.saturating_add(1)),
            fork_reason: fork_reason.into().trim().to_owned(),
            scope_digest: scope_digest.into(),
            merge_policy,
            status: ContextBranchStatus::Active,
            generation: workspace.generation,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        branch.validate_for(workspace, parent, now)?;
        Ok(branch)
    }

    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        parent: Option<&Self>,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        self.validate_for_workspace(workspace, now)?;
        let expected_depth = parent.map_or(0, |value| value.depth.saturating_add(1));
        let expected_parent = parent.map(|value| &value.id);
        if self.parent_branch_id.as_ref() != expected_parent
            || self.depth != expected_depth
            || parent.is_some_and(|value| {
                value.workspace_id != workspace.id
                    || value.status != ContextBranchStatus::Active
                    || value.generation != workspace.generation
                    || value.created_at > self.created_at
            })
        {
            return Err(ContextError::InvalidBranch);
        }
        Ok(())
    }

    pub fn validate_for_workspace(
        &self,
        workspace: &ContextWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.workspace_id != workspace.id
            || self.depth >= workspace.budget.max_depth
            || self.fork_reason.is_empty()
            || !is_sha256(&self.scope_digest)
            || self.generation != workspace.generation
            || self.revision == 0
            || self.created_at < workspace.created_at
            || self.created_at > now
            || self.updated_at < self.created_at
            || self.updated_at > now
        {
            return Err(ContextError::InvalidBranch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerLeaseStatus {
    Active,
    Released,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerLease {
    pub id: WorkerLeaseId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub workspace_id: ContextWorkspaceId,
    pub branch_id: ContextBranchId,
    pub worker_id: WorkerId,
    pub generation: u64,
    pub lease_token_digest: String,
    pub runtime_mapping_digest: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub heartbeat_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: WorkerLeaseStatus,
    pub revision: u64,
}

impl WorkerLease {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        id: WorkerLeaseId,
        workspace: &ContextWorkspace,
        branch: &ContextBranch,
        worker_id: WorkerId,
        generation: u64,
        lease_token_digest: impl Into<String>,
        runtime_mapping_digest: Option<String>,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let lease = Self {
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            workspace_id: workspace.id.clone(),
            branch_id: branch.id.clone(),
            worker_id,
            generation,
            lease_token_digest: lease_token_digest.into(),
            runtime_mapping_digest,
            issued_at: now,
            heartbeat_at: now,
            expires_at,
            status: WorkerLeaseStatus::Active,
            revision: 1,
        };
        lease.validate_for(workspace, branch, now)?;
        Ok(lease)
    }

    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        branch: &ContextBranch,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.workspace_id != workspace.id
            || self.branch_id != branch.id
            || self.worker_id.as_str().trim().is_empty()
            || self.generation == 0
            || self.generation != branch.generation
            || !is_sha256(&self.lease_token_digest)
            || self
                .runtime_mapping_digest
                .as_ref()
                .is_some_and(|value| !is_sha256(value))
            || self.issued_at < branch.created_at
            || self.issued_at > now
            || self.heartbeat_at < self.issued_at
            || self.heartbeat_at > now
            || self.expires_at <= self.issued_at
            || self.expires_at > workspace.budget.deadline_at
            || self.revision == 0
            || match self.status {
                WorkerLeaseStatus::Active => self.heartbeat_at > self.expires_at,
                WorkerLeaseStatus::Expired => self.heartbeat_at < self.expires_at,
                WorkerLeaseStatus::Released | WorkerLeaseStatus::Revoked => false,
            }
        {
            return Err(ContextError::InvalidWorkerLease);
        }
        Ok(())
    }

    pub fn heartbeat(
        &mut self,
        worker_generation: u64,
        lease_token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        self.authorize_active(worker_generation, lease_token_digest, now, false)?;
        let next_revision = self.next_revision()?;
        self.heartbeat_at = now;
        self.revision = next_revision;
        Ok(())
    }

    pub fn release(
        &mut self,
        worker_generation: u64,
        lease_token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        self.transition_terminal(
            worker_generation,
            lease_token_digest,
            WorkerLeaseStatus::Released,
            now,
            false,
        )
    }

    pub fn revoke(
        &mut self,
        worker_generation: u64,
        lease_token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        self.transition_terminal(
            worker_generation,
            lease_token_digest,
            WorkerLeaseStatus::Revoked,
            now,
            false,
        )
    }

    pub fn expire(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        if self.status != WorkerLeaseStatus::Active
            || now < self.heartbeat_at
            || now < self.expires_at
        {
            return Err(ContextError::InvalidWorkerLeaseTransition);
        }
        let next_revision = self.next_revision()?;
        self.status = WorkerLeaseStatus::Expired;
        self.heartbeat_at = now;
        self.revision = next_revision;
        Ok(())
    }

    pub fn effective_status(&self, now: DateTime<Utc>) -> WorkerLeaseStatus {
        if self.status == WorkerLeaseStatus::Active && now >= self.expires_at {
            WorkerLeaseStatus::Expired
        } else {
            self.status
        }
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        let immutable_scope_matches = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.workspace_id == previous.workspace_id
            && self.branch_id == previous.branch_id
            && self.worker_id == previous.worker_id
            && self.generation == previous.generation
            && self.lease_token_digest == previous.lease_token_digest
            && self.runtime_mapping_digest == previous.runtime_mapping_digest
            && self.issued_at == previous.issued_at
            && self.expires_at == previous.expires_at
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.heartbeat_at >= previous.heartbeat_at;
        if !immutable_scope_matches {
            return Ok(false);
        }
        let mut candidate = previous.clone();
        let transition_result = match self.status {
            WorkerLeaseStatus::Active => candidate.heartbeat(
                previous.generation,
                &previous.lease_token_digest,
                self.heartbeat_at,
            ),
            WorkerLeaseStatus::Released => candidate.release(
                previous.generation,
                &previous.lease_token_digest,
                self.heartbeat_at,
            ),
            WorkerLeaseStatus::Revoked => candidate.revoke(
                previous.generation,
                &previous.lease_token_digest,
                self.heartbeat_at,
            ),
            WorkerLeaseStatus::Expired => candidate.expire(self.heartbeat_at),
        };
        Ok(transition_result.is_ok() && candidate == *self)
    }

    fn authorize_active(
        &self,
        worker_generation: u64,
        lease_token_digest: &str,
        now: DateTime<Utc>,
        allow_expired_at: bool,
    ) -> Result<(), ContextError> {
        if self.status != WorkerLeaseStatus::Active
            || worker_generation != self.generation
            || lease_token_digest != self.lease_token_digest
            || !is_sha256(lease_token_digest)
        {
            return Err(ContextError::WorkerLeaseLost);
        }
        if now < self.heartbeat_at || (!allow_expired_at && now >= self.expires_at) {
            return Err(ContextError::InvalidWorkerLeaseTransition);
        }
        Ok(())
    }

    fn transition_terminal(
        &mut self,
        worker_generation: u64,
        lease_token_digest: &str,
        status: WorkerLeaseStatus,
        now: DateTime<Utc>,
        allow_expired_at: bool,
    ) -> Result<(), ContextError> {
        self.authorize_active(worker_generation, lease_token_digest, now, allow_expired_at)?;
        let next_revision = self.next_revision()?;
        self.status = status;
        self.heartbeat_at = now;
        self.revision = next_revision;
        Ok(())
    }

    fn next_revision(&self) -> Result<u64, ContextError> {
        self.revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextFactGrant {
    pub fact_id: FactId,
    pub version: u64,
    pub classification: ContextDataClass,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextInputRefs {
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub work_product_ids: BTreeSet<WorkProductId>,
    pub file_snapshot_digests: BTreeSet<String>,
    pub query_snapshot_digests: BTreeSet<String>,
}

impl ContextInputRefs {
    fn validate_for(&self, mission: &Mission) -> Result<(), ContextError> {
        if self
            .evidence_ids
            .iter()
            .any(|id| !mission.evidence.iter().any(|evidence| &evidence.id == id))
            || self.work_product_ids.iter().any(|id| {
                !mission
                    .work_products
                    .iter()
                    .any(|work_product| &work_product.id == id)
            })
            || self
                .file_snapshot_digests
                .iter()
                .chain(&self.query_snapshot_digests)
                .any(|digest| !is_sha256(digest))
        {
            return Err(ContextError::InvalidInputReference);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextReturnContract {
    pub schema_id: String,
    pub schema_version: u32,
    pub required_fields: BTreeSet<String>,
    pub allowed_artifact_types: BTreeSet<String>,
    pub evidence_required: bool,
    pub uncertainty_required: bool,
    pub max_result_bytes: u64,
}

impl ContextReturnContract {
    fn validate(&self) -> Result<(), ContextError> {
        if self.schema_id.trim().is_empty()
            || self.schema_version == 0
            || self.required_fields.is_empty()
            || self
                .required_fields
                .iter()
                .chain(&self.allowed_artifact_types)
                .any(|value| value.trim().is_empty())
            || !self.uncertainty_required
            || self.max_result_bytes == 0
        {
            return Err(ContextError::InvalidReturnContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextReturnReceipt {
    pub schema_id: String,
    pub schema_version: u32,
    pub result_digest: String,
    pub result_size_bytes: u64,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub artifact_digests: BTreeSet<String>,
    pub uncertainty_digest: String,
    pub next_recommendation_digest: Option<String>,
    pub submitted_at: DateTime<Utc>,
}

impl ContextReturnReceipt {
    fn validate_for(&self, contract: &ContextReturnContract) -> Result<(), ContextError> {
        if self.schema_id != contract.schema_id
            || self.schema_version != contract.schema_version
            || !is_sha256(&self.result_digest)
            || self.result_size_bytes == 0
            || self.result_size_bytes > contract.max_result_bytes
            || (contract.evidence_required && self.evidence_ids.is_empty())
            || self.artifact_digests.iter().any(|value| !is_sha256(value))
            || (contract.uncertainty_required && !is_sha256(&self.uncertainty_digest))
            || self
                .next_recommendation_digest
                .as_ref()
                .is_some_and(|value| !is_sha256(value))
        {
            return Err(ContextError::InvalidReturnReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextCapsuleStatus {
    Issued,
    Claimed,
    ResultSubmitted,
    Accepted,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextCapsule {
    pub id: ContextCapsuleId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: crate::MissionId,
    pub task_id: TaskId,
    pub workspace_id: ContextWorkspaceId,
    pub branch_id: ContextBranchId,
    pub worker_lease_id: WorkerLeaseId,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub child_goal: String,
    pub required_facts: BTreeSet<ContextFactGrant>,
    pub constraints: Vec<Constraint>,
    pub capabilities: BTreeSet<String>,
    pub budget: ContextBudget,
    pub inputs: ContextInputRefs,
    pub return_contract: ContextReturnContract,
    pub data_policy: ContextDataPolicy,
    pub policy_version: String,
    pub authority_digest: String,
    pub status: ContextCapsuleStatus,
    pub result: Option<ContextReturnReceipt>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revision: u64,
}

impl ContextCapsule {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        id: ContextCapsuleId,
        workspace: &ContextWorkspace,
        branch: &ContextBranch,
        lease: &WorkerLease,
        mission: &Mission,
        child_goal: impl Into<String>,
        task_id: TaskId,
        required_facts: BTreeSet<ContextFactGrant>,
        facts: &[TruthFact],
        capabilities: BTreeSet<String>,
        budget: ContextBudget,
        inputs: ContextInputRefs,
        return_contract: ContextReturnContract,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let mut capsule = Self {
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: mission.id.clone(),
            task_id,
            workspace_id: workspace.id.clone(),
            branch_id: branch.id.clone(),
            worker_lease_id: lease.id.clone(),
            worker_id: lease.worker_id.clone(),
            worker_generation: lease.generation,
            child_goal: child_goal.into().trim().to_owned(),
            required_facts,
            constraints: mission.contract.constraints.clone(),
            capabilities,
            budget,
            inputs,
            return_contract,
            data_policy: workspace.data_policy,
            policy_version: workspace.policy_version.clone(),
            authority_digest: String::new(),
            status: ContextCapsuleStatus::Issued,
            result: None,
            issued_at: now,
            expires_at,
            updated_at: now,
            revision: 1,
        };
        capsule.authority_digest = capsule.compute_authority_digest()?;
        capsule.validate_for(workspace, branch, lease, mission, facts, now)?;
        Ok(capsule)
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        branch: &ContextBranch,
        lease: &WorkerLease,
        mission: &Mission,
        facts: &[TruthFact],
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        workspace.validate_for(mission, now)?;
        branch.validate_for_workspace(workspace, now)?;
        lease.validate_for(workspace, branch, now)?;
        self.return_contract.validate()?;
        self.inputs.validate_for(mission)?;
        self.budget.validate_at(self.issued_at)?;
        let branch_status_matches = match self.status {
            ContextCapsuleStatus::Accepted => matches!(
                branch.status,
                ContextBranchStatus::Active
                    | ContextBranchStatus::Completed
                    | ContextBranchStatus::Merged
            ),
            ContextCapsuleStatus::Cancelled | ContextCapsuleStatus::Expired => matches!(
                branch.status,
                ContextBranchStatus::Active | ContextBranchStatus::Abandoned
            ),
            ContextCapsuleStatus::Issued
            | ContextCapsuleStatus::Claimed
            | ContextCapsuleStatus::ResultSubmitted => branch.status == ContextBranchStatus::Active,
        };
        let lease_status_matches = match self.status {
            ContextCapsuleStatus::Cancelled => matches!(
                lease.status,
                WorkerLeaseStatus::Active | WorkerLeaseStatus::Revoked | WorkerLeaseStatus::Expired
            ),
            ContextCapsuleStatus::Expired => matches!(
                lease.status,
                WorkerLeaseStatus::Active | WorkerLeaseStatus::Revoked | WorkerLeaseStatus::Expired
            ),
            ContextCapsuleStatus::Issued
            | ContextCapsuleStatus::Claimed
            | ContextCapsuleStatus::ResultSubmitted
            | ContextCapsuleStatus::Accepted => lease.status == WorkerLeaseStatus::Active,
        };
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != mission.id
            || self.workspace_id != workspace.id
            || self.branch_id != branch.id
            || !branch_status_matches
            || self.worker_lease_id != lease.id
            || self.worker_id != lease.worker_id
            || self.worker_generation != lease.generation
            || self.worker_generation != branch.generation
            || !lease_status_matches
            || self.child_goal.is_empty()
            || self.constraints != mission.contract.constraints
            || self.capabilities.is_empty()
            || self
                .capabilities
                .iter()
                .any(|capability| capability.trim().is_empty())
            || !self.capabilities.is_subset(&workspace.capability_authority)
            || !self
                .capabilities
                .is_subset(&mission.contract.enabled_capabilities)
            || !self
                .capabilities
                .is_disjoint(&mission.contract.forbidden_capabilities)
            || !self.budget.is_subset_of(&workspace.budget)
            || self.data_policy != workspace.data_policy
            || self.policy_version != workspace.policy_version
            || self.issued_at < lease.issued_at
            || self.issued_at > now
            || self.expires_at <= self.issued_at
            || self.expires_at > lease.expires_at
            || self.expires_at > self.budget.deadline_at
            || self.updated_at < self.issued_at
            || self.updated_at > now
            || self.revision == 0
            || self.authority_digest != self.compute_authority_digest()?
        {
            return Err(ContextError::InvalidCapsule);
        }
        let task = mission
            .tasks
            .iter()
            .find(|task| task.id == self.task_id)
            .ok_or(ContextError::UnknownTask)?;
        if !self.capabilities.contains(&task.capability) {
            return Err(ContextError::CapabilityEscalation);
        }
        self.validate_fact_closure(facts, now)?;
        match (&self.status, &self.result) {
            (
                ContextCapsuleStatus::Issued
                | ContextCapsuleStatus::Claimed
                | ContextCapsuleStatus::Cancelled
                | ContextCapsuleStatus::Expired,
                None,
            ) => {}
            (
                ContextCapsuleStatus::ResultSubmitted | ContextCapsuleStatus::Accepted,
                Some(result),
            ) => {
                result.validate_for(&self.return_contract)?;
                if result.submitted_at < self.issued_at || result.submitted_at > self.updated_at {
                    return Err(ContextError::InvalidReturnReceipt);
                }
            }
            _ => return Err(ContextError::InvalidCapsuleState),
        }
        Ok(())
    }

    fn validate_fact_closure(
        &self,
        facts: &[TruthFact],
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        let fact_keys = facts
            .iter()
            .map(|fact| (fact.id.clone(), fact.version))
            .collect::<BTreeSet<_>>();
        let grant_keys = self
            .required_facts
            .iter()
            .map(|grant| (grant.fact_id.clone(), grant.version))
            .collect::<BTreeSet<_>>();
        let fact_ids = facts
            .iter()
            .map(|fact| fact.id.clone())
            .collect::<BTreeSet<_>>();
        let grant_ids = self
            .required_facts
            .iter()
            .map(|grant| grant.fact_id.clone())
            .collect::<BTreeSet<_>>();
        if fact_keys.len() != facts.len()
            || grant_keys.len() != self.required_facts.len()
            || fact_ids.len() != facts.len()
            || grant_ids.len() != self.required_facts.len()
            || fact_keys != grant_keys
        {
            return Err(ContextError::InvalidFactClosure);
        }
        for fact in facts {
            fact.validate(now)
                .map_err(|_| ContextError::InvalidFactClosure)?;
            if fact.tenant_id != self.tenant_id || fact.project_id != self.project_id {
                return Err(ContextError::InvalidFactClosure);
            }
        }
        if self
            .required_facts
            .iter()
            .any(|grant| grant.classification > self.data_policy.maximum_class())
        {
            return Err(ContextError::DataPolicyEscalation);
        }
        Ok(())
    }

    pub fn claim(
        &mut self,
        worker_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != ContextCapsuleStatus::Issued
            || worker_generation != self.worker_generation
            || now > self.expires_at
        {
            return Err(ContextError::InvalidCapsuleTransition);
        }
        let next_revision = self.prepare_touch(now)?;
        self.status = ContextCapsuleStatus::Claimed;
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn submit_result(
        &mut self,
        worker_generation: u64,
        result: ContextReturnReceipt,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != ContextCapsuleStatus::Claimed
            || worker_generation != self.worker_generation
            || now > self.expires_at
            || result.submitted_at != now
        {
            return Err(ContextError::InvalidCapsuleTransition);
        }
        result.validate_for(&self.return_contract)?;
        let next_revision = self.prepare_touch(now)?;
        self.result = Some(result);
        self.status = ContextCapsuleStatus::ResultSubmitted;
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn accept_result(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        if self.status != ContextCapsuleStatus::ResultSubmitted {
            return Err(ContextError::InvalidCapsuleTransition);
        }
        let next_revision = self.prepare_touch(now)?;
        self.status = ContextCapsuleStatus::Accepted;
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn cancel(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        if !matches!(
            self.status,
            ContextCapsuleStatus::Issued | ContextCapsuleStatus::Claimed
        ) {
            return Err(ContextError::InvalidCapsuleTransition);
        }
        let next_revision = self.prepare_touch(now)?;
        self.status = ContextCapsuleStatus::Cancelled;
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn expire(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        if !matches!(
            self.status,
            ContextCapsuleStatus::Issued | ContextCapsuleStatus::Claimed
        ) || now <= self.expires_at
        {
            return Err(ContextError::InvalidCapsuleTransition);
        }
        let next_revision = self.prepare_touch(now)?;
        self.status = ContextCapsuleStatus::Expired;
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        let immutable_matches = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.task_id == previous.task_id
            && self.workspace_id == previous.workspace_id
            && self.branch_id == previous.branch_id
            && self.worker_lease_id == previous.worker_lease_id
            && self.worker_id == previous.worker_id
            && self.worker_generation == previous.worker_generation
            && self.child_goal == previous.child_goal
            && self.required_facts == previous.required_facts
            && self.constraints == previous.constraints
            && self.capabilities == previous.capabilities
            && self.budget == previous.budget
            && self.inputs == previous.inputs
            && self.return_contract == previous.return_contract
            && self.data_policy == previous.data_policy
            && self.policy_version == previous.policy_version
            && self.authority_digest == previous.authority_digest
            && self.issued_at == previous.issued_at
            && self.expires_at == previous.expires_at;
        let transition_allowed = match (&previous.status, &self.status) {
            (ContextCapsuleStatus::Issued, ContextCapsuleStatus::Claimed)
            | (
                ContextCapsuleStatus::Issued | ContextCapsuleStatus::Claimed,
                ContextCapsuleStatus::Cancelled | ContextCapsuleStatus::Expired,
            ) => self.result.is_none(),
            (ContextCapsuleStatus::Claimed, ContextCapsuleStatus::ResultSubmitted) => {
                previous.result.is_none() && self.result.is_some()
            }
            (ContextCapsuleStatus::ResultSubmitted, ContextCapsuleStatus::Accepted) => {
                self.result == previous.result
            }
            _ => false,
        };
        Ok(immutable_matches
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.updated_at >= previous.updated_at
            && transition_allowed)
    }

    fn compute_authority_digest(&self) -> Result<String, ContextError> {
        digest_json(&(
            (
                &self.id,
                &self.tenant_id,
                &self.project_id,
                &self.mission_id,
                &self.task_id,
                &self.workspace_id,
                &self.branch_id,
                &self.worker_lease_id,
                &self.worker_id,
                self.worker_generation,
                &self.child_goal,
            ),
            (
                &self.required_facts,
                &self.constraints,
                &self.capabilities,
                &self.budget,
                &self.inputs,
                &self.return_contract,
                self.data_policy,
                &self.policy_version,
                self.issued_at,
                self.expires_at,
            ),
        ))
    }

    fn prepare_touch(&self, now: DateTime<Utc>) -> Result<u64, ContextError> {
        if now < self.updated_at {
            return Err(ContextError::InvalidCapsuleTransition);
        }
        self.revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)
    }

    fn commit_touch(&mut self, next_revision: u64, now: DateTime<Utc>) {
        self.revision = next_revision;
        self.updated_at = now;
    }
}

pub fn validate_context_branch_lineage(
    workspace: &ContextWorkspace,
    branches: &[ContextBranch],
    now: DateTime<Utc>,
) -> Result<(), ContextError> {
    if branches.is_empty() {
        return Err(ContextError::InvalidBranchLineage);
    }
    let mut seen = BTreeSet::new();
    for (index, branch) in branches.iter().enumerate() {
        if !seen.insert(branch.id.clone()) {
            return Err(ContextError::InvalidBranchLineage);
        }
        let parent = index.checked_sub(1).map(|parent| &branches[parent]);
        branch.validate_for(workspace, parent, now)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContextError {
    #[error("context budget is invalid or exceeds its parent")]
    InvalidBudget,
    #[error("context workspace is incomplete or exceeds mission authority")]
    InvalidWorkspace,
    #[error("context branch is invalid")]
    InvalidBranch,
    #[error("context branch lineage is incomplete or discontinuous")]
    InvalidBranchLineage,
    #[error("worker lease is invalid or belongs to another generation")]
    InvalidWorkerLease,
    #[error("worker lease token, generation, or active owner no longer matches")]
    WorkerLeaseLost,
    #[error("worker lease heartbeat or terminal transition is invalid")]
    InvalidWorkerLeaseTransition,
    #[error("context input references are not available in the mission")]
    InvalidInputReference,
    #[error("context return contract is invalid")]
    InvalidReturnContract,
    #[error("context return receipt does not satisfy its exact contract")]
    InvalidReturnReceipt,
    #[error("context capsule is invalid")]
    InvalidCapsule,
    #[error("context capsule state/result shape is invalid")]
    InvalidCapsuleState,
    #[error("context capsule transition is invalid")]
    InvalidCapsuleTransition,
    #[error("context capsule references an unknown mission task")]
    UnknownTask,
    #[error("context capsule capability exceeds workspace or mission authority")]
    CapabilityEscalation,
    #[error("context capsule fact closure is incomplete, duplicated, or out of scope")]
    InvalidFactClosure,
    #[error("context capsule data classification exceeds its policy")]
    DataPolicyEscalation,
    #[error("working-set item is malformed, unsafe, expired at creation, or outside data policy")]
    InvalidWorkingItem,
    #[error("working set is malformed, unbounded, stale, or outside its workspace")]
    InvalidWorkingSet,
    #[error("continuation entry is malformed or does not reference the current mission revision")]
    InvalidContinuationEntry,
    #[error("continuation ledger is malformed, rewritten, or outside its workspace")]
    InvalidContinuationLedger,
    #[error("typed context invariant block does not exactly match authoritative mission truth")]
    ContextInvariantMismatch,
    #[error("compaction record is malformed, discontinuous, or loses typed invariants")]
    InvalidCompactionRecord,
    #[error("context checkpoint is malformed, stale, or does not close over its dependencies")]
    InvalidContextCheckpoint,
    #[error("runtime recovery attempt is malformed, stale, or outside its checkpoint fence")]
    InvalidRuntimeRecovery,
    #[error("context branch lifecycle or typed merge is invalid")]
    InvalidBranchTransition,
    #[error("worker handle is malformed, stale, detached, or outside parent authority")]
    InvalidWorkerHandle,
    #[error(
        "worker mailbox or message transition is malformed or belongs to an old attachment epoch"
    )]
    InvalidWorkerMessage,
    #[error("worker mailbox reached its bounded pending-message capacity")]
    ContextBackpressure,
    #[error(
        "worker usage exceeds its inherited token, cost, deadline, depth, or concurrency budget"
    )]
    WorkerBudgetExceeded,
    #[error("context foundation revision changed before the atomic checkpoint was committed")]
    StaleContextFoundation,
    #[error("context revision overflow")]
    RevisionOverflow,
    #[error("context digest could not be serialized")]
    Serialization,
}

fn digest_json(value: &impl Serialize) -> Result<String, ContextError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ContextError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::{
        ActorId, ApprovalPolicy, AutonomyLevel, CurrencyCode, EffectClass, Evidence,
        EvidenceStatus, MissionContract, Task, TaskStatus, TruthSource, TruthStatus, TruthValue,
    };
    use proptest::prelude::*;
    use rust_decimal::Decimal;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn mission() -> Mission {
        let contract = MissionContract {
            version: 1,
            mode: crate::OperatingMode::BuildOnce,
            parent_mission_id: None,
            goal: "Produce a bounded market finding".into(),
            non_goals: vec!["Do not publish".into()],
            market: "DE".into(),
            language: "de".into(),
            audience: "owner".into(),
            kpis: BTreeMap::new(),
            budget: Money::new(5_000, CurrencyCode::parse("EUR").expect("EUR")),
            timezone: "Europe/Berlin".into(),
            cadence: None,
            autonomy_by_capability: BTreeMap::from([
                ("search.read".into(), AutonomyLevel::ApprovalRequired),
                ("market.analyze".into(), AutonomyLevel::ApprovalRequired),
            ]),
            consent_requirements: BTreeSet::new(),
            approval_policy: ApprovalPolicy {
                required_effect_classes: BTreeSet::from([EffectClass::ExternalWrite]),
                validity_seconds: 3_600,
                exact_scope_required: true,
            },
            stop_conditions: vec!["user_cancelled".into()],
            completion_conditions: vec!["typed_result_returned".into()],
            valid_from: now(),
            valid_until: now() + Duration::hours(2),
            constraints: vec![Constraint::Market { value: "DE".into() }],
            enabled_capabilities: BTreeSet::from(["search.read".into(), "market.analyze".into()]),
            forbidden_capabilities: BTreeSet::from(["channel.publish".into()]),
        };
        let mut mission = Mission::compile(
            TenantId::from("tenant-context"),
            crate::MissionId::from("mission-context"),
            ProjectId::from("project-context"),
            "Context mission",
            contract,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-context"),
                    title: "Research demand".into(),
                    status: TaskStatus::Ready,
                    capability: "search.read".into(),
                }],
                now(),
            )
            .expect("task");
        mission
    }

    fn fact(mission: &Mission) -> TruthFact {
        TruthFact::create(
            FactId::from("fact-context"),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            "market.query",
            Some(TruthValue::Text("ergonomic keyboard".into())),
            vec![],
            TruthStatus::Confirmed,
            Some(TruthSource {
                provider: "user".into(),
                source_uri: "fixture://context/fact".into(),
                source_digest: "1".repeat(64),
                evidence_ids: BTreeSet::from([EvidenceId::from("evidence-context")]),
                captured_by: ActorId::from("user-context"),
                captured_at: now(),
            }),
            "DE",
            "de",
            now(),
            now(),
            None,
            Decimal::ONE,
            now(),
        )
        .expect("fact")
    }

    fn context_bundle() -> (
        Mission,
        TruthFact,
        ContextWorkspace,
        ContextBranch,
        WorkerLease,
        ContextCapsule,
    ) {
        let mut mission = mission();
        mission.evidence.push(Evidence {
            id: EvidenceId::from("evidence-context"),
            title: "User scope".into(),
            source_uri: "fixture://context/evidence".into(),
            observed_at: now(),
            confidence: 1.0,
            status: EvidenceStatus::Confirmed,
            content_digest: "2".repeat(64),
        });
        let fact = fact(&mission);
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-context"),
            &mission,
            3,
            "context-policy/v1",
            mission.contract.enabled_capabilities.clone(),
            ContextBudget {
                token_limit: 20_000,
                cost_limit: Money::new(2_000, CurrencyCode::parse("EUR").expect("EUR")),
                deadline_at: now() + Duration::hours(1),
                max_depth: 3,
                max_concurrency: 2,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let branch = ContextBranch::create(
            ContextBranchId::from("branch-context"),
            &workspace,
            None,
            "isolate demand research",
            "3".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("branch");
        let lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-context"),
            &workspace,
            &branch,
            WorkerId::from("worker-context"),
            3,
            "4".repeat(64),
            Some("5".repeat(64)),
            now() + Duration::minutes(45),
            now(),
        )
        .expect("lease");
        let capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-context"),
            &workspace,
            &branch,
            &lease,
            &mission,
            "Return a sourced demand finding",
            TaskId::from("task-context"),
            BTreeSet::from([ContextFactGrant {
                fact_id: fact.id.clone(),
                version: fact.version,
                classification: ContextDataClass::Business,
            }]),
            std::slice::from_ref(&fact),
            BTreeSet::from(["search.read".into()]),
            ContextBudget {
                token_limit: 5_000,
                cost_limit: Money::new(500, CurrencyCode::parse("EUR").expect("EUR")),
                deadline_at: now() + Duration::minutes(30),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs {
                evidence_ids: BTreeSet::from([EvidenceId::from("evidence-context")]),
                ..ContextInputRefs::default()
            },
            ContextReturnContract {
                schema_id: "hartevo.context.market-finding".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["finding".into(), "confidence".into()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: true,
                uncertainty_required: true,
                max_result_bytes: 64 * 1024,
            },
            now() + Duration::minutes(30),
            now(),
        )
        .expect("capsule");
        (mission, fact, workspace, branch, lease, capsule)
    }

    fn model_return(submitted_at: DateTime<Utc>) -> ContextReturnReceipt {
        ContextReturnReceipt {
            schema_id: "hartevo.context.market-finding".into(),
            schema_version: 1,
            result_digest: "6".repeat(64),
            result_size_bytes: 128,
            evidence_ids: BTreeSet::from([EvidenceId::from("evidence-context")]),
            artifact_digests: BTreeSet::new(),
            uncertainty_digest: "7".repeat(64),
            next_recommendation_digest: None,
            submitted_at,
        }
    }

    fn advance_capsule(
        capsule: &mut ContextCapsule,
        at: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        let generation = capsule.worker_generation;
        match capsule.status {
            ContextCapsuleStatus::Issued => capsule.claim(generation, at),
            ContextCapsuleStatus::Claimed => {
                capsule.submit_result(generation, model_return(at), at)
            }
            ContextCapsuleStatus::ResultSubmitted => capsule.accept_result(at),
            ContextCapsuleStatus::Accepted
            | ContextCapsuleStatus::Cancelled
            | ContextCapsuleStatus::Expired => capsule.cancel(at),
        }
    }

    #[test]
    fn capsule_rejects_capability_budget_and_data_policy_escalation() {
        let (mission, fact, workspace, branch, lease, capsule) = context_bundle();
        let mut elevated = capsule.clone();
        elevated.capabilities.insert("channel.publish".into());
        elevated.authority_digest = elevated.compute_authority_digest().expect("digest");
        assert_eq!(
            elevated.validate_for(
                &workspace,
                &branch,
                &lease,
                &mission,
                std::slice::from_ref(&fact),
                now()
            ),
            Err(ContextError::InvalidCapsule)
        );

        let mut expensive = capsule.clone();
        expensive.budget.cost_limit.amount_minor = 2_001;
        expensive.authority_digest = expensive.compute_authority_digest().expect("digest");
        assert_eq!(
            expensive.validate_for(
                &workspace,
                &branch,
                &lease,
                &mission,
                std::slice::from_ref(&fact),
                now()
            ),
            Err(ContextError::InvalidCapsule)
        );

        let mut private = capsule;
        private.required_facts = BTreeSet::from([ContextFactGrant {
            fact_id: fact.id.clone(),
            version: fact.version,
            classification: ContextDataClass::RedactedPersonal,
        }]);
        private.authority_digest = private.compute_authority_digest().expect("digest");
        assert_eq!(
            private.validate_for(&workspace, &branch, &lease, &mission, &[fact], now()),
            Err(ContextError::DataPolicyEscalation)
        );
    }

    #[test]
    fn old_worker_generation_cannot_claim_or_return_a_capsule() {
        let (_, _, _, _, _, mut capsule) = context_bundle();
        assert_eq!(
            capsule.claim(2, now() + Duration::minutes(1)),
            Err(ContextError::InvalidCapsuleTransition)
        );
        capsule
            .claim(3, now() + Duration::minutes(1))
            .expect("current generation claims");
        assert_eq!(
            capsule.submit_result(
                2,
                ContextReturnReceipt {
                    schema_id: "hartevo.context.market-finding".into(),
                    schema_version: 1,
                    result_digest: "6".repeat(64),
                    result_size_bytes: 128,
                    evidence_ids: BTreeSet::from([EvidenceId::from("evidence-context")]),
                    artifact_digests: BTreeSet::new(),
                    uncertainty_digest: "7".repeat(64),
                    next_recommendation_digest: None,
                    submitted_at: now() + Duration::minutes(2),
                },
                now() + Duration::minutes(2),
            ),
            Err(ContextError::InvalidCapsuleTransition)
        );
    }

    #[test]
    fn capsule_history_accepts_only_one_exact_state_transition() {
        let (_, _, _, _, _, capsule) = context_bundle();
        let mut claimed = capsule.clone();
        claimed
            .claim(3, now() + Duration::minutes(1))
            .expect("claim");
        assert!(claimed.follows(&capsule).expect("transition"));

        let mut jumped = claimed.clone();
        jumped.revision += 1;
        assert!(!jumped.follows(&capsule).expect("jump rejected"));

        let mut rewritten = claimed;
        rewritten.child_goal = "silently changed scope".into();
        rewritten.authority_digest = rewritten.compute_authority_digest().expect("digest");
        assert!(!rewritten.follows(&capsule).expect("rewrite rejected"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn arbitrary_worker_lease_sequences_are_atomic_token_and_generation_fenced(
            actions in prop::collection::vec((0_u8..9, 0_i64..4), 1..64),
        ) {
            let (_, _, workspace, branch, mut lease, _) = context_bundle();
            let initial = lease.clone();
            let token_digest = "4".repeat(64);
            let mut cursor = now();

            for (action, advance_minutes) in actions {
                cursor += Duration::minutes(advance_minutes);
                let before = lease.clone();
                let mut command_targets_lease = true;
                let result = match action {
                    0 => lease.heartbeat(lease.generation, &token_digest, cursor),
                    1 => lease.heartbeat(
                        lease.generation.saturating_add(1),
                        &token_digest,
                        cursor,
                    ),
                    2 => lease.heartbeat(lease.generation, &"9".repeat(64), cursor),
                    3 => lease.release(lease.generation, &token_digest, cursor),
                    4 => lease.revoke(lease.generation, &token_digest, cursor),
                    5 => {
                        cursor = cursor.max(lease.expires_at);
                        lease.expire(cursor)
                    }
                    6 => lease.heartbeat(
                        lease.generation,
                        &token_digest,
                        before.heartbeat_at - Duration::seconds(1),
                    ),
                    7 => {
                        command_targets_lease = false;
                        let mut overflow = lease.clone();
                        overflow.revision = u64::MAX;
                        let overflow_before = overflow.clone();
                        let command_at = cursor.max(overflow.heartbeat_at);
                        let overflow_result = overflow.heartbeat(
                            overflow.generation,
                            &token_digest,
                            command_at,
                        );
                        prop_assert!(overflow_result.is_err());
                        prop_assert_eq!(overflow, overflow_before);
                        Ok(())
                    }
                    _ => {
                        cursor = cursor.max(lease.expires_at);
                        lease.release(lease.generation, &token_digest, cursor)
                    }
                };

                if command_targets_lease && result.is_ok() {
                    prop_assert_eq!(lease.revision, before.revision + 1);
                    prop_assert!(lease.follows(&before).expect("lease command"));
                } else {
                    prop_assert_eq!(lease.clone(), before);
                }
                prop_assert_eq!(lease.id.clone(), initial.id.clone());
                prop_assert_eq!(lease.tenant_id.clone(), initial.tenant_id.clone());
                prop_assert_eq!(lease.project_id.clone(), initial.project_id.clone());
                prop_assert_eq!(lease.workspace_id.clone(), initial.workspace_id.clone());
                prop_assert_eq!(lease.branch_id.clone(), initial.branch_id.clone());
                prop_assert_eq!(lease.worker_id.clone(), initial.worker_id.clone());
                prop_assert_eq!(lease.generation, initial.generation);
                prop_assert_eq!(lease.lease_token_digest.clone(), initial.lease_token_digest.clone());
                let validation_now = cursor.max(lease.heartbeat_at);
                prop_assert!(lease.validate_for(&workspace, &branch, validation_now).is_ok());
                prop_assert_eq!(
                    lease.effective_status(validation_now),
                    if lease.status == WorkerLeaseStatus::Active
                        && validation_now >= lease.expires_at
                    {
                        WorkerLeaseStatus::Expired
                    } else {
                        lease.status
                    },
                );
                if matches!(
                    lease.status,
                    WorkerLeaseStatus::Released
                        | WorkerLeaseStatus::Revoked
                        | WorkerLeaseStatus::Expired
                ) {
                    let terminal = lease.clone();
                    prop_assert!(lease.heartbeat(
                        lease.generation,
                        &token_digest,
                        validation_now,
                    ).is_err());
                    prop_assert_eq!(lease.clone(), terminal);
                }
            }
        }

        #[test]
        fn arbitrary_capsule_sequences_are_atomic_generation_fenced_and_authority_bounded(
            actions in prop::collection::vec((0_u8..10, 0_i64..4), 1..64),
        ) {
            let (mission, fact, workspace, branch, lease, mut capsule) = context_bundle();
            let initial = capsule.clone();
            let mut cursor = now();

            for (action, advance_minutes) in actions {
                cursor += Duration::minutes(advance_minutes);
                let before = capsule.clone();
                let mut command_targets_capsule = true;
                let result = match action {
                    0 => advance_capsule(&mut capsule, cursor),
                    1 => {
                        let wrong_generation = capsule.worker_generation.saturating_add(1);
                        match capsule.status {
                            ContextCapsuleStatus::Issued => {
                                capsule.claim(wrong_generation, cursor)
                            }
                            ContextCapsuleStatus::Claimed => capsule.submit_result(
                                wrong_generation,
                                model_return(cursor),
                                cursor,
                            ),
                            _ => capsule.claim(wrong_generation, cursor),
                        }
                    }
                    2 => capsule.cancel(cursor),
                    3 => {
                        cursor = cursor.max(capsule.expires_at + Duration::seconds(1));
                        capsule.expire(cursor)
                    }
                    4 => advance_capsule(
                        &mut capsule,
                        before.updated_at - Duration::seconds(1),
                    ),
                    5 => {
                        command_targets_capsule = false;
                        let mut overflow = capsule.clone();
                        overflow.revision = u64::MAX;
                        let overflow_before = overflow.clone();
                        let command_at = cursor.max(overflow.updated_at);
                        let overflow_result = advance_capsule(&mut overflow, command_at);
                        prop_assert!(overflow_result.is_err());
                        prop_assert_eq!(overflow, overflow_before);
                        Ok(())
                    }
                    6 => {
                        command_targets_capsule = false;
                        let mut tampered = capsule.clone();
                        tampered.authority_digest = "0".repeat(64);
                        let validation_now = cursor.max(tampered.updated_at);
                        prop_assert!(tampered
                            .validate_for(
                                &workspace,
                                &branch,
                                &lease,
                                &mission,
                                std::slice::from_ref(&fact),
                                validation_now,
                            )
                            .is_err());
                        Ok(())
                    }
                    7 => capsule.submit_result(
                        capsule.worker_generation,
                        ContextReturnReceipt {
                            result_digest: "not-a-digest".into(),
                            ..model_return(cursor)
                        },
                        cursor,
                    ),
                    8 => {
                        cursor = cursor.max(capsule.expires_at);
                        advance_capsule(&mut capsule, cursor)
                    }
                    _ => capsule.claim(capsule.worker_generation, cursor),
                };

                let command_succeeded = command_targets_capsule && result.is_ok();
                if command_succeeded {
                    prop_assert_eq!(capsule.revision, before.revision + 1);
                    prop_assert!(capsule.updated_at >= before.updated_at);
                    prop_assert!(capsule.follows(&before).expect("transition comparison"));
                } else {
                    prop_assert_eq!(capsule.clone(), before.clone());
                }
                if matches!(
                    before.status,
                    ContextCapsuleStatus::Accepted
                        | ContextCapsuleStatus::Cancelled
                        | ContextCapsuleStatus::Expired
                ) && command_targets_capsule
                {
                    prop_assert!(result.is_err());
                }
                prop_assert_eq!(capsule.id.clone(), initial.id.clone());
                prop_assert_eq!(capsule.tenant_id.clone(), initial.tenant_id.clone());
                prop_assert_eq!(capsule.project_id.clone(), initial.project_id.clone());
                prop_assert_eq!(capsule.workspace_id.clone(), initial.workspace_id.clone());
                prop_assert_eq!(capsule.branch_id.clone(), initial.branch_id.clone());
                prop_assert_eq!(capsule.worker_lease_id.clone(), initial.worker_lease_id.clone());
                prop_assert_eq!(capsule.worker_generation, initial.worker_generation);
                prop_assert_eq!(capsule.authority_digest.clone(), initial.authority_digest.clone());
                let validation_now = cursor.max(capsule.updated_at);
                prop_assert!(capsule
                    .validate_for(
                        &workspace,
                        &branch,
                        &lease,
                        &mission,
                        std::slice::from_ref(&fact),
                        validation_now,
                    )
                    .is_ok());
            }
        }
    }
}

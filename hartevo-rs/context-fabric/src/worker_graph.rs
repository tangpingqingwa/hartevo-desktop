//! Durable, content-free Worker Graph control state.
//!
//! The graph is a projection over the existing Context Branch/Worker/Lease
//! rows.  It carries only digests, revisions, generation fences and usage;
//! worker bodies and provider facts remain in their owning stores.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const WORKER_GRAPH_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerKind {
    Runtime,
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    Planned,
    Claimed,
    Detached,
    Returned,
    Rejected,
    Abandoned,
    Merged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerClaimState {
    Active,
    Detached,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerLeaseState {
    Active,
    Released,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerReturnState {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerGraphDisposition {
    Applied,
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerGraphRestartDisposition {
    ExactReplay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnContract {
    pub schema_digest: String,
    pub required_evidence: bool,
    pub max_result_bytes: u64,
    pub max_tokens: u64,
    pub max_cost_minor: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageAccount {
    pub token_spent: u64,
    pub cost_spent_minor: i64,
    pub tool_calls: u64,
    pub runtime_millis: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerSpec {
    pub worker_id_digest: String,
    pub parent_worker_id_digest: Option<String>,
    pub kind: WorkerKind,
    pub branch_digest: String,
    pub capability_digest: String,
    pub return_contract: ReturnContract,
    pub generation: u64,
    pub revision: u64,
    pub state: WorkerState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerClaim {
    pub worker_id_digest: String,
    pub owner_digest: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub lease_expires_at: DateTime<Utc>,
    pub state: WorkerClaimState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerLease {
    pub worker_id_digest: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub lease_token_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: WorkerLeaseState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffRecord {
    pub worker_id_digest: String,
    pub from_owner_digest: String,
    pub to_owner_digest: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub attachment_epoch: u64,
    pub reason_digest: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerReturn {
    pub worker_id_digest: String,
    pub owner_digest: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub idempotency_digest: String,
    pub result_digest: String,
    pub state: WorkerReturnState,
    pub usage: UsageAccount,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerMerge {
    pub source_worker_id_digest: String,
    pub target_worker_id_digest: String,
    pub idempotency_digest: String,
    pub result_digest: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerGraphDefinition {
    pub tenant_digest: String,
    pub project_digest: String,
    pub mission_digest: String,
    pub workspace_digest: String,
    pub source_revision: u64,
    pub source_digest: String,
    pub workers: Vec<WorkerSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerClaimRequest {
    pub worker_id_digest: String,
    pub owner: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub lease_token_digest: String,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerReattachRequest {
    pub worker_id_digest: String,
    pub owner: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub lease_token_digest: String,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerHandoffRequest {
    pub worker_id_digest: String,
    pub owner: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub next_owner: String,
    pub reason_digest: String,
    pub lease_token_digest: String,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerReturnRequest {
    pub worker_id_digest: String,
    pub owner: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub idempotency_key: String,
    pub result_digest: String,
    pub usage: UsageAccount,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerGraph {
    pub schema_version: u32,
    pub tenant_digest: String,
    pub project_digest: String,
    pub mission_digest: String,
    pub workspace_digest: String,
    pub source_revision: u64,
    pub source_digest: String,
    pub graph_revision: u64,
    pub workers: Vec<WorkerSpec>,
    pub claims: Vec<WorkerClaim>,
    pub leases: Vec<WorkerLease>,
    pub usage: BTreeMap<String, UsageAccount>,
    pub handoffs: Vec<HandoffRecord>,
    pub returns: Vec<WorkerReturn>,
    pub merges: Vec<WorkerMerge>,
}

impl std::fmt::Debug for WorkerGraph {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerGraph")
            .field("schema_version", &self.schema_version)
            .field("tenant_digest", &short(&self.tenant_digest))
            .field("project_digest", &short(&self.project_digest))
            .field("mission_digest", &short(&self.mission_digest))
            .field("workspace_digest", &short(&self.workspace_digest))
            .field("source_revision", &self.source_revision)
            .field("source_digest", &short(&self.source_digest))
            .field("graph_revision", &self.graph_revision)
            .field("worker_count", &self.workers.len())
            .field("claim_count", &self.claims.len())
            .field("lease_count", &self.leases.len())
            .field("handoff_count", &self.handoffs.len())
            .field("return_count", &self.returns.len())
            .field("merge_count", &self.merges.len())
            .field("usage_worker_count", &self.usage.len())
            .finish()
    }
}

impl WorkerGraph {
    pub fn new(
        definition: WorkerGraphDefinition,
        now: DateTime<Utc>,
    ) -> Result<Self, WorkerGraphError> {
        let value = Self {
            schema_version: WORKER_GRAPH_SCHEMA_VERSION,
            tenant_digest: definition.tenant_digest,
            project_digest: definition.project_digest,
            mission_digest: definition.mission_digest,
            workspace_digest: definition.workspace_digest,
            source_revision: definition.source_revision,
            source_digest: definition.source_digest,
            graph_revision: 1,
            workers: definition.workers,
            claims: Vec::new(),
            leases: Vec::new(),
            usage: BTreeMap::new(),
            handoffs: Vec::new(),
            returns: Vec::new(),
            merges: Vec::new(),
        };
        value.validate(now)?;
        Ok(value)
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), WorkerGraphError> {
        if self.schema_version != WORKER_GRAPH_SCHEMA_VERSION
            || self.source_revision == 0
            || self.graph_revision == 0
            || !valid_digest(&self.tenant_digest)
            || !valid_digest(&self.project_digest)
            || !valid_digest(&self.mission_digest)
            || !valid_digest(&self.workspace_digest)
            || !valid_digest(&self.source_digest)
        {
            return Err(WorkerGraphError::InvalidGraph);
        }
        validate_workers(&self.workers)?;
        validate_claims(&self.claims, &self.workers, now)?;
        validate_leases(&self.leases, &self.workers)?;
        validate_handoffs(&self.handoffs, &self.workers)?;
        validate_returns(&self.returns, &self.workers)?;
        validate_merges(&self.merges, &self.workers)?;
        for (worker_id, account) in &self.usage {
            if !valid_digest(worker_id) || account.cost_spent_minor < 0 {
                return Err(WorkerGraphError::InvalidUsage);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, WorkerGraphError> {
        self.validate(Utc::now())?;
        serde_json::to_vec(self)
            .map(|bytes| digest(&bytes))
            .map_err(|_| WorkerGraphError::InvalidGraph)
    }

    pub fn claim(
        &self,
        request: WorkerClaimRequest,
        now: DateTime<Utc>,
    ) -> Result<(Self, WorkerGraphDisposition), WorkerGraphError> {
        self.validate(now)?;
        validate_claim_input(&request, now)?;
        let worker_index = self.worker_index(&request.worker_id_digest)?;
        if request.generation != self.workers[worker_index].generation {
            return Err(WorkerGraphError::StaleGeneration);
        }
        let current_claim = latest_claim(&self.claims, &request.worker_id_digest);
        if let Some(claim) = current_claim {
            if claim.state == WorkerClaimState::Active && claim.lease_expires_at > now {
                if claim.owner_digest == digest(request.owner.as_bytes())
                    && claim.generation == request.generation
                    && claim.attachment_epoch == request.attachment_epoch
                {
                    return Ok((self.clone(), WorkerGraphDisposition::Replay));
                }
                return Err(WorkerGraphError::ClaimLost);
            }
            if request.generation <= claim.generation
                || request.attachment_epoch < claim.attachment_epoch
            {
                return Err(WorkerGraphError::StaleGeneration);
            }
        }
        let mut next = self.clone();
        next.workers[worker_index].state = WorkerState::Claimed;
        next.workers[worker_index].generation = request.generation;
        bump(&mut next.workers[worker_index].revision)?;
        next.claims.push(WorkerClaim {
            worker_id_digest: request.worker_id_digest.clone(),
            owner_digest: digest(request.owner.as_bytes()),
            generation: request.generation,
            attachment_epoch: request.attachment_epoch,
            lease_expires_at: request.lease_expires_at,
            state: WorkerClaimState::Active,
        });
        next.leases.push(WorkerLease {
            worker_id_digest: request.worker_id_digest.clone(),
            generation: request.generation,
            attachment_epoch: request.attachment_epoch,
            lease_token_digest: request.lease_token_digest,
            issued_at: now,
            expires_at: request.lease_expires_at,
            state: WorkerLeaseState::Active,
        });
        bump(&mut next.graph_revision)?;
        next.validate(now)?;
        Ok((next, WorkerGraphDisposition::Applied))
    }

    pub fn detach(
        &self,
        worker_id_digest: &str,
        owner: &str,
        generation: u64,
        attachment_epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<Self, WorkerGraphError> {
        let mut next = self.clone();
        let index =
            next.require_active_claim(worker_id_digest, owner, generation, attachment_epoch, now)?;
        let claim = latest_claim_mut(&mut next.claims, worker_id_digest)?;
        claim.state = WorkerClaimState::Detached;
        let lease = latest_lease_mut(&mut next.leases, worker_id_digest)?;
        lease.state = WorkerLeaseState::Released;
        next.workers[index].state = WorkerState::Detached;
        bump(&mut next.workers[index].revision)?;
        bump(&mut next.graph_revision)?;
        next.validate(now)?;
        Ok(next)
    }

    pub fn reattach(
        &self,
        request: WorkerReattachRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, WorkerGraphError> {
        self.validate(now)?;
        validate_claim_input(
            &WorkerClaimRequest {
                worker_id_digest: request.worker_id_digest.clone(),
                owner: request.owner.clone(),
                generation: request.generation,
                attachment_epoch: request.attachment_epoch,
                lease_token_digest: request.lease_token_digest.clone(),
                lease_expires_at: request.lease_expires_at,
            },
            now,
        )?;
        let index = self.worker_index(&request.worker_id_digest)?;
        let claim = latest_claim(&self.claims, &request.worker_id_digest)
            .ok_or(WorkerGraphError::ClaimLost)?;
        if self.workers[index].state != WorkerState::Detached
            || claim.state != WorkerClaimState::Detached
            || request.generation != self.workers[index].generation
            || request.attachment_epoch <= claim.attachment_epoch
        {
            return Err(WorkerGraphError::StaleGeneration);
        }
        let mut next = self.clone();
        next.workers[index].state = WorkerState::Claimed;
        bump(&mut next.workers[index].revision)?;
        next.claims.push(WorkerClaim {
            worker_id_digest: request.worker_id_digest.clone(),
            owner_digest: digest(request.owner.as_bytes()),
            generation: request.generation,
            attachment_epoch: request.attachment_epoch,
            lease_expires_at: request.lease_expires_at,
            state: WorkerClaimState::Active,
        });
        next.leases.push(WorkerLease {
            worker_id_digest: request.worker_id_digest,
            generation: request.generation,
            attachment_epoch: request.attachment_epoch,
            lease_token_digest: request.lease_token_digest,
            issued_at: now,
            expires_at: request.lease_expires_at,
            state: WorkerLeaseState::Active,
        });
        bump(&mut next.graph_revision)?;
        next.validate(now)?;
        Ok(next)
    }

    pub fn handoff(
        &self,
        request: WorkerHandoffRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, WorkerGraphError> {
        self.validate(now)?;
        self.require_active_claim(
            &request.worker_id_digest,
            &request.owner,
            request.generation,
            request.attachment_epoch,
            now,
        )?;
        if request.next_owner.trim().is_empty()
            || !valid_digest(&request.reason_digest)
            || !valid_digest(&request.lease_token_digest)
            || request.lease_expires_at <= now
        {
            return Err(WorkerGraphError::InvalidHandoff);
        }
        let next_generation = request
            .generation
            .checked_add(1)
            .ok_or(WorkerGraphError::RevisionOverflow)?;
        let next_epoch = request
            .attachment_epoch
            .checked_add(1)
            .ok_or(WorkerGraphError::RevisionOverflow)?;
        let index = self.worker_index(&request.worker_id_digest)?;
        let mut next = self.clone();
        latest_claim_mut(&mut next.claims, &request.worker_id_digest)?.state =
            WorkerClaimState::Released;
        latest_lease_mut(&mut next.leases, &request.worker_id_digest)?.state =
            WorkerLeaseState::Released;
        next.workers[index].generation = next_generation;
        bump(&mut next.workers[index].revision)?;
        next.claims.push(WorkerClaim {
            worker_id_digest: request.worker_id_digest.clone(),
            owner_digest: digest(request.next_owner.as_bytes()),
            generation: next_generation,
            attachment_epoch: next_epoch,
            lease_expires_at: request.lease_expires_at,
            state: WorkerClaimState::Active,
        });
        next.leases.push(WorkerLease {
            worker_id_digest: request.worker_id_digest.clone(),
            generation: next_generation,
            attachment_epoch: next_epoch,
            lease_token_digest: request.lease_token_digest,
            issued_at: now,
            expires_at: request.lease_expires_at,
            state: WorkerLeaseState::Active,
        });
        bump(&mut next.graph_revision)?;
        next.handoffs.push(HandoffRecord {
            worker_id_digest: request.worker_id_digest,
            from_owner_digest: digest(request.owner.as_bytes()),
            to_owner_digest: digest(request.next_owner.as_bytes()),
            from_generation: request.generation,
            to_generation: next_generation,
            attachment_epoch: next_epoch,
            reason_digest: request.reason_digest,
            recorded_at: now,
        });
        next.workers[index].state = WorkerState::Claimed;
        next.validate(now)?;
        Ok(next)
    }

    pub fn fork(
        &self,
        parent_worker_id_digest: &str,
        child: WorkerSpec,
        now: DateTime<Utc>,
    ) -> Result<Self, WorkerGraphError> {
        self.validate(now)?;
        let parent = self.worker(parent_worker_id_digest)?;
        if child.parent_worker_id_digest.as_deref() != Some(parent_worker_id_digest)
            || child.generation != parent.generation
            || parent.state != WorkerState::Claimed
            || self
                .workers
                .iter()
                .any(|worker| worker.worker_id_digest == child.worker_id_digest)
        {
            return Err(WorkerGraphError::InvalidFork);
        }
        let mut next = self.clone();
        next.workers.push(child.clone());
        next.usage
            .insert(child.worker_id_digest, UsageAccount::default());
        bump(&mut next.graph_revision)?;
        next.validate(now)?;
        Ok(next)
    }

    pub fn accept_return(
        &self,
        request: WorkerReturnRequest,
        now: DateTime<Utc>,
    ) -> Result<(Self, WorkerGraphDisposition), WorkerGraphError> {
        self.record_return(request, WorkerReturnState::Accepted, now)
    }

    pub fn reject_return(
        &self,
        mut request: WorkerReturnRequest,
        now: DateTime<Utc>,
    ) -> Result<(Self, WorkerGraphDisposition), WorkerGraphError> {
        request.usage = UsageAccount::default();
        self.record_return(request, WorkerReturnState::Rejected, now)
    }

    pub fn merge(
        &self,
        source_worker_id_digest: &str,
        target_worker_id_digest: &str,
        idempotency_key: &str,
        result_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(Self, WorkerGraphDisposition), WorkerGraphError> {
        self.validate(now)?;
        let source = self.worker(source_worker_id_digest)?;
        let target = self.worker(target_worker_id_digest)?;
        if source.state != WorkerState::Returned
            || target.state == WorkerState::Abandoned
            || source.parent_worker_id_digest.as_deref() != Some(target_worker_id_digest)
        {
            return Err(WorkerGraphError::InvalidMerge);
        }
        let idempotency_digest = digest(idempotency_key.as_bytes());
        if let Some(existing) = self
            .merges
            .iter()
            .find(|merge| merge.idempotency_digest == idempotency_digest)
        {
            if existing.result_digest == result_digest
                && existing.source_worker_id_digest == source_worker_id_digest
            {
                return Ok((self.clone(), WorkerGraphDisposition::Replay));
            }
            return Err(WorkerGraphError::DuplicateWriteback);
        }
        if !valid_digest(result_digest) || idempotency_key.trim().is_empty() {
            return Err(WorkerGraphError::InvalidMerge);
        }
        let mut next = self.clone();
        let source_index = next.worker_index(source_worker_id_digest)?;
        next.workers[source_index].state = WorkerState::Merged;
        bump(&mut next.workers[source_index].revision)?;
        next.merges.push(WorkerMerge {
            source_worker_id_digest: source_worker_id_digest.to_owned(),
            target_worker_id_digest: target_worker_id_digest.to_owned(),
            idempotency_digest,
            result_digest: result_digest.to_owned(),
            recorded_at: now,
        });
        bump(&mut next.graph_revision)?;
        next.validate(now)?;
        Ok((next, WorkerGraphDisposition::Applied))
    }

    pub fn abandon(
        &self,
        worker_id_digest: &str,
        owner: &str,
        generation: u64,
        attachment_epoch: u64,
        reason_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, WorkerGraphError> {
        self.validate(now)?;
        self.require_active_claim(worker_id_digest, owner, generation, attachment_epoch, now)?;
        if !valid_digest(reason_digest) {
            return Err(WorkerGraphError::InvalidHandoff);
        }
        let index = self.worker_index(worker_id_digest)?;
        let mut next = self.clone();
        next.workers[index].state = WorkerState::Abandoned;
        bump(&mut next.workers[index].revision)?;
        latest_claim_mut(&mut next.claims, worker_id_digest)?.state = WorkerClaimState::Released;
        latest_lease_mut(&mut next.leases, worker_id_digest)?.state = WorkerLeaseState::Revoked;
        bump(&mut next.graph_revision)?;
        next.validate(now)?;
        Ok(next)
    }

    pub fn validate_restart(
        &self,
        current: &Self,
        now: DateTime<Utc>,
    ) -> Result<WorkerGraphRestartDisposition, WorkerGraphError> {
        self.validate(now)?;
        current.validate(now)?;
        if self != current {
            return Err(WorkerGraphError::StaleSnapshot);
        }
        Ok(WorkerGraphRestartDisposition::ExactReplay)
    }

    fn record_return(
        &self,
        request: WorkerReturnRequest,
        state: WorkerReturnState,
        now: DateTime<Utc>,
    ) -> Result<(Self, WorkerGraphDisposition), WorkerGraphError> {
        self.validate(now)?;
        if request.idempotency_key.trim().is_empty() || !valid_digest(&request.result_digest) {
            return Err(WorkerGraphError::InvalidReturn);
        }
        let idempotency_digest = digest(request.idempotency_key.as_bytes());
        if let Some(existing) = self
            .returns
            .iter()
            .find(|value| value.idempotency_digest == idempotency_digest)
        {
            if existing.worker_id_digest == request.worker_id_digest
                && existing.owner_digest == digest(request.owner.as_bytes())
                && existing.generation == request.generation
                && existing.attachment_epoch == request.attachment_epoch
                && existing.result_digest == request.result_digest
                && existing.state == state
            {
                return Ok((self.clone(), WorkerGraphDisposition::Replay));
            }
            return Err(WorkerGraphError::DuplicateWriteback);
        }
        let index = self.require_active_claim(
            &request.worker_id_digest,
            &request.owner,
            request.generation,
            request.attachment_epoch,
            now,
        )?;
        let mut next = self.clone();
        let contract = next.workers[index].return_contract.clone();
        apply_usage(
            &mut next,
            &request.worker_id_digest,
            &request.usage,
            &contract,
        )?;
        next.workers[index].state = match state {
            WorkerReturnState::Accepted => WorkerState::Returned,
            WorkerReturnState::Rejected => WorkerState::Rejected,
        };
        bump(&mut next.workers[index].revision)?;
        next.returns.push(WorkerReturn {
            worker_id_digest: request.worker_id_digest.clone(),
            owner_digest: digest(request.owner.as_bytes()),
            generation: request.generation,
            attachment_epoch: request.attachment_epoch,
            idempotency_digest,
            result_digest: request.result_digest,
            state,
            usage: request.usage,
            recorded_at: now,
        });
        latest_claim_mut(&mut next.claims, &request.worker_id_digest)?.state =
            WorkerClaimState::Released;
        latest_lease_mut(&mut next.leases, &request.worker_id_digest)?.state =
            WorkerLeaseState::Released;
        bump(&mut next.graph_revision)?;
        next.validate(now)?;
        Ok((next, WorkerGraphDisposition::Applied))
    }

    fn worker_index(&self, worker_id_digest: &str) -> Result<usize, WorkerGraphError> {
        self.workers
            .iter()
            .position(|worker| worker.worker_id_digest == worker_id_digest)
            .ok_or(WorkerGraphError::UnknownWorker)
    }

    fn worker(&self, worker_id_digest: &str) -> Result<&WorkerSpec, WorkerGraphError> {
        self.workers
            .iter()
            .find(|worker| worker.worker_id_digest == worker_id_digest)
            .ok_or(WorkerGraphError::UnknownWorker)
    }

    fn require_active_claim(
        &self,
        worker_id_digest: &str,
        owner: &str,
        generation: u64,
        attachment_epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<usize, WorkerGraphError> {
        self.validate(now)?;
        let index = self.worker_index(worker_id_digest)?;
        let claim =
            latest_claim(&self.claims, worker_id_digest).ok_or(WorkerGraphError::ClaimLost)?;
        if claim.state != WorkerClaimState::Active
            || claim.lease_expires_at <= now
            || claim.owner_digest != digest(owner.as_bytes())
            || claim.generation != generation
            || claim.attachment_epoch != attachment_epoch
        {
            return Err(WorkerGraphError::ClaimLost);
        }
        Ok(index)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum WorkerGraphError {
    #[error("worker graph is malformed")]
    InvalidGraph,
    #[error("worker claim is stale or owned by another generation")]
    ClaimLost,
    #[error("worker generation or attachment epoch is stale")]
    StaleGeneration,
    #[error("worker graph contains an unknown worker")]
    UnknownWorker,
    #[error("worker graph return contract is invalid")]
    InvalidReturn,
    #[error("worker graph handoff is invalid")]
    InvalidHandoff,
    #[error("worker graph fork is invalid")]
    InvalidFork,
    #[error("worker graph merge is invalid")]
    InvalidMerge,
    #[error("worker graph writeback is a duplicate with different state")]
    DuplicateWriteback,
    #[error("worker graph usage exceeds the return contract")]
    InvalidUsage,
    #[error("worker graph quota is exceeded")]
    QuotaExceeded,
    #[error("worker graph revision overflowed")]
    RevisionOverflow,
    #[error("worker graph restart snapshot is stale")]
    StaleSnapshot,
}

fn validate_workers(workers: &[WorkerSpec]) -> Result<(), WorkerGraphError> {
    let mut ids = BTreeSet::new();
    for worker in workers {
        if !valid_digest(&worker.worker_id_digest)
            || !ids.insert(worker.worker_id_digest.as_str())
            || worker
                .parent_worker_id_digest
                .as_deref()
                .is_some_and(|value| !valid_digest(value))
            || !valid_digest(&worker.branch_digest)
            || !valid_digest(&worker.capability_digest)
            || !valid_digest(&worker.return_contract.schema_digest)
            || worker.return_contract.max_result_bytes == 0
            || worker.return_contract.max_tokens == 0
            || worker.return_contract.max_cost_minor < 0
            || worker.generation == 0
            || worker.revision == 0
        {
            return Err(WorkerGraphError::InvalidGraph);
        }
        if let Some(parent) = &worker.parent_worker_id_digest {
            let Some(parent_worker) = workers
                .iter()
                .find(|candidate| candidate.worker_id_digest == *parent)
            else {
                return Err(WorkerGraphError::InvalidGraph);
            };
            if worker.kind != WorkerKind::ReadOnly || worker.generation != parent_worker.generation
            {
                return Err(WorkerGraphError::InvalidGraph);
            }
        } else if worker.kind != WorkerKind::Runtime {
            return Err(WorkerGraphError::InvalidGraph);
        }
    }
    Ok(())
}

fn validate_claims(
    claims: &[WorkerClaim],
    workers: &[WorkerSpec],
    _now: DateTime<Utc>,
) -> Result<(), WorkerGraphError> {
    let mut keys = BTreeSet::new();
    for claim in claims {
        if !workers
            .iter()
            .any(|worker| worker.worker_id_digest == claim.worker_id_digest)
            || !valid_digest(&claim.worker_id_digest)
            || !valid_digest(&claim.owner_digest)
            || claim.generation == 0
            || claim.attachment_epoch == 0
            || !keys.insert((
                claim.worker_id_digest.as_str(),
                claim.generation,
                claim.attachment_epoch,
            ))
        {
            return Err(WorkerGraphError::InvalidGraph);
        }
    }
    Ok(())
}

fn validate_leases(leases: &[WorkerLease], workers: &[WorkerSpec]) -> Result<(), WorkerGraphError> {
    let mut keys = BTreeSet::new();
    for lease in leases {
        if !workers
            .iter()
            .any(|worker| worker.worker_id_digest == lease.worker_id_digest)
            || !valid_digest(&lease.worker_id_digest)
            || !valid_digest(&lease.lease_token_digest)
            || lease.generation == 0
            || lease.attachment_epoch == 0
            || lease.expires_at <= lease.issued_at
            || !keys.insert((
                lease.worker_id_digest.as_str(),
                lease.generation,
                lease.attachment_epoch,
            ))
        {
            return Err(WorkerGraphError::InvalidGraph);
        }
    }
    Ok(())
}

fn validate_handoffs(
    handoffs: &[HandoffRecord],
    workers: &[WorkerSpec],
) -> Result<(), WorkerGraphError> {
    for handoff in handoffs {
        if !workers
            .iter()
            .any(|worker| worker.worker_id_digest == handoff.worker_id_digest)
            || !valid_digest(&handoff.worker_id_digest)
            || !valid_digest(&handoff.from_owner_digest)
            || !valid_digest(&handoff.to_owner_digest)
            || !valid_digest(&handoff.reason_digest)
            || handoff.from_generation >= handoff.to_generation
            || handoff.attachment_epoch == 0
        {
            return Err(WorkerGraphError::InvalidGraph);
        }
    }
    Ok(())
}

fn validate_returns(
    returns: &[WorkerReturn],
    workers: &[WorkerSpec],
) -> Result<(), WorkerGraphError> {
    let mut keys = BTreeSet::new();
    for value in returns {
        if !workers
            .iter()
            .any(|worker| worker.worker_id_digest == value.worker_id_digest)
            || !valid_digest(&value.worker_id_digest)
            || !valid_digest(&value.owner_digest)
            || !valid_digest(&value.idempotency_digest)
            || !valid_digest(&value.result_digest)
            || value.generation == 0
            || value.attachment_epoch == 0
            || !keys.insert(value.idempotency_digest.as_str())
        {
            return Err(WorkerGraphError::InvalidGraph);
        }
    }
    Ok(())
}

fn validate_merges(merges: &[WorkerMerge], workers: &[WorkerSpec]) -> Result<(), WorkerGraphError> {
    let mut keys = BTreeSet::new();
    for merge in merges {
        if !workers
            .iter()
            .any(|worker| worker.worker_id_digest == merge.source_worker_id_digest)
            || !workers
                .iter()
                .any(|worker| worker.worker_id_digest == merge.target_worker_id_digest)
            || !valid_digest(&merge.source_worker_id_digest)
            || !valid_digest(&merge.target_worker_id_digest)
            || !valid_digest(&merge.idempotency_digest)
            || !valid_digest(&merge.result_digest)
            || !keys.insert(merge.idempotency_digest.as_str())
        {
            return Err(WorkerGraphError::InvalidGraph);
        }
    }
    Ok(())
}

fn validate_claim_input(
    request: &WorkerClaimRequest,
    now: DateTime<Utc>,
) -> Result<(), WorkerGraphError> {
    if !valid_digest(&request.worker_id_digest)
        || request.owner.trim().is_empty()
        || request.generation == 0
        || request.attachment_epoch == 0
        || !valid_digest(&request.lease_token_digest)
        || request.lease_expires_at <= now
    {
        return Err(WorkerGraphError::ClaimLost);
    }
    Ok(())
}

fn apply_usage(
    graph: &mut WorkerGraph,
    worker_id_digest: &str,
    delta: &UsageAccount,
    contract: &ReturnContract,
) -> Result<(), WorkerGraphError> {
    if delta.cost_spent_minor < 0 {
        return Err(WorkerGraphError::InvalidUsage);
    }
    let account = graph.usage.entry(worker_id_digest.to_owned()).or_default();
    let tokens = account
        .token_spent
        .checked_add(delta.token_spent)
        .ok_or(WorkerGraphError::QuotaExceeded)?;
    let cost = account
        .cost_spent_minor
        .checked_add(delta.cost_spent_minor)
        .ok_or(WorkerGraphError::QuotaExceeded)?;
    if tokens > contract.max_tokens || cost > contract.max_cost_minor {
        return Err(WorkerGraphError::QuotaExceeded);
    }
    account.token_spent = tokens;
    account.cost_spent_minor = cost;
    account.tool_calls = account
        .tool_calls
        .checked_add(delta.tool_calls)
        .ok_or(WorkerGraphError::QuotaExceeded)?;
    account.runtime_millis = account
        .runtime_millis
        .checked_add(delta.runtime_millis)
        .ok_or(WorkerGraphError::QuotaExceeded)?;
    Ok(())
}

fn latest_claim<'a>(claims: &'a [WorkerClaim], worker_id_digest: &str) -> Option<&'a WorkerClaim> {
    claims
        .iter()
        .filter(|claim| claim.worker_id_digest == worker_id_digest)
        .max_by_key(|claim| (claim.generation, claim.attachment_epoch))
}

fn latest_claim_mut<'a>(
    claims: &'a mut [WorkerClaim],
    worker_id_digest: &str,
) -> Result<&'a mut WorkerClaim, WorkerGraphError> {
    let index = claims
        .iter()
        .enumerate()
        .filter(|(_, claim)| claim.worker_id_digest == worker_id_digest)
        .max_by_key(|(_, claim)| (claim.generation, claim.attachment_epoch))
        .map(|(index, _)| index)
        .ok_or(WorkerGraphError::ClaimLost)?;
    Ok(&mut claims[index])
}

fn latest_lease_mut<'a>(
    leases: &'a mut [WorkerLease],
    worker_id_digest: &str,
) -> Result<&'a mut WorkerLease, WorkerGraphError> {
    let index = leases
        .iter()
        .enumerate()
        .filter(|(_, lease)| lease.worker_id_digest == worker_id_digest)
        .max_by_key(|(_, lease)| (lease.generation, lease.attachment_epoch))
        .map(|(index, _)| index)
        .ok_or(WorkerGraphError::ClaimLost)?;
    Ok(&mut leases[index])
}

fn bump(value: &mut u64) -> Result<(), WorkerGraphError> {
    *value = value
        .checked_add(1)
        .ok_or(WorkerGraphError::RevisionOverflow)?;
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn short(value: &str) -> String {
    value.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn digest_for(value: &str) -> String {
        digest(value.as_bytes())
    }

    fn spec(worker: &str, parent: Option<&str>, kind: WorkerKind) -> WorkerSpec {
        WorkerSpec {
            worker_id_digest: digest_for(worker),
            parent_worker_id_digest: parent.map(digest_for),
            kind,
            branch_digest: digest_for(&format!("branch-{worker}")),
            capability_digest: digest_for("capability"),
            return_contract: ReturnContract {
                schema_digest: digest_for("return-contract"),
                required_evidence: kind == WorkerKind::Runtime,
                max_result_bytes: 10_000,
                max_tokens: 10_000,
                max_cost_minor: 10_000,
            },
            generation: 1,
            revision: 1,
            state: WorkerState::Planned,
        }
    }

    fn graph() -> WorkerGraph {
        WorkerGraph::new(
            WorkerGraphDefinition {
                tenant_digest: digest_for("tenant"),
                project_digest: digest_for("project"),
                mission_digest: digest_for("mission"),
                workspace_digest: digest_for("workspace"),
                source_revision: 1,
                source_digest: digest_for("source"),
                workers: vec![spec("runtime", None, WorkerKind::Runtime)],
            },
            now(),
        )
        .expect("graph")
    }

    fn claim_request(worker_id_digest: &str, owner: &str, lease: &str) -> WorkerClaimRequest {
        WorkerClaimRequest {
            worker_id_digest: worker_id_digest.to_owned(),
            owner: owner.to_owned(),
            generation: 1,
            attachment_epoch: 1,
            lease_token_digest: digest_for(lease),
            lease_expires_at: now() + chrono::Duration::minutes(5),
        }
    }

    fn return_request(
        worker_id_digest: &str,
        owner: &str,
        generation: u64,
        attachment_epoch: u64,
        idempotency_key: &str,
        result: &str,
        usage: UsageAccount,
    ) -> WorkerReturnRequest {
        WorkerReturnRequest {
            worker_id_digest: worker_id_digest.to_owned(),
            owner: owner.to_owned(),
            generation,
            attachment_epoch,
            idempotency_key: idempotency_key.to_owned(),
            result_digest: digest_for(result),
            usage,
        }
    }

    fn accept_and_replay(
        graph: &WorkerGraph,
        request: WorkerReturnRequest,
        at: DateTime<Utc>,
    ) -> WorkerGraph {
        let (returned, _) = graph.accept_return(request.clone(), at).expect("return");
        let (replay, disposition) = returned.accept_return(request, at).expect("replay");
        assert_eq!(disposition, WorkerGraphDisposition::Replay);
        assert_eq!(replay, returned);
        replay
    }

    #[test]
    fn worker_graph_claim_handoff_fork_return_and_merge_are_generation_fenced() {
        let at = now();
        let runtime = graph();
        let runtime_id = digest_for("runtime");
        let (claimed, disposition) = runtime
            .claim(claim_request(&runtime_id, "worker-a", "lease-a"), at)
            .expect("claim");
        assert_eq!(disposition, WorkerGraphDisposition::Applied);
        assert_eq!(
            claimed.claim(claim_request(&runtime_id, "worker-b", "lease-b"), at,),
            Err(WorkerGraphError::ClaimLost)
        );
        let handed = claimed
            .handoff(
                WorkerHandoffRequest {
                    worker_id_digest: runtime_id.clone(),
                    owner: "worker-a".into(),
                    generation: 1,
                    attachment_epoch: 1,
                    next_owner: "worker-c".into(),
                    reason_digest: digest_for("handoff"),
                    lease_token_digest: digest_for("lease-c"),
                    lease_expires_at: at + chrono::Duration::minutes(5),
                },
                at,
            )
            .expect("handoff");
        let mut child = spec("read-only", Some("runtime"), WorkerKind::ReadOnly);
        child.generation = 2;
        let forked = handed.fork(&runtime_id, child, at).expect("fork");
        let replay = accept_and_replay(
            &forked,
            return_request(
                &runtime_id,
                "worker-c",
                2,
                2,
                "return-1",
                "result",
                UsageAccount {
                    token_spent: 100,
                    ..UsageAccount::default()
                },
            ),
            at,
        );
        let child_id = digest_for("read-only");
        let (child_claimed, _) = replay
            .claim(
                WorkerClaimRequest {
                    worker_id_digest: child_id.clone(),
                    owner: "reader".into(),
                    generation: 2,
                    attachment_epoch: 1,
                    lease_token_digest: digest_for("lease-reader"),
                    lease_expires_at: at + chrono::Duration::minutes(5),
                },
                at,
            )
            .expect("child claim");
        let (child_returned, _) = child_claimed
            .accept_return(
                return_request(
                    &child_id,
                    "reader",
                    2,
                    1,
                    "return-reader",
                    "reader-result",
                    UsageAccount::default(),
                ),
                at,
            )
            .expect("child return");
        let (merged, disposition) = child_returned
            .merge(
                &child_id,
                &runtime_id,
                "merge-1",
                &digest_for("reader-result"),
                at,
            )
            .expect("merge");
        assert_eq!(disposition, WorkerGraphDisposition::Applied);
        assert_eq!(
            merged.worker(&child_id).expect("child").state,
            WorkerState::Merged
        );
    }

    #[test]
    fn worker_graph_restart_and_invalid_writeback_are_exactly_once() {
        let at = now();
        let worker_id = digest_for("runtime");
        let (claimed, _) = graph()
            .claim(claim_request(&worker_id, "worker-a", "lease"), at)
            .expect("claim");
        let (returned, _) = claimed
            .accept_return(
                return_request(
                    &worker_id,
                    "worker-a",
                    1,
                    1,
                    "return",
                    "result",
                    UsageAccount::default(),
                ),
                at,
            )
            .expect("return");
        assert_eq!(
            returned.validate_restart(&returned.clone(), at),
            Ok(WorkerGraphRestartDisposition::ExactReplay)
        );
        assert_eq!(
            returned.accept_return(
                return_request(
                    &worker_id,
                    "worker-a",
                    1,
                    1,
                    "return",
                    "different",
                    UsageAccount::default(),
                ),
                at,
            ),
            Err(WorkerGraphError::DuplicateWriteback)
        );
        let mut invalid = returned;
        invalid.graph_revision = 0;
        assert_eq!(invalid.validate(at), Err(WorkerGraphError::InvalidGraph));
    }

    #[test]
    fn worker_graph_detach_reattach_stale_owner_and_quota_are_fail_closed() {
        let at = now();
        let worker_id = digest_for("runtime");
        let (claimed, _) = graph()
            .claim(claim_request(&worker_id, "worker-a", "lease"), at)
            .expect("claim");
        let detached = claimed
            .detach(&worker_id, "worker-a", 1, 1, at)
            .expect("detach");
        assert_eq!(
            detached.accept_return(
                return_request(
                    &worker_id,
                    "worker-a",
                    1,
                    1,
                    "stale-return",
                    "result",
                    UsageAccount::default(),
                ),
                at,
            ),
            Err(WorkerGraphError::ClaimLost)
        );
        let reattached = detached
            .reattach(
                WorkerReattachRequest {
                    worker_id_digest: worker_id.clone(),
                    owner: "worker-b".into(),
                    generation: 1,
                    attachment_epoch: 2,
                    lease_token_digest: digest_for("lease-b"),
                    lease_expires_at: at + chrono::Duration::minutes(5),
                },
                at,
            )
            .expect("reattach");
        assert_eq!(
            reattached.accept_return(
                return_request(
                    &worker_id,
                    "worker-b",
                    1,
                    2,
                    "too-many",
                    "result",
                    UsageAccount {
                        token_spent: 20_000,
                        ..UsageAccount::default()
                    },
                ),
                at,
            ),
            Err(WorkerGraphError::QuotaExceeded)
        );
        let (returned, disposition) = reattached
            .accept_return(
                return_request(
                    &worker_id,
                    "worker-b",
                    1,
                    2,
                    "valid-return",
                    "result",
                    UsageAccount::default(),
                ),
                at,
            )
            .expect("valid return");
        assert_eq!(disposition, WorkerGraphDisposition::Applied);
        assert_eq!(
            returned.worker(&worker_id).expect("worker").state,
            WorkerState::Returned
        );
    }

    #[test]
    fn worker_graph_claim_input_table_never_crosses_generation_fence() {
        let at = now();
        let worker_id = digest_for("runtime");
        for (generation, attachment_epoch) in [(0, 1), (1, 0), (0, 0)] {
            let mut request = claim_request(&worker_id, "worker-a", "lease");
            request.generation = generation;
            request.attachment_epoch = attachment_epoch;
            assert_eq!(
                graph().claim(request, at),
                Err(WorkerGraphError::ClaimLost),
                "invalid claim input must fail closed"
            );
        }
    }
}

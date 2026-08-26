//! Mission-scoped typed Remote Worker execution over a regional Cloud Cell.
//!
//! The transport stores only authenticated ciphertext and content-free
//! digests.  The Mission consumer owns the meaning of that ciphertext; the
//! Cell owns a bounded lease, its recovery history, and a result receipt.  In
//! particular, an uncertain dispatch is terminal for this execution record
//! and is never made claimable again.

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{MissionId, ProjectId, TaskId, WorkerId, WorkerLeaseId};
use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, Row, Transaction};

use super::{
    CellScope, CloudStorageError, DataCell, EncryptedPayload, PostgresCellStore, canonical_digest,
    ensure_database_cell, ensure_project_exists, ensure_remote_worker_project,
    ensure_request_digest, from_sql_u64, is_sha256, lock_project, remote_worker_plugin, set_scope,
    to_sql_u64,
};

pub const REMOTE_WORKER_EXECUTION_SCHEMA: &str = "hartevo.cloud-cell.remote-worker-execution/v1";
pub const MAX_REMOTE_WORKER_INPUT_BYTES: usize = 512 * 1024;
pub const MAX_REMOTE_WORKER_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_REMOTE_WORKER_ATTEMPTS: u32 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRemoteWorkerDispatchAvailability {
    Connected,
    Disconnected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRemoteWorkerDispatchDecision {
    DispatchToCell,
    KeepLocalPending,
}

impl CloudRemoteWorkerDispatchAvailability {
    pub const fn decision(self) -> CloudRemoteWorkerDispatchDecision {
        match self {
            Self::Connected => CloudRemoteWorkerDispatchDecision::DispatchToCell,
            Self::Disconnected => CloudRemoteWorkerDispatchDecision::KeepLocalPending,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerMissionFence {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub project_key_generation: u64,
    pub mission_id: MissionId,
    pub mission_generation: u64,
    pub mission_version: u64,
    pub mission_digest: String,
}

impl CloudRemoteWorkerMissionFence {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.scope.validate(expected_cell)?;
        if self.project_id.as_str().trim().is_empty()
            || self.project_key_generation == 0
            || self.mission_id.as_str().trim().is_empty()
            || self.mission_generation == 0
            || self.mission_version == 0
            || !is_sha256(&self.mission_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerWorkRequest {
    pub fence: CloudRemoteWorkerMissionFence,
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub dispatch_registration_id: String,
    pub input: EncryptedPayload,
    pub idempotency_key_digest: String,
    pub enqueued_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
}

impl CloudRemoteWorkerWorkRequest {
    pub fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.fence.validate(expected_cell)?;
        self.input.validate()?;
        if self.task_id.as_str().trim().is_empty()
            || self.worker_id.as_str().trim().is_empty()
            || self.worker_id.as_str().len() > 256
            || !is_sha256(&self.dispatch_registration_id)
            || !is_sha256(&self.idempotency_key_digest)
            || self.input.ciphertext.len() > MAX_REMOTE_WORKER_INPUT_BYTES
            || self.deadline_at <= self.enqueued_at
        {
            return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
            "fence": self.fence,
            "taskId": self.task_id,
            "workerId": self.worker_id,
            "dispatchRegistrationId": self.dispatch_registration_id,
            "input": self.input,
            "idempotencyKeyDigest": self.idempotency_key_digest,
            "enqueuedAt": self.enqueued_at,
            "deadlineAt": self.deadline_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerWorkClaim {
    pub fence: CloudRemoteWorkerMissionFence,
    pub task_id: Option<TaskId>,
    pub worker_id: WorkerId,
    pub dispatch_registration_id: String,
    pub lease_owner: String,
    pub lease_token_digest: String,
    pub claim_idempotency_key_digest: String,
    pub now: DateTime<Utc>,
    pub lease_for: Duration,
}

impl CloudRemoteWorkerWorkClaim {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.fence.validate(expected_cell)?;
        if self
            .task_id
            .as_ref()
            .is_some_and(|task_id| task_id.as_str().trim().is_empty())
            || self.worker_id.as_str().trim().is_empty()
            || !is_sha256(&self.dispatch_registration_id)
            || self.lease_owner.trim().is_empty()
            || self.lease_owner.len() > 256
            || !is_sha256(&self.lease_token_digest)
            || !is_sha256(&self.claim_idempotency_key_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
        }
        validate_lease_duration(self.lease_for)
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
            "fence": self.fence,
            "taskId": self.task_id,
            "workerId": self.worker_id,
            "dispatchRegistrationId": self.dispatch_registration_id,
            "leaseOwner": self.lease_owner,
            "leaseTokenDigest": self.lease_token_digest,
            "now": self.now,
            "leaseForSeconds": self.lease_for.num_seconds(),
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerWorkHeartbeat {
    pub fence: CloudRemoteWorkerMissionFence,
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub dispatch_registration_id: String,
    pub lease_id: WorkerLeaseId,
    pub lease_generation: u64,
    pub lease_owner: String,
    pub lease_token_digest: String,
    pub heartbeat_idempotency_key_digest: String,
    pub now: DateTime<Utc>,
    pub lease_for: Duration,
}

impl CloudRemoteWorkerWorkHeartbeat {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.fence.validate(expected_cell)?;
        if self.task_id.as_str().trim().is_empty()
            || self.worker_id.as_str().trim().is_empty()
            || !is_sha256(&self.dispatch_registration_id)
            || self.lease_id.as_str().trim().is_empty()
            || self.lease_generation == 0
            || self.lease_owner.trim().is_empty()
            || self.lease_owner.len() > 256
            || !is_sha256(&self.lease_token_digest)
            || !is_sha256(&self.heartbeat_idempotency_key_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
        }
        validate_lease_duration(self.lease_for)
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
            "fence": self.fence,
            "taskId": self.task_id,
            "workerId": self.worker_id,
            "dispatchRegistrationId": self.dispatch_registration_id,
            "leaseId": self.lease_id,
            "leaseGeneration": self.lease_generation,
            "leaseOwner": self.lease_owner,
            "leaseTokenDigest": self.lease_token_digest,
            "now": self.now,
            "leaseForSeconds": self.lease_for.num_seconds(),
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerWorkResult {
    pub fence: CloudRemoteWorkerMissionFence,
    pub task_id: TaskId,
    pub worker_id: WorkerId,
    pub dispatch_registration_id: String,
    pub request_digest: String,
    pub lease_id: WorkerLeaseId,
    pub lease_generation: u64,
    pub lease_owner: String,
    pub lease_token_digest: String,
    pub output: EncryptedPayload,
    pub evidence_digest: String,
    pub effect_receipt_digest: Option<String>,
    pub outcome_link_digest: Option<String>,
    pub provider_id: String,
    pub provider_implementation_digest: String,
    pub service_contract_digest: String,
    pub current_commit_digest: String,
    pub completion_idempotency_key_digest: String,
    pub completed_at: DateTime<Utc>,
}

impl CloudRemoteWorkerWorkResult {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.fence.validate(expected_cell)?;
        self.output.validate()?;
        if self.task_id.as_str().trim().is_empty()
            || self.worker_id.as_str().trim().is_empty()
            || !is_sha256(&self.dispatch_registration_id)
            || !is_sha256(&self.request_digest)
            || self.lease_id.as_str().trim().is_empty()
            || self.lease_generation == 0
            || self.lease_owner.trim().is_empty()
            || self.lease_owner.len() > 256
            || !is_sha256(&self.lease_token_digest)
            || self.output.ciphertext.len() > MAX_REMOTE_WORKER_OUTPUT_BYTES
            || !is_sha256(&self.evidence_digest)
            || !valid_identifier(&self.provider_id)
            || !is_sha256(&self.provider_implementation_digest)
            || !is_sha256(&self.service_contract_digest)
            || !is_sha256(&self.current_commit_digest)
            || !is_sha256(&self.completion_idempotency_key_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerWorkResult);
        }
        validate_optional_digest(self.effect_receipt_digest.as_deref())?;
        validate_optional_digest(self.outcome_link_digest.as_deref())
    }

    fn result_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
            "fence": self.fence,
            "taskId": self.task_id,
            "workerId": self.worker_id,
            "dispatchRegistrationId": self.dispatch_registration_id,
            "requestDigest": self.request_digest,
            "leaseId": self.lease_id,
            "leaseGeneration": self.lease_generation,
            "output": self.output,
            "evidenceDigest": self.evidence_digest,
            "effectReceiptDigest": self.effect_receipt_digest,
            "outcomeLinkDigest": self.outcome_link_digest,
            "providerId": self.provider_id,
            "providerImplementationDigest": self.provider_implementation_digest,
            "serviceContractDigest": self.service_contract_digest,
            "currentCommitDigest": self.current_commit_digest,
            "completionIdempotencyKeyDigest": self.completion_idempotency_key_digest,
            "completedAt": self.completed_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerWorkCancel {
    pub fence: CloudRemoteWorkerMissionFence,
    pub task_id: TaskId,
    pub dispatch_registration_id: String,
    pub reason_digest: String,
    pub cancel_idempotency_key_digest: String,
    pub cancelled_at: DateTime<Utc>,
}

impl CloudRemoteWorkerWorkCancel {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.fence.validate(expected_cell)?;
        if self.task_id.as_str().trim().is_empty()
            || !is_sha256(&self.dispatch_registration_id)
            || !is_sha256(&self.reason_digest)
            || !is_sha256(&self.cancel_idempotency_key_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
        }
        Ok(())
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
            "fence": self.fence,
            "taskId": self.task_id,
            "dispatchRegistrationId": self.dispatch_registration_id,
            "reasonDigest": self.reason_digest,
            "cancelledAt": self.cancelled_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerWorkUncertain {
    pub fence: CloudRemoteWorkerMissionFence,
    pub task_id: TaskId,
    pub dispatch_registration_id: String,
    pub lease_id: WorkerLeaseId,
    pub lease_generation: u64,
    pub lease_owner: String,
    pub lease_token_digest: String,
    pub reason_digest: String,
    pub uncertain_idempotency_key_digest: String,
    pub uncertain_at: DateTime<Utc>,
}

impl CloudRemoteWorkerWorkUncertain {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.fence.validate(expected_cell)?;
        if self.task_id.as_str().trim().is_empty()
            || !is_sha256(&self.dispatch_registration_id)
            || self.lease_id.as_str().trim().is_empty()
            || self.lease_generation == 0
            || self.lease_owner.trim().is_empty()
            || self.lease_owner.len() > 256
            || !is_sha256(&self.lease_token_digest)
            || !is_sha256(&self.reason_digest)
            || !is_sha256(&self.uncertain_idempotency_key_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
        }
        Ok(())
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
            "fence": self.fence,
            "taskId": self.task_id,
            "dispatchRegistrationId": self.dispatch_registration_id,
            "leaseId": self.lease_id,
            "leaseGeneration": self.lease_generation,
            "leaseOwner": self.lease_owner,
            "leaseTokenDigest": self.lease_token_digest,
            "reasonDigest": self.reason_digest,
            "uncertainAt": self.uncertain_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkLease {
    pub request: CloudRemoteWorkerWorkRequest,
    pub lease_id: WorkerLeaseId,
    pub lease_generation: u64,
    pub lease_owner: String,
    pub lease_token_digest: String,
    pub attempts: u32,
    pub heartbeat_at: DateTime<Utc>,
    pub lease_expires_at: DateTime<Utc>,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRemoteWorkerWorkStatus {
    Pending,
    Leased,
    Completed,
    Cancelled,
    Uncertain,
    DeadLetter,
}

impl CloudRemoteWorkerWorkStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Uncertain => "uncertain",
            Self::DeadLetter => "dead_letter",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkRecord {
    pub request: CloudRemoteWorkerWorkRequest,
    pub status: CloudRemoteWorkerWorkStatus,
    pub attempts: u32,
    pub lease: Option<CloudRemoteWorkerWorkLease>,
    pub result_receipt: Option<CloudRemoteWorkerWorkResultReceipt>,
    pub terminal_reason_digest: Option<String>,
    pub terminal_at: Option<DateTime<Utc>>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkResultReceipt {
    pub fence: CloudRemoteWorkerMissionFence,
    pub task_id: TaskId,
    pub dispatch_registration_id: String,
    pub request_digest: String,
    pub lease_id: WorkerLeaseId,
    pub lease_generation: u64,
    pub lease_owner: String,
    pub output: EncryptedPayload,
    pub evidence_digest: String,
    pub effect_receipt_digest: Option<String>,
    pub outcome_link_digest: Option<String>,
    pub provider_id: String,
    pub provider_implementation_digest: String,
    pub service_contract_digest: String,
    pub current_commit_digest: String,
    pub result_digest: String,
    pub receipt_digest: String,
    pub completion_idempotency_key_digest: String,
    pub completed_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkRequestResult {
    pub task_id: TaskId,
    pub request_digest: String,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkClaimResult {
    pub lease: CloudRemoteWorkerWorkLease,
    pub duplicate: bool,
    pub takeover: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkHeartbeatResult {
    pub lease: CloudRemoteWorkerWorkLease,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkResultCommit {
    pub receipt: CloudRemoteWorkerWorkResultReceipt,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkCancelResult {
    pub task_id: TaskId,
    pub status: CloudRemoteWorkerWorkStatus,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudRemoteWorkerWorkUncertainResult {
    pub task_id: TaskId,
    pub status: CloudRemoteWorkerWorkStatus,
    pub duplicate: bool,
}

#[derive(Clone, Debug)]
struct WorkRow {
    request: CloudRemoteWorkerWorkRequest,
    status: CloudRemoteWorkerWorkStatus,
    attempts: u32,
    lease_id: Option<WorkerLeaseId>,
    lease_generation: u64,
    lease_owner: Option<String>,
    lease_token_digest: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    heartbeat_at: Option<DateTime<Utc>>,
    terminal_idempotency_key_digest: Option<String>,
    terminal_request_digest: Option<String>,
    terminal_reason_digest: Option<String>,
    terminal_at: Option<DateTime<Utc>>,
    revision: u64,
}

impl WorkRow {
    fn into_lease(self) -> Result<Option<CloudRemoteWorkerWorkLease>, CloudStorageError> {
        if self.status != CloudRemoteWorkerWorkStatus::Leased {
            return Ok(None);
        }
        let lease = CloudRemoteWorkerWorkLease {
            request: self.request,
            lease_id: self
                .lease_id
                .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?,
            lease_generation: self.lease_generation,
            lease_owner: self
                .lease_owner
                .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?,
            lease_token_digest: self
                .lease_token_digest
                .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?,
            attempts: self.attempts,
            heartbeat_at: self
                .heartbeat_at
                .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?,
            lease_expires_at: self
                .lease_expires_at
                .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?,
            revision: self.revision,
        };
        if lease.lease_generation == 0 || lease.lease_expires_at <= lease.heartbeat_at {
            return Err(CloudStorageError::RemoteWorkerLeaseLost);
        }
        Ok(Some(lease))
    }

    fn record(
        self,
        result_receipt: Option<CloudRemoteWorkerWorkResultReceipt>,
    ) -> Result<CloudRemoteWorkerWorkRecord, CloudStorageError> {
        let lease = self.clone().into_lease()?;
        Ok(CloudRemoteWorkerWorkRecord {
            request: self.request,
            status: self.status,
            attempts: self.attempts,
            lease,
            result_receipt,
            terminal_reason_digest: self.terminal_reason_digest,
            terminal_at: self.terminal_at,
            revision: self.revision,
        })
    }
}

#[derive(Clone, Debug)]
struct ProviderIdentity {
    provider_id: String,
    provider_implementation_digest: String,
    service_contract_digest: String,
}

#[derive(Clone, Debug)]
struct WorkLogEntry {
    task_id: TaskId,
    request_digest: String,
    event_type: String,
    lease_id: Option<WorkerLeaseId>,
    lease_generation: u64,
    lease_owner: Option<String>,
    lease_token_digest: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    attempts: u32,
    revision: u64,
    recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default)]
struct WorkLogLease {
    lease_id: Option<WorkerLeaseId>,
    lease_generation: u64,
    lease_owner: Option<String>,
    lease_token_digest: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    attempts: u32,
    revision: u64,
}

const WORK_COLUMNS: &str = "project_id, mission_id, task_id, worker_id,
       dispatch_registration_id, project_key_generation, mission_generation,
       mission_version, mission_digest, input_key_version, input_nonce,
       input_ciphertext, input_aad_digest, input_content_digest, idempotency_key,
       request_digest, status, attempts, lease_id, lease_generation, lease_owner,
       lease_token_digest, claim_idempotency_key, claim_request_digest,
       lease_expires_at, heartbeat_at, completion_idempotency_key,
       completion_request_digest, completed_at, terminal_idempotency_key,
       terminal_request_digest, terminal_reason_digest, terminal_at, enqueued_at,
       deadline_at, updated_at, revision";

impl PostgresCellStore {
    #[allow(
        clippy::too_many_lines,
        reason = "enqueue binds the typed Mission fence, provider registration, ciphertext, and durable log atomically"
    )]
    pub async fn enqueue_remote_worker_work(
        &self,
        client: &mut Client,
        request: &CloudRemoteWorkerWorkRequest,
    ) -> Result<CloudRemoteWorkerWorkRequestResult, CloudStorageError> {
        request.validate(self.cell())?;
        let request_digest = request.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &request.fence.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_remote_worker_project(
            &transaction,
            &request.fence.scope,
            &request.fence.project_id,
        )
        .await?;
        lock_project(
            &transaction,
            &request.fence.scope,
            &request.fence.project_id,
        )
        .await?;
        ensure_active_provider(
            &transaction,
            &request.fence,
            &request.dispatch_registration_id,
            &request.worker_id,
        )
        .await?;

        if let Some(existing) = transaction
            .query_opt(
                "SELECT task_id, request_digest
                 FROM hartevo_cell.remote_worker_work_requests
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4",
                &[
                    &request.fence.scope.cell.as_str(),
                    &request.fence.scope.tenant_id.as_str(),
                    &request.fence.project_id.as_str(),
                    &request.idempotency_key_digest,
                ],
            )
            .await?
        {
            ensure_request_digest(&existing.get::<_, String>(1), &request_digest)?;
            transaction.commit().await?;
            return Ok(CloudRemoteWorkerWorkRequestResult {
                task_id: TaskId::from_stable(existing.get::<_, String>(0)),
                request_digest,
                duplicate: true,
            });
        }
        if transaction
            .query_opt(
                "SELECT 1
                 FROM hartevo_cell.remote_worker_work_requests
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4",
                &[
                    &request.fence.scope.cell.as_str(),
                    &request.fence.scope.tenant_id.as_str(),
                    &request.fence.project_id.as_str(),
                    &request.task_id.as_str(),
                ],
            )
            .await?
            .is_some()
        {
            return Err(CloudStorageError::RemoteWorkerWorkAlreadyExists);
        }

        let input_key_version = to_sql_u64(request.input.key_version)?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.remote_worker_work_requests
                   (cell, tenant_id, project_id, mission_id, task_id, worker_id,
                    dispatch_registration_id, project_key_generation, mission_generation,
                    mission_version, mission_digest, input_key_version, input_nonce,
                    input_ciphertext, input_aad_digest, input_content_digest,
                    idempotency_key, request_digest, status, enqueued_at, deadline_at,
                    updated_at, revision)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                         $13, $14, $15, $16, $17, $18, 'pending', $19, $20, $19, 1)",
                &[
                    &request.fence.scope.cell.as_str(),
                    &request.fence.scope.tenant_id.as_str(),
                    &request.fence.project_id.as_str(),
                    &request.fence.mission_id.as_str(),
                    &request.task_id.as_str(),
                    &request.worker_id.as_str(),
                    &request.dispatch_registration_id,
                    &to_sql_u64(request.fence.project_key_generation)?,
                    &to_sql_u64(request.fence.mission_generation)?,
                    &to_sql_u64(request.fence.mission_version)?,
                    &request.fence.mission_digest,
                    &input_key_version,
                    &request.input.nonce,
                    &request.input.ciphertext,
                    &request.input.aad_digest,
                    &request.input.content_digest,
                    &request.idempotency_key_digest,
                    &request_digest,
                    &request.enqueued_at,
                    &request.deadline_at,
                ],
            )
            .await?;
        append_work_log(
            &transaction,
            &request.fence,
            &request.task_id,
            &request.idempotency_key_digest,
            &request_digest,
            "enqueued",
            WorkLogLease::default(),
            None,
            None,
            request.enqueued_at,
        )
        .await?;
        transaction.commit().await?;
        Ok(CloudRemoteWorkerWorkRequestResult {
            task_id: request.task_id.clone(),
            request_digest,
            duplicate: false,
        })
    }

    pub async fn load_remote_worker_work(
        &self,
        client: &mut Client,
        fence: &CloudRemoteWorkerMissionFence,
        task_id: &TaskId,
    ) -> Result<CloudRemoteWorkerWorkRecord, CloudStorageError> {
        fence.validate(self.cell())?;
        if task_id.as_str().trim().is_empty() {
            return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, &fence.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, &fence.scope, &fence.project_id).await?;
        let row = load_work_row_tx(&transaction, fence, task_id, false)
            .await?
            .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
        let receipt = load_result_receipt_tx(&transaction, fence, task_id, false).await?;
        let record = row.record(receipt)?;
        transaction.commit().await?;
        Ok(record)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the provider claim keeps exact Mission fence, registration, bounded lease, takeover, and durable log in one transaction"
    )]
    pub async fn claim_remote_worker_work(
        &self,
        client: &mut Client,
        claim: &CloudRemoteWorkerWorkClaim,
    ) -> Result<Option<CloudRemoteWorkerWorkClaimResult>, CloudStorageError> {
        claim.validate(self.cell())?;
        let request_digest = claim.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &claim.fence.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_remote_worker_project(&transaction, &claim.fence.scope, &claim.fence.project_id)
            .await?;
        lock_project(&transaction, &claim.fence.scope, &claim.fence.project_id).await?;
        ensure_active_provider(
            &transaction,
            &claim.fence,
            &claim.dispatch_registration_id,
            &claim.worker_id,
        )
        .await?;

        if let Some(existing_log) = load_work_log_by_operation(
            &transaction,
            &claim.fence,
            &claim.claim_idempotency_key_digest,
        )
        .await?
        {
            ensure_request_digest(&existing_log.request_digest, &request_digest)?;
            if !matches!(existing_log.event_type.as_str(), "claimed" | "takeover") {
                return Err(CloudStorageError::IdempotencyConflict);
            }
            let row = load_work_row_tx(&transaction, &claim.fence, &existing_log.task_id, true)
                .await?
                .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
            let lease = historical_lease_from_log(row.request, &existing_log)?;
            transaction.commit().await?;
            return Ok(Some(CloudRemoteWorkerWorkClaimResult {
                lease,
                duplicate: true,
                takeover: existing_log.event_type == "takeover",
            }));
        }

        let candidate = load_claim_candidate(&transaction, claim).await?;
        let Some(candidate) = candidate else {
            transaction.commit().await?;
            return Ok(None);
        };
        if candidate.attempts >= MAX_REMOTE_WORKER_ATTEMPTS {
            let terminal_reason = canonical_digest(&serde_json::json!({
                "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
                "reason": "bounded_attempts_exhausted",
                "taskId": candidate.request.task_id,
            }))?;
            let terminal_key = canonical_digest(&serde_json::json!({
                "claim": claim.claim_idempotency_key_digest,
                "reason": terminal_reason,
            }))?;
            let terminal_request = canonical_digest(&serde_json::json!({
                "taskId": candidate.request.task_id,
                "reason": terminal_reason,
                "at": claim.now,
            }))?;
            transaction
                .execute(
                    "UPDATE hartevo_cell.remote_worker_work_requests
                     SET status = 'dead_letter', terminal_idempotency_key = $5,
                         terminal_request_digest = $6, terminal_reason_digest = $7,
                         terminal_at = $8, updated_at = $8, revision = revision + 1,
                         lease_id = NULL, lease_generation = 0, lease_owner = NULL,
                         lease_token_digest = NULL, claim_idempotency_key = NULL,
                         claim_request_digest = NULL, lease_expires_at = NULL,
                         heartbeat_at = NULL
                     WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4",
                    &[
                        &claim.fence.scope.cell.as_str(),
                        &claim.fence.scope.tenant_id.as_str(),
                        &claim.fence.project_id.as_str(),
                        &candidate.request.task_id.as_str(),
                        &terminal_key,
                        &terminal_request,
                        &terminal_reason,
                        &claim.now,
                    ],
                )
                .await?;
            append_work_log(
                &transaction,
                &candidate.request.fence,
                &candidate.request.task_id,
                &terminal_key,
                &terminal_request,
                "dead_letter",
                WorkLogLease::default(),
                Some(terminal_reason),
                None,
                claim.now,
            )
            .await?;
            transaction.commit().await?;
            return Ok(None);
        }

        let takeover = candidate.status == CloudRemoteWorkerWorkStatus::Leased;
        let lease_generation = candidate
            .lease_generation
            .checked_add(1)
            .ok_or(CloudStorageError::RevisionOverflow)?;
        let lease_expires_at =
            bounded_lease_expiry(claim.now, claim.lease_for, candidate.request.deadline_at)?;
        let lease_id = WorkerLeaseId::new();
        let updated = transaction
            .execute(
                "UPDATE hartevo_cell.remote_worker_work_requests
                 SET status = 'leased', attempts = attempts + 1, lease_id = $5,
                     lease_generation = $6, lease_owner = $7, lease_token_digest = $8,
                     claim_idempotency_key = $9, claim_request_digest = $10,
                     lease_expires_at = $11, heartbeat_at = $12, updated_at = $12,
                     revision = revision + 1
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4
                   AND status IN ('pending', 'leased')",
                &[
                    &claim.fence.scope.cell.as_str(),
                    &claim.fence.scope.tenant_id.as_str(),
                    &claim.fence.project_id.as_str(),
                    &candidate.request.task_id.as_str(),
                    &lease_id.as_str(),
                    &to_sql_u64(lease_generation)?,
                    &claim.lease_owner,
                    &claim.lease_token_digest,
                    &claim.claim_idempotency_key_digest,
                    &request_digest,
                    &lease_expires_at,
                    &claim.now,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(CloudStorageError::RemoteWorkerLeaseLost);
        }
        let current = load_work_row_tx(
            &transaction,
            &claim.fence,
            &candidate.request.task_id,
            false,
        )
        .await?
        .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
        let lease = current
            .clone()
            .into_lease()?
            .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?;
        append_work_log(
            &transaction,
            &claim.fence,
            &candidate.request.task_id,
            &claim.claim_idempotency_key_digest,
            &request_digest,
            if takeover { "takeover" } else { "claimed" },
            WorkLogLease {
                lease_id: Some(lease.lease_id.clone()),
                lease_generation: lease.lease_generation,
                lease_owner: Some(lease.lease_owner.clone()),
                lease_token_digest: Some(lease.lease_token_digest.clone()),
                lease_expires_at: Some(lease.lease_expires_at),
                attempts: lease.attempts,
                revision: lease.revision,
            },
            None,
            None,
            claim.now,
        )
        .await?;
        transaction.commit().await?;
        Ok(Some(CloudRemoteWorkerWorkClaimResult {
            lease,
            duplicate: false,
            takeover,
        }))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "heartbeat binds the exact worker lease and append-only operation log atomically"
    )]
    pub async fn heartbeat_remote_worker_work(
        &self,
        client: &mut Client,
        heartbeat: &CloudRemoteWorkerWorkHeartbeat,
    ) -> Result<CloudRemoteWorkerWorkHeartbeatResult, CloudStorageError> {
        heartbeat.validate(self.cell())?;
        let request_digest = heartbeat.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &heartbeat.fence.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_remote_worker_project(
            &transaction,
            &heartbeat.fence.scope,
            &heartbeat.fence.project_id,
        )
        .await?;
        lock_project(
            &transaction,
            &heartbeat.fence.scope,
            &heartbeat.fence.project_id,
        )
        .await?;
        ensure_active_provider(
            &transaction,
            &heartbeat.fence,
            &heartbeat.dispatch_registration_id,
            &heartbeat.worker_id,
        )
        .await?;

        if let Some(existing_log) = load_work_log_by_operation(
            &transaction,
            &heartbeat.fence,
            &heartbeat.heartbeat_idempotency_key_digest,
        )
        .await?
        {
            ensure_request_digest(&existing_log.request_digest, &request_digest)?;
            if existing_log.event_type != "heartbeat" {
                return Err(CloudStorageError::IdempotencyConflict);
            }
            let row =
                load_work_row_tx(&transaction, &heartbeat.fence, &existing_log.task_id, false)
                    .await?
                    .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
            let lease = historical_lease_from_log(row.request, &existing_log)?;
            transaction.commit().await?;
            return Ok(CloudRemoteWorkerWorkHeartbeatResult {
                lease,
                duplicate: true,
            });
        }

        let current = load_work_row_tx(&transaction, &heartbeat.fence, &heartbeat.task_id, true)
            .await?
            .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
        if current.request.dispatch_registration_id != heartbeat.dispatch_registration_id {
            return Err(CloudStorageError::RemoteWorkerDispatchNotRegistered);
        }
        require_current_lease(
            &current,
            &heartbeat.lease_id,
            heartbeat.lease_generation,
            &heartbeat.lease_owner,
            &heartbeat.lease_token_digest,
            heartbeat.now,
        )?;
        let lease_expires_at = bounded_lease_expiry(
            heartbeat.now,
            heartbeat.lease_for,
            current.request.deadline_at,
        )?;
        let updated = transaction
            .execute(
                "UPDATE hartevo_cell.remote_worker_work_requests
                 SET heartbeat_at = $5, lease_expires_at = $6, updated_at = $5,
                     revision = revision + 1
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4
                   AND status = 'leased' AND lease_id = $7 AND lease_generation = $8
                   AND lease_owner = $9 AND lease_token_digest = $10
                   AND lease_expires_at > $5",
                &[
                    &heartbeat.fence.scope.cell.as_str(),
                    &heartbeat.fence.scope.tenant_id.as_str(),
                    &heartbeat.fence.project_id.as_str(),
                    &heartbeat.task_id.as_str(),
                    &heartbeat.now,
                    &lease_expires_at,
                    &heartbeat.lease_id.as_str(),
                    &to_sql_u64(heartbeat.lease_generation)?,
                    &heartbeat.lease_owner,
                    &heartbeat.lease_token_digest,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(CloudStorageError::RemoteWorkerLeaseLost);
        }
        let refreshed = load_work_row_tx(&transaction, &heartbeat.fence, &heartbeat.task_id, false)
            .await?
            .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
        let lease = refreshed
            .clone()
            .into_lease()?
            .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?;
        append_work_log(
            &transaction,
            &heartbeat.fence,
            &heartbeat.task_id,
            &heartbeat.heartbeat_idempotency_key_digest,
            &request_digest,
            "heartbeat",
            WorkLogLease {
                lease_id: Some(lease.lease_id.clone()),
                lease_generation: lease.lease_generation,
                lease_owner: Some(lease.lease_owner.clone()),
                lease_token_digest: Some(lease.lease_token_digest.clone()),
                lease_expires_at: Some(lease.lease_expires_at),
                attempts: lease.attempts,
                revision: lease.revision,
            },
            None,
            None,
            heartbeat.now,
        )
        .await?;
        transaction.commit().await?;
        Ok(CloudRemoteWorkerWorkHeartbeatResult {
            lease,
            duplicate: false,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the result commit binds encrypted output, provider identity, exact lease, receipt, and durable event atomically"
    )]
    pub async fn complete_remote_worker_work(
        &self,
        client: &mut Client,
        result: &CloudRemoteWorkerWorkResult,
    ) -> Result<CloudRemoteWorkerWorkResultCommit, CloudStorageError> {
        result.validate(self.cell())?;
        let result_digest = result.result_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &result.fence.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_remote_worker_project(&transaction, &result.fence.scope, &result.fence.project_id)
            .await?;
        lock_project(&transaction, &result.fence.scope, &result.fence.project_id).await?;
        let provider = ensure_active_provider(
            &transaction,
            &result.fence,
            &result.dispatch_registration_id,
            &result.worker_id,
        )
        .await?;
        if provider.provider_id != result.provider_id
            || (!provider.provider_implementation_digest.is_empty()
                && provider.provider_implementation_digest != result.provider_implementation_digest)
            || (!provider.service_contract_digest.is_empty()
                && provider.service_contract_digest != result.service_contract_digest)
        {
            return Err(CloudStorageError::RemoteWorkerProviderMismatch);
        }
        let current = load_work_row_tx(&transaction, &result.fence, &result.task_id, true)
            .await?
            .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
        if current.request.dispatch_registration_id != result.dispatch_registration_id
            || current.request.request_digest()? != result.request_digest
        {
            return Err(CloudStorageError::RemoteWorkerWorkFenceLost);
        }
        if current.status == CloudRemoteWorkerWorkStatus::Completed {
            let receipt =
                load_result_receipt_tx(&transaction, &result.fence, &result.task_id, false)
                    .await?
                    .ok_or(CloudStorageError::StoredValueInvalid(
                        "completed Remote Worker work is missing its result receipt".into(),
                    ))?;
            if receipt.completion_idempotency_key_digest == result.completion_idempotency_key_digest
                && receipt.result_digest == result_digest
            {
                transaction.commit().await?;
                return Ok(CloudRemoteWorkerWorkResultCommit {
                    receipt,
                    duplicate: true,
                });
            }
            return Err(CloudStorageError::RemoteWorkerWorkAlreadyTerminal);
        }
        require_current_lease(
            &current,
            &result.lease_id,
            result.lease_generation,
            &result.lease_owner,
            &result.lease_token_digest,
            result.completed_at,
        )?;
        let heartbeat_at = current
            .heartbeat_at
            .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?;
        if result.completed_at < heartbeat_at {
            return Err(CloudStorageError::RemoteWorkerLeaseLost);
        }
        let receipt_revision = current
            .revision
            .checked_add(1)
            .ok_or(CloudStorageError::RevisionOverflow)?;
        let receipt_digest = receipt_digest(result, &result_digest)?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.remote_worker_result_receipts
                   (cell, tenant_id, project_id, mission_id, task_id,
                    project_key_generation, mission_generation, mission_version,
                    mission_digest, dispatch_registration_id, lease_id,
                    lease_generation, lease_owner, provider_id,
                    provider_implementation_digest, service_contract_digest,
                    current_commit_digest, output_key_version, output_nonce,
                    output_ciphertext, output_aad_digest, output_content_digest,
                    evidence_digest, effect_receipt_digest, outcome_link_digest,
                    request_digest, result_digest, receipt_digest,
                    completion_idempotency_key, completed_at, recorded_at, revision)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                         $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
                         $23, $24, $25, $26, $27, $28, $29, $30, $31, $32)",
                &[
                    &result.fence.scope.cell.as_str(),
                    &result.fence.scope.tenant_id.as_str(),
                    &result.fence.project_id.as_str(),
                    &result.fence.mission_id.as_str(),
                    &result.task_id.as_str(),
                    &to_sql_u64(result.fence.project_key_generation)?,
                    &to_sql_u64(result.fence.mission_generation)?,
                    &to_sql_u64(result.fence.mission_version)?,
                    &result.fence.mission_digest,
                    &result.dispatch_registration_id,
                    &result.lease_id.as_str(),
                    &to_sql_u64(result.lease_generation)?,
                    &result.lease_owner,
                    &result.provider_id,
                    &result.provider_implementation_digest,
                    &result.service_contract_digest,
                    &result.current_commit_digest,
                    &to_sql_u64(result.output.key_version)?,
                    &result.output.nonce,
                    &result.output.ciphertext,
                    &result.output.aad_digest,
                    &result.output.content_digest,
                    &result.evidence_digest,
                    &result.effect_receipt_digest,
                    &result.outcome_link_digest,
                    &result.request_digest,
                    &result_digest,
                    &receipt_digest,
                    &result.completion_idempotency_key_digest,
                    &result.completed_at,
                    &result.completed_at,
                    &to_sql_u64(receipt_revision)?,
                ],
            )
            .await?;
        let updated = transaction
            .execute(
                "UPDATE hartevo_cell.remote_worker_work_requests
                 SET status = 'completed', completion_idempotency_key = $5,
                     completion_request_digest = $6, completed_at = $7,
                     lease_id = NULL, lease_generation = 0, lease_owner = NULL,
                     lease_token_digest = NULL, lease_expires_at = NULL,
                     heartbeat_at = NULL, updated_at = $7, revision = revision + 1
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4
                   AND status = 'leased' AND lease_id = $8 AND lease_generation = $9
                   AND lease_owner = $10 AND lease_token_digest = $11
                   AND lease_expires_at > $7",
                &[
                    &result.fence.scope.cell.as_str(),
                    &result.fence.scope.tenant_id.as_str(),
                    &result.fence.project_id.as_str(),
                    &result.task_id.as_str(),
                    &result.completion_idempotency_key_digest,
                    &result_digest,
                    &result.completed_at,
                    &result.lease_id.as_str(),
                    &to_sql_u64(result.lease_generation)?,
                    &result.lease_owner,
                    &result.lease_token_digest,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(CloudStorageError::RemoteWorkerWorkFenceLost);
        }
        let final_row = load_work_row_tx(&transaction, &result.fence, &result.task_id, false)
            .await?
            .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
        append_work_log(
            &transaction,
            &result.fence,
            &result.task_id,
            &result.completion_idempotency_key_digest,
            &result_digest,
            "completed",
            WorkLogLease {
                lease_id: Some(result.lease_id.clone()),
                lease_generation: result.lease_generation,
                lease_owner: Some(result.lease_owner.clone()),
                lease_token_digest: Some(result.lease_token_digest.clone()),
                lease_expires_at: None,
                attempts: final_row.attempts,
                revision: final_row.revision,
            },
            None,
            Some(receipt_digest.clone()),
            result.completed_at,
        )
        .await?;
        let receipt = receipt_from_result(result, result_digest, receipt_digest, receipt_revision);
        transaction.commit().await?;
        Ok(CloudRemoteWorkerWorkResultCommit {
            receipt,
            duplicate: false,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "cancel keeps terminal state, lease cleanup, and durable log in one transaction"
    )]
    pub async fn cancel_remote_worker_work(
        &self,
        client: &mut Client,
        cancellation: &CloudRemoteWorkerWorkCancel,
    ) -> Result<CloudRemoteWorkerWorkCancelResult, CloudStorageError> {
        cancellation.validate(self.cell())?;
        let request_digest = cancellation.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &cancellation.fence.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_remote_worker_project(
            &transaction,
            &cancellation.fence.scope,
            &cancellation.fence.project_id,
        )
        .await?;
        lock_project(
            &transaction,
            &cancellation.fence.scope,
            &cancellation.fence.project_id,
        )
        .await?;
        let current = load_work_row_tx(
            &transaction,
            &cancellation.fence,
            &cancellation.task_id,
            true,
        )
        .await?
        .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
        if current.request.dispatch_registration_id != cancellation.dispatch_registration_id {
            return Err(CloudStorageError::RemoteWorkerDispatchNotRegistered);
        }
        if current.status == CloudRemoteWorkerWorkStatus::Cancelled {
            if current.terminal_idempotency_key_digest.as_deref()
                == Some(cancellation.cancel_idempotency_key_digest.as_str())
                && current.terminal_request_digest.as_deref() == Some(request_digest.as_str())
            {
                transaction.commit().await?;
                return Ok(CloudRemoteWorkerWorkCancelResult {
                    task_id: cancellation.task_id.clone(),
                    status: CloudRemoteWorkerWorkStatus::Cancelled,
                    duplicate: true,
                });
            }
            return Err(CloudStorageError::RemoteWorkerWorkAlreadyTerminal);
        }
        if matches!(
            current.status,
            CloudRemoteWorkerWorkStatus::Completed
                | CloudRemoteWorkerWorkStatus::Uncertain
                | CloudRemoteWorkerWorkStatus::DeadLetter
        ) {
            return Err(CloudStorageError::RemoteWorkerWorkAlreadyTerminal);
        }
        let lease = WorkLogLease {
            lease_id: current.lease_id.clone(),
            lease_generation: current.lease_generation,
            lease_owner: current.lease_owner.clone(),
            lease_token_digest: current.lease_token_digest.clone(),
            lease_expires_at: current.lease_expires_at,
            attempts: current.attempts,
            revision: current.revision + 1,
        };
        transaction
            .execute(
                "UPDATE hartevo_cell.remote_worker_work_requests
                 SET status = 'cancelled', terminal_idempotency_key = $5,
                     terminal_request_digest = $6, terminal_reason_digest = $7,
                     terminal_at = $8, updated_at = $8, revision = revision + 1,
                     lease_id = NULL, lease_generation = 0, lease_owner = NULL,
                     lease_token_digest = NULL, claim_idempotency_key = NULL,
                     claim_request_digest = NULL, lease_expires_at = NULL,
                     heartbeat_at = NULL
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4
                   AND status IN ('pending', 'leased')",
                &[
                    &cancellation.fence.scope.cell.as_str(),
                    &cancellation.fence.scope.tenant_id.as_str(),
                    &cancellation.fence.project_id.as_str(),
                    &cancellation.task_id.as_str(),
                    &cancellation.cancel_idempotency_key_digest,
                    &request_digest,
                    &cancellation.reason_digest,
                    &cancellation.cancelled_at,
                ],
            )
            .await?;
        append_work_log(
            &transaction,
            &cancellation.fence,
            &cancellation.task_id,
            &cancellation.cancel_idempotency_key_digest,
            &request_digest,
            "cancelled",
            lease,
            Some(cancellation.reason_digest.clone()),
            None,
            cancellation.cancelled_at,
        )
        .await?;
        transaction.commit().await?;
        Ok(CloudRemoteWorkerWorkCancelResult {
            task_id: cancellation.task_id.clone(),
            status: CloudRemoteWorkerWorkStatus::Cancelled,
            duplicate: false,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "uncertain recovery freezes the lease and records a non-replayable terminal event atomically"
    )]
    pub async fn mark_remote_worker_work_uncertain(
        &self,
        client: &mut Client,
        uncertain: &CloudRemoteWorkerWorkUncertain,
    ) -> Result<CloudRemoteWorkerWorkUncertainResult, CloudStorageError> {
        uncertain.validate(self.cell())?;
        let request_digest = uncertain.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &uncertain.fence.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_remote_worker_project(
            &transaction,
            &uncertain.fence.scope,
            &uncertain.fence.project_id,
        )
        .await?;
        lock_project(
            &transaction,
            &uncertain.fence.scope,
            &uncertain.fence.project_id,
        )
        .await?;
        let current = load_work_row_tx(&transaction, &uncertain.fence, &uncertain.task_id, true)
            .await?
            .ok_or(CloudStorageError::RemoteWorkerWorkNotFound)?;
        if current.request.dispatch_registration_id != uncertain.dispatch_registration_id {
            return Err(CloudStorageError::RemoteWorkerDispatchNotRegistered);
        }
        if current.status == CloudRemoteWorkerWorkStatus::Uncertain {
            if current.terminal_idempotency_key_digest.as_deref()
                == Some(uncertain.uncertain_idempotency_key_digest.as_str())
                && current.terminal_request_digest.as_deref() == Some(request_digest.as_str())
            {
                transaction.commit().await?;
                return Ok(CloudRemoteWorkerWorkUncertainResult {
                    task_id: uncertain.task_id.clone(),
                    status: CloudRemoteWorkerWorkStatus::Uncertain,
                    duplicate: true,
                });
            }
            return Err(CloudStorageError::RemoteWorkerWorkAlreadyTerminal);
        }
        require_current_lease(
            &current,
            &uncertain.lease_id,
            uncertain.lease_generation,
            &uncertain.lease_owner,
            &uncertain.lease_token_digest,
            uncertain.uncertain_at,
        )?;
        transaction
            .execute(
                "UPDATE hartevo_cell.remote_worker_work_requests
                 SET status = 'uncertain', terminal_idempotency_key = $5,
                     terminal_request_digest = $6, terminal_reason_digest = $7,
                     terminal_at = $8, updated_at = $8, revision = revision + 1,
                     lease_id = NULL, lease_generation = 0, lease_owner = NULL,
                     lease_token_digest = NULL, claim_idempotency_key = NULL,
                     claim_request_digest = NULL, lease_expires_at = NULL,
                     heartbeat_at = NULL
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4
                   AND status = 'leased' AND lease_id = $9 AND lease_generation = $10
                   AND lease_owner = $11 AND lease_token_digest = $12
                   AND lease_expires_at > $8",
                &[
                    &uncertain.fence.scope.cell.as_str(),
                    &uncertain.fence.scope.tenant_id.as_str(),
                    &uncertain.fence.project_id.as_str(),
                    &uncertain.task_id.as_str(),
                    &uncertain.uncertain_idempotency_key_digest,
                    &request_digest,
                    &uncertain.reason_digest,
                    &uncertain.uncertain_at,
                    &uncertain.lease_id.as_str(),
                    &to_sql_u64(uncertain.lease_generation)?,
                    &uncertain.lease_owner,
                    &uncertain.lease_token_digest,
                ],
            )
            .await?;
        append_work_log(
            &transaction,
            &uncertain.fence,
            &uncertain.task_id,
            &uncertain.uncertain_idempotency_key_digest,
            &request_digest,
            "uncertain",
            WorkLogLease {
                lease_id: Some(uncertain.lease_id.clone()),
                lease_generation: uncertain.lease_generation,
                lease_owner: Some(uncertain.lease_owner.clone()),
                lease_token_digest: Some(uncertain.lease_token_digest.clone()),
                lease_expires_at: None,
                attempts: current.attempts,
                revision: current.revision + 1,
            },
            Some(uncertain.reason_digest.clone()),
            None,
            uncertain.uncertain_at,
        )
        .await?;
        transaction.commit().await?;
        Ok(CloudRemoteWorkerWorkUncertainResult {
            task_id: uncertain.task_id.clone(),
            status: CloudRemoteWorkerWorkStatus::Uncertain,
            duplicate: false,
        })
    }
}

pub(crate) async fn cleanup_remote_worker_work_for_registration(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    mission_id: &MissionId,
    dispatch_registration_id: &str,
    terminal_status: CloudRemoteWorkerWorkStatus,
    terminal_at: DateTime<Utc>,
) -> Result<(u64, u64), CloudStorageError> {
    let status = terminal_status.as_str();
    if !matches!(
        terminal_status,
        CloudRemoteWorkerWorkStatus::Cancelled | CloudRemoteWorkerWorkStatus::DeadLetter
    ) {
        return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
    }
    let rows = transaction
        .query(
            &format!(
                "SELECT {WORK_COLUMNS}
                 FROM hartevo_cell.remote_worker_work_requests
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND mission_id = $4 AND dispatch_registration_id = $5
                   AND status IN ('pending', 'leased')
                 FOR UPDATE"
            ),
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &mission_id.as_str(),
                &dispatch_registration_id,
            ],
        )
        .await?;
    let mut cleaned = 0_u64;
    let mut leases = 0_u64;
    for row in rows {
        let current = decode_work_row(&row, scope)?;
        let reason_digest = canonical_digest(&serde_json::json!({
            "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
            "dispatchRegistrationId": dispatch_registration_id,
            "status": status,
        }))?;
        let operation_id = canonical_digest(&serde_json::json!({
            "reason": reason_digest,
            "taskId": current.request.task_id,
        }))?;
        let request_digest = canonical_digest(&serde_json::json!({
            "taskId": current.request.task_id,
            "status": status,
            "at": terminal_at,
        }))?;
        if current.lease_id.is_some() {
            leases = leases.saturating_add(1);
        }
        transaction
            .execute(
                "UPDATE hartevo_cell.remote_worker_work_requests
                 SET status = $5, terminal_idempotency_key = $6,
                     terminal_request_digest = $7, terminal_reason_digest = $8,
                     terminal_at = $9, updated_at = $9, revision = revision + 1,
                     lease_id = NULL, lease_generation = 0, lease_owner = NULL,
                     lease_token_digest = NULL, claim_idempotency_key = NULL,
                     claim_request_digest = NULL, lease_expires_at = NULL,
                     heartbeat_at = NULL
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4
                   AND status IN ('pending', 'leased')",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &current.request.task_id.as_str(),
                    &status,
                    &operation_id,
                    &request_digest,
                    &reason_digest,
                    &terminal_at,
                ],
            )
            .await?;
        append_work_log(
            transaction,
            &current.request.fence,
            &current.request.task_id,
            &operation_id,
            &request_digest,
            status,
            WorkLogLease {
                lease_id: current.lease_id,
                lease_generation: current.lease_generation,
                lease_owner: current.lease_owner,
                lease_token_digest: current.lease_token_digest,
                lease_expires_at: current.lease_expires_at,
                attempts: current.attempts,
                revision: current.revision + 1,
            },
            Some(reason_digest),
            None,
            terminal_at,
        )
        .await?;
        cleaned = cleaned.saturating_add(1);
    }
    Ok((cleaned, leases))
}

async fn ensure_active_provider(
    transaction: &Transaction<'_>,
    fence: &CloudRemoteWorkerMissionFence,
    dispatch_registration_id: &str,
    worker_id: &WorkerId,
) -> Result<ProviderIdentity, CloudStorageError> {
    remote_worker_plugin::ensure_remote_worker_dispatch_active(
        transaction,
        &fence.scope,
        &fence.project_id,
        &fence.mission_id,
        dispatch_registration_id,
        worker_id,
    )
    .await?;
    let row = transaction
        .query_one(
            "SELECT registration.provider_id,
                    registration.provider_implementation_digest,
                    registration.service_contract_digest
             FROM hartevo_cell.remote_worker_transport_registrations AS registration
             WHERE registration.cell = $1 AND registration.tenant_id = $2
               AND registration.project_id = $3 AND registration.mission_id = $4
               AND registration.dispatch_registration_id = $5
               AND registration.state = 'mounted'",
            &[
                &fence.scope.cell.as_str(),
                &fence.scope.tenant_id.as_str(),
                &fence.project_id.as_str(),
                &fence.mission_id.as_str(),
                &dispatch_registration_id,
            ],
        )
        .await?;
    Ok(ProviderIdentity {
        provider_id: row.get(0),
        provider_implementation_digest: row.get(1),
        service_contract_digest: row.get(2),
    })
}

async fn load_claim_candidate(
    transaction: &Transaction<'_>,
    claim: &CloudRemoteWorkerWorkClaim,
) -> Result<Option<WorkRow>, CloudStorageError> {
    let base = format!(
        "SELECT {WORK_COLUMNS}
         FROM hartevo_cell.remote_worker_work_requests
         WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
           AND mission_id = $4 AND project_key_generation = $5
           AND mission_generation = $6 AND mission_version = $7
           AND mission_digest = $8 AND dispatch_registration_id = $9
           AND worker_id = $10 AND enqueued_at <= $11 AND deadline_at > $11
           AND (status = 'pending'
                OR (status = 'leased' AND lease_expires_at <= $11))
         ORDER BY enqueued_at ASC, task_id ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1"
    );
    let row = if let Some(task_id) = &claim.task_id {
        transaction
            .query_opt(
                &base.replacen("ORDER BY", "AND task_id = $12 ORDER BY", 1),
                &[
                    &claim.fence.scope.cell.as_str(),
                    &claim.fence.scope.tenant_id.as_str(),
                    &claim.fence.project_id.as_str(),
                    &claim.fence.mission_id.as_str(),
                    &to_sql_u64(claim.fence.project_key_generation)?,
                    &to_sql_u64(claim.fence.mission_generation)?,
                    &to_sql_u64(claim.fence.mission_version)?,
                    &claim.fence.mission_digest,
                    &claim.dispatch_registration_id,
                    &claim.worker_id.as_str(),
                    &claim.now,
                    &task_id.as_str(),
                ],
            )
            .await?
    } else {
        transaction
            .query_opt(
                &base,
                &[
                    &claim.fence.scope.cell.as_str(),
                    &claim.fence.scope.tenant_id.as_str(),
                    &claim.fence.project_id.as_str(),
                    &claim.fence.mission_id.as_str(),
                    &to_sql_u64(claim.fence.project_key_generation)?,
                    &to_sql_u64(claim.fence.mission_generation)?,
                    &to_sql_u64(claim.fence.mission_version)?,
                    &claim.fence.mission_digest,
                    &claim.dispatch_registration_id,
                    &claim.worker_id.as_str(),
                    &claim.now,
                ],
            )
            .await?
    };
    row.map(|row| decode_work_row(&row, &claim.fence.scope))
        .transpose()
}

async fn load_work_row_tx(
    transaction: &Transaction<'_>,
    fence: &CloudRemoteWorkerMissionFence,
    task_id: &TaskId,
    lock: bool,
) -> Result<Option<WorkRow>, CloudStorageError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let row = transaction
        .query_opt(
            &format!(
                "SELECT {WORK_COLUMNS}
                 FROM hartevo_cell.remote_worker_work_requests
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND task_id = $4{suffix}"
            ),
            &[
                &fence.scope.cell.as_str(),
                &fence.scope.tenant_id.as_str(),
                &fence.project_id.as_str(),
                &task_id.as_str(),
            ],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let decoded = decode_work_row(&row, &fence.scope)?;
    if decoded.request.fence != *fence {
        return Err(CloudStorageError::RemoteWorkerWorkFenceLost);
    }
    if decoded.request.task_id != *task_id {
        return Err(CloudStorageError::RemoteWorkerWorkFenceLost);
    }
    Ok(Some(decoded))
}

fn decode_work_row(row: &Row, scope: &CellScope) -> Result<WorkRow, CloudStorageError> {
    let input = EncryptedPayload {
        key_version: from_sql_u64(row.get(9), "Remote Worker input key version")?,
        nonce: row.get(10),
        ciphertext: row.get(11),
        aad_digest: row.get(12),
        content_digest: row.get(13),
    };
    let request = CloudRemoteWorkerWorkRequest {
        fence: CloudRemoteWorkerMissionFence {
            scope: scope.clone(),
            project_id: ProjectId::from_stable(row.get::<_, String>(0)),
            project_key_generation: from_sql_u64(
                row.get(5),
                "Remote Worker project key generation",
            )?,
            mission_id: MissionId::from_stable(row.get::<_, String>(1)),
            mission_generation: from_sql_u64(row.get(6), "Remote Worker mission generation")?,
            mission_version: from_sql_u64(row.get(7), "Remote Worker mission version")?,
            mission_digest: row.get(8),
        },
        task_id: TaskId::from_stable(row.get::<_, String>(2)),
        worker_id: WorkerId::from_stable(row.get::<_, String>(3)),
        dispatch_registration_id: row.get(4),
        input,
        idempotency_key_digest: row.get(14),
        enqueued_at: row.get(33),
        deadline_at: row.get(34),
    };
    request.validate(scope.cell)?;
    let attempts = u32::try_from(row.get::<_, i32>(17))
        .map_err(|_| CloudStorageError::StoredValueInvalid("Remote Worker attempts".into()))?;
    Ok(WorkRow {
        request,
        status: decode_work_status(&row.get::<_, String>(16))?,
        attempts,
        lease_id: row
            .get::<_, Option<String>>(18)
            .map(WorkerLeaseId::from_stable),
        lease_generation: from_sql_u64(row.get(19), "Remote Worker lease generation")?,
        lease_owner: row.get(20),
        lease_token_digest: row.get(21),
        lease_expires_at: row.get(24),
        heartbeat_at: row.get(25),
        terminal_idempotency_key_digest: row.get(29),
        terminal_request_digest: row.get(30),
        terminal_reason_digest: row.get(31),
        terminal_at: row.get(32),
        revision: from_sql_u64(row.get(36), "Remote Worker work revision")?,
    })
}

async fn load_result_receipt_tx(
    transaction: &Transaction<'_>,
    fence: &CloudRemoteWorkerMissionFence,
    task_id: &TaskId,
    lock: bool,
) -> Result<Option<CloudRemoteWorkerWorkResultReceipt>, CloudStorageError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let row = transaction
        .query_opt(
            &format!(
                "SELECT mission_id, project_key_generation, mission_generation,
                        mission_version, mission_digest, dispatch_registration_id,
                        lease_id, lease_generation, lease_owner, provider_id,
                        provider_implementation_digest, service_contract_digest,
                        current_commit_digest, output_key_version, output_nonce,
                        output_ciphertext, output_aad_digest, output_content_digest,
                        evidence_digest, effect_receipt_digest, outcome_link_digest,
                        request_digest, result_digest, receipt_digest,
                        completion_idempotency_key, completed_at, recorded_at, revision
                 FROM hartevo_cell.remote_worker_result_receipts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4{suffix}"
            ),
            &[
                &fence.scope.cell.as_str(),
                &fence.scope.tenant_id.as_str(),
                &fence.project_id.as_str(),
                &task_id.as_str(),
            ],
        )
        .await?;
    row.map(|row| decode_result_receipt(&row, fence, task_id))
        .transpose()
}

fn decode_result_receipt(
    row: &Row,
    fence: &CloudRemoteWorkerMissionFence,
    task_id: &TaskId,
) -> Result<CloudRemoteWorkerWorkResultReceipt, CloudStorageError> {
    let receipt_fence = CloudRemoteWorkerMissionFence {
        scope: fence.scope.clone(),
        project_id: fence.project_id.clone(),
        project_key_generation: from_sql_u64(
            row.get(1),
            "Remote Worker receipt project key generation",
        )?,
        mission_id: MissionId::from_stable(row.get::<_, String>(0)),
        mission_generation: from_sql_u64(row.get(2), "Remote Worker receipt mission generation")?,
        mission_version: from_sql_u64(row.get(3), "Remote Worker receipt mission version")?,
        mission_digest: row.get(4),
    };
    if receipt_fence != *fence {
        return Err(CloudStorageError::RemoteWorkerWorkFenceLost);
    }
    let output = EncryptedPayload {
        key_version: from_sql_u64(row.get(13), "Remote Worker output key version")?,
        nonce: row.get(14),
        ciphertext: row.get(15),
        aad_digest: row.get(16),
        content_digest: row.get(17),
    };
    output.validate()?;
    let receipt = CloudRemoteWorkerWorkResultReceipt {
        fence: receipt_fence,
        task_id: task_id.clone(),
        dispatch_registration_id: row.get(5),
        request_digest: row.get(21),
        lease_id: WorkerLeaseId::from_stable(row.get::<_, String>(6)),
        lease_generation: from_sql_u64(row.get(7), "Remote Worker receipt lease generation")?,
        lease_owner: row.get(8),
        output,
        evidence_digest: row.get(18),
        effect_receipt_digest: row.get(19),
        outcome_link_digest: row.get(20),
        provider_id: row.get(9),
        provider_implementation_digest: row.get(10),
        service_contract_digest: row.get(11),
        current_commit_digest: row.get(12),
        result_digest: row.get(22),
        receipt_digest: row.get(23),
        completion_idempotency_key_digest: row.get(24),
        completed_at: row.get(25),
        recorded_at: row.get(26),
        revision: from_sql_u64(row.get(27), "Remote Worker receipt revision")?,
    };
    if !is_sha256(&receipt.request_digest)
        || !is_sha256(&receipt.evidence_digest)
        || !is_sha256(&receipt.provider_implementation_digest)
        || !is_sha256(&receipt.service_contract_digest)
        || !is_sha256(&receipt.current_commit_digest)
        || !is_sha256(&receipt.result_digest)
        || !is_sha256(&receipt.receipt_digest)
        || !is_sha256(&receipt.completion_idempotency_key_digest)
    {
        return Err(CloudStorageError::StoredValueInvalid(
            "Remote Worker result receipt digest".into(),
        ));
    }
    validate_optional_digest(receipt.effect_receipt_digest.as_deref())?;
    validate_optional_digest(receipt.outcome_link_digest.as_deref())?;
    Ok(receipt)
}

async fn load_work_log_by_operation(
    transaction: &Transaction<'_>,
    fence: &CloudRemoteWorkerMissionFence,
    operation_id_digest: &str,
) -> Result<Option<WorkLogEntry>, CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT sequence, task_id, operation_id_digest, request_digest, event_type,
                    lease_id, lease_generation, lease_owner, lease_token_digest,
                    lease_expires_at, attempts, revision, reason_digest,
                    result_receipt_digest, recorded_at, event_digest
             FROM hartevo_cell.remote_worker_work_log
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND operation_id_digest = $4",
            &[
                &fence.scope.cell.as_str(),
                &fence.scope.tenant_id.as_str(),
                &fence.project_id.as_str(),
                &operation_id_digest,
            ],
        )
        .await?;
    row.map(|row| decode_work_log(&row)).transpose()
}

#[allow(
    clippy::too_many_arguments,
    reason = "durable log rows retain every exact scope, lease, terminal reason, and receipt digest"
)]
async fn append_work_log(
    transaction: &Transaction<'_>,
    fence: &CloudRemoteWorkerMissionFence,
    task_id: &TaskId,
    operation_id_digest: &str,
    request_digest: &str,
    event_type: &str,
    lease: WorkLogLease,
    reason_digest: Option<String>,
    result_receipt_digest: Option<String>,
    recorded_at: DateTime<Utc>,
) -> Result<WorkLogEntry, CloudStorageError> {
    if !is_sha256(operation_id_digest)
        || !is_sha256(request_digest)
        || !matches!(
            event_type,
            "enqueued"
                | "claimed"
                | "takeover"
                | "heartbeat"
                | "completed"
                | "cancelled"
                | "uncertain"
                | "dead_letter"
        )
    {
        return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
    }
    validate_optional_digest(reason_digest.as_deref())?;
    validate_optional_digest(result_receipt_digest.as_deref())?;
    if let Some(existing) =
        load_work_log_by_operation(transaction, fence, operation_id_digest).await?
    {
        ensure_request_digest(&existing.request_digest, request_digest)?;
        if existing.event_type != event_type {
            return Err(CloudStorageError::IdempotencyConflict);
        }
        return Ok(existing);
    }
    let event_digest = canonical_digest(&serde_json::json!({
        "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
        "fence": fence,
        "taskId": task_id,
        "operationIdDigest": operation_id_digest,
        "requestDigest": request_digest,
        "eventType": event_type,
        "leaseId": lease.lease_id,
        "leaseGeneration": lease.lease_generation,
        "leaseOwner": lease.lease_owner,
        "leaseExpiresAt": lease.lease_expires_at,
        "attempts": lease.attempts,
        "revision": lease.revision,
        "reasonDigest": reason_digest,
        "resultReceiptDigest": result_receipt_digest,
        "recordedAt": recorded_at,
    }))?;
    let _sequence = transaction
        .query_one(
            "INSERT INTO hartevo_cell.remote_worker_work_log
               (cell, tenant_id, project_id, mission_id, task_id, operation_id_digest,
                request_digest, event_type, project_key_generation, mission_generation,
                mission_version, mission_digest, lease_id, lease_generation,
                lease_owner, lease_token_digest, lease_expires_at, attempts, revision,
                reason_digest, result_receipt_digest, recorded_at, event_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                     $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
             RETURNING sequence",
            &[
                &fence.scope.cell.as_str(),
                &fence.scope.tenant_id.as_str(),
                &fence.project_id.as_str(),
                &fence.mission_id.as_str(),
                &task_id.as_str(),
                &operation_id_digest,
                &request_digest,
                &event_type,
                &to_sql_u64(fence.project_key_generation)?,
                &to_sql_u64(fence.mission_generation)?,
                &to_sql_u64(fence.mission_version)?,
                &fence.mission_digest,
                &lease.lease_id.as_ref().map(WorkerLeaseId::as_str),
                &to_sql_u64(lease.lease_generation)?,
                &lease.lease_owner,
                &lease.lease_token_digest,
                &lease.lease_expires_at,
                &i32::try_from(lease.attempts).map_err(|_| CloudStorageError::RevisionOverflow)?,
                &to_sql_u64(lease.revision)?,
                &reason_digest,
                &result_receipt_digest,
                &recorded_at,
                &event_digest,
            ],
        )
        .await?
        .get::<_, i64>(0);
    Ok(WorkLogEntry {
        task_id: task_id.clone(),
        request_digest: request_digest.into(),
        event_type: event_type.into(),
        lease_id: lease.lease_id,
        lease_generation: lease.lease_generation,
        lease_owner: lease.lease_owner,
        lease_token_digest: lease.lease_token_digest,
        lease_expires_at: lease.lease_expires_at,
        attempts: lease.attempts,
        revision: lease.revision,
        recorded_at,
    })
}

fn decode_work_log(row: &Row) -> Result<WorkLogEntry, CloudStorageError> {
    Ok(WorkLogEntry {
        task_id: TaskId::from_stable(row.get::<_, String>(1)),
        request_digest: row.get(3),
        event_type: row.get(4),
        lease_id: row
            .get::<_, Option<String>>(5)
            .map(WorkerLeaseId::from_stable),
        lease_generation: from_sql_u64(row.get(6), "Remote Worker log lease generation")?,
        lease_owner: row.get(7),
        lease_token_digest: row.get(8),
        lease_expires_at: row.get(9),
        attempts: u32::try_from(row.get::<_, i32>(10)).map_err(|_| {
            CloudStorageError::StoredValueInvalid("Remote Worker log attempts".into())
        })?,
        revision: from_sql_u64(row.get(11), "Remote Worker log revision")?,
        recorded_at: row.get(14),
    })
}

fn historical_lease_from_log(
    request: CloudRemoteWorkerWorkRequest,
    log: &WorkLogEntry,
) -> Result<CloudRemoteWorkerWorkLease, CloudStorageError> {
    let lease_id = log
        .lease_id
        .clone()
        .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?;
    let lease_owner = log
        .lease_owner
        .clone()
        .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?;
    let lease_token_digest = log
        .lease_token_digest
        .clone()
        .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?;
    let lease_expires_at = log
        .lease_expires_at
        .ok_or(CloudStorageError::RemoteWorkerLeaseLost)?;
    if log.lease_generation == 0 || lease_expires_at <= log.recorded_at {
        return Err(CloudStorageError::RemoteWorkerLeaseLost);
    }
    Ok(CloudRemoteWorkerWorkLease {
        request,
        lease_id,
        lease_generation: log.lease_generation,
        lease_owner,
        lease_token_digest,
        attempts: log.attempts,
        heartbeat_at: log.recorded_at,
        lease_expires_at,
        revision: log.revision,
    })
}

fn receipt_digest(
    result: &CloudRemoteWorkerWorkResult,
    result_digest: &str,
) -> Result<String, CloudStorageError> {
    canonical_digest(&serde_json::json!({
        "schema": REMOTE_WORKER_EXECUTION_SCHEMA,
        "fence": result.fence,
        "taskId": result.task_id,
        "dispatchRegistrationId": result.dispatch_registration_id,
        "requestDigest": result.request_digest,
        "leaseId": result.lease_id,
        "leaseGeneration": result.lease_generation,
        "leaseOwner": result.lease_owner,
        "resultDigest": result_digest,
        "completionIdempotencyKeyDigest": result.completion_idempotency_key_digest,
        "completedAt": result.completed_at,
    }))
}

fn receipt_from_result(
    result: &CloudRemoteWorkerWorkResult,
    result_digest: String,
    receipt_digest: String,
    revision: u64,
) -> CloudRemoteWorkerWorkResultReceipt {
    CloudRemoteWorkerWorkResultReceipt {
        fence: result.fence.clone(),
        task_id: result.task_id.clone(),
        dispatch_registration_id: result.dispatch_registration_id.clone(),
        request_digest: result.request_digest.clone(),
        lease_id: result.lease_id.clone(),
        lease_generation: result.lease_generation,
        lease_owner: result.lease_owner.clone(),
        output: result.output.clone(),
        evidence_digest: result.evidence_digest.clone(),
        effect_receipt_digest: result.effect_receipt_digest.clone(),
        outcome_link_digest: result.outcome_link_digest.clone(),
        provider_id: result.provider_id.clone(),
        provider_implementation_digest: result.provider_implementation_digest.clone(),
        service_contract_digest: result.service_contract_digest.clone(),
        current_commit_digest: result.current_commit_digest.clone(),
        result_digest,
        receipt_digest,
        completion_idempotency_key_digest: result.completion_idempotency_key_digest.clone(),
        completed_at: result.completed_at,
        recorded_at: result.completed_at,
        revision,
    }
}

fn require_current_lease(
    current: &WorkRow,
    lease_id: &WorkerLeaseId,
    lease_generation: u64,
    lease_owner: &str,
    lease_token_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    if current.status != CloudRemoteWorkerWorkStatus::Leased
        || current.lease_id.as_ref() != Some(lease_id)
        || current.lease_generation != lease_generation
        || current.lease_owner.as_deref() != Some(lease_owner)
        || current.lease_token_digest.as_deref() != Some(lease_token_digest)
        || current.heartbeat_at.is_none_or(|heartbeat| now < heartbeat)
        || current
            .lease_expires_at
            .is_none_or(|expires_at| now >= expires_at)
    {
        return Err(CloudStorageError::RemoteWorkerLeaseLost);
    }
    Ok(())
}

fn bounded_lease_expiry(
    now: DateTime<Utc>,
    lease_for: Duration,
    deadline_at: DateTime<Utc>,
) -> Result<DateTime<Utc>, CloudStorageError> {
    validate_lease_duration(lease_for)?;
    let requested_expiry = now
        .checked_add_signed(lease_for)
        .ok_or(CloudStorageError::InvalidRemoteWorkerWorkRequest)?;
    let expires_at = requested_expiry.min(deadline_at);
    if expires_at <= now {
        return Err(CloudStorageError::RemoteWorkerLeaseLost);
    }
    Ok(expires_at)
}

fn validate_lease_duration(lease_for: Duration) -> Result<(), CloudStorageError> {
    if lease_for <= Duration::zero() || lease_for > super::MAX_REMOTE_WORKER_LEASE {
        return Err(CloudStorageError::InvalidRemoteWorkerWorkRequest);
    }
    Ok(())
}

fn validate_optional_digest(value: Option<&str>) -> Result<(), CloudStorageError> {
    if value.is_some_and(|digest| !is_sha256(digest)) {
        return Err(CloudStorageError::InvalidRemoteWorkerWorkResult);
    }
    Ok(())
}

fn decode_work_status(value: &str) -> Result<CloudRemoteWorkerWorkStatus, CloudStorageError> {
    match value {
        "pending" => Ok(CloudRemoteWorkerWorkStatus::Pending),
        "leased" => Ok(CloudRemoteWorkerWorkStatus::Leased),
        "completed" => Ok(CloudRemoteWorkerWorkStatus::Completed),
        "cancelled" => Ok(CloudRemoteWorkerWorkStatus::Cancelled),
        "uncertain" => Ok(CloudRemoteWorkerWorkStatus::Uncertain),
        "dead_letter" => Ok(CloudRemoteWorkerWorkStatus::DeadLetter),
        other => Err(CloudStorageError::StoredValueInvalid(format!(
            "Remote Worker work status {other}"
        ))),
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{TenantId, WorkerId};
    use sha2::{Digest, Sha256};

    use super::*;

    fn digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    fn payload(byte: u8, size: usize) -> EncryptedPayload {
        let ciphertext = vec![byte; size];
        EncryptedPayload {
            key_version: 1,
            nonce: vec![byte; 12],
            aad_digest: digest("aad"),
            content_digest: format!("{:x}", Sha256::digest(&ciphertext)),
            ciphertext,
        }
    }

    fn fence() -> CloudRemoteWorkerMissionFence {
        CloudRemoteWorkerMissionFence {
            scope: CellScope {
                cell: DataCell::Us,
                tenant_id: TenantId::from("tenant-1"),
            },
            project_id: ProjectId::from("project-1"),
            project_key_generation: 3,
            mission_id: MissionId::from("mission-1"),
            mission_generation: 4,
            mission_version: 7,
            mission_digest: digest("mission-contract"),
        }
    }

    fn request() -> CloudRemoteWorkerWorkRequest {
        CloudRemoteWorkerWorkRequest {
            fence: fence(),
            task_id: TaskId::from("task-1"),
            worker_id: WorkerId::from("worker-1"),
            dispatch_registration_id: digest("dispatch"),
            input: payload(3, 64),
            idempotency_key_digest: digest("request"),
            enqueued_at: Utc
                .with_ymd_and_hms(2026, 8, 14, 10, 0, 0)
                .single()
                .expect("valid timestamp"),
            deadline_at: Utc
                .with_ymd_and_hms(2026, 8, 14, 11, 0, 0)
                .single()
                .expect("valid timestamp"),
        }
    }

    #[test]
    fn exact_mission_fence_and_bounded_ciphertext_are_contract_fields() {
        let base = request();
        base.validate(DataCell::Us).expect("valid typed request");
        let base_digest = base.request_digest().expect("request digest");
        let mut changed = base.clone();
        changed.fence.mission_version += 1;
        assert_ne!(
            base_digest,
            changed.request_digest().expect("changed request digest")
        );
        let mut oversized = base;
        oversized.input = payload(9, MAX_REMOTE_WORKER_INPUT_BYTES + 1);
        assert!(matches!(
            oversized.validate(DataCell::Us),
            Err(CloudStorageError::InvalidRemoteWorkerWorkRequest)
        ));
    }

    #[test]
    fn result_contract_has_no_plaintext_and_binds_provider_receipt_fields() {
        let request = request();
        let result = CloudRemoteWorkerWorkResult {
            fence: request.fence.clone(),
            task_id: request.task_id.clone(),
            worker_id: request.worker_id.clone(),
            dispatch_registration_id: request.dispatch_registration_id.clone(),
            request_digest: request.request_digest().expect("request digest"),
            lease_id: WorkerLeaseId::from("lease-1"),
            lease_generation: 1,
            lease_owner: "cell-worker-process".into(),
            lease_token_digest: digest("lease-token"),
            output: payload(4, 64),
            evidence_digest: digest("evidence"),
            effect_receipt_digest: None,
            outcome_link_digest: None,
            provider_id: "regional-cell-provider".into(),
            provider_implementation_digest: digest("provider"),
            service_contract_digest: digest("service"),
            current_commit_digest: digest("commit"),
            completion_idempotency_key_digest: digest("completion"),
            completed_at: request.enqueued_at + Duration::seconds(10),
        };
        result.validate(DataCell::Us).expect("valid typed result");
        let result_digest = result.result_digest().expect("result digest");
        assert_ne!(result_digest, request.fence.mission_digest);
        let serialized = serde_json::to_string(&result).expect("serialize result contract");
        assert!(!serialized.contains("PLAINTEXT"));
        assert!(serialized.contains("providerImplementationDigest"));
    }

    #[test]
    fn uncertain_is_not_a_local_first_replay_permission() {
        assert_eq!(
            CloudRemoteWorkerDispatchAvailability::Connected.decision(),
            CloudRemoteWorkerDispatchDecision::DispatchToCell
        );
        assert_eq!(
            CloudRemoteWorkerDispatchAvailability::Disconnected.decision(),
            CloudRemoteWorkerDispatchDecision::KeepLocalPending
        );
        assert_eq!(CloudRemoteWorkerWorkStatus::Uncertain.as_str(), "uncertain");
    }
}

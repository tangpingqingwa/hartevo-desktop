use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AccountId, ConnectionId, CreatorTask, CreatorTaskId, DeliverableId, Effect, EffectId,
    EffectStatus, Mission, MissionId, Money, ProjectId, Receipt, TenantId, Verification,
    VerificationStatus, WorkerId,
};

/// The largest bounded result a CreatorWork provider may return in one
/// fulfillment. The File Broker remains the artifact boundary; this limit is
/// only for the provider's result metadata and evidence handoff.
pub const CREATOR_WORK_MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
pub const CREATOR_WORK_PROVIDER_PROTOCOL_VERSION: u16 = 1;
pub const CREATOR_WORK_HTTP_PATH: &str = "/creator-work/v1/execute";
pub const CREATOR_WORK_SOURCE_COMMIT_HEX_LEN: usize = 40;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorWorkProviderStatus {
    Registered,
    Disconnected,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkProviderRegistration {
    pub provider_id: String,
    pub connection_id: ConnectionId,
    pub account_id: AccountId,
    pub generation: u64,
    pub status: CreatorWorkProviderStatus,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CreatorWorkProviderRegistration {
    pub fn new(
        provider_id: impl Into<String>,
        connection_id: ConnectionId,
        account_id: AccountId,
        now: DateTime<Utc>,
    ) -> Result<Self, CreatorWorkFulfillmentError> {
        let provider_id = provider_id.into();
        if provider_id.trim().is_empty()
            || connection_id.as_str().trim().is_empty()
            || account_id.as_str().trim().is_empty()
        {
            return Err(CreatorWorkFulfillmentError::InvalidProviderRegistration);
        }
        Ok(Self {
            provider_id,
            connection_id,
            account_id,
            generation: 1,
            status: CreatorWorkProviderStatus::Registered,
            registered_at: now,
            updated_at: now,
        })
    }

    pub fn reconnect(&self, now: DateTime<Utc>) -> Result<Self, CreatorWorkFulfillmentError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(CreatorWorkFulfillmentError::RevisionOverflow)?;
        Ok(Self {
            provider_id: self.provider_id.clone(),
            connection_id: self.connection_id.clone(),
            account_id: self.account_id.clone(),
            generation,
            status: CreatorWorkProviderStatus::Registered,
            registered_at: now,
            updated_at: now,
        })
    }
}

/// Runtime provider registration is deliberately separate from provider
/// execution. An absent registration is an explicit Disconnected state, not
/// an implicit local fallback.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkProviderRegistry {
    registrations: BTreeMap<String, CreatorWorkProviderRegistration>,
}

impl CreatorWorkProviderRegistry {
    pub fn register(
        &mut self,
        registration: CreatorWorkProviderRegistration,
    ) -> Result<(), CreatorWorkFulfillmentError> {
        if let Some(previous) = self.registrations.get(&registration.provider_id) {
            if previous == &registration {
                return Ok(());
            }
            if registration.generation <= previous.generation {
                return Err(CreatorWorkFulfillmentError::StaleProviderRegistration {
                    provider_id: registration.provider_id,
                    generation: registration.generation,
                });
            }
        }
        self.registrations
            .insert(registration.provider_id.clone(), registration);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        provider_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorWorkFulfillmentError> {
        let registration = self
            .registrations
            .get_mut(provider_id)
            .ok_or_else(|| CreatorWorkFulfillmentError::ProviderDisconnected(provider_id.into()))?;
        registration.status = CreatorWorkProviderStatus::Revoked;
        registration.updated_at = now;
        Ok(())
    }

    pub fn status(&self, provider_id: &str) -> CreatorWorkProviderStatus {
        self.registrations
            .get(provider_id)
            .map_or(CreatorWorkProviderStatus::Disconnected, |registration| {
                registration.status
            })
    }

    pub fn registration(&self, provider_id: &str) -> Option<&CreatorWorkProviderRegistration> {
        self.registrations.get(provider_id)
    }
}

/// A CreatorWork plugin/provider only receives a bounded request and returns
/// facts. It never mutates CreatorTask, Mission, Money, or Cell state.
pub trait CreatorWorkProvider: std::fmt::Debug {
    fn provider_id(&self) -> &str;

    fn execute_bounded(
        &self,
        request: &CreatorWorkExecutionRequest,
    ) -> Result<CreatorWorkProviderResult, CreatorWorkProviderError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorWorkExecutionStatus {
    Started,
    ResultRecorded,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkWorkerLease {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: crate::CreatorId,
    pub task_id: CreatorTaskId,
    pub contract_revision: u64,
    pub task_state_revision: u64,
    pub mission_revision: u64,
    pub provider_generation: u64,
    pub worker_id: WorkerId,
    pub generation: u64,
    pub token_digest: String,
    pub status: CreatorWorkWorkerStatus,
    pub acquired_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorWorkWorkerStatus {
    Active,
    Crashed,
    Revoked,
    Completed,
}

impl CreatorWorkWorkerLease {
    #[allow(clippy::too_many_arguments)]
    pub fn acquire(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        creator_id: crate::CreatorId,
        task_id: CreatorTaskId,
        contract_revision: u64,
        task_state_revision: u64,
        mission_revision: u64,
        provider_generation: u64,
        worker_id: WorkerId,
        generation: u64,
        token_digest: impl Into<String>,
        acquired_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, CreatorWorkFulfillmentError> {
        let token_digest = token_digest.into();
        if tenant_id.as_str().trim().is_empty()
            || project_id.as_str().trim().is_empty()
            || mission_id.as_str().trim().is_empty()
            || creator_id.as_str().trim().is_empty()
            || task_id.as_str().trim().is_empty()
            || contract_revision == 0
            || task_state_revision == 0
            || mission_revision == 0
            || provider_generation == 0
            || worker_id.as_str().trim().is_empty()
            || generation == 0
            || !is_sha256(&token_digest)
            || expires_at <= acquired_at
        {
            return Err(CreatorWorkFulfillmentError::InvalidWorkerLease);
        }
        Ok(Self {
            tenant_id,
            project_id,
            mission_id,
            creator_id,
            task_id,
            contract_revision,
            task_state_revision,
            mission_revision,
            provider_generation,
            worker_id,
            generation,
            token_digest,
            status: CreatorWorkWorkerStatus::Active,
            acquired_at,
            updated_at: acquired_at,
            expires_at,
        })
    }

    pub fn mark_crashed(&mut self, now: DateTime<Utc>) -> Result<(), CreatorWorkFulfillmentError> {
        self.mark_terminal(CreatorWorkWorkerStatus::Crashed, now)
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), CreatorWorkFulfillmentError> {
        self.mark_terminal(CreatorWorkWorkerStatus::Revoked, now)
    }

    pub fn complete(&mut self, now: DateTime<Utc>) -> Result<(), CreatorWorkFulfillmentError> {
        self.mark_terminal(CreatorWorkWorkerStatus::Completed, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        &mut self,
        worker_id: WorkerId,
        token_digest: impl Into<String>,
        task_state_revision: u64,
        mission_revision: u64,
        provider_generation: u64,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, CreatorWorkFulfillmentError> {
        if self.status == CreatorWorkWorkerStatus::Active {
            return Err(CreatorWorkFulfillmentError::WorkerStillActive);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(CreatorWorkFulfillmentError::RevisionOverflow)?;
        self.updated_at = now;
        Self::acquire(
            self.tenant_id.clone(),
            self.project_id.clone(),
            self.mission_id.clone(),
            self.creator_id.clone(),
            self.task_id.clone(),
            self.contract_revision,
            task_state_revision,
            mission_revision,
            provider_generation,
            worker_id,
            generation,
            token_digest,
            now,
            expires_at,
        )
    }

    fn mark_terminal(
        &mut self,
        status: CreatorWorkWorkerStatus,
        now: DateTime<Utc>,
    ) -> Result<(), CreatorWorkFulfillmentError> {
        if self.status == status {
            return Ok(());
        }
        if self.status != CreatorWorkWorkerStatus::Active {
            return Err(CreatorWorkFulfillmentError::WorkerAlreadyFenced);
        }
        self.status = status;
        self.updated_at = now;
        Ok(())
    }

    fn validate_current(&self, now: DateTime<Utc>) -> Result<(), CreatorWorkFulfillmentError> {
        if self.status != CreatorWorkWorkerStatus::Active {
            return Err(CreatorWorkFulfillmentError::WorkerFenced {
                worker_id: self.worker_id.clone(),
                generation: self.generation,
            });
        }
        if self.expires_at <= now {
            return Err(CreatorWorkFulfillmentError::WorkerExpired {
                worker_id: self.worker_id.clone(),
                generation: self.generation,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkPayoutIntent {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: crate::CreatorId,
    pub task_id: CreatorTaskId,
    pub contract_revision: u64,
    pub contract_digest: String,
    pub amount: Money,
    pub funding_reservation_id: String,
    pub idempotency_key: String,
    pub status: CreatorWorkSettlementStatus,
    pub intent_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorWorkSettlementStatus {
    Pending,
}

impl CreatorWorkPayoutIntent {
    fn for_task(task: &CreatorTask) -> Result<Self, CreatorWorkFulfillmentError> {
        let reservation = task
            .funding_reservation
            .as_ref()
            .ok_or(CreatorWorkFulfillmentError::MissingFundingReservation)?;
        if reservation.amount != task.bounty
            || reservation.contract_revision != task.contract_revision
            || reservation.contract_digest != task.contract_digest()
            || reservation.external_id.trim().is_empty()
            || reservation.expires_at <= task.updated_at
        {
            return Err(CreatorWorkFulfillmentError::InvalidFundingReservation);
        }
        let idempotency_key = format!(
            "creator-work:{}:task:{}:contract:{}",
            task.mission_id, task.id, task.contract_revision
        );
        let intent_digest = digest_fields([
            task.tenant_id.as_str(),
            task.project_id.as_str(),
            task.mission_id.as_str(),
            task.creator_id.as_str(),
            task.id.as_str(),
            &task.contract_revision.to_string(),
            &task.contract_digest(),
            &task.bounty.amount_minor.to_string(),
            task.bounty.currency.as_str(),
            &reservation.external_id,
            &idempotency_key,
        ]);
        Ok(Self {
            tenant_id: task.tenant_id.clone(),
            project_id: task.project_id.clone(),
            mission_id: task.mission_id.clone(),
            creator_id: task.creator_id.clone(),
            task_id: task.id.clone(),
            contract_revision: task.contract_revision,
            contract_digest: task.contract_digest(),
            amount: task.bounty.clone(),
            funding_reservation_id: reservation.external_id.clone(),
            idempotency_key,
            status: CreatorWorkSettlementStatus::Pending,
            intent_digest,
        })
    }

    fn exactly_matches_task(&self, task: &CreatorTask) -> bool {
        Self::for_task(task).is_ok_and(|expected| expected == *self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkExecutionRequest {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: crate::CreatorId,
    pub task_id: CreatorTaskId,
    pub contract_revision: u64,
    pub task_state_revision: u64,
    pub mission_revision: u64,
    pub protocol_version: u16,
    pub objective: String,
    pub capability: String,
    pub source_commit: String,
    pub provider_id: String,
    pub connection_id: ConnectionId,
    pub account_id: AccountId,
    pub provider_generation: u64,
    pub effect_id: EffectId,
    pub effect_approval_digest: String,
    pub input_digest: String,
    pub max_output_bytes: u64,
    pub worker: CreatorWorkWorkerLease,
    pub payout_intent: CreatorWorkPayoutIntent,
    pub requested_at: DateTime<Utc>,
}

impl CreatorWorkExecutionRequest {
    pub fn request_digest(&self) -> String {
        digest_fields([
            "creator_work.request.v1",
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            self.creator_id.as_str(),
            self.task_id.as_str(),
            &self.contract_revision.to_string(),
            &self.task_state_revision.to_string(),
            &self.mission_revision.to_string(),
            &self.protocol_version.to_string(),
            &self.objective,
            &self.capability,
            &self.source_commit,
            &self.input_digest,
            &self.provider_id,
            self.connection_id.as_str(),
            self.account_id.as_str(),
            &self.provider_generation.to_string(),
            self.effect_id.as_str(),
            &self.effect_approval_digest,
            self.worker.worker_id.as_str(),
            &self.worker.generation.to_string(),
            &self.worker.token_digest,
            &self.payout_intent.intent_digest,
        ])
    }

    pub fn composition_digest(&self) -> String {
        digest_fields([
            "creator_work.composition.v1",
            &self.protocol_version.to_string(),
            &self.objective,
            &self.capability,
            &self.source_commit,
            &self.input_digest,
        ])
    }
}

/// A File Broker reference only. CreatorWork does not scan or read the
/// artifact here; the existing broker/verification boundary owns that work.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkDeliverableReference {
    pub deliverable_id: DeliverableId,
    pub artifact_uri: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub content_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkProviderResult {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: crate::CreatorId,
    pub task_id: CreatorTaskId,
    pub contract_revision: u64,
    pub task_state_revision: u64,
    pub mission_revision: u64,
    pub protocol_version: u16,
    pub objective: String,
    pub capability: String,
    pub source_commit: String,
    pub input_digest: String,
    pub request_digest: String,
    pub provider_id: String,
    pub provider_generation: u64,
    pub effect_id: EffectId,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub result_id: String,
    pub deliverable: CreatorWorkDeliverableReference,
    pub bounded_output_digest: String,
    pub output_size_bytes: u64,
    pub evidence_digest: String,
    pub receipt: Receipt,
    pub verification: Verification,
    pub payout_intent: CreatorWorkPayoutIntent,
    pub outcome_handoff: CreatorWorkOutcomeHandoff,
}

impl CreatorWorkProviderResult {
    pub fn result_digest(&self) -> String {
        digest_fields([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            self.creator_id.as_str(),
            self.task_id.as_str(),
            &self.contract_revision.to_string(),
            &self.task_state_revision.to_string(),
            &self.mission_revision.to_string(),
            &self.protocol_version.to_string(),
            &self.objective,
            &self.capability,
            &self.source_commit,
            &self.input_digest,
            &self.request_digest,
            &self.provider_id,
            &self.provider_generation.to_string(),
            self.effect_id.as_str(),
            self.worker_id.as_str(),
            &self.worker_generation.to_string(),
            &self.result_id,
            self.deliverable.deliverable_id.as_str(),
            &self.deliverable.artifact_uri,
            &self.deliverable.media_type,
            &self.deliverable.size_bytes.to_string(),
            &self.deliverable.content_digest,
            &self.bounded_output_digest,
            &self.output_size_bytes.to_string(),
            &self.evidence_digest,
            self.receipt.id.as_str(),
            &self.receipt.provider,
            &self.receipt.external_id,
            &self.receipt.accepted_at.to_rfc3339(),
            &self.receipt.request_digest,
            &self.receipt.response_digest,
            self.verification.id.as_str(),
            verification_status_name(&self.verification.status),
            &self.verification.verifier,
            &self.verification.independent.to_string(),
            &self.verification.observed_at.to_rfc3339(),
            &self.verification.evidence_digest,
            self.verification.receipt_id.as_str(),
            &self.payout_intent.intent_digest,
        ])
    }
}

/// Durable, Mission-scoped execution state for a provider request. The
/// request is retained verbatim so restart/replay never reconstructs scope
/// from a newer task or Mission projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkExecutionReceipt {
    pub request: CreatorWorkExecutionRequest,
    pub status: CreatorWorkExecutionStatus,
    pub result_id: Option<String>,
    pub result_digest: Option<String>,
    pub provider_receipt_id: Option<crate::ReceiptId>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl CreatorWorkExecutionReceipt {
    pub fn started(
        request: CreatorWorkExecutionRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, CreatorWorkFulfillmentError> {
        request.worker.validate_current(now)?;
        if request.requested_at > now {
            return Err(CreatorWorkFulfillmentError::InvalidExecutionRequest);
        }
        let mut receipt = Self {
            request,
            status: CreatorWorkExecutionStatus::Started,
            result_id: None,
            result_digest: None,
            provider_receipt_id: None,
            started_at: now,
            updated_at: now,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn record_result(
        &self,
        result: &CreatorWorkProviderResult,
        now: DateTime<Utc>,
    ) -> Result<Self, CreatorWorkFulfillmentError> {
        if self.status != CreatorWorkExecutionStatus::Started
            || result.request_digest != self.request.request_digest()
        {
            return Err(CreatorWorkFulfillmentError::ResultBindingMismatch);
        }
        let mut recorded = Self {
            request: self.request.clone(),
            status: CreatorWorkExecutionStatus::ResultRecorded,
            result_id: Some(result.result_id.clone()),
            result_digest: Some(result.result_digest()),
            provider_receipt_id: Some(result.receipt.id.clone()),
            started_at: self.started_at,
            updated_at: now,
            receipt_digest: String::new(),
        };
        recorded.receipt_digest = recorded.expected_digest();
        recorded.validate()?;
        Ok(recorded)
    }

    pub fn revoke(&self, now: DateTime<Utc>) -> Result<Self, CreatorWorkFulfillmentError> {
        if self.status != CreatorWorkExecutionStatus::Started {
            return Err(CreatorWorkFulfillmentError::ExecutionAlreadyTerminal);
        }
        let mut revoked = Self {
            request: self.request.clone(),
            status: CreatorWorkExecutionStatus::Revoked,
            result_id: None,
            result_digest: None,
            provider_receipt_id: None,
            started_at: self.started_at,
            updated_at: now,
            receipt_digest: String::new(),
        };
        revoked.receipt_digest = revoked.expected_digest();
        revoked.validate()?;
        Ok(revoked)
    }

    pub fn validate(&self) -> Result<(), CreatorWorkFulfillmentError> {
        if !is_source_commit(&self.request.source_commit)
            || self.request.protocol_version != CREATOR_WORK_PROVIDER_PROTOCOL_VERSION
            || self.request.objective.trim().is_empty()
            || self.request.capability.trim().is_empty()
            || !is_sha256(&self.request.input_digest)
            || self.request.request_digest().trim().is_empty()
            || self.started_at > self.updated_at
            || self.receipt_digest != self.expected_digest()
        {
            return Err(CreatorWorkFulfillmentError::InvalidExecutionReceipt);
        }
        match self.status {
            CreatorWorkExecutionStatus::Started | CreatorWorkExecutionStatus::Revoked => {
                if self.result_id.is_some()
                    || self.result_digest.is_some()
                    || self.provider_receipt_id.is_some()
                {
                    return Err(CreatorWorkFulfillmentError::InvalidExecutionReceipt);
                }
            }
            CreatorWorkExecutionStatus::ResultRecorded => {
                if self.result_id.as_deref().is_none_or(str::is_empty)
                    || self
                        .result_digest
                        .as_deref()
                        .is_none_or(|digest| !is_sha256(digest))
                    || self
                        .provider_receipt_id
                        .as_ref()
                        .is_none_or(|id| id.as_str().trim().is_empty())
                {
                    return Err(CreatorWorkFulfillmentError::InvalidExecutionReceipt);
                }
            }
        }
        Ok(())
    }

    pub fn follows(&self, next: &Self) -> bool {
        self.request.request_digest() == next.request.request_digest()
            && match (&self.status, &next.status) {
                (
                    CreatorWorkExecutionStatus::Started,
                    CreatorWorkExecutionStatus::ResultRecorded
                    | CreatorWorkExecutionStatus::Revoked,
                ) => true,
                _ => self == next,
            }
    }

    fn expected_digest(&self) -> String {
        digest_fields([
            "creator_work.execution_receipt.v1",
            &self.request.request_digest(),
            execution_status_name(&self.status),
            self.result_id.as_deref().unwrap_or(""),
            self.result_digest.as_deref().unwrap_or(""),
            self.provider_receipt_id
                .as_ref()
                .map_or("", crate::ReceiptId::as_str),
            &self.started_at.to_rfc3339(),
            &self.updated_at.to_rfc3339(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkHttpRequest {
    pub protocol_version: u16,
    pub request: CreatorWorkExecutionRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkHttpResponse {
    pub protocol_version: u16,
    pub request_digest: String,
    pub result: CreatorWorkProviderResult,
}

/// Loopback-only HTTP provider transport. This is a controlled provider
/// boundary for deterministic local execution; it is never a first-party
/// external-network credential adapter.
#[derive(Clone, Debug)]
pub struct CreatorWorkHttpProvider {
    provider_id: String,
    endpoint: SocketAddr,
    connect_timeout: StdDuration,
    io_timeout: StdDuration,
}

impl CreatorWorkHttpProvider {
    pub fn new(
        provider_id: impl Into<String>,
        endpoint: SocketAddr,
    ) -> Result<Self, CreatorWorkProviderError> {
        let provider_id = provider_id.into();
        if provider_id.trim().is_empty() {
            return Err(CreatorWorkProviderError::InvalidResponse(
                "provider id is empty".into(),
            ));
        }
        if !endpoint.ip().is_loopback() {
            return Err(CreatorWorkProviderError::Disconnected);
        }
        Ok(Self {
            provider_id,
            endpoint,
            connect_timeout: StdDuration::from_secs(2),
            io_timeout: StdDuration::from_secs(5),
        })
    }

    pub fn with_timeouts(
        mut self,
        connect_timeout: StdDuration,
        io_timeout: StdDuration,
    ) -> Result<Self, CreatorWorkProviderError> {
        if connect_timeout.is_zero() || io_timeout.is_zero() {
            return Err(CreatorWorkProviderError::InvalidResponse(
                "provider timeouts must be positive".into(),
            ));
        }
        self.connect_timeout = connect_timeout;
        self.io_timeout = io_timeout;
        Ok(self)
    }
}

impl CreatorWorkProvider for CreatorWorkHttpProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn execute_bounded(
        &self,
        request: &CreatorWorkExecutionRequest,
    ) -> Result<CreatorWorkProviderResult, CreatorWorkProviderError> {
        if request.provider_id != self.provider_id {
            return Err(CreatorWorkProviderError::InvalidResponse(
                "request provider does not match loopback provider".into(),
            ));
        }
        if request.protocol_version != CREATOR_WORK_PROVIDER_PROTOCOL_VERSION
            || !is_source_commit(&request.source_commit)
        {
            return Err(CreatorWorkProviderError::InvalidResponse(
                "request protocol or source commit is invalid".into(),
            ));
        }
        let envelope = CreatorWorkHttpRequest {
            protocol_version: CREATOR_WORK_PROVIDER_PROTOCOL_VERSION,
            request: request.clone(),
        };
        let body = serde_json::to_vec(&envelope)
            .map_err(|error| CreatorWorkProviderError::ExecutionFailed(error.to_string()))?;
        let mut stream = TcpStream::connect_timeout(&self.endpoint, self.connect_timeout)
            .map_err(|error| CreatorWorkProviderError::ExecutionFailed(error.to_string()))?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(|error| CreatorWorkProviderError::ExecutionFailed(error.to_string()))?;
        let host = self.endpoint.to_string();
        let headers = format!(
            "POST {CREATOR_WORK_HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
            .map_err(|error| CreatorWorkProviderError::ExecutionFailed(error.to_string()))?;
        let response_body = read_http_response_body(&mut stream, CREATOR_WORK_MAX_OUTPUT_BYTES)
            .map_err(CreatorWorkProviderError::InvalidResponse)?;
        let response: CreatorWorkHttpResponse = serde_json::from_slice(&response_body)
            .map_err(|error| CreatorWorkProviderError::InvalidResponse(error.to_string()))?;
        if response.protocol_version != CREATOR_WORK_PROVIDER_PROTOCOL_VERSION
            || response.request_digest != request.request_digest()
        {
            return Err(CreatorWorkProviderError::TamperedResponse);
        }
        Ok(response.result)
    }
}

fn read_http_response_body(stream: &mut TcpStream, max_body_bytes: u64) -> Result<Vec<u8>, String> {
    let max_wire_bytes = max_body_bytes
        .checked_add(16 * 1024)
        .ok_or_else(|| "response size limit overflowed".to_owned())?;
    let max_wire_bytes = usize::try_from(max_wire_bytes)
        .map_err(|_| "response size limit is not representable".to_owned())?;
    let mut wire = Vec::new();
    stream
        .take(
            u64::try_from(max_wire_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut wire)
        .map_err(|error| error.to_string())?;
    if wire.len() > max_wire_bytes {
        return Err("HTTP response exceeded the bounded wire limit".into());
    }
    let header_end = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "HTTP response headers are incomplete".to_owned())?;
    let header = std::str::from_utf8(&wire[..header_end])
        .map_err(|_| "HTTP response headers are not UTF-8".to_owned())?;
    let mut lines = header.lines();
    let status = lines
        .next()
        .ok_or_else(|| "HTTP response status is missing".to_owned())?;
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(format!("loopback provider returned {status}"));
    }
    let content_length = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(|| "HTTP response content length is missing".to_owned())?;
    if u64::try_from(content_length).unwrap_or(u64::MAX) > max_body_bytes {
        return Err("HTTP response body exceeded the bounded output limit".into());
    }
    let body_start = header_end + 4;
    let body = wire
        .get(body_start..)
        .ok_or_else(|| "HTTP response body is missing".to_owned())?;
    if body.len() != content_length {
        return Err("HTTP response content length does not match its body".into());
    }
    Ok(body.to_vec())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkOutcomeHandoff {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: crate::CreatorId,
    pub task_id: CreatorTaskId,
    pub contract_revision: u64,
    pub task_state_revision: u64,
    pub mission_revision: u64,
    pub result_id: String,
    pub deliverable_id: DeliverableId,
    pub deliverable_digest: String,
    pub result_digest: String,
    pub evidence_digest: String,
    pub receipt_id: crate::ReceiptId,
    pub verification_id: crate::VerificationId,
    pub payout_intent_digest: String,
    pub outcome_key: String,
    pub handoff_digest: String,
}

impl CreatorWorkOutcomeHandoff {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        creator_id: crate::CreatorId,
        task_id: CreatorTaskId,
        contract_revision: u64,
        task_state_revision: u64,
        mission_revision: u64,
        result_id: impl Into<String>,
        deliverable_id: DeliverableId,
        deliverable_digest: impl Into<String>,
        result_digest: impl Into<String>,
        evidence_digest: impl Into<String>,
        receipt_id: crate::ReceiptId,
        verification_id: crate::VerificationId,
        payout_intent_digest: impl Into<String>,
        outcome_key: impl Into<String>,
    ) -> Result<Self, CreatorWorkFulfillmentError> {
        let result_id = result_id.into();
        let deliverable_digest = deliverable_digest.into();
        let result_digest = result_digest.into();
        let evidence_digest = evidence_digest.into();
        let payout_intent_digest = payout_intent_digest.into();
        let outcome_key = outcome_key.into();
        if result_id.trim().is_empty()
            || deliverable_id.as_str().trim().is_empty()
            || !is_sha256(&deliverable_digest)
            || !is_sha256(&result_digest)
            || !is_sha256(&evidence_digest)
            || receipt_id.as_str().trim().is_empty()
            || verification_id.as_str().trim().is_empty()
            || !is_sha256(&payout_intent_digest)
            || outcome_key.trim().is_empty()
        {
            return Err(CreatorWorkFulfillmentError::InvalidOutcomeHandoff);
        }
        let handoff_digest = digest_fields([
            tenant_id.as_str(),
            project_id.as_str(),
            mission_id.as_str(),
            creator_id.as_str(),
            task_id.as_str(),
            &contract_revision.to_string(),
            &task_state_revision.to_string(),
            &mission_revision.to_string(),
            &result_id,
            deliverable_id.as_str(),
            &deliverable_digest,
            &result_digest,
            &evidence_digest,
            receipt_id.as_str(),
            verification_id.as_str(),
            &payout_intent_digest,
            &outcome_key,
        ]);
        Ok(Self {
            tenant_id,
            project_id,
            mission_id,
            creator_id,
            task_id,
            contract_revision,
            task_state_revision,
            mission_revision,
            result_id,
            deliverable_id,
            deliverable_digest,
            result_digest,
            evidence_digest,
            receipt_id,
            verification_id,
            payout_intent_digest,
            outcome_key,
            handoff_digest,
        })
    }

    fn expected_digest(&self) -> String {
        digest_fields([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            self.creator_id.as_str(),
            self.task_id.as_str(),
            &self.contract_revision.to_string(),
            &self.task_state_revision.to_string(),
            &self.mission_revision.to_string(),
            &self.result_id,
            self.deliverable_id.as_str(),
            &self.deliverable_digest,
            &self.result_digest,
            &self.evidence_digest,
            self.receipt_id.as_str(),
            self.verification_id.as_str(),
            &self.payout_intent_digest,
            &self.outcome_key,
        ])
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatorWorkFulfillmentStatus {
    OutcomeReady,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorWorkFulfillment {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub creator_id: crate::CreatorId,
    pub task_id: CreatorTaskId,
    pub contract_revision: u64,
    pub task_state_revision: u64,
    pub mission_revision: u64,
    pub provider_id: String,
    pub provider_generation: u64,
    pub connection_id: ConnectionId,
    pub account_id: AccountId,
    pub effect_id: EffectId,
    pub worker: CreatorWorkWorkerLease,
    pub result: CreatorWorkProviderResult,
    pub payout_intent: CreatorWorkPayoutIntent,
    pub outcome_handoff: CreatorWorkOutcomeHandoff,
    pub status: CreatorWorkFulfillmentStatus,
    pub recorded_at: DateTime<Utc>,
}

/// Mission consumer for provider facts. It is the only layer in this slice
/// that turns a plugin result into a CreatorWork outcome handoff.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreatorWorkMissionConsumer;

impl CreatorWorkMissionConsumer {
    #[allow(clippy::too_many_arguments)]
    pub fn consume_result(
        task: &CreatorTask,
        mission: &Mission,
        registry: &CreatorWorkProviderRegistry,
        request: &CreatorWorkExecutionRequest,
        current_worker: &CreatorWorkWorkerLease,
        result: &CreatorWorkProviderResult,
        now: DateTime<Utc>,
    ) -> Result<CreatorWorkFulfillment, CreatorWorkFulfillmentError> {
        validate_task_scope(task, mission, now)?;
        validate_request_scope(task, mission, registry, request, current_worker, now)?;
        validate_result_scope(task, mission, request, current_worker, result, now)?;
        let handoff = &result.outcome_handoff;
        if handoff.expected_digest() != handoff.handoff_digest {
            return Err(CreatorWorkFulfillmentError::InvalidOutcomeHandoff);
        }
        if handoff.result_digest != result.result_digest()
            || handoff.evidence_digest != result.evidence_digest
            || handoff.receipt_id != result.receipt.id
            || handoff.verification_id != result.verification.id
            || handoff.payout_intent_digest != result.payout_intent.intent_digest
        {
            return Err(CreatorWorkFulfillmentError::OutcomeBindingMismatch);
        }
        Ok(CreatorWorkFulfillment {
            tenant_id: task.tenant_id.clone(),
            project_id: task.project_id.clone(),
            mission_id: task.mission_id.clone(),
            creator_id: task.creator_id.clone(),
            task_id: task.id.clone(),
            contract_revision: task.contract_revision,
            task_state_revision: task.state_revision,
            mission_revision: mission.revision,
            provider_id: request.provider_id.clone(),
            provider_generation: registry
                .registration(&request.provider_id)
                .map_or(0, |registration| registration.generation),
            connection_id: request.connection_id.clone(),
            account_id: request.account_id.clone(),
            effect_id: request.effect_id.clone(),
            worker: current_worker.clone(),
            result: result.clone(),
            payout_intent: result.payout_intent.clone(),
            outcome_handoff: result.outcome_handoff.clone(),
            status: CreatorWorkFulfillmentStatus::OutcomeReady,
            recorded_at: now,
        })
    }
}

/// Small orchestration service that keeps plugin execution outside the
/// aggregate. Application code can persist the returned immutable record and
/// later hand its payout intent to the existing settlement boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreatorWorkFulfillmentService;

impl CreatorWorkFulfillmentService {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_request(
        &self,
        task: &CreatorTask,
        mission: &Mission,
        registry: &CreatorWorkProviderRegistry,
        provider_id: &str,
        worker: &CreatorWorkWorkerLease,
        effect: &Effect,
        input_digest: impl Into<String>,
        source_commit: impl Into<String>,
        max_output_bytes: u64,
        now: DateTime<Utc>,
    ) -> Result<CreatorWorkExecutionRequest, CreatorWorkFulfillmentError> {
        match registry.status(provider_id) {
            CreatorWorkProviderStatus::Disconnected => {
                return Err(CreatorWorkFulfillmentError::ProviderDisconnected(
                    provider_id.into(),
                ));
            }
            CreatorWorkProviderStatus::Revoked => {
                return Err(CreatorWorkFulfillmentError::ProviderRevoked(
                    provider_id.into(),
                ));
            }
            CreatorWorkProviderStatus::Registered => {}
        }
        let registration = registry
            .registration(provider_id)
            .ok_or_else(|| CreatorWorkFulfillmentError::ProviderDisconnected(provider_id.into()))?;
        validate_task_scope(task, mission, now)?;
        worker.validate_current(now)?;
        if worker.tenant_id != task.tenant_id
            || worker.project_id != task.project_id
            || worker.mission_id != task.mission_id
            || worker.creator_id != task.creator_id
            || worker.task_id != task.id
            || worker.contract_revision != task.contract_revision
            || worker.task_state_revision != task.state_revision
            || worker.mission_revision != mission.revision
            || worker.provider_generation != registration.generation
        {
            return Err(CreatorWorkFulfillmentError::WorkerBindingMismatch);
        }
        if max_output_bytes == 0 || max_output_bytes > CREATOR_WORK_MAX_OUTPUT_BYTES {
            return Err(CreatorWorkFulfillmentError::InvalidBoundedLimit);
        }
        let input_digest = input_digest.into();
        let source_commit = source_commit.into();
        let objective = mission.contract.goal.trim().to_owned();
        let capability = effect.capability.trim().to_owned();
        if !is_sha256(&input_digest)
            || !is_source_commit(&source_commit)
            || objective.is_empty()
            || capability.is_empty()
            || !mission.contract.enabled_capabilities.contains(&capability)
            || mission
                .contract
                .forbidden_capabilities
                .contains(&capability)
            || effect.id.as_str().trim().is_empty()
            || effect.tenant_id != task.tenant_id
            || effect.project_id != task.project_id
            || effect.mission_id != task.mission_id
            || effect.provider != provider_id
            || effect.connection_id.as_ref() != Some(&registration.connection_id)
            || effect.account_id.as_ref() != Some(&registration.account_id)
            || !matches!(
                &effect.status,
                EffectStatus::Approved
                    | EffectStatus::Executing
                    | EffectStatus::ReceiptRecorded
                    | EffectStatus::VerificationRequired
                    | EffectStatus::Verified
            )
            || effect.approval.is_none()
            || effect
                .approval
                .as_ref()
                .is_none_or(|approval| approval.scope_digest != effect.approval_digest())
            || !is_sha256(&effect.approval_digest())
        {
            return Err(CreatorWorkFulfillmentError::InvalidExecutionRequest);
        }
        Ok(CreatorWorkExecutionRequest {
            tenant_id: task.tenant_id.clone(),
            project_id: task.project_id.clone(),
            mission_id: task.mission_id.clone(),
            creator_id: task.creator_id.clone(),
            task_id: task.id.clone(),
            contract_revision: task.contract_revision,
            task_state_revision: task.state_revision,
            mission_revision: mission.revision,
            protocol_version: CREATOR_WORK_PROVIDER_PROTOCOL_VERSION,
            objective,
            capability,
            source_commit,
            provider_id: registration.provider_id.clone(),
            connection_id: registration.connection_id.clone(),
            account_id: registration.account_id.clone(),
            provider_generation: registration.generation,
            effect_id: effect.id.clone(),
            effect_approval_digest: effect.approval_digest(),
            input_digest,
            max_output_bytes,
            worker: worker.clone(),
            payout_intent: CreatorWorkPayoutIntent::for_task(task)?,
            requested_at: now,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_bounded<P: CreatorWorkProvider>(
        &self,
        task: &CreatorTask,
        mission: &Mission,
        registry: &CreatorWorkProviderRegistry,
        provider: &P,
        worker: &CreatorWorkWorkerLease,
        effect: &Effect,
        input_digest: impl Into<String>,
        source_commit: impl Into<String>,
        max_output_bytes: u64,
        now: DateTime<Utc>,
    ) -> Result<CreatorWorkProviderResult, CreatorWorkFulfillmentError> {
        let request = self.prepare_request(
            task,
            mission,
            registry,
            provider.provider_id(),
            worker,
            effect,
            input_digest,
            source_commit,
            max_output_bytes,
            now,
        )?;
        let result = provider
            .execute_bounded(&request)
            .map_err(CreatorWorkFulfillmentError::ProviderExecutionFailed)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CreatorWorkProviderError {
    #[error(
        "BLOCKED_ENV: external-network creator provider credentials are unavailable; provider is disconnected"
    )]
    Disconnected,
    #[error("provider is revoked")]
    Revoked,
    #[error("provider failed bounded execution: {0}")]
    ExecutionFailed(String),
    #[error("provider returned an invalid HTTP response: {0}")]
    InvalidResponse(String),
    #[error("provider returned a tampered response")]
    TamperedResponse,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CreatorWorkFulfillmentError {
    #[error("CreatorWork provider {0} is disconnected")]
    ProviderDisconnected(String),
    #[error("CreatorWork provider {0} is revoked")]
    ProviderRevoked(String),
    #[error("provider registration is invalid")]
    InvalidProviderRegistration,
    #[error("provider registration for {provider_id} is stale at generation {generation}")]
    StaleProviderRegistration {
        provider_id: String,
        generation: u64,
    },
    #[error("CreatorWork task is missing a valid funding reservation")]
    MissingFundingReservation,
    #[error("CreatorWork funding reservation is not exact for the task contract")]
    InvalidFundingReservation,
    #[error("CreatorWork worker lease is invalid")]
    InvalidWorkerLease,
    #[error("CreatorWork worker lease is still active")]
    WorkerStillActive,
    #[error("CreatorWork worker lease is already fenced")]
    WorkerAlreadyFenced,
    #[error("CreatorWork worker {worker_id} generation {generation} is fenced")]
    WorkerFenced {
        worker_id: WorkerId,
        generation: u64,
    },
    #[error("CreatorWork worker {worker_id} generation {generation} is expired")]
    WorkerExpired {
        worker_id: WorkerId,
        generation: u64,
    },
    #[error("CreatorWork worker lease does not exactly bind the task")]
    WorkerBindingMismatch,
    #[error("CreatorWork task does not have a creator acceptance at its current contract revision")]
    TaskNotAccepted,
    #[error("CreatorWork task is already paid and cannot accept another fulfillment")]
    TaskAlreadyPaid,
    #[error("CreatorWork tenant/project/Mission/creator/task binding is inconsistent")]
    TaskMissionBindingMismatch,
    #[error("CreatorWork task contract revision is stale")]
    ContractRevisionMismatch,
    #[error("CreatorWork task state revision is stale")]
    TaskRevisionMismatch,
    #[error("CreatorWork Mission revision is stale")]
    MissionRevisionMismatch,
    #[error("CreatorWork execution request is invalid")]
    InvalidExecutionRequest,
    #[error("CreatorWork bounded output limit is invalid")]
    InvalidBoundedLimit,
    #[error("CreatorWork provider result does not exactly bind the request")]
    ResultBindingMismatch,
    #[error("CreatorWork bounded output or evidence is invalid")]
    InvalidBoundedResult,
    #[error("CreatorWork Mission effect, Receipt, or Verification is not the exact verified proof")]
    MissionProofMismatch,
    #[error("CreatorWork outcome handoff is invalid")]
    InvalidOutcomeHandoff,
    #[error("CreatorWork outcome handoff does not exactly bind the result")]
    OutcomeBindingMismatch,
    #[error("CreatorWork provider execution failed: {0}")]
    ProviderExecutionFailed(CreatorWorkProviderError),
    #[error("CreatorWork execution receipt is invalid")]
    InvalidExecutionReceipt,
    #[error("CreatorWork execution receipt is already terminal")]
    ExecutionAlreadyTerminal,
    #[error("CreatorWork revision overflow")]
    RevisionOverflow,
}

fn validate_task_scope(
    task: &CreatorTask,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), CreatorWorkFulfillmentError> {
    if task.tenant_id != mission.tenant_id
        || task.project_id != mission.project_id
        || task.mission_id != mission.id
        || task.contract_revision == 0
        || task.state_revision == 0
    {
        return Err(CreatorWorkFulfillmentError::TaskMissionBindingMismatch);
    }
    if task.status == crate::CreatorTaskStatus::Paid {
        return Err(CreatorWorkFulfillmentError::TaskAlreadyPaid);
    }
    if !matches!(
        task.status,
        crate::CreatorTaskStatus::Accepted | crate::CreatorTaskStatus::InProgress
    ) {
        return Err(CreatorWorkFulfillmentError::TaskNotAccepted);
    }
    let Some(acceptance) = task.acceptance.as_ref() else {
        return Err(CreatorWorkFulfillmentError::TaskNotAccepted);
    };
    if task.accepted_revision != Some(task.contract_revision)
        || acceptance.creator_id != task.creator_id
        || acceptance.contract_revision != task.contract_revision
        || acceptance.contract_digest != task.contract_digest()
        || acceptance.accepted_at > now
    {
        return Err(CreatorWorkFulfillmentError::ContractRevisionMismatch);
    }
    if task
        .funding_reservation
        .as_ref()
        .is_none_or(|reservation| reservation.expires_at <= now)
    {
        return Err(CreatorWorkFulfillmentError::InvalidFundingReservation);
    }
    Ok(())
}

fn validate_request_scope(
    task: &CreatorTask,
    mission: &Mission,
    registry: &CreatorWorkProviderRegistry,
    request: &CreatorWorkExecutionRequest,
    current_worker: &CreatorWorkWorkerLease,
    now: DateTime<Utc>,
) -> Result<(), CreatorWorkFulfillmentError> {
    if request.tenant_id != task.tenant_id
        || request.project_id != task.project_id
        || request.mission_id != task.mission_id
        || request.creator_id != task.creator_id
        || request.task_id != task.id
    {
        return Err(CreatorWorkFulfillmentError::ResultBindingMismatch);
    }
    if request.contract_revision != task.contract_revision {
        return Err(CreatorWorkFulfillmentError::ContractRevisionMismatch);
    }
    if request.task_state_revision != task.state_revision {
        return Err(CreatorWorkFulfillmentError::TaskRevisionMismatch);
    }
    if request.mission_revision != mission.revision {
        return Err(CreatorWorkFulfillmentError::MissionRevisionMismatch);
    }
    if request.protocol_version != CREATOR_WORK_PROVIDER_PROTOCOL_VERSION
        || request.objective != mission.contract.goal
        || request.capability.trim().is_empty()
        || !mission
            .contract
            .enabled_capabilities
            .contains(&request.capability)
        || mission
            .contract
            .forbidden_capabilities
            .contains(&request.capability)
        || !is_source_commit(&request.source_commit)
    {
        return Err(CreatorWorkFulfillmentError::InvalidExecutionRequest);
    }
    if registry.status(&request.provider_id) != CreatorWorkProviderStatus::Registered {
        return match registry.status(&request.provider_id) {
            CreatorWorkProviderStatus::Disconnected => Err(
                CreatorWorkFulfillmentError::ProviderDisconnected(request.provider_id.clone()),
            ),
            CreatorWorkProviderStatus::Revoked => Err(
                CreatorWorkFulfillmentError::ProviderRevoked(request.provider_id.clone()),
            ),
            CreatorWorkProviderStatus::Registered => unreachable!("status checked above"),
        };
    }
    current_worker.validate_current(now)?;
    let registration = registry.registration(&request.provider_id).ok_or_else(|| {
        CreatorWorkFulfillmentError::ProviderDisconnected(request.provider_id.clone())
    })?;
    if request.worker != *current_worker
        || request.worker.contract_revision != task.contract_revision
        || request.worker.task_state_revision != task.state_revision
        || request.worker.mission_revision != mission.revision
        || request.worker.provider_generation != request.provider_generation
        || registration.generation != request.provider_generation
        || request.connection_id != registration.connection_id
        || request.account_id != registration.account_id
    {
        return Err(CreatorWorkFulfillmentError::WorkerBindingMismatch);
    }
    if request.payout_intent.tenant_id != task.tenant_id
        || request.payout_intent.project_id != task.project_id
        || request.payout_intent.mission_id != task.mission_id
        || request.payout_intent.creator_id != task.creator_id
        || request.payout_intent.task_id != task.id
        || request.payout_intent.contract_revision != task.contract_revision
        || request.payout_intent.contract_digest != task.contract_digest()
        || request.payout_intent.amount != task.bounty
        || request.payout_intent.status != CreatorWorkSettlementStatus::Pending
        || !request.payout_intent.exactly_matches_task(task)
    {
        return Err(CreatorWorkFulfillmentError::ResultBindingMismatch);
    }
    if !is_sha256(&request.input_digest)
        || !is_sha256(&request.effect_approval_digest)
        || request.max_output_bytes == 0
    {
        return Err(CreatorWorkFulfillmentError::InvalidExecutionRequest);
    }
    Ok(())
}

fn validate_result_scope(
    task: &CreatorTask,
    mission: &Mission,
    request: &CreatorWorkExecutionRequest,
    current_worker: &CreatorWorkWorkerLease,
    result: &CreatorWorkProviderResult,
    now: DateTime<Utc>,
) -> Result<(), CreatorWorkFulfillmentError> {
    if result.tenant_id != request.tenant_id
        || result.project_id != request.project_id
        || result.mission_id != request.mission_id
        || result.creator_id != request.creator_id
        || result.task_id != request.task_id
        || result.contract_revision != request.contract_revision
        || result.task_state_revision != request.task_state_revision
        || result.mission_revision != request.mission_revision
        || result.provider_id != request.provider_id
        || result.provider_generation != request.provider_generation
        || result.effect_id != request.effect_id
        || result.worker_id != current_worker.worker_id
        || result.worker_generation != current_worker.generation
        || result.protocol_version != request.protocol_version
        || result.objective != request.objective
        || result.capability != request.capability
        || result.source_commit != request.source_commit
        || result.input_digest != request.input_digest
        || result.request_digest != request.request_digest()
    {
        return Err(CreatorWorkFulfillmentError::ResultBindingMismatch);
    }
    if result.result_id.trim().is_empty()
        || result.deliverable.deliverable_id.as_str().trim().is_empty()
        || result.deliverable.artifact_uri.trim().is_empty()
        || result.deliverable.media_type.trim().is_empty()
        || result.deliverable.size_bytes == 0
        || result.deliverable.size_bytes > request.max_output_bytes
        || !is_sha256(&result.deliverable.content_digest)
        || !is_sha256(&result.request_digest)
        || result.output_size_bytes == 0
        || result.output_size_bytes > request.max_output_bytes
        || !is_sha256(&result.bounded_output_digest)
        || !is_sha256(&result.evidence_digest)
        || result.receipt.provider != request.provider_id
        || result.receipt.external_id.trim().is_empty()
        || !is_sha256(&result.receipt.request_digest)
        || !is_sha256(&result.receipt.response_digest)
        || result.receipt.request_digest != request.effect_approval_digest
        || result.receipt.accepted_at < request.requested_at
        || result.receipt.accepted_at > now
        || result.verification.status != VerificationStatus::Confirmed
        || result.verification.verifier.trim().is_empty()
        || !result.verification.independent
        || !is_sha256(&result.verification.evidence_digest)
        || result.verification.evidence_digest != result.evidence_digest
        || result.verification.receipt_id != result.receipt.id
        || result.verification.observed_at < result.receipt.accepted_at
        || result.verification.observed_at > now
    {
        return Err(CreatorWorkFulfillmentError::InvalidBoundedResult);
    }
    if result.payout_intent != request.payout_intent {
        return Err(CreatorWorkFulfillmentError::ResultBindingMismatch);
    }
    let Some(effect) = mission
        .effects
        .iter()
        .find(|effect| effect.id == result.effect_id)
    else {
        return Err(CreatorWorkFulfillmentError::MissionProofMismatch);
    };
    if effect.tenant_id != mission.tenant_id
        || effect.project_id != mission.project_id
        || effect.mission_id != mission.id
        || effect.provider != result.provider_id
        || effect.connection_id.as_ref() != Some(&request.connection_id)
        || effect.account_id.as_ref() != Some(&request.account_id)
        || effect.status != EffectStatus::Verified
        || effect.approval_digest() != request.effect_approval_digest
        || effect
            .approval
            .as_ref()
            .is_none_or(|approval| approval.scope_digest != request.effect_approval_digest)
        || effect.receipt.as_ref() != Some(&result.receipt)
        || effect.verification.as_ref() != Some(&result.verification)
    {
        return Err(CreatorWorkFulfillmentError::MissionProofMismatch);
    }
    if result.outcome_handoff.tenant_id != task.tenant_id
        || result.outcome_handoff.project_id != task.project_id
        || result.outcome_handoff.mission_id != task.mission_id
        || result.outcome_handoff.creator_id != task.creator_id
        || result.outcome_handoff.task_id != task.id
        || result.outcome_handoff.contract_revision != task.contract_revision
        || result.outcome_handoff.task_state_revision != task.state_revision
        || result.outcome_handoff.mission_revision != mission.revision
        || result.outcome_handoff.deliverable_id != result.deliverable.deliverable_id
        || result.outcome_handoff.deliverable_digest != result.deliverable.content_digest
    {
        return Err(CreatorWorkFulfillmentError::OutcomeBindingMismatch);
    }
    Ok(())
}

fn verification_status_name(status: &VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Confirmed => "confirmed",
        VerificationStatus::Rejected => "rejected",
        VerificationStatus::Inconclusive => "inconclusive",
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_source_commit(value: &str) -> bool {
    value.len() == CREATOR_WORK_SOURCE_COMMIT_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn execution_status_name(status: &CreatorWorkExecutionStatus) -> &'static str {
    match status {
        CreatorWorkExecutionStatus::Started => "started",
        CreatorWorkExecutionStatus::ResultRecorded => "result_recorded",
        CreatorWorkExecutionStatus::Revoked => "revoked",
    }
}

fn digest_fields<'a>(fields: impl IntoIterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    for field in fields {
        let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
        digest.update(length.to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::{
        ActorId, Approval, ConsentState, CreatorHiringAward, CreatorMilestone,
        CreatorMilestoneStatus, CreatorTaskStatus, CurrencyCode, Effect, EffectClass, EffectRisk,
        MissionContract, UsageRights,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 10, 0, 0)
            .single()
            .expect("static time")
    }

    #[allow(clippy::too_many_lines)]
    fn task_and_mission() -> (CreatorTask, Mission) {
        let now = now();
        let tenant_id = TenantId::from("tenant-creator-fulfillment");
        let project_id = ProjectId::from("project-creator-fulfillment");
        let mission_id = MissionId::from("mission-creator-fulfillment");
        let creator_id = crate::CreatorId::from("creator-1");
        let bounty = Money::new(10_000, CurrencyCode::parse("USD").expect("currency"));
        let mut task = CreatorTask {
            id: CreatorTaskId::from("task-creator-fulfillment"),
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            creator_id: creator_id.clone(),
            hiring_award: CreatorHiringAward {
                hiring_id: crate::CreatorHiringId::from("hiring-1"),
                tenant_id: tenant_id.clone(),
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                creator_id: creator_id.clone(),
                partner_id: crate::PartnerId::from("partner-1"),
                application_id: crate::CreatorApplicationId::from("application-1"),
                offer_digest: "a".repeat(64),
                bounty: bounty.clone(),
                selected_by: ActorId::from("actor-1"),
                selection_evidence_digest: "b".repeat(64),
                selected_at: now - Duration::hours(1),
            },
            title: "Creator result".into(),
            brief: "Produce the bounded result".into(),
            acceptance_criteria: vec!["digest matches brief".into()],
            deliverable_requirements: vec!["one artifact reference".into()],
            bounty: bounty.clone(),
            milestones: vec![CreatorMilestone {
                id: crate::CreatorMilestoneId::from("milestone-1"),
                title: "Result".into(),
                amount: bounty.clone(),
                due_at: now + Duration::days(2),
                status: CreatorMilestoneStatus::InProgress,
                revisions_used: 0,
            }],
            revision_limit: 2,
            usage_rights: UsageRights {
                license: "commissioned".into(),
                territories: vec!["global".into()],
                channels: vec!["owned".into()],
                exclusivity: "non_exclusive".into(),
                disclosure_required: false,
                source_manifest_required: true,
            },
            due_at: now + Duration::days(2),
            contract_revision: 1,
            state_revision: 2,
            accepted_revision: Some(1),
            status: CreatorTaskStatus::InProgress,
            funding_reservation: None,
            acceptance: Some(crate::CreatorAcceptance {
                creator_id: creator_id.clone(),
                connected_account_id: AccountId::from("account-1"),
                connection_id: ConnectionId::from("connection-1"),
                contract_revision: 1,
                contract_digest: String::new(),
                accepted_at: now - Duration::minutes(20),
            }),
            deliverables: Vec::new(),
            reviews: Vec::new(),
            payout_authorizations: Vec::new(),
            payouts: Vec::new(),
            created_at: now - Duration::hours(2),
            updated_at: now,
        };
        let contract_digest = task.contract_digest();
        task.acceptance
            .as_mut()
            .expect("acceptance")
            .contract_digest = contract_digest.clone();
        task.funding_reservation = Some(crate::FundingReservation {
            provider: "hartevo".into(),
            external_id: "reservation-1".into(),
            connection_id: ConnectionId::from("connection-1"),
            payer_account_id: AccountId::from("payer-1"),
            amount: bounty,
            contract_revision: 1,
            contract_digest,
            reserved_at: now - Duration::hours(1),
            expires_at: now + Duration::days(5),
            request_digest: "c".repeat(64),
            provider_receipt_digest: "d".repeat(64),
            verification_evidence_digest: "e".repeat(64),
        });

        let mission = Mission::compile(
            tenant_id,
            mission_id,
            project_id,
            "Creator Mission",
            MissionContract::bootstrap(
                "creator result",
                ["creator.work.fulfillment".to_owned()],
                now - Duration::days(1),
            ),
            now - Duration::days(1),
        )
        .expect("mission");
        (task, mission)
    }

    fn active_worker(task: &CreatorTask, mission: &Mission) -> CreatorWorkWorkerLease {
        CreatorWorkWorkerLease::acquire(
            task.tenant_id.clone(),
            task.project_id.clone(),
            task.mission_id.clone(),
            task.creator_id.clone(),
            task.id.clone(),
            task.contract_revision,
            task.state_revision,
            mission.revision,
            1,
            WorkerId::from("worker-1"),
            1,
            "f".repeat(64),
            now(),
            now() + Duration::minutes(10),
        )
        .expect("worker")
    }

    fn registered_registry() -> CreatorWorkProviderRegistry {
        let mut registry = CreatorWorkProviderRegistry::default();
        registry
            .register(
                CreatorWorkProviderRegistration::new(
                    "hartevo",
                    ConnectionId::from("connection-1"),
                    AccountId::from("account-1"),
                    now(),
                )
                .expect("registration"),
            )
            .expect("register");
        registry
    }

    fn test_effect() -> Effect {
        let mut effect = Effect {
            id: EffectId::from("effect-creator-work"),
            tenant_id: TenantId::from("tenant-creator-fulfillment"),
            project_id: ProjectId::from("project-creator-fulfillment"),
            mission_id: MissionId::from("mission-creator-fulfillment"),
            actor_id: ActorId::from("actor-1"),
            capability: "creator.work.fulfillment".into(),
            provider: "hartevo".into(),
            connection_id: Some(ConnectionId::from("connection-1")),
            account_id: Some(AccountId::from("account-1")),
            required_scopes: BTreeSet::new(),
            effect_class: EffectClass::ExternalWrite,
            description: "bounded creator work".into(),
            target_resource: "creator-work://result".into(),
            audience_digest: None,
            payload_digest: "5".repeat(64),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "creator-work-test-v1".into(),
            risk: EffectRisk::Low,
            idempotency_key: "creator-work-effect-1".into(),
            amount: Money::zero(CurrencyCode::parse("USD").expect("currency")),
            expires_at: now() + Duration::hours(1),
            status: EffectStatus::Executing,
            approval: Some(Approval {
                id: crate::ApprovalId::from("approval-1"),
                decision: crate::ApprovalDecision::Approved,
                decided_by: ActorId::from("actor-1"),
                decided_at: now(),
                valid_until: now() + Duration::hours(1),
                scope_digest: "0".repeat(64),
                permission_digest: "7".repeat(64),
            }),
            receipt: None,
            verification: None,
        };
        let approval_digest = effect.approval_digest();
        effect.approval.as_mut().expect("approval").scope_digest = approval_digest;
        effect
    }

    fn request(
        task: &CreatorTask,
        mission: &mut Mission,
        registry: &CreatorWorkProviderRegistry,
        worker: &CreatorWorkWorkerLease,
    ) -> CreatorWorkExecutionRequest {
        let effect = test_effect();
        mission.effects.push(effect.clone());
        CreatorWorkFulfillmentService
            .prepare_request(
                task,
                mission,
                registry,
                "hartevo",
                worker,
                &effect,
                "1".repeat(64),
                "0123456789abcdef0123456789abcdef01234567",
                1024,
                now(),
            )
            .expect("request")
    }

    fn result(request: &CreatorWorkExecutionRequest) -> CreatorWorkProviderResult {
        let receipt = Receipt {
            id: crate::ReceiptId::from("receipt-creator-work"),
            provider: request.provider_id.clone(),
            external_id: "provider-result-1".into(),
            accepted_at: request.requested_at,
            request_digest: request.effect_approval_digest.clone(),
            response_digest: "2".repeat(64),
        };
        let verification = Verification {
            id: crate::VerificationId::from("verification-creator-work"),
            status: VerificationStatus::Confirmed,
            verifier: "independent-checker".into(),
            independent: true,
            observed_at: receipt.accepted_at,
            evidence_digest: "3".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        let mut result = CreatorWorkProviderResult {
            tenant_id: request.tenant_id.clone(),
            project_id: request.project_id.clone(),
            mission_id: request.mission_id.clone(),
            creator_id: request.creator_id.clone(),
            task_id: request.task_id.clone(),
            contract_revision: request.contract_revision,
            task_state_revision: request.task_state_revision,
            mission_revision: request.mission_revision,
            protocol_version: request.protocol_version,
            objective: request.objective.clone(),
            capability: request.capability.clone(),
            source_commit: request.source_commit.clone(),
            input_digest: request.input_digest.clone(),
            request_digest: request.request_digest(),
            provider_id: request.provider_id.clone(),
            provider_generation: request.provider_generation,
            effect_id: request.effect_id.clone(),
            worker_id: request.worker.worker_id.clone(),
            worker_generation: request.worker.generation,
            result_id: "result-creator-work".into(),
            deliverable: CreatorWorkDeliverableReference {
                deliverable_id: crate::DeliverableId::from("deliverable-creator-work"),
                artifact_uri: "file-broker://creator-work/result-1".into(),
                media_type: "application/json".into(),
                size_bytes: 128,
                content_digest: "9".repeat(64),
            },
            bounded_output_digest: "4".repeat(64),
            output_size_bytes: 128,
            evidence_digest: verification.evidence_digest.clone(),
            receipt,
            verification,
            payout_intent: request.payout_intent.clone(),
            outcome_handoff: CreatorWorkOutcomeHandoff {
                tenant_id: request.tenant_id.clone(),
                project_id: request.project_id.clone(),
                mission_id: request.mission_id.clone(),
                creator_id: request.creator_id.clone(),
                task_id: request.task_id.clone(),
                contract_revision: request.contract_revision,
                task_state_revision: request.task_state_revision,
                mission_revision: request.mission_revision,
                result_id: "result-creator-work".into(),
                deliverable_id: crate::DeliverableId::from("deliverable-creator-work"),
                deliverable_digest: "9".repeat(64),
                result_digest: "0".repeat(64),
                evidence_digest: "3".repeat(64),
                receipt_id: crate::ReceiptId::from("receipt-creator-work"),
                verification_id: crate::VerificationId::from("verification-creator-work"),
                payout_intent_digest: request.payout_intent.intent_digest.clone(),
                outcome_key: "creator_work.result_ready".into(),
                handoff_digest: "0".repeat(64),
            },
        };
        let result_digest = result.result_digest();
        result.outcome_handoff = CreatorWorkOutcomeHandoff::new(
            result.tenant_id.clone(),
            result.project_id.clone(),
            result.mission_id.clone(),
            result.creator_id.clone(),
            result.task_id.clone(),
            result.contract_revision,
            result.task_state_revision,
            result.mission_revision,
            result.result_id.clone(),
            result.deliverable.deliverable_id.clone(),
            result.deliverable.content_digest.clone(),
            result_digest,
            result.evidence_digest.clone(),
            result.receipt.id.clone(),
            result.verification.id.clone(),
            result.payout_intent.intent_digest.clone(),
            "creator_work.result_ready",
        )
        .expect("handoff");
        result
    }

    fn attach_effect(
        mission: &mut Mission,
        request: &CreatorWorkExecutionRequest,
        result: &CreatorWorkProviderResult,
    ) {
        let effect = mission
            .effects
            .iter_mut()
            .find(|effect| effect.id == request.effect_id)
            .expect("effect");
        effect.status = EffectStatus::Verified;
        effect.receipt = Some(result.receipt.clone());
        effect.verification = Some(result.verification.clone());
    }

    #[derive(Clone, Debug)]
    struct StaticProvider {
        result: CreatorWorkProviderResult,
    }

    impl CreatorWorkProvider for StaticProvider {
        fn provider_id(&self) -> &'static str {
            "hartevo"
        }

        fn execute_bounded(
            &self,
            _request: &CreatorWorkExecutionRequest,
        ) -> Result<CreatorWorkProviderResult, CreatorWorkProviderError> {
            Ok(self.result.clone())
        }
    }

    #[test]
    fn absent_provider_is_disconnected() {
        let (task, mission) = task_and_mission();
        let worker = active_worker(&task, &mission);
        let effect = test_effect();
        let error = CreatorWorkFulfillmentService
            .prepare_request(
                &task,
                &mission,
                &CreatorWorkProviderRegistry::default(),
                "hartevo",
                &worker,
                &effect,
                "1".repeat(64),
                "0123456789abcdef0123456789abcdef01234567",
                1024,
                now(),
            )
            .expect_err("unregistered provider must be disconnected");
        assert_eq!(
            error,
            CreatorWorkFulfillmentError::ProviderDisconnected("hartevo".into())
        );
    }

    #[test]
    fn verified_result_creates_pending_payout_intent_not_paid_task() {
        let (task, mut mission) = task_and_mission();
        let registry = registered_registry();
        let worker = active_worker(&task, &mission);
        let request = request(&task, &mut mission, &registry, &worker);
        let provider_result = result(&request);
        attach_effect(&mut mission, &request, &provider_result);
        let fulfillment = CreatorWorkMissionConsumer::consume_result(
            &task,
            &mission,
            &registry,
            &request,
            &worker,
            &provider_result,
            now() + Duration::seconds(2),
        )
        .expect("verified result");
        assert_eq!(
            fulfillment.status,
            CreatorWorkFulfillmentStatus::OutcomeReady
        );
        assert_eq!(
            fulfillment.payout_intent.status,
            CreatorWorkSettlementStatus::Pending
        );
        assert_ne!(task.status, crate::CreatorTaskStatus::Paid);
    }

    #[test]
    fn provider_service_executes_only_registered_plugin() {
        let (task, mut mission) = task_and_mission();
        let registry = registered_registry();
        let worker = active_worker(&task, &mission);
        let request = request(&task, &mut mission, &registry, &worker);
        let provider_result = result(&request);
        attach_effect(&mut mission, &request, &provider_result);
        let provider = StaticProvider {
            result: provider_result,
        };
        let effect = mission
            .effects
            .iter()
            .find(|effect| effect.id == request.effect_id)
            .expect("effect");
        let provider_result = CreatorWorkFulfillmentService
            .execute_bounded(
                &task,
                &mission,
                &registry,
                &provider,
                &worker,
                effect,
                request.input_digest.clone(),
                request.source_commit.clone(),
                request.max_output_bytes,
                now(),
            )
            .expect("provider execution");
        let fulfillment = CreatorWorkMissionConsumer::consume_result(
            &task,
            &mission,
            &registry,
            &request,
            &worker,
            &provider_result,
            now(),
        )
        .expect("Mission handoff");
        assert_eq!(fulfillment.provider_id, "hartevo");
        assert_eq!(fulfillment.result.result_id, "result-creator-work");
    }

    #[test]
    fn old_worker_cannot_submit_after_crash_and_recovery() {
        let (task, mut mission) = task_and_mission();
        let registry = registered_registry();
        let mut old_worker = active_worker(&task, &mission);
        let request = request(&task, &mut mission, &registry, &old_worker);
        let provider_result = result(&request);
        attach_effect(&mut mission, &request, &provider_result);
        old_worker.mark_crashed(now()).expect("crash");
        let new_worker = old_worker
            .recover(
                WorkerId::from("worker-2"),
                "8".repeat(64),
                task.state_revision,
                mission.revision,
                1,
                now() + Duration::seconds(1),
                now() + Duration::minutes(10),
            )
            .expect("recover");
        let error = CreatorWorkMissionConsumer::consume_result(
            &task,
            &mission,
            &registry,
            &request,
            &new_worker,
            &provider_result,
            now() + Duration::seconds(2),
        )
        .expect_err("old worker result must be fenced");
        assert_eq!(error, CreatorWorkFulfillmentError::WorkerBindingMismatch);
    }

    #[test]
    fn revoked_provider_cannot_start_new_work() {
        let (task, mission) = task_and_mission();
        let mut registry = registered_registry();
        registry.revoke("hartevo", now()).expect("revoke");
        let worker = active_worker(&task, &mission);
        let effect = test_effect();
        let error = CreatorWorkFulfillmentService
            .prepare_request(
                &task,
                &mission,
                &registry,
                "hartevo",
                &worker,
                &effect,
                "1".repeat(64),
                "0123456789abcdef0123456789abcdef01234567",
                1024,
                now(),
            )
            .expect_err("revoked provider must not execute");
        assert_eq!(
            error,
            CreatorWorkFulfillmentError::ProviderRevoked("hartevo".into())
        );
    }

    #[test]
    fn old_worker_cannot_submit_after_provider_reconnect() {
        let (task, mut mission) = task_and_mission();
        let mut registry = registered_registry();
        let worker = active_worker(&task, &mission);
        let request = request(&task, &mut mission, &registry, &worker);
        let provider_result = result(&request);
        attach_effect(&mut mission, &request, &provider_result);
        registry.revoke("hartevo", now()).expect("revoke");
        let reconnected = registry
            .registration("hartevo")
            .expect("registration")
            .reconnect(now() + Duration::seconds(1))
            .expect("reconnect");
        registry.register(reconnected).expect("register reconnect");
        let error = CreatorWorkMissionConsumer::consume_result(
            &task,
            &mission,
            &registry,
            &request,
            &worker,
            &provider_result,
            now() + Duration::seconds(2),
        )
        .expect_err("old provider generation must be fenced");
        assert_eq!(error, CreatorWorkFulfillmentError::WorkerBindingMismatch);
    }

    fn loopback_server(
        tamper_source_commit: bool,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::net::TcpListener;
        use std::sync::atomic::Ordering;

        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let endpoint = listener.local_addr().expect("loopback address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("provider request");
            calls.fetch_add(1, Ordering::SeqCst);
            let mut wire = Vec::new();
            stream.read_to_end(&mut wire).expect("request wire");
            let header_end = wire
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("request headers");
            let body = &wire[header_end + 4..];
            let request: CreatorWorkHttpRequest = serde_json::from_slice(body).expect("request");
            let mut result = result(&request.request);
            if tamper_source_commit {
                result.source_commit = "f".repeat(CREATOR_WORK_SOURCE_COMMIT_HEX_LEN);
            }
            let response = CreatorWorkHttpResponse {
                protocol_version: CREATOR_WORK_PROVIDER_PROTOCOL_VERSION,
                request_digest: request.request.request_digest(),
                result,
            };
            let body = serde_json::to_vec(&response).expect("response");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .expect("response headers");
            stream.write_all(&body).expect("response body");
        });
        (endpoint, handle)
    }

    #[test]
    fn loopback_http_provider_composes_objective_capability_and_exact_request_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (task, mut mission) = task_and_mission();
        let registry = registered_registry();
        let worker = active_worker(&task, &mission);
        let request = request(&task, &mut mission, &registry, &worker);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let (endpoint, server) = loopback_server(false, calls.clone());
        let provider = CreatorWorkHttpProvider::new("hartevo", endpoint).expect("provider");
        let effect = mission
            .effects
            .iter()
            .find(|effect| effect.id == request.effect_id)
            .expect("effect");
        let provider_result = CreatorWorkFulfillmentService
            .execute_bounded(
                &task,
                &mission,
                &registry,
                &provider,
                &worker,
                effect,
                request.input_digest.clone(),
                request.source_commit.clone(),
                request.max_output_bytes,
                now(),
            )
            .expect("loopback result");
        attach_effect(&mut mission, &request, &provider_result);
        let fulfillment = CreatorWorkMissionConsumer::consume_result(
            &task,
            &mission,
            &registry,
            &request,
            &worker,
            &provider_result,
            now(),
        )
        .expect("Mission consumer");
        server.join().expect("server");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(request.objective, mission.contract.goal);
        assert_eq!(request.capability, "creator.work.fulfillment");
        assert_eq!(provider_result.request_digest, request.request_digest());
        assert_eq!(fulfillment.result.source_commit, request.source_commit);
    }

    #[test]
    fn loopback_http_provider_rejects_tampered_result_and_external_network() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (task, mut mission) = task_and_mission();
        let registry = registered_registry();
        let worker = active_worker(&task, &mission);
        let request = request(&task, &mut mission, &registry, &worker);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let (endpoint, server) = loopback_server(true, calls.clone());
        let provider = CreatorWorkHttpProvider::new("hartevo", endpoint).expect("provider");
        let effect = mission
            .effects
            .iter()
            .find(|effect| effect.id == request.effect_id)
            .expect("effect");
        let tampered = CreatorWorkFulfillmentService
            .execute_bounded(
                &task,
                &mission,
                &registry,
                &provider,
                &worker,
                effect,
                request.input_digest.clone(),
                request.source_commit.clone(),
                request.max_output_bytes,
                now(),
            )
            .expect("transport remains typed");
        server.join().expect("server");
        let error = CreatorWorkMissionConsumer::consume_result(
            &task,
            &mission,
            &registry,
            &request,
            &worker,
            &tampered,
            now(),
        )
        .expect_err("tampered source commit must be rejected");
        assert_eq!(error, CreatorWorkFulfillmentError::ResultBindingMismatch);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let external = "192.0.2.1:80".parse().expect("socket address");
        assert_eq!(
            CreatorWorkHttpProvider::new("hartevo", external).expect_err("external blocked"),
            CreatorWorkProviderError::Disconnected
        );
    }
}

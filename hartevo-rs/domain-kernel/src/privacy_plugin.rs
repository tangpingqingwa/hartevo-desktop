use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ActorId, ConsentRecordId, DeletionId, DeletionPropagationReceipt, DeletionPropagationStatus,
    DeletionReason, DeletionReceiptId, DeletionRequestStatus, DeletionSurface, DeletionTombstone,
    MissionId, ProjectId, RetentionAction, RetentionDecision, TenantId, WorkerId,
};

/// The explicit lifecycle of an on-demand privacy plugin scope.
///
/// Unmounting is a durable fence, not a deletion of the work queue. A later
/// mount must use a successor generation before it can claim or acknowledge a
/// propagation job.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyPluginScopeStatus {
    Active,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyPluginScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub scope_id: String,
    pub scope_generation: u64,
    pub policy_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub scope_digest: String,
}

impl PrivacyPluginScope {
    #[allow(
        clippy::too_many_arguments,
        reason = "scope creation binds every durable authority field"
    )]
    pub fn issue(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        scope_id: impl Into<String>,
        policy_digest: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, PrivacyPluginError> {
        let mut scope = Self {
            tenant_id,
            project_id,
            mission_id,
            scope_id: scope_id.into(),
            scope_generation: 1,
            policy_digest: policy_digest.into(),
            issued_at,
            expires_at,
            scope_digest: String::new(),
        };
        scope.scope_digest = scope.compute_digest()?;
        scope.validate(issued_at)?;
        Ok(scope)
    }

    /// Issue the next generation after an explicit unmount or revoke.
    pub fn reissue(
        &self,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, PrivacyPluginError> {
        let mut next = self.clone();
        next.scope_generation = self
            .scope_generation
            .checked_add(1)
            .ok_or_else(|| PrivacyPluginError::InvalidScope("scope generation overflow".into()))?;
        next.issued_at = issued_at;
        next.expires_at = expires_at;
        next.scope_digest = String::new();
        next.scope_digest = next.compute_digest()?;
        next.validate(issued_at)?;
        Ok(next)
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), PrivacyPluginError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.scope_id.trim().is_empty()
            || self.scope_generation == 0
            || !is_sha256(&self.policy_digest)
            || self.expires_at <= self.issued_at
            || self.expires_at <= now
            || self.scope_digest != self.compute_digest()?
        {
            return Err(PrivacyPluginError::InvalidScope(
                "scope is incomplete, expired, or tampered".into(),
            ));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, PrivacyPluginError> {
        let bytes = serde_json::to_vec(&(
            &self.tenant_id,
            &self.project_id,
            &self.mission_id,
            &self.scope_id,
            self.scope_generation,
            &self.policy_digest,
            self.issued_at,
            self.expires_at,
        ))
        .map_err(|_| PrivacyPluginError::Serialization)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyConsentPurpose {
    MissionDeletion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyDeletionConsent {
    pub id: ConsentRecordId,
    pub purpose: PrivacyConsentPurpose,
    pub actor_id: ActorId,
    pub evidence_digest: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PrivacyDeletionConsent {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), PrivacyPluginError> {
        if self.id.as_str().trim().is_empty()
            || !matches!(self.purpose, PrivacyConsentPurpose::MissionDeletion)
            || self.actor_id.as_str().trim().is_empty()
            || !is_sha256(&self.evidence_digest)
            || self.expires_at <= self.granted_at
            || self.expires_at <= now
        {
            return Err(PrivacyPluginError::InvalidConsent);
        }
        Ok(())
    }
}

/// A host-issued local capability. It contains no Project key, keyring, or
/// secret reference; the storage adapter only receives the public cell and key
/// version needed to build the existing typed local sync operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyLocalDeletionPlan {
    pub cell: String,
    pub key_version: u64,
}

impl PrivacyLocalDeletionPlan {
    fn validate(&self) -> Result<(), PrivacyPluginError> {
        if !matches!(self.cell.as_str(), "us" | "eu") || self.key_version == 0 {
            return Err(PrivacyPluginError::InvalidRequest(
                "local deletion plan is not an approved cell/key-version capability".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyDeletionRequest {
    pub id: DeletionId,
    pub mission_id: MissionId,
    pub object_id: String,
    pub object_kind: String,
    pub prior_object_revision: u64,
    pub deletion_generation: u64,
    pub reason: DeletionReason,
    pub consent: PrivacyDeletionConsent,
    pub retention: RetentionDecision,
    pub idempotency_key_digest: String,
    pub local_plan: PrivacyLocalDeletionPlan,
    pub requested_at: DateTime<Utc>,
}

impl PrivacyDeletionRequest {
    pub fn validate_for(
        &self,
        scope: &PrivacyPluginScope,
        now: DateTime<Utc>,
    ) -> Result<(), PrivacyPluginError> {
        if self.id.as_str().trim().is_empty()
            || self.mission_id != scope.mission_id
            || self.object_id.trim().is_empty()
            || self.object_kind.trim().is_empty()
            || self.prior_object_revision == 0
            || self.deletion_generation == 0
            || !is_sha256(&self.idempotency_key_digest)
            || self.requested_at < self.consent.granted_at
            || self.requested_at > now
            || self.retention.policy_digest != scope.policy_digest
        {
            return Err(PrivacyPluginError::InvalidRequest(
                "deletion request is outside the mounted mission/policy scope".into(),
            ));
        }
        self.consent.validate(now)?;
        self.local_plan.validate()?;
        Ok(())
    }

    pub fn tombstone(
        &self,
        scope: &PrivacyPluginScope,
    ) -> Result<DeletionTombstone, PrivacyPluginError> {
        DeletionTombstone::create(
            self.id.clone(),
            scope.tenant_id.clone(),
            scope.project_id.clone(),
            self.object_id.clone(),
            self.object_kind.clone(),
            self.prior_object_revision,
            self.deletion_generation,
            self.reason,
            self.consent.actor_id.clone(),
            self.consent.evidence_digest.clone(),
            self.requested_at,
        )
        .map_err(|error| PrivacyPluginError::InvalidRequest(error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyLocalDeletionReceipt {
    pub request_id: DeletionId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub object_id: String,
    pub object_kind: String,
    pub scope_digest: String,
    pub policy_digest: String,
    pub consent_id: ConsentRecordId,
    pub tombstone_digest: String,
    pub local_record_revision: u64,
    pub operation_revision: u64,
    pub duplicate: bool,
    pub recorded_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl PrivacyLocalDeletionReceipt {
    #[allow(
        clippy::too_many_arguments,
        reason = "receipt binds every local deletion fence"
    )]
    pub fn create(
        scope: &PrivacyPluginScope,
        request: &PrivacyDeletionRequest,
        tombstone: &DeletionTombstone,
        local_record_revision: u64,
        operation_revision: u64,
        duplicate: bool,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, PrivacyPluginError> {
        let mut receipt = Self {
            request_id: request.id.clone(),
            tenant_id: scope.tenant_id.clone(),
            project_id: scope.project_id.clone(),
            object_id: request.object_id.clone(),
            object_kind: request.object_kind.clone(),
            scope_digest: scope.scope_digest.clone(),
            policy_digest: request.retention.policy_digest.clone(),
            consent_id: request.consent.id.clone(),
            tombstone_digest: tombstone.tombstone_digest.clone(),
            local_record_revision,
            operation_revision,
            duplicate,
            recorded_at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        receipt.validate_for(scope, request, tombstone, recorded_at)?;
        Ok(receipt)
    }

    pub fn validate_for(
        &self,
        scope: &PrivacyPluginScope,
        request: &PrivacyDeletionRequest,
        tombstone: &DeletionTombstone,
        now: DateTime<Utc>,
    ) -> Result<(), PrivacyPluginError> {
        if self.request_id != request.id
            || self.tenant_id != scope.tenant_id
            || self.project_id != scope.project_id
            || self.object_id != request.object_id
            || self.object_kind != request.object_kind
            || self.scope_digest != scope.scope_digest
            || self.policy_digest != request.retention.policy_digest
            || self.consent_id != request.consent.id
            || self.tombstone_digest != tombstone.tombstone_digest
            || self.local_record_revision == 0
            || self.operation_revision == 0
            || self.recorded_at < request.requested_at
            || self.recorded_at > now
            || self.receipt_digest != self.compute_digest()?
        {
            return Err(PrivacyPluginError::InvalidReceipt);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, PrivacyPluginError> {
        let bytes = serde_json::to_vec(&(
            &self.request_id,
            &self.tenant_id,
            &self.project_id,
            &self.object_id,
            &self.object_kind,
            &self.scope_digest,
            &self.policy_digest,
            &self.consent_id,
            &self.tombstone_digest,
            self.local_record_revision,
            self.operation_revision,
            self.duplicate,
            self.recorded_at,
        ))
        .map_err(|_| PrivacyPluginError::Serialization)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyDeletionAcceptance {
    pub request_id: DeletionId,
    pub tombstone: DeletionTombstone,
    pub local_receipt: PrivacyLocalDeletionReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyPropagationClaim {
    pub scope: PrivacyPluginScope,
    pub deletion_id: DeletionId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub object_id: String,
    pub object_kind: String,
    pub surface: DeletionSurface,
    pub tombstone: DeletionTombstone,
    pub deletion_generation: u64,
    pub tombstone_digest: String,
    pub worker_id: WorkerId,
    pub lease_generation: u64,
    pub lease_expires_at: DateTime<Utc>,
    pub attempts: u32,
    pub operation_digest: String,
}

impl PrivacyPropagationClaim {
    #[allow(
        clippy::too_many_arguments,
        reason = "claim mirrors the durable exact-scope lease"
    )]
    pub fn create(
        scope: PrivacyPluginScope,
        deletion_id: DeletionId,
        tenant_id: TenantId,
        project_id: ProjectId,
        object_id: String,
        object_kind: String,
        surface: DeletionSurface,
        tombstone: DeletionTombstone,
        worker_id: WorkerId,
        lease_generation: u64,
        lease_expires_at: DateTime<Utc>,
        attempts: u32,
    ) -> Result<Self, PrivacyPluginError> {
        let deletion_generation = tombstone.deletion_generation;
        let tombstone_digest = tombstone.tombstone_digest.clone();
        let operation_digest = digest_json(&(
            &scope.scope_digest,
            &deletion_id,
            &project_id,
            &object_id,
            &object_kind,
            surface,
            deletion_generation,
            &tombstone_digest,
        ))?;
        let claim = Self {
            scope,
            deletion_id,
            tenant_id,
            project_id,
            object_id,
            object_kind,
            surface,
            tombstone,
            deletion_generation,
            tombstone_digest,
            worker_id,
            lease_generation,
            lease_expires_at,
            attempts,
            operation_digest,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn validate(&self) -> Result<(), PrivacyPluginError> {
        if self.tenant_id != self.scope.tenant_id
            || self.project_id != self.scope.project_id
            || self.deletion_id.as_str().trim().is_empty()
            || self.object_id.trim().is_empty()
            || self.object_kind.trim().is_empty()
            || !self.surface.is_worker_managed()
            || self.tombstone.id != self.deletion_id
            || self.tombstone.tenant_id != self.tenant_id
            || self.tombstone.project_id != self.project_id
            || self.tombstone.object_id != self.object_id
            || self.tombstone.object_kind != self.object_kind
            || self.tombstone.deletion_generation != self.deletion_generation
            || self.tombstone.tombstone_digest != self.tombstone_digest
            || self
                .tombstone
                .validate(self.tombstone.requested_at)
                .is_err()
            || self.deletion_generation == 0
            || !is_sha256(&self.tombstone_digest)
            || self.worker_id.as_str().trim().is_empty()
            || self.lease_generation == 0
            || self.attempts == 0
            || self.operation_digest
                != digest_json(&(
                    &self.scope.scope_digest,
                    &self.deletion_id,
                    &self.project_id,
                    &self.object_id,
                    &self.object_kind,
                    self.surface,
                    self.deletion_generation,
                    &self.tombstone_digest,
                ))?
        {
            return Err(PrivacyPluginError::InvalidClaim);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyPropagationEvidence {
    pub inventory_digest: String,
    pub matched_items: u64,
    pub deleted_items: u64,
    pub residual_items: u64,
    pub verification_digest: String,
}

impl PrivacyPropagationEvidence {
    pub fn validate(&self) -> Result<(), PrivacyPluginError> {
        if !is_sha256(&self.inventory_digest)
            || !is_sha256(&self.verification_digest)
            || self.deleted_items > self.matched_items
            || self
                .deleted_items
                .checked_add(self.residual_items)
                .is_none_or(|total| total != self.matched_items)
        {
            return Err(PrivacyPluginError::InvalidProviderEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyProviderFailure {
    pub error_code: String,
    pub retryable: bool,
    pub residual_items: Option<u64>,
}

impl PrivacyProviderFailure {
    pub fn retryable(error_code: impl Into<String>, residual_items: Option<u64>) -> Self {
        Self {
            error_code: error_code.into(),
            retryable: true,
            residual_items,
        }
    }

    pub fn terminal(error_code: impl Into<String>, residual_items: Option<u64>) -> Self {
        Self {
            error_code: error_code.into(),
            retryable: false,
            residual_items,
        }
    }

    fn validate(&self) -> Result<(), PrivacyPluginError> {
        if self.error_code.trim().is_empty() || self.error_code.len() > 128 {
            return Err(PrivacyPluginError::InvalidProviderFailure);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyPropagationResult {
    pub deletion_id: DeletionId,
    pub project_id: ProjectId,
    pub surface: DeletionSurface,
    pub surface_status: DeletionPropagationStatus,
    pub request_status: DeletionRequestStatus,
    pub residual_items: Option<u64>,
    pub receipt_digest: Option<String>,
    pub record_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyConsumeOutcome {
    Idle,
    Applied(PrivacyPropagationResult),
    RetryScheduled {
        deletion_id: DeletionId,
        surface: DeletionSurface,
        attempts: u32,
        available_at: DateTime<Utc>,
        residual_items: Option<u64>,
    },
    DeadLettered {
        deletion_id: DeletionId,
        surface: DeletionSurface,
        attempts: u32,
        residual_items: Option<u64>,
    },
}

pub trait PrivacyPropagationProvider {
    fn propagate(
        &mut self,
        claim: &PrivacyPropagationClaim,
    ) -> Result<PrivacyPropagationEvidence, PrivacyProviderFailure>;
}

pub trait PrivacyPluginRepository {
    type Error;

    fn open_scope(
        &mut self,
        scope: &PrivacyPluginScope,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error>;

    fn suspend_scope(
        &mut self,
        scope: &PrivacyPluginScope,
        status: PrivacyPluginScopeStatus,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error>;

    fn begin_local_deletion(
        &mut self,
        scope: &PrivacyPluginScope,
        request: &PrivacyDeletionRequest,
        tombstone: &DeletionTombstone,
        now: DateTime<Utc>,
    ) -> Result<PrivacyLocalDeletionReceipt, Self::Error>;

    fn claim_propagation(
        &mut self,
        scope: &PrivacyPluginScope,
        surface: DeletionSurface,
        worker_id: &WorkerId,
        now: DateTime<Utc>,
        lease_for: Duration,
    ) -> Result<Option<PrivacyPropagationClaim>, Self::Error>;

    fn complete_propagation(
        &mut self,
        scope: &PrivacyPluginScope,
        claim: &PrivacyPropagationClaim,
        receipt: &DeletionPropagationReceipt,
        now: DateTime<Utc>,
    ) -> Result<PrivacyPropagationResult, Self::Error>;

    fn release_propagation(
        &mut self,
        scope: &PrivacyPluginScope,
        claim: &PrivacyPropagationClaim,
        failure: &PrivacyProviderFailure,
        dead_letter: bool,
        available_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub struct PrivacyPluginService<R> {
    repository: R,
    session: PrivacyPluginSession,
}

impl<R> PrivacyPluginService<R>
where
    R: PrivacyPluginRepository,
    R::Error: std::fmt::Display,
{
    pub fn mount(
        mut repository: R,
        scope: PrivacyPluginScope,
        now: DateTime<Utc>,
    ) -> Result<Self, PrivacyPluginError> {
        scope.validate(now)?;
        repository
            .open_scope(&scope, now)
            .map_err(repository_error)?;
        Ok(Self {
            repository,
            session: PrivacyPluginSession {
                scope,
                status: PrivacyPluginScopeStatus::Active,
            },
        })
    }

    pub fn request_deletion(
        &mut self,
        request: PrivacyDeletionRequest,
        now: DateTime<Utc>,
    ) -> Result<PrivacyDeletionAcceptance, PrivacyPluginError> {
        self.session.require_active(now)?;
        request.validate_for(&self.session.scope, now)?;
        if request.retention.action != RetentionAction::Delete {
            return Err(PrivacyPluginError::RetentionBlocked);
        }
        let tombstone = request.tombstone(&self.session.scope)?;
        let local_receipt = self
            .repository
            .begin_local_deletion(&self.session.scope, &request, &tombstone, now)
            .map_err(repository_error)?;
        Ok(PrivacyDeletionAcceptance {
            request_id: request.id,
            tombstone,
            local_receipt,
        })
    }

    pub fn into_consumer(
        self,
        surface: DeletionSurface,
        worker_id: WorkerId,
        max_attempts: u32,
        lease_for: Duration,
        retry_backoff: Duration,
    ) -> Result<PrivacyPluginConsumer<R>, PrivacyPluginError> {
        PrivacyPluginConsumer::from_parts(
            self.repository,
            self.session,
            surface,
            worker_id,
            max_attempts,
            lease_for,
            retry_backoff,
        )
    }

    pub fn unmount(&mut self, now: DateTime<Utc>) -> Result<(), PrivacyPluginError> {
        self.transition_scope(PrivacyPluginScopeStatus::Unmounted, now)
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), PrivacyPluginError> {
        self.transition_scope(PrivacyPluginScopeStatus::Revoked, now)
    }

    fn transition_scope(
        &mut self,
        status: PrivacyPluginScopeStatus,
        now: DateTime<Utc>,
    ) -> Result<(), PrivacyPluginError> {
        self.session.require_active(now)?;
        self.repository
            .suspend_scope(&self.session.scope, status, now)
            .map_err(repository_error)?;
        self.session.status = status;
        Ok(())
    }
}

#[derive(Debug)]
struct PrivacyPluginSession {
    scope: PrivacyPluginScope,
    status: PrivacyPluginScopeStatus,
}

impl PrivacyPluginSession {
    fn require_active(&self, now: DateTime<Utc>) -> Result<(), PrivacyPluginError> {
        if self.status != PrivacyPluginScopeStatus::Active {
            return Err(PrivacyPluginError::ScopeInactive);
        }
        self.scope.validate(now)
    }
}

#[derive(Debug)]
pub struct PrivacyPluginConsumer<R> {
    repository: R,
    session: PrivacyPluginSession,
    surface: DeletionSurface,
    worker_id: WorkerId,
    max_attempts: u32,
    lease_for: Duration,
    retry_backoff: Duration,
}

impl<R> PrivacyPluginConsumer<R>
where
    R: PrivacyPluginRepository,
    R::Error: std::fmt::Display,
{
    #[allow(
        clippy::too_many_arguments,
        reason = "consumer mount binds its complete lease and retry policy"
    )]
    pub fn mount(
        mut repository: R,
        scope: PrivacyPluginScope,
        surface: DeletionSurface,
        worker_id: WorkerId,
        max_attempts: u32,
        lease_for: Duration,
        retry_backoff: Duration,
        now: DateTime<Utc>,
    ) -> Result<Self, PrivacyPluginError> {
        scope.validate(now)?;
        repository
            .open_scope(&scope, now)
            .map_err(repository_error)?;
        Self::from_parts(
            repository,
            PrivacyPluginSession {
                scope,
                status: PrivacyPluginScopeStatus::Active,
            },
            surface,
            worker_id,
            max_attempts,
            lease_for,
            retry_backoff,
        )
    }

    fn from_parts(
        repository: R,
        session: PrivacyPluginSession,
        surface: DeletionSurface,
        worker_id: WorkerId,
        max_attempts: u32,
        lease_for: Duration,
        retry_backoff: Duration,
    ) -> Result<Self, PrivacyPluginError> {
        if !surface.is_worker_managed()
            || worker_id.as_str().trim().is_empty()
            || max_attempts == 0
            || lease_for <= Duration::zero()
            || retry_backoff < Duration::zero()
        {
            return Err(PrivacyPluginError::InvalidConsumerConfig);
        }
        Ok(Self {
            repository,
            session,
            surface,
            worker_id,
            max_attempts,
            lease_for,
            retry_backoff,
        })
    }

    pub fn consume_once<P: PrivacyPropagationProvider>(
        &mut self,
        provider: &mut P,
        now: DateTime<Utc>,
    ) -> Result<PrivacyConsumeOutcome, PrivacyPluginError> {
        self.session.require_active(now)?;
        let claim = self
            .repository
            .claim_propagation(
                &self.session.scope,
                self.surface,
                &self.worker_id,
                now,
                self.lease_for,
            )
            .map_err(repository_error)?;
        let Some(claim) = claim else {
            return Ok(PrivacyConsumeOutcome::Idle);
        };

        let evidence = match provider.propagate(&claim) {
            Ok(evidence) => evidence,
            Err(failure) => return self.settle_failure(claim, &failure, now),
        };
        if evidence.validate().is_err() {
            return self.settle_failure(
                claim,
                &PrivacyProviderFailure::terminal("invalid_provider_evidence", None),
                now,
            );
        }
        if evidence.residual_items != 0 {
            return self.settle_failure(
                claim,
                &PrivacyProviderFailure::retryable(
                    "residual_items_present",
                    Some(evidence.residual_items),
                ),
                now,
            );
        }

        let receipt_id =
            DeletionReceiptId::from_stable(format!("privacy-plugin:{}", claim.operation_digest));
        let receipt = DeletionPropagationReceipt::create(
            receipt_id,
            &claim.tombstone,
            claim.surface,
            claim.worker_id.clone(),
            claim.lease_generation,
            evidence.inventory_digest,
            evidence.matched_items,
            evidence.deleted_items,
            evidence.residual_items,
            evidence.verification_digest,
            now,
        )
        .map_err(|error| {
            PrivacyPluginError::InvalidProviderEvidenceWithReason(error.to_string())
        })?;
        let result = self
            .repository
            .complete_propagation(&self.session.scope, &claim, &receipt, now)
            .map_err(repository_error)?;
        Ok(PrivacyConsumeOutcome::Applied(result))
    }

    pub fn unmount(&mut self, now: DateTime<Utc>) -> Result<(), PrivacyPluginError> {
        self.transition_scope(PrivacyPluginScopeStatus::Unmounted, now)
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), PrivacyPluginError> {
        self.transition_scope(PrivacyPluginScopeStatus::Revoked, now)
    }

    fn settle_failure(
        &mut self,
        claim: PrivacyPropagationClaim,
        failure: &PrivacyProviderFailure,
        now: DateTime<Utc>,
    ) -> Result<PrivacyConsumeOutcome, PrivacyPluginError> {
        failure.validate()?;
        let dead_letter = !failure.retryable || claim.attempts >= self.max_attempts;
        let available_at = now
            .checked_add_signed(self.retry_backoff)
            .ok_or(PrivacyPluginError::InvalidConsumerConfig)?;
        self.repository
            .release_propagation(
                &self.session.scope,
                &claim,
                failure,
                dead_letter,
                available_at,
                now,
            )
            .map_err(repository_error)?;
        if dead_letter {
            Ok(PrivacyConsumeOutcome::DeadLettered {
                deletion_id: claim.deletion_id,
                surface: claim.surface,
                attempts: claim.attempts,
                residual_items: failure.residual_items,
            })
        } else {
            Ok(PrivacyConsumeOutcome::RetryScheduled {
                deletion_id: claim.deletion_id,
                surface: claim.surface,
                attempts: claim.attempts,
                available_at,
                residual_items: failure.residual_items,
            })
        }
    }

    fn transition_scope(
        &mut self,
        status: PrivacyPluginScopeStatus,
        now: DateTime<Utc>,
    ) -> Result<(), PrivacyPluginError> {
        self.session.require_active(now)?;
        self.repository
            .suspend_scope(&self.session.scope, status, now)
            .map_err(repository_error)?;
        self.session.status = status;
        Ok(())
    }
}

fn repository_error<E: std::fmt::Display>(error: E) -> PrivacyPluginError {
    PrivacyPluginError::Repository(error.to_string())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, PrivacyPluginError> {
    let bytes = serde_json::to_vec(value).map_err(|_| PrivacyPluginError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PrivacyPluginError {
    #[error("privacy plugin scope is invalid: {0}")]
    InvalidScope(String),
    #[error("privacy deletion consent is invalid")]
    InvalidConsent,
    #[error("privacy deletion request is invalid: {0}")]
    InvalidRequest(String),
    #[error("retention policy blocks deletion")]
    RetentionBlocked,
    #[error("privacy plugin scope is not active")]
    ScopeInactive,
    #[error("privacy plugin local deletion receipt is invalid")]
    InvalidReceipt,
    #[error("privacy propagation claim is invalid")]
    InvalidClaim,
    #[error("privacy provider evidence is invalid")]
    InvalidProviderEvidence,
    #[error("privacy provider evidence could not create a typed receipt: {0}")]
    InvalidProviderEvidenceWithReason(String),
    #[error("privacy provider failure is invalid")]
    InvalidProviderFailure,
    #[error("privacy plugin consumer configuration is invalid")]
    InvalidConsumerConfig,
    #[error("privacy plugin repository failed: {0}")]
    Repository(String),
    #[error("privacy plugin digest could not be serialized")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::DataClassification;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 10, 0, 0)
            .single()
            .expect("valid time")
    }

    fn scope() -> PrivacyPluginScope {
        PrivacyPluginScope::issue(
            TenantId::from("tenant-plugin"),
            ProjectId::from("project-plugin"),
            MissionId::from("mission-plugin"),
            "mission-deletion",
            "a".repeat(64),
            now(),
            now() + Duration::hours(1),
        )
        .expect("scope")
    }

    #[test]
    fn scope_reissue_changes_generation_and_digest() {
        let original = scope();
        let next = original
            .reissue(now() + Duration::minutes(1), now() + Duration::hours(2))
            .expect("reissue");
        assert_eq!(next.scope_generation, 2);
        assert_ne!(next.scope_digest, original.scope_digest);
    }

    #[test]
    fn request_requires_exact_mission_and_policy_scope() {
        let scope = scope();
        let request = PrivacyDeletionRequest {
            id: DeletionId::from("privacy-request"),
            mission_id: MissionId::from("other-mission"),
            object_id: "capsule".into(),
            object_kind: "context_capsule".into(),
            prior_object_revision: 1,
            deletion_generation: 1,
            reason: DeletionReason::UserRequest,
            consent: PrivacyDeletionConsent {
                id: ConsentRecordId::from("consent"),
                purpose: PrivacyConsentPurpose::MissionDeletion,
                actor_id: ActorId::from("owner"),
                evidence_digest: "b".repeat(64),
                granted_at: now(),
                expires_at: now() + Duration::hours(1),
            },
            retention: RetentionDecision {
                classification: DataClassification::Restricted,
                action: RetentionAction::Delete,
                due_at: now(),
                legal_hold: false,
                policy_digest: scope.policy_digest.clone(),
            },
            idempotency_key_digest: "c".repeat(64),
            local_plan: PrivacyLocalDeletionPlan {
                cell: "us".into(),
                key_version: 1,
            },
            requested_at: now(),
        };
        assert!(matches!(
            request.validate_for(&scope, now()),
            Err(PrivacyPluginError::InvalidRequest(_))
        ));
    }

    #[test]
    fn provider_evidence_keeps_residual_explicit() {
        let evidence = PrivacyPropagationEvidence {
            inventory_digest: "a".repeat(64),
            matched_items: 3,
            deleted_items: 2,
            residual_items: 1,
            verification_digest: "b".repeat(64),
        };
        assert!(evidence.validate().is_ok());
    }

    #[derive(Clone, Debug)]
    struct FakeRepository {
        state: Arc<Mutex<FakeState>>,
    }

    #[derive(Debug)]
    struct FakeState {
        scope: Option<(PrivacyPluginScope, PrivacyPluginScopeStatus)>,
        tombstone: Option<DeletionTombstone>,
        local_receipt: Option<PrivacyLocalDeletionReceipt>,
        job: FakeJob,
        result: Option<PrivacyPropagationResult>,
        receipt: Option<DeletionPropagationReceipt>,
    }

    #[derive(Debug)]
    struct FakeJob {
        surface: DeletionSurface,
        status: FakeJobStatus,
        attempts: u32,
        lease_generation: u64,
        lease_owner: Option<WorkerId>,
        lease_expires_at: Option<DateTime<Utc>>,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum FakeJobStatus {
        Pending,
        Leased,
        Applied,
        DeadLetter,
    }

    impl FakeRepository {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeState {
                    scope: None,
                    tombstone: None,
                    local_receipt: None,
                    job: FakeJob {
                        surface: DeletionSurface::Cache,
                        status: FakeJobStatus::Pending,
                        attempts: 0,
                        lease_generation: 0,
                        lease_owner: None,
                        lease_expires_at: None,
                    },
                    result: None,
                    receipt: None,
                })),
            }
        }

        fn lock(&self) -> Result<std::sync::MutexGuard<'_, FakeState>, String> {
            self.state
                .lock()
                .map_err(|_| "fake repository poisoned".into())
        }

        fn require_scope(state: &FakeState, scope: &PrivacyPluginScope) -> Result<(), String> {
            match state.scope.as_ref() {
                Some((current, PrivacyPluginScopeStatus::Active))
                    if current.scope_generation == scope.scope_generation
                        && current.scope_digest == scope.scope_digest =>
                {
                    Ok(())
                }
                _ => Err("privacy plugin scope lost".into()),
            }
        }
    }

    impl PrivacyPluginRepository for FakeRepository {
        type Error = String;

        fn open_scope(
            &mut self,
            scope: &PrivacyPluginScope,
            _now: DateTime<Utc>,
        ) -> Result<(), Self::Error> {
            let mut state = self.lock()?;
            match state.scope.as_ref() {
                None => state.scope = Some((scope.clone(), PrivacyPluginScopeStatus::Active)),
                Some((current, PrivacyPluginScopeStatus::Active)) if current == scope => {}
                Some((current, status))
                    if *status != PrivacyPluginScopeStatus::Active
                        && scope.scope_generation == current.scope_generation + 1
                        && current.tenant_id == scope.tenant_id
                        && current.project_id == scope.project_id
                        && current.mission_id == scope.mission_id
                        && current.scope_id == scope.scope_id
                        && current.policy_digest == scope.policy_digest =>
                {
                    state.scope = Some((scope.clone(), PrivacyPluginScopeStatus::Active));
                }
                Some(_) => return Err("privacy plugin scope conflict".into()),
            }
            Ok(())
        }

        fn suspend_scope(
            &mut self,
            scope: &PrivacyPluginScope,
            status: PrivacyPluginScopeStatus,
            _now: DateTime<Utc>,
        ) -> Result<(), Self::Error> {
            let mut state = self.lock()?;
            Self::require_scope(&state, scope)?;
            state.scope = Some((scope.clone(), status));
            Ok(())
        }

        fn begin_local_deletion(
            &mut self,
            scope: &PrivacyPluginScope,
            request: &PrivacyDeletionRequest,
            tombstone: &DeletionTombstone,
            now: DateTime<Utc>,
        ) -> Result<PrivacyLocalDeletionReceipt, Self::Error> {
            let mut state = self.lock()?;
            Self::require_scope(&state, scope)?;
            if let Some(receipt) = state.local_receipt.clone() {
                return Ok(receipt);
            }
            let receipt =
                PrivacyLocalDeletionReceipt::create(scope, request, tombstone, 1, 1, false, now)
                    .map_err(|error| error.to_string())?;
            state.tombstone = Some(tombstone.clone());
            state.local_receipt = Some(receipt.clone());
            Ok(receipt)
        }

        fn claim_propagation(
            &mut self,
            scope: &PrivacyPluginScope,
            surface: DeletionSurface,
            worker_id: &WorkerId,
            now: DateTime<Utc>,
            lease_for: Duration,
        ) -> Result<Option<PrivacyPropagationClaim>, Self::Error> {
            let mut state = self.lock()?;
            Self::require_scope(&state, scope)?;
            if state.job.surface != surface
                || matches!(
                    state.job.status,
                    FakeJobStatus::Applied | FakeJobStatus::DeadLetter
                )
                || (state.job.status == FakeJobStatus::Leased
                    && state
                        .job
                        .lease_expires_at
                        .is_some_and(|expires| expires > now))
            {
                return Ok(None);
            }
            let tombstone = state
                .tombstone
                .clone()
                .ok_or_else(|| "fake repository has no tombstone".to_owned())?;
            state.job.status = FakeJobStatus::Leased;
            state.job.attempts += 1;
            state.job.lease_generation += 1;
            state.job.lease_owner = Some(worker_id.clone());
            state.job.lease_expires_at = Some(now + lease_for);
            Ok(Some(
                PrivacyPropagationClaim::create(
                    scope.clone(),
                    tombstone.id.clone(),
                    tombstone.tenant_id.clone(),
                    tombstone.project_id.clone(),
                    tombstone.object_id.clone(),
                    tombstone.object_kind.clone(),
                    surface,
                    tombstone,
                    worker_id.clone(),
                    state.job.lease_generation,
                    state.job.lease_expires_at.expect("lease expiry"),
                    state.job.attempts,
                )
                .map_err(|error| error.to_string())?,
            ))
        }

        fn complete_propagation(
            &mut self,
            scope: &PrivacyPluginScope,
            claim: &PrivacyPropagationClaim,
            receipt: &DeletionPropagationReceipt,
            _now: DateTime<Utc>,
        ) -> Result<PrivacyPropagationResult, Self::Error> {
            let mut state = self.lock()?;
            Self::require_scope(&state, scope)?;
            if let Some(existing) = &state.receipt {
                if existing == receipt {
                    return state
                        .result
                        .clone()
                        .ok_or_else(|| "fake replay lacks result".into());
                }
                return Err("immutable receipt mismatch".into());
            }
            if state.job.status != FakeJobStatus::Leased
                || state.job.lease_generation != claim.lease_generation
                || state.job.lease_owner.as_ref() != Some(&claim.worker_id)
            {
                return Err("lease lost".into());
            }
            let result = PrivacyPropagationResult {
                deletion_id: claim.deletion_id.clone(),
                project_id: claim.project_id.clone(),
                surface: claim.surface,
                surface_status: DeletionPropagationStatus::Applied,
                request_status: DeletionRequestStatus::Propagating,
                residual_items: Some(0),
                receipt_digest: Some(receipt.receipt_digest.clone()),
                record_revision: 2,
            };
            state.job.status = FakeJobStatus::Applied;
            state.receipt = Some(receipt.clone());
            state.result = Some(result.clone());
            Ok(result)
        }

        fn release_propagation(
            &mut self,
            scope: &PrivacyPluginScope,
            claim: &PrivacyPropagationClaim,
            _failure: &PrivacyProviderFailure,
            dead_letter: bool,
            _available_at: DateTime<Utc>,
            _now: DateTime<Utc>,
        ) -> Result<(), Self::Error> {
            let mut state = self.lock()?;
            Self::require_scope(&state, scope)?;
            if state.job.status != FakeJobStatus::Leased
                || state.job.lease_generation != claim.lease_generation
            {
                return Err("lease lost".into());
            }
            state.job.status = if dead_letter {
                FakeJobStatus::DeadLetter
            } else {
                FakeJobStatus::Pending
            };
            state.job.lease_owner = None;
            state.job.lease_expires_at = None;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ScriptedProvider {
        responses: Vec<Result<PrivacyPropagationEvidence, PrivacyProviderFailure>>,
        calls: usize,
    }

    impl ScriptedProvider {
        fn success() -> Self {
            Self {
                responses: vec![Ok(PrivacyPropagationEvidence {
                    inventory_digest: "1".repeat(64),
                    matched_items: 0,
                    deleted_items: 0,
                    residual_items: 0,
                    verification_digest: "2".repeat(64),
                })],
                calls: 0,
            }
        }

        fn residual_then_success() -> Self {
            let mut provider = Self::success();
            provider.responses.push(Ok(PrivacyPropagationEvidence {
                inventory_digest: "3".repeat(64),
                matched_items: 2,
                deleted_items: 1,
                residual_items: 1,
                verification_digest: "4".repeat(64),
            }));
            provider
        }
    }

    impl PrivacyPropagationProvider for ScriptedProvider {
        fn propagate(
            &mut self,
            _claim: &PrivacyPropagationClaim,
        ) -> Result<PrivacyPropagationEvidence, PrivacyProviderFailure> {
            self.calls += 1;
            self.responses.pop().unwrap_or_else(|| {
                Err(PrivacyProviderFailure::terminal("provider_exhausted", None))
            })
        }
    }

    fn valid_request(scope: &PrivacyPluginScope) -> PrivacyDeletionRequest {
        PrivacyDeletionRequest {
            id: DeletionId::from("privacy-service-request"),
            mission_id: scope.mission_id.clone(),
            object_id: "context-capsule-service".into(),
            object_kind: "context_capsule".into(),
            prior_object_revision: 1,
            deletion_generation: 1,
            reason: DeletionReason::UserRequest,
            consent: PrivacyDeletionConsent {
                id: ConsentRecordId::from("privacy-service-consent"),
                purpose: PrivacyConsentPurpose::MissionDeletion,
                actor_id: ActorId::from("mission-owner"),
                evidence_digest: "5".repeat(64),
                granted_at: now(),
                expires_at: now() + Duration::hours(1),
            },
            retention: RetentionDecision {
                classification: DataClassification::Restricted,
                action: RetentionAction::Delete,
                due_at: now(),
                legal_hold: false,
                policy_digest: scope.policy_digest.clone(),
            },
            idempotency_key_digest: "6".repeat(64),
            local_plan: PrivacyLocalDeletionPlan {
                cell: "us".into(),
                key_version: 1,
            },
            requested_at: now(),
        }
    }

    #[test]
    fn service_binds_typed_consent_policy_receipt_and_restart_result() {
        let repository = FakeRepository::new();
        let mounted_scope = scope();
        let mut service =
            PrivacyPluginService::mount(repository.clone(), mounted_scope.clone(), now())
                .expect("mount");
        let acceptance = service
            .request_deletion(valid_request(&mounted_scope), now())
            .expect("typed deletion request");
        assert_eq!(
            acceptance.local_receipt.tombstone_digest,
            acceptance.tombstone.tombstone_digest
        );
        assert_eq!(
            acceptance.local_receipt.policy_digest,
            mounted_scope.policy_digest
        );
        let mut consumer = service
            .into_consumer(
                DeletionSurface::Cache,
                WorkerId::from("privacy-consumer"),
                3,
                Duration::minutes(5),
                Duration::seconds(1),
            )
            .expect("consumer");
        let mut provider = ScriptedProvider::success();
        let applied = consumer
            .consume_once(&mut provider, now())
            .expect("propagation");
        assert!(matches!(applied, PrivacyConsumeOutcome::Applied(_)));
        assert_eq!(provider.calls, 1);

        let mut restarted = PrivacyPluginConsumer::mount(
            repository,
            mounted_scope,
            DeletionSurface::Cache,
            WorkerId::from("privacy-consumer-restarted"),
            3,
            Duration::minutes(5),
            Duration::seconds(1),
            now() + Duration::seconds(2),
        )
        .expect("restart mount");
        assert!(matches!(
            restarted
                .consume_once(
                    &mut ScriptedProvider::success(),
                    now() + Duration::seconds(2)
                )
                .expect("restart poll"),
            PrivacyConsumeOutcome::Idle
        ));
    }

    #[test]
    fn residual_is_retryable_and_terminal_provider_failure_dead_letters() {
        let repository = FakeRepository::new();
        let mounted_scope = scope();
        let mut service =
            PrivacyPluginService::mount(repository.clone(), mounted_scope.clone(), now())
                .expect("mount");
        service
            .request_deletion(valid_request(&mounted_scope), now())
            .expect("request");
        let mut consumer = service
            .into_consumer(
                DeletionSurface::Cache,
                WorkerId::from("privacy-consumer"),
                2,
                Duration::minutes(5),
                Duration::seconds(1),
            )
            .expect("consumer");
        let mut provider = ScriptedProvider::residual_then_success();
        assert!(matches!(
            consumer
                .consume_once(&mut provider, now())
                .expect("residual result"),
            PrivacyConsumeOutcome::RetryScheduled {
                residual_items: Some(1),
                ..
            }
        ));
        assert!(matches!(
            consumer
                .consume_once(&mut provider, now() + Duration::seconds(1))
                .expect("retry result"),
            PrivacyConsumeOutcome::Applied(_)
        ));

        let terminal_repository = FakeRepository::new();
        let terminal_scope = scope();
        let mut terminal_service =
            PrivacyPluginService::mount(terminal_repository, terminal_scope.clone(), now())
                .expect("terminal mount");
        terminal_service
            .request_deletion(valid_request(&terminal_scope), now())
            .expect("terminal request");
        let mut terminal_consumer = terminal_service
            .into_consumer(
                DeletionSurface::Cache,
                WorkerId::from("privacy-terminal-consumer"),
                3,
                Duration::minutes(5),
                Duration::seconds(1),
            )
            .expect("terminal consumer");
        let mut provider = ScriptedProvider {
            responses: vec![Err(PrivacyProviderFailure::terminal(
                "provider_rejected",
                None,
            ))],
            calls: 0,
        };
        assert!(matches!(
            terminal_consumer
                .consume_once(&mut provider, now())
                .expect("dead letter result"),
            PrivacyConsumeOutcome::DeadLettered { .. }
        ));
    }

    #[test]
    fn crash_recovery_and_scope_fence_reject_old_ack() {
        let repository = FakeRepository::new();
        let mounted_scope = scope();
        let mut service =
            PrivacyPluginService::mount(repository.clone(), mounted_scope.clone(), now())
                .expect("mount");
        service
            .request_deletion(valid_request(&mounted_scope), now())
            .expect("request");
        let old_claim = repository
            .clone()
            .claim_propagation(
                &mounted_scope,
                DeletionSurface::Cache,
                &WorkerId::from("crashed-worker"),
                now(),
                Duration::seconds(5),
            )
            .expect("old claim")
            .expect("job");
        let new_claim = repository
            .clone()
            .claim_propagation(
                &mounted_scope,
                DeletionSurface::Cache,
                &WorkerId::from("restarted-worker"),
                now() + Duration::seconds(6),
                Duration::seconds(5),
            )
            .expect("restarted claim")
            .expect("expired job");
        assert_eq!(new_claim.lease_generation, old_claim.lease_generation + 1);
        let stale_receipt = DeletionPropagationReceipt::create(
            DeletionReceiptId::from_stable(format!(
                "privacy-plugin:{}",
                old_claim.operation_digest
            )),
            &old_claim.tombstone,
            old_claim.surface,
            old_claim.worker_id.clone(),
            old_claim.lease_generation,
            "7".repeat(64),
            0,
            0,
            0,
            "8".repeat(64),
            now() + Duration::seconds(6),
        )
        .expect("stale receipt");
        assert!(matches!(
            repository.clone().complete_propagation(
                &mounted_scope,
                &old_claim,
                &stale_receipt,
                now() + Duration::seconds(6),
            ),
            Err(error) if error == "lease lost"
        ));

        let mut unmount_service =
            PrivacyPluginService::mount(repository.clone(), mounted_scope.clone(), now())
                .expect("remount");
        unmount_service
            .unmount(now() + Duration::seconds(7))
            .expect("unmount");
        assert!(matches!(
            repository.clone().complete_propagation(
                &mounted_scope,
                &new_claim,
                &stale_receipt,
                now() + Duration::seconds(7),
            ),
            Err(error) if error == "privacy plugin scope lost"
        ));

        let next_scope = mounted_scope
            .reissue(now() + Duration::seconds(12), now() + Duration::hours(2))
            .expect("next scope");
        let mut consumer = PrivacyPluginConsumer::mount(
            repository,
            next_scope,
            DeletionSurface::Cache,
            WorkerId::from("successor-worker"),
            3,
            Duration::minutes(5),
            Duration::seconds(1),
            now() + Duration::seconds(12),
        )
        .expect("successor consumer");
        assert!(matches!(
            consumer
                .consume_once(
                    &mut ScriptedProvider::success(),
                    now() + Duration::seconds(12)
                )
                .expect("successor poll"),
            PrivacyConsumeOutcome::Applied(_)
        ));
    }
}

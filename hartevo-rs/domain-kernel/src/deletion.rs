use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ActorId, DeletionId, DeletionReceiptId, ProjectId, TenantId, WorkerId};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionSurface {
    LocalProjection,
    EncryptedCell,
    ContextDerived,
    Cache,
    Replay,
    ObjectStorage,
}

impl DeletionSurface {
    pub fn required() -> BTreeSet<Self> {
        BTreeSet::from([
            Self::LocalProjection,
            Self::EncryptedCell,
            Self::ContextDerived,
            Self::Cache,
            Self::Replay,
            Self::ObjectStorage,
        ])
    }

    pub const fn is_worker_managed(self) -> bool {
        matches!(self, Self::Cache | Self::Replay | Self::ObjectStorage)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionReason {
    UserRequest,
    ProjectDeletion,
    RetentionExpiry,
    ConsentWithdrawal,
    SecurityResponse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionRetentionMode {
    EraseContentRetainAudit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionTombstone {
    pub id: DeletionId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub object_id: String,
    pub object_kind: String,
    pub prior_object_revision: u64,
    pub deletion_generation: u64,
    pub reason: DeletionReason,
    pub authorized_by: ActorId,
    pub authorization_evidence_digest: String,
    pub requested_at: DateTime<Utc>,
    pub retention_mode: DeletionRetentionMode,
    pub required_surfaces: BTreeSet<DeletionSurface>,
    pub tombstone_digest: String,
    pub revision: u64,
}

impl DeletionTombstone {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: DeletionId,
        tenant_id: TenantId,
        project_id: ProjectId,
        object_id: impl Into<String>,
        object_kind: impl Into<String>,
        prior_object_revision: u64,
        deletion_generation: u64,
        reason: DeletionReason,
        authorized_by: ActorId,
        authorization_evidence_digest: impl Into<String>,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        let mut tombstone = Self {
            id,
            tenant_id,
            project_id,
            object_id: object_id.into(),
            object_kind: object_kind.into(),
            prior_object_revision,
            deletion_generation,
            reason,
            authorized_by,
            authorization_evidence_digest: authorization_evidence_digest.into(),
            requested_at,
            retention_mode: DeletionRetentionMode::EraseContentRetainAudit,
            required_surfaces: DeletionSurface::required(),
            tombstone_digest: String::new(),
            revision: 1,
        };
        tombstone.tombstone_digest = tombstone.compute_digest()?;
        tombstone.validate(requested_at)?;
        Ok(tombstone)
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), DeletionError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.object_id.trim().is_empty()
            || self.object_kind.trim().is_empty()
            || self.prior_object_revision == 0
            || self.deletion_generation == 0
            || self.authorized_by.as_str().trim().is_empty()
            || !is_sha256(&self.authorization_evidence_digest)
            || self.requested_at > now
            || self.required_surfaces != DeletionSurface::required()
            || self.revision != 1
            || self.tombstone_digest != self.compute_digest()?
        {
            return Err(DeletionError::InvalidTombstone);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, DeletionError> {
        digest_json(&(
            (
                &self.id,
                &self.tenant_id,
                &self.project_id,
                &self.object_id,
                &self.object_kind,
                self.prior_object_revision,
                self.deletion_generation,
            ),
            (
                self.reason,
                &self.authorized_by,
                &self.authorization_evidence_digest,
                self.requested_at,
                self.retention_mode,
                &self.required_surfaces,
                self.revision,
            ),
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionPropagationStatus {
    Pending,
    Applied,
    NotApplicable,
    BlockedRetention,
    Failed,
    DeadLetter,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionRequestStatus {
    Requested,
    Propagating,
    PartiallyApplied,
    Blocked,
    DeadLettered,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionSurfaceState {
    pub status: DeletionPropagationStatus,
    pub evidence_digest: Option<String>,
    pub error_code: Option<String>,
    #[serde(default)]
    pub matched_items: u64,
    #[serde(default)]
    pub deleted_items: u64,
    #[serde(default)]
    pub residual_items: Option<u64>,
    pub updated_at: DateTime<Utc>,
}

/// Immutable proof returned by a surface-specific deletion worker after both a
/// scoped purge and an independent post-purge inventory have completed.
///
/// A zero-match receipt is valid: it proves the exact surface was inspected and
/// already empty. A non-zero residual is never accepted as completion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionPropagationReceipt {
    pub id: DeletionReceiptId,
    pub deletion_id: DeletionId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub object_id: String,
    pub object_kind: String,
    pub surface: DeletionSurface,
    pub deletion_generation: u64,
    pub tombstone_digest: String,
    pub worker_id: WorkerId,
    pub lease_generation: u64,
    pub inventory_digest: String,
    pub matched_items: u64,
    pub deleted_items: u64,
    pub residual_items: u64,
    pub verification_digest: String,
    pub completed_at: DateTime<Utc>,
    pub receipt_digest: String,
    pub revision: u64,
}

impl DeletionPropagationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: DeletionReceiptId,
        tombstone: &DeletionTombstone,
        surface: DeletionSurface,
        worker_id: WorkerId,
        lease_generation: u64,
        inventory_digest: impl Into<String>,
        matched_items: u64,
        deleted_items: u64,
        residual_items: u64,
        verification_digest: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        let mut receipt = Self {
            id,
            deletion_id: tombstone.id.clone(),
            tenant_id: tombstone.tenant_id.clone(),
            project_id: tombstone.project_id.clone(),
            object_id: tombstone.object_id.clone(),
            object_kind: tombstone.object_kind.clone(),
            surface,
            deletion_generation: tombstone.deletion_generation,
            tombstone_digest: tombstone.tombstone_digest.clone(),
            worker_id,
            lease_generation,
            inventory_digest: inventory_digest.into(),
            matched_items,
            deleted_items,
            residual_items,
            verification_digest: verification_digest.into(),
            completed_at,
            receipt_digest: String::new(),
            revision: 1,
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        receipt.validate_for(tombstone, completed_at)?;
        Ok(receipt)
    }

    pub fn validate_for(
        &self,
        tombstone: &DeletionTombstone,
        now: DateTime<Utc>,
    ) -> Result<(), DeletionError> {
        tombstone.validate(now)?;
        let exact_scope = self.deletion_id == tombstone.id
            && self.tenant_id == tombstone.tenant_id
            && self.project_id == tombstone.project_id
            && self.object_id == tombstone.object_id
            && self.object_kind == tombstone.object_kind
            && self.deletion_generation == tombstone.deletion_generation
            && self.tombstone_digest == tombstone.tombstone_digest;
        if self.id.as_str().trim().is_empty()
            || !exact_scope
            || !self.surface.is_worker_managed()
            || !tombstone.required_surfaces.contains(&self.surface)
            || self.worker_id.as_str().trim().is_empty()
            || self.lease_generation == 0
            || !is_sha256(&self.inventory_digest)
            || self.matched_items != self.deleted_items
            || self.residual_items != 0
            || !is_sha256(&self.verification_digest)
            || self.completed_at < tombstone.requested_at
            || self.completed_at > now
            || self.revision != 1
            || self.receipt_digest != self.compute_digest()?
        {
            return Err(DeletionError::InvalidPropagationReceipt);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, DeletionError> {
        digest_json(&(
            (
                &self.id,
                &self.deletion_id,
                &self.tenant_id,
                &self.project_id,
                &self.object_id,
                &self.object_kind,
                self.surface,
            ),
            (
                self.deletion_generation,
                &self.tombstone_digest,
                &self.worker_id,
                self.lease_generation,
                &self.inventory_digest,
            ),
            (
                self.matched_items,
                self.deleted_items,
                self.residual_items,
                &self.verification_digest,
                self.completed_at,
                self.revision,
            ),
        ))
    }
}

impl DeletionSurfaceState {
    fn validate(&self) -> Result<(), DeletionError> {
        let evidence_valid = self
            .evidence_digest
            .as_ref()
            .is_none_or(|digest| is_sha256(digest));
        let shape_valid = match self.status {
            DeletionPropagationStatus::Pending => {
                self.evidence_digest.is_none()
                    && self.error_code.is_none()
                    && self.matched_items == 0
                    && self.deleted_items == 0
                    && self.residual_items.is_none()
            }
            DeletionPropagationStatus::Applied => {
                self.evidence_digest.is_some()
                    && self.error_code.is_none()
                    && self.deleted_items == self.matched_items
                    && self.residual_items.is_none_or(|residual| residual == 0)
            }
            DeletionPropagationStatus::NotApplicable => {
                self.evidence_digest.is_some()
                    && self.error_code.is_none()
                    && self.matched_items == 0
                    && self.deleted_items == 0
                    && self.residual_items.is_none_or(|residual| residual == 0)
            }
            DeletionPropagationStatus::BlockedRetention
            | DeletionPropagationStatus::Failed
            | DeletionPropagationStatus::DeadLetter => {
                self.error_code
                    .as_ref()
                    .is_some_and(|code| !code.trim().is_empty() && code.len() <= 128)
                    && self.matched_items == 0
                    && self.deleted_items == 0
            }
        };
        let counts_valid = match self.status {
            DeletionPropagationStatus::Applied | DeletionPropagationStatus::NotApplicable => {
                self.deleted_items <= self.matched_items
                    && self.residual_items.is_none_or(|residual| {
                        self.deleted_items
                            .checked_add(residual)
                            .is_some_and(|total| total == self.matched_items)
                    })
            }
            DeletionPropagationStatus::Pending
            | DeletionPropagationStatus::BlockedRetention
            | DeletionPropagationStatus::Failed
            | DeletionPropagationStatus::DeadLetter => true,
        };
        if !evidence_valid || !shape_valid || !counts_valid {
            return Err(DeletionError::InvalidPropagationState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionRecord {
    pub tombstone: DeletionTombstone,
    pub remote_object_revision: u64,
    pub surfaces: BTreeMap<DeletionSurface, DeletionSurfaceState>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DeletionRecord {
    pub fn pending(
        tombstone: DeletionTombstone,
        remote_object_revision: u64,
        local_evidence_digest: String,
        context_evidence_digest: String,
        object_storage_evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        tombstone.validate(now)?;
        let mut surfaces = DeletionSurface::required()
            .into_iter()
            .map(|surface| {
                (
                    surface,
                    DeletionSurfaceState {
                        status: DeletionPropagationStatus::Pending,
                        evidence_digest: None,
                        error_code: None,
                        matched_items: 0,
                        deleted_items: 0,
                        residual_items: None,
                        updated_at: now,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        set_applied(
            &mut surfaces,
            DeletionSurface::LocalProjection,
            local_evidence_digest,
            now,
        )?;
        set_applied(
            &mut surfaces,
            DeletionSurface::ContextDerived,
            context_evidence_digest,
            now,
        )?;
        set_not_applicable(
            &mut surfaces,
            DeletionSurface::ObjectStorage,
            object_storage_evidence_digest,
            now,
        )?;
        let record = Self {
            tombstone,
            remote_object_revision,
            surfaces,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        record.validate(now)?;
        Ok(record)
    }

    fn mark_surface_applied(
        &self,
        surface: DeletionSurface,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        self.mark_surface_applied_with_counts(surface, evidence_digest, 0, 0, 0, now)
    }

    fn mark_surface_applied_with_counts(
        &self,
        surface: DeletionSurface,
        evidence_digest: String,
        matched_items: u64,
        deleted_items: u64,
        residual_items: u64,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        let mut next = self.clone();
        let state = next
            .surfaces
            .get(&surface)
            .ok_or(DeletionError::InvalidPropagationState)?;
        if matches!(
            state.status,
            DeletionPropagationStatus::Applied | DeletionPropagationStatus::NotApplicable
        ) {
            if state.evidence_digest.as_deref() == Some(&evidence_digest) {
                return Ok(next);
            }
            return Err(DeletionError::InvalidPropagationTransition);
        }
        set_applied_with_counts(
            &mut next.surfaces,
            surface,
            evidence_digest,
            matched_items,
            deleted_items,
            residual_items,
            now,
        )?;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(DeletionError::RevisionOverflow)?;
        next.updated_at = now;
        next.validate(now)?;
        Ok(next)
    }

    pub fn mark_encrypted_cell_applied(
        &self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        self.mark_surface_applied(DeletionSurface::EncryptedCell, evidence_digest, now)
    }

    pub fn mark_surface_failed(
        &self,
        surface: DeletionSurface,
        error_code: impl Into<String>,
        residual_items: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        self.mark_surface_failure(
            surface,
            DeletionPropagationStatus::Failed,
            error_code.into(),
            residual_items,
            now,
        )
    }

    pub fn mark_surface_dead_letter(
        &self,
        surface: DeletionSurface,
        error_code: impl Into<String>,
        residual_items: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        self.mark_surface_failure(
            surface,
            DeletionPropagationStatus::DeadLetter,
            error_code.into(),
            residual_items,
            now,
        )
    }

    pub fn mark_surface_blocked(
        &self,
        surface: DeletionSurface,
        error_code: impl Into<String>,
        residual_items: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        self.mark_surface_failure(
            surface,
            DeletionPropagationStatus::BlockedRetention,
            error_code.into(),
            residual_items,
            now,
        )
    }

    fn mark_surface_failure(
        &self,
        surface: DeletionSurface,
        status: DeletionPropagationStatus,
        error_code: String,
        residual_items: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        let worker_failure = matches!(
            status,
            DeletionPropagationStatus::Failed | DeletionPropagationStatus::DeadLetter
        );
        let retention_block = status == DeletionPropagationStatus::BlockedRetention;
        if (!worker_failure && !retention_block)
            || (worker_failure && !surface.is_worker_managed())
            || error_code.trim().is_empty()
            || error_code.len() > 128
        {
            return Err(DeletionError::InvalidPropagationState);
        }
        let mut next = self.clone();
        let state = next
            .surfaces
            .get(&surface)
            .ok_or(DeletionError::InvalidPropagationState)?;
        if matches!(
            state.status,
            DeletionPropagationStatus::Applied
                | DeletionPropagationStatus::NotApplicable
                | DeletionPropagationStatus::BlockedRetention
                | DeletionPropagationStatus::DeadLetter
        ) {
            if state.status == status
                && state.error_code.as_deref() == Some(error_code.as_str())
                && state.residual_items == residual_items
            {
                return Ok(next);
            }
            return Err(DeletionError::InvalidPropagationTransition);
        }
        next.surfaces.insert(
            surface,
            DeletionSurfaceState {
                status,
                evidence_digest: None,
                error_code: Some(error_code),
                matched_items: 0,
                deleted_items: 0,
                residual_items,
                updated_at: now,
            },
        );
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(DeletionError::RevisionOverflow)?;
        next.updated_at = now;
        next.validate(now)?;
        Ok(next)
    }

    pub fn apply_receipt(
        &self,
        receipt: &DeletionPropagationReceipt,
        now: DateTime<Utc>,
    ) -> Result<Self, DeletionError> {
        receipt.validate_for(&self.tombstone, now)?;
        self.mark_surface_applied_with_counts(
            receipt.surface,
            receipt.receipt_digest.clone(),
            receipt.matched_items,
            receipt.deleted_items,
            receipt.residual_items,
            now,
        )
    }

    pub fn is_complete(&self) -> bool {
        self.status() == DeletionRequestStatus::Completed
    }

    pub fn status(&self) -> DeletionRequestStatus {
        if self
            .surfaces
            .values()
            .any(|state| state.status == DeletionPropagationStatus::BlockedRetention)
        {
            return DeletionRequestStatus::Blocked;
        }
        if self
            .surfaces
            .values()
            .any(|state| state.status == DeletionPropagationStatus::DeadLetter)
        {
            return DeletionRequestStatus::DeadLettered;
        }
        if self.surfaces.values().all(|state| {
            matches!(
                state.status,
                DeletionPropagationStatus::Applied | DeletionPropagationStatus::NotApplicable
            ) && state.residual_items == Some(0)
        }) {
            return DeletionRequestStatus::Completed;
        }
        if self
            .surfaces
            .values()
            .any(|state| state.status == DeletionPropagationStatus::Failed)
        {
            return DeletionRequestStatus::PartiallyApplied;
        }
        if self.surfaces.values().any(|state| {
            matches!(
                state.status,
                DeletionPropagationStatus::Applied | DeletionPropagationStatus::NotApplicable
            )
        }) {
            DeletionRequestStatus::Propagating
        } else {
            DeletionRequestStatus::Requested
        }
    }

    /// Returns a count only when every surface has supplied an inventory
    /// result. `None` is intentionally not interpreted as zero.
    pub fn residual_item_count(&self) -> Option<u64> {
        self.surfaces
            .values()
            .map(|state| state.residual_items)
            .collect::<Option<Vec<_>>>()
            .and_then(|counts| counts.into_iter().try_fold(0_u64, u64::checked_add))
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), DeletionError> {
        self.tombstone.validate(now)?;
        if self.remote_object_revision
            != self
                .tombstone
                .prior_object_revision
                .checked_add(1)
                .ok_or(DeletionError::RevisionOverflow)?
            || self.surfaces.keys().copied().collect::<BTreeSet<_>>()
                != self.tombstone.required_surfaces
            || self.revision == 0
            || self.created_at < self.tombstone.requested_at
            || self.updated_at < self.created_at
            || self.updated_at > now
        {
            return Err(DeletionError::InvalidDeletionRecord);
        }
        for state in self.surfaces.values() {
            state.validate()?;
            if state.updated_at < self.created_at || state.updated_at > self.updated_at {
                return Err(DeletionError::InvalidPropagationState);
            }
        }
        Ok(())
    }
}

fn set_applied(
    surfaces: &mut BTreeMap<DeletionSurface, DeletionSurfaceState>,
    surface: DeletionSurface,
    evidence_digest: String,
    now: DateTime<Utc>,
) -> Result<(), DeletionError> {
    set_applied_with_counts(surfaces, surface, evidence_digest, 0, 0, 0, now)
}

fn set_applied_with_counts(
    surfaces: &mut BTreeMap<DeletionSurface, DeletionSurfaceState>,
    surface: DeletionSurface,
    evidence_digest: String,
    matched_items: u64,
    deleted_items: u64,
    residual_items: u64,
    now: DateTime<Utc>,
) -> Result<(), DeletionError> {
    if !is_sha256(&evidence_digest) {
        return Err(DeletionError::InvalidPropagationState);
    }
    if deleted_items > matched_items
        || deleted_items
            .checked_add(residual_items)
            .is_none_or(|total| total != matched_items)
    {
        return Err(DeletionError::InvalidPropagationState);
    }
    surfaces.insert(
        surface,
        DeletionSurfaceState {
            status: DeletionPropagationStatus::Applied,
            evidence_digest: Some(evidence_digest),
            error_code: None,
            matched_items,
            deleted_items,
            residual_items: Some(residual_items),
            updated_at: now,
        },
    );
    Ok(())
}

fn set_not_applicable(
    surfaces: &mut BTreeMap<DeletionSurface, DeletionSurfaceState>,
    surface: DeletionSurface,
    evidence_digest: String,
    now: DateTime<Utc>,
) -> Result<(), DeletionError> {
    if !is_sha256(&evidence_digest) {
        return Err(DeletionError::InvalidPropagationState);
    }
    surfaces.insert(
        surface,
        DeletionSurfaceState {
            status: DeletionPropagationStatus::NotApplicable,
            evidence_digest: Some(evidence_digest),
            error_code: None,
            matched_items: 0,
            deleted_items: 0,
            residual_items: Some(0),
            updated_at: now,
        },
    );
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DeletionError {
    #[error("deletion tombstone scope, authorization, generation, or digest is invalid")]
    InvalidTombstone,
    #[error("deletion surface status, evidence, or error shape is invalid")]
    InvalidPropagationState,
    #[error("deletion surface cannot be rewritten after a terminal propagation result")]
    InvalidPropagationTransition,
    #[error("deletion record revision or propagation coverage is invalid")]
    InvalidDeletionRecord,
    #[error("deletion propagation receipt is not an exact, independently verified empty scan")]
    InvalidPropagationReceipt,
    #[error("deletion revision overflow")]
    RevisionOverflow,
    #[error("deletion digest could not be serialized")]
    Serialization,
}

fn digest_json(value: &impl Serialize) -> Result<String, DeletionError> {
    let bytes = serde_json::to_vec(value).map_err(|_| DeletionError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 15, 0, 0)
            .single()
            .expect("valid time")
    }

    fn tombstone() -> DeletionTombstone {
        DeletionTombstone::create(
            DeletionId::from("deletion-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "capsule-1",
            "context_capsule",
            4,
            1,
            DeletionReason::UserRequest,
            ActorId::from("user-1"),
            "1".repeat(64),
            now(),
        )
        .expect("tombstone")
    }

    #[test]
    fn deletion_requires_every_surface_and_exact_authority_digest() {
        let mut tombstone = tombstone();
        tombstone.required_surfaces.remove(&DeletionSurface::Replay);
        assert_eq!(
            tombstone.validate(now()),
            Err(DeletionError::InvalidTombstone)
        );
    }

    #[test]
    fn propagation_is_monotonic_and_never_claims_pending_work_complete() {
        let record = DeletionRecord::pending(
            tombstone(),
            5,
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            now(),
        )
        .expect("record");
        assert!(!record.is_complete());
        let cell = record
            .mark_encrypted_cell_applied("5".repeat(64), now() + Duration::minutes(1))
            .expect("cell applied");
        assert_eq!(cell.revision, 2);
        assert!(!cell.is_complete());
        assert_eq!(
            cell.mark_encrypted_cell_applied("6".repeat(64), now() + Duration::minutes(2)),
            Err(DeletionError::InvalidPropagationTransition)
        );
    }

    #[test]
    fn propagation_receipt_requires_exact_scope_and_zero_residual() {
        let tombstone = tombstone();
        let receipt = DeletionPropagationReceipt::create(
            DeletionReceiptId::from("deletion-receipt-cache-1"),
            &tombstone,
            DeletionSurface::Cache,
            WorkerId::from("cache-cleaner-1"),
            1,
            "6".repeat(64),
            2,
            2,
            0,
            "7".repeat(64),
            now() + Duration::minutes(1),
        )
        .expect("exact receipt");
        let record = DeletionRecord::pending(
            tombstone.clone(),
            5,
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            now(),
        )
        .expect("record")
        .apply_receipt(&receipt, now() + Duration::minutes(1))
        .expect("apply exact receipt");
        assert_eq!(
            record.surfaces[&DeletionSurface::Cache].evidence_digest,
            Some(receipt.receipt_digest.clone())
        );

        let mut cross_project = receipt.clone();
        cross_project.project_id = ProjectId::from("project-2");
        cross_project.receipt_digest = cross_project.compute_digest().expect("tampered digest");
        assert_eq!(
            cross_project.validate_for(&tombstone, now() + Duration::minutes(1)),
            Err(DeletionError::InvalidPropagationReceipt)
        );

        assert_eq!(
            DeletionPropagationReceipt::create(
                DeletionReceiptId::from("deletion-receipt-cache-residual"),
                &tombstone,
                DeletionSurface::Cache,
                WorkerId::from("cache-cleaner-1"),
                1,
                "6".repeat(64),
                2,
                1,
                1,
                "7".repeat(64),
                now() + Duration::minutes(1),
            ),
            Err(DeletionError::InvalidPropagationReceipt)
        );
    }

    #[test]
    fn retryable_and_dead_letter_surface_states_remain_incomplete() {
        let record = DeletionRecord::pending(
            tombstone(),
            5,
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            now(),
        )
        .expect("record");
        let failed = record
            .mark_surface_failed(
                DeletionSurface::Cache,
                "CACHE_TEMPORARILY_UNAVAILABLE",
                Some(2),
                now() + Duration::minutes(1),
            )
            .expect("retryable failure");
        assert_eq!(failed.status(), DeletionRequestStatus::PartiallyApplied);
        assert_eq!(
            failed.surfaces[&DeletionSurface::Cache].residual_items,
            Some(2)
        );
        assert_eq!(failed.surfaces[&DeletionSurface::Cache].matched_items, 0);
        assert_eq!(failed.surfaces[&DeletionSurface::Cache].deleted_items, 0);
        assert!(!failed.is_complete());

        let dead_lettered = failed
            .mark_surface_dead_letter(
                DeletionSurface::Replay,
                "REPLAY_STORE_UNAVAILABLE",
                None,
                now() + Duration::minutes(2),
            )
            .expect("dead letter");
        assert_eq!(dead_lettered.status(), DeletionRequestStatus::DeadLettered);
        assert!(!dead_lettered.is_complete());

        let blocked = record
            .mark_surface_blocked(
                DeletionSurface::Cache,
                "LEGAL_HOLD_ACTIVE",
                Some(1),
                now() + Duration::minutes(3),
            )
            .expect("retention block");
        assert_eq!(blocked.status(), DeletionRequestStatus::Blocked);
        assert_eq!(
            blocked.surfaces[&DeletionSurface::Cache].residual_items,
            Some(1)
        );
        assert!(!blocked.is_complete());
    }
}

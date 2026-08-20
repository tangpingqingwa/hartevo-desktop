//! Project-scoped encrypted region transfer and recovery receipts.
//!
//! This module is deliberately narrower than sync and Worker execution.  It
//! records an opaque encrypted Mission snapshot together with the exact
//! service/provider/consumer identity that prepared it.  A target Cell can
//! adopt only that immutable, verified request.  No plaintext, key material,
//! Effect authority, or Worker authority is represented here.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{MissionId, ProjectEncryptionMode, ProjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Row, Transaction};

use super::{
    CloudStorageError, DataCell, EncryptedPayload, PostgresCellStore, RevisionWrite,
    SyncObjectKind, append_encrypted_event, append_encrypted_outbox, canonical_digest,
    decode_encryption_mode, ensure_database_cell, from_sql_u64, is_sha256, lock_project,
    record_sync_mutation, set_scope,
};

pub const REGION_TRANSFER_SERVICE_ID: &str = "hartevo.cloud.region-transfer";
pub const REGION_TRANSFER_SERVICE_VERSION: u64 = 1;

const MAX_TRANSFER_ID_BYTES: usize = 256;
const MAX_REPLAY_NONCE_BYTES: usize = 256;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionTransferServiceDefinition {
    pub service_id: String,
    pub version: u64,
    pub contract_digest: String,
}

impl RegionTransferServiceDefinition {
    pub fn current() -> Self {
        Self {
            service_id: REGION_TRANSFER_SERVICE_ID.into(),
            version: REGION_TRANSFER_SERVICE_VERSION,
            contract_digest: transfer_digest(b"hartevo.cloud.region-transfer:v1"),
        }
    }

    fn validate(&self) -> Result<(), CloudStorageError> {
        let expected = Self::current();
        if self != &expected {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionTransferProvider {
    pub provider_id: String,
    pub region: DataCell,
    pub version: u64,
    pub implementation_digest: String,
    pub current_commit_digest: String,
}

impl RegionTransferProvider {
    #[must_use]
    pub fn new(
        provider_id: impl Into<String>,
        region: DataCell,
        version: u64,
        implementation_digest: impl Into<String>,
        current_commit_digest: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            region,
            version,
            implementation_digest: implementation_digest.into(),
            current_commit_digest: current_commit_digest.into(),
        }
    }

    fn validate(&self, source_cell: DataCell) -> Result<(), CloudStorageError> {
        if self.provider_id.trim().is_empty()
            || self.provider_id.len() > MAX_TRANSFER_ID_BYTES
            || self.region != source_cell
            || self.version != REGION_TRANSFER_SERVICE_VERSION
            || !is_sha256(&self.implementation_digest)
            || !is_sha256(&self.current_commit_digest)
        {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        Ok(())
    }

    pub async fn prepare(
        &self,
        store: &PostgresCellStore,
        client: &mut Client,
        request: &EncryptedRegionTransferRequest,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        if &request.provider != self {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        store.prepare_region_transfer(client, request).await
    }

    pub async fn revoke(
        &self,
        store: &PostgresCellStore,
        client: &mut Client,
        scope: &super::CellScope,
        receipt: &RegionTransferReceipt,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        if receipt.request.provider != *self {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        store
            .transition_region_transfer(
                client,
                scope,
                receipt,
                RegionTransferStatus::Revoked,
                None,
                now,
            )
            .await
    }

    pub async fn abort_after_crash(
        &self,
        store: &PostgresCellStore,
        client: &mut Client,
        scope: &super::CellScope,
        receipt: &RegionTransferReceipt,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        if receipt.request.provider != *self {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        store
            .transition_region_transfer(
                client,
                scope,
                receipt,
                RegionTransferStatus::Crashed,
                None,
                now,
            )
            .await
    }

    pub async fn acknowledge_adoption(
        &self,
        store: &PostgresCellStore,
        client: &mut Client,
        source_scope: &super::CellScope,
        source_receipt: &RegionTransferReceipt,
        target_receipt: &RegionTransferReceipt,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        if source_receipt.request.provider != *self
            || target_receipt.status != RegionTransferStatus::Adopted
            || target_receipt.request_digest != source_receipt.request_digest
            || target_receipt.request.consumer.region != target_receipt.request.target_cell
        {
            return Err(CloudStorageError::RegionTransferReceiptTampered);
        }
        target_receipt.verify()?;
        store
            .transition_region_transfer(
                client,
                source_scope,
                source_receipt,
                RegionTransferStatus::Adopted,
                Some(source_receipt.request.mission_revision),
                now,
            )
            .await
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionTransferConsumer {
    pub consumer_id: String,
    pub region: DataCell,
    pub version: u64,
    pub consumer_digest: String,
    pub trusted_provider_id: String,
    pub trusted_provider_digest: String,
    pub current_commit_digest: String,
}

impl RegionTransferConsumer {
    #[must_use]
    pub fn new(
        consumer_id: impl Into<String>,
        region: DataCell,
        version: u64,
        consumer_digest: impl Into<String>,
        trusted_provider_id: impl Into<String>,
        trusted_provider_digest: impl Into<String>,
        current_commit_digest: impl Into<String>,
    ) -> Self {
        Self {
            consumer_id: consumer_id.into(),
            region,
            version,
            consumer_digest: consumer_digest.into(),
            trusted_provider_id: trusted_provider_id.into(),
            trusted_provider_digest: trusted_provider_digest.into(),
            current_commit_digest: current_commit_digest.into(),
        }
    }

    fn validate(&self, target_cell: DataCell) -> Result<(), CloudStorageError> {
        if self.consumer_id.trim().is_empty()
            || self.consumer_id.len() > MAX_TRANSFER_ID_BYTES
            || self.region != target_cell
            || self.version != REGION_TRANSFER_SERVICE_VERSION
            || !is_sha256(&self.consumer_digest)
            || self.trusted_provider_id.trim().is_empty()
            || self.trusted_provider_id.len() > MAX_TRANSFER_ID_BYTES
            || !is_sha256(&self.trusted_provider_digest)
            || !is_sha256(&self.current_commit_digest)
        {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        Ok(())
    }

    pub fn verify_receipt(&self, receipt: &RegionTransferReceipt) -> Result<(), CloudStorageError> {
        receipt.verify()?;
        if receipt.status != RegionTransferStatus::Prepared {
            return match receipt.status {
                RegionTransferStatus::Revoked => Err(CloudStorageError::RegionTransferRevoked),
                RegionTransferStatus::Crashed => Err(CloudStorageError::RegionTransferCrashed),
                RegionTransferStatus::Adopted => {
                    Err(CloudStorageError::RegionTransferAlreadyTerminal)
                }
                RegionTransferStatus::Prepared => unreachable!(),
            };
        }
        if receipt.request.consumer != *self
            || receipt.request.target_cell != self.region
            || receipt.request.provider.provider_id != self.trusted_provider_id
            || receipt.request.provider.implementation_digest != self.trusted_provider_digest
            || receipt.request.current_commit_digest != self.current_commit_digest
        {
            return Err(CloudStorageError::RegionTransferReceiptTampered);
        }
        Ok(())
    }

    pub async fn adopt(
        &self,
        store: &PostgresCellStore,
        client: &mut Client,
        target_scope: &super::CellScope,
        receipt: &RegionTransferReceipt,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        self.verify_receipt(receipt)?;
        store
            .adopt_region_transfer(client, target_scope, receipt, now)
            .await
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionTransferStatus {
    Prepared,
    Adopted,
    Revoked,
    Crashed,
}

impl RegionTransferStatus {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Adopted => "adopted",
            Self::Revoked => "revoked",
            Self::Crashed => "crashed",
        }
    }

    fn decode(value: &str) -> Result<Self, CloudStorageError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "adopted" => Ok(Self::Adopted),
            "revoked" => Ok(Self::Revoked),
            "crashed" => Ok(Self::Crashed),
            other => Err(CloudStorageError::StoredValueInvalid(format!(
                "region transfer status {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedRegionTransferRequest {
    pub transfer_id: String,
    pub source_scope: super::CellScope,
    pub target_cell: DataCell,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub project_revision: u64,
    pub project_metadata_digest: String,
    pub project_encryption_mode: ProjectEncryptionMode,
    pub mission_revision: u64,
    pub key_generation: u64,
    pub source_mission_content_digest: String,
    pub encrypted_bundle_root: String,
    pub encrypted_bundle: EncryptedPayload,
    pub service: RegionTransferServiceDefinition,
    pub provider: RegionTransferProvider,
    pub consumer: RegionTransferConsumer,
    pub sequence: u64,
    pub replay_nonce: String,
    pub idempotency_key_digest: String,
    pub current_commit_digest: String,
    pub requested_at: DateTime<Utc>,
}

impl EncryptedRegionTransferRequest {
    fn validate(&self) -> Result<(), CloudStorageError> {
        if self.transfer_id.trim().is_empty()
            || self.transfer_id.len() > MAX_TRANSFER_ID_BYTES
            || self.source_scope.tenant_id.as_str().trim().is_empty()
            || self.source_scope.cell == self.target_cell
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.project_revision == 0
            || self.mission_revision == 0
            || self.key_generation == 0
            || self.sequence == 0
            || self.replay_nonce.trim().is_empty()
            || self.replay_nonce.len() > MAX_REPLAY_NONCE_BYTES
            || !is_sha256(&self.project_metadata_digest)
            || !is_sha256(&self.source_mission_content_digest)
            || !is_sha256(&self.encrypted_bundle_root)
            || !is_sha256(&self.idempotency_key_digest)
            || !is_sha256(&self.current_commit_digest)
            || self.encrypted_bundle.key_version != self.key_generation
            || self.encrypted_bundle.content_digest != self.encrypted_bundle_root
            || self.encrypted_bundle.content_digest != self.source_mission_content_digest
        {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        self.encrypted_bundle.validate()?;
        self.service.validate()?;
        self.provider.validate(self.source_scope.cell)?;
        self.consumer.validate(self.target_cell)?;
        if self.provider.current_commit_digest != self.current_commit_digest
            || self.consumer.current_commit_digest != self.current_commit_digest
            || self.consumer.trusted_provider_id != self.provider.provider_id
            || self.consumer.trusted_provider_digest != self.provider.implementation_digest
        {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        Ok(())
    }

    fn validate_source(&self, source_cell: DataCell) -> Result<(), CloudStorageError> {
        self.validate()?;
        self.source_scope.validate(source_cell)
    }

    fn validate_target(&self, target_scope: &super::CellScope) -> Result<(), CloudStorageError> {
        self.validate()?;
        if target_scope.cell != self.target_cell
            || target_scope.tenant_id != self.source_scope.tenant_id
        {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        Ok(())
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::to_value(self)?)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionTransferReceipt {
    pub request: EncryptedRegionTransferRequest,
    pub request_digest: String,
    pub status: RegionTransferStatus,
    pub adopted_revision: Option<u64>,
    pub receipt_digest: String,
}

impl RegionTransferReceipt {
    fn new(
        request: EncryptedRegionTransferRequest,
        status: RegionTransferStatus,
        adopted_revision: Option<u64>,
    ) -> Result<Self, CloudStorageError> {
        let request_digest = request.request_digest()?;
        let receipt_digest = receipt_digest(&request_digest, &status, adopted_revision)?;
        Ok(Self {
            request,
            request_digest,
            status,
            adopted_revision,
            receipt_digest,
        })
    }

    pub fn verify(&self) -> Result<(), CloudStorageError> {
        self.request
            .validate()
            .map_err(|_| CloudStorageError::RegionTransferReceiptTampered)?;
        let request_digest = self
            .request
            .request_digest()
            .map_err(|_| CloudStorageError::RegionTransferReceiptTampered)?;
        if request_digest != self.request_digest
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.receipt_digest)
        {
            return Err(CloudStorageError::RegionTransferReceiptTampered);
        }
        let expected = receipt_digest(&self.request_digest, &self.status, self.adopted_revision)
            .map_err(|_| CloudStorageError::RegionTransferReceiptTampered)?;
        if expected != self.receipt_digest
            || (self.status == RegionTransferStatus::Adopted
                && self.adopted_revision != Some(self.request.mission_revision))
            || (self.status != RegionTransferStatus::Adopted && self.adopted_revision.is_some())
        {
            return Err(CloudStorageError::RegionTransferReceiptTampered);
        }
        Ok(())
    }
}

impl PostgresCellStore {
    pub async fn prepare_region_transfer(
        &self,
        client: &mut Client,
        request: &EncryptedRegionTransferRequest,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        request.validate_source(self.cell)?;
        let request_digest = request.request_digest()?;
        let request_json = serde_json::to_value(request)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &request.source_scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        lock_project(&transaction, &request.source_scope, &request.project_id).await?;
        ensure_project_source_matches(&transaction, request).await?;
        ensure_source_mission_head(&transaction, request).await?;

        if let Some(row) =
            load_transfer_row_by_id(&transaction, &request.source_scope, request).await?
        {
            let existing = decode_transfer_row(&row, &request.source_scope)?;
            if existing.request_digest != request_digest {
                return Err(CloudStorageError::IdempotencyConflict);
            }
            transaction.commit().await?;
            return Ok(existing);
        }
        if let Some(row) =
            load_transfer_row_by_idempotency(&transaction, &request.source_scope, request).await?
        {
            let existing = decode_transfer_row(&row, &request.source_scope)?;
            if existing.request_digest != request_digest {
                return Err(CloudStorageError::IdempotencyConflict);
            }
            transaction.commit().await?;
            return Ok(existing);
        }

        let receipt =
            RegionTransferReceipt::new(request.clone(), RegionTransferStatus::Prepared, None)?;
        insert_transfer_receipt(
            &transaction,
            &request.source_scope,
            &receipt,
            request_json,
            request.requested_at,
        )
        .await?;
        append_transfer_event(
            &transaction,
            &request.source_scope,
            &receipt,
            "region_transfer.prepared",
            request.requested_at,
        )
        .await?;
        transaction.commit().await?;
        Ok(receipt)
    }

    pub async fn load_region_transfer_receipt(
        &self,
        client: &mut Client,
        scope: &super::CellScope,
        project_id: &ProjectId,
        transfer_id: &str,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        if project_id.as_str().trim().is_empty()
            || transfer_id.trim().is_empty()
            || transfer_id.len() > MAX_TRANSFER_ID_BYTES
        {
            return Err(CloudStorageError::RegionTransferNotFound);
        }
        scope.validate(self.cell)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let Some(row) = transaction
            .query_opt(
                "SELECT transfer_id, project_id, mission_id, source_cell, target_cell,
                        request_json, request_digest, idempotency_key_digest, status,
                        adopted_revision, receipt_digest
                 FROM hartevo_cell.region_transfer_receipts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND transfer_id = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &transfer_id,
                ],
            )
            .await?
        else {
            transaction.commit().await?;
            return Err(CloudStorageError::RegionTransferNotFound);
        };
        let receipt = decode_transfer_row(&row, scope)?;
        transaction.commit().await?;
        Ok(receipt)
    }

    pub async fn adopt_region_transfer(
        &self,
        client: &mut Client,
        target_scope: &super::CellScope,
        source_receipt: &RegionTransferReceipt,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        source_receipt.verify()?;
        source_receipt.request.validate_target(target_scope)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, target_scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        lock_project(
            &transaction,
            target_scope,
            &source_receipt.request.project_id,
        )
        .await?;
        if let Some(row) =
            load_transfer_row_by_id(&transaction, target_scope, &source_receipt.request).await?
        {
            let existing = decode_transfer_row(&row, target_scope)?;
            if existing.request_digest != source_receipt.request_digest {
                return Err(CloudStorageError::RegionTransferReceiptTampered);
            }
            if existing.status == RegionTransferStatus::Adopted {
                transaction.commit().await?;
                return Ok(existing);
            }
            return Err(status_error(&existing.status));
        }

        ensure_target_project_matches(&transaction, target_scope, &source_receipt.request).await?;
        if transaction
            .query_opt(
                "SELECT 1 FROM hartevo_cell.sync_object_heads
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND object_id = $4
                 FOR UPDATE",
                &[
                    &target_scope.cell.as_str(),
                    &target_scope.tenant_id.as_str(),
                    &source_receipt.request.project_id.as_str(),
                    &source_receipt.request.mission_id.as_str(),
                ],
            )
            .await?
            .is_some()
        {
            return Err(CloudStorageError::RegionTransferTargetConflict);
        }

        persist_region_transfer_snapshot(&transaction, target_scope, source_receipt, now).await?;
        let request_json = serde_json::to_value(&source_receipt.request)?;
        let adopted = RegionTransferReceipt::new(
            source_receipt.request.clone(),
            RegionTransferStatus::Adopted,
            Some(source_receipt.request.mission_revision),
        )?;
        insert_transfer_receipt(&transaction, target_scope, &adopted, request_json, now).await?;
        append_transfer_event(
            &transaction,
            target_scope,
            &adopted,
            "region_transfer.adopted",
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(adopted)
    }

    async fn transition_region_transfer(
        &self,
        client: &mut Client,
        scope: &super::CellScope,
        receipt: &RegionTransferReceipt,
        next_status: RegionTransferStatus,
        adopted_revision: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferReceipt, CloudStorageError> {
        receipt.verify()?;
        scope.validate(self.cell)?;
        if receipt.request.source_scope != *scope {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let row = load_transfer_row_by_id(&transaction, scope, &receipt.request)
            .await?
            .ok_or(CloudStorageError::RegionTransferNotFound)?;
        let existing = decode_transfer_row(&row, scope)?;
        if existing.request_digest != receipt.request_digest
            || existing.receipt_digest != receipt.receipt_digest
        {
            return Err(CloudStorageError::RegionTransferReceiptTampered);
        }
        if existing.status != RegionTransferStatus::Prepared {
            if existing.status == next_status {
                transaction.commit().await?;
                return Ok(existing);
            }
            return Err(status_error(&existing.status));
        }
        let event_type = match next_status {
            RegionTransferStatus::Adopted => "region_transfer.adopted",
            RegionTransferStatus::Revoked => "region_transfer.revoked",
            RegionTransferStatus::Crashed => "region_transfer.crashed",
            RegionTransferStatus::Prepared => "region_transfer.prepared",
        };
        let adopted_revision_sql = adopted_revision.map(super::to_sql_u64).transpose()?;
        let transitioned =
            RegionTransferReceipt::new(receipt.request.clone(), next_status, adopted_revision)?;
        transaction
            .execute(
                "UPDATE hartevo_cell.region_transfer_receipts
                 SET status = $5, adopted_revision = $6, receipt_digest = $7, updated_at = $8
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND transfer_id = $4
                   AND status = 'prepared' AND receipt_digest = $9",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &receipt.request.project_id.as_str(),
                    &receipt.request.transfer_id,
                    &transitioned.status.as_str(),
                    &adopted_revision_sql,
                    &transitioned.receipt_digest,
                    &now,
                    &receipt.receipt_digest,
                ],
            )
            .await?
            .eq(&1)
            .then_some(())
            .ok_or(CloudStorageError::RegionTransferAlreadyTerminal)?;
        append_transfer_event(&transaction, scope, &transitioned, event_type, now).await?;
        transaction.commit().await?;
        Ok(transitioned)
    }
}

async fn ensure_project_source_matches(
    transaction: &Transaction<'_>,
    request: &EncryptedRegionTransferRequest,
) -> Result<(), CloudStorageError> {
    let Some(row) = transaction
        .query_opt(
            "SELECT revision, metadata_digest, encryption_mode
             FROM hartevo_cell.projects
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &request.source_scope.cell.as_str(),
                &request.source_scope.tenant_id.as_str(),
                &request.project_id.as_str(),
            ],
        )
        .await?
    else {
        return Err(CloudStorageError::ProjectNotFound);
    };
    if from_sql_u64(row.get(0), "region transfer project revision")? != request.project_revision
        || row.get::<_, String>(1) != request.project_metadata_digest
        || decode_encryption_mode(&row.get::<_, String>(2))? != request.project_encryption_mode
    {
        return Err(CloudStorageError::InvalidRegionTransfer);
    }
    Ok(())
}

async fn ensure_target_project_matches(
    transaction: &Transaction<'_>,
    target_scope: &super::CellScope,
    request: &EncryptedRegionTransferRequest,
) -> Result<(), CloudStorageError> {
    let Some(row) = transaction
        .query_opt(
            "SELECT revision, metadata_digest, encryption_mode
             FROM hartevo_cell.projects
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &target_scope.cell.as_str(),
                &target_scope.tenant_id.as_str(),
                &request.project_id.as_str(),
            ],
        )
        .await?
    else {
        return Err(CloudStorageError::ProjectNotFound);
    };
    if from_sql_u64(row.get(0), "region transfer target project revision")?
        != request.project_revision
        || row.get::<_, String>(1) != request.project_metadata_digest
        || decode_encryption_mode(&row.get::<_, String>(2))? != request.project_encryption_mode
    {
        return Err(CloudStorageError::RegionTransferTargetConflict);
    }
    Ok(())
}

async fn ensure_source_mission_head(
    transaction: &Transaction<'_>,
    request: &EncryptedRegionTransferRequest,
) -> Result<(), CloudStorageError> {
    let Some(row) = transaction
        .query_opt(
            "SELECT current_revision, key_version, content_digest, object_kind, tombstone
             FROM hartevo_cell.sync_object_heads
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND object_id = $4
             FOR UPDATE",
            &[
                &request.source_scope.cell.as_str(),
                &request.source_scope.tenant_id.as_str(),
                &request.project_id.as_str(),
                &request.mission_id.as_str(),
            ],
        )
        .await?
    else {
        return Err(CloudStorageError::RegionTransferSourceHeadNotFound);
    };
    if row.get::<_, String>(3) != SyncObjectKind::Mission.as_str()
        || row.get::<_, bool>(4)
        || from_sql_u64(row.get(0), "region transfer mission revision")? != request.mission_revision
        || from_sql_u64(row.get(1), "region transfer key generation")? != request.key_generation
        || row.get::<_, String>(2) != request.source_mission_content_digest
    {
        return Err(CloudStorageError::InvalidRegionTransfer);
    }
    Ok(())
}

fn transfer_row_sql(predicate: &str) -> String {
    format!(
        "SELECT transfer_id, project_id, mission_id, source_cell, target_cell,
                request_json, request_digest, idempotency_key_digest, status,
                adopted_revision, receipt_digest
         FROM hartevo_cell.region_transfer_receipts
         WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND {predicate}"
    )
}

async fn load_transfer_row_by_id(
    transaction: &Transaction<'_>,
    scope: &super::CellScope,
    request: &EncryptedRegionTransferRequest,
) -> Result<Option<Row>, CloudStorageError> {
    Ok(transaction
        .query_opt(
            &transfer_row_sql("transfer_id = $4"),
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &request.project_id.as_str(),
                &request.transfer_id,
            ],
        )
        .await?)
}

async fn load_transfer_row_by_idempotency(
    transaction: &Transaction<'_>,
    scope: &super::CellScope,
    request: &EncryptedRegionTransferRequest,
) -> Result<Option<Row>, CloudStorageError> {
    Ok(transaction
        .query_opt(
            &transfer_row_sql("idempotency_key_digest = $4"),
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &request.project_id.as_str(),
                &request.idempotency_key_digest,
            ],
        )
        .await?)
}

fn decode_transfer_row(
    row: &Row,
    scope: &super::CellScope,
) -> Result<RegionTransferReceipt, CloudStorageError> {
    let request: EncryptedRegionTransferRequest = serde_json::from_value(row.get(5))?;
    request.validate()?;
    if request.transfer_id != row.get::<_, String>(0)
        || request.project_id.as_str() != row.get::<_, String>(1)
        || request.mission_id.as_str() != row.get::<_, String>(2)
        || request.source_scope.tenant_id != scope.tenant_id
        || row.get::<_, String>(4) != request.target_cell.as_str()
        || row.get::<_, String>(3) != request.source_scope.cell.as_str()
        || request.idempotency_key_digest != row.get::<_, String>(7)
    {
        return Err(CloudStorageError::RegionTransferReceiptTampered);
    }
    let request_digest: String = row.get(6);
    if request.request_digest()? != request_digest {
        return Err(CloudStorageError::RegionTransferReceiptTampered);
    }
    let status = RegionTransferStatus::decode(&row.get::<_, String>(8))?;
    let adopted_revision = row
        .get::<_, Option<i64>>(9)
        .map(|value| from_sql_u64(value, "region transfer adopted revision"))
        .transpose()?;
    let receipt_digest: String = row.get(10);
    let receipt = RegionTransferReceipt {
        request,
        request_digest,
        status,
        adopted_revision,
        receipt_digest,
    };
    receipt.verify()?;
    Ok(receipt)
}

async fn insert_transfer_receipt(
    transaction: &Transaction<'_>,
    scope: &super::CellScope,
    receipt: &RegionTransferReceipt,
    request_json: serde_json::Value,
    recorded_at: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    let adopted_revision = receipt
        .adopted_revision
        .map(super::to_sql_u64)
        .transpose()?;
    transaction
        .execute(
            "INSERT INTO hartevo_cell.region_transfer_receipts
               (cell, tenant_id, project_id, transfer_id, mission_id, source_cell,
                target_cell, request_json, request_digest, idempotency_key_digest,
                status, adopted_revision, receipt_digest, recorded_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &receipt.request.project_id.as_str(),
                &receipt.request.transfer_id,
                &receipt.request.mission_id.as_str(),
                &receipt.request.source_scope.cell.as_str(),
                &receipt.request.target_cell.as_str(),
                &request_json,
                &receipt.request_digest,
                &receipt.request.idempotency_key_digest,
                &receipt.status.as_str(),
                &adopted_revision,
                &receipt.receipt_digest,
                &recorded_at,
            ],
        )
        .await?;
    Ok(())
}

async fn append_transfer_event(
    transaction: &Transaction<'_>,
    scope: &super::CellScope,
    receipt: &RegionTransferReceipt,
    event_type: &str,
    observed_at: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    transaction
        .execute(
            "INSERT INTO hartevo_cell.region_transfer_events
               (cell, tenant_id, project_id, transfer_id, status, event_type,
                request_digest, receipt_digest, observed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &receipt.request.project_id.as_str(),
                &receipt.request.transfer_id,
                &receipt.status.as_str(),
                &event_type,
                &receipt.request_digest,
                &receipt.receipt_digest,
                &observed_at,
            ],
        )
        .await?;
    Ok(())
}

async fn persist_region_transfer_snapshot(
    transaction: &Transaction<'_>,
    target_scope: &super::CellScope,
    receipt: &RegionTransferReceipt,
    now: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    let request = &receipt.request;
    let revision = super::to_sql_u64(request.mission_revision)?;
    let key_version = super::to_sql_u64(request.key_generation)?;
    transaction
        .execute(
            "INSERT INTO hartevo_cell.sync_object_versions
               (cell, tenant_id, project_id, object_id, object_kind, revision,
                key_version, nonce, ciphertext, aad_digest, content_digest,
                tombstone, recorded_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, FALSE, $12)",
            &[
                &target_scope.cell.as_str(),
                &target_scope.tenant_id.as_str(),
                &request.project_id.as_str(),
                &request.mission_id.as_str(),
                &SyncObjectKind::Mission.as_str(),
                &revision,
                &key_version,
                &request.encrypted_bundle.nonce,
                &request.encrypted_bundle.ciphertext,
                &request.encrypted_bundle.aad_digest,
                &request.encrypted_bundle.content_digest,
                &now,
            ],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO hartevo_cell.sync_object_heads
               (cell, tenant_id, project_id, object_id, object_kind, current_revision,
                key_version, content_digest, tombstone, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, $9)",
            &[
                &target_scope.cell.as_str(),
                &target_scope.tenant_id.as_str(),
                &request.project_id.as_str(),
                &request.mission_id.as_str(),
                &SyncObjectKind::Mission.as_str(),
                &revision,
                &key_version,
                &request.encrypted_bundle.content_digest,
                &now,
            ],
        )
        .await?;
    let write = RevisionWrite {
        scope: target_scope,
        project_id: &request.project_id,
        object_id: request.mission_id.as_str(),
        object_kind: SyncObjectKind::Mission,
        revision: request.mission_revision,
        payload: &request.encrypted_bundle,
        tombstone: false,
        idempotency_key_digest: &request.idempotency_key_digest,
        request_digest: &receipt.request_digest,
        recorded_at: now,
        event_type: "sync.region_transfer.adopted",
    };
    let event_sequence = append_encrypted_event(transaction, &write).await?;
    let outbox_sequence = append_encrypted_outbox(transaction, &write, event_sequence).await?;
    record_sync_mutation(transaction, &write, event_sequence, outbox_sequence).await?;
    Ok(())
}

fn receipt_digest(
    request_digest: &str,
    status: &RegionTransferStatus,
    adopted_revision: Option<u64>,
) -> Result<String, CloudStorageError> {
    canonical_digest(&serde_json::json!({
        "requestDigest": request_digest,
        "status": status,
        "adoptedRevision": adopted_revision,
    }))
}

fn status_error(status: &RegionTransferStatus) -> CloudStorageError {
    match status {
        RegionTransferStatus::Revoked => CloudStorageError::RegionTransferRevoked,
        RegionTransferStatus::Crashed => CloudStorageError::RegionTransferCrashed,
        RegionTransferStatus::Adopted | RegionTransferStatus::Prepared => {
            CloudStorageError::RegionTransferAlreadyTerminal
        }
    }
}

fn transfer_digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use hartevo_domain_kernel::{MissionId, ProjectEncryptionMode, ProjectId, TenantId};
    use sha2::Digest;

    use super::{
        EncryptedPayload, EncryptedRegionTransferRequest, RegionTransferConsumer,
        RegionTransferProvider, RegionTransferReceipt, RegionTransferServiceDefinition,
        RegionTransferStatus,
    };
    use crate::{CellScope, DataCell};

    fn digest(value: &str) -> String {
        super::transfer_digest(value.as_bytes())
    }

    fn request() -> EncryptedRegionTransferRequest {
        let commit = digest("commit");
        let ciphertext = vec![7; 48];
        let bundle = EncryptedPayload {
            key_version: 3,
            nonce: vec![9; 12],
            ciphertext: ciphertext.clone(),
            aad_digest: digest("aad"),
            content_digest: format!("{:x}", sha2::Sha256::digest(ciphertext)),
        };
        EncryptedRegionTransferRequest {
            transfer_id: "transfer-1".into(),
            source_scope: CellScope {
                cell: DataCell::Us,
                tenant_id: TenantId::from("tenant-1"),
            },
            target_cell: DataCell::Eu,
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-1"),
            project_revision: 1,
            project_metadata_digest: digest("metadata"),
            project_encryption_mode: ProjectEncryptionMode::TeamEnvelope,
            mission_revision: 4,
            key_generation: 3,
            source_mission_content_digest: bundle.content_digest.clone(),
            encrypted_bundle_root: bundle.content_digest.clone(),
            encrypted_bundle: bundle,
            service: RegionTransferServiceDefinition::current(),
            provider: RegionTransferProvider::new(
                "source-cell-provider",
                DataCell::Us,
                1,
                digest("provider"),
                commit.clone(),
            ),
            consumer: RegionTransferConsumer::new(
                "target-mission-consumer",
                DataCell::Eu,
                1,
                digest("consumer"),
                "source-cell-provider",
                digest("provider"),
                commit.clone(),
            ),
            sequence: 1,
            replay_nonce: "nonce-1".into(),
            idempotency_key_digest: digest("idempotency"),
            current_commit_digest: commit,
            requested_at: Utc.with_ymd_and_hms(2026, 8, 14, 1, 2, 3).unwrap(),
        }
    }

    #[test]
    fn request_is_exactly_project_mission_and_commit_scoped() {
        let value = request();
        value.validate().expect("valid transfer request");
        let mut cross_cell = value.clone();
        cross_cell.target_cell = DataCell::Us;
        assert!(cross_cell.validate().is_err());
        let mut digest_drift = value;
        digest_drift.current_commit_digest = digest("new-commit");
        assert!(digest_drift.validate().is_err());
    }

    #[test]
    fn receipt_digest_fences_tamper_and_terminal_status() {
        let value = request();
        let receipt = RegionTransferReceipt::new(value, RegionTransferStatus::Prepared, None)
            .expect("receipt");
        receipt.verify().expect("prepared receipt verifies");
        let mut tampered = receipt.clone();
        tampered.request.mission_id = MissionId::from("other-mission");
        assert!(tampered.verify().is_err());

        let adopted =
            RegionTransferReceipt::new(receipt.request, RegionTransferStatus::Adopted, Some(4))
                .expect("adopted receipt");
        adopted.verify().expect("adopted receipt verifies");
        assert!(matches!(
            adopted.request.consumer.verify_receipt(&adopted),
            Err(crate::CloudStorageError::RegionTransferAlreadyTerminal)
        ));
    }
}

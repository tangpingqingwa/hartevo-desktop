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
const REGION_TRANSFER_ACK_GENERATION: u64 = 1;

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

    /// Read and verify the exact target-Cell adoption.  The readback provider
    /// owns only a read-only evidence query plus a durable verification
    /// receipt; it does not expose a Store, Worker, or Effect capability.
    #[allow(
        clippy::too_many_arguments,
        reason = "the typed consumer boundary keeps every scope, generation, and durable receipt input explicit"
    )]
    pub async fn verify_target_adoption(
        &self,
        store: &PostgresCellStore,
        client: &mut Client,
        target_scope: &super::CellScope,
        readback_provider: &RegionTransferReadbackProvider,
        adopted_receipt: &RegionTransferReceipt,
        expected_ack_generation: u64,
        verification_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferVerificationReceipt, CloudStorageError> {
        self.verify_adopted_receipt(adopted_receipt)?;
        readback_provider
            .read_and_verify_adoption(
                store,
                client,
                target_scope,
                self,
                adopted_receipt,
                expected_ack_generation,
                verification_generation,
                now,
            )
            .await
    }

    fn verify_adopted_receipt(
        &self,
        receipt: &RegionTransferReceipt,
    ) -> Result<(), CloudStorageError> {
        receipt.verify()?;
        if receipt.status != RegionTransferStatus::Adopted {
            return Err(status_error(&receipt.status));
        }
        if receipt.request.consumer != *self
            || receipt.request.target_cell != self.region
            || receipt.request.current_commit_digest != self.current_commit_digest
        {
            return Err(CloudStorageError::RegionTransferReceiptTampered);
        }
        Ok(())
    }
}

/// The target-Cell provider is intentionally read-only with respect to the
/// transferred Project/Mission.  Its only durable write is the verification
/// receipt and append-only verification event produced after the readback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionTransferReadbackProvider {
    pub provider_id: String,
    pub region: DataCell,
    pub version: u64,
    pub implementation_digest: String,
    pub current_commit_digest: String,
    pub rls_principal_digest: String,
}

impl RegionTransferReadbackProvider {
    #[must_use]
    pub fn new(
        provider_id: impl Into<String>,
        region: DataCell,
        version: u64,
        implementation_digest: impl Into<String>,
        current_commit_digest: impl Into<String>,
        rls_principal_digest: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            region,
            version,
            implementation_digest: implementation_digest.into(),
            current_commit_digest: current_commit_digest.into(),
            rls_principal_digest: rls_principal_digest.into(),
        }
    }

    /// Derive the non-secret RLS principal evidence bound into a verification
    /// receipt.  The database role itself never enters a Project/Mission
    /// receipt; only this exact scope-bound digest does.
    #[must_use]
    pub fn principal_digest(principal: &str, scope: &super::CellScope) -> String {
        transfer_digest(
            format!(
                "hartevo.cloud.region-transfer.rls-principal:v1:{}:{}:{}",
                scope.cell.as_str(),
                scope.tenant_id.as_str(),
                principal
            )
            .as_bytes(),
        )
    }

    fn validate(&self, target_scope: &super::CellScope) -> Result<(), CloudStorageError> {
        if self.provider_id.trim().is_empty()
            || self.provider_id.len() > MAX_TRANSFER_ID_BYTES
            || self.region != target_scope.cell
            || self.version != REGION_TRANSFER_VERIFICATION_VERSION
            || !is_sha256(&self.implementation_digest)
            || !is_sha256(&self.current_commit_digest)
            || !is_sha256(&self.rls_principal_digest)
        {
            return Err(CloudStorageError::InvalidRegionTransfer);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the provider boundary keeps target scope, consumer identity, receipt, and generation fences explicit"
    )]
    pub async fn read_and_verify_adoption(
        &self,
        store: &PostgresCellStore,
        client: &mut Client,
        target_scope: &super::CellScope,
        consumer: &RegionTransferConsumer,
        adopted_receipt: &RegionTransferReceipt,
        expected_ack_generation: u64,
        verification_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferVerificationReceipt, CloudStorageError> {
        self.validate(target_scope)?;
        store
            .verify_region_transfer_adoption(
                client,
                target_scope,
                consumer,
                self,
                adopted_receipt,
                expected_ack_generation,
                verification_generation,
                now,
            )
            .await
    }
}

pub const REGION_TRANSFER_VERIFICATION_VERSION: u64 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionTransferVerificationStatus {
    Verified,
    Rejected,
}

impl RegionTransferVerificationStatus {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionTransferOutcome {
    Adoptable,
    NotAdoptable,
}

impl RegionTransferOutcome {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Adoptable => "adoptable",
            Self::NotAdoptable => "not_adoptable",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptableRegionTransferResult {
    pub source_scope: super::CellScope,
    pub target_scope: super::CellScope,
    pub transfer_id: String,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub request_digest: String,
    pub source_receipt_digest: String,
    pub target_receipt_digest: String,
    pub ciphertext_digest: String,
    pub sequence: u64,
    pub replay_nonce: String,
    pub current_commit_digest: String,
    pub ack_generation: u64,
    pub verification_generation: u64,
}

impl AdoptableRegionTransferResult {
    fn verify(&self) -> Result<(), CloudStorageError> {
        if self.source_scope.tenant_id != self.target_scope.tenant_id
            || self.source_scope.cell == self.target_scope.cell
            || self.transfer_id.trim().is_empty()
            || self.transfer_id.len() > MAX_TRANSFER_ID_BYTES
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.sequence == 0
            || self.replay_nonce.trim().is_empty()
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.source_receipt_digest)
            || !is_sha256(&self.target_receipt_digest)
            || !is_sha256(&self.ciphertext_digest)
            || !is_sha256(&self.current_commit_digest)
            || self.ack_generation != REGION_TRANSFER_ACK_GENERATION
            || self.verification_generation == 0
        {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionTransferOutcomeReceipt {
    pub verification_digest: String,
    pub outcome: RegionTransferOutcome,
    pub adoptable_result: Option<AdoptableRegionTransferResult>,
    pub outcome_digest: String,
}

impl RegionTransferOutcomeReceipt {
    fn new(
        verification_digest: String,
        outcome: RegionTransferOutcome,
        adoptable_result: Option<AdoptableRegionTransferResult>,
    ) -> Result<Self, CloudStorageError> {
        let outcome_digest = canonical_digest(&serde_json::json!({
            "verificationDigest": verification_digest,
            "outcome": outcome,
            "adoptableResult": adoptable_result,
        }))?;
        Ok(Self {
            verification_digest,
            outcome,
            adoptable_result,
            outcome_digest,
        })
    }

    fn verify(&self, expected_verification_digest: &str) -> Result<(), CloudStorageError> {
        if self.verification_digest != expected_verification_digest
            || !is_sha256(&self.verification_digest)
            || !is_sha256(&self.outcome_digest)
        {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }
        match (&self.outcome, &self.adoptable_result) {
            (RegionTransferOutcome::Adoptable, Some(result)) => result.verify()?,
            (RegionTransferOutcome::NotAdoptable, None) => {}
            _ => return Err(CloudStorageError::RegionTransferVerificationTampered),
        }
        let expected = canonical_digest(&serde_json::json!({
            "verificationDigest": self.verification_digest,
            "outcome": self.outcome,
            "adoptableResult": self.adoptable_result,
        }))
        .map_err(|_| CloudStorageError::RegionTransferVerificationTampered)?;
        if expected != self.outcome_digest {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionTransferVerificationReceipt {
    pub source_scope: super::CellScope,
    pub target_scope: super::CellScope,
    pub transfer_id: String,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub project_revision: u64,
    pub project_metadata_digest: String,
    pub project_encryption_mode: ProjectEncryptionMode,
    pub mission_revision: u64,
    pub key_generation: u64,
    pub encrypted_bundle_root: String,
    pub idempotency_key_digest: String,
    pub request_digest: String,
    pub source_receipt_digest: String,
    pub target_receipt_digest: String,
    pub ciphertext_digest: String,
    pub sequence: u64,
    pub replay_nonce: String,
    pub service: RegionTransferServiceDefinition,
    pub provider: RegionTransferProvider,
    pub consumer: RegionTransferConsumer,
    pub readback_provider: RegionTransferReadbackProvider,
    pub current_commit_digest: String,
    pub rls_principal_digest: String,
    pub ack_generation: u64,
    pub verification_generation: u64,
    pub status: RegionTransferVerificationStatus,
    pub outcome: RegionTransferOutcomeReceipt,
    pub requested_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub verification_digest: String,
}

impl RegionTransferVerificationReceipt {
    fn new(
        source_receipt: &RegionTransferReceipt,
        target_receipt: &RegionTransferReceipt,
        readback_provider: &RegionTransferReadbackProvider,
        expected_rls_principal_digest: String,
        ack_generation: u64,
        verification_generation: u64,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, CloudStorageError> {
        let request = &source_receipt.request;
        let adoptable_result = AdoptableRegionTransferResult {
            source_scope: request.source_scope.clone(),
            target_scope: super::CellScope {
                cell: request.target_cell,
                tenant_id: request.source_scope.tenant_id.clone(),
            },
            transfer_id: request.transfer_id.clone(),
            project_id: request.project_id.clone(),
            mission_id: request.mission_id.clone(),
            request_digest: source_receipt.request_digest.clone(),
            source_receipt_digest: source_receipt.receipt_digest.clone(),
            target_receipt_digest: target_receipt.receipt_digest.clone(),
            ciphertext_digest: request.encrypted_bundle.content_digest.clone(),
            sequence: request.sequence,
            replay_nonce: request.replay_nonce.clone(),
            current_commit_digest: request.current_commit_digest.clone(),
            ack_generation,
            verification_generation,
        };
        let verification_digest = verification_digest_for(
            &request.source_scope,
            &super::CellScope {
                cell: request.target_cell,
                tenant_id: request.source_scope.tenant_id.clone(),
            },
            &request.transfer_id,
            &request.project_id,
            &request.mission_id,
            request.project_revision,
            &request.project_metadata_digest,
            &request.project_encryption_mode,
            request.mission_revision,
            request.key_generation,
            &request.encrypted_bundle_root,
            &request.idempotency_key_digest,
            &source_receipt.request_digest,
            &source_receipt.receipt_digest,
            &target_receipt.receipt_digest,
            &request.encrypted_bundle.content_digest,
            request.sequence,
            &request.replay_nonce,
            &request.service,
            &request.provider,
            &request.consumer,
            readback_provider,
            &request.current_commit_digest,
            &expected_rls_principal_digest,
            ack_generation,
            verification_generation,
            &RegionTransferVerificationStatus::Verified,
            &RegionTransferOutcome::Adoptable,
            &adoptable_result,
            request.requested_at,
            recorded_at,
        )?;
        let outcome = RegionTransferOutcomeReceipt::new(
            verification_digest.clone(),
            RegionTransferOutcome::Adoptable,
            Some(adoptable_result),
        )?;
        Ok(Self {
            source_scope: request.source_scope.clone(),
            target_scope: super::CellScope {
                cell: request.target_cell,
                tenant_id: request.source_scope.tenant_id.clone(),
            },
            transfer_id: request.transfer_id.clone(),
            project_id: request.project_id.clone(),
            mission_id: request.mission_id.clone(),
            project_revision: request.project_revision,
            project_metadata_digest: request.project_metadata_digest.clone(),
            project_encryption_mode: request.project_encryption_mode.clone(),
            mission_revision: request.mission_revision,
            key_generation: request.key_generation,
            encrypted_bundle_root: request.encrypted_bundle_root.clone(),
            idempotency_key_digest: request.idempotency_key_digest.clone(),
            request_digest: source_receipt.request_digest.clone(),
            source_receipt_digest: source_receipt.receipt_digest.clone(),
            target_receipt_digest: target_receipt.receipt_digest.clone(),
            ciphertext_digest: request.encrypted_bundle.content_digest.clone(),
            sequence: request.sequence,
            replay_nonce: request.replay_nonce.clone(),
            service: request.service.clone(),
            provider: request.provider.clone(),
            consumer: request.consumer.clone(),
            readback_provider: readback_provider.clone(),
            current_commit_digest: request.current_commit_digest.clone(),
            rls_principal_digest: expected_rls_principal_digest,
            ack_generation,
            verification_generation,
            status: RegionTransferVerificationStatus::Verified,
            outcome,
            requested_at: request.requested_at,
            recorded_at,
            verification_digest,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "receipt verification intentionally enumerates every Project, Mission, Cell, digest, and authority fence"
    )]
    pub fn verify(&self) -> Result<(), CloudStorageError> {
        self.source_scope.validate(self.source_scope.cell)?;
        self.target_scope.validate(self.target_scope.cell)?;
        if self.source_scope.tenant_id != self.target_scope.tenant_id
            || self.source_scope.cell == self.target_scope.cell
            || self.target_scope.cell != self.consumer.region
            || self.transfer_id.trim().is_empty()
            || self.transfer_id.len() > MAX_TRANSFER_ID_BYTES
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.project_revision == 0
            || !is_sha256(&self.project_metadata_digest)
            || self.mission_revision == 0
            || self.key_generation == 0
            || !is_sha256(&self.encrypted_bundle_root)
            || self.encrypted_bundle_root != self.ciphertext_digest
            || !is_sha256(&self.idempotency_key_digest)
            || self.request_digest
                != self
                    .outcome
                    .adoptable_result
                    .as_ref()
                    .map_or_else(String::new, |result| result.request_digest.clone())
            || self.ack_generation != REGION_TRANSFER_ACK_GENERATION
            || self.verification_generation == 0
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.source_receipt_digest)
            || !is_sha256(&self.target_receipt_digest)
            || !is_sha256(&self.ciphertext_digest)
            || !is_sha256(&self.current_commit_digest)
            || !is_sha256(&self.rls_principal_digest)
        {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }
        self.service.validate()?;
        self.provider.validate(self.source_scope.cell)?;
        self.consumer.validate(self.target_scope.cell)?;
        self.readback_provider.validate(&self.target_scope)?;
        if self.status != RegionTransferVerificationStatus::Verified
            || self.outcome.outcome != RegionTransferOutcome::Adoptable
            || self.provider.current_commit_digest != self.current_commit_digest
            || self.consumer.current_commit_digest != self.current_commit_digest
            || self.readback_provider.current_commit_digest != self.current_commit_digest
            || self.readback_provider.rls_principal_digest != self.rls_principal_digest
            || self.provider.provider_id != self.consumer.trusted_provider_id
            || self.provider.implementation_digest != self.consumer.trusted_provider_digest
        {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }
        let Some(adoptable_result) = self.outcome.adoptable_result.as_ref() else {
            return Err(CloudStorageError::RegionTransferOutcomeNotAdoptable);
        };
        if adoptable_result.source_scope != self.source_scope
            || adoptable_result.target_scope != self.target_scope
            || adoptable_result.transfer_id != self.transfer_id
            || adoptable_result.project_id != self.project_id
            || adoptable_result.mission_id != self.mission_id
            || adoptable_result.request_digest != self.request_digest
            || adoptable_result.source_receipt_digest != self.source_receipt_digest
            || adoptable_result.target_receipt_digest != self.target_receipt_digest
            || adoptable_result.ciphertext_digest != self.ciphertext_digest
            || adoptable_result.sequence != self.sequence
            || adoptable_result.replay_nonce != self.replay_nonce
            || adoptable_result.current_commit_digest != self.current_commit_digest
            || adoptable_result.ack_generation != self.ack_generation
            || adoptable_result.verification_generation != self.verification_generation
        {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }
        let expected = verification_digest_for(
            &self.source_scope,
            &self.target_scope,
            &self.transfer_id,
            &self.project_id,
            &self.mission_id,
            self.project_revision,
            &self.project_metadata_digest,
            &self.project_encryption_mode,
            self.mission_revision,
            self.key_generation,
            &self.encrypted_bundle_root,
            &self.idempotency_key_digest,
            &self.request_digest,
            &self.source_receipt_digest,
            &self.target_receipt_digest,
            &self.ciphertext_digest,
            self.sequence,
            &self.replay_nonce,
            &self.service,
            &self.provider,
            &self.consumer,
            &self.readback_provider,
            &self.current_commit_digest,
            &self.rls_principal_digest,
            self.ack_generation,
            self.verification_generation,
            &self.status,
            &self.outcome.outcome,
            adoptable_result,
            self.requested_at,
            self.recorded_at,
        )?;
        if expected != self.verification_digest {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }
        self.outcome.verify(&self.verification_digest)
    }

    /// Convert a verified receipt into a bounded adoption proof.  This is a
    /// data result only; it grants no Store, Worker, Effect, or plaintext
    /// authority and performs no mutation.
    pub fn adoptable_result(&self) -> Result<AdoptableRegionTransferResult, CloudStorageError> {
        self.verify()?;
        self.outcome
            .adoptable_result
            .clone()
            .ok_or(CloudStorageError::RegionTransferOutcomeNotAdoptable)
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
    pub ack_generation: Option<u64>,
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
        let ack_generation =
            (status == RegionTransferStatus::Adopted).then_some(REGION_TRANSFER_ACK_GENERATION);
        Ok(Self {
            request,
            request_digest,
            status,
            adopted_revision,
            ack_generation,
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
            || (self.status == RegionTransferStatus::Adopted
                && self.ack_generation != Some(REGION_TRANSFER_ACK_GENERATION))
            || (self.status != RegionTransferStatus::Adopted && self.ack_generation.is_some())
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
                        adopted_revision, ack_generation, receipt_digest
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

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the PostgreSQL provider boundary keeps read-only evidence and generation fences in one atomic journey"
    )]
    pub async fn verify_region_transfer_adoption(
        &self,
        client: &mut Client,
        target_scope: &super::CellScope,
        consumer: &RegionTransferConsumer,
        readback_provider: &RegionTransferReadbackProvider,
        adopted_receipt: &RegionTransferReceipt,
        expected_ack_generation: u64,
        verification_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<RegionTransferVerificationReceipt, CloudStorageError> {
        adopted_receipt.verify()?;
        if adopted_receipt.status != RegionTransferStatus::Adopted {
            return Err(status_error(&adopted_receipt.status));
        }
        adopted_receipt.request.validate_target(target_scope)?;
        consumer.validate(target_scope.cell)?;
        readback_provider.validate(target_scope)?;
        if adopted_receipt.request.consumer != *consumer
            || adopted_receipt.request.current_commit_digest
                != readback_provider.current_commit_digest
            || adopted_receipt.ack_generation != Some(expected_ack_generation)
            || expected_ack_generation != REGION_TRANSFER_ACK_GENERATION
            || verification_generation == 0
        {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }

        let target_read = client.transaction().await?;
        set_scope(&target_read, target_scope).await?;
        ensure_database_cell(&target_read, self.cell).await?;
        target_read
            .batch_execute("SET TRANSACTION READ ONLY")
            .await?;
        let principal: String = target_read
            .query_one("SELECT current_user", &[])
            .await?
            .get(0);
        let actual_rls_principal_digest =
            RegionTransferReadbackProvider::principal_digest(&principal, target_scope);
        if actual_rls_principal_digest != readback_provider.rls_principal_digest {
            return Err(CloudStorageError::RegionTransferVerificationRlsMismatch);
        }
        let target_row = target_read
            .query_opt(
                &transfer_row_sql("transfer_id = $4"),
                &[
                    &target_scope.cell.as_str(),
                    &target_scope.tenant_id.as_str(),
                    &adopted_receipt.request.project_id.as_str(),
                    &adopted_receipt.request.transfer_id,
                ],
            )
            .await?
            .ok_or(CloudStorageError::RegionTransferVerificationNotFound)?;
        let target_receipt = decode_transfer_row(&target_row, target_scope)?;
        if target_receipt.status != RegionTransferStatus::Adopted
            || target_receipt.request != adopted_receipt.request
            || target_receipt.request_digest != adopted_receipt.request_digest
            || target_receipt.receipt_digest != adopted_receipt.receipt_digest
            || target_receipt.ack_generation != adopted_receipt.ack_generation
        {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }

        let head = target_read
            .query_opt(
                "SELECT current_revision, key_version, content_digest, object_kind, tombstone
                 FROM hartevo_cell.sync_object_heads
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND object_id = $4",
                &[
                    &target_scope.cell.as_str(),
                    &target_scope.tenant_id.as_str(),
                    &adopted_receipt.request.project_id.as_str(),
                    &adopted_receipt.request.mission_id.as_str(),
                ],
            )
            .await?
            .ok_or(CloudStorageError::RegionTransferVerificationNotFound)?;
        let versions = target_read
            .query_opt(
                "SELECT revision, key_version, nonce, ciphertext, aad_digest,
                        content_digest, tombstone
                 FROM hartevo_cell.sync_object_versions
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND object_id = $4 AND revision = $5",
                &[
                    &target_scope.cell.as_str(),
                    &target_scope.tenant_id.as_str(),
                    &adopted_receipt.request.project_id.as_str(),
                    &adopted_receipt.request.mission_id.as_str(),
                    &super::to_sql_u64(adopted_receipt.request.mission_revision)?,
                ],
            )
            .await?
            .ok_or(CloudStorageError::RegionTransferVerificationNotFound)?;
        let actual_ciphertext: Vec<u8> = versions.get(3);
        let actual_ciphertext_digest = format!("{:x}", Sha256::digest(&actual_ciphertext));
        if head.get::<_, String>(3) != SyncObjectKind::Mission.as_str()
            || head.get::<_, bool>(4)
            || from_sql_u64(head.get(0), "region transfer verified head revision")?
                != adopted_receipt.request.mission_revision
            || from_sql_u64(head.get(1), "region transfer verified head key generation")?
                != adopted_receipt.request.key_generation
            || head.get::<_, String>(2) != adopted_receipt.request.encrypted_bundle.content_digest
            || from_sql_u64(versions.get(0), "region transfer verified version")?
                != adopted_receipt.request.mission_revision
            || from_sql_u64(versions.get(1), "region transfer verified key generation")?
                != adopted_receipt.request.key_generation
            || versions.get::<_, Vec<u8>>(2) != adopted_receipt.request.encrypted_bundle.nonce
            || versions.get::<_, String>(4) != adopted_receipt.request.encrypted_bundle.aad_digest
            || versions.get::<_, String>(5)
                != adopted_receipt.request.encrypted_bundle.content_digest
            || versions.get::<_, bool>(6)
            || actual_ciphertext_digest != adopted_receipt.request.encrypted_bundle.content_digest
        {
            return Err(CloudStorageError::RegionTransferVerificationTampered);
        }
        target_read.commit().await?;

        let transaction = client.transaction().await?;
        set_scope(&transaction, target_scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let generation_sql = super::to_sql_u64(verification_generation)?;
        if let Some(row) = transaction
            .query_opt(
                "SELECT verification_json, verification_digest, outcome_digest,
                        verification_status, outcome_status, ack_generation,
                        verification_generation, source_cell, target_cell,
                        request_digest, source_receipt_digest, target_receipt_digest,
                        ciphertext_digest, sequence, replay_nonce, current_commit_digest,
                        rls_principal_digest, recorded_at
                 FROM hartevo_cell.region_transfer_verification_receipts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND transfer_id = $4 AND verification_generation = $5
                 FOR UPDATE",
                &[
                    &target_scope.cell.as_str(),
                    &target_scope.tenant_id.as_str(),
                    &adopted_receipt.request.project_id.as_str(),
                    &adopted_receipt.request.transfer_id,
                    &generation_sql,
                ],
            )
            .await?
        {
            let existing = decode_verification_row(&row, target_scope)?;
            let expected = RegionTransferVerificationReceipt::new(
                adopted_receipt,
                &target_receipt,
                readback_provider,
                actual_rls_principal_digest,
                expected_ack_generation,
                verification_generation,
                existing.recorded_at,
            )?;
            if expected == existing {
                transaction.commit().await?;
                return Ok(existing);
            }
            return Err(CloudStorageError::RegionTransferVerificationReplay);
        }
        let max_generation: i64 = transaction
            .query_one(
                "SELECT COALESCE(MAX(verification_generation), 0)
                 FROM hartevo_cell.region_transfer_verification_receipts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND transfer_id = $4",
                &[
                    &target_scope.cell.as_str(),
                    &target_scope.tenant_id.as_str(),
                    &adopted_receipt.request.project_id.as_str(),
                    &adopted_receipt.request.transfer_id,
                ],
            )
            .await?
            .get(0);
        if max_generation
            != i64::try_from(verification_generation)
                .map_err(|_| CloudStorageError::RegionTransferVerificationStale)?
                - 1
        {
            return Err(CloudStorageError::RegionTransferVerificationStale);
        }
        if transaction
            .query_opt(
                "SELECT 1
                 FROM hartevo_cell.region_transfer_verification_receipts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND transfer_id = $4 AND request_digest = $5
                   AND source_receipt_digest = $6 AND target_receipt_digest = $7
                 LIMIT 1",
                &[
                    &target_scope.cell.as_str(),
                    &target_scope.tenant_id.as_str(),
                    &adopted_receipt.request.project_id.as_str(),
                    &adopted_receipt.request.transfer_id,
                    &adopted_receipt.request_digest,
                    &adopted_receipt.receipt_digest,
                    &target_receipt.receipt_digest,
                ],
            )
            .await?
            .is_some()
        {
            return Err(CloudStorageError::RegionTransferVerificationReplay);
        }
        let verification = RegionTransferVerificationReceipt::new(
            adopted_receipt,
            &target_receipt,
            readback_provider,
            actual_rls_principal_digest,
            expected_ack_generation,
            verification_generation,
            now,
        )?;
        verification.verify()?;
        insert_verification_receipt(&transaction, target_scope, &verification).await?;
        append_verification_event(&transaction, target_scope, &verification, now).await?;
        transaction.commit().await?;
        Ok(verification)
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
                 SET status = $5, adopted_revision = $6, ack_generation = $7,
                     receipt_digest = $8, updated_at = $9
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND transfer_id = $4
                   AND status = 'prepared' AND receipt_digest = $10",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &receipt.request.project_id.as_str(),
                    &receipt.request.transfer_id,
                    &transitioned.status.as_str(),
                    &adopted_revision_sql,
                    &transitioned
                        .ack_generation
                        .map(super::to_sql_u64)
                        .transpose()?,
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
                adopted_revision, ack_generation, receipt_digest
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
    let ack_generation = row
        .get::<_, Option<i64>>(10)
        .map(|value| from_sql_u64(value, "region transfer acknowledgment generation"))
        .transpose()?;
    let receipt_digest: String = row.get(11);
    let receipt = RegionTransferReceipt {
        request,
        request_digest,
        status,
        adopted_revision,
        ack_generation,
        receipt_digest,
    };
    receipt.verify()?;
    Ok(receipt)
}

fn decode_verification_row(
    row: &Row,
    target_scope: &super::CellScope,
) -> Result<RegionTransferVerificationReceipt, CloudStorageError> {
    let receipt: RegionTransferVerificationReceipt = serde_json::from_value(row.get(0))
        .map_err(|_| CloudStorageError::RegionTransferVerificationTampered)?;
    receipt.verify()?;
    if receipt.target_scope != *target_scope
        || row.get::<_, String>(1) != receipt.verification_digest
        || row.get::<_, String>(2) != receipt.outcome.outcome_digest
        || row.get::<_, String>(3) != receipt.status.as_str()
        || row.get::<_, String>(4) != receipt.outcome.outcome.as_str()
        || from_sql_u64(
            row.get(5),
            "region transfer verification acknowledgment generation",
        )? != receipt.ack_generation
        || from_sql_u64(row.get(6), "region transfer verification generation")?
            != receipt.verification_generation
        || row.get::<_, String>(7) != receipt.source_scope.cell.as_str()
        || row.get::<_, String>(8) != receipt.target_scope.cell.as_str()
        || row.get::<_, String>(9) != receipt.request_digest
        || row.get::<_, String>(10) != receipt.source_receipt_digest
        || row.get::<_, String>(11) != receipt.target_receipt_digest
        || row.get::<_, String>(12) != receipt.ciphertext_digest
        || from_sql_u64(row.get(13), "region transfer verification sequence")? != receipt.sequence
        || row.get::<_, String>(14) != receipt.replay_nonce
        || row.get::<_, String>(15) != receipt.current_commit_digest
        || row.get::<_, String>(16) != receipt.rls_principal_digest
        || row.get::<_, DateTime<Utc>>(17) != receipt.recorded_at
    {
        return Err(CloudStorageError::RegionTransferVerificationTampered);
    }
    Ok(receipt)
}

async fn insert_verification_receipt(
    transaction: &Transaction<'_>,
    target_scope: &super::CellScope,
    receipt: &RegionTransferVerificationReceipt,
) -> Result<(), CloudStorageError> {
    let verification_json = serde_json::to_value(receipt)?;
    let sequence = super::to_sql_u64(receipt.sequence)?;
    let service_version = super::to_sql_u64(receipt.service.version)?;
    let provider_version = super::to_sql_u64(receipt.provider.version)?;
    let consumer_version = super::to_sql_u64(receipt.consumer.version)?;
    let readback_provider_version = super::to_sql_u64(receipt.readback_provider.version)?;
    let ack_generation = super::to_sql_u64(receipt.ack_generation)?;
    let verification_generation = super::to_sql_u64(receipt.verification_generation)?;
    transaction
        .execute(
            "INSERT INTO hartevo_cell.region_transfer_verification_receipts
               (cell, tenant_id, project_id, transfer_id, mission_id, source_cell,
                target_cell, request_digest, source_receipt_digest, target_receipt_digest,
                ciphertext_digest, sequence, replay_nonce, service_version, service_digest,
                provider_id, provider_version, provider_digest, consumer_id, consumer_version,
                consumer_digest, readback_provider_id, readback_provider_version,
                readback_provider_digest, current_commit_digest, rls_principal_digest,
                ack_generation, verification_generation, verification_status, outcome_status,
                verification_json, verification_digest, outcome_digest, recorded_at, updated_at)
             VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28,
                $29, $30, $31, $32, $33, $34, $34)",
            &[
                &target_scope.cell.as_str(),
                &target_scope.tenant_id.as_str(),
                &receipt.project_id.as_str(),
                &receipt.transfer_id,
                &receipt.mission_id.as_str(),
                &receipt.source_scope.cell.as_str(),
                &receipt.target_scope.cell.as_str(),
                &receipt.request_digest,
                &receipt.source_receipt_digest,
                &receipt.target_receipt_digest,
                &receipt.ciphertext_digest,
                &sequence,
                &receipt.replay_nonce,
                &service_version,
                &receipt.service.contract_digest,
                &receipt.provider.provider_id,
                &provider_version,
                &receipt.provider.implementation_digest,
                &receipt.consumer.consumer_id,
                &consumer_version,
                &receipt.consumer.consumer_digest,
                &receipt.readback_provider.provider_id,
                &readback_provider_version,
                &receipt.readback_provider.implementation_digest,
                &receipt.current_commit_digest,
                &receipt.rls_principal_digest,
                &ack_generation,
                &verification_generation,
                &receipt.status.as_str(),
                &receipt.outcome.outcome.as_str(),
                &verification_json,
                &receipt.verification_digest,
                &receipt.outcome.outcome_digest,
                &receipt.recorded_at,
            ],
        )
        .await?;
    Ok(())
}

async fn append_verification_event(
    transaction: &Transaction<'_>,
    target_scope: &super::CellScope,
    receipt: &RegionTransferVerificationReceipt,
    observed_at: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    let verification_generation = super::to_sql_u64(receipt.verification_generation)?;
    transaction
        .execute(
            "INSERT INTO hartevo_cell.region_transfer_verification_events
               (cell, tenant_id, project_id, transfer_id, verification_generation,
                verification_status, outcome_status, verification_digest, outcome_digest,
                observed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &target_scope.cell.as_str(),
                &target_scope.tenant_id.as_str(),
                &receipt.project_id.as_str(),
                &receipt.transfer_id,
                &verification_generation,
                &receipt.status.as_str(),
                &receipt.outcome.outcome.as_str(),
                &receipt.verification_digest,
                &receipt.outcome.outcome_digest,
                &observed_at,
            ],
        )
        .await?;
    Ok(())
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
    let ack_generation = receipt.ack_generation.map(super::to_sql_u64).transpose()?;
    transaction
        .execute(
            "INSERT INTO hartevo_cell.region_transfer_receipts
               (cell, tenant_id, project_id, transfer_id, mission_id, source_cell,
                target_cell, request_json, request_digest, idempotency_key_digest,
                status, adopted_revision, ack_generation, receipt_digest, recorded_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15)",
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
                &ack_generation,
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

#[allow(
    clippy::too_many_arguments,
    reason = "the canonical digest deliberately binds every typed transfer evidence field"
)]
fn verification_digest_for(
    source_scope: &super::CellScope,
    target_scope: &super::CellScope,
    transfer_id: &str,
    project_id: &ProjectId,
    mission_id: &MissionId,
    project_revision: u64,
    project_metadata_digest: &str,
    project_encryption_mode: &ProjectEncryptionMode,
    mission_revision: u64,
    key_generation: u64,
    encrypted_bundle_root: &str,
    idempotency_key_digest: &str,
    request_digest: &str,
    source_receipt_digest: &str,
    target_receipt_digest: &str,
    ciphertext_digest: &str,
    sequence: u64,
    replay_nonce: &str,
    service: &RegionTransferServiceDefinition,
    provider: &RegionTransferProvider,
    consumer: &RegionTransferConsumer,
    readback_provider: &RegionTransferReadbackProvider,
    current_commit_digest: &str,
    rls_principal_digest: &str,
    ack_generation: u64,
    verification_generation: u64,
    status: &RegionTransferVerificationStatus,
    outcome: &RegionTransferOutcome,
    adoptable_result: &AdoptableRegionTransferResult,
    requested_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
) -> Result<String, CloudStorageError> {
    canonical_digest(&serde_json::json!({
        "sourceScope": source_scope,
        "targetScope": target_scope,
        "transferId": transfer_id,
        "projectId": project_id,
        "missionId": mission_id,
        "projectRevision": project_revision,
        "projectMetadataDigest": project_metadata_digest,
        "projectEncryptionMode": project_encryption_mode,
        "missionRevision": mission_revision,
        "keyGeneration": key_generation,
        "encryptedBundleRoot": encrypted_bundle_root,
        "idempotencyKeyDigest": idempotency_key_digest,
        "requestDigest": request_digest,
        "sourceReceiptDigest": source_receipt_digest,
        "targetReceiptDigest": target_receipt_digest,
        "ciphertextDigest": ciphertext_digest,
        "sequence": sequence,
        "replayNonce": replay_nonce,
        "service": service,
        "provider": provider,
        "consumer": consumer,
        "readbackProvider": readback_provider,
        "currentCommitDigest": current_commit_digest,
        "rlsPrincipalDigest": rls_principal_digest,
        "ackGeneration": ack_generation,
        "verificationGeneration": verification_generation,
        "status": status,
        "outcome": outcome,
        "adoptableResult": adoptable_result,
        "requestedAt": requested_at,
        "recordedAt": recorded_at,
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
        RegionTransferOutcome, RegionTransferProvider, RegionTransferReadbackProvider,
        RegionTransferReceipt, RegionTransferServiceDefinition, RegionTransferStatus,
        RegionTransferVerificationReceipt,
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

    #[test]
    fn verification_receipt_is_exact_and_adoptable_only_after_all_fences() {
        let value = request();
        let source =
            RegionTransferReceipt::new(value.clone(), RegionTransferStatus::Adopted, Some(4))
                .expect("source adopted receipt");
        let target = RegionTransferReceipt::new(value, RegionTransferStatus::Adopted, Some(4))
            .expect("target adopted receipt");
        let readback = RegionTransferReadbackProvider::new(
            "target-readback",
            DataCell::Eu,
            1,
            digest("readback"),
            digest("commit"),
            digest("rls-principal"),
        );
        let receipt = RegionTransferVerificationReceipt::new(
            &source,
            &target,
            &readback,
            digest("rls-principal"),
            1,
            1,
            Utc.with_ymd_and_hms(2026, 8, 14, 2, 3, 4).unwrap(),
        )
        .expect("verification receipt");
        receipt.verify().expect("exact verification verifies");
        assert_eq!(
            receipt.outcome.outcome.clone(),
            RegionTransferOutcome::Adoptable
        );
        receipt.adoptable_result().expect("adoptable proof");

        let mut cross_mission = receipt.clone();
        cross_mission.mission_id = MissionId::from("other-mission");
        assert!(cross_mission.verify().is_err());

        let mut replay = receipt.clone();
        replay.outcome.adoptable_result.as_mut().unwrap().sequence = 2;
        assert!(replay.verify().is_err());

        let mut cross_cell = receipt;
        cross_cell.target_scope = CellScope {
            cell: DataCell::Us,
            tenant_id: TenantId::from("tenant-1"),
        };
        assert!(cross_cell.verify().is_err());
    }
}

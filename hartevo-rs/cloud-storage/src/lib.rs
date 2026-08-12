//! PostgreSQL persistence for an isolated Hartevo US or EU Cell.
//!
//! Personal project bodies are accepted only as authenticated ciphertext. The
//! store owns routing metadata, optimistic revisions, append-only versions,
//! events, and a durable outbox; it never accepts a plaintext project body.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    ActorId, DeviceHandoffClaim, DeviceHandoffConsumption, DeviceHandoffGrant, DeviceHandoffId,
    DeviceHandoffRevocation, DeviceId, DeviceKeyAgreementAlgorithm, DevicePublicKeyRegistration,
    KeyManagementError, KeyRecipient, ProjectEncryptionMode, ProjectId, ProjectKeyringBootstrap,
    TenantId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres::{Client, Row, Transaction};

mod effect_ledger;

pub use effect_ledger::{CloudPermissionFenceMutation, CloudPermissionFenceResult};

const SCHEMA: &str = include_str!("schema.sql");
const SCHEMA_VERSION: i64 = 4;
const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;
const CLAIM_OUTBOX_SQL: &str = "WITH candidates AS (
       SELECT sequence FROM hartevo_cell.outbox_messages
       WHERE cell = $1 AND tenant_id = $2
         AND ((status = 'pending' AND available_at <= $3)
           OR (status = 'leased' AND lease_expires_at <= $3))
       ORDER BY sequence ASC
       FOR UPDATE SKIP LOCKED
       LIMIT $4
     )
     UPDATE hartevo_cell.outbox_messages AS message
     SET status = 'leased', lease_owner = $5,
         lease_generation = message.lease_generation + 1,
         lease_expires_at = $6, attempts = message.attempts + 1
     FROM candidates
     WHERE message.sequence = candidates.sequence
     RETURNING message.sequence, message.cell, message.tenant_id,
               message.project_id, message.event_sequence, message.event_type,
               message.object_id, message.object_revision, message.key_version,
               message.nonce, message.payload_ciphertext, message.aad_digest,
               message.content_digest, message.tombstone, message.idempotency_key,
               message.status, message.attempts, message.available_at,
               message.lease_owner, message.lease_generation,
               message.lease_expires_at, message.created_at, message.published_at";
const ACKNOWLEDGE_OUTBOX_SQL: &str = "UPDATE hartevo_cell.outbox_messages
     SET status = 'published', published_at = $6,
         lease_owner = NULL, lease_expires_at = NULL
     WHERE cell = $1 AND tenant_id = $2 AND sequence = $3
       AND status = 'leased' AND lease_owner = $4
       AND lease_generation = $5 AND lease_expires_at > $7";
const RELEASE_OUTBOX_SQL: &str = "UPDATE hartevo_cell.outbox_messages
     SET status = $6, available_at = $7,
         lease_owner = NULL, lease_expires_at = NULL
     WHERE cell = $1 AND tenant_id = $2 AND sequence = $3
       AND status = 'leased' AND lease_owner = $4
       AND lease_generation = $5 AND lease_expires_at > $8";

pub const POSTGRES_L2_URL_ENV: &str = "HARTEVO_TEST_POSTGRES_URL";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCell {
    Us,
    Eu,
}

impl DataCell {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Us => "us",
            Self::Eu => "eu",
        }
    }
}

impl fmt::Display for DataCell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CellScope {
    pub cell: DataCell,
    pub tenant_id: TenantId,
}

impl CellScope {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        if self.cell != expected_cell || self.tenant_id.as_str().trim().is_empty() {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncObjectKind {
    ProjectMetadata,
    ProjectTruth,
    Mission,
    WorkProduct,
    Conversation,
    ConnectionMetadata,
    CreatorWork,
    OutcomeLedger,
    ContextCapsule,
}

impl SyncObjectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectMetadata => "project_metadata",
            Self::ProjectTruth => "project_truth",
            Self::Mission => "mission",
            Self::WorkProduct => "work_product",
            Self::Conversation => "conversation",
            Self::ConnectionMetadata => "connection_metadata",
            Self::CreatorWork => "creator_work",
            Self::OutcomeLedger => "outcome_ledger",
            Self::ContextCapsule => "context_capsule",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedPayload {
    pub key_version: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad_digest: String,
    pub content_digest: String,
}

impl EncryptedPayload {
    fn validate(&self) -> Result<(), CloudStorageError> {
        if self.key_version == 0
            || self.nonce.len() != 12
            || !(16..=MAX_CIPHERTEXT_BYTES).contains(&self.ciphertext.len())
            || !is_sha256(&self.aad_digest)
            || !is_sha256(&self.content_digest)
            || format!("{:x}", Sha256::digest(&self.ciphertext)) != self.content_digest
        {
            return Err(CloudStorageError::InvalidEncryptedPayload);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "revision")]
pub enum MutationPrecondition {
    CreateOnly,
    ExactRevision(u64),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudProjectRegistration {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub encryption_mode: ProjectEncryptionMode,
    pub remote_execution_opt_in: bool,
    pub metadata_digest: String,
    pub initial_payload: EncryptedPayload,
    pub idempotency_key_digest: String,
    pub created_at: DateTime<Utc>,
}

impl CloudProjectRegistration {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.scope.validate(expected_cell)?;
        self.initial_payload.validate()?;
        if self.project_id.as_str().trim().is_empty()
            || !is_sha256(&self.metadata_digest)
            || self.metadata_digest != self.initial_payload.content_digest
            || !is_sha256(&self.idempotency_key_digest)
            || (self.encryption_mode == ProjectEncryptionMode::PersonalE2ee
                && self.remote_execution_opt_in)
        {
            return Err(CloudStorageError::InvalidProjectRegistration);
        }
        Ok(())
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "cell": self.scope.cell,
            "tenantId": self.scope.tenant_id,
            "projectId": self.project_id,
            "encryptionMode": self.encryption_mode,
            "remoteExecutionOptIn": self.remote_execution_opt_in,
            "metadataDigest": self.metadata_digest,
            "payload": self.initial_payload,
            "createdAt": self.created_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedSyncMutation {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub object_id: String,
    pub object_kind: SyncObjectKind,
    pub precondition: MutationPrecondition,
    pub payload: EncryptedPayload,
    pub tombstone: bool,
    pub idempotency_key_digest: String,
    pub recorded_at: DateTime<Utc>,
}

impl EncryptedSyncMutation {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.scope.validate(expected_cell)?;
        self.payload.validate()?;
        if self.project_id.as_str().trim().is_empty()
            || self.object_id.trim().is_empty()
            || self.object_id.len() > 512
            || !is_sha256(&self.idempotency_key_digest)
            || (self.tombstone && self.precondition == MutationPrecondition::CreateOnly)
            || (self.tombstone && self.object_kind != SyncObjectKind::ContextCapsule)
            || matches!(self.precondition, MutationPrecondition::ExactRevision(0))
        {
            return Err(CloudStorageError::InvalidSyncMutation);
        }
        Ok(())
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "cell": self.scope.cell,
            "tenantId": self.scope.tenant_id,
            "projectId": self.project_id,
            "objectId": self.object_id,
            "objectKind": self.object_kind,
            "precondition": self.precondition,
            "payload": self.payload,
            "tombstone": self.tombstone,
            "recordedAt": self.recorded_at,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudMutationResult {
    pub object_revision: u64,
    pub event_sequence: i64,
    pub outbox_sequence: i64,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapMutationResult {
    pub revision: u64,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceHandoffMutationResult {
    pub grant_id: DeviceHandoffId,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedSyncObject {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub object_id: String,
    pub object_kind: SyncObjectKind,
    pub revision: u64,
    pub payload: EncryptedPayload,
    pub tombstone: bool,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudOutboxStatus {
    Pending,
    Leased,
    Published,
    DeadLetter,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudOutboxMessage {
    pub sequence: i64,
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub event_sequence: i64,
    pub event_type: String,
    pub object_id: String,
    pub object_revision: u64,
    pub payload: EncryptedPayload,
    pub tombstone: bool,
    pub idempotency_key_digest: String,
    pub status: CloudOutboxStatus,
    pub attempts: u32,
    pub available_at: DateTime<Utc>,
    pub lease_owner: Option<String>,
    pub lease_generation: u64,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxAcknowledgeTimes {
    pub published_at: DateTime<Utc>,
    pub operation_at: DateTime<Utc>,
}

impl OutboxAcknowledgeTimes {
    pub fn new(
        published_at: DateTime<Utc>,
        operation_at: DateTime<Utc>,
    ) -> Result<Self, CloudStorageError> {
        let times = Self {
            published_at,
            operation_at,
        };
        times.validate()?;
        Ok(times)
    }

    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.published_at > self.operation_at {
            Err(CloudStorageError::InvalidOutboxClaim)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxReleaseTimes {
    pub available_at: DateTime<Utc>,
    pub operation_at: DateTime<Utc>,
}

impl OutboxReleaseTimes {
    pub fn new(
        available_at: DateTime<Utc>,
        operation_at: DateTime<Utc>,
    ) -> Result<Self, CloudStorageError> {
        let times = Self {
            available_at,
            operation_at,
        };
        times.validate()?;
        Ok(times)
    }

    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.available_at < self.operation_at {
            Err(CloudStorageError::InvalidOutboxClaim)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxRelease {
    Requeue(OutboxReleaseTimes),
    DeadLetter(OutboxReleaseTimes),
}

enum OutboxCompletion {
    Acknowledge(OutboxAcknowledgeTimes),
    Release(OutboxRelease),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresL2Environment {
    Ready,
    BlockedEnv,
}

impl PostgresL2Environment {
    pub fn detect() -> Self {
        if std::env::var_os(POSTGRES_L2_URL_ENV).is_some() {
            Self::Ready
        } else {
            Self::BlockedEnv
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresCellStore {
    cell: DataCell,
}

impl PostgresCellStore {
    pub const fn new(cell: DataCell) -> Self {
        Self { cell }
    }

    pub const fn cell(self) -> DataCell {
        self.cell
    }

    pub async fn migrate(
        &self,
        client: &mut Client,
        now: DateTime<Utc>,
    ) -> Result<(), CloudStorageError> {
        let transaction = client.transaction().await?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtext('hartevo_cell_schema_v4'))",
                &[],
            )
            .await?;
        transaction.batch_execute(SCHEMA).await?;

        let configured_cell = transaction
            .query_opt(
                "SELECT cell FROM hartevo_cell.cell_configuration WHERE singleton = TRUE",
                &[],
            )
            .await?
            .map(|row| row.get::<_, String>(0));
        if configured_cell
            .as_deref()
            .is_some_and(|configured| configured != self.cell.as_str())
        {
            return Err(CloudStorageError::DatabaseCellMismatch);
        }
        transaction
            .execute(
                "INSERT INTO hartevo_cell.cell_configuration (singleton, cell, configured_at)
                 VALUES (TRUE, $1, $2) ON CONFLICT (singleton) DO NOTHING",
                &[&self.cell.as_str(), &now],
            )
            .await?;

        let checksum = schema_digest();
        transaction
            .execute(
                "INSERT INTO hartevo_cell.schema_migrations (version, checksum, applied_at)
                 VALUES ($1, $2, $3) ON CONFLICT (version) DO NOTHING",
                &[&SCHEMA_VERSION, &checksum, &now],
            )
            .await?;
        let stored_checksum: String = transaction
            .query_one(
                "SELECT checksum FROM hartevo_cell.schema_migrations WHERE version = $1",
                &[&SCHEMA_VERSION],
            )
            .await?
            .get(0);
        if stored_checksum != checksum {
            return Err(CloudStorageError::MigrationChecksumMismatch);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn register_tenant(
        &self,
        client: &mut Client,
        scope: &CellScope,
        now: DateTime<Utc>,
    ) -> Result<(), CloudStorageError> {
        scope.validate(self.cell)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.tenant_cells (cell, tenant_id, created_at)
                 VALUES ($1, $2, $3) ON CONFLICT (cell, tenant_id) DO NOTHING",
                &[&self.cell.as_str(), &scope.tenant_id.as_str(), &now],
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn create_project(
        &self,
        client: &mut Client,
        registration: &CloudProjectRegistration,
    ) -> Result<CloudMutationResult, CloudStorageError> {
        registration.validate(self.cell)?;
        let request_digest = registration.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &registration.scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        lock_project(&transaction, &registration.scope, &registration.project_id).await?;

        if let Some(existing) = existing_mutation(
            &transaction,
            &registration.scope,
            &registration.project_id,
            &registration.idempotency_key_digest,
            &request_digest,
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(existing);
        }

        let tenant_exists = transaction
            .query_opt(
                "SELECT 1 FROM hartevo_cell.tenant_cells
                 WHERE cell = $1 AND tenant_id = $2",
                &[
                    &registration.scope.cell.as_str(),
                    &registration.scope.tenant_id.as_str(),
                ],
            )
            .await?
            .is_some();
        if !tenant_exists {
            return Err(CloudStorageError::TenantNotRegistered);
        }

        let inserted = transaction
            .execute(
                "INSERT INTO hartevo_cell.projects
                   (cell, tenant_id, project_id, encryption_mode, remote_execution_opt_in,
                    metadata_digest, revision, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $7)
                 ON CONFLICT (cell, tenant_id, project_id) DO NOTHING",
                &[
                    &registration.scope.cell.as_str(),
                    &registration.scope.tenant_id.as_str(),
                    &registration.project_id.as_str(),
                    &encryption_mode_name(&registration.encryption_mode),
                    &registration.remote_execution_opt_in,
                    &registration.metadata_digest,
                    &registration.created_at,
                ],
            )
            .await?;
        if inserted != 1 {
            return Err(CloudStorageError::ProjectAlreadyExists);
        }

        let result = write_revision(
            &transaction,
            &RevisionWrite {
                scope: &registration.scope,
                project_id: &registration.project_id,
                object_id: registration.project_id.as_str(),
                object_kind: SyncObjectKind::ProjectMetadata,
                revision: 1,
                payload: &registration.initial_payload,
                tombstone: false,
                idempotency_key_digest: &registration.idempotency_key_digest,
                request_digest: &request_digest,
                recorded_at: registration.created_at,
                event_type: "sync.project_metadata.created",
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(result)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the transaction keeps idempotency, exact public-key lineage, append-only version, and head CAS visibly co-located"
    )]
    pub async fn publish_device_public_key(
        &self,
        client: &mut Client,
        scope: &CellScope,
        registration: &DevicePublicKeyRegistration,
    ) -> Result<BootstrapMutationResult, CloudStorageError> {
        scope.validate(self.cell)?;
        registration.validate()?;
        if registration.tenant_id != scope.tenant_id {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        let request_digest = canonical_digest(&serde_json::to_value(registration)?)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        lock_project(&transaction, scope, &registration.project_id).await?;
        ensure_project_exists(&transaction, scope, &registration.project_id).await?;

        if let Some(existing) = transaction
            .query_opt(
                "SELECT revision, request_digest
                 FROM hartevo_cell.device_public_key_versions
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &registration.project_id.as_str(),
                    &registration.idempotency_key_digest,
                ],
            )
            .await?
        {
            ensure_request_digest(&existing.get::<_, String>(1), &request_digest)?;
            let revision = from_sql_u64(existing.get(0), "device public key revision")?;
            transaction.commit().await?;
            return Ok(BootstrapMutationResult {
                revision,
                duplicate: true,
            });
        }

        let previous = load_device_public_key_tx(
            &transaction,
            scope,
            &registration.project_id,
            &registration.device_id,
            true,
        )
        .await?;
        match previous.as_ref() {
            None if registration.revision == 1 => {}
            Some(previous) if registration.follows(previous)? => {}
            _ => return Err(CloudStorageError::InvalidDevicePublicKeyTransition),
        }
        let revision = to_sql_u64(registration.revision)?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_public_key_versions
                   (cell, tenant_id, project_id, device_id, revision, algorithm,
                    public_key, public_key_digest, authorized_by,
                    authorization_evidence_digest, idempotency_key, request_digest,
                    registered_at, updated_at, revoked_at)
                 VALUES
                   ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    $13, $14, $15)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &registration.project_id.as_str(),
                    &registration.device_id.as_str(),
                    &revision,
                    &device_key_algorithm_name(registration.algorithm),
                    &registration.public_key,
                    &registration.public_key_digest,
                    &registration.authorized_by.as_str(),
                    &registration.authorization_evidence_digest,
                    &registration.idempotency_key_digest,
                    &request_digest,
                    &registration.registered_at,
                    &registration.updated_at,
                    &registration.revoked_at,
                ],
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_public_key_heads
                   (cell, tenant_id, project_id, device_id, current_revision,
                    public_key_digest, revoked_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (cell, tenant_id, project_id, device_id) DO UPDATE
                 SET current_revision = EXCLUDED.current_revision,
                     public_key_digest = EXCLUDED.public_key_digest,
                     revoked_at = EXCLUDED.revoked_at,
                     updated_at = EXCLUDED.updated_at",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &registration.project_id.as_str(),
                    &registration.device_id.as_str(),
                    &revision,
                    &registration.public_key_digest,
                    &registration.revoked_at,
                    &registration.updated_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(BootstrapMutationResult {
            revision: registration.revision,
            duplicate: false,
        })
    }

    pub async fn load_device_public_key(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        device_id: &DeviceId,
    ) -> Result<DevicePublicKeyRegistration, CloudStorageError> {
        scope.validate(self.cell)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let registration =
            load_device_public_key_tx(&transaction, scope, project_id, device_id, false)
                .await?
                .ok_or(CloudStorageError::DevicePublicKeyNotFound)?;
        transaction.commit().await?;
        Ok(registration)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the transaction keeps previous-manifest authorization, exact keyring lineage, version insertion, and head CAS visibly co-located"
    )]
    pub async fn publish_keyring_bootstrap(
        &self,
        client: &mut Client,
        scope: &CellScope,
        bootstrap: &ProjectKeyringBootstrap,
    ) -> Result<BootstrapMutationResult, CloudStorageError> {
        scope.validate(self.cell)?;
        bootstrap.validate()?;
        if bootstrap.tenant_id != scope.tenant_id {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        let request_digest = bootstrap.request_digest()?;
        let bootstrap_json = serde_json::to_value(bootstrap)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        lock_project(&transaction, scope, &bootstrap.project_id).await?;
        let project_mode = load_project_mode(&transaction, scope, &bootstrap.project_id).await?;
        if project_mode != bootstrap.keyring.mode {
            return Err(CloudStorageError::InvalidKeyringBootstrapTransition);
        }

        if let Some(existing) = transaction
            .query_opt(
                "SELECT keyring_revision, request_digest
                 FROM hartevo_cell.keyring_bootstrap_versions
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &bootstrap.project_id.as_str(),
                    &bootstrap.idempotency_key_digest,
                ],
            )
            .await?
        {
            ensure_request_digest(&existing.get::<_, String>(1), &request_digest)?;
            let revision = from_sql_u64(existing.get(0), "keyring revision")?;
            transaction.commit().await?;
            return Ok(BootstrapMutationResult {
                revision,
                duplicate: true,
            });
        }

        let previous =
            load_keyring_bootstrap_tx(&transaction, scope, &bootstrap.project_id, true).await?;
        match previous.as_ref() {
            None if bootstrap.previous_keyring_revision.is_none() => {}
            Some(previous)
                if bootstrap.previous_keyring_revision == Some(previous.keyring.revision)
                    && bootstrap.keyring.follows(&previous.keyring)? =>
            {
                let authorizing_envelope = previous
                    .keyring
                    .available_envelope_for_version(
                        &bootstrap.published_by,
                        previous.keyring.active_key_version,
                        bootstrap.published_at,
                    )
                    .map_err(|_| CloudStorageError::InvalidKeyringBootstrapAuthorization)?;
                if authorizing_envelope.canonical_digest()? != bootstrap.authorizing_envelope_digest
                {
                    return Err(CloudStorageError::InvalidKeyringBootstrapAuthorization);
                }
            }
            _ => return Err(CloudStorageError::InvalidKeyringBootstrapTransition),
        }

        let keyring_revision = to_sql_u64(bootstrap.keyring.revision)?;
        let previous_revision = bootstrap
            .previous_keyring_revision
            .map(to_sql_u64)
            .transpose()?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.keyring_bootstrap_versions
                   (cell, tenant_id, project_id, keyring_revision,
                    previous_keyring_revision, manifest_digest, bootstrap_json,
                    published_by, authorizing_envelope_digest,
                    authorization_evidence_digest, idempotency_key, request_digest,
                    published_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &bootstrap.project_id.as_str(),
                    &keyring_revision,
                    &previous_revision,
                    &bootstrap.manifest_digest,
                    &bootstrap_json,
                    &bootstrap.published_by.stable_scope(),
                    &bootstrap.authorizing_envelope_digest,
                    &bootstrap.authorization_evidence_digest,
                    &bootstrap.idempotency_key_digest,
                    &request_digest,
                    &bootstrap.published_at,
                ],
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.keyring_bootstrap_heads
                   (cell, tenant_id, project_id, current_keyring_revision,
                    manifest_digest, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (cell, tenant_id, project_id) DO UPDATE
                 SET current_keyring_revision = EXCLUDED.current_keyring_revision,
                     manifest_digest = EXCLUDED.manifest_digest,
                     updated_at = EXCLUDED.updated_at",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &bootstrap.project_id.as_str(),
                    &keyring_revision,
                    &bootstrap.manifest_digest,
                    &bootstrap.published_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(BootstrapMutationResult {
            revision: bootstrap.keyring.revision,
            duplicate: false,
        })
    }

    pub async fn load_keyring_bootstrap(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
    ) -> Result<ProjectKeyringBootstrap, CloudStorageError> {
        scope.validate(self.cell)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let bootstrap = load_keyring_bootstrap_tx(&transaction, scope, project_id, false)
            .await?
            .ok_or(CloudStorageError::KeyringBootstrapNotFound)?;
        transaction.commit().await?;
        Ok(bootstrap)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the transaction atomically validates project mode, source manifest/envelope, target public key, idempotency, and immutable ciphertext"
    )]
    pub async fn publish_device_handoff_grant(
        &self,
        client: &mut Client,
        scope: &CellScope,
        grant: &DeviceHandoffGrant,
    ) -> Result<DeviceHandoffMutationResult, CloudStorageError> {
        scope.validate(self.cell)?;
        grant.validate()?;
        if grant.context.tenant_id != scope.tenant_id {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        let request_digest = grant.request_digest()?;
        let grant_json = serde_json::to_value(grant)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        lock_project(&transaction, scope, &grant.context.project_id).await?;
        let project_mode =
            load_project_mode(&transaction, scope, &grant.context.project_id).await?;
        if project_mode != grant.context.project_mode {
            return Err(CloudStorageError::InvalidDeviceHandoffGrant);
        }

        if let Some(existing) = transaction
            .query_opt(
                "SELECT grant_id, request_digest
                 FROM hartevo_cell.device_handoff_grants
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &grant.context.project_id.as_str(),
                    &grant.idempotency_key_digest,
                ],
            )
            .await?
        {
            ensure_request_digest(&existing.get::<_, String>(1), &request_digest)?;
            let grant_id = DeviceHandoffId::from_stable(existing.get::<_, String>(0));
            transaction.commit().await?;
            return Ok(DeviceHandoffMutationResult {
                grant_id,
                duplicate: true,
            });
        }

        let bootstrap =
            load_keyring_bootstrap_tx(&transaction, scope, &grant.context.project_id, true)
                .await?
                .ok_or(CloudStorageError::KeyringBootstrapNotFound)?;
        if bootstrap.keyring.revision != grant.context.expected_keyring_revision
            || bootstrap.keyring.mode != grant.context.project_mode
            || bootstrap.manifest_digest != grant.context.source_keyring_manifest_digest
        {
            return Err(CloudStorageError::InvalidDeviceHandoffGrant);
        }
        let source_envelope = bootstrap
            .keyring
            .available_envelope_for_version(
                &grant.context.source_recipient,
                grant.context.key_version,
                grant.created_at,
            )
            .map_err(|_| CloudStorageError::InvalidDeviceHandoffGrant)?;
        if source_envelope.canonical_digest()? != grant.context.source_envelope_digest {
            return Err(CloudStorageError::InvalidDeviceHandoffGrant);
        }
        if bootstrap
            .keyring
            .available_envelope_for_version(
                &KeyRecipient::Device(grant.context.target_device_id.clone()),
                grant.context.key_version,
                grant.created_at,
            )
            .is_ok()
        {
            return Err(CloudStorageError::DeviceAlreadyAttached);
        }
        let target_registration = load_device_public_key_tx(
            &transaction,
            scope,
            &grant.context.project_id,
            &grant.context.target_device_id,
            true,
        )
        .await?
        .ok_or(CloudStorageError::DevicePublicKeyNotFound)?;
        if !target_registration.is_active(grant.created_at)
            || target_registration.public_key_digest != grant.context.target_public_key_digest
        {
            return Err(CloudStorageError::InvalidDeviceHandoffTarget);
        }

        let key_version = to_sql_u64(grant.context.key_version)?;
        let keyring_revision = to_sql_u64(grant.context.expected_keyring_revision)?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_handoff_grants
                   (cell, tenant_id, project_id, grant_id, project_mode,
                    source_recipient, source_envelope_digest,
                    source_keyring_manifest_digest, target_device_id,
                    target_public_key_digest, key_version, expected_keyring_revision,
                    algorithm, sender_ephemeral_public_key, nonce, ciphertext,
                    aad_digest, content_digest, authorized_by,
                    authorization_evidence_digest, intent_digest, idempotency_key,
                    request_digest, grant_json, created_at, expires_at)
                 VALUES
                   ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
                    $24, $25, $26)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &grant.context.project_id.as_str(),
                    &grant.context.grant_id.as_str(),
                    &encryption_mode_name(&grant.context.project_mode),
                    &grant.context.source_recipient.stable_scope(),
                    &grant.context.source_envelope_digest,
                    &grant.context.source_keyring_manifest_digest,
                    &grant.context.target_device_id.as_str(),
                    &grant.context.target_public_key_digest,
                    &key_version,
                    &keyring_revision,
                    &device_key_algorithm_name(grant.ciphertext.algorithm),
                    &grant.ciphertext.sender_ephemeral_public_key,
                    &grant.ciphertext.nonce,
                    &grant.ciphertext.ciphertext,
                    &grant.ciphertext.aad_digest,
                    &grant.ciphertext.content_digest,
                    &grant.authorized_by.as_str(),
                    &grant.authorization_evidence_digest,
                    &grant.intent_digest,
                    &grant.idempotency_key_digest,
                    &request_digest,
                    &grant_json,
                    &grant.created_at,
                    &grant.context.expires_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(DeviceHandoffMutationResult {
            grant_id: grant.context.grant_id.clone(),
            duplicate: false,
        })
    }

    pub async fn load_device_handoff_grant(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        grant_id: &DeviceHandoffId,
    ) -> Result<DeviceHandoffGrant, CloudStorageError> {
        scope.validate(self.cell)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let grant = load_device_handoff_grant_tx(&transaction, scope, project_id, grant_id, false)
            .await?
            .ok_or(CloudStorageError::DeviceHandoffGrantNotFound)?;
        transaction.commit().await?;
        Ok(grant)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the claim and revocation race must remain one auditable lock-scoped transaction"
    )]
    pub async fn claim_device_handoff_grant(
        &self,
        client: &mut Client,
        scope: &CellScope,
        claim: &DeviceHandoffClaim,
    ) -> Result<DeviceHandoffMutationResult, CloudStorageError> {
        scope.validate(self.cell)?;
        if claim.tenant_id != scope.tenant_id {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let grant = load_device_handoff_grant_tx(
            &transaction,
            scope,
            &claim.project_id,
            &claim.grant_id,
            true,
        )
        .await?
        .ok_or(CloudStorageError::DeviceHandoffGrantNotFound)?;
        claim.validate_against(&grant)?;
        let request_digest = claim.request_digest()?;
        if let Some(existing) = transaction
            .query_opt(
                "SELECT request_digest
                 FROM hartevo_cell.device_handoff_claims
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND grant_id = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &claim.project_id.as_str(),
                    &claim.grant_id.as_str(),
                ],
            )
            .await?
        {
            ensure_request_digest(&existing.get::<_, String>(0), &request_digest)?;
            transaction.commit().await?;
            return Ok(DeviceHandoffMutationResult {
                grant_id: claim.grant_id.clone(),
                duplicate: true,
            });
        }
        if transaction
            .query_opt(
                "SELECT 1 FROM hartevo_cell.device_handoff_claims
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &claim.project_id.as_str(),
                    &claim.idempotency_key_digest,
                ],
            )
            .await?
            .is_some()
        {
            return Err(CloudStorageError::IdempotencyConflict);
        }
        if handoff_is_revoked(&transaction, scope, &claim.project_id, &claim.grant_id).await? {
            return Err(CloudStorageError::DeviceHandoffRevoked);
        }
        if handoff_is_consumed(&transaction, scope, &claim.project_id, &claim.grant_id).await? {
            return Err(CloudStorageError::DeviceHandoffAlreadyConsumed);
        }
        let target_registration = load_device_public_key_tx(
            &transaction,
            scope,
            &claim.project_id,
            &claim.target_device_id,
            true,
        )
        .await?
        .ok_or(CloudStorageError::DevicePublicKeyNotFound)?;
        if !target_registration.is_active(claim.claimed_at)
            || target_registration.public_key_digest != claim.target_public_key_digest
        {
            return Err(CloudStorageError::InvalidDeviceHandoffTarget);
        }
        let claim_json = serde_json::to_value(claim)?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_handoff_claims
                   (cell, tenant_id, project_id, grant_id, claim_id,
                    target_device_id, target_public_key_digest, idempotency_key,
                    request_digest, claim_json, claimed_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &claim.project_id.as_str(),
                    &claim.grant_id.as_str(),
                    &claim.claim_id.as_str(),
                    &claim.target_device_id.as_str(),
                    &claim.target_public_key_digest,
                    &claim.idempotency_key_digest,
                    &request_digest,
                    &claim_json,
                    &claim.claimed_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(DeviceHandoffMutationResult {
            grant_id: claim.grant_id.clone(),
            duplicate: false,
        })
    }

    pub async fn revoke_device_handoff_grant(
        &self,
        client: &mut Client,
        scope: &CellScope,
        revocation: &DeviceHandoffRevocation,
    ) -> Result<DeviceHandoffMutationResult, CloudStorageError> {
        scope.validate(self.cell)?;
        if revocation.tenant_id != scope.tenant_id {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let grant = load_device_handoff_grant_tx(
            &transaction,
            scope,
            &revocation.project_id,
            &revocation.grant_id,
            true,
        )
        .await?
        .ok_or(CloudStorageError::DeviceHandoffGrantNotFound)?;
        revocation.validate_against(&grant)?;
        let request_digest = revocation.request_digest()?;
        if let Some(existing) = transaction
            .query_opt(
                "SELECT request_digest
                 FROM hartevo_cell.device_handoff_revocations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND grant_id = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &revocation.project_id.as_str(),
                    &revocation.grant_id.as_str(),
                ],
            )
            .await?
        {
            ensure_request_digest(&existing.get::<_, String>(0), &request_digest)?;
            transaction.commit().await?;
            return Ok(DeviceHandoffMutationResult {
                grant_id: revocation.grant_id.clone(),
                duplicate: true,
            });
        }
        if handoff_is_consumed(
            &transaction,
            scope,
            &revocation.project_id,
            &revocation.grant_id,
        )
        .await?
        {
            return Err(CloudStorageError::DeviceHandoffAlreadyConsumed);
        }
        if handoff_is_claimed(
            &transaction,
            scope,
            &revocation.project_id,
            &revocation.grant_id,
        )
        .await?
        {
            return Err(CloudStorageError::DeviceHandoffAlreadyClaimed);
        }
        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_handoff_revocations
                   (cell, tenant_id, project_id, grant_id, revoked_by,
                    authorization_evidence_digest, idempotency_key, request_digest,
                    revoked_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &revocation.project_id.as_str(),
                    &revocation.grant_id.as_str(),
                    &revocation.revoked_by.as_str(),
                    &revocation.authorization_evidence_digest,
                    &revocation.idempotency_key_digest,
                    &request_digest,
                    &revocation.revoked_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(DeviceHandoffMutationResult {
            grant_id: revocation.grant_id.clone(),
            duplicate: false,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "final consumption atomically verifies Claim, target key, published attachment manifest, and single-use receipt"
    )]
    pub async fn consume_device_handoff_grant(
        &self,
        client: &mut Client,
        scope: &CellScope,
        consumption: &DeviceHandoffConsumption,
    ) -> Result<DeviceHandoffMutationResult, CloudStorageError> {
        scope.validate(self.cell)?;
        if consumption.tenant_id != scope.tenant_id {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let grant = load_device_handoff_grant_tx(
            &transaction,
            scope,
            &consumption.project_id,
            &consumption.grant_id,
            true,
        )
        .await?
        .ok_or(CloudStorageError::DeviceHandoffGrantNotFound)?;
        let claim = load_device_handoff_claim_tx(
            &transaction,
            scope,
            &consumption.project_id,
            &consumption.grant_id,
        )
        .await?
        .ok_or(CloudStorageError::DeviceHandoffNotClaimed)?;
        consumption.validate_against(&grant, &claim)?;
        let request_digest = consumption.request_digest()?;
        if let Some(existing) = transaction
            .query_opt(
                "SELECT request_digest
                 FROM hartevo_cell.device_handoff_consumptions
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND grant_id = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &consumption.project_id.as_str(),
                    &consumption.grant_id.as_str(),
                ],
            )
            .await?
        {
            ensure_request_digest(&existing.get::<_, String>(0), &request_digest)?;
            transaction.commit().await?;
            return Ok(DeviceHandoffMutationResult {
                grant_id: consumption.grant_id.clone(),
                duplicate: true,
            });
        }
        if handoff_is_revoked(
            &transaction,
            scope,
            &consumption.project_id,
            &consumption.grant_id,
        )
        .await?
        {
            return Err(CloudStorageError::DeviceHandoffRevoked);
        }
        let target_registration = load_device_public_key_tx(
            &transaction,
            scope,
            &consumption.project_id,
            &consumption.target_device_id,
            true,
        )
        .await?
        .ok_or(CloudStorageError::DevicePublicKeyNotFound)?;
        if !target_registration.is_active(consumption.consumed_at)
            || target_registration.public_key_digest != consumption.target_public_key_digest
        {
            return Err(CloudStorageError::InvalidDeviceHandoffTarget);
        }
        let bootstrap =
            load_keyring_bootstrap_tx(&transaction, scope, &consumption.project_id, true)
                .await?
                .ok_or(CloudStorageError::KeyringBootstrapNotFound)?;
        if bootstrap.keyring.revision != consumption.result_keyring_revision
            || bootstrap
                .keyring
                .available_envelope_for_version(
                    &KeyRecipient::Device(consumption.target_device_id.clone()),
                    consumption.key_version,
                    consumption.consumed_at,
                )
                .is_err()
        {
            return Err(CloudStorageError::DeviceHandoffAttachmentNotPublished);
        }
        let key_version = to_sql_u64(consumption.key_version)?;
        let result_revision = to_sql_u64(consumption.result_keyring_revision)?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_handoff_consumptions
                   (cell, tenant_id, project_id, grant_id, claim_id, receipt_id,
                    target_device_id, target_public_key_digest, key_version,
                    attachment_id, result_keyring_revision, receipt_digest,
                    request_digest, consumed_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &consumption.project_id.as_str(),
                    &consumption.grant_id.as_str(),
                    &consumption.claim_id.as_str(),
                    &consumption.receipt_id.as_str(),
                    &consumption.target_device_id.as_str(),
                    &consumption.target_public_key_digest,
                    &key_version,
                    &consumption.attachment_id.as_str(),
                    &result_revision,
                    &consumption.receipt_digest,
                    &request_digest,
                    &consumption.consumed_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(DeviceHandoffMutationResult {
            grant_id: consumption.grant_id.clone(),
            duplicate: false,
        })
    }

    pub async fn apply_encrypted_mutation(
        &self,
        client: &mut Client,
        mutation: &EncryptedSyncMutation,
    ) -> Result<CloudMutationResult, CloudStorageError> {
        mutation.validate(self.cell)?;
        let request_digest = mutation.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &mutation.scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        lock_project(&transaction, &mutation.scope, &mutation.project_id).await?;

        if let Some(existing) = existing_mutation(
            &transaction,
            &mutation.scope,
            &mutation.project_id,
            &mutation.idempotency_key_digest,
            &request_digest,
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(existing);
        }

        let project_exists = transaction
            .query_opt(
                "SELECT 1 FROM hartevo_cell.projects
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
                &[
                    &mutation.scope.cell.as_str(),
                    &mutation.scope.tenant_id.as_str(),
                    &mutation.project_id.as_str(),
                ],
            )
            .await?
            .is_some();
        if !project_exists {
            return Err(CloudStorageError::ProjectNotFound);
        }

        let current_head = transaction
            .query_opt(
                "SELECT current_revision, tombstone, object_kind
                 FROM hartevo_cell.sync_object_heads
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND object_id = $4
                 FOR UPDATE",
                &[
                    &mutation.scope.cell.as_str(),
                    &mutation.scope.tenant_id.as_str(),
                    &mutation.project_id.as_str(),
                    &mutation.object_id,
                ],
            )
            .await?
            .map(|row| {
                Ok::<_, CloudStorageError>(CurrentSyncHead {
                    revision: from_sql_u64(row.get::<_, i64>(0), "object revision")?,
                    tombstone: row.get::<_, bool>(1),
                    object_kind: row.get::<_, String>(2),
                })
            })
            .transpose()?;
        let next_revision = next_object_revision(mutation, current_head.as_ref())?;
        let event_type = if mutation.tombstone {
            format!("sync.{}.deleted", mutation.object_kind.as_str())
        } else {
            format!("sync.{}.upserted", mutation.object_kind.as_str())
        };
        let result = write_revision(
            &transaction,
            &RevisionWrite {
                scope: &mutation.scope,
                project_id: &mutation.project_id,
                object_id: &mutation.object_id,
                object_kind: mutation.object_kind,
                revision: next_revision,
                payload: &mutation.payload,
                tombstone: mutation.tombstone,
                idempotency_key_digest: &mutation.idempotency_key_digest,
                request_digest: &request_digest,
                recorded_at: mutation.recorded_at,
                event_type: &event_type,
            },
        )
        .await?;
        if mutation.tombstone {
            purge_deleted_object_history(
                &transaction,
                &mutation.scope,
                &mutation.project_id,
                &mutation.object_id,
                next_revision,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn load_encrypted_object(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        object_id: &str,
    ) -> Result<EncryptedSyncObject, CloudStorageError> {
        scope.validate(self.cell)?;
        if project_id.as_str().trim().is_empty() || object_id.trim().is_empty() {
            return Err(CloudStorageError::InvalidSyncMutation);
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let row = transaction
            .query_opt(
                "SELECT h.object_kind, h.current_revision, v.key_version, v.nonce,
                        v.ciphertext, v.aad_digest, v.content_digest, v.tombstone, v.recorded_at
                 FROM hartevo_cell.sync_object_heads h
                 JOIN hartevo_cell.sync_object_versions v
                   ON v.cell = h.cell AND v.tenant_id = h.tenant_id
                  AND v.project_id = h.project_id AND v.object_id = h.object_id
                  AND v.revision = h.current_revision
                 WHERE h.cell = $1 AND h.tenant_id = $2
                   AND h.project_id = $3 AND h.object_id = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &object_id,
                ],
            )
            .await?
            .ok_or(CloudStorageError::SyncObjectNotFound)?;
        let object = decode_sync_object(&row, scope, project_id, object_id)?;
        transaction.commit().await?;
        Ok(object)
    }

    pub async fn claim_outbox(
        &self,
        client: &mut Client,
        scope: &CellScope,
        owner: &str,
        now: DateTime<Utc>,
        lease_for: Duration,
        limit: usize,
    ) -> Result<Vec<CloudOutboxMessage>, CloudStorageError> {
        scope.validate(self.cell)?;
        if owner.trim().is_empty() || lease_for <= Duration::zero() || limit == 0 {
            return Err(CloudStorageError::InvalidOutboxClaim);
        }
        let limit = i64::try_from(limit).map_err(|_| CloudStorageError::InvalidOutboxClaim)?;
        let lease_expires_at = now
            .checked_add_signed(lease_for)
            .ok_or(CloudStorageError::InvalidOutboxClaim)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let rows = transaction
            .query(
                CLAIM_OUTBOX_SQL,
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &now,
                    &limit,
                    &owner,
                    &lease_expires_at,
                ],
            )
            .await?;
        let messages = rows
            .into_iter()
            .map(|row| decode_outbox_message(&row))
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await?;
        Ok(messages)
    }

    pub async fn acknowledge_outbox(
        &self,
        client: &mut Client,
        scope: &CellScope,
        sequence: i64,
        owner: &str,
        generation: u64,
        times: OutboxAcknowledgeTimes,
    ) -> Result<(), CloudStorageError> {
        self.finish_outbox_lease(
            client,
            scope,
            sequence,
            owner,
            generation,
            OutboxCompletion::Acknowledge(times),
        )
        .await
    }

    pub async fn release_outbox(
        &self,
        client: &mut Client,
        scope: &CellScope,
        sequence: i64,
        owner: &str,
        generation: u64,
        release: OutboxRelease,
    ) -> Result<(), CloudStorageError> {
        self.finish_outbox_lease(
            client,
            scope,
            sequence,
            owner,
            generation,
            OutboxCompletion::Release(release),
        )
        .await
    }

    async fn finish_outbox_lease(
        &self,
        client: &mut Client,
        scope: &CellScope,
        sequence: i64,
        owner: &str,
        generation: u64,
        completion: OutboxCompletion,
    ) -> Result<(), CloudStorageError> {
        scope.validate(self.cell)?;
        if sequence <= 0 || owner.trim().is_empty() || generation == 0 {
            return Err(CloudStorageError::InvalidOutboxClaim);
        }
        match &completion {
            OutboxCompletion::Acknowledge(times) => times.validate()?,
            OutboxCompletion::Release(
                OutboxRelease::Requeue(times) | OutboxRelease::DeadLetter(times),
            ) => times.validate()?,
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell).await?;
        let updated = match completion {
            OutboxCompletion::Acknowledge(times) => {
                transaction
                    .execute(
                        ACKNOWLEDGE_OUTBOX_SQL,
                        &[
                            &scope.cell.as_str(),
                            &scope.tenant_id.as_str(),
                            &sequence,
                            &owner,
                            &to_sql_u64(generation)?,
                            &times.published_at,
                            &times.operation_at,
                        ],
                    )
                    .await?
            }
            OutboxCompletion::Release(release) => {
                let (status, times) = match release {
                    OutboxRelease::Requeue(times) => ("pending", times),
                    OutboxRelease::DeadLetter(times) => ("dead_letter", times),
                };
                transaction
                    .execute(
                        RELEASE_OUTBOX_SQL,
                        &[
                            &scope.cell.as_str(),
                            &scope.tenant_id.as_str(),
                            &sequence,
                            &owner,
                            &to_sql_u64(generation)?,
                            &status,
                            &times.available_at,
                            &times.operation_at,
                        ],
                    )
                    .await?
            }
        };
        if updated != 1 {
            return Err(CloudStorageError::OutboxLeaseLost {
                sequence,
                owner: owner.into(),
                generation,
            });
        }
        transaction.commit().await?;
        Ok(())
    }
}

async fn set_scope(
    transaction: &Transaction<'_>,
    scope: &CellScope,
) -> Result<(), CloudStorageError> {
    transaction
        .query_one(
            "SELECT set_config('hartevo.tenant_id', $1, true),
                    set_config('hartevo.cell', $2, true)",
            &[&scope.tenant_id.as_str(), &scope.cell.as_str()],
        )
        .await?;
    Ok(())
}

async fn ensure_database_cell(
    transaction: &Transaction<'_>,
    expected: DataCell,
) -> Result<(), CloudStorageError> {
    let configured: String = transaction
        .query_opt(
            "SELECT cell FROM hartevo_cell.cell_configuration WHERE singleton = TRUE",
            &[],
        )
        .await?
        .ok_or(CloudStorageError::DatabaseNotMigrated)?
        .get(0);
    if configured != expected.as_str() {
        return Err(CloudStorageError::DatabaseCellMismatch);
    }
    Ok(())
}

async fn lock_project(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
) -> Result<(), CloudStorageError> {
    let lock_scope = format!(
        "{}:{}:{}",
        scope.cell,
        scope.tenant_id.as_str(),
        project_id.as_str()
    );
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&lock_scope],
        )
        .await?;
    Ok(())
}

async fn ensure_project_exists(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
) -> Result<(), CloudStorageError> {
    if transaction
        .query_opt(
            "SELECT 1 FROM hartevo_cell.projects
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await?
        .is_none()
    {
        return Err(CloudStorageError::ProjectNotFound);
    }
    Ok(())
}

async fn load_project_mode(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
) -> Result<ProjectEncryptionMode, CloudStorageError> {
    let value = transaction
        .query_opt(
            "SELECT encryption_mode FROM hartevo_cell.projects
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await?
        .ok_or(CloudStorageError::ProjectNotFound)?
        .get::<_, String>(0);
    decode_encryption_mode(&value)
}

async fn load_device_public_key_tx(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    device_id: &DeviceId,
    lock: bool,
) -> Result<Option<DevicePublicKeyRegistration>, CloudStorageError> {
    let base = "SELECT v.revision, v.algorithm, v.public_key, v.public_key_digest,
                       v.authorized_by, v.authorization_evidence_digest,
                       v.idempotency_key, v.registered_at, v.updated_at, v.revoked_at
                FROM hartevo_cell.device_public_key_heads h
                JOIN hartevo_cell.device_public_key_versions v
                  ON v.cell = h.cell AND v.tenant_id = h.tenant_id
                 AND v.project_id = h.project_id AND v.device_id = h.device_id
                 AND v.revision = h.current_revision
                WHERE h.cell = $1 AND h.tenant_id = $2
                  AND h.project_id = $3 AND h.device_id = $4";
    let sql = if lock {
        format!("{base} FOR UPDATE OF h")
    } else {
        base.to_owned()
    };
    let Some(row) = transaction
        .query_opt(
            &sql,
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &device_id.as_str(),
            ],
        )
        .await?
    else {
        return Ok(None);
    };
    let registration = DevicePublicKeyRegistration {
        tenant_id: scope.tenant_id.clone(),
        project_id: project_id.clone(),
        device_id: device_id.clone(),
        revision: from_sql_u64(row.get(0), "device public key revision")?,
        algorithm: decode_device_key_algorithm(&row.get::<_, String>(1))?,
        public_key: row.get(2),
        public_key_digest: row.get(3),
        authorized_by: ActorId::from_stable(row.get::<_, String>(4)),
        authorization_evidence_digest: row.get(5),
        idempotency_key_digest: row.get(6),
        registered_at: row.get(7),
        updated_at: row.get(8),
        revoked_at: row.get(9),
    };
    registration.validate()?;
    Ok(Some(registration))
}

async fn load_keyring_bootstrap_tx(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    lock: bool,
) -> Result<Option<ProjectKeyringBootstrap>, CloudStorageError> {
    let base = "SELECT v.bootstrap_json
                FROM hartevo_cell.keyring_bootstrap_heads h
                JOIN hartevo_cell.keyring_bootstrap_versions v
                  ON v.cell = h.cell AND v.tenant_id = h.tenant_id
                 AND v.project_id = h.project_id
                 AND v.keyring_revision = h.current_keyring_revision
                WHERE h.cell = $1 AND h.tenant_id = $2 AND h.project_id = $3";
    let sql = if lock {
        format!("{base} FOR UPDATE OF h")
    } else {
        base.to_owned()
    };
    let Some(row) = transaction
        .query_opt(
            &sql,
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await?
    else {
        return Ok(None);
    };
    let bootstrap = serde_json::from_value::<ProjectKeyringBootstrap>(row.get(0))?;
    bootstrap.validate()?;
    Ok(Some(bootstrap))
}

async fn load_device_handoff_grant_tx(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    grant_id: &DeviceHandoffId,
    lock: bool,
) -> Result<Option<DeviceHandoffGrant>, CloudStorageError> {
    let base = "SELECT grant_json FROM hartevo_cell.device_handoff_grants
                WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND grant_id = $4";
    let sql = if lock {
        format!("{base} FOR UPDATE")
    } else {
        base.to_owned()
    };
    let Some(row) = transaction
        .query_opt(
            &sql,
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &grant_id.as_str(),
            ],
        )
        .await?
    else {
        return Ok(None);
    };
    let grant = serde_json::from_value::<DeviceHandoffGrant>(row.get(0))?;
    grant.validate()?;
    Ok(Some(grant))
}

async fn handoff_is_revoked(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    grant_id: &DeviceHandoffId,
) -> Result<bool, CloudStorageError> {
    Ok(transaction
        .query_opt(
            "SELECT 1 FROM hartevo_cell.device_handoff_revocations
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND grant_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &grant_id.as_str(),
            ],
        )
        .await?
        .is_some())
}

async fn handoff_is_consumed(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    grant_id: &DeviceHandoffId,
) -> Result<bool, CloudStorageError> {
    Ok(transaction
        .query_opt(
            "SELECT 1 FROM hartevo_cell.device_handoff_consumptions
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND grant_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &grant_id.as_str(),
            ],
        )
        .await?
        .is_some())
}

async fn handoff_is_claimed(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    grant_id: &DeviceHandoffId,
) -> Result<bool, CloudStorageError> {
    Ok(transaction
        .query_opt(
            "SELECT 1 FROM hartevo_cell.device_handoff_claims
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND grant_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &grant_id.as_str(),
            ],
        )
        .await?
        .is_some())
}

async fn load_device_handoff_claim_tx(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    grant_id: &DeviceHandoffId,
) -> Result<Option<DeviceHandoffClaim>, CloudStorageError> {
    let Some(row) = transaction
        .query_opt(
            "SELECT claim_json FROM hartevo_cell.device_handoff_claims
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND grant_id = $4
             FOR UPDATE",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &grant_id.as_str(),
            ],
        )
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_value(row.get(0))?))
}

fn ensure_request_digest(stored: &str, requested: &str) -> Result<(), CloudStorageError> {
    if stored != requested {
        return Err(CloudStorageError::IdempotencyConflict);
    }
    Ok(())
}

async fn existing_mutation(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    idempotency_key_digest: &str,
    request_digest: &str,
) -> Result<Option<CloudMutationResult>, CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT request_digest, object_revision, event_sequence, outbox_sequence
             FROM hartevo_cell.sync_mutations
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND idempotency_key = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &idempotency_key_digest,
            ],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != request_digest {
        return Err(CloudStorageError::IdempotencyConflict);
    }
    Ok(Some(CloudMutationResult {
        object_revision: from_sql_u64(row.get(1), "object revision")?,
        event_sequence: row.get(2),
        outbox_sequence: row.get(3),
        duplicate: true,
    }))
}

struct RevisionWrite<'a> {
    scope: &'a CellScope,
    project_id: &'a ProjectId,
    object_id: &'a str,
    object_kind: SyncObjectKind,
    revision: u64,
    payload: &'a EncryptedPayload,
    tombstone: bool,
    idempotency_key_digest: &'a str,
    request_digest: &'a str,
    recorded_at: DateTime<Utc>,
    event_type: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CurrentSyncHead {
    revision: u64,
    tombstone: bool,
    object_kind: String,
}

fn next_object_revision(
    mutation: &EncryptedSyncMutation,
    current: Option<&CurrentSyncHead>,
) -> Result<u64, CloudStorageError> {
    if current.is_some_and(|head| head.tombstone) {
        return Err(CloudStorageError::SyncObjectDeleted);
    }
    if current.is_some_and(|head| head.object_kind != mutation.object_kind.as_str()) {
        return Err(CloudStorageError::SyncObjectKindMismatch);
    }
    let actual = current.map(|head| head.revision);
    match (mutation.precondition, actual) {
        (MutationPrecondition::CreateOnly, None) => Ok(1),
        (MutationPrecondition::ExactRevision(expected), Some(actual)) if expected == actual => {
            expected
                .checked_add(1)
                .ok_or(CloudStorageError::RevisionOverflow)
        }
        (precondition, actual) => Err(CloudStorageError::OptimisticConflict {
            expected: precondition,
            actual,
        }),
    }
}

async fn write_revision(
    transaction: &Transaction<'_>,
    write: &RevisionWrite<'_>,
) -> Result<CloudMutationResult, CloudStorageError> {
    persist_object_revision(transaction, write).await?;
    let event_sequence = append_encrypted_event(transaction, write).await?;
    let outbox_sequence = append_encrypted_outbox(transaction, write, event_sequence).await?;
    record_sync_mutation(transaction, write, event_sequence, outbox_sequence).await?;
    Ok(CloudMutationResult {
        object_revision: write.revision,
        event_sequence,
        outbox_sequence,
        duplicate: false,
    })
}

async fn purge_deleted_object_history(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    object_id: &str,
    tombstone_revision: u64,
) -> Result<(), CloudStorageError> {
    let revision = to_sql_u64(tombstone_revision)?;
    let parameters: [&(dyn tokio_postgres::types::ToSql + Sync); 5] = [
        &scope.cell.as_str(),
        &scope.tenant_id.as_str(),
        &project_id.as_str(),
        &object_id,
        &revision,
    ];
    transaction
        .execute(
            "DELETE FROM hartevo_cell.sync_mutations
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND object_id = $4 AND object_revision < $5",
            &parameters,
        )
        .await?;
    transaction
        .execute(
            "DELETE FROM hartevo_cell.outbox_messages
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND object_id = $4 AND object_revision < $5",
            &parameters,
        )
        .await?;
    transaction
        .execute(
            "DELETE FROM hartevo_cell.domain_events
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND aggregate_type = 'sync_object' AND aggregate_id = $4
               AND object_revision < $5",
            &parameters,
        )
        .await?;
    transaction
        .execute(
            "DELETE FROM hartevo_cell.sync_object_versions
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND object_id = $4 AND revision < $5",
            &parameters,
        )
        .await?;
    Ok(())
}

async fn persist_object_revision(
    transaction: &Transaction<'_>,
    write: &RevisionWrite<'_>,
) -> Result<(), CloudStorageError> {
    let revision_sql = to_sql_u64(write.revision)?;
    let key_version_sql = to_sql_u64(write.payload.key_version)?;
    transaction
        .execute(
            "INSERT INTO hartevo_cell.sync_object_versions
               (cell, tenant_id, project_id, object_id, object_kind, revision, key_version,
                nonce, ciphertext, aad_digest, content_digest, tombstone, recorded_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            &[
                &write.scope.cell.as_str(),
                &write.scope.tenant_id.as_str(),
                &write.project_id.as_str(),
                &write.object_id,
                &write.object_kind.as_str(),
                &revision_sql,
                &key_version_sql,
                &write.payload.nonce,
                &write.payload.ciphertext,
                &write.payload.aad_digest,
                &write.payload.content_digest,
                &write.tombstone,
                &write.recorded_at,
            ],
        )
        .await?;

    if write.revision == 1 {
        transaction
            .execute(
                "INSERT INTO hartevo_cell.sync_object_heads
                   (cell, tenant_id, project_id, object_id, object_kind, current_revision,
                    key_version, content_digest, tombstone, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    &write.scope.cell.as_str(),
                    &write.scope.tenant_id.as_str(),
                    &write.project_id.as_str(),
                    &write.object_id,
                    &write.object_kind.as_str(),
                    &revision_sql,
                    &key_version_sql,
                    &write.payload.content_digest,
                    &write.tombstone,
                    &write.recorded_at,
                ],
            )
            .await?;
    } else {
        let previous_revision = write
            .revision
            .checked_sub(1)
            .ok_or(CloudStorageError::RevisionOverflow)?;
        let updated = transaction
            .execute(
                "UPDATE hartevo_cell.sync_object_heads
                 SET object_kind = $5, current_revision = $6, key_version = $7,
                     content_digest = $8, tombstone = $9, updated_at = $10
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND object_id = $4
                   AND current_revision = $11",
                &[
                    &write.scope.cell.as_str(),
                    &write.scope.tenant_id.as_str(),
                    &write.project_id.as_str(),
                    &write.object_id,
                    &write.object_kind.as_str(),
                    &revision_sql,
                    &key_version_sql,
                    &write.payload.content_digest,
                    &write.tombstone,
                    &write.recorded_at,
                    &to_sql_u64(previous_revision)?,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(CloudStorageError::OptimisticConflict {
                expected: MutationPrecondition::ExactRevision(previous_revision),
                actual: None,
            });
        }
    }
    Ok(())
}

async fn append_encrypted_event(
    transaction: &Transaction<'_>,
    write: &RevisionWrite<'_>,
) -> Result<i64, CloudStorageError> {
    Ok(transaction
        .query_one(
            "INSERT INTO hartevo_cell.domain_events
               (cell, tenant_id, project_id, aggregate_type, aggregate_id, event_type,
                object_revision, key_version, nonce, payload_ciphertext, aad_digest,
                content_digest, tombstone, recorded_at)
             VALUES ($1, $2, $3, 'sync_object', $4, $5, $6, $7, $8, $9, $10,
                     $11, $12, $13)
             RETURNING sequence",
            &[
                &write.scope.cell.as_str(),
                &write.scope.tenant_id.as_str(),
                &write.project_id.as_str(),
                &write.object_id,
                &write.event_type,
                &to_sql_u64(write.revision)?,
                &to_sql_u64(write.payload.key_version)?,
                &write.payload.nonce,
                &write.payload.ciphertext,
                &write.payload.aad_digest,
                &write.payload.content_digest,
                &write.tombstone,
                &write.recorded_at,
            ],
        )
        .await?
        .get(0))
}

async fn append_encrypted_outbox(
    transaction: &Transaction<'_>,
    write: &RevisionWrite<'_>,
    event_sequence: i64,
) -> Result<i64, CloudStorageError> {
    Ok(transaction
        .query_one(
            "INSERT INTO hartevo_cell.outbox_messages
               (cell, tenant_id, project_id, event_sequence, event_type, object_id,
                object_revision, key_version, nonce, payload_ciphertext, aad_digest,
                content_digest, tombstone, idempotency_key, available_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                     $14, $15, $15)
             RETURNING sequence",
            &[
                &write.scope.cell.as_str(),
                &write.scope.tenant_id.as_str(),
                &write.project_id.as_str(),
                &event_sequence,
                &write.event_type,
                &write.object_id,
                &to_sql_u64(write.revision)?,
                &to_sql_u64(write.payload.key_version)?,
                &write.payload.nonce,
                &write.payload.ciphertext,
                &write.payload.aad_digest,
                &write.payload.content_digest,
                &write.tombstone,
                &write.idempotency_key_digest,
                &write.recorded_at,
            ],
        )
        .await?
        .get(0))
}

async fn record_sync_mutation(
    transaction: &Transaction<'_>,
    write: &RevisionWrite<'_>,
    event_sequence: i64,
    outbox_sequence: i64,
) -> Result<(), CloudStorageError> {
    transaction
        .execute(
            "INSERT INTO hartevo_cell.sync_mutations
               (cell, tenant_id, project_id, idempotency_key, request_digest, object_id,
                object_revision, content_digest, event_sequence, outbox_sequence, recorded_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            &[
                &write.scope.cell.as_str(),
                &write.scope.tenant_id.as_str(),
                &write.project_id.as_str(),
                &write.idempotency_key_digest,
                &write.request_digest,
                &write.object_id,
                &to_sql_u64(write.revision)?,
                &write.payload.content_digest,
                &event_sequence,
                &outbox_sequence,
                &write.recorded_at,
            ],
        )
        .await?;
    Ok(())
}

fn decode_sync_object(
    row: &Row,
    scope: &CellScope,
    project_id: &ProjectId,
    object_id: &str,
) -> Result<EncryptedSyncObject, CloudStorageError> {
    let object_kind = decode_object_kind(&row.get::<_, String>(0))?;
    let payload = EncryptedPayload {
        key_version: from_sql_u64(row.get(2), "key version")?,
        nonce: row.get(3),
        ciphertext: row.get(4),
        aad_digest: row.get(5),
        content_digest: row.get(6),
    };
    payload.validate()?;
    Ok(EncryptedSyncObject {
        scope: scope.clone(),
        project_id: project_id.clone(),
        object_id: object_id.into(),
        object_kind,
        revision: from_sql_u64(row.get(1), "object revision")?,
        payload,
        tombstone: row.get(7),
        recorded_at: row.get(8),
    })
}

fn decode_outbox_message(row: &Row) -> Result<CloudOutboxMessage, CloudStorageError> {
    let cell = decode_cell(&row.get::<_, String>(1))?;
    let payload = EncryptedPayload {
        key_version: from_sql_u64(row.get(8), "key version")?,
        nonce: row.get(9),
        ciphertext: row.get(10),
        aad_digest: row.get(11),
        content_digest: row.get(12),
    };
    payload.validate()?;
    Ok(CloudOutboxMessage {
        sequence: row.get(0),
        scope: CellScope {
            cell,
            tenant_id: TenantId::from_stable(row.get::<_, String>(2)),
        },
        project_id: ProjectId::from_stable(row.get::<_, String>(3)),
        event_sequence: row.get(4),
        event_type: row.get(5),
        object_id: row.get(6),
        object_revision: from_sql_u64(row.get(7), "object revision")?,
        payload,
        tombstone: row.get(13),
        idempotency_key_digest: row.get(14),
        status: decode_outbox_status(&row.get::<_, String>(15))?,
        attempts: u32::try_from(row.get::<_, i32>(16))
            .map_err(|_| CloudStorageError::StoredValueInvalid("attempts".into()))?,
        available_at: row.get(17),
        lease_owner: row.get(18),
        lease_generation: from_sql_u64(row.get(19), "lease generation")?,
        lease_expires_at: row.get(20),
        created_at: row.get(21),
        published_at: row.get(22),
    })
}

fn decode_cell(value: &str) -> Result<DataCell, CloudStorageError> {
    match value {
        "us" => Ok(DataCell::Us),
        "eu" => Ok(DataCell::Eu),
        other => Err(CloudStorageError::StoredValueInvalid(format!(
            "data cell {other}"
        ))),
    }
}

fn decode_object_kind(value: &str) -> Result<SyncObjectKind, CloudStorageError> {
    match value {
        "project_metadata" => Ok(SyncObjectKind::ProjectMetadata),
        "project_truth" => Ok(SyncObjectKind::ProjectTruth),
        "mission" => Ok(SyncObjectKind::Mission),
        "work_product" => Ok(SyncObjectKind::WorkProduct),
        "conversation" => Ok(SyncObjectKind::Conversation),
        "connection_metadata" => Ok(SyncObjectKind::ConnectionMetadata),
        "creator_work" => Ok(SyncObjectKind::CreatorWork),
        "outcome_ledger" => Ok(SyncObjectKind::OutcomeLedger),
        "context_capsule" => Ok(SyncObjectKind::ContextCapsule),
        other => Err(CloudStorageError::StoredValueInvalid(format!(
            "sync object kind {other}"
        ))),
    }
}

fn decode_outbox_status(value: &str) -> Result<CloudOutboxStatus, CloudStorageError> {
    match value {
        "pending" => Ok(CloudOutboxStatus::Pending),
        "leased" => Ok(CloudOutboxStatus::Leased),
        "published" => Ok(CloudOutboxStatus::Published),
        "dead_letter" => Ok(CloudOutboxStatus::DeadLetter),
        other => Err(CloudStorageError::StoredValueInvalid(format!(
            "outbox status {other}"
        ))),
    }
}

fn encryption_mode_name(mode: &ProjectEncryptionMode) -> &'static str {
    match mode {
        ProjectEncryptionMode::PersonalE2ee => "personal_e2ee",
        ProjectEncryptionMode::TeamEnvelope => "team_envelope",
    }
}

fn decode_encryption_mode(value: &str) -> Result<ProjectEncryptionMode, CloudStorageError> {
    match value {
        "personal_e2ee" => Ok(ProjectEncryptionMode::PersonalE2ee),
        "team_envelope" => Ok(ProjectEncryptionMode::TeamEnvelope),
        other => Err(CloudStorageError::StoredValueInvalid(format!(
            "project encryption mode {other}"
        ))),
    }
}

const fn device_key_algorithm_name(algorithm: DeviceKeyAgreementAlgorithm) -> &'static str {
    match algorithm {
        DeviceKeyAgreementAlgorithm::X25519HkdfSha256Aes256GcmV1 => {
            "x25519_hkdf_sha256_aes256_gcm_v1"
        }
    }
}

fn decode_device_key_algorithm(
    value: &str,
) -> Result<DeviceKeyAgreementAlgorithm, CloudStorageError> {
    match value {
        "x25519_hkdf_sha256_aes256_gcm_v1" => {
            Ok(DeviceKeyAgreementAlgorithm::X25519HkdfSha256Aes256GcmV1)
        }
        other => Err(CloudStorageError::StoredValueInvalid(format!(
            "device key agreement algorithm {other}"
        ))),
    }
}

fn schema_digest() -> String {
    format!("{:x}", Sha256::digest(SCHEMA.as_bytes()))
}

fn canonical_digest(value: &serde_json::Value) -> Result<String, CloudStorageError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn to_sql_u64(value: u64) -> Result<i64, CloudStorageError> {
    i64::try_from(value).map_err(|_| CloudStorageError::RevisionOverflow)
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, CloudStorageError> {
    u64::try_from(value).map_err(|_| CloudStorageError::StoredValueInvalid(field.into()))
}

#[derive(Debug, Error)]
pub enum CloudStorageError {
    #[error(transparent)]
    Postgres(#[from] tokio_postgres::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    KeyManagement(#[from] KeyManagementError),
    #[error(transparent)]
    EffectLedger(#[from] hartevo_effect_broker::LedgerError),
    #[error("request cell or tenant does not match this physical Cell")]
    CellOrTenantScopeMismatch,
    #[error("PostgreSQL database is configured for a different physical Cell")]
    DatabaseCellMismatch,
    #[error("PostgreSQL Cell schema has not been migrated")]
    DatabaseNotMigrated,
    #[error("PostgreSQL migration checksum differs from the compiled migration")]
    MigrationChecksumMismatch,
    #[error("encrypted sync payload, nonce, digest, size, or key version is invalid")]
    InvalidEncryptedPayload,
    #[error("cloud project registration or encryption boundary is invalid")]
    InvalidProjectRegistration,
    #[error("encrypted sync mutation or precondition is invalid")]
    InvalidSyncMutation,
    #[error("tenant has not been registered in this Cell")]
    TenantNotRegistered,
    #[error("project already exists and the request is not an idempotent replay")]
    ProjectAlreadyExists,
    #[error("project is not visible in the exact tenant and Cell scope")]
    ProjectNotFound,
    #[error("device public key is not visible in the exact tenant/project/device scope")]
    DevicePublicKeyNotFound,
    #[error("device public-key revision is not the exact next transition")]
    InvalidDevicePublicKeyTransition,
    #[error("project keyring bootstrap is not visible in the exact tenant/project scope")]
    KeyringBootstrapNotFound,
    #[error("project keyring bootstrap is not the exact next aggregate revision")]
    InvalidKeyringBootstrapTransition,
    #[error("project keyring bootstrap is not authorized by the exact previous envelope")]
    InvalidKeyringBootstrapAuthorization,
    #[error("device handoff grant is malformed or does not match the current keyring")]
    InvalidDeviceHandoffGrant,
    #[error("device handoff target public key is revoked, rotated, or mismatched")]
    InvalidDeviceHandoffTarget,
    #[error("device already has an active envelope at the handoff key version")]
    DeviceAlreadyAttached,
    #[error("device handoff grant is not visible in the exact tenant/project scope")]
    DeviceHandoffGrantNotFound,
    #[error("device handoff grant has been revoked")]
    DeviceHandoffRevoked,
    #[error("device handoff grant has already been consumed")]
    DeviceHandoffAlreadyConsumed,
    #[error("device handoff grant has already been claimed and cannot be revoked")]
    DeviceHandoffAlreadyClaimed,
    #[error("device handoff grant must be durably claimed before local decryption")]
    DeviceHandoffNotClaimed,
    #[error("device handoff attachment keyring revision has not been published")]
    DeviceHandoffAttachmentNotPublished,
    #[error("sync object is not visible in the exact tenant, project, and Cell scope")]
    SyncObjectNotFound,
    #[error("sync object has a permanent tombstone and cannot be recreated")]
    SyncObjectDeleted,
    #[error("sync object kind cannot change under the same project/object identity")]
    SyncObjectKindMismatch,
    #[error("idempotency key was reused for a different encrypted request")]
    IdempotencyConflict,
    #[error("sync object optimistic concurrency check failed")]
    OptimisticConflict {
        expected: MutationPrecondition,
        actual: Option<u64>,
    },
    #[error("outbox claim requires a positive lease, bounded limit, and non-empty owner")]
    InvalidOutboxClaim,
    #[error("outbox lease {sequence} owner/generation no longer matches")]
    OutboxLeaseLost {
        sequence: i64,
        owner: String,
        generation: u64,
    },
    #[error("remote Effect execution requires a team project with explicit current opt-in")]
    RemoteEffectExecutionNotAllowed,
    #[error("remote Effect permission fence mutation is malformed or out of scope")]
    InvalidEffectPermissionFence,
    #[error("remote Effect permission fence optimistic concurrency check failed")]
    EffectPermissionFenceConflict {
        expected: MutationPrecondition,
        actual: Option<u64>,
    },
    #[error("remote Effect execution lease owner or generation is no longer current")]
    EffectLeaseLost,
    #[error("stored PostgreSQL value is invalid: {0}")]
    StoredValueInvalid(String),
    #[error("revision or generation exceeds the supported PostgreSQL range")]
    RevisionOverflow,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        DeviceAttachmentId, DeviceHandoffCiphertext, DeviceHandoffContext, KeyEnvelope,
        KeyEnvelopeId, KeyWrapAlgorithm, ProjectKeyring, ReceiptId, WrappedKeyCiphertext,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 18, 0, 0)
            .single()
            .expect("valid time")
    }

    fn payload(byte: u8) -> EncryptedPayload {
        let ciphertext = vec![byte; 48];
        EncryptedPayload {
            key_version: 1,
            nonce: vec![byte; 12],
            content_digest: format!("{:x}", Sha256::digest(&ciphertext)),
            ciphertext,
            aad_digest: "a".repeat(64),
        }
    }

    fn scope(cell: DataCell) -> CellScope {
        CellScope {
            cell,
            tenant_id: TenantId::from("tenant-1"),
        }
    }

    fn key_envelope(
        project_id: &ProjectId,
        id: &str,
        recipient: KeyRecipient,
        created_at: DateTime<Utc>,
    ) -> KeyEnvelope {
        KeyEnvelope {
            id: KeyEnvelopeId::from_stable(id),
            tenant_id: TenantId::from("placeholder"),
            project_id: project_id.clone(),
            key_version: 1,
            recipient,
            wrapping_key_reference_digest: "8".repeat(64),
            sealed_key: WrappedKeyCiphertext {
                algorithm: KeyWrapAlgorithm::Aes256GcmV1,
                nonce: vec![2; 12],
                ciphertext: vec![3; 48],
                aad_digest: "9".repeat(64),
            },
            created_at,
            expires_at: None,
            revoked_at: None,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper keeps every cryptographic and optimistic-concurrency scope explicit"
    )]
    fn handoff_grant(
        tenant_id: &TenantId,
        project_id: &ProjectId,
        source: KeyRecipient,
        source_envelope_digest: String,
        source_keyring_manifest_digest: String,
        target: &DevicePublicKeyRegistration,
        grant_id: &str,
        idempotency_byte: char,
        expected_keyring_revision: u64,
        created_at: DateTime<Utc>,
    ) -> DeviceHandoffGrant {
        let context = DeviceHandoffContext {
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            grant_id: DeviceHandoffId::from_stable(grant_id),
            project_mode: ProjectEncryptionMode::PersonalE2ee,
            source_recipient: source,
            source_envelope_digest,
            source_keyring_manifest_digest,
            target_device_id: target.device_id.clone(),
            target_public_key_digest: target.public_key_digest.clone(),
            key_version: 1,
            expected_keyring_revision,
            expires_at: created_at + Duration::hours(1),
        };
        let aad_digest = context.canonical_digest().expect("handoff AAD digest");
        let ciphertext = vec![6; 48];
        DeviceHandoffGrant::prepare(
            context,
            DeviceHandoffCiphertext {
                algorithm: DeviceKeyAgreementAlgorithm::X25519HkdfSha256Aes256GcmV1,
                sender_ephemeral_public_key: vec![5; 32],
                nonce: vec![4; 12],
                content_digest: format!("{:x}", Sha256::digest(&ciphertext)),
                ciphertext,
                aad_digest,
            },
            ActorId::from("user-1"),
            "a".repeat(64),
            idempotency_byte.to_string().repeat(64),
            created_at,
        )
        .expect("valid handoff grant")
    }

    #[test]
    fn cell_scope_and_personal_remote_execution_fail_closed() {
        assert!(matches!(
            scope(DataCell::Eu).validate(DataCell::Us),
            Err(CloudStorageError::CellOrTenantScopeMismatch)
        ));
        let registration = CloudProjectRegistration {
            scope: scope(DataCell::Us),
            project_id: ProjectId::from("project-1"),
            encryption_mode: ProjectEncryptionMode::PersonalE2ee,
            remote_execution_opt_in: true,
            metadata_digest: payload(7).content_digest,
            initial_payload: payload(7),
            idempotency_key_digest: "b".repeat(64),
            created_at: now(),
        };
        assert!(matches!(
            registration.validate(DataCell::Us),
            Err(CloudStorageError::InvalidProjectRegistration)
        ));
    }

    #[test]
    fn encrypted_payload_requires_exact_ciphertext_digest_and_tombstone_revision() {
        let mut invalid_payload = payload(7);
        invalid_payload.content_digest = "c".repeat(64);
        assert!(matches!(
            invalid_payload.validate(),
            Err(CloudStorageError::InvalidEncryptedPayload)
        ));

        let mutation = EncryptedSyncMutation {
            scope: scope(DataCell::Us),
            project_id: ProjectId::from("project-1"),
            object_id: "mission-1".into(),
            object_kind: SyncObjectKind::Mission,
            precondition: MutationPrecondition::CreateOnly,
            payload: payload(8),
            tombstone: true,
            idempotency_key_digest: "d".repeat(64),
            recorded_at: now(),
        };
        assert!(matches!(
            mutation.validate(DataCell::Us),
            Err(CloudStorageError::InvalidSyncMutation)
        ));
    }

    #[test]
    fn idempotency_request_digest_covers_revision_ciphertext_and_tombstone() {
        let base = EncryptedSyncMutation {
            scope: scope(DataCell::Us),
            project_id: ProjectId::from("project-1"),
            object_id: "mission-1".into(),
            object_kind: SyncObjectKind::Mission,
            precondition: MutationPrecondition::ExactRevision(1),
            payload: payload(8),
            tombstone: false,
            idempotency_key_digest: "d".repeat(64),
            recorded_at: now(),
        };
        let mut changed_revision = base.clone();
        changed_revision.precondition = MutationPrecondition::ExactRevision(2);
        let mut changed_payload = base.clone();
        changed_payload.payload = payload(9);
        let mut changed_tombstone = base.clone();
        changed_tombstone.tombstone = true;

        let digest = base.request_digest().expect("digest");
        assert_ne!(digest, changed_revision.request_digest().expect("revision"));
        assert_ne!(digest, changed_payload.request_digest().expect("payload"));
        assert_ne!(
            digest,
            changed_tombstone.request_digest().expect("tombstone")
        );
    }

    #[test]
    fn tombstoned_head_permanently_rejects_resurrection_and_kind_rebinding() {
        let mutation = EncryptedSyncMutation {
            scope: scope(DataCell::Us),
            project_id: ProjectId::from("project-1"),
            object_id: "capsule-1".into(),
            object_kind: SyncObjectKind::ContextCapsule,
            precondition: MutationPrecondition::ExactRevision(3),
            payload: payload(8),
            tombstone: false,
            idempotency_key_digest: "d".repeat(64),
            recorded_at: now(),
        };
        assert!(matches!(
            next_object_revision(
                &mutation,
                Some(&CurrentSyncHead {
                    revision: 3,
                    tombstone: true,
                    object_kind: "context_capsule".into(),
                })
            ),
            Err(CloudStorageError::SyncObjectDeleted)
        ));
        assert!(matches!(
            next_object_revision(
                &mutation,
                Some(&CurrentSyncHead {
                    revision: 3,
                    tombstone: false,
                    object_kind: "mission".into(),
                })
            ),
            Err(CloudStorageError::SyncObjectKindMismatch)
        ));
    }

    #[test]
    fn schema_contract_has_physical_cell_rls_ciphertext_and_append_only_versions() {
        assert_eq!(SCHEMA_VERSION, 4);
        assert!(SCHEMA.contains("FORCE ROW LEVEL SECURITY"));
        assert!(SCHEMA.contains("current_setting(''hartevo.tenant_id'', true)"));
        assert!(SCHEMA.contains("current_setting(''hartevo.cell'', true)"));
        assert!(SCHEMA.contains("sync_object_versions"));
        assert!(SCHEMA.contains("payload_ciphertext BYTEA"));
        assert!(SCHEMA.contains("sync_mutations"));
        assert!(SCHEMA.contains("device_public_key_versions"));
        assert!(SCHEMA.contains("keyring_bootstrap_versions"));
        assert!(SCHEMA.contains("device_handoff_grants"));
        assert!(SCHEMA.contains("device_handoff_claims"));
        assert!(SCHEMA.contains("device_handoff_consumptions"));
        assert!(SCHEMA.contains("effect_permission_fence_versions"));
        assert!(SCHEMA.contains("effect_permission_fence_heads"));
        assert!(SCHEMA.contains("effect_idempotency"));
        assert!(SCHEMA.contains("effect_execution_attempts"));
        assert!(SCHEMA.contains("effect_reconciliation_heads"));
        assert!(SCHEMA.contains("effect_reconciliation_attempts"));
        assert!(SCHEMA.contains("effect_rate_limit_buckets"));
        assert!(SCHEMA.contains("effect_rate_limit_reservations"));
        assert!(SCHEMA.contains("effect_rate_limit_decisions"));
        assert!(SCHEMA.contains("'creator_contact'"));
        assert!(SCHEMA.contains("'uncertain'"));
        assert!(SCHEMA.contains("jsonb_typeof(receipt_json) = 'object'"));
        assert!(SCHEMA.contains("lease_expires_at > created_at"));
        assert!(SCHEMA.contains("decision = 'reserved' AND consumed_after = consumed_before + 1"));
        assert!(!SCHEMA.contains("payload_json"));
        assert!(!SCHEMA.contains("plaintext"));
        assert!(CLAIM_OUTBOX_SQL.contains("FOR UPDATE SKIP LOCKED"));
        assert!(CLAIM_OUTBOX_SQL.contains("lease_generation = message.lease_generation + 1"));
        assert!(ACKNOWLEDGE_OUTBOX_SQL.contains("lease_expires_at > $7"));
        assert!(!ACKNOWLEDGE_OUTBOX_SQL.contains("lease_expires_at >= $7"));
        assert!(RELEASE_OUTBOX_SQL.contains("lease_expires_at > $8"));
        assert!(!RELEASE_OUTBOX_SQL.contains("lease_expires_at >= $8"));
    }

    #[test]
    fn outbox_completion_time_order_is_explicit_for_ack_and_release() {
        for (case, completion_offset, operation_offset, is_release, valid) in [
            ("ack_same_time", 1, 1, false, true),
            ("ack_backfilled_fact", 0, 1, false, true),
            ("ack_fact_after_operation", 2, 1, false, false),
            ("release_same_time", 1, 1, true, true),
            ("release_scheduled_future", 2, 1, true, true),
            ("release_schedule_before_operation", 0, 1, true, false),
        ] {
            let completion_at = now() + Duration::seconds(completion_offset);
            let operation_at = now() + Duration::seconds(operation_offset);
            let constructor_valid = if is_release {
                OutboxReleaseTimes::new(completion_at, operation_at).is_ok()
            } else {
                OutboxAcknowledgeTimes::new(completion_at, operation_at).is_ok()
            };
            assert_eq!(constructor_valid, valid, "{case}");
            if !valid {
                if is_release {
                    let mut tampered = OutboxReleaseTimes::new(operation_at, operation_at)
                        .expect("valid release times");
                    tampered.available_at = completion_at;
                    assert!(matches!(
                        tampered.validate(),
                        Err(CloudStorageError::InvalidOutboxClaim)
                    ));
                } else {
                    let mut tampered = OutboxAcknowledgeTimes::new(operation_at, operation_at)
                        .expect("valid acknowledgement times");
                    tampered.published_at = completion_at;
                    assert!(matches!(
                        tampered.validate(),
                        Err(CloudStorageError::InvalidOutboxClaim)
                    ));
                }
            }
        }
    }

    #[test]
    fn missing_postgres_is_an_explicit_blocked_environment_gate() {
        if std::env::var_os(POSTGRES_L2_URL_ENV).is_none() {
            assert_eq!(
                PostgresL2Environment::detect(),
                PostgresL2Environment::BlockedEnv
            );
        } else {
            assert_eq!(
                PostgresL2Environment::detect(),
                PostgresL2Environment::Ready
            );
        }
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the PostgreSQL L2 replay intentionally keeps migration, RLS, CAS, idempotency, and lease takeover in one auditable journey"
    )]
    async fn postgres_l2_contract_reports_blocked_or_executes_full_replay() {
        let Some(database_url) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
            eprintln!(
                "BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; PostgreSQL migration/RLS/recovery replay did not execute"
            );
            return;
        };
        let database_url = database_url
            .into_string()
            .expect("PostgreSQL test URL must be valid Unicode");
        let (mut client, connection) =
            tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
                .await
                .expect("connect disposable PostgreSQL L2 database");
        let connection_task = tokio::spawn(connection);
        let role = client
            .query_one(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .expect("inspect PostgreSQL test role");
        assert!(
            !role.get::<_, bool>(0) && !role.get::<_, bool>(1),
            "BLOCKED_ENV: PostgreSQL L2 role must not be superuser or BYPASSRLS"
        );

        let store = PostgresCellStore::new(DataCell::Us);
        store
            .migrate(&mut client, now())
            .await
            .expect("migrate Cell schema");
        let primary_scope = CellScope {
            cell: DataCell::Us,
            tenant_id: TenantId::new(),
        };
        let other_scope = CellScope {
            cell: DataCell::Us,
            tenant_id: TenantId::new(),
        };
        store
            .register_tenant(&mut client, &primary_scope, now())
            .await
            .expect("register primary tenant");
        store
            .register_tenant(&mut client, &other_scope, now())
            .await
            .expect("register isolated tenant");

        let project_id = ProjectId::new();
        let initial_payload = payload(11);
        let registration = CloudProjectRegistration {
            scope: primary_scope.clone(),
            project_id: project_id.clone(),
            encryption_mode: ProjectEncryptionMode::PersonalE2ee,
            remote_execution_opt_in: false,
            metadata_digest: initial_payload.content_digest.clone(),
            initial_payload,
            idempotency_key_digest: "b".repeat(64),
            created_at: now(),
        };
        let created = store
            .create_project(&mut client, &registration)
            .await
            .expect("atomically create encrypted project/event/outbox");
        assert_eq!(created.object_revision, 1);
        assert!(!created.duplicate);
        let replayed = store
            .create_project(&mut client, &registration)
            .await
            .expect("idempotent project replay");
        assert!(replayed.duplicate);
        assert_eq!(replayed.event_sequence, created.event_sequence);

        let source_device = DeviceId::from("source-device");
        let target_device = DeviceId::from("target-device");
        let source_recipient = KeyRecipient::Device(source_device.clone());
        let mut source_envelope = key_envelope(
            &project_id,
            "source-envelope",
            source_recipient.clone(),
            now(),
        );
        source_envelope.tenant_id = primary_scope.tenant_id.clone();
        let mut recovery_envelope = key_envelope(
            &project_id,
            "recovery-envelope",
            KeyRecipient::Recovery("recovery-kit-1".into()),
            now(),
        );
        recovery_envelope.tenant_id = primary_scope.tenant_id.clone();
        let source_envelope_digest = source_envelope
            .canonical_digest()
            .expect("source envelope digest");
        let mut keyring = ProjectKeyring::initialize(
            primary_scope.tenant_id.clone(),
            project_id.clone(),
            ProjectEncryptionMode::PersonalE2ee,
            vec![source_envelope.clone(), recovery_envelope],
            now(),
        )
        .expect("initial personal keyring");
        let initial_bootstrap = ProjectKeyringBootstrap::prepare(
            keyring.clone(),
            None,
            source_recipient.clone(),
            source_envelope_digest.clone(),
            "1".repeat(64),
            "2".repeat(64),
            now(),
        )
        .expect("initial keyring bootstrap");
        let bootstrap_v1 = store
            .publish_keyring_bootstrap(&mut client, &primary_scope, &initial_bootstrap)
            .await
            .expect("publish initial keyring bootstrap");
        assert_eq!(bootstrap_v1.revision, 1);
        assert!(
            store
                .publish_keyring_bootstrap(&mut client, &primary_scope, &initial_bootstrap)
                .await
                .expect("replay initial bootstrap")
                .duplicate
        );

        let source_public_key = DevicePublicKeyRegistration::register(
            primary_scope.tenant_id.clone(),
            project_id.clone(),
            source_device,
            vec![7; 32],
            ActorId::from("user-1"),
            "3".repeat(64),
            "4".repeat(64),
            now(),
        )
        .expect("source public key");
        let target_public_key = DevicePublicKeyRegistration::register(
            primary_scope.tenant_id.clone(),
            project_id.clone(),
            target_device.clone(),
            vec![8; 32],
            ActorId::from("user-1"),
            "5".repeat(64),
            "6".repeat(64),
            now(),
        )
        .expect("target public key");
        store
            .publish_device_public_key(&mut client, &primary_scope, &source_public_key)
            .await
            .expect("publish source public key");
        store
            .publish_device_public_key(&mut client, &primary_scope, &target_public_key)
            .await
            .expect("publish target public key");

        let revoked_grant = handoff_grant(
            &primary_scope.tenant_id,
            &project_id,
            source_recipient.clone(),
            source_envelope_digest.clone(),
            initial_bootstrap.manifest_digest.clone(),
            &target_public_key,
            "revoked-grant",
            '7',
            1,
            now() + Duration::minutes(1),
        );
        store
            .publish_device_handoff_grant(&mut client, &primary_scope, &revoked_grant)
            .await
            .expect("publish revocable handoff");
        let revocation = DeviceHandoffRevocation {
            tenant_id: primary_scope.tenant_id.clone(),
            project_id: project_id.clone(),
            grant_id: revoked_grant.context.grant_id.clone(),
            revoked_by: ActorId::from("user-1"),
            authorization_evidence_digest: "8".repeat(64),
            idempotency_key_digest: "9".repeat(64),
            revoked_at: now() + Duration::minutes(2),
        };
        store
            .revoke_device_handoff_grant(&mut client, &primary_scope, &revocation)
            .await
            .expect("revoke handoff before consumption");
        let revoked_claim = DeviceHandoffClaim::issue(
            &revoked_grant,
            ReceiptId::from("revoked-handoff-claim"),
            "0".repeat(64),
            now() + Duration::minutes(2) + Duration::seconds(1),
        )
        .expect("structurally valid revoked claim");
        assert!(matches!(
            store
                .claim_device_handoff_grant(&mut client, &primary_scope, &revoked_claim)
                .await,
            Err(CloudStorageError::DeviceHandoffRevoked)
        ));

        let grant = handoff_grant(
            &primary_scope.tenant_id,
            &project_id,
            source_recipient.clone(),
            source_envelope_digest.clone(),
            initial_bootstrap.manifest_digest.clone(),
            &target_public_key,
            "consumed-grant",
            'a',
            1,
            now() + Duration::minutes(3),
        );
        let first_grant = store
            .publish_device_handoff_grant(&mut client, &primary_scope, &grant)
            .await
            .expect("publish consumable handoff");
        assert!(!first_grant.duplicate);
        assert!(
            store
                .publish_device_handoff_grant(&mut client, &primary_scope, &grant)
                .await
                .expect("replay exact handoff")
                .duplicate
        );
        let claim = DeviceHandoffClaim::issue(
            &grant,
            ReceiptId::from("handoff-claim"),
            "e".repeat(64),
            now() + Duration::minutes(3) + Duration::seconds(30),
        )
        .expect("claim in grant window");
        store
            .claim_device_handoff_grant(&mut client, &primary_scope, &claim)
            .await
            .expect("claim before local decryption");
        let post_claim_revocation = DeviceHandoffRevocation {
            tenant_id: primary_scope.tenant_id.clone(),
            project_id: project_id.clone(),
            grant_id: grant.context.grant_id.clone(),
            revoked_by: ActorId::from("user-1"),
            authorization_evidence_digest: "1".repeat(64),
            idempotency_key_digest: "2".repeat(64),
            revoked_at: now() + Duration::minutes(3) + Duration::seconds(31),
        };
        assert!(matches!(
            store
                .revoke_device_handoff_grant(&mut client, &primary_scope, &post_claim_revocation,)
                .await,
            Err(CloudStorageError::DeviceHandoffAlreadyClaimed)
        ));

        let mut target_envelope = key_envelope(
            &project_id,
            "target-envelope",
            KeyRecipient::Device(target_device.clone()),
            now() + Duration::minutes(4),
        );
        target_envelope.tenant_id = primary_scope.tenant_id.clone();
        keyring
            .add_envelope(target_envelope, now() + Duration::minutes(4))
            .expect("attach target envelope");
        let bootstrap_v2 = ProjectKeyringBootstrap::prepare(
            keyring,
            Some(1),
            source_recipient,
            source_envelope_digest,
            "b".repeat(64),
            "c".repeat(64),
            now() + Duration::minutes(4),
        )
        .expect("next keyring bootstrap");
        store
            .publish_keyring_bootstrap(&mut client, &primary_scope, &bootstrap_v2)
            .await
            .expect("publish attached keyring revision");
        let consumption = DeviceHandoffConsumption::issue(
            &grant,
            &claim,
            ReceiptId::from("handoff-receipt"),
            DeviceAttachmentId::from("attachment-1"),
            2,
            "d".repeat(64),
            now() + Duration::minutes(5),
        )
        .expect("exact consumption receipt");
        let consumed = store
            .consume_device_handoff_grant(&mut client, &primary_scope, &consumption)
            .await
            .expect("consume only after attached keyring published");
        assert!(!consumed.duplicate);
        assert!(
            store
                .consume_device_handoff_grant(&mut client, &primary_scope, &consumption)
                .await
                .expect("exact consumption replay")
                .duplicate
        );

        let mission_create = EncryptedSyncMutation {
            scope: primary_scope.clone(),
            project_id: project_id.clone(),
            object_id: "mission-1".into(),
            object_kind: SyncObjectKind::Mission,
            precondition: MutationPrecondition::CreateOnly,
            payload: payload(12),
            tombstone: false,
            idempotency_key_digest: "c".repeat(64),
            recorded_at: now() + Duration::minutes(1),
        };
        let mission_v1 = store
            .apply_encrypted_mutation(&mut client, &mission_create)
            .await
            .expect("create encrypted mission");
        assert_eq!(mission_v1.object_revision, 1);
        assert!(
            store
                .apply_encrypted_mutation(&mut client, &mission_create)
                .await
                .expect("idempotent mutation replay")
                .duplicate
        );

        let mut stale = mission_create.clone();
        stale.precondition = MutationPrecondition::ExactRevision(9);
        stale.payload = payload(13);
        stale.idempotency_key_digest = "d".repeat(64);
        assert!(matches!(
            store.apply_encrypted_mutation(&mut client, &stale).await,
            Err(CloudStorageError::OptimisticConflict {
                actual: Some(1),
                ..
            })
        ));

        let mut mission_update = mission_create;
        mission_update.precondition = MutationPrecondition::ExactRevision(1);
        mission_update.payload = payload(14);
        mission_update.idempotency_key_digest = "e".repeat(64);
        mission_update.recorded_at = now() + Duration::minutes(2);
        store
            .apply_encrypted_mutation(&mut client, &mission_update)
            .await
            .expect("CAS mission update");
        let restored = store
            .load_encrypted_object(&mut client, &primary_scope, &project_id, "mission-1")
            .await
            .expect("load encrypted mission head");
        assert_eq!(restored.revision, 2);
        assert_eq!(restored.payload, mission_update.payload);
        assert!(matches!(
            store
                .load_encrypted_object(&mut client, &other_scope, &project_id, "mission-1")
                .await,
            Err(CloudStorageError::SyncObjectNotFound)
        ));

        let context_create = EncryptedSyncMutation {
            scope: primary_scope.clone(),
            project_id: project_id.clone(),
            object_id: "capsule-delete-1".into(),
            object_kind: SyncObjectKind::ContextCapsule,
            precondition: MutationPrecondition::CreateOnly,
            payload: payload(21),
            tombstone: false,
            idempotency_key_digest: "f".repeat(64),
            recorded_at: now() + Duration::minutes(3),
        };
        store
            .apply_encrypted_mutation(&mut client, &context_create)
            .await
            .expect("create context capsule ciphertext");
        let mut context_update = context_create.clone();
        context_update.precondition = MutationPrecondition::ExactRevision(1);
        context_update.payload = payload(22);
        context_update.idempotency_key_digest = "1".repeat(64);
        context_update.recorded_at = now() + Duration::minutes(4);
        store
            .apply_encrypted_mutation(&mut client, &context_update)
            .await
            .expect("update context capsule ciphertext");
        let mut context_delete = context_create.clone();
        context_delete.precondition = MutationPrecondition::ExactRevision(2);
        context_delete.payload = payload(23);
        context_delete.tombstone = true;
        context_delete.idempotency_key_digest = "2".repeat(64);
        context_delete.recorded_at = now() + Duration::minutes(5);
        let deleted = store
            .apply_encrypted_mutation(&mut client, &context_delete)
            .await
            .expect("write permanent context capsule tombstone");
        assert_eq!(deleted.object_revision, 3);
        assert!(
            store
                .apply_encrypted_mutation(&mut client, &context_delete)
                .await
                .expect("exact tombstone replay")
                .duplicate
        );
        let deleted_head = store
            .load_encrypted_object(&mut client, &primary_scope, &project_id, "capsule-delete-1")
            .await
            .expect("load tombstone head");
        assert!(deleted_head.tombstone);
        assert_eq!(deleted_head.revision, 3);
        let mut resurrection = context_create.clone();
        resurrection.precondition = MutationPrecondition::ExactRevision(3);
        resurrection.payload = payload(24);
        resurrection.idempotency_key_digest = "3".repeat(64);
        resurrection.recorded_at = now() + Duration::minutes(6);
        assert!(matches!(
            store
                .apply_encrypted_mutation(&mut client, &resurrection)
                .await,
            Err(CloudStorageError::SyncObjectDeleted)
        ));

        let inspection = client.transaction().await.expect("inspection transaction");
        set_scope(&inspection, &primary_scope)
            .await
            .expect("scope inspection");
        for (table, expected) in [
            ("sync_object_versions", 1_i64),
            ("domain_events", 1_i64),
            ("outbox_messages", 1_i64),
            ("sync_mutations", 1_i64),
        ] {
            let sql = format!(
                "SELECT count(*) FROM hartevo_cell.{table}
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND {} = $4",
                if table == "domain_events" {
                    "aggregate_id"
                } else {
                    "object_id"
                }
            );
            let count: i64 = inspection
                .query_one(
                    &sql,
                    &[
                        &primary_scope.cell.as_str(),
                        &primary_scope.tenant_id.as_str(),
                        &project_id.as_str(),
                        &"capsule-delete-1",
                    ],
                )
                .await
                .expect("inspect purged ciphertext graph")
                .get(0);
            assert_eq!(count, expected, "{table} retains only the tombstone row");
        }
        inspection.commit().await.expect("finish inspection");

        let first_lease = store
            .claim_outbox(
                &mut client,
                &primary_scope,
                "worker-old",
                now(),
                Duration::minutes(1),
                1,
            )
            .await
            .expect("first lease")
            .pop()
            .expect("outbox message");
        let mut invalid_ack_times =
            OutboxAcknowledgeTimes::new(now(), now()).expect("valid acknowledgement times");
        invalid_ack_times.published_at = now() + Duration::seconds(1);
        assert!(matches!(
            store
                .acknowledge_outbox(
                    &mut client,
                    &primary_scope,
                    first_lease.sequence,
                    "worker-old",
                    first_lease.lease_generation,
                    invalid_ack_times,
                )
                .await,
            Err(CloudStorageError::InvalidOutboxClaim)
        ));
        let mut invalid_release_times =
            OutboxReleaseTimes::new(now(), now()).expect("valid release times");
        invalid_release_times.available_at = now() - Duration::seconds(1);
        assert!(matches!(
            store
                .release_outbox(
                    &mut client,
                    &primary_scope,
                    first_lease.sequence,
                    "worker-old",
                    first_lease.lease_generation,
                    OutboxRelease::Requeue(invalid_release_times),
                )
                .await,
            Err(CloudStorageError::InvalidOutboxClaim)
        ));
        assert!(matches!(
            store
                .acknowledge_outbox(
                    &mut client,
                    &primary_scope,
                    first_lease.sequence,
                    "worker-old",
                    first_lease.lease_generation,
                    OutboxAcknowledgeTimes::new(now(), now() + Duration::minutes(1))
                        .expect("valid acknowledgement times"),
                )
                .await,
            Err(CloudStorageError::OutboxLeaseLost { .. })
        ));
        assert!(matches!(
            store
                .release_outbox(
                    &mut client,
                    &primary_scope,
                    first_lease.sequence,
                    "worker-old",
                    first_lease.lease_generation,
                    OutboxRelease::Requeue(
                        OutboxReleaseTimes::new(
                            now() + Duration::minutes(1),
                            now() + Duration::minutes(1),
                        )
                        .expect("valid release times"),
                    ),
                )
                .await,
            Err(CloudStorageError::OutboxLeaseLost { .. })
        ));
        let replacement_lease = store
            .claim_outbox(
                &mut client,
                &primary_scope,
                "worker-new",
                now() + Duration::minutes(2),
                Duration::minutes(1),
                1,
            )
            .await
            .expect("expired lease takeover")
            .pop()
            .expect("reclaimed outbox message");
        assert_eq!(replacement_lease.sequence, first_lease.sequence);
        assert!(replacement_lease.lease_generation > first_lease.lease_generation);
        assert!(matches!(
            store
                .acknowledge_outbox(
                    &mut client,
                    &primary_scope,
                    first_lease.sequence,
                    "worker-old",
                    first_lease.lease_generation,
                    OutboxAcknowledgeTimes::new(
                        now() + Duration::minutes(1),
                        now() + Duration::minutes(2),
                    )
                    .expect("valid acknowledgement times"),
                )
                .await,
            Err(CloudStorageError::OutboxLeaseLost { .. })
        ));
        store
            .acknowledge_outbox(
                &mut client,
                &primary_scope,
                replacement_lease.sequence,
                "worker-new",
                replacement_lease.lease_generation,
                OutboxAcknowledgeTimes::new(
                    now() + Duration::minutes(1),
                    now() + Duration::minutes(2),
                )
                .expect("valid acknowledgement times"),
            )
            .await
            .expect("current generation acknowledges");
        let release_lease = store
            .claim_outbox(
                &mut client,
                &primary_scope,
                "release-old",
                now() + Duration::minutes(2),
                Duration::minutes(1),
                1,
            )
            .await
            .expect("release lease")
            .pop()
            .expect("second outbox message");
        assert!(matches!(
            store
                .release_outbox(
                    &mut client,
                    &primary_scope,
                    release_lease.sequence,
                    "release-old",
                    release_lease.lease_generation,
                    OutboxRelease::Requeue(
                        OutboxReleaseTimes::new(
                            now() + Duration::minutes(3),
                            now() + Duration::minutes(3),
                        )
                        .expect("valid release times"),
                    ),
                )
                .await,
            Err(CloudStorageError::OutboxLeaseLost { .. })
        ));
        let replacement_release_lease = store
            .claim_outbox(
                &mut client,
                &primary_scope,
                "release-new",
                now() + Duration::minutes(3),
                Duration::minutes(1),
                1,
            )
            .await
            .expect("expired release lease takeover")
            .pop()
            .expect("reclaimed release message");
        assert_eq!(replacement_release_lease.sequence, release_lease.sequence);
        assert!(replacement_release_lease.lease_generation > release_lease.lease_generation);
        store
            .release_outbox(
                &mut client,
                &primary_scope,
                replacement_release_lease.sequence,
                "release-new",
                replacement_release_lease.lease_generation,
                OutboxRelease::Requeue(
                    OutboxReleaseTimes::new(
                        now() + Duration::minutes(3) + Duration::seconds(1),
                        now() + Duration::minutes(3),
                    )
                    .expect("valid release times"),
                ),
            )
            .await
            .expect("current generation releases");
        assert!(
            store
                .claim_outbox(
                    &mut client,
                    &other_scope,
                    "isolated-worker",
                    now() + Duration::minutes(3),
                    Duration::minutes(1),
                    10,
                )
                .await
                .expect("isolated tenant claim")
                .is_empty()
        );

        let unscoped_visible_rows: i64 = client
            .query_one("SELECT count(*) FROM hartevo_cell.sync_object_heads", &[])
            .await
            .expect("unscoped RLS query")
            .get(0);
        assert_eq!(unscoped_visible_rows, 0);

        drop(client);
        connection_task
            .await
            .expect("PostgreSQL connection task")
            .expect("PostgreSQL connection closed cleanly");
    }
}

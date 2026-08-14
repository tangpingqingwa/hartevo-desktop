//! Mission/Project-scoped encrypted device synchronization for a regional Cell.
//!
//! This seam carries only authenticated ciphertext and routing/fence metadata.
//! A device session is bound to the current Project keyring generation, the
//! registered device public-key digest, and the versioned service/provider/
//! consumer contract.  Every visible head is committed in the same transaction
//! as an append-only event-log row, so a consumer never observes an unlogged
//! SyncDocument head.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{DeviceId, ProjectId};
use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, Row, Transaction};

use super::{
    CellScope, CloudStorageError, DataCell, EncryptedPayload, MutationPrecondition,
    PostgresCellStore, SyncObjectKind, canonical_digest, ensure_database_cell,
    ensure_project_exists, ensure_request_digest, from_sql_u64, is_sha256,
    load_device_public_key_tx, load_keyring_bootstrap_tx, lock_project, set_scope, to_sql_u64,
};

pub const DEVICE_SYNC_SCHEMA: &str = "hartevo.cloud-cell.device-sync/v1";
pub const DEVICE_SYNC_SERVICE_ID: &str = "hartevo.device-sync.transport";
pub const DEVICE_SYNC_SERVICE_VERSION: u64 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncServiceDefinition {
    pub service_id: String,
    pub version: u64,
    pub contract_digest: String,
}

const REGISTRATION_COLUMNS: &str = "region, mission_scope_digest, device_id,
       project_key_generation, keyring_manifest_digest, registration_version,
       registration_digest, device_public_key_digest, service_id, service_version,
       service_contract_digest, provider_id, provider_region, provider_version,
       provider_implementation_digest, consumer_id, consumer_min_service_version,
       consumer_descriptor_digest, request_digest, state, attached_at, updated_at,
       released_at, release_reason_digest, revision";

async fn load_current_key_fence_tx(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    lock: bool,
) -> Result<CloudDeviceSyncKeyFence, CloudStorageError> {
    let bootstrap = load_keyring_bootstrap_tx(transaction, scope, project_id, lock)
        .await?
        .ok_or(CloudStorageError::KeyringBootstrapNotFound)?;
    Ok(CloudDeviceSyncKeyFence {
        scope: scope.clone(),
        region: scope.cell,
        project_id: project_id.clone(),
        project_key_generation: bootstrap.keyring.revision,
        keyring_manifest_digest: bootstrap.manifest_digest,
    })
}

async fn load_registration_by_idempotency(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    idempotency_key_digest: &str,
    lock: bool,
) -> Result<Option<RegistrationRecord>, CloudStorageError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let row = transaction
        .query_opt(
            &format!(
                "SELECT {REGISTRATION_COLUMNS}
                 FROM hartevo_cell.device_sync_registrations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4{suffix}"
            ),
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &idempotency_key_digest,
            ],
        )
        .await?;
    row.map(|row| decode_registration_row(&row, scope, project_id))
        .transpose()
}

async fn load_registration_by_session(
    transaction: &Transaction<'_>,
    session: &CloudDeviceSyncSession,
    lock: bool,
) -> Result<Option<RegistrationRecord>, CloudStorageError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let row = transaction
        .query_opt(
            &format!(
                "SELECT {REGISTRATION_COLUMNS}
                 FROM hartevo_cell.device_sync_registrations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND device_id = $4 AND registration_version = $5
                   AND registration_digest = $6{suffix}"
            ),
            &[
                &session.scope.cell.as_str(),
                &session.scope.tenant_id.as_str(),
                &session.project_id.as_str(),
                &session.device_id.as_str(),
                &to_sql_u64(session.registration_version)?,
                &session.registration_digest,
            ],
        )
        .await?;
    row.map(|row| decode_registration_row(&row, &session.scope, &session.project_id))
        .transpose()
}

async fn load_active_registration(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    device_id: &DeviceId,
    lock: bool,
) -> Result<Option<RegistrationRecord>, CloudStorageError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let row = transaction
        .query_opt(
            &format!(
                "SELECT {REGISTRATION_COLUMNS}
                 FROM hartevo_cell.device_sync_registrations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND device_id = $4 AND state = 'attached'{suffix}"
            ),
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &device_id.as_str(),
            ],
        )
        .await?;
    row.map(|row| decode_registration_row(&row, scope, project_id))
        .transpose()
}

fn decode_registration_row(
    row: &Row,
    scope: &CellScope,
    project_id: &ProjectId,
) -> Result<RegistrationRecord, CloudStorageError> {
    let region = decode_cell(row.get::<_, String>(0).as_str())?;
    let provider_region = decode_cell(row.get::<_, String>(12).as_str())?;
    let service = CloudDeviceSyncServiceDefinition {
        service_id: row.get(8),
        version: from_sql_u64(row.get(9), "device sync service version")?,
        contract_digest: row.get(10),
    };
    service.validate()?;
    let provider = CloudDeviceSyncProvider {
        provider_id: row.get(11),
        region,
        service_id: service.service_id.clone(),
        version: from_sql_u64(row.get(13), "device sync provider version")?,
        implementation_digest: row.get(14),
    };
    provider.validate(&service, region)?;
    let consumer = CloudDeviceSyncConsumer {
        consumer_id: row.get(15),
        service_id: service.service_id.clone(),
        min_service_version: from_sql_u64(row.get(16), "device sync consumer version")?,
        descriptor_digest: row.get(17),
    };
    consumer.validate(&service)?;
    let session = CloudDeviceSyncSession {
        scope: scope.clone(),
        region,
        mission_scope_digest: row.get(1),
        project_id: project_id.clone(),
        device_id: DeviceId::from_stable(row.get::<_, String>(2)),
        project_key_generation: from_sql_u64(row.get(3), "device sync key generation")?,
        keyring_manifest_digest: row.get(4),
        registration_version: from_sql_u64(row.get(5), "device sync registration version")?,
        registration_digest: row.get(6),
        device_public_key_digest: row.get(7),
        service_id: service.service_id,
        service_version: service.version,
        service_contract_digest: service.contract_digest,
        provider_id: provider.provider_id,
        provider_region,
        provider_version: provider.version,
        provider_implementation_digest: provider.implementation_digest,
        consumer_id: consumer.consumer_id,
        consumer_min_service_version: consumer.min_service_version,
        consumer_descriptor_digest: consumer.descriptor_digest,
    };
    session.validate(scope.cell)?;
    if registration_digest_from_session(&session)? != session.registration_digest {
        return Err(CloudStorageError::StoredValueInvalid(
            "device sync registration digest".into(),
        ));
    }
    Ok(RegistrationRecord {
        session,
        request_digest: row.get(18),
        state: decode_registration_state(row.get::<_, String>(19).as_str())?,
    })
}

fn registration_digest_from_session(
    session: &CloudDeviceSyncSession,
) -> Result<String, CloudStorageError> {
    canonical_digest(&serde_json::json!({
        "schema": DEVICE_SYNC_SCHEMA,
        "scope": session.scope,
        "region": session.region,
        "missionScopeDigest": session.mission_scope_digest,
        "projectId": session.project_id,
        "deviceId": session.device_id,
        "projectKeyGeneration": session.project_key_generation,
        "keyringManifestDigest": session.keyring_manifest_digest,
        "registrationVersion": session.registration_version,
        "devicePublicKeyDigest": session.device_public_key_digest,
        "service": {
            "serviceId": session.service_id,
            "version": session.service_version,
            "contractDigest": session.service_contract_digest,
        },
        "provider": {
            "providerId": session.provider_id,
            "region": session.provider_region,
            "serviceId": session.service_id,
            "version": session.provider_version,
            "implementationDigest": session.provider_implementation_digest,
        },
        "consumer": {
            "consumerId": session.consumer_id,
            "serviceId": session.service_id,
            "minServiceVersion": session.consumer_min_service_version,
            "descriptorDigest": session.consumer_descriptor_digest,
        },
    }))
}

async fn ensure_current_session_tx(
    transaction: &Transaction<'_>,
    session: &CloudDeviceSyncSession,
    at: DateTime<Utc>,
) -> Result<RegistrationRecord, CloudStorageError> {
    let registration = load_registration_by_session(transaction, session, true)
        .await?
        .ok_or(CloudStorageError::DeviceSyncRegistrationNotFound)?;
    if registration.state != CloudDeviceSyncRegistrationState::Attached {
        return Err(CloudStorageError::DeviceSyncRegistrationNotActive);
    }
    if registration.session != *session {
        return Err(CloudStorageError::DeviceSyncDocumentFenceLost);
    }
    let current =
        load_current_key_fence_tx(transaction, &session.scope, &session.project_id, true).await?;
    if current.project_key_generation != session.project_key_generation
        || current.keyring_manifest_digest != session.keyring_manifest_digest
    {
        return Err(CloudStorageError::DeviceSyncKeyGenerationStale);
    }
    let device_key = load_device_public_key_tx(
        transaction,
        &session.scope,
        &session.project_id,
        &session.device_id,
        true,
    )
    .await?
    .ok_or(CloudStorageError::DevicePublicKeyNotFound)?;
    if device_key.public_key_digest != session.device_public_key_digest || !device_key.is_active(at)
    {
        return Err(CloudStorageError::DeviceSyncDeviceKeyRevoked);
    }
    Ok(registration)
}

fn decode_cell(value: &str) -> Result<DataCell, CloudStorageError> {
    match value {
        "us" => Ok(DataCell::Us),
        "eu" => Ok(DataCell::Eu),
        _ => Err(CloudStorageError::StoredValueInvalid(
            "device sync region".into(),
        )),
    }
}

fn decode_registration_state(
    value: &str,
) -> Result<CloudDeviceSyncRegistrationState, CloudStorageError> {
    match value {
        "attached" => Ok(CloudDeviceSyncRegistrationState::Attached),
        "unmounted" => Ok(CloudDeviceSyncRegistrationState::Unmounted),
        "revoked" => Ok(CloudDeviceSyncRegistrationState::Revoked),
        _ => Err(CloudStorageError::StoredValueInvalid(
            "device sync registration state".into(),
        )),
    }
}

fn decode_release_event_state(
    event_type: &str,
) -> Result<CloudDeviceSyncRegistrationState, CloudStorageError> {
    match event_type {
        "unmounted" | "crash_reclaimed" | "stale_generation_reclaimed" => {
            Ok(CloudDeviceSyncRegistrationState::Unmounted)
        }
        "revoked" => Ok(CloudDeviceSyncRegistrationState::Revoked),
        _ => Err(CloudStorageError::StoredValueInvalid(
            "device sync lifecycle event".into(),
        )),
    }
}

impl CloudDeviceSyncServiceDefinition {
    pub fn v1() -> Self {
        Self {
            service_id: DEVICE_SYNC_SERVICE_ID.into(),
            version: DEVICE_SYNC_SERVICE_VERSION,
            contract_digest: canonical_digest(&serde_json::json!({
                "schema": DEVICE_SYNC_SCHEMA,
                "serviceId": DEVICE_SYNC_SERVICE_ID,
                "version": DEVICE_SYNC_SERVICE_VERSION,
                "operations": [
                    "attach",
                    "load_key_fence",
                    "load_head",
                    "advance_head",
                    "unmount",
                    "revoke",
                    "crash_reclaim"
                ],
            }))
            .expect("static device-sync service definition serializes"),
        }
    }

    fn validate(&self) -> Result<(), CloudStorageError> {
        if !valid_identifier(&self.service_id)
            || self.service_id != DEVICE_SYNC_SERVICE_ID
            || self.version != DEVICE_SYNC_SERVICE_VERSION
            || !is_sha256(&self.contract_digest)
            || self != &Self::v1()
        {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncProvider {
    pub provider_id: String,
    pub region: DataCell,
    pub service_id: String,
    pub version: u64,
    pub implementation_digest: String,
}

impl CloudDeviceSyncProvider {
    fn validate(
        &self,
        service: &CloudDeviceSyncServiceDefinition,
        expected_region: DataCell,
    ) -> Result<(), CloudStorageError> {
        if !valid_identifier(&self.provider_id)
            || self.region != expected_region
            || self.service_id != service.service_id
            || self.version != service.version
            || !is_sha256(&self.implementation_digest)
        {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncConsumer {
    pub consumer_id: String,
    pub service_id: String,
    pub min_service_version: u64,
    pub descriptor_digest: String,
}

impl CloudDeviceSyncConsumer {
    fn validate(
        &self,
        service: &CloudDeviceSyncServiceDefinition,
    ) -> Result<(), CloudStorageError> {
        if !valid_identifier(&self.consumer_id)
            || self.service_id != service.service_id
            || self.min_service_version == 0
            || self.min_service_version > service.version
            || !is_sha256(&self.descriptor_digest)
        {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncAttach {
    pub scope: CellScope,
    pub region: DataCell,
    pub mission_scope_digest: String,
    pub project_id: ProjectId,
    pub device_id: DeviceId,
    pub project_key_generation: u64,
    pub keyring_manifest_digest: String,
    pub registration_version: u64,
    pub device_public_key_digest: String,
    pub service: CloudDeviceSyncServiceDefinition,
    pub provider: CloudDeviceSyncProvider,
    pub consumer: CloudDeviceSyncConsumer,
    pub idempotency_key_digest: String,
    pub attached_at: DateTime<Utc>,
}

impl CloudDeviceSyncAttach {
    pub fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.scope.validate(expected_cell)?;
        self.service.validate()?;
        self.provider.validate(&self.service, self.region)?;
        self.consumer.validate(&self.service)?;
        if self.region != self.scope.cell
            || self.mission_scope_digest.len() != 64
            || !is_sha256(&self.mission_scope_digest)
            || self.project_id.as_str().trim().is_empty()
            || self.device_id.as_str().trim().is_empty()
            || self.project_key_generation == 0
            || !is_sha256(&self.keyring_manifest_digest)
            || self.registration_version == 0
            || !is_sha256(&self.device_public_key_digest)
            || !is_sha256(&self.idempotency_key_digest)
        {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        Ok(())
    }

    pub fn registration_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": DEVICE_SYNC_SCHEMA,
            "scope": self.scope,
            "region": self.region,
            "missionScopeDigest": self.mission_scope_digest,
            "projectId": self.project_id,
            "deviceId": self.device_id,
            "projectKeyGeneration": self.project_key_generation,
            "keyringManifestDigest": self.keyring_manifest_digest,
            "registrationVersion": self.registration_version,
            "devicePublicKeyDigest": self.device_public_key_digest,
            "service": self.service,
            "provider": self.provider,
            "consumer": self.consumer,
        }))
    }

    pub fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "registrationDigest": self.registration_digest()?,
            "idempotencyKeyDigest": self.idempotency_key_digest,
            "attachedAt": self.attached_at,
        }))
    }

    fn session(&self) -> Result<CloudDeviceSyncSession, CloudStorageError> {
        Ok(CloudDeviceSyncSession {
            scope: self.scope.clone(),
            region: self.region,
            mission_scope_digest: self.mission_scope_digest.clone(),
            project_id: self.project_id.clone(),
            device_id: self.device_id.clone(),
            project_key_generation: self.project_key_generation,
            keyring_manifest_digest: self.keyring_manifest_digest.clone(),
            registration_version: self.registration_version,
            registration_digest: self.registration_digest()?,
            device_public_key_digest: self.device_public_key_digest.clone(),
            service_id: self.service.service_id.clone(),
            service_version: self.service.version,
            service_contract_digest: self.service.contract_digest.clone(),
            provider_id: self.provider.provider_id.clone(),
            provider_region: self.provider.region,
            provider_version: self.provider.version,
            provider_implementation_digest: self.provider.implementation_digest.clone(),
            consumer_id: self.consumer.consumer_id.clone(),
            consumer_min_service_version: self.consumer.min_service_version,
            consumer_descriptor_digest: self.consumer.descriptor_digest.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncSession {
    pub scope: CellScope,
    pub region: DataCell,
    pub mission_scope_digest: String,
    pub project_id: ProjectId,
    pub device_id: DeviceId,
    pub project_key_generation: u64,
    pub keyring_manifest_digest: String,
    pub registration_version: u64,
    pub registration_digest: String,
    pub device_public_key_digest: String,
    pub service_id: String,
    pub service_version: u64,
    pub service_contract_digest: String,
    pub provider_id: String,
    pub provider_region: DataCell,
    pub provider_version: u64,
    pub provider_implementation_digest: String,
    pub consumer_id: String,
    pub consumer_min_service_version: u64,
    pub consumer_descriptor_digest: String,
}

impl CloudDeviceSyncSession {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.scope.validate(expected_cell)?;
        if self.region != self.scope.cell
            || self.provider_region != self.region
            || !is_sha256(&self.mission_scope_digest)
            || self.project_id.as_str().trim().is_empty()
            || self.device_id.as_str().trim().is_empty()
            || self.project_key_generation == 0
            || !is_sha256(&self.keyring_manifest_digest)
            || self.registration_version == 0
            || !is_sha256(&self.registration_digest)
            || !is_sha256(&self.device_public_key_digest)
            || !valid_identifier(&self.service_id)
            || self.service_version == 0
            || !is_sha256(&self.service_contract_digest)
            || !valid_identifier(&self.provider_id)
            || self.provider_version == 0
            || !is_sha256(&self.provider_implementation_digest)
            || !valid_identifier(&self.consumer_id)
            || self.consumer_min_service_version == 0
            || self.consumer_min_service_version > self.service_version
            || !is_sha256(&self.consumer_descriptor_digest)
        {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncKeyFence {
    pub scope: CellScope,
    pub region: DataCell,
    pub project_id: ProjectId,
    pub project_key_generation: u64,
    pub keyring_manifest_digest: String,
}

impl CloudDeviceSyncKeyFence {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.scope.validate(expected_cell)?;
        if self.region != self.scope.cell
            || self.project_id.as_str().trim().is_empty()
            || self.project_key_generation == 0
            || !is_sha256(&self.keyring_manifest_digest)
        {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncAttachResult {
    pub session: CloudDeviceSyncSession,
    pub duplicate: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudDeviceSyncRegistrationState {
    Attached,
    Unmounted,
    Revoked,
}

impl CloudDeviceSyncRegistrationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Unmounted => "unmounted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CloudDeviceSyncReleaseKind {
    Unmount,
    Revoke,
    Crash,
}

impl CloudDeviceSyncReleaseKind {
    const fn event_type(self) -> &'static str {
        match self {
            Self::Unmount => "unmounted",
            Self::Revoke => "revoked",
            Self::Crash => "crash_reclaimed",
        }
    }

    const fn state(self) -> CloudDeviceSyncRegistrationState {
        match self {
            Self::Unmount | Self::Crash => CloudDeviceSyncRegistrationState::Unmounted,
            Self::Revoke => CloudDeviceSyncRegistrationState::Revoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncRelease {
    pub session: CloudDeviceSyncSession,
    pub kind: CloudDeviceSyncReleaseKind,
    pub reason_digest: String,
    pub idempotency_key_digest: String,
    pub released_at: DateTime<Utc>,
}

impl CloudDeviceSyncRelease {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.session.validate(expected_cell)?;
        if !is_sha256(&self.reason_digest) || !is_sha256(&self.idempotency_key_digest) {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        Ok(())
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": DEVICE_SYNC_SCHEMA,
            "session": self.session,
            "kind": self.kind,
            "reasonDigest": self.reason_digest,
            "releasedAt": self.released_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncReleaseResult {
    pub session: CloudDeviceSyncSession,
    pub state: CloudDeviceSyncRegistrationState,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncDocumentMutation {
    pub session: CloudDeviceSyncSession,
    pub document_id: String,
    pub object_kind: SyncObjectKind,
    pub precondition: MutationPrecondition,
    pub payload: EncryptedPayload,
    pub tombstone: bool,
    pub idempotency_key_digest: String,
    pub recorded_at: DateTime<Utc>,
}

impl CloudDeviceSyncDocumentMutation {
    fn validate(&self, expected_cell: DataCell) -> Result<(), CloudStorageError> {
        self.session.validate(expected_cell)?;
        self.payload.validate()?;
        if self.document_id.trim().is_empty()
            || self.document_id.len() > 512
            || !is_sha256(&self.idempotency_key_digest)
            || (self.tombstone && self.precondition == MutationPrecondition::CreateOnly)
            || matches!(self.precondition, MutationPrecondition::ExactRevision(0))
        {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        Ok(())
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": DEVICE_SYNC_SCHEMA,
            "session": self.session,
            "documentId": self.document_id,
            "objectKind": self.object_kind,
            "precondition": self.precondition,
            "payload": self.payload,
            "tombstone": self.tombstone,
            "recordedAt": self.recorded_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncDocumentHead {
    pub scope: CellScope,
    pub region: DataCell,
    pub project_id: ProjectId,
    pub document_id: String,
    pub object_kind: SyncObjectKind,
    pub revision: u64,
    pub project_key_generation: u64,
    pub keyring_manifest_digest: String,
    pub registration_version: u64,
    pub registration_digest: String,
    pub payload: EncryptedPayload,
    pub tombstone: bool,
    pub recorded_at: DateTime<Utc>,
    pub head_digest: String,
    pub event_sequence: i64,
}

impl CloudDeviceSyncDocumentHead {
    fn digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": DEVICE_SYNC_SCHEMA,
            "scope": self.scope,
            "region": self.region,
            "projectId": self.project_id,
            "documentId": self.document_id,
            "objectKind": self.object_kind,
            "revision": self.revision,
            "projectKeyGeneration": self.project_key_generation,
            "keyringManifestDigest": self.keyring_manifest_digest,
            "registrationVersion": self.registration_version,
            "registrationDigest": self.registration_digest,
            "payload": self.payload,
            "tombstone": self.tombstone,
            "recordedAt": self.recorded_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudDeviceSyncDocumentResult {
    pub head: CloudDeviceSyncDocumentHead,
    pub duplicate: bool,
}

#[derive(Clone, Debug)]
struct RegistrationRecord {
    session: CloudDeviceSyncSession,
    request_digest: String,
    state: CloudDeviceSyncRegistrationState,
}

#[derive(Clone, Debug)]
struct EventRecord {
    sequence: i64,
    event_type: String,
    resource_id: String,
    result_revision: Option<u64>,
    request_digest: String,
}

impl PostgresCellStore {
    pub async fn load_device_sync_key_fence(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
    ) -> Result<CloudDeviceSyncKeyFence, CloudStorageError> {
        scope.validate(self.cell())?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, scope, project_id).await?;
        let fence = load_current_key_fence_tx(&transaction, scope, project_id, false).await?;
        fence.validate(self.cell())?;
        transaction.commit().await?;
        Ok(fence)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "device attach atomically binds current key generation, device key, plugin identities, registration version, and durable log"
    )]
    pub async fn attach_device_sync(
        &self,
        client: &mut Client,
        attach: &CloudDeviceSyncAttach,
    ) -> Result<CloudDeviceSyncAttachResult, CloudStorageError> {
        attach.validate(self.cell())?;
        let registration_digest = attach.registration_digest()?;
        let request_digest = attach.request_digest()?;
        let session = attach.session()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &attach.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, &attach.scope, &attach.project_id).await?;
        lock_project(&transaction, &attach.scope, &attach.project_id).await?;

        if let Some(existing) = load_registration_by_idempotency(
            &transaction,
            &attach.scope,
            &attach.project_id,
            &attach.idempotency_key_digest,
            true,
        )
        .await?
        {
            ensure_request_digest(&existing.request_digest, &request_digest)?;
            transaction.commit().await?;
            return Ok(CloudDeviceSyncAttachResult {
                session: existing.session,
                duplicate: true,
            });
        }

        let key_fence =
            load_current_key_fence_tx(&transaction, &attach.scope, &attach.project_id, true)
                .await?;
        if key_fence.project_key_generation != attach.project_key_generation
            || key_fence.keyring_manifest_digest != attach.keyring_manifest_digest
        {
            return Err(CloudStorageError::DeviceSyncKeyGenerationStale);
        }
        let device_key = load_device_public_key_tx(
            &transaction,
            &attach.scope,
            &attach.project_id,
            &attach.device_id,
            true,
        )
        .await?
        .ok_or(CloudStorageError::DevicePublicKeyNotFound)?;
        if device_key.public_key_digest != attach.device_public_key_digest
            || !device_key.is_active(attach.attached_at)
        {
            return Err(CloudStorageError::DeviceSyncDeviceKeyRevoked);
        }

        let active = load_active_registration(
            &transaction,
            &attach.scope,
            &attach.project_id,
            &attach.device_id,
            true,
        )
        .await?;
        if let Some(active) = active {
            if active.session.project_key_generation >= attach.project_key_generation {
                return Err(CloudStorageError::DeviceSyncRegistrationAlreadyActive);
            }
            let stale_reason = canonical_digest(&serde_json::json!({
                "schema": DEVICE_SYNC_SCHEMA,
                "reason": "key_generation_rotated",
                "oldRegistrationDigest": active.session.registration_digest,
                "newProjectKeyGeneration": attach.project_key_generation,
            }))?;
            let stale_operation = canonical_digest(&serde_json::json!({
                "schema": DEVICE_SYNC_SCHEMA,
                "registrationDigest": active.session.registration_digest,
                "newProjectKeyGeneration": attach.project_key_generation,
            }))?;
            let stale_request = canonical_digest(&serde_json::json!({
                "session": active.session,
                "kind": "stale_generation_reclaimed",
                "reasonDigest": stale_reason,
                "releasedAt": attach.attached_at,
            }))?;
            release_registration_tx(
                &transaction,
                &active,
                CloudDeviceSyncRegistrationState::Unmounted,
                "stale_generation_reclaimed",
                &stale_reason,
                &stale_operation,
                &stale_request,
                attach.attached_at,
            )
            .await?;
        }

        let maximum_version = transaction
            .query_one(
                "SELECT COALESCE(max(registration_version), 0)
                 FROM hartevo_cell.device_sync_registrations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND device_id = $4",
                &[
                    &attach.scope.cell.as_str(),
                    &attach.scope.tenant_id.as_str(),
                    &attach.project_id.as_str(),
                    &attach.device_id.as_str(),
                ],
            )
            .await?
            .get::<_, i64>(0);
        let expected_version = u64::try_from(maximum_version)
            .map_err(|_| CloudStorageError::StoredValueInvalid("device sync version".into()))?
            .checked_add(1)
            .ok_or(CloudStorageError::RevisionOverflow)?;
        if attach.registration_version != expected_version {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }

        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_sync_registrations
                   (cell, tenant_id, project_id, region, mission_scope_digest, device_id,
                    project_key_generation, keyring_manifest_digest, registration_version,
                    registration_digest, device_public_key_digest, service_id, service_version,
                    service_contract_digest, provider_id, provider_region, provider_version,
                    provider_implementation_digest, consumer_id, consumer_min_service_version,
                    consumer_descriptor_digest, idempotency_key, request_digest, state,
                    attached_at, updated_at, revision)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                         $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
                         'attached', $24, $24, 1)",
                &[
                    &attach.scope.cell.as_str(),
                    &attach.scope.tenant_id.as_str(),
                    &attach.project_id.as_str(),
                    &attach.region.as_str(),
                    &attach.mission_scope_digest,
                    &attach.device_id.as_str(),
                    &to_sql_u64(attach.project_key_generation)?,
                    &attach.keyring_manifest_digest,
                    &to_sql_u64(attach.registration_version)?,
                    &registration_digest,
                    &attach.device_public_key_digest,
                    &attach.service.service_id,
                    &to_sql_u64(attach.service.version)?,
                    &attach.service.contract_digest,
                    &attach.provider.provider_id,
                    &attach.provider.region.as_str(),
                    &to_sql_u64(attach.provider.version)?,
                    &attach.provider.implementation_digest,
                    &attach.consumer.consumer_id,
                    &to_sql_u64(attach.consumer.min_service_version)?,
                    &attach.consumer.descriptor_digest,
                    &attach.idempotency_key_digest,
                    &request_digest,
                    &attach.attached_at,
                ],
            )
            .await?;
        append_device_sync_event(
            &transaction,
            &session,
            "attached",
            attach.device_id.as_str(),
            None,
            None,
            None,
            &attach.idempotency_key_digest,
            &request_digest,
            attach.attached_at,
        )
        .await?;
        transaction.commit().await?;
        Ok(CloudDeviceSyncAttachResult {
            session,
            duplicate: false,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "head advancement keeps exact session validation, monotonic CAS, encrypted version, head, and durable log in one transaction"
    )]
    pub async fn apply_device_sync_document(
        &self,
        client: &mut Client,
        mutation: &CloudDeviceSyncDocumentMutation,
    ) -> Result<CloudDeviceSyncDocumentResult, CloudStorageError> {
        mutation.validate(self.cell())?;
        let request_digest = mutation.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &mutation.session.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(
            &transaction,
            &mutation.session.scope,
            &mutation.session.project_id,
        )
        .await?;
        lock_project(
            &transaction,
            &mutation.session.scope,
            &mutation.session.project_id,
        )
        .await?;
        ensure_current_session_tx(&transaction, &mutation.session, mutation.recorded_at).await?;

        if let Some(existing) = load_event_by_operation(
            &transaction,
            &mutation.session.scope,
            &mutation.session.project_id,
            &mutation.idempotency_key_digest,
        )
        .await?
        {
            ensure_request_digest(&existing.request_digest, &request_digest)?;
            if existing.event_type != "head_advanced" {
                return Err(CloudStorageError::IdempotencyConflict);
            }
            let head = load_version_head_tx(
                &transaction,
                &mutation.session.scope,
                &mutation.session.project_id,
                &existing.resource_id,
                existing
                    .result_revision
                    .ok_or(CloudStorageError::StoredValueInvalid(
                        "device sync event is missing its result revision".into(),
                    ))?,
                existing.sequence,
            )
            .await?;
            transaction.commit().await?;
            return Ok(CloudDeviceSyncDocumentResult {
                head,
                duplicate: true,
            });
        }

        let current = load_current_head_tx(
            &transaction,
            &mutation.session.scope,
            &mutation.session.project_id,
            &mutation.document_id,
        )
        .await?;
        let next_revision = next_document_revision(mutation, current.as_ref())?;
        let head_without_digest = CloudDeviceSyncDocumentHead {
            scope: mutation.session.scope.clone(),
            region: mutation.session.region,
            project_id: mutation.session.project_id.clone(),
            document_id: mutation.document_id.clone(),
            object_kind: mutation.object_kind,
            revision: next_revision,
            project_key_generation: mutation.session.project_key_generation,
            keyring_manifest_digest: mutation.session.keyring_manifest_digest.clone(),
            registration_version: mutation.session.registration_version,
            registration_digest: mutation.session.registration_digest.clone(),
            payload: mutation.payload.clone(),
            tombstone: mutation.tombstone,
            recorded_at: mutation.recorded_at,
            head_digest: String::new(),
            event_sequence: 0,
        };
        let head_digest = head_without_digest.digest()?;
        let head = CloudDeviceSyncDocumentHead {
            head_digest: head_digest.clone(),
            ..head_without_digest
        };
        let key_version = to_sql_u64(head.payload.key_version)?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_sync_document_versions
                   (cell, tenant_id, project_id, document_id, object_kind, revision,
                    project_key_generation, keyring_manifest_digest, registration_version,
                    registration_digest, key_version, nonce, ciphertext, aad_digest,
                    content_digest, tombstone, recorded_at, request_digest, head_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                         $13, $14, $15, $16, $17, $18, $19)",
                &[
                    &head.scope.cell.as_str(),
                    &head.scope.tenant_id.as_str(),
                    &head.project_id.as_str(),
                    &head.document_id,
                    &head.object_kind.as_str(),
                    &to_sql_u64(head.revision)?,
                    &to_sql_u64(head.project_key_generation)?,
                    &head.keyring_manifest_digest,
                    &to_sql_u64(head.registration_version)?,
                    &head.registration_digest,
                    &key_version,
                    &head.payload.nonce,
                    &head.payload.ciphertext,
                    &head.payload.aad_digest,
                    &head.payload.content_digest,
                    &head.tombstone,
                    &head.recorded_at,
                    &request_digest,
                    &head.head_digest,
                ],
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.device_sync_document_heads
                   (cell, tenant_id, project_id, document_id, object_kind, current_revision,
                    project_key_generation, keyring_manifest_digest, registration_version,
                    registration_digest, key_version, content_digest, tombstone, head_digest,
                    updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                 ON CONFLICT (cell, tenant_id, project_id, document_id) DO UPDATE
                 SET object_kind = EXCLUDED.object_kind,
                     current_revision = EXCLUDED.current_revision,
                     project_key_generation = EXCLUDED.project_key_generation,
                     keyring_manifest_digest = EXCLUDED.keyring_manifest_digest,
                     registration_version = EXCLUDED.registration_version,
                     registration_digest = EXCLUDED.registration_digest,
                     key_version = EXCLUDED.key_version,
                     content_digest = EXCLUDED.content_digest,
                     tombstone = EXCLUDED.tombstone,
                     head_digest = EXCLUDED.head_digest,
                     updated_at = EXCLUDED.updated_at",
                &[
                    &head.scope.cell.as_str(),
                    &head.scope.tenant_id.as_str(),
                    &head.project_id.as_str(),
                    &head.document_id,
                    &head.object_kind.as_str(),
                    &to_sql_u64(head.revision)?,
                    &to_sql_u64(head.project_key_generation)?,
                    &head.keyring_manifest_digest,
                    &to_sql_u64(head.registration_version)?,
                    &head.registration_digest,
                    &key_version,
                    &head.payload.content_digest,
                    &head.tombstone,
                    &head.head_digest,
                    &head.recorded_at,
                ],
            )
            .await?;
        let event_sequence = append_device_sync_event(
            &transaction,
            &mutation.session,
            "head_advanced",
            &mutation.document_id,
            Some(&mutation.document_id),
            Some(head.revision),
            Some(&head.head_digest),
            &mutation.idempotency_key_digest,
            &request_digest,
            mutation.recorded_at,
        )
        .await?;
        let head = CloudDeviceSyncDocumentHead {
            event_sequence,
            ..head
        };
        transaction.commit().await?;
        Ok(CloudDeviceSyncDocumentResult {
            head,
            duplicate: false,
        })
    }

    pub async fn load_device_sync_document(
        &self,
        client: &mut Client,
        session: &CloudDeviceSyncSession,
        document_id: &str,
        at: DateTime<Utc>,
    ) -> Result<CloudDeviceSyncDocumentHead, CloudStorageError> {
        session.validate(self.cell())?;
        if document_id.trim().is_empty() || document_id.len() > 512 {
            return Err(CloudStorageError::InvalidDeviceSyncRequest);
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, &session.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, &session.scope, &session.project_id).await?;
        lock_project(&transaction, &session.scope, &session.project_id).await?;
        ensure_current_session_tx(&transaction, session, at).await?;
        let mut head = load_current_head_tx(
            &transaction,
            &session.scope,
            &session.project_id,
            document_id,
        )
        .await?
        .ok_or(CloudStorageError::DeviceSyncDocumentNotFound)?;
        let event = load_head_event(
            &transaction,
            &session.scope,
            &session.project_id,
            document_id,
            head.revision,
            &head.head_digest,
        )
        .await?
        .ok_or(CloudStorageError::StoredValueInvalid(
            "device sync head is not durably logged".into(),
        ))?;
        head.event_sequence = event.sequence;
        transaction.commit().await?;
        Ok(head)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "release atomically fences the exact registration, lifecycle state, and durable cleanup event"
    )]
    pub async fn release_device_sync_registration(
        &self,
        client: &mut Client,
        release: &CloudDeviceSyncRelease,
    ) -> Result<CloudDeviceSyncReleaseResult, CloudStorageError> {
        release.validate(self.cell())?;
        let request_digest = release.request_digest()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &release.session.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(
            &transaction,
            &release.session.scope,
            &release.session.project_id,
        )
        .await?;
        lock_project(
            &transaction,
            &release.session.scope,
            &release.session.project_id,
        )
        .await?;
        let registration = load_registration_by_session(&transaction, &release.session, true)
            .await?
            .ok_or(CloudStorageError::DeviceSyncRegistrationNotFound)?;
        if let Some(existing) = load_event_by_operation(
            &transaction,
            &release.session.scope,
            &release.session.project_id,
            &release.idempotency_key_digest,
        )
        .await?
        {
            ensure_request_digest(&existing.request_digest, &request_digest)?;
            if existing.event_type != release.kind.event_type() {
                return Err(CloudStorageError::IdempotencyConflict);
            }
            transaction.commit().await?;
            return Ok(CloudDeviceSyncReleaseResult {
                session: registration.session,
                state: decode_release_event_state(&existing.event_type)?,
                duplicate: true,
            });
        }
        if registration.state != CloudDeviceSyncRegistrationState::Attached {
            return Err(CloudStorageError::DeviceSyncLifecycleAlreadyApplied);
        }
        let state = release.kind.state();
        release_registration_tx(
            &transaction,
            &registration,
            state,
            release.kind.event_type(),
            &release.reason_digest,
            &release.idempotency_key_digest,
            &request_digest,
            release.released_at,
        )
        .await?;
        transaction.commit().await?;
        Ok(CloudDeviceSyncReleaseResult {
            session: registration.session,
            state,
            duplicate: false,
        })
    }
}

async fn load_event_by_operation(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    operation_id_digest: &str,
) -> Result<Option<EventRecord>, CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT sequence, event_type, resource_id, document_id, result_revision,
                    result_head_digest, request_digest
             FROM hartevo_cell.device_sync_event_log
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND operation_id_digest = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &operation_id_digest,
            ],
        )
        .await?;
    row.map(|row| {
        Ok(EventRecord {
            sequence: row.get(0),
            event_type: row.get(1),
            resource_id: row.get(2),
            result_revision: row
                .get::<_, Option<i64>>(4)
                .map(|value| from_sql_u64(value, "device sync event revision"))
                .transpose()?,
            request_digest: row.get(6),
        })
    })
    .transpose()
}

#[allow(
    clippy::too_many_arguments,
    reason = "the append-only event retains every exact session, head result, operation, and recorded timestamp"
)]
async fn append_device_sync_event(
    transaction: &Transaction<'_>,
    session: &CloudDeviceSyncSession,
    event_type: &str,
    resource_id: &str,
    document_id: Option<&str>,
    result_revision: Option<u64>,
    result_head_digest: Option<&str>,
    operation_id_digest: &str,
    request_digest: &str,
    recorded_at: DateTime<Utc>,
) -> Result<i64, CloudStorageError> {
    session.validate(session.scope.cell)?;
    if !matches!(
        event_type,
        "attached"
            | "head_advanced"
            | "unmounted"
            | "revoked"
            | "crash_reclaimed"
            | "stale_generation_reclaimed"
    ) || resource_id.trim().is_empty()
        || !is_sha256(operation_id_digest)
        || !is_sha256(request_digest)
        || (event_type == "head_advanced"
            && (document_id.is_none() || result_revision.is_none() || result_head_digest.is_none()))
        || (event_type != "head_advanced"
            && (document_id.is_some() || result_revision.is_some() || result_head_digest.is_some()))
    {
        return Err(CloudStorageError::InvalidDeviceSyncRequest);
    }
    if let Some(digest) = result_head_digest
        && !is_sha256(digest)
    {
        return Err(CloudStorageError::InvalidDeviceSyncRequest);
    }
    if let Some(existing) = load_event_by_operation(
        transaction,
        &session.scope,
        &session.project_id,
        operation_id_digest,
    )
    .await?
    {
        ensure_request_digest(&existing.request_digest, request_digest)?;
        if existing.event_type != event_type {
            return Err(CloudStorageError::IdempotencyConflict);
        }
        return Ok(existing.sequence);
    }
    let result_revision_sql = result_revision.map(to_sql_u64).transpose()?;
    let event_digest = canonical_digest(&serde_json::json!({
        "schema": DEVICE_SYNC_SCHEMA,
        "session": session,
        "eventType": event_type,
        "resourceId": resource_id,
        "documentId": document_id,
        "resultRevision": result_revision,
        "resultHeadDigest": result_head_digest,
        "operationIdDigest": operation_id_digest,
        "requestDigest": request_digest,
        "recordedAt": recorded_at,
    }))?;
    let row = transaction
        .query_one(
            "INSERT INTO hartevo_cell.device_sync_event_log
               (cell, tenant_id, project_id, event_type, resource_id, device_id,
                mission_scope_digest, project_key_generation, keyring_manifest_digest,
                registration_version, registration_digest, document_id, result_revision,
                result_head_digest, operation_id_digest, request_digest, recorded_at,
                event_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                     $14, $15, $16, $17, $18)
             RETURNING sequence",
            &[
                &session.scope.cell.as_str(),
                &session.scope.tenant_id.as_str(),
                &session.project_id.as_str(),
                &event_type,
                &resource_id,
                &session.device_id.as_str(),
                &session.mission_scope_digest,
                &to_sql_u64(session.project_key_generation)?,
                &session.keyring_manifest_digest,
                &to_sql_u64(session.registration_version)?,
                &session.registration_digest,
                &document_id,
                &result_revision_sql,
                &result_head_digest,
                &operation_id_digest,
                &request_digest,
                &recorded_at,
                &event_digest,
            ],
        )
        .await?;
    Ok(row.get(0))
}

async fn load_current_head_tx(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    document_id: &str,
) -> Result<Option<CloudDeviceSyncDocumentHead>, CloudStorageError> {
    let Some(row) = transaction
        .query_opt(
            "SELECT object_kind, current_revision, project_key_generation,
                    keyring_manifest_digest, registration_version, registration_digest,
                    key_version, content_digest, tombstone, head_digest, updated_at
             FROM hartevo_cell.device_sync_document_heads
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND document_id = $4
             FOR UPDATE",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &document_id,
            ],
        )
        .await?
    else {
        return Ok(None);
    };
    let revision = from_sql_u64(row.get(1), "device sync head revision")?;
    let head =
        load_version_head_tx(transaction, scope, project_id, document_id, revision, 0).await?;
    let expected_kind = decode_sync_object_kind(row.get::<_, String>(0).as_str())?;
    if head.object_kind != expected_kind
        || head.revision != revision
        || head.project_key_generation
            != from_sql_u64(row.get(2), "device sync head key generation")?
        || head.keyring_manifest_digest != row.get::<_, String>(3)
        || head.registration_version
            != from_sql_u64(row.get(4), "device sync head registration version")?
        || head.registration_digest != row.get::<_, String>(5)
        || head.payload.key_version != from_sql_u64(row.get(6), "device sync head key version")?
        || head.payload.content_digest != row.get::<_, String>(7)
        || head.tombstone != row.get::<_, bool>(8)
        || head.head_digest != row.get::<_, String>(9)
        || head.recorded_at != row.get::<_, DateTime<Utc>>(10)
    {
        return Err(CloudStorageError::DeviceSyncDocumentFenceLost);
    }
    Ok(Some(head))
}

async fn load_version_head_tx(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    document_id: &str,
    revision: u64,
    event_sequence: i64,
) -> Result<CloudDeviceSyncDocumentHead, CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT object_kind, revision, project_key_generation,
                    keyring_manifest_digest, registration_version, registration_digest,
                    key_version, nonce, ciphertext, aad_digest, content_digest,
                    tombstone, recorded_at, head_digest
             FROM hartevo_cell.device_sync_document_versions
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND document_id = $4 AND revision = $5",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &document_id,
                &to_sql_u64(revision)?,
            ],
        )
        .await?
        .ok_or(CloudStorageError::DeviceSyncDocumentNotFound)?;
    let payload = EncryptedPayload {
        key_version: from_sql_u64(row.get(6), "device sync payload key version")?,
        nonce: row.get(7),
        ciphertext: row.get(8),
        aad_digest: row.get(9),
        content_digest: row.get(10),
    };
    payload.validate()?;
    let head = CloudDeviceSyncDocumentHead {
        scope: scope.clone(),
        region: scope.cell,
        project_id: project_id.clone(),
        document_id: document_id.into(),
        object_kind: decode_sync_object_kind(row.get::<_, String>(0).as_str())?,
        revision: from_sql_u64(row.get(1), "device sync version revision")?,
        project_key_generation: from_sql_u64(row.get(2), "device sync version key generation")?,
        keyring_manifest_digest: row.get(3),
        registration_version: from_sql_u64(row.get(4), "device sync version registration version")?,
        registration_digest: row.get(5),
        payload,
        tombstone: row.get(11),
        recorded_at: row.get(12),
        head_digest: row.get(13),
        event_sequence,
    };
    if !is_sha256(&head.head_digest) || head.digest()? != head.head_digest {
        return Err(CloudStorageError::DeviceSyncDocumentFenceLost);
    }
    Ok(head)
}

async fn load_head_event(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    document_id: &str,
    revision: u64,
    head_digest: &str,
) -> Result<Option<EventRecord>, CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT sequence, event_type, resource_id, document_id, result_revision,
                    result_head_digest, request_digest
             FROM hartevo_cell.device_sync_event_log
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND event_type = 'head_advanced' AND document_id = $4
               AND result_revision = $5 AND result_head_digest = $6
             ORDER BY sequence DESC LIMIT 1",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &document_id,
                &to_sql_u64(revision)?,
                &head_digest,
            ],
        )
        .await?;
    row.map(|row| {
        Ok(EventRecord {
            sequence: row.get(0),
            event_type: row.get(1),
            resource_id: row.get(2),
            result_revision: row
                .get::<_, Option<i64>>(4)
                .map(|value| from_sql_u64(value, "device sync event revision"))
                .transpose()?,
            request_digest: row.get(6),
        })
    })
    .transpose()
}

fn next_document_revision(
    mutation: &CloudDeviceSyncDocumentMutation,
    current: Option<&CloudDeviceSyncDocumentHead>,
) -> Result<u64, CloudStorageError> {
    let Some(current) = current else {
        return match mutation.precondition {
            MutationPrecondition::CreateOnly => Ok(1),
            expected @ MutationPrecondition::ExactRevision(_) => {
                Err(CloudStorageError::OptimisticConflict {
                    expected,
                    actual: None,
                })
            }
        };
    };
    if current.tombstone {
        return Err(CloudStorageError::SyncObjectDeleted);
    }
    if current.object_kind != mutation.object_kind {
        return Err(CloudStorageError::SyncObjectKindMismatch);
    }
    match mutation.precondition {
        MutationPrecondition::CreateOnly => Err(CloudStorageError::OptimisticConflict {
            expected: MutationPrecondition::CreateOnly,
            actual: Some(current.revision),
        }),
        MutationPrecondition::ExactRevision(expected) if expected == current.revision => current
            .revision
            .checked_add(1)
            .ok_or(CloudStorageError::RevisionOverflow),
        MutationPrecondition::ExactRevision(expected) => {
            Err(CloudStorageError::OptimisticConflict {
                expected: MutationPrecondition::ExactRevision(expected),
                actual: Some(current.revision),
            })
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "lifecycle cleanup retains exact registration, event, reason, idempotency, and timestamp fences"
)]
async fn release_registration_tx(
    transaction: &Transaction<'_>,
    registration: &RegistrationRecord,
    state: CloudDeviceSyncRegistrationState,
    event_type: &str,
    reason_digest: &str,
    operation_id_digest: &str,
    request_digest: &str,
    released_at: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    if state == CloudDeviceSyncRegistrationState::Attached
        || !matches!(
            event_type,
            "unmounted" | "revoked" | "crash_reclaimed" | "stale_generation_reclaimed"
        )
        || !is_sha256(reason_digest)
    {
        return Err(CloudStorageError::InvalidDeviceSyncRequest);
    }
    let updated = transaction
        .execute(
            "UPDATE hartevo_cell.device_sync_registrations
             SET state = $6, updated_at = $7, released_at = $7,
                 release_reason_digest = $8, revision = revision + 1
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND device_id = $4
               AND registration_version = $5 AND registration_digest = $9
               AND state = 'attached'",
            &[
                &registration.session.scope.cell.as_str(),
                &registration.session.scope.tenant_id.as_str(),
                &registration.session.project_id.as_str(),
                &registration.session.device_id.as_str(),
                &to_sql_u64(registration.session.registration_version)?,
                &state.as_str(),
                &released_at,
                &reason_digest,
                &registration.session.registration_digest,
            ],
        )
        .await?;
    if updated != 1 {
        return Err(CloudStorageError::DeviceSyncLifecycleAlreadyApplied);
    }
    append_device_sync_event(
        transaction,
        &registration.session,
        event_type,
        registration.session.device_id.as_str(),
        None,
        None,
        None,
        operation_id_digest,
        request_digest,
        released_at,
    )
    .await?;
    Ok(())
}

fn decode_sync_object_kind(value: &str) -> Result<SyncObjectKind, CloudStorageError> {
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
        _ => Err(CloudStorageError::StoredValueInvalid(
            "device sync object kind".into(),
        )),
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
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::TenantId;
    use sha2::{Digest, Sha256};

    use super::*;

    fn digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    fn timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("valid device sync timestamp")
    }

    fn payload(byte: u8) -> EncryptedPayload {
        let ciphertext = vec![byte; 48];
        EncryptedPayload {
            key_version: 1,
            nonce: vec![byte; 12],
            ciphertext: ciphertext.clone(),
            aad_digest: digest("device-sync-aad"),
            content_digest: format!("{:x}", Sha256::digest(ciphertext)),
        }
    }

    fn attach() -> CloudDeviceSyncAttach {
        let service = CloudDeviceSyncServiceDefinition::v1();
        CloudDeviceSyncAttach {
            scope: CellScope {
                cell: DataCell::Us,
                tenant_id: TenantId::from("tenant-1"),
            },
            region: DataCell::Us,
            mission_scope_digest: digest("mission-scope"),
            project_id: ProjectId::from("project-1"),
            device_id: DeviceId::from("device-2"),
            project_key_generation: 4,
            keyring_manifest_digest: digest("keyring-v4"),
            registration_version: 1,
            device_public_key_digest: digest("device-public-key"),
            provider: CloudDeviceSyncProvider {
                provider_id: "regional-cell-device-sync".into(),
                region: DataCell::Us,
                service_id: service.service_id.clone(),
                version: service.version,
                implementation_digest: digest("provider-v1"),
            },
            consumer: CloudDeviceSyncConsumer {
                consumer_id: "local-project-sync-loop".into(),
                service_id: service.service_id.clone(),
                min_service_version: service.version,
                descriptor_digest: digest("consumer-v1"),
            },
            service,
            idempotency_key_digest: digest("attach-device-2-v1"),
            attached_at: timestamp(),
        }
    }

    #[test]
    fn service_contract_is_versioned_and_lifecycle_scoped() {
        let service = CloudDeviceSyncServiceDefinition::v1();
        service.validate().expect("valid device sync service");
        assert_eq!(DEVICE_SYNC_SERVICE_ID, "hartevo.device-sync.transport");
        assert_eq!(DEVICE_SYNC_SERVICE_VERSION, 1);
        let mut changed = service;
        changed.contract_digest = "0".repeat(64);
        assert!(matches!(
            changed.validate(),
            Err(CloudStorageError::InvalidDeviceSyncRequest)
        ));
    }

    #[test]
    fn attach_digest_binds_exact_project_mission_device_generation_and_provider() {
        let base = attach();
        base.validate(DataCell::Us).expect("valid attach");
        let base_digest = base.registration_digest().expect("attach digest");
        let mut changed_generation = base.clone();
        changed_generation.project_key_generation += 1;
        assert_ne!(
            base_digest,
            changed_generation
                .registration_digest()
                .expect("changed generation digest")
        );
        let mut changed_mission = base.clone();
        changed_mission.mission_scope_digest = digest("different-mission-scope");
        assert_ne!(
            base_digest,
            changed_mission
                .registration_digest()
                .expect("changed Mission digest")
        );
        let mut wrong_region = base;
        wrong_region.region = DataCell::Eu;
        assert!(matches!(
            wrong_region.validate(DataCell::Us),
            Err(CloudStorageError::InvalidDeviceSyncRequest)
        ));
    }

    #[test]
    fn document_contract_is_ciphertext_only_and_monotonic() {
        let registration = attach();
        let session = registration.session().expect("typed session");
        let mutation = CloudDeviceSyncDocumentMutation {
            session: session.clone(),
            document_id: "mission-document-1".into(),
            object_kind: SyncObjectKind::Mission,
            precondition: MutationPrecondition::CreateOnly,
            payload: payload(7),
            tombstone: false,
            idempotency_key_digest: digest("document-v1"),
            recorded_at: timestamp(),
        };
        mutation
            .validate(DataCell::Us)
            .expect("valid encrypted SyncDocument mutation");
        let request_digest = mutation.request_digest().expect("mutation digest");
        let mut changed = mutation.clone();
        changed.session.project_key_generation += 1;
        assert_ne!(
            request_digest,
            changed.request_digest().expect("changed generation digest")
        );
        let serialized = serde_json::to_string(&mutation).expect("serialize mutation");
        assert!(!serialized.contains("PLAINTEXT"));
        assert!(serialized.contains("ciphertext"));
        let mut oversized = mutation;
        oversized.payload.ciphertext = vec![9; 16 * 1024 * 1024 + 1];
        oversized.payload.content_digest =
            format!("{:x}", Sha256::digest(&oversized.payload.ciphertext));
        assert!(matches!(
            oversized.validate(DataCell::Us),
            Err(CloudStorageError::InvalidEncryptedPayload)
        ));
        let mut precondition = CloudDeviceSyncDocumentMutation {
            session,
            document_id: "mission-document-1".into(),
            object_kind: SyncObjectKind::Mission,
            precondition: MutationPrecondition::ExactRevision(1),
            payload: payload(8),
            tombstone: false,
            idempotency_key_digest: digest("document-v2"),
            recorded_at: timestamp() + Duration::seconds(1),
        };
        let current = CloudDeviceSyncDocumentHead {
            scope: precondition.session.scope.clone(),
            region: DataCell::Us,
            project_id: precondition.session.project_id.clone(),
            document_id: precondition.document_id.clone(),
            object_kind: SyncObjectKind::Mission,
            revision: 1,
            project_key_generation: precondition.session.project_key_generation,
            keyring_manifest_digest: precondition.session.keyring_manifest_digest.clone(),
            registration_version: precondition.session.registration_version,
            registration_digest: precondition.session.registration_digest.clone(),
            payload: payload(7),
            tombstone: false,
            recorded_at: timestamp(),
            head_digest: digest("head-v1"),
            event_sequence: 1,
        };
        assert_eq!(
            next_document_revision(&precondition, Some(&current)).expect("next revision"),
            2
        );
        precondition.precondition = MutationPrecondition::ExactRevision(0);
        assert!(matches!(
            precondition.validate(DataCell::Us),
            Err(CloudStorageError::InvalidDeviceSyncRequest)
        ));
    }

    #[test]
    fn lifecycle_states_make_old_sessions_non_active() {
        assert_eq!(
            CloudDeviceSyncReleaseKind::Unmount.state(),
            CloudDeviceSyncRegistrationState::Unmounted
        );
        assert_eq!(
            CloudDeviceSyncReleaseKind::Crash.event_type(),
            "crash_reclaimed"
        );
        assert_eq!(
            CloudDeviceSyncReleaseKind::Revoke.state(),
            CloudDeviceSyncRegistrationState::Revoked
        );
    }
}

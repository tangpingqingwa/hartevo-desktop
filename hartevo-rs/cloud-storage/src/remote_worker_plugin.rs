//! Scoped Remote Worker transport plugin seam for a regional Cloud Cell.
//!
//! This module is deliberately a narrow provider/consumer registration
//! boundary. It stores descriptors, routing identities and lifecycle metadata;
//! task payloads remain encrypted and all database access remains behind the
//! Cloud Cell's exact tenant/Project/Mission scope.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{MissionId, ProjectId, WorkerId};
use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, Row, Transaction};

use super::{
    CellScope, CloudStorageError, PostgresCellStore, canonical_digest, ensure_database_cell,
    ensure_project_exists, ensure_remote_worker_project, from_sql_u64, is_sha256, lock_project,
    set_scope, to_sql_u64,
};

pub const REMOTE_WORKER_TRANSPORT_SCHEMA: &str = "hartevo.cloud-cell.remote-worker-transport/v1";
pub const REMOTE_WORKER_TRANSPORT_SERVICE_ID: &str = "hartevo.remote-worker.transport";
pub const REMOTE_WORKER_TRANSPORT_SERVICE_VERSION: u64 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerServiceDefinition {
    pub service_id: String,
    pub version: u64,
    pub contract_digest: String,
}

impl CloudRemoteWorkerServiceDefinition {
    pub fn v1() -> Self {
        Self {
            service_id: REMOTE_WORKER_TRANSPORT_SERVICE_ID.into(),
            version: REMOTE_WORKER_TRANSPORT_SERVICE_VERSION,
            contract_digest: canonical_digest(&serde_json::json!({
                "schema": REMOTE_WORKER_TRANSPORT_SCHEMA,
                "serviceId": REMOTE_WORKER_TRANSPORT_SERVICE_ID,
                "version": REMOTE_WORKER_TRANSPORT_SERVICE_VERSION,
                "operations": ["enqueue", "claim", "heartbeat", "complete"],
            }))
            .expect("static Remote Worker service definition serializes"),
        }
    }

    fn validate(&self) -> Result<(), CloudStorageError> {
        if !valid_identifier(&self.service_id)
            || self.service_id != REMOTE_WORKER_TRANSPORT_SERVICE_ID
            || self.version != REMOTE_WORKER_TRANSPORT_SERVICE_VERSION
            || !is_sha256(&self.contract_digest)
            || self != &Self::v1()
        {
            return Err(CloudStorageError::InvalidRemoteWorkerTransportDefinition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerTransportProvider {
    pub provider_id: String,
    pub service_id: String,
    pub version: u64,
    pub implementation_digest: String,
}

impl CloudRemoteWorkerTransportProvider {
    fn validate(
        &self,
        service: &CloudRemoteWorkerServiceDefinition,
    ) -> Result<(), CloudStorageError> {
        if !valid_identifier(&self.provider_id)
            || self.service_id != service.service_id
            || self.version != service.version
            || !is_sha256(&self.implementation_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerTransportDefinition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerTransportConsumer {
    pub consumer_id: String,
    pub service_id: String,
    pub min_service_version: u64,
    pub descriptor_digest: String,
}

impl CloudRemoteWorkerTransportConsumer {
    fn validate(
        &self,
        service: &CloudRemoteWorkerServiceDefinition,
    ) -> Result<(), CloudStorageError> {
        if !valid_identifier(&self.consumer_id)
            || self.service_id != service.service_id
            || self.min_service_version == 0
            || self.min_service_version > service.version
            || !is_sha256(&self.descriptor_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerTransportDefinition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRemoteWorkerTransportMount {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub plugin_id: String,
    pub service: CloudRemoteWorkerServiceDefinition,
    pub provider: CloudRemoteWorkerTransportProvider,
    pub consumer: CloudRemoteWorkerTransportConsumer,
    pub dispatch_registration_id: String,
    pub worker_id: WorkerId,
    pub idempotency_key_digest: String,
    pub mounted_at: DateTime<Utc>,
}

impl CloudRemoteWorkerTransportMount {
    pub fn validate(&self, expected_cell: super::DataCell) -> Result<(), CloudStorageError> {
        self.scope.validate(expected_cell)?;
        if self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || !valid_identifier(&self.plugin_id)
            || !is_sha256(&self.dispatch_registration_id)
            || self.worker_id.as_str().trim().is_empty()
            || !is_sha256(&self.idempotency_key_digest)
        {
            return Err(CloudStorageError::InvalidRemoteWorkerTransportDefinition);
        }
        self.service.validate()?;
        self.provider.validate(&self.service)?;
        self.consumer.validate(&self.service)?;
        Ok(())
    }

    fn request_digest(&self) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "schema": REMOTE_WORKER_TRANSPORT_SCHEMA,
            "cell": self.scope.cell,
            "tenantId": self.scope.tenant_id,
            "projectId": self.project_id,
            "missionId": self.mission_id,
            "pluginId": self.plugin_id,
            "service": self.service,
            "provider": self.provider,
            "consumer": self.consumer,
            "dispatchRegistrationId": self.dispatch_registration_id,
            "workerId": self.worker_id,
            "mountedAt": self.mounted_at,
        }))
    }

    fn registration_id(&self) -> String {
        format!("rwt-{}", &self.idempotency_key_digest[..32])
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRemoteWorkerTransportRegistrationState {
    Mounted,
    Unmounted,
    Revoked,
}

impl CloudRemoteWorkerTransportRegistrationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mounted => "mounted",
            Self::Unmounted => "unmounted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudRemoteWorkerTransportRegistration {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub registration_id: String,
    pub dispatch_registration_id: String,
    pub plugin_id: String,
    pub service: CloudRemoteWorkerServiceDefinition,
    pub provider: CloudRemoteWorkerTransportProvider,
    pub consumer: CloudRemoteWorkerTransportConsumer,
    pub worker_id: WorkerId,
    pub state: CloudRemoteWorkerTransportRegistrationState,
    pub mounted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub unmounted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason_digest: Option<String>,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudRemoteWorkerTransportMountResult {
    pub registration_id: String,
    pub dispatch_registration_id: String,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudRemoteWorkerTransportLifecycleResult {
    pub registration_id: String,
    pub state: CloudRemoteWorkerTransportRegistrationState,
    pub mailbox_rows_cleaned: u64,
    pub leases_cleared: u64,
    pub dispatch_registrations_removed: u64,
    pub duplicate: bool,
}

impl PostgresCellStore {
    #[allow(
        clippy::too_many_lines,
        reason = "mounting persists the complete typed provider/consumer seam atomically"
    )]
    pub async fn mount_remote_worker_transport(
        &self,
        client: &mut Client,
        mount: &CloudRemoteWorkerTransportMount,
    ) -> Result<CloudRemoteWorkerTransportMountResult, CloudStorageError> {
        mount.validate(self.cell())?;
        let request_digest = mount.request_digest()?;
        let registration_id = mount.registration_id();
        let transaction = client.transaction().await?;
        set_scope(&transaction, &mount.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_remote_worker_project(&transaction, &mount.scope, &mount.project_id).await?;
        lock_project(&transaction, &mount.scope, &mount.project_id).await?;

        if let Some(existing) = transaction
            .query_opt(
                "SELECT registration_id, dispatch_registration_id, request_digest
                 FROM hartevo_cell.remote_worker_transport_registrations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND mission_id = $4 AND idempotency_key = $5",
                &[
                    &mount.scope.cell.as_str(),
                    &mount.scope.tenant_id.as_str(),
                    &mount.project_id.as_str(),
                    &mount.mission_id.as_str(),
                    &mount.idempotency_key_digest,
                ],
            )
            .await?
        {
            super::ensure_request_digest(&existing.get::<_, String>(2), &request_digest)?;
            transaction.commit().await?;
            return Ok(CloudRemoteWorkerTransportMountResult {
                registration_id: existing.get(0),
                dispatch_registration_id: existing.get(1),
                duplicate: true,
            });
        }

        if transaction
            .query_opt(
                "SELECT 1
                 FROM hartevo_cell.remote_worker_transport_registrations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND mission_id = $4 AND service_id = $5 AND state = 'mounted'",
                &[
                    &mount.scope.cell.as_str(),
                    &mount.scope.tenant_id.as_str(),
                    &mount.project_id.as_str(),
                    &mount.mission_id.as_str(),
                    &mount.service.service_id,
                ],
            )
            .await?
            .is_some()
        {
            return Err(CloudStorageError::RemoteWorkerTransportAlreadyMounted);
        }

        transaction
            .execute(
                "INSERT INTO hartevo_cell.remote_worker_transport_registrations
                   (cell, tenant_id, project_id, mission_id, registration_id,
                    dispatch_registration_id, worker_id, plugin_id, service_id, service_version,
                    service_contract_digest, provider_id, provider_version,
                    provider_implementation_digest, consumer_id,
                    consumer_min_service_version, consumer_descriptor_digest,
                    idempotency_key, request_digest, state, mounted_at, updated_at, revision)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                         $13, $14, $15, $16, $17, $18, $19, 'mounted', $20, $20, 1)",
                &[
                    &mount.scope.cell.as_str(),
                    &mount.scope.tenant_id.as_str(),
                    &mount.project_id.as_str(),
                    &mount.mission_id.as_str(),
                    &registration_id,
                    &mount.dispatch_registration_id,
                    &mount.worker_id.as_str(),
                    &mount.plugin_id,
                    &mount.service.service_id,
                    &to_sql_u64(mount.service.version)?,
                    &mount.service.contract_digest,
                    &mount.provider.provider_id,
                    &to_sql_u64(mount.provider.version)?,
                    &mount.provider.implementation_digest,
                    &mount.consumer.consumer_id,
                    &to_sql_u64(mount.consumer.min_service_version)?,
                    &mount.consumer.descriptor_digest,
                    &mount.idempotency_key_digest,
                    &request_digest,
                    &mount.mounted_at,
                ],
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO hartevo_cell.remote_worker_dispatch_registrations
                   (cell, tenant_id, project_id, mission_id, registration_id,
                    dispatch_registration_id, worker_id, registered_at, updated_at, revision)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, 1)",
                &[
                    &mount.scope.cell.as_str(),
                    &mount.scope.tenant_id.as_str(),
                    &mount.project_id.as_str(),
                    &mount.mission_id.as_str(),
                    &registration_id,
                    &mount.dispatch_registration_id,
                    &mount.worker_id.as_str(),
                    &mount.mounted_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(CloudRemoteWorkerTransportMountResult {
            registration_id,
            dispatch_registration_id: mount.dispatch_registration_id.clone(),
            duplicate: false,
        })
    }

    pub async fn load_remote_worker_transport_registration(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        mission_id: &MissionId,
        registration_id: &str,
    ) -> Result<CloudRemoteWorkerTransportRegistration, CloudStorageError> {
        validate_registration_lookup(self.cell(), scope, project_id, mission_id, registration_id)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, scope, project_id).await?;
        let row = transaction
            .query_opt(
                REGISTRATION_SELECT_SQL,
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &mission_id.as_str(),
                    &registration_id,
                ],
            )
            .await?
            .ok_or(CloudStorageError::RemoteWorkerTransportRegistrationNotFound)?;
        let registration = decode_registration_row(&row, scope)?;
        transaction.commit().await?;
        Ok(registration)
    }

    pub async fn unmount_remote_worker_transport(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        mission_id: &MissionId,
        registration_id: &str,
        unmounted_at: DateTime<Utc>,
    ) -> Result<CloudRemoteWorkerTransportLifecycleResult, CloudStorageError> {
        self.terminate_remote_worker_transport(
            client,
            scope,
            project_id,
            mission_id,
            registration_id,
            CloudRemoteWorkerTransportRegistrationState::Unmounted,
            None,
            unmounted_at,
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "revocation keeps exact Project/Mission registration scope and reason explicit"
    )]
    pub async fn revoke_remote_worker_transport(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        mission_id: &MissionId,
        registration_id: &str,
        revocation_reason_digest: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<CloudRemoteWorkerTransportLifecycleResult, CloudStorageError> {
        if !is_sha256(revocation_reason_digest) {
            return Err(CloudStorageError::InvalidRemoteWorkerTransportDefinition);
        }
        self.terminate_remote_worker_transport(
            client,
            scope,
            project_id,
            mission_id,
            registration_id,
            CloudRemoteWorkerTransportRegistrationState::Revoked,
            Some(revocation_reason_digest),
            revoked_at,
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "lifecycle termination atomically fences leases and removes dispatch registrations"
    )]
    async fn terminate_remote_worker_transport(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        mission_id: &MissionId,
        registration_id: &str,
        state: CloudRemoteWorkerTransportRegistrationState,
        revocation_reason_digest: Option<&str>,
        terminated_at: DateTime<Utc>,
    ) -> Result<CloudRemoteWorkerTransportLifecycleResult, CloudStorageError> {
        validate_registration_lookup(self.cell(), scope, project_id, mission_id, registration_id)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, scope, project_id).await?;
        lock_project(&transaction, scope, project_id).await?;
        let registration = transaction
            .query_opt(
                REGISTRATION_SELECT_SQL,
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &mission_id.as_str(),
                    &registration_id,
                ],
            )
            .await?
            .ok_or(CloudStorageError::RemoteWorkerTransportRegistrationNotFound)?;
        let current = decode_registration_row(&registration, scope)?;
        if current.state != CloudRemoteWorkerTransportRegistrationState::Mounted {
            transaction.commit().await?;
            return Ok(CloudRemoteWorkerTransportLifecycleResult {
                registration_id: registration_id.into(),
                state: current.state,
                mailbox_rows_cleaned: 0,
                leases_cleared: 0,
                dispatch_registrations_removed: 0,
                duplicate: true,
            });
        }

        let mailbox_status = match state {
            CloudRemoteWorkerTransportRegistrationState::Unmounted => "pending",
            CloudRemoteWorkerTransportRegistrationState::Revoked => "dead_letter",
            CloudRemoteWorkerTransportRegistrationState::Mounted => {
                return Err(CloudStorageError::InvalidRemoteWorkerTransportDefinition);
            }
        };

        let leased_rows = transaction
            .query_one(
                "SELECT count(*)
                 FROM hartevo_cell.remote_worker_mailbox_messages
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND mission_id = $4 AND dispatch_registration_id = $5
                   AND status = 'leased'",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &mission_id.as_str(),
                    &current.dispatch_registration_id,
                ],
            )
            .await?
            .get::<_, i64>(0);
        let cleaned_rows = transaction
            .execute(
                "UPDATE hartevo_cell.remote_worker_mailbox_messages
                 SET status = $6, lease_id = NULL, lease_generation = 0,
                     lease_owner = NULL, lease_token_digest = NULL,
                     claim_idempotency_key = NULL, claim_request_digest = NULL,
                     lease_expires_at = NULL, heartbeat_at = NULL,
                     updated_at = $7, revision = revision + 1
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND mission_id = $4 AND dispatch_registration_id = $5
                   AND status IN ('pending', 'leased')",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &mission_id.as_str(),
                    &current.dispatch_registration_id,
                    &mailbox_status,
                    &terminated_at,
                ],
            )
            .await?;
        let removed_dispatches = transaction
            .execute(
                "DELETE FROM hartevo_cell.remote_worker_dispatch_registrations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND mission_id = $4 AND registration_id = $5
                   AND dispatch_registration_id = $6",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &mission_id.as_str(),
                    &registration_id,
                    &current.dispatch_registration_id,
                ],
            )
            .await?;
        transaction
            .execute(
                "UPDATE hartevo_cell.remote_worker_transport_registrations
                 SET state = $6, updated_at = $7,
                     unmounted_at = CASE WHEN $6 = 'unmounted' THEN $7 ELSE unmounted_at END,
                     revoked_at = CASE WHEN $6 = 'revoked' THEN $7 ELSE revoked_at END,
                     revocation_reason_digest = COALESCE($8, revocation_reason_digest),
                     revision = revision + 1
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND mission_id = $4 AND registration_id = $5
                   AND state = 'mounted'",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &mission_id.as_str(),
                    &registration_id,
                    &state.as_str(),
                    &terminated_at,
                    &revocation_reason_digest,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(CloudRemoteWorkerTransportLifecycleResult {
            registration_id: registration_id.into(),
            state,
            mailbox_rows_cleaned: cleaned_rows,
            leases_cleared: u64::try_from(leased_rows)
                .map_err(|_| CloudStorageError::RevisionOverflow)?,
            dispatch_registrations_removed: removed_dispatches,
            duplicate: false,
        })
    }
}

pub(crate) async fn ensure_remote_worker_dispatch_active(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    mission_id: &MissionId,
    dispatch_registration_id: &str,
    worker_id: &WorkerId,
) -> Result<(), CloudStorageError> {
    if transaction
        .query_opt(
            "SELECT 1
             FROM hartevo_cell.remote_worker_dispatch_registrations AS dispatch
             JOIN hartevo_cell.remote_worker_transport_registrations AS registration
               ON registration.cell = dispatch.cell
              AND registration.tenant_id = dispatch.tenant_id
              AND registration.project_id = dispatch.project_id
              AND registration.mission_id = dispatch.mission_id
              AND registration.registration_id = dispatch.registration_id
             WHERE dispatch.cell = $1 AND dispatch.tenant_id = $2
               AND dispatch.project_id = $3 AND dispatch.mission_id = $4
               AND dispatch.dispatch_registration_id = $5
               AND dispatch.worker_id = $6 AND registration.state = 'mounted'",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &mission_id.as_str(),
                &dispatch_registration_id,
                &worker_id.as_str(),
            ],
        )
        .await?
        .is_none()
    {
        return Err(CloudStorageError::RemoteWorkerDispatchNotRegistered);
    }
    Ok(())
}

fn validate_registration_lookup(
    expected_cell: super::DataCell,
    scope: &CellScope,
    project_id: &ProjectId,
    mission_id: &MissionId,
    registration_id: &str,
) -> Result<(), CloudStorageError> {
    scope.validate(expected_cell)?;
    if project_id.as_str().trim().is_empty()
        || mission_id.as_str().trim().is_empty()
        || !valid_identifier(registration_id)
    {
        return Err(CloudStorageError::InvalidRemoteWorkerTransportDefinition);
    }
    Ok(())
}

const REGISTRATION_SELECT_SQL: &str = "SELECT project_id, mission_id, registration_id,
       dispatch_registration_id, worker_id, plugin_id, service_id, service_version,
       service_contract_digest, provider_id, provider_version,
       provider_implementation_digest, consumer_id, consumer_min_service_version,
       consumer_descriptor_digest, state, mounted_at, updated_at, unmounted_at,
       revoked_at, revocation_reason_digest, revision
FROM hartevo_cell.remote_worker_transport_registrations
WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
  AND mission_id = $4 AND registration_id = $5";

fn decode_registration_row(
    row: &Row,
    scope: &CellScope,
) -> Result<CloudRemoteWorkerTransportRegistration, CloudStorageError> {
    let service = CloudRemoteWorkerServiceDefinition {
        service_id: row.get(6),
        version: from_sql_u64(row.get(7), "remote Worker service version")?,
        contract_digest: row.get(8),
    };
    let provider = CloudRemoteWorkerTransportProvider {
        provider_id: row.get(9),
        service_id: service.service_id.clone(),
        version: from_sql_u64(row.get(10), "remote Worker provider version")?,
        implementation_digest: row.get(11),
    };
    let consumer = CloudRemoteWorkerTransportConsumer {
        consumer_id: row.get(12),
        service_id: service.service_id.clone(),
        min_service_version: from_sql_u64(row.get(13), "remote Worker consumer version")?,
        descriptor_digest: row.get(14),
    };
    let registration = CloudRemoteWorkerTransportRegistration {
        scope: scope.clone(),
        project_id: ProjectId::from_stable(row.get::<_, String>(0)),
        mission_id: MissionId::from_stable(row.get::<_, String>(1)),
        registration_id: row.get(2),
        dispatch_registration_id: row.get(3),
        plugin_id: row.get(5),
        service,
        provider,
        consumer,
        worker_id: WorkerId::from_stable(row.get::<_, String>(4)),
        state: decode_registration_state(&row.get::<_, String>(15))?,
        mounted_at: row.get(16),
        updated_at: row.get(17),
        unmounted_at: row.get(18),
        revoked_at: row.get(19),
        revocation_reason_digest: row.get(20),
        revision: from_sql_u64(row.get(21), "remote Worker registration revision")?,
    };
    if !is_sha256(&registration.dispatch_registration_id)
        || !is_sha256(&registration.service.contract_digest)
        || !is_sha256(&registration.provider.implementation_digest)
        || !is_sha256(&registration.consumer.descriptor_digest)
        || !valid_identifier(&registration.registration_id)
        || !valid_identifier(&registration.plugin_id)
        || registration.worker_id.as_str().trim().is_empty()
        || registration
            .revocation_reason_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
    {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote Worker transport registration digest".into(),
        ));
    }
    registration.service.validate().map_err(|_| {
        CloudStorageError::StoredValueInvalid("remote Worker service definition".into())
    })?;
    registration
        .provider
        .validate(&registration.service)
        .map_err(|_| {
            CloudStorageError::StoredValueInvalid("remote Worker provider definition".into())
        })?;
    registration
        .consumer
        .validate(&registration.service)
        .map_err(|_| {
            CloudStorageError::StoredValueInvalid("remote Worker consumer definition".into())
        })?;
    Ok(registration)
}

fn decode_registration_state(
    value: &str,
) -> Result<CloudRemoteWorkerTransportRegistrationState, CloudStorageError> {
    match value {
        "mounted" => Ok(CloudRemoteWorkerTransportRegistrationState::Mounted),
        "unmounted" => Ok(CloudRemoteWorkerTransportRegistrationState::Unmounted),
        "revoked" => Ok(CloudRemoteWorkerTransportRegistrationState::Revoked),
        _ => Err(CloudStorageError::StoredValueInvalid(
            "remote Worker transport registration state".into(),
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
    use hartevo_domain_kernel::{MissionId, ProjectId, TenantId, WorkerId};

    use super::*;

    fn scope() -> CellScope {
        CellScope {
            cell: super::super::DataCell::Us,
            tenant_id: TenantId::from("tenant-1"),
        }
    }

    fn mount() -> CloudRemoteWorkerTransportMount {
        let service = CloudRemoteWorkerServiceDefinition::v1();
        CloudRemoteWorkerTransportMount {
            scope: scope(),
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-1"),
            plugin_id: "cloud-cell.remote-worker".into(),
            provider: CloudRemoteWorkerTransportProvider {
                provider_id: "cloud-cell.remote-worker.provider".into(),
                service_id: service.service_id.clone(),
                version: service.version,
                implementation_digest: "a".repeat(64),
            },
            consumer: CloudRemoteWorkerTransportConsumer {
                consumer_id: "mission.remote-worker.consumer".into(),
                service_id: service.service_id.clone(),
                min_service_version: service.version,
                descriptor_digest: "b".repeat(64),
            },
            service,
            dispatch_registration_id: "c".repeat(64),
            worker_id: WorkerId::from("worker-1"),
            idempotency_key_digest: "d".repeat(64),
            mounted_at: DateTime::from_timestamp(1_755_000_000, 0).expect("valid test time"),
        }
    }

    #[test]
    fn service_definition_is_the_versioned_v1_contract() {
        let service = CloudRemoteWorkerServiceDefinition::v1();
        service.validate().expect("valid v1 service definition");
        let mut changed = service.clone();
        changed.contract_digest = "0".repeat(64);
        assert!(matches!(
            changed.validate(),
            Err(CloudStorageError::InvalidRemoteWorkerTransportDefinition)
        ));
    }

    #[test]
    fn mount_contract_binds_exact_scope_and_dispatch_identity() {
        let base = mount();
        base.validate(super::super::DataCell::Us)
            .expect("valid transport mount");
        let base_digest = base.request_digest().expect("mount request digest");
        let mut changed_mission = base.clone();
        changed_mission.mission_id = MissionId::from("mission-2");
        assert_ne!(
            base_digest,
            changed_mission
                .request_digest()
                .expect("changed mission request digest")
        );
        let mut changed_dispatch = mount();
        changed_dispatch.dispatch_registration_id = "e".repeat(64);
        assert_ne!(
            base_digest,
            changed_dispatch
                .request_digest()
                .expect("changed dispatch request digest")
        );
    }

    #[test]
    fn lifecycle_states_are_terminal_and_serialized_exactly() {
        assert_eq!(
            CloudRemoteWorkerTransportRegistrationState::Mounted.as_str(),
            "mounted"
        );
        assert_eq!(
            CloudRemoteWorkerTransportRegistrationState::Unmounted.as_str(),
            "unmounted"
        );
        assert_eq!(
            CloudRemoteWorkerTransportRegistrationState::Revoked.as_str(),
            "revoked"
        );
    }
}

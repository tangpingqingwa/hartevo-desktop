use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{ProjectId, TenantId};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::aggregate::{PendingEvent, append_events};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBootstrapCell {
    Us,
    Eu,
}

impl KeyBootstrapCell {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Us => "us",
            Self::Eu => "eu",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBootstrapOperationKind {
    DevicePublicKey,
    KeyringBootstrap,
    HandoffGrant,
    HandoffClaim,
    HandoffRevocation,
    HandoffConsumption,
}

impl KeyBootstrapOperationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DevicePublicKey => "device_public_key",
            Self::KeyringBootstrap => "keyring_bootstrap",
            Self::HandoffGrant => "handoff_grant",
            Self::HandoffClaim => "handoff_claim",
            Self::HandoffRevocation => "handoff_revocation",
            Self::HandoffConsumption => "handoff_consumption",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBootstrapOperationStatus {
    Prepared,
    Applied,
    Conflict,
}

impl KeyBootstrapOperationStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applied => "applied",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalKeyBootstrapOperation {
    pub operation_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub cell: KeyBootstrapCell,
    pub kind: KeyBootstrapOperationKind,
    pub idempotency_key_digest: String,
    pub request_digest: String,
    pub request: Value,
    pub status: KeyBootstrapOperationStatus,
    pub remote_revision: Option<u64>,
    pub remote_reference: Option<String>,
    pub error_code: Option<String>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyBootstrapPrepareOutcome {
    pub operation: LocalKeyBootstrapOperation,
    pub duplicate: bool,
}

impl ProjectStore {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the local prepare transaction keeps exact request fencing, sensitive-field rejection, persistence, and audit append visibly ordered"
    )]
    pub fn prepare_key_bootstrap_operation(
        &mut self,
        tenant_id: TenantId,
        project_id: ProjectId,
        cell: KeyBootstrapCell,
        kind: KeyBootstrapOperationKind,
        idempotency_key_digest: String,
        request: Value,
        now: DateTime<Utc>,
    ) -> Result<KeyBootstrapPrepareOutcome, StorageError> {
        validate_sha256(&idempotency_key_digest)?;
        validate_bootstrap_payload(&request)?;
        let request_digest = canonical_digest(&request)?;
        let operation_id = format!("key-bootstrap:{}:{}", kind.as_str(), idempotency_key_digest);
        let candidate = LocalKeyBootstrapOperation {
            operation_id,
            tenant_id,
            project_id,
            cell,
            kind,
            idempotency_key_digest,
            request_digest,
            request,
            status: KeyBootstrapOperationStatus::Prepared,
            remote_revision: None,
            remote_reference: None,
            error_code: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        validate_operation(&candidate)?;
        let transaction = self.connection.transaction()?;
        let stored_tenant = transaction
            .query_row(
                "SELECT tenant_id FROM projects WHERE id = ?1",
                [candidate.project_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::ProjectNotFound(candidate.project_id.clone()))?;
        if stored_tenant != candidate.tenant_id.as_str() {
            return Err(StorageError::TenantScopeMismatch);
        }
        if let Some(existing) = load_operation_by_idempotency(
            &transaction,
            &candidate.project_id,
            candidate.kind,
            &candidate.idempotency_key_digest,
        )? {
            if existing.request_digest != candidate.request_digest
                || existing.request != candidate.request
                || existing.tenant_id != candidate.tenant_id
                || existing.cell != candidate.cell
            {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "key bootstrap operation request",
                    id: candidate.idempotency_key_digest,
                });
            }
            transaction.commit()?;
            return Ok(KeyBootstrapPrepareOutcome {
                operation: existing,
                duplicate: true,
            });
        }
        transaction.execute(
            "INSERT INTO key_bootstrap_operations
               (operation_id, tenant_id, project_id, cell, operation_kind,
                idempotency_key_digest, request_digest, request_json, status,
                remote_revision, remote_reference, error_code, operation_revision,
                created_at, updated_at)
             VALUES
               (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL, 1, ?10, ?10)",
            params![
                candidate.operation_id,
                candidate.tenant_id.as_str(),
                candidate.project_id.as_str(),
                candidate.cell.as_str(),
                candidate.kind.as_str(),
                candidate.idempotency_key_digest,
                candidate.request_digest,
                serde_json::to_string(&candidate.request)?,
                candidate.status.as_str(),
                candidate.created_at.to_rfc3339(),
            ],
        )?;
        append_events(
            &transaction,
            candidate.tenant_id.as_str(),
            candidate.project_id.as_str(),
            None,
            "key_bootstrap_operation",
            &candidate.operation_id,
            &[PendingEvent::new(
                "project_keyring.bootstrap_operation_prepared",
                serde_json::json!({
                    "operationId": candidate.operation_id,
                    "operationKind": candidate.kind.as_str(),
                    "cell": candidate.cell.as_str(),
                    "requestDigest": candidate.request_digest,
                    "idempotencyKeyDigest": candidate.idempotency_key_digest,
                }),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(KeyBootstrapPrepareOutcome {
            operation: candidate,
            duplicate: false,
        })
    }

    pub fn load_key_bootstrap_operation(
        &self,
        project_id: &ProjectId,
        kind: KeyBootstrapOperationKind,
        idempotency_key_digest: &str,
    ) -> Result<LocalKeyBootstrapOperation, StorageError> {
        load_operation_by_idempotency(&self.connection, project_id, kind, idempotency_key_digest)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "key bootstrap operation",
                project_id: project_id.clone(),
                id: idempotency_key_digest.to_owned(),
            })
    }

    pub fn mark_key_bootstrap_operation_applied(
        &mut self,
        operation: &LocalKeyBootstrapOperation,
        remote_revision: Option<u64>,
        remote_reference: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<LocalKeyBootstrapOperation, StorageError> {
        if operation.status == KeyBootstrapOperationStatus::Applied {
            return Ok(operation.clone());
        }
        if operation.status != KeyBootstrapOperationStatus::Prepared
            || operation.revision != 1
            || remote_revision == Some(0)
            || remote_reference
                .as_ref()
                .is_some_and(|reference| reference.trim().is_empty())
            || (remote_revision.is_none() && remote_reference.is_none())
            || now < operation.updated_at
        {
            return Err(StorageError::InvalidKeyBootstrapOperationTransition);
        }
        self.finish_key_bootstrap_operation(
            operation,
            KeyBootstrapOperationStatus::Applied,
            remote_revision,
            remote_reference,
            None,
            now,
        )
    }

    pub fn mark_key_bootstrap_operation_conflict(
        &mut self,
        operation: &LocalKeyBootstrapOperation,
        error_code: String,
        now: DateTime<Utc>,
    ) -> Result<LocalKeyBootstrapOperation, StorageError> {
        if operation.status != KeyBootstrapOperationStatus::Prepared
            || operation.revision != 1
            || error_code.trim().is_empty()
            || now < operation.updated_at
        {
            return Err(StorageError::InvalidKeyBootstrapOperationTransition);
        }
        self.finish_key_bootstrap_operation(
            operation,
            KeyBootstrapOperationStatus::Conflict,
            None,
            None,
            Some(error_code),
            now,
        )
    }

    fn finish_key_bootstrap_operation(
        &mut self,
        operation: &LocalKeyBootstrapOperation,
        status: KeyBootstrapOperationStatus,
        remote_revision: Option<u64>,
        remote_reference: Option<String>,
        error_code: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<LocalKeyBootstrapOperation, StorageError> {
        let mut next = operation.clone();
        next.status = status;
        next.remote_revision = remote_revision;
        next.remote_reference = remote_reference;
        next.error_code = error_code;
        next.revision = 2;
        next.updated_at = now;
        validate_operation(&next)?;
        let transaction = self.connection.transaction()?;
        let updated = transaction.execute(
            "UPDATE key_bootstrap_operations
             SET status = ?4, remote_revision = ?5, remote_reference = ?6,
                 error_code = ?7, operation_revision = 2, updated_at = ?8
             WHERE project_id = ?1 AND operation_id = ?2
               AND operation_revision = ?3 AND status = 'prepared'",
            params![
                next.project_id.as_str(),
                next.operation_id,
                to_sql_u64(operation.revision)?,
                next.status.as_str(),
                next.remote_revision.map(to_sql_u64).transpose()?,
                next.remote_reference,
                next.error_code,
                next.updated_at.to_rfc3339(),
            ],
        )?;
        if updated != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("key_bootstrap_operation:{}", operation.operation_id),
                expected_revision: operation.revision,
            });
        }
        append_events(
            &transaction,
            next.tenant_id.as_str(),
            next.project_id.as_str(),
            None,
            "key_bootstrap_operation",
            &next.operation_id,
            &[PendingEvent::new(
                if status == KeyBootstrapOperationStatus::Applied {
                    "project_keyring.bootstrap_operation_applied"
                } else {
                    "project_keyring.bootstrap_operation_conflict"
                },
                serde_json::json!({
                    "operationId": next.operation_id,
                    "operationKind": next.kind.as_str(),
                    "cell": next.cell.as_str(),
                    "requestDigest": next.request_digest,
                    "remoteRevision": next.remote_revision,
                    "remoteReference": next.remote_reference,
                    "errorCode": next.error_code,
                }),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(next)
    }
}

fn load_operation_by_idempotency(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    kind: KeyBootstrapOperationKind,
    idempotency_key_digest: &str,
) -> Result<Option<LocalKeyBootstrapOperation>, StorageError> {
    let row = connection
        .query_row(
            "SELECT operation_id, tenant_id, cell, request_digest, request_json,
                    status, remote_revision, remote_reference, error_code,
                    operation_revision, created_at, updated_at
             FROM key_bootstrap_operations
             WHERE project_id = ?1 AND operation_kind = ?2 AND idempotency_key_digest = ?3",
            params![project_id.as_str(), kind.as_str(), idempotency_key_digest],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let operation = LocalKeyBootstrapOperation {
        operation_id: row.0,
        tenant_id: TenantId::from_stable(row.1),
        project_id: project_id.clone(),
        cell: decode_cell(&row.2)?,
        kind,
        idempotency_key_digest: idempotency_key_digest.to_owned(),
        request_digest: row.3,
        request: serde_json::from_str(&row.4)?,
        status: decode_status(&row.5)?,
        remote_revision: row
            .6
            .map(|value| from_sql_u64(value, "remote revision"))
            .transpose()?,
        remote_reference: row.7,
        error_code: row.8,
        revision: from_sql_u64(row.9, "key bootstrap operation revision")?,
        created_at: DateTime::parse_from_rfc3339(&row.10)?.with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&row.11)?.with_timezone(&Utc),
    };
    validate_operation(&operation)?;
    Ok(Some(operation))
}

fn validate_operation(operation: &LocalKeyBootstrapOperation) -> Result<(), StorageError> {
    validate_sha256(&operation.idempotency_key_digest)?;
    validate_sha256(&operation.request_digest)?;
    validate_bootstrap_payload(&operation.request)?;
    if operation.operation_id.trim().is_empty()
        || operation.tenant_id.as_str().trim().is_empty()
        || operation.project_id.as_str().trim().is_empty()
        || canonical_digest(&operation.request)? != operation.request_digest
        || operation.created_at > operation.updated_at
        || match operation.status {
            KeyBootstrapOperationStatus::Prepared => {
                operation.revision != 1
                    || operation.remote_revision.is_some()
                    || operation.remote_reference.is_some()
                    || operation.error_code.is_some()
            }
            KeyBootstrapOperationStatus::Applied => {
                operation.revision != 2
                    || (operation.remote_revision.is_none() && operation.remote_reference.is_none())
                    || operation.error_code.is_some()
            }
            KeyBootstrapOperationStatus::Conflict => {
                operation.revision != 2
                    || operation.remote_revision.is_some()
                    || operation.remote_reference.is_some()
                    || operation
                        .error_code
                        .as_ref()
                        .is_none_or(|code| code.trim().is_empty())
            }
        }
    {
        return Err(StorageError::InvalidKeyBootstrapOperation);
    }
    Ok(())
}

fn validate_bootstrap_payload(value: &Value) -> Result<(), StorageError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized = key
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if matches!(
                    normalized.as_str(),
                    "privatekey"
                        | "privatekeybytes"
                        | "recoverysecret"
                        | "accesstoken"
                        | "refreshtoken"
                        | "token"
                        | "cookie"
                        | "cookies"
                        | "secret"
                ) {
                    return Err(StorageError::SensitiveKeyBootstrapPayload);
                }
                validate_bootstrap_payload(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_bootstrap_payload(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn canonical_digest(value: &Value) -> Result<String, StorageError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn validate_sha256(value: &str) -> Result<(), StorageError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StorageError::InvalidKeyBootstrapOperation);
    }
    Ok(())
}

fn decode_cell(value: &str) -> Result<KeyBootstrapCell, StorageError> {
    match value {
        "us" => Ok(KeyBootstrapCell::Us),
        "eu" => Ok(KeyBootstrapCell::Eu),
        other => Err(StorageError::DomainDecode(format!(
            "key bootstrap Cell {other}"
        ))),
    }
}

fn decode_status(value: &str) -> Result<KeyBootstrapOperationStatus, StorageError> {
    match value {
        "prepared" => Ok(KeyBootstrapOperationStatus::Prepared),
        "applied" => Ok(KeyBootstrapOperationStatus::Applied),
        "conflict" => Ok(KeyBootstrapOperationStatus::Conflict),
        other => Err(StorageError::DomainDecode(format!(
            "key bootstrap operation status {other}"
        ))),
    }
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::DomainDecode(field.into()))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{Project, StorageMode};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn store_and_project() -> (ProjectStore, Project) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Bootstrap",
            "",
            "/tmp/hartevo-bootstrap-ledger",
            StorageMode::LocalEncryptedSync,
        )
        .expect("project");
        store.save_project(&project).expect("save project");
        (store, project)
    }

    #[test]
    fn bootstrap_request_is_durable_exact_and_restart_safe() {
        let (mut store, project) = store_and_project();
        let request = serde_json::json!({
            "deviceId": "device-2",
            "publicKey": vec![7; 32],
            "publicKeyDigest": "a".repeat(64),
        });
        let first = store
            .prepare_key_bootstrap_operation(
                project.tenant_id.clone(),
                project.id.clone(),
                KeyBootstrapCell::Eu,
                KeyBootstrapOperationKind::DevicePublicKey,
                "b".repeat(64),
                request.clone(),
                now(),
            )
            .expect("prepare operation");
        assert!(!first.duplicate);
        let replay = store
            .prepare_key_bootstrap_operation(
                project.tenant_id.clone(),
                project.id.clone(),
                KeyBootstrapCell::Eu,
                KeyBootstrapOperationKind::DevicePublicKey,
                "b".repeat(64),
                request,
                now() + chrono::Duration::minutes(1),
            )
            .expect("exact replay");
        assert!(replay.duplicate);
        let applied = store
            .mark_key_bootstrap_operation_applied(
                &replay.operation,
                Some(1),
                None,
                now() + chrono::Duration::minutes(2),
            )
            .expect("mark applied");
        assert_eq!(applied.status, KeyBootstrapOperationStatus::Applied);
        assert_eq!(applied.revision, 2);
    }

    #[test]
    fn bootstrap_ledger_rejects_secret_fields_and_idempotency_payload_swap() {
        let (mut store, project) = store_and_project();
        assert!(matches!(
            store.prepare_key_bootstrap_operation(
                project.tenant_id.clone(),
                project.id.clone(),
                KeyBootstrapCell::Us,
                KeyBootstrapOperationKind::HandoffGrant,
                "c".repeat(64),
                serde_json::json!({"privateKey": vec![9; 32]}),
                now(),
            ),
            Err(StorageError::SensitiveKeyBootstrapPayload)
        ));
        store
            .prepare_key_bootstrap_operation(
                project.tenant_id.clone(),
                project.id.clone(),
                KeyBootstrapCell::Us,
                KeyBootstrapOperationKind::HandoffGrant,
                "d".repeat(64),
                serde_json::json!({"ciphertext": vec![1; 48]}),
                now(),
            )
            .expect("prepare ciphertext");
        assert!(matches!(
            store.prepare_key_bootstrap_operation(
                project.tenant_id,
                project.id,
                KeyBootstrapCell::Us,
                KeyBootstrapOperationKind::HandoffGrant,
                "d".repeat(64),
                serde_json::json!({"ciphertext": vec![2; 48]}),
                now() + chrono::Duration::minutes(1),
            ),
            Err(StorageError::ImmutableRecordMismatch { .. })
        ));
    }
}

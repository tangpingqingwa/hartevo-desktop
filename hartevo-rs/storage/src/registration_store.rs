use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{Project, ProjectDataCell, ProjectId, StorageMode, TenantId};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::aggregate::{PendingEvent, append_events};
use crate::normalized::{load_project_normalized, update_project_normalized_cas};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectCloudRegistrationStatus {
    Prepared,
    Applied,
    Conflict,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProjectCloudRegistration {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub cell: String,
    pub encryption_mode: String,
    pub remote_execution_opt_in: bool,
    pub idempotency_key_digest: String,
    pub intent_digest: String,
    pub request_digest: String,
    pub key_version: u64,
    pub content_digest: String,
    pub request: Value,
    pub authorized_by: String,
    pub authorization_evidence_digest: String,
    pub status: ProjectCloudRegistrationStatus,
    pub remote_revision: Option<u64>,
    pub remote_duplicate: bool,
    pub last_error_code: Option<String>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl LocalProjectCloudRegistration {
    pub fn validate(&self) -> Result<(), StorageError> {
        let state_valid = match self.status {
            ProjectCloudRegistrationStatus::Prepared => {
                self.remote_revision.is_none()
                    && !self.remote_duplicate
                    && self.last_error_code.is_none()
            }
            ProjectCloudRegistrationStatus::Applied => {
                self.remote_revision == Some(1) && self.last_error_code.is_none()
            }
            ProjectCloudRegistrationStatus::Conflict => {
                self.remote_revision.is_none()
                    && !self.remote_duplicate
                    && self
                        .last_error_code
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
            }
        };
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || !matches!(self.cell.as_str(), "us" | "eu")
            || !matches!(
                self.encryption_mode.as_str(),
                "personal_e2ee" | "team_envelope"
            )
            || !is_sha256(&self.idempotency_key_digest)
            || !is_sha256(&self.intent_digest)
            || !is_sha256(&self.request_digest)
            || self.request_digest
                != format!("{:x}", Sha256::digest(serde_json::to_vec(&self.request)?))
            || self.key_version == 0
            || !is_sha256(&self.content_digest)
            || self.authorized_by.trim().is_empty()
            || !is_sha256(&self.authorization_evidence_digest)
            || self.revision == 0
            || self.created_at > self.updated_at
            || !state_valid
        {
            return Err(StorageError::DomainDecode(
                "invalid local project cloud registration".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalProjectCloudRegistrationPrepareOutcome {
    pub registration: LocalProjectCloudRegistration,
    pub duplicate: bool,
    pub event_sequence: Option<i64>,
    pub outbox_sequence: Option<i64>,
}

impl ProjectStore {
    pub fn prepare_project_cloud_registration(
        &mut self,
        selected_project: &Project,
        expected_project_revision: u64,
        registration: &LocalProjectCloudRegistration,
        now: DateTime<Utc>,
    ) -> Result<LocalProjectCloudRegistrationPrepareOutcome, StorageError> {
        registration.validate()?;
        if registration.revision != 1
            || registration.status != ProjectCloudRegistrationStatus::Prepared
        {
            return Err(StorageError::InvalidInitialRevision(registration.revision));
        }
        validate_project_scope(selected_project, registration)?;
        let transaction = self.connection.transaction()?;
        let stored_project = load_project_normalized(&transaction, &selected_project.id)?
            .ok_or_else(|| StorageError::ProjectNotFound(selected_project.id.clone()))?;
        if let Some(existing) = load_registration(&transaction, &selected_project.id)? {
            if existing.idempotency_key_digest != registration.idempotency_key_digest
                || existing.intent_digest != registration.intent_digest
            {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "project cloud registration intent",
                    id: selected_project.id.to_string(),
                });
            }
            transaction.commit()?;
            return Ok(LocalProjectCloudRegistrationPrepareOutcome {
                registration: existing,
                duplicate: true,
                event_sequence: None,
                outbox_sequence: None,
            });
        }
        persist_cell_selection(
            &transaction,
            &stored_project,
            selected_project,
            expected_project_revision,
        )?;
        insert_registration(&transaction, registration)?;
        let (events, outbox) = append_events(
            &transaction,
            registration.tenant_id.as_str(),
            registration.project_id.as_str(),
            None,
            "project_cloud_registration",
            registration.project_id.as_str(),
            &[PendingEvent::new(
                "project.cloud_registration.prepared",
                event_payload(registration),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(LocalProjectCloudRegistrationPrepareOutcome {
            registration: registration.clone(),
            duplicate: false,
            event_sequence: events.first().copied(),
            outbox_sequence: outbox.first().copied(),
        })
    }

    pub fn load_project_cloud_registration(
        &self,
        project_id: &ProjectId,
    ) -> Result<LocalProjectCloudRegistration, StorageError> {
        load_registration(&self.connection, project_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "project cloud registration",
                project_id: project_id.clone(),
                id: project_id.to_string(),
            }
        })
    }

    pub fn record_project_cloud_registration_applied(
        &mut self,
        project_id: &ProjectId,
        expected_revision: u64,
        remote_revision: u64,
        remote_duplicate: bool,
        now: DateTime<Utc>,
    ) -> Result<LocalProjectCloudRegistration, StorageError> {
        if remote_revision != 1 {
            return Err(StorageError::DomainDecode(
                "project cloud registration remote revision must be one".into(),
            ));
        }
        self.finish_project_cloud_registration(
            project_id,
            expected_revision,
            ProjectRegistrationFinish::Applied {
                remote_revision,
                remote_duplicate,
            },
            now,
        )
    }

    pub fn record_project_cloud_registration_conflict(
        &mut self,
        project_id: &ProjectId,
        expected_revision: u64,
        error_code: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalProjectCloudRegistration, StorageError> {
        if error_code.trim().is_empty() {
            return Err(StorageError::DomainDecode(
                "project cloud registration conflict requires a stable code".into(),
            ));
        }
        self.finish_project_cloud_registration(
            project_id,
            expected_revision,
            ProjectRegistrationFinish::Conflict(error_code.trim().into()),
            now,
        )
    }

    fn finish_project_cloud_registration(
        &mut self,
        project_id: &ProjectId,
        expected_revision: u64,
        finish: ProjectRegistrationFinish,
        now: DateTime<Utc>,
    ) -> Result<LocalProjectCloudRegistration, StorageError> {
        let transaction = self.connection.transaction()?;
        let mut registration = load_registration_required(&transaction, project_id)?;
        if let ProjectRegistrationFinish::Applied {
            remote_revision,
            remote_duplicate,
        } = finish
            && registration.status == ProjectCloudRegistrationStatus::Applied
        {
            if registration.remote_revision == Some(remote_revision)
                && registration.remote_duplicate == remote_duplicate
            {
                transaction.commit()?;
                return Ok(registration);
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "applied project cloud registration",
                id: project_id.to_string(),
            });
        }
        if registration.status != ProjectCloudRegistrationStatus::Prepared
            || registration.revision != expected_revision
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("project_cloud_registration:{project_id}"),
                expected_revision,
            });
        }
        match finish {
            ProjectRegistrationFinish::Applied {
                remote_revision,
                remote_duplicate,
            } => {
                registration.status = ProjectCloudRegistrationStatus::Applied;
                registration.remote_revision = Some(remote_revision);
                registration.remote_duplicate = remote_duplicate;
            }
            ProjectRegistrationFinish::Conflict(error_code) => {
                registration.status = ProjectCloudRegistrationStatus::Conflict;
                registration.last_error_code = Some(error_code);
            }
        }
        registration.revision = next_revision(expected_revision)?;
        registration.updated_at = now;
        update_registration(&transaction, &registration, expected_revision)?;
        append_events(
            &transaction,
            registration.tenant_id.as_str(),
            registration.project_id.as_str(),
            None,
            "project_cloud_registration",
            registration.project_id.as_str(),
            &[PendingEvent::new(
                match registration.status {
                    ProjectCloudRegistrationStatus::Applied => "project.cloud_registration.applied",
                    ProjectCloudRegistrationStatus::Conflict => {
                        "project.cloud_registration.conflict"
                    }
                    ProjectCloudRegistrationStatus::Prepared => unreachable!(),
                },
                event_payload(&registration),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(registration)
    }
}

#[derive(Clone, Debug)]
enum ProjectRegistrationFinish {
    Applied {
        remote_revision: u64,
        remote_duplicate: bool,
    },
    Conflict(String),
}

fn validate_project_scope(
    project: &Project,
    registration: &LocalProjectCloudRegistration,
) -> Result<(), StorageError> {
    let cell = match project.data_cell {
        Some(ProjectDataCell::Us) => "us",
        Some(ProjectDataCell::Eu) => "eu",
        None => "",
    };
    if project.tenant_id != registration.tenant_id
        || project.id != registration.project_id
        || project.storage_mode != StorageMode::LocalEncryptedSync
        || cell != registration.cell
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn persist_cell_selection(
    transaction: &Transaction<'_>,
    stored: &Project,
    selected: &Project,
    expected_revision: u64,
) -> Result<(), StorageError> {
    if stored.revision != expected_revision {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("project:{}", selected.id),
            expected_revision,
        });
    }
    if selected.revision == stored.revision && selected == stored {
        return Ok(());
    }
    if selected.revision != next_revision(stored.revision)?
        || stored.data_cell.is_some()
        || selected.data_cell.is_none()
    {
        return Err(StorageError::UnexpectedNewerRevision {
            expected_revision: stored.revision,
            actual: selected.revision,
        });
    }
    update_project_normalized_cas(transaction, selected, stored.revision)
}

fn insert_registration(
    transaction: &Transaction<'_>,
    registration: &LocalProjectCloudRegistration,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO project_cloud_registrations
           (tenant_id, project_id, cell, encryption_mode, remote_execution_opt_in,
            idempotency_key_digest, intent_digest, request_digest, key_version,
            content_digest, request_json, authorized_by, authorization_evidence_digest,
            status, remote_revision, remote_duplicate, last_error_code, revision, created_at,
            updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 'prepared', NULL, 0, NULL, ?14, ?15, ?15)",
        params![
            registration.tenant_id.as_str(),
            registration.project_id.as_str(),
            registration.cell,
            registration.encryption_mode,
            i64::from(registration.remote_execution_opt_in),
            registration.idempotency_key_digest,
            registration.intent_digest,
            registration.request_digest,
            to_sql_u64(registration.key_version)?,
            registration.content_digest,
            serde_json::to_string(&registration.request)?,
            registration.authorized_by,
            registration.authorization_evidence_digest,
            to_sql_u64(registration.revision)?,
            registration.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn update_registration(
    transaction: &Transaction<'_>,
    registration: &LocalProjectCloudRegistration,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE project_cloud_registrations
         SET status = ?3, remote_revision = ?4, remote_duplicate = ?5,
             last_error_code = ?6, revision = ?7, updated_at = ?8
         WHERE project_id = ?1 AND revision = ?2",
        params![
            registration.project_id.as_str(),
            to_sql_u64(expected_revision)?,
            status_name(registration.status),
            registration.remote_revision.map(to_sql_u64).transpose()?,
            i64::from(registration.remote_duplicate),
            registration.last_error_code,
            to_sql_u64(registration.revision)?,
            registration.updated_at.to_rfc3339(),
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("project_cloud_registration:{}", registration.project_id),
            expected_revision,
        });
    }
    Ok(())
}

fn load_registration_required(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
) -> Result<LocalProjectCloudRegistration, StorageError> {
    load_registration(transaction, project_id)?.ok_or_else(|| StorageError::ScopedRecordNotFound {
        kind: "project cloud registration",
        project_id: project_id.clone(),
        id: project_id.to_string(),
    })
}

fn load_registration(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
) -> Result<Option<LocalProjectCloudRegistration>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, cell, encryption_mode, remote_execution_opt_in,
                    idempotency_key_digest, intent_digest, request_digest, key_version,
                    content_digest, request_json, authorized_by, authorization_evidence_digest,
                    status, remote_revision, remote_duplicate, last_error_code, revision,
                    created_at, updated_at
             FROM project_cloud_registrations WHERE project_id = ?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, Option<String>>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let registration = LocalProjectCloudRegistration {
            tenant_id: TenantId::from_stable(row.0),
            project_id: project_id.clone(),
            cell: row.1,
            encryption_mode: row.2,
            remote_execution_opt_in: parse_bool(row.3)?,
            idempotency_key_digest: row.4,
            intent_digest: row.5,
            request_digest: row.6,
            key_version: from_sql_u64(row.7, "registration key version")?,
            content_digest: row.8,
            request: serde_json::from_str(&row.9)?,
            authorized_by: row.10,
            authorization_evidence_digest: row.11,
            status: decode_status(&row.12)?,
            remote_revision: row
                .13
                .map(|value| from_sql_u64(value, "registration remote revision"))
                .transpose()?,
            remote_duplicate: parse_bool(row.14)?,
            last_error_code: row.15,
            revision: from_sql_u64(row.16, "registration revision")?,
            created_at: parse_time(&row.17)?,
            updated_at: parse_time(&row.18)?,
        };
        registration.validate()?;
        Ok(registration)
    })
    .transpose()
}

fn event_payload(registration: &LocalProjectCloudRegistration) -> Value {
    json!({
        "cell": registration.cell,
        "encryptionMode": registration.encryption_mode,
        "remoteExecutionOptIn": registration.remote_execution_opt_in,
        "idempotencyKeyDigest": registration.idempotency_key_digest,
        "intentDigest": registration.intent_digest,
        "requestDigest": registration.request_digest,
        "keyVersion": registration.key_version,
        "contentDigest": registration.content_digest,
        "authorizedBy": registration.authorized_by,
        "authorizationEvidenceDigest": registration.authorization_evidence_digest,
        "status": registration.status,
        "remoteRevision": registration.remote_revision,
        "remoteDuplicate": registration.remote_duplicate,
        "lastErrorCode": registration.last_error_code,
    })
}

const fn status_name(status: ProjectCloudRegistrationStatus) -> &'static str {
    match status {
        ProjectCloudRegistrationStatus::Prepared => "prepared",
        ProjectCloudRegistrationStatus::Applied => "applied",
        ProjectCloudRegistrationStatus::Conflict => "conflict",
    }
}

fn decode_status(value: &str) -> Result<ProjectCloudRegistrationStatus, StorageError> {
    match value {
        "prepared" => Ok(ProjectCloudRegistrationStatus::Prepared),
        "applied" => Ok(ProjectCloudRegistrationStatus::Applied),
        "conflict" => Ok(ProjectCloudRegistrationStatus::Conflict),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid project cloud registration status: {value}"
        ))),
    }
}

fn parse_bool(value: i64) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid project cloud registration boolean: {value}"
        ))),
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| StorageError::DomainDecode(format!("invalid timestamp: {value}")))
}

fn next_revision(value: u64) -> Result<u64, StorageError> {
    value
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(value))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::TimeZone;
    use proptest::prelude::*;

    use super::*;
    use crate::PendingEvent;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 16, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup() -> (ProjectStore, Project) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-registration"),
            ProjectId::from("project-registration"),
            "Private launch strategy",
            "private customer and campaign metadata",
            PathBuf::from("/tmp/hartevo-project-registration"),
            StorageMode::LocalEncryptedSync,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), now())],
            )
            .expect("persist project");
        (store, project)
    }

    fn registration(project: &Project) -> LocalProjectCloudRegistration {
        let request = json!({
            "scope": {"cell": "eu", "tenantId": project.tenant_id},
            "projectId": project.id,
            "encryptionMode": "team_envelope",
            "remoteExecutionOptIn": false,
            "metadataDigest": "c".repeat(64),
            "initialPayload": {
                "keyVersion": 1,
                "nonce": vec![7; 12],
                "ciphertext": vec![9; 32],
                "aadDigest": "a".repeat(64),
                "contentDigest": "c".repeat(64),
            },
            "idempotencyKeyDigest": "d".repeat(64),
            "createdAt": now(),
        });
        LocalProjectCloudRegistration {
            tenant_id: project.tenant_id.clone(),
            project_id: project.id.clone(),
            cell: "eu".into(),
            encryption_mode: "team_envelope".into(),
            remote_execution_opt_in: false,
            idempotency_key_digest: "d".repeat(64),
            intent_digest: "e".repeat(64),
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            key_version: 1,
            content_digest: "c".repeat(64),
            request,
            authorized_by: "owner-device".into(),
            authorization_evidence_digest: "f".repeat(64),
            status: ProjectCloudRegistrationStatus::Prepared,
            remote_revision: None,
            remote_duplicate: false,
            last_error_code: None,
            revision: 1,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum RegistrationAction {
        ReplayExact,
        ReplayChangedIntent,
        Apply {
            expected_revision: u8,
            remote_revision: u8,
            duplicate: bool,
        },
        Conflict {
            expected_revision: u8,
            valid_code: bool,
        },
    }

    fn registration_action() -> impl Strategy<Value = RegistrationAction> {
        prop_oneof![
            Just(RegistrationAction::ReplayExact),
            Just(RegistrationAction::ReplayChangedIntent),
            (0_u8..4, 0_u8..3, any::<bool>()).prop_map(
                |(expected_revision, remote_revision, duplicate)| RegistrationAction::Apply {
                    expected_revision,
                    remote_revision,
                    duplicate,
                }
            ),
            (0_u8..4, any::<bool>()).prop_map(|(expected_revision, valid_code)| {
                RegistrationAction::Conflict {
                    expected_revision,
                    valid_code,
                }
            }),
        ]
    }

    #[test]
    fn cell_selection_and_exact_registration_are_one_restart_safe_saga() {
        let (mut store, project) = setup();
        let mut selected = project.clone();
        selected
            .select_data_cell(ProjectDataCell::Eu)
            .expect("select EU");
        let prepared = registration(&selected);
        let first = store
            .prepare_project_cloud_registration(&selected, 1, &prepared, now())
            .expect("prepare registration");
        assert!(!first.duplicate);
        assert_eq!(
            store.load_project(&project.id).expect("selected project"),
            selected
        );
        let replay = store
            .prepare_project_cloud_registration(&selected, 2, &prepared, now())
            .expect("exact replay");
        assert!(replay.duplicate);
        assert_eq!(replay.registration.request, prepared.request);

        let mut changed = prepared.clone();
        changed.intent_digest = "a".repeat(64);
        assert!(matches!(
            store.prepare_project_cloud_registration(&selected, 2, &changed, now()),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "project cloud registration intent",
                ..
            })
        ));
        assert!(
            store
                .record_project_cloud_registration_applied(&project.id, 1, 2, false, now())
                .is_err()
        );
        let applied = store
            .record_project_cloud_registration_applied(&project.id, 1, 1, false, now())
            .expect("record remote project");
        assert_eq!(
            (applied.status, applied.revision, applied.remote_revision),
            (ProjectCloudRegistrationStatus::Applied, 2, Some(1))
        );
        assert_eq!(
            store
                .record_project_cloud_registration_applied(&project.id, 1, 1, false, now())
                .expect("applied replay"),
            applied
        );

        let audit: String = store
            .connection
            .query_row(
                "SELECT group_concat(payload_json, '') FROM domain_events
                 WHERE project_id = ?1 AND event_type LIKE 'project.cloud_registration.%'",
                [project.id.as_str()],
                |row| row.get(0),
            )
            .expect("project registration audit");
        assert!(!audit.contains("Private launch strategy"));
        assert!(!audit.contains("private customer"));
        assert!(!audit.contains("ciphertext"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn registration_saga_is_exactly_once_and_terminal_under_arbitrary_replays(
            actions in prop::collection::vec(registration_action(), 1..64),
        ) {
            let (mut store, project) = setup();
            let mut selected = project.clone();
            selected.select_data_cell(ProjectDataCell::Eu)?;
            let prepared = registration(&selected);
            let first = store.prepare_project_cloud_registration(
                &selected,
                project.revision,
                &prepared,
                now(),
            )?;
            prop_assert!(!first.duplicate);
            let mut model = prepared.clone();

            for action in actions {
                let before = model.clone();
                match action {
                    RegistrationAction::ReplayExact => {
                        let replay = store.prepare_project_cloud_registration(
                            &selected,
                            selected.revision,
                            &prepared,
                            now(),
                        )?;
                        prop_assert!(replay.duplicate);
                        prop_assert_eq!(replay.registration, model.clone());
                    }
                    RegistrationAction::ReplayChangedIntent => {
                        let mut changed = prepared.clone();
                        changed.intent_digest = "a".repeat(64);
                        let result = store.prepare_project_cloud_registration(
                            &selected,
                            selected.revision,
                            &changed,
                            now(),
                        );
                        let immutable_intent = matches!(
                            result,
                            Err(StorageError::ImmutableRecordMismatch {
                                kind: "project cloud registration intent",
                                ..
                            })
                        );
                        prop_assert!(immutable_intent);
                    }
                    RegistrationAction::Apply {
                        expected_revision,
                        remote_revision,
                        duplicate,
                    } => {
                        let result = store.record_project_cloud_registration_applied(
                            &project.id,
                            u64::from(expected_revision),
                            u64::from(remote_revision),
                            duplicate,
                            now(),
                        );
                        if remote_revision != 1 {
                            let invalid_revision = matches!(result, Err(StorageError::DomainDecode(_)));
                            prop_assert!(invalid_revision);
                        } else if model.status == ProjectCloudRegistrationStatus::Applied {
                            if model.remote_duplicate == duplicate {
                                prop_assert_eq!(result?, model.clone());
                            } else {
                                let immutable_applied = matches!(
                                    result,
                                    Err(StorageError::ImmutableRecordMismatch {
                                        kind: "applied project cloud registration",
                                        ..
                                    })
                                );
                                prop_assert!(immutable_applied);
                            }
                        } else if model.status == ProjectCloudRegistrationStatus::Prepared
                            && u64::from(expected_revision) == model.revision
                        {
                            model.status = ProjectCloudRegistrationStatus::Applied;
                            model.remote_revision = Some(1);
                            model.remote_duplicate = duplicate;
                            model.revision += 1;
                            prop_assert_eq!(result?, model.clone());
                        } else {
                            let optimistic_conflict =
                                matches!(result, Err(StorageError::OptimisticConflict { .. }));
                            prop_assert!(optimistic_conflict);
                        }
                    }
                    RegistrationAction::Conflict {
                        expected_revision,
                        valid_code,
                    } => {
                        let code = if valid_code { "remote_scope_conflict" } else { "" };
                        let result = store.record_project_cloud_registration_conflict(
                            &project.id,
                            u64::from(expected_revision),
                            code,
                            now(),
                        );
                        if !valid_code {
                            let invalid_code = matches!(result, Err(StorageError::DomainDecode(_)));
                            prop_assert!(invalid_code);
                        } else if model.status == ProjectCloudRegistrationStatus::Prepared
                            && u64::from(expected_revision) == model.revision
                        {
                            model.status = ProjectCloudRegistrationStatus::Conflict;
                            model.last_error_code = Some(code.into());
                            model.revision += 1;
                            prop_assert_eq!(result?, model.clone());
                        } else {
                            let optimistic_conflict =
                                matches!(result, Err(StorageError::OptimisticConflict { .. }));
                            prop_assert!(optimistic_conflict);
                        }
                    }
                }

                let stored = store.load_project_cloud_registration(&project.id)?;
                prop_assert_eq!(&stored, &model);
                prop_assert!(stored.revision >= before.revision);
                prop_assert!(stored.revision <= before.revision + 1);
                if before.status != ProjectCloudRegistrationStatus::Prepared {
                    prop_assert_eq!(stored.status, before.status);
                }
            }
        }
    }
}

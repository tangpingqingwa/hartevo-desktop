//! SQLCipher-backed Browser File Grant persistence.
//!
//! The encrypted record contains source/name digests and the complete scanner
//! attestation. Normalized columns and Event/Outbox rows contain only scope,
//! state, size, and evidence digests; no source path, file name, or content is
//! copied into operational telemetry.

use hartevo_browser_adapter::{
    BrowserFileGrant, BrowserFileGrantState, BrowserFileType, BrowserWorkspace,
};
use hartevo_domain_kernel::{BrowserFileGrantId, ProjectId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn create_browser_file_grant_atomic(
        &mut self,
        grant: &BrowserFileGrant,
    ) -> Result<AtomicMutation, StorageError> {
        grant.validate()?;
        if grant.revision != 1 || grant.state != BrowserFileGrantState::Prepared {
            return Err(StorageError::InvalidInitialRevision(grant.revision));
        }
        match load_browser_file_grant_record(&self.connection, &grant.project_id, &grant.id)? {
            Some(stored) if stored == *grant => return Ok(idempotent(grant.revision)),
            Some(_) => {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser file grant",
                    id: grant.id.to_string(),
                });
            }
            None => {}
        }
        let transaction = self.connection.transaction()?;
        validate_file_grant_scope(&transaction, grant, true)?;
        insert_browser_file_grant(&transaction, grant)?;
        let event = browser_file_grant_event("browser.file_grant_prepared", grant)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            grant.tenant_id.as_str(),
            grant.project_id.as_str(),
            Some(grant.mission_id.as_str()),
            "browser_file_grant",
            grant.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: grant.revision,
        })
    }

    pub fn update_browser_file_grant_atomic(
        &mut self,
        grant: &BrowserFileGrant,
        expected_revision: u64,
    ) -> Result<AtomicMutation, StorageError> {
        grant.validate()?;
        let previous = self.load_browser_file_grant(&grant.project_id, &grant.id)?;
        if previous == *grant && grant.revision == expected_revision.saturating_add(1) {
            return Ok(idempotent(grant.revision));
        }
        if previous.revision != expected_revision || !grant.is_valid_successor_of(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("browser_file_grant:{}", grant.id),
                expected_revision,
            });
        }
        let require_current_lease = matches!(
            grant.state,
            BrowserFileGrantState::Leased | BrowserFileGrantState::Consumed
        );
        let transaction = self.connection.transaction()?;
        validate_file_grant_scope(&transaction, grant, require_current_lease)?;
        update_browser_file_grant(&transaction, grant, expected_revision)?;
        let event = browser_file_grant_event(file_grant_event_type(grant.state), grant)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            grant.tenant_id.as_str(),
            grant.project_id.as_str(),
            Some(grant.mission_id.as_str()),
            "browser_file_grant",
            grant.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: grant.revision,
        })
    }

    pub fn load_browser_file_grant(
        &self,
        project_id: &ProjectId,
        grant_id: &BrowserFileGrantId,
    ) -> Result<BrowserFileGrant, StorageError> {
        let grant = load_browser_file_grant_record(&self.connection, project_id, grant_id)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "browser file grant",
                project_id: project_id.clone(),
                id: grant_id.to_string(),
            })?;
        validate_file_grant_scope(&self.connection, &grant, false)?;
        Ok(grant)
    }

    pub fn browser_file_grants_for_project(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<BrowserFileGrant>, StorageError> {
        self.load_project(project_id)?;
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT id FROM browser_file_grants
                 WHERE project_id = ?1 ORDER BY created_at, id",
            )?;
            statement
                .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                self.load_browser_file_grant(project_id, &BrowserFileGrantId::from_stable(id))
            })
            .collect()
    }
}

fn idempotent(state_revision: u64) -> AtomicMutation {
    AtomicMutation {
        event_sequences: Vec::new(),
        outbox_sequences: Vec::new(),
        state_revision,
    }
}

fn validate_file_grant_scope(
    connection: &Connection,
    grant: &BrowserFileGrant,
    require_current_lease: bool,
) -> Result<(), StorageError> {
    let workspace = connection
        .query_row(
            "SELECT tenant_id, mission_id, lease_id_digest, lease_generation, control_state,
                    record_json
             FROM browser_workspaces WHERE project_id = ?1 AND id = ?2",
            params![grant.project_id.as_str(), grant.workspace_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "browser workspace",
            project_id: grant.project_id.clone(),
            id: grant.workspace_id.to_string(),
        })?;
    let durable_workspace: BrowserWorkspace = serde_json::from_str(&workspace.5)?;
    durable_workspace.validate()?;
    let generation = to_sql_u64(grant.lease_generation)?;
    if workspace.0 != grant.tenant_id.as_str()
        || workspace.1 != grant.mission_id.as_str()
        || durable_workspace.project_id != grant.project_id
        || durable_workspace.id != grant.workspace_id
        || (require_current_lease
            && (workspace.2 != grant.lease_id_digest
                || workspace.3 != generation
                || workspace.4 != "agent_controlled"))
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn insert_browser_file_grant(
    transaction: &Transaction<'_>,
    grant: &BrowserFileGrant,
) -> Result<(), StorageError> {
    let digest = grant.digest()?;
    transaction.execute(
        "INSERT INTO browser_file_grants
           (tenant_id, project_id, id, mission_id, workspace_id, lease_id_digest,
            lease_generation, content_digest, byte_count, detected_type,
            scan_evidence_digest, authorization_evidence_digest, upload_payload_digest,
            state, claim_id, terminal_evidence_digest, expires_at, revision,
            created_at, updated_at, record_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
        rusqlite::params_from_iter(grant_values(grant, &digest)?),
    )?;
    Ok(())
}

fn update_browser_file_grant(
    transaction: &Transaction<'_>,
    grant: &BrowserFileGrant,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let digest = grant.digest()?;
    let updated = transaction.execute(
        "UPDATE browser_file_grants SET
           state = ?14, claim_id = ?15, terminal_evidence_digest = ?16,
           revision = ?18, updated_at = ?20, record_digest = ?21, record_json = ?22
         WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3 AND revision = ?23",
        rusqlite::params_from_iter(grant_values(grant, &digest)?.into_iter().chain([
            rusqlite::types::Value::Integer(to_sql_u64(expected_revision)?),
        ])),
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("browser_file_grant:{}", grant.id),
            expected_revision,
        });
    }
    Ok(())
}

fn grant_values(
    grant: &BrowserFileGrant,
    record_digest: &str,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        grant.tenant_id.to_string().into(),
        grant.project_id.to_string().into(),
        grant.id.to_string().into(),
        grant.mission_id.to_string().into(),
        grant.workspace_id.to_string().into(),
        grant.lease_id_digest.clone().into(),
        to_sql_u64(grant.lease_generation)?.into(),
        grant.content_digest.clone().into(),
        to_sql_u64(grant.byte_count)?.into(),
        file_type_name(grant.detected_type).to_owned().into(),
        grant.scan_report.evidence_digest.clone().into(),
        grant.authorization_evidence_digest.clone().into(),
        grant.upload_payload_digest.clone().into(),
        file_grant_state_name(grant.state).to_owned().into(),
        grant.claim_id.as_ref().map(ToString::to_string).into(),
        grant.terminal_evidence_digest.clone().into(),
        grant.expires_at.to_rfc3339().into(),
        to_sql_u64(grant.revision)?.into(),
        grant.created_at.to_rfc3339().into(),
        grant.updated_at.to_rfc3339().into(),
        record_digest.to_owned().into(),
        serde_json::to_string(grant)?.into(),
    ])
}

fn load_browser_file_grant_record(
    connection: &Connection,
    project_id: &ProjectId,
    grant_id: &BrowserFileGrantId,
) -> Result<Option<BrowserFileGrant>, StorageError> {
    let projection = connection
        .query_row(
            "SELECT tenant_id, mission_id, workspace_id, lease_id_digest, lease_generation,
                    content_digest, byte_count, detected_type, scan_evidence_digest,
                    authorization_evidence_digest, upload_payload_digest, state, claim_id,
                    terminal_evidence_digest, expires_at, revision, created_at, updated_at,
                    record_digest, record_json
             FROM browser_file_grants WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), grant_id.as_str()],
            |row| {
                Ok(FileGrantProjection {
                    tenant_id: row.get(0)?,
                    mission_id: row.get(1)?,
                    workspace_id: row.get(2)?,
                    lease_id_digest: row.get(3)?,
                    lease_generation: row.get(4)?,
                    content_digest: row.get(5)?,
                    byte_count: row.get(6)?,
                    detected_type: row.get(7)?,
                    scan_evidence_digest: row.get(8)?,
                    authorization_evidence_digest: row.get(9)?,
                    upload_payload_digest: row.get(10)?,
                    state: row.get(11)?,
                    claim_id: row.get(12)?,
                    terminal_evidence_digest: row.get(13)?,
                    expires_at: row.get(14)?,
                    revision: row.get(15)?,
                    created_at: row.get(16)?,
                    updated_at: row.get(17)?,
                    record_digest: row.get(18)?,
                    record_json: row.get(19)?,
                })
            },
        )
        .optional()?;
    projection
        .as_ref()
        .map(|projection| decode_file_grant(project_id, grant_id, projection))
        .transpose()
}

#[derive(Eq, PartialEq)]
struct FileGrantProjection {
    tenant_id: String,
    mission_id: String,
    workspace_id: String,
    lease_id_digest: String,
    lease_generation: i64,
    content_digest: String,
    byte_count: i64,
    detected_type: String,
    scan_evidence_digest: String,
    authorization_evidence_digest: String,
    upload_payload_digest: String,
    state: String,
    claim_id: Option<String>,
    terminal_evidence_digest: Option<String>,
    expires_at: String,
    revision: i64,
    created_at: String,
    updated_at: String,
    record_digest: String,
    record_json: String,
}

fn decode_file_grant(
    project_id: &ProjectId,
    grant_id: &BrowserFileGrantId,
    projection: &FileGrantProjection,
) -> Result<BrowserFileGrant, StorageError> {
    let grant: BrowserFileGrant = serde_json::from_str(&projection.record_json)?;
    grant.validate()?;
    let expected = FileGrantProjection {
        tenant_id: grant.tenant_id.to_string(),
        mission_id: grant.mission_id.to_string(),
        workspace_id: grant.workspace_id.to_string(),
        lease_id_digest: grant.lease_id_digest.clone(),
        lease_generation: to_sql_u64(grant.lease_generation)?,
        content_digest: grant.content_digest.clone(),
        byte_count: to_sql_u64(grant.byte_count)?,
        detected_type: file_type_name(grant.detected_type).into(),
        scan_evidence_digest: grant.scan_report.evidence_digest.clone(),
        authorization_evidence_digest: grant.authorization_evidence_digest.clone(),
        upload_payload_digest: grant.upload_payload_digest.clone(),
        state: file_grant_state_name(grant.state).into(),
        claim_id: grant.claim_id.as_ref().map(ToString::to_string),
        terminal_evidence_digest: grant.terminal_evidence_digest.clone(),
        expires_at: grant.expires_at.to_rfc3339(),
        revision: to_sql_u64(grant.revision)?,
        created_at: grant.created_at.to_rfc3339(),
        updated_at: grant.updated_at.to_rfc3339(),
        record_digest: grant.digest()?,
        record_json: projection.record_json.clone(),
    };
    if grant.project_id != *project_id || grant.id != *grant_id || *projection != expected {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser file grant projection",
            id: grant_id.to_string(),
        });
    }
    Ok(grant)
}

fn browser_file_grant_event(
    event_type: &str,
    grant: &BrowserFileGrant,
) -> Result<PendingEvent, StorageError> {
    Ok(PendingEvent::new(
        event_type,
        serde_json::json!({
            "grantId": grant.id,
            "grantDigest": grant.digest()?,
            "workspaceId": grant.workspace_id,
            "leaseIdDigest": grant.lease_id_digest,
            "leaseGeneration": grant.lease_generation,
            "contentDigest": grant.content_digest,
            "byteCount": grant.byte_count,
            "detectedType": grant.detected_type,
            "scanEvidenceDigest": grant.scan_report.evidence_digest,
            "authorizationEvidenceDigest": grant.authorization_evidence_digest,
            "uploadPayloadDigest": grant.upload_payload_digest,
            "state": grant.state,
            "claimIdDigest": grant.claim_id.as_ref().map(|id| digest_identity(id.as_str())),
            "terminalEvidenceDigest": grant.terminal_evidence_digest,
            "expiresAt": grant.expires_at,
            "revision": grant.revision,
        }),
        grant.updated_at,
    ))
}

fn file_grant_event_type(state: BrowserFileGrantState) -> &'static str {
    match state {
        BrowserFileGrantState::Prepared => "browser.file_grant_prepared",
        BrowserFileGrantState::Leased => "browser.file_grant_leased",
        BrowserFileGrantState::Consumed => "browser.file_grant_consumed",
        BrowserFileGrantState::Revoked => "browser.file_grant_revoked",
        BrowserFileGrantState::Expired => "browser.file_grant_expired",
    }
}

fn file_grant_state_name(state: BrowserFileGrantState) -> &'static str {
    match state {
        BrowserFileGrantState::Prepared => "prepared",
        BrowserFileGrantState::Leased => "leased",
        BrowserFileGrantState::Consumed => "consumed",
        BrowserFileGrantState::Revoked => "revoked",
        BrowserFileGrantState::Expired => "expired",
    }
}

fn file_type_name(file_type: BrowserFileType) -> &'static str {
    match file_type {
        BrowserFileType::Pdf => "pdf",
        BrowserFileType::Png => "png",
        BrowserFileType::Jpeg => "jpeg",
        BrowserFileType::Gif => "gif",
        BrowserFileType::WebP => "webp",
        BrowserFileType::Mp4 => "mp4",
        BrowserFileType::Json => "json",
        BrowserFileType::Utf8Text => "utf8_text",
    }
}

fn digest_identity(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use chrono::{DateTime, Duration, TimeZone, Utc};
    use hartevo_browser_adapter::{
        BrowserIdentity, BrowserProfile, BrowserWorkspace, FileBroker, FileSafetyScanner,
        FileScanDecision, FileScanReport, FileScanRequest,
    };
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserFileClaimId, BrowserProfileId, BrowserTabId,
        BrowserWorkspaceId, Mission, MissionContract, MissionId, Project, StorageMode, TenantId,
    };
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::{DatabaseKey, STORAGE_SCHEMA_VERSION};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 16, 0, 0)
            .single()
            .expect("time")
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    struct CleanScanner;

    impl FileSafetyScanner for CleanScanner {
        fn scan(
            &mut self,
            request: &FileScanRequest<'_>,
        ) -> Result<FileScanReport, hartevo_browser_adapter::BrowserError> {
            Ok(FileScanReport {
                scanner_id: "storage-fixture-scanner".into(),
                scanner_version: "v1".into(),
                decision: FileScanDecision::Clean,
                evidence_digest: sha('7'),
                scanned_at: request.observed_at,
            })
        }
    }

    struct Fixture {
        _directory: TempDir,
        store: ProjectStore,
        project: Project,
        workspace: BrowserWorkspace,
        broker: FileBroker,
        grant: BrowserFileGrant,
    }

    fn fixture() -> Fixture {
        let directory = tempdir().expect("directory");
        let project_root = directory.path().join("project");
        let broker_root = directory.path().join("broker");
        fs::create_dir(&project_root).expect("project root");
        fs::create_dir(&broker_root).expect("broker root");
        #[cfg(unix)]
        fs::set_permissions(&broker_root, fs::Permissions::from_mode(0o700))
            .expect("private broker root");
        let project = Project::create_local(
            TenantId::from("tenant-browser-file-storage"),
            ProjectId::from("project-browser-file-storage"),
            "Browser file storage",
            "",
            &project_root,
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-browser-file-storage"),
            project.id.clone(),
            "Persist exact file grant",
            MissionContract::bootstrap(
                "Persist exact file grant",
                ["deliverable.upload".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-browser-file-storage"),
            &project,
            "keyring://browser/file-storage",
            BrowserIdentity::new(
                "fixture-provider",
                AccountId::from("account-browser-file-storage"),
                sha('1'),
                sha('2'),
                now(),
            )
            .expect("identity"),
            now(),
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-browser-file-storage"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-browser-file-storage"),
            BrowserControlLeaseId::from("lease-browser-file-storage-1"),
            now() + Duration::hours(1),
            sha('3'),
            now(),
        )
        .expect("workspace");
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("save project");
        store.save_mission(&mission).expect("save mission");
        store
            .create_browser_profile_atomic(&profile)
            .expect("save profile");
        store
            .create_browser_workspace_atomic(&workspace)
            .expect("save workspace");
        let source = project_root.join("private-customer-deliverable.json");
        fs::write(&source, br#"{"customer":"private@example.com"}"#).expect("source");
        let proof = workspace.agent_lease_proof(now()).expect("proof");
        let mut broker = FileBroker::new(&broker_root).expect("broker");
        let grant = broker
            .prepare_upload(
                BrowserFileGrantId::from("grant-browser-file-storage"),
                &project,
                &workspace,
                &proof,
                &source,
                BrowserFileType::Json,
                sha('4'),
                now() + Duration::minutes(10),
                now(),
                &mut CleanScanner,
            )
            .expect("grant");
        Fixture {
            _directory: directory,
            store,
            project,
            workspace,
            broker,
            grant,
        }
    }

    #[test]
    fn grant_claim_and_terminal_state_are_atomic_recoverable_and_content_free() {
        let mut fixture = fixture();
        let created = fixture
            .store
            .create_browser_file_grant_atomic(&fixture.grant)
            .expect("create grant");
        assert_eq!(created.event_sequences.len(), 1);
        assert_eq!(created.outbox_sequences.len(), 1);
        assert_eq!(
            fixture
                .store
                .load_browser_file_grant(&fixture.project.id, &fixture.grant.id)
                .expect("load grant"),
            fixture.grant
        );

        let proof = fixture.workspace.agent_lease_proof(now()).expect("proof");
        let handle = fixture
            .broker
            .claim_upload(
                &fixture.grant.id,
                BrowserFileClaimId::from("claim-browser-file-storage"),
                &fixture.workspace,
                &proof,
                &fixture.grant.upload_payload_digest,
                1,
                now() + Duration::seconds(1),
            )
            .expect("claim");
        let leased = fixture
            .broker
            .grant(&fixture.grant.id)
            .expect("leased")
            .clone();
        fixture
            .store
            .update_browser_file_grant_atomic(&leased, 1)
            .expect("persist claim");
        let replay = fixture
            .store
            .update_browser_file_grant_atomic(&leased, 1)
            .expect("idempotent claim replay");
        assert!(replay.event_sequences.is_empty());
        let consumed = fixture
            .broker
            .complete_upload(
                &leased.id,
                &handle.claim_id,
                &fixture.workspace,
                &proof,
                2,
                sha('5'),
                now() + Duration::seconds(2),
            )
            .expect("complete");
        fixture
            .store
            .update_browser_file_grant_atomic(&consumed, 2)
            .expect("persist terminal state");
        assert_eq!(
            fixture
                .store
                .browser_file_grants_for_project(&fixture.project.id)
                .expect("project grants"),
            vec![consumed]
        );

        let audit_payloads = fixture
            .store
            .connection
            .query_row(
                "SELECT COALESCE(group_concat(payload_json, ''), '') FROM (
                   SELECT payload_json FROM domain_events
                   UNION ALL SELECT payload_json FROM outbox_messages
                 )",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("audit payloads");
        assert!(!audit_payloads.contains("private@example.com"));
        assert!(!audit_payloads.contains("private-customer-deliverable.json"));
        assert!(!audit_payloads.contains("storage-fixture-scanner"));
        assert!(!audit_payloads.contains("claim-browser-file-storage"));
        assert!(audit_payloads.contains(&digest_identity("claim-browser-file-storage")));
    }

    #[test]
    fn projection_tamper_and_stale_workspace_lease_both_fail_closed() {
        let mut tampered = fixture();
        tampered
            .store
            .create_browser_file_grant_atomic(&tampered.grant)
            .expect("grant");
        tampered
            .store
            .connection
            .execute(
                "UPDATE browser_file_grants SET content_digest = ?3
                 WHERE project_id = ?1 AND id = ?2",
                params![
                    tampered.project.id.as_str(),
                    tampered.grant.id.as_str(),
                    sha('9')
                ],
            )
            .expect("tamper projection");
        assert!(matches!(
            tampered
                .store
                .load_browser_file_grant(&tampered.project.id, &tampered.grant.id),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "browser file grant projection",
                ..
            })
        ));

        let mut stale = fixture();
        stale
            .workspace
            .user_takeover(
                1,
                1,
                BrowserControlLeaseId::from("lease-browser-file-storage-2"),
                sha('8'),
                now() + Duration::seconds(1),
            )
            .expect("takeover");
        stale
            .store
            .update_browser_workspace_atomic(&stale.workspace, 1)
            .expect("persist takeover");
        assert!(matches!(
            stale.store.create_browser_file_grant_atomic(&stale.grant),
            Err(StorageError::TenantScopeMismatch)
        ));
    }

    #[test]
    fn migration_v33_backs_up_v32_and_reinstalls_file_grants_idempotently() {
        let directory = tempdir().expect("directory");
        let database_path = directory.path().join("browser-file-migration.sqlite3");
        let key = DatabaseKey::new([41; 32]).expect("key");
        {
            let store = ProjectStore::open(&database_path, &key).expect("current store");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 33;",
                )
                .expect("construct v32");
        }
        {
            let store = ProjectStore::open(&database_path, &key).expect("migrate v32");
            assert_eq!(
                super::super::current_schema_version(&store.connection).expect("version"),
                STORAGE_SCHEMA_VERSION
            );
            let table_count = store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'browser_file_grants'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("table count");
            assert_eq!(table_count, 1);
        }
        let backup_count = fs::read_dir(directory.path())
            .expect("list directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v32")
            })
            .count();
        assert_eq!(backup_count, 1);
        drop(ProjectStore::open(&database_path, &key).expect("idempotent reopen"));
        let reopened_backup_count = fs::read_dir(directory.path())
            .expect("list directory after reopen")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v32")
            })
            .count();
        assert_eq!(reopened_backup_count, 1);
    }
}

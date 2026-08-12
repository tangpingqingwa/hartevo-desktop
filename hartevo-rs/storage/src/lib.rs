//! Local-first, project-scoped persistence with encrypted files and atomic outbox writes.

mod aggregate;
mod authorization;
mod browser_file_store;
mod browser_recipe_store;
mod browser_store;
mod context_assembly_store;
mod context_collaboration_store;
mod context_foundation_store;
mod context_material_store;
mod context_store;
mod creator;
mod creator_hiring_store;
mod deletion_propagation;
mod deletion_store;
mod effect_ledger;
mod identity_store;
mod key_bootstrap_store;
mod keyring_store;
mod mission_conversation_store;
mod mission_schedule_store;
mod normalized;
mod outbox;
mod outcome_store;
mod registration_store;
mod relationship_store;
mod runtime_process_store;
mod runtime_recovery_store;
mod runtime_turn_store;
mod secure_store;
mod sync_store;
mod work_product_store;
pub use aggregate::{AtomicMutation, PendingEvent};
pub use browser_recipe_store::BrowserRecipeRuntimeState;
pub use context_material_store::{
    ContextMaterialDescriptor, ContextMaterialStoreError, ContextQuerySnapshot,
    LocalEncryptedContextMaterialStore,
};
pub use creator::PersistedMutation;
pub use deletion_propagation::{DeletionPropagationJob, DeletionPropagationJobStatus};
pub use key_bootstrap_store::{
    KeyBootstrapCell, KeyBootstrapOperationKind, KeyBootstrapOperationStatus,
    KeyBootstrapPrepareOutcome, LocalKeyBootstrapOperation,
};
pub use keyring_store::{DeviceAttachmentPrepareOutcome, ProjectKeySecretReference};
pub use outbox::{OutboxMessage, OutboxStatus};
pub use registration_store::{
    LocalProjectCloudRegistration, LocalProjectCloudRegistrationPrepareOutcome,
    ProjectCloudRegistrationStatus,
};
pub use runtime_turn_store::RuntimeTurnStartupReconciliation;
pub use secure_store::{
    ContentCrypto, ContentEncryptionContext, DeviceKeyAgreementCrypto, EncryptedContent,
    EnvelopeContext, EnvelopeCrypto, KeyMaterial, MemorySecretStore, OsSecretStore, SecretBytes,
    SecretReference, SecretStore, SecretStoreError,
};
pub use sync_store::{
    LocalInboundSyncEnvelope, LocalInboundSyncObject, LocalInboundSyncStageDisposition,
    LocalInboundSyncStageOutcome, LocalInboundSyncStatus, LocalSyncOperation,
    LocalSyncPrepareOutcome, LocalSyncStatus,
};

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{Mission, MissionId, Project, ProjectId};
use rusqlite::backup::Backup;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const STORAGE_SCHEMA_VERSION: i64 = 45;

pub struct DatabaseKey([u8; 32]);

impl DatabaseKey {
    pub fn new(bytes: [u8; 32]) -> Result<Self, StorageError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(StorageError::InvalidDatabaseKey);
        }
        Ok(Self(bytes))
    }

    pub fn from_secret(secret: &SecretBytes) -> Result<Self, StorageError> {
        let bytes: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::InvalidDatabaseKey)?;
        Self::new(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseKey([REDACTED])")
    }
}

impl Drop for DatabaseKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug)]
pub struct ProjectStore {
    connection: Connection,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainEventRecord {
    pub sequence: i64,
    pub project_id: ProjectId,
    pub mission_id: Option<MissionId>,
    pub event_type: String,
    pub payload: Value,
    pub recorded_at: DateTime<Utc>,
}

impl ProjectStore {
    pub fn open(path: &Path, key: &DatabaseKey) -> Result<Self, StorageError> {
        let path = validated_database_path(path)?;
        let connection = Connection::open(&path)?;
        apply_database_key(&connection, key)?;
        verify_sqlcipher(&connection)?;
        configure_connection(&connection)?;
        let existing_version = current_schema_version(&connection)?;
        if existing_version > 0 && existing_version < STORAGE_SCHEMA_VERSION {
            create_encrypted_backup(&connection, &path, key, existing_version)?;
        }
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, StorageError> {
        let connection = Connection::open_in_memory()?;
        configure_connection(&connection)?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn save_project(&mut self, project: &Project) -> Result<(), StorageError> {
        let transaction = self.connection.transaction()?;
        match normalized::load_project_normalized(&transaction, &project.id)? {
            None => {
                if project.revision != 1 {
                    return Err(StorageError::InvalidInitialRevision(project.revision));
                }
                if project.data_cell.is_some() {
                    return Err(StorageError::ImmutableRecordMismatch {
                        kind: "project data Cell selection",
                        id: project.id.to_string(),
                    });
                }
                normalized::insert_project_normalized(&transaction, project)?;
            }
            Some(stored) if stored == *project => {}
            Some(stored) => {
                if stored.tenant_id != project.tenant_id
                    || stored.storage_mode != project.storage_mode
                    || stored.data_cell != project.data_cell
                {
                    return Err(StorageError::ImmutableRecordMismatch {
                        kind: "project scope or data Cell",
                        id: project.id.to_string(),
                    });
                }
                let expected_revision = stored.revision;
                let next_revision = expected_revision
                    .checked_add(1)
                    .ok_or(StorageError::RevisionOverflow(expected_revision))?;
                if project.revision != next_revision {
                    return Err(StorageError::UnexpectedNextRevision {
                        expected: next_revision,
                        actual: project.revision,
                    });
                }
                normalized::update_project_normalized_cas(
                    &transaction,
                    project,
                    expected_revision,
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_project(&self, project_id: &ProjectId) -> Result<Project, StorageError> {
        if let Some(project) = normalized::load_project_normalized(&self.connection, project_id)? {
            return Ok(project);
        }
        let snapshot: Option<String> = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM projects WHERE id = ?1",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        snapshot
            .map(|value| serde_json::from_str(&value))
            .transpose()?
            .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))
    }

    /// Returns every project by stable id, reloading each full normalized
    /// record instead of treating the list query as authoritative state.
    pub fn list_projects(&self) -> Result<Vec<Project>, StorageError> {
        let project_ids = {
            let mut statement = self
                .connection
                .prepare("SELECT id FROM projects ORDER BY id")?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        project_ids
            .into_iter()
            .map(|id| self.load_project(&ProjectId::from_stable(id)))
            .collect()
    }

    pub fn save_mission(&mut self, mission: &Mission) -> Result<(), StorageError> {
        let project = self.load_project(&mission.project_id)?;
        if project.tenant_id != mission.tenant_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        let transaction = self.connection.transaction()?;
        normalized::upsert_mission_normalized(&transaction, mission)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn load_mission(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Mission, StorageError> {
        if let Some(mission) =
            normalized::load_mission_normalized(&self.connection, project_id, mission_id)?
        {
            return Ok(mission);
        }
        let snapshot: Option<String> = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM missions WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), mission_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        snapshot
            .map(|value| serde_json::from_str(&value))
            .transpose()?
            .ok_or_else(|| StorageError::MissionNotFound {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
            })
    }

    /// Returns the project's Missions by stable id. Project existence and
    /// every complete Mission projection are checked on the read path.
    pub fn list_missions(&self, project_id: &ProjectId) -> Result<Vec<Mission>, StorageError> {
        self.load_project(project_id)?;
        let mission_ids = {
            let mut statement = self
                .connection
                .prepare("SELECT id FROM missions WHERE project_id = ?1 ORDER BY id")?;
            statement
                .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        mission_ids
            .into_iter()
            .map(|id| self.load_mission(project_id, &MissionId::from_stable(id)))
            .collect()
    }

    pub fn append_event(
        &mut self,
        project_id: &ProjectId,
        mission_id: Option<&MissionId>,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let project = self.load_project(project_id)?;
        if let Some(mission_id) = mission_id {
            self.load_mission(project_id, mission_id)?;
        }
        self.connection.execute(
            "INSERT INTO domain_events
               (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                project.tenant_id.as_str(),
                project_id.as_str(),
                mission_id.map(MissionId::as_str),
                event_type,
                serde_json::to_string(payload)?,
                recorded_at.to_rfc3339()
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn events_for_mission(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Vec<DomainEventRecord>, StorageError> {
        self.load_mission(project_id, mission_id)?;
        let mut statement = self.connection.prepare(
            "SELECT sequence, project_id, mission_id, event_type, payload_json, recorded_at
             FROM domain_events
             WHERE project_id = ?1 AND mission_id = ?2
             ORDER BY sequence ASC",
        )?;
        let rows =
            statement.query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?;

        rows.map(|row| {
            let (sequence, project_id, mission_id, event_type, payload, recorded_at) = row?;
            Ok(DomainEventRecord {
                sequence,
                project_id: ProjectId::from_stable(project_id),
                mission_id: mission_id.map(MissionId::from_stable),
                event_type,
                payload: serde_json::from_str(&payload)?,
                recorded_at: DateTime::parse_from_rfc3339(&recorded_at)?.with_timezone(&Utc),
            })
        })
        .collect()
    }

    pub fn schema_version(&self) -> Result<i64, StorageError> {
        current_schema_version(&self.connection)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "schema migrations stay contiguous so every version remains auditable and transactional"
    )]
    fn migrate(&mut self) -> Result<(), StorageError> {
        let current = current_schema_version(&self.connection)?;
        if current > STORAGE_SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchemaVersion {
                found: current,
                supported: STORAGE_SCHEMA_VERSION,
            });
        }
        if current < 1 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
               version INTEGER PRIMARY KEY,
               applied_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS projects (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               snapshot_json TEXT NOT NULL,
               revision INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS missions (
               id TEXT NOT NULL,
               project_id TEXT NOT NULL,
               title TEXT NOT NULL,
               stage TEXT NOT NULL,
               snapshot_json TEXT NOT NULL,
               revision INTEGER NOT NULL,
               PRIMARY KEY (id, project_id),
               FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS domain_events (
               sequence INTEGER PRIMARY KEY AUTOINCREMENT,
               project_id TEXT NOT NULL,
               mission_id TEXT,
               event_type TEXT NOT NULL,
               payload_json TEXT NOT NULL,
               recorded_at TEXT NOT NULL,
               FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
               FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
             );",
            )?;
            record_migration(&transaction, 1)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 2 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE projects ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'legacy-local';
                 ALTER TABLE missions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'legacy-local';
                 ALTER TABLE domain_events ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'legacy-local';
                 CREATE INDEX project_tenant_idx ON projects(tenant_id, id);
                 CREATE INDEX mission_tenant_idx ON missions(tenant_id, project_id, id);
                 CREATE TABLE creator_tasks (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   creator_id TEXT NOT NULL,
                   title TEXT NOT NULL,
                   brief TEXT NOT NULL,
                   acceptance_criteria_json TEXT NOT NULL,
                   deliverable_requirements_json TEXT NOT NULL,
                   bounty_minor INTEGER NOT NULL CHECK (bounty_minor > 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   revision_limit INTEGER NOT NULL CHECK (revision_limit > 0),
                   usage_rights_json TEXT NOT NULL,
                   due_at TEXT NOT NULL,
                   contract_revision INTEGER NOT NULL CHECK (contract_revision > 0),
                   state_revision INTEGER NOT NULL CHECK (state_revision > 0),
                   accepted_revision INTEGER,
                   status TEXT NOT NULL,
                   funding_reservation_json TEXT,
                   acceptance_json TEXT,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (id, project_id),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE creator_milestones (
                   task_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL,
                   title TEXT NOT NULL,
                   amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   due_at TEXT NOT NULL,
                   status TEXT NOT NULL,
                   revisions_used INTEGER NOT NULL CHECK (revisions_used >= 0),
                   PRIMARY KEY (task_id, project_id, id),
                   UNIQUE (task_id, project_id, ordinal),
                   FOREIGN KEY (task_id, project_id) REFERENCES creator_tasks(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE creator_deliverables (
                   task_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   milestone_id TEXT NOT NULL,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   artifact_uri TEXT NOT NULL,
                   media_type TEXT NOT NULL,
                   size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   uploaded_at TEXT NOT NULL,
                   assessment_json TEXT NOT NULL,
                   rights_json TEXT NOT NULL,
                   status TEXT NOT NULL,
                   PRIMARY KEY (task_id, project_id, id),
                   UNIQUE (task_id, project_id, milestone_id, revision),
                   FOREIGN KEY (task_id, project_id, milestone_id)
                     REFERENCES creator_milestones(task_id, project_id, id) ON DELETE CASCADE
                 );
                 CREATE TABLE creator_reviews (
                   task_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   deliverable_id TEXT NOT NULL,
                   deliverable_digest TEXT NOT NULL CHECK (length(deliverable_digest) = 64),
                   reviewer_id TEXT NOT NULL,
                   decision TEXT NOT NULL,
                   acceptance_checks_json TEXT NOT NULL,
                   notes TEXT NOT NULL,
                   reviewed_at TEXT NOT NULL,
                   PRIMARY KEY (task_id, project_id, id),
                   FOREIGN KEY (task_id, project_id, deliverable_id)
                     REFERENCES creator_deliverables(task_id, project_id, id) ON DELETE CASCADE
                 );
                 CREATE TABLE creator_payout_authorizations (
                   task_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   payout_id TEXT NOT NULL,
                   milestone_id TEXT NOT NULL,
                   deliverable_id TEXT NOT NULL,
                   review_id TEXT NOT NULL,
                   scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
                   authorization_json TEXT NOT NULL,
                   authorized_at TEXT NOT NULL,
                   expires_at TEXT NOT NULL,
                   PRIMARY KEY (task_id, project_id, payout_id),
                   UNIQUE (task_id, project_id, milestone_id),
                   FOREIGN KEY (task_id, project_id, milestone_id)
                     REFERENCES creator_milestones(task_id, project_id, id),
                   FOREIGN KEY (task_id, project_id, deliverable_id)
                     REFERENCES creator_deliverables(task_id, project_id, id),
                   FOREIGN KEY (task_id, project_id, review_id)
                     REFERENCES creator_reviews(task_id, project_id, id)
                 );
                 CREATE TABLE creator_payouts (
                   task_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   payout_id TEXT NOT NULL,
                   milestone_id TEXT NOT NULL,
                   deliverable_id TEXT NOT NULL,
                   review_id TEXT NOT NULL,
                   amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
                   provider TEXT NOT NULL,
                   external_id TEXT NOT NULL,
                   authorization_json TEXT NOT NULL,
                   confirmation_json TEXT NOT NULL,
                   verified_at TEXT NOT NULL,
                   PRIMARY KEY (task_id, project_id, payout_id),
                   UNIQUE (task_id, project_id, milestone_id),
                   UNIQUE (provider, external_id),
                   FOREIGN KEY (task_id, project_id, payout_id)
                     REFERENCES creator_payout_authorizations(task_id, project_id, payout_id),
                   FOREIGN KEY (task_id, project_id, milestone_id)
                     REFERENCES creator_milestones(task_id, project_id, id),
                   FOREIGN KEY (task_id, project_id, deliverable_id)
                     REFERENCES creator_deliverables(task_id, project_id, id),
                   FOREIGN KEY (task_id, project_id, review_id)
                     REFERENCES creator_reviews(task_id, project_id, id)
                 );
                 CREATE TABLE outbox_messages (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT,
                   aggregate_type TEXT NOT NULL,
                   aggregate_id TEXT NOT NULL,
                   event_type TEXT NOT NULL,
                   payload_json TEXT NOT NULL,
                   status TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'leased', 'published', 'dead_letter')),
                   attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                   available_at TEXT NOT NULL,
                   lease_owner TEXT,
                   lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
                   lease_expires_at TEXT,
                   created_at TEXT NOT NULL,
                   published_at TEXT,
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                 );
                 CREATE INDEX outbox_claim_idx
                   ON outbox_messages(status, available_at, sequence);
                 CREATE TABLE effect_idempotency (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   idempotency_key TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   approval_digest TEXT NOT NULL,
                   status TEXT NOT NULL,
                   receipt_json TEXT,
                   verification_json TEXT,
                   uncertain_reason TEXT,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, idempotency_key),
                   UNIQUE (project_id, effect_id),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE execution_attempts (
                   id TEXT PRIMARY KEY,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   status TEXT NOT NULL,
                   lease_owner TEXT NOT NULL,
                   lease_expires_at TEXT NOT NULL,
                   request_digest TEXT NOT NULL,
                   receipt_json TEXT,
                   verification_json TEXT,
                   failure_class TEXT,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   UNIQUE (project_id, effect_id, attempt_no),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );",
            )?;
            record_migration(&transaction, 2)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 3 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE connections (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   provider TEXT NOT NULL,
                   account_id TEXT NOT NULL,
                   expected_external_account_id TEXT NOT NULL,
                   required_scopes_json TEXT NOT NULL,
                   granted_scopes_json TEXT NOT NULL,
                   status TEXT NOT NULL,
                   last_probe_json TEXT,
                   revoked_at TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, provider, account_id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE INDEX connections_scope_idx
                   ON connections(tenant_id, project_id, provider, account_id, status);
                 CREATE TABLE consent_records (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   person_id TEXT NOT NULL,
                   purpose TEXT NOT NULL,
                   channel TEXT NOT NULL,
                   market TEXT NOT NULL,
                   legal_basis TEXT NOT NULL,
                   status TEXT NOT NULL,
                   source TEXT NOT NULL,
                   evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                   granted_at TEXT,
                   valid_until TEXT,
                   withdrawn_at TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE INDEX consent_exact_scope_idx
                   ON consent_records(tenant_id, project_id, person_id, purpose, channel, market, status);
                 CREATE TABLE truth_fact_heads (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   fact_key TEXT NOT NULL,
                   market TEXT NOT NULL,
                   language TEXT NOT NULL,
                   current_version INTEGER NOT NULL CHECK (current_version > 0),
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, fact_key, market, language),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE TABLE truth_fact_revisions (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   fact_key TEXT NOT NULL,
                   value_json TEXT,
                   alternatives_json TEXT NOT NULL,
                   status TEXT NOT NULL,
                   source_json TEXT,
                   market TEXT NOT NULL,
                   language TEXT NOT NULL,
                   observed_at TEXT NOT NULL,
                   valid_from TEXT NOT NULL,
                   valid_until TEXT,
                   confidence TEXT NOT NULL,
                   version INTEGER NOT NULL CHECK (version > 0),
                   revision_link_json TEXT,
                   PRIMARY KEY (project_id, id, version),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE INDEX truth_current_scope_idx
                   ON truth_fact_heads(tenant_id, project_id, fact_key, market, language, current_version);",
            )?;
            record_migration(&transaction, 3)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 4 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE projects ADD COLUMN description TEXT NOT NULL DEFAULT '';
                 ALTER TABLE projects ADD COLUMN storage_mode TEXT NOT NULL DEFAULT 'local_existing';
                 CREATE TABLE project_workspace_roots (
                   project_id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   root_path TEXT NOT NULL,
                   PRIMARY KEY (project_id, ordinal),
                   UNIQUE (project_id, root_path),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE TABLE mission_contracts (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   contract_json TEXT NOT NULL,
                   PRIMARY KEY (mission_id, project_id),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE mission_lifecycle (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (mission_id, project_id),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE mission_tasks (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   title TEXT NOT NULL,
                   status TEXT NOT NULL,
                   capability TEXT NOT NULL,
                   PRIMARY KEY (mission_id, project_id, id),
                   UNIQUE (mission_id, project_id, ordinal),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE mission_evidence (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   title TEXT NOT NULL,
                   source_uri TEXT NOT NULL,
                   observed_at TEXT NOT NULL,
                   confidence REAL NOT NULL,
                   status TEXT NOT NULL,
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   PRIMARY KEY (mission_id, project_id, id),
                   UNIQUE (mission_id, project_id, ordinal),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE mission_work_products (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   title TEXT NOT NULL,
                   body TEXT NOT NULL,
                   evidence_ids_json TEXT NOT NULL,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   status TEXT NOT NULL,
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   PRIMARY KEY (mission_id, project_id, id),
                   UNIQUE (mission_id, project_id, ordinal),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE mission_effects (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   capability TEXT NOT NULL,
                   provider TEXT NOT NULL,
                   connection_id TEXT,
                   account_id TEXT,
                   effect_class TEXT NOT NULL,
                   status TEXT NOT NULL,
                   idempotency_key TEXT NOT NULL,
                   approval_digest TEXT NOT NULL CHECK (length(approval_digest) = 64),
                   effect_json TEXT NOT NULL,
                   PRIMARY KEY (mission_id, project_id, id),
                   UNIQUE (project_id, idempotency_key),
                   UNIQUE (mission_id, project_id, ordinal),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE INDEX mission_effect_execution_idx
                   ON mission_effects(project_id, provider, connection_id, account_id, status);
                 CREATE TABLE mission_outcomes (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   outcome_json TEXT NOT NULL,
                   PRIMARY KEY (mission_id, project_id),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );",
            )?;
            record_migration(&transaction, 4)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 5 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE companies (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   legal_name TEXT NOT NULL,
                   market TEXT NOT NULL,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE TABLE people (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   display_name TEXT NOT NULL,
                   company_id TEXT,
                   contacts_json TEXT NOT NULL,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, company_id) REFERENCES companies(project_id, id)
                 );
                 CREATE TABLE partners (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   person_id TEXT,
                   company_id TEXT,
                   display_name TEXT NOT NULL,
                   supply_class TEXT NOT NULL,
                   contact_permission TEXT NOT NULL,
                   permission_evidence_digest TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, person_id) REFERENCES people(project_id, id),
                   FOREIGN KEY (project_id, company_id) REFERENCES companies(project_id, id)
                 );
                 CREATE INDEX partner_supply_permission_idx
                   ON partners(tenant_id, project_id, supply_class, contact_permission);
                 CREATE TABLE identity_links (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   subject_json TEXT NOT NULL,
                   identities_json TEXT NOT NULL,
                   confidence TEXT NOT NULL,
                   status TEXT NOT NULL,
                   confirmed_by TEXT,
                   confirmed_at TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE INDEX identity_link_status_idx
                   ON identity_links(tenant_id, project_id, status);",
            )?;
            record_migration(&transaction, 5)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 6 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE outcome_ledgers (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT PRIMARY KEY,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE TABLE outcome_events (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   kind TEXT NOT NULL,
                   provider TEXT NOT NULL,
                   account_id TEXT,
                   source_event_id TEXT NOT NULL,
                   identity_link_id TEXT,
                   opportunity_id TEXT,
                   campaign_id TEXT,
                   order_id TEXT,
                   refund_id TEXT,
                   commission_id TEXT,
                   payout_id TEXT,
                   partner_id TEXT,
                   amount_minor INTEGER,
                   currency TEXT CHECK (currency IS NULL OR length(currency) = 3),
                   occurred_at TEXT NOT NULL,
                   received_at TEXT NOT NULL,
                   evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                   raw_payload_digest TEXT NOT NULL CHECK (length(raw_payload_digest) = 64),
                   record_json TEXT NOT NULL,
                   UNIQUE (project_id, id),
                   UNIQUE (tenant_id, project_id, provider, source_event_id),
                   FOREIGN KEY (project_id) REFERENCES outcome_ledgers(project_id)
                     ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id),
                   FOREIGN KEY (project_id, identity_link_id)
                     REFERENCES identity_links(project_id, id),
                   FOREIGN KEY (project_id, partner_id) REFERENCES partners(project_id, id)
                 );
                 CREATE INDEX outcome_event_order_idx
                   ON outcome_events(tenant_id, project_id, order_id, received_at);
                 CREATE INDEX outcome_event_identity_idx
                   ON outcome_events(tenant_id, project_id, identity_link_id, occurred_at);
                 CREATE TABLE outcome_orders (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   source_event_id TEXT NOT NULL,
                   amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   occurred_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   UNIQUE (project_id, id),
                   UNIQUE (project_id, source_event_id),
                   FOREIGN KEY (project_id, source_event_id)
                     REFERENCES outcome_events(project_id, id) ON DELETE CASCADE
                 );
                 CREATE TABLE outcome_refunds (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   order_id TEXT NOT NULL,
                   source_event_id TEXT NOT NULL,
                   amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   occurred_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   UNIQUE (project_id, id),
                   UNIQUE (project_id, source_event_id),
                   FOREIGN KEY (project_id, order_id)
                     REFERENCES outcome_orders(project_id, id),
                   FOREIGN KEY (project_id, source_event_id)
                     REFERENCES outcome_events(project_id, id) ON DELETE CASCADE
                 );
                 CREATE TABLE attribution_records (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   order_id TEXT NOT NULL,
                   model TEXT NOT NULL,
                   touchpoint_mission_id TEXT,
                   window_started_at TEXT NOT NULL,
                   window_ended_at TEXT NOT NULL,
                   confidence TEXT NOT NULL,
                   evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                   recorded_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   UNIQUE (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES outcome_ledgers(project_id)
                     ON DELETE CASCADE,
                   FOREIGN KEY (project_id, order_id)
                     REFERENCES outcome_orders(project_id, id),
                   FOREIGN KEY (touchpoint_mission_id, project_id)
                     REFERENCES missions(id, project_id)
                 );
                 CREATE INDEX attribution_order_model_idx
                   ON attribution_records(tenant_id, project_id, order_id, model, recorded_at);
                 CREATE TABLE commission_records (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   order_id TEXT NOT NULL,
                   partner_id TEXT NOT NULL,
                   rate TEXT NOT NULL,
                   eligible_net_minor INTEGER NOT NULL CHECK (eligible_net_minor >= 0),
                   eligible_net_currency TEXT NOT NULL CHECK (length(eligible_net_currency) = 3),
                   commission_minor INTEGER NOT NULL CHECK (commission_minor >= 0),
                   commission_currency TEXT NOT NULL CHECK (length(commission_currency) = 3),
                   terms_digest TEXT NOT NULL CHECK (length(terms_digest) = 64),
                   refund_set_digest TEXT NOT NULL CHECK (length(refund_set_digest) = 64),
                   supersedes TEXT,
                   status TEXT NOT NULL CHECK (
                     status IN ('current', 'recalculation_required', 'superseded')
                   ),
                   calculated_at TEXT NOT NULL,
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   UNIQUE (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES outcome_ledgers(project_id)
                     ON DELETE CASCADE,
                   FOREIGN KEY (project_id, order_id)
                     REFERENCES outcome_orders(project_id, id),
                   FOREIGN KEY (project_id, partner_id) REFERENCES partners(project_id, id),
                   FOREIGN KEY (project_id, supersedes)
                     REFERENCES commission_records(project_id, id)
                 );
                 CREATE INDEX commission_current_idx
                   ON commission_records(tenant_id, project_id, order_id, partner_id, status);",
            )?;
            record_migration(&transaction, 6)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 7 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE mission_lifecycle ADD COLUMN block_json TEXT;
                 ALTER TABLE mission_outcomes RENAME TO mission_outcomes_v6;
                 CREATE TABLE mission_outcomes (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   outcome_json TEXT NOT NULL,
                   PRIMARY KEY (mission_id, project_id, ordinal),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 INSERT INTO mission_outcomes (mission_id, project_id, ordinal, outcome_json)
                   SELECT mission_id, project_id, 0, outcome_json FROM mission_outcomes_v6;
                 DROP TABLE mission_outcomes_v6;",
            )?;
            record_migration(&transaction, 7)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 8 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE project_keyrings (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT PRIMARY KEY,
                   mode TEXT NOT NULL CHECK (mode IN ('personal_e2ee', 'team_envelope')),
                   active_key_version INTEGER NOT NULL CHECK (active_key_version > 0),
                   remote_execution_opt_in INTEGER NOT NULL CHECK (
                     remote_execution_opt_in IN (0, 1)
                   ),
                   rotation_required INTEGER NOT NULL CHECK (rotation_required IN (0, 1)),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE TABLE project_key_envelopes (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   key_version INTEGER NOT NULL CHECK (key_version > 0),
                   recipient_kind TEXT NOT NULL CHECK (
                     recipient_kind IN ('device', 'member', 'worker', 'recovery')
                   ),
                   recipient_id TEXT NOT NULL,
                   wrapping_key_reference_digest TEXT NOT NULL CHECK (
                     length(wrapping_key_reference_digest) = 64
                   ),
                   algorithm TEXT NOT NULL CHECK (algorithm = 'aes256_gcm_v1'),
                   nonce BLOB NOT NULL CHECK (length(nonce) = 12),
                   ciphertext BLOB NOT NULL CHECK (length(ciphertext) >= 16),
                   aad_digest TEXT NOT NULL CHECK (length(aad_digest) = 64),
                   created_at TEXT NOT NULL,
                   expires_at TEXT,
                   revoked_at TEXT,
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   UNIQUE (project_id, id),
                   UNIQUE (project_id, key_version, recipient_kind, recipient_id),
                   FOREIGN KEY (project_id) REFERENCES project_keyrings(project_id)
                     ON DELETE CASCADE
                 );
                 CREATE INDEX project_key_recipient_idx
                   ON project_key_envelopes(
                     tenant_id, project_id, key_version, recipient_kind, recipient_id, revoked_at
                   );",
            )?;
            record_migration(&transaction, 8)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 9 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE conversations (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT,
                   person_id TEXT NOT NULL,
                   company_id TEXT,
                   gateway TEXT NOT NULL,
                   account_id TEXT NOT NULL,
                   route_digest TEXT NOT NULL CHECK (length(route_digest) = 64),
                   contact_channel TEXT NOT NULL,
                   market TEXT NOT NULL,
                   state TEXT NOT NULL,
                   control_json TEXT NOT NULL,
                   control_generation INTEGER NOT NULL CHECK (control_generation > 0),
                   last_resume_evidence_digest TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, gateway, account_id, route_digest),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id),
                   FOREIGN KEY (project_id, person_id) REFERENCES people(project_id, id),
                   FOREIGN KEY (project_id, company_id) REFERENCES companies(project_id, id)
                 );
                 CREATE INDEX conversation_control_idx
                   ON conversations(
                     tenant_id, project_id, state, control_generation, gateway, account_id
                   );
                 CREATE TABLE conversation_messages (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   project_id TEXT NOT NULL,
                   conversation_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   direction TEXT NOT NULL,
                   provider_event_digest TEXT,
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   delivery_json TEXT NOT NULL,
                   control_generation INTEGER NOT NULL CHECK (control_generation > 0),
                   occurred_at TEXT NOT NULL,
                   received_at TEXT NOT NULL,
                   delivered_at TEXT,
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   UNIQUE (project_id, conversation_id, id),
                   UNIQUE (project_id, conversation_id, provider_event_digest),
                   FOREIGN KEY (project_id, conversation_id)
                     REFERENCES conversations(project_id, id) ON DELETE CASCADE
                 );
                 CREATE INDEX conversation_message_replay_idx
                   ON conversation_messages(
                     project_id, conversation_id, received_at, sequence
                   );
                 CREATE TABLE campaigns (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   channel TEXT NOT NULL,
                   purpose TEXT NOT NULL,
                   market TEXT NOT NULL,
                   frequency_window_seconds INTEGER NOT NULL CHECK (frequency_window_seconds > 0),
                   max_messages_per_window INTEGER NOT NULL CHECK (max_messages_per_window > 0),
                   status TEXT NOT NULL,
                   policy_version INTEGER NOT NULL CHECK (policy_version > 0),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                 );
                 CREATE TABLE campaign_recipients (
                   project_id TEXT NOT NULL,
                   campaign_id TEXT NOT NULL,
                   person_id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   consent_record_id TEXT NOT NULL,
                   state_json TEXT NOT NULL,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, campaign_id, person_id),
                   UNIQUE (project_id, campaign_id, ordinal),
                   FOREIGN KEY (project_id, campaign_id)
                     REFERENCES campaigns(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, person_id) REFERENCES people(project_id, id),
                   FOREIGN KEY (project_id, consent_record_id)
                     REFERENCES consent_records(project_id, id)
                 );
                 CREATE INDEX campaign_recipient_state_idx
                   ON campaign_recipients(project_id, campaign_id, state_json);
                 CREATE TABLE opportunities (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   company_id TEXT NOT NULL,
                   stage TEXT NOT NULL,
                   forecast_amount_minor INTEGER,
                   forecast_currency TEXT CHECK (
                     forecast_currency IS NULL OR length(forecast_currency) = 3
                   ),
                   forecast_evidence_digest TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, company_id) REFERENCES companies(project_id, id)
                 );
                 CREATE INDEX opportunity_stage_idx
                   ON opportunities(tenant_id, project_id, stage, updated_at);
                 CREATE TABLE opportunity_committee_members (
                   project_id TEXT NOT NULL,
                   opportunity_id TEXT NOT NULL,
                   person_id TEXT NOT NULL,
                   role TEXT NOT NULL,
                   evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, opportunity_id, person_id, role),
                   FOREIGN KEY (project_id, opportunity_id)
                     REFERENCES opportunities(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, person_id) REFERENCES people(project_id, id)
                 );
                 CREATE TABLE opportunity_stage_history (
                   project_id TEXT NOT NULL,
                   opportunity_id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, opportunity_id, ordinal),
                   FOREIGN KEY (project_id, opportunity_id)
                     REFERENCES opportunities(project_id, id) ON DELETE CASCADE
                 );",
            )?;
            record_migration(&transaction, 9)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 10 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE conversation_messages
                   ADD COLUMN effect_scope_digest TEXT CHECK (
                     effect_scope_digest IS NULL OR length(effect_scope_digest) = 64
                   );",
            )?;
            record_migration(&transaction, 10)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 11 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE creator_tasks ADD COLUMN hiring_award_json TEXT;
                 CREATE TABLE creator_hirings (
                   id TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   title TEXT NOT NULL,
                   brief_digest TEXT NOT NULL CHECK (length(brief_digest) = 64),
                   bounty_minor INTEGER NOT NULL CHECK (bounty_minor > 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   market TEXT NOT NULL,
                   application_deadline TEXT NOT NULL,
                   due_at TEXT NOT NULL,
                   offer_digest TEXT NOT NULL CHECK (length(offer_digest) = 64),
                   status TEXT NOT NULL,
                   state_revision INTEGER NOT NULL CHECK (state_revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE INDEX creator_hiring_status_idx
                   ON creator_hirings(tenant_id, project_id, status, application_deadline);
                 CREATE TABLE creator_hiring_candidates (
                   project_id TEXT NOT NULL,
                   hiring_id TEXT NOT NULL,
                   creator_id TEXT NOT NULL,
                   partner_id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   person_id TEXT,
                   supply_class TEXT NOT NULL,
                   contact_permission TEXT NOT NULL,
                   permission_evidence_digest TEXT,
                   identity_evidence_digest TEXT NOT NULL CHECK (
                     length(identity_evidence_digest) = 64
                   ),
                   fit_evidence_digest TEXT NOT NULL CHECK (length(fit_evidence_digest) = 64),
                   status TEXT NOT NULL,
                   added_at TEXT NOT NULL,
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, hiring_id, creator_id),
                   UNIQUE (project_id, hiring_id, partner_id),
                   UNIQUE (project_id, hiring_id, ordinal),
                   FOREIGN KEY (project_id, hiring_id)
                     REFERENCES creator_hirings(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, partner_id) REFERENCES partners(project_id, id),
                   FOREIGN KEY (project_id, person_id) REFERENCES people(project_id, id)
                 );
                 CREATE TABLE creator_hiring_listings (
                   project_id TEXT NOT NULL,
                   hiring_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
                   receipt_id TEXT NOT NULL,
                   verification_id TEXT NOT NULL,
                   verified_at TEXT NOT NULL,
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, hiring_id),
                   UNIQUE (project_id, effect_id),
                   FOREIGN KEY (project_id, hiring_id)
                     REFERENCES creator_hirings(project_id, id) ON DELETE CASCADE
                 );
                 CREATE TABLE creator_hiring_invitations (
                   project_id TEXT NOT NULL,
                   hiring_id TEXT NOT NULL,
                   creator_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
                   prepared_at TEXT NOT NULL,
                   verified_at TEXT,
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, hiring_id, creator_id),
                   UNIQUE (project_id, effect_id),
                   FOREIGN KEY (project_id, hiring_id, creator_id)
                     REFERENCES creator_hiring_candidates(project_id, hiring_id, creator_id)
                       ON DELETE CASCADE
                 );
                 CREATE TABLE creator_hiring_applications (
                   project_id TEXT NOT NULL,
                   hiring_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   creator_id TEXT NOT NULL,
                   partner_id TEXT NOT NULL,
                   origin_effect_id TEXT NOT NULL,
                   offer_digest TEXT NOT NULL CHECK (length(offer_digest) = 64),
                   proposed_amount_minor INTEGER NOT NULL CHECK (proposed_amount_minor > 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   proposal_digest TEXT NOT NULL CHECK (length(proposal_digest) = 64),
                   rights_ack_digest TEXT NOT NULL CHECK (length(rights_ack_digest) = 64),
                   submitted_at TEXT NOT NULL,
                   status TEXT NOT NULL,
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, hiring_id, id),
                   UNIQUE (project_id, hiring_id, creator_id),
                   FOREIGN KEY (project_id, hiring_id, creator_id)
                     REFERENCES creator_hiring_candidates(project_id, hiring_id, creator_id),
                   FOREIGN KEY (project_id, partner_id) REFERENCES partners(project_id, id)
                 );
                 CREATE TABLE creator_hiring_awards (
                   project_id TEXT NOT NULL,
                   hiring_id TEXT NOT NULL,
                   application_id TEXT NOT NULL,
                   creator_id TEXT NOT NULL,
                   partner_id TEXT NOT NULL,
                   offer_digest TEXT NOT NULL CHECK (length(offer_digest) = 64),
                   amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   selected_by TEXT NOT NULL,
                   selection_evidence_digest TEXT NOT NULL CHECK (
                     length(selection_evidence_digest) = 64
                   ),
                   selected_at TEXT NOT NULL,
                   immutable_digest TEXT NOT NULL CHECK (length(immutable_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, hiring_id),
                   UNIQUE (project_id, hiring_id, application_id),
                   FOREIGN KEY (project_id, hiring_id, application_id)
                     REFERENCES creator_hiring_applications(project_id, hiring_id, id),
                   FOREIGN KEY (project_id, hiring_id, creator_id)
                     REFERENCES creator_hiring_candidates(project_id, hiring_id, creator_id),
                   FOREIGN KEY (project_id, partner_id) REFERENCES partners(project_id, id)
                 );",
            )?;
            record_migration(&transaction, 11)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 12 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE encrypted_sync_operations (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   idempotency_key_digest TEXT NOT NULL CHECK (
                     length(idempotency_key_digest) = 64
                   ),
                   intent_digest TEXT NOT NULL CHECK (length(intent_digest) = 64),
                   request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                   cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
                   object_id TEXT NOT NULL,
                   object_kind TEXT NOT NULL,
                   target_revision INTEGER NOT NULL CHECK (target_revision > 0),
                   key_version INTEGER NOT NULL CHECK (key_version > 0),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
                   request_json TEXT NOT NULL,
                   status TEXT NOT NULL,
                   remote_revision INTEGER CHECK (
                     remote_revision IS NULL OR remote_revision > 0
                   ),
                   remote_duplicate INTEGER NOT NULL DEFAULT 0 CHECK (
                     remote_duplicate IN (0, 1)
                   ),
                   last_error_code TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, idempotency_key_digest),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE INDEX encrypted_sync_status_idx
                   ON encrypted_sync_operations(
                     tenant_id, project_id, status, updated_at
                   );
                 CREATE UNIQUE INDEX encrypted_sync_object_request_idx
                   ON encrypted_sync_operations(
                     project_id, object_id, target_revision, request_digest
                   );",
            )?;
            record_migration(&transaction, 12)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 13 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE encrypted_sync_inbound_versions (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
                   object_id TEXT NOT NULL,
                   object_kind TEXT NOT NULL,
                   remote_revision INTEGER NOT NULL CHECK (remote_revision > 0),
                   key_version INTEGER NOT NULL CHECK (key_version > 0),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
                   request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                   request_json TEXT NOT NULL,
                   remote_recorded_at TEXT NOT NULL,
                   staged_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, cell, object_id, remote_revision),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE TABLE encrypted_sync_inbound_heads (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
                   object_id TEXT NOT NULL,
                   object_kind TEXT NOT NULL,
                   current_remote_revision INTEGER NOT NULL CHECK (
                     current_remote_revision > 0
                   ),
                   key_version INTEGER NOT NULL CHECK (key_version > 0),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
                   status TEXT NOT NULL CHECK (
                     status IN ('staged', 'validated', 'applied', 'conflict')
                   ),
                   validation_digest TEXT CHECK (
                     validation_digest IS NULL OR length(validation_digest) = 64
                   ),
                   projection_digest TEXT CHECK (
                     projection_digest IS NULL OR length(projection_digest) = 64
                   ),
                   projection_revision INTEGER CHECK (
                     projection_revision IS NULL OR projection_revision > 0
                   ),
                   last_error_code TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   staged_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, object_id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, cell, object_id, current_remote_revision)
                     REFERENCES encrypted_sync_inbound_versions(
                       project_id, cell, object_id, remote_revision
                     )
                 );
                 CREATE INDEX encrypted_sync_inbound_status_idx
                   ON encrypted_sync_inbound_heads(
                     tenant_id, project_id, status, updated_at
                   );",
            )?;
            record_migration(&transaction, 13)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 14 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE projects ADD COLUMN data_cell TEXT CHECK (
                   data_cell IS NULL OR data_cell IN ('us', 'eu')
                 );
                 CREATE TABLE project_cloud_registrations (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT PRIMARY KEY,
                   cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
                   encryption_mode TEXT NOT NULL CHECK (
                     encryption_mode IN ('personal_e2ee', 'team_envelope')
                   ),
                   remote_execution_opt_in INTEGER NOT NULL CHECK (
                     remote_execution_opt_in IN (0, 1)
                   ),
                   idempotency_key_digest TEXT NOT NULL CHECK (
                     length(idempotency_key_digest) = 64
                   ),
                   intent_digest TEXT NOT NULL CHECK (length(intent_digest) = 64),
                   request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                   key_version INTEGER NOT NULL CHECK (key_version > 0),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   request_json TEXT NOT NULL,
                   authorized_by TEXT NOT NULL,
                   authorization_evidence_digest TEXT NOT NULL CHECK (
                     length(authorization_evidence_digest) = 64
                   ),
                   status TEXT NOT NULL CHECK (
                     status IN ('prepared', 'applied', 'conflict')
                   ),
                   remote_revision INTEGER CHECK (
                     remote_revision IS NULL OR remote_revision > 0
                   ),
                   remote_duplicate INTEGER NOT NULL DEFAULT 0 CHECK (
                     remote_duplicate IN (0, 1)
                   ),
                   last_error_code TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE UNIQUE INDEX project_cloud_registration_idempotency_idx
                   ON project_cloud_registrations(
                     tenant_id, project_id, idempotency_key_digest
                   );",
            )?;
            record_migration(&transaction, 14)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 15 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE work_product_manifests (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   work_product_id TEXT NOT NULL,
                   work_product_type TEXT NOT NULL,
                   version INTEGER NOT NULL CHECK (version > 0),
                   work_product_revision INTEGER NOT NULL CHECK (work_product_revision > 0),
                   dependencies_json TEXT NOT NULL,
                   artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64),
                   file_digest TEXT CHECK (file_digest IS NULL OR length(file_digest) = 64),
                   preview_json TEXT NOT NULL,
                   editable_scopes_json TEXT NOT NULL,
                   adoption_status TEXT NOT NULL,
                   manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, mission_id, work_product_id),
                   UNIQUE (project_id, work_product_id),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE INDEX work_product_manifest_dependency_idx
                   ON work_product_manifests(
                     tenant_id, project_id, mission_id, updated_at
                   );",
            )?;
            record_migration(&transaction, 15)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 16 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE conversations
                   ADD COLUMN provider TEXT NOT NULL DEFAULT 'legacy_unresolved';
                 ALTER TABLE conversations
                   ADD COLUMN connection_id TEXT NOT NULL DEFAULT 'legacy-unresolved';
                 UPDATE conversations
                 SET provider = CASE gateway
                   WHEN 'gmail' THEN 'gmail'
                   WHEN 'outlook' THEN 'outlook'
                   WHEN 'resend' THEN 'resend'
                   WHEN 'chatwoot' THEN 'chatwoot'
                   WHEN 'slack' THEN 'slack'
                   WHEN 'teams' THEN 'teams'
                   WHEN 'feishu' THEN 'feishu'
                   WHEN 'social' THEN COALESCE(
                     (SELECT candidate.provider FROM connections AS candidate
                      WHERE candidate.project_id = conversations.project_id
                        AND candidate.account_id = conversations.account_id
                        AND candidate.provider IN (
                          'meta', 'tiktok', 'x', 'linkedin', 'reddit', 'youtube'
                        )
                      ORDER BY candidate.id LIMIT 1),
                     'legacy_unresolved'
                   )
                   ELSE 'legacy_unresolved'
                 END;
                 UPDATE conversations
                 SET connection_id = COALESCE(
                   (SELECT candidate.id FROM connections AS candidate
                    WHERE candidate.project_id = conversations.project_id
                      AND candidate.account_id = conversations.account_id
                      AND candidate.provider = conversations.provider
                    ORDER BY candidate.id LIMIT 1),
                   'legacy-unresolved:' || id
                 );
                 UPDATE conversations
                 SET state = 'dead_letter'
                 WHERE provider = 'legacy_unresolved'
                    OR connection_id LIKE 'legacy-unresolved:%'
                    OR EXISTS (
                      SELECT 1 FROM conversation_messages AS message
                      WHERE message.project_id = conversations.project_id
                        AND message.conversation_id = conversations.id
                        AND message.effect_scope_digest IS NOT NULL
                    );
                 UPDATE conversations
                 SET record_json = json_set(
                   record_json,
                   '$.provider', provider,
                   '$.connectionId', connection_id,
                   '$.state', state
                 );
                 CREATE INDEX conversation_connection_idx
                   ON conversations(
                     tenant_id, project_id, provider, connection_id, account_id, state
                   );",
            )?;
            record_migration(&transaction, 16)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 17 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE outcome_events ADD COLUMN connection_id TEXT;
                 ALTER TABLE outcome_events ADD COLUMN source_verification_method TEXT;
                 ALTER TABLE outcome_events ADD COLUMN source_verifier TEXT;
                 ALTER TABLE outcome_events ADD COLUMN source_verification_independent INTEGER
                   CHECK (
                     source_verification_independent IS NULL
                     OR source_verification_independent IN (0, 1)
                   );
                 ALTER TABLE outcome_events ADD COLUMN source_verified_at TEXT;
                 ALTER TABLE outcome_events
                   ADD COLUMN source_verification_evidence_digest TEXT CHECK (
                     source_verification_evidence_digest IS NULL
                     OR length(source_verification_evidence_digest) = 64
                   );
                 CREATE INDEX outcome_event_source_verification_idx
                   ON outcome_events(
                     tenant_id, project_id, provider, connection_id, account_id,
                     source_verification_method, received_at
                   );",
            )?;
            record_migration(&transaction, 17)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 18 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE context_workspaces (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   contract_version INTEGER NOT NULL CHECK (contract_version > 0),
                   policy_version TEXT NOT NULL,
                   capability_authority_json TEXT NOT NULL,
                   constraint_digest TEXT NOT NULL CHECK (length(constraint_digest) = 64),
                   token_limit INTEGER NOT NULL CHECK (token_limit > 0),
                   cost_limit_minor INTEGER NOT NULL CHECK (cost_limit_minor >= 0),
                   currency TEXT NOT NULL CHECK (length(currency) = 3),
                   deadline_at TEXT NOT NULL,
                   max_depth INTEGER NOT NULL CHECK (max_depth > 0),
                   max_concurrency INTEGER NOT NULL CHECK (max_concurrency > 0),
                   data_policy TEXT NOT NULL CHECK (
                     data_policy IN (
                       'public_only', 'business_only', 'business_and_redacted_personal'
                     )
                   ),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, mission_id, generation),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id)
                     ON DELETE CASCADE
                 );
                 CREATE TABLE context_branches (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   parent_branch_id TEXT,
                   depth INTEGER NOT NULL CHECK (depth >= 0),
                   fork_reason TEXT NOT NULL,
                   scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
                   merge_policy TEXT NOT NULL CHECK (
                     merge_policy IN ('typed_result_only', 'manual_review')
                   ),
                   status TEXT NOT NULL CHECK (
                     status IN ('active', 'completed', 'merged', 'abandoned')
                   ),
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, workspace_id, id),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, parent_branch_id)
                     REFERENCES context_branches(project_id, id)
                 );
                 CREATE TABLE worker_leases (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   branch_id TEXT NOT NULL,
                   worker_id TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   lease_token_digest TEXT NOT NULL CHECK (length(lease_token_digest) = 64),
                   runtime_mapping_digest TEXT CHECK (
                     runtime_mapping_digest IS NULL OR length(runtime_mapping_digest) = 64
                   ),
                   issued_at TEXT NOT NULL,
                   heartbeat_at TEXT NOT NULL,
                   expires_at TEXT NOT NULL,
                   status TEXT NOT NULL CHECK (
                     status IN ('active', 'released', 'revoked', 'expired')
                   ),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, branch_id, worker_id, generation),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, branch_id)
                     REFERENCES context_branches(project_id, id) ON DELETE CASCADE
                 );
                 CREATE TABLE context_capsules (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   task_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   branch_id TEXT NOT NULL,
                   worker_lease_id TEXT NOT NULL,
                   worker_id TEXT NOT NULL,
                   worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
                   authority_digest TEXT NOT NULL CHECK (length(authority_digest) = 64),
                   status TEXT NOT NULL CHECK (
                     status IN (
                       'issued', 'claimed', 'result_submitted', 'accepted', 'cancelled', 'expired'
                     )
                   ),
                   issued_at TEXT NOT NULL,
                   expires_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, branch_id, worker_generation),
                   FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id),
                   FOREIGN KEY (project_id, branch_id)
                     REFERENCES context_branches(project_id, id),
                   FOREIGN KEY (project_id, worker_lease_id)
                     REFERENCES worker_leases(project_id, id)
                 );
                 CREATE TABLE context_capsule_facts (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   capsule_id TEXT NOT NULL,
                   fact_id TEXT NOT NULL,
                   fact_version INTEGER NOT NULL CHECK (fact_version > 0),
                   classification TEXT NOT NULL CHECK (
                     classification IN ('public', 'business', 'redacted_personal')
                   ),
                   PRIMARY KEY (project_id, capsule_id, fact_id),
                   FOREIGN KEY (project_id, capsule_id)
                     REFERENCES context_capsules(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, fact_id, fact_version)
                     REFERENCES truth_fact_revisions(project_id, id, version)
                 );
                 CREATE INDEX context_workspace_mission_idx
                   ON context_workspaces(
                     tenant_id, project_id, mission_id, generation, updated_at
                   );
                 CREATE INDEX worker_lease_claim_idx
                   ON worker_leases(
                     tenant_id, project_id, workspace_id, status, expires_at, generation
                   );
                 CREATE INDEX context_capsule_status_idx
                   ON context_capsules(
                     tenant_id, project_id, mission_id, status, updated_at
                   );",
            )?;
            record_migration(&transaction, 18)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 19 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE sync_deletion_records (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   deletion_id TEXT NOT NULL,
                   object_id TEXT NOT NULL,
                   object_kind TEXT NOT NULL,
                   prior_object_revision INTEGER NOT NULL CHECK (prior_object_revision > 0),
                   remote_object_revision INTEGER NOT NULL CHECK (
                     remote_object_revision = prior_object_revision + 1
                   ),
                   deletion_generation INTEGER NOT NULL CHECK (deletion_generation > 0),
                   reason TEXT NOT NULL CHECK (
                     reason IN (
                       'user_request', 'project_deletion', 'retention_expiry',
                       'consent_withdrawal', 'security_response'
                     )
                   ),
                   authorized_by TEXT NOT NULL,
                   authorization_evidence_digest TEXT NOT NULL CHECK (
                     length(authorization_evidence_digest) = 64
                   ),
                   requested_at TEXT NOT NULL,
                   retention_mode TEXT NOT NULL CHECK (
                     retention_mode = 'erase_content_retain_audit'
                   ),
                   tombstone_digest TEXT NOT NULL CHECK (length(tombstone_digest) = 64),
                   surfaces_json TEXT NOT NULL,
                   complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
                   record_revision INTEGER NOT NULL CHECK (record_revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, deletion_id),
                   UNIQUE (project_id, object_kind, object_id),
                   UNIQUE (project_id, object_kind, object_id, deletion_generation),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                 );
                 CREATE INDEX sync_deletion_pending_idx
                   ON sync_deletion_records(
                     tenant_id, project_id, complete, updated_at
                   );",
            )?;
            record_migration(&transaction, 19)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 20 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE deletion_propagation_jobs (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   deletion_id TEXT NOT NULL,
                   object_id TEXT NOT NULL,
                   object_kind TEXT NOT NULL,
                   surface TEXT NOT NULL CHECK (
                     surface IN ('cache', 'replay', 'object_storage')
                   ),
                   deletion_generation INTEGER NOT NULL CHECK (deletion_generation > 0),
                   tombstone_digest TEXT NOT NULL CHECK (length(tombstone_digest) = 64),
                   status TEXT NOT NULL CHECK (
                     status IN ('pending', 'leased', 'applied', 'dead_letter')
                   ),
                   attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                   available_at TEXT NOT NULL,
                   lease_owner TEXT,
                   lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
                   lease_expires_at TEXT,
                   last_error_code TEXT,
                   receipt_id TEXT,
                   receipt_digest TEXT CHECK (
                     receipt_digest IS NULL OR length(receipt_digest) = 64
                   ),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, deletion_id, surface),
                   FOREIGN KEY (project_id, deletion_id)
                     REFERENCES sync_deletion_records(project_id, deletion_id) ON DELETE CASCADE,
                   CHECK (
                     (status = 'pending' AND lease_owner IS NULL AND lease_expires_at IS NULL
                       AND receipt_id IS NULL AND receipt_digest IS NULL)
                     OR (status = 'leased' AND lease_owner IS NOT NULL
                       AND lease_expires_at IS NOT NULL AND receipt_id IS NULL
                       AND receipt_digest IS NULL)
                     OR (status = 'applied' AND lease_owner IS NULL
                       AND lease_expires_at IS NULL AND receipt_id IS NOT NULL
                       AND receipt_digest IS NOT NULL)
                     OR (status = 'dead_letter' AND lease_owner IS NULL
                       AND lease_expires_at IS NULL AND last_error_code IS NOT NULL
                       AND receipt_id IS NULL AND receipt_digest IS NULL)
                   )
                 );
                 CREATE TABLE deletion_propagation_receipts (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   deletion_id TEXT NOT NULL,
                   receipt_id TEXT NOT NULL,
                   object_id TEXT NOT NULL,
                   object_kind TEXT NOT NULL,
                   surface TEXT NOT NULL CHECK (
                     surface IN ('cache', 'replay', 'object_storage')
                   ),
                   deletion_generation INTEGER NOT NULL CHECK (deletion_generation > 0),
                   tombstone_digest TEXT NOT NULL CHECK (length(tombstone_digest) = 64),
                   worker_id TEXT NOT NULL,
                   lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
                   inventory_digest TEXT NOT NULL CHECK (length(inventory_digest) = 64),
                   matched_items INTEGER NOT NULL CHECK (matched_items >= 0),
                   deleted_items INTEGER NOT NULL CHECK (deleted_items >= 0),
                   residual_items INTEGER NOT NULL CHECK (residual_items = 0),
                   verification_digest TEXT NOT NULL CHECK (length(verification_digest) = 64),
                   completed_at TEXT NOT NULL,
                   receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 64),
                   receipt_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, receipt_id),
                   UNIQUE (project_id, deletion_id, surface),
                   FOREIGN KEY (project_id, deletion_id, surface)
                     REFERENCES deletion_propagation_jobs(project_id, deletion_id, surface)
                       ON DELETE CASCADE,
                   CHECK (matched_items = deleted_items)
                 );
                 CREATE INDEX deletion_propagation_claim_idx
                   ON deletion_propagation_jobs(
                     surface, status, available_at, lease_expires_at, created_at
                   );
                 INSERT INTO deletion_propagation_jobs
                   (tenant_id, project_id, deletion_id, object_id, object_kind, surface,
                    deletion_generation, tombstone_digest, status, attempts, available_at,
                    lease_owner, lease_generation, lease_expires_at, last_error_code,
                    receipt_id, receipt_digest, created_at, updated_at)
                 SELECT deletion.tenant_id, deletion.project_id, deletion.deletion_id,
                        deletion.object_id, deletion.object_kind, surface.name,
                        deletion.deletion_generation, deletion.tombstone_digest,
                        'pending', 0, deletion.updated_at, NULL, 0, NULL, NULL,
                        NULL, NULL, deletion.created_at, deletion.updated_at
                 FROM sync_deletion_records deletion
                 CROSS JOIN (
                   SELECT 'cache' AS name
                   UNION ALL SELECT 'replay'
                   UNION ALL SELECT 'object_storage'
                 ) surface
                 WHERE json_extract(
                   deletion.surfaces_json, '$.' || surface.name || '.status'
                 ) = 'pending';",
            )?;
            record_migration(&transaction, 20)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 21 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE device_key_attachments (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   attachment_id TEXT NOT NULL,
                   idempotency_key_digest TEXT NOT NULL CHECK (
                     length(idempotency_key_digest) = 64
                   ),
                   intent_digest TEXT NOT NULL CHECK (length(intent_digest) = 64),
                   project_mode TEXT NOT NULL CHECK (
                     project_mode IN ('personal_e2ee', 'team_envelope')
                   ),
                   method TEXT NOT NULL CHECK (
                     method IN ('authorized_recipient', 'recovery_kit')
                   ),
                   source_recipient_kind TEXT NOT NULL CHECK (
                     source_recipient_kind IN ('device', 'member', 'recovery')
                   ),
                   source_recipient_id TEXT NOT NULL,
                   device_id TEXT NOT NULL,
                   key_version INTEGER NOT NULL CHECK (key_version > 0),
                   expected_keyring_revision INTEGER NOT NULL CHECK (
                     expected_keyring_revision > 0
                   ),
                   envelope_id TEXT NOT NULL,
                   wrapping_key_reference_digest TEXT NOT NULL CHECK (
                     length(wrapping_key_reference_digest) = 64
                   ),
                   authorized_by TEXT NOT NULL,
                   authorization_evidence_digest TEXT NOT NULL CHECK (
                     length(authorization_evidence_digest) = 64
                   ),
                   status TEXT NOT NULL CHECK (
                     status IN ('prepared', 'applied', 'conflict')
                   ),
                   result_keyring_revision INTEGER CHECK (
                     result_keyring_revision IS NULL OR result_keyring_revision > 0
                   ),
                   error_code TEXT,
                   attachment_revision INTEGER NOT NULL CHECK (attachment_revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, attachment_id),
                   UNIQUE (project_id, idempotency_key_digest),
                   UNIQUE (project_id, device_id, key_version),
                   FOREIGN KEY (project_id) REFERENCES project_keyrings(project_id)
                     ON DELETE CASCADE,
                   CHECK (
                     (status = 'prepared' AND attachment_revision = 1
                       AND result_keyring_revision IS NULL AND error_code IS NULL)
                     OR (status = 'applied' AND attachment_revision = 2
                       AND result_keyring_revision = expected_keyring_revision + 1
                       AND error_code IS NULL)
                     OR (status = 'conflict' AND attachment_revision = 2
                       AND result_keyring_revision IS NULL AND error_code IS NOT NULL)
                   )
                 );
                 CREATE INDEX device_key_attachment_status_idx
                   ON device_key_attachments(
                     tenant_id, project_id, status, updated_at
                   );",
            )?;
            record_migration(&transaction, 21)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 22 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "ALTER TABLE device_key_attachments RENAME TO device_key_attachments_v21;
                 CREATE TABLE device_key_attachments (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   attachment_id TEXT NOT NULL,
                   idempotency_key_digest TEXT NOT NULL CHECK (
                     length(idempotency_key_digest) = 64
                   ),
                   intent_digest TEXT NOT NULL CHECK (length(intent_digest) = 64),
                   project_mode TEXT NOT NULL CHECK (
                     project_mode IN ('personal_e2ee', 'team_envelope')
                   ),
                   method TEXT NOT NULL CHECK (
                     method IN (
                       'authorized_recipient', 'public_key_handoff', 'recovery_kit'
                     )
                   ),
                   source_recipient_kind TEXT NOT NULL CHECK (
                     source_recipient_kind IN ('device', 'member', 'recovery')
                   ),
                   source_recipient_id TEXT NOT NULL,
                   device_id TEXT NOT NULL,
                   key_version INTEGER NOT NULL CHECK (key_version > 0),
                   expected_keyring_revision INTEGER NOT NULL CHECK (
                     expected_keyring_revision > 0
                   ),
                   envelope_id TEXT NOT NULL,
                   wrapping_key_reference_digest TEXT NOT NULL CHECK (
                     length(wrapping_key_reference_digest) = 64
                   ),
                   authorized_by TEXT NOT NULL,
                   authorization_evidence_digest TEXT NOT NULL CHECK (
                     length(authorization_evidence_digest) = 64
                   ),
                   status TEXT NOT NULL CHECK (
                     status IN ('prepared', 'applied', 'conflict')
                   ),
                   result_keyring_revision INTEGER CHECK (
                     result_keyring_revision IS NULL OR result_keyring_revision > 0
                   ),
                   error_code TEXT,
                   attachment_revision INTEGER NOT NULL CHECK (attachment_revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, attachment_id),
                   UNIQUE (project_id, idempotency_key_digest),
                   UNIQUE (project_id, device_id, key_version),
                   FOREIGN KEY (project_id) REFERENCES project_keyrings(project_id)
                     ON DELETE CASCADE,
                   CHECK (
                     (status = 'prepared' AND attachment_revision = 1
                       AND result_keyring_revision IS NULL AND error_code IS NULL)
                     OR (status = 'applied' AND attachment_revision = 2
                       AND result_keyring_revision = expected_keyring_revision + 1
                       AND error_code IS NULL)
                     OR (status = 'conflict' AND attachment_revision = 2
                       AND result_keyring_revision IS NULL AND error_code IS NOT NULL)
                   )
                 );
                 INSERT INTO device_key_attachments
                 SELECT * FROM device_key_attachments_v21;
                 DROP TABLE device_key_attachments_v21;
                 CREATE INDEX device_key_attachment_status_idx
                   ON device_key_attachments(
                     tenant_id, project_id, status, updated_at
                   );
                 CREATE TABLE key_bootstrap_operations (
                   operation_id TEXT PRIMARY KEY,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   cell TEXT NOT NULL CHECK (cell IN ('us', 'eu')),
                   operation_kind TEXT NOT NULL CHECK (
                     operation_kind IN (
                       'device_public_key', 'keyring_bootstrap', 'handoff_grant',
                       'handoff_claim', 'handoff_revocation', 'handoff_consumption'
                     )
                   ),
                   idempotency_key_digest TEXT NOT NULL CHECK (
                     length(idempotency_key_digest) = 64
                   ),
                   request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                   request_json TEXT NOT NULL,
                   status TEXT NOT NULL CHECK (
                     status IN ('prepared', 'applied', 'conflict')
                   ),
                   remote_revision INTEGER CHECK (
                     remote_revision IS NULL OR remote_revision > 0
                   ),
                   remote_reference TEXT,
                   error_code TEXT,
                   operation_revision INTEGER NOT NULL CHECK (operation_revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   UNIQUE (project_id, operation_kind, idempotency_key_digest),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   CHECK (
                     (status = 'prepared' AND operation_revision = 1
                       AND remote_revision IS NULL AND remote_reference IS NULL
                       AND error_code IS NULL)
                     OR (status = 'applied' AND operation_revision = 2
                       AND (remote_revision IS NOT NULL OR remote_reference IS NOT NULL)
                       AND error_code IS NULL)
                     OR (status = 'conflict' AND operation_revision = 2
                       AND remote_revision IS NULL AND remote_reference IS NULL
                       AND error_code IS NOT NULL)
                   )
                 );
                 CREATE INDEX key_bootstrap_operation_status_idx
                   ON key_bootstrap_operations(
                     tenant_id, project_id, status, operation_kind, updated_at
                   );",
            )?;
            record_migration(&transaction, 22)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 23 {
            let decision_history_exists = self
                .connection
                .query_row(
                    "SELECT 1 FROM pragma_table_info('identity_links')
                     WHERE name = 'decision_history_json'",
                    [],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let transaction = self.connection.transaction()?;
            if !decision_history_exists {
                transaction.execute_batch(
                    "ALTER TABLE identity_links
                       ADD COLUMN decision_history_json TEXT NOT NULL DEFAULT '[]';",
                )?;
            }
            transaction.execute_batch(
                "UPDATE identity_links
                 SET decision_history_json = json_array(json_object(
                   'from', 'proposed',
                   'to', 'confirmed',
                   'decidedBy', confirmed_by,
                   'evidenceDigest', json_extract(
                     identities_json, '$[0].evidenceDigest'
                   ),
                   'decidedAt', confirmed_at
                 ))
                 WHERE status = 'confirmed'
                   AND revision = 2
                   AND confirmed_by IS NOT NULL
                   AND trim(confirmed_by) != ''
                   AND confirmed_at IS NOT NULL
                   AND length(json_extract(
                     identities_json, '$[0].evidenceDigest'
                   )) = 64
                   AND decision_history_json = '[]';",
            )?;
            record_migration(&transaction, 23)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 24 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS effect_rate_limit_buckets (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
                   rule_id TEXT NOT NULL CHECK (trim(rule_id) != ''),
                   policy_version TEXT NOT NULL CHECK (trim(policy_version) != ''),
                   policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 64),
                   provider TEXT NOT NULL CHECK (trim(provider) != ''),
                   account_id TEXT,
                   capability TEXT NOT NULL CHECK (trim(capability) != ''),
                   window_started_at TEXT NOT NULL,
                   window_ends_at TEXT NOT NULL,
                   max_executions INTEGER NOT NULL CHECK (max_executions > 0),
                   window_seconds INTEGER NOT NULL CHECK (window_seconds > 0),
                   consumed INTEGER NOT NULL CHECK (
                     consumed >= 0 AND consumed <= max_executions
                   ),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, scope_digest, window_started_at),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   CHECK (window_ends_at > window_started_at),
                   CHECK (updated_at >= created_at)
                 );
                 CREATE INDEX IF NOT EXISTS effect_rate_limit_bucket_scope_idx
                   ON effect_rate_limit_buckets(
                     tenant_id, project_id, provider, account_id, capability,
                     window_ends_at
                   );
                 CREATE TABLE IF NOT EXISTS effect_rate_limit_reservations (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   idempotency_key TEXT NOT NULL CHECK (trim(idempotency_key) != ''),
                   approval_digest TEXT NOT NULL CHECK (length(approval_digest) = 64),
                   scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
                   rule_id TEXT NOT NULL CHECK (trim(rule_id) != ''),
                   window_started_at TEXT NOT NULL,
                   window_ends_at TEXT NOT NULL,
                   reserved_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, effect_id),
                   UNIQUE (project_id, idempotency_key),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, scope_digest, window_started_at)
                     REFERENCES effect_rate_limit_buckets(
                       project_id, scope_digest, window_started_at
                     ) ON DELETE RESTRICT,
                   CHECK (window_ends_at > window_started_at),
                   CHECK (reserved_at >= window_started_at AND reserved_at < window_ends_at)
                 );
                 CREATE INDEX IF NOT EXISTS effect_rate_limit_reservation_scope_idx
                   ON effect_rate_limit_reservations(
                     tenant_id, project_id, scope_digest, window_started_at
                   );
                 CREATE TABLE IF NOT EXISTS effect_rate_limit_decisions (
                   decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   approval_digest TEXT NOT NULL CHECK (length(approval_digest) = 64),
                   scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
                   rule_id TEXT NOT NULL CHECK (trim(rule_id) != ''),
                   decision TEXT NOT NULL CHECK (decision IN ('reserved', 'denied')),
                   consumed_before INTEGER NOT NULL CHECK (consumed_before >= 0),
                   consumed_after INTEGER NOT NULL CHECK (consumed_after >= 0),
                   window_started_at TEXT NOT NULL,
                   window_ends_at TEXT NOT NULL,
                   decided_at TEXT NOT NULL,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (window_ends_at > window_started_at),
                   CHECK (decided_at >= window_started_at AND decided_at < window_ends_at),
                   CHECK (
                     (decision = 'reserved' AND consumed_after = consumed_before + 1)
                     OR (decision = 'denied' AND consumed_after = consumed_before)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS effect_rate_limit_decision_scope_idx
                   ON effect_rate_limit_decisions(
                     tenant_id, project_id, scope_digest, window_started_at, decision_id
                   );",
            )?;
            record_migration(&transaction, 24)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 25 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS effect_reconciliation_heads (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   policy_version TEXT NOT NULL CHECK (trim(policy_version) != ''),
                   policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 64),
                   max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
                   retry_delay_seconds INTEGER NOT NULL CHECK (
                     retry_delay_seconds BETWEEN 1 AND 2592000
                   ),
                   status TEXT NOT NULL CHECK (status IN (
                     'leased', 'retry_wait', 'receipt_found', 'not_executed',
                     'provider_rejected', 'dead_letter'
                   )),
                   attempts INTEGER NOT NULL CHECK (attempts > 0 AND attempts <= max_attempts),
                   lease_owner TEXT,
                   lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
                   lease_expires_at TEXT,
                   retry_at TEXT,
                   terminal_reason TEXT,
                   evidence_digest TEXT CHECK (
                     evidence_digest IS NULL OR length(evidence_digest) = 64
                   ),
                   observation_json TEXT,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, effect_id),
                   FOREIGN KEY (project_id, effect_id)
                     REFERENCES effect_idempotency(project_id, effect_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at),
                   CHECK (
                     (status = 'leased' AND lease_owner IS NOT NULL
                       AND trim(lease_owner) != '' AND lease_expires_at IS NOT NULL
                       AND retry_at IS NULL AND terminal_reason IS NULL
                       AND evidence_digest IS NULL AND observation_json IS NULL)
                     OR (status = 'retry_wait' AND lease_owner IS NULL
                       AND lease_expires_at IS NULL AND retry_at IS NOT NULL
                       AND terminal_reason IS NOT NULL AND trim(terminal_reason) != ''
                       AND evidence_digest IS NOT NULL AND observation_json IS NOT NULL)
                     OR (status = 'receipt_found' AND lease_owner IS NULL
                       AND lease_expires_at IS NULL AND retry_at IS NULL
                       AND terminal_reason IS NULL AND evidence_digest IS NOT NULL
                       AND observation_json IS NOT NULL)
                     OR (status IN ('not_executed', 'provider_rejected', 'dead_letter')
                       AND lease_owner IS NULL AND lease_expires_at IS NULL
                       AND retry_at IS NULL AND terminal_reason IS NOT NULL
                       AND trim(terminal_reason) != '' AND evidence_digest IS NOT NULL
                       AND observation_json IS NOT NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS effect_reconciliation_claim_idx
                   ON effect_reconciliation_heads(
                     tenant_id, project_id, status, retry_at, lease_expires_at
                   );
                 CREATE TABLE IF NOT EXISTS effect_reconciliation_attempts (
                   attempt_id TEXT PRIMARY KEY,
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   effect_id TEXT NOT NULL,
                   attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 64),
                   status TEXT NOT NULL CHECK (status IN (
                     'leased', 'retry_wait', 'receipt_found', 'not_executed',
                     'provider_rejected', 'dead_letter'
                   )),
                   lease_owner TEXT NOT NULL CHECK (trim(lease_owner) != ''),
                   lease_expires_at TEXT NOT NULL,
                   terminal_reason TEXT,
                   evidence_digest TEXT CHECK (
                     evidence_digest IS NULL OR length(evidence_digest) = 64
                   ),
                   observed_at TEXT,
                   observation_json TEXT,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   UNIQUE (project_id, effect_id, attempt_no),
                   UNIQUE (project_id, effect_id, generation),
                   FOREIGN KEY (project_id, effect_id)
                     REFERENCES effect_idempotency(project_id, effect_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at AND lease_expires_at > created_at),
                   CHECK (
                     (status = 'leased' AND terminal_reason IS NULL
                       AND evidence_digest IS NULL AND observed_at IS NULL
                       AND observation_json IS NULL)
                     OR (status != 'leased' AND evidence_digest IS NOT NULL
                       AND observed_at IS NOT NULL AND observation_json IS NOT NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS effect_reconciliation_attempt_idx
                   ON effect_reconciliation_attempts(
                     tenant_id, project_id, effect_id, generation
                   );",
            )?;
            record_migration(&transaction, 25)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 26 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS context_working_sets (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, workspace_id),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at)
                 );
                 CREATE TABLE IF NOT EXISTS context_working_items (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   working_set_id TEXT NOT NULL,
                   item_key TEXT NOT NULL CHECK (trim(item_key) != ''),
                   item_kind TEXT NOT NULL CHECK (item_kind IN (
                     'conversation_tail', 'tool_result', 'truth_reference',
                     'evidence_reference', 'work_product_reference',
                     'effect_reference', 'artifact_reference'
                   )),
                   storage_ref TEXT NOT NULL CHECK (trim(storage_ref) != ''),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   byte_len INTEGER NOT NULL CHECK (byte_len > 0),
                   classification TEXT NOT NULL CHECK (classification IN (
                     'public', 'business', 'redacted_personal'
                   )),
                   provenance_digest TEXT NOT NULL CHECK (length(provenance_digest) = 64),
                   expires_at TEXT,
                   created_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, working_set_id, item_key),
                   FOREIGN KEY (project_id, working_set_id)
                     REFERENCES context_working_sets(project_id, id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS context_continuation_ledgers (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, workspace_id),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at)
                 );
                 CREATE TABLE IF NOT EXISTS context_continuation_entries (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   ledger_id TEXT NOT NULL,
                   sequence INTEGER NOT NULL CHECK (sequence > 0),
                   mission_revision INTEGER NOT NULL CHECK (mission_revision > 0),
                   entry_kind TEXT NOT NULL CHECK (entry_kind IN (
                     'decision', 'blocker', 'next_action', 'user_correction',
                     'checkpoint_transition', 'approval_pending',
                     'effect_uncertain', 'human_handoff'
                   )),
                   subject_id TEXT NOT NULL CHECK (trim(subject_id) != ''),
                   payload_ref TEXT NOT NULL CHECK (trim(payload_ref) != ''),
                   payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
                   recorded_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, ledger_id, sequence),
                   FOREIGN KEY (project_id, ledger_id)
                     REFERENCES context_continuation_ledgers(project_id, id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS context_compaction_records (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   ordinal INTEGER NOT NULL CHECK (ordinal > 0),
                   source_first_sequence INTEGER NOT NULL CHECK (source_first_sequence > 0),
                   source_last_sequence INTEGER NOT NULL CHECK (
                     source_last_sequence >= source_first_sequence
                   ),
                   retained_tail_start INTEGER NOT NULL CHECK (
                     retained_tail_start >= source_first_sequence
                     AND retained_tail_start <= source_last_sequence + 1
                   ),
                   source_trace_digest TEXT NOT NULL CHECK (length(source_trace_digest) = 64),
                   summary_digest TEXT NOT NULL CHECK (length(summary_digest) = 64),
                   invariant_digest TEXT NOT NULL CHECK (length(invariant_digest) = 64),
                   created_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, workspace_id, ordinal),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS context_checkpoints (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   ordinal INTEGER NOT NULL CHECK (ordinal > 0),
                   previous_checkpoint_id TEXT,
                   mission_revision INTEGER NOT NULL CHECK (mission_revision > 0),
                   working_set_id TEXT NOT NULL,
                   working_set_revision INTEGER NOT NULL CHECK (working_set_revision > 0),
                   continuation_ledger_id TEXT NOT NULL,
                   continuation_ledger_revision INTEGER NOT NULL CHECK (
                     continuation_ledger_revision > 0
                   ),
                   compaction_record_id TEXT NOT NULL,
                   compaction_ordinal INTEGER NOT NULL CHECK (compaction_ordinal > 0),
                   invariant_digest TEXT NOT NULL CHECK (length(invariant_digest) = 64),
                   worker_graph_digest TEXT NOT NULL CHECK (length(worker_graph_digest) = 64),
                   resume_cursor_digest TEXT NOT NULL CHECK (length(resume_cursor_digest) = 64),
                   trace_tail_sequence INTEGER NOT NULL CHECK (trace_tail_sequence >= 0),
                   created_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, workspace_id, ordinal),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, working_set_id)
                     REFERENCES context_working_sets(project_id, id),
                   FOREIGN KEY (project_id, continuation_ledger_id)
                     REFERENCES context_continuation_ledgers(project_id, id),
                   FOREIGN KEY (project_id, compaction_record_id)
                     REFERENCES context_compaction_records(project_id, id),
                   FOREIGN KEY (project_id, previous_checkpoint_id)
                     REFERENCES context_checkpoints(project_id, id),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS context_working_expiry_idx
                   ON context_working_items(project_id, working_set_id, expires_at);
                 CREATE INDEX IF NOT EXISTS context_continuation_replay_idx
                   ON context_continuation_entries(project_id, ledger_id, sequence);
                 CREATE INDEX IF NOT EXISTS context_compaction_replay_idx
                   ON context_compaction_records(project_id, workspace_id, ordinal);
                 CREATE INDEX IF NOT EXISTS context_checkpoint_resume_idx
                   ON context_checkpoints(project_id, workspace_id, ordinal);",
            )?;
            record_migration(&transaction, 26)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 27 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS context_worker_handles (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   branch_id TEXT NOT NULL,
                   capsule_id TEXT NOT NULL,
                   lease_id TEXT NOT NULL,
                   worker_id TEXT NOT NULL,
                   parent_worker_id TEXT,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   attachment_epoch INTEGER NOT NULL CHECK (attachment_epoch > 0),
                   status TEXT NOT NULL CHECK (status IN (
                     'attached', 'detached', 'completed', 'failed', 'cancelled'
                   )),
                   cursor INTEGER NOT NULL CHECK (cursor >= 0),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, workspace_id, worker_id),
                   UNIQUE (project_id, capsule_id),
                   UNIQUE (project_id, lease_id),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, branch_id)
                     REFERENCES context_branches(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, capsule_id)
                     REFERENCES context_capsules(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, lease_id)
                     REFERENCES worker_leases(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at)
                 );
                 CREATE TABLE IF NOT EXISTS context_worker_mailboxes (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   worker_id TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   max_pending INTEGER NOT NULL CHECK (max_pending BETWEEN 1 AND 1024),
                   next_sequence INTEGER NOT NULL CHECK (next_sequence > 0),
                   acknowledged_cursor INTEGER NOT NULL CHECK (acknowledged_cursor >= 0),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, workspace_id, worker_id),
                   FOREIGN KEY (project_id, workspace_id, worker_id)
                     REFERENCES context_worker_handles(project_id, workspace_id, worker_id)
                       ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at)
                 );
                 CREATE TABLE IF NOT EXISTS context_worker_messages (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   mailbox_id TEXT NOT NULL,
                   message_id TEXT NOT NULL,
                   sequence INTEGER NOT NULL CHECK (sequence > 0),
                   sender_worker_id TEXT,
                   target_worker_id TEXT NOT NULL,
                   message_kind TEXT NOT NULL CHECK (message_kind IN (
                     'data', 'steer', 'follow_up', 'completion', 'redirect'
                   )),
                   status TEXT NOT NULL CHECK (status IN (
                     'pending', 'in_flight', 'acknowledged', 'dead_letter'
                   )),
                   claim_epoch INTEGER CHECK (claim_epoch IS NULL OR claim_epoch > 0),
                   payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
                   result_digest TEXT CHECK (
                     result_digest IS NULL OR length(result_digest) = 64
                   ),
                   enqueued_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, mailbox_id, message_id),
                   UNIQUE (project_id, mailbox_id, sequence),
                   FOREIGN KEY (project_id, mailbox_id)
                     REFERENCES context_worker_mailboxes(project_id, id) ON DELETE CASCADE,
                   CHECK (updated_at >= enqueued_at)
                 );
                 CREATE TABLE IF NOT EXISTS context_branch_merges (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   source_branch_id TEXT NOT NULL,
                   source_branch_revision INTEGER NOT NULL CHECK (source_branch_revision > 0),
                   target_branch_id TEXT NOT NULL,
                   target_branch_revision INTEGER NOT NULL CHECK (target_branch_revision > 0),
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   capsule_id TEXT NOT NULL,
                   capsule_revision INTEGER NOT NULL CHECK (capsule_revision > 0),
                   result_digest TEXT NOT NULL CHECK (length(result_digest) = 64),
                   mission_revision INTEGER NOT NULL CHECK (mission_revision > 0),
                   disposition TEXT NOT NULL CHECK (disposition IN ('applied', 'rejected')),
                   conflict_digest TEXT CHECK (
                     conflict_digest IS NULL OR length(conflict_digest) = 64
                   ),
                   recorded_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, source_branch_id),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, source_branch_id)
                     REFERENCES context_branches(project_id, id),
                   FOREIGN KEY (project_id, target_branch_id)
                     REFERENCES context_branches(project_id, id),
                   FOREIGN KEY (project_id, capsule_id)
                     REFERENCES context_capsules(project_id, id),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (
                     (disposition = 'applied' AND conflict_digest IS NULL)
                     OR (disposition = 'rejected' AND conflict_digest IS NOT NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS context_worker_handle_status_idx
                   ON context_worker_handles(
                     tenant_id, project_id, workspace_id, status, attachment_epoch
                   );
                 CREATE INDEX IF NOT EXISTS context_worker_message_claim_idx
                   ON context_worker_messages(
                     tenant_id, project_id, mailbox_id, status, sequence
                   );
                 CREATE INDEX IF NOT EXISTS context_branch_merge_idx
                   ON context_branch_merges(
                     tenant_id, project_id, workspace_id, target_branch_id, recorded_at
                   );",
            )?;
            record_migration(&transaction, 27)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 28 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS runtime_recovery_attempts (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   worker_id TEXT NOT NULL,
                   worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
                   source_attachment_epoch INTEGER NOT NULL CHECK (source_attachment_epoch > 0),
                   target_attachment_epoch INTEGER NOT NULL CHECK (
                     target_attachment_epoch = source_attachment_epoch + 1
                   ),
                   source_mapping_digest TEXT NOT NULL CHECK (length(source_mapping_digest) = 64),
                   checkpoint_id TEXT NOT NULL,
                   checkpoint_digest TEXT NOT NULL CHECK (length(checkpoint_digest) = 64),
                   runtime_config_digest TEXT NOT NULL CHECK (length(runtime_config_digest) = 64),
                   initial_strategy TEXT NOT NULL CHECK (
                     initial_strategy IN ('start_new', 'resume_existing')
                   ),
                   requested_thread_id_digest TEXT CHECK (
                     requested_thread_id_digest IS NULL
                     OR length(requested_thread_id_digest) = 64
                   ),
                   max_process_attempts INTEGER NOT NULL CHECK (
                     max_process_attempts BETWEEN 1 AND 16
                   ),
                   process_attempt INTEGER NOT NULL CHECK (
                     process_attempt BETWEEN 1 AND max_process_attempts
                   ),
                   health_digest TEXT CHECK (
                     health_digest IS NULL OR length(health_digest) = 64
                   ),
                   runtime_instance_digest TEXT CHECK (
                     runtime_instance_digest IS NULL OR length(runtime_instance_digest) = 64
                   ),
                   runtime_thread_id_digest TEXT CHECK (
                     runtime_thread_id_digest IS NULL OR length(runtime_thread_id_digest) = 64
                   ),
                   runtime_mapping_digest TEXT CHECK (
                     runtime_mapping_digest IS NULL OR length(runtime_mapping_digest) = 64
                   ),
                   failure_count INTEGER NOT NULL CHECK (
                     failure_count >= 0 AND failure_count <= max_process_attempts
                   ),
                   status TEXT NOT NULL CHECK (status IN (
                     'prepared', 'spawned', 'healthy', 'thread_bound', 'attached', 'failed'
                   )),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id, workspace_id, worker_id)
                     REFERENCES context_worker_handles(project_id, workspace_id, worker_id)
                       ON DELETE CASCADE,
                   FOREIGN KEY (project_id, checkpoint_id)
                     REFERENCES context_checkpoints(project_id, id),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at),
                   CHECK (
                     (initial_strategy = 'start_new' AND requested_thread_id_digest IS NULL)
                     OR (initial_strategy = 'resume_existing'
                       AND requested_thread_id_digest IS NOT NULL)
                   ),
                   CHECK (
                     (status IN ('prepared', 'failed')
                       AND health_digest IS NULL
                       AND runtime_instance_digest IS NULL
                       AND runtime_thread_id_digest IS NULL
                       AND runtime_mapping_digest IS NULL)
                     OR (status = 'spawned'
                       AND health_digest IS NULL
                       AND runtime_instance_digest IS NOT NULL
                       AND runtime_thread_id_digest IS NULL
                       AND runtime_mapping_digest IS NULL)
                     OR (status = 'healthy'
                       AND health_digest IS NOT NULL
                       AND runtime_instance_digest IS NOT NULL
                       AND runtime_thread_id_digest IS NULL
                       AND runtime_mapping_digest IS NULL)
                     OR (status IN ('thread_bound', 'attached')
                       AND health_digest IS NOT NULL
                       AND runtime_instance_digest IS NOT NULL
                       AND runtime_thread_id_digest IS NOT NULL
                       AND runtime_mapping_digest IS NOT NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS runtime_recovery_worker_idx
                   ON runtime_recovery_attempts(
                     tenant_id, project_id, workspace_id, worker_id, status, updated_at
                   );",
            )?;
            record_migration(&transaction, 28)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 29 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS context_assembly_manifests (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   capsule_id TEXT NOT NULL,
                   capsule_revision INTEGER NOT NULL CHECK (capsule_revision > 0),
                   branch_id TEXT NOT NULL,
                   branch_revision INTEGER NOT NULL CHECK (branch_revision > 0),
                   worker_id TEXT NOT NULL,
                   worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
                   worker_lease_id TEXT NOT NULL,
                   worker_lease_revision INTEGER NOT NULL CHECK (worker_lease_revision > 0),
                   foundation_sync_version INTEGER NOT NULL CHECK (foundation_sync_version > 0),
                   checkpoint_id TEXT NOT NULL,
                   checkpoint_digest TEXT NOT NULL CHECK (length(checkpoint_digest) = 64),
                   capsule_authority_digest TEXT NOT NULL CHECK (
                     length(capsule_authority_digest) = 64
                   ),
                   policy_version INTEGER NOT NULL CHECK (policy_version > 0),
                   input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
                   manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64),
                   frame_count INTEGER NOT NULL CHECK (frame_count > 0),
                   gap_count INTEGER NOT NULL CHECK (gap_count >= 0),
                   prompt_digest TEXT CHECK (
                     prompt_digest IS NULL OR length(prompt_digest) = 64
                   ),
                   prompt_byte_count INTEGER NOT NULL CHECK (prompt_byte_count >= 0),
                   prompt_token_count INTEGER NOT NULL CHECK (prompt_token_count >= 0),
                   status TEXT NOT NULL CHECK (
                     status IN ('ready', 'blocked_missing_required', 'blocked_budget')
                   ),
                   revision INTEGER NOT NULL CHECK (revision = 1),
                   created_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES context_workspaces(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, capsule_id)
                     REFERENCES context_capsules(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, branch_id)
                     REFERENCES context_branches(project_id, id),
                   FOREIGN KEY (project_id, worker_lease_id)
                     REFERENCES worker_leases(project_id, id),
                   FOREIGN KEY (project_id, checkpoint_id)
                     REFERENCES context_checkpoints(project_id, id),
                   CHECK (
                     (status = 'ready' AND prompt_digest IS NOT NULL
                       AND prompt_byte_count > 0 AND prompt_token_count > 0)
                     OR (status IN ('blocked_missing_required', 'blocked_budget')
                       AND prompt_digest IS NULL
                       AND prompt_byte_count = 0 AND prompt_token_count = 0)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS context_assembly_scope_idx
                   ON context_assembly_manifests(
                     tenant_id, project_id, mission_id, workspace_id, capsule_id, created_at
                   );",
            )?;
            record_migration(&transaction, 29)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 30 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS runtime_turn_attempts (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   capsule_id TEXT NOT NULL,
                   capsule_revision INTEGER NOT NULL CHECK (capsule_revision > 0),
                   capsule_authority_digest TEXT NOT NULL CHECK (
                     length(capsule_authority_digest) = 64
                   ),
                   branch_id TEXT NOT NULL,
                   branch_revision INTEGER NOT NULL CHECK (branch_revision > 0),
                   worker_id TEXT NOT NULL,
                   worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
                   worker_lease_id TEXT NOT NULL,
                   worker_lease_revision INTEGER NOT NULL CHECK (worker_lease_revision > 0),
                   attachment_epoch INTEGER NOT NULL CHECK (attachment_epoch > 0),
                   assembly_id TEXT NOT NULL,
                   assembly_revision INTEGER NOT NULL CHECK (assembly_revision = 1),
                   assembly_manifest_digest TEXT NOT NULL CHECK (
                     length(assembly_manifest_digest) = 64
                   ),
                   assembly_input_digest TEXT NOT NULL CHECK (
                     length(assembly_input_digest) = 64
                   ),
                   prompt_digest TEXT NOT NULL CHECK (length(prompt_digest) = 64),
                   checkpoint_id TEXT NOT NULL,
                   checkpoint_digest TEXT NOT NULL CHECK (length(checkpoint_digest) = 64),
                   recovery_id TEXT NOT NULL,
                   recovery_revision INTEGER NOT NULL CHECK (recovery_revision > 0),
                   runtime_instance_digest TEXT NOT NULL CHECK (
                     length(runtime_instance_digest) = 64
                   ),
                   runtime_mapping_digest TEXT NOT NULL CHECK (
                     length(runtime_mapping_digest) = 64
                   ),
                   runtime_thread_id_digest TEXT NOT NULL CHECK (
                     length(runtime_thread_id_digest) = 64
                   ),
                   runtime_turn_id_digest TEXT CHECK (
                     runtime_turn_id_digest IS NULL OR length(runtime_turn_id_digest) = 64
                   ),
                   dispatch_request_digest TEXT CHECK (
                     dispatch_request_digest IS NULL OR length(dispatch_request_digest) = 64
                   ),
                   dispatch_response_digest TEXT CHECK (
                     dispatch_response_digest IS NULL OR length(dispatch_response_digest) = 64
                   ),
                   pending_approval_request_digest TEXT CHECK (
                     pending_approval_request_digest IS NULL
                     OR length(pending_approval_request_digest) = 64
                   ),
                   approval_decision_digest TEXT CHECK (
                     approval_decision_digest IS NULL OR length(approval_decision_digest) = 64
                   ),
                   interrupt_request_digest TEXT CHECK (
                     interrupt_request_digest IS NULL OR length(interrupt_request_digest) = 64
                   ),
                   failure_count INTEGER NOT NULL CHECK (failure_count BETWEEN 0 AND 32),
                   evidence_count INTEGER NOT NULL CHECK (evidence_count BETWEEN 1 AND 4096),
                   status TEXT NOT NULL CHECK (status IN (
                     'prepared', 'dispatching', 'running', 'waiting_local_approval',
                     'approval_responding', 'interrupt_requested', 'completed',
                     'interrupted', 'failed', 'uncertain'
                   )),
                   revision INTEGER NOT NULL CHECK (revision = evidence_count),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, workspace_id, worker_id)
                     REFERENCES context_worker_handles(project_id, workspace_id, worker_id)
                       ON DELETE CASCADE,
                   FOREIGN KEY (project_id, capsule_id)
                     REFERENCES context_capsules(project_id, id),
                   FOREIGN KEY (project_id, branch_id)
                     REFERENCES context_branches(project_id, id),
                   FOREIGN KEY (project_id, worker_lease_id)
                     REFERENCES worker_leases(project_id, id),
                   FOREIGN KEY (project_id, assembly_id)
                     REFERENCES context_assembly_manifests(project_id, id),
                   FOREIGN KEY (project_id, checkpoint_id)
                     REFERENCES context_checkpoints(project_id, id),
                   FOREIGN KEY (project_id, recovery_id)
                     REFERENCES runtime_recovery_attempts(project_id, id),
                   CHECK (updated_at >= created_at),
                   CHECK (
                     (status IN ('prepared', 'dispatching')
                       AND runtime_turn_id_digest IS NULL
                       AND dispatch_request_digest IS NULL
                       AND dispatch_response_digest IS NULL)
                     OR status IN ('failed', 'uncertain')
                     OR (status IN (
                         'running', 'waiting_local_approval', 'approval_responding',
                         'interrupt_requested', 'completed', 'interrupted'
                       )
                       AND runtime_turn_id_digest IS NOT NULL
                       AND dispatch_request_digest IS NOT NULL
                       AND dispatch_response_digest IS NOT NULL)
                   )
                 );
                 CREATE TABLE IF NOT EXISTS runtime_turn_evidence (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   runtime_turn_attempt_id TEXT NOT NULL,
                   sequence INTEGER NOT NULL CHECK (sequence > 0),
                   evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
                     'prepared', 'dispatch_started', 'dispatch_accepted', 'turn_started',
                     'item_started', 'item_completed', 'diagnostic',
                     'local_approval_requested', 'local_approval_response_started',
                     'local_approval_response_sent', 'interrupt_requested',
                     'interrupt_accepted', 'completed', 'interrupted', 'failed', 'uncertain'
                   )),
                   evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                   resulting_status TEXT NOT NULL CHECK (resulting_status IN (
                     'prepared', 'dispatching', 'running', 'waiting_local_approval',
                     'approval_responding', 'interrupt_requested', 'completed',
                     'interrupted', 'failed', 'uncertain'
                   )),
                   observed_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, runtime_turn_attempt_id, sequence),
                   FOREIGN KEY (project_id, runtime_turn_attempt_id)
                     REFERENCES runtime_turn_attempts(project_id, id) ON DELETE CASCADE
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS runtime_turn_active_worker_idx
                   ON runtime_turn_attempts(project_id, workspace_id, worker_id)
                   WHERE status IN (
                     'prepared', 'dispatching', 'running', 'waiting_local_approval',
                     'approval_responding', 'interrupt_requested', 'uncertain'
                   );
                 CREATE INDEX IF NOT EXISTS runtime_turn_scope_idx
                   ON runtime_turn_attempts(
                     tenant_id, project_id, mission_id, workspace_id, assembly_id, updated_at
                   );",
            )?;
            record_migration(&transaction, 30)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 31 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS context_assembly_tokenizer_profiles (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   assembly_id TEXT NOT NULL,
                   profile_schema_version INTEGER NOT NULL CHECK (
                     profile_schema_version > 0
                   ),
                   profile_digest TEXT NOT NULL CHECK (length(profile_digest) = 64),
                   provider_digest TEXT NOT NULL CHECK (length(provider_digest) = 64),
                   model_digest TEXT NOT NULL CHECK (length(model_digest) = 64),
                   model_revision_digest TEXT NOT NULL CHECK (
                     length(model_revision_digest) = 64
                   ),
                   artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64),
                   add_special_tokens INTEGER NOT NULL CHECK (add_special_tokens IN (0, 1)),
                   request_overhead_tokens INTEGER NOT NULL CHECK (
                     request_overhead_tokens >= 0
                   ),
                   max_input_bytes INTEGER NOT NULL CHECK (max_input_bytes > 0),
                   PRIMARY KEY (project_id, assembly_id),
                   FOREIGN KEY (project_id, assembly_id)
                     REFERENCES context_assembly_manifests(project_id, id) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS context_assembly_tokenizer_scope_idx
                   ON context_assembly_tokenizer_profiles(
                     tenant_id, project_id, artifact_digest, profile_digest
                   );",
            )?;
            context_assembly_store::backfill_context_assembly_tokenizer_profiles(&transaction)?;
            record_migration(&transaction, 31)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 32 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS browser_profiles (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   source TEXT NOT NULL CHECK (source IN ('managed', 'imported_copy')),
                   status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
                   credential_reference_digest TEXT NOT NULL CHECK (
                     length(credential_reference_digest) = 64
                   ),
                   provider_digest TEXT NOT NULL CHECK (length(provider_digest) = 64),
                   account_id_digest TEXT NOT NULL CHECK (length(account_id_digest) = 64),
                   identity_digest TEXT NOT NULL CHECK (length(identity_digest) = 64),
                   probe_digest TEXT NOT NULL CHECK (length(probe_digest) = 64),
                   identity_observed_at TEXT NOT NULL,
                   revocation_evidence_digest TEXT CHECK (
                     revocation_evidence_digest IS NULL
                     OR length(revocation_evidence_digest) = 64
                   ),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at),
                   CHECK (
                     (status = 'active' AND revocation_evidence_digest IS NULL)
                     OR (status = 'revoked' AND revocation_evidence_digest IS NOT NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS browser_profile_scope_idx
                   ON browser_profiles(
                     tenant_id, project_id, status, provider_digest, account_id_digest
                   );
                 CREATE TABLE IF NOT EXISTS browser_workspaces (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   profile_id TEXT NOT NULL,
                   expected_identity_digest TEXT NOT NULL CHECK (
                     length(expected_identity_digest) = 64
                   ),
                   control_state TEXT NOT NULL CHECK (control_state IN (
                     'agent_controlled', 'user_controlled', 'paused_agent', 'paused_user',
                     'completed', 'kept_for_user', 'closed'
                   )),
                   lease_id_digest TEXT NOT NULL CHECK (length(lease_id_digest) = 64),
                   lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
                   agent_lease_expires_at TEXT,
                   active_tab_id_digest TEXT NOT NULL CHECK (
                     length(active_tab_id_digest) = 64
                   ),
                   tab_count INTEGER NOT NULL CHECK (tab_count > 0),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, profile_id)
                     REFERENCES browser_profiles(project_id, id),
                   CHECK (updated_at >= created_at),
                   CHECK (
                     (control_state = 'agent_controlled' AND agent_lease_expires_at IS NOT NULL)
                     OR (control_state != 'agent_controlled' AND agent_lease_expires_at IS NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS browser_workspace_scope_idx
                   ON browser_workspaces(
                     tenant_id, project_id, mission_id, profile_id, control_state, updated_at
                   );
                 CREATE TABLE IF NOT EXISTS browser_workspace_tabs (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   tab_id TEXT NOT NULL,
                   tab_id_digest TEXT NOT NULL CHECK (length(tab_id_digest) = 64),
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   is_active INTEGER NOT NULL CHECK (is_active IN (0, 1)),
                   PRIMARY KEY (project_id, workspace_id, tab_id),
                   UNIQUE (project_id, workspace_id, ordinal),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES browser_workspaces(project_id, id) ON DELETE CASCADE
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS browser_workspace_one_active_tab_idx
                   ON browser_workspace_tabs(project_id, workspace_id)
                   WHERE is_active = 1;
                 CREATE TABLE IF NOT EXISTS browser_control_transitions (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   generation INTEGER NOT NULL CHECK (generation > 0),
                   lease_id_digest TEXT NOT NULL CHECK (length(lease_id_digest) = 64),
                   control_state TEXT NOT NULL CHECK (control_state IN (
                     'agent_controlled', 'user_controlled', 'paused_agent', 'paused_user',
                     'completed', 'kept_for_user', 'closed'
                   )),
                   evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                   agent_lease_expires_at TEXT,
                   occurred_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, workspace_id, generation),
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES browser_workspaces(project_id, id) ON DELETE CASCADE,
                   CHECK (
                     (control_state = 'agent_controlled' AND agent_lease_expires_at IS NOT NULL)
                     OR (control_state != 'agent_controlled' AND agent_lease_expires_at IS NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS browser_control_transition_scope_idx
                   ON browser_control_transitions(
                     tenant_id, project_id, workspace_id, occurred_at
                   );",
            )?;
            record_migration(&transaction, 32)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 33 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS browser_file_grants (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   lease_id_digest TEXT NOT NULL CHECK (length(lease_id_digest) = 64),
                   lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   byte_count INTEGER NOT NULL CHECK (byte_count > 0),
                   detected_type TEXT NOT NULL CHECK (detected_type IN (
                     'pdf', 'png', 'jpeg', 'gif', 'webp', 'mp4', 'json', 'utf8_text'
                   )),
                   scan_evidence_digest TEXT NOT NULL CHECK (
                     length(scan_evidence_digest) = 64
                   ),
                   authorization_evidence_digest TEXT NOT NULL CHECK (
                     length(authorization_evidence_digest) = 64
                   ),
                   upload_payload_digest TEXT NOT NULL CHECK (
                     length(upload_payload_digest) = 64
                   ),
                   state TEXT NOT NULL CHECK (state IN (
                     'prepared', 'leased', 'consumed', 'revoked', 'expired'
                   )),
                   claim_id TEXT,
                   terminal_evidence_digest TEXT CHECK (
                     terminal_evidence_digest IS NULL
                     OR length(terminal_evidence_digest) = 64
                   ),
                   expires_at TEXT NOT NULL,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   FOREIGN KEY (project_id, workspace_id)
                     REFERENCES browser_workspaces(project_id, id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at),
                   CHECK (expires_at > created_at),
                   CHECK (
                     (state = 'prepared' AND claim_id IS NULL
                       AND terminal_evidence_digest IS NULL)
                     OR (state = 'leased' AND claim_id IS NOT NULL
                       AND terminal_evidence_digest IS NULL)
                     OR (state = 'consumed' AND claim_id IS NOT NULL
                       AND terminal_evidence_digest IS NOT NULL)
                     OR (state IN ('revoked', 'expired')
                       AND terminal_evidence_digest IS NOT NULL)
                   )
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS browser_file_claim_unique_idx
                   ON browser_file_grants(project_id, claim_id)
                   WHERE claim_id IS NOT NULL;
                 CREATE INDEX IF NOT EXISTS browser_file_grant_scope_idx
                   ON browser_file_grants(
                     tenant_id, project_id, mission_id, workspace_id, state, expires_at
                   );",
            )?;
            record_migration(&transaction, 33)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 34 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS browser_recipe_trust_keys (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   key_id TEXT NOT NULL,
                   key_id_digest TEXT NOT NULL CHECK (length(key_id_digest) = 64),
                   purpose TEXT NOT NULL CHECK (purpose IN (
                     'candidate_publisher', 'production_release'
                   )),
                   public_key_digest TEXT NOT NULL CHECK (length(public_key_digest) = 64),
                   installation_evidence_digest TEXT NOT NULL CHECK (
                     length(installation_evidence_digest) = 64
                   ),
                   revocation_evidence_digest TEXT CHECK (
                     revocation_evidence_digest IS NULL
                     OR length(revocation_evidence_digest) = 64
                   ),
                   valid_from TEXT NOT NULL,
                   valid_until TEXT NOT NULL,
                   revoked_at TEXT,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   installed_at TEXT NOT NULL,
                   record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, key_id),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   CHECK (valid_until > valid_from),
                   CHECK (installed_at >= valid_from AND installed_at < valid_until),
                   CHECK (
                     (revoked_at IS NULL AND revocation_evidence_digest IS NULL)
                     OR (revoked_at IS NOT NULL AND revocation_evidence_digest IS NOT NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS browser_recipe_trust_scope_idx
                   ON browser_recipe_trust_keys(
                     tenant_id, project_id, purpose, revoked_at, valid_until
                   );
                 CREATE TABLE IF NOT EXISTS browser_recipe_candidates (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   recipe_id TEXT NOT NULL,
                   recipe_id_digest TEXT NOT NULL CHECK (length(recipe_id_digest) = 64),
                   version INTEGER NOT NULL CHECK (version > 0),
                   candidate_digest TEXT NOT NULL CHECK (length(candidate_digest) = 64),
                   provider_digest TEXT NOT NULL CHECK (length(provider_digest) = 64),
                   origin_digest TEXT NOT NULL CHECK (length(origin_digest) = 64),
                   capability_digest TEXT NOT NULL CHECK (length(capability_digest) = 64),
                   effect_class TEXT NOT NULL CHECK (effect_class IN (
                     'external_write', 'outreach', 'spend', 'payment'
                   )),
                   publisher_key_id_digest TEXT NOT NULL CHECK (
                     length(publisher_key_id_digest) = 64
                   ),
                   created_at TEXT NOT NULL,
                   expires_at TEXT NOT NULL,
                   record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, recipe_id, version),
                   UNIQUE (project_id, candidate_digest),
                   FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                   CHECK (expires_at > created_at)
                 );
                 CREATE INDEX IF NOT EXISTS browser_recipe_candidate_scope_idx
                   ON browser_recipe_candidates(
                     tenant_id, project_id, provider_digest, capability_digest, expires_at
                   );
                 CREATE TABLE IF NOT EXISTS browser_recipe_releases (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   recipe_id TEXT NOT NULL,
                   recipe_id_digest TEXT NOT NULL CHECK (length(recipe_id_digest) = 64),
                   version INTEGER NOT NULL CHECK (version > 0),
                   candidate_digest TEXT NOT NULL CHECK (length(candidate_digest) = 64),
                   release_digest TEXT NOT NULL CHECK (length(release_digest) = 64),
                   release_key_id_digest TEXT NOT NULL CHECK (
                     length(release_key_id_digest) = 64
                   ),
                   v1_result_digest TEXT NOT NULL CHECK (length(v1_result_digest) = 64),
                   v2_result_digest TEXT NOT NULL CHECK (length(v2_result_digest) = 64),
                   safety_suite_digest TEXT NOT NULL CHECK (
                     length(safety_suite_digest) = 64
                   ),
                   contamination_audit_digest TEXT NOT NULL CHECK (
                     length(contamination_audit_digest) = 64
                   ),
                   rollback_strategy_digest TEXT NOT NULL CHECK (
                     length(rollback_strategy_digest) = 64
                   ),
                   promotion_approval_digest TEXT NOT NULL CHECK (
                     length(promotion_approval_digest) = 64
                   ),
                   promoted_at TEXT NOT NULL,
                   expires_at TEXT NOT NULL,
                   record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, recipe_id, version),
                   UNIQUE (project_id, release_digest),
                   FOREIGN KEY (project_id, recipe_id, version)
                     REFERENCES browser_recipe_candidates(project_id, recipe_id, version)
                     ON DELETE CASCADE,
                   CHECK (expires_at > promoted_at)
                 );
                 CREATE INDEX IF NOT EXISTS browser_recipe_release_scope_idx
                   ON browser_recipe_releases(
                     tenant_id, project_id, release_key_id_digest, expires_at
                   );
                 CREATE TABLE IF NOT EXISTS browser_recipe_activations (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   recipe_id TEXT NOT NULL,
                   recipe_id_digest TEXT NOT NULL CHECK (length(recipe_id_digest) = 64),
                   version INTEGER NOT NULL CHECK (version > 0),
                   release_digest TEXT NOT NULL CHECK (length(release_digest) = 64),
                   previous_version INTEGER CHECK (previous_version > 0),
                   activation_evidence_digest TEXT NOT NULL CHECK (
                     length(activation_evidence_digest) = 64
                   ),
                   activated_at TEXT NOT NULL,
                   activation_digest TEXT NOT NULL CHECK (length(activation_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, recipe_id, version),
                   UNIQUE (project_id, activation_digest),
                   FOREIGN KEY (project_id, recipe_id, version)
                     REFERENCES browser_recipe_releases(project_id, recipe_id, version)
                     ON DELETE CASCADE,
                   CHECK (previous_version IS NULL OR previous_version < version)
                 );
                 CREATE INDEX IF NOT EXISTS browser_recipe_activation_scope_idx
                   ON browser_recipe_activations(
                     tenant_id, project_id, recipe_id_digest, activated_at
                   );
                 CREATE TABLE IF NOT EXISTS browser_recipe_heads (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   recipe_id TEXT NOT NULL,
                   recipe_id_digest TEXT NOT NULL CHECK (length(recipe_id_digest) = 64),
                   active_version INTEGER NOT NULL CHECK (active_version > 0),
                   activation_digest TEXT NOT NULL CHECK (length(activation_digest) = 64),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, recipe_id),
                   FOREIGN KEY (project_id, recipe_id, active_version)
                     REFERENCES browser_recipe_activations(project_id, recipe_id, version)
                 );
                 CREATE INDEX IF NOT EXISTS browser_recipe_head_scope_idx
                   ON browser_recipe_heads(tenant_id, project_id, recipe_id_digest);",
            )?;
            record_migration(&transaction, 34)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 35 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS project_key_secret_references (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   envelope_id TEXT NOT NULL,
                   key_version INTEGER NOT NULL CHECK (key_version > 0),
                   recipient_scope_digest TEXT NOT NULL CHECK (
                     length(recipient_scope_digest) = 64
                   ),
                   credential_id TEXT NOT NULL CHECK (length(credential_id) = 64),
                   record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, envelope_id),
                   UNIQUE (project_id, credential_id),
                   FOREIGN KEY (project_id, envelope_id)
                     REFERENCES project_key_envelopes(project_id, id) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS project_key_secret_reference_scope_idx
                   ON project_key_secret_references(
                     tenant_id, project_id, recipient_scope_digest, key_version
                   );",
            )?;
            record_migration(&transaction, 35)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 36 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS mission_definitions (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   manifest_id TEXT NOT NULL CHECK (
                     manifest_id GLOB 'VM-[0-9][0-9]'
                   ),
                   manifest_version INTEGER NOT NULL CHECK (manifest_version > 0),
                   catalog_digest TEXT NOT NULL CHECK (length(catalog_digest) = 64),
                   operating_mode TEXT NOT NULL CHECK (operating_mode IN (
                     'build_once', 'continuous_operator', 'campaign',
                     'continuous_relationship', 'one_off_decision'
                   )),
                   cycle INTEGER NOT NULL CHECK (cycle > 0),
                   PRIMARY KEY (mission_id, project_id),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS mission_definition_manifest_idx
                   ON mission_definitions(project_id, manifest_id, manifest_version);
                 CREATE TABLE IF NOT EXISTS mission_definition_capabilities (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   value TEXT NOT NULL CHECK (length(trim(value)) > 0),
                   PRIMARY KEY (mission_id, project_id, ordinal),
                   UNIQUE (mission_id, project_id, value),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES mission_definitions(mission_id, project_id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS mission_definition_artifacts (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   value TEXT NOT NULL CHECK (length(trim(value)) > 0),
                   PRIMARY KEY (mission_id, project_id, ordinal),
                   UNIQUE (mission_id, project_id, value),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES mission_definitions(mission_id, project_id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS mission_definition_oracles (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   value TEXT NOT NULL CHECK (length(trim(value)) > 0),
                   PRIMARY KEY (mission_id, project_id, ordinal),
                   UNIQUE (mission_id, project_id, value),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES mission_definitions(mission_id, project_id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS mission_checkpoints (
                   mission_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                   ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                   depends_on_json TEXT NOT NULL,
                   status TEXT NOT NULL CHECK (status IN (
                     'pending', 'ready', 'running', 'blocked', 'waiting_user',
                     'waiting_approval', 'verifying', 'completed', 'skipped'
                   )),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   attempt INTEGER NOT NULL CHECK (attempt >= 0),
                   started_at TEXT,
                   block_json TEXT,
                   completion_json TEXT,
                   PRIMARY KEY (mission_id, project_id, id),
                   UNIQUE (mission_id, project_id, ordinal),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES mission_definitions(mission_id, project_id) ON DELETE CASCADE,
                   CHECK (
                     (status IN ('pending', 'ready') AND attempt = 0 AND started_at IS NULL)
                     OR (status IN (
                       'running', 'blocked', 'waiting_user', 'waiting_approval',
                       'verifying', 'completed'
                     ) AND attempt > 0 AND started_at IS NOT NULL)
                     OR status = 'skipped'
                   ),
                   CHECK (
                     (status IN ('blocked', 'waiting_user', 'waiting_approval')
                       AND block_json IS NOT NULL)
                     OR (status NOT IN ('blocked', 'waiting_user', 'waiting_approval')
                       AND block_json IS NULL)
                   ),
                   CHECK (
                     (status = 'completed' AND completion_json IS NOT NULL)
                     OR (status != 'completed' AND completion_json IS NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS mission_checkpoint_state_idx
                   ON mission_checkpoints(project_id, mission_id, status, ordinal);",
            )?;
            record_migration(&transaction, 36)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 37 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS mission_conversations (
                   id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, mission_id),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS mission_conversation_messages (
                   id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   conversation_id TEXT NOT NULL,
                   sequence INTEGER NOT NULL CHECK (sequence > 0),
                   role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
                   kind TEXT NOT NULL CHECK (kind IN (
                     'goal', 'steering', 'correction', 'clarification',
                     'runtime_draft', 'system_notice'
                   )),
                   body TEXT NOT NULL CHECK (length(trim(body)) > 0),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   idempotency_key TEXT NOT NULL CHECK (
                     length(trim(idempotency_key)) > 0 AND length(idempotency_key) <= 512
                   ),
                   mission_revision INTEGER NOT NULL CHECK (mission_revision > 0),
                   checkpoint_id TEXT,
                   work_product_id TEXT,
                   recorded_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, conversation_id, id),
                   UNIQUE (project_id, conversation_id, sequence),
                   UNIQUE (project_id, conversation_id, idempotency_key),
                   FOREIGN KEY (project_id, conversation_id)
                     REFERENCES mission_conversations(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (
                     (role = 'user' AND kind IN (
                       'goal', 'steering', 'correction', 'clarification'
                     ) AND work_product_id IS NULL)
                     OR (role = 'assistant' AND kind = 'runtime_draft'
                       AND work_product_id IS NOT NULL)
                     OR (role = 'system' AND kind = 'system_notice'
                       AND work_product_id IS NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS mission_conversation_message_order_idx
                   ON mission_conversation_messages(
                     project_id, mission_id, conversation_id, sequence
                   );",
            )?;
            record_migration(&transaction, 37)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 38 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS runtime_turn_private_messages (
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   runtime_turn_attempt_id TEXT NOT NULL,
                   evidence_sequence INTEGER NOT NULL CHECK (evidence_sequence > 0),
                   worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
                   body TEXT NOT NULL CHECK (
                     length(trim(body)) > 0 AND length(body) <= 4194304
                   ),
                   body_digest TEXT NOT NULL CHECK (length(body_digest) = 64),
                   event_digest TEXT NOT NULL CHECK (length(event_digest) = 64),
                   observed_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, runtime_turn_attempt_id, evidence_sequence),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   FOREIGN KEY (
                     project_id, runtime_turn_attempt_id, evidence_sequence
                   ) REFERENCES runtime_turn_evidence(
                     project_id, runtime_turn_attempt_id, sequence
                   ) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS runtime_turn_private_message_scope_idx
                   ON runtime_turn_private_messages(
                     tenant_id, project_id, mission_id, worker_generation,
                     runtime_turn_attempt_id, evidence_sequence
                   );",
            )?;
            record_migration(&transaction, 38)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 39 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS runtime_process_claims (
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   recovery_id TEXT NOT NULL,
                   process_attempt INTEGER NOT NULL CHECK (process_attempt BETWEEN 1 AND 16),
                   mission_id TEXT NOT NULL,
                   workspace_id TEXT NOT NULL,
                   worker_id TEXT NOT NULL,
                   worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
                   runtime_config_digest TEXT NOT NULL CHECK (length(runtime_config_digest) = 64),
                   program_sha256 TEXT NOT NULL CHECK (length(program_sha256) = 64),
                   launch_token_digest TEXT NOT NULL CHECK (length(launch_token_digest) = 64),
                   launch_executable_path_digest TEXT NOT NULL CHECK (
                     length(launch_executable_path_digest) = 64
                   ),
                   process_id INTEGER CHECK (process_id IS NULL OR process_id > 0),
                   started_at_epoch_seconds INTEGER CHECK (
                     started_at_epoch_seconds IS NULL OR started_at_epoch_seconds > 0
                   ),
                   executable_path_digest TEXT CHECK (
                     executable_path_digest IS NULL OR length(executable_path_digest) = 64
                   ),
                   runtime_instance_digest TEXT CHECK (
                     runtime_instance_digest IS NULL OR length(runtime_instance_digest) = 64
                   ),
                   cleanup_attempt_count INTEGER NOT NULL CHECK (
                     cleanup_attempt_count BETWEEN 0 AND 16
                   ),
                   status TEXT NOT NULL CHECK (status IN (
                     'prepared', 'spawned', 'terminated', 'exited', 'blocked'
                   )),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, recovery_id, process_attempt),
                   UNIQUE (project_id, launch_token_digest),
                   FOREIGN KEY (project_id, recovery_id)
                     REFERENCES runtime_recovery_attempts(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at),
                   CHECK (
                     (status = 'prepared'
                       AND process_id IS NULL
                       AND started_at_epoch_seconds IS NULL
                       AND executable_path_digest IS NULL
                       AND runtime_instance_digest IS NULL)
                     OR (status = 'spawned'
                       AND process_id IS NOT NULL
                       AND started_at_epoch_seconds IS NOT NULL
                       AND executable_path_digest IS NOT NULL
                       AND runtime_instance_digest IS NOT NULL)
                     OR status IN ('terminated', 'exited', 'blocked')
                   )
                 );
                 CREATE INDEX IF NOT EXISTS runtime_process_claim_active_idx
                   ON runtime_process_claims(
                     tenant_id, project_id, status, updated_at, recovery_id, process_attempt
                   );",
            )?;
            record_migration(&transaction, 39)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 40 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS mission_schedules (
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                   mission_id TEXT NOT NULL,
                   cycle INTEGER NOT NULL CHECK (cycle >= 2),
                   scheduled_from_mission_revision INTEGER NOT NULL CHECK (
                     scheduled_from_mission_revision > 0
                   ),
                   contract_version INTEGER NOT NULL CHECK (contract_version > 0),
                   definition_cycle INTEGER CHECK (definition_cycle > 0),
                   trigger TEXT NOT NULL CHECK (trigger IN (
                     'interval', 'event_driven', 'interval_or_event'
                   )),
                   interval_seconds INTEGER NOT NULL CHECK (interval_seconds >= 0),
                   anchor_at TEXT NOT NULL,
                   event_topics_digest TEXT NOT NULL CHECK (
                     length(event_topics_digest) = 64
                   ),
                   due_at TEXT,
                   retry_not_before TEXT,
                   contract_valid_until TEXT NOT NULL,
                   signal_event_id_digest TEXT CHECK (
                     signal_event_id_digest IS NULL OR length(signal_event_id_digest) = 64
                   ),
                   status TEXT NOT NULL CHECK (status IN (
                     'pending', 'leased', 'triggered', 'cancelled', 'dead_letter'
                   )),
                   lease_generation INTEGER NOT NULL CHECK (lease_generation >= 0),
                   lease_owner_digest TEXT CHECK (
                     lease_owner_digest IS NULL OR length(lease_owner_digest) = 64
                   ),
                   lease_token_digest TEXT CHECK (
                     lease_token_digest IS NULL OR length(lease_token_digest) = 64
                   ),
                   lease_expires_at TEXT,
                   failure_count INTEGER NOT NULL CHECK (failure_count BETWEEN 0 AND 5),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, mission_id, cycle),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at),
                   CHECK (contract_valid_until > created_at),
                   CHECK (
                     (trigger = 'interval' AND interval_seconds > 0
                       AND due_at IS NOT NULL AND signal_event_id_digest IS NULL)
                     OR (trigger = 'event_driven' AND interval_seconds = 0
                       AND due_at IS NULL)
                     OR (trigger = 'interval_or_event' AND interval_seconds > 0
                       AND due_at IS NOT NULL)
                   ),
                   CHECK (
                     (status IN ('leased', 'triggered')
                       AND lease_generation > 0
                       AND lease_owner_digest IS NOT NULL
                       AND lease_token_digest IS NOT NULL
                       AND lease_expires_at IS NOT NULL)
                     OR (status IN ('pending', 'cancelled', 'dead_letter')
                       AND lease_owner_digest IS NULL
                       AND lease_token_digest IS NULL
                       AND lease_expires_at IS NULL)
                   )
                 );
                 CREATE INDEX IF NOT EXISTS mission_schedule_due_idx
                   ON mission_schedules(
                     tenant_id, status, retry_not_before, due_at,
                     lease_expires_at, project_id, mission_id, cycle
                   );",
            )?;
            record_migration(&transaction, 40)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 41 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "DROP INDEX IF EXISTS mission_schedule_due_idx;
                 ALTER TABLE mission_schedules RENAME TO mission_schedules_v40;
                 CREATE TABLE mission_schedules (
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                   mission_id TEXT NOT NULL,
                   cycle INTEGER NOT NULL CHECK (cycle >= 2),
                   scheduled_from_mission_revision INTEGER NOT NULL CHECK (
                     scheduled_from_mission_revision > 0
                   ),
                   contract_version INTEGER NOT NULL CHECK (contract_version > 0),
                   definition_cycle INTEGER CHECK (definition_cycle > 0),
                   trigger TEXT NOT NULL CHECK (trigger IN (
                     'interval', 'event_driven', 'interval_or_event'
                   )),
                   interval_seconds INTEGER NOT NULL CHECK (interval_seconds >= 0),
                   anchor_at TEXT NOT NULL,
                   event_topics_digest TEXT NOT NULL CHECK (
                     length(event_topics_digest) = 64
                   ),
                   due_at TEXT,
                   retry_not_before TEXT,
                   contract_valid_until TEXT NOT NULL,
                   signal_event_id_digest TEXT CHECK (
                     signal_event_id_digest IS NULL OR length(signal_event_id_digest) = 64
                   ),
                   status TEXT NOT NULL CHECK (status IN (
                     'pending', 'leased', 'triggered', 'cancelled', 'expired', 'dead_letter'
                   )),
                   lease_generation INTEGER NOT NULL CHECK (lease_generation >= 0),
                   lease_owner_digest TEXT CHECK (
                     lease_owner_digest IS NULL OR length(lease_owner_digest) = 64
                   ),
                   lease_token_digest TEXT CHECK (
                     lease_token_digest IS NULL OR length(lease_token_digest) = 64
                   ),
                   lease_expires_at TEXT,
                   failure_count INTEGER NOT NULL CHECK (failure_count BETWEEN 0 AND 5),
                   revision INTEGER NOT NULL CHECK (revision > 0),
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL,
                   PRIMARY KEY (project_id, id),
                   UNIQUE (project_id, mission_id, cycle),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (updated_at >= created_at),
                   CHECK (contract_valid_until > created_at),
                   CHECK (
                     (trigger = 'interval' AND interval_seconds > 0
                       AND due_at IS NOT NULL AND signal_event_id_digest IS NULL)
                     OR (trigger = 'event_driven' AND interval_seconds = 0
                       AND due_at IS NULL)
                     OR (trigger = 'interval_or_event' AND interval_seconds > 0
                       AND due_at IS NOT NULL)
                   ),
                   CHECK (
                     (status IN ('leased', 'triggered')
                       AND lease_generation > 0
                       AND lease_owner_digest IS NOT NULL
                       AND lease_token_digest IS NOT NULL
                       AND lease_expires_at IS NOT NULL)
                     OR (status IN ('pending', 'cancelled', 'expired', 'dead_letter')
                       AND lease_owner_digest IS NULL
                       AND lease_token_digest IS NULL
                       AND lease_expires_at IS NULL)
                   )
                 );
                 INSERT INTO mission_schedules (
                   tenant_id, project_id, id, mission_id, cycle,
                   scheduled_from_mission_revision, contract_version, definition_cycle,
                   trigger, interval_seconds, anchor_at, event_topics_digest, due_at,
                   retry_not_before, contract_valid_until, signal_event_id_digest,
                   status, lease_generation, lease_owner_digest, lease_token_digest,
                   lease_expires_at, failure_count, revision, created_at, updated_at, record_json
                 )
                 SELECT
                   tenant_id, project_id, id, mission_id, cycle,
                   scheduled_from_mission_revision, contract_version, definition_cycle,
                   trigger, interval_seconds, anchor_at, event_topics_digest, due_at,
                   retry_not_before, contract_valid_until, signal_event_id_digest,
                   status, lease_generation, lease_owner_digest, lease_token_digest,
                   lease_expires_at, failure_count, revision, created_at, updated_at, record_json
                 FROM mission_schedules_v40;
                 DROP TABLE mission_schedules_v40;
                 CREATE INDEX mission_schedule_due_idx
                   ON mission_schedules(
                     tenant_id, status, retry_not_before, due_at,
                     lease_expires_at, project_id, mission_id, cycle
                   );",
            )?;
            record_migration(&transaction, 41)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 42 {
            let route_capability_column_exists = self
                .connection
                .query_row(
                    "SELECT 1 FROM pragma_table_info('mission_checkpoints')
                     WHERE name = 'route_capability_id'",
                    [],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let route_executor_column_exists = self
                .connection
                .query_row(
                    "SELECT 1 FROM pragma_table_info('mission_checkpoints')
                     WHERE name = 'route_executor'",
                    [],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let transaction = self.connection.transaction()?;
            if !route_capability_column_exists {
                transaction.execute_batch(
                    "ALTER TABLE mission_checkpoints
                   ADD COLUMN route_capability_id TEXT CHECK (
                     route_capability_id IS NULL OR length(trim(route_capability_id)) > 0
                   );",
                )?;
            }
            if !route_executor_column_exists {
                transaction.execute_batch(
                    "ALTER TABLE mission_checkpoints
                   ADD COLUMN route_executor TEXT CHECK (
                     route_executor IS NULL OR route_executor IN (
                       'application', 'runtime', 'effect_broker', 'human'
                     )
                   );",
                )?;
            }
            record_migration(&transaction, 42)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 43 {
            let route_oracle_ids_column_exists = self
                .connection
                .query_row(
                    "SELECT 1 FROM pragma_table_info('mission_checkpoints')
                     WHERE name = 'route_oracle_ids_json'",
                    [],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let route_completion_policy_column_exists = self
                .connection
                .query_row(
                    "SELECT 1 FROM pragma_table_info('mission_checkpoints')
                     WHERE name = 'route_completion_policy'",
                    [],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let transaction = self.connection.transaction()?;
            if !route_oracle_ids_column_exists {
                transaction.execute_batch(
                    "ALTER TABLE mission_checkpoints
                   ADD COLUMN route_oracle_ids_json TEXT CHECK (
                     route_oracle_ids_json IS NULL
                     OR length(trim(route_oracle_ids_json)) > 2
                   );",
                )?;
            }
            if !route_completion_policy_column_exists {
                transaction.execute_batch(
                    "ALTER TABLE mission_checkpoints
                   ADD COLUMN route_completion_policy TEXT CHECK (
                     route_completion_policy IS NULL OR route_completion_policy IN (
                       'deterministic_evidence', 'work_product',
                       'verified_effect', 'human_confirmation'
                     )
                   );",
                )?;
            }
            record_migration(&transaction, 43)?;
            transaction.commit()?;
        }
        if current_schema_version(&self.connection)? < 44 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "DROP INDEX IF EXISTS mission_conversation_message_order_idx;
                 ALTER TABLE mission_conversation_messages
                   RENAME TO mission_conversation_messages_v44;
                 CREATE TABLE mission_conversation_messages (
                   id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   conversation_id TEXT NOT NULL,
                   sequence INTEGER NOT NULL CHECK (sequence > 0),
                   role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
                   kind TEXT NOT NULL CHECK (kind IN (
                     'goal', 'steering', 'correction', 'clarification',
                     'checkpoint_confirmation', 'runtime_draft', 'system_notice'
                   )),
                   body TEXT NOT NULL CHECK (length(trim(body)) > 0),
                   content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                   idempotency_key TEXT NOT NULL CHECK (
                     length(trim(idempotency_key)) > 0 AND length(idempotency_key) <= 512
                   ),
                   mission_revision INTEGER NOT NULL CHECK (mission_revision > 0),
                   checkpoint_id TEXT,
                   work_product_id TEXT,
                   recorded_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, conversation_id, id),
                   UNIQUE (project_id, conversation_id, sequence),
                   UNIQUE (project_id, conversation_id, idempotency_key),
                   FOREIGN KEY (project_id, conversation_id)
                     REFERENCES mission_conversations(project_id, id) ON DELETE CASCADE,
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   CHECK (
                     (role = 'user' AND kind IN (
                       'goal', 'steering', 'correction', 'clarification',
                       'checkpoint_confirmation'
                     ) AND work_product_id IS NULL)
                     OR (role = 'assistant' AND kind = 'runtime_draft'
                       AND work_product_id IS NOT NULL)
                     OR (role = 'system' AND kind = 'system_notice'
                       AND work_product_id IS NULL)
                   )
                 );
                 INSERT INTO mission_conversation_messages (
                   id, tenant_id, project_id, mission_id, conversation_id, sequence,
                   role, kind, body, content_digest, idempotency_key, mission_revision,
                   checkpoint_id, work_product_id, recorded_at
                 )
                 SELECT id, tenant_id, project_id, mission_id, conversation_id, sequence,
                   role, kind, body, content_digest, idempotency_key, mission_revision,
                   checkpoint_id, work_product_id, recorded_at
                 FROM mission_conversation_messages_v44;
                 DROP TABLE mission_conversation_messages_v44;
                 CREATE INDEX mission_conversation_message_order_idx
                   ON mission_conversation_messages(
                     project_id, mission_id, conversation_id, sequence
                   );",
            )?;
            record_migration(&transaction, 44)?;
            transaction.commit()?;
        }
        // Provisional v45 on `codex/interaction-baseline`. Integration owns
        // Outcome/Human-decision v45, so this exact migration must be
        // renumbered to v46 and remain after that migration when merged.
        if current_schema_version(&self.connection)? < 45 {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(
                "DROP INDEX IF EXISTS runtime_turn_private_message_scope_idx;
                 ALTER TABLE runtime_turn_private_messages
                   RENAME TO runtime_turn_private_messages_v45;
                 ALTER TABLE runtime_turn_evidence RENAME TO runtime_turn_evidence_v45;
                 CREATE TABLE runtime_turn_evidence (
                   tenant_id TEXT NOT NULL,
                   project_id TEXT NOT NULL,
                   runtime_turn_attempt_id TEXT NOT NULL,
                   sequence INTEGER NOT NULL CHECK (sequence > 0),
                   evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
                     'prepared', 'dispatch_started', 'dispatch_accepted', 'turn_started',
                     'item_started', 'agent_message_delta', 'item_completed', 'diagnostic',
                     'local_approval_requested', 'local_approval_response_started',
                     'local_approval_response_sent', 'interrupt_requested',
                     'interrupt_accepted', 'completed', 'interrupted', 'failed', 'uncertain'
                   )),
                   evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                   resulting_status TEXT NOT NULL CHECK (resulting_status IN (
                     'prepared', 'dispatching', 'running', 'waiting_local_approval',
                     'approval_responding', 'interrupt_requested', 'completed',
                     'interrupted', 'failed', 'uncertain'
                   )),
                   observed_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, runtime_turn_attempt_id, sequence),
                   FOREIGN KEY (project_id, runtime_turn_attempt_id)
                     REFERENCES runtime_turn_attempts(project_id, id) ON DELETE CASCADE
                 );
                 INSERT INTO runtime_turn_evidence (
                   tenant_id, project_id, runtime_turn_attempt_id, sequence,
                   evidence_kind, evidence_digest, resulting_status, observed_at
                 )
                 SELECT tenant_id, project_id, runtime_turn_attempt_id, sequence,
                   evidence_kind, evidence_digest, resulting_status, observed_at
                 FROM runtime_turn_evidence_v45;
                 CREATE TABLE runtime_turn_private_messages (
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   runtime_turn_attempt_id TEXT NOT NULL,
                   evidence_sequence INTEGER NOT NULL CHECK (evidence_sequence > 0),
                   worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
                   item_id_digest TEXT NOT NULL CHECK (length(item_id_digest) = 64),
                   body TEXT NOT NULL CHECK (
                     length(trim(body)) > 0 AND length(body) <= 4194304
                   ),
                   body_digest TEXT NOT NULL CHECK (length(body_digest) = 64),
                   event_digest TEXT NOT NULL CHECK (length(event_digest) = 64),
                   observed_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, runtime_turn_attempt_id, evidence_sequence),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   FOREIGN KEY (
                     project_id, runtime_turn_attempt_id, evidence_sequence
                   ) REFERENCES runtime_turn_evidence(
                     project_id, runtime_turn_attempt_id, sequence
                   ) ON DELETE CASCADE
                 );
                 INSERT INTO runtime_turn_private_messages (
                   tenant_id, project_id, mission_id, runtime_turn_attempt_id,
                   evidence_sequence, worker_generation, item_id_digest, body,
                   body_digest, event_digest, observed_at
                 )
                 SELECT tenant_id, project_id, mission_id, runtime_turn_attempt_id,
                   evidence_sequence, worker_generation,
                   'b907287bacf5470d3b3c410ae6e7934f19ee7e0640b289fc41922a441bb88d5b',
                   body, body_digest, event_digest, observed_at
                 FROM runtime_turn_private_messages_v45;
                 CREATE INDEX runtime_turn_private_message_scope_idx
                   ON runtime_turn_private_messages(
                     tenant_id, project_id, mission_id, worker_generation,
                     runtime_turn_attempt_id, evidence_sequence
                   );
                 DROP TABLE runtime_turn_private_messages_v45;
                 DROP TABLE runtime_turn_evidence_v45;
                 CREATE TABLE runtime_turn_private_text_deltas (
                   tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                   project_id TEXT NOT NULL,
                   mission_id TEXT NOT NULL,
                   runtime_turn_attempt_id TEXT NOT NULL,
                   evidence_sequence INTEGER NOT NULL CHECK (evidence_sequence > 0),
                   stream_sequence INTEGER NOT NULL CHECK (stream_sequence > 0),
                   worker_generation INTEGER NOT NULL CHECK (worker_generation > 0),
                   item_id_digest TEXT NOT NULL CHECK (length(item_id_digest) = 64),
                   delta TEXT NOT NULL CHECK (
                     length(delta) > 0 AND length(delta) <= 4194304
                   ),
                   delta_digest TEXT NOT NULL CHECK (length(delta_digest) = 64),
                   cumulative_byte_count INTEGER NOT NULL CHECK (
                     cumulative_byte_count > 0 AND cumulative_byte_count <= 4194304
                   ),
                   chain_digest TEXT NOT NULL CHECK (length(chain_digest) = 64),
                   event_digest TEXT NOT NULL CHECK (length(event_digest) = 64),
                   observed_at TEXT NOT NULL,
                   PRIMARY KEY (project_id, runtime_turn_attempt_id, evidence_sequence),
                   UNIQUE (
                     project_id, runtime_turn_attempt_id, item_id_digest, stream_sequence
                   ),
                   FOREIGN KEY (mission_id, project_id)
                     REFERENCES missions(id, project_id) ON DELETE CASCADE,
                   FOREIGN KEY (
                     project_id, runtime_turn_attempt_id, evidence_sequence
                   ) REFERENCES runtime_turn_evidence(
                     project_id, runtime_turn_attempt_id, sequence
                   ) ON DELETE CASCADE
                 );
                 CREATE INDEX runtime_turn_private_text_delta_scope_idx
                   ON runtime_turn_private_text_deltas(
                     tenant_id, project_id, mission_id, worker_generation,
                     runtime_turn_attempt_id, item_id_digest, stream_sequence
                   );",
            )?;
            record_migration(&transaction, 45)?;
            transaction.commit()?;
        }
        self.backfill_normalized_state()?;
        self.backfill_mission_conversations()?;
        Ok(())
    }
}

fn validated_database_path(path: &Path) -> Result<PathBuf, StorageError> {
    if !path.is_absolute() {
        return Err(StorageError::InvalidDatabasePath(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::InvalidDatabasePath(path.to_path_buf()))?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| StorageError::InvalidDatabasePath(path.to_path_buf()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| StorageError::InvalidDatabasePath(path.to_path_buf()))?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(StorageError::SymlinkDatabasePath(path.to_path_buf()));
    }
    let candidate = canonical_parent.join(file_name);
    if candidate.exists() {
        let canonical_file = candidate
            .canonicalize()
            .map_err(|_| StorageError::InvalidDatabasePath(path.to_path_buf()))?;
        if canonical_file.parent() != Some(canonical_parent.as_path()) {
            return Err(StorageError::InvalidDatabasePath(path.to_path_buf()));
        }
    }
    Ok(candidate)
}

fn apply_database_key(connection: &Connection, key: &DatabaseKey) -> Result<(), StorageError> {
    let key_hex = Zeroizing::new(hex::encode(key.as_bytes()));
    let statement = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex.as_str()));
    connection.execute_batch(statement.as_str())?;
    Ok(())
}

fn verify_sqlcipher(connection: &Connection) -> Result<(), StorageError> {
    let version = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get::<_, String>(0))
        .optional()?;
    if version.as_deref().is_none_or(str::is_empty) {
        return Err(StorageError::SqlCipherUnavailable);
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<(), StorageError> {
    connection.busy_timeout(StdDuration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = ON;
         PRAGMA cipher_memory_security = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn current_schema_version(connection: &Connection) -> Result<i64, StorageError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Ok(0);
    }
    Ok(connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?)
}

fn record_migration(transaction: &Transaction<'_>, version: i64) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
        params![version, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

fn create_encrypted_backup(
    source: &Connection,
    database_path: &Path,
    key: &DatabaseKey,
    schema_version: i64,
) -> Result<PathBuf, StorageError> {
    let file_name = database_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| StorageError::InvalidDatabasePath(database_path.to_path_buf()))?;
    let backup_path = database_path.with_file_name(format!(
        "{file_name}.pre-migration-v{schema_version}-{}.sqlite3",
        Utc::now().timestamp_millis()
    ));
    let mut destination = Connection::open(&backup_path)?;
    apply_database_key(&destination, key)?;
    verify_sqlcipher(&destination)?;
    {
        let backup = Backup::new(source, &mut destination)?;
        backup.run_to_completion(128, StdDuration::from_millis(10), None)?;
    }
    destination.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    Ok(backup_path)
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database path must be absolute, parent-canonical, and contained: {0}")]
    InvalidDatabasePath(PathBuf),
    #[error("database files may not be symbolic links: {0}")]
    SymlinkDatabasePath(PathBuf),
    #[error("database key may not be all zeroes")]
    InvalidDatabaseKey,
    #[error("the linked SQLite library does not provide SQLCipher")]
    SqlCipherUnavailable,
    #[error("database schema {found} is newer than supported schema {supported}")]
    UnsupportedSchemaVersion { found: i64, supported: i64 },
    #[error("tenant scope does not match the persisted project or mission")]
    TenantScopeMismatch,
    #[error("encrypted sync project {project_id} is not registered and applied in Cell {cell}")]
    EncryptedSyncProjectNotReady { project_id: ProjectId, cell: String },
    #[error(
        "sync object {object_kind}:{object_id} in project {project_id} was permanently deleted"
    )]
    SyncObjectDeleted {
        project_id: ProjectId,
        object_kind: String,
        object_id: String,
    },
    #[error("tombstones must use a typed deletion command and atomic projection cleanup")]
    DeletionRequiresTypedPath,
    #[error("deletion is not yet safe for sync object kind {0}")]
    DeletionUnsupportedObjectKind(String),
    #[error("context capsule deletion requires an exact accepted, cancelled, or expired revision")]
    DeletionRequiresTerminalContextCapsule,
    #[error(
        "deletion propagation lease for {deletion_id}:{surface} is no longer owned by {owner} generation {generation}"
    )]
    DeletionPropagationLeaseLost {
        deletion_id: String,
        surface: String,
        owner: String,
        generation: u64,
    },
    #[error("deletion surface {0} is not managed by a propagation worker")]
    DeletionSurfaceNotWorkerManaged(String),
    #[error("project not found: {0}")]
    ProjectNotFound(ProjectId),
    #[error("mission {mission_id} was not found inside project {project_id}")]
    MissionNotFound {
        project_id: ProjectId,
        mission_id: MissionId,
    },
    #[error("creator task {task_id} was not found inside project {project_id}")]
    CreatorTaskNotFound {
        project_id: ProjectId,
        task_id: hartevo_domain_kernel::CreatorTaskId,
    },
    #[error("{kind} record {id} was not found inside project {project_id}")]
    ScopedRecordNotFound {
        kind: &'static str,
        project_id: ProjectId,
        id: String,
    },
    #[error("new creator aggregates must begin at state revision 1, found {0}")]
    InvalidInitialRevision(u64),
    #[error("aggregate mutation expected next revision {expected}, found {actual}")]
    UnexpectedNextRevision { expected: u64, actual: u64 },
    #[error("aggregate mutation must advance beyond revision {expected_revision}, found {actual}")]
    UnexpectedNewerRevision { expected_revision: u64, actual: u64 },
    #[error("atomic aggregate mutation requires at least one event")]
    EmptyAtomicEventSet,
    #[error("domain event type cannot be empty")]
    EmptyEventType,
    #[error("optimistic write conflict for {aggregate} at expected revision {expected_revision}")]
    OptimisticConflict {
        aggregate: String,
        expected_revision: u64,
    },
    #[error("stored domain data could not be decoded: {0}")]
    DomainDecode(String),
    #[error("key bootstrap operation is malformed or has an invalid terminal state")]
    InvalidKeyBootstrapOperation,
    #[error("key bootstrap operation cannot make the requested revision transition")]
    InvalidKeyBootstrapOperationTransition,
    #[error("private key, recovery secret, token, or cookie cannot enter bootstrap persistence")]
    SensitiveKeyBootstrapPayload,
    #[error(transparent)]
    WorkProductManifest(#[from] hartevo_domain_kernel::WorkProductManifestError),
    #[error(transparent)]
    ContextAssembly(#[from] hartevo_context_fabric::ContextAssemblyError),
    #[error(transparent)]
    Browser(#[from] hartevo_browser_adapter::BrowserError),
    #[error(transparent)]
    RuntimeTurn(#[from] hartevo_domain_kernel::RuntimeTurnError),
    #[error(transparent)]
    Context(#[from] hartevo_domain_kernel::ContextError),
    #[error(transparent)]
    MissionConversation(#[from] hartevo_domain_kernel::MissionConversationError),
    #[error(transparent)]
    MissionSchedule(#[from] hartevo_domain_kernel::MissionScheduleError),
    #[error(transparent)]
    Mission(#[from] hartevo_domain_kernel::MissionError),
    #[error(transparent)]
    KeyManagement(#[from] hartevo_domain_kernel::KeyManagementError),
    #[error(transparent)]
    Deletion(#[from] hartevo_domain_kernel::DeletionError),
    #[error("immutable {kind} record {id} does not match its persisted value")]
    ImmutableRecordMismatch { kind: &'static str, id: String },
    #[error("outbox lease {sequence} is no longer owned by {owner} generation {generation}")]
    OutboxLeaseLost {
        sequence: i64,
        owner: String,
        generation: u64,
    },
    #[error("revision cannot be represented by SQLite INTEGER: {0}")]
    RevisionOverflow(u64),
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Time(#[from] chrono::ParseError),
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Barrier};

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, Cadence, Company, CompanyId,
        Connection as ProviderConnection, ConnectionId, ConsentState, ContactChannel, Conversation,
        ConversationId, ConversationState, CurrencyCode, DeletionId, DeletionReason,
        DeletionRecord, DeletionSurface, DeletionTombstone, Effect, EffectClass, EffectId,
        EffectRisk, EffectSpec, Evidence, EvidenceId, EvidenceStatus, ExternalIdentity,
        IdentityLink, IdentityLinkId, IdentitySubject, MessagingGateway, MissionContract,
        MissionStage, Money, OperatingMode, Outcome, OutcomeDecision, Person, PersonId, Receipt,
        ReceiptId, StorageMode, Verification, VerificationId, VerificationStatus, WorkProduct,
        WorkProductId,
    };
    use hartevo_effect_broker::{
        DurableEffectLedger, EffectPolicy, EffectRateLimit, ExecutionClaimContext, LedgerClaim,
        PermissionEvidence, ReconciliationClaim, ReconciliationDisposition,
        ReconciliationObservation, ReconciliationPolicy,
    };
    use proptest::prelude::*;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 9, 0, 0)
            .single()
            .expect("valid time")
    }

    fn database_key() -> DatabaseKey {
        DatabaseKey::new([7; 32]).expect("database key")
    }

    fn project(id: &str, root: &str) -> Project {
        Project::create_local(
            hartevo_domain_kernel::TenantId::from("tenant-1"),
            ProjectId::from(id),
            id,
            "",
            root,
            StorageMode::LocalExisting,
        )
        .expect("project")
    }

    fn mission(project_id: &str, mission_id: &str) -> Mission {
        Mission::compile(
            hartevo_domain_kernel::TenantId::from("tenant-1"),
            MissionId::from(mission_id),
            ProjectId::from(project_id),
            "Launch brief",
            MissionContract::bootstrap("Create the launch brief", [], now()),
            now(),
        )
        .expect("mission")
    }

    fn catalog_mission(project_id: &str, mission_id: &str) -> Mission {
        let contract = MissionContract::bootstrap(
            "Decide whether to enter Germany",
            ["research.discover".into(), "decision.evaluate".into()],
            now(),
        );
        let definition = hartevo_domain_kernel::MissionDefinition::from_routed_linear_manifest(
            "VM-07",
            1,
            "a".repeat(64),
            OperatingMode::BuildOnce,
            contract.enabled_capabilities.iter().cloned(),
            ["market_evidence_pack".into(), "market_decision".into()],
            [
                "truth".into(),
                "decision".into(),
                "work_product".into(),
                "operating_state".into(),
            ],
            [
                (
                    "constraints_locked".into(),
                    hartevo_domain_kernel::MissionCheckpointRoute::contracted(
                        "research.discover",
                        hartevo_domain_kernel::MissionCheckpointExecutor::Runtime,
                        [
                            "truth".into(),
                            "work_product".into(),
                            "operating_state".into(),
                        ],
                        hartevo_domain_kernel::MissionCheckpointCompletionPolicy::WorkProduct,
                    )
                    .expect("route"),
                ),
                (
                    "decision_ready".into(),
                    hartevo_domain_kernel::MissionCheckpointRoute::contracted(
                        "decision.evaluate",
                        hartevo_domain_kernel::MissionCheckpointExecutor::Application,
                        ["decision".into(), "operating_state".into()],
                        hartevo_domain_kernel::MissionCheckpointCompletionPolicy::DeterministicEvidence,
                    )
                    .expect("route"),
                ),
            ],
        )
        .expect("definition");
        let mut mission = Mission::compile_catalog(
            hartevo_domain_kernel::TenantId::from("tenant-1"),
            MissionId::from(mission_id),
            ProjectId::from(project_id),
            "Germany decision",
            contract,
            definition,
            now(),
        )
        .expect("catalog mission");
        mission
            .start_research(
                [hartevo_domain_kernel::Task {
                    id: hartevo_domain_kernel::TaskId::from("task-catalog"),
                    title: "Lock constraints".into(),
                    status: hartevo_domain_kernel::TaskStatus::Running,
                    capability: "research.discover".into(),
                }],
                now(),
            )
            .expect("start catalog mission");
        mission
    }

    fn persist_catalog_mission_at_next_checkpoint_ready(
        store: &mut ProjectStore,
        project: &Project,
        mission_id: &str,
    ) -> Mission {
        let mut mission = catalog_mission(project.id.as_str(), mission_id);
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new(
                    "mission.checkpoint_started",
                    serde_json::json!({
                        "checkpointId": "constraints_locked",
                        "capabilityId": "research.discover",
                        "executor": "runtime",
                    }),
                    now(),
                )],
            )
            .expect("initial routed Mission");
        let initial_revision = mission.revision;
        let completed_at = now() + Duration::minutes(1);
        let evidence_id = EvidenceId::from("checkpoint-route-evidence");
        let work_product_id = WorkProductId::from("checkpoint-route-work-product");
        mission
            .record_evidence(
                Evidence {
                    id: evidence_id.clone(),
                    title: "Germany evidence plan".into(),
                    source_uri: "fixture://market-evidence".into(),
                    observed_at: now() + Duration::seconds(10),
                    confidence: 1.0,
                    status: EvidenceStatus::Confirmed,
                    content_digest: "7".repeat(64),
                },
                now() + Duration::seconds(10),
            )
            .expect("record first Checkpoint evidence");
        mission
            .record_work_product(
                WorkProduct::draft(
                    work_product_id.clone(),
                    "Germany evidence plan",
                    "A deterministic, source-bound market evidence plan.",
                    [evidence_id],
                ),
                now() + Duration::seconds(20),
            )
            .expect("record first Checkpoint WorkProduct");
        mission
            .begin_checkpoint_verification("constraints_locked", completed_at)
            .expect("verify first Checkpoint");
        mission
            .complete_checkpoint(
                "constraints_locked",
                hartevo_domain_kernel::MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from([
                        "truth".into(),
                        "work_product".into(),
                        "operating_state".into(),
                    ]),
                    work_product_ids: BTreeSet::from([work_product_id]),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: "9".repeat(64),
                    verified_at: completed_at,
                },
            )
            .expect("complete first Checkpoint");
        store
            .update_mission_atomic(
                &mission,
                initial_revision,
                &[PendingEvent::new(
                    "mission.checkpoint_completed",
                    serde_json::json!({
                        "checkpointId": "constraints_locked",
                        "nextCheckpointId": "decision_ready",
                    }),
                    completed_at,
                )],
            )
            .expect("persist completed Checkpoint");
        mission
    }

    fn begin_exact_decision_checkpoint(mission: &mut Mission, transition_at: DateTime<Utc>) {
        mission
            .begin_checkpoint_with_task(
                "decision_ready",
                hartevo_domain_kernel::Task {
                    id: hartevo_domain_kernel::TaskId::from("task-decision-route"),
                    title: "Evaluate the exact decision route".into(),
                    status: hartevo_domain_kernel::TaskStatus::Running,
                    capability: "decision.evaluate".into(),
                },
                transition_at,
            )
            .expect("prepare exact next route");
    }

    fn checkpoint_started_event(transition_at: DateTime<Utc>) -> PendingEvent {
        PendingEvent::new(
            "mission.checkpoint_started",
            serde_json::json!({
                "checkpointId": "decision_ready",
                "capabilityId": "decision.evaluate",
                "executor": "application",
            }),
            transition_at,
        )
    }

    fn assert_exact_decision_checkpoint_persisted(
        store: &ProjectStore,
        project: &Project,
        mission: &Mission,
        expected_event_count: usize,
    ) {
        let restored = store
            .load_mission(&project.id, &mission.id)
            .expect("restored exact route");
        assert_eq!(&restored, mission);
        assert_eq!(
            restored
                .definition
                .as_ref()
                .and_then(hartevo_domain_kernel::MissionDefinition::current_checkpoint)
                .map(|checkpoint| (checkpoint.id.as_str(), checkpoint.status)),
            Some((
                "decision_ready",
                hartevo_domain_kernel::MissionCheckpointStatus::Running
            ))
        );
        assert_eq!(
            restored
                .tasks
                .iter()
                .map(|task| {
                    (
                        task.id.as_str(),
                        task.status.clone(),
                        task.capability.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (
                    "task-catalog",
                    hartevo_domain_kernel::TaskStatus::Completed,
                    "research.discover"
                ),
                (
                    "task-decision-route",
                    hartevo_domain_kernel::TaskStatus::Running,
                    "decision.evaluate"
                ),
            ]
        );
        assert_eq!(
            store
                .events_for_mission(&project.id, &mission.id)
                .expect("events after retry")
                .len(),
            expected_event_count
        );
    }

    #[test]
    fn catalog_mission_definition_and_checkpoint_dag_roundtrip_and_fail_closed_on_tamper() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project(
            "project-catalog-definition",
            "/tmp/project-catalog-definition",
        );
        store.save_project(&project).expect("project");
        let mission = catalog_mission(project.id.as_str(), "mission-catalog-definition");
        store.save_mission(&mission).expect("catalog mission");

        let restored = store
            .load_mission(&project.id, &mission.id)
            .expect("restored catalog mission");
        assert_eq!(restored, mission);
        let definition = restored.definition.as_ref().expect("definition");
        assert_eq!(
            (definition.manifest_id.as_str(), definition.cycle),
            ("VM-07", 1)
        );
        assert_eq!(
            definition
                .current_checkpoint()
                .map(|checkpoint| (checkpoint.id.as_str(), checkpoint.status)),
            Some((
                "constraints_locked",
                hartevo_domain_kernel::MissionCheckpointStatus::Running
            ))
        );
        for table in [
            "mission_definitions",
            "mission_definition_capabilities",
            "mission_definition_artifacts",
            "mission_definition_oracles",
            "mission_checkpoints",
        ] {
            let rows = store
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE project_id = ?1"),
                    [project.id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("normalized definition rows");
            assert!(rows > 0, "{table}");
        }
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT snapshot_json FROM missions WHERE project_id = ?1 AND id = ?2",
                    params![project.id.as_str(), mission.id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .expect("legacy snapshot sentinel"),
            "{}"
        );

        store
            .connection
            .execute(
                "UPDATE mission_checkpoints SET route_capability_id = 'payment.execute'
                 WHERE project_id = ?1 AND mission_id = ?2 AND ordinal = 0",
                params![project.id.as_str(), mission.id.as_str()],
            )
            .expect("tamper Checkpoint route");
        assert!(matches!(
            store.load_mission(&project.id, &mission.id),
            Err(StorageError::DomainDecode(_))
        ));
        store
            .connection
            .execute(
                "UPDATE mission_checkpoints SET route_capability_id = 'research.discover'
                 WHERE project_id = ?1 AND mission_id = ?2 AND ordinal = 0",
                params![project.id.as_str(), mission.id.as_str()],
            )
            .expect("restore Checkpoint route");

        store
            .connection
            .execute(
                "UPDATE mission_checkpoints SET depends_on_json = '[\"decision_ready\"]'
                 WHERE project_id = ?1 AND mission_id = ?2 AND ordinal = 0",
                params![project.id.as_str(), mission.id.as_str()],
            )
            .expect("tamper dependency");
        assert!(matches!(
            store.load_mission(&project.id, &mission.id),
            Err(StorageError::DomainDecode(_))
        ));
    }

    #[test]
    fn checkpoint_route_task_transition_rolls_back_checkpoint_task_and_event_together() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project(
            "project-checkpoint-route-atomic",
            "/tmp/project-checkpoint-route-atomic",
        );
        store.save_project(&project).expect("project");
        let mut mission = persist_catalog_mission_at_next_checkpoint_ready(
            &mut store,
            &project,
            "mission-checkpoint-route-atomic",
        );
        let before = mission.clone();
        let events_before = store
            .events_for_mission(&project.id, &mission.id)
            .expect("events before failure");
        let transition_at = now() + Duration::minutes(2);
        begin_exact_decision_checkpoint(&mut mission, transition_at);
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_exact_checkpoint_task
                 BEFORE INSERT ON mission_tasks
                 WHEN NEW.id = 'task-decision-route'
                 BEGIN
                   SELECT RAISE(ABORT, 'injected exact Checkpoint task failure');
                 END;",
            )
            .expect("install failure trigger");

        let result = store.update_mission_atomic(
            &mission,
            before.revision,
            &[checkpoint_started_event(transition_at)],
        );
        assert!(matches!(result, Err(StorageError::Sql(_))));
        assert_eq!(
            store
                .load_mission(&project.id, &mission.id)
                .expect("Mission after rollback"),
            before
        );
        assert_eq!(
            store
                .events_for_mission(&project.id, &mission.id)
                .expect("events after rollback"),
            events_before
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM mission_tasks
                     WHERE project_id = ?1 AND mission_id = ?2
                       AND id = 'task-decision-route'",
                    params![project.id.as_str(), mission.id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("rolled back Task count"),
            0
        );
        store
            .connection
            .execute_batch("DROP TRIGGER fail_exact_checkpoint_task;")
            .expect("drop failure trigger");
        store
            .update_mission_atomic(
                &mission,
                before.revision,
                &[checkpoint_started_event(transition_at)],
            )
            .expect("retry exact route atomically");
        assert_exact_decision_checkpoint_persisted(
            &store,
            &project,
            &mission,
            events_before.len() + 1,
        );
    }

    #[test]
    fn migration_v36_backs_up_v35_and_installs_mission_definition_dag_idempotently() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("mission-definition-v35.sqlite3");
        let project = project(
            "project-mission-definition-migration",
            "/tmp/mission-definition-migration",
        );
        let mission = mission(project.id.as_str(), "mission-definition-migration-legacy");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("legacy mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE mission_checkpoints;
                     DROP TABLE mission_definition_capabilities;
                     DROP TABLE mission_definition_artifacts;
                     DROP TABLE mission_definition_oracles;
                     DROP TABLE mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 36;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v35");
            assert_eq!(store.schema_version().expect("v35 schema"), 35);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v36");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("legacy mission survives"),
            mission
        );
        for table in [
            "mission_definitions",
            "mission_definition_capabilities",
            "mission_definition_artifacts",
            "mission_definition_oracles",
            "mission_checkpoints",
        ] {
            assert_eq!(
                migrated
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                        [table],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("definition schema object"),
                1,
                "{table}"
            );
        }
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v35")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v35")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    fn migration_v42_preserves_legacy_unbound_checkpoint_routes_and_installs_columns() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("checkpoint-route-v41.sqlite3");
        let project = project(
            "project-checkpoint-route-migration",
            "/tmp/checkpoint-route-migration",
        );
        let mut legacy = catalog_mission(project.id.as_str(), "mission-checkpoint-route-migration");
        for checkpoint in &mut legacy.definition.as_mut().expect("definition").checkpoints {
            checkpoint.route = None;
        }
        legacy
            .definition
            .as_ref()
            .expect("legacy definition")
            .validate()
            .expect("legacy unbound route remains readable");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&legacy).expect("legacy Mission");
            store
                .connection
                .execute_batch(
                    "DROP INDEX mission_checkpoint_state_idx;
                     ALTER TABLE mission_checkpoints RENAME TO mission_checkpoints_v42;
                     CREATE TABLE mission_checkpoints (
                       mission_id TEXT NOT NULL,
                       project_id TEXT NOT NULL,
                       id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                       ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                       depends_on_json TEXT NOT NULL,
                       status TEXT NOT NULL CHECK (status IN (
                         'pending', 'ready', 'running', 'blocked', 'waiting_user',
                         'waiting_approval', 'verifying', 'completed', 'skipped'
                       )),
                       revision INTEGER NOT NULL CHECK (revision > 0),
                       attempt INTEGER NOT NULL CHECK (attempt >= 0),
                       started_at TEXT,
                       block_json TEXT,
                       completion_json TEXT,
                       PRIMARY KEY (mission_id, project_id, id),
                       UNIQUE (mission_id, project_id, ordinal),
                       FOREIGN KEY (mission_id, project_id)
                         REFERENCES mission_definitions(mission_id, project_id) ON DELETE CASCADE
                     );
                     INSERT INTO mission_checkpoints (
                       mission_id, project_id, id, ordinal, depends_on_json, status,
                       revision, attempt, started_at, block_json, completion_json
                     )
                     SELECT mission_id, project_id, id, ordinal, depends_on_json, status,
                       revision, attempt, started_at, block_json, completion_json
                     FROM mission_checkpoints_v42;
                     DROP TABLE mission_checkpoints_v42;
                     CREATE INDEX mission_checkpoint_state_idx
                       ON mission_checkpoints(project_id, mission_id, status, ordinal);
                     DELETE FROM schema_migrations WHERE version >= 42;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v41");
            assert_eq!(store.schema_version().expect("v41 schema"), 41);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v42");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &legacy.id)
                .expect("legacy Mission survives"),
            legacy
        );
        let route_columns = migrated
            .connection
            .prepare("PRAGMA table_info(mission_checkpoints)")
            .expect("table info")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("column names");
        assert!(route_columns.contains(&"route_capability_id".to_owned()));
        assert!(route_columns.contains(&"route_executor".to_owned()));
        assert!(route_columns.contains(&"route_oracle_ids_json".to_owned()));
        assert!(route_columns.contains(&"route_completion_policy".to_owned()));
        drop(migrated);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            reopened
                .load_mission(&project.id, &legacy.id)
                .expect("legacy Mission survives reopen"),
            legacy
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration fixture reproduces schema v42, proves legacy route identity remains auditable but non-completable, and verifies one backup plus idempotent reopen"
    )]
    fn migration_v43_preserves_v42_route_identity_but_leaves_completion_authority_unbound() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("checkpoint-contract-v42.sqlite3");
        let project = project(
            "project-checkpoint-contract-migration",
            "/tmp/checkpoint-contract-migration",
        );
        let contracted =
            catalog_mission(project.id.as_str(), "mission-checkpoint-contract-migration");
        let mut expected_legacy = contracted.clone();
        for checkpoint in &mut expected_legacy
            .definition
            .as_mut()
            .expect("definition")
            .checkpoints
        {
            let route = checkpoint.route.as_ref().expect("routed Checkpoint");
            checkpoint.route = Some(
                hartevo_domain_kernel::MissionCheckpointRoute::new(
                    route.capability_id.clone(),
                    route.executor,
                )
                .expect("legacy route"),
            );
        }
        expected_legacy
            .definition
            .as_ref()
            .expect("legacy definition")
            .validate()
            .expect("uniform v42 routes remain audit-readable");

        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&contracted).expect("contracted Mission");
            store
                .connection
                .execute_batch(
                    "DROP INDEX mission_checkpoint_state_idx;
                     ALTER TABLE mission_checkpoints RENAME TO mission_checkpoints_v43;
                     CREATE TABLE mission_checkpoints (
                       mission_id TEXT NOT NULL,
                       project_id TEXT NOT NULL,
                       id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                       ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                       depends_on_json TEXT NOT NULL,
                       status TEXT NOT NULL CHECK (status IN (
                         'pending', 'ready', 'running', 'blocked', 'waiting_user',
                         'waiting_approval', 'verifying', 'completed', 'skipped'
                       )),
                       revision INTEGER NOT NULL CHECK (revision > 0),
                       attempt INTEGER NOT NULL CHECK (attempt >= 0),
                       started_at TEXT,
                       block_json TEXT,
                       completion_json TEXT,
                       route_capability_id TEXT CHECK (
                         route_capability_id IS NULL OR length(trim(route_capability_id)) > 0
                       ),
                       route_executor TEXT CHECK (
                         route_executor IS NULL OR route_executor IN (
                           'application', 'runtime', 'effect_broker', 'human'
                         )
                       ),
                       PRIMARY KEY (mission_id, project_id, id),
                       UNIQUE (mission_id, project_id, ordinal),
                       FOREIGN KEY (mission_id, project_id)
                         REFERENCES mission_definitions(mission_id, project_id) ON DELETE CASCADE
                     );
                     INSERT INTO mission_checkpoints (
                       mission_id, project_id, id, ordinal, depends_on_json, status,
                       revision, attempt, started_at, block_json, completion_json,
                       route_capability_id, route_executor
                     )
                     SELECT mission_id, project_id, id, ordinal, depends_on_json, status,
                       revision, attempt, started_at, block_json, completion_json,
                       route_capability_id, route_executor
                     FROM mission_checkpoints_v43;
                     DROP TABLE mission_checkpoints_v43;
                     CREATE INDEX mission_checkpoint_state_idx
                       ON mission_checkpoints(project_id, mission_id, status, ordinal);
                     DELETE FROM schema_migrations WHERE version >= 43;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v42");
            assert_eq!(store.schema_version().expect("v42 schema"), 42);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v43");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        let mut restored = migrated
            .load_mission(&project.id, &contracted.id)
            .expect("v42 route identity survives");
        assert_eq!(restored, expected_legacy);
        restored
            .begin_checkpoint_verification("constraints_locked", now() + Duration::minutes(1))
            .expect("legacy route can be inspected through verification state");
        assert!(matches!(
            restored.complete_checkpoint(
                "constraints_locked",
                hartevo_domain_kernel::MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from(["truth".into()]),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: "8".repeat(64),
                    verified_at: now() + Duration::minutes(1),
                },
            ),
            Err(hartevo_domain_kernel::MissionError::InvalidCheckpointCompletion(_))
        ));
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v42")
            })
            .count();
        assert_eq!(backups, 1);
        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            reopened
                .load_mission(&project.id, &contracted.id)
                .expect("legacy route survives reopen"),
            expected_legacy
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v42")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    fn approved_effect(project_id: &str, mission_id: &str) -> (Mission, Effect) {
        approved_effect_named(project_id, mission_id, "effect-1", "effect-idempotency-1")
    }

    fn approved_effect_named(
        project_id: &str,
        mission_id: &str,
        effect_id: &str,
        idempotency_key: &str,
    ) -> (Mission, Effect) {
        let mut mission = Mission::compile(
            hartevo_domain_kernel::TenantId::from("tenant-1"),
            MissionId::from(mission_id),
            ProjectId::from(project_id),
            "Durable effect",
            MissionContract::bootstrap(
                "Execute once across restarts",
                ["channel.preview".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("research");
        let effect_id = mission
            .propose_effect(
                EffectSpec {
                    id: EffectId::from(effect_id),
                    actor_id: ActorId::from("user-1"),
                    capability: "channel.preview".into(),
                    provider: "fixture-provider".into(),
                    connection_id: None,
                    account_id: None,
                    required_scopes: BTreeSet::new(),
                    effect_class: EffectClass::ExternalWrite,
                    description: "Publish controlled preview".into(),
                    target_resource: "preview://one".into(),
                    audience_digest: None,
                    payload_digest: "1".repeat(64),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "UTC".into(),
                    consent: ConsentState::NotRequired,
                    consent_record_id: None,
                    consent_requirement: None,
                    conversation_guard: None,
                    creator_contact_guard: None,
                    policy_version: "policy-v1".into(),
                    risk: EffectRisk::Low,
                    idempotency_key: idempotency_key.into(),
                    amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
                    expires_at: now() + Duration::hours(1),
                },
                now(),
            )
            .expect("effect");
        let proposed = mission.effect(&effect_id).expect("effect");
        let digest = proposed.approval_digest();
        let permission_digest = effect_policy(proposed).authorization_digest(
            &PermissionEvidence::default()
                .digest(proposed)
                .expect("permission digest"),
        );
        let approval_valid_until = mission
            .approval_valid_until(&effect_id, now())
            .expect("approval validity");
        mission
            .approve_effect(
                &effect_id,
                Approval {
                    id: ApprovalId::from("approval-1"),
                    decision: ApprovalDecision::Approved,
                    decided_by: ActorId::from("user-1"),
                    decided_at: now(),
                    valid_until: approval_valid_until,
                    scope_digest: digest,
                    permission_digest,
                },
            )
            .expect("approval");
        let effect = mission.effect(&effect_id).expect("effect").clone();
        (mission, effect)
    }

    fn effect_policy(effect: &Effect) -> EffectPolicy {
        EffectPolicy {
            version: effect.policy_version.clone(),
            allowed_capabilities: BTreeSet::from([effect.capability.clone()]),
            allowed_classes: BTreeSet::from([effect.effect_class.clone()]),
            max_amounts_minor: BTreeMap::from([(
                effect.amount.currency.clone(),
                effect.amount.amount_minor,
            )]),
            rate_limits: vec![EffectRateLimit {
                rule_id: "fixture-preview-per-minute".into(),
                provider: effect.provider.clone(),
                capability: effect.capability.clone(),
                max_executions: 1,
                window_seconds: 60,
            }],
        }
    }

    fn effect_claim_context(effect: &Effect) -> ExecutionClaimContext {
        effect_policy(effect)
            .execution_claim_context(effect, PermissionEvidence::default())
            .expect("valid fixture claim context")
    }

    fn persist_uncertain_effect(
        store: &mut ProjectStore,
        project: &Project,
        mission: &Mission,
        effect: &Effect,
    ) -> DateTime<Utc> {
        store.save_project(project).expect("project");
        store.save_mission(mission).expect("mission");
        let LedgerClaim::Acquired {
            lease,
            receipt: None,
            execution_started_at,
        } = store
            .claim(
                effect,
                Some(&effect_claim_context(effect)),
                "execution-worker",
                now(),
                now() + Duration::seconds(30),
            )
            .expect("execution claim")
        else {
            panic!("expected one Provider execution permit")
        };
        store
            .record_uncertain(
                effect,
                &lease,
                "timeout after Provider submit boundary",
                now() + Duration::seconds(1),
            )
            .expect("durable uncertainty");
        execution_started_at
    }

    fn schedule_reconciliation_retry(
        database: &std::path::Path,
        effect: &Effect,
        policy: &ReconciliationPolicy,
    ) {
        let mut store = ProjectStore::open(database, &database_key()).expect("first reopen");
        let ReconciliationClaim::Acquired { lease, .. } = store
            .claim_reconciliation(
                effect,
                policy,
                "reconcile-worker-1",
                now() + Duration::seconds(2),
                now() + Duration::seconds(32),
            )
            .expect("first reconciliation claim")
        else {
            panic!("expected read-only reconciliation lease")
        };
        assert!(matches!(
            store
                .record_reconciliation(
                    effect,
                    &lease,
                    &ReconciliationObservation::StillUncertain {
                        reason: "lookup has not converged".into(),
                        evidence_digest: "a".repeat(64),
                        observed_at: now() + Duration::seconds(2),
                    },
                    now() + Duration::seconds(2),
                )
                .expect("retry schedule"),
            ReconciliationDisposition::RetryScheduled {
                retry_at,
                attempt_no: 1,
                ..
            } if retry_at == now() + Duration::seconds(12)
        ));
    }

    fn reconcile_receipt_and_verify(
        database: &std::path::Path,
        effect: &Effect,
        policy: &ReconciliationPolicy,
    ) -> (Receipt, Verification) {
        let receipt = Receipt {
            id: ReceiptId::from("receipt-found-by-reconcile"),
            provider: effect.provider.clone(),
            external_id: "external-found-by-reconcile".into(),
            accepted_at: now() + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "b".repeat(64),
        };
        let verification = Verification {
            id: VerificationId::from("verification-after-reconcile"),
            status: VerificationStatus::Confirmed,
            verifier: "independent-reconcile-readback".into(),
            independent: true,
            observed_at: now() + Duration::seconds(13),
            evidence_digest: "c".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        let mut store = ProjectStore::open(database, &database_key()).expect("second reopen");
        assert_eq!(
            store
                .claim_reconciliation(
                    effect,
                    policy,
                    "too-early-worker",
                    now() + Duration::seconds(3),
                    now() + Duration::seconds(33),
                )
                .expect("durable retry boundary"),
            ReconciliationClaim::NotReady {
                retry_at: now() + Duration::seconds(12)
            }
        );
        let ReconciliationClaim::Acquired { lease, .. } = store
            .claim_reconciliation(
                effect,
                policy,
                "reconcile-worker-2",
                now() + Duration::seconds(12),
                now() + Duration::seconds(42),
            )
            .expect("second reconciliation claim")
        else {
            panic!("expected second read-only reconciliation lease")
        };
        let ReconciliationDisposition::ReceiptReadyForVerification {
            lease: verification_lease,
            receipt: found,
            execution_started_at,
        } = store
            .record_reconciliation(
                effect,
                &lease,
                &ReconciliationObservation::ReceiptFound {
                    receipt: receipt.clone(),
                    evidence_digest: "d".repeat(64),
                    observed_at: now() + Duration::seconds(12),
                },
                now() + Duration::seconds(12),
            )
            .expect("Receipt reconciliation")
        else {
            panic!("Receipt must yield only a Verification lease")
        };
        assert_eq!((found, execution_started_at), (receipt.clone(), now()));
        store
            .record_verification(
                effect,
                &verification_lease,
                &verification,
                verification.observed_at,
            )
            .expect("verification after reconciliation");
        (receipt, verification)
    }

    fn persist_rejected_verification(
        store: &mut ProjectStore,
        project: &Project,
        mission: &Mission,
        effect: &Effect,
    ) -> (Receipt, Verification) {
        store.save_project(project).expect("project");
        store.save_mission(mission).expect("mission");
        let LedgerClaim::Acquired { lease, .. } = store
            .claim(
                effect,
                Some(&effect_claim_context(effect)),
                "execution-worker",
                now(),
                now() + Duration::seconds(30),
            )
            .expect("execution claim")
        else {
            panic!("expected execution claim")
        };
        let receipt = Receipt {
            id: ReceiptId::from("receipt-rejected-verification"),
            provider: effect.provider.clone(),
            external_id: "external-rejected-verification".into(),
            accepted_at: now() + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "4".repeat(64),
        };
        store
            .record_receipt(effect, &lease, &receipt, now() + Duration::seconds(1))
            .expect("receipt");
        let LedgerClaim::Acquired {
            lease: verification_lease,
            receipt: Some(reused),
            ..
        } = store
            .claim(
                effect,
                None,
                "verification-worker",
                now() + Duration::seconds(2),
                now() + Duration::seconds(32),
            )
            .expect("verification claim")
        else {
            panic!("expected verification claim")
        };
        assert_eq!(reused, receipt);
        let verification = Verification {
            id: VerificationId::from("verification-rejected"),
            status: VerificationStatus::Rejected,
            verifier: "independent-readback".into(),
            independent: true,
            observed_at: now() + Duration::seconds(3),
            evidence_digest: "5".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        store
            .record_verification(
                effect,
                &verification_lease,
                &verification,
                now() + Duration::seconds(3),
            )
            .expect("rejected verification");
        (receipt, verification)
    }

    #[test]
    fn snapshots_survive_reopen() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("project.sqlite");
        let project = project("project-a", "/tmp/project-a");
        let mission = mission("project-a", "mission-a");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            store.save_project(&project).expect("save project");
            store.save_mission(&mission).expect("save mission");
        }

        let store = ProjectStore::open(&database, &database_key()).expect("reopen");
        assert_eq!(
            store
                .load_mission(&project.id, &mission.id)
                .expect("load mission"),
            mission
        );
        assert_eq!(
            store.schema_version().expect("schema"),
            STORAGE_SCHEMA_VERSION
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test constructs a genuine v17 schema and verifies backup plus every context projection"
    )]
    fn migration_v18_backs_up_v17_and_installs_context_projection_tables_idempotently() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("context-v17.sqlite3");
        let project = project(
            "project-context-migration",
            "/tmp/project-context-migration",
        );
        let mission = mission(&project.id.to_string(), "mission-context-migration");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     ALTER TABLE identity_links DROP COLUMN decision_history_json;
                     DROP TABLE key_bootstrap_operations;
                     DROP TABLE device_key_attachments;
                     DROP TABLE deletion_propagation_receipts;
                     DROP TABLE deletion_propagation_jobs;
                     DROP TABLE sync_deletion_records;
                     DROP TABLE context_capsule_facts;
                     DROP TABLE context_capsules;
                     DROP TABLE worker_leases;
                     DROP TABLE context_branches;
                     DROP TABLE context_workspaces;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 18;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v17");
            assert_eq!(store.schema_version().expect("v17 schema"), 17);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v18");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        let tables = [
            "context_workspaces",
            "context_branches",
            "worker_leases",
            "context_capsules",
            "context_capsule_facts",
        ]
        .into_iter()
        .map(|table| {
            migrated
                .connection
                .query_row(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get::<_, String>(0),
                )
                .expect("context table")
        })
        .collect::<BTreeSet<_>>();
        assert_eq!(tables.len(), 5);
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v17")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v17")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test carries a complete historical schema teardown and backup/reopen proof"
    )]
    fn migration_v19_backs_up_v18_and_installs_deletion_ledger_idempotently() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("deletion-v18.sqlite3");
        let project = project(
            "project-deletion-migration",
            "/tmp/project-deletion-migration",
        );
        let mission = mission(&project.id.to_string(), "mission-deletion-migration");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     ALTER TABLE identity_links DROP COLUMN decision_history_json;
                     DROP TABLE key_bootstrap_operations;
                     DROP TABLE device_key_attachments;
                     DROP TABLE deletion_propagation_receipts;
                     DROP TABLE deletion_propagation_jobs;
                     DROP TABLE sync_deletion_records;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 19;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v18");
            assert_eq!(store.schema_version().expect("v18 schema"), 18);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v19");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        assert_eq!(
            migrated
                .connection
                .query_row(
                    "SELECT name FROM sqlite_master
                     WHERE type = 'table' AND name = 'sync_deletion_records'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("deletion ledger table"),
            "sync_deletion_records"
        );
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v18")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v18")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test proves encrypted backup, pending-job backfill, data survival, and idempotent reopen in one actual database journey"
    )]
    fn migration_v20_backs_up_v19_and_installs_propagation_ledger_idempotently() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("deletion-propagation-v19.sqlite3");
        let project = project(
            "project-deletion-propagation-migration",
            "/tmp/project-deletion-propagation-migration",
        );
        let mission = mission(
            &project.id.to_string(),
            "mission-deletion-propagation-migration",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            let tombstone = DeletionTombstone::create(
                DeletionId::from("deletion-existing-before-v20"),
                project.tenant_id.clone(),
                project.id.clone(),
                "capsule-existing-before-v20",
                "context_capsule",
                4,
                1,
                DeletionReason::UserRequest,
                ActorId::from("migration-user"),
                "1".repeat(64),
                now(),
            )
            .expect("migration tombstone");
            let deletion = DeletionRecord::pending(
                tombstone,
                5,
                "2".repeat(64),
                "3".repeat(64),
                "4".repeat(64),
                now(),
            )
            .expect("migration deletion record");
            let transaction = store
                .connection
                .transaction()
                .expect("deletion transaction");
            crate::deletion_store::insert_deletion_record(&transaction, &deletion)
                .expect("persist v19 deletion record");
            transaction.commit().expect("commit deletion record");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     ALTER TABLE identity_links DROP COLUMN decision_history_json;
                     DROP TABLE key_bootstrap_operations;
                     DROP TABLE device_key_attachments;
                     DROP TABLE deletion_propagation_receipts;
                     DROP TABLE deletion_propagation_jobs;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 20;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v19");
            assert_eq!(store.schema_version().expect("v19 schema"), 19);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v20");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        let propagation_tables = ["deletion_propagation_jobs", "deletion_propagation_receipts"]
            .into_iter()
            .map(|table| {
                migrated
                    .connection
                    .query_row(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                        [table],
                        |row| row.get::<_, String>(0),
                    )
                    .expect("propagation table")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(propagation_tables.len(), 2);
        for surface in [DeletionSurface::Cache, DeletionSurface::Replay] {
            let job = migrated
                .load_deletion_propagation_job(
                    &project.id,
                    &DeletionId::from("deletion-existing-before-v20"),
                    surface,
                )
                .expect("backfilled pending propagation job");
            assert_eq!(job.status, DeletionPropagationJobStatus::Pending);
            assert_eq!(job.attempts, 0);
        }
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v19")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v19")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test carries a complete historical schema teardown and backup/reopen proof"
    )]
    fn migration_v21_backs_up_v20_and_installs_device_attachment_saga_idempotently() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("device-attachment-v20.sqlite3");
        let project = project(
            "project-device-attachment-migration",
            "/tmp/project-device-attachment-migration",
        );
        let mission = mission(
            &project.id.to_string(),
            "mission-device-attachment-migration",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     ALTER TABLE identity_links DROP COLUMN decision_history_json;
                     DROP TABLE key_bootstrap_operations;
                     DROP TABLE device_key_attachments;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 21;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v20");
            assert_eq!(store.schema_version().expect("v20 schema"), 20);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v21");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        assert_eq!(
            migrated
                .connection
                .query_row(
                    "SELECT name FROM sqlite_master
                     WHERE type = 'table' AND name = 'device_key_attachments'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("device attachment saga table"),
            "device_key_attachments"
        );
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v20")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v20")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration replay constructs a genuine v21 attachment table and verifies backup, constraint replacement, ledger installation, and idempotent reopen"
    )]
    fn migration_v22_backs_up_v21_and_installs_claim_first_bootstrap_ledger() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("key-bootstrap-v21.sqlite3");
        let project = project(
            "project-key-bootstrap-migration",
            "/tmp/project-key-bootstrap-migration",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     ALTER TABLE identity_links DROP COLUMN decision_history_json;
                     DROP TABLE key_bootstrap_operations;
                     ALTER TABLE device_key_attachments
                       RENAME TO device_key_attachments_v22_fixture;
                     DROP INDEX device_key_attachment_status_idx;
                     CREATE TABLE device_key_attachments (
                       tenant_id TEXT NOT NULL,
                       project_id TEXT NOT NULL,
                       attachment_id TEXT NOT NULL,
                       idempotency_key_digest TEXT NOT NULL CHECK (
                         length(idempotency_key_digest) = 64
                       ),
                       intent_digest TEXT NOT NULL CHECK (length(intent_digest) = 64),
                       project_mode TEXT NOT NULL CHECK (
                         project_mode IN ('personal_e2ee', 'team_envelope')
                       ),
                       method TEXT NOT NULL CHECK (
                         method IN ('authorized_recipient', 'recovery_kit')
                       ),
                       source_recipient_kind TEXT NOT NULL CHECK (
                         source_recipient_kind IN ('device', 'member', 'recovery')
                       ),
                       source_recipient_id TEXT NOT NULL,
                       device_id TEXT NOT NULL,
                       key_version INTEGER NOT NULL CHECK (key_version > 0),
                       expected_keyring_revision INTEGER NOT NULL CHECK (
                         expected_keyring_revision > 0
                       ),
                       envelope_id TEXT NOT NULL,
                       wrapping_key_reference_digest TEXT NOT NULL CHECK (
                         length(wrapping_key_reference_digest) = 64
                       ),
                       authorized_by TEXT NOT NULL,
                       authorization_evidence_digest TEXT NOT NULL CHECK (
                         length(authorization_evidence_digest) = 64
                       ),
                       status TEXT NOT NULL CHECK (
                         status IN ('prepared', 'applied', 'conflict')
                       ),
                       result_keyring_revision INTEGER CHECK (
                         result_keyring_revision IS NULL OR result_keyring_revision > 0
                       ),
                       error_code TEXT,
                       attachment_revision INTEGER NOT NULL CHECK (
                         attachment_revision > 0
                       ),
                       created_at TEXT NOT NULL,
                       updated_at TEXT NOT NULL,
                       record_json TEXT NOT NULL,
                       PRIMARY KEY (project_id, attachment_id),
                       UNIQUE (project_id, idempotency_key_digest),
                       UNIQUE (project_id, device_id, key_version),
                       FOREIGN KEY (project_id) REFERENCES project_keyrings(project_id)
                         ON DELETE CASCADE,
                       CHECK (
                         (status = 'prepared' AND attachment_revision = 1
                           AND result_keyring_revision IS NULL AND error_code IS NULL)
                         OR (status = 'applied' AND attachment_revision = 2
                           AND result_keyring_revision = expected_keyring_revision + 1
                           AND error_code IS NULL)
                         OR (status = 'conflict' AND attachment_revision = 2
                           AND result_keyring_revision IS NULL AND error_code IS NOT NULL)
                       )
                     );
                     INSERT INTO device_key_attachments
                     SELECT * FROM device_key_attachments_v22_fixture;
                     DROP TABLE device_key_attachments_v22_fixture;
                     CREATE INDEX device_key_attachment_status_idx
                       ON device_key_attachments(
                         tenant_id, project_id, status, updated_at
                       );
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 22;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v21");
            assert_eq!(store.schema_version().expect("v21 schema"), 21);
            let old_schema: String = store
                .connection
                .query_row(
                    "SELECT sql FROM sqlite_master
                     WHERE type = 'table' AND name = 'device_key_attachments'",
                    [],
                    |row| row.get(0),
                )
                .expect("v21 attachment schema");
            assert!(!old_schema.contains("public_key_handoff"));
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v22");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        let attachment_schema: String = migrated
            .connection
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'table' AND name = 'device_key_attachments'",
                [],
                |row| row.get(0),
            )
            .expect("v22 attachment schema");
        assert!(attachment_schema.contains("public_key_handoff"));
        assert_eq!(
            migrated
                .connection
                .query_row(
                    "SELECT name FROM sqlite_master
                     WHERE type = 'table' AND name = 'key_bootstrap_operations'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("bootstrap ledger"),
            "key_bootstrap_operations"
        );
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v21")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);
        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v21")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test proves encrypted backup, legacy confirmation conversion, forged-state fail-closed behavior, and idempotent reopen"
    )]
    fn migration_v23_backs_up_v22_and_installs_identity_decision_history() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("identity-history-v22.sqlite3");
        let project = project(
            "project-identity-history-migration",
            "/tmp/project-identity-history-migration",
        );
        let company = Company::create(
            CompanyId::from("company-identity-history-migration"),
            project.tenant_id.clone(),
            project.id.clone(),
            "Identity customer",
            "DE",
        )
        .expect("company");
        let external_identity = ExternalIdentity {
            provider: "commerce-fixture".into(),
            account_id: AccountId::from("account-identity-history"),
            external_subject_digest: "c".repeat(64),
            encrypted_subject_ref: "ciphertext://identity-history/customer".into(),
            evidence_digest: "d".repeat(64),
        };
        let mut confirmed = IdentityLink::propose(
            IdentityLinkId::from("identity-history-confirmed"),
            project.tenant_id.clone(),
            project.id.clone(),
            IdentitySubject::Company(company.id.clone()),
            [external_identity.clone()],
            rust_decimal::Decimal::ONE,
        )
        .expect("confirmed proposal");
        let forged = IdentityLink::propose(
            IdentityLinkId::from("identity-history-forged"),
            project.tenant_id.clone(),
            project.id.clone(),
            IdentitySubject::Company(company.id.clone()),
            [external_identity],
            rust_decimal::Decimal::ONE,
        )
        .expect("forged proposal seed");

        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store
                .create_company(
                    &company,
                    "company.created",
                    &serde_json::json!({"companyId": company.id}),
                    now(),
                )
                .expect("company persisted");
            store
                .create_identity_link(
                    &confirmed,
                    "identity_link.proposed",
                    &serde_json::json!({"identityLinkId": confirmed.id}),
                    now(),
                )
                .expect("proposal persisted");
            confirmed
                .confirm(
                    ActorId::from("identity-reviewer"),
                    "d".repeat(64),
                    now() + Duration::minutes(1),
                )
                .expect("confirmation");
            store
                .update_identity_link(
                    &confirmed,
                    1,
                    "identity_link.confirmed",
                    &serde_json::json!({"identityLinkId": confirmed.id}),
                    now() + Duration::minutes(1),
                )
                .expect("confirmation persisted");
            store
                .create_identity_link(
                    &forged,
                    "identity_link.proposed",
                    &serde_json::json!({"identityLinkId": forged.id}),
                    now(),
                )
                .expect("forged proposal seed persisted");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     ALTER TABLE identity_links RENAME TO identity_links_v23_fixture;
                     DROP INDEX identity_link_status_idx;
                     CREATE TABLE identity_links (
                       id TEXT NOT NULL,
                       tenant_id TEXT NOT NULL,
                       project_id TEXT NOT NULL,
                       subject_json TEXT NOT NULL,
                       identities_json TEXT NOT NULL,
                       confidence TEXT NOT NULL,
                       status TEXT NOT NULL,
                       confirmed_by TEXT,
                       confirmed_at TEXT,
                       revision INTEGER NOT NULL CHECK (revision > 0),
                       PRIMARY KEY (project_id, id),
                       FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                     );
                     INSERT INTO identity_links
                       (id, tenant_id, project_id, subject_json, identities_json, confidence,
                        status, confirmed_by, confirmed_at, revision)
                     SELECT id, tenant_id, project_id, subject_json, identities_json, confidence,
                            status, confirmed_by, confirmed_at, revision
                     FROM identity_links_v23_fixture;
                     DROP TABLE identity_links_v23_fixture;
                     CREATE INDEX identity_link_status_idx
                       ON identity_links(tenant_id, project_id, status);
                     UPDATE identity_links
                     SET status = 'conflicted'
                     WHERE id = 'identity-history-forged';
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 23;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v22");
            assert_eq!(store.schema_version().expect("v22 schema"), 22);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v23");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_identity_link(&project.id, &confirmed.id)
                .expect("legacy confirmation survives"),
            confirmed
        );
        assert!(matches!(
            migrated.load_identity_link(&project.id, &forged.id),
            Err(StorageError::DomainDecode(_))
        ));
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v22")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v22")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test carries a complete historical schema teardown and backup/reopen proof"
    )]
    fn migration_v24_backs_up_v23_and_installs_durable_rate_limit_ledgers() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("effect-rate-limit-v23.sqlite3");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store
                .save_project(&project(
                    "project-rate-limit-migration",
                    "/tmp/project-rate-limit-migration",
                ))
                .expect("project");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 24;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v23");
            assert_eq!(store.schema_version().expect("v23 schema"), 23);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v24");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        let installed = migrated
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                   'effect_rate_limit_buckets',
                   'effect_rate_limit_reservations',
                   'effect_rate_limit_decisions'
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("rate-limit ledgers");
        assert_eq!(installed, 3);
        let bucket_schema = migrated
            .connection
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'table' AND name = 'effect_rate_limit_buckets'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("rate-limit bucket schema");
        assert!(bucket_schema.contains("consumed <= max_executions"));
        assert!(bucket_schema.contains("policy_digest"));
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v23")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);
        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v23")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    fn migration_v25_backs_up_v24_and_installs_reconciliation_ledgers() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("effect-reconciliation-v24.sqlite3");
        {
            let store = ProjectStore::open(&database, &database_key()).expect("current store");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 25;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v24");
            assert_eq!(store.schema_version().expect("v24 schema"), 24);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v25");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        let installed = migrated
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                   'effect_reconciliation_heads', 'effect_reconciliation_attempts'
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("reconciliation ledgers");
        assert_eq!(installed, 2);
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v24")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);
        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v24")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test carries a complete historical schema teardown and backup/reopen proof"
    )]
    fn migration_v26_backs_up_v25_and_installs_context_foundation_ledgers() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("context-foundation-v25.sqlite3");
        let project = project(
            "project-context-foundation-migration",
            "/tmp/project-context-foundation-migration",
        );
        let mission = mission(
            &project.id.to_string(),
            "mission-context-foundation-migration",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 26;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v25");
            assert_eq!(store.schema_version().expect("v25 schema"), 25);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v26");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        let installed = migrated
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                   'context_working_sets', 'context_working_items',
                   'context_continuation_ledgers', 'context_continuation_entries',
                   'context_compaction_records', 'context_checkpoints'
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("context foundation ledgers");
        assert_eq!(installed, 6);
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v25")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v25")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    fn migration_v27_backs_up_v26_and_installs_context_collaboration_ledgers() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("context-collaboration-v26.sqlite3");
        let project = project(
            "project-context-collaboration-migration",
            "/tmp/project-context-collaboration-migration",
        );
        let mission = mission(
            &project.id.to_string(),
            "mission-context-collaboration-migration",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 27;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v26");
            assert_eq!(store.schema_version().expect("v26 schema"), 26);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v27");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        let installed = migrated
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                   'context_worker_handles', 'context_worker_mailboxes',
                   'context_worker_messages', 'context_branch_merges'
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("context collaboration ledgers");
        assert_eq!(installed, 4);
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v26")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v26")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    fn migration_v28_backs_up_v27_and_installs_runtime_recovery_ledger() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("runtime-recovery-v27.sqlite3");
        let project = project(
            "project-runtime-recovery-migration",
            "/tmp/project-runtime-recovery-migration",
        );
        let mission = mission(
            &project.id.to_string(),
            "mission-runtime-recovery-migration",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 28;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v27");
            assert_eq!(store.schema_version().expect("v27 schema"), 27);
        }

        let migrated =
            ProjectStore::open(&database, &database_key()).expect("migrate through v28 to current");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        let installed = migrated
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'runtime_recovery_attempts'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("runtime recovery ledger");
        assert_eq!(installed, 1);
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v27")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v27")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    fn migration_v29_backs_up_v28_and_installs_content_free_context_assembly_ledger() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("context-assembly-v28.sqlite3");
        let project = project(
            "project-context-assembly-migration",
            "/tmp/project-context-assembly-migration",
        );
        let mission = mission(
            &project.id.to_string(),
            "mission-context-assembly-migration",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 29;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v28");
            assert_eq!(store.schema_version().expect("v28 schema"), 28);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v29");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        let installed = migrated
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'context_assembly_manifests'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("context assembly ledger");
        assert_eq!(installed, 1);
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v28")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v28")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    fn migration_v30_backs_up_v29_and_installs_runtime_turn_ledgers() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("runtime-turn-v29.sqlite3");
        let project = project(
            "project-runtime-turn-migration",
            "/tmp/runtime-turn-migration",
        );
        let mission = mission(&project.id.to_string(), "mission-runtime-turn-migration");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 30;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v29");
            assert_eq!(store.schema_version().expect("v29 schema"), 29);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v30");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        for table in ["runtime_turn_attempts", "runtime_turn_evidence"] {
            let installed = migrated
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get::<_, i64>(0),
                )
                .expect("runtime turn ledger");
            assert_eq!(installed, 1, "{table}");
        }
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v29")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v29")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    fn migration_v31_backs_up_v30_and_installs_tokenizer_profile_projection() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("context-tokenizer-v30.sqlite3");
        let project = project(
            "project-context-tokenizer-migration",
            "/tmp/context-tokenizer-migration",
        );
        let mission = mission(
            &project.id.to_string(),
            "mission-context-tokenizer-migration",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 31;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v30");
            assert_eq!(store.schema_version().expect("v30 schema"), 30);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to v31");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission(&project.id, &mission.id)
                .expect("pre-existing mission survives"),
            mission
        );
        for object in [
            ("table", "context_assembly_tokenizer_profiles"),
            ("index", "context_assembly_tokenizer_scope_idx"),
        ] {
            let installed = migrated
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
                    [object.0, object.1],
                    |row| row.get::<_, i64>(0),
                )
                .expect("tokenizer profile schema object");
            assert_eq!(installed, 1, "{}", object.1);
        }
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v30")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v30")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test constructs an actual v15 database, traverses every later migration, and verifies exact rebinding plus fail-closed recovery"
    )]
    fn migration_from_v15_backs_up_rebinds_and_reaches_the_current_schema() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("conversation-v15.sqlite3");
        let project = project(
            "project-conversation-migration",
            "/tmp/project-conversation-migration",
        );
        let mission = mission(&project.id.to_string(), "mission-conversation-migration");
        let company = Company::create(
            CompanyId::from("company-conversation-migration"),
            project.tenant_id.clone(),
            project.id.clone(),
            "Migration customer",
            "DE",
        )
        .expect("company");
        let person = Person::create(
            PersonId::from("person-conversation-migration"),
            project.tenant_id.clone(),
            project.id.clone(),
            "Migration correspondent",
            Some(company.id.clone()),
            vec![],
        )
        .expect("person");
        let exact_connection = ProviderConnection::register(
            ConnectionId::from("connection-conversation-migration"),
            project.tenant_id.clone(),
            project.id.clone(),
            "gmail",
            AccountId::from("gmail-account-migration"),
            "migration-owner@example.invalid",
            ["messages.send".into()],
            now(),
        )
        .expect("exact connection");
        let unresolved_connection = ProviderConnection::register(
            ConnectionId::from("connection-conversation-unresolved"),
            project.tenant_id.clone(),
            project.id.clone(),
            "gmail",
            AccountId::from("gmail-account-unresolved"),
            "unresolved-owner@example.invalid",
            ["messages.send".into()],
            now(),
        )
        .expect("unresolved connection");
        let exact_conversation = Conversation::open(
            ConversationId::from("conversation-migration-exact"),
            project.tenant_id.clone(),
            project.id.clone(),
            Some(mission.id.clone()),
            person.id.clone(),
            Some(company.id.clone()),
            MessagingGateway::Gmail,
            "gmail",
            exact_connection.id().clone(),
            exact_connection.account_id().clone(),
            "1".repeat(64),
            ContactChannel::Email,
            "DE",
            now(),
        )
        .expect("exact conversation");
        let unresolved_conversation = Conversation::open(
            ConversationId::from("conversation-migration-unresolved"),
            project.tenant_id.clone(),
            project.id.clone(),
            Some(mission.id.clone()),
            person.id.clone(),
            Some(company.id.clone()),
            MessagingGateway::Gmail,
            "gmail",
            unresolved_connection.id().clone(),
            unresolved_connection.account_id().clone(),
            "2".repeat(64),
            ContactChannel::Email,
            "DE",
            now(),
        )
        .expect("unresolved conversation");

        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("current store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .create_company(&company, "company.created", &serde_json::json!({}), now())
                .expect("company");
            store
                .create_person(&person, "person.created", &serde_json::json!({}), now())
                .expect("person");
            store
                .create_connection(
                    &exact_connection,
                    "connection.created",
                    &serde_json::json!({}),
                    now(),
                )
                .expect("exact connection");
            store
                .create_connection(
                    &unresolved_connection,
                    "connection.created",
                    &serde_json::json!({}),
                    now(),
                )
                .expect("unresolved connection");
            store
                .create_conversation(
                    &exact_conversation,
                    "conversation.opened",
                    &serde_json::json!({}),
                    now(),
                )
                .expect("exact conversation");
            store
                .create_conversation(
                    &unresolved_conversation,
                    "conversation.opened",
                    &serde_json::json!({}),
                    now(),
                )
                .expect("unresolved conversation");

            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants; DROP TABLE browser_control_transitions; DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces; DROP TABLE browser_profiles; DROP TABLE context_assembly_tokenizer_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     ALTER TABLE identity_links DROP COLUMN decision_history_json;
                     UPDATE conversations
                     SET record_json = json_remove(record_json, '$.provider', '$.connectionId');
                     DROP TABLE key_bootstrap_operations;
                     DROP TABLE device_key_attachments;
                     DROP TABLE deletion_propagation_receipts;
                     DROP TABLE deletion_propagation_jobs;
                     DROP TABLE sync_deletion_records;
                     DROP TABLE context_capsule_facts;
                     DROP TABLE context_capsules;
                     DROP TABLE worker_leases;
                     DROP TABLE context_branches;
                     DROP TABLE context_workspaces;
                     DROP INDEX conversation_connection_idx;
                     ALTER TABLE conversations DROP COLUMN provider;
                     ALTER TABLE conversations DROP COLUMN connection_id;
                     DROP INDEX outcome_event_source_verification_idx;
                     ALTER TABLE outcome_events DROP COLUMN connection_id;
                     ALTER TABLE outcome_events DROP COLUMN source_verification_method;
                     ALTER TABLE outcome_events DROP COLUMN source_verifier;
                     ALTER TABLE outcome_events DROP COLUMN source_verification_independent;
                     ALTER TABLE outcome_events DROP COLUMN source_verified_at;
                     ALTER TABLE outcome_events DROP COLUMN source_verification_evidence_digest;
                     DELETE FROM connections
                     WHERE id = 'connection-conversation-unresolved';
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 16;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to schema v15");
            assert_eq!(store.schema_version().expect("v15 schema"), 15);
        }

        let migrated = ProjectStore::open(&database, &database_key()).expect("migrate to current");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        let exact = migrated
            .load_conversation(&project.id, &exact_conversation.id)
            .expect("exactly rebound conversation");
        assert_eq!(
            (exact.provider.as_str(), &exact.connection_id, &exact.state),
            ("gmail", exact_connection.id(), &ConversationState::Open)
        );
        let unresolved = migrated
            .load_conversation(&project.id, &unresolved_conversation.id)
            .expect("unresolved legacy conversation remains inspectable");
        assert_eq!(unresolved.provider, "gmail");
        assert!(
            unresolved
                .connection_id
                .as_str()
                .starts_with("legacy-unresolved:")
        );
        assert_eq!(unresolved.state, ConversationState::DeadLetter);
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v15")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);

        let reopened = ProjectStore::open(&database, &database_key()).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("schema"),
            STORAGE_SCHEMA_VERSION
        );
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v15")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    fn generic_project_writes_cannot_bypass_the_cloud_registration_cell_saga() {
        let mut store = ProjectStore::in_memory().expect("store");
        let mut project = Project::create_local(
            hartevo_domain_kernel::TenantId::from("tenant-1"),
            ProjectId::from("project-cell-boundary"),
            "Cell boundary",
            "",
            "/tmp/project-cell-boundary",
            StorageMode::LocalEncryptedSync,
        )
        .expect("project");
        store.save_project(&project).expect("initial project");
        project
            .select_data_cell(hartevo_domain_kernel::ProjectDataCell::Eu)
            .expect("domain selection candidate");

        assert!(matches!(
            store.save_project(&project),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "project scope or data Cell",
                ..
            })
        ));
        assert!(matches!(
            store.update_project_atomic(
                &project,
                1,
                &[aggregate::PendingEvent::new(
                    "project.updated",
                    serde_json::json!({}),
                    now(),
                )],
            ),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "project scope or data Cell",
                ..
            })
        ));
        assert_eq!(
            store
                .load_project(&project.id)
                .expect("unchanged project")
                .data_cell,
            None
        );

        let mut forged_initial = project;
        forged_initial.id = ProjectId::from("forged-initial-cell");
        forged_initial.revision = 1;
        assert!(matches!(
            store.save_project(&forged_initial),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "project data Cell selection",
                ..
            })
        ));
    }

    #[test]
    fn normalized_mission_persists_every_continuous_outcome_cycle() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project("project-cycles", "/tmp/project-cycles");
        store.save_project(&project).expect("project");
        let mut contract = MissionContract::bootstrap("Operate every week", [], now());
        contract.mode = OperatingMode::ContinuousOperator;
        contract.cadence = Some(Cadence {
            interval_seconds: 604_800,
            anchor_at: now(),
            trigger: hartevo_domain_kernel::CadenceTriggerKind::Interval,
            event_topics: BTreeSet::new(),
        });
        let mut mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-cycles"),
            project.id.clone(),
            "Continuous cycles",
            contract,
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("cycle one");
        mission
            .record_outcome(Outcome {
                summary: "Cycle one reviewed".into(),
                decision: OutcomeDecision::Continue,
                metrics: BTreeMap::new(),
                observed_at: now() + Duration::days(7),
            })
            .expect("outcome one");
        mission
            .start_scheduled_cycle(2, [], now() + Duration::days(8))
            .expect("cycle two");
        mission
            .record_outcome(Outcome {
                summary: "Cycle two stopped honestly".into(),
                decision: OutcomeDecision::Stop,
                metrics: BTreeMap::new(),
                observed_at: now() + Duration::days(14),
            })
            .expect("outcome two");
        store.save_mission(&mission).expect("mission persisted");

        let restored = store
            .load_mission(&project.id, &mission.id)
            .expect("mission restored");
        assert_eq!(restored.stage, MissionStage::Completed);
        assert_eq!(restored.outcome_history.len(), 2);
        assert_eq!(restored.outcome, restored.outcome_history.last().cloned());
    }

    #[test]
    fn mission_reads_cannot_cross_project_scope() {
        let mut store = ProjectStore::in_memory().expect("store");
        let first = project("project-a", "/tmp/project-a");
        let second = project("project-b", "/tmp/project-b");
        let mission = mission("project-a", "mission-a");
        store.save_project(&first).expect("first");
        store.save_project(&second).expect("second");
        store.save_mission(&mission).expect("mission");

        let result = store.load_mission(&second.id, &mission.id);
        assert!(matches!(result, Err(StorageError::MissionNotFound { .. })));
    }

    #[test]
    fn event_log_is_append_only_and_ordered() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project("project-a", "/tmp/project-a");
        let mission = mission("project-a", "mission-a");
        store.save_project(&project).expect("project");
        store.save_mission(&mission).expect("mission");
        store
            .append_event(
                &project.id,
                Some(&mission.id),
                "mission.started",
                &serde_json::json!({"revision": 1}),
                now(),
            )
            .expect("first event");
        store
            .append_event(
                &project.id,
                Some(&mission.id),
                "goal.confirmed",
                &serde_json::json!({"goal": "Create the launch brief"}),
                now(),
            )
            .expect("second event");

        let events = store
            .events_for_mission(&project.id, &mission.id)
            .expect("events");
        assert_eq!(events.len(), 2);
        assert!(events[0].sequence < events[1].sequence);
        assert_eq!(events[1].event_type, "goal.confirmed");
    }

    #[test]
    fn sqlcipher_file_rejects_wrong_key_and_contains_no_plaintext_project_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("encrypted.sqlite3");
        let project = project("project-secret", "/tmp/project-secret");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            store.save_project(&project).expect("project");
        }
        let bytes = fs::read(&database).expect("encrypted database bytes");
        assert!(
            !bytes
                .windows(b"project-secret".len())
                .any(|window| { window == b"project-secret" })
        );
        let wrong_key = DatabaseKey::new([8; 32]).expect("wrong key shape");
        assert!(ProjectStore::open(&database, &wrong_key).is_err());
        assert!(ProjectStore::open(&database, &database_key()).is_ok());
    }

    #[test]
    fn expired_execution_lease_freezes_effect_instead_of_replaying_provider_write() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project("project-a", "/tmp/project-a");
        let (mission, effect) = approved_effect("project-a", "mission-a");
        store.save_project(&project).expect("project");
        store.save_mission(&mission).expect("mission");
        let claim_context = effect_claim_context(&effect);

        let first = store
            .claim(
                &effect,
                Some(&claim_context),
                "worker-a",
                now(),
                now() + Duration::seconds(1),
            )
            .expect("first lease");
        assert!(matches!(first, LedgerClaim::Acquired { .. }));
        let second = store
            .claim(
                &effect,
                None,
                "worker-b",
                now() + Duration::seconds(2),
                now() + Duration::seconds(32),
            )
            .expect("expired lease reconciliation");
        assert!(matches!(second, LedgerClaim::Uncertain { .. }));
        let third = store
            .claim(
                &effect,
                None,
                "worker-c",
                now() + Duration::seconds(3),
                now() + Duration::seconds(33),
            )
            .expect("frozen ledger");
        assert!(matches!(third, LedgerClaim::Uncertain { .. }));
    }

    #[test]
    fn recovery_probe_without_authorization_never_creates_execution_or_rate_limit_state() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project("project-recovery-probe", "/tmp/project-recovery-probe");
        let (mission, effect) = approved_effect("project-recovery-probe", "mission-recovery-probe");
        store.save_project(&project).expect("project");
        store.save_mission(&mission).expect("mission");

        assert_eq!(
            store
                .claim(
                    &effect,
                    None,
                    "recovery-probe",
                    now(),
                    now() + Duration::seconds(30),
                )
                .expect("read-only recovery probe"),
            LedgerClaim::AuthorizationRequired
        );
        let claim_context = effect_claim_context(&effect);
        assert_eq!(
            store.claim(
                &effect,
                Some(&claim_context),
                "expired-direct-dispatch",
                now() + Duration::hours(1),
                now() + Duration::hours(1) + Duration::seconds(30),
            ),
            Err(hartevo_effect_broker::LedgerError::DispatchNotAuthorized)
        );
        let counts = store
            .connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM effect_idempotency),
                   (SELECT COUNT(*) FROM execution_attempts),
                   (SELECT COUNT(*) FROM effect_rate_limit_buckets),
                   (SELECT COUNT(*) FROM effect_rate_limit_reservations),
                   (SELECT COUNT(*) FROM effect_rate_limit_decisions)",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .expect("ledger counts");
        assert_eq!(counts, (0, 0, 0, 0, 0));
    }

    #[test]
    fn corrupted_durable_receipt_fails_closed_before_a_verification_lease_is_created() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project("project-corrupt-receipt", "/tmp/project-corrupt-receipt");
        let (mission, effect) =
            approved_effect("project-corrupt-receipt", "mission-corrupt-receipt");
        let claim_context = effect_claim_context(&effect);
        store.save_project(&project).expect("project");
        store.save_mission(&mission).expect("mission");
        let LedgerClaim::Acquired { lease, .. } = store
            .claim(
                &effect,
                Some(&claim_context),
                "execution-worker",
                now(),
                now() + Duration::seconds(30),
            )
            .expect("execution claim")
        else {
            panic!("expected execution claim")
        };
        let receipt = Receipt {
            id: ReceiptId::from("receipt-corrupt"),
            provider: effect.provider.clone(),
            external_id: "external-corrupt".into(),
            accepted_at: now() + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "6".repeat(64),
        };
        store
            .record_receipt(&effect, &lease, &receipt, now() + Duration::seconds(1))
            .expect("durable receipt");
        let mut corrupted = receipt;
        corrupted.request_digest = "7".repeat(64);
        store
            .connection
            .execute(
                "UPDATE effect_idempotency SET receipt_json = ?2 WHERE project_id = ?1",
                params![
                    effect.project_id.as_str(),
                    serde_json::to_string(&corrupted).expect("corrupt receipt json"),
                ],
            )
            .expect("simulate receipt corruption");

        assert!(matches!(
            store.claim(
                &effect,
                None,
                "verification-worker",
                now() + Duration::seconds(2),
                now() + Duration::seconds(32),
            ),
            Err(hartevo_effect_broker::LedgerError::Persistence(_))
        ));
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM execution_attempts WHERE project_id = ?1",
                    params![effect.project_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("attempt count"),
            1
        );
    }

    #[test]
    fn durable_rate_limit_reserves_once_denies_without_an_execution_ledger_and_reopens_next_window()
    {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project("project-rate-limit", "/tmp/project-rate-limit");
        let (first_mission, first_effect) = approved_effect_named(
            "project-rate-limit",
            "mission-rate-limit-1",
            "effect-rate-limit-1",
            "rate-limit-idempotency-1",
        );
        let (second_mission, second_effect) = approved_effect_named(
            "project-rate-limit",
            "mission-rate-limit-2",
            "effect-rate-limit-2",
            "rate-limit-idempotency-2",
        );
        let first_context = effect_claim_context(&first_effect);
        let second_context = effect_claim_context(&second_effect);
        assert_eq!(
            first_context.rate_limit.scope_digest,
            second_context.rate_limit.scope_digest
        );
        store.save_project(&project).expect("project");
        store.save_mission(&first_mission).expect("first mission");
        store.save_mission(&second_mission).expect("second mission");

        let first = store
            .claim(
                &first_effect,
                Some(&first_context),
                "worker-rate-limit-1",
                now(),
                now() + Duration::seconds(30),
            )
            .expect("first reservation");
        assert!(matches!(first, LedgerClaim::Acquired { .. }));
        let denied = store
            .claim(
                &second_effect,
                Some(&second_context),
                "worker-rate-limit-2",
                now() + Duration::seconds(1),
                now() + Duration::seconds(31),
            )
            .expect("deterministic denial");
        assert_eq!(
            denied,
            LedgerClaim::RateLimited {
                retry_at: now() + Duration::seconds(60),
            }
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM effect_idempotency WHERE effect_id = ?1",
                    [second_effect.id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("denied idempotency count"),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM execution_attempts WHERE effect_id = ?1",
                    [second_effect.id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("denied attempt count"),
            0
        );

        let next_window = store
            .claim(
                &second_effect,
                Some(&second_context),
                "worker-rate-limit-2",
                now() + Duration::seconds(60),
                now() + Duration::seconds(90),
            )
            .expect("next window reservation");
        assert!(matches!(next_window, LedgerClaim::Acquired { .. }));
        let (buckets, reservations, reserved, denied) = store
            .connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM effect_rate_limit_buckets),
                   (SELECT COUNT(*) FROM effect_rate_limit_reservations),
                   (SELECT COUNT(*) FROM effect_rate_limit_decisions WHERE decision = 'reserved'),
                   (SELECT COUNT(*) FROM effect_rate_limit_decisions WHERE decision = 'denied')",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .expect("rate-limit audit counts");
        assert_eq!((buckets, reservations, reserved, denied), (2, 2, 2, 1));
    }

    #[test]
    fn two_sqlcipher_connections_cannot_over_reserve_one_rate_limit_slot() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("rate-limit-race.sqlite3");
        let project = project("project-rate-limit-race", "/tmp/project-rate-limit-race");
        let (first_mission, first_effect) = approved_effect_named(
            "project-rate-limit-race",
            "mission-rate-limit-race-1",
            "effect-rate-limit-race-1",
            "rate-limit-race-idempotency-1",
        );
        let (second_mission, second_effect) = approved_effect_named(
            "project-rate-limit-race",
            "mission-rate-limit-race-2",
            "effect-rate-limit-race-2",
            "rate-limit-race-idempotency-2",
        );
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            store.save_project(&project).expect("project");
            store.save_mission(&first_mission).expect("first mission");
            store.save_mission(&second_mission).expect("second mission");
        }
        let barrier = Arc::new(Barrier::new(2));
        let handles = [first_effect, second_effect]
            .into_iter()
            .enumerate()
            .map(|(index, effect)| {
                let database = database.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut store =
                        ProjectStore::open(&database, &database_key()).expect("thread store");
                    let claim_context = effect_claim_context(&effect);
                    barrier.wait();
                    store
                        .claim(
                            &effect,
                            Some(&claim_context),
                            &format!("rate-limit-racer-{index}"),
                            now(),
                            now() + Duration::seconds(30),
                        )
                        .expect("serialized claim")
                })
            })
            .collect::<Vec<_>>();
        let claims = handles
            .into_iter()
            .map(|handle| handle.join().expect("claim thread"))
            .collect::<Vec<_>>();

        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, LedgerClaim::Acquired { .. }))
                .count(),
            1
        );
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, LedgerClaim::RateLimited { .. }))
                .count(),
            1
        );
        let store = ProjectStore::open(&database, &database_key()).expect("audit store");
        let (consumed, reservations) = store
            .connection
            .query_row(
                "SELECT
                   (SELECT consumed FROM effect_rate_limit_buckets),
                   (SELECT COUNT(*) FROM effect_rate_limit_reservations)",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("rate-limit race audit");
        assert_eq!((consumed, reservations), (1, 1));
    }

    #[test]
    fn receipt_and_verification_survive_restart_without_second_execution_claim() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("effect-ledger.sqlite3");
        let project = project("project-a", "/tmp/project-a");
        let (mission, effect) = approved_effect("project-a", "mission-a");
        let claim_context = effect_claim_context(&effect);
        let receipt = Receipt {
            id: ReceiptId::from("receipt-1"),
            provider: "fixture-provider".into(),
            external_id: "external-1".into(),
            accepted_at: now() + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "2".repeat(64),
        };
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            let LedgerClaim::Acquired {
                lease,
                receipt: None,
                ..
            } = store
                .claim(
                    &effect,
                    Some(&claim_context),
                    "worker-a",
                    now(),
                    now() + Duration::seconds(30),
                )
                .expect("claim")
            else {
                panic!("expected first execution lease")
            };
            store
                .record_receipt(&effect, &lease, &receipt, now() + Duration::seconds(1))
                .expect("durable receipt");
        }

        let verification = Verification {
            id: VerificationId::from("verification-1"),
            status: VerificationStatus::Confirmed,
            verifier: "independent-readback".into(),
            independent: true,
            observed_at: now() + Duration::seconds(2),
            evidence_digest: "3".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("reopen");
            let LedgerClaim::Acquired {
                lease,
                receipt: Some(reused),
                ..
            } = store
                .claim(
                    &effect,
                    None,
                    "worker-b",
                    now() + Duration::seconds(2),
                    now() + Duration::seconds(32),
                )
                .expect("verification claim")
            else {
                panic!("receipt should be reused without a second provider execution")
            };
            assert_eq!(reused, receipt);
            store
                .record_verification(&effect, &lease, &verification, now() + Duration::seconds(2))
                .expect("durable verification");
        }
        let mut store = ProjectStore::open(&database, &database_key()).expect("final reopen");
        let claim = store
            .claim(
                &effect,
                None,
                "worker-c",
                now() + Duration::seconds(3),
                now() + Duration::seconds(33),
            )
            .expect("verified claim");
        assert_eq!(
            claim,
            LedgerClaim::AlreadyVerified {
                receipt,
                verification,
                execution_started_at: now(),
            }
        );
    }

    #[test]
    fn provider_rejection_survives_restart_as_typed_non_replayable_state() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("provider-rejection-ledger.sqlite3");
        let project = project(
            "project-provider-rejection",
            "/tmp/project-provider-rejection",
        );
        let (mission, effect) =
            approved_effect("project-provider-rejection", "mission-provider-rejection");
        let claim_context = effect_claim_context(&effect);
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            let LedgerClaim::Acquired {
                lease,
                receipt: None,
                execution_started_at,
            } = store
                .claim(
                    &effect,
                    Some(&claim_context),
                    "provider-rejection-worker",
                    now(),
                    now() + Duration::seconds(30),
                )
                .expect("execution claim")
            else {
                panic!("expected initial execution claim")
            };
            assert_eq!(execution_started_at, now());
            store
                .record_failed(
                    &effect,
                    &lease,
                    "provider rejected exact payload",
                    now() + Duration::seconds(2),
                )
                .expect("durable rejection");
        }

        let mut store = ProjectStore::open(&database, &database_key()).expect("reopen");
        assert_eq!(
            store
                .claim(
                    &effect,
                    None,
                    "recovery-only-worker",
                    now() + Duration::hours(2),
                    now() + Duration::hours(2) + Duration::seconds(30),
                )
                .expect("typed durable rejection"),
            LedgerClaim::ProviderRejected {
                reason: "provider rejected exact payload".into(),
                execution_started_at: now(),
                recorded_at: now() + Duration::seconds(2),
            }
        );
    }

    #[test]
    fn uncertain_reconciliation_receipt_survives_restarts_without_execution_replay() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("reconciliation-receipt.sqlite3");
        let project = project(
            "project-reconcile-receipt",
            "/tmp/project-reconcile-receipt",
        );
        let (mission, effect) =
            approved_effect("project-reconcile-receipt", "mission-reconcile-receipt");
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            assert_eq!(
                persist_uncertain_effect(&mut store, &project, &mission, &effect),
                now()
            );
        }
        let policy = ReconciliationPolicy {
            version: "reconcile-receipt-v1".into(),
            max_attempts: 3,
            retry_delay_seconds: 10,
        };
        schedule_reconciliation_retry(&database, &effect, &policy);
        let (receipt, verification) = reconcile_receipt_and_verify(&database, &effect, &policy);
        let mut store = ProjectStore::open(&database, &database_key()).expect("final reopen");
        assert_eq!(
            store
                .claim(
                    &effect,
                    None,
                    "recovery-reader",
                    now() + Duration::seconds(14),
                    now() + Duration::seconds(44),
                )
                .expect("verified terminal"),
            LedgerClaim::AlreadyVerified {
                receipt,
                verification,
                execution_started_at: now(),
            }
        );
        let counts = store
            .connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM execution_attempts WHERE effect_id = ?1),
                   (SELECT COUNT(*) FROM effect_reconciliation_attempts WHERE effect_id = ?1)",
                params![effect.id.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("attempt audit");
        assert_eq!(counts, (2, 2));
    }

    #[test]
    fn reconciliation_not_executed_is_restart_safe_and_requires_a_new_effect() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("reconciliation-not-executed.sqlite3");
        let project = project("project-reconcile-none", "/tmp/project-reconcile-none");
        let (mission, effect) = approved_effect("project-reconcile-none", "mission-reconcile-none");
        let policy = ReconciliationPolicy::default();
        let evidence_digest = "e".repeat(64);
        {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            persist_uncertain_effect(&mut store, &project, &mission, &effect);
            let ReconciliationClaim::Acquired { lease, .. } = store
                .claim_reconciliation(
                    &effect,
                    &policy,
                    "not-executed-worker",
                    now() + Duration::seconds(2),
                    now() + Duration::seconds(32),
                )
                .expect("reconciliation claim")
            else {
                panic!("expected reconciliation lease")
            };
            assert!(matches!(
                store
                    .record_reconciliation(
                        &effect,
                        &lease,
                        &ReconciliationObservation::NotExecuted {
                            evidence_digest: evidence_digest.clone(),
                            observed_at: now() + Duration::seconds(2),
                        },
                        now() + Duration::seconds(2),
                    )
                    .expect("not-executed terminal"),
                ReconciliationDisposition::ReconciledNotExecuted { .. }
            ));
        }
        let mut store = ProjectStore::open(&database, &database_key()).expect("reopen");
        let expected = LedgerClaim::ReconciledNotExecuted {
            evidence_digest,
            observed_at: now() + Duration::seconds(2),
            execution_started_at: now(),
        };
        assert_eq!(
            store
                .claim(
                    &effect,
                    None,
                    "execution-recovery-probe",
                    now() + Duration::seconds(3),
                    now() + Duration::seconds(33),
                )
                .expect("terminal normal claim"),
            expected
        );
        assert_eq!(
            store
                .claim_reconciliation(
                    &effect,
                    &policy,
                    "reconciliation-recovery-probe",
                    now() + Duration::seconds(3),
                    now() + Duration::seconds(33),
                )
                .expect("terminal reconciliation claim"),
            ReconciliationClaim::Resolved(expected)
        );
    }

    #[test]
    fn exhausted_reconciliation_dead_letters_and_rejects_stale_lease_completion() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("reconciliation-dead-letter.sqlite3");
        let project = project("project-reconcile-dead", "/tmp/project-reconcile-dead");
        let (mission, effect) = approved_effect("project-reconcile-dead", "mission-reconcile-dead");
        let policy = ReconciliationPolicy {
            version: "dead-letter-v1".into(),
            max_attempts: 1,
            retry_delay_seconds: 60,
        };
        let observation = ReconciliationObservation::StillUncertain {
            reason: "Provider lookup remains ambiguous".into(),
            evidence_digest: "f".repeat(64),
            observed_at: now() + Duration::seconds(2),
        };
        let lease = {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            persist_uncertain_effect(&mut store, &project, &mission, &effect);
            let ReconciliationClaim::Acquired { lease, .. } = store
                .claim_reconciliation(
                    &effect,
                    &policy,
                    "dead-letter-worker",
                    now() + Duration::seconds(2),
                    now() + Duration::seconds(32),
                )
                .expect("reconciliation claim")
            else {
                panic!("expected reconciliation lease")
            };
            assert!(matches!(
                store
                    .record_reconciliation(
                        &effect,
                        &lease,
                        &observation,
                        now() + Duration::seconds(2),
                    )
                    .expect("dead letter"),
                ReconciliationDisposition::DeadLetter { attempts: 1, .. }
            ));
            lease
        };
        let mut store = ProjectStore::open(&database, &database_key()).expect("reopen");
        assert!(matches!(
            store
                .claim(
                    &effect,
                    None,
                    "execution-recovery-probe",
                    now() + Duration::seconds(3),
                    now() + Duration::seconds(33),
                )
                .expect("dead-letter terminal"),
            LedgerClaim::DeadLetter { attempts: 1, .. }
        ));
        assert_eq!(
            store.record_reconciliation(
                &effect,
                &lease,
                &observation,
                now() + Duration::seconds(3),
            ),
            Err(hartevo_effect_broker::LedgerError::LeaseLost)
        );
    }

    #[test]
    fn rejected_verification_survives_restart_with_exact_receipt_and_evidence() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory
            .path()
            .join("rejected-verification-ledger.sqlite3");
        let project = project(
            "project-rejected-verification",
            "/tmp/project-rejected-verification",
        );
        let (mission, effect) = approved_effect(
            "project-rejected-verification",
            "mission-rejected-verification",
        );
        let (receipt, verification) = {
            let mut store = ProjectStore::open(&database, &database_key()).expect("store");
            persist_rejected_verification(&mut store, &project, &mission, &effect)
        };

        let mut store = ProjectStore::open(&database, &database_key()).expect("reopen");
        assert_eq!(
            store
                .claim(
                    &effect,
                    None,
                    "recovery-only-worker",
                    now() + Duration::hours(2),
                    now() + Duration::hours(2) + Duration::seconds(30),
                )
                .expect("typed durable verification"),
            LedgerClaim::DurableVerification {
                receipt,
                verification: verification.clone(),
                execution_started_at: now(),
            }
        );
    }

    #[test]
    fn inconsistent_durable_verification_status_fails_closed() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project(
            "project-corrupt-verification",
            "/tmp/project-corrupt-verification",
        );
        let (mission, effect) = approved_effect(
            "project-corrupt-verification",
            "mission-corrupt-verification",
        );
        let (_, mut verification) =
            persist_rejected_verification(&mut store, &project, &mission, &effect);
        verification.status = VerificationStatus::Confirmed;
        store
            .connection
            .execute(
                "UPDATE effect_idempotency SET verification_json = ?2
                 WHERE project_id = ?1",
                params![
                    effect.project_id.as_str(),
                    serde_json::to_string(&verification).expect("tampered json"),
                ],
            )
            .expect("simulate corrupted durable verification");

        assert!(matches!(
            store.claim(
                &effect,
                None,
                "corruption-probe",
                now() + Duration::hours(3),
                now() + Duration::hours(3) + Duration::seconds(30),
            ),
            Err(hartevo_effect_broker::LedgerError::Persistence(_))
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn only_the_latest_verification_generation_can_finish_a_durable_receipt(
            competing_claims in 1_usize..12,
        ) {
            let mut store = ProjectStore::in_memory()?;
            let project = project("project-generation", "/tmp/project-generation");
            let (mission, effect) = approved_effect("project-generation", "mission-generation");
            let claim_context = effect_claim_context(&effect);
            store.save_project(&project)?;
            store.save_mission(&mission)?;
            let LedgerClaim::Acquired {
                lease: execution_lease,
                receipt: None,
                ..
            } = store.claim(
                &effect,
                Some(&claim_context),
                "executor",
                now(),
                now() + Duration::seconds(30),
            )?
            else {
                return Err(TestCaseError::fail("first execution claim was not acquired"));
            };
            let receipt = Receipt {
                id: ReceiptId::from("receipt-generation"),
                provider: "fixture-provider".into(),
                external_id: "external-generation".into(),
                accepted_at: now() + Duration::seconds(1),
                request_digest: effect.approval_digest(),
                response_digest: "9".repeat(64),
            };
            store.record_receipt(
                &effect,
                &execution_lease,
                &receipt,
                now() + Duration::seconds(1),
            )?;

            let mut leases = Vec::with_capacity(competing_claims);
            for index in 0..competing_claims {
                let LedgerClaim::Acquired {
                    lease,
                    receipt: Some(reused),
                    ..
                } = store.claim(
                    &effect,
                    Some(&claim_context),
                    &format!("verifier-{index}"),
                    now() + Duration::seconds(2),
                    now() + Duration::seconds(32),
                )?
                else {
                    return Err(TestCaseError::fail(
                        "durable receipt was not reused for verification",
                    ));
                };
                prop_assert_eq!(reused, receipt.clone());
                leases.push(lease);
            }
            let verification = Verification {
                id: VerificationId::from("verification-generation"),
                status: VerificationStatus::Confirmed,
                verifier: "independent-readback".into(),
                independent: true,
                observed_at: now() + Duration::seconds(3),
                evidence_digest: "8".repeat(64),
                receipt_id: receipt.id.clone(),
            };
            for stale in &leases[..leases.len() - 1] {
                prop_assert_eq!(
                    store.record_verification(
                        &effect,
                        stale,
                        &verification,
                        now() + Duration::seconds(3),
                    ),
                    Err(hartevo_effect_broker::LedgerError::LeaseLost)
                );
            }
            store.record_verification(
                &effect,
                leases.last().expect("at least one lease"),
                &verification,
                now() + Duration::seconds(3),
            )?;
            let final_claim = store.claim(
                &effect,
                Some(&claim_context),
                "late-verifier",
                now() + Duration::seconds(4),
                now() + Duration::seconds(34),
            )?;
            let already_verified = matches!(final_claim, LedgerClaim::AlreadyVerified { .. });
            prop_assert!(already_verified);
        }

        #[test]
        fn arbitrary_outbox_claim_ack_release_sequences_preserve_generation_fencing(
            actions in prop::collection::vec((0_u8..6, 0_i64..4, any::<bool>()), 1..64),
        ) {
            let mut store = ProjectStore::in_memory()?;
            let project = project("project-outbox-model", "/tmp/project-outbox-model");
            let mission = mission("project-outbox-model", "mission-outbox-model");
            store.save_project(&project)?;
            store.save_mission(&mission)?;
            store.connection.execute(
                "INSERT INTO outbox_messages
                   (tenant_id, project_id, mission_id, aggregate_type, aggregate_id,
                    event_type, payload_json, available_at, created_at)
                 VALUES (?1, ?2, ?3, 'mission', ?3, 'model.event', '{}', ?4, ?4)",
                params![
                    project.tenant_id.as_str(),
                    project.id.as_str(),
                    mission.id.as_str(),
                    now().to_rfc3339(),
                ],
            )?;
            let sequence = store.connection.last_insert_rowid();
            let mut cursor = now();
            let mut observed_leases = Vec::<(String, u64)>::new();

            for (action, advance_seconds, dead_letter) in actions {
                cursor += Duration::seconds(advance_seconds);
                let before = store.outbox_message(sequence)?;
                let mut claimed = false;
                let result = match action {
                    0 | 1 => {
                        let owner = if action == 0 { "worker-a" } else { "worker-b" };
                        let messages = store.claim_outbox(
                            owner,
                            cursor,
                            Duration::seconds(2),
                            1,
                        )?;
                        if let Some(message) = messages.first() {
                            claimed = true;
                            observed_leases.push((
                                message.lease_owner.clone().expect("leased owner"),
                                message.lease_generation,
                            ));
                        }
                        Ok(())
                    }
                    2 => {
                        let owner = before.lease_owner.as_deref().unwrap_or("no-current-owner");
                        store.acknowledge_outbox(
                            sequence,
                            owner,
                            before.lease_generation,
                            cursor,
                        )
                    }
                    3 => {
                        let stale = observed_leases.iter().find(|(owner, generation)| {
                            before.status != OutboxStatus::Leased
                                || Some(owner.as_str()) != before.lease_owner.as_deref()
                                || *generation != before.lease_generation
                        });
                        let (owner, generation) = stale
                            .cloned()
                            .unwrap_or_else(|| ("stale-worker".into(), 0));
                        store.acknowledge_outbox(sequence, &owner, generation, cursor)
                    }
                    4 => {
                        let owner = before.lease_owner.as_deref().unwrap_or("no-current-owner");
                        store.release_outbox(
                            sequence,
                            owner,
                            before.lease_generation,
                            cursor + Duration::seconds(1),
                            dead_letter,
                        )
                    }
                    _ => {
                        let stale = observed_leases.iter().find(|(owner, generation)| {
                            before.status != OutboxStatus::Leased
                                || Some(owner.as_str()) != before.lease_owner.as_deref()
                                || *generation != before.lease_generation
                        });
                        let (owner, generation) = stale
                            .cloned()
                            .unwrap_or_else(|| ("stale-worker".into(), 0));
                        store.release_outbox(
                            sequence,
                            &owner,
                            generation,
                            cursor + Duration::seconds(1),
                            dead_letter,
                        )
                    }
                };
                let after = store.outbox_message(sequence)?;

                if result.is_err() || ((action == 0 || action == 1) && !claimed) {
                    prop_assert_eq!(after.clone(), before.clone());
                } else if action == 0 || action == 1 {
                    prop_assert_eq!(after.status.clone(), OutboxStatus::Leased);
                    prop_assert_eq!(after.lease_generation, before.lease_generation + 1);
                    prop_assert_eq!(after.attempts, before.attempts + 1);
                } else if action == 2 {
                    prop_assert_eq!(after.status.clone(), OutboxStatus::Published);
                } else if action == 4 {
                    prop_assert_eq!(
                        after.status.clone(),
                        if dead_letter {
                            OutboxStatus::DeadLetter
                        } else {
                            OutboxStatus::Pending
                        },
                    );
                }

                prop_assert!(after.lease_generation >= before.lease_generation);
                prop_assert_eq!(u64::from(after.attempts), after.lease_generation);
                match &after.status {
                    OutboxStatus::Leased => {
                        prop_assert!(after.lease_owner.is_some());
                        prop_assert!(after.lease_expires_at.is_some());
                        prop_assert!(after.published_at.is_none());
                    }
                    OutboxStatus::Published => {
                        prop_assert!(after.lease_owner.is_none());
                        prop_assert!(after.lease_expires_at.is_none());
                        prop_assert!(after.published_at.is_some());
                    }
                    OutboxStatus::Pending | OutboxStatus::DeadLetter => {
                        prop_assert!(after.lease_owner.is_none());
                        prop_assert!(after.lease_expires_at.is_none());
                        prop_assert!(after.published_at.is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn expired_outbox_generation_cannot_ack_after_another_worker_reclaims() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project("project-a", "/tmp/project-a");
        let mission = mission("project-a", "mission-a");
        store.save_project(&project).expect("project");
        store.save_mission(&mission).expect("mission");
        store
            .connection
            .execute(
                "INSERT INTO outbox_messages
                   (tenant_id, project_id, mission_id, aggregate_type, aggregate_id,
                    event_type, payload_json, available_at, created_at)
                 VALUES (?1, ?2, ?3, 'mission', ?3, 'test.event', '{}', ?4, ?4)",
                params![
                    project.tenant_id.as_str(),
                    project.id.as_str(),
                    mission.id.as_str(),
                    now().to_rfc3339(),
                ],
            )
            .expect("outbox seed");
        let first = store
            .claim_outbox("worker-a", now(), Duration::seconds(1), 1)
            .expect("first claim")
            .remove(0);
        let second = store
            .claim_outbox(
                "worker-b",
                now() + Duration::seconds(2),
                Duration::seconds(30),
                1,
            )
            .expect("reclaim")
            .remove(0);
        assert!(second.lease_generation > first.lease_generation);
        assert!(matches!(
            store.acknowledge_outbox(
                first.sequence,
                "worker-a",
                first.lease_generation,
                now() + Duration::seconds(3)
            ),
            Err(StorageError::OutboxLeaseLost { .. })
        ));
        store
            .acknowledge_outbox(
                second.sequence,
                "worker-b",
                second.lease_generation,
                now() + Duration::seconds(3),
            )
            .expect("current generation ack");
        assert_eq!(
            store
                .outbox_message(second.sequence)
                .expect("outbox")
                .status,
            OutboxStatus::Published
        );
    }
}

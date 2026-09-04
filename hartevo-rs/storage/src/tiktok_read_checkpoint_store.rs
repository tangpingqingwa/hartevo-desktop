use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{ConnectionId, MissionId, ProjectId, TenantId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ProjectStore, StorageError};

const MAX_TIKTOK_READ_CHECKPOINT_BYTES: usize = 128 * 1024 * 1024;

const TIKTOK_READ_CHECKPOINT_TABLE_SQL: &str =
    "CREATE TABLE IF NOT EXISTS tiktok_read_checkpoints (
  tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
  project_id TEXT NOT NULL CHECK (length(trim(project_id)) > 0),
  mission_id TEXT NOT NULL CHECK (length(trim(mission_id)) > 0),
  connection_id TEXT NOT NULL CHECK (length(trim(connection_id)) > 0),
  binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64),
  mission_revision INTEGER NOT NULL CHECK (mission_revision > 0),
  connection_revision INTEGER NOT NULL CHECK (connection_revision > 0),
  provider_scope_digest TEXT NOT NULL CHECK (length(provider_scope_digest) = 64),
  credential_reference_digest TEXT NOT NULL CHECK (length(credential_reference_digest) = 64),
  credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
  page_size INTEGER NOT NULL CHECK (page_size BETWEEN 1 AND 20),
  max_pages INTEGER NOT NULL CHECK (max_pages BETWEEN 1 AND 100),
  page_generation INTEGER NOT NULL CHECK (page_generation BETWEEN 0 AND max_pages),
  checkpoint_digest TEXT NOT NULL CHECK (length(checkpoint_digest) = 64),
  checkpoint_json TEXT NOT NULL CHECK (
    length(checkpoint_json) BETWEEN 2 AND 134217728
  ),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (project_id, mission_id, connection_id, binding_digest),
  FOREIGN KEY (mission_id, project_id)
    REFERENCES missions(id, project_id) ON DELETE CASCADE,
  FOREIGN KEY (project_id, connection_id)
    REFERENCES connections(project_id, id) ON DELETE CASCADE
)";

const TIKTOK_READ_CHECKPOINT_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS tiktok_read_checkpoint_scope_idx
     ON tiktok_read_checkpoints(tenant_id, project_id, mission_id, updated_at)";

pub(crate) fn install_tiktok_read_checkpoint_schema(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StorageError> {
    transaction.execute_batch(TIKTOK_READ_CHECKPOINT_TABLE_SQL)?;
    transaction.execute_batch(TIKTOK_READ_CHECKPOINT_INDEX_SQL)?;
    Ok(())
}

pub(crate) fn verify_tiktok_read_checkpoint_schema(
    connection: &rusqlite::Connection,
) -> Result<(), StorageError> {
    let table_sql = schema_sql(connection, "table", "tiktok_read_checkpoints")?;
    let index_sql = schema_sql(connection, "index", "tiktok_read_checkpoint_scope_idx")?;
    if normalize_schema_sql(&table_sql) != normalize_schema_sql(TIKTOK_READ_CHECKPOINT_TABLE_SQL) {
        return Err(StorageError::DomainDecode(
            "TikTok read checkpoint table definition does not match v51".into(),
        ));
    }
    if normalize_schema_sql(&index_sql) != normalize_schema_sql(TIKTOK_READ_CHECKPOINT_INDEX_SQL) {
        return Err(StorageError::DomainDecode(
            "TikTok read checkpoint v51 index definition does not match".into(),
        ));
    }
    Ok(())
}

fn schema_sql(
    connection: &rusqlite::Connection,
    object_type: &str,
    name: &str,
) -> Result<String, StorageError> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::DomainDecode(format!(
                "TikTok read checkpoint v51 {object_type} {name} is missing"
            ))
        })
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE")
        .replace("CREATE INDEX IF NOT EXISTS", "CREATE INDEX")
}

/// Exact content-free identity of one resumable TikTok sequence.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TiktokReadCheckpointBinding {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub connection_id: ConnectionId,
    pub mission_revision: u64,
    pub connection_revision: u64,
    pub provider_scope_digest: String,
    pub credential_reference_digest: String,
    pub credential_generation: u64,
    pub page_size: u8,
    pub max_pages: u16,
}

impl fmt::Debug for TiktokReadCheckpointBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TiktokReadCheckpointBinding")
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("connection_id", &self.connection_id)
            .field("mission_revision", &self.mission_revision)
            .field("connection_revision", &self.connection_revision)
            .field("credential_generation", &self.credential_generation)
            .field("page_size", &self.page_size)
            .field("max_pages", &self.max_pages)
            .finish_non_exhaustive()
    }
}

impl TiktokReadCheckpointBinding {
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.connection_id.as_str().trim().is_empty()
            || self.mission_revision == 0
            || self.connection_revision == 0
            || self.credential_generation == 0
            || !(1..=20).contains(&self.page_size)
            || !(1..=100).contains(&self.max_pages)
            || !is_sha256(&self.provider_scope_digest)
            || !is_sha256(&self.credential_reference_digest)
        {
            return Err(invalid_checkpoint("invalid checkpoint binding"));
        }
        sqlite_u64(self.mission_revision, "mission revision")?;
        sqlite_u64(self.connection_revision, "connection revision")?;
        sqlite_u64(self.credential_generation, "credential generation")?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, StorageError> {
        self.validate()?;
        Ok(sha256(&serde_json::to_vec(self)?))
    }
}

/// Private provider pages plus their exact durable binding. The JSON is stored
/// only inside SQLCipher and is deliberately omitted from `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct TiktokReadCheckpoint {
    binding: TiktokReadCheckpointBinding,
    page_generation: u64,
    checkpoint_digest: String,
    checkpoint_json: String,
    updated_at: DateTime<Utc>,
}

impl fmt::Debug for TiktokReadCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TiktokReadCheckpoint")
            .field("binding", &self.binding)
            .field("page_generation", &self.page_generation)
            .field("checkpoint_digest", &self.checkpoint_digest)
            .field("checkpoint_json", &"[REDACTED]")
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl TiktokReadCheckpoint {
    pub fn new(
        binding: TiktokReadCheckpointBinding,
        page_generation: u64,
        checkpoint_json: String,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, StorageError> {
        let checkpoint_digest = sha256(checkpoint_json.as_bytes());
        let checkpoint = Self {
            binding,
            page_generation,
            checkpoint_digest,
            checkpoint_json,
            updated_at,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub const fn binding(&self) -> &TiktokReadCheckpointBinding {
        &self.binding
    }

    pub const fn page_generation(&self) -> u64 {
        self.page_generation
    }

    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    pub fn checkpoint_json(&self) -> &str {
        &self.checkpoint_json
    }

    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn validate(&self) -> Result<(), StorageError> {
        self.binding.validate()?;
        let byte_len = self.checkpoint_json.len();
        if !(2..=MAX_TIKTOK_READ_CHECKPOINT_BYTES).contains(&byte_len)
            || self.page_generation > u64::from(self.binding.max_pages)
            || !is_sha256(&self.checkpoint_digest)
            || sha256(self.checkpoint_json.as_bytes()) != self.checkpoint_digest
        {
            return Err(invalid_checkpoint("invalid checkpoint payload"));
        }
        sqlite_u64(self.page_generation, "page generation")?;
        Ok(())
    }
}

impl ProjectStore {
    pub fn load_tiktok_read_checkpoint(
        &self,
        binding: &TiktokReadCheckpointBinding,
    ) -> Result<Option<TiktokReadCheckpoint>, StorageError> {
        binding.validate()?;
        validate_current_scope(&self.connection, binding)?;
        let binding_digest = binding.digest()?;
        let checkpoint = load_checkpoint(&self.connection, binding, &binding_digest)?;
        if let Some(checkpoint) = checkpoint.as_ref() {
            checkpoint.validate()?;
        }
        Ok(checkpoint)
    }

    /// Insert or advance one exact checkpoint. An update must name the exact
    /// previously observed payload digest so concurrent Desktop instances
    /// cannot silently overwrite each other's progress.
    pub fn persist_tiktok_read_checkpoint(
        &mut self,
        checkpoint: &TiktokReadCheckpoint,
        expected_previous_digest: Option<&str>,
    ) -> Result<bool, StorageError> {
        checkpoint.validate()?;
        if expected_previous_digest.is_some_and(|digest| !is_sha256(digest)) {
            return Err(invalid_checkpoint("invalid expected checkpoint digest"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_current_scope(&transaction, checkpoint.binding())?;
        let binding_digest = checkpoint.binding.digest()?;
        let existing = load_checkpoint(&transaction, checkpoint.binding(), &binding_digest)?;
        match existing {
            None => {
                if expected_previous_digest.is_some() {
                    return Err(checkpoint_conflict(checkpoint.binding()));
                }
                insert_checkpoint(&transaction, checkpoint, &binding_digest)?;
                transaction.commit()?;
                Ok(true)
            }
            Some(existing) => {
                existing.validate()?;
                if expected_previous_digest != Some(existing.checkpoint_digest()) {
                    return Err(checkpoint_conflict(checkpoint.binding()));
                }
                if checkpoint.page_generation < existing.page_generation
                    || checkpoint.updated_at < existing.updated_at
                {
                    return Err(invalid_checkpoint("checkpoint progression moved backwards"));
                }
                if checkpoint == &existing {
                    transaction.commit()?;
                    return Ok(false);
                }
                let changed = transaction.execute(
                    "UPDATE tiktok_read_checkpoints
                     SET page_generation = ?1, checkpoint_digest = ?2,
                         checkpoint_json = ?3, updated_at = ?4
                     WHERE project_id = ?5 AND mission_id = ?6 AND connection_id = ?7
                       AND binding_digest = ?8 AND checkpoint_digest = ?9",
                    params![
                        sqlite_u64(checkpoint.page_generation, "page generation")?,
                        checkpoint.checkpoint_digest,
                        checkpoint.checkpoint_json,
                        checkpoint.updated_at.to_rfc3339(),
                        checkpoint.binding.project_id.as_str(),
                        checkpoint.binding.mission_id.as_str(),
                        checkpoint.binding.connection_id.as_str(),
                        binding_digest,
                        existing.checkpoint_digest,
                    ],
                )?;
                if changed != 1 {
                    return Err(checkpoint_conflict(checkpoint.binding()));
                }
                transaction.commit()?;
                Ok(true)
            }
        }
    }

    /// Remove only the exact adopted checkpoint. This remains valid after the
    /// Mission revision advances because every old binding and payload digest
    /// must still match the row being removed.
    pub fn delete_tiktok_read_checkpoint(
        &mut self,
        binding: &TiktokReadCheckpointBinding,
        expected_checkpoint_digest: &str,
    ) -> Result<bool, StorageError> {
        binding.validate()?;
        if !is_sha256(expected_checkpoint_digest) {
            return Err(invalid_checkpoint("invalid expected checkpoint digest"));
        }
        let binding_digest = binding.digest()?;
        let changed = self.connection.execute(
            "DELETE FROM tiktok_read_checkpoints
             WHERE project_id = ?1 AND mission_id = ?2 AND connection_id = ?3
               AND binding_digest = ?4 AND checkpoint_digest = ?5",
            params![
                binding.project_id.as_str(),
                binding.mission_id.as_str(),
                binding.connection_id.as_str(),
                binding_digest,
                expected_checkpoint_digest,
            ],
        )?;
        Ok(changed == 1)
    }
}

fn validate_current_scope(
    connection: &rusqlite::Connection,
    binding: &TiktokReadCheckpointBinding,
) -> Result<(), StorageError> {
    let current = connection
        .query_row(
            "SELECT projects.tenant_id, missions.tenant_id, missions.revision,
                    connections.tenant_id, connections.provider, connections.revision
             FROM projects
             JOIN missions ON missions.project_id = projects.id AND missions.id = ?2
             JOIN connections ON connections.project_id = projects.id AND connections.id = ?3
             WHERE projects.id = ?1",
            params![
                binding.project_id.as_str(),
                binding.mission_id.as_str(),
                binding.connection_id.as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "TikTok read checkpoint binding",
            project_id: binding.project_id.clone(),
            id: format!(
                "{}:{}",
                binding.mission_id.as_str(),
                binding.connection_id.as_str()
            ),
        })?;
    if current.0 != binding.tenant_id.as_str()
        || current.1 != binding.tenant_id.as_str()
        || current.3 != binding.tenant_id.as_str()
        || current.4 != "tiktok"
        || decode_u64(current.2, "mission revision")? != binding.mission_revision
        || decode_u64(current.5, "connection revision")? != binding.connection_revision
    {
        return Err(invalid_checkpoint("checkpoint scope is no longer current"));
    }
    Ok(())
}

fn load_checkpoint(
    connection: &rusqlite::Connection,
    binding: &TiktokReadCheckpointBinding,
    binding_digest: &str,
) -> Result<Option<TiktokReadCheckpoint>, StorageError> {
    connection
        .query_row(
            "SELECT tenant_id, project_id, mission_id, connection_id,
                    mission_revision, connection_revision, provider_scope_digest,
                    credential_reference_digest, credential_generation, page_size,
                    max_pages, page_generation, checkpoint_digest, checkpoint_json,
                    updated_at
             FROM tiktok_read_checkpoints
             WHERE project_id = ?1 AND mission_id = ?2 AND connection_id = ?3
               AND binding_digest = ?4",
            params![
                binding.project_id.as_str(),
                binding.mission_id.as_str(),
                binding.connection_id.as_str(),
                binding_digest,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            let stored_binding = TiktokReadCheckpointBinding {
                tenant_id: TenantId::from_stable(row.0),
                project_id: ProjectId::from_stable(row.1),
                mission_id: MissionId::from_stable(row.2),
                connection_id: ConnectionId::from_stable(row.3),
                mission_revision: decode_u64(row.4, "mission revision")?,
                connection_revision: decode_u64(row.5, "connection revision")?,
                provider_scope_digest: row.6,
                credential_reference_digest: row.7,
                credential_generation: decode_u64(row.8, "credential generation")?,
                page_size: decode_u8(row.9, "page size")?,
                max_pages: decode_u16(row.10, "maximum pages")?,
            };
            if stored_binding != *binding || stored_binding.digest()? != binding_digest {
                return Err(invalid_checkpoint("stored checkpoint binding drifted"));
            }
            let checkpoint = TiktokReadCheckpoint {
                binding: stored_binding,
                page_generation: decode_u64(row.11, "page generation")?,
                checkpoint_digest: row.12,
                checkpoint_json: row.13,
                updated_at: DateTime::parse_from_rfc3339(&row.14)?.with_timezone(&Utc),
            };
            checkpoint.validate()?;
            Ok(checkpoint)
        })
        .transpose()
}

fn insert_checkpoint(
    transaction: &rusqlite::Transaction<'_>,
    checkpoint: &TiktokReadCheckpoint,
    binding_digest: &str,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO tiktok_read_checkpoints (
           tenant_id, project_id, mission_id, connection_id, binding_digest,
           mission_revision, connection_revision, provider_scope_digest,
           credential_reference_digest, credential_generation, page_size,
           max_pages, page_generation, checkpoint_digest, checkpoint_json, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
         )",
        params![
            checkpoint.binding.tenant_id.as_str(),
            checkpoint.binding.project_id.as_str(),
            checkpoint.binding.mission_id.as_str(),
            checkpoint.binding.connection_id.as_str(),
            binding_digest,
            sqlite_u64(checkpoint.binding.mission_revision, "mission revision")?,
            sqlite_u64(
                checkpoint.binding.connection_revision,
                "connection revision"
            )?,
            checkpoint.binding.provider_scope_digest,
            checkpoint.binding.credential_reference_digest,
            sqlite_u64(
                checkpoint.binding.credential_generation,
                "credential generation"
            )?,
            i64::from(checkpoint.binding.page_size),
            i64::from(checkpoint.binding.max_pages),
            sqlite_u64(checkpoint.page_generation, "page generation")?,
            checkpoint.checkpoint_digest,
            checkpoint.checkpoint_json,
            checkpoint.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn checkpoint_conflict(binding: &TiktokReadCheckpointBinding) -> StorageError {
    StorageError::OptimisticConflict {
        aggregate: format!(
            "TikTok read checkpoint {}:{}:{}",
            binding.project_id.as_str(),
            binding.mission_id.as_str(),
            binding.connection_id.as_str()
        ),
        expected_revision: binding.mission_revision,
    }
}

fn invalid_checkpoint(reason: &'static str) -> StorageError {
    StorageError::InvalidTiktokReadCheckpoint(reason)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, StorageError> {
    i64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("{field} does not fit SQLite INTEGER")))
}

fn decode_u64(value: i64, field: &'static str) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::DomainDecode(format!("{field} is negative")))
}

fn decode_u8(value: i64, field: &'static str) -> Result<u8, StorageError> {
    u8::try_from(value).map_err(|_| StorageError::DomainDecode(format!("{field} does not fit u8")))
}

fn decode_u16(value: i64, field: &'static str) -> Result<u16, StorageError> {
    u16::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("{field} does not fit u16")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{TimeZone, Utc};
    use hartevo_domain_kernel::{
        AccountId, Connection, ConnectionId, Mission, MissionContract, MissionId, Project,
        ProjectId, StorageMode, TenantId,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 4, 9, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn fixture() -> (
        ProjectStore,
        TiktokReadCheckpointBinding,
        TiktokReadCheckpoint,
    ) {
        let tenant_id = TenantId::from("tenant-tiktok-checkpoint");
        let project_id = ProjectId::from("project-tiktok-checkpoint");
        let mission_id = MissionId::from("mission-tiktok-checkpoint");
        let connection_id = ConnectionId::from("connection-tiktok-checkpoint");
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "TikTok checkpoint",
            "",
            "/workspace/tiktok-checkpoint",
            StorageMode::LocalExisting,
        )
        .expect("Project");
        let mission = Mission::compile(
            tenant_id.clone(),
            mission_id.clone(),
            project_id.clone(),
            "TikTok checkpoint",
            MissionContract::bootstrap("Resume TikTok reads", ["channel.read".into()], now()),
            now(),
        )
        .expect("Mission");
        let connection = Connection::register(
            connection_id.clone(),
            tenant_id.clone(),
            project_id.clone(),
            "tiktok",
            AccountId::from("business-checkpoint"),
            "account-checkpoint",
            BTreeSet::from(["video.list".to_owned()]),
            now(),
        )
        .expect("Connection");
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("persist Project");
        store.save_mission(&mission).expect("persist Mission");
        store
            .create_connection(
                &connection,
                "connection_registered",
                &serde_json::json!({"provider": "tiktok"}),
                now(),
            )
            .expect("persist Connection");
        let binding = TiktokReadCheckpointBinding {
            tenant_id,
            project_id,
            mission_id,
            connection_id,
            mission_revision: mission.revision,
            connection_revision: connection.revision(),
            provider_scope_digest: "a".repeat(64),
            credential_reference_digest: "b".repeat(64),
            credential_generation: connection.revision(),
            page_size: 20,
            max_pages: 4,
        };
        let checkpoint = TiktokReadCheckpoint::new(
            binding.clone(),
            1,
            r#"{"privatePage":"PRIVATE-TIKTOK-PAGE"}"#.into(),
            now(),
        )
        .expect("checkpoint");
        (store, binding, checkpoint)
    }

    #[test]
    fn checkpoint_round_trip_advances_by_exact_digest_and_deletes_exactly() {
        let (mut store, binding, first) = fixture();
        assert!(
            store
                .persist_tiktok_read_checkpoint(&first, None)
                .expect("insert checkpoint")
        );
        let loaded = store
            .load_tiktok_read_checkpoint(&binding)
            .expect("load checkpoint")
            .expect("checkpoint exists");
        assert_eq!(loaded, first);
        assert!(!format!("{loaded:?}").contains("PRIVATE-TIKTOK-PAGE"));

        let advanced = TiktokReadCheckpoint::new(
            binding.clone(),
            2,
            r#"{"privatePage":"PRIVATE-TIKTOK-PAGE-2"}"#.into(),
            now(),
        )
        .expect("advanced checkpoint");
        assert!(matches!(
            store.persist_tiktok_read_checkpoint(&advanced, Some(&"c".repeat(64))),
            Err(StorageError::OptimisticConflict { .. })
        ));
        assert!(
            store
                .persist_tiktok_read_checkpoint(&advanced, Some(first.checkpoint_digest()))
                .expect("advance exact checkpoint")
        );
        assert_eq!(
            store
                .load_tiktok_read_checkpoint(&binding)
                .expect("load advanced")
                .expect("advanced exists"),
            advanced
        );
        assert!(
            !store
                .delete_tiktok_read_checkpoint(&binding, &"d".repeat(64))
                .expect("wrong digest is a no-op")
        );
        assert!(
            store
                .delete_tiktok_read_checkpoint(&binding, advanced.checkpoint_digest())
                .expect("delete exact checkpoint")
        );
        assert!(
            store
                .load_tiktok_read_checkpoint(&binding)
                .expect("load after delete")
                .is_none()
        );
    }

    #[test]
    fn checkpoint_tamper_and_stale_scope_fail_closed() {
        let (mut store, binding, checkpoint) = fixture();
        store
            .persist_tiktok_read_checkpoint(&checkpoint, None)
            .expect("insert checkpoint");
        store
            .connection
            .execute(
                "UPDATE tiktok_read_checkpoints SET checkpoint_json = ?1
                 WHERE binding_digest = ?2",
                params![r#"{"tampered":true}"#, binding.digest().unwrap()],
            )
            .expect("inject payload tamper");
        assert!(matches!(
            store.load_tiktok_read_checkpoint(&binding),
            Err(StorageError::InvalidTiktokReadCheckpoint(_))
        ));

        let mut stale = binding;
        stale.mission_revision += 1;
        assert!(matches!(
            store.load_tiktok_read_checkpoint(&stale),
            Err(StorageError::InvalidTiktokReadCheckpoint(_))
        ));
    }

    #[test]
    fn migration_v51_installs_and_verifies_private_checkpoint_schema() {
        let store = ProjectStore::in_memory().expect("migrated store");
        assert_eq!(
            store
                .connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("schema version"),
            crate::STORAGE_SCHEMA_VERSION
        );
        verify_tiktok_read_checkpoint_schema(&store.connection).expect("v51 schema");
    }
}

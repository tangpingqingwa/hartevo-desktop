use hartevo_domain_kernel::media_generation::{MediaGeneration, MediaGenerationState};
use hartevo_domain_kernel::{Mission, MissionId, ProjectId, WorkProductManifest};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::aggregate::append_events;
use crate::normalized::update_mission_normalized_cas;
use crate::work_product_store::{
    load_work_product_manifest, persist_manifest_revision, validate_manifest_dependencies,
    validate_manifest_scope,
};
use crate::{PendingEvent, ProjectStore, StorageError};

#[derive(Debug)]
pub struct MediaWorkProductCommit<'a> {
    pub mission: &'a Mission,
    pub expected_mission_revision: u64,
    pub manifest: &'a WorkProductManifest,
    pub expected_manifest_version: Option<u64>,
}

const TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS media_generations (
           project_id TEXT NOT NULL,
           mission_id TEXT NOT NULL,
           id TEXT NOT NULL CHECK(length(id) BETWEEN 1 AND 128),
           revision INTEGER NOT NULL CHECK(revision > 0),
           job_json TEXT NOT NULL CHECK(length(job_json) BETWEEN 2 AND 65536),
           asset_bytes BLOB CHECK(asset_bytes IS NULL OR length(asset_bytes) BETWEEN 1 AND 33554432),
           PRIMARY KEY(project_id, id),
           FOREIGN KEY(mission_id, project_id) REFERENCES missions(id, project_id) ON DELETE CASCADE
         )";
const INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS media_generation_mission_idx ON media_generations(project_id, mission_id)";

pub(crate) fn install_schema(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(TABLE_SQL)?;
    connection.execute_batch(INDEX_SQL)?;
    verify_schema(connection)
}

pub(crate) fn verify_schema(connection: &Connection) -> Result<(), StorageError> {
    for (name, kind, expected) in [
        ("media_generations", "table", TABLE_SQL),
        ("media_generation_mission_idx", "index", INDEX_SQL),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                [kind, name],
                |row| row.get(0),
            )
            .optional()?;
        let normalize = |sql: &str| {
            sql.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .replace(" IF NOT EXISTS", "")
        };
        if actual.as_deref().map(normalize) != Some(normalize(expected)) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn invalid() -> StorageError {
    StorageError::DomainDecode("MEDIA_INTEGRITY_ERROR".into())
}

fn sql_revision(revision: u64) -> Result<i64, StorageError> {
    i64::try_from(revision).map_err(|_| invalid())
}

fn decode(json: &str, revision: i64) -> Result<MediaGeneration, StorageError> {
    let job: MediaGeneration = serde_json::from_str(json).map_err(|_| invalid())?;
    job.validate().map_err(|_| invalid())?;
    if sql_revision(job.revision)? != revision {
        return Err(invalid());
    }
    Ok(job)
}

impl ProjectStore {
    /// Insert the one-shot send claim before any network request. Duplicate IDs
    /// never grant another POST, including after a crash in Submitting.
    pub fn begin_media_generation(&mut self, job: &MediaGeneration) -> Result<bool, StorageError> {
        job.validate().map_err(|_| invalid())?;
        if job.state != MediaGenerationState::Submitting || job.revision != 1 || job.asset.is_some()
        {
            return Err(invalid());
        }
        let mission = self.load_mission(&job.request.project_id, &job.request.mission_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, i64)> = transaction
            .query_row(
                "SELECT job_json,revision FROM media_generations WHERE project_id=?1 AND id=?2",
                params![job.request.project_id.as_str(), job.request.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((json, revision)) = existing {
            let previous = decode(&json, revision)?;
            if previous.request != job.request || previous.tenant_id != job.tenant_id {
                return Err(invalid());
            }
            return Ok(false);
        }
        if mission.tenant_id != job.tenant_id
            || mission.revision != job.request.expected_mission_revision
        {
            return Err(invalid());
        }
        let revision: i64 = transaction.query_row(
            "SELECT revision FROM missions WHERE project_id=?1 AND id=?2",
            params![
                job.request.project_id.as_str(),
                job.request.mission_id.as_str()
            ],
            |r| r.get(0),
        )?;
        if revision != sql_revision(mission.revision)? {
            return Err(invalid());
        }
        transaction.execute("INSERT INTO media_generations(project_id,mission_id,id,revision,job_json) VALUES(?1,?2,?3,?4,?5)",
            params![job.request.project_id.as_str(),job.request.mission_id.as_str(),job.request.id,sql_revision(job.revision)?,serde_json::to_string(job)?])?;
        append_events(
            &transaction,
            job.tenant_id.as_str(),
            job.request.project_id.as_str(),
            Some(job.request.mission_id.as_str()),
            "media_generation",
            &job.request.id,
            &[PendingEvent::new(
                "media.generation_started",
                serde_json::json!({"generationId":job.request.id}),
                job.created_at,
            )],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn load_media_generation(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        id: &str,
    ) -> Result<Option<MediaGeneration>, StorageError> {
        let row: Option<(String,i64)> = self.connection.query_row(
            "SELECT job_json,revision FROM media_generations WHERE project_id=?1 AND mission_id=?2 AND id=?3",
            params![project_id.as_str(),mission_id.as_str(),id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        row.map(|(json, revision)| {
            let job = decode(&json, revision)?;
            if job.request.project_id != *project_id
                || job.request.mission_id != *mission_id
                || job.request.id != id
            {
                return Err(invalid());
            }
            Ok(job)
        })
        .transpose()
    }

    pub fn list_media_generations(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Vec<MediaGeneration>, StorageError> {
        let mut stmt = self.connection.prepare("SELECT id FROM media_generations WHERE project_id=?1 AND mission_id=?2 ORDER BY rowid DESC LIMIT 50")?;
        let ids = stmt
            .query_map(params![project_id.as_str(), mission_id.as_str()], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter()
            .map(|id| {
                self.load_media_generation(project_id, mission_id, id)?
                    .ok_or_else(invalid)
            })
            .collect()
    }

    pub fn media_generation_bytes(&self, job: &MediaGeneration) -> Result<Vec<u8>, StorageError> {
        let bytes: Option<Vec<u8>> = self.connection.query_row(
            "SELECT asset_bytes FROM media_generations WHERE project_id=?1 AND mission_id=?2 AND id=?3 AND revision=?4",
            params![job.request.project_id.as_str(),job.request.mission_id.as_str(),job.request.id,sql_revision(job.revision)?], |r| r.get(0))?;
        let bytes = bytes.ok_or_else(invalid)?;
        job.asset
            .as_ref()
            .ok_or_else(invalid)?
            .validate_bytes(&bytes)
            .map_err(|_| invalid())?;
        Ok(bytes)
    }

    /// Asset bytes, Domain WorkProduct, manifest and job state share one commit.
    pub fn commit_media_generation(
        &mut self,
        job: &MediaGeneration,
        bytes: Option<&[u8]>,
        product: Option<MediaWorkProductCommit<'_>>,
    ) -> Result<(), StorageError> {
        let previous = self
            .load_media_generation(
                &job.request.project_id,
                &job.request.mission_id,
                &job.request.id,
            )?
            .ok_or_else(invalid)?;
        if !job.follows(&previous).map_err(|_| invalid())? {
            return Err(invalid());
        }
        if let Some(asset) = &job.asset {
            asset
                .validate_bytes(bytes.ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        }
        if (job.state == MediaGenerationState::Ready) != product.is_some() {
            return Err(invalid());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(product) = product {
            let manifest = product.manifest;
            let work_product = validate_manifest_scope(product.mission, manifest)?;
            manifest.validate_against(work_product)?;
            if product.mission.id != job.request.mission_id
                || product.mission.project_id != job.request.project_id
                || product.mission.tenant_id != job.tenant_id
                || manifest.work_product_id != job.work_product_id
                || manifest.file_digest.as_ref() != job.asset.as_ref().map(|asset| &asset.sha256)
            {
                return Err(invalid());
            }
            validate_manifest_dependencies(&transaction, product.mission, manifest)?;
            let existing = load_work_product_manifest(
                &transaction,
                &manifest.project_id,
                &manifest.work_product_id,
            )?;
            persist_manifest_revision(
                &transaction,
                existing.as_ref(),
                manifest,
                product.expected_manifest_version,
            )?;
            update_mission_normalized_cas(
                &transaction,
                product.mission,
                product.expected_mission_revision,
            )?;
        }
        let changed = transaction.execute(
            "UPDATE media_generations SET revision=?1,job_json=?2,asset_bytes=?3 WHERE project_id=?4 AND mission_id=?5 AND id=?6 AND revision=?7",
            params![sql_revision(job.revision)?,serde_json::to_string(job)?,bytes,job.request.project_id.as_str(),job.request.mission_id.as_str(),job.request.id,sql_revision(previous.revision)?])?;
        if changed != 1 {
            return Err(invalid());
        }
        append_events(
            &transaction,
            job.tenant_id.as_str(),
            job.request.project_id.as_str(),
            Some(job.request.mission_id.as_str()),
            "media_generation",
            &job.request.id,
            &[PendingEvent::new(
                "media.generation_updated",
                serde_json::json!({"generationId":job.request.id,"state":job.state,"revision":job.revision}),
                job.updated_at,
            )],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_schema_migration_is_transactional_and_verifies_constraints() {
        let mut store = ProjectStore::in_memory().unwrap();
        store
            .connection
            .execute_batch(
                "DROP TABLE media_generations; DELETE FROM schema_migrations WHERE version=53;",
            )
            .unwrap();
        assert_eq!(store.schema_version().unwrap(), 52);
        store
            .connection
            .execute_batch("CREATE TABLE media_generations(project_id TEXT);")
            .unwrap();
        assert!(store.migrate().is_err());
        assert_eq!(store.schema_version().unwrap(), 52);
        store
            .connection
            .execute_batch("DROP TABLE media_generations;")
            .unwrap();
        store.migrate().unwrap();
        assert_eq!(store.schema_version().unwrap(), 53);
        store.migrate().unwrap();
        store
            .connection
            .execute_batch("DROP INDEX media_generation_mission_idx;")
            .unwrap();
        assert!(verify_schema(&store.connection).is_err());
    }
}

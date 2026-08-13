use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    DataClassification, DataSubjectExport, DataSubjectExportArtifact, DataSubjectExportId,
    DataSubjectExportRedaction, DataSubjectExportStatus, ProjectId, RetentionPolicy, TenantId,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn save_retention_policy(
        &mut self,
        project_id: &ProjectId,
        policy: &RetentionPolicy,
        now: DateTime<Utc>,
    ) -> Result<RetentionPolicy, StorageError> {
        policy.validate(now)?;
        let tenant_id = project_tenant(&self.connection, project_id)?;
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load_retention_policy(&transaction, project_id)? {
            if existing != *policy {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "local retention policy",
                    id: project_id.to_string(),
                });
            }
            transaction.commit()?;
            return Ok(existing);
        }
        transaction.execute(
            "INSERT INTO privacy_retention_policies
               (tenant_id, project_id, policy_id, version, effective_at, policy_digest, policy_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                tenant_id.as_str(),
                project_id.as_str(),
                policy.id,
                to_sql_u64(policy.version)?,
                policy.effective_at.to_rfc3339(),
                policy.policy_digest,
                serde_json::to_string(policy)?,
            ],
        )?;
        transaction.commit()?;
        Ok(policy.clone())
    }

    pub fn load_retention_policy(
        &self,
        project_id: &ProjectId,
    ) -> Result<RetentionPolicy, StorageError> {
        load_retention_policy(&self.connection, project_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "retention policy",
                project_id: project_id.clone(),
                id: "local".into(),
            }
        })
    }

    pub fn ensure_local_retention_policy(
        &mut self,
        project_id: &ProjectId,
        now: DateTime<Utc>,
    ) -> Result<RetentionPolicy, StorageError> {
        match self.load_retention_policy(project_id) {
            Ok(policy) => Ok(policy),
            Err(StorageError::ScopedRecordNotFound {
                kind: "retention policy",
                ..
            }) => {
                self.save_retention_policy(project_id, &RetentionPolicy::local_default(now)?, now)
            }
            Err(error) => Err(error),
        }
    }

    pub fn build_redacted_data_subject_export(
        &mut self,
        export_id: DataSubjectExportId,
        project_id: &ProjectId,
        subject_digest: &str,
        authorized_by: &str,
        authorization_evidence_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<DataSubjectExport, StorageError> {
        if !is_sha256(subject_digest)
            || authorized_by.trim().is_empty()
            || !is_sha256(authorization_evidence_digest)
        {
            return Err(StorageError::DomainDecode(
                "redacted data-subject export requires digested subject and authorization".into(),
            ));
        }
        let tenant_id = project_tenant(&self.connection, project_id)?;
        let policy = self.ensure_local_retention_policy(project_id, now)?;
        let mission_rows = load_mission_metadata(&self.connection, project_id)?;
        let event_rows = load_event_metadata(&self.connection, project_id)?;
        let deletion_rows = load_deletion_metadata(&self.connection, project_id)?;
        let sync_count = count_sync_metadata(&self.connection, project_id)?;
        let secret_count = count_secret_references(&self.connection, project_id)?;

        let artifacts = vec![
            metadata_artifact(
                "project_metadata",
                DataClassification::Restricted,
                1,
                &[digest_json(&json!({
                    "projectIdDigest": sha256_text(project_id.as_str()),
                    "tenantIdDigest": sha256_text(tenant_id.as_str()),
                    "retentionPolicyDigest": policy.policy_digest,
                }))?],
                DataSubjectExportRedaction::MetadataOnly,
            )?,
            metadata_artifact(
                "mission_metadata",
                DataClassification::Restricted,
                mission_rows.len() as u64,
                &mission_rows,
                DataSubjectExportRedaction::MetadataOnly,
            )?,
            metadata_artifact(
                "domain_audit",
                DataClassification::Audit,
                event_rows.len() as u64,
                &event_rows,
                DataSubjectExportRedaction::ContentErased,
            )?,
            metadata_artifact(
                "deletion_ledger",
                DataClassification::Audit,
                deletion_rows.len() as u64,
                &deletion_rows,
                DataSubjectExportRedaction::ContentErased,
            )?,
            metadata_artifact(
                "encrypted_sync_metadata",
                DataClassification::Restricted,
                sync_count,
                &[digest_json(&json!({
                    "projectIdDigest": sha256_text(project_id.as_str()),
                    "rowCount": sync_count,
                }))?],
                DataSubjectExportRedaction::ContentErased,
            )?,
            metadata_artifact(
                "secret_references",
                DataClassification::Secret,
                secret_count,
                &[digest_json(&json!({
                    "projectIdDigest": sha256_text(project_id.as_str()),
                    "rowCount": secret_count,
                }))?],
                DataSubjectExportRedaction::SecretWithheld,
            )?,
        ];
        let export = DataSubjectExport::create(
            export_id,
            tenant_id,
            project_id.clone(),
            subject_digest,
            authorized_by,
            authorization_evidence_digest,
            "dsr.metadata.v1",
            artifacts,
            now,
        )?;
        self.save_data_subject_export(&export, now)
    }

    pub fn save_data_subject_export(
        &mut self,
        export: &DataSubjectExport,
        now: DateTime<Utc>,
    ) -> Result<DataSubjectExport, StorageError> {
        export.validate(now)?;
        let tenant_id = project_tenant(&self.connection, &export.project_id)?;
        if tenant_id != export.tenant_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        let transaction = self.connection.transaction()?;
        if let Some(existing) =
            load_data_subject_export(&transaction, &export.project_id, &export.id)?
        {
            if existing != *export {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "data-subject export",
                    id: export.id.to_string(),
                });
            }
            transaction.commit()?;
            return Ok(existing);
        }
        transaction.execute(
            "INSERT INTO privacy_data_subject_exports
               (tenant_id, project_id, export_id, subject_digest, authorized_by,
                authorization_evidence_digest, status, redaction_profile, artifact_json,
                generated_at, export_digest, revision, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                export.tenant_id.as_str(),
                export.project_id.as_str(),
                export.id.as_str(),
                export.subject_digest,
                export.authorized_by,
                export.authorization_evidence_digest,
                export_status_name(export.status),
                export.redaction_profile,
                serde_json::to_string(&export.artifacts)?,
                export.generated_at.to_rfc3339(),
                export.export_digest,
                to_sql_u64(export.revision)?,
                serde_json::to_string(export)?,
            ],
        )?;
        transaction.commit()?;
        Ok(export.clone())
    }

    pub fn load_data_subject_export(
        &self,
        project_id: &ProjectId,
        export_id: &DataSubjectExportId,
    ) -> Result<DataSubjectExport, StorageError> {
        load_data_subject_export(&self.connection, project_id, export_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "data-subject export",
                project_id: project_id.clone(),
                id: export_id.to_string(),
            }
        })
    }

    pub fn list_data_subject_exports(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<DataSubjectExport>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT export_id FROM privacy_data_subject_exports
             WHERE project_id = ?1 ORDER BY generated_at, export_id",
        )?;
        let rows = statement.query_map([project_id.as_str()], |row| row.get::<_, String>(0))?;
        let export_ids = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        export_ids
            .into_iter()
            .map(|export_id| {
                self.load_data_subject_export(
                    project_id,
                    &DataSubjectExportId::from_stable(export_id),
                )
            })
            .collect()
    }
}

fn project_tenant(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<TenantId, StorageError> {
    connection
        .query_row(
            "SELECT tenant_id FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(TenantId::from_stable)
        .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))
}

fn load_retention_policy(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<RetentionPolicy>, StorageError> {
    let expected_tenant = project_tenant(connection, project_id)?;
    connection
        .query_row(
            "SELECT policy_json, tenant_id, policy_id, version, effective_at, policy_digest
             FROM privacy_retention_policies WHERE project_id = ?1",
            [project_id.as_str()],
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
        .map(|row| {
            let policy: RetentionPolicy = serde_json::from_str(&row.0)?;
            policy.validate(Utc::now())?;
            let normalized_matches = policy.id == row.2
                && row.1 == expected_tenant.as_str()
                && to_sql_u64(policy.version)? == row.3
                && policy.effective_at == parse_time(&row.4)?
                && policy.policy_digest == row.5;
            if !normalized_matches {
                return Err(StorageError::DomainDecode(
                    "normalized retention policy differs from record body".into(),
                ));
            }
            Ok(policy)
        })
        .transpose()
}

fn load_data_subject_export(
    connection: &Connection,
    project_id: &ProjectId,
    export_id: &DataSubjectExportId,
) -> Result<Option<DataSubjectExport>, StorageError> {
    let expected_tenant = project_tenant(connection, project_id)?;
    connection
        .query_row(
            "SELECT record_json, tenant_id, export_id, subject_digest, authorized_by,
                    authorization_evidence_digest, status, redaction_profile, generated_at,
                    export_digest, revision
             FROM privacy_data_subject_exports
             WHERE project_id = ?1 AND export_id = ?2",
            params![project_id.as_str(), export_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            let export: DataSubjectExport = serde_json::from_str(&row.0)?;
            export.validate(Utc::now())?;
            let normalized_matches = row.1 == expected_tenant.as_str()
                && export.tenant_id.as_str() == row.1
                && export.project_id.as_str() == project_id.as_str()
                && export.id.as_str() == row.2
                && export.subject_digest == row.3
                && export.authorized_by == row.4
                && export.authorization_evidence_digest == row.5
                && export_status_name(export.status) == row.6
                && export.redaction_profile == row.7
                && export.generated_at == parse_time(&row.8)?
                && export.export_digest == row.9
                && to_sql_u64(export.revision)? == row.10;
            if !normalized_matches {
                return Err(StorageError::DomainDecode(
                    "normalized data-subject export differs from record body".into(),
                ));
            }
            Ok(export)
        })
        .transpose()
}

fn load_mission_metadata(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<String>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, revision, stage FROM missions
         WHERE project_id = ?1 ORDER BY id",
    )?;
    let rows = statement.query_map([project_id.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    rows.map(|row| {
        let (id, revision, stage) = row?;
        digest_json(&json!({
            "idDigest": sha256_text(&id),
            "revision": revision,
            "stage": stage,
        }))
    })
    .collect()
}

fn load_event_metadata(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<String>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT sequence, event_type, recorded_at FROM domain_events
         WHERE project_id = ?1 ORDER BY sequence",
    )?;
    let rows = statement.query_map([project_id.as_str()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    rows.map(|row| {
        let (sequence, event_type, recorded_at) = row?;
        digest_json(&json!({
            "sequence": sequence,
            "eventTypeDigest": sha256_text(&event_type),
            "recordedAt": recorded_at,
        }))
    })
    .collect()
}

fn load_deletion_metadata(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<String>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT deletion_id, object_kind, object_id, tombstone_digest,
                record_revision, updated_at
         FROM sync_deletion_records WHERE project_id = ?1 ORDER BY deletion_id",
    )?;
    let rows = statement.query_map([project_id.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    rows.map(|row| {
        let (deletion_id, object_kind, object_id, tombstone_digest, revision, updated_at) = row?;
        digest_json(&json!({
            "deletionIdDigest": sha256_text(&deletion_id),
            "objectKind": object_kind,
            "objectIdDigest": sha256_text(&object_id),
            "tombstoneDigest": tombstone_digest,
            "recordRevision": revision,
            "updatedAt": updated_at,
        }))
    })
    .collect()
}

fn count_sync_metadata(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<u64, StorageError> {
    let count: i64 = connection.query_row(
        "SELECT
           (SELECT count(*) FROM encrypted_sync_operations WHERE project_id = ?1)
         + (SELECT count(*) FROM encrypted_sync_inbound_heads WHERE project_id = ?1)
         + (SELECT count(*) FROM encrypted_sync_inbound_versions WHERE project_id = ?1)",
        [project_id.as_str()],
        |row| row.get(0),
    )?;
    from_sql_u64(count, "encrypted sync metadata count")
}

fn count_secret_references(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<u64, StorageError> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM project_key_secret_references WHERE project_id = ?1",
        [project_id.as_str()],
        |row| row.get(0),
    )?;
    from_sql_u64(count, "secret reference count")
}

fn metadata_artifact(
    source_kind: &str,
    classification: DataClassification,
    object_count: u64,
    row_digests: &[String],
    redaction: DataSubjectExportRedaction,
) -> Result<DataSubjectExportArtifact, StorageError> {
    Ok(DataSubjectExportArtifact {
        source_kind: source_kind.to_owned(),
        classification,
        object_count,
        metadata_digest: digest_json(&json!({
            "source": source_kind,
            "rowDigests": row_digests,
            "redaction": redaction,
        }))?,
        provenance_digest: digest_json(&json!({
            "source": source_kind,
            "schema": "privacy-export-source-v1",
            "rowCount": object_count,
            "redacted": true,
        }))?,
        redaction,
    })
}

fn digest_json(value: &impl Serialize) -> Result<String, StorageError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn sha256_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

const fn export_status_name(status: DataSubjectExportStatus) -> &'static str {
    match status {
        DataSubjectExportStatus::Requested => "requested",
        DataSubjectExportStatus::Ready => "ready",
        DataSubjectExportStatus::Blocked => "blocked",
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, label: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("{label} cannot be negative")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::PendingEvent;
    use chrono::TimeZone;
    use hartevo_domain_kernel::{Project, StorageMode, TenantId};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup() -> (ProjectStore, ProjectId) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-privacy"),
            ProjectId::from("project-privacy"),
            "private project name",
            "private project description",
            PathBuf::from("/tmp/hartevo-privacy"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new(
                    "project.created",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("persist project");
        (store, project.id)
    }

    #[test]
    fn local_policy_and_redacted_export_survive_reopen_and_hide_content() {
        let (mut store, project_id) = setup();
        let policy = store
            .ensure_local_retention_policy(&project_id, now())
            .expect("default policy");
        assert_eq!(
            store
                .load_retention_policy(&project_id)
                .expect("policy reopen"),
            policy
        );
        let export = store
            .build_redacted_data_subject_export(
                DataSubjectExportId::from("export-privacy-1"),
                &project_id,
                &"1".repeat(64),
                "privacy-owner",
                &"2".repeat(64),
                now() + chrono::Duration::minutes(1),
            )
            .expect("redacted export");
        let encoded = serde_json::to_string(&export).expect("export json");
        assert!(!encoded.contains("private project name"));
        assert!(!encoded.contains("private project description"));
        assert!(!encoded.contains("secret_store"));
        assert!(
            export
                .artifacts
                .iter()
                .any(|artifact| artifact.redaction == DataSubjectExportRedaction::SecretWithheld)
        );
        assert_eq!(
            store
                .list_data_subject_exports(&project_id)
                .expect("export list"),
            vec![export.clone()]
        );
        let reopened = store
            .load_data_subject_export(&project_id, &export.id)
            .expect("export reopen");
        assert_eq!(reopened, export);
    }
}

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    PublicationActivity, PublicationActivityKind, PublicationId, PublicationStatus,
    WebPublicationProjection,
};
use rusqlite::{OptionalExtension, params};

use crate::normalized::{decode_enum, enum_name};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationActivityRecord {
    pub sequence: i64,
    pub activity: PublicationActivity,
}

impl ProjectStore {
    /// Persists the complete typed web publication projection inside the
    /// project SQLCipher cell. Publication content remains in the encrypted
    /// projection JSON; the activity table stores only status and digests.
    #[allow(clippy::too_many_lines)]
    pub fn save_web_publication(
        &mut self,
        projection: &WebPublicationProjection,
    ) -> Result<(), StorageError> {
        projection
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let project = self.load_project(&projection.site.project_id)?;
        let mission = self.load_mission(
            &projection.publication.project_id,
            &projection.publication.mission_id,
        )?;
        if project.tenant_id != projection.site.tenant_id
            || mission.tenant_id != projection.publication.tenant_id
            || mission.project_id != projection.publication.project_id
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        let mut persisted = projection.clone();
        persisted.activity.clear();
        let projection_json = serde_json::to_string(&persisted)?;
        let environment = enum_name(&projection.publication.request.environment)?;
        let status = enum_name(&projection.publication.status)?;
        let revision = to_sql_u64(projection.publication.revision)?;
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT projection_json, revision FROM web_publications
                 WHERE project_id = ?1 AND publication_id = ?2",
                params![
                    projection.publication.project_id.as_str(),
                    projection.publication.id.as_str()
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        match existing {
            None => {
                if projection.publication.revision != 1 {
                    return Err(StorageError::InvalidInitialRevision(
                        projection.publication.revision,
                    ));
                }
                transaction.execute(
                    "INSERT INTO web_publications (
                       tenant_id, project_id, mission_id, publication_id,
                       site_id, domain_id, deployment_id, environment, status,
                       revision, payload_digest, idempotency_key,
                       created_at, updated_at, projection_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        projection.publication.tenant_id.as_str(),
                        projection.publication.project_id.as_str(),
                        projection.publication.mission_id.as_str(),
                        projection.publication.id.as_str(),
                        projection.publication.site_id.as_str(),
                        projection.publication.domain_id.as_str(),
                        projection.publication.deployment_id.as_str(),
                        environment,
                        status,
                        revision,
                        projection.publication.request.payload_digest,
                        projection.publication.request.idempotency_key,
                        projection.publication.created_at.to_rfc3339(),
                        projection.publication.updated_at.to_rfc3339(),
                        projection_json,
                    ],
                )?;
            }
            Some((stored_json, stored_revision)) => {
                if stored_json == projection_json && stored_revision == revision {
                    transaction.commit()?;
                    return Ok(());
                }
                let expected_revision: u64 = stored_revision.try_into().map_err(|_| {
                    StorageError::DomainDecode("stored publication revision".into())
                })?;
                if projection.publication.revision != expected_revision.saturating_add(1) {
                    return Err(StorageError::UnexpectedNextRevision {
                        expected: expected_revision.saturating_add(1),
                        actual: projection.publication.revision,
                    });
                }
                let updated = transaction.execute(
                    "UPDATE web_publications SET
                       tenant_id = ?1, mission_id = ?3, site_id = ?5, domain_id = ?6,
                       deployment_id = ?7, environment = ?8, status = ?9, revision = ?10,
                       payload_digest = ?11, idempotency_key = ?12, updated_at = ?13,
                       projection_json = ?14
                     WHERE project_id = ?2 AND publication_id = ?4 AND revision = ?15",
                    params![
                        projection.publication.tenant_id.as_str(),
                        projection.publication.project_id.as_str(),
                        projection.publication.mission_id.as_str(),
                        projection.publication.id.as_str(),
                        projection.publication.site_id.as_str(),
                        projection.publication.domain_id.as_str(),
                        projection.publication.deployment_id.as_str(),
                        environment,
                        status,
                        revision,
                        projection.publication.request.payload_digest,
                        projection.publication.request.idempotency_key,
                        projection.publication.updated_at.to_rfc3339(),
                        projection_json,
                        stored_revision,
                    ],
                )?;
                if updated != 1 {
                    return Err(StorageError::OptimisticConflict {
                        aggregate: format!("web_publication:{}", projection.publication.id),
                        expected_revision,
                    });
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_web_publication(
        &self,
        project_id: &hartevo_domain_kernel::ProjectId,
        publication_id: &PublicationId,
    ) -> Result<WebPublicationProjection, StorageError> {
        let projection_json: String = self
            .connection
            .query_row(
                "SELECT projection_json FROM web_publications
                 WHERE project_id = ?1 AND publication_id = ?2",
                params![project_id.as_str(), publication_id.as_str()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "web publication",
                project_id: project_id.clone(),
                id: publication_id.to_string(),
            })?;
        let mut projection: WebPublicationProjection = serde_json::from_str(&projection_json)?;
        if projection.publication.project_id != *project_id
            || projection.publication.id != *publication_id
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        projection.activity = self
            .list_web_publication_activity(project_id, publication_id)?
            .into_iter()
            .map(|record| record.activity)
            .collect();
        projection
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        Ok(projection)
    }

    pub fn list_web_publications(
        &self,
        project_id: &hartevo_domain_kernel::ProjectId,
    ) -> Result<Vec<WebPublicationProjection>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT publication_id FROM web_publications
             WHERE project_id = ?1 ORDER BY updated_at ASC, publication_id ASC",
        )?;
        let ids = statement
            .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| self.load_web_publication(project_id, &PublicationId::from_stable(id)))
            .collect()
    }

    pub fn append_web_publication_activity(
        &mut self,
        activity: &PublicationActivity,
    ) -> Result<(), StorageError> {
        activity
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let publication =
            self.load_web_publication(&activity.project_id, &activity.publication_id)?;
        if publication.publication.mission_id != activity.mission_id
            || publication.publication.tenant_id != activity.tenant_id
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        let kind = enum_name(&activity.kind)?;
        let status = enum_name(&activity.status)?;
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT digest, kind, status, recorded_at FROM web_publication_activity
                 WHERE project_id = ?1 AND id = ?2",
                params![activity.project_id.as_str(), activity.id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((digest, existing_kind, existing_status, recorded_at)) = existing {
            if digest == activity.digest
                && existing_kind == kind
                && existing_status == status
                && recorded_at == activity.recorded_at.to_rfc3339()
            {
                transaction.commit()?;
                return Ok(());
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "web publication activity",
                id: activity.id.to_string(),
            });
        }
        transaction.execute(
            "INSERT INTO web_publication_activity (
               id, tenant_id, project_id, mission_id, publication_id,
               kind, status, digest, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                activity.id.as_str(),
                activity.tenant_id.as_str(),
                activity.project_id.as_str(),
                activity.mission_id.as_str(),
                activity.publication_id.as_str(),
                kind,
                status,
                activity.digest,
                activity.recorded_at.to_rfc3339(),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_web_publication_activity(
        &self,
        project_id: &hartevo_domain_kernel::ProjectId,
        publication_id: &PublicationId,
    ) -> Result<Vec<PublicationActivityRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, id, tenant_id, project_id, mission_id, publication_id,
                    kind, status, digest, recorded_at
             FROM web_publication_activity
             WHERE project_id = ?1 AND publication_id = ?2
             ORDER BY sequence ASC",
        )?;
        statement
            .query_map(
                params![project_id.as_str(), publication_id.as_str()],
                |row| {
                    let recorded_at = row.get::<_, String>(9)?;
                    let activity = PublicationActivity {
                        id: hartevo_domain_kernel::PublicationActivityId::from_stable(
                            row.get::<_, String>(1)?,
                        ),
                        tenant_id: hartevo_domain_kernel::TenantId::from_stable(
                            row.get::<_, String>(2)?,
                        ),
                        project_id: hartevo_domain_kernel::ProjectId::from_stable(
                            row.get::<_, String>(3)?,
                        ),
                        mission_id: hartevo_domain_kernel::MissionId::from_stable(
                            row.get::<_, String>(4)?,
                        ),
                        publication_id: PublicationId::from_stable(row.get::<_, String>(5)?),
                        kind: decode_enum::<PublicationActivityKind>(&row.get::<_, String>(6)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        status: decode_enum::<PublicationStatus>(&row.get::<_, String>(7)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        digest: row.get(8)?,
                        recorded_at: DateTime::parse_from_rfc3339(&recorded_at)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?
                            .with_timezone(&Utc),
                    };
                    Ok(PublicationActivityRecord {
                        sequence: row.get(0)?,
                        activity,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

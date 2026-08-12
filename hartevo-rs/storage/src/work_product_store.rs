use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ContextBranch, ContextCapsule, Mission, MissionConversation, MissionConversationMessageKind,
    MissionId, ProjectId, WorkProduct, WorkProductId, WorkProductManifest, WorkerHandle,
    WorkerLease,
};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::mission_conversation_store::update_mission_conversation_append;
use crate::normalized::{decode_enum, enum_name, update_mission_normalized_cas};
use crate::{ProjectStore, StorageError};
use crate::{
    context_collaboration_store::{update_context_branch_row, update_worker_handle_row},
    context_store::{update_context_capsule_row, update_worker_lease_row},
};

impl ProjectStore {
    /// Atomically adopts one private Runtime draft into the Mission,
    /// WorkProductManifest, and persistent same-Mission Conversation.
    /// Neither the draft body nor preview is copied into the event/outbox
    /// payloads supplied by the Application layer.
    pub fn create_runtime_draft_with_conversation_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        conversation: &MissionConversation,
        expected_conversation_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if mission.revision <= expected_mission_revision || events.is_empty() {
            return Err(if events.is_empty() {
                StorageError::EmptyAtomicEventSet
            } else {
                StorageError::UnexpectedNewerRevision {
                    expected_revision: expected_mission_revision,
                    actual: mission.revision,
                }
            });
        }
        let work_product = validate_manifest_scope(mission, manifest)?;
        manifest.validate_against(work_product)?;
        conversation.validate_for(mission, conversation.updated_at)?;
        let previous_conversation =
            self.load_mission_conversation(&mission.project_id, &mission.id)?;
        let message = conversation
            .messages
            .last()
            .ok_or_else(|| StorageError::DomainDecode("missing Runtime draft message".into()))?;
        if previous_conversation.revision != expected_conversation_revision
            || !conversation.follows(&previous_conversation)?
            || message.kind != MissionConversationMessageKind::RuntimeDraft
            || message.work_product_id.as_ref() != Some(&manifest.work_product_id)
            || message.mission_revision != mission.revision
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_draft:{}", manifest.work_product_id),
                expected_revision: expected_conversation_revision,
            });
        }

        let transaction = self.connection.transaction()?;
        validate_manifest_dependencies(&transaction, mission, manifest)?;
        let existing = load_work_product_manifest(
            &transaction,
            &mission.project_id,
            &manifest.work_product_id,
        )?;
        persist_manifest_revision(&transaction, existing.as_ref(), manifest, None)?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        update_mission_conversation_append(
            &transaction,
            conversation,
            expected_conversation_revision,
            message,
        )?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "runtime_draft",
            manifest.work_product_id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }

    /// One crash-safe adoption boundary for a completed local Runtime result.
    /// The Work Product and Conversation become visible only together with an
    /// accepted capsule, completed worker/branch, and released lease.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the transaction must name every independently versioned authority aggregate"
    )]
    pub fn finalize_runtime_draft_with_conversation_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        conversation: &MissionConversation,
        expected_conversation_revision: u64,
        submitted_capsule: &ContextCapsule,
        accepted_capsule: &ContextCapsule,
        expected_capsule_revision: u64,
        branch: &ContextBranch,
        expected_branch_revision: u64,
        handle: &WorkerHandle,
        expected_handle_revision: u64,
        lease: &WorkerLease,
        expected_lease_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() || mission.revision <= expected_mission_revision {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let work_product = validate_manifest_scope(mission, manifest)?;
        manifest.validate_against(work_product)?;
        conversation.validate_for(mission, conversation.updated_at)?;
        let previous_conversation =
            self.load_mission_conversation(&mission.project_id, &mission.id)?;
        let message = conversation
            .messages
            .last()
            .ok_or_else(|| StorageError::DomainDecode("missing Runtime draft message".into()))?;
        let previous_capsule =
            self.load_context_capsule(&accepted_capsule.project_id, &accepted_capsule.id)?;
        let previous_branch = self.load_context_branch(&branch.project_id, &branch.id)?;
        let previous_handle =
            self.load_worker_handle(&handle.project_id, &handle.workspace_id, &handle.worker_id)?;
        let previous_lease = self.load_worker_lease(&lease.project_id, &lease.id)?;
        if previous_conversation.revision != expected_conversation_revision
            || !conversation.follows(&previous_conversation)?
            || message.kind != MissionConversationMessageKind::RuntimeDraft
            || message.work_product_id.as_ref() != Some(&manifest.work_product_id)
            || previous_capsule.revision != expected_capsule_revision
            || !submitted_capsule.follows(&previous_capsule)?
            || !accepted_capsule.follows(submitted_capsule)?
            || previous_branch.revision != expected_branch_revision
            || !branch.follows(&previous_branch)?
            || previous_handle.revision != expected_handle_revision
            || !handle.follows(&previous_handle)?
            || previous_lease.revision != expected_lease_revision
            || !lease.follows(&previous_lease)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_draft_finalization:{}", manifest.work_product_id),
                expected_revision: expected_mission_revision,
            });
        }
        if accepted_capsule.project_id != mission.project_id
            || accepted_capsule.mission_id != mission.id
            || branch.project_id != mission.project_id
            || branch.workspace_id != accepted_capsule.workspace_id
            || handle.project_id != mission.project_id
            || handle.mission_id != mission.id
            || handle.workspace_id != accepted_capsule.workspace_id
            || handle.capsule_id != accepted_capsule.id
            || lease.project_id != mission.project_id
            || lease.workspace_id != accepted_capsule.workspace_id
            || lease.id != accepted_capsule.worker_lease_id
            || lease.worker_id != accepted_capsule.worker_id
            || lease.generation != accepted_capsule.worker_generation
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        let workspace =
            self.load_context_workspace(&mission.project_id, &accepted_capsule.workspace_id)?;
        let facts = self.load_context_capsule_facts(&mission.project_id, &accepted_capsule.id)?;
        let parent = handle
            .parent_worker_id
            .as_ref()
            .map(|worker_id| {
                self.load_worker_handle(&mission.project_id, &handle.workspace_id, worker_id)
            })
            .transpose()?;
        let mailbox = self.load_worker_mailbox_for_handle(
            &mission.project_id,
            &handle.workspace_id,
            &handle.worker_id,
        )?;
        mailbox.validate_for(&previous_handle, now)?;
        if mailbox.unsettled_count() != 0 {
            return Err(StorageError::DomainDecode(
                "cannot finalize Runtime draft with unsettled mailbox messages".into(),
            ));
        }
        accepted_capsule.validate_for(&workspace, branch, &previous_lease, mission, &facts, now)?;
        branch.validate_for_workspace(&workspace, now)?;
        handle.validate_for(
            &workspace,
            branch,
            &previous_lease,
            accepted_capsule,
            parent.as_ref(),
            now,
        )?;
        lease.validate_for(&workspace, branch, now)?;

        let transaction = self.connection.transaction()?;
        validate_manifest_dependencies(&transaction, mission, manifest)?;
        let existing = load_work_product_manifest(
            &transaction,
            &mission.project_id,
            &manifest.work_product_id,
        )?;
        persist_manifest_revision(&transaction, existing.as_ref(), manifest, None)?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        update_mission_conversation_append(
            &transaction,
            conversation,
            expected_conversation_revision,
            message,
        )?;
        update_context_capsule_row(&transaction, accepted_capsule, expected_capsule_revision)?;
        update_context_branch_row(&transaction, branch, expected_branch_revision)?;
        update_worker_handle_row(&transaction, handle, expected_handle_revision)?;
        update_worker_lease_row(&transaction, lease, expected_lease_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "runtime_draft_finalization",
            manifest.work_product_id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }

    pub fn create_work_product_manifest_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        self.persist_work_product_manifest_atomic(
            mission,
            expected_mission_revision,
            manifest,
            None,
            events,
        )
    }

    pub fn revise_work_product_manifest_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        expected_manifest_version: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        self.persist_work_product_manifest_atomic(
            mission,
            expected_mission_revision,
            manifest,
            Some(expected_manifest_version),
            events,
        )
    }

    pub fn load_work_product_manifest(
        &self,
        project_id: &ProjectId,
        work_product_id: &WorkProductId,
    ) -> Result<WorkProductManifest, StorageError> {
        load_work_product_manifest(&self.connection, project_id, work_product_id)?.ok_or_else(
            || StorageError::ScopedRecordNotFound {
                kind: "work_product_manifest",
                project_id: project_id.clone(),
                id: work_product_id.to_string(),
            },
        )
    }

    fn persist_work_product_manifest_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        expected_manifest_version: Option<u64>,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if mission.revision <= expected_mission_revision {
            return Err(StorageError::UnexpectedNewerRevision {
                expected_revision: expected_mission_revision,
                actual: mission.revision,
            });
        }
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let work_product = validate_manifest_scope(mission, manifest)?;
        manifest.validate_against(work_product)?;

        let transaction = self.connection.transaction()?;
        validate_manifest_dependencies(&transaction, mission, manifest)?;
        let existing = load_work_product_manifest(
            &transaction,
            &mission.project_id,
            &manifest.work_product_id,
        )?;
        persist_manifest_revision(
            &transaction,
            existing.as_ref(),
            manifest,
            expected_manifest_version,
        )?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "work_product_manifest",
            manifest.work_product_id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }
}

pub(crate) fn validate_manifest_scope<'a>(
    mission: &'a Mission,
    manifest: &WorkProductManifest,
) -> Result<&'a WorkProduct, StorageError> {
    if manifest.tenant_id != mission.tenant_id
        || manifest.project_id != mission.project_id
        || manifest.mission_id != mission.id
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    mission
        .work_products
        .iter()
        .find(|product| product.id == manifest.work_product_id)
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "mission_work_product",
            project_id: mission.project_id.clone(),
            id: manifest.work_product_id.to_string(),
        })
}

pub(crate) fn validate_manifest_dependencies(
    transaction: &Transaction<'_>,
    mission: &Mission,
    manifest: &WorkProductManifest,
) -> Result<(), StorageError> {
    let evidence_valid = manifest
        .dependencies
        .evidence_ids
        .iter()
        .all(|id| mission.evidence.iter().any(|evidence| evidence.id == *id));
    let tasks_valid = manifest
        .dependencies
        .task_ids
        .iter()
        .all(|id| mission.tasks.iter().any(|task| task.id == *id));
    if !evidence_valid || !tasks_valid {
        return Err(StorageError::DomainDecode(
            "work product manifest references unknown Mission dependencies".into(),
        ));
    }
    for fact_id in &manifest.dependencies.fact_ids {
        let exists = transaction
            .query_row(
                "SELECT 1 FROM truth_fact_heads
                 WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3",
                params![
                    manifest.tenant_id.as_str(),
                    manifest.project_id.as_str(),
                    fact_id.as_str(),
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            return Err(StorageError::ScopedRecordNotFound {
                kind: "truth_fact",
                project_id: manifest.project_id.clone(),
                id: fact_id.to_string(),
            });
        }
    }
    Ok(())
}

pub(crate) fn persist_manifest_revision(
    transaction: &Transaction<'_>,
    existing: Option<&WorkProductManifest>,
    manifest: &WorkProductManifest,
    expected_version: Option<u64>,
) -> Result<(), StorageError> {
    match (existing, expected_version) {
        (None, None) if manifest.version == 1 => insert_manifest(transaction, manifest),
        (Some(existing), Some(expected))
            if existing.version == expected && manifest.follows(existing)? =>
        {
            update_manifest(transaction, manifest, expected)
        }
        (None, None) => Err(StorageError::InvalidInitialRevision(manifest.version)),
        (Some(_), None) => Err(StorageError::ImmutableRecordMismatch {
            kind: "work product manifest",
            id: manifest.work_product_id.to_string(),
        }),
        _ => Err(StorageError::OptimisticConflict {
            aggregate: format!("work_product_manifest:{}", manifest.work_product_id),
            expected_revision: expected_version.unwrap_or_default(),
        }),
    }
}

pub(crate) fn load_work_product_manifest(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    work_product_id: &WorkProductId,
) -> Result<Option<WorkProductManifest>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, project_id, mission_id, work_product_id, work_product_type,
                    version, work_product_revision, dependencies_json, artifact_digest,
                    file_digest, preview_json, editable_scopes_json, adoption_status,
                    manifest_digest, created_at, updated_at
             FROM work_product_manifests
             WHERE project_id = ?1 AND work_product_id = ?2",
            params![project_id.as_str(), work_product_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                ))
            },
        )
        .optional()?;
    row.map(decode_manifest).transpose()
}

fn insert_manifest(
    transaction: &Transaction<'_>,
    manifest: &WorkProductManifest,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO work_product_manifests
           (tenant_id, project_id, mission_id, work_product_id, work_product_type,
            version, work_product_revision, dependencies_json, artifact_digest,
            file_digest, preview_json, editable_scopes_json, adoption_status,
            manifest_digest, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        rusqlite::params_from_iter(manifest_param_values(manifest)?),
    )?;
    Ok(())
}

fn update_manifest(
    transaction: &Transaction<'_>,
    manifest: &WorkProductManifest,
    expected_version: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE work_product_manifests SET
           work_product_type = ?5, version = ?6, work_product_revision = ?7,
           dependencies_json = ?8, artifact_digest = ?9, file_digest = ?10,
           preview_json = ?11, editable_scopes_json = ?12, adoption_status = ?13,
           manifest_digest = ?14, created_at = ?15, updated_at = ?16
         WHERE tenant_id = ?1 AND project_id = ?2 AND mission_id = ?3
           AND work_product_id = ?4 AND version = ?17",
        rusqlite::params_from_iter(manifest_param_values(manifest)?.into_iter().chain([
            rusqlite::types::Value::Integer(to_sql_u64(expected_version)?),
        ])),
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("work_product_manifest:{}", manifest.work_product_id),
            expected_revision: expected_version,
        });
    }
    Ok(())
}

fn manifest_param_values(
    manifest: &WorkProductManifest,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    use rusqlite::types::Value;

    Ok(vec![
        Value::Text(manifest.tenant_id.to_string()),
        Value::Text(manifest.project_id.to_string()),
        Value::Text(manifest.mission_id.to_string()),
        Value::Text(manifest.work_product_id.to_string()),
        Value::Text(manifest.work_product_type.clone()),
        Value::Integer(to_sql_u64(manifest.version)?),
        Value::Integer(to_sql_u64(manifest.work_product_revision)?),
        Value::Text(serde_json::to_string(&manifest.dependencies)?),
        Value::Text(manifest.artifact_digest.clone()),
        manifest
            .file_digest
            .clone()
            .map_or(Value::Null, Value::Text),
        Value::Text(serde_json::to_string(&manifest.preview)?),
        Value::Text(serde_json::to_string(&manifest.editable_scopes)?),
        Value::Text(enum_name(&manifest.adoption_status)?),
        Value::Text(manifest.manifest_digest.clone()),
        Value::Text(manifest.created_at.to_rfc3339()),
        Value::Text(manifest.updated_at.to_rfc3339()),
    ])
}

type ManifestRow = (
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
    String,
);

fn decode_manifest(row: ManifestRow) -> Result<WorkProductManifest, StorageError> {
    let manifest = WorkProductManifest {
        tenant_id: hartevo_domain_kernel::TenantId::from_stable(row.0),
        project_id: ProjectId::from_stable(row.1),
        mission_id: MissionId::from_stable(row.2),
        work_product_id: WorkProductId::from_stable(row.3),
        work_product_type: row.4,
        version: from_sql_u64(row.5, "work product manifest version")?,
        work_product_revision: from_sql_u64(row.6, "work product revision")?,
        dependencies: serde_json::from_str(&row.7)?,
        artifact_digest: row.8,
        file_digest: row.9,
        preview: serde_json::from_str(&row.10)?,
        editable_scopes: serde_json::from_str(&row.11)?,
        adoption_status: decode_enum(&row.12)?,
        manifest_digest: row.13,
        created_at: parse_time(&row.14)?,
        updated_at: parse_time(&row.15)?,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        Evidence, EvidenceId, EvidenceStatus, FactId, MissionContract, StorageMode, Task, TaskId,
        TaskStatus, TenantId, TruthFact, TruthStatus, WorkProductPreview,
    };
    use rust_decimal::Decimal;
    use serde_json::json;

    use super::*;
    use crate::PendingEvent;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 19, 0, 0)
            .single()
            .expect("valid time")
    }

    fn truth_fact(tenant_id: TenantId, project_id: ProjectId) -> TruthFact {
        TruthFact::create(
            FactId::from("fact-work-product"),
            tenant_id,
            project_id,
            "launch.constraint",
            None,
            vec![],
            TruthStatus::Unknown,
            None,
            "US",
            "en",
            now(),
            now(),
            None,
            Decimal::ZERO,
            now(),
        )
        .expect("fact")
    }

    fn work_product_manifest(
        mission: &Mission,
        product: &WorkProduct,
        fact_id: FactId,
        task_id: TaskId,
    ) -> WorkProductManifest {
        WorkProductManifest::create(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            product,
            "document.launch_brief",
            hartevo_domain_kernel::WorkProductDependencies {
                fact_ids: BTreeSet::from([fact_id]),
                evidence_ids: product.evidence_ids.clone(),
                task_ids: BTreeSet::from([task_id]),
            },
            None,
            WorkProductPreview::new("text/plain", "Launch brief preview").expect("preview"),
            BTreeSet::from(["/body".into()]),
            now(),
        )
        .expect("manifest")
    }

    fn setup() -> (ProjectStore, Mission, WorkProductManifest, TruthFact) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = hartevo_domain_kernel::Project::create_local(
            TenantId::from("tenant-work-product"),
            ProjectId::from("project-work-product"),
            "Work product manifest",
            "",
            PathBuf::from("/tmp/hartevo-work-product-manifest"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), now())],
            )
            .expect("persist project");
        let mut mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-work-product"),
            project.id.clone(),
            "Traceable work product",
            MissionContract::bootstrap(
                "Create a traceable work product",
                ["work_product.compose".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new("mission.created", json!({}), now())],
            )
            .expect("persist mission");
        let task_id = TaskId::from("task-work-product");
        let evidence_id = EvidenceId::from("evidence-work-product");
        mission
            .start_research(
                [Task {
                    id: task_id.clone(),
                    title: "Create artifact".into(),
                    status: TaskStatus::Ready,
                    capability: "work_product.compose".into(),
                }],
                now(),
            )
            .expect("start research");
        mission
            .record_evidence(
                Evidence {
                    id: evidence_id.clone(),
                    title: "Verified evidence".into(),
                    source_uri: "fixture://work-product/evidence".into(),
                    observed_at: now(),
                    confidence: 1.0,
                    status: EvidenceStatus::Confirmed,
                    content_digest: "a".repeat(64),
                },
                now(),
            )
            .expect("record evidence");
        mission
            .record_work_product(
                WorkProduct::draft(
                    WorkProductId::from("work-product-1"),
                    "Launch brief",
                    "Evidence-backed body",
                    [evidence_id.clone()],
                ),
                now(),
            )
            .expect("record work product");
        let product = mission.work_products[0].clone();
        let fact = truth_fact(project.tenant_id, project.id);
        let manifest = work_product_manifest(&mission, &product, fact.id.clone(), task_id);
        (store, mission, manifest, fact)
    }

    #[test]
    fn manifest_and_mission_commit_atomically_with_truth_dependencies_and_cas() {
        let (mut store, mut mission, manifest, fact) = setup();
        assert!(matches!(
            store.create_work_product_manifest_atomic(
                &mission,
                1,
                &manifest,
                &[PendingEvent::new("work_product.created", json!({}), now())],
            ),
            Err(StorageError::ScopedRecordNotFound {
                kind: "truth_fact",
                ..
            })
        ));
        assert_eq!(
            store
                .load_mission(&mission.project_id, &mission.id)
                .expect("rolled-back mission")
                .revision,
            1
        );
        store
            .create_truth_fact(&fact, "truth.created", &json!({}), now())
            .expect("persist truth dependency");
        store
            .create_work_product_manifest_atomic(
                &mission,
                1,
                &manifest,
                &[PendingEvent::new("work_product.created", json!({}), now())],
            )
            .expect("persist mission and manifest");
        assert_eq!(
            store
                .load_work_product_manifest(&mission.project_id, &manifest.work_product_id)
                .expect("manifest round trip"),
            manifest
        );

        let previous_mission_revision = mission.revision;
        let revised_product = mission.work_products[0]
            .revise_content(
                "Corrected launch brief",
                "Corrected evidence-backed body",
                manifest.dependencies.evidence_ids.iter().cloned(),
            )
            .expect("revised product");
        mission
            .revise_work_product(revised_product.clone(), now() + Duration::minutes(1))
            .expect("revise mission product");
        let revised_manifest = manifest
            .revise(
                &revised_product,
                manifest.dependencies.clone(),
                None,
                WorkProductPreview::new("text/plain", "Corrected preview").expect("preview"),
                manifest.editable_scopes.clone(),
                now() + Duration::minutes(1),
            )
            .expect("revised manifest");
        store
            .revise_work_product_manifest_atomic(
                &mission,
                previous_mission_revision,
                &revised_manifest,
                1,
                &[PendingEvent::new("work_product.revised", json!({}), now())],
            )
            .expect("persist revision");
        assert_eq!(
            store
                .load_work_product_manifest(&mission.project_id, &manifest.work_product_id)
                .expect("manifest v2")
                .version,
            2
        );
        assert!(matches!(
            store.revise_work_product_manifest_atomic(
                &mission,
                previous_mission_revision,
                &revised_manifest,
                1,
                &[PendingEvent::new("work_product.stale", json!({}), now())],
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
    }
}

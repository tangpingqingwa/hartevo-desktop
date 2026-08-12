use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Campaign, CampaignId, Company, CompanyId, ConnectionId, ConnectionSnapshot, ConsentRecord,
    ConsentRecordId, ContextBranch, ContextBranchId, ContextCapsule, ContextWorkspace,
    Conversation, ConversationIdentitySnapshot, CreatorHiring, CreatorIdentitySnapshot,
    CreatorTask, CreatorTaskId, FactId, IdentityLink, IdentityLinkId, IdentityLinkStatus,
    IdentitySubject, Mission, MissionId, Opportunity, OpportunityId, OutcomeLedger, Partner,
    PartnerId, Person, PersonId, Project, ProjectDataCell, ProjectId, StorageMode, TenantId,
    TruthFact, WorkProduct, WorkProductManifest, WorkProductStatus, WorkerLease,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::aggregate::{PendingEvent, append_events};
use crate::authorization::{
    insert_connection, insert_consent, insert_truth_head, insert_truth_revision, update_connection,
    update_truth_head,
};
use crate::context_store::{
    insert_context_branch, insert_context_capsule, insert_context_capsule_facts,
    insert_context_workspace, insert_worker_lease, update_context_capsule_row,
    validate_context_bundle,
};
use crate::creator::{
    clear_creator_children, ensure_project_and_mission, insert_creator_children,
    insert_creator_task, update_creator_task_row,
};
use crate::creator_hiring_store::{
    ensure_scope as ensure_hiring_scope, insert_hiring, persist_children,
};
use crate::identity_store::{
    ensure_company_reference, ensure_partner_references, ensure_subject, insert_company_record,
    insert_identity_link, insert_partner, insert_person_record,
};
use crate::normalized::{
    insert_mission_normalized, load_mission_normalized, load_project_normalized,
    update_mission_normalized_cas, update_project_normalized_cas,
};
use crate::outcome_store::{
    insert_outcome_ledger_head, persist_children as persist_outcome_children,
    update_outcome_ledger_head,
};
use crate::relationship_store::{
    ensure_campaign_scope, ensure_conversation_scope, ensure_opportunity_scope, insert_campaign,
    insert_conversation, insert_opportunity, persist_campaign_recipients,
    persist_conversation_messages, persist_opportunity_children, update_conversation_row,
};
use crate::work_product_store::{
    load_work_product_manifest, persist_manifest_revision, validate_manifest_dependencies,
};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSyncStatus {
    Prepared,
    Applied,
    Conflict,
    DeadLetter,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncOperation {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub idempotency_key_digest: String,
    pub intent_digest: String,
    pub request_digest: String,
    pub cell: String,
    pub object_id: String,
    pub object_kind: String,
    pub target_revision: u64,
    pub key_version: u64,
    pub content_digest: String,
    pub tombstone: bool,
    pub request: Value,
    pub status: LocalSyncStatus,
    pub remote_revision: Option<u64>,
    pub remote_duplicate: bool,
    pub last_error_code: Option<String>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl LocalSyncOperation {
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || !is_sha256(&self.idempotency_key_digest)
            || !is_sha256(&self.intent_digest)
            || !is_sha256(&self.request_digest)
            || self.request_digest
                != format!("{:x}", Sha256::digest(serde_json::to_vec(&self.request)?))
            || !matches!(self.cell.as_str(), "us" | "eu")
            || self.object_id.trim().is_empty()
            || self.object_kind.trim().is_empty()
            || self.target_revision == 0
            || self.key_version == 0
            || !is_sha256(&self.content_digest)
            || self.revision == 0
            || self.created_at > self.updated_at
            || (self.status == LocalSyncStatus::Prepared
                && (self.remote_revision.is_some()
                    || self.remote_duplicate
                    || self.last_error_code.is_some()))
            || (self.status == LocalSyncStatus::Applied && self.remote_revision.is_none())
            || (matches!(
                self.status,
                LocalSyncStatus::Conflict | LocalSyncStatus::DeadLetter
            ) && self.last_error_code.as_deref().is_none_or(str::is_empty))
        {
            return Err(StorageError::DomainDecode(
                "invalid local encrypted sync operation".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalSyncPrepareOutcome {
    pub operation: LocalSyncOperation,
    pub duplicate: bool,
    pub event_sequence: Option<i64>,
    pub outbox_sequence: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalInboundSyncStatus {
    Staged,
    Validated,
    Applied,
    Conflict,
}

/// Exact encrypted object received from a Cell. `request` must remain the
/// serialized ciphertext envelope; plaintext belongs only in the caller's
/// zeroizing buffer and the eventual typed SQLCipher projection.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalInboundSyncEnvelope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub cell: String,
    pub object_id: String,
    pub object_kind: String,
    pub remote_revision: u64,
    pub key_version: u64,
    pub content_digest: String,
    pub tombstone: bool,
    pub request_digest: String,
    pub request: Value,
    pub remote_recorded_at: DateTime<Utc>,
}

impl LocalInboundSyncEnvelope {
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || !matches!(self.cell.as_str(), "us" | "eu")
            || self.object_id.trim().is_empty()
            || self.object_kind.trim().is_empty()
            || self.remote_revision == 0
            || self.key_version == 0
            || !is_sha256(&self.content_digest)
            || !is_sha256(&self.request_digest)
            || self.request_digest
                != format!("{:x}", Sha256::digest(serde_json::to_vec(&self.request)?))
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound encrypted sync envelope".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalInboundSyncObject {
    #[serde(flatten)]
    pub envelope: LocalInboundSyncEnvelope,
    pub status: LocalInboundSyncStatus,
    pub validation_digest: Option<String>,
    pub projection_digest: Option<String>,
    pub projection_revision: Option<u64>,
    pub last_error_code: Option<String>,
    pub revision: u64,
    pub staged_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl LocalInboundSyncObject {
    pub fn validate(&self) -> Result<(), StorageError> {
        self.envelope.validate()?;
        let validation_present = self.validation_digest.as_deref().is_some_and(is_sha256);
        let projection_present = self.projection_digest.as_deref().is_some_and(is_sha256);
        let projection_revision_present = self.projection_revision.is_some_and(|value| value > 0);
        let projection_pair_valid = projection_present == projection_revision_present;
        let error_present = self
            .last_error_code
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let state_valid = match self.status {
            LocalInboundSyncStatus::Staged => {
                !validation_present && projection_pair_valid && !error_present
            }
            LocalInboundSyncStatus::Validated => {
                validation_present && projection_pair_valid && !error_present
            }
            LocalInboundSyncStatus::Applied => {
                validation_present && projection_present && projection_pair_valid && !error_present
            }
            LocalInboundSyncStatus::Conflict => error_present && projection_pair_valid,
        };
        if self.revision == 0
            || self.staged_at > self.updated_at
            || !state_valid
            || self
                .validation_digest
                .as_deref()
                .is_some_and(|value| !is_sha256(value))
            || self
                .projection_digest
                .as_deref()
                .is_some_and(|value| !is_sha256(value))
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound encrypted sync object".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalInboundSyncStageDisposition {
    Inserted,
    Advanced,
    Duplicate,
    Stale,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalInboundSyncStageOutcome {
    pub object: LocalInboundSyncObject,
    pub disposition: LocalInboundSyncStageDisposition,
}

impl ProjectStore {
    pub fn prepare_local_sync_operation(
        &mut self,
        operation: &LocalSyncOperation,
    ) -> Result<LocalSyncPrepareOutcome, StorageError> {
        operation.validate()?;
        if operation.tombstone {
            return Err(StorageError::DeletionRequiresTypedPath);
        }
        if operation.revision != 1 || operation.status != LocalSyncStatus::Prepared {
            return Err(StorageError::InvalidInitialRevision(operation.revision));
        }
        let transaction = self.connection.transaction()?;
        ensure_registered_sync_project(
            &transaction,
            &operation.tenant_id,
            &operation.project_id,
            &operation.cell,
        )?;
        crate::deletion_store::ensure_sync_object_not_deleted_in_transaction(
            &transaction,
            &operation.project_id,
            &operation.object_kind,
            &operation.object_id,
        )?;
        if let Some(existing) = load_operation(
            &transaction,
            &operation.project_id,
            &operation.idempotency_key_digest,
        )? {
            if existing.intent_digest != operation.intent_digest {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "encrypted sync request",
                    id: operation.idempotency_key_digest.clone(),
                });
            }
            transaction.commit()?;
            return Ok(LocalSyncPrepareOutcome {
                operation: existing,
                duplicate: true,
                event_sequence: None,
                outbox_sequence: None,
            });
        }
        insert_operation(&transaction, operation)?;
        let (events, outbox) = append_events(
            &transaction,
            operation.tenant_id.as_str(),
            operation.project_id.as_str(),
            None,
            "encrypted_sync_operation",
            &operation.idempotency_key_digest,
            &[PendingEvent::new(
                "sync.operation.prepared",
                event_payload(operation),
                operation.created_at,
            )],
        )?;
        transaction.commit()?;
        Ok(LocalSyncPrepareOutcome {
            operation: operation.clone(),
            duplicate: false,
            event_sequence: events.first().copied(),
            outbox_sequence: outbox.first().copied(),
        })
    }

    pub fn load_local_sync_operation(
        &self,
        project_id: &ProjectId,
        idempotency_key_digest: &str,
    ) -> Result<LocalSyncOperation, StorageError> {
        load_operation(&self.connection, project_id, idempotency_key_digest)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "encrypted sync operation",
                project_id: project_id.clone(),
                id: idempotency_key_digest.to_owned(),
            }
        })
    }

    pub fn record_local_sync_applied(
        &mut self,
        project_id: &ProjectId,
        idempotency_key_digest: &str,
        expected_revision: u64,
        remote_revision: u64,
        remote_duplicate: bool,
        now: DateTime<Utc>,
    ) -> Result<LocalSyncOperation, StorageError> {
        if remote_revision == 0 {
            return Err(StorageError::DomainDecode(
                "remote sync revision must be positive".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let mut operation = load_required(&transaction, project_id, idempotency_key_digest)?;
        if operation.status == LocalSyncStatus::Applied {
            if operation.remote_revision == Some(remote_revision)
                && operation.remote_duplicate == remote_duplicate
            {
                transaction.commit()?;
                return Ok(operation);
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "applied encrypted sync result",
                id: idempotency_key_digest.to_owned(),
            });
        }
        if operation.status != LocalSyncStatus::Prepared || operation.revision != expected_revision
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("encrypted_sync_operation:{idempotency_key_digest}"),
                expected_revision,
            });
        }
        operation.status = LocalSyncStatus::Applied;
        operation.remote_revision = Some(remote_revision);
        operation.remote_duplicate = remote_duplicate;
        operation.revision = next_revision(expected_revision)?;
        operation.updated_at = now;
        update_operation(&transaction, &operation, expected_revision)?;
        if operation.tombstone {
            crate::deletion_store::mark_encrypted_cell_applied_in_transaction(
                &transaction,
                &operation,
                now,
            )?;
        }
        append_events(
            &transaction,
            operation.tenant_id.as_str(),
            operation.project_id.as_str(),
            None,
            "encrypted_sync_operation",
            &operation.idempotency_key_digest,
            &[PendingEvent::new(
                "sync.operation.applied",
                event_payload(&operation),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(operation)
    }

    pub fn record_local_sync_conflict(
        &mut self,
        project_id: &ProjectId,
        idempotency_key_digest: &str,
        expected_revision: u64,
        error_code: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalSyncOperation, StorageError> {
        if error_code.trim().is_empty() {
            return Err(StorageError::DomainDecode(
                "sync conflict requires a stable error code".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let mut operation = load_required(&transaction, project_id, idempotency_key_digest)?;
        if operation.status != LocalSyncStatus::Prepared || operation.revision != expected_revision
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("encrypted_sync_operation:{idempotency_key_digest}"),
                expected_revision,
            });
        }
        operation.status = LocalSyncStatus::Conflict;
        operation.last_error_code = Some(error_code.trim().to_owned());
        operation.revision = next_revision(expected_revision)?;
        operation.updated_at = now;
        update_operation(&transaction, &operation, expected_revision)?;
        append_events(
            &transaction,
            operation.tenant_id.as_str(),
            operation.project_id.as_str(),
            None,
            "encrypted_sync_operation",
            &operation.idempotency_key_digest,
            &[PendingEvent::new(
                "sync.operation.conflict",
                event_payload(&operation),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(operation)
    }

    pub fn stage_local_inbound_sync_object(
        &mut self,
        envelope: &LocalInboundSyncEnvelope,
        expected_remote_revision: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncStageOutcome, StorageError> {
        envelope.validate()?;
        let transaction = self.connection.transaction()?;
        ensure_registered_sync_project(
            &transaction,
            &envelope.tenant_id,
            &envelope.project_id,
            &envelope.cell,
        )?;
        if envelope.tombstone && envelope.object_kind != "context_capsule" {
            return Err(StorageError::DeletionUnsupportedObjectKind(
                envelope.object_kind.clone(),
            ));
        }
        if !envelope.tombstone {
            crate::deletion_store::ensure_sync_object_not_deleted_in_transaction(
                &transaction,
                &envelope.project_id,
                &envelope.object_kind,
                &envelope.object_id,
            )?;
        }
        let existing =
            load_inbound_object(&transaction, &envelope.project_id, &envelope.object_id)?;
        let outcome = match existing {
            Some(existing) => stage_over_inbound_head(
                &transaction,
                existing,
                envelope,
                expected_remote_revision,
                now,
            )?,
            None => {
                stage_first_inbound_head(&transaction, envelope, expected_remote_revision, now)?
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn load_local_inbound_sync_object(
        &self,
        project_id: &ProjectId,
        object_id: &str,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        load_inbound_object(&self.connection, project_id, object_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "inbound encrypted sync object",
                project_id: project_id.clone(),
                id: object_id.to_owned(),
            }
        })
    }

    pub fn record_local_inbound_sync_validated(
        &mut self,
        project_id: &ProjectId,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        if !is_sha256(validation_digest) {
            return Err(StorageError::DomainDecode(
                "inbound sync validation digest is invalid".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let current = load_inbound_required(&transaction, project_id, object_id)?;
        if current.envelope.remote_revision != remote_revision {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: remote_revision,
            });
        }
        if matches!(
            current.status,
            LocalInboundSyncStatus::Validated | LocalInboundSyncStatus::Applied
        ) {
            if current.validation_digest.as_deref() == Some(validation_digest) {
                transaction.commit()?;
                return Ok(current);
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "inbound encrypted sync validation",
                id: format!("{object_id}:{remote_revision}"),
            });
        }
        if current.status != LocalInboundSyncStatus::Staged
            || current.revision != expected_local_revision
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }
        let updated = transaction.execute(
            "UPDATE encrypted_sync_inbound_heads
             SET status = 'validated', validation_digest = ?4, revision = ?5, updated_at = ?6
             WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
               AND current_remote_revision = ?7 AND status = 'staged'",
            params![
                project_id.as_str(),
                object_id,
                to_sql_u64(expected_local_revision)?,
                validation_digest,
                to_sql_u64(next_revision(expected_local_revision)?)?,
                now.to_rfc3339(),
                to_sql_u64(remote_revision)?,
            ],
        )?;
        if updated != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }
        append_inbound_audit(
            &transaction,
            &current.envelope,
            "sync.inbound.validated",
            LocalInboundSyncStatus::Validated,
            now,
        )?;
        let validated = load_inbound_required(&transaction, project_id, object_id)?;
        transaction.commit()?;
        Ok(validated)
    }

    pub fn apply_local_inbound_mission(
        &mut self,
        mission: &Mission,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        if mission.tenant_id.as_str().trim().is_empty()
            || mission.project_id.as_str().trim().is_empty()
            || mission.id.as_str() != object_id
            || mission.revision == 0
            || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound mission projection".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &mission.tenant_id, &mission.project_id)?;
        let current = load_inbound_required(&transaction, &mission.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(mission.revision)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "mission"
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        let existing = load_mission_normalized(&transaction, &mission.project_id, &mission.id)?;
        let projection_conflict = match &existing {
            Some(existing) if existing == mission => None,
            Some(existing) if current.projection_revision == Some(existing.revision) => {
                if mission.revision > existing.revision {
                    update_mission_normalized_cas(&transaction, mission, existing.revision)?;
                    None
                } else {
                    Some(existing.revision)
                }
            }
            Some(existing) => Some(existing.revision),
            None if current.projection_revision.is_none() => {
                insert_mission_normalized(&transaction, mission)?;
                None
            }
            None => Some(current.projection_revision.unwrap_or_default()),
        };
        if let Some(actual_revision) = projection_conflict {
            mark_inbound_projection_conflict(
                &transaction,
                &current,
                "local_mission_changed_since_remote_projection",
                now,
            )?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("mission:{}", mission.id),
                expected_revision: actual_revision,
            });
        }

        let next_local_revision = next_revision(expected_local_revision)?;
        let updated = transaction.execute(
            "UPDATE encrypted_sync_inbound_heads
             SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
                 last_error_code = NULL, revision = ?6, updated_at = ?7
             WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
               AND current_remote_revision = ?8 AND status = 'validated'",
            params![
                mission.project_id.as_str(),
                object_id,
                to_sql_u64(expected_local_revision)?,
                validation_digest,
                to_sql_u64(mission.revision)?,
                to_sql_u64(next_local_revision)?,
                now.to_rfc3339(),
                to_sql_u64(remote_revision)?,
            ],
        )?;
        if updated != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }
        append_inbound_mission_projection_audit(&transaction, &current.envelope, mission, now)?;
        let applied = load_inbound_required(&transaction, &mission.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }

    pub fn apply_local_inbound_project_metadata(
        &mut self,
        project: &Project,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let project_cell = match project.data_cell {
            Some(ProjectDataCell::Us) => "us",
            Some(ProjectDataCell::Eu) => "eu",
            None => "",
        };
        if project.tenant_id.as_str().trim().is_empty()
            || project.id.as_str() != object_id
            || project.storage_mode != StorageMode::LocalEncryptedSync
            || project_cell.is_empty()
            || project.workspace_roots.is_empty()
            || project.revision == 0
            || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound project metadata projection".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &project.tenant_id, &project.id)?;
        let current = load_inbound_required(&transaction, &project.id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(project.revision)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "project_metadata"
            || current.envelope.cell != project_cell
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        let existing = load_project_normalized(&transaction, &project.id)?
            .ok_or_else(|| StorageError::ProjectNotFound(project.id.clone()))?;
        let projection_conflict = if existing == *project {
            None
        } else if current.projection_revision == Some(existing.revision)
            && project.revision > existing.revision
            && project.workspace_roots == existing.workspace_roots
            && project.storage_mode == existing.storage_mode
            && project.data_cell == existing.data_cell
        {
            update_project_normalized_cas(&transaction, project, existing.revision)?;
            None
        } else {
            Some(existing.revision)
        };
        if let Some(actual_revision) = projection_conflict {
            mark_inbound_projection_conflict(
                &transaction,
                &current,
                "local_project_changed_since_remote_projection",
                now,
            )?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("project:{}", project.id),
                expected_revision: actual_revision,
            });
        }

        finish_inbound_project_projection(
            &transaction,
            &current,
            project,
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &project.id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }

    pub fn apply_local_inbound_truth_fact(
        &mut self,
        fact: &TruthFact,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        fact.validate(now)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if fact.id.as_str() != object_id || !is_sha256(validation_digest) {
            return Err(StorageError::DomainDecode(
                "invalid inbound project truth projection".into(),
            ));
        }
        let existing = match self.load_truth_fact(&fact.project_id, &fact.id) {
            Ok(existing) => Some(existing),
            Err(StorageError::ScopedRecordNotFound {
                kind: "truth_fact", ..
            }) => None,
            Err(error) => return Err(error),
        };
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &fact.tenant_id, &fact.project_id)?;
        let current = load_inbound_required(&transaction, &fact.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(fact.version)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "project_truth"
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        let projection_conflict = match &existing {
            Some(existing) if existing == fact => None,
            Some(existing) if current.projection_revision == Some(existing.version) => {
                let previous_digest = existing
                    .digest()
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
                let links_exact_previous = fact.revision_link.as_ref().is_some_and(|link| {
                    link.previous_version == existing.version
                        && link.previous_digest == previous_digest
                });
                if existing.version.checked_add(1) == Some(fact.version) && links_exact_previous {
                    update_truth_head(&transaction, fact, existing.version)?;
                    insert_truth_revision(&transaction, fact)?;
                    None
                } else {
                    Some(existing.version)
                }
            }
            None if current.projection_revision.is_none() && fact.version == 1 => {
                insert_truth_head(&transaction, fact)?;
                insert_truth_revision(&transaction, fact)?;
                None
            }
            Some(existing) => Some(existing.version),
            None => Some(current.projection_revision.unwrap_or_default()),
        };
        if let Some(actual_version) = projection_conflict {
            mark_inbound_projection_conflict(
                &transaction,
                &current,
                "local_truth_changed_since_remote_projection",
                now,
            )?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("truth_fact:{}", fact.id),
                expected_revision: actual_version,
            });
        }

        finish_inbound_truth_projection(
            &transaction,
            &current,
            fact,
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &fact.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_local_inbound_work_product(
        &mut self,
        manifest: &WorkProductManifest,
        work_product: &WorkProduct,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        manifest.validate_against(work_product)?;
        if manifest.work_product_id.as_str() != object_id
            || manifest.version != remote_revision
            || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound work product projection".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &manifest.tenant_id, &manifest.project_id)?;
        let current = load_inbound_required(&transaction, &manifest.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(manifest.version)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "work_product"
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        let mut mission =
            load_mission_normalized(&transaction, &manifest.project_id, &manifest.mission_id)?
                .ok_or_else(|| StorageError::MissionNotFound {
                    project_id: manifest.project_id.clone(),
                    mission_id: manifest.mission_id.clone(),
                })?;
        let existing_manifest = load_work_product_manifest(
            &transaction,
            &manifest.project_id,
            &manifest.work_product_id,
        )?;
        let mission_revision = mission.revision;
        let projection = plan_work_product_projection(
            &current,
            &mut mission,
            existing_manifest.as_ref(),
            manifest,
            work_product,
            now,
        );
        if let Err(error_code) = projection {
            mark_inbound_projection_conflict(&transaction, &current, error_code, now)?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("work_product_manifest:{}", manifest.work_product_id),
                expected_revision: existing_manifest.as_ref().map_or(0, |item| item.version),
            });
        }
        validate_manifest_dependencies(&transaction, &mission, manifest)?;
        if existing_manifest.as_ref() != Some(manifest) {
            persist_manifest_revision(
                &transaction,
                existing_manifest.as_ref(),
                manifest,
                existing_manifest.as_ref().map(|item| item.version),
            )?;
        }
        if mission.revision != mission_revision {
            update_mission_normalized_cas(&transaction, &mission, mission_revision)?;
        }
        finish_inbound_work_product_projection(
            &transaction,
            &current,
            manifest,
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &manifest.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_local_inbound_conversation(
        &mut self,
        identity: &ConversationIdentitySnapshot,
        connection: &ConnectionSnapshot,
        consents: &[ConsentRecord],
        conversation: &Conversation,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        if conversation.id.as_str() != object_id
            || conversation.revision != remote_revision
            || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound conversation projection".into(),
            ));
        }
        let mission_id = conversation
            .mission_id
            .as_ref()
            .ok_or_else(|| StorageError::DomainDecode("conversation mission is required".into()))?;
        let mission = self.load_mission(&conversation.project_id, mission_id)?;
        conversation
            .validate_snapshot(identity, connection, &mission, consents, now)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let existing =
            load_existing_conversation_projection(self, conversation, connection, consents)?;

        let transaction = self.connection.transaction()?;
        ensure_project(
            &transaction,
            &conversation.tenant_id,
            &conversation.project_id,
        )?;
        let current = load_inbound_required(&transaction, &conversation.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(conversation.revision)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "conversation"
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        transaction.execute_batch("SAVEPOINT conversation_projection")?;
        let projection = project_conversation_snapshot(
            &transaction,
            current.projection_revision,
            existing.conversation.as_ref(),
            existing.connection.as_ref(),
            &existing.consents,
            identity,
            connection,
            consents,
            conversation,
            &mission,
            now,
        );
        if let Err(error_code) = projection {
            transaction.execute_batch(
                "ROLLBACK TO conversation_projection; RELEASE conversation_projection",
            )?;
            mark_inbound_projection_conflict(&transaction, &current, error_code, now)?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("conversation:{}", conversation.id),
                expected_revision: existing
                    .conversation
                    .as_ref()
                    .map_or(0, |item| item.revision),
            });
        }
        transaction.execute_batch("RELEASE conversation_projection")?;
        finish_inbound_conversation_projection(
            &transaction,
            &current,
            conversation,
            consents.len(),
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &conversation.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_local_inbound_connection_metadata(
        &mut self,
        snapshot: &ConnectionSnapshot,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        snapshot
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if snapshot.id.as_str() != object_id
            || remote_revision == 0
            || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound connection metadata projection".into(),
            ));
        }
        let connection_id = ConnectionId::from_stable(object_id);
        let existing = match self.load_connection(&snapshot.project_id, &connection_id) {
            Ok(connection) => Some(connection.snapshot()),
            Err(StorageError::ScopedRecordNotFound {
                kind: "connection", ..
            }) => None,
            Err(error) => return Err(error),
        };
        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &snapshot.tenant_id, &snapshot.project_id)?;
        let current = load_inbound_required(&transaction, &snapshot.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(snapshot.revision)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "connection_metadata"
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        let projection = project_connection_snapshot(
            &transaction,
            current.projection_revision,
            existing.as_ref(),
            snapshot,
        );
        if let Err(error_code) = projection {
            mark_inbound_projection_conflict(&transaction, &current, error_code, now)?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("connection:{}", snapshot.id),
                expected_revision: existing.as_ref().map_or(0, |item| item.revision),
            });
        }
        finish_inbound_connection_projection(
            &transaction,
            &current,
            snapshot,
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &snapshot.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_local_inbound_creator_work(
        &mut self,
        identities: &[CreatorIdentitySnapshot],
        hiring: &CreatorHiring,
        task: &CreatorTask,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        if task.id.as_str() != object_id
            || hiring.id != task.hiring_award.hiring_id
            || remote_revision == 0
            || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound creator work projection".into(),
            ));
        }
        validate_creator_identity_bundle(identities, hiring, task)?;
        let mission = self.load_mission(&task.project_id, &task.mission_id)?;
        task.validate_snapshot(hiring, &mission, now)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let existing_hiring = match self.load_creator_hiring(&task.project_id, &hiring.id) {
            Ok(existing) => Some(existing),
            Err(StorageError::ScopedRecordNotFound {
                kind: "creator hiring",
                ..
            }) => None,
            Err(error) => return Err(error),
        };
        let task_id = CreatorTaskId::from_stable(object_id);
        let existing_task = match self.load_creator_task(&task.project_id, &task_id) {
            Ok(existing) => Some(existing),
            Err(StorageError::CreatorTaskNotFound { .. }) => None,
            Err(error) => return Err(error),
        };

        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &task.tenant_id, &task.project_id)?;
        let current = load_inbound_required(&transaction, &task.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(task.state_revision)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "creator_work"
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        transaction.execute_batch("SAVEPOINT creator_work_projection")?;
        let projection = project_creator_work_snapshot(
            &transaction,
            current.projection_revision,
            existing_hiring.as_ref(),
            existing_task.as_ref(),
            identities,
            hiring,
            task,
            &mission,
            now,
        );
        if let Err(error_code) = projection {
            transaction.execute_batch(
                "ROLLBACK TO creator_work_projection; RELEASE creator_work_projection",
            )?;
            mark_inbound_projection_conflict(&transaction, &current, error_code, now)?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("creator_work:{}", task.id),
                expected_revision: existing_task.as_ref().map_or(0, |item| item.state_revision),
            });
        }
        transaction.execute_batch("RELEASE creator_work_projection")?;
        finish_inbound_creator_work_projection(
            &transaction,
            &current,
            identities,
            hiring,
            task,
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &task.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_local_inbound_outcome_ledger(
        &mut self,
        missions: &[Mission],
        connections: &[ConnectionSnapshot],
        companies: &[Company],
        people: &[Person],
        partners: &[Partner],
        identity_links: &[IdentityLink],
        consents: &[ConsentRecord],
        campaigns: &[Campaign],
        opportunities: &[Opportunity],
        ledger: &OutcomeLedger,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        if object_id != ledger.project_id.as_str()
            || remote_revision == 0
            || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound outcome ledger projection".into(),
            ));
        }
        validate_outcome_projection_bundle(
            missions,
            connections,
            companies,
            people,
            partners,
            identity_links,
            consents,
            campaigns,
            opportunities,
            ledger,
        )?;
        let existing = load_existing_outcome_projection(
            self,
            missions,
            connections,
            companies,
            people,
            partners,
            identity_links,
            consents,
            campaigns,
            opportunities,
            ledger,
        )?;

        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &ledger.tenant_id, &ledger.project_id)?;
        let current = load_inbound_required(&transaction, &ledger.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(ledger.revision)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "outcome_ledger"
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        transaction.execute_batch("SAVEPOINT outcome_ledger_projection")?;
        let projection = project_outcome_ledger_snapshot(
            &transaction,
            current.projection_revision,
            &existing,
            missions,
            connections,
            companies,
            people,
            partners,
            identity_links,
            consents,
            campaigns,
            opportunities,
            ledger,
        );
        if let Err(error_code) = projection {
            transaction.execute_batch(
                "ROLLBACK TO outcome_ledger_projection; RELEASE outcome_ledger_projection",
            )?;
            mark_inbound_projection_conflict(&transaction, &current, error_code, now)?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("outcome_ledger:{}", ledger.project_id),
                expected_revision: existing.ledger.as_ref().map_or(0, |item| item.revision),
            });
        }
        transaction.execute_batch("RELEASE outcome_ledger_projection")?;
        finish_inbound_outcome_ledger_projection(
            &transaction,
            &current,
            ledger,
            missions.len(),
            connections.len(),
            identity_links.len(),
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &ledger.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_local_inbound_context_capsule(
        &mut self,
        workspace: &ContextWorkspace,
        branches: &[ContextBranch],
        lease: &WorkerLease,
        facts: &[TruthFact],
        capsule: &ContextCapsule,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        if object_id != capsule.id.as_str() || remote_revision == 0 || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound context capsule projection".into(),
            ));
        }
        let mission = self.load_mission(&capsule.project_id, &capsule.mission_id)?;
        validate_context_bundle(workspace, branches, lease, capsule, facts, &mission, now)?;
        let existing =
            load_existing_context_projection(self, workspace, branches, lease, facts, capsule)?;

        let transaction = self.connection.transaction()?;
        ensure_project(&transaction, &capsule.tenant_id, &capsule.project_id)?;
        let current = load_inbound_required(&transaction, &capsule.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(capsule.revision)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != "context_capsule"
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        transaction.execute_batch("SAVEPOINT context_capsule_projection")?;
        let projection = project_context_capsule_snapshot(
            &transaction,
            current.projection_revision,
            &existing,
            workspace,
            branches,
            lease,
            facts,
            capsule,
        );
        if let Err(error_code) = projection {
            transaction.execute_batch(
                "ROLLBACK TO context_capsule_projection; RELEASE context_capsule_projection",
            )?;
            mark_inbound_projection_conflict(&transaction, &current, error_code, now)?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_capsule:{}", capsule.id),
                expected_revision: existing.capsule.as_ref().map_or(0, |item| item.revision),
            });
        }
        transaction.execute_batch("RELEASE context_capsule_projection")?;
        finish_inbound_context_capsule_projection(
            &transaction,
            &current,
            capsule,
            branches.len(),
            facts.len(),
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &capsule.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }
}

struct ExistingContextProjection {
    workspace: Option<ContextWorkspace>,
    branches: BTreeMap<ContextBranchId, Option<ContextBranch>>,
    lease: Option<WorkerLease>,
    facts: BTreeMap<(FactId, u64), Option<TruthFact>>,
    capsule: Option<ContextCapsule>,
}

fn load_existing_context_projection(
    store: &ProjectStore,
    workspace: &ContextWorkspace,
    branches: &[ContextBranch],
    lease: &WorkerLease,
    facts: &[TruthFact],
    capsule: &ContextCapsule,
) -> Result<ExistingContextProjection, StorageError> {
    let mut existing = ExistingContextProjection {
        workspace: optional_projection_record(
            store.load_context_workspace(&workspace.project_id, &workspace.id),
        )?,
        branches: BTreeMap::new(),
        lease: optional_projection_record(store.load_worker_lease(&lease.project_id, &lease.id))?,
        facts: BTreeMap::new(),
        capsule: optional_projection_record(
            store.load_context_capsule(&capsule.project_id, &capsule.id),
        )?,
    };
    for branch in branches {
        existing.branches.insert(
            branch.id.clone(),
            optional_projection_record(store.load_context_branch(&branch.project_id, &branch.id))?,
        );
    }
    for fact in facts {
        existing.facts.insert(
            (fact.id.clone(), fact.version),
            optional_projection_record(store.load_truth_fact_revision(
                &fact.project_id,
                &fact.id,
                fact.version,
            ))?,
        );
    }
    Ok(existing)
}

struct ExistingOutcomeProjection {
    ledger: Option<OutcomeLedger>,
    missions: BTreeMap<MissionId, Option<Mission>>,
    connections: BTreeMap<ConnectionId, Option<ConnectionSnapshot>>,
    companies: BTreeMap<CompanyId, Option<Company>>,
    people: BTreeMap<PersonId, Option<Person>>,
    partners: BTreeMap<PartnerId, Option<Partner>>,
    identity_links: BTreeMap<IdentityLinkId, Option<IdentityLink>>,
    consents: BTreeMap<ConsentRecordId, Option<ConsentRecord>>,
    campaigns: BTreeMap<CampaignId, Option<Campaign>>,
    opportunities: BTreeMap<OpportunityId, Option<Opportunity>>,
}

#[allow(clippy::too_many_arguments)]
fn load_existing_outcome_projection(
    store: &ProjectStore,
    missions: &[Mission],
    connections: &[ConnectionSnapshot],
    companies: &[Company],
    people: &[Person],
    partners: &[Partner],
    identity_links: &[IdentityLink],
    consents: &[ConsentRecord],
    campaigns: &[Campaign],
    opportunities: &[Opportunity],
    ledger: &OutcomeLedger,
) -> Result<ExistingOutcomeProjection, StorageError> {
    let mut existing = ExistingOutcomeProjection {
        ledger: optional_projection_record(store.load_outcome_ledger(&ledger.project_id))?,
        missions: BTreeMap::new(),
        connections: BTreeMap::new(),
        companies: BTreeMap::new(),
        people: BTreeMap::new(),
        partners: BTreeMap::new(),
        identity_links: BTreeMap::new(),
        consents: BTreeMap::new(),
        campaigns: BTreeMap::new(),
        opportunities: BTreeMap::new(),
    };
    for mission in missions {
        existing.missions.insert(
            mission.id.clone(),
            optional_projection_record(store.load_mission(&ledger.project_id, &mission.id))?,
        );
    }
    for connection in connections {
        existing.connections.insert(
            connection.id.clone(),
            optional_projection_record(
                store
                    .load_connection(&ledger.project_id, &connection.id)
                    .map(|item| item.snapshot()),
            )?,
        );
    }
    for company in companies {
        existing.companies.insert(
            company.id.clone(),
            optional_projection_record(store.load_company(&ledger.project_id, &company.id))?,
        );
    }
    for person in people {
        existing.people.insert(
            person.id.clone(),
            optional_projection_record(store.load_person(&ledger.project_id, &person.id))?,
        );
    }
    for partner in partners {
        existing.partners.insert(
            partner.id.clone(),
            optional_projection_record(store.load_partner(&ledger.project_id, &partner.id))?,
        );
    }
    for link in identity_links {
        existing.identity_links.insert(
            link.id.clone(),
            optional_projection_record(store.load_identity_link(&ledger.project_id, &link.id))?,
        );
    }
    for consent in consents {
        existing.consents.insert(
            consent.id.clone(),
            optional_projection_record(store.load_consent_record(&ledger.project_id, &consent.id))?,
        );
    }
    for campaign in campaigns {
        existing.campaigns.insert(
            campaign.id.clone(),
            optional_projection_record(store.load_campaign(&ledger.project_id, &campaign.id))?,
        );
    }
    for opportunity in opportunities {
        existing.opportunities.insert(
            opportunity.id.clone(),
            optional_projection_record(
                store.load_opportunity(&ledger.project_id, &opportunity.id),
            )?,
        );
    }
    Ok(existing)
}

fn optional_projection_record<T>(
    result: Result<T, StorageError>,
) -> Result<Option<T>, StorageError> {
    match result {
        Ok(item) => Ok(Some(item)),
        Err(StorageError::ScopedRecordNotFound { .. } | StorageError::MissionNotFound { .. }) => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn project_context_capsule_snapshot(
    transaction: &Transaction<'_>,
    previous_projection_revision: Option<u64>,
    existing: &ExistingContextProjection,
    workspace: &ContextWorkspace,
    branches: &[ContextBranch],
    lease: &WorkerLease,
    facts: &[TruthFact],
    capsule: &ContextCapsule,
) -> Result<(), &'static str> {
    match &existing.workspace {
        Some(stored) if stored == workspace => {}
        Some(_) => return Err("context_workspace_conflict"),
        None => insert_context_workspace(transaction, workspace)
            .map_err(|_| "context_workspace_insert_failed")?,
    }
    for branch in branches {
        match existing.branches.get(&branch.id).and_then(Option::as_ref) {
            Some(stored) if stored == branch => {}
            Some(_) => return Err("context_branch_conflict"),
            None => insert_context_branch(transaction, branch)
                .map_err(|_| "context_branch_insert_failed")?,
        }
    }
    for fact in facts {
        match existing
            .facts
            .get(&(fact.id.clone(), fact.version))
            .and_then(Option::as_ref)
        {
            Some(stored) if stored == fact => {}
            Some(_) => return Err("context_fact_revision_conflict"),
            None => {
                let current_version: Option<i64> = transaction
                    .query_row(
                        "SELECT current_version FROM truth_fact_heads
                         WHERE project_id = ?1 AND id = ?2",
                        params![fact.project_id.as_str(), fact.id.as_str()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|_| "context_fact_head_read_failed")?;
                if current_version.is_some() || fact.version != 1 {
                    return Err("context_fact_history_incomplete");
                }
                insert_truth_head(transaction, fact)
                    .map_err(|_| "context_fact_head_insert_failed")?;
                insert_truth_revision(transaction, fact)
                    .map_err(|_| "context_fact_revision_insert_failed")?;
            }
        }
    }
    match &existing.lease {
        Some(stored) if stored == lease => {}
        Some(_) => return Err("worker_lease_conflict"),
        None => {
            insert_worker_lease(transaction, lease).map_err(|_| "worker_lease_insert_failed")?;
        }
    }
    match &existing.capsule {
        Some(stored) if stored == capsule => {}
        Some(stored)
            if previous_projection_revision == Some(stored.revision)
                && capsule.follows(stored).unwrap_or(false) =>
        {
            update_context_capsule_row(transaction, capsule, stored.revision)
                .map_err(|_| "context_capsule_update_failed")?;
        }
        Some(_) => return Err("context_capsule_local_divergence"),
        None => {
            insert_context_capsule(transaction, capsule)
                .map_err(|_| "context_capsule_insert_failed")?;
            insert_context_capsule_facts(transaction, capsule)
                .map_err(|_| "context_capsule_fact_insert_failed")?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn validate_outcome_projection_bundle(
    missions: &[Mission],
    connections: &[ConnectionSnapshot],
    companies: &[Company],
    people: &[Person],
    partners: &[Partner],
    identity_links: &[IdentityLink],
    consents: &[ConsentRecord],
    campaigns: &[Campaign],
    opportunities: &[Opportunity],
    ledger: &OutcomeLedger,
) -> Result<(), StorageError> {
    let invalid = || StorageError::DomainDecode("invalid inbound outcome support closure".into());
    ledger.validate().map_err(|_| invalid())?;
    for event in &ledger.events {
        event.validate().map_err(|_| invalid())?;
    }
    let mission_map = missions
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let connection_map = connections
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let company_map = companies
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let person_map = people
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let partner_map = partners
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let identity_map = identity_links
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let consent_map = consents
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let campaign_map = campaigns
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let opportunity_map = opportunities
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    if mission_map.len() != missions.len()
        || connection_map.len() != connections.len()
        || company_map.len() != companies.len()
        || person_map.len() != people.len()
        || partner_map.len() != partners.len()
        || identity_map.len() != identity_links.len()
        || consent_map.len() != consents.len()
        || campaign_map.len() != campaigns.len()
        || opportunity_map.len() != opportunities.len()
    {
        return Err(invalid());
    }
    let in_scope = |tenant_id: &TenantId, project_id: &ProjectId| {
        tenant_id == &ledger.tenant_id && project_id == &ledger.project_id
    };
    for mission in missions {
        if !in_scope(&mission.tenant_id, &mission.project_id)
            || mission.title.trim().is_empty()
            || mission.revision == 0
            || mission.created_at > mission.updated_at
            || mission
                .contract
                .validate(mission.contract.valid_from)
                .is_err()
        {
            return Err(invalid());
        }
    }
    for connection in connections {
        connection.validate().map_err(|_| invalid())?;
        if !in_scope(&connection.tenant_id, &connection.project_id) {
            return Err(invalid());
        }
    }
    for company in companies {
        company.validate().map_err(|_| invalid())?;
        if !in_scope(&company.tenant_id, &company.project_id) {
            return Err(invalid());
        }
    }
    for person in people {
        person.validate().map_err(|_| invalid())?;
        if !in_scope(&person.tenant_id, &person.project_id) {
            return Err(invalid());
        }
    }
    for partner in partners {
        partner.validate().map_err(|_| invalid())?;
        if !in_scope(&partner.tenant_id, &partner.project_id) {
            return Err(invalid());
        }
    }
    for link in identity_links {
        link.validate().map_err(|_| invalid())?;
        if !in_scope(&link.tenant_id, &link.project_id)
            || link.status != IdentityLinkStatus::Confirmed
        {
            return Err(invalid());
        }
    }
    for consent in consents {
        consent.validate().map_err(|_| invalid())?;
        if !in_scope(&consent.tenant_id, &consent.project_id) {
            return Err(invalid());
        }
    }
    for campaign in campaigns {
        campaign.validate().map_err(|_| invalid())?;
        if !in_scope(&campaign.tenant_id, &campaign.project_id) {
            return Err(invalid());
        }
    }
    for opportunity in opportunities {
        opportunity.validate().map_err(|_| invalid())?;
        if !in_scope(&opportunity.tenant_id, &opportunity.project_id) {
            return Err(invalid());
        }
    }

    let mut expected_missions = BTreeSet::new();
    let mut expected_connections = BTreeSet::new();
    let mut expected_identities = BTreeSet::new();
    let mut expected_campaigns = BTreeSet::new();
    let mut expected_opportunities = BTreeSet::new();
    let mut expected_partners = BTreeSet::new();
    for event in &ledger.events {
        expected_missions.insert(event.mission_id.clone());
        if let Some(connection_id) = &event.connection_id {
            expected_connections.insert(connection_id.clone());
            let connection = connection_map.get(connection_id).ok_or_else(&invalid)?;
            if connection.provider != event.provider
                || Some(&connection.account_id) != event.account_id.as_ref()
            {
                return Err(invalid());
            }
        }
        if let Some(link_id) = &event.identity_link_id {
            expected_identities.insert(link_id.clone());
            let link = identity_map.get(link_id).ok_or_else(&invalid)?;
            if let Some(account_id) = &event.account_id
                && !link.confirms_external_identity(&event.provider, account_id)
            {
                return Err(invalid());
            }
        }
        if let Some(campaign_id) = &event.campaign_id {
            expected_campaigns.insert(campaign_id.clone());
        }
        if let Some(opportunity_id) = &event.opportunity_id {
            expected_opportunities.insert(opportunity_id.clone());
        }
        if let Some(partner_id) = &event.partner_id {
            expected_partners.insert(partner_id.clone());
        }
    }
    for attribution in &ledger.attributions {
        if let Some(touchpoint) = &attribution.touchpoint {
            expected_missions.insert(touchpoint.mission_id.clone());
        }
    }
    expected_partners.extend(
        ledger
            .commissions
            .iter()
            .map(|record| record.partner_id.clone()),
    );
    if expected_connections != connection_map.keys().cloned().collect()
        || expected_identities != identity_map.keys().cloned().collect()
        || expected_campaigns != campaign_map.keys().cloned().collect()
        || expected_opportunities != opportunity_map.keys().cloned().collect()
    {
        return Err(invalid());
    }

    let mut expected_people = BTreeSet::new();
    let mut expected_companies = BTreeSet::new();
    let mut expected_consents = BTreeSet::new();
    for link in identity_links {
        match &link.subject {
            IdentitySubject::Person(id) => {
                expected_people.insert(id.clone());
            }
            IdentitySubject::Company(id) => {
                expected_companies.insert(id.clone());
            }
            IdentitySubject::Partner(id) => {
                expected_partners.insert(id.clone());
            }
        }
    }
    for campaign in campaigns {
        expected_missions.insert(campaign.mission_id.clone());
        for recipient in &campaign.recipients {
            expected_people.insert(recipient.person_id.clone());
            expected_consents.insert(recipient.consent_record_id.clone());
            let consent = consent_map
                .get(&recipient.consent_record_id)
                .ok_or_else(&invalid)?;
            if consent.person_id != recipient.person_id
                || consent.purpose != campaign.purpose
                || consent.channel != campaign.channel
                || !consent.market.eq_ignore_ascii_case(&campaign.market)
            {
                return Err(invalid());
            }
        }
    }
    for opportunity in opportunities {
        expected_companies.insert(opportunity.company_id.clone());
        expected_people.extend(
            opportunity
                .buying_committee
                .iter()
                .map(|member| member.person_id.clone()),
        );
    }
    for partner in partners {
        if let Some(person_id) = &partner.person_id {
            expected_people.insert(person_id.clone());
        }
        if let Some(company_id) = &partner.company_id {
            expected_companies.insert(company_id.clone());
        }
    }
    for person in people {
        if let Some(company_id) = &person.company_id {
            expected_companies.insert(company_id.clone());
        }
    }
    if expected_missions != mission_map.keys().cloned().collect()
        || expected_partners != partner_map.keys().cloned().collect()
        || expected_people != person_map.keys().cloned().collect()
        || expected_companies != company_map.keys().cloned().collect()
        || expected_consents != consent_map.keys().cloned().collect()
    {
        return Err(invalid());
    }
    for person in people {
        if person
            .company_id
            .as_ref()
            .is_some_and(|id| !company_map.contains_key(id))
        {
            return Err(invalid());
        }
    }
    for partner in partners {
        if partner
            .person_id
            .as_ref()
            .is_some_and(|id| !person_map.contains_key(id))
            || partner
                .company_id
                .as_ref()
                .is_some_and(|id| !company_map.contains_key(id))
        {
            return Err(invalid());
        }
    }
    for opportunity in opportunities {
        if !company_map.contains_key(&opportunity.company_id)
            || opportunity
                .buying_committee
                .iter()
                .any(|member| !person_map.contains_key(&member.person_id))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn project_outcome_ledger_snapshot(
    transaction: &Transaction<'_>,
    projection_revision: Option<u64>,
    existing: &ExistingOutcomeProjection,
    missions: &[Mission],
    connections: &[ConnectionSnapshot],
    companies: &[Company],
    people: &[Person],
    partners: &[Partner],
    identity_links: &[IdentityLink],
    consents: &[ConsentRecord],
    campaigns: &[Campaign],
    opportunities: &[Opportunity],
    ledger: &OutcomeLedger,
) -> Result<(), &'static str> {
    project_outcome_support(
        transaction,
        existing,
        missions,
        connections,
        companies,
        people,
        partners,
        identity_links,
        consents,
        campaigns,
        opportunities,
    )?;
    match &existing.ledger {
        None if projection_revision.is_none() => {
            insert_outcome_ledger_head(transaction, ledger)
                .map_err(|_| "outcome_ledger_insert_failed")?;
            persist_outcome_children(transaction, ledger)
                .map_err(|_| "outcome_ledger_children_insert_failed")
        }
        Some(stored) if stored == ledger && projection_revision.is_none() => Ok(()),
        Some(stored)
            if stored == ledger
                && projection_revision.and_then(|revision| revision.checked_add(1))
                    == Some(ledger.revision) =>
        {
            Ok(())
        }
        Some(stored)
            if projection_revision == Some(stored.revision)
                && ledger.follows(stored).unwrap_or(false) =>
        {
            if update_outcome_ledger_head(transaction, ledger, stored.revision)
                .map_err(|_| "outcome_ledger_cas_failed")?
                != 1
            {
                return Err("outcome_ledger_cas_failed");
            }
            persist_outcome_children(transaction, ledger)
                .map_err(|_| "outcome_ledger_children_projection_failed")
        }
        _ => Err("local_outcome_ledger_changed_since_remote_projection"),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn project_outcome_support(
    transaction: &Transaction<'_>,
    existing: &ExistingOutcomeProjection,
    missions: &[Mission],
    connections: &[ConnectionSnapshot],
    companies: &[Company],
    people: &[Person],
    partners: &[Partner],
    identity_links: &[IdentityLink],
    consents: &[ConsentRecord],
    campaigns: &[Campaign],
    opportunities: &[Opportunity],
) -> Result<(), &'static str> {
    for mission in missions {
        match existing.missions.get(&mission.id) {
            Some(Some(stored)) if stored == mission => {}
            Some(None) => insert_mission_normalized(transaction, mission)
                .map_err(|_| "outcome_mission_insert_failed")?,
            _ => return Err("outcome_mission_changed_since_projection"),
        }
    }
    for connection in connections {
        match existing.connections.get(&connection.id) {
            Some(Some(stored)) if stored == connection => {}
            Some(None) => insert_connection(transaction, connection)
                .map_err(|_| "outcome_connection_insert_failed")?,
            _ => return Err("outcome_connection_changed_since_projection"),
        }
    }
    for company in companies {
        match existing.companies.get(&company.id) {
            Some(Some(stored)) if stored == company => {}
            Some(None) => insert_company_record(transaction, company)
                .map_err(|_| "outcome_company_insert_failed")?,
            _ => return Err("outcome_company_changed_since_projection"),
        }
    }
    for person in people {
        match existing.people.get(&person.id) {
            Some(Some(stored)) if stored == person => {}
            Some(None) => {
                ensure_company_reference(
                    transaction,
                    &person.tenant_id,
                    &person.project_id,
                    person.company_id.as_ref(),
                )
                .map_err(|_| "outcome_person_company_scope_failed")?;
                insert_person_record(transaction, person)
                    .map_err(|_| "outcome_person_insert_failed")?;
            }
            _ => return Err("outcome_person_changed_since_projection"),
        }
    }
    for partner in partners {
        match existing.partners.get(&partner.id) {
            Some(Some(stored)) if stored == partner => {}
            Some(None) => {
                ensure_partner_references(transaction, partner)
                    .map_err(|_| "outcome_partner_reference_failed")?;
                insert_partner(transaction, partner)
                    .map_err(|_| "outcome_partner_insert_failed")?;
            }
            _ => return Err("outcome_partner_changed_since_projection"),
        }
    }
    for link in identity_links {
        match existing.identity_links.get(&link.id) {
            Some(Some(stored)) if stored == link => {}
            Some(None) => {
                ensure_subject(
                    transaction,
                    &link.tenant_id,
                    &link.project_id,
                    &link.subject,
                )
                .map_err(|_| "outcome_identity_subject_scope_failed")?;
                insert_identity_link(transaction, link)
                    .map_err(|_| "outcome_identity_link_insert_failed")?;
            }
            _ => return Err("outcome_identity_link_changed_since_projection"),
        }
    }
    for consent in consents {
        match existing.consents.get(&consent.id) {
            Some(Some(stored)) if stored == consent => {}
            Some(None) => {
                insert_consent(transaction, consent)
                    .map_err(|_| "outcome_consent_insert_failed")?;
            }
            _ => return Err("outcome_consent_changed_since_projection"),
        }
    }
    for campaign in campaigns {
        match existing.campaigns.get(&campaign.id) {
            Some(Some(stored)) if stored == campaign => {}
            Some(None) => {
                ensure_campaign_scope(transaction, campaign)
                    .map_err(|_| "outcome_campaign_scope_failed")?;
                insert_campaign(transaction, campaign)
                    .map_err(|_| "outcome_campaign_insert_failed")?;
                persist_campaign_recipients(transaction, campaign)
                    .map_err(|_| "outcome_campaign_recipients_insert_failed")?;
            }
            _ => return Err("outcome_campaign_changed_since_projection"),
        }
    }
    for opportunity in opportunities {
        match existing.opportunities.get(&opportunity.id) {
            Some(Some(stored)) if stored == opportunity => {}
            Some(None) => {
                ensure_opportunity_scope(transaction, opportunity)
                    .map_err(|_| "outcome_opportunity_scope_failed")?;
                insert_opportunity(transaction, opportunity)
                    .map_err(|_| "outcome_opportunity_insert_failed")?;
                persist_opportunity_children(transaction, opportunity)
                    .map_err(|_| "outcome_opportunity_children_insert_failed")?;
            }
            _ => return Err("outcome_opportunity_changed_since_projection"),
        }
    }
    Ok(())
}

struct ExistingConversationProjection {
    conversation: Option<Conversation>,
    connection: Option<ConnectionSnapshot>,
    consents: BTreeMap<ConsentRecordId, Option<ConsentRecord>>,
}

fn load_existing_conversation_projection(
    store: &ProjectStore,
    conversation: &Conversation,
    connection: &ConnectionSnapshot,
    consents: &[ConsentRecord],
) -> Result<ExistingConversationProjection, StorageError> {
    let existing_conversation =
        match store.load_conversation(&conversation.project_id, &conversation.id) {
            Ok(existing) => Some(existing),
            Err(StorageError::ScopedRecordNotFound {
                kind: "conversation",
                ..
            }) => None,
            Err(error) => return Err(error),
        };
    let existing_connection = match store.load_connection(&conversation.project_id, &connection.id)
    {
        Ok(existing) => Some(existing.snapshot()),
        Err(StorageError::ScopedRecordNotFound {
            kind: "connection", ..
        }) => None,
        Err(error) => return Err(error),
    };
    let mut existing_consents = BTreeMap::new();
    for consent in consents {
        let existing = match store.load_consent_record(&conversation.project_id, &consent.id) {
            Ok(existing) => Some(existing),
            Err(StorageError::ScopedRecordNotFound {
                kind: "consent", ..
            }) => None,
            Err(error) => return Err(error),
        };
        existing_consents.insert(consent.id.clone(), existing);
    }
    Ok(ExistingConversationProjection {
        conversation: existing_conversation,
        connection: existing_connection,
        consents: existing_consents,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the projector receives the authenticated aggregate and each independently scoped prerequisite"
)]
fn project_conversation_snapshot(
    transaction: &Transaction<'_>,
    projection_revision: Option<u64>,
    existing_conversation: Option<&Conversation>,
    existing_connection: Option<&ConnectionSnapshot>,
    existing_consents: &BTreeMap<ConsentRecordId, Option<ConsentRecord>>,
    identity: &ConversationIdentitySnapshot,
    connection: &ConnectionSnapshot,
    consents: &[ConsentRecord],
    conversation: &Conversation,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    match existing_conversation {
        None if projection_revision.is_none()
            && conversation.is_initial_snapshot().unwrap_or(false) =>
        {
            project_conversation_support(
                transaction,
                existing_connection,
                existing_consents,
                identity,
                connection,
                consents,
            )?;
            ensure_conversation_scope(transaction, conversation)
                .map_err(|_| "invalid_conversation_scope")?;
            insert_conversation(transaction, conversation)
                .map_err(|_| "conversation_insert_failed")?;
            persist_conversation_messages(transaction, conversation)
                .map_err(|_| "conversation_message_insert_failed")?;
            Ok(())
        }
        Some(existing) if existing == conversation && projection_revision.is_none() => {
            project_conversation_support(
                transaction,
                existing_connection,
                existing_consents,
                identity,
                connection,
                consents,
            )
        }
        Some(existing)
            if existing == conversation
                && projection_revision.and_then(|revision| revision.checked_add(1))
                    == Some(conversation.revision) =>
        {
            project_conversation_support(
                transaction,
                existing_connection,
                existing_consents,
                identity,
                connection,
                consents,
            )
        }
        Some(existing)
            if projection_revision == Some(existing.revision)
                && conversation
                    .follows(existing, identity, connection, mission, consents, now)
                    .unwrap_or(false) =>
        {
            project_conversation_support(
                transaction,
                existing_connection,
                existing_consents,
                identity,
                connection,
                consents,
            )?;
            let updated = update_conversation_row(transaction, conversation, existing.revision)
                .map_err(|_| "conversation_cas_failed")?;
            if updated != 1 {
                return Err("conversation_cas_failed");
            }
            persist_conversation_messages(transaction, conversation)
                .map_err(|_| "conversation_message_projection_failed")?;
            Ok(())
        }
        _ => Err("local_conversation_changed_since_remote_projection"),
    }
}

fn project_conversation_support(
    transaction: &Transaction<'_>,
    existing_connection: Option<&ConnectionSnapshot>,
    existing_consents: &BTreeMap<ConsentRecordId, Option<ConsentRecord>>,
    identity: &ConversationIdentitySnapshot,
    connection: &ConnectionSnapshot,
    consents: &[ConsentRecord],
) -> Result<(), &'static str> {
    project_conversation_identity(transaction, identity)?;
    match existing_connection {
        Some(existing) if existing == connection => {}
        None => insert_connection(transaction, connection)
            .map_err(|_| "conversation_connection_insert_failed")?,
        Some(_) => return Err("conversation_connection_changed_since_projection"),
    }
    for consent in consents {
        match existing_consents.get(&consent.id) {
            Some(Some(existing)) if existing == consent => {}
            Some(None) => insert_consent(transaction, consent)
                .map_err(|_| "conversation_consent_insert_failed")?,
            _ => return Err("conversation_consent_changed_since_projection"),
        }
    }
    Ok(())
}

fn project_conversation_identity(
    transaction: &Transaction<'_>,
    identity: &ConversationIdentitySnapshot,
) -> Result<(), &'static str> {
    if let Some(company) = &identity.company {
        match load_creator_company(transaction, &company.project_id, &company.id)
            .map_err(|_| "conversation_company_read_failed")?
        {
            Some(existing) if existing == *company => {}
            Some(_) => return Err("conversation_company_changed_since_projection"),
            None => insert_company_record(transaction, company)
                .map_err(|_| "conversation_company_insert_failed")?,
        }
    }
    match load_creator_person(
        transaction,
        &identity.person.project_id,
        &identity.person.id,
    )
    .map_err(|_| "conversation_person_read_failed")?
    {
        Some(existing) if existing == identity.person => Ok(()),
        Some(_) => Err("conversation_person_changed_since_projection"),
        None => {
            ensure_company_reference(
                transaction,
                &identity.person.tenant_id,
                &identity.person.project_id,
                identity.person.company_id.as_ref(),
            )
            .map_err(|_| "conversation_person_company_scope_failed")?;
            insert_person_record(transaction, &identity.person)
                .map_err(|_| "conversation_person_insert_failed")
        }
    }
}

fn validate_creator_identity_bundle(
    identities: &[CreatorIdentitySnapshot],
    hiring: &CreatorHiring,
    task: &CreatorTask,
) -> Result<(), StorageError> {
    let invalid =
        || StorageError::DomainDecode("invalid inbound creator identity projection".into());
    if identities.len() != hiring.candidates.len() {
        return Err(invalid());
    }
    let mut partner_ids = BTreeSet::new();
    let mut people = BTreeMap::new();
    let mut companies = BTreeMap::new();
    for identity in identities {
        let candidate = hiring
            .candidates
            .iter()
            .find(|candidate| candidate.partner_id == identity.partner.id)
            .ok_or_else(&invalid)?;
        identity
            .validate_for_candidate(&task.tenant_id, &task.project_id, candidate)
            .map_err(|_| invalid())?;
        if !partner_ids.insert(identity.partner.id.clone()) {
            return Err(invalid());
        }
        if let Some(person) = &identity.person
            && people
                .insert(person.id.clone(), person.clone())
                .is_some_and(|previous: Person| previous != *person)
        {
            return Err(invalid());
        }
        if let Some(company) = &identity.company
            && companies
                .insert(company.id.clone(), company.clone())
                .is_some_and(|previous: Company| previous != *company)
        {
            return Err(invalid());
        }
    }
    if hiring
        .candidates
        .iter()
        .any(|candidate| !partner_ids.contains(&candidate.partner_id))
    {
        return Err(invalid());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn project_creator_work_snapshot(
    transaction: &Transaction<'_>,
    projection_revision: Option<u64>,
    existing_hiring: Option<&CreatorHiring>,
    existing_task: Option<&CreatorTask>,
    identities: &[CreatorIdentitySnapshot],
    hiring: &CreatorHiring,
    task: &CreatorTask,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    match (existing_hiring, existing_task) {
        (None, None) if projection_revision.is_none() => {
            project_creator_identities(transaction, identities)?;
            ensure_hiring_scope(transaction, hiring).map_err(|_| "invalid_creator_hiring_scope")?;
            ensure_project_and_mission(
                transaction,
                &task.tenant_id,
                &task.project_id,
                &task.mission_id,
            )
            .map_err(|_| "invalid_creator_task_scope")?;
            insert_hiring(transaction, hiring).map_err(|_| "creator_hiring_insert_failed")?;
            persist_children(transaction, hiring)
                .map_err(|_| "creator_hiring_children_insert_failed")?;
            insert_creator_task(transaction, task).map_err(|_| "creator_task_insert_failed")?;
            insert_creator_children(transaction, task)
                .map_err(|_| "creator_task_children_insert_failed")?;
            Ok(())
        }
        (Some(existing_hiring), Some(existing_task))
            if projection_revision.is_none()
                && existing_hiring == hiring
                && existing_task == task =>
        {
            ensure_creator_identities_exact(transaction, identities)?;
            Ok(())
        }
        (Some(existing_hiring), Some(existing_task))
            if existing_hiring == hiring
                && existing_task == task
                && projection_revision.and_then(|revision| revision.checked_add(1))
                    == Some(task.state_revision) =>
        {
            ensure_creator_identities_exact(transaction, identities)?;
            Ok(())
        }
        (Some(existing_hiring), Some(existing_task))
            if existing_hiring == hiring
                && projection_revision == Some(existing_task.state_revision)
                && task
                    .follows(existing_task, hiring, mission, now)
                    .unwrap_or(false) =>
        {
            ensure_creator_identities_exact(transaction, identities)?;
            update_creator_task_row(transaction, task, existing_task.state_revision)
                .map_err(|_| "creator_task_cas_failed")?;
            clear_creator_children(transaction, task)
                .map_err(|_| "creator_task_children_clear_failed")?;
            insert_creator_children(transaction, task)
                .map_err(|_| "creator_task_children_insert_failed")?;
            Ok(())
        }
        _ => Err("local_creator_work_changed_since_remote_projection"),
    }
}

fn project_creator_identities(
    transaction: &Transaction<'_>,
    identities: &[CreatorIdentitySnapshot],
) -> Result<(), &'static str> {
    for identity in identities {
        if let Some(company) = &identity.company {
            match load_creator_company(transaction, &company.project_id, &company.id)
                .map_err(|_| "creator_company_read_failed")?
            {
                Some(existing) if existing == *company => {}
                Some(_) => return Err("creator_company_changed_since_projection"),
                None => insert_company_record(transaction, company)
                    .map_err(|_| "creator_company_insert_failed")?,
            }
        }
    }

    for identity in identities {
        if let Some(person) = &identity.person {
            match load_creator_person(transaction, &person.project_id, &person.id)
                .map_err(|_| "creator_person_read_failed")?
            {
                Some(existing) if existing == *person => {}
                Some(_) => return Err("creator_person_changed_since_projection"),
                None => {
                    ensure_company_reference(
                        transaction,
                        &person.tenant_id,
                        &person.project_id,
                        person.company_id.as_ref(),
                    )
                    .map_err(|_| "creator_person_company_scope_failed")?;
                    insert_person_record(transaction, person)
                        .map_err(|_| "creator_person_insert_failed")?;
                }
            }
        }
    }

    let mut partner_ids = BTreeSet::new();
    for identity in identities {
        if !partner_ids.insert(identity.partner.id.clone()) {
            return Err("duplicate_creator_partner_identity");
        }
        match load_creator_partner(
            transaction,
            &identity.partner.project_id,
            &identity.partner.id,
        )
        .map_err(|_| "creator_partner_read_failed")?
        {
            Some(existing) if existing == identity.partner => {}
            Some(_) => return Err("creator_partner_changed_since_projection"),
            None => {
                ensure_partner_references(transaction, &identity.partner)
                    .map_err(|_| "creator_partner_reference_failed")?;
                insert_partner(transaction, &identity.partner)
                    .map_err(|_| "creator_partner_insert_failed")?;
            }
        }
    }
    Ok(())
}

fn ensure_creator_identities_exact(
    transaction: &Transaction<'_>,
    identities: &[CreatorIdentitySnapshot],
) -> Result<(), &'static str> {
    for identity in identities {
        if load_creator_partner(
            transaction,
            &identity.partner.project_id,
            &identity.partner.id,
        )
        .map_err(|_| "creator_partner_read_failed")?
            != Some(identity.partner.clone())
        {
            return Err("creator_partner_changed_since_projection");
        }
        if let Some(person) = &identity.person
            && load_creator_person(transaction, &person.project_id, &person.id)
                .map_err(|_| "creator_person_read_failed")?
                != Some(person.clone())
        {
            return Err("creator_person_changed_since_projection");
        }
        if let Some(company) = &identity.company
            && load_creator_company(transaction, &company.project_id, &company.id)
                .map_err(|_| "creator_company_read_failed")?
                != Some(company.clone())
        {
            return Err("creator_company_changed_since_projection");
        }
    }
    Ok(())
}

fn load_creator_company(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    company_id: &CompanyId,
) -> Result<Option<Company>, StorageError> {
    transaction
        .query_row(
            "SELECT id, tenant_id, project_id, legal_name, market, revision
             FROM companies WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), company_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(Company {
                id: CompanyId::from_stable(row.0),
                tenant_id: TenantId::from_stable(row.1),
                project_id: ProjectId::from_stable(row.2),
                legal_name: row.3,
                market: row.4,
                revision: from_sql_u64(row.5, "creator company revision")?,
            })
        })
        .transpose()
}

fn load_creator_person(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    person_id: &PersonId,
) -> Result<Option<Person>, StorageError> {
    transaction
        .query_row(
            "SELECT id, tenant_id, project_id, display_name, company_id, contacts_json, revision
             FROM people WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), person_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(Person {
                id: PersonId::from_stable(row.0),
                tenant_id: TenantId::from_stable(row.1),
                project_id: ProjectId::from_stable(row.2),
                display_name: row.3,
                company_id: row.4.map(CompanyId::from_stable),
                contacts: serde_json::from_str(&row.5)?,
                revision: from_sql_u64(row.6, "creator person revision")?,
            })
        })
        .transpose()
}

fn load_creator_partner(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    partner_id: &PartnerId,
) -> Result<Option<Partner>, StorageError> {
    transaction
        .query_row(
            "SELECT id, tenant_id, project_id, person_id, company_id, display_name,
                    supply_class, contact_permission, permission_evidence_digest, revision
             FROM partners WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), partner_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(Partner {
                id: PartnerId::from_stable(row.0),
                tenant_id: TenantId::from_stable(row.1),
                project_id: ProjectId::from_stable(row.2),
                person_id: row.3.map(PersonId::from_stable),
                company_id: row.4.map(CompanyId::from_stable),
                display_name: row.5,
                supply_class: serde_json::from_value(Value::String(row.6))?,
                contact_permission: serde_json::from_value(Value::String(row.7))?,
                permission_evidence_digest: row.8,
                revision: from_sql_u64(row.9, "creator partner revision")?,
            })
        })
        .transpose()
}

fn project_connection_snapshot(
    transaction: &Transaction<'_>,
    projection_revision: Option<u64>,
    existing: Option<&ConnectionSnapshot>,
    snapshot: &ConnectionSnapshot,
) -> Result<(), &'static str> {
    match existing {
        Some(existing) if existing == snapshot => Ok(()),
        None if projection_revision.is_none() => {
            insert_connection(transaction, snapshot)
                .map_err(|_| "invalid_initial_connection_metadata")?;
            Ok(())
        }
        Some(existing)
            if projection_revision == Some(existing.revision)
                && snapshot.follows(existing).unwrap_or(false) =>
        {
            update_connection(transaction, snapshot, existing.revision)
                .map_err(|_| "connection_metadata_cas_failed")?;
            Ok(())
        }
        _ => Err("local_connection_changed_since_remote_projection"),
    }
}

fn plan_work_product_projection(
    current: &LocalInboundSyncObject,
    mission: &mut Mission,
    existing_manifest: Option<&WorkProductManifest>,
    manifest: &WorkProductManifest,
    work_product: &WorkProduct,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    let existing_product = mission
        .work_products
        .iter()
        .find(|product| product.id == manifest.work_product_id)
        .cloned();
    match (existing_manifest, existing_product) {
        (None, None) if current.projection_revision.is_none() && manifest.version == 1 => {
            let mut draft = work_product.clone();
            if draft.revision != 1 || draft.status != WorkProductStatus::ReadyForReview {
                return Err("invalid_initial_work_product_revision");
            }
            draft.status = WorkProductStatus::Draft;
            mission
                .record_work_product(draft, now)
                .map_err(|_| "invalid_initial_work_product")?;
            if mission.work_products.last() != Some(work_product) {
                return Err("work_product_projection_mismatch");
            }
            Ok(())
        }
        (Some(previous_manifest), Some(previous_product))
            if current.projection_revision.is_none()
                && previous_manifest == manifest
                && &previous_product == work_product =>
        {
            Ok(())
        }
        (Some(previous_manifest), Some(previous_product))
            if current
                .projection_revision
                .and_then(|version| version.checked_add(1))
                == Some(manifest.version)
                && previous_manifest == manifest
                && &previous_product == work_product =>
        {
            Ok(())
        }
        (Some(previous_manifest), Some(previous_product))
            if current.projection_revision == Some(previous_manifest.version)
                && manifest.follows(previous_manifest).unwrap_or(false) =>
        {
            previous_manifest
                .validate_against(&previous_product)
                .map_err(|_| "local_work_product_changed_since_remote_projection")?;
            if work_product == &previous_product {
                Ok(())
            } else {
                mission
                    .revise_work_product(work_product.clone(), now)
                    .map_err(|_| "invalid_work_product_revision")
            }
        }
        _ => Err("local_work_product_changed_since_remote_projection"),
    }
}

fn stage_over_inbound_head(
    transaction: &Transaction<'_>,
    existing: LocalInboundSyncObject,
    envelope: &LocalInboundSyncEnvelope,
    expected_remote_revision: Option<u64>,
    now: DateTime<Utc>,
) -> Result<LocalInboundSyncStageOutcome, StorageError> {
    if existing.envelope.cell != envelope.cell
        || existing.envelope.object_kind != envelope.object_kind
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "inbound encrypted sync object scope",
            id: envelope.object_id.clone(),
        });
    }
    if envelope.remote_revision == existing.envelope.remote_revision {
        if existing.envelope != *envelope {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "inbound encrypted sync revision",
                id: format!("{}:{}", envelope.object_id, envelope.remote_revision),
            });
        }
        return Ok(LocalInboundSyncStageOutcome {
            object: existing,
            disposition: LocalInboundSyncStageDisposition::Duplicate,
        });
    }
    if envelope.remote_revision < existing.envelope.remote_revision {
        return Ok(LocalInboundSyncStageOutcome {
            object: existing,
            disposition: LocalInboundSyncStageDisposition::Stale,
        });
    }
    if expected_remote_revision != Some(existing.envelope.remote_revision) {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", envelope.object_id),
            expected_revision: expected_remote_revision.unwrap_or_default(),
        });
    }
    insert_inbound_version(transaction, envelope, now)?;
    let next_local_revision = next_revision(existing.revision)?;
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET current_remote_revision = ?4, key_version = ?5, content_digest = ?6,
             tombstone = ?7, status = 'staged', validation_digest = NULL,
             last_error_code = NULL, revision = ?8, updated_at = ?9
         WHERE project_id = ?1 AND object_id = ?2
           AND current_remote_revision = ?3 AND revision = ?10",
        params![
            envelope.project_id.as_str(),
            envelope.object_id,
            to_sql_u64(existing.envelope.remote_revision)?,
            to_sql_u64(envelope.remote_revision)?,
            to_sql_u64(envelope.key_version)?,
            envelope.content_digest,
            i64::from(envelope.tombstone),
            to_sql_u64(next_local_revision)?,
            now.to_rfc3339(),
            to_sql_u64(existing.revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", envelope.object_id),
            expected_revision: existing.revision,
        });
    }
    append_inbound_audit(
        transaction,
        envelope,
        "sync.inbound.advanced",
        LocalInboundSyncStatus::Staged,
        now,
    )?;
    Ok(LocalInboundSyncStageOutcome {
        object: load_inbound_required(transaction, &envelope.project_id, &envelope.object_id)?,
        disposition: LocalInboundSyncStageDisposition::Advanced,
    })
}

fn stage_first_inbound_head(
    transaction: &Transaction<'_>,
    envelope: &LocalInboundSyncEnvelope,
    expected_remote_revision: Option<u64>,
    now: DateTime<Utc>,
) -> Result<LocalInboundSyncStageOutcome, StorageError> {
    if expected_remote_revision.is_some() {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", envelope.object_id),
            expected_revision: expected_remote_revision.unwrap_or_default(),
        });
    }
    insert_inbound_version(transaction, envelope, now)?;
    transaction.execute(
        "INSERT INTO encrypted_sync_inbound_heads
           (tenant_id, project_id, cell, object_id, object_kind, current_remote_revision,
            key_version, content_digest, tombstone, status, validation_digest,
            projection_digest, projection_revision, last_error_code, revision, staged_at,
            updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'staged', NULL, NULL,
                 NULL, NULL, 1, ?10, ?10)",
        params![
            envelope.tenant_id.as_str(),
            envelope.project_id.as_str(),
            envelope.cell,
            envelope.object_id,
            envelope.object_kind,
            to_sql_u64(envelope.remote_revision)?,
            to_sql_u64(envelope.key_version)?,
            envelope.content_digest,
            i64::from(envelope.tombstone),
            now.to_rfc3339(),
        ],
    )?;
    append_inbound_audit(
        transaction,
        envelope,
        "sync.inbound.staged",
        LocalInboundSyncStatus::Staged,
        now,
    )?;
    Ok(LocalInboundSyncStageOutcome {
        object: load_inbound_required(transaction, &envelope.project_id, &envelope.object_id)?,
        disposition: LocalInboundSyncStageDisposition::Inserted,
    })
}

pub(crate) fn insert_operation(
    transaction: &Transaction<'_>,
    operation: &LocalSyncOperation,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO encrypted_sync_operations
           (tenant_id, project_id, idempotency_key_digest, intent_digest, request_digest, cell, object_id,
            object_kind, target_revision, key_version, content_digest, tombstone, request_json,
            status, remote_revision, remote_duplicate, last_error_code, revision, created_at,
            updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                 ?16, ?17, ?18, ?19, ?20)",
        rusqlite::params_from_iter(operation_params(operation)?),
    )?;
    Ok(())
}

fn update_operation(
    transaction: &Transaction<'_>,
    operation: &LocalSyncOperation,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_operations SET status = ?4, remote_revision = ?5,
           remote_duplicate = ?6, last_error_code = ?7, revision = ?8, updated_at = ?9
         WHERE project_id = ?1 AND idempotency_key_digest = ?2 AND revision = ?3",
        params![
            operation.project_id.as_str(),
            operation.idempotency_key_digest,
            to_sql_u64(expected_revision)?,
            status_name(operation.status),
            operation.remote_revision.map(to_sql_u64).transpose()?,
            i64::from(operation.remote_duplicate),
            operation.last_error_code,
            to_sql_u64(operation.revision)?,
            operation.updated_at.to_rfc3339(),
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!(
                "encrypted_sync_operation:{}",
                operation.idempotency_key_digest
            ),
            expected_revision,
        });
    }
    Ok(())
}

fn operation_params(
    operation: &LocalSyncOperation,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        operation.tenant_id.as_str().to_owned().into(),
        operation.project_id.as_str().to_owned().into(),
        operation.idempotency_key_digest.clone().into(),
        operation.intent_digest.clone().into(),
        operation.request_digest.clone().into(),
        operation.cell.clone().into(),
        operation.object_id.clone().into(),
        operation.object_kind.clone().into(),
        to_sql_u64(operation.target_revision)?.into(),
        to_sql_u64(operation.key_version)?.into(),
        operation.content_digest.clone().into(),
        i64::from(operation.tombstone).into(),
        serde_json::to_string(&operation.request)?.into(),
        status_name(operation.status).to_owned().into(),
        operation
            .remote_revision
            .map(to_sql_u64)
            .transpose()?
            .into(),
        i64::from(operation.remote_duplicate).into(),
        operation.last_error_code.clone().into(),
        to_sql_u64(operation.revision)?.into(),
        operation.created_at.to_rfc3339().into(),
        operation.updated_at.to_rfc3339().into(),
    ])
}

fn load_required(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    idempotency_key_digest: &str,
) -> Result<LocalSyncOperation, StorageError> {
    load_operation(transaction, project_id, idempotency_key_digest)?.ok_or_else(|| {
        StorageError::ScopedRecordNotFound {
            kind: "encrypted sync operation",
            project_id: project_id.clone(),
            id: idempotency_key_digest.to_owned(),
        }
    })
}

pub(crate) fn load_operation(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    idempotency_key_digest: &str,
) -> Result<Option<LocalSyncOperation>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, intent_digest, request_digest, cell, object_id, object_kind, target_revision,
                    key_version, content_digest, tombstone, request_json, status,
                    remote_revision, remote_duplicate, last_error_code, revision, created_at,
                    updated_at
             FROM encrypted_sync_operations
             WHERE project_id = ?1 AND idempotency_key_digest = ?2",
            params![project_id.as_str(), idempotency_key_digest],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let operation = LocalSyncOperation {
            tenant_id: TenantId::from_stable(row.0),
            project_id: project_id.clone(),
            idempotency_key_digest: idempotency_key_digest.to_owned(),
            intent_digest: row.1,
            request_digest: row.2,
            cell: row.3,
            object_id: row.4,
            object_kind: row.5,
            target_revision: from_sql_u64(row.6, "sync target revision")?,
            key_version: from_sql_u64(row.7, "sync key version")?,
            content_digest: row.8,
            tombstone: parse_bool(row.9)?,
            request: serde_json::from_str(&row.10)?,
            status: decode_status(&row.11)?,
            remote_revision: row
                .12
                .map(|value| from_sql_u64(value, "remote revision"))
                .transpose()?,
            remote_duplicate: parse_bool(row.13)?,
            last_error_code: row.14,
            revision: from_sql_u64(row.15, "sync operation revision")?,
            created_at: parse_time(&row.16)?,
            updated_at: parse_time(&row.17)?,
        };
        operation.validate()?;
        Ok(operation)
    })
    .transpose()
}

fn insert_inbound_version(
    transaction: &Transaction<'_>,
    envelope: &LocalInboundSyncEnvelope,
    staged_at: DateTime<Utc>,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO encrypted_sync_inbound_versions
           (tenant_id, project_id, cell, object_id, object_kind, remote_revision, key_version,
            content_digest, tombstone, request_digest, request_json, remote_recorded_at,
            staged_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            envelope.tenant_id.as_str(),
            envelope.project_id.as_str(),
            envelope.cell,
            envelope.object_id,
            envelope.object_kind,
            to_sql_u64(envelope.remote_revision)?,
            to_sql_u64(envelope.key_version)?,
            envelope.content_digest,
            i64::from(envelope.tombstone),
            envelope.request_digest,
            serde_json::to_string(&envelope.request)?,
            envelope.remote_recorded_at.to_rfc3339(),
            staged_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub(crate) fn load_inbound_required(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    object_id: &str,
) -> Result<LocalInboundSyncObject, StorageError> {
    load_inbound_object(transaction, project_id, object_id)?.ok_or_else(|| {
        StorageError::ScopedRecordNotFound {
            kind: "inbound encrypted sync object",
            project_id: project_id.clone(),
            id: object_id.to_owned(),
        }
    })
}

fn load_inbound_object(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    object_id: &str,
) -> Result<Option<LocalInboundSyncObject>, StorageError> {
    let row = connection
        .query_row(
            "SELECT h.tenant_id, h.cell, h.object_kind, h.current_remote_revision,
                    h.key_version, h.content_digest, h.tombstone, v.request_digest,
                    v.request_json, v.remote_recorded_at, h.status, h.validation_digest,
                    h.projection_digest, h.projection_revision, h.last_error_code, h.revision,
                    h.staged_at, h.updated_at
             FROM encrypted_sync_inbound_heads h
             JOIN encrypted_sync_inbound_versions v
               ON v.project_id = h.project_id AND v.cell = h.cell
              AND v.object_id = h.object_id
              AND v.remote_revision = h.current_remote_revision
             WHERE h.project_id = ?1 AND h.object_id = ?2",
            params![project_id.as_str(), object_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let object = LocalInboundSyncObject {
            envelope: LocalInboundSyncEnvelope {
                tenant_id: TenantId::from_stable(row.0),
                project_id: project_id.clone(),
                cell: row.1,
                object_id: object_id.to_owned(),
                object_kind: row.2,
                remote_revision: from_sql_u64(row.3, "inbound remote revision")?,
                key_version: from_sql_u64(row.4, "inbound key version")?,
                content_digest: row.5,
                tombstone: parse_bool(row.6)?,
                request_digest: row.7,
                request: serde_json::from_str(&row.8)?,
                remote_recorded_at: parse_time(&row.9)?,
            },
            status: decode_inbound_status(&row.10)?,
            validation_digest: row.11,
            projection_digest: row.12,
            projection_revision: row
                .13
                .map(|value| from_sql_u64(value, "inbound projection revision"))
                .transpose()?,
            last_error_code: row.14,
            revision: from_sql_u64(row.15, "inbound local revision")?,
            staged_at: parse_time(&row.16)?,
            updated_at: parse_time(&row.17)?,
        };
        object.validate()?;
        Ok(object)
    })
    .transpose()
}

fn append_inbound_audit(
    transaction: &Transaction<'_>,
    envelope: &LocalInboundSyncEnvelope,
    event_type: &str,
    status: LocalInboundSyncStatus,
    recorded_at: DateTime<Utc>,
) -> Result<(), StorageError> {
    let payload = json!({
        "cell": envelope.cell,
        "objectId": envelope.object_id,
        "objectKind": envelope.object_kind,
        "remoteRevision": envelope.remote_revision,
        "keyVersion": envelope.key_version,
        "contentDigest": envelope.content_digest,
        "tombstone": envelope.tombstone,
        "requestDigest": envelope.request_digest,
        "status": status,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
        params![
            envelope.tenant_id.as_str(),
            envelope.project_id.as_str(),
            event_type,
            serde_json::to_string(&payload)?,
            recorded_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub(crate) fn mark_inbound_projection_conflict(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    error_code: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'conflict', last_error_code = ?4, revision = ?5, updated_at = ?6
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3",
        params![
            current.envelope.project_id.as_str(),
            current.envelope.object_id,
            to_sql_u64(current.revision)?,
            error_code,
            to_sql_u64(next_revision(current.revision)?)?,
            now.to_rfc3339(),
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", current.envelope.object_id),
            expected_revision: current.revision,
        });
    }
    append_inbound_audit(
        transaction,
        &current.envelope,
        "sync.inbound.projection_conflict",
        LocalInboundSyncStatus::Conflict,
        now,
    )
}

fn append_inbound_mission_projection_audit(
    transaction: &Transaction<'_>,
    envelope: &LocalInboundSyncEnvelope,
    mission: &Mission,
    recorded_at: DateTime<Utc>,
) -> Result<(), StorageError> {
    let payload = json!({
        "cell": envelope.cell,
        "objectId": envelope.object_id,
        "objectKind": envelope.object_kind,
        "remoteRevision": envelope.remote_revision,
        "missionRevision": mission.revision,
        "contentDigest": envelope.content_digest,
        "status": LocalInboundSyncStatus::Applied,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, ?3, 'sync.inbound.mission_applied', ?4, ?5)",
        params![
            envelope.tenant_id.as_str(),
            envelope.project_id.as_str(),
            mission.id.as_str(),
            serde_json::to_string(&payload)?,
            recorded_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_project_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    project: &Project,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let next_local_revision = next_revision(expected_local_revision)?;
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated'",
        params![
            project.id.as_str(),
            project.id.as_str(),
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(project.revision)?,
            to_sql_u64(next_local_revision)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", project.id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": current.envelope.remote_revision,
        "projectRevision": project.revision,
        "contentDigest": current.envelope.content_digest,
        "status": LocalInboundSyncStatus::Applied,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, 'sync.inbound.project_metadata_applied', ?3, ?4)",
        params![
            project.tenant_id.as_str(),
            project.id.as_str(),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_truth_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    fact: &TruthFact,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated'",
        params![
            fact.project_id.as_str(),
            fact.id.as_str(),
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(fact.version)?,
            to_sql_u64(next_revision(expected_local_revision)?)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", fact.id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": current.envelope.remote_revision,
        "truthVersion": fact.version,
        "contentDigest": current.envelope.content_digest,
        "status": LocalInboundSyncStatus::Applied,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, 'sync.inbound.truth_applied', ?3, ?4)",
        params![
            fact.tenant_id.as_str(),
            fact.project_id.as_str(),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_work_product_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    manifest: &WorkProductManifest,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated'",
        params![
            manifest.project_id.as_str(),
            manifest.work_product_id.as_str(),
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(manifest.version)?,
            to_sql_u64(next_revision(expected_local_revision)?)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", manifest.work_product_id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": current.envelope.remote_revision,
        "manifestVersion": manifest.version,
        "workProductRevision": manifest.work_product_revision,
        "manifestDigest": manifest.manifest_digest,
        "contentDigest": current.envelope.content_digest,
        "status": LocalInboundSyncStatus::Applied,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, ?3, 'sync.inbound.work_product_applied', ?4, ?5)",
        params![
            manifest.tenant_id.as_str(),
            manifest.project_id.as_str(),
            manifest.mission_id.as_str(),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_conversation_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    conversation: &Conversation,
    consent_count: usize,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated'",
        params![
            conversation.project_id.as_str(),
            conversation.id.as_str(),
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(conversation.revision)?,
            to_sql_u64(next_revision(expected_local_revision)?)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", conversation.id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": current.envelope.remote_revision,
        "conversationRevision": conversation.revision,
        "provider": conversation.provider,
        "gateway": conversation.gateway,
        "state": conversation.state,
        "controlGeneration": conversation.control.generation(),
        "messageCount": conversation.messages.len(),
        "consentCount": consent_count,
        "contentDigest": current.envelope.content_digest,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, ?3, 'sync.inbound.conversation_applied', ?4, ?5)",
        params![
            conversation.tenant_id.as_str(),
            conversation.project_id.as_str(),
            conversation.mission_id.as_ref().map(MissionId::as_str),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_connection_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    snapshot: &ConnectionSnapshot,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated'",
        params![
            snapshot.project_id.as_str(),
            snapshot.id.as_str(),
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(snapshot.revision)?,
            to_sql_u64(next_revision(expected_local_revision)?)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", snapshot.id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": current.envelope.remote_revision,
        "connectionRevision": snapshot.revision,
        "provider": snapshot.provider,
        "status": snapshot.status,
        "contentDigest": current.envelope.content_digest,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, 'sync.inbound.connection_metadata_applied', ?3, ?4)",
        params![
            snapshot.tenant_id.as_str(),
            snapshot.project_id.as_str(),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_creator_work_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    identities: &[CreatorIdentitySnapshot],
    hiring: &CreatorHiring,
    task: &CreatorTask,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated'",
        params![
            task.project_id.as_str(),
            task.id.as_str(),
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(task.state_revision)?,
            to_sql_u64(next_revision(expected_local_revision)?)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", task.id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": current.envelope.remote_revision,
        "hiringId": hiring.id,
        "hiringRevision": hiring.state_revision,
        "identityCount": identities.len(),
        "taskRevision": task.state_revision,
        "taskStatus": task.status,
        "deliverableCount": task.deliverables.len(),
        "reviewCount": task.reviews.len(),
        "payoutCount": task.payouts.len(),
        "contentDigest": current.envelope.content_digest,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, ?3, 'sync.inbound.creator_work_applied', ?4, ?5)",
        params![
            task.tenant_id.as_str(),
            task.project_id.as_str(),
            task.mission_id.as_str(),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_outcome_ledger_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    ledger: &OutcomeLedger,
    mission_count: usize,
    connection_count: usize,
    identity_link_count: usize,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated'",
        params![
            ledger.project_id.as_str(),
            ledger.project_id.as_str(),
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(ledger.revision)?,
            to_sql_u64(next_revision(expected_local_revision)?)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", ledger.project_id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": current.envelope.remote_revision,
        "ledgerRevision": ledger.revision,
        "eventCount": ledger.events.len(),
        "orderCount": ledger.orders.len(),
        "refundCount": ledger.refunds.len(),
        "attributionCount": ledger.attributions.len(),
        "commissionCount": ledger.commissions.len(),
        "missionCount": mission_count,
        "connectionCount": connection_count,
        "identityLinkCount": identity_link_count,
        "contentDigest": current.envelope.content_digest,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, 'sync.inbound.outcome_ledger_applied', ?3, ?4)",
        params![
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_context_capsule_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    capsule: &ContextCapsule,
    branch_count: usize,
    fact_count: usize,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated'",
        params![
            capsule.project_id.as_str(),
            capsule.id.as_str(),
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(capsule.revision)?,
            to_sql_u64(next_revision(expected_local_revision)?)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", capsule.id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": current.envelope.remote_revision,
        "capsuleRevision": capsule.revision,
        "capsuleStatus": capsule.status,
        "workspaceId": capsule.workspace_id,
        "branchId": capsule.branch_id,
        "workerId": capsule.worker_id,
        "workerGeneration": capsule.worker_generation,
        "authorityDigest": capsule.authority_digest,
        "branchCount": branch_count,
        "factCount": fact_count,
        "capabilityCount": capsule.capabilities.len(),
        "contentDigest": current.envelope.content_digest,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, ?3, 'sync.inbound.context_capsule_applied', ?4, ?5)",
        params![
            capsule.tenant_id.as_str(),
            capsule.project_id.as_str(),
            capsule.mission_id.as_str(),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn ensure_project(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
) -> Result<(), StorageError> {
    let stored_tenant = transaction
        .query_row(
            "SELECT tenant_id FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))?;
    if stored_tenant != tenant_id.as_str() {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

pub(crate) fn ensure_registered_sync_project(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    cell: &str,
) -> Result<(), StorageError> {
    let project = transaction
        .query_row(
            "SELECT tenant_id, storage_mode, data_cell FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))?;
    if project.0 != tenant_id.as_str() {
        return Err(StorageError::TenantScopeMismatch);
    }
    let registration_ready = transaction
        .query_row(
            "SELECT 1 FROM project_cloud_registrations
             WHERE project_id = ?1 AND tenant_id = ?2 AND cell = ?3 AND status = 'applied'",
            params![project_id.as_str(), tenant_id.as_str(), cell],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if project.1 != "local_encrypted_sync"
        || project.2.as_deref() != Some(cell)
        || !matches!(cell, "us" | "eu")
        || !registration_ready
    {
        return Err(StorageError::EncryptedSyncProjectNotReady {
            project_id: project_id.clone(),
            cell: cell.to_owned(),
        });
    }
    Ok(())
}

fn event_payload(operation: &LocalSyncOperation) -> Value {
    json!({
        "idempotencyKeyDigest": operation.idempotency_key_digest,
        "intentDigest": operation.intent_digest,
        "requestDigest": operation.request_digest,
        "cell": operation.cell,
        "objectId": operation.object_id,
        "objectKind": operation.object_kind,
        "targetRevision": operation.target_revision,
        "keyVersion": operation.key_version,
        "contentDigest": operation.content_digest,
        "tombstone": operation.tombstone,
        "status": operation.status,
        "remoteRevision": operation.remote_revision,
        "remoteDuplicate": operation.remote_duplicate,
        "lastErrorCode": operation.last_error_code,
    })
}

const fn status_name(status: LocalSyncStatus) -> &'static str {
    match status {
        LocalSyncStatus::Prepared => "prepared",
        LocalSyncStatus::Applied => "applied",
        LocalSyncStatus::Conflict => "conflict",
        LocalSyncStatus::DeadLetter => "dead_letter",
    }
}

fn decode_status(value: &str) -> Result<LocalSyncStatus, StorageError> {
    match value {
        "prepared" => Ok(LocalSyncStatus::Prepared),
        "applied" => Ok(LocalSyncStatus::Applied),
        "conflict" => Ok(LocalSyncStatus::Conflict),
        "dead_letter" => Ok(LocalSyncStatus::DeadLetter),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid local sync status: {value}"
        ))),
    }
}

fn decode_inbound_status(value: &str) -> Result<LocalInboundSyncStatus, StorageError> {
    match value {
        "staged" => Ok(LocalInboundSyncStatus::Staged),
        "validated" => Ok(LocalInboundSyncStatus::Validated),
        "applied" => Ok(LocalInboundSyncStatus::Applied),
        "conflict" => Ok(LocalInboundSyncStatus::Conflict),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid inbound sync status: {value}"
        ))),
    }
}

fn parse_bool(value: i64) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid local sync boolean: {value}"
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
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, AutomatedReplyAuthorization,
        Connection, ConnectionProbe, ConsentPurpose, ConsentState, ContactChannel,
        ContactPermission, ContextBranch, ContextBranchId, ContextBudget, ContextCapsule,
        ContextCapsuleId, ContextDataClass, ContextDataPolicy, ContextFactGrant, ContextInputRefs,
        ContextMergePolicy, ContextReturnContract, ContextReturnReceipt, ContextWorkspace,
        ContextWorkspaceId, ConversationContentRisk, ConversationEffectGuard, ConversationId,
        CreatorApplicationId, CreatorApplicationInput, CreatorApplicationOrigin,
        CreatorContactEffectGuard, CreatorExternalProof, CreatorHiringId, CreatorHiringSpec,
        CreatorId, CreatorMilestoneId, CreatorMilestoneSpec, CreatorTaskSpec, CurrencyCode,
        DeletionId, DeletionPropagationReceipt, DeletionReason, DeletionReceiptId, DeletionSurface,
        DeletionTombstone, EffectClass, EffectId, EffectRisk, EffectSpec, Evidence, EvidenceId,
        EvidenceStatus, ExternalIdentity, FactId, FundingReservation, IdentityLink,
        IdentitySubject, InboundMessageInput, LegalBasis, MessageId, MessagingGateway, Mission,
        MissionContract, MissionId, Money, OrderId, OutcomeEvent, OutcomeEventId, OutcomeEventKind,
        OutcomeLedger, OutcomeSourceVerification, OutcomeVerificationMethod, Partner, PartnerId,
        PartnerSupplyClass, ProbeOutcome, Project, Receipt, ReceiptId, StorageMode, Task, TaskId,
        TaskStatus, TruthSource, TruthStatus, TruthValue, UsageRights, Verification,
        VerificationId, VerificationStatus, WebhookAttestation, WorkProductDependencies,
        WorkProductId, WorkProductPreview, WorkerId, WorkerLease, WorkerLeaseId,
    };
    use proptest::prelude::*;
    use rust_decimal::Decimal;

    use super::*;
    use crate::{
        DeletionPropagationJobStatus, LocalProjectCloudRegistration, PendingEvent,
        ProjectCloudRegistrationStatus,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup() -> (ProjectStore, ProjectId) {
        let mut store = ProjectStore::in_memory().expect("store");
        let mut project = Project::create_local(
            TenantId::from("tenant-sync-local"),
            ProjectId::from("project-sync-local"),
            "Encrypted sync ledger",
            "",
            PathBuf::from("/tmp/hartevo-sync-ledger"),
            StorageMode::LocalEncryptedSync,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), now())],
            )
            .expect("persist project");
        project
            .select_data_cell(ProjectDataCell::Eu)
            .expect("select EU Cell");
        let registration = registration(&project);
        store
            .prepare_project_cloud_registration(&project, 1, &registration, now())
            .expect("prepare project registration");
        store
            .record_project_cloud_registration_applied(&project.id, 1, 1, false, now())
            .expect("record applied project registration");
        (store, project.id)
    }

    fn unregistered_setup() -> (ProjectStore, ProjectId) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-sync-local"),
            ProjectId::from("project-sync-local"),
            "Unregistered encrypted sync ledger",
            "",
            PathBuf::from("/tmp/hartevo-sync-ledger-unregistered"),
            StorageMode::LocalEncryptedSync,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), now())],
            )
            .expect("persist project");
        (store, project.id)
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

    fn operation(project_id: ProjectId) -> LocalSyncOperation {
        let request = json!({"ciphertext": [1, 2, 3], "aadDigest": "4".repeat(64)});
        LocalSyncOperation {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id,
            idempotency_key_digest: "1".repeat(64),
            intent_digest: "0".repeat(64),
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            cell: "eu".into(),
            object_id: "mission-1".into(),
            object_kind: "mission".into(),
            target_revision: 1,
            key_version: 1,
            content_digest: "3".repeat(64),
            tombstone: false,
            request,
            status: LocalSyncStatus::Prepared,
            remote_revision: None,
            remote_duplicate: false,
            last_error_code: None,
            revision: 1,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn inbound_envelope(
        project_id: ProjectId,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": "tenant-sync-local"},
            "projectId": project_id,
            "objectId": "mission-inbound-1",
            "objectKind": "mission",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id,
            cell: "eu".into(),
            object_id: "mission-inbound-1".into(),
            object_kind: "mission".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn project_metadata_envelope(
        project: &Project,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": project.tenant_id},
            "projectId": project.id,
            "objectId": project.id,
            "objectKind": "project_metadata",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: project.tenant_id.clone(),
            project_id: project.id.clone(),
            cell: "eu".into(),
            object_id: project.id.to_string(),
            object_kind: "project_metadata".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn truth_envelope(
        project_id: ProjectId,
        fact_id: &FactId,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": "tenant-sync-local"},
            "projectId": project_id,
            "objectId": fact_id,
            "objectKind": "project_truth",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id,
            cell: "eu".into(),
            object_id: fact_id.to_string(),
            object_kind: "project_truth".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn work_product_envelope(
        project_id: ProjectId,
        work_product_id: &WorkProductId,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": "tenant-sync-local"},
            "projectId": project_id,
            "objectId": work_product_id,
            "objectKind": "work_product",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id,
            cell: "eu".into(),
            object_id: work_product_id.to_string(),
            object_kind: "work_product".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn connection_metadata_envelope(
        project_id: ProjectId,
        connection_id: &ConnectionId,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": "tenant-sync-local"},
            "projectId": project_id,
            "objectId": connection_id,
            "objectKind": "connection_metadata",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id,
            cell: "eu".into(),
            object_id: connection_id.to_string(),
            object_kind: "connection_metadata".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn conversation_envelope(
        project_id: ProjectId,
        conversation_id: &ConversationId,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": "tenant-sync-local"},
            "projectId": project_id,
            "objectId": conversation_id,
            "objectKind": "conversation",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id,
            cell: "eu".into(),
            object_id: conversation_id.to_string(),
            object_kind: "conversation".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn creator_work_envelope(
        project_id: ProjectId,
        task_id: &CreatorTaskId,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": "tenant-sync-local"},
            "projectId": project_id,
            "objectId": task_id,
            "objectKind": "creator_work",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id,
            cell: "eu".into(),
            object_id: task_id.to_string(),
            object_kind: "creator_work".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn outcome_ledger_envelope(
        project_id: &ProjectId,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": "tenant-sync-local"},
            "projectId": project_id,
            "objectId": project_id,
            "objectKind": "outcome_ledger",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id: project_id.clone(),
            cell: "eu".into(),
            object_id: project_id.to_string(),
            object_kind: "outcome_ledger".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn context_capsule_envelope(
        project_id: &ProjectId,
        capsule_id: &ContextCapsuleId,
        remote_revision: u64,
        byte: u8,
    ) -> LocalInboundSyncEnvelope {
        let ciphertext = vec![byte; 32];
        let content_digest = format!("{:x}", Sha256::digest(&ciphertext));
        let request = json!({
            "scope": {"cell": "eu", "tenantId": "tenant-sync-local"},
            "projectId": project_id,
            "objectId": capsule_id,
            "objectKind": "context_capsule",
            "revision": remote_revision,
            "payload": {
                "keyVersion": 1,
                "nonce": vec![byte; 12],
                "ciphertext": ciphertext,
                "aadDigest": "a".repeat(64),
                "contentDigest": content_digest,
            },
            "tombstone": false,
            "recordedAt": now(),
        });
        LocalInboundSyncEnvelope {
            tenant_id: TenantId::from("tenant-sync-local"),
            project_id: project_id.clone(),
            cell: "eu".into(),
            object_id: capsule_id.to_string(),
            object_kind: "context_capsule".into(),
            remote_revision,
            key_version: 1,
            content_digest,
            tombstone: false,
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            request,
            remote_recorded_at: now(),
        }
    }

    fn context_deletion(
        capsule: &ContextCapsule,
        requested_at: DateTime<Utc>,
    ) -> (DeletionTombstone, LocalSyncOperation) {
        let tombstone = DeletionTombstone::create(
            DeletionId::from("deletion-context-1"),
            capsule.tenant_id.clone(),
            capsule.project_id.clone(),
            capsule.id.to_string(),
            "context_capsule",
            capsule.revision,
            1,
            DeletionReason::UserRequest,
            ActorId::from("owner-context-delete"),
            "8".repeat(64),
            requested_at,
        )
        .expect("context deletion tombstone");
        let request = json!({
            "encryptedTombstoneDigest": tombstone.tombstone_digest,
            "ciphertext": [7, 7, 7],
        });
        let operation = LocalSyncOperation {
            tenant_id: capsule.tenant_id.clone(),
            project_id: capsule.project_id.clone(),
            idempotency_key_digest: "9".repeat(64),
            intent_digest: "a".repeat(64),
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            cell: "eu".into(),
            object_id: capsule.id.to_string(),
            object_kind: "context_capsule".into(),
            target_revision: capsule.revision + 1,
            key_version: 1,
            content_digest: "b".repeat(64),
            tombstone: true,
            request,
            status: LocalSyncStatus::Prepared,
            remote_revision: None,
            remote_duplicate: false,
            last_error_code: None,
            revision: 1,
            created_at: requested_at,
            updated_at: requested_at,
        };
        (tombstone, operation)
    }

    struct ContextProjectionFixture {
        mission: Mission,
        fact: TruthFact,
        workspace: ContextWorkspace,
        branches: Vec<ContextBranch>,
        lease: WorkerLease,
        capsule: ContextCapsule,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps the complete workspace, branch, lease, fact, task, budget, and return authority visible"
    )]
    fn context_projection_fixture(project_id: &ProjectId) -> ContextProjectionFixture {
        let tenant_id = TenantId::from("tenant-sync-local");
        let mut contract = MissionContract::bootstrap(
            "Return a bounded market finding",
            ["search.read".into(), "market.analyze".into()],
            now(),
        );
        contract.budget = Money::new(5_000, CurrencyCode::parse("USD").expect("USD"));
        let mut mission = Mission::compile(
            tenant_id.clone(),
            MissionId::from("mission-context-inbound"),
            project_id.clone(),
            "Bounded context projection",
            contract,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-context-inbound"),
                    title: "Read market evidence".into(),
                    status: TaskStatus::Ready,
                    capability: "search.read".into(),
                }],
                now(),
            )
            .expect("task");
        let fact = TruthFact::create(
            FactId::from("fact-context-inbound"),
            tenant_id,
            project_id.clone(),
            "market.query",
            Some(TruthValue::Text("verified demand query".into())),
            vec![],
            TruthStatus::Confirmed,
            Some(TruthSource {
                provider: "user".into(),
                source_uri: "fixture://context/query".into(),
                source_digest: "1".repeat(64),
                evidence_ids: BTreeSet::from([EvidenceId::from("evidence-context-inbound")]),
                captured_by: ActorId::from("user-context-inbound"),
                captured_at: now(),
            }),
            "US",
            "en",
            now(),
            now(),
            None,
            Decimal::ONE,
            now(),
        )
        .expect("fact");
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-context-inbound"),
            &mission,
            7,
            "context-policy/v1",
            mission.contract.enabled_capabilities.clone(),
            ContextBudget {
                token_limit: 20_000,
                cost_limit: Money::new(2_000, CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::hours(1),
                max_depth: 3,
                max_concurrency: 2,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let branch = ContextBranch::create(
            ContextBranchId::from("branch-context-inbound"),
            &workspace,
            None,
            "isolate one typed task",
            "2".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("branch");
        let lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-context-inbound"),
            &workspace,
            &branch,
            WorkerId::from("worker-context-inbound"),
            7,
            "3".repeat(64),
            Some("4".repeat(64)),
            now() + Duration::minutes(45),
            now(),
        )
        .expect("lease");
        let capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-context-inbound"),
            &workspace,
            &branch,
            &lease,
            &mission,
            "Return one sourced finding with uncertainty",
            TaskId::from("task-context-inbound"),
            BTreeSet::from([ContextFactGrant {
                fact_id: fact.id.clone(),
                version: fact.version,
                classification: ContextDataClass::Business,
            }]),
            std::slice::from_ref(&fact),
            BTreeSet::from(["search.read".into()]),
            ContextBudget {
                token_limit: 5_000,
                cost_limit: Money::new(500, CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::minutes(30),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs::default(),
            ContextReturnContract {
                schema_id: "hartevo.context.market-finding".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["finding".into(), "confidence".into()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: true,
                uncertainty_required: true,
                max_result_bytes: 65_536,
            },
            now() + Duration::minutes(30),
            now(),
        )
        .expect("capsule");
        ContextProjectionFixture {
            mission,
            fact,
            workspace,
            branches: vec![branch],
            lease,
            capsule,
        }
    }

    struct OutcomeProjectionFixture {
        mission: Mission,
        connection: ConnectionSnapshot,
        partner: Partner,
        identity_link: IdentityLink,
        ledger: OutcomeLedger,
    }

    fn outcome_projection_fixture(project_id: &ProjectId) -> OutcomeProjectionFixture {
        let tenant_id = TenantId::from("tenant-sync-local");
        let mission = Mission::compile(
            tenant_id.clone(),
            MissionId::from("mission-outcome-inbound"),
            project_id.clone(),
            "Verified outcome projection",
            MissionContract::bootstrap("Project verified commerce outcomes", [], now()),
            now(),
        )
        .expect("mission");
        let connection = Connection::register(
            ConnectionId::from("connection-outcome-inbound"),
            tenant_id.clone(),
            project_id.clone(),
            "commerce-fixture",
            AccountId::from("merchant-outcome-inbound"),
            "merchant-external-outcome-inbound",
            ["orders.read".into()],
            now(),
        )
        .expect("connection")
        .snapshot();
        let partner = Partner::create(
            PartnerId::from("partner-outcome-inbound"),
            tenant_id.clone(),
            project_id.clone(),
            None,
            None,
            "Verified buyer identity",
            PartnerSupplyClass::HartevoOptIn,
            ContactPermission::ExplicitOptIn,
            Some("1".repeat(64)),
        )
        .expect("partner");
        let mut identity_link = IdentityLink::propose(
            IdentityLinkId::from("identity-outcome-inbound"),
            tenant_id.clone(),
            project_id.clone(),
            IdentitySubject::Partner(partner.id.clone()),
            [ExternalIdentity {
                provider: connection.provider.clone(),
                account_id: connection.account_id.clone(),
                external_subject_digest: "2".repeat(64),
                encrypted_subject_ref: "ciphertext://outcome-buyer".into(),
                evidence_digest: "3".repeat(64),
            }],
            Decimal::ONE,
        )
        .expect("identity link");
        identity_link
            .confirm(
                ActorId::from("operator-outcome-inbound"),
                "3".repeat(64),
                now(),
            )
            .expect("identity confirmation");
        let mut ledger = OutcomeLedger::new(tenant_id.clone(), project_id.clone()).expect("ledger");
        ledger
            .ingest(OutcomeEvent {
                id: OutcomeEventId::from("order-event-outcome-inbound"),
                tenant_id,
                project_id: project_id.clone(),
                mission_id: mission.id.clone(),
                kind: OutcomeEventKind::OrderPlaced,
                provider: connection.provider.clone(),
                connection_id: Some(connection.id.clone()),
                account_id: Some(connection.account_id.clone()),
                source_event_id: "provider-order-outcome-inbound".into(),
                identity_link_id: Some(identity_link.id.clone()),
                opportunity_id: None,
                campaign_id: None,
                order_id: Some(OrderId::from("order-outcome-inbound")),
                refund_id: None,
                commission_id: None,
                payout_id: None,
                partner_id: None,
                amount: Some(Money::new(12_500, CurrencyCode::parse("USD").expect("USD"))),
                occurred_at: now(),
                received_at: now() + Duration::minutes(1),
                evidence_digest: "4".repeat(64),
                raw_payload_digest: "5".repeat(64),
                source_verification: Some(OutcomeSourceVerification {
                    method: OutcomeVerificationMethod::SignedWebhook,
                    verifier: "commerce-signature-fixture".into(),
                    independent: true,
                    verified_at: now() + Duration::minutes(1),
                    evidence_digest: "6".repeat(64),
                }),
            })
            .expect("order");
        OutcomeProjectionFixture {
            mission,
            connection,
            partner,
            identity_link,
            ledger,
        }
    }

    fn apply_inbound_project_revision(
        store: &mut ProjectStore,
        project: &Project,
        remote_revision: u64,
        expected_remote_revision: Option<u64>,
        byte: u8,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &project_metadata_envelope(project, remote_revision, byte),
            expected_remote_revision,
            now(),
        )?;
        let validated = store.record_local_inbound_sync_validated(
            &project.id,
            project.id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            now(),
        )?;
        store.apply_local_inbound_project_metadata(
            project,
            project.id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            now(),
        )
    }

    fn apply_inbound_truth_revision(
        store: &mut ProjectStore,
        fact: &TruthFact,
        remote_revision: u64,
        expected_remote_revision: Option<u64>,
        byte: u8,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &truth_envelope(fact.project_id.clone(), &fact.id, remote_revision, byte),
            expected_remote_revision,
            now(),
        )?;
        let validated = store.record_local_inbound_sync_validated(
            &fact.project_id,
            fact.id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            now(),
        )?;
        store.apply_local_inbound_truth_fact(
            fact,
            fact.id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            now(),
        )
    }

    fn apply_inbound_work_product_revision(
        store: &mut ProjectStore,
        manifest: &WorkProductManifest,
        work_product: &WorkProduct,
        remote_revision: u64,
        expected_remote_revision: Option<u64>,
        byte: u8,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &work_product_envelope(
                manifest.project_id.clone(),
                &manifest.work_product_id,
                remote_revision,
                byte,
            ),
            expected_remote_revision,
            now(),
        )?;
        let validated = store.record_local_inbound_sync_validated(
            &manifest.project_id,
            manifest.work_product_id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            now(),
        )?;
        store.apply_local_inbound_work_product(
            manifest,
            work_product,
            manifest.work_product_id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            now(),
        )
    }

    fn apply_inbound_connection_metadata_revision(
        store: &mut ProjectStore,
        snapshot: &ConnectionSnapshot,
        remote_revision: u64,
        expected_remote_revision: Option<u64>,
        byte: u8,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &connection_metadata_envelope(
                snapshot.project_id.clone(),
                &snapshot.id,
                remote_revision,
                byte,
            ),
            expected_remote_revision,
            now(),
        )?;
        let validated = store.record_local_inbound_sync_validated(
            &snapshot.project_id,
            snapshot.id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            now(),
        )?;
        store.apply_local_inbound_connection_metadata(
            snapshot,
            snapshot.id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            now(),
        )
    }

    fn apply_inbound_conversation_revision(
        store: &mut ProjectStore,
        identity: &ConversationIdentitySnapshot,
        connection: &ConnectionSnapshot,
        consents: &[ConsentRecord],
        conversation: &Conversation,
        expected_remote_revision: Option<u64>,
        byte: u8,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let remote_revision = conversation.revision;
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &conversation_envelope(
                conversation.project_id.clone(),
                &conversation.id,
                remote_revision,
                byte,
            ),
            expected_remote_revision,
            now(),
        )?;
        let validated = store.record_local_inbound_sync_validated(
            &conversation.project_id,
            conversation.id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            now(),
        )?;
        store.apply_local_inbound_conversation(
            identity,
            connection,
            consents,
            conversation,
            conversation.id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            now() + Duration::minutes(20),
        )
    }

    fn apply_inbound_creator_work_revision(
        store: &mut ProjectStore,
        identities: &[CreatorIdentitySnapshot],
        hiring: &CreatorHiring,
        task: &CreatorTask,
        remote_revision: u64,
        expected_remote_revision: Option<u64>,
        byte: u8,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &creator_work_envelope(task.project_id.clone(), &task.id, remote_revision, byte),
            expected_remote_revision,
            now(),
        )?;
        let validated = store.record_local_inbound_sync_validated(
            &task.project_id,
            task.id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            now(),
        )?;
        store.apply_local_inbound_creator_work(
            identities,
            hiring,
            task,
            task.id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            now() + Duration::minutes(20),
        )
    }

    fn apply_inbound_outcome_ledger_revision(
        store: &mut ProjectStore,
        fixture: &OutcomeProjectionFixture,
        remote_revision: u64,
        expected_remote_revision: Option<u64>,
        byte: u8,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &outcome_ledger_envelope(&fixture.ledger.project_id, remote_revision, byte),
            expected_remote_revision,
            now(),
        )?;
        let validated = store.record_local_inbound_sync_validated(
            &fixture.ledger.project_id,
            fixture.ledger.project_id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            now(),
        )?;
        store.apply_local_inbound_outcome_ledger(
            std::slice::from_ref(&fixture.mission),
            std::slice::from_ref(&fixture.connection),
            &[],
            &[],
            std::slice::from_ref(&fixture.partner),
            std::slice::from_ref(&fixture.identity_link),
            &[],
            &[],
            &[],
            &fixture.ledger,
            fixture.ledger.project_id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            now() + Duration::minutes(2),
        )
    }

    fn apply_inbound_context_capsule_revision(
        store: &mut ProjectStore,
        fixture: &ContextProjectionFixture,
        capsule: &ContextCapsule,
        remote_revision: u64,
        expected_remote_revision: Option<u64>,
        byte: u8,
        applied_at: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &context_capsule_envelope(
                &fixture.workspace.project_id,
                &capsule.id,
                remote_revision,
                byte,
            ),
            expected_remote_revision,
            applied_at,
        )?;
        let validated = store.record_local_inbound_sync_validated(
            &fixture.workspace.project_id,
            capsule.id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            applied_at,
        )?;
        store.apply_local_inbound_context_capsule(
            &fixture.workspace,
            &fixture.branches,
            &fixture.lease,
            std::slice::from_ref(&fixture.fact),
            capsule,
            capsule.id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            applied_at,
        )
    }

    fn connected_connection(project_id: &ProjectId) -> Connection {
        let mut connection = Connection::register(
            ConnectionId::from("connection-inbound-1"),
            TenantId::from("tenant-sync-local"),
            project_id.clone(),
            "fixture-provider",
            AccountId::from("account-inbound-1"),
            "external-account-inbound-1",
            ["publish.write".into()],
            now(),
        )
        .expect("connection");
        connection
            .begin_probe(now() + Duration::minutes(1))
            .expect("begin probe");
        connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "external-account-inbound-1".into(),
                    granted_scopes: BTreeSet::from(["publish.write".into()]),
                    probed_at: now() + Duration::minutes(2),
                    valid_until: now() + Duration::hours(4),
                    credential_expires_at: now() + Duration::hours(4),
                    evidence_digest: "a".repeat(64),
                },
                now() + Duration::minutes(2),
            )
            .expect("successful probe");
        connection
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps the exact Mission, identity, live Connection, Consent, and Conversation trust bundle visible"
    )]
    fn conversation_sync_fixture(
        store: &mut ProjectStore,
        project_id: &ProjectId,
    ) -> (
        ConversationIdentitySnapshot,
        ConnectionSnapshot,
        ConsentRecord,
        Mission,
        Conversation,
    ) {
        let tenant_id = TenantId::from("tenant-sync-local");
        let mission_id = MissionId::from("mission-conversation-inbound");
        let mut mission = Mission::compile(
            tenant_id.clone(),
            mission_id.clone(),
            project_id.clone(),
            "Conversation handoff",
            MissionContract::bootstrap(
                "Preserve signed inbox identity and human control",
                ["conversation.reply".into()],
                now(),
            ),
            now(),
        )
        .expect("conversation mission");
        mission
            .start_research([], now())
            .expect("start conversation mission");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new(
                    "mission.conversation_fixture",
                    json!({"missionId": mission.id}),
                    now(),
                )],
            )
            .expect("persist conversation mission");

        let company = Company::create(
            CompanyId::from("company-conversation-inbound"),
            tenant_id.clone(),
            project_id.clone(),
            "Conversation customer",
            "DE",
        )
        .expect("conversation company");
        let person = Person::create(
            PersonId::from("person-conversation-inbound"),
            tenant_id.clone(),
            project_id.clone(),
            "Verified correspondent",
            Some(company.id.clone()),
            vec![],
        )
        .expect("conversation person");
        let identity = ConversationIdentitySnapshot {
            person: person.clone(),
            company: Some(company),
        };
        let mut connection = Connection::register(
            ConnectionId::from("connection-conversation-inbound"),
            tenant_id.clone(),
            project_id.clone(),
            "gmail",
            AccountId::from("account-conversation-inbound"),
            "owner@example.invalid",
            ["messages.send".into()],
            now(),
        )
        .expect("conversation connection");
        connection
            .begin_probe(now() + Duration::seconds(1))
            .expect("begin conversation probe");
        connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "owner@example.invalid".into(),
                    granted_scopes: BTreeSet::from(["messages.send".into()]),
                    probed_at: now() + Duration::seconds(2),
                    valid_until: now() + Duration::days(30),
                    credential_expires_at: now() + Duration::days(30),
                    evidence_digest: "1".repeat(64),
                },
                now() + Duration::seconds(2),
            )
            .expect("probe conversation connection");
        let consent = ConsentRecord::grant(
            ConsentRecordId::from("consent-conversation-inbound"),
            tenant_id.clone(),
            project_id.clone(),
            person.id.clone(),
            ConsentPurpose::AutomatedReply,
            ContactChannel::Email,
            "DE",
            LegalBasis::ExplicitConsent,
            "preference-center",
            "2".repeat(64),
            now(),
            None,
        )
        .expect("conversation consent");
        let conversation = Conversation::open(
            ConversationId::from("conversation-inbound"),
            tenant_id,
            project_id.clone(),
            Some(mission_id),
            person.id,
            person.company_id,
            MessagingGateway::Gmail,
            "gmail",
            connection.id().clone(),
            connection.account_id().clone(),
            "3".repeat(64),
            ContactChannel::Email,
            "DE",
            now() + Duration::seconds(3),
        )
        .expect("conversation");
        (
            identity,
            connection.snapshot(),
            consent,
            mission,
            conversation,
        )
    }

    fn propose_conversation_reply(
        mission: &mut Mission,
        conversation: &mut Conversation,
        consent: &ConsentRecord,
        at: DateTime<Utc>,
    ) -> EffectId {
        let effect_id = EffectId::from("effect-conversation-inbound");
        let prepared = conversation
            .prepare_automatic_reply(
                MessageId::from("outbound-conversation-inbound"),
                "6".repeat(64),
                effect_id.clone(),
                conversation.control.generation(),
                AutomatedReplyAuthorization::Consent(consent),
                at,
            )
            .expect("prepare conversation reply");
        mission
            .propose_effect(
                EffectSpec {
                    id: effect_id.clone(),
                    actor_id: ActorId::from("conversation-agent"),
                    capability: "conversation.reply".into(),
                    provider: conversation.provider.clone(),
                    connection_id: Some(conversation.connection_id.clone()),
                    account_id: Some(conversation.account_id.clone()),
                    required_scopes: BTreeSet::from(["messages.send".into()]),
                    effect_class: EffectClass::Outreach,
                    description: "Send reviewed conversation reply".into(),
                    target_resource: format!("conversation://{}", conversation.id),
                    audience_digest: Some(format!(
                        "{:x}",
                        Sha256::digest(conversation.person_id.as_str().as_bytes())
                    )),
                    payload_digest: "6".repeat(64),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "Europe/Berlin".into(),
                    consent: ConsentState::Confirmed,
                    consent_record_id: Some(consent.id.clone()),
                    consent_requirement: Some(hartevo_domain_kernel::ConsentRequirement {
                        person_id: conversation.person_id.clone(),
                        purpose: ConsentPurpose::AutomatedReply,
                        channel: ContactChannel::Email,
                        market: "DE".into(),
                    }),
                    conversation_guard: Some(ConversationEffectGuard {
                        conversation_id: conversation.id.clone(),
                        control_generation: prepared.control_generation,
                        scope_digest: prepared.scope_digest,
                    }),
                    creator_contact_guard: None,
                    policy_version: "conversation-sync-v1".into(),
                    risk: EffectRisk::High,
                    idempotency_key: "conversation-sync-effect-v1".into(),
                    amount: Money::zero(CurrencyCode::parse("EUR").expect("EUR")),
                    expires_at: at + Duration::hours(1),
                },
                at,
            )
            .expect("propose conversation effect")
    }

    fn creator_work_mission(project_id: &ProjectId) -> Mission {
        let tenant_id = TenantId::from("tenant-sync-local");
        let mission_id = MissionId::from("mission-creator-work-inbound");
        let mut mission = Mission::compile(
            tenant_id,
            mission_id,
            project_id.clone(),
            "Creator hiring and delivery",
            MissionContract::bootstrap(
                "Hire a creator and receive a reviewed delivery",
                ["partner.engage".into()],
                now(),
            ),
            now(),
        )
        .expect("creator mission");
        mission.start_research([], now()).expect("start mission");
        mission
    }

    fn creator_hiring_candidate(
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> (CreatorHiring, Partner, CreatorId, Money) {
        let tenant_id = TenantId::from("tenant-sync-local");
        let usd = CurrencyCode::parse("USD").expect("USD");
        let bounty = Money::new(50_000, usd.clone());
        let mut hiring = CreatorHiring::create(
            CreatorHiringSpec {
                id: CreatorHiringId::from("hiring-creator-work-inbound"),
                tenant_id: tenant_id.clone(),
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                title: "Verified creator demonstration".into(),
                brief_digest: "1".repeat(64),
                bounty: bounty.clone(),
                market: "US".into(),
                application_deadline: now() + Duration::days(3),
                due_at: now() + Duration::days(10),
            },
            now(),
        )
        .expect("creator hiring");
        hiring
            .open(now() + Duration::minutes(1))
            .expect("open hiring");
        let partner = Partner::create(
            PartnerId::from("partner-creator-work-inbound"),
            tenant_id.clone(),
            project_id.clone(),
            None,
            None,
            "Verified opt-in creator",
            PartnerSupplyClass::HartevoOptIn,
            ContactPermission::ExplicitOptIn,
            Some("2".repeat(64)),
        )
        .expect("partner");
        let creator_id = CreatorId::from("creator-work-inbound");
        hiring
            .shortlist(
                &partner,
                creator_id.clone(),
                "3".repeat(64),
                "4".repeat(64),
                now() + Duration::minutes(2),
            )
            .expect("shortlist");
        (hiring, partner, creator_id, bounty)
    }

    fn creator_invitation_effect(
        hiring: &CreatorHiring,
        partner: &Partner,
        creator_id: &CreatorId,
        effect_id: EffectId,
        scope_digest: String,
    ) -> EffectSpec {
        EffectSpec {
            id: effect_id,
            actor_id: ActorId::from("creator-owner"),
            capability: "partner.engage".into(),
            provider: "hartevo-opt-in".into(),
            connection_id: Some(ConnectionId::from("connection-creator-network")),
            account_id: Some(AccountId::from("account-creator-network")),
            required_scopes: BTreeSet::from(["creator.invite.write".into()]),
            effect_class: EffectClass::Outreach,
            description: "Invite verified creator".into(),
            target_resource: "creator-hiring://candidate".into(),
            audience_digest: Some("3".repeat(64)),
            payload_digest: scope_digest.clone(),
            asset_digests: BTreeSet::from(["1".repeat(64)]),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: Some(CreatorContactEffectGuard {
                hiring_id: hiring.id.clone(),
                creator_id: creator_id.clone(),
                partner_id: partner.id.clone(),
                scope_digest,
                permission_evidence_digest: "2".repeat(64),
            }),
            policy_version: "creator-contact-v1".into(),
            risk: EffectRisk::High,
            idempotency_key: "creator-work-invitation-v1".into(),
            amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
            expires_at: now() + Duration::days(1),
        }
    }

    fn creator_invitation_provider_evidence(
        mission: &mut Mission,
        effect_id: &EffectId,
    ) -> (Receipt, Verification) {
        let approval_digest = mission
            .effect(effect_id)
            .expect("invitation effect")
            .approval_digest();
        let approval_valid_until = mission
            .approval_valid_until(effect_id, now() + Duration::minutes(4))
            .expect("approval validity");
        mission
            .approve_effect(
                effect_id,
                Approval {
                    id: ApprovalId::from("approval-creator-work-invitation"),
                    decision: ApprovalDecision::Approved,
                    decided_by: ActorId::from("creator-owner"),
                    decided_at: now() + Duration::minutes(4),
                    valid_until: approval_valid_until,
                    scope_digest: approval_digest.clone(),
                    permission_digest: "5".repeat(64),
                },
            )
            .expect("approve invitation");
        mission
            .begin_effect(effect_id, now() + Duration::minutes(5))
            .expect("begin invitation");
        let receipt = Receipt {
            id: ReceiptId::from("receipt-creator-work-invitation"),
            provider: "hartevo-opt-in".into(),
            external_id: "invitation-external-1".into(),
            accepted_at: now() + Duration::minutes(6),
            request_digest: approval_digest,
            response_digest: "6".repeat(64),
        };
        mission
            .record_receipt(effect_id, receipt.clone())
            .expect("invitation receipt");
        let verification = Verification {
            id: VerificationId::from("verification-creator-work-invitation"),
            status: VerificationStatus::Confirmed,
            verifier: "invitation-readback".into(),
            independent: true,
            observed_at: now() + Duration::minutes(7),
            evidence_digest: "7".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        mission
            .record_verification(effect_id, verification.clone())
            .expect("invitation verification");
        (receipt, verification)
    }

    fn verify_creator_invitation(
        mission: &mut Mission,
        hiring: &mut CreatorHiring,
        partner: &Partner,
        creator_id: &CreatorId,
    ) -> EffectId {
        let effect_id = EffectId::from("effect-creator-work-invitation");
        let scope_digest = hiring.invitation_scope_digest(creator_id);
        hiring
            .prepare_invitation(
                creator_id,
                effect_id.clone(),
                scope_digest.clone(),
                now() + Duration::minutes(3),
            )
            .expect("prepare invitation");
        mission
            .propose_effect(
                creator_invitation_effect(
                    hiring,
                    partner,
                    creator_id,
                    effect_id.clone(),
                    scope_digest.clone(),
                ),
                now() + Duration::minutes(3),
            )
            .expect("propose invitation effect");
        let (receipt, verification) = creator_invitation_provider_evidence(mission, &effect_id);
        let proof = CreatorExternalProof {
            effect_id: effect_id.clone(),
            receipt_id: receipt.id.clone(),
            verification_id: verification.id.clone(),
            provider: receipt.provider.clone(),
            connection_id: ConnectionId::from("connection-creator-network"),
            account_id: AccountId::from("account-creator-network"),
            scope_digest: scope_digest.clone(),
            provider_receipt_digest: format!(
                "{:x}",
                Sha256::digest(
                    format!(
                        "{}:{}:{}",
                        receipt.provider, receipt.external_id, receipt.response_digest
                    )
                    .as_bytes()
                )
            ),
            verification_evidence_digest: verification.evidence_digest,
            occurred_at: receipt.accepted_at,
            verified_at: verification.observed_at,
        };
        hiring
            .record_verified_invitation(creator_id, proof, now() + Duration::minutes(7))
            .expect("record invitation");
        effect_id
    }

    fn award_creator(
        hiring: &mut CreatorHiring,
        partner: &Partner,
        creator_id: &CreatorId,
        bounty: &Money,
        invitation_effect_id: EffectId,
    ) -> hartevo_domain_kernel::CreatorHiringAward {
        let application_id = CreatorApplicationId::from("application-creator-work-inbound");
        hiring
            .apply(
                CreatorApplicationInput {
                    id: application_id.clone(),
                    creator_id: creator_id.clone(),
                    partner_id: partner.id.clone(),
                    origin: CreatorApplicationOrigin::VerifiedInvitation(invitation_effect_id),
                    offer_digest: hiring.offer_digest(),
                    proposed_amount: bounty.clone(),
                    proposal_digest: "8".repeat(64),
                    rights_acknowledgement_digest: "9".repeat(64),
                    submitted_at: now() + Duration::minutes(8),
                },
                now() + Duration::minutes(8),
            )
            .expect("creator application");
        hiring
            .award(
                &application_id,
                ActorId::from("creator-owner"),
                "a".repeat(64),
                now() + Duration::minutes(9),
            )
            .expect("user award")
    }

    fn creator_task_fixture(
        project_id: &ProjectId,
        award: hartevo_domain_kernel::CreatorHiringAward,
        bounty: Money,
    ) -> CreatorTask {
        CreatorTask::create(
            CreatorTaskSpec {
                id: CreatorTaskId::from("task-creator-work-inbound"),
                tenant_id: TenantId::from("tenant-sync-local"),
                project_id: project_id.clone(),
                mission_id: MissionId::from("mission-creator-work-inbound"),
                creator_id: CreatorId::from("creator-work-inbound"),
                hiring_award: award,
                title: "Verified product demonstration".into(),
                brief: "Deliver an original video and editable source".into(),
                acceptance_criteria: vec!["Shows the product workflow".into()],
                deliverable_requirements: vec!["MP4 and source archive".into()],
                bounty: bounty.clone(),
                milestones: vec![CreatorMilestoneSpec {
                    id: CreatorMilestoneId::from("milestone-creator-work-inbound"),
                    title: "Final delivery".into(),
                    amount: bounty,
                    due_at: now() + Duration::days(7),
                }],
                revision_limit: 2,
                usage_rights: UsageRights {
                    license: "exclusive campaign license".into(),
                    territories: vec!["US".into()],
                    channels: vec!["owned_social".into()],
                    exclusivity: "30_days".into(),
                    disclosure_required: true,
                    source_manifest_required: true,
                },
                due_at: now() + Duration::days(10),
            },
            now() + Duration::minutes(10),
        )
        .expect("creator task")
    }

    fn verified_creator_work_bundle(
        store: &mut ProjectStore,
        project_id: &ProjectId,
    ) -> (Vec<CreatorIdentitySnapshot>, CreatorHiring, CreatorTask) {
        let mut mission = creator_work_mission(project_id);
        let (mut hiring, partner, creator_id, bounty) =
            creator_hiring_candidate(project_id, &mission.id);
        let invitation_effect_id =
            verify_creator_invitation(&mut mission, &mut hiring, &partner, &creator_id);
        let award = award_creator(
            &mut hiring,
            &partner,
            &creator_id,
            &bounty,
            invitation_effect_id,
        );
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new(
                    "mission.creator_work_fixture",
                    json!({"effectId": "effect-creator-work-invitation"}),
                    now() + Duration::minutes(9),
                )],
            )
            .expect("persist creator mission");
        let task = creator_task_fixture(project_id, award, bounty);
        (
            vec![CreatorIdentitySnapshot {
                partner,
                person: None,
                company: None,
            }],
            hiring,
            task,
        )
    }

    fn creator_funding_reservation(
        task: &CreatorTask,
        external_id: &str,
        digest_byte: char,
        at: DateTime<Utc>,
    ) -> FundingReservation {
        FundingReservation {
            provider: "stripe-connect".into(),
            external_id: external_id.into(),
            connection_id: ConnectionId::from("connection-creator-payout"),
            payer_account_id: AccountId::from("account-creator-owner"),
            amount: task.bounty.clone(),
            contract_revision: task.contract_revision,
            contract_digest: task.contract_digest(),
            reserved_at: at,
            expires_at: now() + Duration::days(30),
            request_digest: digest_byte.to_string().repeat(64),
            provider_receipt_digest: "b".repeat(64),
            verification_evidence_digest: "c".repeat(64),
        }
    }

    fn persisted_work_product(
        store: &mut ProjectStore,
        project_id: &ProjectId,
    ) -> (Mission, WorkProductManifest, WorkProduct) {
        let mut mission = Mission::compile(
            TenantId::from("tenant-sync-local"),
            MissionId::from("mission-work-product-inbound"),
            project_id.clone(),
            "Inbound work product",
            MissionContract::bootstrap(
                "Project a typed work product",
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
        let task_id = TaskId::from("task-work-product-inbound");
        let evidence_id = EvidenceId::from("evidence-work-product-inbound");
        mission
            .start_research(
                [Task {
                    id: task_id.clone(),
                    title: "Compose work product".into(),
                    status: TaskStatus::Ready,
                    capability: "work_product.compose".into(),
                }],
                now(),
            )
            .expect("research");
        mission
            .record_evidence(
                Evidence {
                    id: evidence_id.clone(),
                    title: "Evidence".into(),
                    source_uri: "fixture://work-product".into(),
                    observed_at: now(),
                    confidence: 1.0,
                    status: EvidenceStatus::Confirmed,
                    content_digest: "a".repeat(64),
                },
                now(),
            )
            .expect("evidence");
        mission
            .record_work_product(
                WorkProduct::draft(
                    WorkProductId::from("work-product-inbound-1"),
                    "Work product",
                    "Original body",
                    [evidence_id],
                ),
                now(),
            )
            .expect("work product");
        let product = mission.work_products[0].clone();
        let manifest = WorkProductManifest::create(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            &product,
            "document.brief",
            WorkProductDependencies {
                fact_ids: BTreeSet::new(),
                evidence_ids: product.evidence_ids.clone(),
                task_ids: BTreeSet::from([task_id]),
            },
            None,
            WorkProductPreview::new("text/plain", "Original preview").expect("preview"),
            BTreeSet::from(["/body".into()]),
            now(),
        )
        .expect("manifest");
        store
            .create_work_product_manifest_atomic(
                &mission,
                1,
                &manifest,
                &[PendingEvent::new("work_product.created", json!({}), now())],
            )
            .expect("persist work product manifest");
        (mission, manifest, product)
    }

    fn apply_inbound_mission_revision(
        store: &mut ProjectStore,
        project_id: &ProjectId,
        mission: &Mission,
        remote_revision: u64,
        expected_remote_revision: Option<u64>,
        byte: u8,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        let digest = format!("{byte:x}").repeat(64);
        let staged = store.stage_local_inbound_sync_object(
            &inbound_envelope(project_id.clone(), remote_revision, byte),
            expected_remote_revision,
            now(),
        )?;
        let validated = store.record_local_inbound_sync_validated(
            project_id,
            mission.id.as_str(),
            staged.object.revision,
            remote_revision,
            &digest,
            now(),
        )?;
        store.apply_local_inbound_mission(
            mission,
            mission.id.as_str(),
            validated.revision,
            remote_revision,
            &digest,
            now(),
        )
    }

    #[derive(Clone, Copy, Debug)]
    enum ExpectedHead {
        Exact,
        None,
        Previous,
        Candidate,
    }

    fn inbound_stage_command() -> impl Strategy<Value = (u64, u8, ExpectedHead)> {
        (
            1_u64..10,
            0_u8..6,
            prop_oneof![
                Just(ExpectedHead::Exact),
                Just(ExpectedHead::None),
                Just(ExpectedHead::Previous),
                Just(ExpectedHead::Candidate),
            ],
        )
    }

    #[test]
    fn prepared_ciphertext_replays_exactly_and_applied_result_is_cas_persisted() {
        let (mut store, project_id) = setup();
        let prepared = operation(project_id.clone());
        let first = store
            .prepare_local_sync_operation(&prepared)
            .expect("prepare operation");
        assert!(!first.duplicate);
        assert!(first.event_sequence.is_some() && first.outbox_sequence.is_some());

        let replay = store
            .prepare_local_sync_operation(&prepared)
            .expect("exact replay");
        assert!(replay.duplicate);
        assert_eq!(replay.operation.request, prepared.request);
        let mut conflicting = prepared.clone();
        conflicting.intent_digest = "5".repeat(64);
        assert!(matches!(
            store.prepare_local_sync_operation(&conflicting),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "encrypted sync request",
                ..
            })
        ));

        let applied = store
            .record_local_sync_applied(&project_id, &"1".repeat(64), 1, 1, false, now())
            .expect("record applied");
        assert_eq!(
            (applied.status, applied.revision),
            (LocalSyncStatus::Applied, 2)
        );
        assert_eq!(
            store
                .record_local_sync_applied(&project_id, &"1".repeat(64), 1, 1, false, now())
                .expect("idempotent applied replay"),
            applied
        );
    }

    #[test]
    fn low_level_sync_apis_require_the_exact_applied_project_cell_registration() {
        let (mut unregistered, project_id) = unregistered_setup();
        assert!(matches!(
            unregistered.prepare_local_sync_operation(&operation(project_id.clone())),
            Err(StorageError::EncryptedSyncProjectNotReady { .. })
        ));
        assert!(matches!(
            unregistered.stage_local_inbound_sync_object(
                &inbound_envelope(project_id.clone(), 1, 1),
                None,
                now(),
            ),
            Err(StorageError::EncryptedSyncProjectNotReady { .. })
        ));

        let (mut registered, project_id) = setup();
        let mut wrong_cell_operation = operation(project_id.clone());
        wrong_cell_operation.cell = "us".into();
        assert!(matches!(
            registered.prepare_local_sync_operation(&wrong_cell_operation),
            Err(StorageError::EncryptedSyncProjectNotReady { cell, .. }) if cell == "us"
        ));

        let mut wrong_cell_inbound = inbound_envelope(project_id, 1, 1);
        wrong_cell_inbound.cell = "us".into();
        wrong_cell_inbound.request["scope"]["cell"] = json!("us");
        wrong_cell_inbound.request_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&wrong_cell_inbound.request).expect("request"))
        );
        assert!(matches!(
            registered.stage_local_inbound_sync_object(&wrong_cell_inbound, None, now()),
            Err(StorageError::EncryptedSyncProjectNotReady { cell, .. }) if cell == "us"
        ));
    }

    #[test]
    fn inbound_ciphertext_is_monotonic_cas_validated_and_never_copied_into_audit() {
        let (mut store, project_id) = setup();
        let revision_three = inbound_envelope(project_id.clone(), 3, 3);
        let inserted = store
            .stage_local_inbound_sync_object(&revision_three, None, now())
            .expect("bootstrap from a full remote snapshot");
        assert_eq!(
            inserted.disposition,
            LocalInboundSyncStageDisposition::Inserted
        );
        assert_eq!(
            (inserted.object.revision, inserted.object.status),
            (1, LocalInboundSyncStatus::Staged)
        );

        let duplicate = store
            .stage_local_inbound_sync_object(&revision_three, None, now())
            .expect("exact duplicate");
        assert_eq!(
            duplicate.disposition,
            LocalInboundSyncStageDisposition::Duplicate
        );
        let different_same_revision = inbound_envelope(project_id.clone(), 3, 9);
        assert!(matches!(
            store.stage_local_inbound_sync_object(&different_same_revision, Some(3), now()),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "inbound encrypted sync revision",
                ..
            })
        ));

        let stale = store
            .stage_local_inbound_sync_object(
                &inbound_envelope(project_id.clone(), 2, 2),
                Some(3),
                now(),
            )
            .expect("stale head is ignored");
        assert_eq!(stale.disposition, LocalInboundSyncStageDisposition::Stale);
        assert_eq!(stale.object.envelope.remote_revision, 3);

        let revision_four = inbound_envelope(project_id.clone(), 4, 4);
        let advanced = store
            .stage_local_inbound_sync_object(&revision_four, Some(3), now())
            .expect("advance exact head");
        assert_eq!(
            advanced.disposition,
            LocalInboundSyncStageDisposition::Advanced
        );
        assert_eq!(
            (advanced.object.revision, advanced.object.status),
            (2, LocalInboundSyncStatus::Staged)
        );
        let validated = store
            .record_local_inbound_sync_validated(
                &project_id,
                "mission-inbound-1",
                2,
                4,
                &"b".repeat(64),
                now(),
            )
            .expect("authenticated and schema validated");
        assert_eq!(
            (validated.revision, validated.status),
            (3, LocalInboundSyncStatus::Validated)
        );
        assert_eq!(
            store
                .record_local_inbound_sync_validated(
                    &project_id,
                    "mission-inbound-1",
                    2,
                    4,
                    &"b".repeat(64),
                    now(),
                )
                .expect("validation replay"),
            validated
        );
        assert!(matches!(
            store.stage_local_inbound_sync_object(
                &inbound_envelope(project_id.clone(), 5, 5),
                Some(2),
                now(),
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));

        let audit: String = store
            .connection
            .query_row(
                "SELECT group_concat(payload_json, '') FROM domain_events
                 WHERE project_id = ?1 AND event_type LIKE 'sync.inbound.%'",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .expect("inbound audit");
        assert!(!audit.contains("ciphertext"));
        assert!(!audit.contains("nonce"));
        assert!(!audit.contains("requestJson"));
    }

    #[test]
    fn inbound_mission_projection_advances_only_when_local_revision_is_unchanged() {
        let (mut store, project_id) = setup();
        let tenant_id = TenantId::from("tenant-sync-local");
        let mission_id = MissionId::from("mission-inbound-1");
        let mission_v1 = Mission::compile(
            tenant_id,
            mission_id.clone(),
            project_id.clone(),
            "Remote mission",
            MissionContract::bootstrap(
                "Project an authenticated remote Mission",
                ["mission.sync".into()],
                now(),
            ),
            now(),
        )
        .expect("mission v1");
        let applied_v1 =
            apply_inbound_mission_revision(&mut store, &project_id, &mission_v1, 1, None, 1)
                .expect("apply v1");
        assert_eq!(
            (applied_v1.status, applied_v1.projection_revision),
            (LocalInboundSyncStatus::Applied, Some(1))
        );

        let mut mission_v2 = mission_v1.clone();
        mission_v2
            .start_research(
                [Task {
                    id: TaskId::from("remote-task"),
                    title: "Remote task".into(),
                    status: TaskStatus::Ready,
                    capability: "mission.sync".into(),
                }],
                now(),
            )
            .expect("remote v2");
        let applied_v2 =
            apply_inbound_mission_revision(&mut store, &project_id, &mission_v2, 2, Some(1), 2)
                .expect("apply v2 over unchanged local projection");
        assert_eq!(applied_v2.projection_revision, Some(2));

        let mut locally_changed = store
            .load_mission(&project_id, &mission_id)
            .expect("local v2");
        locally_changed
            .record_evidence(
                Evidence {
                    id: EvidenceId::from("local-evidence"),
                    title: "Local evidence".into(),
                    source_uri: "local://evidence".into(),
                    observed_at: now(),
                    confidence: 1.0,
                    status: EvidenceStatus::Confirmed,
                    content_digest: "a".repeat(64),
                },
                now(),
            )
            .expect("local revision 3");
        store
            .update_mission_atomic(
                &locally_changed,
                2,
                &[PendingEvent::new(
                    "mission.local_changed",
                    json!({"revision": locally_changed.revision}),
                    now(),
                )],
            )
            .expect("persist local revision");

        let mut remote_v3 = mission_v2;
        remote_v3
            .record_evidence(
                Evidence {
                    id: EvidenceId::from("remote-evidence"),
                    title: "Remote evidence".into(),
                    source_uri: "remote://evidence".into(),
                    observed_at: now(),
                    confidence: 1.0,
                    status: EvidenceStatus::Confirmed,
                    content_digest: "b".repeat(64),
                },
                now(),
            )
            .expect("remote revision 3");
        assert!(matches!(
            apply_inbound_mission_revision(&mut store, &project_id, &remote_v3, 3, Some(2), 3,),
            Err(StorageError::OptimisticConflict { .. })
        ));
        let conflicted = store
            .load_local_inbound_sync_object(&project_id, mission_id.as_str())
            .expect("persisted conflict");
        assert_eq!(conflicted.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(conflicted.projection_revision, Some(2));
        assert_eq!(
            store
                .load_mission(&project_id, &mission_id)
                .expect("local wins until reconcile"),
            locally_changed
        );
    }

    #[test]
    fn inbound_project_metadata_preserves_local_roots_and_conflicts_with_local_edits() {
        let (mut store, project_id) = setup();
        let selected = store.load_project(&project_id).expect("project");

        let first = apply_inbound_project_revision(&mut store, &selected, 1, None, 1)
            .expect("adopt matching registration metadata");
        assert_eq!(
            (first.status, first.projection_revision),
            (LocalInboundSyncStatus::Applied, Some(2))
        );

        let mut remote_v3 = selected.clone();
        remote_v3
            .update_metadata("Remote project name", "remote revision")
            .expect("remote metadata update");
        apply_inbound_project_revision(&mut store, &remote_v3, 2, Some(1), 2)
            .expect("apply remote v3");
        let projected_v3 = store.load_project(&project_id).expect("projected v3");
        assert_eq!(projected_v3, remote_v3);
        assert_eq!(projected_v3.workspace_roots, selected.workspace_roots);

        let mut local_v4 = projected_v3.clone();
        local_v4
            .update_metadata("Local project name", "local revision")
            .expect("local metadata update");
        store
            .update_project_atomic(
                &local_v4,
                projected_v3.revision,
                &[PendingEvent::new(
                    "project.local_changed",
                    json!({"revision": local_v4.revision}),
                    now(),
                )],
            )
            .expect("persist local v4");

        let mut remote_v4 = remote_v3;
        remote_v4
            .update_metadata("Divergent remote name", "remote divergent revision")
            .expect("remote v4");
        assert!(matches!(
            apply_inbound_project_revision(&mut store, &remote_v4, 3, Some(2), 3),
            Err(StorageError::OptimisticConflict { .. })
        ));
        let conflicted = store
            .load_local_inbound_sync_object(&project_id, project_id.as_str())
            .expect("persisted project conflict");
        assert_eq!(conflicted.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(conflicted.projection_revision, Some(3));
        assert_eq!(
            store.load_project(&project_id).expect("local project wins"),
            local_v4
        );
    }

    #[test]
    fn inbound_truth_requires_an_exact_correction_chain_and_preserves_local_conflict() {
        let (mut store, project_id) = setup();
        let fact_v1 = TruthFact::create(
            FactId::from("truth-inbound-1"),
            TenantId::from("tenant-sync-local"),
            project_id.clone(),
            "market.unknown",
            None,
            vec![],
            TruthStatus::Unknown,
            None,
            "JP",
            "ja",
            now(),
            now(),
            None,
            Decimal::ZERO,
            now(),
        )
        .expect("truth v1");
        apply_inbound_truth_revision(&mut store, &fact_v1, 1, None, 1)
            .expect("insert remote truth v1");

        let fact_v2 = fact_v1
            .revise(
                None,
                vec![],
                TruthStatus::Unknown,
                None,
                Decimal::ZERO,
                now(),
                "remote requested more evidence",
                ActorId::from("remote-owner"),
                now(),
            )
            .expect("truth v2");
        apply_inbound_truth_revision(&mut store, &fact_v2, 2, Some(1), 2)
            .expect("apply exact remote correction");
        assert_eq!(
            store
                .load_truth_fact(&project_id, &fact_v2.id)
                .expect("truth v2 head"),
            fact_v2
        );

        let local_v3 = fact_v2
            .revise(
                None,
                vec![],
                TruthStatus::Unknown,
                None,
                Decimal::ZERO,
                now(),
                "local owner changed evidence plan",
                ActorId::from("local-owner"),
                now(),
            )
            .expect("local truth v3");
        store
            .revise_truth_fact(
                &local_v3,
                2,
                "truth.local_revised",
                &json!({"version": 3}),
                now(),
            )
            .expect("persist local truth v3");
        let remote_v3 = fact_v2
            .revise(
                None,
                vec![],
                TruthStatus::Unknown,
                None,
                Decimal::ZERO,
                now(),
                "remote owner chose another evidence plan",
                ActorId::from("remote-owner"),
                now(),
            )
            .expect("remote truth v3");
        assert!(matches!(
            apply_inbound_truth_revision(&mut store, &remote_v3, 3, Some(2), 3),
            Err(StorageError::OptimisticConflict { .. })
        ));
        let conflict = store
            .load_local_inbound_sync_object(&project_id, fact_v1.id.as_str())
            .expect("truth conflict head");
        assert_eq!(conflict.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(conflict.projection_revision, Some(2));
        assert_eq!(
            store
                .load_truth_fact(&project_id, &fact_v1.id)
                .expect("local truth preserved"),
            local_v3
        );
    }

    #[test]
    fn inbound_work_product_preserves_a_locally_diverged_manifest_and_artifact() {
        let (mut store, project_id) = setup();
        let (mut mission, manifest_v1, product_v1) =
            persisted_work_product(&mut store, &project_id);
        apply_inbound_work_product_revision(&mut store, &manifest_v1, &product_v1, 1, None, 1)
            .expect("establish remote projection v1");

        let local_product_v2 = product_v1
            .revise_content(
                "Local work product",
                "Local owner revision",
                product_v1.evidence_ids.iter().cloned(),
            )
            .expect("local product v2");
        let previous_mission_revision = mission.revision;
        mission
            .revise_work_product(local_product_v2.clone(), now())
            .expect("local mission revision");
        let local_manifest_v2 = manifest_v1
            .revise(
                &local_product_v2,
                manifest_v1.dependencies.clone(),
                None,
                WorkProductPreview::new("text/plain", "Local preview").expect("preview"),
                manifest_v1.editable_scopes.clone(),
                now(),
            )
            .expect("local manifest v2");
        store
            .revise_work_product_manifest_atomic(
                &mission,
                previous_mission_revision,
                &local_manifest_v2,
                1,
                &[PendingEvent::new("work_product.local", json!({}), now())],
            )
            .expect("persist local divergence");

        let remote_product_v2 = product_v1
            .revise_content(
                "Remote work product",
                "Divergent remote revision",
                product_v1.evidence_ids.iter().cloned(),
            )
            .expect("remote product v2");
        let remote_manifest_v2 = manifest_v1
            .revise(
                &remote_product_v2,
                manifest_v1.dependencies.clone(),
                None,
                WorkProductPreview::new("text/plain", "Remote preview").expect("preview"),
                manifest_v1.editable_scopes.clone(),
                now(),
            )
            .expect("remote manifest v2");
        assert!(matches!(
            apply_inbound_work_product_revision(
                &mut store,
                &remote_manifest_v2,
                &remote_product_v2,
                2,
                Some(1),
                2,
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
        let conflict = store
            .load_local_inbound_sync_object(&project_id, product_v1.id.as_str())
            .expect("work product conflict");
        assert_eq!(conflict.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(conflict.projection_revision, Some(1));
        assert_eq!(
            store
                .load_work_product_manifest(&project_id, &product_v1.id)
                .expect("local manifest wins"),
            local_manifest_v2
        );
        assert_eq!(
            store
                .load_mission(&project_id, &mission.id)
                .expect("local mission wins")
                .work_products[0],
            local_product_v2
        );
    }

    #[test]
    fn inbound_connection_metadata_preserves_a_locally_revoked_connection() {
        let (mut store, project_id) = setup();
        let connected = connected_connection(&project_id);
        let connected_snapshot = connected.snapshot();
        let applied_v1 =
            apply_inbound_connection_metadata_revision(&mut store, &connected_snapshot, 1, None, 1)
                .expect("establish remote connection projection");
        assert_eq!(
            applied_v1.projection_revision,
            Some(connected_snapshot.revision)
        );

        let mut locally_revoked =
            Connection::restore(connected_snapshot.clone()).expect("restore connected projection");
        locally_revoked
            .revoke(now() + Duration::minutes(3))
            .expect("local revoke");
        store
            .update_connection(
                &locally_revoked,
                connected_snapshot.revision,
                "connection.locally_revoked",
                &json!({}),
                now() + Duration::minutes(3),
            )
            .expect("persist local revoke");

        let mut remote_branch =
            Connection::restore(connected_snapshot.clone()).expect("restore remote branch");
        remote_branch
            .begin_probe(now() + Duration::minutes(4))
            .expect("remote probe branch");
        assert!(matches!(
            apply_inbound_connection_metadata_revision(
                &mut store,
                &remote_branch.snapshot(),
                2,
                Some(1),
                2,
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));

        let conflict = store
            .load_local_inbound_sync_object(&project_id, connected.id().as_str())
            .expect("connection conflict");
        assert_eq!(conflict.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(
            conflict.projection_revision,
            Some(connected_snapshot.revision)
        );
        let preserved = store
            .load_connection(&project_id, connected.id())
            .expect("local revoke wins");
        assert_eq!(preserved.snapshot(), locally_revoked.snapshot());
        assert!(!preserved.is_connected(now() + Duration::minutes(4)));
        assert!(preserved.snapshot().granted_scopes.is_empty());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the replay test intentionally shows every signed inbound, Consent-bound Effect, handoff, identity projection, redaction, and local-wins assertion"
    )]
    fn inbound_conversation_replays_signed_consent_handoff_and_preserves_local_control() {
        let (mut store, project_id) = setup();
        let (identity, connection, consent, mut mission, conversation_v1) =
            conversation_sync_fixture(&mut store, &project_id);

        let applied_v1 = apply_inbound_conversation_revision(
            &mut store,
            &identity,
            &connection,
            &[],
            &conversation_v1,
            None,
            1,
        )
        .expect("project initial conversation and identity bundle");
        assert_eq!(applied_v1.projection_revision, Some(1));

        let mut conversation_v2 = conversation_v1.clone();
        conversation_v2
            .ingest_inbound(
                InboundMessageInput {
                    id: MessageId::from("inbound-conversation-message"),
                    provider_event_digest: "4".repeat(64),
                    content_digest: "5".repeat(64),
                    attachment_digests: BTreeSet::new(),
                    risk: ConversationContentRisk::Safe,
                    classification_confidence: Decimal::ONE,
                    occurred_at: now() + Duration::seconds(4),
                },
                &WebhookAttestation {
                    signature_verified: true,
                    route_digest: conversation_v2.route_digest.clone(),
                    provider: conversation_v2.provider.clone(),
                    connection_id: conversation_v2.connection_id.clone(),
                    account_id: conversation_v2.account_id.clone(),
                    received_at: now() + Duration::seconds(5),
                },
            )
            .expect("ingest signed provider event");
        apply_inbound_conversation_revision(
            &mut store,
            &identity,
            &connection,
            &[],
            &conversation_v2,
            Some(1),
            2,
        )
        .expect("project signed inbound message");

        let mut conversation_v3 = conversation_v2.clone();
        let previous_mission_revision = mission.revision;
        let effect_id = propose_conversation_reply(
            &mut mission,
            &mut conversation_v3,
            &consent,
            now() + Duration::seconds(6),
        );
        store
            .update_mission_atomic(
                &mission,
                previous_mission_revision,
                &[PendingEvent::new(
                    "mission.conversation_reply_proposed",
                    json!({"effectId": effect_id}),
                    now() + Duration::seconds(6),
                )],
            )
            .expect("persist exact reply Effect");
        apply_inbound_conversation_revision(
            &mut store,
            &identity,
            &connection,
            std::slice::from_ref(&consent),
            &conversation_v3,
            Some(2),
            3,
        )
        .expect("project consent-bound prepared reply");

        let mut conversation_v4 = conversation_v3.clone();
        let previous_mission_revision = mission.revision;
        mission
            .cancel_effect(&effect_id, now() + Duration::seconds(7))
            .expect("cancel pending reply Effect before handoff");
        conversation_v4
            .take_human_control(
                conversation_v4.control.generation(),
                ActorId::from("human-owner"),
                now() + Duration::seconds(7),
            )
            .expect("take human control");
        store
            .update_mission_atomic(
                &mission,
                previous_mission_revision,
                &[PendingEvent::new(
                    "mission.conversation_reply_cancelled",
                    json!({"effectId": effect_id}),
                    now() + Duration::seconds(7),
                )],
            )
            .expect("persist cancelled reply Effect");
        apply_inbound_conversation_revision(
            &mut store,
            &identity,
            &connection,
            std::slice::from_ref(&consent),
            &conversation_v4,
            Some(3),
            4,
        )
        .expect("project hard human handoff");

        assert_eq!(
            store
                .load_company(
                    &project_id,
                    identity
                        .company
                        .as_ref()
                        .map(|company| &company.id)
                        .expect("company"),
                )
                .expect("projected company"),
            *identity.company.as_ref().expect("company")
        );
        assert_eq!(
            store
                .load_person(&project_id, &identity.person.id)
                .expect("projected person"),
            identity.person
        );
        assert_eq!(
            store
                .load_connection(&project_id, &connection.id)
                .expect("projected connection")
                .snapshot(),
            connection
        );
        assert_eq!(
            store
                .load_consent_record(&project_id, &consent.id)
                .expect("projected consent"),
            consent
        );

        let mut local_v5 = conversation_v4.clone();
        local_v5
            .resume_agent(
                local_v5.control.generation(),
                "a".repeat(64),
                now() + Duration::seconds(8),
            )
            .expect("local owner explicitly resumes agent");
        store
            .update_conversation(
                &local_v5,
                conversation_v4.revision,
                "conversation.local_resume",
                &json!({"conversationId": local_v5.id}),
                now() + Duration::seconds(8),
            )
            .expect("persist local resume");

        let mut remote_v5 = conversation_v4;
        remote_v5
            .resume_agent(
                remote_v5.control.generation(),
                "b".repeat(64),
                now() + Duration::seconds(8),
            )
            .expect("divergent remote resume");
        assert!(matches!(
            apply_inbound_conversation_revision(
                &mut store,
                &identity,
                &connection,
                std::slice::from_ref(&consent),
                &remote_v5,
                Some(4),
                5,
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
        let conflict = store
            .load_local_inbound_sync_object(&project_id, remote_v5.id.as_str())
            .expect("conversation conflict head");
        assert_eq!(conflict.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(conflict.projection_revision, Some(4));
        assert_eq!(
            store
                .load_conversation(&project_id, &local_v5.id)
                .expect("local control decision wins"),
            local_v5
        );

        let audit: String = store
            .connection
            .query_row(
                "SELECT group_concat(payload_json, '') FROM domain_events
                 WHERE project_id = ?1 AND event_type LIKE 'sync.inbound.conversation%'",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .expect("conversation projection audit");
        for private_value in [
            "Verified correspondent",
            "owner@example.invalid",
            conversation_v1.route_digest.as_str(),
            consent.evidence_digest.as_str(),
            "4".repeat(64).as_str(),
            "5".repeat(64).as_str(),
            "6".repeat(64).as_str(),
        ] {
            assert!(!audit.contains(private_value));
        }
    }

    #[test]
    fn inbound_conversation_rolls_back_identity_projection_before_connection_conflict() {
        let (mut store, project_id) = setup();
        let (identity, remote_connection, _, _, conversation) =
            conversation_sync_fixture(&mut store, &project_id);
        let local_connection = Connection::register(
            remote_connection.id.clone(),
            remote_connection.tenant_id.clone(),
            project_id.clone(),
            remote_connection.provider.clone(),
            remote_connection.account_id.clone(),
            remote_connection.expected_external_account_id.clone(),
            ["messages.read".into(), "messages.send".into()],
            now(),
        )
        .expect("divergent local connection");
        store
            .create_connection(
                &local_connection,
                "connection.local_fixture",
                &json!({"connectionId": local_connection.id()}),
                now(),
            )
            .expect("persist divergent local connection");

        assert!(matches!(
            apply_inbound_conversation_revision(
                &mut store,
                &identity,
                &remote_connection,
                &[],
                &conversation,
                None,
                1,
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
        assert!(matches!(
            store.load_person(&project_id, &identity.person.id),
            Err(StorageError::ScopedRecordNotFound { kind: "person", .. })
        ));
        let company_id = &identity.company.as_ref().expect("company").id;
        assert!(matches!(
            store.load_company(&project_id, company_id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "company",
                ..
            })
        ));
        assert_eq!(
            store
                .load_connection(&project_id, &remote_connection.id)
                .expect("local connection survives")
                .snapshot(),
            local_connection.snapshot()
        );
        assert!(matches!(
            store.load_conversation(&project_id, &conversation.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "conversation",
                ..
            })
        ));
        let head = store
            .load_local_inbound_sync_object(&project_id, conversation.id.as_str())
            .expect("conflicted inbound head");
        assert_eq!(head.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(head.projection_revision, None);
    }

    #[test]
    fn inbound_creator_work_preserves_local_funding_and_requires_verified_hiring_evidence() {
        let (mut store, project_id) = setup();
        let (identities, hiring, task_v1) = verified_creator_work_bundle(&mut store, &project_id);
        let applied_v1 = apply_inbound_creator_work_revision(
            &mut store,
            &identities,
            &hiring,
            &task_v1,
            1,
            None,
            1,
        )
        .expect("insert verified creator work bundle");
        assert_eq!(applied_v1.projection_revision, Some(task_v1.state_revision));
        assert_eq!(
            store
                .load_creator_hiring(&project_id, &hiring.id)
                .expect("projected hiring"),
            hiring
        );
        assert_eq!(
            store
                .load_creator_task(&project_id, &task_v1.id)
                .expect("projected creator task"),
            task_v1
        );

        let mut local_v2 = task_v1.clone();
        local_v2
            .publish(
                creator_funding_reservation(
                    &task_v1,
                    "local-funding-reservation",
                    'd',
                    now() + Duration::minutes(11),
                ),
                now() + Duration::minutes(11),
            )
            .expect("local funding");
        store
            .update_creator_task(
                &local_v2,
                task_v1.state_revision,
                "creator_task.local_funding",
                &json!({"taskId": local_v2.id}),
                now() + Duration::minutes(11),
            )
            .expect("persist local funding");

        let mut remote_v2 = task_v1.clone();
        remote_v2
            .publish(
                creator_funding_reservation(
                    &task_v1,
                    "remote-funding-reservation",
                    'e',
                    now() + Duration::minutes(11),
                ),
                now() + Duration::minutes(11),
            )
            .expect("remote funding");
        assert!(matches!(
            apply_inbound_creator_work_revision(
                &mut store,
                &identities,
                &hiring,
                &remote_v2,
                2,
                Some(1),
                2,
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
        let conflict = store
            .load_local_inbound_sync_object(&project_id, task_v1.id.as_str())
            .expect("creator work conflict");
        assert_eq!(conflict.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(conflict.projection_revision, Some(task_v1.state_revision));
        assert_eq!(
            store
                .load_creator_task(&project_id, &task_v1.id)
                .expect("local creator funding wins"),
            local_v2
        );

        let events = store
            .events_for_mission(&project_id, &task_v1.mission_id)
            .expect("creator work audit events");
        let audit = serde_json::to_string(&events).expect("serialize audit");
        assert!(!audit.contains("Deliver an original video"));
        assert!(!audit.contains("local-funding-reservation"));
        assert!(!audit.contains("remote-funding-reservation"));
    }

    #[test]
    fn inbound_creator_work_rejects_an_incomplete_identity_bundle_before_projection() {
        let (mut store, project_id) = setup();
        let (_, hiring, task) = verified_creator_work_bundle(&mut store, &project_id);
        assert!(matches!(
            apply_inbound_creator_work_revision(
                &mut store,
                &[],
                &hiring,
                &task,
                1,
                None,
                1,
            ),
            Err(StorageError::DomainDecode(message))
                if message == "invalid inbound creator identity projection"
        ));
        assert!(matches!(
            store.load_creator_hiring(&project_id, &hiring.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "creator hiring",
                ..
            })
        ));
        assert!(matches!(
            store.load_creator_task(&project_id, &task.id),
            Err(StorageError::CreatorTaskNotFound { .. })
        ));
        let head = store
            .load_local_inbound_sync_object(&project_id, task.id.as_str())
            .expect("validated inbound head remains inspectable");
        assert_eq!(head.status, LocalInboundSyncStatus::Validated);
        assert_eq!(head.projection_revision, None);
    }

    #[test]
    fn inbound_creator_work_rolls_back_partial_identity_projection_before_conflict_commit() {
        let (mut store, project_id) = setup();
        let (mut identities, hiring, task) = verified_creator_work_bundle(&mut store, &project_id);
        let local_partner = identities[0].partner.clone();
        store
            .create_partner(
                &local_partner,
                "partner.local_fixture",
                &json!({"partnerId": local_partner.id}),
                now(),
            )
            .expect("persist pre-existing local partner");

        let company = Company {
            id: CompanyId::from("company-remote-creator-work"),
            tenant_id: task.tenant_id.clone(),
            project_id: project_id.clone(),
            legal_name: "Remote creator studio".into(),
            market: "US".into(),
            revision: 1,
        };
        identities[0].partner.company_id = Some(company.id.clone());
        identities[0].company = Some(company.clone());

        assert!(matches!(
            apply_inbound_creator_work_revision(
                &mut store,
                &identities,
                &hiring,
                &task,
                1,
                None,
                1,
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
        assert!(matches!(
            store.load_company(&project_id, &company.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "company",
                ..
            })
        ));
        assert_eq!(
            store
                .load_partner(&project_id, &local_partner.id)
                .expect("local partner survives"),
            local_partner
        );
        assert!(matches!(
            store.load_creator_hiring(&project_id, &hiring.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "creator hiring",
                ..
            })
        ));
        assert!(matches!(
            store.load_creator_task(&project_id, &task.id),
            Err(StorageError::CreatorTaskNotFound { .. })
        ));
        let head = store
            .load_local_inbound_sync_object(&project_id, task.id.as_str())
            .expect("conflicted inbound head");
        assert_eq!(head.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(head.projection_revision, None);
    }

    #[test]
    fn inbound_outcome_ledger_projects_exact_support_and_immutable_order_atomically() {
        let (mut store, project_id) = setup();
        let fixture = outcome_projection_fixture(&project_id);
        let applied = apply_inbound_outcome_ledger_revision(&mut store, &fixture, 1, None, 1)
            .expect("project verified outcome closure");
        assert_eq!(applied.projection_revision, Some(fixture.ledger.revision));
        assert_eq!(
            store
                .load_mission(&project_id, &fixture.mission.id)
                .expect("mission"),
            fixture.mission
        );
        assert_eq!(
            store
                .load_connection(&project_id, &fixture.connection.id)
                .expect("connection")
                .snapshot(),
            fixture.connection
        );
        assert_eq!(
            store
                .load_partner(&project_id, &fixture.partner.id)
                .expect("partner"),
            fixture.partner
        );
        assert_eq!(
            store
                .load_identity_link(&project_id, &fixture.identity_link.id)
                .expect("identity link"),
            fixture.identity_link
        );
        assert_eq!(
            store
                .load_outcome_ledger(&project_id)
                .expect("outcome ledger"),
            fixture.ledger
        );
    }

    #[test]
    fn inbound_outcome_ledger_rolls_back_support_before_connection_conflict() {
        let (mut store, project_id) = setup();
        let fixture = outcome_projection_fixture(&project_id);
        let local_connection = Connection::register(
            fixture.connection.id.clone(),
            fixture.connection.tenant_id.clone(),
            project_id.clone(),
            fixture.connection.provider.clone(),
            AccountId::from("different-local-merchant"),
            "different-local-merchant",
            ["orders.read".into()],
            now(),
        )
        .expect("local connection");
        store
            .create_connection(
                &local_connection,
                "connection.local_fixture",
                &json!({"connectionId": local_connection.id()}),
                now(),
            )
            .expect("persist conflicting local connection");

        assert!(matches!(
            apply_inbound_outcome_ledger_revision(&mut store, &fixture, 1, None, 1),
            Err(StorageError::OptimisticConflict { .. })
        ));
        assert_eq!(
            store
                .load_connection(&project_id, &fixture.connection.id)
                .expect("local connection survives")
                .snapshot(),
            local_connection.snapshot()
        );
        assert!(matches!(
            store.load_mission(&project_id, &fixture.mission.id),
            Err(StorageError::MissionNotFound { .. })
        ));
        assert!(matches!(
            store.load_partner(&project_id, &fixture.partner.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "partner",
                ..
            })
        ));
        assert!(matches!(
            store.load_identity_link(&project_id, &fixture.identity_link.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "identity_link",
                ..
            })
        ));
        assert!(matches!(
            store.load_outcome_ledger(&project_id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "outcome ledger",
                ..
            })
        ));
        let head = store
            .load_local_inbound_sync_object(&project_id, project_id.as_str())
            .expect("conflicted inbound head");
        assert_eq!(head.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(head.projection_revision, None);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the replay proves initial projection, exact transition, local fork preservation, and durable conflict in one state history"
    )]
    fn inbound_context_capsule_projects_minimal_authority_and_rejects_local_fork_overwrite() {
        let (mut store, project_id) = setup();
        let fixture = context_projection_fixture(&project_id);
        store
            .create_mission_atomic(
                &fixture.mission,
                &[PendingEvent::new(
                    "mission.context_fixture",
                    json!({"missionId": fixture.mission.id}),
                    now(),
                )],
            )
            .expect("persist mission authority");

        let applied = apply_inbound_context_capsule_revision(
            &mut store,
            &fixture,
            &fixture.capsule,
            1,
            None,
            1,
            now(),
        )
        .expect("project initial context capsule");
        assert_eq!(applied.projection_revision, Some(1));
        assert_eq!(
            store
                .load_context_workspace(&project_id, &fixture.workspace.id)
                .expect("workspace"),
            fixture.workspace
        );
        assert_eq!(
            store
                .load_context_branch_lineage(&project_id, &fixture.capsule.branch_id)
                .expect("lineage"),
            fixture.branches
        );
        assert_eq!(
            store
                .load_context_capsule_facts(&project_id, &fixture.capsule.id)
                .expect("exact facts"),
            vec![fixture.fact.clone()]
        );

        let mut claimed = fixture.capsule.clone();
        claimed
            .claim(7, now() + Duration::minutes(1))
            .expect("current generation claim");
        let applied = apply_inbound_context_capsule_revision(
            &mut store,
            &fixture,
            &claimed,
            2,
            Some(1),
            2,
            now() + Duration::minutes(1),
        )
        .expect("project exact claim transition");
        assert_eq!(applied.projection_revision, Some(2));

        let mut local = claimed.clone();
        local
            .submit_result(
                7,
                ContextReturnReceipt {
                    schema_id: "hartevo.context.market-finding".into(),
                    schema_version: 1,
                    result_digest: "5".repeat(64),
                    result_size_bytes: 256,
                    evidence_ids: BTreeSet::from([EvidenceId::from("returned-evidence")]),
                    artifact_digests: BTreeSet::new(),
                    uncertainty_digest: "6".repeat(64),
                    next_recommendation_digest: Some("7".repeat(64)),
                    submitted_at: now() + Duration::minutes(2),
                },
                now() + Duration::minutes(2),
            )
            .expect("local result");
        store
            .update_context_capsule(
                &local,
                claimed.revision,
                &[PendingEvent::new(
                    "context.local_result",
                    json!({"capsuleId": local.id}),
                    now() + Duration::minutes(2),
                )],
                now() + Duration::minutes(2),
            )
            .expect("persist local fork");

        let mut remote = claimed;
        remote
            .cancel(now() + Duration::minutes(2))
            .expect("remote cancellation");
        assert!(matches!(
            apply_inbound_context_capsule_revision(
                &mut store,
                &fixture,
                &remote,
                3,
                Some(2),
                3,
                now() + Duration::minutes(2),
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
        assert_eq!(
            store
                .load_context_capsule(&project_id, &local.id)
                .expect("local result survives"),
            local
        );
        let head = store
            .load_local_inbound_sync_object(&project_id, fixture.capsule.id.as_str())
            .expect("conflicted head");
        assert_eq!(head.status, LocalInboundSyncStatus::Conflict);
        assert_eq!(head.projection_revision, Some(2));
    }

    #[test]
    fn inbound_context_capsule_rolls_back_workspace_and_branch_before_fact_conflict() {
        let (mut store, project_id) = setup();
        let fixture = context_projection_fixture(&project_id);
        store
            .create_mission_atomic(
                &fixture.mission,
                &[PendingEvent::new(
                    "mission.context_fixture",
                    json!({"missionId": fixture.mission.id}),
                    now(),
                )],
            )
            .expect("persist mission authority");
        let mut conflicting_fact = fixture.fact.clone();
        conflicting_fact.value = Some(TruthValue::Text("different local query".into()));
        store
            .create_truth_fact(
                &conflicting_fact,
                "truth.local_conflict",
                &json!({"factId": conflicting_fact.id}),
                now(),
            )
            .expect("persist conflicting fact");

        assert!(matches!(
            apply_inbound_context_capsule_revision(
                &mut store,
                &fixture,
                &fixture.capsule,
                1,
                None,
                1,
                now(),
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
        assert_eq!(
            store
                .load_truth_fact(&project_id, &conflicting_fact.id)
                .expect("local fact survives"),
            conflicting_fact
        );
        assert!(matches!(
            store.load_context_workspace(&project_id, &fixture.workspace.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "context workspace",
                ..
            })
        ));
        assert!(matches!(
            store.load_context_branch(&project_id, &fixture.branches[0].id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "context branch",
                ..
            })
        ));
        assert!(matches!(
            store.load_worker_lease(&project_id, &fixture.lease.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "worker lease",
                ..
            })
        ));
        assert!(matches!(
            store.load_context_capsule(&project_id, &fixture.capsule.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "context capsule",
                ..
            })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the deletion replay keeps terminal projection, atomic cleanup, ciphertext purge, resurrection fences, and Cell evidence in one auditable journey"
    )]
    fn context_deletion_is_atomic_purges_ciphertext_and_blocks_resurrection() {
        let (mut store, project_id) = setup();
        let fixture = context_projection_fixture(&project_id);
        store
            .create_mission_atomic(
                &fixture.mission,
                &[PendingEvent::new(
                    "mission.context_deletion_fixture",
                    json!({"missionId": fixture.mission.id}),
                    now(),
                )],
            )
            .expect("persist mission authority");
        apply_inbound_context_capsule_revision(
            &mut store,
            &fixture,
            &fixture.capsule,
            1,
            None,
            1,
            now(),
        )
        .expect("project initial capsule");
        let mut cancelled = fixture.capsule.clone();
        cancelled
            .cancel(now() + Duration::minutes(1))
            .expect("terminal cancellation");
        apply_inbound_context_capsule_revision(
            &mut store,
            &fixture,
            &cancelled,
            2,
            Some(1),
            2,
            now() + Duration::minutes(1),
        )
        .expect("project terminal capsule");

        let (tombstone, operation) = context_deletion(&cancelled, now() + Duration::minutes(2));
        let prepared = store
            .prepare_local_context_capsule_deletion(
                &operation,
                &tombstone,
                now() + Duration::minutes(2),
            )
            .expect("atomically delete local projection and prepare tombstone");
        assert!(!prepared.duplicate);
        assert!(matches!(
            store.load_context_capsule(&project_id, &cancelled.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "context capsule",
                ..
            })
        ));
        let pending = store
            .load_deletion_record(&project_id, "context_capsule", cancelled.id.as_str())
            .expect("deletion record");
        assert!(!pending.is_complete());
        assert_eq!(
            pending.surfaces[&DeletionSurface::EncryptedCell].status,
            hartevo_domain_kernel::DeletionPropagationStatus::Pending
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT count(*) FROM encrypted_sync_inbound_versions
                     WHERE project_id = ?1 AND object_id = ?2",
                    params![project_id.as_str(), cancelled.id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("inbound ciphertext count"),
            0
        );

        let old_envelope = context_capsule_envelope(&project_id, &cancelled.id, 2, 3);
        assert!(matches!(
            store.stage_local_inbound_sync_object(
                &old_envelope,
                None,
                now() + Duration::minutes(3)
            ),
            Err(StorageError::SyncObjectDeleted { .. })
        ));
        let mut resurrection = operation.clone();
        resurrection.tombstone = false;
        resurrection.idempotency_key_digest = "7".repeat(64);
        resurrection.target_revision += 1;
        resurrection.request = json!({"ciphertext": [1, 2, 3]});
        resurrection.request_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&resurrection.request).expect("request"))
        );
        assert!(matches!(
            store.prepare_local_sync_operation(&resurrection),
            Err(StorageError::SyncObjectDeleted { .. })
        ));

        let applied = store
            .record_local_sync_applied(
                &project_id,
                &operation.idempotency_key_digest,
                1,
                cancelled.revision + 1,
                false,
                now() + Duration::minutes(3),
            )
            .expect("record Cell tombstone");
        assert_eq!(applied.status, LocalSyncStatus::Applied);
        let recorded = store
            .load_deletion_record(&project_id, "context_capsule", cancelled.id.as_str())
            .expect("updated deletion record");
        assert_eq!(
            recorded.surfaces[&DeletionSurface::EncryptedCell].status,
            hartevo_domain_kernel::DeletionPropagationStatus::Applied
        );
        assert!(
            !recorded.is_complete(),
            "cache and replay propagation remain honest pending work"
        );

        let cache_job = store
            .load_deletion_propagation_job(&project_id, &tombstone.id, DeletionSurface::Cache)
            .expect("durable cache propagation job");
        let replay_job = store
            .load_deletion_propagation_job(&project_id, &tombstone.id, DeletionSurface::Replay)
            .expect("durable replay propagation job");
        assert_eq!(cache_job.status, DeletionPropagationJobStatus::Pending);
        assert_eq!(replay_job.status, DeletionPropagationJobStatus::Pending);
        assert!(matches!(
            store.load_deletion_propagation_job(
                &project_id,
                &tombstone.id,
                DeletionSurface::ObjectStorage,
            ),
            Err(StorageError::ScopedRecordNotFound { .. })
        ));

        let stale_cache_lease = store
            .claim_deletion_propagation_jobs(
                DeletionSurface::Cache,
                "cache-cleaner-stale",
                now() + Duration::minutes(3),
                Duration::minutes(1),
                1,
            )
            .expect("claim first cache lease")
            .into_iter()
            .next()
            .expect("cache work");
        let current_cache_lease = store
            .claim_deletion_propagation_jobs(
                DeletionSurface::Cache,
                "cache-cleaner-current",
                now() + Duration::minutes(5),
                Duration::minutes(2),
                1,
            )
            .expect("reclaim expired cache lease")
            .into_iter()
            .next()
            .expect("reclaimed cache work");
        assert!(current_cache_lease.lease_generation > stale_cache_lease.lease_generation);
        let current_cache_lease = store
            .heartbeat_deletion_propagation_job(
                &project_id,
                &tombstone.id,
                DeletionSurface::Cache,
                "cache-cleaner-current",
                current_cache_lease.lease_generation,
                now() + Duration::minutes(6),
                Duration::minutes(5),
            )
            .expect("heartbeat exact cache lease");

        let stale_receipt = DeletionPropagationReceipt::create(
            DeletionReceiptId::from("cache-receipt-stale"),
            &tombstone,
            DeletionSurface::Cache,
            WorkerId::from("cache-cleaner-stale"),
            stale_cache_lease.lease_generation,
            "8".repeat(64),
            1,
            1,
            0,
            "9".repeat(64),
            now() + Duration::minutes(4),
        )
        .expect("well-formed but stale receipt");
        assert!(matches!(
            store.complete_deletion_propagation(&stale_receipt, now() + Duration::minutes(6)),
            Err(StorageError::DeletionPropagationLeaseLost { .. })
        ));
        assert!(
            DeletionPropagationReceipt::create(
                DeletionReceiptId::from("cache-receipt-residual"),
                &tombstone,
                DeletionSurface::Cache,
                WorkerId::from("cache-cleaner-current"),
                current_cache_lease.lease_generation,
                "8".repeat(64),
                2,
                1,
                1,
                "9".repeat(64),
                now() + Duration::minutes(6),
            )
            .is_err()
        );

        let cache_receipt = DeletionPropagationReceipt::create(
            DeletionReceiptId::from("cache-receipt-current"),
            &tombstone,
            DeletionSurface::Cache,
            WorkerId::from("cache-cleaner-current"),
            current_cache_lease.lease_generation,
            "a".repeat(64),
            2,
            2,
            0,
            "b".repeat(64),
            now() + Duration::minutes(6),
        )
        .expect("verified cache purge receipt");
        let cache_applied = store
            .complete_deletion_propagation(&cache_receipt, now() + Duration::minutes(6))
            .expect("apply cache receipt");
        assert_eq!(
            cache_applied.surfaces[&DeletionSurface::Cache].evidence_digest,
            Some(cache_receipt.receipt_digest.clone())
        );
        assert_eq!(
            store
                .complete_deletion_propagation(&cache_receipt, now() + Duration::minutes(7))
                .expect("idempotent exact receipt replay"),
            cache_applied
        );

        let replay_first = store
            .claim_deletion_propagation_jobs(
                DeletionSurface::Replay,
                "replay-cleaner",
                now() + Duration::minutes(6),
                Duration::minutes(5),
                1,
            )
            .expect("claim replay cleanup")
            .into_iter()
            .next()
            .expect("replay work");
        store
            .release_deletion_propagation_job(
                &project_id,
                &tombstone.id,
                DeletionSurface::Replay,
                "replay-cleaner",
                replay_first.lease_generation,
                "REPLAY_STORE_TEMPORARILY_UNAVAILABLE",
                now() + Duration::minutes(8),
                now() + Duration::minutes(7),
                false,
            )
            .expect("release with durable retry backoff");
        assert!(
            store
                .claim_deletion_propagation_jobs(
                    DeletionSurface::Replay,
                    "replay-cleaner",
                    now() + Duration::minutes(7),
                    Duration::minutes(5),
                    1,
                )
                .expect("backoff claim")
                .is_empty()
        );
        let replay_current = store
            .claim_deletion_propagation_jobs(
                DeletionSurface::Replay,
                "replay-cleaner",
                now() + Duration::minutes(8),
                Duration::minutes(5),
                1,
            )
            .expect("claim retry after backoff")
            .into_iter()
            .next()
            .expect("retried replay work");
        assert!(replay_current.lease_generation > replay_first.lease_generation);
        let replay_receipt = DeletionPropagationReceipt::create(
            DeletionReceiptId::from("replay-receipt-current"),
            &tombstone,
            DeletionSurface::Replay,
            WorkerId::from("replay-cleaner"),
            replay_current.lease_generation,
            "c".repeat(64),
            0,
            0,
            0,
            "d".repeat(64),
            now() + Duration::minutes(8),
        )
        .expect("verified empty replay inventory receipt");
        let complete = store
            .complete_deletion_propagation(&replay_receipt, now() + Duration::minutes(8))
            .expect("apply replay receipt");
        assert!(complete.is_complete());
        assert_eq!(
            complete.surfaces[&DeletionSurface::Replay].evidence_digest,
            Some(replay_receipt.receipt_digest)
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT count(*) FROM deletion_propagation_receipts
                     WHERE project_id = ?1 AND deletion_id = ?2",
                    params![project_id.as_str(), tombstone.id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("immutable receipt count"),
            2
        );
    }

    #[test]
    fn non_terminal_context_deletion_rolls_back_without_a_tombstone_ledger() {
        let (mut store, project_id) = setup();
        let fixture = context_projection_fixture(&project_id);
        store
            .create_mission_atomic(
                &fixture.mission,
                &[PendingEvent::new(
                    "mission.context_deletion_fixture",
                    json!({"missionId": fixture.mission.id}),
                    now(),
                )],
            )
            .expect("persist mission authority");
        apply_inbound_context_capsule_revision(
            &mut store,
            &fixture,
            &fixture.capsule,
            1,
            None,
            1,
            now(),
        )
        .expect("project issued capsule");
        let (tombstone, operation) =
            context_deletion(&fixture.capsule, now() + Duration::minutes(1));
        assert!(matches!(
            store.prepare_local_context_capsule_deletion(
                &operation,
                &tombstone,
                now() + Duration::minutes(1)
            ),
            Err(StorageError::DeletionRequiresTerminalContextCapsule)
        ));
        assert_eq!(
            store
                .load_context_capsule(&project_id, &fixture.capsule.id)
                .expect("issued capsule survives"),
            fixture.capsule
        );
        assert!(matches!(
            store.load_deletion_record(&project_id, "context_capsule", fixture.capsule.id.as_str()),
            Err(StorageError::ScopedRecordNotFound {
                kind: "sync deletion record",
                ..
            })
        ));
        assert!(matches!(
            store.load_local_sync_operation(&project_id, &operation.idempotency_key_digest),
            Err(StorageError::ScopedRecordNotFound {
                kind: "encrypted sync operation",
                ..
            })
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn inbound_head_cas_never_regresses_or_rewrites_a_remote_revision(
            commands in prop::collection::vec(inbound_stage_command(), 1..80),
        ) {
            let (mut store, project_id) = setup();
            let mut model_head: Option<(u64, u8, u64)> = None;

            for (candidate_revision, byte, expected_mode) in commands {
                let expected_remote_revision = match expected_mode {
                    ExpectedHead::Exact => model_head.map(|(revision, _, _)| revision),
                    ExpectedHead::None => None,
                    ExpectedHead::Previous => Some(
                        model_head
                            .map_or(0, |(revision, _, _)| revision.saturating_sub(1)),
                    ),
                    ExpectedHead::Candidate => Some(candidate_revision),
                };
                let before = model_head;
                let candidate =
                    inbound_envelope(project_id.clone(), candidate_revision, byte);
                let result = store.stage_local_inbound_sync_object(
                    &candidate,
                    expected_remote_revision,
                    now(),
                );

                match before {
                    None if expected_remote_revision.is_none() => {
                        let outcome = result?;
                        prop_assert_eq!(
                            outcome.disposition,
                            LocalInboundSyncStageDisposition::Inserted
                        );
                        model_head = Some((candidate_revision, byte, 1));
                    }
                    None => {
                        let optimistic_conflict =
                            matches!(result, Err(StorageError::OptimisticConflict { .. }));
                        prop_assert!(optimistic_conflict);
                    }
                    Some((head_revision, head_byte, local_revision))
                        if candidate_revision == head_revision && byte == head_byte =>
                    {
                        let outcome = result?;
                        prop_assert_eq!(
                            outcome.disposition,
                            LocalInboundSyncStageDisposition::Duplicate
                        );
                        prop_assert_eq!(outcome.object.revision, local_revision);
                    }
                    Some((head_revision, _, _)) if candidate_revision == head_revision => {
                        let immutable_revision = matches!(
                            result,
                            Err(StorageError::ImmutableRecordMismatch {
                                kind: "inbound encrypted sync revision",
                                ..
                            })
                        );
                        prop_assert!(immutable_revision);
                    }
                    Some((head_revision, _, local_revision))
                        if candidate_revision < head_revision =>
                    {
                        let outcome = result?;
                        prop_assert_eq!(
                            outcome.disposition,
                            LocalInboundSyncStageDisposition::Stale
                        );
                        prop_assert_eq!(outcome.object.envelope.remote_revision, head_revision);
                        prop_assert_eq!(outcome.object.revision, local_revision);
                    }
                    Some((head_revision, _, local_revision))
                        if expected_remote_revision == Some(head_revision) =>
                    {
                        let outcome = result?;
                        prop_assert_eq!(
                            outcome.disposition,
                            LocalInboundSyncStageDisposition::Advanced
                        );
                        model_head = Some((candidate_revision, byte, local_revision + 1));
                    }
                    Some(_) => {
                        let optimistic_conflict =
                            matches!(result, Err(StorageError::OptimisticConflict { .. }));
                        prop_assert!(optimistic_conflict);
                    }
                }

                if let Some((remote_revision, expected_byte, local_revision)) = model_head {
                    let stored = store.load_local_inbound_sync_object(
                        &project_id,
                        "mission-inbound-1",
                    )?;
                    prop_assert_eq!(stored.envelope.remote_revision, remote_revision);
                    prop_assert_eq!(stored.envelope, inbound_envelope(
                        project_id.clone(),
                        remote_revision,
                        expected_byte,
                    ));
                    prop_assert_eq!(stored.revision, local_revision);
                    if let Some((before_remote, _, before_local)) = before {
                        prop_assert!(remote_revision >= before_remote);
                        prop_assert!(local_revision >= before_local);
                    }
                } else {
                    let missing = store.load_local_inbound_sync_object(
                        &project_id,
                        "mission-inbound-1",
                    );
                    let scoped_missing = matches!(
                        missing,
                        Err(StorageError::ScopedRecordNotFound { .. })
                    );
                    prop_assert!(scoped_missing);
                }
            }
        }
    }
}

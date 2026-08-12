use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ContextBranch, ContextBranchId, ContextBranchStatus, ContextCapsule, ContextCapsuleId,
    ContextCapsuleStatus, ContextDataClass, ContextDataPolicy, ContextFactGrant,
    ContextMergePolicy, ContextWorkingSet, ContextWorkspace, ContextWorkspaceId,
    ContinuationLedger, Mission, ProjectId, TruthFact, WorkerHandle, WorkerLease, WorkerLeaseId,
    WorkerLeaseStatus, WorkerMailbox, validate_context_branch_lineage,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::context_collaboration_store::{insert_worker_handle, insert_worker_mailbox};
use crate::context_foundation_store::{
    insert_context_continuation_ledger, insert_context_working_set,
};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn create_context_workspace(
        &mut self,
        workspace: &ContextWorkspace,
        working_set: &ContextWorkingSet,
        continuation_ledger: &ContinuationLedger,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if workspace.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(workspace.revision));
        }
        let mission = self.load_mission(&workspace.project_id, &workspace.mission_id)?;
        workspace.validate_for(&mission, now)?;
        working_set.validate_for(workspace, now)?;
        continuation_ledger.validate_for(workspace, Some(&mission), now)?;
        if working_set.revision != 1 || continuation_ledger.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(
                working_set.revision.max(continuation_ledger.revision),
            ));
        }
        let transaction = self.connection.transaction()?;
        if load_context_workspace_record(&transaction, &workspace.project_id, &workspace.id)?
            .is_some()
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "context workspace",
                id: workspace.id.to_string(),
            });
        }
        insert_context_workspace(&transaction, workspace)?;
        insert_context_working_set(&transaction, working_set)?;
        insert_context_continuation_ledger(&transaction, continuation_ledger)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            workspace.tenant_id.as_str(),
            workspace.project_id.as_str(),
            Some(workspace.mission_id.as_str()),
            "context_workspace",
            workspace.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: workspace.revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_context_capsule_bundle(
        &mut self,
        workspace: &ContextWorkspace,
        branches: &[ContextBranch],
        lease: &WorkerLease,
        capsule: &ContextCapsule,
        worker_handle: &WorkerHandle,
        worker_mailbox: &WorkerMailbox,
        facts: &[TruthFact],
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let mission = self.load_mission(&workspace.project_id, &workspace.mission_id)?;
        validate_context_bundle(workspace, branches, lease, capsule, facts, &mission, now)?;
        let parent_handle = worker_handle
            .parent_worker_id
            .as_ref()
            .map(|worker_id| {
                self.load_worker_handle(&workspace.project_id, &workspace.id, worker_id)
            })
            .transpose()?;
        worker_handle.validate_for(
            workspace,
            branches.last().expect("validated non-empty branch lineage"),
            lease,
            capsule,
            parent_handle.as_ref(),
            now,
        )?;
        worker_mailbox.validate_for(worker_handle, now)?;
        let stored_workspace = self.load_context_workspace(&workspace.project_id, &workspace.id)?;
        if stored_workspace != *workspace {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "context workspace",
                id: workspace.id.to_string(),
            });
        }
        for fact in facts {
            if self.load_truth_fact_revision(&fact.project_id, &fact.id, fact.version)? != *fact {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "context fact revision",
                    id: fact.id.to_string(),
                });
            }
        }

        let transaction = self.connection.transaction()?;
        for branch in branches {
            match load_context_branch_record(&transaction, &branch.project_id, &branch.id)? {
                Some(stored) if stored == *branch => {}
                Some(_) => {
                    return Err(StorageError::ImmutableRecordMismatch {
                        kind: "context branch",
                        id: branch.id.to_string(),
                    });
                }
                None => insert_context_branch(&transaction, branch)?,
            }
        }
        if load_worker_lease_record(&transaction, &lease.project_id, &lease.id)?.is_some() {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "worker lease",
                id: lease.id.to_string(),
            });
        }
        if load_context_capsule_record(&transaction, &capsule.project_id, &capsule.id)?.is_some() {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "context capsule",
                id: capsule.id.to_string(),
            });
        }
        let active_workers: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM worker_leases
             WHERE project_id = ?1 AND workspace_id = ?2
               AND status = 'active' AND expires_at > ?3",
            params![
                workspace.project_id.as_str(),
                workspace.id.as_str(),
                now.to_rfc3339()
            ],
            |row| row.get(0),
        )?;
        if u32::try_from(active_workers).unwrap_or(u32::MAX) >= workspace.budget.max_concurrency {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_workspace:{}:concurrency", workspace.id),
                expected_revision: workspace.revision,
            });
        }
        insert_worker_lease(&transaction, lease)?;
        insert_context_capsule(&transaction, capsule)?;
        insert_context_capsule_facts(&transaction, capsule)?;
        insert_worker_handle(&transaction, worker_handle)?;
        insert_worker_mailbox(&transaction, worker_mailbox)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            capsule.tenant_id.as_str(),
            capsule.project_id.as_str(),
            Some(capsule.mission_id.as_str()),
            "context_capsule",
            capsule.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: capsule.revision,
        })
    }

    pub fn update_worker_lease(
        &mut self,
        lease: &WorkerLease,
        expected_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous = self.load_worker_lease(&lease.project_id, &lease.id)?;
        if previous.revision != expected_revision || !lease.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("worker_lease:{}", lease.id),
                expected_revision,
            });
        }
        let workspace = self.load_context_workspace(&lease.project_id, &lease.workspace_id)?;
        let branch = self.load_context_branch(&lease.project_id, &lease.branch_id)?;
        lease.validate_for(&workspace, &branch, now)?;

        let transaction = self.connection.transaction()?;
        update_worker_lease_row(&transaction, lease, expected_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            lease.tenant_id.as_str(),
            lease.project_id.as_str(),
            Some(workspace.mission_id.as_str()),
            "worker_lease",
            lease.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: lease.revision,
        })
    }

    pub fn update_context_capsule(
        &mut self,
        capsule: &ContextCapsule,
        expected_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous = self.load_context_capsule(&capsule.project_id, &capsule.id)?;
        if previous.revision != expected_revision || !capsule.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_capsule:{}", capsule.id),
                expected_revision,
            });
        }
        let workspace = self.load_context_workspace(&capsule.project_id, &capsule.workspace_id)?;
        let branch = self.load_context_branch(&capsule.project_id, &capsule.branch_id)?;
        let lease = self.load_worker_lease(&capsule.project_id, &capsule.worker_lease_id)?;
        let mission = self.load_mission(&capsule.project_id, &capsule.mission_id)?;
        let facts = self.load_context_capsule_facts(&capsule.project_id, &capsule.id)?;
        capsule.validate_for(&workspace, &branch, &lease, &mission, &facts, now)?;

        let transaction = self.connection.transaction()?;
        update_context_capsule_row(&transaction, capsule, expected_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            capsule.tenant_id.as_str(),
            capsule.project_id.as_str(),
            Some(capsule.mission_id.as_str()),
            "context_capsule",
            capsule.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: capsule.revision,
        })
    }

    pub fn load_context_workspace(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
    ) -> Result<ContextWorkspace, StorageError> {
        load_context_workspace_record(&self.connection, project_id, workspace_id)?.ok_or_else(
            || StorageError::ScopedRecordNotFound {
                kind: "context workspace",
                project_id: project_id.clone(),
                id: workspace_id.to_string(),
            },
        )
    }

    pub fn load_context_branch(
        &self,
        project_id: &ProjectId,
        branch_id: &ContextBranchId,
    ) -> Result<ContextBranch, StorageError> {
        load_context_branch_record(&self.connection, project_id, branch_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "context branch",
                project_id: project_id.clone(),
                id: branch_id.to_string(),
            }
        })
    }

    pub fn load_context_branch_lineage(
        &self,
        project_id: &ProjectId,
        branch_id: &ContextBranchId,
    ) -> Result<Vec<ContextBranch>, StorageError> {
        let mut lineage = Vec::new();
        let mut cursor = Some(branch_id.clone());
        let mut seen = BTreeSet::new();
        while let Some(id) = cursor.take() {
            if !seen.insert(id.clone()) {
                return Err(StorageError::DomainDecode(
                    "cyclic context branch lineage".into(),
                ));
            }
            let branch = self.load_context_branch(project_id, &id)?;
            cursor.clone_from(&branch.parent_branch_id);
            lineage.push(branch);
        }
        lineage.reverse();
        Ok(lineage)
    }

    pub fn load_worker_lease(
        &self,
        project_id: &ProjectId,
        lease_id: &WorkerLeaseId,
    ) -> Result<WorkerLease, StorageError> {
        load_worker_lease_record(&self.connection, project_id, lease_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "worker lease",
                project_id: project_id.clone(),
                id: lease_id.to_string(),
            }
        })
    }

    pub fn load_context_capsule(
        &self,
        project_id: &ProjectId,
        capsule_id: &ContextCapsuleId,
    ) -> Result<ContextCapsule, StorageError> {
        load_context_capsule_record(&self.connection, project_id, capsule_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "context capsule",
                project_id: project_id.clone(),
                id: capsule_id.to_string(),
            }
        })
    }

    pub fn load_context_capsule_facts(
        &self,
        project_id: &ProjectId,
        capsule_id: &ContextCapsuleId,
    ) -> Result<Vec<TruthFact>, StorageError> {
        let capsule = self.load_context_capsule(project_id, capsule_id)?;
        let grants = load_context_fact_grants(&self.connection, project_id, capsule_id)?;
        if grants != capsule.required_facts {
            return Err(StorageError::DomainDecode(
                "context capsule fact projection does not match record".into(),
            ));
        }
        grants
            .iter()
            .map(|grant| self.load_truth_fact_revision(project_id, &grant.fact_id, grant.version))
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_context_bundle(
    workspace: &ContextWorkspace,
    branches: &[ContextBranch],
    lease: &WorkerLease,
    capsule: &ContextCapsule,
    facts: &[TruthFact],
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    workspace.validate_for(mission, now)?;
    validate_context_branch_lineage(workspace, branches, now)?;
    let branch = branches.last().ok_or_else(|| {
        StorageError::DomainDecode("context capsule requires branch lineage".into())
    })?;
    if branch.id != capsule.branch_id {
        return Err(StorageError::DomainDecode(
            "context capsule branch is not the lineage head".into(),
        ));
    }
    lease.validate_for(workspace, branch, now)?;
    capsule.validate_for(workspace, branch, lease, mission, facts, now)?;
    Ok(())
}

pub(crate) fn insert_context_workspace(
    transaction: &Transaction<'_>,
    workspace: &ContextWorkspace,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_workspaces
           (tenant_id, project_id, id, mission_id, generation, contract_version,
            policy_version, capability_authority_json, constraint_digest, token_limit,
            cost_limit_minor, currency, deadline_at, max_depth, max_concurrency,
            data_policy, revision, created_at, updated_at, record_json)
         VALUES
           (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            workspace.tenant_id.as_str(),
            workspace.project_id.as_str(),
            workspace.id.as_str(),
            workspace.mission_id.as_str(),
            to_sql_u64(workspace.generation)?,
            to_sql_u64(workspace.contract_version)?,
            workspace.policy_version,
            serde_json::to_string(&workspace.capability_authority)?,
            workspace.constraint_digest,
            to_sql_u64(workspace.budget.token_limit)?,
            workspace.budget.cost_limit.amount_minor,
            workspace.budget.cost_limit.currency.as_str(),
            workspace.budget.deadline_at.to_rfc3339(),
            i64::from(workspace.budget.max_depth),
            i64::from(workspace.budget.max_concurrency),
            data_policy_name(workspace.data_policy),
            to_sql_u64(workspace.revision)?,
            workspace.created_at.to_rfc3339(),
            workspace.updated_at.to_rfc3339(),
            serde_json::to_string(workspace)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn insert_context_branch(
    transaction: &Transaction<'_>,
    branch: &ContextBranch,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_branches
           (tenant_id, project_id, id, workspace_id, parent_branch_id, depth,
            fork_reason, scope_digest, merge_policy, status, generation, revision,
            created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            branch.tenant_id.as_str(),
            branch.project_id.as_str(),
            branch.id.as_str(),
            branch.workspace_id.as_str(),
            branch
                .parent_branch_id
                .as_ref()
                .map(ContextBranchId::as_str),
            i64::from(branch.depth),
            branch.fork_reason,
            branch.scope_digest,
            merge_policy_name(branch.merge_policy),
            branch_status_name(branch.status),
            to_sql_u64(branch.generation)?,
            to_sql_u64(branch.revision)?,
            branch.created_at.to_rfc3339(),
            branch.updated_at.to_rfc3339(),
            serde_json::to_string(branch)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn insert_worker_lease(
    transaction: &Transaction<'_>,
    lease: &WorkerLease,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO worker_leases
           (tenant_id, project_id, id, workspace_id, branch_id, worker_id, generation,
            lease_token_digest, runtime_mapping_digest, issued_at, heartbeat_at,
            expires_at, status, revision, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            lease.tenant_id.as_str(),
            lease.project_id.as_str(),
            lease.id.as_str(),
            lease.workspace_id.as_str(),
            lease.branch_id.as_str(),
            lease.worker_id.as_str(),
            to_sql_u64(lease.generation)?,
            lease.lease_token_digest,
            lease.runtime_mapping_digest,
            lease.issued_at.to_rfc3339(),
            lease.heartbeat_at.to_rfc3339(),
            lease.expires_at.to_rfc3339(),
            worker_lease_status_name(lease.status),
            to_sql_u64(lease.revision)?,
            serde_json::to_string(lease)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn update_worker_lease_row(
    transaction: &Transaction<'_>,
    lease: &WorkerLease,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE worker_leases
         SET heartbeat_at = ?1, status = ?2, revision = ?3, record_json = ?4
         WHERE project_id = ?5 AND id = ?6 AND revision = ?7",
        params![
            lease.heartbeat_at.to_rfc3339(),
            worker_lease_status_name(lease.status),
            to_sql_u64(lease.revision)?,
            serde_json::to_string(lease)?,
            lease.project_id.as_str(),
            lease.id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("worker_lease:{}", lease.id),
            expected_revision,
        });
    }
    Ok(())
}

pub(crate) fn insert_context_capsule(
    transaction: &Transaction<'_>,
    capsule: &ContextCapsule,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_capsules
           (tenant_id, project_id, id, mission_id, task_id, workspace_id, branch_id,
            worker_lease_id, worker_id, worker_generation, authority_digest, status,
            issued_at, expires_at, updated_at, revision, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            capsule.tenant_id.as_str(),
            capsule.project_id.as_str(),
            capsule.id.as_str(),
            capsule.mission_id.as_str(),
            capsule.task_id.as_str(),
            capsule.workspace_id.as_str(),
            capsule.branch_id.as_str(),
            capsule.worker_lease_id.as_str(),
            capsule.worker_id.as_str(),
            to_sql_u64(capsule.worker_generation)?,
            capsule.authority_digest,
            capsule_status_name(capsule.status),
            capsule.issued_at.to_rfc3339(),
            capsule.expires_at.to_rfc3339(),
            capsule.updated_at.to_rfc3339(),
            to_sql_u64(capsule.revision)?,
            serde_json::to_string(capsule)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn insert_context_capsule_facts(
    transaction: &Transaction<'_>,
    capsule: &ContextCapsule,
) -> Result<(), StorageError> {
    for grant in &capsule.required_facts {
        transaction.execute(
            "INSERT INTO context_capsule_facts
               (tenant_id, project_id, capsule_id, fact_id, fact_version, classification)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                capsule.tenant_id.as_str(),
                capsule.project_id.as_str(),
                capsule.id.as_str(),
                grant.fact_id.as_str(),
                to_sql_u64(grant.version)?,
                data_class_name(grant.classification),
            ],
        )?;
    }
    Ok(())
}

pub(crate) fn update_context_capsule_row(
    transaction: &Transaction<'_>,
    capsule: &ContextCapsule,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE context_capsules
         SET status = ?1, updated_at = ?2, revision = ?3, record_json = ?4
         WHERE project_id = ?5 AND id = ?6 AND revision = ?7",
        params![
            capsule_status_name(capsule.status),
            capsule.updated_at.to_rfc3339(),
            to_sql_u64(capsule.revision)?,
            serde_json::to_string(capsule)?,
            capsule.project_id.as_str(),
            capsule.id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("context_capsule:{}", capsule.id),
            expected_revision,
        });
    }
    Ok(())
}

pub(crate) fn load_context_workspace_record(
    connection: &Connection,
    project_id: &ProjectId,
    workspace_id: &ContextWorkspaceId,
) -> Result<Option<ContextWorkspace>, StorageError> {
    load_record_json(
        connection,
        "SELECT record_json FROM context_workspaces WHERE project_id = ?1 AND id = ?2",
        project_id,
        workspace_id.as_str(),
    )
}

pub(crate) fn load_context_branch_record(
    connection: &Connection,
    project_id: &ProjectId,
    branch_id: &ContextBranchId,
) -> Result<Option<ContextBranch>, StorageError> {
    load_record_json(
        connection,
        "SELECT record_json FROM context_branches WHERE project_id = ?1 AND id = ?2",
        project_id,
        branch_id.as_str(),
    )
}

pub(crate) fn load_worker_lease_record(
    connection: &Connection,
    project_id: &ProjectId,
    lease_id: &WorkerLeaseId,
) -> Result<Option<WorkerLease>, StorageError> {
    load_record_json(
        connection,
        "SELECT record_json FROM worker_leases WHERE project_id = ?1 AND id = ?2",
        project_id,
        lease_id.as_str(),
    )
}

pub(crate) fn load_context_capsule_record(
    connection: &Connection,
    project_id: &ProjectId,
    capsule_id: &ContextCapsuleId,
) -> Result<Option<ContextCapsule>, StorageError> {
    load_record_json(
        connection,
        "SELECT record_json FROM context_capsules WHERE project_id = ?1 AND id = ?2",
        project_id,
        capsule_id.as_str(),
    )
}

pub(crate) fn load_context_fact_grants(
    connection: &Connection,
    project_id: &ProjectId,
    capsule_id: &ContextCapsuleId,
) -> Result<BTreeSet<ContextFactGrant>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT fact_id, fact_version, classification
         FROM context_capsule_facts
         WHERE project_id = ?1 AND capsule_id = ?2
         ORDER BY fact_id",
    )?;
    let rows = statement.query_map(params![project_id.as_str(), capsule_id.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    rows.map(|row| {
        let (fact_id, version, classification) = row?;
        Ok(ContextFactGrant {
            fact_id: hartevo_domain_kernel::FactId::from_stable(fact_id),
            version: from_sql_u64(version, "context fact version")?,
            classification: parse_data_class(&classification)?,
        })
    })
    .collect()
}

fn load_record_json<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    project_id: &ProjectId,
    id: &str,
) -> Result<Option<T>, StorageError> {
    let record: Option<String> = connection
        .query_row(sql, params![project_id.as_str(), id], |row| row.get(0))
        .optional()?;
    record
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .map_err(StorageError::from)
}

fn data_policy_name(value: ContextDataPolicy) -> &'static str {
    match value {
        ContextDataPolicy::PublicOnly => "public_only",
        ContextDataPolicy::BusinessOnly => "business_only",
        ContextDataPolicy::BusinessAndRedactedPersonal => "business_and_redacted_personal",
    }
}

fn data_class_name(value: ContextDataClass) -> &'static str {
    match value {
        ContextDataClass::Public => "public",
        ContextDataClass::Business => "business",
        ContextDataClass::RedactedPersonal => "redacted_personal",
    }
}

fn parse_data_class(value: &str) -> Result<ContextDataClass, StorageError> {
    match value {
        "public" => Ok(ContextDataClass::Public),
        "business" => Ok(ContextDataClass::Business),
        "redacted_personal" => Ok(ContextDataClass::RedactedPersonal),
        _ => Err(StorageError::DomainDecode(format!(
            "invalid context data class: {value}"
        ))),
    }
}

fn merge_policy_name(value: ContextMergePolicy) -> &'static str {
    match value {
        ContextMergePolicy::TypedResultOnly => "typed_result_only",
        ContextMergePolicy::ManualReview => "manual_review",
    }
}

fn branch_status_name(value: ContextBranchStatus) -> &'static str {
    match value {
        ContextBranchStatus::Active => "active",
        ContextBranchStatus::Completed => "completed",
        ContextBranchStatus::Merged => "merged",
        ContextBranchStatus::Abandoned => "abandoned",
    }
}

fn worker_lease_status_name(value: WorkerLeaseStatus) -> &'static str {
    match value {
        WorkerLeaseStatus::Active => "active",
        WorkerLeaseStatus::Released => "released",
        WorkerLeaseStatus::Revoked => "revoked",
        WorkerLeaseStatus::Expired => "expired",
    }
}

fn capsule_status_name(value: ContextCapsuleStatus) -> &'static str {
    match value {
        ContextCapsuleStatus::Issued => "issued",
        ContextCapsuleStatus::Claimed => "claimed",
        ContextCapsuleStatus::ResultSubmitted => "result_submitted",
        ContextCapsuleStatus::Accepted => "accepted",
        ContextCapsuleStatus::Cancelled => "cancelled",
        ContextCapsuleStatus::Expired => "expired",
    }
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

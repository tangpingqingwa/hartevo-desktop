//! SQLCipher-backed Browser Profile and Workspace projections.
//!
//! The encrypted `record_json` columns are the recoverable domain records.
//! Normalized columns and Event/Outbox payloads contain only scope identifiers,
//! state, counts, and digests: credential references never cross those surfaces.

use hartevo_browser_adapter::{
    BrowserControlState, BrowserControlTransition, BrowserProfile, BrowserProfileSource,
    BrowserProfileStatus, BrowserWorkspace,
};
use hartevo_domain_kernel::{BrowserProfileId, BrowserWorkspaceId, MissionId, ProjectId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn create_browser_profile_atomic(
        &mut self,
        profile: &BrowserProfile,
    ) -> Result<AtomicMutation, StorageError> {
        profile.validate()?;
        if profile.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(profile.revision));
        }
        match load_browser_profile_record(&self.connection, &profile.project_id, &profile.id)? {
            Some(stored) if stored == *profile => return Ok(idempotent(profile.revision)),
            Some(_) => {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser profile",
                    id: profile.id.to_string(),
                });
            }
            None => {}
        }

        let transaction = self.connection.transaction()?;
        ensure_project_tenant(
            &transaction,
            &profile.project_id,
            profile.tenant_id.as_str(),
        )?;
        insert_browser_profile(&transaction, profile)?;
        let event = browser_profile_event("browser.profile_created", profile)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            profile.tenant_id.as_str(),
            profile.project_id.as_str(),
            None,
            "browser_profile",
            profile.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: profile.revision,
        })
    }

    pub fn update_browser_profile_atomic(
        &mut self,
        profile: &BrowserProfile,
        expected_revision: u64,
    ) -> Result<AtomicMutation, StorageError> {
        profile.validate()?;
        let previous = self.load_browser_profile(&profile.project_id, &profile.id)?;
        if previous == *profile && profile.revision == expected_revision.saturating_add(1) {
            return Ok(idempotent(profile.revision));
        }
        if previous.revision != expected_revision || !profile.is_valid_successor_of(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("browser_profile:{}", profile.id),
                expected_revision,
            });
        }

        let transaction = self.connection.transaction()?;
        update_browser_profile(&transaction, profile, expected_revision)?;
        let event = browser_profile_event("browser.profile_updated", profile)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            profile.tenant_id.as_str(),
            profile.project_id.as_str(),
            None,
            "browser_profile",
            profile.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: profile.revision,
        })
    }

    pub fn load_browser_profile(
        &self,
        project_id: &ProjectId,
        profile_id: &BrowserProfileId,
    ) -> Result<BrowserProfile, StorageError> {
        load_browser_profile_record(&self.connection, project_id, profile_id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "browser profile",
                project_id: project_id.clone(),
                id: profile_id.to_string(),
            }
        })
    }

    /// Returns the Project's Browser Profiles by stable id. Every record is
    /// reloaded through the existing full projection-integrity checks.
    pub fn list_browser_profiles(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<BrowserProfile>, StorageError> {
        self.load_project(project_id)?;
        let profile_ids = {
            let mut statement = self
                .connection
                .prepare("SELECT id FROM browser_profiles WHERE project_id = ?1 ORDER BY id")?;
            statement
                .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        profile_ids
            .into_iter()
            .map(|id| self.load_browser_profile(project_id, &BrowserProfileId::from_stable(id)))
            .collect()
    }

    pub fn create_browser_workspace_atomic(
        &mut self,
        workspace: &BrowserWorkspace,
    ) -> Result<AtomicMutation, StorageError> {
        workspace.validate()?;
        if workspace.revision != 1
            || workspace.lease_generation != 1
            || workspace.control_history.len() != 1
        {
            return Err(StorageError::InvalidInitialRevision(workspace.revision));
        }
        match load_browser_workspace_record(&self.connection, &workspace.project_id, &workspace.id)?
        {
            Some(stored) if stored == *workspace => return Ok(idempotent(workspace.revision)),
            Some(_) => {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "browser workspace",
                    id: workspace.id.to_string(),
                });
            }
            None => {}
        }

        let transaction = self.connection.transaction()?;
        validate_workspace_scope(&transaction, workspace)?;
        require_no_live_workspace_for_mission(&transaction, workspace)?;
        insert_browser_workspace(&transaction, workspace)?;
        replace_workspace_tabs(&transaction, workspace)?;
        insert_control_transition(
            &transaction,
            workspace,
            workspace
                .control_history
                .first()
                .ok_or_else(|| StorageError::DomainDecode("missing browser history".into()))?,
        )?;
        let event = browser_workspace_event("browser.workspace_created", workspace)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            workspace.tenant_id.as_str(),
            workspace.project_id.as_str(),
            Some(workspace.mission_id.as_str()),
            "browser_workspace",
            workspace.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: workspace.revision,
        })
    }

    pub fn update_browser_workspace_atomic(
        &mut self,
        workspace: &BrowserWorkspace,
        expected_revision: u64,
    ) -> Result<AtomicMutation, StorageError> {
        workspace.validate()?;
        let previous = self.load_browser_workspace(&workspace.project_id, &workspace.id)?;
        if previous == *workspace && workspace.revision == expected_revision.saturating_add(1) {
            return Ok(idempotent(workspace.revision));
        }
        if previous.revision != expected_revision || !workspace.is_valid_successor_of(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("browser_workspace:{}", workspace.id),
                expected_revision,
            });
        }

        let transaction = self.connection.transaction()?;
        validate_workspace_scope(&transaction, workspace)?;
        update_browser_workspace(&transaction, workspace, expected_revision)?;
        replace_workspace_tabs(&transaction, workspace)?;
        if workspace.control_history.len() == previous.control_history.len() + 1 {
            insert_control_transition(
                &transaction,
                workspace,
                workspace.control_history.last().ok_or_else(|| {
                    StorageError::DomainDecode("missing browser transition".into())
                })?,
            )?;
        }
        let event = browser_workspace_event("browser.workspace_updated", workspace)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            workspace.tenant_id.as_str(),
            workspace.project_id.as_str(),
            Some(workspace.mission_id.as_str()),
            "browser_workspace",
            workspace.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: workspace.revision,
        })
    }

    pub fn load_browser_workspace(
        &self,
        project_id: &ProjectId,
        workspace_id: &BrowserWorkspaceId,
    ) -> Result<BrowserWorkspace, StorageError> {
        let workspace = load_browser_workspace_record(&self.connection, project_id, workspace_id)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "browser workspace",
                project_id: project_id.clone(),
                id: workspace_id.to_string(),
            })?;
        let profile = self.load_browser_profile(project_id, &workspace.profile_id)?;
        if profile.status != BrowserProfileStatus::Active
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        Ok(workspace)
    }

    /// Loads the single live Browser Workspace bound to one Project/Mission.
    ///
    /// Duplicate live rows or a projection/Mission mismatch fail closed rather
    /// than inventing a workspace. Closed/completed workspaces are ignored so
    /// callers can honestly report EMPTY.
    pub fn load_live_browser_workspace_for_mission(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Option<BrowserWorkspace>, StorageError> {
        self.load_project(project_id)?;
        self.load_mission(project_id, mission_id)?;
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT id FROM browser_workspaces
                 WHERE project_id = ?1 AND mission_id = ?2
                   AND control_state NOT IN ('completed', 'kept_for_user', 'closed')
                 ORDER BY updated_at DESC, id",
            )?;
            statement
                .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        match ids.as_slice() {
            [] => Ok(None),
            [id] => {
                let workspace =
                    self.load_browser_workspace(project_id, &BrowserWorkspaceId::from_stable(id))?;
                if workspace.mission_id != *mission_id {
                    return Err(StorageError::TenantScopeMismatch);
                }
                Ok(Some(workspace))
            }
            _ => Err(StorageError::ImmutableRecordMismatch {
                kind: "browser workspace mission scope",
                id: mission_id.to_string(),
            }),
        }
    }
}

fn idempotent(state_revision: u64) -> AtomicMutation {
    AtomicMutation {
        event_sequences: Vec::new(),
        outbox_sequences: Vec::new(),
        state_revision,
    }
}

fn ensure_project_tenant(
    connection: &Connection,
    project_id: &ProjectId,
    tenant_id: &str,
) -> Result<(), StorageError> {
    let stored_tenant = connection
        .query_row(
            "SELECT tenant_id FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))?;
    if stored_tenant != tenant_id {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn validate_workspace_scope(
    connection: &Connection,
    workspace: &BrowserWorkspace,
) -> Result<(), StorageError> {
    ensure_project_tenant(
        connection,
        &workspace.project_id,
        workspace.tenant_id.as_str(),
    )?;
    let mission_tenant = connection
        .query_row(
            "SELECT tenant_id FROM missions WHERE id = ?1 AND project_id = ?2",
            params![workspace.mission_id.as_str(), workspace.project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::MissionNotFound {
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
        })?;
    let profile =
        load_browser_profile_record(connection, &workspace.project_id, &workspace.profile_id)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "browser profile",
                project_id: workspace.project_id.clone(),
                id: workspace.profile_id.to_string(),
            })?;
    if mission_tenant != workspace.tenant_id.as_str()
        || profile.status != BrowserProfileStatus::Active
        || profile.tenant_id != workspace.tenant_id
        || profile.project_id != workspace.project_id
        || profile.identity.identity_digest != workspace.expected_identity_digest
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn require_no_live_workspace_for_mission(
    connection: &Connection,
    workspace: &BrowserWorkspace,
) -> Result<(), StorageError> {
    let live_count = connection.query_row(
        "SELECT COUNT(*) FROM browser_workspaces
         WHERE project_id = ?1 AND mission_id = ?2
           AND control_state NOT IN ('completed', 'kept_for_user', 'closed')",
        params![workspace.project_id.as_str(), workspace.mission_id.as_str()],
        |row| row.get::<_, i64>(0),
    )?;
    if live_count != 0 {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser workspace mission scope",
            id: workspace.mission_id.to_string(),
        });
    }
    Ok(())
}

fn insert_browser_profile(
    transaction: &Transaction<'_>,
    profile: &BrowserProfile,
) -> Result<(), StorageError> {
    let record_digest = profile.digest()?;
    transaction.execute(
        "INSERT INTO browser_profiles
           (tenant_id, project_id, id, source, status, credential_reference_digest,
            provider_digest, account_id_digest, identity_digest, probe_digest,
            identity_observed_at, revocation_evidence_digest, revision, created_at,
            updated_at, record_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17)",
        profile_params(profile, &record_digest)?,
    )?;
    Ok(())
}

fn update_browser_profile(
    transaction: &Transaction<'_>,
    profile: &BrowserProfile,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let record_digest = profile.digest()?;
    let updated = transaction.execute(
        "UPDATE browser_profiles SET
           status = ?5, revocation_evidence_digest = ?12, revision = ?13,
           updated_at = ?15, record_digest = ?16, record_json = ?17
         WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3 AND revision = ?18",
        rusqlite::params_from_iter(
            profile_param_values(profile, &record_digest)?
                .into_iter()
                .chain([rusqlite::types::Value::Integer(to_sql_u64(
                    expected_revision,
                )?)]),
        ),
    )?;
    require_cas(
        updated,
        format!("browser_profile:{}", profile.id),
        expected_revision,
    )
}

fn profile_params<'a>(
    profile: &'a BrowserProfile,
    record_digest: &'a str,
) -> Result<impl rusqlite::Params + 'a, StorageError> {
    Ok(rusqlite::params_from_iter(profile_param_values(
        profile,
        record_digest,
    )?))
}

fn profile_param_values(
    profile: &BrowserProfile,
    record_digest: &str,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        profile.tenant_id.to_string().into(),
        profile.project_id.to_string().into(),
        profile.id.to_string().into(),
        profile_source_name(profile.source).to_owned().into(),
        profile_status_name(profile.status).to_owned().into(),
        digest_identity(&profile.credential_reference).into(),
        digest_identity(&profile.identity.provider).into(),
        digest_identity(profile.identity.account_id.as_str()).into(),
        profile.identity.identity_digest.clone().into(),
        profile.identity.probe_digest.clone().into(),
        profile.identity.observed_at.to_rfc3339().into(),
        profile.revocation_evidence_digest.clone().into(),
        to_sql_u64(profile.revision)?.into(),
        profile.created_at.to_rfc3339().into(),
        profile.updated_at.to_rfc3339().into(),
        record_digest.to_owned().into(),
        serde_json::to_string(profile)?.into(),
    ])
}

fn load_browser_profile_record(
    connection: &Connection,
    project_id: &ProjectId,
    profile_id: &BrowserProfileId,
) -> Result<Option<BrowserProfile>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, source, status, credential_reference_digest,
                    provider_digest, account_id_digest, identity_digest, probe_digest,
                    identity_observed_at, revocation_evidence_digest, revision,
                    created_at, updated_at, record_digest, record_json
             FROM browser_profiles WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), profile_id.as_str()],
            |row| {
                Ok(ProfileProjection {
                    tenant_id: row.get(0)?,
                    source: row.get(1)?,
                    status: row.get(2)?,
                    credential_reference_digest: row.get(3)?,
                    provider_digest: row.get(4)?,
                    account_id_digest: row.get(5)?,
                    identity_digest: row.get(6)?,
                    probe_digest: row.get(7)?,
                    identity_observed_at: row.get(8)?,
                    revocation_evidence_digest: row.get(9)?,
                    revision: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                    record_digest: row.get(13)?,
                    record_json: row.get(14)?,
                })
            },
        )
        .optional()?;
    row.as_ref()
        .map(|projection| decode_profile(project_id, profile_id, projection))
        .transpose()
}

#[derive(Eq, PartialEq)]
struct ProfileProjection {
    tenant_id: String,
    source: String,
    status: String,
    credential_reference_digest: String,
    provider_digest: String,
    account_id_digest: String,
    identity_digest: String,
    probe_digest: String,
    identity_observed_at: String,
    revocation_evidence_digest: Option<String>,
    revision: i64,
    created_at: String,
    updated_at: String,
    record_digest: String,
    record_json: String,
}

fn decode_profile(
    project_id: &ProjectId,
    profile_id: &BrowserProfileId,
    projection: &ProfileProjection,
) -> Result<BrowserProfile, StorageError> {
    let profile: BrowserProfile = serde_json::from_str(&projection.record_json)?;
    profile.validate()?;
    let expected = ProfileProjection {
        tenant_id: profile.tenant_id.to_string(),
        source: profile_source_name(profile.source).into(),
        status: profile_status_name(profile.status).into(),
        credential_reference_digest: digest_identity(&profile.credential_reference),
        provider_digest: digest_identity(&profile.identity.provider),
        account_id_digest: digest_identity(profile.identity.account_id.as_str()),
        identity_digest: profile.identity.identity_digest.clone(),
        probe_digest: profile.identity.probe_digest.clone(),
        identity_observed_at: profile.identity.observed_at.to_rfc3339(),
        revocation_evidence_digest: profile.revocation_evidence_digest.clone(),
        revision: to_sql_u64(profile.revision)?,
        created_at: profile.created_at.to_rfc3339(),
        updated_at: profile.updated_at.to_rfc3339(),
        record_digest: profile.digest()?,
        record_json: projection.record_json.clone(),
    };
    if profile.project_id != *project_id || profile.id != *profile_id || *projection != expected {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser profile projection",
            id: profile_id.to_string(),
        });
    }
    Ok(profile)
}

fn insert_browser_workspace(
    transaction: &Transaction<'_>,
    workspace: &BrowserWorkspace,
) -> Result<(), StorageError> {
    let record_digest = workspace.digest()?;
    transaction.execute(
        "INSERT INTO browser_workspaces
           (tenant_id, project_id, id, mission_id, profile_id, expected_identity_digest,
            control_state, lease_id_digest, lease_generation, agent_lease_expires_at,
            active_tab_id_digest, tab_count, revision, created_at, updated_at,
            record_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17)",
        rusqlite::params_from_iter(workspace_param_values(workspace, &record_digest)?),
    )?;
    Ok(())
}

fn update_browser_workspace(
    transaction: &Transaction<'_>,
    workspace: &BrowserWorkspace,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let record_digest = workspace.digest()?;
    let updated = transaction.execute(
        "UPDATE browser_workspaces SET
           control_state = ?7, lease_id_digest = ?8, lease_generation = ?9,
           agent_lease_expires_at = ?10, active_tab_id_digest = ?11,
           tab_count = ?12, revision = ?13, updated_at = ?15,
           record_digest = ?16, record_json = ?17
         WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3 AND revision = ?18",
        rusqlite::params_from_iter(
            workspace_param_values(workspace, &record_digest)?
                .into_iter()
                .chain([rusqlite::types::Value::Integer(to_sql_u64(
                    expected_revision,
                )?)]),
        ),
    )?;
    require_cas(
        updated,
        format!("browser_workspace:{}", workspace.id),
        expected_revision,
    )
}

fn workspace_param_values(
    workspace: &BrowserWorkspace,
    record_digest: &str,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        workspace.tenant_id.to_string().into(),
        workspace.project_id.to_string().into(),
        workspace.id.to_string().into(),
        workspace.mission_id.to_string().into(),
        workspace.profile_id.to_string().into(),
        workspace.expected_identity_digest.clone().into(),
        control_state_name(workspace.control_state)
            .to_owned()
            .into(),
        digest_identity(workspace.lease_id.as_str()).into(),
        to_sql_u64(workspace.lease_generation)?.into(),
        workspace
            .agent_lease_expires_at
            .map(|value| value.to_rfc3339())
            .into(),
        digest_identity(workspace.active_tab_id.as_str()).into(),
        to_sql_usize(workspace.tabs.len())?.into(),
        to_sql_u64(workspace.revision)?.into(),
        workspace.created_at.to_rfc3339().into(),
        workspace.updated_at.to_rfc3339().into(),
        record_digest.to_owned().into(),
        serde_json::to_string(workspace)?.into(),
    ])
}

fn replace_workspace_tabs(
    transaction: &Transaction<'_>,
    workspace: &BrowserWorkspace,
) -> Result<(), StorageError> {
    transaction.execute(
        "DELETE FROM browser_workspace_tabs WHERE project_id = ?1 AND workspace_id = ?2",
        params![workspace.project_id.as_str(), workspace.id.as_str()],
    )?;
    for (ordinal, tab_id) in workspace.tabs.iter().enumerate() {
        transaction.execute(
            "INSERT INTO browser_workspace_tabs
               (tenant_id, project_id, workspace_id, tab_id, tab_id_digest, ordinal, is_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                workspace.tenant_id.as_str(),
                workspace.project_id.as_str(),
                workspace.id.as_str(),
                tab_id.as_str(),
                digest_identity(tab_id.as_str()),
                to_sql_usize(ordinal)?,
                i64::from(tab_id == &workspace.active_tab_id),
            ],
        )?;
    }
    Ok(())
}

fn insert_control_transition(
    transaction: &Transaction<'_>,
    workspace: &BrowserWorkspace,
    transition: &BrowserControlTransition,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO browser_control_transitions
           (tenant_id, project_id, workspace_id, generation, lease_id_digest,
            control_state, evidence_digest, agent_lease_expires_at, occurred_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            workspace.tenant_id.as_str(),
            workspace.project_id.as_str(),
            workspace.id.as_str(),
            to_sql_u64(transition.generation)?,
            digest_identity(transition.lease_id.as_str()),
            control_state_name(transition.state),
            transition.evidence_digest,
            transition
                .agent_lease_expires_at
                .map(|value| value.to_rfc3339()),
            transition.occurred_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn load_browser_workspace_record(
    connection: &Connection,
    project_id: &ProjectId,
    workspace_id: &BrowserWorkspaceId,
) -> Result<Option<BrowserWorkspace>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, mission_id, profile_id, expected_identity_digest,
                    control_state, lease_id_digest, lease_generation, agent_lease_expires_at,
                    active_tab_id_digest, tab_count, revision, created_at, updated_at,
                    record_digest, record_json
             FROM browser_workspaces WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), workspace_id.as_str()],
            |row| {
                Ok(WorkspaceProjection {
                    tenant_id: row.get(0)?,
                    mission_id: row.get(1)?,
                    profile_id: row.get(2)?,
                    expected_identity_digest: row.get(3)?,
                    control_state: row.get(4)?,
                    lease_id_digest: row.get(5)?,
                    lease_generation: row.get(6)?,
                    agent_lease_expires_at: row.get(7)?,
                    active_tab_id_digest: row.get(8)?,
                    tab_count: row.get(9)?,
                    revision: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                    record_digest: row.get(13)?,
                    record_json: row.get(14)?,
                })
            },
        )
        .optional()?;
    let Some(projection) = row else {
        return Ok(None);
    };
    let workspace: BrowserWorkspace = serde_json::from_str(&projection.record_json)?;
    workspace.validate()?;
    let expected = WorkspaceProjection {
        tenant_id: workspace.tenant_id.to_string(),
        mission_id: workspace.mission_id.to_string(),
        profile_id: workspace.profile_id.to_string(),
        expected_identity_digest: workspace.expected_identity_digest.clone(),
        control_state: control_state_name(workspace.control_state).into(),
        lease_id_digest: digest_identity(workspace.lease_id.as_str()),
        lease_generation: to_sql_u64(workspace.lease_generation)?,
        agent_lease_expires_at: workspace
            .agent_lease_expires_at
            .map(|value| value.to_rfc3339()),
        active_tab_id_digest: digest_identity(workspace.active_tab_id.as_str()),
        tab_count: to_sql_usize(workspace.tabs.len())?,
        revision: to_sql_u64(workspace.revision)?,
        created_at: workspace.created_at.to_rfc3339(),
        updated_at: workspace.updated_at.to_rfc3339(),
        record_digest: workspace.digest()?,
        record_json: projection.record_json.clone(),
    };
    if workspace.project_id != *project_id
        || workspace.id != *workspace_id
        || projection != expected
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser workspace projection",
            id: workspace_id.to_string(),
        });
    }
    validate_workspace_tab_projection(connection, &workspace)?;
    validate_control_transition_projection(connection, &workspace)?;
    Ok(Some(workspace))
}

#[derive(Eq, PartialEq)]
struct WorkspaceProjection {
    tenant_id: String,
    mission_id: String,
    profile_id: String,
    expected_identity_digest: String,
    control_state: String,
    lease_id_digest: String,
    lease_generation: i64,
    agent_lease_expires_at: Option<String>,
    active_tab_id_digest: String,
    tab_count: i64,
    revision: i64,
    created_at: String,
    updated_at: String,
    record_digest: String,
    record_json: String,
}

fn validate_workspace_tab_projection(
    connection: &Connection,
    workspace: &BrowserWorkspace,
) -> Result<(), StorageError> {
    let stored = {
        let mut statement = connection.prepare(
            "SELECT tab_id, tab_id_digest, ordinal, is_active
             FROM browser_workspace_tabs
             WHERE project_id = ?1 AND workspace_id = ?2 ORDER BY ordinal",
        )?;
        statement
            .query_map(
                params![workspace.project_id.as_str(), workspace.id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let expected = workspace
        .tabs
        .iter()
        .enumerate()
        .map(|(ordinal, tab_id)| {
            Ok((
                tab_id.to_string(),
                digest_identity(tab_id.as_str()),
                to_sql_usize(ordinal)?,
                i64::from(tab_id == &workspace.active_tab_id),
            ))
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    if stored != expected {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser workspace tab projection",
            id: workspace.id.to_string(),
        });
    }
    Ok(())
}

fn validate_control_transition_projection(
    connection: &Connection,
    workspace: &BrowserWorkspace,
) -> Result<(), StorageError> {
    let stored = {
        let mut statement = connection.prepare(
            "SELECT generation, lease_id_digest, control_state, evidence_digest,
                    agent_lease_expires_at, occurred_at
             FROM browser_control_transitions
             WHERE project_id = ?1 AND workspace_id = ?2 ORDER BY generation",
        )?;
        statement
            .query_map(
                params![workspace.project_id.as_str(), workspace.id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let expected = workspace
        .control_history
        .iter()
        .map(|transition| {
            Ok((
                to_sql_u64(transition.generation)?,
                digest_identity(transition.lease_id.as_str()),
                control_state_name(transition.state).into(),
                transition.evidence_digest.clone(),
                transition
                    .agent_lease_expires_at
                    .map(|value| value.to_rfc3339()),
                transition.occurred_at.to_rfc3339(),
            ))
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    if stored != expected {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "browser control transition projection",
            id: workspace.id.to_string(),
        });
    }
    Ok(())
}

fn browser_profile_event(
    event_type: &str,
    profile: &BrowserProfile,
) -> Result<PendingEvent, StorageError> {
    Ok(PendingEvent::new(
        event_type,
        serde_json::json!({
            "profileId": profile.id,
            "profileDigest": profile.digest()?,
            "source": profile.source,
            "status": profile.status,
            "providerDigest": digest_identity(&profile.identity.provider),
            "accountIdDigest": digest_identity(profile.identity.account_id.as_str()),
            "identityDigest": profile.identity.identity_digest,
            "probeDigest": profile.identity.probe_digest,
            "revision": profile.revision,
        }),
        profile.updated_at,
    ))
}

fn browser_workspace_event(
    event_type: &str,
    workspace: &BrowserWorkspace,
) -> Result<PendingEvent, StorageError> {
    let latest = workspace
        .control_history
        .last()
        .ok_or_else(|| StorageError::DomainDecode("missing browser transition".into()))?;
    Ok(PendingEvent::new(
        event_type,
        serde_json::json!({
            "workspaceId": workspace.id,
            "workspaceDigest": workspace.digest()?,
            "profileIdDigest": digest_identity(workspace.profile_id.as_str()),
            "expectedIdentityDigest": workspace.expected_identity_digest,
            "controlState": workspace.control_state,
            "leaseIdDigest": digest_identity(workspace.lease_id.as_str()),
            "leaseGeneration": workspace.lease_generation,
            "controlEvidenceDigest": latest.evidence_digest,
            "activeTabIdDigest": digest_identity(workspace.active_tab_id.as_str()),
            "tabCount": workspace.tabs.len(),
            "revision": workspace.revision,
        }),
        workspace.updated_at,
    ))
}

fn profile_source_name(source: BrowserProfileSource) -> &'static str {
    match source {
        BrowserProfileSource::Managed => "managed",
        BrowserProfileSource::ImportedCopy => "imported_copy",
    }
}

fn profile_status_name(status: BrowserProfileStatus) -> &'static str {
    match status {
        BrowserProfileStatus::Active => "active",
        BrowserProfileStatus::Revoked => "revoked",
    }
}

fn control_state_name(state: BrowserControlState) -> &'static str {
    match state {
        BrowserControlState::AgentControlled => "agent_controlled",
        BrowserControlState::UserControlled => "user_controlled",
        BrowserControlState::PausedAgent => "paused_agent",
        BrowserControlState::PausedUser => "paused_user",
        BrowserControlState::Completed => "completed",
        BrowserControlState::KeptForUser => "kept_for_user",
        BrowserControlState::Closed => "closed",
    }
}

fn digest_identity(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn to_sql_usize(value: usize) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(u64::MAX))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn require_cas(
    updated: usize,
    aggregate: String,
    expected_revision: u64,
) -> Result<(), StorageError> {
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate,
            expected_revision,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use hartevo_browser_adapter::{BrowserIdentity, BrowserProfile};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, BrowserTabId, BrowserWorkspaceId,
        Mission, MissionContract, MissionId, Project, StorageMode, TenantId,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::{DatabaseKey, STORAGE_SCHEMA_VERSION};

    const CREDENTIAL_REFERENCE: &str =
        "keychain://PRIVATE-BROWSER-CREDENTIAL-REFERENCE/profile-storage";

    struct Fixture {
        store: ProjectStore,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 9, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn project_and_mission() -> (Project, Mission) {
        let project = Project::create_local(
            TenantId::from("tenant-browser-storage"),
            ProjectId::from("project-browser-storage"),
            "Browser persistence",
            "",
            "/workspace/browser-storage",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-browser-storage"),
            project.id.clone(),
            "Browser persistence",
            MissionContract::bootstrap("Persist browser controls", ["browser.read".into()], now()),
            now(),
        )
        .expect("mission");
        (project, mission)
    }

    fn fixture() -> Fixture {
        let (project, mission) = project_and_mission();
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-browser-storage"),
            &project,
            CREDENTIAL_REFERENCE,
            BrowserIdentity::new(
                "fixture-provider",
                AccountId::from("account-browser-storage"),
                sha('1'),
                sha('2'),
                now(),
            )
            .expect("identity"),
            now(),
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-browser-storage"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-browser-storage"),
            BrowserControlLeaseId::from("lease-browser-storage-1"),
            now() + Duration::hours(1),
            sha('3'),
            now(),
        )
        .expect("workspace");
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("save project");
        store.save_mission(&mission).expect("save mission");
        Fixture {
            store,
            profile,
            workspace,
        }
    }

    fn persist_fixture(fixture: &mut Fixture) {
        fixture
            .store
            .create_browser_profile_atomic(&fixture.profile)
            .expect("profile mutation");
        fixture
            .store
            .create_browser_workspace_atomic(&fixture.workspace)
            .expect("workspace mutation");
    }

    #[test]
    fn encrypted_record_is_recoverable_while_events_and_projections_are_content_free() {
        let mut fixture = fixture();
        let profile_mutation = fixture
            .store
            .create_browser_profile_atomic(&fixture.profile)
            .expect("profile");
        let workspace_mutation = fixture
            .store
            .create_browser_workspace_atomic(&fixture.workspace)
            .expect("workspace");
        assert_eq!(profile_mutation.event_sequences.len(), 1);
        assert_eq!(profile_mutation.outbox_sequences.len(), 1);
        assert_eq!(workspace_mutation.event_sequences.len(), 1);
        assert_eq!(workspace_mutation.outbox_sequences.len(), 1);
        assert_eq!(
            fixture
                .store
                .load_browser_profile(&fixture.profile.project_id, &fixture.profile.id)
                .expect("load profile"),
            fixture.profile
        );
        assert_eq!(
            fixture
                .store
                .load_browser_workspace(&fixture.workspace.project_id, &fixture.workspace.id)
                .expect("load workspace"),
            fixture.workspace
        );

        let persisted = fixture
            .store
            .connection
            .query_row(
                "SELECT credential_reference_digest, provider_digest, account_id_digest,
                        record_json FROM browser_profiles WHERE project_id = ?1 AND id = ?2",
                params![
                    fixture.profile.project_id.as_str(),
                    fixture.profile.id.as_str()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .expect("profile row");
        assert_eq!(persisted.0, digest_identity(CREDENTIAL_REFERENCE));
        assert_eq!(persisted.1, digest_identity("fixture-provider"));
        assert_eq!(persisted.2, digest_identity("account-browser-storage"));
        assert!(persisted.3.contains(CREDENTIAL_REFERENCE));

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
        assert!(!audit_payloads.contains(CREDENTIAL_REFERENCE));
        assert!(!audit_payloads.contains("account-browser-storage"));
        assert!(!audit_payloads.contains("fixture-provider"));
        assert!(!audit_payloads.contains("lease-browser-storage-1"));
        assert!(audit_payloads.contains(&fixture.profile.digest().expect("profile digest")));
    }

    #[test]
    fn profile_inventory_is_project_scoped_and_integrity_checked() {
        let mut fixture = fixture();
        fixture
            .store
            .create_browser_profile_atomic(&fixture.profile)
            .expect("profile");

        assert_eq!(
            fixture
                .store
                .list_browser_profiles(&fixture.profile.project_id)
                .expect("profile inventory"),
            vec![fixture.profile.clone()]
        );

        fixture
            .store
            .connection
            .execute(
                "UPDATE browser_profiles SET identity_digest = ?3
                 WHERE project_id = ?1 AND id = ?2",
                params![
                    fixture.profile.project_id.as_str(),
                    fixture.profile.id.as_str(),
                    sha('9')
                ],
            )
            .expect("tamper profile projection");
        assert!(matches!(
            fixture
                .store
                .list_browser_profiles(&fixture.profile.project_id),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "browser profile projection",
                ..
            })
        ));
    }

    #[test]
    fn takeover_update_is_cas_append_only_and_idempotently_replayable() {
        let mut fixture = fixture();
        persist_fixture(&mut fixture);
        let old_lease = fixture.workspace.lease_id.to_string();
        fixture
            .workspace
            .user_takeover(
                1,
                1,
                BrowserControlLeaseId::from("lease-browser-storage-2"),
                sha('4'),
                now() + Duration::seconds(1),
            )
            .expect("takeover");
        let mutation = fixture
            .store
            .update_browser_workspace_atomic(&fixture.workspace, 1)
            .expect("persist takeover");
        assert_eq!(mutation.state_revision, 2);
        assert_eq!(
            fixture
                .store
                .load_browser_workspace(&fixture.workspace.project_id, &fixture.workspace.id)
                .expect("load takeover"),
            fixture.workspace
        );
        let transition_count = fixture
            .store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM browser_control_transitions
                 WHERE project_id = ?1 AND workspace_id = ?2",
                params![
                    fixture.workspace.project_id.as_str(),
                    fixture.workspace.id.as_str()
                ],
                |row| row.get::<_, i64>(0),
            )
            .expect("transition count");
        assert_eq!(transition_count, 2);
        let lease_digests = {
            let mut statement = fixture
                .store
                .connection
                .prepare(
                    "SELECT lease_id_digest FROM browser_control_transitions
                     WHERE project_id = ?1 AND workspace_id = ?2 ORDER BY generation",
                )
                .expect("prepare");
            statement
                .query_map(
                    params![
                        fixture.workspace.project_id.as_str(),
                        fixture.workspace.id.as_str()
                    ],
                    |row| row.get::<_, String>(0),
                )
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("digests")
        };
        assert_eq!(lease_digests[0], digest_identity(&old_lease));
        assert_eq!(lease_digests[1], digest_identity("lease-browser-storage-2"));
        assert!(!lease_digests.iter().any(|value| value == &old_lease));

        let replay = fixture
            .store
            .update_browser_workspace_atomic(&fixture.workspace, 1)
            .expect("idempotent replay");
        assert!(replay.event_sequences.is_empty());
        assert!(replay.outbox_sequences.is_empty());
        assert_eq!(transition_count, 2);
    }

    #[test]
    fn outbox_failure_rolls_back_workspace_transition_and_event() {
        let mut fixture = fixture();
        persist_fixture(&mut fixture);
        let previous = fixture.workspace.clone();
        fixture
            .workspace
            .user_takeover(
                1,
                1,
                BrowserControlLeaseId::from("lease-browser-storage-2"),
                sha('4'),
                now() + Duration::seconds(1),
            )
            .expect("takeover");
        fixture
            .store
            .connection
            .execute_batch(
                "CREATE TRIGGER browser_test_abort_outbox
                 BEFORE INSERT ON outbox_messages
                 WHEN NEW.aggregate_type = 'browser_workspace'
                 BEGIN SELECT RAISE(ABORT, 'browser outbox failure'); END;",
            )
            .expect("failure trigger");

        assert!(
            fixture
                .store
                .update_browser_workspace_atomic(&fixture.workspace, 1)
                .is_err()
        );
        assert_eq!(
            fixture
                .store
                .load_browser_workspace(&previous.project_id, &previous.id)
                .expect("rollback load"),
            previous
        );
        let transition_count = fixture
            .store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM browser_control_transitions
                 WHERE project_id = ?1 AND workspace_id = ?2",
                params![previous.project_id.as_str(), previous.id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .expect("transition count");
        assert_eq!(transition_count, 1);
        let update_event_count = fixture
            .store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM domain_events
                 WHERE event_type = 'browser.workspace_updated'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("event count");
        assert_eq!(update_event_count, 0);
    }

    #[test]
    fn projection_tampering_fails_closed_on_reload() {
        let mut fixture = fixture();
        persist_fixture(&mut fixture);
        fixture
            .store
            .connection
            .execute(
                "UPDATE browser_control_transitions SET evidence_digest = ?3
                 WHERE project_id = ?1 AND workspace_id = ?2 AND generation = 1",
                params![
                    fixture.workspace.project_id.as_str(),
                    fixture.workspace.id.as_str(),
                    sha('9')
                ],
            )
            .expect("tamper transition");

        assert!(matches!(
            fixture
                .store
                .load_browser_workspace(&fixture.workspace.project_id, &fixture.workspace.id),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "browser control transition projection",
                ..
            })
        ));
    }

    #[test]
    fn revoked_profile_makes_linked_workspace_fail_closed() {
        let mut fixture = fixture();
        persist_fixture(&mut fixture);
        fixture
            .profile
            .revoke(1, sha('4'), now() + Duration::seconds(1))
            .expect("revoke");
        fixture
            .store
            .update_browser_profile_atomic(&fixture.profile, 1)
            .expect("persist revoke");
        assert_eq!(
            fixture
                .store
                .load_browser_profile(&fixture.profile.project_id, &fixture.profile.id)
                .expect("revoked profile"),
            fixture.profile
        );
        assert!(matches!(
            fixture
                .store
                .load_browser_workspace(&fixture.workspace.project_id, &fixture.workspace.id),
            Err(StorageError::TenantScopeMismatch)
        ));
    }

    #[test]
    fn live_workspace_for_mission_is_absent_until_persisted_and_unique() {
        let mut fixture = fixture();
        assert_eq!(
            fixture
                .store
                .load_live_browser_workspace_for_mission(
                    &fixture.workspace.project_id,
                    &fixture.workspace.mission_id
                )
                .expect("empty live workspace"),
            None
        );
        persist_fixture(&mut fixture);
        let mut replacement = fixture.workspace.clone();
        replacement.id = BrowserWorkspaceId::from("workspace-browser-storage-replacement");
        assert!(matches!(
            fixture.store.create_browser_workspace_atomic(&replacement),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "browser workspace mission scope",
                ..
            })
        ));
        let loaded = fixture
            .store
            .load_live_browser_workspace_for_mission(
                &fixture.workspace.project_id,
                &fixture.workspace.mission_id,
            )
            .expect("live workspace")
            .expect("one Mission-bound workspace");
        assert_eq!(loaded.id, fixture.workspace.id);
        assert_eq!(loaded.mission_id, fixture.workspace.mission_id);
        fixture
            .workspace
            .complete(
                1,
                1,
                BrowserControlLeaseId::from("lease-browser-storage-complete"),
                sha('5'),
                now() + Duration::seconds(1),
            )
            .expect("complete");
        fixture
            .store
            .update_browser_workspace_atomic(&fixture.workspace, 1)
            .expect("persist complete");
        assert_eq!(
            fixture
                .store
                .load_live_browser_workspace_for_mission(
                    &fixture.workspace.project_id,
                    &fixture.workspace.mission_id
                )
                .expect("terminal workspace is not live"),
            None
        );
        fixture
            .store
            .create_browser_workspace_atomic(&replacement)
            .expect("replacement after terminal Workspace");
        assert_eq!(
            fixture
                .store
                .load_live_browser_workspace_for_mission(
                    &replacement.project_id,
                    &replacement.mission_id
                )
                .expect("replacement live Workspace")
                .expect("one replacement Workspace")
                .id,
            replacement.id
        );
    }

    #[test]
    fn workspace_identity_mismatch_is_rejected_before_any_row_or_event() {
        let mut fixture = fixture();
        fixture
            .store
            .create_browser_profile_atomic(&fixture.profile)
            .expect("profile");
        fixture.workspace.expected_identity_digest = sha('9');

        assert!(matches!(
            fixture
                .store
                .create_browser_workspace_atomic(&fixture.workspace),
            Err(StorageError::TenantScopeMismatch)
        ));
        let workspace_count = fixture
            .store
            .connection
            .query_row("SELECT COUNT(*) FROM browser_workspaces", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("workspace count");
        assert_eq!(workspace_count, 0);
    }

    #[test]
    fn migration_v32_backs_up_v31_and_reinstalls_browser_tables_idempotently() {
        let directory = tempdir().expect("tempdir");
        let database_path = directory.path().join("browser-migration.sqlite3");
        let key = DatabaseKey::new([23; 32]).expect("key");
        {
            let mut store = ProjectStore::open(&database_path, &key).expect("current store");
            let (project, mission) = project_and_mission();
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE browser_file_grants;
                     DROP TABLE browser_control_transitions;
                     DROP TABLE browser_workspace_tabs;
                     DROP TABLE browser_workspaces;
                     DROP TABLE browser_profiles;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 32;",
                )
                .expect("construct v31");
        }

        {
            let store = ProjectStore::open(&database_path, &key).expect("migrate v31");
            assert_eq!(
                super::super::current_schema_version(&store.connection).expect("version"),
                STORAGE_SCHEMA_VERSION
            );
            for table in [
                "browser_profiles",
                "browser_workspaces",
                "browser_workspace_tabs",
                "browser_control_transitions",
            ] {
                let exists = store
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master
                         WHERE type = 'table' AND name = ?1",
                        [table],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("table query");
                assert_eq!(exists, 1, "missing {table}");
            }
        }
        let backup_count = std::fs::read_dir(directory.path())
            .expect("list migration directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v31")
            })
            .count();
        assert_eq!(backup_count, 1);

        drop(ProjectStore::open(&database_path, &key).expect("idempotent reopen"));
        let reopened_backup_count = std::fs::read_dir(directory.path())
            .expect("list after reopen")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v31")
            })
            .count();
        assert_eq!(reopened_backup_count, 1);
    }
}

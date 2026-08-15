use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    IdentityAccount, IdentityBootstrapError, IdentityBootstrapSelection, IdentityBootstrapSnapshot,
    IdentityBootstrapState, IdentityDevice, IdentityMembership, IdentityProject, IdentitySession,
    IdentitySessionStatus, IdentityTeam, ProjectId, TeamId, TenantId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::aggregate::append_events;
use crate::identity_store::ensure_project;
use crate::secure_store::SecretReference;
use crate::{AtomicMutation, PendingEvent, ProjectStore, StorageError};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySessionSecretReferences {
    pub access_token: SecretReference,
    pub refresh_token: SecretReference,
    pub device_binding: SecretReference,
}

impl IdentitySessionSecretReferences {
    pub fn validate_for(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        account_id: &str,
        device_id: &str,
        session: &IdentitySession,
        device: &IdentityDevice,
    ) -> Result<(), StorageError> {
        let access_digest = self
            .access_token
            .credential_id()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let refresh_digest = self
            .refresh_token
            .credential_id()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let device_digest = self
            .device_binding
            .credential_id()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if self.access_token.tenant_id != *tenant_id
            || self.access_token.project_id != *project_id
            || self.refresh_token.tenant_id != *tenant_id
            || self.refresh_token.project_id != *project_id
            || self.device_binding.tenant_id != *tenant_id
            || self.device_binding.project_id != *project_id
            || self.access_token.provider != session.provider_id
            || self.refresh_token.provider != session.provider_id
            || self.access_token.account_scope != format!("identity:{account_id}")
            || self.refresh_token.account_scope != format!("identity:{account_id}")
            || self.device_binding.provider != "hartevo"
            || self.device_binding.account_scope != format!("identity:{device_id}")
            || self.access_token.purpose != hartevo_domain_kernel::OIDC_ACCESS_TOKEN_PURPOSE
            || self.refresh_token.purpose != hartevo_domain_kernel::OIDC_REFRESH_TOKEN_PURPOSE
            || self.device_binding.purpose != hartevo_domain_kernel::IDENTITY_DEVICE_BINDING_PURPOSE
            || session.access_secret_reference_digest != access_digest
            || session.refresh_secret_reference_digest != refresh_digest
            || device.binding_secret_reference_digest != device_digest
        {
            return Err(StorageError::IdentityBootstrapScopeMismatch);
        }
        Ok(())
    }
}

impl ProjectStore {
    #[allow(clippy::too_many_arguments)]
    pub fn save_identity_bootstrap_atomic(
        &mut self,
        snapshot: &IdentityBootstrapSnapshot,
        selected_team_id: &TeamId,
        selected_project_id: &ProjectId,
        device: &IdentityDevice,
        session: &IdentitySession,
        references: &IdentitySessionSecretReferences,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        let selection = snapshot
            .select(selected_team_id, selected_project_id)
            .map_err(|error| identity_decode(&error))?;
        session
            .validate()
            .map_err(|error| identity_decode(&error))?;
        validate_selected_scope(&selection, device, session)?;
        references.validate_for(
            &snapshot.account.tenant_id,
            selected_project_id,
            snapshot.account.id.as_str(),
            device.id.as_str(),
            session,
            device,
        )?;
        let transaction = self.connection.transaction()?;
        ensure_project(
            &transaction,
            &snapshot.account.tenant_id,
            selected_project_id,
        )?;

        ensure_or_insert_account(&transaction, &snapshot.account)?;
        for team in &snapshot.teams {
            ensure_or_insert_team(&transaction, team)?;
        }
        for membership in &snapshot.memberships {
            ensure_or_insert_membership(&transaction, membership)?;
        }
        for project in &snapshot.projects {
            ensure_or_insert_project(&transaction, project)?;
        }
        ensure_or_insert_device(&transaction, device, references)?;

        let session_json = serde_json::to_string(session)?;
        let session_digest = json_digest(session)?;
        let existing_session = transaction
            .query_row(
                "SELECT record_digest FROM identity_sessions
                 WHERE project_id = ?1 AND id = ?2",
                params![session.project_id.as_str(), session.id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_digest) = existing_session {
            if existing_digest != session_digest {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "identity_session",
                    id: session.id.to_string(),
                });
            }
            transaction.commit()?;
            return Ok(AtomicMutation {
                event_sequences: Vec::new(),
                outbox_sequences: Vec::new(),
                state_revision: session.revision,
            });
        }
        transaction.execute(
            "INSERT INTO identity_sessions (
               tenant_id, project_id, id, account_id, team_id, member_id, device_id,
               session_json, record_digest, access_secret_reference_json,
               refresh_secret_reference_json, status, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                snapshot.account.tenant_id.as_str(),
                session.project_id.as_str(),
                session.id.as_str(),
                session.account_id.as_str(),
                session.team_id.as_str(),
                session.member_id.as_str(),
                session.device_id.as_str(),
                session_json,
                session_digest,
                serde_json::to_string(&references.access_token)?,
                serde_json::to_string(&references.refresh_token)?,
                serde_json::to_value(session.status)?.as_str(),
                to_sql_u64(session.revision)?,
            ],
        )?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            snapshot.account.tenant_id.as_str(),
            session.project_id.as_str(),
            None,
            "identity_session",
            session.id.as_str(),
            &[PendingEvent::new(event_type, payload.clone(), recorded_at)],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: session.revision,
        })
    }

    pub fn load_identity_session(
        &self,
        project_id: &ProjectId,
        session_id: &hartevo_domain_kernel::IdentitySessionId,
    ) -> Result<IdentitySession, StorageError> {
        self.connection
            .query_row(
                "SELECT tenant_id, project_id, id, account_id, team_id, member_id, device_id,
                        status, session_json, record_digest, revision
                 FROM identity_sessions WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), session_id.as_str()],
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
            .map(decode_session_row)
            .transpose()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "identity_session",
                project_id: project_id.clone(),
                id: session_id.to_string(),
            })
    }

    pub fn load_identity_session_secret_references(
        &self,
        project_id: &ProjectId,
        session_id: &hartevo_domain_kernel::IdentitySessionId,
    ) -> Result<IdentitySessionSecretReferences, StorageError> {
        let session = self.load_identity_session(project_id, session_id)?;
        let row = self.connection.query_row(
            "SELECT access_secret_reference_json, refresh_secret_reference_json
                 FROM identity_sessions WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), session_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        let references = IdentitySessionSecretReferences {
            access_token: serde_json::from_str(&row.0)?,
            refresh_token: serde_json::from_str(&row.1)?,
            device_binding: self.load_identity_device_reference(&session.device_id, project_id)?,
        };
        references.validate_for(
            &session.scope.tenant_id,
            project_id,
            session.account_id.as_str(),
            session.device_id.as_str(),
            &session,
            &self.load_identity_device(project_id, &session.device_id)?,
        )?;
        Ok(references)
    }

    pub fn load_identity_bootstrap_state(
        &self,
        project_id: &ProjectId,
        session_id: &hartevo_domain_kernel::IdentitySessionId,
    ) -> Result<IdentityBootstrapState, StorageError> {
        let session = self.load_identity_session(project_id, session_id)?;
        let account = self.load_identity_account(&session.scope.tenant_id, &session.account_id)?;
        let team = self.load_identity_team(&session.scope.tenant_id, &session.team_id)?;
        let membership =
            self.load_identity_membership(&session.scope.tenant_id, &session.member_id)?;
        let project = self.load_identity_project(&session.scope.tenant_id, project_id)?;
        let device = self.load_identity_device(project_id, &session.device_id)?;
        let selection = IdentityBootstrapSelection {
            account: account.clone(),
            team: team.clone(),
            membership: membership.clone(),
            project: project.clone(),
        };
        validate_selected_scope(&selection, &device, &session)?;
        let state = IdentityBootstrapState {
            account,
            team,
            membership,
            project,
            device,
            session,
        };
        state.validate().map_err(|error| identity_decode(&error))?;
        Ok(state)
    }

    pub fn update_identity_session_atomic(
        &mut self,
        session: &IdentitySession,
        references: &IdentitySessionSecretReferences,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        session
            .validate()
            .map_err(|error| identity_decode(&error))?;
        let previous = self.load_identity_session(&session.project_id, &session.id)?;
        if previous.revision != expected_revision
            || session.revision != expected_revision.saturating_add(1)
            || previous.scope != session.scope
            || previous.account_id != session.account_id
            || previous.team_id != session.team_id
            || previous.member_id != session.member_id
            || previous.project_id != session.project_id
            || previous.device_id != session.device_id
            || previous.provider_id != session.provider_id
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("identity_session:{}", session.id),
                expected_revision,
            });
        }
        let device = self.load_identity_device(&session.project_id, &session.device_id)?;
        references.validate_for(
            &session.scope.tenant_id,
            &session.project_id,
            session.account_id.as_str(),
            session.device_id.as_str(),
            session,
            &device,
        )?;
        let session_json = serde_json::to_string(session)?;
        let session_digest = json_digest(session)?;
        let transaction = self.connection.transaction()?;
        let updated = transaction.execute(
            "UPDATE identity_sessions SET session_json = ?3, record_digest = ?4,
                access_secret_reference_json = ?5, refresh_secret_reference_json = ?6,
                status = ?7, revision = ?8
             WHERE project_id = ?1 AND id = ?2 AND revision = ?9",
            params![
                session.project_id.as_str(),
                session.id.as_str(),
                session_json,
                session_digest,
                serde_json::to_string(&references.access_token)?,
                serde_json::to_string(&references.refresh_token)?,
                serde_json::to_value(session.status)?.as_str(),
                to_sql_u64(session.revision)?,
                to_sql_u64(expected_revision)?,
            ],
        )?;
        if updated != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("identity_session:{}", session.id),
                expected_revision,
            });
        }
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            session.scope.tenant_id.as_str(),
            session.project_id.as_str(),
            None,
            "identity_session",
            session.id.as_str(),
            &[PendingEvent::new(event_type, payload.clone(), recorded_at)],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: session.revision,
        })
    }

    fn load_identity_account(
        &self,
        tenant_id: &TenantId,
        account_id: &hartevo_domain_kernel::AccountId,
    ) -> Result<IdentityAccount, StorageError> {
        load_identity_json_projection(
            &self.connection,
            "SELECT tenant_id, id, NULL, NULL, NULL, record_json, record_digest, revision
             FROM identity_accounts WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id.as_str(), account_id.as_str()],
            "identity account",
            |account: &IdentityAccount, projection| {
                projection.tenant_id == account.tenant_id.as_str()
                    && projection.id == account.id.as_str()
                    && revision_matches(account.revision, projection.revision)
            },
        )
    }

    fn load_identity_team(
        &self,
        tenant_id: &TenantId,
        team_id: &TeamId,
    ) -> Result<IdentityTeam, StorageError> {
        load_identity_json_projection(
            &self.connection,
            "SELECT tenant_id, id, NULL, NULL, NULL, record_json, record_digest, revision
             FROM identity_teams WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id.as_str(), team_id.as_str()],
            "identity team",
            |team: &IdentityTeam, projection| {
                projection.tenant_id == team.tenant_id.as_str()
                    && projection.id == team.id.as_str()
                    && revision_matches(team.revision, projection.revision)
            },
        )
    }

    fn load_identity_membership(
        &self,
        tenant_id: &TenantId,
        member_id: &hartevo_domain_kernel::MemberId,
    ) -> Result<IdentityMembership, StorageError> {
        load_identity_json_projection(
            &self.connection,
            "SELECT tenant_id, id, team_id, account_id, NULL, record_json, record_digest, revision
             FROM identity_memberships WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id.as_str(), member_id.as_str()],
            "identity membership",
            |membership: &IdentityMembership, projection| {
                projection.tenant_id == membership.tenant_id.as_str()
                    && projection.id == membership.id.as_str()
                    && projection.team_id.as_deref() == Some(membership.team_id.as_str())
                    && projection.account_id.as_deref() == Some(membership.account_id.as_str())
                    && revision_matches(membership.revision, projection.revision)
            },
        )
    }

    fn load_identity_project(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
    ) -> Result<IdentityProject, StorageError> {
        load_identity_json_projection(
            &self.connection,
            "SELECT tenant_id, id, team_id, NULL, NULL, record_json, record_digest, revision
             FROM identity_projects WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id.as_str(), project_id.as_str()],
            "identity project",
            |project: &IdentityProject, projection| {
                projection.tenant_id == project.tenant_id.as_str()
                    && projection.id == project.id.as_str()
                    && projection.team_id.as_deref() == Some(project.team_id.as_str())
                    && revision_matches(project.revision, projection.revision)
            },
        )
    }

    fn load_identity_device(
        &self,
        project_id: &ProjectId,
        device_id: &hartevo_domain_kernel::DeviceId,
    ) -> Result<IdentityDevice, StorageError> {
        load_identity_json_projection(
            &self.connection,
            "SELECT tenant_id, id, NULL, account_id, project_id, record_json, record_digest, revision
             FROM identity_devices WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), device_id.as_str()],
            "identity device",
            |device: &IdentityDevice, projection| {
                projection.tenant_id == device.tenant_id.as_str()
                    && projection.id == device.id.as_str()
                    && projection.account_id.as_deref() == Some(device.account_id.as_str())
                    && projection.project_id.as_deref() == Some(device.project_id.as_str())
                    && revision_matches(device.revision, projection.revision)
            },
        )
    }

    fn load_identity_device_reference(
        &self,
        device_id: &hartevo_domain_kernel::DeviceId,
        project_id: &ProjectId,
    ) -> Result<SecretReference, StorageError> {
        self.connection
            .query_row(
                "SELECT binding_secret_reference_json FROM identity_devices
                 WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), device_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .map_err(StorageError::from)
            .and_then(|value| serde_json::from_str(&value).map_err(StorageError::from))
    }
}

fn validate_selected_scope(
    selection: &IdentityBootstrapSelection,
    device: &IdentityDevice,
    session: &IdentitySession,
) -> Result<(), StorageError> {
    if device.tenant_id != selection.account.tenant_id
        || device.account_id != selection.account.id
        || device.project_id != selection.project.id
        || session.issuer_url != selection.account.issuer_url
        || session.subject_digest != selection.account.subject_digest
        || session.account_id != selection.account.id
        || session.team_id != selection.team.id
        || session.member_id != selection.membership.id
        || session.project_id != selection.project.id
        || session.device_id != device.id
        || session.scope.tenant_id != selection.account.tenant_id
        || session.scope.team_id != selection.team.id
        || session.scope.project_id != selection.project.id
        || session.scope.device_id != device.id
        || session.scope.account_revision != selection.account.revision
        || session.scope.team_revision != selection.team.revision
        || session.scope.membership_revision != selection.membership.revision
        || session.scope.project_revision != selection.project.revision
        || session.scope.device_revision != device.revision
    {
        return Err(StorageError::IdentityBootstrapScopeMismatch);
    }
    Ok(())
}

fn ensure_or_insert_account(
    transaction: &Transaction<'_>,
    account: &IdentityAccount,
) -> Result<(), StorageError> {
    account
        .validate()
        .map_err(|error| identity_decode(&error))?;
    let json = serde_json::to_string(account)?;
    let digest = json_digest(account)?;
    ensure_or_insert(
        transaction,
        "SELECT record_digest FROM identity_accounts WHERE tenant_id = ?1 AND id = ?2",
        params![account.tenant_id.as_str(), account.id.as_str()],
        &digest,
        || {
            transaction.execute(
                "INSERT INTO identity_accounts
                   (tenant_id, id, record_json, record_digest, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    account.tenant_id.as_str(),
                    account.id.as_str(),
                    json,
                    digest,
                    to_sql_u64(account.revision)?,
                ],
            )?;
            Ok(())
        },
    )
}

fn ensure_or_insert_team(
    transaction: &Transaction<'_>,
    team: &IdentityTeam,
) -> Result<(), StorageError> {
    team.validate().map_err(|error| identity_decode(&error))?;
    let json = serde_json::to_string(team)?;
    let digest = json_digest(team)?;
    ensure_or_insert(
        transaction,
        "SELECT record_digest FROM identity_teams WHERE tenant_id = ?1 AND id = ?2",
        params![team.tenant_id.as_str(), team.id.as_str()],
        &digest,
        || {
            transaction.execute(
                "INSERT INTO identity_teams
                   (tenant_id, id, record_json, record_digest, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    team.tenant_id.as_str(),
                    team.id.as_str(),
                    json,
                    digest,
                    to_sql_u64(team.revision)?,
                ],
            )?;
            Ok(())
        },
    )
}

fn ensure_or_insert_membership(
    transaction: &Transaction<'_>,
    membership: &IdentityMembership,
) -> Result<(), StorageError> {
    membership
        .validate()
        .map_err(|error| identity_decode(&error))?;
    let json = serde_json::to_string(membership)?;
    let digest = json_digest(membership)?;
    ensure_or_insert(
        transaction,
        "SELECT record_digest FROM identity_memberships WHERE tenant_id = ?1 AND id = ?2",
        params![membership.tenant_id.as_str(), membership.id.as_str()],
        &digest,
        || {
            transaction.execute(
                "INSERT INTO identity_memberships
                   (tenant_id, id, team_id, account_id, record_json, record_digest, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    membership.tenant_id.as_str(),
                    membership.id.as_str(),
                    membership.team_id.as_str(),
                    membership.account_id.as_str(),
                    json,
                    digest,
                    to_sql_u64(membership.revision)?,
                ],
            )?;
            Ok(())
        },
    )
}

fn ensure_or_insert_project(
    transaction: &Transaction<'_>,
    project: &IdentityProject,
) -> Result<(), StorageError> {
    project
        .validate()
        .map_err(|error| identity_decode(&error))?;
    let json = serde_json::to_string(project)?;
    let digest = json_digest(project)?;
    ensure_or_insert(
        transaction,
        "SELECT record_digest FROM identity_projects WHERE tenant_id = ?1 AND id = ?2",
        params![project.tenant_id.as_str(), project.id.as_str()],
        &digest,
        || {
            transaction.execute(
                "INSERT INTO identity_projects
                   (tenant_id, id, team_id, record_json, record_digest, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    project.tenant_id.as_str(),
                    project.id.as_str(),
                    project.team_id.as_str(),
                    json,
                    digest,
                    to_sql_u64(project.revision)?,
                ],
            )?;
            Ok(())
        },
    )
}

fn ensure_or_insert_device(
    transaction: &Transaction<'_>,
    device: &IdentityDevice,
    references: &IdentitySessionSecretReferences,
) -> Result<(), StorageError> {
    device.validate().map_err(|error| identity_decode(&error))?;
    let json = serde_json::to_string(device)?;
    let digest = json_digest(device)?;
    ensure_or_insert(
        transaction,
        "SELECT record_digest FROM identity_devices WHERE project_id = ?1 AND id = ?2",
        params![device.project_id.as_str(), device.id.as_str()],
        &digest,
        || {
            transaction.execute(
                "INSERT INTO identity_devices
                   (tenant_id, project_id, id, account_id, record_json, record_digest,
                    binding_secret_reference_json, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    device.tenant_id.as_str(),
                    device.project_id.as_str(),
                    device.id.as_str(),
                    device.account_id.as_str(),
                    json,
                    digest,
                    serde_json::to_string(&references.device_binding)?,
                    to_sql_u64(device.revision)?,
                ],
            )?;
            Ok(())
        },
    )
}

fn ensure_or_insert(
    transaction: &Transaction<'_>,
    query: &str,
    query_params: impl rusqlite::Params,
    expected_digest: &str,
    insert: impl FnOnce() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let existing = transaction
        .query_row(query, query_params, |row| row.get::<_, String>(0))
        .optional()?;
    if let Some(existing) = existing {
        if existing != expected_digest {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "identity_bootstrap_record",
                id: expected_digest.to_owned(),
            });
        }
        return Ok(());
    }
    insert()
}

struct IdentityProjectionColumns {
    tenant_id: String,
    id: String,
    team_id: Option<String>,
    account_id: Option<String>,
    project_id: Option<String>,
    record_json: String,
    record_digest: String,
    revision: i64,
}

fn load_identity_json_projection<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    query_params: impl rusqlite::Params,
    kind: &'static str,
    matches: impl FnOnce(&T, &IdentityProjectionColumns) -> bool,
) -> Result<T, StorageError> {
    let row = connection
        .query_row(sql, query_params, |row| {
            Ok(IdentityProjectionColumns {
                tenant_id: row.get(0)?,
                id: row.get(1)?,
                team_id: row.get(2)?,
                account_id: row.get(3)?,
                project_id: row.get(4)?,
                record_json: row.get(5)?,
                record_digest: row.get(6)?,
                revision: row.get(7)?,
            })
        })
        .optional()?;
    let Some(projection) = row else {
        return Err(StorageError::DomainDecode(format!("missing {kind} record")));
    };
    if json_text_digest(&projection.record_json) != projection.record_digest {
        return Err(StorageError::IdentityBootstrapProjectionMismatch);
    }
    let record: T = serde_json::from_str(&projection.record_json)?;
    if !matches(&record, &projection) {
        return Err(StorageError::IdentityBootstrapProjectionMismatch);
    }
    Ok(record)
}

fn decode_session_row(
    row: (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
    ),
) -> Result<IdentitySession, StorageError> {
    let (
        tenant_id,
        project_id,
        id,
        account_id,
        team_id,
        member_id,
        device_id,
        status,
        json,
        expected_digest,
        expected_revision,
    ) = row;
    if json_text_digest(&json) != expected_digest {
        return Err(StorageError::IdentityBootstrapProjectionMismatch);
    }
    let session: IdentitySession = serde_json::from_str(&json)?;
    if session.scope.tenant_id.as_str() != tenant_id
        || session.project_id.as_str() != project_id
        || session.id.as_str() != id
        || session.account_id.as_str() != account_id
        || session.team_id.as_str() != team_id
        || session.member_id.as_str() != member_id
        || session.device_id.as_str() != device_id
        || session_status_name(session.status) != status
        || session.revision != from_sql_u64(expected_revision, "identity session revision")?
    {
        return Err(StorageError::IdentityBootstrapProjectionMismatch);
    }
    session
        .validate()
        .map_err(|error| identity_decode(&error))?;
    Ok(session)
}

fn revision_matches(record_revision: u64, projected_revision: i64) -> bool {
    i64::try_from(record_revision).ok() == Some(projected_revision)
}

fn session_status_name(status: IdentitySessionStatus) -> &'static str {
    match status {
        IdentitySessionStatus::Online => "online",
        IdentitySessionStatus::Offline => "offline",
        IdentitySessionStatus::Expired => "expired",
        IdentitySessionStatus::Revoked => "revoked",
    }
}

fn json_digest<T: Serialize>(value: &T) -> Result<String, StorageError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn json_text_digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn identity_decode(error: &IdentityBootstrapError) -> StorageError {
    StorageError::DomainDecode(error.to_string())
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
    use std::path::PathBuf;

    use chrono::{DateTime, Duration, TimeZone, Utc};
    use hartevo_domain_kernel::{
        AccountId, DeviceId, IdentityAccount, IdentityBootstrapSnapshot, IdentityDevice,
        IdentityMembership, IdentityProject, IdentitySession, IdentitySessionId, IdentityTeam,
        KEYCLOAK_PROVIDER_ID, Project, ProjectId, StorageMode, TeamId, TenantId,
    };
    use rusqlite::params;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;

    const ISSUER: &str = "https://sso.example.test/realms/hartevo";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 9, 0, 0)
            .single()
            .expect("valid time")
    }

    fn digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the persistence test builds one complete identity graph before tampering with its normalized revision"
    )]
    fn normalized_identity_projection_tampering_fails_closed() {
        let tenant_id = TenantId::from("tenant-identity-projection");
        let project_id = ProjectId::from("project-identity-projection");
        let account_id = AccountId::from("account-identity-projection");
        let team_id = TeamId::from("team-identity-projection");
        let device_id = DeviceId::from("device-identity-projection");
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Identity projection",
            "",
            PathBuf::from("/tmp/identity-projection"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("project persisted");

        let account = IdentityAccount::new(
            account_id.clone(),
            tenant_id.clone(),
            ISSUER,
            digest("identity-projection-subject"),
            "Projection owner",
            None,
        )
        .expect("account");
        let team = IdentityTeam::new(team_id.clone(), tenant_id.clone(), "Growth").expect("team");
        let membership = IdentityMembership::new(
            hartevo_domain_kernel::MemberId::from("member-identity-projection"),
            tenant_id.clone(),
            team_id.clone(),
            account_id.clone(),
            "owner",
        )
        .expect("membership");
        let identity_project = IdentityProject::new(
            project_id.clone(),
            tenant_id.clone(),
            team_id,
            "Identity projection",
            "",
        )
        .expect("identity project");
        let snapshot = IdentityBootstrapSnapshot::new(
            ISSUER,
            account.subject_digest.clone(),
            account,
            vec![team],
            vec![membership],
            vec![identity_project],
        )
        .expect("snapshot");
        let selection = snapshot
            .select(&TeamId::from("team-identity-projection"), &project_id)
            .expect("selection");
        let device_reference = SecretReference::identity_device_binding(
            tenant_id.clone(),
            project_id.clone(),
            device_id.as_str(),
            1,
        )
        .expect("device reference");
        let device = IdentityDevice::bind(
            device_id.clone(),
            tenant_id.clone(),
            account_id.clone(),
            project_id.clone(),
            device_reference.credential_id().expect("device digest"),
        )
        .expect("device");
        let access_reference = SecretReference::oidc_access_token(
            tenant_id.clone(),
            project_id.clone(),
            KEYCLOAK_PROVIDER_ID,
            account_id.as_str(),
            1,
        )
        .expect("access reference");
        let refresh_reference = SecretReference::oidc_refresh_token(
            tenant_id,
            project_id.clone(),
            KEYCLOAK_PROVIDER_ID,
            account_id.as_str(),
            1,
        )
        .expect("refresh reference");
        let session = IdentitySession::create(
            IdentitySessionId::from("session-identity-projection"),
            KEYCLOAK_PROVIDER_ID,
            ISSUER,
            snapshot.subject_digest.clone(),
            &selection,
            &device,
            access_reference.credential_id().expect("access digest"),
            refresh_reference.credential_id().expect("refresh digest"),
            now(),
            now() + Duration::hours(1),
            now() + Duration::hours(2),
        )
        .expect("session");
        let references = IdentitySessionSecretReferences {
            access_token: access_reference,
            refresh_token: refresh_reference,
            device_binding: device_reference,
        };
        store
            .save_identity_bootstrap_atomic(
                &snapshot,
                &selection.team.id,
                &selection.project.id,
                &device,
                &session,
                &references,
                "identity_session.authorized",
                &json!({}),
                now(),
            )
            .expect("identity bootstrap");

        store
            .connection
            .execute(
                "UPDATE identity_projects SET revision = revision + 1
                 WHERE tenant_id = ?1 AND id = ?2",
                params!["tenant-identity-projection", "project-identity-projection"],
            )
            .expect("tamper normalized project revision");
        assert!(matches!(
            store.load_identity_bootstrap_state(&project_id, &session.id),
            Err(StorageError::IdentityBootstrapProjectionMismatch)
        ));
    }
}

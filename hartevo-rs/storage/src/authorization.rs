use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Connection, ConnectionId, ConnectionSnapshot, ConsentRecord, ConsentRecordId, ConsentState,
    Effect, EffectStatus, FactId, ProjectId, TruthFact,
};
use hartevo_effect_broker::{
    EffectPermissionResolver, LedgerError, PermissionEvidence, PermissionFailure, PermissionFence,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{PersistedMutation, ProjectStore, StorageError};

impl ProjectStore {
    pub fn create_connection(
        &mut self,
        connection: &Connection,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        let snapshot = connection.snapshot();
        snapshot
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if snapshot.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(snapshot.revision));
        }
        if !snapshot
            .is_initial_snapshot()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::DomainDecode(
                "connection must begin from its exact registration snapshot".into(),
            ));
        }
        self.persist_connection(connection, None, event_type, payload, recorded_at)
    }

    pub fn update_connection(
        &mut self,
        connection: &Connection,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        let actual = connection.revision();
        require_next_revision(expected_revision, actual)?;
        let snapshot = connection.snapshot();
        let previous = self.load_connection(&snapshot.project_id, &snapshot.id)?;
        if previous.revision() != expected_revision
            || !snapshot
                .follows(&previous.snapshot())
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "connection command transition",
                id: snapshot.id.to_string(),
            });
        }
        self.persist_connection(
            connection,
            Some(expected_revision),
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_connection(
        &self,
        project_id: &ProjectId,
        connection_id: &ConnectionId,
    ) -> Result<Connection, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT id, tenant_id, project_id, provider, account_id,
                        expected_external_account_id, required_scopes_json, granted_scopes_json,
                        status, last_probe_json, revoked_at, revision, created_at, updated_at
                 FROM connections WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), connection_id.as_str()],
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
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, String>(13)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "connection",
                project_id: project_id.clone(),
                id: connection_id.to_string(),
            })?;
        Connection::restore(ConnectionSnapshot {
            id: ConnectionId::from_stable(row.0),
            tenant_id: hartevo_domain_kernel::TenantId::from_stable(row.1),
            project_id: ProjectId::from_stable(row.2),
            provider: row.3,
            account_id: hartevo_domain_kernel::AccountId::from_stable(row.4),
            expected_external_account_id: row.5,
            required_scopes: decode_json(&row.6)?,
            granted_scopes: decode_json(&row.7)?,
            status: decode_enum(&row.8)?,
            last_probe: row.9.as_deref().map(decode_json).transpose()?,
            revoked_at: row.10.as_deref().map(parse_time).transpose()?,
            revision: from_sql_u64(row.11, "connection revision")?,
            created_at: parse_time(&row.12)?,
            updated_at: parse_time(&row.13)?,
        })
        .map_err(|error| StorageError::DomainDecode(error.to_string()))
    }

    pub fn create_consent_record(
        &mut self,
        record: &ConsentRecord,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        record
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if record.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(record.revision));
        }
        if !record
            .is_initial_snapshot()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::DomainDecode(
                "consent must begin from its exact grant snapshot".into(),
            ));
        }
        self.persist_consent_record(record, None, event_type, payload, recorded_at)
    }

    pub fn update_consent_record(
        &mut self,
        record: &ConsentRecord,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        record
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        require_next_revision(expected_revision, record.revision)?;
        let previous = self.load_consent_record(&record.project_id, &record.id)?;
        if previous.revision != expected_revision
            || !record
                .follows(&previous)
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "consent command transition",
                id: record.id.to_string(),
            });
        }
        self.persist_consent_record(
            record,
            Some(expected_revision),
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_consent_record(
        &self,
        project_id: &ProjectId,
        record_id: &ConsentRecordId,
    ) -> Result<ConsentRecord, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT id, tenant_id, project_id, person_id, purpose, channel, market,
                        legal_basis, status, source, evidence_digest, granted_at, valid_until,
                        withdrawn_at, revision
                 FROM consent_records WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), record_id.as_str()],
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
                        row.get::<_, String>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<String>>(13)?,
                        row.get::<_, i64>(14)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "consent",
                project_id: project_id.clone(),
                id: record_id.to_string(),
            })?;
        let record = ConsentRecord {
            id: ConsentRecordId::from_stable(row.0),
            tenant_id: hartevo_domain_kernel::TenantId::from_stable(row.1),
            project_id: ProjectId::from_stable(row.2),
            person_id: hartevo_domain_kernel::PersonId::from_stable(row.3),
            purpose: decode_enum(&row.4)?,
            channel: decode_enum(&row.5)?,
            market: row.6,
            legal_basis: decode_enum(&row.7)?,
            status: decode_enum(&row.8)?,
            source: row.9,
            evidence_digest: row.10,
            granted_at: row.11.as_deref().map(parse_time).transpose()?,
            valid_until: row.12.as_deref().map(parse_time).transpose()?,
            withdrawn_at: row.13.as_deref().map(parse_time).transpose()?,
            revision: from_sql_u64(row.14, "consent revision")?,
        };
        record
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        Ok(record)
    }

    pub fn create_truth_fact(
        &mut self,
        fact: &TruthFact,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        if fact.version != 1 {
            return Err(StorageError::InvalidInitialRevision(fact.version));
        }
        self.persist_truth_fact(fact, None, event_type, payload, recorded_at)
    }

    pub fn revise_truth_fact(
        &mut self,
        fact: &TruthFact,
        expected_version: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        require_next_revision(expected_version, fact.version)?;
        self.persist_truth_fact(
            fact,
            Some(expected_version),
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_truth_fact(
        &self,
        project_id: &ProjectId,
        fact_id: &FactId,
    ) -> Result<TruthFact, StorageError> {
        let version = self
            .connection
            .query_row(
                "SELECT current_version FROM truth_fact_heads WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), fact_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "truth_fact",
                project_id: project_id.clone(),
                id: fact_id.to_string(),
            })?;
        self.load_truth_fact_revision(project_id, fact_id, from_sql_u64(version, "truth version")?)
    }

    pub fn load_truth_fact_revision(
        &self,
        project_id: &ProjectId,
        fact_id: &FactId,
        version: u64,
    ) -> Result<TruthFact, StorageError> {
        let sql_version = to_sql_u64(version)?;
        let row = self
            .connection
            .query_row(
                "SELECT id, tenant_id, project_id, fact_key, value_json, alternatives_json,
                        status, source_json, market, language, observed_at, valid_from,
                        valid_until, confidence, version, revision_link_json
                 FROM truth_fact_revisions
                 WHERE project_id = ?1 AND id = ?2 AND version = ?3",
                params![project_id.as_str(), fact_id.as_str(), sql_version],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, String>(13)?,
                        row.get::<_, i64>(14)?,
                        row.get::<_, Option<String>>(15)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "truth_fact_revision",
                project_id: project_id.clone(),
                id: format!("{fact_id}@{version}"),
            })?;
        Ok(TruthFact {
            id: FactId::from_stable(row.0),
            tenant_id: hartevo_domain_kernel::TenantId::from_stable(row.1),
            project_id: ProjectId::from_stable(row.2),
            key: row.3,
            value: row.4.as_deref().map(decode_json).transpose()?,
            alternatives: decode_json(&row.5)?,
            status: decode_enum(&row.6)?,
            source: row.7.as_deref().map(decode_json).transpose()?,
            market: row.8,
            language: row.9,
            observed_at: parse_time(&row.10)?,
            valid_from: parse_time(&row.11)?,
            valid_until: row.12.as_deref().map(parse_time).transpose()?,
            confidence: decode_json(&row.13)?,
            version: from_sql_u64(row.14, "truth version")?,
            revision_link: row.15.as_deref().map(decode_json).transpose()?,
        })
    }

    fn persist_connection(
        &mut self,
        connection: &Connection,
        expected_revision: Option<u64>,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        let snapshot = connection.snapshot();
        let transaction = self.connection.transaction()?;
        ensure_project_scope(&transaction, &snapshot.tenant_id, &snapshot.project_id)?;
        match expected_revision {
            None => insert_connection(&transaction, &snapshot)?,
            Some(expected) => update_connection(&transaction, &snapshot, expected)?,
        }
        let (event_sequence, outbox_sequence) = append_event_and_outbox(
            &transaction,
            &snapshot.tenant_id,
            &snapshot.project_id,
            "connection",
            snapshot.id.as_str(),
            event_type,
            payload,
            recorded_at,
        )?;
        transaction.commit()?;
        Ok(PersistedMutation {
            event_sequence,
            outbox_sequence,
            state_revision: snapshot.revision,
        })
    }

    fn persist_consent_record(
        &mut self,
        record: &ConsentRecord,
        expected_revision: Option<u64>,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        let transaction = self.connection.transaction()?;
        ensure_project_scope(&transaction, &record.tenant_id, &record.project_id)?;
        ensure_person_scope(
            &transaction,
            &record.tenant_id,
            &record.project_id,
            &record.person_id,
        )?;
        match expected_revision {
            None => insert_consent(&transaction, record)?,
            Some(expected) => update_consent(&transaction, record, expected)?,
        }
        let (event_sequence, outbox_sequence) = append_event_and_outbox(
            &transaction,
            &record.tenant_id,
            &record.project_id,
            "consent_record",
            record.id.as_str(),
            event_type,
            payload,
            recorded_at,
        )?;
        transaction.commit()?;
        Ok(PersistedMutation {
            event_sequence,
            outbox_sequence,
            state_revision: record.revision,
        })
    }

    fn persist_truth_fact(
        &mut self,
        fact: &TruthFact,
        expected_version: Option<u64>,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        let transaction = self.connection.transaction()?;
        ensure_project_scope(&transaction, &fact.tenant_id, &fact.project_id)?;
        match expected_version {
            None => insert_truth_head(&transaction, fact)?,
            Some(expected) => update_truth_head(&transaction, fact, expected)?,
        }
        insert_truth_revision(&transaction, fact)?;
        let (event_sequence, outbox_sequence) = append_event_and_outbox(
            &transaction,
            &fact.tenant_id,
            &fact.project_id,
            "truth_fact",
            fact.id.as_str(),
            event_type,
            payload,
            recorded_at,
        )?;
        transaction.commit()?;
        Ok(PersistedMutation {
            event_sequence,
            outbox_sequence,
            state_revision: fact.version,
        })
    }
}

impl EffectPermissionResolver for ProjectStore {
    fn authorize(
        &self,
        effect: &Effect,
        now: DateTime<Utc>,
    ) -> Result<PermissionEvidence, PermissionFailure> {
        let (connection_evidence_digest, connection_fence) =
            authorize_connection(self, effect, now)?;
        let (consent_evidence_digest, consent_fence) = authorize_consent(self, effect, now)?;
        let (conversation_evidence_digest, conversation_fence) =
            authorize_conversation(self, effect)?;
        let (creator_contact_evidence_digest, creator_contact_fence) =
            authorize_creator_contact(self, effect)?;
        Ok(PermissionEvidence {
            connection_evidence_digest,
            consent_evidence_digest,
            conversation_evidence_digest,
            creator_contact_evidence_digest,
            fences: [
                connection_fence,
                consent_fence,
                conversation_fence,
                creator_contact_fence,
            ]
            .into_iter()
            .flatten()
            .collect(),
        })
    }
}

type AuthorizedPermission = (Option<String>, Option<PermissionFence>);

fn authorize_connection(
    store: &ProjectStore,
    effect: &Effect,
    now: DateTime<Utc>,
) -> Result<AuthorizedPermission, PermissionFailure> {
    let Some(connection_id) = &effect.connection_id else {
        return if effect.required_scopes.is_empty() && effect.account_id.is_none() {
            Ok((None, None))
        } else {
            Err(PermissionFailure::ConnectionAccountOrScopeMismatch)
        };
    };
    let connection = store
        .load_connection(&effect.project_id, connection_id)
        .map_err(map_connection_error)?;
    if connection.tenant_id() != &effect.tenant_id || connection.project_id() != &effect.project_id
    {
        return Err(PermissionFailure::ConnectionScopeMismatch);
    }
    if connection.provider() != effect.provider
        || effect.account_id.as_ref() != Some(connection.account_id())
        || !connection.permits_scopes(&effect.required_scopes, now)
    {
        return if connection.is_connected(now) {
            Err(PermissionFailure::ConnectionAccountOrScopeMismatch)
        } else {
            Err(PermissionFailure::ConnectionNotConnected)
        };
    }
    Ok((
        Some(digest_json(&connection.snapshot())?),
        Some(PermissionFence::Connection {
            connection_id: connection.id().clone(),
            revision: connection.revision(),
        }),
    ))
}

fn authorize_consent(
    store: &ProjectStore,
    effect: &Effect,
    now: DateTime<Utc>,
) -> Result<AuthorizedPermission, PermissionFailure> {
    if effect.consent == ConsentState::NotRequired
        && effect.consent_record_id.is_none()
        && effect.consent_requirement.is_none()
    {
        return Ok((None, None));
    }
    if effect.consent != ConsentState::Confirmed {
        return Err(PermissionFailure::ConsentNotPermitted);
    }
    let record_id = effect
        .consent_record_id
        .as_ref()
        .ok_or(PermissionFailure::ConsentMissing)?;
    let requirement = effect
        .consent_requirement
        .as_ref()
        .ok_or(PermissionFailure::ConsentMissing)?;
    let record = store
        .load_consent_record(&effect.project_id, record_id)
        .map_err(map_consent_error)?;
    if record.tenant_id != effect.tenant_id || record.project_id != effect.project_id {
        return Err(PermissionFailure::ConsentScopeMismatch);
    }
    if !record.permits_requirement(requirement, now) {
        return Err(PermissionFailure::ConsentNotPermitted);
    }
    Ok((
        Some(digest_json(&record)?),
        Some(PermissionFence::Consent {
            consent_record_id: record.id.clone(),
            revision: record.revision,
        }),
    ))
}

fn authorize_conversation(
    store: &ProjectStore,
    effect: &Effect,
) -> Result<AuthorizedPermission, PermissionFailure> {
    let Some(guard) = &effect.conversation_guard else {
        return Ok((None, None));
    };
    let conversation = store
        .load_conversation(&effect.project_id, &guard.conversation_id)
        .map_err(map_conversation_error)?;
    if conversation.tenant_id != effect.tenant_id
        || conversation.project_id != effect.project_id
        || conversation.mission_id.as_ref() != Some(&effect.mission_id)
    {
        return Err(PermissionFailure::ConversationGuardMissingOrScopedElsewhere);
    }
    let guard_is_current = if effect.status == EffectStatus::Verified {
        effect.receipt.as_ref().is_some_and(|receipt| {
            conversation.records_sent_agent_effect_scope(
                &effect.id,
                guard.control_generation,
                &guard.scope_digest,
                &receipt.id,
            )
        })
    } else {
        conversation.authorizes_agent_effect_scope(
            &effect.id,
            guard.control_generation,
            &guard.scope_digest,
        )
    };
    if !guard_is_current {
        return Err(PermissionFailure::ConversationControlLost);
    }
    Ok((
        Some(digest_json(&conversation)?),
        Some(PermissionFence::Conversation {
            conversation_id: conversation.id.clone(),
            revision: conversation.revision,
            control_generation: conversation.control.generation(),
        }),
    ))
}

fn authorize_creator_contact(
    store: &ProjectStore,
    effect: &Effect,
) -> Result<AuthorizedPermission, PermissionFailure> {
    let Some(guard) = &effect.creator_contact_guard else {
        return Ok((None, None));
    };
    let hiring = store
        .load_creator_hiring(&effect.project_id, &guard.hiring_id)
        .map_err(map_creator_contact_error)?;
    if hiring.tenant_id != effect.tenant_id
        || hiring.project_id != effect.project_id
        || hiring.mission_id != effect.mission_id
        || effect.payload_digest != guard.scope_digest
    {
        return Err(PermissionFailure::CreatorContactGuardMissingOrScopedElsewhere);
    }
    let candidate = hiring
        .candidates
        .iter()
        .find(|candidate| {
            candidate.creator_id == guard.creator_id && candidate.partner_id == guard.partner_id
        })
        .ok_or(PermissionFailure::CreatorContactGuardMissingOrScopedElsewhere)?;
    let invitation = hiring
        .invitations
        .iter()
        .find(|invitation| {
            invitation.creator_id == guard.creator_id
                && invitation.effect_id == effect.id
                && invitation.scope_digest == guard.scope_digest
        })
        .ok_or(PermissionFailure::CreatorContactGuardMissingOrScopedElsewhere)?;
    let partner = store
        .load_partner(&effect.project_id, &guard.partner_id)
        .map_err(map_creator_contact_error)?;
    if partner.tenant_id != effect.tenant_id
        || partner.project_id != effect.project_id
        || !partner.can_contact()
        || partner.permission_evidence_digest.as_deref()
            != Some(guard.permission_evidence_digest.as_str())
        || candidate.permission_evidence_digest.as_deref()
            != Some(guard.permission_evidence_digest.as_str())
    {
        return Err(PermissionFailure::CreatorContactPermissionLost);
    }
    let hiring_id = hiring.id.clone();
    let hiring_revision = hiring.state_revision;
    let partner_id = partner.id.clone();
    let partner_revision = partner.revision;
    Ok((
        Some(digest_json(&serde_json::json!({
            "hiringId": hiring.id,
            "hiringRevision": hiring.state_revision,
            "candidate": candidate,
            "invitation": invitation,
            "partner": partner,
        }))?),
        Some(PermissionFence::CreatorContact {
            hiring_id,
            hiring_revision,
            partner_id,
            partner_revision,
        }),
    ))
}

fn map_creator_contact_error(error: StorageError) -> PermissionFailure {
    match error {
        StorageError::ScopedRecordNotFound { .. } => {
            PermissionFailure::CreatorContactGuardMissingOrScopedElsewhere
        }
        other => PermissionFailure::Unavailable(other.to_string()),
    }
}

/// Re-validates the exact revisions used for approval after the durable claim
/// transaction has acquired its write lock. A permission mutation and a claim
/// therefore have one observable order: a mutation that commits first rejects
/// the stale claim, while a claim that commits first was authorized at its
/// dispatch linearization point.
pub(crate) fn validate_permission_fences(
    transaction: &Transaction<'_>,
    effect: &Effect,
    evidence: &PermissionEvidence,
) -> Result<(), LedgerError> {
    let expected = permission_fence_kinds_for_effect(effect);
    if expected != permission_fence_kinds_for_evidence_digests(evidence) {
        return Err(LedgerError::ScopeConflict);
    }

    let mut seen = BTreeSet::new();
    for fence in &evidence.fences {
        match fence {
            PermissionFence::Connection {
                connection_id,
                revision,
            } => {
                if !seen.insert(PermissionFenceKind::Connection) {
                    return Err(LedgerError::ScopeConflict);
                }
                validate_connection_fence(transaction, effect, connection_id, *revision)?;
            }
            PermissionFence::Consent {
                consent_record_id,
                revision,
            } => {
                if !seen.insert(PermissionFenceKind::Consent) {
                    return Err(LedgerError::ScopeConflict);
                }
                validate_consent_fence(transaction, effect, consent_record_id, *revision)?;
            }
            PermissionFence::Conversation {
                conversation_id,
                revision,
                control_generation,
            } => {
                if !seen.insert(PermissionFenceKind::Conversation) {
                    return Err(LedgerError::ScopeConflict);
                }
                validate_conversation_fence(
                    transaction,
                    effect,
                    conversation_id,
                    *revision,
                    *control_generation,
                )?;
            }
            PermissionFence::CreatorContact {
                hiring_id,
                hiring_revision,
                partner_id,
                partner_revision,
            } => {
                if !seen.insert(PermissionFenceKind::CreatorContact) {
                    return Err(LedgerError::ScopeConflict);
                }
                validate_creator_contact_fence(
                    transaction,
                    effect,
                    hiring_id,
                    *hiring_revision,
                    partner_id,
                    *partner_revision,
                )?;
            }
        }
    }

    if expected != seen {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PermissionFenceKind {
    Connection,
    Consent,
    Conversation,
    CreatorContact,
}

fn permission_fence_kinds_for_effect(effect: &Effect) -> BTreeSet<PermissionFenceKind> {
    let mut kinds = BTreeSet::new();
    if effect.connection_id.is_some() {
        kinds.insert(PermissionFenceKind::Connection);
    }
    if effect.consent_record_id.is_some() {
        kinds.insert(PermissionFenceKind::Consent);
    }
    if effect.conversation_guard.is_some() {
        kinds.insert(PermissionFenceKind::Conversation);
    }
    if effect.creator_contact_guard.is_some() {
        kinds.insert(PermissionFenceKind::CreatorContact);
    }
    kinds
}

fn permission_fence_kinds_for_evidence_digests(
    evidence: &PermissionEvidence,
) -> BTreeSet<PermissionFenceKind> {
    let mut kinds = BTreeSet::new();
    if evidence.connection_evidence_digest.is_some() {
        kinds.insert(PermissionFenceKind::Connection);
    }
    if evidence.consent_evidence_digest.is_some() {
        kinds.insert(PermissionFenceKind::Consent);
    }
    if evidence.conversation_evidence_digest.is_some() {
        kinds.insert(PermissionFenceKind::Conversation);
    }
    if evidence.creator_contact_evidence_digest.is_some() {
        kinds.insert(PermissionFenceKind::CreatorContact);
    }
    kinds
}

fn validate_connection_fence(
    transaction: &Transaction<'_>,
    effect: &Effect,
    connection_id: &ConnectionId,
    revision: u64,
) -> Result<(), LedgerError> {
    if effect.connection_id.as_ref() != Some(connection_id) {
        return Err(LedgerError::ScopeConflict);
    }
    let stored = transaction
        .query_row(
            "SELECT revision FROM connections
             WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3",
            params![
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                connection_id.as_str(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| ledger_persistence(&error))?;
    require_fence_revision(stored, revision, "connection")
}

fn validate_consent_fence(
    transaction: &Transaction<'_>,
    effect: &Effect,
    consent_record_id: &ConsentRecordId,
    revision: u64,
) -> Result<(), LedgerError> {
    if effect.consent_record_id.as_ref() != Some(consent_record_id) {
        return Err(LedgerError::ScopeConflict);
    }
    let stored = transaction
        .query_row(
            "SELECT revision FROM consent_records
             WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3",
            params![
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                consent_record_id.as_str(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| ledger_persistence(&error))?;
    require_fence_revision(stored, revision, "consent")
}

fn validate_conversation_fence(
    transaction: &Transaction<'_>,
    effect: &Effect,
    conversation_id: &hartevo_domain_kernel::ConversationId,
    revision: u64,
    control_generation: u64,
) -> Result<(), LedgerError> {
    let guard_matches = effect.conversation_guard.as_ref().is_some_and(|guard| {
        guard.conversation_id == *conversation_id && guard.control_generation == control_generation
    });
    if !guard_matches {
        return Err(LedgerError::ScopeConflict);
    }
    let stored = transaction
        .query_row(
            "SELECT revision, control_generation FROM conversations
             WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3",
            params![
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                conversation_id.as_str(),
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|error| ledger_persistence(&error))?;
    let Some((stored_revision, stored_generation)) = stored else {
        return Err(LedgerError::ScopeConflict);
    };
    require_fence_revision(Some(stored_revision), revision, "conversation")?;
    require_fence_revision(
        Some(stored_generation),
        control_generation,
        "conversation control generation",
    )
}

fn validate_creator_contact_fence(
    transaction: &Transaction<'_>,
    effect: &Effect,
    hiring_id: &hartevo_domain_kernel::CreatorHiringId,
    hiring_revision: u64,
    partner_id: &hartevo_domain_kernel::PartnerId,
    partner_revision: u64,
) -> Result<(), LedgerError> {
    let guard_matches = effect
        .creator_contact_guard
        .as_ref()
        .is_some_and(|guard| guard.hiring_id == *hiring_id && guard.partner_id == *partner_id);
    if !guard_matches {
        return Err(LedgerError::ScopeConflict);
    }
    let stored_hiring = transaction
        .query_row(
            "SELECT state_revision FROM creator_hirings
             WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3",
            params![
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                hiring_id.as_str(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| ledger_persistence(&error))?;
    require_fence_revision(stored_hiring, hiring_revision, "creator hiring")?;
    let stored_partner = transaction
        .query_row(
            "SELECT revision FROM partners
             WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3",
            params![
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                partner_id.as_str(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| ledger_persistence(&error))?;
    require_fence_revision(stored_partner, partner_revision, "partner")
}

fn require_fence_revision(
    stored: Option<i64>,
    expected: u64,
    field: &str,
) -> Result<(), LedgerError> {
    let Some(stored) = stored else {
        return Err(LedgerError::ScopeConflict);
    };
    let stored = u64::try_from(stored).map_err(|_| {
        LedgerError::Persistence(format!("invalid {field} authorization revision: {stored}"))
    })?;
    if stored != expected {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn ledger_persistence(error: &rusqlite::Error) -> LedgerError {
    LedgerError::Persistence(error.to_string())
}

pub(crate) fn insert_connection(
    transaction: &Transaction<'_>,
    snapshot: &ConnectionSnapshot,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO connections
           (id, tenant_id, project_id, provider, account_id, expected_external_account_id,
            required_scopes_json, granted_scopes_json, status, last_probe_json, revoked_at,
            revision, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        connection_params(snapshot)?,
    )?;
    Ok(())
}

pub(crate) fn update_connection(
    transaction: &Transaction<'_>,
    snapshot: &ConnectionSnapshot,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE connections SET provider = ?4, account_id = ?5,
           expected_external_account_id = ?6, required_scopes_json = ?7,
           granted_scopes_json = ?8, status = ?9, last_probe_json = ?10,
           revoked_at = ?11, revision = ?12, created_at = ?13, updated_at = ?14
         WHERE id = ?1 AND tenant_id = ?2 AND project_id = ?3 AND revision = ?15",
        rusqlite::params_from_iter(connection_values(snapshot)?.into_iter().chain([
            rusqlite::types::Value::Integer(to_sql_u64(expected_revision)?),
        ])),
    )?;
    require_updated(
        updated,
        "connection",
        snapshot.id.as_str(),
        expected_revision,
    )
}

fn connection_params(
    snapshot: &ConnectionSnapshot,
) -> Result<impl rusqlite::Params + use<>, StorageError> {
    Ok(rusqlite::params_from_iter(connection_values(snapshot)?))
}

fn connection_values(
    snapshot: &ConnectionSnapshot,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        snapshot.id.as_str().to_owned().into(),
        snapshot.tenant_id.as_str().to_owned().into(),
        snapshot.project_id.as_str().to_owned().into(),
        snapshot.provider.clone().into(),
        snapshot.account_id.as_str().to_owned().into(),
        snapshot.expected_external_account_id.clone().into(),
        serde_json::to_string(&snapshot.required_scopes)?.into(),
        serde_json::to_string(&snapshot.granted_scopes)?.into(),
        enum_name(&snapshot.status)?.into(),
        snapshot
            .last_probe
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?
            .into(),
        snapshot.revoked_at.map(|value| value.to_rfc3339()).into(),
        to_sql_u64(snapshot.revision)?.into(),
        snapshot.created_at.to_rfc3339().into(),
        snapshot.updated_at.to_rfc3339().into(),
    ])
}

pub(crate) fn insert_consent(
    transaction: &Transaction<'_>,
    record: &ConsentRecord,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO consent_records
           (id, tenant_id, project_id, person_id, purpose, channel, market, legal_basis,
            status, source, evidence_digest, granted_at, valid_until, withdrawn_at, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        consent_params(record, None)?,
    )?;
    Ok(())
}

fn update_consent(
    transaction: &Transaction<'_>,
    record: &ConsentRecord,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE consent_records SET person_id = ?4, purpose = ?5, channel = ?6,
           market = ?7, legal_basis = ?8, status = ?9, source = ?10,
           evidence_digest = ?11, granted_at = ?12, valid_until = ?13,
           withdrawn_at = ?14, revision = ?15
         WHERE id = ?1 AND tenant_id = ?2 AND project_id = ?3 AND revision = ?16",
        consent_params(record, Some(expected_revision))?,
    )?;
    require_updated(
        updated,
        "consent_record",
        record.id.as_str(),
        expected_revision,
    )
}

fn consent_params(
    record: &ConsentRecord,
    expected_revision: Option<u64>,
) -> Result<impl rusqlite::Params + use<>, StorageError> {
    let mut values = vec![
        rusqlite::types::Value::from(record.id.as_str().to_owned()),
        rusqlite::types::Value::from(record.tenant_id.as_str().to_owned()),
        rusqlite::types::Value::from(record.project_id.as_str().to_owned()),
        rusqlite::types::Value::from(record.person_id.as_str().to_owned()),
        enum_name(&record.purpose)?.into(),
        enum_name(&record.channel)?.into(),
        record.market.clone().into(),
        enum_name(&record.legal_basis)?.into(),
        enum_name(&record.status)?.into(),
        record.source.clone().into(),
        record.evidence_digest.clone().into(),
        record.granted_at.map(|value| value.to_rfc3339()).into(),
        record.valid_until.map(|value| value.to_rfc3339()).into(),
        record.withdrawn_at.map(|value| value.to_rfc3339()).into(),
        to_sql_u64(record.revision)?.into(),
    ];
    if let Some(expected) = expected_revision {
        values.push(to_sql_u64(expected)?.into());
    }
    Ok(rusqlite::params_from_iter(values))
}

pub(crate) fn insert_truth_head(
    transaction: &Transaction<'_>,
    fact: &TruthFact,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO truth_fact_heads
           (id, tenant_id, project_id, fact_key, market, language, current_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            fact.id.as_str(),
            fact.tenant_id.as_str(),
            fact.project_id.as_str(),
            fact.key,
            fact.market,
            fact.language,
            to_sql_u64(fact.version)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn update_truth_head(
    transaction: &Transaction<'_>,
    fact: &TruthFact,
    expected_version: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE truth_fact_heads SET fact_key = ?4, market = ?5, language = ?6,
           current_version = ?7
         WHERE id = ?1 AND tenant_id = ?2 AND project_id = ?3 AND current_version = ?8",
        params![
            fact.id.as_str(),
            fact.tenant_id.as_str(),
            fact.project_id.as_str(),
            fact.key,
            fact.market,
            fact.language,
            to_sql_u64(fact.version)?,
            to_sql_u64(expected_version)?,
        ],
    )?;
    require_updated(updated, "truth_fact", fact.id.as_str(), expected_version)
}

pub(crate) fn insert_truth_revision(
    transaction: &Transaction<'_>,
    fact: &TruthFact,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO truth_fact_revisions
           (id, tenant_id, project_id, fact_key, value_json, alternatives_json, status,
            source_json, market, language, observed_at, valid_from, valid_until, confidence,
            version, revision_link_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            fact.id.as_str(),
            fact.tenant_id.as_str(),
            fact.project_id.as_str(),
            fact.key,
            fact.value.as_ref().map(serde_json::to_string).transpose()?,
            serde_json::to_string(&fact.alternatives)?,
            enum_name(&fact.status)?,
            fact.source
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            fact.market,
            fact.language,
            fact.observed_at.to_rfc3339(),
            fact.valid_from.to_rfc3339(),
            fact.valid_until.map(|value| value.to_rfc3339()),
            serde_json::to_string(&fact.confidence)?,
            to_sql_u64(fact.version)?,
            fact.revision_link
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        ],
    )?;
    Ok(())
}

fn ensure_project_scope(
    transaction: &Transaction<'_>,
    tenant_id: &hartevo_domain_kernel::TenantId,
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

fn ensure_person_scope(
    transaction: &Transaction<'_>,
    tenant_id: &hartevo_domain_kernel::TenantId,
    project_id: &ProjectId,
    person_id: &hartevo_domain_kernel::PersonId,
) -> Result<(), StorageError> {
    let stored_tenant = transaction
        .query_row(
            "SELECT tenant_id FROM people WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), person_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "person",
            project_id: project_id.clone(),
            id: person_id.to_string(),
        })?;
    if stored_tenant != tenant_id.as_str() {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_event_and_outbox(
    transaction: &Transaction<'_>,
    tenant_id: &hartevo_domain_kernel::TenantId,
    project_id: &ProjectId,
    aggregate_type: &str,
    aggregate_id: &str,
    event_type: &str,
    payload: &Value,
    recorded_at: DateTime<Utc>,
) -> Result<(i64, i64), StorageError> {
    let payload_json = serde_json::to_string(payload)?;
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    let event_sequence = transaction.last_insert_rowid();
    transaction.execute(
        "INSERT INTO outbox_messages
           (tenant_id, project_id, mission_id, aggregate_type, aggregate_id, event_type,
            payload_json, available_at, created_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            aggregate_type,
            aggregate_id,
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    Ok((event_sequence, transaction.last_insert_rowid()))
}

fn require_next_revision(expected: u64, actual: u64) -> Result<(), StorageError> {
    let next = expected
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(expected))?;
    if actual != next {
        return Err(StorageError::UnexpectedNextRevision {
            expected: next,
            actual,
        });
    }
    Ok(())
}

fn require_updated(
    updated: usize,
    aggregate: &str,
    id: &str,
    expected_revision: u64,
) -> Result<(), StorageError> {
    if updated == 1 {
        Ok(())
    } else {
        Err(StorageError::OptimisticConflict {
            aggregate: format!("{aggregate}:{id}"),
            expected_revision,
        })
    }
}

fn enum_name(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as a string".into()))
}

fn decode_enum<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(Value::String(value.to_owned()))?)
}

fn decode_json<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_str(value)?)
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

fn digest_json(value: &impl Serialize) -> Result<String, PermissionFailure> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PermissionFailure::Unavailable(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn map_connection_error(error: StorageError) -> PermissionFailure {
    match error {
        StorageError::ScopedRecordNotFound {
            kind: "connection", ..
        } => PermissionFailure::ConnectionMissing,
        other => PermissionFailure::Unavailable(other.to_string()),
    }
}

fn map_consent_error(error: StorageError) -> PermissionFailure {
    match error {
        StorageError::ScopedRecordNotFound {
            kind: "consent", ..
        } => PermissionFailure::ConsentMissing,
        other => PermissionFailure::Unavailable(other.to_string()),
    }
}

fn map_conversation_error(error: StorageError) -> PermissionFailure {
    match error {
        StorageError::ScopedRecordNotFound {
            kind: "conversation",
            ..
        } => PermissionFailure::ConversationGuardMissingOrScopedElsewhere,
        other => PermissionFailure::Unavailable(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, ActorId, ConnectionProbe, ConsentPurpose, ConsentRequirement, ContactChannel,
        CurrencyCode, EffectClass, EffectId, EffectRisk, EffectSpec, LegalBasis, Mission,
        MissionContract, MissionId, ProbeOutcome, Project, Receipt, ReceiptId, StorageMode,
        TenantId, TruthStatus, Verification, VerificationId, VerificationStatus,
    };
    use hartevo_effect_broker::{
        BrokerError, DurableEffectLedger, EffectBroker, EffectExecutor, EffectPolicy,
        EffectRateLimit, EffectVerifier, LedgerClaim, LedgerError, ProviderFailure,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup_store() -> (ProjectStore, ProjectId) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project_id = ProjectId::from("project-auth");
        store
            .save_project(
                &Project::create_local(
                    TenantId::from("tenant-auth"),
                    project_id.clone(),
                    "Authorization project",
                    "",
                    "/tmp/hartevo-auth",
                    StorageMode::LocalExisting,
                )
                .expect("project"),
            )
            .expect("persist project");
        (store, project_id)
    }

    fn connect(store: &mut ProjectStore, project_id: &ProjectId) -> Connection {
        let mut connection = Connection::register(
            ConnectionId::from("connection-1"),
            TenantId::from("tenant-auth"),
            project_id.clone(),
            "fixture-provider",
            AccountId::from("account-1"),
            "external-account-1",
            ["publish.write".into()],
            now(),
        )
        .expect("connection");
        store
            .create_connection(
                &connection,
                "connection.registered",
                &serde_json::json!({}),
                now(),
            )
            .expect("create connection");
        connection.begin_probe(now()).expect("begin probe");
        store
            .update_connection(
                &connection,
                1,
                "connection.probe_started",
                &serde_json::json!({}),
                now(),
            )
            .expect("persist probing");
        connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "external-account-1".into(),
                    granted_scopes: BTreeSet::from(["publish.write".into()]),
                    probed_at: now(),
                    valid_until: now() + Duration::hours(4),
                    credential_expires_at: now() + Duration::hours(4),
                    evidence_digest: "a".repeat(64),
                },
                now(),
            )
            .expect("apply probe");
        store
            .update_connection(
                &connection,
                2,
                "connection.probed",
                &serde_json::json!({}),
                now(),
            )
            .expect("persist connected");
        connection
    }

    fn persist_active_social_consent(
        store: &mut ProjectStore,
        project_id: &ProjectId,
    ) -> ConsentRecord {
        let person = hartevo_domain_kernel::Person::create(
            hartevo_domain_kernel::PersonId::from("person-1"),
            TenantId::from("tenant-auth"),
            project_id.clone(),
            "Consent subject",
            None,
            vec![],
        )
        .expect("person");
        store
            .create_person(&person, "person.created", &serde_json::json!({}), now())
            .expect("persist person");
        let record = ConsentRecord::grant(
            ConsentRecordId::from("consent-1"),
            TenantId::from("tenant-auth"),
            project_id.clone(),
            hartevo_domain_kernel::PersonId::from("person-1"),
            ConsentPurpose::DirectOutreach,
            ContactChannel::SocialDirectMessage,
            "US",
            LegalBasis::ExplicitConsent,
            "signed creator agreement",
            "e".repeat(64),
            now(),
            Some(now() + Duration::days(30)),
        )
        .expect("consent");
        store
            .create_consent_record(&record, "consent.granted", &serde_json::json!({}), now())
            .expect("persist consent");
        record
    }

    fn mission_with_effect(
        project_id: &ProjectId,
        consent_record_id: Option<ConsentRecordId>,
        consent_requirement: Option<ConsentRequirement>,
    ) -> (Mission, EffectId) {
        let mut mission = Mission::compile(
            TenantId::from("tenant-auth"),
            MissionId::from("mission-auth"),
            project_id.clone(),
            "Authorized publish",
            MissionContract::bootstrap(
                "Publish only with current authorization",
                ["channel.publish".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("research");
        let consent = if consent_record_id.is_some() {
            ConsentState::Confirmed
        } else {
            ConsentState::NotRequired
        };
        let effect_id = mission
            .propose_effect(
                EffectSpec {
                    id: EffectId::from("effect-auth"),
                    actor_id: ActorId::from("user-1"),
                    capability: "channel.publish".into(),
                    provider: "fixture-provider".into(),
                    connection_id: Some(ConnectionId::from("connection-1")),
                    account_id: Some(AccountId::from("account-1")),
                    required_scopes: BTreeSet::from(["publish.write".into()]),
                    effect_class: EffectClass::ExternalWrite,
                    description: "Publish exact approved artifact".into(),
                    target_resource: "fixture://publication/1".into(),
                    audience_digest: None,
                    payload_digest: "b".repeat(64),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "UTC".into(),
                    consent,
                    consent_record_id,
                    consent_requirement,
                    conversation_guard: None,
                    creator_contact_guard: None,
                    policy_version: "policy-v1".into(),
                    risk: EffectRisk::High,
                    idempotency_key: "authorized-publish-v1".into(),
                    amount: hartevo_domain_kernel::Money::zero(
                        CurrencyCode::parse("USD").expect("USD"),
                    ),
                    expires_at: now() + Duration::hours(1),
                },
                now(),
            )
            .expect("effect");
        (mission, effect_id)
    }

    fn effect_policy() -> EffectPolicy {
        EffectPolicy {
            version: "policy-v1".into(),
            allowed_capabilities: BTreeSet::from(["channel.publish".into()]),
            allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
            max_amounts_minor: BTreeMap::from([(CurrencyCode::parse("USD").expect("USD"), 0)]),
            rate_limits: vec![EffectRateLimit {
                rule_id: "fixture-publish-per-minute".into(),
                provider: "fixture-provider".into(),
                capability: "channel.publish".into(),
                max_executions: 10,
                window_seconds: 60,
            }],
        }
    }

    fn broker() -> EffectBroker {
        EffectBroker::new(effect_policy(), "authorization-test-worker")
    }

    #[derive(Default)]
    struct CountingExecutor {
        calls: usize,
    }

    impl EffectExecutor for CountingExecutor {
        fn execute(&mut self, effect: &Effect) -> Result<Receipt, ProviderFailure> {
            self.calls += 1;
            Ok(Receipt {
                id: ReceiptId::from("receipt-1"),
                provider: effect.provider.clone(),
                external_id: "external-write-1".into(),
                accepted_at: now() + Duration::minutes(5),
                request_digest: effect.approval_digest(),
                response_digest: "c".repeat(64),
            })
        }
    }

    struct ConfirmingVerifier;

    impl EffectVerifier for ConfirmingVerifier {
        fn verify(&mut self, _effect: &Effect, receipt: &Receipt) -> Verification {
            Verification {
                id: VerificationId::from("verification-1"),
                status: VerificationStatus::Confirmed,
                verifier: "fixture-readback".into(),
                independent: true,
                observed_at: now() + Duration::minutes(6),
                evidence_digest: "d".repeat(64),
                receipt_id: receipt.id.clone(),
            }
        }
    }

    #[test]
    fn revocation_after_approval_blocks_provider_execution() {
        let (mut store, project_id) = setup_store();
        let mut connection = connect(&mut store, &project_id);
        let mut no_op_revision = connection.snapshot();
        no_op_revision.revision += 1;
        no_op_revision.updated_at += Duration::seconds(1);
        let forged = Connection::restore(no_op_revision).expect("internally valid forged snapshot");
        assert!(matches!(
            store.update_connection(
                &forged,
                3,
                "connection.forged_noop",
                &serde_json::json!({}),
                now() + Duration::seconds(1),
            ),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "connection command transition",
                ..
            })
        ));
        assert_eq!(
            store
                .load_connection(&project_id, connection.id())
                .expect("connection unchanged"),
            connection
        );
        let (mut mission, effect_id) = mission_with_effect(&project_id, None, None);
        let mut broker = broker();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &store,
                now() + Duration::minutes(1),
            )
            .expect("approval while connected");
        connection
            .revoke(now() + Duration::minutes(2))
            .expect("revoke");
        store
            .update_connection(
                &connection,
                3,
                "connection.revoked",
                &serde_json::json!({}),
                now() + Duration::minutes(2),
            )
            .expect("persist revoke");
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut store,
            &mut executor,
            &mut verifier,
            now() + Duration::minutes(3),
        );

        assert_eq!(
            result,
            Err(BrokerError::Permission(
                PermissionFailure::ConnectionNotConnected
            ))
        );
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn successful_reprobe_with_new_evidence_invalidates_the_old_approval() {
        let (mut store, project_id) = setup_store();
        let mut connection = connect(&mut store, &project_id);
        let (mut mission, effect_id) = mission_with_effect(&project_id, None, None);
        let mut broker = broker();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &store,
                now() + Duration::minutes(1),
            )
            .expect("approval under the original probe evidence");

        connection
            .begin_probe(now() + Duration::minutes(2))
            .expect("reprobe starts");
        store
            .update_connection(
                &connection,
                3,
                "connection.probe_started",
                &serde_json::json!({}),
                now() + Duration::minutes(2),
            )
            .expect("persist reprobe start");
        connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "external-account-1".into(),
                    granted_scopes: BTreeSet::from(["publish.write".into()]),
                    probed_at: now() + Duration::minutes(3),
                    valid_until: now() + Duration::hours(4),
                    credential_expires_at: now() + Duration::hours(4),
                    evidence_digest: "f".repeat(64),
                },
                now() + Duration::minutes(3),
            )
            .expect("reprobe remains connected");
        store
            .update_connection(
                &connection,
                4,
                "connection.probed",
                &serde_json::json!({}),
                now() + Duration::minutes(3),
            )
            .expect("persist new probe evidence");
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut store,
            &mut executor,
            &mut verifier,
            now() + Duration::minutes(4),
        );

        assert_eq!(result, Err(BrokerError::PermissionEvidenceChanged));
        assert_eq!(executor.calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            hartevo_domain_kernel::EffectStatus::Approved
        );
    }

    #[test]
    fn unchanged_permission_revision_passes_the_transactional_claim_fence() {
        let (mut store, project_id) = setup_store();
        connect(&mut store, &project_id);
        let (mut mission, effect_id) = mission_with_effect(&project_id, None, None);
        let mut broker = broker();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &store,
                now() + Duration::minutes(1),
            )
            .expect("approval");
        store
            .save_mission(&mission)
            .expect("persist approved mission");
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker
            .execute_and_verify(
                &mut mission,
                &effect_id,
                &mut store,
                &mut executor,
                &mut verifier,
                now() + Duration::minutes(2),
            )
            .expect("unchanged revision remains authorized at durable claim");

        assert_eq!(
            result.disposition,
            hartevo_effect_broker::ExecutionDisposition::Executed
        );
        assert_eq!(executor.calls, 1);
    }

    #[test]
    fn durable_receipt_recovers_after_connection_revocation_without_a_second_provider_write() {
        let (mut store, project_id) = setup_store();
        let mut connection = connect(&mut store, &project_id);
        let (mut mission, effect_id) = mission_with_effect(&project_id, None, None);
        let mut broker = broker();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &store,
                now() + Duration::minutes(1),
            )
            .expect("approval");
        store
            .save_mission(&mission)
            .expect("persist approved mission");
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let context = effect_policy()
            .execution_claim_context(
                &effect,
                store
                    .authorize(&effect, now() + Duration::minutes(1))
                    .expect("authorized dispatch evidence"),
            )
            .expect("claim context");
        let LedgerClaim::Acquired {
            lease,
            receipt: None,
            ..
        } = store
            .claim(
                &effect,
                Some(&context),
                "crash-before-mission-projection",
                now() + Duration::minutes(1),
                now() + Duration::minutes(2),
            )
            .expect("initial execution claim")
        else {
            panic!("initial execution claim must be acquired")
        };
        let receipt = Receipt {
            id: ReceiptId::from("receipt-crash-recovery"),
            provider: effect.provider.clone(),
            external_id: "external-crash-recovery".into(),
            accepted_at: now() + Duration::minutes(2),
            request_digest: effect.approval_digest(),
            response_digest: "9".repeat(64),
        };
        store
            .record_receipt(&effect, &lease, &receipt, now() + Duration::minutes(2))
            .expect("receipt committed before simulated crash");

        connection
            .revoke(now() + Duration::minutes(3))
            .expect("revoke after provider dispatch");
        store
            .update_connection(
                &connection,
                3,
                "connection.revoked",
                &serde_json::json!({}),
                now() + Duration::minutes(3),
            )
            .expect("persist revocation");
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker
            .execute_and_verify(
                &mut mission,
                &effect_id,
                &mut store,
                &mut executor,
                &mut verifier,
                now() + Duration::minutes(4),
            )
            .expect("resume verification from durable receipt");

        assert_eq!(
            result.disposition,
            hartevo_effect_broker::ExecutionDisposition::ReusedIdempotentReceipt
        );
        assert_eq!(result.receipt, receipt);
        assert_eq!(executor.calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Verified
        );
    }

    #[test]
    fn stale_preflight_revision_is_rejected_inside_claim_without_ledger_side_effects() {
        let (mut store, project_id) = setup_store();
        let mut connection = connect(&mut store, &project_id);
        let (mut mission, effect_id) = mission_with_effect(&project_id, None, None);
        let broker = broker();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &store,
                now() + Duration::minutes(1),
            )
            .expect("approval");
        store
            .save_mission(&mission)
            .expect("persist approved mission");
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let stale_context = effect_policy()
            .execution_claim_context(
                &effect,
                store
                    .authorize(&effect, now() + Duration::minutes(1))
                    .expect("preflight permission evidence"),
            )
            .expect("claim context");

        connection
            .begin_probe(now() + Duration::minutes(2))
            .expect("permission revision advances");
        store
            .update_connection(
                &connection,
                3,
                "connection.probe_started",
                &serde_json::json!({}),
                now() + Duration::minutes(2),
            )
            .expect("commit permission change before claim");

        assert_eq!(
            store.claim(
                &effect,
                Some(&stale_context),
                "stale-preflight-worker",
                now() + Duration::minutes(3),
                now() + Duration::minutes(4),
            ),
            Err(LedgerError::ScopeConflict)
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
            .expect("effect ledger counts");
        assert_eq!(counts, (0, 0, 0, 0, 0));
    }

    #[test]
    fn consent_withdrawal_after_approval_blocks_provider_execution() {
        let (mut store, project_id) = setup_store();
        connect(&mut store, &project_id);
        let mut record = persist_active_social_consent(&mut store, &project_id);
        let record_id = record.id.clone();
        let mut rewritten_scope = record.clone();
        rewritten_scope.purpose = ConsentPurpose::EmailMarketing;
        rewritten_scope
            .withdraw(now() + Duration::minutes(1))
            .expect("internally valid rewritten consent");
        assert!(matches!(
            store.update_consent_record(
                &rewritten_scope,
                1,
                "consent.scope_rewritten",
                &serde_json::json!({}),
                now() + Duration::minutes(1),
            ),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "consent command transition",
                ..
            })
        ));
        assert_eq!(
            store
                .load_consent_record(&project_id, &record.id)
                .expect("consent unchanged"),
            record
        );
        let requirement = ConsentRequirement {
            person_id: hartevo_domain_kernel::PersonId::from("person-1"),
            purpose: ConsentPurpose::DirectOutreach,
            channel: ContactChannel::SocialDirectMessage,
            market: "US".into(),
        };
        let (mut mission, effect_id) =
            mission_with_effect(&project_id, Some(record_id), Some(requirement));
        let mut broker = broker();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &store,
                now() + Duration::minutes(1),
            )
            .expect("approval while consent active");
        record
            .withdraw(now() + Duration::minutes(2))
            .expect("withdraw");
        store
            .update_consent_record(
                &record,
                1,
                "consent.withdrawn",
                &serde_json::json!({}),
                now() + Duration::minutes(2),
            )
            .expect("persist withdrawal");
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut store,
            &mut executor,
            &mut verifier,
            now() + Duration::minutes(3),
        );

        assert_eq!(
            result,
            Err(BrokerError::Permission(
                PermissionFailure::ConsentNotPermitted
            ))
        );
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn truth_revisions_are_immutable_and_head_update_is_optimistic() {
        let (mut store, project_id) = setup_store();
        let first = TruthFact::create(
            FactId::from("fact-market"),
            TenantId::from("tenant-auth"),
            project_id.clone(),
            "market.readiness",
            None,
            vec![],
            TruthStatus::Unknown,
            None,
            "US",
            "en",
            now(),
            now(),
            None,
            "0".parse().expect("decimal"),
            now(),
        )
        .expect("truth fact");
        store
            .create_truth_fact(&first, "truth.created", &serde_json::json!({}), now())
            .expect("persist first");
        let revised_at = now() + Duration::minutes(1);
        let second = first
            .revise(
                None,
                vec![],
                TruthStatus::Unknown,
                None,
                "0".parse().expect("decimal"),
                revised_at,
                "new collection still has no authoritative answer",
                ActorId::from("analyst-1"),
                revised_at,
            )
            .expect("revision");
        store
            .revise_truth_fact(
                &second,
                1,
                "truth.revised",
                &serde_json::json!({}),
                revised_at,
            )
            .expect("persist revision");

        assert_eq!(
            store
                .load_truth_fact(&project_id, &first.id)
                .expect("head")
                .version,
            2
        );
        assert_eq!(
            store
                .load_truth_fact_revision(&project_id, &first.id, 1)
                .expect("history"),
            first
        );
        assert!(matches!(
            store.revise_truth_fact(
                &second,
                1,
                "truth.stale_retry",
                &serde_json::json!({}),
                revised_at,
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
    }
}

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    CreatorApplication, CreatorApplicationOrigin, CreatorCandidate, CreatorHiring,
    CreatorHiringAward, CreatorHiringId, CreatorInvitation, CreatorListingPublication,
    CurrencyCode, Mission, MissionId, Money, PersonId, ProjectId, TenantId,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::aggregate::{PendingEvent, append_events};
use crate::normalized::update_mission_normalized_cas;
use crate::{PersistedMutation, ProjectStore, StorageError};

impl ProjectStore {
    pub fn creator_hirings_for_project(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<CreatorHiring>, StorageError> {
        self.load_project(project_id)?;
        let mut statement = self.connection.prepare(
            "SELECT id FROM creator_hirings
             WHERE project_id = ?1 ORDER BY created_at, id",
        )?;
        let ids = statement
            .query_map(params![project_id.as_str()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| self.load_creator_hiring(project_id, &CreatorHiringId::from_stable(id)))
            .collect()
    }

    pub fn update_creator_hiring_and_mission_atomic(
        &mut self,
        hiring: &CreatorHiring,
        expected_hiring_revision: u64,
        mission: &Mission,
        expected_mission_revision: u64,
        hiring_events: &[PendingEvent],
        mission_events: &[PendingEvent],
    ) -> Result<(), StorageError> {
        if hiring.state_revision != expected_hiring_revision.saturating_add(1) {
            return Err(StorageError::UnexpectedNextRevision {
                expected: expected_hiring_revision.saturating_add(1),
                actual: hiring.state_revision,
            });
        }
        if mission.revision <= expected_mission_revision {
            return Err(StorageError::UnexpectedNewerRevision {
                expected_revision: expected_mission_revision,
                actual: mission.revision,
            });
        }
        if hiring_events.is_empty() || mission_events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if hiring.tenant_id != mission.tenant_id
            || hiring.project_id != mission.project_id
            || hiring.mission_id != mission.id
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        let transaction = self.connection.transaction()?;
        ensure_scope(&transaction, hiring)?;
        update_hiring_row(&transaction, hiring, expected_hiring_revision)?;
        persist_children(&transaction, hiring)?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        append_events(
            &transaction,
            hiring.tenant_id.as_str(),
            hiring.project_id.as_str(),
            Some(hiring.mission_id.as_str()),
            "creator_hiring",
            hiring.id.as_str(),
            hiring_events,
        )?;
        append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission",
            mission.id.as_str(),
            mission_events,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn create_creator_hiring(
        &mut self,
        hiring: &CreatorHiring,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        if hiring.state_revision != 1 {
            return Err(StorageError::InvalidInitialRevision(hiring.state_revision));
        }
        let transaction = self.connection.transaction()?;
        ensure_scope(&transaction, hiring)?;
        insert_hiring(&transaction, hiring)?;
        persist_children(&transaction, hiring)?;
        finish(transaction, hiring, event_type, payload, recorded_at)
    }

    pub fn update_creator_hiring(
        &mut self,
        hiring: &CreatorHiring,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        if hiring.state_revision != expected_revision.saturating_add(1) {
            return Err(StorageError::UnexpectedNextRevision {
                expected: expected_revision.saturating_add(1),
                actual: hiring.state_revision,
            });
        }
        let transaction = self.connection.transaction()?;
        ensure_scope(&transaction, hiring)?;
        update_hiring_row(&transaction, hiring, expected_revision)?;
        persist_children(&transaction, hiring)?;
        finish(transaction, hiring, event_type, payload, recorded_at)
    }

    pub fn load_creator_hiring(
        &self,
        project_id: &ProjectId,
        hiring_id: &CreatorHiringId,
    ) -> Result<CreatorHiring, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT id, tenant_id, project_id, mission_id, title, brief_digest,
                        bounty_minor, currency, market, application_deadline, due_at,
                        offer_digest, status, state_revision, created_at, updated_at
                 FROM creator_hirings WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), hiring_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, String>(14)?,
                        row.get::<_, String>(15)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| missing_hiring(project_id, hiring_id))?;
        let mut hiring = CreatorHiring {
            id: CreatorHiringId::from_stable(row.0),
            tenant_id: TenantId::from_stable(row.1),
            project_id: ProjectId::from_stable(row.2),
            mission_id: MissionId::from_stable(row.3),
            title: row.4,
            brief_digest: row.5,
            bounty: Money::new(row.6, parse_currency(&row.7)?),
            market: row.8,
            application_deadline: parse_time(&row.9)?,
            due_at: parse_time(&row.10)?,
            status: decode_enum(&row.12)?,
            candidates: self.load_hiring_candidates(project_id, hiring_id)?,
            listing: self.load_hiring_listing(project_id, hiring_id)?,
            invitations: self.load_hiring_invitations(project_id, hiring_id)?,
            applications: self.load_hiring_applications(project_id, hiring_id)?,
            award: self.load_hiring_award(project_id, hiring_id)?,
            state_revision: checked_u64(row.13, "creator hiring state revision")?,
            created_at: parse_time(&row.14)?,
            updated_at: parse_time(&row.15)?,
        };
        if hiring.offer_digest() != row.11 {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "creator hiring contract",
                id: hiring.id.to_string(),
            });
        }
        // Keep deterministic order even if a database query plan changes.
        hiring.candidates.sort_by(|left, right| {
            left.added_at
                .cmp(&right.added_at)
                .then(left.creator_id.cmp(&right.creator_id))
        });
        hiring.invitations.sort_by(|left, right| {
            left.prepared_at
                .cmp(&right.prepared_at)
                .then(left.creator_id.cmp(&right.creator_id))
        });
        hiring.applications.sort_by(|left, right| {
            left.submitted_at
                .cmp(&right.submitted_at)
                .then(left.id.cmp(&right.id))
        });
        Ok(hiring)
    }

    fn load_hiring_candidates(
        &self,
        project_id: &ProjectId,
        hiring_id: &CreatorHiringId,
    ) -> Result<Vec<CreatorCandidate>, StorageError> {
        load_records(
            &self.connection,
            "SELECT record_json, immutable_digest FROM creator_hiring_candidates
             WHERE project_id = ?1 AND hiring_id = ?2 ORDER BY ordinal",
            project_id,
            hiring_id,
            candidate_immutable_digest,
            "creator candidate",
        )
    }

    fn load_hiring_invitations(
        &self,
        project_id: &ProjectId,
        hiring_id: &CreatorHiringId,
    ) -> Result<Vec<CreatorInvitation>, StorageError> {
        load_records(
            &self.connection,
            "SELECT record_json, immutable_digest FROM creator_hiring_invitations
             WHERE project_id = ?1 AND hiring_id = ?2 ORDER BY prepared_at, creator_id",
            project_id,
            hiring_id,
            invitation_immutable_digest,
            "creator invitation",
        )
    }

    fn load_hiring_applications(
        &self,
        project_id: &ProjectId,
        hiring_id: &CreatorHiringId,
    ) -> Result<Vec<CreatorApplication>, StorageError> {
        load_records(
            &self.connection,
            "SELECT record_json, immutable_digest FROM creator_hiring_applications
             WHERE project_id = ?1 AND hiring_id = ?2 ORDER BY submitted_at, id",
            project_id,
            hiring_id,
            application_immutable_digest,
            "creator application",
        )
    }

    fn load_hiring_listing(
        &self,
        project_id: &ProjectId,
        hiring_id: &CreatorHiringId,
    ) -> Result<Option<CreatorListingPublication>, StorageError> {
        load_optional_record(
            &self.connection,
            "SELECT record_json, immutable_digest FROM creator_hiring_listings
             WHERE project_id = ?1 AND hiring_id = ?2",
            project_id,
            hiring_id,
            full_record_digest::<CreatorListingPublication>,
            "creator listing",
        )
    }

    fn load_hiring_award(
        &self,
        project_id: &ProjectId,
        hiring_id: &CreatorHiringId,
    ) -> Result<Option<CreatorHiringAward>, StorageError> {
        load_optional_record(
            &self.connection,
            "SELECT record_json, immutable_digest FROM creator_hiring_awards
             WHERE project_id = ?1 AND hiring_id = ?2",
            project_id,
            hiring_id,
            full_record_digest::<CreatorHiringAward>,
            "creator hiring award",
        )
    }
}

pub(crate) fn ensure_scope(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
) -> Result<(), StorageError> {
    let exists = transaction
        .query_row(
            "SELECT 1 FROM missions
             WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3",
            params![
                hiring.tenant_id.as_str(),
                hiring.project_id.as_str(),
                hiring.mission_id.as_str()
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Err(StorageError::MissionNotFound {
            project_id: hiring.project_id.clone(),
            mission_id: hiring.mission_id.clone(),
        });
    }
    Ok(())
}

pub(crate) fn insert_hiring(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO creator_hirings
           (id, tenant_id, project_id, mission_id, title, brief_digest, bounty_minor, currency,
            market, application_deadline, due_at, offer_digest, status, state_revision,
            created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            hiring.id.as_str(),
            hiring.tenant_id.as_str(),
            hiring.project_id.as_str(),
            hiring.mission_id.as_str(),
            hiring.title,
            hiring.brief_digest,
            hiring.bounty.amount_minor,
            hiring.bounty.currency.as_str(),
            hiring.market,
            hiring.application_deadline.to_rfc3339(),
            hiring.due_at.to_rfc3339(),
            hiring.offer_digest(),
            enum_name(&hiring.status)?,
            to_sql_u64(hiring.state_revision)?,
            hiring.created_at.to_rfc3339(),
            hiring.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn update_hiring_row(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let stored_offer_digest = transaction
        .query_row(
            "SELECT offer_digest FROM creator_hirings WHERE project_id = ?1 AND id = ?2",
            params![hiring.project_id.as_str(), hiring.id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| missing_hiring(&hiring.project_id, &hiring.id))?;
    if stored_offer_digest != hiring.offer_digest() {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "creator hiring contract",
            id: hiring.id.to_string(),
        });
    }
    let updated = transaction.execute(
        "UPDATE creator_hirings SET status = ?3, state_revision = ?4, updated_at = ?5
         WHERE project_id = ?1 AND id = ?2 AND state_revision = ?6",
        params![
            hiring.project_id.as_str(),
            hiring.id.as_str(),
            enum_name(&hiring.status)?,
            to_sql_u64(hiring.state_revision)?,
            hiring.updated_at.to_rfc3339(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("creator_hiring:{}", hiring.id),
            expected_revision,
        });
    }
    Ok(())
}

pub(crate) fn persist_children(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
) -> Result<(), StorageError> {
    persist_candidates(transaction, hiring)?;
    persist_listing(transaction, hiring)?;
    persist_invitations(transaction, hiring)?;
    persist_applications(transaction, hiring)?;
    persist_award(transaction, hiring)
}

fn persist_candidates(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
) -> Result<(), StorageError> {
    for (ordinal, candidate) in hiring.candidates.iter().enumerate() {
        let immutable_digest = candidate_immutable_digest(candidate)?;
        let record_json = serde_json::to_string(candidate)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO creator_hiring_candidates
               (project_id, hiring_id, creator_id, partner_id, ordinal, person_id, supply_class,
                contact_permission, permission_evidence_digest, identity_evidence_digest,
                fit_evidence_digest, status, added_at, immutable_digest, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                hiring.project_id.as_str(),
                hiring.id.as_str(),
                candidate.creator_id.as_str(),
                candidate.partner_id.as_str(),
                to_sql_usize(ordinal)?,
                candidate.person_id.as_ref().map(PersonId::as_str),
                enum_name(&candidate.supply_class)?,
                enum_name(&candidate.contact_permission)?,
                candidate.permission_evidence_digest,
                candidate.identity_evidence_digest,
                candidate.fit_evidence_digest,
                enum_name(&candidate.status)?,
                candidate.added_at.to_rfc3339(),
                immutable_digest,
                record_json,
            ],
        )?;
        if inserted == 0 {
            verify_immutable(
                transaction,
                &hiring.project_id,
                &hiring.id,
                &immutable_digest,
                ImmutableChild {
                    table: "creator_hiring_candidates",
                    id_column: "creator_id",
                    id: candidate.creator_id.as_str(),
                    kind: "creator candidate",
                },
            )?;
            transaction.execute(
                "UPDATE creator_hiring_candidates SET status = ?4, record_json = ?5
                 WHERE project_id = ?1 AND hiring_id = ?2 AND creator_id = ?3",
                params![
                    hiring.project_id.as_str(),
                    hiring.id.as_str(),
                    candidate.creator_id.as_str(),
                    enum_name(&candidate.status)?,
                    record_json,
                ],
            )?;
        }
    }
    Ok(())
}

fn persist_listing(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
) -> Result<(), StorageError> {
    let Some(listing) = &hiring.listing else {
        return Ok(());
    };
    let digest = full_record_digest(listing)?;
    let record_json = serde_json::to_string(listing)?;
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO creator_hiring_listings
           (project_id, hiring_id, effect_id, scope_digest, receipt_id, verification_id,
            verified_at, immutable_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            hiring.project_id.as_str(),
            hiring.id.as_str(),
            listing.proof.effect_id.as_str(),
            listing.proof.scope_digest,
            listing.proof.receipt_id.as_str(),
            listing.proof.verification_id.as_str(),
            listing.proof.verified_at.to_rfc3339(),
            digest,
            record_json,
        ],
    )?;
    if inserted == 0 {
        verify_singleton_immutable(
            transaction,
            "creator_hiring_listings",
            hiring,
            &digest,
            "creator listing",
        )?;
    }
    Ok(())
}

fn persist_invitations(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
) -> Result<(), StorageError> {
    for invitation in &hiring.invitations {
        let digest = invitation_immutable_digest(invitation)?;
        let record_json = serde_json::to_string(invitation)?;
        let verified_at = invitation
            .proof
            .as_ref()
            .map(|proof| proof.verified_at.to_rfc3339());
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO creator_hiring_invitations
               (project_id, hiring_id, creator_id, effect_id, scope_digest, prepared_at,
                verified_at, immutable_digest, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                hiring.project_id.as_str(),
                hiring.id.as_str(),
                invitation.creator_id.as_str(),
                invitation.effect_id.as_str(),
                invitation.scope_digest,
                invitation.prepared_at.to_rfc3339(),
                verified_at,
                digest,
                record_json,
            ],
        )?;
        if inserted == 0 {
            verify_immutable(
                transaction,
                &hiring.project_id,
                &hiring.id,
                &digest,
                ImmutableChild {
                    table: "creator_hiring_invitations",
                    id_column: "creator_id",
                    id: invitation.creator_id.as_str(),
                    kind: "creator invitation",
                },
            )?;
            let existing_verified: Option<String> = transaction.query_row(
                "SELECT verified_at FROM creator_hiring_invitations
                 WHERE project_id = ?1 AND hiring_id = ?2 AND creator_id = ?3",
                params![
                    hiring.project_id.as_str(),
                    hiring.id.as_str(),
                    invitation.creator_id.as_str()
                ],
                |row| row.get(0),
            )?;
            if existing_verified.is_some() && existing_verified != verified_at {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "verified creator invitation",
                    id: invitation.effect_id.to_string(),
                });
            }
            transaction.execute(
                "UPDATE creator_hiring_invitations SET verified_at = ?4, record_json = ?5
                 WHERE project_id = ?1 AND hiring_id = ?2 AND creator_id = ?3",
                params![
                    hiring.project_id.as_str(),
                    hiring.id.as_str(),
                    invitation.creator_id.as_str(),
                    verified_at,
                    record_json,
                ],
            )?;
        }
    }
    Ok(())
}

fn persist_applications(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
) -> Result<(), StorageError> {
    for application in &hiring.applications {
        let digest = application_immutable_digest(application)?;
        let record_json = serde_json::to_string(application)?;
        let origin_effect_id = origin_effect_id(&application.origin);
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO creator_hiring_applications
               (project_id, hiring_id, id, creator_id, partner_id, origin_effect_id,
                offer_digest, proposed_amount_minor, currency, proposal_digest,
                rights_ack_digest, submitted_at, status, immutable_digest, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                hiring.project_id.as_str(),
                hiring.id.as_str(),
                application.id.as_str(),
                application.creator_id.as_str(),
                application.partner_id.as_str(),
                origin_effect_id,
                application.offer_digest,
                application.proposed_amount.amount_minor,
                application.proposed_amount.currency.as_str(),
                application.proposal_digest,
                application.rights_acknowledgement_digest,
                application.submitted_at.to_rfc3339(),
                enum_name(&application.status)?,
                digest,
                record_json,
            ],
        )?;
        if inserted == 0 {
            verify_immutable(
                transaction,
                &hiring.project_id,
                &hiring.id,
                &digest,
                ImmutableChild {
                    table: "creator_hiring_applications",
                    id_column: "id",
                    id: application.id.as_str(),
                    kind: "creator application",
                },
            )?;
            transaction.execute(
                "UPDATE creator_hiring_applications SET status = ?4, record_json = ?5
                 WHERE project_id = ?1 AND hiring_id = ?2 AND id = ?3",
                params![
                    hiring.project_id.as_str(),
                    hiring.id.as_str(),
                    application.id.as_str(),
                    enum_name(&application.status)?,
                    record_json,
                ],
            )?;
        }
    }
    Ok(())
}

fn persist_award(
    transaction: &Transaction<'_>,
    hiring: &CreatorHiring,
) -> Result<(), StorageError> {
    let Some(award) = &hiring.award else {
        return Ok(());
    };
    let digest = full_record_digest(award)?;
    let record_json = serde_json::to_string(award)?;
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO creator_hiring_awards
           (project_id, hiring_id, application_id, creator_id, partner_id, offer_digest,
            amount_minor, currency, selected_by, selection_evidence_digest, selected_at,
            immutable_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            hiring.project_id.as_str(),
            hiring.id.as_str(),
            award.application_id.as_str(),
            award.creator_id.as_str(),
            award.partner_id.as_str(),
            award.offer_digest,
            award.bounty.amount_minor,
            award.bounty.currency.as_str(),
            award.selected_by.as_str(),
            award.selection_evidence_digest,
            award.selected_at.to_rfc3339(),
            digest,
            record_json,
        ],
    )?;
    if inserted == 0 {
        verify_singleton_immutable(
            transaction,
            "creator_hiring_awards",
            hiring,
            &digest,
            "creator hiring award",
        )?;
    }
    Ok(())
}

fn finish(
    transaction: Transaction<'_>,
    hiring: &CreatorHiring,
    event_type: &str,
    payload: &Value,
    recorded_at: DateTime<Utc>,
) -> Result<PersistedMutation, StorageError> {
    if event_type.trim().is_empty() {
        return Err(StorageError::EmptyEventType);
    }
    let payload_json = serde_json::to_string(payload)?;
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            hiring.tenant_id.as_str(),
            hiring.project_id.as_str(),
            hiring.mission_id.as_str(),
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
         VALUES (?1, ?2, ?3, 'creator_hiring', ?4, ?5, ?6, ?7, ?7)",
        params![
            hiring.tenant_id.as_str(),
            hiring.project_id.as_str(),
            hiring.mission_id.as_str(),
            hiring.id.as_str(),
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    let outbox_sequence = transaction.last_insert_rowid();
    transaction.commit()?;
    Ok(PersistedMutation {
        event_sequence,
        outbox_sequence,
        state_revision: hiring.state_revision,
    })
}

#[derive(Clone, Copy)]
struct ImmutableChild<'a> {
    table: &'a str,
    id_column: &'a str,
    id: &'a str,
    kind: &'static str,
}

fn verify_immutable(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    hiring_id: &CreatorHiringId,
    expected_digest: &str,
    child: ImmutableChild<'_>,
) -> Result<(), StorageError> {
    let sql = format!(
        "SELECT immutable_digest FROM {}
         WHERE project_id = ?1 AND hiring_id = ?2 AND {} = ?3",
        child.table, child.id_column
    );
    let stored = transaction
        .query_row(
            &sql,
            params![project_id.as_str(), hiring_id.as_str(), child.id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: child.kind,
            project_id: project_id.clone(),
            id: child.id.to_owned(),
        })?;
    if stored != expected_digest {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: child.kind,
            id: child.id.to_owned(),
        });
    }
    Ok(())
}

fn verify_singleton_immutable(
    transaction: &Transaction<'_>,
    table: &str,
    hiring: &CreatorHiring,
    expected_digest: &str,
    kind: &'static str,
) -> Result<(), StorageError> {
    let sql =
        format!("SELECT immutable_digest FROM {table} WHERE project_id = ?1 AND hiring_id = ?2");
    let stored = transaction.query_row(
        &sql,
        params![hiring.project_id.as_str(), hiring.id.as_str()],
        |row| row.get::<_, String>(0),
    )?;
    if stored != expected_digest {
        return Err(StorageError::ImmutableRecordMismatch {
            kind,
            id: hiring.id.to_string(),
        });
    }
    Ok(())
}

fn load_records<T>(
    connection: &rusqlite::Connection,
    sql: &str,
    project_id: &ProjectId,
    hiring_id: &CreatorHiringId,
    digest: fn(&T) -> Result<String, StorageError>,
    kind: &'static str,
) -> Result<Vec<T>, StorageError>
where
    T: DeserializeOwned,
{
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(params![project_id.as_str(), hiring_id.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    rows.map(|row| {
        let (record_json, immutable_digest) = row?;
        let record = serde_json::from_str::<T>(&record_json)?;
        if digest(&record)? != immutable_digest {
            return Err(StorageError::ImmutableRecordMismatch {
                kind,
                id: hiring_id.to_string(),
            });
        }
        Ok(record)
    })
    .collect()
}

fn load_optional_record<T>(
    connection: &rusqlite::Connection,
    sql: &str,
    project_id: &ProjectId,
    hiring_id: &CreatorHiringId,
    digest: fn(&T) -> Result<String, StorageError>,
    kind: &'static str,
) -> Result<Option<T>, StorageError>
where
    T: DeserializeOwned,
{
    let row = connection
        .query_row(
            sql,
            params![project_id.as_str(), hiring_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    row.map(|(record_json, immutable_digest)| {
        let record = serde_json::from_str::<T>(&record_json)?;
        if digest(&record)? != immutable_digest {
            return Err(StorageError::ImmutableRecordMismatch {
                kind,
                id: hiring_id.to_string(),
            });
        }
        Ok(record)
    })
    .transpose()
}

fn candidate_immutable_digest(candidate: &CreatorCandidate) -> Result<String, StorageError> {
    json_digest(&json!({
        "creatorId": candidate.creator_id,
        "partnerId": candidate.partner_id,
        "personId": candidate.person_id,
        "supplyClass": candidate.supply_class,
        "contactPermission": candidate.contact_permission,
        "permissionEvidenceDigest": candidate.permission_evidence_digest,
        "identityEvidenceDigest": candidate.identity_evidence_digest,
        "fitEvidenceDigest": candidate.fit_evidence_digest,
        "addedAt": candidate.added_at,
    }))
}

fn invitation_immutable_digest(invitation: &CreatorInvitation) -> Result<String, StorageError> {
    json_digest(&json!({
        "creatorId": invitation.creator_id,
        "effectId": invitation.effect_id,
        "scopeDigest": invitation.scope_digest,
        "preparedAt": invitation.prepared_at,
    }))
}

fn application_immutable_digest(application: &CreatorApplication) -> Result<String, StorageError> {
    json_digest(&json!({
        "id": application.id,
        "creatorId": application.creator_id,
        "partnerId": application.partner_id,
        "origin": application.origin,
        "offerDigest": application.offer_digest,
        "proposedAmount": application.proposed_amount,
        "proposalDigest": application.proposal_digest,
        "rightsAcknowledgementDigest": application.rights_acknowledgement_digest,
        "submittedAt": application.submitted_at,
    }))
}

fn full_record_digest<T: Serialize>(record: &T) -> Result<String, StorageError> {
    json_digest(&serde_json::to_value(record)?)
}

fn json_digest(value: &Value) -> Result<String, StorageError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn origin_effect_id(origin: &CreatorApplicationOrigin) -> &str {
    match origin {
        CreatorApplicationOrigin::VerifiedInvitation(effect_id)
        | CreatorApplicationOrigin::VerifiedListing(effect_id) => effect_id.as_str(),
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

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn parse_currency(value: &str) -> Result<CurrencyCode, StorageError> {
    CurrencyCode::parse(value).map_err(|error| StorageError::DomainDecode(error.to_string()))
}

fn checked_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn to_sql_usize(value: usize) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::DomainDecode("ordinal overflow".into()))
}

fn missing_hiring(project_id: &ProjectId, hiring_id: &CreatorHiringId) -> StorageError {
    StorageError::ScopedRecordNotFound {
        kind: "creator hiring",
        project_id: project_id.clone(),
        id: hiring_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, ActorId, ConnectionId, ContactPermission, CreatorApplicationId,
        CreatorApplicationInput, CreatorExternalProof, CreatorHiringSpec, CreatorId, EffectId,
        Mission, MissionContract, Partner, PartnerId, PartnerSupplyClass, Project, ReceiptId,
        StorageMode, Task, TaskId, TaskStatus, VerificationId,
    };

    use super::*;
    use crate::PendingEvent;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 9, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup() -> (ProjectStore, ProjectId, MissionId, Partner) {
        let mut store = ProjectStore::in_memory().expect("store");
        let tenant_id = TenantId::from("tenant-hiring-store");
        let project_id = ProjectId::from("project-hiring-store");
        let mission_id = MissionId::from("mission-hiring-store");
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Creator hiring persistence",
            "",
            PathBuf::from("/tmp/hartevo-creator-hiring-store"),
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
            tenant_id.clone(),
            mission_id.clone(),
            project_id.clone(),
            "Creator hiring",
            MissionContract::bootstrap(
                "Hire one opt-in creator",
                ["partner.engage".into(), "creator.task.publish".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-hiring-store"),
                    title: "Select creator".into(),
                    status: TaskStatus::Running,
                    capability: "partner.engage".into(),
                }],
                now(),
            )
            .expect("running");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new("mission.started", json!({}), now())],
            )
            .expect("persist mission");
        let partner = Partner::create(
            PartnerId::from("partner-hiring-store"),
            tenant_id,
            project_id.clone(),
            None,
            None,
            "Opt-in creator",
            PartnerSupplyClass::HartevoOptIn,
            ContactPermission::ExplicitOptIn,
            Some("1".repeat(64)),
        )
        .expect("partner");
        store
            .create_partner(&partner, "partner.created", &json!({}), now())
            .expect("persist partner");
        (store, project_id, mission_id, partner)
    }

    fn external_proof(scope_digest: String, at: DateTime<Utc>) -> CreatorExternalProof {
        CreatorExternalProof {
            effect_id: EffectId::from("effect-invite-store"),
            receipt_id: ReceiptId::from("receipt-invite-store"),
            verification_id: VerificationId::from("verification-invite-store"),
            provider: "hartevo-opt-in".into(),
            connection_id: ConnectionId::from("connection-invite-store"),
            account_id: AccountId::from("account-invite-store"),
            scope_digest,
            provider_receipt_digest: "2".repeat(64),
            verification_evidence_digest: "3".repeat(64),
            occurred_at: at,
            verified_at: at,
        }
    }

    fn persist_transition(
        store: &mut ProjectStore,
        hiring: &CreatorHiring,
        expected_revision: u64,
        event_type: &str,
        minute: i64,
    ) {
        store
            .update_creator_hiring(
                hiring,
                expected_revision,
                event_type,
                &json!({}),
                now() + Duration::minutes(minute),
            )
            .expect("persist hiring transition");
    }

    fn create_hiring(
        store: &mut ProjectStore,
        project_id: &ProjectId,
        mission_id: MissionId,
    ) -> CreatorHiring {
        let hiring = CreatorHiring::create(
            CreatorHiringSpec {
                id: CreatorHiringId::from("hiring-store-1"),
                tenant_id: TenantId::from("tenant-hiring-store"),
                project_id: project_id.clone(),
                mission_id,
                title: "Verified product demo".into(),
                brief_digest: "4".repeat(64),
                bounty: Money::new(25_000, CurrencyCode::parse("USD").expect("USD")),
                market: "US".into(),
                application_deadline: now() + Duration::days(3),
                due_at: now() + Duration::days(7),
            },
            now(),
        )
        .expect("hiring");
        store
            .create_creator_hiring(&hiring, "creator_hiring.created", &json!({}), now())
            .expect("persist hiring");
        hiring
    }

    fn verify_invitation(
        store: &mut ProjectStore,
        hiring: &mut CreatorHiring,
        partner: &Partner,
        creator_id: &CreatorId,
    ) {
        let revision = hiring.state_revision;
        hiring.open(now() + Duration::minutes(1)).expect("open");
        persist_transition(store, hiring, revision, "creator_hiring.opened", 1);

        let revision = hiring.state_revision;
        hiring
            .shortlist(
                partner,
                creator_id.clone(),
                "5".repeat(64),
                "6".repeat(64),
                now() + Duration::minutes(2),
            )
            .expect("shortlist");
        persist_transition(
            store,
            hiring,
            revision,
            "creator_hiring.candidate_shortlisted",
            2,
        );

        let revision = hiring.state_revision;
        let invitation_scope = hiring.invitation_scope_digest(creator_id);
        hiring
            .prepare_invitation(
                creator_id,
                EffectId::from("effect-invite-store"),
                invitation_scope.clone(),
                now() + Duration::minutes(3),
            )
            .expect("prepare invitation");
        persist_transition(
            store,
            hiring,
            revision,
            "creator_hiring.invitation_prepared",
            3,
        );

        let revision = hiring.state_revision;
        hiring
            .record_verified_invitation(
                creator_id,
                external_proof(invitation_scope, now() + Duration::minutes(4)),
                now() + Duration::minutes(4),
            )
            .expect("verify invitation");
        persist_transition(
            store,
            hiring,
            revision,
            "creator_hiring.invitation_verified",
            4,
        );
    }

    fn apply_and_award(
        store: &mut ProjectStore,
        hiring: &mut CreatorHiring,
        partner: &Partner,
        creator_id: &CreatorId,
    ) {
        let revision = hiring.state_revision;
        hiring
            .apply(
                CreatorApplicationInput {
                    id: CreatorApplicationId::from("application-store-1"),
                    creator_id: creator_id.clone(),
                    partner_id: partner.id.clone(),
                    origin: CreatorApplicationOrigin::VerifiedInvitation(EffectId::from(
                        "effect-invite-store",
                    )),
                    offer_digest: hiring.offer_digest(),
                    proposed_amount: hiring.bounty.clone(),
                    proposal_digest: "7".repeat(64),
                    rights_acknowledgement_digest: "8".repeat(64),
                    submitted_at: now() + Duration::minutes(5),
                },
                now() + Duration::minutes(5),
            )
            .expect("application");
        persist_transition(
            store,
            hiring,
            revision,
            "creator_hiring.application_received",
            5,
        );

        let revision = hiring.state_revision;
        hiring
            .award(
                &CreatorApplicationId::from("application-store-1"),
                ActorId::from("user-1"),
                "9".repeat(64),
                now() + Duration::minutes(6),
            )
            .expect("award");
        persist_transition(store, hiring, revision, "creator_hiring.awarded", 6);
    }

    #[test]
    fn creator_hiring_survives_replay_with_immutable_selection_evidence() {
        let (mut store, project_id, mission_id, partner) = setup();
        let hiring_id = CreatorHiringId::from("hiring-store-1");
        let creator_id = CreatorId::from("creator-store-1");
        let mut hiring = create_hiring(&mut store, &project_id, mission_id);
        verify_invitation(&mut store, &mut hiring, &partner, &creator_id);
        apply_and_award(&mut store, &mut hiring, &partner, &creator_id);

        let restored = store
            .load_creator_hiring(&project_id, &hiring_id)
            .expect("restore hiring");
        assert_eq!(restored, hiring);
        assert_eq!(restored.applications.len(), 1);
        assert!(restored.award.is_some());

        let mut forged = restored.clone();
        forged.title = "Silently changed offer".into();
        forged.state_revision += 1;
        forged.updated_at += Duration::minutes(1);
        assert!(matches!(
            store.update_creator_hiring(
                &forged,
                restored.state_revision,
                "creator_hiring.forged",
                &json!({}),
                forged.updated_at,
            ),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "creator hiring contract",
                ..
            })
        ));
    }
}

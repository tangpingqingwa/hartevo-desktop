use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    CreditGrantId, CurrencyCode, EffectId, EffectStatus, Mission, MissionId, MissionUsageEntry,
    MissionUsageEntryKind, MissionUsageLedger, MissionUsageReservation, ProjectId,
    StripeBillingFact, UsageCommitEvidence, UsageLedgerMutation, UsageReleaseEvidence,
    UsageReleaseReason, UsageReservationId,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::Value;

use crate::aggregate::{PendingEvent, append_events, ensure_project_scope};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsagePersistenceDisposition {
    Applied,
    Replayed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsagePersistenceOutcome {
    pub disposition: UsagePersistenceDisposition,
    pub ledger_revision: u64,
    pub entry: Option<MissionUsageEntry>,
    pub reservation: Option<MissionUsageReservation>,
    pub event_sequence: Option<i64>,
    pub outbox_sequence: Option<i64>,
}

impl ProjectStore {
    pub fn load_mission_usage_ledger(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<MissionUsageLedger>, StorageError> {
        let project = self.load_project(project_id)?;
        load_usage_ledger(&self.connection, project_id, project.tenant_id.as_str())
    }

    pub fn apply_stripe_credit_grant(
        &mut self,
        project_id: &ProjectId,
        grant_id: CreditGrantId,
        billing_fact_digest: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<UsagePersistenceOutcome, StorageError> {
        let project = self.load_project(project_id)?;
        let fact_json: String = self
            .connection
            .query_row(
                "SELECT record_json FROM stripe_billing_facts
                 WHERE project_id = ?1 AND immutable_digest = ?2",
                params![project_id.as_str(), billing_fact_digest],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "Stripe Billing fact",
                project_id: project_id.clone(),
                id: billing_fact_digest.to_owned(),
            })?;
        let fact: StripeBillingFact = serde_json::from_str(&fact_json)?;
        if fact.tenant_id != project.tenant_id || fact.project_id != *project_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        let amount = fact
            .credit_grant_amount()
            .ok_or_else(|| {
                StorageError::Usage(hartevo_domain_kernel::UsageLedgerError::InvalidCreditGrant)
            })?
            .clone();
        let transaction = self.connection.transaction()?;
        ensure_project_scope(&transaction, fact.tenant_id.as_str(), project_id.as_str())?;
        let mut ledger =
            load_usage_ledger_in_transaction(&transaction, project_id, fact.tenant_id.as_str())?
                .unwrap_or_else(|| {
                    MissionUsageLedger::new(
                        fact.tenant_id.clone(),
                        fact.project_id.clone(),
                        amount.currency.clone(),
                    )
                });
        let previous_revision = ledger.revision;
        let mutation = ledger.grant_credit(grant_id, billing_fact_digest, amount, recorded_at)?;
        let entry = match mutation {
            UsageLedgerMutation::Applied(entry) => entry,
            UsageLedgerMutation::Replayed(entry) => {
                transaction.commit()?;
                return Ok(UsagePersistenceOutcome {
                    disposition: UsagePersistenceDisposition::Replayed,
                    ledger_revision: ledger.revision,
                    entry: Some(entry),
                    reservation: None,
                    event_sequence: None,
                    outbox_sequence: None,
                });
            }
        };
        let (event_sequence, outbox_sequence) = append_usage_entry(
            &transaction,
            &ledger,
            previous_revision,
            &entry,
            "billing.credit_granted",
        )?;
        transaction.commit()?;
        Ok(UsagePersistenceOutcome {
            disposition: UsagePersistenceDisposition::Applied,
            ledger_revision: ledger.revision,
            entry: Some(entry),
            reservation: None,
            event_sequence: Some(event_sequence),
            outbox_sequence: Some(outbox_sequence),
        })
    }

    pub fn reserve_mission_usage(
        &mut self,
        reservation: MissionUsageReservation,
    ) -> Result<UsagePersistenceOutcome, StorageError> {
        let project = self.load_project(&reservation.project_id)?;
        if project.tenant_id != reservation.tenant_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        let mission = self.load_mission(&reservation.project_id, &reservation.mission_id)?;
        validate_reservation_effect_scope(&mission, &reservation)?;
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            reservation.tenant_id.as_str(),
            reservation.project_id.as_str(),
        )?;
        let mut ledger = load_usage_ledger_in_transaction(
            &transaction,
            &reservation.project_id,
            reservation.tenant_id.as_str(),
        )?
        .unwrap_or_else(|| {
            MissionUsageLedger::new(
                reservation.tenant_id.clone(),
                reservation.project_id.clone(),
                reservation.amount.currency.clone(),
            )
        });
        let previous_revision = ledger.revision;
        let mutation = ledger.reserve(reservation)?;
        let reservation = match mutation {
            UsageLedgerMutation::Applied(reservation) => {
                let entry = ledger
                    .entries
                    .last()
                    .cloned()
                    .ok_or(StorageError::BillingLedgerIntegrity)?;
                let (event_sequence, outbox_sequence) = append_usage_entry(
                    &transaction,
                    &ledger,
                    previous_revision,
                    &entry,
                    "mission.usage_reserved",
                )?;
                transaction.commit()?;
                return Ok(UsagePersistenceOutcome {
                    disposition: UsagePersistenceDisposition::Applied,
                    ledger_revision: ledger.revision,
                    entry: Some(entry),
                    reservation: Some(reservation),
                    event_sequence: Some(event_sequence),
                    outbox_sequence: Some(outbox_sequence),
                });
            }
            UsageLedgerMutation::Replayed(reservation) => reservation,
        };
        transaction.commit()?;
        Ok(UsagePersistenceOutcome {
            disposition: UsagePersistenceDisposition::Replayed,
            ledger_revision: ledger.revision,
            entry: None,
            reservation: Some(reservation),
            event_sequence: None,
            outbox_sequence: None,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the command binds project, Mission, Effect, reservation, revision, scope, and receipt evidence"
    )]
    pub fn commit_mission_usage(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        effect_id: &EffectId,
        reservation_id: &UsageReservationId,
        mission_revision: u64,
        effect_scope_digest: &str,
        evidence: UsageCommitEvidence,
    ) -> Result<UsagePersistenceOutcome, StorageError> {
        let project = self.load_project(project_id)?;
        let mission = self.load_mission(project_id, mission_id)?;
        validate_effect_scope(&mission, effect_id, mission_revision, effect_scope_digest)?;
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            project.tenant_id.as_str(),
            project_id.as_str(),
        )?;
        let mut ledger =
            load_usage_ledger_in_transaction(&transaction, project_id, project.tenant_id.as_str())?
                .ok_or_else(|| StorageError::UsageLedgerNotFound(project_id.clone()))?;
        let current = ledger.reservation(reservation_id).ok_or_else(|| {
            hartevo_domain_kernel::UsageLedgerError::UnknownReservation(reservation_id.clone())
        })?;
        if current.mission_id != *mission_id || current.effect_id != *effect_id {
            return Err(StorageError::UsageEffectScopeMismatch);
        }
        let effect = mission
            .effects
            .iter()
            .find(|effect| effect.id == *effect_id)
            .ok_or_else(|| StorageError::UsageEffectNotFound {
                mission_id: mission.id.clone(),
                effect_id: effect_id.to_string(),
            })?;
        if effect.status != evidence.effect_status
            || !matches!(
                effect.status,
                EffectStatus::ReceiptRecorded | EffectStatus::Verified
            )
        {
            return Err(StorageError::UsageEffectStateMismatch);
        }
        let previous_revision = ledger.revision;
        let mutation = ledger.commit(
            reservation_id,
            mission_revision,
            effect_scope_digest,
            evidence,
        )?;
        let reservation = match mutation {
            UsageLedgerMutation::Applied(reservation) => {
                let entry = ledger
                    .entries
                    .last()
                    .cloned()
                    .ok_or(StorageError::BillingLedgerIntegrity)?;
                let (event_sequence, outbox_sequence) = append_usage_entry(
                    &transaction,
                    &ledger,
                    previous_revision,
                    &entry,
                    "mission.usage_committed",
                )?;
                transaction.commit()?;
                return Ok(UsagePersistenceOutcome {
                    disposition: UsagePersistenceDisposition::Applied,
                    ledger_revision: ledger.revision,
                    entry: Some(entry),
                    reservation: Some(reservation),
                    event_sequence: Some(event_sequence),
                    outbox_sequence: Some(outbox_sequence),
                });
            }
            UsageLedgerMutation::Replayed(reservation) => reservation,
        };
        transaction.commit()?;
        Ok(UsagePersistenceOutcome {
            disposition: UsagePersistenceDisposition::Replayed,
            ledger_revision: ledger.revision,
            entry: None,
            reservation: Some(reservation),
            event_sequence: None,
            outbox_sequence: None,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the command binds project, Mission, Effect, reservation, revision, scope, and release evidence"
    )]
    pub fn release_mission_usage(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        effect_id: &EffectId,
        reservation_id: &UsageReservationId,
        mission_revision: u64,
        effect_scope_digest: &str,
        evidence: UsageReleaseEvidence,
    ) -> Result<UsagePersistenceOutcome, StorageError> {
        let project = self.load_project(project_id)?;
        let mission = self.load_mission(project_id, mission_id)?;
        validate_effect_scope(&mission, effect_id, mission_revision, effect_scope_digest)?;
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            project.tenant_id.as_str(),
            project_id.as_str(),
        )?;
        let mut ledger =
            load_usage_ledger_in_transaction(&transaction, project_id, project.tenant_id.as_str())?
                .ok_or_else(|| StorageError::UsageLedgerNotFound(project_id.clone()))?;
        let current = ledger.reservation(reservation_id).ok_or_else(|| {
            hartevo_domain_kernel::UsageLedgerError::UnknownReservation(reservation_id.clone())
        })?;
        if current.mission_id != *mission_id || current.effect_id != *effect_id {
            return Err(StorageError::UsageEffectScopeMismatch);
        }
        let effect = mission
            .effects
            .iter()
            .find(|effect| effect.id == *effect_id)
            .ok_or_else(|| StorageError::UsageEffectNotFound {
                mission_id: mission.id.clone(),
                effect_id: effect_id.to_string(),
            })?;
        let release_matches_effect = match &evidence.reason {
            UsageReleaseReason::EffectCancelled => effect.status == EffectStatus::Cancelled,
            UsageReleaseReason::ProviderRejected => effect.status == EffectStatus::Rejected,
            UsageReleaseReason::ReconciledNotExecuted => {
                matches!(
                    effect.status,
                    EffectStatus::Reconciled | EffectStatus::DeadLetter
                )
            }
            UsageReleaseReason::ReservationExpired => evidence.observed_at >= current.expires_at,
        };
        if !release_matches_effect {
            return Err(StorageError::UsageEffectStateMismatch);
        }
        let previous_revision = ledger.revision;
        let mutation = ledger.release(
            reservation_id,
            mission_revision,
            effect_scope_digest,
            evidence,
        )?;
        let reservation = match mutation {
            UsageLedgerMutation::Applied(reservation) => {
                let entry = ledger
                    .entries
                    .last()
                    .cloned()
                    .ok_or(StorageError::BillingLedgerIntegrity)?;
                let (event_sequence, outbox_sequence) = append_usage_entry(
                    &transaction,
                    &ledger,
                    previous_revision,
                    &entry,
                    "mission.usage_released",
                )?;
                transaction.commit()?;
                return Ok(UsagePersistenceOutcome {
                    disposition: UsagePersistenceDisposition::Applied,
                    ledger_revision: ledger.revision,
                    entry: Some(entry),
                    reservation: Some(reservation),
                    event_sequence: Some(event_sequence),
                    outbox_sequence: Some(outbox_sequence),
                });
            }
            UsageLedgerMutation::Replayed(reservation) => reservation,
        };
        transaction.commit()?;
        Ok(UsagePersistenceOutcome {
            disposition: UsagePersistenceDisposition::Replayed,
            ledger_revision: ledger.revision,
            entry: None,
            reservation: Some(reservation),
            event_sequence: None,
            outbox_sequence: None,
        })
    }
}

fn validate_reservation_effect_scope(
    mission: &Mission,
    reservation: &MissionUsageReservation,
) -> Result<(), StorageError> {
    if mission.revision != reservation.mission_revision {
        return Err(StorageError::Usage(
            hartevo_domain_kernel::UsageLedgerError::RevisionFenceMismatch,
        ));
    }
    validate_effect_scope(
        mission,
        &reservation.effect_id,
        reservation.mission_revision,
        &reservation.effect_scope_digest,
    )?;
    let effect = mission
        .effects
        .iter()
        .find(|effect| effect.id == reservation.effect_id)
        .ok_or_else(|| StorageError::UsageEffectNotFound {
            mission_id: mission.id.clone(),
            effect_id: reservation.effect_id.to_string(),
        })?;
    if effect.amount != reservation.amount {
        return Err(StorageError::UsageEffectScopeMismatch);
    }
    Ok(())
}

fn validate_effect_scope(
    mission: &Mission,
    effect_id: &EffectId,
    mission_revision: u64,
    effect_scope_digest: &str,
) -> Result<(), StorageError> {
    let _ = mission_revision;
    let effect = mission
        .effects
        .iter()
        .find(|effect| effect.id == *effect_id)
        .ok_or_else(|| StorageError::UsageEffectNotFound {
            mission_id: mission.id.clone(),
            effect_id: effect_id.to_string(),
        })?;
    if effect.usage_scope_digest() != effect_scope_digest {
        return Err(StorageError::UsageEffectScopeMismatch);
    }
    Ok(())
}

fn load_usage_ledger(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    tenant_id: &str,
) -> Result<Option<MissionUsageLedger>, StorageError> {
    load_usage_ledger_with_query(connection, project_id, tenant_id)
}

fn load_usage_ledger_in_transaction(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    tenant_id: &str,
) -> Result<Option<MissionUsageLedger>, StorageError> {
    load_usage_ledger_with_query(transaction, project_id, tenant_id)
}

fn load_usage_ledger_with_query(
    queryable: &rusqlite::Connection,
    project_id: &ProjectId,
    tenant_id: &str,
) -> Result<Option<MissionUsageLedger>, StorageError> {
    let head = queryable
        .query_row(
            "SELECT tenant_id, currency, revision FROM mission_usage_ledger_heads
             WHERE project_id = ?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_tenant, currency, head_revision)) = head else {
        return Ok(None);
    };
    if stored_tenant != tenant_id || head_revision < 0 {
        return Err(StorageError::TenantScopeMismatch);
    }
    let currency = CurrencyCode::parse(&currency)
        .map_err(|_| StorageError::DomainDecode("invalid usage ledger currency".into()))?;
    let mut statement = queryable.prepare(
        "SELECT sequence, tenant_id, id, record_json
         FROM mission_usage_entries
         WHERE project_id = ?1 ORDER BY sequence ASC",
    )?;
    let mut rows = statement.query([project_id.as_str()])?;
    let mut entries = Vec::new();
    let mut expected_sequence = 1_u64;
    while let Some(row) = rows.next()? {
        let sequence = u64::try_from(row.get::<_, i64>(0)?)
            .map_err(|_| StorageError::BillingLedgerIntegrity)?;
        let entry_tenant = row.get::<_, String>(1)?;
        let entry_id = row.get::<_, String>(2)?;
        let entry: MissionUsageEntry = serde_json::from_str(&row.get::<_, String>(3)?)?;
        if sequence != expected_sequence
            || entry_tenant != tenant_id
            || entry.id.as_str() != entry_id
            || entry.project_id != *project_id
        {
            return Err(StorageError::BillingLedgerIntegrity);
        }
        entries.push(entry);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(StorageError::BillingLedgerIntegrity)?;
    }
    let ledger = MissionUsageLedger::from_entries(
        hartevo_domain_kernel::TenantId::from(tenant_id),
        project_id.clone(),
        currency,
        entries,
    )?;
    if ledger.revision != u64::try_from(head_revision).unwrap_or(u64::MAX) {
        return Err(StorageError::BillingLedgerIntegrity);
    }
    Ok(Some(ledger))
}

fn append_usage_entry(
    transaction: &Transaction<'_>,
    ledger: &MissionUsageLedger,
    previous_revision: u64,
    entry: &MissionUsageEntry,
    event_type: &str,
) -> Result<(i64, i64), StorageError> {
    if entry.revision != previous_revision.saturating_add(1) {
        return Err(StorageError::BillingLedgerIntegrity);
    }
    let (entry_kind, mission_id, amount_minor) = entry_columns(ledger, entry)?;
    transaction.execute(
        "INSERT INTO mission_usage_entries
           (tenant_id, project_id, sequence, id, entry_kind, mission_id, amount_minor,
            currency, record_json, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            entry.tenant_id.as_str(),
            entry.project_id.as_str(),
            i64::try_from(entry.revision)
                .map_err(|_| StorageError::RevisionOverflow(entry.revision))?,
            entry.id.as_str(),
            entry_kind,
            mission_id,
            amount_minor,
            ledger.currency.as_str(),
            serde_json::to_string(entry)?,
            entry.recorded_at.to_rfc3339(),
        ],
    )?;
    let previous_i64 = i64::try_from(previous_revision)
        .map_err(|_| StorageError::RevisionOverflow(previous_revision))?;
    let revision_i64 = i64::try_from(entry.revision)
        .map_err(|_| StorageError::RevisionOverflow(entry.revision))?;
    if previous_revision == 0 {
        transaction.execute(
            "INSERT INTO mission_usage_ledger_heads
               (tenant_id, project_id, currency, revision, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                entry.tenant_id.as_str(),
                entry.project_id.as_str(),
                ledger.currency.as_str(),
                revision_i64,
                entry.recorded_at.to_rfc3339(),
            ],
        )?;
    } else {
        let updated = transaction.execute(
            "UPDATE mission_usage_ledger_heads
             SET revision = ?1, updated_at = ?2
             WHERE project_id = ?3 AND tenant_id = ?4 AND revision = ?5",
            params![
                revision_i64,
                entry.recorded_at.to_rfc3339(),
                entry.project_id.as_str(),
                entry.tenant_id.as_str(),
                previous_i64,
            ],
        )?;
        if updated != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: "mission_usage_ledger".into(),
                expected_revision: previous_revision,
            });
        }
    }
    let payload: Value = serde_json::to_value(entry)?;
    let mission_id_ref = mission_id.as_deref();
    let (event_sequences, outbox_sequences) = append_events(
        transaction,
        entry.tenant_id.as_str(),
        entry.project_id.as_str(),
        mission_id_ref,
        "mission_usage",
        mission_id_ref.unwrap_or(entry.project_id.as_str()),
        &[PendingEvent::new(event_type, payload, entry.recorded_at)],
    )?;
    Ok((event_sequences[0], outbox_sequences[0]))
}

fn entry_columns(
    ledger: &MissionUsageLedger,
    entry: &MissionUsageEntry,
) -> Result<(&'static str, Option<String>, Option<i64>), StorageError> {
    match &entry.kind {
        MissionUsageEntryKind::CreditGranted { amount, .. } => {
            Ok(("credit_granted", None, Some(amount.amount_minor)))
        }
        MissionUsageEntryKind::Reserved { reservation } => Ok((
            "reserved",
            Some(reservation.mission_id.to_string()),
            Some(reservation.amount.amount_minor),
        )),
        MissionUsageEntryKind::Committed { reservation_id, .. }
        | MissionUsageEntryKind::Released { reservation_id, .. } => {
            let reservation = ledger
                .reservation(reservation_id)
                .ok_or_else(|| StorageError::UsageLedgerNotFound(ledger.project_id.clone()))?;
            Ok((
                match &entry.kind {
                    MissionUsageEntryKind::Committed { .. } => "committed",
                    MissionUsageEntryKind::Released { .. } => "released",
                    _ => unreachable!(),
                },
                Some(reservation.mission_id.to_string()),
                Some(reservation.amount.amount_minor),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{DateTime, TimeZone, Utc};
    use hartevo_domain_kernel::{
        ActorId, ConsentState, EffectClass, EffectRisk, EffectSpec, EffectStatus, MissionContract,
        Money, Project, StorageMode, StripeFactSource, Task, TaskStatus, TenantId,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 2, 0, 0)
            .single()
            .expect("time")
    }

    fn project() -> Project {
        Project::create_local(
            TenantId::from("tenant-money"),
            ProjectId::from("project-usage"),
            "Usage fixture",
            "",
            "/tmp/hartevo-money01-usage",
            StorageMode::LocalExisting,
        )
        .expect("project")
    }

    fn mission_with_effect() -> Mission {
        let start = now() + chrono::Duration::minutes(1);
        let mut mission = Mission::compile(
            TenantId::from("tenant-money"),
            MissionId::from("mission-usage"),
            ProjectId::from("project-usage"),
            "Usage mission",
            MissionContract::bootstrap("Reserve exact usage", ["billing.use".into()], start),
            start,
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: hartevo_domain_kernel::TaskId::from("task-usage"),
                    title: "Use credits".into(),
                    status: TaskStatus::Running,
                    capability: "billing.use".into(),
                }],
                start + chrono::Duration::seconds(1),
            )
            .expect("start mission");
        mission
            .propose_effect(
                EffectSpec {
                    id: EffectId::from("effect-usage"),
                    actor_id: ActorId::from("actor-usage"),
                    capability: "billing.use".into(),
                    provider: "stripe".into(),
                    connection_id: None,
                    account_id: None,
                    required_scopes: BTreeSet::new(),
                    effect_class: EffectClass::ExternalWrite,
                    description: "Use reserved Mission credits".into(),
                    target_resource: "stripe://customer/cus_usage".into(),
                    audience_digest: None,
                    payload_digest: "a".repeat(64),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "UTC".into(),
                    consent: ConsentState::NotRequired,
                    consent_record_id: None,
                    consent_requirement: None,
                    conversation_guard: None,
                    creator_contact_guard: None,
                    policy_version: "money01-test".into(),
                    risk: EffectRisk::Low,
                    idempotency_key: "usage-effect-1".into(),
                    amount: Money::new(400, CurrencyCode::parse("USD").expect("USD")),
                    expires_at: start + chrono::Duration::hours(1),
                },
                start + chrono::Duration::seconds(2),
            )
            .expect("effect");
        mission
    }

    fn credit_fact() -> StripeBillingFact {
        StripeBillingFact::new(
            "reconciliation:credit-usage",
            TenantId::from("tenant-money"),
            ProjectId::from("project-usage"),
            StripeFactSource::Reconciliation {
                request_id: "reconcile-credit-usage".into(),
                readback_digest: "c".repeat(64),
                observed_at: now(),
            },
            now(),
            hartevo_domain_kernel::StripeBillingFactPayload::Credit {
                credit_id: "cbtxn_usage".into(),
                customer_id: "cus_usage".into(),
                amount: Money::new(1_000, CurrencyCode::parse("USD").expect("USD")),
                direction: hartevo_domain_kernel::StripeCreditDirection::Grant,
                expires_at: None,
            },
        )
        .expect("credit fact")
    }

    #[test]
    fn usage_reservation_is_atomic_fenced_and_release_is_explicit() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project();
        store.save_project(&project).expect("project");
        let mission = mission_with_effect();
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new(
                    "mission.created",
                    serde_json::json!({"missionId": mission.id}),
                    now(),
                )],
            )
            .expect("mission");
        let fact = credit_fact();
        store
            .record_stripe_reconciliation_fact(fact.clone())
            .expect("credit fact");
        store
            .apply_stripe_credit_grant(
                &project.id,
                CreditGrantId::from("grant-usage"),
                &fact.immutable_digest,
                now(),
            )
            .expect("credit grant");
        let effect_scope_digest = mission.effects[0].usage_scope_digest();
        let reservation = MissionUsageReservation {
            id: UsageReservationId::from("reservation-usage"),
            tenant_id: project.tenant_id.clone(),
            project_id: project.id.clone(),
            mission_id: mission.id.clone(),
            effect_id: EffectId::from("effect-usage"),
            mission_revision: mission.revision,
            effect_scope_digest: effect_scope_digest.clone(),
            amount: Money::new(400, CurrencyCode::parse("USD").expect("USD")),
            idempotency_key: "reservation-usage-1".into(),
            reserved_at: now() + chrono::Duration::minutes(2),
            expires_at: now() + chrono::Duration::minutes(10),
            status: hartevo_domain_kernel::UsageReservationStatus::Reserved,
        };
        let applied = store
            .reserve_mission_usage(reservation.clone())
            .expect("reserve");
        assert_eq!(applied.disposition, UsagePersistenceDisposition::Applied);
        let replay = store
            .reserve_mission_usage(reservation.clone())
            .expect("replay reserve");
        assert_eq!(replay.disposition, UsagePersistenceDisposition::Replayed);
        let fake_commit = store.commit_mission_usage(
            &project.id,
            &mission.id,
            &EffectId::from("effect-usage"),
            &reservation.id,
            mission.revision,
            &effect_scope_digest,
            UsageCommitEvidence {
                receipt_id: hartevo_domain_kernel::ReceiptId::from("receipt-fake"),
                effect_status: EffectStatus::Verified,
                evidence_digest: "d".repeat(64),
                observed_at: now() + chrono::Duration::minutes(3),
            },
        );
        assert!(matches!(
            fake_commit,
            Err(StorageError::UsageEffectStateMismatch)
        ));

        let mut cancelled = mission.clone();
        cancelled
            .cancel_effect(
                &EffectId::from("effect-usage"),
                now() + chrono::Duration::minutes(4),
            )
            .expect("cancel effect");
        store
            .save_mission(&cancelled)
            .expect("persist cancellation");
        let released = store
            .release_mission_usage(
                &project.id,
                &mission.id,
                &EffectId::from("effect-usage"),
                &reservation.id,
                mission.revision,
                &effect_scope_digest,
                UsageReleaseEvidence {
                    reason: UsageReleaseReason::EffectCancelled,
                    evidence_digest: "e".repeat(64),
                    observed_at: now() + chrono::Duration::minutes(4),
                },
            )
            .expect("release");
        assert_eq!(released.disposition, UsagePersistenceDisposition::Applied);
        let ledger = store
            .load_mission_usage_ledger(&project.id)
            .expect("ledger")
            .expect("ledger exists");
        assert_eq!(ledger.available().expect("available").amount_minor, 1_000);
        assert_eq!(ledger.reserved().expect("reserved").amount_minor, 0);
    }
}

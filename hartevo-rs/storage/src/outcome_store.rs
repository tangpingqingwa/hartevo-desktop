use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AttributionRecord, CommissionRecord, MissionId, OutcomeEvent, OutcomeLedger, OutcomeOrder,
    OutcomeRefund, ProjectId, TenantId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{PersistedMutation, ProjectStore, StorageError};

impl ProjectStore {
    pub fn create_outcome_ledger(
        &mut self,
        ledger: &OutcomeLedger,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_ledger(ledger)?;
        if ledger.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(ledger.revision));
        }
        let transaction = self.connection.transaction()?;
        ensure_scope(&transaction, &ledger.tenant_id, &ledger.project_id, None)?;
        insert_outcome_ledger_head(&transaction, ledger)?;
        persist_children(&transaction, ledger)?;
        finish(transaction, ledger, None, event_type, payload, recorded_at)
    }

    pub fn update_outcome_ledger(
        &mut self,
        ledger: &OutcomeLedger,
        expected_revision: u64,
        mission_id: Option<&MissionId>,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_ledger(ledger)?;
        require_next(expected_revision, ledger.revision)?;
        let transaction = self.connection.transaction()?;
        ensure_scope(
            &transaction,
            &ledger.tenant_id,
            &ledger.project_id,
            mission_id,
        )?;
        let updated = update_outcome_ledger_head(&transaction, ledger, expected_revision)?;
        if updated != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: "outcome_ledger".into(),
                expected_revision,
            });
        }
        persist_children(&transaction, ledger)?;
        finish(
            transaction,
            ledger,
            mission_id,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_outcome_ledger(
        &self,
        project_id: &ProjectId,
    ) -> Result<OutcomeLedger, StorageError> {
        let head = self
            .connection
            .query_row(
                "SELECT tenant_id, revision FROM outcome_ledgers WHERE project_id = ?1",
                [project_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "outcome ledger",
                project_id: project_id.clone(),
                id: project_id.to_string(),
            })?;
        let ledger = OutcomeLedger {
            tenant_id: TenantId::from_stable(head.0),
            project_id: project_id.clone(),
            events: load_json_records(
                &self.connection,
                "SELECT record_json FROM outcome_events
                 WHERE project_id = ?1 ORDER BY sequence ASC",
                project_id,
            )?,
            orders: load_json_records(
                &self.connection,
                "SELECT record_json FROM outcome_orders
                 WHERE project_id = ?1 ORDER BY sequence ASC",
                project_id,
            )?,
            refunds: load_json_records(
                &self.connection,
                "SELECT record_json FROM outcome_refunds
                 WHERE project_id = ?1 ORDER BY sequence ASC",
                project_id,
            )?,
            attributions: load_json_records(
                &self.connection,
                "SELECT record_json FROM attribution_records
                 WHERE project_id = ?1 ORDER BY sequence ASC",
                project_id,
            )?,
            commissions: load_json_records(
                &self.connection,
                "SELECT record_json FROM commission_records
                 WHERE project_id = ?1 ORDER BY sequence ASC",
                project_id,
            )?,
            revision: from_sql_u64(head.1, "outcome ledger revision")?,
        };
        validate_ledger(&ledger)?;
        Ok(ledger)
    }
}

pub(crate) fn insert_outcome_ledger_head(
    transaction: &Transaction<'_>,
    ledger: &OutcomeLedger,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO outcome_ledgers (tenant_id, project_id, revision)
         VALUES (?1, ?2, ?3)",
        params![
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            to_sql_u64(ledger.revision)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn update_outcome_ledger_head(
    transaction: &Transaction<'_>,
    ledger: &OutcomeLedger,
    expected_revision: u64,
) -> Result<usize, StorageError> {
    Ok(transaction.execute(
        "UPDATE outcome_ledgers SET revision = ?3
         WHERE tenant_id = ?1 AND project_id = ?2 AND revision = ?4",
        params![
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            to_sql_u64(ledger.revision)?,
            to_sql_u64(expected_revision)?,
        ],
    )?)
}

pub(crate) fn persist_children(
    transaction: &Transaction<'_>,
    ledger: &OutcomeLedger,
) -> Result<(), StorageError> {
    for event in &ledger.events {
        insert_event(transaction, event)?;
    }
    for order in &ledger.orders {
        insert_order(transaction, ledger, order)?;
    }
    for refund in &ledger.refunds {
        insert_refund(transaction, ledger, refund)?;
    }
    for attribution in &ledger.attributions {
        insert_attribution(transaction, attribution)?;
    }
    for commission in &ledger.commissions {
        upsert_commission_projection(transaction, commission)?;
    }
    Ok(())
}

fn insert_event(transaction: &Transaction<'_>, event: &OutcomeEvent) -> Result<(), StorageError> {
    let record_json = serde_json::to_string(event)?;
    let inserted = transaction.execute(
        "INSERT INTO outcome_events
           (id, tenant_id, project_id, mission_id, kind, provider, connection_id, account_id,
            source_event_id, identity_link_id, opportunity_id, campaign_id, order_id,
            refund_id, commission_id, payout_id, partner_id, amount_minor, currency,
            occurred_at, received_at, evidence_digest, raw_payload_digest,
            source_verification_method, source_verifier, source_verification_independent,
            source_verified_at, source_verification_evidence_digest, record_json)
         VALUES
           (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
            ?27, ?28, ?29)
         ON CONFLICT(project_id, id) DO NOTHING",
        params![
            event.id.as_str(),
            event.tenant_id.as_str(),
            event.project_id.as_str(),
            event.mission_id.as_str(),
            enum_name(&event.kind)?,
            event.provider,
            event
                .connection_id
                .as_ref()
                .map(hartevo_domain_kernel::ConnectionId::as_str),
            event
                .account_id
                .as_ref()
                .map(hartevo_domain_kernel::AccountId::as_str),
            event.source_event_id,
            event
                .identity_link_id
                .as_ref()
                .map(hartevo_domain_kernel::IdentityLinkId::as_str),
            event
                .opportunity_id
                .as_ref()
                .map(hartevo_domain_kernel::OpportunityId::as_str),
            event
                .campaign_id
                .as_ref()
                .map(hartevo_domain_kernel::CampaignId::as_str),
            event
                .order_id
                .as_ref()
                .map(hartevo_domain_kernel::OrderId::as_str),
            event
                .refund_id
                .as_ref()
                .map(hartevo_domain_kernel::RefundId::as_str),
            event
                .commission_id
                .as_ref()
                .map(hartevo_domain_kernel::CommissionId::as_str),
            event
                .payout_id
                .as_ref()
                .map(hartevo_domain_kernel::PayoutId::as_str),
            event
                .partner_id
                .as_ref()
                .map(hartevo_domain_kernel::PartnerId::as_str),
            event.amount.as_ref().map(|money| money.amount_minor),
            event.amount.as_ref().map(|money| money.currency.as_str()),
            event.occurred_at.to_rfc3339(),
            event.received_at.to_rfc3339(),
            event.evidence_digest,
            event.raw_payload_digest,
            event
                .source_verification
                .as_ref()
                .map(|verification| enum_name(&verification.method))
                .transpose()?,
            event
                .source_verification
                .as_ref()
                .map(|verification| verification.verifier.as_str()),
            event
                .source_verification
                .as_ref()
                .map(|verification| verification.independent),
            event
                .source_verification
                .as_ref()
                .map(|verification| verification.verified_at.to_rfc3339()),
            event
                .source_verification
                .as_ref()
                .map(|verification| verification.evidence_digest.as_str()),
            record_json,
        ],
    )?;
    verify_if_existing(
        transaction,
        inserted,
        ImmutableTable::Event,
        &event.project_id,
        event.id.as_str(),
        &record_json,
    )
}

fn insert_order(
    transaction: &Transaction<'_>,
    ledger: &OutcomeLedger,
    order: &OutcomeOrder,
) -> Result<(), StorageError> {
    let record_json = serde_json::to_string(order)?;
    let inserted = transaction.execute(
        "INSERT INTO outcome_orders
           (project_id, id, source_event_id, amount_minor, currency, occurred_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(project_id, id) DO NOTHING",
        params![
            ledger.project_id.as_str(),
            order.id.as_str(),
            order.source_event_id.as_str(),
            order.original_amount.amount_minor,
            order.original_amount.currency.as_str(),
            order.occurred_at.to_rfc3339(),
            record_json,
        ],
    )?;
    verify_if_existing(
        transaction,
        inserted,
        ImmutableTable::Order,
        &ledger.project_id,
        order.id.as_str(),
        &record_json,
    )
}

fn insert_refund(
    transaction: &Transaction<'_>,
    ledger: &OutcomeLedger,
    refund: &OutcomeRefund,
) -> Result<(), StorageError> {
    let record_json = serde_json::to_string(refund)?;
    let inserted = transaction.execute(
        "INSERT INTO outcome_refunds
           (project_id, id, order_id, source_event_id, amount_minor, currency,
            occurred_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(project_id, id) DO NOTHING",
        params![
            ledger.project_id.as_str(),
            refund.id.as_str(),
            refund.order_id.as_str(),
            refund.source_event_id.as_str(),
            refund.amount.amount_minor,
            refund.amount.currency.as_str(),
            refund.occurred_at.to_rfc3339(),
            record_json,
        ],
    )?;
    verify_if_existing(
        transaction,
        inserted,
        ImmutableTable::Refund,
        &ledger.project_id,
        refund.id.as_str(),
        &record_json,
    )
}

fn insert_attribution(
    transaction: &Transaction<'_>,
    attribution: &AttributionRecord,
) -> Result<(), StorageError> {
    let record_json = serde_json::to_string(attribution)?;
    let inserted = transaction.execute(
        "INSERT INTO attribution_records
           (id, tenant_id, project_id, order_id, model, touchpoint_mission_id,
            window_started_at, window_ended_at, confidence, evidence_digest,
            recorded_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(project_id, id) DO NOTHING",
        params![
            attribution.id.as_str(),
            attribution.tenant_id.as_str(),
            attribution.project_id.as_str(),
            attribution.order_id.as_str(),
            enum_name(&attribution.model)?,
            attribution
                .touchpoint
                .as_ref()
                .map(|touchpoint| touchpoint.mission_id.as_str()),
            attribution.window_started_at.to_rfc3339(),
            attribution.window_ended_at.to_rfc3339(),
            attribution.confidence.to_string(),
            attribution.evidence_digest,
            attribution.recorded_at.to_rfc3339(),
            record_json,
        ],
    )?;
    verify_if_existing(
        transaction,
        inserted,
        ImmutableTable::Attribution,
        &attribution.project_id,
        attribution.id.as_str(),
        &record_json,
    )
}

fn upsert_commission_projection(
    transaction: &Transaction<'_>,
    commission: &CommissionRecord,
) -> Result<(), StorageError> {
    let record_json = serde_json::to_string(commission)?;
    let immutable_digest = commission_immutable_digest(commission)?;
    let inserted = transaction.execute(
        "INSERT INTO commission_records
           (id, tenant_id, project_id, order_id, partner_id, rate, eligible_net_minor,
            eligible_net_currency, commission_minor, commission_currency, terms_digest,
            refund_set_digest, supersedes, status, calculated_at, immutable_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17)
         ON CONFLICT(project_id, id) DO NOTHING",
        params![
            commission.id.as_str(),
            commission.tenant_id.as_str(),
            commission.project_id.as_str(),
            commission.order_id.as_str(),
            commission.partner_id.as_str(),
            commission.rate.to_string(),
            commission.eligible_net_amount.amount_minor,
            commission.eligible_net_amount.currency.as_str(),
            commission.commission_amount.amount_minor,
            commission.commission_amount.currency.as_str(),
            commission.terms_digest,
            commission.refund_set_digest,
            commission
                .supersedes
                .as_ref()
                .map(hartevo_domain_kernel::CommissionId::as_str),
            enum_name(&commission.status)?,
            commission.calculated_at.to_rfc3339(),
            immutable_digest,
            record_json,
        ],
    )?;
    if inserted == 0 {
        let stored_digest = transaction
            .query_row(
                "SELECT immutable_digest FROM commission_records
                 WHERE project_id = ?1 AND id = ?2",
                params![commission.project_id.as_str(), commission.id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "commission",
                project_id: commission.project_id.clone(),
                id: commission.id.to_string(),
            })?;
        if stored_digest != immutable_digest {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "commission",
                id: commission.id.to_string(),
            });
        }
        transaction.execute(
            "UPDATE commission_records SET status = ?3, record_json = ?4
             WHERE project_id = ?1 AND id = ?2",
            params![
                commission.project_id.as_str(),
                commission.id.as_str(),
                enum_name(&commission.status)?,
                record_json,
            ],
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum ImmutableTable {
    Event,
    Order,
    Refund,
    Attribution,
}

impl ImmutableTable {
    fn select_sql(self) -> &'static str {
        match self {
            Self::Event => {
                "SELECT record_json FROM outcome_events WHERE project_id = ?1 AND id = ?2"
            }
            Self::Order => {
                "SELECT record_json FROM outcome_orders WHERE project_id = ?1 AND id = ?2"
            }
            Self::Refund => {
                "SELECT record_json FROM outcome_refunds WHERE project_id = ?1 AND id = ?2"
            }
            Self::Attribution => {
                "SELECT record_json FROM attribution_records WHERE project_id = ?1 AND id = ?2"
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Event => "outcome event",
            Self::Order => "outcome order",
            Self::Refund => "outcome refund",
            Self::Attribution => "attribution",
        }
    }
}

fn verify_if_existing(
    transaction: &Transaction<'_>,
    inserted: usize,
    table: ImmutableTable,
    project_id: &ProjectId,
    id: &str,
    expected_json: &str,
) -> Result<(), StorageError> {
    if inserted == 1 {
        return Ok(());
    }
    let stored = transaction
        .query_row(
            table.select_sql(),
            params![project_id.as_str(), id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: table.name(),
            project_id: project_id.clone(),
            id: id.to_owned(),
        })?;
    if stored == expected_json {
        Ok(())
    } else {
        Err(StorageError::ImmutableRecordMismatch {
            kind: table.name(),
            id: id.to_owned(),
        })
    }
}

fn commission_immutable_digest(commission: &CommissionRecord) -> Result<String, StorageError> {
    let immutable = serde_json::json!({
        "id": commission.id,
        "tenantId": commission.tenant_id,
        "projectId": commission.project_id,
        "orderId": commission.order_id,
        "partnerId": commission.partner_id,
        "rate": commission.rate,
        "eligibleNetAmount": commission.eligible_net_amount,
        "commissionAmount": commission.commission_amount,
        "termsDigest": commission.terms_digest,
        "refundSetDigest": commission.refund_set_digest,
        "supersedes": commission.supersedes,
        "calculatedAt": commission.calculated_at,
    });
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&immutable)?)
    ))
}

fn ensure_scope(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    mission_id: Option<&MissionId>,
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
    if let Some(mission_id) = mission_id {
        let mission_tenant = transaction
            .query_row(
                "SELECT tenant_id FROM missions WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), mission_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::MissionNotFound {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
            })?;
        if mission_tenant != tenant_id.as_str() {
            return Err(StorageError::TenantScopeMismatch);
        }
    }
    Ok(())
}

fn finish(
    transaction: Transaction<'_>,
    ledger: &OutcomeLedger,
    mission_id: Option<&MissionId>,
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
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            mission_id.map(MissionId::as_str),
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
         VALUES (?1, ?2, ?3, 'outcome_ledger', ?4, ?5, ?6, ?7, ?7)",
        params![
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            mission_id.map(MissionId::as_str),
            ledger.project_id.as_str(),
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
        state_revision: ledger.revision,
    })
}

fn load_json_records<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    project_id: &ProjectId,
) -> Result<Vec<T>, StorageError> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([project_id.as_str()], |row| row.get::<_, String>(0))?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

fn validate_ledger(ledger: &OutcomeLedger) -> Result<(), StorageError> {
    ledger
        .validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))
}

fn enum_name(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as a string".into()))
}

fn require_next(expected: u64, actual: u64) -> Result<(), StorageError> {
    let next = expected
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(expected))?;
    if actual == next {
        Ok(())
    } else {
        Err(StorageError::UnexpectedNextRevision {
            expected: next,
            actual,
        })
    }
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
    use std::fs;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, ActorId, CommissionId, CommissionStatus, ConnectionId, ContactPermission,
        CurrencyCode, ExternalIdentity, IdentityLink, IdentityLinkId, IdentitySubject,
        MissionContract, Money, OrderId, OutcomeEventId, OutcomeEventKind,
        OutcomeSourceVerification, OutcomeVerificationMethod, Partner, PartnerId,
        PartnerSupplyClass, PayoutId, Project, RefundId, StorageMode,
    };
    use rust_decimal::Decimal;

    use super::*;
    use crate::{DatabaseKey, STORAGE_SCHEMA_VERSION};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 9, 0, 0)
            .single()
            .expect("valid time")
    }

    fn outcome_event(kind: OutcomeEventKind, id: &str, amount_minor: i64) -> OutcomeEvent {
        OutcomeEvent {
            id: OutcomeEventId::from(id),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-11"),
            kind,
            provider: "commerce-fixture".into(),
            connection_id: Some(ConnectionId::from("connection-1")),
            account_id: Some(AccountId::from("account-1")),
            source_event_id: format!("provider-{id}"),
            identity_link_id: Some(IdentityLinkId::from("identity-1")),
            opportunity_id: None,
            campaign_id: None,
            order_id: Some(OrderId::from("order-1")),
            refund_id: None,
            commission_id: None,
            payout_id: None,
            partner_id: None,
            amount: Some(Money::new(
                amount_minor,
                CurrencyCode::parse("USD").expect("USD"),
            )),
            occurred_at: now(),
            received_at: now() + Duration::minutes(1),
            evidence_digest: "a".repeat(64),
            raw_payload_digest: "b".repeat(64),
            source_verification: Some(OutcomeSourceVerification {
                method: OutcomeVerificationMethod::SignedWebhook,
                verifier: "commerce-fixture-webhook".into(),
                independent: true,
                verified_at: now() + Duration::minutes(1),
                evidence_digest: "c".repeat(64),
            }),
        }
    }

    fn populate_store(mut store: ProjectStore) -> (ProjectStore, ProjectId, MissionId, PartnerId) {
        let project_id = ProjectId::from("project-1");
        let mission_id = MissionId::from("mission-11");
        let project = Project::create_local(
            TenantId::from("tenant-1"),
            project_id.clone(),
            "Outcome ledger",
            "",
            "/tmp/hartevo-outcome-ledger",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = hartevo_domain_kernel::Mission::compile(
            TenantId::from("tenant-1"),
            mission_id.clone(),
            project_id.clone(),
            "Outcome and attribution",
            MissionContract::bootstrap("Reconcile verified outcomes", [], now()),
            now(),
        )
        .expect("mission");
        store.save_project(&project).expect("project persisted");
        store.save_mission(&mission).expect("mission persisted");
        let partner_id = PartnerId::from("partner-1");
        let partner = Partner::create(
            partner_id.clone(),
            TenantId::from("tenant-1"),
            project_id.clone(),
            None,
            None,
            "Creator One",
            PartnerSupplyClass::HartevoOptIn,
            ContactPermission::ExplicitOptIn,
            Some("c".repeat(64)),
        )
        .expect("partner");
        store
            .create_partner(
                &partner,
                "partner.created",
                &serde_json::json!({"partnerId": partner.id}),
                now(),
            )
            .expect("partner persisted");
        let mut identity_link = IdentityLink::propose(
            IdentityLinkId::from("identity-1"),
            TenantId::from("tenant-1"),
            project_id.clone(),
            IdentitySubject::Partner(partner_id.clone()),
            [ExternalIdentity {
                provider: "commerce-fixture".into(),
                account_id: AccountId::from("account-1"),
                external_subject_digest: "d".repeat(64),
                encrypted_subject_ref: "ciphertext://buyer-identity".into(),
                evidence_digest: "e".repeat(64),
            }],
            Decimal::ONE,
        )
        .expect("identity proposal");
        store
            .create_identity_link(
                &identity_link,
                "identity_link.proposed",
                &serde_json::json!({"identityLinkId": identity_link.id}),
                now(),
            )
            .expect("identity link persisted");
        identity_link
            .confirm(ActorId::from("operator-1"), "e".repeat(64), now())
            .expect("identity confirmation");
        store
            .update_identity_link(
                &identity_link,
                1,
                "identity_link.confirmed",
                &serde_json::json!({"identityLinkId": identity_link.id}),
                now(),
            )
            .expect("identity confirmation persisted");
        (store, project_id, mission_id, partner_id)
    }

    fn setup_store() -> (ProjectStore, ProjectId, MissionId, PartnerId) {
        populate_store(ProjectStore::in_memory().expect("store"))
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the normalized ledger test keeps order, refund, supersession and replay in one auditable sequence"
    )]
    fn normalized_outcome_ledger_survives_refund_recalculation_and_replay() {
        let (mut store, project_id, mission_id, partner_id) = setup_store();
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), project_id.clone()).expect("ledger");
        store
            .create_outcome_ledger(
                &ledger,
                "outcome_ledger.created",
                &serde_json::json!({"projectId": project_id}),
                now(),
            )
            .expect("ledger persisted");

        ledger
            .ingest(outcome_event(
                OutcomeEventKind::OrderPlaced,
                "order-event",
                10_000,
            ))
            .expect("order");
        store
            .update_outcome_ledger(
                &ledger,
                1,
                Some(&mission_id),
                "outcome.order_ingested",
                &serde_json::json!({"orderId": "order-1"}),
                now(),
            )
            .expect("order persisted");
        ledger
            .calculate_commission(
                CommissionId::from("commission-1"),
                &OrderId::from("order-1"),
                partner_id.clone(),
                "0.15".parse().expect("rate"),
                "d".repeat(64),
                now() + Duration::days(1),
            )
            .expect("commission");
        store
            .update_outcome_ledger(
                &ledger,
                2,
                Some(&mission_id),
                "outcome.commission_calculated",
                &serde_json::json!({"commissionId": "commission-1"}),
                now() + Duration::days(1),
            )
            .expect("commission persisted");

        let mut refund = outcome_event(OutcomeEventKind::RefundIssued, "refund-event", 2_500);
        refund.refund_id = Some(RefundId::from("refund-1"));
        refund.occurred_at = now() + Duration::days(2);
        refund.received_at = now() + Duration::days(3);
        refund
            .source_verification
            .as_mut()
            .expect("verified source")
            .verified_at = refund.received_at;
        ledger.ingest(refund).expect("refund");
        assert_eq!(
            ledger.commissions[0].status,
            CommissionStatus::RecalculationRequired
        );
        store
            .update_outcome_ledger(
                &ledger,
                3,
                Some(&mission_id),
                "outcome.refund_ingested",
                &serde_json::json!({"refundId": "refund-1"}),
                now() + Duration::days(3),
            )
            .expect("refund persisted");
        ledger
            .calculate_commission(
                CommissionId::from("commission-2"),
                &OrderId::from("order-1"),
                partner_id,
                "0.15".parse().expect("rate"),
                "d".repeat(64),
                now() + Duration::days(4),
            )
            .expect("recalculated");
        store
            .update_outcome_ledger(
                &ledger,
                4,
                Some(&mission_id),
                "outcome.commission_recalculated",
                &serde_json::json!({"commissionId": "commission-2"}),
                now() + Duration::days(4),
            )
            .expect("recalculation persisted");

        let restored = store
            .load_outcome_ledger(&project_id)
            .expect("restored ledger");
        assert_eq!(restored, ledger);
        assert_eq!(restored.commissions[0].status, CommissionStatus::Superseded);
        assert_eq!(
            restored.commissions[1].commission_amount.amount_minor,
            1_125
        );
        assert_eq!(restored.revision, 5);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration test constructs a real encrypted v16 outcome ledger, removes v17 proof fields, and verifies fail-closed reconciliation after backup"
    )]
    fn migration_v17_preserves_legacy_outcomes_but_never_upgrades_them_to_verified() {
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("outcome-v16.sqlite3");
        let key = DatabaseKey::new([9; 32]).expect("database key");
        let project_id;
        {
            let store = ProjectStore::open(&database, &key).expect("current store");
            let (mut store, project, mission_id, _) = populate_store(store);
            project_id = project;
            let mut ledger =
                OutcomeLedger::new(TenantId::from("tenant-1"), project_id.clone()).expect("ledger");
            store
                .create_outcome_ledger(
                    &ledger,
                    "outcome_ledger.created",
                    &serde_json::json!({}),
                    now(),
                )
                .expect("ledger");
            ledger
                .ingest(outcome_event(
                    OutcomeEventKind::OrderPlaced,
                    "legacy-order-event",
                    10_000,
                ))
                .expect("verified order before downgrade");
            store
                .update_outcome_ledger(
                    &ledger,
                    1,
                    Some(&mission_id),
                    "outcome.order_ingested",
                    &serde_json::json!({}),
                    now(),
                )
                .expect("persist order");
            store
                .connection
                .execute_batch(
                    "UPDATE outcome_events
                     SET record_json = json_remove(
                       record_json, '$.connectionId', '$.sourceVerification'
                     );
                     DROP TABLE runtime_turn_evidence;
                     DROP TABLE runtime_turn_attempts;
                     DROP TABLE context_assembly_manifests;
                     DROP TABLE runtime_recovery_attempts;
                     DROP TABLE context_branch_merges;
                     DROP TABLE context_worker_messages;
                     DROP TABLE context_worker_mailboxes;
                     DROP TABLE context_worker_handles;
                     DROP TABLE context_checkpoints;
                     DROP TABLE context_compaction_records;
                     DROP TABLE context_continuation_entries;
                     DROP TABLE context_continuation_ledgers;
                     DROP TABLE context_working_items;
                     DROP TABLE context_working_sets;
                     DROP TABLE effect_reconciliation_attempts;
                     DROP TABLE effect_reconciliation_heads;
                     DROP TABLE effect_rate_limit_reservations;
                     DROP TABLE effect_rate_limit_decisions;
                     DROP TABLE effect_rate_limit_buckets;
                     ALTER TABLE identity_links DROP COLUMN decision_history_json;
                     DROP TABLE key_bootstrap_operations;
                     DROP TABLE device_key_attachments;
                     DROP TABLE deletion_propagation_receipts;
                     DROP TABLE deletion_propagation_jobs;
                     DROP TABLE sync_deletion_records;
                     DROP TABLE context_capsule_facts;
                     DROP TABLE context_capsules;
                     DROP TABLE worker_leases;
                     DROP TABLE context_branches;
                     DROP TABLE context_workspaces;
                     DROP INDEX outcome_event_source_verification_idx;
                     ALTER TABLE outcome_events DROP COLUMN connection_id;
                     ALTER TABLE outcome_events DROP COLUMN source_verification_method;
                     ALTER TABLE outcome_events DROP COLUMN source_verifier;
                     ALTER TABLE outcome_events DROP COLUMN source_verification_independent;
                     ALTER TABLE outcome_events DROP COLUMN source_verified_at;
                     ALTER TABLE outcome_events DROP COLUMN source_verification_evidence_digest;
                     DROP TABLE IF EXISTS runtime_turn_private_messages;
                     DROP TABLE IF EXISTS mission_conversation_messages;
                     DROP TABLE IF EXISTS mission_conversations;
                     DROP TABLE IF EXISTS mission_checkpoints;
                     DROP TABLE IF EXISTS mission_definition_oracles;
                     DROP TABLE IF EXISTS mission_definition_artifacts;
                     DROP TABLE IF EXISTS mission_definition_capabilities;
                     DROP TABLE IF EXISTS mission_definitions;
                     DELETE FROM schema_migrations WHERE version >= 17;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("downgrade fixture to v16");
            assert_eq!(store.schema_version().expect("v16 schema"), 16);
        }

        let migrated = ProjectStore::open(&database, &key).expect("migrate to v17");
        assert_eq!(
            migrated.schema_version().expect("schema"),
            STORAGE_SCHEMA_VERSION
        );
        let legacy = migrated
            .load_outcome_ledger(&project_id)
            .expect("legacy outcome remains inspectable");
        assert_eq!(legacy.events.len(), 1);
        assert!(legacy.events[0].connection_id.is_none());
        assert!(legacy.events[0].source_verification.is_none());
        assert_eq!(
            legacy.events[0].validate(),
            Err(hartevo_domain_kernel::OutcomeLedgerError::UnverifiedOutcomeSource)
        );
        let normalized: (Option<String>, Option<String>, Option<String>) = migrated
            .connection
            .query_row(
                "SELECT connection_id, source_verification_method,
                        source_verification_evidence_digest
                 FROM outcome_events WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), "legacy-order-event"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("normalized legacy proof columns");
        assert_eq!(normalized, (None, None, None));
        drop(migrated);

        let backups = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v16")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0].metadata().expect("backup metadata").len() > 0);
        let reopened = ProjectStore::open(&database, &key).expect("idempotent reopen");
        assert_eq!(
            reopened.schema_version().expect("schema"),
            STORAGE_SCHEMA_VERSION
        );
        let backup_count = fs::read_dir(directory.path())
            .expect("backup directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v16")
            })
            .count();
        assert_eq!(backup_count, 1);
    }

    #[test]
    fn old_outcome_event_cannot_be_rewritten_inside_a_later_revision() {
        let (mut store, project_id, mission_id, partner_id) = setup_store();
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), project_id.clone()).expect("ledger");
        store
            .create_outcome_ledger(
                &ledger,
                "outcome_ledger.created",
                &serde_json::json!({}),
                now(),
            )
            .expect("ledger persisted");
        ledger
            .ingest(outcome_event(
                OutcomeEventKind::OrderPlaced,
                "order-event",
                10_000,
            ))
            .expect("order");
        store
            .update_outcome_ledger(
                &ledger,
                1,
                Some(&mission_id),
                "outcome.order_ingested",
                &serde_json::json!({}),
                now(),
            )
            .expect("order persisted");

        ledger.events[0].raw_payload_digest = "e".repeat(64);
        let mut payout = outcome_event(OutcomeEventKind::PayoutCompleted, "payout-event", 1_500);
        payout.order_id = None;
        payout.payout_id = Some(PayoutId::from("payout-1"));
        payout.partner_id = Some(partner_id);
        ledger.ingest(payout).expect("new payout event");
        let result = store.update_outcome_ledger(
            &ledger,
            2,
            Some(&mission_id),
            "outcome.payout_ingested",
            &serde_json::json!({}),
            now() + Duration::days(1),
        );
        assert!(matches!(
            result,
            Err(StorageError::ImmutableRecordMismatch {
                kind: "outcome event",
                ..
            })
        ));
        assert_eq!(
            store
                .load_outcome_ledger(&project_id)
                .expect("unchanged ledger")
                .revision,
            2
        );
    }
}

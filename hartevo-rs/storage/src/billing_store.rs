use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ProjectId, ScopedVerifiedStripeWebhook, StripeBillingFact, StripeBillingFactKind,
    StripeBillingLedger, StripeFactSource,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::Value;

use crate::aggregate::{PendingEvent, append_events, ensure_project_scope};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BillingPersistenceDisposition {
    Applied,
    Replayed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BillingPersistenceOutcome {
    pub disposition: BillingPersistenceDisposition,
    pub revision: u64,
    pub fact_digest: String,
    pub event_sequence: Option<i64>,
    pub outbox_sequence: Option<i64>,
}

impl ProjectStore {
    /// Persists a verified, scope-bound Stripe webhook as one immutable fact.
    /// A duplicate event id with the same payload is a replay; a payload swap
    /// is a hard conflict and never reaches the outbox.
    pub fn ingest_stripe_billing_webhook(
        &mut self,
        webhook: &ScopedVerifiedStripeWebhook,
    ) -> Result<BillingPersistenceOutcome, StorageError> {
        let fact = webhook.fact()?;
        let project = self.load_project(&fact.project_id)?;
        if project.tenant_id != fact.tenant_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        let recorded_at = webhook.webhook.received_at;
        let event_type = webhook.webhook.event.event_type.as_str().to_owned();
        let object_id = webhook.webhook.event.object_id.clone();
        let event_id = webhook.event_id().to_owned();
        let payload_digest = webhook.webhook.event.payload_digest.clone();
        let signature_digest = webhook.webhook.signature_digest.clone();
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            fact.tenant_id.as_str(),
            fact.project_id.as_str(),
        )?;

        if let Some((existing_payload_digest, existing_fact_digest)) = transaction
            .query_row(
                "SELECT payload_digest, fact_digest
                 FROM stripe_webhook_events
                 WHERE project_id = ?1 AND event_id = ?2",
                params![fact.project_id.as_str(), event_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if existing_payload_digest != payload_digest {
                return Err(StorageError::BillingWebhookConflict { event_id });
            }
            let revision = transaction
                .query_row(
                    "SELECT revision FROM stripe_billing_facts
                     WHERE project_id = ?1 AND immutable_digest = ?2",
                    params![fact.project_id.as_str(), existing_fact_digest.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .ok_or(StorageError::BillingLedgerIntegrity)?;
            transaction.commit()?;
            return Ok(BillingPersistenceOutcome {
                disposition: BillingPersistenceDisposition::Replayed,
                revision: u64::try_from(revision)
                    .map_err(|_| StorageError::BillingLedgerIntegrity)?,
                fact_digest: existing_fact_digest,
                event_sequence: None,
                outbox_sequence: None,
            });
        }

        let (revision, event_sequence, outbox_sequence) = insert_fact_and_event(
            &transaction,
            &fact,
            recorded_at,
            Some((
                &event_id,
                &event_type,
                &object_id,
                &payload_digest,
                &signature_digest,
            )),
            "billing.stripe_webhook_recorded",
        )?;
        transaction.commit()?;
        Ok(BillingPersistenceOutcome {
            disposition: BillingPersistenceDisposition::Applied,
            revision,
            fact_digest: fact.immutable_digest,
            event_sequence: Some(event_sequence),
            outbox_sequence: Some(outbox_sequence),
        })
    }

    /// Persists a read-back fact from a provider reconciliation request. The
    /// caller must construct it with a Reconciliation source; webhook facts
    /// cannot be upgraded into settlement evidence after the fact.
    pub fn record_stripe_reconciliation_fact(
        &mut self,
        fact: StripeBillingFact,
    ) -> Result<BillingPersistenceOutcome, StorageError> {
        if !fact.source.is_reconciliation() {
            return Err(
                hartevo_domain_kernel::BillingLedgerError::ReconciliationSourceRequired.into(),
            );
        }
        let project = self.load_project(&fact.project_id)?;
        if project.tenant_id != fact.tenant_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            fact.tenant_id.as_str(),
            fact.project_id.as_str(),
        )?;
        if let Some(revision) = transaction
            .query_row(
                "SELECT revision FROM stripe_billing_facts
                 WHERE project_id = ?1 AND immutable_digest = ?2",
                params![fact.project_id.as_str(), fact.immutable_digest.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            transaction.commit()?;
            return Ok(BillingPersistenceOutcome {
                disposition: BillingPersistenceDisposition::Replayed,
                revision: u64::try_from(revision)
                    .map_err(|_| StorageError::BillingLedgerIntegrity)?,
                fact_digest: fact.immutable_digest,
                event_sequence: None,
                outbox_sequence: None,
            });
        }
        let (revision, event_sequence, outbox_sequence) = insert_fact_and_event(
            &transaction,
            &fact,
            fact.observed_at,
            None,
            "billing.stripe_reconciled",
        )?;
        transaction.commit()?;
        Ok(BillingPersistenceOutcome {
            disposition: BillingPersistenceDisposition::Applied,
            revision,
            fact_digest: fact.immutable_digest,
            event_sequence: Some(event_sequence),
            outbox_sequence: Some(outbox_sequence),
        })
    }

    pub fn load_stripe_billing_ledger(
        &self,
        project_id: &ProjectId,
    ) -> Result<StripeBillingLedger, StorageError> {
        self.load_project(project_id)?;
        let mut statement = self.connection.prepare(
            "SELECT revision, fact_kind, source_kind, source_id, immutable_digest, record_json
             FROM stripe_billing_facts
             WHERE project_id = ?1
             ORDER BY revision ASC",
        )?;
        let mut rows = statement.query([project_id.as_str()])?;
        let mut facts = Vec::new();
        let mut expected_revision = 1_u64;
        while let Some(row) = rows.next()? {
            let revision = u64::try_from(row.get::<_, i64>(0)?)
                .map_err(|_| StorageError::BillingLedgerIntegrity)?;
            let fact_kind = row.get::<_, String>(1)?;
            let source_kind = row.get::<_, String>(2)?;
            let source_id = row.get::<_, String>(3)?;
            let immutable_digest = row.get::<_, String>(4)?;
            let fact: StripeBillingFact = serde_json::from_str(&row.get::<_, String>(5)?)?;
            if revision != expected_revision
                || fact.project_id != *project_id
                || fact.immutable_digest != immutable_digest
                || serde_json::to_value(fact.kind)? != Value::String(fact_kind)
                || source_kind_for(&fact.source) != source_kind
                || source_id_for(&fact.source) != source_id
            {
                return Err(StorageError::BillingLedgerIntegrity);
            }
            facts.push(fact);
            expected_revision = expected_revision
                .checked_add(1)
                .ok_or(StorageError::BillingLedgerIntegrity)?;
        }
        let mut event_statement = self.connection.prepare(
            "SELECT event_id, payload_digest FROM stripe_webhook_events
             WHERE project_id = ?1 ORDER BY event_id ASC",
        )?;
        let event_rows = event_statement.query_map([project_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let webhook_event_digests = event_rows.collect::<Result<BTreeMap<_, _>, _>>()?;
        let revision = expected_revision.saturating_sub(1);
        StripeBillingLedger::from_parts(revision, webhook_event_digests, facts)
            .map_err(StorageError::from)
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_fact_and_event(
    transaction: &Transaction<'_>,
    fact: &StripeBillingFact,
    recorded_at: DateTime<Utc>,
    webhook: Option<(&str, &str, &str, &str, &str)>,
    event_type: &str,
) -> Result<(u64, i64, i64), StorageError> {
    let existing_fact_id = transaction
        .query_row(
            "SELECT immutable_digest FROM stripe_billing_facts
             WHERE project_id = ?1 AND fact_id = ?2",
            params![fact.project_id.as_str(), fact.fact_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if existing_fact_id.is_some_and(|digest| digest != fact.immutable_digest) {
        return Err(StorageError::BillingLedgerIntegrity);
    }
    let previous_revision = transaction.query_row(
        "SELECT COALESCE(MAX(revision), 0) FROM stripe_billing_facts WHERE project_id = ?1",
        [fact.project_id.as_str()],
        |row| row.get::<_, i64>(0),
    )?;
    let revision_i64 = previous_revision
        .checked_add(1)
        .ok_or(StorageError::BillingLedgerIntegrity)?;
    let revision = u64::try_from(revision_i64).map_err(|_| StorageError::BillingLedgerIntegrity)?;
    let record_json = serde_json::to_string(fact)?;
    transaction.execute(
        "INSERT INTO stripe_billing_facts
           (tenant_id, project_id, revision, fact_id, external_id, fact_kind,
            source_kind, source_id, immutable_digest, observed_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            fact.tenant_id.as_str(),
            fact.project_id.as_str(),
            revision_i64,
            fact.fact_id.as_str(),
            fact.external_id.as_str(),
            fact_kind_for(fact.kind),
            source_kind_for(&fact.source),
            source_id_for(&fact.source),
            fact.immutable_digest.as_str(),
            fact.observed_at.to_rfc3339(),
            record_json,
        ],
    )?;
    if let Some((event_id, webhook_event_type, object_id, payload_digest, signature_digest)) =
        webhook
    {
        transaction.execute(
            "INSERT INTO stripe_webhook_events
               (tenant_id, project_id, event_id, event_type, object_id, payload_digest,
                signature_digest, fact_digest, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                fact.tenant_id.as_str(),
                fact.project_id.as_str(),
                event_id,
                webhook_event_type,
                object_id,
                payload_digest,
                signature_digest,
                fact.immutable_digest.as_str(),
                recorded_at.to_rfc3339(),
            ],
        )?;
    }
    let payload = serde_json::to_value(fact)?;
    let (event_sequences, outbox_sequences) = append_events(
        transaction,
        fact.tenant_id.as_str(),
        fact.project_id.as_str(),
        None,
        "billing_ledger",
        fact.project_id.as_str(),
        &[PendingEvent::new(event_type, payload, recorded_at)],
    )?;
    Ok((revision, event_sequences[0], outbox_sequences[0]))
}

fn source_kind_for(source: &StripeFactSource) -> &'static str {
    match source {
        StripeFactSource::Webhook { .. } => "webhook",
        StripeFactSource::Reconciliation { .. } => "reconciliation",
    }
}

fn source_id_for(source: &StripeFactSource) -> &str {
    match source {
        StripeFactSource::Webhook { event_id, .. } => event_id,
        StripeFactSource::Reconciliation { request_id, .. } => request_id,
    }
}

fn fact_kind_for(kind: StripeBillingFactKind) -> &'static str {
    match kind {
        StripeBillingFactKind::Customer => "customer",
        StripeBillingFactKind::Subscription => "subscription",
        StripeBillingFactKind::ProviderAccepted => "provider_accepted",
        StripeBillingFactKind::Invoice => "invoice",
        StripeBillingFactKind::Payment => "payment",
        StripeBillingFactKind::Credit => "credit",
        StripeBillingFactKind::Refund => "refund",
        StripeBillingFactKind::Dispute => "dispute",
        StripeBillingFactKind::Payout => "payout",
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use hartevo_domain_kernel::{
        CurrencyCode, Money, Project, ProjectId, ScopedVerifiedStripeWebhook, StorageMode,
        StripeBillingFact, StripeBillingFactPayload, StripeFactSource, TenantId,
        verify_stripe_webhook,
    };
    use sha2::{Digest, Sha256};

    use super::*;

    const FIXTURE_SECRET: &str = "whsec_money01_fixture";
    const FIXTURE_BODY: &str = include_str!(
        "../../../contracts/providers/stripe-fixtures/checkout-session-completed.json"
    );

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 2, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn hmac_hex(key: &[u8], message: &[u8]) -> String {
        let mut key_block = [0_u8; 64];
        if key.len() > key_block.len() {
            key_block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha256::new();
        for byte in &mut key_block {
            *byte ^= 0x36;
        }
        inner.update(key_block);
        inner.update(message);
        let inner_digest = inner.finalize();
        for byte in &mut key_block {
            *byte ^= 0x36 ^ 0x5c;
        }
        let mut outer = Sha256::new();
        outer.update(key_block);
        outer.update(inner_digest);
        format!("{:x}", outer.finalize())
    }

    fn signed(body: &str) -> ScopedVerifiedStripeWebhook {
        let timestamp = now().timestamp();
        let signature = format!(
            "t={timestamp},v1={}",
            hmac_hex(
                FIXTURE_SECRET.as_bytes(),
                format!("{timestamp}.{body}").as_bytes(),
            )
        );
        verify_stripe_webhook(
            body,
            &signature,
            FIXTURE_SECRET,
            now(),
            chrono::Duration::seconds(300),
        )
        .expect("verify fixture")
        .bind_scope(
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
        )
        .expect("bind fixture")
    }

    fn project() -> Project {
        Project::create_local(
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
            "Money fixture",
            "",
            "/tmp/hartevo-money01-storage",
            StorageMode::LocalExisting,
        )
        .expect("project")
    }

    #[test]
    fn signed_webhook_is_persisted_once_and_acceptance_is_not_settlement() {
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project()).expect("persist project");
        let webhook = signed(FIXTURE_BODY);
        let applied = store
            .ingest_stripe_billing_webhook(&webhook)
            .expect("persist webhook");
        assert_eq!(applied.disposition, BillingPersistenceDisposition::Applied);
        let replay = store
            .ingest_stripe_billing_webhook(&webhook)
            .expect("replay webhook");
        assert_eq!(replay.disposition, BillingPersistenceDisposition::Replayed);
        assert_eq!(replay.fact_digest, applied.fact_digest);
        let ledger = store
            .load_stripe_billing_ledger(&ProjectId::from("project-money"))
            .expect("ledger");
        assert_eq!(ledger.revision, 1);
        assert!(!ledger.facts[0].is_independently_settled());
        assert_eq!(
            store
                .events_for_project(&ProjectId::from("project-money"))
                .expect("events")
                .len(),
            1
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM outbox_messages", [], |row| row
                    .get::<_, i64>(0))
                .expect("outbox"),
            1
        );
    }

    #[test]
    fn same_event_id_with_changed_payload_is_a_hard_conflict() {
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project()).expect("persist project");
        store
            .ingest_stripe_billing_webhook(&signed(FIXTURE_BODY))
            .expect("persist webhook");
        let changed = FIXTURE_BODY.replace("\"amount_total\":4900", "\"amount_total\":4901");
        let error = store
            .ingest_stripe_billing_webhook(&signed(&changed))
            .expect_err("payload swap must fail");
        assert!(matches!(error, StorageError::BillingWebhookConflict { .. }));
    }

    #[test]
    fn reconciliation_fact_is_append_only_and_can_settle_a_payout() {
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project()).expect("persist project");
        let fact = StripeBillingFact::new(
            "reconciliation:payout-money",
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
            StripeFactSource::Reconciliation {
                request_id: "reconcile-payout-money".into(),
                readback_digest: "b".repeat(64),
                observed_at: now(),
            },
            now(),
            StripeBillingFactPayload::Payout {
                payout_id: "po_money01".into(),
                connected_account_id: Some("acct_money01".into()),
                amount: Money::new(1_000, CurrencyCode::parse("USD").expect("USD")),
                status: hartevo_domain_kernel::StripePayoutStatus::Paid,
                arrival_at: None,
            },
        )
        .expect("fact");
        store
            .record_stripe_reconciliation_fact(fact.clone())
            .expect("reconciliation");
        assert!(
            store
                .load_stripe_billing_ledger(&ProjectId::from("project-money"))
                .expect("ledger")
                .facts[0]
                .is_independently_settled()
        );
        let replay = store
            .record_stripe_reconciliation_fact(fact)
            .expect("replay reconciliation");
        assert_eq!(replay.disposition, BillingPersistenceDisposition::Replayed);
    }
}

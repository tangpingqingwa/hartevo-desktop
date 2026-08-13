//! Durable append-only storage boundary for the attribution spine.
//!
//! ATTR-01 deliberately uses the existing `domain_events` table. This keeps
//! SQLCipher schema v47 unchanged while preserving immutable observation
//! batches, provider cursor fences, and deterministic replay after restart.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE, ATTRIBUTION_SPINE_EVENT_TYPE,
    ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE, AttributionError, AttributionLedger,
    CurrencyCode, OutcomeCandidate, OutcomeCandidateId, OutcomeVerification, ProjectId,
    SourceObservationBatch, TenantId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DomainEventRecord, ProjectStore, StorageError};

impl ProjectStore {
    /// Appends one connector observation batch as an immutable domain event.
    /// The batch's provider cursor is the durable replay fence; no connector
    /// response is promoted to a verified outcome by this write.
    pub fn append_attribution_observation_batch(
        &mut self,
        batch: &SourceObservationBatch,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        batch
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if let Some(existing) = self
            .events_for_project(&batch.project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_SPINE_EVENT_TYPE)
            .find_map(|event| {
                decode_batch(event.clone(), &batch.tenant_id, &batch.project_id)
                    .ok()
                    .filter(|existing| existing == batch)
                    .map(|_| event.sequence)
            })
        {
            return Ok(existing);
        }
        let reporting_currency = batch
            .events
            .iter()
            .find_map(|event| event.amount.as_ref().map(|amount| amount.currency.clone()))
            .unwrap_or_else(|| CurrencyCode::parse("USD").expect("static currency"));
        let mut ledger = self.replay_attribution_spine(&batch.project_id, reporting_currency)?;
        ledger
            .ingest_batch(batch.clone())
            .map_err(|error| domain_decode(&error))?;
        let payload = serde_json::to_value(batch)?;
        self.append_event(
            &batch.project_id,
            batch.mission_id.as_ref(),
            ATTRIBUTION_SPINE_EVENT_TYPE,
            &payload,
            recorded_at,
        )
    }

    /// Persists the candidate stage independently from verification. A
    /// duplicate exact candidate is idempotent; a same-id content swap is
    /// rejected before another domain event can be appended.
    pub fn append_attribution_candidate(
        &mut self,
        project_id: &ProjectId,
        candidate: &OutcomeCandidate,
        reporting_currency: CurrencyCode,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let mut ledger = self.replay_attribution_spine(project_id, reporting_currency)?;
        if let Some(existing) = ledger
            .candidates
            .iter()
            .find(|existing| existing.id == candidate.id)
        {
            if existing == candidate {
                return self.find_attribution_record_sequence(
                    project_id,
                    ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE,
                    |payload| {
                        serde_json::from_value::<OutcomeCandidate>(payload.clone())
                            .ok()
                            .is_some_and(|value| value == *candidate)
                    },
                );
            }
            return Err(StorageError::DomainDecode(
                "attribution candidate content conflicts with immutable history".into(),
            ));
        }
        ledger
            .register_candidate(candidate.clone())
            .map_err(|error| domain_decode(&error))?;
        let event = ledger
            .events
            .iter()
            .find(|event| event.id == candidate.source_event_id)
            .ok_or_else(|| StorageError::DomainDecode("candidate source event missing".into()))?;
        let payload = serde_json::to_value(candidate)?;
        self.append_event(
            project_id,
            event.mission_id.as_ref(),
            ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE,
            &payload,
            recorded_at,
        )
    }

    /// Persists an independent verification record without mutating the
    /// candidate payload. Exact replay is idempotent; a second, different
    /// verification for one candidate fails closed.
    pub fn append_attribution_verification(
        &mut self,
        project_id: &ProjectId,
        candidate_id: &OutcomeCandidateId,
        verification: &OutcomeVerification,
        reporting_currency: CurrencyCode,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let mut ledger = self.replay_attribution_spine(project_id, reporting_currency)?;
        let candidate = ledger
            .candidates
            .iter()
            .find(|candidate| candidate.id == *candidate_id)
            .cloned()
            .ok_or_else(|| StorageError::DomainDecode("verification candidate missing".into()))?;
        if let Some(existing) = ledger
            .verified_outcomes
            .iter()
            .find(|existing| existing.candidate_id == *candidate_id)
        {
            if existing.verification == *verification {
                let record = StoredAttributionVerification {
                    candidate_id: candidate_id.clone(),
                    verification: verification.clone(),
                };
                return self.find_attribution_record_sequence(
                    project_id,
                    ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE,
                    |payload| {
                        serde_json::from_value::<StoredAttributionVerification>(payload.clone())
                            .ok()
                            .is_some_and(|value| value == record)
                    },
                );
            }
            return Err(StorageError::DomainDecode(
                "verified outcome content conflicts with immutable history".into(),
            ));
        }
        ledger
            .verify_candidate(candidate_id, verification.clone())
            .map_err(|error| domain_decode(&error))?;
        let event = ledger
            .events
            .iter()
            .find(|event| event.id == candidate.source_event_id)
            .ok_or_else(|| {
                StorageError::DomainDecode("verification source event missing".into())
            })?;
        let payload = serde_json::to_value(StoredAttributionVerification {
            candidate_id: candidate_id.clone(),
            verification: verification.clone(),
        })?;
        self.append_event(
            project_id,
            event.mission_id.as_ref(),
            ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE,
            &payload,
            recorded_at,
        )
    }

    /// Reads only ATTR-01 observation batches for one project, retaining the
    /// domain-event sequence as the durable order and never repairing state.
    pub fn attribution_observation_batches(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<SourceObservationBatch>, StorageError> {
        let project = self.load_project(project_id)?;
        self.events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_SPINE_EVENT_TYPE)
            .map(|event| decode_batch(event, &project.tenant_id, project_id))
            .collect()
    }

    /// Rebuilds the Domain Kernel ledger from persisted immutable batches.
    /// Replaying is intentionally strict: a missing/corrupt cursor or a
    /// changed identity causes a fail-closed error instead of a best-effort
    /// projection.
    pub fn replay_attribution_spine(
        &self,
        project_id: &ProjectId,
        reporting_currency: CurrencyCode,
    ) -> Result<AttributionLedger, StorageError> {
        let project = self.load_project(project_id)?;
        let mut ledger = AttributionLedger::new(
            project.tenant_id.clone(),
            project_id.clone(),
            reporting_currency,
        )
        .map_err(|error| domain_decode(&error))?;
        for event in self.events_for_project(project_id)? {
            let event_mission_id = event.mission_id.clone();
            match event.event_type.as_str() {
                ATTRIBUTION_SPINE_EVENT_TYPE => {
                    let batch = decode_batch(event, &project.tenant_id, project_id)?;
                    ledger
                        .ingest_batch(batch)
                        .map_err(|error| domain_decode(&error))?;
                }
                ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE => {
                    let candidate: OutcomeCandidate = serde_json::from_value(event.payload)?;
                    let source_event = ledger
                        .events
                        .iter()
                        .find(|source| source.id == candidate.source_event_id)
                        .ok_or_else(|| {
                            StorageError::DomainDecode(
                                "candidate source event missing during replay".into(),
                            )
                        })?;
                    if source_event.mission_id != event_mission_id {
                        return Err(StorageError::DomainDecode(
                            "candidate mission scope differs from its source event".into(),
                        ));
                    }
                    if let Some(existing) = ledger
                        .candidates
                        .iter()
                        .find(|existing| existing.id == candidate.id)
                    {
                        if existing != &candidate {
                            return Err(StorageError::DomainDecode(
                                "duplicate attribution candidate differs from history".into(),
                            ));
                        }
                    } else {
                        ledger
                            .register_candidate(candidate)
                            .map_err(|error| domain_decode(&error))?;
                    }
                }
                ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE => {
                    let record: StoredAttributionVerification =
                        serde_json::from_value(event.payload)?;
                    let candidate = ledger
                        .candidates
                        .iter()
                        .find(|candidate| candidate.id == record.candidate_id)
                        .ok_or_else(|| {
                            StorageError::DomainDecode(
                                "verification candidate missing during replay".into(),
                            )
                        })?;
                    let source_event = ledger
                        .events
                        .iter()
                        .find(|source| source.id == candidate.source_event_id)
                        .ok_or_else(|| {
                            StorageError::DomainDecode(
                                "verification source event missing during replay".into(),
                            )
                        })?;
                    if source_event.mission_id != event_mission_id {
                        return Err(StorageError::DomainDecode(
                            "verification mission scope differs from its source event".into(),
                        ));
                    }
                    if let Some(existing) = ledger
                        .verified_outcomes
                        .iter()
                        .find(|existing| existing.candidate_id == record.candidate_id)
                    {
                        if existing.verification != record.verification {
                            return Err(StorageError::DomainDecode(
                                "duplicate verified outcome differs from history".into(),
                            ));
                        }
                    } else {
                        ledger
                            .verify_candidate(&record.candidate_id, record.verification)
                            .map_err(|error| domain_decode(&error))?;
                    }
                }
                _ => {}
            }
        }
        ledger.validate().map_err(|error| domain_decode(&error))?;
        Ok(ledger)
    }

    fn find_attribution_record_sequence(
        &self,
        project_id: &ProjectId,
        event_type: &str,
        matches: impl Fn(&Value) -> bool,
    ) -> Result<i64, StorageError> {
        self.events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .find(|event| matches(&event.payload))
            .map(|event| event.sequence)
            .ok_or_else(|| {
                StorageError::DomainDecode("attribution idempotency record missing".into())
            })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredAttributionVerification {
    candidate_id: OutcomeCandidateId,
    verification: OutcomeVerification,
}

fn decode_batch(
    event: DomainEventRecord,
    tenant_id: &TenantId,
    project_id: &ProjectId,
) -> Result<SourceObservationBatch, StorageError> {
    let recorded_mission_id = event.mission_id.clone();
    let batch: SourceObservationBatch = serde_json::from_value(event.payload)?;
    if batch.tenant_id != *tenant_id
        || batch.project_id != *project_id
        || batch.mission_id != recorded_mission_id
    {
        return Err(StorageError::DomainDecode(
            "attribution observation batch scope mismatch".into(),
        ));
    }
    batch
        .validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
    Ok(batch)
}

fn domain_decode(error: &AttributionError) -> StorageError {
    StorageError::DomainDecode(error.to_string())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        CorrectionLineage, CurrencyCode, Money, ObservationOrigin, ObservationProvenance,
        OutcomeVerification, Project, ProjectId, ProviderCursor, ProviderEntityRef,
        ProviderEventIdentity, SourceEntityKind, SourceEvent, SourceEventId, SourceEventKind,
        SourceEventLinks, StorageMode, TenantId, VerificationMethod,
    };
    use serde_json::json;

    use super::*;
    use crate::PendingEvent;

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .expect("time")
            + Duration::minutes(minute)
    }

    fn setup_store() -> ProjectStore {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Attribution",
            "",
            "/tmp/hartevo-attribution-spine",
            StorageMode::LocalExisting,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), at(0))],
            )
            .expect("project event");
        store
    }

    fn click_batch() -> SourceObservationBatch {
        let provider = "meta";
        let identity = ProviderEventIdentity::new(provider, "acct-1", "click-1").expect("identity");
        let account =
            ProviderEntityRef::new(SourceEntityKind::Account, provider, "acct-1", "acct-1")
                .expect("account");
        let mut links = SourceEventLinks::new(account).expect("links");
        links.click = Some(
            ProviderEntityRef::new(SourceEntityKind::Click, provider, "acct-1", "click-1")
                .expect("click"),
        );
        let event = SourceEvent {
            id: SourceEventId::from_stable("click-1"),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: None,
            identity,
            kind: SourceEventKind::Click,
            links,
            provider_occurred_at: at(1),
            observed_at: at(2),
            ingested_at: at(3),
            amount: None,
            fx_quote: None,
            provenance: ObservationProvenance::new(
                ObservationOrigin::FirstParty,
                "a".repeat(64),
                at(2),
            )
            .expect("provenance"),
            lineage: CorrectionLineage::original(SourceEventId::from_stable("click-1")),
            payload_digest: "b".repeat(64),
        };
        let mut batch = SourceObservationBatch {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: None,
            provider: provider.into(),
            account_id: "acct-1".into(),
            cursor_before: None,
            cursor_after: ProviderCursor {
                provider: provider.into(),
                account_id: "acct-1".into(),
                sequence: 1,
                token: "cursor-1".into(),
                observed_through: at(2),
                ingested_at: at(3),
                batch_digest: "c".repeat(64),
            },
            events: vec![event],
        };
        batch.cursor_after.batch_digest = batch.content_digest().expect("batch digest");
        batch
    }

    fn order_batch(cursor_before: ProviderCursor) -> SourceObservationBatch {
        let provider = "meta";
        let identity = ProviderEventIdentity::new(provider, "acct-1", "order-1").expect("identity");
        let account =
            ProviderEntityRef::new(SourceEntityKind::Account, provider, "acct-1", "acct-1")
                .expect("account");
        let mut links = SourceEventLinks::new(account).expect("links");
        links.order = Some(
            ProviderEntityRef::new(SourceEntityKind::Order, provider, "acct-1", "order-1")
                .expect("order"),
        );
        let order = SourceEvent {
            id: SourceEventId::from_stable("order-1"),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: None,
            identity,
            kind: SourceEventKind::Order,
            links,
            provider_occurred_at: at(5),
            observed_at: at(6),
            ingested_at: at(7),
            amount: Some(Money::new(12_000, CurrencyCode::parse("USD").expect("USD"))),
            fx_quote: None,
            provenance: ObservationProvenance::new(
                ObservationOrigin::FirstParty,
                "d".repeat(64),
                at(6),
            )
            .expect("provenance"),
            lineage: CorrectionLineage::original(SourceEventId::from_stable("order-1")),
            payload_digest: "e".repeat(64),
        };
        let mut batch = SourceObservationBatch {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: None,
            provider: provider.into(),
            account_id: "acct-1".into(),
            cursor_before: Some(cursor_before),
            cursor_after: ProviderCursor {
                provider: provider.into(),
                account_id: "acct-1".into(),
                sequence: 2,
                token: "cursor-2".into(),
                observed_through: at(6),
                ingested_at: at(7),
                batch_digest: "f".repeat(64),
            },
            events: vec![order],
        };
        batch.cursor_after.batch_digest = batch.content_digest().expect("digest");
        batch
    }

    #[test]
    fn observation_batches_survive_restart_and_replay_from_domain_events() {
        let mut store = setup_store();
        let batch = click_batch();
        store
            .append_attribution_observation_batch(&batch, at(4))
            .expect("persist batch");
        let replayed = store
            .replay_attribution_spine(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            )
            .expect("replay");
        assert_eq!(replayed.events.len(), 1);
        assert_eq!(replayed.cursors[0].sequence, 1);
        assert_eq!(replayed.events[0].id, SourceEventId::from_stable("click-1"));
        assert_eq!(
            store
                .attribution_observation_batches(&ProjectId::from("project-1"))
                .expect("batches")
                .len(),
            1
        );

        let order_batch = order_batch(batch.cursor_after.clone());
        let order_sequence = store
            .append_attribution_observation_batch(&order_batch, at(8))
            .expect("persist order");
        assert_eq!(
            store
                .append_attribution_observation_batch(&order_batch, at(9))
                .expect("idempotent batch"),
            order_sequence
        );
        let mut replayed = store
            .replay_attribution_spine(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            )
            .expect("replay order");
        let candidate = replayed.events[1].outcome_candidate().expect("candidate");
        let candidate_sequence = store
            .append_attribution_candidate(
                &ProjectId::from("project-1"),
                &candidate,
                CurrencyCode::parse("USD").expect("USD"),
                at(10),
            )
            .expect("persist candidate");
        assert_eq!(
            store
                .append_attribution_candidate(
                    &ProjectId::from("project-1"),
                    &candidate,
                    CurrencyCode::parse("USD").expect("USD"),
                    at(11),
                )
                .expect("idempotent candidate"),
            candidate_sequence
        );
        let verification = OutcomeVerification {
            method: VerificationMethod::IndependentReadback,
            verifier: "shopify-readback".into(),
            independent: true,
            verified_at: at(12),
            evidence_digest: "a".repeat(64),
        };
        store
            .append_attribution_verification(
                &ProjectId::from("project-1"),
                &candidate.id,
                &verification,
                CurrencyCode::parse("USD").expect("USD"),
                at(13),
            )
            .expect("persist verification");
        replayed = store
            .replay_attribution_spine(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            )
            .expect("replay verified outcome");
        assert_eq!(replayed.candidates.len(), 1);
        assert_eq!(replayed.verified_outcomes.len(), 1);
    }
}

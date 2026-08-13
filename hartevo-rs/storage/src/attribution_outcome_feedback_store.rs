//! Durable adoption feedback for the next attribution evaluation window.
//!
//! Feedback is append-only input: it never rewrites the adopted candidate or
//! its receipt. A feedback event can optionally reference a newly observed
//! candidate from the exact next window, while its consumer-facing signal
//! contains only typed scope and digests.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ATTRIBUTION_ADOPTION_RECEIPT_EVENT_TYPE, ATTRIBUTION_FEEDBACK_EVENT_TYPE,
    AttributionAdoptionConsumer, AttributionAdoptionConsumerRecord,
    AttributionAdoptionConsumerState, AttributionAdoptionError, AttributionAdoptionReceipt,
    AttributionFeedbackError, AttributionFeedbackInput, AttributionFeedbackRecord,
    AttributionFeedbackSignal, AttributionFeedbackSnapshot, AttributionFeedbackWindow,
    AttributionOutcomeCandidate, AttributionReason, CurrencyCode, OutcomeCandidateId, ProjectId,
};

use crate::{DomainEventRecord, ProjectStore, StorageError};

impl ProjectStore {
    /// Appends one feedback input for a receipt and the exact next evaluation
    /// window. The operation is idempotent for the same receipt/window digest.
    pub fn append_attribution_feedback(
        &mut self,
        project_id: &ProjectId,
        receipt_id: &str,
        next_window: AttributionFeedbackWindow,
        reporting_currency: CurrencyCode,
        recorded_at: DateTime<Utc>,
    ) -> Result<AttributionFeedbackSignal, StorageError> {
        let receipt_event = find_receipt_event(self.events_for_project(project_id)?, receipt_id)?;
        let snapshot = self.replay_attribution_adoption(project_id, reporting_currency.clone())?;
        let receipt = snapshot
            .receipts
            .iter()
            .find(|receipt| receipt.receipt_id == receipt_id)
            .ok_or_else(|| StorageError::DomainDecode("feedback receipt is not durable".into()))?;
        let consumer = active_consumer_from_slice(&snapshot.consumers, &receipt.consumer_id)?;
        let input = AttributionFeedbackInput::from_receipt(
            receipt,
            u64::try_from(receipt_event.sequence).map_err(|_| {
                StorageError::DomainDecode("feedback adoption revision overflow".into())
            })?,
            next_window,
        )
        .map_err(feedback_decode)?;

        if let Some(existing) = self.find_feedback_for_window(
            project_id,
            &input.receipt_id,
            input.next_window.revision,
        )? && existing.input != input
        {
            return Err(StorageError::DomainDecode(
                "feedback receipt/window was reused with different content".into(),
            ));
        }
        if let Some(existing) = self.find_feedback_record(project_id, &input.feedback_id)? {
            let candidate = self.feedback_candidate(
                project_id,
                &existing,
                &consumer.consumer,
                reporting_currency.clone(),
                existing_sequence(
                    self.events_for_project(project_id)?,
                    &existing.input.feedback_id,
                )?,
            )?;
            existing
                .input
                .validate_against_receipt(receipt)
                .map_err(feedback_decode)?;
            existing
                .validate(candidate.as_ref())
                .map_err(feedback_decode)?;
            if existing.input != input {
                return Err(StorageError::DomainDecode(
                    "feedback id was reused with different content".into(),
                ));
            }
            return Ok(existing.signal);
        }

        let ledger = self.replay_attribution_adoption_ledger(project_id, reporting_currency)?;
        let candidate = AttributionOutcomeCandidate::from_verified_ledger_in_window(
            &ledger,
            &consumer.consumer,
            input.next_window.attribution_window.clone(),
            input.next_window.model_version.clone(),
            input.next_window.starts_at,
            input.next_window.ends_at,
        )
        .map_err(domain_decode)?;
        if let Some(candidate) = candidate.as_ref() {
            ensure_candidate_is_live(candidate)?;
            self.append_attribution_adoption_candidate(candidate, recorded_at)?;
        }
        let record = AttributionFeedbackRecord::from_input(input, candidate.as_ref())
            .map_err(feedback_decode)?;
        let signal = record.signal.clone();
        self.append_event(
            project_id,
            Some(&record.input.scope.mission_id),
            ATTRIBUTION_FEEDBACK_EVENT_TYPE,
            &serde_json::to_value(&record)?,
            recorded_at,
        )?;
        Ok(signal)
    }

    /// Replays feedback events and checks every receipt, candidate, lifecycle,
    /// scope, and digest binding. A later consumer revoke does not invalidate
    /// an earlier feedback event; it only blocks feedback appended afterwards.
    pub fn replay_attribution_feedback(
        &self,
        project_id: &ProjectId,
        reporting_currency: CurrencyCode,
    ) -> Result<AttributionFeedbackSnapshot, StorageError> {
        let events = self.events_for_project(project_id)?;
        let ledger = self.replay_attribution_adoption_ledger(project_id, reporting_currency)?;
        let mut records = Vec::new();
        let mut feedback_ids = BTreeMap::<String, (String, u64)>::new();
        let mut receipt_windows = BTreeMap::<(String, u64), String>::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == ATTRIBUTION_FEEDBACK_EVENT_TYPE)
        {
            let record: AttributionFeedbackRecord = serde_json::from_value(event.payload.clone())?;
            let receipt_event = find_receipt_event(events.clone(), &record.input.receipt_id)?;
            let receipt: AttributionAdoptionReceipt =
                serde_json::from_value(receipt_event.payload.clone())?;
            if receipt_event.sequence
                != i64::try_from(record.input.adoption_revision).unwrap_or(i64::MAX)
                || event.project_id != *project_id
                || event.mission_id.as_ref() != Some(&record.input.scope.mission_id)
            {
                return Err(StorageError::DomainDecode(
                    "feedback event receipt revision or mission scope mismatch".into(),
                ));
            }
            record
                .input
                .validate_against_receipt(&receipt)
                .map_err(feedback_decode)?;
            let consumers =
                self.replay_attribution_adoption_consumers_through(project_id, event.sequence)?;
            let consumer = active_consumer(&consumers, &receipt.consumer_id)?;
            let candidate = feedback_candidate_from_events(
                &events,
                event.sequence,
                record.new_candidate_id.as_ref(),
                &ledger,
                &consumer.consumer,
            )?;
            if let Some(candidate) = candidate.as_ref() {
                ensure_candidate_is_live(candidate)?;
            }
            record
                .validate(candidate.as_ref())
                .map_err(feedback_decode)?;
            if feedback_ids
                .insert(
                    record.input.feedback_id.clone(),
                    (
                        record.input.receipt_id.clone(),
                        record.input.next_window.revision,
                    ),
                )
                .is_some()
                || receipt_windows
                    .insert(
                        (
                            record.input.receipt_id.clone(),
                            record.input.next_window.revision,
                        ),
                        record.input.feedback_id.clone(),
                    )
                    .is_some()
            {
                return Err(StorageError::DomainDecode(
                    "duplicate feedback event is not replayable".into(),
                ));
            }
            records.push(record);
        }
        AttributionFeedbackSnapshot::new(project_id.clone(), records).map_err(feedback_decode)
    }

    fn find_feedback_record(
        &self,
        project_id: &ProjectId,
        feedback_id: &str,
    ) -> Result<Option<AttributionFeedbackRecord>, StorageError> {
        self.events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_FEEDBACK_EVENT_TYPE)
            .try_fold(None, |found, event| {
                let record: AttributionFeedbackRecord = serde_json::from_value(event.payload)?;
                if record.input.feedback_id != feedback_id {
                    return Ok(found);
                }
                if found.as_ref().is_some_and(|existing| existing != &record) {
                    return Err(StorageError::DomainDecode(
                        "feedback identity differs in immutable history".into(),
                    ));
                }
                Ok(Some(record))
            })
    }

    fn find_feedback_for_window(
        &self,
        project_id: &ProjectId,
        receipt_id: &str,
        window_revision: u64,
    ) -> Result<Option<AttributionFeedbackRecord>, StorageError> {
        self.events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_FEEDBACK_EVENT_TYPE)
            .try_fold(None, |found, event| {
                let record: AttributionFeedbackRecord = serde_json::from_value(event.payload)?;
                if record.input.receipt_id != receipt_id
                    || record.input.next_window.revision != window_revision
                {
                    return Ok(found);
                }
                if found.as_ref().is_some_and(|existing| existing != &record) {
                    return Err(StorageError::DomainDecode(
                        "feedback receipt/window has conflicting immutable history".into(),
                    ));
                }
                Ok(Some(record))
            })
    }

    fn feedback_candidate(
        &self,
        project_id: &ProjectId,
        record: &AttributionFeedbackRecord,
        consumer: &AttributionAdoptionConsumer,
        reporting_currency: CurrencyCode,
        through_sequence: i64,
    ) -> Result<Option<AttributionOutcomeCandidate>, StorageError> {
        let Some(candidate_id) = record.new_candidate_id.as_ref() else {
            return Ok(None);
        };
        let ledger = self.replay_attribution_adoption_ledger(project_id, reporting_currency)?;
        feedback_candidate_from_events(
            &self.events_for_project(project_id)?,
            through_sequence,
            Some(candidate_id),
            &ledger,
            consumer,
        )
    }
}

fn find_receipt_event(
    events: Vec<DomainEventRecord>,
    receipt_id: &str,
) -> Result<DomainEventRecord, StorageError> {
    events
        .into_iter()
        .filter(|event| event.event_type == ATTRIBUTION_ADOPTION_RECEIPT_EVENT_TYPE)
        .find(|event| {
            serde_json::from_value::<AttributionAdoptionReceipt>(event.payload.clone())
                .ok()
                .is_some_and(|receipt| receipt.receipt_id == receipt_id)
        })
        .ok_or_else(|| StorageError::DomainDecode("adoption receipt event is missing".into()))
}

fn active_consumer(
    consumers: &BTreeMap<String, AttributionAdoptionConsumerRecord>,
    consumer_id: &str,
) -> Result<AttributionAdoptionConsumerRecord, StorageError> {
    let record = consumers
        .get(consumer_id)
        .ok_or_else(|| StorageError::DomainDecode("feedback consumer is missing".into()))?;
    if record.state != AttributionAdoptionConsumerState::Active {
        return Err(StorageError::DomainDecode(
            "feedback consumer is revoked or unmounted".into(),
        ));
    }
    Ok(record.clone())
}

fn active_consumer_from_slice(
    consumers: &[AttributionAdoptionConsumerRecord],
    consumer_id: &str,
) -> Result<AttributionAdoptionConsumerRecord, StorageError> {
    let record = consumers
        .iter()
        .find(|record| record.consumer.consumer_id == consumer_id)
        .ok_or_else(|| StorageError::DomainDecode("feedback consumer is missing".into()))?;
    if record.state != AttributionAdoptionConsumerState::Active {
        return Err(StorageError::DomainDecode(
            "feedback consumer is revoked or unmounted".into(),
        ));
    }
    Ok(record.clone())
}

fn existing_sequence(
    events: Vec<DomainEventRecord>,
    feedback_id: &str,
) -> Result<i64, StorageError> {
    events
        .into_iter()
        .filter(|event| event.event_type == ATTRIBUTION_FEEDBACK_EVENT_TYPE)
        .find(|event| {
            serde_json::from_value::<AttributionFeedbackRecord>(event.payload.clone())
                .ok()
                .is_some_and(|record| record.input.feedback_id == feedback_id)
        })
        .map(|event| event.sequence)
        .ok_or_else(|| StorageError::DomainDecode("feedback event is missing".into()))
}

fn feedback_candidate_from_events(
    events: &[DomainEventRecord],
    through_sequence: i64,
    candidate_id: Option<&OutcomeCandidateId>,
    ledger: &hartevo_domain_kernel::AttributionLedger,
    consumer: &hartevo_domain_kernel::AttributionAdoptionConsumer,
) -> Result<Option<AttributionOutcomeCandidate>, StorageError> {
    let Some(candidate_id) = candidate_id else {
        return Ok(None);
    };
    let mut found = None;
    for event in events.iter().filter(|event| {
        event.sequence <= through_sequence
            && event.event_type == hartevo_domain_kernel::ATTRIBUTION_ADOPTION_CANDIDATE_EVENT_TYPE
    }) {
        let candidate: AttributionOutcomeCandidate = serde_json::from_value(event.payload.clone())?;
        if candidate.candidate_id != *candidate_id {
            continue;
        }
        candidate
            .validate_with_ledger(ledger, consumer)
            .map_err(domain_decode)?;
        if found
            .as_ref()
            .is_some_and(|existing| existing != &candidate)
        {
            return Err(StorageError::DomainDecode(
                "feedback candidate identity differs in immutable history".into(),
            ));
        }
        found = Some(candidate);
    }
    found
        .ok_or_else(|| StorageError::DomainDecode("feedback candidate event is missing".into()))
        .map(Some)
}

fn ensure_candidate_is_live(candidate: &AttributionOutcomeCandidate) -> Result<(), StorageError> {
    if matches!(
        candidate.assignment.reason,
        AttributionReason::UnattributedInactiveLineage
    ) {
        return Err(StorageError::DomainDecode(
            "feedback source lineage is revoked or reversed".into(),
        ));
    }
    Ok(())
}

fn feedback_decode(error: AttributionFeedbackError) -> StorageError {
    let message = error.to_string();
    drop(error);
    StorageError::DomainDecode(message)
}

fn domain_decode(error: AttributionAdoptionError) -> StorageError {
    let message = error.to_string();
    drop(error);
    StorageError::DomainDecode(message)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AttributionAdoptionConsumer, AttributionAdoptionScope, AttributionModelVersion,
        AttributionWindow, CorrectionKind, CorrectionLineage, CurrencyCode, Mission,
        MissionContract, MissionId, ObservationOrigin, ObservationProvenance, OutcomeVerification,
        Project, ProviderCursor, ProviderEntityRef, ProviderEventIdentity, SourceEntityKind,
        SourceEvent, SourceEventId, SourceEventKind, SourceEventLinks, SourceObservationBatch,
        StorageMode, TenantId, VerificationMethod,
    };
    use serde_json::json;

    use super::*;
    use crate::PendingEvent;

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 8, 0, 0)
            .single()
            .expect("time")
            + Duration::minutes(minute)
    }

    fn setup_store() -> ProjectStore {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Attribution feedback",
            "",
            "/tmp/hartevo-attribution-feedback",
            StorageMode::LocalExisting,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), at(0))],
            )
            .expect("project event");
        let mission = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-1"),
            ProjectId::from("project-1"),
            "Attributed outcome",
            MissionContract::bootstrap("Evaluate provider outcomes", [], at(0)),
            at(0),
        )
        .expect("mission");
        store.save_mission(&mission).expect("mission");
        store
    }

    fn consumer(store: &ProjectStore) -> AttributionAdoptionConsumer {
        let mission = store
            .load_mission(&ProjectId::from("project-1"), &MissionId::from("mission-1"))
            .expect("mission");
        AttributionAdoptionConsumer::new(
            "market.outcome.consumer",
            "market.outcome.plugin",
            1,
            "f".repeat(64),
            AttributionAdoptionScope::from_mission(&mission).expect("scope"),
            1,
        )
        .expect("consumer")
    }

    fn source_event(provider: &str, id: &str, minute: i64) -> SourceEvent {
        let identity = ProviderEventIdentity::new(provider, "acct-1", id).expect("identity");
        let account =
            ProviderEntityRef::new(SourceEntityKind::Account, provider, "acct-1", "acct-1")
                .expect("account");
        let mut links = SourceEventLinks::new(account).expect("links");
        links.order = Some(
            ProviderEntityRef::new(SourceEntityKind::Order, provider, "acct-1", id).expect("order"),
        );
        SourceEvent {
            id: SourceEventId::from_stable(id),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: Some(MissionId::from("mission-1")),
            identity,
            kind: SourceEventKind::Order,
            links,
            provider_occurred_at: at(minute),
            observed_at: at(minute + 1),
            ingested_at: at(minute + 2),
            amount: Some(hartevo_domain_kernel::Money::new(
                10_000,
                CurrencyCode::parse("USD").expect("USD"),
            )),
            fx_quote: None,
            provenance: ObservationProvenance::new(
                ObservationOrigin::FirstParty,
                "a".repeat(64),
                at(minute + 1),
            )
            .expect("provenance"),
            lineage: CorrectionLineage::original(SourceEventId::from_stable(id)),
            payload_digest: "b".repeat(64),
        }
    }

    fn batch(
        event: SourceEvent,
        sequence: u64,
        cursor_before: Option<ProviderCursor>,
    ) -> SourceObservationBatch {
        let cursor_after = ProviderCursor {
            provider: event.identity.provider.clone(),
            account_id: event.identity.account_id.clone(),
            sequence,
            token: format!("cursor-{sequence}"),
            observed_through: event.observed_at,
            ingested_at: event.ingested_at,
            batch_digest: format!("{sequence:0<64}"),
        };
        SourceObservationBatch {
            tenant_id: event.tenant_id.clone(),
            project_id: event.project_id.clone(),
            mission_id: event.mission_id.clone(),
            provider: event.identity.provider.clone(),
            account_id: event.identity.account_id.clone(),
            cursor_before,
            cursor_after,
            events: vec![event],
        }
    }

    fn seed_verified(
        store: &mut ProjectStore,
        event: SourceEvent,
        sequence: u64,
        cursor_before: Option<ProviderCursor>,
    ) -> ProviderCursor {
        let source_candidate = event.outcome_candidate().expect("candidate");
        let batch = batch(event, sequence, cursor_before);
        let cursor = batch.cursor_after.clone();
        let verified_at = batch.events[0].observed_at + Duration::minutes(1);
        store
            .append_attribution_observation_batch(&batch, at(sequence.cast_signed() + 3))
            .expect("observation");
        store
            .append_attribution_candidate(
                &ProjectId::from("project-1"),
                &source_candidate,
                CurrencyCode::parse("USD").expect("USD"),
                at(sequence.cast_signed() + 4),
            )
            .expect("candidate");
        store
            .append_attribution_verification(
                &ProjectId::from("project-1"),
                &source_candidate.id,
                &OutcomeVerification {
                    method: VerificationMethod::SignedWebhook,
                    verifier: "meta-webhook".into(),
                    independent: true,
                    verified_at,
                    evidence_digest: format!("{sequence:0<64}"),
                },
                CurrencyCode::parse("USD").expect("USD"),
                verified_at + Duration::minutes(1),
            )
            .expect("verification");
        cursor
    }

    fn first_receipt(
        store: &mut ProjectStore,
        consumer: &AttributionAdoptionConsumer,
    ) -> ProviderCursor {
        store
            .mount_attribution_adoption_consumer(consumer, at(1))
            .expect("mount");
        let cursor = seed_verified(store, source_event("meta", "order-1", 10), 1, None);
        let first = store
            .derive_attribution_outcome_candidate(
                &ProjectId::from("project-1"),
                &consumer.consumer_id,
                CurrencyCode::parse("USD").expect("USD"),
                AttributionWindow {
                    version: 1,
                    click_lookback_seconds: 86_400,
                    view_lookback_seconds: 86_400,
                    effective_at: at(0),
                },
                AttributionModelVersion::new("last-touch.v1").expect("model"),
            )
            .expect("derive")
            .expect("first candidate");
        store
            .append_attribution_adoption_receipt(
                &first,
                hartevo_domain_kernel::AttributionAdoptionDecision::Adopt,
                hartevo_domain_kernel::ActorId::from("human-1"),
                "decision-1",
                at(20),
            )
            .expect("receipt");
        cursor
    }

    fn next_window() -> AttributionFeedbackWindow {
        AttributionFeedbackWindow::new(
            2,
            at(20),
            at(40),
            AttributionWindow {
                version: 2,
                click_lookback_seconds: 86_400,
                view_lookback_seconds: 86_400,
                effective_at: at(20),
            },
            AttributionModelVersion::new("last-touch.v2").expect("model"),
        )
        .expect("window")
    }

    #[test]
    fn feedback_replays_late_candidate_and_keeps_signal_content_free() {
        let mut store = setup_store();
        let adoption_consumer = consumer(&store);
        let first_cursor = first_receipt(&mut store, &adoption_consumer);
        seed_verified(
            &mut store,
            source_event("meta", "order-2", 30),
            2,
            Some(first_cursor),
        );
        let signal = store
            .append_attribution_feedback(
                &ProjectId::from("project-1"),
                &store
                    .replay_attribution_adoption(
                        &ProjectId::from("project-1"),
                        CurrencyCode::parse("USD").expect("USD"),
                    )
                    .expect("adoption")
                    .receipts[0]
                    .receipt_id,
                next_window(),
                CurrencyCode::parse("USD").expect("USD"),
                at(41),
            )
            .expect("feedback");
        assert_eq!(
            signal.signal_kind,
            hartevo_domain_kernel::AttributionFeedbackSignalKind::NewCandidateAvailable
        );
        let signal_json = serde_json::to_string(&signal).expect("signal json");
        assert!(!signal_json.contains("acct-1"));
        assert!(!signal_json.contains("order-2"));
        assert_eq!(
            store
                .replay_attribution_feedback(
                    &ProjectId::from("project-1"),
                    CurrencyCode::parse("USD").expect("USD"),
                )
                .expect("feedback replay")
                .records
                .len(),
            1
        );
        assert_eq!(
            store
                .replay_attribution_adoption(
                    &ProjectId::from("project-1"),
                    CurrencyCode::parse("USD").expect("USD"),
                )
                .expect("adoption replay")
                .receipts
                .len(),
            1
        );
    }

    #[test]
    fn feedback_without_new_candidate_is_idempotent_and_revoke_fails_closed() {
        let mut store = setup_store();
        let adoption_consumer = consumer(&store);
        first_receipt(&mut store, &adoption_consumer);
        let receipt_id = store
            .replay_attribution_adoption(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            )
            .expect("adoption")
            .receipts[0]
            .receipt_id
            .clone();
        let first = store
            .append_attribution_feedback(
                &ProjectId::from("project-1"),
                &receipt_id,
                next_window(),
                CurrencyCode::parse("USD").expect("USD"),
                at(21),
            )
            .expect("feedback");
        assert_eq!(
            first.signal_kind,
            hartevo_domain_kernel::AttributionFeedbackSignalKind::NoNewCandidate
        );
        let second = store
            .append_attribution_feedback(
                &ProjectId::from("project-1"),
                &receipt_id,
                next_window(),
                CurrencyCode::parse("USD").expect("USD"),
                at(22),
            )
            .expect("idempotent feedback");
        assert_eq!(first, second);
        store
            .revoke_attribution_adoption_consumer(
                &ProjectId::from("project-1"),
                &adoption_consumer.consumer_id,
                "c".repeat(64),
                at(23),
            )
            .expect("revoke");
        assert!(
            store
                .append_attribution_feedback(
                    &ProjectId::from("project-1"),
                    &receipt_id,
                    AttributionFeedbackWindow::new(
                        3,
                        at(24),
                        at(50),
                        AttributionWindow {
                            version: 3,
                            click_lookback_seconds: 86_400,
                            view_lookback_seconds: 86_400,
                            effective_at: at(24),
                        },
                        AttributionModelVersion::new("last-touch.v3").expect("model"),
                    )
                    .expect("window"),
                    CurrencyCode::parse("USD").expect("USD"),
                    at(25),
                )
                .is_err()
        );
    }

    #[test]
    fn feedback_replay_rejects_tampered_record_and_revoked_source_has_no_candidate() {
        let mut store = setup_store();
        let adoption_consumer = consumer(&store);
        let first_cursor = first_receipt(&mut store, &adoption_consumer);
        let mut correction = source_event("meta", "order-correction", 30);
        correction.identity.external_event_id = "order-1".into();
        correction.lineage = CorrectionLineage {
            kind: CorrectionKind::Correction,
            root_event_id: SourceEventId::from_stable("order-1"),
            supersedes: Some(SourceEventId::from_stable("order-1")),
            reason: Some("provider correction".into()),
        };
        let correction_batch = batch(correction, 2, Some(first_cursor));
        store
            .append_attribution_observation_batch(&correction_batch, at(32))
            .expect("correction");
        let receipt_id = store
            .replay_attribution_adoption(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            )
            .expect("adoption")
            .receipts[0]
            .receipt_id
            .clone();
        let signal = store
            .append_attribution_feedback(
                &ProjectId::from("project-1"),
                &receipt_id,
                next_window(),
                CurrencyCode::parse("USD").expect("USD"),
                at(33),
            )
            .expect("feedback after correction");
        assert_eq!(
            signal.signal_kind,
            hartevo_domain_kernel::AttributionFeedbackSignalKind::NoNewCandidate
        );

        let event = store
            .events_for_project(&ProjectId::from("project-1"))
            .expect("events")
            .into_iter()
            .find(|event| event.event_type == ATTRIBUTION_FEEDBACK_EVENT_TYPE)
            .expect("feedback event");
        let mut tampered: AttributionFeedbackRecord =
            serde_json::from_value(event.payload).expect("record");
        tampered.signal.signal_digest = "d".repeat(64);
        store
            .append_event(
                &ProjectId::from("project-1"),
                Some(&MissionId::from("mission-1")),
                ATTRIBUTION_FEEDBACK_EVENT_TYPE,
                &serde_json::to_value(tampered).expect("tampered payload"),
                at(34),
            )
            .expect("tampered event");
        assert!(matches!(
            store.replay_attribution_feedback(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            ),
            Err(StorageError::DomainDecode(_))
        ));
    }
}

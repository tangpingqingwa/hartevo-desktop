//! Durable attribution evidence delivery receipts.
//!
//! A receipt is appended only after the exact query response, consumer
//! lifecycle, current ledger/cursor fence, and any adoption feedback have
//! been revalidated. The event payload is content-free and replayable.

use hartevo_domain_kernel::{
    ATTRIBUTION_EVIDENCE_DELIVERY_RECEIPT_EVENT_TYPE,
    ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE, AttributionEvidenceAdoptionFeedback,
    AttributionEvidenceDeliveryDisposition, AttributionEvidenceDeliveryReceipt,
    AttributionEvidenceDeliveryService, AttributionEvidenceDeliverySnapshot,
    AttributionEvidenceQueryId, AttributionEvidenceQueryRecord, AttributionEvidenceQueryResponse,
    CurrencyCode, ProjectId,
};
use sha2::{Digest, Sha256};

use crate::attribution_evidence_query_store::active_consumer;
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    /// Appends a model-visible delivery receipt only after rechecking the
    /// response against the current ledger and provider cursor. Exact replay
    /// of an existing delivery id is idempotent; altered identity is rejected.
    pub fn append_attribution_evidence_delivery_receipt(
        &mut self,
        receipt: &AttributionEvidenceDeliveryReceipt,
        reporting_currency: CurrencyCode,
    ) -> Result<AttributionEvidenceDeliveryReceipt, StorageError> {
        receipt.validate().map_err(delivery_decode)?;
        let existing =
            self.replay_attribution_evidence_delivery_receipts(&receipt.scope.project_id)?;
        if let Some(previous) = existing
            .records
            .iter()
            .find(|record| record.delivery_id == receipt.delivery_id)
        {
            if previous == receipt {
                return Ok(previous.clone());
            }
            return Err(StorageError::DomainDecode(
                "evidence delivery id conflicts with immutable history".into(),
            ));
        }
        if existing.records.iter().any(|record| {
            record.model_invocation.invocation_id == receipt.model_invocation.invocation_id
        }) {
            return Err(StorageError::DomainDecode(
                "model invocation already has an immutable evidence delivery".into(),
            ));
        }
        let mission = self.load_mission(&receipt.scope.project_id, &receipt.scope.mission_id)?;
        receipt
            .scope
            .validate_against_mission(&mission)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let query = query_record(self, &receipt.scope.project_id, &receipt.query_id)?;
        let consumers =
            self.replay_attribution_evidence_query_consumers(&receipt.scope.project_id)?;
        let consumer = active_consumer(&consumers, &receipt.consumer_id)?;
        receipt
            .validate_against(&consumer.consumer, &query.request, &query.response)
            .map_err(delivery_decode)?;
        if receipt.disposition != AttributionEvidenceDeliveryDisposition::Superseded {
            ensure_current_response(
                self,
                &receipt.scope.project_id,
                &query.response,
                reporting_currency.clone(),
            )?;
        }
        let feedback = feedback_for_receipt(
            self,
            &receipt.scope.project_id,
            receipt,
            &query.response,
            i64::MAX,
        )?;
        if matches!(
            receipt.disposition,
            AttributionEvidenceDeliveryDisposition::Adopted
                | AttributionEvidenceDeliveryDisposition::Rejected
        ) {
            feedback.ok_or_else(|| {
                StorageError::DomainDecode(
                    "adopted or rejected delivery is missing durable feedback".into(),
                )
            })?;
        }
        ensure_superseder(
            self,
            &receipt.scope.project_id,
            receipt,
            &query.response,
            None,
        )?;
        if receipt.disposition == AttributionEvidenceDeliveryDisposition::Superseded {
            let successor_id = receipt.superseded_by_query_id.as_ref().ok_or_else(|| {
                StorageError::DomainDecode(
                    "superseded delivery is missing its successor query".into(),
                )
            })?;
            let successor = query_record(self, &receipt.scope.project_id, successor_id)?;
            ensure_current_response(
                self,
                &receipt.scope.project_id,
                &successor.response,
                reporting_currency,
            )?;
        }
        self.append_event(
            &receipt.scope.project_id,
            Some(&receipt.scope.mission_id),
            ATTRIBUTION_EVIDENCE_DELIVERY_RECEIPT_EVENT_TYPE,
            &serde_json::to_value(receipt)?,
            receipt.delivered_at,
        )?;
        Ok(receipt.clone())
    }

    /// Replays content-free delivery receipts and rechecks every immutable
    /// binding, including feedback and superseding response lineage.
    pub fn replay_attribution_evidence_delivery_receipts(
        &self,
        project_id: &ProjectId,
    ) -> Result<AttributionEvidenceDeliverySnapshot, StorageError> {
        let query_snapshot = self.replay_attribution_evidence_queries(project_id)?;
        let events = self.events_for_project(project_id)?;
        let mut records = Vec::new();
        let mut delivery_ids = std::collections::BTreeSet::new();
        let mut invocation_ids = std::collections::BTreeSet::new();
        for event in &events {
            if event.event_type != ATTRIBUTION_EVIDENCE_DELIVERY_RECEIPT_EVENT_TYPE {
                continue;
            }
            let receipt: AttributionEvidenceDeliveryReceipt =
                serde_json::from_value(event.payload.clone())?;
            receipt.validate().map_err(delivery_decode)?;
            if event.mission_id.as_ref() != Some(&receipt.scope.mission_id)
                || event.recorded_at != receipt.delivered_at
                || !delivery_ids.insert(receipt.delivery_id.clone())
                || !invocation_ids.insert(receipt.model_invocation.invocation_id.clone())
            {
                return Err(StorageError::DomainDecode(
                    "evidence delivery event scope, timestamp, or identity is invalid".into(),
                ));
            }
            let query = query_snapshot
                .records
                .iter()
                .find(|record| record.request.query_id == receipt.query_id)
                .ok_or_else(|| {
                    StorageError::DomainDecode(
                        "evidence delivery references a missing query response".into(),
                    )
                })?;
            let consumers = self
                .replay_attribution_evidence_query_consumers_through(project_id, event.sequence)?;
            let consumer = active_consumer(&consumers, &receipt.consumer_id)?;
            receipt
                .validate_against(&consumer.consumer, &query.request, &query.response)
                .map_err(delivery_decode)?;
            feedback_for_receipt(self, project_id, &receipt, &query.response, event.sequence)?;
            ensure_superseder(
                self,
                project_id,
                &receipt,
                &query.response,
                Some(event.sequence),
            )?;
            records.push(receipt);
        }
        AttributionEvidenceDeliverySnapshot::new(project_id.clone(), records)
            .map_err(delivery_decode)
    }
}

impl AttributionEvidenceDeliveryService for ProjectStore {
    type Error = StorageError;

    fn append_attribution_evidence_delivery_receipt(
        &mut self,
        receipt: &AttributionEvidenceDeliveryReceipt,
        reporting_currency: CurrencyCode,
    ) -> Result<AttributionEvidenceDeliveryReceipt, Self::Error> {
        ProjectStore::append_attribution_evidence_delivery_receipt(
            self,
            receipt,
            reporting_currency,
        )
    }

    fn replay_attribution_evidence_delivery_receipts(
        &self,
        project_id: &ProjectId,
    ) -> Result<AttributionEvidenceDeliverySnapshot, Self::Error> {
        ProjectStore::replay_attribution_evidence_delivery_receipts(self, project_id)
    }
}

fn query_record(
    store: &ProjectStore,
    project_id: &ProjectId,
    query_id: &AttributionEvidenceQueryId,
) -> Result<AttributionEvidenceQueryRecord, StorageError> {
    store
        .replay_attribution_evidence_queries(project_id)?
        .records
        .into_iter()
        .find(|record| record.request.query_id == *query_id)
        .ok_or_else(|| {
            StorageError::DomainDecode("evidence delivery query response is missing".into())
        })
}

fn ensure_current_response(
    store: &ProjectStore,
    project_id: &ProjectId,
    response: &AttributionEvidenceQueryResponse,
    reporting_currency: CurrencyCode,
) -> Result<(), StorageError> {
    let ledger = store.replay_attribution_spine(project_id, reporting_currency)?;
    let ledger_digest = AttributionEvidenceQueryResponse::ledger_digest(&ledger)
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
    if response.ledger_revision != ledger.revision || response.ledger_digest != ledger_digest {
        return Err(StorageError::DomainDecode(
            "evidence delivery response is stale against the current ledger".into(),
        ));
    }
    let cursor = ledger.cursors.iter().find(|cursor| {
        cursor.provider == response.provider.provider
            && cursor.account_id == response.provider.account_id
    });
    match cursor {
        Some(cursor)
            if response.provider_revision == cursor.sequence
                && response.provider_digest == cursor.batch_digest =>
        {
            Ok(())
        }
        None if response.provider_revision == 0
            && response.provider_digest == digest_text("attribution-evidence-query:no-cursor") =>
        {
            Ok(())
        }
        _ => Err(StorageError::DomainDecode(
            "evidence delivery response is stale against the provider cursor".into(),
        )),
    }
}

fn feedback_for_receipt(
    store: &ProjectStore,
    project_id: &ProjectId,
    receipt: &AttributionEvidenceDeliveryReceipt,
    response: &AttributionEvidenceQueryResponse,
    before_sequence: i64,
) -> Result<Option<AttributionEvidenceAdoptionFeedback>, StorageError> {
    let Some(feedback_digest) = receipt.feedback_digest.as_deref() else {
        return Ok(None);
    };
    let mut found = None;
    for event in store
        .events_for_project(project_id)?
        .into_iter()
        .filter(|event| {
            event.sequence < before_sequence
                && event.event_type == ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE
        })
    {
        let feedback: AttributionEvidenceAdoptionFeedback = serde_json::from_value(event.payload)?;
        if feedback.feedback_digest != feedback_digest {
            continue;
        }
        if event.mission_id.as_ref() != Some(&receipt.scope.mission_id)
            || feedback.consumer_id != receipt.consumer_id
            || feedback.scope != receipt.scope
            || feedback.provider != receipt.provider
            || feedback.window.window_digest != receipt.window_digest
        {
            return Err(StorageError::DomainDecode(
                "evidence delivery feedback crosses an immutable scope fence".into(),
            ));
        }
        feedback
            .validate_against_response(response)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        receipt
            .feedback_decision(&feedback)
            .map_err(delivery_decode)?;
        let consumers = store
            .replay_attribution_evidence_query_consumers_through(project_id, event.sequence)?;
        let consumer = active_consumer(&consumers, &feedback.consumer_id)?;
        if consumer.consumer.scope != feedback.scope {
            return Err(StorageError::DomainDecode(
                "evidence delivery feedback consumer is outside its scope".into(),
            ));
        }
        if found.replace(feedback).is_some() {
            return Err(StorageError::DomainDecode(
                "evidence delivery feedback digest is duplicated".into(),
            ));
        }
    }
    found
        .ok_or_else(|| {
            StorageError::DomainDecode("evidence delivery feedback digest is not durable".into())
        })
        .map(Some)
}

fn ensure_superseder(
    store: &ProjectStore,
    project_id: &ProjectId,
    receipt: &AttributionEvidenceDeliveryReceipt,
    response: &AttributionEvidenceQueryResponse,
    before_sequence: Option<i64>,
) -> Result<(), StorageError> {
    let Some(successor_id) = receipt.superseded_by_query_id.as_ref() else {
        return Ok(());
    };
    let successor = query_record(store, project_id, successor_id)?;
    if let Some(sequence) = before_sequence {
        let successor_sequence = store
            .events_for_project(project_id)?
            .into_iter()
            .find(|event| {
                event.event_type
                    == hartevo_domain_kernel::ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE
                    && event
                        .payload
                        .get("request")
                        .and_then(|value| value.get("queryId"))
                        .and_then(serde_json::Value::as_str)
                        == Some(successor_id.as_str())
            })
            .map(|event| event.sequence)
            .ok_or_else(|| {
                StorageError::DomainDecode("evidence delivery successor event is missing".into())
            })?;
        if successor_sequence >= sequence {
            return Err(StorageError::DomainDecode(
                "evidence delivery successor was not durable before the receipt".into(),
            ));
        }
    }
    if successor.request.consumer_id != receipt.consumer_id
        || successor.request.scope != receipt.scope
        || successor.request.provider != receipt.provider
        || successor.request.window != response.window
        || successor.response.response_digest
            != receipt
                .superseded_by_response_digest
                .as_deref()
                .unwrap_or_default()
        || successor.response.ledger_revision <= receipt.response_revision
    {
        return Err(StorageError::DomainDecode(
            "evidence delivery successor is not an exact newer response".into(),
        ));
    }
    Ok(())
}

fn digest_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn delivery_decode(error: hartevo_domain_kernel::AttributionEvidenceDeliveryError) -> StorageError {
    let message = error.to_string();
    drop(error);
    StorageError::DomainDecode(message)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use hartevo_domain_kernel::{
        AttributionEvidenceAdoptionDecision, AttributionEvidenceAdoptionFeedback,
        AttributionEvidenceDeliveryDisposition, AttributionEvidenceDeliveryReceipt,
        AttributionEvidenceModelInvocation, AttributionEvidenceQueryConsumer,
        AttributionEvidenceQueryProvider, AttributionEvidenceQueryRequest,
        AttributionEvidenceQueryResponse, AttributionEvidenceQueryScope,
        AttributionEvidenceQueryWindow, AttributionLedger, CorrectionLineage, CurrencyCode,
        Mission, MissionContract, MissionId, Money, ObservationOrigin, ObservationProvenance,
        Project, ProjectId, ProviderCursor, ProviderEntityRef, ProviderEventIdentity,
        SourceEntityKind, SourceEvent, SourceEventId, SourceEventKind, SourceEventLinks,
        SourceObservationBatch, StorageMode, TenantId,
    };
    use serde_json::json;

    use super::*;
    use crate::PendingEvent;

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .expect("valid test time")
            + Duration::minutes(minute)
    }

    struct Fixture {
        store: ProjectStore,
        project: Project,
        mission: Mission,
        consumer: AttributionEvidenceQueryConsumer,
        provider: AttributionEvidenceQueryProvider,
        currency: CurrencyCode,
    }

    fn fixture() -> Fixture {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-delivery"),
            ProjectId::from("project-delivery"),
            "Attribution delivery",
            "",
            "/tmp/hartevo-attribution-delivery",
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
            project.tenant_id.clone(),
            MissionId::from_stable("mission-delivery"),
            project.id.clone(),
            "Delivery mission",
            MissionContract::bootstrap(
                "Deliver attribution evidence",
                ["research.read".into()],
                at(0),
            ),
            at(0),
        )
        .expect("mission");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new("mission.compiled", json!({}), at(0))],
            )
            .expect("mission event");
        let scope = AttributionEvidenceQueryScope::from_mission(&mission).expect("scope");
        let consumer = AttributionEvidenceQueryConsumer::new(
            "consumer-delivery",
            "planning-model",
            1,
            "d".repeat(64),
            scope,
            1,
        )
        .expect("consumer");
        store
            .mount_attribution_evidence_query_consumer(&consumer, at(0))
            .expect("mount");
        Fixture {
            store,
            project,
            mission,
            consumer,
            provider: AttributionEvidenceQueryProvider::new("meta", "acct-1"),
            currency: CurrencyCode::parse("USD").expect("currency"),
        }
    }

    fn source_event(
        mission: &Mission,
        id: &str,
        kind: SourceEventKind,
        minute: i64,
    ) -> SourceEvent {
        let provider = "meta";
        let account_id = "acct-1";
        let identity = ProviderEventIdentity::new(provider, account_id, id).expect("identity");
        let account =
            ProviderEntityRef::new(SourceEntityKind::Account, provider, account_id, account_id)
                .expect("account");
        let mut links = SourceEventLinks::new(account).expect("links");
        let entity_kind = match kind {
            SourceEventKind::Click => SourceEntityKind::Click,
            SourceEventKind::Order => SourceEntityKind::Order,
            _ => panic!("test helper only supports click and order"),
        };
        let entity = ProviderEntityRef::new(entity_kind, provider, account_id, id).expect("entity");
        match kind {
            SourceEventKind::Click => links.click = Some(entity),
            SourceEventKind::Order => links.order = Some(entity),
            _ => unreachable!(),
        }
        let observed_at = at(minute);
        let mut provenance =
            ObservationProvenance::new(ObservationOrigin::FirstParty, "a".repeat(64), observed_at)
                .expect("provenance");
        provenance.fresh_until = Some(at(120));
        SourceEvent {
            id: SourceEventId::from_stable(id),
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: Some(mission.id.clone()),
            identity,
            kind,
            links,
            provider_occurred_at: at(minute - 1),
            observed_at,
            ingested_at: at(minute + 1),
            amount: (kind == SourceEventKind::Order)
                .then(|| Money::new(1_000, CurrencyCode::parse("USD").expect("currency"))),
            fx_quote: None,
            provenance,
            lineage: CorrectionLineage::original(SourceEventId::from_stable(id)),
            payload_digest: "b".repeat(64),
        }
    }

    fn batch(
        mission: &Mission,
        events: Vec<SourceEvent>,
        cursor_before: Option<ProviderCursor>,
        sequence: u64,
        token: &str,
    ) -> SourceObservationBatch {
        let sequence_minute = i64::try_from(sequence).expect("test sequence fits i64");
        SourceObservationBatch {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: Some(mission.id.clone()),
            provider: "meta".into(),
            account_id: "acct-1".into(),
            cursor_before,
            cursor_after: ProviderCursor {
                provider: "meta".into(),
                account_id: "acct-1".into(),
                sequence,
                token: token.into(),
                observed_through: at(sequence_minute + 4),
                ingested_at: at(sequence_minute + 5),
                batch_digest: format!("{sequence:064x}"),
            },
            events,
        }
    }

    fn request(
        fixture: &Fixture,
        ledger: &AttributionLedger,
        evaluated_minute: i64,
    ) -> AttributionEvidenceQueryRequest {
        let window =
            AttributionEvidenceQueryWindow::new(1, at(-1), at(30), 3_600, 3_600).expect("window");
        AttributionEvidenceQueryRequest::new(
            fixture.consumer.consumer_id.clone(),
            fixture.consumer.scope.clone(),
            fixture.provider.clone(),
            window,
            at(evaluated_minute),
            ledger.cursors.first().cloned(),
            ledger.revision,
            AttributionEvidenceQueryResponse::ledger_digest(ledger).expect("ledger digest"),
        )
        .expect("request")
    }

    fn first_query(
        fixture: &mut Fixture,
    ) -> (
        AttributionLedger,
        AttributionEvidenceQueryRequest,
        AttributionEvidenceQueryResponse,
    ) {
        let first = batch(
            &fixture.mission,
            vec![
                source_event(&fixture.mission, "click-1", SourceEventKind::Click, 2),
                source_event(&fixture.mission, "order-1", SourceEventKind::Order, 4),
            ],
            None,
            1,
            "cursor-1",
        );
        fixture
            .store
            .append_attribution_observation_batch(&first, at(6))
            .expect("first observation");
        let ledger = fixture
            .store
            .replay_attribution_spine(&fixture.project.id, fixture.currency.clone())
            .expect("first ledger");
        let request = request(fixture, &ledger, 10);
        let response = fixture
            .store
            .append_attribution_evidence_query(&request, fixture.currency.clone())
            .expect("query");
        (ledger, request, response)
    }

    fn invocation(id: &str) -> AttributionEvidenceModelInvocation {
        AttributionEvidenceModelInvocation::new(
            id,
            "planner-model",
            7,
            "e".repeat(64),
            "f".repeat(64),
        )
        .expect("invocation")
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one durable receipt regression covers adoption, rejection, idempotency, and redaction"
    )]
    fn delivery_receipts_are_durable_content_free_and_idempotent() {
        let mut fixture = fixture();
        let (_ledger, request, response) = first_query(&mut fixture);
        let adopted_feedback = AttributionEvidenceAdoptionFeedback::new(
            fixture.consumer.consumer_id.clone(),
            &response,
            AttributionEvidenceAdoptionDecision::Adopt,
        )
        .expect("adopt feedback");
        fixture
            .store
            .append_attribution_evidence_adoption_feedback(&adopted_feedback, at(11))
            .expect("adopt feedback event");
        let adopted = AttributionEvidenceDeliveryReceipt::new(
            "delivery-adopted",
            &fixture.consumer,
            invocation("invocation-adopted"),
            &request,
            &response,
            AttributionEvidenceDeliveryDisposition::Adopted,
            Some(adopted_feedback.feedback_digest.clone()),
            None,
            at(12),
        )
        .expect("adopted receipt");
        assert_eq!(
            fixture
                .store
                .append_attribution_evidence_delivery_receipt(&adopted, fixture.currency.clone())
                .expect("adopted delivery"),
            adopted
        );
        assert_eq!(
            fixture
                .store
                .append_attribution_evidence_delivery_receipt(&adopted, fixture.currency.clone())
                .expect("idempotent delivery"),
            adopted
        );
        let encoded = serde_json::to_string(&adopted).expect("receipt json");
        assert!(!encoded.contains("click-1"));
        assert!(!encoded.contains("order-1"));

        let rejected_feedback = AttributionEvidenceAdoptionFeedback::new(
            fixture.consumer.consumer_id.clone(),
            &response,
            AttributionEvidenceAdoptionDecision::Reject,
        )
        .expect("reject feedback");
        fixture
            .store
            .append_attribution_evidence_adoption_feedback(&rejected_feedback, at(13))
            .expect("reject feedback event");
        let rejected = AttributionEvidenceDeliveryReceipt::new(
            "delivery-rejected",
            &fixture.consumer,
            invocation("invocation-rejected"),
            &request,
            &response,
            AttributionEvidenceDeliveryDisposition::Rejected,
            Some(rejected_feedback.feedback_digest.clone()),
            None,
            at(14),
        )
        .expect("rejected receipt");
        fixture
            .store
            .append_attribution_evidence_delivery_receipt(&rejected, fixture.currency.clone())
            .expect("rejected delivery");
        let snapshot = fixture
            .store
            .replay_attribution_evidence_delivery_receipts(&fixture.project.id)
            .expect("delivery replay");
        assert_eq!(snapshot.records.len(), 2);
        assert!(
            snapshot
                .records
                .iter()
                .all(|record| record.scope == fixture.consumer.scope)
        );
    }

    #[test]
    fn superseded_receipt_binds_a_newer_query_and_stale_active_delivery_fails() {
        let mut fixture = fixture();
        let (old_ledger, old_request, old_response) = first_query(&mut fixture);
        let second = batch(
            &fixture.mission,
            vec![source_event(
                &fixture.mission,
                "click-2",
                SourceEventKind::Click,
                7,
            )],
            old_ledger.cursors.first().cloned(),
            2,
            "cursor-2",
        );
        fixture
            .store
            .append_attribution_observation_batch(&second, at(9))
            .expect("second observation");
        let current = fixture
            .store
            .replay_attribution_spine(&fixture.project.id, fixture.currency.clone())
            .expect("current ledger");
        let new_request = request(&fixture, &current, 12);
        let new_response = fixture
            .store
            .append_attribution_evidence_query(&new_request, fixture.currency.clone())
            .expect("new query");
        let superseded = AttributionEvidenceDeliveryReceipt::new(
            "delivery-superseded",
            &fixture.consumer,
            invocation("invocation-superseded"),
            &old_request,
            &old_response,
            AttributionEvidenceDeliveryDisposition::Superseded,
            None,
            Some((
                new_response.query_id.clone(),
                new_response.response_digest.clone(),
            )),
            at(14),
        )
        .expect("superseded receipt");
        fixture
            .store
            .append_attribution_evidence_delivery_receipt(&superseded, fixture.currency.clone())
            .expect("superseded delivery");
        assert_eq!(
            fixture
                .store
                .replay_attribution_evidence_delivery_receipts(&fixture.project.id)
                .expect("replay")
                .records
                .len(),
            1
        );

        let stale = AttributionEvidenceDeliveryReceipt::new(
            "delivery-stale",
            &fixture.consumer,
            invocation("invocation-stale"),
            &old_request,
            &old_response,
            AttributionEvidenceDeliveryDisposition::Adopted,
            Some("f".repeat(64)),
            None,
            at(15),
        )
        .expect("stale receipt shape");
        assert!(
            fixture
                .store
                .append_attribution_evidence_delivery_receipt(&stale, fixture.currency)
                .is_err()
        );
    }

    #[test]
    fn revoked_consumer_and_altered_feedback_digest_fail_closed() {
        let mut fixture = fixture();
        let (_ledger, request, response) = first_query(&mut fixture);
        let feedback = AttributionEvidenceAdoptionFeedback::new(
            fixture.consumer.consumer_id.clone(),
            &response,
            AttributionEvidenceAdoptionDecision::Adopt,
        )
        .expect("feedback");
        fixture
            .store
            .append_attribution_evidence_adoption_feedback(&feedback, at(11))
            .expect("feedback event");
        let altered = AttributionEvidenceDeliveryReceipt::new(
            "delivery-altered-feedback",
            &fixture.consumer,
            invocation("invocation-altered-feedback"),
            &request,
            &response,
            AttributionEvidenceDeliveryDisposition::Adopted,
            Some("0".repeat(64)),
            None,
            at(12),
        )
        .expect("altered receipt shape");
        assert!(
            fixture
                .store
                .append_attribution_evidence_delivery_receipt(&altered, fixture.currency.clone())
                .is_err()
        );

        fixture
            .store
            .revoke_attribution_evidence_query_consumer(
                &fixture.project.id,
                &fixture.consumer.consumer_id,
                "a".repeat(64),
                at(13),
            )
            .expect("revoke consumer");
        let valid = AttributionEvidenceDeliveryReceipt::new(
            "delivery-revoked",
            &fixture.consumer,
            invocation("invocation-revoked"),
            &request,
            &response,
            AttributionEvidenceDeliveryDisposition::Adopted,
            Some(feedback.feedback_digest),
            None,
            at(14),
        )
        .expect("valid receipt shape");
        assert!(
            fixture
                .store
                .append_attribution_evidence_delivery_receipt(&valid, fixture.currency)
                .is_err()
        );
    }

    #[test]
    fn tampered_receipt_event_and_cross_scope_mutation_fail_replay() {
        let mut fixture = fixture();
        let (_ledger, request, response) = first_query(&mut fixture);
        let feedback = AttributionEvidenceAdoptionFeedback::new(
            fixture.consumer.consumer_id.clone(),
            &response,
            AttributionEvidenceAdoptionDecision::Adopt,
        )
        .expect("feedback");
        fixture
            .store
            .append_attribution_evidence_adoption_feedback(&feedback, at(11))
            .expect("feedback event");
        let receipt = AttributionEvidenceDeliveryReceipt::new(
            "delivery-tamper",
            &fixture.consumer,
            invocation("invocation-tamper"),
            &request,
            &response,
            AttributionEvidenceDeliveryDisposition::Adopted,
            Some(feedback.feedback_digest),
            None,
            at(12),
        )
        .expect("receipt");
        fixture
            .store
            .append_attribution_evidence_delivery_receipt(&receipt, fixture.currency.clone())
            .expect("delivery");
        let event = fixture
            .store
            .events_for_project(&fixture.project.id)
            .expect("events")
            .into_iter()
            .find(|event| event.event_type == ATTRIBUTION_EVIDENCE_DELIVERY_RECEIPT_EVENT_TYPE)
            .expect("receipt event");
        let mut tampered = event.payload;
        tampered["receiptDigest"] = json!("0".repeat(64));
        fixture
            .store
            .append_event(
                &fixture.project.id,
                Some(&fixture.mission.id),
                ATTRIBUTION_EVIDENCE_DELIVERY_RECEIPT_EVENT_TYPE,
                &tampered,
                at(13),
            )
            .expect("tampered event append");
        assert!(
            fixture
                .store
                .replay_attribution_evidence_delivery_receipts(&fixture.project.id)
                .is_err()
        );

        let mut cross_scope = receipt;
        cross_scope.scope.mission_id = MissionId::from_stable("mission-other");
        assert!(cross_scope.validate().is_err());
    }
}

//! Durable attribution outcome adoption and verification boundary.
//!
//! The store uses the existing append-only `domain_events` table. No SQL
//! migration is needed: source observations, candidate/verification records,
//! consumer lifecycle, candidate snapshots, and user decision receipts are
//! all replayed in sequence and rejected on scope or digest drift.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ATTRIBUTION_ADOPTION_CANDIDATE_EVENT_TYPE, ATTRIBUTION_ADOPTION_CONSUMER_MOUNT_EVENT_TYPE,
    ATTRIBUTION_ADOPTION_CONSUMER_REVOKE_EVENT_TYPE,
    ATTRIBUTION_ADOPTION_CONSUMER_UNMOUNT_EVENT_TYPE, ATTRIBUTION_ADOPTION_RECEIPT_EVENT_TYPE,
    ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE, ATTRIBUTION_SPINE_EVENT_TYPE,
    ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE, AttributionAdoptionConsumer,
    AttributionAdoptionConsumerRecord, AttributionAdoptionConsumerState,
    AttributionAdoptionDecision, AttributionAdoptionError, AttributionAdoptionReceipt,
    AttributionAdoptionSnapshot, AttributionLedger, AttributionModelVersion,
    AttributionOutcomeCandidate, AttributionVerificationRecord, AttributionWindow, CurrencyCode,
    OutcomeCandidate, OutcomeCandidateId, OutcomeVerification, ProjectId, SourceObservationBatch,
};

use crate::{DomainEventRecord, ProjectStore, StorageError};

impl ProjectStore {
    /// Persists one exact source candidate. This is the minimal durable bridge
    /// for providers that already emitted a source observation batch; it does
    /// not promote the candidate to a verified outcome.
    pub fn append_attribution_candidate(
        &mut self,
        project_id: &ProjectId,
        candidate: &OutcomeCandidate,
        reporting_currency: CurrencyCode,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let ledger = self.replay_attribution_adoption_ledger(project_id, reporting_currency)?;
        let event = ledger
            .events
            .iter()
            .find(|event| event.id == candidate.source_event_id)
            .ok_or_else(|| {
                StorageError::DomainDecode("candidate source event is missing".into())
            })?;
        let expected = event
            .outcome_candidate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if expected != *candidate {
            return Err(StorageError::DomainDecode(
                "candidate is not bound to the exact source event".into(),
            ));
        }
        if let Some(existing) = self
            .events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE)
            .find_map(|event| {
                serde_json::from_value::<OutcomeCandidate>(event.payload)
                    .ok()
                    .filter(|existing| existing.id == candidate.id)
                    .map(|existing| (event.sequence, existing))
            })
        {
            if existing.1 == *candidate {
                return Ok(existing.0);
            }
            return Err(StorageError::DomainDecode(
                "duplicate candidate identity differs from immutable history".into(),
            ));
        }
        self.append_event(
            project_id,
            event.mission_id.as_ref(),
            ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE,
            &serde_json::to_value(candidate)?,
            recorded_at,
        )
    }

    /// Persists one exact verification record after rechecking the candidate
    /// against the durable source ledger. The verifier is never inferred from
    /// the adoption consumer.
    pub fn append_attribution_verification(
        &mut self,
        project_id: &ProjectId,
        candidate_id: &OutcomeCandidateId,
        verification: &OutcomeVerification,
        reporting_currency: CurrencyCode,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let ledger = self.replay_attribution_adoption_ledger(project_id, reporting_currency)?;
        let mut checked = ledger.clone();
        let expected = checked
            .verify_candidate(candidate_id, verification.clone())
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let record = AttributionVerificationRecord {
            candidate_id: candidate_id.clone(),
            verification: verification.clone(),
        };
        record
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if let Some(existing) = self
            .events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE)
            .find_map(|event| {
                serde_json::from_value::<AttributionVerificationRecord>(event.payload)
                    .ok()
                    .filter(|existing| existing.candidate_id == *candidate_id)
                    .map(|existing| (event.sequence, existing))
            })
        {
            if existing.1 == record {
                return Ok(existing.0);
            }
            return Err(StorageError::DomainDecode(
                "duplicate verification identity differs from immutable history".into(),
            ));
        }
        let source = ledger
            .events
            .iter()
            .find(|event| event.id == expected.source_event_id)
            .ok_or_else(|| {
                StorageError::DomainDecode("verification source event is missing".into())
            })?;
        self.append_event(
            project_id,
            source.mission_id.as_ref(),
            ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE,
            &serde_json::to_value(record)?,
            recorded_at,
        )
    }

    /// Mounts an adoption consumer against the current exact Mission goal
    /// revision. A repeated identical mount is idempotent; a stale or swapped
    /// identity fails closed.
    pub fn mount_attribution_adoption_consumer(
        &mut self,
        consumer: &AttributionAdoptionConsumer,
        mounted_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        consumer.validate().map_err(adoption_decode)?;
        let mission = self.load_mission(&consumer.scope.project_id, &consumer.scope.mission_id)?;
        consumer
            .scope
            .validate_against_mission(&mission)
            .map_err(adoption_decode)?;
        let records = self.replay_attribution_adoption_consumers(&consumer.scope.project_id)?;
        if let Some(existing) = records.get(&consumer.consumer_id) {
            if existing.state == AttributionAdoptionConsumerState::Active
                && existing.consumer == *consumer
            {
                return self.find_adoption_lifecycle_sequence(
                    &consumer.scope.project_id,
                    ATTRIBUTION_ADOPTION_CONSUMER_MOUNT_EVENT_TYPE,
                    &consumer.consumer_id,
                );
            }
            return Err(StorageError::DomainDecode(
                "adoption consumer identity conflicts with immutable history".into(),
            ));
        }
        let record = AttributionAdoptionConsumerRecord::active(consumer.clone(), mounted_at)
            .map_err(adoption_decode)?;
        self.append_event(
            &consumer.scope.project_id,
            Some(&consumer.scope.mission_id),
            ATTRIBUTION_ADOPTION_CONSUMER_MOUNT_EVENT_TYPE,
            &serde_json::to_value(record)?,
            mounted_at,
        )
    }

    /// Normal unmount is terminal for new work but preserves old adoption
    /// receipts for audit replay.
    pub fn unmount_attribution_adoption_consumer(
        &mut self,
        project_id: &ProjectId,
        consumer_id: &str,
        reason_digest: String,
        changed_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        self.transition_attribution_adoption_consumer(
            project_id,
            consumer_id,
            AttributionAdoptionConsumerState::Unmounted,
            reason_digest,
            changed_at,
        )
    }

    /// Revocation is terminal and fail-closed. Existing receipts remain
    /// immutable evidence, while all new candidate/decision writes fail.
    pub fn revoke_attribution_adoption_consumer(
        &mut self,
        project_id: &ProjectId,
        consumer_id: &str,
        reason_digest: String,
        changed_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        self.transition_attribution_adoption_consumer(
            project_id,
            consumer_id,
            AttributionAdoptionConsumerState::Revoked,
            reason_digest,
            changed_at,
        )
    }

    /// Derives a candidate from exact verified provider evidence. There is no
    /// fallback fixture or estimate path: no real verified event returns None.
    pub fn derive_attribution_outcome_candidate(
        &self,
        project_id: &ProjectId,
        consumer_id: &str,
        reporting_currency: CurrencyCode,
        window: AttributionWindow,
        model_version: AttributionModelVersion,
    ) -> Result<Option<AttributionOutcomeCandidate>, StorageError> {
        let snapshot = self.replay_attribution_adoption(project_id, reporting_currency.clone())?;
        let record = snapshot
            .consumers
            .iter()
            .find(|record| record.consumer.consumer_id == consumer_id)
            .ok_or_else(|| StorageError::DomainDecode("adoption consumer is not mounted".into()))?;
        if record.state != AttributionAdoptionConsumerState::Active {
            return Err(StorageError::DomainDecode(
                "adoption consumer is not active".into(),
            ));
        }
        let mission = self.load_mission(project_id, &record.consumer.scope.mission_id)?;
        record
            .consumer
            .scope
            .validate_against_mission(&mission)
            .map_err(adoption_decode)?;
        let ledger = self.replay_attribution_adoption_ledger(project_id, reporting_currency)?;
        AttributionOutcomeCandidate::from_verified_ledger(
            &ledger,
            &record.consumer,
            window,
            model_version,
        )
        .map_err(adoption_decode)
    }

    /// Persists a deterministic candidate snapshot. Exact duplicate replay is
    /// idempotent; a candidate with the same identity but different evidence
    /// is rejected.
    pub fn append_attribution_adoption_candidate(
        &mut self,
        candidate: &AttributionOutcomeCandidate,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let ledger = self.replay_attribution_adoption_ledger(
            &candidate.scope.project_id,
            candidate.reporting_currency.clone(),
        )?;
        let existing_event = self
            .events_for_project(&candidate.scope.project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_ADOPTION_CANDIDATE_EVENT_TYPE)
            .find_map(|event| {
                serde_json::from_value::<AttributionOutcomeCandidate>(event.payload)
                    .ok()
                    .filter(|existing| existing.candidate_id == candidate.candidate_id)
                    .map(|existing| (event.sequence, existing))
            });
        if let Some((sequence, existing)) = existing_event {
            if existing == *candidate {
                return Ok(sequence);
            }
            return Err(StorageError::DomainDecode(
                "adoption candidate identity differs from immutable history".into(),
            ));
        }
        let records = self.replay_attribution_adoption_consumers(&candidate.scope.project_id)?;
        let consumer = records
            .get(&candidate.consumer_id)
            .ok_or_else(|| StorageError::DomainDecode("adoption consumer is not mounted".into()))?;
        if consumer.state != AttributionAdoptionConsumerState::Active {
            return Err(StorageError::DomainDecode(
                "adoption consumer is not active".into(),
            ));
        }
        candidate
            .validate_with_ledger(&ledger, &consumer.consumer)
            .map_err(adoption_decode)?;
        let mission =
            self.load_mission(&candidate.scope.project_id, &candidate.scope.mission_id)?;
        candidate
            .scope
            .validate_against_mission(&mission)
            .map_err(adoption_decode)?;
        self.append_event(
            &candidate.scope.project_id,
            Some(&candidate.scope.mission_id),
            ATTRIBUTION_ADOPTION_CANDIDATE_EVENT_TYPE,
            &serde_json::to_value(candidate)?,
            recorded_at,
        )
    }

    /// Records a user Adopt or Reject decision as an immutable typed receipt.
    /// Candidate and consumer scope are checked again immediately before the
    /// append, so stale, swapped, replayed, or revoked decisions fail closed.
    pub fn append_attribution_adoption_receipt(
        &mut self,
        candidate: &AttributionOutcomeCandidate,
        decision: AttributionAdoptionDecision,
        actor_id: hartevo_domain_kernel::ActorId,
        idempotency_key: impl Into<String>,
        decided_at: DateTime<Utc>,
    ) -> Result<AttributionAdoptionReceipt, StorageError> {
        self.append_attribution_adoption_candidate(candidate, decided_at)?;
        let receipt = AttributionAdoptionReceipt::from_candidate(
            candidate,
            decision,
            actor_id,
            idempotency_key,
            decided_at,
        )
        .map_err(adoption_decode)?;
        let snapshot = self.replay_attribution_adoption(
            &candidate.scope.project_id,
            candidate.reporting_currency.clone(),
        )?;
        if let Some(existing) = snapshot
            .receipts
            .iter()
            .find(|existing| existing.receipt_id == receipt.receipt_id)
        {
            return Ok(existing.clone());
        }
        if snapshot.receipts.iter().any(|existing| {
            existing.consumer_id == receipt.consumer_id
                && existing.idempotency_key == receipt.idempotency_key
                && existing != &receipt
        }) {
            return Err(StorageError::DomainDecode(
                "adoption idempotency key was reused with different content".into(),
            ));
        }
        let consumer = snapshot
            .consumers
            .iter()
            .find(|record| record.consumer.consumer_id == receipt.consumer_id)
            .ok_or_else(|| StorageError::DomainDecode("adoption consumer is not mounted".into()))?;
        if consumer.state != AttributionAdoptionConsumerState::Active {
            return Err(StorageError::DomainDecode(
                "adoption consumer is revoked or unmounted".into(),
            ));
        }
        self.append_event(
            &candidate.scope.project_id,
            Some(&candidate.scope.mission_id),
            ATTRIBUTION_ADOPTION_RECEIPT_EVENT_TYPE,
            &serde_json::to_value(&receipt)?,
            decided_at,
        )?;
        Ok(receipt)
    }

    /// Replays consumer lifecycle, candidate snapshots, and receipts against
    /// the exact source ledger. Old adopted results remain valid when later
    /// source events arrive; a later source event simply derives another
    /// candidate identity.
    pub fn replay_attribution_adoption(
        &self,
        project_id: &ProjectId,
        reporting_currency: CurrencyCode,
    ) -> Result<AttributionAdoptionSnapshot, StorageError> {
        let project = self.load_project(project_id)?;
        let ledger = self.replay_attribution_adoption_ledger(project_id, reporting_currency)?;
        let mut consumers = BTreeMap::<String, AttributionAdoptionConsumerRecord>::new();
        let mut candidates = BTreeMap::<String, AttributionOutcomeCandidate>::new();
        let mut receipts = BTreeMap::<String, AttributionAdoptionReceipt>::new();
        let mut idempotency = BTreeMap::<(String, String), String>::new();
        for event in self.events_for_project(project_id)? {
            match event.event_type.as_str() {
                ATTRIBUTION_ADOPTION_CONSUMER_MOUNT_EVENT_TYPE
                | ATTRIBUTION_ADOPTION_CONSUMER_UNMOUNT_EVENT_TYPE
                | ATTRIBUTION_ADOPTION_CONSUMER_REVOKE_EVENT_TYPE => {
                    apply_consumer_lifecycle_event(&mut consumers, &event)?;
                }
                ATTRIBUTION_ADOPTION_CANDIDATE_EVENT_TYPE => {
                    apply_adoption_candidate_event(&event, &ledger, &consumers, &mut candidates)?;
                }
                ATTRIBUTION_ADOPTION_RECEIPT_EVENT_TYPE => {
                    apply_adoption_receipt_event(
                        &event,
                        &consumers,
                        &candidates,
                        &mut receipts,
                        &mut idempotency,
                    )?;
                }
                _ => {}
            }
        }
        let snapshot = AttributionAdoptionSnapshot::new(
            project.tenant_id,
            project_id.clone(),
            consumers.into_values().collect(),
            candidates.into_values().collect(),
            receipts.into_values().collect(),
        )
        .map_err(adoption_decode)?;
        snapshot
            .validate_with_ledger(&ledger)
            .map_err(adoption_decode)?;
        Ok(snapshot)
    }

    pub(crate) fn replay_attribution_adoption_ledger(
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
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        for event in self.events_for_project(project_id)? {
            match event.event_type.as_str() {
                ATTRIBUTION_SPINE_EVENT_TYPE => {
                    let batch: SourceObservationBatch = serde_json::from_value(event.payload)?;
                    if event.mission_id != batch.mission_id
                        || batch.tenant_id != project.tenant_id
                        || batch.project_id != *project_id
                    {
                        return Err(StorageError::DomainDecode(
                            "attribution observation event scope mismatch".into(),
                        ));
                    }
                    batch
                        .validate()
                        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
                    ledger
                        .ingest_batch(batch)
                        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
                }
                ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE => {
                    let candidate: OutcomeCandidate = serde_json::from_value(event.payload)?;
                    let source = ledger
                        .events
                        .iter()
                        .find(|source| source.id == candidate.source_event_id)
                        .ok_or_else(|| {
                            StorageError::DomainDecode(
                                "candidate event precedes its source observation".into(),
                            )
                        })?;
                    if event.mission_id != source.mission_id {
                        return Err(StorageError::DomainDecode(
                            "candidate event mission scope mismatch".into(),
                        ));
                    }
                    ledger
                        .register_candidate(candidate)
                        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
                }
                ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE => {
                    let record: AttributionVerificationRecord =
                        serde_json::from_value(event.payload)?;
                    record.validate().map_err(adoption_decode)?;
                    let candidate = ledger
                        .candidates
                        .iter()
                        .find(|candidate| candidate.id == record.candidate_id)
                        .ok_or_else(|| {
                            StorageError::DomainDecode(
                                "verification event precedes its candidate".into(),
                            )
                        })?;
                    let source = ledger
                        .events
                        .iter()
                        .find(|source| source.id == candidate.source_event_id)
                        .ok_or_else(|| {
                            StorageError::DomainDecode("verification source is missing".into())
                        })?;
                    if event.mission_id != source.mission_id {
                        return Err(StorageError::DomainDecode(
                            "verification event mission scope mismatch".into(),
                        ));
                    }
                    ledger
                        .verify_candidate(&record.candidate_id, record.verification)
                        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
                }
                _ => {}
            }
        }
        ledger
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        Ok(ledger)
    }

    pub(crate) fn replay_attribution_adoption_consumers(
        &self,
        project_id: &ProjectId,
    ) -> Result<BTreeMap<String, AttributionAdoptionConsumerRecord>, StorageError> {
        self.replay_attribution_adoption_consumers_through(project_id, i64::MAX)
    }

    pub(crate) fn replay_attribution_adoption_consumers_through(
        &self,
        project_id: &ProjectId,
        through_sequence: i64,
    ) -> Result<BTreeMap<String, AttributionAdoptionConsumerRecord>, StorageError> {
        let mut consumers = BTreeMap::new();
        for event in self
            .events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.sequence <= through_sequence)
        {
            if matches!(
                event.event_type.as_str(),
                ATTRIBUTION_ADOPTION_CONSUMER_MOUNT_EVENT_TYPE
                    | ATTRIBUTION_ADOPTION_CONSUMER_UNMOUNT_EVENT_TYPE
                    | ATTRIBUTION_ADOPTION_CONSUMER_REVOKE_EVENT_TYPE
            ) {
                apply_consumer_lifecycle_event(&mut consumers, &event)?;
            }
        }
        Ok(consumers)
    }

    fn transition_attribution_adoption_consumer(
        &mut self,
        project_id: &ProjectId,
        consumer_id: &str,
        state: AttributionAdoptionConsumerState,
        reason_digest: String,
        changed_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        if consumer_id.trim().is_empty() {
            return Err(StorageError::DomainDecode(
                "adoption consumer id is empty".into(),
            ));
        }
        let records = self.replay_attribution_adoption_consumers(project_id)?;
        let existing = records
            .get(consumer_id)
            .ok_or_else(|| StorageError::DomainDecode("adoption consumer is not mounted".into()))?;
        if existing.state != AttributionAdoptionConsumerState::Active {
            return Err(StorageError::DomainDecode(
                "adoption consumer is already terminal".into(),
            ));
        }
        let next = existing
            .transition(state, changed_at, reason_digest)
            .map_err(adoption_decode)?;
        let event_type = match state {
            AttributionAdoptionConsumerState::Unmounted => {
                ATTRIBUTION_ADOPTION_CONSUMER_UNMOUNT_EVENT_TYPE
            }
            AttributionAdoptionConsumerState::Revoked => {
                ATTRIBUTION_ADOPTION_CONSUMER_REVOKE_EVENT_TYPE
            }
            AttributionAdoptionConsumerState::Active => {
                return Err(StorageError::DomainDecode(
                    "active is not a lifecycle transition".into(),
                ));
            }
        };
        let mission_id = next.consumer.scope.mission_id.clone();
        let payload = serde_json::to_value(next)?;
        self.append_event(
            project_id,
            Some(&mission_id),
            event_type,
            &payload,
            changed_at,
        )
    }

    fn find_adoption_lifecycle_sequence(
        &self,
        project_id: &ProjectId,
        event_type: &str,
        consumer_id: &str,
    ) -> Result<i64, StorageError> {
        self.events_for_project(project_id)?
            .into_iter()
            .find(|event| {
                event.event_type == event_type
                    && serde_json::from_value::<AttributionAdoptionConsumerRecord>(
                        event.payload.clone(),
                    )
                    .ok()
                    .is_some_and(|record| record.consumer.consumer_id == consumer_id)
            })
            .map(|event| event.sequence)
            .ok_or_else(|| StorageError::DomainDecode("adoption lifecycle event is missing".into()))
    }
}

fn apply_consumer_lifecycle_event(
    consumers: &mut BTreeMap<String, AttributionAdoptionConsumerRecord>,
    event: &DomainEventRecord,
) -> Result<(), StorageError> {
    let expected_state = match event.event_type.as_str() {
        ATTRIBUTION_ADOPTION_CONSUMER_MOUNT_EVENT_TYPE => AttributionAdoptionConsumerState::Active,
        ATTRIBUTION_ADOPTION_CONSUMER_UNMOUNT_EVENT_TYPE => {
            AttributionAdoptionConsumerState::Unmounted
        }
        ATTRIBUTION_ADOPTION_CONSUMER_REVOKE_EVENT_TYPE => {
            AttributionAdoptionConsumerState::Revoked
        }
        _ => return Ok(()),
    };
    let record: AttributionAdoptionConsumerRecord = serde_json::from_value(event.payload.clone())?;
    record.validate().map_err(adoption_decode)?;
    if record.state != expected_state
        || event.mission_id.as_ref() != Some(&record.consumer.scope.mission_id)
        || event.recorded_at != record.changed_at
    {
        return Err(StorageError::DomainDecode(
            "adoption consumer lifecycle scope, state, or timestamp mismatch".into(),
        ));
    }
    let consumer_id = record.consumer.consumer_id.clone();
    if let Some(existing) = consumers.get_mut(&consumer_id) {
        if existing.consumer != record.consumer {
            return Err(StorageError::DomainDecode(
                "adoption consumer identity changed in immutable history".into(),
            ));
        }
        if existing.state == record.state && *existing == record {
            return Ok(());
        }
        let next = existing
            .transition(
                record.state,
                record.changed_at,
                record.reason_digest.clone().unwrap_or_default(),
            )
            .map_err(adoption_decode)?;
        if next != record {
            return Err(StorageError::DomainDecode(
                "adoption consumer transition differs from immutable history".into(),
            ));
        }
        *existing = record;
    } else {
        if record.state != AttributionAdoptionConsumerState::Active {
            return Err(StorageError::DomainDecode(
                "adoption consumer lifecycle begins outside a mount".into(),
            ));
        }
        consumers.insert(consumer_id, record);
    }
    Ok(())
}

fn apply_adoption_candidate_event(
    event: &DomainEventRecord,
    ledger: &AttributionLedger,
    consumers: &BTreeMap<String, AttributionAdoptionConsumerRecord>,
    candidates: &mut BTreeMap<String, AttributionOutcomeCandidate>,
) -> Result<(), StorageError> {
    let candidate: AttributionOutcomeCandidate = serde_json::from_value(event.payload.clone())?;
    let record = consumers.get(&candidate.consumer_id).ok_or_else(|| {
        StorageError::DomainDecode("adoption candidate precedes consumer mount".into())
    })?;
    if record.state != AttributionAdoptionConsumerState::Active
        || event.mission_id.as_ref() != Some(&candidate.scope.mission_id)
    {
        return Err(StorageError::DomainDecode(
            "adoption candidate is cross-scope or follows lifecycle terminal".into(),
        ));
    }
    candidate
        .validate_with_ledger(ledger, &record.consumer)
        .map_err(adoption_decode)?;
    if let Some(existing) = candidates.get(candidate.candidate_id.as_str()) {
        if existing != &candidate {
            return Err(StorageError::DomainDecode(
                "duplicate adoption candidate differs from history".into(),
            ));
        }
    } else {
        candidates.insert(candidate.candidate_id.to_string(), candidate);
    }
    Ok(())
}

fn apply_adoption_receipt_event(
    event: &DomainEventRecord,
    consumers: &BTreeMap<String, AttributionAdoptionConsumerRecord>,
    candidates: &BTreeMap<String, AttributionOutcomeCandidate>,
    receipts: &mut BTreeMap<String, AttributionAdoptionReceipt>,
    idempotency: &mut BTreeMap<(String, String), String>,
) -> Result<(), StorageError> {
    let receipt: AttributionAdoptionReceipt = serde_json::from_value(event.payload.clone())?;
    let record = consumers.get(&receipt.consumer_id).ok_or_else(|| {
        StorageError::DomainDecode("adoption receipt precedes consumer mount".into())
    })?;
    if record.state != AttributionAdoptionConsumerState::Active
        || event.mission_id.as_ref() != Some(&receipt.scope.mission_id)
    {
        return Err(StorageError::DomainDecode(
            "adoption receipt is cross-scope or follows lifecycle terminal".into(),
        ));
    }
    let candidate = candidates
        .get(receipt.candidate_id.as_str())
        .ok_or_else(|| {
            StorageError::DomainDecode("adoption receipt candidate is missing".into())
        })?;
    receipt
        .validate_for_candidate(candidate)
        .map_err(adoption_decode)?;
    if let Some(existing) = receipts.get(&receipt.receipt_id) {
        if existing != &receipt {
            return Err(StorageError::DomainDecode(
                "duplicate adoption receipt differs from history".into(),
            ));
        }
        return Ok(());
    }
    if let Some(existing_id) = idempotency.insert(
        (receipt.consumer_id.clone(), receipt.idempotency_key.clone()),
        receipt.receipt_id.clone(),
    ) && existing_id != receipt.receipt_id
    {
        return Err(StorageError::DomainDecode(
            "adoption idempotency key has conflicting receipts".into(),
        ));
    }
    receipts.insert(receipt.receipt_id.clone(), receipt);
    Ok(())
}

fn adoption_decode(error: AttributionAdoptionError) -> StorageError {
    let message = error.to_string();
    drop(error);
    StorageError::DomainDecode(message)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        CorrectionLineage, CurrencyCode, Mission, MissionContract, MissionId, ObservationOrigin,
        ObservationProvenance, Project, ProviderCursor, ProviderEntityRef, ProviderEventIdentity,
        SourceEntityKind, SourceEvent, SourceEventId, SourceEventKind, SourceEventLinks,
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
            "Attribution adoption",
            "",
            "/tmp/hartevo-attribution-adoption",
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

    fn source_event(
        provider: &str,
        id: &str,
        minute: i64,
        origin: ObservationOrigin,
    ) -> SourceEvent {
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
            provenance: ObservationProvenance::new(origin, "a".repeat(64), at(minute + 1))
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

    fn consumer(store: &ProjectStore) -> AttributionAdoptionConsumer {
        let mission = store
            .load_mission(&ProjectId::from("project-1"), &MissionId::from("mission-1"))
            .expect("mission");
        AttributionAdoptionConsumer::new(
            "market.outcome.consumer",
            "market.outcome.plugin",
            1,
            "f".repeat(64),
            hartevo_domain_kernel::AttributionAdoptionScope::from_mission(&mission).expect("scope"),
            1,
        )
        .expect("consumer")
    }

    fn window() -> AttributionWindow {
        AttributionWindow {
            version: 1,
            click_lookback_seconds: 86_400,
            view_lookback_seconds: 86_400,
            effective_at: at(0),
        }
    }

    fn seed_verified(
        store: &mut ProjectStore,
        event: SourceEvent,
        sequence: u64,
    ) -> (OutcomeCandidateId, ProviderCursor) {
        let source_candidate = event.outcome_candidate().expect("candidate");
        let batch = batch(event, sequence, None);
        let cursor = batch.cursor_after.clone();
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
                    verified_at: at(sequence.cast_signed() + 15),
                    evidence_digest: format!("{:0<64}", sequence + 20),
                },
                CurrencyCode::parse("USD").expect("USD"),
                at(sequence.cast_signed() + 16),
            )
            .expect("verification");
        (source_candidate.id, cursor)
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one replay test keeps adopt, late-event, reject, and revoke invariants together"
    )]
    fn adoption_candidate_receipt_replay_late_event_and_revoke_are_durable() {
        let mut store = setup_store();
        let adoption_consumer = consumer(&store);
        store
            .mount_attribution_adoption_consumer(&adoption_consumer, at(1))
            .expect("mount");
        assert!(
            store
                .derive_attribution_outcome_candidate(
                    &ProjectId::from("project-1"),
                    &adoption_consumer.consumer_id,
                    CurrencyCode::parse("USD").expect("USD"),
                    window(),
                    AttributionModelVersion::new("last-touch.v1").expect("model"),
                )
                .expect("empty")
                .is_none()
        );

        let (_source_id, first_cursor) = seed_verified(
            &mut store,
            source_event("meta", "order-1", 10, ObservationOrigin::FirstParty),
            1,
        );
        let first = store
            .derive_attribution_outcome_candidate(
                &ProjectId::from("project-1"),
                &adoption_consumer.consumer_id,
                CurrencyCode::parse("USD").expect("USD"),
                window(),
                AttributionModelVersion::new("last-touch.v1").expect("model"),
            )
            .expect("derive")
            .expect("first candidate");
        let receipt = store
            .append_attribution_adoption_receipt(
                &first,
                AttributionAdoptionDecision::Adopt,
                hartevo_domain_kernel::ActorId::from("human-1"),
                "decision-1",
                at(20),
            )
            .expect("adopt");
        assert_eq!(receipt.candidate_digest, first.candidate_digest);
        assert_eq!(
            store
                .append_attribution_adoption_receipt(
                    &first,
                    AttributionAdoptionDecision::Adopt,
                    hartevo_domain_kernel::ActorId::from("human-1"),
                    "decision-1",
                    at(20),
                )
                .expect("idempotent receipt"),
            receipt
        );

        let second_event = source_event("meta", "order-2", 30, ObservationOrigin::FirstParty);
        let second_candidate = second_event.outcome_candidate().expect("second candidate");
        let second_batch = batch(second_event, 2, Some(first_cursor));
        store
            .append_attribution_observation_batch(&second_batch, at(31))
            .expect("late observation");
        store
            .append_attribution_candidate(
                &ProjectId::from("project-1"),
                &second_candidate,
                CurrencyCode::parse("USD").expect("USD"),
                at(32),
            )
            .expect("late candidate");
        store
            .append_attribution_verification(
                &ProjectId::from("project-1"),
                &second_candidate.id,
                &OutcomeVerification {
                    method: VerificationMethod::IndependentReadback,
                    verifier: "meta-readback".into(),
                    independent: true,
                    verified_at: at(33),
                    evidence_digest: "e".repeat(64),
                },
                CurrencyCode::parse("USD").expect("USD"),
                at(34),
            )
            .expect("late verification");
        let second = store
            .derive_attribution_outcome_candidate(
                &ProjectId::from("project-1"),
                &adoption_consumer.consumer_id,
                CurrencyCode::parse("USD").expect("USD"),
                window(),
                AttributionModelVersion::new("last-touch.v1").expect("model"),
            )
            .expect("derive late")
            .expect("late candidate");
        assert_ne!(first.candidate_id, second.candidate_id);
        let second_receipt = store
            .append_attribution_adoption_receipt(
                &second,
                AttributionAdoptionDecision::Reject,
                hartevo_domain_kernel::ActorId::from("human-1"),
                "decision-2",
                at(35),
            )
            .expect("reject");
        let replay = store
            .replay_attribution_adoption(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            )
            .expect("replay");
        assert_eq!(replay.candidates.len(), 2);
        assert_eq!(replay.receipts.len(), 2);
        assert!(replay.receipts.iter().any(|item| item == &receipt));
        assert!(replay.receipts.iter().any(|item| item == &second_receipt));

        store
            .revoke_attribution_adoption_consumer(
                &ProjectId::from("project-1"),
                &adoption_consumer.consumer_id,
                "a".repeat(64),
                at(40),
            )
            .expect("revoke");
        assert!(
            store
                .derive_attribution_outcome_candidate(
                    &ProjectId::from("project-1"),
                    &adoption_consumer.consumer_id,
                    CurrencyCode::parse("USD").expect("USD"),
                    window(),
                    AttributionModelVersion::new("last-touch.v1").expect("model"),
                )
                .is_err()
        );
        let after_revoke = store
            .replay_attribution_adoption(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            )
            .expect("replay after revoke");
        assert_eq!(
            after_revoke.consumers[0].state,
            AttributionAdoptionConsumerState::Revoked
        );
        assert_eq!(after_revoke.receipts.len(), 2);
    }

    #[test]
    fn tampered_or_cross_provider_candidate_fails_closed_on_replay() {
        let mut store = setup_store();
        let adoption_consumer = consumer(&store);
        store
            .mount_attribution_adoption_consumer(&adoption_consumer, at(1))
            .expect("mount");
        let (_source_id, _cursor) = seed_verified(
            &mut store,
            source_event("meta", "order-1", 10, ObservationOrigin::FirstParty),
            1,
        );
        let candidate = store
            .derive_attribution_outcome_candidate(
                &ProjectId::from("project-1"),
                &adoption_consumer.consumer_id,
                CurrencyCode::parse("USD").expect("USD"),
                window(),
                AttributionModelVersion::new("last-touch.v1").expect("model"),
            )
            .expect("derive")
            .expect("candidate");
        let mut tampered = candidate.clone();
        tampered.provider_event_identity.provider = "shopify".into();
        store
            .append_event(
                &ProjectId::from("project-1"),
                Some(&MissionId::from("mission-1")),
                ATTRIBUTION_ADOPTION_CANDIDATE_EVENT_TYPE,
                &serde_json::to_value(tampered).expect("payload"),
                at(50),
            )
            .expect("tampered event");
        assert!(matches!(
            store.replay_attribution_adoption(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            ),
            Err(StorageError::DomainDecode(_))
        ));
    }
}

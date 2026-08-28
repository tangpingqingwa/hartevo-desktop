//! Durable Mission-scoped attribution evidence query provider.
//!
//! The provider reads only the append-only attribution spine and emits a
//! content-free response record. Query consumer lifecycle, response replay,
//! and adoption feedback digests all use the existing domain event ledger;
//! SQLCipher schema v47 remains unchanged.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_MOUNT_EVENT_TYPE,
    ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_REVOKE_EVENT_TYPE,
    ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE, ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE,
    AttributionEvidenceAdoptionFeedback, AttributionEvidenceConfidence,
    AttributionEvidenceCounterevidence, AttributionEvidenceFreshness,
    AttributionEvidenceFreshnessState, AttributionEvidenceQueryConsumer,
    AttributionEvidenceQueryConsumerRecord, AttributionEvidenceQueryConsumerState,
    AttributionEvidenceQueryError, AttributionEvidenceQueryId, AttributionEvidenceQueryProvider,
    AttributionEvidenceQueryRecord, AttributionEvidenceQueryRequest,
    AttributionEvidenceQueryResponse, AttributionEvidenceQueryService,
    AttributionEvidenceQuerySnapshot, AttributionEvidenceSourceCoverage, AttributionReason,
    CorrectionKind, ObservationOrigin, ProjectId, ProviderCursor, SourceEvent, SourceEventKind,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{DomainEventRecord, ProjectStore, StorageError};

impl ProjectStore {
    /// Mounts a typed planning/model consumer against the current Mission
    /// revision. A consumer never grants execution authority.
    pub fn mount_attribution_evidence_query_consumer(
        &mut self,
        consumer: &AttributionEvidenceQueryConsumer,
        mounted_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        consumer.validate().map_err(query_decode)?;
        let mission = self.load_mission(&consumer.scope.project_id, &consumer.scope.mission_id)?;
        consumer
            .scope
            .validate_against_mission(&mission)
            .map_err(query_decode)?;
        let consumers =
            self.replay_attribution_evidence_query_consumers(&consumer.scope.project_id)?;
        if let Some(existing) = consumers.get(&consumer.consumer_id) {
            if existing.state == AttributionEvidenceQueryConsumerState::Active
                && existing.consumer == *consumer
            {
                return self.find_query_consumer_lifecycle_sequence(
                    &consumer.scope.project_id,
                    ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_MOUNT_EVENT_TYPE,
                    &consumer.consumer_id,
                );
            }
            return Err(StorageError::DomainDecode(
                "evidence query consumer identity conflicts with immutable history".into(),
            ));
        }
        let record = AttributionEvidenceQueryConsumerRecord::active(consumer.clone(), mounted_at)
            .map_err(query_decode)?;
        self.append_event(
            &consumer.scope.project_id,
            Some(&consumer.scope.mission_id),
            ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_MOUNT_EVENT_TYPE,
            &serde_json::to_value(record)?,
            mounted_at,
        )
    }

    /// Revocation is terminal for new queries and feedback while historical
    /// response records remain replayable for audit.
    pub fn revoke_attribution_evidence_query_consumer(
        &mut self,
        project_id: &ProjectId,
        consumer_id: &str,
        reason_digest: String,
        revoked_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        if consumer_id.trim().is_empty() {
            return Err(StorageError::DomainDecode(
                "evidence query consumer id is empty".into(),
            ));
        }
        let consumers = self.replay_attribution_evidence_query_consumers(project_id)?;
        let existing = consumers.get(consumer_id).ok_or_else(|| {
            StorageError::DomainDecode("evidence query consumer is not mounted".into())
        })?;
        if existing.state != AttributionEvidenceQueryConsumerState::Active {
            return Err(StorageError::DomainDecode(
                "evidence query consumer is already revoked".into(),
            ));
        }
        let next = existing
            .revoked(revoked_at, reason_digest)
            .map_err(query_decode)?;
        let mission_id = next.consumer.scope.mission_id.clone();
        let payload = serde_json::to_value(&next)?;
        self.append_event(
            project_id,
            Some(&mission_id),
            ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_REVOKE_EVENT_TYPE,
            &payload,
            revoked_at,
        )
    }

    /// Computes and durably logs one content-free evidence response. The
    /// request's ledger and provider cursor fences must match the spine's
    /// current replay exactly; otherwise the query fails closed as stale.
    pub fn append_attribution_evidence_query(
        &mut self,
        request: &AttributionEvidenceQueryRequest,
        reporting_currency: hartevo_domain_kernel::CurrencyCode,
    ) -> Result<AttributionEvidenceQueryResponse, StorageError> {
        request.validate().map_err(query_decode)?;
        let mission = self.load_mission(&request.scope.project_id, &request.scope.mission_id)?;
        request
            .scope
            .validate_against_mission(&mission)
            .map_err(query_decode)?;
        let consumers =
            self.replay_attribution_evidence_query_consumers(&request.scope.project_id)?;
        let consumer = active_consumer(&consumers, &request.consumer_id)?;
        if consumer.consumer.scope != request.scope {
            return Err(StorageError::DomainDecode(
                "evidence query consumer scope does not match request".into(),
            ));
        }
        let ledger =
            self.replay_attribution_spine(&request.scope.project_id, reporting_currency)?;
        let ledger_digest =
            AttributionEvidenceQueryResponse::ledger_digest(&ledger).map_err(query_decode)?;
        if ledger.revision != request.ledger_revision || ledger_digest != request.ledger_digest {
            return Err(StorageError::DomainDecode(
                "evidence query ledger revision or digest is stale".into(),
            ));
        }
        let current_cursor = current_cursor(&ledger, &request.provider);
        if request.cursor_fence != current_cursor {
            return Err(StorageError::DomainDecode(
                "evidence query provider cursor is stale or outside scope".into(),
            ));
        }
        if let Some(existing) =
            self.find_query_record(&request.scope.project_id, &request.query_id)?
        {
            if existing.request != *request {
                return Err(StorageError::DomainDecode(
                    "evidence query identity conflicts with immutable history".into(),
                ));
            }
            return Ok(existing.response);
        }
        let feedback_digests =
            self.feedback_digests_for_request(&request.scope.project_id, request)?;
        let response = build_response(&ledger, request, feedback_digests).map_err(query_decode)?;
        let record = AttributionEvidenceQueryRecord::new(request.clone(), response.clone())
            .map_err(query_decode)?;
        self.append_event(
            &request.scope.project_id,
            Some(&request.scope.mission_id),
            ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE,
            &serde_json::to_value(record)?,
            request.evaluated_at,
        )?;
        Ok(response)
    }

    /// Appends a digest-only Adopt or Reject feedback receipt against one
    /// previously logged response. It never changes the spine or response.
    pub fn append_attribution_evidence_adoption_feedback(
        &mut self,
        feedback: &AttributionEvidenceAdoptionFeedback,
        recorded_at: DateTime<Utc>,
    ) -> Result<AttributionEvidenceAdoptionFeedback, StorageError> {
        feedback.scope.validate().map_err(query_decode)?;
        let consumers =
            self.replay_attribution_evidence_query_consumers(&feedback.scope.project_id)?;
        let consumer = active_consumer(&consumers, &feedback.consumer_id)?;
        if consumer.consumer.scope != feedback.scope {
            return Err(StorageError::DomainDecode(
                "evidence query feedback consumer scope mismatch".into(),
            ));
        }
        let response = self
            .find_query_record(&feedback.scope.project_id, &feedback.query_id)?
            .ok_or_else(|| StorageError::DomainDecode("feedback query response is missing".into()))?
            .response;
        feedback
            .validate_against_response(&response)
            .map_err(query_decode)?;
        if let Some(existing) =
            self.find_feedback(&feedback.scope.project_id, &feedback.feedback_id)?
        {
            if existing != *feedback {
                return Err(StorageError::DomainDecode(
                    "evidence query feedback identity conflicts with immutable history".into(),
                ));
            }
            return Ok(existing);
        }
        self.append_event(
            &feedback.scope.project_id,
            Some(&feedback.scope.mission_id),
            ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE,
            &serde_json::to_value(feedback)?,
            recorded_at,
        )?;
        Ok(feedback.clone())
    }

    /// Replays query responses and feedback, including lifecycle state at the
    /// event sequence so a later revoke does not erase earlier audit records.
    pub fn replay_attribution_evidence_queries(
        &self,
        project_id: &ProjectId,
    ) -> Result<AttributionEvidenceQuerySnapshot, StorageError> {
        let events = self.events_for_project(project_id)?;
        let mut records = Vec::new();
        let mut query_map =
            BTreeMap::<AttributionEvidenceQueryId, AttributionEvidenceQueryRecord>::new();
        let mut feedback_ids = BTreeSet::new();
        for event in &events {
            match event.event_type.as_str() {
                ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE => {
                    let record: AttributionEvidenceQueryRecord =
                        serde_json::from_value(event.payload.clone())?;
                    record.validate().map_err(query_decode)?;
                    if event.mission_id.as_ref() != Some(&record.request.scope.mission_id)
                        || event.recorded_at != record.request.evaluated_at
                        || record.request.scope.project_id != *project_id
                    {
                        return Err(StorageError::DomainDecode(
                            "evidence query record scope mismatch".into(),
                        ));
                    }
                    let consumers = self.replay_attribution_evidence_query_consumers_through(
                        project_id,
                        event.sequence,
                    )?;
                    let consumer = active_consumer(&consumers, &record.request.consumer_id)?;
                    if consumer.consumer.scope != record.request.scope
                        || query_map
                            .insert(record.request.query_id.clone(), record.clone())
                            .is_some()
                    {
                        return Err(StorageError::DomainDecode(
                            "evidence query record is duplicate or cross-scope".into(),
                        ));
                    }
                    let expected_feedback =
                        Self::feedback_digests_before(&events, event.sequence, &record.request)?;
                    if expected_feedback != record.response.adoption_feedback_digests {
                        return Err(StorageError::DomainDecode(
                            "evidence query feedback digest projection drifted".into(),
                        ));
                    }
                    records.push(record);
                }
                ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE => {
                    let feedback: AttributionEvidenceAdoptionFeedback =
                        serde_json::from_value(event.payload.clone())?;
                    let query = query_map.get(&feedback.query_id).ok_or_else(|| {
                        StorageError::DomainDecode("feedback precedes its query response".into())
                    })?;
                    feedback
                        .validate_against_response(&query.response)
                        .map_err(query_decode)?;
                    let consumers = self.replay_attribution_evidence_query_consumers_through(
                        project_id,
                        event.sequence,
                    )?;
                    let consumer = active_consumer(&consumers, &feedback.consumer_id)?;
                    if event.mission_id.as_ref() != Some(&feedback.scope.mission_id)
                        || consumer.consumer.scope != feedback.scope
                        || !feedback_ids.insert(feedback.feedback_id)
                    {
                        return Err(StorageError::DomainDecode(
                            "evidence query feedback is duplicate or cross-scope".into(),
                        ));
                    }
                }
                _ => {}
            }
        }
        AttributionEvidenceQuerySnapshot::new(project_id.clone(), records).map_err(query_decode)
    }

    pub(crate) fn replay_attribution_evidence_query_consumers(
        &self,
        project_id: &ProjectId,
    ) -> Result<BTreeMap<String, AttributionEvidenceQueryConsumerRecord>, StorageError> {
        self.replay_attribution_evidence_query_consumers_through(project_id, i64::MAX)
    }

    pub(crate) fn replay_attribution_evidence_query_consumers_through(
        &self,
        project_id: &ProjectId,
        through_sequence: i64,
    ) -> Result<BTreeMap<String, AttributionEvidenceQueryConsumerRecord>, StorageError> {
        let mut consumers = BTreeMap::<String, AttributionEvidenceQueryConsumerRecord>::new();
        for event in self
            .events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.sequence <= through_sequence)
        {
            if !matches!(
                event.event_type.as_str(),
                ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_MOUNT_EVENT_TYPE
                    | ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_REVOKE_EVENT_TYPE
            ) {
                continue;
            }
            let expected_state =
                if event.event_type == ATTRIBUTION_EVIDENCE_QUERY_CONSUMER_MOUNT_EVENT_TYPE {
                    AttributionEvidenceQueryConsumerState::Active
                } else {
                    AttributionEvidenceQueryConsumerState::Revoked
                };
            let record: AttributionEvidenceQueryConsumerRecord =
                serde_json::from_value(event.payload)?;
            record.validate().map_err(query_decode)?;
            if record.state != expected_state
                || event.mission_id.as_ref() != Some(&record.consumer.scope.mission_id)
                || event.recorded_at != record.changed_at
            {
                return Err(StorageError::DomainDecode(
                    "evidence query consumer lifecycle scope or timestamp mismatch".into(),
                ));
            }
            let id = record.consumer.consumer_id.clone();
            if let Some(existing) = consumers.get_mut(&id) {
                if existing.consumer != record.consumer
                    || existing.state != AttributionEvidenceQueryConsumerState::Active
                {
                    return Err(StorageError::DomainDecode(
                        "evidence query consumer lifecycle is not monotonic".into(),
                    ));
                }
                *existing = record;
            } else if record.state == AttributionEvidenceQueryConsumerState::Active {
                consumers.insert(id, record);
            } else {
                return Err(StorageError::DomainDecode(
                    "evidence query consumer was revoked before mount".into(),
                ));
            }
        }
        Ok(consumers)
    }

    fn find_query_consumer_lifecycle_sequence(
        &self,
        project_id: &ProjectId,
        event_type: &str,
        consumer_id: &str,
    ) -> Result<i64, StorageError> {
        self.events_for_project(project_id)?
            .into_iter()
            .find(|event| {
                event.event_type == event_type
                    && serde_json::from_value::<AttributionEvidenceQueryConsumerRecord>(
                        event.payload.clone(),
                    )
                    .ok()
                    .is_some_and(|record| record.consumer.consumer_id == consumer_id)
            })
            .map(|event| event.sequence)
            .ok_or_else(|| {
                StorageError::DomainDecode("evidence query lifecycle event is missing".into())
            })
    }

    fn find_query_record(
        &self,
        project_id: &ProjectId,
        query_id: &AttributionEvidenceQueryId,
    ) -> Result<Option<AttributionEvidenceQueryRecord>, StorageError> {
        self.events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE)
            .try_fold(None, |found, event| {
                let record: AttributionEvidenceQueryRecord = serde_json::from_value(event.payload)?;
                if record.request.query_id != *query_id {
                    return Ok(found);
                }
                if found.as_ref().is_some_and(|existing| existing != &record) {
                    return Err(StorageError::DomainDecode(
                        "evidence query identity differs in immutable history".into(),
                    ));
                }
                Ok(Some(record))
            })
    }

    fn find_feedback(
        &self,
        project_id: &ProjectId,
        feedback_id: &str,
    ) -> Result<Option<AttributionEvidenceAdoptionFeedback>, StorageError> {
        self.events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE)
            .try_fold(None, |found, event| {
                let feedback: AttributionEvidenceAdoptionFeedback =
                    serde_json::from_value(event.payload)?;
                if feedback.feedback_id != feedback_id {
                    return Ok(found);
                }
                if found.as_ref().is_some_and(|existing| existing != &feedback) {
                    return Err(StorageError::DomainDecode(
                        "evidence query feedback differs in immutable history".into(),
                    ));
                }
                Ok(Some(feedback))
            })
    }

    fn feedback_digests_for_request(
        &self,
        project_id: &ProjectId,
        request: &AttributionEvidenceQueryRequest,
    ) -> Result<Vec<String>, StorageError> {
        let mut digests = Vec::new();
        for event in self.events_for_project(project_id)? {
            if event.event_type != ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE {
                continue;
            }
            let feedback: AttributionEvidenceAdoptionFeedback =
                serde_json::from_value(event.payload)?;
            if feedback.scope == request.scope
                && feedback.consumer_id == request.consumer_id
                && feedback.provider == request.provider
                && feedback.window == request.window
                && feedback.ledger_revision == request.ledger_revision
            {
                let query = self
                    .find_query_record(project_id, &feedback.query_id)?
                    .ok_or_else(|| {
                        StorageError::DomainDecode(
                            "evidence query feedback references a missing response".into(),
                        )
                    })?;
                if query.response.ledger_digest != request.ledger_digest
                    || query.response.ledger_revision != request.ledger_revision
                {
                    continue;
                }
                feedback
                    .validate_against_response(&query.response)
                    .map_err(query_decode)?;
                digests.push(feedback.feedback_digest);
            }
        }
        digests.sort();
        digests.dedup();
        Ok(digests)
    }

    fn feedback_digests_before(
        events: &[DomainEventRecord],
        through_sequence: i64,
        request: &AttributionEvidenceQueryRequest,
    ) -> Result<Vec<String>, StorageError> {
        let mut digests = Vec::new();
        for event in events.iter().filter(|event| {
            event.sequence < through_sequence
                && event.event_type == ATTRIBUTION_EVIDENCE_QUERY_FEEDBACK_EVENT_TYPE
        }) {
            let feedback: AttributionEvidenceAdoptionFeedback =
                serde_json::from_value(event.payload.clone())?;
            if feedback.scope == request.scope
                && feedback.consumer_id == request.consumer_id
                && feedback.provider == request.provider
                && feedback.window == request.window
                && feedback.ledger_revision == request.ledger_revision
            {
                digests.push(feedback.feedback_digest);
            }
        }
        digests.sort();
        digests.dedup();
        Ok(digests)
    }
}

impl AttributionEvidenceQueryService for ProjectStore {
    type Error = StorageError;

    fn mount_attribution_evidence_query_consumer(
        &mut self,
        consumer: &AttributionEvidenceQueryConsumer,
        mounted_at: DateTime<Utc>,
    ) -> Result<i64, Self::Error> {
        ProjectStore::mount_attribution_evidence_query_consumer(self, consumer, mounted_at)
    }

    fn revoke_attribution_evidence_query_consumer(
        &mut self,
        project_id: &ProjectId,
        consumer_id: &str,
        reason_digest: String,
        revoked_at: DateTime<Utc>,
    ) -> Result<i64, Self::Error> {
        ProjectStore::revoke_attribution_evidence_query_consumer(
            self,
            project_id,
            consumer_id,
            reason_digest,
            revoked_at,
        )
    }

    fn append_attribution_evidence_query(
        &mut self,
        request: &AttributionEvidenceQueryRequest,
        reporting_currency: hartevo_domain_kernel::CurrencyCode,
    ) -> Result<AttributionEvidenceQueryResponse, Self::Error> {
        ProjectStore::append_attribution_evidence_query(self, request, reporting_currency)
    }

    fn append_attribution_evidence_adoption_feedback(
        &mut self,
        feedback: &AttributionEvidenceAdoptionFeedback,
        recorded_at: DateTime<Utc>,
    ) -> Result<AttributionEvidenceAdoptionFeedback, Self::Error> {
        ProjectStore::append_attribution_evidence_adoption_feedback(self, feedback, recorded_at)
    }

    fn replay_attribution_evidence_queries(
        &self,
        project_id: &ProjectId,
    ) -> Result<AttributionEvidenceQuerySnapshot, Self::Error> {
        ProjectStore::replay_attribution_evidence_queries(self, project_id)
    }
}

pub(crate) fn active_consumer(
    consumers: &BTreeMap<String, AttributionEvidenceQueryConsumerRecord>,
    consumer_id: &str,
) -> Result<AttributionEvidenceQueryConsumerRecord, StorageError> {
    let consumer = consumers.get(consumer_id).ok_or_else(|| {
        StorageError::DomainDecode("evidence query consumer is not mounted".into())
    })?;
    if consumer.state != AttributionEvidenceQueryConsumerState::Active {
        return Err(StorageError::DomainDecode(
            "evidence query consumer is revoked".into(),
        ));
    }
    Ok(consumer.clone())
}

fn current_cursor(
    ledger: &hartevo_domain_kernel::AttributionLedger,
    provider: &AttributionEvidenceQueryProvider,
) -> Option<ProviderCursor> {
    ledger
        .cursors
        .iter()
        .find(|cursor| {
            cursor.provider == provider.provider && cursor.account_id == provider.account_id
        })
        .cloned()
}

#[allow(
    clippy::too_many_lines,
    reason = "the deterministic query projection keeps all content-free metrics in one auditable calculation"
)]
fn build_response(
    ledger: &hartevo_domain_kernel::AttributionLedger,
    request: &AttributionEvidenceQueryRequest,
    adoption_feedback_digests: Vec<String>,
) -> Result<AttributionEvidenceQueryResponse, AttributionEvidenceQueryError> {
    let selected = ledger
        .events
        .iter()
        .filter(|event| event_matches(event, request))
        .collect::<Vec<_>>();
    let selected_ids = selected
        .iter()
        .map(|event| event.id.clone())
        .collect::<BTreeSet<_>>();
    let first_party_event_count = selected
        .iter()
        .filter(|event| event.provenance.origin == ObservationOrigin::FirstParty)
        .count();
    let partner_event_count = selected
        .iter()
        .filter(|event| event.provenance.origin == ObservationOrigin::PartnerNetwork)
        .count();
    let weak_provenance_event_count =
        selected.len() - first_party_event_count - partner_event_count;
    let explicit_candidates = ledger
        .candidates
        .iter()
        .filter(|candidate| selected_ids.contains(&candidate.source_event_id))
        .collect::<Vec<_>>();
    let explicit_candidate_ids = explicit_candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect::<BTreeSet<_>>();
    let derived_candidate_count = selected
        .iter()
        .filter(|event| {
            matches!(
                event.kind,
                SourceEventKind::Conversion
                    | SourceEventKind::Order
                    | SourceEventKind::Refund
                    | SourceEventKind::Commission
                    | SourceEventKind::Payout
            )
        })
        .filter(|event| {
            !explicit_candidates
                .iter()
                .any(|candidate| candidate.source_event_id == event.id)
        })
        .count();
    let outcome_candidate_count =
        u64::try_from(explicit_candidates.len() + derived_candidate_count).map_err(|_| {
            AttributionEvidenceQueryError::AttributionSpine("count overflow".into())
        })?;
    let verified_outcome_count = u64::try_from(
        ledger
            .verified_outcomes
            .iter()
            .filter(|verified| {
                selected_ids.contains(&verified.source_event_id)
                    && (explicit_candidate_ids.is_empty()
                        || explicit_candidate_ids.contains(&verified.candidate_id))
            })
            .count(),
    )
    .map_err(|_| AttributionEvidenceQueryError::AttributionSpine("count overflow".into()))?;
    let coverage_digest = digest_events(&selected)?;
    let projection = ledger.replay(request.window.attribution_window())?;
    let mut unattributed_outcome_count = 0_u64;
    let mut inactive_lineage_count = 0_u64;
    for assignment in projection
        .assignments
        .iter()
        .filter(|assignment| selected_ids.contains(&assignment.source_event_id))
    {
        if assignment.touchpoint_event_id.is_none() {
            unattributed_outcome_count = unattributed_outcome_count.saturating_add(1);
        }
        if assignment.reason == AttributionReason::UnattributedInactiveLineage {
            inactive_lineage_count = inactive_lineage_count.saturating_add(1);
        }
    }
    let correction_count = selected
        .iter()
        .filter(|event| event.lineage.kind == CorrectionKind::Correction)
        .count();
    let reversal_count = selected
        .iter()
        .filter(|event| event.lineage.kind == CorrectionKind::Reversal)
        .count();
    let counterevidence = AttributionEvidenceCounterevidence {
        unverified_outcome_count: outcome_candidate_count.saturating_sub(verified_outcome_count),
        unattributed_outcome_count,
        inactive_lineage_count,
        correction_count: u64::try_from(correction_count).map_err(|_| {
            AttributionEvidenceQueryError::AttributionSpine("count overflow".into())
        })?,
        reversal_count: u64::try_from(reversal_count).map_err(|_| {
            AttributionEvidenceQueryError::AttributionSpine("count overflow".into())
        })?,
        counterevidence_digest: digest_json(&(
            &selected_ids,
            unattributed_outcome_count,
            inactive_lineage_count,
            correction_count,
            reversal_count,
        ))?,
    };
    let source_event_count = u64::try_from(selected.len())
        .map_err(|_| AttributionEvidenceQueryError::AttributionSpine("count overflow".into()))?;
    let source_coverage = AttributionEvidenceSourceCoverage {
        source_event_count,
        first_party_event_count: u64::try_from(first_party_event_count).map_err(|_| {
            AttributionEvidenceQueryError::AttributionSpine("count overflow".into())
        })?,
        partner_event_count: u64::try_from(partner_event_count).map_err(|_| {
            AttributionEvidenceQueryError::AttributionSpine("count overflow".into())
        })?,
        weak_provenance_event_count: u64::try_from(weak_provenance_event_count).map_err(|_| {
            AttributionEvidenceQueryError::AttributionSpine("count overflow".into())
        })?,
        outcome_candidate_count,
        verified_outcome_count,
        coverage_digest,
    };
    let freshness = freshness(&selected, request.evaluated_at)?;
    let confidence = if source_event_count == 0 {
        AttributionEvidenceConfidence::None
    } else if outcome_candidate_count == 0 {
        AttributionEvidenceConfidence::Low
    } else if verified_outcome_count == outcome_candidate_count && counterevidence.total() == 0 {
        AttributionEvidenceConfidence::High
    } else if verified_outcome_count > 0 {
        AttributionEvidenceConfidence::Medium
    } else {
        AttributionEvidenceConfidence::Low
    };
    let provider_cursor = current_cursor(ledger, &request.provider);
    let provider_revision = provider_cursor.as_ref().map_or(0, |cursor| cursor.sequence);
    let provider_digest = provider_cursor.as_ref().map_or_else(
        || digest_text("attribution-evidence-query:no-cursor"),
        |cursor| cursor.batch_digest.clone(),
    );
    AttributionEvidenceQueryResponse::new(
        request,
        provider_revision,
        provider_digest,
        source_coverage,
        counterevidence,
        freshness,
        confidence,
        adoption_feedback_digests,
    )
}

fn event_matches(event: &SourceEvent, request: &AttributionEvidenceQueryRequest) -> bool {
    event.tenant_id == request.scope.tenant_id
        && event.project_id == request.scope.project_id
        && event.mission_id.as_ref() == Some(&request.scope.mission_id)
        && event.identity.provider == request.provider.provider
        && event.identity.account_id == request.provider.account_id
        && event.observed_at >= request.window.starts_at
        && event.observed_at < request.window.ends_at
}

fn freshness(
    selected: &[&SourceEvent],
    evaluated_at: DateTime<Utc>,
) -> Result<AttributionEvidenceFreshness, AttributionEvidenceQueryError> {
    let latest_observed_at = selected.iter().map(|event| event.observed_at).max();
    let fresh_untils = selected
        .iter()
        .map(|event| event.provenance.fresh_until)
        .collect::<Vec<_>>();
    let fresh_until = fresh_untils.iter().copied().flatten().min();
    let state = if selected.is_empty() || fresh_untils.iter().any(Option::is_none) {
        AttributionEvidenceFreshnessState::Unknown
    } else if fresh_until.is_some_and(|until| until >= evaluated_at) {
        AttributionEvidenceFreshnessState::Fresh
    } else {
        AttributionEvidenceFreshnessState::Stale
    };
    AttributionEvidenceFreshness::new(state, latest_observed_at, fresh_until)
}

fn digest_events(events: &[&SourceEvent]) -> Result<String, AttributionEvidenceQueryError> {
    let mut digests = events
        .iter()
        .map(|event| {
            event
                .canonical_digest()
                .map_err(|error| AttributionEvidenceQueryError::AttributionSpine(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    digests.sort();
    digest_json(&digests)
}

fn digest_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, AttributionEvidenceQueryError> {
    let bytes = serde_json::to_vec(value).map_err(AttributionEvidenceQueryError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn query_decode(error: AttributionEvidenceQueryError) -> StorageError {
    let message = error.to_string();
    drop(error);
    StorageError::DomainDecode(message)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AttributionEvidenceAdoptionDecision, AttributionEvidenceQueryConsumer,
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
            TenantId::from("tenant-query"),
            ProjectId::from("project-query"),
            "Attribution query",
            "",
            "/tmp/hartevo-attribution-query",
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
            MissionId::from_stable("mission-query"),
            project.id.clone(),
            "Query mission",
            MissionContract::bootstrap(
                "Measure attribution evidence",
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
            "consumer-query",
            "planning-model",
            1,
            "d".repeat(64),
            scope,
            1,
        )
        .expect("consumer");
        let provider = AttributionEvidenceQueryProvider::new("meta", "acct-1");
        let currency = CurrencyCode::parse("USD").expect("currency");
        Fixture {
            store,
            project,
            mission,
            consumer,
            provider,
            currency,
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
        let cursor = ledger
            .cursors
            .iter()
            .find(|cursor| {
                cursor.provider == fixture.provider.provider
                    && cursor.account_id == fixture.provider.account_id
            })
            .cloned();
        AttributionEvidenceQueryRequest::new(
            fixture.consumer.consumer_id.clone(),
            fixture.consumer.scope.clone(),
            fixture.provider.clone(),
            window,
            at(evaluated_minute),
            cursor,
            ledger.revision,
            AttributionEvidenceQueryResponse::ledger_digest(ledger).expect("ledger digest"),
        )
        .expect("request")
    }

    fn seed_first_batch(fixture: &mut Fixture) -> AttributionLedger {
        let events = vec![
            source_event(&fixture.mission, "click-1", SourceEventKind::Click, 2),
            source_event(&fixture.mission, "order-1", SourceEventKind::Order, 4),
        ];
        let first = batch(&fixture.mission, events, None, 1, "cursor-1");
        fixture
            .store
            .append_attribution_observation_batch(&first, at(6))
            .expect("observation batch");
        fixture
            .store
            .replay_attribution_spine(&fixture.project.id, fixture.currency.clone())
            .expect("ledger")
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one durable query fixture proves content-free projection and feedback replay"
    )]
    fn query_is_content_free_durable_and_feedback_bound() {
        let mut fixture = fixture();
        fixture
            .store
            .mount_attribution_evidence_query_consumer(&fixture.consumer, at(0))
            .expect("mount");
        let ledger = seed_first_batch(&mut fixture);
        let first_request = request(&fixture, &ledger, 10);
        let first_response = fixture
            .store
            .append_attribution_evidence_query(&first_request, fixture.currency.clone())
            .expect("query");
        assert_eq!(first_response.source_coverage.source_event_count, 2);
        assert_eq!(first_response.source_coverage.first_party_event_count, 2);
        assert_eq!(first_response.source_coverage.outcome_candidate_count, 1);
        assert_eq!(first_response.source_coverage.verified_outcome_count, 0);
        assert_eq!(
            first_response.confidence,
            AttributionEvidenceConfidence::Low
        );
        assert!(first_response.adoption_feedback_digests.is_empty());
        let encoded = serde_json::to_string(&first_response).expect("response json");
        assert!(!encoded.contains("click-1"));
        assert!(!encoded.contains("order-1"));

        let feedback = AttributionEvidenceAdoptionFeedback::new(
            fixture.consumer.consumer_id.clone(),
            &first_response,
            AttributionEvidenceAdoptionDecision::Adopt,
        )
        .expect("feedback");
        fixture
            .store
            .append_attribution_evidence_adoption_feedback(&feedback, at(11))
            .expect("feedback event");
        let second_request = request(&fixture, &ledger, 12);
        let second_response = fixture
            .store
            .append_attribution_evidence_query(&second_request, fixture.currency.clone())
            .expect("second query");
        assert_eq!(
            second_response.adoption_feedback_digests,
            vec![feedback.feedback_digest.clone()]
        );
        let snapshot = fixture
            .store
            .replay_attribution_evidence_queries(&fixture.project.id)
            .expect("query replay");
        assert_eq!(snapshot.records.len(), 2);
        assert!(
            snapshot
                .records
                .iter()
                .all(|record| record.request.scope == fixture.consumer.scope)
        );
    }

    #[test]
    fn stale_cursor_and_revoked_consumer_fail_closed() {
        let mut fixture = fixture();
        fixture
            .store
            .mount_attribution_evidence_query_consumer(&fixture.consumer, at(0))
            .expect("mount");
        let first_ledger = seed_first_batch(&mut fixture);
        let first_request = request(&fixture, &first_ledger, 10);
        fixture
            .store
            .append_attribution_evidence_query(&first_request, fixture.currency.clone())
            .expect("query");
        let second = batch(
            &fixture.mission,
            vec![source_event(
                &fixture.mission,
                "click-2",
                SourceEventKind::Click,
                7,
            )],
            first_ledger.cursors.first().cloned(),
            2,
            "cursor-2",
        );
        fixture
            .store
            .append_attribution_observation_batch(&second, at(9))
            .expect("second observation batch");
        assert!(
            fixture
                .store
                .append_attribution_evidence_query(&first_request, fixture.currency.clone())
                .is_err()
        );

        let current = fixture
            .store
            .replay_attribution_spine(&fixture.project.id, fixture.currency.clone())
            .expect("current ledger");
        let second_request = request(&fixture, &current, 12);
        fixture
            .store
            .append_attribution_evidence_query(&second_request, fixture.currency.clone())
            .expect("current query");
        fixture
            .store
            .revoke_attribution_evidence_query_consumer(
                &fixture.project.id,
                &fixture.consumer.consumer_id,
                "e".repeat(64),
                at(13),
            )
            .expect("revoke");
        let revoked_request = request(&fixture, &current, 14);
        assert!(
            fixture
                .store
                .append_attribution_evidence_query(&revoked_request, fixture.currency.clone())
                .is_err()
        );
    }

    #[test]
    fn tampered_query_and_cross_mission_request_fail_closed() {
        let mut fixture = fixture();
        fixture
            .store
            .mount_attribution_evidence_query_consumer(&fixture.consumer, at(0))
            .expect("mount");
        let ledger = seed_first_batch(&mut fixture);
        let query = request(&fixture, &ledger, 10);
        fixture
            .store
            .append_attribution_evidence_query(&query, fixture.currency.clone())
            .expect("query");
        let query_event = fixture
            .store
            .events_for_project(&fixture.project.id)
            .expect("events")
            .into_iter()
            .find(|event| event.event_type == ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE)
            .expect("query event");
        let mut tampered = query_event.payload;
        tampered["response"]["responseDigest"] = json!("f".repeat(64));
        fixture
            .store
            .append_event(
                &fixture.project.id,
                Some(&fixture.mission.id),
                ATTRIBUTION_EVIDENCE_QUERY_REQUEST_EVENT_TYPE,
                &tampered,
                at(11),
            )
            .expect("tampered event append");
        assert!(
            fixture
                .store
                .replay_attribution_evidence_queries(&fixture.project.id)
                .is_err()
        );

        let foreign_mission = Mission::compile(
            fixture.mission.tenant_id.clone(),
            MissionId::from_stable("mission-foreign"),
            fixture.project.id.clone(),
            "Foreign mission",
            MissionContract::bootstrap("Other scope", ["research.read".into()], at(0)),
            at(0),
        )
        .expect("foreign mission");
        fixture
            .store
            .create_mission_atomic(
                &foreign_mission,
                &[PendingEvent::new("mission.compiled", json!({}), at(0))],
            )
            .expect("foreign mission event");
        let foreign_scope =
            AttributionEvidenceQueryScope::from_mission(&foreign_mission).expect("foreign scope");
        let foreign_window = AttributionEvidenceQueryWindow::new(1, at(-1), at(30), 3_600, 3_600)
            .expect("foreign window");
        let foreign_request = AttributionEvidenceQueryRequest::new(
            fixture.consumer.consumer_id.clone(),
            foreign_scope,
            fixture.provider.clone(),
            foreign_window,
            at(12),
            ledger.cursors.first().cloned(),
            ledger.revision,
            AttributionEvidenceQueryResponse::ledger_digest(&ledger).expect("ledger digest"),
        )
        .expect("foreign request");
        assert!(
            fixture
                .store
                .append_attribution_evidence_query(&foreign_request, fixture.currency)
                .is_err()
        );
    }
}

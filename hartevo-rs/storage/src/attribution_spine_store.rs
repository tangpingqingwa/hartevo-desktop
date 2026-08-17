//! Durable append-only storage boundary for the attribution spine.
//!
//! ATTR-01 deliberately uses the existing `domain_events` table. This keeps
//! SQLCipher schema v47 unchanged while preserving immutable observation
//! batches, provider cursor fences, and deterministic replay after restart.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ATTRIBUTION_OUTCOME_PLUGIN_MOUNT_EVENT_TYPE, ATTRIBUTION_OUTCOME_PLUGIN_REVOKE_EVENT_TYPE,
    ATTRIBUTION_OUTCOME_PLUGIN_UNMOUNT_EVENT_TYPE, ATTRIBUTION_OUTCOME_RESULT_PACKET_EVENT_TYPE,
    ATTRIBUTION_SPINE_EVENT_TYPE, AttributionError, AttributionLedger,
    AttributionOutcomePluginError, AttributionOutcomePluginSnapshot, CurrencyCode,
    OutcomeCandidate, OutcomeCandidateId, OutcomePluginMount, OutcomePluginMountReceipt,
    OutcomePluginMountRecord, OutcomePluginMountState, OutcomeResultPacket, OutcomeVerification,
    ProjectId, SourceObservationBatch, TenantId,
    attribution_spine_contract::{
        ATTRIBUTION_SPINE_CANDIDATE_EVENT_TYPE, ATTRIBUTION_SPINE_VERIFIED_OUTCOME_EVENT_TYPE,
    },
};
use hartevo_effect_broker::ProviderAdapterRegistry;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{DomainEventRecord, ProjectStore, StorageError};

/// Returns the canonical digest used to bind attribution plugin mounts to one
/// exact ProviderAdapterRegistry snapshot. Registration order is normalized so
/// a registry cannot drift merely by reordering equivalent entries.
pub fn attribution_provider_registry_digest(registry: &ProviderAdapterRegistry) -> String {
    let mut registrations = registry
        .registrations()
        .iter()
        .map(|registration| serde_json::to_value(registration).expect("provider metadata"))
        .collect::<Vec<_>>();
    registrations.sort_by_key(Value::to_string);
    let value = serde_json::json!({
        "schemaVersion": "hartevo-provider-adapter-contract/v1",
        "contractVersion": "provider-adapter-e1/v1",
        "registryVersion": registry.registry_version(),
        "registrations": registrations,
    });
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&value).expect("provider registry"))
    )
}

/// Compatibility extension for the pre-adoption attribution storage API.
///
/// The newer adoption slice owns the same inherent method names on
/// `ProjectStore`. Keeping these two methods on a trait lets this branch stay
/// independently usable while allowing a clean synthetic composition with
/// that newer slice (inherent methods take precedence when both are present).
pub trait AttributionSpineStoreExt {
    fn append_attribution_candidate(
        &mut self,
        project_id: &ProjectId,
        candidate: &OutcomeCandidate,
        reporting_currency: CurrencyCode,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError>;

    fn append_attribution_verification(
        &mut self,
        project_id: &ProjectId,
        candidate_id: &OutcomeCandidateId,
        verification: &OutcomeVerification,
        reporting_currency: CurrencyCode,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError>;
}

impl ProjectStore {
    /// Appends one connector observation batch as an immutable domain event.
    /// The batch's provider cursor is the durable replay fence; no connector
    /// response is promoted to a verified outcome by this write.
    pub fn append_attribution_observation_batch(
        &mut self,
        batch: &SourceObservationBatch,
        recorded_at: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let mut batch = batch.clone();
        let reporting_currency = batch
            .events
            .iter()
            .find_map(|event| event.amount.as_ref().map(|amount| amount.currency.clone()))
            .unwrap_or_else(|| CurrencyCode::parse("USD").expect("static currency"));
        let mut ledger = self.replay_attribution_spine(&batch.project_id, reporting_currency)?;
        // Older provider adapters populated a cursor token but left the
        // content digest as a transport placeholder. Rebind only an exact
        // prior cursor whose non-digest fields match, then derive the new
        // content digest before strict validation.
        if let Some(cursor_before) = batch.cursor_before.as_mut()
            && let Some(expected) = ledger.cursors.iter().find(|expected| {
                let mut candidate = cursor_before.clone();
                candidate.batch_digest.clone_from(&expected.batch_digest);
                candidate == **expected
            })
        {
            cursor_before
                .batch_digest
                .clone_from(&expected.batch_digest);
        }
        batch.cursor_after.batch_digest = batch
            .content_digest()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
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
                    .filter(|existing| existing == &batch)
                    .map(|_| event.sequence)
            })
        {
            return Ok(existing);
        }
        ledger
            .ingest_batch(batch.clone())
            .map_err(|error| domain_decode(&error))?;
        let payload = serde_json::to_value(&batch)?;
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

    /// Atomically records one Project/Mission-scoped outcome service mount.
    /// The existing ProviderAdapterRegistry is the only provider registry;
    /// this method stores only its exact version/digest binding.
    pub fn mount_attribution_outcome_plugin(
        &mut self,
        mount: &OutcomePluginMount,
        registry: &ProviderAdapterRegistry,
    ) -> Result<OutcomePluginMountReceipt, StorageError> {
        mount.validate().map_err(|error| plugin_decode(&error))?;
        Self::validate_outcome_plugin_provider(mount, registry)?;
        let project = self.load_project(&mount.scope.project_id)?;
        if project.tenant_id != mount.scope.tenant_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        let mission = self.load_mission(&mount.scope.project_id, &mount.scope.mission_id)?;
        if mission.tenant_id != mount.scope.tenant_id
            || mission.revision != mount.scope.mission_revision
        {
            return Err(StorageError::DomainDecode(
                "outcome plugin mount Mission revision is stale".into(),
            ));
        }
        let receipt =
            OutcomePluginMountReceipt::from_mount(mount).map_err(|error| plugin_decode(&error))?;
        let records = self.replay_outcome_plugin_records(&mount.scope.project_id, registry)?;
        if let Some(existing) = records
            .iter()
            .find(|record| record.mount.mount_id == mount.mount_id)
        {
            if existing.state == OutcomePluginMountState::Active
                && existing.mount == *mount
                && existing.receipt == receipt
            {
                return Ok(receipt);
            }
            return Err(StorageError::DomainDecode(
                "outcome plugin mount identity conflicts with immutable history".into(),
            ));
        }
        let record = OutcomePluginMountRecord::active(mount.clone(), receipt.clone())
            .map_err(|error| plugin_decode(&error))?;
        let payload = serde_json::to_value(record)?;
        self.append_event(
            &mount.scope.project_id,
            Some(&mount.scope.mission_id),
            ATTRIBUTION_OUTCOME_PLUGIN_MOUNT_EVENT_TYPE,
            &payload,
            mount.mounted_at,
        )?;
        Ok(receipt)
    }

    /// Reversibly removes one active mount. The receipt is an exact stale and
    /// cross-scope fence; a repeated identical transition is idempotent.
    pub fn unmount_attribution_outcome_plugin(
        &mut self,
        receipt: &OutcomePluginMountReceipt,
        reason_digest: String,
        changed_at: DateTime<Utc>,
        registry: &ProviderAdapterRegistry,
    ) -> Result<i64, StorageError> {
        self.transition_attribution_outcome_plugin(
            receipt,
            OutcomePluginMountState::Unmounted,
            reason_digest,
            changed_at,
            registry,
        )
    }

    /// Permanently revokes one active mount. Revocation is a durable terminal
    /// state and is intentionally distinct from a normal unmount.
    pub fn revoke_attribution_outcome_plugin(
        &mut self,
        receipt: &OutcomePluginMountReceipt,
        reason_digest: String,
        changed_at: DateTime<Utc>,
        registry: &ProviderAdapterRegistry,
    ) -> Result<i64, StorageError> {
        self.transition_attribution_outcome_plugin(
            receipt,
            OutcomePluginMountState::Revoked,
            reason_digest,
            changed_at,
            registry,
        )
    }

    /// Generates and durably records one result packet from the exact replayed
    /// attribution ledger. No source event or verification is fabricated here.
    pub fn append_attribution_outcome_result(
        &mut self,
        project_id: &ProjectId,
        mount_id: &str,
        candidate_id: &OutcomeCandidateId,
        reporting_currency: CurrencyCode,
        registry: &ProviderAdapterRegistry,
        recorded_at: DateTime<Utc>,
    ) -> Result<OutcomeResultPacket, StorageError> {
        let records = self.replay_outcome_plugin_records(project_id, registry)?;
        let record = records
            .iter()
            .find(|record| record.mount.mount_id == mount_id)
            .ok_or_else(|| StorageError::DomainDecode("outcome plugin mount missing".into()))?;
        if record.state != OutcomePluginMountState::Active {
            return Err(StorageError::DomainDecode(
                "outcome plugin mount is not active".into(),
            ));
        }
        let ledger = self.replay_attribution_spine(project_id, reporting_currency)?;
        let packet = OutcomeResultPacket::from_ledger(&ledger, &record.mount, candidate_id)
            .map_err(|error| plugin_decode(&error))?;
        if let Some(existing) = self
            .events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == ATTRIBUTION_OUTCOME_RESULT_PACKET_EVENT_TYPE)
            .find_map(|event| {
                serde_json::from_value::<OutcomeResultPacket>(event.payload)
                    .ok()
                    .filter(|existing| existing.packet_id == packet.packet_id)
                    .map(|existing| (event.sequence, existing))
            })
        {
            if existing.1 == packet {
                return Ok(packet);
            }
            return Err(StorageError::DomainDecode(
                "outcome result packet identity conflicts with immutable history".into(),
            ));
        }
        let payload = serde_json::to_value(&packet)?;
        self.append_event(
            project_id,
            Some(&record.mount.scope.mission_id),
            ATTRIBUTION_OUTCOME_RESULT_PACKET_EVENT_TYPE,
            &payload,
            recorded_at,
        )?;
        Ok(packet)
    }

    /// Reconstructs all mounted services and result packets from immutable
    /// domain events. A packet is accepted only while its mount was active and
    /// only when it still validates against the exact source ledger revision.
    pub fn replay_attribution_outcome_plugins(
        &self,
        project_id: &ProjectId,
        reporting_currency: CurrencyCode,
        registry: &ProviderAdapterRegistry,
    ) -> Result<AttributionOutcomePluginSnapshot, StorageError> {
        let records = self.replay_outcome_plugin_records(project_id, registry)?;
        let ledger = self.replay_attribution_spine(project_id, reporting_currency)?;
        let mut packets = Vec::new();
        for event in self.events_for_project(project_id)? {
            if event.event_type != ATTRIBUTION_OUTCOME_RESULT_PACKET_EVENT_TYPE {
                continue;
            }
            let packet: OutcomeResultPacket = serde_json::from_value(event.payload)?;
            packet.validate().map_err(|error| plugin_decode(&error))?;
            let record = self
                .replay_outcome_plugin_records_through(project_id, registry, event.sequence)?
                .into_iter()
                .find(|record| record.mount.mount_id == packet.mount_id)
                .ok_or_else(|| {
                    StorageError::DomainDecode("outcome result mount missing during replay".into())
                })?;
            if record.state != OutcomePluginMountState::Active {
                return Err(StorageError::DomainDecode(
                    "outcome result references an inactive mount".into(),
                ));
            }
            if event.mission_id.as_ref() != Some(&record.mount.scope.mission_id) {
                return Err(StorageError::DomainDecode(
                    "outcome result references a cross-scope mount".into(),
                ));
            }
            packet
                .validate_for_replay(&ledger, &record.mount)
                .map_err(|error| plugin_decode(&error))?;
            if let Some(existing) = packets
                .iter()
                .find(|existing: &&OutcomeResultPacket| existing.packet_id == packet.packet_id)
            {
                if *existing != packet {
                    return Err(StorageError::DomainDecode(
                        "duplicate outcome result packet differs from history".into(),
                    ));
                }
            } else {
                packets.push(packet);
            }
        }
        let project = self.load_project(project_id)?;
        AttributionOutcomePluginSnapshot::new(
            project.tenant_id,
            project_id.clone(),
            records,
            packets,
        )
        .map_err(|error| plugin_decode(&error))
    }

    fn transition_attribution_outcome_plugin(
        &mut self,
        receipt: &OutcomePluginMountReceipt,
        state: OutcomePluginMountState,
        reason_digest: String,
        changed_at: DateTime<Utc>,
        registry: &ProviderAdapterRegistry,
    ) -> Result<i64, StorageError> {
        receipt.validate().map_err(|error| plugin_decode(&error))?;
        let records = self.replay_outcome_plugin_records(&receipt.project_id, registry)?;
        let existing = records
            .iter()
            .find(|record| record.mount.mount_id == receipt.mount_id)
            .ok_or_else(|| StorageError::DomainDecode("outcome plugin mount missing".into()))?;
        if existing.receipt != *receipt {
            return Err(StorageError::DomainDecode(
                "outcome plugin mount receipt is stale or swapped".into(),
            ));
        }
        if existing.state == state {
            if existing.reason_digest.as_deref() != Some(reason_digest.as_str())
                || existing.changed_at != changed_at
            {
                return Err(StorageError::DomainDecode(
                    "outcome plugin lifecycle replay differs from immutable history".into(),
                ));
            }
            return self.find_attribution_plugin_record_sequence(
                &receipt.project_id,
                state,
                receipt.mount_id.as_str(),
            );
        }
        if existing.state != OutcomePluginMountState::Active {
            return Err(StorageError::DomainDecode(
                "outcome plugin mount is already terminal".into(),
            ));
        }
        let next = existing
            .transition(state, changed_at, Some(reason_digest))
            .map_err(|error| plugin_decode(&error))?;
        let event_type = match state {
            OutcomePluginMountState::Unmounted => ATTRIBUTION_OUTCOME_PLUGIN_UNMOUNT_EVENT_TYPE,
            OutcomePluginMountState::Revoked => ATTRIBUTION_OUTCOME_PLUGIN_REVOKE_EVENT_TYPE,
            OutcomePluginMountState::Active => {
                return Err(StorageError::DomainDecode(
                    "active is not a lifecycle transition".into(),
                ));
            }
        };
        let payload = serde_json::to_value(next)?;
        self.append_event(
            &receipt.project_id,
            Some(&receipt.mission_id),
            event_type,
            &payload,
            changed_at,
        )
    }

    fn validate_outcome_plugin_provider(
        mount: &OutcomePluginMount,
        registry: &ProviderAdapterRegistry,
    ) -> Result<(), StorageError> {
        registry
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if registry.registry_version() != mount.provider.registry_version
            || attribution_provider_registry_digest(registry) != mount.provider.registry_digest
        {
            return Err(StorageError::DomainDecode(
                "outcome plugin provider registry version or digest mismatch".into(),
            ));
        }
        let registration = registry
            .registrations()
            .iter()
            .find(|registration| {
                registration.key().provider_id() == mount.provider.provider_id
                    && registration.key().capability_id() == mount.provider.capability_id
            })
            .ok_or_else(|| {
                StorageError::DomainDecode("outcome plugin provider is not registered".into())
            })?;
        if registration.adapter().adapter_id() != mount.provider.adapter_id
            || registration.adapter().adapter_version() != mount.provider.adapter_version
        {
            return Err(StorageError::DomainDecode(
                "outcome plugin provider adapter does not match registry".into(),
            ));
        }
        Ok(())
    }

    fn replay_outcome_plugin_records(
        &self,
        project_id: &ProjectId,
        registry: &ProviderAdapterRegistry,
    ) -> Result<Vec<OutcomePluginMountRecord>, StorageError> {
        self.replay_outcome_plugin_records_through(project_id, registry, i64::MAX)
    }

    fn replay_outcome_plugin_records_through(
        &self,
        project_id: &ProjectId,
        registry: &ProviderAdapterRegistry,
        through_sequence: i64,
    ) -> Result<Vec<OutcomePluginMountRecord>, StorageError> {
        let mut records: Vec<OutcomePluginMountRecord> = Vec::new();
        for event in self.events_for_project(project_id)? {
            if event.sequence > through_sequence {
                break;
            }
            let state = match event.event_type.as_str() {
                ATTRIBUTION_OUTCOME_PLUGIN_MOUNT_EVENT_TYPE => {
                    Some(OutcomePluginMountState::Active)
                }
                ATTRIBUTION_OUTCOME_PLUGIN_UNMOUNT_EVENT_TYPE => {
                    Some(OutcomePluginMountState::Unmounted)
                }
                ATTRIBUTION_OUTCOME_PLUGIN_REVOKE_EVENT_TYPE => {
                    Some(OutcomePluginMountState::Revoked)
                }
                _ => None,
            };
            let Some(expected_state) = state else {
                continue;
            };
            let record: OutcomePluginMountRecord = serde_json::from_value(event.payload)?;
            record.validate().map_err(|error| plugin_decode(&error))?;
            if record.state != expected_state
                || record.mount.scope.project_id != *project_id
                || event.mission_id.as_ref() != Some(&record.mount.scope.mission_id)
            {
                return Err(StorageError::DomainDecode(
                    "outcome plugin lifecycle event scope or state mismatch".into(),
                ));
            }
            Self::validate_outcome_plugin_provider(&record.mount, registry)?;
            if let Some(existing) = records
                .iter_mut()
                .find(|existing| existing.mount.mount_id == record.mount.mount_id)
            {
                if existing.mount != record.mount || existing.receipt != record.receipt {
                    return Err(StorageError::DomainDecode(
                        "outcome plugin mount identity differs from history".into(),
                    ));
                }
                if existing.state == record.state && *existing == record {
                    continue;
                }
                if existing.state != OutcomePluginMountState::Active
                    || record.state == OutcomePluginMountState::Active
                    || record.changed_at < existing.changed_at
                {
                    return Err(StorageError::DomainDecode(
                        "outcome plugin lifecycle transition is invalid".into(),
                    ));
                }
                *existing = record;
            } else {
                if record.state != OutcomePluginMountState::Active {
                    return Err(StorageError::DomainDecode(
                        "outcome plugin lifecycle begins outside a mount".into(),
                    ));
                }
                records.push(record);
            }
        }
        Ok(records)
    }

    fn find_attribution_plugin_record_sequence(
        &self,
        project_id: &ProjectId,
        state: OutcomePluginMountState,
        mount_id: &str,
    ) -> Result<i64, StorageError> {
        let event_type = match state {
            OutcomePluginMountState::Unmounted => ATTRIBUTION_OUTCOME_PLUGIN_UNMOUNT_EVENT_TYPE,
            OutcomePluginMountState::Revoked => ATTRIBUTION_OUTCOME_PLUGIN_REVOKE_EVENT_TYPE,
            OutcomePluginMountState::Active => ATTRIBUTION_OUTCOME_PLUGIN_MOUNT_EVENT_TYPE,
        };
        self.events_for_project(project_id)?
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .find_map(|event| {
                serde_json::from_value::<OutcomePluginMountRecord>(event.payload)
                    .ok()
                    .filter(|record| record.mount.mount_id == mount_id && record.state == state)
                    .map(|_| event.sequence)
            })
            .ok_or_else(|| {
                StorageError::DomainDecode("outcome plugin idempotency record missing".into())
            })
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

impl AttributionSpineStoreExt for ProjectStore {
    /// Persists the candidate stage independently from verification. A
    /// duplicate exact candidate is idempotent; a same-id content swap is
    /// rejected before another domain event can be appended.
    fn append_attribution_candidate(
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
    fn append_attribution_verification(
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

fn plugin_decode(error: &AttributionOutcomePluginError) -> StorageError {
    StorageError::DomainDecode(error.to_string())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        CorrectionLineage, CurrencyCode, Mission, MissionContract, MissionId, Money,
        ObservationOrigin, ObservationProvenance, OutcomeMissionConsumer, OutcomePluginIdentity,
        OutcomePluginMount, OutcomePluginScope, OutcomeServiceDefinition, OutcomeServiceProvider,
        OutcomeVerification, Project, ProjectId, ProviderCursor, ProviderEntityRef,
        ProviderEventIdentity, SourceEntityKind, SourceEvent, SourceEventId, SourceEventKind,
        SourceEventLinks, StorageMode, TenantId, VerificationMethod,
    };
    use hartevo_effect_broker::{
        ProviderAdapterIdentity, ProviderAdapterOperation, ProviderAdapterRegistry,
        ProviderCapabilityKey, ProviderCapabilitySupport, ProviderEvidenceClass,
        ProviderEvidenceSupport, ProviderProvenanceClass,
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
        let mission = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-1"),
            ProjectId::from("project-1"),
            "Attribution outcome",
            MissionContract::bootstrap("Produce an attributed outcome", [], at(0)),
            at(0),
        )
        .expect("mission");
        store.save_mission(&mission).expect("mission");
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
            mission_id: Some(MissionId::from("mission-1")),
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
            mission_id: Some(MissionId::from("mission-1")),
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
            mission_id: Some(MissionId::from("mission-1")),
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
            mission_id: Some(MissionId::from("mission-1")),
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

    fn outcome_registry() -> ProviderAdapterRegistry {
        let key = ProviderCapabilityKey::new("meta", "marketplace.read").expect("key");
        let adapter = ProviderAdapterIdentity::new("meta.readback", 1).expect("adapter");
        let support = ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Read,
            ProviderEvidenceClass::ReadObservation,
            ProviderProvenanceClass::ControlledProvider,
        )
        .expect("support");
        ProviderAdapterRegistry::new(
            "fixture-registry.v1",
            [ProviderCapabilitySupport::new(key, adapter, [support]).expect("registration")],
        )
        .expect("registry")
    }

    fn outcome_mount(registry: &ProviderAdapterRegistry) -> OutcomePluginMount {
        let scope = OutcomePluginScope {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-1"),
            mission_revision: 1,
        };
        let service = OutcomeServiceDefinition::attribution_result();
        let provider = OutcomeServiceProvider {
            provider_id: "meta".into(),
            capability_id: "marketplace.read".into(),
            adapter_id: "meta.readback".into(),
            adapter_version: 1,
            registry_version: registry.registry_version().into(),
            registry_digest: attribution_provider_registry_digest(registry),
        };
        let consumer = OutcomeMissionConsumer {
            consumer_id: "mission.outcome.consumer".into(),
            service_id: service.service_id.clone(),
            provider_id: provider.provider_id.clone(),
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
        };
        OutcomePluginMount::new(
            OutcomePluginIdentity::new("attribution.outcome.plugin", 1, "f".repeat(64))
                .expect("identity"),
            scope,
            service,
            provider,
            consumer,
            1,
            at(10),
        )
        .expect("mount")
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

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one lifecycle test keeps mount, candidate, verification, replay, and unmount fences auditable"
    )]
    fn outcome_plugin_mount_result_lifecycle_and_replay_are_exact() {
        let mut store = setup_store();
        let click = click_batch();
        store
            .append_attribution_observation_batch(&click, at(4))
            .expect("click");
        let order = order_batch(click.cursor_after.clone());
        store
            .append_attribution_observation_batch(&order, at(8))
            .expect("order");
        let registry = outcome_registry();
        let mount = outcome_mount(&registry);
        let receipt = store
            .mount_attribution_outcome_plugin(&mount, &registry)
            .expect("mount");
        assert_eq!(
            store
                .mount_attribution_outcome_plugin(&mount, &registry)
                .expect("idempotent mount"),
            receipt
        );
        let replayed = store
            .replay_attribution_outcome_plugins(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
                &registry,
            )
            .expect("mount replay");
        assert_eq!(replayed.mounts.len(), 1);
        assert_eq!(replayed.mounts[0].state, OutcomePluginMountState::Active);

        let ledger = store
            .replay_attribution_spine(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
            )
            .expect("ledger");
        let candidate = ledger.events[1].outcome_candidate().expect("candidate");
        let candidate_id = candidate.id.clone();
        store
            .append_attribution_candidate(
                &ProjectId::from("project-1"),
                &candidate,
                CurrencyCode::parse("USD").expect("USD"),
                at(10),
            )
            .expect("candidate");
        let candidate_packet = store
            .append_attribution_outcome_result(
                &ProjectId::from("project-1"),
                &mount.mount_id,
                &candidate_id,
                CurrencyCode::parse("USD").expect("USD"),
                &registry,
                at(11),
            )
            .expect("candidate packet");
        assert_eq!(
            candidate_packet.readiness,
            hartevo_domain_kernel::OutcomeResultReadiness::RequiresIndependentVerification
        );
        let replayed = store
            .replay_attribution_outcome_plugins(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
                &registry,
            )
            .expect("candidate replay");
        assert_eq!(replayed.packets.len(), 1);

        store
            .append_attribution_verification(
                &ProjectId::from("project-1"),
                &candidate_id,
                &OutcomeVerification {
                    method: VerificationMethod::IndependentReadback,
                    verifier: "meta-readback".into(),
                    independent: true,
                    verified_at: at(12),
                    evidence_digest: "a".repeat(64),
                },
                CurrencyCode::parse("USD").expect("USD"),
                at(13),
            )
            .expect("verification");
        let verified_packet = store
            .append_attribution_outcome_result(
                &ProjectId::from("project-1"),
                &mount.mount_id,
                &candidate_id,
                CurrencyCode::parse("USD").expect("USD"),
                &registry,
                at(14),
            )
            .expect("verified packet");
        assert_eq!(
            verified_packet.readiness,
            hartevo_domain_kernel::OutcomeResultReadiness::AdoptableVerified
        );
        let replayed = store
            .replay_attribution_outcome_plugins(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
                &registry,
            )
            .expect("verified replay");
        assert_eq!(replayed.packets.len(), 2);

        let reason = "b".repeat(64);
        store
            .unmount_attribution_outcome_plugin(&receipt, reason.clone(), at(15), &registry)
            .expect("unmount");
        assert!(matches!(
            store.mount_attribution_outcome_plugin(&mount, &registry),
            Err(StorageError::DomainDecode(_))
        ));
        assert!(matches!(
            store.append_attribution_outcome_result(
                &ProjectId::from("project-1"),
                &mount.mount_id,
                &candidate_id,
                CurrencyCode::parse("USD").expect("USD"),
                &registry,
                at(16),
            ),
            Err(StorageError::DomainDecode(_))
        ));
        let replayed = store
            .replay_attribution_outcome_plugins(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
                &registry,
            )
            .expect("unmount replay");
        assert_eq!(replayed.mounts[0].state, OutcomePluginMountState::Unmounted);
        assert_eq!(replayed.packets.len(), 2);
    }

    #[test]
    fn outcome_plugin_provider_registry_and_receipt_tamper_fail_closed() {
        let mut store = setup_store();
        let registry = outcome_registry();
        let mount = outcome_mount(&registry);
        let mut tampered = mount.clone();
        tampered.provider.registry_digest = "0".repeat(64);
        assert!(matches!(
            store.mount_attribution_outcome_plugin(&tampered, &registry),
            Err(StorageError::DomainDecode(_))
        ));
        let receipt = store
            .mount_attribution_outcome_plugin(&mount, &registry)
            .expect("mount");
        let mut swapped = receipt.clone();
        swapped.mission_revision += 1;
        assert!(matches!(
            store.unmount_attribution_outcome_plugin(&swapped, "c".repeat(64), at(15), &registry,),
            Err(StorageError::DomainDecode(_))
        ));
        let revoke_reason = "d".repeat(64);
        let revoke_sequence = store
            .revoke_attribution_outcome_plugin(&receipt, revoke_reason.clone(), at(15), &registry)
            .expect("revoke");
        assert_eq!(
            store
                .revoke_attribution_outcome_plugin(&receipt, revoke_reason, at(15), &registry,)
                .expect("idempotent revoke"),
            revoke_sequence
        );
        assert!(matches!(
            store.revoke_attribution_outcome_plugin(&receipt, "e".repeat(64), at(16), &registry,),
            Err(StorageError::DomainDecode(_))
        ));
        let replayed = store
            .replay_attribution_outcome_plugins(
                &ProjectId::from("project-1"),
                CurrencyCode::parse("USD").expect("USD"),
                &registry,
            )
            .expect("revoke replay");
        assert_eq!(replayed.mounts[0].state, OutcomePluginMountState::Revoked);
    }
}

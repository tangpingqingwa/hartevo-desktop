//! Durable append-only storage boundary for the attribution spine.
//!
//! ATTR-01 deliberately uses the existing `domain_events` table. This keeps
//! SQLCipher schema v47 unchanged while preserving immutable observation
//! batches, provider cursor fences, and deterministic replay after restart.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ATTRIBUTION_SPINE_EVENT_TYPE, AttributionError, AttributionLedger, CurrencyCode, ProjectId,
    SourceObservationBatch, TenantId,
};

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
        let payload = serde_json::to_value(batch)?;
        self.append_event(
            &batch.project_id,
            batch.mission_id.as_ref(),
            ATTRIBUTION_SPINE_EVENT_TYPE,
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
        for batch in self.attribution_observation_batches(project_id)? {
            ledger
                .ingest_batch(batch)
                .map_err(|error| domain_decode(&error))?;
        }
        ledger.validate().map_err(|error| domain_decode(&error))?;
        Ok(ledger)
    }
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
        CorrectionLineage, CurrencyCode, ObservationOrigin, ObservationProvenance, Project,
        ProjectId, ProviderCursor, ProviderEntityRef, ProviderEventIdentity, SourceEntityKind,
        SourceEvent, SourceEventId, SourceEventKind, SourceEventLinks, StorageMode, TenantId,
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

    #[test]
    fn observation_batches_survive_restart_and_replay_from_domain_events() {
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
        let batch = SourceObservationBatch {
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
    }
}

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Mission, MissionId, ProjectId, WORK_PRODUCT_ADOPTION_PLUGIN_ID,
    WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION, WorkProductAdoptionCommand,
    WorkProductAdoptionLifecycle, WorkProductAdoptionReceipt, WorkProductAdoptionScope,
    WorkProductAdoptionState, WorkProductHandoffSnapshot, WorkProductId, WorkProductManifest,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{AtomicMutation, PendingEvent, ProjectStore, StorageError};

const WORK_PRODUCT_ADOPTION_STATE_EVENT: &str = "work_product.adoption_plugin.state";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkProductAdoptionStateEvent {
    schema_version: u32,
    plugin_id: String,
    operation_id: String,
    operation_digest: String,
    work_product_id: WorkProductId,
    state: WorkProductAdoptionState,
}

impl ProjectStore {
    pub fn create_work_product_outcome_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        self.create_work_product_manifest_atomic(
            mission,
            expected_mission_revision,
            manifest,
            events,
        )
    }

    pub fn revise_work_product_outcome_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        expected_manifest_version: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        self.revise_work_product_manifest_atomic(
            mission,
            expected_mission_revision,
            manifest,
            expected_manifest_version,
            events,
        )
    }

    pub fn load_work_product_outcome_snapshot(
        &self,
        project_id: &ProjectId,
        work_product_id: &WorkProductId,
    ) -> Result<WorkProductHandoffSnapshot, StorageError> {
        let manifest = self.load_work_product_manifest(project_id, work_product_id)?;
        WorkProductHandoffSnapshot::from_preview(&manifest.preview)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))
    }

    pub fn load_work_product_outcome_mission(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Mission, StorageError> {
        self.load_mission(project_id, mission_id)
    }

    pub fn outbox_sequences_for_mission(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Vec<i64>, StorageError> {
        self.load_mission(project_id, mission_id)?;
        let mut statement = self.connection.prepare(
            "SELECT sequence FROM outbox_messages
             WHERE project_id = ?1 AND mission_id = ?2
             ORDER BY sequence ASC",
        )?;
        let rows = statement
            .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
                row.get::<_, i64>(0)
            })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn load_work_product_adoption_state(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        work_product_id: &WorkProductId,
    ) -> Result<Option<WorkProductAdoptionState>, StorageError> {
        let events = self.events_for_mission(project_id, mission_id)?;
        let mut state: Option<WorkProductAdoptionState> = None;
        for event in events {
            if event.event_type != WORK_PRODUCT_ADOPTION_STATE_EVENT {
                continue;
            }
            if event.project_id != *project_id || event.mission_id.as_ref() != Some(mission_id) {
                return Err(StorageError::DomainDecode(
                    "adoption plugin event scope does not match its Mission".into(),
                ));
            }
            let payload: WorkProductAdoptionStateEvent = serde_json::from_value(event.payload)
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
            if payload.schema_version != WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION
                || payload.plugin_id != WORK_PRODUCT_ADOPTION_PLUGIN_ID
            {
                return Err(StorageError::DomainDecode(
                    "adoption plugin event version or identity is invalid".into(),
                ));
            }
            payload
                .state
                .validate()
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
            let last_operation = payload.state.operations.last().ok_or_else(|| {
                StorageError::DomainDecode("adoption plugin state has no operation history".into())
            })?;
            if payload.work_product_id != payload.state.scope.work_product_id
                || payload.operation_id != last_operation.operation_id
                || payload.operation_digest != last_operation.operation_digest
            {
                return Err(StorageError::DomainDecode(
                    "adoption plugin event operation or Work Product scope is invalid".into(),
                ));
            }
            if payload.work_product_id != *work_product_id {
                continue;
            }
            if let Some(previous) = &state {
                if payload.state.operations.len() != previous.operations.len() + 1
                    || payload.state.operations[..previous.operations.len()]
                        != previous.operations[..]
                {
                    return Err(StorageError::DomainDecode(
                        "adoption plugin event history is not an append-only replay".into(),
                    ));
                }
                if payload.state.scope != previous.scope {
                    return Err(StorageError::DomainDecode(
                        "adoption plugin scope changed during replay".into(),
                    ));
                }
            }
            state = Some(payload.state);
        }
        Ok(state)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the atomic plugin journey keeps scope validation, idempotency, lifecycle transition, and Mission Event/Outbox CAS visibly together"
    )]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "a one-shot typed adoption command is consumed exactly once by the atomic transition"
    )]
    #[allow(clippy::type_complexity)]
    pub fn apply_work_product_adoption_atomic(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        work_product_id: &WorkProductId,
        expected_mission_revision: u64,
        command: WorkProductAdoptionCommand,
        now: DateTime<Utc>,
    ) -> Result<
        (
            WorkProductAdoptionState,
            Option<WorkProductAdoptionReceipt>,
            AtomicMutation,
            bool,
        ),
        StorageError,
    > {
        let mission = self.load_work_product_outcome_mission(project_id, mission_id)?;
        let snapshot = self.load_work_product_outcome_snapshot(project_id, work_product_id)?;
        let current =
            self.load_work_product_adoption_state(project_id, mission_id, work_product_id)?;
        verify_adoption_handoff(
            &mission,
            &snapshot,
            work_product_id,
            current.as_ref().map(|state| &state.scope),
            &command,
        )?;

        let operation_id = command.operation_id().to_owned();
        let operation_digest = command
            .operation_digest()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if let Some(state) = &current {
            if let Some(previous) = state.operation(&operation_id) {
                if previous.operation_digest != operation_digest {
                    return Err(StorageError::DomainDecode(
                        "adoption operation id was reused with a different digest".into(),
                    ));
                }
                let receipt = state.receipt_for_operation(&operation_id).cloned();
                return Ok((
                    state.clone(),
                    receipt,
                    AtomicMutation {
                        event_sequences: Vec::new(),
                        outbox_sequences: Vec::new(),
                        state_revision: mission.revision,
                    },
                    true,
                ));
            }
            if now < mission.updated_at
                || now
                    < state
                        .operations
                        .last()
                        .map_or(mission.updated_at, |operation| operation.occurred_at)
            {
                return Err(StorageError::DomainDecode(
                    "adoption operation time moved backwards".into(),
                ));
            }
        } else if now < mission.updated_at {
            return Err(StorageError::DomainDecode(
                "adoption operation time is older than the Mission state".into(),
            ));
        }

        let (next_state, receipt) = match (&current, command.clone()) {
            (None, WorkProductAdoptionCommand::Mount { service, mount }) => (
                WorkProductAdoptionState::initial(service, *mount, now)
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?,
                None,
            ),
            (Some(previous), WorkProductAdoptionCommand::Mount { service, mount }) => (
                previous
                    .remount(service, *mount, now)
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?,
                None,
            ),
            (Some(previous), WorkProductAdoptionCommand::Unmount { .. }) => (
                previous
                    .transition(WorkProductAdoptionLifecycle::Unmounted, &command, now)
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?,
                None,
            ),
            (Some(previous), WorkProductAdoptionCommand::Revoke { .. }) => (
                previous
                    .transition(WorkProductAdoptionLifecycle::Revoked, &command, now)
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?,
                None,
            ),
            (Some(previous), WorkProductAdoptionCommand::Crash { .. }) => (
                previous
                    .transition(WorkProductAdoptionLifecycle::Crashed, &command, now)
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?,
                None,
            ),
            (Some(previous), WorkProductAdoptionCommand::Adopt { .. }) => {
                let (state, receipt) = previous
                    .adopt(&command, now)
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
                (state, Some(receipt))
            }
            (None, _) => {
                return Err(StorageError::DomainDecode(
                    "adoption lifecycle operation requires a mounted plugin".into(),
                ));
            }
        };

        let mut next_mission = mission.clone();
        next_mission.revision = mission
            .revision
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow(mission.revision))?;
        next_mission.updated_at = now;
        let payload = WorkProductAdoptionStateEvent {
            schema_version: WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION,
            plugin_id: WORK_PRODUCT_ADOPTION_PLUGIN_ID.into(),
            operation_id,
            operation_digest,
            work_product_id: work_product_id.clone(),
            state: next_state.clone(),
        };
        let mutation = self.update_mission_atomic(
            &next_mission,
            expected_mission_revision,
            &[PendingEvent::new(
                WORK_PRODUCT_ADOPTION_STATE_EVENT,
                serde_json::to_value(payload)?,
                now,
            )],
        )?;
        Ok((next_state, receipt, mutation, false))
    }
}

fn verify_adoption_handoff(
    mission: &Mission,
    snapshot: &WorkProductHandoffSnapshot,
    work_product_id: &WorkProductId,
    existing_scope: Option<&WorkProductAdoptionScope>,
    command: &WorkProductAdoptionCommand,
) -> Result<(), StorageError> {
    if let WorkProductAdoptionCommand::Mount { service, mount } = command {
        let scope = match existing_scope {
            Some(scope) => {
                scope
                    .matches_verified_handoff(snapshot)
                    .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
                scope.clone()
            }
            None => WorkProductAdoptionScope::from_verified_handoff(
                snapshot,
                &mission.tenant_id,
                &mission.project_id,
                &mission.id,
                mission.revision,
                mount.scope.work_product_revision,
            )
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?,
        };
        mount
            .validate_for(service)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if mount.scope != scope || mount.scope.work_product_id != *work_product_id {
            return Err(StorageError::DomainDecode(
                "adoption mount is not bound to the exact verified handoff".into(),
            ));
        }
    } else {
        command
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if let Some(scope) = existing_scope {
            scope
                .matches_verified_handoff(snapshot)
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
            if scope.work_product_id != *work_product_id {
                return Err(StorageError::DomainDecode(
                    "adoption operation Work Product scope is invalid".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AdoptionDecision, AdoptionDecisionKind, MissionContract, OutcomeClassification,
        OutcomeLink, OutcomeVerificationKind, Project, ResultClassification, ResultPacket,
        StorageMode, Task, TaskId, TaskStatus, TenantId, WorkProduct, WorkProductAdoptionLifecycle,
        WorkProductDependencies, WorkProductManifest, WorkProductRevision,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::DatabaseKey;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 10, 0, 0)
            .single()
            .expect("valid time")
    }

    struct Fixture {
        directory: tempfile::TempDir,
        database: std::path::PathBuf,
        key: DatabaseKey,
        store: ProjectStore,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        mission_revision: u64,
        service: hartevo_domain_kernel::WorkProductAdoptionPluginService,
        mount: hartevo_domain_kernel::WorkProductAdoptionMountRequest,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture creates the exact persisted Project, Mission, handoff manifest, verified Outcome and plugin scope"
    )]
    fn fixture() -> Fixture {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("work-product-adoption.db");
        let key = DatabaseKey::new([7; 32]).expect("database key");
        let mut store = ProjectStore::open(&database, &key).expect("store");
        let project_id = ProjectId::from("project-adoption");
        let mission_id = MissionId::from("mission-adoption");
        let work_product_id = WorkProductId::from("work-product-adoption");
        let project = Project::create_local(
            TenantId::from("tenant-adoption"),
            project_id.clone(),
            "Adoption project",
            "",
            directory.path(),
            StorageMode::LocalExisting,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new(
                    "project.created",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("project event");
        let mut mission = Mission::compile(
            project.tenant_id.clone(),
            mission_id.clone(),
            project_id.clone(),
            "Adopt verified result",
            MissionContract::bootstrap(
                "Adopt a verified Work Product",
                ["research.read".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-adoption"),
                    title: "Verify result".into(),
                    status: TaskStatus::Running,
                    capability: "research.read".into(),
                }],
                now(),
            )
            .expect("research");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new(
                    "mission.started",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("mission event");

        let packet = ResultPacket::new(
            "packet-adoption",
            project.tenant_id.clone(),
            project_id.clone(),
            mission_id.clone(),
            mission.revision,
            "source://adoption",
            "runtime://adoption-turn",
            Some("provider://result".into()),
            "Verified result",
            "Result content is retained only by the handoff manifest",
            ResultClassification::ReadyForReview,
            Vec::new(),
            now(),
            now(),
        )
        .expect("packet");
        mission
            .record_work_product(
                WorkProduct::draft(
                    work_product_id.clone(),
                    packet.title.clone(),
                    packet.content.clone(),
                    BTreeSet::new(),
                ),
                now(),
            )
            .expect("work product");
        let revision = WorkProductRevision::from_packet(&packet, work_product_id.clone(), 1, now())
            .expect("revision");
        let mut snapshot =
            WorkProductHandoffSnapshot::new(packet.clone(), revision).expect("snapshot");
        snapshot
            .append_adoption_decision(
                AdoptionDecision::new(
                    "decision-adoption",
                    project.tenant_id.clone(),
                    project_id.clone(),
                    mission_id.clone(),
                    packet.mission_revision,
                    work_product_id.clone(),
                    1,
                    packet.packet_digest.clone(),
                    AdoptionDecisionKind::Adopt,
                    "independent verification is present",
                    now(),
                )
                .expect("decision"),
            )
            .expect("adoption decision");
        snapshot
            .append_outcome_link(
                OutcomeLink::new(
                    "outcome-adoption",
                    project.tenant_id.clone(),
                    project_id.clone(),
                    mission_id.clone(),
                    packet.mission_revision,
                    work_product_id.clone(),
                    1,
                    packet.packet_digest,
                    OutcomeVerificationKind::IndependentProvider,
                    "provider://independent",
                    "outcome://adoption",
                    OutcomeClassification::Positive,
                    "a".repeat(64),
                    "b".repeat(64),
                    now(),
                )
                .expect("outcome"),
            )
            .expect("outcome link");
        let product = mission.work_products.first().expect("product").clone();
        let manifest = WorkProductManifest::create(
            project.tenant_id.clone(),
            project_id.clone(),
            mission_id.clone(),
            &product,
            "result_work_product",
            WorkProductDependencies::default(),
            None,
            snapshot.to_preview().expect("preview"),
            BTreeSet::from(["/adoption".into()]),
            now(),
        )
        .expect("manifest");
        let expected_mission_revision = packet.mission_revision;
        store
            .create_work_product_outcome_atomic(
                &mission,
                expected_mission_revision,
                &manifest,
                &[PendingEvent::new(
                    "work_product.outcome.handoff.created",
                    serde_json::json!({"workProductId": work_product_id}),
                    now(),
                )],
            )
            .expect("handoff");
        let scope = hartevo_domain_kernel::WorkProductAdoptionScope::from_verified_handoff(
            &snapshot,
            &project.tenant_id,
            &project_id,
            &mission_id,
            mission.revision,
            1,
        )
        .expect("scope");
        let service = hartevo_domain_kernel::WorkProductAdoptionPluginService::new(
            "provider://adoption-plugin",
        )
        .expect("service");
        let mount = service
            .mount_request(
                scope,
                "mission-consumer-adoption",
                1,
                now() + Duration::seconds(1),
            )
            .expect("mount");
        let mission_revision = mission.revision;
        Fixture {
            directory,
            database,
            key,
            store,
            project_id,
            mission_id,
            work_product_id,
            mission_revision,
            service,
            mount,
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one ordered journey proves mount, adopt, replay, stale fencing, unmount, remount, crash, revoke, and reopen"
    )]
    fn adoption_lifecycle_is_atomic_replayable_and_restart_safe() {
        let mut fixture = fixture();
        let baseline = fixture
            .store
            .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
            .expect("baseline outbox");
        let mount_command =
            WorkProductAdoptionCommand::mount(fixture.service.clone(), fixture.mount.clone());
        let (mounted, receipt, mutation, replayed) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                fixture.mission_revision,
                mount_command.clone(),
                now() + Duration::seconds(1),
            )
            .expect("mount");
        assert!(!replayed);
        assert!(receipt.is_none());
        assert_eq!(mounted.lifecycle, WorkProductAdoptionLifecycle::Mounted);
        assert_eq!(mutation.event_sequences.len(), 1);
        assert_eq!(mutation.outbox_sequences.len(), 1);
        let after_mount = fixture
            .store
            .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
            .expect("mount outbox");
        assert_eq!(after_mount.len(), baseline.len() + 1);

        let (replayed_state, replayed_receipt, replayed_mutation, was_replayed) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                fixture.mission_revision,
                mount_command,
                now() + Duration::seconds(1),
            )
            .expect("mount replay");
        assert!(was_replayed);
        assert_eq!(replayed_state, mounted);
        assert!(replayed_receipt.is_none());
        assert!(replayed_mutation.event_sequences.is_empty());
        assert_eq!(
            fixture
                .store
                .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
                .expect("replay outbox"),
            after_mount
        );

        let adopt_command = WorkProductAdoptionCommand::adopt(
            "adopt-operation-1",
            fixture.service.service_digest.clone(),
            fixture.mount.mount_digest.clone(),
            fixture.mount.generation,
            fixture.mount.consumer_id.clone(),
            "adoption-receipt-1",
        );
        let (adopted, receipt, adopt_mutation, _) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                mutation.state_revision,
                adopt_command.clone(),
                now() + Duration::seconds(2),
            )
            .expect("adopt");
        assert_eq!(adopted.receipts.len(), 1);
        assert_eq!(receipt.expect("receipt").receipt_id, "adoption-receipt-1");
        assert_eq!(adopt_mutation.event_sequences.len(), 1);
        let after_adopt = fixture
            .store
            .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
            .expect("adopt outbox");
        let (_, replayed_receipt, replayed_adopt_mutation, was_replayed) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                mutation.state_revision,
                adopt_command,
                now() + Duration::seconds(2),
            )
            .expect("adopt replay");
        assert!(was_replayed);
        assert_eq!(
            replayed_receipt.expect("replayed receipt").receipt_id,
            "adoption-receipt-1"
        );
        assert!(replayed_adopt_mutation.event_sequences.is_empty());
        assert_eq!(
            fixture
                .store
                .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
                .expect("replay adoption outbox"),
            after_adopt
        );

        let stale_unmount = WorkProductAdoptionCommand::unmount(
            "stale-unmount",
            fixture.service.service_digest.clone(),
            fixture.mount.mount_digest.clone(),
            fixture.mount.generation,
        );
        assert!(
            fixture
                .store
                .apply_work_product_adoption_atomic(
                    &fixture.project_id,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                    mutation.state_revision,
                    stale_unmount,
                    now() + Duration::seconds(3),
                )
                .is_err()
        );
        assert_eq!(
            fixture
                .store
                .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
                .expect("stale outbox"),
            after_adopt
        );

        let unmount = WorkProductAdoptionCommand::unmount(
            "unmount-operation-1",
            fixture.service.service_digest.clone(),
            fixture.mount.mount_digest.clone(),
            fixture.mount.generation,
        );
        let (unmounted, _, unmount_mutation, _) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                adopt_mutation.state_revision,
                unmount,
                now() + Duration::seconds(3),
            )
            .expect("unmount");
        assert_eq!(unmounted.lifecycle, WorkProductAdoptionLifecycle::Unmounted);
        let old_consumer = WorkProductAdoptionCommand::adopt(
            "old-consumer-after-unmount",
            fixture.service.service_digest.clone(),
            fixture.mount.mount_digest.clone(),
            fixture.mount.generation,
            fixture.mount.consumer_id.clone(),
            "adoption-receipt-old",
        );
        assert!(
            fixture
                .store
                .apply_work_product_adoption_atomic(
                    &fixture.project_id,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                    unmount_mutation.state_revision,
                    old_consumer,
                    now() + Duration::seconds(4),
                )
                .is_err()
        );

        let scope = fixture.mount.scope.clone();
        let remount = fixture
            .service
            .mount_request(
                scope,
                "mission-consumer-adoption-new",
                2,
                now() + Duration::seconds(5),
            )
            .expect("remount");
        let remount_command =
            WorkProductAdoptionCommand::mount(fixture.service.clone(), remount.clone());
        let (remounted, _, remount_mutation, _) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                unmount_mutation.state_revision,
                remount_command,
                now() + Duration::seconds(5),
            )
            .expect("remount");
        assert_eq!(remounted.generation, 2);
        let stale_mount_consumer = WorkProductAdoptionCommand::adopt(
            "stale-mount-after-remount",
            fixture.service.service_digest.clone(),
            fixture.mount.mount_digest.clone(),
            fixture.mount.generation,
            fixture.mount.consumer_id.clone(),
            "adoption-receipt-stale",
        );
        assert!(
            fixture
                .store
                .apply_work_product_adoption_atomic(
                    &fixture.project_id,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                    remount_mutation.state_revision,
                    stale_mount_consumer,
                    now() + Duration::seconds(6),
                )
                .is_err()
        );

        let crash = WorkProductAdoptionCommand::crash(
            "crash-operation-2",
            fixture.service.service_digest.clone(),
            remount.mount_digest.clone(),
            remount.generation,
        );
        let (crashed, _, crash_mutation, _) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                remount_mutation.state_revision,
                crash,
                now() + Duration::seconds(7),
            )
            .expect("crash");
        assert_eq!(crashed.lifecycle, WorkProductAdoptionLifecycle::Crashed);
        let crashed_consumer = WorkProductAdoptionCommand::adopt(
            "consumer-after-crash",
            fixture.service.service_digest.clone(),
            remount.mount_digest.clone(),
            remount.generation,
            remount.consumer_id.clone(),
            "adoption-receipt-crashed",
        );
        assert!(
            fixture
                .store
                .apply_work_product_adoption_atomic(
                    &fixture.project_id,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                    crash_mutation.state_revision,
                    crashed_consumer,
                    now() + Duration::seconds(8),
                )
                .is_err()
        );

        let remount_after_crash = fixture
            .service
            .mount_request(
                fixture.mount.scope.clone(),
                "mission-consumer-adoption-final",
                3,
                now() + Duration::seconds(9),
            )
            .expect("remount after crash");
        let (mounted_again, _, mounted_again_mutation, _) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                crash_mutation.state_revision,
                WorkProductAdoptionCommand::mount(
                    fixture.service.clone(),
                    remount_after_crash.clone(),
                ),
                now() + Duration::seconds(9),
            )
            .expect("final mount");
        assert_eq!(mounted_again.generation, 3);
        let revoke = WorkProductAdoptionCommand::revoke(
            "revoke-operation-3",
            fixture.service.service_digest.clone(),
            remount_after_crash.mount_digest.clone(),
            remount_after_crash.generation,
        );
        let (revoked, _, revoke_mutation, _) = fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                mounted_again_mutation.state_revision,
                revoke,
                now() + Duration::seconds(10),
            )
            .expect("revoke");
        assert_eq!(revoked.lifecycle, WorkProductAdoptionLifecycle::Revoked);
        let revoked_consumer = WorkProductAdoptionCommand::adopt(
            "consumer-after-revoke",
            fixture.service.service_digest.clone(),
            remount_after_crash.mount_digest.clone(),
            remount_after_crash.generation,
            remount_after_crash.consumer_id.clone(),
            "adoption-receipt-revoked",
        );
        assert!(
            fixture
                .store
                .apply_work_product_adoption_atomic(
                    &fixture.project_id,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                    revoke_mutation.state_revision,
                    revoked_consumer,
                    now() + Duration::seconds(12),
                )
                .is_err()
        );
        let revoked_remount = fixture
            .service
            .mount_request(
                fixture.mount.scope.clone(),
                "mission-consumer-after-revoke",
                4,
                now() + Duration::seconds(11),
            )
            .expect("revoked mount request");
        assert!(
            fixture
                .store
                .apply_work_product_adoption_atomic(
                    &fixture.project_id,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                    revoke_mutation.state_revision,
                    WorkProductAdoptionCommand::mount(fixture.service.clone(), revoked_remount),
                    now() + Duration::seconds(11),
                )
                .is_err()
        );

        let outbox_before_reopen = fixture
            .store
            .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
            .expect("outbox before reopen");
        drop(fixture.store);
        let reopened = ProjectStore::open(&fixture.database, &fixture.key).expect("reopen");
        let state = reopened
            .load_work_product_adoption_state(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
            )
            .expect("replayed state")
            .expect("state");
        assert_eq!(state.lifecycle, WorkProductAdoptionLifecycle::Revoked);
        assert_eq!(state.receipts.len(), 1);
        assert_eq!(
            reopened
                .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
                .expect("outbox after reopen"),
            outbox_before_reopen
        );
        assert!(!fixture.directory.path().as_os_str().is_empty());
    }

    #[test]
    fn adoption_scope_swap_fails_closed_without_event_growth() {
        let mut fixture = fixture();
        let baseline = fixture
            .store
            .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
            .expect("baseline");
        let mut swapped = fixture.mount.clone();
        swapped.scope.project_id = ProjectId::from("project-swapped");
        assert!(
            fixture
                .store
                .apply_work_product_adoption_atomic(
                    &fixture.project_id,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                    fixture.mission_revision,
                    WorkProductAdoptionCommand::mount(fixture.service.clone(), swapped),
                    now() + Duration::seconds(1),
                )
                .is_err()
        );
        assert_eq!(
            fixture
                .store
                .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
                .expect("outbox after swap"),
            baseline
        );
        let other_project = ProjectId::from("project-other");
        assert!(
            fixture
                .store
                .apply_work_product_adoption_atomic(
                    &other_project,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                    fixture.mission_revision,
                    WorkProductAdoptionCommand::mount(
                        fixture.service.clone(),
                        fixture.mount.clone(),
                    ),
                    now() + Duration::seconds(1),
                )
                .is_err()
        );
        assert_eq!(
            fixture
                .store
                .outbox_sequences_for_mission(&fixture.project_id, &fixture.mission_id)
                .expect("outbox after cross-project"),
            baseline
        );
    }

    #[test]
    fn adoption_event_tamper_fails_closed_on_reopen() {
        let mut fixture = fixture();
        fixture
            .store
            .apply_work_product_adoption_atomic(
                &fixture.project_id,
                &fixture.mission_id,
                &fixture.work_product_id,
                fixture.mission_revision,
                WorkProductAdoptionCommand::mount(fixture.service.clone(), fixture.mount.clone()),
                now() + Duration::seconds(1),
            )
            .expect("mount");
        let payload_text: String = fixture
            .store
            .connection
            .query_row(
                "SELECT payload_json FROM domain_events WHERE event_type = ?1",
                rusqlite::params![WORK_PRODUCT_ADOPTION_STATE_EVENT],
                |row| row.get(0),
            )
            .expect("state event");
        let mut payload: serde_json::Value =
            serde_json::from_str(&payload_text).expect("payload json");
        payload["state"]["lifecycle"] = serde_json::json!("crashed");
        fixture
            .store
            .connection
            .execute(
                "UPDATE domain_events SET payload_json = ?1 WHERE event_type = ?2",
                rusqlite::params![payload.to_string(), WORK_PRODUCT_ADOPTION_STATE_EVENT],
            )
            .expect("tamper event");
        assert!(
            fixture
                .store
                .load_work_product_adoption_state(
                    &fixture.project_id,
                    &fixture.mission_id,
                    &fixture.work_product_id,
                )
                .is_err()
        );
    }
}

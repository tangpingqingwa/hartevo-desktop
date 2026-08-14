use std::process::Command;

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_cloud_storage::{
    CellScope, CloudDeviceSyncAttach, CloudDeviceSyncConsumer, CloudDeviceSyncDocumentMutation,
    CloudDeviceSyncProvider, CloudDeviceSyncRelease, CloudDeviceSyncReleaseKind,
    CloudDeviceSyncServiceDefinition, CloudProjectRegistration, CloudRemoteWorkerCompletion,
    CloudRemoteWorkerMissionFence, CloudRemoteWorkerServiceDefinition, CloudRemoteWorkerTask,
    CloudRemoteWorkerTransportConsumer, CloudRemoteWorkerTransportMount,
    CloudRemoteWorkerTransportProvider, CloudRemoteWorkerWorkCancel, CloudRemoteWorkerWorkClaim,
    CloudRemoteWorkerWorkHeartbeat, CloudRemoteWorkerWorkRequest, CloudRemoteWorkerWorkResult,
    CloudRemoteWorkerWorkStatus, CloudRemoteWorkerWorkUncertain, CloudStorageError, DataCell,
    EncryptedPayload, EncryptedSyncMutation, MutationPrecondition, POSTGRES_L2_URL_ENV,
    PostgresCellStore, SyncObjectKind,
};
use hartevo_domain_kernel::{
    ActorId, DeviceId, DevicePublicKeyRegistration, KeyEnvelope, KeyEnvelopeId, KeyRecipient,
    KeyWrapAlgorithm, MissionId, ProjectEncryptionMode, ProjectId, ProjectKeyring,
    ProjectKeyringBootstrap, TaskId, TenantId, WorkerId, WorkerLeaseId, WrappedKeyCiphertext,
};
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;

#[derive(Clone, Debug)]
struct ProcessLease {
    task_id: TaskId,
    lease_id: WorkerLeaseId,
    generation: u64,
    owner: String,
    token_digest: String,
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 13, 10, 0, 0)
        .single()
        .expect("valid integration timestamp")
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn sql_i64(value: u64) -> i64 {
    i64::try_from(value).expect("integration value fits PostgreSQL BIGINT")
}

fn payload(byte: u8) -> EncryptedPayload {
    let ciphertext = vec![byte; 48];
    EncryptedPayload {
        key_version: 1,
        nonce: vec![byte; 12],
        ciphertext: ciphertext.clone(),
        aad_digest: digest("aad"),
        content_digest: format!("{:x}", Sha256::digest(ciphertext)),
    }
}

fn key_envelope(
    scope: &CellScope,
    project_id: &ProjectId,
    id: &str,
    key_version: u64,
    recipient: KeyRecipient,
    created_at: DateTime<Utc>,
) -> KeyEnvelope {
    KeyEnvelope {
        id: KeyEnvelopeId::from_stable(id),
        tenant_id: scope.tenant_id.clone(),
        project_id: project_id.clone(),
        key_version,
        recipient,
        wrapping_key_reference_digest: digest("device-sync-wrapping-key"),
        sealed_key: WrappedKeyCiphertext {
            algorithm: KeyWrapAlgorithm::Aes256GcmV1,
            nonce: vec![2; 12],
            ciphertext: vec![3; 48],
            aad_digest: digest("device-sync-envelope-aad"),
        },
        created_at,
        expires_at: None,
        revoked_at: None,
    }
}

fn transport_mount(
    scope: &CellScope,
    project_id: &ProjectId,
    mission_id: &MissionId,
    dispatch_registration_id: String,
    worker_id: &WorkerId,
    idempotency_key_digest: String,
    mounted_at: DateTime<Utc>,
) -> CloudRemoteWorkerTransportMount {
    let service = CloudRemoteWorkerServiceDefinition::v1();
    CloudRemoteWorkerTransportMount {
        scope: scope.clone(),
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        plugin_id: "cloud-cell.remote-worker".into(),
        provider: CloudRemoteWorkerTransportProvider {
            provider_id: "cloud-cell.remote-worker.provider".into(),
            service_id: service.service_id.clone(),
            version: service.version,
            implementation_digest: digest("cloud-cell.remote-worker.provider.v1"),
        },
        consumer: CloudRemoteWorkerTransportConsumer {
            consumer_id: "mission.remote-worker.consumer".into(),
            service_id: service.service_id.clone(),
            min_service_version: service.version,
            descriptor_digest: digest("mission.remote-worker.consumer.v1"),
        },
        service,
        dispatch_registration_id,
        worker_id: worker_id.clone(),
        idempotency_key_digest,
        mounted_at,
    }
}

fn env_required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for this harness"))
}

async fn connect() -> (tokio_postgres::Client, tokio::task::JoinHandle<()>) {
    let (client, connection) = tokio_postgres::connect(&env_required(POSTGRES_L2_URL_ENV), NoTls)
        .await
        .expect("connect PostgreSQL integration database");
    let task = tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("integration PostgreSQL connection failed: {error}");
        }
    });
    (client, task)
}

async fn set_sql_scope(transaction: &tokio_postgres::Transaction<'_>, scope: &CellScope) {
    transaction
        .query_one(
            "SELECT set_config('hartevo.tenant_id', $1, true),
                    set_config('hartevo.cell', $2, true)",
            &[&scope.tenant_id.as_str(), &scope.cell.as_str()],
        )
        .await
        .expect("set SQL RLS scope");
}

fn spawn_process(mode: &str, variables: &[(&str, String)]) -> String {
    let binary = std::env::var("CARGO_BIN_EXE_cell_process_harness")
        .expect("Cargo must provide the cell process harness binary");
    let mut command = Command::new(binary);
    command.arg(mode);
    for (name, value) in variables {
        command.env(name, value);
    }
    let output = command.output().expect("spawn Cell process harness");
    assert!(
        output.status.success(),
        "Cell process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("Cell process output is UTF-8")
}

fn parse_claim(output: &str) -> (bool, ProcessLease) {
    let parts: Vec<&str> = output.trim().split('|').collect();
    assert_eq!(parts.len(), 9, "unexpected claim output: {output}");
    assert_eq!(parts[0], "CLAIM");
    (
        parts[1].parse().expect("claim duplicate flag"),
        ProcessLease {
            task_id: TaskId::from_stable(parts[2]),
            lease_id: WorkerLeaseId::from_stable(parts[3]),
            generation: parts[4].parse().expect("lease generation"),
            owner: parts[5].into(),
            token_digest: parts[6].into(),
        },
    )
}

fn assert_completion(output: &str, task_id: &TaskId, duplicate: bool) {
    let parts: Vec<&str> = output.trim().split('|').collect();
    assert_eq!(
        parts,
        ["COMPLETE", task_id.as_str(), &duplicate.to_string()]
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the PostgreSQL process harness keeps registration, sync CAS, device revocation, and lease recovery in one acceptance journey"
)]
async fn postgres_cell_two_process_sync_device_and_worker_recovery_contract() {
    let Some(database_url) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
        eprintln!(
            "NOT_RUN/BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; two-process Cell integration did not execute"
        );
        return;
    };
    let database_url = database_url
        .into_string()
        .expect("PostgreSQL test URL must be valid Unicode");
    let (mut client, _connection_task) = connect().await;
    let store = PostgresCellStore::new(DataCell::Us);
    let timestamp = now();
    store
        .migrate(&mut client, timestamp)
        .await
        .expect("migrate Cell schema");

    let scope = CellScope {
        cell: DataCell::Us,
        tenant_id: TenantId::new(),
    };
    let project_id = ProjectId::new();
    let metadata = payload(17);
    store
        .register_tenant(&mut client, &scope, timestamp)
        .await
        .expect("register tenant");
    store
        .create_project(
            &mut client,
            &CloudProjectRegistration {
                scope: scope.clone(),
                project_id: project_id.clone(),
                encryption_mode: ProjectEncryptionMode::TeamEnvelope,
                remote_execution_opt_in: true,
                metadata_digest: metadata.content_digest.clone(),
                initial_payload: metadata,
                idempotency_key_digest: digest("project-registration"),
                created_at: timestamp,
            },
        )
        .await
        .expect("create encrypted team project");

    let mission_id = MissionId::from("integration-mission");
    let worker_id = WorkerId::from("integration-worker");
    let initial_mount = transport_mount(
        &scope,
        &project_id,
        &mission_id,
        digest("remote-worker-dispatch-initial"),
        &worker_id,
        digest("remote-worker-transport-mount-initial"),
        timestamp + Duration::seconds(5),
    );
    let initial_mount_result = store
        .mount_remote_worker_transport(&mut client, &initial_mount)
        .await
        .expect("mount scoped Remote Worker transport plugin");
    assert!(!initial_mount_result.duplicate);
    let replayed_mount = store
        .mount_remote_worker_transport(&mut client, &initial_mount)
        .await
        .expect("replay scoped Remote Worker transport mount");
    assert!(replayed_mount.duplicate);
    assert_eq!(replayed_mount, initial_mount_result);
    let registration = store
        .load_remote_worker_transport_registration(
            &mut client,
            &scope,
            &project_id,
            &mission_id,
            &initial_mount_result.registration_id,
        )
        .await
        .expect("load mounted Remote Worker transport registration");
    assert_eq!(registration.project_id, project_id);
    assert_eq!(registration.mission_id, mission_id);
    assert_eq!(
        registration.dispatch_registration_id,
        initial_mount_result.dispatch_registration_id
    );
    assert_eq!(registration.worker_id, worker_id);
    assert_eq!(
        registration.state,
        hartevo_cloud_storage::CloudRemoteWorkerTransportRegistrationState::Mounted
    );

    let mission_object = "mission-sync-head";
    let create_sync = EncryptedSyncMutation {
        scope: scope.clone(),
        project_id: project_id.clone(),
        object_id: mission_object.into(),
        object_kind: SyncObjectKind::Mission,
        precondition: MutationPrecondition::CreateOnly,
        payload: payload(21),
        tombstone: false,
        idempotency_key_digest: digest("sync-create"),
        recorded_at: timestamp + Duration::seconds(1),
    };
    assert_eq!(
        store
            .apply_encrypted_mutation(&mut client, &create_sync)
            .await
            .expect("create encrypted sync head")
            .object_revision,
        1
    );
    let update_sync = EncryptedSyncMutation {
        precondition: MutationPrecondition::ExactRevision(1),
        payload: payload(22),
        idempotency_key_digest: digest("sync-update"),
        recorded_at: timestamp + Duration::seconds(2),
        ..create_sync.clone()
    };
    assert_eq!(
        store
            .apply_encrypted_mutation(&mut client, &update_sync)
            .await
            .expect("advance encrypted sync head")
            .object_revision,
        2
    );
    let stale_sync = EncryptedSyncMutation {
        payload: payload(23),
        idempotency_key_digest: digest("sync-stale"),
        recorded_at: timestamp + Duration::seconds(3),
        ..create_sync
    };
    assert!(matches!(
        store
            .apply_encrypted_mutation(&mut client, &stale_sync)
            .await,
        Err(CloudStorageError::OptimisticConflict {
            actual: Some(2),
            ..
        })
    ));
    assert_eq!(
        store
            .load_encrypted_object(&mut client, &scope, &project_id, mission_object)
            .await
            .expect("load encrypted sync head")
            .revision,
        2
    );

    let sync_inspection = client
        .transaction()
        .await
        .expect("start encrypted SyncDocument head inspection");
    set_sql_scope(&sync_inspection, &scope).await;
    let sync_head = sync_inspection
        .query_one(
            "SELECT h.current_revision, h.object_kind, h.key_version,
                    h.content_digest, h.tombstone, v.ciphertext
             FROM hartevo_cell.sync_object_heads h
             JOIN hartevo_cell.sync_object_versions v
               ON v.cell = h.cell AND v.tenant_id = h.tenant_id
              AND v.project_id = h.project_id AND v.object_id = h.object_id
              AND v.revision = h.current_revision
             WHERE h.cell = $1 AND h.tenant_id = $2 AND h.project_id = $3
               AND h.object_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &mission_object,
            ],
        )
        .await
        .expect("read encrypted SyncDocument head from PostgreSQL");
    assert_eq!(sync_head.get::<_, i64>(0), 2);
    assert_eq!(
        sync_head.get::<_, String>(1),
        SyncObjectKind::Mission.as_str()
    );
    assert_eq!(
        sync_head.get::<_, i64>(2),
        sql_i64(update_sync.payload.key_version)
    );
    assert_eq!(
        sync_head.get::<_, String>(3),
        update_sync.payload.content_digest
    );
    assert!(!sync_head.get::<_, bool>(4));
    assert_eq!(
        sync_head.get::<_, Vec<u8>>(5),
        update_sync.payload.ciphertext
    );
    let sync_versions: i64 = sync_inspection
        .query_one(
            "SELECT count(*)
             FROM hartevo_cell.sync_object_versions
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND object_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &mission_object,
            ],
        )
        .await
        .expect("count encrypted SyncDocument versions")
        .get(0);
    assert_eq!(sync_versions, 2);
    sync_inspection
        .commit()
        .await
        .expect("finish encrypted SyncDocument head inspection");
    let tampered_sync_digest = "0".repeat(64);
    let tamper_sync_head = client
        .transaction()
        .await
        .expect("start SyncDocument head tamper fixture");
    set_sql_scope(&tamper_sync_head, &scope).await;
    tamper_sync_head
        .execute(
            "UPDATE hartevo_cell.sync_object_heads
             SET content_digest = $5
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND object_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &mission_object,
                &tampered_sync_digest,
            ],
        )
        .await
        .expect("tamper SyncDocument head digest in fixture");
    tamper_sync_head
        .commit()
        .await
        .expect("commit SyncDocument head tamper fixture");
    assert!(matches!(
        store
            .load_encrypted_object(&mut client, &scope, &project_id, mission_object)
            .await,
        Err(CloudStorageError::StoredValueInvalid(_))
    ));
    let repair_sync_head = client
        .transaction()
        .await
        .expect("start SyncDocument head repair fixture");
    set_sql_scope(&repair_sync_head, &scope).await;
    repair_sync_head
        .execute(
            "UPDATE hartevo_cell.sync_object_heads
             SET content_digest = $5
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND object_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &mission_object,
                &update_sync.payload.content_digest,
            ],
        )
        .await
        .expect("repair SyncDocument head digest fixture");
    repair_sync_head
        .commit()
        .await
        .expect("commit SyncDocument head repair fixture");

    let device = DevicePublicKeyRegistration::register(
        scope.tenant_id.clone(),
        project_id.clone(),
        DeviceId::from("integration-device"),
        vec![7; 32],
        ActorId::from("integration-actor"),
        digest("device-attach-evidence"),
        digest("device-attach"),
        timestamp + Duration::seconds(4),
    )
    .expect("prepare device attachment");
    store
        .publish_device_public_key(&mut client, &scope, &device)
        .await
        .expect("attach device public key");
    let revoked_device = device
        .revoke(
            1,
            ActorId::from("integration-actor"),
            digest("device-revoke-evidence"),
            digest("device-revoke"),
            timestamp + Duration::seconds(5),
        )
        .expect("prepare device revocation");
    store
        .publish_device_public_key(&mut client, &scope, &revoked_device)
        .await
        .expect("revoke device public key");
    assert_eq!(
        store
            .load_device_public_key(
                &mut client,
                &scope,
                &project_id,
                &DeviceId::from("integration-device")
            )
            .await
            .expect("load revoked device key")
            .revoked_at,
        Some(timestamp + Duration::seconds(5))
    );
    let mut stale_device = device.clone();
    stale_device.idempotency_key_digest = digest("device-stale-after-revoke");
    assert!(matches!(
        store
            .publish_device_public_key(&mut client, &scope, &stale_device)
            .await,
        Err(CloudStorageError::InvalidDevicePublicKeyTransition)
    ));
    let device_inspection = client
        .transaction()
        .await
        .expect("start device revoke fence inspection");
    set_sql_scope(&device_inspection, &scope).await;
    let device_head = device_inspection
        .query_one(
            "SELECT current_revision, revoked_at
             FROM hartevo_cell.device_public_key_heads
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND device_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &"integration-device",
            ],
        )
        .await
        .expect("read device revoke fence head");
    assert_eq!(device_head.get::<_, i64>(0), 2);
    assert_eq!(
        device_head.get::<_, Option<DateTime<Utc>>>(1),
        Some(timestamp + Duration::seconds(5))
    );
    let device_versions: i64 = device_inspection
        .query_one(
            "SELECT count(*)
             FROM hartevo_cell.device_public_key_versions
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND device_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &"integration-device",
            ],
        )
        .await
        .expect("count device key revisions")
        .get(0);
    assert_eq!(device_versions, 2);
    device_inspection
        .commit()
        .await
        .expect("finish device revoke fence inspection");
    let tamper_device_head = client
        .transaction()
        .await
        .expect("start device revoke head tamper fixture");
    set_sql_scope(&tamper_device_head, &scope).await;
    tamper_device_head
        .execute(
            "UPDATE hartevo_cell.device_public_key_heads
             SET revoked_at = NULL
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND device_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &"integration-device",
            ],
        )
        .await
        .expect("tamper device revoke head fixture");
    tamper_device_head
        .commit()
        .await
        .expect("commit device revoke head tamper fixture");
    assert!(matches!(
        store
            .load_device_public_key(
                &mut client,
                &scope,
                &project_id,
                &DeviceId::from("integration-device")
            )
            .await,
        Err(CloudStorageError::StoredValueInvalid(_))
    ));
    let repair_device_head = client
        .transaction()
        .await
        .expect("start device revoke head repair fixture");
    set_sql_scope(&repair_device_head, &scope).await;
    repair_device_head
        .execute(
            "UPDATE hartevo_cell.device_public_key_heads
             SET revoked_at = $5
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND device_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &"integration-device",
                &(timestamp + Duration::seconds(5)),
            ],
        )
        .await
        .expect("repair device revoke head fixture");
    repair_device_head
        .commit()
        .await
        .expect("commit device revoke head repair fixture");

    let first_task = CloudRemoteWorkerTask {
        scope: scope.clone(),
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        task_id: TaskId::from("worker-task-complete"),
        worker_id: worker_id.clone(),
        dispatch_registration_id: initial_mount_result.dispatch_registration_id.clone(),
        payload: payload(31),
        idempotency_key_digest: digest("worker-task-complete"),
        enqueued_at: timestamp + Duration::seconds(6),
        deadline_at: timestamp + Duration::hours(1),
    };
    let recovery_task = CloudRemoteWorkerTask {
        task_id: TaskId::from("worker-task-recover"),
        payload: payload(32),
        idempotency_key_digest: digest("worker-task-recover"),
        ..first_task.clone()
    };
    let race_worker = worker_id.clone();
    let race_task = CloudRemoteWorkerTask {
        worker_id: race_worker.clone(),
        task_id: TaskId::from("worker-task-race"),
        payload: payload(33),
        idempotency_key_digest: digest("worker-task-race"),
        enqueued_at: timestamp + Duration::seconds(5),
        ..first_task.clone()
    };
    store
        .enqueue_remote_worker_task(&mut client, &first_task)
        .await
        .expect("enqueue first encrypted Worker task");
    store
        .enqueue_remote_worker_task(&mut client, &recovery_task)
        .await
        .expect("enqueue recovery Worker task");
    store
        .enqueue_remote_worker_task(&mut client, &race_task)
        .await
        .expect("enqueue claim-race Worker task");

    let wrong_mission = MissionId::from("wrong-mission");
    assert!(matches!(
        store
            .claim_remote_worker_task(
                &mut client,
                &scope,
                &project_id,
                &wrong_mission,
                &initial_mount_result.dispatch_registration_id,
                &worker_id,
                "wrong-mission-process",
                &digest("wrong-mission-token"),
                &digest("wrong-mission-claim"),
                timestamp + Duration::seconds(9),
                Duration::seconds(60),
            )
            .await,
        Err(CloudStorageError::RemoteWorkerDispatchNotRegistered)
    ));

    let (mut race_client_a, _race_connection_a) = connect().await;
    let (mut race_client_b, _race_connection_b) = connect().await;
    let race_token_a = digest("race-token-a");
    let race_claim_key_a = digest("race-claim-a");
    let race_token_b = digest("race-token-b");
    let race_claim_key_b = digest("race-claim-b");
    let (race_claim_a, race_claim_b) = tokio::join!(
        store.claim_remote_worker_task(
            &mut race_client_a,
            &scope,
            &project_id,
            &mission_id,
            &initial_mount_result.dispatch_registration_id,
            &race_worker,
            "race-process-a",
            &race_token_a,
            &race_claim_key_a,
            timestamp + Duration::seconds(10),
            Duration::seconds(60),
        ),
        store.claim_remote_worker_task(
            &mut race_client_b,
            &scope,
            &project_id,
            &mission_id,
            &initial_mount_result.dispatch_registration_id,
            &race_worker,
            "race-process-b",
            &race_token_b,
            &race_claim_key_b,
            timestamp + Duration::seconds(10),
            Duration::seconds(60),
        )
    );
    let race_claim_a = race_claim_a
        .expect("first concurrent Worker claim")
        .map(|result| result.lease);
    let race_claim_b = race_claim_b
        .expect("second concurrent Worker claim")
        .map(|result| result.lease);
    let race_lease = match (race_claim_a, race_claim_b) {
        (Some(lease), None) | (None, Some(lease)) => lease,
        (left, right) => {
            panic!("exactly one concurrent claim must win, left={left:?}, right={right:?}")
        }
    };
    assert_eq!(race_lease.task_id, race_task.task_id);
    assert_eq!(race_lease.lease_generation, 1);
    let race_heartbeat = store
        .heartbeat_remote_worker_task(
            &mut client,
            &scope,
            &project_id,
            &race_lease.task_id,
            &race_lease.lease_id,
            race_lease.lease_generation,
            &race_lease.lease_owner,
            &race_lease.lease_token_digest,
            timestamp + Duration::seconds(15),
            Duration::seconds(60),
        )
        .await
        .expect("heartbeat winning concurrent Worker claim");
    assert_eq!(
        race_heartbeat.heartbeat_at,
        timestamp + Duration::seconds(15)
    );
    let race_completion = CloudRemoteWorkerCompletion {
        scope: scope.clone(),
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        task_id: race_lease.task_id.clone(),
        dispatch_registration_id: initial_mount_result.dispatch_registration_id.clone(),
        lease_id: race_lease.lease_id,
        lease_generation: race_lease.lease_generation,
        lease_owner: race_lease.lease_owner.clone(),
        lease_token_digest: race_lease.lease_token_digest.clone(),
        result_digest: digest("race-result"),
        idempotency_key_digest: digest("race-completion"),
        completed_at: timestamp + Duration::seconds(20),
    };
    assert!(
        !store
            .complete_remote_worker_task(&mut client, &race_completion)
            .await
            .expect("complete winning concurrent Worker claim")
            .duplicate
    );

    let common = vec![
        (POSTGRES_L2_URL_ENV, database_url.clone()),
        ("HARTEVO_CELL_TENANT", scope.tenant_id.as_str().into()),
        ("HARTEVO_CELL_PROJECT", project_id.as_str().into()),
        ("HARTEVO_CELL_MISSION", mission_id.as_str().into()),
        (
            "HARTEVO_CELL_DISPATCH_REGISTRATION",
            initial_mount_result.dispatch_registration_id.clone(),
        ),
        ("HARTEVO_CELL_WORKER", worker_id.as_str().into()),
    ];
    let mut first_claim_variables = common.clone();
    first_claim_variables.extend([
        ("HARTEVO_CELL_LEASE_OWNER", "process-a".into()),
        ("HARTEVO_CELL_LEASE_TOKEN_DIGEST", digest("process-a-token")),
        ("HARTEVO_CELL_CLAIM_KEY", digest("claim-first")),
        (
            "HARTEVO_CELL_NOW",
            (timestamp + Duration::seconds(10)).to_rfc3339(),
        ),
        ("HARTEVO_CELL_LEASE_SECONDS", "60".into()),
    ]);
    let first_claim_output = spawn_process("claim", &first_claim_variables);
    let (first_duplicate, first_lease) = parse_claim(&first_claim_output);
    assert!(!first_duplicate);
    assert_eq!(first_lease.task_id, first_task.task_id);
    let refreshed_lease = store
        .heartbeat_remote_worker_task(
            &mut client,
            &scope,
            &project_id,
            &first_lease.task_id,
            &first_lease.lease_id,
            first_lease.generation,
            &first_lease.owner,
            &first_lease.token_digest,
            timestamp + Duration::seconds(15),
            Duration::seconds(60),
        )
        .await
        .expect("heartbeat active Worker lease");
    assert_eq!(
        refreshed_lease.heartbeat_at,
        timestamp + Duration::seconds(15)
    );

    let mut first_complete_variables = common.clone();
    first_complete_variables.extend([
        ("HARTEVO_CELL_TASK", first_lease.task_id.as_str().into()),
        (
            "HARTEVO_CELL_LEASE_ID",
            first_lease.lease_id.as_str().into(),
        ),
        (
            "HARTEVO_CELL_LEASE_GENERATION",
            first_lease.generation.to_string(),
        ),
        ("HARTEVO_CELL_LEASE_OWNER", first_lease.owner.clone()),
        (
            "HARTEVO_CELL_LEASE_TOKEN_DIGEST",
            first_lease.token_digest.clone(),
        ),
        ("HARTEVO_CELL_RESULT_DIGEST", digest("first-result")),
        ("HARTEVO_CELL_COMPLETION_KEY", digest("complete-first")),
        (
            "HARTEVO_CELL_NOW",
            (timestamp + Duration::seconds(20)).to_rfc3339(),
        ),
    ]);
    assert_completion(
        &spawn_process("complete", &first_complete_variables),
        &first_task.task_id,
        false,
    );
    assert_completion(
        &spawn_process("complete", &first_complete_variables),
        &first_task.task_id,
        true,
    );

    let mut recovery_claim_variables = common.clone();
    recovery_claim_variables.extend([
        ("HARTEVO_CELL_LEASE_OWNER", "process-old".into()),
        ("HARTEVO_CELL_LEASE_TOKEN_DIGEST", digest("old-token")),
        ("HARTEVO_CELL_CLAIM_KEY", digest("claim-recovery-old")),
        (
            "HARTEVO_CELL_NOW",
            (timestamp + Duration::seconds(30)).to_rfc3339(),
        ),
        ("HARTEVO_CELL_LEASE_SECONDS", "1".into()),
    ]);
    let old_claim_output = spawn_process("claim", &recovery_claim_variables);
    let (old_duplicate, old_lease) = parse_claim(&old_claim_output);
    assert!(!old_duplicate);
    assert_eq!(old_lease.task_id, recovery_task.task_id);

    let mut recovered_claim_variables = common.clone();
    recovered_claim_variables.extend([
        ("HARTEVO_CELL_LEASE_OWNER", "process-recovered".into()),
        ("HARTEVO_CELL_LEASE_TOKEN_DIGEST", digest("recovered-token")),
        ("HARTEVO_CELL_CLAIM_KEY", digest("claim-recovery-new")),
        (
            "HARTEVO_CELL_NOW",
            (timestamp + Duration::seconds(32)).to_rfc3339(),
        ),
        ("HARTEVO_CELL_LEASE_SECONDS", "60".into()),
    ]);
    let recovered_claim_output = spawn_process("claim", &recovered_claim_variables);
    let (recovered_duplicate, recovered_lease) = parse_claim(&recovered_claim_output);
    assert!(!recovered_duplicate);
    assert_eq!(recovered_lease.task_id, recovery_task.task_id);
    assert_ne!(recovered_lease.generation, old_lease.generation);
    let (replayed_duplicate, replayed_lease) =
        parse_claim(&spawn_process("claim", &recovery_claim_variables));
    assert!(replayed_duplicate);
    assert_eq!(replayed_lease.lease_id, old_lease.lease_id);
    assert_eq!(replayed_lease.generation, old_lease.generation);

    assert!(matches!(
        store
            .heartbeat_remote_worker_task(
                &mut client,
                &scope,
                &project_id,
                &old_lease.task_id,
                &old_lease.lease_id,
                old_lease.generation,
                &old_lease.owner,
                &old_lease.token_digest,
                timestamp + Duration::seconds(33),
                Duration::seconds(60),
            )
            .await,
        Err(CloudStorageError::RemoteWorkerLeaseLost)
    ));
    let stale_completion = CloudRemoteWorkerCompletion {
        scope: scope.clone(),
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        task_id: old_lease.task_id.clone(),
        dispatch_registration_id: initial_mount_result.dispatch_registration_id.clone(),
        lease_id: old_lease.lease_id,
        lease_generation: old_lease.generation,
        lease_owner: old_lease.owner.clone(),
        lease_token_digest: old_lease.token_digest.clone(),
        result_digest: digest("stale-result"),
        idempotency_key_digest: digest("stale-completion"),
        completed_at: timestamp + Duration::seconds(33),
    };
    assert!(matches!(
        store
            .complete_remote_worker_task(&mut client, &stale_completion)
            .await,
        Err(CloudStorageError::RemoteWorkerLeaseLost)
    ));

    let mut recovered_complete_variables = common;
    recovered_complete_variables.extend([
        ("HARTEVO_CELL_TASK", recovered_lease.task_id.as_str().into()),
        (
            "HARTEVO_CELL_LEASE_ID",
            recovered_lease.lease_id.as_str().into(),
        ),
        (
            "HARTEVO_CELL_LEASE_GENERATION",
            recovered_lease.generation.to_string(),
        ),
        ("HARTEVO_CELL_LEASE_OWNER", recovered_lease.owner.clone()),
        (
            "HARTEVO_CELL_LEASE_TOKEN_DIGEST",
            recovered_lease.token_digest.clone(),
        ),
        ("HARTEVO_CELL_RESULT_DIGEST", digest("recovered-result")),
        ("HARTEVO_CELL_COMPLETION_KEY", digest("complete-recovery")),
        (
            "HARTEVO_CELL_NOW",
            (timestamp + Duration::seconds(34)).to_rfc3339(),
        ),
    ]);
    assert_completion(
        &spawn_process("complete", &recovered_complete_variables),
        &recovery_task.task_id,
        false,
    );

    let record = store
        .load_remote_worker_task(&mut client, &scope, &project_id, &recovery_task.task_id)
        .await
        .expect("load recovered completed task");
    assert_eq!(
        record.status,
        hartevo_cloud_storage::CloudRemoteWorkerTaskStatus::Completed
    );
    assert_eq!(record.result_digest, Some(digest("recovered-result")));

    let marker = b"PLAINTEXT-MISSION-CONTENT";
    let worker_inspection = client
        .transaction()
        .await
        .expect("start scoped Worker recovery inspection");
    set_sql_scope(&worker_inspection, &scope).await;
    let recovery_row = worker_inspection
        .query_one(
            "SELECT status, attempts, lease_generation, lease_id, lease_owner,
                    lease_token_digest, lease_expires_at, heartbeat_at,
                    result_digest, completed_at, payload_ciphertext
             FROM hartevo_cell.remote_worker_mailbox_messages
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &recovery_task.task_id.as_str(),
            ],
        )
        .await
        .expect("read recovered Worker mailbox state");
    assert_eq!(recovery_row.get::<_, String>(0), "completed");
    assert_eq!(recovery_row.get::<_, i32>(1), 2);
    assert_eq!(
        recovery_row.get::<_, i64>(2),
        sql_i64(recovered_lease.generation)
    );
    assert!(recovery_row.get::<_, Option<String>>(3).is_none());
    assert!(recovery_row.get::<_, Option<String>>(4).is_none());
    assert!(recovery_row.get::<_, Option<String>>(5).is_none());
    assert!(recovery_row.get::<_, Option<DateTime<Utc>>>(6).is_none());
    assert!(recovery_row.get::<_, Option<DateTime<Utc>>>(7).is_none());
    assert_eq!(
        recovery_row.get::<_, Option<String>>(8),
        Some(digest("recovered-result"))
    );
    assert_eq!(
        recovery_row.get::<_, Option<DateTime<Utc>>>(9),
        Some(timestamp + Duration::seconds(34))
    );
    let raw_ciphertext: Vec<u8> = recovery_row.get(10);
    assert_eq!(raw_ciphertext, recovery_task.payload.ciphertext);
    assert!(
        !raw_ciphertext
            .windows(marker.len())
            .any(|window| window == marker)
    );

    let claim_rows = worker_inspection
        .query(
            "SELECT lease_generation, lease_owner, lease_token_digest,
                    heartbeat_at, lease_expires_at
             FROM hartevo_cell.remote_worker_claims
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4
             ORDER BY lease_generation",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &recovery_task.task_id.as_str(),
            ],
        )
        .await
        .expect("read immutable Worker claim history");
    assert_eq!(claim_rows.len(), 2);
    assert_eq!(
        claim_rows[0].get::<_, i64>(0),
        sql_i64(old_lease.generation)
    );
    assert_eq!(claim_rows[0].get::<_, String>(1), old_lease.owner);
    assert_eq!(claim_rows[0].get::<_, String>(2), old_lease.token_digest);
    assert_eq!(
        claim_rows[0].get::<_, DateTime<Utc>>(3),
        timestamp + Duration::seconds(30)
    );
    assert_eq!(
        claim_rows[0].get::<_, DateTime<Utc>>(4),
        timestamp + Duration::seconds(31)
    );
    assert_eq!(
        claim_rows[1].get::<_, i64>(0),
        sql_i64(recovered_lease.generation)
    );
    assert_eq!(claim_rows[1].get::<_, String>(1), recovered_lease.owner);
    assert_eq!(
        claim_rows[1].get::<_, String>(2),
        recovered_lease.token_digest
    );
    assert_eq!(
        claim_rows[1].get::<_, DateTime<Utc>>(3),
        timestamp + Duration::seconds(32)
    );
    assert_eq!(
        claim_rows[1].get::<_, DateTime<Utc>>(4),
        timestamp + Duration::seconds(32) + Duration::seconds(60)
    );
    worker_inspection
        .commit()
        .await
        .expect("finish scoped Worker recovery inspection");

    let cleanup_task = CloudRemoteWorkerTask {
        task_id: TaskId::from("worker-task-unmount-cleanup"),
        payload: payload(34),
        idempotency_key_digest: digest("worker-task-unmount-cleanup"),
        enqueued_at: timestamp + Duration::seconds(40),
        ..first_task.clone()
    };
    store
        .enqueue_remote_worker_task(&mut client, &cleanup_task)
        .await
        .expect("enqueue task for transport unmount cleanup");
    let cleanup_lease = store
        .claim_remote_worker_task(
            &mut client,
            &scope,
            &project_id,
            &mission_id,
            &initial_mount_result.dispatch_registration_id,
            &worker_id,
            "unmount-cleanup-worker",
            &digest("unmount-cleanup-token"),
            &digest("unmount-cleanup-claim"),
            timestamp + Duration::seconds(41),
            Duration::seconds(60),
        )
        .await
        .expect("claim task before transport unmount")
        .expect("task available before transport unmount")
        .lease;
    let unmount = store
        .unmount_remote_worker_transport(
            &mut client,
            &scope,
            &project_id,
            &mission_id,
            &initial_mount_result.registration_id,
            timestamp + Duration::seconds(42),
        )
        .await
        .expect("unmount Remote Worker transport");
    assert!(!unmount.duplicate);
    assert_eq!(unmount.mailbox_rows_cleaned, 1);
    assert_eq!(unmount.leases_cleared, 1);
    assert_eq!(unmount.dispatch_registrations_removed, 1);
    assert_eq!(
        unmount.state,
        hartevo_cloud_storage::CloudRemoteWorkerTransportRegistrationState::Unmounted
    );
    assert!(matches!(
        store
            .heartbeat_remote_worker_task(
                &mut client,
                &scope,
                &project_id,
                &cleanup_lease.task_id,
                &cleanup_lease.lease_id,
                cleanup_lease.lease_generation,
                &cleanup_lease.lease_owner,
                &cleanup_lease.lease_token_digest,
                timestamp + Duration::seconds(43),
                Duration::seconds(60),
            )
            .await,
        Err(CloudStorageError::RemoteWorkerDispatchNotRegistered)
    ));
    let stale_cleanup_completion = CloudRemoteWorkerCompletion {
        scope: scope.clone(),
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        task_id: cleanup_lease.task_id.clone(),
        dispatch_registration_id: initial_mount_result.dispatch_registration_id.clone(),
        lease_id: cleanup_lease.lease_id.clone(),
        lease_generation: cleanup_lease.lease_generation,
        lease_owner: cleanup_lease.lease_owner.clone(),
        lease_token_digest: cleanup_lease.lease_token_digest.clone(),
        result_digest: digest("unmount-cleanup-result"),
        idempotency_key_digest: digest("unmount-cleanup-completion"),
        completed_at: timestamp + Duration::seconds(43),
    };
    assert!(matches!(
        store
            .complete_remote_worker_task(&mut client, &stale_cleanup_completion)
            .await,
        Err(CloudStorageError::RemoteWorkerDispatchNotRegistered)
    ));
    let unmount_inspection = client
        .transaction()
        .await
        .expect("start transport unmount cleanup inspection");
    set_sql_scope(&unmount_inspection, &scope).await;
    let cleanup_row = unmount_inspection
        .query_one(
            "SELECT status, lease_generation, lease_id, lease_owner,
                    lease_token_digest, lease_expires_at, heartbeat_at
             FROM hartevo_cell.remote_worker_mailbox_messages
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &cleanup_task.task_id.as_str(),
            ],
        )
        .await
        .expect("read unmounted Worker mailbox cleanup");
    assert_eq!(cleanup_row.get::<_, String>(0), "pending");
    assert_eq!(cleanup_row.get::<_, i64>(1), 0);
    assert!(cleanup_row.get::<_, Option<String>>(2).is_none());
    assert!(cleanup_row.get::<_, Option<String>>(3).is_none());
    assert!(cleanup_row.get::<_, Option<String>>(4).is_none());
    assert!(cleanup_row.get::<_, Option<DateTime<Utc>>>(5).is_none());
    assert!(cleanup_row.get::<_, Option<DateTime<Utc>>>(6).is_none());
    let cleanup_claim_count: i64 = unmount_inspection
        .query_one(
            "SELECT count(*)
             FROM hartevo_cell.remote_worker_claims
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &cleanup_task.task_id.as_str(),
            ],
        )
        .await
        .expect("read immutable unmount claim history")
        .get(0);
    assert_eq!(cleanup_claim_count, 1);
    let active_dispatch_count: i64 = unmount_inspection
        .query_one(
            "SELECT count(*)
             FROM hartevo_cell.remote_worker_dispatch_registrations
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND mission_id = $4 AND registration_id = $5",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &mission_id.as_str(),
                &initial_mount_result.registration_id,
            ],
        )
        .await
        .expect("read removed unmount dispatch registration")
        .get(0);
    assert_eq!(active_dispatch_count, 0);
    unmount_inspection
        .commit()
        .await
        .expect("finish transport unmount cleanup inspection");

    let revoked_mount = transport_mount(
        &scope,
        &project_id,
        &mission_id,
        digest("remote-worker-dispatch-revoked"),
        &worker_id,
        digest("remote-worker-transport-mount-revoked"),
        timestamp + Duration::seconds(50),
    );
    let revoked_mount_result = store
        .mount_remote_worker_transport(&mut client, &revoked_mount)
        .await
        .expect("remount Remote Worker transport after unmount");
    let revoke_task = CloudRemoteWorkerTask {
        task_id: TaskId::from("worker-task-revoke-cleanup"),
        dispatch_registration_id: revoked_mount_result.dispatch_registration_id.clone(),
        payload: payload(35),
        idempotency_key_digest: digest("worker-task-revoke-cleanup"),
        enqueued_at: timestamp + Duration::seconds(51),
        ..first_task.clone()
    };
    store
        .enqueue_remote_worker_task(&mut client, &revoke_task)
        .await
        .expect("enqueue task for transport revoke cleanup");
    let revoke_lease = store
        .claim_remote_worker_task(
            &mut client,
            &scope,
            &project_id,
            &mission_id,
            &revoked_mount_result.dispatch_registration_id,
            &worker_id,
            "revoke-cleanup-worker",
            &digest("revoke-cleanup-token"),
            &digest("revoke-cleanup-claim"),
            timestamp + Duration::seconds(52),
            Duration::seconds(60),
        )
        .await
        .expect("claim task before transport revoke")
        .expect("task available before transport revoke")
        .lease;
    let revoke = store
        .revoke_remote_worker_transport(
            &mut client,
            &scope,
            &project_id,
            &mission_id,
            &revoked_mount_result.registration_id,
            &digest("remote-worker-revocation-reason"),
            timestamp + Duration::seconds(53),
        )
        .await
        .expect("revoke Remote Worker transport");
    assert!(!revoke.duplicate);
    assert_eq!(revoke.mailbox_rows_cleaned, 1);
    assert_eq!(revoke.leases_cleared, 1);
    assert_eq!(revoke.dispatch_registrations_removed, 1);
    assert_eq!(
        revoke.state,
        hartevo_cloud_storage::CloudRemoteWorkerTransportRegistrationState::Revoked
    );
    let revoked_completion = CloudRemoteWorkerCompletion {
        scope: scope.clone(),
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        task_id: revoke_lease.task_id.clone(),
        dispatch_registration_id: revoked_mount_result.dispatch_registration_id.clone(),
        lease_id: revoke_lease.lease_id,
        lease_generation: revoke_lease.lease_generation,
        lease_owner: revoke_lease.lease_owner.clone(),
        lease_token_digest: revoke_lease.lease_token_digest.clone(),
        result_digest: digest("revoke-cleanup-result"),
        idempotency_key_digest: digest("revoke-cleanup-completion"),
        completed_at: timestamp + Duration::seconds(54),
    };
    assert!(matches!(
        store
            .complete_remote_worker_task(&mut client, &revoked_completion)
            .await,
        Err(CloudStorageError::RemoteWorkerDispatchNotRegistered)
    ));
    let revoke_inspection = client
        .transaction()
        .await
        .expect("start transport revoke cleanup inspection");
    set_sql_scope(&revoke_inspection, &scope).await;
    let revoked_row = revoke_inspection
        .query_one(
            "SELECT status, lease_generation, lease_id, lease_owner,
                    lease_token_digest, lease_expires_at, heartbeat_at
             FROM hartevo_cell.remote_worker_mailbox_messages
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &revoke_task.task_id.as_str(),
            ],
        )
        .await
        .expect("read revoked Worker mailbox cleanup");
    assert_eq!(revoked_row.get::<_, String>(0), "dead_letter");
    assert_eq!(revoked_row.get::<_, i64>(1), 0);
    assert!(revoked_row.get::<_, Option<String>>(2).is_none());
    assert!(revoked_row.get::<_, Option<String>>(3).is_none());
    assert!(revoked_row.get::<_, Option<String>>(4).is_none());
    assert!(revoked_row.get::<_, Option<DateTime<Utc>>>(5).is_none());
    assert!(revoked_row.get::<_, Option<DateTime<Utc>>>(6).is_none());
    let revoked_dispatch_count: i64 = revoke_inspection
        .query_one(
            "SELECT count(*)
             FROM hartevo_cell.remote_worker_dispatch_registrations
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND mission_id = $4 AND registration_id = $5",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &mission_id.as_str(),
                &revoked_mount_result.registration_id,
            ],
        )
        .await
        .expect("read removed revoke dispatch registration")
        .get(0);
    assert_eq!(revoked_dispatch_count, 0);
    revoke_inspection
        .commit()
        .await
        .expect("finish transport revoke cleanup inspection");

    let isolated_scope = CellScope {
        cell: DataCell::Us,
        tenant_id: TenantId::new(),
    };
    let isolated_inspection = client
        .transaction()
        .await
        .expect("start cross-tenant RLS inspection");
    set_sql_scope(&isolated_inspection, &isolated_scope).await;
    for table in [
        "sync_object_heads",
        "device_public_key_heads",
        "remote_worker_mailbox_messages",
        "remote_worker_claims",
    ] {
        let count: i64 = isolated_inspection
            .query_one(&format!("SELECT count(*) FROM hartevo_cell.{table}"), &[])
            .await
            .expect("read cross-tenant RLS-isolated table")
            .get(0);
        assert_eq!(count, 0, "cross-tenant rows leaked from {table}");
    }
    isolated_inspection
        .commit()
        .await
        .expect("finish cross-tenant RLS inspection");
    let unscoped_visible_rows: i64 = client
        .query_one(
            "SELECT count(*) FROM hartevo_cell.remote_worker_claims",
            &[],
        )
        .await
        .expect("read unscoped Worker claims")
        .get(0);
    assert_eq!(unscoped_visible_rows, 0);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the PostgreSQL journey keeps the typed Mission fence, takeover, receipt, uncertain, cancel, and revoke contract in one acceptance path"
)]
async fn postgres_typed_mission_remote_worker_execution_is_bounded_and_non_replayable() {
    let Some(database_url) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
        eprintln!(
            "NOT_RUN/BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; typed Mission Remote Worker PostgreSQL journey did not execute"
        );
        return;
    };
    let database_url = database_url
        .into_string()
        .expect("PostgreSQL test URL must be valid Unicode");
    let (mut client, _connection_task) = connect().await;
    let store = PostgresCellStore::new(DataCell::Us);
    let timestamp = now() + Duration::days(1);
    store
        .migrate(&mut client, timestamp)
        .await
        .expect("migrate typed Remote Worker schema");
    let scope = CellScope {
        cell: DataCell::Us,
        tenant_id: TenantId::new(),
    };
    let project_id = ProjectId::new();
    let mission_id = MissionId::from("typed-remote-worker-mission");
    let worker_id = WorkerId::from("typed-regional-worker");
    store
        .register_tenant(&mut client, &scope, timestamp)
        .await
        .expect("register typed Remote Worker tenant");
    let metadata = payload(71);
    store
        .create_project(
            &mut client,
            &CloudProjectRegistration {
                scope: scope.clone(),
                project_id: project_id.clone(),
                encryption_mode: ProjectEncryptionMode::TeamEnvelope,
                remote_execution_opt_in: true,
                metadata_digest: metadata.content_digest.clone(),
                initial_payload: metadata,
                idempotency_key_digest: digest("typed-remote-project"),
                created_at: timestamp,
            },
        )
        .await
        .expect("create typed Remote Worker project");
    let dispatch_registration_id = digest("typed-remote-dispatch");
    let mounted = transport_mount(
        &scope,
        &project_id,
        &mission_id,
        dispatch_registration_id.clone(),
        &worker_id,
        digest("typed-remote-mount"),
        timestamp + Duration::seconds(1),
    );
    let mount_result = store
        .mount_remote_worker_transport(&mut client, &mounted)
        .await
        .expect("mount typed Remote Worker provider");
    let fence = CloudRemoteWorkerMissionFence {
        scope: scope.clone(),
        project_id: project_id.clone(),
        project_key_generation: 4,
        mission_id: mission_id.clone(),
        mission_generation: 2,
        mission_version: 9,
        mission_digest: digest("typed-mission-contract-v9"),
    };

    let first_request = CloudRemoteWorkerWorkRequest {
        fence: fence.clone(),
        task_id: TaskId::from("typed-work-takeover"),
        worker_id: worker_id.clone(),
        dispatch_registration_id: dispatch_registration_id.clone(),
        input: payload(72),
        idempotency_key_digest: digest("typed-work-takeover-request"),
        enqueued_at: timestamp + Duration::seconds(2),
        deadline_at: timestamp + Duration::minutes(10),
    };
    let first_request_result = store
        .enqueue_remote_worker_work(&mut client, &first_request)
        .await
        .expect("enqueue typed encrypted Work request");
    assert!(!first_request_result.duplicate);
    assert!(
        store
            .enqueue_remote_worker_work(&mut client, &first_request)
            .await
            .expect("replay typed Work request")
            .duplicate
    );
    let marker = b"MISSION-PLAINTEXT-MUST-NOT-REACH-CELL";
    let inspection = client
        .transaction()
        .await
        .expect("start typed ciphertext inspection");
    set_sql_scope(&inspection, &scope).await;
    let stored_input: Vec<u8> = inspection
        .query_one(
            "SELECT input_ciphertext
             FROM hartevo_cell.remote_worker_work_requests
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND task_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
                &first_request.task_id.as_str(),
            ],
        )
        .await
        .expect("inspect typed encrypted input")
        .get(0);
    assert!(
        !stored_input
            .windows(marker.len())
            .any(|window| window == marker)
    );
    inspection
        .commit()
        .await
        .expect("finish typed ciphertext inspection");

    let first_claim = store
        .claim_remote_worker_work(
            &mut client,
            &CloudRemoteWorkerWorkClaim {
                fence: fence.clone(),
                task_id: Some(first_request.task_id.clone()),
                worker_id: worker_id.clone(),
                dispatch_registration_id: dispatch_registration_id.clone(),
                lease_owner: "typed-worker-old".into(),
                lease_token_digest: digest("typed-old-token"),
                claim_idempotency_key_digest: digest("typed-old-claim"),
                now: timestamp + Duration::seconds(10),
                lease_for: Duration::seconds(2),
            },
        )
        .await
        .expect("claim typed Work request")
        .expect("typed Work request is available");
    assert!(!first_claim.duplicate);
    assert!(!first_claim.takeover);
    assert_eq!(first_claim.lease.lease_generation, 1);
    assert!(
        store
            .claim_remote_worker_work(
                &mut client,
                &CloudRemoteWorkerWorkClaim {
                    fence: fence.clone(),
                    task_id: Some(first_request.task_id.clone()),
                    worker_id: worker_id.clone(),
                    dispatch_registration_id: dispatch_registration_id.clone(),
                    lease_owner: "typed-worker-old".into(),
                    lease_token_digest: digest("typed-old-token"),
                    claim_idempotency_key_digest: digest("typed-old-claim"),
                    now: timestamp + Duration::seconds(10),
                    lease_for: Duration::seconds(2),
                },
            )
            .await
            .expect("replay typed claim")
            .expect("replayed typed claim")
            .duplicate
    );
    let heartbeat = store
        .heartbeat_remote_worker_work(
            &mut client,
            &CloudRemoteWorkerWorkHeartbeat {
                fence: fence.clone(),
                task_id: first_request.task_id.clone(),
                worker_id: worker_id.clone(),
                dispatch_registration_id: dispatch_registration_id.clone(),
                lease_id: first_claim.lease.lease_id.clone(),
                lease_generation: first_claim.lease.lease_generation,
                lease_owner: first_claim.lease.lease_owner.clone(),
                lease_token_digest: first_claim.lease.lease_token_digest.clone(),
                heartbeat_idempotency_key_digest: digest("typed-old-heartbeat"),
                now: timestamp + Duration::seconds(11),
                lease_for: Duration::seconds(2),
            },
        )
        .await
        .expect("heartbeat typed Work lease");
    assert!(!heartbeat.duplicate);
    let takeover = store
        .claim_remote_worker_work(
            &mut client,
            &CloudRemoteWorkerWorkClaim {
                fence: fence.clone(),
                task_id: Some(first_request.task_id.clone()),
                worker_id: worker_id.clone(),
                dispatch_registration_id: dispatch_registration_id.clone(),
                lease_owner: "typed-worker-recovered".into(),
                lease_token_digest: digest("typed-recovered-token"),
                claim_idempotency_key_digest: digest("typed-recovered-claim"),
                now: timestamp + Duration::seconds(14),
                lease_for: Duration::seconds(30),
            },
        )
        .await
        .expect("take over expired typed Work lease")
        .expect("typed Work takeover is available");
    assert!(takeover.takeover);
    assert_eq!(takeover.lease.lease_generation, 2);
    assert!(matches!(
        store
            .heartbeat_remote_worker_work(
                &mut client,
                &CloudRemoteWorkerWorkHeartbeat {
                    fence: fence.clone(),
                    task_id: first_request.task_id.clone(),
                    worker_id: worker_id.clone(),
                    dispatch_registration_id: dispatch_registration_id.clone(),
                    lease_id: first_claim.lease.lease_id.clone(),
                    lease_generation: first_claim.lease.lease_generation,
                    lease_owner: first_claim.lease.lease_owner.clone(),
                    lease_token_digest: first_claim.lease.lease_token_digest.clone(),
                    heartbeat_idempotency_key_digest: digest("typed-stale-heartbeat"),
                    now: timestamp + Duration::seconds(15),
                    lease_for: Duration::seconds(10),
                },
            )
            .await,
        Err(CloudStorageError::RemoteWorkerLeaseLost)
    ));
    let uncertain = store
        .mark_remote_worker_work_uncertain(
            &mut client,
            &CloudRemoteWorkerWorkUncertain {
                fence: fence.clone(),
                task_id: first_request.task_id.clone(),
                dispatch_registration_id: dispatch_registration_id.clone(),
                lease_id: takeover.lease.lease_id.clone(),
                lease_generation: takeover.lease.lease_generation,
                lease_owner: takeover.lease.lease_owner.clone(),
                lease_token_digest: takeover.lease.lease_token_digest.clone(),
                reason_digest: digest("typed-provider-timeout"),
                uncertain_idempotency_key_digest: digest("typed-uncertain"),
                uncertain_at: timestamp + Duration::seconds(16),
            },
        )
        .await
        .expect("freeze typed uncertain Work");
    assert!(!uncertain.duplicate);
    assert_eq!(uncertain.status, CloudRemoteWorkerWorkStatus::Uncertain);
    assert!(
        store
            .mark_remote_worker_work_uncertain(
                &mut client,
                &CloudRemoteWorkerWorkUncertain {
                    fence: fence.clone(),
                    task_id: first_request.task_id.clone(),
                    dispatch_registration_id: dispatch_registration_id.clone(),
                    lease_id: takeover.lease.lease_id.clone(),
                    lease_generation: takeover.lease.lease_generation,
                    lease_owner: takeover.lease.lease_owner.clone(),
                    lease_token_digest: takeover.lease.lease_token_digest.clone(),
                    reason_digest: digest("typed-provider-timeout"),
                    uncertain_idempotency_key_digest: digest("typed-uncertain"),
                    uncertain_at: timestamp + Duration::seconds(16),
                },
            )
            .await
            .expect("replay typed uncertain Work")
            .duplicate
    );
    assert!(
        store
            .claim_remote_worker_work(
                &mut client,
                &CloudRemoteWorkerWorkClaim {
                    fence: fence.clone(),
                    task_id: Some(first_request.task_id.clone()),
                    worker_id: worker_id.clone(),
                    dispatch_registration_id: dispatch_registration_id.clone(),
                    lease_owner: "typed-worker-no-replay".into(),
                    lease_token_digest: digest("typed-no-replay-token"),
                    claim_idempotency_key_digest: digest("typed-no-replay-claim"),
                    now: timestamp + Duration::seconds(17),
                    lease_for: Duration::seconds(30),
                },
            )
            .await
            .expect("query uncertain typed Work")
            .is_none()
    );

    let completed_request = CloudRemoteWorkerWorkRequest {
        task_id: TaskId::from("typed-work-completed"),
        input: payload(73),
        idempotency_key_digest: digest("typed-work-completed-request"),
        enqueued_at: timestamp + Duration::seconds(20),
        deadline_at: timestamp + Duration::minutes(10),
        ..first_request.clone()
    };
    let completed_enqueue = store
        .enqueue_remote_worker_work(&mut client, &completed_request)
        .await
        .expect("enqueue typed completed Work request");
    let completed_claim = store
        .claim_remote_worker_work(
            &mut client,
            &CloudRemoteWorkerWorkClaim {
                fence: fence.clone(),
                task_id: Some(completed_request.task_id.clone()),
                worker_id: worker_id.clone(),
                dispatch_registration_id: dispatch_registration_id.clone(),
                lease_owner: "typed-worker-completer".into(),
                lease_token_digest: digest("typed-completer-token"),
                claim_idempotency_key_digest: digest("typed-completer-claim"),
                now: timestamp + Duration::seconds(21),
                lease_for: Duration::seconds(30),
            },
        )
        .await
        .expect("claim typed completed Work")
        .expect("completed Work is available");
    let completed_result = CloudRemoteWorkerWorkResult {
        fence: fence.clone(),
        task_id: completed_request.task_id.clone(),
        worker_id: worker_id.clone(),
        dispatch_registration_id: dispatch_registration_id.clone(),
        request_digest: completed_enqueue.request_digest,
        lease_id: completed_claim.lease.lease_id.clone(),
        lease_generation: completed_claim.lease.lease_generation,
        lease_owner: completed_claim.lease.lease_owner.clone(),
        lease_token_digest: completed_claim.lease.lease_token_digest.clone(),
        output: payload(74),
        evidence_digest: digest("typed-result-evidence"),
        effect_receipt_digest: None,
        outcome_link_digest: None,
        provider_id: mounted.provider.provider_id.clone(),
        provider_implementation_digest: mounted.provider.implementation_digest.clone(),
        service_contract_digest: mounted.service.contract_digest.clone(),
        current_commit_digest: digest("typed-provider-commit"),
        completion_idempotency_key_digest: digest("typed-completion"),
        completed_at: timestamp + Duration::seconds(22),
    };
    let receipt = store
        .complete_remote_worker_work(&mut client, &completed_result)
        .await
        .expect("commit encrypted typed result receipt");
    assert!(!receipt.duplicate);
    assert_eq!(receipt.receipt.result_digest.len(), 64);
    let replayed_receipt = store
        .complete_remote_worker_work(&mut client, &completed_result)
        .await
        .expect("replay typed result receipt");
    assert!(replayed_receipt.duplicate);
    assert_eq!(replayed_receipt.receipt, receipt.receipt);
    let completed_record = store
        .load_remote_worker_work(&mut client, &fence, &completed_request.task_id)
        .await
        .expect("load completed typed Work");
    assert_eq!(
        completed_record.status,
        CloudRemoteWorkerWorkStatus::Completed
    );
    assert_eq!(
        completed_record
            .result_receipt
            .as_ref()
            .expect("durable result receipt")
            .output
            .content_digest,
        completed_result.output.content_digest
    );

    let cancelled_request = CloudRemoteWorkerWorkRequest {
        task_id: TaskId::from("typed-work-cancelled"),
        input: payload(75),
        idempotency_key_digest: digest("typed-work-cancelled-request"),
        enqueued_at: timestamp + Duration::seconds(30),
        deadline_at: timestamp + Duration::minutes(10),
        ..first_request.clone()
    };
    store
        .enqueue_remote_worker_work(&mut client, &cancelled_request)
        .await
        .expect("enqueue typed cancellable Work");
    let cancellation = CloudRemoteWorkerWorkCancel {
        fence: fence.clone(),
        task_id: cancelled_request.task_id.clone(),
        dispatch_registration_id: dispatch_registration_id.clone(),
        reason_digest: digest("typed-user-cancel"),
        cancel_idempotency_key_digest: digest("typed-cancel"),
        cancelled_at: timestamp + Duration::seconds(31),
    };
    assert_eq!(
        store
            .cancel_remote_worker_work(&mut client, &cancellation)
            .await
            .expect("cancel typed Work")
            .status,
        CloudRemoteWorkerWorkStatus::Cancelled
    );
    assert!(
        store
            .cancel_remote_worker_work(&mut client, &cancellation)
            .await
            .expect("replay typed cancellation")
            .duplicate
    );

    let revoked_request = CloudRemoteWorkerWorkRequest {
        task_id: TaskId::from("typed-work-revoked"),
        input: payload(76),
        idempotency_key_digest: digest("typed-work-revoked-request"),
        enqueued_at: timestamp + Duration::seconds(40),
        deadline_at: timestamp + Duration::minutes(10),
        ..first_request
    };
    store
        .enqueue_remote_worker_work(&mut client, &revoked_request)
        .await
        .expect("enqueue typed revoke-cleanup Work");
    store
        .claim_remote_worker_work(
            &mut client,
            &CloudRemoteWorkerWorkClaim {
                fence: fence.clone(),
                task_id: Some(revoked_request.task_id.clone()),
                worker_id: worker_id.clone(),
                dispatch_registration_id: dispatch_registration_id.clone(),
                lease_owner: "typed-worker-revoked".into(),
                lease_token_digest: digest("typed-revoked-token"),
                claim_idempotency_key_digest: digest("typed-revoked-claim"),
                now: timestamp + Duration::seconds(41),
                lease_for: Duration::seconds(30),
            },
        )
        .await
        .expect("claim revoke-cleanup Work")
        .expect("revoke-cleanup Work is available");
    store
        .revoke_remote_worker_transport(
            &mut client,
            &scope,
            &project_id,
            &mission_id,
            &mount_result.registration_id,
            &digest("typed-revoke-reason"),
            timestamp + Duration::seconds(42),
        )
        .await
        .expect("revoke typed Remote Worker transport");
    let revoked_record = store
        .load_remote_worker_work(&mut client, &fence, &revoked_request.task_id)
        .await
        .expect("load revoke-cleaned typed Work");
    assert_eq!(
        revoked_record.status,
        CloudRemoteWorkerWorkStatus::DeadLetter
    );
    assert_eq!(
        revoked_record
            .terminal_reason_digest
            .expect("revoke cleanup reason")
            .len(),
        64
    );

    let log_inspection = client
        .transaction()
        .await
        .expect("start typed durable log inspection");
    set_sql_scope(&log_inspection, &scope).await;
    let counts = log_inspection
        .query_one(
            "SELECT
                (SELECT count(*) FROM hartevo_cell.remote_worker_work_log
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3),
                (SELECT count(*) FROM hartevo_cell.remote_worker_result_receipts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3)",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await
        .expect("inspect typed durable log and receipt");
    let log_count: i64 = counts.get(0);
    let receipt_count: i64 = counts.get(1);
    assert!(log_count >= 10);
    assert_eq!(receipt_count, 1);
    log_inspection
        .commit()
        .await
        .expect("finish typed durable log inspection");

    let isolated_scope = CellScope {
        cell: DataCell::Us,
        tenant_id: TenantId::new(),
    };
    let isolated = client
        .transaction()
        .await
        .expect("start typed cross-tenant RLS inspection");
    set_sql_scope(&isolated, &isolated_scope).await;
    let visible: i64 = isolated
        .query_one(
            "SELECT count(*) FROM hartevo_cell.remote_worker_work_requests",
            &[],
        )
        .await
        .expect("read typed RLS-isolated work table")
        .get(0);
    assert_eq!(visible, 0);
    isolated
        .commit()
        .await
        .expect("finish typed cross-tenant RLS inspection");
    drop(database_url);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the PostgreSQL journey keeps typed attach, encrypted head CAS, key rotation, stale-session recovery, revoke, and RLS evidence together"
)]
async fn postgres_typed_device_sync_attach_head_rotation_and_revoke_is_fail_closed() {
    let Some(_) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
        eprintln!(
            "NOT_RUN/BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; typed device-sync PostgreSQL journey did not execute"
        );
        return;
    };

    let (mut client, _connection_task) = connect().await;
    let store = PostgresCellStore::new(DataCell::Us);
    let timestamp = now() + Duration::days(2);
    store
        .migrate(&mut client, timestamp)
        .await
        .expect("migrate typed device-sync schema");

    let scope = CellScope {
        cell: DataCell::Us,
        tenant_id: TenantId::new(),
    };
    let isolated_scope = CellScope {
        cell: DataCell::Us,
        tenant_id: TenantId::new(),
    };
    let project_id = ProjectId::new();
    store
        .register_tenant(&mut client, &scope, timestamp)
        .await
        .expect("register typed device-sync tenant");
    store
        .register_tenant(&mut client, &isolated_scope, timestamp)
        .await
        .expect("register isolated device-sync tenant");

    let metadata = payload(70);
    store
        .create_project(
            &mut client,
            &CloudProjectRegistration {
                scope: scope.clone(),
                project_id: project_id.clone(),
                encryption_mode: ProjectEncryptionMode::TeamEnvelope,
                remote_execution_opt_in: false,
                metadata_digest: metadata.content_digest.clone(),
                initial_payload: metadata,
                idempotency_key_digest: digest("device-sync-project"),
                created_at: timestamp,
            },
        )
        .await
        .expect("create typed device-sync project");

    let source_device = DeviceId::from("device-sync-source");
    let target_device = DeviceId::from("device-sync-target");
    let source_recipient = KeyRecipient::Device(source_device.clone());
    let source_envelope = key_envelope(
        &scope,
        &project_id,
        "device-sync-source-v1",
        1,
        source_recipient.clone(),
        timestamp,
    );
    let source_envelope_digest = source_envelope
        .canonical_digest()
        .expect("digest source key envelope");
    let keyring_v1 = ProjectKeyring::initialize(
        scope.tenant_id.clone(),
        project_id.clone(),
        ProjectEncryptionMode::TeamEnvelope,
        vec![source_envelope.clone()],
        timestamp,
    )
    .expect("initialize typed device-sync keyring");
    let bootstrap_v1 = ProjectKeyringBootstrap::prepare(
        keyring_v1.clone(),
        None,
        source_recipient.clone(),
        source_envelope_digest.clone(),
        digest("device-sync-bootstrap-evidence-v1"),
        digest("device-sync-bootstrap-v1"),
        timestamp + Duration::seconds(1),
    )
    .expect("prepare typed device-sync keyring bootstrap");
    store
        .publish_keyring_bootstrap(&mut client, &scope, &bootstrap_v1)
        .await
        .expect("publish typed device-sync keyring bootstrap");

    let target_public_key = DevicePublicKeyRegistration::register(
        scope.tenant_id.clone(),
        project_id.clone(),
        target_device.clone(),
        vec![8; 32],
        ActorId::from("device-sync-authorizer"),
        digest("device-sync-key-evidence"),
        digest("device-sync-public-key-v1"),
        timestamp + Duration::seconds(1),
    )
    .expect("register target device public key");
    store
        .publish_device_public_key(&mut client, &scope, &target_public_key)
        .await
        .expect("publish target device public key");

    let fence_v1 = store
        .load_device_sync_key_fence(&mut client, &scope, &project_id)
        .await
        .expect("load initial device-sync key fence");
    let service = CloudDeviceSyncServiceDefinition::v1();
    let provider = CloudDeviceSyncProvider {
        provider_id: "regional-cell-device-sync".into(),
        region: DataCell::Us,
        service_id: service.service_id.clone(),
        version: service.version,
        implementation_digest: digest("regional-cell-device-sync-provider-v1"),
    };
    let consumer = CloudDeviceSyncConsumer {
        consumer_id: "local-project-sync-loop".into(),
        service_id: service.service_id.clone(),
        min_service_version: service.version,
        descriptor_digest: digest("local-project-sync-loop-v1"),
    };
    let attach_v1 = CloudDeviceSyncAttach {
        scope: scope.clone(),
        region: DataCell::Us,
        mission_scope_digest: digest("device-sync-mission-scope"),
        project_id: project_id.clone(),
        device_id: target_device.clone(),
        project_key_generation: fence_v1.project_key_generation,
        keyring_manifest_digest: fence_v1.keyring_manifest_digest.clone(),
        registration_version: 1,
        device_public_key_digest: target_public_key.public_key_digest.clone(),
        service: service.clone(),
        provider: provider.clone(),
        consumer: consumer.clone(),
        idempotency_key_digest: digest("device-sync-attach-v1"),
        attached_at: timestamp + Duration::seconds(2),
    };
    let attached_v1 = store
        .attach_device_sync(&mut client, &attach_v1)
        .await
        .expect("attach target device to typed sync transport");
    assert!(!attached_v1.duplicate);
    let attach_replay = store
        .attach_device_sync(&mut client, &attach_v1)
        .await
        .expect("replay typed device attach");
    assert!(attach_replay.duplicate);
    assert_eq!(attach_replay.session, attached_v1.session);

    let mutation_v1 = CloudDeviceSyncDocumentMutation {
        session: attached_v1.session.clone(),
        document_id: "mission-sync-document".into(),
        object_kind: SyncObjectKind::Mission,
        precondition: MutationPrecondition::CreateOnly,
        payload: payload(90),
        tombstone: false,
        idempotency_key_digest: digest("device-sync-document-v1"),
        recorded_at: timestamp + Duration::seconds(3),
    };
    let head_v1 = store
        .apply_device_sync_document(&mut client, &mutation_v1)
        .await
        .expect("advance encrypted device-sync head v1");
    assert!(!head_v1.duplicate);
    assert_eq!(head_v1.head.revision, 1);
    assert_eq!(head_v1.head.project_key_generation, 1);
    let head_v1_replay = store
        .apply_device_sync_document(&mut client, &mutation_v1)
        .await
        .expect("replay encrypted device-sync head v1");
    assert!(head_v1_replay.duplicate);
    assert_eq!(head_v1_replay.head, head_v1.head);

    let mut keyring_v2 = keyring_v1;
    let source_envelope_v2 = key_envelope(
        &scope,
        &project_id,
        "device-sync-source-v2",
        2,
        source_recipient.clone(),
        timestamp + Duration::seconds(4),
    );
    keyring_v2
        .rotate(vec![source_envelope_v2], timestamp + Duration::seconds(4))
        .expect("rotate typed device-sync key generation");
    let bootstrap_v2 = ProjectKeyringBootstrap::prepare(
        keyring_v2,
        Some(1),
        source_recipient,
        source_envelope_digest,
        digest("device-sync-bootstrap-evidence-v2"),
        digest("device-sync-bootstrap-v2"),
        timestamp + Duration::seconds(4),
    )
    .expect("prepare rotated typed device-sync keyring bootstrap");
    store
        .publish_keyring_bootstrap(&mut client, &scope, &bootstrap_v2)
        .await
        .expect("publish rotated typed device-sync keyring bootstrap");

    assert!(matches!(
        store
            .load_device_sync_document(
                &mut client,
                &attached_v1.session,
                "mission-sync-document",
                timestamp + Duration::seconds(5),
            )
            .await,
        Err(CloudStorageError::DeviceSyncKeyGenerationStale)
    ));

    let fence_v2 = store
        .load_device_sync_key_fence(&mut client, &scope, &project_id)
        .await
        .expect("load rotated device-sync key fence");
    assert_eq!(fence_v2.project_key_generation, 2);
    assert_ne!(
        fence_v1.keyring_manifest_digest,
        fence_v2.keyring_manifest_digest
    );
    let attach_v2 = CloudDeviceSyncAttach {
        scope: scope.clone(),
        region: DataCell::Us,
        mission_scope_digest: attached_v1.session.mission_scope_digest.clone(),
        project_id: project_id.clone(),
        device_id: target_device,
        project_key_generation: fence_v2.project_key_generation,
        keyring_manifest_digest: fence_v2.keyring_manifest_digest.clone(),
        registration_version: 2,
        device_public_key_digest: target_public_key.public_key_digest.clone(),
        service,
        provider,
        consumer,
        idempotency_key_digest: digest("device-sync-attach-v2"),
        attached_at: timestamp + Duration::seconds(6),
    };
    let attached_v2 = store
        .attach_device_sync(&mut client, &attach_v2)
        .await
        .expect("reattach target device at rotated key generation");
    assert!(!attached_v2.duplicate);
    assert_eq!(attached_v2.session.registration_version, 2);
    assert_ne!(
        attached_v1.session.registration_digest,
        attached_v2.session.registration_digest
    );

    let stale_mutation = CloudDeviceSyncDocumentMutation {
        session: attached_v1.session.clone(),
        document_id: "mission-sync-document".into(),
        object_kind: SyncObjectKind::Mission,
        precondition: MutationPrecondition::ExactRevision(1),
        payload: payload(91),
        tombstone: false,
        idempotency_key_digest: digest("device-sync-stale-write"),
        recorded_at: timestamp + Duration::seconds(7),
    };
    assert!(matches!(
        store
            .apply_device_sync_document(&mut client, &stale_mutation)
            .await,
        Err(CloudStorageError::DeviceSyncRegistrationNotActive)
    ));
    assert!(matches!(
        store
            .load_device_sync_document(
                &mut client,
                &attached_v1.session,
                "mission-sync-document",
                timestamp + Duration::seconds(7),
            )
            .await,
        Err(CloudStorageError::DeviceSyncRegistrationNotActive)
    ));

    let mut encrypted_payload_v2 = payload(91);
    encrypted_payload_v2.key_version = 2;
    let mutation_v2 = CloudDeviceSyncDocumentMutation {
        session: attached_v2.session.clone(),
        document_id: "mission-sync-document".into(),
        object_kind: SyncObjectKind::Mission,
        precondition: MutationPrecondition::ExactRevision(1),
        payload: encrypted_payload_v2,
        tombstone: false,
        idempotency_key_digest: digest("device-sync-document-v2"),
        recorded_at: timestamp + Duration::seconds(7),
    };
    let head_v2 = store
        .apply_device_sync_document(&mut client, &mutation_v2)
        .await
        .expect("advance encrypted device-sync head v2");
    assert!(!head_v2.duplicate);
    assert_eq!(head_v2.head.revision, 2);
    assert_eq!(head_v2.head.project_key_generation, 2);
    assert_ne!(head_v1.head.head_digest, head_v2.head.head_digest);

    let release = CloudDeviceSyncRelease {
        session: attached_v2.session.clone(),
        kind: CloudDeviceSyncReleaseKind::Revoke,
        reason_digest: digest("device-sync-revoke-reason"),
        idempotency_key_digest: digest("device-sync-revoke-v2"),
        released_at: timestamp + Duration::seconds(8),
    };
    let released = store
        .release_device_sync_registration(&mut client, &release)
        .await
        .expect("revoke typed device-sync registration");
    assert!(!released.duplicate);
    assert_eq!(
        released.state,
        hartevo_cloud_storage::CloudDeviceSyncRegistrationState::Revoked
    );
    let release_replay = store
        .release_device_sync_registration(&mut client, &release)
        .await
        .expect("replay typed device-sync revoke");
    assert!(release_replay.duplicate);
    assert_eq!(release_replay.state, released.state);
    assert!(matches!(
        store
            .load_device_sync_document(
                &mut client,
                &attached_v2.session,
                "mission-sync-document",
                timestamp + Duration::seconds(9),
            )
            .await,
        Err(CloudStorageError::DeviceSyncRegistrationNotActive)
    ));

    let inspection = client
        .transaction()
        .await
        .expect("start typed device-sync durable inspection");
    set_sql_scope(&inspection, &scope).await;
    let counts = inspection
        .query_one(
            "SELECT
                (SELECT count(*) FROM hartevo_cell.device_sync_registrations
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3),
                (SELECT count(*) FROM hartevo_cell.device_sync_document_versions
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3),
                (SELECT count(*) FROM hartevo_cell.device_sync_document_heads
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3),
                (SELECT count(*) FROM hartevo_cell.device_sync_event_log
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3),
                (SELECT count(*) FROM hartevo_cell.device_sync_event_log
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND event_type = 'stale_generation_reclaimed'),
                (SELECT ciphertext FROM hartevo_cell.device_sync_document_versions
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND document_id = 'mission-sync-document' AND revision = 2)",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await
        .expect("inspect typed device-sync durable tables");
    assert_eq!(counts.get::<_, i64>(0), 2);
    assert_eq!(counts.get::<_, i64>(1), 2);
    assert_eq!(counts.get::<_, i64>(2), 1);
    assert_eq!(counts.get::<_, i64>(3), 6);
    assert_eq!(counts.get::<_, i64>(4), 1);
    let stored_ciphertext: Vec<u8> = counts.get(5);
    assert_eq!(stored_ciphertext, mutation_v2.payload.ciphertext);
    assert!(
        !stored_ciphertext
            .windows(b"device-sync-plaintext".len())
            .any(|window| window == b"device-sync-plaintext")
    );
    inspection
        .commit()
        .await
        .expect("finish typed device-sync durable inspection");

    let isolated = client
        .transaction()
        .await
        .expect("start typed device-sync RLS inspection");
    set_sql_scope(&isolated, &isolated_scope).await;
    let visible: i64 = isolated
        .query_one(
            "SELECT count(*) FROM hartevo_cell.device_sync_event_log",
            &[],
        )
        .await
        .expect("read typed device-sync RLS-isolated event log")
        .get(0);
    assert_eq!(visible, 0);
    isolated
        .commit()
        .await
        .expect("finish typed device-sync RLS inspection");
}

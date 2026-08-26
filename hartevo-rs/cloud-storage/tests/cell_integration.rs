use std::process::Command;

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_cloud_storage::{
    CellScope, CloudProjectRegistration, CloudRemoteWorkerCompletion, CloudRemoteWorkerTask,
    CloudStorageError, DataCell, EncryptedPayload, EncryptedSyncMutation, MutationPrecondition,
    POSTGRES_L2_URL_ENV, PostgresCellStore, SyncObjectKind,
};
use hartevo_domain_kernel::{
    ActorId, DeviceId, DevicePublicKeyRegistration, MissionId, ProjectEncryptionMode, ProjectId,
    TaskId, TenantId, WorkerId, WorkerLeaseId,
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

async fn spawn_process(mode: &str, variables: &[(&str, String)]) -> String {
    let binary = std::env::var("CARGO_BIN_EXE_cell_process_harness")
        .expect("Cargo must provide the cell process harness binary");
    let mode = mode.to_owned();
    let variables: Vec<(String, String)> = variables
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect();
    let output = tokio::task::spawn_blocking(move || {
        let mut command = Command::new(binary);
        command.arg(mode);
        for (name, value) in variables {
            command.env(name, value);
        }
        command.output()
    })
    .await
    .expect("join Cell process harness")
    .expect("spawn Cell process harness");
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

    let worker_id = WorkerId::from("integration-worker");
    let first_task = CloudRemoteWorkerTask {
        scope: scope.clone(),
        project_id: project_id.clone(),
        mission_id: MissionId::from("integration-mission"),
        task_id: TaskId::from("worker-task-complete"),
        worker_id: worker_id.clone(),
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
    let race_worker = WorkerId::from("integration-race-worker");
    let race_task = CloudRemoteWorkerTask {
        worker_id: race_worker.clone(),
        task_id: TaskId::from("worker-task-race"),
        payload: payload(33),
        idempotency_key_digest: digest("worker-task-race"),
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
        task_id: race_lease.task_id.clone(),
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
    let first_claim_output = spawn_process("claim", &first_claim_variables).await;
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
        &spawn_process("complete", &first_complete_variables).await,
        &first_task.task_id,
        false,
    );
    assert_completion(
        &spawn_process("complete", &first_complete_variables).await,
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
    let old_claim_output = spawn_process("claim", &recovery_claim_variables).await;
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
    let recovered_claim_output = spawn_process("claim", &recovered_claim_variables).await;
    let (recovered_duplicate, recovered_lease) = parse_claim(&recovered_claim_output);
    assert!(!recovered_duplicate);
    assert_eq!(recovered_lease.task_id, recovery_task.task_id);
    assert_ne!(recovered_lease.generation, old_lease.generation);
    let (replayed_duplicate, replayed_lease) =
        parse_claim(&spawn_process("claim", &recovery_claim_variables).await);
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
        task_id: old_lease.task_id.clone(),
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
        &spawn_process("complete", &recovered_complete_variables).await,
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

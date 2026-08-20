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
            "BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; two-process Cell integration did not execute"
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
    store
        .enqueue_remote_worker_task(&mut client, &first_task)
        .await
        .expect("enqueue first encrypted Worker task");
    store
        .enqueue_remote_worker_task(&mut client, &recovery_task)
        .await
        .expect("enqueue recovery Worker task");

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

    let stale_completion = CloudRemoteWorkerCompletion {
        scope: scope.clone(),
        project_id: project_id.clone(),
        task_id: old_lease.task_id.clone(),
        lease_id: old_lease.lease_id,
        lease_generation: old_lease.generation,
        lease_owner: old_lease.owner,
        lease_token_digest: old_lease.token_digest,
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
    let transaction = client
        .transaction()
        .await
        .expect("start scoped ciphertext inspection");
    transaction
        .query_one(
            "SELECT set_config('hartevo.tenant_id', $1, true),
                    set_config('hartevo.cell', $2, true)",
            &[&scope.tenant_id.as_str(), &scope.cell.as_str()],
        )
        .await
        .expect("set RLS scope for ciphertext inspection");
    let raw_ciphertext: Vec<u8> = transaction
        .query_one(
            "SELECT payload_ciphertext
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
        .expect("read stored Worker ciphertext")
        .get(0);
    transaction
        .commit()
        .await
        .expect("finish ciphertext inspection");
    assert!(
        !raw_ciphertext
            .windows(marker.len())
            .any(|window| window == marker)
    );
}

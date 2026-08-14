use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_cloud_storage::{
    CellScope, CloudProjectRegistration, CloudStorageError, DataCell, EncryptedPayload,
    EncryptedRegionTransferRequest, EncryptedSyncMutation, MutationPrecondition,
    POSTGRES_L2_URL_ENV, PostgresCellStore, RegionTransferConsumer, RegionTransferOutcome,
    RegionTransferProvider, RegionTransferReadbackProvider, RegionTransferServiceDefinition,
    RegionTransferStatus, RegionTransferVerificationStatus, SyncObjectKind,
};
use hartevo_domain_kernel::{MissionId, ProjectEncryptionMode, ProjectId, TenantId};
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;

const POSTGRES_TARGET_URL_ENV: &str = "HARTEVO_TEST_POSTGRES_TARGET_URL";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 4, 0, 0)
        .single()
        .expect("valid region transfer timestamp")
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn encrypted_payload(byte: u8, key_version: u64) -> EncryptedPayload {
    let ciphertext = vec![byte; 48];
    EncryptedPayload {
        key_version,
        nonce: vec![byte; 12],
        ciphertext: ciphertext.clone(),
        aad_digest: digest(&format!("aad-{byte}")),
        content_digest: format!("{:x}", Sha256::digest(ciphertext)),
    }
}

async fn connect(url: &str) -> (tokio_postgres::Client, tokio::task::JoinHandle<()>) {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect PostgreSQL Cell database");
    let task = tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("region transfer PostgreSQL connection failed: {error}");
        }
    });
    (client, task)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixture builder keeps every transfer identity and digest explicit"
)]
fn request(
    source_scope: CellScope,
    project_id: ProjectId,
    mission_id: MissionId,
    bundle: EncryptedPayload,
    transfer_id: &str,
    idempotency: &str,
    sequence: u64,
    provider: RegionTransferProvider,
    consumer: RegionTransferConsumer,
    project_metadata_digest: String,
) -> EncryptedRegionTransferRequest {
    let commit = digest("region-transfer-current-commit");
    EncryptedRegionTransferRequest {
        transfer_id: transfer_id.into(),
        source_scope,
        target_cell: DataCell::Eu,
        project_id,
        mission_id,
        project_revision: 1,
        project_metadata_digest,
        project_encryption_mode: ProjectEncryptionMode::TeamEnvelope,
        mission_revision: 1,
        key_generation: bundle.key_version,
        source_mission_content_digest: bundle.content_digest.clone(),
        encrypted_bundle_root: bundle.content_digest.clone(),
        encrypted_bundle: bundle,
        service: RegionTransferServiceDefinition::current(),
        provider,
        consumer,
        sequence,
        replay_nonce: format!("replay-{transfer_id}"),
        idempotency_key_digest: digest(idempotency),
        current_commit_digest: commit,
        requested_at: now() + Duration::seconds(i64::try_from(sequence).expect("small sequence")),
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the real source/target Cell journey keeps prepare, revoke, crash, tamper, adoption, and RLS evidence together"
)]
async fn postgres_region_transfer_receipt_is_encrypted_scoped_and_fail_closed() {
    let Some(source_url) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
        eprintln!(
            "BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; PostgreSQL region transfer did not execute"
        );
        return;
    };
    let Some(target_url) = std::env::var_os(POSTGRES_TARGET_URL_ENV) else {
        eprintln!(
            "BLOCKED_ENV: {POSTGRES_TARGET_URL_ENV} is absent; cross-Cell region transfer did not execute"
        );
        return;
    };
    let source_url = source_url
        .into_string()
        .expect("source PostgreSQL URL must be Unicode");
    let target_url = target_url
        .into_string()
        .expect("target PostgreSQL URL must be Unicode");
    let (mut source_client, _source_connection) = connect(&source_url).await;
    let (mut target_client, _target_connection) = connect(&target_url).await;
    let source_store = PostgresCellStore::new(DataCell::Us);
    let target_store = PostgresCellStore::new(DataCell::Eu);
    for client in [&source_client, &target_client] {
        let role = client
            .query_one(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .expect("inspect Cell integration role");
        assert!(!role.get::<_, bool>(0), "Cell role must not be superuser");
        assert!(!role.get::<_, bool>(1), "Cell role must not bypass RLS");
    }
    let timestamp = now();
    source_store
        .migrate(&mut source_client, timestamp)
        .await
        .expect("migrate source Cell");
    target_store
        .migrate(&mut target_client, timestamp)
        .await
        .expect("migrate target Cell");

    let tenant_id = TenantId::new();
    let source_scope = CellScope {
        cell: DataCell::Us,
        tenant_id: tenant_id.clone(),
    };
    let target_scope = CellScope {
        cell: DataCell::Eu,
        tenant_id: tenant_id.clone(),
    };
    source_store
        .register_tenant(&mut source_client, &source_scope, timestamp)
        .await
        .expect("register source tenant");
    target_store
        .register_tenant(&mut target_client, &target_scope, timestamp)
        .await
        .expect("register target tenant");

    let project_id = ProjectId::new();
    let mission_id = MissionId::new();
    let metadata = encrypted_payload(11, 1);
    let registration = CloudProjectRegistration {
        scope: source_scope.clone(),
        project_id: project_id.clone(),
        encryption_mode: ProjectEncryptionMode::TeamEnvelope,
        remote_execution_opt_in: false,
        metadata_digest: metadata.content_digest.clone(),
        initial_payload: metadata.clone(),
        idempotency_key_digest: digest("region-project-registration-source"),
        created_at: timestamp,
    };
    source_store
        .create_project(&mut source_client, &registration)
        .await
        .expect("create source project");
    target_store
        .create_project(
            &mut target_client,
            &CloudProjectRegistration {
                scope: target_scope.clone(),
                idempotency_key_digest: digest("region-project-registration-target"),
                ..registration.clone()
            },
        )
        .await
        .expect("create target project");

    let mission_payload = encrypted_payload(22, 3);
    source_store
        .apply_encrypted_mutation(
            &mut source_client,
            &EncryptedSyncMutation {
                scope: source_scope.clone(),
                project_id: project_id.clone(),
                object_id: mission_id.as_str().into(),
                object_kind: SyncObjectKind::Mission,
                precondition: MutationPrecondition::CreateOnly,
                payload: mission_payload.clone(),
                tombstone: false,
                idempotency_key_digest: digest("region-mission-source"),
                recorded_at: timestamp + Duration::seconds(1),
            },
        )
        .await
        .expect("create source Mission head");

    let provider = RegionTransferProvider::new(
        "postgres-source-region-provider",
        DataCell::Us,
        1,
        digest("region-transfer-provider"),
        digest("region-transfer-current-commit"),
    );
    let consumer = RegionTransferConsumer::new(
        "local-project-recovery-consumer",
        DataCell::Eu,
        1,
        digest("region-transfer-consumer"),
        "postgres-source-region-provider",
        digest("region-transfer-provider"),
        digest("region-transfer-current-commit"),
    );

    let revoked_request = request(
        source_scope.clone(),
        project_id.clone(),
        mission_id.clone(),
        mission_payload.clone(),
        "transfer-revoked",
        "region-transfer-revoked",
        1,
        provider.clone(),
        consumer.clone(),
        metadata.content_digest.clone(),
    );
    let prepared = provider
        .prepare(&source_store, &mut source_client, &revoked_request)
        .await
        .expect("prepare encrypted transfer");
    assert_eq!(prepared.status, RegionTransferStatus::Prepared);
    source_store
        .load_region_transfer_receipt(
            &mut source_client,
            &source_scope,
            &prepared.request.project_id,
            &prepared.request.transfer_id,
        )
        .await
        .expect("load durable source receipt")
        .verify()
        .expect("durable source receipt verifies");

    let mut tampered = prepared.clone();
    tampered.request.mission_id = MissionId::from("other-mission");
    assert!(matches!(
        consumer.verify_receipt(&tampered),
        Err(CloudStorageError::RegionTransferReceiptTampered)
    ));
    let mut cross_project = prepared.clone();
    cross_project.request.project_id = ProjectId::from("other-project");
    assert!(matches!(
        consumer.verify_receipt(&cross_project),
        Err(CloudStorageError::RegionTransferReceiptTampered)
    ));
    let revoked = provider
        .revoke(
            &source_store,
            &mut source_client,
            &source_scope,
            &prepared,
            timestamp + Duration::seconds(2),
        )
        .await
        .expect("revoke prepared transfer");
    assert_eq!(revoked.status, RegionTransferStatus::Revoked);
    assert!(matches!(
        consumer
            .adopt(
                &target_store,
                &mut target_client,
                &target_scope,
                &revoked,
                timestamp + Duration::seconds(3),
            )
            .await,
        Err(CloudStorageError::RegionTransferRevoked)
    ));

    let adoption_request = request(
        source_scope.clone(),
        project_id.clone(),
        mission_id.clone(),
        mission_payload.clone(),
        "transfer-adopted",
        "region-transfer-adopted",
        2,
        provider.clone(),
        consumer.clone(),
        metadata.content_digest.clone(),
    );
    let adoption_source = provider
        .prepare(&source_store, &mut source_client, &adoption_request)
        .await
        .expect("prepare adoptable transfer");
    let adopted = consumer
        .adopt(
            &target_store,
            &mut target_client,
            &target_scope,
            &adoption_source,
            timestamp + Duration::seconds(4),
        )
        .await
        .expect("adopt encrypted Mission snapshot");
    assert_eq!(adopted.status, RegionTransferStatus::Adopted);
    assert_eq!(adopted.adopted_revision, Some(1));
    assert_eq!(adopted.ack_generation, Some(1));
    let source_adopted = provider
        .acknowledge_adoption(
            &source_store,
            &mut source_client,
            &source_scope,
            &adoption_source,
            &adopted,
            timestamp + Duration::seconds(4),
        )
        .await
        .expect("durably acknowledge target adoption");
    assert_eq!(source_adopted.status, RegionTransferStatus::Adopted);
    assert_eq!(source_adopted.ack_generation, Some(1));
    let target_principal: String = target_client
        .query_one("SELECT current_user", &[])
        .await
        .expect("inspect target RLS principal")
        .get(0);
    let readback_provider = RegionTransferReadbackProvider::new(
        "postgres-target-readback-provider",
        DataCell::Eu,
        1,
        digest("region-transfer-readback-provider"),
        digest("region-transfer-current-commit"),
        RegionTransferReadbackProvider::principal_digest(&target_principal, &target_scope),
    );
    let verification = consumer
        .verify_target_adoption(
            &target_store,
            &mut target_client,
            &target_scope,
            &readback_provider,
            &source_adopted,
            1,
            1,
            timestamp + Duration::seconds(4),
        )
        .await
        .expect("read back and durably verify target adoption");
    assert_eq!(
        verification.status,
        RegionTransferVerificationStatus::Verified
    );
    assert!(matches!(
        verification.outcome.outcome,
        RegionTransferOutcome::Adoptable
    ));
    verification
        .verify()
        .expect("verification receipt verifies");
    assert_eq!(
        verification
            .adoptable_result()
            .expect("adoptable result")
            .ciphertext_digest,
        mission_payload.content_digest
    );
    let reopened = consumer
        .verify_target_adoption(
            &target_store,
            &mut target_client,
            &target_scope,
            &readback_provider,
            &source_adopted,
            1,
            1,
            timestamp + Duration::seconds(8),
        )
        .await
        .expect("reopen exact durable verification");
    assert_eq!(reopened, verification);
    let mut tampered_verification = verification.clone();
    tampered_verification.target_scope.cell = DataCell::Us;
    assert!(matches!(
        tampered_verification.verify(),
        Err(CloudStorageError::RegionTransferVerificationTampered)
    ));
    let mut wrong_rls_provider = readback_provider.clone();
    wrong_rls_provider.rls_principal_digest = digest("different-rls-principal");
    assert!(matches!(
        consumer
            .verify_target_adoption(
                &target_store,
                &mut target_client,
                &target_scope,
                &wrong_rls_provider,
                &source_adopted,
                1,
                2,
                timestamp + Duration::seconds(9),
            )
            .await,
        Err(CloudStorageError::RegionTransferVerificationRlsMismatch)
    ));
    assert!(matches!(
        consumer
            .verify_target_adoption(
                &target_store,
                &mut target_client,
                &target_scope,
                &readback_provider,
                &source_adopted,
                1,
                2,
                timestamp + Duration::seconds(10),
            )
            .await,
        Err(CloudStorageError::RegionTransferVerificationReplay)
    ));
    assert!(matches!(
        provider
            .revoke(
                &source_store,
                &mut source_client,
                &source_scope,
                &source_adopted,
                timestamp + Duration::seconds(5),
            )
            .await,
        Err(CloudStorageError::RegionTransferAlreadyTerminal)
    ));
    assert_eq!(
        target_store
            .load_encrypted_object(
                &mut target_client,
                &target_scope,
                &project_id,
                mission_id.as_str(),
            )
            .await
            .expect("load adopted Mission head")
            .payload
            .content_digest,
        mission_payload.content_digest
    );
    let duplicate_adoption = consumer
        .adopt(
            &target_store,
            &mut target_client,
            &target_scope,
            &adoption_source,
            timestamp + Duration::seconds(6),
        )
        .await
        .expect("exact adoption replay");
    assert_eq!(duplicate_adoption, adopted);

    let crashed_request = request(
        source_scope.clone(),
        project_id.clone(),
        mission_id.clone(),
        mission_payload,
        "transfer-crashed",
        "region-transfer-crashed",
        3,
        provider.clone(),
        consumer.clone(),
        metadata.content_digest,
    );
    let crashed_source = provider
        .prepare(&source_store, &mut source_client, &crashed_request)
        .await
        .expect("prepare crash-recovery transfer");
    let crashed = provider
        .abort_after_crash(
            &source_store,
            &mut source_client,
            &source_scope,
            &crashed_source,
            timestamp + Duration::seconds(6),
        )
        .await
        .expect("durably abort crashed transfer");
    assert_eq!(crashed.status, RegionTransferStatus::Crashed);
    assert!(matches!(
        consumer
            .adopt(
                &target_store,
                &mut target_client,
                &target_scope,
                &crashed,
                timestamp + Duration::seconds(7),
            )
            .await,
        Err(CloudStorageError::RegionTransferCrashed)
    ));

    let foreign_scope = CellScope {
        cell: DataCell::Us,
        tenant_id: TenantId::new(),
    };
    assert!(matches!(
        source_store
            .load_region_transfer_receipt(
                &mut source_client,
                &foreign_scope,
                &project_id,
                &adoption_source.request.transfer_id,
            )
            .await,
        Err(CloudStorageError::RegionTransferNotFound)
    ));

    let source_inspection = source_client
        .transaction()
        .await
        .expect("start source receipt inspection");
    source_inspection
        .query_one(
            "SELECT set_config('hartevo.tenant_id', $1, true),
                    set_config('hartevo.cell', $2, true)",
            &[
                &source_scope.tenant_id.as_str(),
                &source_scope.cell.as_str(),
            ],
        )
        .await
        .expect("set source RLS scope");
    let source_receipts: i64 = source_inspection
        .query_one(
            "SELECT count(*) FROM hartevo_cell.region_transfer_receipts
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &source_scope.cell.as_str(),
                &source_scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await
        .expect("count source receipts")
        .get(0);
    let source_events: i64 = source_inspection
        .query_one(
            "SELECT count(*) FROM hartevo_cell.region_transfer_events
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &source_scope.cell.as_str(),
                &source_scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await
        .expect("count source transfer events")
        .get(0);
    source_inspection
        .commit()
        .await
        .expect("finish source receipt inspection");
    assert_eq!(source_receipts, 3);
    assert_eq!(source_events, 6);

    let target_inspection = target_client
        .transaction()
        .await
        .expect("start target receipt inspection");
    target_inspection
        .query_one(
            "SELECT set_config('hartevo.tenant_id', $1, true),
                    set_config('hartevo.cell', $2, true)",
            &[
                &target_scope.tenant_id.as_str(),
                &target_scope.cell.as_str(),
            ],
        )
        .await
        .expect("set target RLS scope");
    let target_events: i64 = target_inspection
        .query_one(
            "SELECT count(*) FROM hartevo_cell.region_transfer_events
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &target_scope.cell.as_str(),
                &target_scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await
        .expect("count target transfer events")
        .get(0);
    assert_eq!(target_events, 1);
    let target_verifications: i64 = target_inspection
        .query_one(
            "SELECT count(*) FROM hartevo_cell.region_transfer_verification_receipts
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &target_scope.cell.as_str(),
                &target_scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await
        .expect("count target verification receipts")
        .get(0);
    let target_verification_events: i64 = target_inspection
        .query_one(
            "SELECT count(*) FROM hartevo_cell.region_transfer_verification_events
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3",
            &[
                &target_scope.cell.as_str(),
                &target_scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await
        .expect("count target verification events")
        .get(0);
    assert_eq!(target_verifications, 1);
    assert_eq!(target_verification_events, 1);
    target_inspection
        .commit()
        .await
        .expect("finish target receipt inspection");
}

use std::time::Duration;

use chrono::{TimeZone, Utc};
use hartevo_aws_dynamodb_table_result_plugin::{
    AttributeType, AwsAccountId, AwsDynamoDbEvidenceState, AwsDynamoDbProvider,
    AwsDynamoDbTableReadRequest, AwsDynamoDbTableScope, AwsDynamoDbTableService,
    AwsDynamoDbTransportError, AwsRegion, DescribeContinuousBackupsRequest,
    DescribeContinuousBackupsResponse, DescribeTableRequest, DescribeTableResponse,
    DescribeTimeToLiveRequest, DescribeTimeToLiveResponse, Digest, EncryptionKeyType,
    EncryptionPosture, EventualConsistencyFence, KeyComponent, KeyRole, ListTablesRequest,
    ListTablesResponse, ListTagsOfResourceRequest, ListTagsOfResourceResponse,
    MissionAwsDynamoDbConsumer, MissionId, OpaquePageToken, PointInTimeRecoveryStatus, ProjectId,
    RecordingTransport, RevisionId, SecretReference, TableArn, TableName, TablePosture,
    TableSchemaPosture, TableStatus, TableSummary, TtlPosture, TtlStatus, WorkProductId,
};

fn observed_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope() -> AwsDynamoDbTableScope {
    AwsDynamoDbTableScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        TableArn::new("arn:aws:dynamodb:us-east-1:123456789012:table/orders").expect("table ARN"),
        TableName::new("orders").expect("table name"),
        RevisionId::new(1).expect("table revision"),
        hartevo_aws_dynamodb_table_result_plugin::MissionIdentity::new(
            MissionId::new("mission-1").expect("Mission"),
            RevisionId::new(1).expect("Mission revision"),
        ),
        hartevo_aws_dynamodb_table_result_plugin::ProjectIdentity::new(
            ProjectId::new("project-1").expect("Project"),
            RevisionId::new(1).expect("Project revision"),
        ),
        hartevo_aws_dynamodb_table_result_plugin::WorkProductIdentity::new(
            WorkProductId::new("work-product-1").expect("Work Product"),
            RevisionId::new(1).expect("Work Product revision"),
        ),
    )
    .expect("scope")
}

fn fixture_posture(scope: &AwsDynamoDbTableScope) -> TablePosture {
    TablePosture::new(
        scope,
        "table-id-1",
        TableStatus::Active,
        TableSchemaPosture::new(vec![
            KeyComponent::new("pk", KeyRole::Partition, AttributeType::String).expect("key"),
        ])
        .expect("schema"),
        Vec::new(),
        Vec::new(),
        EncryptionPosture::new(true, EncryptionKeyType::AwsOwned, None::<&str>)
            .expect("encryption"),
        scope.table_revision(),
        observed_at(),
    )
    .expect("posture")
}

fn queued_service() -> AwsDynamoDbTableService<RecordingTransport> {
    let scope = scope();
    let secret = SecretReference::sigv4("opaque-fixture-handle", &scope, 1).expect("secret");
    let provider = AwsDynamoDbProvider::new(RecordingTransport::default()).expect("provider");
    let mut service =
        AwsDynamoDbTableService::new(scope.clone(), secret, provider).expect("service");
    let request =
        AwsDynamoDbTableReadRequest::for_scope(&scope, observed_at()).expect("read request");
    let posture = fixture_posture(&scope);
    let summary = TableSummary::from_posture(&scope, &posture).expect("summary");
    let list_request =
        ListTablesRequest::new(&scope, request.bounds(), None).expect("list request");
    let list_response = ListTablesResponse::new(
        &list_request,
        vec![summary],
        None,
        512,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Recording,
    )
    .expect("list response");
    let fence = EventualConsistencyFence::new(&scope, observed_at());
    let table_request =
        DescribeTableRequest::for_scope(&scope, fence.clone()).expect("table request");
    let table_response = DescribeTableResponse::new(
        &table_request,
        posture,
        512,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Recording,
    )
    .expect("table response");
    let backup_request =
        DescribeContinuousBackupsRequest::for_scope(&scope, fence.clone()).expect("backup request");
    let backup = hartevo_aws_dynamodb_table_result_plugin::BackupPosture::new(
        &scope,
        PointInTimeRecoveryStatus::Enabled,
        Some(observed_at()),
        Some(observed_at()),
        scope.table_revision(),
        observed_at(),
    )
    .expect("backup");
    let backup_response = DescribeContinuousBackupsResponse::new(
        &backup_request,
        backup,
        256,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Recording,
    )
    .expect("backup response");
    let ttl_request =
        DescribeTimeToLiveRequest::for_scope(&scope, fence.clone()).expect("TTL request");
    let ttl = TtlPosture::new(
        &scope,
        TtlStatus::Enabled,
        Some("expires_at"),
        scope.table_revision(),
        observed_at(),
    )
    .expect("TTL");
    let ttl_response = DescribeTimeToLiveResponse::new(
        &ttl_request,
        ttl,
        256,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Recording,
    )
    .expect("TTL response");
    let tags_request = ListTagsOfResourceRequest::for_scope(&scope, fence).expect("tag request");
    let tags = hartevo_aws_dynamodb_table_result_plugin::TagKeyPosture::new(
        &scope,
        vec!["environment".to_owned()],
        observed_at(),
    )
    .expect("tags");
    let tags_response = ListTagsOfResourceResponse::new(
        &tags_request,
        tags,
        256,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Recording,
    )
    .expect("tag response");
    let transport = service.provider_mut().transport_mut();
    transport.push_list_tables_response(Ok(list_response));
    transport.push_describe_table_response(Ok(table_response));
    transport.push_describe_continuous_backups_response(Ok(backup_response));
    transport.push_describe_time_to_live_response(Ok(ttl_response));
    transport.push_list_tags_of_resource_response(Ok(tags_response));
    service
}

#[test]
fn completed_posture_is_digest_only_and_below_kernel_authority() {
    let mut service = queued_service();
    let request =
        AwsDynamoDbTableReadRequest::for_scope(service.scope(), observed_at()).expect("request");
    let proposal = service.propose(request, observed_at()).expect("proposal");
    assert_eq!(proposal.state, AwsDynamoDbEvidenceState::Completed);
    assert_eq!(proposal.evidence.provenance.as_str(), "recording");
    assert!(proposal.evidence.table.is_some());
    assert!(proposal.evidence.backup.is_some());
    assert!(proposal.evidence.ttl.is_some());
    assert!(proposal.evidence.tags.is_some());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(proposal.evidence.is_review_only());
    assert!(!proposal.evidence.can_be_adopted());
    let serialized = serde_json::to_string(&proposal).expect("safe proposal serializes");
    assert!(!serialized.contains("orders"));
    assert!(!serialized.contains("opaque-fixture-handle"));
    assert!(!serialized.contains("environment"));
    service.verify_proposal(&proposal).expect("verify proposal");
    let record = service.record_at(&proposal, observed_at()).expect("record");
    let verified = service.verify(&record).expect("verify record");
    assert!(verified.verified);
    assert!(!verified.connected);
    assert!(!verified.native);
    let mut consumer =
        MissionAwsDynamoDbConsumer::new(service.scope().clone(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.is_review_only());
    assert!(!result.can_be_adopted());
    assert!(!result.outcome_adopted);
    let first = consumer
        .record(&proposal, "idempotency-key")
        .expect("record result");
    let replay = consumer
        .record(&proposal, "idempotency-key")
        .expect("replay result");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn access_loss_is_non_adoptable_and_transport_is_non_native() {
    let scope = scope();
    let secret = SecretReference::sigv4("opaque-access-loss", &scope, 1).expect("secret");
    let mut transport = RecordingTransport::default();
    let request = ListTablesRequest::for_scope(&scope).expect("list request");
    transport.push_list_tables_response(Err(AwsDynamoDbTransportError::Forbidden));
    let provider = AwsDynamoDbProvider::new(transport).expect("provider");
    let mut service =
        AwsDynamoDbTableService::new(scope.clone(), secret, provider).expect("service");
    let result = service
        .read(AwsDynamoDbTableReadRequest::for_scope(&scope, observed_at()).expect("request"))
        .expect("read result");
    assert_eq!(result.evidence.state, AwsDynamoDbEvidenceState::AccessLoss);
    assert!(!result.evidence.can_be_adopted());
    assert!(!service.provider().definition().connected);
    assert!(!service.provider().definition().native);
    assert_eq!(request.page_number(), 1);
}

#[test]
fn pagination_cursor_replay_fails_closed() {
    let scope = scope();
    let secret = SecretReference::sigv4("opaque-pagination", &scope, 1).expect("secret");
    let mut transport = RecordingTransport::default();
    let bounds = hartevo_aws_dynamodb_table_result_plugin::ReadBounds::layer1();
    let first_request = ListTablesRequest::new(&scope, bounds, None).expect("first request");
    let cursor_page_two = OpaquePageToken::new("cursor", &scope, 2).expect("cursor");
    let posture = fixture_posture(&scope);
    let summary = TableSummary::from_posture(&scope, &posture).expect("summary");
    transport.push_list_tables_response(Ok(ListTablesResponse::new(
        &first_request,
        vec![summary.clone()],
        Some(cursor_page_two.clone()),
        128,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Recording,
    )
    .expect("first page")));
    let second_request = ListTablesRequest::new(&scope, bounds, Some(cursor_page_two.clone()))
        .expect("second request");
    let repeated_cursor =
        OpaquePageToken::from_digest(cursor_page_two.token_digest().clone(), &scope, 3)
            .expect("repeated cursor");
    transport.push_list_tables_response(Ok(ListTablesResponse::new(
        &second_request,
        vec![summary],
        Some(repeated_cursor),
        128,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Recording,
    )
    .expect("second page")));
    let provider = AwsDynamoDbProvider::new(transport).expect("provider");
    let mut service =
        AwsDynamoDbTableService::new(scope.clone(), secret, provider).expect("service");
    let error = service
        .read(AwsDynamoDbTableReadRequest::new(scope, bounds, observed_at()).expect("request"))
        .expect_err("cursor replay must fail closed");
    assert_eq!(
        error,
        hartevo_aws_dynamodb_table_result_plugin::AwsDynamoDbTableError::PaginationLoop
    );
}

#[test]
fn tamper_and_revocation_are_rejected() {
    let mut service = queued_service();
    let request =
        AwsDynamoDbTableReadRequest::for_scope(service.scope(), observed_at()).expect("request");
    let mut proposal = service.propose(request, observed_at()).expect("proposal");
    proposal.evidence.evidence_digest = Digest::from_text("tampered");
    assert!(service.verify_proposal(&proposal).is_err());
    service.revoke_registration().expect("revoke");
    let request =
        AwsDynamoDbTableReadRequest::for_scope(service.scope(), observed_at()).expect("request");
    assert!(service.propose(request, observed_at()).is_err());
    service.restore_registration().expect("restore");
    service.reverse_registration().expect("reverse");
    let request =
        AwsDynamoDbTableReadRequest::for_scope(service.scope(), observed_at()).expect("request");
    assert!(service.propose(request, observed_at()).is_err());
}

#[test]
fn opaque_secret_reference_redacts_debug_output() {
    let scope = scope();
    let secret = SecretReference::sigv4("never-print-this-handle", &scope, 1).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("never-print-this-handle"));
    assert!(debug.contains("reference_digest"));
}

#[test]
fn bounded_fixture_types_do_not_claim_native_provenance() {
    let fixtures = [
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Fixture,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::Loopback,
        hartevo_aws_dynamodb_table_result_plugin::TransportProvenance::BlockedEnv,
    ];
    for provenance in fixtures {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

#[test]
fn no_unbounded_waits_are_needed_for_fixture_reads() {
    let mut service = queued_service();
    let started = std::time::Instant::now();
    let request =
        AwsDynamoDbTableReadRequest::for_scope(service.scope(), observed_at()).expect("request");
    let _ = service.propose(request, observed_at()).expect("proposal");
    assert!(started.elapsed() < Duration::from_secs(1));
}

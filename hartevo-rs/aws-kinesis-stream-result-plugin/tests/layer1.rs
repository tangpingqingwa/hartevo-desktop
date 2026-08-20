use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_kinesis_stream_result_plugin::{
    AwsAccountId, AwsKinesisProvider, AwsKinesisStreamResultService, AwsKinesisStreamScope,
    AwsKinesisTransportError, AwsRegion, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON,
    CONTRACT_SCHEMA, CONTRACT_VERSION, ConsentScope, ConsumerArn, ConsumerIdentity, ConsumerName,
    Cursor, DescribeStreamSummaryRequest, DescribeStreamSummaryResponse, Digest, EncryptionType,
    FixtureTransport, KinesisEvidenceState, ListShardsResponse, MissionIdentity, ProjectIdentity,
    RecordingTransport, SecretReference, ShardFilter, ShardMetadataInput, StreamArn,
    StreamIdentity, StreamMode, StreamName, StreamStatus, StreamSummary, StreamSummaryInput,
    TransportProvenance, WorkProductIdentity, contract_digest,
};
use proptest::prelude::*;
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_STREAM_ARN: &str = "arn:aws:kinesis:us-east-1:123456789012:stream/orders";
const RAW_CONSUMER_ARN: &str =
    "arn:aws:kinesis:us-east-1:123456789012:stream/orders/consumer/mission-reader:1";
const RAW_SECRET: &str = "opaque-sigv4-kinesis-secret-handle";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope(with_consumer: bool) -> AwsKinesisStreamScope {
    AwsKinesisStreamScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        StreamIdentity::new(
            StreamArn::new(RAW_STREAM_ARN).expect("stream arn"),
            StreamName::new("orders").expect("stream name"),
        )
        .expect("stream identity"),
        hartevo_aws_kinesis_stream_result_plugin::StreamVersion::new(NOW_SECONDS - 86_400)
            .expect("stream version"),
        ShardFilter::at_trim_horizon(),
        with_consumer.then(|| {
            ConsumerIdentity::new(
                ConsumerArn::new(RAW_CONSUMER_ARN).expect("consumer arn"),
                ConsumerName::new("mission-reader").expect("consumer name"),
            )
            .expect("consumer identity")
        }),
        MissionIdentity::new("mission-kinesis-834", 7).expect("mission"),
        ProjectIdentity::new("project-kinesis-834", 11).expect("project"),
        WorkProductIdentity::new("work-product-kinesis-834", 13).expect("work product"),
    )
    .expect("scope")
}

fn service() -> AwsKinesisStreamResultService<FixtureTransport> {
    let scope = scope(true);
    let provider = hartevo_aws_kinesis_stream_result_plugin::AwsKinesisProvider::new(
        FixtureTransport::for_scope(&scope, now()),
    )
    .expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_layer_one("consent-kinesis-834", 1, now() + Duration::days(7))
        .expect("consent");
    AwsKinesisStreamResultService::new(scope, secret, consent, provider, now()).expect("service")
}

fn recorded_service(
    scope: &AwsKinesisStreamScope,
    statuses: &[StreamStatus],
) -> AwsKinesisStreamResultService<RecordingTransport> {
    let summary_request = DescribeStreamSummaryRequest::for_scope(scope).expect("summary request");
    let list_request = hartevo_aws_kinesis_stream_result_plugin::ListShardsRequest::new(
        scope,
        scope.shard_filter().clone(),
        None,
        100,
    )
    .expect("list request");
    let mut transport = RecordingTransport::default();
    for status in statuses {
        let summary = StreamSummary::new(
            scope,
            StreamSummaryInput {
                status: *status,
                mode: StreamMode::Provisioned,
                retention_period_hours: 24,
                open_shard_count: 0,
                creation_timestamp_epoch_seconds: scope.stream_version().value(),
                monitoring_metrics: Vec::new(),
                encryption_type: EncryptionType::None,
                encryption_key_id: None,
                max_record_size_kib: None,
            },
        )
        .expect("summary");
        transport.push_summary_response(Ok(DescribeStreamSummaryResponse::new(
            &summary_request,
            summary,
            512,
            TransportProvenance::Recording,
        )
        .expect("summary response")));
        transport.push_shard_response(Ok(ListShardsResponse::new(
            &list_request,
            Vec::new(),
            None,
            512,
            TransportProvenance::Recording,
        )
        .expect("shard response")));
    }
    let provider = AwsKinesisProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, scope, 1).expect("secret");
    let consent = ConsentScope::for_layer_one("consent-recorded", 1, now() + Duration::days(7))
        .expect("consent");
    AwsKinesisStreamResultService::new(scope.clone(), secret, consent, provider, now())
        .expect("service")
}

fn service_with_summary_error(
    error: AwsKinesisTransportError,
) -> AwsKinesisStreamResultService<RecordingTransport> {
    let scope = scope(false);
    let mut transport = RecordingTransport::default();
    transport.push_summary_response(Err(error));
    let provider = AwsKinesisProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_layer_one("consent-error", 1, now() + Duration::days(7))
        .expect("consent");
    AwsKinesisStreamResultService::new(scope, secret, consent, provider, now()).expect("service")
}

#[test]
fn contract_and_registration_are_digest_bound_without_secret_material() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract_digest(), CONTRACT_DIGEST);

    let service = service();
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert!(service.registration().validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
}

#[test]
fn fixture_result_is_bounded_digest_only_and_mission_scoped() {
    let mut service = service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, KinesisEvidenceState::Active);
    assert!(proposal.list_complete);
    assert_eq!(proposal.list_pages, 1);
    let stream = proposal.stream.as_ref().expect("stream projection");
    assert_eq!(stream.open_shard_count, 2);
    assert_eq!(stream.shard_count, 2);
    assert!(stream.encryption.encrypted);
    assert!(stream.monitoring.enabled);
    assert!(stream.consumer.is_some());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.truth_authority);
    assert!(!proposal.consent_authority);
    assert!(!proposal.effect_authority);
    assert!(!proposal.receipt_authority);
    assert!(!proposal.verification_authority);
    assert!(!proposal.outcome_adopted);
    assert!(!proposal.work_product_adopted);
    assert!(proposal.validate_integrity().is_ok());
    assert!(service.verify(&proposal).valid);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_STREAM_ARN,
        RAW_CONSUMER_ARN,
        RAW_SECRET,
        "shardId-000000000001",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    let mut consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("consume");
    assert!(mission_result.review_only);
    assert!(!mission_result.can_be_adopted());
    let recorded = consumer
        .record(&proposal, "record-kinesis-834")
        .expect("record");
    let replay = consumer
        .record(&proposal, "record-kinesis-834")
        .expect("replay");
    assert!(!recorded.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn all_offline_provenances_are_honest() {
    let scope = scope(false);
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_native());
        assert!(!provenance.claims_connected());
        assert!(!provenance.claims_first_party());
    }
    let blocked_provider =
        hartevo_aws_kinesis_stream_result_plugin::AwsKinesisProvider::new(BlockedEnvTransport)
            .expect("blocked provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_layer_one("consent-blocked", 1, now() + Duration::days(7))
        .expect("consent");
    let mut service =
        AwsKinesisStreamResultService::new(scope, secret, consent, blocked_provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, KinesisEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn token_binding_expiry_filter_drift_and_replay_fail_closed() {
    let current_scope = scope(false);
    let filter = ShardFilter::at_trim_horizon();
    let cursor = Cursor::new_at(
        "opaque-next-token",
        &current_scope,
        &filter,
        2,
        now() - Duration::seconds(301),
    )
    .expect("cursor");
    assert_eq!(cursor.scope_digest(), &current_scope.digest());
    assert_eq!(cursor.filter_digest(), &filter.digest());
    assert!(
        cursor
            .validate_against(&current_scope, &filter, now())
            .is_err()
    );
    let after_filter = ShardFilter::after_shard_id("shardId-000000000001").expect("filter");
    assert_ne!(after_filter.digest(), filter.digest());
    assert!(
        hartevo_aws_kinesis_stream_result_plugin::ListShardsRequest::new(
            &current_scope,
            after_filter,
            None,
            100,
        )
        .is_ok()
    );

    let mut service = service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    consumer
        .record(&proposal, "same-key")
        .expect("first record");
    let mut changed = proposal.clone();
    changed.state = KinesisEvidenceState::Tampered;
    changed.proposal_digest = Digest::from_text("changed-proposal");
    assert_eq!(
        consumer
            .record(&changed, "same-key")
            .expect_err("replay conflict accepted"),
        hartevo_aws_kinesis_stream_result_plugin::AwsKinesisStreamResultError::TamperedEvidence
    );
}

#[test]
fn registration_reversal_and_stale_mission_are_rejected() {
    let mut reversed_service = service();
    let request = reversed_service.default_request(now()).expect("request");
    reversed_service.reverse().expect("reverse");
    assert!(!reversed_service.registration().is_active());
    assert!(reversed_service.propose(request).is_err());

    let mut second_service = service();
    let proposal = second_service
        .propose(second_service.default_request(now()).expect("request"))
        .expect("proposal");
    let consumer = second_service.consumer().expect("consumer");
    assert_eq!(
        consumer
            .consume_for_mission_revision(&proposal, 999)
            .expect_err("stale mission accepted"),
        hartevo_aws_kinesis_stream_result_plugin::AwsKinesisStreamResultError::StaleMissionRevision
    );
}

#[test]
fn response_tamper_and_provider_errors_are_bounded() {
    let scope = scope(false);
    let summary_request =
        hartevo_aws_kinesis_stream_result_plugin::DescribeStreamSummaryRequest::for_scope(&scope)
            .expect("summary request");
    let summary = StreamSummary::new(
        &scope,
        StreamSummaryInput {
            status: StreamStatus::Active,
            mode: StreamMode::Provisioned,
            retention_period_hours: 24,
            open_shard_count: 1,
            creation_timestamp_epoch_seconds: scope.stream_version().value(),
            monitoring_metrics: Vec::new(),
            encryption_type: EncryptionType::None,
            encryption_key_id: None,
            max_record_size_kib: None,
        },
    )
    .expect("summary");
    let response = hartevo_aws_kinesis_stream_result_plugin::DescribeStreamSummaryResponse::new(
        &summary_request,
        summary,
        256,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered"));
    let mut transport = RecordingTransport::default();
    transport.push_summary_response(Ok(response));
    let provider = hartevo_aws_kinesis_stream_result_plugin::AwsKinesisProvider::new(transport)
        .expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_layer_one("consent-tamper", 1, now() + Duration::days(7))
        .expect("consent");
    let mut service = AwsKinesisStreamResultService::new(scope, secret, consent, provider, now())
        .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("tampered proposal");
    assert_eq!(proposal.state, KinesisEvidenceState::Tampered);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "invalid_response"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert_ne!(
        AwsKinesisTransportError::TokenExpired.status_code(),
        Some(200)
    );
}

#[test]
fn status_scope_and_posture_drift_fail_closed() {
    assert_eq!(StreamStatus::from_api("CREATING"), StreamStatus::Creating);
    assert_eq!(StreamStatus::from_api("UPDATING"), StreamStatus::Updating);
    assert_eq!(StreamStatus::from_api("DELETING"), StreamStatus::Deleting);
    assert_eq!(StreamStatus::from_api("future"), StreamStatus::Unknown);
    assert_eq!(
        KinesisEvidenceState::from(StreamStatus::Updating),
        KinesisEvidenceState::Updating
    );
    assert_eq!(
        KinesisEvidenceState::from(StreamStatus::Unknown),
        KinesisEvidenceState::ProviderUnknown
    );

    let valid_scope = scope(false);
    let mismatched_stream = StreamIdentity::new(
        StreamArn::new("arn:aws:kinesis:us-west-2:123456789012:stream/orders").expect("stream arn"),
        StreamName::new("orders").expect("stream name"),
    )
    .expect("stream identity");
    assert!(
        AwsKinesisStreamScope::new(
            valid_scope.account().clone(),
            valid_scope.region().clone(),
            mismatched_stream,
            valid_scope.stream_version(),
            valid_scope.shard_filter().clone(),
            None,
            valid_scope.mission().clone(),
            valid_scope.project().clone(),
            valid_scope.work_product().clone(),
        )
        .is_err()
    );

    let drifted_version = StreamSummary::new(
        &valid_scope,
        StreamSummaryInput {
            status: StreamStatus::Active,
            mode: StreamMode::Provisioned,
            retention_period_hours: 24,
            open_shard_count: 1,
            creation_timestamp_epoch_seconds: valid_scope.stream_version().value() + 1,
            monitoring_metrics: Vec::new(),
            encryption_type: EncryptionType::None,
            encryption_key_id: None,
            max_record_size_kib: None,
        },
    );
    assert!(drifted_version.is_err());

    assert!(
        StreamSummary::new(
            &valid_scope,
            StreamSummaryInput {
                status: StreamStatus::Active,
                mode: StreamMode::Provisioned,
                retention_period_hours: 24,
                open_shard_count: 1,
                creation_timestamp_epoch_seconds: valid_scope.stream_version().value(),
                monitoring_metrics: Vec::new(),
                encryption_type: EncryptionType::Kms,
                encryption_key_id: None,
                max_record_size_kib: None,
            },
        )
        .is_err()
    );
    assert!(
        StreamSummary::new(
            &valid_scope,
            StreamSummaryInput {
                status: StreamStatus::Active,
                mode: StreamMode::Provisioned,
                retention_period_hours: 24,
                open_shard_count: 1,
                creation_timestamp_epoch_seconds: valid_scope.stream_version().value(),
                monitoring_metrics: vec!["invalid metric".to_owned()],
                encryption_type: EncryptionType::None,
                encryption_key_id: None,
                max_record_size_kib: None,
            },
        )
        .is_err()
    );
}

#[test]
fn partial_access_timeout_and_replay_conflict_are_fail_closed() {
    for (error, state) in [
        (
            AwsKinesisTransportError::Partial,
            KinesisEvidenceState::Partial,
        ),
        (
            AwsKinesisTransportError::Unauthorized,
            KinesisEvidenceState::AccessLost,
        ),
        (
            AwsKinesisTransportError::Timeout,
            KinesisEvidenceState::ProviderUnknown,
        ),
        (
            AwsKinesisTransportError::BadRequest,
            KinesisEvidenceState::ProviderUnknown,
        ),
    ] {
        let mut service = service_with_summary_error(error);
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, state);
        assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    }

    let replay_scope = scope(false);
    let mut service = recorded_service(
        &replay_scope,
        &[StreamStatus::Active, StreamStatus::Updating],
    );
    let request = service.default_request(now()).expect("request");
    let first = service.propose(request.clone()).expect("first proposal");
    let second = service.propose(request).expect("second proposal");
    assert_eq!(second.state, KinesisEvidenceState::Updating);
    let mut consumer = service.consumer().expect("consumer");
    consumer.record(&first, "same-key").expect("first record");
    assert_eq!(
        consumer
            .record(&second, "same-key")
            .expect_err("replay conflict accepted"),
        hartevo_aws_kinesis_stream_result_plugin::AwsKinesisStreamResultError::ReplayConflict
    );
}

#[test]
fn revocation_and_secret_revocation_are_fail_closed() {
    let mut revoked = service();
    let request = revoked.default_request(now()).expect("request");
    revoked.revoke().expect("revoke");
    assert_eq!(
        revoked.registration().status(),
        hartevo_aws_kinesis_stream_result_plugin::RegistrationStatus::Revoked
    );
    assert_eq!(
        revoked
            .propose(request)
            .expect_err("revoked registration accepted"),
        hartevo_aws_kinesis_stream_result_plugin::AwsKinesisStreamResultError::RegistrationInactive
    );

    let mut secret_revoked = service();
    let request = secret_revoked.default_request(now()).expect("request");
    secret_revoked
        .registration_mut()
        .secret_reference_mut()
        .revoke();
    assert_eq!(
        secret_revoked
            .propose(request)
            .expect_err("revoked secret accepted"),
        hartevo_aws_kinesis_stream_result_plugin::AwsKinesisStreamResultError::SecretRevoked
    );
}

#[test]
fn shard_inputs_never_serialize_raw_lineage() {
    let input = ShardMetadataInput::new(
        "shardId-000000000001",
        Some("shardId-parent"),
        Some("shardId-adjacent"),
    );
    let debug = format!("{input:?}");
    assert!(!debug.contains("shardId-000000000001"));
    assert!(debug.contains("shard-id:"));
    let input_debug = format!(
        "{:?}",
        StreamSummaryInput {
            status: StreamStatus::Active,
            mode: StreamMode::Provisioned,
            retention_period_hours: 24,
            open_shard_count: 1,
            creation_timestamp_epoch_seconds: NOW_SECONDS - 86_400,
            monitoring_metrics: vec!["IncomingBytes".to_owned()],
            encryption_type: EncryptionType::Kms,
            encryption_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/raw".to_owned()),
            max_record_size_kib: None,
        }
    );
    assert!(!input_debug.contains("arn:aws:kms"));
    let scope = scope(false);
    let summary = StreamSummary::new(
        &scope,
        StreamSummaryInput {
            status: StreamStatus::Creating,
            mode: StreamMode::OnDemand,
            retention_period_hours: 24,
            open_shard_count: 1,
            creation_timestamp_epoch_seconds: scope.stream_version().value(),
            monitoring_metrics: vec!["IncomingBytes".to_owned()],
            encryption_type: EncryptionType::None,
            encryption_key_id: None,
            max_record_size_kib: None,
        },
    )
    .expect("summary");
    let lineage =
        hartevo_aws_kinesis_stream_result_plugin::ShardLineageProjection::from_input(input)
            .expect("lineage");
    let projection = hartevo_aws_kinesis_stream_result_plugin::StreamProjection::from_parts(
        &scope,
        &summary,
        vec![lineage],
        None,
    )
    .expect("projection");
    let serialized = serde_json::to_string(&projection).expect("projection JSON");
    assert!(!serialized.contains("shardId-000000000001"));
    assert!(!serialized.contains("shardId-parent"));
}

proptest! {
    #[test]
    fn nonpositive_timestamp_filters_fail_closed(timestamp in any::<i64>()) {
        let accepted = ShardFilter::at_timestamp(timestamp).is_ok();
        prop_assert_eq!(accepted, timestamp > 0);
    }
}

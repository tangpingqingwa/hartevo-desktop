#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Duration, Utc};
use hartevo_aws_sns_topic_result_plugin::{
    AwsAccountId, AwsRegion, AwsSnsOperation, AwsSnsProvider, AwsSnsTopicReadRequest,
    AwsSnsTopicScope, AwsSnsTopicService, AwsSnsTransportError, BlockedEnvTransport,
    ConfirmationState, ConsentScope, ConsumerDeploymentIdentity, DeploymentId, Digest,
    EvidenceState, FixtureTransport, GetTopicAttributesRequest, ListTopicsRequest,
    ListTopicsResponse, LoopbackTransport, MissionAwsSnsConsumer, MissionId, MissionIdentity,
    OpaqueCursor, PermissionSnapshot, ProjectId, ProjectIdentity, RecordingTransport,
    SecretReference, SubscriptionArn, SubscriptionIdentity, SubscriptionPosture, TopicArn,
    TopicIdentity, TopicPosture, TopicRecord, TransportProvenance, WorkProductId,
    WorkProductIdentity,
};

type FixtureService = AwsSnsTopicService<FixtureTransport>;
type RecordingService = AwsSnsTopicService<RecordingTransport>;

fn at(hour: u8) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-08-15T{hour:02}:00:00Z"))
        .expect("valid timestamp")
        .with_timezone(&Utc)
}

fn scope() -> AwsSnsTopicScope {
    AwsSnsTopicScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        TopicIdentity::new(
            TopicArn::new("arn:aws:sns:us-east-1:123456789012:fanout.fifo").expect("topic"),
        ),
        vec![
            SubscriptionIdentity::new(
                SubscriptionArn::new(
                    "arn:aws:sns:us-east-1:123456789012:fanout.fifo:00000000-0000-0000-0000-000000000001",
                )
                .expect("subscription one"),
            ),
            SubscriptionIdentity::new(
                SubscriptionArn::new(
                    "arn:aws:sns:us-east-1:123456789012:fanout.fifo:00000000-0000-0000-0000-000000000002",
                )
                .expect("subscription two"),
            ),
        ],
        ConsumerDeploymentIdentity::new(DeploymentId::new("deployment-1").expect("deployment"), 4)
            .expect("deployment binding"),
        MissionIdentity::new(MissionId::new("mission-1").expect("mission"), 8)
            .expect("mission binding"),
        ProjectIdentity::new(ProjectId::new("project-1").expect("project"), 5)
            .expect("project binding"),
        WorkProductIdentity::new(
            WorkProductId::new("work-product-1").expect("work product"),
            6,
        )
        .expect("work product binding"),
    )
    .expect("scope")
}

fn secret(scope: &AwsSnsTopicScope) -> SecretReference {
    SecretReference::for_scope("opaque-sigv4-keyring-reference", scope, 3).expect("secret")
}

fn permission() -> PermissionSnapshot {
    PermissionSnapshot::for_layer_one(2)
}

fn consent(now: DateTime<Utc>) -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 7, now + Duration::hours(2)).expect("consent")
}

fn fixture_service() -> FixtureService {
    let scope = scope();
    let now = at(1);
    AwsSnsTopicService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        consent(now),
        AwsSnsProvider::new(FixtureTransport::for_scope(&scope).expect("fixture transport"))
            .expect("provider"),
        now,
    )
    .expect("service")
}

fn recording_service_with(
    response: std::result::Result<ListTopicsResponse, AwsSnsTransportError>,
) -> RecordingService {
    let scope = scope();
    let now = at(1);
    let mut transport = RecordingTransport::default();
    transport.push_list_topics(response);
    AwsSnsTopicService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        consent(now),
        AwsSnsProvider::new(transport).expect("provider"),
        now,
    )
    .expect("service")
}

fn request_for(scope: &AwsSnsTopicScope, now: DateTime<Utc>) -> AwsSnsTopicReadRequest {
    AwsSnsTopicReadRequest::new(scope, 4, 50, now).expect("read request")
}

#[test]
fn contract_scope_registration_and_capabilities_are_explicit() {
    let service = fixture_service();
    assert_eq!(service.provider().definition().operations.len(), 4);
    assert!(service.is_active());
    assert_eq!(
        service.registration().provider_id,
        "aws.sns.topic-result.recording"
    );
    assert_ne!(service.registration().scope_digest, Digest::zero());
    assert_ne!(
        service.registration().permission_snapshot_digest,
        Digest::zero()
    );
    assert_ne!(service.registration().evidence_digest, Digest::zero());
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.recording_only);
    assert!(!capabilities.external_writes);
    assert!(!capabilities.kernel_authority);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.adopts_outcome);
    assert!(!capabilities.adopts_work_product);

    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains("opaque-sigv4-keyring-reference"));
    assert!(
        !format!("{:?}", service.secret_reference()).contains("opaque-sigv4-keyring-reference")
    );
    assert!(!format!("{:?}", service.scope()).contains("arn:aws:sns"));
}

#[test]
fn fixture_complete_posture_is_review_only_and_recordable() {
    let mut service = fixture_service();
    let scope = service.scope().clone();
    let proposal = service
        .propose(service.default_request(at(1)).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Complete);
    assert!(proposal.evidence.list_topics_complete);
    assert!(proposal.evidence.list_subscriptions_complete);
    assert_eq!(proposal.evidence.subscription_postures.len(), 2);
    assert_eq!(
        proposal.evidence.subscription_postures[0].confirmation,
        ConfirmationState::Confirmed
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert!(service.verify(&proposal).valid);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        "arn:aws:sns:us-east-1:123456789012:fanout.fifo",
        "00000000-0000-0000-0000-000000000001",
    ] {
        assert!(
            !serialized.contains(raw),
            "raw SNS identifier leaked: {raw}"
        );
    }
    assert!(!serialized.contains("opaque-sigv4-keyring-reference"));
    assert!(!serialized.contains("endpointAddress"));

    let mut consumer =
        MissionAwsSnsConsumer::new(scope, service.registration().clone()).expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("Mission result");
    assert!(mission_result.requires_human_review);
    assert!(!mission_result.safe_to_promote);
    assert!(!mission_result.adopted_outcome);
    assert!(!mission_result.adopted_work_product);
    assert!(!mission_result.truth_authority);
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope();
    let now = at(1);
    let mut loopback = AwsSnsTopicService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        consent(now),
        AwsSnsProvider::new(LoopbackTransport::for_scope(&scope).expect("loopback transport"))
            .expect("provider"),
        now,
    )
    .expect("loopback service");
    let loopback_proposal = loopback
        .propose(request_for(&scope, now))
        .expect("loopback proposal");
    assert_eq!(
        loopback_proposal.evidence.provenance,
        TransportProvenance::Loopback
    );
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);

    let mut blocked = AwsSnsTopicService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        consent(now),
        AwsSnsProvider::new(BlockedEnvTransport).expect("provider"),
        now,
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .propose(request_for(&scope, now))
        .expect("blocked proposal");
    assert_eq!(blocked_proposal.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        blocked_proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "blocked_env"
    );
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
    assert!(!blocked_proposal.first_party);
}

#[test]
fn transport_statuses_fail_closed_without_raw_error_retention() {
    let cases = [
        (
            AwsSnsTransportError::BadRequest,
            EvidenceState::ProviderUnknown,
            Some(400),
        ),
        (
            AwsSnsTransportError::Unauthorized,
            EvidenceState::AccessLoss,
            Some(401),
        ),
        (
            AwsSnsTransportError::Forbidden,
            EvidenceState::AccessLoss,
            Some(403),
        ),
        (
            AwsSnsTransportError::NotFound,
            EvidenceState::NotFound,
            Some(404),
        ),
        (
            AwsSnsTransportError::RateLimited {
                retry_after_seconds: Some(3),
            },
            EvidenceState::Throttled,
            Some(429),
        ),
        (
            AwsSnsTransportError::ServerError { status: 500 },
            EvidenceState::ProviderUnknown,
            Some(500),
        ),
        (
            AwsSnsTransportError::Timeout,
            EvidenceState::ProviderUnknown,
            None,
        ),
    ];
    for (error, state, status_code) in cases {
        let mut service = recording_service_with(Err(error));
        let proposal = service
            .propose(service.default_request(at(1)).expect("request"))
            .expect("proposal");
        assert_eq!(proposal.state, state);
        assert_eq!(
            proposal
                .evidence
                .failure
                .as_ref()
                .expect("failure")
                .status_code,
            status_code
        );
        assert!(
            !serde_json::to_string(&proposal)
                .expect("proposal JSON")
                .contains("AWS SNS")
        );
        assert!(!proposal.connected);
        assert!(!proposal.native);
    }
}

#[test]
fn tamper_replacement_and_pagination_loops_fail_closed() {
    let scope = scope();
    let now = at(1);
    let request = ListTopicsRequest::new(&scope, 50, None).expect("list request");
    let tampered = ListTopicsResponse::new(
        &request,
        vec![TopicRecord::new(scope.topic(), TopicPosture::fixture())],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered"));
    let mut tampered_service = recording_service_with(Ok(tampered));
    let tampered_proposal = tampered_service
        .propose(request_for(&scope, now))
        .expect("proposal");
    assert_eq!(tampered_proposal.state, EvidenceState::Tampered);
    assert!(!tampered_service.verify(&tampered_proposal).valid);

    let other_topic = TopicIdentity::new(
        TopicArn::new("arn:aws:sns:us-east-1:123456789012:replacement.fifo").expect("other topic"),
    );
    let replacement_request = ListTopicsRequest::new(&scope, 50, None).expect("list request");
    let replacement = ListTopicsResponse::new(
        &replacement_request,
        vec![TopicRecord::new(&other_topic, TopicPosture::fixture())],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("response");
    let mut replacement_service = recording_service_with(Ok(replacement));
    let replacement_proposal = replacement_service
        .propose(request_for(&scope, now))
        .expect("proposal");
    assert_eq!(replacement_proposal.state, EvidenceState::TopicReplaced);

    let loop_request = ListTopicsRequest::new(&scope, 50, None).expect("first request");
    let repeated_cursor = OpaqueCursor::new("opaque-loop-token").expect("cursor");
    let first_page = ListTopicsResponse::new(
        &loop_request,
        vec![TopicRecord::new(scope.topic(), TopicPosture::fixture())],
        Some(repeated_cursor.clone()),
        256,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let second_request =
        ListTopicsRequest::new(&scope, 50, Some(repeated_cursor.clone())).expect("second request");
    let second_page = ListTopicsResponse::new(
        &second_request,
        vec![TopicRecord::new(scope.topic(), TopicPosture::fixture())],
        Some(repeated_cursor),
        256,
        TransportProvenance::Recording,
    )
    .expect("second page");
    let mut loop_transport = RecordingTransport::default();
    loop_transport.push_list_topics(Ok(first_page));
    loop_transport.push_list_topics(Ok(second_page));
    let mut loop_service = AwsSnsTopicService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        consent(now),
        AwsSnsProvider::new(loop_transport).expect("provider"),
        now,
    )
    .expect("service");
    let loop_proposal = loop_service
        .propose(request_for(&scope, now))
        .expect("proposal");
    assert_eq!(loop_proposal.state, EvidenceState::Partial);
}

#[test]
fn reversible_registration_and_secret_revocation_are_fail_closed() {
    let mut service = fixture_service();
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(
        reversed.new_status,
        hartevo_aws_sns_topic_result_plugin::RegistrationStatus::Reversed
    );
    let proposal = service
        .propose(service.default_request(at(1)).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, EvidenceState::RegistrationRevoked);
    assert!(!service.verify(&proposal).valid);
    service.restore_registration().expect("restore");
    service.revoke_secret_reference();
    let revoked_secret = service
        .propose(service.default_request(at(1)).expect("request"))
        .expect("proposal");
    assert_eq!(revoked_secret.state, EvidenceState::ProviderUnknown);
}

#[test]
fn subscription_posture_never_retains_endpoint_or_filter_values() {
    let identity = SubscriptionIdentity::new(
        SubscriptionArn::new(
            "arn:aws:sns:us-east-1:123456789012:fanout.fifo:00000000-0000-0000-0000-000000000001",
        )
        .expect("subscription"),
    );
    let posture = SubscriptionPosture::new(
        &identity,
        "sqs",
        ConfirmationState::Confirmed,
        Some(r#"{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq"}"#.to_owned()),
        Some(r#"{"tenant":"private-value"}"#.to_owned()),
    )
    .expect("posture");
    let encoded = serde_json::to_string(&posture).expect("posture JSON");
    assert!(!encoded.contains("deadLetterTargetArn"));
    assert!(!encoded.contains("private-value"));
    assert!(!encoded.contains("arn:aws:sqs"));
    assert!(encoded.contains("redrivePolicyDigest"));
    assert!(encoded.contains("filterPolicyDigest"));
}

#[test]
fn imported_types_keep_native_credential_and_write_surfaces_absent() {
    let _ = AwsSnsOperation::ListTopics;
    let _ = GetTopicAttributesRequest::new(&scope()).expect("request");
}

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_cost_anomaly_result_plugin::{
    AnomalyEvidenceState, AnomalyFeedback, AnomalyFilter, AnomalyId, AnomalyIdentity,
    AnomalyMetadata, AnomalyMetadataInput, AnomalyWindow, AwsAccountId, AwsCostAnomalyProvider,
    AwsCostAnomalyScope, AwsCostAnomalyService, AwsCostAnomalyTransport,
    AwsCostAnomalyTransportError, AwsRegion, BlockedEnvTransport, ConsentScope, Cursor,
    DeploymentId, DeploymentIdentity, Digest, FixtureTransport, GetAnomaliesRequest,
    GetAnomaliesResponse, GetAnomalyMonitorsRequest, GetAnomalyMonitorsResponse,
    GetAnomalySubscriptionsRequest, GetAnomalySubscriptionsResponse, LoopbackTransport, MissionId,
    MissionIdentity, MonitorArn, MonitorFilter, MonitorMetadata, MonitorMetadataInput,
    MonitorStatus, MonitorType, PermissionSnapshot, ProjectId, ProjectIdentity,
    RecordedAwsCostAnomalyResult, RecordingTransport, SecretReference, ServiceName,
    ServiceRevisionIdentity, SubscriptionArn, SubscriptionFilter, SubscriptionFrequency,
    SubscriptionMetadata, SubscriptionMetadataInput, SubscriptionStatus, TransportProvenance,
    WorkProductId, WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_OPAQUE_HANDLE: &str = "opaque-sigv4-handle";
const RAW_MONITOR_ARN: &str = "arn:aws:ce::123456789012:anomaly-monitor/fixture-monitor";
const RAW_SUBSCRIPTION_ARN: &str =
    "arn:aws:ce::123456789012:anomaly-subscription/fixture-subscription";
const RAW_ANOMALY_ID: &str = "fixture-anomaly";
const RAW_MONITOR_NAME: &str = "fixture-monitor-name";
const RAW_SUBSCRIBER: &str = "subscriber@example.test";
const RAW_ROOT_CAUSE: &str = "raw-root-cause-dimension";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsCostAnomalyScope {
    AwsCostAnomalyScope::new(
        AwsAccountId::new("123456789012").expect("management account"),
        AwsAccountId::new("210987654321").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        MonitorArn::new(RAW_MONITOR_ARN).expect("monitor"),
        AnomalyIdentity::new(
            AnomalyId::new(RAW_ANOMALY_ID).expect("anomaly id"),
            AnomalyWindow::new(now() - Duration::days(2), now() - Duration::hours(1))
                .expect("window"),
        )
        .expect("anomaly"),
        DeploymentIdentity::new(DeploymentId::new("deployment-7").expect("deployment"), 7)
            .expect("deployment identity"),
        ServiceRevisionIdentity::new(ServiceName::new("billing-service").expect("service"), 11)
            .expect("service revision"),
        SubscriptionArn::new(RAW_SUBSCRIPTION_ARN).expect("subscription"),
        MissionIdentity::new(MissionId::new("mission-1").expect("mission"), 3)
            .expect("mission identity"),
        ProjectIdentity::new(ProjectId::new("project-1").expect("project"), 5)
            .expect("project identity"),
        WorkProductIdentity::new(
            WorkProductId::new("work-product-1").expect("work product"),
            9,
        )
        .expect("work product identity"),
    )
    .expect("scope")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 1, now() + Duration::days(7)).expect("consent")
}

fn secret(scope: &AwsCostAnomalyScope) -> SecretReference {
    SecretReference::sigv4(RAW_OPAQUE_HANDLE, scope, 1).expect("secret reference")
}

fn anomaly(scope: &AwsCostAnomalyScope) -> AnomalyMetadata {
    AnomalyMetadata::new(
        scope,
        AnomalyMetadataInput {
            anomaly_id: scope.anomaly().id().clone(),
            monitor_arn: scope.monitor().clone(),
            window: scope.anomaly().window().clone(),
            impact_usd: Some(500),
            feedback: AnomalyFeedback::Negative,
            root_cause_dimensions: vec![RAW_ROOT_CAUSE.to_owned()],
        },
    )
    .expect("anomaly metadata")
}

fn monitor(scope: &AwsCostAnomalyScope) -> MonitorMetadata {
    MonitorMetadata::new(
        scope,
        MonitorMetadataInput {
            monitor_arn: scope.monitor().clone(),
            monitor_name: RAW_MONITOR_NAME.to_owned(),
            monitor_type: MonitorType::Dimensional,
            status: MonitorStatus::Active,
            evaluation_start: Some(now() - Duration::days(7)),
            evaluation_end: Some(now()),
        },
    )
    .expect("monitor metadata")
}

fn subscription(scope: &AwsCostAnomalyScope) -> SubscriptionMetadata {
    SubscriptionMetadata::new(
        scope,
        SubscriptionMetadataInput {
            subscription_arn: scope.subscription().clone(),
            frequency: SubscriptionFrequency::Daily,
            status: SubscriptionStatus::Active,
            subscriber_addresses: vec![RAW_SUBSCRIBER.to_owned()],
        },
    )
    .expect("subscription metadata")
}

fn recording_service() -> AwsCostAnomalyService<RecordingTransport> {
    let scope = scope();
    let anomaly_filter = AnomalyFilter::for_scope(&scope, 10).expect("anomaly filter");
    let monitor_filter = MonitorFilter::for_scope(&scope, 10).expect("monitor filter");
    let subscription_filter =
        SubscriptionFilter::for_scope(&scope, 10).expect("subscription filter");
    let anomaly_request =
        GetAnomaliesRequest::new(&scope, anomaly_filter, None).expect("anomaly request");
    let monitor_request =
        GetAnomalyMonitorsRequest::new(&scope, monitor_filter, None).expect("monitor request");
    let subscription_request =
        GetAnomalySubscriptionsRequest::new(&scope, subscription_filter, None)
            .expect("subscription request");
    let mut transport = RecordingTransport::default();
    transport.push_anomalies_response(Ok(GetAnomaliesResponse::new(
        &anomaly_request,
        vec![anomaly(&scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("anomaly response")));
    transport.push_monitors_response(Ok(GetAnomalyMonitorsResponse::new(
        &monitor_request,
        vec![monitor(&scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("monitor response")));
    transport.push_subscriptions_response(Ok(GetAnomalySubscriptionsResponse::new(
        &subscription_request,
        vec![subscription(&scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("subscription response")));
    AwsCostAnomalyService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsCostAnomalyProvider::new(transport).expect("provider"),
        now(),
    )
    .expect("service")
}

fn assert_non_native_fixture<T: AwsCostAnomalyTransport>(
    provider: AwsCostAnomalyProvider<T>,
    expected_provenance: &TransportProvenance,
    scope: &AwsCostAnomalyScope,
) {
    let mut service =
        AwsCostAnomalyService::new(scope.clone(), secret(scope), consent(), provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(&proposal.provenance, expected_provenance);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
}

#[test]
fn registration_and_projection_boundaries_are_digest_only() {
    let scope = scope();
    let service = AwsCostAnomalyService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsCostAnomalyProvider::default(),
        now(),
    )
    .expect("service");
    service.registration().validate().expect("registration");
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    let registration_debug = format!("{:?}", service.registration());
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains(RAW_OPAQUE_HANDLE));
    assert!(!registration_debug.contains(RAW_OPAQUE_HANDLE));
    assert!(
        !serde_json::to_string(&scope)
            .expect("scope JSON")
            .contains(RAW_MONITOR_ARN)
    );
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);

    let anomaly = anomaly(&scope);
    let monitor = monitor(&scope);
    let subscription = subscription(&scope);
    for serialized in [
        serde_json::to_string(&anomaly).expect("anomaly JSON"),
        serde_json::to_string(&monitor).expect("monitor JSON"),
        serde_json::to_string(&subscription).expect("subscription JSON"),
    ] {
        assert!(!serialized.contains(RAW_MONITOR_ARN));
        assert!(!serialized.contains(RAW_SUBSCRIPTION_ARN));
        assert!(!serialized.contains(RAW_MONITOR_NAME));
        assert!(!serialized.contains(RAW_SUBSCRIBER));
        assert!(!serialized.contains(RAW_ROOT_CAUSE));
    }
}

#[test]
fn recording_proposes_three_reads_and_records_idempotently() {
    let mut service = recording_service();
    let request = service.default_request(now()).expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, AnomalyEvidenceState::AnomalyDetected);
    assert!(proposal.anomaly_complete);
    assert!(proposal.monitor_complete);
    assert!(proposal.subscription_complete);
    assert!(proposal.anomaly.is_some());
    assert!(proposal.monitor.is_some());
    assert!(proposal.subscription.is_some());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.financial_advice);
    assert!(!proposal.cost_causality_claim);
    assert!(!proposal.notification_sent);
    assert!(!proposal.billing_effect);
    assert!(proposal.validate_integrity().is_ok());
    let verification = service.verify(&proposal);
    assert!(verification.valid);
    assert!(verification.review_eligible);

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("consume");
    assert!(!result.can_be_adopted());
    assert!(!result.connected);
    assert!(!result.native);
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
    let _: RecordedAwsCostAnomalyResult = first;

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_MONITOR_ARN,
        RAW_SUBSCRIPTION_ARN,
        RAW_MONITOR_NAME,
        RAW_SUBSCRIBER,
        RAW_ROOT_CAUSE,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope();
    assert_non_native_fixture(
        AwsCostAnomalyProvider::new(FixtureTransport::for_scope(&scope, now()))
            .expect("fixture provider"),
        &TransportProvenance::Fixture,
        &scope,
    );
    assert_non_native_fixture(
        AwsCostAnomalyProvider::new(LoopbackTransport::for_scope(&scope, now()))
            .expect("loopback provider"),
        &TransportProvenance::Loopback,
        &scope,
    );

    let mut blocked = AwsCostAnomalyService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsCostAnomalyProvider::<BlockedEnvTransport>::default(),
        now(),
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .propose(blocked.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        blocked_proposal.state,
        AnomalyEvidenceState::ProviderUnknown
    );
    assert_eq!(blocked_proposal.provenance, TransportProvenance::BlockedEnv);
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
    assert!(!blocked_proposal.first_party);
    assert!(!blocked_proposal.provider_receipt);
    assert!(matches!(
        blocked.provider_mut().get_anomalies(
            &GetAnomaliesRequest::new(
                &scope,
                AnomalyFilter::for_scope(&scope, 1).expect("filter"),
                None,
            )
            .expect("request")
        ),
        Err(AwsCostAnomalyTransportError::BlockedEnv)
    ));
}

#[test]
fn pagination_is_opaque_and_digest_fenced() {
    let scope = scope();
    let filter = AnomalyFilter::for_scope(&scope, 10).expect("filter");
    let cursor = Cursor::new("opaque-next-token", &scope, &filter, 2).expect("cursor");
    let request =
        GetAnomaliesRequest::new(&scope, filter.clone(), Some(cursor.clone())).expect("request");
    let path = request.path_and_query();
    assert!(path.contains("nextTokenDigest"));
    assert!(!path.contains("opaque-next-token"));
    assert_eq!(request.filter().digest(), filter.digest());
    assert_eq!(
        request.cursor().expect("cursor").token_digest(),
        cursor.token_digest()
    );

    let response = GetAnomaliesResponse::new(
        &request,
        vec![anomaly(&scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("response");
    let tampered = response.with_declared_digest(Digest::from_text("tampered"));
    assert!(tampered.validate_integrity(&request).is_err());
}

#[test]
fn retention_and_registration_fences_fail_closed() {
    let old_scope = AwsCostAnomalyScope::new(
        AwsAccountId::new("123456789012").expect("management account"),
        AwsAccountId::new("210987654321").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        MonitorArn::new(RAW_MONITOR_ARN).expect("monitor"),
        AnomalyIdentity::new(
            AnomalyId::new(RAW_ANOMALY_ID).expect("anomaly id"),
            AnomalyWindow::new(now() - Duration::days(92), now() - Duration::days(91))
                .expect("old window"),
        )
        .expect("anomaly"),
        DeploymentIdentity::new(DeploymentId::new("deployment-7").expect("deployment"), 7)
            .expect("deployment identity"),
        ServiceRevisionIdentity::new(ServiceName::new("billing-service").expect("service"), 11)
            .expect("service revision"),
        SubscriptionArn::new(RAW_SUBSCRIPTION_ARN).expect("subscription"),
        MissionIdentity::new(MissionId::new("mission-1").expect("mission"), 3)
            .expect("mission identity"),
        ProjectIdentity::new(ProjectId::new("project-1").expect("project"), 5)
            .expect("project identity"),
        WorkProductIdentity::new(
            WorkProductId::new("work-product-1").expect("work product"),
            9,
        )
        .expect("work product identity"),
    )
    .expect("old scope");
    let old_service = AwsCostAnomalyService::new(
        old_scope.clone(),
        SecretReference::sigv4(RAW_OPAQUE_HANDLE, &old_scope, 1).expect("secret"),
        consent(),
        AwsCostAnomalyProvider::default(),
        now(),
    )
    .expect("old service");
    assert!(old_service.default_request(now()).is_err());

    let mut service = recording_service();
    let transition = service.revoke().expect("revoke");
    assert_eq!(
        transition.new_status,
        hartevo_aws_cost_anomaly_result_plugin::RegistrationStatus::Revoked
    );
    assert!(service.default_request(now()).is_ok());
    assert!(
        service
            .propose(service.default_request(now()).expect("request"))
            .is_err()
    );
    service.restore_registration().expect("restore");
    assert!(service.registration().validate().is_ok());
    service.reverse().expect("reverse");
    assert!(service.restore_registration().is_err());
}

#[test]
fn custom_permission_snapshot_cannot_escape_allowlist() {
    let invalid = PermissionSnapshot::new(1, ["ce:GetAnomalies", "ce:CreateAnomalyMonitor"]);
    assert!(invalid.is_err());
}

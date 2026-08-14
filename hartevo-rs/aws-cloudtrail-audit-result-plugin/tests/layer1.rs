use chrono::{TimeZone, Utc};
use hartevo_aws_cloudtrail_audit_result_plugin::{
    AWS_CLOUDTRAIL_AUDIT_PROVIDER_REVISION, AuditBounds, AuditProjection, AwsCloudTrailAuditScope,
    AwsCloudTrailAuditService, AwsCloudTrailProvider, AwsCloudTrailProviderError, DeploymentScope,
    EffectKind, EffectScope, EventMetadataInput, EventName, EventOutcome, EventSource,
    FakeAwsCloudTrailTransport, MissionCloudTrailAuditConsumer, MissionCloudTrailAuditState,
    MissionScope, PermissionBinding, ProjectScope, ProviderFailureClass, RedactedEventMetadata,
    RegistrationState, ResourceScope, Revision, SigV4SecretReference, TimeWindow, WorkProductScope,
};

fn time(hour: u32, minute: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, hour, minute, 0)
        .single()
        .expect("valid fixture time")
}

fn scope() -> AwsCloudTrailAuditScope {
    AwsCloudTrailAuditScope::new(
        "123456789012".parse().expect("account"),
        "us-east-1".parse().expect("region"),
        TimeWindow::new(time(0, 0), time(1, 0)).expect("window"),
        EventSource::new("s3.amazonaws.com").expect("source"),
        EventName::new("CreateBucket").expect("event name"),
        ResourceScope::new("AWS::S3::Bucket", "arn:aws:s3:::audit-fixture").expect("resource"),
        EffectScope::new(
            "opaque-effect-509",
            EffectKind::Create,
            Revision::new(1).expect("effect revision"),
        )
        .expect("effect"),
        MissionScope::new("mission-509", Revision::new(3).expect("mission revision"))
            .expect("mission"),
        ProjectScope::new("project-509", Revision::new(2).expect("project revision"))
            .expect("project"),
        DeploymentScope::new(
            "deployment-509",
            Revision::new(4).expect("deployment revision"),
        )
        .expect("deployment"),
        WorkProductScope::new("work-product-509", Revision::new(5).expect("work revision"))
            .expect("work product"),
        PermissionBinding::cloudtrail_lookup_events(),
    )
}

fn event(scope: &AwsCloudTrailAuditScope, id: &str, minute: u32) -> RedactedEventMetadata {
    RedactedEventMetadata::from_input(EventMetadataInput::new(
        id,
        time(0, minute),
        scope.event_source.clone(),
        scope.event_name.clone(),
        scope.resource.resource_type.clone(),
        "arn:aws:s3:::audit-fixture",
        EventOutcome::Success,
        hartevo_aws_cloudtrail_audit_result_plugin::RedactedIdentityClass::IamRole,
    ))
    .expect("safe event projection")
}

fn service(
    bounds: AuditBounds,
    events: impl IntoIterator<Item = RedactedEventMetadata>,
) -> AwsCloudTrailAuditService<FakeAwsCloudTrailTransport> {
    let scope = scope();
    let secret = SigV4SecretReference::for_scope(
        "opaque-host-sigv4-reference",
        &scope,
        Revision::new(7).expect("credential revision"),
    )
    .expect("secret reference");
    let provider = AwsCloudTrailProvider::new(
        FakeAwsCloudTrailTransport::new(events),
        "1.0.0",
        AWS_CLOUDTRAIL_AUDIT_PROVIDER_REVISION,
    )
    .expect("provider");
    AwsCloudTrailAuditService::with_bounds(scope, secret, provider, bounds).expect("service")
}

#[test]
fn complete_audit_is_redacted_deduplicated_ordered_and_not_effect_authority() {
    let scope = scope();
    let first = event(&scope, "event-older", 20);
    let second = event(&scope, "event-newer", 40);
    let duplicate = second.clone();
    let mut service = service(AuditBounds::default(), [second, first, duplicate]);

    let evidence = service.read_bounded().expect("bounded read");
    assert_eq!(evidence.projection, AuditProjection::Complete);
    assert_eq!(evidence.raw_event_count, 3);
    assert_eq!(evidence.unique_event_count, 2);
    assert_eq!(evidence.duplicate_event_count, 1);
    assert!(evidence.verify_integrity());
    assert_eq!(evidence.events[0].event_time, time(0, 20));
    assert!(
        evidence
            .anomalies
            .contains(&hartevo_aws_cloudtrail_audit_result_plugin::AuditAnomaly::DuplicateEvent)
    );
    assert!(
        evidence
            .anomalies
            .contains(&hartevo_aws_cloudtrail_audit_result_plugin::AuditAnomaly::OrderNormalized)
    );

    let serialized = serde_json::to_string(&evidence).expect("safe evidence serializes");
    assert!(!serialized.contains("event-older"));
    assert!(!serialized.contains("audit-fixture"));
    assert!(!serialized.contains("sourceIPAddress"));
    assert!(!serialized.contains("requestParameters"));

    let consumer = MissionCloudTrailAuditConsumer::new(scope, service.registration())
        .expect("mission consumer");
    let result = consumer.consume(evidence).expect("mission observation");
    assert_eq!(result.state, MissionCloudTrailAuditState::EvidenceAvailable);
    assert_eq!(result.events.len(), 2);
    assert!(!result.external_effect_succeeded);
    assert_eq!(
        result.effect_observation,
        hartevo_aws_cloudtrail_audit_result_plugin::EffectObservation::NoExternalEffectClaim
    );
}

#[test]
fn cursor_is_opaque_and_bound_to_the_next_page() {
    let scope = scope();
    let mut service = service(
        AuditBounds::new(4, 1, 10).expect("bounds"),
        [
            event(&scope, "event-one", 10),
            event(&scope, "event-two", 11),
        ],
    );

    let evidence = service.read_bounded().expect("two page read");
    assert_eq!(evidence.projection, AuditProjection::Complete);
    assert_eq!(evidence.page_count, 2);
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].cursor_digest.is_none());
    assert_eq!(
        requests[1].cursor_digest,
        Some(
            hartevo_aws_cloudtrail_audit_result_plugin::fake_cursor_for_page(2)
                .expect("cursor")
                .digest()
        )
    );
    let debug = format!("{:?}", requests[1].cursor());
    assert!(!debug.contains("fake-page:2"));
    let request_json = serde_json::to_string(&requests[1]).expect("safe request");
    assert!(!request_json.contains("fake-page:2"));
}

#[test]
fn page_cap_and_provider_states_are_explicit() {
    let scope = scope();
    let mut partial = service(
        AuditBounds::new(1, 1, 10).expect("bounds"),
        [
            event(&scope, "event-one", 10),
            event(&scope, "event-two", 11),
        ],
    );
    assert_eq!(
        partial.read_bounded().expect("partial read").projection,
        AuditProjection::Partial(
            hartevo_aws_cloudtrail_audit_result_plugin::PartialReason::PageCap
        )
    );

    for (failure, expected) in [
        (
            ProviderFailureClass::RetentionUnavailable,
            AuditProjection::RetentionUnavailable,
        ),
        (
            ProviderFailureClass::AccessDenied,
            AuditProjection::AccessLost,
        ),
        (
            ProviderFailureClass::ProviderUnknown,
            AuditProjection::ProviderUnknown,
        ),
    ] {
        let mut failing = service(AuditBounds::default(), []);
        failing
            .provider_mut()
            .transport_mut()
            .push_failure(AwsCloudTrailProviderError::failure(failure, Some(403)));
        assert_eq!(
            failing.read_bounded().expect("typed state").projection,
            expected
        );
    }
}

#[test]
fn replay_tamper_and_revision_drift_fail_closed() {
    let scope = scope();
    let mut first_service = service(AuditBounds::default(), [event(&scope, "event-one", 10)]);
    let proposal = first_service
        .propose_lookup_events(1, None)
        .expect("proposal");
    first_service
        .read_lookup_events(&proposal)
        .expect("first read");
    assert!(matches!(
        first_service.read_lookup_events(&proposal),
        Err(
            hartevo_aws_cloudtrail_audit_result_plugin::AwsCloudTrailServiceError::Provider(
                AwsCloudTrailProviderError::ReplayDetected
            )
        )
    ));

    let mut another = service(AuditBounds::default(), [event(&scope, "event-one", 10)]);
    let proposal = another.propose_lookup_events(1, None).expect("proposal");
    let mut page = another
        .provider_mut()
        .read(proposal.request())
        .expect("page");
    page.events[0].event_name = EventName::new("DeleteBucket").expect("tampered selector");
    assert!(matches!(
        another.record_lookup_events(&proposal, &page),
        Err(hartevo_aws_cloudtrail_audit_result_plugin::AwsCloudTrailServiceError::RecordTampered)
    ));

    let mut consumer =
        MissionCloudTrailAuditConsumer::new(scope, another.registration()).expect("consumer");
    consumer.revoke().expect("revoke");
    assert!(matches!(
        consumer.consume(another.read_bounded().expect("evidence")),
        Err(hartevo_aws_cloudtrail_audit_result_plugin::ConsumerError::Revoked)
    ));
    assert_eq!(another.registration().state, RegistrationState::Active);
}

#[test]
fn secret_reference_is_opaque_and_scope_digest_is_exact() {
    let scope = scope();
    let secret = SigV4SecretReference::for_scope(
        "AKIAIOSFODNN7EXAMPLE",
        &scope,
        Revision::new(1).expect("revision"),
    )
    .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!debug.contains("secret"));

    let mut changed = scope.clone();
    changed.event_name = EventName::new("DeleteBucket").expect("new event");
    assert_ne!(scope.scope_digest(), changed.scope_digest());
    changed = scope.clone();
    changed.project.revision = Revision::new(99).expect("new revision");
    assert_ne!(scope.scope_digest(), changed.scope_digest());
}

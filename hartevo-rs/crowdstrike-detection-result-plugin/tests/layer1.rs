use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_crowdstrike_detection_result_plugin::{
    BlockedEnvTransport, CrowdStrikeDetectionReadRequest, CrowdStrikeDetectionResultService,
    CrowdStrikeDetectionScope, CrowdStrikeFalconProvider, CrowdStrikeFalconTransport,
    CrowdStrikeProviderError, DetectionEvidenceState, DetectionId, DetectionProjection,
    DetectionTimeWindow, FalconCloud, FalconDetectionAlertScope, FalconDetectionStatus,
    FalconReadBounds, FalconSeverity, FalconTransportError, FalconTransportFailure,
    FixtureTransport, FqlFilter, GroupId, HostId, Layer1Authority, LoopbackTransport,
    MissionCrowdStrikeDetectionConsumer, MissionScope, PermissionSnapshot, PlatformClass,
    ProjectScope, RateLimitReceipt, RecordingTransport, RedactedDeviceFields,
    RedactedProcessFields, RedactedTechniqueFields, SecretReference, TransportProvenance,
    WorkProductScope,
};

fn timestamp(value: &str) -> DateTime<Utc> {
    value
        .parse::<DateTime<Utc>>()
        .expect("valid test timestamp")
}

fn scope() -> CrowdStrikeDetectionScope {
    CrowdStrikeDetectionScope::new(
        "customer-001",
        "cid-001",
        hartevo_crowdstrike_detection_result_plugin::FalconHostGroupScope::new(
            vec![HostId::parse("host-001").expect("host")],
            vec![GroupId::parse("group-001").expect("group")],
        )
        .expect("host/group scope"),
        FalconDetectionAlertScope::from_values(["detection-001"], ["alert-001"])
            .expect("detection/alert scope"),
        Some(FalconSeverity::High),
        Some(FalconDetectionStatus::New),
        FqlFilter::all(&[
            FqlFilter::exact("status", "new").expect("status filter"),
            FqlFilter::exact("device.device_id", "host'001").expect("escaped filter"),
        ])
        .expect("FQL filter"),
        DetectionTimeWindow::new(
            timestamp("2026-08-14T00:00:00Z"),
            timestamp("2026-08-15T00:00:00Z"),
            1,
        )
        .expect("time window"),
        ProjectScope::new("project-001", 7).expect("project"),
        MissionScope::new("mission-001", 11).expect("mission"),
        WorkProductScope::new("work-product-001", 13).expect("work product"),
        17,
    )
    .expect("scope")
}

fn registration(
    service: CrowdStrikeDetectionResultService,
    scope: CrowdStrikeDetectionScope,
) -> hartevo_crowdstrike_detection_result_plugin::CrowdStrikeRegistration {
    let secret = SecretReference::for_alerts_read(
        "opaque-falcon-oauth-client-handle",
        hartevo_crowdstrike_detection_result_plugin::FalconRegion::parse("us-east")
            .expect("region"),
        FalconCloud::Us1,
    )
    .expect("opaque secret reference");
    service
        .register(
            "registration-001",
            scope,
            secret,
            PermissionSnapshot::alerts_read(),
            23,
        )
        .expect("registration")
}

fn detection(id: &str, revision: u64) -> DetectionProjection {
    let device = RedactedDeviceFields::from_sensitive(
        &format!("device-{id}"),
        Some(&format!("host-{id}.example")),
        &["group-001"],
        PlatformClass::Macos,
    )
    .expect("device redaction");
    let process = RedactedProcessFields::from_sensitive(
        Some("/usr/bin/private-process"),
        Some("private-process --user-email alice@example.invalid"),
        Some("/sbin/launchd"),
    );
    let technique =
        RedactedTechniqueFields::from_sensitive("execution", "T1059").expect("technique redaction");
    DetectionProjection::from_sensitive(
        id,
        Some(format!("alert-{id}")),
        FalconSeverity::Medium,
        FalconDetectionStatus::New,
        device,
        Some(process),
        vec![technique],
        timestamp("2026-08-14T12:00:00Z"),
        timestamp("2026-08-14T12:05:00Z"),
        revision,
    )
    .expect("detection")
}

fn bounds(page_size: u16, max_pages: u16, max_retries: u8) -> FalconReadBounds {
    FalconReadBounds::new(0, page_size, max_pages, max_retries).expect("bounds")
}

fn assert_harness_read<T: CrowdStrikeFalconTransport>(
    scope: &CrowdStrikeDetectionScope,
    registration: &hartevo_crowdstrike_detection_result_plugin::CrowdStrikeRegistration,
    mut provider: CrowdStrikeFalconProvider<T>,
    expected: TransportProvenance,
) {
    let mut consumer =
        MissionCrowdStrikeDetectionConsumer::new(scope.clone(), registration.clone())
            .expect("consumer");
    let result = consumer
        .read_with_bounds(
            &mut provider,
            bounds(10, 2, 1),
            timestamp("2026-08-15T01:00:00Z"),
        )
        .expect("harness read");
    assert_eq!(result.provenance, expected);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.provider_receipt);
}

#[test]
fn complete_fixture_read_is_revision_fenced_and_redacted() {
    let scope = scope();
    let service = CrowdStrikeDetectionResultService::new();
    let registration = registration(service, scope.clone());
    let transport = FixtureTransport::for_scope(&scope).expect("fixture");
    let mut provider =
        CrowdStrikeFalconProvider::new(transport, registration.clone()).expect("provider");
    let mut consumer =
        MissionCrowdStrikeDetectionConsumer::new(scope.clone(), registration).expect("consumer");

    let result = consumer
        .read_with_bounds(
            &mut provider,
            bounds(10, 4, 2),
            timestamp("2026-08-15T01:00:00Z"),
        )
        .expect("fixture read");
    assert_eq!(result.state, DetectionEvidenceState::Present);
    assert_eq!(result.provenance, TransportProvenance::Fixture);
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.provider_receipt);
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    assert!(!result.can_be_adopted());

    let request = consumer.request(bounds(10, 4, 2)).expect("request");
    let proposal = consumer
        .read_proposal(&mut provider, &request, timestamp("2026-08-15T01:00:00Z"))
        .expect("proposal");
    let verification = consumer.verify(&proposal);
    assert!(verification.valid);
    assert!(verification.review_eligible);
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for forbidden in [
        "opaque-falcon-oauth-client-handle",
        "fixture process --bounded",
        "private-process --user-email alice@example.invalid",
        "fixture-host.example",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "raw value leaked: {forbidden}"
        );
        assert!(
            !debug.contains(forbidden),
            "raw value leaked in Debug: {forbidden}"
        );
    }
    assert!(serialized.contains("commandLineDigest"));
    assert!(serialized.contains("deviceIdDigest"));
}

#[test]
fn all_harness_provenances_are_explicitly_non_native() {
    let scope = scope();
    let service = CrowdStrikeDetectionResultService::new();
    let registration = registration(service, scope.clone());
    assert_harness_read(
        &scope,
        &registration,
        CrowdStrikeFalconProvider::new(
            LoopbackTransport::for_scope(&scope).expect("loopback"),
            registration.clone(),
        )
        .expect("loopback provider"),
        TransportProvenance::Loopback,
    );
    assert_harness_read(
        &scope,
        &registration,
        CrowdStrikeFalconProvider::new(BlockedEnvTransport, registration.clone())
            .expect("blocked provider"),
        TransportProvenance::BlockedEnv,
    );

    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::first_party());
}

#[test]
fn empty_results_are_distinct_and_transport_failure_receipts_stay_typed() {
    let scope = scope();
    let service = CrowdStrikeDetectionResultService::new();
    let registration = registration(service, scope.clone());
    let empty_transport = FixtureTransport::with_detections(&scope, vec![]).expect("empty fixture");
    let mut empty_provider =
        CrowdStrikeFalconProvider::new(empty_transport, registration.clone()).expect("provider");
    let mut empty_consumer =
        MissionCrowdStrikeDetectionConsumer::new(scope.clone(), registration.clone())
            .expect("consumer");
    let empty = empty_consumer
        .read_with_bounds(
            &mut empty_provider,
            bounds(10, 2, 0),
            timestamp("2026-08-15T01:00:00Z"),
        )
        .expect("empty read");
    assert_eq!(empty.state, DetectionEvidenceState::Empty);
    assert!(!empty.can_be_adopted());

    let mut transport = RecordingTransport::for_scope(&scope).expect("recording");
    transport.push_query_response(Err(FalconTransportError::from_status(429).with_rate_limit(
        RateLimitReceipt::new(60, Some(0), Some(5), true).expect("rate receipt"),
    )));
    let mut provider =
        CrowdStrikeFalconProvider::new(transport, registration.clone()).expect("provider");
    let mut consumer =
        MissionCrowdStrikeDetectionConsumer::new(scope.clone(), registration).expect("consumer");
    let request = consumer.request(bounds(10, 2, 0)).expect("request");
    let proposal = consumer
        .read_proposal(&mut provider, &request, timestamp("2026-08-15T01:00:00Z"))
        .expect("failure proposal");
    let failure = proposal.evidence.failure.as_ref().expect("failure receipt");
    assert_eq!(failure.status_code, Some(429));
    assert_eq!(failure.retry.attempts, 1);
    assert_eq!(failure.rate_limit.retry_after_seconds, Some(5));
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
}

#[test]
fn transport_failures_become_explicit_access_loss_or_provider_unknown_states() {
    let cases = [
        (401, DetectionEvidenceState::AccessLoss),
        (403, DetectionEvidenceState::AccessLoss),
        (404, DetectionEvidenceState::ProviderUnknown),
        (409, DetectionEvidenceState::ProviderUnknown),
        (429, DetectionEvidenceState::ProviderUnknown),
        (500, DetectionEvidenceState::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let scope = scope();
        let service = CrowdStrikeDetectionResultService::new();
        let registration = registration(service, scope.clone());
        let mut transport = RecordingTransport::for_scope(&scope).expect("recording");
        let error = FalconTransportError::from_status(status).with_rate_limit(
            RateLimitReceipt::new(60, Some(0), (status == 429).then_some(4), status == 429)
                .expect("rate receipt"),
        );
        transport.push_query_response(Err(error));
        let mut provider =
            CrowdStrikeFalconProvider::new(transport, registration.clone()).expect("provider");
        let mut consumer =
            MissionCrowdStrikeDetectionConsumer::new(scope, registration).expect("consumer");
        let result = consumer
            .read_with_bounds(
                &mut provider,
                bounds(10, 2, 0),
                timestamp("2026-08-15T01:00:00Z"),
            )
            .expect("failure proposal");
        assert_eq!(result.state, expected, "status {status}");
        assert!(result.state.is_non_adoptable());
        assert!(!result.connected);
        assert!(!result.native);
    }
}

#[test]
fn retries_and_rate_limits_are_bounded_and_recorded_without_raw_headers() {
    let scope = scope();
    let service = CrowdStrikeDetectionResultService::new();
    let registration = registration(service, scope.clone());
    let mut transport = RecordingTransport::for_scope(&scope).expect("recording");
    for _ in 0..3 {
        transport.push_query_response(Err(FalconTransportError::from_status(429).with_rate_limit(
            RateLimitReceipt::new(60, Some(0), Some(3), true).expect("rate receipt"),
        )));
    }
    let mut provider =
        CrowdStrikeFalconProvider::new(transport, registration.clone()).expect("provider");
    let request =
        CrowdStrikeDetectionReadRequest::for_registration(&scope, &registration, bounds(10, 2, 2))
            .expect("read request");
    let query =
        hartevo_crowdstrike_detection_result_plugin::QueryDetectsRequest::from_read_request(
            &request, 1,
        )
        .expect("query request");
    let error = provider
        .query_detects(&query, 2)
        .expect_err("bounded retry failure");
    match error {
        CrowdStrikeProviderError::Transport(error) => {
            assert_eq!(error.status_code, Some(429));
            assert_eq!(error.retry.attempts, 3);
            assert_eq!(error.retry.retries, 2);
            assert!(error.retry.exhausted);
            assert_eq!(error.rate_limit.retry_after_seconds, Some(3));
        }
        other => panic!("unexpected provider error: {other:?}"),
    }
}

#[test]
fn partial_pages_and_duplicate_replays_fail_closed() {
    let scope = scope();
    let service = CrowdStrikeDetectionResultService::new();
    let registration = registration(service, scope.clone());
    let transport = FixtureTransport::with_detections(
        &scope,
        vec![detection("detection-a", 1), detection("detection-b", 1)],
    )
    .expect("fixture");
    let mut provider =
        CrowdStrikeFalconProvider::new(transport, registration.clone()).expect("provider");
    let mut consumer =
        MissionCrowdStrikeDetectionConsumer::new(scope.clone(), registration.clone())
            .expect("consumer");
    let partial = consumer
        .read_with_bounds(
            &mut provider,
            bounds(1, 1, 0),
            timestamp("2026-08-15T01:00:00Z"),
        )
        .expect("partial read");
    assert_eq!(partial.state, DetectionEvidenceState::Partial);
    assert!(!partial.can_be_adopted());

    let duplicate = detection("detection-duplicate", 1);
    let transport = FixtureTransport::with_detections(&scope, vec![duplicate.clone(), duplicate])
        .expect("duplicate fixture");
    let mut provider =
        CrowdStrikeFalconProvider::new(transport, registration.clone()).expect("provider");
    let request =
        CrowdStrikeDetectionReadRequest::for_registration(&scope, &registration, bounds(1, 2, 0))
            .expect("request");
    let error = provider.read(&request, timestamp("2026-08-15T01:00:00Z"));
    assert!(matches!(
        error,
        Err(CrowdStrikeProviderError::TamperedResponse)
    ));
}

#[test]
fn fql_scope_and_revision_fences_reject_injection_and_stale_requests() {
    assert!(FqlFilter::parse("status:'new'; delete=true").is_err());
    assert!(FqlFilter::parse("unknown_field:'value'").is_err());
    let escaped = FqlFilter::exact("status", "new'quoted").expect("escaped value");
    assert!(escaped.as_str().contains("\\'"));

    let scope = scope();
    let service = CrowdStrikeDetectionResultService::new();
    let registration = registration(service, scope.clone());
    let mut provider = CrowdStrikeFalconProvider::new(
        FixtureTransport::for_scope(&scope).expect("fixture"),
        registration.clone(),
    )
    .expect("provider");
    let mut request =
        CrowdStrikeDetectionReadRequest::for_registration(&scope, &registration, bounds(10, 2, 0))
            .expect("request");
    request.permission_digest =
        hartevo_crowdstrike_detection_result_plugin::Digest::from_text("drift");
    let query =
        hartevo_crowdstrike_detection_result_plugin::QueryDetectsRequest::from_read_request(
            &request, 1,
        )
        .expect("query");
    assert!(matches!(
        provider.query_detects(&query, 0),
        Err(CrowdStrikeProviderError::PermissionMismatch)
    ));

    let mut stale_scope = scope.clone();
    stale_scope.mission.revision =
        hartevo_crowdstrike_detection_result_plugin::Revision::new(12).expect("stale revision");
    assert!(MissionCrowdStrikeDetectionConsumer::new(stale_scope, registration).is_err());
}

#[test]
fn registration_is_reversible_and_serialization_contains_only_digests() {
    let service = CrowdStrikeDetectionResultService::new();
    let mut registration = registration(service, scope());
    let active_digest = registration.registration_digest().clone();
    let revoked = registration.revoke().expect("revoke");
    assert_eq!(
        revoked.new_status,
        hartevo_crowdstrike_detection_result_plugin::RegistrationStatus::Revoked
    );
    assert_ne!(registration.registration_digest(), &active_digest);
    registration.restore().expect("restore");
    registration.reverse().expect("reverse");
    assert!(!registration.is_active());
    assert!(registration.restore().is_err());

    let serialized = serde_json::to_string(&registration).expect("registration JSON");
    let debug = format!("{registration:?}");
    assert!(!serialized.contains("opaque-falcon-oauth-client-handle"));
    assert!(!serialized.contains("host-001"));
    assert!(!debug.contains("opaque-falcon-oauth-client-handle"));
    assert!(serialized.contains("secretReferenceDigest"));
}

#[test]
fn projection_digest_is_deterministic_and_tamper_is_detectable() {
    let first = detection("detection-deterministic", 1);
    let second = detection("detection-deterministic", 1);
    assert_eq!(first.detection_digest, second.detection_digest);
    assert!(first.validate_integrity().is_ok());
    let first_digest = first.detection_digest.clone();
    let tampered = first.with_declared_digest(
        hartevo_crowdstrike_detection_result_plugin::Digest::from_text("tampered"),
    );
    assert!(tampered.validate_integrity().is_err());

    let mut ids = BTreeSet::new();
    ids.insert(first_digest);
    ids.insert(second.detection_digest);
    assert_eq!(ids.len(), 1);
}

#[test]
fn transport_failure_helpers_cover_required_statuses_and_timeout() {
    for (status, expected) in [
        (400, FalconTransportFailure::BadRequest),
        (401, FalconTransportFailure::Unauthorized),
        (403, FalconTransportFailure::AccessDenied),
        (404, FalconTransportFailure::NotFound),
        (409, FalconTransportFailure::Conflict),
        (429, FalconTransportFailure::Throttled),
        (500, FalconTransportFailure::Server),
        (503, FalconTransportFailure::Server),
    ] {
        let error = FalconTransportError::from_status(status);
        assert_eq!(error.failure, expected);
        assert_eq!(error.status_code, Some(status.clamp(400, 500)));
    }
    assert_eq!(FalconTransportError::timeout().status_code, None);
    assert_eq!(
        FalconTransportError::blocked_env().failure,
        FalconTransportFailure::BlockedEnv
    );
}

#[allow(dead_code)]
fn assert_transport<T: CrowdStrikeFalconTransport>(_: T) {}

#[allow(dead_code)]
fn assert_ids(_: DetectionId) {}

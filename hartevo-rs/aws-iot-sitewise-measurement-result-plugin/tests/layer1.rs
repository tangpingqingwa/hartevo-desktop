use chrono::{Duration, TimeZone, Utc};
use serde_json::to_string;

use hartevo_aws_iot_sitewise_measurement_result_plugin::*;

const RAW_SECRET: &str = "opaque-sigv4-secret-reference";
const RAW_TOKEN: &str = "opaque-provider-next-token";
const RAW_ASSET: &str = "asset-raw-01";
const RAW_PROPERTY: &str = "property-raw-01";

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0)
        .single()
        .expect("valid fixed test time")
}

fn scope() -> AwsIoTSiteWiseMeasurementScope {
    scope_with(
        QualityFilter::Any,
        MeasurementBounds::new(8, 4, 4 * 1024 * 1024).unwrap(),
    )
}

fn scope_with(quality: QualityFilter, bounds: MeasurementBounds) -> AwsIoTSiteWiseMeasurementScope {
    AwsIoTSiteWiseMeasurementScope::from_strings(
        "123456789012",
        "us-east-1",
        "model-raw-01",
        RAW_ASSET,
        RAW_PROPERTY,
        Some("/factory/line-1/temperature".to_owned()),
        TimeWindow::new(now() - Duration::hours(1), now() - Duration::minutes(5)).unwrap(),
        quality,
        bounds,
        "mission-raw-01",
        7,
        "project-raw-01",
        5,
        "work-product-raw-01",
        3,
    )
    .unwrap()
}

fn secret(scope: &AwsIoTSiteWiseMeasurementScope) -> SecretReference {
    SecretReference::new(RAW_SECRET, scope).unwrap()
}

fn fixture_service(
    scope: &AwsIoTSiteWiseMeasurementScope,
) -> AwsIoTSiteWiseMeasurementService<FixtureTransport> {
    let provider = AwsIoTSiteWiseProvider::new(FixtureTransport::for_scope(scope, now())).unwrap();
    AwsIoTSiteWiseMeasurementService::new(
        scope.clone(),
        secret(scope),
        ConsentScope::read_only(),
        provider,
        now(),
    )
    .unwrap()
}

#[test]
fn scope_registration_and_allowlisted_provider_are_digest_fenced() {
    let scope = scope();
    let provider = AwsIoTSiteWiseProvider::new(FixtureTransport::for_scope(&scope, now())).unwrap();
    let service = AwsIoTSiteWiseMeasurementService::new(
        scope.clone(),
        secret(&scope),
        ConsentScope::read_only(),
        provider,
        now(),
    )
    .unwrap();
    assert!(service.registration().validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 4);
    assert_eq!(service.describe_capabilities().permissions.len(), 5);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(!service.describe_capabilities().first_party);

    let registration_json = to_string(service.registration()).unwrap();
    let registration_debug = format!("{:?}", service.registration());
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains(RAW_SECRET));
    assert!(!registration_debug.contains(RAW_SECRET));
    assert!(!to_string(&scope).unwrap().contains(RAW_ASSET));

    let list_request = ListAssetsRequest::for_scope(&scope, None).unwrap();
    let cursor = Cursor::new(RAW_TOKEN, &scope, list_request.binding_digest(), 2).unwrap();
    let paged = ListAssetsRequest::for_scope(&scope, Some(cursor)).unwrap();
    assert!(!paged.path_and_query().contains(RAW_TOKEN));
    assert!(paged.path_and_query().contains("nextTokenDigest"));
    assert_eq!(
        paged.cursor().unwrap().filter_digest(),
        paged.binding_digest()
    );
}

#[test]
fn fixture_produces_present_redacted_aggregate_and_idempotent_mission_record() {
    let scope = scope();
    let mut service = fixture_service(&scope);
    let request = service.default_request(now()).unwrap();
    let proposal = service.propose(request).unwrap();
    assert_eq!(proposal.state, MeasurementEvidenceState::Present);
    let aggregate = proposal.aggregate.as_ref().unwrap();
    assert_eq!(aggregate.count, 2);
    assert_eq!(aggregate.quality_counts.good, 1);
    assert!(aggregate.min_value_digest.is_some());
    assert!(aggregate.max_value_digest.is_some());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert!(service.verify(&proposal).valid);

    let serialized = to_string(&proposal).unwrap();
    for raw in [
        RAW_SECRET,
        RAW_TOKEN,
        RAW_ASSET,
        RAW_PROPERTY,
        "42.5",
        "43.0",
    ] {
        assert!(
            !serialized.contains(raw),
            "raw value leaked in proposal: {raw}"
        );
    }

    let mut consumer = service.consumer().unwrap();
    let mission = consumer.consume(&proposal).unwrap();
    assert_eq!(mission.state, MeasurementEvidenceState::Present);
    assert!(!mission.can_be_adopted());
    let first = consumer
        .record(&proposal, "measurement-record-key")
        .unwrap();
    let replay = consumer
        .record(&proposal, "measurement-record-key")
        .unwrap();
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
}

#[test]
fn fixture_loopback_and_blocked_env_remain_non_native() {
    let scope = scope();
    let mut loopback_service = AwsIoTSiteWiseMeasurementService::new(
        scope.clone(),
        secret(&scope),
        ConsentScope::read_only(),
        AwsIoTSiteWiseProvider::new(LoopbackTransport::for_scope(&scope, now())).unwrap(),
        now(),
    )
    .unwrap();
    let loopback_request = loopback_service.default_request(now()).unwrap();
    let loopback = loopback_service.propose(loopback_request).unwrap();
    assert_eq!(loopback.provenance, TransportProvenance::Loopback);
    assert!(!loopback.connected);
    assert!(!loopback.native);
    assert!(!loopback.first_party);

    let mut blocked_service = AwsIoTSiteWiseMeasurementService::new(
        scope.clone(),
        secret(&scope),
        ConsentScope::read_only(),
        AwsIoTSiteWiseProvider::default(),
        now(),
    )
    .unwrap();
    let blocked_request = blocked_service.default_request(now()).unwrap();
    let blocked = blocked_service.propose(blocked_request).unwrap();
    assert_eq!(blocked.state, MeasurementEvidenceState::ProviderUnknown);
    assert_eq!(blocked.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(blocked.failure.as_ref().unwrap().category, "blocked_env");
    assert!(!blocked.connected);
    assert!(!blocked.native);
    assert!(!blocked.first_party);
}

#[test]
fn empty_and_access_loss_states_are_distinct() {
    let scope = scope();
    let list_request = ListAssetsRequest::for_scope(&scope, None).unwrap();
    let empty_response = ListAssetsResponse::new(
        &list_request,
        Vec::new(),
        None,
        64,
        TransportProvenance::Recording,
    )
    .unwrap();
    let mut empty_transport = RecordingTransport::default();
    empty_transport.push_list_assets_response(Ok(empty_response));
    let mut empty_service = AwsIoTSiteWiseMeasurementService::new(
        scope.clone(),
        secret(&scope),
        ConsentScope::read_only(),
        AwsIoTSiteWiseProvider::new(empty_transport).unwrap(),
        now(),
    )
    .unwrap();
    let empty_request = empty_service.default_request(now()).unwrap();
    let empty = empty_service.propose(empty_request).unwrap();
    assert_eq!(empty.state, MeasurementEvidenceState::Empty);
    assert!(empty.aggregate.is_none());

    let mut access_transport = RecordingTransport::default();
    access_transport.push_list_assets_response(Err(AwsIoTSiteWiseTransportError::AccessDenied(
        AwsIoTSiteWiseOperation::ListAssets,
    )));
    let mut access_service = AwsIoTSiteWiseMeasurementService::new(
        scope.clone(),
        secret(&scope),
        ConsentScope::read_only(),
        AwsIoTSiteWiseProvider::new(access_transport).unwrap(),
        now(),
    )
    .unwrap();
    let access_request = access_service.default_request(now()).unwrap();
    let access = access_service.propose(access_request).unwrap();
    assert_eq!(access.state, MeasurementEvidenceState::AccessLost);
    assert_eq!(access.failure.as_ref().unwrap().category, "access_denied");
}

#[test]
fn pagination_is_opaque_and_bounded_across_all_four_allowlisted_seams() {
    let scope = scope();
    let list_request = ListAssetsRequest::for_scope(&scope, None).unwrap();
    let list_cursor = Cursor::new(RAW_TOKEN, &scope, list_request.binding_digest(), 2).unwrap();
    let first_list = ListAssetsResponse::new(
        &list_request,
        Vec::new(),
        Some(list_cursor.clone()),
        128,
        TransportProvenance::Recording,
    )
    .unwrap();
    let second_list_request = ListAssetsRequest::for_scope(&scope, Some(list_cursor)).unwrap();
    let second_list = ListAssetsResponse::new(
        &second_list_request,
        vec![AssetProjection::for_scope(&scope).unwrap()],
        None,
        128,
        TransportProvenance::Recording,
    )
    .unwrap();

    let describe_request = DescribeAssetRequest::for_scope(&scope).unwrap();
    let describe = DescribeAssetResponse::new(
        &describe_request,
        AssetDescription::for_scope(&scope).unwrap(),
        256,
        TransportProvenance::Recording,
    )
    .unwrap();
    let property_request = DescribeAssetPropertyRequest::for_scope(&scope).unwrap();
    let property = DescribeAssetPropertyResponse::new(
        &property_request,
        PropertyDescription::for_scope(&scope).unwrap(),
        256,
        TransportProvenance::Recording,
    )
    .unwrap();
    let history_request = GetAssetPropertyValueHistoryRequest::for_scope(&scope, None).unwrap();
    let sample = MeasurementSample::double(
        scope.time_window().start + Duration::minutes(10),
        MeasurementQuality::Good,
        10.0,
    )
    .unwrap();
    let history = MeasurementHistoryResponse::from_samples(
        &history_request,
        vec![sample],
        None,
        512,
        TransportProvenance::Recording,
    )
    .unwrap();

    let mut transport = RecordingTransport::default();
    transport.push_list_assets_response(Ok(first_list));
    transport.push_list_assets_response(Ok(second_list));
    transport.push_describe_asset_response(Ok(describe));
    transport.push_describe_asset_property_response(Ok(property));
    transport.push_history_response(Ok(history));
    let mut service = AwsIoTSiteWiseMeasurementService::new(
        scope.clone(),
        secret(&scope),
        ConsentScope::read_only(),
        AwsIoTSiteWiseProvider::new(transport).unwrap(),
        now(),
    )
    .unwrap();
    let request = service.default_request(now()).unwrap();
    let proposal = service.propose(request).unwrap();
    assert_eq!(proposal.state, MeasurementEvidenceState::Present);
    assert_eq!(proposal.aggregate.as_ref().unwrap().count, 1);

    let transport = service.provider().transport();
    assert_eq!(transport.requests().len(), 5);
    assert!(transport.requests().iter().all(|request| request.operation
        != AwsIoTSiteWiseOperation::ListAssets
        || request.path_digest.as_str() != RAW_TOKEN));
}

#[test]
fn stale_state_preserves_redacted_measurement_bounds() {
    let bounds = MeasurementBounds::with_stale_after_seconds(8, 4, 4 * 1024 * 1024, 60).unwrap();
    let scope = scope_with(QualityFilter::GoodOnly, bounds);
    let mut service = fixture_service(&scope);
    let request = service.default_request(now() + Duration::hours(2)).unwrap();
    let proposal = service.propose(request).unwrap();
    assert_eq!(proposal.state, MeasurementEvidenceState::Stale);
    assert_eq!(proposal.aggregate.as_ref().unwrap().quality_counts.bad, 0);
    assert_eq!(proposal.aggregate.as_ref().unwrap().quality_counts.good, 2);
}

#[test]
fn time_quality_ordering_and_response_size_fences_fail_closed() {
    let good_only_scope = scope_with(
        QualityFilter::GoodOnly,
        MeasurementBounds::new(2, 2, 1024).unwrap(),
    );
    let request = GetAssetPropertyValueHistoryRequest::for_scope(&good_only_scope, None).unwrap();
    let bad_sample = MeasurementSample::double(
        good_only_scope.time_window().start + Duration::minutes(1),
        MeasurementQuality::Bad,
        1.0,
    )
    .unwrap();
    assert!(
        MeasurementHistoryResponse::from_samples(
            &request,
            vec![bad_sample],
            None,
            128,
            TransportProvenance::Recording,
        )
        .is_err()
    );

    let outside_sample = MeasurementSample::double(
        good_only_scope.time_window().end + Duration::seconds(1),
        MeasurementQuality::Good,
        1.0,
    )
    .unwrap();
    assert!(
        MeasurementHistoryResponse::from_samples(
            &request,
            vec![outside_sample],
            None,
            128,
            TransportProvenance::Recording,
        )
        .is_err()
    );

    let later = MeasurementSample::double(
        good_only_scope.time_window().start + Duration::minutes(20),
        MeasurementQuality::Good,
        2.0,
    )
    .unwrap();
    let earlier = MeasurementSample::double(
        good_only_scope.time_window().start + Duration::minutes(10),
        MeasurementQuality::Good,
        1.0,
    )
    .unwrap();
    assert!(
        MeasurementHistoryResponse::from_samples(
            &request,
            vec![later, earlier],
            None,
            128,
            TransportProvenance::Recording,
        )
        .is_err()
    );

    assert!(
        MeasurementHistoryResponse::from_samples(
            &request,
            vec![
                MeasurementSample::double(
                    good_only_scope.time_window().start + Duration::minutes(1),
                    MeasurementQuality::Good,
                    1.0,
                )
                .unwrap()
            ],
            None,
            1025,
            TransportProvenance::Recording,
        )
        .is_err()
    );
}

#[test]
fn tampered_provider_response_maps_to_tampered_projection() {
    let scope = scope();
    let request = ListAssetsRequest::for_scope(&scope, None).unwrap();
    let tampered = ListAssetsResponse::new(
        &request,
        vec![AssetProjection::for_scope(&scope).unwrap()],
        None,
        128,
        TransportProvenance::Recording,
    )
    .unwrap()
    .with_declared_digest(Digest::from_text("tampered-list-response"));
    let mut transport = RecordingTransport::default();
    transport.push_list_assets_response(Ok(tampered));
    let mut service = AwsIoTSiteWiseMeasurementService::new(
        scope.clone(),
        secret(&scope),
        ConsentScope::read_only(),
        AwsIoTSiteWiseProvider::new(transport).unwrap(),
        now(),
    )
    .unwrap();
    let request = service.default_request(now()).unwrap();
    let proposal = service.propose(request).unwrap();
    assert_eq!(proposal.state, MeasurementEvidenceState::Tampered);
    assert_eq!(proposal.failure.as_ref().unwrap().category, "tampered");
}

#[test]
fn registration_revocation_reversal_and_restore_are_digest_fenced() {
    let scope = scope();
    let mut service = fixture_service(&scope);
    let old_request = service.default_request(now()).unwrap();
    let old_proposal = service.propose(old_request).unwrap();
    let active_digest = service.registration().registration_digest().clone();
    let revoked_transition = service.revoke_registration().unwrap();
    assert_eq!(revoked_transition.new_status, RegistrationStatus::Revoked);
    assert_ne!(active_digest, *service.registration().registration_digest());

    let revoked_request = service.default_request(now()).unwrap();
    let revoked = service.propose(revoked_request).unwrap();
    assert_eq!(revoked.state, MeasurementEvidenceState::Revoked);
    assert!(service.verify(&revoked).valid);

    let consumer = service.consumer().unwrap();
    assert!(consumer.consume(&old_proposal).is_err());
    assert_eq!(
        consumer.consume(&revoked).unwrap().state,
        MeasurementEvidenceState::Revoked
    );

    let reversed_transition = service.reverse_registration().unwrap();
    assert_eq!(reversed_transition.new_status, RegistrationStatus::Reversed);
    assert!(service.restore_registration().is_err());
}

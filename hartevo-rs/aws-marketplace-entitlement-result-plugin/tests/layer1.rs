use chrono::{Duration, TimeZone, Utc};
use serde_json::to_string;

use hartevo_aws_marketplace_entitlement_result_plugin::{
    AwsMarketplaceEntitlementError, AwsMarketplaceEntitlementProvider,
    AwsMarketplaceEntitlementScope, AwsMarketplaceEntitlementService, BlockedEnvTransport,
    ConsentScope, CustomerFilter, CustomerReference, EntitlementDimension,
    EntitlementEvidenceState, EntitlementProjection, ExpiryWindow, FixtureTransport,
    GetEntitlementsRequest, Layer1Authority, LicenseReference, MissionIdentity, PageTokenReference,
    ProductCode, ProjectIdentity, RecordingTransport, SecretReference, TransportProvenance,
    WorkProductIdentity,
};
use hartevo_aws_marketplace_entitlement_result_plugin::{
    CONTRACT_DIGEST, CONTRACT_JSON, GetEntitlementsResponse, MAX_PAGE_SIZE,
};

fn scope() -> AwsMarketplaceEntitlementScope {
    let observed_at = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap();
    let required_until = observed_at + Duration::days(30);
    AwsMarketplaceEntitlementScope::new(
        ProductCode::new("product-123").unwrap(),
        CustomerReference::aws_account("123456789012").unwrap(),
        EntitlementDimension::new("seats").unwrap(),
        LicenseReference::new("arn:aws:license-manager:us-east-1:123456789012:license/abc")
            .unwrap(),
        ExpiryWindow::new(observed_at, required_until).unwrap(),
        MissionIdentity::new("mission-673", 4).unwrap(),
        ProjectIdentity::new("project-673", 2).unwrap(),
        WorkProductIdentity::new("work-product-673", 1).unwrap(),
    )
    .unwrap()
}

fn fixture_service() -> AwsMarketplaceEntitlementService<FixtureTransport> {
    let scope = scope();
    let observed_at = scope.expiry().observed_at();
    let secret = SecretReference::sigv4("opaque-sigv4-handle", &scope, 1).unwrap();
    let consent =
        ConsentScope::for_layer_one("consent-673", 1, observed_at + Duration::days(2)).unwrap();
    let provider =
        AwsMarketplaceEntitlementProvider::new(FixtureTransport::for_scope(&scope, observed_at))
            .unwrap();
    AwsMarketplaceEntitlementService::new(scope, secret, consent, provider, observed_at).unwrap()
}

fn recording_service(
    transport: RecordingTransport,
) -> AwsMarketplaceEntitlementService<RecordingTransport> {
    let scope = scope();
    let observed_at = scope.expiry().observed_at();
    let secret = SecretReference::sigv4("opaque-recording-handle", &scope, 1).unwrap();
    let consent =
        ConsentScope::for_layer_one("consent-recording", 1, observed_at + Duration::days(2))
            .unwrap();
    let provider = AwsMarketplaceEntitlementProvider::new(transport).unwrap();
    AwsMarketplaceEntitlementService::new(scope, secret, consent, provider, observed_at).unwrap()
}

#[test]
fn contract_is_pinned_and_authority_is_false() {
    let contract = hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceEntitlementContract::baseline()
        .unwrap();
    assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
    assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
    assert!(CONTRACT_JSON.contains("GetEntitlements"));
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::first_party());
}

#[test]
fn scope_secret_and_registration_are_redacted_and_digest_bound() {
    let service = fixture_service();
    let registration = service.registration();
    let serialized = to_string(registration).unwrap();
    let debug = format!("{registration:?}");
    for raw in [
        "123456789012",
        "arn:aws:license-manager:us-east-1:123456789012:license/abc",
        "opaque-sigv4-handle",
        "seats",
    ] {
        assert!(
            !serialized.contains(raw),
            "serialized registration leaked {raw}"
        );
        assert!(!debug.contains(raw), "debug registration leaked {raw}");
    }
    assert!(registration.validate().is_ok());
    assert!(
        registration
            .secret_reference()
            .reference_digest()
            .as_str()
            .len()
            == 64
    );
}

#[test]
fn raw_entitlement_projection_drops_customer_license_dimension_and_value() {
    let scope = scope();
    let projection = EntitlementProjection::from_raw(
        &scope,
        scope.customer().kind(),
        "123456789012",
        "seats",
        "arn:aws:license-manager:us-east-1:123456789012:license/abc",
        scope.expiry().required_until() + Duration::hours(1),
        "raw-entitlement-value",
    )
    .unwrap();
    let serialized = to_string(&projection).unwrap();
    let debug = format!("{projection:?}");
    for raw in [
        "123456789012",
        "arn:aws:license-manager:us-east-1:123456789012:license/abc",
        "seats",
        "raw-entitlement-value",
    ] {
        assert!(!serialized.contains(raw));
        assert!(!debug.contains(raw));
    }
}

#[test]
fn fixture_is_complete_but_never_native_or_connected() {
    let mut service = fixture_service();
    let request = service
        .default_request(service.scope().expiry().observed_at())
        .unwrap();
    let proposal = service.propose(&request).unwrap();
    assert_eq!(proposal.state, EntitlementEvidenceState::Complete);
    assert_eq!(proposal.pages, 1);
    assert!(proposal.list_complete);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.can_be_adopted());
    assert!(service.verify(&proposal).valid);
    assert!(service.consumer().unwrap().consume(&proposal).is_ok());
}

#[test]
fn recording_reads_multiple_pages_and_digests_next_token() {
    let scope = scope();
    let first = GetEntitlementsRequest::first(&scope, MAX_PAGE_SIZE).unwrap();
    let token = PageTokenReference::from_raw("opaque-next-token").unwrap();
    let second = first.next_page(&scope, token.clone(), 2).unwrap();
    let projection = EntitlementProjection::for_scope(
        &scope,
        scope.expiry().required_until() + Duration::hours(1),
        hartevo_aws_marketplace_entitlement_result_plugin::Digest::from_text("page-value"),
    );
    let page_one =
        GetEntitlementsResponse::new(&first, vec![projection.clone()], Some(token)).unwrap();
    let page_two = GetEntitlementsResponse::new(&second, vec![projection], None).unwrap();
    let mut transport = RecordingTransport::default();
    transport.push_response(Ok(page_one));
    transport.push_response(Ok(page_two));
    let mut service = recording_service(transport);
    let request = service
        .default_request(scope.expiry().observed_at())
        .unwrap();
    let proposal = service.propose(&request).unwrap();
    assert_eq!(proposal.state, EntitlementEvidenceState::Complete);
    assert_eq!(proposal.pages, 2);
    assert_eq!(service.provider().transport().requests().len(), 2);
}

#[test]
fn empty_page_with_next_token_is_a_fence_not_success() {
    let scope = scope();
    let first = GetEntitlementsRequest::first(&scope, MAX_PAGE_SIZE).unwrap();
    let token = PageTokenReference::from_raw("opaque-empty-page-token").unwrap();
    let page = GetEntitlementsResponse::empty(&first, Some(token)).unwrap();
    let mut transport = RecordingTransport::default();
    transport.push_response(Ok(page));
    let mut service = recording_service(transport);
    let request = service
        .default_request(scope.expiry().observed_at())
        .unwrap();
    let proposal = service.propose(&request).unwrap();
    assert_eq!(proposal.state, EntitlementEvidenceState::EmptyPage);
    assert!(proposal.empty_page_fence);
    assert!(!proposal.list_complete);
    assert!(!service.verify(&proposal).valid);
}

#[test]
fn expired_entitlement_is_fail_closed() {
    let scope = scope();
    let first = GetEntitlementsRequest::first(&scope, MAX_PAGE_SIZE).unwrap();
    let projection = EntitlementProjection::for_scope(
        &scope,
        scope.expiry().observed_at() - Duration::minutes(1),
        hartevo_aws_marketplace_entitlement_result_plugin::Digest::from_text("expired-value"),
    );
    let page = GetEntitlementsResponse::new(&first, vec![projection], None).unwrap();
    let mut transport = RecordingTransport::default();
    transport.push_response(Ok(page));
    let mut service = recording_service(transport);
    let request = service
        .default_request(scope.expiry().observed_at())
        .unwrap();
    let proposal = service.propose(&request).unwrap();
    assert_eq!(proposal.state, EntitlementEvidenceState::Expired);
    assert_eq!(proposal.expiry_projection.expired, 1);
    assert!(!service.verify(&proposal).valid);
}

#[test]
fn repeated_next_token_is_a_pagination_loop_fence() {
    let scope = scope();
    let first = GetEntitlementsRequest::first(&scope, MAX_PAGE_SIZE).unwrap();
    let token = PageTokenReference::from_raw("repeated-next-token").unwrap();
    let second = first.next_page(&scope, token.clone(), 2).unwrap();
    let projection = EntitlementProjection::for_scope(
        &scope,
        scope.expiry().required_until() + Duration::hours(1),
        hartevo_aws_marketplace_entitlement_result_plugin::Digest::from_text("value"),
    );
    let page_one =
        GetEntitlementsResponse::new(&first, vec![projection.clone()], Some(token.clone()))
            .unwrap();
    let page_two = GetEntitlementsResponse::new(&second, vec![projection], Some(token)).unwrap();
    let mut transport = RecordingTransport::default();
    transport.push_response(Ok(page_one));
    transport.push_response(Ok(page_two));
    let mut service = recording_service(transport);
    let request = service
        .default_request(scope.expiry().observed_at())
        .unwrap();
    let proposal = service.propose(&request).unwrap();
    assert_eq!(proposal.state, EntitlementEvidenceState::PaginationLoop);
    assert!(!proposal.list_complete);
    assert!(!service.verify(&proposal).valid);
}

#[test]
fn tampered_response_and_transport_access_loss_fail_closed() {
    let scope = scope();
    let first = GetEntitlementsRequest::first(&scope, MAX_PAGE_SIZE).unwrap();
    let projection = EntitlementProjection::for_scope(
        &scope,
        scope.expiry().required_until() + Duration::hours(1),
        hartevo_aws_marketplace_entitlement_result_plugin::Digest::from_text("value"),
    );
    let page = GetEntitlementsResponse::new(&first, vec![projection], None)
        .unwrap()
        .with_declared_digest(
            hartevo_aws_marketplace_entitlement_result_plugin::Digest::from_text(
                "tampered-response",
            ),
        );
    let mut transport = RecordingTransport::default();
    transport.push_response(Ok(page));
    let mut service = recording_service(transport);
    let request = service
        .default_request(scope.expiry().observed_at())
        .unwrap();
    let proposal = service.propose(&request).unwrap();
    assert_eq!(proposal.state, EntitlementEvidenceState::Tampered);
    assert!(!service.verify(&proposal).valid);

    let mut loss_transport = RecordingTransport::default();
    loss_transport.push_response(Err(
        hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceTransportError::Unauthorized,
    ));
    let mut loss_service = recording_service(loss_transport);
    let loss_request = loss_service
        .default_request(scope.expiry().observed_at())
        .unwrap();
    let loss = loss_service.propose(&loss_request).unwrap();
    assert_eq!(loss.state, EntitlementEvidenceState::AccessLoss);
    assert_eq!(loss.failure.unwrap().status_code, Some(401));
}

#[test]
fn documented_transport_failures_remain_non_adoptable() {
    let cases = [
        (
            hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceTransportError::BadRequest,
            EntitlementEvidenceState::ProviderUnknown,
            Some(400),
        ),
        (
            hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceTransportError::Unauthorized,
            EntitlementEvidenceState::AccessLoss,
            Some(401),
        ),
        (
            hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceTransportError::Forbidden,
            EntitlementEvidenceState::AccessLoss,
            Some(403),
        ),
        (
            hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceTransportError::NotFound,
            EntitlementEvidenceState::NotFound,
            Some(404),
        ),
        (
            hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceTransportError::RateLimited {
                retry_after_seconds: Some(2),
            },
            EntitlementEvidenceState::Throttled,
            Some(429),
        ),
        (
            hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceTransportError::ServerError {
                status: 500,
            },
            EntitlementEvidenceState::ProviderUnknown,
            Some(500),
        ),
        (
            hartevo_aws_marketplace_entitlement_result_plugin::AwsMarketplaceTransportError::Timeout,
            EntitlementEvidenceState::ProviderUnknown,
            None,
        ),
    ];
    for (error, expected_state, expected_status) in cases {
        let mut transport = RecordingTransport::default();
        transport.push_response(Err(error));
        let mut service = recording_service(transport);
        let request = service
            .default_request(service.scope().expiry().observed_at())
            .unwrap();
        let proposal = service.propose(&request).unwrap();
        assert_eq!(proposal.state, expected_state);
        assert_eq!(
            proposal.failure.as_ref().unwrap().status_code,
            expected_status
        );
        assert!(!proposal.can_be_adopted());
    }
}

#[test]
fn recording_replay_and_revocation_fences_are_idempotent() {
    let scope = scope();
    let first = GetEntitlementsRequest::first(&scope, MAX_PAGE_SIZE).unwrap();
    let projection = EntitlementProjection::for_scope(
        &scope,
        scope.expiry().required_until() + Duration::hours(1),
        hartevo_aws_marketplace_entitlement_result_plugin::Digest::from_text("value"),
    );
    let complete = GetEntitlementsResponse::new(&first, vec![projection], None).unwrap();
    let empty = GetEntitlementsResponse::empty(&first, None).unwrap();
    let mut transport = RecordingTransport::default();
    transport.push_response(Ok(complete));
    transport.push_response(Ok(empty));
    let mut service = recording_service(transport);
    let request = service
        .default_request(scope.expiry().observed_at())
        .unwrap();
    let proposal = service.propose(&request).unwrap();
    let second_proposal = service.propose(&request).unwrap();
    let mut consumer = service.consumer().unwrap();
    let first_record = consumer.record(&proposal, "same-key").unwrap();
    let replay = consumer.record(&proposal, "same-key").unwrap();
    assert!(!first_record.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert_eq!(
        consumer.record(&second_proposal, "same-key").unwrap_err(),
        AwsMarketplaceEntitlementError::ReplayConflict
    );

    service.revoke().unwrap();
    let revoked_proposal = service.propose(&request).unwrap();
    assert_eq!(
        revoked_proposal.state,
        EntitlementEvidenceState::RegistrationRevoked
    );
    assert!(service.consumer().is_err());
}

#[test]
fn all_local_provenances_are_non_native() {
    for provenance in [
        TransportProvenance::Recording,
        TransportProvenance::Fixture,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_connected());
        assert!(!provenance.is_native());
        assert!(!provenance.is_first_party());
    }
    let mut provider = AwsMarketplaceEntitlementProvider::new(BlockedEnvTransport).unwrap();
    assert!(!provider.definition().connected());
    assert!(!provider.definition().native());
    assert!(!provider.definition().first_party());
    let request = GetEntitlementsRequest::first(&scope(), MAX_PAGE_SIZE).unwrap();
    assert!(provider.get_entitlements(&request).is_err());
}

#[test]
fn customer_filter_is_exactly_one_digest_bound_variant() {
    let account = CustomerReference::aws_account("123456789012").unwrap();
    let filter = CustomerFilter::from_reference(&account);
    assert_eq!(filter.kind(), account.kind());
    assert_eq!(filter.digest(), account.digest());
}

#[test]
fn recorded_result_rejects_native_claims() {
    let mut service = fixture_service();
    let request = service
        .default_request(service.scope().expiry().observed_at())
        .unwrap();
    let proposal = service.propose(&request).unwrap();
    let mut consumer = service.consumer().unwrap();
    let record = consumer.record(&proposal, "recorded-key").unwrap();
    assert!(record.validate_integrity().is_ok());
    let json = to_string(&record).unwrap();
    assert!(!json.contains("connected\":true"));
}

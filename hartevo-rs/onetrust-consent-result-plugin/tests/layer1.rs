use chrono::{Duration, TimeZone, Utc};
use hartevo_onetrust_consent_result_plugin::{
    BlockedEnvOneTrustTransport, CollectionPointId, ConsentBinding, ConsentEvidenceStatus,
    ConsentId, ConsentWindow, Digest, MissionBinding, MissionId, MissionOneTrustConsentConsumer,
    ONETRUST_MAX_PAGES, ONETRUST_PAGE_SIZE, ONETRUST_PROVIDER_REVISION_TEXT,
    OneTrustConsentEvidenceService, OneTrustConsentObservation, OneTrustConsentResultContract,
    OneTrustConsentScope, OneTrustEndpoint, OneTrustEvidenceBundle,
    OneTrustEvidenceProposalRequest, OneTrustHttpRequest, OneTrustHttpResponse,
    OneTrustReadRequest, OneTrustResponseBody, OneTrustTransport, OneTrustTransportError,
    PolicyRevision, ProjectBinding, ProjectId, ProviderRevision, RecordingOneTrustTransport,
    Region, Revision, SecretReference, SubjectReferenceHash, TenantId, TransportProvenance,
    WorkProductBinding, WorkProductId,
};

fn at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 16, 0, 0)
        .single()
        .expect("fixed test time")
}

fn scope() -> OneTrustConsentScope {
    let subject = SubjectReferenceHash::new(
        &Digest::from_text("scope-binding-v1"),
        "fixture-salt-v1",
        "alice@example.com",
    )
    .expect("opaque subject hash");
    OneTrustConsentScope::new(
        TenantId::new("tenant-1").expect("tenant"),
        Region::new("us").expect("region"),
        hartevo_onetrust_consent_result_plugin::PurposeId::new("purpose-1").expect("purpose"),
        hartevo_onetrust_consent_result_plugin::PurposeVersion::new("v2").expect("purpose version"),
        CollectionPointId::new("web-checkout").expect("collection point"),
        ConsentWindow::new(at() - Duration::hours(6), at()).expect("window"),
        subject,
        PolicyRevision::new("policy-7").expect("policy revision"),
        MissionBinding::new(
            MissionId::new("mission-1").expect("Mission"),
            Revision::new(11).expect("Mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("Project"),
            Revision::new(5).expect("Project revision"),
        ),
        ConsentBinding::new(
            ConsentId::new("consent-1").expect("consent"),
            Revision::new(2).expect("consent revision"),
            Digest::from_text("consent-revision-2"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("Work Product"),
            Revision::new(3).expect("Work Product revision"),
        ),
        Digest::from_text("permission-revision-1"),
    )
    .expect("scope")
}

fn secret() -> SecretReference {
    SecretReference::new("native-onetrust-secret-material").expect("opaque secret")
}

fn provider_revision() -> ProviderRevision {
    ProviderRevision::new(ONETRUST_PROVIDER_REVISION_TEXT).expect("provider revision")
}

fn observation(
    scope: &OneTrustConsentScope,
    status: ConsentEvidenceStatus,
) -> OneTrustConsentObservation {
    OneTrustConsentObservation::new(
        scope.purpose_id.clone(),
        scope.purpose_version.clone(),
        status,
        (status == ConsentEvidenceStatus::Granted).then_some(at() - Duration::minutes(20)),
        (status == ConsentEvidenceStatus::Withdrawn).then_some(at() - Duration::minutes(10)),
        None,
        scope.collection_point.clone(),
        Some(Digest::from_text("transaction-1")),
        scope.policy_revision.clone(),
        scope.subject_reference.clone(),
        Digest::from_text("fixture-source"),
    )
}

fn response_for(
    scope: &OneTrustConsentScope,
    endpoint: OneTrustEndpoint,
    status_code: u16,
    body: OneTrustResponseBody,
    next_cursor: Option<hartevo_onetrust_consent_result_plugin::OpaqueCursor>,
) -> OneTrustHttpResponse {
    let read = OneTrustReadRequest::new(
        endpoint,
        scope,
        ONETRUST_PAGE_SIZE,
        ONETRUST_MAX_PAGES,
        at(),
    )
    .expect("read request");
    let request = OneTrustHttpRequest::from_read(&read).expect("HTTP request");
    OneTrustHttpResponse::from_body(
        &request,
        status_code,
        body,
        provider_revision(),
        next_cursor,
    )
    .expect("typed response")
}

fn fixture_responses(
    scope: &OneTrustConsentScope,
    status: ConsentEvidenceStatus,
) -> Vec<Result<OneTrustHttpResponse, OneTrustTransportError>> {
    scope
        .expected_endpoints()
        .into_iter()
        .map(|endpoint| {
            let body = OneTrustResponseBody::new(vec![observation(scope, status)])
                .expect("observation body");
            Ok(response_for(scope, endpoint, 200, body, None))
        })
        .collect()
}

fn service_with_fixture(
    scope: OneTrustConsentScope,
    status: ConsentEvidenceStatus,
) -> OneTrustConsentEvidenceService<RecordingOneTrustTransport> {
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::fixture(fixture_responses(&scope, status)),
    )
    .expect("provider");
    OneTrustConsentEvidenceService::new(scope, secret(), provider).expect("service")
}

#[test]
fn contract_and_registration_are_typed_version_and_digest_fences() {
    let contract = OneTrustConsentResultContract::baseline().expect("contract");
    assert_eq!(
        contract.digest(),
        hartevo_onetrust_consent_result_plugin::contract_digest()
    );
    assert!(hartevo_onetrust_consent_result_plugin::contract_bounds_tripwire());
    let service = service_with_fixture(scope(), ConsentEvidenceStatus::Granted);
    let registration = service.registration();
    assert!(registration.is_active());
    assert_eq!(registration.mission_revision.get(), 11);
    assert_eq!(registration.project_revision.get(), 5);
    assert_eq!(registration.consent_revision.get(), 2);
    assert_eq!(registration.work_product_revision.get(), 3);
    assert_eq!(registration.provider_id, "onetrust.consent");
    assert_eq!(
        registration.service_implementation,
        "OneTrustConsentEvidenceService"
    );
    let debug = format!("{:?}", service.secret_reference());
    let encoded = serde_json::to_string(service.secret_reference()).expect("opaque secret JSON");
    assert!(!debug.contains("native-onetrust-secret-material"));
    assert!(!encoded.contains("native-onetrust-secret-material"));
    assert!(!encoded.contains("eyJ"));
}

#[test]
fn granted_evidence_is_bounded_recordable_and_non_mutating() {
    let mut service = service_with_fixture(scope(), ConsentEvidenceStatus::Granted);
    let proposal = service
        .propose(OneTrustEvidenceProposalRequest::new(at()))
        .expect("proposal");
    assert_eq!(proposal.status(), ConsentEvidenceStatus::Granted);
    assert_eq!(proposal.evidence.observations.len(), 3);
    assert!(proposal.read_only);
    assert!(proposal.proposal_only);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.consent_receipt_created);
    assert!(!proposal.consent_withdrawn);
    assert!(!proposal.preference_updated);
    assert!(!proposal.adopted_by_kernel);
    assert!(!proposal.evidence.raw_preference_payload_retained);
    assert!(!proposal.evidence.raw_subject_identifier_retained);
    assert!(!proposal.evidence.raw_jwt_retained);
    assert!(!proposal.evidence.raw_pii_retained);

    let consumer =
        MissionOneTrustConsentConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let adoption = consumer.consume(&proposal).expect("adoption proposal");
    assert!(!adoption.adopted);
    assert!(!adoption.mutates_consent);
    assert!(!adoption.creates_effect);
    assert!(!adoption.kernel_authority);
    assert!(!adoption.outcome_authority);
    assert_eq!(adoption.evidence_digest, proposal.evidence.evidence_digest);

    let verification = service.verify(&proposal).expect("verification");
    assert!(verification.verified);
    assert!(!verification.kernel_authority);
    let receipt = service.record(&proposal).expect("recording receipt");
    assert!(receipt.recorded);
    assert!(!receipt.raw_provider_payload_retained);
    assert!(!receipt.raw_subject_identifier_retained);
    assert!(!receipt.raw_jwt_retained);
    assert!(!receipt.consent_receipt_created);
    assert!(!receipt.preference_updated);
}

#[test]
fn subject_hash_is_salted_scope_bound_and_redacts_raw_json() {
    let scope = scope();
    let same_scope_hash = SubjectReferenceHash::new(
        scope.subject_scope_digest(),
        "fixture-salt-v1",
        "alice@example.com",
    )
    .expect("subject hash");
    let other_scope_hash = SubjectReferenceHash::new(
        &Digest::from_text("different-scope"),
        "fixture-salt-v1",
        "alice@example.com",
    )
    .expect("other subject hash");
    assert_ne!(same_scope_hash.digest(), other_scope_hash.digest());
    assert!(same_scope_hash.is_opaque());
    let encoded_hash = serde_json::to_string(&same_scope_hash).expect("subject hash JSON");
    assert!(!encoded_hash.contains("alice@example.com"));

    let read = OneTrustReadRequest::new(
        OneTrustEndpoint::RealtimePreferencesV2,
        &scope,
        ONETRUST_PAGE_SIZE,
        ONETRUST_MAX_PAGES,
        at(),
    )
    .expect("read request");
    let request = OneTrustHttpRequest::from_read(&read).expect("HTTP request");
    let raw = br#"{
      "data": [{
        "purposeId": "purpose-1",
        "purposeVersion": "v2",
        "status": "granted",
        "consentTimestamp": "2026-08-14T15:40:00Z",
        "collectionPoint": "web-checkout",
        "policyRevision": "policy-7",
        "transactionId": "transaction-raw-1",
        "subject": "alice@example.com",
        "email": "alice@example.com",
        "phone": "+15555550123",
        "name": "Alice Example",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.raw.jwt",
        "preferences": {"raw": "do-not-retain"}
      }]
    }"#;
    let response = OneTrustHttpResponse::from_json(&request, 200, raw, provider_revision(), None)
        .expect("redacted response");
    let encoded = serde_json::to_string(&response).expect("response JSON");
    for forbidden in [
        "alice@example.com",
        "+15555550123",
        "Alice Example",
        "eyJhbGciOiJIUzI1NiJ9",
        "do-not-retain",
        "transaction-raw-1",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "raw value survived: {forbidden}"
        );
    }
    assert!(!response.receipt.raw_preference_payload_retained);
    assert!(!response.receipt.raw_pii_retained);
    assert!(!response.receipt.raw_jwt_retained);
}

#[test]
fn official_read_surfaces_have_bounded_paths_and_methods() {
    let scope = scope();
    let expected = [
        (
            OneTrustEndpoint::DataSubjectDetailsV4,
            "GET",
            "https://tenant-1.onetrust.com",
            "/rest/api/consent/v4/datasubjects/details?pageSize=50",
        ),
        (
            OneTrustEndpoint::RealtimePreferencesV2,
            "GET",
            "https://consent-api.onetrust.com",
            "/v2/preferences?pageSize=50",
        ),
        (
            OneTrustEndpoint::TransactionsV2,
            "POST",
            "https://tenant-1.onetrust.com",
            "/api/consent/v2/transactions?pageSize=50",
        ),
    ];
    for (endpoint, method, origin, path) in expected {
        let read = OneTrustReadRequest::new(
            endpoint,
            &scope,
            ONETRUST_PAGE_SIZE,
            ONETRUST_MAX_PAGES,
            at(),
        )
        .expect("request");
        let request = OneTrustHttpRequest::from_read(&read).expect("HTTP request");
        assert_eq!(request.method, method);
        assert_eq!(request.origin, origin);
        assert_eq!(request.path_and_query, path);
        assert!(!request.path_and_query.contains("alice@example.com"));
    }
}

#[test]
fn consent_states_distinguish_withdrawn_expired_and_no_record() {
    for (input, expected) in [
        (
            ConsentEvidenceStatus::Withdrawn,
            ConsentEvidenceStatus::Withdrawn,
        ),
        (ConsentEvidenceStatus::Denied, ConsentEvidenceStatus::Denied),
        (
            ConsentEvidenceStatus::Pending,
            ConsentEvidenceStatus::Pending,
        ),
    ] {
        let mut service = service_with_fixture(scope(), input);
        let proposal = service
            .propose(OneTrustEvidenceProposalRequest::new(at()))
            .expect("proposal");
        assert_eq!(proposal.status(), expected);
    }

    let expired_scope = scope();
    let expired = OneTrustConsentObservation::new(
        expired_scope.purpose_id.clone(),
        expired_scope.purpose_version.clone(),
        ConsentEvidenceStatus::Granted,
        Some(at() - Duration::hours(2)),
        None,
        Some(at() - Duration::minutes(1)),
        expired_scope.collection_point.clone(),
        None,
        expired_scope.policy_revision.clone(),
        expired_scope.subject_reference.clone(),
        Digest::from_text("expired-source"),
    );
    let responses = expired_scope
        .expected_endpoints()
        .into_iter()
        .map(|endpoint| {
            Ok(response_for(
                &expired_scope,
                endpoint,
                200,
                OneTrustResponseBody::new(vec![expired.clone()]).expect("body"),
                None,
            ))
        })
        .collect::<Vec<_>>();
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::fixture(responses),
    )
    .expect("provider");
    let mut service =
        OneTrustConsentEvidenceService::new(expired_scope.clone(), secret(), provider)
            .expect("service");
    let expired_proposal = service
        .propose(OneTrustEvidenceProposalRequest::new(at()))
        .expect("expired proposal");
    assert_eq!(expired_proposal.status(), ConsentEvidenceStatus::Expired);

    let empty_scope = scope();
    let empty_responses = empty_scope
        .expected_endpoints()
        .into_iter()
        .map(|endpoint| {
            Ok(response_for(
                &empty_scope,
                endpoint,
                200,
                OneTrustResponseBody::empty(),
                None,
            ))
        })
        .collect::<Vec<_>>();
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::fixture(empty_responses),
    )
    .expect("provider");
    let mut service =
        OneTrustConsentEvidenceService::new(empty_scope, secret(), provider).expect("service");
    let no_record = service
        .propose(OneTrustEvidenceProposalRequest::new(at()))
        .expect("no-record proposal");
    assert_eq!(no_record.status(), ConsentEvidenceStatus::NoRecord);
}

#[test]
fn blocked_env_and_deterministic_provenance_are_honest() {
    let scope = scope();
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        BlockedEnvOneTrustTransport,
    )
    .expect("blocked provider");
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
    assert!(!provider.definition().native);
    assert!(!provider.definition().connected);
    let mut service =
        OneTrustConsentEvidenceService::new(scope.clone(), secret(), provider).expect("service");
    let proposal = service
        .propose(OneTrustEvidenceProposalRequest::new(at()))
        .expect("blocked proposal");
    assert_eq!(proposal.status(), ConsentEvidenceStatus::ProviderUnknown);
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.evidence.raw_jwt_retained);

    let endpoint = OneTrustEndpoint::DataSubjectDetailsV4;
    let response = response_for(&scope, endpoint, 200, OneTrustResponseBody::empty(), None);
    for (transport, provenance) in [
        (
            RecordingOneTrustTransport::fixture([Ok(response.clone())]),
            TransportProvenance::Fixture,
        ),
        (
            RecordingOneTrustTransport::new([Ok(response.clone())]),
            TransportProvenance::Recording,
        ),
        (
            RecordingOneTrustTransport::loopback([Ok(response)]),
            TransportProvenance::Loopback,
        ),
    ] {
        let provider =
            hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(transport)
                .expect("provider");
        assert_eq!(provider.provenance(), provenance);
        assert!(!provider.provenance().is_native());
    }
}

#[test]
fn cursor_loops_tamper_and_stale_policy_fail_closed() {
    let scope = scope();
    let endpoint = OneTrustEndpoint::DataSubjectDetailsV4;
    let cursor =
        hartevo_onetrust_consent_result_plugin::OpaqueCursor::new("page-1").expect("cursor");
    let first_request = OneTrustReadRequest::new(
        endpoint,
        &scope,
        ONETRUST_PAGE_SIZE,
        ONETRUST_MAX_PAGES,
        at(),
    )
    .expect("first read");
    let first_http = OneTrustHttpRequest::from_read(&first_request).expect("first HTTP");
    let first = OneTrustHttpResponse::from_body(
        &first_http,
        200,
        OneTrustResponseBody::new(vec![observation(&scope, ConsentEvidenceStatus::Granted)])
            .expect("body"),
        provider_revision(),
        Some(cursor.clone()),
    )
    .expect("first response");
    let second_request = first_request.with_cursor(Some(cursor.clone()));
    let second_http = OneTrustHttpRequest::from_read(&second_request).expect("second HTTP");
    let second = OneTrustHttpResponse::from_body(
        &second_http,
        200,
        OneTrustResponseBody::new(vec![observation(&scope, ConsentEvidenceStatus::Granted)])
            .expect("body"),
        provider_revision(),
        Some(cursor),
    )
    .expect("second response");
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::new([Ok(first), Ok(second)]),
    )
    .expect("provider");
    let mut service =
        OneTrustConsentEvidenceService::new(scope.clone(), secret(), provider).expect("service");
    assert!(
        service
            .read(endpoint, ONETRUST_PAGE_SIZE, ONETRUST_MAX_PAGES, at())
            .is_err()
    );

    let mut tampered_response = response_for(
        &scope,
        endpoint,
        200,
        OneTrustResponseBody::new(vec![observation(&scope, ConsentEvidenceStatus::Granted)])
            .expect("body"),
        None,
    );
    tampered_response.body.observations[0].status = ConsentEvidenceStatus::Denied;
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::new([Ok(tampered_response)]),
    )
    .expect("provider");
    let mut service =
        OneTrustConsentEvidenceService::new(scope.clone(), secret(), provider).expect("service");
    assert!(
        service
            .read(endpoint, ONETRUST_PAGE_SIZE, ONETRUST_MAX_PAGES, at())
            .is_err()
    );

    let stale = OneTrustConsentObservation::new(
        scope.purpose_id.clone(),
        scope.purpose_version.clone(),
        ConsentEvidenceStatus::Granted,
        None,
        None,
        None,
        scope.collection_point.clone(),
        None,
        PolicyRevision::new("policy-old").expect("old policy"),
        scope.subject_reference.clone(),
        Digest::from_text("stale-source"),
    );
    let stale_response = response_for(
        &scope,
        endpoint,
        200,
        OneTrustResponseBody::new(vec![stale]).expect("stale body"),
        None,
    );
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::new([Ok(stale_response)]),
    )
    .expect("provider");
    let mut service =
        OneTrustConsentEvidenceService::new(scope, secret(), provider).expect("service");
    assert!(
        service
            .read(endpoint, ONETRUST_PAGE_SIZE, ONETRUST_MAX_PAGES, at())
            .is_err()
    );
}

#[test]
fn status_errors_timeouts_rate_limits_and_revocation_fail_closed() {
    for status_code in [401, 403, 404, 409, 429, 500, 503] {
        let scope = scope();
        let endpoint = OneTrustEndpoint::DataSubjectDetailsV4;
        let response = response_for(
            &scope,
            endpoint,
            status_code,
            OneTrustResponseBody::empty(),
            None,
        );
        let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
            RecordingOneTrustTransport::new([Ok(response)]),
        )
        .expect("provider");
        let mut service =
            OneTrustConsentEvidenceService::new(scope, secret(), provider).expect("service");
        assert!(
            service
                .read(endpoint, ONETRUST_PAGE_SIZE, ONETRUST_MAX_PAGES, at())
                .is_err(),
            "HTTP {status_code} must fail closed"
        );
    }

    let rate_scope = scope();
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::new([
            Err(OneTrustTransportError::Timeout),
            Err(OneTrustTransportError::Timeout),
            Err(OneTrustTransportError::Timeout),
            Err(OneTrustTransportError::Timeout),
            Err(OneTrustTransportError::Timeout),
            Err(OneTrustTransportError::Timeout),
        ]),
    )
    .expect("provider");
    let mut service = OneTrustConsentEvidenceService::new(rate_scope.clone(), secret(), provider)
        .expect("service");
    for _ in 0..5 {
        assert!(
            service
                .read(
                    OneTrustEndpoint::DataSubjectDetailsV4,
                    ONETRUST_PAGE_SIZE,
                    ONETRUST_MAX_PAGES,
                    at(),
                )
                .is_err()
        );
    }
    let rate_limited = service.read(
        OneTrustEndpoint::DataSubjectDetailsV4,
        ONETRUST_PAGE_SIZE,
        ONETRUST_MAX_PAGES,
        at(),
    );
    assert!(matches!(
        rate_limited,
        Err(hartevo_onetrust_consent_result_plugin::OneTrustConsentResultError::RateLimited { .. })
    ));

    let mut service = service_with_fixture(scope(), ConsentEvidenceStatus::Granted);
    service.registration_mut().permission_digest = Digest::from_text("tampered-permission");
    assert!(matches!(
        service.read(
            OneTrustEndpoint::DataSubjectDetailsV4,
            ONETRUST_PAGE_SIZE,
            ONETRUST_MAX_PAGES,
            at(),
        ),
        Err(
            hartevo_onetrust_consent_result_plugin::OneTrustConsentResultError::RegistrationDrift(
                _
            )
        )
    ));

    let mut service = service_with_fixture(scope(), ConsentEvidenceStatus::Granted);
    service.revoke_registration().expect("revoke");
    assert!(
        service
            .read(
                OneTrustEndpoint::DataSubjectDetailsV4,
                ONETRUST_PAGE_SIZE,
                ONETRUST_MAX_PAGES,
                at(),
            )
            .is_err()
    );
    assert!(service.revoke_registration().is_err());
    let mut service = service_with_fixture(scope(), ConsentEvidenceStatus::Granted);
    service.revoke_secret().expect("revoke secret");
    assert!(
        service
            .read(
                OneTrustEndpoint::DataSubjectDetailsV4,
                ONETRUST_PAGE_SIZE,
                ONETRUST_MAX_PAGES,
                at(),
            )
            .is_err()
    );
}

#[test]
fn transport_request_receipts_are_scope_bound_and_recording_is_typed() {
    let scope = scope();
    let endpoint = OneTrustEndpoint::TransactionsV2;
    let response = response_for(&scope, endpoint, 200, OneTrustResponseBody::empty(), None);
    let mut transport = RecordingOneTrustTransport::fixture([Ok(response)]);
    let read = OneTrustReadRequest::new(
        endpoint,
        &scope,
        ONETRUST_PAGE_SIZE,
        ONETRUST_MAX_PAGES,
        at(),
    )
    .expect("read");
    let request = OneTrustHttpRequest::from_read(&read).expect("HTTP request");
    let response = transport.send(&request).expect("response");
    assert_eq!(response.receipt.request_digest, request.request_digest);
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].scope_digest, scope.scope_digest());
    assert!(transport.requests()[0].body_digest.is_some());
    assert!(!format!("{transport:?}").contains("alice@example.com"));
}

#[test]
fn read_level_partial_failures_project_fail_closed() {
    let scope = scope();
    let endpoint = OneTrustEndpoint::DataSubjectDetailsV4;
    let read = OneTrustReadRequest::new(endpoint, &scope, ONETRUST_PAGE_SIZE, 1, at())
        .expect("bounded one-page read");
    let request = OneTrustHttpRequest::from_read(&read).expect("HTTP request");
    let response = OneTrustHttpResponse::from_body(
        &request,
        200,
        OneTrustResponseBody::new(vec![observation(&scope, ConsentEvidenceStatus::Granted)])
            .expect("body"),
        provider_revision(),
        Some(
            hartevo_onetrust_consent_result_plugin::OpaqueCursor::new("next-page").expect("cursor"),
        ),
    )
    .expect("response");
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::fixture([Ok(response)]),
    )
    .expect("provider");
    let mut service =
        OneTrustConsentEvidenceService::new(scope.clone(), secret(), provider).expect("service");
    let read_evidence = service
        .read(endpoint, ONETRUST_PAGE_SIZE, 1, at())
        .expect("partial read evidence");
    assert!(read_evidence.failures.iter().any(|failure| failure.kind
        == hartevo_onetrust_consent_result_plugin::OneTrustProviderErrorKind::Partial));

    let bundle = OneTrustEvidenceBundle::new(
        &scope,
        service.registration().registration_digest.clone(),
        service.provider().provider_digest().clone(),
        service.provider().provider_revision().clone(),
        vec![read_evidence],
        Vec::new(),
        service.provider().provenance(),
    )
    .expect("bundle");
    let proposal = service
        .compile_evidence_proposal(bundle, at())
        .expect("proposal");
    assert_eq!(proposal.status(), ConsentEvidenceStatus::Partial);
    assert!(proposal.projection.partial);
    assert!(proposal.projection.fail_closed);
}

#[test]
fn observations_outside_requested_window_fail_closed() {
    let scope = scope();
    for (consented_at, withdrawn_at, expires_at) in [
        (Some(at() + Duration::seconds(1)), None, None),
        (None, Some(at() + Duration::seconds(1)), None),
        (None, None, Some(at() + Duration::seconds(1))),
    ] {
        let observation = OneTrustConsentObservation::new(
            scope.purpose_id.clone(),
            scope.purpose_version.clone(),
            ConsentEvidenceStatus::Granted,
            consented_at,
            withdrawn_at,
            expires_at,
            scope.collection_point.clone(),
            None,
            scope.policy_revision.clone(),
            scope.subject_reference.clone(),
            Digest::from_text("outside-window-source"),
        );
        assert!(observation.validate_against(&scope).is_err());
    }

    let endpoint = OneTrustEndpoint::DataSubjectDetailsV4;
    let response = response_for(
        &scope,
        endpoint,
        200,
        OneTrustResponseBody::new(vec![OneTrustConsentObservation::new(
            scope.purpose_id.clone(),
            scope.purpose_version.clone(),
            ConsentEvidenceStatus::Granted,
            Some(at() + Duration::seconds(1)),
            None,
            None,
            scope.collection_point.clone(),
            None,
            scope.policy_revision.clone(),
            scope.subject_reference.clone(),
            Digest::from_text("provider-outside-window-source"),
        )])
        .expect("body"),
        None,
    );
    let provider = hartevo_onetrust_consent_result_plugin::OneTrustConsentProvider::new(
        RecordingOneTrustTransport::new([Ok(response)]),
    )
    .expect("provider");
    let mut service =
        OneTrustConsentEvidenceService::new(scope, secret(), provider).expect("service");
    assert!(
        service
            .read(endpoint, ONETRUST_PAGE_SIZE, ONETRUST_MAX_PAGES, at())
            .is_err()
    );
}

#[test]
fn proposal_verification_recomputes_nested_digests_and_redaction_flags() {
    let mut service = service_with_fixture(scope(), ConsentEvidenceStatus::Granted);
    let proposal = service
        .propose(OneTrustEvidenceProposalRequest::new(at()))
        .expect("proposal");

    let mut nested_tamper = proposal.clone();
    nested_tamper.evidence.observations[0].status = ConsentEvidenceStatus::Denied;
    nested_tamper.proposal_digest = nested_tamper.recompute_digest().expect("outer digest");
    assert!(service.verify(&nested_tamper).is_err());

    let mut receipt_tamper = proposal.clone();
    receipt_tamper.evidence.request_receipt_digests[0] = Digest::from_text("tampered-receipt");
    receipt_tamper.proposal_digest = receipt_tamper.recompute_digest().expect("outer digest");
    assert!(service.verify(&receipt_tamper).is_err());

    let mut pagination_tamper = proposal.clone();
    pagination_tamper.evidence.pages_observed = 0;
    pagination_tamper.evidence.source_digest = pagination_tamper
        .evidence
        .recompute_source_digest()
        .expect("source digest");
    pagination_tamper.evidence.result_digest = pagination_tamper
        .evidence
        .recompute_result_digest()
        .expect("result digest");
    pagination_tamper.evidence.evidence_digest = pagination_tamper
        .evidence
        .recompute_evidence_digest()
        .expect("evidence digest");
    pagination_tamper.proposal_digest = pagination_tamper.recompute_digest().expect("outer digest");
    assert!(service.verify(&pagination_tamper).is_err());

    let mut encoded = serde_json::to_value(&proposal).expect("proposal JSON");
    encoded["evidence"]["rawPiiRetained"] = serde_json::Value::Bool(true);
    let redaction_tamper = serde_json::from_value(encoded).expect("tampered proposal JSON");
    assert!(service.verify(&redaction_tamper).is_err());

    let mut encoded = serde_json::to_value(&proposal).expect("proposal JSON");
    encoded["evidence"]["resultDigest"] =
        serde_json::Value::String(Digest::from_text("tampered-result").as_str().to_owned());
    let digest_tamper = serde_json::from_value(encoded).expect("tampered proposal JSON");
    assert!(service.verify(&digest_tamper).is_err());
}

#[test]
fn registration_revocation_reaches_existing_mission_consumers() {
    let mut service = service_with_fixture(scope(), ConsentEvidenceStatus::Granted);
    let consumer =
        MissionOneTrustConsentConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let proposal = service
        .propose(OneTrustEvidenceProposalRequest::new(at()))
        .expect("proposal");
    assert!(consumer.is_active());
    service.revoke_registration().expect("registration revoke");
    assert!(!consumer.is_active());
    assert!(matches!(
        consumer.consume(&proposal),
        Err(hartevo_onetrust_consent_result_plugin::OneTrustConsumerError::Revoked)
    ));
}

#[test]
fn response_missing_scope_identifiers_never_fall_back_to_request_scope() {
    let scope = scope();
    let endpoint = OneTrustEndpoint::RealtimePreferencesV2;
    let read = OneTrustReadRequest::new(
        endpoint,
        &scope,
        ONETRUST_PAGE_SIZE,
        ONETRUST_MAX_PAGES,
        at(),
    )
    .expect("read");
    let request = OneTrustHttpRequest::from_read(&read).expect("HTTP request");
    for missing in [
        "purposeId",
        "purposeVersion",
        "collectionPoint",
        "policyRevision",
    ] {
        let mut record = serde_json::json!({
            "purposeId": "purpose-1",
            "purposeVersion": "v2",
            "status": "granted",
            "collectionPoint": "web-checkout",
            "policyRevision": "policy-7",
        });
        record
            .as_object_mut()
            .expect("record object")
            .remove(missing);
        let raw =
            serde_json::to_vec(&serde_json::json!({ "data": [record] })).expect("response JSON");
        assert!(
            OneTrustHttpResponse::from_json(&request, 200, &raw, provider_revision(), None)
                .is_err(),
            "missing {missing} must fail closed"
        );
    }
}

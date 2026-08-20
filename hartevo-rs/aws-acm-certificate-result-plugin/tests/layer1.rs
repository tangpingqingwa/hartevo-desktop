use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_acm_certificate_result_plugin::{
    AccountId, AcmOperation, AwsAcmCertificateScope, AwsAcmCertificateService, AwsAcmProvider,
    AwsAcmTransportError, CertificateArn, CertificateDescription, CertificateDescriptionInput,
    CertificateEvidenceState, CertificateIdentity, CertificateIssuer, CertificateStatus,
    CertificateSummary, DeploymentBinding, DeploymentId, DomainName, FixtureTransport,
    KeyAlgorithm, KeyUsage, ListCertificatesFilter, ListCertificatesRequest,
    ListCertificatesResponse, LoopbackTransport, MissionBinding, MissionId, OpaqueNextToken,
    PermissionFence, PermissionId, ProjectBinding, ProjectId, RecordingTransport, Revision,
    SecretReference, TransportProvenance, WorkProductBinding, WorkProductId,
};

const ARN: &str = "arn:aws:acm:us-east-1:123456789012:certificate/fixture-certificate";
const DOMAIN: &str = "www.example.test";
const ACCOUNT: &str = "123456789012";
const OBSERVED_SECONDS: i64 = 1_787_000_000;

fn observed_at() -> DateTime<Utc> {
    Utc.timestamp_opt(OBSERVED_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> (AwsAcmCertificateScope, PermissionFence) {
    let permission = PermissionFence::readonly(
        PermissionId::new("acm-read-permission").expect("permission id"),
        Revision::new(1).expect("permission revision"),
    )
    .expect("permission");
    let certificate = CertificateIdentity::new(
        CertificateArn::new(ARN).expect("certificate ARN"),
        DomainName::new(DOMAIN).expect("domain"),
        vec![DOMAIN.to_owned()],
    )
    .expect("certificate identity");
    let scope = AwsAcmCertificateScope::new(
        DeploymentBinding::new(
            DeploymentId::new("deployment-1").expect("deployment"),
            Revision::new(2).expect("deployment revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-1").expect("mission"),
            Revision::new(3).expect("mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(4).expect("project revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(5).expect("work product revision"),
        ),
        AccountId::new(ACCOUNT).expect("account"),
        hartevo_aws_acm_certificate_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        certificate,
        Revision::new(7).expect("certificate revision"),
        permission.digest(),
    )
    .expect("scope");
    (scope, permission)
}

fn secret(scope: &AwsAcmCertificateScope) -> SecretReference {
    SecretReference::sigv4("opaque-acm-keyring-ref", scope, 1).expect("secret reference")
}

fn input(
    scope: &AwsAcmCertificateScope,
    status: CertificateStatus,
    observed_at: DateTime<Utc>,
) -> CertificateDescriptionInput {
    CertificateDescriptionInput::new(
        ARN,
        DOMAIN,
        vec![DOMAIN.to_owned()],
        status,
        CertificateIssuer::Amazon,
        KeyAlgorithm::Rsa2048,
        [KeyUsage::ServerAuth],
        Some(observed_at),
        Some(observed_at + Duration::days(90)),
        hartevo_aws_acm_certificate_result_plugin::RenewalEligibility::Eligible,
        true,
        scope.certificate_revision,
        observed_at,
    )
    .expect("certificate input")
}

fn recording_service(
    list_status: CertificateStatus,
    describe_status: CertificateStatus,
) -> AwsAcmCertificateService<RecordingTransport> {
    let (scope, permission) = scope();
    let list_request = ListCertificatesRequest::new(
        &scope,
        ListCertificatesFilter::all(50).expect("filter"),
        None,
    )
    .expect("list request");
    let describe_request =
        hartevo_aws_acm_certificate_result_plugin::DescribeCertificateRequest::for_scope(&scope)
            .expect("describe request");
    let list_summary = CertificateSummary::from_input(&input(&scope, list_status, observed_at()))
        .expect("list summary");
    let description =
        CertificateDescription::from_input(&input(&scope, describe_status, observed_at()))
            .expect("description");
    let list_response = ListCertificatesResponse::new(
        &list_request,
        vec![list_summary],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_response =
        hartevo_aws_acm_certificate_result_plugin::DescribeCertificateResponse::new(
            &describe_request,
            description,
            512,
            TransportProvenance::Recording,
        )
        .expect("describe response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    AwsAcmCertificateService::new(
        scope.clone(),
        secret(&scope),
        permission,
        AwsAcmProvider::new(transport).expect("provider"),
    )
    .expect("service")
}

#[test]
fn contract_and_secret_boundary_are_redacted() {
    let document = serde_json::from_str::<serde_json::Value>(
        hartevo_aws_acm_certificate_result_plugin::CONTRACT_JSON,
    )
    .expect("contract JSON");
    assert_eq!(document["layer"], 1);
    assert_eq!(document["provider"]["connectedEvidence"], false);
    assert_eq!(document["provider"]["nativeEvidence"], false);
    assert_eq!(document["provider"]["firstPartyEvidence"], false);
    let (scope, _) = scope();
    let secret = secret(&scope);
    assert_eq!(
        serde_json::to_string(&secret).expect("secret JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{secret:?}").contains("opaque-acm-keyring-ref"));
    let encoded_scope = serde_json::to_string(&scope).expect("scope JSON");
    for raw in [ARN, DOMAIN, ACCOUNT] {
        assert!(
            !encoded_scope.contains(raw),
            "raw scope value leaked: {raw}"
        );
    }
    let cursor = OpaqueNextToken::new("provider-next-token-secret").expect("cursor");
    assert_eq!(
        serde_json::to_string(&cursor).expect("cursor JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{cursor:?}").contains("provider-next-token-secret"));
}

#[test]
fn fixture_loopback_and_blocked_env_are_never_native_or_connected() {
    let (scope, permission) = scope();
    let fixture_provider = AwsAcmProvider::new(
        FixtureTransport::for_scope(&scope, observed_at()).expect("fixture transport"),
    )
    .expect("fixture provider");
    let mut fixture_service = AwsAcmCertificateService::new(
        scope.clone(),
        secret(&scope),
        permission.clone(),
        fixture_provider,
    )
    .expect("fixture service");
    let fixture = fixture_service
        .propose(
            fixture_service
                .default_list_request()
                .expect("list request"),
        )
        .expect("fixture proposal");
    assert_eq!(fixture.state(), CertificateEvidenceState::Complete);
    assert_eq!(fixture.evidence.provenance, TransportProvenance::Fixture);
    assert!(!fixture.connected);
    assert!(!fixture.native);
    assert!(!fixture.first_party);
    assert!(!fixture.evidence.provider_receipt);

    let loopback_provider = AwsAcmProvider::new(
        LoopbackTransport::for_scope(&scope, observed_at()).expect("loopback transport"),
    )
    .expect("loopback provider");
    let mut loopback_service = AwsAcmCertificateService::new(
        scope.clone(),
        secret(&scope),
        permission.clone(),
        loopback_provider,
    )
    .expect("loopback service");
    let loopback = loopback_service
        .propose(
            loopback_service
                .default_search_request()
                .expect("search request"),
        )
        .expect("loopback proposal");
    assert_eq!(loopback.evidence.provenance, TransportProvenance::Loopback);
    assert!(!loopback.connected);
    assert!(!loopback.native);
    assert!(!loopback.first_party);

    let mut blocked_service = AwsAcmCertificateService::new(
        scope.clone(),
        secret(&scope),
        permission,
        AwsAcmProvider::default(),
    )
    .expect("blocked service");
    let blocked = blocked_service
        .propose(
            blocked_service
                .default_list_request()
                .expect("list request"),
        )
        .expect("blocked proposal");
    assert_eq!(blocked.state(), CertificateEvidenceState::ProviderUnknown);
    assert_eq!(blocked.evidence.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        blocked.evidence.failure.as_ref().expect("failure").reason,
        hartevo_aws_acm_certificate_result_plugin::FailureReason::BlockedEnv
    );
    assert!(!blocked.connected);
    assert!(!blocked.native);
    assert!(!blocked.first_party);
}

#[test]
fn complete_projection_contains_only_digests_and_bounded_metadata() {
    let mut service = recording_service(CertificateStatus::Issued, CertificateStatus::Issued);
    let proposal = service
        .propose(service.default_list_request().expect("list request"))
        .expect("proposal");
    assert_eq!(proposal.state(), CertificateEvidenceState::Complete);
    let certificate = proposal.certificate().expect("certificate projection");
    assert_eq!(certificate.status, CertificateStatus::Issued);
    assert_eq!(certificate.issuer, CertificateIssuer::Amazon);
    assert_eq!(certificate.key_algorithm, KeyAlgorithm::Rsa2048);
    assert!(certificate.key_usages.contains(&KeyUsage::ServerAuth));
    assert!(certificate.not_before.is_some());
    assert!(certificate.not_after.is_some());
    assert_eq!(
        certificate.renewal_eligibility,
        hartevo_aws_acm_certificate_result_plugin::RenewalEligibility::Eligible
    );
    assert!(certificate.in_use);
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains(ARN)
    );
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains(DOMAIN)
    );
    assert!(!format!("{proposal:?}").contains(ARN));
    assert!(!format!("{proposal:?}").contains(DOMAIN));
    assert!(!proposal.evidence.request_receipt.raw_request_retained);
    assert!(!proposal.evidence.cost_receipt.raw_cost_payload_retained);
    assert!(proposal.evidence.validate_integrity().is_ok());
    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);
    assert!(!report.verification_digest.as_str().is_empty());
}

#[test]
fn all_certificate_statuses_are_typed_and_failed_states_are_not_certification() {
    for status in [
        CertificateStatus::PendingValidation,
        CertificateStatus::Issued,
        CertificateStatus::Inactive,
        CertificateStatus::Expired,
        CertificateStatus::ValidationTimedOut,
        CertificateStatus::Revoked,
        CertificateStatus::Failed,
    ] {
        let mut service = recording_service(status, status);
        let proposal = service
            .propose(service.default_list_request().expect("list request"))
            .expect("status proposal");
        assert_eq!(proposal.state(), CertificateEvidenceState::Complete);
        assert!(!proposal.certification_claim);
        assert!(!proposal.can_be_adopted());
        assert_eq!(proposal.certificate().expect("certificate").status, status);
    }
}

#[test]
fn stale_list_and_describe_states_fail_closed() {
    let mut service = recording_service(
        CertificateStatus::PendingValidation,
        CertificateStatus::Issued,
    );
    let proposal = service
        .propose(service.default_list_request().expect("list request"))
        .expect("proposal");
    assert_eq!(proposal.state(), CertificateEvidenceState::Partial);
    assert_eq!(
        proposal.evidence.failure.as_ref().expect("failure").reason,
        hartevo_aws_acm_certificate_result_plugin::FailureReason::StaleState
    );
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn transport_statuses_are_explicitly_non_adoptable() {
    let cases = [
        (
            AwsAcmTransportError::BadRequest,
            CertificateEvidenceState::ProviderUnknown,
            400,
        ),
        (
            AwsAcmTransportError::Unauthorized,
            CertificateEvidenceState::AccessLoss,
            401,
        ),
        (
            AwsAcmTransportError::Forbidden,
            CertificateEvidenceState::AccessLoss,
            403,
        ),
        (
            AwsAcmTransportError::NotFound,
            CertificateEvidenceState::NotFound,
            404,
        ),
        (
            AwsAcmTransportError::RateLimited {
                retry_after_seconds: Some(3),
            },
            CertificateEvidenceState::ProviderUnknown,
            429,
        ),
        (
            AwsAcmTransportError::ServerError { status: 500 },
            CertificateEvidenceState::ProviderUnknown,
            500,
        ),
        (
            AwsAcmTransportError::Timeout,
            CertificateEvidenceState::ProviderUnknown,
            0,
        ),
    ];
    for (error, state, status_code) in cases {
        let (scope, permission) = scope();
        let request = ListCertificatesRequest::new(
            &scope,
            ListCertificatesFilter::all(50).expect("filter"),
            None,
        )
        .expect("request");
        let mut transport = RecordingTransport::default();
        transport.push_list_response(Err(error));
        let mut service = AwsAcmCertificateService::new(
            scope.clone(),
            secret(&scope),
            permission,
            AwsAcmProvider::new(transport).expect("provider"),
        )
        .expect("service");
        let proposal = service.propose(request).expect("typed failure proposal");
        assert_eq!(proposal.state(), state);
        assert_eq!(
            proposal
                .evidence
                .failure
                .as_ref()
                .expect("failure")
                .status_code,
            (status_code != 0).then_some(status_code)
        );
        assert!(!proposal.can_be_adopted());
    }
}

#[test]
fn pagination_filter_binding_and_response_tamper_fail_closed() {
    let (scope, permission) = scope();
    let filter = ListCertificatesFilter::all(1).expect("filter");
    let first_request = ListCertificatesRequest::new(&scope, filter.clone(), None).expect("first");
    let token = OpaqueNextToken::for_request(
        "next-token-secret",
        AcmOperation::ListCertificates,
        &scope,
        filter.digest(),
        2,
    )
    .expect("token");
    let summary =
        CertificateSummary::from_input(&input(&scope, CertificateStatus::Issued, observed_at()))
            .expect("summary");
    let first = ListCertificatesResponse::new(
        &first_request,
        vec![summary],
        Some(token),
        512,
        TransportProvenance::Recording,
    )
    .expect("first response");
    let mut tampered = first.clone();
    tampered.connected = true;
    assert!(tampered.validate_for(&first_request).is_err());
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(first));
    let mut service = AwsAcmCertificateService::new(
        scope.clone(),
        secret(&scope),
        permission,
        AwsAcmProvider::new(transport).expect("provider"),
    )
    .expect("service");
    let proposal = service.propose(first_request).expect("partial proposal");
    assert_eq!(proposal.state(), CertificateEvidenceState::Partial);
    assert_eq!(
        proposal.evidence.failure.as_ref().expect("failure").reason,
        hartevo_aws_acm_certificate_result_plugin::FailureReason::PartialResponse
    );
    assert!(!proposal.evidence.list_complete);
}

#[test]
fn registration_is_reversible_revocable_and_recording_is_idempotent() {
    let mut service = recording_service(CertificateStatus::Issued, CertificateStatus::Issued);
    let proposal = service
        .propose(service.default_list_request().expect("list request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(result.state, CertificateEvidenceState::Complete);
    assert!(result.review_only);
    assert!(!result.outcome_adopted);
    let first = consumer.record(&proposal, "record-key-1").expect("record");
    let replay = consumer.record(&proposal, "record-key-1").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());

    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(
        reversed.to,
        hartevo_aws_acm_certificate_result_plugin::RegistrationState::Reversed
    );
    assert!(
        service
            .propose(service.default_list_request().expect("request"))
            .is_ok()
    );
    assert!(service.restore_registration().is_ok());
    assert!(service.revoke_registration().is_ok());
    assert!(!service.is_active());
    let revoked = service
        .propose(service.default_list_request().expect("request"))
        .expect("revoked proposal");
    assert_eq!(
        revoked.state(),
        CertificateEvidenceState::RegistrationRevoked
    );
    assert!(service.revoke_registration().is_err());
}

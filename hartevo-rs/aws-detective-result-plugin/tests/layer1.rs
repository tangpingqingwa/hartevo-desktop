#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Duration, Utc};
use hartevo_aws_detective_result_plugin::{
    AWS_DETECTIVE_API_VERSION, AWS_DETECTIVE_BLOCKED_ENV, AwsDetectiveContract,
    AwsDetectiveProvider, AwsDetectiveReadRequest, AwsDetectiveScope, AwsDetectiveService,
    BehaviorGraphBinding, BehaviorGraphId, BlockedEnvTransport, Digest, EntityType,
    FixtureAwsDetectiveTransport, GetInvestigationResponse, IndicatorBinding, IndicatorId,
    IndicatorPage, IndicatorProjection, IndicatorStatus, IndicatorType, InvestigationBinding,
    InvestigationId, InvestigationPage, InvestigationProjection, InvestigationState,
    InvestigationStatus, MemberBinding, MemberId, MemberPage, MemberProjection, MemberStatus,
    MissionAwsDetectiveConsumer, MissionBinding, MissionId, OpaqueCursor, PermissionFence,
    PermissionId, ProjectBinding, ProjectId, ProviderProvenance, ReadBounds, RegistrationState,
    Revision, SecretReference, ServiceError, Severity, TimeWindow, WorkProductBinding,
    WorkProductId,
};

fn at(hour: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&Utc)
        + Duration::hours(hour)
}

fn scope() -> AwsDetectiveScope {
    let window = TimeWindow::new(at(0), at(24)).expect("24-hour window");
    AwsDetectiveScope::new(
        hartevo_aws_detective_result_plugin::AccountId::new("123456789012").expect("account"),
        hartevo_aws_detective_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        BehaviorGraphBinding::new(
            BehaviorGraphId::new("graph-1").expect("graph"),
            Revision::new(4).expect("graph revision"),
        )
        .expect("graph binding"),
        vec![
            InvestigationBinding::new(
                InvestigationId::new("investigation-1").expect("investigation"),
                Revision::new(7).expect("investigation revision"),
                window.clone(),
            )
            .expect("investigation binding"),
        ],
        vec![
            IndicatorBinding::new(
                IndicatorId::new("indicator-1").expect("indicator"),
                Revision::new(2).expect("indicator revision"),
            )
            .expect("indicator binding"),
        ],
        vec![
            MemberBinding::new(
                MemberId::new("member-1").expect("member"),
                Revision::new(3).expect("member revision"),
            )
            .expect("member binding"),
        ],
        window,
        MissionBinding::new(
            MissionId::new("mission-1").expect("Mission"),
            Revision::new(8).expect("Mission revision"),
        )
        .expect("Mission binding"),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("Project"),
            Revision::new(5).expect("Project revision"),
        )
        .expect("Project binding"),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("Work Product"),
            Revision::new(6).expect("Work Product revision"),
        )
        .expect("Work Product binding"),
        permission().permission_digest,
    )
    .expect("scope")
}

fn permission() -> PermissionFence {
    PermissionFence::readonly(
        PermissionId::new("detective-read").expect("permission"),
        Revision::new(2).expect("permission revision"),
    )
    .expect("permission fence")
}

fn investigation() -> InvestigationProjection {
    let current_scope = scope();
    InvestigationProjection::new(
        BehaviorGraphId::new("graph-1").expect("graph"),
        InvestigationId::new("investigation-1").expect("investigation"),
        Revision::new(7).expect("investigation revision"),
        EntityType::IamRole,
        "arn:aws:iam::123456789012:role/incident-review",
        at(12),
        current_scope.time_window.clone(),
        Severity::High,
        InvestigationState::Active,
        InvestigationStatus::Successful,
    )
    .expect("investigation projection")
}

fn indicator() -> IndicatorProjection {
    IndicatorProjection::new(
        BehaviorGraphId::new("graph-1").expect("graph"),
        InvestigationId::new("investigation-1").expect("investigation"),
        Revision::new(7).expect("investigation revision"),
        IndicatorId::new("indicator-1").expect("indicator"),
        Revision::new(2).expect("indicator revision"),
        IndicatorType::TtpObserved,
        Severity::High,
        IndicatorStatus::Observed,
        Some("credential-access"),
        Some("T1078"),
    )
    .expect("indicator projection")
}

fn member() -> MemberProjection {
    MemberProjection::new(
        BehaviorGraphId::new("graph-1").expect("graph"),
        MemberId::new("member-1").expect("member"),
        Revision::new(3).expect("member revision"),
        hartevo_aws_detective_result_plugin::AccountId::new("123456789012").expect("account"),
        None,
        MemberStatus::Enabled,
        at(12),
    )
    .expect("member projection")
}

#[test]
fn contract_and_layer_one_honesty_are_frozen() {
    let contract = AwsDetectiveContract::baseline().expect("contract");
    assert_eq!(contract.value()["layer"], 1);
    assert_eq!(AWS_DETECTIVE_API_VERSION, "2018-10-26");
    assert_eq!(AWS_DETECTIVE_BLOCKED_ENV, "BLOCKED_ENV");
    assert!(!ProviderProvenance::Fixture.connected());
    assert!(!ProviderProvenance::Fixture.native());
    assert!(!ProviderProvenance::Fixture.first_party());
}

#[test]
fn secret_and_cursor_are_opaque_and_redacted() {
    let current_scope = scope();
    let secret =
        SecretReference::for_detective("sigv4-keyring-ref", &current_scope).expect("secret");
    assert!(serde_json::to_string(&secret).is_err());
    assert!(!format!("{secret:?}").contains("sigv4-keyring-ref"));

    let cursor = OpaqueCursor::new_at("raw-provider-next-token", at(12)).expect("cursor");
    assert_eq!(
        serde_json::to_string(&cursor).expect("opaque cursor"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{cursor:?}").contains("raw-provider-next-token"));

    let request =
        AwsDetectiveReadRequest::list_investigations(&current_scope, 50, 4, None).expect("request");
    assert!(
        !serde_json::to_string(&request)
            .expect("request JSON")
            .contains("raw-provider-next-token")
    );
}

#[test]
fn list_investigations_proposes_records_verifies_and_consumes_as_review_only() {
    let current_scope = scope();
    let secret =
        SecretReference::for_detective("sigv4-keyring-ref", &current_scope).expect("secret");
    let mut transport = FixtureAwsDetectiveTransport::default();
    let page = InvestigationPage::new(1, vec![investigation()], None, 512).expect("page");
    transport.push_investigations(Ok(page));
    let provider = AwsDetectiveProvider::new(transport).expect("provider");
    let mut service =
        AwsDetectiveService::new(current_scope.clone(), secret, permission(), provider)
            .expect("service");
    let request =
        AwsDetectiveReadRequest::list_investigations(&current_scope, 50, 4, None).expect("request");
    let proposal = service.propose_at(request, at(12)).expect("proposal");
    proposal.validate().expect("proposal digest");
    assert!(proposal.read_only);
    assert!(!proposal.live_execution);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.adopted_outcome);
    assert!(!proposal.adopted_work_product);
    assert!(!proposal.evidence.is_connected());
    assert!(!proposal.evidence.is_native());
    proposal.evidence.verify().expect("evidence digest");

    let receipt = service.record_at(&proposal, at(13)).expect("record");
    let verified = service.verify(&receipt).expect("verify");
    assert!(verified.verified);
    assert!(!verified.connected);
    assert!(!verified.native);
    assert!(!verified.adopted_outcome);
    assert!(!verified.adopted_work_product);

    let consumer = MissionAwsDetectiveConsumer::new(current_scope, service.registration().clone())
        .expect("Mission consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.adopted_outcome);
    assert!(!result.adopted_work_product);
    assert!(!result.truth_authority);
}

#[test]
fn all_four_reads_are_bounded_and_redacted() {
    let current_scope = scope();
    let secret =
        SecretReference::for_detective("sigv4-keyring-ref", &current_scope).expect("secret");
    let mut transport = FixtureAwsDetectiveTransport::default();
    transport.push_investigations(Ok(InvestigationPage::new(
        1,
        vec![investigation()],
        None,
        100,
    )
    .expect("investigations")));
    transport.push_get_investigation(Ok(GetInvestigationResponse::new(
        Some(investigation()),
        100,
    )
    .expect("investigation")));
    transport.push_indicators(Ok(
        IndicatorPage::new(1, vec![indicator()], None, 100).expect("indicators")
    ));
    transport.push_members(Ok(
        MemberPage::new(1, vec![member()], None, 100).expect("members")
    ));
    let provider = AwsDetectiveProvider::new(transport).expect("provider");
    let mut service =
        AwsDetectiveService::new(current_scope.clone(), secret, permission(), provider)
            .expect("service");

    let list = AwsDetectiveReadRequest::list_investigations(&current_scope, 50, 4, None)
        .expect("list investigations");
    let result = service
        .read_at(list, at(12))
        .expect("list investigations read");
    result.evidence.verify().expect("investigation evidence");

    let get = AwsDetectiveReadRequest::get_investigation(
        &current_scope,
        InvestigationId::new("investigation-1").expect("investigation"),
    )
    .expect("get investigation");
    let result = service
        .read_at(get, at(12))
        .expect("get investigation read");
    result.evidence.verify().expect("get evidence");

    let indicators = AwsDetectiveReadRequest::list_indicators(
        &current_scope,
        InvestigationId::new("investigation-1").expect("investigation"),
        50,
        4,
        None,
    )
    .expect("list indicators");
    let result = service.read_at(indicators, at(12)).expect("indicator read");
    result.evidence.verify().expect("indicator evidence");

    let members =
        AwsDetectiveReadRequest::list_members(&current_scope, 50, 4, None).expect("list members");
    let result = service.read_at(members, at(12)).expect("member read");
    result.evidence.verify().expect("member evidence");

    let serialized = serde_json::to_string(&result.evidence).expect("evidence JSON");
    assert!(!serialized.contains("entity-arn"));
    assert!(!serialized.contains("email"));
    assert!(!serialized.contains("raw-graph"));
    assert!(!serialized.contains("credential-access"));
}

#[test]
fn expired_and_replayed_cursors_fail_closed() {
    let current_scope = scope();
    let secret =
        SecretReference::for_detective("sigv4-keyring-ref", &current_scope).expect("secret");
    let expired =
        OpaqueCursor::new_at("expired-token", at(0) - Duration::hours(25)).expect("expired cursor");
    let mut transport = FixtureAwsDetectiveTransport::default();
    transport.push_investigations(Ok(InvestigationPage::new(
        1,
        Vec::new(),
        Some(expired),
        100,
    )
    .expect("expired page")));
    let provider = AwsDetectiveProvider::new(transport).expect("provider");
    let mut service =
        AwsDetectiveService::new(current_scope.clone(), secret, permission(), provider)
            .expect("service");
    let request =
        AwsDetectiveReadRequest::list_investigations(&current_scope, 50, 4, None).expect("request");
    assert_eq!(
        service.read_at(request, at(0)),
        Err(ServiceError::CursorExpired)
    );

    let secret =
        SecretReference::for_detective("sigv4-keyring-ref", &current_scope).expect("secret");
    let replay = OpaqueCursor::new_at("replayed-token", at(12)).expect("replay cursor");
    let mut transport = FixtureAwsDetectiveTransport::default();
    transport.push_investigations(Ok(InvestigationPage::new(
        1,
        Vec::new(),
        Some(replay.clone()),
        100,
    )
    .expect("first page")));
    transport.push_investigations(Ok(
        InvestigationPage::new(2, Vec::new(), Some(replay), 100).expect("second page")
    ));
    let provider = AwsDetectiveProvider::new(transport).expect("provider");
    let mut service =
        AwsDetectiveService::new(current_scope.clone(), secret, permission(), provider)
            .expect("service");
    let request =
        AwsDetectiveReadRequest::list_investigations(&current_scope, 50, 4, None).expect("request");
    assert_eq!(
        service.read_at(request, at(12)),
        Err(ServiceError::CursorReplay)
    );
}

#[test]
fn tamper_and_registration_revocation_are_fences() {
    let current_scope = scope();
    let secret =
        SecretReference::for_detective("sigv4-keyring-ref", &current_scope).expect("secret");
    let mut transport = FixtureAwsDetectiveTransport::default();
    transport.push_investigations(Ok(InvestigationPage::new(
        1,
        vec![investigation()],
        None,
        100,
    )
    .expect("page")));
    let provider = AwsDetectiveProvider::new(transport).expect("provider");
    let mut service =
        AwsDetectiveService::new(current_scope.clone(), secret, permission(), provider)
            .expect("service");
    let request =
        AwsDetectiveReadRequest::list_investigations(&current_scope, 50, 4, None).expect("request");
    let result = service.read_at(request, at(12)).expect("read");
    let mut tampered = result.evidence.clone();
    tampered.digests.evidence_digest = Digest::from_text("tampered");
    assert_eq!(tampered.verify(), Err(ServiceError::TamperedEvidence));

    let revocation = service.revoke_registration().expect("revocation");
    assert_eq!(service.registration().state, RegistrationState::Revoked);
    assert_eq!(revocation.revision.get(), 2);
    let request =
        AwsDetectiveReadRequest::list_members(&current_scope, 50, 4, None).expect("request");
    assert_eq!(
        service.read_at(request, at(12)),
        Err(ServiceError::RegistrationRevoked)
    );
}

#[test]
fn blocked_env_and_http_failures_never_become_connected_evidence() {
    let current_scope = scope();
    let secret =
        SecretReference::for_detective("sigv4-keyring-ref", &current_scope).expect("secret");
    let provider = AwsDetectiveProvider::<BlockedEnvTransport>::default();
    assert_eq!(provider.provenance(), ProviderProvenance::BlockedEnv);
    assert!(!provider.provenance().connected());
    assert!(!provider.provenance().native());
    assert!(!provider.provenance().first_party());
    let mut service =
        AwsDetectiveService::new(current_scope.clone(), secret, permission(), provider)
            .expect("service");
    let request =
        AwsDetectiveReadRequest::list_members(&current_scope, 50, 4, None).expect("request");
    assert_eq!(
        service.read_at(request, at(12)),
        Err(ServiceError::BlockedEnvironment)
    );

    let failures = [
        hartevo_aws_detective_result_plugin::TransportError::InvalidRequest,
        hartevo_aws_detective_result_plugin::TransportError::Unauthorized,
        hartevo_aws_detective_result_plugin::TransportError::Forbidden,
        hartevo_aws_detective_result_plugin::TransportError::NotFound,
        hartevo_aws_detective_result_plugin::TransportError::RateLimited {
            retry_after_seconds: Some(2),
        },
        hartevo_aws_detective_result_plugin::TransportError::ServerFailure {
            status_code: Some(500),
        },
        hartevo_aws_detective_result_plugin::TransportError::Timeout,
    ];
    for failure in failures {
        let secret =
            SecretReference::for_detective("sigv4-keyring-ref", &current_scope).expect("secret");
        let mut transport = FixtureAwsDetectiveTransport::default();
        transport.push_members(Err(failure));
        let provider = AwsDetectiveProvider::new(transport).expect("provider");
        let mut service =
            AwsDetectiveService::new(current_scope.clone(), secret, permission(), provider)
                .expect("service");
        let request =
            AwsDetectiveReadRequest::list_members(&current_scope, 50, 4, None).expect("request");
        assert!(service.read_at(request, at(12)).is_err());
    }
}

#[test]
fn scope_and_bounds_reject_invalid_values() {
    assert!(TimeWindow::new(at(0), at(25)).is_err());
    assert!(ReadBounds::new(101, 4).is_err());
    assert!(ReadBounds::new(50, 5).is_err());
}

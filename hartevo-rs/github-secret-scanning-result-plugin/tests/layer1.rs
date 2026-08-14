use chrono::{DateTime, TimeZone, Utc};
use hartevo_github_secret_scanning_result_plugin::{
    AlertNumber, AlertState, AlertTarget, BlockedEnvTransport, CommitSha, Digest, GithubAuthKind,
    GithubSecretScanningAlert, GithubSecretScanningAlertResponse, GithubSecretScanningPage,
    GithubSecretScanningProvider, GithubSecretScanningRequest, GithubSecretScanningResponse,
    GithubSecretScanningScope, InstallationId, LocationKind, MissionGithubSecretScanningConsumer,
    MissionGithubSecretScanningDecisionState, MissionId, MissionScopeBinding, OpaqueCursor,
    PermissionSnapshot, ProjectId, PushProtectionMetadata, RecordingTransport, RedactedLocation,
    RefName, RepositoryIdentity, SecretReference, SecretScanningAlertInput,
    SecretScanningOperation, SecretScanningQuery, SecretType, SecretTypeClass, ServiceError,
    TransportProvenance, ValidityClass, WorkProductId, contract_bounds_tripwire, contract_digest,
    native_probe_from_environment,
};

const NOW_SECONDS: i64 = 1_800_000_000;
const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn at() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture time")
}

fn scope() -> GithubSecretScanningScope {
    GithubSecretScanningScope::new(
        InstallationId::new("installation-1").expect("installation"),
        hartevo_github_secret_scanning_result_plugin::OrganizationName::new("acme")
            .expect("organization"),
        RepositoryIdentity::from_parts("acme", "payments").expect("repository"),
        RefName::new("refs/heads/main").expect("ref"),
        CommitSha::new(COMMIT).expect("commit"),
        AlertNumber::new(7).expect("alert number"),
        AlertState::Open,
        ValidityClass::Active,
        PermissionSnapshot::least_privilege(),
        SecretScanningQuery::all(),
        MissionScopeBinding::new(
            ProjectId::new("project-1").expect("project"),
            hartevo_github_secret_scanning_result_plugin::Revision::new(1).expect("revision"),
            MissionId::new("mission-1").expect("mission"),
            hartevo_github_secret_scanning_result_plugin::Revision::new(2).expect("revision"),
            WorkProductId::new("work-product-1").expect("work product"),
            hartevo_github_secret_scanning_result_plugin::Revision::new(3).expect("revision"),
        )
        .expect("mission binding"),
    )
    .expect("scope")
}

fn location(scope: &GithubSecretScanningScope) -> RedactedLocation {
    RedactedLocation::from_digests(
        LocationKind::Commit,
        Digest::from_text("path-digest-input"),
        Digest::from_text("region-digest-input"),
        Some(3),
        Some(3),
        scope.commit_digest(),
        scope.ref_digest(),
    )
    .expect("redacted location")
}

fn alert(scope: &GithubSecretScanningScope, state: AlertState) -> GithubSecretScanningAlert {
    let resolved_at = match state {
        AlertState::Open => None,
        AlertState::Resolved => Some(at()),
    };
    GithubSecretScanningAlert::new(SecretScanningAlertInput {
        number: scope.alert_number,
        state,
        opened_at: at(),
        resolved_at,
        secret_type: SecretType::from_provider_text(
            "provider-pattern-id",
            SecretTypeClass::DefaultPattern,
        )
        .expect("secret type digest"),
        validity: ValidityClass::Active,
        installation_digest: scope.installation_digest(),
        organization_digest: scope.organization_digest(),
        repository_digest: scope.repository_digest(),
        ref_digest: scope.ref_digest(),
        commit_digest: scope.commit_digest(),
        locations: vec![location(scope)],
        has_more_locations: false,
        push_protection: PushProtectionMetadata::new(false, None, false, false, false, false)
            .expect("push protection metadata"),
    })
    .expect("alert")
}

fn page(
    scope: &GithubSecretScanningScope,
    target: AlertTarget,
    operation: SecretScanningOperation,
    page_number: u16,
    next_cursor: Option<OpaqueCursor>,
    items: Vec<GithubSecretScanningAlert>,
) -> GithubSecretScanningPage {
    page_with_request_cursor(
        scope,
        target,
        operation,
        page_number,
        next_cursor.clone(),
        next_cursor,
        items,
    )
}

fn page_with_request_cursor(
    scope: &GithubSecretScanningScope,
    target: AlertTarget,
    operation: SecretScanningOperation,
    page_number: u16,
    request_cursor: Option<OpaqueCursor>,
    next_cursor: Option<OpaqueCursor>,
    items: Vec<GithubSecretScanningAlert>,
) -> GithubSecretScanningPage {
    let request = match target {
        AlertTarget::Repository => {
            GithubSecretScanningRequest::list_repository(scope, page_number, request_cursor)
        }
        AlertTarget::Organization => {
            GithubSecretScanningRequest::list_organization(scope, page_number, request_cursor)
        }
    }
    .expect("list request");
    GithubSecretScanningPage::new(
        operation,
        target,
        page_number,
        items,
        next_cursor,
        request.query_digest,
        hartevo_github_secret_scanning_result_plugin::RedactedRateReceipt::empty(),
    )
    .expect("page")
}

fn detail(
    scope: &GithubSecretScanningScope,
    alert: GithubSecretScanningAlert,
) -> GithubSecretScanningAlertResponse {
    let request = GithubSecretScanningRequest::get_repository(scope, scope.alert_number)
        .expect("get request");
    GithubSecretScanningAlertResponse::new(
        SecretScanningOperation::GetRepositoryAlert,
        AlertTarget::Repository,
        alert,
        request.query_digest,
        hartevo_github_secret_scanning_result_plugin::RedactedRateReceipt::empty(),
    )
    .expect("detail response")
}

fn repository_service(
    responses: impl IntoIterator<
        Item = Result<
            GithubSecretScanningResponse,
            hartevo_github_secret_scanning_result_plugin::ProviderError,
        >,
    >,
) -> hartevo_github_secret_scanning_result_plugin::GithubSecretScanningService<RecordingTransport> {
    let scope = scope();
    let secret = SecretReference::new("opaque-reference", &scope, 1, GithubAuthKind::App)
        .expect("opaque secret reference");
    let provider = GithubSecretScanningProvider::new(RecordingTransport::fixture(responses))
        .expect("provider");
    hartevo_github_secret_scanning_result_plugin::GithubSecretScanningService::new(
        scope, secret, provider,
    )
    .expect("service")
}

#[test]
fn contract_registration_and_provenance_are_layer_one_only() {
    assert!(contract_bounds_tripwire());
    assert_eq!(contract_digest().as_str().len(), 64);
    let probe = native_probe_from_environment();
    assert_eq!(
        probe.status,
        hartevo_github_secret_scanning_result_plugin::NativeProbeStatus::BlockedEnv
    );
    assert!(!probe.connected && !probe.native && !probe.first_party);

    let scope = scope();
    let secret = SecretReference::new("opaque-reference", &scope, 9, GithubAuthKind::OAuth)
        .expect("opaque secret reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-reference"));
    assert!(secret.is_opaque());
    assert!(!secret.is_revoked());
    assert!(!TransportProvenance::Fixture.connected());
    assert!(!TransportProvenance::Recording.native());
    assert!(!TransportProvenance::Loopback.first_party());
    assert_eq!(TransportProvenance::BlockedEnv.as_str(), "BLOCKED_ENV");
}

#[test]
fn repository_read_projects_safe_metadata_and_binds_hide_secret() {
    let scope = scope();
    let safe_alert = alert(&scope, AlertState::Open);
    let list = page(
        &scope,
        AlertTarget::Repository,
        SecretScanningOperation::ListRepositoryAlerts,
        1,
        None,
        vec![safe_alert.clone()],
    );
    let get = detail(&scope, safe_alert);
    let mut service = repository_service([
        Ok(GithubSecretScanningResponse::Page(list)),
        Ok(GithubSecretScanningResponse::Alert(get)),
    ]);

    let evidence = service
        .read_repository_evidence()
        .expect("repository evidence");
    assert_eq!(evidence.alert.number, AlertNumber::new(7).unwrap());
    assert_eq!(evidence.alert.state, AlertState::Open);
    assert_eq!(evidence.alert.validity, ValidityClass::Active);
    assert!(
        evidence
            .alert
            .secret_type
            .secret_type_digest
            .validate()
            .is_ok()
    );
    assert_eq!(evidence.alert.locations.len(), 1);
    assert!(evidence.alert.locations[0].path_digest.validate().is_ok());
    assert!(evidence.alert.locations[0].region_digest.validate().is_ok());
    assert!(!evidence.connected && !evidence.native && !evidence.first_party);
    assert!(
        evidence
            .response_receipts
            .iter()
            .all(|receipt| receipt.method == "GET")
    );

    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].path_and_query().contains("hide_secret=true"));
    assert!(requests[1].path_and_query().contains("hide_secret=true"));
    assert!(!requests[0].path_and_query().contains("opaque-reference"));
}

#[test]
fn organization_read_produces_a_bounded_single_alert_projection() {
    let scope = scope();
    let safe_alert = alert(&scope, AlertState::Open);
    let list = page(
        &scope,
        AlertTarget::Organization,
        SecretScanningOperation::ListOrganizationAlerts,
        1,
        None,
        vec![safe_alert],
    );
    let mut service = repository_service([Ok(GithubSecretScanningResponse::Page(list))]);
    let evidence = service
        .read_organization_alert()
        .expect("organization bounded single alert");
    assert_eq!(evidence.alert.repository_digest, scope.repository_digest());
    let request = &service.provider().transport().requests()[0];
    assert!(
        request
            .path_and_query()
            .starts_with("/orgs/acme/secret-scanning/alerts")
    );
    assert!(request.path_and_query().contains("hide_secret=true"));
    assert!(request.path_and_query().contains("per_page=50"));
    assert!(request.path_and_query().contains("page=1"));
}

#[test]
fn proposal_record_and_mission_consumer_remain_below_kernel_authority() {
    let scope = scope();
    let safe_alert = alert(&scope, AlertState::Open);
    let list = page(
        &scope,
        AlertTarget::Repository,
        SecretScanningOperation::ListRepositoryAlerts,
        1,
        None,
        vec![safe_alert.clone()],
    );
    let get = detail(&scope, safe_alert);
    let mut service = repository_service([
        Ok(GithubSecretScanningResponse::Page(list)),
        Ok(GithubSecretScanningResponse::Alert(get)),
    ]);
    let proposal = service.propose("mission-read-1").expect("proposal");
    assert!(proposal.read_only && proposal.proposal_only);
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!proposal.adopts_kernel_outcome);

    let consumer = MissionGithubSecretScanningConsumer::new(scope.clone(), service.registration())
        .expect("consumer");
    let decision = consumer.consume(&proposal).expect("decision proposal");
    assert_eq!(
        decision.state,
        MissionGithubSecretScanningDecisionState::UnresolvedAlert
    );
    assert!(decision.unresolved);
    assert!(!decision.adopted);
    assert!(!decision.creates_effect);
    assert!(!decision.mutates_consent);
    assert!(!decision.truth_authority);
    assert!(!decision.receipt_authority);
    assert!(!decision.verification_authority);
    assert!(!decision.outcome_authority);
    assert!(!decision.security_certification_authority);

    let recording = service.record(&proposal).expect("local recording");
    assert!(recording.recorded);
    assert!(!recording.durable_provider_receipt && !recording.provider_mutated);
    let verified = service
        .verify_recording(&proposal, &recording)
        .expect("local integrity");
    assert!(verified.integrity_valid);
    assert!(!verified.provider_readback_performed);
    assert!(!verified.security_certification_authority);
}

#[test]
fn registration_is_reversible_then_revocable() {
    let scope = scope();
    let safe_alert = alert(&scope, AlertState::Open);
    let list = page(
        &scope,
        AlertTarget::Repository,
        SecretScanningOperation::ListRepositoryAlerts,
        1,
        None,
        vec![safe_alert.clone()],
    );
    let get = detail(&scope, safe_alert);
    let mut service = repository_service([
        Ok(GithubSecretScanningResponse::Page(list)),
        Ok(GithubSecretScanningResponse::Alert(get)),
    ]);
    service.reverse_registration().expect("reverse");
    assert!(!service.is_active());
    assert!(matches!(
        service.read_evidence(),
        Err(ServiceError::RegistrationInactive)
    ));
    service.restore_registration().expect("restore");
    assert!(service.is_active());
    service.revoke_registration().expect("revoke");
    assert!(!service.is_active());
    assert!(matches!(
        service.read_evidence(),
        Err(ServiceError::SecretRevoked)
    ));
}

#[test]
fn status_errors_fail_closed_without_a_partial_projection() {
    let kinds = [
        (
            hartevo_github_secret_scanning_result_plugin::ProviderErrorKind::Unauthorized,
            ServiceError::AccessLoss,
        ),
        (
            hartevo_github_secret_scanning_result_plugin::ProviderErrorKind::Forbidden,
            ServiceError::AccessLoss,
        ),
        (
            hartevo_github_secret_scanning_result_plugin::ProviderErrorKind::NotFound,
            ServiceError::AccessLoss,
        ),
        (
            hartevo_github_secret_scanning_result_plugin::ProviderErrorKind::Conflict,
            ServiceError::ProviderRejected,
        ),
        (
            hartevo_github_secret_scanning_result_plugin::ProviderErrorKind::Unprocessable,
            ServiceError::ProviderRejected,
        ),
        (
            hartevo_github_secret_scanning_result_plugin::ProviderErrorKind::RateLimited,
            ServiceError::ProviderRejected,
        ),
        (
            hartevo_github_secret_scanning_result_plugin::ProviderErrorKind::ServiceUnavailable,
            ServiceError::ProviderRejected,
        ),
        (
            hartevo_github_secret_scanning_result_plugin::ProviderErrorKind::Timeout,
            ServiceError::ProviderRejected,
        ),
    ];
    for (kind, expected) in kinds {
        let mut service = repository_service([Err(
            hartevo_github_secret_scanning_result_plugin::ProviderError::new(kind, "safe-code"),
        )]);
        assert!(
            matches!(service.read_evidence(), Err(error) if std::mem::discriminant(&error) == std::mem::discriminant(&expected))
        );
    }
}

#[test]
fn cursor_loops_stale_state_and_tamper_fail_closed() {
    let scope = scope();
    let cursor = OpaqueCursor::new("opaque-page-cursor").expect("cursor");
    let first = page_with_request_cursor(
        &scope,
        AlertTarget::Repository,
        SecretScanningOperation::ListRepositoryAlerts,
        1,
        None,
        Some(cursor.clone()),
        Vec::new(),
    );
    let second = page_with_request_cursor(
        &scope,
        AlertTarget::Repository,
        SecretScanningOperation::ListRepositoryAlerts,
        2,
        Some(cursor.clone()),
        Some(cursor.clone()),
        Vec::new(),
    );
    let mut service = repository_service([
        Ok(GithubSecretScanningResponse::Page(first)),
        Ok(GithubSecretScanningResponse::Page(second)),
    ]);
    assert!(matches!(
        service.read_evidence(),
        Err(ServiceError::CursorLoop)
    ));

    let stale = alert(&scope, AlertState::Resolved);
    let stale_page = page(
        &scope,
        AlertTarget::Repository,
        SecretScanningOperation::ListRepositoryAlerts,
        1,
        None,
        vec![stale],
    );
    let mut stale_service =
        repository_service([Ok(GithubSecretScanningResponse::Page(stale_page))]);
    assert!(matches!(
        stale_service.read_evidence(),
        Err(ServiceError::StaleAlertState)
    ));

    let good = alert(&scope, AlertState::Open);
    let mut tampered_page = page(
        &scope,
        AlertTarget::Repository,
        SecretScanningOperation::ListRepositoryAlerts,
        1,
        None,
        vec![good],
    );
    tampered_page.response_digest = Digest::from_text("tampered-response");
    let mut tampered_service =
        repository_service([Ok(GithubSecretScanningResponse::Page(tampered_page))]);
    assert!(matches!(
        tampered_service.read_evidence(),
        Err(ServiceError::TamperedEvidence)
    ));
}

#[test]
fn blocked_environment_is_never_native_or_connected() {
    let provider = GithubSecretScanningProvider::new(BlockedEnvTransport).expect("provider");
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
    assert!(!provider.provenance().connected());
    assert!(!provider.provenance().native());
    assert!(!provider.provenance().first_party());
}

#[test]
fn request_paths_are_get_only_and_secret_hidden() {
    let scope = scope();
    let list = GithubSecretScanningRequest::list_repository(&scope, 1, None).expect("list");
    assert_eq!(list.method(), "GET");
    assert!(
        list.path_and_query()
            .contains("/repos/acme/payments/secret-scanning/alerts")
    );
    assert!(list.path_and_query().contains("hide_secret=true"));
    let get = GithubSecretScanningRequest::get_repository(&scope, scope.alert_number).expect("get");
    assert_eq!(get.method(), "GET");
    assert!(get.path_and_query().ends_with("/7?hide_secret=true"));
}

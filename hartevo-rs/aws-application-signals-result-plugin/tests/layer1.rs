use chrono::{DateTime, TimeZone, Utc};
use hartevo_aws_application_signals_result_plugin as plugin;
use plugin::{
    AWS_APPLICATION_SIGNALS_API_VERSION, AWS_APPLICATION_SIGNALS_CONTRACT_VERSION,
    AWS_APPLICATION_SIGNALS_PLUGIN_VERSION_TEXT, AWS_APPLICATION_SIGNALS_PROVIDER_REVISION,
    AccountId, AwsApplicationSignalsProvider, AwsApplicationSignalsReadRequest,
    AwsApplicationSignalsScope, AwsApplicationSignalsService, DeploymentBinding, Digest,
    ErrorBudgetSummary, EvidenceStatus, FixtureAwsApplicationSignalsTransport,
    GetServiceLevelObjectiveRequest, GetServiceRequest, ListServiceLevelObjectivesRequest,
    ListServicesPage, ListServicesRequest, MissionAwsApplicationSignalsConsumer, MissionBinding,
    ModelError, OpaquePageToken, OperationName, PermissionScope, ProviderError, ProviderProvenance,
    ReadBounds, ReadOperation, RecordingAwsApplicationSignalsTransport, Region, ReleaseBinding,
    ServiceDetail, ServiceError, ServiceName, ServiceSummary, SigV4SecretReference, SloDetail,
    SloId, SloStatus, SloStatusSummary, SloSummary, SloTransition, TimeWindow, TransportError,
    TransportFailure,
};

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

fn account() -> AccountId {
    AccountId::new("123456789012").expect("account")
}

fn region() -> Region {
    Region::new("us-east-1").expect("region")
}

fn window() -> TimeWindow {
    TimeWindow::closed(at("2026-08-14T00:00:00Z"), at("2026-08-14T00:15:00Z")).expect("window")
}

fn scope_with(
    account_id: AccountId,
    region_value: Region,
    service_name: Option<&str>,
    slo_id: Option<&str>,
    operation_name: Option<&str>,
) -> AwsApplicationSignalsScope {
    let permissions = PermissionScope::all(
        account_id.clone(),
        region_value.clone(),
        plugin::RevisionId::new("permission-revision-1").expect("permission revision"),
    )
    .expect("permissions");
    let mission = MissionBinding::new(
        plugin::MissionId::new("mission-554").expect("mission"),
        plugin::ProjectId::new("project-554").expect("project"),
        plugin::RevisionId::new("mission-revision-1").expect("mission revision"),
        Digest::from_text("consent-554"),
    );
    AwsApplicationSignalsScope::new(
        account_id,
        region_value,
        service_name.map(|value| ServiceName::new(value).expect("service")),
        slo_id.map(|value| SloId::new(value).expect("SLO")),
        operation_name.map(|value| OperationName::new(value).expect("operation")),
        window(),
        DeploymentBinding::new("deployment-554", 3).expect("deployment"),
        ReleaseBinding::new("release-554", 7).expect("release"),
        mission,
        permissions,
    )
    .expect("scope")
}

fn scope() -> AwsApplicationSignalsScope {
    scope_with(
        account(),
        region(),
        Some("checkout"),
        Some("availability"),
        Some("GET /checkout"),
    )
}

fn service_for(
    scope: &AwsApplicationSignalsScope,
    transport: RecordingAwsApplicationSignalsTransport,
) -> AwsApplicationSignalsService<RecordingAwsApplicationSignalsTransport> {
    let secret =
        SigV4SecretReference::new("opaque-host-secret/aws/application-signals/554", scope, 11)
            .expect("secret");
    AwsApplicationSignalsService::new(
        scope.clone(),
        secret,
        AwsApplicationSignalsProvider::new(transport).expect("provider"),
    )
    .expect("service")
}

fn service_summary(scope: &AwsApplicationSignalsScope) -> ServiceSummary {
    ServiceSummary::new(
        scope.account_id.clone(),
        scope.region.clone(),
        scope.service_name.clone().expect("service-scoped fixture"),
        Some("prod".to_owned()),
    )
    .expect("service summary")
}

fn service_detail(scope: &AwsApplicationSignalsScope) -> ServiceDetail {
    ServiceDetail::new(
        service_summary(scope),
        vec![OperationName::new("GET /checkout").expect("operation")],
    )
    .expect("service detail")
}

fn slo_summary(scope: &AwsApplicationSignalsScope, status: SloStatus) -> SloSummary {
    SloSummary::new(
        scope.account_id.clone(),
        scope.region.clone(),
        scope.service_name.clone().expect("service"),
        scope.slo_id.clone().expect("SLO"),
        scope.operation_name.clone().expect("operation"),
        99.9,
        status,
    )
    .expect("SLO summary")
}

fn slo_detail(scope: &AwsApplicationSignalsScope, status: SloStatus) -> SloDetail {
    let observed_at = scope.time_window.end;
    let previous = (status != SloStatus::Healthy).then_some(SloStatus::Healthy);
    let transition = previous.map(|from| SloTransition {
        from: Some(from),
        to: status,
        observed_at,
    });
    SloDetail::new(
        slo_summary(scope, status),
        scope.time_window.clone(),
        SloStatusSummary::new(status, previous, transition, observed_at).expect("status"),
        ErrorBudgetSummary::new(99.9, Some(99.8), Some(0.1), Some(99.9), Some(60)).expect("budget"),
    )
    .expect("SLO detail")
}

fn list_services_request(scope: &AwsApplicationSignalsScope) -> ListServicesRequest {
    ListServicesRequest::new(scope, ReadBounds::default()).expect("list request")
}

#[test]
fn contract_and_runtime_definition_are_layer1_read_only() {
    plugin::validate_contract_document().expect("contract validates");
    let document: serde_json::Value =
        serde_json::from_str(plugin::AWS_APPLICATION_SIGNALS_CONTRACT_JSON).expect("contract");
    assert_eq!(
        document["schemaVersion"],
        plugin::AWS_APPLICATION_SIGNALS_SCHEMA_VERSION
    );
    assert_eq!(
        document["contractVersion"],
        AWS_APPLICATION_SIGNALS_CONTRACT_VERSION
    );
    assert_eq!(document["layer"], 1);
    assert_eq!(
        document["service"]["apiVersion"],
        AWS_APPLICATION_SIGNALS_API_VERSION
    );
    assert_eq!(
        document["provider"]["providerRevision"],
        AWS_APPLICATION_SIGNALS_PROVIDER_REVISION
    );
    assert_eq!(document["authority"]["connected"], false);
    assert_eq!(document["authority"]["nativeProvider"], false);
    assert_eq!(document["authority"]["sloWrites"], false);
    assert_eq!(document["authority"]["metricWrites"], false);
    assert_eq!(document["authority"]["causalClaims"], false);
    assert_eq!(document["authority"]["outcomeAuthority"], false);
    assert_eq!(
        plugin::plugin_version().to_string(),
        AWS_APPLICATION_SIGNALS_PLUGIN_VERSION_TEXT
    );
    assert!(!plugin::Layer1Authority::connected());
    assert!(!plugin::Layer1Authority::native_provider());
    assert!(!plugin::Layer1Authority::live_credential_resolution());
}

#[test]
fn sigv4_reference_is_opaque_and_only_digest_handles_are_serializable() {
    let scope = scope();
    let secret = SigV4SecretReference::new("raw-secret-material-that-must-not-leak", &scope, 9)
        .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("raw-secret-material-that-must-not-leak"));
    assert!(debug.contains(scope.digest().as_str()));
    assert_eq!(secret.scope_digest(), scope.digest());
    assert_eq!(secret.credential_revision(), 9);
    let cursor = OpaquePageToken::new("raw-provider-next-token").expect("cursor");
    let serialized_cursor = serde_json::to_string(&cursor).expect("cursor digest serializes");
    assert!(!serialized_cursor.contains("raw-provider-next-token"));
    assert_eq!(
        serde_json::from_str::<plugin::OpaquePageToken>(&serialized_cursor)
            .unwrap()
            .digest(),
        cursor.digest()
    );
}

#[test]
fn bounded_service_list_and_get_reads_produce_redacted_receipts() {
    let scope = scope();
    let request = list_services_request(&scope);
    let page = ListServicesPage::new(&request, vec![service_summary(&scope)], None).expect("page");
    let mut service = service_for(&scope, FixtureAwsApplicationSignalsTransport::fixture());
    service
        .provider_mut()
        .transport_mut()
        .queue_list_services(Ok(page));
    let result = service
        .read(AwsApplicationSignalsReadRequest::ListServices(request))
        .expect("list services");

    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.services.len(), 1);
    assert!(result.evidence.pagination.complete);
    assert!(result.evidence.redactions.validate().is_ok());
    assert!(!result.receipt.native);
    assert!(!result.receipt.connected);
    assert!(!result.receipt.durable_request_receipt);
    assert!(!result.receipt.durable_cost_receipt);
    result.receipt.verify().expect("receipt");
    let encoded = serde_json::to_string(&result).expect("result serializes");
    assert!(!encoded.contains("raw-secret-material"));
    assert!(!encoded.contains("raw-provider-next-token"));

    let request = GetServiceRequest::new(&scope).expect("get request");
    let response =
        plugin::GetServiceResponse::new(&request, service_detail(&scope), EvidenceStatus::Complete)
            .expect("response");
    let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .queue_get_service(Ok(response));
    let result = service
        .read(AwsApplicationSignalsReadRequest::GetService(request))
        .expect("get service");
    assert_eq!(
        result
            .evidence
            .service
            .expect("service")
            .summary
            .service_name
            .as_str(),
        "checkout"
    );
    assert_eq!(
        result.evidence.digests.api_digest,
        Digest::from_text(AWS_APPLICATION_SIGNALS_API_VERSION)
    );
}

#[test]
fn bounded_slo_list_and_get_include_status_transitions_and_error_budget() {
    let scope = scope();
    let request = ListServiceLevelObjectivesRequest::new(&scope, ReadBounds::default())
        .expect("list SLO request");
    let page = plugin::ListServiceLevelObjectivesPage::new(
        &request,
        vec![slo_summary(&scope, SloStatus::Warning)],
        None,
    )
    .expect("SLO page");
    let mut service = service_for(&scope, FixtureAwsApplicationSignalsTransport::fixture());
    service
        .provider_mut()
        .transport_mut()
        .queue_list_service_level_objectives(Ok(page));
    let result = service
        .read(AwsApplicationSignalsReadRequest::ListServiceLevelObjectives(request))
        .expect("list SLOs");
    assert_eq!(result.evidence.slos[0].status, SloStatus::Warning);

    let request = GetServiceLevelObjectiveRequest::new(&scope).expect("get SLO request");
    let response = plugin::GetServiceLevelObjectiveResponse::new(
        &request,
        slo_detail(&scope, SloStatus::Breached),
        EvidenceStatus::Complete,
    )
    .expect("SLO response");
    let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .queue_get_service_level_objective(Ok(response));
    let result = service
        .read(AwsApplicationSignalsReadRequest::GetServiceLevelObjective(
            request,
        ))
        .expect("get SLO");
    let slo = result.evidence.slo.expect("SLO");
    assert_eq!(slo.status_summary.current, SloStatus::Breached);
    assert_eq!(slo.status_summary.previous, Some(SloStatus::Healthy));
    assert_eq!(
        slo.status_summary.transition.expect("transition").to,
        SloStatus::Breached
    );
    assert_eq!(slo.error_budget.remaining_seconds, Some(60));
    assert!(!result.evidence.authority.outcome_authority);
}

#[test]
fn pagination_is_opaque_bounded_and_cursor_binding_is_exact() {
    let scope = scope();
    let bounds = ReadBounds::new(1, 3, 2).expect("bounds");
    let request = ListServicesRequest::new(&scope, bounds).expect("request");
    let cursor = OpaquePageToken::new("provider-cursor-page-2").expect("cursor");
    let second_request = request
        .with_cursor(Some(cursor.clone()))
        .expect("bound cursor");
    let first_page = ListServicesPage::new(
        &request,
        vec![service_summary(&scope)],
        Some(cursor.clone()),
    )
    .expect("first page");
    let second_page = ListServicesPage::new(&second_request, vec![], None)
        .expect("second page")
        .with_status(EvidenceStatus::Complete);
    let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .queue_list_services(Ok(first_page));
    service
        .provider_mut()
        .transport_mut()
        .queue_list_services(Ok(second_page));
    let result = service
        .read(AwsApplicationSignalsReadRequest::ListServices(
            request.clone(),
        ))
        .expect("paged read");
    assert_eq!(result.evidence.pagination.pages_observed, 2);
    assert_eq!(result.evidence.pagination.cursor_digests.len(), 1);
    assert_eq!(service.provider().transport().calls().len(), 2);
    assert_ne!(
        request.request_digest().unwrap(),
        second_request.request_digest().unwrap()
    );
    let encoded = serde_json::to_string(&result).expect("result serializes");
    assert!(!encoded.contains("provider-cursor-page-2"));

    let wrong_cursor = OpaquePageToken::for_request(
        "provider-cursor-page-2",
        Digest::from_text("different-request"),
    )
    .expect("wrong cursor");
    let mut bad_page =
        ListServicesPage::new(&request, vec![service_summary(&scope)], None).expect("page");
    bad_page.next_cursor = Some(wrong_cursor);
    let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .queue_list_services(Ok(bad_page));
    let error = service
        .read(AwsApplicationSignalsReadRequest::ListServices(request))
        .expect_err("wrong cursor fails closed");
    assert!(matches!(
        error,
        ServiceError::Provider(ProviderError::CursorBindingMismatch)
    ));
}

#[test]
fn account_region_service_slo_operation_and_window_fences_fail_closed() {
    let scope = scope();
    let request = list_services_request(&scope);
    let service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());

    let mut wrong_account = request.clone();
    wrong_account.account_id = AccountId::new("210987654321").expect("account");
    assert!(matches!(
        service.propose(AwsApplicationSignalsReadRequest::ListServices(
            wrong_account
        )),
        Err(ServiceError::ScopeMismatch)
    ));

    let mut wrong_region = request.clone();
    wrong_region.region = Region::new("eu-west-1").expect("region");
    assert!(matches!(
        service.propose(AwsApplicationSignalsReadRequest::ListServices(wrong_region)),
        Err(ServiceError::ScopeMismatch)
    ));

    let mut wrong_service = request.clone();
    wrong_service.service_name = Some(ServiceName::new("payments").expect("service"));
    assert!(matches!(
        service.propose(AwsApplicationSignalsReadRequest::ListServices(
            wrong_service
        )),
        Err(ServiceError::ScopeMismatch)
    ));

    let slo_request = GetServiceLevelObjectiveRequest::new(&scope).expect("SLO request");
    let mut wrong_slo = slo_request.clone();
    wrong_slo.slo_id = SloId::new("latency").expect("SLO");
    assert!(matches!(
        service.propose(AwsApplicationSignalsReadRequest::GetServiceLevelObjective(
            wrong_slo
        )),
        Err(ServiceError::ScopeMismatch)
    ));

    let mut wrong_operation = slo_request.clone();
    wrong_operation.operation_name = OperationName::new("POST /checkout").expect("operation");
    assert!(matches!(
        service.propose(AwsApplicationSignalsReadRequest::GetServiceLevelObjective(
            wrong_operation
        )),
        Err(ServiceError::ScopeMismatch)
    ));

    let mut wrong_window = slo_request;
    wrong_window.time_window =
        TimeWindow::closed_seconds(window().start_seconds(), window().end_seconds() + 60)
            .expect("window");
    assert!(matches!(
        service.propose(AwsApplicationSignalsReadRequest::GetServiceLevelObjective(
            wrong_window
        )),
        Err(ServiceError::ScopeMismatch)
    ));
}

#[test]
fn time_windows_round_outward_to_api_seconds_and_reject_invalid_ranges() {
    let start = Utc
        .timestamp_opt(1_000, 100_000_000)
        .single()
        .expect("start");
    let end = Utc.timestamp_opt(1_010, 1).single().expect("end");
    let rounded = TimeWindow::closed(start, end).expect("rounded");
    assert_eq!(rounded.start_seconds(), 1_000);
    assert_eq!(rounded.end_seconds(), 1_011);
    assert!(TimeWindow::exact(start, end).is_err());
    assert!(matches!(
        TimeWindow::closed_seconds(10, 10),
        Err(ModelError::InvalidTimeWindow)
    ));
    assert!(matches!(
        TimeWindow::closed_seconds(10, 10 + 7_776_001),
        Err(ModelError::InvalidTimeWindow)
    ));
}

#[test]
fn no_data_partial_expired_access_loss_and_provider_unknown_are_not_healthy() {
    let statuses = [
        EvidenceStatus::NoData,
        EvidenceStatus::Partial,
        EvidenceStatus::Expired,
        EvidenceStatus::AccessLost,
        EvidenceStatus::ProviderUnknown,
    ];
    for status in statuses {
        let scope = scope();
        let request = list_services_request(&scope);
        let page = ListServicesPage::new(&request, Vec::new(), None)
            .expect("page")
            .with_status(status);
        let mut service = service_for(&scope, FixtureAwsApplicationSignalsTransport::fixture());
        service
            .provider_mut()
            .transport_mut()
            .queue_list_services(Ok(page));
        let result = service
            .read(AwsApplicationSignalsReadRequest::ListServices(request))
            .expect("safe status is recorded");
        assert_eq!(result.evidence.status, status);
        assert_ne!(result.evidence.status, EvidenceStatus::Complete);
        assert!(!result.evidence.authority.connected);
        assert!(!result.evidence.authority.native_provider);
    }
}

#[test]
fn transport_failures_preserve_400_401_403_404_409_429_5xx_and_timeout() {
    let cases = [
        (TransportError::from_status(400), Some(400)),
        (TransportError::from_status(401), Some(401)),
        (TransportError::from_status(403), Some(403)),
        (TransportError::from_status(404), Some(404)),
        (TransportError::from_status(409), Some(409)),
        (TransportError::rate_limited(Some(8)), Some(429)),
        (TransportError::from_status(503), Some(503)),
        (TransportError::timeout(), None),
    ];
    for (transport_error, status_code) in cases {
        let scope = scope();
        let request = list_services_request(&scope);
        let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
        service
            .provider_mut()
            .transport_mut()
            .queue_list_services(Err(transport_error.clone()));
        let error = service
            .read(AwsApplicationSignalsReadRequest::ListServices(request))
            .expect_err("transport error is surfaced");
        let ServiceError::Provider(ProviderError::Transport(error)) = error else {
            panic!("unexpected error variant");
        };
        assert_eq!(error.status_code(), status_code);
        if status_code == Some(429) {
            assert_eq!(error.retry_after_seconds, Some(8));
        }
    }
    assert_eq!(
        TransportFailure::from_status(503),
        TransportFailure::Server5xx
    );
}

#[test]
fn proposal_record_evidence_and_receipt_tamper_checks_are_independent() {
    let scope = scope();
    let request = list_services_request(&scope);
    let page = ListServicesPage::new(&request, vec![service_summary(&scope)], None).expect("page");
    let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .queue_list_services(Ok(page));
    let proposal = service
        .propose(AwsApplicationSignalsReadRequest::ListServices(
            request.clone(),
        ))
        .expect("proposal");
    let mut bad_proposal = proposal.clone();
    bad_proposal.proposal_digest = Digest::from_text("proposal-tamper");
    assert!(matches!(
        service.record(&bad_proposal),
        Err(ServiceError::ProposalTampered)
    ));

    let record = service.record(&proposal).expect("record");
    let mut bad_record = record.clone();
    bad_record.record_digest = Digest::from_text("record-tamper");
    assert!(matches!(
        service.verify(&proposal, &bad_record),
        Err(ServiceError::RecordTampered)
    ));

    let evidence = service.verify(&proposal, &record).expect("evidence");
    let mut bad_evidence = evidence.clone();
    bad_evidence.digests.evidence_digest = Digest::from_text("evidence-tamper");
    assert!(matches!(
        bad_evidence.verify(),
        Err(ServiceError::EvidenceTampered)
    ));
    let result = service.read(AwsApplicationSignalsReadRequest::ListServices(
        list_services_request(&scope),
    ));
    // The transport has no second queued response; the failed read proves the
    // earlier record path did not silently replay a native/live call.
    assert!(result.is_err());

    let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    let request = list_services_request(&scope);
    let page = ListServicesPage::new(&request, vec![service_summary(&scope)], None).expect("page");
    service
        .provider_mut()
        .transport_mut()
        .queue_list_services(Ok(page));
    let result = service
        .read(AwsApplicationSignalsReadRequest::ListServices(request))
        .expect("result");
    let mut bad_receipt = result.receipt.clone();
    bad_receipt.receipt_digest = Digest::from_text("receipt-tamper");
    assert!(matches!(
        service.verify_receipt(&bad_receipt),
        Err(ServiceError::ReceiptTampered)
    ));
}

#[test]
fn registration_secret_and_mission_consumer_revocation_are_fail_closed() {
    let scope = scope();
    let request = list_services_request(&scope);
    let page = ListServicesPage::new(&request, vec![service_summary(&scope)], None).expect("page");
    let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .queue_list_services(Ok(page));
    let mut consumer = MissionAwsApplicationSignalsConsumer::with_registration(
        scope.clone(),
        service.registration(),
    )
    .expect("consumer");
    let result = service
        .read(AwsApplicationSignalsReadRequest::ListServices(request))
        .expect("read");
    let accepted = consumer.consume(&result).expect("consume");
    assert!(accepted.accepted);
    assert!(!accepted.adopted_outcome);
    assert!(!accepted.truth_authority);
    assert_eq!(consumer.consumed_count(), 1);
    assert!(matches!(
        consumer.consume(&result),
        Err(plugin::ConsumerError::Replay)
    ));

    consumer.revoke().expect("consumer revoke");
    assert!(matches!(
        consumer.consume(&result),
        Err(plugin::ConsumerError::Revoked)
    ));

    let mut service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    service.revoke_registration().expect("registration revoke");
    assert!(matches!(
        service.propose_list_services(ReadBounds::default()),
        Err(ServiceError::RegistrationRevoked)
    ));

    let mut secret = SigV4SecretReference::new("opaque-secret", &scope, 3).expect("secret");
    secret.revoke().expect("secret revoke");
    assert!(secret.is_revoked());
    assert!(matches!(
        AwsApplicationSignalsService::new(scope, secret, AwsApplicationSignalsProvider::default(),),
        Err(ServiceError::SecretRevoked)
    ));
}

#[test]
fn all_non_native_provenances_are_honest_and_blocked_env_is_explicit() {
    for (transport, provenance) in [
        (
            RecordingAwsApplicationSignalsTransport::fixture(),
            ProviderProvenance::Fixture,
        ),
        (
            RecordingAwsApplicationSignalsTransport::recording(),
            ProviderProvenance::Recording,
        ),
        (
            RecordingAwsApplicationSignalsTransport::loopback(),
            ProviderProvenance::Loopback,
        ),
    ] {
        let provider = AwsApplicationSignalsProvider::new(transport).expect("provider");
        assert_eq!(provider.provenance(), provenance);
        assert!(!provenance.native());
        assert!(!provenance.connected());
        assert!(!provider.definition().native);
        assert!(!provider.definition().connected);
    }
    let provider = AwsApplicationSignalsProvider::default();
    assert_eq!(provider.provenance(), ProviderProvenance::BlockedEnv);
    assert!(!provider.provenance().native());
    assert!(!provider.provenance().connected());
}

#[test]
fn permission_scope_is_operation_specific() {
    let account_id = account();
    let region_value = region();
    let permission = PermissionScope::new(
        account_id.clone(),
        region_value.clone(),
        [ReadOperation::ListServices].into_iter().collect(),
        plugin::RevisionId::new("permission-revision-list-only").expect("revision"),
    )
    .expect("permission");
    let mission = MissionBinding::new(
        plugin::MissionId::new("mission-permission").expect("mission"),
        plugin::ProjectId::new("project-permission").expect("project"),
        plugin::RevisionId::new("mission-revision").expect("revision"),
        Digest::from_text("consent"),
    );
    let scope = AwsApplicationSignalsScope::new(
        account_id,
        region_value,
        Some(ServiceName::new("checkout").expect("service")),
        Some(SloId::new("availability").expect("SLO")),
        Some(OperationName::new("GET /checkout").expect("operation")),
        window(),
        DeploymentBinding::new("deployment", 1).expect("deployment"),
        ReleaseBinding::new("release", 1).expect("release"),
        mission,
        permission,
    )
    .expect("scope");
    let service = service_for(&scope, RecordingAwsApplicationSignalsTransport::recording());
    assert!(service.propose_list_services(ReadBounds::default()).is_ok());
    assert!(matches!(
        service.propose_get_service(),
        Err(ServiceError::PermissionMismatch)
    ));
}

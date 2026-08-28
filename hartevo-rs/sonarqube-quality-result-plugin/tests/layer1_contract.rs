use hartevo_sonarqube_quality_result_plugin::{
    AnalysisDate, AnalysisIdentity, AnalysisKey, AnalysisPage, BranchOrPullRequest,
    ComparisonOperator, ConditionStatus, Digest, HostIdentity, MAX_PAGE_SIZE, Measure,
    MeasureBasis, MeasureSelector, MeasureValue, MetricKey, MissionConsumptionDisposition,
    MissionId, MissionScope, Permission, PermissionSnapshot, ProjectId, ProjectionState,
    QualityDecision, QualityGateCondition, QualityGateId, QualityGateIdentity, QualityGateName,
    QualityGateStatus, ReadLimits, RecordingTransport, RegistrationStatus, SecretReference,
    SonarProjectKey, SonarQubeEndpoint, SonarQubeProvider, SonarQubeProviderError,
    SonarQubeQualityRecordingLog, SonarQubeQualityResultService, SonarQubeQualityScope,
    SonarQubeTransportError, SourceRevision, TransportProvenance, WorkProductId,
};

const OBSERVED_REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn digest(value: &str) -> Digest {
    Digest::from_text(value)
}

fn analysis() -> AnalysisIdentity {
    AnalysisIdentity::new(
        AnalysisKey::new("analysis-01").expect("analysis key"),
        AnalysisDate::new("2026-08-14T09:00:00+0800").expect("analysis date"),
        SourceRevision::new(OBSERVED_REVISION).expect("source revision"),
    )
    .expect("analysis")
}

fn scope_with_selector(selector: MeasureSelector) -> SonarQubeQualityScope {
    SonarQubeQualityScope::new(
        HostIdentity::new("https://sonarqube.example.test").expect("host"),
        hartevo_sonarqube_quality_result_plugin::OrganizationId::new("org-01")
            .expect("organization"),
        SonarProjectKey::new("hartevo-project").expect("sonar project"),
        BranchOrPullRequest::branch("main").expect("branch"),
        analysis(),
        QualityGateIdentity::new(
            QualityGateId::new("gate-01").expect("gate id"),
            QualityGateName::new("Sonar way").expect("gate name"),
        )
        .expect("quality gate"),
        vec![selector],
        MissionScope::new(
            MissionId::new("mission-01").expect("mission"),
            3,
            ProjectId::new("project-01").expect("project"),
            7,
            WorkProductId::new("work-product-01").expect("work product"),
            2,
            digest("policy"),
            digest("consent"),
        )
        .expect("mission scope"),
    )
    .expect("scope")
}

fn scope() -> SonarQubeQualityScope {
    scope_with_selector(
        MeasureSelector::new(
            MetricKey::new("coverage").expect("metric"),
            MeasureBasis::NewCode,
        )
        .expect("selector"),
    )
}

fn condition(scope: &SonarQubeQualityScope) -> QualityGateCondition {
    QualityGateCondition::new(
        scope.measures[0].clone(),
        ConditionStatus::Ok,
        ComparisonOperator::GreaterThanOrEqual,
        MeasureValue::new("80.0").expect("threshold"),
        Some(MeasureValue::new("92.0").expect("actual")),
    )
    .expect("condition")
}

fn queue_success(transport: &mut RecordingTransport, scope: &SonarQubeQualityScope) {
    let provenance = transport.provenance();
    transport.push_analysis_page(
        AnalysisPage::new(scope, 1, vec![scope.analysis.clone()], None, provenance)
            .expect("analysis page")
            .with_page_size(MAX_PAGE_SIZE),
    );
    transport.push_quality_gate(
        hartevo_sonarqube_quality_result_plugin::QualityGateStatusResponse::new(
            scope,
            scope.analysis.clone(),
            scope.quality_gate.clone(),
            QualityGateStatus::Ok,
            vec![condition(scope)],
            provenance,
        )
        .expect("quality gate response"),
    );
    transport.push_measures(
        hartevo_sonarqube_quality_result_plugin::MeasuresComponentResponse::new(
            scope,
            scope.analysis.clone(),
            vec![
                Measure::new(
                    scope.measures[0].clone(),
                    MeasureValue::new("92.0").expect("measure"),
                    Some(false),
                )
                .expect("measure evidence"),
            ],
            provenance,
        )
        .expect("measures response"),
    );
}

fn service(
    transport: RecordingTransport,
    scope: SonarQubeQualityScope,
) -> SonarQubeQualityResultService<RecordingTransport> {
    SonarQubeQualityResultService::new(
        SonarQubeProvider::new(transport),
        scope,
        SecretReference::new("opaque-sonarqube-handle", 1).expect("secret reference"),
        hartevo_sonarqube_quality_result_plugin::RegistrationId::new("registration-01")
            .expect("registration"),
    )
    .expect("service")
}

#[test]
fn contract_and_registration_are_digest_bound_and_redacted() {
    assert_eq!(
        hartevo_sonarqube_quality_result_plugin::contract_digest(),
        Digest::parse(hartevo_sonarqube_quality_result_plugin::CONTRACT_DIGEST)
            .expect("contract digest")
    );
    let scope = scope();
    let mut transport = RecordingTransport::fixture();
    queue_success(&mut transport, &scope);
    let service = service(transport, scope);
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(!registration_json.contains("opaque-sonarqube-handle"));
    assert!(registration_json.contains("secretReferenceDigest"));
    let debug = format!("{:?}", service.registration().secret_reference());
    assert!(!debug.contains("opaque-sonarqube-handle"));
    assert!(service.registration().registration_digest().as_str().len() == 64);
    assert!(!service.registration_receipt().connected);
    assert!(!service.registration_receipt().native);
    assert!(!service.registration_receipt().first_party);
}

#[test]
fn successful_quality_result_uses_all_three_allowlisted_reads() {
    let scope = scope();
    let mut transport = RecordingTransport::recording();
    queue_success(&mut transport, &scope);
    let mut service = service(transport, scope.clone());
    let projection = service.read_quality_result().expect("quality result");
    assert_eq!(projection.state, ProjectionState::Pass);
    assert_eq!(projection.quality_gate_status, Some(QualityGateStatus::Ok));
    assert_eq!(projection.measures.len(), 1);
    assert!(!projection.connected());
    assert!(!projection.native());
    assert!(!projection.first_party());
    let requests = service.provider().requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].endpoint,
        SonarQubeEndpoint::ProjectAnalysesSearch
    );
    assert_eq!(
        requests[1].endpoint,
        SonarQubeEndpoint::QualityGatesProjectStatus
    );
    assert_eq!(requests[2].endpoint, SonarQubeEndpoint::MeasuresComponent);
    assert_eq!(requests[0].path, "/api/project_analyses/search");
    assert_eq!(requests[1].path, "/api/qualitygates/project_status");
    assert_eq!(requests[2].path, "/api/measures/component");
    assert!(
        requests
            .iter()
            .all(|request| { !request.connected && !request.native && !request.first_party })
    );
}

#[test]
fn proposal_recording_and_mission_consumption_are_below_kernel_and_idempotent() {
    let scope = scope();
    let mut transport = RecordingTransport::fixture();
    queue_success(&mut transport, &scope);
    let mut service = service(transport, scope.clone());
    let projection = service.read_quality_result().expect("quality result");
    let proposal = service
        .compile_quality_result_proposal(&projection, "idempotency-01")
        .expect("proposal");
    assert_eq!(proposal.decision, QualityDecision::Pass);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.outcome_adopted);
    proposal.validate_integrity().expect("proposal integrity");
    let mut log = SonarQubeQualityRecordingLog::default();
    let first = service
        .record_quality_result(&mut log, &proposal)
        .expect("recording");
    assert_eq!(first.state, ProjectionState::Pass);
    assert_eq!(log.len(), 1);
    let replay = service
        .record_quality_result(&mut log, &proposal)
        .expect("replay");
    assert!(replay.replayed);
    let mut consumer =
        hartevo_sonarqube_quality_result_plugin::MissionSonarQubeQualityConsumer::new(scope)
            .expect("consumer");
    let consumption = consumer.consume(&proposal).expect("consume");
    assert!(!consumption.replayed);
    assert_eq!(
        consumption.disposition,
        MissionConsumptionDisposition::Fresh
    );
    assert!(!consumption.adopted);
    let consumption_replay = consumer.consume(&proposal).expect("consume replay");
    assert!(consumption_replay.replayed);
    assert_eq!(
        consumption_replay.disposition,
        MissionConsumptionDisposition::Replay
    );
}

#[test]
fn no_analysis_stale_and_partial_are_explicit_non_adoptable_states() {
    let scope = scope();

    let mut missing_transport = RecordingTransport::fixture();
    missing_transport.push_analysis_page(
        AnalysisPage::new(&scope, 1, Vec::new(), None, TransportProvenance::Fixture)
            .expect("missing page"),
    );
    let mut missing_service = service(missing_transport, scope.clone());
    assert_eq!(
        missing_service
            .read_quality_result()
            .expect("no analysis projection")
            .state,
        ProjectionState::NoAnalysis
    );

    let stale_analysis = AnalysisIdentity::new(
        scope.analysis.key.clone(),
        AnalysisDate::new("2026-08-13T09:00:00+0800").expect("stale date"),
        SourceRevision::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").expect("stale revision"),
    )
    .expect("stale analysis");
    let mut stale_transport = RecordingTransport::fixture();
    stale_transport.push_analysis_page(
        AnalysisPage::new(
            &scope,
            1,
            vec![stale_analysis],
            None,
            TransportProvenance::Fixture,
        )
        .expect("stale page"),
    );
    let mut stale_service = service(stale_transport, scope.clone());
    assert_eq!(
        stale_service
            .read_quality_result()
            .expect("stale projection")
            .state,
        ProjectionState::Stale
    );

    let mut partial_transport = RecordingTransport::fixture();
    partial_transport.push_analysis_page(
        AnalysisPage::new(
            &scope,
            1,
            vec![scope.analysis.clone()],
            None,
            TransportProvenance::Fixture,
        )
        .expect("partial page")
        .with_partial(true),
    );
    let mut partial_service = service(partial_transport, scope);
    assert_eq!(
        partial_service
            .read_quality_result()
            .expect("partial projection")
            .state,
        ProjectionState::Partial
    );
}

#[test]
fn quality_gate_status_maps_warn_and_error_without_approval_authority() {
    for (status, expected_state, expected_decision) in [
        (
            QualityGateStatus::Warn,
            ProjectionState::Warn,
            QualityDecision::Review,
        ),
        (
            QualityGateStatus::Error,
            ProjectionState::Error,
            QualityDecision::Fail,
        ),
    ] {
        let scope = scope();
        let mut transport = RecordingTransport::fixture();
        let provenance = transport.provenance();
        transport.push_analysis_page(
            AnalysisPage::new(&scope, 1, vec![scope.analysis.clone()], None, provenance)
                .expect("analysis"),
        );
        transport.push_quality_gate(
            hartevo_sonarqube_quality_result_plugin::QualityGateStatusResponse::new(
                &scope,
                scope.analysis.clone(),
                scope.quality_gate.clone(),
                status,
                vec![condition(&scope)],
                provenance,
            )
            .expect("gate"),
        );
        transport.push_measures(
            hartevo_sonarqube_quality_result_plugin::MeasuresComponentResponse::new(
                &scope,
                scope.analysis.clone(),
                vec![
                    Measure::new(
                        scope.measures[0].clone(),
                        MeasureValue::new("92.0").expect("measure"),
                        Some(false),
                    )
                    .expect("measure evidence"),
                ],
                provenance,
            )
            .expect("measures"),
        );
        let mut service = service(transport, scope);
        let projection = service.read_quality_result().expect("projection");
        assert_eq!(projection.state, expected_state);
        let proposal = service
            .compile_quality_result_proposal(&projection, "status-key")
            .expect("proposal");
        assert_eq!(proposal.decision, expected_decision);
    }
}

#[test]
fn tamper_redaction_bounds_and_http_failures_fail_closed() {
    let scope = scope();
    let mut tampered_transport = RecordingTransport::fixture();
    let mut page = AnalysisPage::new(
        &scope,
        1,
        vec![scope.analysis.clone()],
        None,
        TransportProvenance::Fixture,
    )
    .expect("page");
    page.response_digest = digest("tampered");
    tampered_transport.push_analysis_page(page);
    let mut tampered_service = service(tampered_transport, scope.clone());
    assert!(matches!(
        tampered_service.read_quality_result(),
        Err(SonarQubeProviderError::Contract(
            hartevo_sonarqube_quality_result_plugin::SonarQubeQualityResultError::TamperedEvidence
        ))
    ));

    let mut unredacted_transport = RecordingTransport::fixture();
    unredacted_transport.push_analysis_page(
        AnalysisPage::new(
            &scope,
            1,
            vec![scope.analysis.clone()],
            None,
            TransportProvenance::Fixture,
        )
        .expect("page")
        .with_redacted(false),
    );
    let mut unredacted_service = service(unredacted_transport, scope.clone());
    assert!(matches!(
        unredacted_service.read_quality_result(),
        Err(SonarQubeProviderError::Contract(
            hartevo_sonarqube_quality_result_plugin::SonarQubeQualityResultError::ResponseNotRedacted
        ))
    ));

    for error in [
        SonarQubeTransportError::Unauthorized401,
        SonarQubeTransportError::Forbidden403,
        SonarQubeTransportError::NotFound404,
        SonarQubeTransportError::Conflict409,
        SonarQubeTransportError::RateLimited429,
        SonarQubeTransportError::Timeout,
        SonarQubeTransportError::Server5xx { status: 503 },
    ] {
        let mut transport = RecordingTransport::fixture();
        transport.push_error(error.clone());
        let mut service = service(transport, scope.clone());
        let failure = service
            .read_quality_result()
            .expect_err("transport failure");
        assert_eq!(
            SonarQubeProvider::<RecordingTransport>::projection_state_for_error(&failure),
            if matches!(
                error,
                SonarQubeTransportError::Unauthorized401 | SonarQubeTransportError::Forbidden403
            ) {
                ProjectionState::AccessLoss
            } else {
                ProjectionState::ProviderUnknown
            }
        );
    }
}

#[test]
fn pagination_measure_scope_and_proposal_fences_fail_closed() {
    let scope = scope();
    let mut repeated_transport = RecordingTransport::fixture();
    let provenance = repeated_transport.provenance();
    repeated_transport.push_analysis_page(
        AnalysisPage::new(&scope, 1, vec![scope.analysis.clone()], Some(2), provenance)
            .expect("first page"),
    );
    let mut repeated_page =
        AnalysisPage::new(&scope, 2, Vec::new(), None, provenance).expect("second page");
    repeated_page.next_page = Some(2);
    repeated_page.response_digest = repeated_page.computed_digest();
    repeated_transport.push_analysis_page(repeated_page);
    let mut repeated_service = service(repeated_transport, scope.clone());
    assert!(matches!(
        repeated_service.read_quality_result(),
        Err(SonarQubeProviderError::Contract(
            hartevo_sonarqube_quality_result_plugin::SonarQubeQualityResultError::PaginationLoop
        ))
    ));

    let mut missing_measure_transport = RecordingTransport::fixture();
    missing_measure_transport.push_analysis_page(
        AnalysisPage::new(&scope, 1, vec![scope.analysis.clone()], None, provenance)
            .expect("analysis page"),
    );
    missing_measure_transport.push_quality_gate(
        hartevo_sonarqube_quality_result_plugin::QualityGateStatusResponse::new(
            &scope,
            scope.analysis.clone(),
            scope.quality_gate.clone(),
            QualityGateStatus::Ok,
            vec![condition(&scope)],
            provenance,
        )
        .expect("gate"),
    );
    missing_measure_transport.push_measures(
        hartevo_sonarqube_quality_result_plugin::MeasuresComponentResponse::new(
            &scope,
            scope.analysis.clone(),
            Vec::new(),
            provenance,
        )
        .expect("empty measures"),
    );
    let mut missing_measure_service = service(missing_measure_transport, scope.clone());
    assert!(matches!(
        missing_measure_service.read_quality_result(),
        Err(SonarQubeProviderError::Contract(
            hartevo_sonarqube_quality_result_plugin::SonarQubeQualityResultError::MeasureMissing
        ))
    ));

    let mut good_transport = RecordingTransport::fixture();
    queue_success(&mut good_transport, &scope);
    let mut good_service = service(good_transport, scope.clone());
    let projection = good_service.read_quality_result().expect("projection");
    let mut proposal = good_service
        .compile_quality_result_proposal(&projection, "fence-key")
        .expect("proposal");
    proposal.decision = QualityDecision::Fail;
    assert!(matches!(
        hartevo_sonarqube_quality_result_plugin::MissionSonarQubeQualityConsumer::new(
            scope.clone()
        )
        .expect("consumer")
        .consume(&proposal),
        Err(hartevo_sonarqube_quality_result_plugin::SonarQubeQualityResultError::ProposalTampered)
    ));

    let mut stale_proposal = good_service
        .compile_quality_result_proposal(&projection, "stale-key")
        .expect("stale proposal");
    stale_proposal.mission_revision += 1;
    stale_proposal.proposal_digest = stale_proposal.computed_digest();
    let mut consumer =
        hartevo_sonarqube_quality_result_plugin::MissionSonarQubeQualityConsumer::new(scope)
            .expect("consumer");
    assert!(matches!(
        consumer.consume(&stale_proposal),
        Err(
            hartevo_sonarqube_quality_result_plugin::SonarQubeQualityResultError::StaleMissionRevision
        )
    ));
}

#[test]
fn registration_unmount_remount_revocation_and_secret_revocation_fence_reads() {
    let scope = scope();
    let mut transport = RecordingTransport::fixture();
    queue_success(&mut transport, &scope);
    let mut registered_service = service(transport, scope.clone());
    assert_eq!(
        registered_service.registration().status(),
        RegistrationStatus::Active
    );
    registered_service.unmount().expect("unmount");
    assert!(matches!(
        registered_service.read_quality_result(),
        Err(SonarQubeProviderError::RegistrationInactive)
    ));
    registered_service.remount().expect("remount");
    registered_service
        .read_quality_result()
        .expect("remounted read");

    let mut revoked_transport = RecordingTransport::fixture();
    queue_success(&mut revoked_transport, &scope);
    let mut revoked_service = service(revoked_transport, scope.clone());
    revoked_service.revoke().expect("revoke");
    assert_eq!(
        revoked_service.registration().status(),
        RegistrationStatus::Revoked
    );
    assert!(matches!(
        revoked_service.read_quality_result(),
        Err(SonarQubeProviderError::Contract(
            hartevo_sonarqube_quality_result_plugin::SonarQubeQualityResultError::InvalidRegistration
        ) | SonarQubeProviderError::RegistrationRevoked)
    ));

    let mut secret_transport = RecordingTransport::fixture();
    queue_success(&mut secret_transport, &scope);
    let mut secret_service = service(secret_transport, scope);
    secret_service.revoke_secret_reference();
    assert!(matches!(
        secret_service.read_quality_result(),
        Err(SonarQubeProviderError::SecretRevoked
            | SonarQubeProviderError::Contract(
                hartevo_sonarqube_quality_result_plugin::SonarQubeQualityResultError::InvalidRegistration
            ))
    ));
}

#[test]
fn scope_metric_permission_branch_and_provider_bounds_are_exact() {
    assert!(MetricKey::new("arbitrary_provider_metric").is_err());
    let invalid_permissions = PermissionSnapshot::new(vec![Permission::ProjectRead]);
    let scope = scope();
    let result = SonarQubeQualityResultService::new_with_permissions(
        SonarQubeProvider::new(RecordingTransport::fixture()),
        scope.clone(),
        SecretReference::new("opaque", 1).expect("secret"),
        hartevo_sonarqube_quality_result_plugin::RegistrationId::new("registration-invalid")
            .expect("registration"),
        invalid_permissions,
    );
    assert!(result.is_err());

    let pull_request_scope = SonarQubeQualityScope::new(
        scope.host.clone(),
        scope.organization.clone(),
        scope.project.clone(),
        BranchOrPullRequest::pull_request("42").expect("pull request"),
        scope.analysis.clone(),
        scope.quality_gate.clone(),
        scope.measures.clone(),
        scope.mission.clone(),
    )
    .expect("pull request scope");
    let mut transport = RecordingTransport::fixture();
    let provenance = transport.provenance();
    transport.push_analysis_page(
        AnalysisPage::new(&pull_request_scope, 1, vec![], None, provenance)
            .expect("pull request page"),
    );
    let mut pull_request_service = service(transport, pull_request_scope);
    pull_request_service
        .read_quality_result()
        .expect("pull request no analysis");
    let request = &pull_request_service.provider().requests()[0];
    assert_eq!(request.endpoint, SonarQubeEndpoint::ProjectAnalysesSearch);

    assert!(
        SonarQubeProvider::with_limits(
            RecordingTransport::fixture(),
            ReadLimits {
                max_analysis_pages: 0,
                ..ReadLimits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn all_supported_fixture_recording_loopback_and_blocked_env_provenance_is_honest() {
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Loopback,
    ] {
        let scope = scope();
        let mut transport = RecordingTransport::new(provenance);
        queue_success(&mut transport, &scope);
        let mut service = service(transport, scope);
        let projection = service.read_quality_result().expect("non-native read");
        assert_eq!(projection.provenance, provenance);
        assert!(!projection.connected());
        assert!(!projection.native());
        assert!(!projection.first_party());
        assert!(service.provider().requests().iter().all(|request| {
            request.provenance == provenance
                && !request.connected
                && !request.native
                && !request.first_party
        }));
    }

    let scope = scope();
    let mut blocked = service(RecordingTransport::blocked_env(), scope);
    let error = blocked
        .read_quality_result()
        .expect_err("BLOCKED_ENV must not connect");
    assert_eq!(
        error,
        SonarQubeProviderError::Transport(SonarQubeTransportError::BlockedEnv)
    );
}

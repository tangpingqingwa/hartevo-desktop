use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_appconfig_deployment_result_plugin::{
    AppConfigApplicationId, AppConfigConfigurationProfileId, AppConfigConfigurationVersion,
    AppConfigDeploymentId, AppConfigDeploymentState, AppConfigEnvironmentId, AwsAccountId,
    AwsAppConfigDeploymentError, AwsAppConfigDeploymentScope, AwsAppConfigProvider,
    AwsAppConfigTransportError, ConsentScope, Cursor, DeploymentEvent,
    DeploymentEventClassification, DeploymentFilter, DeploymentMetadata, DeploymentMetadataInput,
    DeploymentStrategy, DeploymentStrategyId, FixtureTransport, ListDeploymentsRequest,
    ListDeploymentsResponse, LoopbackTransport, MissionAwsAppConfigConsumer, MissionIdentity,
    ProjectIdentity, RecordedAwsAppConfigResult, RecordingTransport, RegistrationStatus,
    SecretReference, TransportProvenance, WorkProductIdentity,
};
use serde_json::to_string;

const NOW_SECONDS: i64 = 1_787_000_000;

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsAppConfigDeploymentScope {
    AwsAppConfigDeploymentScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_appconfig_deployment_result_plugin::AwsRegion::new("us-east-1")
            .expect("region"),
        AppConfigApplicationId::new("app-1").expect("application"),
        AppConfigEnvironmentId::new("env-1").expect("environment"),
        AppConfigDeploymentId::new("deployment-7").expect("deployment"),
        AppConfigConfigurationProfileId::new("profile-1").expect("profile"),
        AppConfigConfigurationVersion::new("version-12").expect("version"),
        MissionIdentity::new("mission-1", 7).expect("mission"),
        ProjectIdentity::new("project-1", 11).expect("project"),
        WorkProductIdentity::new("work-product-1", 13).expect("work product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsAppConfigDeploymentScope) -> SecretReference {
    SecretReference::sigv4("opaque-sigv4-handle", scope, 1).expect("secret")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 4, now() + Duration::days(7)).expect("consent")
}

fn metadata(
    scope: &AwsAppConfigDeploymentScope,
    state: AppConfigDeploymentState,
    deployment: Option<&str>,
    profile: Option<&str>,
    version: Option<&str>,
) -> DeploymentMetadata {
    let terminal = state.is_terminal();
    let observed_at = now();
    let strategy = DeploymentStrategy::new(
        DeploymentStrategyId::new("linear-10").expect("strategy"),
        Some("fixture strategy name".to_owned()),
    )
    .expect("strategy projection");
    let events = vec![
        DeploymentEvent::new(
            1,
            DeploymentEventClassification::Started,
            observed_at - Duration::minutes(15),
            "provider event body is redacted",
        )
        .expect("event"),
        DeploymentEvent::new(
            2,
            if terminal {
                DeploymentEventClassification::Completed
            } else {
                DeploymentEventClassification::Progressed
            },
            observed_at - Duration::minutes(1),
            "second provider event body is redacted",
        )
        .expect("event"),
    ];
    let input = DeploymentMetadataInput {
        deployment: deployment.map_or_else(
            || scope.deployment().clone(),
            |value| AppConfigDeploymentId::new(value).expect("deployment"),
        ),
        configuration_profile: profile.map_or_else(
            || scope.configuration_profile().clone(),
            |value| AppConfigConfigurationProfileId::new(value).expect("profile"),
        ),
        configuration_version: version.map_or_else(
            || scope.configuration_version().clone(),
            |value| AppConfigConfigurationVersion::new(value).expect("version"),
        ),
        strategy,
        state,
        percentage_complete: if terminal { 100.0 } else { 42.5 },
        started_at: observed_at - Duration::minutes(15),
        last_updated_at: observed_at,
        completed_at: terminal.then_some(observed_at - Duration::minutes(1)),
        events,
        events_truncated: false,
    };
    if deployment.is_some() || profile.is_some() || version.is_some() {
        DeploymentMetadata::new_list_item(scope, input).expect("list metadata")
    } else {
        DeploymentMetadata::new(scope, input).expect("metadata")
    }
}

fn recording_service(
    transport: RecordingTransport,
) -> hartevo_aws_appconfig_deployment_result_plugin::AwsAppConfigDeploymentService<RecordingTransport>
{
    let scope = scope();
    let provider = AwsAppConfigProvider::new(transport).expect("provider");
    hartevo_aws_appconfig_deployment_result_plugin::AwsAppConfigDeploymentService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service")
}

#[test]
fn contract_scope_registration_and_secret_boundary_are_digest_fenced() {
    let scope = scope();
    let service =
        hartevo_aws_appconfig_deployment_result_plugin::AwsAppConfigDeploymentService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            AwsAppConfigProvider::default(),
            now(),
        )
        .expect("service");
    assert!(service.registration().validate().is_ok());
    let serialized = to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains("opaque-sigv4-handle"));
    assert!(!debug.contains("opaque-sigv4-handle"));
    let capabilities = service.describe_capabilities();
    assert_eq!(capabilities.operations.len(), 2);
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.provider_receipt);
}

#[test]
fn fixture_and_loopback_never_claim_connected_or_native() {
    fn assert_non_native<
        T: hartevo_aws_appconfig_deployment_result_plugin::AwsAppConfigTransport,
    >(
        provider: AwsAppConfigProvider<T>,
    ) {
        let scope = scope();
        let mut service =
            hartevo_aws_appconfig_deployment_result_plugin::AwsAppConfigDeploymentService::new(
                scope.clone(),
                secret(&scope),
                consent(),
                provider,
                now(),
            )
            .expect("service");
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("proposal");
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!proposal.first_party);
        assert!(!proposal.provider_receipt);
        assert!(!proposal.can_be_adopted());
        assert!(proposal.is_review_only());
    }
    assert_non_native(
        AwsAppConfigProvider::new(FixtureTransport::for_scope(&scope(), now()))
            .expect("fixture provider"),
    );
    assert_non_native(
        AwsAppConfigProvider::new(LoopbackTransport::for_scope(&scope(), now()))
            .expect("loopback provider"),
    );
}

#[test]
fn pagination_cursor_is_opaque_and_bound_to_filter_and_revision() {
    let scope = scope();
    let filter = DeploymentFilter::for_scope(&scope, 20).expect("filter");
    let cursor = Cursor::new("raw-provider-next-token", &scope, &filter, 2).expect("cursor");
    let first_request = ListDeploymentsRequest::new(&scope, filter.clone(), None).expect("request");
    let second_request =
        ListDeploymentsRequest::new(&scope, filter.clone(), Some(cursor.clone())).expect("request");
    assert!(
        !second_request
            .path_and_query()
            .contains("raw-provider-next-token")
    );
    assert!(second_request.path_and_query().contains("nextToken="));

    let other = metadata(
        &scope,
        AppConfigDeploymentState::Deploying,
        Some("deployment-other"),
        Some("profile-other"),
        Some("version-other"),
    );
    let target = metadata(&scope, AppConfigDeploymentState::Complete, None, None, None);
    let first = ListDeploymentsResponse::new(
        &first_request,
        vec![other],
        Some(cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let second = ListDeploymentsResponse::new(
        &second_request,
        vec![target.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("second page");
    let get_request =
        hartevo_aws_appconfig_deployment_result_plugin::GetDeploymentRequest::for_scope(&scope)
            .expect("get request");
    let get = hartevo_aws_appconfig_deployment_result_plugin::GetDeploymentResponse::new(
        &get_request,
        target,
        512,
        TransportProvenance::Recording,
    )
    .expect("get response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(first));
    transport.push_list_response(Ok(second));
    transport.push_get_response(Ok(get));
    let mut service = recording_service(transport);
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.list_pages, 2);
    assert!(proposal.list_complete);
    assert_eq!(
        proposal.state,
        hartevo_aws_appconfig_deployment_result_plugin::DeploymentEvidenceState::Completed
    );
}

#[test]
fn scope_filter_and_revision_drift_are_rejected() {
    let scope = scope();
    let other_scope = AwsAppConfigDeploymentScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_appconfig_deployment_result_plugin::AwsRegion::new("us-east-1")
            .expect("region"),
        AppConfigApplicationId::new("other-app").expect("application"),
        AppConfigEnvironmentId::new("env-1").expect("environment"),
        AppConfigDeploymentId::new("deployment-7").expect("deployment"),
        AppConfigConfigurationProfileId::new("profile-1").expect("profile"),
        AppConfigConfigurationVersion::new("version-12").expect("version"),
        MissionIdentity::new("mission-1", 7).expect("mission"),
        ProjectIdentity::new("project-1", 11).expect("project"),
        WorkProductIdentity::new("work-product-1", 13).expect("work product"),
    )
    .expect("other scope");
    assert!(
        DeploymentFilter::for_scope(&other_scope, 10)
            .expect("other filter")
            .validate_against(&scope)
            .is_err()
    );
    assert!(
        AwsAppConfigProvider::with_identity(RecordingTransport::default(), 0, "invalid").is_err()
    );

    let mut service = recording_service(RecordingTransport::default());
    let mut request = service.default_request(now()).expect("request");
    request.registration_revision += 1;
    assert_eq!(
        service.propose(request).expect_err("revision drift"),
        AwsAppConfigDeploymentError::ScopeMismatch
    );
    assert_eq!(scope.application().as_str(), "app-1");
}

#[test]
fn transport_statuses_are_redacted_into_non_adoptable_states() {
    for error in [
        AwsAppConfigTransportError::BadRequest,
        AwsAppConfigTransportError::Unauthorized,
        AwsAppConfigTransportError::Forbidden,
        AwsAppConfigTransportError::NotFound,
        AwsAppConfigTransportError::Conflict,
        AwsAppConfigTransportError::RateLimited {
            retry_after_seconds: Some(2),
        },
        AwsAppConfigTransportError::ServerError { status: 503 },
        AwsAppConfigTransportError::Timeout,
        AwsAppConfigTransportError::AccessLost,
        AwsAppConfigTransportError::Partial,
        AwsAppConfigTransportError::BlockedEnv,
    ] {
        let mut transport = RecordingTransport::default();
        transport.push_list_response(Err(error.clone()));
        let mut service = recording_service(transport);
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("proposal");
        assert!(proposal.failure.is_some());
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!proposal.can_be_adopted());
    }
}

#[test]
fn tamper_and_state_progress_drift_do_not_cross_the_boundary() {
    let scope = scope();
    let request = ListDeploymentsRequest::new(
        &scope,
        DeploymentFilter::for_scope(&scope, 20).expect("filter"),
        None,
    )
    .expect("request");
    let tampered = ListDeploymentsResponse::new(
        &request,
        vec![metadata(
            &scope,
            AppConfigDeploymentState::Complete,
            None,
            None,
            None,
        )],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(
        hartevo_aws_appconfig_deployment_result_plugin::Digest::from_text("tampered"),
    );
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(tampered));
    let mut service = recording_service(transport);
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(
        proposal.state,
        hartevo_aws_appconfig_deployment_result_plugin::DeploymentEvidenceState::ProviderUnknown
    );
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "invalid_response"
    );

    let list_request = ListDeploymentsRequest::new(
        &scope,
        DeploymentFilter::for_scope(&scope, 20).expect("filter"),
        None,
    )
    .expect("request");
    let list = ListDeploymentsResponse::new(
        &list_request,
        vec![metadata(
            &scope,
            AppConfigDeploymentState::Deploying,
            None,
            None,
            None,
        )],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list");
    let get_request =
        hartevo_aws_appconfig_deployment_result_plugin::GetDeploymentRequest::for_scope(&scope)
            .expect("get request");
    let get = hartevo_aws_appconfig_deployment_result_plugin::GetDeploymentResponse::new(
        &get_request,
        metadata(&scope, AppConfigDeploymentState::Complete, None, None, None),
        512,
        TransportProvenance::Recording,
    )
    .expect("get");
    let mut drift_transport = RecordingTransport::default();
    drift_transport.push_list_response(Ok(list));
    drift_transport.push_get_response(Ok(get));
    let mut drift_service = recording_service(drift_transport);
    let drift = drift_service
        .propose(drift_service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(
        drift.failure.as_ref().expect("failure").category,
        "state_progress_drift"
    );
    assert_eq!(
        drift.state,
        hartevo_aws_appconfig_deployment_result_plugin::DeploymentEvidenceState::Partial
    );
}

#[test]
fn replay_conflict_and_revocation_are_fenced() {
    let scope = scope();
    let mut fixture_service =
        hartevo_aws_appconfig_deployment_result_plugin::AwsAppConfigDeploymentService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            AwsAppConfigProvider::new(FixtureTransport::for_scope(&scope, now())).expect("fixture"),
            now(),
        )
        .expect("service");
    let proposal = fixture_service
        .propose(fixture_service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer = fixture_service.consumer().expect("consumer");
    let first: RecordedAwsAppConfigResult =
        consumer.record(&proposal, "record-key").expect("record");
    let replay = consumer.record(&proposal, "record-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);

    let mut loopback_service = hartevo_aws_appconfig_deployment_result_plugin::AwsAppConfigDeploymentService::with_registration(
        scope.clone(),
        fixture_service.registration().clone(),
        AwsAppConfigProvider::new(LoopbackTransport::for_scope(&scope, now()))
            .expect("loopback"),
        now(),
    )
    .expect("loopback service");
    let other_proposal = loopback_service
        .propose(loopback_service.default_request(now()).expect("request"))
        .expect("other proposal");
    assert_eq!(
        consumer
            .record(&other_proposal, "record-key")
            .expect_err("replay conflict"),
        AwsAppConfigDeploymentError::RecordingConflict
    );

    fixture_service.revoke().expect("revoke");
    assert_eq!(
        fixture_service.registration().status(),
        RegistrationStatus::Revoked
    );
    assert_eq!(
        fixture_service
            .propose(fixture_service.default_request(now()).expect("request"))
            .expect_err("revoked registration"),
        AwsAppConfigDeploymentError::RegistrationRevoked
    );
    let mut revoked = consumer.registration().clone();
    revoked.revoke().expect("revoke clone");
    assert!(MissionAwsAppConfigConsumer::new(scope, revoked).is_err());
}

#[test]
fn blocked_env_is_explicitly_not_native() {
    let scope = scope();
    let mut service =
        hartevo_aws_appconfig_deployment_result_plugin::AwsAppConfigDeploymentService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            AwsAppConfigProvider::default(),
            now(),
        )
        .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
}

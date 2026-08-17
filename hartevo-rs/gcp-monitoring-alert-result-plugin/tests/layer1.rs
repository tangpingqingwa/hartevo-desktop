use std::collections::BTreeMap;

use hartevo_gcp_monitoring_alert_result_plugin::{
    AlertId, AlertPolicyId, AlertPolicyInput, AlertPolicyScope, AlertScope, AlertState,
    AlertStateFilter, BlockedEnvTransport, Digest, FixtureTransport, GcpMonitoringAlertScope,
    GcpMonitoringAlertService, GcpMonitoringProvider, GcpProjectScope, GoogleAuthKind,
    Layer1Authority, ListAlertPoliciesRequest, ListAlertPoliciesResponse, MetricsScope,
    MissionGcpMonitoringAlertConsumer, MissionId, MissionScope, OpaquePageToken,
    PermissionEvidence, PolicyConditionInput, ProjectId, ProjectScope, ProjectScopeId,
    ProviderProvenance, RecordingTransport, ResourceScope, ResultProjection, Revision,
    SecretReference, Severity, SeverityFilter, Timestamp, TransportError,
};

const RAW_METRIC_LABEL: &str = "raw-customer-label";
const RAW_RESOURCE_LABEL: &str = "raw-resource-label";
const RAW_LOG_LABEL: &str = "raw-log-label";
const RAW_FILTER: &str = "metric.type = \"custom.googleapis.com/raw-filter\"";

fn scope() -> GcpMonitoringAlertScope {
    let project = ProjectId::new("fixture-project").expect("project");
    let monitored = ProjectId::new("monitored-project").expect("monitored project");
    let metrics_scope =
        MetricsScope::new(project.clone(), [project.clone(), monitored]).expect("metrics scope");
    let policy = AlertPolicyId::new("policy-1").expect("policy");
    let alert = AlertId::new("alert-1").expect("alert");
    let policy_scope = AlertPolicyScope::new([policy], 4).expect("policy scope");
    let alert_scope = AlertScope::new([alert], AlertStateFilter::OpenOnly, SeverityFilter::Any, 4)
        .expect("alert scope");
    let resource_scope = ResourceScope::any(4).expect("resource scope");
    let mission = MissionScope::new(
        MissionId::new("mission-1").expect("mission"),
        Revision::new(7).expect("mission revision"),
    );
    let project_scope = ProjectScope::new(
        ProjectScopeId::new("hartevo-project-1").expect("Hartevo project"),
        Revision::new(11).expect("project revision"),
    );
    GcpMonitoringAlertScope::new(
        metrics_scope,
        GcpProjectScope::new(project),
        policy_scope,
        alert_scope,
        resource_scope,
        mission,
        project_scope,
        PermissionEvidence::default().permission_digest,
        Digest::from_text("consent-1"),
    )
    .expect("scope")
}

fn metric_condition() -> PolicyConditionInput {
    PolicyConditionInput::metric(
        RAW_FILTER,
        BTreeMap::from([("resource_name".to_owned(), RAW_RESOURCE_LABEL.to_owned())]),
        BTreeMap::from([("metric_name".to_owned(), RAW_METRIC_LABEL.to_owned())]),
    )
    .expect("metric condition")
}

fn policy_projection() -> hartevo_gcp_monitoring_alert_result_plugin::AlertPolicyProjection {
    AlertPolicyInput::new(
        AlertPolicyId::new("policy-1").expect("policy"),
        "raw-policy-display-name",
        Some(true),
        Severity::Warning,
        vec![metric_condition()],
        1,
    )
    .expect("policy input")
    .into_projection()
}

fn alert_projection() -> hartevo_gcp_monitoring_alert_result_plugin::AlertProjection {
    alert_projection_for("policy-1", "alert-1", AlertState::Open, None)
}

fn alert_projection_for(
    policy_id: &str,
    alert_id: &str,
    state: AlertState,
    close_time: Option<&str>,
) -> hartevo_gcp_monitoring_alert_result_plugin::AlertProjection {
    hartevo_gcp_monitoring_alert_result_plugin::AlertInput::new(
        AlertId::new(alert_id).expect("alert"),
        state,
        Timestamp::new("2026-01-01T00:00:00Z").expect("timestamp"),
        close_time.map(|value| Timestamp::new(value).expect("close timestamp")),
        AlertPolicyId::new(policy_id).expect("policy"),
        "raw-policy-display-name",
        Severity::Warning,
        Some((
            hartevo_gcp_monitoring_alert_result_plugin::ResourceType::new("gce_instance")
                .expect("resource type"),
            BTreeMap::from([("instance_id".to_owned(), RAW_RESOURCE_LABEL.to_owned())]),
        )),
        Some((
            hartevo_gcp_monitoring_alert_result_plugin::MetricType::new(
                "custom.googleapis.com/raw-filter",
            )
            .expect("metric type"),
            BTreeMap::from([("metric_name".to_owned(), RAW_METRIC_LABEL.to_owned())]),
        )),
        BTreeMap::from([("log_name".to_owned(), RAW_LOG_LABEL.to_owned())]),
    )
    .expect("alert input")
    .into_projection()
    .expect("alert projection")
}

fn fixture_service() -> GcpMonitoringAlertService<GcpMonitoringProvider<FixtureTransport>> {
    let scope = scope();
    let secret = SecretReference::new("opaque-google-secret", &scope, 3, GoogleAuthKind::OAuth)
        .expect("secret");
    let transport = FixtureTransport::for_scope(&scope).expect("fixture transport");
    let provider = GcpMonitoringProvider::new(transport, "1.0.0", ProviderProvenance::Fixture)
        .expect("provider");
    GcpMonitoringAlertService::new(scope, secret, provider).expect("service")
}

#[test]
fn fixture_complete_flow_is_bounded_redacted_and_non_native() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request())
        .expect("proposal");
    assert_eq!(proposal.projection, ResultProjection::Complete);
    assert_eq!(proposal.evidence.policies_listed.len(), 1);
    assert_eq!(proposal.evidence.policies_read_back.len(), 1);
    assert_eq!(proposal.evidence.alerts_listed.len(), 1);
    assert_eq!(proposal.evidence.alerts_read_back.len(), 1);
    assert!(proposal.evidence.redaction_complete);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.causal_incident_claim);
    assert!(proposal.validate_integrity().is_ok());
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        "fixture-instance",
        "fixture-log",
        "opaque-google-secret",
        RAW_FILTER,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked in JSON: {raw}");
    }
    assert!(!format!("{:?}", service.secret_reference()).contains("opaque-google-secret"));

    let mut consumer =
        MissionGcpMonitoringAlertConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(
        result.disposition,
        hartevo_gcp_monitoring_alert_result_plugin::ProposalDisposition::PendingMissionDecision
    );
    assert!(result.validate_integrity().is_ok());
    let recorded = consumer.record(&proposal, "idempotency-1").expect("record");
    assert!(!recorded.replayed);
    assert!(recorded.validate_integrity().is_ok());
    let read_back = consumer.read_back("idempotency-1").expect("read back");
    assert_eq!(read_back.proposal_digest, proposal.proposal_digest);
    assert!(!read_back.connected);
    assert!(!read_back.native);
}

#[test]
fn blocked_environment_is_provider_unknown_and_never_native() {
    let scope = scope();
    let secret =
        SecretReference::service_account("opaque-service-account", &scope, 1).expect("secret");
    let provider =
        GcpMonitoringProvider::new(BlockedEnvTransport, "1.0.0", ProviderProvenance::BlockedEnv)
            .expect("provider");
    let mut service = GcpMonitoringAlertService::new(scope, secret, provider).expect("service");
    let proposal = service
        .propose(service.default_request())
        .expect("proposal");
    assert_eq!(proposal.projection, ResultProjection::ProviderUnknown);
    assert!(
        proposal
            .evidence
            .provider_errors
            .iter()
            .any(|error| error.blocked_env)
    );
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.outcome_adopted);
}

#[test]
fn repeated_opaque_page_token_is_rejected() {
    let scope = scope();
    let secret = SecretReference::oauth("opaque-oauth", &scope, 1).expect("secret");
    let request = ListAlertPoliciesRequest::for_scope(&scope, &secret, 4, None).expect("request");
    let token = OpaquePageToken::new("opaque-next-page").expect("token");
    let first = ListAlertPoliciesResponse::new(
        &request,
        vec![policy_projection()],
        Some(token.clone()),
        2,
        512,
        ProviderProvenance::Recording,
    )
    .expect("first response");
    let next_request = ListAlertPoliciesRequest::for_scope(&scope, &secret, 4, Some(token.clone()))
        .expect("next request");
    let second = ListAlertPoliciesResponse::new(
        &next_request,
        vec![policy_projection()],
        Some(token),
        2,
        512,
        ProviderProvenance::Recording,
    )
    .expect("second response");
    let mut transport = RecordingTransport::default();
    transport.push_list_alert_policies(Ok(first));
    transport.push_list_alert_policies(Ok(second));
    let provider = GcpMonitoringProvider::new(transport, "1.0.0", ProviderProvenance::Recording)
        .expect("provider");
    let mut service = GcpMonitoringAlertService::new(scope, secret, provider).expect("service");
    let error = service
        .propose(
            hartevo_gcp_monitoring_alert_result_plugin::ProposalRequest::list_only(
                hartevo_gcp_monitoring_alert_result_plugin::BoundedReadLimits::new(
                    4, 4, 4, 4, 1_024,
                )
                .expect("limits"),
            ),
        )
        .expect_err("page loop");
    assert_eq!(
        error,
        hartevo_gcp_monitoring_alert_result_plugin::GcpMonitoringAlertServiceError::PaginationLoop
    );
}

#[test]
fn stale_mission_and_tamper_are_rejected_and_registration_is_reversible() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request())
        .expect("proposal");
    let mut consumer =
        MissionGcpMonitoringAlertConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");

    let mut stale = proposal.clone();
    stale.mission_revision = Revision::new(99).expect("revision");
    assert!(matches!(
        consumer.consume(stale),
        Err(hartevo_gcp_monitoring_alert_result_plugin::consumer::ConsumerError::FenceMismatch)
    ));

    let mut tampered = proposal.clone();
    tampered.evidence.redaction_complete = false;
    assert!(tampered.validate_integrity().is_err());

    let transition = service.reverse_registration().expect("reverse");
    assert_eq!(
        transition.to,
        hartevo_gcp_monitoring_alert_result_plugin::RegistrationStatus::Reversed
    );
    assert!(service.propose(service.default_request()).is_err());
    let restored = service.restore_registration().expect("restore");
    assert_eq!(
        restored.to,
        hartevo_gcp_monitoring_alert_result_plugin::RegistrationStatus::Active
    );
    assert!(service.propose(service.default_request()).is_ok());
    consumer.revoke().expect("consumer revoke");
    assert!(consumer.consume(&proposal).is_err());
}

#[test]
fn transport_statuses_map_to_non_adoptable_projections() {
    for (error, expected) in [
        (TransportError::unauthorized(), ResultProjection::AccessLost),
        (TransportError::forbidden(), ResultProjection::AccessLost),
        (
            TransportError::not_found(),
            ResultProjection::ProviderUnknown,
        ),
        (TransportError::conflict(), ResultProjection::FinalError),
        (
            TransportError::rate_limited(),
            ResultProjection::ProviderUnknown,
        ),
        (
            TransportError::server_failure(),
            ResultProjection::ProviderUnknown,
        ),
        (TransportError::timeout(), ResultProjection::ProviderUnknown),
    ] {
        let scope = scope();
        let secret = SecretReference::oauth("opaque-status-test", &scope, 1).expect("secret");
        let request =
            ListAlertPoliciesRequest::for_scope(&scope, &secret, 4, None).expect("request");
        let mut transport = RecordingTransport::default();
        transport.push_list_alert_policies(Err(error));
        let provider =
            GcpMonitoringProvider::new(transport, "1.0.0", ProviderProvenance::Recording)
                .expect("provider");
        let mut service = GcpMonitoringAlertService::new(scope, secret, provider).expect("service");
        let proposal = service
            .propose(service.default_request())
            .expect("proposal");
        assert_eq!(proposal.projection, expected);
        assert!(!proposal.can_be_adopted());
        assert_eq!(request.page_token_digest(), None);
    }
}

#[test]
fn raw_label_projection_is_digest_only() {
    let policy = policy_projection();
    let alert = alert_projection();
    let policy_json = serde_json::to_string(&policy).expect("policy JSON");
    let alert_json = serde_json::to_string(&alert).expect("alert JSON");
    for raw in [
        RAW_METRIC_LABEL,
        RAW_RESOURCE_LABEL,
        RAW_LOG_LABEL,
        RAW_FILTER,
    ] {
        assert!(!policy_json.contains(raw), "raw policy value leaked: {raw}");
        assert!(!alert_json.contains(raw), "raw alert value leaked: {raw}");
    }
    assert_eq!(alert.state, AlertState::Open);
    assert_eq!(alert.severity, Severity::Warning);
}

#[test]
fn policy_alert_mismatch_is_rejected_before_proposal() {
    let scope = scope();
    let secret = SecretReference::oauth("opaque-mismatch-test", &scope, 1).expect("secret");
    let policy_request =
        ListAlertPoliciesRequest::for_scope(&scope, &secret, 4, None).expect("policy request");
    let alert_request = hartevo_gcp_monitoring_alert_result_plugin::ListAlertsRequest::for_scope(
        &scope, &secret, 4, None,
    )
    .expect("alert request");
    let policy_response = ListAlertPoliciesResponse::new(
        &policy_request,
        vec![policy_projection()],
        None,
        1,
        512,
        ProviderProvenance::Recording,
    )
    .expect("policy response");
    let alert_response = hartevo_gcp_monitoring_alert_result_plugin::ListAlertsResponse::new(
        &alert_request,
        vec![alert_projection_for(
            "policy-2",
            "alert-1",
            AlertState::Open,
            None,
        )],
        None,
        1,
        512,
        ProviderProvenance::Recording,
    )
    .expect("alert response");
    let mut transport = RecordingTransport::default();
    transport.push_list_alert_policies(Ok(policy_response));
    transport.push_list_alerts(Ok(alert_response));
    let provider = GcpMonitoringProvider::new(transport, "1.0.0", ProviderProvenance::Recording)
        .expect("provider");
    let mut service = GcpMonitoringAlertService::new(scope, secret, provider).expect("service");
    let error = service
        .propose(
            hartevo_gcp_monitoring_alert_result_plugin::ProposalRequest::list_only(
                hartevo_gcp_monitoring_alert_result_plugin::BoundedReadLimits::new(
                    2, 4, 4, 4, 1_024,
                )
                .expect("limits"),
            ),
        )
        .expect_err("policy/alert mismatch");
    assert_eq!(
        error,
        hartevo_gcp_monitoring_alert_result_plugin::GcpMonitoringAlertServiceError::OutOfScope
    );
}

#[test]
fn open_closed_and_unspecified_alert_states_are_typed() {
    let closed = alert_projection_for(
        "policy-1",
        "alert-1",
        AlertState::Closed,
        Some("2026-01-01T01:00:00Z"),
    );
    let unspecified = alert_projection_for("policy-1", "alert-1", AlertState::Unspecified, None);
    assert_eq!(alert_projection().state, AlertState::Open);
    assert_eq!(closed.state, AlertState::Closed);
    assert_eq!(unspecified.state, AlertState::Unspecified);
    assert_eq!(
        serde_json::to_string(&AlertState::Unspecified).expect("state JSON"),
        "\"STATE_UNSPECIFIED\""
    );
    assert_eq!(
        serde_json::to_string(&Severity::Unspecified).expect("severity JSON"),
        "\"SEVERITY_UNSPECIFIED\""
    );
}

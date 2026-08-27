use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::{Value, json};

use hartevo_digitalocean_app_deployment_result_plugin::{
    AccountId, AppId, BlockedEnvTransport, ComponentSelector, ConsentScope, DeploymentId,
    DigitalOceanAppDeploymentResultContract, DigitalOceanAppDeploymentResultService,
    DigitalOceanAppsProvider, DigitalOceanAppsResponse, DigitalOceanAppsTransport,
    DigitalOceanEvidenceState, FixtureTransport, Identity,
    MissionDigitalOceanAppDeploymentConsumer, RecordingTransport, Region, SecretReference,
    SourceRevision, TeamId, TransportProvenance, WorkProductIdentity, contract_digest_value,
};

fn observed_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 1, 0, 0)
        .single()
        .expect("test timestamp is valid")
}

fn scope() -> hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentScope {
    hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentScope::new(
        AccountId::new("account-855").expect("account id"),
        TeamId::new("team-855").expect("team id"),
        AppId::new("app-855").expect("app id"),
        DeploymentId::new("deployment-855").expect("deployment id"),
        Region::new("nyc3").expect("region"),
        vec![ComponentSelector::new("web", "service").expect("component")],
        SourceRevision::new("source-revision-855").expect("source revision"),
        Identity::new("project-855", 1).expect("project"),
        Identity::new("mission-855", 7).expect("mission"),
        WorkProductIdentity::new("work-product-855", 2).expect("work product"),
    )
    .expect("scope")
}

fn service_for<T: DigitalOceanAppsTransport>(
    scope: hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentScope,
    provider: DigitalOceanAppsProvider<T>,
    at: DateTime<Utc>,
) -> DigitalOceanAppDeploymentResultService<T> {
    let secret = SecretReference::oauth("opaque-oauth-reference-855", &scope, 1)
        .expect("opaque secret reference");
    let consent =
        ConsentScope::for_layer_one("consent-855", 1, at + Duration::days(1)).expect("consent");
    DigitalOceanAppDeploymentResultService::new(scope, secret, consent, provider, at)
        .expect("service")
}

fn fixture_service(
    provenance: TransportProvenance,
) -> DigitalOceanAppDeploymentResultService<FixtureTransport> {
    let at = observed_at();
    let scope = scope();
    let transport = FixtureTransport::for_scope_with_provenance(&scope, at, provenance);
    let provider = DigitalOceanAppsProvider::new(transport).expect("fixture provider");
    service_for(scope, provider, at)
}

fn app_value(
    scope: &hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentScope,
    region: &str,
) -> Value {
    json!({
        "app": {
            "id": scope.app().as_str(),
            "account_id": scope.account().as_str(),
            "team_id": scope.team().as_str(),
            "region": region,
            "active_deployment": {"id": scope.deployment().as_str()}
        }
    })
}

fn deployment_value(
    scope: &hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentScope,
    phase: &str,
    source_digest: &str,
    component_name: &str,
) -> Value {
    json!({
        "deployment": {
            "id": scope.deployment().as_str(),
            "phase": phase,
            "cause": "private cause text is digest-only",
            "created_at": observed_at().to_rfc3339(),
            "updated_at": observed_at().to_rfc3339(),
            "phase_last_updated_at": observed_at().to_rfc3339(),
            "source_revision_digest": source_digest,
            "superseded_by": "deployment-856",
            "components": [{
                "name": component_name,
                "component_type": "service",
                "status": "READY",
                "replicas_desired": 2,
                "replicas_ready": 2,
                "source_revision_digest": source_digest
            }]
        }
    })
}

fn recording_service_for_scope(
    scope: hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentScope,
    app_response: DigitalOceanAppsResponse,
) -> DigitalOceanAppDeploymentResultService<RecordingTransport> {
    let at = observed_at();
    let mut transport = RecordingTransport::default();
    transport.push_app_response(Ok(app_response));
    let provider = DigitalOceanAppsProvider::new(transport).expect("recording provider");
    service_for(scope, provider, at)
}

fn assert_non_native(connected: bool, native: bool, first_party: bool) {
    assert!(!connected);
    assert!(!native);
    assert!(!first_party);
}

#[test]
fn contract_secret_and_response_surfaces_are_redacted() {
    let contract = DigitalOceanAppDeploymentResultContract::baseline().expect("contract");
    contract.validate().expect("contract validates");
    assert_eq!(contract.digest(), contract_digest_value());

    let scope = scope();
    let secret = SecretReference::oauth("opaque-oauth-reference-855", &scope, 1).expect("secret");
    let secret_json = serde_json::to_string(&secret).expect("secret serialization");
    assert!(!secret_json.contains("opaque-oauth-reference-855"));
    assert!(!format!("{secret:?}").contains("opaque-oauth-reference-855"));

    let scope_json = serde_json::to_string(&scope).expect("scope serialization");
    assert!(!scope_json.contains("account-855"));
    assert!(!scope_json.contains("deployment-855"));

    let response = DigitalOceanAppsResponse::new(
        200,
        br#"{"spec":{"envs":[{"value":"private-secret"}]}}"#.to_vec(),
        TransportProvenance::Fixture,
    );
    assert!(!format!("{response:?}").contains("private-secret"));
}

#[test]
fn fixture_proposes_bounded_active_evidence_and_records_replay() {
    let mut service = fixture_service(TransportProvenance::Fixture);
    let request = service.default_request(observed_at()).expect("request");
    assert_eq!(request.scope_digest, service.scope().digest());
    let proposal = service.propose(request).expect("proposal");

    assert_eq!(proposal.state, DigitalOceanEvidenceState::Active);
    assert_eq!(
        proposal.phase,
        Some(hartevo_digitalocean_app_deployment_result_plugin::DeploymentPhase::Active)
    );
    assert_eq!(proposal.deployment_pages, 1);
    assert_eq!(proposal.event_pages, 1);
    assert!(proposal.list_complete);
    assert!(proposal.events_complete);
    assert_eq!(proposal.request_receipts.len(), 5);
    assert_eq!(proposal.cost_receipts.len(), 5);
    assert_eq!(proposal.events.len(), 1);
    assert!(proposal.failure.is_none());
    assert_non_native(proposal.connected, proposal.native, proposal.first_party);
    assert!(!proposal.provider_receipt);
    proposal.validate_integrity().expect("proposal integrity");

    let payload = serde_json::to_string(&proposal).expect("proposal serialization");
    assert!(!payload.contains("private-app"));
    assert!(!payload.contains("fixture-secret"));
    assert!(!payload.contains("private.example.com"));
    assert!(!payload.contains("https://github.com/private/repo"));

    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);

    let mut consumer: MissionDigitalOceanAppDeploymentConsumer =
        service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("mission result");
    assert!(!mission_result.can_be_adopted());
    assert_non_native(
        mission_result.connected,
        mission_result.native,
        mission_result.first_party,
    );

    let first_record = consumer
        .record(&proposal, "mission-recording-key-855")
        .expect("recording");
    first_record.validate_integrity().expect("record integrity");
    assert!(!first_record.replayed);
    let replay = consumer
        .record(&proposal, "mission-recording-key-855")
        .expect("replay");
    assert!(replay.replayed);
    replay.validate_integrity().expect("replay integrity");
    assert_eq!(consumer.record_count(), 1);

    let later_request = service
        .default_request(observed_at() + Duration::seconds(1))
        .expect("later request");
    let later_proposal = service.propose(later_request).expect("later proposal");
    assert_ne!(proposal.proposal_digest, later_proposal.proposal_digest);
    assert_eq!(
        consumer
            .record(&later_proposal, "mission-recording-key-855")
            .expect_err("replay conflict"),
        hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentResultError::ReplayConflict
    );
    assert_eq!(
        consumer
            .consume_with_mission_revision(&proposal, 8)
            .expect_err("stale mission"),
        hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentResultError::StaleMission
    );
}

#[test]
fn fixture_loopback_and_blocked_env_are_never_native_or_connected() {
    for provenance in [TransportProvenance::Fixture, TransportProvenance::Loopback] {
        let mut service = fixture_service(provenance);
        let proposal = service
            .propose(service.default_request(observed_at()).expect("request"))
            .expect("proposal");
        assert_eq!(proposal.provenance, provenance);
        assert_non_native(proposal.connected, proposal.native, proposal.first_party);
    }

    let at = observed_at();
    let scope = scope();
    let provider = DigitalOceanAppsProvider::new(BlockedEnvTransport).expect("blocked provider");
    let mut service = service_for(scope, provider, at);
    let proposal = service
        .propose(service.default_request(at).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, DigitalOceanEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert_non_native(proposal.connected, proposal.native, proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn http_status_and_tampered_response_fail_closed() {
    let scope_for_status = scope();
    let status_response = DigitalOceanAppsResponse::json(
        401,
        &json!({"error": "unauthorized"}),
        TransportProvenance::Recording,
    );
    let mut status_service = recording_service_for_scope(scope_for_status, status_response);
    let status_proposal = status_service
        .propose(
            status_service
                .default_request(observed_at())
                .expect("request"),
        )
        .expect("status proposal");
    assert_eq!(status_proposal.state, DigitalOceanEvidenceState::AccessLost);
    let status_failure = status_proposal.failure.as_ref().expect("status failure");
    assert_eq!(status_failure.category, "unauthorized");
    assert_eq!(status_failure.status_code, Some(401));
    status_proposal
        .validate_integrity()
        .expect("status proposal integrity");

    let scope_for_tamper = scope();
    let tampered_response = DigitalOceanAppsResponse::json(
        200,
        &app_value(&scope_for_tamper, scope_for_tamper.region().as_str()),
        TransportProvenance::Recording,
    )
    .with_declared_digest(heartevo_digest("tampered-response"));
    let mut tampered_service = recording_service_for_scope(scope_for_tamper, tampered_response);
    let tampered_proposal = tampered_service
        .propose(
            tampered_service
                .default_request(observed_at())
                .expect("request"),
        )
        .expect("tampered proposal");
    assert_eq!(tampered_proposal.state, DigitalOceanEvidenceState::Tampered);
    assert_eq!(
        tampered_proposal
            .failure
            .as_ref()
            .expect("tamper failure")
            .category,
        "tampered"
    );
    tampered_proposal
        .validate_integrity()
        .expect("tampered proposal integrity");
}

fn heartevo_digest(value: &str) -> hartevo_digitalocean_app_deployment_result_plugin::Digest {
    hartevo_digitalocean_app_deployment_result_plugin::Digest::from_text(value)
}

#[test]
fn app_replacement_is_explicitly_superseded_and_not_review_eligible() {
    let scope = scope();
    let replacement_app = json!({
        "app": {
            "id": scope.app().as_str(),
            "account_id": scope.account().as_str(),
            "team_id": scope.team().as_str(),
            "region": scope.region().as_str(),
            "active_deployment": {"id": "deployment-856"}
        }
    });
    let mut service = recording_service_for_scope(
        scope,
        DigitalOceanAppsResponse::json(200, &replacement_app, TransportProvenance::Recording),
    );
    let proposal = service
        .propose(service.default_request(observed_at()).expect("request"))
        .expect("replacement proposal");
    assert_eq!(proposal.state, DigitalOceanEvidenceState::Superseded);
    assert!(proposal.app.is_some());
    assert!(proposal.deployment.is_none());
    assert_non_native(proposal.connected, proposal.native, proposal.first_party);
    proposal
        .validate_integrity()
        .expect("replacement integrity");
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn pagination_source_component_and_lifecycle_drift_are_partial() {
    let pagination_scope = scope();
    let mut pagination_service = recording_service_for_scope(
        pagination_scope.clone(),
        DigitalOceanAppsResponse::json(
            200,
            &app_value(&pagination_scope, pagination_scope.region().as_str()),
            TransportProvenance::Recording,
        ),
    );
    let empty_page = json!({"deployments": [], "next_page": 2});
    pagination_service
        .provider_mut()
        .transport_mut()
        .push_deployments_response(Ok(DigitalOceanAppsResponse::json(
            200,
            &empty_page,
            TransportProvenance::Recording,
        )));
    pagination_service
        .provider_mut()
        .transport_mut()
        .push_deployments_response(Ok(DigitalOceanAppsResponse::json(
            200,
            &empty_page,
            TransportProvenance::Recording,
        )));
    let pagination_proposal = pagination_service
        .propose(
            pagination_service
                .default_request(observed_at())
                .expect("request"),
        )
        .expect("pagination proposal");
    assert_eq!(
        pagination_proposal.state,
        DigitalOceanEvidenceState::Partial
    );
    assert_eq!(
        pagination_proposal
            .failure
            .as_ref()
            .expect("pagination failure")
            .category,
        "pagination_loop"
    );
    assert_eq!(pagination_proposal.deployment_pages, 2);

    let source_scope = scope();
    let expected_source = source_scope.source_revision().digest().as_str().to_owned();
    let wrong_source = heartevo_digest("wrong-source").as_str().to_owned();
    let mut source_service = recording_service_for_scope(
        source_scope.clone(),
        DigitalOceanAppsResponse::json(
            200,
            &app_value(&source_scope, source_scope.region().as_str()),
            TransportProvenance::Recording,
        ),
    );
    source_service
        .provider_mut()
        .transport_mut()
        .push_deployments_response(Ok(DigitalOceanAppsResponse::json(
            200,
            &json!({
                "deployments": [{
                    "id": source_scope.deployment().as_str(),
                    "phase": "ACTIVE",
                    "source_revision_digest": expected_source
                }]
            }),
            TransportProvenance::Recording,
        )));
    source_service
        .provider_mut()
        .transport_mut()
        .push_deployment_response(Ok(DigitalOceanAppsResponse::json(
            200,
            &deployment_value(&source_scope, "ACTIVE", &wrong_source, "web"),
            TransportProvenance::Recording,
        )));
    let source_proposal = source_service
        .propose(
            source_service
                .default_request(observed_at())
                .expect("request"),
        )
        .expect("source proposal");
    assert_eq!(source_proposal.state, DigitalOceanEvidenceState::Partial);
    assert_eq!(
        source_proposal
            .failure
            .as_ref()
            .expect("source failure")
            .category,
        "source_revision_drift"
    );

    let component_scope = scope();
    let component_source = component_scope
        .source_revision()
        .digest()
        .as_str()
        .to_owned();
    let mut component_service = recording_service_for_scope(
        component_scope.clone(),
        DigitalOceanAppsResponse::json(
            200,
            &app_value(&component_scope, component_scope.region().as_str()),
            TransportProvenance::Recording,
        ),
    );
    component_service
        .provider_mut()
        .transport_mut()
        .push_deployments_response(Ok(DigitalOceanAppsResponse::json(
            200,
            &json!({
                "deployments": [{
                    "id": component_scope.deployment().as_str(),
                    "phase": "ACTIVE",
                    "source_revision_digest": component_source
                }]
            }),
            TransportProvenance::Recording,
        )));
    component_service
        .provider_mut()
        .transport_mut()
        .push_deployment_response(Ok(DigitalOceanAppsResponse::json(
            200,
            &deployment_value(
                &component_scope,
                "ACTIVE",
                component_scope.source_revision().digest().as_str(),
                "unexpected-component",
            ),
            TransportProvenance::Recording,
        )));
    let component_proposal = component_service
        .propose(
            component_service
                .default_request(observed_at())
                .expect("request"),
        )
        .expect("component proposal");
    assert_eq!(component_proposal.state, DigitalOceanEvidenceState::Partial);
    assert_eq!(
        component_proposal
            .failure
            .as_ref()
            .expect("component failure")
            .category,
        "component_drift"
    );

    let lifecycle_scope = scope();
    let lifecycle_source = lifecycle_scope
        .source_revision()
        .digest()
        .as_str()
        .to_owned();
    let mut lifecycle_service = recording_service_for_scope(
        lifecycle_scope.clone(),
        DigitalOceanAppsResponse::json(
            200,
            &app_value(&lifecycle_scope, lifecycle_scope.region().as_str()),
            TransportProvenance::Recording,
        ),
    );
    lifecycle_service
        .provider_mut()
        .transport_mut()
        .push_deployments_response(Ok(DigitalOceanAppsResponse::json(
            200,
            &json!({
                "deployments": [{
                    "id": lifecycle_scope.deployment().as_str(),
                    "phase": "ACTIVE",
                    "source_revision_digest": lifecycle_source
                }]
            }),
            TransportProvenance::Recording,
        )));
    lifecycle_service
        .provider_mut()
        .transport_mut()
        .push_deployment_response(Ok(DigitalOceanAppsResponse::json(
            200,
            &deployment_value(
                &lifecycle_scope,
                "BUILDING",
                lifecycle_scope.source_revision().digest().as_str(),
                "web",
            ),
            TransportProvenance::Recording,
        )));
    let lifecycle_proposal = lifecycle_service
        .propose(
            lifecycle_service
                .default_request(observed_at())
                .expect("request"),
        )
        .expect("lifecycle proposal");
    assert_eq!(lifecycle_proposal.state, DigitalOceanEvidenceState::Partial);
    assert_eq!(
        lifecycle_proposal
            .failure
            .as_ref()
            .expect("lifecycle failure")
            .category,
        "lifecycle_regression"
    );
}

#[test]
fn registration_is_reversible_and_revocable() {
    let mut service = fixture_service(TransportProvenance::Fixture);
    assert!(service.registration().is_active());
    assert!(service.is_active());
    assert!(service.register().expect("register").is_active());
    assert!(
        hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentRegistration::is_reversible()
    );

    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(
        revoked.status,
        hartevo_digitalocean_app_deployment_result_plugin::RegistrationStatus::Revoked
    );
    assert!(!service.registration().is_active());
    let revoked_proposal = service
        .propose(service.default_request(observed_at()).expect("request"))
        .expect("revoked proposal");
    assert_eq!(revoked_proposal.state, DigitalOceanEvidenceState::Revoked);
    assert!(!service.verify(&revoked_proposal).review_eligible);

    let restored = service.restore_registration().expect("restore");
    assert_eq!(
        restored.status,
        hartevo_digitalocean_app_deployment_result_plugin::RegistrationStatus::Active
    );
    let proposal = service
        .propose(service.default_request(observed_at()).expect("request"))
        .expect("restored proposal");
    assert_eq!(proposal.state, DigitalOceanEvidenceState::Active);

    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(
        reversed.status,
        hartevo_digitalocean_app_deployment_result_plugin::RegistrationStatus::Reversed
    );
    assert!(matches!(
        service.restore_registration(),
        Err(hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentResultError::RegistrationReversed)
    ));
}

#[test]
fn mission_consumer_rejects_tampered_and_stale_proposals() {
    let mut service = fixture_service(TransportProvenance::Loopback);
    let proposal = service
        .propose(service.default_request(observed_at()).expect("request"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.connected = true;
    assert_eq!(
        tampered.validate_integrity().expect_err("tamper"),
        hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentResultError::TamperedEvidence
    );

    let consumer = service.consumer().expect("consumer");
    assert!(matches!(
        consumer.consume_with_mission_revision(&proposal, service.scope().mission().revision() + 1),
        Err(hartevo_digitalocean_app_deployment_result_plugin::DigitalOceanAppDeploymentResultError::StaleMission)
    ));
}

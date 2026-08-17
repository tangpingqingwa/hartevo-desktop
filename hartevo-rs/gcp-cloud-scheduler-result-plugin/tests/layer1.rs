use hartevo_gcp_cloud_scheduler_result_plugin as scheduler;
use serde_json::{Value, json};

const GCP_PROJECT: &str = "gcp-project-1";
const LOCATION: &str = "us-central1";
const SCHEDULE: &str = "*/5 * * * *";

fn target_value() -> Value {
    json!({
        "uri": "https://example.invalid/private-target",
        "httpMethod": "POST",
        "headers": {"Authorization": "raw-header-must-not-escape"},
        "body": "raw-body-must-not-escape",
        "oauthToken": {"serviceAccountEmail": "private@example.invalid"}
    })
}

fn scope(job: scheduler::JobSelector) -> scheduler::GcpCloudSchedulerScope {
    let target_digest = scheduler::Digest::from_serializable(&target_value());
    scheduler::GcpCloudSchedulerScope::read_only(
        scheduler::ProjectBinding::new("hartevo-project", 2).expect("project"),
        scheduler::MissionBinding::new("mission-1", 3).expect("mission"),
        scheduler::WorkProductBinding::new("work-product-1", 4).expect("work product"),
        GCP_PROJECT,
        LOCATION,
        job,
        scheduler::ScheduleSelector::exact(SCHEDULE),
        scheduler::TargetSelector::exact_digest(Some(scheduler::TargetKind::Http), target_digest)
            .expect("target selector"),
        scheduler::ConsentScope::new("mission-consent-1", 5).expect("consent"),
    )
    .expect("scope")
}

fn response_job(id: &str, state: &str, schedule: &str) -> Value {
    json!({
        "name": format!("projects/{GCP_PROJECT}/locations/{LOCATION}/jobs/{id}"),
        "schedule": schedule,
        "state": state,
        "revision": 7,
        "lastAttemptStatus": {"code": 0, "message": "raw status detail"},
        "httpTarget": target_value(),
        "privateProviderField": "must-not-escape"
    })
}

fn list_response(id: &str, state: &str) -> scheduler::CloudSchedulerResponse {
    scheduler::CloudSchedulerResponse::json(
        200,
        &json!({"jobs": [response_job(id, state, SCHEDULE)]}),
    )
}

fn service_with_response(
    scope: scheduler::GcpCloudSchedulerScope,
    response: scheduler::CloudSchedulerResponse,
) -> scheduler::GcpCloudSchedulerResultService<scheduler::RecordingGcpCloudSchedulerTransport> {
    let secret =
        scheduler::SecretReference::oauth("keyring://raw-secret-handle-must-not-print", &scope, 7)
            .expect("opaque secret reference");
    let provider = scheduler::GcpCloudSchedulerProvider::new(
        scope,
        secret,
        scheduler::RecordingGcpCloudSchedulerTransport::new(response),
    )
    .expect("provider");
    scheduler::GcpCloudSchedulerResultService::new(provider).expect("service")
}

#[test]
fn contract_and_authority_are_exactly_layer_one() {
    scheduler::validate_contract().expect("contract invariants");
    let definition = scheduler::GcpCloudSchedulerResultServiceDefinition::new();
    definition.validate().expect("service definition");
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(!definition.native);
    assert!(!definition.connected);
    assert!(!definition.external_writes);
    assert!(!scheduler::Layer1Authority::connected());
    assert!(!scheduler::Layer1Authority::native_provider());
    assert!(!scheduler::Layer1Authority::credential_resolution());
    assert!(!scheduler::Layer1Authority::creates_jobs());
    assert!(!scheduler::Layer1Authority::deletes_jobs());
    assert!(!scheduler::Layer1Authority::patches_jobs());
    assert!(!scheduler::Layer1Authority::pauses_jobs());
    assert!(!scheduler::Layer1Authority::resumes_jobs());
    assert!(!scheduler::Layer1Authority::runs_jobs());
    assert!(!scheduler::Layer1Authority::invokes_targets());
    assert!(!scheduler::Layer1Authority::kernel_authority());
}

#[test]
fn bounded_list_is_typed_and_redacted() {
    let mut service = service_with_response(
        scope(scheduler::JobSelector::any()),
        list_response("job-1", "ENABLED"),
    );
    let evidence = service.read().expect("evidence");
    assert_eq!(evidence.state, scheduler::EvidenceState::Complete);
    assert_eq!(evidence.jobs.len(), 1);
    assert_eq!(
        evidence.jobs[0].state,
        scheduler::SchedulerJobState::Enabled
    );
    assert_eq!(evidence.jobs[0].resource_revision.get(), 7);
    assert!(evidence.verify_digest());
    assert_eq!(
        evidence.request_receipts[0].operation,
        scheduler::CloudSchedulerOperation::List
    );
    assert_eq!(
        evidence.request_receipts[0].path,
        "/v1/projects/gcp-project-1/locations/us-central1/jobs"
    );

    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!serialized.contains("raw-target-must-not-escape"));
    assert!(!serialized.contains("raw-header-must-not-escape"));
    assert!(!serialized.contains("raw-body-must-not-escape"));
    assert!(!serialized.contains("private@example.invalid"));
    assert!(!serialized.contains("privateProviderField"));
    let debug = format!("{:?}", service.secret_reference());
    assert!(!debug.contains("raw-secret-handle-must-not-print"));
    assert!(debug.contains("reference_digest"));
}

#[test]
fn exact_get_and_scope_fences_are_typed() {
    let mut service = service_with_response(
        scope(scheduler::JobSelector::exact("job-1")),
        scheduler::CloudSchedulerResponse::json(200, &response_job("job-1", "PAUSED", SCHEDULE)),
    );
    let evidence = service.read().expect("get evidence");
    assert_eq!(evidence.operation, scheduler::CloudSchedulerOperation::Get);
    assert_eq!(evidence.jobs[0].job_id.as_str(), "job-1");
    assert_eq!(evidence.jobs[0].state, scheduler::SchedulerJobState::Paused);
    assert_eq!(
        evidence.request_receipts[0].path,
        "/v1/projects/gcp-project-1/locations/us-central1/jobs/job-1"
    );

    let stale = service
        .read_at_mission_revision(99)
        .expect("stale evidence");
    assert_eq!(stale.state, scheduler::EvidenceState::Stale);
    assert!(stale.jobs.is_empty());
    assert!(stale.request_receipts.is_empty());
}

#[test]
fn pagination_is_opaque_and_loops_become_partial() {
    let first = scheduler::CloudSchedulerResponse::json(
        200,
        &json!({
            "jobs": [response_job("job-1", "ENABLED", SCHEDULE)],
            "nextPageToken": "raw-page-token-must-not-escape"
        }),
    );
    let second = scheduler::CloudSchedulerResponse::json(200, &json!({"jobs": []}));
    let base_scope = scope(scheduler::JobSelector::any());
    let secret =
        scheduler::SecretReference::service_account("opaque-service-account", &base_scope, 1)
            .expect("secret");
    let mut transport = scheduler::RecordingGcpCloudSchedulerTransport::empty();
    transport.push_list_response(first);
    transport.push_list_response(second);
    let provider =
        scheduler::GcpCloudSchedulerProvider::new(base_scope, secret, transport).expect("provider");
    let mut service = scheduler::GcpCloudSchedulerResultService::new(provider).expect("service");
    let evidence = service.read_list_jobs().expect("paged evidence");
    assert_eq!(evidence.state, scheduler::EvidenceState::Complete);
    assert_eq!(evidence.request_receipts.len(), 2);
    assert!(evidence.request_receipts[1].page_token_digest.is_some());
    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!serialized.contains("raw-page-token-must-not-escape"));

    let loop_response = scheduler::CloudSchedulerResponse::json(
        200,
        &json!({
            "jobs": [response_job("job-1", "ENABLED", SCHEDULE)],
            "nextPageToken": "same-token"
        }),
    );
    let mut loop_transport = scheduler::RecordingGcpCloudSchedulerTransport::empty();
    loop_transport.push_list_response(loop_response.clone());
    loop_transport.push_list_response(loop_response);
    let loop_scope = scope(scheduler::JobSelector::any());
    let loop_secret =
        scheduler::SecretReference::oauth("opaque-oauth", &loop_scope, 1).expect("secret");
    let loop_provider =
        scheduler::GcpCloudSchedulerProvider::new(loop_scope, loop_secret, loop_transport)
            .expect("provider");
    let mut loop_service =
        scheduler::GcpCloudSchedulerResultService::new(loop_provider).expect("service");
    assert_eq!(
        loop_service.read().expect("loop evidence").state,
        scheduler::EvidenceState::Partial
    );
}

#[test]
fn provider_errors_and_provenance_never_become_native() {
    for (status, expected) in [
        (401, scheduler::EvidenceState::AccessLost),
        (403, scheduler::EvidenceState::AccessLost),
        (404, scheduler::EvidenceState::NotFound),
        (409, scheduler::EvidenceState::Conflict),
        (429, scheduler::EvidenceState::RateLimited),
        (500, scheduler::EvidenceState::ProviderUnknown),
        (408, scheduler::EvidenceState::Timeout),
    ] {
        let mut service = service_with_response(
            scope(scheduler::JobSelector::any()),
            scheduler::CloudSchedulerResponse::new(
                status,
                br#"{"message":"raw provider diagnostic"}"#.to_vec(),
            ),
        );
        let evidence = service.read().expect("typed provider status");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.native && !evidence.connected && !evidence.first_party);
        assert!(
            !serde_json::to_string(&evidence)
                .expect("evidence JSON")
                .contains("raw provider diagnostic")
        );
    }

    let blocked_scope = scope(scheduler::JobSelector::any());
    let secret =
        scheduler::SecretReference::oauth("blocked-secret", &blocked_scope, 1).expect("secret");
    let provider = scheduler::GcpCloudSchedulerProvider::new(
        blocked_scope,
        secret,
        scheduler::BlockedEnvGcpCloudSchedulerTransport,
    )
    .expect("provider");
    assert_eq!(
        provider.provenance(),
        scheduler::TransportProvenance::BlockedEnv
    );
    assert!(!provider.is_native() && !provider.is_connected());
    let mut service = scheduler::GcpCloudSchedulerResultService::new(provider).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.state, scheduler::EvidenceState::AccessLost);
    assert!(!evidence.native && !evidence.connected);
}

#[test]
fn registration_and_consumer_replay_are_reversible_and_fail_closed() {
    let registration_scope = scope(scheduler::JobSelector::any());
    let secret =
        scheduler::SecretReference::oauth("opaque-oauth", &registration_scope, 1).expect("secret");
    let mut transport = scheduler::RecordingGcpCloudSchedulerTransport::empty();
    transport.push_list_response(list_response("job-1", "ENABLED"));
    transport.push_list_response(list_response("job-1", "ENABLED"));
    let provider = scheduler::GcpCloudSchedulerProvider::new(registration_scope, secret, transport)
        .expect("provider");
    let mut service = scheduler::GcpCloudSchedulerResultService::new(provider).expect("service");
    let proposal = service.propose_list_jobs().expect("proposal");
    let record = service.record_list_jobs().expect("record");
    let original = service.registration().registration_digest.clone();
    let receipt = service.revoke_registration().expect("revoke");
    assert_eq!(receipt.previous_registration_digest, original);
    assert_ne!(receipt.registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(scheduler::GcpCloudSchedulerResultServiceError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    assert_ne!(service.registration().registration_digest, original);
    assert!(matches!(
        service.verify_proposal(&proposal, &record),
        Err(scheduler::GcpCloudSchedulerResultServiceError::ProposalTampered)
    ));

    let consumer_scope = scope(scheduler::JobSelector::any());
    let secret =
        scheduler::SecretReference::oauth("consumer-secret", &consumer_scope, 1).expect("secret");
    let provider = scheduler::GcpCloudSchedulerProvider::new(
        consumer_scope,
        secret,
        scheduler::RecordingGcpCloudSchedulerTransport::new(list_response("job-1", "ENABLED")),
    )
    .expect("provider");
    let service = scheduler::GcpCloudSchedulerResultService::new(provider).expect("service");
    let mut consumer = scheduler::MissionGcpCloudSchedulerConsumer::new(service).expect("consumer");
    let evidence = consumer.read().expect("consumer read");
    let result = consumer.consume(evidence.clone()).expect("consume");
    assert_eq!(
        result.state,
        scheduler::MissionGcpCloudSchedulerState::EvidenceReady
    );
    assert!(!result.native && !result.connected && !result.first_party);
    assert!(!result.adopts_outcome && !result.work_product_adoption);
    assert!(matches!(
        consumer.consume(evidence),
        Err(scheduler::MissionGcpCloudSchedulerConsumerError::ReplayDetected)
    ));
}

#[test]
fn project_location_schedule_and_target_drift_fail_closed() {
    for (field, value) in [
        (
            "name",
            json!("projects/other-project/locations/us-central1/jobs/job-1"),
        ),
        ("schedule", json!("0 0 * * *")),
    ] {
        let mut job = response_job("job-1", "ENABLED", SCHEDULE);
        job[field] = value;
        let mut service = service_with_response(
            scope(scheduler::JobSelector::any()),
            scheduler::CloudSchedulerResponse::json(200, &json!({"jobs": [job]})),
        );
        assert_eq!(
            service.read().expect("drift evidence").state,
            scheduler::EvidenceState::Stale
        );
    }

    let mut job = response_job("job-1", "ENABLED", SCHEDULE);
    job["httpTarget"]["uri"] = json!("https://other.invalid/target");
    let mut service = service_with_response(
        scope(scheduler::JobSelector::any()),
        scheduler::CloudSchedulerResponse::json(200, &json!({"jobs": [job]})),
    );
    assert_eq!(
        service.read().expect("target drift evidence").state,
        scheduler::EvidenceState::Stale
    );
}

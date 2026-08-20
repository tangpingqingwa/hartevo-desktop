use chrono::{Duration, TimeZone, Utc};
use hartevo_gcp_dataflow_job_result_plugin as dataflow;
use serde_json::{Value, json};

const GCP_PROJECT: &str = "gcp-project-1";
const LOCATION: &str = "us-central1";
const RAW_SECRET: &str = "raw-oauth-or-service-account-material";
const NOW_SECONDS: i64 = 1_787_000_000;

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn consent() -> dataflow::ConsentScope {
    dataflow::ConsentScope::for_layer_one("consent-dataflow-1", 5, now() + Duration::days(7))
        .expect("consent")
}

fn scope(selector: dataflow::DataflowJobSelector) -> dataflow::GcpDataflowJobResultScope {
    dataflow::GcpDataflowJobResultScope::read_only(
        dataflow::ProjectBinding::new("project-1", 2).expect("project"),
        dataflow::MissionBinding::new("mission-1", 3).expect("mission"),
        dataflow::WorkProductBinding::new("work-product-1", 4).expect("work product"),
        GCP_PROJECT,
        LOCATION,
        selector,
        dataflow::DataflowPipelineType::Batch,
        ["stage-a"],
        ["metric-a", "metric-b"],
        7,
        consent(),
    )
    .expect("scope")
}

fn job_response(state: &str) -> Value {
    json!({
        "id": "job-1",
        "projectId": GCP_PROJECT,
        "location": LOCATION,
        "type": "JOB_TYPE_BATCH",
        "currentState": state,
        "createTime": "2026-08-15T00:00:00Z",
        "startTime": "2026-08-15T00:00:01Z",
        "currentStateTime": "2026-08-15T00:00:11Z",
        "name": "private-pipeline-name",
        "replaceJobId": "private-replaced-job",
        "steps": [
            {"name": "stage-a", "state": state, "metricCount": 2},
            {"name": "secret-stage-not-allowlisted", "state": state, "metricCount": 999}
        ],
        "pipelineOptions": {"serviceAccountEmail": "private@example.invalid"},
        "workerPools": [{"ipv4AccessConfig": "10.0.0.1"}],
        "privateError": "raw provider diagnostic that must not escape"
    })
}

fn get_response(state: &str) -> dataflow::DataflowResponse {
    dataflow::DataflowResponse::json(200, &job_response(state))
}

fn metrics_response() -> dataflow::DataflowResponse {
    dataflow::DataflowResponse::json(
        200,
        &json!({
            "metrics": [
                {
                    "name": "metric-a",
                    "scalar": {"integerValue": "12"},
                    "unit": "count",
                    "tentative": false,
                    "updateTime": "2026-08-15T00:00:12Z"
                },
                {"name": "metric-not-allowlisted", "scalar": {"integerValue": "999"}},
                {"name": "metric-b", "scalar": {"doubleValue": 1.5}}
            ]
        }),
    )
}

fn exact_service() -> dataflow::GcpDataflowJobResultService<dataflow::FixtureGcpDataflowTransport> {
    let scope = scope(dataflow::DataflowJobSelector::try_exact("job-1").expect("selector"));
    let secret = dataflow::SecretReference::for_scope(RAW_SECRET, 8, &scope).expect("secret");
    let transport = dataflow::FixtureGcpDataflowTransport::from_responses(
        None,
        Some(get_response("JOB_STATE_RUNNING")),
        Some(metrics_response()),
    );
    let provider = dataflow::GcpDataflowProvider::new(scope, secret, transport).expect("provider");
    dataflow::GcpDataflowJobResultService::new(provider).expect("service")
}

#[test]
fn contract_and_registration_are_exactly_layer_one() {
    dataflow::validate_contract().expect("contract invariants");
    let definition = dataflow::GcpDataflowJobResultServiceDefinition::new();
    definition.validate().expect("service definition");
    assert!(definition.read_only && definition.proposal_only);
    assert!(!definition.native && !definition.connected && !definition.external_writes);
    assert_eq!(dataflow::contract_digest().len(), 64);
    assert_eq!(dataflow::GCP_DATAFLOW_JOB_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
    assert!(!dataflow::Layer1Authority::connected());
    assert!(!dataflow::Layer1Authority::native_provider());
    assert!(!dataflow::Layer1Authority::first_party());
    assert!(!dataflow::Layer1Authority::creates_jobs());
    assert!(!dataflow::Layer1Authority::updates_jobs());
    assert!(!dataflow::Layer1Authority::cancels_jobs());
    assert!(!dataflow::Layer1Authority::drains_jobs());

    let exact_scope = scope(dataflow::DataflowJobSelector::try_exact("job-1").expect("selector"));
    let oauth = dataflow::SecretReference::oauth(
        RAW_SECRET,
        &exact_scope,
        dataflow::Revision::new(8).expect("revision"),
    )
    .expect("oauth secret reference");
    let service_account = dataflow::SecretReference::service_account(
        RAW_SECRET,
        &exact_scope,
        dataflow::Revision::new(8).expect("revision"),
    )
    .expect("service-account secret reference");
    assert_eq!(oauth.kind(), dataflow::SecretReferenceKind::OAuth);
    assert_eq!(
        service_account.kind(),
        dataflow::SecretReferenceKind::ServiceAccount
    );
    assert_ne!(oauth.reference_digest(), service_account.reference_digest());
    assert!(!format!("{oauth:?}").contains(RAW_SECRET));

    let service = exact_service();
    assert!(service.registration().verify_digest());
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
}

#[test]
fn exact_get_and_metrics_are_bounded_and_redacted() {
    let mut service = exact_service();
    let evidence = service.read().expect("exact evidence");
    assert_eq!(evidence.state, dataflow::EvidenceState::Complete);
    assert_eq!(evidence.jobs.len(), 1);
    assert_eq!(evidence.jobs[0].state, dataflow::DataflowJobState::Running);
    assert_eq!(evidence.jobs[0].stages.len(), 1);
    assert_eq!(evidence.metrics.len(), 2);
    assert!(
        evidence
            .metrics
            .iter()
            .any(|metric| metric.integer_value == Some(12))
    );
    assert!(evidence.verify_digest());
    assert!(!evidence.native && !evidence.connected && !evidence.first_party);
    assert!(!evidence.provider_receipt && !evidence.can_be_adopted());
    assert_eq!(evidence.request_receipts.len(), 2);
    assert_eq!(
        evidence.request_receipts[0].path_digest.len(),
        64,
        "request path is digest-bound"
    );

    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    for raw in [
        RAW_SECRET,
        "private-pipeline-name",
        "private@example.invalid",
        "10.0.0.1",
        "raw provider diagnostic",
        "metric-not-allowlisted",
        "secret-stage-not-allowlisted",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
}

#[test]
fn list_pagination_is_opaque_and_order_independent() {
    let list = dataflow::DataflowResponse::json(
        200,
        &json!({"jobs": [job_response("JOB_STATE_QUEUED")], "nextPageToken": "raw-page-token"}),
    );
    let second = dataflow::DataflowResponse::json(200, &json!({"jobs": []}));
    let scope = scope(dataflow::DataflowJobSelector::any());
    let secret = dataflow::SecretReference::for_scope(RAW_SECRET, 8, &scope).expect("secret");
    let mut transport = dataflow::RecordingGcpDataflowTransport::empty();
    transport.push_list_response(list);
    transport.push_list_response(second);
    let provider = dataflow::GcpDataflowProvider::new(scope, secret, transport).expect("provider");
    let mut service = dataflow::GcpDataflowJobResultService::new(provider).expect("service");
    let evidence = service.read().expect("list evidence");
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.jobs.len(), 1);
    assert!(evidence.request_receipts[1].page_token_digest.is_some());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence JSON")
            .contains("raw-page-token")
    );
    assert_eq!(evidence.jobs[0].digest().len(), 64);
}

#[test]
fn provider_status_and_missing_metrics_fail_closed() {
    let scope = scope(dataflow::DataflowJobSelector::try_exact("job-1").expect("selector"));
    let secret = dataflow::SecretReference::for_scope(RAW_SECRET, 8, &scope).expect("secret");
    let mut transport = dataflow::RecordingGcpDataflowTransport::empty();
    transport.push_get_failure(dataflow::GcpDataflowProviderError::from_status(
        401,
        dataflow::TransportProvenance::Recording,
    ));
    let provider =
        dataflow::GcpDataflowProvider::new(scope.clone(), secret, transport).expect("provider");
    let mut service = dataflow::GcpDataflowJobResultService::new(provider).expect("service");
    assert_eq!(
        service.read().expect("access-loss evidence").state,
        dataflow::EvidenceState::AccessLost
    );

    let secret = dataflow::SecretReference::for_scope(RAW_SECRET, 8, &scope).expect("secret");
    let transport = dataflow::FixtureGcpDataflowTransport::from_responses(
        None,
        Some(get_response("JOB_STATE_DONE")),
        Some(dataflow::DataflowResponse::json(200, &json!({}))),
    );
    let provider = dataflow::GcpDataflowProvider::new(scope, secret, transport).expect("provider");
    let mut service = dataflow::GcpDataflowJobResultService::new(provider).expect("service");
    let evidence = service.read().expect("partial metric evidence");
    assert_eq!(evidence.state, dataflow::EvidenceState::Partial);
    assert_eq!(evidence.jobs.len(), 1);
    assert!(evidence.metrics.is_empty());
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_connected_evidence() {
    let scope = scope(dataflow::DataflowJobSelector::try_exact("job-1").expect("selector"));
    let secret = dataflow::SecretReference::for_scope(RAW_SECRET, 8, &scope).expect("secret");
    let transport = dataflow::FixtureGcpDataflowTransport::from_responses(
        None,
        Some(get_response("JOB_STATE_DONE")),
        Some(metrics_response()),
    );
    let provider =
        dataflow::GcpDataflowProvider::new(scope.clone(), secret, transport).expect("provider");
    let mut service = dataflow::GcpDataflowJobResultService::new(provider).expect("service");
    let fixture = service.read().expect("fixture evidence");
    assert!(!fixture.connected && !fixture.native && !fixture.first_party);

    let secret = dataflow::SecretReference::for_scope(RAW_SECRET, 8, &scope).expect("secret");
    let provider = dataflow::GcpDataflowProvider::new(
        scope.clone(),
        secret,
        dataflow::BlockedEnvGcpDataflowTransport,
    )
    .expect("blocked provider");
    let mut service = dataflow::GcpDataflowJobResultService::new(provider).expect("service");
    let blocked = service.read().expect("blocked evidence");
    assert_eq!(blocked.state, dataflow::EvidenceState::ProviderUnknown);
    assert!(!blocked.connected && !blocked.native && !blocked.first_party);
}

#[test]
fn registration_revocation_replay_and_state_transition_fences_work() {
    let mut service = exact_service();
    let proposal = service.compile_proposal().expect("proposal");
    let record = service.record_observation(&proposal).expect("record");
    assert!(service.verify_proposal(&proposal, &record).is_ok());
    let original = service.registration().registration_digest.clone();
    service.revoke_registration().expect("revoke");
    assert!(matches!(
        service.record_observation(&proposal),
        Err(dataflow::GcpDataflowJobResultServiceError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    assert_ne!(service.registration().registration_digest, original);
    assert!(service.verify_proposal(&proposal, &record).is_err());

    let service = exact_service();
    let mut consumer = dataflow::MissionGcpDataflowConsumer::new(service).expect("consumer");
    let evidence = consumer.read().expect("consumer read");
    let result = consumer.consume(evidence.clone()).expect("consume");
    assert_eq!(result.state, dataflow::MissionGcpDataflowState::Running);
    assert!(!result.native && !result.connected && !result.first_party);
    assert!(!result.adopts_outcome && !result.work_product_adoption);
    assert!(matches!(
        consumer.consume(evidence),
        Err(dataflow::MissionGcpDataflowConsumerError::ReplayDetected)
    ));

    assert!(
        dataflow::DataflowJobState::Pending.can_transition_to(dataflow::DataflowJobState::Queued)
    );
    assert!(
        dataflow::DataflowJobState::Running.can_transition_to(dataflow::DataflowJobState::Draining)
    );
    assert!(
        !dataflow::DataflowJobState::Done.can_transition_to(dataflow::DataflowJobState::Running)
    );
}

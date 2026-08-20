use hartevo_gcp_cloud_build_result_plugin as cloud_build;
use serde_json::{Value, json};

const GCP_PROJECT: &str = "gcp-project-1";
const LOCATION: &str = "us-central1";
const REPOSITORY: &str = "github.com/acme/hartevo";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const TRIGGER: &str = "trigger-1";

fn scope(selector: cloud_build::BuildSelector) -> cloud_build::GcpCloudBuildScope {
    cloud_build::GcpCloudBuildScope::read_only(
        cloud_build::ProjectBinding::new("project-1", 2).expect("project binding"),
        cloud_build::MissionBinding::new("mission-1", 3).expect("mission binding"),
        cloud_build::WorkProductBinding::new("work-product-1", 4).expect("work product"),
        GCP_PROJECT,
        LOCATION,
        selector,
        Some(TRIGGER),
        cloud_build::SourceScope::new(REPOSITORY, COMMIT).expect("source scope"),
        cloud_build::ConsentScope::new("mission-consent-1", 5).expect("consent"),
    )
    .expect("scope")
}

fn response_build(id: &str, status: &str) -> Value {
    json!({
        "id": id,
        "projectId": GCP_PROJECT,
        "status": status,
        "triggerId": TRIGGER,
        "createTime": "2026-08-15T00:00:00Z",
        "startTime": "2026-08-15T00:00:01Z",
        "finishTime": "2026-08-15T00:00:11Z",
        "source": {
            "repoSource": {
                "repoName": REPOSITORY,
                "commitSha": COMMIT
            }
        },
        "steps": [
            {
                "name": "gcr.io/cloud-builders/rust",
                "id": "compile",
                "status": status,
                "args": ["--secret-looking-argument"],
                "env": ["PRIVATE=do-not-retain"],
                "secretEnv": ["TOKEN"],
                "results": {"exitCode": 0, "private": "do-not-retain"}
            }
        ],
        "images": ["us-central1-docker.pkg.dev/acme/app:latest"],
        "results": {
            "images": [
                {
                    "name": "us-central1-docker.pkg.dev/acme/app:latest",
                    "digest": "sha256:private-image-digest",
                    "sizeBytes": "not retained"
                }
            ]
        },
        "logsBucket": "gs://private-logs",
        "privateMessage": "raw provider diagnostic must not escape"
    })
}

fn list_response(status: &str) -> cloud_build::CloudBuildResponse {
    cloud_build::CloudBuildResponse::json(
        200,
        &json!({
            "builds": [response_build("build-1", status)]
        }),
    )
}

fn service_with_transport<T>(
    scope: cloud_build::GcpCloudBuildScope,
    transport: T,
) -> cloud_build::GcpCloudBuildResultService<T>
where
    T: cloud_build::GcpCloudBuildTransport,
{
    let secret = cloud_build::SecretReference::new("keyring://opaque-gcp-build-handle", 7)
        .expect("opaque secret reference");
    let provider =
        cloud_build::GcpCloudBuildProvider::new(scope, secret, transport).expect("provider");
    cloud_build::GcpCloudBuildResultService::new(provider).expect("service")
}

fn evidence_with_response(status: &str) -> cloud_build::GcpCloudBuildEvidence {
    let transport = cloud_build::RecordingGcpCloudBuildTransport::new(list_response(status));
    let mut service = service_with_transport(scope(cloud_build::BuildSelector::any()), transport);
    service.read().expect("evidence")
}

#[test]
fn contract_and_service_are_exactly_layer_one() {
    cloud_build::validate_contract().expect("contract invariants");
    let definition = cloud_build::GcpCloudBuildResultServiceDefinition::new();
    definition.validate().expect("service definition");
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(!definition.native);
    assert!(!definition.connected);
    assert!(!definition.external_writes);
    assert_eq!(cloud_build::contract_digest().len(), 64);
    assert_eq!(cloud_build::GCP_CLOUD_BUILD_BLOCKED_ENV, "BLOCKED_ENV");
    assert!(!cloud_build::Layer1Authority::connected());
    assert!(!cloud_build::Layer1Authority::native_provider());
    assert!(!cloud_build::Layer1Authority::first_party());
    assert!(!cloud_build::Layer1Authority::credential_resolution());
    assert!(!cloud_build::Layer1Authority::creates_builds());
    assert!(!cloud_build::Layer1Authority::cancels_builds());
    assert!(!cloud_build::Layer1Authority::retries_builds());
    assert!(!cloud_build::Layer1Authority::trigger_mutation());
    assert!(!cloud_build::Layer1Authority::raw_logs());
    assert!(!cloud_build::Layer1Authority::outcome_authority());
    assert!(!cloud_build::Layer1Authority::work_product_adoption());
}

#[test]
fn list_and_exact_get_are_bounded_and_typed() {
    let mut list_service = service_with_transport(
        scope(cloud_build::BuildSelector::any()),
        cloud_build::RecordingGcpCloudBuildTransport::new(list_response("SUCCESS")),
    );
    let list_evidence = list_service.read().expect("list evidence");
    assert_eq!(list_evidence.state, cloud_build::EvidenceState::Complete);
    assert_eq!(list_evidence.builds.len(), 1);
    assert_eq!(
        list_evidence.builds[0].status,
        cloud_build::CloudBuildStatus::Success
    );
    assert_eq!(list_evidence.builds[0].duration_seconds, Some(10));
    assert_eq!(list_evidence.builds[0].step_digests.len(), 1);
    assert_eq!(list_evidence.builds[0].artifact_metadata.len(), 2);
    assert!(list_evidence.builds[0].verify_digest());
    assert!(list_evidence.verify_digest());
    assert_eq!(list_evidence.request_receipts[0].method, "GET");
    assert_eq!(
        list_evidence.request_receipts[0].path,
        "/v1/projects/gcp-project-1/builds"
    );

    let mut get_service = service_with_transport(
        scope(cloud_build::BuildSelector::try_exact("build-1").expect("build selector")),
        cloud_build::RecordingGcpCloudBuildTransport::new(cloud_build::CloudBuildResponse::json(
            200,
            &response_build("build-1", "SUCCESS"),
        )),
    );
    let get_evidence = get_service.read().expect("get evidence");
    assert_eq!(
        get_evidence.operation,
        cloud_build::CloudBuildOperation::Get
    );
    assert_eq!(get_evidence.builds[0].build_id.as_str(), "build-1");
    assert_eq!(
        get_evidence.request_receipts[0].path,
        "/v1/projects/gcp-project-1/builds/build-1"
    );
}

#[test]
fn statuses_are_normalized_without_claiming_build_correctness() {
    let cases = [
        ("QUEUED", cloud_build::CloudBuildStatus::Queued),
        ("WORKING", cloud_build::CloudBuildStatus::Working),
        ("SUCCESS", cloud_build::CloudBuildStatus::Success),
        ("FAILURE", cloud_build::CloudBuildStatus::Failure),
        (
            "INTERNAL_ERROR",
            cloud_build::CloudBuildStatus::InternalError,
        ),
        ("TIMEOUT", cloud_build::CloudBuildStatus::Timeout),
        ("CANCELLED", cloud_build::CloudBuildStatus::Cancelled),
        ("EXPIRED", cloud_build::CloudBuildStatus::Expired),
        (
            "A_PROVIDER_STATUS_ADDED_LATER",
            cloud_build::CloudBuildStatus::Unknown,
        ),
    ];
    for (status, expected) in cases {
        let evidence = evidence_with_response(status);
        assert_eq!(evidence.builds[0].status, expected);
        assert!(!evidence.native);
        assert!(!evidence.connected);
        assert!(!evidence.outcome_authority);
        assert!(!evidence.work_product_adoption);
        assert!(evidence.proposal_only);
    }
    assert_eq!(
        evidence_with_response("A_PROVIDER_STATUS_ADDED_LATER").state,
        cloud_build::EvidenceState::Partial
    );
}

#[test]
fn redaction_is_structural_and_secret_reference_is_opaque() {
    let evidence = evidence_with_response("SUCCESS");
    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("secret-looking-argument"));
    assert!(!serialized.contains("PRIVATE=do-not-retain"));
    assert!(!serialized.contains("TOKEN"));
    assert!(!serialized.contains("private-logs"));
    assert!(!serialized.contains("raw provider diagnostic"));
    assert!(!serialized.contains("private-image-digest"));

    let secret =
        cloud_build::SecretReference::new("raw-secret-handle-must-not-print", 8).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("raw-secret-handle-must-not-print"));
    assert!(debug.contains("reference_digest"));
    assert!(
        serde_json::to_string(&evidence)
            .expect("evidence JSON")
            .contains("bodyDigest")
    );
}

#[test]
fn opaque_page_tokens_and_deterministic_result_digests_are_fenced() {
    let first = cloud_build::CloudBuildResponse::json(
        200,
        &json!({
            "builds": [response_build("build-1", "SUCCESS")],
            "nextPageToken": "raw-page-token-that-must-not-escape"
        }),
    );
    let second = cloud_build::CloudBuildResponse::json(200, &json!({"builds": []}));
    let mut transport = cloud_build::RecordingGcpCloudBuildTransport::empty();
    transport.push_list_response(first);
    transport.push_list_response(second);
    let paged_scope = scope(cloud_build::BuildSelector::any());
    let mut service = service_with_transport(paged_scope, transport);
    let evidence = service.read_list_builds().expect("paged evidence");
    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("raw-page-token-that-must-not-escape"));
    assert!(evidence.request_receipts[1].page_token_digest.is_some());
    assert!(evidence.builds[0].digest().len() == 64);

    let mut reordered = response_build("build-1", "SUCCESS");
    let object = reordered.as_object_mut().expect("object");
    let steps = object.remove("steps").expect("steps");
    let source = object.remove("source").expect("source");
    object.insert("source".to_owned(), source);
    object.insert("steps".to_owned(), steps);
    let left = evidence_with_response("SUCCESS");
    let reordered_response =
        cloud_build::CloudBuildResponse::json(200, &json!({"builds": [reordered]}));
    let mut reordered_service = service_with_transport(
        scope(cloud_build::BuildSelector::any()),
        cloud_build::RecordingGcpCloudBuildTransport::new(reordered_response),
    );
    let right = reordered_service.read().expect("reordered evidence");
    assert_eq!(left.digests.result_digest, right.digests.result_digest);
    assert_eq!(left.builds[0].digest(), right.builds[0].digest());
    assert_eq!(left.evidence_digest, right.evidence_digest);
}

#[test]
fn provider_status_errors_cover_access_conflict_rate_and_unknown() {
    let cases = [
        (408, cloud_build::EvidenceState::Timeout),
        (401, cloud_build::EvidenceState::AccessLost),
        (403, cloud_build::EvidenceState::AccessLost),
        (404, cloud_build::EvidenceState::NotFound),
        (409, cloud_build::EvidenceState::Conflict),
        (429, cloud_build::EvidenceState::RateLimited),
        (500, cloud_build::EvidenceState::ProviderUnknown),
        (503, cloud_build::EvidenceState::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let response = cloud_build::CloudBuildResponse::new(
            status,
            br#"{"message":"raw diagnostic with secret"}"#.to_vec(),
        );
        let mut service = service_with_transport(
            scope(cloud_build::BuildSelector::any()),
            cloud_build::RecordingGcpCloudBuildTransport::new(response),
        );
        let evidence = service.read().expect("typed provider status");
        assert_eq!(evidence.state, expected);
        assert!(evidence.builds.is_empty());
        assert!(
            !serde_json::to_string(&evidence)
                .expect("evidence serializes")
                .contains("raw diagnostic with secret")
        );
    }

    let mut transport = cloud_build::RecordingGcpCloudBuildTransport::empty();
    transport.push_list_failure(cloud_build::GcpCloudBuildProviderError::failure(
        cloud_build::ProviderFailureClass::Timeout,
        None,
        None,
        cloud_build::TransportProvenance::Recording,
    ));
    let mut service = service_with_transport(scope(cloud_build::BuildSelector::any()), transport);
    assert_eq!(
        service.read().expect("timeout evidence").state,
        cloud_build::EvidenceState::Timeout
    );
}

#[test]
fn fixture_loopback_and_blocked_env_never_become_connected_or_native() {
    let mut fixture_service = service_with_transport(
        scope(cloud_build::BuildSelector::any()),
        cloud_build::FixtureGcpCloudBuildTransport::from_response(list_response("SUCCESS")),
    );
    assert_eq!(
        fixture_service.provider_provenance(),
        cloud_build::TransportProvenance::Fixture
    );
    let fixture = fixture_service.read().expect("fixture evidence");
    assert!(!fixture.native && !fixture.connected && !fixture.first_party);

    let mut loopback_service = service_with_transport(
        scope(cloud_build::BuildSelector::any()),
        cloud_build::LoopbackGcpCloudBuildTransport::new(Vec::new()),
    );
    let loopback = loopback_service.read().expect("loopback evidence");
    assert!(!loopback.native && !loopback.connected && !loopback.first_party);

    let mut blocked_service = service_with_transport(
        scope(cloud_build::BuildSelector::any()),
        cloud_build::BlockedEnvGcpCloudBuildTransport,
    );
    assert_eq!(
        blocked_service.read().expect("blocked evidence").state,
        cloud_build::EvidenceState::AccessLost
    );
    assert!(!blocked_service.provider().is_native());
    assert!(!blocked_service.provider().is_connected());
}

#[test]
fn registration_is_reversible_and_old_proposals_fail_closed() {
    let mut service = service_with_transport(scope(cloud_build::BuildSelector::any()), {
        let mut transport = cloud_build::RecordingGcpCloudBuildTransport::empty();
        transport.push_list_response(list_response("SUCCESS"));
        transport.push_list_response(list_response("SUCCESS"));
        transport
    });
    let proposal = service.compile_proposal().expect("proposal");
    let record = service.record_list_builds().expect("record");
    let original = service.registration().registration_digest.clone();
    let revocation = service.revoke_registration().expect("revoke");
    assert_eq!(revocation.previous_registration_digest, original);
    assert_ne!(revocation.registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(cloud_build::GcpCloudBuildResultServiceError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    assert_ne!(service.registration().registration_digest, original);
    assert!(matches!(
        service.verify_proposal(&proposal, &record),
        Err(cloud_build::GcpCloudBuildResultServiceError::ProposalTampered)
    ));
}

#[test]
fn tamper_replay_and_stale_mission_fences_are_typed() {
    let mut service = service_with_transport(scope(cloud_build::BuildSelector::any()), {
        let mut transport = cloud_build::RecordingGcpCloudBuildTransport::empty();
        transport.push_list_response(list_response("SUCCESS"));
        transport.push_list_response(list_response("SUCCESS"));
        transport
    });
    let proposal = service.compile_proposal().expect("proposal");
    let record = service.record_list_builds().expect("record");
    let mut tampered_record = record.clone();
    tampered_record.builds[0].result_digest = cloud_build::Digest::from_text("tampered");
    assert!(matches!(
        service.verify_proposal(&proposal, &tampered_record),
        Err(cloud_build::GcpCloudBuildResultServiceError::ProposalTampered)
    ));

    let stale = service
        .read_at_mission_revision(99)
        .expect("stale evidence");
    assert_eq!(stale.state, cloud_build::EvidenceState::Stale);
    assert!(stale.builds.is_empty());
    assert!(service.record_observation(&stale).is_ok());

    let mut consumer = cloud_build::MissionGcpBuildConsumer::new(service).expect("consumer");
    let evidence = consumer.read().expect("consumer read");
    let result = consumer.consume(evidence.clone()).expect("consume");
    assert_eq!(
        result.state,
        cloud_build::MissionGcpBuildState::EvidenceReady
    );
    assert!(!result.native);
    assert!(!result.connected);
    assert!(!result.first_party);
    assert!(!result.adopts_outcome);
    assert!(!result.work_product_adoption);
    assert!(matches!(
        consumer.consume(evidence),
        Err(cloud_build::MissionGcpBuildConsumerError::ReplayDetected)
    ));
}

#[test]
fn project_location_source_commit_and_trigger_drift_fail_closed() {
    let cases = [
        ("projectId", json!("different-project")),
        ("location", json!("europe-west1")),
    ];
    for (field, value) in cases {
        let mut build = response_build("build-1", "SUCCESS");
        build[field] = value;
        let response = cloud_build::CloudBuildResponse::json(200, &json!({"builds": [build]}));
        let mut service = service_with_transport(
            scope(cloud_build::BuildSelector::any()),
            cloud_build::RecordingGcpCloudBuildTransport::new(response),
        );
        assert_eq!(
            service.read().expect("drift evidence").state,
            cloud_build::EvidenceState::Stale
        );
    }

    for (field, value) in [
        (
            "commitSha",
            json!("fedcba9876543210fedcba9876543210fedcba98"),
        ),
        ("repoName", json!("github.com/other/repo")),
    ] {
        let mut build = response_build("build-1", "SUCCESS");
        build["source"]["repoSource"][field] = value;
        let response = cloud_build::CloudBuildResponse::json(200, &json!({"builds": [build]}));
        let mut service = service_with_transport(
            scope(cloud_build::BuildSelector::any()),
            cloud_build::RecordingGcpCloudBuildTransport::new(response),
        );
        assert_eq!(
            service.read().expect("source drift evidence").state,
            cloud_build::EvidenceState::Stale
        );
    }

    let mut trigger_build = response_build("build-1", "SUCCESS");
    trigger_build["triggerId"] = json!("different-trigger");
    let response = cloud_build::CloudBuildResponse::json(200, &json!({"builds": [trigger_build]}));
    let mut service = service_with_transport(
        scope(cloud_build::BuildSelector::any()),
        cloud_build::RecordingGcpCloudBuildTransport::new(response),
    );
    assert_eq!(
        service.read().expect("trigger drift evidence").state,
        cloud_build::EvidenceState::Stale
    );
}

#[test]
fn pagination_loop_and_malformed_payload_are_partial_without_raw_escape() {
    let loop_response = cloud_build::CloudBuildResponse::json(
        200,
        &json!({
            "builds": [response_build("build-1", "SUCCESS")],
            "nextPageToken": "same-token"
        }),
    );
    let mut transport = cloud_build::RecordingGcpCloudBuildTransport::empty();
    transport.push_list_response(loop_response.clone());
    transport.push_list_response(loop_response);
    let mut service = service_with_transport(scope(cloud_build::BuildSelector::any()), transport);
    let evidence = service.read().expect("loop evidence");
    assert_eq!(evidence.state, cloud_build::EvidenceState::Partial);
    assert_eq!(evidence.request_receipts.len(), 2);

    let malformed = cloud_build::CloudBuildResponse::new(
        200,
        br#"{"builds":[{"id":"build-1","status":"SUCCESS"}]}"#.to_vec(),
    );
    let mut malformed_service = service_with_transport(
        scope(cloud_build::BuildSelector::any()),
        cloud_build::RecordingGcpCloudBuildTransport::new(malformed),
    );
    let malformed_evidence = malformed_service
        .read()
        .expect("partial malformed evidence");
    assert_eq!(
        malformed_evidence.state,
        cloud_build::EvidenceState::Partial
    );
    assert!(
        !serde_json::to_string(&malformed_evidence)
            .expect("malformed evidence serializes")
            .contains("private provider raw body")
    );
}

#[test]
fn oversized_response_is_bounded() {
    let oversized =
        cloud_build::CloudBuildResponse::new(200, vec![b'X'; cloud_build::MAX_RESPONSE_BYTES + 1]);
    let mut service = service_with_transport(
        scope(cloud_build::BuildSelector::any()),
        cloud_build::RecordingGcpCloudBuildTransport::new(oversized),
    );
    assert_eq!(
        service.read().expect("oversized evidence").state,
        cloud_build::EvidenceState::Partial
    );
}

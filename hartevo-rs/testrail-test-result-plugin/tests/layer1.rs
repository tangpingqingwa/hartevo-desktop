use hartevo_testrail_test_result_plugin::{
    BlockedEnvTransport, CommitOrRelease, DefectIdentity, Digest, FixtureTransport,
    HartevoProjectIdentity, HostIdentity, LoopbackTransport, MissionIdentity,
    MissionTestRailResultConsumer, PermissionSnapshot, ProjectIdentity, RecordingTransport,
    RedactionState, ResultScope, RunIdentity, SecretReference, SectionIdentity, SuiteIdentity,
    TestIdentity, TestRailBounds, TestRailEndpoint, TestRailError, TestRailProvider,
    TestRailRegistration, TestRailRequest, TestRailResponse, TestRailResultStatus, TestRailScope,
    TestRailTestResultService, TestRailTransport, TransportError, TransportProvenance,
    WorkProductIdentity, contract_digest,
};
use serde_json::json;

const RUN_ID: u64 = 77;
const PROJECT_ID: u64 = 9;
const SUITE_ID: u64 = 4;
const SECTION_ID: u64 = 6;
const UPDATED_ON: u64 = 1_700_000_000;

fn scope() -> TestRailScope {
    let statuses = [
        (1, "Passed"),
        (2, "Blocked"),
        (3, "Untested"),
        (4, "Retest"),
        (5, "Failed"),
    ]
    .into_iter()
    .map(|(id, label)| {
        hartevo_testrail_test_result_plugin::StatusIdentity::new(id, label, 1).unwrap()
    });
    let tests = [
        TestIdentity::new(101, Some(1001), "login works", 1).unwrap(),
        TestIdentity::new(102, Some(1002), "checkout fails safely", 1).unwrap(),
    ];
    TestRailScope::new(
        HostIdentity::new("https://testrail.example.test", 1).unwrap(),
        ProjectIdentity::new(PROJECT_ID, "Hartevo QA", 2).unwrap(),
        SuiteIdentity::new(SUITE_ID, "release suite", 3).unwrap(),
        SectionIdentity::new(SECTION_ID, "smoke", 4).unwrap(),
        RunIdentity::new(RUN_ID, "release-42", 5, UPDATED_ON).unwrap(),
        tests,
        ResultScope::new([1001, 1002], 6).unwrap(),
        statuses,
        [DefectIdentity::new("TR-42", 7).unwrap()],
        CommitOrRelease::release("build-42", 8).unwrap(),
        MissionIdentity::new("mission-qa", 10).unwrap(),
        HartevoProjectIdentity::new("project-delivery", 11).unwrap(),
        WorkProductIdentity::new("work-product-release", 12).unwrap(),
        PermissionSnapshot::read_only().permissions,
    )
    .unwrap()
}

fn registration() -> TestRailRegistration {
    let scope = scope();
    let secret = SecretReference::api_key("opaque-api-key-reference", &scope, 1).unwrap();
    TestRailRegistration::register(scope, secret).unwrap()
}

#[allow(clippy::needless_pass_by_value)]
fn response(value: serde_json::Value, provenance: TransportProvenance) -> TestRailResponse {
    TestRailResponse::json(serde_json::to_vec(&value).unwrap(), provenance)
}

fn run_response(provenance: TransportProvenance, updated_on: u64) -> TestRailResponse {
    response(
        json!({
            "id": RUN_ID,
            "name": "release-42",
            "project_id": PROJECT_ID,
            "suite_id": SUITE_ID,
            "updated_on": updated_on,
            "due_on": null,
            "is_completed": true,
            "passed_count": 1,
            "failed_count": 1,
            "comment": "a field outside the projection"
        }),
        provenance,
    )
}

fn test_item(id: u64, case_id: u64, title: &str, status_id: u16) -> serde_json::Value {
    json!({
        "id": id,
        "case_id": case_id,
        "run_id": RUN_ID,
        "title": title,
        "status_id": status_id,
        "section_id": SECTION_ID,
        "custom_steps_separated": [{"content": "secret step", "expected": "secret"}]
    })
}

fn result_item(id: u64, test_id: u64, status_id: u16) -> serde_json::Value {
    json!({
        "id": id,
        "test_id": test_id,
        "status_id": status_id,
        "created_on": id + 1_000_000,
        "comment": "SECRET COMMENT SHOULD NEVER APPEAR",
        "defects": "TR-42",
        "version": "build-42",
        "custom_step_results": [{"actual": "secret screenshot pointer"}],
        "attachments": [{"id": "secret-attachment"}]
    })
}

#[allow(clippy::needless_pass_by_value)]
fn tests_page_at(
    offset: usize,
    items: Vec<serde_json::Value>,
    next_offset: Option<usize>,
    limit: usize,
    provenance: TransportProvenance,
) -> TestRailResponse {
    response(
        json!({
            "offset": offset,
            "limit": limit,
            "size": items.len(),
            "_links": {"next": next_offset.map(|next| format!("/api/v2/get_tests/{RUN_ID}?limit={limit}&offset={next}")), "prev": null},
            "tests": items
        }),
        provenance,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn results_page_at(
    offset: usize,
    items: Vec<serde_json::Value>,
    next_offset: Option<usize>,
    limit: usize,
    provenance: TransportProvenance,
) -> TestRailResponse {
    response(
        json!({
            "offset": offset,
            "limit": limit,
            "size": items.len(),
            "_links": {"next": next_offset.map(|next| format!("/api/v2/get_results_for_run/{RUN_ID}?limit={limit}&offset={next}")), "prev": null},
            "results": items
        }),
        provenance,
    )
}

fn happy_responses(provenance: TransportProvenance) -> Vec<TestRailResponse> {
    vec![
        run_response(provenance, UPDATED_ON),
        tests_page_at(
            0,
            vec![
                test_item(101, 1001, "login works", 1),
                test_item(102, 1002, "checkout fails safely", 5),
            ],
            None,
            250,
            provenance,
        ),
        results_page_at(
            0,
            vec![result_item(1001, 101, 1), result_item(1002, 102, 5)],
            None,
            250,
            provenance,
        ),
    ]
}

fn recording_service() -> TestRailTestResultService<RecordingTransport> {
    let responses = happy_responses(TransportProvenance::Recording);
    TestRailTestResultService::new(
        registration(),
        RecordingTransport::from_responses(responses),
    )
    .unwrap()
}

#[test]
fn contract_digest_and_scope_digests_are_present_and_deterministic() {
    let bound_scope = scope();
    assert!(bound_scope.scope_digest().is_valid());
    assert!(bound_scope.version_digest().is_valid());
    assert!(bound_scope.contract_digest().is_valid());
    assert!(registration().provider().digest().is_valid());
    assert!(bound_scope.permission_digest().is_valid());
    assert!(bound_scope.revision_digest().is_valid());
    assert_eq!(bound_scope.scope_digest(), scope().scope_digest());
    assert_eq!(
        contract_digest().as_str(),
        "f2635ad3f012f94a28ab2716c2cc8a2caec27de21b6a66825c4233e1a513150a"
    );
}

#[test]
fn capabilities_and_all_layer1_provenances_are_honest() {
    let service = recording_service();
    let capabilities = service.describe_capabilities();
    assert_eq!(capabilities.layer, 1);
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.recording_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.verified);
    assert!(
        capabilities
            .forbidden_operations
            .iter()
            .any(|operation| operation == "add_result")
    );
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_native());
        assert!(!provenance.claims_connected());
        assert!(!provenance.claims_first_party());
        assert!(provenance.is_explicit_non_native());
    }
}

#[test]
fn bounded_read_projects_counts_fingerprints_and_redacted_metadata() {
    let mut service = recording_service();
    let projection = service.read_result().unwrap();
    assert_eq!(projection.status, TestRailResultStatus::Partial);
    assert_eq!(projection.counts.total, 2);
    assert_eq!(projection.counts.passed, 1);
    assert_eq!(projection.counts.failed, 1);
    assert!(projection.complete);
    assert!(projection.source_verified);
    assert!(projection.section_verified);
    assert!(projection.metadata_redacted);
    assert!(!projection.raw_payload_retained);
    assert!(!projection.connected);
    assert!(!projection.native);
    assert!(!projection.verified);
    assert!(projection.validate_integrity().is_ok());
    assert!(
        projection
            .results
            .iter()
            .all(|result| result.redaction == RedactionState::CommentAndDefectMetadataRedacted)
    );
    let serialized = serde_json::to_string(&projection).unwrap();
    assert!(!serialized.contains("SECRET COMMENT SHOULD NEVER APPEAR"));
    assert!(!serialized.contains("TR-42"));
    assert!(!serialized.contains("build-42"));
    assert!(
        projection
            .results
            .iter()
            .all(|result| result.comment_present)
    );
    assert!(
        projection
            .results
            .iter()
            .all(|result| result.comment_digest.is_some())
    );
    assert!(
        projection
            .results
            .iter()
            .all(|result| result.defect_count == 1)
    );

    let mut second = recording_service();
    let second_projection = second.read_result().unwrap();
    assert_eq!(
        projection.test_fingerprint,
        second_projection.test_fingerprint
    );
    assert_eq!(
        projection.result_fingerprint,
        second_projection.result_fingerprint
    );
    assert_eq!(
        projection.status_fingerprint,
        second_projection.status_fingerprint
    );
}

#[test]
fn pagination_is_offset_bounded_and_deterministic() {
    let provenance = TransportProvenance::Loopback;
    let responses = vec![
        run_response(provenance, UPDATED_ON),
        tests_page_at(
            0,
            vec![test_item(101, 1001, "login works", 1)],
            Some(1),
            1,
            provenance,
        ),
        tests_page_at(
            1,
            vec![test_item(102, 1002, "checkout fails safely", 5)],
            None,
            1,
            provenance,
        ),
        results_page_at(0, vec![result_item(1001, 101, 1)], Some(1), 1, provenance),
        results_page_at(1, vec![result_item(1002, 102, 5)], None, 1, provenance),
    ];
    let provider =
        TestRailProvider::new(registration(), LoopbackTransport::from_responses(responses))
            .unwrap()
            .with_bounds(TestRailBounds::new(1, 4, 128 * 1024).unwrap())
            .unwrap();
    let mut service = TestRailTestResultService::from_provider(provider).unwrap();
    let projection = service.read_result().unwrap();
    assert_eq!(projection.tests.len(), 2);
    assert_eq!(projection.results.len(), 2);
}

#[test]
fn tamper_duplicate_replay_and_stale_mission_fences_fail_closed() {
    let mut service = recording_service();
    let projection = service.read_result().unwrap();
    let mut tampered = projection.clone();
    tampered.result_fingerprint = Digest::from_text("tampered-result");
    assert_eq!(
        tampered.validate_integrity(),
        Err(TestRailError::TamperDetected)
    );

    let proposal = service.compile_adoption_proposal(&projection).unwrap();
    assert!(proposal.validate_integrity().is_ok());
    let mut proposal_tampered = proposal.clone();
    proposal_tampered.run_updated_on += 1;
    assert_eq!(
        proposal_tampered.validate_integrity(),
        Err(TestRailError::TamperDetected)
    );
    assert_eq!(
        service.compile_adoption_proposal(&projection),
        Err(TestRailError::DuplicateProposal)
    );

    let consumer =
        MissionTestRailResultConsumer::from_registration(service.registration()).unwrap();
    assert_eq!(
        consumer.propose(
            &projection,
            scope().mission.revision + 1,
            service.registration()
        ),
        Err(TestRailError::StaleMissionRevision)
    );
    let mut log = hartevo_testrail_test_result_plugin::TestRailRecordingLog::default();
    let first = service.record_proposal(&mut log, &proposal).unwrap();
    assert!(!first.replayed);
    let replay = service.record_proposal(&mut log, &proposal).unwrap();
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);
}

#[test]
fn registration_revocation_is_shared_and_reversible_state_is_visible() {
    let mut service = recording_service();
    let projection = service.read_result().unwrap();
    let registration = service.registration();
    assert!(registration.is_active());
    let revocation = registration.revoke().unwrap();
    assert_eq!(
        revocation.state,
        hartevo_testrail_test_result_plugin::RegistrationStatus::Revoked
    );
    assert!(!registration.is_active());
    assert_eq!(
        service.read_result(),
        Err(TestRailError::RegistrationRevoked)
    );
    assert_eq!(
        service.compile_adoption_proposal(&projection),
        Err(TestRailError::RegistrationRevoked)
    );
}

#[test]
fn run_revision_source_scope_and_status_allowlist_drift_fail_closed() {
    let drifted = vec![
        run_response(TransportProvenance::Fixture, UPDATED_ON + 1),
        tests_page_at(
            0,
            vec![
                test_item(101, 1001, "login works", 1),
                test_item(102, 1002, "checkout fails safely", 5),
            ],
            None,
            250,
            TransportProvenance::Fixture,
        ),
        results_page_at(
            0,
            vec![result_item(1001, 101, 1), result_item(1002, 102, 5)],
            None,
            250,
            TransportProvenance::Fixture,
        ),
    ];
    let mut provider =
        TestRailProvider::new(registration(), FixtureTransport::from_responses(drifted)).unwrap();
    assert_eq!(
        provider.read_result_projection(),
        Err(TestRailError::RunRevisionDrift)
    );

    let mut status_payload = happy_responses(TransportProvenance::Fixture);
    status_payload[2] = results_page_at(
        0,
        vec![result_item(1001, 101, 6), result_item(1002, 102, 5)],
        None,
        250,
        TransportProvenance::Fixture,
    );
    let mut provider = TestRailProvider::new(
        registration(),
        FixtureTransport::from_responses(status_payload),
    )
    .unwrap();
    assert_eq!(
        provider.read_result_projection(),
        Err(TestRailError::StatusNotAllowlisted)
    );
}

#[test]
fn http_failures_and_blocked_env_never_become_native_evidence() {
    for status in [401, 403, 404, 409, 429, 500, 503] {
        let mut provider = TestRailProvider::new(
            registration(),
            RecordingTransport::new(TestRailResponse::error(
                status,
                TransportProvenance::Recording,
            )),
        )
        .unwrap();
        let error = provider.read_run().unwrap_err();
        assert!(matches!(error, TestRailError::Transport(_)));
    }
    let mut provider = TestRailProvider::new(registration(), BlockedEnvTransport).unwrap();
    assert_eq!(
        provider.read_run(),
        Err(TestRailError::Transport(TransportError::BlockedEnv))
    );
}

#[test]
fn malformed_partial_offset_loop_and_response_bounds_fail_closed() {
    let provenance = TransportProvenance::Recording;
    let malformed = vec![
        run_response(provenance, UPDATED_ON),
        response(
            json!({"offset": 0, "limit": 250, "size": 1, "_links": {"next": null}, "unexpected": []}),
            provenance,
        ),
        results_page_at(0, vec![], None, 250, provenance),
    ];
    let mut provider = TestRailProvider::new(
        registration(),
        RecordingTransport::from_responses(malformed),
    )
    .unwrap();
    assert_eq!(
        provider.read_result_projection(),
        Err(TestRailError::MalformedResponse)
    );

    let offset_loop = vec![
        run_response(provenance, UPDATED_ON),
        tests_page_at(
            0,
            vec![test_item(101, 1001, "login works", 1)],
            Some(0),
            1,
            provenance,
        ),
    ];
    let mut provider = TestRailProvider::new(
        registration(),
        RecordingTransport::from_responses(offset_loop),
    )
    .unwrap();
    assert_eq!(
        provider.read_result_projection(),
        Err(TestRailError::PaginationLoop)
    );

    let huge = vec![TestRailResponse::from_json(
        200,
        vec![b'x'; 2 * 1024 * 1024],
        provenance,
    )];
    let mut provider =
        TestRailProvider::new(registration(), RecordingTransport::from_responses(huge)).unwrap();
    assert_eq!(provider.read_run(), Err(TestRailError::ResponseTooLarge));
}

#[test]
fn exact_allowlisted_request_shape_has_no_mutation_surface() {
    let request = TestRailRequest::new_for_test(
        TestRailEndpoint::GetResultsForRun,
        PROJECT_ID,
        RUN_ID,
        3,
        10,
    )
    .unwrap();
    assert_eq!(request.endpoint, TestRailEndpoint::GetResultsForRun);
    assert_eq!(
        request.path,
        "/api/v2/get_results_for_run/77?limit=10&offset=3"
    );
    assert!(!request.path.contains("add_"));
    assert!(!request.path.contains("edit_"));
}

#[test]
fn contract_fixture_is_machine_valid_and_declares_honesty_boundary() {
    let contract: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/plugins/testrail-test-result/service.v1.json"
    ))
    .unwrap();
    assert_eq!(contract["layer"], 1);
    assert_eq!(contract["contractDigest"], contract_digest().as_str());
    assert_eq!(contract["credentials"]["serialized"], false);
    assert_eq!(contract["provider"]["mutations"]["addResult"], false);
    assert_eq!(contract["provider"]["mutations"]["editResult"], false);
    assert_eq!(
        contract["provenance"]["recording"],
        "non_native_non_connected"
    );
    assert_eq!(
        contract["provenance"]["blocked_env"],
        "non_native_non_connected"
    );
    assert!(
        contract["provider"]["allowlistedPaths"]
            .as_array()
            .unwrap()
            .iter()
            .all(|path| path.as_str().unwrap().starts_with("/api/v2/"))
    );
}

#[test]
fn transport_trait_is_typed_and_non_mutating() {
    fn assert_transport<T: TestRailTransport>() {}
    assert_transport::<FixtureTransport>();
    assert_transport::<RecordingTransport>();
    assert_transport::<LoopbackTransport>();
    assert_transport::<BlockedEnvTransport>();
}

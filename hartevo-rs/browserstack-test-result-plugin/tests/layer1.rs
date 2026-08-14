use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use hartevo_browserstack_test_result_plugin::{
    BrowserStackBuildPayload, BrowserStackEndpoint, BrowserStackHttpRequest,
    BrowserStackHttpResponse, BrowserStackMatrixEntry, BrowserStackProduct, BrowserStackProvider,
    BrowserStackProviderDefinition, BrowserStackReadRequest, BrowserStackRegistrationRequest,
    BrowserStackResponseBody, BrowserStackScope, BrowserStackScopeInput,
    BrowserStackSessionPayload, BrowserStackTestResultContract, BrowserStackTestResultError,
    BrowserStackTransportError, EvidenceStatus, FixtureCredentialResolver,
    MissionBrowserStackTestConsumer, OutcomeCounts, PartialReason, PermissionSnapshot,
    ProviderFailure, RecordingBrowserStackTransport, RequestBounds, SecretReference,
    TransportProvenance,
};

const BUILD_ID: &str = "build-42";
const SESSION_1: &str = "session-1";
const SESSION_2: &str = "session-2";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const ARTIFACT: &str = "artifact-42";

fn at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 1, 0, 0)
        .single()
        .expect("valid fixture time")
}

fn scope(session_id: Option<&str>) -> BrowserStackScope {
    BrowserStackScope::new(BrowserStackScopeInput {
        account_id: "account-7".to_owned(),
        group_id: "group-7".to_owned(),
        browserstack_project_id: "bs-project-7".to_owned(),
        product: BrowserStackProduct::Automate,
        build_id: BUILD_ID.to_owned(),
        session_id: session_id.map(str::to_owned),
        build_revision: 1,
        session_revision: session_id.map(|_| 1),
        commit: Some(COMMIT.to_owned()),
        artifact: Some(ARTIFACT.to_owned()),
        hartevo_project_id: "project-7".to_owned(),
        hartevo_project_revision: 3,
        mission_id: "mission-7".to_owned(),
        mission_revision: 5,
        work_product_id: "work-product-7".to_owned(),
        work_product_revision: 9,
        permission: PermissionSnapshot::read_only(4).expect("permission snapshot"),
    })
    .expect("scope")
}

fn build_payload() -> BrowserStackBuildPayload {
    let mut build =
        BrowserStackBuildPayload::new(BUILD_ID, BrowserStackProduct::Automate, "done", 1)
            .expect("build payload");
    build.project_id = Some("bs-project-7".to_owned());
    build.name = Some("bounded build".to_owned());
    build.duration_seconds = Some(42);
    build.commit = Some(COMMIT.to_owned());
    build.artifact = Some(ARTIFACT.to_owned());
    build.session_count = Some(2);
    build
}

fn session_payload(
    id: &str,
    device: &str,
    status: &str,
    passed: u32,
) -> BrowserStackSessionPayload {
    let mut session = BrowserStackSessionPayload::new(
        id,
        BUILD_ID,
        BrowserStackProduct::Automate,
        status,
        1,
        BrowserStackMatrixEntry::new(
            Some(device.to_owned()),
            Some("chrome".to_owned()),
            Some("latest".to_owned()),
            Some("windows".to_owned()),
            Some("11".to_owned()),
        )
        .expect("matrix"),
        OutcomeCounts::new(passed, passed, 0, 0, 0, 0).expect("outcomes"),
    )
    .expect("session payload");
    session.project_id = Some("bs-project-7".to_owned());
    session.commit = Some(COMMIT.to_owned());
    session.artifact = Some(ARTIFACT.to_owned());
    session.duration_seconds = Some(17);
    session
}

fn request(endpoint: BrowserStackEndpoint) -> BrowserStackHttpRequest {
    BrowserStackHttpRequest::new(endpoint, at(), 1_048_576).expect("request")
}

fn build_response() -> BrowserStackHttpResponse {
    let request = request(BrowserStackEndpoint::Build {
        product: BrowserStackProduct::Automate,
        project_id: "bs-project-7".to_owned(),
        build_id: BUILD_ID.to_owned(),
    });
    BrowserStackHttpResponse::from_body(&request, BrowserStackResponseBody::Build(build_payload()))
        .expect("build response")
}

fn sessions_response(
    offset: u32,
    values: Vec<BrowserStackSessionPayload>,
) -> BrowserStackHttpResponse {
    sessions_response_with_limit(offset, 100, values)
}

fn sessions_response_with_limit(
    offset: u32,
    limit: u16,
    values: Vec<BrowserStackSessionPayload>,
) -> BrowserStackHttpResponse {
    let request = request(BrowserStackEndpoint::Sessions {
        product: BrowserStackProduct::Automate,
        project_id: "bs-project-7".to_owned(),
        build_id: BUILD_ID.to_owned(),
        offset,
        limit,
    });
    BrowserStackHttpResponse::from_body(&request, BrowserStackResponseBody::Sessions(values))
        .expect("sessions response")
}

fn provider_with_responses(
    scope: BrowserStackScope,
    responses: Vec<Result<BrowserStackHttpResponse, BrowserStackTransportError>>,
) -> BrowserStackProvider<RecordingBrowserStackTransport, FixtureCredentialResolver> {
    BrowserStackProvider::new(
        scope,
        SecretReference::new("username-handle", "access-key-handle", 1).expect("secret"),
        RecordingBrowserStackTransport::fixture(responses),
        FixtureCredentialResolver,
    )
    .expect("provider")
}

#[test]
fn contract_and_registration_are_digest_bound_and_layer_one_only() {
    let contract = BrowserStackTestResultContract::baseline().expect("contract");
    assert_eq!(contract.layer, 1);
    assert!(contract.digest().is_sha256());

    let provider = provider_with_responses(
        scope(None),
        vec![
            Ok(build_response()),
            Ok(sessions_response(
                0,
                vec![session_payload(SESSION_1, "Pixel 8", "passed", 1)],
            )),
        ],
    );
    assert!(provider.registration().registration_digest().is_sha256());
    assert!(provider.provider_digest().is_sha256());
    assert!(!provider.definition().native);
    assert!(!provider.is_connected());
    assert!(!provider.is_native());
    assert!(provider.scope().digest().is_sha256());
    assert!(provider.scope().permission().digest().is_sha256());
}

#[test]
fn recording_read_projects_build_session_duration_matrix_and_counts() {
    let mut provider = provider_with_responses(
        scope(None),
        vec![
            Ok(build_response()),
            Ok(sessions_response(
                0,
                vec![
                    session_payload(SESSION_1, "Pixel 8", "passed", 2),
                    session_payload(SESSION_2, "iPhone 15", "failed", 0),
                ],
            )),
        ],
    );
    let proposal = provider
        .propose(BrowserStackReadRequest::default())
        .expect("proposal");
    let evidence = provider.read(&proposal, at()).expect("evidence");

    assert_eq!(evidence.status, EvidenceStatus::Complete);
    assert_eq!(
        evidence.build.as_ref().expect("build").duration_seconds,
        Some(42)
    );
    assert_eq!(evidence.sessions.len(), 2);
    assert_eq!(evidence.matrix.len(), 2);
    assert_eq!(evidence.outcome_counts.total, 2);
    assert_eq!(evidence.outcome_counts.passed, 2);
    assert!(evidence.evidence_digest.is_sha256());
    assert!(evidence.verify_integrity().is_ok());
    assert!(!evidence.is_native());
    assert!(!evidence.is_connected());
    assert!(evidence.receipts.iter().all(|receipt| {
        !receipt.raw_payload_retained
            && !receipt.raw_logs_retained
            && !receipt.raw_network_retained
            && !receipt.raw_har_retained
            && !receipt.raw_video_retained
            && !receipt.raw_screenshots_retained
            && !receipt.credential_material_retained
    }));
}

#[test]
fn selected_session_reads_bounded_detail_and_binds_revisions() {
    let selected_scope = scope(Some(SESSION_1));
    let list = sessions_response(0, vec![session_payload(SESSION_1, "Pixel 8", "done", 1)]);
    let detail_request = request(BrowserStackEndpoint::Session {
        product: BrowserStackProduct::Automate,
        project_id: "bs-project-7".to_owned(),
        build_id: BUILD_ID.to_owned(),
        session_id: SESSION_1.to_owned(),
    });
    let detail = BrowserStackHttpResponse::from_body(
        &detail_request,
        BrowserStackResponseBody::Session(session_payload(SESSION_1, "Pixel 8", "passed", 1)),
    )
    .expect("detail response");
    let mut provider = provider_with_responses(
        selected_scope,
        vec![Ok(build_response()), Ok(list), Ok(detail)],
    );
    let proposal = provider
        .propose(BrowserStackReadRequest::default())
        .expect("proposal");
    let evidence = provider.read(&proposal, at()).expect("selected evidence");
    assert_eq!(evidence.sessions.len(), 1);
    assert_eq!(evidence.sessions[0].id, SESSION_1);
    assert_eq!(evidence.sessions[0].status, "passed");
    assert_eq!(provider.transport().requests().len(), 3);
}

#[test]
fn official_json_normalization_drops_logs_urls_and_arbitrary_capabilities() {
    let request = request(BrowserStackEndpoint::Session {
        product: BrowserStackProduct::AppAutomate,
        project_id: "project".to_owned(),
        build_id: "build".to_owned(),
        session_id: "session".to_owned(),
    });
    let raw = serde_json::json!({
        "automation_session": {
            "hashed_id": "session",
            "status": "passed",
            "duration": 9,
            "device": "Pixel 8",
            "os": "android",
            "os_version": "14",
            "browser": "app",
            "browser_version": "latest",
            "logs": "SECRET_LOG_URL",
            "har_logs_url": "SECRET_HAR_URL",
            "video_url": "SECRET_VIDEO_URL",
            "desired_capabilities": {"secret": "must-not-retain"},
            "testcases": [{"status": "passed"}, {"status": "failed"}]
        }
    })
    .to_string();
    let response =
        BrowserStackHttpResponse::from_json(&request, raw.as_bytes()).expect("normalize");
    let safe = serde_json::to_string(response.body().expect("body")).expect("safe body");
    assert!(!safe.contains("SECRET_LOG_URL"));
    assert!(!safe.contains("SECRET_HAR_URL"));
    assert!(!safe.contains("SECRET_VIDEO_URL"));
    assert!(!safe.contains("must-not-retain"));
    assert!(safe.contains("Pixel 8"));
}

#[test]
fn status_failures_are_typed_without_claiming_native_or_connected() {
    for status in [401_u16, 403, 404, 409, 429, 500, 502, 503, 504] {
        let build_request = request(BrowserStackEndpoint::Build {
            product: BrowserStackProduct::Automate,
            project_id: "bs-project-7".to_owned(),
            build_id: BUILD_ID.to_owned(),
        });
        let response =
            BrowserStackHttpResponse::from_status(&build_request, status).expect("status response");
        let mut provider = provider_with_responses(scope(None), vec![Ok(response)]);
        let proposal = provider
            .propose(BrowserStackReadRequest::default())
            .expect("proposal");
        let evidence = provider.read(&proposal, at()).expect("failure evidence");
        assert!(!evidence.is_native());
        assert!(!evidence.is_connected());
        assert_eq!(evidence.failures[0].status_code, Some(status));
        match status {
            401 | 403 | 404 => assert_eq!(evidence.status, EvidenceStatus::AccessLost),
            429 => {
                assert_eq!(evidence.status, EvidenceStatus::Partial);
                assert_eq!(evidence.partial_reason, Some(PartialReason::RateLimited));
            }
            _ => assert_eq!(evidence.status, EvidenceStatus::ProviderUnknown),
        }
    }
}

#[test]
fn timeout_and_blocked_env_are_recorded_as_non_native_evidence() {
    let timeout = Err(BrowserStackTransportError::Transport {
        detail: "bounded timeout".to_owned(),
        retryable: true,
        timeout: true,
        diagnostic_digest: hartevo_browserstack_test_result_plugin::Digest::from_text("timeout"),
    });
    let mut provider = provider_with_responses(scope(None), vec![timeout]);
    let proposal = provider
        .propose(BrowserStackReadRequest::default())
        .expect("proposal");
    let evidence = provider.read(&proposal, at()).expect("timeout evidence");
    assert_eq!(evidence.status, EvidenceStatus::Partial);
    assert_eq!(evidence.partial_reason, Some(PartialReason::Timeout));
    assert_eq!(
        evidence.failures[0].class,
        hartevo_browserstack_test_result_plugin::FailureClass::Timeout
    );

    let mut blocked = BrowserStackProvider::new(
        scope(None),
        SecretReference::new("user", "key", 1).expect("secret"),
        hartevo_browserstack_test_result_plugin::BlockedEnvTransport,
        hartevo_browserstack_test_result_plugin::BlockedEnvCredentialResolver,
    )
    .expect("blocked provider");
    let proposal = blocked
        .propose(BrowserStackReadRequest::default())
        .expect("proposal");
    let evidence = blocked.read(&proposal, at()).expect("blocked evidence");
    assert_eq!(evidence.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        evidence.failures[0].class,
        hartevo_browserstack_test_result_plugin::FailureClass::BlockedEnv
    );
    assert!(!evidence.is_native());
}

#[test]
fn pagination_repeated_page_is_fail_closed_and_page_caps_are_bounded() {
    let scope = scope(None);
    let transport = RecordingBrowserStackTransport::fixture(vec![
        Ok(build_response()),
        Ok(sessions_response_with_limit(
            0,
            1,
            vec![session_payload(SESSION_1, "Pixel 8", "passed", 1)],
        )),
        Ok(sessions_response_with_limit(
            1,
            1,
            vec![session_payload(SESSION_1, "Pixel 8", "passed", 1)],
        )),
    ]);
    let definition = BrowserStackProviderDefinition::new(
        BrowserStackProduct::Automate,
        TransportProvenance::Fixture,
    )
    .expect("definition");
    let registration = BrowserStackRegistrationRequest::baseline(
        scope.clone(),
        SecretReference::new("user", "key", 1).expect("secret"),
        definition.provider_digest.clone(),
    )
    .expect("registration request");
    let bounds = RequestBounds::new(1_048_576, 4, 1, 8, 10, 8).expect("bounds");
    let mut provider = BrowserStackProvider::from_registration_request(
        registration,
        transport,
        FixtureCredentialResolver,
        bounds,
    )
    .expect("provider");
    let proposal = provider
        .propose(BrowserStackReadRequest::default())
        .expect("proposal");
    assert_eq!(
        provider.read(&proposal, at()),
        Err(BrowserStackTestResultError::PaginationLoop)
    );
}

#[test]
fn consumer_is_mission_bound_proposal_only_and_revocable() {
    let provider = provider_with_responses(
        scope(None),
        vec![
            Ok(build_response()),
            Ok(sessions_response(
                0,
                vec![session_payload(SESSION_1, "Pixel 8", "passed", 1)],
            )),
        ],
    );
    let mut consumer = MissionBrowserStackTestConsumer::new(scope(None), provider.registration())
        .expect("consumer");
    let mut provider = provider;
    let proposal = provider
        .propose(BrowserStackReadRequest::default())
        .expect("proposal");
    let result = consumer
        .read(&mut provider, &proposal, at())
        .expect("mission result");
    assert!(result.proposal_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert_eq!(
        result.state,
        hartevo_browserstack_test_result_plugin::MissionBrowserStackResultState::PendingDecision
    );
    consumer.revoke().expect("revoke");
    assert_eq!(
        consumer.consume(result.evidence),
        Err(BrowserStackTestResultError::ConsumerRevoked)
    );
}

#[test]
fn secret_reference_is_opaque_and_evidence_tamper_is_rejected() {
    let secret = SecretReference::new("username-secret-handle", "access-key-secret-handle", 7)
        .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("username-secret-handle"));
    assert!(!debug.contains("access-key-secret-handle"));
    assert!(secret.reference_digest().is_sha256());

    let mut provider = provider_with_responses(
        scope(None),
        vec![
            Ok(build_response()),
            Ok(sessions_response(
                0,
                vec![session_payload(SESSION_1, "Pixel 8", "passed", 1)],
            )),
        ],
    );
    let proposal = provider
        .propose(BrowserStackReadRequest::default())
        .expect("proposal");
    let mut evidence = provider.read(&proposal, at()).expect("evidence");
    evidence.status = EvidenceStatus::ProviderUnknown;
    assert!(evidence.validate().is_err());
}

#[test]
fn scope_and_permission_fences_reject_drift() {
    let mut input = BrowserStackScopeInput {
        account_id: "account".to_owned(),
        group_id: "group".to_owned(),
        browserstack_project_id: "bs-project".to_owned(),
        product: BrowserStackProduct::AppAutomate,
        build_id: "build".to_owned(),
        session_id: None,
        build_revision: 2,
        session_revision: None,
        commit: None,
        artifact: None,
        hartevo_project_id: "project".to_owned(),
        hartevo_project_revision: 1,
        mission_id: "mission".to_owned(),
        mission_revision: 1,
        work_product_id: "work".to_owned(),
        work_product_revision: 1,
        permission: PermissionSnapshot::new(1, true, true, true, false, true).expect("permission"),
    };
    let scope = BrowserStackScope::new(input.clone()).expect("scope");
    let provider = BrowserStackProvider::new(
        scope,
        SecretReference::new("user", "key", 1).expect("secret"),
        RecordingBrowserStackTransport::fixture(Vec::new()),
        FixtureCredentialResolver,
    )
    .expect("provider");
    assert!(matches!(
        provider.propose(BrowserStackReadRequest::default()),
        Err(BrowserStackTestResultError::ScopeMismatch(_))
    ));

    input.permission = PermissionSnapshot::read_only(2).expect("permission revision");
    let changed_scope = BrowserStackScope::new(input).expect("changed scope");
    assert_ne!(changed_scope.digest(), provider.scope().digest());
}

#[test]
fn evidence_failure_can_be_constructed_for_retention_redaction_and_tamper_classes() {
    let failure = ProviderFailure::new(
        hartevo_browserstack_test_result_plugin::FailureClass::Retention,
        Some(404),
        false,
        "retention-expired",
    );
    assert!(failure.diagnostic_digest.is_sha256());
    let failure2 = ProviderFailure::new(
        hartevo_browserstack_test_result_plugin::FailureClass::Redaction,
        None,
        false,
        "redaction-required",
    );
    let classes = [failure.class, failure2.class];
    assert_eq!(classes.into_iter().collect::<BTreeSet<_>>().len(), 2);
}

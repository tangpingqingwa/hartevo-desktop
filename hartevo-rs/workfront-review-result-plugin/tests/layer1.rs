use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_workfront_review_result_plugin::{
    ApprovalId, ApprovalReadResponse, ApprovalSnapshot, ApprovalStatus, BlockedEnvTransport,
    CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, ConsentScope, Cursor,
    Digest, DocumentId, EvidenceState, FixtureTransport, MissionIdentity, ProjectId,
    ProjectIdentity, ProjectReadResponse, ProjectSnapshot, ProjectStatus, RecordingTransport,
    ReviewId, ReviewReadResponse, ReviewSnapshot, ReviewStatus, SecretReference, TaskId,
    TaskReadResponse, TaskSnapshot, TaskStatus, TimeWindow, TransportProvenance,
    WorkProductIdentity, WorkfrontOperation, WorkfrontProvider, WorkfrontReadRequest,
    WorkfrontReviewResultContract, WorkfrontReviewResultError, WorkfrontReviewResultService,
    WorkfrontReviewScope, WorkfrontTransportError, contract_digest,
};
use proptest::prelude::*;
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_TENANT: &str = "tenant-acme-01";
const RAW_PROJECT: &str = "proj-620";
const RAW_TASK: &str = "task-620";
const RAW_DOCUMENT: &str = "document-620";
const RAW_REVIEW: &str = "review-620";
const RAW_APPROVAL: &str = "approval-620";
const RAW_ASSIGNEE: &str = "assignee-620";
const RAW_SECRET: &str = "oauth-live-material-must-not-escape";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> WorkfrontReviewScope {
    WorkfrontReviewScope::new(
        hartevo_workfront_review_result_plugin::TenantId::new(RAW_TENANT).expect("tenant"),
        ProjectId::new(RAW_PROJECT).expect("project"),
        TaskId::new(RAW_TASK).expect("task"),
        DocumentId::new(RAW_DOCUMENT).expect("document"),
        ReviewId::new(RAW_REVIEW).expect("review"),
        ApprovalId::new(RAW_APPROVAL).expect("approval"),
        hartevo_workfront_review_result_plugin::AssigneeId::new(RAW_ASSIGNEE).expect("assignee"),
        TimeWindow::new(now() - Duration::hours(2), now() + Duration::days(2)).expect("window"),
        MissionIdentity::new("mission-620", 7).expect("mission"),
        ProjectIdentity::new("hartevo-project-620", 11).expect("host project"),
        WorkProductIdentity::new("work-product-620", 13).expect("work product"),
    )
    .expect("scope")
}

fn fixture_service() -> WorkfrontReviewResultService<FixtureTransport> {
    let scope = scope();
    let provider = WorkfrontProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let secret = SecretReference::oauth_api(RAW_SECRET, &scope, 1).expect("secret");
    let consent =
        ConsentScope::for_layer_one("consent-620", 1, now() + Duration::days(7)).expect("consent");
    WorkfrontReviewResultService::new(scope, secret, consent, provider, now()).expect("service")
}

#[test]
fn contract_registration_and_secret_are_digest_bound() {
    let contract = WorkfrontReviewResultContract::baseline().expect("contract");
    assert_eq!(contract.digest().as_str(), contract_digest());
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(document["provider"]["connected"], false);
    assert_eq!(document["provider"]["native"], false);
    assert_eq!(document["provider"]["firstParty"], false);

    let service = fixture_service();
    let registration = service.registration();
    let encoded_registration = serde_json::to_string(registration).expect("registration JSON");
    let debug_registration = format!("{registration:?}");
    let secret = service.secret_reference();
    let encoded_secret = serde_json::to_string(secret).expect("secret JSON");
    let debug_secret = format!("{secret:?}");
    for rendered in [
        encoded_registration,
        debug_registration,
        encoded_secret,
        debug_secret,
    ] {
        assert!(!rendered.contains(RAW_SECRET));
        assert!(!rendered.contains("Authorization"));
    }
    assert!(
        serde_json::to_string(registration)
            .expect("registration JSON")
            .contains("secretReferenceDigest")
    );
    assert!(registration.validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 4);
    assert!(!service.describe_capabilities().approval_effects);
}

#[test]
fn fixture_proposal_is_bounded_review_only_and_recordable() {
    let mut service = fixture_service();
    let request = service.default_request(now()).expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Approved);
    assert_eq!(proposal.pages, 1);
    assert!(proposal.pagination_complete);
    assert!(proposal.project_state.is_some());
    assert!(proposal.task_state.is_some());
    assert!(proposal.review_state.is_some());
    assert!(proposal.approval_state.is_some());
    assert_eq!(proposal.decision_timestamps.len(), 2);
    assert_eq!(proposal.reviewer_role_digests.len(), 2);
    assert_eq!(proposal.request_receipts.len(), 4);
    assert_eq!(proposal.cost_receipts.len(), 4);
    assert!(
        proposal
            .request_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(
        proposal
            .cost_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.approval_effect);
    assert!(!proposal.document_bytes_retained);
    assert!(!proposal.reviewer_pii_retained);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());

    let rendered = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_TENANT,
        RAW_PROJECT,
        RAW_TASK,
        RAW_DOCUMENT,
        RAW_REVIEW,
        RAW_APPROVAL,
        RAW_ASSIGNEE,
        RAW_SECRET,
        "reviewer@example.com",
        "document-bytes",
    ] {
        assert!(!rendered.contains(raw), "raw value leaked: {raw}");
    }

    let verification = service.verify(&proposal);
    assert!(verification.valid);
    assert!(verification.review_eligible);
    assert!(!verification.provider_readback_performed);

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let recorded = consumer
        .record(&proposal, "idempotency-620")
        .expect("record");
    assert!(!recorded.replayed);
    assert!(recorded.validate_integrity().is_ok());
    let replay = consumer
        .record(&proposal, "idempotency-620")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn blocked_environment_is_provider_unknown_and_never_native() {
    let scope = scope();
    let provider = WorkfrontProvider::new(BlockedEnvTransport).expect("provider");
    assert!(!provider.definition().connected);
    assert!(!provider.definition().native);
    assert!(!provider.definition().first_party);
    let secret = SecretReference::oauth_api(RAW_SECRET, &scope, 1).expect("secret");
    let consent =
        ConsentScope::for_layer_one("consent-620", 1, now() + Duration::days(7)).expect("consent");
    let mut service = WorkfrontReviewResultService::new(scope, secret, consent, provider, now())
        .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn registration_revocation_is_digest_bound_and_reversible() {
    let mut service = fixture_service();
    let original_digest = service.registration().registration_digest().clone();
    let request = service.default_request(now()).expect("request");
    service.revoke_registration().expect("revoke");
    assert_ne!(
        service.registration().registration_digest(),
        &original_digest
    );
    assert!(!service.registration().is_active());
    assert!(matches!(
        service.propose(request),
        Err(WorkfrontReviewResultError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    let restored = service
        .propose(service.default_request(now()).expect("restored request"))
        .expect("restored proposal");
    assert_eq!(restored.state, EvidenceState::Approved);
    service.reverse_registration().expect("reverse");
    assert!(matches!(
        service.restore_registration(),
        Err(WorkfrontReviewResultError::RegistrationReversed)
    ));
}

#[test]
fn tampered_stale_and_raw_review_data_fail_closed() {
    let scope = scope();
    let provider = WorkfrontProvider::new(RecordingTransport::new()).expect("provider");
    let secret = SecretReference::oauth_api(RAW_SECRET, &scope, 1).expect("secret");
    let consent =
        ConsentScope::for_layer_one("consent-620", 1, now() + Duration::days(7)).expect("consent");
    let service =
        WorkfrontReviewResultService::new(scope.clone(), secret, consent, provider, now())
            .expect("service");
    let request = service.default_request(now()).expect("request");
    let read_request = WorkfrontReadRequest::new(
        WorkfrontOperation::ReadProject,
        &scope,
        service.registration().registration_digest(),
        100,
        1,
        None,
        now(),
    )
    .expect("read request");
    let stale = ProjectSnapshot::new(scope.project().clone(), ProjectStatus::Active, 99, now())
        .expect("stale snapshot");
    let tampered = ProjectReadResponse::new(
        &read_request,
        stale,
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered-response"));
    assert!(!service.provider().definition().connected);

    let mut transport = RecordingTransport::new();
    transport.push_project_response(Ok(tampered));
    let provider = WorkfrontProvider::new(transport).expect("recording provider");
    let secret = SecretReference::oauth_api(RAW_SECRET, &scope, 1).expect("secret");
    let consent =
        ConsentScope::for_layer_one("consent-620", 1, now() + Duration::days(7)).expect("consent");
    let mut service = WorkfrontReviewResultService::new(scope, secret, consent, provider, now())
        .expect("service");
    let proposal = service.propose(request).expect("fail-closed proposal");
    assert_eq!(proposal.state, EvidenceState::Tampered);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn opaque_cursor_loop_and_response_scope_are_rejected() {
    let scope = scope();
    let provider = WorkfrontProvider::new(RecordingTransport::new()).expect("provider");
    let secret = SecretReference::oauth_api(RAW_SECRET, &scope, 1).expect("secret");
    let consent =
        ConsentScope::for_layer_one("consent-620", 1, now() + Duration::days(7)).expect("consent");
    let service =
        WorkfrontReviewResultService::new(scope.clone(), secret, consent, provider, now())
            .expect("service");
    let request = service.request(100, 1, now()).expect("request");
    let cursored = Cursor::new(
        "opaque-marker-a",
        &WorkfrontReadRequest::new(
            WorkfrontOperation::ReadProject,
            &scope,
            service.registration().registration_digest(),
            100,
            1,
            None,
            now(),
        )
        .expect("cursor source")
        .digest(),
        &scope.digest(),
        1,
    )
    .expect("cursor");
    assert!(
        !serde_json::to_string(&cursored)
            .expect("cursor JSON")
            .contains("opaque-marker-a")
    );

    let first_requests = [
        WorkfrontOperation::ReadProject,
        WorkfrontOperation::ReadTask,
        WorkfrontOperation::ReadReview,
        WorkfrontOperation::ReadApproval,
    ]
    .map(|operation| {
        WorkfrontReadRequest::new(
            operation,
            &scope,
            service.registration().registration_digest(),
            100,
            1,
            None,
            now(),
        )
        .expect("first request")
    });
    let project = ProjectReadResponse::new(
        &first_requests[0],
        ProjectSnapshot::new(scope.project().clone(), ProjectStatus::Active, 1, now())
            .expect("project"),
        Some(cursored.clone()),
        100,
        TransportProvenance::Recording,
    )
    .expect("project response");
    let task = TaskReadResponse::new(
        &first_requests[1],
        TaskSnapshot::new(scope.task().clone(), TaskStatus::InProgress, 50, 1, now())
            .expect("task"),
        Some(cursored.clone()),
        100,
        TransportProvenance::Recording,
    )
    .expect("task response");
    let review = ReviewReadResponse::new(
        &first_requests[2],
        ReviewSnapshot::new(
            scope.review().clone(),
            ReviewStatus::InReview,
            1,
            Some(now()),
            None,
            ["reviewer@example.com"],
        )
        .expect("review"),
        Some(cursored.clone()),
        100,
        TransportProvenance::Recording,
    )
    .expect("review response");
    let approval = ApprovalReadResponse::new(
        &first_requests[3],
        ApprovalSnapshot::new(
            scope.approval().clone(),
            ApprovalStatus::InReview,
            1,
            None,
            ["reviewer@example.com"],
        )
        .expect("approval"),
        Some(cursored.clone()),
        100,
        TransportProvenance::Recording,
    )
    .expect("approval response");
    let mut transport = RecordingTransport::new();
    transport.push_project_response(Ok(project));
    transport.push_task_response(Ok(task));
    transport.push_review_response(Ok(review));
    transport.push_approval_response(Ok(approval));
    let provider = WorkfrontProvider::new(transport).expect("recording provider");
    let secret = SecretReference::oauth_api(RAW_SECRET, &scope, 1).expect("secret");
    let consent =
        ConsentScope::for_layer_one("consent-620", 1, now() + Duration::days(7)).expect("consent");
    let mut service = WorkfrontReviewResultService::new(scope, secret, consent, provider, now())
        .expect("service");
    let proposal = service.propose(request).expect("loop proposal");
    assert_eq!(proposal.state, EvidenceState::Partial);
    assert!(!proposal.pagination_complete);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn all_layer1_transport_provenance_is_non_native() {
    let scope = scope();
    let values = [
        TransportProvenance::Recording,
        TransportProvenance::Fixture,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ];
    for provenance in values {
        assert!(!provenance.is_connected());
        assert!(!provenance.is_native());
        assert!(!provenance.is_first_party());
    }
    assert_eq!(TransportProvenance::Fixture.as_str(), "fixture");
    let loopback = WorkfrontProvider::new(
        hartevo_workfront_review_result_plugin::LoopbackTransport::for_scope(&scope, now()),
    )
    .expect("loopback provider");
    assert_eq!(loopback.provenance(), TransportProvenance::Loopback);
}

#[test]
fn status_errors_are_redacted_and_secret_revocation_fails_closed() {
    assert_eq!(
        WorkfrontTransportError::Unauthorized.status_code(),
        Some(401)
    );
    assert!(WorkfrontTransportError::Forbidden.is_access_loss());
    let scope = scope();
    let mut secret = SecretReference::oauth_api(RAW_SECRET, &scope, 1).expect("secret");
    secret.revoke();
    let provider = WorkfrontProvider::new(BlockedEnvTransport).expect("provider");
    let consent =
        ConsentScope::for_layer_one("consent-620", 1, now() + Duration::days(7)).expect("consent");
    let mut service = WorkfrontReviewResultService::new(scope, secret, consent, provider, now())
        .expect("service allows opaque revoked reference to fail at read");
    assert!(matches!(
        service.propose(service.default_request(now()).expect("request")),
        Err(WorkfrontReviewResultError::SecretRevoked)
    ));
}

proptest! {
    #[test]
    fn arbitrary_identifier_text_never_escapes_as_raw_digest_input(value in "[a-zA-Z0-9_-]{1,64}") {
        let id = hartevo_workfront_review_result_plugin::TenantId::new(value.clone()).expect("id");
        let digest = id.digest();
        prop_assert_eq!(digest.clone(), Digest::from_text(&value));
        prop_assert_ne!(digest.as_str(), value);
    }
}

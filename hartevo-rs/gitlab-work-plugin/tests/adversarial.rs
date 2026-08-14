use std::collections::BTreeSet;

use hartevo_gitlab_work_plugin::{
    ApprovalState, BlockedEnvTransport, CONTRACT_VERSION, Capability, CommitSha, Digest,
    GitLabHost, GitLabProjectId, GitLabScope, GitLabScopeSpec, GitLabWorkError, GitLabWorkProvider,
    GlobalGitLabId, HartevoProjectId, IssueIid, IssueState, JobId, MergeRequestIid, MergeStatus,
    MissionGitLabWorkConsumer, MissionId, MissionScope, PaginationBounds, PipelineId,
    PipelineStatus, ProviderProvenance, ProviderRevision, RecordingTransport,
    RecordingWebhookVerifier, RefName, RegistrationProbeStatus, RequestOperation, SecretReference,
    TransportError, TransportResponse, WebhookEnvelope, WorkProposalKind, contract_digest,
};
use serde_json::{Value, json};

const SOURCE_SHA: &str = "1111111111111111111111111111111111111111";
const TARGET_SHA: &str = "2222222222222222222222222222222222222222";
const HEAD_SHA: &str = "3333333333333333333333333333333333333333";

fn mission_scope() -> MissionScope {
    MissionScope::new(
        MissionId::parse("mission-318").expect("mission"),
        7,
        HartevoProjectId::parse("project-318").expect("project"),
        11,
        hartevo_gitlab_work_plugin::WorkProductId::parse("work-product-318").expect("work product"),
        13,
    )
    .expect("mission scope")
}

fn issue_scope(host: GitLabHost) -> GitLabScope {
    GitLabScope::new(GitLabScopeSpec {
        host,
        namespace: hartevo_gitlab_work_plugin::NamespacePath::parse("acme/platform")
            .expect("namespace"),
        project_id: GitLabProjectId::new(42).expect("project id"),
        issue_iid: Some(IssueIid::new(7).expect("issue IID")),
        merge_request_iid: None,
        source_ref: None,
        target_ref: None,
        source_sha: None,
        target_sha: None,
        head_sha: None,
        pipeline_id: None,
        job_ids: Vec::new(),
        mission: mission_scope(),
    })
    .expect("issue scope")
}

fn merge_request_scope(with_pipeline: bool) -> GitLabScope {
    GitLabScope::new(GitLabScopeSpec {
        host: GitLabHost::gitlab_com(),
        namespace: hartevo_gitlab_work_plugin::NamespacePath::parse("acme/platform")
            .expect("namespace"),
        project_id: GitLabProjectId::new(42).expect("project id"),
        issue_iid: None,
        merge_request_iid: Some(MergeRequestIid::new(9).expect("MR IID")),
        source_ref: Some(RefName::parse("feature/gitlab-work").expect("source ref")),
        target_ref: Some(RefName::parse("main").expect("target ref")),
        source_sha: Some(CommitSha::parse(SOURCE_SHA).expect("source SHA")),
        target_sha: Some(CommitSha::parse(TARGET_SHA).expect("target SHA")),
        head_sha: Some(CommitSha::parse(HEAD_SHA).expect("head SHA")),
        pipeline_id: with_pipeline.then(|| PipelineId::new(88).expect("pipeline id")),
        job_ids: if with_pipeline {
            vec![
                JobId::new(101).expect("job id"),
                JobId::new(102).expect("job id"),
            ]
        } else {
            Vec::new()
        },
        mission: mission_scope(),
    })
    .expect("MR scope")
}

fn capabilities() -> BTreeSet<Capability> {
    BTreeSet::from([
        Capability::DescribeCapabilities,
        Capability::ProbeRegistration,
        Capability::ReadIssueGraph,
        Capability::ReadMergeRequest,
        Capability::ReadPipelineResult,
        Capability::CompileIssueProposal,
        Capability::CompileMergeRequestProposal,
        Capability::VerifyWebhookEnvelope,
    ])
}

fn registered_provider(
    transport: RecordingTransport,
    scope: GitLabScope,
) -> GitLabWorkProvider<RecordingTransport> {
    let mut provider = GitLabWorkProvider::new(transport);
    let secret = SecretReference::pat("vault/gitlab/issue-318").expect("opaque secret reference");
    let request = hartevo_gitlab_work_plugin::RegistrationRequest::new(
        "gitlab-work-plugin/1.0.0",
        CONTRACT_VERSION,
        contract_digest(),
        hartevo_gitlab_work_plugin::PROVIDER_ID,
        scope.host.clone(),
        scope,
        ProviderRevision::parse("registration-revision-1").expect("provider revision"),
        secret,
        capabilities(),
    )
    .expect("registration request");
    provider.register(request).expect("registration");
    provider
}

fn response(
    status: u16,
    origin: &str,
    path: &str,
    revision: &str,
    value: &Value,
) -> TransportResponse {
    TransportResponse::json(status, format!("{origin}{path}"), revision, value)
        .expect("fixture response")
}

fn issue_body(project_id: u64, iid: u64) -> Value {
    json!({
        "id": 9001,
        "iid": iid,
        "project_id": project_id,
        "title": "Bounded GitLab issue",
        "description": "fixture-provider-body-must-not-escape",
        "state": "opened",
        "updated_at": "2026-08-14T08:00:00Z",
        "web_url": "https://gitlab.com/acme/platform/-/issues/7"
    })
}

fn merge_request_body(head_sha: &str) -> Value {
    json!({
        "id": 9002,
        "iid": 9,
        "project_id": 42,
        "title": "Read-only GitLab MR",
        "state": "opened",
        "draft": false,
        "source_branch": "feature/gitlab-work",
        "target_branch": "main",
        "sha": head_sha,
        "diff_refs": {
            "base_sha": TARGET_SHA,
            "start_sha": SOURCE_SHA,
            "head_sha": head_sha
        },
        "merge_status": "checking",
        "detailed_merge_status": "mergeable_state_unknown",
        "updated_at": "2026-08-14T08:01:00Z",
        "web_url": "https://gitlab.com/acme/platform/-/merge_requests/9"
    })
}

fn approvals_body(project_id: u64, approved: Option<bool>, approvals_left: u32) -> Value {
    json!({
        "project_id": project_id,
        "iid": 9,
        "approvals_before_merge": 2,
        "approvals_left": approvals_left,
        "approved": approved,
        "approved_by": [{"user": {"id": 77}, "approved_at": "2026-08-14T08:01:30Z"}]
    })
}

fn pipeline_body() -> Value {
    json!({
        "id": 88,
        "project_id": 42,
        "sha": HEAD_SHA,
        "ref": "main",
        "status": "running",
        "updated_at": "2026-08-14T08:02:00Z"
    })
}

fn jobs_body(ids: &[u64]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| {
                json!({
                    "id": id,
                    "name": format!("job-{id}"),
                    "stage": "test",
                    "status": "success",
                    "commit": {"id": HEAD_SHA},
                    "pipeline": {"id": 88}
                })
            })
            .collect(),
    )
}

#[test]
fn typed_service_provider_consumer_are_read_only_and_block_native_claims() {
    let scope = issue_scope(GitLabHost::gitlab_com());
    let provider = registered_provider(RecordingTransport::fixture([]), scope.clone());
    let service = provider.service();
    assert_eq!(service.service_id, hartevo_gitlab_work_plugin::SERVICE_ID);
    assert_eq!(service.provider_id, hartevo_gitlab_work_plugin::PROVIDER_ID);
    assert!(service.read_only);
    assert!(!service.connected);
    assert!(!service.native_evidence);
    assert!(!service.first_party_evidence);
    assert!(
        service
            .describe_capabilities()
            .iter()
            .all(|capability| capability.read_only
                && !capability.mutates_provider
                && !capability.native_evidence)
    );
    let probe = provider.probe_registration().expect("probe seam");
    assert_eq!(probe.status, RegistrationProbeStatus::BlockedEnv);
    assert!(!probe.native_credentials_resolved);
    assert!(!probe.live_https_verified);
    assert_eq!(probe.scope_fence, scope.fence());
    let consumer = MissionGitLabWorkConsumer::new(scope);
    assert_eq!(consumer.scope().mission.mission_revision, 7);
}

#[test]
fn registration_is_contract_scope_bound_reversible_and_revocable() {
    let scope = issue_scope(GitLabHost::gitlab_com());
    let secret = SecretReference::oauth("vault/gitlab/oauth-ref").expect("secret reference");
    let bad_request = hartevo_gitlab_work_plugin::RegistrationRequest::new(
        "gitlab-work-plugin/1.0.0",
        CONTRACT_VERSION,
        Digest::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("digest"),
        hartevo_gitlab_work_plugin::PROVIDER_ID,
        scope.host.clone(),
        scope.clone(),
        ProviderRevision::parse("registration-revision-1").expect("revision"),
        secret.clone(),
        capabilities(),
    )
    .expect("request");
    let mut provider = GitLabWorkProvider::new(RecordingTransport::fixture([response(
        200,
        "https://gitlab.com",
        "/api/v4/projects/42/issues/7",
        "provider-revision-1",
        &issue_body(42, 7),
    )]));
    assert!(matches!(
        provider.register(bad_request),
        Err(GitLabWorkError::ContractDigestMismatch)
    ));
    let registration = provider
        .register(
            hartevo_gitlab_work_plugin::RegistrationRequest::new(
                "gitlab-work-plugin/1.0.0",
                CONTRACT_VERSION,
                contract_digest(),
                hartevo_gitlab_work_plugin::PROVIDER_ID,
                scope.host.clone(),
                scope.clone(),
                ProviderRevision::parse("registration-revision-1").expect("revision"),
                secret,
                capabilities(),
            )
            .expect("request"),
        )
        .expect("registration");
    let original_fence = registration.registration_fence();
    let consumer = MissionGitLabWorkConsumer::new(scope.clone());
    let first = consumer
        .read_issue_graph(&mut provider, PaginationBounds::default())
        .expect("first read");
    provider.revoke_registration().expect("revoke");
    assert!(matches!(
        consumer.read_issue_graph(&mut provider, PaginationBounds::default()),
        Err(GitLabWorkError::RegistrationRevoked)
    ));
    let restored = provider.reinstate_registration().expect("reinstate");
    assert_ne!(original_fence, restored.registration_fence);
    assert!(matches!(
        consumer.compile_issue_proposal(&provider, &first.value),
        Err(GitLabWorkError::StaleProjection)
    ));
}

#[test]
fn secret_reference_and_transport_receipts_redact_tokens_and_payloads() {
    let secret = SecretReference::pat("vault/gitlab/pat-ref").expect("secret reference");
    let secret_debug = format!("{secret:?}");
    let secret_json = serde_json::to_string(&secret).expect("secret JSON");
    assert!(!secret_debug.contains("vault/gitlab/pat-ref"));
    assert!(!secret_debug.contains("fixture-token"));
    assert!(secret_json.contains("pat-ref"));
    assert!(!secret_json.contains("fixture-token"));

    let scope = issue_scope(GitLabHost::gitlab_com());
    let transport = RecordingTransport::fixture([response(
        200,
        "https://gitlab.com",
        "/api/v4/projects/42/issues/7",
        "provider-revision-1",
        &issue_body(42, 7),
    )]);
    let mut provider = registered_provider(transport, scope.clone());
    let read = provider
        .read_issue_graph(&scope, PaginationBounds::default())
        .expect("issue read");
    let receipt_json = serde_json::to_string(&read.receipts[0]).expect("receipt JSON");
    let transport_debug = format!("{:?}", provider.transport());
    assert!(!receipt_json.contains("fixture-provider-body"));
    assert!(!receipt_json.contains("fixture-token"));
    assert!(!transport_debug.contains("fixture-provider-body"));
    assert!(transport_debug.contains("redacted"));
    assert!(!read.receipts[0].raw_payload_retained);
    assert!(!read.receipts[0].credential_material_retained);
}

#[test]
fn project_global_id_and_iid_are_distinct_and_cross_origin_redirects_fail_closed() {
    let scope = issue_scope(GitLabHost::gitlab_com());
    let mut provider = registered_provider(
        RecordingTransport::fixture([response(
            200,
            "https://gitlab.com",
            "/api/v4/projects/42/issues/7",
            "provider-revision-1",
            &issue_body(42, 900),
        )]),
        scope.clone(),
    );
    assert!(matches!(
        provider.read_issue_graph(&scope, PaginationBounds::default()),
        Err(GitLabWorkError::IssueIidMismatch)
    ));

    let mut redirected = registered_provider(
        RecordingTransport::fixture([response(
            200,
            "https://evil.example",
            "/api/v4/projects/42/issues/7",
            "provider-revision-1",
            &issue_body(42, 7),
        )]),
        scope.clone(),
    );
    assert!(matches!(
        redirected.read_issue_graph(&scope, PaginationBounds::default()),
        Err(GitLabWorkError::CrossOriginRedirect { .. })
    ));
    assert!(GitLabHost::parse("https://gitlab.com").is_ok());
    assert!(GitLabHost::parse("http://gitlab.com").is_err());
    assert!(GitLabHost::parse("https://gitlab.example/gitlab").is_err());
    let success_scope = scope;
    let mut distinct = registered_provider(
        RecordingTransport::fixture([response(
            200,
            "https://gitlab.com",
            "/api/v4/projects/42/issues/7",
            "provider-revision-1",
            &issue_body(42, 7),
        )]),
        success_scope.clone(),
    );
    let read = distinct
        .read_issue_graph(&success_scope, PaginationBounds::default())
        .expect("project-scoped IID");
    assert_eq!(
        read.value.project_id,
        GitLabProjectId::new(42).expect("project")
    );
    assert_eq!(read.value.iid, IssueIid::new(7).expect("IID"));
    assert_eq!(
        read.value.global_id,
        GlobalGitLabId::new(9001).expect("global id")
    );
    assert_eq!(read.value.state, IssueState::Opened);
}

#[test]
fn force_push_stale_sha_and_approval_mismatch_never_become_proposals() {
    let scope = merge_request_scope(false);
    let stale_head = "4444444444444444444444444444444444444444";
    let mut stale_provider = registered_provider(
        RecordingTransport::fixture([
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/merge_requests/9",
                "provider-revision-1",
                &merge_request_body(stale_head),
            ),
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/merge_requests/9/approvals",
                "provider-revision-1",
                &approvals_body(42, Some(false), 1),
            ),
        ]),
        scope.clone(),
    );
    assert!(matches!(
        stale_provider.read_merge_request(&scope, PaginationBounds::default()),
        Err(GitLabWorkError::ShaFenceMismatch { field: "head_sha" })
    ));

    let mut approval_provider = registered_provider(
        RecordingTransport::fixture([
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/merge_requests/9",
                "provider-revision-1",
                &merge_request_body(HEAD_SHA),
            ),
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/merge_requests/9/approvals",
                "provider-revision-1",
                &approvals_body(999, Some(false), 1),
            ),
        ]),
        scope.clone(),
    );
    assert!(matches!(
        approval_provider.read_merge_request(&scope, PaginationBounds::default()),
        Err(GitLabWorkError::ApprovalMismatch)
    ));

    let mut valid_provider = registered_provider(
        RecordingTransport::fixture([
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/merge_requests/9",
                "provider-revision-1",
                &merge_request_body(HEAD_SHA),
            ),
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/merge_requests/9/approvals",
                "provider-revision-1",
                &approvals_body(42, Some(false), 1),
            ),
        ]),
        scope.clone(),
    );
    let read = valid_provider
        .read_merge_request(&scope, PaginationBounds::default())
        .expect("valid MR read");
    assert_eq!(read.approval.state, ApprovalState::NeedsApproval);
    assert_eq!(read.merge_request.merge_status, MergeStatus::Checking);
    assert_eq!(read.merge_request.merge_status.eligible(), None);
    let consumer = MissionGitLabWorkConsumer::new(scope);
    let proposal = consumer
        .compile_merge_request_proposal(&valid_provider, &read)
        .expect("observation proposal");
    assert_eq!(proposal.kind, WorkProposalKind::MergeRequestObservation);
    assert!(proposal.non_mutating);
    assert!(!proposal.creates_effect);
    assert!(!proposal.adopts_work_product);
}

#[test]
fn pipeline_jobs_are_bounded_paginated_sha_checked_and_fenced() {
    let scope = merge_request_scope(true);
    let page_one = response(
        200,
        "https://gitlab.com",
        "/api/v4/projects/42/pipelines/88/jobs?page=1",
        "provider-revision-2",
        &jobs_body(&[101]),
    )
    .with_header("x-next-page", "2")
    .with_header("ratelimit-remaining", "17");
    let page_two = response(
        200,
        "https://gitlab.com",
        "/api/v4/projects/42/pipelines/88/jobs?page=2",
        "provider-revision-2",
        &jobs_body(&[102]),
    )
    .with_header("x-next-page", "0");
    let mut provider = registered_provider(
        RecordingTransport::fixture([
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/pipelines/88",
                "provider-revision-2",
                &pipeline_body(),
            ),
            page_one,
            page_two,
        ]),
        scope.clone(),
    );
    let consumer = MissionGitLabWorkConsumer::new(scope.clone());
    let read = consumer
        .read_pipeline_result(&mut provider, PaginationBounds::default())
        .expect("pipeline read");
    assert_eq!(read.receipts.len(), 3);
    assert_eq!(read.pipeline.jobs.len(), 2);
    assert_eq!(read.pipeline.status, PipelineStatus::Running);
    assert_eq!(read.receipts[1].rate_limit.remaining, Some(17));
    assert!(
        read.receipts
            .iter()
            .all(|receipt| !receipt.raw_payload_retained && !receipt.credential_material_retained)
    );
    let requests = provider.transport().requests();
    assert_eq!(requests[0].operation, RequestOperation::Pipeline);
    assert_eq!(requests[1].operation, RequestOperation::PipelineJobs);
    assert_eq!(requests[1].page, 1);
    assert_eq!(requests[2].page, 2);
    let proposal = consumer
        .compile_pipeline_result_proposal(&provider, &read)
        .expect("pipeline proposal");
    assert_eq!(
        proposal
            .sha_fence
            .source_sha
            .as_ref()
            .map(CommitSha::as_str),
        Some(SOURCE_SHA)
    );
    assert_eq!(
        proposal
            .sha_fence
            .target_sha
            .as_ref()
            .map(CommitSha::as_str),
        Some(TARGET_SHA)
    );
    assert_eq!(
        proposal.sha_fence.head_sha.as_ref().map(CommitSha::as_str),
        Some(HEAD_SHA)
    );
    assert!(proposal.non_mutating);
    assert!(!proposal.native_evidence);
}

#[test]
fn pagination_loop_item_bound_and_rate_limit_are_fail_closed() {
    let scope = merge_request_scope(true);
    let loop_response = response(
        200,
        "https://gitlab.com",
        "/api/v4/projects/42/pipelines/88/jobs?page=1",
        "provider-revision-2",
        &jobs_body(&[101]),
    )
    .with_header("x-next-page", "1");
    let mut loop_provider = registered_provider(
        RecordingTransport::fixture([
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/pipelines/88",
                "provider-revision-2",
                &pipeline_body(),
            ),
            loop_response,
        ]),
        scope.clone(),
    );
    assert!(matches!(
        loop_provider.read_pipeline_result(&scope, PaginationBounds::default()),
        Err(GitLabWorkError::PaginationLoop)
    ));

    let mut bounded_provider = registered_provider(
        RecordingTransport::fixture([
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/pipelines/88",
                "provider-revision-2",
                &pipeline_body(),
            ),
            response(
                200,
                "https://gitlab.com",
                "/api/v4/projects/42/pipelines/88/jobs?page=1",
                "provider-revision-2",
                &jobs_body(&[101, 102]),
            ),
        ]),
        scope.clone(),
    );
    let bounds = PaginationBounds::new(2, 1, 100_000, 50).expect("bounds");
    assert!(matches!(
        bounded_provider.read_pipeline_result(&scope, bounds),
        Err(GitLabWorkError::ItemLimitExceeded)
    ));

    let mut sha_mismatch_provider = registered_provider(
        RecordingTransport::fixture([response(
            200,
            "https://gitlab.com",
            "/api/v4/projects/42/pipelines/88",
            "provider-revision-2",
            &json!({
                "id": 88,
                "project_id": 42,
                "sha": TARGET_SHA,
                "ref": "main",
                "status": "failed"
            }),
        )]),
        scope.clone(),
    );
    assert!(matches!(
        sha_mismatch_provider.read_pipeline_result(&scope, PaginationBounds::default()),
        Err(GitLabWorkError::PipelineShaMismatch)
    ));

    let rate_limited = response(
        429,
        "https://gitlab.com",
        "/api/v4/projects/42/pipelines/88",
        "provider-revision-2",
        &json!({"message": "rate limited"}),
    )
    .with_header("retry-after", "30")
    .with_header("ratelimit-remaining", "0");
    let mut rate_provider =
        registered_provider(RecordingTransport::fixture([rate_limited]), scope.clone());
    let error = rate_provider
        .read_pipeline_result(&scope, PaginationBounds::default())
        .expect_err("rate limit");
    match error {
        GitLabWorkError::RateLimited { receipt } => {
            assert_eq!(receipt.rate_limit.remaining, Some(0));
            assert_eq!(receipt.rate_limit.retry_after_seconds, Some(30));
            assert!(!receipt.raw_payload_retained);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn webhook_verification_has_origin_timestamp_signature_and_replay_fences() {
    let scope = issue_scope(GitLabHost::gitlab_com());
    let mut provider = registered_provider(RecordingTransport::fixture([]), scope);
    let body = br#"{"event":"merge_request"}"#;
    let envelope = WebhookEnvelope::new(
        GitLabHost::gitlab_com(),
        GitLabProjectId::new(42).expect("project"),
        "delivery-1",
        "Merge Request Hook",
        1_000,
        body,
        "fixture-signature",
    )
    .expect("webhook envelope");
    let verifier = RecordingWebhookVerifier::accepting("fixture-signature");
    let signal = provider
        .verify_webhook_envelope(&envelope, 1_005, 30, &verifier)
        .expect("verified signal");
    assert!(signal.change_signal_only);
    assert!(!signal.accepted_as_truth);
    assert!(!signal.receipt.accepted_as_truth);
    assert!(signal.receipt.requires_readback);
    assert_eq!(
        signal.receipt.provider_provenance,
        ProviderProvenance::Fixture
    );
    let signal_json = serde_json::to_string(&signal).expect("signal JSON");
    assert!(!signal_json.contains("event\\\":\\\"merge_request"));
    assert!(matches!(
        provider.verify_webhook_envelope(&envelope, 1_005, 30, &verifier),
        Err(GitLabWorkError::WebhookReplay)
    ));

    let bad_signature = WebhookEnvelope::new(
        GitLabHost::gitlab_com(),
        GitLabProjectId::new(42).expect("project"),
        "delivery-2",
        "Merge Request Hook",
        1_000,
        body,
        "wrong-signature",
    )
    .expect("webhook envelope");
    assert!(matches!(
        provider.verify_webhook_envelope(&bad_signature, 1_005, 30, &verifier),
        Err(GitLabWorkError::WebhookSignatureInvalid)
    ));
    let stale = WebhookEnvelope::new(
        GitLabHost::gitlab_com(),
        GitLabProjectId::new(42).expect("project"),
        "delivery-3",
        "Merge Request Hook",
        900,
        body,
        "fixture-signature",
    )
    .expect("webhook envelope");
    assert!(matches!(
        provider.verify_webhook_envelope(&stale, 1_005, 30, &verifier),
        Err(GitLabWorkError::WebhookTimestampOutsideWindow)
    ));
    let wrong_origin = WebhookEnvelope::new(
        GitLabHost::self_managed("https://gitlab.example.com").expect("host"),
        GitLabProjectId::new(42).expect("project"),
        "delivery-4",
        "Merge Request Hook",
        1_000,
        body,
        "fixture-signature",
    )
    .expect("webhook envelope");
    assert!(matches!(
        provider.verify_webhook_envelope(&wrong_origin, 1_005, 30, &verifier),
        Err(GitLabWorkError::WebhookOriginMismatch)
    ));
}

#[test]
fn fixture_recording_loopback_and_blocked_env_never_claim_connected_native_or_first_party() {
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Loopback,
    ] {
        let scope = issue_scope(GitLabHost::gitlab_com());
        let provider = registered_provider(RecordingTransport::new(provenance, []), scope);
        assert!(!provider.service().connected);
        assert!(!provider.service().native_evidence);
        assert!(!provider.service().first_party_evidence);
        assert!(!provenance.is_connected());
        assert!(!provenance.is_native());
        assert!(!provenance.is_first_party());
    }
    let scope = issue_scope(GitLabHost::gitlab_com());
    let secret = SecretReference::pat("vault/gitlab/blocked").expect("secret");
    let mut provider = GitLabWorkProvider::new(BlockedEnvTransport);
    provider
        .register(
            hartevo_gitlab_work_plugin::RegistrationRequest::new(
                "gitlab-work-plugin/1.0.0",
                CONTRACT_VERSION,
                contract_digest(),
                hartevo_gitlab_work_plugin::PROVIDER_ID,
                scope.host.clone(),
                scope.clone(),
                ProviderRevision::parse("registration-revision-1").expect("revision"),
                secret,
                capabilities(),
            )
            .expect("request"),
        )
        .expect("registration");
    assert!(matches!(
        provider.read_issue_graph(&scope, PaginationBounds::default()),
        Err(GitLabWorkError::Transport(TransportError::BlockedEnv))
    ));
}

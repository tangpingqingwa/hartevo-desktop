use std::collections::BTreeMap;

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_connector_sdk::authenticated_probe::SecretMaterial;
use hartevo_connector_sdk::{
    ConnectorAuth, ConnectorScope, ProviderAdapterIdentity, ProviderProvenanceClass,
    SecretReference,
};
use hartevo_domain_kernel::{
    Mission, MissionContract, MissionId, ProjectId, TenantId, WorkProduct, WorkProductId,
};

use crate::model::{
    GithubAccountPayload, GithubCheckRunPayload, GithubGitRefPayload, GithubHttpResponseBody,
    GithubHttpResponseReceipt, GithubInstallationPayload, GithubIssuePayload,
    GithubPullRequestPayload, GithubRateLimitReceipt, GithubRepositoryPayload,
};
use crate::{
    GITHUB_API_VERSION, GITHUB_REQUIRED_PERMISSIONS, GITHUB_REQUIRED_SCOPES,
    GithubAppCredentialResolver, GithubAppWorkConnection, GithubAppWorkProvider,
    GithubHttpResponse, GithubProposalTarget, GithubTransportError, GithubWorkContract,
    GithubWorkError, GithubWorkHttpTransport, GithubWorkReadRequest, LoopbackGithubWorkTransport,
    MissionGithubWorkConsumer,
};

const NOW_SECONDS: i64 = 1_787_000_000;

#[derive(Clone, Debug)]
struct TestCredentialResolver;

impl GithubAppCredentialResolver for TestCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &SecretReference,
        _at: DateTime<Utc>,
    ) -> Result<SecretMaterial, GithubWorkError> {
        SecretMaterial::new(b"test-installation-token").map_err(|_| GithubWorkError::BlockedEnv)
    }
}

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("test timestamp")
}

fn sha(byte: char) -> String {
    std::iter::repeat_n(byte, 40).collect()
}

fn response_receipt(
    at: DateTime<Utc>,
    next_page: Option<u32>,
    etag: Option<&str>,
) -> GithubHttpResponseReceipt {
    GithubHttpResponseReceipt::new(
        200,
        GITHUB_API_VERSION,
        etag.map(str::to_owned),
        GithubRateLimitReceipt::new(5_000, 4_999, at + Duration::hours(1)).expect("rate limit"),
        next_page,
        Some("github-request-1".to_owned()),
        at,
    )
    .expect("response receipt")
}

fn response(
    body: GithubHttpResponseBody,
    at: DateTime<Utc>,
    next_page: Option<u32>,
    etag: Option<&str>,
) -> GithubHttpResponse {
    GithubHttpResponse::new(Some(body), response_receipt(at, next_page, etag)).expect("response")
}

fn permissions(checks: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("metadata".to_owned(), "read".to_owned()),
        ("issues".to_owned(), "read".to_owned()),
        ("pull_requests".to_owned(), "read".to_owned()),
        ("checks".to_owned(), checks.to_owned()),
    ])
}

fn installation_response(at: DateTime<Utc>, checks: &str) -> GithubHttpResponse {
    response(
        GithubHttpResponseBody::Installation(GithubInstallationPayload {
            id: 7,
            account: Some(GithubAccountPayload {
                login: Some("octo".to_owned()),
            }),
            permissions: permissions(checks),
            suspended_at: None,
        }),
        at,
        None,
        None,
    )
}

fn repository_response(at: DateTime<Utc>) -> GithubHttpResponse {
    response(
        GithubHttpResponseBody::Repository(GithubRepositoryPayload {
            id: 99,
            name: "repo".to_owned(),
            full_name: "octo/repo".to_owned(),
            owner: GithubAccountPayload {
                login: Some("octo".to_owned()),
            },
            default_branch: "main".to_owned(),
            permissions: BTreeMap::from([(String::from("pull"), true)]),
        }),
        at,
        None,
        None,
    )
}

fn connection(at: DateTime<Utc>) -> GithubAppWorkConnection {
    let scope = ConnectorScope::new(
        "tenant-1",
        "project-1",
        "github",
        "installation-7",
        GITHUB_REQUIRED_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned()),
    )
    .expect("scope");
    let secret = SecretReference::new("secret-ref-github-work", scope.clone(), 1).expect("secret");
    let adapter = ProviderAdapterIdentity::new("github.app-work", 1).expect("adapter");
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        adapter,
        "lease-github-work",
        1,
        at - Duration::seconds(10),
        at + Duration::seconds(300),
    )
    .expect("lease");
    let session = ConnectorAuth::begin_auth_session(
        &secret,
        &lease,
        "auth-session-github-work",
        1,
        at - Duration::seconds(5),
        at + Duration::seconds(180),
    )
    .expect("session");
    GithubAppWorkConnection::new(
        scope,
        MissionId::from("mission-1"),
        secret,
        lease,
        session,
        7,
        "octo",
        "repo",
    )
    .expect("connection")
}

fn provider(
    responses: impl IntoIterator<Item = Result<GithubHttpResponse, GithubTransportError>>,
    at: DateTime<Utc>,
) -> GithubAppWorkProvider<LoopbackGithubWorkTransport, TestCredentialResolver> {
    GithubAppWorkProvider::new(
        connection(at),
        LoopbackGithubWorkTransport::new(responses),
        TestCredentialResolver,
        at,
    )
    .expect("provider")
}

#[test]
fn contract_and_provider_registry_are_typed_and_exact() {
    let contract = GithubWorkContract::baseline().expect("contract");
    assert_eq!(contract.digest(), crate::github_work_plugin_digest());
    assert_eq!(
        contract.required_permissions.len(),
        GITHUB_REQUIRED_PERMISSIONS.len()
    );
    let registry = crate::github_work_provider_registry().expect("registry");
    assert_eq!(registry.registrations().len(), 3);
    assert!(
        registry
            .registrations()
            .iter()
            .all(|registration| registration.adapter().adapter_id() == "github.app-work")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn read_projection_binds_installation_repository_issue_pr_and_checks() {
    let at = now();
    let head = sha('a');
    let responses = [
        Ok(installation_response(at, "read")),
        Ok(repository_response(at)),
        Ok(response(
            GithubHttpResponseBody::Issues(vec![GithubIssuePayload {
                number: 7,
                title: "Issue title".to_owned(),
                state: "open".to_owned(),
                body: Some("Issue body".to_owned()),
                html_url: None,
            }]),
            at,
            None,
            None,
        )),
        Ok(response(
            GithubHttpResponseBody::PullRequests(vec![GithubPullRequestPayload {
                number: 8,
                title: "PR title".to_owned(),
                state: "open".to_owned(),
                base: GithubGitRefPayload {
                    ref_name: "main".to_owned(),
                    sha: sha('b'),
                },
                head: GithubGitRefPayload {
                    ref_name: "feature".to_owned(),
                    sha: head.clone(),
                },
                body: Some("PR body".to_owned()),
                draft: false,
                merged: false,
                html_url: None,
            }]),
            at,
            None,
            None,
        )),
        Ok(response(
            GithubHttpResponseBody::CheckRuns(vec![GithubCheckRunPayload {
                id: 100,
                name: "unit".to_owned(),
                status: "completed".to_owned(),
                conclusion: Some("success".to_owned()),
                head_sha: head.clone(),
                html_url: None,
            }]),
            at,
            None,
            None,
        )),
    ];
    let mut provider = provider(responses, at);
    let request =
        GithubWorkReadRequest::new(Some(7), Some(8), Some(head.clone())).expect("request");
    let projection = provider.read(&request, at).expect("read");
    projection.validate().expect("projection");
    assert_eq!(projection.repository.full_name, "octo/repo");
    assert_eq!(projection.issue.as_ref().expect("issue").number, 7);
    assert_eq!(projection.pull_request.as_ref().expect("pr").head_sha, head);
    assert_eq!(projection.check_runs.len(), 1);
    assert!(!projection.metadata.is_connected());
    assert!(!provider.is_connected());

    let mission = Mission::compile(
        TenantId::from("tenant-1"),
        MissionId::from("mission-1"),
        ProjectId::from("project-1"),
        "GitHub work",
        MissionContract::bootstrap(
            "Review repository work",
            [
                crate::GITHUB_WORK_CAPABILITY_ID.to_owned(),
                crate::GITHUB_WORK_PROPOSAL_CAPABILITY_ID.to_owned(),
            ],
            at,
        ),
        at,
    )
    .expect("mission");
    let read_result = MissionGithubWorkConsumer::new()
        .consume_read(&mission, projection.clone())
        .expect("consumer");
    read_result.validate().expect("read result");
    let work_product = WorkProduct::draft(
        WorkProductId::from("work-product-1"),
        "Adoptable work",
        "Work product body",
        [],
    );
    let proposal = crate::model::GithubWorkProposal::seal(
        GithubProposalTarget::PullRequestComment {
            pull_request_number: 8,
        },
        Some("Review".to_owned()),
        "Please review the current head.".to_owned(),
        mission.tenant_id.clone(),
        mission.project_id.clone(),
        mission.id.clone(),
        work_product.id,
        work_product.revision,
        work_product.content_digest,
        &projection,
    )
    .expect("proposal");
    assert!(proposal.preview_only);
    assert!(!proposal.external_mutation_created);
    assert_eq!(proposal.head_sha.as_deref(), Some(head.as_str()));
}

#[test]
fn pagination_etag_and_permission_drift_are_fenced() {
    let at = now();
    let responses = [
        Ok(installation_response(at, "read")),
        Ok(repository_response(at)),
        Ok(response(
            GithubHttpResponseBody::Issues(vec![GithubIssuePayload {
                number: 1,
                title: "Other".to_owned(),
                state: "open".to_owned(),
                body: None,
                html_url: None,
            }]),
            at,
            Some(2),
            Some("etag-1"),
        )),
        Ok(response(
            GithubHttpResponseBody::Issues(vec![GithubIssuePayload {
                number: 42,
                title: "Target".to_owned(),
                state: "open".to_owned(),
                body: None,
                html_url: None,
            }]),
            at,
            None,
            Some("etag-2"),
        )),
    ];
    let mut provider = provider(responses, at);
    let request = GithubWorkReadRequest::new(Some(42), None, None)
        .expect("request")
        .with_page_size(1)
        .expect("page size")
        .with_etag("issues", "etag-1")
        .expect("etag");
    let projection = provider.read(&request, at).expect("paginated read");
    assert_eq!(projection.page_receipts.len(), 2);
    let requests = provider
        .last_probe()
        .expect("probe")
        .installation_response
        .status;
    assert_eq!(requests, 200);

    let drift_transport = LoopbackGithubWorkTransport::new([
        Ok(installation_response(at, "read")),
        Ok(repository_response(at)),
    ]);
    let mut drift_provider = GithubAppWorkProvider::new(
        connection(at),
        drift_transport.clone(),
        TestCredentialResolver,
        at,
    )
    .expect("drift provider");
    drift_provider.probe(at).expect("initial probe");
    drift_transport.push_response(Ok(installation_response(at, "write")));
    drift_transport.push_response(Ok(repository_response(at)));
    assert_eq!(
        drift_provider.probe(at + Duration::seconds(1)),
        Err(GithubWorkError::PermissionDrift)
    );
}

#[test]
fn explicit_revoke_and_blocked_credentials_never_report_connected() {
    let at = now();
    let mut provider = provider(
        [
            Ok(installation_response(at, "read")),
            Ok(repository_response(at)),
        ],
        at,
    );
    provider.revoke(at + Duration::seconds(1)).expect("revoke");
    assert_eq!(
        provider.probe(at + Duration::seconds(2)),
        Err(GithubWorkError::Revoked)
    );
    let mut blocked = crate::BlockedEnvCredentialResolver;
    assert_eq!(
        blocked
            .resolve(provider.connection().secret_reference(), at)
            .expect_err("blocked resolver"),
        GithubWorkError::BlockedEnv
    );
    assert!(!provider.is_connected());
}

#[test]
fn loopback_transport_is_not_native_even_if_response_data_is_valid() {
    let transport = LoopbackGithubWorkTransport::new([])
        .with_provenance(ProviderProvenanceClass::ControlledProvider);
    assert!(!transport.is_native());
    assert_eq!(
        transport.provenance_class(),
        ProviderProvenanceClass::ControlledProvider
    );
}

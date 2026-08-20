use std::collections::BTreeSet;

use hartevo_confluence_result_plugin::{
    AtlassianAccountId, AuthMethod, BlockedEnvCredentialResolver, BodyField, BodyRepresentation,
    CloudId, ConfluenceCapability, ConfluenceCloudProvider, ConfluenceFixture,
    ConfluenceKnowledgeResultError, ConfluenceKnowledgeResultService, ConfluencePageId,
    ConfluencePageReadRequest, ConfluencePluginRegistration, ConfluenceProviderError,
    ConfluenceProviderState, ConfluenceSearchRequest, ConfluenceSite, ConfluenceSpaceId,
    ConfluenceTransportOperation, ConsentBinding, CqlTemplate, FixtureConfluenceTransport,
    FixtureFailure, FixturePage, KnowledgeEvidence, MAX_PAGE_SIZE, MAX_PAGES,
    MissionConfluenceKnowledgeConsumer, MissionId, MissionWorkProduct, PageState, PageVersion,
    ProjectId, SecretReference, StaticConfluenceCredentialResolver, WorkProductId, sha256_digest,
};

const TOKEN: &str = "fixture-atlassian-token-not-for-logs";
const TITLE: &str = "Customer Confidential Decision Page";
const BODY: &str = "hartevo bounded knowledge evidence body";

fn digest(value: &str) -> String {
    sha256_digest(value.as_bytes())
}

fn all_capabilities() -> BTreeSet<ConfluenceCapability> {
    BTreeSet::from([
        ConfluenceCapability::DescribeContentScope,
        ConfluenceCapability::ReadPageEvidence,
        ConfluenceCapability::SearchKnowledge,
        ConfluenceCapability::CompileKnowledgeProposal,
        ConfluenceCapability::RecordKnowledgeReceipt,
        ConfluenceCapability::VerifyKnowledgeResult,
    ])
}

fn scope() -> hartevo_confluence_result_plugin::ConfluenceScope {
    let space_id = ConfluenceSpaceId::new("SPACE").expect("space");
    let cql = CqlTemplate::space_text(space_id.clone(), "hartevo").expect("CQL");
    hartevo_confluence_result_plugin::ConfluenceScope::new(
        ConfluenceSite::new("https://example.atlassian.net").expect("site"),
        CloudId::new("cloud-1").expect("cloud"),
        AtlassianAccountId::new("account-1").expect("account"),
        space_id,
        ConfluencePageId::new("page-1").expect("page"),
        hartevo_confluence_result_plugin::ConfluenceContentId::new("content-1").expect("content"),
        PageVersion::new(3, "2026-08-14T10:00:00Z").expect("version"),
        BodyRepresentation::Storage,
        BTreeSet::from([
            BodyField::Representation,
            BodyField::ValueDigest,
            BodyField::ByteLength,
        ]),
        64 * 1024,
        cql,
        ProjectId::new("project-1").expect("project"),
        MissionId::new("mission-1").expect("mission"),
        WorkProductId::new("work-product-1").expect("work product"),
        7,
        ConsentBinding::new("consent-1", 4, all_capabilities()).expect("consent"),
        digest("permission-snapshot-1"),
    )
    .expect("scope")
}

fn fixture(scope: &hartevo_confluence_result_plugin::ConfluenceScope) -> ConfluenceFixture {
    let mut fixture = ConfluenceFixture::new();
    fixture.insert_page(FixturePage::new(scope, TITLE, BODY).expect("page"));
    fixture
}

fn second_page(scope: &hartevo_confluence_result_plugin::ConfluenceScope) -> FixturePage {
    let mut page = FixturePage::new(scope, "Second bounded result", "hartevo second result")
        .expect("second page");
    page.page_id = ConfluencePageId::new("page-2").expect("second page id");
    page.content_id = hartevo_confluence_result_plugin::ConfluenceContentId::new("content-2")
        .expect("second content id");
    page
}

fn registration(
    scope: &hartevo_confluence_result_plugin::ConfluenceScope,
) -> ConfluencePluginRegistration {
    let secret = SecretReference::new(
        "secret-ref-confluence-fixture",
        scope.digest(),
        1,
        AuthMethod::ApiToken,
    )
    .expect("secret reference");
    ConfluencePluginRegistration::new(scope.clone(), secret).expect("registration")
}

fn make_service(
    scope: &hartevo_confluence_result_plugin::ConfluenceScope,
    transport: FixtureConfluenceTransport,
) -> ConfluenceKnowledgeResultService<FixtureConfluenceTransport, StaticConfluenceCredentialResolver>
{
    let provider = ConfluenceCloudProvider::new(
        registration(scope),
        transport,
        StaticConfluenceCredentialResolver::new(TOKEN),
    )
    .expect("provider");
    ConfluenceKnowledgeResultService::new(provider).expect("service")
}

fn work_product() -> MissionWorkProduct {
    MissionWorkProduct::new(
        ProjectId::new("project-1").expect("project"),
        MissionId::new("mission-1").expect("mission"),
        WorkProductId::new("work-product-1").expect("work product"),
        7,
        digest("work product content"),
        digest("research objective"),
    )
    .expect("work product")
}

fn read_request(
    scope: &hartevo_confluence_result_plugin::ConfluenceScope,
) -> ConfluencePageReadRequest {
    ConfluencePageReadRequest::new(scope.clone()).expect("page request")
}

#[test]
fn fixture_is_bounded_redacted_and_never_connected_or_native() {
    let scope = scope();
    let fixture = fixture(&scope);
    let transport = FixtureConfluenceTransport::fixture(fixture.clone());
    let mut service = make_service(&scope, transport.clone());

    let description = service.describe_content_scope().expect("description");
    assert_eq!(description.scope_digest, scope.digest());
    assert_eq!(
        description.evidence_source,
        hartevo_confluence_result_plugin::ProviderProvenance::Fixture
    );
    assert!(!description.native_transport);
    assert!(!description.native_connected);

    let evidence = service
        .read_page_evidence(&read_request(&scope))
        .expect("page evidence");
    assert_eq!(evidence.body.byte_length, BODY.len());
    assert_eq!(evidence.body.value_digest, digest(BODY));
    assert!(!evidence.native_transport);
    assert!(!evidence.native_connected);
    assert_eq!(transport.operations().len(), 1);
    assert!(matches!(
        transport.operations()[0],
        ConfluenceTransportOperation::ReadPage { .. }
    ));

    let debug = format!("{fixture:?} {evidence:?} {:?}", service.provider());
    assert!(!debug.contains(TOKEN));
    assert!(!debug.contains(TITLE));
    assert!(!debug.contains(BODY));
}

#[test]
fn recording_loopback_and_blocked_env_have_honest_provenance() {
    let scope = scope();
    let recording_transport = FixtureConfluenceTransport::recording(fixture(&scope));
    let mut recording_service = make_service(&scope, recording_transport);
    let page = recording_service
        .read_page_evidence(&read_request(&scope))
        .expect("recording page");
    assert_eq!(
        page.evidence_source,
        hartevo_confluence_result_plugin::ProviderProvenance::Recording
    );
    assert!(!page.evidence_source.is_native());
    assert!(!page.evidence_source.is_connected());

    let loopback_transport = FixtureConfluenceTransport::loopback(fixture(&scope));
    let mut loopback_service = make_service(&scope, loopback_transport);
    let loopback_page = loopback_service
        .read_page_evidence(&read_request(&scope))
        .expect("loopback page");
    assert_eq!(
        loopback_page.evidence_source,
        hartevo_confluence_result_plugin::ProviderProvenance::Loopback
    );
    assert!(!loopback_page.native_transport);
    assert!(!loopback_page.native_connected);

    let provider = ConfluenceCloudProvider::new(
        registration(&scope),
        FixtureConfluenceTransport::fixture(fixture(&scope)),
        BlockedEnvCredentialResolver,
    )
    .expect("blocked provider construction");
    let mut blocked_service = ConfluenceKnowledgeResultService::new(provider).expect("service");
    assert!(matches!(
        blocked_service.read_page_evidence(&read_request(&scope)),
        Err(ConfluenceKnowledgeResultError::Provider(
            ConfluenceProviderError::BlockedEnv
        ))
    ));
    assert_eq!(
        blocked_service.provider().state(),
        &ConfluenceProviderState::BlockedEnv
    );
}

#[test]
fn mission_consumer_compiles_records_and_verifies_proposal_without_adoption() {
    let scope = scope();
    let transport = FixtureConfluenceTransport::recording(fixture(&scope));
    let service = make_service(&scope, transport);
    let mut consumer = MissionConfluenceKnowledgeConsumer::new(service);
    let page = consumer
        .read_page_evidence(&read_request(&scope))
        .expect("page");
    let search_request =
        ConfluenceSearchRequest::new(scope.clone(), MAX_PAGE_SIZE, None).expect("search request");
    let search = consumer.search_knowledge(&search_request).expect("search");
    let evidence = KnowledgeEvidence::new(page, Some(search)).expect("knowledge evidence");
    let proposal = consumer
        .compose_knowledge_result(work_product(), evidence)
        .expect("proposal");
    proposal.validate().expect("proposal validation");
    assert!(proposal.non_mutating);
    assert!(!proposal.external_write_performed);
    assert!(!proposal.durable_native_receipt);
    assert!(!proposal.native_connected);

    let receipt = consumer
        .record_knowledge_receipt(&proposal)
        .expect("recording receipt");
    receipt.validate().expect("receipt validation");
    assert_eq!(
        receipt.evidence_source,
        hartevo_confluence_result_plugin::ProviderProvenance::Recording
    );
    let verified = consumer
        .verify_knowledge_result(&proposal, &receipt)
        .expect("verified recording");
    assert!(verified.verified);
    assert!(!verified.adopted);
    assert!(!verified.native_connected);
    let serialized = serde_json::to_string(&receipt).expect("receipt JSON");
    assert!(!serialized.contains(TOKEN));
    assert!(!serialized.contains(TITLE));
    assert!(!serialized.contains(BODY));
}

#[test]
fn version_permission_site_account_and_page_drift_fail_closed() {
    let scope = scope();
    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    let mut service = make_service(&scope, transport.clone());
    transport.update_fixture(|fixture| {
        fixture.page_mut(&scope.page_id).expect("page").version =
            PageVersion::new(4, "2026-08-14T11:00:00Z").expect("version");
    });
    assert!(matches!(
        service.read_page_evidence(&read_request(&scope)),
        Err(ConfluenceKnowledgeResultError::Provider(
            ConfluenceProviderError::VersionDrift
        ))
    ));

    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture
            .page_mut(&scope.page_id)
            .expect("page")
            .permission_digest = digest("permission-drift");
    });
    let mut service = make_service(&scope, transport);
    assert!(matches!(
        service.read_page_evidence(&read_request(&scope)),
        Err(ConfluenceKnowledgeResultError::Provider(
            ConfluenceProviderError::PermissionDrift
        ))
    ));

    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture.page_mut(&scope.page_id).expect("page").state = PageState::Archived;
    });
    let mut service = make_service(&scope, transport);
    assert!(matches!(
        service.read_page_evidence(&read_request(&scope)),
        Err(ConfluenceKnowledgeResultError::Provider(
            ConfluenceProviderError::Archived
        ))
    ));

    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture.page_mut(&scope.page_id).expect("page").state = PageState::Deleted;
    });
    let mut service = make_service(&scope, transport);
    assert!(matches!(
        service.read_page_evidence(&read_request(&scope)),
        Err(ConfluenceKnowledgeResultError::Provider(
            ConfluenceProviderError::Deleted
        ))
    ));

    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture.page_mut(&scope.page_id).expect("page").state = PageState::AccessLost;
    });
    let mut service = make_service(&scope, transport);
    assert!(matches!(
        service.read_page_evidence(&read_request(&scope)),
        Err(ConfluenceKnowledgeResultError::Provider(
            ConfluenceProviderError::AccessLost
        ))
    ));
}

#[test]
fn typed_http_statuses_timeout_and_upstream_failures_are_not_successes() {
    let scope = scope();
    let cases = [
        (
            FixtureFailure::Unauthorized,
            ConfluenceProviderError::Unauthorized,
        ),
        (
            FixtureFailure::Forbidden,
            ConfluenceProviderError::Forbidden,
        ),
        (FixtureFailure::NotFound, ConfluenceProviderError::NotFound),
        (FixtureFailure::Conflict, ConfluenceProviderError::Conflict),
        (
            FixtureFailure::RateLimited {
                retry_after_seconds: Some(3),
            },
            ConfluenceProviderError::RateLimited {
                retry_after_seconds: Some(3),
            },
        ),
        (FixtureFailure::Timeout, ConfluenceProviderError::Transport),
        (
            FixtureFailure::ServerFailure { status: 503 },
            ConfluenceProviderError::ServerFailure { status: 503 },
        ),
    ];
    for (failure, expected) in cases {
        let transport = FixtureConfluenceTransport::fixture(fixture(&scope)).with_failure(failure);
        let mut service = make_service(&scope, transport);
        let error = service
            .read_page_evidence(&read_request(&scope))
            .expect_err("typed provider failure");
        assert_eq!(error, ConfluenceKnowledgeResultError::Provider(expected));
    }
}

#[test]
fn cql_rejection_cursor_loop_and_opaque_cursor_fence_are_fail_closed() {
    let scope = scope();
    let rejected = FixtureConfluenceTransport::fixture(fixture(&scope))
        .with_failure(FixtureFailure::CqlRejected);
    let mut rejected_service = make_service(&scope, rejected);
    let request = ConfluenceSearchRequest::new(scope.clone(), 1, None).expect("search");
    assert_eq!(
        rejected_service
            .search_knowledge(&request)
            .expect_err("CQL rejection"),
        ConfluenceKnowledgeResultError::Provider(ConfluenceProviderError::CqlRejected)
    );

    let mut fixture_with_two = fixture(&scope);
    fixture_with_two.insert_page(second_page(&scope));
    let transport = FixtureConfluenceTransport::fixture(fixture_with_two);
    transport.set_cursor_loop(true);
    let mut service = make_service(&scope, transport);
    let first = service
        .search_knowledge(&ConfluenceSearchRequest::new(scope.clone(), 1, None).expect("first"))
        .expect("first search");
    let cursor = first.next_cursor.expect("opaque cursor");
    let cursor_debug = format!("{cursor:?}");
    assert!(!cursor_debug.contains("fixture-page-1"));
    assert!(
        serde_json::to_string(&cursor)
            .expect("cursor JSON")
            .contains("cursorDigest")
    );
    let second_request = ConfluenceSearchRequest::new(scope, 1, Some(cursor)).expect("second");
    assert_eq!(
        service
            .search_knowledge(&second_request)
            .expect_err("cursor loop"),
        ConfluenceKnowledgeResultError::Provider(ConfluenceProviderError::CursorLoop)
    );
}

#[test]
fn body_metadata_tamper_partial_empty_and_truncation_never_become_evidence() {
    let scope = scope();
    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture
            .page_mut(&scope.page_id)
            .expect("page")
            .set_body_digest_tamper(digest("tampered body"));
    });
    let mut service = make_service(&scope, transport);
    assert_eq!(
        service
            .read_page_evidence(&read_request(&scope))
            .expect_err("body mismatch"),
        ConfluenceKnowledgeResultError::Provider(ConfluenceProviderError::BodyMismatch)
    );

    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture
            .page_mut(&scope.page_id)
            .expect("page")
            .set_metadata_digest_tamper(digest("tampered metadata"));
    });
    let mut service = make_service(&scope, transport);
    assert_eq!(
        service
            .read_page_evidence(&read_request(&scope))
            .expect_err("metadata mismatch"),
        ConfluenceKnowledgeResultError::Provider(ConfluenceProviderError::MetadataMismatch)
    );

    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture.page_mut(&scope.page_id).expect("page").partial = true;
    });
    let mut service = make_service(&scope, transport);
    assert_eq!(
        service
            .read_page_evidence(&read_request(&scope))
            .expect_err("partial page"),
        ConfluenceKnowledgeResultError::Provider(ConfluenceProviderError::PartialResponse)
    );

    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture.page_mut(&scope.page_id).expect("page").truncated = true;
    });
    let mut service = make_service(&scope, transport);
    assert_eq!(
        service
            .read_page_evidence(&read_request(&scope))
            .expect_err("truncated page"),
        ConfluenceKnowledgeResultError::Provider(ConfluenceProviderError::Truncated)
    );

    let mut empty_fixture = fixture(&scope);
    empty_fixture.page_mut(&scope.page_id).expect("page").body = String::from("unrelated text");
    let transport = FixtureConfluenceTransport::fixture(empty_fixture);
    let mut service = make_service(&scope, transport);
    let page = service
        .read_page_evidence(&read_request(&scope))
        .expect("page evidence");
    let search = service
        .search_knowledge(&ConfluenceSearchRequest::new(scope.clone(), 1, None).expect("search"))
        .expect("empty search evidence");
    assert!(search.empty);
    let evidence = KnowledgeEvidence::new(page, Some(search)).expect("empty evidence");
    assert_eq!(
        service
            .compile_knowledge_proposal(work_product(), evidence)
            .expect_err("empty result must not be proposed"),
        ConfluenceKnowledgeResultError::EmptyEvidence
    );
}

#[test]
fn cql_injection_and_revocation_are_explicitly_rejected() {
    let space = ConfluenceSpaceId::new("SPACE").expect("space");
    assert!(CqlTemplate::space_text(space.clone(), "x\" OR text ~ \"secret").is_err());
    assert!(
        CqlTemplate::from_raw(
            space,
            "space = \"SPACE\" AND text ~ \"x\" OR text ~ \"secret\""
        )
        .is_err()
    );

    let scope = scope();
    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    let mut service = make_service(&scope, transport);
    let revocation = service.provider_mut().revoke().expect("revocation");
    assert!(revocation.revoked);
    assert_eq!(revocation.revocation_revision, 2);
    assert_eq!(
        service.provider().state(),
        &ConfluenceProviderState::Revoked
    );
    assert!(matches!(
        service.read_page_evidence(&read_request(&scope)),
        Err(ConfluenceKnowledgeResultError::Provider(
            ConfluenceProviderError::RegistrationRevoked
        ))
    ));
}

#[test]
fn exact_scope_and_bounds_are_enforced() {
    assert_eq!(MAX_PAGES, 16);
    assert_eq!(MAX_PAGE_SIZE, 50);
    let scope = scope();
    let wrong_cursor_request = ConfluenceSearchRequest::new(scope.clone(), 0, None);
    assert!(wrong_cursor_request.is_err());
    let mut other_scope = scope.clone();
    other_scope.page_id = ConfluencePageId::new("page-other").expect("other page");
    assert!(ConfluencePageReadRequest::new(other_scope).is_ok());

    let transport = FixtureConfluenceTransport::fixture(fixture(&scope));
    transport.update_fixture(|fixture| {
        let page = fixture.page_mut(&scope.page_id).expect("page");
        page.site = ConfluenceSite::new("https://other.atlassian.net").expect("other site");
    });
    let mut service = make_service(&scope, transport);
    assert!(matches!(
        service.read_page_evidence(&read_request(&scope)),
        Err(ConfluenceKnowledgeResultError::Provider(
            ConfluenceProviderError::SiteDrift
        ))
    ));
}

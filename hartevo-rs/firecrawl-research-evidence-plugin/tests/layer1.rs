use std::collections::BTreeSet;

use hartevo_firecrawl_research_evidence_plugin::{
    CanonicalUrl, FirecrawlAllowlistRule, FirecrawlCacheMode, FirecrawlCachePolicy,
    FirecrawlContentFormat, FirecrawlCrawlOptions, FirecrawlExtractionSchema, FirecrawlJobId,
    FirecrawlJobRequest, FirecrawlJobStatus, FirecrawlPluginRegistration, FirecrawlProvider,
    FirecrawlProviderError, FirecrawlProviderManifest, FirecrawlResearchEvidenceError,
    FirecrawlResearchEvidenceService, FirecrawlScope, FirecrawlScrapeOptions,
    FirecrawlTransportOperation, FirecrawlUrlAllowlist, FixtureFailure, FixtureFirecrawlTransport,
    MissionFirecrawlResearchConsumer, MissionFirecrawlResearchRequest, MissionWorkProduct,
    NativeStatus, RawFirecrawlPage, ReadOnlyAuthority, SecretReference,
    StaticFirecrawlCredentialResolver, contract_digest, sha256_digest,
};
use serde_json::Value;

type TestService =
    FirecrawlResearchEvidenceService<FixtureFirecrawlTransport, StaticFirecrawlCredentialResolver>;

fn scope() -> FirecrawlScope {
    FirecrawlScope::fixture("mission-firecrawl").expect("scope")
}

fn scrape_request(scope: &FirecrawlScope, nonce: &str) -> FirecrawlJobRequest {
    FirecrawlJobRequest::scrape(
        scope.clone(),
        FirecrawlJobId::new("job-firecrawl-1").expect("job id"),
        nonce,
        100_000,
        CanonicalUrl::new("https://example.com/research/guide/").expect("url"),
        FirecrawlScrapeOptions::fixture(),
    )
    .expect("scrape request")
}

fn service() -> (TestService, FixtureFirecrawlTransport) {
    let scope = scope();
    let provider = FirecrawlProvider::recording(scope).expect("provider");
    let transport = provider.transport().clone();
    (TestService::new(provider).expect("service"), transport)
}

fn service_with_failure(failure: FixtureFailure) -> TestService {
    let scope = scope();
    let transport = FixtureFirecrawlTransport::recording(scope.clone()).with_failure(failure);
    let manifest = FirecrawlProviderManifest::fixture(&scope).expect("manifest");
    let provider = FirecrawlProvider::new(
        manifest,
        transport,
        StaticFirecrawlCredentialResolver::new("fixture-api-key-not-for-logs"),
    )
    .expect("provider");
    TestService::new(provider).expect("service")
}

fn mission_request(
    service: &TestService,
    request: FirecrawlJobRequest,
) -> MissionFirecrawlResearchRequest {
    MissionFirecrawlResearchRequest::new(
        request.scope.clone(),
        request,
        service.current_registration_digest(),
        service.current_permission_digest(),
    )
    .expect("Mission request")
}

#[test]
fn contract_is_layer_one_and_authority_is_honest() {
    let contract: Value = serde_json::from_str(
        hartevo_firecrawl_research_evidence_plugin::FIRECRAWL_RESEARCH_EVIDENCE_CONTRACT_JSON,
    )
    .expect("contract JSON");
    assert_eq!(contract["contractVersion"], "EXT-FIRECRAWL-01-L1/v1");
    assert_eq!(contract["layer"], 1);
    assert_eq!(contract["api"]["version"], "v2");
    assert_eq!(
        contract["content"]["formats"],
        serde_json::json!(["markdown"])
    );
    assert_eq!(contract["authority"]["externalWrite"], false);
    assert_eq!(contract["authority"]["browserActions"], false);
    assert_eq!(contract["authority"]["arbitraryCode"], false);
    assert_eq!(contract["authority"]["workProductAdoption"], false);
    assert_eq!(contract["native"]["status"], "BLOCKED_ENV");
    assert_eq!(contract_digest().len(), 64);
    assert!(!ReadOnlyAuthority::external_write());
    assert!(!ReadOnlyAuthority::browser_actions());
    assert!(!ReadOnlyAuthority::arbitrary_code());
    assert!(!ReadOnlyAuthority::adoption());
    assert!(!ReadOnlyAuthority::connected());
    assert!(!ReadOnlyAuthority::native());
}

#[test]
fn url_canonicalization_and_exact_allowlist_fail_closed() {
    let canonical =
        CanonicalUrl::new("https://EXAMPLE.com/research/guide/?b=2&a=1").expect("canonical URL");
    assert_eq!(
        canonical.as_str(),
        "https://example.com/research/guide?a=1&b=2"
    );
    assert!(CanonicalUrl::new("http://example.com/research").is_err());
    assert!(CanonicalUrl::new("https://user:password@example.com/research").is_err());
    assert!(CanonicalUrl::new("https://example.com/login").is_err());
    assert!(CanonicalUrl::new("https://localhost/research").is_err());
    assert!(CanonicalUrl::new("https://127.0.0.1/research").is_err());

    let exact = FirecrawlUrlAllowlist::new([FirecrawlAllowlistRule::exact_url(
        CanonicalUrl::new("https://example.com/research/guide").expect("allowed URL"),
    )])
    .expect("exact allowlist");
    let mut restricted_scope = scope();
    restricted_scope.allowlist = exact;
    assert_eq!(
        scrape_request(&restricted_scope, "allowlist-ok")
            .url()
            .as_str(),
        "https://example.com/research/guide"
    );
    let disallowed = FirecrawlJobRequest::scrape(
        restricted_scope,
        FirecrawlJobId::new("job-disallowed").expect("job"),
        "allowlist-bad",
        100_000,
        CanonicalUrl::new("https://example.com/other").expect("URL"),
        FirecrawlScrapeOptions::fixture(),
    );
    assert!(matches!(
        disallowed,
        Err(FirecrawlResearchEvidenceError::UrlNotAllowlisted { .. })
    ));
}

#[test]
fn scope_job_options_and_content_format_are_exactly_bound() {
    let scope = scope();
    let request = scrape_request(&scope, "scope-bind");
    assert_eq!(request.scope.mission_id.as_str(), "mission-firecrawl");
    assert_eq!(request.scope.project_revision, 1);
    assert_eq!(request.scope.work_product_revision, 1);
    assert_eq!(
        request.kind(),
        hartevo_firecrawl_research_evidence_plugin::FirecrawlJobKind::Scrape
    );
    assert!(request.request_digest().len() == 64);
    assert_eq!(
        request.job.content_format(),
        FirecrawlContentFormat::Markdown
    );
    assert!(
        FirecrawlScrapeOptions {
            content_format: FirecrawlContentFormat::Html,
            ..FirecrawlScrapeOptions::fixture()
        }
        .validate()
        .is_err()
    );
    assert!(
        FirecrawlCrawlOptions::markdown(
            33,
            1,
            60_000,
            FirecrawlCachePolicy::fixture(),
            FirecrawlExtractionSchema::none(),
        )
        .is_err()
    );
    assert!(
        FirecrawlCrawlOptions::markdown(
            1,
            5,
            60_000,
            FirecrawlCachePolicy::fixture(),
            FirecrawlExtractionSchema::none(),
        )
        .is_err()
    );
}

#[test]
fn bounded_scrape_produces_revision_fenced_digest_only_proposal_and_receipt() {
    let (mut service, transport) = service();
    let scope = scope();
    let request = scrape_request(&scope, "proposal-1");
    let description = service
        .describe_url(request.url().clone(), &scope)
        .expect("URL description");
    assert!(description.allowlisted);
    assert_eq!(description.native_status, NativeStatus::BlockedEnv);
    assert!(!description.connected);
    assert!(!description.first_party);
    let job = service.describe_job(&request).expect("job description");
    assert_eq!(job.status, FirecrawlJobStatus::ProviderUnknown);
    let evidence = service.scrape(&request).expect("scrape evidence");
    evidence.validate_for(&request).expect("evidence fences");
    assert!(evidence.is_source_evidence());
    assert_eq!(evidence.pages.len(), 1);
    assert!(evidence.markdown.as_deref().unwrap_or_default().len() < 64 * 1024);
    assert!(!evidence.native_transport);
    assert!(!evidence.native_connected);
    assert!(!evidence.first_party);
    let work_product = MissionWorkProduct::fixture(&scope);
    let proposal = service
        .compile_research_proposal(work_product, evidence)
        .expect("proposal");
    proposal.validate().expect("proposal digest");
    assert!(!proposal.adopted);
    assert!(!proposal.external_write_performed);
    assert!(!proposal.durable_native_receipt);
    let receipt = service.record_research_receipt(&proposal).expect("receipt");
    receipt.validate().expect("receipt digest");
    let verification = service
        .verify_research_evidence(&proposal, &receipt)
        .expect("verification");
    verification.validate().expect("verification digest");
    assert!(verification.verified);
    assert!(!verification.adopted);
    assert!(!verification.read_back);
    assert!(!verification.native_connected);
    let serialized = format!("{proposal:?} {receipt:?}");
    assert!(!serialized.contains("Bounded fixture Markdown evidence"));
    assert_eq!(transport.operations().len(), 1);
    assert!(matches!(
        transport.operations()[0],
        FirecrawlTransportOperation::SubmitScrape { .. }
    ));
}

#[test]
fn mission_consumer_binds_registration_permission_and_work_product_scope() {
    let (service, _transport) = service();
    let scope = scope();
    let request = scrape_request(&scope, "consumer-1");
    let mission = mission_request(&service, request);
    let mut consumer = MissionFirecrawlResearchConsumer::new(service);
    let result = consumer
        .consume(&mission, MissionWorkProduct::fixture(&scope))
        .expect("Mission result");
    assert!(result.evidence.is_source_evidence());
    assert!(!result.proposal.adopted);
    assert!(!result.receipt.durable);
    assert!(result.verification.verified);
    assert_eq!(result.evidence.mission_revision, scope.mission_revision);
}

#[test]
fn registration_is_versioned_scope_bound_reversible_and_revocable() {
    let registration_scope = scope();
    let manifest = FirecrawlProviderManifest::fixture(&registration_scope).expect("manifest");
    manifest
        .validate(&registration_scope)
        .expect("manifest validates");
    assert!(manifest.registration.reversible);
    assert!(manifest.registration.enabled);
    let revoked = manifest.revoked().expect("revoked manifest");
    assert!(!revoked.registration.enabled);
    assert_ne!(revoked.manifest_digest, manifest.manifest_digest);
    revoked
        .validate(&registration_scope)
        .expect("revoked manifest validates");
    let reactivated = revoked.reactivated().expect("reactivated manifest");
    assert!(reactivated.registration.enabled);
    reactivated
        .validate(&registration_scope)
        .expect("reactivated validates");

    let provider = FirecrawlProvider::fixture(registration_scope.clone()).expect("provider");
    let mut service = TestService::new(provider).expect("service");
    let old_digest = service.current_registration_digest();
    service.provider_mut().revoke().expect("revoke");
    assert_ne!(service.current_registration_digest(), old_digest);
    assert_eq!(
        service.current_status(),
        hartevo_firecrawl_research_evidence_plugin::FirecrawlProviderState::Revoked
    );
    let error = service
        .read(&scrape_request(&registration_scope, "revoked-read"))
        .expect_err("revoked read");
    assert_eq!(
        error,
        FirecrawlResearchEvidenceError::Provider(FirecrawlProviderError::RegistrationRevoked)
    );
    service.provider_mut().reactivate().expect("reactivate");
    assert!(
        service
            .read(&scrape_request(&registration_scope, "reactivated-read"))
            .is_ok()
    );
}

#[test]
fn opaque_api_key_reference_never_enters_plans_debug_or_receipts() {
    let scope = scope();
    let secret = SecretReference::new("raw-api-key-must-not-escape", scope.digest(), 7)
        .expect("secret reference");
    assert!(!format!("{secret:?}").contains("raw-api-key-must-not-escape"));
    let manifest = FirecrawlProviderManifest::new(&scope, secret).expect("manifest");
    let provider = FirecrawlProvider::new(
        manifest,
        FixtureFirecrawlTransport::recording(scope.clone()),
        StaticFirecrawlCredentialResolver::new("raw-api-key-bytes-never-serialized"),
    )
    .expect("provider");
    let request = scrape_request(&scope, "opaque-plan");
    let plan = provider.request_plan(&request).expect("plan");
    assert!(plan.secret_reference_required);
    assert!(!plan.connected);
    assert!(!plan.native);
    assert!(!plan.first_party);
    assert!(!format!("{plan:?}").contains("raw-api-key"));
    assert!(
        !serde_json::to_string(&plan)
            .expect("plan JSON")
            .contains("raw-api-key")
    );
}

#[test]
fn blocked_environment_is_honest_and_does_not_fallback_to_connected() {
    let scope = scope();
    let manifest = FirecrawlProviderManifest::fixture(&scope).expect("manifest");
    let provider = FirecrawlProvider::from_manifest(manifest).expect("blocked provider");
    let mut service = FirecrawlResearchEvidenceService::new(provider).expect("service");
    let error = service
        .read(&scrape_request(&scope, "blocked-env"))
        .expect_err("blocked env");
    assert_eq!(
        error,
        FirecrawlResearchEvidenceError::Provider(FirecrawlProviderError::BlockedEnv)
    );
    assert_eq!(service.provider().native_status(), NativeStatus::BlockedEnv);
    assert!(!service.provider().connected());
    assert!(!service.provider().native());
}

#[test]
fn all_required_http_statuses_timeout_and_access_loss_are_typed() {
    let cases = [
        (
            FixtureFailure::Unauthorized,
            FirecrawlProviderError::Unauthorized { status: 401 },
        ),
        (
            FixtureFailure::Forbidden,
            FirecrawlProviderError::Forbidden { status: 403 },
        ),
        (
            FixtureFailure::NotFound,
            FirecrawlProviderError::NotFound { status: 404 },
        ),
        (
            FixtureFailure::Conflict,
            FirecrawlProviderError::Conflict { status: 409 },
        ),
        (
            FixtureFailure::RateLimited {
                retry_after_seconds: Some(3),
            },
            FirecrawlProviderError::RateLimited {
                status: 429,
                retry_after_seconds: Some(3),
            },
        ),
        (
            FixtureFailure::ServerFailure { status: 500 },
            FirecrawlProviderError::ServerFailure { status: 500 },
        ),
        (
            FixtureFailure::ServerFailure { status: 503 },
            FirecrawlProviderError::ServerFailure { status: 503 },
        ),
    ];
    for (failure, expected) in cases {
        let mut service = service_with_failure(failure);
        let error = service
            .read(&scrape_request(&scope(), "typed-http"))
            .expect_err("typed provider error");
        assert_eq!(error, FirecrawlResearchEvidenceError::Provider(expected));
    }
    let mut timeout = service_with_failure(FixtureFailure::Timeout);
    assert_eq!(
        timeout
            .read(&scrape_request(&scope(), "timeout"))
            .expect_err("timeout"),
        FirecrawlResearchEvidenceError::Timeout
    );
    let mut access = service_with_failure(FixtureFailure::AccessLost);
    assert_eq!(
        access
            .read(&scrape_request(&scope(), "access-lost"))
            .expect_err("access loss"),
        FirecrawlResearchEvidenceError::AccessLost
    );
}

#[test]
fn malformed_partial_content_citation_and_digest_tamper_fail_closed() {
    for failure in [
        FixtureFailure::Malformed,
        FixtureFailure::Partial,
        FixtureFailure::ContentType,
        FixtureFailure::CitationMismatch,
        FixtureFailure::ContentDigestMismatch,
        FixtureFailure::JobDigestMismatch,
        FixtureFailure::ResponseDigestMismatch,
        FixtureFailure::RegistrationDigestMismatch,
    ] {
        let mut service = service_with_failure(failure.clone());
        let error = service
            .read(&scrape_request(&scope(), "malformed-matrix"))
            .expect_err("failure must not become evidence");
        assert!(!matches!(error, FirecrawlResearchEvidenceError::AccessLost));
        assert!(!matches!(
            error,
            FirecrawlResearchEvidenceError::StatusNotSourceEvidence { .. }
        ));
    }
}

#[test]
fn cache_age_and_crawl_limits_are_enforced() {
    let (mut service, transport) = service();
    transport.set_cached_at_ms(Some(0));
    let error = service
        .read(&scrape_request(&scope(), "stale-cache"))
        .expect_err("stale cache");
    assert_eq!(error, FirecrawlResearchEvidenceError::CacheExpired);

    let scope = scope();
    let options = FirecrawlCrawlOptions::markdown(
        1,
        1,
        60_000,
        FirecrawlCachePolicy::new(FirecrawlCacheMode::PreferCache, 60_000).expect("cache"),
        FirecrawlExtractionSchema::none(),
    )
    .expect("crawl options");
    let request = FirecrawlJobRequest::crawl(
        scope.clone(),
        FirecrawlJobId::new("job-crawl-limited").expect("job"),
        "crawl-limited",
        100_000,
        CanonicalUrl::new("https://example.com/research").expect("URL"),
        options,
    )
    .expect("crawl request");
    let page_one = RawFirecrawlPage::default_for(request.url());
    let page_two = RawFirecrawlPage::new(
        CanonicalUrl::new("https://example.com/research/second").expect("second URL"),
        "Second page",
        200,
        "text/html",
        "second bounded page",
        request.job.extraction_schema_digest().clone(),
    )
    .expect("page");
    let transport = FixtureFirecrawlTransport::recording(scope.clone());
    transport.set_pages(vec![page_one, page_two]);
    let manifest = FirecrawlProviderManifest::fixture(&scope).expect("manifest");
    let provider = FirecrawlProvider::new(
        manifest,
        transport,
        StaticFirecrawlCredentialResolver::new("fixture-key"),
    )
    .expect("provider");
    let mut crawl_service = TestService::new(provider).expect("service");
    assert_eq!(
        crawl_service.crawl(&request).expect_err("page limit"),
        FirecrawlResearchEvidenceError::CrawlLimitExceeded {
            field: "response_pages"
        }
    );
}

#[test]
fn duplicate_replay_statuses_and_non_source_jobs_are_explicit() {
    let (mut service, _transport) = service();
    let request = scrape_request(&scope(), "replay");
    service.read(&request).expect("first read");
    assert_eq!(
        service.read(&request).expect_err("replay"),
        FirecrawlResearchEvidenceError::ReplayDetected
    );
    let duplicate_job = scrape_request(&scope(), "different-request-same-job");
    assert_eq!(
        service.read(&duplicate_job).expect_err("duplicate job"),
        FirecrawlResearchEvidenceError::DuplicateJob
    );

    for (failure, status) in [
        (
            FixtureFailure::Status(FirecrawlJobStatus::Queued),
            FirecrawlJobStatus::Queued,
        ),
        (
            FixtureFailure::Status(FirecrawlJobStatus::Running),
            FirecrawlJobStatus::Running,
        ),
        (
            FixtureFailure::Status(FirecrawlJobStatus::Failed),
            FirecrawlJobStatus::Failed,
        ),
        (
            FixtureFailure::Status(FirecrawlJobStatus::Canceled),
            FirecrawlJobStatus::Canceled,
        ),
        (
            FixtureFailure::Status(FirecrawlJobStatus::Expired),
            FirecrawlJobStatus::Expired,
        ),
        (
            FixtureFailure::ProviderUnknown,
            FirecrawlJobStatus::ProviderUnknown,
        ),
    ] {
        let mut service = service_with_failure(failure);
        let evidence = service
            .read(&scrape_request(&scope(), "non-source"))
            .expect("typed non-source status");
        assert_eq!(evidence.status, status);
        assert!(!evidence.is_source_evidence());
        let error = service
            .compile_research_proposal(MissionWorkProduct::fixture(&scope()), evidence)
            .expect_err("non-source cannot become proposal");
        assert!(matches!(
            error,
            FirecrawlResearchEvidenceError::StatusNotSourceEvidence { .. }
        ));
    }
}

#[test]
fn bounded_status_poll_is_a_local_read_job_projection() {
    let (mut service, transport) = service();
    let request = scrape_request(&scope(), "status-poll");
    let evidence = service.poll(&request).expect("poll evidence");
    assert_eq!(evidence.status, FirecrawlJobStatus::Completed);
    assert!(evidence.is_source_evidence());
    assert!(matches!(
        transport.operations().as_slice(),
        [FirecrawlTransportOperation::ReadJob { .. }]
    ));
}

#[test]
fn arbitrary_crawl_url_expansion_is_refused() {
    let scope = scope();
    let request = FirecrawlJobRequest::crawl(
        scope.clone(),
        FirecrawlJobId::new("job-expansion").expect("job"),
        "expansion",
        100_000,
        CanonicalUrl::new("https://example.com/research").expect("URL"),
        FirecrawlCrawlOptions::fixture(),
    )
    .expect("crawl request");
    let outside = RawFirecrawlPage::new(
        CanonicalUrl::new("https://other.example/research").expect("outside URL"),
        "Outside page",
        200,
        "text/html",
        "must not be expanded",
        request.job.extraction_schema_digest().clone(),
    )
    .expect("outside page");
    let transport = FixtureFirecrawlTransport::recording(scope.clone());
    transport.set_pages(vec![outside]);
    let manifest = FirecrawlProviderManifest::fixture(&scope).expect("manifest");
    let provider = FirecrawlProvider::new(
        manifest,
        transport,
        StaticFirecrawlCredentialResolver::new("fixture-key"),
    )
    .expect("provider");
    let mut service = TestService::new(provider).expect("service");
    assert!(matches!(
        service.crawl(&request),
        Err(FirecrawlResearchEvidenceError::UrlNotAllowlisted { .. })
    ));
}

#[test]
fn stale_mission_project_and_work_product_revisions_are_rejected() {
    let (mut service, _transport) = service();
    let scope = scope();
    let evidence = service
        .read(&scrape_request(&scope, "revision-fence"))
        .expect("evidence");
    let stale_mission = MissionWorkProduct::new(
        scope.project_id.clone(),
        scope.project_revision,
        scope.mission_id.clone(),
        scope.mission_revision + 1,
        scope.work_product_id.clone(),
        scope.work_product_revision,
        sha256_digest(b"work-product"),
        sha256_digest(b"objective"),
    )
    .expect("stale Mission work product");
    assert!(matches!(
        service.compile_research_proposal(stale_mission, evidence.clone()),
        Err(FirecrawlResearchEvidenceError::StaleMissionRevision { .. })
    ));

    let stale_project = MissionWorkProduct::new(
        scope.project_id.clone(),
        scope.project_revision + 1,
        scope.mission_id.clone(),
        scope.mission_revision,
        scope.work_product_id.clone(),
        scope.work_product_revision,
        sha256_digest(b"work-product"),
        sha256_digest(b"objective"),
    )
    .expect("stale Project work product");
    assert!(matches!(
        service.compile_research_proposal(stale_project, evidence.clone()),
        Err(FirecrawlResearchEvidenceError::StaleProjectRevision { .. })
    ));

    let stale_work_product = MissionWorkProduct::new(
        scope.project_id.clone(),
        scope.project_revision,
        scope.mission_id.clone(),
        scope.mission_revision,
        scope.work_product_id.clone(),
        scope.work_product_revision + 1,
        sha256_digest(b"work-product"),
        sha256_digest(b"objective"),
    )
    .expect("stale Work Product");
    assert!(matches!(
        service.compile_research_proposal(stale_work_product, evidence),
        Err(FirecrawlResearchEvidenceError::StaleWorkProductRevision { .. })
    ));
}

#[test]
fn registration_permission_and_citation_digests_are_checked_on_verification() {
    let (mut service, _transport) = service();
    let scope = scope();
    let evidence = service
        .read(&scrape_request(&scope, "verify-tamper"))
        .expect("evidence");
    let proposal = service
        .compile_research_proposal(MissionWorkProduct::fixture(&scope), evidence)
        .expect("proposal");
    let mut receipt = service.record_research_receipt(&proposal).expect("receipt");
    receipt.citation_digest = sha256_digest(b"citation-tamper");
    receipt.receipt_digest = receipt.calculate_digest();
    assert!(matches!(
        service.verify_research_evidence(&proposal, &receipt),
        Err(FirecrawlResearchEvidenceError::CitationMismatch)
    ));

    let mut stale_request = scrape_request(&scope, "stale-registration");
    stale_request.scope.permission_digest = String::from("permission-drift");
    assert!(stale_request.validate().is_err());
    assert!(
        FirecrawlPluginRegistration::new(&scope)
            .expect("registration")
            .validate(&scope)
            .is_ok()
    );
}

#[test]
fn fixture_recording_fake_loopback_are_never_connected_native_or_first_party() {
    let scope = scope();
    let providers = [
        FirecrawlProvider::fixture(scope.clone()).expect("fixture"),
        FirecrawlProvider::recording(scope.clone()).expect("recording"),
        FirecrawlProvider::fake(scope.clone()).expect("fake"),
        FirecrawlProvider::loopback(scope).expect("loopback"),
    ];
    for provider in providers {
        assert_eq!(provider.native_status(), NativeStatus::BlockedEnv);
        assert!(!provider.connected());
        assert!(!provider.native());
        assert!(!provider.first_party());
        assert!(!provider.provenance().is_connected());
        assert!(!provider.provenance().is_native());
        assert!(!provider.provenance().is_first_party());
    }
}

#[test]
fn content_and_registration_objects_are_digest_stable_and_redacted() {
    let scope = scope();
    let page = RawFirecrawlPage::default_for(&scope.allowlist.first_url().expect("URL"));
    let debug = format!("{page:?}");
    assert!(!debug.contains("Bounded fixture Markdown evidence"));
    assert_eq!(page.content_digest.len(), 64);
    assert_eq!(page.page_digest.len(), 64);
    let json = serde_json::to_string(&page).expect("page JSON");
    assert!(json.contains("contentDigest"));
    assert!(json.contains("pageDigest"));
    assert!(BTreeSet::<String>::new().is_empty());
}

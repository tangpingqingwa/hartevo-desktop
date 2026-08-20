use std::collections::BTreeMap;

use hartevo_opensearch_retrieval_plugin::{
    Digest, FixtureOpenSearchProvider, MissionRetrievalEvidenceConsumer,
    MissionRetrievalEvidenceRequest, NativeStatus, OpenSearchAccessLoss, OpenSearchAuthMode,
    OpenSearchConflictReason, OpenSearchEvidenceError, OpenSearchHit, OpenSearchMapping,
    OpenSearchPage, OpenSearchPitRequest, OpenSearchProvider, OpenSearchProviderError,
    OpenSearchProviderManifest, OpenSearchQuery, OpenSearchQueryClause, OpenSearchQueryPolicy,
    OpenSearchResultStatus, OpenSearchRetrievalService, OpenSearchScalar, OpenSearchScope,
    OpenSearchSearchAfterCursor, OpenSearchSearchRequest, OpenSearchSortField, OpenSearchSortOrder,
    OpenSearchTotalRelation, SecretKind,
};
use serde_json::Value;

fn scope(mission: &str) -> OpenSearchScope {
    OpenSearchScope::fixture(mission).expect("fixture scope")
}

fn query() -> OpenSearchQuery {
    OpenSearchQuery::new(
        OpenSearchQueryClause::match_text("title", "governed retrieval").expect("match"),
        [String::from("title"), String::from("tenant")],
        vec![
            OpenSearchSortField::new("updated_at", OpenSearchSortOrder::Asc).expect("sort"),
            OpenSearchSortField::new("_id", OpenSearchSortOrder::Asc).expect("tie-breaker"),
        ],
        10,
    )
    .expect("bounded query")
}

fn service() -> (
    OpenSearchRetrievalService<OpenSearchProvider>,
    OpenSearchScope,
    OpenSearchQueryPolicy,
) {
    let scope = scope("mission-open-search");
    let policy = OpenSearchQueryPolicy::fixture().expect("policy");
    let provider = FixtureOpenSearchProvider::fixture(scope.clone()).expect("provider");
    (
        OpenSearchRetrievalService::new(provider).expect("service"),
        scope,
        policy,
    )
}

fn request(
    service: &OpenSearchRetrievalService<OpenSearchProvider>,
    scope: &OpenSearchScope,
) -> (OpenSearchSearchRequest, OpenSearchQueryPolicy) {
    let proposal = service
        .compile_query_proposal(query())
        .expect("query proposal");
    let pit = service
        .create_pit(&OpenSearchPitRequest::at(scope.clone(), 60, 0).expect("pit request"))
        .expect("pit")
        .handle()
        .expect("opaque pit handle")
        .clone();
    let request =
        OpenSearchSearchRequest::at(scope.clone(), proposal, pit, None, 0).expect("search request");
    (request, OpenSearchQueryPolicy::fixture().expect("policy"))
}

fn hit(id: &str) -> OpenSearchHit {
    OpenSearchHit::new(
        id,
        vec![
            OpenSearchScalar::Integer(1),
            OpenSearchScalar::Text(id.to_owned()),
        ],
        BTreeMap::from([(
            String::from("title"),
            hartevo_opensearch_retrieval_plugin::OpenSearchSourceValue::Text(format!("title-{id}")),
        )]),
    )
    .expect("hit")
}

#[test]
fn contract_is_layer_one_and_authority_is_honest() {
    let contract: Value = serde_json::from_str(
        hartevo_opensearch_retrieval_plugin::OPENSEARCH_RETRIEVAL_CONTRACT_JSON,
    )
    .expect("contract JSON");
    assert_eq!(contract["contractVersion"], "EXT-OPENSEARCH-01-L1/v1");
    assert_eq!(contract["layer"], 1);
    assert_eq!(contract["queryPolicy"]["scroll"], "forbidden");
    assert_eq!(contract["pagination"]["pointInTime"], "required");
    assert_eq!(contract["authority"]["truthAuthority"], false);
    assert_eq!(contract["authority"]["durableReceipt"], false);
    assert_eq!(contract["native"]["status"], "BLOCKED_ENV");
    assert_eq!(
        contract["contractDigest"],
        hartevo_opensearch_retrieval_plugin::contract_digest().as_str()
    );
}

#[test]
fn service_and_mission_consumer_bind_scope_query_mapping_and_digests() {
    let (service, scope, policy) = service();
    let capabilities = service.describe_capabilities().expect("capabilities");
    assert_eq!(capabilities.native_status, NativeStatus::BlockedEnv);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.external_write);

    let proposal = service
        .compile_query_proposal(query())
        .expect("query proposal");
    proposal
        .validate_for(
            &scope,
            &OpenSearchMapping::fixture().expect("mapping"),
            &policy,
        )
        .expect("proposal binding");
    assert_eq!(proposal.scope_digest(), &scope.digest());
    assert!(!proposal.query_digest().as_str().is_empty());

    let pit = service
        .create_pit(&OpenSearchPitRequest::new(scope.clone(), 60).expect("pit request"))
        .expect("pit")
        .handle()
        .expect("pit handle")
        .clone();
    let search_request =
        OpenSearchSearchRequest::new(scope.clone(), proposal, pit, None).expect("search request");
    let page = service.search(&search_request).expect("search page");
    assert_eq!(page.status, OpenSearchResultStatus::Present);
    assert!(page.is_source_evidence());
    assert_eq!(page.hits.len(), 1);

    let mission_request = MissionRetrievalEvidenceRequest::new(
        scope,
        hartevo_opensearch_retrieval_plugin::ClaimId::new("claim-1").expect("claim"),
        hartevo_opensearch_retrieval_plugin::ResultId::new("result-1").expect("result"),
        1,
        Digest::from_text("consent"),
        policy.digest().clone(),
    )
    .expect("Mission request");
    let consumer = MissionRetrievalEvidenceConsumer::new(service);
    let evidence = consumer.consume(&mission_request, &page).expect("evidence");
    evidence.proposal.validate().expect("proposal digest");
    evidence
        .receipt_candidate
        .validate()
        .expect("receipt candidate");
    evidence.verification.validate().expect("read verification");
    assert!(!evidence.proposal.adopted);
    assert!(!evidence.proposal.can_claim_verified_source);
    assert!(!evidence.receipt_candidate.durable);
    assert!(!evidence.verification.read_back);
    assert!(!evidence.verification.kernel_verified);
}

#[test]
fn https_and_sigv4_plans_are_redacted_secret_reference_seams() {
    let scope = scope("mission-auth");
    let mapping = OpenSearchMapping::fixture().expect("mapping");
    let policy = OpenSearchQueryPolicy::fixture().expect("policy");
    let manifest = OpenSearchProviderManifest::https_secret_reference(
        scope.clone(),
        mapping.clone(),
        policy.clone(),
        SecretKind::Bearer,
    )
    .expect("HTTPS manifest");
    let provider = OpenSearchProvider::new(manifest).expect("provider");
    let pit_request = OpenSearchPitRequest::new(scope.clone(), 30).expect("pit");
    let plan = provider
        .request_plan_for_pit(&pit_request)
        .expect("HTTPS plan");
    assert!(plan.secret_reference_required);
    assert!(!plan.connected);
    assert!(!plan.native);
    assert!(!format!("{plan:?}").contains("raw-secret"));

    let secret = hartevo_opensearch_retrieval_plugin::SecretReference::with_kind(
        SecretKind::Bearer,
        "raw-secret-must-not-escape",
        scope.digest(),
        1,
    )
    .expect("opaque secret reference");
    assert!(!format!("{secret:?}").contains("raw-secret-must-not-escape"));
    assert!(
        !serde_json::to_string(&plan)
            .expect("plan JSON")
            .contains("raw-secret")
    );

    let sigv4 = OpenSearchProviderManifest::https_sigv4(scope, mapping, policy, "us-east-1", "es")
        .expect("SigV4 manifest");
    assert!(matches!(
        sigv4.auth_mode,
        OpenSearchAuthMode::HttpsSigV4 { .. }
    ));
}

#[test]
fn sort_stability_and_allowlists_fail_closed() {
    let missing_tie_breaker = OpenSearchQuery::new(
        OpenSearchQueryClause::match_text("title", "bounded").expect("query"),
        [String::from("title")],
        vec![OpenSearchSortField::new("updated_at", OpenSearchSortOrder::Asc).expect("sort")],
        10,
    );
    assert_eq!(
        missing_tie_breaker.expect_err("unstable sort"),
        OpenSearchEvidenceError::SortInstability
    );

    let (service, _, _) = service();
    let disallowed = OpenSearchQuery::new(
        OpenSearchQueryClause::term(
            "unregistered_field",
            OpenSearchScalar::Text(String::from("nope")),
        )
        .expect("typed term"),
        [String::from("title")],
        vec![
            OpenSearchSortField::new("updated_at", OpenSearchSortOrder::Asc).expect("sort"),
            OpenSearchSortField::new("_id", OpenSearchSortOrder::Asc).expect("tie-breaker"),
        ],
        10,
    )
    .expect("syntactically valid query");
    assert!(matches!(
        service.compile_query_proposal(disallowed),
        Err(OpenSearchEvidenceError::FieldNotAllowlisted { .. })
    ));
}

#[test]
fn pagination_uses_pit_search_after_and_rejects_cursor_loops() {
    let (service, scope, _) = service();
    let (first_request, _) = request(&service, &scope);
    let pit = first_request.pit.as_ref().expect("pit").clone();
    let cursor = OpenSearchSearchAfterCursor::new(
        &pit,
        first_request.query_digest(),
        vec![
            OpenSearchScalar::Integer(1),
            OpenSearchScalar::Text(String::from("hit-1")),
        ],
        1,
    )
    .expect("cursor");
    let manifest = service.provider_manifest().expect("manifest");
    let first_page = OpenSearchPage::recorded(
        &first_request,
        &manifest,
        vec![hit("hit-1")],
        2,
        OpenSearchTotalRelation::Eq,
        false,
        Vec::new(),
        Some(cursor.clone()),
        Some(1),
    )
    .expect("first page");
    let second_request = OpenSearchSearchRequest::new(
        scope.clone(),
        first_request.proposal.clone(),
        pit.clone(),
        Some(cursor.clone()),
    )
    .expect("second request");
    let second_page = OpenSearchPage::recorded(
        &second_request,
        &manifest,
        vec![hit("hit-2")],
        2,
        OpenSearchTotalRelation::Eq,
        false,
        Vec::new(),
        None,
        Some(1),
    )
    .expect("second page");
    service
        .provider()
        .set_search_responses([Ok(first_page), Ok(second_page)]);
    let result = service
        .paginate(first_request.clone(), 2)
        .expect("bounded pagination");
    assert_eq!(result.page_count, 2);
    assert_eq!(result.hits.len(), 2);
    assert_eq!(result.status, OpenSearchResultStatus::Present);

    let looping_page = OpenSearchPage::recorded(
        &second_request,
        &manifest,
        vec![hit("hit-loop")],
        3,
        OpenSearchTotalRelation::Eq,
        false,
        Vec::new(),
        Some(cursor),
        Some(1),
    )
    .expect("looping page");
    service.provider().set_search_responses([
        Ok(OpenSearchPage::recorded(
            &first_request,
            &manifest,
            vec![hit("hit-1")],
            3,
            OpenSearchTotalRelation::Eq,
            false,
            Vec::new(),
            Some(
                OpenSearchSearchAfterCursor::new(
                    &pit,
                    first_request.query_digest(),
                    vec![
                        OpenSearchScalar::Integer(1),
                        OpenSearchScalar::Text(String::from("hit-1")),
                    ],
                    1,
                )
                .expect("loop cursor"),
            ),
            Some(1),
        )
        .expect("loop first")),
        Ok(looping_page),
    ]);
    assert_eq!(
        service
            .paginate(first_request, 3)
            .expect_err("cursor loop")
            .to_string(),
        OpenSearchEvidenceError::CursorLoop.to_string()
    );
}

#[test]
fn pit_expiry_mapping_drift_tamper_and_partial_shards_are_typed() {
    let (service, scope, _) = service();
    let proposal = service.compile_query_proposal(query()).expect("proposal");
    let pit = service
        .create_pit(&OpenSearchPitRequest::at(scope.clone(), 2, 10).expect("pit"))
        .expect("pit")
        .handle()
        .expect("handle")
        .clone();
    let expired =
        OpenSearchSearchRequest::at(scope.clone(), proposal.clone(), pit.clone(), None, 12)
            .expect("expired request");
    assert_eq!(
        service.search(&expired).expect_err("expired PIT"),
        OpenSearchEvidenceError::PitExpired
    );

    let (request, _) = request(&service, &scope);
    let clean = service.search(&request).expect("clean");
    let mut tampered = clean.clone();
    tampered.hits[0].source_digest = Digest::from_text("tamper");
    service.provider().set_search_response(Ok(tampered));
    assert_eq!(
        service.search(&request).expect_err("tampered hit"),
        OpenSearchEvidenceError::TamperedResponse
    );

    let manifest = service.provider_manifest().expect("manifest");
    let mut drifted = clean;
    drifted.mapping_digest = Digest::from_text("mapping-drift");
    service.provider().set_search_response(Ok(drifted));
    assert!(matches!(
        service.search(&request),
        Err(OpenSearchEvidenceError::MappingDrift { .. })
    ));

    let shard_page = OpenSearchPage::recorded(
        &request,
        &manifest,
        vec![hit("shard-hit")],
        1,
        OpenSearchTotalRelation::Eq,
        false,
        vec![
            hartevo_opensearch_retrieval_plugin::OpenSearchShardFailure::new(
                "shard-0",
                503,
                "timeout detail is digest-only",
            )
            .expect("shard failure"),
        ],
        None,
        Some(20),
    )
    .expect("shard page");
    service.provider().set_search_response(Ok(shard_page));
    let page = service.search(&request).expect("partial shard projection");
    assert_eq!(page.status, OpenSearchResultStatus::ShardFailure);
    assert!(!page.is_source_evidence());
}

#[test]
fn empty_success_is_distinct_from_access_deleted_and_unknown() {
    let (service, scope, _) = service();
    let (request, _) = request(&service, &scope);
    let manifest = service.provider_manifest().expect("manifest");
    let empty = OpenSearchPage::recorded(
        &request,
        &manifest,
        Vec::new(),
        0,
        OpenSearchTotalRelation::Eq,
        false,
        Vec::new(),
        None,
        Some(0),
    )
    .expect("empty success");
    service.provider().set_search_response(Ok(empty));
    let page = service.search(&request).expect("empty");
    assert_eq!(page.status, OpenSearchResultStatus::Empty);
    assert!(page.is_empty_success());
    assert!(page.is_source_evidence());

    for (error, expected) in [
        (
            OpenSearchProviderError::Unauthorized401 {
                access: OpenSearchAccessLoss::Unauthorized,
            },
            OpenSearchResultStatus::AccessLoss,
        ),
        (
            OpenSearchProviderError::NotFound404 { deleted: true },
            OpenSearchResultStatus::Deleted,
        ),
        (
            OpenSearchProviderError::ProviderUnknown {
                operation: hartevo_opensearch_retrieval_plugin::OpenSearchOperation::Search,
            },
            OpenSearchResultStatus::ProviderUnknown,
        ),
    ] {
        assert_eq!(error.projection().status, expected);
    }
}

#[test]
fn all_http_statuses_timeout_rate_limit_and_conflict_are_typed_without_bodies() {
    for status in [401, 403, 404, 409, 429, 500, 503] {
        assert_eq!(
            OpenSearchProviderError::from_status(status).status_code(),
            Some(status)
        );
    }
    assert_eq!(
        OpenSearchProviderError::Conflict409 {
            reason: OpenSearchConflictReason::MappingDrift,
        }
        .status_code(),
        Some(409)
    );
    assert_eq!(OpenSearchProviderError::Timeout.status_code(), None);
    assert_eq!(
        OpenSearchProviderError::RateLimited429 {
            retry_after_seconds: Some(5),
        }
        .projection()
        .status,
        OpenSearchResultStatus::ProviderUnknown
    );
    let debug = format!(
        "{:?}",
        OpenSearchProviderError::Unauthorized401 {
            access: OpenSearchAccessLoss::CredentialRevoked,
        }
    );
    assert!(!debug.contains("raw-secret"));
}

#[test]
fn fixture_recording_fake_loopback_and_blocked_env_never_claim_connected_or_native() {
    let scope = scope("mission-provenance");
    let mapping = OpenSearchMapping::fixture().expect("mapping");
    let policy = OpenSearchQueryPolicy::fixture().expect("policy");
    let providers = [
        OpenSearchProvider::fixture(scope.clone()).expect("fixture"),
        OpenSearchProvider::recording(scope.clone(), mapping.clone(), policy.clone())
            .expect("recording"),
        OpenSearchProvider::fake(scope.clone(), mapping.clone(), policy.clone()).expect("fake"),
        OpenSearchProvider::loopback(scope.clone(), mapping.clone(), policy.clone())
            .expect("loopback"),
    ];
    for provider in providers {
        let manifest = provider.current_manifest();
        assert_eq!(manifest.native_status, NativeStatus::BlockedEnv);
        assert!(!manifest.connected);
        assert!(!manifest.native);
        assert!(!provider.external_write_available());
    }
    let blocked = OpenSearchProvider::blocked_env(scope, mapping, policy).expect("blocked env");
    assert_eq!(
        blocked
            .create_pit(
                &OpenSearchPitRequest::new(
                    OpenSearchScope::fixture("mission-provenance").expect("scope"),
                    30,
                )
                .expect("pit")
            )
            .expect_err("blocked")
            .projection()
            .status,
        OpenSearchResultStatus::ProviderUnknown
    );
}

#[test]
fn registration_is_versioned_scope_bound_reversible_and_revocable() {
    let scope = scope("mission-registration");
    let manifest = OpenSearchProviderManifest::fixture(scope).expect("manifest");
    manifest.validate().expect("manifest");
    assert!(manifest.registration.reversible);
    assert!(manifest.registration.enabled);
    let revoked = manifest.revoked().expect("revoked");
    assert!(!revoked.registration.enabled);
    assert_ne!(revoked.manifest_digest, manifest.manifest_digest);
    assert!(revoked.validate().is_err());
    let reactivated = revoked.reactivated().expect("reactivated");
    reactivated.validate().expect("reactivated manifest");

    let provider =
        OpenSearchProvider::fixture(OpenSearchScope::fixture("mission-revocation").expect("scope"))
            .expect("provider");
    let service = OpenSearchRetrievalService::new(provider.clone()).expect("service");
    provider.revoke().expect("revoke");
    assert_eq!(
        service
            .describe_capabilities()
            .expect_err("revoked")
            .to_string(),
        OpenSearchEvidenceError::RegistrationRevoked.to_string()
    );
}

#[test]
fn query_values_and_source_projections_are_bounded() {
    let oversized = OpenSearchQueryClause::match_text("title", "x".repeat(9 * 1024));
    assert!(oversized.is_err());
    let oversized_source = OpenSearchHit::new(
        "hit",
        vec![OpenSearchScalar::Text(String::from("sort"))],
        BTreeMap::from([(
            String::from("title"),
            hartevo_opensearch_retrieval_plugin::OpenSearchSourceValue::Text("x".repeat(5 * 1024)),
        )]),
    );
    assert!(oversized_source.is_err());
    let json_projection = hartevo_opensearch_retrieval_plugin::OpenSearchSourceValue::JsonDigest(
        Digest::from_text("bounded-json"),
    );
    assert!(
        serde_json::to_string(&json_projection)
            .expect("JSON projection")
            .contains("jsonDigest")
    );
}

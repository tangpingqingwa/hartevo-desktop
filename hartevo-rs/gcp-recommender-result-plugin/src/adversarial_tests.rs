use super::*;

fn scope() -> GcpRecommenderScope {
    let permission = PermissionScope::read_only("recommender-read", 1).expect("permission");
    let consent = ConsentScope::new("mission-read-consent", 1).expect("consent");
    let spec = GcpRecommenderScopeSpec::new(
        GcpParent::project("gcp-project").expect("parent"),
        Location::new("us-central1").expect("location"),
        GcpResultKind::Recommendation(RecommenderId::new("cost").expect("recommender")),
        vec![Digest::from_text("resource-1")],
        ProjectBinding::new(ProjectId::new("hartevo-project").expect("project"), 1)
            .expect("project binding"),
        MissionBinding::new(MissionId::new("mission-1").expect("mission"), 1)
            .expect("mission binding"),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product"),
            1,
        )
        .expect("work product binding"),
        permission,
        consent,
    )
    .with_allowed_subtypes([RecommendationSubtype::new("rightsizing").expect("subtype")]);
    GcpRecommenderScope::new(spec).expect("scope")
}

fn query() -> GcpRecommenderQuery {
    let filters = ResultFilters::new(
        [RecommendationState::Active],
        [RecommendationPriority::P1],
        [RecommendationSubtype::new("rightsizing").expect("subtype")],
    )
    .expect("filters");
    GcpRecommenderQuery::new(filters, 2, 4, 8).expect("query")
}

fn record(
    scope: &GcpRecommenderScope,
    state: RecommendationState,
    etag: &str,
    revision: u64,
) -> GcpRecommenderRecord {
    GcpRecommenderRecord::new(
        scope.result_kind().clone(),
        ResultId::new("recommendation-1").expect("result id"),
        Some(RecommendationPriority::P1),
        RecommendationSubtype::new("rightsizing").expect("subtype"),
        state,
        ImpactCategory::Cost,
        ImpactCategory::Cost,
        Timestamp::new(1_700_000_000).expect("refresh"),
        Timestamp::new(1_700_000_100).expect("observed"),
        vec![Digest::from_text("resource-1")],
        Digest::from_text("redacted-content"),
        Digest::from_text(etag),
        revision,
    )
    .expect("record")
}

fn materialize_requests(
    scope: &GcpRecommenderScope,
    query: &GcpRecommenderQuery,
    token: Option<OpaquePageToken>,
) -> (
    SecretReference,
    GcpRecommenderListRequest,
    GcpRecommenderGetRequest,
    GcpRecommenderRecord,
) {
    let secret = SecretReference::new("opaque-gcp-reference", scope, 1, GoogleAuthKind::OAuth)
        .expect("secret");
    let list_request = GcpRecommenderListRequest::from_scope(scope, query, &secret, 1, token);
    let result = ResultId::new("recommendation-1").expect("result id");
    let get_request = GcpRecommenderGetRequest::from_scope(scope, query, &secret, result, None);
    let result_record = record(scope, RecommendationState::Active, "etag-1", 1);
    (secret, list_request, get_request, result_record)
}

fn service_with_list_results(
    list_results: Vec<Result<GcpRecommenderListResponse, TransportError>>,
) -> GcpRecommenderService<GcpRecommenderProvider<FixtureGcpRecommenderTransport>> {
    let scope = scope();
    let query = query();
    let (secret, request, get_request, result_record) = materialize_requests(&scope, &query, None);
    let list_response =
        GcpRecommenderListResponse::new(&request, vec![result_record.clone()], None, true);
    let get_response = GcpRecommenderGetResponse::new(&get_request, result_record);
    let transport = FixtureGcpRecommenderTransport::from_results(
        if list_results.is_empty() {
            vec![Ok(list_response)]
        } else {
            list_results
        },
        vec![Ok(get_response)],
    );
    let provider =
        GcpRecommenderProvider::layer1(transport, ProviderProvenance::Fixture).expect("provider");
    GcpRecommenderService::with_query(scope, query, secret, provider, RetryPolicy::default())
        .expect("service")
}

#[test]
fn complete_list_proposal_record_and_mission_consume_are_read_only() {
    let scope = scope();
    let query = query();
    let (secret, request, get_request, result_record) = materialize_requests(&scope, &query, None);
    let list_response =
        GcpRecommenderListResponse::new(&request, vec![result_record.clone()], None, true);
    let get_response = GcpRecommenderGetResponse::new(&get_request, result_record);
    let transport = FixtureGcpRecommenderTransport::new(list_response, get_response);
    let provider =
        GcpRecommenderProvider::layer1(transport, ProviderProvenance::Fixture).expect("provider");
    let mut service = GcpRecommenderService::with_query(
        scope.clone(),
        query,
        secret,
        provider,
        RetryPolicy::default(),
    )
    .expect("service");
    let proposal = service.propose_list().expect("proposal");
    service.verify(&proposal).expect("proposal verifies");
    let receipt = service.record(&proposal).expect("record receipt");
    assert!(receipt.recorded);
    assert!(!receipt.durable);
    assert!(!receipt.connected);
    assert!(!receipt.native);
    assert!(!receipt.independent_native_readback);
    assert!(!receipt.adopts_outcome);

    let mut consumer = MissionGcpRecommendationConsumer::new(scope);
    let result = consumer.consume(proposal).expect("consume");
    assert_eq!(result.state, MissionGcpRecommendationState::Complete);
    assert!(!result.adopted_work_product);
    assert!(!result.outcome_authority);
    assert!(!result.marks_recommendation);
    assert!(!result.executes_operation_group);
    assert_eq!(result.provider_provenance, ProviderProvenance::Fixture);
}

#[test]
fn all_recommendation_states_are_typed_and_filters_are_allowlisted() {
    let all_states = [
        RecommendationState::Active,
        RecommendationState::Dismissed,
        RecommendationState::Claimed,
        RecommendationState::Failed,
        RecommendationState::Succeeded,
    ];
    let filters = ResultFilters::new(
        all_states,
        [RecommendationPriority::P1, RecommendationPriority::P2],
        [RecommendationSubtype::new("rightsizing").expect("subtype")],
    )
    .expect("filters");
    let query = GcpRecommenderQuery::new(filters, 10, 1, 10).expect("query");
    let scope = scope();
    let secret = SecretReference::new(
        "opaque-gcp-reference",
        &scope,
        1,
        GoogleAuthKind::ServiceAccount,
    )
    .expect("secret");
    let request = GcpRecommenderListRequest::from_scope(&scope, &query, &secret, 1, None);
    let list_response = GcpRecommenderListResponse::new(
        &request,
        vec![record(&scope, RecommendationState::Claimed, "etag", 1)],
        None,
        true,
    );
    let get_request = GcpRecommenderGetRequest::from_scope(
        &scope,
        &query,
        &secret,
        ResultId::new("recommendation-1").expect("id"),
        None,
    );
    let get_response = GcpRecommenderGetResponse::new(
        &get_request,
        record(&scope, RecommendationState::Claimed, "etag", 1),
    );
    let provider = GcpRecommenderProvider::layer1(
        FixtureGcpRecommenderTransport::new(list_response, get_response),
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    let mut service =
        GcpRecommenderService::with_query(scope, query, secret, provider, RetryPolicy::default())
            .expect("service");
    let evidence = service.read_list().expect("all allowlisted states read");
    assert_eq!(evidence.records[0].state, RecommendationState::Claimed);
}

#[test]
fn pagination_binds_opaque_cursor_to_exact_query_and_filter() {
    let scope = scope();
    let query = query();
    let (secret, request_one, get_request, result_record) =
        materialize_requests(&scope, &query, None);
    let cursor = OpaquePageToken::new("opaque-page-token").expect("cursor");
    let response_one = GcpRecommenderListResponse::new(
        &request_one,
        vec![result_record.clone()],
        Some(cursor.clone()),
        true,
    );
    let request_two =
        GcpRecommenderListRequest::from_scope(&scope, &query, &secret, 2, Some(cursor));
    let response_two = GcpRecommenderListResponse::new(&request_two, Vec::new(), None, true);
    let get_response = GcpRecommenderGetResponse::new(&get_request, result_record);
    let transport = RecordingGcpRecommenderTransport::from_results(
        vec![Ok(response_one), Ok(response_two)],
        vec![Ok(get_response)],
    );
    let provider =
        GcpRecommenderProvider::layer1(transport, ProviderProvenance::Recording).expect("provider");
    let mut service =
        GcpRecommenderService::with_query(scope, query, secret, provider, RetryPolicy::default())
            .expect("service");
    let evidence = service.read_list().expect("list evidence");
    assert_eq!(evidence.projection, ResultProjection::Complete);
    assert_eq!(evidence.page_count, 2);
    let requests = service.provider().transport().list_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].page_token_digest(), None);
    assert!(requests[1].page_token_digest().is_some());
    assert_eq!(evidence.page_token_digests.len(), 2);
    assert_eq!(evidence.records.len(), 1);
}

#[test]
fn loopback_provenance_is_explicitly_non_native() {
    let scope = scope();
    let query = query();
    let (secret, request, get_request, result_record) = materialize_requests(&scope, &query, None);
    let list_response =
        GcpRecommenderListResponse::new(&request, vec![result_record.clone()], None, true);
    let get_response = GcpRecommenderGetResponse::new(&get_request, result_record);
    let provider = GcpRecommenderProvider::layer1(
        LoopbackGcpRecommenderTransport::new(list_response, get_response),
        ProviderProvenance::Loopback,
    )
    .expect("loopback provider");
    let mut service =
        GcpRecommenderService::with_query(scope, query, secret, provider, RetryPolicy::default())
            .expect("loopback service");
    let evidence = service.read_list().expect("loopback evidence");
    assert_eq!(evidence.provider_provenance, ProviderProvenance::Loopback);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
}

#[test]
fn opaque_secret_and_page_token_never_serialize_or_debug_print_raw_values() {
    let scope = scope();
    let query = query();
    let token = OpaquePageToken::new("super-secret-cursor").expect("cursor");
    let secret = SecretReference::new("super-secret-reference", &scope, 1, GoogleAuthKind::OAuth)
        .expect("secret");
    let request = GcpRecommenderListRequest::from_scope(&scope, &query, &secret, 1, Some(token));
    let json = serde_json::to_string(&request).expect("request serializes safely");
    let debug = format!("{request:?}{secret:?}");
    assert!(!json.contains("super-secret-cursor"));
    assert!(!debug.contains("super-secret-cursor"));
    assert!(!debug.contains("super-secret-reference"));
    assert!(json.contains("pageTokenDigest"));
}

#[test]
fn response_tamper_target_escape_and_version_drift_fail_closed() {
    let mut service = service_with_list_results(Vec::new());
    // The fixture response is consumed through the provider, so construct a
    // fresh service with an intentionally stale response digest for the
    // tamper assertion.
    let scope = scope();
    let query = query();
    let (secret, request, get_request, result_record) = materialize_requests(&scope, &query, None);
    let mut response =
        GcpRecommenderListResponse::new(&request, vec![result_record.clone()], None, true);
    response.records[0].state = RecommendationState::Dismissed;
    let get_response = GcpRecommenderGetResponse::new(&get_request, result_record.clone());
    let provider = GcpRecommenderProvider::layer1(
        FixtureGcpRecommenderTransport::new(response, get_response),
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    let mut tampered_service = GcpRecommenderService::with_query(
        scope.clone(),
        query.clone(),
        secret.clone(),
        provider,
        RetryPolicy::default(),
    )
    .expect("service");
    assert_eq!(
        tampered_service.read_list(),
        Err(GcpRecommenderServiceError::TamperedEvidence)
    );

    let escaped = GcpRecommenderRecord::new(
        scope.result_kind().clone(),
        ResultId::new("recommendation-1").expect("id"),
        Some(RecommendationPriority::P1),
        RecommendationSubtype::new("rightsizing").expect("subtype"),
        RecommendationState::Active,
        ImpactCategory::Cost,
        ImpactCategory::Cost,
        Timestamp::new(1).expect("time"),
        Timestamp::new(2).expect("time"),
        vec![Digest::from_text("outside-scope")],
        Digest::from_text("content"),
        Digest::from_text("etag"),
        1,
    )
    .expect("escaped record");
    let request = GcpRecommenderListRequest::from_scope(&scope, &query, &secret, 1, None);
    let response = GcpRecommenderListResponse::new(&request, vec![escaped], None, true);
    let get_request = GcpRecommenderGetRequest::from_scope(
        &scope,
        &query,
        &secret,
        ResultId::new("recommendation-1").expect("id"),
        None,
    );
    let get_response = GcpRecommenderGetResponse::new(
        &get_request,
        record(&scope, RecommendationState::Active, "etag", 1),
    );
    let provider = GcpRecommenderProvider::layer1(
        FixtureGcpRecommenderTransport::new(response, get_response),
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    let mut escaped_service = GcpRecommenderService::with_query(
        scope.clone(),
        query,
        secret,
        provider,
        RetryPolicy::default(),
    )
    .expect("service");
    assert_eq!(
        escaped_service.read_list(),
        Err(GcpRecommenderServiceError::TargetOutOfScope)
    );

    let binding = PageTokenBinding::new(
        OpaquePageToken::new("cursor").expect("cursor"),
        scope.digest(),
        Digest::from_text("query"),
        Digest::from_text("filter"),
        2,
    );
    assert!(
        binding
            .validate(
                &scope.digest(),
                &Digest::from_text("different-query"),
                binding.filter_digest(),
                2,
            )
            .is_err()
    );

    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.read_list(),
        Err(GcpRecommenderServiceError::RegistrationRevoked)
    );
    let mut revoked_secret = service_with_list_results(Vec::new());
    revoked_secret.revoke_secret().expect("revoke secret");
    assert_eq!(
        revoked_secret.read_list(),
        Err(GcpRecommenderServiceError::SecretRevoked)
    );
}

#[test]
fn provider_error_provenance_is_truthful_and_retry_is_bounded() {
    let errors = [
        (TransportError::bad_request(), ResultProjection::FinalError),
        (
            TransportError::unauthenticated(),
            ResultProjection::AccessLost,
        ),
        (
            TransportError::access_denied(),
            ResultProjection::AccessLost,
        ),
        (TransportError::not_found(), ResultProjection::FinalError),
        (TransportError::conflict(), ResultProjection::FinalError),
    ];
    for (error, expected) in errors {
        let mut service = service_with_list_results(vec![Err(error)]);
        let evidence = service.read_list().expect("provider error is evidence");
        assert_eq!(evidence.projection, expected);
        assert!(!evidence.connected);
        assert!(!evidence.native);
        assert!(!evidence.first_party);
        assert_eq!(evidence.provider_errors.len(), 1);
    }

    let mut rate_limited = service_with_list_results(vec![
        Err(TransportError::rate_limited()),
        Err(TransportError::rate_limited()),
        Err(TransportError::rate_limited()),
    ]);
    let evidence = rate_limited.read_list().expect("rate limit evidence");
    assert_eq!(evidence.projection, ResultProjection::RateLimited);
    assert_eq!(evidence.retries.len(), 2);
    assert_eq!(evidence.provider_errors.len(), 1);

    let mut server_failure = service_with_list_results(vec![
        Err(TransportError::server_failure(503)),
        Err(TransportError::server_failure(503)),
        Err(TransportError::server_failure(503)),
    ]);
    let evidence = server_failure.read_list().expect("server failure evidence");
    assert_eq!(evidence.projection, ResultProjection::ProviderUnknown);
    assert_eq!(evidence.retries.len(), 2);

    let mut timeout = service_with_list_results(vec![
        Err(TransportError::timeout()),
        Err(TransportError::timeout()),
        Err(TransportError::timeout()),
    ]);
    let evidence = timeout.read_list().expect("timeout evidence");
    assert_eq!(evidence.projection, ResultProjection::ProviderUnknown);
    assert_eq!(evidence.retries.len(), 2);

    let blocked_scope = scope();
    let blocked_query = query();
    let blocked_secret = SecretReference::new(
        "blocked-env-reference",
        &blocked_scope,
        1,
        GoogleAuthKind::OAuth,
    )
    .expect("blocked secret");
    let blocked_provider = GcpRecommenderProvider::layer1(
        BlockedEnvGcpRecommenderTransport::new(),
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut blocked_service = GcpRecommenderService::with_query(
        blocked_scope,
        blocked_query,
        blocked_secret,
        blocked_provider,
        RetryPolicy::default(),
    )
    .expect("blocked service");
    let evidence = blocked_service.read_list().expect("blocked env evidence");
    assert_eq!(evidence.projection, ResultProjection::BlockedEnv);
    assert_eq!(evidence.provider_provenance, ProviderProvenance::BlockedEnv);
    assert!(!evidence.connected);
    assert!(!evidence.native);
}

#[test]
fn get_etag_and_revision_fences_are_enforced_without_mutation_methods() {
    let scope = scope();
    let query = query();
    let (secret, list_request, _get_request, original) = materialize_requests(&scope, &query, None);
    let list_response = GcpRecommenderListResponse::new(&list_request, Vec::new(), None, true);
    let expected = original.version_fence();
    let changed = record(&scope, RecommendationState::Active, "new-etag", 2);
    let get_request = GcpRecommenderGetRequest::from_scope(
        &scope,
        &query,
        &secret,
        original.result_id.clone(),
        Some(expected.clone()),
    );
    let get_response = GcpRecommenderGetResponse::new(&get_request, changed);
    let provider = GcpRecommenderProvider::layer1(
        FixtureGcpRecommenderTransport::new(list_response, get_response),
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    let mut service =
        GcpRecommenderService::with_query(scope, query, secret, provider, RetryPolicy::default())
            .expect("service");
    assert_eq!(
        service.read_get(original.result_id, Some(expected)),
        Err(GcpRecommenderServiceError::EtagDrift)
    );
}

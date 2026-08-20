use hartevo_gcp_recommender_result_plugin::*;

fn insight_scope() -> GcpRecommenderScope {
    let spec = GcpRecommenderScopeSpec::new(
        GcpParent::organization("organization-1").expect("organization"),
        Location::new("global").expect("location"),
        GcpResultKind::Insight(InsightTypeId::new("security").expect("insight type")),
        vec![Digest::from_text("resource-fingerprint")],
        ProjectBinding::new(ProjectId::new("project-1").expect("project"), 1)
            .expect("project binding"),
        MissionBinding::new(MissionId::new("mission-1").expect("mission"), 1)
            .expect("mission binding"),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product"),
            1,
        )
        .expect("work product binding"),
        PermissionScope::read_only("recommender-read", 1).expect("permission"),
        ConsentScope::new("mission-consent", 1).expect("consent"),
    )
    .with_allowed_subtypes([RecommendationSubtype::new("security").expect("subtype")]);
    GcpRecommenderScope::new(spec).expect("scope")
}

#[test]
fn standalone_public_root_supports_insight_mission_consumption() {
    validate_contract().expect("contract");
    let scope = insight_scope();
    let query = GcpRecommenderQuery::bounded(
        ResultFilters::new(
            [RecommendationState::Active],
            [],
            [RecommendationSubtype::new("security").expect("subtype")],
        )
        .expect("filters"),
    )
    .expect("query");
    let secret = SecretReference::new(
        "opaque-reference",
        &scope,
        1,
        GoogleAuthKind::ServiceAccount,
    )
    .expect("secret");
    let list_request = GcpRecommenderListRequest::from_scope(&scope, &query, &secret, 1, None);
    let record = GcpRecommenderRecord::new(
        scope.result_kind().clone(),
        ResultId::new("insight-1").expect("result"),
        None,
        RecommendationSubtype::new("security").expect("subtype"),
        RecommendationState::Active,
        ImpactCategory::Security,
        ImpactCategory::Security,
        Timestamp::new(1_700_000_000).expect("refresh"),
        Timestamp::new(1_700_000_001).expect("observed"),
        vec![Digest::from_text("resource-fingerprint")],
        Digest::from_text("redacted-insight-content"),
        Digest::from_text("etag-1"),
        1,
    )
    .expect("record");
    let list_response =
        GcpRecommenderListResponse::new(&list_request, vec![record.clone()], None, true);
    let get_request = GcpRecommenderGetRequest::from_scope(
        &scope,
        &query,
        &secret,
        ResultId::new("insight-1").expect("result"),
        None,
    );
    let get_response = GcpRecommenderGetResponse::new(&get_request, record);
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
    let mut consumer = MissionGcpRecommendationConsumer::new(scope);
    let result = consumer.read(&mut service).expect("mission result");
    assert_eq!(result.state, MissionGcpRecommendationState::Complete);
    assert_eq!(result.consumer_id, GCP_RECOMMENDER_RESULT_CONSUMER_ID);
    assert!(!result.outcome_authority);
    assert!(!result.marks_recommendation);
    assert!(!result.executes_operation_group);
}

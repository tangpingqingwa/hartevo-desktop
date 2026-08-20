use super::*;

fn scope() -> ObservabilityScope {
    let project = ProjectBinding::new(ProjectId::new("project-r1").unwrap(), 1).unwrap();
    let work_product =
        WorkProductBinding::new(WorkProductId::new("work-product-r1").unwrap(), 3).unwrap();
    let consent = ConsentBinding::read_only(Digest::from_text("consent-r1")).unwrap();
    let mission = MissionBinding::new(
        MissionId::new("mission-r1").unwrap(),
        7,
        &project,
        &work_product,
        &consent,
    )
    .unwrap();
    let entity_type = EntityType::new("APM-APPLICATION").unwrap();
    let policy = PolicyReference::new(PolicyId::new("policy-17").unwrap(), "policy-rev-4").unwrap();
    let condition = ConditionReference::new(
        ConditionId::new("condition-23").unwrap(),
        &policy,
        "condition-rev-2",
    )
    .unwrap();
    ObservabilityScope::new(
        AccountId::new(42).unwrap(),
        EntityReference::new(
            EntityGuid::new("MXxBUE18QVBQTElDQVRJT058NDI").unwrap(),
            entity_type.clone(),
        )
        .unwrap(),
        WorkloadReference::new(
            WorkloadId::new("checkout-service").unwrap(),
            "checkout-service production",
            entity_type,
        )
        .unwrap(),
        policy,
        condition,
        TimeWindow::new(1_700_000_000_000, 1_700_003_600_000).unwrap(),
        mission,
        project,
        work_product,
        consent,
        PermissionSnapshot::new(
            vec![
                Permission::EntitySearchRead,
                Permission::EntitySummaryRead,
                Permission::AlertPolicyRead,
                Permission::NrqlConditionRead,
                Permission::IssuesRead,
                Permission::IssueEventsRead,
            ],
            9,
        )
        .unwrap(),
        QueryPolicy::bounded_default().unwrap(),
    )
    .unwrap()
}

fn complete_responses(scope: &ObservabilityScope) -> Vec<Result<ProviderResponse, TransportError>> {
    let guid = scope.entity().guid.clone();
    let entity_type = scope.entity().entity_type.clone();
    let entity = EntityRecord::new(
        guid.clone(),
        entity_type.clone(),
        Some(true),
        Some(Severity::Medium),
        Some(scope.time_window().end_millis),
    )
    .unwrap();
    let policy = PolicyRecord::new(
        scope.policy().id.clone(),
        Some(true),
        1,
        Digest::from_text("policy-definition-rev-4"),
    )
    .unwrap();
    let condition = ConditionRecord::new(
        scope.condition().id.clone(),
        scope.policy().id.clone(),
        ConditionType::Static,
        Some(true),
        Digest::from_text("condition-rev-2"),
        Digest::from_text("nrql-definition-digest-only"),
        Some(scope.time_window().end_millis),
    )
    .unwrap();
    let issue = IssueRecord::new(
        IssueId::new("issue-99").unwrap(),
        Severity::High,
        IssueState::Activated,
        vec![guid.clone()],
        vec![entity_type.clone()],
        "raw title must not survive projection",
        Some(scope.time_window().end_millis),
    )
    .unwrap();
    let event = IssueEventRecord::new(
        issue.id.clone(),
        Severity::High,
        IssueState::Activated,
        IssueEventType::IncidentAdded,
        "raw incident title must not survive projection",
        Some(scope.time_window().end_millis),
    )
    .unwrap();
    vec![
        Ok(ProviderResponse::Entities(
            EntityPage::new(vec![entity], None, 512).unwrap(),
        )),
        Ok(ProviderResponse::EntitySummary(
            EntityPage::new(Vec::new(), None, 128).unwrap(),
        )),
        Ok(ProviderResponse::Policies(
            PolicyPage::new(vec![policy], None, 384).unwrap(),
        )),
        Ok(ProviderResponse::Conditions(
            ConditionPage::new(vec![condition], None, 448).unwrap(),
        )),
        Ok(ProviderResponse::Issues(
            IssuePage::new(vec![issue], None, 768).unwrap(),
        )),
        Ok(ProviderResponse::IssueEvents(
            IssueEventPage::new(vec![event], None, 448).unwrap(),
        )),
    ]
}

fn service_with_responses(
    responses: Vec<Result<ProviderResponse, TransportError>>,
) -> NewRelicObservabilityResultService<FixtureTransport> {
    let scope = scope();
    let secret =
        SecretReference::from_opaque_handle("opaque-secret-reference", scope.digest()).unwrap();
    let provider = NewRelicProvider::fixture(FixtureTransport::new(responses)).unwrap();
    NewRelicObservabilityResultService::new(scope, secret, provider).unwrap()
}

#[test]
fn complete_projection_is_digest_bound_and_redacted() {
    let scope = scope();
    let mut service = service_with_responses(complete_responses(&scope));
    let result = service.observe().unwrap();

    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.state, ObservationState::Alerting);
    assert!(result.evidence.authority == AuthorityBoundary::layer1());
    result.verify(&scope).unwrap();
    let receipt = service.record_observation_receipt(&result).unwrap();
    service.verify_receipt(&result, &receipt).unwrap();

    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("raw title must not survive"));
    assert!(!json.contains("raw incident title must not survive"));
    assert!(!json.contains("opaque-secret-reference"));
    assert!(!json.contains("connected\":true"));
    assert!(!json.contains("native\":true"));
}

#[test]
fn tampered_scope_and_evidence_are_rejected() {
    let scope = scope();
    let mut service = service_with_responses(complete_responses(&scope));
    let mut result = service.observe().unwrap();

    result.evidence.issues[0].priority = Severity::Critical;
    assert_eq!(
        service.verify_result(&result),
        Err(ServiceError::TamperedEvidence)
    );

    let mut clean_service = service_with_responses(complete_responses(&scope));
    let mut clean_result = clean_service.observe().unwrap();
    clean_result.evidence.scope_digest = Digest::from_text("scope-drift");
    assert_eq!(
        clean_service.verify_result(&clean_result),
        Err(ServiceError::TamperedEvidence)
    );
}

#[test]
fn mission_staleness_and_revocation_fail_closed() {
    let scope = scope();
    let mut service = service_with_responses(complete_responses(&scope));
    let result = service.observe().unwrap();
    let mut consumer = MissionNewRelicObservabilityConsumer::new(&scope);
    consumer.bind_registration(service.registration()).unwrap();
    consumer.consume(&result).unwrap();

    let stale_mission = MissionBinding::new(
        MissionId::new("mission-replaced").unwrap(),
        8,
        service.scope().project(),
        service.scope().work_product(),
        service.scope().consent(),
    )
    .unwrap();
    consumer.replace_mission(stale_mission);
    assert_eq!(consumer.consume(&result), Err(ConsumerError::StaleMission));

    service.revoke_registration().unwrap();
    assert_eq!(
        service.verify_result(&result),
        Err(ServiceError::RegistrationRevoked)
    );
    assert_eq!(service.observe(), Err(ServiceError::RegistrationRevoked));
}

#[test]
fn rate_limit_is_bounded_and_partial_is_not_consumable() {
    let scope = scope();
    let mut responses = vec![
        Err(TransportError::throttled(Some(10_000))),
        Err(TransportError::throttled(Some(10_000))),
        Err(TransportError::throttled(Some(10_000))),
    ];
    responses.extend(complete_responses(&scope).into_iter().skip(1));
    let mut service = service_with_responses(responses);
    let result = service.observe().unwrap();

    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(result.evidence.retries.len(), 2);
    assert!(
        result
            .evidence
            .retries
            .iter()
            .all(|retry| retry.delay_millis <= MAX_RETRY_DELAY_MILLIS)
    );
    let mut consumer = MissionNewRelicObservabilityConsumer::new(&scope);
    consumer.bind_registration(service.registration()).unwrap();
    assert_eq!(
        consumer.consume(&result),
        Err(ConsumerError::PartialEvidence)
    );
}

#[test]
fn duplicate_cursor_page_is_partial_and_cursor_is_opaque() {
    let scope = scope();
    let request = NewRelicReadRequest::first(&scope, ReadOperation::SearchEntities).unwrap();
    let cursor = OpaqueCursor::new("provider-cursor-value", &request.query_digest, 2).unwrap();
    let entity = EntityRecord::new(
        scope.entity().guid.clone(),
        scope.entity().entity_type.clone(),
        Some(true),
        None,
        Some(scope.time_window().end_millis),
    )
    .unwrap();
    let first = ProviderResponse::Entities(
        EntityPage::new(vec![entity.clone()], Some(cursor), 512).unwrap(),
    );
    let second = ProviderResponse::Entities(EntityPage::new(vec![entity], None, 512).unwrap());
    let mut responses = vec![Ok(first), Ok(second)];
    responses.extend(complete_responses(&scope).into_iter().skip(1));
    let mut service = service_with_responses(responses);
    let result = service.observe().unwrap();
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert!(result.evidence.completeness.duplicate_detected);
    assert!(!format!("{request:?}").contains("provider-cursor-value"));
    assert!(
        !serde_json::to_string(&request)
            .unwrap()
            .contains("provider-cursor-value")
    );
}

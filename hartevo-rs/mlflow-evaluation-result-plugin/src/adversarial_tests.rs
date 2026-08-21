use super::*;

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn revisions() -> ScopeRevisions {
    ScopeRevisions::new(
        Revision::new(11).expect("experiment revision"),
        Revision::new(12).expect("run revision"),
        Revision::new(13).expect("dataset revision"),
        Revision::new(14).expect("mission revision"),
        Revision::new(15).expect("project revision"),
        Revision::new(16).expect("work product revision"),
    )
}

fn scope() -> MlflowScope {
    MlflowScope::new(
        digest("tracking-server"),
        [ExperimentId::new("experiment-1").expect("experiment")],
        [RunId::new("run-1").expect("run")],
        [MetricKey::new("accuracy").expect("metric")],
        [ParamKey::new("model").expect("param")],
        [TagKey::new("environment").expect("tag")],
        [DatasetDigest::new("dataset-1").expect("dataset")],
        MissionId::new("mission-1").expect("mission"),
        ProjectId::new("project-1").expect("project"),
        WorkProductId::new("work-product-1").expect("work product"),
        revisions(),
        digest("permission-1"),
        digest("consent-1"),
    )
    .expect("scope")
}

fn bounds() -> ResultBounds {
    ResultBounds::new(10, 10, 10, 4, 10, 16 * 1024).expect("bounds")
}

fn secret(scope: &MlflowScope) -> SecretReference {
    SecretReference::new("mlflow-secret-ref", scope, 3, MlflowAuthKind::ApiToken).expect("secret")
}

fn make_recording_service(
    retry_policy: RetryPolicy,
) -> MlflowEvaluationResultService<RecordingMlflowProvider> {
    let scope = scope();
    let secret = secret(&scope);
    let provider = RecordingMlflowProvider::new("1.0.0").expect("provider");
    MlflowEvaluationResultService::new(scope, secret, provider, retry_policy).expect("service")
}

fn request(service: &MlflowEvaluationResultService<RecordingMlflowProvider>) -> MlflowReadRequest {
    MlflowReadRequest::get_run(
        RunId::new("run-1").expect("run"),
        bounds(),
        service.scope().revisions().work_product,
    )
}

fn run_record(scope: &MlflowScope) -> RunRecord {
    let dataset = DatasetReference::new(
        "private-dataset-name",
        DatasetDigest::new("dataset-1").expect("dataset"),
        Some("evaluation"),
    );
    let metric = MetricValue::new(
        MetricKey::new("accuracy").expect("metric"),
        0.91,
        1_700_000_000_000,
        0,
        Some(DatasetDigest::new("dataset-1").expect("dataset")),
    )
    .expect("metric");
    let parameter =
        RedactedAttribute::from_public_value("model", "private-model-value").expect("parameter");
    let tag = RedactedAttribute::from_public_value("environment", "private-user-tag").expect("tag");
    RunRecord::new(
        RunId::new("run-1").expect("run"),
        ExperimentId::new("experiment-1").expect("experiment"),
        RunStatus::Finished,
        Some(1_700_000_000_000),
        Some(1_700_000_001_000),
        Some("private-run-name"),
        Some("private-user-id"),
        vec![metric],
        vec![parameter],
        vec![tag],
        vec![dataset],
        scope.revisions().run,
    )
}

fn page_for(
    proposal: &MlflowReadProposal,
    runs: Vec<RunRecord>,
    history: Vec<MetricHistoryPoint>,
    next_page_token: Option<OpaquePageToken>,
    complete: bool,
) -> MlflowResponsePage {
    MlflowResponsePage::for_proposal(
        proposal,
        Vec::new(),
        runs,
        history,
        next_page_token,
        complete,
        proposal.credential_revision(),
        512,
    )
}

#[test]
fn typed_filters_reject_injection_and_redact_values() {
    let scope = scope();
    let injection = FilterValue::text("value' OR '1'='1").expect("quoted literal is safe");
    let filter = MlflowFilter::new(
        &scope,
        [FilterClause::new(
            FilterField::Tag(TagKey::new("environment").expect("tag")),
            FilterOperator::Eq,
            injection,
        )
        .expect("clause")],
    )
    .expect("filter");
    assert!(!format!("{filter:?}").contains("value' OR"));
    assert!(
        !serde_json::to_string(&filter)
            .expect("filter JSON")
            .contains("value' OR")
    );
    assert!(matches!(
        FilterValue::text("value; DROP TABLE runs"),
        Err(FilterCompileError::InvalidLiteral)
    ));
    assert!(matches!(
        MlflowFilter::new(
            &scope,
            [FilterClause::new(
                FilterField::Param(ParamKey::new("not-allowed").expect("key")),
                FilterOperator::Eq,
                FilterValue::text("x").expect("value"),
            )
            .expect("clause")]
        ),
        Err(FilterCompileError::FieldNotAllowlisted)
    ));
    let dataset_filter = MlflowFilter::new(
        &scope,
        [FilterClause::new(
            FilterField::DatasetDigest,
            FilterOperator::Eq,
            FilterValue::text("not-allowlisted").expect("value"),
        )
        .expect("clause")],
    );
    assert!(matches!(
        dataset_filter,
        Err(FilterCompileError::FieldNotAllowlisted)
    ));
}

#[test]
fn secret_and_page_tokens_are_opaque_and_non_serializing() {
    let scope = scope();
    let secret = secret(&scope);
    let token = OpaquePageToken::new("private-page-token").expect("token");
    assert!(!format!("{secret:?}").contains("mlflow-secret-ref"));
    assert!(!format!("{token:?}").contains("private-page-token"));
    assert!(matches!(
        OpaquePageToken::new("token with whitespace"),
        Err(ModelError::InvalidPageToken)
    ));
}

#[test]
fn complete_recorded_run_is_bounded_redacted_and_not_authority() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let request = request(&service);
    let proposal = service.propose(request).expect("proposal");
    let run = run_record(service.scope());
    service.provider_mut().push_response(Ok(page_for(
        &proposal,
        vec![run],
        Vec::new(),
        None,
        true,
    )));
    let result = service.record(proposal).expect("recorded result");
    assert_eq!(result.status, ResultStatus::Complete);
    assert_eq!(result.evidence.runs.len(), 1);
    assert_eq!(result.evidence.pages_observed, 1);
    assert_eq!(
        result.evidence.provider_provenance,
        ProviderProvenance::Recording
    );
    assert!(result.evidence.digests.scope_digest == result.evidence.scope_digest);
    assert!(!result.authority.connected());
    assert!(!result.authority.native());
    assert!(!result.authority.truth());
    assert!(!result.authority.adopted());
    assert!(!result.is_adopted());
    let evidence_json = serde_json::to_string(&result.evidence).expect("evidence JSON");
    for secret_value in [
        "private-model-value",
        "private-user-tag",
        "private-user-id",
        "private-run-name",
        "private-dataset-name",
    ] {
        assert!(
            !evidence_json.contains(secret_value),
            "leaked {secret_value}"
        );
    }
}

#[test]
fn pagination_loop_becomes_explicit_partial_state() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let proposal = service
        .propose(MlflowReadRequest::search_runs(
            [ExperimentId::new("experiment-1").expect("experiment")],
            MlflowFilter::empty(service.scope()),
            bounds(),
            service.scope().revisions().work_product,
        ))
        .expect("proposal");
    let token = OpaquePageToken::new("cursor-1").expect("token");
    let first = page_for(
        &proposal,
        vec![run_record(service.scope())],
        Vec::new(),
        Some(token.clone()),
        false,
    );
    let second = page_for(&proposal, Vec::new(), Vec::new(), Some(token), false);
    service.provider_mut().push_response(Ok(first));
    service.provider_mut().push_response(Ok(second));
    let result = service.record(proposal).expect("partial result");
    assert_eq!(
        result.status,
        ResultStatus::Partial(PartialReason::PaginationLoop)
    );
    assert_eq!(result.evidence.page_token_digests.len(), 1);
}

#[test]
fn metric_history_bound_is_enforced_without_unbounded_retention() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let narrow_bounds = ResultBounds::new(10, 10, 1, 2, 10, 16 * 1024).expect("bounds");
    let request = MlflowReadRequest::metric_history(
        RunId::new("run-1").expect("run"),
        MetricKey::new("accuracy").expect("metric"),
        narrow_bounds,
        service.scope().revisions().work_product,
    );
    let proposal = service.propose(request).expect("proposal");
    let metric = MetricValue::new(
        MetricKey::new("accuracy").expect("metric"),
        0.8,
        10,
        0,
        None,
    )
    .expect("metric");
    let point_one = MetricHistoryPoint::new(metric.clone());
    let point_two = MetricHistoryPoint::new(
        MetricValue::new(
            MetricKey::new("accuracy").expect("metric"),
            0.9,
            11,
            1,
            None,
        )
        .expect("metric"),
    );
    service.provider_mut().push_response(Ok(page_for(
        &proposal,
        Vec::new(),
        vec![point_one, point_two],
        None,
        true,
    )));
    let result = service.record(proposal).expect("bounded result");
    assert_eq!(
        result.status,
        ResultStatus::Partial(PartialReason::MetricHistoryLimit)
    );
    assert_eq!(result.evidence.metric_history.len(), 1);
}

#[test]
fn tampered_response_is_rejected_before_evidence_is_recorded() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let proposal = service.propose(request(&service)).expect("proposal");
    let mut page = page_for(
        &proposal,
        vec![run_record(service.scope())],
        Vec::new(),
        None,
        true,
    );
    page.response_bytes += 1;
    service.provider_mut().push_response(Ok(page));
    assert!(matches!(
        service.record(proposal),
        Err(ServiceError::TamperedEvidence)
    ));
}

#[test]
fn http_and_timeout_failures_map_to_explicit_states_without_diagnostics() {
    let cases = [
        (
            TransportError::http(400, "bad request details"),
            ResultStatus::FinalError,
        ),
        (
            TransportError::http(401, "user token"),
            ResultStatus::AccessLoss,
        ),
        (
            TransportError::http(403, "policy details"),
            ResultStatus::AccessLoss,
        ),
        (TransportError::http(404, "gone run"), ResultStatus::Stale),
        (
            TransportError::http(409, "revision conflict"),
            ResultStatus::ProviderUnknown,
        ),
        (
            TransportError::http(429, "rate limit details"),
            ResultStatus::ProviderUnknown,
        ),
        (
            TransportError::http(500, "server stack details"),
            ResultStatus::ProviderUnknown,
        ),
        (
            TransportError::timeout("socket timeout details"),
            ResultStatus::ProviderUnknown,
        ),
    ];
    for (error, expected) in cases {
        let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
        let proposal = service.propose(request(&service)).expect("proposal");
        service.provider_mut().push_response(Err(error));
        let result = service.record(proposal).expect("error evidence");
        assert_eq!(result.status, expected);
        let encoded = serde_json::to_string(&result.evidence).expect("evidence JSON");
        assert!(!encoded.contains("details"));
    }
}

#[test]
fn retries_are_bounded_and_captured_as_digest_only_evidence() {
    let mut service = make_recording_service(RetryPolicy::new(3).expect("retry"));
    let proposal = service.propose(request(&service)).expect("proposal");
    service
        .provider_mut()
        .push_response(Err(TransportError::http(429, "first")));
    service
        .provider_mut()
        .push_response(Err(TransportError::http(500, "second")));
    service
        .provider_mut()
        .push_response(Err(TransportError::timeout("third")));
    let result = service.record(proposal).expect("unknown result");
    assert_eq!(result.status, ResultStatus::ProviderUnknown);
    assert_eq!(result.evidence.retries.len(), 2);
    assert_eq!(result.evidence.provider_errors.len(), 1);
}

#[test]
fn provider_provenance_fixture_loopback_and_blocked_env_is_explicit() {
    let scope = scope();
    let secret = secret(&scope);
    let fixture = FixtureMlflowProvider::new("1.0.0").expect("fixture provider");
    let mut fixture_service = MlflowEvaluationResultService::new(
        scope.clone(),
        secret.clone(),
        fixture,
        RetryPolicy::new(1).expect("retry"),
    )
    .expect("fixture service");
    let fixture_proposal = fixture_service
        .propose(MlflowReadRequest::get_run(
            RunId::new("run-1").expect("run"),
            bounds(),
            scope.revisions().work_product,
        ))
        .expect("proposal");
    fixture_service.provider_mut().push_response(Ok(page_for(
        &fixture_proposal,
        vec![run_record(&scope)],
        Vec::new(),
        None,
        true,
    )));
    let fixture_result = fixture_service
        .record(fixture_proposal)
        .expect("fixture result");
    assert_eq!(
        fixture_result.evidence.provider_provenance,
        ProviderProvenance::Fixture
    );

    let loopback = LoopbackMlflowProvider::new("1.0.0").expect("loopback provider");
    let mut loopback_service = MlflowEvaluationResultService::new(
        scope.clone(),
        secret.clone(),
        loopback,
        RetryPolicy::new(1).expect("retry"),
    )
    .expect("loopback service");
    let loopback_result = loopback_service
        .read(MlflowReadRequest::get_run(
            RunId::new("run-1").expect("run"),
            bounds(),
            scope.revisions().work_product,
        ))
        .expect("loopback result");
    assert_eq!(
        loopback_result.evidence.provider_provenance,
        ProviderProvenance::Loopback
    );
    assert_eq!(loopback_result.status, ResultStatus::ProviderUnknown);

    let blocked = BlockedEnvMlflowProvider::new("1.0.0").expect("blocked provider");
    let mut blocked_service = MlflowEvaluationResultService::new(
        scope,
        secret,
        blocked,
        RetryPolicy::new(1).expect("retry"),
    )
    .expect("blocked service");
    let blocked_result = blocked_service
        .read(MlflowReadRequest::get_run(
            RunId::new("run-1").expect("run"),
            bounds(),
            revisions().work_product,
        ))
        .expect("blocked result");
    assert_eq!(blocked_result.status, ResultStatus::ProviderUnknown);
    assert_eq!(
        blocked_result.evidence.provider_provenance,
        ProviderProvenance::BlockedEnv
    );
    assert!(blocked_result.evidence.provider_errors[0].blocked_env);
}

#[test]
fn consumer_is_mission_project_work_product_bound_and_reversible() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let request = request(&service);
    let proposal = service.propose(request).expect("proposal");
    let run = run_record(service.scope());
    let proposal_copy = proposal.clone();
    service.provider_mut().push_response(Ok(page_for(
        &proposal,
        vec![run],
        Vec::new(),
        None,
        true,
    )));
    let result = service.record(proposal).expect("result");
    let mut consumer = MissionMlflowEvaluationConsumer::new(
        service.scope().clone(),
        service.registration(),
        service.secret_reference(),
    )
    .expect("consumer");
    let mission_result = consumer
        .consume(result.clone(), &proposal_copy)
        .expect("mission result");
    assert_eq!(mission_result.status, ResultStatus::Complete);
    assert_eq!(
        mission_result.state,
        MissionMlflowResultState::PendingDecision
    );
    assert_eq!(mission_result.mission_id.as_str(), "mission-1");
    assert_eq!(mission_result.project_id.as_str(), "project-1");
    assert!(!mission_result.authority.connected());
    assert!(!mission_result.authority.kernel());
    assert!(!mission_result.authority.adopted());
    assert_eq!(proposal_copy.operation(), MlflowOperation::GetRun);
    consumer.revoke().expect("revoke consumer");
    assert!(matches!(
        consumer.consume(result, &proposal_copy),
        Err(ConsumerError::Revoked)
    ));
    service.revoke_registration().expect("revoke registration");
    assert!(!service.is_active());
}

#[test]
fn stale_and_partial_states_are_not_promoted_to_decision_ready() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let proposal = service.propose(request(&service)).expect("proposal");
    let proposal_copy = proposal.clone();
    service
        .provider_mut()
        .push_response(Err(TransportError::http(404, "stale")));
    let stale = service.record(proposal).expect("stale result");
    let mut consumer = MissionMlflowEvaluationConsumer::new(
        service.scope().clone(),
        service.registration(),
        service.secret_reference(),
    )
    .expect("consumer");
    let mission_result = consumer
        .consume(stale, &proposal_copy)
        .expect("mission result");
    assert_eq!(
        mission_result.state,
        MissionMlflowResultState::Layer2AdoptionRequired
    );
    assert!(!mission_result.authority.truth());
    assert_eq!(
        mission_result.adoption,
        AdoptionAvailability::NotAdoptedLayer2
    );
    consumer.revoke().expect("revoke");
}

#[test]
fn malformed_dataset_digest_filters_fail_closed_and_require_nonempty_binding() {
    let scope = scope();
    let malformed = MlflowFilter::new(
        &scope,
        [FilterClause::new(
            FilterField::DatasetDigest,
            FilterOperator::Eq,
            FilterValue::text("not a digest").expect("literal"),
        )
        .expect("clause")],
    );
    assert!(matches!(
        malformed,
        Err(FilterCompileError::MalformedDatasetDigest)
    ));

    let empty_dataset_scope = MlflowScope::new(
        scope.tracking_server_digest().clone(),
        scope.allowlisted_experiments().iter().cloned(),
        scope.allowlisted_runs().iter().cloned(),
        scope.allowlisted_metrics().iter().cloned(),
        scope.allowlisted_params().iter().cloned(),
        scope.allowlisted_tags().iter().cloned(),
        [],
        scope.mission_id().clone(),
        scope.project_id().clone(),
        scope.work_product_id().clone(),
        scope.revisions(),
        scope.permission_digest().clone(),
        scope.consent_digest().clone(),
    )
    .expect("scope without dataset allowlist");
    let unbound = MlflowFilter::new(
        &empty_dataset_scope,
        [FilterClause::new(
            FilterField::DatasetDigest,
            FilterOperator::Eq,
            FilterValue::text("dataset-1").expect("literal"),
        )
        .expect("clause")],
    );
    assert!(matches!(
        unbound,
        Err(FilterCompileError::DatasetDigestAllowlistRequired)
    ));
}

#[test]
fn validated_leaf_serde_rejects_bypasses_and_unknown_revision_fields() {
    assert!(serde_json::from_str::<Digest>("\"not-a-digest\"").is_err());
    assert!(serde_json::from_str::<ExperimentId>("\"invalid id\"").is_err());
    assert!(serde_json::from_str::<DatasetDigest>("\"bad/digest\"").is_err());
    assert!(serde_json::from_str::<Revision>("0").is_err());
    let unknown_fields = serde_json::json!({
        "experiment": 11,
        "run": 12,
        "dataset": 13,
        "mission": 14,
        "project": 15,
        "work_product": 16,
        "extra": 17
    });
    assert!(serde_json::from_value::<ScopeRevisions>(unknown_fields).is_err());
    let encoded =
        serde_json::to_string(&Revision::new(17).expect("revision")).expect("revision JSON");
    assert_eq!(
        serde_json::from_str::<Revision>(&encoded)
            .expect("validated revision")
            .get(),
        17
    );
}

#[test]
fn response_byte_overflow_truncates_before_retention_and_stops_pagination() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let narrow_bounds = ResultBounds::new(10, 10, 10, 4, 10, 256).expect("bounds");
    let proposal = service
        .propose(MlflowReadRequest::get_run(
            RunId::new("run-1").expect("run"),
            narrow_bounds,
            service.scope().revisions().work_product,
        ))
        .expect("proposal");
    let token = OpaquePageToken::new("must-not-be-followed").expect("token");
    let overflow_run = run_record(service.scope());
    service
        .provider_mut()
        .push_response(Ok(MlflowResponsePage::for_proposal(
            &proposal,
            Vec::new(),
            vec![overflow_run],
            Vec::new(),
            Some(token),
            true,
            proposal.credential_revision(),
            512,
        )));
    service
        .provider_mut()
        .push_response(Ok(MlflowResponsePage::empty(&proposal)));
    let result = service.record(proposal).expect("bounded partial result");
    assert_eq!(
        result.status,
        ResultStatus::Partial(PartialReason::ResponseBytesLimit)
    );
    assert!(result.evidence.runs.is_empty());
    assert_eq!(service.provider().calls().len(), 1);
}

#[test]
fn nested_record_bounds_fail_closed_before_retention() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let proposal = service.propose(request(&service)).expect("proposal");
    let metrics = (0..=crate::model::MAX_RUN_METRICS_PER_RECORD)
        .map(|step| {
            MetricValue::new(
                MetricKey::new("accuracy").expect("metric"),
                0.5,
                step as u64,
                i64::try_from(step).expect("test step fits"),
                None,
            )
            .expect("metric")
        })
        .collect();
    let oversized = RunRecord::new(
        RunId::new("run-1").expect("run"),
        ExperimentId::new("experiment-1").expect("experiment"),
        RunStatus::Finished,
        None,
        None,
        None::<&str>,
        None::<&str>,
        metrics,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        service.scope().revisions().run,
    );
    service.provider_mut().push_response(Ok(page_for(
        &proposal,
        vec![oversized],
        Vec::new(),
        None,
        true,
    )));
    assert!(matches!(
        service.record(proposal),
        Err(ServiceError::BoundExceeded)
    ));
}

#[test]
fn exact_get_cardinality_rejects_empty_and_duplicate_complete_pages() {
    let mut empty_service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let empty_proposal = empty_service
        .propose(request(&empty_service))
        .expect("proposal");
    empty_service
        .provider_mut()
        .push_response(Ok(MlflowResponsePage::empty(&empty_proposal)));
    assert!(matches!(
        empty_service.record(empty_proposal),
        Err(ServiceError::InvalidResponseShape)
    ));

    let mut duplicate_service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let duplicate_proposal = duplicate_service
        .propose(request(&duplicate_service))
        .expect("proposal");
    let run = run_record(duplicate_service.scope());
    duplicate_service.provider_mut().push_response(Ok(page_for(
        &duplicate_proposal,
        vec![run.clone(), run],
        Vec::new(),
        None,
        true,
    )));
    assert!(matches!(
        duplicate_service.record(duplicate_proposal),
        Err(ServiceError::InvalidResponseShape)
    ));

    let mut experiment_service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let experiment_proposal = experiment_service
        .propose(MlflowReadRequest::get_experiment(
            ExperimentId::new("experiment-1").expect("experiment"),
            bounds(),
            experiment_service.scope().revisions().work_product,
        ))
        .expect("proposal");
    experiment_service
        .provider_mut()
        .push_response(Ok(MlflowResponsePage::empty(&experiment_proposal)));
    assert!(matches!(
        experiment_service.record(experiment_proposal),
        Err(ServiceError::InvalidResponseShape)
    ));
}

#[test]
fn consumer_requires_exact_proposal_parity_and_live_revocation_fences() {
    let mut service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let proposal = service.propose(request(&service)).expect("proposal");
    let proposal_copy = proposal.clone();
    let consumer_run = run_record(service.scope());
    service.provider_mut().push_response(Ok(page_for(
        &proposal,
        vec![consumer_run],
        Vec::new(),
        None,
        true,
    )));
    let result = service.record(proposal).expect("result");
    let consumer = MissionMlflowEvaluationConsumer::new(
        service.scope().clone(),
        service.registration(),
        service.secret_reference(),
    )
    .expect("consumer");
    let mut wrong_operation = result.clone();
    wrong_operation.operation = MlflowOperation::SearchRuns;
    assert!(matches!(
        consumer.consume(wrong_operation, &proposal_copy),
        Err(ConsumerError::ProposalMismatch)
    ));

    service.revoke_secret().expect("secret revocation");
    assert!(matches!(
        consumer.consume(result.clone(), &proposal_copy),
        Err(ConsumerError::Revoked)
    ));

    let mut registration_service = make_recording_service(RetryPolicy::new(1).expect("retry"));
    let registration_proposal = registration_service
        .propose(request(&registration_service))
        .expect("proposal");
    let registration_proposal_copy = registration_proposal.clone();
    let registration_run = run_record(registration_service.scope());
    registration_service
        .provider_mut()
        .push_response(Ok(page_for(
            &registration_proposal,
            vec![registration_run],
            Vec::new(),
            None,
            true,
        )));
    let registration_result = registration_service
        .record(registration_proposal)
        .expect("result");
    let registration_consumer = MissionMlflowEvaluationConsumer::new(
        registration_service.scope().clone(),
        registration_service.registration(),
        registration_service.secret_reference(),
    )
    .expect("consumer");
    registration_service
        .revoke_registration()
        .expect("registration revocation");
    assert!(matches!(
        registration_consumer.consume(registration_result, &registration_proposal_copy),
        Err(ConsumerError::Revoked)
    ));
    assert!(!LiveRevocationFence::durable());
}

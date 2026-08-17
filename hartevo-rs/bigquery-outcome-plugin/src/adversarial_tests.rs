use super::*;
type TestProvider = BigQueryJobsProvider<RecordingBigQueryTransport>;

#[derive(Clone)]
struct Fixture {
    scope: BigQueryScope,
    secret: SecretReference,
    query: ParameterizedSelect,
    bounds: ResultBounds,
    proposal: BigQueryQueryProposal,
    job: JobMetadata,
    schema: QuerySchema,
    row: BoundedRow,
}

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn fixture_with_bounds(bounds: ResultBounds) -> Fixture {
    let scope = BigQueryScope::new(
        ProjectId::new("project-1").expect("project"),
        Location::new("US").expect("location"),
        DatasetId::new("analytics").expect("dataset"),
        [TableId::new("events").expect("table")],
        MissionId::new("mission-1").expect("mission"),
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(7).expect("revision"),
        digest("permission-revision-1"),
        digest("consent-1"),
    )
    .expect("scope");
    let secret = SecretReference::new("google-secret-ref", &scope, 3, GoogleAuthKind::OAuth)
        .expect("secret reference");
    let query = ParameterizedSelect::compile(
        &scope,
        format!(
            "SELECT id FROM `project-1.analytics.events` WHERE id = @id LIMIT {}",
            bounds.max_rows().min(2)
        ),
        [
            QueryParameter::from_public_value("id", QueryParameterType::Int64, "7")
                .expect("parameter"),
        ],
        bounds,
    )
    .expect("query");
    let proposal = BigQueryQueryProposal::compile(
        &scope,
        &secret,
        QueryProposalRequest::new(
            query.clone(),
            bounds,
            QueryMode::BoundedReadProposal,
            scope.work_product_revision(),
        ),
    )
    .expect("proposal");
    let job = JobMetadata::new(
        JobReference::new(
            scope.project_id().clone(),
            scope.location().clone(),
            JobId::new("job-1").expect("job"),
        ),
        JobState::Done,
        proposal.query_digest().clone(),
        proposal.config_digest().clone(),
        scope.scope_digest(),
        scope.permission_digest().clone(),
        secret.credential_revision(),
        false,
    );
    let schema = QuerySchema::new(vec![
        QuerySchemaField::new("id", CellType::Integer, false).expect("field"),
    ])
    .expect("schema");
    let row = BoundedRow::new(vec![
        RedactedCell::from_public_value(CellType::Integer, "7").expect("redacted cell"),
    ])
    .expect("row");
    Fixture {
        scope,
        secret,
        query,
        bounds,
        proposal,
        job,
        schema,
        row,
    }
}

fn new_fixture() -> Fixture {
    fixture_with_bounds(ResultBounds::new(10, 1_024, 4, 10).expect("bounds"))
}

fn query_request(fixture: &Fixture) -> QueryProposalRequest {
    QueryProposalRequest::new(
        fixture.query.clone(),
        fixture.bounds,
        QueryMode::BoundedReadProposal,
        fixture.scope.work_product_revision(),
    )
}

fn query_response(
    fixture: &Fixture,
    job: JobMetadata,
    complete: bool,
    rows: Vec<BoundedRow>,
    next_page_token: Option<OpaquePageToken>,
    errors: Vec<QueryErrorEvidence>,
) -> JobsQueryResponse {
    JobsQueryResponse::new(
        job,
        complete,
        Some(fixture.schema.clone()),
        rows,
        next_page_token,
        Some(1),
        42,
        Some(false),
        errors,
        fixture.scope.fence(),
        fixture.secret.credential_revision(),
    )
}

fn result_page(
    fixture: &Fixture,
    job: JobMetadata,
    complete: bool,
    rows: Vec<BoundedRow>,
    next_page_token: Option<OpaquePageToken>,
    errors: Vec<QueryErrorEvidence>,
) -> QueryResultPage {
    QueryResultPage::new(
        job,
        complete,
        Some(fixture.schema.clone()),
        rows,
        next_page_token,
        Some(1),
        42,
        Some(false),
        errors,
        fixture.scope.fence(),
        fixture.secret.credential_revision(),
    )
}

fn service_with(
    fixture: &Fixture,
    initial: Result<JobsQueryResponse, TransportError>,
    pages: impl IntoIterator<Item = Result<QueryResultPage, TransportError>>,
    provenance: ProviderProvenance,
) -> BigQueryResultService<TestProvider> {
    let mut transport = RecordingBigQueryTransport::default();
    transport.push_query_response(initial);
    for page in pages {
        transport.push_page_response(page);
    }
    let provider = BigQueryJobsProvider::new(transport, "1.0.0", provenance).expect("provider");
    BigQueryResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
        RetryPolicy::default(),
    )
    .expect("service")
}

#[test]
fn query_compilation_is_allowlisted_parameterized_and_bounded() {
    let fixture = new_fixture();
    assert_eq!(fixture.query.referenced_table_count(), 1);
    assert_eq!(
        fixture.query.parameter_names().collect::<Vec<_>>(),
        vec!["id"]
    );

    let dml = ParameterizedSelect::compile(
        &fixture.scope,
        "DELETE FROM `project-1.analytics.events` WHERE id = @id LIMIT 1",
        [
            QueryParameter::from_public_value("id", QueryParameterType::Int64, "7")
                .expect("parameter"),
        ],
        fixture.bounds,
    );
    assert!(matches!(dml, Err(QueryCompileError::NotSelect)));

    let multi = ParameterizedSelect::compile(
        &fixture.scope,
        "SELECT id FROM `project-1.analytics.events` WHERE id = @id LIMIT 1; SELECT id FROM `project-1.analytics.events` WHERE id = @id LIMIT 1",
        [
            QueryParameter::from_public_value("id", QueryParameterType::Int64, "7")
                .expect("parameter"),
        ],
        fixture.bounds,
    );
    assert!(matches!(multi, Err(QueryCompileError::MultiStatement)));

    let unbounded = ParameterizedSelect::compile(
        &fixture.scope,
        "SELECT id FROM `project-1.analytics.events` WHERE id = @id",
        [
            QueryParameter::from_public_value("id", QueryParameterType::Int64, "7")
                .expect("parameter"),
        ],
        fixture.bounds,
    );
    assert!(matches!(unbounded, Err(QueryCompileError::UnboundedRead)));

    let out_of_scope = ParameterizedSelect::compile(
        &fixture.scope,
        "SELECT id FROM `project-1.analytics.other` WHERE id = @id LIMIT 1",
        [
            QueryParameter::from_public_value("id", QueryParameterType::Int64, "7")
                .expect("parameter"),
        ],
        fixture.bounds,
    );
    assert!(matches!(
        out_of_scope,
        Err(QueryCompileError::TableOutOfScope)
    ));
}

#[test]
fn complete_recorded_result_projects_to_mission_without_authority() {
    let fixture = new_fixture();
    let initial = query_response(
        &fixture,
        fixture.job.clone(),
        true,
        vec![fixture.row.clone()],
        None,
        Vec::new(),
    );
    let mut service = service_with(&fixture, Ok(initial), [], ProviderProvenance::Recording);
    let proposal = service.propose(query_request(&fixture)).expect("proposal");
    assert_eq!(proposal.status(), ResultStatus::Complete);
    assert_eq!(proposal.evidence.rows.len(), 1);
    assert_eq!(
        proposal.evidence.digests.query_digest,
        *fixture.proposal.query_digest()
    );
    assert_eq!(
        proposal.evidence.digests.config_digest,
        *fixture.proposal.config_digest()
    );
    assert!(!proposal.authority().connected());
    assert!(!proposal.authority().native());
    assert!(!proposal.authority().truth());
    assert!(!proposal.is_adopted());
    assert!(!format!("{proposal:?}").contains("SELECT"));
    assert!(!format!("{:?}", fixture.secret).contains("google-secret-ref"));

    let consumer =
        MissionBigQueryResultConsumer::new(fixture.scope.clone(), service.registration())
            .expect("consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert_eq!(result.mission_id, *fixture.scope.mission_id());
    assert_eq!(result.work_product_id, *fixture.scope.work_product_id());
    assert_eq!(result.state, MissionResultState::PendingDecision);
    assert!(!result.authority.truth());
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
}

#[test]
fn location_query_and_fence_drift_fail_closed() {
    let fixture = new_fixture();
    let wrong_location = Location::new("EU").expect("location");
    let wrong_job = JobMetadata::new(
        JobReference::new(
            fixture.scope.project_id().clone(),
            wrong_location,
            JobId::new("job-1").expect("job"),
        ),
        JobState::Done,
        fixture.proposal.query_digest().clone(),
        fixture.proposal.config_digest().clone(),
        fixture.scope.scope_digest(),
        fixture.scope.permission_digest().clone(),
        fixture.secret.credential_revision(),
        false,
    );
    let mut service = service_with(
        &fixture,
        Ok(query_response(
            &fixture,
            wrong_job,
            true,
            vec![fixture.row.clone()],
            None,
            Vec::new(),
        )),
        [],
        ProviderProvenance::Fake,
    );
    assert_eq!(
        service
            .propose(query_request(&fixture))
            .expect_err("location drift"),
        BigQueryServiceError::LocationMismatch
    );

    let drifted_job = JobMetadata::new(
        fixture.job.reference.clone(),
        JobState::Done,
        digest("different-query"),
        fixture.proposal.config_digest().clone(),
        fixture.scope.scope_digest(),
        fixture.scope.permission_digest().clone(),
        fixture.secret.credential_revision(),
        false,
    );
    let mut service = service_with(
        &fixture,
        Ok(query_response(
            &fixture,
            drifted_job,
            true,
            vec![fixture.row.clone()],
            None,
            Vec::new(),
        )),
        [],
        ProviderProvenance::Fake,
    );
    assert_eq!(
        service
            .propose(query_request(&fixture))
            .expect_err("query drift"),
        BigQueryServiceError::QueryDrift
    );
}

#[test]
fn page_loops_are_rejected_and_bounded_retries_are_recorded() {
    let fixture = new_fixture();
    let token = OpaquePageToken::new("page-1").expect("token");
    let initial = query_response(
        &fixture,
        fixture.job.clone(),
        false,
        Vec::new(),
        Some(token.clone()),
        Vec::new(),
    );
    let loop_page = result_page(
        &fixture,
        fixture.job.clone(),
        false,
        Vec::new(),
        Some(token),
        Vec::new(),
    );
    let mut service = service_with(
        &fixture,
        Ok(initial),
        [Ok(loop_page)],
        ProviderProvenance::Loopback,
    );
    assert_eq!(
        service
            .propose(query_request(&fixture))
            .expect_err("page loop"),
        BigQueryServiceError::PageLoop
    );

    let fixture = new_fixture();
    let initial = query_response(
        &fixture,
        fixture.job.clone(),
        true,
        vec![fixture.row.clone()],
        None,
        Vec::new(),
    );
    let mut transport = RecordingBigQueryTransport::default();
    transport.push_query_response(Err(TransportError::quota()));
    transport.push_query_response(Ok(initial));
    let provider =
        BigQueryJobsProvider::new(transport, "1.0.0", ProviderProvenance::Fake).expect("provider");
    let mut service = BigQueryResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
        RetryPolicy::new(2).expect("retry policy"),
    )
    .expect("service");
    let proposal = service
        .propose(query_request(&fixture))
        .expect("retry result");
    assert_eq!(proposal.status(), ResultStatus::Complete);
    assert_eq!(proposal.evidence.retries.len(), 1);
    assert_eq!(service.provider().transport().query_calls(), 2);
}

#[test]
fn exhausted_server_errors_are_provider_unknown_and_blocked_env_is_honest() {
    let fixture = new_fixture();
    let mut transport = RecordingBigQueryTransport::default();
    transport.push_query_response(Err(TransportError::server_failure()));
    transport.push_query_response(Err(TransportError::server_failure()));
    transport.push_query_response(Err(TransportError::server_failure()));
    let provider =
        BigQueryJobsProvider::new(transport, "1.0.0", ProviderProvenance::Fake).expect("provider");
    let mut service = BigQueryResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
        RetryPolicy::default(),
    )
    .expect("service");
    let proposal = service
        .propose(query_request(&fixture))
        .expect("unknown projection");
    assert_eq!(proposal.status(), ResultStatus::ProviderUnknown);
    assert_eq!(proposal.evidence.retries.len(), 2);
    assert_eq!(proposal.evidence.provider_errors.len(), 1);

    let blocked_scope = new_fixture();
    let blocked_provider =
        BigQueryJobsProvider::new(BlockedEnvTransport, "1.0.0", ProviderProvenance::BlockedEnv)
            .expect("blocked provider");
    let mut blocked_service = BigQueryResultService::new(
        blocked_scope.scope.clone(),
        blocked_scope.secret.clone(),
        blocked_provider,
        RetryPolicy::default(),
    )
    .expect("blocked service");
    let proposal = blocked_service
        .propose(query_request(&blocked_scope))
        .expect("blocked projection");
    assert_eq!(proposal.status(), ResultStatus::ProviderUnknown);
    assert!(proposal.evidence.provider_errors[0].blocked_env);
    assert!(!proposal.evidence.authority.native());
    assert_eq!(
        blocked_service.provider().provenance(),
        ProviderProvenance::BlockedEnv
    );
}

#[test]
fn tamper_truncation_access_loss_and_final_error_are_typed() {
    let fixture = new_fixture();
    let mut tampered_row = fixture.row.clone();
    tampered_row.row_digest = digest("tampered-row");
    let mut service = service_with(
        &fixture,
        Ok(query_response(
            &fixture,
            fixture.job.clone(),
            true,
            vec![tampered_row],
            None,
            Vec::new(),
        )),
        [],
        ProviderProvenance::Recording,
    );
    assert_eq!(
        service
            .propose(query_request(&fixture))
            .expect_err("row tamper"),
        BigQueryServiceError::TamperedEvidence
    );

    let truncation = fixture_with_bounds(ResultBounds::new(1, 1_024, 4, 10).expect("bounds"));
    let second_row = BoundedRow::new(vec![
        RedactedCell::from_public_value(CellType::Integer, "8").expect("cell"),
    ])
    .expect("row");
    let mut service = service_with(
        &truncation,
        Ok(query_response(
            &truncation,
            truncation.job.clone(),
            true,
            vec![truncation.row.clone(), second_row],
            None,
            Vec::new(),
        )),
        [],
        ProviderProvenance::Recording,
    );
    let proposal = service
        .propose(query_request(&truncation))
        .expect("truncation");
    assert_eq!(proposal.status(), ResultStatus::Partial);
    assert_eq!(
        proposal.projection,
        ResultProjection::Partial(PartialReason::RowCap)
    );
    assert_eq!(proposal.evidence.rows.len(), 1);
    assert!(proposal.evidence.row_bound_exceeded);

    let access = new_fixture();
    let mut service = service_with(
        &access,
        Err(TransportError::access_denied()),
        [],
        ProviderProvenance::Fake,
    );
    let proposal = service
        .propose(query_request(&access))
        .expect("access projection");
    assert_eq!(proposal.status(), ResultStatus::AccessLost);

    let warning = QueryErrorEvidence::new(
        ProviderErrorKind::RateLimited,
        ErrorSeverity::Warning,
        Some(429),
        "warning",
    );
    let final_error = QueryErrorEvidence::new(
        ProviderErrorKind::BadRequest,
        ErrorSeverity::Final,
        Some(400),
        "bad-query",
    );
    let warning_fixture = new_fixture();
    let mut service = service_with(
        &warning_fixture,
        Ok(query_response(
            &warning_fixture,
            warning_fixture.job.clone(),
            true,
            vec![warning_fixture.row.clone()],
            None,
            vec![warning],
        )),
        [],
        ProviderProvenance::Recording,
    );
    let proposal = service
        .propose(query_request(&warning_fixture))
        .expect("warning projection");
    assert_eq!(
        proposal.projection,
        ResultProjection::Partial(PartialReason::Warning)
    );

    let final_fixture = new_fixture();
    let mut service = service_with(
        &final_fixture,
        Ok(query_response(
            &final_fixture,
            final_fixture.job.clone(),
            true,
            Vec::new(),
            None,
            vec![final_error],
        )),
        [],
        ProviderProvenance::Recording,
    );
    let proposal = service
        .propose(query_request(&final_fixture))
        .expect("final projection");
    assert_eq!(proposal.status(), ResultStatus::FinalError);
}

#[test]
fn stale_jobs_missing_tokens_byte_caps_and_http_families_are_typed() {
    let stale = new_fixture();
    let stale_job = JobMetadata::new(
        stale.job.reference.clone(),
        JobState::Expired,
        stale.proposal.query_digest().clone(),
        stale.proposal.config_digest().clone(),
        stale.scope.scope_digest(),
        stale.scope.permission_digest().clone(),
        stale.secret.credential_revision(),
        true,
    );
    let mut service = service_with(
        &stale,
        Ok(query_response(
            &stale,
            stale_job,
            true,
            Vec::new(),
            None,
            Vec::new(),
        )),
        [],
        ProviderProvenance::Recording,
    );
    let proposal = service
        .propose(query_request(&stale))
        .expect("stale projection");
    assert_eq!(proposal.status(), ResultStatus::Expired);

    let missing = new_fixture();
    let mut service = service_with(
        &missing,
        Ok(query_response(
            &missing,
            missing.job.clone(),
            false,
            Vec::new(),
            None,
            Vec::new(),
        )),
        [],
        ProviderProvenance::Recording,
    );
    let proposal = service
        .propose(query_request(&missing))
        .expect("missing token");
    assert_eq!(
        proposal.projection,
        ResultProjection::Partial(PartialReason::MissingPageToken)
    );

    let byte_bound = fixture_with_bounds(ResultBounds::new(10, 10, 4, 10).expect("bounds"));
    let mut service = service_with(
        &byte_bound,
        Ok(query_response(
            &byte_bound,
            byte_bound.job.clone(),
            true,
            vec![byte_bound.row.clone()],
            None,
            Vec::new(),
        )),
        [],
        ProviderProvenance::Recording,
    );
    let proposal = service
        .propose(query_request(&byte_bound))
        .expect("byte cap");
    assert_eq!(
        proposal.projection,
        ResultProjection::Partial(PartialReason::ByteCap)
    );
    assert!(proposal.evidence.byte_bound_exceeded);

    let http_cases = [
        (
            TransportError::new(ProviderErrorKind::BadRequest, Some(400), "bad request"),
            ResultStatus::FinalError,
        ),
        (
            TransportError::new(
                ProviderErrorKind::Unauthenticated,
                Some(401),
                "unauthenticated",
            ),
            ResultStatus::AccessLost,
        ),
        (TransportError::access_denied(), ResultStatus::AccessLost),
        (TransportError::not_found(), ResultStatus::Expired),
        (
            TransportError::new(ProviderErrorKind::Conflict, Some(409), "conflict"),
            ResultStatus::FinalError,
        ),
        (
            TransportError::rate_limited(),
            ResultStatus::ProviderUnknown,
        ),
        (TransportError::timeout(), ResultStatus::ProviderUnknown),
    ];
    for (error, expected_status) in http_cases {
        let fixture = new_fixture();
        let mut service = service_with(&fixture, Err(error), [], ProviderProvenance::Fake);
        let proposal = service
            .propose(query_request(&fixture))
            .expect("typed error");
        assert_eq!(proposal.status(), expected_status);
    }

    let schema_tamper = new_fixture();
    let mut tampered_schema = schema_tamper.schema.clone();
    tampered_schema.schema_digest = digest("tampered-schema");
    let response = JobsQueryResponse::new(
        schema_tamper.job.clone(),
        true,
        Some(tampered_schema),
        vec![schema_tamper.row.clone()],
        None,
        Some(1),
        42,
        Some(false),
        Vec::new(),
        schema_tamper.scope.fence(),
        schema_tamper.secret.credential_revision(),
    );
    let mut service = service_with(
        &schema_tamper,
        Ok(response),
        [],
        ProviderProvenance::Recording,
    );
    assert_eq!(
        service
            .propose(query_request(&schema_tamper))
            .expect_err("schema tamper"),
        BigQueryServiceError::TamperedEvidence
    );
}

#[test]
fn registration_and_secret_revocation_close_the_slice() {
    let fixture = new_fixture();
    let initial = query_response(
        &fixture,
        fixture.job.clone(),
        true,
        vec![fixture.row.clone()],
        None,
        Vec::new(),
    );
    let mut service = service_with(&fixture, Ok(initial), [], ProviderProvenance::Recording);
    service.revoke_registration().expect("revoke registration");
    assert_eq!(
        service
            .propose(query_request(&fixture))
            .expect_err("revoked registration"),
        BigQueryServiceError::RegistrationRevoked
    );

    let fixture = new_fixture();
    let initial = query_response(
        &fixture,
        fixture.job.clone(),
        true,
        vec![fixture.row.clone()],
        None,
        Vec::new(),
    );
    let mut service = service_with(&fixture, Ok(initial), [], ProviderProvenance::Recording);
    service.revoke_secret().expect("revoke secret");
    assert_eq!(
        service
            .propose(query_request(&fixture))
            .expect_err("revoked secret"),
        BigQueryServiceError::SecretRevoked
    );

    let oauth = SecretReference::new("oauth-reference", &fixture.scope, 1, GoogleAuthKind::OAuth)
        .expect("OAuth reference");
    let service_account = SecretReference::new(
        "service-account-reference",
        &fixture.scope,
        1,
        GoogleAuthKind::ServiceAccount,
    )
    .expect("service account reference");
    assert_eq!(oauth.auth_kind(), GoogleAuthKind::OAuth);
    assert_eq!(service_account.auth_kind(), GoogleAuthKind::ServiceAccount);
    assert!(!format!("{oauth:?}").contains("oauth-reference"));
    assert!(!format!("{service_account:?}").contains("service-account-reference"));
}

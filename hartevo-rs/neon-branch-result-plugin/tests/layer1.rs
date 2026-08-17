use hartevo_neon_branch_result_plugin::{
    BranchPoint, BranchProposalRequest, BranchState, CapabilityProbeRequest, DatabaseName,
    DatabaseResultAdoptionRequest, EndpointId, EndpointState, EventualConsistencyState,
    EvidenceSource, InputViolation, MissionDatabaseResultConsumer, MissionDatabaseResultSource,
    NeonBranchResultError, NeonBranchResultRegistry, NeonBranchResultService, NeonProviderError,
    NeonProviderManifest, NeonProviderRegistration, NeonScope, OrganizationId, ParameterizedQuery,
    ProjectId, QueryBudget, QueryColumn, QueryParameter, QueryProposalRequest,
    QueryResultObservation, QueryRow, QuerySchema, QueryTransportProtocol, QueryValue,
    RecordingNeonBranchResultProvider, RetryPolicy, RoleName, RowSetCanonicalization,
    SecretReference, SourceResultId,
};

fn scope() -> NeonScope {
    NeonScope::new(
        OrganizationId::new("org-1").expect("organization"),
        ProjectId::new("project-1").expect("project"),
        hartevo_neon_branch_result_plugin::MissionId::new("mission-1").expect("mission"),
        hartevo_neon_branch_result_plugin::BranchId::new("br-parent").expect("parent branch"),
        hartevo_neon_branch_result_plugin::BranchId::new("br-child").expect("child branch"),
        EndpointId::new("ep-1").expect("endpoint"),
        DatabaseName::new("app_db").expect("database"),
        RoleName::new("app_role").expect("role"),
    )
    .expect("scope")
}

fn service() -> (
    NeonBranchResultService<RecordingNeonBranchResultProvider>,
    RecordingNeonBranchResultProvider,
) {
    let manifest = NeonProviderManifest::layer1(scope()).expect("manifest");
    let provider = RecordingNeonBranchResultProvider::new(manifest);
    let service = NeonBranchResultService::new(provider.clone()).expect("service");
    (service, provider)
}

fn query_request(scope: NeonScope) -> QueryProposalRequest {
    let query = ParameterizedQuery::new(
        "SELECT id FROM widgets WHERE id = $1 LIMIT 10",
        vec![QueryParameter::Integer(7)],
    )
    .expect("parameterized query");
    QueryProposalRequest::new(
        scope,
        BranchPoint::head(),
        query,
        QueryBudget::new(10, 1_024, 1_000, RetryPolicy::layer1()).expect("budget"),
        RowSetCanonicalization::Ordered,
        None,
    )
    .expect("query request")
}

fn observation(
    scope: NeonScope,
    point: BranchPoint,
    rows: Vec<QueryRow>,
) -> QueryResultObservation {
    let fence = scope.branch_fence(point).expect("branch fence");
    let schema = QuerySchema::new(vec![QueryColumn::new("id", "int8", false).expect("column")])
        .expect("schema");
    QueryResultObservation::new(
        scope,
        fence,
        schema,
        rows,
        2,
        QueryTransportProtocol::Http,
        EvidenceSource::Fixture,
    )
    .expect("observation")
}

#[test]
fn exact_scope_probe_branch_point_and_native_boundary_are_digest_bound() {
    let (service, provider) = service();
    let scope = scope();
    let probe = service
        .capability_probe(
            &CapabilityProbeRequest::new(
                scope.clone(),
                BranchPoint::timestamp("2026-08-14T00:00:00Z").expect("timestamp"),
            )
            .expect("probe request"),
        )
        .expect("probe");
    assert!(probe.proposal_capable);
    assert_eq!(probe.branch_state, BranchState::Ready);
    assert_eq!(probe.endpoint_state, EndpointState::Ready);
    assert_eq!(
        probe.native_status,
        hartevo_neon_branch_result_plugin::NativeStatus::BlockedEnv
    );
    assert!(!probe.native_status.is_connected());
    assert_eq!(probe.scope, scope);
    assert_eq!(probe.branch_fence.branch_digest, scope.digest());
    assert!(!format!("{probe:?}").contains("connection"));

    let branch_receipt = service
        .propose_branch(
            BranchProposalRequest::new(
                scope.clone(),
                BranchPoint::lsn("0/16B6C50").expect("LSN"),
                Some(String::from("human-label-not-identity")),
            )
            .expect("branch request"),
        )
        .expect("branch proposal receipt");
    assert_eq!(branch_receipt.scope, scope);
    assert_eq!(
        branch_receipt.operation,
        hartevo_neon_branch_result_plugin::NeonOperation::BranchProposal
    );
    assert_eq!(provider.calls().len(), 2);
}

#[test]
fn query_allowlist_requires_parameter_binding_and_explicit_bounded_limit() {
    let valid = ParameterizedQuery::new(
        "SELECT id FROM widgets WHERE id = $1 LIMIT 10",
        vec![QueryParameter::Integer(1)],
    )
    .expect("valid select");
    assert_eq!(valid.limit_upper_bound().expect("limit"), 10);

    let explain = ParameterizedQuery::new(
        "EXPLAIN (FORMAT JSON) SELECT id FROM widgets WHERE id = $1 LIMIT 5",
        vec![QueryParameter::Integer(1)],
    )
    .expect("valid explain");
    assert_eq!(explain.limit_upper_bound().expect("explain limit"), 5);

    let refused = [
        (
            "UPDATE widgets SET id = $1 WHERE id = $2 LIMIT 1",
            vec![QueryParameter::Integer(1), QueryParameter::Integer(2)],
        ),
        (
            "SELECT id FROM widgets WHERE id = $1; SELECT id FROM widgets LIMIT 1",
            vec![QueryParameter::Integer(1)],
        ),
        (
            "SELECT id FROM widgets -- hidden statement\n WHERE id = $1 LIMIT 1",
            vec![QueryParameter::Integer(1)],
        ),
        (
            "SELECT id FROM widgets WHERE id = $1",
            vec![QueryParameter::Integer(1)],
        ),
        (
            "EXPLAIN ANALYZE SELECT id FROM widgets WHERE id = $1 LIMIT 1",
            vec![QueryParameter::Integer(1)],
        ),
        (
            "SELECT id FROM widgets WHERE id = 'unsafe' AND id = $1 LIMIT 1",
            vec![QueryParameter::Integer(1)],
        ),
    ];
    for (sql, parameters) in refused {
        assert!(
            ParameterizedQuery::new(sql, parameters).is_err(),
            "query must be refused"
        );
    }

    let too_large = QueryProposalRequest::new(
        scope(),
        BranchPoint::head(),
        valid,
        QueryBudget::new(5, 1_024, 1_000, RetryPolicy::layer1()).expect("budget"),
        RowSetCanonicalization::Ordered,
        None,
    )
    .expect_err("budget below SQL LIMIT must fail closed");
    assert!(matches!(
        too_large,
        NeonBranchResultError::InvalidInput {
            reason: InputViolation::UnboundedResult,
            ..
        }
    ));
}

#[test]
fn query_receipt_and_mission_adoption_bind_all_digests_without_raw_rows() {
    let (service, provider) = service();
    let scope = scope();
    let proposal = service
        .propose_query(query_request(scope.clone()))
        .expect("query proposal");
    let receipt = service
        .record_query_receipt(&proposal)
        .expect("query receipt");
    let replay = service
        .record_query_receipt(&proposal)
        .expect("identical fingerprint replay");
    assert_eq!(replay, receipt);
    assert_eq!(receipt.scope, scope);
    assert_eq!(receipt.branch_fence, proposal.branch_fence);
    assert_eq!(receipt.query_digest, proposal.query.query_digest);
    assert_eq!(receipt.parameter_digest, proposal.query.parameter_digest);
    assert!(receipt.independent);
    assert!(!receipt.truncated);
    assert_eq!(receipt.row_count, 1);
    assert!(
        !serde_json::to_string(&receipt)
            .expect("receipt JSON")
            .contains("fixture-row")
    );
    assert!(!format!("{:?}", provider.calls()).contains("fixture-row"));
    assert!(!format!("{provider:?}").contains("fixture-row"));

    provider.set_query_observation(observation(
        scope.clone(),
        BranchPoint::head(),
        vec![QueryRow(vec![QueryValue::Integer(99)])],
    ));
    assert!(matches!(
        service.record_query_receipt(&proposal),
        Err(NeonBranchResultError::Provider(
            NeonProviderError::DuplicateFingerprint
        ))
    ));

    let source = MissionDatabaseResultSource::new(
        scope.project_id.clone(),
        scope.mission_id.clone(),
        SourceResultId::new("result-1").expect("source result"),
        4,
    )
    .expect("source");
    let adoption = service
        .propose_database_result_adoption(
            DatabaseResultAdoptionRequest::new(source, proposal.clone(), receipt.clone())
                .expect("adoption request"),
        )
        .expect("adoption proposal");
    assert!(adoption.verified);
    assert!(!adoption.durable_adoption);
    assert_eq!(adoption.branch_fence, receipt.branch_fence);
    assert_eq!(adoption.row_set_digest, receipt.row_set_digest);
    assert_eq!(adoption.provider_version, receipt.provider_version);
    assert_eq!(adoption.registration_digest, *service.registration_digest());
    let adoption_receipt = service
        .record_adoption_proposal(&adoption)
        .expect("record adoption proposal");
    assert!(adoption_receipt.recorded);
    assert!(!adoption_receipt.durable_adoption);
}

#[test]
fn branch_and_query_receipt_tamper_or_scope_drift_fails_closed() {
    let (service, provider) = service();
    let proposal = service
        .propose_query(query_request(scope()))
        .expect("query proposal");
    let mut tampered = observation(
        scope(),
        BranchPoint::timestamp("2026-08-14T00:00:00Z").expect("timestamp"),
        vec![QueryRow(vec![QueryValue::Integer(1)])],
    );
    tampered.scope = NeonScope::new(
        OrganizationId::new("org-1").expect("organization"),
        ProjectId::new("project-other").expect("project"),
        hartevo_neon_branch_result_plugin::MissionId::new("mission-1").expect("mission"),
        hartevo_neon_branch_result_plugin::BranchId::new("br-parent").expect("parent"),
        hartevo_neon_branch_result_plugin::BranchId::new("br-child").expect("child"),
        EndpointId::new("ep-1").expect("endpoint"),
        DatabaseName::new("app_db").expect("database"),
        RoleName::new("app_role").expect("role"),
    )
    .expect("drifted scope");
    provider.set_query_observation(tampered);
    assert!(matches!(
        service.record_query_receipt(&proposal),
        Err(NeonBranchResultError::ReceiptMismatch { .. }
            | NeonBranchResultError::ScopeMismatch { .. },)
    ));

    provider.set_query_observation(observation(
        scope(),
        BranchPoint::head(),
        vec![QueryRow(vec![QueryValue::Integer(1)])],
    ));
    let receipt = service
        .record_query_receipt(&proposal)
        .expect("fresh receipt");
    let mut rewritten = receipt.clone();
    rewritten.row_set_digest = hartevo_neon_branch_result_plugin::sha256_digest(b"tampered");
    rewritten.receipt_digest = rewritten.calculate_digest();
    assert!(matches!(
        service.verify_query_receipt(&proposal, &rewritten),
        Err(NeonBranchResultError::Provider(
            NeonProviderError::ReceiptMismatch
        ))
    ));
}

#[test]
fn unordered_row_canonicalization_is_explicit_and_ordered_reordering_is_detectable() {
    let rows_a = vec![
        QueryRow(vec![QueryValue::Integer(1)]),
        QueryRow(vec![QueryValue::Integer(2)]),
    ];
    let rows_b = vec![
        QueryRow(vec![QueryValue::Integer(2)]),
        QueryRow(vec![QueryValue::Integer(1)]),
    ];
    let first = observation(scope(), BranchPoint::head(), rows_a);
    let second = observation(scope(), BranchPoint::head(), rows_b);
    assert_eq!(
        first
            .row_set_digest(RowSetCanonicalization::Unordered)
            .expect("unordered digest"),
        second
            .row_set_digest(RowSetCanonicalization::Unordered)
            .expect("unordered digest")
    );
    assert_ne!(
        first
            .row_set_digest(RowSetCanonicalization::Ordered)
            .expect("ordered digest"),
        second
            .row_set_digest(RowSetCanonicalization::Ordered)
            .expect("ordered digest")
    );
}

#[test]
fn eventual_consistency_scale_to_zero_and_rate_limit_states_remain_non_native() {
    let (service, provider) = service();
    let mut observation = service
        .capability_probe(
            &CapabilityProbeRequest::new(scope(), BranchPoint::head()).expect("request"),
        )
        .expect("probe");
    assert!(observation.proposal_capable);

    provider.set_control_plane_observation(
        hartevo_neon_branch_result_plugin::ControlPlaneObservation {
            scope: scope(),
            point_in_time: BranchPoint::head(),
            branch_state: BranchState::Activating,
            endpoint_state: EndpointState::ScaleToZero,
            eventual_consistency: EventualConsistencyState::Pending,
            observed_branch_digest: scope().digest(),
            observed_endpoint_digest: hartevo_neon_branch_result_plugin::canonical_digest(
                &scope().endpoint_id,
            ),
            evidence_source: EvidenceSource::Fixture,
            native_status: hartevo_neon_branch_result_plugin::NativeStatus::BlockedEnv,
        },
    );
    observation = service
        .capability_probe(
            &CapabilityProbeRequest::new(scope(), BranchPoint::head()).expect("request"),
        )
        .expect("unstable probe still records");
    assert!(!observation.proposal_capable);
    assert_eq!(observation.endpoint_state, EndpointState::ScaleToZero);
    assert!(!observation.native_status.is_native());

    provider.set_query_fault(NeonProviderError::RateLimited {
        retry_after_ms: 250,
    });
    let proposal = service
        .propose_query(query_request(scope()))
        .expect("query proposal");
    assert!(matches!(
        service.record_query_receipt(&proposal),
        Err(NeonBranchResultError::Provider(
            NeonProviderError::RateLimited {
                retry_after_ms: 250
            }
        ))
    ));
    provider.set_query_fault(NeonProviderError::PermissionLost);
    assert!(matches!(
        service.record_query_receipt(&proposal),
        Err(NeonBranchResultError::Provider(
            NeonProviderError::PermissionLost
        ))
    ));
}

#[test]
fn registration_is_opaque_scope_bound_version_bound_and_reversible() {
    let scope = scope();
    let manifest = NeonProviderManifest::layer1(scope.clone()).expect("manifest");
    let secret = SecretReference::for_scope("secret-ref-neon-key", &scope, 3).expect("secret");
    assert!(!format!("{secret:?}").contains("secret-ref-neon-key"));
    let registration =
        NeonProviderRegistration::new(manifest, scope.clone(), secret).expect("registration");
    let registration_digest = registration.registration_digest.clone();
    let mut registry = NeonBranchResultRegistry::default();
    let active = registry.register(registration).expect("register");
    assert!(active.active);
    assert!(registry.contains(&registration_digest));
    assert_eq!(active.scope_digest, scope.digest());
    let removed = registry.unregister(&active).expect("unregister");
    assert!(!removed.active);
    assert!(!registry.contains(&registration_digest));
}

#[test]
fn explicit_registration_can_be_used_by_mission_consumer_without_durable_adoption() {
    let scope = scope();
    let manifest = NeonProviderManifest::layer1(scope.clone()).expect("manifest");
    let secret = SecretReference::for_scope("secret-ref-neon-key", &scope, 1).expect("secret");
    let registration = NeonProviderRegistration::new(manifest.clone(), scope.clone(), secret)
        .expect("registration");
    let mut registry = NeonBranchResultRegistry::default();
    let registration_receipt = registry.register(registration).expect("register");
    let provider = RecordingNeonBranchResultProvider::new(manifest);
    let service = NeonBranchResultService::new(provider).expect("service");
    let consumer = MissionDatabaseResultConsumer::with_registration(service, registration_receipt)
        .expect("consumer");
    let proposal = consumer
        .propose_query(query_request(scope.clone()))
        .expect("query proposal");
    let receipt = consumer.record_query_receipt(&proposal).expect("receipt");
    let source = MissionDatabaseResultSource::new(
        scope.project_id,
        scope.mission_id,
        SourceResultId::new("source-1").expect("source"),
        1,
    )
    .expect("source");
    let adoption = consumer
        .propose_adoption(
            DatabaseResultAdoptionRequest::new(source, proposal, receipt).expect("request"),
        )
        .expect("adoption");
    assert!(adoption.verified);
    assert!(!adoption.durable_adoption);
}

#[test]
fn retry_policy_is_bounded_and_deterministic() {
    let policy = RetryPolicy::new(3, 100, 500);
    assert_eq!(policy.delay_for_retry(0), 100);
    assert_eq!(policy.delay_for_retry(1), 200);
    assert_eq!(policy.delay_for_retry(2), 400);
    assert_eq!(policy.delay_for_retry(3), 500);
    assert!(policy.validate().is_ok());
}

use super::*;

type TestProvider = RecordingGcpCloudLoggingTransport;

fn scope() -> GcpCloudLoggingScope {
    let resource = ProviderResourceScope::new(
        OrganizationId::new("org-1").expect("organization"),
        FolderId::new("folder-1").expect("folder"),
        ProjectId::new("project-1").expect("provider project"),
        Location::new("global").expect("location"),
        BucketId::new("bucket-1").expect("bucket"),
        ViewId::new("view-1").expect("view"),
        [LogId::new("syslog").expect("log")],
        [ResourceType::new("gce_instance").expect("resource type")],
    )
    .expect("resource scope");
    GcpCloudLoggingScope::new(
        resource,
        FilterTemplate::new(
            ResourceType::new("gce_instance").expect("resource type"),
            LogId::new("syslog").expect("log"),
            Some(LogSeverity::Warning),
        )
        .expect("filter template"),
        TimeWindow::new(100, 200).expect("time window"),
        Project::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(2).expect("project revision"),
        ),
        Mission::new(
            MissionId::new("mission-1").expect("mission"),
            Revision::new(3).expect("mission revision"),
        ),
        WorkProduct::new(
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(4).expect("work product revision"),
        ),
        PermissionFence::least_privilege(),
    )
    .expect("scope")
}

fn secret(scope: &GcpCloudLoggingScope) -> SecretReference {
    SecretReference::new("gcp-keyring-reference", scope, 9, GoogleAuthKind::OAuth)
        .expect("opaque secret")
}

fn entry(timestamp: i64, label: &str) -> LogEntryAggregate {
    LogEntryAggregate::from_metadata(
        timestamp,
        LogSeverity::Error,
        ResourceType::new("gce_instance").expect("resource type"),
        LogId::new("syslog").expect("log"),
        label.as_bytes(),
    )
    .expect("aggregate")
}

fn page(
    scope: &GcpCloudLoggingScope,
    request: &EntriesListRequest,
    entries: Vec<LogEntryAggregate>,
    token: Option<&str>,
) -> LogEntriesPage {
    LogEntriesPage::new(
        scope,
        request,
        entries,
        token.map(|value| OpaquePageToken::new(value).expect("opaque token")),
    )
    .expect("page")
}

fn service_with(
    scope: &GcpCloudLoggingScope,
    responses: impl IntoIterator<Item = Result<LogEntriesPage, TransportError>>,
    provenance: ProviderProvenance,
    retry_policy: RetryPolicy,
) -> GcpCloudLoggingResultService<TestProvider> {
    let mut transport = RecordingGcpCloudLoggingTransport::default();
    for response in responses {
        transport.push_response(response);
    }
    let provider =
        GcpCloudLoggingProvider::new(transport, "gcp-cloud-logging-api-v2-r1", provenance)
            .expect("provider");
    GcpCloudLoggingResultService::new(scope.clone(), secret(scope), provider, retry_policy)
        .expect("service")
}

#[test]
fn filter_scope_and_time_window_fail_closed() {
    let scope = scope();
    assert!(matches!(
        FilterTemplate::try_from_raw("resource.type=\"gce_instance\""),
        Err(ModelError::ArbitraryFilterRejected)
    ));
    assert!(matches!(
        TimeWindow::new(200, 100),
        Err(ModelError::InvalidTimeWindow)
    ));
    assert!(matches!(
        TimeWindow::new(0, MAX_TIME_WINDOW_SECONDS + 1),
        Err(ModelError::InvalidTimeWindow)
    ));
    let wrong_template = FilterTemplate::new(
        ResourceType::new("k8s_container").expect("resource type"),
        LogId::new("syslog").expect("log"),
        None,
    )
    .expect("typed template");
    assert!(matches!(
        FilterAst::compile(&scope, wrong_template, scope.time_window.clone()),
        Err(ModelError::InvalidFilter)
    ));
    assert!(matches!(
        ProviderResourceScope::new(
            OrganizationId::new("org-1").expect("organization"),
            FolderId::new("folder-1").expect("folder"),
            ProjectId::new("project-1").expect("project"),
            Location::new("global").expect("location"),
            BucketId::new("bucket-1").expect("bucket"),
            ViewId::new("view-1").expect("view"),
            std::iter::empty(),
            [ResourceType::new("gce_instance").expect("resource type")],
        ),
        Err(ModelError::InvalidScope)
    ));
}

#[test]
fn opaque_references_and_all_transport_provenance_are_honest() {
    let scope = scope();
    let secret = secret(&scope);
    assert!(secret.is_opaque());
    assert!(!format!("{secret:?}").contains("gcp-keyring-reference"));
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        let definition =
            GcpCloudLoggingProviderDefinition::layer1(provenance).expect("Layer-1 definition");
        assert!(!definition.connected);
        assert!(!definition.native);
        assert!(!definition.first_party);
        definition.validate().expect("definition remains honest");
    }
    let authority = EvidenceAuthority;
    assert!(!authority.connected());
    assert!(!authority.native());
    assert!(!authority.first_party());
    assert!(!authority.truth());
    assert!(!authority.consent());
    assert!(!authority.effect());
    assert!(!authority.receipt());
    assert!(!authority.verification());
    assert!(!authority.outcome());
}

#[test]
fn present_result_is_bounded_and_consumable_without_authority() {
    let scope = scope();
    let request = EntriesListRequest::first(&scope).expect("request");
    let mut service = service_with(
        &scope,
        [Ok(page(
            &scope,
            &request,
            vec![entry(150, "private log payload is hashed")],
            None,
        ))],
        ProviderProvenance::Recording,
        RetryPolicy::new(0).expect("retry policy"),
    );
    let proposal = service.propose().expect("proposal");
    assert_eq!(proposal.projection, GcpCloudLoggingProjection::Present);
    assert_eq!(proposal.evidence.entries.len(), 1);
    assert_eq!(proposal.evidence.pages.len(), 1);
    assert_eq!(proposal.evidence.entries[0].timestamp_seconds, 150);
    assert!(!format!("{proposal:?}").contains("private log payload"));
    assert!(!proposal.authority.native());
    assert!(!proposal.authority.connected());
    assert!(!proposal.authority.first_party());
    assert!(!proposal.authority.truth());
    assert!(!proposal.authority.consent());
    assert!(!proposal.authority.effect());
    assert!(!proposal.authority.receipt());
    assert!(!proposal.authority.verification());
    assert!(!proposal.authority.outcome());

    let consumer = MissionGcpCloudLoggingConsumer::new(scope.clone(), service.registration())
        .expect("Mission consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert_eq!(result.project_id, scope.project.id);
    assert_eq!(result.mission_id, scope.mission.id);
    assert_eq!(result.work_product_id, scope.work_product.id);
    assert_eq!(result.state, MissionResultState::PendingDecision);
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
    assert!(!result.authority.truth());
}

#[test]
fn empty_and_blocked_env_are_typed_without_native_claims() {
    let scope = scope();
    let request = EntriesListRequest::first(&scope).expect("request");
    let mut empty = service_with(
        &scope,
        [Ok(page(&scope, &request, Vec::new(), None))],
        ProviderProvenance::Fixture,
        RetryPolicy::new(0).expect("retry policy"),
    );
    assert_eq!(
        empty.propose().expect("empty proposal").projection,
        GcpCloudLoggingProjection::Empty
    );

    let mut blocked = GcpCloudLoggingResultService::new(
        scope.clone(),
        secret(&scope),
        GcpCloudLoggingProvider::new(
            BlockedEnvGcpCloudLoggingTransport,
            "gcp-cloud-logging-api-v2-r1",
            ProviderProvenance::BlockedEnv,
        )
        .expect("blocked provider"),
        RetryPolicy::new(0).expect("retry policy"),
    )
    .expect("blocked service");
    let proposal = blocked.propose().expect("blocked proposal");
    assert_eq!(
        proposal.projection,
        GcpCloudLoggingProjection::ProviderUnknown
    );
    assert!(
        proposal
            .evidence
            .provider_error
            .expect("blocked error")
            .blocked_env
    );
    assert!(!proposal.authority.native());
    assert!(!proposal.authority.connected());
    assert!(!proposal.authority.first_party());
}

#[test]
fn opaque_pagination_is_scope_bound_and_replay_loops_fail_closed() {
    let scope = scope();
    let first_request = EntriesListRequest::first(&scope).expect("first request");
    let first_page = page(
        &scope,
        &first_request,
        vec![entry(150, "first")],
        Some("page-1"),
    );
    let second_request = EntriesListRequest::next(
        &scope,
        &first_request,
        &first_page.next_page_token.clone().expect("next token"),
    )
    .expect("second request");
    let second_page = page(&scope, &second_request, vec![entry(151, "second")], None);
    let mut service = service_with(
        &scope,
        [Ok(first_page), Ok(second_page)],
        ProviderProvenance::Loopback,
        RetryPolicy::new(0).expect("retry policy"),
    );
    let proposal = service.propose().expect("paginated proposal");
    assert_eq!(proposal.projection, GcpCloudLoggingProjection::Present);
    assert_eq!(proposal.evidence.pages.len(), 2);
    assert_eq!(proposal.evidence.entries.len(), 2);
    assert_eq!(service.provider().transport().call_count(), 2);
    assert!(!format!("{:?}", proposal.evidence.pages[0]).contains("page-1"));

    let loop_first_request = EntriesListRequest::first(&scope).expect("first request");
    let loop_first = page(&scope, &loop_first_request, Vec::new(), Some("loop"));
    let loop_second_request = EntriesListRequest::next(
        &scope,
        &loop_first_request,
        &loop_first.next_page_token.clone().expect("loop token"),
    )
    .expect("loop request");
    let loop_second = page(&scope, &loop_second_request, Vec::new(), Some("loop"));
    let mut loop_service = service_with(
        &scope,
        [Ok(loop_first), Ok(loop_second)],
        ProviderProvenance::Recording,
        RetryPolicy::new(0).expect("retry policy"),
    );
    assert_eq!(
        loop_service
            .propose()
            .expect("tampered proposal")
            .projection,
        GcpCloudLoggingProjection::Tampered
    );
}

#[test]
fn result_bound_is_partial_and_retains_only_bounded_aggregates() {
    let scope = scope();
    let mut request = EntriesListRequest::first(&scope).expect("first request");
    let mut responses = Vec::new();
    for page_index in 0..5 {
        let entries = (0..1_000)
            .map(|entry_index| entry(100 + i64::from((page_index + entry_index) % 99), "bounded"))
            .collect::<Vec<_>>();
        let token = (page_index < 4).then(|| format!("page-{page_index}"));
        let current = page(&scope, &request, entries, token.as_deref());
        let next_request = current
            .next_page_token
            .clone()
            .map(|next| EntriesListRequest::next(&scope, &request, &next).expect("next request"));
        responses.push(Ok(current));
        if let Some(next_request) = next_request {
            request = next_request;
        }
    }
    let mut service = service_with(
        &scope,
        responses,
        ProviderProvenance::Fixture,
        RetryPolicy::new(0).expect("retry policy"),
    );
    let proposal = service.propose().expect("partial proposal");
    assert_eq!(proposal.projection, GcpCloudLoggingProjection::Partial);
    assert_eq!(proposal.evidence.entries.len(), MAX_RESULT_ENTRIES);
    assert_eq!(
        proposal.evidence.metadata_sample_digests.len(),
        MAX_METADATA_SAMPLES
    );
    assert_eq!(
        proposal.evidence.partial_reason,
        Some(PartialReason::EntryBound)
    );
    assert!(proposal.evidence.truncated);
}

#[test]
fn provider_error_matrix_is_typed_and_retries_are_bounded() {
    for (status, expected) in [
        (401, GcpCloudLoggingProjection::AccessLost),
        (403, GcpCloudLoggingProjection::AccessLost),
        (404, GcpCloudLoggingProjection::AccessLost),
        (409, GcpCloudLoggingProjection::ProviderUnknown),
        (500, GcpCloudLoggingProjection::ProviderUnknown),
        (429, GcpCloudLoggingProjection::ProviderUnknown),
    ] {
        let scope = scope();
        let mut service = service_with(
            &scope,
            [Err(TransportError::from_status(
                status,
                format!("status-{status}"),
            ))],
            ProviderProvenance::Recording,
            RetryPolicy::new(0).expect("retry policy"),
        );
        assert_eq!(
            service.propose().expect("error proposal").projection,
            expected
        );
    }

    let scope = scope();
    let mut timeout = service_with(
        &scope,
        [Err(TransportError::timeout("deadline"))],
        ProviderProvenance::Recording,
        RetryPolicy::new(0).expect("retry policy"),
    );
    assert_eq!(
        timeout.propose().expect("timeout proposal").projection,
        GcpCloudLoggingProjection::Timeout
    );

    let request = EntriesListRequest::first(&scope).expect("request");
    let first = page(
        &scope,
        &request,
        vec![entry(150, "before rate limit")],
        Some("next"),
    );
    let second_request = EntriesListRequest::next(
        &scope,
        &request,
        &first.next_page_token.clone().expect("next token"),
    )
    .expect("second request");
    let mut partial = service_with(
        &scope,
        [
            Ok(first),
            Err(TransportError::from_status(429, "rate limited")),
            Err(TransportError::from_status(429, "rate limited")),
        ],
        ProviderProvenance::Recording,
        RetryPolicy::new(1).expect("retry policy"),
    );
    assert_eq!(
        partial.propose().expect("partial rate proposal").projection,
        GcpCloudLoggingProjection::Partial
    );
    assert_eq!(partial.provider().transport().call_count(), 3);
    assert_eq!(
        partial
            .propose()
            .expect("second scripted proposal")
            .projection,
        GcpCloudLoggingProjection::ProviderUnknown
    );
    let _ = second_request;
}

#[test]
fn tamper_stale_mission_and_registration_lifecycle_are_fail_closed() {
    let scope = scope();
    let request = EntriesListRequest::first(&scope).expect("request");
    let mut service = service_with(
        &scope,
        [Ok(page(&scope, &request, vec![entry(150, "tamper")], None))],
        ProviderProvenance::Recording,
        RetryPolicy::new(0).expect("retry policy"),
    );
    let mut proposal = service.propose().expect("proposal");
    proposal.evidence.entries[0].metadata_digest = Digest::from_text("tampered");
    assert_eq!(
        proposal.validate_digest(),
        Err(GcpCloudLoggingResultServiceError::TamperedEvidence)
    );
    let consumer = MissionGcpCloudLoggingConsumer::new(scope.clone(), service.registration())
        .expect("consumer");
    assert_eq!(
        consumer.consume(proposal).expect_err("tampered proposal"),
        ConsumerError::InvalidProposal
    );

    let registration = service.registration().clone();
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(reversed.new_state, RegistrationState::Reversed);
    assert!(!service.registration().is_active());
    assert_eq!(
        service.propose().expect("revoked projection").projection,
        GcpCloudLoggingProjection::Revoked
    );
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.propose().expect("revoked projection").projection,
        GcpCloudLoggingProjection::Revoked
    );
    assert_eq!(
        service.revoke_registration().expect_err("double revoke"),
        ModelError::AlreadyRevoked
    );
    assert!(MissionGcpCloudLoggingConsumer::new(scope, &registration).is_ok());
}

#[test]
fn scope_and_page_token_digests_are_deterministic() {
    let first = scope();
    let second = scope();
    assert_eq!(first.digest(), second.digest());
    assert_eq!(
        first.filter_ast().expect("filter").digest(),
        second.filter_ast().expect("filter").digest()
    );
    let token = OpaquePageToken::new("provider-page-token").expect("token");
    let request = EntriesListRequest::first(&first).expect("request");
    let bound = token.bind(request.page_binding_digest());
    assert_eq!(
        bound.token_digest(),
        OpaquePageToken::new("provider-page-token")
            .expect("token")
            .token_digest()
    );
    assert_eq!(bound.binding_digest(), Some(request.page_binding_digest()));
    assert!(!format!("{bound:?}").contains("provider-page-token"));
}

use hartevo_gcp_iam_analysis_result_plugin::*;

const PROVIDER_REVISION: &str = GCP_IAM_ANALYSIS_PROVIDER_REVISION;

fn digest(seed: &str) -> Digest {
    Digest::from_text(seed)
}

fn scope() -> GcpIamScope {
    let resource =
        ResourceName::new("//cloudresourcemanager.googleapis.com/projects/cloud-project-1")
            .expect("resource");
    let query = IamAnalysisQuery::from_opaque_principal(
        PrincipalClass::User,
        "alice@example.com",
        resource.clone(),
        [PermissionName::new("storage.objects.get").expect("permission")],
    )
    .expect("query");
    let hierarchy = GcpHierarchyScope::new(
        "1234567890",
        [FolderId::new("folder-1").expect("folder")],
        [GcpProjectId::new("cloud-project-1").expect("cloud project")],
        digest("hierarchy-r1"),
    )
    .expect("hierarchy");
    GcpIamScope::new(
        hierarchy,
        resource,
        PolicyBindingFingerprint::new("binding-1", "roles/storage.objectViewer").expect("binding"),
        query,
        MissionScope::new("mission-1", 7).expect("Mission"),
        ProjectScope::new("project-1", 3).expect("Project"),
        WorkProductScope::new("work-product-1", 2).expect("Work Product"),
        digest("consent-r1"),
        digest("policy-r1"),
    )
    .expect("scope")
}

fn secret(scope: &GcpIamScope) -> SecretReference {
    SecretReference::oauth("oauth-token-material-should-not-appear", scope, 4)
        .expect("secret reference")
}

fn search_page(scope: &GcpIamScope, partial: bool, access_loss: bool) -> SearchAllIamPoliciesPage {
    let principal = PrincipalEvidence::new(
        scope.query.principal_class,
        scope.query.principal_digest.clone(),
    )
    .expect("principal");
    let binding = PolicyBindingEvidence::new(
        scope.policy_binding.binding_fingerprint.clone(),
        scope.policy_binding.role_fingerprint.clone(),
        scope.policy_revision.clone(),
        scope.resource_name.digest(),
        None,
        true,
    )
    .expect("binding evidence");
    let item = IamPolicyMatch::new(
        scope.resource_ancestry(),
        principal,
        binding,
        AccessClassification::Allowed,
        [AnalysisExplanationCode::DirectBinding],
    )
    .expect("policy match");
    SearchAllIamPoliciesPage::new(
        scope.scope_digest(),
        scope.query_digest.clone(),
        scope.hierarchy_revision().clone(),
        scope.policy_revision.clone(),
        vec![item],
        None,
        partial,
        access_loss,
    )
    .expect("search page")
}

fn analysis_page(scope: &GcpIamScope, partial: bool, access_loss: bool) -> AccessAnalysisPage {
    let principal = PrincipalEvidence::new(
        scope.query.principal_class,
        scope.query.principal_digest.clone(),
    )
    .expect("principal");
    let resource_node =
        AnalysisNode::new(AnalysisNodeKind::Resource, scope.resource_name.digest(), 0)
            .expect("resource node");
    AccessAnalysisPage::new(
        scope.scope_digest(),
        scope.query_digest.clone(),
        scope.hierarchy_revision().clone(),
        scope.policy_revision.clone(),
        principal,
        scope.resource_name.digest(),
        scope.permission_digest.clone(),
        if access_loss {
            AccessClassification::AccessLost
        } else if partial {
            AccessClassification::Partial
        } else {
            AccessClassification::Allowed
        },
        if access_loss {
            vec![AnalysisExplanationCode::AccessLost]
        } else if partial {
            vec![AnalysisExplanationCode::GraphTruncated]
        } else {
            vec![AnalysisExplanationCode::DirectBinding]
        },
        vec![resource_node],
        Vec::new(),
        None,
        partial,
        access_loss,
    )
    .expect("analysis page")
}

fn response(
    request: &GcpCloudAssetRequest,
    payload: GcpCloudAssetPayload,
) -> GcpCloudAssetResponse {
    GcpCloudAssetResponse::for_request(request, 200, 512, PROVIDER_REVISION, payload)
        .expect("response")
}

#[test]
fn fixture_read_record_verify_and_mission_consume_are_bounded() {
    let scope = scope();
    let service = GcpIamAnalysisService::new();
    let mut provider = service
        .register(
            scope.clone(),
            secret(&scope),
            FixtureGcpCloudAssetTransport::default(),
        )
        .expect("provider");
    let request = GcpIamReadRequest::new(&scope).expect("request");
    let proposal = service.propose(&mut provider, &request).expect("proposal");
    assert_eq!(proposal.evidence.provenance, ProviderProvenance::Fixture);
    assert_eq!(proposal.evidence.operations.len(), 2);
    assert_eq!(proposal.evidence.search_pages.len(), 1);
    assert_eq!(proposal.evidence.analysis_pages.len(), 1);
    assert!(!proposal.evidence.native_evidence);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.raw_policy_retained);
    assert!(!proposal.evidence.raw_principal_retained);
    assert!(!provider.is_connected());
    assert!(!provider.native());

    let record = service.record(proposal).expect("record");
    service.verify(&record, &scope).expect("verification");
    let consumer = MissionGcpIamConsumer::new(scope.clone())
        .with_registration_digest(record.evidence.registration_digest.clone());
    let result = consumer.consume(&record).expect("Mission result");
    assert_eq!(result.observation.mission_id.as_str(), "mission-1");
    assert_eq!(result.observation.project_id.as_str(), "project-1");
    assert_eq!(
        result.observation.work_product_id.as_str(),
        "work-product-1"
    );
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
    assert!(!result.observation.native_authority);
    assert!(!result.observation.truth_authority);
    assert!(!result.observation.effective_authorization);
    result.validate(&scope).expect("result validation");
}

#[test]
fn opaque_secret_principal_policy_and_cursor_material_is_never_retained() {
    let scope = scope();
    let secret = secret(&scope);
    let secret_debug = format!("{secret:?}");
    let query_debug = format!("{:?}", scope.query);
    assert!(!secret_debug.contains("oauth-token-material"));
    assert!(!query_debug.contains("alice@example.com"));
    assert!(!format!("{scope:?}").contains("roles/storage.objectViewer"));

    let cursor = PageTokenDigest::from_opaque("raw-page-token-that-must-not-be-retained");
    assert!(!format!("{cursor:?}").contains("raw-page-token"));
    let request = GcpCloudAssetRequest::new(
        &scope,
        GcpCloudAssetOperation::SearchAllIamPolicies,
        10,
        1,
        Some(cursor),
    )
    .expect("request");
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains("raw-page-token"));
    assert!(!request_debug.contains("alice@example.com"));

    let service_account =
        SecretReference::service_account("service-account-key-material", &scope, 5)
            .expect("service account reference");
    assert_eq!(service_account.kind(), SecretReferenceKind::ServiceAccount);
    assert!(!format!("{service_account:?}").contains("service-account-key-material"));
}

#[test]
fn multi_page_search_and_analysis_bind_cursor_hierarchy_policy_and_query() {
    let scope = scope();
    let read_request = GcpIamReadRequest::new(&scope).expect("read request");
    let search_request_1 = GcpCloudAssetRequest::new(
        &scope,
        GcpCloudAssetOperation::SearchAllIamPolicies,
        read_request.page_size,
        1,
        None,
    )
    .expect("search request 1");
    let cursor = PageTokenDigest::from_opaque("search-cursor-1");
    let search_request_2 = GcpCloudAssetRequest::new(
        &scope,
        GcpCloudAssetOperation::SearchAllIamPolicies,
        read_request.page_size,
        2,
        Some(cursor.clone()),
    )
    .expect("search request 2");
    let analysis_request = GcpCloudAssetRequest::new(
        &scope,
        GcpCloudAssetOperation::AnalyzeIamPolicy,
        read_request.page_size,
        1,
        None,
    )
    .expect("analysis request");
    let first_search = SearchAllIamPoliciesPage::new(
        scope.scope_digest(),
        scope.query_digest.clone(),
        scope.hierarchy_revision().clone(),
        scope.policy_revision.clone(),
        search_page(&scope, false, false).matches,
        Some(cursor),
        false,
        false,
    )
    .expect("first search page");
    let second_search = search_page(&scope, false, false);
    let mut transport = RecordingGcpCloudAssetTransport::default();
    transport.push_response(response(
        &search_request_1,
        GcpCloudAssetPayload::SearchAllIamPolicies(first_search),
    ));
    transport.push_response(response(
        &search_request_2,
        GcpCloudAssetPayload::SearchAllIamPolicies(second_search),
    ));
    transport.push_response(response(
        &analysis_request,
        GcpCloudAssetPayload::AnalyzeIamPolicy(analysis_page(&scope, false, false)),
    ));
    let service = GcpIamAnalysisService::new();
    let mut provider = service
        .register(scope.clone(), secret(&scope), transport)
        .expect("provider");
    let evidence = provider.read(&read_request).expect("multi-page evidence");
    assert_eq!(evidence.search_pages.len(), 2);
    assert_eq!(evidence.analysis_pages.len(), 1);
    assert_eq!(provider.transport().requests().len(), 3);
    assert_eq!(provider.transport().requests()[1].page_number, 2);
    assert_eq!(
        provider.transport().requests()[1]
            .page_token
            .as_ref()
            .expect("cursor")
            .digest,
        PageTokenDigest::from_opaque("search-cursor-1").digest
    );
}

#[test]
fn partial_and_access_loss_are_explicit_non_native_evidence() {
    let scope = scope();
    let request = GcpIamReadRequest::new(&scope).expect("request");
    let search_request = GcpCloudAssetRequest::new(
        &scope,
        GcpCloudAssetOperation::SearchAllIamPolicies,
        request.page_size,
        1,
        None,
    )
    .expect("search request");
    let analysis_request = GcpCloudAssetRequest::new(
        &scope,
        GcpCloudAssetOperation::AnalyzeIamPolicy,
        request.page_size,
        1,
        None,
    )
    .expect("analysis request");
    let mut transport = FixtureGcpCloudAssetTransport::default();
    transport.push_response(response(
        &search_request,
        GcpCloudAssetPayload::SearchAllIamPolicies(search_page(&scope, true, true)),
    ));
    transport.push_response(response(
        &analysis_request,
        GcpCloudAssetPayload::AnalyzeIamPolicy(analysis_page(&scope, true, true)),
    ));
    let service = GcpIamAnalysisService::new();
    let mut provider = service
        .register(scope.clone(), secret(&scope), transport)
        .expect("provider");
    let evidence = provider.read(&request).expect("partial evidence");
    assert!(evidence.partial);
    assert!(evidence.access_loss);
    assert!(!evidence.native_evidence);
    let record = service
        .record(GcpIamAnalysisProposal {
            proposal_digest: Digest::from_text("placeholder"),
            evidence: evidence.clone(),
        })
        .expect_err("a forged proposal must fail");
    assert_eq!(record, GcpIamAnalysisError::EvidenceDigestMismatch);
}

#[test]
fn response_tamper_policy_mismatch_cursor_replay_and_revocation_fail_closed() {
    let scope = scope();
    let request = GcpIamReadRequest::new(&scope)
        .expect("request")
        .search_only();
    let asset_request = GcpCloudAssetRequest::new(
        &scope,
        GcpCloudAssetOperation::SearchAllIamPolicies,
        request.page_size,
        1,
        None,
    )
    .expect("request");
    let mut tampered = response(
        &asset_request,
        GcpCloudAssetPayload::SearchAllIamPolicies(search_page(&scope, false, false)),
    );
    tampered.response_digest = Digest::zero();
    let mut transport = RecordingGcpCloudAssetTransport::default();
    transport.push_response(tampered);
    let service = GcpIamAnalysisService::new();
    let mut provider = service
        .register(scope.clone(), secret(&scope), transport)
        .expect("provider");
    assert!(matches!(
        provider.read(&request),
        Err(GcpCloudAssetProviderError::ResponseTampered)
    ));

    let cursor = PageTokenDigest::from_opaque("replayed-cursor");
    let first = SearchAllIamPoliciesPage::new(
        scope.scope_digest(),
        scope.query_digest.clone(),
        scope.hierarchy_revision().clone(),
        scope.policy_revision.clone(),
        Vec::new(),
        Some(cursor.clone()),
        false,
        false,
    )
    .expect("first page");
    let second = SearchAllIamPoliciesPage::new(
        scope.scope_digest(),
        scope.query_digest.clone(),
        scope.hierarchy_revision().clone(),
        scope.policy_revision.clone(),
        Vec::new(),
        Some(cursor),
        false,
        false,
    )
    .expect("replayed page");
    let request_2 = GcpCloudAssetRequest::new(
        &scope,
        GcpCloudAssetOperation::SearchAllIamPolicies,
        request.page_size,
        2,
        Some(PageTokenDigest::from_opaque("replayed-cursor")),
    )
    .expect("request 2");
    let mut replay_transport = RecordingGcpCloudAssetTransport::default();
    replay_transport.push_response(response(
        &asset_request,
        GcpCloudAssetPayload::SearchAllIamPolicies(first),
    ));
    replay_transport.push_response(response(
        &request_2,
        GcpCloudAssetPayload::SearchAllIamPolicies(second),
    ));
    let mut replay_provider = service
        .register(scope.clone(), secret(&scope), replay_transport)
        .expect("replay provider");
    assert!(matches!(
        replay_provider.read(&request),
        Err(GcpCloudAssetProviderError::CursorReplay)
    ));

    service
        .revoke_registration(&mut replay_provider, 42)
        .expect("revoke");
    assert!(matches!(
        service.propose(&mut replay_provider, &request),
        Err(GcpIamAnalysisError::Provider(
            GcpCloudAssetProviderError::RegistrationRevoked
        ))
    ));
}

#[test]
fn blocked_environment_and_http_statuses_are_not_native() {
    let scope = scope();
    let request = GcpIamReadRequest::new(&scope)
        .expect("request")
        .search_only();
    let service = GcpIamAnalysisService::new();
    let mut blocked = service
        .register(
            scope.clone(),
            secret(&scope),
            BlockedEnvGcpCloudAssetTransport,
        )
        .expect("blocked provider");
    assert_eq!(blocked.provenance(), ProviderProvenance::BlockedEnv);
    assert!(!blocked.is_connected());
    assert!(matches!(
        blocked.read(&request),
        Err(GcpCloudAssetProviderError::Transport(
            GcpTransportError::BlockedEnv
        ))
    ));

    for status in [400, 401, 403, 404, 409, 429, 500, 503] {
        let asset_request = GcpCloudAssetRequest::new(
            &scope,
            GcpCloudAssetOperation::SearchAllIamPolicies,
            request.page_size,
            1,
            None,
        )
        .expect("status request");
        let payload = GcpCloudAssetPayload::SearchAllIamPolicies(
            SearchAllIamPoliciesPage::new(
                scope.scope_digest(),
                scope.query_digest.clone(),
                scope.hierarchy_revision().clone(),
                scope.policy_revision.clone(),
                Vec::new(),
                None,
                false,
                false,
            )
            .expect("status page"),
        );
        let response = GcpCloudAssetResponse::for_request(
            &asset_request,
            status,
            512,
            PROVIDER_REVISION,
            payload,
        )
        .expect("status response");
        let mut transport = RecordingGcpCloudAssetTransport::default();
        transport.push_response(response);
        let mut provider = service
            .register(scope.clone(), secret(&scope), transport)
            .expect("status provider");
        assert!(matches!(
            provider.read(&request),
            Err(GcpCloudAssetProviderError::UnexpectedStatus {
                status: observed,
                ..
            }) if observed == status
        ));
    }
}

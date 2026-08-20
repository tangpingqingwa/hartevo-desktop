use std::collections::BTreeMap;

use hartevo_aws_service_catalog_provisioned_result_plugin::{
    AccessLevelScope, AwsServiceCatalogError, AwsServiceCatalogOperation,
    AwsServiceCatalogProvider, AwsServiceCatalogProvisionedResultService, AwsServiceCatalogScope,
    AwsServiceCatalogTransportError, BlockedEnvTransport, DescribeProvisionedProductResponse,
    DescribeRecordResponse, EvidenceState, ListRecordHistoryRequest, ListRecordHistoryResponse,
    MAX_HISTORY_PAGE_SIZE, MAX_SEARCH_PAGE_SIZE, MissionAwsServiceCatalogConsumer, MissionScope,
    PageToken, PortfolioScope, ProductScope, ProjectScope, ProvisionedProductProjection,
    ProvisionedProductScope, ProvisionedProductStatus, RecordProjection, RecordScope, RecordType,
    RecordingTransport, SearchProvisionedProductsRequest, SearchProvisionedProductsResponse,
    SearchQuery, SecretReference, TransportProvenance, WorkProductScope, validate_contract,
};

fn scope() -> AwsServiceCatalogScope {
    AwsServiceCatalogScope::new(
        "123456789012",
        "us-east-1",
        AccessLevelScope::account("123456789012").expect("account access"),
        PortfolioScope::new("portfolio-1", 7).expect("portfolio"),
        ProductScope::new("product-1", 11, "artifact-1", 13).expect("product"),
        ProvisionedProductScope::new("provisioned-product-1", 17).expect("provisioned product"),
        RecordScope::new("record-1", 19).expect("record"),
        ProjectScope::new("project-1", 23).expect("Project"),
        MissionScope::new("mission-1", 29).expect("Mission"),
        WorkProductScope::new("work-product-1", 31).expect("Work Product"),
    )
    .expect("scope")
}

fn projection(scope: &AwsServiceCatalogScope) -> ProvisionedProductProjection {
    let mut tags = BTreeMap::new();
    tags.insert(
        "owner".to_owned(),
        "sensitive-person@example.invalid".to_owned(),
    );
    let mut outputs = BTreeMap::new();
    outputs.insert("physical_id".to_owned(), "i-raw-physical-id".to_owned());
    ProvisionedProductProjection::from_provider_fields(
        scope,
        "product-1",
        "artifact-1",
        "provisioned-product-1",
        Some("record-1"),
        ProvisionedProductStatus::Available,
        "2026-08-15T00:00:00Z",
        "2026-08-15T01:00:00Z",
        Some(RecordType::Provision),
        None,
        11,
        13,
        17,
        19,
        tags,
        outputs,
    )
    .expect("projection")
}

fn record(scope: &AwsServiceCatalogScope) -> RecordProjection {
    let mut outputs = BTreeMap::new();
    outputs.insert("resource".to_owned(), "raw-resource-output".to_owned());
    RecordProjection::from_provider_fields(
        scope,
        "record-1",
        "provisioned-product-1",
        "product-1",
        "artifact-1",
        ProvisionedProductStatus::Available,
        "2026-08-15T00:30:00Z",
        "2026-08-15T01:00:00Z",
        RecordType::Provision,
        None,
        19,
        outputs,
    )
    .expect("record")
}

fn service_with_recording() -> (
    AwsServiceCatalogProvisionedResultService<RecordingTransport>,
    AwsServiceCatalogScope,
) {
    let scope = scope();
    let mut transport = RecordingTransport::new();
    let product = projection(&scope);
    let record = record(&scope);
    transport.push_search_response(SearchProvisionedProductsResponse::new(
        vec![product.clone()],
        None,
    ));
    transport.push_describe_provisioned_product_response(DescribeProvisionedProductResponse::new(
        product,
    ));
    transport.push_history_response(ListRecordHistoryResponse::new(vec![record.clone()], None));
    transport.push_describe_record_response(DescribeRecordResponse::new(record));
    let provider = AwsServiceCatalogProvider::new(transport, 1).expect("provider");
    let secret = SecretReference::sigv4(&scope, "opaque-handle-1").expect("secret reference");
    let service = AwsServiceCatalogProvisionedResultService::new(scope.clone(), secret, provider)
        .expect("service");
    (service, scope)
}

#[test]
fn contract_and_capability_are_explicitly_layer_one() {
    validate_contract().expect("contract validates");
    let (service, _) = service_with_recording();
    let capabilities = service.describe_capabilities();
    assert_eq!(
        capabilities.operations,
        vec![
            "SearchProvisionedProducts",
            "DescribeProvisionedProduct",
            "ListRecordHistory",
            "DescribeRecord",
        ]
    );
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.durable_provider_receipt);
    assert!(!capabilities.outcome_adoption);
    assert!(!capabilities.work_product_adoption);
}

#[test]
fn secret_scope_cursor_and_page_bounds_are_redacted_and_fenced() {
    let (service, scope) = service_with_recording();
    let secret_debug = format!("{:?}", service.registration().secret_reference());
    assert!(!secret_debug.contains("opaque-handle-1"));
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(!registration_json.contains("opaque-handle-1"));

    assert!(
        SearchProvisionedProductsRequest::new(
            &scope,
            SearchQuery::All,
            MAX_SEARCH_PAGE_SIZE + 1,
            None
        )
        .is_err()
    );
    assert!(ListRecordHistoryRequest::new(&scope, MAX_HISTORY_PAGE_SIZE + 1, None).is_err());
    assert!(SearchQuery::from_allowlisted("arbitrary", "injected").is_err());
    assert!(SearchQuery::from_allowlisted("status", "* OR status=AVAILABLE").is_err());
    assert!(SearchQuery::from_allowlisted("product", "product-1|status=AVAILABLE").is_err());

    let first = SearchProvisionedProductsRequest::new(&scope, SearchQuery::All, 10, None)
        .expect("first search request");
    let next = first.next_page_token();
    let second =
        SearchProvisionedProductsRequest::new(&scope, SearchQuery::All, 10, Some(next.clone()))
            .expect("bound next token");
    assert_eq!(second.page_number(), 2);
    assert!(next.to_string().starts_with("SC1.2."));
    let tampered = PageToken::parse(format!("SC1.2.{}", "0".repeat(64))).expect("token shape");
    assert!(
        SearchProvisionedProductsRequest::new(&scope, SearchQuery::All, 10, Some(tampered))
            .is_err()
    );
}

#[test]
fn proposal_is_deterministic_redacted_and_never_adoptable() {
    let (mut service, _) = service_with_recording();
    let request = service
        .default_request("idem-1", "2026-08-15T02:00:00Z")
        .expect("request");
    let proposal = service.propose(request.clone()).expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Available);
    assert_eq!(proposal.status, Some(ProvisionedProductStatus::Available));
    assert!(proposal.search_complete);
    assert!(proposal.history_complete);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.outcome_adopted);
    assert!(!proposal.work_product_adopted);
    let json = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!json.contains("raw-resource-output"));
    assert!(!json.contains("raw-physical-id"));
    assert!(!json.contains("sensitive-person@example.invalid"));
    assert!(json.contains("tagsDigest"));
    assert!(json.contains("outputsDigest"));
    assert_eq!(
        service
            .propose(request)
            .expect("idempotent replay")
            .digest(),
        proposal.digest()
    );

    let consumer: MissionAwsServiceCatalogConsumer = service.consumer().expect("consumer");
    let result = consumer.accept(&proposal).expect("review result");
    assert_eq!(
        result.disposition,
        hartevo_aws_service_catalog_provisioned_result_plugin::ProposalDisposition::ReviewOnly
    );
    assert!(!result.verified_work_product);
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    let recorded = service.record(&proposal).expect("recording result");
    assert!(recorded.review_only);
    assert!(!recorded.durable_provider_receipt);
}

#[test]
fn revision_stale_mission_replay_and_revocation_are_rejected() {
    let (mut service, _) = service_with_recording();
    let mut stale = service
        .default_request("idem-stale", "2026-08-15T02:00:00Z")
        .expect("request");
    stale.revision_fences.mission_revision += 1;
    assert_eq!(
        service.propose(stale),
        Err(AwsServiceCatalogError::StaleMission)
    );

    let request = service
        .default_request("idem-conflict", "2026-08-15T02:00:00Z")
        .expect("request");
    let _ = service.propose(request).expect("first proposal");
    let conflict = service
        .request(
            "idem-conflict",
            SearchQuery::Status(ProvisionedProductStatus::Tainted),
            10,
            10,
            1,
            1,
            "2026-08-15T02:00:00Z",
        )
        .expect("conflicting request");
    assert_eq!(
        service.propose(conflict),
        Err(AwsServiceCatalogError::IdempotencyConflict)
    );

    service.revoke().expect("revoke");
    let request = service
        .default_request("idem-revoked", "2026-08-15T02:00:00Z")
        .expect("request");
    assert_eq!(
        service.propose(request),
        Err(AwsServiceCatalogError::RegistrationInactive)
    );
}

#[test]
fn partial_access_loss_provider_unknown_and_cursor_loop_are_projected() {
    let scope = scope();
    let secret = SecretReference::sigv4(&scope, "opaque-handle-2").expect("secret");

    let mut access_transport = RecordingTransport::new();
    access_transport.push_search_error(AwsServiceCatalogTransportError::AccessLost);
    let access_provider = AwsServiceCatalogProvider::new(access_transport, 1).expect("provider");
    let mut access_service = AwsServiceCatalogProvisionedResultService::new(
        scope.clone(),
        secret.clone(),
        access_provider,
    )
    .expect("service");
    let access_proposal = access_service
        .propose(
            access_service
                .default_request("access-loss", "2026-08-15T02:00:00Z")
                .expect("request"),
        )
        .expect("access loss proposal");
    assert_eq!(access_proposal.state, EvidenceState::AccessLoss);
    assert_eq!(
        access_proposal
            .failure
            .as_ref()
            .map(|failure| failure.category.as_str()),
        Some("access_loss")
    );

    let mut unknown_transport = RecordingTransport::new();
    unknown_transport.push_search_error(AwsServiceCatalogTransportError::Timeout);
    let unknown_provider = AwsServiceCatalogProvider::new(unknown_transport, 1).expect("provider");
    let mut unknown_service = AwsServiceCatalogProvisionedResultService::new(
        scope.clone(),
        secret.clone(),
        unknown_provider,
    )
    .expect("service");
    let unknown_proposal = unknown_service
        .propose(
            unknown_service
                .default_request("provider-unknown", "2026-08-15T02:00:00Z")
                .expect("request"),
        )
        .expect("unknown proposal");
    assert_eq!(unknown_proposal.state, EvidenceState::ProviderUnknown);

    let mut loop_transport = RecordingTransport::new();
    let first_request = SearchProvisionedProductsRequest::new(&scope, SearchQuery::All, 10, None)
        .expect("first request");
    loop_transport.push_search_response(SearchProvisionedProductsResponse::new(
        vec![],
        Some(first_request.next_page_token()),
    ));
    loop_transport.push_search_response(SearchProvisionedProductsResponse::new(
        vec![],
        Some(first_request.next_page_token()),
    ));
    let loop_provider = AwsServiceCatalogProvider::new(loop_transport, 1).expect("provider");
    let mut loop_service =
        AwsServiceCatalogProvisionedResultService::new(scope, secret, loop_provider)
            .expect("service");
    let loop_request = loop_service
        .request(
            "cursor-loop",
            SearchQuery::All,
            10,
            10,
            2,
            1,
            "2026-08-15T02:00:00Z",
        )
        .expect("request");
    let loop_proposal = loop_service.propose(loop_request).expect("loop proposal");
    assert_eq!(loop_proposal.state, EvidenceState::CursorLoop);
    assert_eq!(
        loop_proposal
            .failure
            .as_ref()
            .map(|failure| failure.category.as_str()),
        Some("cursor_loop")
    );
}

#[test]
fn blocked_env_is_never_connected_or_native() {
    let scope = scope();
    let provider = AwsServiceCatalogProvider::new(BlockedEnvTransport, 1).expect("provider");
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
    assert!(!provider.provenance().connected());
    assert!(!provider.provenance().native());
    let secret = SecretReference::sigv4(&scope, "opaque-handle-3").expect("secret");
    let mut service =
        AwsServiceCatalogProvisionedResultService::new(scope, secret, provider).expect("service");
    let proposal = service
        .propose(
            service
                .default_request("blocked", "2026-08-15T02:00:00Z")
                .expect("request"),
        )
        .expect("blocked proposal");
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
    assert!(!proposal.connected);
    assert!(!proposal.native);
}

#[test]
fn provider_http_failure_classes_are_redacted_and_non_adoptable() {
    let scope = scope();
    let cases = [
        (
            AwsServiceCatalogTransportError::BadRequest,
            "bad_request",
            EvidenceState::ProviderUnknown,
            Some(400),
        ),
        (
            AwsServiceCatalogTransportError::Unauthorized,
            "unauthorized",
            EvidenceState::ProviderUnknown,
            Some(401),
        ),
        (
            AwsServiceCatalogTransportError::Forbidden,
            "forbidden",
            EvidenceState::ProviderUnknown,
            Some(403),
        ),
        (
            AwsServiceCatalogTransportError::NotFound,
            "not_found",
            EvidenceState::NotFound,
            Some(404),
        ),
        (
            AwsServiceCatalogTransportError::RateLimited,
            "throttled",
            EvidenceState::Throttled,
            Some(429),
        ),
        (
            AwsServiceCatalogTransportError::ServerError,
            "server_error",
            EvidenceState::ProviderUnknown,
            Some(500),
        ),
        (
            AwsServiceCatalogTransportError::Timeout,
            "timeout",
            EvidenceState::ProviderUnknown,
            None,
        ),
    ];
    for (error, category, state, status_code) in cases {
        let mut transport = RecordingTransport::new();
        transport.push_search_error(error);
        let provider = AwsServiceCatalogProvider::new(transport, 1).expect("provider");
        let secret =
            SecretReference::sigv4(&scope, format!("opaque-{category}")).expect("secret reference");
        let mut service =
            AwsServiceCatalogProvisionedResultService::new(scope.clone(), secret, provider)
                .expect("service");
        let proposal = service
            .propose(
                service
                    .default_request(format!("error-{category}"), "2026-08-15T02:00:00Z")
                    .expect("request"),
            )
            .expect("failure proposal");
        assert_eq!(proposal.state, state);
        let failure = proposal.failure.as_ref().expect("redacted failure");
        assert_eq!(failure.category, category);
        assert_eq!(failure.status_code, status_code);
        assert!(!failure.failure_digest.as_str().is_empty());
        assert!(proposal.is_review_only());
        assert!(!proposal.can_be_adopted());
    }
}

#[test]
fn operation_allowlist_has_no_write_effects() {
    assert_eq!(AwsServiceCatalogOperation::ALL.len(), 4);
    assert!(
        !AwsServiceCatalogOperation::ALL
            .iter()
            .any(|operation| operation.as_str().contains("ProvisionProduct"))
    );
    assert!(
        !AwsServiceCatalogOperation::ALL
            .iter()
            .any(|operation| operation.as_str().contains("Update"))
    );
    assert!(
        !AwsServiceCatalogOperation::ALL
            .iter()
            .any(|operation| operation.as_str().contains("Terminate"))
    );
    assert!(
        !AwsServiceCatalogOperation::ALL
            .iter()
            .any(|operation| operation.as_str().contains("Execute"))
    );
}

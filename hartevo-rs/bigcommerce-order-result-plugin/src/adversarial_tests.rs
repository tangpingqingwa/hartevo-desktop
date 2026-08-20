use super::*;

fn test_scope() -> (
    BigCommerceOrderScope,
    BigCommerceSecretReference,
    BigCommerceOrderSnapshot,
) {
    let store = StoreId::new("store-hash-01").expect("store");
    let order_id = OrderId::new(42).expect("order");
    let transaction = TransactionEvidence::new(
        "transaction-1",
        TransactionStatus::Captured,
        "usd",
        "10.00",
        "order-revision-1",
    )
    .expect("transaction");
    let fulfillment = FulfillmentEvidence::new(
        "fulfillment-1",
        FulfillmentStatus::Fulfilled,
        1,
        Some("tracking-1"),
        "fulfillment-revision-1",
    )
    .expect("fulfillment");
    let order = BigCommerceOrderSnapshot::new(
        store.clone(),
        order_id,
        "customer@example.invalid",
        OrderStatus::Completed,
        "order-revision-1",
        "USD",
        "10.00",
        vec![transaction],
        vec![fulfillment],
    )
    .expect("order");
    let mission = MissionScope::new(
        MissionId::new("mission-01").expect("mission id"),
        Revision::new(1).expect("mission revision"),
    );
    let project = ProjectScope::new(
        ProjectId::new("project-01").expect("project id"),
        Revision::new(1).expect("project revision"),
    );
    let work_product = WorkProductScope::new(
        WorkProductId::new("work-product-01").expect("work product id"),
        Revision::new(1).expect("work product revision"),
    );
    let scope = BigCommerceOrderScope::new(
        store,
        [order_id],
        [CustomerFingerprint::from_value("customer@example.invalid")],
        [OrderStatus::Completed],
        true,
        true,
        mission,
        project,
        work_product,
        Digest::from_text("permission-fence"),
        Digest::from_text("consent-fence"),
    )
    .expect("scope");
    let secret = BigCommerceSecretReference::new(
        "store-api-token-reference",
        &scope,
        Revision::new(3).expect("credential revision"),
        BigCommerceAuthKind::ApiToken,
    )
    .expect("secret reference");
    (scope, secret, order)
}

fn service_with_fixture()
-> BigCommerceOrderResultService<BigCommerceProvider<FixtureTransport>> {
    let (scope, secret, order) = test_scope();
    let list_request = ListOrdersRequest::new(&scope, &secret, 10, None).expect("list request");
    let list_response =
        ListOrdersResponse::new(vec![order.clone()], None, 512, list_request.fence());
    let get_request = GetOrderRequest::new(&scope, &secret, order.order_id).expect("get request");
    let get_response = GetOrderResponse::new(order.clone(), 768, get_request.fence());
    let mut transport = FixtureTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_get_response(order.order_id, Ok(get_response));
    let provider = BigCommerceProvider::new(transport, "1.0.0", ProviderProvenance::Fixture)
        .expect("provider");
    BigCommerceOrderResultService::new(
        scope,
        secret,
        provider,
        Revision::new(1).expect("registration revision"),
    )
    .expect("service")
}

#[test]
fn bounded_get_list_and_get_order_produce_redacted_complete_evidence() {
    let mut service = service_with_fixture();
    let proposal = service
        .propose(BigCommerceOrderEvidenceRequest::default())
        .expect("proposal");
    assert_eq!(proposal.status(), EvidenceState::Complete);
    assert_eq!(proposal.evidence.orders.len(), 1);
    assert_eq!(proposal.evidence.requests.len(), 2);
    assert_eq!(
        proposal.evidence.requests[0].operation,
        BigCommerceOrderOperation::ListOrders
    );
    assert_eq!(
        proposal.evidence.requests[1].operation,
        BigCommerceOrderOperation::GetOrder
    );
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.revision_digests().is_empty());
    assert!(!proposal.evidence.amount_digests().is_empty());
    proposal.validate_integrity().expect("proposal fence");

    let debug = format!("{:?}", proposal.evidence.orders[0]);
    assert!(!debug.contains("customer@example.invalid"));
    assert!(!debug.contains("10.00"));
    let secret_debug = format!("{:?}", service.secret_reference());
    assert!(!secret_debug.contains("store-api-token-reference"));
}

#[test]
fn mission_record_and_read_back_are_idempotent_and_review_only() {
    let mut service = service_with_fixture();
    let proposal = service
        .propose(BigCommerceOrderEvidenceRequest::default())
        .expect("proposal");
    let mut consumer = MissionBigCommerceOrderConsumer::new(
        service.scope().clone(),
        service.registration().clone(),
    )
    .expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("mission result");
    assert!(mission_result.review_only);
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    assert!(!mission_result.outcome_adopted);
    assert_eq!(mission_result.mission, *service.scope().mission());
    assert_eq!(mission_result.project, *service.scope().project());
    assert_eq!(mission_result.work_product, *service.scope().work_product());

    let first = consumer
        .record(&proposal, "mission-record-01")
        .expect("record");
    first.validate_integrity().expect("record fence");
    assert_eq!(consumer.record_count(), 1);
    let replay = consumer
        .record(&proposal, "mission-record-01")
        .expect("replay");
    assert!(replay.replayed);
    let read_back = consumer.read_back("mission-record-01").expect("read back");
    assert!(read_back.replayed);
    read_back.validate_integrity().expect("read-back fence");
}

#[test]
fn blocked_environment_never_claims_connected_or_native() {
    let (scope, secret, _) = test_scope();
    let provider = BigCommerceOrdersProvider::new(
        BlockedEnvTransport,
        "1.0.0",
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut service = BigCommerceOrderResultService::new(
        scope,
        secret,
        provider,
        Revision::new(1).expect("registration revision"),
    )
    .expect("service");
    let proposal = service
        .propose(BigCommerceOrderEvidenceRequest::default())
        .expect("blocked proposal");
    assert_eq!(proposal.status(), EvidenceState::ProviderUnknown);
    assert!(proposal.evidence.provider_errors[0].blocked_env);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert_eq!(
        proposal.evidence.provider_provenance,
        ProviderProvenance::BlockedEnv
    );
}

#[test]
fn tampered_order_revision_or_amount_fence_is_rejected() {
    let mut service = service_with_fixture();
    let mut proposal = service
        .propose(BigCommerceOrderEvidenceRequest::default())
        .expect("proposal");
    proposal.evidence.orders[0].status = OrderStatus::Cancelled;
    assert!(proposal.validate_integrity().is_err());
}

#[test]
fn registration_can_be_revoked_reversed_and_restored_without_native_authority() {
    let mut service = service_with_fixture();
    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(revoked.new_status, RegistrationStatus::Revoked);
    assert!(!service.registration().is_active());
    assert!(
        service
            .propose(BigCommerceOrderEvidenceRequest::default())
            .is_err()
    );
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(reversed.new_status, RegistrationStatus::Reversed);
    assert!(!service.registration().is_active());
    assert!(service.restore_registration().is_err());
}

#[test]
fn order_metadata_keeps_addresses_emails_and_items_digest_only() {
    let (scope, _, order) = test_scope();
    let metadata = OrderRedactionMetadata::from_values(
        3,
        ShipmentStatus::PartiallyShipped,
        PaymentState::Paid,
        Some("123 Private Street"),
        Some("456 Billing Street"),
        Some("customer@example.invalid"),
        Some("sku-1|sku-2|sku-3"),
    );
    let enriched = BigCommerceOrderSnapshot::from_redacted_with_metadata(
        order.store.clone(),
        order.order_id,
        order.customer_fingerprint.clone(),
        order.status,
        order.revision_digest.clone(),
        order.total_amount.clone(),
        order.transactions.clone(),
        order.fulfillments.clone(),
        metadata,
    )
    .expect("enriched order");
    assert_eq!(enriched.line_item_count, 3);
    assert_eq!(enriched.shipment_status, ShipmentStatus::PartiallyShipped);
    assert_eq!(enriched.payment_state, PaymentState::Paid);
    let serialized = serde_json::to_string(&enriched).expect("redacted order JSON");
    assert!(!serialized.contains("Private Street"));
    assert!(!serialized.contains("customer@example.invalid"));
    assert!(!serialized.contains("sku-1"));
    assert!(scope.allows(&enriched).is_ok());
}

#[test]
fn amount_currency_mismatch_is_rejected_before_evidence() {
    let store = StoreId::new("store-hash-01").expect("store");
    let transaction = TransactionEvidence::new(
        "transaction-1",
        TransactionStatus::Captured,
        "EUR",
        "10.00",
        "revision-1",
    )
    .expect("transaction");
    let result = BigCommerceOrderSnapshot::new(
        store,
        OrderId::new(42).expect("order"),
        "customer-1",
        OrderStatus::Completed,
        "revision-1",
        "USD",
        "10.00",
        vec![transaction],
        Vec::new(),
    );
    assert_eq!(result, Err(BigCommerceOrderResultError::InvalidAmount));
}

#[test]
fn date_and_status_filters_are_digest_bound_to_the_list_get_request() {
    let mut service = service_with_fixture();
    let filter = OrderListFilter::new(
        [OrderStatus::Completed],
        [CustomerFingerprint::from_value("customer@example.invalid")],
        Some(
            OrderDateFilter::from_strs(Some("2026-08-01T00:00:00Z"), Some("2026-08-31T23:59:59Z"))
                .expect("date filter"),
        ),
    );
    let proposal = service
        .propose(
            BigCommerceOrderEvidenceRequest::with_filter(10, 1, true, filter.clone())
                .expect("bounded filter"),
        )
        .expect("filtered proposal");
    proposal.validate_integrity().expect("filtered fence");
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].filter_digest, filter.digest());
}

#[test]
fn list_get_revision_drift_and_stale_mission_fail_closed() {
    let (scope, secret, order) = test_scope();
    let list_request = ListOrdersRequest::new(&scope, &secret, 10, None).expect("list request");
    let list_response =
        ListOrdersResponse::new(vec![order.clone()], None, 100, list_request.fence());
    let drifted = BigCommerceOrderSnapshot::new(
        order.store.clone(),
        order.order_id,
        "customer@example.invalid",
        OrderStatus::Completed,
        "order-revision-2",
        "USD",
        "10.00",
        order.transactions.clone(),
        order.fulfillments.clone(),
    )
    .expect("drifted order");
    let get_request = GetOrderRequest::new(&scope, &secret, order.order_id).expect("get request");
    let get_response = GetOrderResponse::new(drifted, 100, get_request.fence());
    let mut transport = FixtureTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_get_response(order.order_id, Ok(get_response));
    let provider = BigCommerceOrdersProvider::new(transport, "1.0.0", ProviderProvenance::Fixture)
        .expect("provider");
    let mut service = BigCommerceOrderResultService::new(
        scope.clone(),
        secret,
        provider,
        Revision::new(1).expect("registration revision"),
    )
    .expect("service");
    assert_eq!(
        service
            .propose(BigCommerceOrderEvidenceRequest::default())
            .expect_err("revision drift"),
        BigCommerceOrderResultError::OrderRevisionDrift
    );

    let stale_scope = BigCommerceOrderScope::new(
        scope.store().clone(),
        scope.order_ids().iter().copied(),
        scope.customer_fingerprints().iter().cloned(),
        scope.statuses().iter().copied(),
        scope.include_transactions(),
        scope.include_fulfillments(),
        MissionScope::new(
            scope.mission().id().clone(),
            Revision::new(2).expect("stale mission revision"),
        ),
        scope.project().clone(),
        scope.work_product().clone(),
        scope.permission_digest().clone(),
        scope.consent_digest().clone(),
    )
    .expect("stale scope");
    assert!(
        MissionBigCommerceOrderConsumer::new(stale_scope, service.registration().clone()).is_err()
    );
}

#[test]
fn provider_statuses_remain_bounded_and_non_native() {
    let cases = [
        (
            BigCommerceTransportError::Unauthorized,
            EvidenceState::AccessLost,
            ProviderFailureClass::Unauthorized,
        ),
        (
            BigCommerceTransportError::Forbidden,
            EvidenceState::AccessLost,
            ProviderFailureClass::Forbidden,
        ),
        (
            BigCommerceTransportError::NotFound,
            EvidenceState::NotFound,
            ProviderFailureClass::NotFound,
        ),
        (
            BigCommerceTransportError::Conflict,
            EvidenceState::Conflict,
            ProviderFailureClass::Conflict,
        ),
        (
            BigCommerceTransportError::RateLimited {
                retry_after_seconds: Some(2),
            },
            EvidenceState::RateLimited,
            ProviderFailureClass::RateLimited,
        ),
        (
            BigCommerceTransportError::ServerError { status: 503 },
            EvidenceState::ProviderUnknown,
            ProviderFailureClass::ServerError,
        ),
        (
            BigCommerceTransportError::Timeout,
            EvidenceState::ProviderUnknown,
            ProviderFailureClass::Timeout,
        ),
    ];
    for (error, state, class) in cases {
        let (scope, secret, _) = test_scope();
        let provider = BigCommerceOrdersProvider::new(
            FixtureTransportWithListError::new(error),
            "1.0.0",
            ProviderProvenance::Fixture,
        )
        .expect("provider");
        let mut service = BigCommerceOrderResultService::new(
            scope,
            secret,
            provider,
            Revision::new(1).expect("registration revision"),
        )
        .expect("service");
        let proposal = service
            .propose(BigCommerceOrderEvidenceRequest::default())
            .expect("failure proposal");
        assert_eq!(proposal.status(), state);
        assert_eq!(proposal.evidence.provider_errors[0].class, class);
        assert!(!proposal.evidence.connected);
        assert!(!proposal.evidence.native);
    }
}

#[derive(Debug)]
struct FixtureTransportWithListError(BigCommerceTransportError);

impl FixtureTransportWithListError {
    fn new(error: BigCommerceTransportError) -> Self {
        Self(error)
    }
}

impl BigCommerceTransport for FixtureTransportWithListError {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn list_orders(
        &mut self,
        _request: &ListOrdersRequest,
    ) -> std::result::Result<ListOrdersResponse, BigCommerceTransportError> {
        Err(self.0.clone())
    }

    fn get_order(
        &mut self,
        _request: &GetOrderRequest,
    ) -> std::result::Result<GetOrderResponse, BigCommerceTransportError> {
        Err(BigCommerceTransportError::InvalidResponse)
    }
}

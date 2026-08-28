use hartevo_shopify_order_result_plugin::{
    BlockedEnvReason, Digest, FulfillmentState, GraphqlResponse, MissionScope,
    MissionShopifyOrderConsumer, MissionShopifyOrderResultState, ModelError, PermissionLease,
    PolicyRevision, ProjectScope, ProjectionState, ProviderFailureClass, ProviderMode,
    ProviderProvenance, ResponseMetadata, Revision, SHOPIFY_ADMIN_API_VERSION,
    SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT, SecretReference, ShopDomain, ShopifyAdminProvider,
    ShopifyApiVersion, ShopifyId, ShopifyOrderResultContract, ShopifyOrderResultScope,
    ShopifyOrderResultScopeInput, ShopifyOrderResultService, ShopifyPermission,
    ShopifyProviderError, TransactionState, WorkProductScope,
};

const ORDER_ID: &str = "gid://shopify/Order/1001";
const NOW: u64 = 1_800_000_000;

fn scope(expires_at: Option<u64>) -> ShopifyOrderResultScope {
    ShopifyOrderResultScope::new(ShopifyOrderResultScopeInput {
        api_version: ShopifyApiVersion::pinned(),
        shop: ShopDomain::new("hartevo-test.myshopify.com").expect("shop"),
        order_id: ShopifyId::new(ORDER_ID).expect("order"),
        secret_reference: SecretReference::new("host/keychain/shopify-admin", 7)
            .expect("opaque secret"),
        permission_lease: PermissionLease::new(
            vec![
                ShopifyPermission::ReadOrders,
                ShopifyPermission::ReadMerchantManagedFulfillmentOrders,
            ],
            3,
            expires_at,
        )
        .expect("permission lease"),
        project: ProjectScope::new("project-1", 4).expect("project"),
        mission: MissionScope::new("mission-1", 9).expect("mission"),
        work_product: WorkProductScope::new("work-product-1", 12).expect("work product"),
        policy_revision: PolicyRevision::new("policy-7").expect("policy"),
    })
    .expect("scope")
}

fn service(mode: ProviderMode, expires_at: Option<u64>) -> ShopifyOrderResultService {
    ShopifyOrderResultService::new(
        scope(expires_at),
        ShopifyAdminProvider::new(mode).expect("provider"),
    )
    .expect("service")
}

fn order_body(has_next_page: bool) -> Vec<u8> {
    serde_json::json!({
        "data": {
            "order": {
                "id": ORDER_ID,
                "createdAt": "2026-08-14T08:00:00Z",
                "updatedAt": "2026-08-14T09:00:00Z",
                "currencyCode": "USD",
                "displayFinancialStatus": "PARTIALLY_REFUNDED",
                "displayFulfillmentStatus": "PARTIALLY_FULFILLED",
                "currentTotalPriceSet": {"shopMoney": {"amount": "80.00", "currencyCode": "USD"}},
                "totalRefundedSet": {"shopMoney": {"amount": "20.00", "currencyCode": "USD"}},
                "fulfillmentOrders": {
                    "nodes": [{
                        "id": "gid://shopify/FulfillmentOrder/1",
                        "status": "OPEN",
                        "requestStatus": "UNREQUESTED",
                        "createdAt": "2026-08-14T08:30:00Z",
                        "updatedAt": "2026-08-14T08:45:00Z"
                    }],
                    "pageInfo": {"hasNextPage": has_next_page, "endCursor": "opaque-cursor-1"}
                },
                "fulfillments": [{
                    "id": "gid://shopify/Fulfillment/1",
                    "status": "SUCCESS",
                    "createdAt": "2026-08-14T08:50:00Z",
                    "updatedAt": "2026-08-14T08:55:00Z"
                }],
                "refunds": [{
                    "id": "gid://shopify/Refund/1",
                    "createdAt": "2026-08-14T08:56:00Z",
                    "processedAt": "2026-08-14T08:57:00Z",
                    "updatedAt": "2026-08-14T08:58:00Z",
                    "totalRefundedSet": {"shopMoney": {"amount": "20.00", "currencyCode": "USD"}},
                    "transactions": {"nodes": [{"id": "gid://shopify/OrderTransaction/2", "status": "SUCCESS"}], "pageInfo": {"hasNextPage": false, "endCursor": null}}
                }],
                "transactions": [{
                    "id": "gid://shopify/OrderTransaction/1",
                    "kind": "SALE",
                    "status": "SUCCESS",
                    "amountSet": {"shopMoney": {"amount": "100.00", "currencyCode": "USD"}},
                    "createdAt": "2026-08-14T08:01:00Z",
                    "processedAt": "2026-08-14T08:02:00Z"
                }]
            }
        }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn contract_and_query_are_explicitly_layer_one_and_redacted() {
    let contract = ShopifyOrderResultContract::baseline().expect("contract");
    assert_eq!(contract.document()["apiVersion"], SHOPIFY_ADMIN_API_VERSION);
    assert!(!SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT.contains("mutation"));
    for forbidden in [
        "customer",
        "shippingAddress",
        "billingAddress",
        "lineItems",
        "paymentInstrument",
        "paymentDetails",
        "gateway",
    ] {
        assert!(
            !SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase())
        );
    }
}

#[test]
fn registration_binds_versions_provider_permissions_and_all_revisions() {
    let service = service(ProviderMode::Recording, None);
    let registration = service.registration();
    assert!(registration.contract_digest.is_sha256());
    assert!(registration.provider_digest.is_sha256());
    assert!(registration.provider_implementation_digest.is_sha256());
    assert!(registration.permission_digest.is_sha256());
    assert!(registration.scope_digest.is_sha256());
    assert!(registration.registration_digest.is_sha256());
    assert!(registration.verify(service.scope(), service.provider()));
    assert_eq!(registration.api_version, SHOPIFY_ADMIN_API_VERSION);
    assert_eq!(
        registration.project_revision,
        Revision::new(4).expect("revision")
    );
    assert_eq!(
        registration.mission_revision,
        Revision::new(9).expect("revision")
    );
    assert_eq!(
        registration.work_product_revision,
        Revision::new(12).expect("revision")
    );
    assert!(!format!("{:?}", service.scope().secret_reference()).contains("host/keychain"));
    assert!(
        !serde_json::to_string(registration)
            .expect("registration json")
            .contains("host/keychain")
    );
}

#[test]
fn recording_projects_financial_fulfillment_refund_transaction_and_revision_evidence() {
    let service = service(ProviderMode::Recording, None);
    let proposal = service.compile_read_proposal().expect("proposal");
    let body = order_body(false);
    let evidence = service
        .record_read_evidence(
            &proposal,
            GraphqlResponse::new(200, &body).with_metadata(
                ResponseMetadata::new(Some("shopify-request-1"), Some(98), None, 0)
                    .expect("metadata"),
            ),
        )
        .expect("evidence");

    assert_eq!(evidence.provenance, ProviderProvenance::Recording);
    assert_eq!(evidence.projection_state, ProjectionState::Complete);
    assert!(evidence.is_complete());
    assert!(evidence.verify_digest());
    let projection = evidence.projection.as_ref().expect("projection");
    assert_eq!(
        projection.financial_state,
        TransactionState::PartiallyRefunded
    );
    assert_eq!(
        projection.fulfillment_state,
        FulfillmentState::PartiallyFulfilled
    );
    assert_eq!(projection.refunds[0].state, TransactionState::Succeeded);
    assert_eq!(
        projection.transactions[0].state,
        TransactionState::Succeeded
    );
    assert_eq!(projection.order_revision_digest.as_str().len(), 64);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    assert!(!evidence.durable_native_receipt);
    assert!(!evidence.independent_read_back);
    assert!(!evidence.verified_work_product_adoption);
    let serialized = serde_json::to_string(&evidence).expect("evidence json");
    assert!(!serialized.contains("customer"));
    assert!(!serialized.contains("host/keychain"));
    assert!(!serialized.contains("opaque-cursor-1"));
}

#[test]
fn adoption_and_mission_consumption_are_evidence_only() {
    let service = service(ProviderMode::Fixture, None);
    let proposal = service.compile_read_proposal().expect("proposal");
    let body = order_body(false);
    let evidence = service
        .record_read_evidence(&proposal, GraphqlResponse::new(200, &body))
        .expect("evidence");
    let adoption = service
        .propose_adoption(&evidence)
        .expect("adoption proposal");
    assert!(adoption.verify_digest());
    assert!(adoption.is_evidence_only());
    assert!(!adoption.connected);
    assert!(!adoption.native);
    assert!(!adoption.first_party);
    assert!(!adoption.adopts_work_product);

    let consumer =
        MissionShopifyOrderConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let result = consumer.consume(adoption).expect("mission result");
    assert_eq!(result.state, MissionShopifyOrderResultState::EvidenceReady);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.adopts_work_product);
}

#[test]
fn pagination_is_bounded_and_cursor_is_digest_only() {
    let service = service(ProviderMode::Loopback, None);
    let proposal = service.compile_read_proposal().expect("proposal");
    let body = order_body(true);
    let evidence = service
        .record_read_evidence(&proposal, GraphqlResponse::new(200, &body))
        .expect("partial evidence");
    assert_eq!(evidence.projection_state, ProjectionState::Partial);
    assert!(evidence.page_info.has_next_page);
    assert!(evidence.page_info.end_cursor_digest.is_some());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence json")
            .contains("opaque-cursor-1")
    );
    let next = service
        .next_page_proposal(&proposal, &evidence.page_info)
        .expect("next page")
        .expect("more pages");
    assert_eq!(next.page_number(), 2);
    assert!(next.cursor_digest().expect("cursor digest").is_sha256());

    let final_page = service
        .compile_read_proposal_with_page(4, 25, next.cursor_digest().cloned())
        .expect("bounded final page");
    assert_eq!(
        service
            .next_page_proposal(&final_page, &evidence.page_info)
            .expect_err("page bound"),
        hartevo_shopify_order_result_plugin::ShopifyServiceError::PaginationBoundExceeded
    );
}

#[test]
fn adversarial_http_statuses_project_access_deletion_conflict_rate_limit_and_unknown() {
    let cases = [
        (
            401,
            ProviderFailureClass::Unauthorized,
            ProjectionState::AccessLost,
        ),
        (
            403,
            ProviderFailureClass::Forbidden,
            ProjectionState::AccessLost,
        ),
        (
            404,
            ProviderFailureClass::NotFound,
            ProjectionState::Deleted,
        ),
        (
            409,
            ProviderFailureClass::Conflict,
            ProjectionState::Conflict,
        ),
        (
            429,
            ProviderFailureClass::RateLimited,
            ProjectionState::RateLimited,
        ),
        (
            503,
            ProviderFailureClass::ServerFailure,
            ProjectionState::ProviderUnknown,
        ),
    ];
    for (status, class, state) in cases {
        let service = service(ProviderMode::Recording, None);
        let proposal = service.compile_read_proposal().expect("proposal");
        let response = if status == 429 {
            GraphqlResponse::new(status, b"rate limited").with_metadata(
                ResponseMetadata::new(Some("request-429"), Some(0), Some(1200), 1)
                    .expect("metadata"),
            )
        } else {
            GraphqlResponse::new(status, b"provider error")
        };
        let evidence = service
            .record_read_evidence(&proposal, response)
            .expect("failure evidence");
        assert_eq!(evidence.projection_state, state);
        assert_eq!(evidence.failure.as_ref().expect("failure").class, class);
        assert!(!evidence.connected);
        assert!(!evidence.native);
    }
}

#[test]
fn blocked_env_and_permission_expiry_never_become_native_evidence() {
    let blocked = service(ProviderMode::BlockedEnv, None);
    let proposal = blocked.compile_read_proposal().expect("proposal");
    let evidence = blocked
        .record_read_evidence(&proposal, GraphqlResponse::new(200, &order_body(false)))
        .expect("blocked evidence");
    assert_eq!(evidence.provenance, ProviderProvenance::BlockedEnv);
    assert_eq!(evidence.projection_state, ProjectionState::BlockedEnv);
    assert_eq!(
        evidence.failure.as_ref().expect("failure").class,
        ProviderFailureClass::BlockedEnv
    );
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);

    let expiring = service(ProviderMode::Recording, Some(NOW));
    let proposal = expiring.compile_read_proposal().expect("proposal");
    let evidence = expiring
        .record_read_evidence_at(
            &proposal,
            GraphqlResponse::new(200, &order_body(false)),
            NOW,
        )
        .expect("expired evidence");
    assert_eq!(evidence.projection_state, ProjectionState::Expired);
    assert_eq!(
        evidence.failure.as_ref().expect("failure").class,
        ProviderFailureClass::PermissionExpired
    );
    assert!(!evidence.connected);
    assert!(!evidence.native);

    let explicit = expiring
        .record_blocked_env(
            &proposal,
            BlockedEnvReason::NativeCredentialResolutionUnavailable,
        )
        .expect("explicit blocked env");
    assert_eq!(explicit.projection_state, ProjectionState::BlockedEnv);
}

#[test]
fn tampered_proposals_evidence_and_revocations_fail_closed() {
    let mut service = service(ProviderMode::Recording, None);
    let proposal = service.compile_read_proposal().expect("proposal");
    let mut tampered_proposal = proposal.clone();
    tampered_proposal.scope_digest = Digest::from_text("tampered-scope");
    assert_eq!(
        service
            .record_read_evidence(
                &tampered_proposal,
                GraphqlResponse::new(200, &order_body(false))
            )
            .expect_err("tampered proposal"),
        hartevo_shopify_order_result_plugin::ShopifyServiceError::ProposalTampered
    );

    let evidence = service
        .record_read_evidence(&proposal, GraphqlResponse::new(200, &order_body(false)))
        .expect("evidence");
    let mut tampered_evidence = evidence.clone();
    tampered_evidence.permission_digest = Digest::from_text("tampered-permission");
    assert_eq!(
        service
            .propose_adoption(&tampered_evidence)
            .expect_err("tampered evidence"),
        hartevo_shopify_order_result_plugin::ShopifyServiceError::EvidenceTampered
    );

    service.revoke_registration().expect("revoke");
    assert!(service.compile_read_proposal().is_err());
    assert_eq!(
        service.revoke_registration().expect_err("second revoke"),
        hartevo_shopify_order_result_plugin::ShopifyServiceError::RegistrationRevoked
    );
}

#[test]
fn response_size_retry_and_duplicate_permission_bounds_are_adversarial() {
    assert_eq!(
        PermissionLease::new(
            vec![ShopifyPermission::ReadOrders, ShopifyPermission::ReadOrders],
            1,
            None,
        )
        .expect_err("duplicate permissions"),
        ModelError::DuplicatePermission {
            field: "permission lease"
        }
    );

    let bounded = ShopifyOrderResultService::new(
        scope(None),
        ShopifyAdminProvider::new(ProviderMode::Recording)
            .expect("provider")
            .with_response_bound(32)
            .expect("response bound"),
    )
    .expect("service");
    let proposal = bounded.compile_read_proposal().expect("proposal");
    let evidence = bounded
        .record_read_evidence(&proposal, GraphqlResponse::new(200, &order_body(false)))
        .expect("size evidence");
    assert_eq!(evidence.projection_state, ProjectionState::ProviderUnknown);
    assert_eq!(
        evidence.failure.as_ref().expect("failure").class,
        ProviderFailureClass::ResponseTooLarge
    );

    let metadata = ResponseMetadata::new(Some("request"), None, Some(600_001), 0)
        .expect_err("retry-after bound");
    assert_eq!(metadata, ShopifyProviderError::RetryAfterExceeded);
    assert!(ResponseMetadata::new(Some("request"), None, Some(1000), 1).is_ok());
}

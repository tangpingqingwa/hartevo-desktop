use hartevo_paddle_subscription_result_plugin::{
    ApiBinding, CONTRACT_JSON, CONTRACT_VERSION, CursorKind, Digest, EVENT_RETENTION_SECONDS,
    EvidenceDisposition, MissionPaddleSubscriptionConsumer, MissionResultState, PADDLE_API_VERSION,
    PLUGIN_ID, PLUGIN_VERSION, PaddleBillingProvider, PaddleBillingProviderError,
    PaddleBillingScope, PaddleEventCursor, PaddleHttpResponse, PaddleSubscriptionResultError,
    PaddleSubscriptionResultService, PaddleTransactionStatus, PaddleTransportError,
    ProviderProvenance, ReadOnlyAuthority, RecordingPaddleBillingTransport, Revision,
    ScheduledChangeAction, SubscriptionStatus, TransactionStatus,
};
use serde_json::json;

fn scope() -> PaddleBillingScope {
    PaddleBillingScope::fixture().expect("fixture scope")
}

fn service_with(
    transport: &RecordingPaddleBillingTransport,
    provenance: ProviderProvenance,
) -> PaddleSubscriptionResultService {
    PaddleSubscriptionResultService::new(
        scope(),
        PaddleBillingProvider::new(transport.clone(), provenance).expect("provider"),
    )
    .expect("service")
}

fn subscription_json(status: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "data": {
            "id": "sub_fixture",
            "status": status,
            "seller_id": "acct_fixture",
            "customer_id": "ctm_fixture",
            "customer": {"name": "Private Customer", "email": "private@example.invalid"},
            "currency_code": "USD",
            "created_at": "2026-08-14T00:00:00Z",
            "started_at": "2026-08-14T00:01:00Z",
            "first_billed_at": "2026-08-14T00:02:00Z",
            "next_billed_at": "2026-09-14T00:02:00Z",
            "paused_at": null,
            "canceled_at": null,
            "current_billing_period": {
                "starts_at": "2026-08-14T00:02:00Z",
                "ends_at": "2026-09-14T00:02:00Z"
            },
            "scheduled_change": {
                "action": "pause",
                "effective_at": "2026-09-14T00:02:00Z",
                "resume_at": "2026-10-14T00:02:00Z"
            },
            "collection_mode": "automatic",
            "billing_cycle": {"frequency": 1, "interval": "month"},
            "items": [{
                "price": {
                    "id": "pri_fixture",
                    "name": "Private Plan Name",
                    "unit_price": {"amount": "900", "currency_code": "USD"}
                },
                "quantity": 2
            }],
            "custom_data": {"internal_reference": "private-metadata"}
        }
    }))
    .expect("subscription JSON")
}

fn transaction_json(id: &str, status: &str, origin: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "data": {
            "id": id,
            "status": status,
            "seller_id": "acct_fixture",
            "subscription_id": "sub_fixture",
            "customer_id": "ctm_fixture",
            "customer": {"name": "Private Customer", "email": "private@example.invalid"},
            "currency_code": "USD",
            "origin": origin,
            "created_at": "2026-08-14T00:02:00Z",
            "updated_at": "2026-08-14T00:03:00Z",
            "billed_at": "2026-08-14T00:03:00Z",
            "completed_at": "2026-08-14T00:04:00Z",
            "billing_period": {
                "starts_at": "2026-08-14T00:02:00Z",
                "ends_at": "2026-09-14T00:02:00Z"
            },
            "details": {"totals": {
                "subtotal": {"amount": "900", "currency_code": "USD"},
                "discount": {"amount": "0", "currency_code": "USD"},
                "tax": {"amount": "90", "currency_code": "USD"},
                "total": {"amount": "990", "currency_code": "USD"},
                "earnings": {"amount": "891", "currency_code": "USD"}
            }},
            "items": [{"price": {"id": "pri_fixture", "name": "Private Item Name"}}],
            "payments": [{
                "payment_attempt_id": "attempt_fixture",
                "payment_method_id": "paymtd_fixture",
                "amount": "990",
                "status": "captured",
                "created_at": "2026-08-14T00:03:30Z",
                "error_code": null
            }],
            "custom_data": {"private": "value"}
        }
    }))
    .expect("transaction JSON")
}

fn transaction_list_json(ids: &[&str], has_more: bool, next: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "data": ids.iter().map(|id| {
            serde_json::from_slice::<serde_json::Value>(&transaction_json(
                id,
                if *id == "txn_two" { "refunded" } else { "completed" },
                "subscription_recurring",
            )).expect("transaction value")["data"].clone()
        }).collect::<Vec<_>>(),
        "meta": {"pagination": {"has_more": has_more, "next": next}}
    }))
    .expect("transaction list JSON")
}

fn event_list_json(
    event_id: &str,
    event_type: &str,
    entity_id: &str,
    has_more: bool,
    next: Option<&str>,
) -> Vec<u8> {
    let data = if event_type.starts_with("subscription.") {
        json!({"id": entity_id, "status": "active", "seller_id": "acct_fixture", "customer_id": "ctm_fixture", "items": [{"name": "Private"}]})
    } else {
        json!({"id": entity_id, "status": "completed", "seller_id": "acct_fixture", "subscription_id": "sub_fixture", "customer_id": "ctm_fixture", "items": [{"name": "Private"}]})
    };
    serde_json::to_vec(&json!({
        "data": [{
            "event_id": event_id,
            "event_type": event_type,
            "occurred_at": "2026-08-14T00:05:00Z",
            "data": data
        }],
        "meta": {"pagination": {"has_more": has_more, "next": next}}
    }))
    .expect("event JSON")
}

#[test]
fn contract_and_authority_are_exact_layer_one_read_only() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract");
    assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
    assert_eq!(contract["plugin"]["id"], PLUGIN_ID);
    assert_eq!(contract["plugin"]["version"], PLUGIN_VERSION);
    assert_eq!(contract["provider"]["apiVersion"], PADDLE_API_VERSION);
    assert_eq!(
        contract["service"]["type"],
        "PaddleSubscriptionResultService"
    );
    assert_eq!(contract["provider"]["type"], "PaddleBillingProvider");
    assert_eq!(
        contract["consumer"]["type"],
        "MissionPaddleSubscriptionConsumer"
    );
    assert_eq!(contract["provider"]["nativeStatus"], "BLOCKED_ENV");
    assert_eq!(contract["provider"]["connected"], false);
    assert_eq!(contract["provider"]["native"], false);
    assert_eq!(contract["provider"]["firstParty"], false);
    assert_eq!(contract["evidence"]["connected"], false);
    assert_eq!(contract["evidence"]["native"], false);
    assert_eq!(contract["evidence"]["firstParty"], false);
    assert_eq!(contract["authority"]["paymentInitiation"], false);
    assert!(!ReadOnlyAuthority::external_writes());
    assert!(!ReadOnlyAuthority::payment_initiation());
    assert!(!ReadOnlyAuthority::checkout());
    assert!(!ReadOnlyAuthority::subscription_mutation());
    assert!(!ReadOnlyAuthority::transaction_mutation());
    assert!(!ReadOnlyAuthority::refund());
    assert!(!ReadOnlyAuthority::customer_portal());
    assert!(!ReadOnlyAuthority::webhook_effect());
    assert!(!ReadOnlyAuthority::durable_native_receipt());
    assert!(!ReadOnlyAuthority::independent_readback());
    assert!(!ReadOnlyAuthority::kernel_authority());
    assert!(!ReadOnlyAuthority::outcome_adoption());
    assert!(!ReadOnlyAuthority::connected());
    assert!(!ReadOnlyAuthority::native());
    assert!(!ReadOnlyAuthority::first_party());
}

#[test]
fn opaque_secret_and_registration_bind_all_digests_without_serializing_key() {
    let scope = scope();
    let debug = format!("{scope:?}");
    assert!(!debug.contains("fixture-api-key-reference"));
    let identity_json = serde_json::to_string(scope.identity()).expect("identity JSON");
    assert!(!identity_json.contains("fixture-api-key-reference"));
    assert_eq!(
        scope.identity().api,
        ApiBinding::official(Revision::new(1).unwrap())
    );
    let transport = RecordingPaddleBillingTransport::new();
    let service = service_with(&transport, ProviderProvenance::Recording);
    let registration = service.registration();
    assert_eq!(registration.scope_digest, scope.scope_digest());
    assert_eq!(
        registration.secret_reference_digest,
        *scope.secret_reference().reference_digest()
    );
    assert_eq!(registration.api_digest, scope.identity().api.digest());
    assert_eq!(
        registration.permission_digest,
        scope.identity().permission.digest
    );
    assert_eq!(registration.revision_digest, scope.revision_digest());
    assert!(registration.reversible);
    assert!(registration.revocable);
    assert!(!service.provider().definition().connected());
    assert!(!service.provider().definition().native());
    assert!(!service.provider().definition().first_party());
}

#[test]
fn subscription_projection_keeps_lifecycle_renewal_schedule_amount_and_redacted_metadata() {
    let transport = RecordingPaddleBillingTransport::new();
    transport.push_response(
        PaddleHttpResponse::new(200, subscription_json("active"))
            .with_observed_at(100)
            .with_snapshot_revision(Revision::new(1).unwrap()),
    );
    let mut service = service_with(&transport, ProviderProvenance::Fixture);
    let evidence = service
        .read_subscription(
            hartevo_paddle_subscription_result_plugin::SubscriptionId::new("sub_fixture").unwrap(),
            100,
        )
        .expect("subscription evidence");
    let subscription = evidence.subscription.as_ref().expect("subscription");
    assert_eq!(subscription.status, SubscriptionStatus::Active);
    assert!(subscription.is_renewing());
    assert_eq!(subscription.item_count, 1);
    assert_eq!(subscription.amount.as_ref().unwrap().amount, "900");
    assert_eq!(
        subscription.scheduled_change.as_ref().unwrap().action,
        ScheduledChangeAction::Pause
    );
    assert_eq!(evidence.disposition, EvidenceDisposition::Present);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    let evidence_json = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!evidence_json.contains("private@example.invalid"));
    assert!(!evidence_json.contains("Private Plan Name"));
    assert!(!evidence_json.contains("private-metadata"));
    let request = &transport.requests()[0];
    assert_eq!(
        request.method(),
        hartevo_paddle_subscription_result_plugin::PaddleHttpMethod::Get
    );
    assert_eq!(request.target(), "/subscriptions/sub_fixture");
}

#[test]
fn related_transactions_are_bounded_paginated_and_preserve_renewal_payment_and_refund_states() {
    let transport = RecordingPaddleBillingTransport::new();
    transport.push_response(
        PaddleHttpResponse::new(
            200,
            transaction_list_json(
                &["txn_one"],
                true,
                Some("https://api.paddle.com/transactions?after=txn_one"),
            ),
        )
        .with_observed_at(100)
        .with_snapshot_revision(Revision::new(1).unwrap()),
    );
    transport.push_response(
        PaddleHttpResponse::new(200, transaction_list_json(&["txn_two"], false, None))
            .with_observed_at(101)
            .with_snapshot_revision(Revision::new(1).unwrap()),
    );
    let mut service = service_with(&transport, ProviderProvenance::Recording);
    let evidence = service
        .paginate_transactions(1, 100)
        .expect("transaction pages");
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.transactions.len(), 2);
    assert!(evidence.has_renewal_evidence());
    assert_eq!(
        evidence.transactions[0].status,
        TransactionStatus::Completed
    );
    assert_eq!(evidence.transactions[1].status, TransactionStatus::Refunded);
    assert_eq!(evidence.transactions[0].payment_attempts.len(), 1);
    assert_eq!(
        evidence.transactions[0].total.as_ref().unwrap().amount,
        "990"
    );
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains("Private Item Name")
    );
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0]
            .target()
            .starts_with("/transactions?subscription_id=sub_fixture&per_page=1")
    );
    assert!(requests[1].target().contains("after=txn_one"));
}

#[test]
fn event_stream_is_subscription_scoped_redacted_and_expiry_fenced() {
    let transport = RecordingPaddleBillingTransport::new();
    transport.push_response(
        PaddleHttpResponse::new(
            200,
            event_list_json(
                "evt_one",
                "subscription.updated",
                "sub_fixture",
                true,
                Some("https://api.paddle.com/events?after=evt_one"),
            ),
        )
        .with_observed_at(100)
        .with_snapshot_revision(Revision::new(1).unwrap()),
    );
    transport.push_response(
        PaddleHttpResponse::new(
            200,
            event_list_json("evt_two", "transaction.completed", "txn_one", false, None),
        )
        .with_observed_at(101)
        .with_snapshot_revision(Revision::new(1).unwrap()),
    );
    let mut service = service_with(&transport, ProviderProvenance::Loopback);
    let evidence = service.paginate_events(1, 100).expect("event pages");
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.events.len(), 2);
    assert_eq!(evidence.events[0].event_type, "subscription.updated");
    assert_eq!(
        evidence.events[1].transaction_status,
        Some(TransactionStatus::Completed)
    );
    let output = serde_json::to_string(&evidence).expect("event evidence JSON");
    assert!(!output.contains("private@example.invalid"));
    assert!(!output.contains("Private"));

    let cursor = PaddleEventCursor::new(
        "evt_old",
        CursorKind::Events,
        service.scope().scope_digest(),
        Digest::from_text("previous-response"),
        100,
        100 + EVENT_RETENTION_SECONDS,
    )
    .expect("cursor");
    let error = service
        .compile_bounded_event_read(1, Some(&cursor), 100 + EVENT_RETENTION_SECONDS + 1)
        .expect_err("expired cursor");
    assert_eq!(error, PaddleSubscriptionResultError::CursorExpired);
}

#[test]
fn provider_errors_are_bounded_and_blocked_env_never_claims_native_or_connected() {
    let transport = RecordingPaddleBillingTransport::new();
    transport.push_response(PaddleHttpResponse::new(
        401,
        br#"{"error":"private secret body"}"#.to_vec(),
    ));
    let mut service = service_with(&transport, ProviderProvenance::Recording);
    let evidence = service
        .read_subscription(
            hartevo_paddle_subscription_result_plugin::SubscriptionId::new("sub_fixture").unwrap(),
            0,
        )
        .expect("bounded access-loss evidence");
    assert_eq!(evidence.disposition, EvidenceDisposition::AccessLost);
    assert_eq!(evidence.provider_error.as_ref().unwrap().status, Some(401));
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains("private secret body")
    );

    let blocked = PaddleBillingProvider::blocked_env().expect("blocked provider");
    assert!(!blocked.connected());
    assert!(!blocked.native());
    assert!(!blocked.first_party());
    let mut blocked_service = PaddleSubscriptionResultService::new(scope(), blocked).unwrap();
    let blocked_evidence = blocked_service
        .read_subscription(
            hartevo_paddle_subscription_result_plugin::SubscriptionId::new("sub_fixture").unwrap(),
            0,
        )
        .expect("BLOCKED_ENV evidence");
    assert_eq!(
        blocked_evidence.disposition,
        EvidenceDisposition::BlockedEnv
    );
    assert!(!blocked_evidence.connected);
    assert!(!blocked_evidence.native);
    assert!(!blocked_evidence.first_party);
}

#[test]
fn stale_revision_drift_proposal_tamper_and_reversible_registration_fail_closed() {
    let transport = RecordingPaddleBillingTransport::new();
    transport.push_response(
        PaddleHttpResponse::new(200, subscription_json("trialing"))
            .with_observed_at(99)
            .with_snapshot_revision(Revision::new(1).unwrap()),
    );
    let mut service = service_with(&transport, ProviderProvenance::Recording);
    let stale = service
        .read_subscription(
            hartevo_paddle_subscription_result_plugin::SubscriptionId::new("sub_fixture").unwrap(),
            100,
        )
        .expect_err("stale snapshot");
    assert_eq!(stale, PaddleSubscriptionResultError::StaleResult);

    transport.push_response(
        PaddleHttpResponse::new(200, subscription_json("trialing"))
            .with_observed_at(100)
            .with_snapshot_revision(Revision::new(2).unwrap()),
    );
    let drift = service
        .read_subscription(
            hartevo_paddle_subscription_result_plugin::SubscriptionId::new("sub_fixture").unwrap(),
            100,
        )
        .expect_err("revision drift");
    assert_eq!(drift, PaddleSubscriptionResultError::RevisionDrift);

    transport.push_response(
        PaddleHttpResponse::new(200, subscription_json("trialing"))
            .with_observed_at(100)
            .with_snapshot_revision(Revision::new(1).unwrap()),
    );
    let evidence = service
        .read_subscription(
            hartevo_paddle_subscription_result_plugin::SubscriptionId::new("sub_fixture").unwrap(),
            100,
        )
        .expect("valid evidence");
    let mut proposal = service.compile_result_proposal(&evidence).unwrap();
    proposal.connected = true;
    assert_eq!(
        service
            .verify_result_proposal(&proposal, &evidence)
            .expect_err("proposal tamper"),
        PaddleSubscriptionResultError::ProposalTampered
    );
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.describe_capabilities().expect_err("revoked"),
        PaddleSubscriptionResultError::RegistrationRevoked
    );
    service.restore_registration().expect("restore");
    service.describe_capabilities().expect("active again");
}

#[test]
fn mission_consumer_preserves_revision_fence_and_renewal_state_without_adoption() {
    let transport = RecordingPaddleBillingTransport::new();
    transport.push_response(
        PaddleHttpResponse::new(200, subscription_json("active"))
            .with_observed_at(100)
            .with_snapshot_revision(Revision::new(1).unwrap()),
    );
    let provider = PaddleBillingProvider::new(transport, ProviderProvenance::Fixture).unwrap();
    let mut consumer = MissionPaddleSubscriptionConsumer::new(scope(), provider).unwrap();
    let result = consumer
        .read_and_consume_subscription(100)
        .expect("Mission result");
    assert_eq!(result.state, MissionResultState::RenewalEvidence);
    assert!(result.renewal_evidence);
    assert_eq!(result.project_revision.get(), 1);
    assert_eq!(result.mission_revision.get(), 1);
    assert_eq!(result.work_product_revision.get(), 1);
    assert!(result.proposal_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.work_product_adopted);
    assert!(!result.kernel_authority);
}

#[test]
fn status_projection_preserves_official_and_adversarial_unknown_states() {
    for (raw, expected) in [
        ("active", SubscriptionStatus::Active),
        ("trialing", SubscriptionStatus::Trialing),
        ("past_due", SubscriptionStatus::PastDue),
        ("paused", SubscriptionStatus::Paused),
        ("canceled", SubscriptionStatus::Canceled),
        ("future-provider-state", SubscriptionStatus::ProviderUnknown),
    ] {
        assert_eq!(SubscriptionStatus::parse(raw), expected);
    }
    assert_eq!(
        PaddleTransactionStatus::parse("refunded"),
        TransactionStatus::Refunded
    );
    assert_eq!(
        PaddleTransactionStatus::parse("future"),
        TransactionStatus::ProviderUnknown
    );
}

#[test]
fn transport_error_classes_preserve_retry_and_access_boundaries() {
    assert!(
        PaddleBillingProviderError::RateLimited {
            retry_after_seconds: Some(4),
        }
        .is_retryable()
    );
    assert!(PaddleBillingProviderError::ServerError { status: 503 }.is_retryable());
    assert!(PaddleBillingProviderError::Timeout.is_retryable());
    assert!(PaddleBillingProviderError::Unauthorized.is_access_loss());
    assert!(PaddleBillingProviderError::Forbidden.is_access_loss());
    assert_eq!(
        PaddleTransportError::RateLimited,
        PaddleTransportError::RateLimited
    );
}

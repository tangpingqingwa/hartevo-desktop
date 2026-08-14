use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_ramp_spend_outcome_plugin::{
    AccessMode, BlockedEnvRampTransport, DateWindow, EvidenceStatus, FixtureRampTransport,
    IdentityBinding, LoopbackRampTransport, MissionRampSpendConsumer, OfficialRampApiResponseSpec,
    OfficialRampApiTransport, PermissionSnapshot, RampApiPage, RampAuditEventInput,
    RampAuditEventInputSpec, RampEndpoint, RampMerchantInput, RampMerchantInputSpec, RampProvider,
    RampSpendOutcomeError, RampSpendOutcomePluginDefinition, RampSpendOutcomeService,
    RampSpendScope, RampSpendScopeSpec, RampTransactionInput, RampTransactionInputSpec,
    RampTransport, RampTransportError, ReadOperation, RecordingRampTransport, RefundState,
    RetryPolicy, SecretReference, TransactionState, TransportProvenance, canonical_digest,
    sha256_digest, validate_contract_document,
};

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

fn window() -> DateWindow {
    DateWindow::closed(at("2026-08-14T00:00:00Z"), at("2026-08-15T00:00:00Z"))
        .expect("bounded date window")
}

fn identity(id: &str, revision: u64, field: &'static str) -> IdentityBinding {
    IdentityBinding::new(id, revision, field).expect("identity binding")
}

fn scope_spec() -> RampSpendScopeSpec {
    let mut spec = RampSpendScopeSpec {
        business_id: "business-1".to_owned(),
        entity_id: Some("entity-1".to_owned()),
        spend_program_id: Some("spend-program-1".to_owned()),
        card_id: Some("card-1".to_owned()),
        vendor_id: Some("merchant-1".to_owned()),
        transaction_id: None,
        audit_event_id: None,
        date_window: window(),
        project: identity("project-1", 4, "project id"),
        mission: identity("mission-1", 8, "mission id"),
        work_product: identity("work-product-1", 12, "work product id"),
        deployment: Some(identity("deployment-1", 2, "deployment id")),
        release: Some(identity("release-1", 3, "release id")),
        policy_revision: 6,
        permissions: PermissionSnapshot {
            requested: BTreeSet::new(),
            granted: BTreeSet::new(),
            revision: 1,
        },
    };
    spec.permissions = PermissionSnapshot::least_privilege_for(&spec);
    spec
}

fn scope_and_secret() -> (RampSpendScope, SecretReference) {
    let spec = scope_spec();
    let secret = SecretReference::oauth("opaque-ramp-oauth-reference", 7).expect("secret ref");
    let scope = RampSpendScope::new(spec, &secret).expect("scope");
    (scope, secret)
}

fn transaction(
    id: &str,
    state: &str,
    amount_minor: Option<i64>,
    transaction_time: &str,
) -> RampTransactionInput {
    RampTransactionInput::from_spec(RampTransactionInputSpec {
        id: id.to_owned(),
        state: state.to_owned(),
        amount_minor,
        currency_code: Some("USD".to_owned()),
        entity_id: Some("entity-1".to_owned()),
        spend_program_id: Some("spend-program-1".to_owned()),
        card_id: Some("card-1".to_owned()),
        merchant_id: Some("merchant-1".to_owned()),
        merchant_name: Some("Example Merchant".to_owned()),
        category_id: Some("category-42".to_owned()),
        category_name: Some("software".to_owned()),
        original_transaction_id: None,
        transaction_time: Some(at(transaction_time)),
        updated_at: Some(at("2026-08-14T01:00:00Z")),
        settlement_date: Some(at("2026-08-14T02:00:00Z")),
        refund_state: None,
    })
    .expect("transaction input")
}

fn merchant() -> RampMerchantInput {
    RampMerchantInput::from_spec(RampMerchantInputSpec {
        id: "merchant-1".to_owned(),
        merchant_name: "Example Merchant".to_owned(),
        category_name: Some("software".to_owned()),
    })
    .expect("merchant input")
}

fn audit_event() -> RampAuditEventInput {
    RampAuditEventInput::from_spec(RampAuditEventInputSpec {
        id: "audit-1".to_owned(),
        event_type: "Transaction cleared".to_owned(),
        actor_type: "user".to_owned(),
        resource_name: "Transaction".to_owned(),
        resource_id: Some("transaction-1".to_owned()),
        event_time: at("2026-08-14T03:00:00Z"),
    })
    .expect("audit event input")
}

fn page_set() -> Vec<RampApiPage> {
    vec![
        RampApiPage::new(
            RampEndpoint::Transactions,
            "business-1",
            vec![transaction(
                "transaction-1",
                "AUTHORIZED",
                Some(12_500),
                "2026-08-14T00:30:00Z",
            )],
            Vec::new(),
            Vec::new(),
            Some("cursor-1".to_owned()),
            "high-water-transactions",
        )
        .expect("transaction page 1"),
        RampApiPage::new(
            RampEndpoint::Transactions,
            "business-1",
            vec![transaction(
                "transaction-2",
                "CLEARED",
                Some(-2_500),
                "2026-08-14T04:30:00Z",
            )],
            Vec::new(),
            Vec::new(),
            None,
            "high-water-transactions",
        )
        .expect("transaction page 2"),
        RampApiPage::new(
            RampEndpoint::Merchants,
            "business-1",
            Vec::new(),
            vec![merchant()],
            Vec::new(),
            None,
            "high-water-merchants",
        )
        .expect("merchant page"),
        RampApiPage::new(
            RampEndpoint::AuditLogs,
            "business-1",
            Vec::new(),
            Vec::new(),
            vec![audit_event()],
            None,
            "high-water-audit",
        )
        .expect("audit page"),
    ]
}

fn provider_with_loopback() -> (
    RampProvider<LoopbackRampTransport>,
    RampSpendScope,
    SecretReference,
) {
    let (scope, secret) = scope_and_secret();
    let provider = RampProvider::new(
        LoopbackRampTransport::from_pages(page_set()),
        scope.clone(),
        secret.clone(),
        2,
        9,
    )
    .expect("provider registration");
    (provider, scope, secret)
}

#[test]
fn contract_and_secret_reference_are_layer_one_honest_and_redacted() {
    validate_contract_document().expect("contract validates");
    let definition = RampSpendOutcomePluginDefinition::layer1().expect("definition");
    assert_eq!(definition.service.access, AccessMode::ReadOnly);
    assert!(!definition.writes);
    assert!(!definition.native);
    assert_eq!(definition.provider.implementation, "RampProvider");
    assert!(
        !definition
            .provider
            .permissions
            .iter()
            .any(|scope| scope.ends_with(":write"))
    );

    let (scope, secret) = scope_and_secret();
    let serialized_scope = serde_json::to_string(&scope).expect("scope serializes as digests");
    assert!(!serialized_scope.contains("business-1"));
    assert!(!serialized_scope.contains("opaque-ramp-oauth-reference"));
    let debug_secret = format!("{secret:?}");
    assert!(!debug_secret.contains("opaque-ramp-oauth-reference"));
    assert_eq!(
        secret.kind(),
        hartevo_ramp_spend_outcome_plugin::SecretKind::OAuth
    );
    assert_eq!(secret.revision(), 7);
    assert_eq!(scope.permissions.requested, scope.permissions.granted);
}

#[test]
fn bounded_read_proposal_record_verify_and_mission_projection_are_non_mutating() {
    let (provider, scope, _) = provider_with_loopback();
    let service = RampSpendOutcomeService::new(provider);
    let evidence = service
        .read_spend_evidence(window())
        .expect("bounded evidence");
    assert_eq!(evidence.status, EvidenceStatus::Complete);
    assert_eq!(evidence.transactions.len(), 2);
    assert_eq!(evidence.transactions[0].state, TransactionState::Authorized);
    assert_eq!(evidence.transactions[1].refund_state, RefundState::Partial);
    assert!(!evidence.native);
    assert!(!evidence.connected);
    assert_eq!(evidence.provenance, TransportProvenance::Loopback);
    assert!(
        serde_json::to_string(&evidence)
            .expect("evidence serializes")
            .contains("transactionIdDigest")
    );

    let proposal = service
        .compile_outcome_proposal(&evidence)
        .expect("outcome proposal");
    proposal.validate().expect("proposal validates");
    assert_eq!(proposal.project, scope.project);
    assert_eq!(proposal.mission, scope.mission);
    assert_eq!(proposal.work_product, scope.work_product);
    assert!(!proposal.effect_requested);

    let receipt = service.record_evidence(&evidence).expect("receipt");
    let verification = service.verify_evidence(&receipt).expect("verification");
    assert!(verification.verified);
    assert!(!verification.adoptable);
    assert!(!verification.native);

    let consumer = MissionRampSpendConsumer::from_evidence_scope(&scope).expect("consumer");
    let adoption = consumer
        .compile_adoption_proposal(&proposal)
        .expect("adoption proposal");
    adoption.validate().expect("adoption validates");
    assert!(!adoption.truth_authority);
    assert!(!adoption.consent_authority);
    assert!(!adoption.effect_authority);
    assert!(!adoption.receipt_authority);
    assert!(!adoption.verification_authority);
    assert!(!adoption.outcome_authority);
    assert!(!adoption.mutates_provider);
}

#[test]
fn registration_is_version_provider_contract_scope_and_permission_bound_and_revocable() {
    let (provider, scope, _) = provider_with_loopback();
    let registration = provider.registration().expect("registration");
    assert_eq!(registration.scope_digest, scope.digest());
    assert_eq!(registration.permission_digest, scope.permissions.digest());
    assert_eq!(registration.implementation, "RampProvider");
    assert!(registration.is_active());
    assert_eq!(registration.provider_revision, 2);

    provider.revoke().expect("revocation");
    assert!(matches!(
        provider.read_evidence(window()),
        Err(RampSpendOutcomeError::RegistrationRevoked)
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn cursor_loops_high_water_drift_and_page_tamper_fail_closed() {
    let (scope, secret) = scope_and_secret();
    let loop_pages = vec![
        RampApiPage::new(
            RampEndpoint::Transactions,
            "business-1",
            vec![transaction(
                "transaction-1",
                "PENDING",
                Some(10),
                "2026-08-14T00:30:00Z",
            )],
            Vec::new(),
            Vec::new(),
            Some("same-cursor".to_owned()),
            "high-water",
        )
        .expect("loop page 1"),
        RampApiPage::new(
            RampEndpoint::Transactions,
            "business-1",
            vec![transaction(
                "transaction-2",
                "CLEARED",
                Some(20),
                "2026-08-14T01:30:00Z",
            )],
            Vec::new(),
            Vec::new(),
            Some("same-cursor".to_owned()),
            "high-water",
        )
        .expect("loop page 2"),
    ];
    let provider = RampProvider::new(
        LoopbackRampTransport::from_pages(loop_pages),
        scope.clone(),
        secret.clone(),
        1,
        1,
    )
    .expect("loop provider");
    assert!(matches!(
        provider.read_evidence(window()),
        Err(RampSpendOutcomeError::CursorLoop)
    ));

    let drift_pages = vec![
        RampApiPage::new(
            RampEndpoint::Transactions,
            "business-1",
            vec![transaction(
                "transaction-1",
                "PENDING",
                Some(10),
                "2026-08-14T00:30:00Z",
            )],
            Vec::new(),
            Vec::new(),
            Some("next".to_owned()),
            "high-water-1",
        )
        .expect("drift page 1"),
        RampApiPage::new(
            RampEndpoint::Transactions,
            "business-1",
            vec![transaction(
                "transaction-2",
                "CLEARED",
                Some(20),
                "2026-08-14T01:30:00Z",
            )],
            Vec::new(),
            Vec::new(),
            None,
            "high-water-2",
        )
        .expect("drift page 2"),
    ];
    let drift_provider = RampProvider::new(
        LoopbackRampTransport::from_pages(drift_pages),
        scope.clone(),
        secret.clone(),
        1,
        1,
    )
    .expect("drift provider");
    assert!(matches!(
        drift_provider.read_evidence(window()),
        Err(RampSpendOutcomeError::HighWaterMarkDrift)
    ));

    let tampered_page = RampApiPage::new(
        RampEndpoint::Transactions,
        "business-1",
        vec![transaction(
            "transaction-1",
            "PENDING",
            Some(10),
            "2026-08-14T00:30:00Z",
        )],
        Vec::new(),
        Vec::new(),
        None,
        "high-water",
    )
    .expect("page")
    .tampered();
    let tampered_provider = RampProvider::new(
        LoopbackRampTransport::from_pages(vec![tampered_page]),
        scope,
        secret,
        1,
        1,
    )
    .expect("tampered provider");
    assert!(matches!(
        tampered_provider.read_evidence(window()),
        Err(RampSpendOutcomeError::ResponseTampered)
    ));
}

#[test]
fn rate_limit_and_gateway_timeout_backoff_are_recorded_without_sleeping() {
    let (scope, secret) = scope_and_secret();
    let transport = RecordingRampTransport::from_pages(Vec::new());
    transport
        .push_error(RampTransportError::RateLimited429 {
            retry_after_seconds: Some(4),
        })
        .expect("429");
    transport
        .push_error(RampTransportError::GatewayTimeout504)
        .expect("504");
    for page in page_set() {
        transport.push_page(page).expect("fixture page");
    }
    let provider = RampProvider::new(transport.clone(), scope, secret, 1, 1)
        .expect("provider")
        .with_retry_policy(RetryPolicy::new(3, 1, 8).expect("retry policy"));
    provider
        .read_evidence(window())
        .expect("recovered evidence");
    let requests = transport.requests();
    assert_eq!(requests[0].operation, ReadOperation::ReadTransactions);
    assert_eq!(requests[0].attempt, 1);
    assert_eq!(requests[0].backoff_seconds, 0);
    assert_eq!(requests[1].attempt, 2);
    assert_eq!(requests[1].backoff_seconds, 4);
    assert_eq!(requests[2].attempt, 3);
    assert_eq!(requests[2].backoff_seconds, 2);
}

#[test]
#[allow(clippy::too_many_lines)]
fn access_loss_retention_partial_provider_unknown_and_blocked_env_are_not_success() {
    let (scope, secret) = scope_and_secret();
    let access_provider = RampProvider::new(
        RecordingRampTransport::from_pages(Vec::new()),
        scope.clone(),
        secret.clone(),
        1,
        1,
    )
    .expect("access provider");
    access_provider
        .transport()
        .push_error(RampTransportError::Forbidden403)
        .expect("403");
    assert!(matches!(
        access_provider.read_evidence(window()),
        Err(RampSpendOutcomeError::AccessLost)
    ));

    let mut exact_spec = scope_spec();
    exact_spec.transaction_id = Some("missing-transaction".to_owned());
    exact_spec.permissions = PermissionSnapshot::least_privilege_for(&exact_spec);
    let exact_scope = RampSpendScope::new(exact_spec, &secret).expect("exact scope");
    let exact_pages = vec![
        RampApiPage::new(
            RampEndpoint::Transactions,
            "business-1",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            "high-water-transactions",
        )
        .expect("empty transaction page"),
        RampApiPage::new(
            RampEndpoint::Merchants,
            "business-1",
            Vec::new(),
            vec![merchant()],
            Vec::new(),
            None,
            "high-water-merchants",
        )
        .expect("merchant page"),
        RampApiPage::new(
            RampEndpoint::AuditLogs,
            "business-1",
            Vec::new(),
            Vec::new(),
            vec![audit_event()],
            None,
            "high-water-audit",
        )
        .expect("audit page"),
    ];
    let retention_provider = RampProvider::new(
        LoopbackRampTransport::from_pages(exact_pages),
        exact_scope,
        secret.clone(),
        1,
        1,
    )
    .expect("retention provider");
    assert!(matches!(
        retention_provider.read_evidence(window()),
        Err(RampSpendOutcomeError::RetentionGap)
    ));

    let partial_provider = RampProvider::new(
        RecordingRampTransport::from_pages(Vec::new()),
        scope.clone(),
        secret.clone(),
        1,
        1,
    )
    .expect("partial provider");
    partial_provider
        .transport()
        .push_error(RampTransportError::PartialResponse)
        .expect("partial");
    assert!(matches!(
        partial_provider.read_evidence(window()),
        Err(RampSpendOutcomeError::PartialEvidence)
    ));

    let unknown_tx = transaction(
        "transaction-unknown",
        "future-provider-state",
        Some(100),
        "2026-08-14T00:30:00Z",
    );
    let unknown_provider = RampProvider::new(
        LoopbackRampTransport::from_pages(vec![
            RampApiPage::new(
                RampEndpoint::Transactions,
                "business-1",
                vec![unknown_tx],
                Vec::new(),
                Vec::new(),
                None,
                "high-water-transactions",
            )
            .expect("unknown page"),
            RampApiPage::new(
                RampEndpoint::Merchants,
                "business-1",
                Vec::new(),
                vec![merchant()],
                Vec::new(),
                None,
                "high-water-merchants",
            )
            .expect("unknown merchant page"),
            RampApiPage::new(
                RampEndpoint::AuditLogs,
                "business-1",
                Vec::new(),
                Vec::new(),
                vec![audit_event()],
                None,
                "high-water-audit",
            )
            .expect("unknown audit page"),
        ]),
        scope.clone(),
        secret.clone(),
        1,
        1,
    )
    .expect("unknown provider");
    assert!(matches!(
        unknown_provider.read_evidence(window()),
        Err(RampSpendOutcomeError::ProviderUnknown)
    ));

    let blocked_provider = RampProvider::new(BlockedEnvRampTransport, scope, secret, 1, 1)
        .expect("blocked provider registration");
    assert!(matches!(
        blocked_provider.read_evidence(window()),
        Err(RampSpendOutcomeError::Transport(
            RampTransportError::BlockedEnv
        ))
    ));
}

#[test]
fn official_parser_ignores_prohibited_payload_fields_and_preserves_only_allowlisted_data() {
    let body = r#"{
      "data": [{
        "id": "transaction-1",
        "state": "CLEARED",
        "amount": 12500,
        "currency_code": "USD",
        "entity_id": "entity-1",
        "spend_program_id": "spend-program-1",
        "card_id": "card-1",
        "merchant_id": "merchant-1",
        "merchant_name": "Example Merchant",
        "sk_category_id": 42,
        "sk_category_name": "software",
        "created_at": "2026-08-14T00:30:00Z",
        "updated_at": "2026-08-14T01:00:00Z",
        "settlement_date": "2026-08-14T02:00:00Z",
        "memo": "unbounded private memo that must not be retained",
        "receipts": ["receipt-file-url"],
        "card_holder": {"first_name": "Employee", "last_name": "Private"},
        "bank_account": {"account_number": "never"}
      }],
      "page": {"next": null}
    }"#;
    let page = hartevo_ramp_spend_outcome_plugin::parse_official_json_page(
        RampEndpoint::Transactions,
        "business-1",
        body,
        "high-water",
    )
    .expect("official transaction response parses");
    let debug = format!("{page:?}");
    assert!(!debug.contains("unbounded private memo"));
    assert!(!debug.contains("Employee"));
    assert!(!debug.contains("receipt-file-url"));
    assert_eq!(page.endpoint, RampEndpoint::Transactions);
    assert_eq!(page.transactions.len(), 1);

    let official_transport =
        OfficialRampApiTransport::from_json_pages(vec![OfficialRampApiResponseSpec::new(
            RampEndpoint::Transactions,
            "business-1",
            body,
            "high-water",
        )])
        .expect("official parser transport");
    assert_eq!(
        official_transport.provenance(),
        TransportProvenance::OfficialApiParser
    );
    assert!(!official_transport.provenance().is_native());
    assert!(!official_transport.provenance().is_connected());
}

#[test]
fn tampered_receipts_and_consumer_revision_drift_fail_closed() {
    let (provider, scope, _) = provider_with_loopback();
    let service = RampSpendOutcomeService::new(provider);
    let evidence = service.read_spend_evidence(window()).expect("evidence");
    let receipt = service.record_evidence(&evidence).expect("receipt");
    let mut tampered = receipt.clone();
    tampered.evidence_digest = sha256_digest(b"changed");
    assert!(matches!(
        service.verify_evidence(&tampered),
        Err(RampSpendOutcomeError::ReceiptTampered)
    ));

    let consumer = MissionRampSpendConsumer::new(
        identity("project-1", 5, "project id"),
        scope.mission.clone(),
        scope.work_product.clone(),
    )
    .expect("consumer with different revision");
    let proposal = service
        .compile_outcome_proposal(&evidence)
        .expect("proposal");
    assert!(matches!(
        consumer.compile_adoption_proposal(&proposal),
        Err(RampSpendOutcomeError::ConsumerBindingMismatch)
    ));
}

#[test]
fn fixture_and_recording_provenance_never_claims_connected_or_native() {
    let (scope, secret) = scope_and_secret();
    let provider = RampProvider::new(
        FixtureRampTransport::from_pages(page_set()),
        scope,
        secret,
        1,
        1,
    )
    .expect("fixture provider");
    assert_eq!(provider.provenance(), TransportProvenance::Fixture);
    assert!(!provider.provenance().is_native());
    assert!(!provider.provenance().is_connected());
    assert!(!provider.capabilities().native);
    assert!(!provider.capabilities().connected);
}

#[test]
fn digest_helpers_are_stable_and_read_operations_are_endpoint_bound() {
    assert_eq!(canonical_digest(&"ramp"), sha256_digest(br#""ramp""#));
    assert_ne!(sha256_digest(b"ramp"), canonical_digest(&"ramp"));
    assert_eq!(
        ReadOperation::ReadTransactions.endpoint(),
        RampEndpoint::Transactions
    );
    assert_eq!(
        ReadOperation::ReadMerchants.endpoint(),
        RampEndpoint::Merchants
    );
    assert_eq!(
        ReadOperation::ReadAuditLogs.endpoint(),
        RampEndpoint::AuditLogs
    );
    assert_eq!(
        RampEndpoint::AuditLogs.path(),
        "/developer/v1/audit-logs/events"
    );
}

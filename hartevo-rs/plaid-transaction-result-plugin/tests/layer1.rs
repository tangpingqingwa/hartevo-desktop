use hartevo_plaid_transaction_result_plugin as plaid;
use serde_json::{Value, json};

fn scope_and_secret() -> (plaid::PlaidTransactionsScope, plaid::SecretReference) {
    let secret = plaid::SecretReference::new("host/plaid/access-token", 7).expect("secret");
    let permission = plaid::PermissionScope::new(
        plaid::PlaidProduct::Transactions,
        plaid::PlaidPermission::TransactionsRead,
        secret.clone(),
    )
    .expect("permission");
    let scope = plaid::PlaidTransactionsScope::new(
        plaid::PlaidEnvironment::Sandbox,
        plaid::ItemScope::new("item-opaque-1", 3).expect("item"),
        plaid::ProjectScope::new("project-1", 2).expect("project"),
        plaid::MissionScope::new("mission-1", 4).expect("mission"),
        plaid::WorkProductScope::new("work-product-1", 5).expect("work product"),
        permission,
    )
    .expect("scope")
    .with_update_window(plaid::UpdateWindow::new(1_700_000_000, 1_700_100_000, 6).expect("window"))
    .with_transaction_revision(
        plaid::TransactionRevision::new(8, plaid::Digest::sha256(b"high-water-8"))
            .expect("transaction revision"),
    );
    (scope, secret)
}

#[allow(clippy::needless_pass_by_value)]
fn page(
    added: Vec<Value>,
    modified: Vec<Value>,
    removed: Vec<Value>,
    next_cursor: &str,
    has_more: bool,
) -> String {
    json!({
        "added": added,
        "modified": modified,
        "removed": removed,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "request_id": "request-redacted-at-boundary"
    })
    .to_string()
}

fn transaction(id: &str, account_id: &str, pending: bool, amount: &str) -> Value {
    json!({
        "transaction_id": id,
        "account_id": account_id,
        "amount": amount,
        "iso_currency_code": "USD",
        "date": "2026-08-14",
        "authorized_date": "2026-08-13",
        "pending": pending,
        "merchant_name": "PRIVATE-MERCHANT-PII",
        "merchant_entity_id": "merchant-opaque-1",
        "personal_finance_category": {
            "primary": "FOOD_AND_DRINK",
            "detailed": "FOOD_AND_DRINK_RESTAURANT"
        }
    })
}

fn modified_transaction(id: &str, account_id: &str, pending: bool) -> Value {
    transaction(id, account_id, pending, "42.00")
}

fn removed_transaction(id: &str) -> Value {
    json!({"transaction_id": id})
}

fn fixture_service(
    responses: impl IntoIterator<Item = Result<plaid::PlaidHttpResponse, plaid::PlaidTransportError>>,
) -> plaid::PlaidTransactionResultService {
    let (scope, secret) = scope_and_secret();
    let provider = plaid::PlaidTransactionsProvider::new(
        plaid::FixturePlaidTransport::new(responses),
        plaid::FixtureSecretResolver::new("fixture-access-token").expect("fixture secret"),
    );
    plaid::PlaidTransactionResultService::new(scope, secret, provider).expect("service")
}

fn fixture_request(
    service: &plaid::PlaidTransactionResultService,
) -> plaid::TransactionSyncRequest {
    plaid::TransactionSyncRequest::from_scope(service.scope(), 100).expect("request")
}

#[test]
fn contract_is_versioned_read_only_and_bounded() {
    let contract: Value =
        serde_json::from_str(plaid::PLAID_TRANSACTION_RESULT_CONTRACT_JSON).expect("contract");
    assert_eq!(
        contract["schemaVersion"],
        plaid::PLAID_TRANSACTION_RESULT_SCHEMA_VERSION
    );
    assert_eq!(contract["contractVersion"], "plaid-transaction-result/v1");
    assert_eq!(contract["api"], "/transactions/sync");
    assert_eq!(contract["method"], "POST");
    assert_eq!(contract["sync"]["boundedCountMax"], 500);
    assert_eq!(contract["sync"]["boundedTransactionMax"], 500);
    assert_eq!(contract["authority"]["connected"], false);
    assert_eq!(contract["authority"]["native"], false);
    assert_eq!(contract["authority"]["externalWrites"], false);
    assert_eq!(contract["authority"]["financialAdvice"], false);
    assert_eq!(contract["authority"]["kernelOutcomeAdoption"], false);
    assert_eq!(
        contract["evidenceModes"].as_array().expect("modes").len(),
        4
    );
}

#[test]
fn redacts_secret_cursor_ids_merchant_and_account_payloads() {
    let secret = plaid::SecretReference::new("REAL-PLAID-ACCESS-TOKEN", 9).expect("secret");
    assert!(!format!("{secret:?}").contains("REAL-PLAID-ACCESS-TOKEN"));
    let (scope, _) = scope_and_secret();
    let request = plaid::TransactionSyncRequest::from_scope(&scope, 10).expect("request");
    assert!(!format!("{scope:?}").contains("item-opaque-1"));
    assert!(!format!("{request:?}").contains("item-opaque-1"));
    let response = plaid::PlaidHttpResponse::json(
        200,
        page(
            vec![transaction("tx-1", "acct-1", true, "12.34")],
            vec![],
            vec![],
            "cursor-1",
            false,
        ),
    );
    assert!(!format!("{response:?}").contains("PRIVATE-MERCHANT-PII"));
    assert!(!format!("{response:?}").contains("acct-1"));

    let mut service = fixture_service([Ok(response)]);
    let evidence = service.read(&request).expect("read");
    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    let debug = format!("{evidence:?}");
    for forbidden in [
        "REAL-PLAID-ACCESS-TOKEN",
        "PRIVATE-MERCHANT-PII",
        "merchant-opaque-1",
        "acct-1",
        "tx-1",
        "cursor-1",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "serialized leaked {forbidden}"
        );
        assert!(!debug.contains(forbidden), "debug leaked {forbidden}");
    }
    let permission_json = serde_json::to_string(scope.permission()).expect("permission JSON");
    assert!(!permission_json.contains("REAL-PLAID-ACCESS-TOKEN"));
}

#[test]
fn reads_pending_posted_modified_removed_and_binds_sync_request() {
    let first = page(
        vec![
            transaction("tx-pending", "acct-1", true, "9.99"),
            transaction("tx-posted", "acct-1", false, "100.00"),
        ],
        vec![],
        vec![],
        "cursor-1",
        true,
    );
    let second = page(
        vec![],
        vec![modified_transaction("tx-modified", "acct-1", false)],
        vec![removed_transaction("tx-removed")],
        "cursor-2",
        false,
    );
    let mut service = fixture_service([
        Ok(plaid::PlaidHttpResponse::json(200, first)),
        Ok(plaid::PlaidHttpResponse::json(200, second)),
    ]);
    let request = fixture_request(&service);
    let proposal = service.compile_result_proposal(&request).expect("proposal");
    let evidence = service
        .read_for_proposal(&proposal, &request)
        .expect("read");
    assert_eq!(evidence.status, plaid::EvidenceStatus::Ready);
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.transaction_count(), 4);
    assert_eq!(evidence.added_count(), 2);
    assert_eq!(evidence.modified_count(), 1);
    assert_eq!(evidence.removed_count(), 1);
    assert!(
        evidence
            .transactions
            .iter()
            .any(|tx| tx.state == plaid::TransactionState::Pending)
    );
    assert!(
        evidence
            .transactions
            .iter()
            .any(|tx| tx.state == plaid::TransactionState::Posted)
    );
    assert!(
        evidence
            .transactions
            .iter()
            .any(|tx| tx.state == plaid::TransactionState::Modified)
    );
    assert!(
        evidence
            .transactions
            .iter()
            .any(|tx| tx.state == plaid::TransactionState::Removed)
    );
    assert!(evidence.verify_integrity().is_ok());
    assert!(service.verify(&proposal, &evidence).is_ok());

    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].endpoint, "/transactions/sync");
    assert_eq!(requests[0].api_version, "2020-09-14");
    assert_ne!(requests[0].cursor_digest, requests[1].cursor_digest);
}

#[test]
fn pagination_mutation_restarts_from_original_cursor_once() {
    let mutation = json!({
        "error_code": "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION",
        "error_message": "provider detail is not retained"
    })
    .to_string();
    let response = page(
        vec![transaction("tx-1", "acct-1", false, "1.00")],
        vec![],
        vec![],
        "cursor-after-restart",
        false,
    );
    let mut service = fixture_service([
        Ok(plaid::PlaidHttpResponse::json(400, mutation)),
        Ok(plaid::PlaidHttpResponse::json(200, response)),
    ]);
    let request = fixture_request(&service);
    let evidence = service.read(&request).expect("restarted read");
    assert_eq!(evidence.status, plaid::EvidenceStatus::Ready);
    assert_eq!(evidence.restart_count, 1);
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].cursor_digest, requests[1].cursor_digest);
}

#[test]
fn repeated_pagination_mutation_fails_closed() {
    let mutation = json!({
        "error_code": "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION"
    })
    .to_string();
    let mut service = fixture_service([
        Ok(plaid::PlaidHttpResponse::json(400, mutation.clone())),
        Ok(plaid::PlaidHttpResponse::json(400, mutation)),
    ]);
    let request = fixture_request(&service);
    assert!(matches!(
        service.read(&request),
        Err(plaid::PlaidTransactionResultError::PaginationMutationRestartExceeded)
    ));
}

#[test]
fn cursor_loops_count_bounds_and_account_filter_drift_are_rejected() {
    let (scope, _) = scope_and_secret();
    assert!(matches!(
        plaid::TransactionSyncRequest::new(&scope, 501, 1, 1),
        Err(plaid::PlaidTransactionResultError::InvalidField { field: "count", .. })
    ));
    assert!(matches!(
        plaid::TransactionSyncRequest::new(&scope, 1, 65, 1),
        Err(plaid::PlaidTransactionResultError::InvalidField {
            field: "max_pages",
            ..
        })
    ));
    let too_many_accounts = (0..=plaid::MAX_ACCOUNT_FILTERS)
        .map(|index| plaid::Digest::sha256(index.to_string()))
        .collect::<Vec<_>>();
    assert!(matches!(
        plaid::AccountFilter::only(too_many_accounts),
        Err(plaid::PlaidTransactionResultError::AccountFilterLimitExceeded)
    ));

    let loop_page = page(
        vec![transaction("tx-loop", "acct-1", false, "1.00")],
        vec![],
        vec![],
        "",
        true,
    );
    let mut service = fixture_service([Ok(plaid::PlaidHttpResponse::json(200, loop_page))]);
    let request = fixture_request(&service);
    assert!(matches!(
        service.read(&request),
        Err(plaid::PlaidTransactionResultError::CursorLoop)
    ));

    let account = plaid::AccountScope::new("acct-allowed", 1).expect("account");
    let filtered_scope =
        scope.with_account_filter(plaid::AccountFilter::only_accounts([account]).expect("filter"));
    let secret = filtered_scope.secret_reference().clone();
    let provider = plaid::PlaidTransactionsProvider::new(
        plaid::FixturePlaidTransport::new([Ok(plaid::PlaidHttpResponse::json(
            200,
            page(
                vec![transaction("tx-other", "acct-denied", false, "2.00")],
                vec![],
                vec![],
                "cursor-1",
                false,
            ),
        ))]),
        plaid::FixtureSecretResolver::new("fixture").expect("secret"),
    );
    let mut filtered = plaid::PlaidTransactionResultService::new(filtered_scope, secret, provider)
        .expect("filtered service");
    let request = fixture_request(&filtered);
    assert!(matches!(
        filtered.read(&request),
        Err(plaid::PlaidTransactionResultError::ScopeMismatch(_))
    ));
}

#[test]
fn status_states_are_explicit_and_strict_reads_fail_closed() {
    let cases = [
        (401, plaid::EvidenceStatus::AccessLost),
        (403, plaid::EvidenceStatus::AccessLost),
        (404, plaid::EvidenceStatus::AccessLost),
        (409, plaid::EvidenceStatus::Stale),
        (429, plaid::EvidenceStatus::ProviderUnknown),
        (500, plaid::EvidenceStatus::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let mut service = fixture_service([Ok(plaid::PlaidHttpResponse::json(
            status,
            json!({"error_code": "redacted"}).to_string(),
        ))]);
        let request = fixture_request(&service);
        let evidence = service.read(&request).expect("explicit failure evidence");
        assert_eq!(evidence.status, expected);
        assert!(matches!(
            service.read_strict(&request),
            Err(plaid::PlaidTransactionResultError::NonAdoptableState { .. })
        ));
    }

    let mut timeout_service = fixture_service([Err(plaid::PlaidTransportError::Timeout)]);
    let timeout_request = fixture_request(&timeout_service);
    let timeout = timeout_service
        .read(&timeout_request)
        .expect("timeout evidence");
    assert_eq!(timeout.status, plaid::EvidenceStatus::ProviderUnknown);

    let not_ready_page = json!({
        "added": [],
        "modified": [],
        "removed": [],
        "next_cursor": "cursor-not-ready",
        "has_more": false,
        "transactions_update_status": "in_progress"
    })
    .to_string();
    let mut not_ready = fixture_service([Ok(plaid::PlaidHttpResponse::json(200, not_ready_page))]);
    let request = fixture_request(&not_ready);
    assert_eq!(
        not_ready.read(&request).expect("not-ready evidence").status,
        plaid::EvidenceStatus::NotReady
    );

    let mut empty = fixture_service([Ok(plaid::PlaidHttpResponse::json(
        200,
        page(vec![], vec![], vec![], "cursor-empty", false),
    ))]);
    let request = fixture_request(&empty);
    assert_eq!(
        empty.read(&request).expect("empty evidence").status,
        plaid::EvidenceStatus::Empty
    );
}

#[test]
fn partial_page_and_transaction_bounds_are_explicit() {
    let partial = page(
        vec![transaction("tx-partial", "acct-1", false, "1.00")],
        vec![],
        vec![],
        "cursor-more",
        true,
    );
    let mut service = fixture_service([Ok(plaid::PlaidHttpResponse::json(200, partial))]);
    let request = plaid::TransactionSyncRequest::new(service.scope(), 1, 1, 1).expect("bounded");
    let evidence = service.read(&request).expect("partial evidence");
    assert_eq!(evidence.status, plaid::EvidenceStatus::Partial);
    let mut strict_service = fixture_service([Ok(plaid::PlaidHttpResponse::json(
        200,
        page(
            vec![transaction("tx-partial", "acct-1", false, "1.00")],
            vec![],
            vec![],
            "cursor-more",
            true,
        ),
    ))]);
    let strict_request = plaid::TransactionSyncRequest::new(strict_service.scope(), 1, 1, 1)
        .expect("strict bounded request");
    assert!(matches!(
        strict_service.read_strict(&strict_request),
        Err(plaid::PlaidTransactionResultError::NonAdoptableState {
            status: plaid::EvidenceStatus::Partial
        })
    ));
}

#[test]
fn provider_scope_version_and_identity_fences_fail_closed() {
    let (scope, _) = scope_and_secret();
    let request = plaid::TransactionSyncRequest::from_scope(&scope, 1).expect("request");
    for response in [
        plaid::PlaidHttpResponse::json(
            200,
            page(
                vec![transaction("tx-1", "acct-1", false, "1.00")],
                vec![],
                vec![],
                "cursor-1",
                false,
            ),
        )
        .with_scope_digest(plaid::Digest::sha256(b"wrong-scope")),
        plaid::PlaidHttpResponse::json(
            200,
            page(
                vec![transaction("tx-1", "acct-1", false, "1.00")],
                vec![],
                vec![],
                "cursor-1",
                false,
            ),
        )
        .with_api_version("2024-01-01"),
        plaid::PlaidHttpResponse::json(
            200,
            page(
                vec![transaction("tx-1", "acct-1", false, "1.00")],
                vec![],
                vec![],
                "cursor-1",
                false,
            ),
        )
        .with_provider_id("other.provider"),
    ] {
        let secret = scope.secret_reference().clone();
        let provider = plaid::PlaidTransactionsProvider::new(
            plaid::FixturePlaidTransport::new([Ok(response)]),
            plaid::FixtureSecretResolver::new("fixture").expect("secret"),
        );
        let mut service =
            plaid::PlaidTransactionResultService::new(scope.clone(), secret, provider)
                .expect("service");
        assert!(matches!(
            service.read(&request),
            Err(plaid::PlaidTransactionResultError::ProviderScopeDrift
                | plaid::PlaidTransactionResultError::ProviderApiVersionDrift
                | plaid::PlaidTransactionResultError::ProviderIdentityDrift)
        ));
    }
}

#[test]
fn fixture_recording_loopback_and_blocked_env_provenance_is_truthful() {
    let body = page(
        vec![transaction("tx-mode", "acct-1", false, "3.00")],
        vec![],
        vec![],
        "cursor-mode",
        false,
    );
    let (scope, secret) = scope_and_secret();
    let modes = [(
        plaid::TransportMode::Fixture,
        plaid::FixturePlaidTransport::new([Ok(plaid::PlaidHttpResponse::json(200, body.clone()))]),
    )];
    for (mode, transport) in modes {
        let provider = plaid::PlaidTransactionsProvider::new(
            transport,
            plaid::FixtureSecretResolver::new("fixture").expect("secret"),
        );
        let mut service =
            plaid::PlaidTransactionResultService::new(scope.clone(), secret.clone(), provider)
                .expect("service");
        let request = fixture_request(&service);
        let evidence = service.read(&request).expect("mode read");
        assert_eq!(service.evidence_mode(), mode);
        assert_eq!(evidence.provenance, plaid::EvidenceProvenance::Fixture);
        assert!(!evidence.authority.connected);
        assert!(!evidence.authority.native);
    }

    let recording_provider = plaid::PlaidTransactionsProvider::new(
        plaid::RecordingPlaidTransport::new([Ok(plaid::PlaidHttpResponse::json(
            200,
            body.clone(),
        ))]),
        plaid::FixtureSecretResolver::new("recording").expect("secret"),
    );
    let mut recording = plaid::PlaidTransactionResultService::new(
        scope.clone(),
        secret.clone(),
        recording_provider,
    )
    .expect("recording service");
    let request = fixture_request(&recording);
    assert_eq!(
        recording.read(&request).expect("recording read").provenance,
        plaid::EvidenceProvenance::Recording
    );

    let loopback_provider = plaid::PlaidTransactionsProvider::new(
        plaid::LoopbackPlaidTransport::new([Ok(plaid::PlaidHttpResponse::json(200, body))]),
        plaid::FixtureSecretResolver::new("loopback").expect("secret"),
    );
    let mut loopback =
        plaid::PlaidTransactionResultService::new(scope.clone(), secret.clone(), loopback_provider)
            .expect("loopback service");
    let request = fixture_request(&loopback);
    assert_eq!(
        loopback.read(&request).expect("loopback read").provenance,
        plaid::EvidenceProvenance::Loopback
    );

    let blocked_provider = plaid::PlaidTransactionsProvider::new(
        plaid::BlockedEnvPlaidTransport,
        plaid::BlockedEnvSecretResolver,
    );
    let mut blocked = plaid::PlaidTransactionResultService::new(scope, secret, blocked_provider)
        .expect("blocked service");
    let request = fixture_request(&blocked);
    let evidence = blocked.read(&request).expect("blocked evidence");
    assert_eq!(evidence.status, plaid::EvidenceStatus::BlockedEnv);
    assert_eq!(evidence.provenance, plaid::EvidenceProvenance::BlockedEnv);
    assert!(!evidence.authority.connected);
    assert!(!evidence.authority.native);
}

#[test]
fn registration_is_reversible_and_local_recording_is_replay_fenced() {
    let mut service = fixture_service([Ok(plaid::PlaidHttpResponse::json(
        200,
        page(
            vec![transaction("tx-record", "acct-1", false, "4.00")],
            vec![],
            vec![],
            "cursor-record",
            false,
        ),
    ))]);
    let request = fixture_request(&service);
    let proposal = service.compile_result_proposal(&request).expect("proposal");
    let evidence = service
        .read_for_proposal(&proposal, &request)
        .expect("evidence");
    let record = service.record(&proposal, &evidence).expect("record");
    assert!(record.local_only);
    assert!(!record.kernel_receipt);
    assert!(matches!(
        service.record(&proposal, &evidence),
        Err(plaid::PlaidTransactionResultError::ReplayDetected)
    ));

    service
        .revoke_registration(9, plaid::RevocationReason::UserRequested)
        .expect("revoke");
    assert!(!service.is_active());
    assert!(matches!(
        service.read(&request),
        Err(plaid::PlaidTransactionResultError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    assert!(service.is_active());

    service
        .revoke_secret(10, plaid::RevocationReason::SecretRotated)
        .expect("secret revoke");
    assert!(matches!(
        service.read(&request),
        Err(plaid::PlaidTransactionResultError::SecretRevoked)
    ));
    service.restore().expect("secret restore");
}

#[test]
fn mission_consumer_projects_bound_work_product_without_kernel_authority() {
    let mut service = fixture_service([Ok(plaid::PlaidHttpResponse::json(
        200,
        page(
            vec![transaction("tx-consume", "acct-1", false, "5.00")],
            vec![],
            vec![],
            "cursor-consume",
            false,
        ),
    ))]);
    let request = fixture_request(&service);
    let evidence = service.read(&request).expect("evidence");
    let consumer =
        plaid::MissionPlaidTransactionConsumer::new(service.scope().clone()).expect("consumer");
    let proposal = consumer.consume(&evidence).expect("mission proposal");
    consumer
        .verify_proposal(&proposal)
        .expect("proposal verifies");
    assert_eq!(proposal.project_id, "project-1");
    assert_eq!(proposal.mission_id, "mission-1");
    assert_eq!(proposal.work_product_id, "work-product-1");
    assert!(proposal.adoption_candidate);
    assert!(proposal.proposal_only);
    assert!(proposal.non_mutating);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.kernel_authority);
    assert!(!proposal.financial_advice);

    let mut tampered = proposal.clone();
    tampered.evidence_digest = plaid::Digest::sha256(b"tampered");
    assert!(matches!(
        consumer.verify_proposal(&tampered),
        Err(plaid::PlaidTransactionResultError::ProposalTampered)
    ));

    let mut tampered_evidence = evidence;
    tampered_evidence.evidence_digest = plaid::Digest::sha256(b"tampered-evidence");
    assert!(matches!(
        consumer.consume(&tampered_evidence),
        Err(plaid::PlaidTransactionResultError::EvidenceTampered)
    ));
}

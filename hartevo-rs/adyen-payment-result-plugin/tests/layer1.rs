use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
};

use hartevo_adyen_payment_result_plugin::*;

const API_KEY: &str = "adyen-api-key-must-never-escape";

fn digest(seed: u8) -> Digest {
    Digest::from_bytes(&[seed; 16])
}

fn scope() -> AdyenPaymentScope {
    AdyenPaymentScope::from_ids(
        "merchant_1",
        "account_1",
        "PSPREFERENCE01",
        1_250,
        "EUR",
        digest(1),
        "project-1",
        "mission-1",
        "work-product-1",
        2,
        3,
        4,
        AdyenPermissionSnapshot::read_only_default("permissions-r7").expect("permissions"),
    )
    .expect("scope")
}

fn api_record(scope: &AdyenPaymentScope, status: &str) -> AdyenPaymentApiRecord {
    let mut record = AdyenPaymentApiRecord::new(
        scope.merchant_account.as_str(),
        scope.account_id.as_str(),
        scope.payment_reference.as_str(),
        scope.amount.value_minor_units,
        scope.amount.currency.as_str(),
        status,
    );
    record.result_code = Some(match status {
        "Authorised" => "Authorised".to_owned(),
        "Refused" => "Refused".to_owned(),
        "Pending" => "Pending".to_owned(),
        _ => status.to_owned(),
    });
    record.customer_fingerprint_digest = Some(scope.customer_fingerprint.digest().clone());
    record.payment_method_digest = Some(Digest::from_text("scheme"));
    record.created_at = Some("2026-08-15T00:00:00Z".to_owned());
    record.updated_at = Some("2026-08-15T00:01:00Z".to_owned());
    record.reconciliation_reference = Some("reconciliation-1".to_owned());
    record
}

fn registration(scope: &AdyenPaymentScope) -> AdyenPaymentRegistration {
    let secret = SecretReference::for_scope("secret-ref-adyen-test", scope, 9).expect("secret");
    AdyenPaymentRegistration::new(scope.clone(), secret).expect("registration")
}

fn service(
    scope: &AdyenPaymentScope,
    payment_status: &str,
) -> AdyenPaymentResultService<AdyenRecordingTransport, StaticAdyenCredentialResolver> {
    let record = api_record(scope, payment_status);
    let transport = AdyenRecordingTransport::recording(record);
    let provider = AdyenPaymentsProvider::new(
        registration(scope),
        transport,
        StaticAdyenCredentialResolver::new(API_KEY),
    )
    .expect("provider");
    AdyenPaymentResultService::new(provider).expect("service")
}

#[test]
fn authorised_flow_is_bounded_digest_bound_and_mission_scoped() {
    let scope = scope();
    let registration = registration(&scope);
    assert_eq!(registration.api_digest, api_digest());
    assert_eq!(registration.provider_digest, provider_digest());
    assert_eq!(registration.contract_digest, contract_digest());
    let mut service = service(&scope, "Authorised");
    let evidence = service.read_evidence().expect("evidence");
    assert_eq!(evidence.payment.status, AdyenPaymentStatus::Authorised);
    assert_eq!(
        evidence.result_state,
        AdyenPaymentResultState::DecisionReady
    );
    assert!(evidence.is_adoptable());
    assert!(!evidence.native_connected);
    assert!(!evidence.external_effect_performed);
    assert!(!evidence.financial_advice);
    assert!(evidence.idempotency_key.starts_with("hartevo-adyen-"));

    let receipt = service
        .record_payment_receipt(&evidence, 1_000)
        .expect("recording");
    let proposal = service
        .compile_payment_result_proposal(&evidence, &receipt)
        .expect("proposal");
    let verified = service
        .verify_payment_result(&proposal, &evidence, &receipt)
        .expect("verification");
    let read_back = service
        .read_back_and_verify(&evidence)
        .expect("read-back verification");
    read_back.validate().expect("read-back validates");

    let consumer = MissionAdyenPaymentConsumer::from_registration(&registration)
        .expect("consumer from registration");
    let result = consumer.consume_result(&verified).expect("Mission result");
    result.validate().expect("Mission result validates");
    assert!(!result.durable_adoption);
    assert!(!result.kernel_authority);
    assert!(!result.financial_advice);
}

#[test]
fn secret_reference_and_debug_are_opaque_and_registration_serialization_excludes_it() {
    let scope = scope();
    let secret = SecretReference::for_scope("secret-ref-opaque", &scope, 1).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains(API_KEY));
    assert!(!debug.contains("opaque"));
    let registration = AdyenPaymentRegistration::new(scope, secret).expect("registration");
    let serialized = serde_json::to_string(&registration).expect("safe registration JSON");
    assert!(!serialized.contains("secret_reference"));
    assert!(!serialized.contains("secret-ref-opaque"));
    assert!(!serialized.contains(API_KEY));
}

#[test]
fn fixtures_recordings_loopback_and_blocked_env_never_become_native_or_connected() {
    let scope = scope();
    let record = api_record(&scope, "Authorised");
    for transport in [
        AdyenRecordingTransport::recording(record.clone()),
        AdyenRecordingTransport::fake(record.clone()),
        AdyenRecordingTransport::fixture(record.clone()),
        AdyenRecordingTransport::loopback(record.clone()),
    ] {
        let provider = AdyenPaymentsProvider::new(
            registration(&scope),
            transport,
            StaticAdyenCredentialResolver::new(API_KEY),
        )
        .expect("provider");
        assert!(!provider.is_native());
        assert!(!provider.provenance().is_connected());
    }
    let mut blocked = AdyenPaymentResultService::new(
        AdyenPaymentsProvider::new(
            registration(&scope),
            AdyenRecordingTransport::blocked_env(record),
            BlockedEnvCredentialResolver,
        )
        .expect("blocked provider"),
    )
    .expect("blocked service");
    assert_eq!(
        blocked.read_evidence().expect_err("BLOCKED_ENV"),
        AdyenPaymentResultError::BlockedEnv
    );
    assert_eq!(blocked.provider().state(), AdyenProviderState::BlockedEnv);
    assert!(!blocked.provider().is_native());
}

#[test]
fn revocation_fences_provider_and_consumer() {
    let scope = scope();
    let registration = registration(&scope);
    let consumer =
        MissionAdyenPaymentConsumer::from_registration(&registration).expect("active consumer");
    let mut service = service(&scope, "Authorised");
    service.revoke(2_000).expect("revoke");
    assert_eq!(service.provider().state(), AdyenProviderState::Revoked);
    assert_eq!(
        service.read_evidence().expect_err("revoked read"),
        AdyenPaymentResultError::RegistrationRevoked
    );
    let evidence = service
        .provider_mut()
        .registration_mut()
        .registration_digest()
        .clone();
    assert_ne!(evidence, *consumer.registration_digest());
}

#[test]
fn merchant_account_reference_amount_currency_and_customer_drift_fail_closed() {
    let scope = scope();
    for mutation in [
        "merchant",
        "account",
        "reference",
        "amount",
        "currency",
        "customer",
    ] {
        let transport = AdyenRecordingTransport::recording(api_record(&scope, "Authorised"));
        let changed = match mutation {
            "merchant" => {
                let mut record = api_record(&scope, "Authorised");
                record.merchant_account = "merchant-drift".to_owned();
                record
            }
            "account" => {
                let mut record = api_record(&scope, "Authorised");
                record.account_id = "account-drift".to_owned();
                record
            }
            "reference" => {
                let mut record = api_record(&scope, "Authorised");
                record.payment_reference = "PSPREFERENCE02".to_owned();
                record
            }
            "amount" => {
                let mut record = api_record(&scope, "Authorised");
                record.amount_minor_units += 1;
                record
            }
            "currency" => {
                let mut record = api_record(&scope, "Authorised");
                record.currency = "USD".to_owned();
                record
            }
            "customer" => {
                let mut record = api_record(&scope, "Authorised");
                record.customer_fingerprint_digest = Some(digest(8));
                record
            }
            _ => unreachable!(),
        };
        let transport = {
            transport.set_payment(changed.clone());
            transport.set_status(changed);
            transport
        };
        let provider = AdyenPaymentsProvider::new(
            registration(&scope),
            transport,
            StaticAdyenCredentialResolver::new(API_KEY),
        )
        .expect("provider");
        let mut service = AdyenPaymentResultService::new(provider).expect("service");
        let error = service.read_evidence().expect_err("scope drift");
        assert!(
            matches!(
                error,
                AdyenPaymentResultError::MerchantMismatch
                    | AdyenPaymentResultError::AccountMismatch
                    | AdyenPaymentResultError::PaymentReferenceMismatch
                    | AdyenPaymentResultError::AmountMismatch
                    | AdyenPaymentResultError::CurrencyMismatch
                    | AdyenPaymentResultError::CustomerFingerprintMismatch
            ),
            "unexpected {mutation} error: {error:?}"
        );
    }
}

#[test]
fn status_transitions_and_tamper_replay_fail_closed() {
    let scope = scope();
    let transport = AdyenRecordingTransport::recording(api_record(&scope, "Pending"));
    let transport_for_mutation = transport.clone();
    let provider = AdyenPaymentsProvider::new(
        registration(&scope),
        transport,
        StaticAdyenCredentialResolver::new(API_KEY),
    )
    .expect("provider");
    let mut transition_service = AdyenPaymentResultService::new(provider).expect("service");
    let pending = transition_service
        .read_evidence()
        .expect("pending evidence");
    assert_eq!(pending.result_state, AdyenPaymentResultState::Pending);
    transport_for_mutation.set_payment(api_record(&scope, "Authorised"));
    transport_for_mutation.set_status(api_record(&scope, "Authorised"));
    let authorised = transition_service
        .read_evidence()
        .expect("authorised transition");
    assert!(authorised.is_adoptable());
    transport_for_mutation.set_payment(api_record(&scope, "Pending"));
    transport_for_mutation.set_status(api_record(&scope, "Pending"));
    assert_eq!(
        transition_service.read_evidence().expect_err("regression"),
        AdyenPaymentResultError::StatusRegression
    );

    let mut ready_service = service(&scope, "Authorised");
    let evidence = ready_service.read_evidence().expect("evidence");
    let receipt = ready_service
        .record_payment_receipt(&evidence, 3_000)
        .expect("receipt");
    let mut tampered = evidence.clone();
    tampered.payment.status = AdyenPaymentStatus::Refused;
    assert!(tampered.validate().is_err());
    let proposal = ready_service
        .compile_payment_result_proposal(&evidence, &receipt)
        .expect("proposal");
    let mut replay = proposal.clone();
    replay.idempotency_key.push_str("-replay");
    assert!(
        ready_service
            .verify_payment_result(&replay, &evidence, &receipt)
            .is_err()
    );
}

#[test]
fn all_required_http_failures_are_typed_and_body_free() {
    let scope = scope();
    let failures = [
        AdyenPaymentTransportError::Unauthorized,
        AdyenPaymentTransportError::Forbidden,
        AdyenPaymentTransportError::NotFoundOrUnauthorized,
        AdyenPaymentTransportError::NotFound,
        AdyenPaymentTransportError::Conflict,
        AdyenPaymentTransportError::RateLimited {
            retry_after_seconds: Some(3),
        },
        AdyenPaymentTransportError::ServerUnavailable,
        AdyenPaymentTransportError::Timeout,
    ];
    for failure in failures {
        let transport = AdyenRecordingTransport::recording(api_record(&scope, "Authorised"));
        transport.set_fault(failure.clone());
        let provider = AdyenPaymentsProvider::new(
            registration(&scope),
            transport,
            StaticAdyenCredentialResolver::new(API_KEY),
        )
        .expect("provider");
        let mut service = AdyenPaymentResultService::new(provider).expect("service");
        let error = service.read_evidence().expect_err("typed failure");
        assert!(!error.to_string().contains(API_KEY));
        assert!(!error.to_string().contains("raw"));
    }
}

#[test]
fn mutation_surface_is_explicitly_forbidden() {
    let scope = scope();
    let service = service(&scope, "Authorised");
    for operation in [
        "authorise",
        "capture",
        "refund",
        "cancel",
        "webhook registration",
        "payment instrument read",
        "raw customer PII",
        "financial advice",
    ] {
        assert_eq!(
            service.reject_write(operation),
            Err(AdyenPaymentResultError::MutationForbidden { operation })
        );
    }
}

#[test]
fn loopback_transport_uses_api_key_header_and_only_get_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut captured = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("request");
            let mut request = [0_u8; 4096];
            let size = stream.read(&mut request).expect("read request");
            captured.push(String::from_utf8_lossy(&request[..size]).into_owned());
            let body = r#"{"merchantAccount":"merchant_1","accountId":"account_1","reference":"PSPREFERENCE01","amount":{"value":1250,"currency":"EUR"},"status":"Authorised","resultCode":"Authorised","shopperReference":"shopper-1","paymentMethod":{"type":"scheme"}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).expect("response");
        }
        sender.send(captured).expect("captured requests");
    });

    let transport = UreqAdyenTransport::new_loopback(format!("http://{address}"))
        .expect("loopback transport")
        .with_retry_policy(RetryPolicy::new(1, 0).expect("retry policy"));
    let scope = scope();
    let secret = SecretMaterial::new(API_KEY);
    let _ = transport
        .retrieve_payment(&secret, &scope, AdyenPaymentReadMode::PaymentLink)
        .expect("retrieve");
    let _ = transport
        .read_payment_status(&secret, &scope, AdyenPaymentReadMode::Session)
        .expect("status");
    let requests = receiver.recv().expect("requests");
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    assert!(requests.iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains("x-api-key: adyen-api-key-must-never-escape")
    }));
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("authorise") && !request.contains("capture"))
    );
}

use std::fmt::Write as _;

use chrono::{TimeZone, Utc};
use hartevo_xero_accounting_result_plugin::{
    AccountId, BlockedEnvCredentialResolver, BlockedEnvXeroTransport, ContactId, CurrencyCode,
    DateBounds, Digest, EvidenceProvenance, EvidenceStatus, FixtureCredentialResolver,
    FixtureXeroTransport, InvoiceOrBillId, InvoiceOrBillKind, InvoiceOrBillScope, MAX_PAGE_SIZE,
    MAX_PAGES, MAX_RECORDS, MAX_RESPONSE_BYTES, MissionScope, MissionXeroAccountingConsumer,
    OrganisationId, PageBounds, PaymentId, PermissionSnapshot, ProjectScope, ReadBounds, Revision,
    SecretReference, TenantId, UpdatedRevision, WorkProductScope, XeroAccountingContract,
    XeroAccountingError, XeroAccountingResultService, XeroAccountingScope, XeroEndpoint,
    XeroHttpResponse, XeroProvider, XeroReadRequest, XeroTransportError,
};

const INVOICES: &str = include_str!("../fixtures/invoices.json");
const PAYMENTS: &str = include_str!("../fixtures/payments.json");
const CONTACTS: &str = include_str!("../fixtures/contacts.json");

fn fixed_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
        .single()
        .expect("fixed test timestamp")
}

fn scope() -> XeroAccountingScope {
    XeroAccountingScope::new(
        hartevo_xero_accounting_result_plugin::XeroApiHost::xero(),
        TenantId::new("tenant-1").expect("tenant"),
        OrganisationId::new("organisation-1").expect("organisation"),
        ContactId::new("contact-1").expect("contact"),
        InvoiceOrBillScope::new(
            InvoiceOrBillId::new("invoice-1").expect("invoice"),
            InvoiceOrBillKind::Invoice,
        )
        .expect("invoice scope"),
        PaymentId::new("payment-1").expect("payment"),
        AccountId::new("account-1").expect("account"),
        CurrencyCode::new("USD").expect("currency"),
        UpdatedRevision::new("2026-08-10T12:00:00Z").expect("updated revision"),
        MissionScope::new("mission-1", Revision::new(3).expect("mission revision"))
            .expect("mission"),
        ProjectScope::new("project-1", Revision::new(5).expect("project revision"))
            .expect("project"),
        WorkProductScope::new("work-product-1", Revision::new(7).expect("work revision"))
            .expect("work product"),
        PermissionSnapshot::new(true),
    )
    .expect("scope")
}

fn secret(scope: &XeroAccountingScope) -> SecretReference {
    SecretReference::new(
        "fixture-oauth2-handle",
        scope.digest(),
        Revision::new(2).expect("credential revision"),
    )
    .expect("secret reference")
}

fn bounds() -> ReadBounds {
    ReadBounds::new(
        MAX_RESPONSE_BYTES,
        MAX_RECORDS,
        PageBounds::new(MAX_PAGE_SIZE, MAX_PAGES).expect("page bounds"),
    )
    .expect("read bounds")
}

fn request(include_contacts: bool) -> XeroReadRequest {
    XeroReadRequest::new(
        include_contacts,
        DateBounds::new("2026-08-01", "2026-08-31").expect("dates"),
        bounds(),
    )
    .expect("request")
}

fn fixture_service() -> XeroAccountingResultService<FixtureXeroTransport, FixtureCredentialResolver>
{
    let scope = scope();
    let secret = secret(&scope);
    let transport = FixtureXeroTransport::new([
        Ok(XeroHttpResponse::json(200, INVOICES)),
        Ok(XeroHttpResponse::json(200, PAYMENTS)),
        Ok(XeroHttpResponse::json(200, CONTACTS)),
    ]);
    let resolver = FixtureCredentialResolver::new("fixture-bearer-token").expect("resolver");
    XeroAccountingResultService::new(scope, secret, XeroProvider::new(transport, resolver))
        .expect("service")
}

#[test]
fn contract_is_exactly_layer1_read_only_and_native_honest() {
    let contract = XeroAccountingContract::baseline().expect("contract");
    assert_eq!(
        contract.digest(),
        hartevo_xero_accounting_result_plugin::contract_digest()
    );
    assert_eq!(contract.value()["layer"], "Layer-1");
    assert_eq!(contract.value()["api"]["method"], "GET");
    assert_eq!(contract.value()["authority"]["connected"], false);
    assert_eq!(contract.value()["authority"]["native"], false);
    assert!(
        contract.value()["forbidden"]
            .as_array()
            .expect("forbidden list")
            .iter()
            .any(|value| value == "payment_initiation")
    );
}

#[test]
fn exact_scope_digests_and_opaque_secret_reference_are_stable_and_redacted() {
    let scope = scope();
    let first = secret(&scope);
    let second = secret(&scope);
    assert_eq!(scope.digest(), scope.digest());
    assert_eq!(first, second);
    let debug = format!("{first:?} {scope:?}");
    assert!(!debug.contains("fixture-oauth2-handle"));
    assert!(debug.contains("reference_digest"));
    assert_eq!(scope.permission_digest().as_str().len(), 64);
    assert_eq!(scope.revision_digest().as_str().len(), 64);
}

#[test]
fn fixture_read_projects_invoice_payment_account_and_contact_without_authority() {
    let mut service = fixture_service();
    let consumer = MissionXeroAccountingConsumer::new(service.scope().clone());
    let result = consumer
        .read(&mut service, &request(true), fixed_time())
        .expect("fixture read");
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.provenance, EvidenceProvenance::Fixture);
    assert_eq!(result.evidence.invoices.len(), 1);
    assert_eq!(result.evidence.payments.len(), 1);
    assert_eq!(result.evidence.contacts.len(), 1);
    assert!(result.evidence.authority.read_only);
    assert!(!result.evidence.authority.connected);
    assert!(!result.evidence.authority.native);
    assert!(!result.evidence.authority.external_writes);
    assert!(!result.evidence.authority.financial_advice);
    assert!(!result.evidence.authority.kernel_authority);
    assert!(format!("{result:?}").contains("invoice-1"));
    assert!(!format!("{result:?}").contains("BankAccountNumber"));
    assert!(!format!("{result:?}").contains("EmailAddress"));

    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].endpoint, XeroEndpoint::Invoices);
    assert_eq!(
        requests[0].path_and_query().split('?').next(),
        Some("/api.xro/2.0/Invoices")
    );
    assert_eq!(requests[1].endpoint, XeroEndpoint::Payments);
    assert_eq!(requests[2].endpoint, XeroEndpoint::Contacts);
    assert!(
        requests
            .iter()
            .all(|request| request.path_and_query().contains("pageSize=100"))
    );
}

#[test]
fn recording_and_loopback_are_distinct_non_native_evidence_modes() {
    let scope = scope();
    let secret = secret(&scope);
    let resolver = FixtureCredentialResolver::new("fixture-token").expect("resolver");
    let mut recording = XeroAccountingResultService::new(
        scope.clone(),
        secret.clone(),
        XeroProvider::new(
            hartevo_xero_accounting_result_plugin::RecordingXeroTransport::new([
                Ok(XeroHttpResponse::json(200, INVOICES)),
                Ok(XeroHttpResponse::json(200, PAYMENTS)),
            ]),
            resolver,
        ),
    )
    .expect("recording service");
    let recording_evidence = recording
        .read(&request(false), fixed_time())
        .expect("recording");
    assert_eq!(recording_evidence.provenance, EvidenceProvenance::Recording);
    assert!(!recording_evidence.authority.native);
    assert!(!recording_evidence.authority.connected);

    let mut loopback = XeroAccountingResultService::new(
        scope,
        secret,
        XeroProvider::new(
            hartevo_xero_accounting_result_plugin::LoopbackXeroTransport::new([
                Ok(XeroHttpResponse::json(200, INVOICES)),
                Ok(XeroHttpResponse::json(200, PAYMENTS)),
            ]),
            FixtureCredentialResolver::new("fixture-token").expect("resolver"),
        ),
    )
    .expect("loopback service");
    let loopback_evidence = loopback
        .read(&request(false), fixed_time())
        .expect("loopback");
    assert_eq!(loopback_evidence.provenance, EvidenceProvenance::Loopback);
    assert!(!loopback_evidence.authority.native);
    assert!(!loopback_evidence.authority.connected);
}

#[test]
fn blocked_env_is_evidence_not_connected_claim() {
    let scope = scope();
    let secret = secret(&scope);
    let mut service = XeroAccountingResultService::new(
        scope.clone(),
        secret,
        XeroProvider::new(BlockedEnvXeroTransport, BlockedEnvCredentialResolver),
    )
    .expect("blocked service");
    let evidence = service
        .read(&request(false), fixed_time())
        .expect("blocked evidence");
    assert_eq!(evidence.status, EvidenceStatus::BlockedEnv);
    assert_eq!(evidence.provenance, EvidenceProvenance::BlockedEnv);
    assert!(!evidence.authority.connected);
    assert!(!evidence.authority.native);
    let consumer = MissionXeroAccountingConsumer::new(scope);
    consumer.consume(evidence).expect("blocked observation");
}

#[test]
fn stale_revision_currency_access_loss_tamper_and_revocation_fail_closed() {
    let scope = scope();
    let secret = secret(&scope);
    let stale = PAYMENTS.replace("2026-08-10T12:00:00Z", "2026-08-11T12:00:00Z");
    let mut stale_service = XeroAccountingResultService::new(
        scope.clone(),
        secret.clone(),
        XeroProvider::new(
            FixtureXeroTransport::new([
                Ok(XeroHttpResponse::json(200, INVOICES)),
                Ok(XeroHttpResponse::json(200, &stale)),
            ]),
            FixtureCredentialResolver::new("token").expect("resolver"),
        ),
    )
    .expect("stale service");
    assert!(matches!(
        stale_service.read(&request(false), fixed_time()),
        Err(XeroAccountingError::UpdatedRevisionMismatch)
    ));

    let currency = PAYMENTS.replace("\"USD\"", "\"EUR\"");
    let mut currency_service = XeroAccountingResultService::new(
        scope.clone(),
        secret.clone(),
        XeroProvider::new(
            FixtureXeroTransport::new([
                Ok(XeroHttpResponse::json(200, INVOICES)),
                Ok(XeroHttpResponse::json(200, &currency)),
            ]),
            FixtureCredentialResolver::new("token").expect("resolver"),
        ),
    )
    .expect("currency service");
    assert!(matches!(
        currency_service.read(&request(false), fixed_time()),
        Err(XeroAccountingError::CurrencyMismatch { .. })
    ));

    let mut access_service = XeroAccountingResultService::new(
        scope.clone(),
        secret.clone(),
        XeroProvider::new(
            FixtureXeroTransport::new([
                Ok(XeroHttpResponse::json(403, "{}")),
                Ok(XeroHttpResponse::json(200, PAYMENTS)),
            ]),
            FixtureCredentialResolver::new("token").expect("resolver"),
        ),
    )
    .expect("access service");
    assert!(matches!(
        access_service.read(&request(false), fixed_time()),
        Err(XeroAccountingError::AccessLost)
    ));

    let mut good_service = fixture_service();
    let mut evidence = good_service
        .read(&request(true), fixed_time())
        .expect("good evidence");
    evidence.provider_digest = Digest::from_bytes(b"tampered");
    let consumer = MissionXeroAccountingConsumer::new(scope.clone());
    assert!(matches!(
        consumer.consume(evidence),
        Err(XeroAccountingError::EvidenceTampered | XeroAccountingError::StaleEvidence)
    ));

    let mut revoked = fixture_service();
    revoked
        .revoke_registration(Revision::new(8).expect("revocation revision"))
        .expect("revoke");
    assert!(matches!(
        revoked.read(&request(true), fixed_time()),
        Err(XeroAccountingError::RegistrationRevoked)
    ));
    let mut secret_revoked = fixture_service();
    secret_revoked
        .revoke_secret(Revision::new(9).expect("secret revocation revision"))
        .expect("revoke secret");
    assert!(matches!(
        secret_revoked.read(&request(true), fixed_time()),
        Err(XeroAccountingError::SecretRevoked)
    ));
}

#[test]
fn bounds_and_endpoint_allowlist_reject_unbounded_requests() {
    assert!(DateBounds::new("2025-01-01", "2027-01-01").is_err());
    assert!(PageBounds::new(MAX_PAGE_SIZE + 1, 1).is_err());
    assert!(PageBounds::new(1, MAX_PAGES + 1).is_err());
    assert!(ReadBounds::new(MAX_RESPONSE_BYTES + 1, 1, PageBounds::default()).is_err());
    assert!(ReadBounds::new(MAX_RESPONSE_BYTES, MAX_RECORDS + 1, PageBounds::default()).is_err());
    let request = request(true);
    assert_eq!(
        request.endpoints(),
        vec![
            XeroEndpoint::Invoices,
            XeroEndpoint::Payments,
            XeroEndpoint::Contacts
        ]
    );
    assert!(
        XeroEndpoint::Invoices
            .allowlisted_fields()
            .contains(&"InvoiceID")
    );
    assert!(
        XeroEndpoint::Payments
            .allowlisted_fields()
            .contains(&"PaymentID")
    );
    assert!(
        XeroEndpoint::Contacts
            .allowlisted_fields()
            .contains(&"ContactID")
    );
}

#[test]
fn response_fences_reject_provider_api_scope_and_permission_drift() {
    let scope = scope();
    let secret = secret(&scope);
    let bad_revision =
        XeroHttpResponse::json(200, INVOICES).with_api_revision("xero-accounting-api-2.0-r2");
    let mut service = XeroAccountingResultService::new(
        scope.clone(),
        secret.clone(),
        XeroProvider::new(
            FixtureXeroTransport::new([
                Ok(bad_revision),
                Ok(XeroHttpResponse::json(200, PAYMENTS)),
            ]),
            FixtureCredentialResolver::new("token").expect("resolver"),
        ),
    )
    .expect("revision service");
    assert!(matches!(
        service.read(&request(false), fixed_time()),
        Err(XeroAccountingError::ProviderRevisionDrift)
    ));

    let wrong_scope = Digest::from_bytes(b"wrong-scope");
    let bad_scope =
        XeroHttpResponse::json(200, INVOICES).with_fences(wrong_scope, scope.permission_digest());
    let mut service = XeroAccountingResultService::new(
        scope.clone(),
        secret,
        XeroProvider::new(
            FixtureXeroTransport::new([Ok(bad_scope), Ok(XeroHttpResponse::json(200, PAYMENTS))]),
            FixtureCredentialResolver::new("token").expect("resolver"),
        ),
    )
    .expect("scope service");
    assert!(matches!(
        service.read(&request(false), fixed_time()),
        Err(XeroAccountingError::ScopeMismatch(_))
    ));
}

#[test]
fn transport_debug_and_error_do_not_retain_provider_payload_or_bearer() {
    let response = XeroHttpResponse::json(200, "{\"secret\":\"payload\"}");
    assert!(!format!("{response:?}").contains("payload"));
    let error = XeroTransportError::Transport("provider body is redacted".to_owned());
    assert!(format!("{error}").contains("redacted"));
    let mut text = String::new();
    write!(&mut text, "{response:?}").expect("debug formatting");
    assert!(!text.contains("secret"));
}

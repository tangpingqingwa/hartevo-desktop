use serde_json::json;

use hartevo_coda_structured_result_plugin as coda;

const SECRET_REFERENCE: &str = "opaque-api-token-reference-not-token-material";
const RAW_PAGE_TOKEN: &str = "opaque-page-token-with-private-cursor";
const RAW_RICH_TEXT: &str = "private rich text must never cross Layer 1";
const RAW_PII: &str = "person@example.invalid";

fn scope() -> coda::CodaStructuredResultScope {
    coda::CodaStructuredResultScope::new(
        coda::CodaWorkspaceId::new("workspace-1").expect("workspace"),
        coda::CodaDocId::new("doc-1").expect("doc"),
        vec![coda::CodaPageId::new("page-1").expect("page")],
        vec![coda::CodaTableId::new("table-1").expect("table")],
        vec![coda::CodaViewId::new("view-1").expect("view")],
        vec![coda::CodaRowId::new("row-1").expect("row")],
        vec![coda::CodaColumnId::new("column-1").expect("column")],
        coda::Revision::new(7).expect("revision"),
        coda::Project::new("project-1", 2).expect("Project"),
        coda::Mission::new("mission-1", 3).expect("Mission"),
        coda::WorkProduct::new("work-product-1", 4).expect("Work Product"),
    )
    .expect("scope")
}

fn secret() -> coda::SecretReference {
    coda::SecretReference::new(SECRET_REFERENCE, 9).expect("opaque secret reference")
}

fn document_payload() -> serde_json::Value {
    json!({
        "id": "doc-1",
        "type": "doc",
        "name": "Confidential launch decision",
        "revision": 7,
        "createdAt": "2026-08-14T10:00:00Z",
        "updatedAt": "2026-08-15T10:00:00Z",
        "owner": {"name": "Private Person", "email": RAW_PII},
        "content": RAW_RICH_TEXT,
        "formula": "Rows.Filter(...)",
        "values": {"c-secret": RAW_PII}
    })
}

fn response(status: u16, payload: &serde_json::Value) -> coda::CodaResponse {
    coda::CodaResponse::json(status, payload)
}

fn fixture_service(
    response: coda::CodaResponse,
) -> coda::CodaStructuredResultService<coda::FixtureCodaTransport> {
    let provider =
        coda::CodaProvider::new(scope(), secret(), coda::FixtureCodaTransport::new(response))
            .expect("provider");
    coda::CodaStructuredResultService::new(provider).expect("service")
}

#[test]
fn bounded_fixture_read_is_redacted_and_digest_bound() {
    let mut service = fixture_service(response(200, &document_payload()));
    let evidence = service.read_doc_metadata(1).expect("doc metadata");
    assert_eq!(evidence.state, coda::CodaEvidenceState::Present);
    assert_eq!(evidence.metadata.len(), 1);
    assert!(evidence.is_present());
    assert_eq!(
        evidence.revision_digest,
        coda::Revision::new(7).unwrap().digest()
    );
    assert!(!evidence.native && !evidence.connected && !evidence.first_party);
    assert!(evidence.redacted);
    assert!(!evidence.raw_rich_text_retained);
    assert!(!evidence.raw_pii_retained);
    assert!(!evidence.formula_executed);

    let proposal = service.compile_proposal(&evidence).expect("proposal");
    assert!(proposal.proposal_only && proposal.read_only && proposal.adoptable);
    assert!(!proposal.native && !proposal.connected && !proposal.first_party);
    assert_eq!(proposal.evidence.digest(), &evidence.evidence_digest);
    assert_eq!(proposal.idempotency_key.len(), 64);
    assert_eq!(proposal.digest().len(), 64);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{evidence:?} {proposal:?} {service:?}");
    for forbidden in [SECRET_REFERENCE, RAW_PAGE_TOKEN, RAW_RICH_TEXT, RAW_PII] {
        assert!(
            !serialized.contains(forbidden),
            "serialized leaked {forbidden}"
        );
        assert!(!debug.contains(forbidden), "Debug leaked {forbidden}");
    }
    assert!(!serialized.contains("Rows.Filter"));
}

#[test]
fn all_truthful_transport_provenances_are_not_connected_native_or_first_party() {
    let payload = document_payload();
    let transports: Vec<(&str, Box<dyn coda::CodaTransport>)> = vec![
        (
            "fixture",
            Box::new(coda::FixtureCodaTransport::new(response(200, &payload))),
        ),
        (
            "recording",
            Box::new(coda::RecordingCodaTransport::new(response(200, &payload))),
        ),
        (
            "fake",
            Box::new(coda::FakeCodaTransport::new(response(200, &payload))),
        ),
        (
            "loopback",
            Box::new(coda::LoopbackCodaTransport::new(response(200, &payload))),
        ),
        (
            "BLOCKED_ENV",
            Box::new(coda::BlockedEnvCodaTransport::new()),
        ),
    ];
    for (name, transport) in transports {
        let provenance = transport.provenance();
        assert!(!provenance.is_native(), "{name} claimed native");
        assert!(!provenance.is_connected(), "{name} claimed connected");
        assert!(!provenance.is_first_party(), "{name} claimed first party");
    }

    let provider = coda::CodaProvider::new(scope(), secret(), coda::BlockedEnvCodaTransport::new())
        .expect("blocked provider construction");
    let mut service = coda::CodaStructuredResultService::new(provider).expect("service");
    let evidence = service.read_doc_metadata(1).expect("blocked evidence");
    assert_eq!(evidence.state, coda::CodaEvidenceState::Denied);
    assert_eq!(
        evidence.classification,
        coda::CodaEvidenceClassification::BlockedEnv
    );
    assert_eq!(
        evidence.provenance,
        coda::CodaTransportProvenance::BlockedEnv
    );
    assert!(!evidence.native && !evidence.connected && !evidence.first_party);
}

#[test]
fn typed_statuses_never_become_present_evidence() {
    let cases = [
        (403, coda::CodaEvidenceState::Denied),
        (404, coda::CodaEvidenceState::Denied),
        (429, coda::CodaEvidenceState::RateLimited),
        (500, coda::CodaEvidenceState::ProviderUnknown),
        (400, coda::CodaEvidenceState::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let mut service = fixture_service(response(
            status,
            &json!({"message": RAW_RICH_TEXT, "email": RAW_PII}),
        ));
        let evidence = service.read_doc_metadata(1).expect("typed status evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.is_present());
        assert!(evidence.metadata.is_empty());
        let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
        assert!(!serialized.contains(RAW_RICH_TEXT));
        assert!(!serialized.contains(RAW_PII));
    }

    let mut service = fixture_service(response(200, &json!({"items": []})));
    assert_eq!(
        service.read_doc_metadata(1).expect("empty evidence").state,
        coda::CodaEvidenceState::Empty
    );
    let mut service = fixture_service(response(
        206,
        &json!({"partial": true, "items": [{"id": "doc-1", "revision": 7}]}),
    ));
    assert_eq!(
        service
            .read_doc_metadata(1)
            .expect("partial evidence")
            .state,
        coda::CodaEvidenceState::Partial
    );
}

#[test]
fn scope_revision_and_page_token_fences_fail_closed() {
    let scope = scope();
    assert!(
        coda::CodaReadRequest::new(
            &scope,
            coda::CodaReadOperation::PageMetadata,
            "page-not-allowlisted",
            1,
            None,
        )
        .is_err()
    );
    assert!(coda::CodaReadRequest::doc(&scope, 0).is_err());
    assert!(coda::CodaReadRequest::doc(&scope, coda::MAX_PAGE_SIZE + 1).is_err());

    let mut service = fixture_service(response(
        200,
        &json!({"id": "doc-1", "revision": 8, "name": "drifted"}),
    ));
    assert_eq!(
        service
            .read_doc_metadata(1)
            .expect_err("revision drift")
            .to_string(),
        "Coda provider error: Coda Doc revision drifted"
    );

    let mut service = fixture_service(coda::CodaResponse::json_with_page_token(
        200,
        &json!({
            "items": [{"id": "page-1", "name": "bounded page", "revision": 7}],
            "nextPageToken": RAW_PAGE_TOKEN
        }),
        RAW_PAGE_TOKEN,
    ));
    let page = coda::CodaPageId::new("page-1").expect("page");
    let first = service
        .read_page_metadata(&page, 1, None)
        .expect("first page");
    let token = first.next_page_token.clone().expect("opaque token");
    assert_eq!(token.page_number(), 1);
    assert_eq!(token.operation(), coda::CodaReadOperation::PageMetadata);
    assert!(!format!("{token:?}").contains(RAW_PAGE_TOKEN));
    assert!(
        !serde_json::to_string(&token)
            .expect("token JSON")
            .contains(RAW_PAGE_TOKEN)
    );
    let second = service.read_page_metadata(&page, 1, Some(token));
    assert!(matches!(
        second,
        Err(coda::CodaStructuredResultError::Provider(
            coda::CodaProviderError::PageTokenLoop
        ))
    ));
}

#[test]
fn tamper_idempotency_replay_and_reversible_revocation_are_fenced() {
    let response = response(200, &document_payload());
    let provider = coda::CodaProvider::new(
        scope(),
        secret(),
        coda::RecordingCodaTransport::new(response),
    )
    .expect("provider");
    let mut service = coda::CodaStructuredResultService::new(provider).expect("service");
    let evidence = service.read_doc_metadata(1).expect("evidence");
    let proposal = service.compile_proposal(&evidence).expect("proposal");
    let mut tampered = proposal.clone();
    tampered.state = coda::CodaEvidenceState::Denied;
    assert!(matches!(
        service.verify_proposal(&tampered),
        Err(coda::CodaStructuredResultError::Tampered)
    ));

    let first_receipt = service.record_proposal(&proposal).expect("record");
    let second_receipt = service
        .record_proposal(&proposal)
        .expect("idempotent record");
    assert_eq!(first_receipt, second_receipt);
    assert!(!first_receipt.durable_provider_receipt);
    assert!(!first_receipt.native && !first_receipt.connected);

    let mut consumer = coda::MissionCodaStructuredConsumer::new(service);
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(result.state, coda::CodaEvidenceState::Present);
    assert!(result.proposal_only);
    assert!(!result.adopts_outcome && !result.adopts_work_product);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(coda::MissionCodaStructuredConsumerError::ReplayDetected)
    ));

    let old_registration = consumer
        .service()
        .registration()
        .registration_digest
        .clone();
    let revocation = consumer.revoke().expect("revoke");
    assert!(revocation.revoked);
    assert_ne!(revocation.registration_digest, old_registration);
    assert!(matches!(
        consumer.service_mut().read_doc_metadata(1),
        Err(coda::CodaStructuredResultError::RegistrationRevoked)
    ));
    consumer.restore().expect("restore");
    let new_evidence = consumer
        .service_mut()
        .read_doc_metadata(1)
        .expect("read after restore");
    assert_ne!(
        new_evidence.registration_digest, proposal.registration_digest,
        "registration rotation must fence old evidence"
    );
    assert!(matches!(
        consumer.consume(&proposal),
        Err(coda::MissionCodaStructuredConsumerError::ScopeMismatch)
    ));
}

#[test]
fn rate_limit_receipt_and_secret_are_bounded() {
    let rate = coda::CodaRateLimitReceipt::new(60, Some(0), Some(30), true).expect("rate");
    let response = coda::CodaResponse::new(
        429,
        br#"{"message":"too many requests","email":"person@example.invalid"}"#.to_vec(),
        rate,
    );
    let mut service = fixture_service(response);
    let evidence = service.read_doc_metadata(1).expect("rate evidence");
    assert_eq!(evidence.state, coda::CodaEvidenceState::RateLimited);
    assert!(evidence.rate_limit.throttled);
    assert_eq!(evidence.rate_limit.retry_after_seconds, Some(30));
    assert!(
        !serde_json::to_string(&evidence)
            .expect("rate evidence JSON")
            .contains("too many requests")
    );

    let secret = secret();
    let serialized = serde_json::to_string(&secret).expect("secret JSON");
    let debug = format!("{secret:?}");
    assert!(serialized.contains("referenceDigest"));
    assert!(!serialized.contains(SECRET_REFERENCE));
    assert!(!debug.contains(SECRET_REFERENCE));
    assert!(coda::CodaRateLimitReceipt::new(61, None, None, false).is_err());
    assert!(coda::CodaRateLimitReceipt::new(60, None, Some(3_601), false).is_err());
}

#[test]
fn contract_and_provider_definitions_freeze_layer_one_boundary() {
    coda::CodaStructuredResultContract::baseline()
        .expect("contract validation")
        .validate()
        .expect("contract remains valid");
    coda::CodaProviderDefinition::layer1()
        .validate()
        .expect("provider definition");
    coda::CodaStructuredResultServiceDefinition::layer1()
        .validate()
        .expect("service definition");
    assert_eq!(
        coda::CODA_API_REFERENCE_URL,
        "https://coda.io/developers/apis/v1"
    );
    assert!(!coda::Layer1Authority::connected());
    assert!(!coda::Layer1Authority::native());
    assert!(!coda::Layer1Authority::first_party());
}

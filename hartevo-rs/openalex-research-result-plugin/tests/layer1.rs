use hartevo_openalex_research_result_plugin as openalex;
use serde_json::{Value, json};

fn work(id: &str, title: &str) -> Value {
    json!({
        "id": id,
        "doi": format!("https://doi.org/10.1000/{id}"),
        "title": title,
        "abstract_inverted_index": {"private abstract": [0]},
        "type": "article",
        "publication_year": 2024,
        "cited_by_count": 7,
        "referenced_works": ["https://openalex.org/WREF1", "https://openalex.org/WREF2"],
        "authorships": [
            {
                "author": {"id": "https://openalex.org/A1", "display_name": "Private Author"},
                "institutions": [{"id": "https://openalex.org/I1"}]
            }
        ],
        "concepts": [{"id": "https://openalex.org/C1", "display_name": "Private Concept"}]
    })
}

fn scope() -> openalex::OpenAlexResearchScope {
    openalex::OpenAlexResearchScope::from_ids(
        "project-728",
        "mission-728",
        "work-product-728",
        openalex::OpenAlexQuery::search_with_filter(
            openalex::OpenAlexEntity::Work,
            "private scholarly query",
            "publication_year:2024",
        )
        .expect("query"),
        2,
        7,
        openalex::ConsentScope::new("bounded research evidence review", 3).expect("consent"),
    )
    .expect("scope")
}

fn response(results: Vec<Value>, count: u64) -> openalex::OpenAlexResponse {
    openalex::OpenAlexResponse::json(
        200,
        &openalex::OpenAlexFixturePayload::results(count, results),
    )
}

fn service_with_scope<T: openalex::OpenAlexTransport>(
    scope: openalex::OpenAlexResearchScope,
    transport: T,
) -> openalex::OpenAlexResearchResultService<T> {
    let provider = openalex::OpenAlexProvider::new(
        scope,
        openalex::OpenAlexPermission::metadata_read(4).expect("permission"),
        openalex::SecretReference::new("opaque-openalex-api-key-handle").expect("secret"),
        transport,
    )
    .expect("provider");
    openalex::OpenAlexResearchResultService::new(provider).expect("service")
}

fn service<T: openalex::OpenAlexTransport>(
    transport: T,
) -> openalex::OpenAlexResearchResultService<T> {
    service_with_scope(scope(), transport)
}

#[test]
fn contract_is_valid_and_layer_one_authority_is_false() {
    openalex::validate_contract().expect("contract validation");
    assert_eq!(
        openalex::OPENALEX_RESEARCH_RESULT_CONTRACT_PATH,
        "contracts/plugins/openalex-research-result/openalex-research-result.v1.json"
    );
    assert!(!openalex::Layer1Authority::connected());
    assert!(!openalex::Layer1Authority::native_provider());
    assert!(!openalex::Layer1Authority::durable_receipt());
    assert!(!openalex::Layer1Authority::ranking_authority());
    assert!(!openalex::Layer1Authority::full_text_authority());
    assert!(!openalex::Layer1Authority::citation_truth_authority());
    assert!(!openalex::Layer1Authority::research_truth_authority());
}

#[test]
fn work_evidence_is_redacted_deterministic_and_idempotent() {
    let mut first = service(openalex::FixtureOpenAlexTransport::new(response(
        vec![
            work("https://openalex.org/W2", "Second private title"),
            work("https://openalex.org/W1", "First private title"),
        ],
        2,
    )));
    let mut second = service(openalex::FixtureOpenAlexTransport::new(response(
        vec![
            work("https://openalex.org/W1", "First private title"),
            work("https://openalex.org/W2", "Second private title"),
        ],
        2,
    )));

    let proposal_a = first.compile_proposal().expect("proposal A");
    let proposal_b = second.compile_proposal().expect("proposal B");
    assert_eq!(proposal_a, proposal_b);
    assert_eq!(
        proposal_a.evidence.state,
        openalex::OpenAlexEvidenceState::Complete
    );
    assert_eq!(proposal_a.evidence.returned_results, 2);
    assert!(proposal_a.proposal_only);
    assert!(!proposal_a.native && !proposal_a.connected);
    assert!(!proposal_a.ranking_claim && !proposal_a.full_text);
    assert!(!proposal_a.author_identity_claim);
    assert!(!proposal_a.citation_truth_claim && !proposal_a.research_truth_claim);
    first
        .verify_proposal(&proposal_a)
        .expect("proposal verifies");

    let receipt_a = first
        .record_observation_receipt(&proposal_a)
        .expect("receipt A");
    let receipt_b = first
        .record_observation_receipt(&proposal_a)
        .expect("receipt B");
    assert_eq!(receipt_a, receipt_b);
    assert_eq!(receipt_a.idempotency_digest, proposal_a.idempotency_digest);
    assert!(!receipt_a.connected && !receipt_a.native && !receipt_a.durable_native_receipt);

    let serialized = serde_json::to_string(&proposal_a).expect("proposal serializes");
    for forbidden in [
        "opaque-openalex-api-key-handle",
        "private scholarly query",
        "publication_year:2024",
        "First private title",
        "Second private title",
        "private abstract",
        "Private Author",
        "Private Concept",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
    let secret = openalex::SecretReference::new("opaque-openalex-api-key-handle").expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-openalex-api-key-handle"));
    assert!(debug.contains("reference_digest"));
}

#[test]
fn entity_and_citation_scopes_use_only_fixed_get_paths() {
    let entity_cases = [
        (
            openalex::OpenAlexEntity::Author,
            json!({
                "meta": {"count": 1, "next_cursor": null},
                "results": [{"id": "https://openalex.org/A1", "display_name": "Private Author", "works_count": 12, "cited_by_count": 20, "affiliations": [{"institution": {"id": "I1"}}]}]
            }),
            "/authors",
        ),
        (
            openalex::OpenAlexEntity::Institution,
            json!({
                "meta": {"count": 1, "next_cursor": null},
                "results": [{"id": "https://openalex.org/I1", "display_name": "Private Institution", "ror": "https://ror.org/secret", "country_code": "US", "works_count": 10, "cited_by_count": 30}]
            }),
            "/institutions",
        ),
        (
            openalex::OpenAlexEntity::Concept,
            json!({
                "meta": {"count": 1, "next_cursor": null},
                "results": [{"id": "https://openalex.org/C1", "display_name": "Private Concept", "works_count": 10, "cited_by_count": 30, "level": 1}]
            }),
            "/concepts",
        ),
    ];
    for (entity, body, expected_path) in entity_cases {
        let query = openalex::OpenAlexQuery::search(entity, "bounded selector").expect("query");
        let entity_scope = openalex::OpenAlexResearchScope::from_ids(
            "project-728",
            "mission-728",
            "work-product-728",
            query,
            2,
            1,
            openalex::ConsentScope::new("metadata", 1).expect("consent"),
        )
        .expect("scope");
        let mut service = service_with_scope(
            entity_scope,
            openalex::RecordingOpenAlexTransport::new(openalex::OpenAlexResponse::json(200, &body)),
        );
        let _ = service.read().expect("read");
        let request = &service.provider().transport().requests()[0];
        assert_eq!(request.path_template, expected_path);
        assert!(request.is_allowlisted());
        let request_json = serde_json::to_string(request).expect("request serializes");
        assert!(!request_json.contains("bounded selector"));
        assert!(!request_json.contains("Private"));
    }

    let citation_scope = openalex::OpenAlexResearchScope::from_ids(
        "project-728",
        "mission-728",
        "work-product-728",
        openalex::OpenAlexQuery::citations(
            openalex::OpenAlexCitationDirection::Cites,
            "https://openalex.org/WTARGET",
        )
        .expect("citation query"),
        2,
        1,
        openalex::ConsentScope::new("citation metadata", 1).expect("consent"),
    )
    .expect("citation scope");
    let mut citation_service = service_with_scope(
        citation_scope,
        openalex::FixtureOpenAlexTransport::new(response(
            vec![work("https://openalex.org/WCITING", "citation result")],
            1,
        )),
    );
    let evidence = citation_service.read().expect("citation read");
    assert_eq!(evidence.citations.len(), 1);
    assert_eq!(
        evidence.citations[0].cited_work_digest,
        openalex::sha256_digest(b"https://openalex.org/WTARGET")
    );
    assert!(evidence.citations[0].provider_reported_only);
    let request = citation_service
        .provider()
        .build_request()
        .expect("request");
    assert_eq!(request.path_template, "/works?filter=cites:{id}");
}

#[test]
fn cursor_is_bound_to_query_and_scope_revision_and_next_cursor_is_redacted() {
    let base = scope();
    let wrong_query =
        openalex::OpenAlexCursor::new("opaque-next", openalex::sha256_digest(b"other"), 7)
            .expect("wrong query cursor");
    assert!(base.with_cursor(wrong_query).is_err());
    let wrong_revision = openalex::OpenAlexCursor::new("opaque-next", base.query().digest(), 8)
        .expect("wrong revision cursor");
    assert!(base.with_cursor(wrong_revision).is_err());

    let cursor = openalex::OpenAlexCursor::for_scope("opaque-next-cursor", &base).expect("cursor");
    let cursor_scope = base.with_cursor(cursor).expect("bound cursor scope");
    let mut service = service_with_scope(
        cursor_scope,
        openalex::FixtureOpenAlexTransport::new(openalex::OpenAlexResponse::json(
            200,
            &openalex::OpenAlexFixturePayload::results(
                2,
                vec![work("https://openalex.org/W1", "one")],
            )
            .with_next_cursor("opaque-server-next-cursor"),
        )),
    );
    let evidence = service.read().expect("cursor read");
    assert!(evidence.cursor_digest.is_some());
    assert!(evidence.next_cursor.is_some());
    assert_eq!(evidence.state, openalex::OpenAlexEvidenceState::Partial);
    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("opaque-next-cursor"));
    assert!(!serialized.contains("opaque-server-next-cursor"));
}

#[test]
fn status_matrix_rate_limit_malformed_oversize_and_blocked_env_fail_closed() {
    for (status, expected) in [
        (401, openalex::OpenAlexEvidenceState::AccessLost),
        (403, openalex::OpenAlexEvidenceState::AccessLost),
        (404, openalex::OpenAlexEvidenceState::Empty),
        (429, openalex::OpenAlexEvidenceState::RateLimited),
        (500, openalex::OpenAlexEvidenceState::ProviderUnknown),
    ] {
        let body = json!({"message": "private provider diagnostic", "query": "private query"});
        let response = if status == 429 {
            openalex::OpenAlexResponse::json_with_rate_limit(
                status,
                &body,
                openalex::RateLimitReceipt::throttled(30),
            )
        } else {
            openalex::OpenAlexResponse::json(status, &body)
        };
        let mut service = service(openalex::FixtureOpenAlexTransport::new(response));
        let evidence = service.read().expect("status becomes typed evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.read_receipt.connected && !evidence.read_receipt.native);
        let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
        assert!(!serialized.contains("private provider diagnostic"));
        assert!(!serialized.contains("private query"));
    }

    let mut malformed = service(openalex::FixtureOpenAlexTransport::new(
        openalex::OpenAlexResponse::new(
            200,
            b"not-json".to_vec(),
            openalex::RateLimitReceipt::default(),
        ),
    ));
    assert_eq!(
        malformed.read().expect("malformed evidence").state,
        openalex::OpenAlexEvidenceState::MalformedResponse
    );

    let mut oversized = service(openalex::FixtureOpenAlexTransport::new(
        openalex::OpenAlexResponse::new(
            200,
            vec![b'x'; openalex::MAX_RESPONSE_BYTES + 1],
            openalex::RateLimitReceipt::default(),
        ),
    ));
    assert_eq!(
        oversized.read().expect("oversized evidence").state,
        openalex::OpenAlexEvidenceState::ResponseTooLarge
    );

    let mut blocked = service(openalex::BlockedEnvOpenAlexTransport);
    let blocked_evidence = blocked.read().expect("blocked evidence");
    assert_eq!(
        blocked_evidence.state,
        openalex::OpenAlexEvidenceState::BlockedEnv
    );
    assert_eq!(
        blocked_evidence.read_receipt.provenance,
        openalex::TransportProvenance::BlockedEnv
    );
    assert!(!blocked_evidence.read_receipt.connected && !blocked_evidence.read_receipt.native);
}

#[test]
fn registration_consent_and_secret_fences_are_reversible_and_digest_bound() {
    let response = response(vec![work("https://openalex.org/W1", "one")], 1);
    let mut service = service(openalex::FixtureOpenAlexTransport::new(response));
    let original_registration = service.registration().registration_digest.clone();
    let proposal = service.compile_proposal().expect("proposal");
    assert!(matches!(
        service.compile_proposal_with_consent(
            &openalex::ConsentScope::new("different purpose", 1).expect("other consent")
        ),
        Err(openalex::OpenAlexResearchResultServiceError::ConsentMismatch)
    ));

    let revoked = service.revoke_registration().expect("revoke");
    assert!(revoked.reversible);
    assert_ne!(revoked.registration_digest, original_registration);
    assert!(matches!(
        service.read(),
        Err(openalex::OpenAlexResearchResultServiceError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    assert!(service.verify_proposal(&proposal).is_err());

    let fresh = service.compile_proposal().expect("fresh proposal");
    service
        .provider_mut()
        .revoke_secret()
        .expect("revoke secret");
    assert!(matches!(
        service.read(),
        Err(openalex::OpenAlexResearchResultServiceError::SecretRevoked)
    ));
    service
        .provider_mut()
        .restore_secret()
        .expect("restore secret");
    assert!(service.compile_proposal().is_ok());
    assert_ne!(proposal.proposal_digest, fresh.proposal_digest);
}

#[test]
fn mission_consumer_enforces_scope_authority_tamper_and_replay_fences() {
    let mut service = service(openalex::FakeOpenAlexTransport::new(response(
        vec![work("https://openalex.org/W1", "one")],
        1,
    )));
    let proposal = service.compile_proposal().expect("proposal");
    let mut consumer = openalex::MissionOpenAlexResearchConsumer::new(service.scope());
    let result = consumer.consume(&proposal).expect("mission projection");
    assert_eq!(result.state, openalex::MissionResultState::Complete);
    assert_eq!(result.idempotency_digest, proposal.idempotency_digest);
    assert!(!result.connected && !result.native);
    assert!(!result.adopts_outcome && !result.adopts_work_product);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(openalex::MissionOpenAlexResearchConsumerError::ReplayDetected)
    ));

    let mut authority_tampered = proposal.clone();
    authority_tampered.ranking_claim = true;
    assert!(matches!(
        consumer.consume(&authority_tampered),
        Err(openalex::MissionOpenAlexResearchConsumerError::AuthorityClaim)
    ));

    let mut digest_tampered = proposal.clone();
    digest_tampered.proposal_digest = openalex::sha256_digest(b"tampered");
    assert!(matches!(
        consumer.consume(&digest_tampered),
        Err(openalex::MissionOpenAlexResearchConsumerError::ProposalTampered)
    ));
}

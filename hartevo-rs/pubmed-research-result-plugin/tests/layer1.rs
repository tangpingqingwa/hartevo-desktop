use hartevo_pubmed_research_result_plugin::{
    BlockedEnvNcbiEutilsTransport, ConsentScope, FakeNcbiEutilsTransport,
    FixtureNcbiEutilsTransport, LoopbackNcbiEutilsTransport, MissionPubMedResearchConsumer,
    NcbiEutilsProvider, PubMedEvidenceState, PubMedPermission, PubMedQuery,
    PubMedResearchResultService, PubMedResearchResultServiceError, PubMedResearchScope,
    PubMedResponse, RateLimitReceipt, RecordingNcbiEutilsTransport, SecretReference,
    TransportProvenance,
};

fn scope(max_results: usize) -> PubMedResearchScope {
    scope_for_query(
        PubMedQuery::search("bounded biomedical publication evidence").expect("query"),
        max_results,
    )
}

fn scope_for_query(query: PubMedQuery, max_results: usize) -> PubMedResearchScope {
    PubMedResearchScope::from_ids(
        "project-734",
        "mission-734",
        "work-product-734",
        query,
        max_results,
        1,
        ConsentScope::new("research metadata review", 1).expect("consent"),
    )
    .expect("scope")
}

fn esearch_response(status: u16, ids: &[&str], count: u64) -> PubMedResponse {
    PubMedResponse::json(
        status,
        &serde_json::json!({
            "esearchresult": {
                "count": count.to_string(),
                "retstart": "0",
                "retmax": ids.len().to_string(),
                "idlist": ids,
                "webenv": "opaque-web-environment",
                "querykey": "1"
            }
        }),
    )
}

fn service<T: hartevo_pubmed_research_result_plugin::NcbiEutilsTransport>(
    transport: T,
    max_results: usize,
) -> PubMedResearchResultService<T> {
    service_for_query(
        transport,
        PubMedQuery::search("bounded biomedical publication evidence").expect("query"),
        max_results,
    )
}

fn service_for_query<T: hartevo_pubmed_research_result_plugin::NcbiEutilsTransport>(
    transport: T,
    query: PubMedQuery,
    max_results: usize,
) -> PubMedResearchResultService<T> {
    let provider = NcbiEutilsProvider::new(
        scope_for_query(query, max_results),
        PubMedPermission::metadata_read(1).expect("permission"),
        SecretReference::new("opaque-ncbi-reference").expect("secret reference"),
        transport,
    )
    .expect("provider");
    PubMedResearchResultService::new(provider).expect("service")
}

#[test]
fn all_allowlisted_eutilities_project_metadata_only() {
    let summary = PubMedResponse::json(
        200,
        &serde_json::json!({
            "result": {
                "uids": ["19393038"],
                "19393038": {
                    "uid": "19393038",
                    "pmc": "PMC123456",
                    "title": "A bounded metadata title",
                    "pubdate": "2020 Jan",
                    "source": "A journal",
                    "authors": [{"name": "Author"}],
                    "meshheadinglist": [{"meshheading": "Biomedical Research"}]
                }
            }
        }),
    );
    let mut summary_service = service_for_query(
        FixtureNcbiEutilsTransport::new(summary),
        PubMedQuery::summary("19393038").expect("summary query"),
        1,
    );
    let summary_evidence = summary_service.read().expect("summary evidence");
    assert_eq!(summary_evidence.state, PubMedEvidenceState::Complete);
    assert!(summary_evidence.articles[0].pmcid_digest.is_some());
    assert!(summary_evidence.articles[0].title_digest.is_some());
    assert_eq!(summary_evidence.articles[0].mesh_term_digests.len(), 1);

    let fetch = PubMedResponse::json(
        200,
        &serde_json::json!({
            "articles": [{
                "pmid": "19393038",
                "pmcid": "PMC123456",
                "title": "A metadata-only fetch",
                "publication_year": 2020,
                "journal": "A journal",
                "mesh_terms": ["Biomedical Research"]
            }]
        }),
    );
    let mut fetch_service = service_for_query(
        FixtureNcbiEutilsTransport::new(fetch),
        PubMedQuery::fetch_metadata("19393038").expect("fetch query"),
        1,
    );
    let fetch_evidence = fetch_service.read().expect("fetch evidence");
    assert_eq!(fetch_evidence.state, PubMedEvidenceState::Complete);
    assert_eq!(fetch_evidence.articles.len(), 1);

    let link = PubMedResponse::json(
        200,
        &serde_json::json!({
            "linksets": [{
                "ids": ["19393038"],
                "linksetdbs": [{
                    "dbto": "pmc",
                    "linkname": "pubmed_pmc",
                    "links": ["PMC123456"]
                }]
            }]
        }),
    );
    let mut link_service = service_for_query(
        FixtureNcbiEutilsTransport::new(link),
        PubMedQuery::link("19393038").expect("link query"),
        1,
    );
    let link_evidence = link_service.read().expect("link evidence");
    assert_eq!(link_evidence.state, PubMedEvidenceState::Complete);
    assert_eq!(link_evidence.links.len(), 1);
    assert!(link_evidence.links.iter().all(|link| {
        !serde_json::to_string(link)
            .expect("link JSON")
            .contains("19393038")
    }));
}

#[test]
fn fixture_result_is_redacted_deterministic_and_mission_projectable() {
    let mut first = service(
        FixtureNcbiEutilsTransport::new(esearch_response(200, &["30242208", "19393038"], 2)),
        2,
    );
    let mut second = service(
        FixtureNcbiEutilsTransport::new(esearch_response(200, &["19393038", "30242208"], 2)),
        2,
    );

    let proposal_a = first.compile_proposal().expect("proposal A");
    let proposal_b = second.compile_proposal().expect("proposal B");
    assert_eq!(proposal_a, proposal_b);
    assert!(proposal_a.proposal_only);
    assert!(!proposal_a.native);
    assert!(!proposal_a.connected);
    assert!(!proposal_a.first_party);
    assert_eq!(proposal_a.evidence.returned_results, 2);
    first
        .verify_proposal(&proposal_a)
        .expect("proposal verifies");

    let receipt_a = first.record_receipt(&proposal_a).expect("receipt A");
    let receipt_b = first.record_receipt(&proposal_a).expect("receipt B");
    assert_eq!(receipt_a, receipt_b);
    assert!(!receipt_a.connected);
    assert!(!receipt_a.native);
    assert!(!receipt_a.first_party);
    assert!(!receipt_a.durable_native_receipt);

    let result = MissionPubMedResearchConsumer::new(first.scope())
        .consume(&proposal_a)
        .expect("mission projection");
    assert_eq!(result.article_digests.len(), 2);
    assert_eq!(result.result_digests.len(), 2);
    assert!(!result.adopts_outcome);
    assert!(!result.adopts_work_product);
}

#[test]
fn fixture_recording_fake_loopback_and_blocked_env_never_claim_native_connection() {
    let mut recording = service(
        RecordingNcbiEutilsTransport::new(esearch_response(200, &["19393038"], 1)),
        1,
    );
    let recording_proposal = recording.compile_proposal().expect("recording proposal");
    assert_eq!(
        recording_proposal.evidence.read_receipt.provenance,
        TransportProvenance::Recording
    );
    assert!(!recording_proposal.evidence.read_receipt.connected);
    assert!(!recording_proposal.evidence.read_receipt.native);
    assert_eq!(recording.provider().transport().requests().len(), 1);

    let mut fake = service(
        FakeNcbiEutilsTransport::new(esearch_response(200, &["19393038"], 1)),
        1,
    );
    let fake_proposal = fake.compile_proposal().expect("fake proposal");
    assert_eq!(
        fake_proposal.evidence.read_receipt.provenance,
        TransportProvenance::Fake
    );

    let mut loopback = service(
        LoopbackNcbiEutilsTransport::new(esearch_response(200, &["19393038"], 1)),
        1,
    );
    let loopback_proposal = loopback.compile_proposal().expect("loopback proposal");
    assert_eq!(
        loopback_proposal.evidence.read_receipt.provenance,
        TransportProvenance::Loopback
    );
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);
    assert!(!loopback_proposal.first_party);

    let mut blocked = service(BlockedEnvNcbiEutilsTransport, 1);
    let blocked_evidence = blocked.read().expect("blocked evidence is typed");
    assert_eq!(blocked_evidence.state, PubMedEvidenceState::BlockedEnv);
    assert_eq!(
        blocked_evidence.read_receipt.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(!blocked_evidence.read_receipt.connected);
    assert!(!blocked_evidence.read_receipt.native);
    assert!(!blocked_evidence.read_receipt.first_party);
    let blocked_proposal = blocked
        .compile_proposal()
        .expect("blocked proposal remains typed");
    blocked
        .verify_proposal(&blocked_proposal)
        .expect("blocked proposal verifies");
}

#[test]
fn rate_limit_partial_denied_empty_and_malformed_are_explicit_states() {
    let rate_limit = RateLimitReceipt::new(Some(50), Some(0), Some(30), true).expect("rate");
    let mut rate_limited = service(
        FixtureNcbiEutilsTransport::new(PubMedResponse::json_with_rate_limit(
            429,
            &serde_json::json!({"error": "rate limited"}),
            rate_limit,
        )),
        1,
    );
    let rate_evidence = rate_limited.read().expect("rate evidence");
    assert_eq!(rate_evidence.state, PubMedEvidenceState::RateLimited);
    assert!(rate_evidence.rate_limit.throttled);
    assert_eq!(rate_evidence.rate_limit.retry_after_seconds, Some(30));

    let mut partial = service(
        FixtureNcbiEutilsTransport::new(esearch_response(
            200,
            &["19393038", "30242208", "99999999"],
            3,
        )),
        1,
    );
    let partial_evidence = partial.read().expect("partial evidence");
    assert_eq!(partial_evidence.state, PubMedEvidenceState::Partial);
    assert_eq!(partial_evidence.returned_results, 1);
    assert_eq!(partial_evidence.total_results, Some(3));

    let mut denied = service(
        FixtureNcbiEutilsTransport::new(PubMedResponse::new(
            403,
            b"denied".to_vec(),
            RateLimitReceipt::default(),
        )),
        1,
    );
    assert_eq!(
        denied.read().expect("denied evidence").state,
        PubMedEvidenceState::Denied
    );

    let mut empty = service(
        FixtureNcbiEutilsTransport::new(esearch_response(200, &[], 0)),
        1,
    );
    assert_eq!(
        empty.read().expect("empty evidence").state,
        PubMedEvidenceState::Empty
    );

    let mut malformed = service(
        FixtureNcbiEutilsTransport::new(PubMedResponse::new(
            200,
            b"not-json".to_vec(),
            RateLimitReceipt::default(),
        )),
        1,
    );
    let malformed_evidence = malformed.read().expect("malformed evidence");
    assert_eq!(
        malformed_evidence.state,
        PubMedEvidenceState::MalformedResponse
    );
    assert_eq!(malformed_evidence.returned_results, 0);
}

#[test]
fn cursor_and_history_binding_reject_replay_and_cross_scope_use() {
    let response = esearch_response(200, &["19393038"], 2);
    let mut first = service(FixtureNcbiEutilsTransport::new(response.clone()), 1);
    let cursor =
        hartevo_pubmed_research_result_plugin::OpaqueCursor::new("retstart:1").expect("cursor");
    let history =
        hartevo_pubmed_research_result_plugin::OpaqueHistory::new("opaque-web-environment", "1")
            .expect("history");
    let first_evidence = first
        .read_with_page(Some(cursor.clone()), Some(history.clone()))
        .expect("first page");
    assert_eq!(first_evidence.state, PubMedEvidenceState::Partial);
    let replay = first.read_with_page(Some(cursor), Some(history));
    assert!(matches!(
        replay,
        Ok(evidence) if evidence.state == PubMedEvidenceState::Tamper
    ));

    let mut other = service(FixtureNcbiEutilsTransport::new(response), 1);
    let wrong_history =
        hartevo_pubmed_research_result_plugin::OpaqueHistory::new("different-web-environment", "1")
            .expect("wrong history");
    let result = other.read_with_page(
        Some(
            hartevo_pubmed_research_result_plugin::OpaqueCursor::new("retstart:1").expect("cursor"),
        ),
        Some(wrong_history),
    );
    assert!(result.is_ok());
    assert_eq!(
        result.expect("typed evidence").state,
        PubMedEvidenceState::Partial
    );
}

#[test]
fn tamper_scope_revocation_restore_and_opaque_secret_fail_closed() {
    let mut scoped_service = service(
        FixtureNcbiEutilsTransport::new(esearch_response(200, &["19393038"], 1)),
        1,
    );
    let proposal = scoped_service.compile_proposal().expect("proposal");

    let mut tampered = proposal.clone();
    tampered.native = true;
    assert!(matches!(
        scoped_service.verify_proposal(&tampered),
        Err(PubMedResearchResultServiceError::ProposalMismatch)
    ));

    scoped_service
        .provider_mut()
        .set_scope(scope(2))
        .expect("scope replacement");
    assert!(matches!(
        scoped_service.read(),
        Err(PubMedResearchResultServiceError::ScopeMismatch)
    ));

    let mut revocable = service(
        FixtureNcbiEutilsTransport::new(esearch_response(200, &["19393038"], 1)),
        1,
    );
    let old_registration = revocable.registration().registration_digest.clone();
    let old_proposal = revocable.compile_proposal().expect("old proposal");
    let transition = revocable
        .revoke_registration()
        .expect("revoke registration");
    assert!(transition.reversible);
    assert!(matches!(
        revocable.read(),
        Err(PubMedResearchResultServiceError::RegistrationRevoked)
    ));
    revocable
        .restore_registration()
        .expect("restore registration");
    assert_ne!(
        old_registration,
        revocable.registration().registration_digest
    );
    assert!(revocable.verify_proposal(&old_proposal).is_err());
    let new_proposal = revocable.compile_proposal().expect("new proposal");
    assert_ne!(old_proposal.proposal_digest, new_proposal.proposal_digest);

    let secret = SecretReference::new("do-not-print-this-value").expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("do-not-print-this-value"));
    assert!(debug.contains("reference_digest"));
    assert!(secret.is_opaque());
}

#[test]
fn contract_and_request_fences_are_stable() {
    hartevo_pubmed_research_result_plugin::validate_contract().expect("contract");
    let scope = scope(1);
    let provider = NcbiEutilsProvider::new(
        scope,
        PubMedPermission::metadata_read(1).expect("permission"),
        SecretReference::new("opaque-ncbi-reference").expect("secret"),
        FixtureNcbiEutilsTransport::new(esearch_response(200, &["19393038"], 1)),
    )
    .expect("provider");
    let request = provider.build_request().expect("request");
    assert!(request.is_allowlisted());
    assert_eq!(request.request_digest, request.digest());
    assert_eq!(request.idempotency_digest, request.idempotency_digest());
    assert!(!format!("{request:?}").contains("opaque-ncbi-reference"));
}

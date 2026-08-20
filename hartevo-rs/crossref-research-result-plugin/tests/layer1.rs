use hartevo_crossref_research_result_plugin::{
    BlockedEnvCrossrefTransport, ConsentScope, CrossrefFixtureAuthor, CrossrefFixturePayload,
    CrossrefFixtureWork, CrossrefPermission, CrossrefProvider, CrossrefQuery,
    CrossrefResearchResultService, CrossrefResearchResultServiceError, CrossrefResearchScope,
    CrossrefResponse, FixtureCrossrefTransport, LoopbackCrossrefTransport, MAX_RESULTS,
    MissionCrossrefResearchConsumer, RateLimitReceipt, RecordingCrossrefTransport, SecretReference,
    TransportProvenance,
};

fn scope(max_results: usize) -> CrossrefResearchScope {
    CrossrefResearchScope::from_ids(
        "project-699",
        "mission-699",
        "work-product-699",
        CrossrefQuery::search("bounded scholarly metadata").expect("query"),
        max_results,
        1,
        ConsentScope::new("research metadata review", 1).expect("consent"),
    )
    .expect("scope")
}

fn fixture_work(doi: &str) -> CrossrefFixtureWork {
    let mut work = CrossrefFixtureWork::minimal(doi);
    work.title = vec!["A bounded research result".to_owned()];
    work.author = vec![CrossrefFixtureAuthor::default()];
    work.reference_count = Some(4);
    work.cited_by_count = Some(2);
    work.container_title = vec!["A journal".to_owned()];
    work
}

fn response(total_results: u64, dois: &[&str]) -> CrossrefResponse {
    CrossrefResponse::json(
        200,
        &CrossrefFixturePayload::works(
            total_results,
            dois.iter().map(|doi| fixture_work(doi)).collect(),
        ),
    )
}

fn service<T: hartevo_crossref_research_result_plugin::CrossrefTransport>(
    transport: T,
    max_results: usize,
) -> CrossrefResearchResultService<T> {
    let provider = CrossrefProvider::new(
        scope(max_results),
        CrossrefPermission::metadata_read(1).expect("permission"),
        SecretReference::new("opaque-crossref-reference").expect("secret reference"),
        transport,
    )
    .expect("provider");
    CrossrefResearchResultService::new(provider).expect("service")
}

#[test]
fn fixture_result_is_redacted_deterministic_and_mission_projectable() {
    let mut first = service(
        FixtureCrossrefTransport::new(response(2, &["10.1000/second", "10.1000/first"])),
        2,
    );
    let mut second = service(
        FixtureCrossrefTransport::new(response(2, &["10.1000/first", "10.1000/second"])),
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

    let result = MissionCrossrefResearchConsumer::new(first.scope())
        .consume(&proposal_a)
        .expect("mission projection");
    assert_eq!(result.work_digests.len(), 2);
    assert!(!result.adopts_outcome);
    assert!(!result.adopts_work_product);
}

#[test]
fn recording_loopback_and_blocked_env_never_claim_native_connection() {
    let mut recording = service(
        RecordingCrossrefTransport::new(response(1, &["10.1000/recorded"])),
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

    let mut loopback = service(
        LoopbackCrossrefTransport::new(response(1, &["10.1000/loopback"])),
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

    let mut blocked = service(BlockedEnvCrossrefTransport, 1);
    let blocked_evidence = blocked.read().expect("blocked evidence is typed");
    assert_eq!(
        blocked_evidence.state,
        hartevo_crossref_research_result_plugin::CrossrefEvidenceState::BlockedEnv
    );
    assert_eq!(
        blocked_evidence.read_receipt.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(!blocked_evidence.read_receipt.connected);
    assert!(!blocked_evidence.read_receipt.native);
    assert!(!blocked_evidence.read_receipt.first_party);
}

#[test]
fn rate_limit_and_partial_results_are_explicit_bounded_states() {
    let rate_limit = RateLimitReceipt::new(Some(50), Some(0), Some(30), true).expect("rate");
    let mut rate_limited = service(
        FixtureCrossrefTransport::new(CrossrefResponse::json_with_rate_limit(
            429,
            &serde_json::json!({"message": "rate limited"}),
            rate_limit,
        )),
        1,
    );
    let rate_evidence = rate_limited.read().expect("rate evidence");
    assert_eq!(
        rate_evidence.state,
        hartevo_crossref_research_result_plugin::CrossrefEvidenceState::RateLimited
    );
    assert!(rate_evidence.rate_limit.throttled);
    assert_eq!(rate_evidence.rate_limit.retry_after_seconds, Some(30));

    let mut partial = service(
        FixtureCrossrefTransport::new(response(
            3,
            &["10.1000/one", "10.1000/two", "10.1000/three"],
        )),
        1,
    );
    let partial_evidence = partial.read().expect("partial evidence");
    assert_eq!(
        partial_evidence.state,
        hartevo_crossref_research_result_plugin::CrossrefEvidenceState::Partial
    );
    assert_eq!(partial_evidence.returned_results, 1);
    assert_eq!(partial_evidence.total_results, Some(3));
    assert!(partial_evidence.works.len() <= MAX_RESULTS);
}

#[test]
fn tamper_stale_scope_revocation_and_restore_fail_closed() {
    let mut scope_service = service(
        FixtureCrossrefTransport::new(response(1, &["10.1000/stable"])),
        1,
    );
    let proposal = scope_service.compile_proposal().expect("proposal");

    let mut tampered = proposal.clone();
    tampered.native = true;
    assert!(matches!(
        scope_service.verify_proposal(&tampered),
        Err(CrossrefResearchResultServiceError::ProposalMismatch)
    ));

    scope_service
        .provider_mut()
        .set_scope(scope(2))
        .expect("scope replacement");
    assert!(matches!(
        scope_service.read(),
        Err(CrossrefResearchResultServiceError::ScopeMismatch)
    ));

    let mut restored_service = service(
        FixtureCrossrefTransport::new(response(1, &["10.1000/revocable"])),
        1,
    );
    let old_proposal = restored_service.compile_proposal().expect("old proposal");
    let transition = restored_service
        .revoke_registration()
        .expect("revoke registration");
    assert!(transition.reversible);
    assert!(matches!(
        restored_service.read(),
        Err(CrossrefResearchResultServiceError::RegistrationRevoked)
    ));
    restored_service
        .restore_registration()
        .expect("restore registration");
    assert!(restored_service.verify_proposal(&old_proposal).is_err());
    let new_proposal = restored_service.compile_proposal().expect("new proposal");
    assert_ne!(old_proposal.proposal_digest, new_proposal.proposal_digest);
}

#[test]
fn secret_reference_is_opaque_in_debug_and_malformed_response_is_not_success() {
    let secret = SecretReference::new("do-not-print-this-value").expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("do-not-print-this-value"));
    assert!(debug.contains("reference_digest"));

    let mut malformed = service(
        FixtureCrossrefTransport::new(CrossrefResponse::new(
            200,
            b"not-json".to_vec(),
            RateLimitReceipt::default(),
        )),
        1,
    );
    let evidence = malformed.read().expect("malformed is typed evidence");
    assert_eq!(
        evidence.state,
        hartevo_crossref_research_result_plugin::CrossrefEvidenceState::MalformedResponse
    );
    assert_eq!(evidence.returned_results, 0);
}

#[test]
fn registration_binds_permission_secret_and_contract_and_secret_revocation_is_fail_closed() {
    let mut service = service(
        FixtureCrossrefTransport::new(response(1, &["10.1000/bound"])),
        1,
    );
    let original_registration = service.registration().registration_digest.clone();
    service
        .provider_mut()
        .revoke_secret()
        .expect("revoke secret reference");
    assert!(matches!(
        service.read(),
        Err(CrossrefResearchResultServiceError::SecretRevoked)
    ));
    service
        .provider_mut()
        .restore_secret()
        .expect("restore secret reference");
    assert_eq!(
        original_registration,
        service.registration().registration_digest
    );

    service.provider_mut().registration_mut().contract_digest =
        hartevo_crossref_research_result_plugin::sha256_digest(b"tampered");
    assert!(matches!(
        service.read(),
        Err(CrossrefResearchResultServiceError::RegistrationDrift)
    ));
}

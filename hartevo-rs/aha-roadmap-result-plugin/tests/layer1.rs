use hartevo_aha_roadmap_result_plugin as aha;
use serde_json::{Value, json};

fn scope() -> aha::AhaRoadmapScope {
    let spec = aha::AhaRoadmapScopeSpec::new(
        aha::AccountId::new("account-1").expect("account"),
        aha::WorkspaceId::new("workspace-1").expect("workspace"),
        aha::ProductLineId::new("product-line-1").expect("product line"),
        aha::InitiativeId::new("initiative-1").expect("initiative"),
        aha::ReleaseId::new("release-1").expect("release"),
        aha::FeatureId::new("feature-1").expect("feature"),
        aha::RequirementId::new("requirement-1").expect("requirement"),
        aha::ProjectBinding::new("project-1", 2).expect("project"),
        aha::MissionBinding::new("mission-1", 3).expect("mission"),
        aha::WorkProductBinding::new("work-product-1", 4).expect("work product"),
        aha::AhaPermissionSnapshot::read_only(5).expect("permissions"),
        7,
    )
    .expect("scope spec");
    aha::AhaRoadmapScope::new(spec).expect("scope")
}

fn secret() -> aha::SecretReference {
    aha::SecretReference::api_token("actual-api-token-must-not-escape", 6).expect("secret")
}

fn release_payload(revision: u64, id: &str) -> Value {
    json!({
        "id": id,
        "name": "Private release title",
        "description": "Private roadmap description",
        "url": "https://account-1.aha.io/releases/release-1",
        "status": {"name": "In progress"},
        "revision": revision,
        "children": [{"id": "private-child"}]
    })
}

fn fixture_service(
    response: aha::AhaResponse,
) -> aha::AhaRoadmapResultService<aha::FixtureAhaTransport> {
    let provider =
        aha::AhaRoadmapProvider::new(scope(), secret(), aha::FixtureAhaTransport::new(response))
            .expect("provider");
    aha::AhaRoadmapResultService::new(provider).expect("service")
}

fn release_request(
    service: &aha::AhaRoadmapResultService<aha::FixtureAhaTransport>,
    key: &str,
) -> aha::AhaRoadmapRequest {
    aha::AhaRoadmapRequest::release(
        service.scope(),
        &aha::IdempotencyKey::new(key).expect("idempotency key"),
    )
    .expect("release request")
}

#[test]
fn contract_scope_and_registration_are_machine_bound() {
    let provider = aha::AhaRoadmapProvider::new(
        scope(),
        secret(),
        aha::LoopbackAhaTransport::new(aha::AhaResponse::json(
            200,
            &release_payload(7, "release-1"),
        )),
    )
    .expect("provider");
    assert_eq!(
        provider.registration().permission_digest,
        provider.scope().permission_digest()
    );
    assert_eq!(
        provider.registration().scope_digest,
        *provider.scope().scope_digest()
    );
    assert_eq!(
        provider.registration().revision_digest,
        *provider.scope().revision_digest()
    );
    assert_eq!(provider.registration().evidence_digest.len(), 64);
    assert!(provider.registration().reversible);
    assert!(provider.registration().revocable);
    assert_eq!(provider.definition().provider_id, aha::AHA_PROVIDER_ID);
    assert!(!provider.definition().connected);
    assert!(!provider.definition().native);
    assert!(!provider.definition().first_party);

    for provenance in [
        aha::AhaTransportProvenance::Fixture,
        aha::AhaTransportProvenance::Recording,
        aha::AhaTransportProvenance::Fake,
        aha::AhaTransportProvenance::Loopback,
        aha::AhaTransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

#[test]
fn release_read_is_redacted_bounded_and_idempotently_replayable() {
    let mut service = fixture_service(aha::AhaResponse::json(
        200,
        &release_payload(7, "release-1"),
    ));
    let request = release_request(&service, "release-read-1");
    let proposal = service.propose(&request).expect("proposal");

    assert_eq!(proposal.state(), aha::AhaEvidenceState::Complete);
    let evidence = proposal.evidence();
    assert_eq!(evidence.aggregate().expect("aggregate").item_count, 1);
    assert_eq!(
        evidence.aggregate().expect("aggregate").items[0].child_count,
        1
    );
    assert!(evidence.redactions.is_complete());
    assert!(!evidence.connected);
    assert!(!evidence.native_provider);
    assert!(!evidence.first_party);
    assert!(!evidence.durable_provider_receipt);
    assert!(!evidence.kernel_authority);
    assert!(!proposal.work_product_adopted);

    let encoded = serde_json::to_string(&proposal).expect("proposal serializes");
    for forbidden in [
        "actual-api-token-must-not-escape",
        "Private release title",
        "Private roadmap description",
        "private-child",
        "https://account-1.aha.io/releases/release-1",
    ] {
        assert!(!encoded.contains(forbidden), "leaked {forbidden}");
    }
    assert!(!format!("{service:?}").contains("actual-api-token-must-not-escape"));
    assert!(
        !format!("{:?}", service.provider().transport()).contains("Private roadmap description")
    );

    let replay = service.propose(&request).expect("replay");
    assert!(replay.replayed);
    assert_eq!(replay.proposal_digest, proposal.proposal_digest);
    assert_eq!(replay.evidence_digest, proposal.evidence_digest);
}

#[test]
fn recording_transport_is_get_only_and_exactly_scoped() {
    let provider = aha::AhaRoadmapProvider::new(
        scope(),
        secret(),
        aha::RecordingAhaTransport::new(aha::AhaResponse::json(
            200,
            &release_payload(7, "release-1"),
        )),
    )
    .expect("provider");
    let mut service = aha::AhaRoadmapResultService::new(provider).expect("service");
    let request = aha::AhaRoadmapRequest::release(
        service.scope(),
        &aha::IdempotencyKey::new("recording-read").expect("key"),
    )
    .expect("request");
    service.read_request(&request).expect("read");
    let recorded = &service.provider().transport().requests()[0];
    assert_eq!(recorded.method, aha::AhaHttpMethod::Get);
    assert_eq!(recorded.path, "/api/v1/releases/release-1");
    assert!(recorded.is_allowlisted());
    assert!(recorded.path.contains("/releases/"));
    assert!(!recorded.path.contains("update"));
    assert!(!recorded.path.contains("delete"));
    assert!(
        !serde_json::to_string(recorded)
            .expect("recorded request serializes")
            .contains("actual-api-token-must-not-escape")
    );
}

#[test]
fn cursor_is_opaque_and_bound_to_the_exact_request_fence() {
    let payload = json!({
        "items": [release_payload(7, "release-1")],
        "total": 2,
        "next_page_token": "opaque-next-page-token"
    });
    let mut service = fixture_service(aha::AhaResponse::json(200, &payload));
    let first = release_request(&service, "cursor-first")
        .with_page_size(10)
        .expect("first page size");
    let first_evidence = service.read_request(&first).expect("first page");
    let aggregate = first_evidence.aggregate().expect("aggregate");
    let cursor_digest = aggregate
        .next_page_token_digest
        .clone()
        .expect("next cursor digest");
    let binding = aggregate
        .cursor_binding_digest
        .clone()
        .expect("cursor binding");
    let cursor = aha::OpaquePageToken::from_digest(cursor_digest.clone(), Some(binding.clone()))
        .expect("opaque cursor");
    assert_eq!(cursor.digest(), &cursor_digest);
    assert_eq!(cursor.binding_digest(), Some(&binding));

    let second = aha::AhaRoadmapRequest::release(
        service.scope(),
        &aha::IdempotencyKey::new("cursor-second").expect("key"),
    )
    .expect("second request")
    .with_page_size(10)
    .expect("page size")
    .with_page_token(&cursor);
    service.read_request(&second).expect("bound second page");

    let mut tampered_value = serde_json::to_value(&second).expect("request value");
    tampered_value["cursorBindingDigest"] = Value::String("a".repeat(64));
    let tampered: aha::AhaRoadmapRequest = serde_json::from_value(tampered_value)
        .expect("tampered request remains syntactically typed");
    assert!(matches!(
        service.read_request(&tampered),
        Err(aha::AhaRoadmapResultServiceError::ScopeMismatch)
    ));

    let raw_cursor = aha::OpaquePageToken::new("raw-cursor-material").expect("raw cursor");
    let bound_request = aha::AhaRoadmapRequest::release(
        service.scope(),
        &aha::IdempotencyKey::new("cursor-auto-bind").expect("key"),
    )
    .expect("request")
    .with_page_token(&raw_cursor);
    let binding_digest = bound_request.cursor_binding_digest();
    assert_eq!(bound_request.cursor_binding(), Some(&binding_digest));
}

#[test]
fn response_scope_revision_and_malformed_body_fail_closed_without_raw_material() {
    let mut wrong_revision = fixture_service(aha::AhaResponse::json(
        200,
        &release_payload(8, "release-1"),
    ));
    let request = release_request(&wrong_revision, "wrong-revision");
    assert!(matches!(
        wrong_revision.read_request(&request),
        Err(aha::AhaRoadmapResultServiceError::RevisionMismatch)
    ));

    let mut wrong_scope = fixture_service(aha::AhaResponse::json(
        200,
        &release_payload(7, "release-outside-scope"),
    ));
    let request = release_request(&wrong_scope, "wrong-scope");
    let error = wrong_scope.read_request(&request).expect_err("scope drift");
    assert!(matches!(
        error,
        aha::AhaRoadmapResultServiceError::EvidenceTampered
    ));
    assert!(!error.to_string().contains("release-outside-scope"));

    let provider = aha::AhaRoadmapProvider::new(
        scope(),
        secret(),
        aha::FixtureAhaTransport::new(aha::AhaResponse::new(
            200,
            b"not-json-private-response".to_vec(),
            aha::AhaRateLimitReceipt::default(),
        )),
    )
    .expect("provider");
    let mut malformed = aha::AhaRoadmapResultService::new(provider).expect("service");
    let request = release_request(&malformed, "malformed");
    assert!(matches!(
        malformed.read_request(&request),
        Err(aha::AhaRoadmapResultServiceError::EvidenceTampered)
    ));
}

#[test]
fn partial_empty_rate_timeout_provider_unknown_and_blocked_states_are_typed() {
    let mut empty = fixture_service(aha::AhaResponse::json(
        200,
        &json!({"items": [], "total": 0}),
    ));
    assert_eq!(
        empty.read().expect("empty evidence").state,
        aha::AhaEvidenceState::Empty
    );

    let mut partial = fixture_service(aha::AhaResponse::json(
        206,
        &json!({"items": [release_payload(7, "release-1")], "total": 2}),
    ));
    let partial_evidence = partial.read().expect("partial evidence");
    assert_eq!(partial_evidence.state, aha::AhaEvidenceState::Partial);
    assert_eq!(
        partial_evidence.classification,
        aha::EvidenceClassification::Partial
    );

    let exhausted =
        aha::AhaRateLimitReceipt::new(60, Some(0), Some(4), 4, 1, true).expect("rate receipt");
    let mut rate = fixture_service(aha::AhaResponse::json_with_rate_limit(
        429,
        &json!({"error": "private rate details"}),
        exhausted,
    ));
    let rate_evidence = rate.read().expect("rate evidence");
    assert_eq!(rate_evidence.state, aha::AhaEvidenceState::RateLimited);
    assert_eq!(rate_evidence.rate_limit.backoff_seconds, 4);
    assert!(rate_evidence.aggregate.is_none());

    let mut timeout_transport = aha::FakeAhaTransport::default();
    timeout_transport.push_error(aha::AhaTransportError::Timeout);
    let provider = aha::AhaRoadmapProvider::new(scope(), secret(), timeout_transport)
        .expect("timeout provider");
    let mut timeout = aha::AhaRoadmapResultService::new(provider).expect("timeout service");
    assert_eq!(
        timeout.read().expect("timeout evidence").state,
        aha::AhaEvidenceState::Timeout
    );

    let mut unknown_transport = aha::FakeAhaTransport::default();
    unknown_transport.push_error(aha::AhaTransportError::ProviderUnknown);
    let provider = aha::AhaRoadmapProvider::new(scope(), secret(), unknown_transport)
        .expect("unknown provider");
    let mut unknown = aha::AhaRoadmapResultService::new(provider).expect("unknown service");
    assert_eq!(
        unknown.read().expect("unknown evidence").state,
        aha::AhaEvidenceState::ProviderUnknown
    );

    let provider = aha::AhaRoadmapProvider::new(scope(), secret(), aha::BlockedEnvAhaTransport)
        .expect("blocked provider");
    let mut blocked = aha::AhaRoadmapResultService::new(provider).expect("blocked service");
    let blocked_evidence = blocked.read().expect("blocked evidence");
    assert_eq!(blocked_evidence.state, aha::AhaEvidenceState::BlockedEnv);
    assert_eq!(
        blocked_evidence.provenance,
        aha::AhaTransportProvenance::BlockedEnv
    );
    assert_eq!(
        blocked_evidence.classification,
        aha::EvidenceClassification::BlockedEnv
    );
    assert!(!blocked_evidence.connected);
    assert!(!blocked_evidence.native_provider);
    assert!(!blocked_evidence.first_party);
}

#[test]
fn registration_and_secret_revocation_are_reversible_and_digest_bound() {
    let mut service = fixture_service(aha::AhaResponse::json(
        200,
        &release_payload(7, "release-1"),
    ));
    let original = service.registration().registration_digest.clone();
    let revocation = service.revoke().expect("revoke");
    assert_eq!(revocation.previous_registration_digest, original);
    assert_ne!(revocation.registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(aha::AhaRoadmapResultServiceError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    assert_ne!(service.registration().registration_digest, original);
    service.revoke_secret().expect("revoke secret");
    assert!(matches!(
        service.read(),
        Err(aha::AhaRoadmapResultServiceError::SecretRevoked)
    ));
    service.restore_secret().expect("restore secret");
    service.read().expect("restored secret");
}

#[test]
fn mission_consumer_is_review_only_and_rejects_replay_or_tampering() {
    let mut service = fixture_service(aha::AhaResponse::json(
        200,
        &release_payload(7, "release-1"),
    ));
    let request = release_request(&service, "consumer-read");
    let proposal = service.propose(&request).expect("proposal");
    let mut consumer = aha::MissionAhaRoadmapConsumer::new_bound(
        service.scope().clone(),
        service.registration().clone(),
    )
    .expect("bound consumer");
    let result = consumer.consume(proposal.clone()).expect("consume");
    assert_eq!(
        result.state,
        aha::MissionAhaRoadmapResultState::DecisionReady
    );
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native_provider);
    assert!(!result.first_party);
    assert!(!result.outcome_authority);
    assert!(!result.work_product_adopted);
    assert!(!result.receipt.durable);
    assert!(!result.receipt.provider_receipt);
    assert!(matches!(
        consumer.consume(proposal.clone()),
        Err(aha::MissionAhaRoadmapConsumerError::ReplayDetected)
    ));

    let mut tampered = proposal;
    tampered.native_provider = true;
    assert!(matches!(
        consumer.consume(tampered),
        Err(aha::MissionAhaRoadmapConsumerError::Tampered)
    ));
}

#[test]
fn idempotency_conflict_and_consumer_scope_drift_fail_closed() {
    let mut service = fixture_service(aha::AhaResponse::json(
        200,
        &release_payload(7, "release-1"),
    ));
    let key = aha::IdempotencyKey::new("same-key").expect("key");
    let first = aha::AhaRoadmapRequest::release(&scope(), &key).expect("first");
    service.propose(&first).expect("first proposal");
    let second = aha::AhaRoadmapRequest::roadmap(service.scope(), &key).expect("second");
    assert!(matches!(
        service.propose(&second),
        Err(aha::AhaRoadmapResultServiceError::IdempotencyConflict)
    ));

    let other_scope = {
        let mut value = serde_json::to_value(scope().spec()).expect("scope value");
        value["release"] = Value::String("release-2".to_owned());
        let spec: aha::AhaRoadmapScopeSpec = serde_json::from_value(value).expect("other spec");
        aha::AhaRoadmapScope::new(spec).expect("other scope")
    };
    let other_provider = aha::AhaRoadmapProvider::new(
        other_scope.clone(),
        secret(),
        aha::FixtureAhaTransport::new(aha::AhaResponse::json(
            200,
            &release_payload(7, "release-2"),
        )),
    )
    .expect("other provider");
    let mut other_service = aha::AhaRoadmapResultService::new(other_provider).expect("service");
    let other_request = aha::AhaRoadmapRequest::release(
        other_service.scope(),
        &aha::IdempotencyKey::new("other-key").expect("other key"),
    )
    .expect("other request");
    let other_proposal = other_service
        .propose(&other_request)
        .expect("other proposal");
    let mut consumer = aha::MissionAhaRoadmapConsumer::new(scope());
    assert!(matches!(
        consumer.consume(other_proposal),
        Err(aha::MissionAhaRoadmapConsumerError::ScopeMismatch)
    ));
}

#[test]
fn read_only_mutation_boundary_is_explicit() {
    assert_eq!(
        aha::mutation_forbidden("prioritize-release").to_string(),
        "Layer-1 Aha operation is read-only: prioritize-release"
    );
    assert!(!aha::Layer1Authority::durable_provider_receipt());
    assert!(!aha::Layer1Authority::kernel_authority());
}

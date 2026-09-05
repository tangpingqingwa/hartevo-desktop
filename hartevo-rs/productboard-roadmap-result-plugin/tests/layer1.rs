use hartevo_productboard_roadmap_result_plugin as productboard;
use serde_json::{Value, json};

fn scope() -> productboard::ProductboardRoadmapScope {
    let spec = productboard::ProductboardRoadmapScopeSpec::new(
        productboard::WorkspaceId::new("workspace-1").expect("workspace"),
        productboard::EntityConfigurationId::new("entity-config-1").expect("configuration"),
        productboard::NoteId::new("note-1").expect("note"),
        productboard::InsightId::new("insight-1").expect("insight"),
        productboard::FeatureId::new("feature-1").expect("feature"),
        productboard::ComponentId::new("component-1").expect("component"),
        productboard::InitiativeId::new("initiative-1").expect("initiative"),
        productboard::ObjectiveId::new("objective-1").expect("objective"),
        productboard::ReleaseId::new("release-1").expect("release"),
        productboard::ProjectBinding::new("project-1", 2).expect("project"),
        productboard::MissionBinding::new("mission-1", 3).expect("mission"),
        productboard::WorkProductBinding::new("work-product-1", 4).expect("work product"),
        productboard::ProductboardPermissionSnapshot::read_only(5).expect("permissions"),
        7,
    )
    .expect("scope spec");
    productboard::ProductboardRoadmapScope::new(spec).expect("scope")
}

fn secret() -> productboard::SecretReference {
    productboard::SecretReference::public_api_token("pb-public-token-must-not-escape", 6)
        .expect("secret")
}

fn note_payload(revision: u64, archived: bool) -> Value {
    json!({
        "id": "note-1",
        "type": "textNote",
        "workspaceId": "workspace-1",
        "name": "Private note title",
        "content": "Private note body must never escape",
        "customer": {"email": "private@example.com"},
        "revision": revision,
        "archived": archived,
        "relationships": [{"type": "link", "target": {"id": "feature-1"}}]
    })
}

fn roadmap_payload(revision: u64, archived: bool) -> Value {
    json!({
        "data": [{
            "id": "feature-1",
            "type": "feature",
            "name": "Private feature title",
            "description": "Private roadmap description",
            "revision": revision,
            "archived": archived,
            "relationships": [{"type": "parent", "target": {"id": "initiative-1"}}]
        }],
        "total": 1,
        "links": {"next": "opaque-next-page-token"}
    })
}

fn fixture_service(
    response: productboard::ProductboardResponse,
) -> productboard::ProductboardRoadmapResultService<productboard::FixtureProductboardTransport> {
    let provider = productboard::ProductboardProvider::new(
        scope(),
        secret(),
        productboard::FixtureProductboardTransport::new(response),
    )
    .expect("provider");
    productboard::ProductboardRoadmapResultService::new(provider).expect("service")
}

fn note_request(
    service: &productboard::ProductboardRoadmapResultService<
        productboard::FixtureProductboardTransport,
    >,
    key: &str,
) -> productboard::ProductboardRoadmapRequest {
    productboard::ProductboardRoadmapRequest::note(
        service.scope(),
        &productboard::IdempotencyKey::new(key).expect("idempotency key"),
    )
    .expect("note request")
}

#[test]
fn contract_scope_registration_and_provenance_are_machine_bound() {
    let provider = productboard::ProductboardProvider::new(
        scope(),
        secret(),
        productboard::LoopbackProductboardTransport::new(productboard::ProductboardResponse::json(
            200,
            &roadmap_payload(7, false),
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
    assert_eq!(provider.registration().evidence_digest.len(), 64);
    assert!(provider.registration().reversible);
    assert!(provider.registration().revocable);
    assert_eq!(
        provider.definition().provider_id,
        productboard::PRODUCTBOARD_PROVIDER_ID
    );
    assert_eq!(
        provider.definition().base_url,
        productboard::PRODUCTBOARD_API_BASE_URL
    );
    assert!(!provider.definition().connected);
    assert!(!provider.definition().native);
    assert!(!provider.definition().first_party);

    for provenance in [
        productboard::ProductboardTransportProvenance::Fixture,
        productboard::ProductboardTransportProvenance::Recording,
        productboard::ProductboardTransportProvenance::Fake,
        productboard::ProductboardTransportProvenance::Loopback,
        productboard::ProductboardTransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

#[test]
fn note_read_is_bounded_redacted_and_proposal_only() {
    let mut service = fixture_service(productboard::ProductboardResponse::json(
        200,
        &note_payload(7, false),
    ));
    let request = note_request(&service, "note-read-1");
    let proposal = service.propose(&request).expect("proposal");

    assert_eq!(
        proposal.state(),
        productboard::ProductboardEvidenceState::Present
    );
    let evidence = proposal.evidence();
    assert_eq!(evidence.aggregate().expect("aggregate").item_count, 1);
    assert_eq!(
        evidence.aggregate().expect("aggregate").items[0].relationship_count,
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
        "pb-public-token-must-not-escape",
        "Private note title",
        "Private note body must never escape",
        "private@example.com",
    ] {
        assert!(!encoded.contains(forbidden), "leaked {forbidden}");
    }
    assert!(!format!("{service:?}").contains("pb-public-token-must-not-escape"));
    assert!(!format!("{service:?}").contains("Private note body must never escape"));
}

#[test]
fn recording_transport_is_get_only_and_exactly_scoped() {
    let provider = productboard::ProductboardProvider::new(
        scope(),
        secret(),
        productboard::RecordingProductboardTransport::new(
            productboard::ProductboardResponse::json(200, &note_payload(7, false)),
        ),
    )
    .expect("provider");
    let mut service =
        productboard::ProductboardRoadmapResultService::new(provider).expect("service");
    let request = productboard::ProductboardRoadmapRequest::note(
        service.scope(),
        &productboard::IdempotencyKey::new("recording-read").expect("key"),
    )
    .expect("request");
    service.read_request(&request).expect("read");
    let recorded = &service.provider().transport().requests()[0];
    assert_eq!(recorded.method, productboard::ProductboardHttpMethod::Get);
    assert_eq!(recorded.host, productboard::PRODUCTBOARD_API_HOST);
    assert_eq!(recorded.path, "/v2/notes/note-1");
    assert!(recorded.is_allowlisted());
    assert!(!recorded.path.contains("update"));
    assert!(!recorded.path.contains("delete"));
    assert!(
        !serde_json::to_string(recorded)
            .expect("recorded request serializes")
            .contains("pb-public-token-must-not-escape")
    );
}

#[test]
fn cursor_is_opaque_and_bound_to_operation_scope_revision_and_fields() {
    let mut service = fixture_service(productboard::ProductboardResponse::json(
        200,
        &roadmap_payload(7, false),
    ));
    let first = productboard::ProductboardRoadmapRequest::roadmap(
        service.scope(),
        &productboard::IdempotencyKey::new("cursor-first").expect("key"),
    )
    .expect("first request")
    .with_page_size(10)
    .expect("page size");
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
    let cursor =
        productboard::OpaquePageToken::from_digest(cursor_digest.clone(), Some(binding.clone()))
            .expect("opaque cursor");
    assert_eq!(cursor.digest(), &cursor_digest);
    assert_eq!(cursor.binding_digest(), Some(&binding));

    let second = productboard::ProductboardRoadmapRequest::roadmap(
        service.scope(),
        &productboard::IdempotencyKey::new("cursor-second").expect("key"),
    )
    .expect("second request")
    .with_page_size(10)
    .expect("page size")
    .with_page_token(&cursor);
    service.read_request(&second).expect("bound second page");

    let mut tampered_value = serde_json::to_value(&second).expect("request value");
    tampered_value["cursorBindingDigest"] = Value::String("a".repeat(64));
    let tampered: productboard::ProductboardRoadmapRequest = serde_json::from_value(tampered_value)
        .expect("tampered request remains syntactically typed");
    assert!(matches!(
        tampered.validate(service.scope()),
        Err(productboard::ModelError::InvalidCursor)
    ));
    assert!(matches!(
        productboard::ProductboardRoadmapRequest::note(
            service.scope(),
            &productboard::IdempotencyKey::new("raw-fields").expect("key")
        )
        .expect("request")
        .with_fields(vec!["content".to_owned()]),
        Err(productboard::ModelError::InvalidRequest)
    ));
}

#[test]
fn archived_stale_tamper_access_loss_and_blocked_env_are_typed_projections() {
    let mut archived = fixture_service(productboard::ProductboardResponse::json(
        200,
        &roadmap_payload(7, true),
    ));
    assert_eq!(
        archived.read().expect("archived evidence").state,
        productboard::ProductboardEvidenceState::Archived
    );

    let mut stale = fixture_service(productboard::ProductboardResponse::json(
        200,
        &roadmap_payload(8, false),
    ));
    assert_eq!(
        stale.read().expect("stale evidence").state,
        productboard::ProductboardEvidenceState::Stale
    );

    let mut tamper = fixture_service(productboard::ProductboardResponse::new(
        200,
        b"private malformed body".to_vec(),
        productboard::ProductboardRateLimitReceipt::default(),
    ));
    assert_eq!(
        tamper.read().expect("tamper evidence").state,
        productboard::ProductboardEvidenceState::Tamper
    );

    let access_provider = productboard::ProductboardProvider::new(
        scope(),
        secret(),
        productboard::FakeProductboardTransport::new(productboard::ProductboardResponse::new(
            403,
            b"private access error".to_vec(),
            productboard::ProductboardRateLimitReceipt::default(),
        )),
    )
    .expect("access provider");
    let mut access = productboard::ProductboardRoadmapResultService::new(access_provider)
        .expect("access service");
    assert_eq!(
        access.read().expect("access evidence").state,
        productboard::ProductboardEvidenceState::AccessLoss
    );

    let blocked_provider = productboard::ProductboardProvider::new(
        scope(),
        secret(),
        productboard::BlockedEnvProductboardTransport,
    )
    .expect("blocked provider");
    let mut blocked = productboard::ProductboardRoadmapResultService::new(blocked_provider)
        .expect("blocked service");
    let blocked_evidence = blocked.read().expect("blocked evidence");
    assert_eq!(
        blocked_evidence.state,
        productboard::ProductboardEvidenceState::BlockedEnv
    );
    assert_eq!(
        blocked_evidence.provenance,
        productboard::ProductboardTransportProvenance::BlockedEnv
    );
    assert!(!blocked_evidence.connected);
    assert!(!blocked_evidence.native_provider);
    assert!(!blocked_evidence.first_party);
}

#[test]
fn registration_secret_and_mission_replay_fences_are_reversible() {
    let mut service = fixture_service(productboard::ProductboardResponse::json(
        200,
        &note_payload(7, false),
    ));
    let original = service.registration().registration_digest.clone();
    service.revoke().expect("revoke");
    assert_ne!(service.registration().registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(productboard::ProductboardRoadmapResultServiceError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    service.revoke_secret().expect("revoke secret");
    assert!(matches!(
        service.read(),
        Err(productboard::ProductboardRoadmapResultServiceError::SecretRevoked)
    ));
    service.restore_secret().expect("restore secret");

    let request = note_request(&service, "consumer-read");
    let proposal = service.propose(&request).expect("proposal");
    let mut consumer = productboard::MissionProductboardRoadmapConsumer::new_bound(
        service.scope().clone(),
        service.registration().clone(),
    )
    .expect("bound consumer");
    let result = consumer.consume(proposal.clone()).expect("consume");
    assert_eq!(
        result.state,
        productboard::MissionProductboardRoadmapResultState::DecisionReady
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
        consumer.consume(proposal),
        Err(productboard::MissionProductboardRoadmapConsumerError::ReplayDetected)
    ));
}

#[test]
fn read_only_mutation_boundary_is_explicit() {
    assert_eq!(
        productboard::mutation_forbidden("update-note").to_string(),
        "Layer-1 Productboard operation is read-only: update-note"
    );
    assert!(!productboard::Layer1Authority::durable_provider_receipt());
    assert!(!productboard::Layer1Authority::kernel_authority());
}

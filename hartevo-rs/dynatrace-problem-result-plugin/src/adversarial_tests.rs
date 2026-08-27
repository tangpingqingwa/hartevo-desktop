use super::*;

fn scope(problem_id: Option<&str>, expires_at_ms: u64) -> DynatraceProblemScope {
    DynatraceProblemScope::new(DynatraceProblemScopeInput {
        environment_id: "env-1".into(),
        account_id: "account-1".into(),
        management_zone_id: "mz-1".into(),
        entity_selector: "type(\"HOST\"),mzId(123)".into(),
        problem_id: problem_id.map(str::to_owned),
        from_ms: 1_000,
        to_ms: 2_000,
        expires_at_ms,
        project_id: "project-1".into(),
        project_revision: 1,
        mission_id: "mission-1".into(),
        mission_revision: 1,
        work_product_id: "work-product-1".into(),
        work_product_revision: 1,
    })
    .expect("valid scope")
}

fn problem(status: &str) -> DynatraceProblemPayload {
    DynatraceProblemPayload::new(
        "problem-1",
        status,
        "PERFORMANCE",
        "APPLICATION",
        1_200,
        if status == "OPEN" { -1 } else { 1_900 },
        vec![
            DynatraceRawEntity::new("HOST-1", "HOST").expect("valid entity"),
            DynatraceRawEntity::new("SERVICE-1", "SERVICE").expect("valid entity"),
        ],
    )
    .expect("valid problem")
}

fn page(index: u8, next_page_key: Option<&str>, status: &str) -> DynatraceProblemPage {
    DynatraceProblemPage::new(
        index,
        100,
        1,
        next_page_key.map(str::to_owned),
        vec![problem(status)],
    )
    .expect("valid page")
}

fn service(
    scope: DynatraceProblemScope,
    transport: RecordingDynatraceTransport,
) -> DynatraceProblemResultService<RecordingDynatraceTransport> {
    let secret = SecretReference::new("vault/dynatrace/access-token", &scope, 1)
        .expect("valid secret reference");
    let provider = DynatraceProvider::new(transport).expect("valid provider");
    DynatraceProblemResultService::new(provider, scope, secret).expect("valid service")
}

#[test]
fn list_pagination_is_bounded_and_projection_is_redacted() {
    let scope = scope(None, 10_000);
    let mut service = service(
        scope,
        RecordingDynatraceTransport::fixture([
            Ok(page(0, Some("cursor-1"), "OPEN")),
            Ok(page(1, None, "OPEN")),
        ]),
    );
    let evidence = service.read_at(2_500).expect("read succeeds");
    assert_eq!(evidence.state, EvidenceState::Open);
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.problems.len(), 2);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    assert!(!evidence.native_evidence);
    let encoded = serde_json::to_string(&evidence).expect("evidence serializes");
    for forbidden in [
        "displayName",
        "evidenceDetails",
        "impactAnalysis",
        "recentComments",
        "topology",
        "logs",
        "userIds",
        "pii",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "projection leaked {forbidden}"
        );
    }
    assert!(encoded.contains("problemIdDigest"));
    assert!(encoded.contains("entityTypeDigest"));
    assert!(service.provider().transport().calls().iter().all(|call| {
        call.method == DynatraceHttpMethod::Get
            && !call.connected
            && !call.native
            && !call.first_party
    }));
}

#[test]
fn detail_reads_are_get_only_and_state_transition_is_resolved() {
    let scope = scope(Some("problem-1"), 10_000);
    let detail_open = DynatraceProblemDetail::new(problem("OPEN"));
    let detail_closed = DynatraceProblemDetail::new(problem("CLOSED"));
    let mut service = service(
        scope,
        RecordingDynatraceTransport::fixture_with_details([], [Ok(detail_open), Ok(detail_closed)]),
    );
    let first = service.read_at(2_500).expect("open detail succeeds");
    let second = service.read_at(2_500).expect("closed detail succeeds");
    assert_eq!(first.state, EvidenceState::Open);
    assert_eq!(second.state, EvidenceState::Resolved);
    assert_eq!(second.problems[0].state, ProblemObservationState::Resolved);
    assert_eq!(service.provider().transport().calls().len(), 2);
    assert!(
        service
            .provider()
            .transport()
            .calls()
            .iter()
            .all(|call| call.kind == DynatraceApiRequestKind::Detail)
    );
}

#[test]
fn partial_page_and_access_loss_fail_closed() {
    let mut partial_service = service(
        scope(None, 10_000),
        RecordingDynatraceTransport::new(
            ProviderProvenance::Recording,
            [
                Ok(page(0, Some("cursor-1"), "OPEN")),
                Err(TransportError::HttpStatus(503)),
            ],
            [],
        ),
    );
    let partial = partial_service
        .read_at(2_500)
        .expect("partial read is represented");
    assert_eq!(partial.state, EvidenceState::Partial);
    assert!(partial.partial);
    assert_eq!(partial.problems.len(), 1);

    let mut blocked = service(
        scope(None, 10_000),
        RecordingDynatraceTransport::blocked_env(),
    );
    let access_lost = blocked.read_at(2_500).expect("access loss is represented");
    assert_eq!(access_lost.state, EvidenceState::AccessLost);
    assert!(!access_lost.connected);
    assert!(!access_lost.native);
    assert!(!access_lost.first_party);
}

#[test]
fn expired_unknown_and_tampered_results_do_not_escape_as_successful_evidence() {
    let mut expired = service(
        scope(None, 2_500),
        RecordingDynatraceTransport::fixture([Ok(page(0, None, "OPEN"))]),
    );
    let expired_evidence = expired.read_at(2_500).expect("expiry is represented");
    assert_eq!(expired_evidence.state, EvidenceState::Expired);
    assert!(expired.provider().transport().calls().is_empty());

    let unknown = DynatraceProblemPayload::new(
        "problem-unknown",
        "FUTURE_STATUS",
        "PERFORMANCE",
        "APPLICATION",
        1_200,
        -1,
        vec![DynatraceRawEntity::new("HOST-1", "HOST").expect("entity")],
    )
    .expect("raw unknown status is retained only at transport seam");
    let unknown_page = DynatraceProblemPage::new(0, 100, 1, None, vec![unknown]).expect("page");
    let mut provider_unknown = service(
        scope(None, 10_000),
        RecordingDynatraceTransport::fixture([Ok(unknown_page)]),
    );
    assert_eq!(
        provider_unknown
            .read_at(2_500)
            .expect("unknown is represented")
            .state,
        EvidenceState::ProviderUnknown
    );

    let tampered = page(0, None, "OPEN").with_declared_digest(Digest::from_text("tampered"));
    let mut tampered_service = service(
        scope(None, 10_000),
        RecordingDynatraceTransport::fixture([Ok(tampered)]),
    );
    assert_eq!(
        tampered_service
            .read_at(2_500)
            .expect("tamper is represented")
            .state,
        EvidenceState::Tampered
    );
}

#[test]
fn mission_rejects_stale_scope_replay_tamper_and_revocation() {
    let registered_scope = scope(None, 10_000);
    let stale_scope = DynatraceProblemScope::new(DynatraceProblemScopeInput {
        mission_revision: 2,
        ..DynatraceProblemScopeInput {
            environment_id: "env-1".into(),
            account_id: "account-1".into(),
            management_zone_id: "mz-1".into(),
            entity_selector: "type(\"HOST\")".into(),
            problem_id: None,
            from_ms: 1_000,
            to_ms: 2_000,
            expires_at_ms: 10_000,
            project_id: "project-1".into(),
            project_revision: 1,
            mission_id: "mission-1".into(),
            mission_revision: 1,
            work_product_id: "work-product-1".into(),
            work_product_revision: 1,
        }
    })
    .expect("stale scope is syntactically valid");
    let mut stale_consumer = MissionDynatraceProblemConsumer::new(stale_scope);
    let mut registered_service = service(
        registered_scope,
        RecordingDynatraceTransport::fixture([
            Ok(page(0, None, "OPEN")),
            Ok(page(0, None, "OPEN")),
        ]),
    );
    assert_eq!(
        stale_consumer.consume_at(&mut registered_service, 2_500),
        Err(ConsumerError::ScopeMismatch)
    );

    let mut consumer = MissionDynatraceProblemConsumer::new(registered_service.scope().clone());
    let first = consumer
        .consume_at(&mut registered_service, 2_500)
        .expect("first result accepted");
    assert_eq!(first.state, EvidenceState::Open);
    assert_eq!(
        consumer.consume_at(&mut registered_service, 2_500),
        Err(ConsumerError::ReplayDetected)
    );

    registered_service.revoke().expect("revokes");
    assert_eq!(
        consumer.consume_at(&mut registered_service, 2_500),
        Err(ConsumerError::Revoked)
    );
}

#[test]
fn transport_and_registration_cannot_claim_native_authority() {
    for transport in [
        RecordingDynatraceTransport::fixture([]),
        RecordingDynatraceTransport::recording([], []),
        RecordingDynatraceTransport::loopback([], []),
        RecordingDynatraceTransport::blocked_env(),
    ] {
        let provider = DynatraceProvider::new(transport).expect("provider");
        assert!(!provider.definition().native);
        assert!(!provider.definition().connected);
        assert!(!provider.definition().first_party);
    }
    let scope = scope(None, 10_000);
    let secret = SecretReference::new("opaque-reference", &scope, 1).expect("secret");
    assert!(!format!("{secret:?}").contains("opaque-reference"));
    assert!(
        !serde_json::to_string(&scope)
            .expect("scope serialization")
            .contains("opaque")
    );
}

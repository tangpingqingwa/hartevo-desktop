use super::*;

fn digest(value: &str) -> Digest {
    Digest::from_text(value)
}

fn scope() -> MiroDecisionScope {
    MiroDecisionScope::from_parts(
        TeamId::new("team-1").expect("team"),
        BoardId::new("board-1").expect("board"),
        [
            ItemId::new("card-1").expect("card"),
            ItemId::new("text-1").expect("text"),
            ItemId::new("sticky-1").expect("sticky"),
            ItemId::new("link-1").expect("link"),
            ItemId::new("unsupported-1").expect("unsupported"),
            ItemId::new("second-1").expect("second"),
        ],
        Revision::new(7).expect("board revision"),
        MissionId::new("mission-1").expect("mission"),
        Revision::new(11).expect("mission revision"),
        ProjectId::new("project-1").expect("project"),
        Revision::new(13).expect("project revision"),
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(17).expect("work product revision"),
        digest("permission-v1"),
        digest("consent-v1"),
    )
    .expect("scope")
}

fn secret(scope: &MiroDecisionScope) -> SecretReference {
    SecretReference::oauth("opaque-miro-secret-handle", scope, 19).expect("secret")
}

fn board(scope: &MiroDecisionScope) -> MiroBoardMetadata {
    MiroBoardMetadata::new(
        scope.team_id().clone(),
        scope.board_id().clone(),
        scope.board_revision(),
        UpdateTimestamp::new("2026-08-14T21:00:00Z").expect("timestamp"),
    )
}

fn item(
    _scope: &MiroDecisionScope,
    id: &str,
    kind: MiroBoardItemKind,
    raw_text: Option<&str>,
    external_link: Option<&str>,
) -> MiroBoardItem {
    MiroBoardItem::from_raw(
        ItemId::new(id).expect("item id"),
        kind,
        Revision::new(3).expect("item revision"),
        UpdateTimestamp::new("2026-08-14T21:01:00Z").expect("timestamp"),
        [Label::new("decision").expect("label")],
        raw_text,
        external_link,
    )
    .expect("item")
}

fn page(
    scope: &MiroDecisionScope,
    items: Vec<MiroBoardItem>,
    next_cursor: Option<&str>,
) -> MiroBoardPage {
    MiroBoardPage::new(
        board(scope),
        items,
        next_cursor.map(|value| OpaqueCursor::new(value).expect("cursor")),
        scope.fence(),
        Revision::new(19).expect("credential revision"),
    )
}

fn service_with_responses(
    scope: MiroDecisionScope,
    responses: impl IntoIterator<Item = Result<MiroBoardPage, TransportError>>,
    provenance: ProviderProvenance,
) -> MiroDecisionResultService<MiroBoardProviderAdapter<RecordingMiroBoardTransport>> {
    service_with_responses_policy(scope, responses, provenance, 1)
}

fn service_with_responses_policy(
    scope: MiroDecisionScope,
    responses: impl IntoIterator<Item = Result<MiroBoardPage, TransportError>>,
    provenance: ProviderProvenance,
    max_attempts: u8,
) -> MiroDecisionResultService<MiroBoardProviderAdapter<RecordingMiroBoardTransport>> {
    let secret = secret(&scope);
    let transport = RecordingMiroBoardTransport::new(provenance, responses);
    let provider =
        MiroBoardProviderAdapter::new(transport, "fixture-v1", provenance).expect("provider");
    MiroDecisionResultService::new(
        scope,
        secret,
        provider,
        RetryPolicy::new(max_attempts).expect("retry"),
    )
    .expect("service")
}

#[test]
fn contract_registration_and_secret_are_bound_and_reversible() {
    let scope = self::scope();
    let secret = secret(&scope);
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-miro-secret-handle"));
    assert!(debug.contains("reference_digest"));

    let provider = MiroBoardProviderAdapter::new(
        RecordingMiroBoardTransport::fixture([]),
        "fixture-v1",
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    let mut service =
        MiroDecisionResultService::new(scope.clone(), secret, provider, RetryPolicy::default())
            .expect("service");
    assert_eq!(
        service.service_definition().contract_version,
        MIRO_DECISION_RESULT_CONTRACT_VERSION
    );
    assert!(service.service_definition().read_only);
    assert!(!service.service_definition().live_execution);
    assert!(!service.service_definition().external_writes);
    assert!(!service.service_definition().sharing_authority);
    assert!(!service.provider_definition().native);
    assert!(!service.provider_definition().connected);
    assert_eq!(service.registration().scope_digest(), &scope.scope_digest());
    let revocation = service.revoke_registration().expect("revoke registration");
    assert_eq!(revocation.state, RegistrationState::Revoked);
    assert!(matches!(
        service.propose(MiroDecisionProposalRequest::default()),
        Err(MiroDecisionResultServiceError::RegistrationRevoked)
    ));
}

#[test]
fn complete_read_recording_and_mission_consume_are_redacted_and_bounded() {
    let scope = self::scope();
    let responses = [Ok(page(
        &scope,
        vec![
            item(
                &scope,
                "link-1",
                MiroBoardItemKind::Link,
                Some("a decision link"),
                Some("https://User:pass@example.com/private/email@example.com?token=secret#frag"),
            ),
            item(
                &scope,
                "text-1",
                MiroBoardItemKind::Text,
                Some("decision text with owner@example.com"),
                None,
            ),
            item(
                &scope,
                "card-1",
                MiroBoardItemKind::Card,
                Some("approve"),
                None,
            ),
            item(
                &scope,
                "sticky-1",
                MiroBoardItemKind::StickyNote,
                Some("sticky decision"),
                None,
            ),
        ],
        None,
    ))];
    let mut service = service_with_responses(scope.clone(), responses, ProviderProvenance::Fixture);
    let proposal = service
        .propose(MiroDecisionProposalRequest::default())
        .expect("proposal");
    assert_eq!(proposal.projection, MiroDecisionProjection::Complete);
    assert_eq!(proposal.evidence.items.len(), 4);
    assert_eq!(proposal.evidence.items[0].id.as_str(), "card-1");
    assert!(proposal.evidence.redacted);
    assert!(!proposal.evidence.raw_text_retained);
    assert!(!proposal.evidence.raw_urls_retained);
    assert!(!proposal.evidence.credential_material_retained);
    assert!(!proposal.evidence.authority.connected());
    assert!(!proposal.evidence.authority.native_provider());
    assert!(!proposal.evidence.authority.truth_authority());
    let serialized = serde_json::to_string(&proposal.evidence).expect("evidence JSON");
    assert!(!serialized.contains("owner@example.com"));
    assert!(!serialized.contains("token=secret"));
    assert!(!serialized.contains("User:pass"));
    assert!(serialized.contains("<redacted>"));
    let query_only = RedactedExternalLink::new("https://example.com?token=query-secret#fragment")
        .expect("query-only link");
    assert_eq!(query_only.as_str(), "https://example.com");

    let recording = service.record(&proposal).expect("recording");
    recording.validate(&scope).expect("recording validates");
    assert!(recording.recorded);
    assert!(!recording.durable);
    assert!(!recording.native);
    assert!(!recording.connected);
    assert!(!recording.adopted_outcome);

    let consumer =
        MissionMiroDecisionConsumer::new(scope, service.registration()).expect("consumer");
    let recorded_result = consumer
        .consume_recording(&recording)
        .expect("recorded Mission result");
    assert_eq!(
        recorded_result.recording_digest.as_ref(),
        Some(&recording.recording_digest)
    );
    let result = consumer.consume(proposal).expect("Mission result");
    result.validate().expect("Mission result validates");
    assert_eq!(result.state, MissionMiroDecisionState::PendingDecision);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.durable);
}

#[test]
fn provenance_and_blocked_environment_never_become_native() {
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_native());
        assert!(!provenance.is_connected());
        assert!(!provenance.is_first_party());
    }
    let scope = self::scope();
    let secret = secret(&scope);
    let provider = MiroBoardProviderAdapter::new(
        BlockedEnvMiroBoardTransport,
        "blocked-env-v1",
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut service = MiroDecisionResultService::new(
        scope,
        secret,
        provider,
        RetryPolicy::new(1).expect("retry"),
    )
    .expect("service");
    let proposal = service
        .propose(MiroDecisionProposalRequest::default())
        .expect("blocked proposal");
    assert_eq!(proposal.projection, MiroDecisionProjection::BlockedEnv);
    assert_eq!(
        proposal.evidence.provider_provenance,
        ProviderProvenance::BlockedEnv
    );
    assert!(!proposal.evidence.authority.connected());
    assert!(!proposal.evidence.authority.native_provider());
}

#[test]
fn provider_failure_states_are_explicit_and_retries_are_bounded() {
    let cases = [
        (
            TransportError::unsupported_item(),
            MiroDecisionProjection::Unsupported,
        ),
        (TransportError::deleted(), MiroDecisionProjection::Deleted),
        (
            TransportError::access_lost(),
            MiroDecisionProjection::AccessLost,
        ),
        (TransportError::empty(), MiroDecisionProjection::Empty),
        (
            TransportError::partial(),
            MiroDecisionProjection::Partial(PartialReason::ProviderPartial),
        ),
        (
            TransportError::rate_limited(),
            MiroDecisionProjection::RateLimited,
        ),
        (
            TransportError::server_failure(503),
            MiroDecisionProjection::ServerFailure,
        ),
        (TransportError::timeout(), MiroDecisionProjection::Timeout),
    ];
    for (error, expected) in cases {
        let scope = self::scope();
        let mut service =
            service_with_responses(scope, [Err(error)], ProviderProvenance::Recording);
        let proposal = service
            .propose(MiroDecisionProposalRequest::default())
            .expect("failure projection");
        assert_eq!(proposal.projection, expected);
        assert_eq!(proposal.evidence.errors.len(), 1);
        assert!(!proposal.evidence.authority.connected());
    }

    let scope = self::scope();
    let mut service = service_with_responses_policy(
        scope,
        [
            Err(TransportError::rate_limited()),
            Err(TransportError::server_failure(502)),
            Err(TransportError::timeout()),
        ],
        ProviderProvenance::Loopback,
        3,
    );
    let proposal = service
        .propose(MiroDecisionProposalRequest::default())
        .expect("retry projection");
    assert_eq!(proposal.projection, MiroDecisionProjection::Timeout);
    assert_eq!(proposal.evidence.retries.len(), 2);
    assert_eq!(proposal.evidence.errors.len(), 1);
    assert_eq!(service.provider().transport().requests().len(), 3);
}

#[test]
fn page_item_caps_cursor_loops_and_unsupported_items_fail_closed() {
    let scope = self::scope();
    let mut service = service_with_responses(
        scope.clone(),
        [
            Ok(page(
                &scope,
                vec![item(
                    &scope,
                    "card-1",
                    MiroBoardItemKind::Card,
                    Some("one"),
                    None,
                )],
                Some("cursor-1"),
            )),
            Ok(page(
                &scope,
                vec![item(
                    &scope,
                    "second-1",
                    MiroBoardItemKind::Text,
                    Some("two"),
                    None,
                )],
                None,
            )),
        ],
        ProviderProvenance::Loopback,
    );
    let proposal = service
        .propose(MiroDecisionProposalRequest::bounded(1, 10, 10).expect("bounds"))
        .expect("bounded proposal");
    assert_eq!(
        proposal.projection,
        MiroDecisionProjection::Partial(PartialReason::PageCap)
    );
    assert_eq!(proposal.evidence.items.len(), 1);
    assert_eq!(proposal.evidence.pages_observed, 1);

    let scope = self::scope();
    let mut service = service_with_responses(
        scope.clone(),
        [Ok(page(
            &scope,
            vec![
                item(&scope, "card-1", MiroBoardItemKind::Card, Some("one"), None),
                item(
                    &scope,
                    "second-1",
                    MiroBoardItemKind::Text,
                    Some("two"),
                    None,
                ),
            ],
            None,
        ))],
        ProviderProvenance::Fixture,
    );
    let proposal = service
        .propose(MiroDecisionProposalRequest::bounded(2, 1, 10).expect("bounds"))
        .expect("item cap proposal");
    assert_eq!(
        proposal.projection,
        MiroDecisionProjection::Partial(PartialReason::ItemCap)
    );
    assert_eq!(proposal.evidence.items.len(), 1);
    assert!(proposal.evidence.item_bound_exceeded);

    let scope = self::scope();
    let mut service = service_with_responses(
        scope.clone(),
        [Ok(page(
            &scope,
            vec![item(
                &scope,
                "unsupported-1",
                MiroBoardItemKind::Unsupported,
                Some("unknown item"),
                None,
            )],
            None,
        ))],
        ProviderProvenance::Recording,
    );
    let proposal = service
        .propose(MiroDecisionProposalRequest::default())
        .expect("unsupported projection");
    assert_eq!(proposal.projection, MiroDecisionProjection::Unsupported);
    assert!(proposal.evidence.items.is_empty());
}

#[test]
fn tampered_scope_duplicate_and_consumer_fences_fail_closed() {
    let scope = self::scope();
    let mut tampered = page(
        &scope,
        vec![item(
            &scope,
            "card-1",
            MiroBoardItemKind::Card,
            Some("one"),
            None,
        )],
        None,
    );
    tampered.response_digest = digest("tampered-response");
    let mut service =
        service_with_responses(scope.clone(), [Ok(tampered)], ProviderProvenance::Fixture);
    assert!(matches!(
        service.propose(MiroDecisionProposalRequest::default()),
        Err(MiroDecisionResultServiceError::TamperedEvidence)
    ));

    let wrong_fence = MiroDecisionScope::from_parts(
        scope.team_id().clone(),
        scope.board_id().clone(),
        scope.allowlisted_item_ids().clone(),
        scope.board_revision(),
        scope.mission_id().clone(),
        Revision::new(12).expect("wrong mission revision"),
        scope.project_id().clone(),
        scope.project_revision(),
        scope.work_product_id().clone(),
        scope.work_product_revision(),
        scope.permission_digest().clone(),
        scope.consent_digest().clone(),
    )
    .expect("wrong fence scope");
    let wrong_page = page(
        &wrong_fence,
        vec![item(
            &wrong_fence,
            "card-1",
            MiroBoardItemKind::Card,
            Some("one"),
            None,
        )],
        None,
    );
    let mut service =
        service_with_responses(scope.clone(), [Ok(wrong_page)], ProviderProvenance::Fixture);
    assert!(matches!(
        service.propose(MiroDecisionProposalRequest::default()),
        Err(MiroDecisionResultServiceError::FenceViolation)
    ));

    let mut service = service_with_responses(
        scope.clone(),
        [
            Ok(page(
                &scope,
                vec![item(
                    &scope,
                    "card-1",
                    MiroBoardItemKind::Card,
                    Some("one"),
                    None,
                )],
                Some("repeat"),
            )),
            Ok(page(
                &scope,
                vec![item(
                    &scope,
                    "card-1",
                    MiroBoardItemKind::Card,
                    Some("one"),
                    None,
                )],
                Some("repeat"),
            )),
        ],
        ProviderProvenance::Loopback,
    );
    assert!(matches!(
        service.propose(MiroDecisionProposalRequest::default()),
        Err(MiroDecisionResultServiceError::DuplicateItem)
    ));

    let mut service = service_with_responses(
        scope.clone(),
        [Ok(page(
            &scope,
            vec![item(
                &scope,
                "card-1",
                MiroBoardItemKind::Card,
                Some("one"),
                None,
            )],
            None,
        ))],
        ProviderProvenance::Fixture,
    );
    let proposal = service
        .propose(MiroDecisionProposalRequest::default())
        .expect("proposal");
    let other_scope = MiroDecisionScope::from_parts(
        TeamId::new("team-other").expect("team"),
        scope.board_id().clone(),
        scope.allowlisted_item_ids().clone(),
        scope.board_revision(),
        scope.mission_id().clone(),
        scope.mission_revision(),
        scope.project_id().clone(),
        scope.project_revision(),
        scope.work_product_id().clone(),
        scope.work_product_revision(),
        scope.permission_digest().clone(),
        scope.consent_digest().clone(),
    )
    .expect("other scope");
    assert!(matches!(
        MissionMiroDecisionConsumer::new(other_scope, service.registration()),
        Err(ConsumerError::RegistrationMismatch)
    ));
    let mut consumer =
        MissionMiroDecisionConsumer::new(scope, service.registration()).expect("consumer");
    consumer.revoke().expect("consumer revoke");
    assert!(matches!(
        consumer.consume(proposal),
        Err(ConsumerError::Revoked)
    ));
}

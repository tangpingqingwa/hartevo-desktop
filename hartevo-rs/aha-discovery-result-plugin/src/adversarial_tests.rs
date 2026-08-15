use super::*;

fn exact_scope() -> AhaDiscoveryScope {
    AhaDiscoveryScope::new(
        AccountId::new("account-1").unwrap(),
        WorkspaceId::new("workspace-1").unwrap(),
        ProjectId::new("project-1").unwrap(),
        MissionId::new("mission-1").unwrap(),
        WorkProductId::new("work-product-1").unwrap(),
        Some(StudyId::new("study-1").unwrap()),
        Some(InterviewId::new("interview-1").unwrap()),
        Some(QuestionId::new("question-1").unwrap()),
        Some(ResponseId::new("response-1").unwrap()),
        Some(HighlightId::new("highlight-1").unwrap()),
        Some(LinkedRecordId::new("linked-record-1").unwrap()),
    )
    .unwrap()
}

fn second_scope() -> AhaDiscoveryScope {
    AhaDiscoveryScope::new(
        AccountId::new("account-1").unwrap(),
        WorkspaceId::new("workspace-1").unwrap(),
        ProjectId::new("project-1").unwrap(),
        MissionId::new("mission-1").unwrap(),
        WorkProductId::new("work-product-1").unwrap(),
        Some(StudyId::new("study-2").unwrap()),
        Some(InterviewId::new("interview-2").unwrap()),
        Some(QuestionId::new("question-2").unwrap()),
        Some(ResponseId::new("response-2").unwrap()),
        Some(HighlightId::new("highlight-2").unwrap()),
        Some(LinkedRecordId::new("linked-record-2").unwrap()),
    )
    .unwrap()
}

fn fence(revision: u64) -> EvidenceFence {
    EvidenceFence::new(
        Revision::new(revision).unwrap(),
        Digest::from_text(format!("transcript-{revision}")),
        Digest::from_text(format!("highlight-{revision}")),
    )
    .unwrap()
}

fn study_projection(id: &str, label: &str) -> AhaDiscoveryProjection {
    AhaDiscoveryProjection::Study(
        StudyProjection::new(
            StudyId::new(id).unwrap(),
            RedactedText::new(label).unwrap(),
            Revision::new(1).unwrap(),
            InsightState::Present,
        )
        .unwrap(),
    )
}

fn request(
    scope: &AhaDiscoveryScope,
    fence: &EvidenceFence,
    cursor: Option<PageCursor>,
) -> AhaDiscoveryRequest {
    AhaDiscoveryRequest::new(
        scope.clone(),
        DiscoveryResource::Studies,
        2,
        cursor,
        fence.clone(),
    )
    .unwrap()
}

fn register(
    service: &mut AhaDiscoveryResultService,
    scope: &AhaDiscoveryScope,
    provider: &AhaDiscoveryProviderDefinition,
    fence: &EvidenceFence,
) -> AhaDiscoveryRegistration {
    let secret = SecretReference::from_handle("opaque-token-never-retained", scope).unwrap();
    service
        .register(
            "registration-1",
            scope.clone(),
            secret,
            PermissionSnapshot::layer1_read_only(),
            provider,
            fence.clone(),
            1,
        )
        .unwrap()
}

fn proposal_fixture(
    scope: &AhaDiscoveryScope,
    fence: &EvidenceFence,
    label: &str,
) -> (
    AhaDiscoveryProvider<FixtureAhaDiscoveryTransport>,
    AhaDiscoveryRequest,
) {
    let request = request(scope, fence, None);
    let page = AhaDiscoveryPage::new(
        &request,
        None,
        vec![study_projection(
            scope.study_id.as_ref().unwrap().as_str(),
            label,
        )],
    )
    .unwrap();
    let transport = FixtureAhaDiscoveryTransport::new(page).unwrap();
    (AhaDiscoveryProvider::new(transport).unwrap(), request)
}

#[test]
fn fixture_produces_bounded_partial_redacted_proposal() {
    let scope = exact_scope();
    let fence = fence(1);
    let (provider, request) = proposal_fixture(
        &scope,
        &fence,
        "Customer cohort alice@example.com 13800138000",
    );
    let provider_definition = provider.definition().clone();
    let mut service = AhaDiscoveryResultService::new();
    let registration = register(&mut service, &scope, &provider_definition, &fence);
    let proposal = service
        .propose(&provider, registration.id(), request)
        .unwrap();

    assert_eq!(proposal.state, InsightState::Present);
    assert!(proposal.review_only);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert_eq!(proposal.page.items.len(), 1);
    let serialized = serde_json::to_string(&proposal).unwrap();
    assert!(serialized.contains("[REDACTED_EMAIL]"));
    assert!(serialized.contains("[REDACTED_NUMBER]"));
    assert!(!serialized.contains("alice@example.com"));
    assert!(!serialized.contains("13800138000"));

    let mut consumer = MissionAhaDiscoveryConsumer::new(scope, registration).unwrap();
    let result = consumer.consume(&proposal).unwrap();
    assert!(!result.can_be_adopted());
    assert!(result.review_only);
    let first = consumer.record(&proposal, "mission-record-1").unwrap();
    let replay = consumer.record(&proposal, "mission-record-1").unwrap();
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn deterministic_projection_order_is_stable() {
    let scope = exact_scope();
    let fence = fence(1);
    let request = request(&scope, &fence, None);
    let first = study_projection("study-1", "one");
    let second = study_projection("study-1", "one");
    let page_a = AhaDiscoveryPage::new(&request, None, vec![first]).unwrap();
    let page_b = AhaDiscoveryPage::new(&request, None, vec![second]).unwrap();
    assert_eq!(page_a.digest(), page_b.digest());
}

#[test]
fn secret_reference_is_opaque_and_scope_bound() {
    let scope = exact_scope();
    let other_scope = second_scope();
    let secret = SecretReference::from_handle("native-aha-token-private", &scope).unwrap();
    assert!(!format!("{secret:?}").contains("native-aha-token-private"));
    assert_eq!(secret.scope_digest(), &scope.digest());
    assert_eq!(
        secret.validate(&other_scope),
        Err(AhaDiscoveryResultError::SecretScopeMismatch)
    );

    let provider = AhaDiscoveryProviderDefinition::new(TransportProvenance::Fixture).unwrap();
    let registration = AhaDiscoveryRegistration::new(
        "registration-opaque",
        scope.clone(),
        secret,
        PermissionSnapshot::layer1_read_only(),
        &provider,
        fence(1),
        1,
    )
    .unwrap();
    let serialized = serde_json::to_string(&registration.redacted_projection()).unwrap();
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains("native-aha-token-private"));
}

#[test]
fn pagination_and_scope_bounds_are_adversarially_checked() {
    let scope = exact_scope();
    let fence = fence(1);
    assert_eq!(
        AhaDiscoveryRequest::new(
            scope.clone(),
            DiscoveryResource::Studies,
            AHA_DISCOVERY_MAX_PAGE_SIZE + 1,
            None,
            fence.clone(),
        ),
        Err(AhaDiscoveryResultError::InvalidPageSize)
    );
    assert_eq!(
        PageCursor::new("cursor with spaces"),
        Err(AhaDiscoveryResultError::InvalidCursor)
    );

    let request = request(&scope, &fence, None);
    assert_eq!(
        AhaDiscoveryPage::new(
            &request,
            None,
            vec![
                study_projection("study-1", "one"),
                study_projection("study-1", "two"),
                study_projection("study-1", "three"),
            ],
        ),
        Err(AhaDiscoveryResultError::PageBoundExceeded)
    );

    let provider = AhaDiscoveryProviderDefinition::new(TransportProvenance::Fixture).unwrap();
    let secret = SecretReference::from_handle("scope-bound", &scope).unwrap();
    assert_eq!(
        AhaDiscoveryRegistration::new(
            "wrong-scope",
            second_scope(),
            secret,
            PermissionSnapshot::layer1_read_only(),
            &provider,
            fence,
            1,
        ),
        Err(AhaDiscoveryResultError::SecretScopeMismatch)
    );
}

#[test]
fn stale_fence_and_blocked_provider_are_honest() {
    let scope = exact_scope();
    let registered_fence = fence(2);
    let stale_fence = fence(1);
    let (provider, stale_request) = proposal_fixture(&scope, &stale_fence, "stale study");
    let provider_definition = provider.definition().clone();
    let mut service = AhaDiscoveryResultService::new();
    let registration = register(
        &mut service,
        &scope,
        &provider_definition,
        &registered_fence,
    );
    let stale = service
        .propose(&provider, registration.id(), stale_request)
        .unwrap();
    assert_eq!(stale.state, InsightState::Stale);
    assert!(!stale.connected);
    assert!(!stale.native);
    assert!(!stale.first_party);

    let blocked = AhaDiscoveryProvider::new(BlockedEnvTransport).unwrap();
    let blocked_definition = blocked.definition().clone();
    let mut blocked_service = AhaDiscoveryResultService::new();
    let blocked_registration = register(
        &mut blocked_service,
        &scope,
        &blocked_definition,
        &registered_fence,
    );
    let blocked_request = request(&scope, &registered_fence, None);
    let unknown = blocked_service
        .propose(&blocked, blocked_registration.id(), blocked_request)
        .unwrap();
    assert_eq!(unknown.state, InsightState::ProviderUnknown);
    assert_eq!(unknown.provenance, TransportProvenance::BlockedEnv);
    assert!(!unknown.connected);
    assert!(!unknown.native);
    assert!(!unknown.first_party);
}

#[test]
fn proposal_scope_redaction_and_digest_tamper_are_rejected() {
    let scope = exact_scope();
    let fence = fence(1);
    let (provider, request) = proposal_fixture(&scope, &fence, "safe label");
    let provider_definition = provider.definition().clone();
    let mut service = AhaDiscoveryResultService::new();
    let registration = register(&mut service, &scope, &provider_definition, &fence);
    let proposal = service
        .propose(&provider, registration.id(), request)
        .unwrap();

    let mut digest_tampered = proposal.clone();
    digest_tampered.page.page_digest = Digest::from_text("tampered-page");
    assert_eq!(
        digest_tampered.validate_integrity(),
        Err(AhaDiscoveryResultError::DigestMismatch)
    );

    let mut flag_tampered = proposal.clone();
    flag_tampered.connected = true;
    assert_eq!(
        flag_tampered.validate_integrity(),
        Err(AhaDiscoveryResultError::TamperedEvidence)
    );

    let mut scope_tampered = proposal;
    scope_tampered.scope_digest = Digest::from_text("other-scope");
    assert_eq!(
        scope_tampered.validate_integrity(),
        Err(AhaDiscoveryResultError::TamperedEvidence)
    );
}

#[test]
fn recording_replay_conflict_is_idempotent_and_bounded() {
    let scope = exact_scope();
    let fence = fence(1);
    let request_one = request(&scope, &fence, None);
    let request_two = request(
        &scope,
        &fence,
        Some(PageCursor::new("opaque-page-2").unwrap()),
    );
    let page_one = AhaDiscoveryPage::new(
        &request_one,
        None,
        vec![study_projection("study-1", "first")],
    )
    .unwrap();
    let page_two = AhaDiscoveryPage::new(
        &request_two,
        None,
        vec![study_projection("study-1", "second")],
    )
    .unwrap();
    let recording = RecordingAhaDiscoveryTransport::from_pages([page_one, page_two]).unwrap();
    assert_eq!(recording.page_count(), 2);
    let provider = AhaDiscoveryProvider::new(recording).unwrap();
    let provider_definition = provider.definition().clone();
    let mut service = AhaDiscoveryResultService::new();
    let registration = register(&mut service, &scope, &provider_definition, &fence);
    let proposal_one = service
        .propose(&provider, registration.id(), request_one)
        .unwrap();
    let proposal_two = service
        .propose(&provider, registration.id(), request_two)
        .unwrap();
    let mut consumer = MissionAhaDiscoveryConsumer::new(scope, registration).unwrap();

    consumer.record(&proposal_one, "same-key").unwrap();
    let replay = consumer.record(&proposal_one, "same-key").unwrap();
    assert!(replay.replayed);
    assert_eq!(
        consumer.record(&proposal_two, "same-key"),
        Err(AhaDiscoveryResultError::RecordingConflict)
    );
}

#[test]
fn revocation_is_digest_bound_and_restorable() {
    let scope = exact_scope();
    let fence = fence(1);
    let (provider, request) = proposal_fixture(&scope, &fence, "revocable");
    let provider_definition = provider.definition().clone();
    let mut service = AhaDiscoveryResultService::new();
    let registration = register(&mut service, &scope, &provider_definition, &fence);
    let active_digest = registration.registration_digest().clone();
    let transition = service.revoke(registration.id()).unwrap();
    assert_eq!(transition.new_status, RegistrationStatus::Revoked);
    let revoked = service.registration(registration.id()).unwrap().clone();
    assert_ne!(revoked.registration_digest(), &active_digest);

    let revoked_proposal = service
        .propose(&provider, registration.id(), request.clone())
        .unwrap();
    assert_eq!(revoked_proposal.state, InsightState::Revoked);
    assert!(matches!(
        MissionAhaDiscoveryConsumer::new(scope.clone(), revoked),
        Err(AhaDiscoveryResultError::RegistrationInactive)
    ));

    let restored_transition = service.restore(registration.id()).unwrap();
    assert_eq!(restored_transition.new_status, RegistrationStatus::Active);
    let restored = service.registration(registration.id()).unwrap().clone();
    assert_eq!(restored.registration_digest(), &active_digest);
    let consumer = MissionAhaDiscoveryConsumer::new(scope, restored).unwrap();
    assert_eq!(
        consumer.consume(&revoked_proposal),
        Err(AhaDiscoveryResultError::ScopeMismatch)
    );
}

#![allow(clippy::too_many_lines)]

use hartevo_intercom_conversation_result_plugin::{
    BLOCKED_ENV, CONTRACT_SCHEMA, ConversationDecisionDisposition, Digest,
    IntercomConversationPage, IntercomConversationPart, IntercomConversationResultService,
    IntercomConversationScope, IntercomConversationSnapshot, IntercomConversationState,
    IntercomConversationStatus, IntercomOperation, IntercomPage, IntercomPartKind, IntercomPayload,
    IntercomPermission, IntercomProvider, IntercomReadRequest, IntercomRegistration,
    IntercomRegistrationRegistry, IntercomTransportError, IntercomWorkspaceIdentity,
    MAX_CURSOR_AGE_SECONDS, MAX_CURSOR_BYTES, MAX_PAGE_ITEMS, MAX_RESPONSE_BYTES,
    MissionIntercomConversationConsumer, MissionScopeBinding, ReadLimits, RedactionEvidence,
    RegistrationStatus, SecretReference, TransportProvenance,
};

const OBSERVED_AT: u64 = 1_750_000_000;

fn scope() -> IntercomConversationScope {
    IntercomConversationScope::new(
        IntercomWorkspaceIdentity::new("workspace-acme", 2).expect("workspace"),
        hartevo_intercom_conversation_result_plugin::IntercomConversationIdentity::new(
            "conversation-427",
            4,
        )
        .expect("conversation"),
        hartevo_intercom_conversation_result_plugin::ConversationResolutionObjective::new(
            "resolve-customer-conversation",
            5,
        )
        .expect("objective"),
        MissionScopeBinding::new(
            "project-support",
            "mission-427",
            "work-product-conversation-resolution",
            10,
            11,
            12,
            Digest::from_text("policy-digest"),
            Digest::from_text("consent-digest"),
        )
        .expect("Mission binding"),
        [
            IntercomPermission::WorkspaceRead,
            IntercomPermission::ConversationRead,
            IntercomPermission::ConversationPartsRead,
            IntercomPermission::AssignmentRead,
            IntercomPermission::MissionScope,
        ],
    )
    .expect("scope")
}

fn enqueue_fixture(
    transport: &mut hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport,
    state: IntercomConversationState,
) {
    let current_scope = scope();
    transport.push_conversation_response(Ok(IntercomPayload::new(
        IntercomOperation::ReadConversation,
        IntercomConversationSnapshot::for_scope(&current_scope, state),
    )));
    transport.push_parts_page(Ok(IntercomPage::new(
        IntercomOperation::ReadConversationParts,
        0,
        None,
        None,
        vec![IntercomConversationPart::for_scope(
            &current_scope,
            "part-1",
            IntercomPartKind::Reply,
        )],
    )));
}

fn service_with_transport(
    transport: hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport,
) -> IntercomConversationResultService<
    hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport,
> {
    let current_scope = scope();
    let secret = SecretReference::access_token("opaque-access-token", &current_scope, 9)
        .expect("opaque access token");
    IntercomConversationResultService::new(IntercomProvider::new(transport), current_scope, secret)
        .expect("service")
}

fn evidence(
    service: &mut IntercomConversationResultService<
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport,
    >,
) -> hartevo_intercom_conversation_result_plugin::IntercomConversationEvidence {
    service
        .read_conversation_evidence(IntercomReadRequest::for_scope(service.scope(), OBSERVED_AT))
        .expect("conversation evidence")
}

#[test]
fn happy_path_binds_conversation_result_and_mission_fences() {
    let mut transport =
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::new(
            TransportProvenance::Recording,
        );
    enqueue_fixture(&mut transport, IntercomConversationState::Closed);
    let mut service = service_with_transport(transport);
    let evidence = evidence(&mut service);
    assert_eq!(evidence.state, IntercomConversationState::Closed);
    assert_eq!(evidence.status, IntercomConversationStatus::Closed);
    assert!(evidence.complete);
    assert!(!evidence.partial);
    assert_eq!(evidence.pages_read, 1);
    assert!(evidence.conversation_digest.is_valid());
    assert!(evidence.parts_digest.is_valid());
    assert!(!evidence.provenance.connected);
    assert!(!evidence.provenance.native);
    assert!(!evidence.provenance.first_party);

    let proposal = service
        .compile_adoption_proposal(&evidence)
        .expect("adoption proposal");
    assert_eq!(
        proposal.decision,
        ConversationDecisionDisposition::ReviewNextMissionDecision
    );
    assert!(!proposal.adopted);
    assert!(!proposal.connected);
    assert!(proposal.proposal_digest.is_valid());

    let recording = service
        .record_conversation_receipt(&evidence)
        .expect("recording");
    assert!(!recording.replayed);
    assert!(!recording.durable);
    recording
        .validate(&evidence, service.registration())
        .expect("recording integrity");
    assert!(
        service
            .record_conversation_receipt(&evidence)
            .expect("recording replay")
            .replayed
    );

    let verification = service
        .verify_conversation_evidence(&evidence)
        .expect("verification");
    assert!(verification.conversation_verified);
    assert!(verification.parts_verified);
    assert!(verification.redaction_verified);
    assert!(verification.registration_verified);

    let mut consumer = MissionIntercomConversationConsumer::new(service.scope()).expect("consumer");
    let mission_record = consumer.consume(&proposal).expect("consumer proposal");
    assert_eq!(
        mission_record.disposition,
        hartevo_intercom_conversation_result_plugin::MissionConsumptionDisposition::Fresh
    );
    assert!(!mission_record.adopted);
    assert!(!mission_record.connected);
    assert_eq!(
        consumer
            .consume(&proposal)
            .expect("consumer replay")
            .disposition,
        hartevo_intercom_conversation_result_plugin::MissionConsumptionDisposition::Replay
    );
}

#[test]
fn secret_is_opaque_and_registration_is_reversible_and_revocable() {
    let current_scope = scope();
    let secret = SecretReference::oauth("oauth-secret-material", &current_scope, 13)
        .expect("OAuth reference");
    let debug = format!("{secret:?}");
    let serialized = serde_json::to_string(&secret).expect("secret serialization");
    assert!(!debug.contains("oauth-secret-material"));
    assert!(!serialized.contains("oauth-secret-material"));
    assert!(serialized.contains("referenceDigest"));

    let registration = IntercomRegistration::new(&current_scope, &secret).expect("registration");
    let registration_id = registration.registration_digest.clone();
    let mut registry = IntercomRegistrationRegistry::default();
    assert_eq!(
        registry.register(registration).expect("register").status,
        RegistrationStatus::Active
    );
    registry
        .get_mut(&registration_id)
        .expect("registered")
        .unmount()
        .expect("unmount");
    assert_eq!(
        registry.restore(&registration_id).expect("restore").to,
        RegistrationStatus::Active
    );
    let mut secret = secret;
    let revoked = registry
        .revoke(&registration_id, &mut secret)
        .expect("revoke");
    assert!(revoked.secret_revoked);
    assert!(secret.is_revoked());
    assert_eq!(
        registry.reverse(&registration_id).expect("reverse").to,
        RegistrationStatus::Reversed
    );
}

#[test]
fn bounded_pages_deduplicate_replays_and_expire_cursors() {
    let current_scope = scope();
    let mut transport =
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::loopback();
    transport.push_conversation_response(Ok(IntercomPayload::new(
        IntercomOperation::ReadConversation,
        IntercomConversationSnapshot::for_scope(&current_scope, IntercomConversationState::Open),
    )));
    let first =
        IntercomConversationPart::for_scope(&current_scope, "part-1", IntercomPartKind::Reply);
    let second =
        IntercomConversationPart::for_scope(&current_scope, "part-2", IntercomPartKind::Note);
    transport.push_parts_page(Ok(IntercomPage::new(
        IntercomOperation::ReadConversationParts,
        0,
        None,
        Some("cursor-1".into()),
        vec![first.clone()],
    )
    .with_cursor_issued_at(OBSERVED_AT)));
    transport.push_parts_page(Ok(IntercomConversationPage::new(
        IntercomOperation::ReadConversationParts,
        1,
        Some("cursor-1".into()),
        None,
        vec![first, second],
    )
    .with_cursor_issued_at(OBSERVED_AT)));
    let mut service = service_with_transport(transport);
    let result = evidence(&mut service);
    assert_eq!(result.pages_read, 2);
    assert_eq!(result.parts_read, 2);
    assert_eq!(result.duplicate_parts_dropped, 1);
    assert_eq!(result.provenance.transport, TransportProvenance::Loopback);

    let mut expired_transport =
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::recording();
    expired_transport.push_conversation_response(Ok(IntercomPayload::new(
        IntercomOperation::ReadConversation,
        IntercomConversationSnapshot::for_scope(&current_scope, IntercomConversationState::Open),
    )));
    expired_transport.push_parts_page(Ok(IntercomPage::new(
        IntercomOperation::ReadConversationParts,
        0,
        None,
        None,
        Vec::<IntercomConversationPart>::new(),
    )
    .with_cursor_issued_at(OBSERVED_AT - MAX_CURSOR_AGE_SECONDS - 1)));
    let mut expired = service_with_transport(expired_transport);
    assert_eq!(
        expired
            .read_conversation_evidence(IntercomReadRequest::for_scope(
                expired.scope(),
                OBSERVED_AT
            ))
            .expect_err("expired cursor accepted"),
        hartevo_intercom_conversation_result_plugin::IntercomError::PaginationExpired
    );
}

#[test]
fn redaction_partial_tamper_and_provider_failures_fail_closed() {
    let current_scope = scope();
    let mut redacted =
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::recording();
    redacted.push_conversation_response(Ok(IntercomPayload::new(
        IntercomOperation::ReadConversation,
        IntercomConversationSnapshot::for_scope(&current_scope, IntercomConversationState::Open),
    )
    .with_metadata(
        10,
        true,
        RedactionEvidence {
            raw_message_bodies_retained: true,
            ..RedactionEvidence::default()
        },
    )));
    let mut redacted_service = service_with_transport(redacted);
    assert_eq!(
        redacted_service
            .read_conversation_evidence(IntercomReadRequest::for_scope(
                redacted_service.scope(),
                OBSERVED_AT,
            ))
            .expect_err("raw body accepted"),
        hartevo_intercom_conversation_result_plugin::IntercomError::RedactionViolation
    );

    let mut partial =
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::recording();
    partial.push_conversation_response(Ok(IntercomPayload::new(
        IntercomOperation::ReadConversation,
        IntercomConversationSnapshot::for_scope(&current_scope, IntercomConversationState::Open),
    )
    .with_metadata(10, false, RedactionEvidence::default())));
    let mut partial_service = service_with_transport(partial);
    assert_eq!(
        partial_service
            .read_conversation_evidence(IntercomReadRequest::for_scope(
                partial_service.scope(),
                OBSERVED_AT,
            ))
            .expect_err("partial response accepted"),
        hartevo_intercom_conversation_result_plugin::IntercomError::PartialResponse
    );

    let mut tampered =
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::recording();
    tampered.push_conversation_response(Ok(IntercomPayload::new(
        IntercomOperation::ReadConversation,
        IntercomConversationSnapshot::for_scope(&current_scope, IntercomConversationState::Open),
    )));
    let mut page = IntercomPage::new(
        IntercomOperation::ReadConversationParts,
        0,
        None,
        None,
        Vec::<IntercomConversationPart>::new(),
    );
    page.next_cursor = Some("tampered-cursor".into());
    tampered.push_parts_page(Ok(page));
    let mut tampered_service = service_with_transport(tampered);
    assert_eq!(
        tampered_service
            .read_conversation_evidence(IntercomReadRequest::for_scope(
                tampered_service.scope(),
                OBSERVED_AT,
            ))
            .expect_err("tampered page accepted"),
        hartevo_intercom_conversation_result_plugin::IntercomError::PaginationTampered
    );

    for (status, projection) in [
        (401, IntercomConversationState::AccessLoss),
        (403, IntercomConversationState::AccessLoss),
        (404, IntercomConversationState::ProviderUnknown),
        (409, IntercomConversationState::ProviderUnknown),
        (429, IntercomConversationState::ProviderUnknown),
        (500, IntercomConversationState::ProviderUnknown),
        (503, IntercomConversationState::ProviderUnknown),
    ] {
        let transport =
            hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::recording()
                .with_failure(IntercomTransportError::HttpStatus {
                    status,
                    retry_after_seconds: (status == 429).then_some(3),
                });
        let mut service = service_with_transport(transport);
        let error = service
            .read_conversation_evidence(IntercomReadRequest::for_scope(
                service.scope(),
                OBSERVED_AT,
            ))
            .expect_err("HTTP error accepted");
        assert_eq!(error.http_status(), Some(status));
        assert_eq!(service.projection_for_error(&error), projection);
    }

    let mut blocked = service_with_transport(
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::blocked_env(),
    );
    let error = blocked
        .read_conversation_evidence(IntercomReadRequest::for_scope(blocked.scope(), OBSERVED_AT))
        .expect_err("BLOCKED_ENV accepted");
    assert_eq!(
        error,
        hartevo_intercom_conversation_result_plugin::IntercomError::BlockedEnv
    );
    assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
    assert_eq!(
        blocked.provider().provenance(),
        TransportProvenance::BlockedEnv
    );
}

#[test]
fn closed_reopened_assignment_and_scope_drift_are_classified() {
    let mut transport =
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::fake();
    enqueue_fixture(&mut transport, IntercomConversationState::Closed);
    enqueue_fixture(&mut transport, IntercomConversationState::Reopened);
    let current_scope = scope();
    transport.push_conversation_response(Ok(IntercomPayload::new(
        IntercomOperation::ReadConversation,
        IntercomConversationSnapshot::for_scope(&current_scope, IntercomConversationState::Open)
            .with_assignment(Some("new-assignee".into()), Some("new-team".into())),
    )));
    transport.push_parts_page(Ok(IntercomPage::new(
        IntercomOperation::ReadConversationParts,
        0,
        None,
        None,
        Vec::new(),
    )));
    let mut service = service_with_transport(transport);
    assert_eq!(
        evidence(&mut service).state,
        IntercomConversationState::Closed
    );
    assert_eq!(
        evidence(&mut service).state,
        IntercomConversationState::Reopened
    );
    assert_eq!(
        evidence(&mut service).state,
        IntercomConversationState::AssignmentChanged
    );

    let mut drifted =
        IntercomConversationSnapshot::for_scope(&current_scope, IntercomConversationState::Open);
    drifted.conversation.revision += 1;
    drifted.reseal();
    let mut drift_transport =
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::recording();
    drift_transport.push_conversation_response(Ok(IntercomPayload::new(
        IntercomOperation::ReadConversation,
        drifted,
    )));
    let mut drift_service = service_with_transport(drift_transport);
    assert_eq!(
        drift_service
            .read_conversation_evidence(IntercomReadRequest::for_scope(
                drift_service.scope(),
                OBSERVED_AT,
            ))
            .expect_err("conversation revision drift accepted"),
        hartevo_intercom_conversation_result_plugin::IntercomError::RevisionDrift
    );
}

#[test]
fn public_limits_and_contract_definition_are_closed() {
    assert_eq!(MAX_CURSOR_BYTES, 512);
    assert_eq!(MAX_PAGE_ITEMS, 100);
    assert_eq!(MAX_RESPONSE_BYTES, 2 * 1024 * 1024);
    assert_eq!(CONTRACT_SCHEMA, "hartevo.intercom-conversation-result/v1");
    assert!(
        IntercomProvider::with_limits(
            hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport::recording(),
            ReadLimits {
                max_page_items: MAX_PAGE_ITEMS + 1,
                ..ReadLimits::default()
            },
        )
        .is_err()
    );
    let definition = IntercomConversationResultService::<
        hartevo_intercom_conversation_result_plugin::RecordingIntercomTransport,
    >::definition();
    assert_eq!(definition.layer, 1);
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(definition.recording_only);
    assert!(!definition.connected);
    assert!(!definition.native);
    assert!(!definition.first_party);
}

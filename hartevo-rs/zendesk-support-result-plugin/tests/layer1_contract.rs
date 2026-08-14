use hartevo_zendesk_support_result_plugin::{
    AuditTransitionKind, CustomerResolutionObjective, Digest, FakeZendeskTransport,
    LoopbackZendeskTransport, MAX_AUDIT_TRANSITIONS, MAX_CURSOR_BYTES, MAX_PAGE_ITEMS,
    MAX_RESPONSE_BYTES, MissionConsumptionDisposition, MissionScopeBinding,
    MissionZendeskSupportConsumer, ReadLimits, RecordingZendeskTransport, RedactionEvidence,
    RegistrationStatus, SecretReference, SlaTargetState, SupportDecisionDisposition,
    TransportProvenance, VerificationProjection, ZendeskAccountIdentity, ZendeskAuditIdentity,
    ZendeskAuditTransition, ZendeskError, ZendeskMetricIdentity, ZendeskOperation,
    ZendeskOrganizationIdentity, ZendeskPage, ZendeskPayload, ZendeskPermission,
    ZendeskReadRequest, ZendeskRequesterIdentity, ZendeskSatisfactionSummary,
    ZendeskServiceDefinition, ZendeskSlaIdentity, ZendeskSlaTargetSnapshot,
    ZendeskSupportResultService, ZendeskSupportScope, ZendeskTicketIdentity, ZendeskTicketMetric,
    ZendeskTicketSnapshot, ZendeskTicketStatus, ZendeskTransport, ZendeskTransportError,
};

const OBSERVED_AT: u64 = 1_750_000_000;

fn scope() -> ZendeskSupportScope {
    ZendeskSupportScope::new(
        ZendeskAccountIdentity::new("acme", "account-acme", 2).expect("account"),
        ZendeskTicketIdentity::new(39701, 4).expect("ticket"),
        ZendeskRequesterIdentity::new(39702, 3).expect("requester"),
        ZendeskOrganizationIdentity::new(Some(39703), 2).expect("organization"),
        ZendeskSlaIdentity::new(Some(39704), 5).expect("SLA"),
        ZendeskMetricIdentity::new(39705, 6).expect("metric"),
        ZendeskAuditIdentity::new(None, 7).expect("audit"),
        CustomerResolutionObjective::new("resolve-customer-ticket", 8).expect("objective"),
        MissionScopeBinding::new(
            "project-support",
            "mission-397",
            "work-product-resolution",
            10,
            11,
            12,
            Digest::from_text("policy-digest"),
            Digest::from_text("consent-digest"),
        )
        .expect("Mission binding"),
        [
            ZendeskPermission::AccountRead,
            ZendeskPermission::TicketRead,
            ZendeskPermission::RequesterRead,
            ZendeskPermission::OrganizationRead,
            ZendeskPermission::SlaRead,
            ZendeskPermission::MetricRead,
            ZendeskPermission::AuditRead,
            ZendeskPermission::SatisfactionRead,
            ZendeskPermission::MissionScope,
        ],
    )
    .expect("scope")
}

fn enqueue_fixture(transport: &mut RecordingZendeskTransport, status: ZendeskTicketStatus) {
    let current_scope = scope();
    transport.push_ticket_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadTicket,
        ZendeskTicketSnapshot::for_scope(&current_scope, status),
    )));
    transport.push_sla_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadSlaTarget,
        ZendeskSlaTargetSnapshot::for_scope(&current_scope, SlaTargetState::Satisfied),
    )));
    transport.push_metric_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadTicketMetric,
        ZendeskTicketMetric::for_scope(&current_scope),
    )));
    let transition = ZendeskAuditTransition::new(
        current_scope.account.clone(),
        current_scope.ticket.clone(),
        39706,
        39707,
        current_scope.audit.revision,
        OBSERVED_AT,
        AuditTransitionKind::StatusChanged,
        Some(ZendeskTicketStatus::Open),
        Some(status),
        None,
        None,
    )
    .expect("audit transition");
    transport.push_audit_page(Ok(ZendeskPage::new(
        ZendeskOperation::ReadAuditEvents,
        0,
        None,
        None,
        vec![transition],
    )));
    transport.push_satisfaction_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadSatisfaction,
        ZendeskSatisfactionSummary::new(
            current_scope.account.clone(),
            current_scope.ticket.clone(),
            current_scope.requester.clone(),
            current_scope.organization.clone(),
            hartevo_zendesk_support_result_plugin::SatisfactionAvailability::Received,
            Some(hartevo_zendesk_support_result_plugin::SatisfactionScore::Good),
            Some(39708),
            true,
            Some(OBSERVED_AT),
            current_scope.ticket.revision,
        )
        .expect("satisfaction"),
    )));
}

fn queued_transport(
    status: ZendeskTicketStatus,
    provenance: TransportProvenance,
) -> RecordingZendeskTransport {
    let mut transport = RecordingZendeskTransport::new(provenance);
    enqueue_fixture(&mut transport, status);
    transport
}

fn enqueue_non_audit_fixture(
    transport: &mut RecordingZendeskTransport,
    status: ZendeskTicketStatus,
) {
    let current_scope = scope();
    transport.push_ticket_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadTicket,
        ZendeskTicketSnapshot::for_scope(&current_scope, status),
    )));
    transport.push_sla_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadSlaTarget,
        ZendeskSlaTargetSnapshot::for_scope(&current_scope, SlaTargetState::Satisfied),
    )));
    transport.push_metric_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadTicketMetric,
        ZendeskTicketMetric::for_scope(&current_scope),
    )));
    transport.push_satisfaction_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadSatisfaction,
        ZendeskSatisfactionSummary::new(
            current_scope.account.clone(),
            current_scope.ticket.clone(),
            current_scope.requester.clone(),
            current_scope.organization.clone(),
            hartevo_zendesk_support_result_plugin::SatisfactionAvailability::Received,
            Some(hartevo_zendesk_support_result_plugin::SatisfactionScore::Good),
            Some(39708),
            true,
            Some(OBSERVED_AT),
            current_scope.ticket.revision,
        )
        .expect("satisfaction"),
    )));
}

fn service_with_transport(
    transport: RecordingZendeskTransport,
) -> ZendeskSupportResultService<RecordingZendeskTransport> {
    let current_scope = scope();
    let secret = SecretReference::api_token("opaque-api-token", &current_scope, 9)
        .expect("opaque API token");
    ZendeskSupportResultService::new(
        hartevo_zendesk_support_result_plugin::ZendeskProvider::new(transport),
        current_scope,
        secret,
    )
    .expect("service")
}

fn evidence(
    service: &mut ZendeskSupportResultService<RecordingZendeskTransport>,
) -> hartevo_zendesk_support_result_plugin::ZendeskSupportEvidence {
    service
        .read_support_evidence(ZendeskReadRequest::for_scope(service.scope(), OBSERVED_AT))
        .expect("support evidence")
}

#[test]
fn happy_path_binds_ticket_resolution_evidence_and_fences_proposal() {
    let mut service = service_with_transport(queued_transport(
        ZendeskTicketStatus::Solved,
        TransportProvenance::Recording,
    ));
    let evidence = evidence(&mut service);
    assert_eq!(evidence.status, ZendeskTicketStatus::Solved);
    assert!(evidence.complete);
    assert!(!evidence.partial);
    assert_eq!(evidence.pages_read, 1);
    assert!(evidence.ticket_digest.is_valid());
    assert!(evidence.metric_digest.is_valid());
    assert!(evidence.audit_digest.is_valid());
    assert!(evidence.satisfaction_digest.is_valid());
    assert!(!evidence.provenance.connected);
    assert!(!evidence.provenance.native);
    assert!(!evidence.provenance.first_party);

    let proposal = service
        .compile_support_outcome_proposal(&evidence)
        .expect("proposal");
    assert_eq!(
        proposal.decision,
        SupportDecisionDisposition::ReviewNextMissionDecision
    );
    assert!(!proposal.adopted);
    assert!(!proposal.connected);
    assert!(proposal.proposal_digest.is_valid());

    let verification = service
        .verify_support_evidence(&evidence)
        .expect("verification");
    assert_verified(&verification);

    let recording = service
        .record_support_receipt(&evidence)
        .expect("recording");
    assert!(!recording.replayed);
    assert!(!recording.durable);
    recording
        .validate(&evidence, service.registration())
        .expect("recording integrity");

    let replay = service
        .record_support_receipt(&evidence)
        .expect("recording replay");
    assert!(replay.replayed);

    let mission_consumer =
        &mut MissionZendeskSupportConsumer::new(service.scope()).expect("consumer");
    let mission_record = mission_consumer
        .consume(&proposal)
        .expect("consumer proposal");
    assert_eq!(
        mission_record.disposition,
        MissionConsumptionDisposition::Fresh
    );
    assert!(!mission_record.adopted);
    assert!(!mission_record.connected);
    assert_eq!(
        mission_consumer
            .consume(&proposal)
            .expect("consumer replay")
            .disposition,
        MissionConsumptionDisposition::Replay
    );
}

fn assert_verified(verification: &VerificationProjection) {
    assert!(verification.ticket_verified);
    assert!(verification.metric_verified);
    assert!(verification.audit_verified);
    assert!(verification.satisfaction_verified);
    assert!(verification.registration_verified);
    assert!(verification.bounded_evidence_verified);
    assert!(!verification.connected);
    assert!(!verification.native);
    assert!(!verification.first_party);
}

#[test]
fn secret_reference_is_opaque_and_registration_is_reversible_and_revocable() {
    let current_scope = scope();
    let secret = SecretReference::oauth("oauth-secret-material", &current_scope, 13)
        .expect("OAuth reference");
    let debug = format!("{secret:?}");
    let serialized = serde_json::to_string(&secret).expect("secret serialization");
    assert!(!debug.contains("oauth-secret-material"));
    assert!(!serialized.contains("oauth-secret-material"));
    assert!(serialized.contains("referenceDigest"));
    assert_eq!(
        secret.kind(),
        hartevo_zendesk_support_result_plugin::SecretReferenceKind::OAuth
    );

    let registration =
        hartevo_zendesk_support_result_plugin::ZendeskRegistration::new(&current_scope, &secret)
            .expect("registration");
    let registration_id = registration.registration_digest.clone();
    let mut registry =
        hartevo_zendesk_support_result_plugin::ZendeskRegistrationRegistry::default();
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
fn cursor_and_incremental_audit_pages_deduplicate_replays() {
    let current_scope = scope();
    let mut transport = RecordingZendeskTransport::new(TransportProvenance::Loopback);
    enqueue_non_audit_fixture(&mut transport, ZendeskTicketStatus::Solved);
    let first = ZendeskAuditTransition::status_change(
        &current_scope,
        39706,
        39707,
        ZendeskTicketStatus::Open,
        ZendeskTicketStatus::Solved,
    )
    .expect("first audit");
    let second = ZendeskAuditTransition::new(
        current_scope.account.clone(),
        current_scope.ticket.clone(),
        39706,
        39708,
        current_scope.audit.revision,
        OBSERVED_AT + 1,
        AuditTransitionKind::SlaTargetChanged,
        None,
        None,
        Some(SlaTargetState::Satisfied),
        None,
    )
    .expect("second audit");
    transport.push_audit_page(Ok(ZendeskPage::new(
        ZendeskOperation::ReadAuditEvents,
        0,
        None,
        Some("cursor-1".into()),
        vec![first.clone()],
    )
    .with_incremental(true)));
    transport.push_audit_page(Ok(ZendeskPage::new(
        ZendeskOperation::ReadAuditEvents,
        1,
        Some("cursor-1".into()),
        None,
        vec![first, second],
    )
    .with_incremental(true)));
    let mut service = service_with_transport(transport);
    let request = ZendeskReadRequest::for_scope(service.scope(), OBSERVED_AT)
        .incremental_since(OBSERVED_AT - 60);
    let result = service
        .read_support_evidence(request)
        .expect("incremental evidence");
    assert_eq!(result.audit.pages_read, 2);
    assert_eq!(result.audit.transitions.len(), 2);
    assert_eq!(result.audit.duplicate_events_dropped, 1);
    assert!(result.audit.incremental);
    assert_eq!(result.provenance.transport, TransportProvenance::Loopback);
}

#[test]
fn status_reopen_transition_is_allowed_and_invalid_reversal_is_rejected() {
    let mut transport = queued_transport(ZendeskTicketStatus::Solved, TransportProvenance::Fake);
    enqueue_fixture(&mut transport, ZendeskTicketStatus::Reopened);
    enqueue_fixture(&mut transport, ZendeskTicketStatus::Open);
    let mut service = service_with_transport(transport);
    assert_eq!(evidence(&mut service).status, ZendeskTicketStatus::Solved);
    assert_eq!(evidence(&mut service).status, ZendeskTicketStatus::Reopened);
    assert_eq!(evidence(&mut service).status, ZendeskTicketStatus::Open);

    assert!(ZendeskTicketStatus::Solved.can_follow(ZendeskTicketStatus::Reopened));
    assert!(!ZendeskTicketStatus::Solved.can_follow(ZendeskTicketStatus::New));
}

#[test]
fn malformed_partial_redacted_and_oversized_responses_fail_closed() {
    let current_scope = scope();
    let mut redacted = RecordingZendeskTransport::recording();
    redacted.push_ticket_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadTicket,
        ZendeskTicketSnapshot::for_scope(&current_scope, ZendeskTicketStatus::Open),
    )
    .with_metadata(
        10,
        true,
        RedactionEvidence {
            raw_comments_retained: true,
            ..RedactionEvidence::default()
        },
    )));
    let mut service = service_with_transport(redacted);
    let error = service
        .read_support_evidence(ZendeskReadRequest::for_scope(service.scope(), OBSERVED_AT))
        .expect_err("raw comments accepted");
    assert_eq!(error, ZendeskError::RedactionViolation);
    assert_eq!(
        service.projection_for_error(&error),
        ZendeskTicketStatus::Partial
    );

    let mut partial = RecordingZendeskTransport::recording();
    partial.push_ticket_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadTicket,
        ZendeskTicketSnapshot::for_scope(&current_scope, ZendeskTicketStatus::Open),
    )
    .with_metadata(10, false, RedactionEvidence::default())));
    let mut partial_service = service_with_transport(partial);
    assert_eq!(
        partial_service
            .read_support_evidence(ZendeskReadRequest::for_scope(
                partial_service.scope(),
                OBSERVED_AT,
            ))
            .expect_err("partial response accepted"),
        ZendeskError::PartialResponse
    );

    let limits = ReadLimits {
        max_response_bytes: 64,
        ..ReadLimits::default()
    };
    assert!(
        hartevo_zendesk_support_result_plugin::ZendeskProvider::with_limits(
            RecordingZendeskTransport::recording(),
            limits,
        )
        .is_ok()
    );
    assert_eq!(
        ReadLimits {
            max_page_items: MAX_PAGE_ITEMS + 1,
            ..ReadLimits::default()
        }
        .validate()
        .expect_err("invalid page limit"),
        ZendeskError::InvalidLimits
    );
    assert_eq!(MAX_RESPONSE_BYTES, 2 * 1024 * 1024);
    assert_eq!(MAX_CURSOR_BYTES, 512);
    assert_eq!(MAX_AUDIT_TRANSITIONS, 1024);
}

#[test]
fn http_status_timeout_and_blocked_environment_are_honest() {
    for (status, projection) in [
        (401, ZendeskTicketStatus::AccessLoss),
        (403, ZendeskTicketStatus::AccessLoss),
        (404, ZendeskTicketStatus::ProviderUnknown),
        (409, ZendeskTicketStatus::ProviderUnknown),
        (429, ZendeskTicketStatus::ProviderUnknown),
        (500, ZendeskTicketStatus::ProviderUnknown),
        (503, ZendeskTicketStatus::ProviderUnknown),
    ] {
        let mut transport = RecordingZendeskTransport::recording();
        transport.fail_with(ZendeskTransportError::HttpStatus {
            status,
            retry_after_seconds: (status == 429).then_some(3),
        });
        let mut service = service_with_transport(transport);
        let error = service
            .read_support_evidence(ZendeskReadRequest::for_scope(service.scope(), OBSERVED_AT))
            .expect_err("HTTP error accepted");
        assert_eq!(error.http_status(), Some(status));
        assert_eq!(service.projection_for_error(&error), projection);
    }

    let mut blocked = service_with_transport(RecordingZendeskTransport::blocked_env());
    let error = blocked
        .read_support_evidence(ZendeskReadRequest::for_scope(blocked.scope(), OBSERVED_AT))
        .expect_err("BLOCKED_ENV accepted");
    assert_eq!(error, ZendeskError::BlockedEnv);
    assert_eq!(
        blocked.provider().provenance(),
        TransportProvenance::BlockedEnv
    );

    let mut timed_out = service_with_transport(
        RecordingZendeskTransport::recording().with_failure(ZendeskTransportError::Timeout),
    );
    let error = timed_out
        .read_support_evidence(ZendeskReadRequest::for_scope(
            timed_out.scope(),
            OBSERVED_AT,
        ))
        .expect_err("timeout accepted");
    assert_eq!(error, ZendeskError::Timeout);
}

#[test]
fn scope_drift_stale_mission_and_revocation_are_blocked() {
    let current_scope = scope();
    let mut drifted_ticket =
        ZendeskTicketSnapshot::for_scope(&current_scope, ZendeskTicketStatus::Solved);
    drifted_ticket.ticket.revision += 1;
    drifted_ticket.reseal();
    let mut transport = RecordingZendeskTransport::recording();
    transport.push_ticket_response(Ok(ZendeskPayload::new(
        ZendeskOperation::ReadTicket,
        drifted_ticket,
    )));
    let mut service = service_with_transport(transport);
    assert_eq!(
        service
            .read_support_evidence(ZendeskReadRequest::for_scope(&current_scope, OBSERVED_AT))
            .expect_err("ticket revision drift accepted"),
        ZendeskError::RevisionDrift
    );

    let mut healthy = service_with_transport(queued_transport(
        ZendeskTicketStatus::Solved,
        TransportProvenance::Recording,
    ));
    let healthy_evidence = evidence(&mut healthy);
    let proposal = healthy
        .compile_support_outcome_proposal(&healthy_evidence)
        .expect("proposal");
    let mut stale_scope = scope();
    stale_scope.mission.mission_revision += 1;
    let mut stale_consumer =
        MissionZendeskSupportConsumer::new(&stale_scope).expect("stale consumer");
    assert_eq!(
        stale_consumer
            .consume(&proposal)
            .expect_err("stale Mission accepted"),
        ZendeskError::StaleMissionRevision
    );

    healthy.revoke().expect("revoke service");
    assert!(matches!(
        healthy
            .read_support_evidence(ZendeskReadRequest::for_scope(healthy.scope(), OBSERVED_AT,))
            .expect_err("revoked service accepted"),
        ZendeskError::SecretRevoked | ZendeskError::RegistrationInactive
    ));
}

#[test]
fn public_definition_keeps_loopback_fake_recording_non_native() {
    let definition: ZendeskServiceDefinition =
        ZendeskSupportResultService::<RecordingZendeskTransport>::definition();
    assert_eq!(definition.layer, 1);
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(definition.recording_only);
    assert!(!definition.connected);
    assert!(!definition.native);
    assert!(!definition.first_party);
    assert_eq!(definition.allowed_provenance.len(), 4);
    assert!(!FakeZendeskTransport::fake().provenance().connected());
    assert!(!LoopbackZendeskTransport::loopback().provenance().native());
}

#[test]
fn satisfaction_unavailable_is_valid_without_comment_or_pii() {
    let current_scope = scope();
    let unavailable = ZendeskSatisfactionSummary::for_scope(
        &current_scope,
        hartevo_zendesk_support_result_plugin::SatisfactionAvailability::Unavailable,
    );
    assert_eq!(unavailable.score, None);
    assert!(!unavailable.comment_present);
    assert!(unavailable.validate().is_ok());
    let serialized = serde_json::to_string(&unavailable).expect("summary JSON");
    assert!(!serialized.contains("commentBody"));
}

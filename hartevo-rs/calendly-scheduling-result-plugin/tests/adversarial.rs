use hartevo_calendly_scheduling_result_plugin::{
    AuthMethod, CalendlyPage, CalendlyProvider, CalendlySchedulingResult,
    CalendlySchedulingResultError, CalendlySchedulingResultService, CalendlyScope,
    CalendlyScopeBinding, DateWindow, EventStatus, EventTypeProjection, EvidenceCompleteness,
    InviteeStatus, InviteeStatusProjection, LocationKind, MAX_WEBHOOK_AGE_MILLIS,
    MeetingResultState, MissionCalendlyMeetingConsumer, MissionContext, NoShowEvidence,
    OpaqueCalendlyUri, PROVIDER_REVISION, PageBudget, PermissionLease, ProviderError, ProviderMode,
    RedactedTrackingFields, RescheduleEvidence, ScheduledEventProjection, SecretReference,
    TrackingValues, UserProjection, WebhookChangeSignal, WebhookEventKind, WebhookReplayPolicy,
    contract_digest, validate_contract_document,
};

const NOW: u64 = 1_700_000_000_000;
const PROVIDER_REVISION_NUMBER: u64 = 7;

fn uri(path: &str) -> OpaqueCalendlyUri {
    OpaqueCalendlyUri::new(format!("https://api.calendly.com/{path}")).unwrap()
}

fn lease() -> PermissionLease {
    PermissionLease::required_read(3).unwrap()
}

fn scope(lease: &PermissionLease) -> CalendlyScope {
    let binding = CalendlyScopeBinding::new(
        "https://api.calendly.com/organizations/ORG1",
        "https://api.calendly.com/users/USER1",
        "https://api.calendly.com/event_types/TYPE1",
        "https://api.calendly.com/scheduled_events/EVENT1",
        "project-1",
        4,
        "mission-1",
        8,
        "work-product-1",
        12,
        16,
        DateWindow::new(NOW - 86_400_000, NOW + 86_400_000).unwrap(),
    )
    .unwrap();
    CalendlyScope::new(binding, lease.permission_digest().clone()).unwrap()
}

fn secret(scope: &CalendlyScope, lease: &PermissionLease) -> SecretReference {
    SecretReference::for_scope(
        "secret-ref-calendly-test",
        scope,
        lease,
        2,
        AuthMethod::OAuth21,
    )
    .unwrap()
}

fn page(
    scope: &CalendlyScope,
    lease: &PermissionLease,
    event_status: EventStatus,
    rescheduled: bool,
    no_show: bool,
    signal_kind: &str,
    next_cursor: Option<&str>,
    include_invitee: bool,
    signal_time: u64,
) -> CalendlyPage {
    let event_uri = scope.scheduled_event_uri().clone();
    let invitee_uri = uri("scheduled_events/EVENT1/invitees/INVITEE1");
    let reschedule = RescheduleEvidence::new(
        rescheduled,
        rescheduled.then(|| uri("scheduled_events/EVENT0/invitees/OLD")),
        rescheduled.then(|| invitee_uri.clone()),
    )
    .unwrap();
    let no_show_evidence = NoShowEvidence::new(
        no_show,
        no_show.then(|| uri("invitee_no_shows/NOSHOW1")),
        no_show.then_some(signal_time),
    )
    .unwrap();
    let tracking = RedactedTrackingFields::from_values(&TrackingValues::new(
        Some("source-sentinel"),
        Some("campaign-sentinel"),
        Some("medium-sentinel"),
        Some("content-sentinel"),
        Some("term-sentinel"),
        Some("salesforce-sentinel"),
    ))
    .unwrap();
    let event = ScheduledEventProjection::new(
        event_uri.clone(),
        scope.event_type_uri().clone(),
        event_status,
        NOW - 10_000,
        NOW + 10_000,
        "UTC",
        LocationKind::Online,
        if event_status == EventStatus::Canceled {
            hartevo_calendly_scheduling_result_plugin::CancellationActor::Invitee
        } else {
            hartevo_calendly_scheduling_result_plugin::CancellationActor::Unknown
        },
        (event_status == EventStatus::Canceled).then_some("cancellation-sentinel"),
        reschedule,
        no_show_evidence,
        tracking,
        scope.event_revision().get(),
        NOW - 2_000,
    )
    .unwrap();
    let invitee = InviteeStatusProjection::new(
        invitee_uri.clone(),
        if event_status == EventStatus::Canceled {
            InviteeStatus::Canceled
        } else {
            InviteeStatus::Active
        },
        no_show,
        NOW - 1_000,
    )
    .unwrap();
    let signal = WebhookChangeSignal::new(
        format!("delivery-calendly-{signal_time}"),
        signal_kind,
        event_uri,
        Some(invitee_uri),
        if event_status == EventStatus::Canceled {
            InviteeStatus::Canceled
        } else {
            InviteeStatus::Active
        },
        rescheduled,
        signal_time,
        signal_time + 100,
        b"email=invitee@example.com;reason=private-sentinel",
        Some(b"signature-sentinel"),
    )
    .unwrap();
    let invitees = if include_invitee {
        vec![invitee]
    } else {
        Vec::new()
    };
    CalendlyPage::new(
        hartevo_calendly_scheduling_result_plugin::OrganizationProjection::new(
            scope.organization_uri().clone(),
            Some("organization-name-sentinel"),
        )
        .unwrap(),
        UserProjection::new(scope.user_uri().clone(), Some("user-email-sentinel")).unwrap(),
        EventTypeProjection::new(
            scope.event_type_uri().clone(),
            Some(30),
            Some("event-name-sentinel"),
        )
        .unwrap(),
        event,
        invitees,
        vec![signal],
        next_cursor.map(|cursor| {
            hartevo_calendly_scheduling_result_plugin::PageCursor::new(cursor).unwrap()
        }),
        PROVIDER_REVISION_NUMBER,
        lease.permission_digest().clone(),
        2_048,
    )
    .unwrap()
}

fn service_with(
    event_status: EventStatus,
    rescheduled: bool,
    no_show: bool,
    signal_kind: &str,
) -> (
    CalendlySchedulingResultService<CalendlyProvider>,
    MissionContext,
) {
    let permission_lease = lease();
    let scope = scope(&permission_lease);
    let page = page(
        &scope,
        &permission_lease,
        event_status,
        rescheduled,
        no_show,
        signal_kind,
        None,
        true,
        NOW - 1_000,
    );
    let provider = CalendlyProvider::recording(vec![page], PROVIDER_REVISION_NUMBER).unwrap();
    let secret_reference = secret(&scope, &permission_lease);
    let service = CalendlySchedulingResultService::register(
        provider,
        scope.clone(),
        permission_lease,
        secret_reference,
    )
    .unwrap();
    let context = MissionContext::from_scope(&scope);
    (service, context)
}

#[test]
fn contract_is_versioned_and_honest() {
    validate_contract_document().unwrap();
    let digest = contract_digest().unwrap();
    assert_eq!(digest.as_str().len(), 64);
}

#[test]
fn typed_seams_and_provider_honesty_are_exposed() {
    let (service, context) = service_with(EventStatus::Active, false, false, "invitee.created");
    let description = service.describe_capabilities().unwrap();
    assert_eq!(
        description.service().service_id(),
        "calendly.scheduling-result.service"
    );
    assert_eq!(
        description.provider().provider_id(),
        "calendly.scheduling-result.provider"
    );
    assert_eq!(
        description.consumer().consumer_id(),
        "mission.calendly-meeting.consumer"
    );
    assert!(description.service().read_only());
    assert!(description.service().proposal_only());
    assert!(!description.service().external_writes());
    assert!(!description.calendar_authority());
    assert!(!description.booking_authority());
    assert!(!description.connected());
    assert!(!description.native());
    assert!(!description.first_party());
    assert!(!service.provider_state().can_claim_native_or_connected());
    assert_eq!(context.scope_digest(), service.scope().scope_digest());
    assert_eq!(PROVIDER_REVISION, "calendly-api-v2-layer1-r1");
}

#[test]
fn mission_consumer_emits_all_redacted_layer1_artifacts() {
    let (service, context) = service_with(EventStatus::Active, false, false, "invitee.created");
    let output = MissionCalendlyMeetingConsumer::new()
        .consume(&service, &context, NOW)
        .unwrap();
    assert_eq!(output.result().state(), MeetingResultState::Scheduled);
    assert_eq!(output.result().invitee_status_counts().active(), 1);
    assert!(output.result().is_non_mutating());
    assert!(!output.result().has_calendar_authority());
    assert!(!output.result().has_booking_authority());
    assert!(output.proposal().non_mutating());
    assert!(!output.proposal().external_write());
    assert!(!output.proposal().work_product_adopted());
    assert!(!output.proposal().outcome_adopted());
    assert!(!output.recording().raw_provider_payload_serialized());
    assert!(!output.recording().credential_material_serialized());
    assert!(!output.recording().invitee_pii_serialized());
    assert!(!output.recording().durable_native_receipt());
    assert!(!output.recording().independently_verified());
    let result_json = serde_json::to_string(output.result()).unwrap();
    let proposal_json = serde_json::to_string(output.proposal()).unwrap();
    let recording_json = serde_json::to_string(output.recording()).unwrap();
    for serialized in [result_json, proposal_json, recording_json] {
        assert!(!serialized.contains("invitee@example.com"));
        assert!(!serialized.contains("source-sentinel"));
        assert!(!serialized.contains("campaign-sentinel"));
        assert!(!serialized.contains("cancellation-sentinel"));
        assert!(!serialized.contains("signature-sentinel"));
        assert!(!serialized.contains("access_token"));
        assert!(!serialized.contains("Authorization"));
        assert!(!serialized.contains("join_url"));
    }
    let secret_debug = format!("{:?}", service.secret_reference());
    assert!(!secret_debug.contains("secret-ref-calendly-test"));
}

#[test]
fn missing_invitee_status_is_explicitly_partial() {
    let permission_lease = lease();
    let scope = scope(&permission_lease);
    let partial_page = page(
        &scope,
        &permission_lease,
        EventStatus::Active,
        false,
        false,
        "invitee.created",
        None,
        false,
        NOW - 1_000,
    );
    let service = CalendlySchedulingResultService::register(
        CalendlyProvider::fixture(vec![partial_page], PROVIDER_REVISION_NUMBER).unwrap(),
        scope.clone(),
        permission_lease.clone(),
        secret(&scope, &permission_lease),
    )
    .unwrap();
    let result = service
        .read_result(&MissionContext::from_scope(&scope), NOW)
        .unwrap();
    assert_eq!(result.state(), MeetingResultState::Scheduled);
    assert_eq!(result.completeness(), EvidenceCompleteness::Partial);
    assert_eq!(
        service
            .compile_adoption_proposal(&result)
            .unwrap()
            .completeness(),
        EvidenceCompleteness::Partial
    );
}

#[test]
fn scheduled_canceled_rescheduled_no_show_and_unknown_are_distinct() {
    let cases = [
        (
            EventStatus::Active,
            false,
            false,
            "invitee.created",
            MeetingResultState::Scheduled,
        ),
        (
            EventStatus::Canceled,
            false,
            false,
            "invitee.canceled",
            MeetingResultState::Canceled,
        ),
        (
            EventStatus::Canceled,
            true,
            false,
            "invitee.canceled",
            MeetingResultState::Rescheduled,
        ),
        (
            EventStatus::Active,
            false,
            true,
            "invitee_no_show.created",
            MeetingResultState::NoShow,
        ),
        (
            EventStatus::Unknown,
            false,
            false,
            "unknown.event",
            MeetingResultState::Unknown,
        ),
    ];
    for (event_status, rescheduled, no_show, signal_kind, expected) in cases {
        let (service, context) = service_with(event_status, rescheduled, no_show, signal_kind);
        let result = service.read_result(&context, NOW).unwrap();
        assert_eq!(result.state(), expected);
    }
}

#[test]
fn all_controlled_modes_stay_non_native_and_blocked_env_is_honest() {
    let permission_lease = lease();
    let scope = scope(&permission_lease);
    let modes = [
        ProviderMode::Fixture,
        ProviderMode::Recording,
        ProviderMode::Loopback,
    ];
    for mode in modes {
        let page = page(
            &scope,
            &permission_lease,
            EventStatus::Active,
            false,
            false,
            "invitee.created",
            None,
            true,
            NOW - 1_000,
        );
        let provider = CalendlyProvider::new(mode, vec![page], PROVIDER_REVISION_NUMBER).unwrap();
        assert!(!provider.state().connected());
        assert!(!provider.state().native());
        assert!(!provider.state().first_party());
        assert!(!provider.state().can_claim_native_or_connected());
    }
    let blocked = CalendlyProvider::blocked_env(PROVIDER_REVISION_NUMBER).unwrap();
    assert_eq!(blocked.mode(), ProviderMode::BlockedEnv);
    assert!(!blocked.state().connected());
    assert!(!blocked.state().native());
    assert!(!blocked.state().first_party());
}

#[test]
fn stale_revision_scope_and_revocation_fail_closed() {
    let (service, context) = service_with(EventStatus::Active, false, false, "invitee.created");
    let stale_context = MissionContext::new(
        "project-1",
        4,
        "mission-1",
        9,
        "work-product-1",
        12,
        16,
        service.scope().scope_digest().clone(),
    )
    .unwrap();
    assert_eq!(
        service.read_result(&stale_context, NOW),
        Err(CalendlySchedulingResultError::StaleMissionRevision)
    );
    let mut service = service;
    let receipt = service.revoke_registration(NOW).unwrap();
    assert!(receipt.reversible());
    assert!(receipt.provider_unmounted());
    assert!(receipt.secret_reference_revoked());
    assert_eq!(
        service.read_result(&context, NOW),
        Err(CalendlySchedulingResultError::RegistrationRevoked)
    );
}

#[test]
fn bounded_pagination_and_webhook_replay_are_fail_closed() {
    let permission_lease = lease();
    let scope = scope(&permission_lease);
    let mut pages = Vec::new();
    for index in 0..8 {
        let cursor = format!("page-{}", index + 1);
        pages.push(page(
            &scope,
            &permission_lease,
            EventStatus::Active,
            false,
            false,
            "invitee.created",
            Some(cursor.as_str()),
            false,
            NOW - 1_000 - index as u64,
        ));
    }
    let provider = CalendlyProvider::recording(pages, PROVIDER_REVISION_NUMBER).unwrap();
    let service = CalendlySchedulingResultService::register(
        provider,
        scope.clone(),
        permission_lease.clone(),
        secret(&scope, &permission_lease),
    )
    .unwrap();
    let error = service
        .read_result(&MissionContext::from_scope(&scope), NOW)
        .unwrap_err();
    assert_eq!(error, CalendlySchedulingResultError::PageBudgetExceeded);

    let replay_page = page(
        &scope,
        &permission_lease,
        EventStatus::Active,
        false,
        false,
        "invitee.created",
        None,
        true,
        NOW - MAX_WEBHOOK_AGE_MILLIS - 1,
    );
    let replay_service = CalendlySchedulingResultService::register(
        CalendlyProvider::fixture(vec![replay_page], PROVIDER_REVISION_NUMBER).unwrap(),
        scope.clone(),
        permission_lease.clone(),
        secret(&scope, &permission_lease),
    )
    .unwrap();
    assert_eq!(
        replay_service
            .read_result(&MissionContext::from_scope(&scope), NOW)
            .unwrap_err(),
        CalendlySchedulingResultError::WebhookReplay
    );
}

#[test]
fn http_failure_classes_are_explicit() {
    assert_eq!(
        ProviderError::from_http_status(401).status_code(),
        Some(401)
    );
    assert_eq!(
        ProviderError::from_http_status(403).status_code(),
        Some(403)
    );
    assert_eq!(
        ProviderError::from_http_status(404).status_code(),
        Some(404)
    );
    assert_eq!(
        ProviderError::from_http_status(409).status_code(),
        Some(409)
    );
    assert_eq!(
        ProviderError::from_http_status(429).status_code(),
        Some(429)
    );
    assert_eq!(
        ProviderError::from_http_status(500).status_code(),
        Some(500)
    );
    assert_eq!(
        ProviderError::from_http_status(599).status_code(),
        Some(599)
    );
    assert_eq!(ProviderError::Timeout.status_code(), None);
}

#[test]
fn malformed_webhook_and_redaction_inputs_do_not_cross_the_seam() {
    let event_uri = uri("scheduled_events/EVENT1");
    let malformed = WebhookChangeSignal::new(
        "delivery-1",
        "invitee.created",
        event_uri.clone(),
        None,
        InviteeStatus::Active,
        false,
        NOW,
        NOW,
        &[],
        None,
    );
    assert_eq!(
        malformed,
        Err(CalendlySchedulingResultError::MalformedProviderData)
    );
    let signal = WebhookChangeSignal::new(
        "delivery-2",
        "invitee.created",
        event_uri,
        None,
        InviteeStatus::Active,
        false,
        NOW + 1_000_000,
        NOW,
        b"private-payload",
        None,
    )
    .unwrap();
    assert_eq!(
        signal.validate_at(NOW, WebhookReplayPolicy::bounded()),
        Err(CalendlySchedulingResultError::WebhookFutureTimestamp)
    );
    let tracking = RedactedTrackingFields::from_values(&TrackingValues::new(
        Some("private-source"),
        None::<&str>,
        None::<&str>,
        None::<&str>,
        None::<&str>,
        None::<&str>,
    ))
    .unwrap();
    let serialized = serde_json::to_string(&tracking).unwrap();
    assert!(!serialized.contains("private-source"));
}

#[test]
fn custom_page_budget_is_still_bounded_by_contract() {
    assert!(PageBudget::new(0, 1, 1).is_err());
    assert!(PageBudget::new(9, 1, 1).is_err());
    assert!(PageBudget::new(1, 33, 1).is_err());
    assert!(PageBudget::new(1, 1, 33).is_err());
    assert!(WebhookReplayPolicy::new(1, 301_000).is_err());
}

#[test]
fn unknown_webhook_event_is_not_promoted_to_authority() {
    assert_eq!(
        WebhookEventKind::parse("arbitrary.created"),
        WebhookEventKind::Unknown
    );
    let (service, context) = service_with(EventStatus::Unknown, false, false, "arbitrary.created");
    let result = service.read_result(&context, NOW).unwrap();
    assert_eq!(result.state(), MeetingResultState::Unknown);
    assert!(!result.redaction().calendar_authority());
    assert!(!result.redaction().booking_authority());
}

fn _assert_result_is_serializable(result: &CalendlySchedulingResult) {
    let _ = serde_json::to_string(result).unwrap();
}

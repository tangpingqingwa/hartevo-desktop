use hartevo_segment_event_evidence_plugin::{
    ConnectionStatus, DeliveryEvidence, DeliveryHealth, DestinationEvidence, Digest,
    EventSchemaEvidence, EvidenceBounds, EvidenceStatus, EvidenceWindow, FreshnessState,
    MissionSegmentOutcomeConsumer, ModelError, PageStatus, Permission, PermissionSnapshot,
    PluginVersion, ProviderProvenance, Revision, SecretKind, SecretReference,
    SegmentEventEvidenceService, SegmentProvider, SegmentProviderDefinition, SegmentReadOperation,
    SegmentReadPage, SegmentReadRequest, SegmentRecord, SegmentScope, ServiceError, SourceEvidence,
    TrackingPlanEvidence, TransportError, ViolationCategory, ViolationEvidence, WorkProductId,
    WorkspaceId,
};

use hartevo_segment_event_evidence_plugin::{
    DestinationId, EventSpecId, MissionId, ProjectId, SourceId, TrackingPlanId,
};

fn scope() -> SegmentScope {
    SegmentScope::read_only(
        WorkspaceId::new("workspace").unwrap(),
        SourceId::new("source").unwrap(),
        TrackingPlanId::new("plan").unwrap(),
        Revision::new(1).unwrap(),
        EventSpecId::new("event").unwrap(),
        DestinationId::new("destination").unwrap(),
        ProjectId::new("project").unwrap(),
        Revision::new(7).unwrap(),
        MissionId::new("mission").unwrap(),
        Revision::new(9).unwrap(),
        WorkProductId::new("work-product").unwrap(),
        Revision::new(3).unwrap(),
    )
}

fn provider_definition(provenance: ProviderProvenance) -> SegmentProviderDefinition {
    SegmentProviderDefinition::new(PluginVersion::V1, "protocols-fixture/v1", provenance).unwrap()
}

fn secret(scope: &SegmentScope) -> SecretReference {
    SecretReference::new(
        "segment-keyring-alias",
        scope,
        4,
        SecretKind::PublicApiToken,
    )
    .unwrap()
}

fn base_records(scope: &SegmentScope) -> Vec<SegmentRecord> {
    let plan = TrackingPlanEvidence::new(
        scope.tracking_plan_id().clone(),
        scope.plan_revision(),
        1,
        Digest::from_text("tracking-plan-schema"),
    )
    .unwrap();
    let delivery = DeliveryEvidence::new(
        scope.destination_id().clone(),
        DeliveryHealth::Healthy,
        42,
        0,
        1_700_000_000,
        FreshnessState::Fresh,
        hartevo_segment_event_evidence_plugin::RetentionState::Complete,
    );
    vec![
        SegmentRecord::TrackingPlan(plan.clone()),
        SegmentRecord::EventSchema(EventSchemaEvidence::new(
            scope.event_spec_id().clone(),
            scope.plan_revision(),
            Digest::from_text("event-schema"),
            4,
        )),
        SegmentRecord::Source(SourceEvidence {
            source_id: scope.source_id().clone(),
            status: ConnectionStatus::Enabled,
            tracking_plan_digest: plan.plan_digest.clone(),
            plan_revision: scope.plan_revision(),
        }),
        SegmentRecord::Destination(DestinationEvidence {
            destination_id: scope.destination_id().clone(),
            status: ConnectionStatus::Enabled,
            source_id: scope.source_id().clone(),
            delivery_digest: delivery.delivery_digest.clone(),
        }),
        SegmentRecord::Delivery(delivery),
    ]
}

fn page(
    scope: &SegmentScope,
    provenance: ProviderProvenance,
    secret: &SecretReference,
    records: Vec<SegmentRecord>,
    status: PageStatus,
    freshness: FreshnessState,
    retention: hartevo_segment_event_evidence_plugin::RetentionState,
    page_number: u16,
    cursor_digest: Option<Digest>,
    next_cursor_digest: Option<Digest>,
) -> SegmentReadPage {
    let definition = provider_definition(provenance);
    let request = SegmentReadRequest::new(
        scope,
        SegmentReadOperation::Describe,
        EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap(),
        &EvidenceBounds::default(),
        definition.provider_digest(),
        hartevo_segment_event_evidence_plugin::segment_event_evidence_contract_digest(),
        secret.reference_digest().clone(),
        secret.credential_revision(),
        page_number,
        100,
        cursor_digest,
    )
    .unwrap();
    let page = SegmentReadPage::new(
        &request,
        records,
        next_cursor_digest,
        freshness,
        retention,
        status,
    )
    .unwrap();
    assert_eq!(page.page_number, page_number);
    assert!(page.validate_digest().is_ok());
    page
}

fn service_with_pages(
    pages: impl IntoIterator<Item = Result<SegmentReadPage, TransportError>>,
    provenance: ProviderProvenance,
) -> (
    SegmentEventEvidenceService<
        SegmentProvider<hartevo_segment_event_evidence_plugin::RecordingSegmentTransport>,
    >,
    SegmentScope,
) {
    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let provider = SegmentProvider::new(
        hartevo_segment_event_evidence_plugin::RecordingSegmentTransport::from_pages(pages),
        PluginVersion::V1,
        "protocols-fixture/v1",
        provenance,
    )
    .unwrap();
    let service = SegmentEventEvidenceService::new(
        current_scope.clone(),
        current_secret,
        provider,
        EvidenceBounds::default(),
    )
    .unwrap();
    (service, current_scope)
}

#[test]
fn compile_record_verify_and_consume_are_digest_bound_and_non_mutating() {
    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let pages = [Ok(page(
        &current_scope,
        ProviderProvenance::Fixture,
        &current_secret,
        base_records(&current_scope),
        PageStatus::Complete,
        FreshnessState::Fresh,
        hartevo_segment_event_evidence_plugin::RetentionState::Complete,
        1,
        None,
        None,
    ))];
    let (mut service, current_scope) = service_with_pages(pages, ProviderProvenance::Fixture);
    let proposal = service
        .compile_evidence_proposal(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
        .unwrap();
    assert_eq!(proposal.evidence.status, EvidenceStatus::Conforming);
    assert_eq!(
        proposal.evidence.digests.evidence_digest,
        proposal.evidence.recompute_evidence_digest()
    );
    assert!(!proposal.evidence.provenance.is_native());

    let receipt = service.record(&proposal).unwrap();
    let verified = service.verify(&receipt).unwrap();
    assert!(!verified.native);
    assert_eq!(verified.authority, "read_only_observational_evidence");

    let consumer =
        MissionSegmentOutcomeConsumer::new(current_scope, service.registration()).unwrap();
    let outcome = consumer.consume(&proposal).unwrap();
    assert_eq!(outcome.evidence_status, EvidenceStatus::Conforming);
    assert!(!outcome.adoption.mutates_external_state);
    assert!(!outcome.adoption.adopts_kernel_outcome);
}

#[test]
fn violations_and_delivery_degradation_are_typed_projections() {
    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let mut records = base_records(&current_scope);
    records.push(SegmentRecord::Violation(
        ViolationEvidence::new(
            ViolationCategory::MissingProperty,
            3,
            vec![Digest::from_text("sample-1")],
        )
        .unwrap(),
    ));
    let (mut service, current_scope) = service_with_pages(
        [Ok(page(
            &current_scope,
            ProviderProvenance::Recording,
            &current_secret,
            records,
            PageStatus::Complete,
            FreshnessState::Fresh,
            hartevo_segment_event_evidence_plugin::RetentionState::Complete,
            1,
            None,
            None,
        ))],
        ProviderProvenance::Recording,
    );
    let proposal = service
        .compile_evidence_proposal(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
        .unwrap();
    assert_eq!(proposal.evidence.status, EvidenceStatus::Violation);
    let consumer =
        MissionSegmentOutcomeConsumer::new(current_scope, service.registration()).unwrap();
    assert_eq!(
        consumer.consume(&proposal).unwrap().adoption.action,
        hartevo_segment_event_evidence_plugin::AdoptionAction::RepairInstrumentation
    );

    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let mut degraded_records = base_records(&current_scope);
    for record in &mut degraded_records {
        if let SegmentRecord::Delivery(delivery) = record {
            *delivery = DeliveryEvidence::new(
                current_scope.destination_id().clone(),
                DeliveryHealth::Degraded,
                40,
                2,
                1_700_000_000,
                FreshnessState::Fresh,
                hartevo_segment_event_evidence_plugin::RetentionState::Complete,
            );
        }
    }
    let (mut degraded_service, _) = service_with_pages(
        [Ok(page(
            &current_scope,
            ProviderProvenance::Loopback,
            &current_secret,
            degraded_records,
            PageStatus::Complete,
            FreshnessState::Fresh,
            hartevo_segment_event_evidence_plugin::RetentionState::Complete,
            1,
            None,
            None,
        ))],
        ProviderProvenance::Loopback,
    );
    let degraded = degraded_service
        .compile_evidence_proposal(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
        .unwrap();
    assert_eq!(degraded.evidence.status, EvidenceStatus::DeliveryDegraded);
}

#[test]
fn pagination_is_bounded_and_cursor_loops_fail_closed() {
    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let cursor = Digest::from_text("cursor-a");
    let first = page(
        &current_scope,
        ProviderProvenance::Loopback,
        &current_secret,
        base_records(&current_scope),
        PageStatus::Complete,
        FreshnessState::Fresh,
        hartevo_segment_event_evidence_plugin::RetentionState::Complete,
        1,
        None,
        Some(cursor.clone()),
    );
    let second = page(
        &current_scope,
        ProviderProvenance::Loopback,
        &current_secret,
        vec![],
        PageStatus::Complete,
        FreshnessState::Fresh,
        hartevo_segment_event_evidence_plugin::RetentionState::Complete,
        2,
        Some(cursor.clone()),
        None,
    );
    let (mut service, _) =
        service_with_pages([Ok(first), Ok(second)], ProviderProvenance::Loopback);
    let read = service
        .read(
            SegmentReadOperation::Describe,
            EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap(),
        )
        .unwrap();
    assert_eq!(read.pages_observed, 2);
    assert_eq!(read.cursor_digests, vec![cursor]);
    assert_eq!(
        read.high_water_cursor_digest,
        read.cursor_digests.last().cloned()
    );

    let loop_page = page(
        &scope(),
        ProviderProvenance::Loopback,
        &secret(&scope()),
        base_records(&scope()),
        PageStatus::Complete,
        FreshnessState::Fresh,
        hartevo_segment_event_evidence_plugin::RetentionState::Complete,
        1,
        None,
        Some(Digest::from_text("loop")),
    );
    let loop_cursor = Digest::from_text("loop");
    let loop_page_2 = page(
        &scope(),
        ProviderProvenance::Loopback,
        &secret(&scope()),
        vec![],
        PageStatus::Complete,
        FreshnessState::Fresh,
        hartevo_segment_event_evidence_plugin::RetentionState::Complete,
        2,
        Some(loop_cursor.clone()),
        Some(loop_cursor),
    );
    let (mut loop_service, _) = service_with_pages(
        [Ok(loop_page), Ok(loop_page_2)],
        ProviderProvenance::Loopback,
    );
    assert_eq!(
        loop_service
            .read(
                SegmentReadOperation::Describe,
                EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap(),
            )
            .unwrap_err(),
        ServiceError::CursorLoop
    );
}

#[test]
fn provider_errors_and_blocked_env_remain_explicit() {
    let errors = [
        TransportError::Unauthorized401,
        TransportError::Forbidden403,
        TransportError::NotFound404,
        TransportError::Conflict409,
        TransportError::RateLimited429,
        TransportError::Server5xx { status: 503 },
        TransportError::Timeout,
    ];
    for error in errors {
        let (mut service, _) =
            service_with_pages([Err(error.clone())], ProviderProvenance::Recording);
        assert_eq!(
            service
                .describe(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
                .unwrap_err(),
            ServiceError::Transport(error)
        );
    }

    let blocked = SegmentProvider::blocked_env().unwrap();
    let current_scope = scope();
    let blocked_service = SegmentEventEvidenceService::new(
        current_scope.clone(),
        secret(&current_scope),
        blocked,
        EvidenceBounds::default(),
    )
    .unwrap();
    let mut blocked_service = blocked_service;
    assert_eq!(
        blocked_service
            .describe(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
            .unwrap_err(),
        ServiceError::Transport(TransportError::BlockedEnv)
    );
    let official = SegmentProvider::official_api().unwrap();
    let mut official_service = SegmentEventEvidenceService::new(
        current_scope.clone(),
        secret(&current_scope),
        official,
        EvidenceBounds::default(),
    )
    .unwrap();
    assert_eq!(
        official_service
            .describe(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
            .unwrap_err(),
        ServiceError::Transport(TransportError::NativeUnavailable)
    );
}

#[test]
fn partial_stale_empty_unknown_and_retention_gap_are_not_recordable() {
    let statuses = [
        (
            PageStatus::Partial,
            FreshnessState::Fresh,
            EvidenceStatus::Partial,
        ),
        (
            PageStatus::ProviderUnknown,
            FreshnessState::Fresh,
            EvidenceStatus::ProviderUnknown,
        ),
        (
            PageStatus::Complete,
            FreshnessState::Stale,
            EvidenceStatus::Stale,
        ),
        (
            PageStatus::Complete,
            FreshnessState::Fresh,
            EvidenceStatus::Empty,
        ),
    ];
    for (status, freshness, expected) in statuses {
        let current_scope = scope();
        let current_secret = secret(&current_scope);
        let records = if expected == EvidenceStatus::Empty {
            vec![]
        } else {
            base_records(&current_scope)
        };
        let (mut service, _) = service_with_pages(
            [Ok(page(
                &current_scope,
                ProviderProvenance::Fixture,
                &current_secret,
                records,
                status,
                freshness,
                hartevo_segment_event_evidence_plugin::RetentionState::Complete,
                1,
                None,
                None,
            ))],
            ProviderProvenance::Fixture,
        );
        let proposal = service
            .compile_evidence_proposal(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
            .unwrap();
        assert_eq!(proposal.evidence.status, expected);
        assert_eq!(
            service.record(&proposal).unwrap_err(),
            ServiceError::NotRecordable(expected)
        );
    }

    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let (mut service, _) = service_with_pages(
        [Ok(page(
            &current_scope,
            ProviderProvenance::Fixture,
            &current_secret,
            base_records(&current_scope),
            PageStatus::Complete,
            FreshnessState::Fresh,
            hartevo_segment_event_evidence_plugin::RetentionState::Gap,
            1,
            None,
            None,
        ))],
        ProviderProvenance::Fixture,
    );
    assert_eq!(
        service
            .describe(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
            .unwrap_err(),
        ServiceError::RetentionGap
    );
}

#[test]
fn tamper_scope_plan_and_page_digests_are_rejected() {
    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let mut tampered = page(
        &current_scope,
        ProviderProvenance::Fixture,
        &current_secret,
        base_records(&current_scope),
        PageStatus::Complete,
        FreshnessState::Fresh,
        hartevo_segment_event_evidence_plugin::RetentionState::Complete,
        1,
        None,
        None,
    );
    tampered.response_digest = Digest::from_text("tampered");
    let (mut service, _) = service_with_pages([Ok(tampered)], ProviderProvenance::Fixture);
    assert_eq!(
        service
            .describe(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
            .unwrap_err(),
        ServiceError::TamperedEvidence
    );

    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let mut plan_drift = page(
        &current_scope,
        ProviderProvenance::Fixture,
        &current_secret,
        base_records(&current_scope),
        PageStatus::Complete,
        FreshnessState::Fresh,
        hartevo_segment_event_evidence_plugin::RetentionState::Complete,
        1,
        None,
        None,
    );
    plan_drift.plan_revision = Revision::new(2).unwrap();
    let (mut service, _) = service_with_pages([Ok(plan_drift)], ProviderProvenance::Fixture);
    assert!(matches!(
        service
            .describe(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
            .unwrap_err(),
        ServiceError::TamperedEvidence | ServiceError::PlanDrift
    ));
}

#[test]
fn registration_is_reversible_and_permission_windows_are_bounded() {
    assert!(PermissionSnapshot::new([Permission::DestinationWrite]).is_err());
    assert_eq!(
        EvidenceWindow::new(10, 10).unwrap_err(),
        ModelError::InvalidWindow
    );

    let current_scope = scope();
    let current_secret = secret(&current_scope);
    let (mut service, _) = service_with_pages(
        [Ok(page(
            &current_scope,
            ProviderProvenance::Fixture,
            &current_secret,
            base_records(&current_scope),
            PageStatus::Complete,
            FreshnessState::Fresh,
            hartevo_segment_event_evidence_plugin::RetentionState::Complete,
            1,
            None,
            None,
        ))],
        ProviderProvenance::Fixture,
    );
    assert!(service.revoke().is_ok());
    assert_eq!(
        service
            .describe(EvidenceWindow::new(1_700_000_000, 1_700_000_600).unwrap())
            .unwrap_err(),
        ServiceError::RegistrationInactive
    );
}

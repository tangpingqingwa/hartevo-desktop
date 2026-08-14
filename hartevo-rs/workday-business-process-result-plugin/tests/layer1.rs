use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use hartevo_workday_business_process_result_plugin::*;

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("revision")
}

fn at(hour: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, hour, 0, 0)
        .single()
        .expect("timestamp")
}

fn scope() -> WorkdayScope {
    let consent = ConsentScope::new(
        digest("permission-revision-1"),
        digest("consent-1"),
        revision(4),
        [ReadKind::Events, ReadKind::Raas, ReadKind::Wql],
        Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0)
            .single()
            .expect("consent expiry"),
    )
    .expect("consent");
    WorkdayScope::new(WorkdayScopeInput {
        tenant_id: TenantId::new("tenant-1").expect("tenant"),
        region: TenantRegion::new("us").expect("region"),
        api_version: ApiVersion::new("v1").expect("api version"),
        business_process_id: BusinessProcessId::new("hire-worker").expect("process"),
        event_id: BusinessProcessEventId::new("event-1").expect("event"),
        business_object: BusinessObjectReference::new(
            BusinessObjectId::new("worker-object-1").expect("object"),
            revision(7),
        ),
        worker_reference: WorkerReference::new("worker-1").expect("worker"),
        allowlisted_report_ids: BTreeSet::from([ReportId::new("bp-results").expect("report")]),
        time_window: TimeWindow::new(at(0), at(22)).expect("window"),
        bounds: ReadBounds::new(4_096, 25, 2, 10).expect("bounds"),
        mission_id: MissionId::new("mission-1").expect("mission"),
        project_id: ProjectId::new("project-1").expect("project"),
        work_product_id: WorkProductId::new("work-product-1").expect("work product"),
        tenant_revision: revision(2),
        process_revision: revision(3),
        mission_revision: revision(8),
        project_revision: revision(5),
        work_product_revision: revision(9),
        consent,
    })
    .expect("scope")
}

fn payload(
    scope: &WorkdayScope,
    status: &str,
    due_at: Option<chrono::DateTime<Utc>>,
) -> WorkdayEventPayload {
    WorkdayEventPayload {
        event_id: scope.event_id().clone(),
        event_revision: revision(4),
        business_process_id: scope.business_process_id().clone(),
        business_object: scope.business_object().clone(),
        worker: WorkdayWorkerPayload {
            reference_id: "worker-1".to_owned(),
            display_name: Some("Ada Sensitive Worker".to_owned()),
            email: Some("ada-sensitive@example.test".to_owned()),
        },
        status: status.to_owned(),
        initiated_at: at(1),
        due_at,
        completed_at: (status == "completed").then_some(at(10)),
        steps: vec![
            WorkdayStepPayload {
                reference: StepReference::new(
                    StepId::new("manager-approval").expect("step"),
                    revision(2),
                ),
                status: "completed".to_owned(),
                due_at: Some(at(8)),
                completed_at: Some(at(9)),
            },
            WorkdayStepPayload {
                reference: StepReference::new(StepId::new("hr-review").expect("step"), revision(1)),
                status: "in_progress".to_owned(),
                due_at: Some(at(22)),
                completed_at: None,
            },
        ],
        comments: vec!["Sensitive comment must never cross the Mission seam".to_owned()],
        attachments: vec![WorkdayAttachmentPayload {
            attachment_id: "attachment-1".to_owned(),
            filename: Some("payroll-detail.pdf".to_owned()),
            content_digest: Some(digest("attachment-content")),
        }],
        provider_partial: false,
        provider_redacted: false,
    }
}

fn setup_recording(
    status: &str,
) -> (
    WorkdayBusinessProcessResultService,
    WorkdayProvider<RecordingWorkdayTransport>,
    WorkdayScope,
    SecretReference,
    WorkdayRegistration,
) {
    let scope = scope();
    let secret = SecretReference::new("host-owned-workday-credential", &scope, revision(6))
        .expect("secret reference");
    let api_version = ApiVersion::new("v1").expect("api version");
    let provider_revision = ProviderRevision::new(WORKDAY_PROVIDER_REVISION).expect("provider");
    let response = WorkdayHttpResponse::success(
        payload(&scope, status, Some(at(22))),
        api_version,
        provider_revision,
        1_024,
        at(12),
    );
    let mut transport = RecordingWorkdayTransport::default();
    transport.push_response(Ok(response));
    let provider =
        WorkdayProvider::new(transport, "1.0.0", ProviderProvenance::Recording).expect("provider");
    let registration = provider.register(&scope, &secret).expect("registration");
    (
        WorkdayBusinessProcessResultService::new(),
        provider,
        scope,
        secret,
        registration,
    )
}

#[test]
fn contract_and_runtime_definition_are_layer_one_only() {
    WorkdayContract::baseline()
        .expect("checked-in Workday contract should validate")
        .validate()
        .expect("contract validation");
    let service = WorkdayBusinessProcessResultService::new();
    service.validate().expect("service descriptor");
    let definition = service.runtime_definition().expect("runtime definition");
    assert_eq!(
        definition.id().as_str(),
        WORKDAY_BUSINESS_PROCESS_RESULT_SERVICE_ID
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::effect());
    assert!(!Layer1Authority::native_receipt());
    assert!(!Layer1Authority::exact_read_back());
    assert!(!Layer1Authority::adopted_outcome());
    assert!(!Layer1Authority::work_product_adoption());
}

#[test]
fn recording_read_is_redacted_bounded_and_revision_fenced() {
    let (service, mut provider, scope, secret, registration) = setup_recording("in_progress");
    let request = WorkdayReadRequest::events(
        &scope,
        ReadBounds::new(2_048, 10, 2, 10).expect("request bounds"),
    )
    .expect("events request");
    let proposal = service
        .propose(&mut provider, &scope, &secret, &registration, &request)
        .expect("proposal");
    proposal.validate().expect("proposal fence");
    assert_eq!(
        proposal.evidence.process_status,
        BusinessProcessStatus::InProgress
    );
    assert_eq!(proposal.evidence.quality, EvidenceQuality::Redacted);
    assert_eq!(
        proposal.evidence.mission_state(),
        MissionResultState::Redacted
    );
    assert!(proposal.evidence.redaction.worker_pii_redacted);
    assert!(!proposal.evidence.receipt.native_receipt);
    assert!(!proposal.authority.connected);
    assert!(!proposal.authority.effect);
    assert_eq!(
        proposal.effect.availability,
        EffectAvailability::NotAvailableLayer1
    );
    assert_eq!(proposal.receipt, ReceiptAvailability::ProviderEvidenceOnly);
    assert_eq!(
        proposal.read_back.availability,
        ReadBackAvailability::DeferredLayer2
    );
    assert!(!format!("{proposal:?}").contains("Ada Sensitive Worker"));
    assert!(!format!("{proposal:?}").contains("Sensitive comment"));
    assert!(!format!("{secret:?}").contains("host-owned-workday-credential"));
    let encoded = serde_json::to_string(&proposal).expect("safe proposal JSON");
    assert!(!encoded.contains("Ada Sensitive Worker"));
    assert!(!encoded.contains("ada-sensitive@example.test"));
    assert!(!encoded.contains("Sensitive comment"));
    assert!(!encoded.contains("payroll-detail.pdf"));

    let requests = provider.transport().requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].endpoint, WorkdayEndpoint::Events);
    assert!(
        requests[0]
            .path_and_query
            .contains("/api/businessProcess/v1/tenant-1/events/event-1")
    );
    assert!(
        !requests[0]
            .path_and_query
            .contains("host-owned-workday-credential")
    );

    let consumer =
        MissionWorkdayBusinessProcessConsumer::new(scope, &registration).expect("consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert_eq!(result.state, MissionResultState::Redacted);
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
    assert!(!result.connected());
    assert!(!result.truth_authority());
    assert!(!result.adopted_outcome());
    assert_eq!(
        result
            .evidence()
            .event()
            .expect("event")
            .worker_reference
            .kind(),
        &WorkerReferenceKind::Redacted
    );
}

#[test]
fn fixture_and_loopback_are_deterministic_non_native_transports() {
    let scope = scope();
    let secret = SecretReference::new("fixture-secret", &scope, revision(1)).expect("secret");
    let payload = payload(&scope, "completed", Some(at(20)));
    let response = WorkdayHttpResponse::success(
        payload.clone(),
        ApiVersion::new("v1").expect("api"),
        ProviderRevision::new(WORKDAY_PROVIDER_REVISION).expect("provider revision"),
        256,
        at(12),
    );
    let mut fixture = WorkdayProvider::new(
        FixtureWorkdayTransport::new(response),
        "1.0.0",
        ProviderProvenance::Fixture,
    )
    .expect("fixture provider");
    let fixture_registration = fixture.register(&scope, &secret).expect("registration");
    let service = WorkdayBusinessProcessResultService::new();
    let raas_request = WorkdayReadRequest::raas(
        &scope,
        ReportId::new("bp-results").expect("report"),
        [WorkdayField::EventId, WorkdayField::EventStatus],
        ReadBounds::new(1_024, 10, 1, 10).expect("bounds"),
    )
    .expect("RaaS request");
    let fixture_proposal = service
        .propose(
            &mut fixture,
            &scope,
            &secret,
            &fixture_registration,
            &raas_request,
        )
        .expect("fixture proposal");
    assert_eq!(
        fixture_proposal.evidence.process_status,
        BusinessProcessStatus::Completed
    );
    assert_eq!(
        fixture_proposal.evidence.receipt.provenance,
        TransportProvenance::Fixture
    );
    assert!(!fixture_proposal.evidence.receipt.native_receipt);
    assert!(
        fixture_proposal
            .evidence
            .receipt
            .request_path_and_query
            .starts_with("/raas/tenant-1/bp-results")
    );
    let fixture_repeat = service
        .propose(
            &mut fixture,
            &scope,
            &secret,
            &fixture_registration,
            &raas_request,
        )
        .expect("repeat fixture proposal");
    assert_eq!(
        fixture_repeat.evidence.evidence_digest,
        fixture_proposal.evidence.evidence_digest
    );

    let mut loopback = WorkdayProvider::new(
        LoopbackWorkdayTransport::from_payload(
            payload,
            ApiVersion::new("v1").expect("api"),
            ProviderRevision::new(WORKDAY_PROVIDER_REVISION).expect("provider revision"),
            at(12),
        ),
        "1.0.0",
        ProviderProvenance::Loopback,
    )
    .expect("loopback provider");
    let loopback_registration = loopback.register(&scope, &secret).expect("registration");
    let wql_request = WorkdayReadRequest::wql(
        &scope,
        WqlDataSource::BusinessProcessEvents,
        [WorkdayField::EventId, WorkdayField::EventStatus],
        ReadBounds::new(1_024, 10, 1, 10).expect("bounds"),
    )
    .expect("WQL request");
    let loopback_proposal = service
        .propose(
            &mut loopback,
            &scope,
            &secret,
            &loopback_registration,
            &wql_request,
        )
        .expect("loopback proposal");
    assert_eq!(
        loopback_proposal.evidence.receipt.provenance,
        TransportProvenance::Loopback
    );
    assert_ne!(
        loopback_proposal.evidence.receipt.provenance,
        fixture_proposal.evidence.receipt.provenance
    );
    assert!(!loopback_proposal.authority.native_provider);
}

#[test]
fn blocked_env_is_explicit_and_access_loss_is_a_non_native_state() {
    let scope = scope();
    let secret = SecretReference::new("blocked-secret", &scope, revision(1)).expect("secret");
    let service = WorkdayBusinessProcessResultService::new();
    let request = WorkdayReadRequest::events(&scope, scope.bounds().clone()).expect("request");
    let blocked_provider = WorkdayProvider::new(
        BlockedEnvWorkdayTransport,
        "1.0.0",
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let registration = blocked_provider
        .register(&scope, &secret)
        .expect("registration");
    let mut blocked_provider = blocked_provider;
    assert_eq!(
        service
            .propose(
                &mut blocked_provider,
                &scope,
                &secret,
                &registration,
                &request,
            )
            .expect_err("native environment is unavailable"),
        WorkdayError::BlockedEnv
    );

    let mut recording = WorkdayProvider::new(
        {
            let mut transport = RecordingWorkdayTransport::default();
            transport.push_response(Err(TransportError::access_denied()));
            transport
        },
        "1.0.0",
        ProviderProvenance::Recording,
    )
    .expect("recording provider");
    let access_registration = recording.register(&scope, &secret).expect("registration");
    let proposal = service
        .propose(
            &mut recording,
            &scope,
            &secret,
            &access_registration,
            &request,
        )
        .expect("access loss is represented as evidence");
    assert_eq!(proposal.evidence.quality, EvidenceQuality::AccessLost);
    assert_eq!(
        proposal.evidence.mission_state(),
        MissionResultState::AccessLost
    );
    assert_eq!(proposal.evidence.receipt.response_status, 403);
    assert!(!proposal.authority.connected);
}

#[test]
fn unsafe_queries_reports_and_fields_fail_closed() {
    let scope = scope();
    let bounds = ReadBounds::new(2_048, 10, 1, 10).expect("bounds");
    assert!(matches!(
        WorkdayReadRequest::wql_text(&scope, "SELECT * FROM allWorkers LIMIT 10", bounds.clone(),),
        Err(ModelError::ArbitraryWql)
    ));
    assert!(matches!(
        WorkdayReadRequest::wql_text(
            &scope,
            "SELECT eventId FROM businessProcessEvents WHERE eventId = 'event-1'",
            bounds.clone(),
        ),
        Err(ModelError::UnboundedRaas)
    ));
    assert!(matches!(
        WorkdayReadRequest::wql_text(
            &scope,
            "SELECT payroll FROM businessProcessEvents WHERE eventId = 'event-1' LIMIT 10",
            bounds.clone(),
        ),
        Err(ModelError::ArbitraryWql)
    ));
    assert!(matches!(
        WorkdayReadRequest::raas(
            &scope,
            ReportId::new("unknown-report").expect("report"),
            [WorkdayField::EventId],
            bounds.clone(),
        ),
        Err(ModelError::UnboundedRaas)
    ));
    assert!(matches!(
        WorkdayReadRequest::raas(
            &scope,
            ReportId::new("bp-results").expect("report"),
            [WorkdayField::Payroll],
            bounds,
        ),
        Err(ModelError::ForbiddenField { .. })
    ));
    assert!(ReadBounds::new(WORKDAY_MAX_RESPONSE_BYTES + 1, 1, 1, 1).is_err());
    assert!(ReadBounds::new(1, WORKDAY_MAX_ROWS + 1, 1, 1).is_err());
}

#[test]
fn registration_and_fences_are_reversible_and_revocable() {
    let (service, mut provider, initial_scope, secret, mut registration) =
        setup_recording("completed");
    let request = WorkdayReadRequest::events(&initial_scope, initial_scope.bounds().clone())
        .expect("request");
    provider
        .revoke_registration(&mut registration)
        .expect("revoke");
    assert!(!registration.is_active());
    assert_eq!(
        service
            .propose(
                &mut provider,
                &initial_scope,
                &secret,
                &registration,
                &request,
            )
            .expect_err("revoked registration must fail closed"),
        WorkdayError::RegistrationRevoked
    );

    let scope_again = scope();
    let secret_again =
        SecretReference::new("same-host-secret", &scope_again, revision(1)).expect("secret");
    let second_provider = WorkdayProvider::new(
        RecordingWorkdayTransport::default(),
        "1.0.0",
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let second_registration = second_provider
        .register(&scope_again, &secret_again)
        .expect("registration");
    let mut consumer =
        MissionWorkdayBusinessProcessConsumer::new(scope_again, &second_registration)
            .expect("consumer");
    consumer.revoke().expect("consumer revoke");
    assert!(
        consumer
            .consume(WorkdayBusinessProcessResultProposal {
                evidence: WorkdayBusinessProcessResultEvidence {
                    scope_digest: digest("scope"),
                    registration_digest: digest("registration"),
                    provider_digest: digest("provider"),
                    capability_digest: digest("capability"),
                    consent_digest: digest("consent"),
                    consent_revision: revision(1),
                    tenant_revision: revision(1),
                    process_revision: revision(1),
                    mission_revision: revision(1),
                    project_revision: revision(1),
                    work_product_revision: revision(1),
                    step_revision_digest: digest("steps"),
                    event: None,
                    process_status: BusinessProcessStatus::ProviderUnknown,
                    quality: EvidenceQuality::AccessLost,
                    overdue: false,
                    redaction: RedactionSummary {
                        worker_pii_redacted: true,
                        comments_redacted: true,
                        attachments_redacted: true,
                        payroll_and_compensation_redacted: true,
                        redacted_field_count: 0,
                    },
                    receipt: WorkdayResponseReceipt {
                        endpoint: WorkdayEndpoint::Events,
                        request_path_and_query: "/blocked".to_owned(),
                        api_version: ApiVersion::new("v1").expect("api"),
                        response_status: 403,
                        response_size: 0,
                        response_digest: digest("response"),
                        provider_revision: ProviderRevision::new(WORKDAY_PROVIDER_REVISION)
                            .expect("provider"),
                        observed_at: at(12),
                        freshness_digest: digest("freshness"),
                        provenance: TransportProvenance::Recording,
                        raw_provider_payload: false,
                        credential_material: false,
                        native_receipt: false,
                    },
                    evidence_digest: digest("invalid"),
                },
                registration_digest: digest("registration"),
                secret_reference_digest: digest("secret"),
                decision: WorkdayDecisionProposal {
                    action: WorkdayDecisionAction::EscalateAccess,
                    observed_state: MissionResultState::AccessLost,
                    reason: "test".to_owned(),
                    effect_allowed: false,
                },
                effect: WorkdayEffectProposal {
                    kind: WorkdayEffectKind::NoMutationLayer1,
                    availability: EffectAvailability::NotAvailableLayer1,
                    scope_digest: digest("scope"),
                    consent_digest: digest("consent"),
                    native: false,
                },
                receipt: ReceiptAvailability::ProviderEvidenceOnly,
                read_back: WorkdayReadBackProposal {
                    availability: ReadBackAvailability::DeferredLayer2,
                    expected_scope_digest: digest("scope"),
                    expected_event_revision: None,
                    source_evidence_digest: digest("invalid"),
                },
                adopted: false,
                authority: Layer1AuthorityView::current(),
                proposal_digest: digest("invalid"),
            })
            .expect_err("revoked consumer")
            .to_string()
            .contains("revoked")
    );
}

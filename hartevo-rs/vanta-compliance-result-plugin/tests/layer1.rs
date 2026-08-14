use chrono::{TimeZone, Utc};
use hartevo_vanta_compliance_result_plugin::{
    AuditBinding, AuditId, BlockedEnvVantaTransport, ComplianceObjective, ComplianceObjectiveId,
    ConsentBinding, ConsentId, ControlId, Digest, FrameworkId, InformationRequestId, IssueId,
    MissionBinding, MissionId, MissionVantaComplianceConsumer, MissionVantaDecisionState,
    OpaqueCursor, ProjectBinding, ProjectId, ProviderRevision, RecordingVantaTransport, Revision,
    SecretReference, TestId, TransportProvenance, VANTA_MAX_PAGES, VANTA_PAGE_SIZE,
    VANTA_PROVIDER_REVISION_TEXT, VantaApiFamily, VantaComplianceResultContract,
    VantaComplianceResultService, VantaComplianceState, VantaControlRecord, VantaEndpoint,
    VantaHttpRequest, VantaHttpResponse, VantaInformationRequestRecord, VantaIssueRecord,
    VantaProposalRequest, VantaProvider, VantaReadRequest, VantaResponseBody, VantaTestRecord,
};

fn at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 16, 0, 0)
        .single()
        .expect("fixed test time")
}

fn scope() -> hartevo_vanta_compliance_result_plugin::VantaComplianceScope {
    let mut scope = hartevo_vanta_compliance_result_plugin::VantaComplianceScope::new(
        hartevo_vanta_compliance_result_plugin::TenantId::new("tenant-1").expect("tenant"),
        hartevo_vanta_compliance_result_plugin::Region::new("us").expect("region"),
        VantaApiFamily::ManageAndAudit,
        AuditBinding::new(
            AuditId::new("audit-1").expect("audit"),
            FrameworkId::new("framework-1").expect("framework"),
            Revision::new(7).expect("audit revision"),
        ),
        [ControlId::new("control-1").expect("control")],
        [TestId::new("test-1").expect("test")],
        [IssueId::new("issue-1").expect("issue")],
        [InformationRequestId::new("request-1").expect("request")],
        ComplianceObjective::new(
            ComplianceObjectiveId::new("objective-1").expect("objective"),
            Revision::new(3).expect("objective revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-1").expect("Mission"),
            Revision::new(11).expect("Mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("Project"),
            Revision::new(5).expect("Project revision"),
        ),
        ConsentBinding::new(
            ConsentId::new("consent-1").expect("consent"),
            Revision::new(2).expect("consent revision"),
            Digest::from_text("consent-revision-2"),
        ),
        Digest::from_text("permission-revision-1"),
    )
    .expect("scope");
    scope
        .with_revision_fences(
            [(
                ControlId::new("control-1").expect("control"),
                Revision::new(8).expect("control revision"),
            )],
            [(
                TestId::new("test-1").expect("test"),
                Revision::new(9).expect("test revision"),
            )],
            [(
                IssueId::new("issue-1").expect("issue"),
                Revision::new(10).expect("issue revision"),
            )],
            [(
                InformationRequestId::new("request-1").expect("request"),
                Revision::new(12).expect("request revision"),
            )],
        )
        .expect("revision fences");
    scope
}

fn secret() -> SecretReference {
    SecretReference::new("vanta-native-secret-material").expect("opaque secret")
}

fn provider_revision() -> ProviderRevision {
    ProviderRevision::new(VANTA_PROVIDER_REVISION_TEXT).expect("provider revision")
}

fn request_for(
    scope: &hartevo_vanta_compliance_result_plugin::VantaComplianceScope,
    endpoint: VantaEndpoint,
) -> VantaHttpRequest {
    let read = VantaReadRequest::new(
        endpoint,
        scope.digest(),
        VANTA_PAGE_SIZE,
        VANTA_MAX_PAGES,
        at(),
    )
    .expect("read request");
    VantaHttpRequest::new(&read, None).expect("HTTP request")
}

fn body_for(
    scope: &hartevo_vanta_compliance_result_plugin::VantaComplianceScope,
    endpoint: &VantaEndpoint,
) -> VantaResponseBody {
    let audit_id = scope.audit.id.clone();
    match endpoint {
        VantaEndpoint::ListAudits { .. } => VantaResponseBody::Audits(vec![
            hartevo_vanta_compliance_result_plugin::VantaAuditRecord::new(
                audit_id,
                scope.audit.framework_id.clone(),
                scope.audit.revision,
                VantaComplianceState::Complete,
            ),
        ]),
        VantaEndpoint::ListControls { .. } => {
            VantaResponseBody::Controls(vec![VantaControlRecord::new(
                audit_id,
                scope.controls[0].clone(),
                Revision::new(8).expect("control revision"),
                VantaComplianceState::Complete,
            )])
        }
        VantaEndpoint::ListTests { .. } => VantaResponseBody::Tests(vec![VantaTestRecord::new(
            audit_id,
            scope.tests[0].clone(),
            Some(scope.controls[0].clone()),
            Revision::new(9).expect("test revision"),
            VantaComplianceState::Complete,
        )]),
        VantaEndpoint::ListIssues { .. } => VantaResponseBody::Issues(vec![VantaIssueRecord::new(
            audit_id,
            scope.issues[0].clone(),
            Some(scope.controls[0].clone()),
            Revision::new(10).expect("issue revision"),
            VantaComplianceState::Complete,
        )]),
        VantaEndpoint::ListInformationRequests { .. } => {
            VantaResponseBody::InformationRequests(vec![VantaInformationRequestRecord::new(
                audit_id,
                scope.information_requests[0].clone(),
                Some(scope.controls[0].clone()),
                Revision::new(12).expect("request revision"),
                VantaComplianceState::Complete,
            )])
        }
    }
}

fn fixture_responses(
    scope: &hartevo_vanta_compliance_result_plugin::VantaComplianceScope,
) -> Vec<Result<VantaHttpResponse, hartevo_vanta_compliance_result_plugin::VantaTransportError>> {
    scope
        .expected_endpoints()
        .into_iter()
        .map(|endpoint| {
            let request = request_for(scope, endpoint.clone());
            VantaHttpResponse::from_body(
                &request,
                200,
                body_for(scope, &endpoint),
                provider_revision(),
                None,
            )
        })
        .collect()
}

fn service_with_fixture() -> VantaComplianceResultService<RecordingVantaTransport> {
    let scope = scope();
    let provider = VantaProvider::new(RecordingVantaTransport::fixture(fixture_responses(&scope)))
        .expect("provider");
    VantaComplianceResultService::new(scope, secret(), provider).expect("service")
}

#[test]
fn contract_and_typed_registration_are_fenced() {
    let contract = VantaComplianceResultContract::baseline().expect("contract");
    assert_eq!(
        contract.digest(),
        hartevo_vanta_compliance_result_plugin::contract_digest()
    );

    let service = service_with_fixture();
    let registration = service.registration();
    assert!(registration.is_active());
    assert_eq!(registration.audit_revision.get(), 7);
    assert_eq!(registration.project_revision.get(), 5);
    assert_eq!(registration.mission_revision.get(), 11);
    assert!(!format!("{:?}", service.secret_reference()).contains("vanta-native-secret-material"));
    assert!(
        !serde_json::to_string(service.secret_reference())
            .expect("secret JSON")
            .contains("vanta-native-secret-material")
    );
}

#[test]
fn complete_result_is_redacted_non_native_and_recordable() {
    let mut service = service_with_fixture();
    let proposal = service
        .propose(VantaProposalRequest::new(
            service.scope().objective.clone(),
            at(),
        ))
        .expect("proposal");
    assert_eq!(proposal.projection.state, VantaComplianceState::Complete);
    assert_eq!(proposal.projection.observed_read_count, 5);
    assert!(!proposal.certification_claim);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.projection.no_issues_is_certification);
    assert_eq!(proposal.provenance, TransportProvenance::Fixture);
    let encoded = serde_json::to_string(&proposal).expect("proposal JSON");
    for forbidden in [
        "owner@example.com",
        "https://evidence.vanta.example",
        "provider comment",
        "document body",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "redaction failed for {forbidden}"
        );
    }

    let consumer =
        MissionVantaComplianceConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let result = consumer.consume(proposal.clone()).expect("Mission result");
    assert_eq!(
        result.decision_state,
        MissionVantaDecisionState::PendingDecision
    );
    assert!(!result.certification_claim);
    assert!(!result.adopted_outcome);
    let receipt = service.record(&proposal).expect("recording receipt");
    assert!(receipt.recorded);
    assert!(!receipt.raw_provider_payload_retained);
    assert!(receipt.owners_redacted);
    assert!(receipt.evidence_urls_redacted);
    assert!(receipt.comments_redacted);
    assert!(receipt.document_bodies_redacted);
}

#[test]
fn tamper_scope_and_registration_drift_fail_closed() {
    let mut service = service_with_fixture();
    let proposal = service
        .propose(VantaProposalRequest::new(
            service.scope().objective.clone(),
            at(),
        ))
        .expect("proposal");
    let consumer =
        MissionVantaComplianceConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let mut tampered = proposal.clone();
    tampered.projection.state = VantaComplianceState::Blocked;
    assert!(consumer.consume(tampered).is_err());

    service.revoke_registration().expect("revoke registration");
    assert!(!service.is_active());
    assert!(service.record(&proposal).is_err());
    assert!(service.revoke_registration().is_err());
}

#[test]
fn raw_json_parser_strictly_redacts_sensitive_provider_fields() {
    let scope = scope();
    let request = request_for(
        &scope,
        VantaEndpoint::ListAudits {
            audit_id: scope.audit.id.clone(),
        },
    );
    let raw = br#"{
      "results": { "data": [{
        "id": "audit-1",
        "frameworkId": "framework-1",
        "revision": 7,
        "status": "complete",
        "owner": "owner@example.com",
        "evidenceUrl": "https://evidence.vanta.example/secret",
        "comment": "provider comment",
        "documentBody": "document body"
      }] }
    }"#;
    let response = VantaHttpResponse::from_json(&request, 200, raw, provider_revision(), None)
        .expect("redacted JSON response");
    let encoded = serde_json::to_string(response.body()).expect("body JSON");
    assert!(encoded.contains("audit-1"));
    assert_eq!(request.path_and_query, "/v1/audits?pageSize=50");
    for forbidden in [
        "owner@example.com",
        "https://evidence.vanta.example",
        "provider comment",
        "document body",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "raw field survived: {forbidden}"
        );
    }
    assert!(!response.receipt().raw_provider_payload_retained);
    assert!(response.receipt().owners_redacted);
    assert!(response.receipt().evidence_urls_redacted);
    assert!(response.receipt().comments_redacted);
    assert!(response.receipt().document_bodies_redacted);
}

#[test]
fn allowlisted_get_paths_are_scoped_to_the_documented_api_family() {
    let scope = scope();
    let expected = [
        (
            VantaEndpoint::ListAudits {
                audit_id: scope.audit.id.clone(),
            },
            "/v1/audits?pageSize=50",
            VantaApiFamily::Audit,
        ),
        (
            VantaEndpoint::ListControls {
                audit_id: scope.audit.id.clone(),
            },
            "/v1/audits/audit-1/controls?pageSize=50",
            VantaApiFamily::Audit,
        ),
        (
            VantaEndpoint::ListIssues {
                audit_id: scope.audit.id.clone(),
            },
            "/v1/audits/audit-1/issues/items?pageSize=50",
            VantaApiFamily::Audit,
        ),
        (
            VantaEndpoint::ListInformationRequests {
                audit_id: scope.audit.id.clone(),
            },
            "/v1/audits/audit-1/information-requests?pageSize=50",
            VantaApiFamily::Audit,
        ),
        (
            VantaEndpoint::ListTests {
                audit_id: scope.audit.id.clone(),
            },
            "/v1/tests?pageSize=50",
            VantaApiFamily::Manage,
        ),
    ];
    for (endpoint, path, family) in expected {
        assert_eq!(endpoint.family(), family);
        assert_eq!(
            endpoint.path_and_query(VANTA_PAGE_SIZE, None).unwrap(),
            path
        );
    }
}

#[test]
fn pagination_is_bounded_and_cursor_loops_are_rejected() {
    let scope = scope();
    let endpoint = VantaEndpoint::ListControls {
        audit_id: scope.audit.id.clone(),
    };
    let request = request_for(&scope, endpoint.clone());
    let cursor = OpaqueCursor::new("page-1").expect("cursor");
    let first = VantaHttpResponse::from_body(
        &request,
        200,
        body_for(&scope, &endpoint),
        provider_revision(),
        Some(cursor.clone()),
    )
    .expect("first page");
    let second_request = {
        let read = VantaReadRequest::new(
            endpoint.clone(),
            scope.digest(),
            VANTA_PAGE_SIZE,
            VANTA_MAX_PAGES,
            at(),
        )
        .expect("read");
        VantaHttpRequest::new(&read, Some(cursor.clone())).expect("second request")
    };
    let second = VantaHttpResponse::from_body(
        &second_request,
        200,
        body_for(&scope, &endpoint),
        provider_revision(),
        Some(cursor),
    )
    .expect("loop page");
    let provider = VantaProvider::new(RecordingVantaTransport::new([Ok(first), Ok(second)]))
        .expect("provider");
    let mut service =
        VantaComplianceResultService::new(scope.clone(), secret(), provider).expect("service");
    assert!(
        service
            .read(endpoint, VANTA_PAGE_SIZE, VANTA_MAX_PAGES, at())
            .is_err()
    );
    assert!(
        VantaReadRequest::new(
            VantaEndpoint::ListControls {
                audit_id: scope.audit.id.clone(),
            },
            scope.digest(),
            VANTA_PAGE_SIZE + 1,
            VANTA_MAX_PAGES,
            at(),
        )
        .is_err()
    );
}

#[test]
fn item_revision_fences_reject_stale_control_evidence() {
    let scope = scope();
    let endpoint = VantaEndpoint::ListControls {
        audit_id: scope.audit.id.clone(),
    };
    let request = request_for(&scope, endpoint.clone());
    let stale_body = VantaResponseBody::Controls(vec![VantaControlRecord::new(
        scope.audit.id.clone(),
        scope.controls[0].clone(),
        Revision::new(7).expect("stale revision"),
        VantaComplianceState::Complete,
    )]);
    let response =
        VantaHttpResponse::from_body(&request, 200, stale_body, provider_revision(), None)
            .expect("response");
    let provider =
        VantaProvider::new(RecordingVantaTransport::new([Ok(response)])).expect("provider");
    let mut service =
        VantaComplianceResultService::new(scope, secret(), provider).expect("service");
    assert!(
        service
            .read(endpoint, VANTA_PAGE_SIZE, VANTA_MAX_PAGES, at())
            .is_err()
    );
}

#[test]
fn blocked_env_is_explicitly_provider_unknown_and_never_connected() {
    let scope = scope();
    let provider = VantaProvider::new(BlockedEnvVantaTransport).expect("provider");
    let mut service =
        VantaComplianceResultService::new(scope.clone(), secret(), provider).expect("service");
    let proposal = service
        .propose(VantaProposalRequest::new(scope.objective.clone(), at()))
        .expect("blocked proposal");
    assert_eq!(
        proposal.projection.state,
        VantaComplianceState::ProviderUnknown
    );
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.certification_claim);
    assert_eq!(proposal.projection.observed_read_count, 5);
}

#[test]
fn five_requests_per_minute_are_enforced_without_native_auth() {
    let scope = scope();
    let provider = VantaProvider::new(BlockedEnvVantaTransport).expect("provider");
    let mut service =
        VantaComplianceResultService::new(scope.clone(), secret(), provider).expect("service");
    let endpoint = VantaEndpoint::ListAudits {
        audit_id: scope.audit.id.clone(),
    };
    let mut saw_rate_limit = false;
    for _ in 0..6 {
        let error = service
            .read(endpoint.clone(), VANTA_PAGE_SIZE, VANTA_MAX_PAGES, at())
            .expect_err("blocked transport should not read");
        if matches!(
            error,
            hartevo_vanta_compliance_result_plugin::VantaComplianceResultError::RateLimited { .. }
        ) {
            saw_rate_limit = true;
        }
    }
    assert!(saw_rate_limit);
}

#[test]
fn fixture_recording_and_loopback_provenance_are_non_native() {
    let scope = scope();
    let endpoint = VantaEndpoint::ListAudits {
        audit_id: scope.audit.id.clone(),
    };
    let request = request_for(&scope, endpoint.clone());
    let response = VantaHttpResponse::from_body(
        &request,
        200,
        body_for(&scope, &endpoint),
        provider_revision(),
        None,
    )
    .expect("response");
    for transport in [
        RecordingVantaTransport::fixture([Ok(response.clone())]),
        RecordingVantaTransport::new([Ok(response.clone())]),
        RecordingVantaTransport::loopback([Ok(response)]),
    ] {
        let provider = VantaProvider::new(transport).expect("provider");
        assert!(!provider.provenance().is_native());
        assert!(!provider_is_native(&provider));
    }
}

fn provider_is_native<T: hartevo_vanta_compliance_result_plugin::VantaTransport>(
    provider: &VantaProvider<T>,
) -> bool {
    provider.transport().is_native()
}

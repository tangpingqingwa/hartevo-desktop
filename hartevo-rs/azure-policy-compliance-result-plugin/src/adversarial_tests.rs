use serde_json::json;

use crate::{
    AzurePolicyComplianceService, AzurePolicyHttpResponse, AzurePolicyReadRequest,
    AzurePolicyScope, AzurePolicyTransportError, BlockedEnvAzurePolicyTransport, ComplianceState,
    ComplianceSummary, Digest, EvidenceStatus, MAX_RECORDS_PER_PAGE, MissionAzurePolicyConsumer,
    MissionBinding, ODataFilter, PolicyFingerprints, PolicyStateView, ProjectBinding,
    ProviderErrorKind, ProviderProvenance, QueryBounds, QueryWindow, RecordingAzurePolicyTransport,
    ResourceGroupName, ResourceId, SecretReference, SubscriptionId, Timestamp, WorkProductBinding,
};

const START: &str = "2026-08-14T00:00:00Z";
const END: &str = "2026-08-16T00:00:00Z";
const RESOURCE: &str =
    "/subscriptions/sub-01/resourceGroups/rg-01/providers/Microsoft.Compute/virtualMachines/vm-01";
const POLICY_DEFINITION: &str = "/providers/Microsoft.Authorization/policyDefinitions/policy-1";
const POLICY_ASSIGNMENT: &str =
    "/subscriptions/sub-01/providers/Microsoft.Authorization/policyAssignments/assign-1";
const POLICY_SET: &str = "/providers/Microsoft.Authorization/policySetDefinitions/set-1";

fn scope() -> AzurePolicyScope {
    let fingerprints = PolicyFingerprints::new(
        [Digest::from_text(POLICY_DEFINITION)],
        [Digest::from_text(POLICY_ASSIGNMENT)],
        [Digest::from_text(POLICY_SET)],
    )
    .expect("fingerprints");
    let window = QueryWindow::with_bounds(
        Timestamp::new(START).expect("start"),
        Timestamp::new(END).expect("end"),
        PolicyStateView::Latest,
        QueryBounds::new(3, 8, MAX_RECORDS_PER_PAGE, 32 * 1024).expect("bounds"),
    )
    .expect("window");
    AzurePolicyScope::new(
        "tenant-01",
        SubscriptionId::new("sub-01").expect("subscription"),
        Some(ResourceGroupName::new("rg-01").expect("resource group")),
        Some(ResourceId::new(RESOURCE).expect("resource")),
        fingerprints,
        window,
        ProjectBinding::new("project-01", 4).expect("project"),
        MissionBinding::new("mission-01", 7).expect("mission"),
        WorkProductBinding::new("work-product-01", 9).expect("work product"),
        Digest::from_text("permission-fence-01"),
    )
    .expect("scope")
}

fn response_body(state: &str) -> String {
    json!({
        "value": [{
            "policyAssignmentId": POLICY_ASSIGNMENT,
            "policyDefinitionId": POLICY_DEFINITION,
            "policySetDefinitionId": POLICY_SET,
            "resourceId": RESOURCE,
            "complianceState": state,
            "timestamp": "2026-08-15T12:00:00Z",
            "resourceLocation": "eastus",
            "resourceType": "Microsoft.Compute/virtualMachines",
            "policyDefinitionGroupNames": ["security"],
            "policyDefinitionAction": "audit",
            "policyAssignmentScope": "/subscriptions/sub-01",
            "managementGroupIds": ["mg-01"],
            "resourceTags": {"secret": "do-not-retain"},
            "remediationDetails": {"command": "do-not-retain"}
        }],
        "rawPolicyJson": {"secret": "do-not-retain"}
    })
    .to_string()
}

fn recorded_service(
    responses: impl IntoIterator<Item = Result<AzurePolicyHttpResponse, AzurePolicyTransportError>>,
) -> AzurePolicyComplianceService<RecordingAzurePolicyTransport> {
    service_for_scope(scope(), responses)
}

fn service_for_scope(
    scope: AzurePolicyScope,
    responses: impl IntoIterator<Item = Result<AzurePolicyHttpResponse, AzurePolicyTransportError>>,
) -> AzurePolicyComplianceService<RecordingAzurePolicyTransport> {
    let secret = SecretReference::new("entra-keyring-handle", &scope, 3).expect("secret");
    let mut transport = RecordingAzurePolicyTransport::new();
    for response in responses {
        match response {
            Ok(response) => transport.push_response(response),
            Err(error) => transport.push_error(error),
        }
    }
    let provider = crate::AzurePolicyInsightsProvider::new(
        scope,
        secret,
        transport,
        ProviderProvenance::Recording,
    )
    .expect("provider");
    AzurePolicyComplianceService::new(provider).expect("service")
}

fn request(scope: &AzurePolicyScope) -> AzurePolicyReadRequest {
    AzurePolicyReadRequest::without_filter(scope).expect("request")
}

#[test]
fn bounded_resource_query_redacts_payload_and_reports_provider_state_only() {
    let scope = scope();
    let mut service = recorded_service([Ok(AzurePolicyHttpResponse::ok(response_body(
        "NonCompliant",
    )))]);
    let proposal = service.propose(&request(&scope)).expect("proposal");
    assert_eq!(proposal.status(), EvidenceStatus::Complete);
    assert_eq!(proposal.summary(), &ComplianceSummary::NonCompliant);
    assert_eq!(
        proposal.evidence.records[0].compliance_state,
        ComplianceState::NonCompliant
    );
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.certification);
    assert!(!proposal.outcome_authority);
    assert_eq!(proposal.evidence.records.len(), 1);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for forbidden in [
        "entra-keyring-handle",
        "do-not-retain",
        "remediationDetails",
        "rawPolicyJson",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
    let request = &service.provider().transport().requests()[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.api_version, crate::AZURE_POLICY_API_VERSION);
    assert!(request.path.contains("queryResults"));
}

#[test]
fn allowlisted_odata_ast_rejects_injection_and_keeps_filter_bounded() {
    assert!(ODataFilter::parse("complianceState eq 'Compliant'").is_ok());
    assert!(
        ODataFilter::parse(
            "complianceState eq 'Compliant' and timestamp ge '2026-08-14T00:00:00Z'"
        )
        .is_ok()
    );
    for injected in [
        "complianceState eq 'Compliant' or 1 eq 1",
        "complianceState eq 'Compliant'; drop table",
        "complianceState eq 'Compliant' --comment",
        "rawField eq 'secret'",
        "complianceState eq 'Compliant' and (resourceId eq 'secret')",
    ] {
        assert!(ODataFilter::parse(injected).is_err(), "{injected}");
    }
}

#[test]
fn resource_group_and_subscription_endpoints_are_bounded_and_state_view_bound() {
    let fingerprints = PolicyFingerprints::empty();
    let window = QueryWindow::new(
        Timestamp::new(START).expect("start"),
        Timestamp::new(END).expect("end"),
        PolicyStateView::Default,
    )
    .expect("window");
    let resource_group_scope = AzurePolicyScope::new(
        "tenant-01",
        SubscriptionId::new("sub-01").expect("subscription"),
        Some(ResourceGroupName::new("rg-01").expect("resource group")),
        None,
        fingerprints.clone(),
        window.clone(),
        ProjectBinding::new("project-01", 4).expect("project"),
        MissionBinding::new("mission-01", 7).expect("mission"),
        WorkProductBinding::new("work-product-01", 9).expect("work product"),
        Digest::from_text("permission-fence-01"),
    )
    .expect("resource-group scope");
    let mut resource_group_service = service_for_scope(
        resource_group_scope.clone(),
        [Ok(AzurePolicyHttpResponse::ok(response_body("Compliant")))],
    );
    let resource_group_evidence = resource_group_service
        .read(&request(&resource_group_scope))
        .expect("resource-group read");
    assert_eq!(resource_group_evidence.status, EvidenceStatus::Complete);
    assert!(
        resource_group_service.provider().transport().requests()[0]
            .path
            .contains("/resourceGroups/rg-01/")
    );
    assert!(
        resource_group_service.provider().transport().requests()[0]
            .path
            .contains("/policyStates/default/queryResults")
    );

    let subscription_scope = AzurePolicyScope::new(
        "tenant-01",
        SubscriptionId::new("sub-01").expect("subscription"),
        None,
        None,
        fingerprints,
        window,
        ProjectBinding::new("project-01", 4).expect("project"),
        MissionBinding::new("mission-01", 7).expect("mission"),
        WorkProductBinding::new("work-product-01", 9).expect("work product"),
        Digest::from_text("permission-fence-01"),
    )
    .expect("subscription scope");
    let mut subscription_service = service_for_scope(
        subscription_scope.clone(),
        [Ok(AzurePolicyHttpResponse::ok(response_body("Exempt")))],
    );
    let subscription_evidence = subscription_service
        .read(&request(&subscription_scope))
        .expect("subscription read");
    assert_eq!(subscription_evidence.status, EvidenceStatus::Complete);
    assert_eq!(subscription_evidence.summary, ComplianceSummary::Exempt);
    assert!(
        subscription_service.provider().transport().requests()[0]
            .path
            .contains("/subscriptions/sub-01/providers/Microsoft.PolicyInsights")
    );
}

#[test]
fn filter_query_is_bound_into_registration_proposal_record_and_verify() {
    let scope = scope();
    let filter = ODataFilter::compliance_state(ComplianceState::Compliant);
    let request = AzurePolicyReadRequest::with_filter(&scope, filter).expect("filtered request");
    let mut service =
        recorded_service([Ok(AzurePolicyHttpResponse::ok(response_body("Compliant")))]);
    let proposal = service.propose(&request).expect("filtered proposal");
    assert_eq!(proposal.evidence.summary, ComplianceSummary::Compliant);
    assert_eq!(
        service.provider().transport().requests()[0]
            .filter
            .as_deref(),
        Some("complianceState eq 'Compliant'")
    );
    service.verify(&proposal).expect("filtered verify");
    service.record(&proposal).expect("filtered record");
}

#[test]
fn all_policy_states_are_typed_without_certification_claims() {
    for (state, expected) in [
        ("Compliant", ComplianceSummary::Compliant),
        ("NonCompliant", ComplianceSummary::NonCompliant),
        ("Exempt", ComplianceSummary::Exempt),
        ("Unknown", ComplianceSummary::Unknown),
    ] {
        let scope = scope();
        let mut service = recorded_service([Ok(AzurePolicyHttpResponse::ok(response_body(state)))]);
        let proposal = service.propose(&request(&scope)).expect("proposal");
        assert_eq!(proposal.summary(), &expected);
        assert!(!proposal.certification);
    }
}

#[test]
fn http_statuses_and_transport_failures_fail_closed_without_body_retention() {
    for status in [400, 401, 403, 404, 409, 429, 500, 503] {
        let scope = scope();
        let mut service = recorded_service([Ok(AzurePolicyHttpResponse::new(
            status,
            r#"{"error":{"message":"private policy diagnostic","remediation":"secret"}}"#,
        ))]);
        let proposal = service
            .propose(&request(&scope))
            .expect("typed failure proposal");
        assert!(matches!(
            proposal.status(),
            EvidenceStatus::AccessLost
                | EvidenceStatus::ProviderUnknown
                | EvidenceStatus::FinalError
        ));
        assert_eq!(proposal.evidence.records.len(), 0);
        let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
        assert!(!serialized.contains("private policy diagnostic"));
        assert!(!serialized.contains("remediation"));
    }
    let scope = scope();
    let mut service = recorded_service([Err(AzurePolicyTransportError::timeout())]);
    let proposal = service.propose(&request(&scope)).expect("timeout proposal");
    assert_eq!(proposal.status(), EvidenceStatus::ProviderUnknown);
    assert_eq!(
        proposal.evidence.provider_errors[0].kind,
        ProviderErrorKind::Timeout
    );
}

#[test]
fn pagination_is_bounded_and_next_links_are_scope_fenced() {
    let scope = scope();
    let next_link = "https://management.azure.com/subscriptions/sub-01/resourceGroups/rg-01/providers/Microsoft.Compute/virtualMachines/vm-01/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2024-10-01&$skiptoken=cursor-1";
    let first = json!({
        "value": [{
            "policyAssignmentId": POLICY_ASSIGNMENT,
            "policyDefinitionId": POLICY_DEFINITION,
            "policySetDefinitionId": POLICY_SET,
            "resourceId": RESOURCE,
            "complianceState": "Compliant",
            "timestamp": "2026-08-15T12:00:00Z"
        }],
        "@odata.nextLink": next_link
    })
    .to_string();
    let mut service = recorded_service([
        Ok(AzurePolicyHttpResponse::ok(first)),
        Ok(AzurePolicyHttpResponse::ok(response_body("Exempt"))),
    ]);
    let evidence = service.read(&request(&scope)).expect("paged read");
    assert_eq!(evidence.pages_observed, 2);
    assert_eq!(evidence.records.len(), 2);
    assert_eq!(evidence.next_link_digests.len(), 1);
    assert_eq!(service.provider().transport().call_count(), 2);

    let bad_link = next_link.replace("sub-01", "other-subscription");
    let bad_page = json!({"value": [], "@odata.nextLink": bad_link}).to_string();
    let mut service = recorded_service([Ok(AzurePolicyHttpResponse::ok(bad_page))]);
    let evidence = service
        .read(&request(&scope))
        .expect("fenced link evidence");
    assert_eq!(evidence.status, EvidenceStatus::FinalError);
    assert_eq!(
        evidence.provider_errors[0].kind,
        ProviderErrorKind::NextLinkScopeMismatch
    );
}

#[test]
fn partial_page_and_replayed_cursor_fail_closed() {
    let scope = scope();
    let partial = json!({"value": [], "partial": true}).to_string();
    let mut service = recorded_service([Ok(AzurePolicyHttpResponse::ok(partial))]);
    let evidence = service.read(&request(&scope)).expect("partial evidence");
    assert_eq!(evidence.status, EvidenceStatus::FinalError);
    assert_eq!(
        evidence.provider_errors[0].kind,
        ProviderErrorKind::PartialPage
    );

    let next_link = "https://management.azure.com/subscriptions/sub-01/resourceGroups/rg-01/providers/Microsoft.Compute/virtualMachines/vm-01/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2024-10-01&$skiptoken=cursor-1";
    let first = json!({"value": [], "@odata.nextLink": next_link}).to_string();
    let second = json!({"value": [], "@odata.nextLink": next_link}).to_string();
    let mut service = recorded_service([
        Ok(AzurePolicyHttpResponse::ok(first)),
        Ok(AzurePolicyHttpResponse::ok(second)),
    ]);
    let evidence = service.read(&request(&scope)).expect("replay evidence");
    assert_eq!(
        evidence.provider_errors[0].kind,
        ProviderErrorKind::NextLinkReplay
    );
}

#[test]
fn blocked_env_fixture_and_loopback_are_truthful_provenance() {
    let scope = scope();
    let secret = SecretReference::new("entra-keyring-handle", &scope, 3).expect("secret");
    let provider = crate::AzurePolicyInsightsProvider::new(
        scope.clone(),
        secret,
        BlockedEnvAzurePolicyTransport,
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut service = AzurePolicyComplianceService::new(provider).expect("service");
    let evidence = service.read(&request(&scope)).expect("blocked evidence");
    assert_eq!(evidence.provenance, ProviderProvenance::BlockedEnv);
    assert_eq!(evidence.status, EvidenceStatus::ProviderUnknown);
    assert_eq!(
        evidence.provider_errors[0].kind,
        ProviderErrorKind::BlockedEnv
    );
    assert!(!evidence.provenance.is_native());
    assert!(!crate::Layer1Authority::connected());
    assert!(!crate::Layer1Authority::native_provider());
}

#[test]
fn registration_record_verify_consume_replay_tamper_and_revocation_are_fenced() {
    let fixture_scope = scope();
    let mut service =
        recorded_service([Ok(AzurePolicyHttpResponse::ok(response_body("Compliant")))]);
    let proposal = service.propose(&request(&fixture_scope)).expect("proposal");
    service.verify(&proposal).expect("verify");
    let receipt = service.record(&proposal).expect("record");
    assert!(!receipt.durable_native_receipt);
    assert!(!receipt.independent_readback);

    let mut tampered = proposal.clone();
    tampered.evidence.records.clear();
    assert!(service.verify(&tampered).is_err());
    assert!(service.revoke_registration().is_ok());
    assert!(matches!(
        service.verify(&proposal),
        Err(crate::AzurePolicyComplianceServiceError::RegistrationRevoked)
    ));

    let scope = scope();
    let secret = SecretReference::new("entra-keyring-handle", &scope, 3).expect("secret");
    let provider = crate::AzurePolicyInsightsProvider::new(
        scope.clone(),
        secret,
        RecordingAzurePolicyTransport::new(),
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let mut consumer = MissionAzurePolicyConsumer::new(provider).expect("consumer");
    consumer
        .service_mut()
        .provider_mut()
        .transport_mut()
        .push_response(AzurePolicyHttpResponse::ok(response_body("Compliant")));
    let proposal = consumer
        .propose(&request(&scope))
        .expect("consumer proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        crate::MissionAzurePolicyResultState::EvidenceReady
    );
    assert!(consumer.consume(&proposal).is_err());
    consumer.revoke().expect("consumer revoke");
    assert!(consumer.consume(&proposal).is_err());
}

#[test]
fn stale_scope_and_secret_reference_are_rejected() {
    let scope = scope();
    let other_scope = AzurePolicyScope::new(
        "tenant-01",
        SubscriptionId::new("other-sub").expect("subscription"),
        None,
        None,
        PolicyFingerprints::empty(),
        QueryWindow::new(
            Timestamp::new(START).expect("start"),
            Timestamp::new(END).expect("end"),
            PolicyStateView::Default,
        )
        .expect("window"),
        ProjectBinding::new("project-01", 4).expect("project"),
        MissionBinding::new("mission-01", 7).expect("mission"),
        WorkProductBinding::new("work-product-01", 9).expect("work product"),
        Digest::from_text("permission-fence-01"),
    )
    .expect("other scope");
    let secret = SecretReference::new("entra-keyring-handle", &scope, 3).expect("secret");
    assert_ne!(secret.scope_digest(), &other_scope.scope_digest());
    assert!(
        AzurePolicyReadRequest::new(
            &scope,
            Some(ODataFilter::compliance_state(ComplianceState::Compliant)),
        )
        .is_ok()
    );
}

use chrono::{Duration, TimeZone, Utc};
use hartevo_aws_firewall_manager_result_plugin::{
    AwsFirewallManagerError, AwsFirewallManagerProvider, AwsFirewallManagerReadRequest,
    AwsFirewallManagerScope, AwsFirewallManagerService, ComplianceDetailProjection, CompliancePage,
    ComplianceState, ConsentScope, Digest, EvidenceState, FixtureAwsFirewallManagerTransport,
    GetComplianceDetailRequest, GetPolicyRequest, ListComplianceStatusRequest, ListPoliciesRequest,
    MissionAwsFirewallManagerConsumer, MissionBinding, OpaquePageToken, PermissionSnapshot,
    PolicyIdentity, PolicyPage, PolicyPosture, PolicySummary, PolicyType, ProjectBinding,
    ResourceId, ResourceType, Revision, SecretReference, TransportError, TransportFailure,
    WorkProductBinding,
};

const NOW: i64 = 1_787_000_000;
const RAW_POLICY_ID: &str = "p-examplepolicyid111";
const RAW_POLICY_ARN: &str = "arn:aws:fms:us-east-1:111111111111:policy/p-examplepolicyid111";
const RAW_RESOURCE_ID: &str = "i-raw-resource-id-123";
const RAW_VIOLATION: &str = "provider-private-violation-category";
const RAW_SECRET: &str = "host-secret-handle/aws-fms/653";

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW, 0).single().expect("fixture time")
}

fn scope() -> AwsFirewallManagerScope {
    let policy = PolicyIdentity::new(
        PolicyType::Waf,
        hartevo_aws_firewall_manager_result_plugin::PolicyId::new(RAW_POLICY_ID).unwrap(),
        hartevo_aws_firewall_manager_result_plugin::PolicyArn::new(RAW_POLICY_ARN).unwrap(),
        Revision::new(3).unwrap(),
    );
    AwsFirewallManagerScope::new(
        hartevo_aws_firewall_manager_result_plugin::OrganizationId::new("o-exampleorgid").unwrap(),
        hartevo_aws_firewall_manager_result_plugin::AdminAccountId::new("111111111111").unwrap(),
        hartevo_aws_firewall_manager_result_plugin::AwsRegion::new("us-east-1").unwrap(),
        vec![policy],
        vec![
            hartevo_aws_firewall_manager_result_plugin::MemberAccountId::new("222222222222")
                .unwrap(),
            hartevo_aws_firewall_manager_result_plugin::MemberAccountId::new("333333333333")
                .unwrap(),
        ],
        vec![
            ResourceType::new("AWS::EC2::Instance").unwrap(),
            ResourceType::new("AWS::S3::Bucket").unwrap(),
        ],
        MissionBinding::new(
            hartevo_aws_firewall_manager_result_plugin::MissionId::new("mission-653").unwrap(),
            Revision::new(7).unwrap(),
        ),
        ProjectBinding::new(
            hartevo_aws_firewall_manager_result_plugin::ProjectId::new("project-653").unwrap(),
            Revision::new(11).unwrap(),
        ),
        WorkProductBinding::new(
            hartevo_aws_firewall_manager_result_plugin::WorkProductId::new("work-product-653")
                .unwrap(),
            Revision::new(13).unwrap(),
        ),
        PermissionSnapshot::for_layer_one(Revision::new(1).unwrap()),
        ConsentScope::for_layer_one(
            "consent-653",
            Revision::new(1).unwrap(),
            now() + Duration::days(7),
        )
        .unwrap(),
    )
    .unwrap()
}

fn policy(scope: &AwsFirewallManagerScope) -> PolicyIdentity {
    scope.policies()[0].clone()
}

fn secret(scope: &AwsFirewallManagerScope) -> SecretReference {
    SecretReference::sigv4(RAW_SECRET, scope, Revision::new(1).unwrap()).unwrap()
}

fn make_service(
    transport: FixtureAwsFirewallManagerTransport,
) -> AwsFirewallManagerService<FixtureAwsFirewallManagerTransport> {
    let scope = scope();
    AwsFirewallManagerService::new(
        scope.clone(),
        secret(&scope),
        AwsFirewallManagerProvider::new(transport).unwrap(),
        now(),
    )
    .unwrap()
}

fn list_policy_request(scope: &AwsFirewallManagerScope) -> ListPoliciesRequest {
    ListPoliciesRequest::new(scope, None, 10, None).unwrap()
}

fn list_policy_page(
    request: &ListPoliciesRequest,
    policy: &PolicyIdentity,
    next: Option<OpaquePageToken>,
) -> PolicyPage {
    PolicyPage::new(
        request,
        vec![PolicySummary::from_identity(policy)],
        next,
        512,
        hartevo_aws_firewall_manager_result_plugin::TransportProvenance::Fixture,
    )
    .unwrap()
}

#[test]
fn contract_scope_registration_and_secret_are_digest_bound() {
    let contract =
        hartevo_aws_firewall_manager_result_plugin::AwsFirewallManagerContract::baseline().unwrap();
    assert_eq!(
        contract.digest(),
        hartevo_aws_firewall_manager_result_plugin::contract_digest()
    );
    let scope = scope();
    let registration_service = make_service(FixtureAwsFirewallManagerTransport::default());
    assert!(scope.validate().is_ok());
    assert!(registration_service.registration().validate().is_ok());
    let serialized = serde_json::to_string(registration_service.registration()).unwrap();
    let scope_json = serde_json::to_string(&scope).unwrap();
    let debug = format!("{:?}", registration_service.registration());
    for raw in [RAW_SECRET, RAW_POLICY_ID, RAW_POLICY_ARN, "111111111111"] {
        assert!(!serialized.contains(raw), "registration leaked {raw}");
        assert!(!scope_json.contains(raw), "scope leaked {raw}");
        assert!(!debug.contains(raw), "debug leaked {raw}");
    }
    assert!(!registration_service.describe_capabilities().connected);
    assert!(!registration_service.describe_capabilities().native);
    assert!(!registration_service.describe_capabilities().first_party);
}

#[test]
fn list_policies_produces_complete_redacted_mission_proposal_and_replayable_record() {
    let scope = scope();
    let request = list_policy_request(&scope);
    let mut transport = FixtureAwsFirewallManagerTransport::default();
    transport.queue_list_policies(Ok(list_policy_page(&request, &policy(&scope), None)));
    let mut service = make_service(transport);
    let proposal = service
        .propose(AwsFirewallManagerReadRequest::ListPolicies(request))
        .unwrap();
    assert_eq!(proposal.evidence.state, EvidenceState::Complete);
    assert!(proposal.evidence.pagination.complete);
    assert_eq!(proposal.evidence.policy_summaries.len(), 1);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.first_party);
    assert!(!proposal.evidence.provider_receipt);
    assert!(!proposal.evidence.outcome_adopted);
    assert!(proposal.validate_integrity().is_ok());
    let mut consumer = MissionAwsFirewallManagerConsumer::new(service.scope());
    consumer.bind_registration(service.registration()).unwrap();
    let result = consumer.consume(&proposal).unwrap();
    assert!(result.accepted);
    assert!(!result.adopted_outcome);
    assert!(!result.adopted_work_product);
    let first = service.record(&proposal, "record-key-653").unwrap();
    let replay = service.record(&proposal, "record-key-653").unwrap();
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);
}

#[test]
fn get_policy_projects_posture_without_policy_json_or_rule_body() {
    let scope = scope();
    let identity = policy(&scope);
    let request = GetPolicyRequest::new(&scope, identity.clone()).unwrap();
    let posture = PolicyPosture::new(
        &identity,
        vec![scope.resource_types()[0].clone()],
        Digest::from_text("resource-scope-fixture"),
        false,
        Some("managed-service-fixture".to_owned()),
    )
    .unwrap();
    let response = hartevo_aws_firewall_manager_result_plugin::PolicyResponse::new(
        &request,
        posture,
        512,
        hartevo_aws_firewall_manager_result_plugin::TransportProvenance::Fixture,
    )
    .unwrap();
    let mut transport = FixtureAwsFirewallManagerTransport::default();
    transport.queue_get_policy(Ok(response));
    let mut service = make_service(transport);
    let proposal = service
        .propose(AwsFirewallManagerReadRequest::GetPolicy(request))
        .unwrap();
    assert!(proposal.evidence.policy_posture.is_some());
    assert!(
        !proposal
            .evidence
            .policy_posture
            .as_ref()
            .unwrap()
            .remediation_enabled
    );
    let json = serde_json::to_string(&proposal).unwrap();
    assert!(!json.contains(RAW_POLICY_ID));
    assert!(!json.contains(RAW_POLICY_ARN));
    assert!(!json.contains("managed-service-fixture"));
    assert!(!json.contains("PolicyDocument"));
}

#[test]
fn compliance_status_and_detail_redact_resource_and_violation_values() {
    let scope = scope();
    let identity = policy(&scope);
    let list_request =
        ListComplianceStatusRequest::new(&scope, identity.clone(), 10, None).unwrap();
    let status = hartevo_aws_firewall_manager_result_plugin::ComplianceSummary::new(
        &identity,
        &scope.member_accounts()[0],
        ComplianceState::NonCompliant,
        4,
        2,
        vec![scope.resource_types()[0].clone()],
        vec![RAW_VIOLATION.to_owned()],
        Revision::new(9).unwrap(),
        now(),
    )
    .unwrap();
    let page = CompliancePage::new(
        &list_request,
        vec![status],
        None,
        512,
        hartevo_aws_firewall_manager_result_plugin::TransportProvenance::Fixture,
    )
    .unwrap();
    let detail_request = GetComplianceDetailRequest::new(
        &scope,
        identity,
        scope.member_accounts()[0].clone(),
        scope.resource_types()[0].clone(),
        ResourceId::new(RAW_RESOURCE_ID).unwrap(),
    )
    .unwrap();
    let detail = ComplianceDetailProjection::new(
        &detail_request,
        ComplianceState::NonCompliant,
        vec![RAW_VIOLATION.to_owned()],
        Revision::new(9).unwrap(),
        now(),
    )
    .unwrap();
    let detail_response =
        hartevo_aws_firewall_manager_result_plugin::ComplianceDetailResponse::new(
            &detail_request,
            detail,
            512,
            hartevo_aws_firewall_manager_result_plugin::TransportProvenance::Fixture,
        )
        .unwrap();
    let mut transport = FixtureAwsFirewallManagerTransport::default();
    transport.queue_list_compliance_status(Ok(page));
    let mut service = make_service(transport);
    let proposal = service
        .propose(AwsFirewallManagerReadRequest::ListComplianceStatus(
            list_request,
        ))
        .unwrap();
    assert_eq!(proposal.evidence.compliance_statuses.len(), 1);
    assert_eq!(
        proposal.evidence.compliance_statuses[0]
            .violation_category_digests
            .len(),
        1
    );
    let json = serde_json::to_string(&proposal).unwrap();
    assert!(!json.contains(RAW_RESOURCE_ID));
    assert!(!json.contains(RAW_VIOLATION));
    assert!(!json.contains("accountEmail"));

    let mut detail_transport = FixtureAwsFirewallManagerTransport::default();
    detail_transport.queue_get_compliance_detail(Ok(detail_response));
    let mut detail_service = make_service(detail_transport);
    let detail_proposal = detail_service
        .propose(AwsFirewallManagerReadRequest::GetComplianceDetail(
            detail_request,
        ))
        .unwrap();
    assert!(detail_proposal.evidence.compliance_detail.is_some());
    let detail_json = serde_json::to_string(&detail_proposal).unwrap();
    assert!(!detail_json.contains(RAW_RESOURCE_ID));
    assert!(!detail_json.contains(RAW_VIOLATION));
}

#[test]
fn pagination_is_opaque_bounded_and_loop_or_incomplete_is_non_adoptable() {
    let scope = scope();
    let first_request = list_policy_request(&scope);
    let cursor = OpaquePageToken::new(
        "raw-provider-next-token",
        first_request.request_digest(),
        &first_request.scope_digest,
        2,
    )
    .unwrap();
    let second_request = first_request.with_cursor(Some(cursor.clone())).unwrap();
    let mut transport = FixtureAwsFirewallManagerTransport::default();
    transport.queue_list_policies(Ok(list_policy_page(
        &first_request,
        &policy(&scope),
        Some(cursor.clone()),
    )));
    transport.queue_list_policies(Ok(list_policy_page(&second_request, &policy(&scope), None)));
    let mut service = make_service(transport);
    let proposal = service
        .propose(AwsFirewallManagerReadRequest::ListPolicies(first_request))
        .unwrap();
    assert_eq!(proposal.evidence.pagination.pages_observed, 2);
    assert!(proposal.evidence.pagination.complete);
    let json = serde_json::to_string(&proposal).unwrap();
    assert!(!json.contains("raw-provider-next-token"));

    let mut incomplete_transport = FixtureAwsFirewallManagerTransport::default();
    let one = list_policy_request(&scope);
    let next =
        OpaquePageToken::new("still-more", one.request_digest(), &one.scope_digest, 2).unwrap();
    incomplete_transport.queue_list_policies(Ok(list_policy_page(
        &one,
        &policy(&scope),
        Some(next),
    )));
    let mut incomplete_service = make_service(incomplete_transport);
    let incomplete = incomplete_service
        .propose(AwsFirewallManagerReadRequest::ListPolicies(one))
        .unwrap();
    assert_eq!(incomplete.evidence.state, EvidenceState::Partial);
    assert!(!incomplete.evidence.pagination.complete);
    assert!(
        MissionAwsFirewallManagerConsumer::new(incomplete_service.scope())
            .propose_review(&incomplete.evidence)
            .is_ok()
    );
}

#[test]
fn provider_error_classes_fail_closed_and_access_loss_is_explicit() {
    for (failure, expected) in [
        (TransportFailure::BadRequest, EvidenceState::Unknown),
        (TransportFailure::Unauthorized, EvidenceState::AccessLoss),
        (TransportFailure::AccessDenied, EvidenceState::AccessLoss),
        (TransportFailure::NotFound, EvidenceState::Unknown),
        (TransportFailure::Throttled, EvidenceState::Unknown),
        (TransportFailure::Server, EvidenceState::Unknown),
        (TransportFailure::Timeout, EvidenceState::Unknown),
    ] {
        let scope = scope();
        let request = list_policy_request(&scope);
        let mut transport = FixtureAwsFirewallManagerTransport::default();
        transport.queue_list_policies(Err(TransportError::new(failure)));
        let mut service = make_service(transport);
        let proposal = service
            .propose(AwsFirewallManagerReadRequest::ListPolicies(request))
            .unwrap();
        assert_eq!(proposal.evidence.state, expected);
        assert!(!service.verify(&proposal).review_eligible);
    }
}

#[test]
fn tamper_expiry_registration_revocation_and_permission_drift_fail_closed() {
    let scope = scope();
    let request = list_policy_request(&scope);
    let mut transport = FixtureAwsFirewallManagerTransport::default();
    transport.queue_list_policies(Ok(list_policy_page(&request, &policy(&scope), None)));
    let mut service = make_service(transport);
    let mut proposal = service
        .propose(AwsFirewallManagerReadRequest::ListPolicies(request))
        .unwrap();
    proposal.evidence.scope_digest = Digest::from_text("tampered-scope");
    assert!(proposal.validate_integrity().is_err());

    let mut fresh = make_service(FixtureAwsFirewallManagerTransport::default());
    let fresh_scope = fresh.scope().clone();
    let fresh_request = list_policy_request(&fresh_scope);
    let mut expired_transport = FixtureAwsFirewallManagerTransport::default();
    expired_transport.queue_list_policies(Ok(list_policy_page(
        &fresh_request,
        &policy(&fresh_scope),
        None,
    )));
    let mut expired_service = make_service(expired_transport);
    let expired_proposal = expired_service
        .propose_at(
            AwsFirewallManagerReadRequest::ListPolicies(fresh_request),
            now(),
            now() + Duration::minutes(1),
        )
        .unwrap();
    assert!(
        !expired_service
            .verify_at(&expired_proposal, now() + Duration::minutes(2))
            .review_eligible
    );

    assert!(fresh.revoke_registration().is_ok());
    assert!(
        fresh
            .propose(AwsFirewallManagerReadRequest::ListPolicies(
                list_policy_request(&fresh_scope),
            ))
            .is_err()
    );
    assert!(matches!(
        AwsFirewallManagerError::Transport(TransportError::blocked_env()),
        AwsFirewallManagerError::Transport(_)
    ));
}

#[test]
fn all_non_native_transport_provenances_are_honest() {
    for provenance in [
        hartevo_aws_firewall_manager_result_plugin::TransportProvenance::Fixture,
        hartevo_aws_firewall_manager_result_plugin::TransportProvenance::Fake,
        hartevo_aws_firewall_manager_result_plugin::TransportProvenance::Recording,
        hartevo_aws_firewall_manager_result_plugin::TransportProvenance::Loopback,
        hartevo_aws_firewall_manager_result_plugin::TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

use hartevo_aws_network_firewall_posture_result_plugin::{
    AwsAccountId, AwsNetworkFirewallPostureService, AwsNetworkFirewallProvider,
    AwsNetworkFirewallReadRequest, AwsNetworkFirewallScope, AwsRegion,
    DescribeFirewallPolicyRequest, DescribeFirewallPolicyResponse, Digest, EndpointBinding,
    FirewallAction, FirewallArn, FirewallIdentity, FirewallListItem, FirewallName,
    FirewallPolicyArn, FirewallPolicyDescription, FirewallPolicyIdentity, FirewallPolicyName,
    FixtureTransport, ListFirewallsPage, ListFirewallsRequest, LoopbackTransport,
    MissionAwsNetworkFirewallConsumer, MissionBinding, ModelError, OpaqueCursor, PermissionScope,
    PolicyRevision, ProjectBinding, ProviderProvenance, RecordingTransport, Revision,
    RuleGroupKind, RuleGroupReferenceProjection, SecretReference, ServiceError, SubnetId,
    TransportError, TransportFailure, VpcId, WorkProductBinding,
};

type Service = AwsNetworkFirewallPostureService<RecordingTransport>;

const ACCOUNT: &str = "123456789012";
const REGION: &str = "us-east-1";
const VPC: &str = "vpc-0123456789abcdef";
const FIREWALL_ARN: &str =
    "arn:aws:network-firewall:us-east-1:123456789012:firewall/fixture-firewall";
const POLICY_ARN: &str =
    "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/fixture-policy";
const RAW_SECRET_HANDLE: &str = "raw-sigv4-secret-handle-must-not-leak";
const RAW_CURSOR: &str = "raw-provider-next-token-must-not-leak";
const RAW_UPDATE_TOKEN: &str = "11111111-1111-1111-1111-111111111111";

fn scope() -> AwsNetworkFirewallScope {
    let account = AwsAccountId::new(ACCOUNT).expect("account");
    let region = AwsRegion::new(REGION).expect("region");
    let vpc = VpcId::new(VPC).expect("vpc");
    let firewall = FirewallIdentity::new(
        FirewallArn::new(FIREWALL_ARN).expect("firewall arn"),
        FirewallName::new("fixture-firewall").expect("firewall name"),
    )
    .expect("firewall");
    let policy_identity = FirewallPolicyIdentity::new(
        FirewallPolicyArn::new(POLICY_ARN).expect("policy arn"),
        FirewallPolicyName::new("fixture-policy").expect("policy name"),
    )
    .expect("policy");
    let policy = hartevo_aws_network_firewall_posture_result_plugin::FirewallPolicyBinding::new(
        policy_identity,
        PolicyRevision::new(Revision::new(7).expect("revision"), RAW_UPDATE_TOKEN)
            .expect("policy revision"),
    )
    .expect("policy binding");
    AwsNetworkFirewallScope::new(
        account,
        region,
        vpc,
        vec![firewall],
        vec![policy],
        vec![EndpointBinding::new(
            hartevo_aws_network_firewall_posture_result_plugin::EndpointId::new("vpce-0123")
                .expect("endpoint"),
            SubnetId::new("subnet-0123").expect("subnet"),
        )],
        MissionBinding::new(
            hartevo_aws_network_firewall_posture_result_plugin::MissionId::new("mission-1")
                .expect("Mission"),
            Revision::new(3).expect("Mission revision"),
        ),
        ProjectBinding::new(
            hartevo_aws_network_firewall_posture_result_plugin::ProjectId::new("project-1")
                .expect("Project"),
            Revision::new(4).expect("Project revision"),
        ),
        WorkProductBinding::new(
            hartevo_aws_network_firewall_posture_result_plugin::WorkProductId::new("work-1")
                .expect("Work Product"),
            Revision::new(5).expect("Work Product revision"),
        ),
        PermissionScope::read_only(Revision::new(2).expect("permission revision"))
            .expect("permissions"),
    )
    .expect("scope")
}

fn secret(scope: &AwsNetworkFirewallScope) -> SecretReference {
    SecretReference::new(
        RAW_SECRET_HANDLE,
        scope,
        Revision::new(1).expect("secret generation"),
    )
    .expect("secret reference")
}

fn recording_service() -> (AwsNetworkFirewallScope, Service) {
    let scope = scope();
    let provider =
        AwsNetworkFirewallProvider::new(RecordingTransport::default()).expect("provider");
    let service = Service::new(scope.clone(), secret(&scope), provider).expect("service");
    (scope, service)
}

#[test]
fn contract_scope_registration_and_opaque_secret_are_digest_fenced() {
    let scope = scope();
    assert!(scope.validate().is_ok());
    assert_ne!(scope.scope_digest, Digest::zero());
    assert_ne!(scope.policy_digest, Digest::zero());
    let provider = AwsNetworkFirewallProvider::default();
    let service =
        hartevo_aws_network_firewall_posture_result_plugin::AwsNetworkFirewallPostureService::new(
            scope.clone(),
            secret(&scope),
            provider,
        )
        .expect("service");
    assert!(service.registration().is_active());
    assert_eq!(
        service.registration().provider_id(),
        "aws.network-firewall.read"
    );
    let encoded_secret = serde_json::to_string(service.secret_reference()).expect("secret JSON");
    assert!(!encoded_secret.contains(RAW_SECRET_HANDLE));
    assert!(!format!("{:?}", service.secret_reference()).contains(RAW_SECRET_HANDLE));
    let registration = serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(registration.contains("secretReferenceDigest"));
    assert!(!registration.contains(RAW_SECRET_HANDLE));
    assert!(!format!("{:?}", service.registration()).contains(RAW_SECRET_HANDLE));
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
}

#[test]
fn fixture_list_is_bounded_redacted_and_consumable_below_kernel_authority() {
    let scope = scope();
    let fixture = FixtureTransport::for_scope(&scope).expect("fixture transport");
    let provider = AwsNetworkFirewallProvider::new(fixture).expect("provider");
    let mut service =
        hartevo_aws_network_firewall_posture_result_plugin::AwsNetworkFirewallPostureService::new(
            scope.clone(),
            secret(&scope),
            provider,
        )
        .expect("service");
    let result = service.read_list_firewalls().expect("fixture read");
    assert_eq!(
        result.evidence.status,
        hartevo_aws_network_firewall_posture_result_plugin::EvidenceStatus::Complete
    );
    assert_eq!(result.evidence.firewall_list.len(), 1);
    assert_eq!(result.evidence.pagination.pages_observed, 1);
    assert_eq!(result.evidence.provenance, ProviderProvenance::Fixture);
    assert!(result.evidence.is_review_only());
    assert!(!result.evidence.can_be_adopted());
    assert!(!result.evidence.authority.connected);
    assert!(!result.evidence.authority.native_provider);
    assert!(!result.evidence.authority.first_party);
    let encoded = serde_json::to_string(&result.evidence).expect("evidence JSON");
    for raw in [
        FIREWALL_ARN,
        POLICY_ARN,
        RAW_SECRET_HANDLE,
        RAW_UPDATE_TOKEN,
    ] {
        assert!(!encoded.contains(raw), "raw value leaked: {raw}");
    }

    let consumer =
        MissionAwsNetworkFirewallConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    let mission_result = consumer.consume(&result).expect("Mission result");
    assert!(mission_result.accepted);
    assert!(mission_result.review_only);
    assert!(!mission_result.safe_to_adopt);
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    assert!(!mission_result.first_party);
    assert!(!mission_result.adopted_outcome);
    assert!(!mission_result.truth_authority);
}

#[test]
fn loopback_describe_firewall_is_non_native_and_endpoint_vpc_bound() {
    let scope = scope();
    let firewall = scope.firewalls[0].clone();
    let loopback = LoopbackTransport::for_scope(&scope).expect("loopback");
    let provider = AwsNetworkFirewallProvider::new(loopback).expect("provider");
    let mut service =
        hartevo_aws_network_firewall_posture_result_plugin::AwsNetworkFirewallPostureService::new(
            scope.clone(),
            secret(&scope),
            provider,
        )
        .expect("service");
    let result = service
        .read_describe_firewall(firewall)
        .expect("describe firewall");
    let posture = result.evidence.firewall.expect("firewall posture");
    assert_eq!(posture.endpoint_attachments.len(), 1);
    assert_eq!(
        posture.status,
        hartevo_aws_network_firewall_posture_result_plugin::FirewallStatus::Ready
    );
    assert_eq!(result.evidence.provenance, ProviderProvenance::Loopback);
    assert!(!result.evidence.provenance.connected());
    assert!(!result.evidence.provenance.native());
    assert!(
        !serde_json::to_string(&posture)
            .expect("posture JSON")
            .contains("subnet-0123")
    );
}

#[test]
fn fixture_policy_projection_is_action_summary_only_and_revision_bound() {
    let scope = scope();
    let fixture = FixtureTransport::for_scope(&scope).expect("fixture transport");
    let provider = AwsNetworkFirewallProvider::new(fixture).expect("provider");
    let mut service =
        hartevo_aws_network_firewall_posture_result_plugin::AwsNetworkFirewallPostureService::new(
            scope.clone(),
            secret(&scope),
            provider,
        )
        .expect("service");
    let result = service
        .read_describe_firewall_policy(scope.policies[0].identity.clone())
        .expect("describe policy");
    let policy = result.evidence.policy.expect("policy posture");
    assert_eq!(
        policy.status,
        hartevo_aws_network_firewall_posture_result_plugin::PolicyStatus::Active
    );
    assert_eq!(
        policy.stateful_default_actions.actions,
        vec![FirewallAction::Drop]
    );
    assert_eq!(
        policy.stateless_default_actions.actions,
        vec![FirewallAction::ForwardToStateful]
    );
    assert_eq!(policy.stateful_rule_group_references.len(), 1);
    let encoded = serde_json::to_string(&policy).expect("policy JSON");
    assert!(!encoded.contains("fixture-stateful-rule-group"));
    assert!(!encoded.contains("fixture-policy"));
    assert!(!encoded.contains(RAW_UPDATE_TOKEN));
}

#[test]
fn policy_revision_drift_fails_closed_without_retaining_actions_or_rule_text() {
    let (scope, mut service) = recording_service();
    let policy = scope.policies[0].identity.clone();
    let request =
        DescribeFirewallPolicyRequest::for_scope(&scope, policy.clone()).expect("request");
    let drifted_revision = PolicyRevision::new(
        Revision::new(8).expect("drifted revision"),
        "22222222-2222-2222-2222-222222222222",
    )
    .expect("drifted policy revision");
    let description = FirewallPolicyDescription::new(
        policy,
        drifted_revision,
        "ACTIVE",
        vec!["raw-rule-action-and-suricata-text".to_owned()],
        vec!["aws:drop".to_owned()],
        vec![RuleGroupReferenceProjection {
            reference_digest: Digest::from_text("rule-arn-never-serialized"),
            kind: RuleGroupKind::Stateful,
            priority: None,
            deep_threat_inspection: false,
            override_action: Some(FirewallAction::Drop),
        }],
        Vec::new(),
        None::<&str>,
        1,
    )
    .expect("policy description");
    service
        .provider_mut()
        .transport_mut()
        .push_describe_policy_response(Ok(DescribeFirewallPolicyResponse::new(
            &request,
            description,
            512,
        )
        .expect("response")));
    let error = service
        .read(AwsNetworkFirewallReadRequest::DescribeFirewallPolicy(
            request,
        ))
        .expect_err("drift must fail closed");
    assert_eq!(error, ServiceError::PolicyRevisionDrift);
}

#[test]
fn pagination_cursor_replay_and_opaque_cursor_redaction_fail_closed() {
    let (scope, mut service) = recording_service();
    let request = ListFirewallsRequest::for_scope(&scope, None);
    let cursor = OpaqueCursor::new(RAW_CURSOR).expect("cursor");
    assert!(
        !serde_json::to_string(&cursor)
            .expect("cursor JSON")
            .contains(RAW_CURSOR)
    );
    assert!(!format!("{cursor:?}").contains(RAW_CURSOR));
    let item = FirewallListItem::new(
        scope.firewalls[0].clone(),
        scope.vpc_id.clone(),
        None::<&str>,
    )
    .expect("list item");
    let first = ListFirewallsPage::new(&request, 1, vec![item.clone()], Some(cursor.clone()), 512)
        .expect("first page");
    let second_request = request.with_next_token(Some(cursor.clone()));
    let second = ListFirewallsPage::new(&second_request, 2, vec![item], Some(cursor), 512)
        .expect("second page");
    service
        .provider_mut()
        .transport_mut()
        .push_list_response(Ok(first));
    service
        .provider_mut()
        .transport_mut()
        .push_list_response(Ok(second));
    let error = service
        .read(AwsNetworkFirewallReadRequest::ListFirewalls(request))
        .expect_err("cursor replay must fail closed");
    assert_eq!(error, ServiceError::PaginationLoop);
}

#[test]
fn blocked_env_and_adversarial_statuses_never_claim_connected_or_native() {
    let scope = scope();
    let mut blocked =
        hartevo_aws_network_firewall_posture_result_plugin::AwsNetworkFirewallPostureService::new(
            scope.clone(),
            secret(&scope),
            AwsNetworkFirewallProvider::default(),
        )
        .expect("blocked service");
    let error = blocked.read_list_firewalls().expect_err("BLOCKED_ENV");
    assert!(matches!(error, ServiceError::Provider(_)));
    assert_eq!(
        blocked.provider().provenance(),
        ProviderProvenance::BlockedEnv
    );
    assert!(!blocked.provider().provenance().connected());
    assert!(!blocked.provider().provenance().native());

    for failure in [
        TransportFailure::BadRequest,
        TransportFailure::Unauthorized,
        TransportFailure::AccessDenied,
        TransportFailure::NotFound,
        TransportFailure::Conflict,
        TransportFailure::Throttled,
        TransportFailure::Server,
        TransportFailure::Timeout,
        TransportFailure::Partial,
        TransportFailure::AccessLost,
    ] {
        let error = TransportError::new(failure);
        assert!(failure.is_fail_closed());
        assert!(!error.error_digest.as_str().is_empty());
    }
}

#[test]
fn reversible_registration_invalidates_old_proposals_and_secret_revocation_closes_reads() {
    let (_scope, mut service) = recording_service();
    let proposal = service.propose_list_firewalls().expect("proposal");
    service.revoke_registration().expect("revoke");
    assert!(!service.registration().is_active());
    let error = service
        .record(&proposal)
        .expect_err("revoked proposal cannot record");
    assert_eq!(error, ServiceError::RegistrationRevoked);

    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    let next_proposal = service.propose_list_firewalls().expect("new proposal");
    service.revoke_secret_reference().expect("revoke secret");
    let error = service
        .record(&next_proposal)
        .expect_err("revoked secret cannot record");
    assert_eq!(error, ServiceError::SecretRevoked);
}

#[test]
fn invalid_scope_inputs_are_rejected_before_provider_execution() {
    assert!(matches!(
        AwsAccountId::new("not-an-account"),
        Err(ModelError::Invalid { .. })
    ));
    assert!(matches!(
        OpaqueCursor::new("raw cursor with spaces"),
        Err(ModelError::InvalidCharacters { .. })
    ));
    assert!(matches!(
        Revision::new(0),
        Err(ModelError::MustBePositive { .. })
    ));
}

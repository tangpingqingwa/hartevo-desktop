use std::collections::BTreeSet;

use hartevo_aws_waf_posture_result_plugin::{
    ActionClass, AwsAccountId, AwsRegion, AwsWafPostureScope, AwsWafPostureService,
    BlockedEnvAwsWafTransport, ConsentBinding, Digest, EvidenceState, FixtureAwsWafTransport,
    GetWebAclRequest, ListResourcesForWebAclPage, ListResourcesForWebAclRequest, ListWebAclsPage,
    ListWebAclsRequest, MissionAwsWafConsumer, MissionBinding, MissionId, ModelError,
    OpaquePageToken, PermissionScope, ProjectBinding, ProjectId, RecordingAwsWafTransport,
    ResourceArn, ResourceAssociation, ResourceReference, Revision, RuleActionSummary,
    SecretReference, TransportError, WafDeploymentDecision, WafOperation, WafScopeKind, WebAclArn,
    WebAclDetails, WebAclId, WebAclListItem, WebAclReference, WorkProductBinding, WorkProductId,
};

const ACCOUNT: &str = "123456789012";
const REGION: &str = "us-east-1";
const WEB_ACL_ARN: &str =
    "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/fixture-acl/fixture-id";
const RESOURCE_ARN: &str =
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/fixture/1";
const SECRET_HANDLE: &str = "host-owned/aws-waf/fixture-secret";
const LOCK_TOKEN: &str = "fixture-lock-token";

struct Fixtures {
    scope: AwsWafPostureScope,
    secret: SecretReference,
}

impl Fixtures {
    fn new() -> Self {
        let account = AwsAccountId::new(ACCOUNT).expect("account");
        let region = AwsRegion::new(REGION).expect("region");
        let lock_digest = Digest::from_parts("aws-waf-lock-token/v1", &[LOCK_TOKEN.to_owned()]);
        let acl = WebAclReference::new(
            WebAclId::new("fixture-acl").expect("ACL id"),
            WebAclArn::new(WEB_ACL_ARN).expect("ACL ARN"),
            Revision::new(1).expect("ACL revision"),
            Some(lock_digest),
        )
        .expect("ACL reference");
        let resource = ResourceReference::new(
            ResourceArn::new(RESOURCE_ARN).expect("resource ARN"),
            Revision::new(1).expect("resource revision"),
        );
        let permission = PermissionScope::read_only(
            account.clone(),
            Revision::new(1).expect("permission revision"),
            ConsentBinding::from_text(
                "mission-consent",
                Revision::new(1).expect("consent revision"),
            ),
        );
        let scope = AwsWafPostureScope::new(
            account,
            region.clone(),
            WafScopeKind::Regional,
            vec![acl],
            vec![resource],
            MissionBinding::new(
                MissionId::new("mission-waf-609").expect("mission"),
                Revision::new(3).expect("mission revision"),
            ),
            ProjectBinding::new(
                ProjectId::new("project-security").expect("project"),
                Revision::new(2).expect("project revision"),
            ),
            WorkProductBinding::new(
                WorkProductId::new("work-product-deployment").expect("work product"),
                Revision::new(4).expect("work product revision"),
            ),
            permission,
        )
        .expect("scope");
        let secret = SecretReference::sigv4(
            SECRET_HANDLE,
            region,
            scope.digest(),
            Revision::new(7).expect("secret revision"),
        )
        .expect("secret");
        Self { scope, secret }
    }

    fn fixture_service(&self) -> AwsWafPostureService<FixtureAwsWafTransport> {
        AwsWafPostureService::new(
            self.scope.clone(),
            self.secret.clone(),
            FixtureAwsWafTransport::for_scope(&self.scope).expect("fixture transport"),
        )
        .expect("service")
    }

    fn first_acl(&self) -> WebAclReference {
        self.scope.web_acl().clone()
    }
}

#[test]
fn fixture_vertical_slice_is_bounded_redacted_and_mission_scoped() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.fixture_service();
    let read = service.read_bounded().expect("bounded read");
    assert_eq!(read.evidence.state, EvidenceState::Complete);
    assert!(read.evidence.review_eligible());
    assert_eq!(read.evidence.web_acls.len(), 1);
    assert_eq!(read.evidence.associations.len(), 1);
    assert!(read.evidence.associations[0].associated);
    assert_eq!(read.evidence.web_acls[0].default_action, ActionClass::Block);
    assert_eq!(read.evidence.pagination.web_acl_pages_observed, 1);
    assert_eq!(read.evidence.pagination.resource_pages_observed, 1);
    assert!(!read.evidence.connected);
    assert!(!read.evidence.native);
    assert!(!read.evidence.first_party);
    assert!(!read.evidence.provider_receipt);
    assert!(!read.evidence.can_be_adopted);
    assert!(read.evidence.validate_integrity().is_ok());

    let serialized = serde_json::to_string(&read.evidence).expect("evidence JSON");
    let debug = format!("{service:?}");
    for raw in [WEB_ACL_ARN, RESOURCE_ARN, SECRET_HANDLE, LOCK_TOKEN] {
        assert!(
            !serialized.contains(raw),
            "raw value leaked in evidence: {raw}"
        );
        assert!(!debug.contains(raw), "raw value leaked in Debug: {raw}");
    }
    assert!(serialized.contains("ruleStatementsRedacted"));

    let proposal = service
        .propose_from_evidence(read.evidence)
        .expect("proposal");
    assert_eq!(proposal.deployment_decision, WafDeploymentDecision::Review);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.adopts_outcome);
    service.verify(&proposal).expect("proposal verification");

    let consumer = MissionAwsWafConsumer::from_service(&service).expect("consumer");
    let decision = consumer.consume(&proposal).expect("Mission decision");
    assert_eq!(
        decision.state,
        hartevo_aws_waf_posture_result_plugin::WafDecisionState::Protected
    );
    assert_eq!(decision.deployment_decision, WafDeploymentDecision::Review);
    assert!(decision.requires_human_review);
    assert!(!decision.safe_to_deploy);
    assert!(!decision.truth_authority);
    assert!(!decision.effective_authorization);
    assert!(!decision.adopted_outcome);

    let first = service.record(&proposal, "recording-key").expect("record");
    let replay = service.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);
    service.verify_record(&first).expect("record verification");
}

#[test]
fn service_definition_registration_and_contract_are_explicitly_layer_one() {
    let fixtures = Fixtures::new();
    let service = fixtures.fixture_service();
    let definition = service.describe_capabilities();
    assert_eq!(definition.operations.len(), 7);
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(!definition.live_execution);
    assert!(!definition.external_writes);
    assert!(!definition.authority.truth);
    assert!(!definition.authority.consent);
    assert!(!definition.authority.effect);
    assert!(!definition.authority.receipt);
    assert!(!definition.authority.verification);
    assert!(!definition.authority.outcome);
    assert_eq!(service.registration().scope_digest, fixtures.scope.digest());
    assert_eq!(
        service.registration().permission_digest,
        *fixtures.scope.permission_digest()
    );
    assert!(service.registration().reversible);
    assert!(service.registration().revocable);
    assert!(
        service.registration().registration_digest == service.registration().recomputed_digest()
    );
    hartevo_aws_waf_posture_result_plugin::validate_contract_document()
        .expect("contract validation");
}

#[test]
fn blocked_env_is_access_loss_and_never_connected_or_native() {
    let fixtures = Fixtures::new();
    let mut service = AwsWafPostureService::new(
        fixtures.scope.clone(),
        fixtures.secret.clone(),
        BlockedEnvAwsWafTransport,
    )
    .expect("blocked env service");
    let read = service
        .read()
        .expect("blocked env is represented as evidence");
    assert_eq!(read.evidence.state, EvidenceState::AccessLoss);
    assert_eq!(
        read.evidence.provenance,
        hartevo_aws_waf_posture_result_plugin::TransportProvenance::BlockedEnv
    );
    assert!(!read.evidence.connected);
    assert!(!read.evidence.native);
    assert!(!read.evidence.first_party);
    let proposal = service
        .propose_from_evidence(read.evidence)
        .expect("proposal");
    assert_eq!(
        proposal.deployment_decision,
        WafDeploymentDecision::InsufficientEvidence
    );
    assert_eq!(
        proposal.decision_state,
        hartevo_aws_waf_posture_result_plugin::WafDecisionState::AccessLoss
    );
}

#[test]
fn recording_and_loopback_provenance_never_widen_authority() {
    let fixtures = Fixtures::new();
    let transport = RecordingAwsWafTransport::default();
    let provider = hartevo_aws_waf_posture_result_plugin::AwsWafProvider::new(
        fixtures.scope.clone(),
        fixtures.secret.clone(),
        transport,
    )
    .expect("recording provider");
    assert_eq!(
        provider.provenance(),
        hartevo_aws_waf_posture_result_plugin::TransportProvenance::Recording
    );
    assert!(!provider.definition().connected);
    assert!(!provider.definition().native);
    assert!(!provider.definition().first_party);
}

#[test]
fn registration_and_secret_revocation_fail_closed_and_restore_is_digest_fenced() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.fixture_service();
    let active_digest = service.registration().registration_digest.clone();
    let revocation = service.revoke_registration().expect("revoke registration");
    assert_eq!(revocation.previous_registration_digest, active_digest);
    assert!(!service.registration().is_active());
    assert!(matches!(
        service.read(),
        Err(hartevo_aws_waf_posture_result_plugin::ServiceError::RegistrationRevoked)
    ));
    service
        .restore_registration()
        .expect("restore registration");
    assert!(service.registration().is_active());
    assert_ne!(service.registration().registration_digest, active_digest);

    let mut secret = fixtures.secret.clone();
    secret.revoke().expect("revoke secret");
    let provider = hartevo_aws_waf_posture_result_plugin::AwsWafProvider::new(
        fixtures.scope.clone(),
        secret,
        FixtureAwsWafTransport::for_scope(&fixtures.scope).expect("fixture"),
    )
    .expect("provider construction does not resolve secret");
    let mut revoked_service = AwsWafPostureService::from_provider(provider).expect("service");
    assert!(matches!(
        revoked_service.read(),
        Err(hartevo_aws_waf_posture_result_plugin::ServiceError::SecretRevoked)
    ));
}

#[test]
fn tampered_proposal_and_evidence_are_rejected() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.fixture_service();
    let read = service.read().expect("read");
    let mut evidence = read.evidence.clone();
    evidence.native = true;
    assert!(service.verify_evidence(&evidence).is_err());

    let mut proposal = service
        .propose_from_evidence(read.evidence)
        .expect("proposal");
    proposal.native = true;
    assert!(service.verify(&proposal).is_err());

    let consumer = MissionAwsWafConsumer::from_service(&service).expect("consumer");
    assert!(consumer.consume(&proposal).is_err());
}

#[test]
fn lock_token_and_resource_revision_drift_fail_closed() {
    let fixtures = Fixtures::new();
    let acl = fixtures.first_acl();
    let list_request = ListWebAclsRequest::new(&fixtures.scope, None).expect("list request");
    let get_request = GetWebAclRequest::new(&fixtures.scope, acl.clone()).expect("get request");
    let bad_details = WebAclDetails::new(
        acl.clone(),
        ActionClass::Block,
        vec![RuleActionSummary::new(ActionClass::Block, 1).expect("rule")],
        "different-lock-token",
        acl.revision(),
    )
    .expect("details");
    let mut transport = FixtureAwsWafTransport::default();
    transport.queue_list_web_acls(Ok(ListWebAclsPage::new(
        &list_request,
        vec![WebAclListItem::new(acl.clone())],
        None,
        256,
    )
    .expect("list page")));
    transport.queue_get_web_acl(Ok(
        hartevo_aws_waf_posture_result_plugin::GetWebAclResponse::new(
            &get_request,
            bad_details,
            256,
        )
        .expect("get response"),
    ));
    let mut service =
        AwsWafPostureService::new(fixtures.scope.clone(), fixtures.secret.clone(), transport)
            .expect("service");
    assert!(matches!(
        service.read(),
        Err(hartevo_aws_waf_posture_result_plugin::ServiceError::ScopeMismatch)
    ));

    let list_request = ListWebAclsRequest::new(&fixtures.scope, None).expect("list request");
    let get_request = GetWebAclRequest::new(&fixtures.scope, acl.clone()).expect("get request");
    let resources_request = ListResourcesForWebAclRequest::new(&fixtures.scope, acl.clone(), None)
        .expect("resources request");
    let details = WebAclDetails::new(
        acl.clone(),
        ActionClass::Block,
        vec![],
        LOCK_TOKEN,
        acl.revision(),
    )
    .expect("details");
    let wrong_resource = ResourceReference::new(
        ResourceArn::new(RESOURCE_ARN).expect("resource"),
        Revision::new(2).expect("wrong revision"),
    );
    let mut transport = FixtureAwsWafTransport::default();
    transport.queue_list_web_acls(Ok(ListWebAclsPage::new(
        &list_request,
        vec![WebAclListItem::new(acl.clone())],
        None,
        256,
    )
    .expect("list page")));
    transport.queue_get_web_acl(Ok(
        hartevo_aws_waf_posture_result_plugin::GetWebAclResponse::new(&get_request, details, 256)
            .expect("get response"),
    ));
    transport.queue_list_resources_for_web_acl(Ok(ListResourcesForWebAclPage::new(
        &resources_request,
        vec![ResourceAssociation::new(
            wrong_resource,
            Revision::new(1).expect("association revision"),
        )],
        None,
        256,
    )
    .expect("resources page")));
    let mut service =
        AwsWafPostureService::new(fixtures.scope.clone(), fixtures.secret.clone(), transport)
            .expect("service");
    assert!(matches!(
        service.read(),
        Err(hartevo_aws_waf_posture_result_plugin::ServiceError::ScopeMismatch)
    ));
}

#[test]
fn pagination_loop_and_page_tamper_are_rejected() {
    let fixtures = Fixtures::new();
    let request_one = ListWebAclsRequest::new(&fixtures.scope, None).expect("request one");
    let token_one = OpaquePageToken::new(
        "opaque-page-one",
        &fixtures.scope,
        WafOperation::ListWebAcls,
        2,
    )
    .expect("token one");
    let token_two = OpaquePageToken::from_digest(
        token_one.token_digest.clone(),
        &fixtures.scope,
        WafOperation::ListWebAcls,
        3,
    )
    .expect("replayed token");
    let request_two =
        ListWebAclsRequest::new(&fixtures.scope, Some(token_one.clone())).expect("request two");
    let mut transport = FixtureAwsWafTransport::default();
    transport.queue_list_web_acls(Ok(ListWebAclsPage::new(
        &request_one,
        vec![],
        Some(token_one),
        128,
    )
    .expect("page one")));
    transport.queue_list_web_acls(Ok(ListWebAclsPage::new(
        &request_two,
        vec![],
        Some(token_two),
        128,
    )
    .expect("page two")));
    let mut service =
        AwsWafPostureService::new(fixtures.scope.clone(), fixtures.secret.clone(), transport)
            .expect("service");
    assert!(matches!(
        service.read(),
        Err(hartevo_aws_waf_posture_result_plugin::ServiceError::PaginationLoop)
    ));

    let request = ListWebAclsRequest::new(&fixtures.scope, None).expect("request");
    let mut page = ListWebAclsPage::new(&request, vec![], None, 128).expect("page");
    page.response_bytes = 999_999_999;
    let mut transport = FixtureAwsWafTransport::default();
    transport.queue_list_web_acls(Ok(page));
    let mut service =
        AwsWafPostureService::new(fixtures.scope.clone(), fixtures.secret.clone(), transport)
            .expect("service");
    assert!(matches!(
        service.read(),
        Err(hartevo_aws_waf_posture_result_plugin::ServiceError::ScopeMismatch)
    ));
}

#[test]
fn status_throttle_timeout_and_partial_evidence_fail_closed() {
    let fixtures = Fixtures::new();
    for error in [
        TransportError::HttpStatus(400),
        TransportError::HttpStatus(429),
        TransportError::Timeout,
        TransportError::HttpStatus(503),
    ] {
        let mut transport = FixtureAwsWafTransport::default();
        transport.queue_list_web_acls(Err(error.clone()));
        let mut service =
            AwsWafPostureService::new(fixtures.scope.clone(), fixtures.secret.clone(), transport)
                .expect("service");
        let read = service.read().expect("bounded failure evidence");
        let expected = match error {
            TransportError::HttpStatus(429) => EvidenceState::Throttled,
            TransportError::Timeout => EvidenceState::Timeout,
            _ => EvidenceState::ProviderUnknown,
        };
        assert_eq!(read.evidence.state, expected);
        assert!(!read.evidence.review_eligible());
    }

    let request = ListWebAclsRequest::new(&fixtures.scope, None).expect("request");
    let mut transport = FixtureAwsWafTransport::default();
    transport.queue_list_web_acls(Ok(ListWebAclsPage::with_partial(
        &request,
        vec![],
        None,
        128,
        true,
    )
    .expect("partial page")));
    let mut service =
        AwsWafPostureService::new(fixtures.scope.clone(), fixtures.secret.clone(), transport)
            .expect("service");
    let read = service.read().expect("partial evidence");
    assert_eq!(read.evidence.state, EvidenceState::Partial);
    assert!(!read.evidence.pagination.complete);
    assert!(!read.evidence.review_eligible());
}

#[test]
fn permission_scope_is_exact_and_missing_operations_are_rejected() {
    let account = AwsAccountId::new(ACCOUNT).expect("account");
    let operations = [WafOperation::ListWebAcls, WafOperation::GetWebAcl]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let error = PermissionScope::new(
        account,
        Revision::new(1).expect("revision"),
        operations,
        ConsentBinding::from_text("consent", Revision::new(1).expect("consent revision")),
    )
    .expect_err("missing ListResourcesForWebACL must fail");
    assert!(matches!(error, ModelError::MissingPermission { .. }));
}

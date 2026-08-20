#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Utc};
use hartevo_aws_config_compliance_result_plugin::{
    AWS_CONFIG_API_REVISION, AccountId, AwsConfigComplianceContract, AwsConfigComplianceService,
    AwsConfigReadPage, AwsConfigReadRequest, AwsConfigScope, AwsConfigTarget, AwsRegion,
    ComplianceEvaluation, ComplianceFilter, ComplianceState, ConfigRuleBinding, ConfigRuleName,
    DeploymentBinding, DeploymentId, Digest, MissionAwsConfigConsumer, MissionBinding, MissionId,
    OpaqueCursor, PermissionFence, PermissionId, ProjectBinding, ProjectId, ProviderRevision,
    RecordingAwsConfigTransport, ResourceBinding, ResourceId, ResourceKey, ResourceType, Revision,
    SecretReference, TransportError, WorkProductBinding, WorkProductId,
};

type Service = AwsConfigComplianceService<RecordingAwsConfigTransport>;

fn at(day: u8) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-02-{day:02}T00:00:00Z"))
        .expect("valid test timestamp")
        .with_timezone(&Utc)
}

fn target() -> AwsConfigTarget {
    AwsConfigTarget::account_region(
        AccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
    )
    .expect("account-region target")
}

fn scope_for(target: AwsConfigTarget) -> (AwsConfigScope, PermissionFence) {
    let permission = PermissionFence::readonly(
        PermissionId::new("aws-config-read").expect("permission id"),
        Revision::new(3).expect("permission revision"),
    )
    .expect("permission");
    let rule = ConfigRuleBinding::new(
        ConfigRuleName::new("rule-ec2-encrypted").expect("rule"),
        Revision::new(7).expect("rule revision"),
        [
            ResourceBinding::new(
                ResourceKey::new(
                    ResourceType::new("AWS::S3::Bucket").expect("resource type"),
                    ResourceId::new("bucket-a").expect("resource id"),
                ),
                Revision::new(2).expect("resource revision"),
            ),
            ResourceBinding::new(
                ResourceKey::new(
                    ResourceType::new("AWS::EC2::Instance").expect("resource type"),
                    ResourceId::new("i-1234567890").expect("resource id"),
                ),
                Revision::new(3).expect("resource revision"),
            ),
        ],
    )
    .expect("rule scope");
    let scope = AwsConfigScope::new(
        DeploymentBinding::new(
            DeploymentId::new("deployment-1").expect("deployment"),
            Revision::new(4).expect("deployment revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-1").expect("Mission"),
            Revision::new(8).expect("Mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("Project"),
            Revision::new(5).expect("Project revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("Work Product"),
            Revision::new(6).expect("Work Product revision"),
        ),
        target,
        rule,
        permission.digest(),
    )
    .expect("scope");
    (scope, permission)
}

fn fixture() -> (AwsConfigScope, Service) {
    let (scope, permission) = scope_for(target());
    let secret = SecretReference::for_config("sigv4-keyring-ref", &scope.target).expect("secret");
    let provider = hartevo_aws_config_compliance_result_plugin::AwsConfigProvider::new(
        RecordingAwsConfigTransport::default(),
    )
    .expect("provider");
    let service = Service::new(scope.clone(), secret, permission, provider).expect("service");
    (scope, service)
}

fn rule_request(scope: &AwsConfigScope) -> AwsConfigReadRequest {
    AwsConfigReadRequest::by_config_rule(scope, ComplianceFilter::all(), 50, 4, None)
        .expect("rule read request")
}

fn resource_request(scope: &AwsConfigScope, index: usize) -> AwsConfigReadRequest {
    AwsConfigReadRequest::by_resource(
        scope,
        scope.config_rule.resources[index].key.clone(),
        ComplianceFilter::all(),
        50,
        4,
        None,
    )
    .expect("resource read request")
}

fn evaluation(
    scope: &AwsConfigScope,
    key: &ResourceKey,
    evaluation_revision: u64,
    state: ComplianceState,
    day: u8,
) -> ComplianceEvaluation {
    let resource_revision = scope.resource_revision(key).expect("allowlisted resource");
    ComplianceEvaluation::new(
        scope.config_rule.name.clone(),
        scope.config_rule.revision,
        key.resource_type.clone(),
        key.resource_id.clone(),
        resource_revision,
        Revision::new(evaluation_revision).expect("evaluation revision"),
        state,
        at(day),
        at(day),
    )
    .expect("evaluation")
}

fn page(
    request: &AwsConfigReadRequest,
    number: u16,
    evaluations: Vec<ComplianceEvaluation>,
    next: Option<OpaqueCursor>,
) -> AwsConfigReadPage {
    AwsConfigReadPage::new(
        request,
        number,
        evaluations,
        next,
        512,
        ProviderRevision::new(AWS_CONFIG_API_REVISION).expect("provider revision"),
    )
    .expect("page")
}

fn push_page(
    service: &mut Service,
    request: &AwsConfigReadRequest,
    number: u16,
    evaluations: Vec<ComplianceEvaluation>,
    next: Option<OpaqueCursor>,
) {
    service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(page(request, number, evaluations, next)));
}

#[test]
fn contract_target_and_registration_are_explicitly_bound() {
    AwsConfigComplianceContract::baseline().expect("contract");
    let (scope, service) = fixture();
    assert!(!scope.target.is_approved_aggregator());
    assert_eq!(
        scope.target.account_id().expect("account").as_str(),
        "123456789012"
    );
    assert_eq!(scope.target.region().as_str(), "us-east-1");
    assert!(service.is_active());
    assert_eq!(service.registration().provider_id.as_str(), "aws.config");
    assert_ne!(service.registration().scope_digest, Digest::zero());
    assert_ne!(service.registration().permission_digest, Digest::zero());
    assert_ne!(service.registration().evidence_digest, Digest::zero());

    let aggregator = AwsConfigTarget::approved_aggregator(
        hartevo_aws_config_compliance_result_plugin::AggregatorId::new("org-aggregator")
            .expect("aggregator"),
        AwsRegion::new("us-west-2").expect("aggregator region"),
        Digest::from_text("approved-by-host"),
    )
    .expect("approved aggregator");
    let (aggregator_scope, _) = scope_for(aggregator);
    assert!(aggregator_scope.target.is_approved_aggregator());
    assert!(SecretReference::for_config("sigv4-ref", &aggregator_scope.target).is_ok());
}

#[test]
fn opaque_secret_and_cursor_never_serialize_raw_material() {
    let (scope, service) = fixture();
    let secret = service.secret_reference();
    let encoded_secret = serde_json::to_string(secret).expect("opaque secret JSON");
    assert_eq!(encoded_secret, r#"{"opaque":true}"#);
    assert!(!format!("{secret:?}").contains("sigv4-keyring-ref"));
    assert!(
        !serde_json::to_string(secret)
            .expect("secret JSON")
            .contains("sigv4-keyring-ref")
    );

    let cursor = OpaqueCursor::new("provider-next-token-secret").expect("cursor");
    assert_eq!(
        serde_json::to_string(&cursor).expect("cursor JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{cursor:?}").contains("provider-next-token-secret"));
    let request = rule_request(&scope);
    let bound = request.with_cursor(Some(cursor)).expect("bound cursor");
    assert!(
        !serde_json::to_string(&bound)
            .expect("request JSON")
            .contains("provider-next-token-secret")
    );
}

#[test]
fn complete_compliance_is_recordable_but_not_certification_or_adoption() {
    let (scope, mut service) = fixture();
    let request = rule_request(&scope);
    let evaluations = scope
        .config_rule
        .resources
        .iter()
        .map(|resource| evaluation(&scope, &resource.key, 2, ComplianceState::Compliant, 2))
        .collect();
    push_page(&mut service, &request, 1, evaluations, None);
    let proposal = service.propose(request, at(3)).expect("proposal");
    assert_eq!(proposal.state, ComplianceState::Compliant);
    assert!(proposal.read_only);
    assert!(!proposal.live_execution);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.certification_claim);
    assert!(!proposal.adopted_outcome);
    assert_eq!(
        proposal.evidence.provenance,
        hartevo_aws_config_compliance_result_plugin::TransportProvenance::Recording
    );
    assert_ne!(proposal.evidence.evidence_digest, Digest::zero());

    let consumer = MissionAwsConfigConsumer::new(scope.clone(), service.registration().clone())
        .expect("consumer");
    let result = consumer.consume(proposal.clone()).expect("Mission result");
    assert_eq!(result.observed_compliance_state, ComplianceState::Compliant);
    assert_eq!(
        result.decision_state,
        hartevo_aws_config_compliance_result_plugin::MissionAwsConfigDecisionState::ReviewRequired
    );
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.certification_claim);
    assert!(!result.adopted_outcome);
    assert!(!result.truth_authority);

    let receipt = service.record_at(&proposal, at(4)).expect("record");
    assert!(receipt.recorded);
    assert!(!receipt.raw_provider_payload_retained);
    assert!(!receipt.durable_receipt);
    assert!(!receipt.connected);
    assert!(!receipt.native);
    let verified = service.verify(&receipt).expect("verify");
    assert!(verified.verified);
    assert!(!verified.adopted_outcome);
}

#[test]
fn resource_state_transition_uses_latest_evaluation_revision() {
    let (scope, mut service) = fixture();
    let request = resource_request(&scope, 0);
    let key = &scope.config_rule.resources[0].key;
    push_page(
        &mut service,
        &request,
        1,
        vec![
            evaluation(&scope, key, 2, ComplianceState::Compliant, 3),
            evaluation(&scope, key, 1, ComplianceState::NonCompliant, 2),
        ],
        None,
    );
    let result = service.read(request).expect("read");
    assert_eq!(result.evidence.state, ComplianceState::Compliant);
    assert_eq!(result.evidence.evaluations[0].evaluation_revision.get(), 2);
    assert_eq!(result.evidence.evaluations[1].evaluation_revision.get(), 1);
}

#[test]
fn stale_rule_and_resource_revisions_fail_closed_as_partial() {
    let (scope, mut service) = fixture();
    let request = resource_request(&scope, 0);
    let key = &scope.config_rule.resources[0].key;
    let mut stale_rule = evaluation(&scope, key, 1, ComplianceState::Compliant, 2);
    stale_rule.rule_revision = Revision::new(6).expect("stale rule revision");
    stale_rule.evaluation_digest = stale_rule.recomputed_digest();
    push_page(&mut service, &request, 1, vec![stale_rule], None);
    let result = service.read(request).expect("stale rule read");
    assert_eq!(result.evidence.state, ComplianceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_config_compliance_result_plugin::PartialReason::StaleRuleRevision)
    );

    let (scope, mut service) = fixture();
    let request = resource_request(&scope, 0);
    let key = &scope.config_rule.resources[0].key;
    let mut stale_resource = evaluation(&scope, key, 1, ComplianceState::Compliant, 2);
    stale_resource.resource_revision = Revision::new(1).expect("stale resource revision");
    stale_resource.evaluation_digest = stale_resource.recomputed_digest();
    push_page(&mut service, &request, 1, vec![stale_resource], None);
    let result = service.read(request).expect("stale resource read");
    assert_eq!(result.evidence.state, ComplianceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_config_compliance_result_plugin::PartialReason::StaleResourceRevision)
    );
}

#[test]
fn cursor_and_filter_binding_reject_replay_and_detect_loops() {
    let (scope, mut service) = fixture();
    let request = rule_request(&scope);
    let cursor = OpaqueCursor::new("page-one").expect("cursor");
    let first = page(
        &request,
        1,
        vec![evaluation(
            &scope,
            &scope.config_rule.resources[0].key,
            1,
            ComplianceState::Compliant,
            2,
        )],
        Some(cursor.clone()),
    );
    let second = page(
        &request,
        2,
        vec![evaluation(
            &scope,
            &scope.config_rule.resources[1].key,
            1,
            ComplianceState::Compliant,
            2,
        )],
        Some(cursor),
    );
    service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(first));
    service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(second));
    let result = service.read(request).expect("cursor replay read");
    assert_eq!(result.evidence.state, ComplianceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_config_compliance_result_plugin::PartialReason::CursorReplay)
    );

    let (scope, _) = scope_for(target());
    let request = rule_request(&scope);
    let cursor = OpaqueCursor::new("cursor-bound-to-all-states").expect("cursor");
    let filtered = AwsConfigReadRequest::by_config_rule(
        &scope,
        ComplianceFilter::new([ComplianceState::Compliant]).expect("filter"),
        50,
        4,
        None,
    )
    .expect("filtered request");
    assert!(
        filtered
            .with_cursor(Some(cursor.bind(&request.query_digest())))
            .is_err()
    );
}

#[test]
fn page_budget_and_evaluation_order_are_explicitly_partial() {
    let (scope, mut service) = fixture();
    let request =
        AwsConfigReadRequest::by_config_rule(&scope, ComplianceFilter::all(), 50, 1, None)
            .expect("one-page request");
    let next = OpaqueCursor::new("bounded-page-two").expect("cursor");
    push_page(
        &mut service,
        &request,
        1,
        vec![evaluation(
            &scope,
            &scope.config_rule.resources[0].key,
            1,
            ComplianceState::Compliant,
            2,
        )],
        Some(next),
    );
    let result = service.read(request).expect("bounded read");
    assert_eq!(result.evidence.state, ComplianceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_config_compliance_result_plugin::PartialReason::PageBudget)
    );
    assert!(result.evidence.truncated);

    let (scope, mut service) = fixture();
    let request = resource_request(&scope, 0);
    let key = &scope.config_rule.resources[0].key;
    let mut newer_but_older = evaluation(&scope, key, 2, ComplianceState::Compliant, 2);
    newer_but_older.ordering_timestamp = at(2);
    newer_but_older.result_recorded_timestamp = at(2);
    newer_but_older.evaluation_digest = newer_but_older.recomputed_digest();
    let older_but_newer = evaluation(&scope, key, 1, ComplianceState::NonCompliant, 3);
    push_page(
        &mut service,
        &request,
        1,
        vec![newer_but_older, older_but_newer],
        None,
    );
    let result = service.read(request).expect("ordering read");
    assert_eq!(result.evidence.state, ComplianceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_config_compliance_result_plugin::PartialReason::EvaluationOrdering)
    );
}

#[test]
fn provider_error_families_are_typed_and_fail_closed() {
    let cases = [
        (
            TransportError::InvalidRequest,
            ComplianceState::ProviderUnknown,
        ),
        (TransportError::Unauthorized, ComplianceState::AccessLoss),
        (TransportError::Forbidden, ComplianceState::AccessLoss),
        (TransportError::NotFound, ComplianceState::AccessLoss),
        (TransportError::Conflict, ComplianceState::Partial),
        (
            TransportError::RateLimited {
                retry_after_seconds: Some(4),
            },
            ComplianceState::ProviderUnknown,
        ),
        (
            TransportError::ServerFailure {
                status_code: Some(503),
            },
            ComplianceState::ProviderUnknown,
        ),
        (TransportError::Timeout, ComplianceState::ProviderUnknown),
    ];
    for (error, expected_state) in cases {
        let (scope, mut service) = fixture();
        let request = resource_request(&scope, 0);
        for _ in 0..3 {
            service
                .provider_mut()
                .transport_mut()
                .push_response(Err(error.clone()));
        }
        let result = service.read(request).expect("typed provider failure");
        assert_eq!(result.evidence.state, expected_state);
        assert!(!result.evidence.provider_errors.is_empty());
        assert!(result.evidence.provider_errors.len() <= 3);
        assert!(service.provider().transport().requests().len() <= 6);
    }

    let (scope, permission) = scope_for(target());
    let secret = SecretReference::for_config("sigv4-ref", &scope.target).expect("secret");
    let provider = hartevo_aws_config_compliance_result_plugin::AwsConfigProvider::new(
        hartevo_aws_config_compliance_result_plugin::BlockedEnvAwsConfigTransport,
    )
    .expect("blocked provider");
    let mut service = AwsConfigComplianceService::new(scope.clone(), secret, permission, provider)
        .expect("blocked service");
    let result = service
        .read(resource_request(&scope, 0))
        .expect("blocked read");
    assert_eq!(result.evidence.state, ComplianceState::ProviderUnknown);
    assert!(!result.evidence.provenance.native());
}

#[test]
fn raw_json_parser_retains_only_bounded_compliance_fields() {
    let (scope, _) = scope_for(target());
    let request = rule_request(&scope);
    let body = br#"{
      "EvaluationResults": [{
        "EvaluationResultIdentifier": {
          "EvaluationResultQualifier": {
            "ConfigRuleName": "rule-ec2-encrypted",
            "ResourceType": "AWS::S3::Bucket",
            "ResourceId": "bucket-a"
          }
        },
        "ComplianceType": "COMPLIANT",
        "RuleRevision": 7,
        "ResourceRevision": 2,
        "EvaluationRevision": 4,
        "OrderingTimestamp": "2026-02-02T00:00:00Z",
        "ResultRecordedTime": "2026-02-02T00:00:00Z",
        "Annotation": "do not retain",
        "ConfigurationItem": {"secret": "snapshot"},
        "Tags": {"Environment": "production"},
        "Environment": "prod"
      }],
      "NextToken": "raw-provider-token"
    }"#;
    let page = hartevo_aws_config_compliance_result_plugin::AwsConfigProvider::<
        RecordingAwsConfigTransport,
    >::parse_json_page(
        &request,
        1,
        200,
        body,
        ProviderRevision::new(AWS_CONFIG_API_REVISION).expect("provider revision"),
    )
    .expect("redacted page");
    let encoded = serde_json::to_string(&page).expect("page JSON");
    for forbidden in [
        "do not retain",
        "snapshot",
        "production",
        "raw-provider-token",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "raw field survived: {forbidden}"
        );
    }
    assert!(encoded.contains("bucket-a"));
    assert!(encoded.contains("COMPLIANT"));
}

#[test]
fn proposal_tamper_and_registration_revocation_fences_are_fail_closed() {
    let (scope, mut service) = fixture();
    let request = resource_request(&scope, 0);
    push_page(
        &mut service,
        &request,
        1,
        vec![evaluation(
            &scope,
            &scope.config_rule.resources[0].key,
            1,
            ComplianceState::Compliant,
            2,
        )],
        None,
    );
    let proposal = service.propose(request, at(3)).expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.state = ComplianceState::NonCompliant;
    assert!(service.verify_proposal(&tampered).is_err());
    let consumer = MissionAwsConfigConsumer::new(scope.clone(), service.registration().clone())
        .expect("consumer");
    assert!(consumer.consume(tampered).is_err());

    let mut registration = service.registration().clone();
    registration.scope_digest = Digest::zero();
    assert!(
        registration
            .validate(
                &scope,
                service.secret_reference(),
                service.provider().identity()
            )
            .is_err()
    );

    let receipt = service.record_at(&proposal, at(4)).expect("receipt");
    service.revoke_registration().expect("revoke");
    assert!(!service.is_active());
    assert!(service.record(&proposal).is_err());
    assert!(service.verify(&receipt).is_err());
    assert!(service.revoke_registration().is_err());
}

#[test]
fn insufficient_data_is_not_compliant() {
    let (scope, mut service) = fixture();
    let request = resource_request(&scope, 0);
    push_page(&mut service, &request, 1, Vec::new(), None);
    let result = service.read(request).expect("empty response");
    assert_eq!(result.evidence.state, ComplianceState::InsufficientData);
    assert!(result.evidence.state.is_fail_closed());
}

#[test]
fn unsupported_permission_and_invalid_scope_are_rejected() {
    let permission = PermissionFence::new(
        PermissionId::new("only-rule-read").expect("permission"),
        Revision::new(1).expect("revision"),
        [hartevo_aws_config_compliance_result_plugin::PermissionAction::GetComplianceDetailsByConfigRule],
    )
    .expect("permission");
    let (scope, _) = scope_for(target());
    let secret = SecretReference::for_config("sigv4-ref", &scope.target).expect("secret");
    let provider = hartevo_aws_config_compliance_result_plugin::AwsConfigProvider::new(
        RecordingAwsConfigTransport::default(),
    )
    .expect("provider");
    assert!(AwsConfigComplianceService::new(scope, secret, permission, provider).is_err());

    let invalid = AwsConfigTarget::ApprovedAggregator {
        aggregator_id: hartevo_aws_config_compliance_result_plugin::AggregatorId::new("unapproved")
            .expect("aggregator"),
        region: AwsRegion::new("us-east-1").expect("region"),
        approval_digest: Digest::zero(),
    };
    let (mut invalid_scope, _) = scope_for(target());
    invalid_scope.target = invalid;
    assert!(invalid_scope.validate().is_err());
}

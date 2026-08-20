use std::collections::BTreeSet;

use hartevo_aws_organizations_governance_result_plugin::{
    AccountId, AttachmentDirection, AttachmentState, AuthorityKind,
    AwsOrganizationsGovernanceService, AwsOrganizationsProvider, AwsOrganizationsReadRequest,
    AwsOrganizationsScope, ConsentBinding, Digest, FixtureAwsOrganizationsTransport, HierarchyNode,
    ListPoliciesForTargetPage, ListPoliciesForTargetRequest, ListPoliciesPage, ListPoliciesRequest,
    ListTargetsForPolicyPage, ListTargetsForPolicyRequest, MissionAwsOrganizationsConsumer,
    MissionBinding, MissionId, OpaquePageToken, OrganizationHierarchy, OrganizationId,
    OrganizationalUnitId, PermissionScope, PolicyIdentity, PolicyType, ProjectId, ProviderError,
    ReadBounds, ReadOperation, RegistrationState, RevisionId, RootId, ServiceError,
    SigV4SecretReference, TargetId, TargetReference, TransportError, TransportFailure,
    WorkProductId,
};

struct Fixtures {
    organization_id: OrganizationId,
    hierarchy: OrganizationHierarchy,
    root: TargetReference,
    ou: TargetReference,
    account: TargetReference,
    policy: PolicyIdentity,
    scope: AwsOrganizationsScope,
    secret: SigV4SecretReference,
}

impl Fixtures {
    fn new() -> Self {
        let organization_id = OrganizationId::parse("o-exampleorgid").unwrap();
        let root = TargetReference::new(
            organization_id.clone(),
            TargetId::Root(RootId::parse("r-examplerootid111").unwrap()),
            "arn:aws:organizations::111111111111:root/o-exampleorgid/r-examplerootid111",
        )
        .unwrap();
        let ou = TargetReference::new(
            organization_id.clone(),
            TargetId::OrganizationalUnit(OrganizationalUnitId::parse(
                "ou-examplerootid111-exampleouid111",
            )
            .unwrap()),
            "arn:aws:organizations::111111111111:ou/o-exampleorgid/ou-examplerootid111-exampleouid111",
        )
        .unwrap();
        let account = TargetReference::new(
            organization_id.clone(),
            TargetId::Account(AccountId::parse("111111111111").unwrap()),
            "arn:aws:organizations::111111111111:account/o-exampleorgid/111111111111",
        )
        .unwrap();
        let hierarchy = OrganizationHierarchy::new(
            organization_id.clone(),
            vec![
                HierarchyNode {
                    target: account.clone(),
                    parent_target_id: Some(ou.target_id.clone()),
                },
                HierarchyNode {
                    target: root.clone(),
                    parent_target_id: None,
                },
                HierarchyNode {
                    target: ou.clone(),
                    parent_target_id: Some(root.target_id.clone()),
                },
            ],
        )
        .unwrap();
        let policy = PolicyIdentity::from_values(
            PolicyType::ServiceControlPolicy,
            "p-examplepolicyid111",
            "arn:aws:organizations::111111111111:policy/o-exampleorgid/service_control_policy/p-examplepolicyid111",
        )
        .unwrap();
        let mission = MissionBinding::new(
            MissionId::parse("mission-513").unwrap(),
            ProjectId::parse("project-513").unwrap(),
            WorkProductId::parse("work-product-513").unwrap(),
            RevisionId::parse("mission-rev-1").unwrap(),
            Digest::from_text("consent-1"),
        );
        let consent = ConsentBinding::new(
            Digest::from_text("consent-1"),
            RevisionId::parse("consent-rev-1").unwrap(),
        );
        let permissions = PermissionScope::all(
            organization_id.clone(),
            AccountId::parse("111111111111").unwrap(),
            AuthorityKind::ManagementAccount,
            RevisionId::parse("permission-rev-1").unwrap(),
            consent,
        )
        .unwrap();
        let scope = AwsOrganizationsScope::new(
            organization_id.clone(),
            hierarchy.clone(),
            vec![root.clone(), ou.clone(), account.clone()],
            PolicyType::ServiceControlPolicy,
            mission,
            permissions,
        )
        .unwrap();
        let secret = SigV4SecretReference::new(
            "host-ref/aws-organizations/513",
            "us-east-1",
            scope.scope_digest.clone(),
            RevisionId::parse("credential-rev-1").unwrap(),
        )
        .unwrap();
        Self {
            organization_id,
            hierarchy,
            root,
            ou,
            account,
            policy,
            scope,
            secret,
        }
    }

    fn service_with_transport(
        &self,
        transport: FixtureAwsOrganizationsTransport,
    ) -> AwsOrganizationsGovernanceService<FixtureAwsOrganizationsTransport> {
        AwsOrganizationsGovernanceService::new(
            self.scope.clone(),
            self.secret.clone(),
            AwsOrganizationsProvider::new(transport),
        )
        .unwrap()
    }

    fn page_policy(&self, next_token: Option<OpaquePageToken>) -> ListPoliciesPage {
        ListPoliciesPage::new(
            vec![self.policy.clone()],
            next_token,
            self.scope.hierarchy_digest.clone(),
            self.scope.permissions.permission_digest.clone(),
        )
    }

    fn page_targets(
        &self,
        targets: Vec<TargetReference>,
        next_token: Option<OpaquePageToken>,
    ) -> ListTargetsForPolicyPage {
        ListTargetsForPolicyPage::new(
            targets,
            next_token,
            self.scope.hierarchy_digest.clone(),
            self.scope.permissions.permission_digest.clone(),
        )
    }

    fn page_target_policies(&self) -> ListPoliciesForTargetPage {
        ListPoliciesForTargetPage::new(
            vec![self.policy.clone()],
            None,
            self.scope.hierarchy_digest.clone(),
            self.scope.permissions.permission_digest.clone(),
        )
    }
}

#[test]
fn list_policies_produces_bounded_policy_summary_and_mission_result() {
    let fixtures = Fixtures::new();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies(Ok(fixtures.page_policy(None)));
    let mut service = fixtures.service_with_transport(transport);
    let mut consumer = MissionAwsOrganizationsConsumer::new(service.scope());
    consumer.bind_registration(service.registration()).unwrap();

    let result = service.read_list_policies().unwrap();
    let mission_result = consumer.consume(&result).unwrap();

    assert_eq!(result.evidence.policies.len(), 1);
    assert_eq!(
        result.evidence.policies[0].policy_type,
        PolicyType::ServiceControlPolicy
    );
    assert_eq!(
        result.evidence.policies[0].policy_id.as_str(),
        "p-examplepolicyid111"
    );
    assert!(
        result.evidence.policies[0]
            .policy_arn
            .as_str()
            .contains("service_control_policy")
    );
    assert_eq!(result.evidence.pagination.pages_observed, 1);
    assert!(result.evidence.pagination.complete);
    assert!(result.evidence.redaction.policy_documents_redacted);
    assert!(result.evidence.redaction.account_pii_redacted);
    assert!(!result.evidence.authority.connected);
    assert!(!result.evidence.authority.native_provider);
    assert!(!result.evidence.authority.effective_authorization);
    assert!(mission_result.accepted);
    assert!(!mission_result.adopted_outcome);
    assert!(!mission_result.truth_authority);
    assert!(!mission_result.effective_authorization);

    let serialized = serde_json::to_string(&result.evidence).unwrap();
    assert!(!serialized.contains("PolicyDocument"));
    assert!(!serialized.contains("accountEmail"));
    assert!(!serialized.contains("host-ref/aws-organizations/513"));
}

#[test]
fn list_targets_records_both_attachment_directions_and_missing_state() {
    let fixtures = Fixtures::new();
    let token = OpaquePageToken::new("opaque-next-token-1").unwrap();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_targets_for_policy(Ok(
        fixtures.page_targets(vec![fixtures.root.clone()], Some(token))
    ));
    transport.queue_list_targets_for_policy(Ok(
        fixtures.page_targets(vec![fixtures.account.clone()], None)
    ));
    let mut service = fixtures.service_with_transport(transport);

    let result = service
        .read_list_targets_for_policy(fixtures.policy.clone())
        .unwrap();
    assert_eq!(result.evidence.attachments.len(), 3);
    assert_eq!(
        result
            .evidence
            .attachments
            .iter()
            .filter(|item| item.direction == AttachmentDirection::PolicyToTarget)
            .count(),
        3
    );
    assert_eq!(
        result
            .evidence
            .attachments
            .iter()
            .filter(|item| item.state == AttachmentState::Attached)
            .count(),
        2
    );
    assert_eq!(
        result
            .evidence
            .attachments
            .iter()
            .filter(|item| item.state == AttachmentState::NotAttached)
            .count(),
        1
    );
    assert_eq!(result.evidence.pagination.pages_observed, 2);
    assert_eq!(result.evidence.pagination.page_token_digests.len(), 1);
    assert!(
        !serde_json::to_string(&result.evidence)
            .unwrap()
            .contains("opaque-next-token-1")
    );
}

#[test]
fn list_policies_for_target_records_target_to_policy_direction() {
    let fixtures = Fixtures::new();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies_for_target(Ok(fixtures.page_target_policies()));
    let mut service = fixtures.service_with_transport(transport);

    let result = service
        .read_list_policies_for_target(fixtures.ou.clone())
        .unwrap();
    assert_eq!(result.evidence.policies.len(), 1);
    assert_eq!(result.evidence.attachments.len(), 1);
    assert_eq!(
        result.evidence.attachments[0].direction,
        AttachmentDirection::TargetToPolicy
    );
    assert_eq!(
        result.evidence.attachments[0].target.target_id,
        fixtures.ou.target_id
    );
    assert_eq!(
        result.evidence.attachments[0].state,
        AttachmentState::Attached
    );
}

#[test]
fn request_digest_binds_filters_scope_and_opaque_cursor_without_retaining_cursor() {
    let fixtures = Fixtures::new();
    let bounds = ReadBounds::default();
    let first = ListPoliciesRequest::new(
        fixtures.organization_id.clone(),
        PolicyType::ServiceControlPolicy,
        &bounds,
        fixtures.scope.hierarchy_digest.clone(),
        fixtures.scope.permissions.permission_digest.clone(),
        fixtures.scope.scope_digest.clone(),
    );
    let token_a = OpaquePageToken::new("cursor-a").unwrap();
    let token_b = OpaquePageToken::new("cursor-b").unwrap();
    let a = first
        .with_next_token(Some(token_a.clone()))
        .request_digest()
        .unwrap();
    let b = first
        .with_next_token(Some(token_b))
        .request_digest()
        .unwrap();
    let different_filter = ListPoliciesRequest::new(
        fixtures.organization_id.clone(),
        PolicyType::TagPolicy,
        &bounds,
        fixtures.scope.hierarchy_digest.clone(),
        fixtures.scope.permissions.permission_digest.clone(),
        fixtures.scope.scope_digest.clone(),
    )
    .with_next_token(Some(token_a.clone()))
    .request_digest()
    .unwrap();

    assert_ne!(a, b);
    assert_ne!(a, different_filter);
    assert!(!format!("{token_a:?}").contains("cursor-a"));
}

#[test]
fn provider_fails_closed_on_duplicate_items_and_incomplete_pagination() {
    let fixtures = Fixtures::new();
    let mut duplicate_transport = FixtureAwsOrganizationsTransport::fixture();
    duplicate_transport.queue_list_policies(Ok(ListPoliciesPage::new(
        vec![fixtures.policy.clone(), fixtures.policy.clone()],
        None,
        fixtures.scope.hierarchy_digest.clone(),
        fixtures.scope.permissions.permission_digest.clone(),
    )));
    let mut duplicate_provider = AwsOrganizationsProvider::new(duplicate_transport);
    let duplicate_request = ListPoliciesRequest::new(
        fixtures.organization_id.clone(),
        fixtures.scope.policy_type,
        duplicate_provider.bounds(),
        fixtures.scope.hierarchy_digest.clone(),
        fixtures.scope.permissions.permission_digest.clone(),
        fixtures.scope.scope_digest.clone(),
    );
    assert!(matches!(
        duplicate_provider.list_policies(duplicate_request),
        Err(ProviderError::DuplicateItem)
    ));

    let mut incomplete_transport = FixtureAwsOrganizationsTransport::fixture();
    incomplete_transport.queue_list_policies(Ok(
        fixtures.page_policy(Some(OpaquePageToken::new("still-more").unwrap()))
    ));
    let bounds = ReadBounds::new(1, 20, 20).unwrap();
    let mut incomplete_provider =
        AwsOrganizationsProvider::with_bounds(incomplete_transport, bounds);
    let incomplete_request = ListPoliciesRequest::new(
        fixtures.organization_id.clone(),
        fixtures.scope.policy_type,
        incomplete_provider.bounds(),
        fixtures.scope.hierarchy_digest.clone(),
        fixtures.scope.permissions.permission_digest.clone(),
        fixtures.scope.scope_digest.clone(),
    );
    assert!(matches!(
        incomplete_provider.list_policies(incomplete_request),
        Err(ProviderError::PaginationIncomplete)
    ));
}

#[test]
fn hierarchy_and_permission_drift_are_fences_not_warnings() {
    let fixtures = Fixtures::new();
    let mut hierarchy_transport = FixtureAwsOrganizationsTransport::fixture();
    hierarchy_transport.queue_list_policies(Ok(ListPoliciesPage::new(
        vec![fixtures.policy.clone()],
        None,
        Digest::from_text("different-hierarchy"),
        fixtures.scope.permissions.permission_digest.clone(),
    )));
    let mut hierarchy_service = fixtures.service_with_transport(hierarchy_transport);
    assert!(matches!(
        hierarchy_service.read_list_policies(),
        Err(ServiceError::HierarchyDrift)
    ));

    let mut permission_transport = FixtureAwsOrganizationsTransport::fixture();
    permission_transport.queue_list_policies(Ok(ListPoliciesPage::new(
        vec![fixtures.policy.clone()],
        None,
        fixtures.scope.hierarchy_digest.clone(),
        Digest::from_text("different-permission"),
    )));
    let mut permission_service = fixtures.service_with_transport(permission_transport);
    assert!(matches!(
        permission_service.read_list_policies(),
        Err(ServiceError::PermissionLoss)
    ));
}

#[test]
fn stale_mission_revision_and_consumer_revocation_block_consumption() {
    let fixtures = Fixtures::new();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies(Ok(fixtures.page_policy(None)));
    let mut service = fixtures.service_with_transport(transport);
    let result = service.read_list_policies().unwrap();
    let mut consumer = MissionAwsOrganizationsConsumer::new(service.scope());
    consumer.replace_mission(MissionBinding::new(
        MissionId::parse("mission-513").unwrap(),
        ProjectId::parse("project-513").unwrap(),
        WorkProductId::parse("work-product-513").unwrap(),
        RevisionId::parse("mission-rev-2").unwrap(),
        Digest::from_text("consent-1"),
    ));
    assert!(matches!(
        consumer.consume(&result),
        Err(hartevo_aws_organizations_governance_result_plugin::ConsumerError::StaleMission)
    ));
    consumer.replace_mission(service.scope().mission.clone());
    consumer.revoke().unwrap();
    assert!(matches!(
        consumer.consume(&result),
        Err(hartevo_aws_organizations_governance_result_plugin::ConsumerError::Revoked)
    ));
}

#[test]
fn service_registration_and_secret_revocation_are_operation_fences() {
    let fixtures = Fixtures::new();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies(Ok(fixtures.page_policy(None)));
    let mut service = fixtures.service_with_transport(transport);
    assert_eq!(service.registration().state, RegistrationState::Active);
    let revocation = service.revoke_registration().unwrap();
    assert_ne!(
        revocation.prior_registration_digest,
        revocation.revocation_digest
    );
    assert!(matches!(
        service.read_list_policies(),
        Err(ServiceError::RegistrationRevoked)
    ));

    let mut second_transport = FixtureAwsOrganizationsTransport::fixture();
    second_transport.queue_list_policies(Ok(fixtures.page_policy(None)));
    let mut second_service = fixtures.service_with_transport(second_transport);
    second_service.revoke_secret_reference().unwrap();
    assert!(matches!(
        second_service.read_list_policies(),
        Err(ServiceError::SecretRevoked)
    ));
}

#[test]
fn scope_and_hierarchy_reject_cross_organization_or_invalid_relationships() {
    let fixtures = Fixtures::new();
    let invalid_parent = OrganizationHierarchy::new(
        fixtures.organization_id.clone(),
        vec![
            HierarchyNode {
                target: fixtures.root.clone(),
                parent_target_id: Some(fixtures.account.target_id.clone()),
            },
            HierarchyNode {
                target: fixtures.account.clone(),
                parent_target_id: None,
            },
        ],
    );
    assert!(invalid_parent.is_err());
    let missing_parent = OrganizationHierarchy::new(
        fixtures.organization_id.clone(),
        vec![HierarchyNode {
            target: fixtures.ou.clone(),
            parent_target_id: None,
        }],
    );
    assert!(missing_parent.is_err());

    let other_org = OrganizationId::parse("o-otherorgid").unwrap();
    let other_account = TargetReference::new(
        other_org,
        TargetId::Account(AccountId::parse("222222222222").unwrap()),
        "arn:aws:organizations::222222222222:account/o-otherorgid/222222222222",
    )
    .unwrap();
    assert!(
        AwsOrganizationsScope::new(
            fixtures.organization_id.clone(),
            fixtures.hierarchy.clone(),
            vec![other_account],
            fixtures.scope.policy_type,
            fixtures.scope.mission.clone(),
            fixtures.scope.permissions.clone(),
        )
        .is_err()
    );

    let cross_org_policy = PolicyIdentity::from_values(
        fixtures.scope.policy_type,
        "p-crossorgpolicy111",
        "arn:aws:organizations::222222222222:policy/o-otherorgid/service_control_policy/p-crossorgpolicy111",
    )
    .unwrap();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_targets_for_policy(Ok(fixtures.page_targets(vec![], None)));
    let mut service = fixtures.service_with_transport(transport);
    assert!(matches!(
        service.read_list_targets_for_policy(cross_org_policy),
        Err(ServiceError::Provider(ProviderError::OrganizationMismatch))
    ));
}

#[test]
fn transport_failures_keep_statuses_and_permission_failures_distinct() {
    for (status, failure) in [
        (400, TransportFailure::BadRequest),
        (401, TransportFailure::Unauthorized),
        (403, TransportFailure::AccessDenied),
        (404, TransportFailure::NotFound),
        (409, TransportFailure::Conflict),
        (429, TransportFailure::Throttled),
        (500, TransportFailure::Server),
    ] {
        let error = TransportError::from_status(status);
        assert_eq!(error.status_code, Some(status));
        assert_eq!(error.failure, failure);
    }
    assert_eq!(TransportError::timeout().failure, TransportFailure::Timeout);
    assert_eq!(
        TransportError::blocked_env().failure,
        TransportFailure::BlockedEnv
    );

    let fixtures = Fixtures::new();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies(Err(TransportError::from_status(403)));
    let mut service = fixtures.service_with_transport(transport);
    assert!(matches!(
        service.read_list_policies(),
        Err(ServiceError::PermissionLoss)
    ));
}

#[test]
fn tampered_record_and_evidence_are_rejected() {
    let fixtures = Fixtures::new();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies(Ok(fixtures.page_policy(None)));
    let mut service = fixtures.service_with_transport(transport);
    let proposal = service.propose_list_policies().unwrap();
    let mut record = service.record(&proposal).unwrap();
    record.item_count = 900;
    assert!(matches!(
        service.verify(&proposal, &record),
        Err(ServiceError::TamperedEvidence)
    ));

    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies(Ok(fixtures.page_policy(None)));
    let mut service = fixtures.service_with_transport(transport);
    let mut evidence = service.read_list_policies().unwrap().evidence;
    evidence.digests.evidence_digest = Digest::from_text("tampered");
    assert!(matches!(
        evidence.verify(),
        Err(ServiceError::TamperedEvidence)
    ));
}

#[test]
fn blocked_environment_never_claims_native_or_connected() {
    let fixtures = Fixtures::new();
    let provider = AwsOrganizationsProvider::default();
    assert!(!provider.definition().native);
    assert!(!provider.definition().connected);
    assert!(!provider.provenance().native());
    assert!(!provider.provenance().connected());
    let mut service =
        AwsOrganizationsGovernanceService::new(fixtures.scope, fixtures.secret, provider).unwrap();
    assert!(matches!(
        service.read_list_policies(),
        Err(ServiceError::Provider(ProviderError::Transport(error)))
            if error.failure == TransportFailure::BlockedEnv
    ));
}

#[test]
fn permission_scope_can_remove_an_operation_without_leaking_authority() {
    let fixtures = Fixtures::new();
    let permissions = PermissionScope::new(
        fixtures.organization_id.clone(),
        AccountId::parse("111111111111").unwrap(),
        AuthorityKind::DelegatedAdministrator,
        BTreeSet::from([ReadOperation::ListPolicies]),
        RevisionId::parse("permission-rev-only-list").unwrap(),
        fixtures.scope.permissions.consent.clone(),
    )
    .unwrap();
    let scope = AwsOrganizationsScope::new(
        fixtures.organization_id.clone(),
        fixtures.hierarchy.clone(),
        vec![fixtures.root.clone()],
        fixtures.scope.policy_type,
        fixtures.scope.mission.clone(),
        permissions,
    )
    .unwrap();
    let secret = SigV4SecretReference::new(
        "opaque-delegated-admin-ref",
        "us-east-1",
        scope.scope_digest.clone(),
        RevisionId::parse("credential-rev-2").unwrap(),
    )
    .unwrap();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies_for_target(Ok(ListPoliciesForTargetPage::new(
        vec![],
        None,
        scope.hierarchy_digest.clone(),
        scope.permissions.permission_digest.clone(),
    )));
    let mut service = AwsOrganizationsGovernanceService::new(
        scope,
        secret,
        AwsOrganizationsProvider::new(transport),
    )
    .unwrap();
    assert!(matches!(
        service.read_list_policies_for_target(fixtures.root),
        Err(ServiceError::PermissionLoss)
    ));
}

#[test]
fn generic_read_seam_is_equivalent_to_operation_specific_read() {
    let fixtures = Fixtures::new();
    let mut transport = FixtureAwsOrganizationsTransport::fixture();
    transport.queue_list_policies(Ok(fixtures.page_policy(None)));
    let mut service = fixtures.service_with_transport(transport);
    let request = AwsOrganizationsReadRequest::ListPolicies(ListPoliciesRequest::new(
        fixtures.organization_id,
        fixtures.scope.policy_type,
        service.provider().bounds(),
        fixtures.scope.hierarchy_digest,
        fixtures.scope.permissions.permission_digest,
        fixtures.scope.scope_digest,
    ));
    let result = service.read(request).unwrap();
    assert_eq!(result.proposal.operation, ReadOperation::ListPolicies);
    assert_eq!(
        result.evidence.status,
        hartevo_aws_organizations_governance_result_plugin::EvidenceStatus::Complete
    );
}

#[test]
fn target_request_keeps_exact_target_and_policy_type_bound() {
    let fixtures = Fixtures::new();
    let bounds = ReadBounds::default();
    let request = ListPoliciesForTargetRequest::new(
        fixtures.organization_id.clone(),
        fixtures.account.clone(),
        PolicyType::ServiceControlPolicy,
        &bounds,
        fixtures.scope.hierarchy_digest.clone(),
        fixtures.scope.permissions.permission_digest.clone(),
        fixtures.scope.scope_digest.clone(),
    );
    let targets_request = ListTargetsForPolicyRequest::new(
        fixtures.organization_id,
        fixtures.policy,
        &bounds,
        fixtures.scope.hierarchy_digest,
        fixtures.scope.permissions.permission_digest,
        fixtures.scope.scope_digest,
    );
    assert_eq!(
        request.target.target_id,
        TargetId::Account(AccountId::parse("111111111111").unwrap())
    );
    assert_eq!(request.policy_type, PolicyType::ServiceControlPolicy);
    assert_eq!(
        targets_request.policy.policy_id.as_str(),
        "p-examplepolicyid111"
    );
}

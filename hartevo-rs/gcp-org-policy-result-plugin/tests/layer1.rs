use hartevo_gcp_org_policy_result_plugin::{
    BlockedEnvTransport, ConstraintId, ConstraintKind, Digest, FixtureGcpOrgPolicyTransport,
    GcpAuthKind, GcpOrgPolicyProvider, GcpOrgPolicyProviderDefinition, GcpOrgPolicyScope,
    GcpOrgPolicyService, GcpOrgPolicyServiceError, GcpOrgPolicyTransport, GcpProjectId,
    GcpResource, GetPolicyResponse, ListAvailableConstraintsRequest, ListPoliciesRequest,
    LoopbackGcpOrgPolicyTransport, MissionGcpOrgPolicyConsumer, MissionId, MissionScope,
    ModelError, OpaquePageToken, PermissionScope, PolicyId, PolicyRuleMode, PolicySource,
    PolicyState, ProjectId, ReadBounds, ReadOperation, RecordingGcpOrgPolicyTransport, Revision,
    SecretReference, TransportError, TransportFailure, TransportProvenance,
    UntrustedAvailableConstraint, UntrustedPolicy, WorkProductId,
};

#[derive(Clone)]
struct Fixtures {
    organization: hartevo_gcp_org_policy_result_plugin::OrganizationId,
    resource: GcpResource,
    constraint: ConstraintId,
    scope: GcpOrgPolicyScope,
    secret: SecretReference,
    current_policy: hartevo_gcp_org_policy_result_plugin::PolicySummary,
    inherited_policy: hartevo_gcp_org_policy_result_plugin::PolicySummary,
    dry_run_policy: hartevo_gcp_org_policy_result_plugin::PolicySummary,
    available_constraint: hartevo_gcp_org_policy_result_plugin::AvailableConstraintSummary,
}

impl Fixtures {
    fn new() -> Self {
        let organization =
            hartevo_gcp_org_policy_result_plugin::OrganizationId::parse("123456789012")
                .expect("organization");
        let resource = GcpResource::project(
            GcpProjectId::parse("demo-org-policy-684").expect("Google project"),
        );
        let constraint =
            ConstraintId::parse("constraints/compute.disableSerialPortAccess").expect("constraint");
        let consent = Digest::from_text("consent-684");
        let permissions = PermissionScope::all(Revision::new(1).expect("revision"), consent)
            .expect("permissions");
        let mission = MissionScope::new(
            ProjectId::parse("project-684").expect("Project"),
            Revision::new(3).expect("Project revision"),
            MissionId::parse("mission-684").expect("Mission"),
            Revision::new(7).expect("Mission revision"),
            WorkProductId::parse("work-product-684").expect("Work Product"),
            Revision::new(2).expect("Work Product revision"),
            Digest::from_text("mission-consent-684"),
        );
        let scope = GcpOrgPolicyScope::new(
            organization.clone(),
            resource.clone(),
            [constraint.clone()],
            Revision::new(11).expect("policy revision"),
            mission,
            permissions,
        )
        .expect("scope");
        let secret = SecretReference::new(
            "keyring-gcp-org-policy-684",
            &scope,
            Revision::new(4).expect("credential revision"),
            GcpAuthKind::OAuth,
        )
        .expect("opaque secret reference");
        let policy_id = PolicyId::for_resource(&resource, &constraint);
        let current_policy = policy(
            resource.clone(),
            constraint.clone(),
            policy_id.clone(),
            PolicySource::Current,
            PolicyRuleMode::Enforced,
            "enforced raw value: user@example.com",
            ["user@example.com", "member@example.com"],
        );
        let inherited_policy = policy(
            resource.clone(),
            constraint.clone(),
            policy_id.clone(),
            PolicySource::Inherited,
            PolicyRuleMode::Enforced,
            "inherited raw value: secret-member@example.com",
            ["secret-member@example.com"],
        );
        let dry_run_policy = policy(
            resource.clone(),
            constraint.clone(),
            policy_id,
            PolicySource::Current,
            PolicyRuleMode::DryRun,
            "dry-run raw value: private@example.com",
            ["private@example.com"],
        );
        let available_constraint = UntrustedAvailableConstraint::new(
            constraint.clone(),
            Revision::new(5).expect("constraint revision"),
            ConstraintKind::Managed,
            "private constraint description with PII@example.com",
        )
        .expect("available constraint")
        .into_summary();
        Self {
            organization,
            resource,
            constraint,
            scope,
            secret,
            current_policy,
            inherited_policy,
            dry_run_policy,
            available_constraint,
        }
    }

    fn list_request(&self, token: Option<OpaquePageToken>) -> ListPoliciesRequest {
        ListPoliciesRequest::new(&self.scope, ReadBounds::default(), None, token)
            .expect("list request")
    }

    fn available_request(&self, token: Option<OpaquePageToken>) -> ListAvailableConstraintsRequest {
        ListAvailableConstraintsRequest::new(&self.scope, ReadBounds::default(), token)
    }

    fn service(
        &self,
        transport: FixtureGcpOrgPolicyTransport,
    ) -> GcpOrgPolicyService<FixtureGcpOrgPolicyTransport> {
        GcpOrgPolicyService::new(
            self.scope.clone(),
            self.secret.clone(),
            GcpOrgPolicyProvider::new(transport),
        )
        .expect("service")
    }
}

fn policy(
    resource: GcpResource,
    constraint: ConstraintId,
    policy_id: PolicyId,
    source: PolicySource,
    mode: PolicyRuleMode,
    raw_values: &str,
    members: impl IntoIterator<Item = &'static str>,
) -> hartevo_gcp_org_policy_result_plugin::PolicySummary {
    UntrustedPolicy::new(
        resource,
        constraint,
        policy_id,
        Revision::new(1).expect("policy revision"),
        source,
        mode,
        "etag-684",
        "2026-08-15T00:00:00Z",
        raw_values,
        members,
    )
    .expect("untrusted policy")
    .into_summary()
}

#[test]
fn contract_and_provider_definitions_are_layer_one_non_native() {
    let definition =
        GcpOrgPolicyProviderDefinition::new(Revision::new(1).expect("revision"), "1.0.0");
    assert_eq!(definition.provider_id, "gcp.organization-policy.recording");
    assert_eq!(definition.api_version, "v2");
    assert!(definition.read_only);
    assert!(!definition.connected);
    assert!(!definition.native);
    assert!(!definition.first_party);
    assert_eq!(TransportProvenance::Fixture.as_str(), "fixture");
    assert!(!TransportProvenance::Fixture.connected());
    assert!(!TransportProvenance::Recording.native());
    assert!(!TransportProvenance::Loopback.first_party());
    assert!(!TransportProvenance::BlockedEnv.connected());
}

#[test]
fn list_policies_is_bounded_and_retains_only_redacted_policy_projection() {
    let fixtures = Fixtures::new();
    let first_request = fixtures.list_request(None);
    let token =
        OpaquePageToken::new("opaque-page-token-with-member@example.com").expect("opaque token");
    let second_request = fixtures.list_request(Some(token.clone()));
    let mut transport = FixtureGcpOrgPolicyTransport::fixture();
    transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.current_policy.clone()],
            Some(token.clone()),
            &first_request,
        ),
    ));
    transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.inherited_policy.clone()],
            None,
            &second_request,
        ),
    ));
    let mut service = fixtures.service(transport);
    let read = service.read_list_policies().expect("bounded list");
    assert_eq!(read.evidence.policies.len(), 2);
    assert_eq!(read.evidence.pagination.pages_observed, 2);
    assert!(read.evidence.pagination.complete);
    assert_eq!(read.evidence.pagination.page_token_digests.len(), 1);
    assert_eq!(read.evidence.pagination.request_digests.len(), 2);
    assert!(read.evidence.redaction.raw_policy_values_removed);
    assert!(read.evidence.redaction.raw_policy_members_removed);
    assert!(read.evidence.redaction.pii_removed);
    let serialized = serde_json::to_string(&read.evidence).expect("evidence JSON");
    assert!(!serialized.contains("user@example.com"));
    assert!(!serialized.contains("opaque-page-token-with-member"));
    assert!(!format!("{token:?}").contains("opaque-page-token-with-member"));
}

#[test]
fn current_inherited_and_dry_run_states_remain_distinct() {
    let fixtures = Fixtures::new();
    assert_eq!(fixtures.current_policy.source, PolicySource::Current);
    assert_eq!(fixtures.current_policy.state, PolicyState::Current);
    assert_eq!(fixtures.inherited_policy.source, PolicySource::Inherited);
    assert_eq!(fixtures.inherited_policy.state, PolicyState::Inherited);
    assert_eq!(fixtures.dry_run_policy.rule_mode, PolicyRuleMode::DryRun);
    assert_eq!(fixtures.dry_run_policy.state, PolicyState::DryRun);

    let request = hartevo_gcp_org_policy_result_plugin::GetEffectivePolicyRequest::new(
        &fixtures.scope,
        fixtures.constraint.clone(),
    )
    .expect("effective policy request");
    let mut transport = FixtureGcpOrgPolicyTransport::fixture();
    transport.queue_get_effective_policy(Ok(GetPolicyResponse::new(
        fixtures.dry_run_policy.clone(),
        request.scope_digest.clone(),
        request.permission_digest.clone(),
        request.request_digest.clone(),
    )));
    let mut service = fixtures.service(transport);
    let read = service
        .read_get_effective_policy(fixtures.constraint.clone())
        .expect("effective policy");
    assert_eq!(read.evidence.operation, ReadOperation::GetEffectivePolicy);
    assert_eq!(read.evidence.policies[0].state, PolicyState::DryRun);
    assert!(!read.evidence.authority.effective_authorization);
}

#[test]
fn get_policy_read_is_distinct_from_effective_policy_read() {
    let fixtures = Fixtures::new();
    let request = hartevo_gcp_org_policy_result_plugin::GetPolicyRequest::new(
        &fixtures.scope,
        fixtures.constraint.clone(),
    )
    .expect("policy request");
    let mut transport = FixtureGcpOrgPolicyTransport::fixture();
    transport.queue_get_policy(Ok(GetPolicyResponse::new(
        fixtures.current_policy.clone(),
        request.scope_digest.clone(),
        request.permission_digest.clone(),
        request.request_digest.clone(),
    )));
    let mut service = fixtures.service(transport);
    let read = service
        .read_get_policy(fixtures.constraint)
        .expect("current policy");
    assert_eq!(read.evidence.operation, ReadOperation::GetPolicy);
    assert_eq!(read.evidence.policies[0].state, PolicyState::Current);
    assert!(read.evidence.pagination.complete);
}

#[test]
fn available_constraint_read_is_allowlisted_and_digest_only() {
    let fixtures = Fixtures::new();
    let request = fixtures.available_request(None);
    let mut transport = FixtureGcpOrgPolicyTransport::fixture();
    transport.queue_list_available_constraints(Ok(
        hartevo_gcp_org_policy_result_plugin::ConstraintPage::for_request(
            vec![fixtures.available_constraint.clone()],
            None,
            &request,
        ),
    ));
    let mut service = fixtures.service(transport);
    let read = service
        .read_list_available_constraints()
        .expect("available constraints");
    assert_eq!(read.evidence.available_constraints.len(), 1);
    assert_eq!(
        read.evidence.available_constraints[0].constraint,
        fixtures.constraint
    );
    let serialized = serde_json::to_string(&read.evidence).expect("constraint JSON");
    assert!(!serialized.contains("private constraint description"));
    assert!(read.evidence.redaction.raw_constraint_definition_removed);
}

#[test]
fn page_request_binding_rejects_cursor_tamper_and_filter_drift() {
    let fixtures = Fixtures::new();
    let first_request = fixtures.list_request(None);
    let token = OpaquePageToken::new("cursor-one").expect("cursor");
    let second_request = fixtures.list_request(Some(token.clone()));
    let mut transport = FixtureGcpOrgPolicyTransport::fixture();
    transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.current_policy.clone()],
            Some(token.clone()),
            &first_request,
        ),
    ));
    transport.queue_list_policies(Ok(hartevo_gcp_org_policy_result_plugin::PolicyPage::new(
        vec![fixtures.inherited_policy.clone()],
        None,
        second_request.scope_digest.clone(),
        second_request.permission_digest.clone(),
        Digest::from_text("tampered-request"),
    )));
    let mut provider = GcpOrgPolicyProvider::new(transport);
    let error = provider
        .list_policies(first_request)
        .expect_err("tampered request digest must fail closed");
    assert!(matches!(
        error,
        hartevo_gcp_org_policy_result_plugin::ProviderError::RequestDigestMismatch
    ));

    let out_of_scope = ConstraintId::parse("constraints/storage.uniformBucketLevelAccess")
        .expect("other constraint");
    assert!(matches!(
        hartevo_gcp_org_policy_result_plugin::GetPolicyRequest::new(&fixtures.scope, out_of_scope),
        Err(ModelError::Invalid {
            field: "constraint allowlist"
        })
    ));
}

#[test]
fn hierarchy_permission_page_and_response_tamper_are_rejected() {
    let fixtures = Fixtures::new();
    let request = fixtures.list_request(None);
    let mut hierarchy_transport = FixtureGcpOrgPolicyTransport::fixture();
    hierarchy_transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::new(
            vec![fixtures.current_policy.clone()],
            None,
            Digest::from_text("different-scope"),
            request.permission_digest.clone(),
            request.request_digest.clone(),
        ),
    ));
    let mut hierarchy_provider = GcpOrgPolicyProvider::new(hierarchy_transport);
    assert!(matches!(
        hierarchy_provider.list_policies(request.clone()),
        Err(hartevo_gcp_org_policy_result_plugin::ProviderError::ScopeDigestMismatch)
    ));

    let mut permission_transport = FixtureGcpOrgPolicyTransport::fixture();
    permission_transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::new(
            vec![fixtures.current_policy.clone()],
            None,
            request.scope_digest.clone(),
            Digest::from_text("different-permission"),
            request.request_digest.clone(),
        ),
    ));
    let mut permission_provider = GcpOrgPolicyProvider::new(permission_transport);
    assert!(matches!(
        permission_provider.list_policies(request.clone()),
        Err(hartevo_gcp_org_policy_result_plugin::ProviderError::PermissionDigestMismatch)
    ));

    let mut page_transport = FixtureGcpOrgPolicyTransport::fixture();
    let mut tampered_page = hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
        vec![fixtures.current_policy.clone()],
        None,
        &request,
    );
    tampered_page.page_digest = Digest::from_text("tampered-page");
    page_transport.queue_list_policies(Ok(tampered_page));
    let mut page_provider = GcpOrgPolicyProvider::new(page_transport);
    assert!(matches!(
        page_provider.list_policies(request),
        Err(hartevo_gcp_org_policy_result_plugin::ProviderError::PageDigestMismatch)
    ));
}

#[test]
fn repeated_and_incomplete_pagination_fail_closed() {
    let fixtures = Fixtures::new();
    let first_request = fixtures.list_request(None);
    let token = OpaquePageToken::new("repeated-cursor").expect("cursor");
    let second_request = fixtures.list_request(Some(token.clone()));
    let mut repeated_transport = FixtureGcpOrgPolicyTransport::fixture();
    repeated_transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.current_policy.clone()],
            Some(token.clone()),
            &first_request,
        ),
    ));
    repeated_transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.inherited_policy.clone()],
            Some(token),
            &second_request,
        ),
    ));
    let mut repeated_provider = GcpOrgPolicyProvider::new(repeated_transport);
    assert!(matches!(
        repeated_provider.list_policies(first_request),
        Err(hartevo_gcp_org_policy_result_plugin::ProviderError::PaginationTokenMismatch)
    ));

    let first_request = fixtures.list_request(None);
    let token = OpaquePageToken::new("more-pages-than-bound").expect("cursor");
    let mut incomplete_transport = FixtureGcpOrgPolicyTransport::fixture();
    incomplete_transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.current_policy],
            Some(token),
            &first_request,
        ),
    ));
    let bounds = ReadBounds::new(1, 10, 10).expect("small bounds");
    let mut incomplete_provider = GcpOrgPolicyProvider::with_bounds(incomplete_transport, bounds);
    assert!(matches!(
        incomplete_provider.list_policies(first_request),
        Err(hartevo_gcp_org_policy_result_plugin::ProviderError::PaginationIncomplete)
    ));
}

#[test]
fn proposal_consumer_binds_project_mission_work_product_and_records_replay() {
    let fixtures = Fixtures::new();
    let request = fixtures.list_request(None);
    let mut transport = FixtureGcpOrgPolicyTransport::fixture();
    transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.current_policy.clone()],
            None,
            &request,
        ),
    ));
    let mut service = fixtures.service(transport);
    let read = service.read_list_policies().expect("read");
    let proposal = service.propose(&read).expect("proposal");
    let verification = service.verify(&proposal).expect("verification");
    assert!(verification.valid);
    assert!(verification.pagination_complete);
    let mut consumer =
        MissionGcpOrgPolicyConsumer::new(fixtures.scope.clone(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(result.project_id.as_str(), "project-684");
    assert_eq!(result.mission_id.as_str(), "mission-684");
    assert_eq!(result.work_product_id.as_str(), "work-product-684");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let first = consumer
        .record(&proposal, "idempotency-684")
        .expect("record");
    let replay = consumer
        .record(&proposal, "idempotency-684")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn stale_mission_tampered_proposal_and_recording_conflict_are_rejected() {
    let fixtures = Fixtures::new();
    let request = fixtures.list_request(None);
    let mut transport = FixtureGcpOrgPolicyTransport::fixture();
    transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.current_policy.clone()],
            None,
            &request,
        ),
    ));
    let mut service = fixtures.service(transport);
    let read = service.read_list_policies().expect("read");
    let proposal = service.propose(&read).expect("proposal");
    let mut consumer =
        MissionGcpOrgPolicyConsumer::new(fixtures.scope.clone(), service.registration().clone())
            .expect("consumer");
    let mut stale = fixtures.scope.mission.clone();
    stale.mission_revision = Revision::new(8).expect("new Mission revision");
    consumer.replace_mission(stale);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(hartevo_gcp_org_policy_result_plugin::ConsumerError::StaleMission)
    ));

    let mut tampered = proposal.clone();
    tampered.evidence.digests.evidence_digest = Digest::from_text("tampered");
    assert!(matches!(
        service.verify(&tampered),
        Err(GcpOrgPolicyServiceError::TamperedEvidence)
    ));

    let mut second_transport = FixtureGcpOrgPolicyTransport::fixture();
    second_transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.dry_run_policy.clone()],
            None,
            &request,
        ),
    ));
    let mut second_service = fixtures.service(second_transport);
    let second_read = second_service.read_list_policies().expect("second read");
    let second_proposal = second_service
        .propose(&second_read)
        .expect("second proposal");
    service
        .record(&proposal, "shared-key")
        .expect("first record");
    assert!(matches!(
        service.record(&second_proposal, "shared-key"),
        Err(GcpOrgPolicyServiceError::RecordingConflict)
    ));
}

#[test]
fn registration_and_secret_revocation_are_reversible_fences() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.service(FixtureGcpOrgPolicyTransport::fixture());
    assert!(service.registration().is_active());
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(
        reversed.new_state,
        hartevo_gcp_org_policy_result_plugin::RegistrationState::Reversed
    );
    assert!(matches!(
        service.read_list_policies(),
        Err(GcpOrgPolicyServiceError::RegistrationRevoked)
    ));
    let restored = service.restore_registration().expect("restore");
    assert_eq!(
        restored.new_state,
        hartevo_gcp_org_policy_result_plugin::RegistrationState::Active
    );
    service.revoke_secret_reference().expect("revoke secret");
    assert!(matches!(
        service.read_list_policies(),
        Err(GcpOrgPolicyServiceError::SecretRevoked)
    ));
}

#[test]
fn oauth_and_service_account_references_are_opaque_and_scope_bound() {
    let fixtures = Fixtures::new();
    let oauth_debug = format!("{:?}", fixtures.secret);
    assert!(!oauth_debug.contains("keyring-gcp-org-policy-684"));
    let service_account = SecretReference::new(
        "keyring-gcp-org-policy-684",
        &fixtures.scope,
        Revision::new(4).expect("credential revision"),
        GcpAuthKind::ServiceAccount,
    )
    .expect("service-account reference");
    assert_ne!(
        fixtures.secret.reference_digest(),
        service_account.reference_digest()
    );
    assert!(!format!("{service_account:?}").contains("keyring-gcp-org-policy-684"));
    let other_scope = GcpOrgPolicyScope::new(
        fixtures.organization,
        fixtures.resource,
        [fixtures.constraint],
        Revision::new(12).expect("other revision"),
        fixtures.scope.mission.clone(),
        fixtures.scope.permissions.clone(),
    )
    .expect("other scope");
    assert!(matches!(
        GcpOrgPolicyService::new(
            other_scope,
            fixtures.secret,
            GcpOrgPolicyProvider::new(FixtureGcpOrgPolicyTransport::fixture()),
        ),
        Err(GcpOrgPolicyServiceError::SecretScopeMismatch)
    ));
}

#[test]
fn all_non_native_transports_keep_authority_false_and_record_only_digests() {
    let fixtures = Fixtures::new();
    let request = fixtures.list_request(None);
    let mut fixture = FixtureGcpOrgPolicyTransport::fixture();
    fixture.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![fixtures.current_policy.clone()],
            None,
            &request,
        ),
    ));
    let recording = RecordingGcpOrgPolicyTransport::new(fixture);
    let mut service = GcpOrgPolicyService::new(
        fixtures.scope.clone(),
        fixtures.secret.clone(),
        GcpOrgPolicyProvider::new(recording),
    )
    .expect("recording service");
    let read = service.read_list_policies().expect("recorded read");
    assert_eq!(read.evidence.provenance, TransportProvenance::Recording);
    assert!(!read.connected);
    assert!(!read.native);
    assert!(!read.first_party);
    assert_eq!(service.provider().transport().calls().len(), 1);
    assert!(
        service.provider().transport().calls()[0]
            .page_token_digest
            .is_none()
    );

    let mut loopback = LoopbackGcpOrgPolicyTransport::loopback();
    loopback.queue_list_policies(Err(TransportError::Timeout));
    assert_eq!(loopback.provenance(), TransportProvenance::Loopback);
    let mut blocked = BlockedEnvTransport;
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    assert!(matches!(
        blocked.list_policies(&request),
        Err(TransportError::BlockedEnv)
    ));
}

#[test]
fn provider_maps_adversarial_http_statuses_without_native_claims() {
    let fixtures = Fixtures::new();
    let request = fixtures.list_request(None);
    let failures: [TransportFailure; 9] = [
        TransportError::BadRequest,
        TransportError::Unauthorized,
        TransportError::Forbidden,
        TransportError::NotFound,
        TransportError::Conflict,
        TransportError::Throttled,
        TransportError::ServerFailure,
        TransportError::Timeout,
        TransportError::Malformed,
    ];
    for failure in failures {
        let mut transport = FixtureGcpOrgPolicyTransport::fixture();
        transport.queue_list_policies(Err(failure.clone()));
        let mut provider = GcpOrgPolicyProvider::new(transport);
        assert!(matches!(
            provider.list_policies(request.clone()),
            Err(hartevo_gcp_org_policy_result_plugin::ProviderError::Transport(received))
                if received == failure
        ));
    }
}

#[test]
fn policy_and_constraint_ids_cannot_cross_the_declared_scope() {
    let fixtures = Fixtures::new();
    let wrong_resource = GcpResource::project(
        GcpProjectId::parse("other-org-policy-684").expect("other Google project"),
    );
    let wrong_policy = policy(
        wrong_resource,
        fixtures.constraint.clone(),
        PolicyId::parse("projects/other/policies/constraints/compute.disableSerialPortAccess")
            .expect("policy id"),
        PolicySource::Current,
        PolicyRuleMode::Enforced,
        "other raw value",
        ["other@example.com", "other2@example.com"],
    );
    let request = fixtures.list_request(None);
    let mut transport = FixtureGcpOrgPolicyTransport::fixture();
    transport.queue_list_policies(Ok(
        hartevo_gcp_org_policy_result_plugin::PolicyPage::for_request(
            vec![wrong_policy],
            None,
            &request,
        ),
    ));
    let mut provider = GcpOrgPolicyProvider::new(transport);
    assert!(matches!(
        provider.list_policies(request),
        Err(hartevo_gcp_org_policy_result_plugin::ProviderError::MalformedResponse)
    ));
}

#[test]
fn opaque_cursor_changes_request_digest_without_exposing_cursor() {
    let fixtures = Fixtures::new();
    let first = fixtures.list_request(Some(OpaquePageToken::new("cursor-a").expect("cursor")));
    let second = fixtures.list_request(Some(OpaquePageToken::new("cursor-b").expect("cursor")));
    assert_ne!(first.request_digest, second.request_digest);
    assert_ne!(first.page_token_digest(), second.page_token_digest());
    assert!(!format!("{first:?}").contains("cursor-a"));
    assert!(!format!("{second:?}").contains("cursor-b"));
}

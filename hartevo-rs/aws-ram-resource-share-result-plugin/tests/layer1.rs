use hartevo_aws_ram_resource_share_result_plugin::{
    AWS_RAM_API_REVISION, AssociationStatus, AwsAccountId, AwsRamContract, AwsRamProvider,
    AwsRamReadPage, AwsRamResourceShareService, AwsRamScope, AwsRegion, BlockedEnvTransport,
    Digest, FixtureAwsRamTransport, InvitationArn, InvitationMetadata, InvitationStatus,
    MissionAwsRamConsumer, MissionBinding, MissionId, OpaquePageToken, PermissionArn,
    PermissionMetadata, PermissionSnapshot, PrincipalId, PrincipalMetadata, ProjectBinding,
    ProjectId, RamEvidenceState, RamPageItems, RamReadFilter, RamReadRequest,
    RecordingAwsRamTransport, ResourceArn, ResourceMetadata, ResourceRegionScope, ResourceShareArn,
    ResourceShareMetadata, ResourceShareStatus, ResourceType, Revision, SecretReference,
    TransportError, WorkProductBinding, WorkProductId,
};

const RAW_ACCOUNT: &str = "123456789012";
const RAW_OTHER_ACCOUNT: &str = "210987654321";
const RAW_SHARE_ARN: &str = "arn:aws:ram:us-east-1:123456789012:resource-share/share-ram-1";
const RAW_RESOURCE_ARN: &str = "arn:aws:s3:us-east-1:123456789012:accesspoint/ram-1";
const RAW_PRINCIPAL: &str = "arn:aws:iam::210987654321:role/ram-reader";
const RAW_PERMISSION_ARN: &str =
    "arn:aws:ram:us-east-1:123456789012:permission/AWSRAMDefaultPermissionS3";
const RAW_INVITATION_ARN: &str =
    "arn:aws:ram:us-east-1:123456789012:resource-share-invitation/invite-1";
const RAW_SECRET: &str = "keyring://aws/ram/sigv4/opaque";

struct Fixtures {
    scope: AwsRamScope,
    share: ResourceShareArn,
    invitation: InvitationArn,
}

impl Fixtures {
    fn new() -> Self {
        let share = ResourceShareArn::new(RAW_SHARE_ARN).expect("share ARN");
        let resource = ResourceArn::new(RAW_RESOURCE_ARN).expect("resource ARN");
        let principal = PrincipalId::new(RAW_PRINCIPAL).expect("principal");
        let permission_arn = PermissionArn::new(RAW_PERMISSION_ARN).expect("permission ARN");
        let invitation = InvitationArn::new(RAW_INVITATION_ARN).expect("invitation ARN");
        let scope = AwsRamScope::single(
            AwsAccountId::new(RAW_ACCOUNT).expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            hartevo_aws_ram_resource_share_result_plugin::OrganizationId::new("o-exampleorgid")
                .expect("organization"),
            share.clone(),
            resource.clone(),
            principal.clone(),
            permission_arn.clone(),
            invitation.clone(),
            MissionBinding::new(
                MissionId::new("mission-ram-781").expect("Mission"),
                Revision::new(1).expect("Mission revision"),
            ),
            ProjectBinding::new(
                ProjectId::new("project-ram-781").expect("Project"),
                Revision::new(2).expect("Project revision"),
            ),
            WorkProductBinding::new(
                WorkProductId::new("work-product-ram-781").expect("Work Product"),
                Revision::new(3).expect("Work Product revision"),
            ),
            Revision::new(7).expect("association revision"),
        )
        .expect("scope");
        Self {
            scope,
            share,
            invitation,
        }
    }

    fn permission() -> PermissionSnapshot {
        PermissionSnapshot::read_only(Revision::new(4).expect("permission revision"))
            .expect("read-only permission")
    }

    fn secret(&self) -> SecretReference {
        SecretReference::sigv4(
            RAW_SECRET,
            &self.scope,
            Revision::new(9).expect("credential revision"),
        )
        .expect("secret reference")
    }

    fn resource_arn() -> ResourceArn {
        ResourceArn::new(RAW_RESOURCE_ARN).expect("resource ARN")
    }

    fn principal_id() -> PrincipalId {
        PrincipalId::new(RAW_PRINCIPAL).expect("principal")
    }

    fn permission_arn_value() -> PermissionArn {
        PermissionArn::new(RAW_PERMISSION_ARN).expect("permission ARN")
    }

    fn shares_page(&self, request: &RamReadRequest) -> AwsRamReadPage {
        AwsRamReadPage::new(
            request,
            RamPageItems::ResourceShares(vec![ResourceShareMetadata {
                resource_share_arn: self.share.clone(),
                name: hartevo_aws_ram_resource_share_result_plugin::ShareName::new(
                    "cross-account-read",
                )
                .expect("share name"),
                owning_account: AwsAccountId::new(RAW_ACCOUNT).expect("owning account"),
                status: ResourceShareStatus::Active,
                allow_external_principals: false,
                feature_set: Some("STANDARD".to_owned()),
                creation_time: 1_787_000_000,
                last_updated_time: 1_787_000_100,
                retain_sharing_on_account_leave_organization: true,
                association_revision: Revision::new(7).expect("association revision"),
            }]),
            None,
            512,
            Revision::new(7).expect("page association revision"),
            AWS_RAM_API_REVISION,
        )
        .expect("share page")
    }

    fn service_with_fixture(
        &self,
        transport: FixtureAwsRamTransport,
    ) -> AwsRamResourceShareService<FixtureAwsRamTransport> {
        let permission = Self::permission();
        let provider = AwsRamProvider::new(transport).expect("provider");
        AwsRamResourceShareService::new(self.scope.clone(), self.secret(), permission, provider)
            .expect("service")
    }
}

fn shares_request(fixtures: &Fixtures) -> RamReadRequest {
    RamReadRequest::get_resource_shares(
        fixtures.scope.clone(),
        RamReadFilter::new(
            hartevo_aws_ram_resource_share_result_plugin::ResourceOwner::SelfAccount,
        ),
        50,
    )
    .expect("request")
}

#[test]
fn contract_registration_and_sensitive_values_are_redacted() {
    let fixtures = Fixtures::new();
    AwsRamContract::baseline().expect("contract");
    let serialized_secret = serde_json::to_string(&fixtures.secret()).expect("secret JSON");
    assert_eq!(serialized_secret, r#"{"opaque":true}"#);
    assert!(!format!("{:?}", fixtures.secret()).contains(RAW_SECRET));
    assert!(!serialized_secret.contains(RAW_SECRET));

    let cursor = OpaquePageToken::new("provider-next-token-ram-secret").expect("cursor");
    let cursor_json = serde_json::to_string(&cursor).expect("cursor JSON");
    assert_eq!(cursor_json, r#"{"opaque":true}"#);
    assert!(!format!("{cursor:?}").contains("provider-next-token-ram-secret"));

    let request = shares_request(&fixtures);
    let request_json = serde_json::to_string(&request).expect("request JSON");
    assert!(!request_json.contains(RAW_ACCOUNT));
    assert!(!request_json.contains(RAW_SHARE_ARN));

    let mut transport = FixtureAwsRamTransport::fixture();
    transport.push_response(Ok(fixtures.shares_page(&request)));
    let service = fixtures.service_with_fixture(transport);
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(!registration_json.contains(RAW_SECRET));
    assert!(!registration_json.contains(RAW_ACCOUNT));
    assert!(!format!("{:?}", service.registration()).contains(RAW_SECRET));
    assert!(service.registration().validate().is_ok());
}

#[test]
fn fixture_share_proposal_is_bounded_review_only_and_idempotently_recorded() {
    let fixtures = Fixtures::new();
    let request = shares_request(&fixtures);
    let mut transport = FixtureAwsRamTransport::fixture();
    transport.push_response(Ok(fixtures.shares_page(&request)));
    let mut service = fixtures.service_with_fixture(transport);

    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, RamEvidenceState::Present);
    assert_eq!(proposal.evidence.resource_shares.len(), 1);
    assert!(proposal.evidence.pagination.complete);
    assert!(proposal.evidence.redaction.raw_account_identifiers_redacted);
    assert!(proposal.evidence.redaction.raw_arns_redacted);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(proposal.validate_integrity().is_ok());
    let verification = service.verify(&proposal);
    assert!(verification.valid);
    assert!(verification.review_eligible);

    let mut consumer = service.consumer();
    consumer
        .bind_registration(service.registration())
        .expect("bind registration");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.accepted);
    assert!(result.review_only);
    assert!(!result.adopted_outcome);
    assert!(!result.truth_authority);
    assert!(!result.effective_authorization);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);

    let receipt = service.record(&proposal, "record-ram-781").expect("record");
    assert!(receipt.recorded);
    assert!(!receipt.replayed);
    let replay = service.record(&proposal, "record-ram-781").expect("replay");
    assert!(replay.replayed);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_ACCOUNT,
        RAW_OTHER_ACCOUNT,
        RAW_SHARE_ARN,
        RAW_RESOURCE_ARN,
        RAW_PRINCIPAL,
        RAW_PERMISSION_ARN,
        RAW_INVITATION_ARN,
        RAW_SECRET,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
}

#[test]
fn resource_principal_and_permission_reads_are_typed_and_redacted() {
    let fixtures = Fixtures::new();
    let resource_request = RamReadRequest::list_resources(
        fixtures.scope.clone(),
        RamReadFilter::new(
            hartevo_aws_ram_resource_share_result_plugin::ResourceOwner::SelfAccount,
        ),
        50,
    )
    .expect("resource request");
    let principal_request = RamReadRequest::list_principals(
        fixtures.scope.clone(),
        RamReadFilter::new(
            hartevo_aws_ram_resource_share_result_plugin::ResourceOwner::SelfAccount,
        ),
        50,
    )
    .expect("principal request");
    let permission_request = RamReadRequest::list_resource_share_permissions(
        fixtures.scope.clone(),
        RamReadFilter::new(
            hartevo_aws_ram_resource_share_result_plugin::ResourceOwner::SelfAccount,
        ),
        50,
    )
    .expect("permission request");
    let mut transport = FixtureAwsRamTransport::fixture();
    transport.push_response(Ok(AwsRamReadPage::new(
        &resource_request,
        RamPageItems::Resources(vec![ResourceMetadata {
            arn: Fixtures::resource_arn(),
            resource_share_arn: fixtures.share.clone(),
            resource_type: ResourceType::new("s3:accesspoint").expect("resource type"),
            resource_region_scope: ResourceRegionScope::Regional,
            status: AssociationStatus::Associated,
            resource_group_arn: None,
            creation_time: 1,
            last_updated_time: 2,
            association_revision: Revision::new(7).expect("revision"),
        }]),
        None,
        256,
        Revision::new(7).expect("revision"),
        AWS_RAM_API_REVISION,
    )
    .expect("resource page")));
    transport.push_response(Ok(AwsRamReadPage::new(
        &principal_request,
        RamPageItems::Principals(vec![PrincipalMetadata {
            id: Fixtures::principal_id(),
            resource_share_arn: fixtures.share.clone(),
            external: true,
            creation_time: 1,
            last_updated_time: 2,
            association_revision: Revision::new(7).expect("revision"),
        }]),
        None,
        256,
        Revision::new(7).expect("revision"),
        AWS_RAM_API_REVISION,
    )
    .expect("principal page")));
    transport.push_response(Ok(AwsRamReadPage::new(
        &permission_request,
        RamPageItems::Permissions(vec![PermissionMetadata {
            permission_arn: Fixtures::permission_arn_value(),
            version: 1,
            default_version: true,
            resource_type: ResourceType::new("s3:accesspoint").expect("resource type"),
            customer_managed: false,
            association_revision: Revision::new(7).expect("revision"),
        }]),
        None,
        256,
        Revision::new(7).expect("revision"),
        AWS_RAM_API_REVISION,
    )
    .expect("permission page")));
    let mut service = fixtures.service_with_fixture(transport);
    let resource = service
        .propose(resource_request)
        .expect("resource proposal");
    let principal = service
        .propose(principal_request)
        .expect("principal proposal");
    let permission = service
        .propose(permission_request)
        .expect("permission proposal");
    assert_eq!(resource.state, RamEvidenceState::Present);
    assert_eq!(principal.state, RamEvidenceState::Present);
    assert_eq!(permission.state, RamEvidenceState::Present);
    assert_eq!(resource.evidence.resources.len(), 1);
    assert_eq!(principal.evidence.principals.len(), 1);
    assert_eq!(permission.evidence.permissions.len(), 1);
    for serialized in [
        serde_json::to_string(&resource).expect("resource JSON"),
        serde_json::to_string(&principal).expect("principal JSON"),
        serde_json::to_string(&permission).expect("permission JSON"),
    ] {
        assert!(!serialized.contains(RAW_ACCOUNT));
        assert!(!serialized.contains(RAW_RESOURCE_ARN));
        assert!(!serialized.contains(RAW_PRINCIPAL));
        assert!(!serialized.contains(RAW_PERMISSION_ARN));
    }
}

#[test]
fn blocked_environment_is_provider_unknown_and_never_native() {
    let fixtures = Fixtures::new();
    let request = shares_request(&fixtures);
    let provider = AwsRamProvider::new(BlockedEnvTransport).expect("provider");
    let mut service = AwsRamResourceShareService::new(
        fixtures.scope.clone(),
        fixtures.secret(),
        Fixtures::permission(),
        provider,
    )
    .expect("service");
    let proposal = service.propose(request).expect("blocked proposal");
    assert_eq!(proposal.state, RamEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        hartevo_aws_ram_resource_share_result_plugin::RamFailureCategory::BlockedEnv
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn invitation_statuses_are_projected_without_raw_accounts() {
    let fixtures = Fixtures::new();
    let request = RamReadRequest::get_resource_share_invitations(
        fixtures.scope.clone(),
        RamReadFilter::new(
            hartevo_aws_ram_resource_share_result_plugin::ResourceOwner::OtherAccounts,
        ),
        50,
    )
    .expect("invitation request");
    let page = AwsRamReadPage::new(
        &request,
        RamPageItems::Invitations(vec![InvitationMetadata {
            invitation_arn: fixtures.invitation.clone(),
            resource_share_arn: fixtures.share.clone(),
            sender_account: AwsAccountId::new(RAW_OTHER_ACCOUNT).expect("sender"),
            receiver_account: AwsAccountId::new(RAW_ACCOUNT).expect("receiver"),
            status: InvitationStatus::Pending,
            creation_time: 1_787_000_000,
            expiration_time: Some(1_787_100_000),
            association_revision: Revision::new(7).expect("association revision"),
        }]),
        None,
        384,
        Revision::new(7).expect("page association revision"),
        AWS_RAM_API_REVISION,
    )
    .expect("invitation page");
    let mut transport = FixtureAwsRamTransport::fixture();
    transport.push_response(Ok(page));
    let mut service = fixtures.service_with_fixture(transport);
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, RamEvidenceState::Pending);
    assert_eq!(proposal.evidence.invitations.len(), 1);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains(RAW_ACCOUNT));
    assert!(!serialized.contains(RAW_OTHER_ACCOUNT));
}

#[test]
fn partial_access_loss_stale_and_tamper_are_fail_closed() {
    let fixtures = Fixtures::new();
    let request = shares_request(&fixtures);

    let mut partial_transport = FixtureAwsRamTransport::fixture();
    let next = OpaquePageToken::new("opaque-next-ram").expect("next token");
    let page = AwsRamReadPage::new(
        &request,
        RamPageItems::ResourceShares(Vec::new()),
        Some(next),
        256,
        Revision::new(7).expect("association revision"),
        AWS_RAM_API_REVISION,
    )
    .expect("partial page");
    partial_transport.push_response(Ok(page));
    partial_transport.push_response(Err(TransportError::AccessLoss));
    let mut partial_service = fixtures.service_with_fixture(partial_transport);
    let partial = partial_service
        .propose(request.clone())
        .expect("partial proposal");
    assert_eq!(partial.state, RamEvidenceState::AccessLoss);
    assert!(!partial_service.verify(&partial).review_eligible);

    let mut stale_transport = FixtureAwsRamTransport::fixture();
    let stale_page = AwsRamReadPage::new(
        &request,
        RamPageItems::ResourceShares(Vec::new()),
        None,
        128,
        Revision::new(8).expect("stale revision"),
        AWS_RAM_API_REVISION,
    )
    .expect("stale page");
    stale_transport.push_response(Ok(stale_page));
    let mut stale_service = fixtures.service_with_fixture(stale_transport);
    let stale = stale_service.propose(request).expect("stale proposal");
    assert_eq!(stale.state, RamEvidenceState::Stale);
    assert!(!stale_service.verify(&stale).review_eligible);

    let mut tamper_transport = FixtureAwsRamTransport::fixture();
    let tamper_request = shares_request(&fixtures);
    tamper_transport.push_response(Ok(fixtures.shares_page(&tamper_request)));
    let mut tamper_service = fixtures.service_with_fixture(tamper_transport);
    let mut tampered = tamper_service.propose(tamper_request).expect("proposal");
    tampered.evidence.state = RamEvidenceState::Declined;
    let verification = tamper_service.verify(&tampered);
    assert!(!verification.valid);
    assert_eq!(verification.state, RamEvidenceState::Tamper);
}

#[test]
fn registration_is_reversible_and_revocation_closes_reads() {
    let fixtures = Fixtures::new();
    let request = shares_request(&fixtures);
    let mut transport = FixtureAwsRamTransport::fixture();
    transport.push_response(Ok(fixtures.shares_page(&request)));
    let mut service = fixtures.service_with_fixture(transport);
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.registration().status(),
        hartevo_aws_ram_resource_share_result_plugin::RegistrationStatus::Revoked
    );
    assert!(service.propose(request.clone()).is_err());
    service.restore_registration().expect("restore");
    assert!(service.is_active());
    let mut consumer = MissionAwsRamConsumer::new(service.scope());
    consumer
        .bind_registration(service.registration())
        .expect("bind");
    consumer.revoke().expect("consumer revoke");
    assert!(
        consumer
            .consume_evidence(&service.propose(request).expect("proposal").evidence)
            .is_err()
    );
}

#[test]
fn all_provider_provenance_modes_are_explicitly_non_native() {
    let fixtures = Fixtures::new();
    let request = shares_request(&fixtures);
    let mut recording = RecordingAwsRamTransport::default();
    recording.push_response(Ok(fixtures.shares_page(&request)));
    let provider = AwsRamProvider::new(recording).expect("recording provider");
    assert!(!provider.identity().connected);
    assert!(!provider.identity().native);
    assert!(!provider.identity().first_party);
}

#[allow(dead_code)]
fn _unused_type_coverage() {
    let _ = (AssociationStatus::Associated, ResourceRegionScope::Regional);
    let _ = PermissionMetadata {
        permission_arn: PermissionArn::new(RAW_PERMISSION_ARN).expect("permission"),
        version: 1,
        default_version: true,
        resource_type: ResourceType::new("ec2:subnet").expect("resource type"),
        customer_managed: false,
        association_revision: Revision::new(1).expect("revision"),
    };
    let _ = PrincipalMetadata {
        id: PrincipalId::new(RAW_PRINCIPAL).expect("principal"),
        resource_share_arn: ResourceShareArn::new(RAW_SHARE_ARN).expect("share"),
        external: true,
        creation_time: 1,
        last_updated_time: 2,
        association_revision: Revision::new(1).expect("revision"),
    };
    let _ = ResourceMetadata {
        arn: ResourceArn::new(RAW_RESOURCE_ARN).expect("resource"),
        resource_share_arn: ResourceShareArn::new(RAW_SHARE_ARN).expect("share"),
        resource_type: ResourceType::new("s3:accesspoint").expect("resource type"),
        resource_region_scope: ResourceRegionScope::All,
        status: AssociationStatus::Associated,
        resource_group_arn: None,
        creation_time: 1,
        last_updated_time: 2,
        association_revision: Revision::new(1).expect("revision"),
    };
    let _ = Digest::from_text("coverage");
}

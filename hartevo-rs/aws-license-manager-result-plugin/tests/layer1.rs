use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_license_manager_result_plugin as plugin;
use plugin::{
    AwsAccountId, AwsLicenseManagerProvider, AwsLicenseManagerScope, AwsLicenseManagerService,
    AwsLicenseManagerTransportError, AwsRegion, BlockedEnvTransport, Digest,
    GetLicenseConfigurationPage, GetLicenseConfigurationRequest, LicenseConfigurationId,
    LicenseConfigurationMetadata, LicenseConfigurationMetadataInput, LicenseConfigurationStatus,
    LicenseManagerDecisionState, LicenseType, ListLicenseConfigurationsPage,
    ListLicenseConfigurationsRequest, ListUsageForLicenseConfigurationPage,
    ManagedResourceIdentity, ManagedResourceStatus, MissionId, MissionIdentity, OpaquePageToken,
    PermissionSnapshot, ProjectId, ProjectIdentity, ProviderProvenance, RecordingTransport,
    ResourceType, Revision, SecretReference, UsageWindow, WorkProductId, WorkProductIdentity,
};

type Service = AwsLicenseManagerService<RecordingTransport>;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_SECRET: &str = "raw-sigv4-keyring-handle";
const RAW_CURSOR: &str = "raw-provider-pagination-token";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsLicenseManagerScope {
    let start = now() - Duration::hours(2);
    let end = now() + Duration::hours(22);
    AwsLicenseManagerScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        plugin::LicenseConfigurationIdentity::new(
            LicenseConfigurationId::new("lic-0123456789abcdef").expect("license configuration"),
            Some(
                "arn:aws:license-manager:us-east-1:123456789012:license-configuration:lic-0123456789abcdef",
            ),
        )
        .expect("configuration identity"),
        ManagedResourceIdentity::from_values(
            "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
            "EC2_INSTANCE",
        )
        .expect("managed resource"),
        UsageWindow::new(start, end).expect("usage window"),
        MissionIdentity::new(
            MissionId::new("mission-license-1").expect("mission id"),
            Revision::new(7).expect("mission revision"),
        )
        .expect("mission"),
        ProjectIdentity::new(
            ProjectId::new("project-license-1").expect("project id"),
            Revision::new(11).expect("project revision"),
        )
        .expect("project"),
        WorkProductIdentity::new(
            WorkProductId::new("work-product-license-1").expect("work product id"),
            Revision::new(13).expect("work product revision"),
        )
        .expect("work product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsLicenseManagerScope) -> SecretReference {
    SecretReference::sigv4(
        RAW_SECRET,
        scope,
        Revision::new(3).expect("secret revision"),
    )
    .expect("secret reference")
}

fn permissions() -> PermissionSnapshot {
    PermissionSnapshot::readonly(Revision::new(5).expect("permission revision"))
        .expect("permissions")
}

fn fixture_service() -> Service {
    let scope = scope();
    let provider = AwsLicenseManagerProvider::new(RecordingTransport::fixture(&scope, now()))
        .expect("fixture provider");
    Service::new(scope.clone(), secret(&scope), permissions(), provider).expect("service")
}

#[test]
fn contract_registration_and_capabilities_are_layer_one_only() {
    assert_eq!(plugin::contract_digest().as_str().len(), 64);
    assert_eq!(plugin::provider_digest().as_str().len(), 64);
    let service = fixture_service();
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.outcome_adoption);
    assert_eq!(capabilities.operations.len(), 3);
    assert!(service.registration().validate().is_ok());
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains(RAW_SECRET));
    assert!(!format!("{:?}", service.registration()).contains(RAW_SECRET));
}

#[test]
fn secret_and_cursor_are_opaque_and_raw_identifiers_are_redacted() {
    let scope = scope();
    let reference = secret(&scope);
    assert_eq!(
        serde_json::to_string(&reference).expect("secret JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{reference:?}").contains(RAW_SECRET));
    assert!(!reference.to_string().contains(RAW_SECRET));

    let cursor = OpaquePageToken::new(RAW_CURSOR).expect("cursor");
    assert_eq!(
        serde_json::to_string(&cursor).expect("cursor JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{cursor:?}").contains(RAW_CURSOR));
    let request = ListLicenseConfigurationsRequest::for_scope(&scope, 10).expect("request");
    let bound = request.next_page(cursor).expect("bound cursor");
    let encoded = serde_json::to_string(&bound).expect("request JSON");
    assert!(!encoded.contains(RAW_CURSOR));
    assert!(!encoded.contains("license-configuration:lic-0123456789abcdef"));
}

#[test]
fn fixture_read_propose_record_verify_consume_and_replay_are_fenced() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, plugin::EvidenceState::Complete);
    assert_eq!(proposal.evidence.list_pages, 1);
    assert_eq!(proposal.evidence.usage_pages, 1);
    assert_eq!(
        proposal
            .evidence
            .configuration
            .as_ref()
            .expect("configuration")
            .license_count,
        8
    );
    assert_eq!(proposal.evidence.usage.consumed_licenses, 1);
    assert_eq!(
        proposal.evidence.usage.quota_state,
        plugin::QuotaState::WithinLimit
    );
    assert!(proposal.evidence.is_review_eligible());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.can_be_adopted());
    proposal.validate_integrity().expect("proposal integrity");

    let consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(
        result.decision_state,
        LicenseManagerDecisionState::WithinLimit
    );
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.truth_authority);
    assert!(!result.outcome_adopted);

    let first = service.record(&proposal, "recording-key").expect("record");
    let replay = service.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.recording_digest, replay.recording_digest);
    assert!(service.verify(&proposal).valid);
    assert!(service.verify_record(&first).valid);
}

#[test]
fn quota_exceeded_is_recordable_but_never_review_eligible() {
    let scope = scope();
    let list_request =
        ListLicenseConfigurationsRequest::for_scope(&scope, 10).expect("list request");
    let get_request = GetLicenseConfigurationRequest::for_scope(&scope).expect("get request");
    let usage_request = plugin::ListUsageForLicenseConfigurationRequest::for_scope(&scope, 10)
        .expect("usage request");
    let configuration = LicenseConfigurationMetadata::new(
        &scope,
        LicenseConfigurationMetadataInput {
            identity: scope.license_configuration().clone(),
            license_type: LicenseType::LicenseIncluded,
            license_count: 1,
            license_count_hard_limit: true,
            status: LicenseConfigurationStatus::Active,
            resource_type: ResourceType::new("EC2_INSTANCE").expect("resource type"),
            discovery_timestamp: now(),
            license_rules: None,
        },
    )
    .expect("configuration");
    let usage = plugin::LicenseUsageItem::new(&scope, now(), 2, ManagedResourceStatus::Active)
        .expect("usage");
    let list_page = ListLicenseConfigurationsPage::new(
        &list_request,
        vec![configuration.clone()],
        None,
        512,
        plugin::AWS_LICENSE_MANAGER_PROVIDER_REVISION,
    )
    .expect("list page");
    let get_page = GetLicenseConfigurationPage::new(
        &get_request,
        configuration,
        512,
        plugin::AWS_LICENSE_MANAGER_PROVIDER_REVISION,
    )
    .expect("get page");
    let usage_page = ListUsageForLicenseConfigurationPage::new(
        &usage_request,
        vec![usage],
        None,
        512,
        plugin::AWS_LICENSE_MANAGER_PROVIDER_REVISION,
    )
    .expect("usage page");
    let mut transport = RecordingTransport::new();
    transport.push_list_response(Ok(list_page));
    transport.push_get_response(Ok(get_page));
    transport.push_usage_response(Ok(usage_page));
    let provider = AwsLicenseManagerProvider::new(transport).expect("provider");
    let mut service =
        Service::new(scope.clone(), secret(&scope), permissions(), provider).expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, plugin::EvidenceState::QuotaExceeded);
    assert_eq!(
        proposal.evidence.usage.quota_state,
        plugin::QuotaState::Exceeded
    );
    assert!(!service.verify(&proposal).valid);
    assert!(service.record(&proposal, "quota-record").is_ok());
}

#[test]
fn repeated_pagination_and_tamper_fail_closed() {
    let scope = scope();
    let first_request = ListLicenseConfigurationsRequest::for_scope(&scope, 1).expect("request");
    let configuration =
        LicenseConfigurationMetadata::fixture(&scope, now()).expect("configuration");
    let first_token = OpaquePageToken::new(RAW_CURSOR).expect("cursor");
    let first_page = ListLicenseConfigurationsPage::new(
        &first_request,
        vec![configuration.clone()],
        Some(first_token),
        512,
        plugin::AWS_LICENSE_MANAGER_PROVIDER_REVISION,
    )
    .expect("first page");
    let second_request = first_request
        .next_page(first_page.next_token.clone().expect("next token"))
        .expect("second request");
    let repeated_token =
        OpaquePageToken::for_request(RAW_CURSOR, &scope, &first_request.filter_digest, 3)
            .expect("repeated token");
    let second_page = ListLicenseConfigurationsPage::new(
        &second_request,
        vec![configuration],
        Some(repeated_token),
        512,
        plugin::AWS_LICENSE_MANAGER_PROVIDER_REVISION,
    )
    .expect("second page");
    let mut transport = RecordingTransport::new();
    transport.push_list_response(Ok(first_page));
    transport.push_list_response(Ok(second_page));
    let provider = AwsLicenseManagerProvider::new(transport).expect("provider");
    let mut service =
        Service::new(scope.clone(), secret(&scope), permissions(), provider).expect("service");
    let proposal = service
        .propose(service.request(1, 2, now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, plugin::EvidenceState::Drifted);
    assert!(!service.verify(&proposal).valid);

    let mut clean_service = fixture_service();
    let mut tampered = clean_service
        .propose(clean_service.default_request(now()).expect("request"))
        .expect("proposal");
    tampered.evidence.usage.consumed_licenses = 99;
    assert!(matches!(
        clean_service
            .consumer()
            .expect("consumer")
            .consume(&tampered),
        Err(plugin::AwsLicenseManagerError::TamperedEvidence)
    ));
}

#[test]
fn transport_failures_and_revocation_never_claim_connected_or_native() {
    let scope = scope();
    let blocked_provider = AwsLicenseManagerProvider::new(BlockedEnvTransport).expect("provider");
    let mut blocked_service = AwsLicenseManagerService::new(
        scope.clone(),
        secret(&scope),
        permissions(),
        blocked_provider,
    )
    .expect("service");
    let blocked = blocked_service
        .propose(blocked_service.default_request(now()).expect("request"))
        .expect("blocked evidence");
    assert_eq!(blocked.state, plugin::EvidenceState::AccessLoss);
    assert_eq!(blocked.evidence.provenance, ProviderProvenance::BlockedEnv);
    assert!(!blocked.connected);
    assert!(!blocked.native);
    assert!(!blocked.first_party);

    let mut service = fixture_service();
    service.revoke().expect("revoke");
    assert!(matches!(
        service.propose(service.default_request(now()).expect("request")),
        Err(plugin::AwsLicenseManagerError::RegistrationInactive)
    ));
    service.restore_registration().expect("restore");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("restored proposal");
    assert!(!proposal.native);

    let _ = AwsLicenseManagerTransportError::ServerError { status: 500 };
    let _ = Digest::zero();
}

#[test]
fn documented_provider_statuses_are_typed_fail_closed_states() {
    let cases = [
        (
            AwsLicenseManagerTransportError::BadRequest,
            plugin::EvidenceState::Drifted,
        ),
        (
            AwsLicenseManagerTransportError::Unauthorized,
            plugin::EvidenceState::AccessLoss,
        ),
        (
            AwsLicenseManagerTransportError::Forbidden,
            plugin::EvidenceState::AccessLoss,
        ),
        (
            AwsLicenseManagerTransportError::NotFound,
            plugin::EvidenceState::NotFound,
        ),
        (
            AwsLicenseManagerTransportError::RateLimited {
                retry_after_seconds: Some(3),
            },
            plugin::EvidenceState::Throttled,
        ),
        (
            AwsLicenseManagerTransportError::ServerError { status: 500 },
            plugin::EvidenceState::ProviderUnknown,
        ),
        (
            AwsLicenseManagerTransportError::Timeout,
            plugin::EvidenceState::ProviderUnknown,
        ),
    ];
    for (error, expected_state) in cases {
        let scope = scope();
        let mut transport = RecordingTransport::new();
        transport.push_list_response(Err(error));
        let provider = AwsLicenseManagerProvider::new(transport).expect("provider");
        let mut service =
            Service::new(scope.clone(), secret(&scope), permissions(), provider).expect("service");
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("typed failure proposal");
        assert_eq!(proposal.state, expected_state);
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!proposal.first_party);
        assert!(!proposal.can_be_adopted());
    }
}

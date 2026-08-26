use hartevo_aws_security_hub_finding_result_plugin as plugin;
use plugin::{
    AWS_SECURITY_HUB_CONTRACT_VERSION, AWS_SECURITY_HUB_IAM_PERMISSION,
    AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT, AWS_SECURITY_HUB_PROVIDER_REVISION, AwsAccountId,
    AwsRegion, AwsSecurityHubFindingService, AwsSecurityHubProvider, AwsSecurityHubScope,
    BlockedEnvAwsSecurityHubTransport, Digest, FindingFilter, FindingResourceMetadata,
    FindingSeverity, FindingStatus, FindingsReadRequest, GetFindingsPage, GetFindingsRequest,
    MissionAwsSecurityHubConsumer, OpaquePageToken, ProductId, ProviderProvenance,
    RecordingAwsSecurityHubTransport, ResourceId, SecretReference, SecurityHubFinding,
    SigV4SecretReference, SourceId, WorkProductId,
};

fn scope() -> AwsSecurityHubScope {
    AwsSecurityHubScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        ProductId::new("arn:aws:securityhub:us-east-1::product/provider/product").expect("product"),
        SourceId::new("provider/source").expect("source"),
        plugin::FindingId::new("finding-1").expect("finding"),
        ResourceId::new("arn:aws:s3:::example").expect("resource"),
        plugin::ProjectId::new("project-1").expect("project"),
        plugin::MissionId::new("mission-1").expect("mission"),
        WorkProductId::new("work-product-1").expect("work product"),
    )
}

fn secret(scope: &AwsSecurityHubScope) -> SecretReference {
    SigV4SecretReference::new("raw-secret-reference-that-must-not-leak", scope, 7)
        .expect("secret reference")
}

fn permission_digest() -> Digest {
    Digest::from_text(AWS_SECURITY_HUB_IAM_PERMISSION)
}

fn finding(scope: &AwsSecurityHubScope, severity: FindingSeverity) -> SecurityHubFinding {
    let resource = FindingResourceMetadata::new(
        scope.resource_id.clone(),
        "AwsS3Bucket",
        scope.account_id.clone(),
        scope.region.clone(),
    )
    .expect("resource metadata");
    SecurityHubFinding::new(
        scope.finding_id.clone(),
        scope.product_arn.clone(),
        scope.source_id.clone(),
        severity,
        FindingStatus::New,
        resource,
    )
    .expect("finding")
}

fn provider_with_page(
    scope: &AwsSecurityHubScope,
    read_request: &FindingsReadRequest,
    page: GetFindingsPage,
) -> (
    AwsSecurityHubProvider<RecordingAwsSecurityHubTransport>,
    plugin::AwsSecurityHubRegistration,
) {
    let transport = RecordingAwsSecurityHubTransport::new([Ok(page)]);
    let mut provider = AwsSecurityHubProvider::new(
        transport,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let registration = provider
        .register_scope(scope.clone(), secret(scope), permission_digest())
        .expect("registration");
    let first_page = read_request.first_page(scope).expect("first page");
    assert_eq!(first_page.api(), read_request.api());
    (provider, registration)
}

#[test]
fn contract_and_runtime_definition_are_layer1_read_only() {
    plugin::validate_contract_document().expect("contract");
    assert_eq!(plugin::contract_digest().as_str().len(), 64);

    let service = AwsSecurityHubFindingService::new();
    service.validate().expect("service");
    assert!(service.read_only());
    assert!(!service.native_connected());
    assert!(
        service
            .capabilities()
            .iter()
            .all(|capability| capability.read_only
                && !capability.mutates_provider
                && !capability.native_evidence)
    );

    let runtime_scope = hartevo_plugin_runtime::PluginScope::new(
        hartevo_plugin_runtime::ProjectId::new("project.security").expect("runtime project"),
        hartevo_plugin_runtime::MissionId::new("mission.security").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    let definition = plugin::plugin_definition(runtime_scope).expect("definition");
    definition.validate().expect("definition validates");
}

#[test]
fn sigv4_reference_is_opaque_and_normalized_findings_are_redacted() {
    let scope = scope();
    let reference = secret(&scope);
    let debug = format!("{reference:?}");
    let display = reference.to_string();
    assert!(!debug.contains("raw-secret-reference"));
    assert!(!display.contains("raw-secret-reference"));
    assert_eq!(reference.scope_digest(), &scope.digest());
    assert_eq!(reference.credential_revision().get(), 7);

    let finding = finding(&scope, FindingSeverity::High);
    assert_eq!(finding.severity, FindingSeverity::High);
    assert_eq!(finding.status, FindingStatus::New);
    assert!(!finding.redaction.raw_provider_payload_retained);
    assert!(
        finding
            .redaction
            .redacted_fields
            .contains(&plugin::RedactedFindingField::RawProviderPayload)
    );
    assert!(!format!("{finding:?}").contains("description"));
}

#[test]
fn get_findings_read_propose_record_verify_is_bound_to_scope_and_digests() {
    let scope = scope();
    let filter = FindingFilter::all()
        .with_severity(FindingSeverity::High)
        .expect("filter");
    let read_request = FindingsReadRequest::new(filter, 10, 4, 10).expect("read request");
    let first_request = read_request.first_page(&scope).expect("request");
    let page = GetFindingsPage::new(
        &first_request,
        vec![finding(&scope, FindingSeverity::High)],
        None,
        false,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("page");
    let (mut provider, registration) = provider_with_page(&scope, &read_request, page);
    let consumer = MissionAwsSecurityHubConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");

    let result = consumer.read(&mut provider, &read_request).expect("read");
    assert_eq!(result.evidence.status, plugin::EvidenceStatus::Complete);
    assert_eq!(result.evidence.findings.len(), 1);
    assert_eq!(
        result.evidence.provider_revision,
        AWS_SECURITY_HUB_PROVIDER_REVISION
    );
    assert_eq!(
        result.evidence.contract_version,
        AWS_SECURITY_HUB_CONTRACT_VERSION
    );
    assert_eq!(
        result.evidence.plugin_version,
        AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT
    );
    assert_eq!(result.evidence.permission_digest, permission_digest());
    assert_eq!(result.evidence.scope_digest, scope.digest());
    result.validate(&scope).expect("result validates");

    let service = AwsSecurityHubFindingService::new();
    let proposal = service.propose(result.evidence.clone()).expect("proposal");
    assert!(proposal.read_only);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.outcome_authority);
    let record = service.record(&proposal).expect("record");
    assert!(!record.durable);
    assert!(!record.verified);
    assert!(!record.adopted);
    let verification = service.verify(&record, &result.evidence).expect("verify");
    assert_eq!(
        verification.status,
        plugin::VerificationStatus::VerifiedReadOnly
    );
    assert!(verification.accepted);
    assert!(!verification.independent_live_readback);
    assert!(!verification.native);
}

#[test]
fn get_findings_v2_uses_the_same_bound_permission_and_non_native_transport() {
    let scope = scope();
    let read_request = FindingsReadRequest::v2(FindingFilter::all(), 5, 2, 5).expect("request");
    let first_request = read_request.first_page(&scope).expect("first page");
    assert_eq!(first_request.api(), plugin::GetFindingsApi::GetFindingsV2);
    let page = GetFindingsPage::new(
        &first_request,
        vec![finding(&scope, FindingSeverity::Critical)],
        None,
        false,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("page");
    let (mut provider, registration) = provider_with_page(&scope, &read_request, page);
    let consumer = MissionAwsSecurityHubConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");
    let result = consumer
        .read(&mut provider, &read_request)
        .expect("v2 read");
    assert_eq!(
        result.evidence.findings[0].severity,
        FindingSeverity::Critical
    );
    assert_eq!(
        provider.transport().requests()[0].api,
        plugin::GetFindingsApi::GetFindingsV2
    );
    assert_eq!(provider.provenance(), ProviderProvenance::Recording);
    assert_eq!(
        plugin::provider_digest(),
        provider.provider_digest().clone()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn pagination_is_filter_and_page_bound_and_repeated_tokens_fail_closed() {
    let scope = scope();
    let read_request = FindingsReadRequest::new(FindingFilter::all(), 2, 4, 10).expect("request");
    let first_request = read_request.first_page(&scope).expect("first page");
    let token = OpaquePageToken::new("provider-page-2").expect("token");
    let first_page = GetFindingsPage::new(
        &first_request,
        vec![finding(&scope, FindingSeverity::Low)],
        Some(token.clone()),
        false,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("first page");
    let second_request = first_request
        .next_page(token.clone())
        .expect("second request");
    let second_page = GetFindingsPage::new(
        &second_request,
        vec![finding(&scope, FindingSeverity::Medium)],
        None,
        false,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("second page");
    let transport = RecordingAwsSecurityHubTransport::new([Ok(first_page), Ok(second_page)]);
    let mut provider = AwsSecurityHubProvider::new(
        transport,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let registration = provider
        .register_scope(scope.clone(), secret(&scope), permission_digest())
        .expect("registration");
    let consumer = MissionAwsSecurityHubConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");
    let result = consumer
        .read(&mut provider, &read_request)
        .expect("paged read");
    assert_eq!(result.evidence.findings.len(), 2);
    assert_eq!(result.evidence.page_bindings.len(), 2);
    assert_eq!(provider.transport().call_count(), 2);
    assert_eq!(result.evidence.status, plugin::EvidenceStatus::Complete);

    let wrong_filter = FindingFilter::all()
        .with_severity(FindingSeverity::High)
        .expect("filter");
    let wrong_request = GetFindingsRequest::new(&scope, wrong_filter, 2).expect("wrong request");
    let mismatched_page = GetFindingsPage::new(
        &wrong_request,
        Vec::new(),
        None,
        false,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("mismatched page");
    let mut mismatched_provider = AwsSecurityHubProvider::new(
        RecordingAwsSecurityHubTransport::new([Ok(mismatched_page)]),
        AWS_SECURITY_HUB_PROVIDER_REVISION,
        ProviderProvenance::Recording,
    )
    .expect("provider");
    mismatched_provider
        .register_scope(scope.clone(), secret(&scope), permission_digest())
        .expect("registration");
    assert_eq!(
        mismatched_provider
            .get_findings(&first_request)
            .expect_err("page binding drift")
            .to_string(),
        "the finding page binding drifted"
    );

    let repeated_first = GetFindingsPage::new(
        &first_request,
        Vec::new(),
        Some(token.clone()),
        false,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("repeated first");
    let repeated_second_request = first_request
        .next_page(token.clone())
        .expect("repeated second");
    let repeated_second = GetFindingsPage::new(
        &repeated_second_request,
        Vec::new(),
        Some(token),
        false,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("repeated second");
    let mut repeated_provider = AwsSecurityHubProvider::new(
        RecordingAwsSecurityHubTransport::new([Ok(repeated_first), Ok(repeated_second)]),
        AWS_SECURITY_HUB_PROVIDER_REVISION,
        ProviderProvenance::Loopback,
    )
    .expect("provider");
    let registration = repeated_provider
        .register_scope(scope.clone(), secret(&scope), permission_digest())
        .expect("registration");
    let repeated_consumer =
        MissionAwsSecurityHubConsumer::with_registration(scope, registration).expect("consumer");
    assert!(matches!(
        repeated_consumer.read(&mut repeated_provider, &read_request),
        Err(plugin::AwsSecurityHubError::PageLoop)
    ));
}

#[test]
fn tamper_and_revocation_are_adversarial_fail_closed_cases() {
    let scope = scope();
    let read_request = FindingsReadRequest::new(FindingFilter::all(), 10, 2, 10).expect("request");
    let first_request = read_request.first_page(&scope).expect("first page");
    let page = GetFindingsPage::new(
        &first_request,
        vec![finding(&scope, FindingSeverity::Medium)],
        None,
        false,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("page");
    let (mut provider, registration) = provider_with_page(&scope, &read_request, page);
    let consumer = MissionAwsSecurityHubConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");
    let result = consumer.read(&mut provider, &read_request).expect("read");
    let mut tampered = result.evidence.clone();
    tampered.findings[0].status = FindingStatus::Resolved;
    assert!(matches!(
        consumer.consume_evidence(tampered),
        Err(plugin::AwsSecurityHubError::TamperedEvidence)
    ));

    provider
        .revoke_registration(plugin::Revision::new(8).expect("revision"))
        .expect("revoke");
    assert!(matches!(
        consumer.read(&mut provider, &read_request),
        Err(plugin::AwsSecurityHubError::RegistrationRevoked)
    ));
}

#[test]
fn partial_and_blocked_env_evidence_never_becomes_complete_or_native() {
    let scope = scope();
    let read_request = FindingsReadRequest::new(FindingFilter::all(), 10, 2, 10).expect("request");
    let first_request = read_request.first_page(&scope).expect("first page");
    let partial_page = GetFindingsPage::new(
        &first_request,
        vec![finding(&scope, FindingSeverity::Low)],
        None,
        true,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
    )
    .expect("partial page");
    let (mut partial_provider, registration) =
        provider_with_page(&scope, &read_request, partial_page);
    let partial_consumer =
        MissionAwsSecurityHubConsumer::with_registration(scope.clone(), registration)
            .expect("consumer");
    let partial = partial_consumer
        .read(&mut partial_provider, &read_request)
        .expect("partial evidence");
    assert_eq!(partial.evidence.status, plugin::EvidenceStatus::Partial);
    let service = AwsSecurityHubFindingService::new();
    let partial_proposal = service.propose(partial.evidence.clone()).expect("proposal");
    let partial_record = service.record(&partial_proposal).expect("record");
    let partial_verification = service
        .verify(&partial_record, &partial.evidence)
        .expect("verify");
    assert_eq!(
        partial_verification.status,
        plugin::VerificationStatus::PartialEvidence
    );
    assert!(!partial_verification.accepted);
    assert!(!partial_verification.native);

    let mut blocked_provider = AwsSecurityHubProvider::new(
        BlockedEnvAwsSecurityHubTransport,
        AWS_SECURITY_HUB_PROVIDER_REVISION,
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let blocked_registration = blocked_provider
        .register_scope(scope.clone(), secret(&scope), permission_digest())
        .expect("registration");
    let blocked_consumer =
        MissionAwsSecurityHubConsumer::with_registration(scope, blocked_registration)
            .expect("consumer");
    let blocked = blocked_consumer
        .read(&mut blocked_provider, &read_request)
        .expect("blocked evidence");
    assert_eq!(blocked.evidence.status, plugin::EvidenceStatus::AccessLost);
    assert_eq!(blocked.evidence.provenance, ProviderProvenance::BlockedEnv);
    assert!(blocked.evidence.access_loss.is_some());
    assert!(!blocked.observation.native);
    assert!(!blocked.observation.connected);
}

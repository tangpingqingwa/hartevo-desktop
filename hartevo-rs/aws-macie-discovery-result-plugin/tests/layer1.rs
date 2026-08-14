use hartevo_aws_macie_discovery_result_plugin as plugin;
use plugin::{
    AccessLossKind, AwsAccountId, AwsRegion, BlockedEnvMacieTransport, ClassificationMetadata,
    ClassificationScope, ClassificationStatus, ConsentId, ConsentScope, Digest, EvidenceStatus,
    FindingFilter, FindingId, FindingIdAllowlist, GetFindingsPage, GetFindingsRequest,
    ListFindingsPage, MacieDiscoveryResultService, MacieDiscoveryScope, MacieFinding,
    MacieFindingCategory, MacieFindingStatus, MacieReadRequest, MacieResourceScope,
    MacieResourceType, MacieSeverity, MacieTransportError, MissionMacieDiscoveryConsumer,
    OpaquePageToken, PolicyId, PolicyMetadata, PolicyScope, ProviderProvenance, Revision,
    SecretReference, SigV4SecretReference, Timestamp,
};

fn scope() -> MacieDiscoveryScope {
    let account = AwsAccountId::new("123456789012").expect("account");
    let region = AwsRegion::new("us-east-1").expect("region");
    let resource = MacieResourceScope::new(
        plugin::ResourceId::new("arn:aws:s3:::macie-fixture-bucket").expect("resource"),
        MacieResourceType::S3Bucket,
        account.clone(),
        region.clone(),
    );
    MacieDiscoveryScope::new(
        account,
        region,
        FindingId::new("finding-1").expect("finding"),
        resource,
        ClassificationScope::new(MacieFindingCategory::Classification),
        PolicyScope::new(
            PolicyId::new("policy-1").expect("policy"),
            Revision::new(1).expect("revision"),
        ),
        plugin::ProjectId::new("project-1").expect("project"),
        plugin::MissionId::new("mission-1").expect("mission"),
        ConsentScope::new(
            ConsentId::new("consent-1").expect("consent"),
            Revision::new(1).expect("consent revision"),
        ),
    )
}

fn secret(scope: &MacieDiscoveryScope) -> SecretReference {
    SigV4SecretReference::new("raw-sigv4-handle-must-not-leak", scope, 7).expect("secret")
}

fn classification() -> ClassificationMetadata {
    ClassificationMetadata::new(
        MacieFindingCategory::Classification,
        3,
        ClassificationStatus::Complete,
        false,
    )
    .expect("classification")
    .with_type_count(
        plugin::ClassificationTypeCount::new(Digest::from_text("sensitive-data-type-email"), 3)
            .expect("type count"),
    )
    .expect("classification type")
}

fn finding(scope: &MacieDiscoveryScope, lifecycle: MacieFindingStatus) -> MacieFinding {
    let policy = PolicyMetadata::new(&scope.policy, MacieFindingCategory::Classification);
    MacieFinding::new(
        scope,
        MacieSeverity::High,
        lifecycle,
        classification(),
        policy,
        Timestamp::new("2026-08-15T01:02:03Z").expect("created"),
        Timestamp::new("2026-08-15T01:03:04Z").expect("updated"),
    )
    .expect("finding")
}

#[test]
fn contract_and_runtime_definition_are_layer1_read_only() {
    plugin::validate_contract_document().expect("contract");
    assert_eq!(plugin::contract_digest().as_str().len(), 64);

    let service = MacieDiscoveryResultService::new();
    service.validate().expect("service");
    assert!(service.read_only());
    assert!(!service.native_connected());
    assert!(!service.first_party());
    assert!(service.capabilities().iter().all(|capability| {
        capability.read_only
            && !capability.mutates_provider
            && !capability.native_evidence
            && !capability.connected
            && !capability.first_party
    }));

    let runtime_scope = hartevo_plugin_runtime::PluginScope::new(
        hartevo_plugin_runtime::ProjectId::new("project.macie").expect("runtime project"),
        hartevo_plugin_runtime::MissionId::new("mission.macie").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    plugin::plugin_definition(runtime_scope)
        .expect("definition")
        .validate()
        .expect("definition validates");
}

#[test]
fn secret_reference_is_opaque_and_projection_is_redacted() {
    let scope = scope();
    let reference = secret(&scope);
    let debug = format!("{reference:?}");
    let display = reference.to_string();
    assert!(!debug.contains("raw-sigv4-handle"));
    assert!(!display.contains("raw-sigv4-handle"));
    assert_eq!(reference.scope_digest(), &scope.digest());
    assert_eq!(reference.credential_revision().get(), 7);

    let finding = finding(&scope, MacieFindingStatus::New);
    let encoded = serde_json::to_string(&finding).expect("finding serializes");
    assert!(!encoded.contains("detailed-results-location"));
    assert!(!encoded.contains("object-path-value"));
    assert!(!encoded.contains("raw-pii-value"));
    assert!(!finding.redaction.raw_pii_retained);
    assert!(!finding.redaction.raw_object_keys_retained);
    assert!(!finding.redaction.raw_object_paths_retained);
    assert!(!finding.redaction.raw_provider_payload_retained);
    finding.validate().expect("redacted finding validates");
}

#[test]
fn list_then_allowlisted_get_is_bound_to_scope_and_all_required_digests() {
    let scope = scope();
    let read_request =
        MacieReadRequest::new(FindingFilter::all(), 10, 4, 10).expect("read request");
    let list_request = read_request.first_list_page(&scope).expect("list request");
    let allowlist = FindingIdAllowlist::for_get(vec![scope.finding_id.clone()]).expect("allowlist");
    let list_page = ListFindingsPage::new(
        &list_request,
        allowlist.clone(),
        None,
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("list page");
    let get_request =
        GetFindingsRequest::new(&scope, &list_request, allowlist).expect("get request");
    let get_page = GetFindingsPage::new(
        &get_request,
        vec![finding(&scope, MacieFindingStatus::Open)],
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("get page");
    let transport = plugin::RecordingMacieTransport::new([Ok(list_page)], [Ok(get_page)]);
    let mut provider = plugin::MacieProvider::new(
        transport,
        plugin::AWS_MACIE_PROVIDER_REVISION,
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let registration = provider
        .register_scope(scope.clone(), secret(&scope))
        .expect("registration");
    let consumer = MissionMacieDiscoveryConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");

    let result = consumer.read(&mut provider, &read_request).expect("read");
    result.validate(&scope).expect("read validates");
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.findings.len(), 1);
    assert_eq!(result.evidence.list_page_bindings.len(), 1);
    assert_eq!(result.evidence.get_page_bindings.len(), 1);
    assert_eq!(result.evidence.scope_digest, scope.digest());
    assert_eq!(result.evidence.permission_digest, scope.permission_digest);
    assert_eq!(
        result.evidence.provider_revision,
        plugin::AWS_MACIE_PROVIDER_REVISION
    );
    assert_eq!(
        result.evidence.contract_version,
        plugin::AWS_MACIE_CONTRACT_VERSION
    );
    assert_eq!(
        result.evidence.plugin_version,
        plugin::AWS_MACIE_PLUGIN_VERSION_TEXT
    );
    assert!(!result.observation.connected);
    assert!(!result.observation.native);
    assert!(!result.observation.first_party);

    let service = MacieDiscoveryResultService::new();
    let proposal = service.propose(result.evidence.clone()).expect("proposal");
    assert!(proposal.read_only);
    assert!(proposal.proposal_only);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.truth_authority);
    assert!(!proposal.consent_authority);
    assert!(!proposal.effect_authority);
    assert!(!proposal.receipt_authority);
    assert!(!proposal.verification_authority);
    assert!(!proposal.outcome_authority);
    assert!(!proposal.adopted);
    let record = service.record(&proposal).expect("record");
    assert!(!record.durable);
    assert!(!record.verified);
    assert!(!record.adopted);
    let verification = service
        .verify(&record, &result.evidence)
        .expect("verification");
    assert_eq!(
        verification.status,
        plugin::VerificationStatus::VerifiedReadOnly
    );
    assert!(verification.accepted);
    assert!(!verification.independent_live_readback);
    assert!(!verification.connected);
    assert!(!verification.native);
    assert!(!verification.first_party);
    assert!(!verification.verification_authority);
    assert!(!verification.outcome_authority);
}

#[test]
fn pagination_is_opaque_and_repeated_tokens_fail_closed() {
    let scope = scope();
    let read_request = MacieReadRequest::new(FindingFilter::all(), 10, 4, 10).expect("request");
    let first = read_request.first_list_page(&scope).expect("first");
    let token = OpaquePageToken::new("provider-next-token").expect("token");
    let first_page = ListFindingsPage::new(
        &first,
        FindingIdAllowlist::empty(),
        Some(token.clone()),
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("first page");
    let second = first.next_page(token.clone()).expect("second");
    let second_page = ListFindingsPage::new(
        &second,
        FindingIdAllowlist::empty(),
        None,
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("second page");
    let mut provider = plugin::MacieProvider::new(
        plugin::RecordingMacieTransport::new([Ok(first_page), Ok(second_page)], []),
        plugin::AWS_MACIE_PROVIDER_REVISION,
        ProviderProvenance::Loopback,
    )
    .expect("provider");
    let registration = provider
        .register_scope(scope.clone(), secret(&scope))
        .expect("registration");
    let consumer = MissionMacieDiscoveryConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");
    let result = consumer
        .read(&mut provider, &read_request)
        .expect("paged read");
    assert_eq!(result.evidence.list_page_bindings.len(), 2);
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);

    let repeat_first = ListFindingsPage::new(
        &first,
        FindingIdAllowlist::empty(),
        Some(token.clone()),
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("repeat first");
    let repeat_second = ListFindingsPage::new(
        &second,
        FindingIdAllowlist::empty(),
        Some(token),
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("repeat second");
    let mut repeated_provider = plugin::MacieProvider::new(
        plugin::RecordingMacieTransport::new([Ok(repeat_first), Ok(repeat_second)], []),
        plugin::AWS_MACIE_PROVIDER_REVISION,
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let repeated_registration = repeated_provider
        .register_scope(scope.clone(), secret(&scope))
        .expect("registration");
    let repeated_consumer =
        MissionMacieDiscoveryConsumer::with_registration(scope, repeated_registration)
            .expect("consumer");
    assert!(matches!(
        repeated_consumer.read(&mut repeated_provider, &read_request),
        Err(plugin::MacieDiscoveryResultError::PageLoop)
    ));
}

#[test]
fn blocked_env_access_loss_is_non_native_and_provider_unknown_is_explicit() {
    let scope = scope();
    let read_request = MacieReadRequest::new(FindingFilter::all(), 10, 2, 10).expect("request");
    let mut blocked_provider = plugin::MacieProvider::new(
        BlockedEnvMacieTransport,
        plugin::AWS_MACIE_PROVIDER_REVISION,
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let registration = blocked_provider
        .register_scope(scope.clone(), secret(&scope))
        .expect("registration");
    let blocked_consumer =
        MissionMacieDiscoveryConsumer::with_registration(scope.clone(), registration)
            .expect("consumer");
    let blocked = blocked_consumer
        .read(&mut blocked_provider, &read_request)
        .expect("blocked evidence");
    assert_eq!(blocked.evidence.status, EvidenceStatus::AccessLost);
    assert_eq!(blocked.evidence.provenance, ProviderProvenance::BlockedEnv);
    assert_eq!(
        blocked.evidence.access_loss.as_ref().expect("loss").kind,
        AccessLossKind::BlockedEnv
    );
    assert!(!blocked.observation.connected);
    assert!(!blocked.observation.native);
    assert!(!blocked.observation.first_party);

    let list_request = read_request.first_list_page(&scope).expect("list request");
    let unknown_transport =
        plugin::RecordingMacieTransport::new([Err(MacieTransportError::ProviderUnknown)], []);
    let mut unknown_provider = plugin::MacieProvider::new(
        unknown_transport,
        plugin::AWS_MACIE_PROVIDER_REVISION,
        ProviderProvenance::ProviderUnknown,
    )
    .expect("unknown provider");
    let unknown_registration = unknown_provider
        .register_scope(scope.clone(), secret(&scope))
        .expect("unknown registration");
    let unknown_consumer =
        MissionMacieDiscoveryConsumer::with_registration(scope, unknown_registration)
            .expect("unknown consumer");
    let unknown_request =
        MacieReadRequest::new(list_request.filter().clone(), 10, 2, 10).expect("unknown request");
    let unknown = unknown_consumer
        .read(&mut unknown_provider, &unknown_request)
        .expect("unknown evidence");
    assert_eq!(unknown.evidence.status, EvidenceStatus::ProviderUnknown);
    assert_eq!(
        unknown.evidence.provenance,
        ProviderProvenance::ProviderUnknown
    );
    assert!(!unknown.observation.connected);
    assert!(!unknown.observation.native);
    assert!(!unknown.observation.first_party);
}

#[test]
fn tamper_and_revocation_fail_closed() {
    let scope = scope();
    let read_request = MacieReadRequest::new(FindingFilter::all(), 10, 2, 10).expect("request");
    let list_request = read_request.first_list_page(&scope).expect("list request");
    let allowlist = FindingIdAllowlist::for_get(vec![scope.finding_id.clone()]).expect("allowlist");
    let list_page = ListFindingsPage::new(
        &list_request,
        allowlist.clone(),
        None,
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("list page");
    let get_request =
        GetFindingsRequest::new(&scope, &list_request, allowlist).expect("get request");
    let get_page = GetFindingsPage::new(
        &get_request,
        vec![finding(&scope, MacieFindingStatus::Updated)],
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("get page");
    let mut provider = plugin::MacieProvider::new(
        plugin::RecordingMacieTransport::new([Ok(list_page)], [Ok(get_page)]),
        plugin::AWS_MACIE_PROVIDER_REVISION,
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let registration = provider
        .register_scope(scope.clone(), secret(&scope))
        .expect("registration");
    let consumer = MissionMacieDiscoveryConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");
    let result = consumer.read(&mut provider, &read_request).expect("read");
    let mut tampered = result.evidence.clone();
    tampered.findings[0].lifecycle = MacieFindingStatus::Archived;
    assert!(matches!(
        MacieDiscoveryResultService::new().propose(tampered),
        Err(plugin::MacieDiscoveryResultError::TamperedEvidence)
    ));

    provider
        .revoke_registration(Revision::new(2).expect("revoke revision"))
        .expect("revoke");
    assert!(matches!(
        consumer.read(&mut provider, &read_request),
        Err(plugin::MacieDiscoveryResultError::RegistrationRevoked)
    ));
}

#[test]
fn forbidden_path_and_allowlist_drift_are_rejected() {
    assert!(plugin::ResourceId::new("arn:aws:s3:::bucket/object.txt").is_err());
    assert!(
        FindingIdAllowlist::for_get(vec![
            FindingId::new("same").expect("id"),
            FindingId::new("same").expect("id"),
        ])
        .is_err()
    );

    let scope = scope();
    let request = MacieReadRequest::new(FindingFilter::all(), 10, 1, 10).expect("request");
    let list_request = request.first_list_page(&scope).expect("list request");
    let out_of_scope = FindingIdAllowlist::new(vec![
        FindingId::new("finding-1").expect("finding"),
        FindingId::new("finding-2").expect("finding"),
    ])
    .expect("allowlist");
    let page = ListFindingsPage::new(
        &list_request,
        out_of_scope,
        None,
        false,
        plugin::AWS_MACIE_PROVIDER_REVISION,
    )
    .expect("page");
    let mut provider = plugin::MacieProvider::new(
        plugin::RecordingMacieTransport::new([Ok(page)], []),
        plugin::AWS_MACIE_PROVIDER_REVISION,
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    provider
        .register_scope(scope.clone(), secret(&scope))
        .expect("registration");
    let consumer = MissionMacieDiscoveryConsumer::with_registration(
        scope,
        provider.registration().expect("registration").clone(),
    )
    .expect("consumer");
    assert!(matches!(
        consumer.read(&mut provider, &request),
        Err(plugin::MacieDiscoveryResultError::FindingOutOfScope)
    ));
}

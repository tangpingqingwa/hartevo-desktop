use chrono::{DateTime, TimeZone, Utc};
use hartevo_plugin_runtime::{
    MissionId as RuntimeMissionId, PluginRuntime, PluginScope, ProjectId as RuntimeProjectId,
};

use hartevo_gcp_security_command_center_result_plugin::{
    AdoptionAvailability, BlockedEnvGcpSecurityCenterTransport, Category, Digest,
    EvidenceProjection, FindingFilter, FindingRecord, FindingSeverity, FindingState,
    FindingsGroupRequest, FindingsGroupResponse, FindingsListRequest, FindingsListResponse,
    GCP_SECURITY_CENTER_RESULT_CONTRACT_JSON, GCP_SECURITY_CENTER_RESULT_CONTRACT_VERSION,
    GCP_SECURITY_CENTER_RESULT_PROVIDER_ID, GCP_SECURITY_CENTER_RESULT_SCHEMA_VERSION,
    GCP_SECURITY_CENTER_RESULT_SERVICE_ID, GcpSecurityCenterError, GcpSecurityCenterProvider,
    GcpSecurityCenterScope, GcpSecurityCenterScopeInput, GcpSecurityCenterService, GroupBy,
    GroupFindingBucket, GroupKey, HartevoProjectId, Layer1Authority, Location,
    MISSION_GCP_SECURITY_CENTER_RESULT_CONSUMER_ID, MissionGcpSecurityCenterConsumer, MissionId,
    MissionResultState, MissionScope, OpaquePageToken, OrganizationId, PageBinding,
    PermissionSnapshot, ProjectScope, ProviderRevision, RecordingGcpSecurityCenterTransport,
    RequestBounds, ResourceName, Revision, SecretKind, SecretReference, SecurityCenterTarget,
    SourceId, TransportError, TransportProvenance, WorkProductId, WorkProductScope,
    contract_digest, plugin_definition,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const PROVIDER_REVISION: &str = "security-center-v1-r1";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope(include_group: bool) -> GcpSecurityCenterScope {
    let revision = Revision::new(3).expect("permission revision");
    GcpSecurityCenterScope::new(GcpSecurityCenterScopeInput {
        target: SecurityCenterTarget::Organization(
            OrganizationId::new("org-1").expect("organization"),
        ),
        source_id: SourceId::new("source-1").expect("source"),
        location: Location::new("global").expect("location"),
        finding_id: None,
        resource_name: None,
        project: ProjectScope::new(
            HartevoProjectId::new("hartevo-project-1").expect("Hartevo Project"),
            Revision::new(4).expect("Project revision"),
        ),
        mission: MissionScope::new(
            MissionId::new("mission-1").expect("Mission"),
            Revision::new(5).expect("Mission revision"),
        ),
        work_product: WorkProductScope::new(
            WorkProductId::new("work-product-1").expect("Work Product"),
            Revision::new(6).expect("Work Product revision"),
        ),
        permissions: PermissionSnapshot::least_privilege(revision, include_group)
            .expect("permissions"),
    })
    .expect("scope")
}

fn secret() -> SecretReference {
    SecretReference::oauth("host/oauth/security-center", 7).expect("opaque secret")
}

fn finding(id: &str, severity: FindingSeverity) -> FindingRecord {
    FindingRecord::new(
        hartevo_gcp_security_command_center_result_plugin::FindingId::new(id).expect("finding id"),
        SourceId::new("source-1").expect("source"),
        ResourceName::new("//compute.googleapis.com/projects/gcp-project-1/instances/1")
            .expect("resource"),
        Category::new("MISCONFIGURATION").expect("category"),
        FindingState::Active,
        severity,
        now(),
    )
    .expect("finding")
}

fn list_response(
    findings: Vec<FindingRecord>,
    next_page_token: Option<OpaquePageToken>,
    partial: bool,
) -> FindingsListResponse {
    FindingsListResponse::new(
        findings,
        next_page_token,
        partial,
        0,
        ProviderRevision::new(PROVIDER_REVISION).expect("provider revision"),
    )
    .expect("list response")
}

fn list_request(scope: &GcpSecurityCenterScope) -> FindingsListRequest {
    FindingsListRequest::bounded(scope, FindingFilter::new()).expect("list request")
}

fn provider_with(
    scope: GcpSecurityCenterScope,
    transport: RecordingGcpSecurityCenterTransport,
) -> GcpSecurityCenterProvider<RecordingGcpSecurityCenterTransport> {
    GcpSecurityCenterProvider::new(scope, secret(), transport, PROVIDER_REVISION, 11)
        .expect("provider")
}

#[test]
fn contract_service_and_reversible_runtime_registration_are_exact() {
    let document: serde_json::Value =
        serde_json::from_str(GCP_SECURITY_CENTER_RESULT_CONTRACT_JSON).expect("contract JSON");
    assert_eq!(
        document["schemaVersion"],
        GCP_SECURITY_CENTER_RESULT_SCHEMA_VERSION
    );
    assert_eq!(
        document["contractVersion"],
        GCP_SECURITY_CENTER_RESULT_CONTRACT_VERSION
    );
    assert_eq!(document["layer"], 1);
    assert_eq!(
        document["service"]["id"],
        GCP_SECURITY_CENTER_RESULT_SERVICE_ID
    );
    assert_eq!(
        document["provider"]["id"],
        GCP_SECURITY_CENTER_RESULT_PROVIDER_ID
    );
    assert_eq!(
        document["consumer"]["id"],
        MISSION_GCP_SECURITY_CENTER_RESULT_CONSUMER_ID
    );
    assert!(
        document["mutatingProviderOperations"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(contract_digest().as_str().len(), 64);

    let service = GcpSecurityCenterService::new();
    service.validate().expect("service descriptor");
    assert!(service.read_only());
    assert!(!service.native_connected());
    assert!(service.capabilities().iter().all(|capability| {
        capability.read_only && !capability.mutates_provider && !capability.native_evidence
    }));

    let runtime_scope = PluginScope::new(
        RuntimeProjectId::new("project-1").expect("runtime Project"),
        RuntimeMissionId::new("mission-1").expect("runtime Mission"),
        1,
    )
    .expect("runtime scope");
    let definition = plugin_definition(runtime_scope.clone()).expect("plugin definition");
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition).expect("define");
    let receipt = runtime.mount(&handle).expect("mount");
    assert_eq!(receipt.generation(), 1);
    runtime.revoke(&handle).expect("revoke");
    assert!(runtime.inspect(&runtime_scope).plugins.is_empty());
}

#[test]
fn opaque_oauth_and_service_account_references_never_print_the_handle() {
    let oauth = secret();
    let service_account = SecretReference::service_account("host/service-account/key", 8)
        .expect("service account reference");
    assert_eq!(oauth.kind(), SecretKind::OAuth);
    assert_eq!(service_account.kind(), SecretKind::ServiceAccount);
    assert!(!format!("{oauth:?}").contains("host/oauth/security-center"));
    assert!(!format!("{service_account:?}").contains("host/service-account/key"));
    assert!(format!("{oauth:?}").contains("redacted"));

    let scope = scope(false);
    let response = list_response(
        vec![finding("finding-1", FindingSeverity::High)],
        None,
        false,
    );
    let mut provider = provider_with(
        scope.clone(),
        RecordingGcpSecurityCenterTransport::fixture([Ok(response)]),
    );
    let proposal = provider
        .propose_findings_list(list_request(&scope))
        .expect("proposal");
    let evidence = provider
        .read_findings_list(&proposal, now())
        .expect("evidence");
    let encoded = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!encoded.contains("host/oauth/security-center"));
    assert!(!encoded.contains("rawProviderPayloadRetained\":true"));
    assert!(!encoded.contains("sourceProperties\":{"));
    assert!(!encoded.contains("securityMarks\":{"));
}

#[test]
fn bounded_list_flow_records_verifies_and_consumes_without_native_authority() {
    let scope = scope(false);
    let response = list_response(
        vec![
            finding("finding-1", FindingSeverity::High),
            finding("finding-2", FindingSeverity::Medium),
        ],
        None,
        false,
    );
    let mut provider = provider_with(
        scope.clone(),
        RecordingGcpSecurityCenterTransport::fixture([Ok(response)]),
    );
    let proposal = provider
        .propose_findings_list(list_request(&scope))
        .expect("list proposal");
    let evidence = provider
        .read_findings_list(&proposal, now())
        .expect("list evidence");
    assert_eq!(evidence.projection, EvidenceProjection::Complete);
    assert_eq!(evidence.findings.len(), 2);
    assert_eq!(evidence.scope_digest, *scope.scope_digest());
    assert_eq!(evidence.permission_digest, *scope.permissions().digest());
    assert!(!evidence.authority.connected);
    assert!(!evidence.authority.native);
    assert!(!evidence.authority.durable_receipt);
    assert!(!evidence.authority.truth_authority);
    assert!(!evidence.authority.adopted);
    assert!(!evidence.classification.is_native());
    assert!(!evidence.classification.is_connected());

    let receipt = provider.record_findings_list(&evidence).expect("record");
    assert!(!receipt.durable);
    let verification = provider.verify_findings_list(&receipt).expect("verify");
    assert!(verification.verified);
    assert!(verification.complete);
    assert!(!verification.adoptable);
    assert!(!verification.native);
    assert!(!verification.connected);

    let consumer = MissionGcpSecurityCenterConsumer::new(scope.clone(), provider.registration())
        .expect("consumer");
    let result = consumer
        .consume_findings_list(&receipt, &verification)
        .expect("Mission result");
    assert_eq!(result.mission_id.as_str(), "mission-1");
    assert_eq!(result.work_product_id.as_str(), "work-product-1");
    assert_eq!(result.state, MissionResultState::PendingDecision);
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
    assert_eq!(
        result.authority,
        hartevo_gcp_security_command_center_result_plugin::EvidenceAuthority::layer1()
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());

    let request = provider
        .transport()
        .requests()
        .first()
        .expect("recorded request");
    assert_eq!(request.operation, "findings.list");
    assert_eq!(request.method, "GET");
    assert_eq!(request.api_version, "v1");
    assert!(request.redacted_path_and_query.contains("findings"));
    assert!(request.redacted_path_and_query.contains("api-version=v1"));
}

#[test]
fn optional_group_flow_requires_permission_and_has_the_same_fences() {
    let group_scope = scope(true);
    let bucket = GroupFindingBucket::new(
        GroupBy::Severity,
        GroupKey::Severity(FindingSeverity::High),
        3,
    )
    .expect("group bucket");
    let response = FindingsGroupResponse::new(
        vec![bucket],
        None,
        false,
        0,
        ProviderRevision::new(PROVIDER_REVISION).expect("provider revision"),
    )
    .expect("group response");
    let mut transport = RecordingGcpSecurityCenterTransport::new(TransportProvenance::Loopback);
    transport.push_group_response(Ok(response));
    let mut provider = provider_with(group_scope.clone(), transport);
    let request = FindingsGroupRequest::new(
        &group_scope,
        GroupBy::Severity,
        FindingFilter::new(),
        PageBinding::first(50).expect("page"),
        RequestBounds::default(),
    )
    .expect("group request");
    let proposal = provider
        .propose_findings_group(request)
        .expect("group proposal");
    let evidence = provider
        .read_findings_group(&proposal, now())
        .expect("group evidence");
    assert_eq!(evidence.projection, EvidenceProjection::Complete);
    assert_eq!(evidence.groups.len(), 1);
    assert_eq!(evidence.group_by, GroupBy::Severity);
    assert!(!evidence.classification.is_native());
    let receipt = provider
        .record_findings_group(&evidence)
        .expect("group record");
    let verification = provider
        .verify_findings_group(&receipt)
        .expect("group verify");
    assert!(verification.verified);
    assert!(!verification.adoptable);
    let request = provider
        .transport()
        .requests()
        .first()
        .expect("group request");
    assert_eq!(request.operation, "findings.group");
    assert_eq!(request.method, "POST");
    assert!(request.redacted_path_and_query.contains("findings:group"));

    let no_group_scope = scope(false);
    let no_group_request = FindingsGroupRequest::new(
        &no_group_scope,
        GroupBy::Severity,
        FindingFilter::new(),
        PageBinding::first(50).expect("page"),
        RequestBounds::default(),
    );
    assert!(no_group_request.is_err());
}

#[test]
fn partial_access_loss_and_blocked_env_are_explicit_non_native_projections() {
    let partial_scope = scope(false);
    let page_token = OpaquePageToken::new("opaque-next-page").expect("page token");
    let partial_response = list_response(
        vec![finding("finding-partial", FindingSeverity::Low)],
        Some(page_token),
        false,
    );
    let mut partial_provider = provider_with(
        partial_scope.clone(),
        RecordingGcpSecurityCenterTransport::fixture([Ok(partial_response)]),
    );
    let partial_proposal = partial_provider
        .propose_findings_list(list_request(&partial_scope))
        .expect("partial proposal");
    let partial = partial_provider
        .read_findings_list(&partial_proposal, now())
        .expect("partial evidence");
    assert_eq!(
        partial.projection,
        EvidenceProjection::Partial(
            hartevo_gcp_security_command_center_result_plugin::PartialReason::NextPage
        )
    );
    assert!(partial.has_next_page);

    let access_scope = scope(false);
    let mut access_provider = provider_with(
        access_scope.clone(),
        RecordingGcpSecurityCenterTransport::fixture([Err(TransportError::Forbidden)]),
    );
    let access_proposal = access_provider
        .propose_findings_list(list_request(&access_scope))
        .expect("access proposal");
    let access = access_provider
        .read_findings_list(&access_proposal, now())
        .expect("access-loss evidence");
    assert_eq!(access.projection, EvidenceProjection::AccessLost);
    assert!(access.errors[0].access_lost);
    let access_receipt = access_provider
        .record_findings_list(&access)
        .expect("access receipt");
    let access_verification = access_provider
        .verify_findings_list(&access_receipt)
        .expect("access verification");
    assert!(!access_verification.complete);
    let access_consumer =
        MissionGcpSecurityCenterConsumer::new(access_scope, access_provider.registration())
            .expect("access consumer");
    let access_result = access_consumer
        .consume_findings_list(&access_receipt, &access_verification)
        .expect("access Mission result");
    assert_eq!(access_result.state, MissionResultState::AccessLost);

    let blocked_scope = scope(false);
    let mut blocked_provider = GcpSecurityCenterProvider::new(
        blocked_scope.clone(),
        secret(),
        BlockedEnvGcpSecurityCenterTransport,
        PROVIDER_REVISION,
        11,
    )
    .expect("blocked provider");
    let blocked_proposal = blocked_provider
        .propose_findings_list(list_request(&blocked_scope))
        .expect("blocked proposal");
    let blocked = blocked_provider
        .read_findings_list(&blocked_proposal, now())
        .expect("blocked evidence");
    assert_eq!(blocked.projection, EvidenceProjection::ProviderUnknown);
    assert!(blocked.errors[0].blocked_env);
    assert_eq!(blocked.classification, TransportProvenance::BlockedEnv);
    assert!(!blocked.authority.native);
}

#[test]
fn tamper_and_revocation_fail_closed() {
    let response = list_response(
        vec![finding("finding-tamper", FindingSeverity::Critical)],
        None,
        false,
    );
    let mut tampered_response = response.clone();
    tampered_response.response_digest = Digest::from_text("tampered-response");
    let tamper_scope = scope(false);
    let mut tamper_provider = provider_with(
        tamper_scope.clone(),
        RecordingGcpSecurityCenterTransport::fixture([Ok(tampered_response)]),
    );
    let tamper_proposal = tamper_provider
        .propose_findings_list(list_request(&tamper_scope))
        .expect("tamper proposal");
    assert_eq!(
        tamper_provider
            .read_findings_list(&tamper_proposal, now())
            .expect_err("tampered response"),
        GcpSecurityCenterError::ResponseTampered
    );

    let clean_scope = scope(false);
    let mut provider = provider_with(
        clean_scope.clone(),
        RecordingGcpSecurityCenterTransport::fixture([Ok(response)]),
    );
    let proposal = provider
        .propose_findings_list(list_request(&clean_scope))
        .expect("proposal");
    let mut evidence = provider
        .read_findings_list(&proposal, now())
        .expect("evidence");
    evidence.evidence_digest = Digest::from_text("tampered-evidence");
    assert_eq!(
        provider
            .record_findings_list(&evidence)
            .expect_err("tampered evidence"),
        GcpSecurityCenterError::EvidenceTampered
    );

    provider.revoke().expect("provider revoke");
    assert_eq!(
        provider
            .propose_findings_list(list_request(&clean_scope))
            .expect_err("revoked proposal"),
        GcpSecurityCenterError::RegistrationRevoked
    );
    let registration = provider.registration().clone();
    assert!(!registration.is_active());
    assert!(registration.reversible);
    assert!(registration.revocable);

    let mut consumer = MissionGcpSecurityCenterConsumer::new(clean_scope, &registration)
        .expect_err("revoked registration cannot create a consumer");
    let _ = &mut consumer;
}

#[test]
fn filter_page_and_scope_metadata_are_bound_without_arbitrary_query_or_raw_payloads() {
    let scope = scope(false);
    let category = Category::new("VULNERABILITY").expect("category");
    let filter = FindingFilter::new()
        .with_states([FindingState::Active])
        .expect("state filter")
        .with_severities([FindingSeverity::High, FindingSeverity::Critical])
        .expect("severity filter")
        .with_categories([category])
        .expect("category filter")
        .for_source(SourceId::new("source-1").expect("source"));
    assert!(filter.to_api_filter().contains("state"));
    assert!(filter.to_api_filter().contains("severity"));
    assert!(!filter.to_api_filter().contains("sourceProperties"));
    assert!(
        FindingFilter::new()
            .with_categories([Category::new("sourceProperties.secret").expect("category")])
            .is_err()
    );

    let token = OpaquePageToken::new("opaque-token").expect("page token");
    let page = PageBinding::new(2, 25, Some(token.clone())).expect("page binding");
    assert!(!format!("{token:?}").contains("opaque-token"));
    let request = FindingsListRequest::new(&scope, filter, page, RequestBounds::default())
        .expect("bounded request");
    assert_eq!(request.scope_digest(), scope.scope_digest());
    assert_eq!(request.page().page_number(), 2);
    assert_eq!(request.page().page_size(), 25);
    assert_eq!(
        request.page().page_token().expect("token").digest(),
        token.digest()
    );
}

#[test]
fn all_fixture_recording_loopback_and_blocked_env_provenance_is_non_native() {
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_native());
        assert!(!provenance.is_connected());
    }
    assert!(!Layer1Authority::durable_receipt());
    assert!(!Layer1Authority::adopted_outcome());
    assert!(!Layer1Authority::truth_authority());
}

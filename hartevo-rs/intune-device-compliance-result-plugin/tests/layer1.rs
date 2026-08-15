use serde_json::json;

use hartevo_intune_device_compliance_result_plugin::{
    BlockedEnvIntuneGraphTransport, ComplianceState, ComplianceSummary, ComplianceWindow,
    DeviceSelector, Digest, EvidenceStatus, FixtureIntuneGraphTransport,
    IntuneDeviceComplianceResultService, IntuneDeviceComplianceService, IntuneGraphResponse,
    IntuneProvider, IntuneReadRequest, IntuneScope, MissionBinding,
    MissionIntuneComplianceConsumer, MissionIntuneComplianceConsumerError,
    MissionIntuneComplianceResultState, NationalCloud, Platform, PolicyFingerprints,
    ProjectBinding, ProviderErrorKind, ProviderProvenance, QueryBounds, ReadSurface,
    RecordingIntuneGraphTransport, SecretReference, Timestamp, WorkProductBinding,
};

const START: &str = "2026-08-14T00:00:00Z";
const END: &str = "2026-08-16T00:00:00Z";
const POLICY: &str = "policy-01";
const DEVICE: &str = "device-01";
const NEXT_LINK: &str =
    "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=cursor-1";

fn scope() -> IntuneScope {
    IntuneScope::new(
        "tenant-01",
        NationalCloud::Global,
        PolicyFingerprints::new([Digest::from_text(POLICY)]).expect("policy fingerprints"),
        DeviceSelector::AllManagedDevices,
        Platform::Windows,
        ComplianceWindow::new(
            Timestamp::new(START).expect("start"),
            Timestamp::new(END).expect("end"),
        )
        .expect("window"),
        ProjectBinding::new("project-01", 4).expect("project"),
        MissionBinding::new("mission-01", 7).expect("mission"),
        WorkProductBinding::new("work-product-01", 9).expect("work product"),
        Digest::from_text("permission-01"),
    )
    .expect("scope")
}

fn policy_body() -> String {
    json!({
        "value": [{
            "id": POLICY,
            "platforms": ["windows10"],
            "createdDateTime": "2026-08-14T00:00:00Z",
            "lastModifiedDateTime": "2026-08-15T00:00:00Z",
            "displayName": "do-not-retain-policy-name",
            "rawPolicyJson": {"secret": "do-not-retain-policy-json"}
        }]
    })
    .to_string()
}

fn device_body(state: &str) -> String {
    json!({
        "value": [{
            "id": DEVICE,
            "policyId": POLICY,
            "complianceState": state,
            "operatingSystem": "Windows",
            "lastSyncDateTime": "2026-08-15T12:00:00Z",
            "userId": "user-raw-should-not-escape",
            "userPrincipalName": "person@example.invalid",
            "serialNumber": "serial-should-not-escape",
            "imei": "imei-should-not-escape",
            "deviceName": "laptop-should-not-escape",
            "location": "should-not-escape"
        }]
    })
    .to_string()
}

fn summary_body() -> String {
    json!({
        "value": [{
            "id": "summary-01",
            "settingName": "setting-that-is-digest-only",
            "policyId": POLICY,
            "compliantDeviceCount": 1,
            "nonCompliantDeviceCount": 1,
            "errorDeviceCount": 0,
            "conflictDeviceCount": 0,
            "unknownDeviceCount": 0,
            "retiredDeviceCount": 0
        }]
    })
    .to_string()
}

fn provider_with_responses(
    scope: &IntuneScope,
    responses: impl IntoIterator<
        Item = Result<
            IntuneGraphResponse,
            hartevo_intune_device_compliance_result_plugin::IntuneTransportError,
        >,
    >,
) -> IntuneProvider<RecordingIntuneGraphTransport> {
    let secret = SecretReference::new("entra-keyring-handle", scope, 3).expect("secret");
    let mut transport = RecordingIntuneGraphTransport::new();
    for response in responses {
        match response {
            Ok(response) => transport.push_response(response),
            Err(error) => transport.push_error(error),
        }
    }
    IntuneProvider::new(
        scope.clone(),
        secret,
        transport,
        ProviderProvenance::Recording,
    )
    .expect("provider")
}

fn full_service() -> IntuneDeviceComplianceResultService<RecordingIntuneGraphTransport> {
    let scope = scope();
    IntuneDeviceComplianceService::new(provider_with_responses(
        &scope,
        [
            Ok(IntuneGraphResponse::ok(policy_body())),
            Ok(IntuneGraphResponse::ok(device_body("nonCompliant"))),
            Ok(IntuneGraphResponse::ok(summary_body())),
        ],
    ))
    .expect("service")
}

fn single_device_request(scope: &IntuneScope) -> IntuneReadRequest {
    IntuneReadRequest::for_surface(scope, ReadSurface::ManagedDeviceCompliance)
        .expect("device request")
}

#[test]
fn contract_and_scope_are_versioned_and_secret_reference_is_opaque() {
    hartevo_intune_device_compliance_result_plugin::validate_contract().expect("contract");
    let scope = scope();
    let secret = SecretReference::new("entra-keyring-handle", &scope, 3).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("entra-keyring-handle"));
    assert_eq!(secret.scope_digest(), &scope.scope_digest());
    assert_eq!(secret.revision().get(), 3);
    assert_ne!(scope.scope_digest(), Digest::from_text("tenant-01"));
    assert!(!ProviderProvenance::Fixture.connected());
    assert!(!ProviderProvenance::Recording.native());
    assert!(!ProviderProvenance::Loopback.first_party());
    assert!(!ProviderProvenance::BlockedEnv.is_native());
}

#[test]
fn full_bounded_read_exposes_only_typed_digest_projections() {
    let mut service = full_service();
    let scope = scope();
    let proposal = service
        .propose(&IntuneReadRequest::all_surfaces(&scope).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.status(), EvidenceStatus::Complete);
    assert_eq!(proposal.summary(), &ComplianceSummary::NonCompliant);
    assert_eq!(proposal.evidence.records.len(), 1);
    assert_eq!(proposal.evidence.policies.len(), 1);
    assert_eq!(proposal.evidence.policy_summaries.len(), 1);
    assert_eq!(
        proposal.evidence.records[0].state,
        ComplianceState::NonCompliant
    );
    assert_eq!(
        proposal.evidence.records[0].device_digest,
        Digest::from_text(DEVICE)
    );
    assert!(!proposal.connected());
    assert!(!proposal.native());
    assert!(!proposal.first_party());
    assert!(!proposal.certification());
    assert!(!proposal.outcome_authority());
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for forbidden in [
        "entra-keyring-handle",
        "device-01",
        "policy-01",
        "user-raw-should-not-escape",
        "person@example.invalid",
        "serial-should-not-escape",
        "imei-should-not-escape",
        "laptop-should-not-escape",
        "do-not-retain-policy-name",
        "do-not-retain-policy-json",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
    let request = &service.provider().transport().requests()[0];
    assert_eq!(request.method, "GET");
    assert_eq!(request.api_version, "v1.0");
    assert_eq!(request.host, "graph.microsoft.com");
    assert_eq!(request.surface, ReadSurface::PolicyMetadata);
    assert_eq!(request.top, 128);
    assert!(request.select.contains(&"id".to_owned()));
    assert!(request.select.contains(&"lastModifiedDateTime".to_owned()));
    assert!(!request.select.contains(&"userPrincipalName".to_owned()));
    assert!(request.query_string().contains("$select=id,platforms"));
}

#[test]
fn read_proposal_verify_record_and_revocation_are_digest_and_scope_bound() {
    let mut service = full_service();
    let scope = scope();
    let proposal = service
        .propose(&IntuneReadRequest::all_surfaces(&scope).expect("request"))
        .expect("proposal");
    let verification = service.verify(&proposal).expect("verify");
    assert!(verification.valid);
    let receipt = service.record(&proposal).expect("record");
    assert!(receipt.recorded);
    assert!(!receipt.durable_provider_receipt);
    assert!(!receipt.independent_readback);
    assert!(matches!(
        service.record(&proposal),
        Err(hartevo_intune_device_compliance_result_plugin::IntuneDeviceComplianceServiceError::AlreadyRecorded)
    ));

    let mut tampered = proposal.clone();
    tampered.evidence.records.clear();
    assert!(service.verify(&tampered).is_err());
    service
        .revoke_registration("operator-revoked-registration")
        .expect("revoke");
    assert!(!service.registration().is_active());
    assert!(matches!(
        service.verify(&proposal),
        Err(hartevo_intune_device_compliance_result_plugin::IntuneDeviceComplianceServiceError::RegistrationRevoked)
    ));
}

#[test]
fn bounded_graph_requests_reject_unsafe_pagination_and_partial_pages() {
    let scope = scope();
    let first = json!({
        "value": [{
            "id": DEVICE,
            "complianceState": "compliant",
            "operatingSystem": "Windows",
            "lastSyncDateTime": "2026-08-15T12:00:00Z"
        }],
        "@odata.nextLink": NEXT_LINK
    })
    .to_string();
    let second = device_body("retired");
    let mut provider = provider_with_responses(
        &scope,
        [
            Ok(IntuneGraphResponse::ok(first)),
            Ok(IntuneGraphResponse::ok(second)),
        ],
    );
    let evidence = provider.read(&single_device_request(&scope));
    assert_eq!(evidence.pages_observed, 2);
    assert_eq!(evidence.records.len(), 2);
    assert_eq!(evidence.next_link_digests.len(), 1);
    assert_eq!(provider.transport().call_count(), 2);

    let replay = json!({"value": [], "@odata.nextLink": NEXT_LINK}).to_string();
    let mut provider = provider_with_responses(
        &scope,
        [
            Ok(IntuneGraphResponse::ok(replay.clone())),
            Ok(IntuneGraphResponse::ok(replay)),
        ],
    );
    let replay_evidence = provider.read(&single_device_request(&scope));
    assert_eq!(replay_evidence.status, EvidenceStatus::Tampered);
    assert_eq!(
        replay_evidence.provider_errors[0].kind,
        ProviderErrorKind::NextLinkReplay
    );

    let bad_link = NEXT_LINK.replace("graph.microsoft.com", "evil.example");
    let mut provider = provider_with_responses(
        &scope,
        [Ok(IntuneGraphResponse::ok(
            json!({"value": [], "@odata.nextLink": bad_link}).to_string(),
        ))],
    );
    let bad_link_evidence = provider.read(&single_device_request(&scope));
    assert_eq!(bad_link_evidence.status, EvidenceStatus::Tampered);
    assert_eq!(
        bad_link_evidence.provider_errors[0].kind,
        ProviderErrorKind::NextLinkScopeMismatch
    );

    let mut provider = provider_with_responses(
        &scope,
        [Ok(IntuneGraphResponse::ok(
            json!({"value": [], "partial": true}).to_string(),
        ))],
    );
    let partial = provider.read(&single_device_request(&scope));
    assert_eq!(partial.status, EvidenceStatus::Partial);
    assert_eq!(
        partial.provider_errors[0].kind,
        ProviderErrorKind::PartialPage
    );
}

#[test]
fn scope_platform_window_and_record_bounds_fail_closed() {
    let scope = scope();
    let wrong_platform = json!({
        "value": [{"id": DEVICE, "complianceState": "compliant", "operatingSystem": "Android"}]
    })
    .to_string();
    let mut provider =
        provider_with_responses(&scope, [Ok(IntuneGraphResponse::ok(wrong_platform))]);
    let platform_evidence = provider.read(&single_device_request(&scope));
    assert_eq!(platform_evidence.status, EvidenceStatus::Tampered);
    assert_eq!(
        platform_evidence.provider_errors[0].kind,
        ProviderErrorKind::ScopeMismatch
    );

    let outside_window = json!({
        "value": [{
            "id": DEVICE,
            "complianceState": "compliant",
            "operatingSystem": "Windows",
            "lastSyncDateTime": "2026-08-20T12:00:00Z"
        }]
    })
    .to_string();
    let mut provider =
        provider_with_responses(&scope, [Ok(IntuneGraphResponse::ok(outside_window))]);
    let window_evidence = provider.read(&single_device_request(&scope));
    assert_eq!(window_evidence.status, EvidenceStatus::Tampered);
    assert_eq!(
        window_evidence.provider_errors[0].kind,
        ProviderErrorKind::ScopeMismatch
    );

    let too_many = json!({
        "value": [
            {"id": "device-01", "complianceState": "compliant", "operatingSystem": "Windows"},
            {"id": "device-02", "complianceState": "compliant", "operatingSystem": "Windows"}
        ]
    })
    .to_string();
    let bounds = QueryBounds::new(1, 1, 1, 32 * 1024).expect("bounds");
    let request = IntuneReadRequest::new(&scope, [ReadSurface::ManagedDeviceCompliance], bounds)
        .expect("bounded request");
    let mut provider = provider_with_responses(&scope, [Ok(IntuneGraphResponse::ok(too_many))]);
    let bounded = provider.read(&request);
    assert_eq!(bounded.status, EvidenceStatus::Tampered);
    assert_eq!(
        bounded.provider_errors[0].kind,
        ProviderErrorKind::RecordLimit
    );
}

#[test]
fn provider_statuses_and_blocked_env_never_upgrade_authority() {
    for (status, expected) in [
        (401, EvidenceStatus::AccessLoss),
        (403, EvidenceStatus::AccessLoss),
        (404, EvidenceStatus::ProviderUnknown),
        (409, EvidenceStatus::ProviderUnknown),
        (429, EvidenceStatus::ProviderUnknown),
        (500, EvidenceStatus::ProviderUnknown),
    ] {
        let scope = scope();
        let mut provider = provider_with_responses(
            &scope,
            [Ok(IntuneGraphResponse::new(
                status,
                r#"{"error":{"message":"private diagnostic","userPrincipalName":"redact"}}"#,
            ))],
        );
        let evidence = provider.read(&single_device_request(&scope));
        assert_eq!(evidence.status, expected);
        assert!(evidence.records.is_empty());
        let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
        assert!(!serialized.contains("private diagnostic"));
        assert!(!serialized.contains("userPrincipalName"));
        assert!(!evidence.connected());
        assert!(!evidence.native());
        assert!(!evidence.first_party());
    }

    let scope = scope();
    let secret = SecretReference::new("entra-keyring-handle", &scope, 3).expect("secret");
    let provider = IntuneProvider::new(
        scope.clone(),
        secret,
        BlockedEnvIntuneGraphTransport,
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut service = IntuneDeviceComplianceService::new(provider).expect("service");
    let evidence = service
        .read(&single_device_request(&scope))
        .expect("blocked evidence");
    assert_eq!(evidence.status, EvidenceStatus::ProviderUnknown);
    assert_eq!(evidence.provenance, ProviderProvenance::BlockedEnv);
    assert_eq!(
        evidence.provider_errors[0].kind,
        ProviderErrorKind::BlockedEnv
    );
    assert!(!evidence.authority.connected);
    assert!(!evidence.authority.native_provider);
    assert!(!evidence.authority.first_party);
}

#[test]
fn mission_consumer_is_proposal_only_and_replay_fenced() {
    let scope = scope();
    let provider = provider_with_responses(
        &scope,
        [Ok(IntuneGraphResponse::ok(device_body("compliant")))],
    );
    let mut consumer = MissionIntuneComplianceConsumer::new(provider).expect("consumer");
    let request = single_device_request(&scope);
    let proposal = consumer.propose(&request).expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        MissionIntuneComplianceResultState::EvidenceReady
    );
    assert_eq!(result.summary, ComplianceSummary::Compliant);
    assert!(result.proposal_only);
    assert!(!result.adopts_outcome);
    assert!(!result.certification);
    assert!(!result.authority.truth_authority);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(MissionIntuneComplianceConsumerError::Replay)
    ));
    consumer.revoke().expect("revoke");
    assert!(consumer.consume(&proposal).is_err());
}

#[test]
fn fixture_loopback_and_blocked_environment_provenance_are_explicit() {
    let scope = scope();
    let secret = SecretReference::new("entra-keyring-handle", &scope, 3).expect("secret");
    let mut fixture_transport = FixtureIntuneGraphTransport::new();
    fixture_transport.push_response(IntuneGraphResponse::ok(device_body("unknown")));
    let mut fixture = IntuneProvider::new(
        scope.clone(),
        secret.clone(),
        fixture_transport,
        ProviderProvenance::Fixture,
    )
    .expect("fixture provider");
    let evidence = fixture.read(&single_device_request(&scope));
    assert_eq!(evidence.provenance, ProviderProvenance::Fixture);
    assert_eq!(evidence.summary, ComplianceSummary::Unknown);
    assert!(!evidence.authority.connected);

    let mut loopback_transport =
        hartevo_intune_device_compliance_result_plugin::LoopbackIntuneGraphTransport::new();
    loopback_transport.push_response(IntuneGraphResponse::ok(device_body("retired")));
    let mut loopback = IntuneProvider::new(
        scope.clone(),
        secret,
        loopback_transport,
        ProviderProvenance::Loopback,
    )
    .expect("loopback provider");
    let evidence = loopback.read(&single_device_request(&scope));
    assert_eq!(evidence.provenance, ProviderProvenance::Loopback);
    assert_eq!(evidence.summary, ComplianceSummary::Retired);
    assert!(!evidence.authority.native_provider);
}

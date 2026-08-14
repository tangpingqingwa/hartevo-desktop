use hartevo_ninjaone_device_result_plugin::{
    ActivityResult, ActivitySeverity, AlertKind, BlockedEnvNinjaOneTransport, HealthStatus,
    MissionNinjaOneDeviceConsumer, NinjaOneDeviceActivityRecord, NinjaOneDeviceAlertRecord,
    NinjaOneDeviceHealthRecord, NinjaOneDeviceRecord, NinjaOneDeviceResultService,
    NinjaOneDeviceState, NinjaOneEndpoint, NinjaOneError, NinjaOneOrganizationRecord,
    NinjaOnePatchRecord, NinjaOnePayload, NinjaOneProvider, NinjaOneResponse, NinjaOneScope,
    PatchStatus, PermissionLease, SecretKind, SecretReference, TransportMode, contract_digest,
    validate_contract,
};

fn scope() -> (NinjaOneScope, PermissionLease) {
    let lease = PermissionLease::required_read(3).expect("read lease");
    let scope = NinjaOneScope::from_parts(
        "org-1",
        "site-1",
        "device-1",
        "agent-1",
        "alert-1",
        "device-1",
        "activity-1",
        "mission-1",
        "project-1",
        "consent-1",
        [1, 1, 1, 1, 1, 1, 1, 8, 4, 2],
        lease.permission_digest().clone(),
    )
    .expect("scope");
    (scope, lease)
}

fn responses(
    scope: &NinjaOneScope,
    health_status: HealthStatus,
    offline: bool,
    with_alert: bool,
    with_pending_patch: bool,
) -> Vec<(NinjaOneEndpoint, NinjaOneResponse)> {
    let organization = NinjaOneOrganizationRecord::new(
        scope.organization_id().as_str(),
        [scope.site_id().as_str()],
        1,
        b"organization-metadata",
    )
    .expect("organization");
    let device = NinjaOneDeviceRecord::new(
        scope.organization_id().as_str(),
        scope.site_id().as_str(),
        scope.device_id().as_str(),
        scope.agent_id().as_str(),
        offline,
        Some(1_700_000_000_000),
        1,
        b"device-metadata",
    )
    .expect("device");
    let alert = NinjaOneDeviceAlertRecord::new(
        scope.alert_id().as_str(),
        scope.device_id().as_str(),
        "AGENT_OFFLINE",
        Some(1_700_000_000_000),
        Some(1_700_000_000_100),
        1,
        Some("private-alert-body"),
    )
    .expect("alert");
    let health = NinjaOneDeviceHealthRecord::new(
        scope.device_id().as_str(),
        health_status,
        offline,
        usize::from(with_alert),
        usize::from(with_pending_patch),
        0,
        0,
        0,
        Some(1_700_000_000_100),
        1,
        b"health-metadata",
    )
    .expect("health")
    .with_patch_health_id(scope.patch_health_id().as_str())
    .expect("patch-health identity");
    let patch = NinjaOnePatchRecord::new(
        "patch-1",
        scope.device_id().as_str(),
        PatchStatus::Pending,
        None,
        1,
        b"patch-metadata",
    )
    .expect("patch");
    let activity = NinjaOneDeviceActivityRecord::new(
        scope.activity_id().as_str(),
        scope.device_id().as_str(),
        "PATCH_MANAGEMENT_MESSAGE",
        ActivitySeverity::Minor,
        ActivityResult::Success,
        Some(1_700_000_000_200),
        1,
    )
    .expect("activity");
    vec![
        (
            NinjaOneEndpoint::Organizations,
            NinjaOneResponse::success(
                NinjaOneEndpoint::Organizations,
                NinjaOnePayload::Organizations(vec![organization]),
                512,
                None,
            )
            .expect("organization response"),
        ),
        (
            NinjaOneEndpoint::Devices,
            NinjaOneResponse::success(
                NinjaOneEndpoint::Devices,
                NinjaOnePayload::Devices(vec![device]),
                512,
                None,
            )
            .expect("device response"),
        ),
        (
            NinjaOneEndpoint::DeviceAlerts,
            NinjaOneResponse::success(
                NinjaOneEndpoint::DeviceAlerts,
                NinjaOnePayload::DeviceAlerts(if with_alert { vec![alert] } else { Vec::new() }),
                512,
                None,
            )
            .expect("alert response"),
        ),
        (
            NinjaOneEndpoint::DeviceHealth,
            NinjaOneResponse::success(
                NinjaOneEndpoint::DeviceHealth,
                NinjaOnePayload::DeviceHealth(vec![health]),
                512,
                None,
            )
            .expect("health response"),
        ),
        (
            NinjaOneEndpoint::DeviceOsPatches,
            NinjaOneResponse::success(
                NinjaOneEndpoint::DeviceOsPatches,
                NinjaOnePayload::OsPatches(if with_pending_patch {
                    vec![patch.clone()]
                } else {
                    Vec::new()
                }),
                512,
                None,
            )
            .expect("OS patch response"),
        ),
        (
            NinjaOneEndpoint::DeviceSoftwarePatches,
            NinjaOneResponse::success(
                NinjaOneEndpoint::DeviceSoftwarePatches,
                NinjaOnePayload::SoftwarePatches(Vec::new()),
                512,
                None,
            )
            .expect("software patch response"),
        ),
        (
            NinjaOneEndpoint::DeviceActivities,
            NinjaOneResponse::success(
                NinjaOneEndpoint::DeviceActivities,
                NinjaOnePayload::DeviceActivities(vec![activity]),
                512,
                None,
            )
            .expect("activity response"),
        ),
    ]
}

fn service_with(
    health_status: HealthStatus,
    offline: bool,
    with_alert: bool,
    with_pending_patch: bool,
) -> NinjaOneDeviceResultService {
    let (scope, lease) = scope();
    let secret = SecretReference::for_scope(
        "secret-ref-ninjaone-test",
        &scope,
        &lease,
        2,
        SecretKind::OAuth2Bearer,
    )
    .expect("opaque secret reference");
    let provider = NinjaOneProvider::recording(
        &scope,
        &lease,
        secret,
        responses(
            &scope,
            health_status,
            offline,
            with_alert,
            with_pending_patch,
        ),
        10,
    )
    .expect("recording provider");
    NinjaOneDeviceResultService::new(provider, scope).expect("service")
}

#[test]
fn contract_is_versioned_and_honest() {
    validate_contract().expect("contract validation");
    assert_eq!(contract_digest().as_str().len(), 64);
}

#[test]
fn healthy_result_compiles_to_redacted_non_adoptable_mission_observation() {
    let mut service = service_with(HealthStatus::Healthy, false, false, false);
    let description = service.describe_capabilities().expect("capabilities");
    assert!(description.service.read_only);
    assert!(description.service.proposal_only);
    assert!(!description.service.external_writes);
    assert!(!description.connected);
    assert!(!description.native);
    assert_eq!(description.provider.method, "GET");
    assert_eq!(
        service.provider_state(),
        hartevo_ninjaone_device_result_plugin::NinjaOneProviderState::Recording
    );

    let evidence = service.read_device_result().expect("device evidence");
    assert_eq!(
        evidence.projection().primary_state,
        NinjaOneDeviceState::Healthy
    );
    assert!(!evidence.is_connected());
    assert!(!evidence.is_native());
    assert_eq!(evidence.provenance(), TransportMode::Recording);
    assert_eq!(evidence.receipts().len(), 7);
    evidence.verify_integrity().expect("evidence digest");

    let proposal = service
        .compile_device_result_proposal(&evidence)
        .expect("proposal");
    proposal.verify_integrity().expect("proposal digest");
    let recording = service
        .record_device_result(&evidence)
        .expect("redacted recording");
    assert!(!recording.durable);
    assert!(!recording.raw_provider_payload_retained);
    assert!(!recording.raw_activity_log_retained);
    assert!(!recording.credential_material_serialized);
    assert!(!recording.raw_pii_retained);

    let mission_result = MissionNinjaOneDeviceConsumer::from_scope(service.scope())
        .consume(proposal.clone(), evidence.clone())
        .expect("Mission observation");
    assert_eq!(
        mission_result.observation.result_state,
        NinjaOneDeviceState::Healthy
    );
    assert!(mission_result.observation.non_adoptable);
    assert!(!mission_result.observation.work_product_adopted);
    assert!(!mission_result.observation.kernel_authority);
    assert!(!mission_result.observation.connected);
    assert!(!mission_result.observation.native);
    service
        .verify_device_result(&proposal, &evidence)
        .expect("verified proposal");

    let secret_debug = format!("{:?}", service.secret_reference());
    let secret_json = serde_json::to_string(service.secret_reference()).expect("secret JSON");
    assert!(!secret_debug.contains("secret-ref-ninjaone-test"));
    assert!(!secret_json.contains("secret-ref-ninjaone-test"));
    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!serialized.contains("private-alert-body"));
    assert!(!serialized.contains("Authorization: Bearer"));
}

#[test]
fn projection_distinguishes_offline_alerted_degraded_and_patch_pending() {
    let mut service = service_with(HealthStatus::NeedsAttention, true, true, true);
    let evidence = service.read_device_result().expect("degraded evidence");
    for state in [
        NinjaOneDeviceState::Offline,
        NinjaOneDeviceState::Degraded,
        NinjaOneDeviceState::Alerted,
        NinjaOneDeviceState::PatchPending,
    ] {
        assert!(evidence.projection().has_state(state), "missing {state:?}");
    }
    assert_eq!(
        evidence.projection().primary_state,
        NinjaOneDeviceState::Offline
    );
    assert!(!evidence.projection().partial);
}

#[test]
fn blocked_environment_is_provider_unknown_and_never_native() {
    let (scope, lease) = scope();
    let secret = SecretReference::for_scope(
        "secret-ref-ninjaone-blocked",
        &scope,
        &lease,
        2,
        SecretKind::OAuth2Bearer,
    )
    .expect("secret");
    let registration = hartevo_ninjaone_device_result_plugin::NinjaOneRegistration::new(
        &scope, &lease, secret, 10,
    )
    .expect("registration");
    let provider =
        NinjaOneProvider::new(registration, BlockedEnvNinjaOneTransport).expect("provider");
    let mut service = NinjaOneDeviceResultService::new(provider, scope).expect("service");
    let evidence = service.read_device_result().expect("blocked evidence");
    assert!(
        evidence
            .projection()
            .has_state(NinjaOneDeviceState::ProviderUnknown)
    );
    assert!(evidence.projection().partial);
    assert_eq!(evidence.provenance(), TransportMode::BlockedEnv);
    assert!(!evidence.is_connected());
    assert!(!evidence.is_native());
}

#[test]
fn registration_is_reversible_and_revocable_and_mutations_are_forbidden() {
    let mut service = service_with(HealthStatus::Healthy, false, false, false);
    let unmounted = service.unmount().expect("unmount");
    assert_eq!(
        unmounted.current,
        hartevo_ninjaone_device_result_plugin::RegistrationStatus::Unmounted
    );
    service.remount().expect("remount");
    service
        .provider()
        .reject_write("reboot_device")
        .expect_err("write blocked");
    service.revoke().expect("revoke");
    assert_eq!(
        service.registration().status(),
        hartevo_ninjaone_device_result_plugin::RegistrationStatus::Revoked
    );
    assert_eq!(
        service.read_device_result(),
        Err(NinjaOneError::RegistrationRevoked)
    );
}

#[test]
fn json_ingestion_discards_alert_bodies_and_activity_messages() {
    let alert = NinjaOneResponse::from_json(
        NinjaOneEndpoint::DeviceAlerts,
        br#"[{"uid":"alert-1","deviceId":"device-1","sourceType":"AGENT_OFFLINE","message":"raw-alert-body","createTime":1700000000,"updateTime":1700000001}]"#,
        None,
    )
    .expect("alert JSON");
    let activity = NinjaOneResponse::from_json(
        NinjaOneEndpoint::DeviceActivities,
        br#"{"activities":[{"id":1,"deviceId":"device-1","type":"PATCH_MANAGEMENT_MESSAGE","severity":"MINOR","activityResult":"SUCCESS","activityTime":1700000002,"message":"raw-activity-message","data":{"script":"raw-script"}}]}"#,
        None,
    )
    .expect("activity JSON");
    let alert_json = serde_json::to_string(&alert).expect("alert normalized JSON");
    let activity_json = serde_json::to_string(&activity).expect("activity normalized JSON");
    assert!(!alert_json.contains("raw-alert-body"));
    assert!(!activity_json.contains("raw-activity-message"));
    assert!(!activity_json.contains("raw-script"));
    assert!(alert_json.contains("bodyDigest"));
    assert!(activity_json.contains("activityTypeDigest"));
    assert_eq!(AlertKind::parse("AGENT_OFFLINE"), AlertKind::AgentOffline);
}

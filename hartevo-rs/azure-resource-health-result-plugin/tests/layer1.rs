use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_azure_resource_health_result_plugin::{
    AvailabilityState, AzureResourceHealthOperation, AzureResourceHealthProvider,
    AzureResourceHealthResponse, AzureResourceHealthScope, AzureResourceHealthScopeInput,
    AzureResourceHealthService, AzureResourceHealthTransport,
    BlockedEnvAzureResourceHealthTransport, Digest, EventStatus, EventWindow,
    FixtureAzureResourceHealthTransport, MissionAzureResourceHealthConsumer,
    RecordingAzureResourceHealthTransport, SecretReference, TransportProvenance, contract_digest,
};
use serde_json::json;

const RESOURCE_ID: &str =
    "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1";
const NOW: i64 = 1_785_542_400;

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW, 0).single().expect("timestamp")
}

fn scope() -> AzureResourceHealthScope {
    let start = now();
    let window = EventWindow::new(start, start + Duration::hours(24)).expect("window");
    AzureResourceHealthScope::new(AzureResourceHealthScopeInput {
        tenant_id: "tenant-1".to_owned(),
        subscription_id: "sub-1".to_owned(),
        resource_id: RESOURCE_ID.to_owned(),
        resource_revision: 7,
        region: "eastus".to_owned(),
        event_window: window,
        project_id: "project-1".to_owned(),
        project_revision: 2,
        mission_id: "mission-1".to_owned(),
        mission_revision: 3,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 4,
        permissions: hartevo_azure_resource_health_result_plugin::PermissionFence::least_privilege(
        ),
    })
    .expect("scope")
}

fn secret() -> SecretReference {
    SecretReference::new("keyring/entra/resource-health", "tenant-1", 1).expect("secret")
}

fn availability(status: &str) -> AzureResourceHealthResponse {
    AzureResourceHealthResponse::json(
        200,
        &json!({
            "id": format!("{RESOURCE_ID}/providers/Microsoft.ResourceHealth/availabilityStatuses/current"),
            "location": "eastus",
            "properties": {
                "availabilityState": status,
                "occurredTime": "2026-08-01T00:01:00Z",
                "reportedTime": "2026-08-01T00:02:00Z",
                "healthEventId": "health-event-1",
                "detailedStatus": "private detailed status must not escape",
                "summary": "private summary must not escape",
                "recommendedActions": [{"action": "restart the VM"}]
            }
        }),
    )
}

fn events() -> AzureResourceHealthResponse {
    AzureResourceHealthResponse::json(
        200,
        &json!({
            "nextLink": format!(
                "https://management.azure.com{RESOURCE_ID}/providers/Microsoft.ResourceHealth/events?api-version=2025-05-01&$skipToken=opaque-page-2"
            ),
            "value": [
                {
                    "id": "/providers/Microsoft.ResourceHealth/events/event-2",
                    "properties": {
                        "status": "Resolved",
                        "impactStartTime": "2026-08-01T00:20:00Z",
                        "lastUpdateTime": "2026-08-01T00:30:00Z",
                        "previousStatus": "Active",
                        "level": "Informational",
                        "summary": "private event summary",
                        "eventTags": ["Final PIR"],
                        "impact": [{"impactedSubscriptions": ["sub-1"]}]
                    }
                },
                {
                    "id": "/providers/Microsoft.ResourceHealth/events/event-1",
                    "properties": {
                        "status": "Active",
                        "impactStartTime": "2026-08-01T00:10:00Z",
                        "lastUpdateTime": "2026-08-01T00:11:00Z",
                        "level": "Warning",
                        "description": "private event description",
                        "impact": [{"impactedResources": [RESOURCE_ID]}]
                    }
                }
            ]
        }),
    )
}

fn provider(
    transport: RecordingAzureResourceHealthTransport,
) -> AzureResourceHealthProvider<RecordingAzureResourceHealthTransport> {
    AzureResourceHealthProvider::new(scope(), secret(), transport).expect("provider")
}

#[test]
fn bounded_read_proposal_record_and_mission_projection_are_honest() {
    let transport = RecordingAzureResourceHealthTransport::new(availability("Available"), events());
    let mut service = AzureResourceHealthService::new(provider(transport)).expect("service");
    let mut consumer = MissionAzureResourceHealthConsumer::new(scope());

    let result = consumer.read(&mut service).expect("mission result");
    assert_eq!(
        result.state,
        hartevo_azure_resource_health_result_plugin::MissionAzureResourceHealthState::Complete
    );
    assert!(result.decision_ready);
    assert_eq!(
        result
            .proposal
            .evidence
            .availability
            .as_ref()
            .unwrap()
            .status,
        AvailabilityState::Available
    );
    assert_eq!(
        result.proposal.evidence.events[0].status,
        EventStatus::Active
    );
    assert_eq!(
        result.proposal.evidence.events[1].status,
        EventStatus::Resolved
    );
    assert!(result.proposal.evidence.next_cursor_digest.is_some());
    assert!(!result.native && !result.connected && !result.outcome_authority);
    assert_eq!(
        service.provider().transport_provenance(),
        TransportProvenance::Recording
    );
    assert_eq!(service.provider().transport().requests().len(), 2);
    assert!(
        service
            .provider()
            .transport()
            .requests()
            .iter()
            .all(|request| request.method == "GET"
                && request.query.contains("api-version=2025-05-01")
                && request.scope_digest == *scope().scope_digest())
    );

    let serialized = serde_json::to_string(&result).expect("safe result serializes");
    assert!(!serialized.contains("private detailed status"));
    assert!(!serialized.contains("private event description"));
    assert!(!serialized.contains("restart the VM"));
    assert!(!serialized.contains("keyring/entra/resource-health"));
    assert!(!format!("{service:?}").contains("keyring/entra/resource-health"));

    let record = service.record(&result.proposal).expect("record");
    assert!(record.recorded);
    assert!(!record.durable_native_receipt);
    let verification = service.verify(&result.proposal).expect("verify");
    assert!(verification.verified);
    assert!(!verification.independent_native_readback);
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_native_or_connected() {
    let fixture = FixtureAzureResourceHealthTransport::new(availability("Available"), events());
    assert!(!fixture.provenance().is_native());
    assert!(!fixture.provenance().is_connected());

    let provider = AzureResourceHealthProvider::new(scope(), secret(), fixture).expect("provider");
    let mut service = AzureResourceHealthService::new(provider).expect("service");
    let proposal = service.propose().expect("fixture proposal");
    assert!(!proposal.native_provider && !proposal.connected);

    let blocked =
        AzureResourceHealthProvider::new(scope(), secret(), BlockedEnvAzureResourceHealthTransport)
            .expect("blocked provider");
    let mut blocked_service = AzureResourceHealthService::new(blocked).expect("blocked service");
    let blocked_proposal = blocked_service
        .propose()
        .expect("blocked evidence proposal");
    assert_eq!(
        blocked_proposal.state,
        hartevo_azure_resource_health_result_plugin::EvidenceState::AccessLost
    );
    assert!(!blocked_proposal.decision_ready);
    assert!(!blocked_proposal.native_provider && !blocked_proposal.connected);
    assert_eq!(
        blocked_service.provider().transport_provenance(),
        TransportProvenance::BlockedEnv
    );
}

#[test]
fn status_unknown_window_mismatch_http_and_redaction_fail_closed() {
    let unknown_transport = RecordingAzureResourceHealthTransport::new(
        availability("Unknown"),
        AzureResourceHealthResponse::json(200, &json!({"value": []})),
    );
    let mut unknown_service =
        AzureResourceHealthService::new(provider(unknown_transport)).expect("service");
    let unknown = unknown_service.propose().expect("unknown proposal");
    assert_eq!(
        unknown.evidence.availability.as_ref().unwrap().status,
        AvailabilityState::Unknown
    );
    assert!(!unknown.decision_ready);

    let out_of_window = AzureResourceHealthResponse::json(
        200,
        &json!({
            "value": [{
                "id": "event-outside",
                "properties": {
                    "status": "Active",
                    "impactStartTime": "2026-08-03T00:00:00Z",
                    "impact": []
                }
            }]
        }),
    );
    let mut mismatch_service = AzureResourceHealthService::new(provider(
        RecordingAzureResourceHealthTransport::new(availability("Available"), out_of_window),
    ))
    .expect("service");
    let mismatch = mismatch_service.propose().expect("mismatch proposal");
    assert_eq!(
        mismatch.state,
        hartevo_azure_resource_health_result_plugin::EvidenceState::Unknown
    );
    assert!(!mismatch.decision_ready);

    let mut unauthorized_service =
        AzureResourceHealthService::new(provider(RecordingAzureResourceHealthTransport::new(
            AzureResourceHealthResponse::new(403, b"{\"message\":\"tenant pii\"}".to_vec()),
            events(),
        )))
        .expect("service");
    let unauthorized = unauthorized_service
        .propose()
        .expect("access-loss proposal");
    assert_eq!(
        unauthorized.state,
        hartevo_azure_resource_health_result_plugin::EvidenceState::AccessLost
    );
    assert!(
        !serde_json::to_string(&unauthorized)
            .unwrap()
            .contains("tenant pii")
    );
}

#[test]
fn registration_rotation_tamper_replay_and_cursor_scope_are_rejected() {
    let mut service = AzureResourceHealthService::new(provider(
        RecordingAzureResourceHealthTransport::new(availability("Available"), events()),
    ))
    .expect("service");
    let proposal = service.propose().expect("proposal");
    let original_registration = proposal.registration_digest.clone();
    let original_evidence = proposal.evidence_digest.clone();

    let mut tampered = proposal.clone();
    tampered.evidence_digest = Digest::from_text("tampered");
    assert!(service.verify(&tampered).is_err());

    let mut consumer = MissionAzureResourceHealthConsumer::new(scope());
    consumer.consume(proposal.clone()).expect("consume");
    assert!(consumer.consume(proposal).is_err());

    let revocation = service.revoke_registration().expect("revoke");
    assert_eq!(
        revocation.previous_registration_digest,
        original_registration
    );
    assert_ne!(revocation.registration_digest, original_registration);
    assert!(service.verify(&tampered).is_err());
    service.restore_registration().expect("restore");
    assert_ne!(
        service.registration().registration_digest,
        original_registration
    );
    assert_ne!(
        service.registration().registration_digest,
        original_evidence
    );

    let cursor =
        hartevo_azure_resource_health_result_plugin::OpaquePageCursor::new("opaque-page-2")
            .expect("cursor");
    let read = service
        .provider_mut()
        .read_event_list(Some(&cursor))
        .expect("bound cursor read");
    assert_eq!(read.events.len(), 2);
    let request = service.provider().transport().requests().last().unwrap();
    assert_eq!(request.operation, AzureResourceHealthOperation::EventList);
    assert_eq!(request.cursor_digest.as_ref(), Some(cursor.digest()));
    assert_eq!(contract_digest(), service.registration().contract_digest);
}

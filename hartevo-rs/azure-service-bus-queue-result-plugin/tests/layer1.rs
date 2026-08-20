use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

use hartevo_azure_service_bus_queue_result_plugin::{
    ARM_QUEUE_GET_PATH_TEMPLATE, ARM_QUEUE_LIST_PATH_TEMPLATE, AzureServiceBusHttpResponse,
    AzureServiceBusProvider, AzureServiceBusProviderError, AzureServiceBusQueueResultService,
    AzureServiceBusReadPage, AzureServiceBusReadRequest, AzureServiceBusScope,
    BlockedEnvAzureServiceBusTransport, FixtureAzureServiceBusTransport,
    MissionAzureServiceBusConsumer, OpaqueContinuation, PermissionFence, ProviderRevision,
    QueueConfigurationProjection, QueueCountProjection, QueuePostureProjection, QueuePostureState,
    QueueStatus, RecordingAzureServiceBusTransport, Revision, SecretReference, TransportError,
    TransportProvenance, contract_digest,
};

const TENANT: &str = "11111111-1111-1111-1111-111111111111";
const SUBSCRIPTION: &str = "22222222-2222-2222-2222-222222222222";
const API_REVISION: &str = "servicebus-queues-get-list-2026-01-01-r1";
const TEST_AT: i64 = 1_762_000_000;

fn scope() -> AzureServiceBusScope {
    let permission = PermissionFence::readonly(
        hartevo_azure_service_bus_queue_result_plugin::PermissionId::new("permission-01")
            .expect("permission id"),
        Revision::new(1).expect("permission revision"),
    )
    .expect("permission");
    AzureServiceBusScope::from_values(
        TENANT,
        SUBSCRIPTION,
        "rg-posture",
        "namespace-01",
        3,
        "handoff-queue",
        7,
        true,
        2,
        "project-01",
        11,
        "mission-01",
        13,
        "work-product-01",
        17,
        permission.digest(),
    )
    .expect("scope")
}

fn secret(scope: &AzureServiceBusScope) -> SecretReference {
    SecretReference::new(
        "entra-keyring-handle-01",
        scope,
        Revision::new(5).expect("secret revision"),
    )
    .expect("secret")
}

fn request(scope: &AzureServiceBusScope) -> AzureServiceBusReadRequest {
    AzureServiceBusReadRequest::get_queue(scope, None).expect("request")
}

fn provider_revision() -> ProviderRevision {
    ProviderRevision::new(API_REVISION).expect("provider revision")
}

fn page(
    request: &AzureServiceBusReadRequest,
    scope: &AzureServiceBusScope,
    next: Option<OpaqueContinuation>,
) -> hartevo_azure_service_bus_queue_result_plugin::AzureServiceBusReadPage {
    AzureServiceBusReadPage::new(
        request,
        vec![QueuePostureProjection::fixture(scope, QueueStatus::Active)],
        next,
        512,
        provider_revision(),
        TransportProvenance::Recording,
    )
    .expect("page")
}

fn recorded_service(
    scope: &AzureServiceBusScope,
    responses: impl IntoIterator<
        Item = Result<
            hartevo_azure_service_bus_queue_result_plugin::AzureServiceBusReadPage,
            TransportError,
        >,
    >,
) -> AzureServiceBusQueueResultService<RecordingAzureServiceBusTransport> {
    let mut transport = RecordingAzureServiceBusTransport::new();
    for response in responses {
        transport.push_response(response);
    }
    let provider = AzureServiceBusProvider::new(transport).expect("provider");
    AzureServiceBusQueueResultService::new(
        scope.clone(),
        secret(scope),
        PermissionFence::readonly(
            hartevo_azure_service_bus_queue_result_plugin::PermissionId::new("permission-01")
                .expect("permission id"),
            Revision::new(1).expect("permission revision"),
        )
        .expect("permission"),
        provider,
    )
    .expect("service")
}

fn arm_queue_json(scope: &AzureServiceBusScope) -> Value {
    json!({
        "name": scope.queue().name.as_str(),
        "type": "Microsoft.ServiceBus/Namespaces/Queues",
        "id": format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.ServiceBus/namespaces/{}/queues/{}",
            scope.subscription_id().as_str(),
            scope.resource_group_name().as_str(),
            scope.namespace().name.as_str(),
            scope.queue().name.as_str()
        ),
        "location": "eastus",
        "properties": {
            "status": "Active",
            "messageCount": 12,
            "sizeInBytes": 4096,
            "countDetails": {
                "activeMessageCount": 9,
                "deadLetterMessageCount": 2,
                "scheduledMessageCount": 1,
                "transferDeadLetterMessageCount": 0,
                "transferMessageCount": 0
            },
            "defaultMessageTimeToLive": "PT24H",
            "autoDeleteOnIdle": "PT1H",
            "duplicateDetectionHistoryTimeWindow": "PT10M",
            "lockDuration": "PT1M",
            "requiresSession": false,
            "enablePartitioning": true,
            "requiresDuplicateDetection": true,
            "deadLetteringOnMessageExpiration": true,
            "maxDeliveryCount": 10,
            "maxSizeInMegabytes": 1024,
            "maxMessageSizeInKilobytes": 1024,
            "updatedAt": "2026-08-15T05:00:00Z",
            "createdAt": "2026-08-14T05:00:00Z",
            "forwardTo": "https://secret.endpoint.invalid",
            "userMetadata": "customer PII",
            "authorizationRules": [{"primaryKey": "secret-key"}],
            "connectionString": "Endpoint=sb://private.servicebus.windows.net/;SharedAccessKey=secret"
        },
        "message": {"body": "do not retain", "properties": {"customer": "pii"}},
        "lockToken": "lock-token-secret",
        "sessionState": "private-session-state"
    })
}

#[test]
fn exact_scope_and_read_only_api_seam_are_bound() {
    let scope = scope();
    let request = request(&scope);
    assert_eq!(
        request.path_template(),
        "/subscriptions/<opaque>/resourceGroups/<opaque>/providers/Microsoft.ServiceBus/namespaces/<opaque>/queues/<opaque>"
    );
    assert!(ARM_QUEUE_GET_PATH_TEMPLATE.contains("queues/{queueName}"));
    assert!(ARM_QUEUE_LIST_PATH_TEMPLATE.ends_with("/queues"));
    assert_eq!(
        request.operation().api_name(),
        "Microsoft.ServiceBus/namespaces/queues/read"
    );
    assert!(request.query_digest() != scope.digest());
    assert_eq!(
        scope.namespace().revision,
        Revision::new(3).expect("revision")
    );
    assert_eq!(scope.queue().revision, Revision::new(7).expect("revision"));
    assert_eq!(
        scope.dead_letter().revision,
        Revision::new(2).expect("revision")
    );
    assert_eq!(
        scope.project().revision,
        Revision::new(11).expect("revision")
    );
    assert_eq!(
        scope.mission().revision,
        Revision::new(13).expect("revision")
    );
    assert_eq!(
        scope.work_product().revision,
        Revision::new(17).expect("revision")
    );
}

#[test]
fn scope_and_secret_serialization_are_digest_only() {
    let scope = scope();
    let secret = secret(&scope);
    let scope_json = serde_json::to_string(&scope).expect("scope JSON");
    let secret_json = serde_json::to_string(&secret).expect("secret JSON");
    let debug = format!("{secret:?}");
    for forbidden in [
        TENANT,
        SUBSCRIPTION,
        "rg-posture",
        "namespace-01",
        "handoff-queue",
        "entra-keyring-handle-01",
    ] {
        assert!(!scope_json.contains(forbidden), "scope leaked {forbidden}");
        assert!(
            !secret_json.contains(forbidden),
            "secret leaked {forbidden}"
        );
        assert!(!debug.contains(forbidden), "debug leaked {forbidden}");
    }
    assert!(secret_json.contains("opaque"));
    assert!(format!("{scope:?}").contains("scope_digest"));
}

#[test]
fn official_json_is_bounded_and_redacted_to_queue_posture() {
    let scope = scope();
    let request = request(&scope);
    let body = arm_queue_json(&scope).to_string();
    let page = AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_page(
        &request,
        200,
        body.as_bytes(),
        provider_revision(),
        TransportProvenance::Recording,
    )
    .expect("parsed page");
    assert_eq!(page.queues.len(), 1);
    let projection = &page.queues[0];
    assert_eq!(projection.status, QueueStatus::Active);
    assert_eq!(projection.counts.message_count, Some(12));
    assert_eq!(projection.counts.dead_letter_message_count, Some(2));
    assert_eq!(
        projection.configuration.default_message_ttl_seconds,
        Some(86_400)
    );
    assert!(projection.complete);
    let serialized = serde_json::to_string(&page).expect("page JSON");
    for forbidden in [
        "Microsoft.ServiceBus/Namespaces/Queues",
        "subscriptions/",
        "https://secret.endpoint.invalid",
        "customer PII",
        "secret-key",
        "Endpoint=sb://",
        "do not retain",
        "lock-token-secret",
        "private-session-state",
    ] {
        assert!(!serialized.contains(forbidden), "page leaked {forbidden}");
    }
    assert!(serialized.contains("queueNameDigest"));
}

#[test]
fn list_pagination_uses_opaque_bound_continuation() {
    let scope = scope();
    let first_request =
        AzureServiceBusReadRequest::list_queues(&scope, None).expect("list request");
    let continuation = OpaqueContinuation::new(
        "https://management.azure.com/private/nextLink?sig=secret&resourceId=/subscriptions/secret",
    )
    .expect("continuation");
    let first = AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_page(
        &first_request,
        200,
        json!({"value": [{"name": "other-queue", "id": "/subscriptions/other/resourceGroups/other/providers/Microsoft.ServiceBus/namespaces/other/queues/other-queue"}], "nextLink": "https://management.azure.com/private/nextLink?sig=secret"}).to_string().as_bytes(),
        provider_revision(),
        TransportProvenance::Recording,
    )
    .expect("first list page");
    assert!(first.queues.is_empty());
    assert!(first.next_continuation.is_some());
    let next_request = first_request
        .with_continuation(Some(continuation))
        .expect("bound continuation");
    assert_eq!(next_request.page_number(), 2);
    assert!(
        serde_json::to_string(&next_request)
            .expect("request JSON")
            .contains("opaque")
    );
    assert!(!format!("{next_request:?}").contains("management.azure.com"));
}

#[test]
fn stale_continuation_binding_is_rejected() {
    let scope = scope();
    let other = AzureServiceBusReadRequest::list_queues(&scope, None)
        .expect("request")
        .query_digest();
    let cursor = OpaqueContinuation::new("cursor-secret")
        .expect("cursor")
        .bind(&other);
    let get = AzureServiceBusReadRequest::get_queue(&scope, Some(cursor));
    assert!(matches!(
        get,
        Err(hartevo_azure_service_bus_queue_result_plugin::ModelError::ScopeMismatch { .. })
    ));
}

#[test]
fn status_and_missing_configuration_fail_closed() {
    let scope = scope();
    let mut body = arm_queue_json(&scope);
    body["properties"]["status"] = json!("SendDisabled");
    let request = request(&scope);
    let page = AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_page(
        &request,
        200,
        body.to_string().as_bytes(),
        provider_revision(),
        TransportProvenance::Recording,
    )
    .expect("send-disabled page");
    assert_eq!(page.queues[0].status, QueueStatus::SendDisabled);

    let incomplete = json!({
        "name": scope.queue().name.as_str(),
        "properties": {"status": "Active"}
    });
    let incomplete_page =
        AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_page(
            &request,
            200,
            incomplete.to_string().as_bytes(),
            provider_revision(),
            TransportProvenance::Recording,
        )
        .expect("incomplete page");
    assert!(!incomplete_page.queues[0].complete);
}

#[test]
fn scope_drift_and_bounds_fail_closed_without_payload_leakage() {
    let scope = scope();
    let request = request(&scope);
    let mut drift = arm_queue_json(&scope);
    drift["id"] = json!(
        "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-posture/providers/Microsoft.ServiceBus/namespaces/namespace-01/queues/handoff-queue"
    );
    let drift_error =
        AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_page(
            &request,
            200,
            drift.to_string().as_bytes(),
            provider_revision(),
            TransportProvenance::Recording,
        )
        .expect_err("scope drift");
    assert!(matches!(
        drift_error,
        AzureServiceBusProviderError::Transport(TransportError::ScopeDrift)
    ));

    let mut too_large = arm_queue_json(&scope);
    too_large["properties"]["messageCount"] = json!(1_000_000_000_001_u64);
    let bound_error =
        AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_page(
            &request,
            200,
            too_large.to_string().as_bytes(),
            provider_revision(),
            TransportProvenance::Recording,
        )
        .expect_err("count bound");
    assert!(matches!(
        bound_error,
        AzureServiceBusProviderError::Transport(TransportError::BoundExceeded)
    ));

    let mut oversized_queue = arm_queue_json(&scope);
    oversized_queue["properties"]["maxSizeInMegabytes"] =
        json!(hartevo_azure_service_bus_queue_result_plugin::MAX_SIZE_MEGABYTES + 1);
    let size_bound_error =
        AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_page(
            &request,
            200,
            oversized_queue.to_string().as_bytes(),
            provider_revision(),
            TransportProvenance::Recording,
        )
        .expect_err("queue size bound");
    assert!(matches!(
        size_bound_error,
        AzureServiceBusProviderError::Transport(TransportError::BoundExceeded)
    ));

    let oversized =
        vec![b'x'; hartevo_azure_service_bus_queue_result_plugin::MAX_RESPONSE_BYTES + 1];
    let oversized_error =
        AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_page(
            &request,
            200,
            &oversized,
            provider_revision(),
            TransportProvenance::Recording,
        )
        .expect_err("response bound");
    assert!(matches!(
        oversized_error,
        AzureServiceBusProviderError::Transport(TransportError::BoundExceeded)
    ));
}

#[test]
fn http_failures_map_to_typed_non_leaking_errors() {
    let scope = scope();
    let request = request(&scope);
    for (status, expected) in [
        (401, TransportError::Unauthorized),
        (403, TransportError::Forbidden),
        (404, TransportError::NotFound),
        (400, TransportError::InvalidRequest),
        (
            500,
            TransportError::ServerFailure {
                status_code: Some(500),
            },
        ),
    ] {
        let response = AzureServiceBusHttpResponse::new(
            status,
            br#"{"error":{"message":"private endpoint","authorization":"secret"}}"#,
        );
        let error =
            AzureServiceBusProvider::<RecordingAzureServiceBusTransport>::parse_json_response(
                &request,
                &response,
                provider_revision(),
                TransportProvenance::Recording,
            )
            .expect_err("HTTP failure");
        assert_eq!(error, AzureServiceBusProviderError::Transport(expected));
        assert!(!error.to_string().contains("private endpoint"));
        assert!(!error.to_string().contains("secret"));
    }
}

#[test]
fn service_pagination_partial_access_and_provider_unknown_are_typed() {
    let scope = scope();
    let first_request = request(&scope);
    let cursor = OpaqueContinuation::new("opaque-page-2").expect("cursor");
    let first = page(&first_request, &scope, Some(cursor.clone()));
    let second_request = first_request
        .with_continuation(Some(cursor))
        .expect("second request");
    let second = page(&second_request, &scope, None);
    let mut service = recorded_service(&scope, [Ok(first), Ok(second)]);
    let result = service.read(first_request).expect("read");
    assert_eq!(result.evidence.state, QueuePostureState::Active);
    assert_eq!(result.evidence.page_count, 2);
    assert_eq!(result.page_digests.len(), 2);
    assert!(!result.evidence.connected);
    assert!(!result.evidence.native);
    assert!(!result.evidence.first_party);

    let request = request(&scope);
    let mut access_service = recorded_service(&scope, [Err(TransportError::Forbidden)]);
    let access = access_service
        .read(request.clone())
        .expect("access evidence");
    assert_eq!(access.evidence.state, QueuePostureState::AccessLost);

    let mut unknown_service = recorded_service(&scope, [Err(TransportError::InvalidRequest)]);
    let unknown = unknown_service.read(request).expect("unknown evidence");
    assert_eq!(unknown.evidence.state, QueuePostureState::ProviderUnknown);
}

#[test]
fn continuation_replay_and_conflicting_projection_fail_closed() {
    let scope = scope();
    let first_request = request(&scope);
    let cursor = OpaqueContinuation::new("same-cursor").expect("cursor");
    let first = page(&first_request, &scope, Some(cursor.clone()));
    let second_request = first_request
        .with_continuation(Some(cursor.clone()))
        .expect("second request");
    let second = page(&second_request, &scope, Some(cursor));
    let mut replay_service = recorded_service(&scope, [Ok(first), Ok(second)]);
    let replay = replay_service.read(first_request).expect("replay evidence");
    assert_eq!(replay.evidence.state, QueuePostureState::Partial);
    assert_eq!(
        replay.evidence.partial_reason,
        Some(hartevo_azure_service_bus_queue_result_plugin::PartialReason::ContinuationReplay)
    );

    let first_request = request(&scope);
    let cursor = OpaqueContinuation::new("conflict-cursor").expect("cursor");
    let second_request = first_request
        .with_continuation(Some(cursor.clone()))
        .expect("second request");
    let mut tampered_projection = QueuePostureProjection::fixture(&scope, QueueStatus::Active);
    tampered_projection.status = QueueStatus::Disabled;
    tampered_projection.posture_digest = tampered_projection.recomputed_digest();
    let conflicting = AzureServiceBusReadPage::new(
        &second_request,
        vec![tampered_projection],
        None,
        512,
        provider_revision(),
        TransportProvenance::Recording,
    )
    .expect("conflicting page");
    let first = page(&first_request, &scope, Some(cursor));
    let mut conflict_service = recorded_service(&scope, [Ok(first), Ok(conflicting)]);
    let conflict = conflict_service
        .read(first_request)
        .expect("conflict evidence");
    assert_eq!(conflict.evidence.state, QueuePostureState::Partial);
    assert_eq!(
        conflict.evidence.partial_reason,
        Some(hartevo_azure_service_bus_queue_result_plugin::PartialReason::ProviderConflict)
    );
}

#[test]
fn registration_is_reversible_and_digest_bound() {
    let scope = scope();
    let request = request(&scope);
    let first = page(&request, &scope, None);
    let mut service = recorded_service(&scope, [Ok(first)]);
    let registration_digest = service.registration().registration_digest.clone();
    assert!(service.is_active());
    service.revoke_registration().expect("revoke");
    assert!(!service.is_active());
    assert_eq!(
        service.registration().state,
        hartevo_azure_service_bus_queue_result_plugin::AzureServiceBusRegistrationState::Revoked
    );
    assert_ne!(
        service.registration().registration_digest,
        registration_digest
    );
    let error = service.read(request).expect_err("revoked read");
    assert!(matches!(
        error,
        hartevo_azure_service_bus_queue_result_plugin::AzureServiceBusQueueResultServiceError::RegistrationRevoked
    ));

    let scope_two = scope.clone();
    let request_two = AzureServiceBusReadRequest::get_queue(&scope_two, None).expect("request");
    let first = page(&request_two, &scope_two, None);
    let mut secret_service = recorded_service(&scope_two, [Ok(first)]);
    secret_service.revoke_secret().expect("revoke secret");
    let error = secret_service
        .read(request_two)
        .expect_err("secret revoked");
    assert!(matches!(
        error,
        hartevo_azure_service_bus_queue_result_plugin::AzureServiceBusQueueResultServiceError::SecretRevoked
    ));
}

#[test]
fn proposal_record_verification_and_mission_consumer_are_non_authoritative() {
    let scope = scope();
    let request = request(&scope);
    let first = page(&request, &scope, None);
    let mut service = recorded_service(&scope, [Ok(first)]);
    let proposed_at = Utc.timestamp_opt(TEST_AT, 0).single().expect("timestamp");
    let proposal = service.propose(request, proposed_at).expect("proposal");
    assert_eq!(proposal.state, QueuePostureState::Active);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.truth_authority);
    assert!(!proposal.consent_authority);
    assert!(!proposal.effect_authority);
    assert!(!proposal.receipt_authority);
    assert!(!proposal.verification_authority);
    assert!(!proposal.outcome_authority);
    assert!(!proposal.queue_count_is_delivery_verification);

    let receipt = service.record_at(&proposal, proposed_at).expect("record");
    assert!(receipt.recorded);
    assert!(!receipt.durable_receipt);
    assert!(!receipt.receipt_authority);
    let verified = service.verify(&receipt).expect("local verification");
    assert!(verified.verified);
    assert!(!verified.verification_authority);
    assert!(!verified.adopted_outcome);

    let before_proposal = proposed_at - chrono::Duration::seconds(1);
    assert!(matches!(
        service.record_at(&proposal, before_proposal),
        Err(hartevo_azure_service_bus_queue_result_plugin::AzureServiceBusQueueResultServiceError::Model(
            hartevo_azure_service_bus_queue_result_plugin::ModelError::Invalid {
                field: "timestamp ordering"
            }
        ))
    ));

    let mut consumer =
        MissionAzureServiceBusConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    let mission_result = consumer.consume(proposal.clone()).expect("consume");
    assert_eq!(mission_result.observed_state, QueuePostureState::Active);
    assert!(mission_result.requires_human_review);
    assert!(!mission_result.safe_to_promote);
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    assert!(!mission_result.first_party);
    assert!(!mission_result.truth_authority);
    assert!(!mission_result.consent_authority);
    assert!(!mission_result.effect_authority);
    assert!(!mission_result.receipt_authority);
    assert!(!mission_result.verification_authority);
    assert!(!mission_result.outcome_authority);
    assert!(!mission_result.adopted_outcome);
    assert!(matches!(
        consumer.consume(proposal),
        Err(hartevo_azure_service_bus_queue_result_plugin::ConsumerError::Replay)
    ));
}

#[test]
fn stale_mission_and_tampered_proposal_fail_closed() {
    let scope = scope();
    let request = request(&scope);
    let first = page(&request, &scope, None);
    let mut service = recorded_service(&scope, [Ok(first)]);
    let proposal = service.propose_now(request).expect("proposal");
    let mut consumer =
        MissionAzureServiceBusConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    let mut tampered = proposal.clone();
    tampered.native = true;
    assert!(matches!(
        consumer.consume(tampered),
        Err(hartevo_azure_service_bus_queue_result_plugin::ConsumerError::ProposalTampered)
    ));

    let stale_scope = AzureServiceBusScope::from_values(
        TENANT,
        SUBSCRIPTION,
        "rg-posture",
        "namespace-01",
        3,
        "handoff-queue",
        7,
        true,
        2,
        "project-01",
        11,
        "mission-01",
        14,
        "work-product-01",
        17,
        scope.permission_digest().clone(),
    )
    .expect("stale scope");
    assert!(matches!(
        MissionAzureServiceBusConsumer::new(stale_scope, service.registration().clone()),
        Err(hartevo_azure_service_bus_queue_result_plugin::ConsumerError::ScopeMismatch)
    ));
}

#[test]
fn blocked_fixture_and_loopback_are_always_non_native() {
    let scope = scope();
    let blocked_provider =
        AzureServiceBusProvider::new(BlockedEnvAzureServiceBusTransport).expect("blocked");
    assert!(!blocked_provider.identity().connected);
    assert!(!blocked_provider.identity().native);
    assert!(!blocked_provider.identity().first_party);
    let request = request(&scope);
    let mut blocked_service = AzureServiceBusQueueResultService::new(
        scope.clone(),
        secret(&scope),
        PermissionFence::readonly(
            hartevo_azure_service_bus_queue_result_plugin::PermissionId::new("permission-01")
                .expect("permission id"),
            Revision::new(1).expect("permission revision"),
        )
        .expect("permission"),
        blocked_provider,
    )
    .expect("blocked service");
    let blocked = blocked_service.read(request).expect("blocked evidence");
    assert_eq!(blocked.evidence.state, QueuePostureState::ProviderUnknown);
    assert_eq!(blocked.evidence.provenance, TransportProvenance::BlockedEnv);
    assert!(!blocked.evidence.connected);
    assert!(!blocked.evidence.native);
    assert!(!blocked.evidence.first_party);

    let fixture_provider = AzureServiceBusProvider::new(FixtureAzureServiceBusTransport::new())
        .expect("fixture provider");
    assert!(!fixture_provider.identity().connected);
    assert!(!fixture_provider.identity().native);
    assert!(!fixture_provider.identity().first_party);
}

#[test]
fn tampered_page_and_digest_validation_are_fail_closed() {
    let scope = scope();
    let request = request(&scope);
    let mut projection = QueuePostureProjection::fixture(&scope, QueueStatus::Active);
    projection.queue_scope_revision = Revision::new(8).expect("stale revision");
    let page = AzureServiceBusReadPage::new(
        &request,
        vec![projection],
        None,
        512,
        provider_revision(),
        TransportProvenance::Recording,
    )
    .expect("page");
    let mut transport = RecordingAzureServiceBusTransport::new();
    transport.push_response(Ok(page));
    let provider = AzureServiceBusProvider::new(transport).expect("provider");
    let permission = PermissionFence::readonly(
        hartevo_azure_service_bus_queue_result_plugin::PermissionId::new("permission-01")
            .expect("permission id"),
        Revision::new(1).expect("permission revision"),
    )
    .expect("permission");
    let mut service =
        AzureServiceBusQueueResultService::new(scope.clone(), secret(&scope), permission, provider)
            .expect("service");
    assert!(matches!(
        service.read(request),
        Err(hartevo_azure_service_bus_queue_result_plugin::AzureServiceBusQueueResultServiceError::Provider(_))
    ));

    let contract =
        serde_json::from_str::<Value>(hartevo_azure_service_bus_queue_result_plugin::CONTRACT_JSON)
            .expect("contract JSON");
    assert_eq!(
        contract["contractVersion"],
        "EXT-AZURE-SERVICE-BUS-01-L1/v1"
    );
    assert_eq!(contract_digest().as_str().len(), 64);
    assert_eq!(QueueCountProjection::empty().message_count, None);
    assert_eq!(QueueConfigurationProjection::empty().requires_session, None);
}

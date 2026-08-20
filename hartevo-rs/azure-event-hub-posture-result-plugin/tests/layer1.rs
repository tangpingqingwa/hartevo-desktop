use chrono::{Duration, Utc};
use hartevo_azure_event_hub_posture_result_plugin as plugin;
use plugin::{
    AzureConsumerGroupName, AzureEventHubEvidenceState, AzureEventHubName,
    AzureEventHubNamespaceName, AzureEventHubOperation, AzureEventHubPostureResultError,
    AzureEventHubPostureResultService, AzureEventHubPostureScope, AzureEventHubsProvider,
    BlockedEnvTransport, ConsentScope, ConsumerGroupPostureProjection, Cursor,
    EventHubPostureProjection, FixtureTransport, GetConsumerGroupRequest, GetEventHubRequest,
    GetNamespaceRequest, ListConsumerGroupsRequest, ListConsumerGroupsResponse,
    MissionAzureEventHubPostureConsumer, MissionIdentity, PermissionSnapshot, ProjectIdentity,
    ProposalDisposition, RecordingTransport, RegistrationStatus, ResourceGroupName,
    SecretReference, SubscriptionId, TenantId, TransportProvenance, WorkProductIdentity,
};

fn scope() -> AzureEventHubPostureScope {
    AzureEventHubPostureScope::new(
        TenantId::new("tenant-01").expect("tenant"),
        SubscriptionId::new("subscription-01").expect("subscription"),
        ResourceGroupName::new("resource-group-01").expect("resource group"),
        AzureEventHubNamespaceName::new("namespace-01").expect("namespace"),
        AzureEventHubName::new("event-hub-01").expect("event hub"),
        AzureConsumerGroupName::new("consumer-group-01").expect("consumer group"),
        MissionIdentity::new("mission-01", 1).expect("mission"),
        ProjectIdentity::new("project-01", 2).expect("project"),
        WorkProductIdentity::new("work-product-01", 3).expect("work product"),
    )
    .expect("scope")
}

fn now() -> chrono::DateTime<Utc> {
    Utc::now()
}

fn fixture_service() -> AzureEventHubPostureResultService<FixtureTransport> {
    let observed_at = now();
    let scope = scope();
    let secret = SecretReference::entra("opaque-secret-handle", &scope, 1).expect("secret");
    let consent = ConsentScope::for_layer_one("consent-01", 1, observed_at + Duration::hours(1))
        .expect("consent");
    let provider = AzureEventHubsProvider::new(FixtureTransport::for_scope(&scope, observed_at))
        .expect("provider");
    AzureEventHubPostureResultService::new(scope, secret, consent, provider, observed_at)
        .expect("service")
}

#[test]
fn contract_exposes_only_layer_one_authority() {
    let contract = plugin::AzureEventHubPostureContract::baseline().expect("contract");
    assert_eq!(contract.digest().as_str(), plugin::CONTRACT_DIGEST);
    assert!(!plugin::Layer1Authority::connected());
    assert!(!plugin::Layer1Authority::native());
    assert!(!plugin::Layer1Authority::first_party());
    assert!(!plugin::Layer1Authority::durable_provider_receipt());
    assert!(!plugin::Layer1Authority::outcome_adoption());
    assert!(!plugin::Layer1Authority::work_product_adoption());
}

#[test]
fn fixture_produces_redacted_review_only_proposal_and_local_recording() {
    let mut service = fixture_service();
    let request = service.default_request(now()).expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, AzureEventHubEvidenceState::Ready);
    assert!(proposal.list_complete);
    assert!(proposal.posture.is_some());
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert!(serialized.contains("statusDigest"));
    assert!(!serialized.contains("namespace-01"));
    assert!(!serialized.contains("servicebus.windows.net"));
    assert!(!serialized.contains("fixture-user-metadata"));
    assert!(!serialized.contains("opaque-secret-handle"));
    assert!(!serialized.contains("rawBody"));

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer
        .consume(&proposal, "recording-key-01")
        .expect("record");
    assert_eq!(result.disposition, ProposalDisposition::Ready);
    assert!(!result.can_be_adopted());
    assert!(result.is_review_only());
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.provider_receipt);
    assert_eq!(consumer.record_count(), 1);
    let replay = consumer
        .consume(&proposal, "recording-key-01")
        .expect("replay");
    assert_eq!(replay.result_digest, result.result_digest);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn registration_is_reversible_revocable_and_secret_revocation_fails_closed() {
    let mut service = fixture_service();
    assert!(AzureEventHubPostureResultService::<FixtureTransport>::registration_reversible());
    assert!(AzureEventHubPostureResultService::<FixtureTransport>::registration_revocable());
    assert_eq!(service.registration().status(), RegistrationStatus::Active);
    service.revoke().expect("revoke");
    assert_eq!(service.registration().status(), RegistrationStatus::Revoked);
    let error = service.propose(service.default_request(now()).expect("request"));
    assert_eq!(
        error,
        Err(AzureEventHubPostureResultError::RegistrationInactive)
    );
    service.restore_registration().expect("restore");
    service.reverse().expect("reverse");
    assert_eq!(
        service.registration().status(),
        RegistrationStatus::Reversed
    );
    assert_eq!(
        service.restore_registration(),
        Err(AzureEventHubPostureResultError::RegistrationReversed)
    );

    let observed_at = now();
    let fenced_scope = scope();
    let mut revoked_secret =
        SecretReference::entra("opaque-secret", &fenced_scope, 1).expect("secret");
    revoked_secret.revoke();
    let consent = ConsentScope::for_layer_one("consent-02", 1, observed_at + Duration::hours(1))
        .expect("consent");
    let provider =
        AzureEventHubsProvider::new(FixtureTransport::for_scope(&fenced_scope, observed_at))
            .expect("provider");
    assert!(matches!(
        AzureEventHubPostureResultService::new(
            fenced_scope,
            revoked_secret,
            consent,
            provider,
            observed_at,
        ),
        Err(AzureEventHubPostureResultError::SecretRevoked)
    ));
}

#[test]
fn management_paths_are_operation_specific_and_redacted() {
    let scope = scope();
    let namespace = GetNamespaceRequest::for_scope(&scope).expect("namespace request");
    let event_hub = GetEventHubRequest::for_scope(&scope).expect("event hub request");
    let consumer_group = GetConsumerGroupRequest::for_scope(&scope).expect("consumer request");
    let list = ListConsumerGroupsRequest::first(&scope, 10).expect("list request");
    for path in [
        namespace.path_and_query(),
        event_hub.path_and_query(),
        consumer_group.path_and_query(),
        list.path_and_query(),
    ] {
        assert!(!path.contains("tenant-01"));
        assert!(!path.contains("subscription-01"));
        assert!(!path.contains("resource-group-01"));
        assert!(!path.contains("namespace-01"));
        assert!(!path.contains("event-hub-01"));
        assert!(!path.contains("consumer-group-01"));
        assert!(path.contains("api-version=2024-01-01"));
    }
    assert!(namespace.path_and_query().contains("/namespaces/"));
    assert!(!namespace.path_and_query().contains("/eventhubs/"));
    assert!(event_hub.path_and_query().contains("/eventhubs/"));
    assert!(!event_hub.path_and_query().contains("/consumergroups/"));
    assert!(consumer_group.path_and_query().contains("/consumergroups/"));
    assert!(list.path_and_query().ends_with("$skiptoken="));
}

#[test]
fn blocked_environment_is_unknown_and_never_native() {
    let observed_at = now();
    let scope = scope();
    let secret = SecretReference::entra("opaque-secret", &scope, 1).expect("secret");
    let consent = ConsentScope::for_layer_one("consent-03", 1, observed_at + Duration::hours(1))
        .expect("consent");
    let provider = AzureEventHubsProvider::new(BlockedEnvTransport).expect("provider");
    let mut service =
        AzureEventHubPostureResultService::new(scope, secret, consent, provider, observed_at)
            .expect("service");
    let proposal = service
        .propose(service.default_request(observed_at).expect("request"))
        .expect("non-adopting failure proposal");
    assert_eq!(proposal.state, AzureEventHubEvidenceState::ProviderUnknown);
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn pagination_is_bounded_and_loops_are_rejected() {
    let scope = scope();
    let request = ListConsumerGroupsRequest::first(&scope, 1).expect("request");
    let first_cursor = Cursor::new("opaque-next-link-01", &scope, 2).expect("cursor");
    let group = ConsumerGroupPostureProjection::for_scope(&scope, "Active", None, "revision-01")
        .expect("group");
    assert_eq!(
        ListConsumerGroupsResponse::new(
            &request,
            vec![group.clone(), group.clone()],
            None,
            100,
            TransportProvenance::Recording,
        ),
        Err(AzureEventHubPostureResultError::PartialEvidence)
    );
    let response = ListConsumerGroupsResponse::new(
        &request,
        vec![group],
        Some(first_cursor.clone()),
        100,
        TransportProvenance::Recording,
    )
    .expect("first page");
    assert!(response.has_more());
    let next_request = ListConsumerGroupsRequest::new(&scope, 1, Some(first_cursor.clone()))
        .expect("next request");
    assert_eq!(
        ListConsumerGroupsResponse::new(
            &next_request,
            Vec::new(),
            Some(first_cursor),
            100,
            TransportProvenance::Recording,
        ),
        Err(AzureEventHubPostureResultError::PaginationLoop)
    );
}

#[test]
fn revision_fences_and_permission_snapshots_fail_closed() {
    let observed_at = now();
    let fenced_scope = scope()
        .with_revision_fences(Some("expected-namespace"), None::<String>, None::<String>)
        .expect("fenced scope");
    let secret = SecretReference::entra("opaque-secret", &fenced_scope, 1).expect("secret");
    let consent = ConsentScope::for_layer_one("consent-04", 1, observed_at + Duration::hours(1))
        .expect("consent");
    let provider =
        AzureEventHubsProvider::new(FixtureTransport::for_scope(&fenced_scope, observed_at))
            .expect("provider");
    let mut service = AzureEventHubPostureResultService::new(
        fenced_scope,
        secret,
        consent,
        provider,
        observed_at,
    )
    .expect("service");
    let proposal = service
        .propose(service.default_request(observed_at).expect("request"))
        .expect("stale proposal");
    assert_eq!(proposal.state, AzureEventHubEvidenceState::StaleState);
    assert!(!service.verify(&proposal).review_eligible);

    let permissions = PermissionSnapshot::for_layer_one(7);
    assert_eq!(permissions.permissions.len(), 4);
    assert!(
        permissions
            .permissions
            .contains("Microsoft.EventHub/namespaces/eventhubs/consumergroups/read")
    );
}

#[test]
fn projections_and_secret_debug_are_digest_only() {
    let scope = scope();
    let secret = SecretReference::entra("very-secret-handle", &scope, 9).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("very-secret-handle"));
    assert!(!debug.contains("serde"));
    assert!(debug.contains("reference_digest"));

    let namespace = plugin::NamespacePostureProjection::new(
        scope.namespace_digest(),
        "Active",
        "Succeeded",
        "Standard",
        1,
        Some("https://private.servicebus.windows.net/".to_owned()),
        Some("private user metadata".to_owned()),
        "revision-01",
    )
    .expect("namespace");
    let json = serde_json::to_string(&namespace).expect("namespace serializes");
    assert!(!json.contains("private.servicebus.windows.net"));
    assert!(!json.contains("private user metadata"));
    assert!(json.contains("serviceBusEndpointDigest"));

    let event_hub = EventHubPostureProjection::new(
        scope.event_hub_digest(),
        "Active",
        1,
        vec!["0".to_owned()],
        7,
        false,
        Some("capture configuration".to_owned()),
        Some("event metadata".to_owned()),
        "revision-01",
    )
    .expect("event hub");
    assert!(event_hub.status.is_known());
    assert!(!event_hub.capture_enabled);
    assert!(
        !serde_json::to_string(&event_hub)
            .expect("event hub serializes")
            .contains("capture configuration")
    );
}

#[test]
fn tampered_recording_is_rejected_by_provider() {
    let scope = scope();
    let request = GetNamespaceRequest::for_scope(&scope).expect("request");
    let namespace = plugin::NamespacePostureProjection::new(
        scope.namespace_digest(),
        "Active",
        "Succeeded",
        "Standard",
        1,
        None,
        None,
        "revision-01",
    )
    .expect("namespace");
    let response =
        plugin::GetNamespaceResponse::new(&request, namespace, 100, TransportProvenance::Recording)
            .expect("response")
            .with_declared_digest(plugin::Digest::from_text("tampered"));
    let mut transport = RecordingTransport::default();
    transport.push_namespace_response(Ok(response));
    let mut provider = AzureEventHubsProvider::new(transport).expect("provider");
    assert_eq!(
        provider.get_namespace(&request),
        Err(plugin::AzureEventHubTransportError::Tampered)
    );
    assert_eq!(
        request.recorded_request().operation,
        AzureEventHubOperation::GetNamespace
    );
}

#[test]
fn consumer_rejects_scope_and_replay_conflicts() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer: MissionAzureEventHubPostureConsumer = service.consumer().expect("consumer");
    let mut altered = proposal.clone();
    altered.list_complete = false;
    assert_eq!(
        consumer.consume(&altered, "conflict-key"),
        Err(AzureEventHubPostureResultError::TamperedEvidence)
    );
    let first = consumer.consume(&proposal, "conflict-key").expect("record");
    let replay = consumer
        .consume(&proposal, "conflict-key")
        .expect("replay result");
    assert_eq!(replay.result_digest, first.result_digest);
}

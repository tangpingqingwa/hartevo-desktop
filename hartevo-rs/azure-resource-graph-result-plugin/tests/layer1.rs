use std::collections::BTreeMap;

use hartevo_plugin_runtime::{
    MissionId as RuntimeMissionId, PluginRuntime, PluginScope, ProjectId as RuntimeProjectId,
};
use serde_json::json;

use graph::AzureResourceGraphTransport;
use hartevo_azure_resource_graph_result_plugin as graph;

fn scope() -> graph::AzureResourceGraphScope {
    graph::AzureResourceGraphScope::new(graph::AzureResourceGraphScopeInput {
        tenant_id: "tenant-1".to_owned(),
        target: graph::AzureResourceGraphTarget::subscriptions(["sub-1"]).expect("target"),
        resource_types: vec![
            graph::AzureResourceType::MicrosoftStorageStorageAccounts,
            graph::AzureResourceType::MicrosoftComputeVirtualMachines,
        ],
        properties: vec![
            graph::AzureResourceProperty::Kind,
            graph::AzureResourceProperty::Location,
            graph::AzureResourceProperty::PropertiesProvisioningState,
            graph::AzureResourceProperty::PropertiesSkuName,
        ],
        query_revision: 7,
        project: graph::ProjectBinding::new("project-1", 3).expect("project"),
        mission: graph::MissionBinding::new("mission-1", 4).expect("mission"),
        work_product: graph::WorkProductBinding::new("work-product-1", 5).expect("work product"),
        permission: graph::PermissionSnapshot::for_subscriptions(6).expect("permission"),
        consent: graph::ConsentScope::new("consent-1", 8).expect("consent"),
    })
    .expect("scope")
}

fn secret() -> graph::SecretReference {
    graph::SecretReference::new("keyring/entra/resource-graph", 9).expect("secret")
}

fn registration_request() -> graph::AzureResourceGraphRegistrationRequest {
    graph::AzureResourceGraphRegistrationRequest::baseline(scope(), secret())
        .expect("registration request")
}

fn request_for(
    scope: &graph::AzureResourceGraphScope,
    registration_digest: &graph::Digest,
    page: u16,
    continuation: Option<graph::ContinuationToken>,
) -> graph::AzureResourceGraphHttpRequest {
    graph::AzureResourceGraphHttpRequest::new(
        scope,
        registration_digest.clone(),
        &scope.query_ast(),
        page,
        continuation,
        graph::RequestBounds::default(),
    )
    .expect("request")
}

fn payload(
    id: &str,
    resource_type: &str,
    sku: &str,
    provisioning_state: &str,
) -> graph::AzureResourceGraphResourcePayload {
    let properties = BTreeMap::from([
        ("sku".to_owned(), json!({"name": sku})),
        ("provisioningState".to_owned(), json!(provisioning_state)),
        (
            "secretValue".to_owned(),
            json!("must never cross into evidence"),
        ),
        ("tags".to_owned(), json!({"owner": "private"})),
    ]);
    graph::AzureResourceGraphResourcePayload::new(
        id,
        resource_type,
        Some("eastus".to_owned()),
        Some("sub-1".to_owned()),
        Some("rg-1".to_owned()),
        Some("fixture-kind".to_owned()),
        properties,
    )
    .expect("payload")
}

fn provider_with_response(
    response: Result<
        graph::AzureResourceGraphHttpResponse,
        graph::AzureResourceGraphTransportError,
    >,
) -> graph::AzureResourceGraphProvider<
    graph::RecordingAzureResourceGraphTransport,
    graph::FixtureCredentialResolver,
> {
    let request = registration_request();
    graph::AzureResourceGraphProvider::from_registration_request(
        request,
        graph::RecordingAzureResourceGraphTransport::fixture([response]),
        graph::FixtureCredentialResolver,
        graph::RequestBounds::default(),
    )
    .expect("provider")
}

fn response_for_status(
    status: u16,
) -> Result<graph::AzureResourceGraphHttpResponse, graph::AzureResourceGraphTransportError> {
    let request = registration_request();
    let registration =
        graph::AzureResourceGraphRegistration::new(request.clone()).expect("registration");
    let http_request = request_for(
        registration.scope(),
        registration.registration_digest(),
        1,
        None,
    );
    graph::AzureResourceGraphHttpResponse::for_status(&http_request, status)
}

#[test]
fn contract_service_definition_and_reversible_runtime_registration_are_exact() {
    let contract = graph::AzureResourceGraphContract::baseline().expect("contract");
    assert_eq!(contract.digest(), graph::contract_digest());
    assert_eq!(contract.provider.api_version, "2022-10-01");
    assert_eq!(contract.provider.method, "POST");
    assert!(!contract.provider.arbitrary_kql);
    assert!(!contract.provider.raw_properties);
    assert_eq!(
        contract.transport_provenance,
        vec!["fixture", "recording", "loopback", "BLOCKED_ENV"]
    );

    let service = graph::AzureResourceGraphService::new();
    service.validate().expect("service");
    assert!(service.read_only());
    assert!(!service.native_connected());
    assert_eq!(service.capabilities().len(), 9);

    let runtime_scope = PluginScope::new(
        RuntimeProjectId::new("project-1").expect("runtime project"),
        RuntimeMissionId::new("mission-1").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    let definition = graph::plugin_definition(runtime_scope.clone()).expect("definition");
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition).expect("define");
    let receipt = runtime.mount(&handle).expect("mount");
    assert_eq!(receipt.generation(), 1);
    runtime.revoke(&handle).expect("revoke");
}

#[test]
fn allowlisted_inventory_is_deterministic_and_properties_are_digest_only() {
    let registration_request = registration_request();
    let registration = graph::AzureResourceGraphRegistration::new(registration_request.clone())
        .expect("registration");
    let http_request = request_for(
        registration.scope(),
        registration.registration_digest(),
        1,
        None,
    );
    assert!(http_request.is_allowlisted());
    assert_eq!(
        http_request.method,
        graph::AzureResourceGraphHttpMethod::Post
    );
    assert_eq!(
        http_request.path_and_query(),
        "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
    );
    assert!(graph::AzureResourceType::parse("Microsoft.Storage/storageAccounts").is_ok());
    assert!(
        graph::AzureResourceType::parse("Microsoft.Storage/storageAccounts | project id").is_err()
    );
    assert!(graph::AzureResourceProperty::parse("properties.secretValue").is_err());

    let first = payload(
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/zeta",
        "Microsoft.Storage/storageAccounts",
        "Standard_LRS",
        "Succeeded",
    );
    let second = payload(
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/alpha",
        "Microsoft.Compute/virtualMachines",
        "Standard_D2s_v5",
        "Succeeded",
    );
    let response = graph::AzureResourceGraphHttpResponse::from_payloads(
        &http_request,
        200,
        vec![first, second],
        false,
        false,
        Some(2),
        None,
    )
    .expect("response");
    let mut provider = graph::AzureResourceGraphProvider::from_registration_request(
        registration_request,
        graph::RecordingAzureResourceGraphTransport::fixture([Ok(response)]),
        graph::FixtureCredentialResolver,
        graph::RequestBounds::default(),
    )
    .expect("provider");
    let evidence = provider.read().expect("evidence");
    assert_eq!(
        evidence.state,
        graph::AzureResourceGraphEvidenceState::Complete
    );
    assert!(evidence.usable);
    assert_eq!(
        evidence.resources[0].resource_id.as_str(),
        "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/alpha"
    );
    assert_eq!(evidence.resources[0].property_digests.len(), 4);
    assert!(
        evidence
            .resources
            .iter()
            .flat_map(|resource| resource.property_digests.iter())
            .all(|property| property.value_digest.as_str().len() == 64)
    );
    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("Standard_LRS"));
    assert!(!serialized.contains("Standard_D2s_v5"));
    assert!(!serialized.contains("must never cross"));
    assert!(!serialized.contains("secretValue"));
    assert!(!serialized.contains("fixture-token"));
    assert!(!provider.is_connected());
    assert!(!provider.is_native());
}

#[test]
#[allow(clippy::too_many_lines)]
fn continuation_is_bound_to_registration_scope_query_and_page() {
    let request = registration_request();
    let registration =
        graph::AzureResourceGraphRegistration::new(request.clone()).expect("registration");
    let first_request = request_for(
        registration.scope(),
        registration.registration_digest(),
        1,
        None,
    );
    let query_digest = registration.scope().query_digest();
    let binding = graph::continuation_binding_digest(
        registration.registration_digest(),
        registration.scope().scope_digest(),
        &query_digest,
        2,
    );
    let cursor = graph::ContinuationToken::new("cursor-1", binding, 2).expect("cursor");
    let first_response = graph::AzureResourceGraphHttpResponse::from_payloads(
        &first_request,
        200,
        vec![payload(
            "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/zeta",
            "Microsoft.Storage/storageAccounts",
            "Standard_LRS",
            "Succeeded",
        )],
        false,
        false,
        Some(2),
        Some(cursor.clone()),
    )
    .expect("first response");
    let second_request = request_for(
        registration.scope(),
        registration.registration_digest(),
        2,
        Some(cursor.clone()),
    );
    let second_response = graph::AzureResourceGraphHttpResponse::from_payloads(
        &second_request,
        200,
        vec![payload(
            "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/alpha",
            "Microsoft.Compute/virtualMachines",
            "Standard_D2s_v5",
            "Succeeded",
        )],
        false,
        false,
        Some(2),
        None,
    )
    .expect("second response");
    let mut provider = graph::AzureResourceGraphProvider::from_registration_request(
        request,
        graph::RecordingAzureResourceGraphTransport::recording([
            Ok(first_response),
            Ok(second_response),
        ]),
        graph::FixtureCredentialResolver,
        graph::RequestBounds::default(),
    )
    .expect("provider");
    let evidence = provider.read().expect("paged evidence");
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.resources.len(), 2);
    assert_eq!(provider.transport().requests().len(), 2);
    assert_eq!(
        provider.transport().requests()[1].continuation_digest,
        Some(cursor.digest())
    );

    let wrong_cursor =
        graph::ContinuationToken::new("cursor-1", graph::sha256_digest(b"wrong-binding"), 2)
            .expect("wrong cursor");
    let request = registration_request();
    let registration =
        graph::AzureResourceGraphRegistration::new(request.clone()).expect("registration");
    let first_request = request_for(
        registration.scope(),
        registration.registration_digest(),
        1,
        None,
    );
    let bad_response = graph::AzureResourceGraphHttpResponse::from_payloads(
        &first_request,
        200,
        Vec::new(),
        false,
        false,
        None,
        Some(wrong_cursor),
    )
    .expect("bad response");
    let mut bad_provider = graph::AzureResourceGraphProvider::from_registration_request(
        request,
        graph::RecordingAzureResourceGraphTransport::fixture([Ok(bad_response)]),
        graph::FixtureCredentialResolver,
        graph::RequestBounds::default(),
    )
    .expect("bad provider");
    assert_eq!(
        bad_provider.read().expect_err("binding must fail closed"),
        graph::AzureResourceGraphError::ContinuationRejected
    );
}

#[test]
fn status_matrix_partial_truncated_timeout_and_blocked_env_never_become_usable() {
    for (status, expected) in [
        (400, graph::AzureResourceGraphEvidenceState::BadRequest),
        (401, graph::AzureResourceGraphEvidenceState::Unauthorized),
        (403, graph::AzureResourceGraphEvidenceState::Forbidden),
        (404, graph::AzureResourceGraphEvidenceState::NotFound),
        (409, graph::AzureResourceGraphEvidenceState::Conflict),
        (429, graph::AzureResourceGraphEvidenceState::RateLimited),
        (
            500,
            graph::AzureResourceGraphEvidenceState::ProviderUnavailable,
        ),
        (
            503,
            graph::AzureResourceGraphEvidenceState::ProviderUnavailable,
        ),
    ] {
        let mut provider = provider_with_response(response_for_status(status));
        let evidence = provider.read().expect("status evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.usable);
        assert!(evidence.resources.is_empty());
        assert!(!evidence.native && !evidence.connected);
    }

    let request = registration_request();
    let registration =
        graph::AzureResourceGraphRegistration::new(request.clone()).expect("registration");
    let http_request = request_for(
        registration.scope(),
        registration.registration_digest(),
        1,
        None,
    );
    let partial = graph::AzureResourceGraphHttpResponse::from_payloads(
        &http_request,
        200,
        vec![payload(
            "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/zeta",
            "Microsoft.Storage/storageAccounts",
            "Standard_LRS",
            "Succeeded",
        )],
        true,
        false,
        Some(1),
        None,
    )
    .expect("partial response");
    let mut partial_provider = graph::AzureResourceGraphProvider::from_registration_request(
        request,
        graph::RecordingAzureResourceGraphTransport::fixture([Ok(partial)]),
        graph::FixtureCredentialResolver,
        graph::RequestBounds::default(),
    )
    .expect("partial provider");
    let partial_evidence = partial_provider.read().expect("partial evidence");
    assert_eq!(
        partial_evidence.state,
        graph::AzureResourceGraphEvidenceState::Partial
    );
    assert!(partial_evidence.resources.is_empty());
    assert!(!partial_evidence.usable);

    let blocked_scope = scope();
    let mut blocked_provider = graph::AzureResourceGraphProvider::new(
        blocked_scope,
        secret(),
        graph::BlockedEnvTransport,
        graph::FixtureCredentialResolver,
    )
    .expect("blocked provider");
    let blocked = blocked_provider.read().expect("blocked evidence");
    assert_eq!(
        blocked.state,
        graph::AzureResourceGraphEvidenceState::BlockedEnv
    );
    assert_eq!(blocked.provenance, graph::TransportProvenance::BlockedEnv);
    assert!(!blocked.usable);

    let request = registration_request();
    let mut timeout_provider = graph::AzureResourceGraphProvider::from_registration_request(
        request,
        graph::RecordingAzureResourceGraphTransport::recording([Err(
            graph::AzureResourceGraphTransportError::Timeout("fixture timeout".to_owned()),
        )]),
        graph::FixtureCredentialResolver,
        graph::RequestBounds::default(),
    )
    .expect("timeout provider");
    let timeout = timeout_provider.read().expect("timeout evidence");
    assert_eq!(
        timeout.state,
        graph::AzureResourceGraphEvidenceState::Timeout
    );
    assert!(!timeout.usable);
}

#[test]
fn registration_revision_secret_scope_tamper_and_consumer_replay_fences_hold() {
    let mut provider = provider_with_response(response_for_status(200));
    assert_eq!(
        provider.read().expect("empty evidence").state,
        graph::AzureResourceGraphEvidenceState::Empty
    );
    provider.revoke_registration().expect("revoke");
    assert_eq!(
        provider.read().expect_err("revoked registration"),
        graph::AzureResourceGraphError::RegistrationRevoked
    );
    provider.restore_registration().expect("restore");

    let reference = secret();
    assert!(!format!("{reference:?}").contains("keyring/entra/resource-graph"));
    assert!(!format!("{:?}", graph::FixtureCredentialResolver).contains("fixture-token"));

    let mut proposal_provider = provider_with_response(response_for_status(200));
    let proposal = proposal_provider.compile_proposal().expect("proposal");
    assert!(proposal.proposal_only);
    assert!(!proposal.native && !proposal.connected && !proposal.adopts_outcome);
    let receipt = proposal_provider
        .record_observation_receipt(&proposal)
        .expect("observation receipt");
    receipt.validate().expect("receipt");
    assert!(!receipt.durable_provider_receipt);

    let mut consumer = graph::MissionAzureResourceConsumer::new(scope());
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        graph::MissionAzureResourceResultState::NeedsMoreEvidence
    );
    assert!(consumer.consume(&proposal).is_err());
    consumer.revoke().expect("consumer revoke");
    assert!(consumer.consume(&proposal).is_err());

    let mut altered = proposal.clone();
    altered.scope = graph::AzureResourceGraphScope::new(graph::AzureResourceGraphScopeInput {
        tenant_id: "other-tenant".to_owned(),
        target: graph::AzureResourceGraphTarget::subscriptions(["sub-1"]).expect("target"),
        resource_types: vec![graph::AzureResourceType::MicrosoftStorageStorageAccounts],
        properties: vec![graph::AzureResourceProperty::Kind],
        query_revision: 7,
        project: graph::ProjectBinding::new("project-1", 3).expect("project"),
        mission: graph::MissionBinding::new("mission-1", 4).expect("mission"),
        work_product: graph::WorkProductBinding::new("work-product-1", 5).expect("work product"),
        permission: graph::PermissionSnapshot::for_subscriptions(6).expect("permission"),
        consent: graph::ConsentScope::new("consent-1", 8).expect("consent"),
    })
    .expect("altered scope");
    let mut active_consumer = graph::MissionAzureResourceConsumer::new(scope());
    assert!(active_consumer.consume(&altered).is_err());
}

#[test]
fn provenance_and_native_probe_are_truthful_for_all_layer1_seams() {
    assert_eq!(
        graph::RecordingAzureResourceGraphTransport::fixture([]).provenance(),
        graph::TransportProvenance::Fixture
    );
    assert_eq!(
        graph::RecordingAzureResourceGraphTransport::new([]).provenance(),
        graph::TransportProvenance::Recording
    );
    assert_eq!(
        graph::RecordingAzureResourceGraphTransport::loopback([]).provenance(),
        graph::TransportProvenance::Loopback
    );
    for provenance in [
        graph::TransportProvenance::Fixture,
        graph::TransportProvenance::Recording,
        graph::TransportProvenance::Loopback,
        graph::TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_native());
        assert!(!provenance.is_connected());
    }
    let probe = graph::native_probe_from_environment();
    assert_eq!(probe.status, graph::NativeProbeStatus::BlockedEnv);
    assert!(!probe.native_credentials_resolved);
    assert!(!probe.live_https_verified);
    assert!(!probe.native_connected_claim);
}

use chrono::{DateTime, TimeZone, Utc};
use hartevo_azure_container_apps_revision_result_plugin::{
    AppMetadata, AppProvisioningState, AzureContainerAppsEvidenceState, AzureContainerAppsProvider,
    AzureContainerAppsRevisionResultService, AzureContainerAppsRevisionScope,
    AzureContainerAppsTransportError, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON,
    CONTRACT_SCHEMA, CONTRACT_VERSION, ComponentId, ContainerAppName, Digest,
    EnvironmentResourceId, FakeTransport, FixtureTransport, GenerationIdentity,
    GetContainerAppRequest, GetContainerAppResponse, GetRevisionRequest, GetRevisionResponse,
    ListRevisionsRequest, ListRevisionsResponse, LocalIntegrityFailure, ProposalDisposition,
    RecordingTransport, ResourceGroupName, RevisionHealthState, RevisionMetadata, RevisionName,
    RevisionProvisioningState, RevisionRunningState, SecretReference, SubscriptionId, TenantId,
    TransportProvenance,
};
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_TENANT: &str = "11111111-1111-4111-8111-111111111111";
const RAW_SUBSCRIPTION: &str = "22222222-2222-4222-8222-222222222222";
const RAW_RESOURCE_GROUP: &str = "rg-860";
const RAW_ENVIRONMENT: &str = "/subscriptions/22222222-2222-4222-8222-222222222222/resourceGroups/rg-860/providers/Microsoft.App/managedEnvironments/env-860";
const RAW_APP: &str = "app-860";
const RAW_REVISION: &str = "app-860--r1";
const RAW_IMAGE: &str = "registry.example.invalid/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RAW_SECRET: &str = "opaque-entra-secret-reference";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AzureContainerAppsRevisionScope {
    AzureContainerAppsRevisionScope::new(
        TenantId::new(RAW_TENANT).expect("tenant"),
        SubscriptionId::new(RAW_SUBSCRIPTION).expect("subscription"),
        ResourceGroupName::new(RAW_RESOURCE_GROUP).expect("resource group"),
        EnvironmentResourceId::new(RAW_ENVIRONMENT).expect("environment"),
        ContainerAppName::new(RAW_APP).expect("app"),
        RevisionName::new(RAW_REVISION).expect("revision"),
        RAW_IMAGE,
        ComponentId::new("component-860").expect("component"),
        GenerationIdentity::new("project-860", 7, "project").expect("project"),
        GenerationIdentity::new("mission-860", 11, "mission").expect("mission"),
        GenerationIdentity::new("work-product-860", 13, "work_product").expect("work product"),
    )
    .expect("scope")
}

fn fixture_service() -> AzureContainerAppsRevisionResultService<FixtureTransport> {
    let scope = scope();
    let provider = AzureContainerAppsProvider::new(
        FixtureTransport::for_scope(&scope, now()).expect("fixture transport"),
        1,
        "1.0.0",
    )
    .expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &scope, 1).expect("secret");
    AzureContainerAppsRevisionResultService::new(scope, secret, provider, now()).expect("service")
}

fn app_response(
    scope: &AzureContainerAppsRevisionScope,
    request: &GetContainerAppRequest,
) -> GetContainerAppResponse {
    GetContainerAppResponse::new(
        request,
        AppMetadata::from_provider(
            scope,
            AppProvisioningState::Succeeded,
            Some(RAW_REVISION.to_owned()),
        )
        .expect("app metadata"),
        512,
        TransportProvenance::Recording,
    )
    .expect("app response")
}

fn revision_metadata(
    scope: &AzureContainerAppsRevisionScope,
    health: RevisionHealthState,
    running: RevisionRunningState,
    traffic_weight: u16,
) -> RevisionMetadata {
    RevisionMetadata::for_scope(
        scope,
        true,
        health,
        RevisionProvisioningState::Provisioned,
        running,
        Some(now()),
        Some(now()),
        2,
        traffic_weight,
    )
    .expect("revision metadata")
}

#[test]
fn contract_and_registration_are_digest_bound_and_secret_redacted() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    let service = fixture_service();
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    for raw in [
        RAW_SECRET,
        RAW_RESOURCE_GROUP,
        RAW_ENVIRONMENT,
        RAW_APP,
        RAW_REVISION,
        RAW_IMAGE,
    ] {
        assert!(
            !serialized.contains(raw),
            "registration leaked raw value: {raw}"
        );
        assert!(
            !debug.contains(raw),
            "registration Debug leaked raw value: {raw}"
        );
    }
    assert!(service.registration().validate().is_ok());
    let capabilities = service.describe_capabilities();
    assert_eq!(capabilities.operations.len(), 3);
    assert!(capabilities.read_only);
    assert!(!capabilities.connected && !capabilities.native && !capabilities.first_party);
}

#[test]
fn fixture_proposal_is_bounded_review_only_and_idempotent() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, AzureContainerAppsEvidenceState::Healthy);
    assert_eq!(proposal.list_pages, 1);
    assert!(proposal.list_complete && !proposal.truncated && proposal.projection.is_some());
    assert!(
        !proposal.connected
            && !proposal.native
            && !proposal.first_party
            && !proposal.provider_receipt
    );
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());
    let report = service.verify(&proposal);
    assert!(report.valid && report.review_eligible && !report.adoptable);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_TENANT,
        RAW_SUBSCRIPTION,
        RAW_RESOURCE_GROUP,
        RAW_ENVIRONMENT,
        RAW_APP,
        RAW_REVISION,
        RAW_IMAGE,
        RAW_SECRET,
    ] {
        assert!(
            !serialized.contains(raw),
            "proposal leaked raw value: {raw}"
        );
    }
    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(result.disposition, ProposalDisposition::Healthy);
    assert!(!result.connected && !result.native && !result.first_party);
    let first = consumer
        .record(&proposal, "idempotency-860")
        .expect("record");
    assert!(!first.replayed && first.validate_integrity().is_ok());
    let replay = consumer
        .record(&proposal, "idempotency-860")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn blocked_environment_is_unknown_and_never_native() {
    let scope = scope();
    let provider =
        AzureContainerAppsProvider::new(BlockedEnvTransport, 1, "1.0.0").expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &scope, 1).expect("secret");
    let mut service = AzureContainerAppsRevisionResultService::new(scope, secret, provider, now())
        .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        proposal.state,
        AzureContainerAppsEvidenceState::ProviderUnknown
    );
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        hartevo_azure_container_apps_revision_result_plugin::FailureCategory::BlockedEnv
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn registration_revoke_reverse_and_restore_fail_closed() {
    let mut service = fixture_service();
    let request = service.default_request(now()).expect("request");
    service.revoke().expect("revoke");
    assert!(!service.registration().is_active());
    assert!(service.propose(request).is_err());
    assert!(service.consumer().is_err());
    service.restore_registration().expect("restore");
    service.reverse().expect("reverse");
    assert!(
        service
            .propose(service.default_request(now()).expect("request"))
            .is_err()
    );
    assert!(service.restore_registration().is_err());
}

#[test]
fn truncation_and_opaque_next_link_are_non_adoptable() {
    let scope = scope();
    let app_request = GetContainerAppRequest::for_scope(&scope).expect("app request");
    let list_request = ListRevisionsRequest::first(&scope, 10).expect("list request");
    let metadata = revision_metadata(
        &scope,
        RevisionHealthState::Healthy,
        RevisionRunningState::Running,
        100,
    );
    let list_response = ListRevisionsResponse::new(
        &list_request,
        vec![metadata],
        Some("https://management.azure.com/opaque-next-link".to_owned()),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let mut transport = RecordingTransport::default();
    transport.push_app_response(Ok(app_response(&scope, &app_request)));
    transport.push_list_response(Ok(list_response));
    let provider = AzureContainerAppsProvider::new(transport, 1, "1.0.0").expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &scope, 1).expect("secret");
    let mut service = AzureContainerAppsRevisionResultService::new(scope, secret, provider, now())
        .expect("service");
    let proposal = service
        .propose(service.request(1, 10, now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, AzureContainerAppsEvidenceState::Partial);
    assert!(proposal.truncated && !proposal.is_review_eligible());
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("opaque-next-link"));
}

#[test]
fn pagination_loop_and_revision_replacement_fail_closed() {
    let loop_scope = scope();
    let app_request = GetContainerAppRequest::for_scope(&loop_scope).expect("app request");
    let list_request_one =
        ListRevisionsRequest::first(&loop_scope, 10).expect("first list request");
    let metadata_one = revision_metadata(
        &loop_scope,
        RevisionHealthState::Healthy,
        RevisionRunningState::Running,
        100,
    );
    let list_response_one = ListRevisionsResponse::new(
        &list_request_one,
        vec![metadata_one.clone()],
        Some("same-next-link".to_owned()),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("first list response");
    let list_request_two =
        ListRevisionsRequest::new(&loop_scope, 10, list_response_one.next_cursor.clone())
            .expect("second list request");
    let list_response_two = ListRevisionsResponse::new(
        &list_request_two,
        vec![metadata_one],
        Some("same-next-link".to_owned()),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("second list response");
    let mut loop_transport = RecordingTransport::default();
    loop_transport.push_app_response(Ok(app_response(&loop_scope, &app_request)));
    loop_transport.push_list_response(Ok(list_response_one));
    loop_transport.push_list_response(Ok(list_response_two));
    let provider = AzureContainerAppsProvider::new(loop_transport, 1, "1.0.0").expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &loop_scope, 1).expect("secret");
    let mut service =
        AzureContainerAppsRevisionResultService::new(loop_scope, secret, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.request(3, 10, now()).expect("request"))
        .expect("proposal");
    assert_eq!(
        proposal.state,
        AzureContainerAppsEvidenceState::PaginationLoop
    );
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        hartevo_azure_container_apps_revision_result_plugin::FailureCategory::PaginationLoop
    );

    let replacement_scope = scope();
    let app_request = GetContainerAppRequest::for_scope(&replacement_scope).expect("app request");
    let list_request = ListRevisionsRequest::first(&replacement_scope, 10).expect("list request");
    let list_metadata = revision_metadata(
        &replacement_scope,
        RevisionHealthState::Healthy,
        RevisionRunningState::Running,
        100,
    );
    let get_metadata = revision_metadata(
        &replacement_scope,
        RevisionHealthState::Healthy,
        RevisionRunningState::Running,
        50,
    );
    let mut replacement_transport = RecordingTransport::default();
    replacement_transport.push_app_response(Ok(app_response(&replacement_scope, &app_request)));
    replacement_transport.push_list_response(Ok(ListRevisionsResponse::single(
        &list_request,
        list_metadata,
        1_024,
        TransportProvenance::Recording,
    )
    .expect("list response")));
    let get_request = GetRevisionRequest::for_scope(&replacement_scope).expect("get request");
    replacement_transport.push_revision_response(Ok(GetRevisionResponse::new(
        &get_request,
        get_metadata,
        768,
        TransportProvenance::Recording,
    )
    .expect("get response")));
    let provider =
        AzureContainerAppsProvider::new(replacement_transport, 1, "1.0.0").expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &replacement_scope, 1).expect("secret");
    let mut replacement_service =
        AzureContainerAppsRevisionResultService::new(replacement_scope, secret, provider, now())
            .expect("service");
    let replacement = replacement_service
        .propose(replacement_service.default_request(now()).expect("request"))
        .expect("replacement proposal");
    assert_eq!(replacement.state, AzureContainerAppsEvidenceState::Partial);
    assert_eq!(
        replacement.failure.as_ref().expect("failure").category,
        hartevo_azure_container_apps_revision_result_plugin::FailureCategory::RevisionReplaced
    );
}

#[test]
fn readiness_conflict_tamper_access_loss_and_stale_request_are_rejected() {
    let conflict_scope = scope();
    let app_request = GetContainerAppRequest::for_scope(&conflict_scope).expect("app request");
    let list_request = ListRevisionsRequest::first(&conflict_scope, 10).expect("list request");
    let conflicting = revision_metadata(
        &conflict_scope,
        RevisionHealthState::Healthy,
        RevisionRunningState::Stopped,
        100,
    );
    let get_request = GetRevisionRequest::for_scope(&conflict_scope).expect("get request");
    let mut transport = RecordingTransport::default();
    transport.push_app_response(Ok(app_response(&conflict_scope, &app_request)));
    transport.push_list_response(Ok(ListRevisionsResponse::single(
        &list_request,
        conflicting.clone(),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("list response")));
    transport.push_revision_response(Ok(GetRevisionResponse::new(
        &get_request,
        conflicting,
        768,
        TransportProvenance::Recording,
    )
    .expect("get response")));
    let provider = AzureContainerAppsProvider::new(transport, 1, "1.0.0").expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &conflict_scope, 1).expect("secret");
    let mut service =
        AzureContainerAppsRevisionResultService::new(conflict_scope, secret, provider, now())
            .expect("service");
    let conflict = service
        .propose(service.default_request(now()).expect("request"))
        .expect("conflict proposal");
    assert_eq!(conflict.state, AzureContainerAppsEvidenceState::Conflict);
    assert_eq!(
        conflict.failure.as_ref().expect("failure").category,
        hartevo_azure_container_apps_revision_result_plugin::FailureCategory::ReadinessConflict
    );

    let tampered_scope = scope();
    let app_request = GetContainerAppRequest::for_scope(&tampered_scope).expect("app request");
    let mut tampered_transport = RecordingTransport::default();
    tampered_transport.push_app_response(Ok(app_response(&tampered_scope, &app_request)
        .with_declared_digest(Digest::from_text("tampered"))));
    let provider =
        AzureContainerAppsProvider::new(tampered_transport, 1, "1.0.0").expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &tampered_scope, 1).expect("secret");
    let mut tampered_service =
        AzureContainerAppsRevisionResultService::new(tampered_scope, secret, provider, now())
            .expect("service");
    let tampered = tampered_service
        .propose(tampered_service.default_request(now()).expect("request"))
        .expect("tampered proposal");
    assert_eq!(tampered.state, AzureContainerAppsEvidenceState::Tampered);
    assert!(
        tampered_service
            .verify(&tampered)
            .failures
            .contains(&LocalIntegrityFailure::TamperedEvidence)
    );

    let access_scope = scope();
    let provider = AzureContainerAppsProvider::new(RecordingTransport::default(), 1, "1.0.0")
        .expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &access_scope, 1).expect("secret");
    let mut access_service =
        AzureContainerAppsRevisionResultService::new(access_scope, secret, provider, now())
            .expect("service");
    access_service
        .provider_mut()
        .transport_mut()
        .push_app_response(Err(AzureContainerAppsTransportError::AccessLost));
    let access = access_service
        .propose(access_service.default_request(now()).expect("request"))
        .expect("access loss proposal");
    assert_eq!(access.state, AzureContainerAppsEvidenceState::AccessLost);
    assert!(!access.connected && !access.native && !access.first_party);

    let stale_scope = scope();
    let provider = AzureContainerAppsProvider::new(
        FixtureTransport::for_scope(&stale_scope, now()).expect("fixture transport"),
        1,
        "1.0.0",
    )
    .expect("provider");
    let secret = SecretReference::entra(RAW_SECRET, &stale_scope, 1).expect("secret");
    let mut stale_service =
        AzureContainerAppsRevisionResultService::new(stale_scope, secret, provider, now())
            .expect("service");
    let mut stale_request = stale_service.default_request(now()).expect("request");
    stale_request.request_digest = Digest::from_text("stale-request");
    assert_eq!(stale_service.propose(stale_request).expect_err("stale request"), hartevo_azure_container_apps_revision_result_plugin::AzureContainerAppsRevisionResultError::StaleEvidence);
}

#[test]
fn every_layer_one_provenance_is_non_native() {
    let scope = scope();
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Fake,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_connected());
        assert!(!provenance.is_native());
        assert!(!provenance.is_first_party());
    }
    let fake = FakeTransport::for_scope(&scope, now()).expect("fake transport");
    let provider = AzureContainerAppsProvider::new(fake, 1, "1.0.0").expect("fake provider");
    assert!(!provider.definition().connected());
    assert!(!provider.definition().native());
    assert!(!provider.definition().first_party());
}

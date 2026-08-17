use hartevo_gcp_memorystore_redis_result_plugin::{
    BlockedEnvTransport, Digest, EvidenceState, FakeGcpMemorystoreTransport, GcpLocation,
    GcpMemorystoreAdminProvider, GcpMemorystoreError, GcpMemorystoreEvidenceRequest,
    GcpMemorystoreInstanceResultService, GcpMemorystoreScope, GcpMemorystoreTransportError,
    GetInstanceRequest, GoogleAuthKind, InstanceInput, InstanceSummary, ListInstancesRequest,
    ListInstancesResponse, MAX_RESPONSE_BYTES, MissionGcpMemorystoreInstanceConsumer,
    OpaquePageToken, RecordingTransport, SecretReference, TransportProvenance,
};
use proptest::prelude::*;

fn scope() -> GcpMemorystoreScope {
    GcpMemorystoreScope::from_values(
        "demo-project",
        "us-central1",
        "redis-instance-1",
        "mission-1",
        1,
        "project-1",
        1,
        "work-product-1",
        1,
    )
    .expect("valid exact scope")
}

fn secret(scope: &GcpMemorystoreScope) -> SecretReference {
    SecretReference::new(
        "opaque-google-credential-handle",
        scope,
        1,
        GoogleAuthKind::OAuth,
    )
    .expect("valid opaque secret reference")
}

fn fixture_service() -> GcpMemorystoreInstanceResultService<
    hartevo_gcp_memorystore_redis_result_plugin::FixtureTransport,
> {
    let scope = scope();
    let provider = GcpMemorystoreAdminProvider::new(
        hartevo_gcp_memorystore_redis_result_plugin::FixtureTransport::for_scope(&scope),
    )
    .expect("fixture provider");
    GcpMemorystoreInstanceResultService::new(scope.clone(), secret(&scope), provider)
        .expect("fixture service")
}

fn request_for(
    service: &GcpMemorystoreInstanceResultService<
        hartevo_gcp_memorystore_redis_result_plugin::FixtureTransport,
    >,
) -> GcpMemorystoreEvidenceRequest {
    GcpMemorystoreEvidenceRequest::for_scope(service.scope(), service.registration())
        .expect("bounded evidence request")
}

fn recorded_provider(
    list: Vec<Result<ListInstancesResponse, GcpMemorystoreTransportError>>,
    get: Vec<
        Result<
            hartevo_gcp_memorystore_redis_result_plugin::GetInstanceResponse,
            GcpMemorystoreTransportError,
        >,
    >,
) -> GcpMemorystoreAdminProvider<FakeGcpMemorystoreTransport> {
    let mut transport = RecordingTransport::default();
    for response in list {
        transport.push_list_response(response);
    }
    for response in get {
        transport.push_get_response(response);
    }
    GcpMemorystoreAdminProvider::new(transport).expect("recording provider")
}

#[test]
fn contract_and_scope_are_exact_and_bounded() {
    assert!(GcpLocation::new("-").is_err());
    assert!(
        GcpMemorystoreScope::from_values(
            "demo-project",
            "-",
            "redis-instance-1",
            "mission-1",
            1,
            "project-1",
            1,
            "work-product-1",
            1,
        )
        .is_err()
    );

    let contract = hartevo_gcp_memorystore_redis_result_plugin::GcpMemorystoreContract::baseline()
        .expect("contract JSON and digest");
    assert_eq!(
        contract
            .value()
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .and_then(|provider| provider.get("wildcardLocationAllowed")),
        Some(&serde_json::Value::Bool(false))
    );
    assert!(!hartevo_gcp_memorystore_redis_result_plugin::Layer1Authority::connected());
    assert!(!hartevo_gcp_memorystore_redis_result_plugin::Layer1Authority::native());
    assert!(!hartevo_gcp_memorystore_redis_result_plugin::Layer1Authority::first_party());
}

#[test]
fn fixture_service_performs_list_then_get_and_stays_non_native() {
    let mut service = fixture_service();
    let proposal = service
        .propose(request_for(&service))
        .expect("fixture proposal");

    assert_eq!(proposal.state, EvidenceState::Ready);
    assert!(proposal.list_complete);
    assert_eq!(proposal.list_pages, 1);
    assert!(proposal.projection.is_some());
    assert_eq!(
        proposal
            .request_receipts
            .iter()
            .map(|receipt| receipt.operation.as_str())
            .collect::<Vec<_>>(),
        ["instances.list", "instances.get"]
    );
    assert_eq!(proposal.provenance, TransportProvenance::Fixture);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(service.verify(&proposal).valid);
    assert!(proposal.validate_integrity().is_ok());

    let mut consumer = MissionGcpMemorystoreInstanceConsumer::new(
        service.scope().clone(),
        service.registration().clone(),
    )
    .expect("consumer registration");
    let result = consumer.consume(&proposal).expect("review-only result");
    assert_eq!(result.state, EvidenceState::Ready);
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.can_be_adopted());

    let first = consumer
        .record(&proposal, "mission-1-evidence")
        .expect("local recording");
    let replay = consumer
        .record(&proposal, "mission-1-evidence")
        .expect("idempotent replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn registration_and_secret_revocation_fail_closed_and_restore_is_validated() {
    let mut service = fixture_service();
    service
        .reverse_registration()
        .expect("reversible registration");
    assert!(!service.registration().is_active());
    assert!(service.registration().validate().is_ok());
    assert_eq!(
        service.propose(request_for(&service)).unwrap_err(),
        GcpMemorystoreError::RegistrationInactive
    );

    service
        .restore_registration()
        .expect("restore registration");
    assert!(service.registration().is_active());
    assert!(service.registration().validate().is_ok());

    service.revoke_secret().expect("secret revocation");
    assert_eq!(
        service.propose(request_for(&service)).unwrap_err(),
        GcpMemorystoreError::SecretRevoked
    );

    service.revoke_registration().expect("terminal revocation");
    assert!(!service.registration().is_active());
    assert_eq!(
        service.restore_registration().unwrap_err(),
        GcpMemorystoreError::RegistrationRevoked
    );
}

#[test]
fn sensitive_material_is_digest_only_or_dropped() {
    let scope = scope()
        .with_label_allowlist([String::from("environment")])
        .expect("label allowlist");
    let secret = SecretReference::new(
        "AUTH-STRING-and-endpoint-must-not-escape",
        &scope,
        1,
        GoogleAuthKind::ServiceAccount,
    )
    .expect("secret reference");
    let secret_debug = format!("{secret:?}");
    assert!(!secret_debug.contains("AUTH-STRING"));
    assert!(!secret_debug.contains("endpoint"));

    let input = InstanceInput::new(
        "projects/demo-project/locations/us-central1/instances/redis-instance-1",
        "STANDARD_HA",
        4,
        "REDIS_7_2",
        "ACTIVE",
        1,
    )
    .expect("instance input")
    .with_sensitive_metadata(
        [String::from("https://redis.example.invalid")],
        Some(String::from("AUTH secret")),
        [String::from("certificate bytes")],
        [
            (String::from("environment"), String::from("production")),
            (String::from("private-label"), String::from("do-not-emit")),
        ],
        [String::from("redis-key")],
        [String::from("redis-value")],
        Some(String::from("redis-cli output")),
        Some(String::from("raw response body")),
    );
    let input_debug = format!("{input:?}");
    assert!(!input_debug.contains("redis.example.invalid"));
    assert!(!input_debug.contains("AUTH secret"));
    assert!(!input_debug.contains("certificate bytes"));
    assert!(!input_debug.contains("do-not-emit"));
    assert!(!input_debug.contains("redis-key"));
    assert!(!input_debug.contains("redis-value"));
    assert!(!input_debug.contains("redis-cli output"));
    assert!(!input_debug.contains("raw response body"));

    let serialized_scope = serde_json::to_string(&scope).expect("redacted scope");
    assert!(!serialized_scope.contains("demo-project"));
    assert!(!serialized_scope.contains("us-central1"));
    assert!(!serialized_scope.contains("redis-instance-1"));
    assert!(!serialized_scope.contains("private-label"));
    assert_eq!(secret.scope_digest(), &scope.digest());
}

#[test]
fn pagination_loop_and_unreachable_location_are_non_adoptable() {
    let scope = scope();
    let first_request = ListInstancesRequest::first(&scope, 100).expect("first page");
    let token = OpaquePageToken::new("same-page-token").expect("opaque token");
    let second_request =
        ListInstancesRequest::new(&scope, 100, 2, Some(token.clone())).expect("second page");
    let first_response = ListInstancesResponse::new(
        &first_request,
        vec![InstanceSummary::fixture(&scope)],
        Some(token.clone()),
        Vec::<String>::new(),
        128,
        TransportProvenance::Recording,
    )
    .expect("first response");
    let second_response = ListInstancesResponse::new(
        &second_request,
        Vec::new(),
        Some(token),
        Vec::<String>::new(),
        128,
        TransportProvenance::Recording,
    )
    .expect("loop response");
    let provider = recorded_provider(vec![Ok(first_response), Ok(second_response)], Vec::new());
    let mut service =
        GcpMemorystoreInstanceResultService::new(scope.clone(), secret(&scope), provider)
            .expect("recording service");
    let proposal = service
        .propose(
            GcpMemorystoreEvidenceRequest::for_scope(&scope, service.registration())
                .expect("request"),
        )
        .expect("loop proposal");
    assert_eq!(proposal.state, EvidenceState::PaginationLoop);
    assert!(!proposal.list_complete);
    assert!(!service.verify(&proposal).valid);

    let list_request = ListInstancesRequest::first(&scope, 100).expect("list request");
    let unreachable = ListInstancesResponse::new(
        &list_request,
        Vec::new(),
        None,
        [String::from("europe-west1")],
        128,
        TransportProvenance::Recording,
    )
    .expect("unreachable response");
    let provider = recorded_provider(vec![Ok(unreachable)], Vec::new());
    let mut service =
        GcpMemorystoreInstanceResultService::new(scope.clone(), secret(&scope), provider)
            .expect("unreachable service");
    let proposal = service
        .propose(
            GcpMemorystoreEvidenceRequest::for_scope(&scope, service.registration())
                .expect("request"),
        )
        .expect("unreachable proposal");
    assert_eq!(proposal.state, EvidenceState::UnreachableLocation);
    assert!(!proposal.list_complete);
}

#[test]
fn provider_rejects_tamper_and_truncation_before_service_use() {
    let scope = scope();
    let request = ListInstancesRequest::first(&scope, 100).expect("list request");
    let mut tampered = ListInstancesResponse::new(
        &request,
        Vec::new(),
        None,
        Vec::<String>::new(),
        128,
        TransportProvenance::Recording,
    )
    .expect("construct bounded response candidate");
    let original_digest = tampered.evidence_digest.clone();
    tampered.evidence_digest = Digest::from_text("tampered");
    assert_ne!(tampered.evidence_digest, original_digest);

    let provider = recorded_provider(vec![Ok(tampered)], Vec::new());
    let mut provider = provider;
    assert_eq!(
        provider.list_instances(&request).unwrap_err(),
        GcpMemorystoreTransportError::Tampered
    );

    let oversized = ListInstancesResponse::new(
        &request,
        Vec::new(),
        None,
        Vec::<String>::new(),
        MAX_RESPONSE_BYTES + 1,
        TransportProvenance::Recording,
    )
    .expect("construct truncation candidate");
    let mut provider = recorded_provider(vec![Ok(oversized)], Vec::new());
    assert_eq!(
        provider.list_instances(&request).unwrap_err(),
        GcpMemorystoreTransportError::Truncated
    );
}

#[test]
fn blocked_environment_is_explicitly_unknown_and_never_native() {
    let scope = scope();
    let provider = GcpMemorystoreAdminProvider::new(BlockedEnvTransport).expect("blocked provider");
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
    assert!(!provider.provenance().connected());
    assert!(!provider.provenance().native());
    assert!(!provider.provenance().first_party());
    let mut service =
        GcpMemorystoreInstanceResultService::new(scope.clone(), secret(&scope), provider)
            .expect("blocked service");
    let proposal = service
        .propose(
            GcpMemorystoreEvidenceRequest::for_scope(&scope, service.registration())
                .expect("request"),
        )
        .expect("blocked proposal");
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
}

#[test]
fn get_request_is_exactly_bound_to_scope() {
    let scope = scope();
    let request = GetInstanceRequest::new(&scope).expect("get request");
    assert_eq!(request.scope().digest(), scope.digest());
    assert_eq!(
        request.recorded_request().operation.as_str(),
        "instances.get"
    );
    let debug = format!("{request:?}");
    assert!(!debug.contains("demo-project"));
    assert!(!debug.contains("us-central1"));
    assert!(!debug.contains("redis-instance-1"));
}

#[test]
fn transport_error_mapping_preserves_access_loss_and_unknown_states() {
    let scope = scope();
    let provider = recorded_provider(
        vec![Err(GcpMemorystoreTransportError::Forbidden)],
        Vec::new(),
    );
    let mut service =
        GcpMemorystoreInstanceResultService::new(scope.clone(), secret(&scope), provider)
            .expect("forbidden service");
    let proposal = service
        .propose(
            GcpMemorystoreEvidenceRequest::for_scope(&scope, service.registration())
                .expect("request"),
        )
        .expect("forbidden proposal");
    assert_eq!(proposal.state, EvidenceState::Forbidden);
    assert!(!service.verify(&proposal).valid);
}

proptest! {
    #[test]
    fn opaque_page_tokens_never_serialize_their_raw_value(raw in "opaque-[a-zA-Z0-9_]{1,64}") {
        let token = OpaquePageToken::new(raw.clone()).expect("generated token");
        let debug = format!("{token:?}");
        let serialized = serde_json::to_string(&token).expect("digest serialization");
        prop_assert!(!debug.contains(&raw));
        prop_assert!(!serialized.contains(&raw));
        prop_assert_eq!(serialized, serde_json::to_string(&token.digest()).expect("digest"));
    }
}

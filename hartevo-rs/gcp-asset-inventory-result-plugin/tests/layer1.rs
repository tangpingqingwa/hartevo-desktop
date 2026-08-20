use chrono::{TimeZone, Utc};
use hartevo_gcp_asset_inventory_result_plugin::{
    AncestryNode, AssetInventoryScope, AssetInventorySearchScope, AssetMetadataInput,
    AssetProjection, AssetResourceInput, AssetType, BlockedEnvGcpAssetInventoryTransport,
    ConsumerError, EffectObservation, GCP_ASSET_INVENTORY_PROVIDER_REVISION,
    GcpAssetInventoryProvider, GcpAssetInventoryProviderError, GcpAssetInventoryScope,
    GcpAssetInventoryService, GcpAssetInventoryServiceError, GcpAssetInventoryTransport,
    MissionGcpAssetConsumer, MissionGcpAssetInventoryState, MissionScope, OAuthSecretReference,
    PermissionBinding, ProjectScope, ProviderFailureClass, ProviderProvenance, RedactedAsset,
    RedactedProviderState, ResourceAncestry, ResourceIdentity, Revision, SearchAllResourcesPage,
    SearchAllResourcesRequest, SearchBounds, SearchResponseStatus, SecretReference,
    SecretReferenceKind, ServiceAccountSecretReference, WorkProductScope, fake_page_token_for_page,
};

fn time(minute: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 1, minute, 0)
        .single()
        .expect("valid fixture time")
}

fn ancestry() -> ResourceAncestry {
    ResourceAncestry::new(vec![
        AncestryNode::new(
            "cloudresourcemanager.googleapis.com/Project",
            "projects/fixture-project",
        )
        .expect("project ancestry"),
        AncestryNode::new(
            "cloudresourcemanager.googleapis.com/Folder",
            "folders/fixture-folder",
        )
        .expect("folder ancestry"),
    ])
    .expect("bounded ancestry")
}

fn scope() -> GcpAssetInventoryScope {
    let asset_type = AssetType::new("compute.googleapis.com/Instance").expect("asset type");
    let identity = ResourceIdentity::new(
        asset_type,
        "//compute.googleapis.com/projects/fixture-project/zones/asia-east1-a/instances/one",
        ancestry(),
    )
    .expect("resource identity");
    GcpAssetInventoryScope::new(
        AssetInventorySearchScope::project("fixture-project").expect("project search scope"),
        identity,
        time(0),
        ProjectScope::new("project-530", Revision::new(2).expect("project revision"))
            .expect("project scope"),
        MissionScope::new("mission-530", Revision::new(3).expect("mission revision"))
            .expect("mission scope"),
        WorkProductScope::new(
            "work-product-530",
            Revision::new(4).expect("work product revision"),
        )
        .expect("work product scope"),
        PermissionBinding::cloud_asset_search_all_resources(),
    )
}

fn asset(scope: &AssetInventoryScope, version: &str, enrichment: &str) -> RedactedAsset {
    RedactedAsset::from_input(AssetResourceInput::new(
        "//compute.googleapis.com/projects/fixture-project/zones/asia-east1-a/instances/one",
        scope.resource.asset_type.clone(),
        scope.resource.ancestry.clone(),
        scope.read_time,
        AssetMetadataInput::new(
            Some(version.to_owned()),
            Some(enrichment.to_owned()),
            RedactedProviderState::Present,
        ),
    ))
    .expect("safe asset projection")
}

fn service(
    scope: GcpAssetInventoryScope,
    bounds: SearchBounds,
    assets: impl IntoIterator<Item = RedactedAsset>,
) -> GcpAssetInventoryService<
    hartevo_gcp_asset_inventory_result_plugin::FakeGcpAssetInventoryTransport,
> {
    let secret = SecretReference::oauth(
        "opaque-oauth-host-reference",
        &scope,
        Revision::new(7).expect("credential revision"),
    )
    .expect("OAuth reference");
    let provider = GcpAssetInventoryProvider::new(
        hartevo_gcp_asset_inventory_result_plugin::FakeGcpAssetInventoryTransport::new(assets),
        "1.0.0",
        GCP_ASSET_INVENTORY_PROVIDER_REVISION,
    )
    .expect("provider");
    GcpAssetInventoryService::with_bounds(scope, secret, provider, bounds).expect("service")
}

#[test]
fn complete_evidence_is_redacted_and_mission_bound() {
    let scope = scope();
    let resource_name =
        "//compute.googleapis.com/projects/fixture-project/zones/asia-east1-a/instances/one";
    let version = "provider-version-secret-shaped";
    let enrichment = "raw-enrichment-shaped";
    let mut service = service(
        scope.clone(),
        SearchBounds::default(),
        [asset(&scope, version, enrichment)],
    );

    let evidence = service.read_bounded().expect("bounded read");
    assert_eq!(evidence.projection, AssetProjection::Complete);
    assert_eq!(evidence.raw_asset_count, 1);
    assert_eq!(evidence.unique_asset_count, 1);
    assert!(evidence.verify_integrity());
    assert_eq!(evidence.digests.scope_digest, scope.scope_digest());
    assert_eq!(evidence.digests.query_digest, service.query().query_digest);

    let serialized = serde_json::to_string(&evidence).expect("safe evidence serializes");
    assert!(!serialized.contains(resource_name));
    assert!(!serialized.contains(version));
    assert!(!serialized.contains(enrichment));
    assert!(!serialized.contains("resourceData"));
    assert!(!serialized.contains("labels"));
    assert!(!serialized.contains("tags"));

    let consumer = MissionGcpAssetConsumer::new(scope, service.registration()).expect("consumer");
    let result = consumer.consume(evidence).expect("mission observation");
    assert_eq!(
        result.state,
        MissionGcpAssetInventoryState::EvidenceAvailable
    );
    assert_eq!(result.assets.len(), 1);
    assert_eq!(
        result.effect_observation,
        EffectObservation::NoExternalEffectClaim
    );
    assert!(!result.external_effect_succeeded);
    assert!(!result.adopts_outcome);
    assert!(!result.truth_authority);
}

#[test]
fn page_token_is_opaque_and_bound_to_query_page() {
    let scope = scope();
    let mut service = service(
        scope.clone(),
        SearchBounds::new(4, 1, 10).expect("bounds"),
        [
            asset(&scope, "version", "enrichment"),
            asset(&scope, "version", "enrichment"),
        ],
    );

    let evidence = service.read_bounded().expect("two-page read");
    assert_eq!(evidence.projection, AssetProjection::Complete);
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.raw_asset_count, 2);
    assert_eq!(evidence.unique_asset_count, 1);
    assert_eq!(evidence.duplicate_asset_count, 1);
    assert!(
        evidence
            .anomalies
            .contains(&hartevo_gcp_asset_inventory_result_plugin::AssetAnomaly::DuplicateAsset)
    );

    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].page_token_digest.is_none());
    assert_eq!(
        requests[1].page_token_digest,
        Some(fake_page_token_for_page(2).expect("token").digest())
    );
    let debug = format!("{:?}", requests[1].page_token());
    assert!(!debug.contains("fake-page:2"));
    let request_json = serde_json::to_string(&requests[1]).expect("safe request");
    assert!(!request_json.contains("fake-page:2"));
}

#[test]
fn partial_access_lost_and_blocked_states_are_explicit() {
    let scope = scope();
    let mut partial = service(
        scope.clone(),
        SearchBounds::new(1, 1, 10).expect("bounds"),
        [
            asset(&scope, "version", "enrichment"),
            asset(&scope, "version", "enrichment"),
        ],
    );
    assert_eq!(
        partial.read_bounded().expect("partial read").projection,
        AssetProjection::Partial(hartevo_gcp_asset_inventory_result_plugin::PartialReason::PageCap)
    );

    let mut denied = service(scope.clone(), SearchBounds::default(), []);
    denied
        .provider_mut()
        .transport_mut()
        .push_failure(GcpAssetInventoryProviderError::failure(
            ProviderFailureClass::AccessDenied,
            Some(403),
        ));
    assert_eq!(
        denied.read_bounded().expect("access state").projection,
        AssetProjection::AccessLost
    );

    let blocked_provider = GcpAssetInventoryProvider::new(
        BlockedEnvGcpAssetInventoryTransport,
        "1.0.0",
        GCP_ASSET_INVENTORY_PROVIDER_REVISION,
    )
    .expect("blocked provider");
    let blocked_secret = SecretReference::unbound(
        SecretReferenceKind::ServiceAccount,
        "opaque-service-account-reference",
        Revision::new(1).expect("revision"),
    )
    .expect("unbound service-account reference");
    let mut blocked = GcpAssetInventoryService::new(scope, blocked_secret, blocked_provider)
        .expect("blocked service");
    assert_eq!(
        blocked.read_bounded().expect("blocked state").projection,
        AssetProjection::ProviderUnknown
    );
}

#[test]
fn replay_tamper_and_reversible_registration_fail_closed() {
    let scope = scope();
    let mut first_service = service(
        scope.clone(),
        SearchBounds::default(),
        [asset(&scope, "v", "e")],
    );
    let proposal = first_service
        .propose_search_all_resources(1, None)
        .expect("proposal");
    first_service
        .read_search_all_resources(&proposal)
        .expect("first read");
    assert!(matches!(
        first_service.read_search_all_resources(&proposal),
        Err(GcpAssetInventoryServiceError::Provider(
            GcpAssetInventoryProviderError::ReplayDetected
        ))
    ));

    let mut another = service(
        scope.clone(),
        SearchBounds::default(),
        [asset(&scope, "v", "e")],
    );
    let proposal = another
        .propose_search_all_resources(1, None)
        .expect("proposal");
    let mut page = another
        .provider_mut()
        .read(proposal.request())
        .expect("page");
    page.assets[0].asset_type = AssetType::new("storage.googleapis.com/Bucket").expect("tamper");
    assert!(matches!(
        another.record_search_all_resources(&proposal, &page),
        Err(GcpAssetInventoryServiceError::RecordTampered
            | GcpAssetInventoryServiceError::AssetScopeMismatch,)
    ));

    let mut consumer =
        MissionGcpAssetConsumer::new(scope, another.registration()).expect("consumer");
    consumer.revoke().expect("revoke consumer");
    assert!(matches!(
        consumer.consume(another.read_bounded().expect("evidence")),
        Err(ConsumerError::Revoked)
    ));

    assert!(another.is_registered());
    another.revoke_registration().expect("revoke registration");
    assert!(!another.is_registered());
    another.register().expect("re-register");
    assert!(another.is_registered());
}

#[test]
fn oauth_and_service_account_references_are_opaque_non_serializing_bindings() {
    let scope = scope();
    let oauth: OAuthSecretReference = SecretReference::oauth(
        "oauth-access-token-shaped-value",
        &scope,
        Revision::new(1).expect("revision"),
    )
    .expect("OAuth reference");
    let service_account: ServiceAccountSecretReference = SecretReference::service_account(
        "service-account-private-key-shaped-value",
        &scope,
        Revision::new(2).expect("revision"),
    )
    .expect("service-account reference");
    let debug = format!("{oauth:?} {service_account:?}");
    assert!(!debug.contains("oauth-access-token-shaped-value"));
    assert!(!debug.contains("service-account-private-key-shaped-value"));
    assert!(!debug.contains("private-key"));
    assert_ne!(oauth.reference_digest(), service_account.reference_digest());
    assert_eq!(oauth.kind(), SecretReferenceKind::OAuth);
    assert_eq!(service_account.kind(), SecretReferenceKind::ServiceAccount);
}

#[test]
fn provider_page_rejects_raw_scope_drift_and_keeps_provenance_non_native() {
    let scope = scope();
    let mut service = service(
        scope.clone(),
        SearchBounds::default(),
        [asset(&scope, "v", "e")],
    );
    assert_eq!(service.provider_provenance(), ProviderProvenance::Fake);
    assert!(!service.provider().is_native());

    let proposal = service
        .propose_search_all_resources(1, None)
        .expect("proposal");
    let mut page = service
        .provider_mut()
        .read(proposal.request())
        .expect("page");
    page.response_status = SearchResponseStatus::Warning;
    assert!(matches!(
        service.record_search_all_resources(&proposal, &page),
        Err(GcpAssetInventoryServiceError::RecordTampered)
    ));
}

#[derive(Clone, Debug)]
struct NoopTransport;

impl GcpAssetInventoryTransport for NoopTransport {
    fn search_all_resources(
        &mut self,
        _request: &SearchAllResourcesRequest,
    ) -> Result<SearchAllResourcesPage, GcpAssetInventoryProviderError> {
        Err(GcpAssetInventoryProviderError::failure(
            ProviderFailureClass::ProviderUnknown,
            None,
        ))
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }
}

#[test]
fn loopback_transport_is_an_explicit_non_native_provenance() {
    let provider = GcpAssetInventoryProvider::new(
        NoopTransport,
        "1.0.0",
        GCP_ASSET_INVENTORY_PROVIDER_REVISION,
    )
    .expect("loopback provider");
    assert_eq!(provider.provenance(), ProviderProvenance::Loopback);
    assert!(!provider.is_native());
}

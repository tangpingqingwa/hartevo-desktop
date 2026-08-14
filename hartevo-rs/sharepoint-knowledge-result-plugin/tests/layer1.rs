use hartevo_sharepoint_knowledge_result_plugin::{
    BlockedEnvCredentialResolver, BlockedEnvTransport, ConsentScope, DeltaChange, DriveId,
    DriveItemDeltaPayload, DriveItemId, DriveItemKind, DriveItemMetadataPayload,
    DriveItemReadRequest, DriveItemSearchPayload, DriveItemVersionPayload, EntraSecretReference,
    FixtureSharePointTransport, ItemVersionId, ListId, LoopbackSharePointTransport,
    MicrosoftGraphRequest, MicrosoftGraphResponse, MicrosoftGraphResponseBody,
    MicrosoftGraphSharePointProvider, MicrosoftGraphSharePointTransport, MissionWorkProduct,
    NativeProbeStatus, OpaqueGraphNextLink, ProjectId, ProviderProvenance,
    RecordingSharePointTransport, SharePointCapability, SharePointGraphOperation,
    SharePointKnowledgeEvidence, SharePointKnowledgeResultError, SharePointKnowledgeResultService,
    SharePointKnowledgeScope, SharePointKnowledgeScopeInput, SharePointSearchRequest,
    SharePointTransportError, SiteId, StaticEntraCredentialResolver, TenantId, WorkProductId,
    contract_digest, native_probe_from_environment, sha256_digest,
};

fn scope() -> SharePointKnowledgeScope {
    SharePointKnowledgeScope::new(SharePointKnowledgeScopeInput {
        tenant_id: String::from("tenant-1"),
        national_cloud: hartevo_sharepoint_knowledge_result_plugin::NationalCloud::Global,
        site_id: String::from("site-1"),
        site_hostname: String::from("contoso.sharepoint.com"),
        drive_id: String::from("drive-1"),
        list_id: String::from("list-1"),
        item_id: String::from("item-1"),
        item_version: String::from("version-7"),
        search_scope: hartevo_sharepoint_knowledge_result_plugin::SharePointSearchScope::new(
            None, true, true, 128, 3,
        )
        .expect("search scope"),
        permission_digest: sha256_digest("permission-snapshot"),
        project_id: String::from("project-1"),
        mission_id: String::from("mission-1"),
        work_product_id: String::from("work-product-1"),
        work_product_revision: 4,
        consent_scope: ConsentScope::new("consent-1", 9, SharePointCapability::all_layer1())
            .expect("consent"),
    })
    .expect("scope")
}

fn secret() -> EntraSecretReference {
    EntraSecretReference::new("vault/entra/sharepoint", "tenant-1", "client-1", 1)
        .expect("secret reference")
}

fn request(
    scope: &SharePointKnowledgeScope,
    operation: SharePointGraphOperation,
) -> MicrosoftGraphRequest {
    MicrosoftGraphRequest::new(operation, scope, 1, None, None)
}

fn response(
    scope: &SharePointKnowledgeScope,
    operation: SharePointGraphOperation,
    body: MicrosoftGraphResponseBody,
) -> MicrosoftGraphResponse {
    MicrosoftGraphResponse::new(&request(scope, operation), 200, body, 512).expect("response")
}

fn metadata_payload(scope: &SharePointKnowledgeScope, name: &str) -> DriveItemMetadataPayload {
    DriveItemMetadataPayload::for_scope(scope, name).expect("metadata payload")
}

fn child_payload(
    scope: &SharePointKnowledgeScope,
    item_id: &str,
    name: &str,
) -> DriveItemMetadataPayload {
    let mut payload = metadata_payload(scope, name);
    payload.item_id = DriveItemId::new(item_id).expect("child item");
    payload.parent_item_id = Some(scope.item_id.clone());
    payload.kind = DriveItemKind::Folder;
    payload
}

fn provider(
    scope: SharePointKnowledgeScope,
    responses: impl IntoIterator<Item = Result<MicrosoftGraphResponse, SharePointTransportError>>,
) -> MicrosoftGraphSharePointProvider<FixtureSharePointTransport, StaticEntraCredentialResolver> {
    MicrosoftGraphSharePointProvider::new(
        scope,
        secret(),
        FixtureSharePointTransport::new(responses),
        StaticEntraCredentialResolver::new("fixture-token-never-retained"),
    )
    .expect("provider")
}

#[test]
fn contract_registration_and_native_gap_are_typed() {
    assert_eq!(contract_digest().len(), 64);
    let scope = scope();
    let registration =
        hartevo_sharepoint_knowledge_result_plugin::SharePointPluginRegistration::new(
            scope.clone(),
            secret(),
        )
        .expect("registration");
    registration
        .validate(
            &scope,
            &hartevo_sharepoint_knowledge_result_plugin::SharePointProviderManifest::layer1(&scope),
        )
        .expect("registration validation");
    let mut revoked = provider(scope.clone(), Vec::new());
    let old_digest = revoked.registration().registration_digest.clone();
    let revocation = revoked.revoke().expect("revoke");
    assert!(revocation.revoked);
    assert_eq!(revocation.previous_registration_digest, old_digest);
    assert_ne!(revocation.registration_digest, old_digest);
    assert_eq!(
        native_probe_from_environment().status,
        NativeProbeStatus::BlockedEnv
    );
    assert!(!native_probe_from_environment().native_connected_claim);
}

#[test]
#[allow(clippy::too_many_lines)]
fn all_graph_v1_read_seams_are_bounded_and_redacted() {
    let scope = scope();
    let next_link = OpaqueGraphNextLink::new(
        "https://graph.microsoft.com/v1.0/sites/site-1/drives/drive-1/root/children?$skiptoken=private-search-token",
    )
    .expect("next link");
    let mut child_page = child_payload(&scope, "child-1", "Private child name");
    child_page.e_tag = String::from("private-etag");
    let search_hit = DriveItemSearchPayload {
        site_id: scope.site_id.clone(),
        drive_id: scope.drive_id.clone(),
        list_id: scope.list_id.clone(),
        item_id: DriveItemId::new("search-item-1").expect("search item"),
        name: String::from("PII customer name"),
        path: String::from("/private/customer-record.docx"),
        version: scope.item_version.clone(),
        rank: 1,
        permission_digest: scope.permission_digest.clone(),
    };
    let version = DriveItemVersionPayload {
        site_id: scope.site_id.clone(),
        drive_id: scope.drive_id.clone(),
        list_id: scope.list_id.clone(),
        item_id: scope.item_id.clone(),
        version_id: ItemVersionId::new("version-6").expect("version"),
        modified_at_epoch_seconds: 1_787_000_000,
        version_digest: sha256_digest("version-payload"),
        permission_digest: scope.permission_digest.clone(),
    };
    let delta = DriveItemDeltaPayload {
        site_id: scope.site_id.clone(),
        drive_id: scope.drive_id.clone(),
        list_id: scope.list_id.clone(),
        item_id: scope.item_id.clone(),
        change: DeltaChange::Upserted,
        item_digest: sha256_digest("delta-item"),
        version: Some(scope.item_version.clone()),
        permission_digest: scope.permission_digest.clone(),
    };
    let responses = vec![
        Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemMetadata,
            MicrosoftGraphResponseBody::Metadata(metadata_payload(&scope, "PII metadata name")),
        )),
        Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemChildren,
            MicrosoftGraphResponseBody::Children {
                items: vec![child_page],
                next_link: Some(next_link.clone()),
            },
        )),
        Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemChildren,
            MicrosoftGraphResponseBody::Children {
                items: vec![child_payload(&scope, "child-2", "Second private child")],
                next_link: None,
            },
        )),
        Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemSearch,
            MicrosoftGraphResponseBody::Search {
                hits: vec![search_hit],
                next_link: None,
            },
        )),
        Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemVersions,
            MicrosoftGraphResponseBody::Versions {
                versions: vec![version],
                next_link: None,
            },
        )),
        Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemDelta,
            MicrosoftGraphResponseBody::Delta {
                entries: vec![delta],
                next_link: None,
            },
        )),
    ];
    let mut provider = provider(scope.clone(), responses);
    let read_request = DriveItemReadRequest::new(scope.clone());
    let metadata = provider
        .read_drive_item_metadata(&read_request)
        .expect("metadata");
    let children = provider
        .read_drive_item_children(&read_request)
        .expect("children");
    assert_eq!(children.children.len(), 2);
    assert_eq!(children.page_count, 2);
    assert_eq!(children.cursor_digests, vec![next_link.digest().to_owned()]);
    let search = provider
        .search_drive_items(
            &SharePointSearchRequest::new(scope.clone(), "private customer query")
                .expect("search request"),
        )
        .expect("search");
    let versions = provider
        .read_drive_item_versions(&read_request)
        .expect("versions");
    let delta = provider
        .read_drive_item_delta(&read_request)
        .expect("delta");
    assert_eq!(search.hits.len(), 1);
    assert_eq!(versions.versions.len(), 1);
    assert_eq!(delta.entries.len(), 1);
    assert!(!provider.provenance().is_native());
    assert!(!provider.provenance().is_connected());
    assert_eq!(provider.transport().requests().len(), 6);
    assert!(
        provider
            .transport()
            .requests()
            .iter()
            .all(|request| request.api_version == "v1.0")
    );

    let mut evidence = SharePointKnowledgeEvidence {
        scope: scope.clone(),
        metadata,
        children: Some(children),
        search: Some(search),
        versions: Some(versions),
        delta: Some(delta),
        provider_manifest_digest: provider.provider_manifest().digest(),
        registration_digest: provider.registration().registration_digest.clone(),
        evidence_source: ProviderProvenance::Fixture,
        native_connected: false,
        raw_bytes_retained: false,
        download_url_retained: false,
        pii_retained: false,
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = evidence.calculate_digest();
    evidence.validate().expect("evidence");
    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!serialized.contains("PII metadata name"));
    assert!(!serialized.contains("private customer query"));
    assert!(!serialized.contains("customer-record.docx"));
    assert!(!serialized.contains("private-search-token"));
    assert!(!serialized.contains("fixture-token-never-retained"));

    let work_product = MissionWorkProduct {
        project_id: ProjectId::new("project-1").expect("project"),
        mission_id: hartevo_sharepoint_knowledge_result_plugin::MissionId::new("mission-1")
            .expect("mission"),
        work_product_id: WorkProductId::new("work-product-1").expect("work product"),
        revision: 4,
        content_digest: sha256_digest("work product content"),
    };
    let proposal = provider
        .compile_knowledge_result(&evidence, work_product)
        .expect("proposal");
    proposal.validate().expect("proposal validation");
    assert!(!proposal.native_connected);
    assert!(proposal.non_mutating);
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains("PII metadata name")
    );

    let next_link_json = serde_json::to_string(&next_link).expect("next link JSON");
    assert!(!next_link_json.contains("private-search-token"));
    assert_eq!(
        next_link_json,
        format!(r#"{{"present":true,"digest":"{}"}}"#, next_link.digest())
    );
}

#[test]
fn blocked_env_never_emits_a_request_and_service_consumer_are_typed() {
    let scope = scope();
    let blocked_response = response(
        &scope,
        SharePointGraphOperation::DriveItemMetadata,
        MicrosoftGraphResponseBody::Metadata(metadata_payload(&scope, "safe name")),
    );
    let mut blocked = MicrosoftGraphSharePointProvider::new(
        scope.clone(),
        secret(),
        FixtureSharePointTransport::new([Ok(blocked_response)]),
        BlockedEnvCredentialResolver,
    )
    .expect("blocked provider");
    let error = blocked
        .read_drive_item_metadata(&DriveItemReadRequest::new(scope.clone()))
        .expect_err("blocked credentials");
    assert!(matches!(
        error,
        SharePointKnowledgeResultError::Provider(
            hartevo_sharepoint_knowledge_result_plugin::MicrosoftGraphSharePointProviderError::BlockedEnv
        )
    ));
    assert!(blocked.transport().requests().is_empty());
    assert_eq!(
        *blocked.state(),
        hartevo_sharepoint_knowledge_result_plugin::ProviderState::BlockedEnv
    );

    let service_provider = provider(
        scope.clone(),
        [Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemMetadata,
            MicrosoftGraphResponseBody::Metadata(metadata_payload(&scope, "safe name")),
        ))],
    );
    let service = SharePointKnowledgeResultService::new(service_provider).expect("service");
    let mut consumer =
        hartevo_sharepoint_knowledge_result_plugin::MissionSharePointKnowledgeConsumer::new(
            service,
        );
    let description = consumer.describe_scope().expect("description");
    assert_eq!(description.scope_digest, scope.digest());
    let evidence = consumer
        .read_drive_item_metadata(&DriveItemReadRequest::new(scope))
        .expect("consumer metadata");
    assert!(!evidence.envelope.native_connected);

    let blocked_transport = BlockedEnvTransport;
    assert_eq!(
        blocked_transport.provenance(),
        ProviderProvenance::BlockedEnv
    );
    assert!(!blocked_transport.provenance().native_connected_claim());
}

#[test]
fn version_api_download_and_cursor_fences_fail_closed() {
    let scope = scope();
    let mut wrong_version = metadata_payload(&scope, "safe");
    wrong_version.version = ItemVersionId::new("version-drift").expect("version");
    let mut version_provider = provider(
        scope.clone(),
        [Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemMetadata,
            MicrosoftGraphResponseBody::Metadata(wrong_version),
        ))],
    );
    assert!(matches!(
        version_provider.read_drive_item_metadata(&DriveItemReadRequest::new(scope.clone())),
        Err(SharePointKnowledgeResultError::Provider(
            hartevo_sharepoint_knowledge_result_plugin::MicrosoftGraphSharePointProviderError::VersionDrift
        ))
    ));

    let api_response = response(
        &scope,
        SharePointGraphOperation::DriveItemMetadata,
        MicrosoftGraphResponseBody::Metadata(metadata_payload(&scope, "safe")),
    )
    .with_api_version("v1.0-beta");
    let mut api_provider = provider(scope.clone(), [Ok(api_response)]);
    assert!(matches!(
        api_provider.read_drive_item_metadata(&DriveItemReadRequest::new(scope.clone())),
        Err(SharePointKnowledgeResultError::Provider(
            hartevo_sharepoint_knowledge_result_plugin::MicrosoftGraphSharePointProviderError::ApiVersionDrift
        ))
    ));

    let mut url_payload = metadata_payload(&scope, "safe");
    url_payload.has_download_url = true;
    let mut url_provider = provider(
        scope.clone(),
        [Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemMetadata,
            MicrosoftGraphResponseBody::Metadata(url_payload),
        ))],
    );
    assert!(matches!(
        url_provider.read_drive_item_metadata(&DriveItemReadRequest::new(scope.clone())),
        Err(SharePointKnowledgeResultError::Provider(
            hartevo_sharepoint_knowledge_result_plugin::MicrosoftGraphSharePointProviderError::InvalidResponse
        ))
    ));

    let cursor = OpaqueGraphNextLink::new("https://graph.microsoft.com/v1.0/next?token=opaque")
        .expect("cursor");
    let child = child_payload(&scope, "child-1", "safe");
    let loop_responses = [
        Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemChildren,
            MicrosoftGraphResponseBody::Children {
                items: vec![child.clone()],
                next_link: Some(cursor.clone()),
            },
        )),
        Ok(response(
            &scope,
            SharePointGraphOperation::DriveItemChildren,
            MicrosoftGraphResponseBody::Children {
                items: vec![child],
                next_link: Some(cursor),
            },
        )),
    ];
    let mut loop_provider = provider(scope.clone(), loop_responses);
    assert!(matches!(
        loop_provider.read_drive_item_children(&DriveItemReadRequest::new(scope)),
        Err(SharePointKnowledgeResultError::Provider(
            hartevo_sharepoint_knowledge_result_plugin::MicrosoftGraphSharePointProviderError::PaginationLoop
        ))
    ));
}

#[test]
fn raw_secret_reference_debug_is_opaque() {
    let secret = secret();
    let debug = format!("{secret:?}");
    assert!(!debug.contains("vault/entra/sharepoint"));
    assert!(!debug.contains("client-1"));
    assert!(!debug.contains("tenant-1"));
    assert!(debug.contains(&secret.digest()));
}

#[test]
fn recording_fixture_loopback_and_blocked_env_are_never_native() {
    let recording = RecordingSharePointTransport::new(Vec::new());
    let fixture = FixtureSharePointTransport::new(Vec::new());
    let loopback = LoopbackSharePointTransport::new(Vec::new());
    for provenance in [
        recording.provenance(),
        fixture.provenance(),
        loopback.provenance(),
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_native());
        assert!(!provenance.is_connected());
        assert!(!provenance.native_connected_claim());
    }
    assert_eq!(recording.provenance(), ProviderProvenance::Recording);
    assert_eq!(fixture.provenance(), ProviderProvenance::Fixture);
    assert_eq!(loopback.provenance(), ProviderProvenance::Loopback);
}

#[allow(dead_code)]
fn _typed_scope_markers(_tenant: TenantId, _site: SiteId, _drive: DriveId, _list: ListId) {}

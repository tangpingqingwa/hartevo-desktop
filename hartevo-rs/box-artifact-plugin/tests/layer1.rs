use hartevo_box_artifact_plugin::{
    ArtifactAvailability, ArtifactProposalRequest, ArtifactRevisionFence,
    BOX_ARTIFACT_PROVIDER_VERSION, BlockedEnvCredentialResolver, BoxArtifactError,
    BoxArtifactFixture, BoxArtifactPluginRegistration, BoxArtifactProvider, BoxArtifactScope,
    BoxArtifactService, BoxArtifactServiceDefinition, BoxAuthMethod, BoxFileRecord,
    BoxFolderRecord, BoxProviderState, BoxTransportOperation, BoxUserRecord, BoxVersionRecord,
    ByteRange, ContentDigest, ContentReadRequest, EnterpriseId, FileId, FileReadRequest,
    FixtureBoxArtifactTransport, FixtureFileFailure, FolderId, FolderItemsRequest,
    MissionArtifactResultConsumer, MissionArtifactResultStatus, MissionId, MissionResultBinding,
    ProbeStatus, ProjectId, ProviderProvenance, ResultId, SecretReference, Sha1Digest,
    StaticBoxCredentialResolver, UserId, VersionId, VersionReadRequest,
};

const TOKEN: &str = "fixture-token-not-for-logs";

fn enterprise(value: &str) -> EnterpriseId {
    EnterpriseId::new(value).expect("enterprise id")
}

fn user(value: &str) -> UserId {
    UserId::new(value).expect("user id")
}

fn folder(value: &str) -> FolderId {
    FolderId::new(value).expect("folder id")
}

fn file(value: &str) -> FileId {
    FileId::new(value).expect("file id")
}

fn version(value: &str) -> VersionId {
    VersionId::new(value).expect("version id")
}

fn project(value: &str) -> ProjectId {
    ProjectId::new(value).expect("project id")
}

fn mission(value: &str) -> MissionId {
    MissionId::new(value).expect("mission id")
}

fn result(value: &str) -> ResultId {
    ResultId::new(value).expect("result id")
}

fn scope() -> BoxArtifactScope {
    BoxArtifactScope::new(
        enterprise("enterprise-1"),
        user("user-1"),
        Some(folder("folder-root")),
        None,
        project("project-1"),
        mission("mission-1"),
    )
    .expect("scope")
}

fn file_record(file_id: &str, version_id: &str, bytes: &[u8], name: &str) -> BoxFileRecord {
    BoxFileRecord {
        enterprise_id: enterprise("enterprise-1"),
        owner_user_id: user("user-1"),
        file_id: file(file_id),
        parent_folder_id: folder("folder-root"),
        name: name.to_owned(),
        media_type: "text/plain".to_owned(),
        size: bytes.len() as u64,
        sha1: Sha1Digest::from_bytes(bytes),
        version_id: version(version_id),
        trashed: false,
        deleted: false,
    }
}

fn fixture() -> (BoxArtifactFixture, BoxFileRecord, Vec<u8>) {
    let bytes = b"hello box world".to_vec();
    let current = file_record("file-1", "version-2", &bytes, "customer-secret-name.txt");
    let older_bytes = b"older box data";
    let older = BoxVersionRecord {
        file_id: file("file-1"),
        version_id: version("version-1"),
        size: older_bytes.len() as u64,
        sha1: Sha1Digest::from_bytes(older_bytes),
        trashed: false,
        deleted: false,
    };
    let current_version = BoxVersionRecord {
        file_id: file("file-1"),
        version_id: version("version-2"),
        size: bytes.len() as u64,
        sha1: Sha1Digest::from_bytes(&bytes),
        trashed: false,
        deleted: false,
    };
    let second_bytes = b"second file";
    let second = file_record("file-2", "version-1", second_bytes, "second.txt");
    let mut fixture = BoxArtifactFixture::new(BoxUserRecord {
        enterprise_id: enterprise("enterprise-1"),
        user_id: user("user-1"),
        display_name: Some("Alice Customer".to_owned()),
        email_address: Some("alice@example.invalid".to_owned()),
    });
    fixture.insert_folder(BoxFolderRecord {
        enterprise_id: enterprise("enterprise-1"),
        user_id: user("user-1"),
        folder_id: folder("folder-root"),
        parent_folder_id: None,
        name: "Customer Folder".to_owned(),
    });
    fixture.insert_file(current.clone(), bytes.clone());
    fixture.insert_file(second, second_bytes.to_vec());
    fixture.insert_versions(file("file-1"), vec![older, current_version]);
    (fixture, current, bytes)
}

fn registration(scope: &BoxArtifactScope) -> BoxArtifactPluginRegistration {
    let secret = SecretReference::new(
        "secret-ref-box-fixture",
        scope.digest(),
        1,
        BoxAuthMethod::OAuth2Bearer,
    )
    .expect("secret reference");
    BoxArtifactPluginRegistration::new(scope.clone(), secret).expect("registration")
}

fn provider(
    transport: FixtureBoxArtifactTransport,
    scope: &BoxArtifactScope,
) -> BoxArtifactProvider<FixtureBoxArtifactTransport, StaticBoxCredentialResolver> {
    BoxArtifactProvider::new(
        registration(scope),
        transport,
        StaticBoxCredentialResolver::new(TOKEN),
    )
    .expect("provider")
}

fn full_content_request(
    scope: &BoxArtifactScope,
    current: &BoxFileRecord,
    bytes: &[u8],
) -> ContentReadRequest {
    let revision = ArtifactRevisionFence {
        file_id: current.file_id.clone(),
        version_id: current.version_id.clone(),
        sha1: current.sha1.clone(),
        size: current.size,
    };
    let range = ByteRange::new(0, bytes.len() as u64 - 1).expect("full range");
    ContentReadRequest::new(scope.clone(), revision, range).expect("content request")
}

fn result_binding() -> MissionResultBinding {
    MissionResultBinding::new(
        project("project-1"),
        mission("mission-1"),
        7,
        result("result-1"),
        3,
    )
    .expect("result binding")
}

#[test]
fn fixture_probe_is_typed_and_never_connected_or_native() {
    let (fixture, _current, _bytes) = fixture();
    let scope = scope();
    let transport = FixtureBoxArtifactTransport::fixture(fixture);
    let mut provider = provider(transport.clone(), &scope);

    let probe = provider.probe().expect("fixture probe");
    assert_eq!(probe.status, ProbeStatus::VerifiedFixtureNotConnected);
    assert_eq!(probe.provenance, ProviderProvenance::Fixture);
    assert!(!probe.native_transport);
    assert!(!probe.native_connected);
    assert!(!probe.status.is_connected());
    assert_eq!(provider.state(), BoxProviderState::Fixture);
    assert_eq!(transport.operations(), vec![BoxTransportOperation::GetUser]);
}

#[test]
fn loopback_probe_is_explicitly_non_native() {
    let (fixture, _current, _bytes) = fixture();
    let scope = scope();
    let mut provider = provider(FixtureBoxArtifactTransport::loopback(fixture), &scope);
    let probe = provider.probe().expect("loopback probe");
    assert_eq!(probe.status, ProbeStatus::VerifiedLoopbackNotConnected);
    assert_eq!(probe.provenance, ProviderProvenance::Loopback);
    assert!(!probe.native_transport);
    assert!(!probe.native_connected);
}

#[test]
fn folder_and_version_pagination_are_scope_bound_and_bounded() {
    let (fixture, current, _bytes) = fixture();
    let scope = scope();
    let mut provider = provider(FixtureBoxArtifactTransport::fixture(fixture), &scope);

    let first_request = FolderItemsRequest::new(scope.clone(), folder("folder-root"), None, 1)
        .expect("folder request");
    let first = provider
        .list_folder_items(&first_request)
        .expect("first folder page");
    assert_eq!(first.entries.len(), 1);
    let cursor = first.next_cursor.clone().expect("next folder cursor");
    let second_request =
        FolderItemsRequest::new(scope.clone(), folder("folder-root"), Some(cursor), 1)
            .expect("second folder request");
    let second = provider
        .list_folder_items(&second_request)
        .expect("second folder page");
    assert_eq!(second.entries.len(), 1);
    assert!(second.next_cursor.is_none());

    let version_request = VersionReadRequest::new(scope.clone(), current.file_id.clone(), None, 1)
        .expect("version request");
    let versions = provider.read_versions(&version_request).expect("versions");
    assert_eq!(versions.versions.len(), 1);
    assert!(versions.next_cursor.is_some());
    assert_eq!(versions.total_count, 2);

    let wrong_scope = BoxArtifactScope::new(
        enterprise("enterprise-other"),
        user("user-1"),
        Some(folder("folder-root")),
        None,
        project("project-1"),
        mission("mission-1"),
    )
    .expect("other scope");
    let wrong_cursor = first.next_cursor.clone();
    let error = FolderItemsRequest::new(wrong_scope, folder("folder-root"), wrong_cursor, 1)
        .expect_err("cursor should be scope-fenced");
    assert_eq!(error, BoxArtifactError::CursorScopeMismatch);
}

#[test]
fn full_content_read_verifies_sha1_and_content_digest() {
    let (fixture, current, bytes) = fixture();
    let scope = scope();
    let mut provider = provider(FixtureBoxArtifactTransport::fixture(fixture), &scope);
    let request = full_content_request(&scope, &current, &bytes);
    let content = provider.read_content(&request).expect("content");
    assert!(content.complete);
    assert!(content.sha1_verified);
    assert_eq!(content.bytes, bytes);
    assert_eq!(content.content_digest, ContentDigest::from_bytes(&bytes));
    assert!(!content.native_transport);
    assert!(!content.native_connected);
}

#[test]
fn sha1_mismatch_and_range_mismatch_fail_closed() {
    let (fixture, current, bytes) = fixture();
    let scope = scope();
    let transport = FixtureBoxArtifactTransport::fixture(fixture.clone());
    transport.update_fixture(|fixture| {
        fixture.content.insert(
            (current.file_id.clone(), current.version_id.clone()),
            b"jello box world".to_vec(),
        );
    });
    let mut sha_provider = provider(transport, &scope);
    let request = full_content_request(&scope, &current, &bytes);
    assert_eq!(
        sha_provider
            .read_content(&request)
            .expect_err("SHA-1 mismatch"),
        BoxArtifactError::Sha1Mismatch
    );

    let transport = FixtureBoxArtifactTransport::fixture(fixture.clone());
    let wrong_range = ByteRange::new(1, bytes.len() as u64).expect("range");
    transport.update_fixture(|fixture| {
        fixture.set_content_range(
            current.file_id.clone(),
            current.version_id.clone(),
            wrong_range,
        );
    });
    let mut range_provider = provider(transport, &scope);
    let request = full_content_request(&scope, &current, &bytes);
    assert_eq!(
        range_provider
            .read_content(&request)
            .expect_err("range mismatch"),
        BoxArtifactError::RangeMismatch
    );
}

#[test]
fn stale_version_and_partial_content_are_not_adoptable() {
    let (fixture, current, bytes) = fixture();
    let scope = scope();
    let transport = FixtureBoxArtifactTransport::fixture(fixture);
    let mut provider = provider(transport, &scope);
    let stale = ArtifactRevisionFence {
        file_id: current.file_id.clone(),
        version_id: version("version-1"),
        sha1: Sha1Digest::from_bytes(b"older box data"),
        size: b"older box data".len() as u64,
    };
    let stale_request = ContentReadRequest::new(
        scope.clone(),
        stale,
        ByteRange::new(0, b"older box data".len() as u64 - 1).expect("stale range"),
    )
    .expect("stale request");
    assert_eq!(
        provider
            .read_content(&stale_request)
            .expect_err("stale revision"),
        BoxArtifactError::StaleRevision
    );

    let current_request = full_content_request(&scope, &current, &bytes);
    let partial_range = ByteRange::new(0, 4).expect("partial range");
    let partial_request = ContentReadRequest::new(
        scope.clone(),
        current_request.revision.clone(),
        partial_range,
    )
    .expect("partial request");
    let partial = provider
        .read_content(&partial_request)
        .expect("partial read");
    assert!(!partial.complete);
    assert!(!partial.sha1_verified);
    let file = provider
        .read_file(&FileReadRequest::new(scope.clone(), current.file_id.clone()).expect("file"))
        .expect("file projection")
        .metadata
        .expect("metadata");
    let consumer = MissionArtifactResultConsumer::new(
        scope.clone(),
        BOX_ARTIFACT_PROVIDER_VERSION,
        partial.registration_digest.clone(),
    )
    .expect("consumer");
    assert_eq!(
        consumer
            .consume(&result_binding(), file, partial)
            .expect_err("partial content must not be adoptable"),
        BoxArtifactError::NotAdoptable {
            reason: "receipt is outside the Mission scope or is partial/ambiguous"
        }
    );
}

#[test]
fn deletion_and_access_loss_remain_explicit_projections() {
    let (fixture, current, _bytes) = fixture();
    let scope = scope();
    let transport = FixtureBoxArtifactTransport::fixture(fixture);
    let mut provider = provider(transport.clone(), &scope);
    let request = FileReadRequest::new(scope.clone(), current.file_id.clone()).expect("file");

    transport.update_fixture(|fixture| {
        fixture.set_file_failure(current.file_id.clone(), FixtureFileFailure::NotFound);
    });
    let deleted = provider.read_file(&request).expect("not found projection");
    assert_eq!(deleted.availability, ArtifactAvailability::NotFound);
    assert!(deleted.metadata.is_none());
    assert_eq!(provider.state(), BoxProviderState::NotFound);

    transport.update_fixture(|fixture| {
        fixture.set_file_failure(current.file_id.clone(), FixtureFileFailure::AccessLost);
    });
    let access_lost = provider
        .read_file(&request)
        .expect("access loss projection");
    assert_eq!(access_lost.availability, ArtifactAvailability::AccessLost);
    assert!(access_lost.metadata.is_none());
    assert_eq!(provider.state(), BoxProviderState::AccessLost);
}

#[test]
fn blocked_env_and_revocation_fence_reads() {
    let (fixture, _current, _bytes) = fixture();
    let scope = scope();
    let registration = registration(&scope);
    let mut blocked = BoxArtifactProvider::new(
        registration,
        FixtureBoxArtifactTransport::fixture(fixture.clone()),
        BlockedEnvCredentialResolver,
    )
    .expect("blocked provider");
    assert_eq!(
        blocked.probe().expect_err("blocked env"),
        BoxArtifactError::BlockedEnv
    );
    assert_eq!(blocked.state(), BoxProviderState::BlockedEnv);
    assert_eq!(blocked.provenance(), ProviderProvenance::BlockedEnv);
    assert!(!blocked.native_transport());
    assert!(!blocked.native_connected());

    let mut provider = provider(FixtureBoxArtifactTransport::fixture(fixture), &scope);
    let revocation = provider.revoke().expect("revoke");
    assert_eq!(revocation.revocation_revision, 2);
    assert_eq!(provider.state(), BoxProviderState::Revoked);
    assert_eq!(
        provider.read_user().expect_err("revoked read"),
        BoxArtifactError::Revoked
    );
}

#[test]
fn service_and_consumer_seal_a_non_mutating_result_with_all_fences() {
    let (fixture, current, bytes) = fixture();
    let scope = scope();
    let registration = registration(&scope);
    let provider = BoxArtifactProvider::new(
        registration,
        FixtureBoxArtifactTransport::fixture(fixture),
        StaticBoxCredentialResolver::new(TOKEN),
    )
    .expect("provider");
    let mut service = BoxArtifactService::new(provider).expect("service");
    let definition: &BoxArtifactServiceDefinition = service.definition();
    definition.validate().expect("definition");
    assert!(definition.read_only);
    assert!(!definition.external_writes);
    assert!(!definition.durable_readback);

    let request = ArtifactProposalRequest::new(
        scope.clone(),
        result_binding(),
        current.revision(),
        ByteRange::new(0, bytes.len() as u64 - 1).expect("range"),
    )
    .expect("proposal request");
    let result = service
        .propose_artifact_result(request)
        .expect("proposal result");
    result.validate().expect("valid result");
    assert_eq!(result.status, MissionArtifactResultStatus::Proposed);
    assert_eq!(result.proposal.file_id, current.file_id);
    assert_eq!(result.proposal.version_id, current.version_id);
    assert_eq!(result.proposal.sha1, current.sha1);
    assert_eq!(result.proposal.size, bytes.len() as u64);
    assert_eq!(result.source_mission_revision, 7);
    assert_eq!(result.source_result_revision, 3);
    assert!(!result.external_write_performed);
    assert!(!result.native_connected);
}

#[test]
fn consumer_rejects_tampered_cross_scope_and_ambiguous_receipts() {
    let (fixture, current, bytes) = fixture();
    let scope = scope();
    let transport = FixtureBoxArtifactTransport::fixture(fixture);
    let mut provider = provider(transport, &scope);
    let content_request = full_content_request(&scope, &current, &bytes);
    let content = provider.read_content(&content_request).expect("content");
    let file = provider
        .read_file(&FileReadRequest::new(scope.clone(), current.file_id.clone()).expect("file"))
        .expect("file")
        .metadata
        .expect("metadata");
    let consumer = MissionArtifactResultConsumer::new(
        scope.clone(),
        BOX_ARTIFACT_PROVIDER_VERSION,
        content.registration_digest.clone(),
    )
    .expect("consumer");

    let mut tampered = content.clone();
    tampered.bytes[0] ^= 1;
    assert!(matches!(
        consumer.consume(&result_binding(), file.clone(), tampered),
        Err(BoxArtifactError::NotAdoptable { .. })
    ));

    let other_scope = BoxArtifactScope::new(
        enterprise("enterprise-2"),
        user("user-2"),
        Some(folder("folder-root")),
        None,
        project("project-1"),
        mission("mission-1"),
    )
    .expect("other scope");
    let other_source = MissionResultBinding::new(
        project("project-1"),
        mission("mission-other"),
        7,
        result("result-2"),
        1,
    )
    .expect("other source");
    assert_eq!(
        MissionArtifactResultConsumer::new(
            other_scope,
            BOX_ARTIFACT_PROVIDER_VERSION,
            content.registration_digest.clone(),
        )
        .expect("other consumer")
        .consume(&other_source, file.clone(), content.clone())
        .expect_err("cross scope"),
        BoxArtifactError::NotAdoptable {
            reason: "receipt is outside the Mission scope or is partial/ambiguous"
        }
    );

    let mut ambiguous = content;
    ambiguous.native_connected = true;
    assert!(matches!(
        consumer.consume(&result_binding(), file, ambiguous),
        Err(BoxArtifactError::NotAdoptable { .. })
    ));
}

#[test]
fn redaction_excludes_tokens_names_email_and_content_bytes_from_debug() {
    let (fixture, current, bytes) = fixture();
    let scope = scope();
    let secret = SecretReference::new(
        "secret-ref-redaction",
        scope.digest(),
        1,
        BoxAuthMethod::JwtBearer,
    )
    .expect("secret");
    let debug = format!("{secret:?} {fixture:?} {current:?}");
    assert!(!debug.contains(TOKEN));
    assert!(!debug.contains("Alice Customer"));
    assert!(!debug.contains("alice@example.invalid"));
    assert!(!debug.contains("customer-secret-name.txt"));

    let transport = FixtureBoxArtifactTransport::fixture(fixture);
    let mut provider = provider(transport, &scope);
    let content = provider
        .read_content(&full_content_request(&scope, &current, &bytes))
        .expect("content");
    let debug = format!("{content:?}");
    assert!(!debug.contains("hello box world"));
    assert!(debug.contains("byte_len"));
}

#[test]
fn native_transport_requires_https_and_layer_one_has_no_mutation_surface() {
    assert_eq!(
        hartevo_box_artifact_plugin::UreqBoxArtifactTransport::new("http://example.com")
            .expect_err("insecure native URL"),
        BoxArtifactError::InvalidConfiguration
    );
    let definition = BoxArtifactServiceDefinition::layer1();
    assert_eq!(definition.operations.len(), 8);
}

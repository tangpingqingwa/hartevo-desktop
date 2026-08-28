use hartevo_airbyte_sync_result_plugin::{
    AirbyteCloudProvider, AirbyteProviderError, AirbyteRegistration, AirbyteRegistrationRegistry,
    AirbyteScope, AirbyteSyncResultService, AirbyteTransport, AirbyteTransportError,
    AttemptResponse, CatalogEntry, CatalogPage, FakeTransport, PermissionSnapshot,
    ProjectionCompleteness, ProviderAttemptRecord, ProviderIdentity, RegistrationId,
    SchemaFingerprint, SecretReference, SyncAttemptStatus, SyncResultRecordingLog,
    TransportProvenance,
};

fn fixture_scope(
    workspace_id: &str,
    source_id: &str,
    destination_id: &str,
    connection_id: &str,
    stream_name: &str,
    job_id: &str,
    attempt_id: &str,
) -> AirbyteScope {
    AirbyteScope::from_ids(
        workspace_id,
        "https://api.airbyte.com",
        1,
        source_id,
        1,
        destination_id,
        1,
        connection_id,
        1,
        "public",
        stream_name,
        1,
        "a".repeat(64),
        job_id,
        1,
        attempt_id,
        1,
        "mission-airbyte-1",
        "project-airbyte-1",
        "work-product-airbyte-1",
    )
    .expect("fixture scope")
}

fn scope() -> AirbyteScope {
    fixture_scope(
        "workspace-airbyte-1",
        "source-airbyte-1",
        "destination-airbyte-1",
        "connection-airbyte-1",
        "users",
        "job-airbyte-1",
        "attempt-airbyte-1",
    )
}

fn registration(scope: AirbyteScope) -> AirbyteRegistration {
    AirbyteRegistration::new(
        RegistrationId::new("registration-airbyte-1").expect("registration id"),
        scope,
        SecretReference::oauth("opaque-oauth-handle", 1).expect("secret"),
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "airbyte-cloud-release-1").expect("provider"),
        1,
    )
    .expect("registration")
}

fn provider_with_attempt(
    scope: &AirbyteScope,
    record: ProviderAttemptRecord,
) -> AirbyteCloudProvider<FakeTransport> {
    let mut response = AttemptResponse::for_scope(scope, TransportProvenance::Fake);
    response.record = record;
    AirbyteCloudProvider::new(
        registration(scope.clone()),
        FakeTransport::new(vec![CatalogPage::for_scope(scope)], response),
    )
    .expect("provider")
}

#[test]
fn all_provider_statuses_are_projected_without_native_claims() {
    for status in [
        SyncAttemptStatus::Queued,
        SyncAttemptStatus::Running,
        SyncAttemptStatus::Succeeded,
        SyncAttemptStatus::Failed,
        SyncAttemptStatus::Cancelled,
        SyncAttemptStatus::Incomplete,
        SyncAttemptStatus::ProviderUnknown,
    ] {
        let scope = scope();
        let record = ProviderAttemptRecord::for_scope(&scope, status, 1_744_550_401);
        let mut provider = provider_with_attempt(&scope, record);
        let projection = provider.read_attempt("status-matrix").expect("projection");
        assert_eq!(projection.status, status);
        assert!(!projection.connected);
        assert!(!projection.native);
        assert!(!projection.provenance.is_native());
        assert!(!projection.provenance.claims_connected());
    }
}

#[test]
fn source_destination_stream_job_and_attempt_drift_fail_closed() {
    let expected = scope();
    let cases = [
        (
            fixture_scope(
                "workspace-drift",
                "source-airbyte-1",
                "destination-airbyte-1",
                "connection-airbyte-1",
                "users",
                "job-airbyte-1",
                "attempt-airbyte-1",
            ),
            AirbyteProviderError::WorkspaceDrift,
        ),
        (
            fixture_scope(
                "workspace-airbyte-1",
                "source-drift",
                "destination-airbyte-1",
                "connection-airbyte-1",
                "users",
                "job-airbyte-1",
                "attempt-airbyte-1",
            ),
            AirbyteProviderError::SourceDrift,
        ),
        (
            fixture_scope(
                "workspace-airbyte-1",
                "source-airbyte-1",
                "destination-drift",
                "connection-airbyte-1",
                "users",
                "job-airbyte-1",
                "attempt-airbyte-1",
            ),
            AirbyteProviderError::DestinationDrift,
        ),
        (
            fixture_scope(
                "workspace-airbyte-1",
                "source-airbyte-1",
                "destination-airbyte-1",
                "connection-drift",
                "users",
                "job-airbyte-1",
                "attempt-airbyte-1",
            ),
            AirbyteProviderError::ConnectionDrift,
        ),
        (
            fixture_scope(
                "workspace-airbyte-1",
                "source-airbyte-1",
                "destination-airbyte-1",
                "connection-airbyte-1",
                "stream-drift",
                "job-airbyte-1",
                "attempt-airbyte-1",
            ),
            AirbyteProviderError::StreamDrift,
        ),
        (
            fixture_scope(
                "workspace-airbyte-1",
                "source-airbyte-1",
                "destination-airbyte-1",
                "connection-airbyte-1",
                "users",
                "job-drift",
                "attempt-airbyte-1",
            ),
            AirbyteProviderError::JobDrift,
        ),
        (
            fixture_scope(
                "workspace-airbyte-1",
                "source-airbyte-1",
                "destination-airbyte-1",
                "connection-airbyte-1",
                "users",
                "job-airbyte-1",
                "attempt-drift",
            ),
            AirbyteProviderError::AttemptDrift,
        ),
    ];

    for (drifted, expected_error) in cases {
        let record =
            ProviderAttemptRecord::for_scope(&drifted, SyncAttemptStatus::Failed, 1_744_550_401);
        let mut provider = provider_with_attempt(&expected, record);
        assert_eq!(
            provider.read_attempt("drift").expect_err("drift accepted"),
            expected_error
        );
    }
}

#[test]
fn schema_mismatch_is_explicit_and_not_a_success_projection() {
    let scope = scope();
    let record = ProviderAttemptRecord::from_values(
        &scope,
        SyncAttemptStatus::Succeeded,
        Some(10),
        Some(10),
        Some(1_024),
        Some(1_024),
        Some(SchemaFingerprint::new("a".repeat(64)).expect("source schema")),
        Some(SchemaFingerprint::new("b".repeat(64)).expect("destination schema")),
        false,
        ProjectionCompleteness::Complete,
        None,
        1_744_550_401,
        512,
    );
    let mut provider = provider_with_attempt(&scope, record);
    assert_eq!(
        provider
            .read_attempt("schema-mismatch")
            .expect_err("schema mismatch accepted"),
        AirbyteProviderError::SchemaMismatch
    );
}

#[test]
fn truncation_and_unknown_are_review_only_evidence() {
    let scope = scope();
    let record = ProviderAttemptRecord::from_values(
        &scope,
        SyncAttemptStatus::Incomplete,
        Some(10),
        Some(9),
        Some(1_024),
        Some(900),
        Some(SchemaFingerprint::new("a".repeat(64)).expect("schema")),
        Some(SchemaFingerprint::new("a".repeat(64)).expect("schema")),
        true,
        ProjectionCompleteness::Truncated,
        None,
        1_744_550_401,
        512,
    );
    let mut provider = provider_with_attempt(&scope, record);
    let projection = provider.read_attempt("truncated").expect("projection");
    assert!(!projection.is_complete());
    assert!(projection.response_truncated);
    assert_eq!(projection.status, SyncAttemptStatus::Incomplete);
}

#[test]
fn tamper_is_detected_before_recording() {
    let scope = scope();
    let mut record =
        ProviderAttemptRecord::for_scope(&scope, SyncAttemptStatus::Succeeded, 1_744_550_401);
    record.records_read = Some(999_999);
    let mut provider = provider_with_attempt(&scope, record);
    assert_eq!(
        provider
            .read_attempt("tampered")
            .expect_err("tamper accepted"),
        AirbyteProviderError::AttemptTampered
    );

    let mut page = CatalogPage::for_scope(&scope);
    page.response_bytes = 2;
    let response = AttemptResponse::for_scope(&scope, TransportProvenance::Fake);
    let mut catalog_provider = AirbyteCloudProvider::new(
        registration(scope.clone()),
        FakeTransport::new(vec![page], response),
    )
    .expect("provider");
    assert_eq!(
        catalog_provider
            .read_catalog(100)
            .expect_err("page tamper accepted"),
        AirbyteProviderError::CatalogTampered
    );
}

#[test]
fn repeated_page_tokens_and_http_adversaries_fail_closed() {
    let scope = scope();
    let mut oversized_page = provider_with_attempt(
        &scope,
        ProviderAttemptRecord::for_scope(&scope, SyncAttemptStatus::Failed, 1_744_550_401),
    );
    assert_eq!(
        oversized_page
            .read_catalog(101)
            .expect_err("unbounded page accepted"),
        AirbyteProviderError::PaginationLimit
    );

    let entry = CatalogEntry::for_scope(&scope);
    let page_one =
        CatalogPage::new(1, vec![entry.clone()], Some("page-1".into()), 512).expect("page one");
    let page_two = CatalogPage::new(2, vec![entry], Some("page-1".into()), 512).expect("page two");
    let response = AttemptResponse::for_scope(&scope, TransportProvenance::Fake);
    let mut provider = AirbyteCloudProvider::new(
        registration(scope.clone()),
        FakeTransport::new(vec![page_one, page_two], response),
    )
    .expect("provider");
    assert_eq!(
        provider.read_catalog(100).expect_err("page loop accepted"),
        AirbyteProviderError::PaginationLoop
    );

    for error in [
        AirbyteTransportError::Unauthorized,
        AirbyteTransportError::Forbidden,
        AirbyteTransportError::NotFound,
        AirbyteTransportError::Conflict,
        AirbyteTransportError::RateLimited {
            retry_after_seconds: 2,
        },
        AirbyteTransportError::Timeout,
        AirbyteTransportError::ServerError { status: 503 },
        AirbyteTransportError::AccessLost,
    ] {
        let mut failing = AirbyteCloudProvider::new(
            registration(scope.clone()),
            FakeTransport::from_scope(&scope).fail_catalog_with(error.clone()),
        )
        .expect("provider");
        assert_eq!(
            failing
                .read_catalog(100)
                .expect_err("transport error hidden"),
            AirbyteProviderError::Transport(error)
        );
        assert!(!failing.connected());
        assert!(!failing.native());
    }
}

#[derive(Debug)]
struct WrongRequestTransport {
    scope: AirbyteScope,
    response: AttemptResponse,
}

impl AirbyteTransport for WrongRequestTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_catalog(
        &mut self,
        _request: &hartevo_airbyte_sync_result_plugin::CatalogReadRequest,
    ) -> Result<CatalogPage, AirbyteTransportError> {
        Ok(CatalogPage::for_scope(&self.scope))
    }

    fn read_attempt(
        &mut self,
        _request: &hartevo_airbyte_sync_result_plugin::AttemptReadRequest,
    ) -> Result<AttemptResponse, AirbyteTransportError> {
        Ok(self.response.clone())
    }
}

#[test]
fn idempotency_mismatch_and_secret_revocation_block_reads() {
    let scope = scope();
    let response = AttemptResponse::for_scope(&scope, TransportProvenance::Loopback);
    let mut provider = AirbyteCloudProvider::new(
        registration(scope.clone()),
        WrongRequestTransport {
            scope: scope.clone(),
            response,
        },
    )
    .expect("provider");
    assert_eq!(
        provider
            .read_attempt("idempotency-mismatch")
            .expect_err("request mismatch accepted"),
        AirbyteProviderError::IdempotencyMismatch
    );

    let mut secret = SecretReference::service_token("opaque-token-to-revoke", 1).expect("secret");
    secret.revoke();
    let revoked_registration = AirbyteRegistration::new(
        RegistrationId::new("registration-revoked-secret").expect("id"),
        scope.clone(),
        secret,
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "airbyte-cloud-release-1").expect("provider"),
        1,
    )
    .expect("registration");
    let mut revoked =
        AirbyteCloudProvider::new(revoked_registration, FakeTransport::from_scope(&scope))
            .expect("provider");
    assert_eq!(
        revoked
            .read_catalog(100)
            .expect_err("revoked secret accepted"),
        AirbyteProviderError::SecretRevoked
    );
}

#[test]
fn registration_is_reversible_and_secret_material_stays_opaque() {
    let scope = scope();
    let mut registry = AirbyteRegistrationRegistry::default();
    let registration = registration(scope);
    let opaque = "opaque-oauth-handle";
    assert!(!format!("{:?}", registration.secret_reference()).contains(opaque));
    let serialized = serde_json::to_string(&registration).expect("safe registration JSON");
    assert!(!serialized.contains(opaque));
    let id = registration.id().clone();
    registry.register(registration).expect("register");
    registry.revoke(&id).expect("revoke");
    assert!(!registry.get(&id).expect("registration").is_active());
    registry.restore(&id).expect("restore");
    assert!(registry.get(&id).expect("registration").is_active());
    registry.reverse(&id).expect("reverse");
    assert!(!registry.get(&id).expect("registration").is_active());
}

#[test]
fn service_exposes_the_complete_layer_one_vertical_slice_only() {
    let scope = scope();
    let mut service = AirbyteSyncResultService::new(
        registration(scope.clone()),
        FakeTransport::from_scope(&scope),
    )
    .expect("service");
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.can_trigger_sync);
    assert!(!capabilities.can_cancel_sync);
    assert!(!capabilities.can_mutate_connection);
    assert!(!capabilities.can_mutate_credential);
    assert!(!capabilities.can_adopt_outcome);

    let catalog = service
        .read_connection_stream_catalog(100)
        .expect("catalog");
    let attempt = service
        .read_sync_attempt("service-idempotency")
        .expect("attempt");
    let proposal = service
        .compile_sync_result_proposal(&catalog, &attempt, "service-idempotency")
        .expect("proposal");
    let mut log = SyncResultRecordingLog::default();
    let recorded = service
        .record_sync_result(&mut log, &proposal)
        .expect("recording");
    assert!(!recorded.connected);
    assert!(!recorded.native);
    assert!(!recorded.provider_receipt);
    assert!(!recorded.outcome_adopted);

    service.revoke_registration().expect("revoke");
    assert_eq!(
        service
            .read_sync_attempt("revoked")
            .expect_err("revoked registration read"),
        AirbyteProviderError::RegistrationRevoked
    );
}

#[test]
fn every_layer_one_provenance_is_non_native_and_non_connected() {
    let scope = scope();
    assert_fixture_provenance(
        &scope,
        hartevo_airbyte_sync_result_plugin::RecordingTransport::from_scope(&scope),
        TransportProvenance::Recording,
    );
    assert_fixture_provenance(
        &scope,
        FakeTransport::from_scope(&scope),
        TransportProvenance::Fake,
    );
    assert_fixture_provenance(
        &scope,
        hartevo_airbyte_sync_result_plugin::LoopbackTransport::from_scope(&scope),
        TransportProvenance::Loopback,
    );
    let blocked = hartevo_airbyte_sync_result_plugin::BlockedEnvTransport;
    assert!(!blocked.provenance().is_native());
    assert!(!blocked.provenance().claims_connected());
}

fn assert_fixture_provenance<T: AirbyteTransport>(
    scope: &AirbyteScope,
    transport: T,
    provenance: TransportProvenance,
) {
    let mut provider = AirbyteCloudProvider::new(registration(scope.clone()), transport)
        .expect("fixture provider");
    assert_eq!(provider.provenance(), provenance);
    assert!(!provider.connected());
    assert!(!provider.native());
    assert!(!provider.read_catalog(100).expect("catalog").connected);
}

use chrono::{DateTime, TimeZone, Utc};
use codeartifact::{
    AwsAccountId, AwsCodeArtifactEvidenceState, AwsCodeArtifactOperation,
    AwsCodeArtifactProvenanceScope, AwsCodeArtifactProvenanceService, AwsCodeArtifactProvider,
    AwsCodeArtifactTransportError, CodeArtifactDomain, CodeArtifactRepository, ConsentScope,
    Cursor, DependencyMetadataInput, DescribePackageVersionRequest, DescribePackageVersionResponse,
    Digest, FixtureTransport, ListPackageVersionDependenciesRequest,
    ListPackageVersionDependenciesResponse, ListPackageVersionsRequest,
    ListPackageVersionsResponse, LoopbackTransport, MissionBinding, PackageFormat, PackageName,
    PackageOrigin, PackageVersion, PackageVersionFilter, PackageVersionObservation,
    PackageVersionStatus, PermissionSnapshot, ProjectBinding, RecordingTransport, SecretReference,
    TransportProvenance, VersionSortOrder, WorkProductBinding,
};
use hartevo_aws_codeartifact_provenance_result_plugin as codeartifact;

const RAW_SECRET_HANDLE: &str = "opaque-sigv4-handle-never-serialized";
const OBSERVED_AT: (i32, u32, u32, u32, u32, u32) = (2026, 8, 15, 12, 0, 0);

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(
        OBSERVED_AT.0,
        OBSERVED_AT.1,
        OBSERVED_AT.2,
        OBSERVED_AT.3,
        OBSERVED_AT.4,
        OBSERVED_AT.5,
    )
    .single()
    .expect("valid test time")
}

fn scope() -> AwsCodeArtifactProvenanceScope {
    AwsCodeArtifactProvenanceScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        codeartifact::AwsRegion::new("us-east-1").expect("region"),
        CodeArtifactDomain::new("hartevo").expect("domain"),
        CodeArtifactRepository::new("production").expect("repository"),
        PackageFormat::new("npm").expect("format"),
        Some(codeartifact::PackageNamespace::new("@hartevo").expect("namespace")),
        PackageName::new("provenance-client").expect("package"),
        PackageVersion::new("1.2.3").expect("version"),
        MissionBinding::new("mission-589", 4).expect("mission"),
        ProjectBinding::new("project-589", 7).expect("project"),
        WorkProductBinding::new("work-product-589", 2).expect("work product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsCodeArtifactProvenanceScope) -> SecretReference {
    SecretReference::new(RAW_SECRET_HANDLE, scope).expect("secret reference")
}

fn permissions() -> PermissionSnapshot {
    PermissionSnapshot::readonly(3).expect("permissions")
}

fn consent() -> ConsentScope {
    ConsentScope::readonly("consent-589", 5).expect("consent")
}

fn observation(
    version: &str,
    revision: &str,
    origin: PackageOrigin,
    status: PackageVersionStatus,
    asset_count: u32,
) -> PackageVersionObservation {
    let package_version = PackageVersion::new(version).expect("package version");
    let arn = format!(
        "arn:aws:codeartifact:us-east-1:123456789012:package/hartevo/production/npm/provenance-client/{version}"
    );
    PackageVersionObservation::new(
        package_version,
        revision,
        origin,
        status,
        Some(now()),
        asset_count,
        Some(arn),
    )
    .expect("observation")
}

fn dependency_items() -> Vec<DependencyMetadataInput> {
    vec![
        DependencyMetadataInput::new(
            Some(codeartifact::PackageNamespace::new("@hartevo").expect("namespace")),
            PackageName::new("shared-types").expect("dependency package"),
            "^4.0.0",
        )
        .expect("dependency"),
    ]
}

fn complete_service() -> AwsCodeArtifactProvenanceService<RecordingTransport> {
    let scope = scope();
    let filter =
        PackageVersionFilter::new(None, 10, VersionSortOrder::PublishedTime).expect("filter");
    let list_request = ListPackageVersionsRequest::new(&scope, filter.clone(), None).expect("list");
    let describe_request = DescribePackageVersionRequest::for_scope(&scope).expect("describe");
    let dependency_request =
        ListPackageVersionDependenciesRequest::new(&scope, 10, None).expect("dependencies");
    let metadata = observation(
        "1.2.3",
        "revision-a",
        PackageOrigin::Internal,
        PackageVersionStatus::Published,
        3,
    );
    let list_response = ListPackageVersionsResponse::new(
        &list_request,
        vec![metadata.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_response = DescribePackageVersionResponse::new(
        &describe_request,
        metadata,
        512,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let dependency_response = ListPackageVersionDependenciesResponse::new(
        &dependency_request,
        dependency_items(),
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("dependency response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    transport.push_dependency_response(Ok(dependency_response));
    service_from_transport(transport)
}

fn service_from_transport(
    transport: RecordingTransport,
) -> AwsCodeArtifactProvenanceService<RecordingTransport> {
    let scope = scope();
    let provider = AwsCodeArtifactProvider::new(transport).expect("provider");
    AwsCodeArtifactProvenanceService::new(
        scope.clone(),
        secret(&scope),
        permissions(),
        consent(),
        provider,
        now(),
    )
    .expect("service")
}

#[test]
fn contract_scope_registration_and_service_definition_are_digest_fenced() {
    codeartifact::validate_contract().expect("contract validation");
    let scope = scope();
    let service = complete_service();
    assert_eq!(service.scope().digest(), scope.digest());
    service
        .service_definition()
        .validate()
        .expect("service definition");
    service.registration().validate().expect("registration");
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET_HANDLE));
    assert!(!debug.contains(RAW_SECRET_HANDLE));
    assert_eq!(
        service
            .describe_capabilities()
            .operations
            .iter()
            .filter(|operation| operation.contains("package"))
            .count(),
        3
    );
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(!service.describe_capabilities().outcome_adoption);

    let request = service.default_request(now()).expect("request");
    assert!(request.include_dependencies());
    assert!(
        request
            .list_request()
            .expect("list request")
            .path_and_query()
            .contains("package")
    );
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_connected_or_native() {
    let artifact_scope = scope();
    let fixture_transport = FixtureTransport::for_scope(&artifact_scope, now()).expect("fixture");
    let fixture_provider = AwsCodeArtifactProvider::new(fixture_transport).expect("provider");
    let mut fixture_service = AwsCodeArtifactProvenanceService::new(
        artifact_scope.clone(),
        secret(&artifact_scope),
        permissions(),
        consent(),
        fixture_provider,
        now(),
    )
    .expect("fixture service");
    let fixture = fixture_service
        .propose(fixture_service.default_request(now()).expect("request"))
        .expect("fixture proposal");
    assert_eq!(fixture.state, AwsCodeArtifactEvidenceState::Completed);
    assert_eq!(fixture.provenance, TransportProvenance::Fixture);
    assert!(!fixture.connected);
    assert!(!fixture.native);
    assert!(!fixture.first_party);
    assert!(!fixture.provider_receipt);
    assert!(!fixture.can_be_adopted());

    let loopback_transport =
        LoopbackTransport::for_scope(&artifact_scope, now()).expect("loopback");
    let loopback_provider = AwsCodeArtifactProvider::new(loopback_transport).expect("provider");
    let mut loopback_service = AwsCodeArtifactProvenanceService::new(
        artifact_scope.clone(),
        secret(&artifact_scope),
        permissions(),
        consent(),
        loopback_provider,
        now(),
    )
    .expect("loopback service");
    let loopback = loopback_service
        .propose(loopback_service.default_request(now()).expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback.provenance, TransportProvenance::Loopback);
    assert!(!loopback.connected);
    assert!(!loopback.native);

    let blocked_scope = scope();
    let blocked_provider = AwsCodeArtifactProvider::default();
    let mut blocked_service = AwsCodeArtifactProvenanceService::new(
        blocked_scope.clone(),
        secret(&blocked_scope),
        permissions(),
        consent(),
        blocked_provider,
        now(),
    )
    .expect("blocked service");
    let blocked = blocked_service
        .propose(blocked_service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(blocked.state, AwsCodeArtifactEvidenceState::ProviderUnknown);
    assert_eq!(blocked.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        blocked.failure.as_ref().expect("blocked failure").category,
        "blocked_env"
    );
    assert!(!blocked.connected);
    assert!(!blocked.native);
}

#[test]
#[allow(clippy::too_many_lines)]
fn paginated_versions_bind_scope_and_filter_and_describe_exact_revision() {
    let scope = scope();
    let filter =
        PackageVersionFilter::new(None, 1, VersionSortOrder::PublishedTime).expect("filter");
    let first_request =
        ListPackageVersionsRequest::new(&scope, filter.clone(), None).expect("page 1");
    let cursor = Cursor::new(
        "opaque-next-token",
        first_request.pagination_binding_digest(),
        2,
    )
    .expect("cursor");
    let second_request =
        ListPackageVersionsRequest::new(&scope, filter.clone(), Some(cursor.clone()))
            .expect("page 2");
    let describe_request = DescribePackageVersionRequest::for_scope(&scope).expect("describe");
    let dependency_request =
        ListPackageVersionDependenciesRequest::new(&scope, 1, None).expect("dependencies");
    let first = ListPackageVersionsResponse::new(
        &first_request,
        vec![observation(
            "1.2.2",
            "revision-old",
            PackageOrigin::External,
            PackageVersionStatus::Published,
            2,
        )],
        Some(cursor),
        256,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let target = observation(
        "1.2.3",
        "revision-a",
        PackageOrigin::Internal,
        PackageVersionStatus::Published,
        3,
    );
    let second = ListPackageVersionsResponse::new(
        &second_request,
        vec![target.clone()],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("second page");
    let describe = DescribePackageVersionResponse::new(
        &describe_request,
        target,
        256,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let dependencies = ListPackageVersionDependenciesResponse::new(
        &dependency_request,
        dependency_items(),
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("dependency response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(first));
    transport.push_list_response(Ok(second));
    transport.push_describe_response(Ok(describe));
    transport.push_dependency_response(Ok(dependencies));
    let mut service = service_from_transport(transport);
    let request = service
        .request(filter, None, true, now())
        .expect("read request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, AwsCodeArtifactEvidenceState::Completed);
    assert_eq!(proposal.list_pages, 2);
    assert!(proposal.list_complete);
    assert!(proposal.dependency_complete);
    assert_eq!(proposal.package_version.expect("target").asset_count(), 3);
    assert_eq!(service.provider().transport().requests().len(), 4);
    let request_debug = format!("{:?}", service.provider().transport().requests());
    assert!(!request_debug.contains("opaque-next-token"));

    let other_filter = PackageVersionFilter::new(
        Some(PackageVersionStatus::Published),
        1,
        VersionSortOrder::PublishedTime,
    )
    .expect("other filter");
    assert!(
        ListPackageVersionsRequest::new(
            &scope,
            other_filter,
            Some(
                Cursor::new(
                    "opaque-next-token",
                    ListPackageVersionsRequest::new(&scope, filter_for_cursor(), None)
                        .expect("cursor request")
                        .pagination_binding_digest(),
                    2,
                )
                .expect("cursor"),
            ),
        )
        .is_err()
    );
}

fn filter_for_cursor() -> PackageVersionFilter {
    PackageVersionFilter::new(None, 1, VersionSortOrder::PublishedTime).expect("filter")
}

#[test]
fn mission_revision_scope_drift_is_rejected_before_provider_reads() {
    let service = complete_service();
    let original_scope = scope();
    let changed_scope = AwsCodeArtifactProvenanceScope::new(
        original_scope.account().clone(),
        original_scope.region().clone(),
        original_scope.domain().clone(),
        original_scope.repository().clone(),
        original_scope.format().clone(),
        original_scope.namespace().cloned(),
        original_scope.package().clone(),
        original_scope.version().clone(),
        MissionBinding::new("mission-589", 5).expect("changed mission revision"),
        original_scope.project().clone(),
        original_scope.work_product().clone(),
    )
    .expect("changed scope");
    let provider = AwsCodeArtifactProvider::new(RecordingTransport::default()).expect("provider");
    let result = AwsCodeArtifactProvenanceService::with_registration(
        changed_scope,
        service.registration().clone(),
        provider,
    );
    assert!(result.is_err());
}

#[test]
fn revision_status_origin_drift_is_non_adoptable() {
    let scope = scope();
    let filter = PackageVersionFilter::all(10).expect("filter");
    let list_request = ListPackageVersionsRequest::new(&scope, filter.clone(), None).expect("list");
    let describe_request = DescribePackageVersionRequest::for_scope(&scope).expect("describe");
    let listed = observation(
        "1.2.3",
        "revision-a",
        PackageOrigin::Internal,
        PackageVersionStatus::Published,
        3,
    );
    let described = observation(
        "1.2.3",
        "revision-b",
        PackageOrigin::External,
        PackageVersionStatus::Archived,
        4,
    );
    let list_response = ListPackageVersionsResponse::new(
        &list_request,
        vec![listed],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_response = DescribePackageVersionResponse::new(
        &describe_request,
        described,
        512,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    let mut service = service_from_transport(transport);
    let proposal = service
        .propose(
            service
                .request(filter, None, false, now())
                .expect("request"),
        )
        .expect("proposal");
    assert_eq!(proposal.state, AwsCodeArtifactEvidenceState::RevisionDrift);
    assert!(!proposal.can_be_adopted());
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn dependency_truncation_is_explicit_and_non_adoptable() {
    let scope = scope();
    let filter = PackageVersionFilter::all(10).expect("filter");
    let list_request = ListPackageVersionsRequest::new(&scope, filter.clone(), None).expect("list");
    let describe_request = DescribePackageVersionRequest::for_scope(&scope).expect("describe");
    let dependency_request =
        ListPackageVersionDependenciesRequest::new(&scope, 10, None).expect("dependency request");
    let dependency_cursor = Cursor::new(
        "dependency-next-token",
        dependency_request.pagination_binding_digest(),
        2,
    )
    .expect("dependency cursor");
    let metadata = observation(
        "1.2.3",
        "revision-a",
        PackageOrigin::Internal,
        PackageVersionStatus::Published,
        3,
    );
    let list_response = ListPackageVersionsResponse::new(
        &list_request,
        vec![metadata.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_response = DescribePackageVersionResponse::new(
        &describe_request,
        metadata,
        512,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let dependency_response = ListPackageVersionDependenciesResponse::new(
        &dependency_request,
        dependency_items(),
        Some(dependency_cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("truncated dependencies");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    transport.push_dependency_response(Ok(dependency_response));
    let mut service = service_from_transport(transport);
    let proposal = service
        .propose(service.request(filter, None, true, now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, AwsCodeArtifactEvidenceState::Partial);
    assert!(!proposal.dependency_complete);
    assert!(
        proposal
            .dependencies
            .as_ref()
            .expect("dependency summary")
            .truncated
    );
    assert!(!proposal.can_be_adopted());
}

#[test]
fn transport_errors_are_classified_without_native_claims() {
    let cases = [
        (
            AwsCodeArtifactTransportError::BadRequest,
            AwsCodeArtifactEvidenceState::ProviderUnknown,
            Some(400),
        ),
        (
            AwsCodeArtifactTransportError::Unauthorized,
            AwsCodeArtifactEvidenceState::AccessLoss,
            Some(401),
        ),
        (
            AwsCodeArtifactTransportError::Forbidden,
            AwsCodeArtifactEvidenceState::AccessLoss,
            Some(403),
        ),
        (
            AwsCodeArtifactTransportError::NotFound,
            AwsCodeArtifactEvidenceState::NotFound,
            Some(404),
        ),
        (
            AwsCodeArtifactTransportError::Conflict,
            AwsCodeArtifactEvidenceState::ProviderUnknown,
            Some(409),
        ),
        (
            AwsCodeArtifactTransportError::RateLimited {
                retry_after_seconds: Some(9),
            },
            AwsCodeArtifactEvidenceState::Throttled,
            Some(429),
        ),
        (
            AwsCodeArtifactTransportError::ServerError { status: 503 },
            AwsCodeArtifactEvidenceState::ProviderUnknown,
            Some(503),
        ),
        (
            AwsCodeArtifactTransportError::Timeout,
            AwsCodeArtifactEvidenceState::ProviderUnknown,
            None,
        ),
    ];
    for (error, expected_state, expected_status) in cases {
        let mut transport = RecordingTransport::default();
        transport.push_list_response(Err(error));
        let mut service = service_from_transport(transport);
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected_state);
        let failure = proposal.failure.as_ref().expect("failure evidence");
        assert_eq!(failure.status_code, expected_status);
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!proposal.can_be_adopted());
    }
}

#[test]
fn tamper_replay_and_revocation_fail_closed() {
    let mut service = complete_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.evidence_digest = Digest::from_text("tampered");
    assert!(tampered.validate_integrity().is_err());

    let mut consumer = service.consumer().expect("consumer");
    assert!(consumer.consume(&tampered).is_err());
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    first.validate_integrity().expect("record integrity");

    service.revoke().expect("revoke");
    assert_eq!(
        service.registration().status(),
        codeartifact::RegistrationStatus::Revoked
    );
    assert!(service.default_request(now()).is_err());
    assert!(service.consumer().is_err());
    assert!(service.restore_registration().is_ok());
    assert!(service.consumer().is_ok());
    service.reverse().expect("reverse");
    assert!(service.restore_registration().is_err());
}

#[test]
fn provider_recordings_are_digest_only_and_operation_allowlist_is_bounded() {
    let scope = scope();
    let filter = PackageVersionFilter::all(10).expect("filter");
    let request = ListPackageVersionsRequest::new(&scope, filter, None).expect("request");
    let recorded = request.recorded_request();
    assert_eq!(
        recorded.operation,
        AwsCodeArtifactOperation::ListPackageVersions
    );
    assert_eq!(recorded.scope_digest, scope.digest());
    assert!(!format!("{recorded:?}").contains(RAW_SECRET_HANDLE));
    assert!(!request.path_and_query().is_empty());
    assert!(request.path_and_query().contains("package"));
    let serialized = serde_json::to_string(&recorded).expect("recording JSON");
    assert!(!serialized.contains("opaque-next-token"));
}

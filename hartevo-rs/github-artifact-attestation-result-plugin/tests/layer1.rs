use std::collections::BTreeSet;

use hartevo_github_artifact_attestation_result_plugin::{
    AttestationEvidenceState, AttestationMetadataDigestFence, GithubArtifactAttestationProvider,
    GithubArtifactAttestationScope, GithubArtifactAttestationService, GithubAttestationPage,
    GithubAttestationPermission, GithubAttestationRecord, GithubAuthKind, GithubOrganization,
    GithubRepository, GithubRepositoryName, GithubRepositoryVisibility, InstallationId,
    MissionGithubAttestationConsumer, MissionId, MissionScopeBinding, PermissionSnapshot,
    PredicateType, ProjectId, ProviderErrorKind, ReadLimits, ReadScript, RecordingTransport,
    RepositoryAccess, Revision, SecretReference, ServiceError, SubjectDigest, TransportError,
    TransportProvenance, Version, WorkProductId,
};

struct Fixture {
    scope: GithubArtifactAttestationScope,
    metadata: AttestationMetadataDigestFence,
}

fn fixture() -> Fixture {
    let metadata = AttestationMetadataDigestFence::new(
        b"builder@example.invalid",
        b"certificate-chain-metadata",
        b"signature-metadata",
        b"2026-08-15T00:00:00Z",
        b"predicate-metadata",
        b"verification-metadata",
    )
    .expect("metadata fence");
    let scope = GithubArtifactAttestationScope::new(
        InstallationId::new("installation-7").expect("installation"),
        GithubOrganization::new("acme").expect("organization"),
        GithubRepository::new(
            GithubOrganization::new("acme").expect("owner"),
            GithubRepositoryName::new("widget").expect("repository"),
            GithubRepositoryVisibility::Private,
        )
        .expect("repository")
        .with_repository_id(41)
        .expect("repository id"),
        SubjectDigest::new(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("subject"),
        PredicateType::new("provenance").expect("predicate"),
        PermissionSnapshot::least_privilege(),
        MissionScopeBinding::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(2).expect("project revision"),
            MissionId::new("mission-1").expect("mission"),
            Revision::new(3).expect("mission revision"),
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(4).expect("work product revision"),
        )
        .expect("mission binding"),
    )
    .expect("scope")
    .with_metadata_fence(metadata.clone())
    .expect("metadata scope fence");
    Fixture { scope, metadata }
}

fn record(fixture: &Fixture) -> GithubAttestationRecord {
    GithubAttestationRecord::new(
        b"https://opaque.invalid/bundle/1",
        41,
        GithubRepositoryVisibility::Private,
        RepositoryAccess::Accessible,
        fixture.scope.subject_digest.clone(),
        fixture.scope.predicate_type.clone(),
        fixture.metadata.clone(),
    )
    .expect("record")
}

fn page(records: Vec<GithubAttestationRecord>, next: Option<&[u8]>) -> GithubAttestationPage {
    GithubAttestationPage::new(
        1,
        records,
        next.map(|token| {
            hartevo_github_artifact_attestation_result_plugin::OpaquePageToken::new(token)
                .expect("token")
        }),
        GithubRepositoryVisibility::Private,
        RepositoryAccess::Accessible,
    )
    .expect("page")
}

fn make_service(
    scope: GithubArtifactAttestationScope,
    pages: impl IntoIterator<Item = Result<GithubAttestationPage, TransportError>>,
) -> GithubArtifactAttestationService<RecordingTransport> {
    let secret = SecretReference::new(
        "opaque-app-secret-reference",
        &scope,
        7,
        GithubAuthKind::App,
    )
    .expect("secret");
    let provider = GithubArtifactAttestationProvider::new(
        RecordingTransport::new(ReadScript::new(pages)),
        Version::new(1, 0, 0),
        TransportProvenance::Recording,
    )
    .expect("provider");
    GithubArtifactAttestationService::new(scope, secret, provider, ReadLimits::default())
        .expect("service")
}

#[test]
fn scope_registration_and_secret_are_fenced_and_redacted() {
    let fixture = fixture();
    let secret = SecretReference::new(
        "opaque-app-secret-reference",
        &fixture.scope,
        7,
        GithubAuthKind::OAuth,
    )
    .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-app-secret-reference"));
    assert_eq!(secret.auth_kind(), GithubAuthKind::OAuth);
    assert_eq!(fixture.scope.repository.owner.as_str(), "acme");
    assert_eq!(fixture.scope.predicate_type.as_str(), "provenance");
    assert!(fixture.scope.digest().len() == 64);
    assert!(PermissionSnapshot::new([GithubAttestationPermission::MetadataRead]).is_err());
    let provider = GithubArtifactAttestationProvider::new(
        RecordingTransport::new(ReadScript::default()),
        Version::new(1, 0, 0),
        TransportProvenance::Recording,
    )
    .expect("provider");
    let service = GithubArtifactAttestationService::new(
        fixture.scope.clone(),
        secret,
        provider,
        ReadLimits::default(),
    )
    .expect("service");
    assert!(service.registration().is_active());
    assert_eq!(service.registration().scope_digest, *fixture.scope.digest());
    assert!(
        GithubArtifactAttestationProvider::new(
            RecordingTransport::new(ReadScript::default()),
            Version::new(1, 0, 1),
            TransportProvenance::Recording,
        )
        .is_err()
    );
}

#[test]
fn successful_listing_proposal_record_verify_and_mission_consume_are_below_kernel() {
    let fixture = fixture();
    let expected = record(&fixture);
    let mut service = make_service(fixture.scope.clone(), [Ok(page(vec![expected], None))]);
    let proposal = service.compile_proposal("idempotency-1").expect("proposal");
    assert_eq!(
        proposal.projection.state,
        AttestationEvidenceState::AttestationEvidence
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_adopt_outcome());
    let serialized = serde_json::to_string(&proposal).expect("proposal serialization");
    assert!(!serialized.contains("builder@example.invalid"));
    assert!(!serialized.contains("certificate-chain-metadata"));
    assert!(!serialized.contains("bundle/1"));

    let recording = service.record(&proposal).expect("recording");
    service
        .verify_recording(&recording)
        .expect("recording verifies");
    let verification = service
        .verify_proposal(&proposal)
        .expect("proposal verifies");
    assert!(verification.valid);
    let consumer =
        MissionGithubAttestationConsumer::new(fixture.scope.clone(), service.registration())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert_eq!(
        result.evidence_state,
        AttestationEvidenceState::AttestationEvidence
    );
    assert_eq!(result.project_id.as_str(), "project-1");
    assert_eq!(result.mission_id.as_str(), "mission-1");
    assert_eq!(result.work_product_id.as_str(), "work-product-1");
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.outcome_adopted);
    assert!(!result.can_adopt_outcome());
    let serialized_result = serde_json::to_string(&result).expect("Mission result serialization");
    assert!(!serialized_result.contains("builder@example.invalid"));
    assert!(!serialized_result.contains("certificate-chain-metadata"));
}

#[test]
fn subject_predicate_and_metadata_fences_fail_closed_without_raw_metadata() {
    let fixture = fixture();
    let mut wrong_subject = record(&fixture);
    wrong_subject.subject_digest = SubjectDigest::new(
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .expect("wrong subject");
    wrong_subject.metadata_digest = wrong_subject.computed_digest();
    let mut service = make_service(fixture.scope.clone(), [Ok(page(vec![wrong_subject], None))]);
    let projection = service.read_evidence().expect("projection");
    assert_eq!(projection.state, AttestationEvidenceState::SubjectMismatch);
    assert_eq!(
        projection.provider_errors[0].kind,
        ProviderErrorKind::SubjectMismatch
    );

    let wrong_metadata = AttestationMetadataDigestFence::new(
        b"different-signer",
        b"certificate-chain-metadata",
        b"signature-metadata",
        b"2026-08-15T00:00:00Z",
        b"predicate-metadata",
        b"verification-metadata",
    )
    .expect("wrong metadata");
    let fenced_scope = GithubArtifactAttestationScope::new(
        fixture.scope.installation_id.clone(),
        fixture.scope.organization.clone(),
        fixture.scope.repository.clone(),
        fixture.scope.subject_digest.clone(),
        fixture.scope.predicate_type.clone(),
        fixture.scope.permissions.clone(),
        fixture.scope.mission.clone(),
    )
    .expect("scope")
    .with_metadata_fence(fixture.metadata.clone())
    .expect("scope fence");
    let wrong_record = GithubAttestationRecord::new(
        b"opaque-ref-2",
        41,
        GithubRepositoryVisibility::Private,
        RepositoryAccess::Accessible,
        fenced_scope.subject_digest.clone(),
        fenced_scope.predicate_type.clone(),
        wrong_metadata,
    )
    .expect("wrong record");
    let mut wrong_service =
        make_service(fenced_scope.clone(), [Ok(page(vec![wrong_record], None))]);
    let projection = wrong_service.read_evidence().expect("projection");
    assert_eq!(projection.state, AttestationEvidenceState::SignerMismatch);
    assert_eq!(
        projection.provider_errors[0].kind,
        ProviderErrorKind::SignerMismatch
    );
    assert_eq!(fenced_scope.subject_digest.as_str().len(), 71);
}

#[test]
fn repository_identity_fence_rejects_cross_repository_evidence() {
    let fixture = fixture();
    let mut wrong_repository = record(&fixture);
    wrong_repository.repository_id = 42;
    wrong_repository.metadata_digest = wrong_repository.computed_digest();
    let mut service = make_service(fixture.scope, [Ok(page(vec![wrong_repository], None))]);
    let projection = service.read_evidence().expect("projection");
    assert_eq!(
        projection.state,
        AttestationEvidenceState::RepositoryMismatch
    );
    assert_eq!(
        projection.provider_errors[0].kind,
        ProviderErrorKind::RepositoryMismatch
    );
}

#[test]
fn pagination_is_opaque_bounded_and_repeated_cursors_are_rejected() {
    let fixture = fixture();
    let first = GithubAttestationPage::new(
        1,
        vec![record(&fixture)],
        Some(
            hartevo_github_artifact_attestation_result_plugin::OpaquePageToken::new(b"cursor-1")
                .expect("cursor"),
        ),
        GithubRepositoryVisibility::Private,
        RepositoryAccess::Accessible,
    )
    .expect("first page");
    let mut second = GithubAttestationPage::new(
        2,
        vec![],
        None,
        GithubRepositoryVisibility::Private,
        RepositoryAccess::Accessible,
    )
    .expect("second page");
    let mut service = make_service(fixture.scope.clone(), [Ok(first), Ok(second.clone())]);
    let projection = service.read_evidence().expect("projection");
    assert_eq!(
        projection.state,
        AttestationEvidenceState::AttestationEvidence
    );
    assert_eq!(projection.response_digests.len(), 2);

    second.next_page_token = Some(
        hartevo_github_artifact_attestation_result_plugin::OpaquePageToken::new(b"cursor-1")
            .expect("cursor"),
    );
    second.seal();
    let first = GithubAttestationPage::new(
        1,
        vec![],
        Some(
            hartevo_github_artifact_attestation_result_plugin::OpaquePageToken::new(b"cursor-1")
                .expect("cursor"),
        ),
        GithubRepositoryVisibility::Private,
        RepositoryAccess::Accessible,
    )
    .expect("first page");
    let mut service = make_service(fixture.scope, [Ok(first), Ok(second)]);
    assert!(matches!(
        service.read_evidence(),
        Err(ServiceError::PaginationMismatch)
    ));
}

#[test]
fn access_visibility_truncation_and_all_typed_http_failures_are_non_native() {
    let fixture = fixture();
    let mut inaccessible = GithubAttestationPage::new(
        1,
        vec![],
        None,
        GithubRepositoryVisibility::Private,
        RepositoryAccess::Filtered,
    )
    .expect("inaccessible page");
    let mut service = make_service(fixture.scope.clone(), [Ok(inaccessible.clone())]);
    let projection = service.read_evidence().expect("access projection");
    assert_eq!(projection.state, AttestationEvidenceState::AccessLoss);
    assert!(!projection.connected);
    assert!(!projection.native);
    inaccessible.repository_access = RepositoryAccess::Accessible;
    inaccessible.mark_truncated();
    let mut service = make_service(fixture.scope.clone(), [Ok(inaccessible)]);
    let projection = service.read_evidence().expect("truncated projection");
    assert_eq!(projection.state, AttestationEvidenceState::Partial);
    assert!(projection.partial);

    for (status, expected) in [
        (401, AttestationEvidenceState::AccessLoss),
        (403, AttestationEvidenceState::AccessLoss),
        (404, AttestationEvidenceState::RepositoryNotFound),
        (409, AttestationEvidenceState::ProviderRejected),
        (422, AttestationEvidenceState::ProviderRejected),
        (429, AttestationEvidenceState::RateLimited),
        (500, AttestationEvidenceState::ProviderUnknown),
        (503, AttestationEvidenceState::ProviderUnknown),
    ] {
        let mut service = make_service(
            fixture.scope.clone(),
            [Err(TransportError::http(status, b"bounded diagnostic"))],
        );
        let projection = service.read_evidence().expect("typed HTTP projection");
        assert_eq!(projection.state, expected);
        assert_eq!(projection.provider_errors[0].status_code, Some(status));
        assert!(!projection.connected);
        assert!(!projection.native);
    }
    let mut service = make_service(fixture.scope, [Err(TransportError::timeout())]);
    let projection = service.read_evidence().expect("timeout projection");
    assert_eq!(projection.state, AttestationEvidenceState::ProviderUnknown);
    assert!(projection.provider_errors[0].retryable);
}

#[test]
fn provider_tamper_error_is_rejected_instead_of_projected_as_evidence() {
    let fixture = fixture();
    let mut service = make_service(fixture.scope, [Err(TransportError::tampered())]);
    assert!(matches!(
        service.read_evidence(),
        Err(ServiceError::TamperedEvidence)
    ));
}

#[test]
fn tamper_and_revocation_fences_are_fail_closed() {
    let fixture = fixture();
    let mut tampered = record(&fixture);
    tampered.signer_identity_digest =
        hartevo_github_artifact_attestation_result_plugin::metadata_digest(b"tampered-signer");
    let tampered_page = page(vec![tampered], None);
    let mut service = make_service(fixture.scope.clone(), [Ok(tampered_page)]);
    assert!(matches!(
        service.read_evidence(),
        Err(ServiceError::TamperedEvidence)
    ));

    let expected = record(&fixture);
    let mut service = make_service(fixture.scope.clone(), [Ok(page(vec![expected], None))]);
    let proposal = service.compile_proposal("revocation").expect("proposal");
    let revision_before = service.registration().registration_revision;
    service.unmount_registration().expect("unmount");
    assert!(service.registration().registration_revision > revision_before);
    assert!(matches!(
        service.record(&proposal),
        Err(ServiceError::RegistrationInactive)
    ));
    service.remount_registration().expect("remount");
    service.revoke_registration().expect("revoke");
    assert!(matches!(
        service.read_evidence(),
        Err(ServiceError::SecretRevoked)
    ));
    assert!(MissionGithubAttestationConsumer::new(fixture.scope, service.registration(),).is_err());
}

#[test]
fn fixture_recording_loopback_and_blocked_env_provenance_never_claim_native() {
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
    let fixture = fixture();
    let mut service = make_service(
        fixture.scope,
        [Err(TransportError::blocked_env(
            b"native environment intentionally unavailable",
        ))],
    );
    let projection = service.read_evidence().expect("blocked projection");
    assert_eq!(projection.provenance, TransportProvenance::Recording);
    assert!(projection.provider_errors[0].blocked_env);
    assert!(!projection.connected);
    assert!(!projection.native);
}

#[test]
fn permission_snapshot_digest_is_order_independent() {
    let left = PermissionSnapshot::new([
        GithubAttestationPermission::AttestationsRead,
        GithubAttestationPermission::MetadataRead,
    ])
    .expect("permissions");
    let right = PermissionSnapshot::new([
        GithubAttestationPermission::MetadataRead,
        GithubAttestationPermission::AttestationsRead,
    ])
    .expect("permissions");
    assert_eq!(left, right);
    let mut set = BTreeSet::new();
    set.insert(GithubAttestationPermission::AttestationsRead);
    set.insert(GithubAttestationPermission::MetadataRead);
    assert_eq!(set.len(), 2);
}

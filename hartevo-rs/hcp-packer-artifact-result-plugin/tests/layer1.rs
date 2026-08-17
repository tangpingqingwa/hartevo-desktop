use chrono::{TimeZone, Utc};
use hartevo_hcp_packer_artifact_result_plugin as plugin;
use plugin::{
    BlockedEnvTransport, CloudProvider, CloudRegion, FixtureTransport,
    HcpPackerArtifactResultError, HcpPackerArtifactResultService, HcpPackerArtifactScope,
    HcpPackerEvidenceState, HcpPackerProvider, LabelKey, MissionBinding, PermissionFence,
    ProjectBinding, ProposalDisposition, Revision, SecretReference, TransportProvenance,
    VersionFingerprint, WorkProductBinding,
};

fn observed_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0)
        .single()
        .expect("fixture timestamp is valid")
}

fn scope() -> HcpPackerArtifactScope {
    let revision = Revision::new(1).expect("revision is positive");
    HcpPackerArtifactScope::new(
        plugin::OrganizationId::new("org-example").unwrap(),
        plugin::ProjectId::new("hcp-project-example").unwrap(),
        plugin::BucketName::new("production-images").unwrap(),
        VersionFingerprint::new("version-fingerprint-example").unwrap(),
        plugin::ChannelName::new("stable").unwrap(),
        CloudProvider::new("aws").unwrap(),
        CloudRegion::new("us-east-1").unwrap(),
        MissionBinding::new("mission-hcp-packer", revision).unwrap(),
        ProjectBinding::new("project-hcp-packer", revision).unwrap(),
        WorkProductBinding::new("work-product-hcp-packer", revision).unwrap(),
        [
            LabelKey::new("environment").unwrap(),
            LabelKey::new("pipeline").unwrap(),
            LabelKey::new("artifact-label").unwrap(),
        ],
    )
    .unwrap()
}

fn fixture_service() -> HcpPackerArtifactResultService<FixtureTransport> {
    let scope = scope();
    let provider = HcpPackerProvider::new(FixtureTransport::for_scope(&scope, observed_at()))
        .expect("fixture provider identity is valid");
    let secret = SecretReference::hcp("opaque-hcp-packer-secret", &scope, 1)
        .expect("opaque secret reference is valid");
    HcpPackerArtifactResultService::new(scope, secret, PermissionFence::for_layer_one(1), provider)
        .expect("fixture service registration is valid")
}

#[test]
fn contract_and_secret_boundary_are_pinned() {
    plugin::validate_contract().expect("contract metadata validates");
    assert_eq!(plugin::contract_digest(), plugin::CONTRACT_DIGEST);

    let service = fixture_service();
    let serialized = serde_json::to_string(service.secret_reference()).unwrap();
    assert_eq!(serialized, r#"{"opaque":true}"#);
    assert!(!serialized.contains("opaque-hcp-packer-secret"));
    assert!(service.registration().validate().is_ok());
    assert_eq!(
        service.registration().secret_reference_digest(),
        service.secret_reference().reference_digest()
    );
}

#[test]
fn fixture_produces_bounded_redacted_proposal() {
    let mut service = fixture_service();
    let request = service.default_request().unwrap();
    let proposal = service.propose(request).unwrap();

    assert_eq!(proposal.state, HcpPackerEvidenceState::Ready);
    assert_eq!(proposal.provenance, TransportProvenance::Fixture);
    assert!(proposal.review_eligible());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_be_adopted());
    proposal.validate_integrity(service.scope()).unwrap();
    assert!(service.verify(&proposal).valid);

    let evidence = proposal.evidence.as_ref().unwrap();
    assert_eq!(evidence.builds.len(), 1);
    assert_eq!(evidence.artifacts.len(), 1);
    assert_eq!(
        evidence.bucket.allowlisted_labels.get("environment"),
        Some(&"fixture".to_owned())
    );
    assert_eq!(
        evidence.builds[0].allowlisted_labels.get("pipeline"),
        Some(&"fixture".to_owned())
    );
    assert!(evidence.version.allowlisted_labels.is_empty());
    assert!(evidence.artifacts[0].artifact_location_digest.is_some());

    let serialized = serde_json::to_string(&proposal).unwrap();
    assert!(serialized.contains("environment"));
    assert!(!serialized.contains("owner"));
    assert!(!serialized.contains("private.example.invalid"));
    assert!(!serialized.contains("ami-private-location-should-not-leak"));
    assert!(!serialized.contains("fixture build log must never cross"));
}

#[test]
fn mission_consumer_records_only_local_non_authoritative_replays() {
    let mut service = fixture_service();
    let request = service.default_request().unwrap();
    let proposal = service.propose(request).unwrap();
    let mut consumer = service.consumer().unwrap();

    let first = consumer.record(&proposal, "mission-record-1").unwrap();
    let replay = consumer.record(&proposal, "mission-record-1").unwrap();

    assert_eq!(consumer.record_count(), 1);
    assert!(!first.replayed);
    assert!(replay.replayed);
    first.validate_integrity().unwrap();
    replay.validate_integrity().unwrap();
    assert_eq!(replay.disposition, ProposalDisposition::Ready);
    assert!(!replay.connected);
    assert!(!replay.native);
    assert!(!replay.first_party);
    assert!(!replay.provider_receipt);
    assert!(!replay.durable_provider_receipt);
    assert!(!replay.truth_authority);
    assert!(!replay.verification_authority);
    assert!(!replay.outcome_adopted);
    assert!(!replay.work_product_adopted);
}

#[test]
fn all_non_native_provenances_are_explicitly_disconnected() {
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Fake,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }

    let mut service = HcpPackerArtifactResultService::new(
        scope(),
        SecretReference::hcp("opaque-blocked-secret", &scope(), 1).unwrap(),
        PermissionFence::for_layer_one(1),
        HcpPackerProvider::<BlockedEnvTransport>::default(),
    )
    .unwrap();
    let request = service.default_request().unwrap();
    let proposal = service.propose(request).unwrap();
    assert_eq!(proposal.state, HcpPackerEvidenceState::ProviderUnknown);
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        proposal.failure.as_ref().unwrap().category,
        "provider_unknown"
    );
    assert!(proposal.evidence.is_none());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
}

#[test]
fn registration_revocation_reversal_secret_and_provider_drift_fail_closed() {
    let mut service = fixture_service();
    let request = service.default_request().unwrap();
    let revoked = service.revoke_registration().unwrap();
    assert_eq!(revoked.new_status, plugin::RegistrationStatus::Revoked);
    assert!(matches!(
        service.propose(request.clone()),
        Err(HcpPackerArtifactResultError::RegistrationInactive)
    ));
    service.restore_registration().unwrap();
    service.reverse_registration().unwrap();
    assert!(matches!(
        service.propose(request),
        Err(HcpPackerArtifactResultError::RegistrationInactive)
    ));

    let mut secret_revoked = fixture_service();
    secret_revoked.revoke_secret().unwrap();
    let request = secret_revoked.default_request().unwrap();
    assert!(matches!(
        secret_revoked.propose(request),
        Err(HcpPackerArtifactResultError::SecretRevoked)
    ));

    let mut provider_drift = fixture_service();
    provider_drift.provider_mut().definition_mut().release = "drifted-release".to_owned();
    let request = provider_drift.default_request().unwrap();
    assert!(matches!(
        provider_drift.propose(request),
        Err(HcpPackerArtifactResultError::ProviderDrift)
    ));
}

#[test]
fn proposal_and_evidence_tampering_are_rejected() {
    let mut service = fixture_service();
    let request = service.default_request().unwrap();
    let proposal = service.propose(request).unwrap();

    let mut proposal_tampered = proposal.clone();
    proposal_tampered.connected = true;
    assert_eq!(
        service.verify(&proposal_tampered).failure,
        Some(plugin::VerificationFailure::Tampered)
    );

    let mut evidence_tampered = proposal;
    evidence_tampered.evidence.as_mut().unwrap().builds[0].component_type_digest =
        plugin::Digest::from_text("tampered-component");
    assert_eq!(
        service.verify(&evidence_tampered).failure,
        Some(plugin::VerificationFailure::Tampered)
    );
}

#[test]
fn request_limits_reject_unbounded_reads() {
    let scope = scope();
    assert!(matches!(
        plugin::HcpPackerReadRequest::with_limits(
            &scope,
            1,
            plugin::MAX_PAGES,
            1,
            1,
            plugin::MAX_RESPONSE_BYTES + 1,
            observed_at(),
        ),
        Err(HcpPackerArtifactResultError::InvalidRequest)
    ));
}

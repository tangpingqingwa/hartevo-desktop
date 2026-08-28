use hartevo_cloudinary_asset_result_plugin::*;

fn secret() -> SecretReference {
    SecretReference::api_key("api-key-material-must-not-escape", 7).expect("secret")
}

fn scope() -> CloudinaryScope {
    CloudinaryScope::fixture(secret()).expect("scope")
}

#[test]
fn contract_and_authority_are_pinned() {
    let contract = CloudinaryAssetResultContract::baseline().expect("contract");
    assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::first_party());
    assert!(!Layer1Authority::signed_url_execution());
    assert!(!Layer1Authority::delivery_guarantee());
    assert!(!Layer1Authority::raw_media_download());
    assert!(!Layer1Authority::adopts_outcome());
    assert!(!Layer1Authority::adopts_work_product());
}

#[test]
fn scope_revisions_and_secret_are_opaque_and_bound() {
    let scoped = scope();
    assert_ne!(scoped.digest(), scoped.asset_digest());
    assert_eq!(scoped.secret().scope_digest(), &scoped.digest());
    assert!(!format!("{:?}", scoped.secret()).contains("api-key-material"));
    assert!(!format!("{scoped:?}").contains("media/asset-1"));

    let serialized = serde_json::to_string(&PermissionSnapshot::for_layer_one(1)).expect("json");
    assert!(!serialized.contains("api-key-material"));
    assert!(SecretReference::api_key("", 1).is_err());
    assert!(AssetScope::new("asset-1", 0).is_err());
}

#[test]
fn fixture_produces_bounded_present_evidence_without_native_claims() {
    let scoped = scope();
    let provider = CloudinaryProvider::new(FixtureTransport::for_scope(&scoped)).expect("provider");
    let mut service = CloudinaryAssetResultService::new(scoped.clone(), provider).expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");

    assert_eq!(proposal.state, CloudinaryEvidenceState::Present);
    assert!(proposal.asset.is_some());
    assert!(proposal.usage.is_some());
    assert!(proposal.transformation.is_some());
    assert!(proposal.delivery.is_some());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.delivery_guarantee);
    assert!(!proposal.signed_url_execution);
    assert!(!proposal.media_bytes_retained);
    assert!(!proposal.raw_url_retained);
    assert!(!proposal.pii_retained);
    assert!(!proposal.can_be_adopted());
    proposal.validate_integrity().expect("integrity");

    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);
    let serialized = serde_json::to_string(&proposal).expect("proposal json");
    for forbidden in [
        "api-key-material",
        "fixture-delivery-reference",
        "https://",
        "raw_media",
        "signed_url_execution\":true",
    ] {
        assert!(!serialized.contains(forbidden), "found {forbidden}");
    }
}

#[test]
fn registration_is_digest_bound_reversible_and_revocable() {
    let scoped = scope();
    let provider = CloudinaryProvider::new(FixtureTransport::for_scope(&scoped)).expect("provider");
    let mut service = CloudinaryAssetResultService::new(scoped, provider).expect("service");
    let active_digest = service.registration().registration_digest().clone();
    let transition = service.revoke().expect("revoke");
    assert_eq!(transition.new_status, RegistrationStatus::Revoked);
    assert_ne!(active_digest, *service.registration().registration_digest());
    assert!(service.default_request().is_ok());
    let err = service
        .propose(service.default_request().expect("request"))
        .expect_err("revoked registration must fail closed");
    assert_eq!(err, CloudinaryAssetResultError::RegistrationInactive);
    service.restore_registration().expect("restore");
    service.registration().validate().expect("restored binding");
    service.reverse().expect("reverse");
    assert!(service.restore_registration().is_err());
}

#[test]
fn consumer_records_once_and_rejects_tamper_or_replay() {
    let scoped = scope();
    let provider = CloudinaryProvider::new(FixtureTransport::for_scope(&scoped)).expect("provider");
    let mut service = CloudinaryAssetResultService::new(scoped.clone(), provider).expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    let recorded = consumer.consume(&proposal).expect("record");
    assert_eq!(recorded.disposition, ProposalDisposition::RecordedForReview);
    assert_eq!(consumer.record_count(), 1);
    assert_eq!(
        consumer.consume(&proposal),
        Err(CloudinaryAssetResultError::DuplicateEvidence)
    );

    let mut tampered = proposal.clone();
    tampered.delivery_guarantee = true;
    assert_eq!(
        tampered.validate_integrity(),
        Err(CloudinaryAssetResultError::TamperedEvidence)
    );

    let other_scope = CloudinaryScope::from_parts(
        CloudScope::new("other-cloud", 1).expect("cloud"),
        FolderScope::new("media", 1).expect("folder"),
        AssetScope::new("asset-2", 1).expect("asset"),
        PublicIdScope::new("media/asset-2", 1).expect("public id"),
        VersionScope::new("v1", 1).expect("version"),
        TransformationScope::new("f_auto,q_auto", 1).expect("transformation"),
        DeliveryScope::new(DeliveryType::Upload, 1).expect("delivery"),
        ProjectScope::new("project-1", 1).expect("project"),
        MissionScope::new("mission-1", 1).expect("mission"),
        WorkProductScope::new("work-product-1", 1).expect("work product"),
        secret(),
    )
    .expect("other scope");
    let other_provider =
        CloudinaryProvider::new(FixtureTransport::for_scope(&other_scope)).expect("provider");
    let mut other_service =
        CloudinaryAssetResultService::new(other_scope, other_provider).expect("service");
    let mut other_proposal = other_service
        .propose(other_service.default_request().expect("request"))
        .expect("proposal");
    other_proposal.registration_digest = proposal.registration_digest.clone();
    assert_eq!(
        consumer.consume(&other_proposal),
        Err(CloudinaryAssetResultError::ReplayConflict)
    );
}

#[test]
fn rate_limit_is_bounded_and_backoff_is_deterministic() {
    let scoped = scope();
    let provider = CloudinaryProvider::new(RecordingTransport::default()).expect("provider");
    let mut service = CloudinaryAssetResultService::new(scoped.clone(), provider).expect("service");
    let request = service.default_request().expect("request");
    let response = CloudinaryProviderResponse::new(
        &request,
        Some(ResourceMetadataPayload::fixture(&scoped)),
        Some(UsageMetadataPayload::fixture()),
        Some(TransformationMetadataPayload::fixture(&scoped)),
        Some(DeliveryMetadataPayload::fixture(&scoped).expect("delivery")),
        2_048,
        TransportProvenance::Recording,
    )
    .expect("response");
    service.provider_mut().transport_mut().push_response(Err(
        CloudinaryTransportError::RateLimited {
            retry_after_seconds: Some(2),
        },
    ));
    service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(response));
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, CloudinaryEvidenceState::Present);
    assert_eq!(proposal.attempts, 2);
    assert_eq!(
        CloudinaryRetryPolicy::default().backoff_seconds(1, Some(2)),
        2
    );
    assert!(service.provider().transport().requests().len() >= 2);
}

#[test]
fn blocked_env_never_becomes_connected_or_native() {
    let scoped = scope();
    let provider = CloudinaryProvider::new(BlockedEnvTransport).expect("provider");
    let mut service = CloudinaryAssetResultService::new(scoped, provider).expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("typed blocked result");
    assert_eq!(proposal.state, CloudinaryEvidenceState::ProviderUnknown);
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn loopback_is_explicitly_non_native() {
    let scoped = scope();
    let provider =
        CloudinaryProvider::new(LoopbackTransport::for_scope(&scoped)).expect("provider");
    let mut service = CloudinaryAssetResultService::new(scoped, provider).expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    assert_eq!(proposal.provenance, TransportProvenance::Loopback);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
}

#[test]
fn partial_and_access_loss_fail_closed_with_typed_states() {
    let cases = [
        (
            CloudinaryTransportError::Partial,
            CloudinaryEvidenceState::Partial,
        ),
        (
            CloudinaryTransportError::AccessLost,
            CloudinaryEvidenceState::AccessLoss,
        ),
        (
            CloudinaryTransportError::Forbidden,
            CloudinaryEvidenceState::Denied,
        ),
        (
            CloudinaryTransportError::Deleted,
            CloudinaryEvidenceState::Deleted,
        ),
        (
            CloudinaryTransportError::BadRequest,
            CloudinaryEvidenceState::Invalid,
        ),
        (
            CloudinaryTransportError::Tampered,
            CloudinaryEvidenceState::Tampered,
        ),
    ];
    for (error, expected_state) in cases {
        let scoped = scope();
        let provider = CloudinaryProvider::new(RecordingTransport::default()).expect("provider");
        let mut service = CloudinaryAssetResultService::new(scoped, provider).expect("service");
        service
            .provider_mut()
            .transport_mut()
            .push_response(Err(error));
        let proposal = service
            .propose(service.default_request().expect("request"))
            .expect("typed failure proposal");
        assert_eq!(proposal.state, expected_state);
        assert!(!service.verify(&proposal).review_eligible);
        proposal.validate_integrity().expect("failure integrity");
    }
}

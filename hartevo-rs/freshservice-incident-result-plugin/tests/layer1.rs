use std::fmt::Debug;

use chrono::{Duration, Utc};
use hartevo_freshservice_incident_result_plugin::{
    AssetLifecycle, AssetMetadata, AssetPage, AssetRequest, BlockedEnvTransport, ChangeMetadata,
    ChangePage, ChangeRequest, ChangeRisk, ChangeStatus, ChangeWindowMetadata, ConsentScope,
    Digest, FakeTransport, FixtureTransport, FreshserviceAccountId, FreshserviceAgentId,
    FreshserviceAssetId, FreshserviceChangeId, FreshserviceGroupId, FreshserviceIncidentId,
    FreshserviceIncidentResultError, FreshserviceIncidentResultScope,
    FreshserviceIncidentResultService, FreshserviceProvider, FreshserviceResultState,
    FreshserviceTransport, FreshserviceTransportError, IncidentMetadata, IncidentPage,
    IncidentPriority, IncidentRequest, IncidentStatus, LoopbackTransport,
    MissionFreshserviceIncidentConsumer, MissionIdentity, PageCursor, ProjectIdentity,
    RecordingTransport, SecretReference, TransportProvenance, WorkProductIdentity,
};

const RAW_SECRET: &str = "fixture-secret-handle-do-not-print";
const RAW_CURSOR: &str = "provider-private-next-page-token-do-not-print";
const RAW_NOTE: &str = "private-requester-note-do-not-export";

fn now() -> chrono::DateTime<Utc> {
    Utc::now()
}

fn scope() -> FreshserviceIncidentResultScope {
    FreshserviceIncidentResultScope::new(
        FreshserviceAccountId::new("account-fixture").expect("account"),
        FreshserviceAgentId::new("agent-17").expect("agent"),
        FreshserviceGroupId::new("group-support").expect("group"),
        FreshserviceIncidentId::new("incident-723").expect("incident"),
        FreshserviceChangeId::new("change-723").expect("change"),
        FreshserviceAssetId::new("asset-723").expect("asset"),
        ProjectIdentity::new("project-support", 7).expect("project"),
        MissionIdentity::new("mission-support", 11).expect("mission"),
        WorkProductIdentity::new("work-product-support", 13).expect("work product"),
    )
    .expect("scope")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-723", 3, now() + Duration::days(30)).expect("consent")
}

fn secret() -> SecretReference {
    SecretReference::freshservice(RAW_SECRET, 1).expect("secret")
}

fn fixture_service() -> FreshserviceIncidentResultService<FixtureTransport> {
    let scope = scope();
    let provider = FreshserviceProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    FreshserviceIncidentResultService::new(scope, secret(), consent(), provider, now())
        .expect("fixture service")
}

fn assert_non_native<T: FreshserviceTransport + Debug>(
    transport: T,
    expected: TransportProvenance,
) {
    assert_eq!(transport.provenance(), expected);
    assert!(!transport.provenance().connected());
    assert!(!transport.provenance().native());
    assert!(!transport.provenance().first_party());
    let provider = FreshserviceProvider::new(transport).expect("provider");
    assert!(!provider.definition().connected);
    assert!(!provider.definition().native);
    assert!(!provider.definition().first_party);
    assert!(!provider.definition().provider_receipt);
}

fn push_complete_pages(
    transport: &mut RecordingTransport,
    scope: &FreshserviceIncidentResultScope,
    observed_at: chrono::DateTime<Utc>,
    incident_status: IncidentStatus,
    include_asset: bool,
) {
    let incident_request = IncidentRequest::for_scope(scope, 10, None).expect("incident request");
    let incident = IncidentMetadata::new(
        scope,
        incident_status,
        IncidentPriority::High,
        observed_at,
        3,
    )
    .expect("incident metadata");
    transport.push_incident_response(Ok(IncidentPage::new(
        &incident_request,
        vec![incident],
        None,
        true,
        512,
        TransportProvenance::Recording,
    )
    .expect("incident page")));

    let change_request = ChangeRequest::for_scope(scope, 10, None).expect("change request");
    let change = ChangeMetadata::new(
        scope,
        ChangeStatus::Planned,
        ChangeRisk::Medium,
        ChangeWindowMetadata::new(None, None, None, None).expect("change window"),
        observed_at,
        2,
    )
    .expect("change metadata");
    transport.push_change_response(Ok(ChangePage::new(
        &change_request,
        vec![change],
        None,
        true,
        512,
        TransportProvenance::Recording,
    )
    .expect("change page")));

    if include_asset {
        let asset_request = AssetRequest::for_scope(scope, 10, None).expect("asset request");
        let asset = AssetMetadata::new(
            scope,
            AssetLifecycle::Active,
            Some("server"),
            observed_at,
            5,
        )
        .expect("asset metadata");
        transport.push_asset_response(Ok(AssetPage::new(
            &asset_request,
            vec![asset],
            None,
            true,
            512,
            TransportProvenance::Recording,
        )
        .expect("asset page")));
    }
}

#[test]
fn fixture_proposal_is_bounded_redacted_and_review_only() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");

    assert_eq!(proposal.state, FreshserviceResultState::Complete);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.ticket_mutation);
    assert!(!proposal.raw_notes);
    assert_eq!(proposal.evidence.incident.len(), 1);
    assert_eq!(proposal.evidence.change.len(), 1);
    assert_eq!(proposal.evidence.asset.len(), 1);
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for raw in [
        RAW_SECRET,
        RAW_NOTE,
        "incident-723",
        "change-723",
        "asset-723",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw value leaked in Debug: {raw}");
    }
    assert!(serialized.contains("\"project\""));
    assert!(serialized.contains("\"mission\""));
    assert!(serialized.contains("\"workProduct\""));
}

#[test]
fn opaque_secret_and_cursor_never_serialize_raw_material() {
    let secret = secret();
    assert!(serde_json::to_string(&secret).is_err());
    assert!(!format!("{secret:?}").contains(RAW_SECRET));

    let scope = scope();
    let request = IncidentRequest::for_scope(&scope, 10, None).expect("request");
    let cursor = PageCursor::new(
        RAW_CURSOR,
        &request.scope_digest,
        &request.record_digest,
        &request.filter_digest,
        1,
    )
    .expect("cursor");
    let next = IncidentRequest::for_scope(&scope, 10, Some(cursor.clone())).expect("next request");
    assert!(
        !serde_json::to_string(&cursor)
            .expect("cursor JSON")
            .contains(RAW_CURSOR)
    );
    assert!(!format!("{cursor:?}").contains(RAW_CURSOR));
    assert!(!next.path_and_query().contains(RAW_CURSOR));

    let wrong_filter = Digest::from_text("different-filter");
    let wrong_cursor = PageCursor::new(
        RAW_CURSOR,
        &request.scope_digest,
        &request.record_digest,
        &wrong_filter,
        1,
    )
    .expect("wrong cursor object");
    assert!(matches!(
        IncidentRequest::for_scope(&scope, 10, Some(wrong_cursor)),
        Err(FreshserviceIncidentResultError::PaginationDrift)
    ));
}

#[test]
fn all_layer_one_transports_are_honest_and_blocked_env_is_typed() {
    let scope = scope();
    let observed_at = now();
    assert_non_native(
        FixtureTransport::for_scope(&scope, observed_at),
        TransportProvenance::Fixture,
    );
    assert_non_native(
        FakeTransport::for_scope(&scope, observed_at),
        TransportProvenance::Fake,
    );
    assert_non_native(
        LoopbackTransport::for_scope(&scope, observed_at),
        TransportProvenance::Loopback,
    );
    assert_non_native(
        RecordingTransport::default(),
        TransportProvenance::Recording,
    );
    assert_non_native(BlockedEnvTransport, TransportProvenance::BlockedEnv);

    let provider = FreshserviceProvider::new(BlockedEnvTransport).expect("blocked provider");
    let mut service =
        FreshserviceIncidentResultService::new(scope, secret(), consent(), provider, now())
            .expect("blocked service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, FreshserviceResultState::ProviderUnknown);
    assert!(proposal.failures.iter().all(|failure| !matches!(
        failure,
        hartevo_freshservice_incident_result_plugin::ObservationFailure::Denied
    )));
    assert!(!proposal.connected);
    assert!(!proposal.native);
}

#[test]
fn registration_revoke_restore_and_revision_fences_are_reversible() {
    let mut service = fixture_service();
    let original_registration_digest = service.registration().registration_digest().clone();
    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(
        revoked.before_status,
        hartevo_freshservice_incident_result_plugin::RegistrationStatus::Active
    );
    assert_eq!(
        revoked.after_status,
        hartevo_freshservice_incident_result_plugin::RegistrationStatus::Revoked
    );
    assert_ne!(revoked.before_digest, revoked.after_digest);
    let revoked_proposal = service
        .propose(service.default_request().expect("request"))
        .expect("revoked proposal");
    assert_eq!(
        revoked_proposal.state,
        FreshserviceResultState::RegistrationRevoked
    );
    assert!(!service.verify(&revoked_proposal).valid);

    let restored = service.restore_registration().expect("restore");
    assert_eq!(
        restored.after_status,
        hartevo_freshservice_incident_result_plugin::RegistrationStatus::Active
    );
    assert_ne!(
        original_registration_digest,
        service.registration().registration_digest().clone()
    );
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("restored proposal");
    assert_eq!(proposal.state, FreshserviceResultState::Complete);
    assert!(service.verify(&proposal).valid);

    let mut consumer = service.consumer().expect("consumer");
    let drifted_scope = FreshserviceIncidentResultScope::new(
        FreshserviceAccountId::new("account-fixture").expect("account"),
        FreshserviceAgentId::new("agent-17").expect("agent"),
        FreshserviceGroupId::new("group-support").expect("group"),
        FreshserviceIncidentId::new("incident-723").expect("incident"),
        FreshserviceChangeId::new("change-723").expect("change"),
        FreshserviceAssetId::new("asset-723").expect("asset"),
        ProjectIdentity::new("project-support", 7).expect("project"),
        MissionIdentity::new("mission-support", 12).expect("drifted mission"),
        WorkProductIdentity::new("work-product-support", 13).expect("work product"),
    )
    .expect("drifted scope");
    assert!(matches!(
        MissionFreshserviceIncidentConsumer::new(drifted_scope, service.registration().clone()),
        Err(FreshserviceIncidentResultError::ScopeMismatch)
    ));
    assert!(consumer.record(&proposal, "recording-key").is_ok());
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(replay.validate_integrity().is_ok());
}

#[test]
fn provider_errors_are_redacted_and_verification_rejects_tampering() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.connected = true;
    assert!(matches!(
        service.consumer().expect("consumer").consume(&tampered),
        Err(FreshserviceIncidentResultError::TamperedProposal)
    ));

    let errors = [
        FreshserviceTransportError::Denied,
        FreshserviceTransportError::AccessLoss,
        FreshserviceTransportError::RateLimited {
            retry_after_seconds: 30,
        },
        FreshserviceTransportError::ProviderUnknown,
        FreshserviceTransportError::BlockedEnv,
    ];
    for error in errors {
        let serialized = serde_json::to_string(&error).expect("typed provider error JSON");
        assert!(!serialized.contains(RAW_NOTE));
        assert!(error.is_non_adoptable());
    }
}

#[test]
fn rate_limit_partial_and_idempotency_conflicts_are_fenced() {
    let scope = scope();
    let mut rate_limited_transport = RecordingTransport::default();
    rate_limited_transport.push_incident_response(Err(FreshserviceIncidentResultError::Provider(
        FreshserviceTransportError::RateLimited {
            retry_after_seconds: 37,
        },
    )));
    let rate_provider = FreshserviceProvider::new(rate_limited_transport).expect("rate provider");
    let mut rate_service = FreshserviceIncidentResultService::new(
        scope.clone(),
        secret(),
        consent(),
        rate_provider,
        now(),
    )
    .expect("rate service");
    let rate_proposal = rate_service
        .propose(rate_service.request(10, 1).expect("rate request"))
        .expect("rate proposal");
    assert_eq!(rate_proposal.state, FreshserviceResultState::RateLimited);
    assert!(rate_proposal.failures.iter().any(|failure| matches!(
        failure,
        hartevo_freshservice_incident_result_plugin::ObservationFailure::RateLimited {
            retry_after_seconds: 37
        }
    )));

    let observed_at = now();
    let mut partial_transport = RecordingTransport::default();
    push_complete_pages(
        &mut partial_transport,
        &scope,
        observed_at,
        IncidentStatus::Open,
        false,
    );
    let asset_request = AssetRequest::for_scope(&scope, 10, None).expect("partial asset request");
    let asset = AssetMetadata::new(
        &scope,
        AssetLifecycle::Active,
        Some("server"),
        observed_at,
        5,
    )
    .expect("partial asset metadata");
    let cursor = PageCursor::new(
        "partial-asset-page",
        &asset_request.scope_digest,
        &asset_request.record_digest,
        &asset_request.filter_digest,
        2,
    )
    .expect("partial cursor");
    partial_transport.push_asset_response(Ok(AssetPage::new(
        &asset_request,
        vec![asset],
        Some(cursor),
        false,
        512,
        TransportProvenance::Recording,
    )
    .expect("partial page")));
    let partial_provider = FreshserviceProvider::new(partial_transport).expect("partial provider");
    let mut partial_service = FreshserviceIncidentResultService::new(
        scope.clone(),
        secret(),
        consent(),
        partial_provider,
        now(),
    )
    .expect("partial service");
    let partial_proposal = partial_service
        .propose(partial_service.request(10, 1).expect("partial request"))
        .expect("partial proposal");
    assert_eq!(partial_proposal.state, FreshserviceResultState::Partial);

    let mut transport = RecordingTransport::default();
    push_complete_pages(
        &mut transport,
        &scope,
        observed_at,
        IncidentStatus::Open,
        true,
    );
    push_complete_pages(
        &mut transport,
        &scope,
        observed_at,
        IncidentStatus::Resolved,
        true,
    );
    let provider = FreshserviceProvider::new(transport).expect("recording provider");
    let mut service =
        FreshserviceIncidentResultService::new(scope, secret(), consent(), provider, now())
            .expect("recording service");
    let first = service
        .propose(service.request(10, 1).expect("first request"))
        .expect("first proposal");
    let second = service
        .propose(service.request(10, 1).expect("second request"))
        .expect("second proposal");
    assert_ne!(first.proposal_digest, second.proposal_digest);
    let mut consumer = service.consumer().expect("consumer");
    consumer
        .record(&first, "same-idempotency-key")
        .expect("first record");
    assert!(matches!(
        consumer.record(&second, "same-idempotency-key"),
        Err(FreshserviceIncidentResultError::RecordingConflict)
    ));
}

#[test]
fn request_paths_are_digest_only_and_scope_exact() {
    let scope = scope();
    let incident = IncidentRequest::for_scope(&scope, 10, None).expect("incident");
    let change = ChangeRequest::for_scope(&scope, 10, None).expect("change");
    let asset = AssetRequest::for_scope(&scope, 10, None).expect("asset");
    for path in [
        incident.path_and_query(),
        change.path_and_query(),
        asset.path_and_query(),
    ] {
        assert!(path.starts_with("/api/v2/"));
        assert!(!path.contains("incident-723"));
        assert!(!path.contains("change-723"));
        assert!(!path.contains("asset-723"));
    }
}

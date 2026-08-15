use std::collections::BTreeMap;

use hartevo_meltano_pipeline_result_plugin::{
    Digest, FixtureTransport, LoopbackTransport, MAX_RESPONSE_BYTES, MeltanoConfigMetadata,
    MeltanoCursor, MeltanoEvidenceState, MeltanoJobMetadata, MeltanoJobStatus, MeltanoJobType,
    MeltanoPipelineMetadata, MeltanoPipelineReadRequest, MeltanoPipelineResultResponse,
    MeltanoPipelineResultScope, MeltanoPipelineResultService, MeltanoPipelineStatus,
    MeltanoProvider, MeltanoReadOperation, MeltanoStateMetadata, MeltanoTransportError,
    MissionMeltanoPipelineConsumer, RecordingTransport, SecretReference, TransportProvenance,
};
use serde_json::to_string;

const NOW: u64 = 1_787_000_000;

fn scope() -> MeltanoPipelineResultScope {
    MeltanoPipelineResultScope::from_values(
        "workspace-1",
        "cloud-project-1",
        "production",
        "sales-sync",
        Some("sales-job-1".to_owned()),
        Some("tap-salesforce".to_owned()),
        Some("prod:tap-salesforce-to-target-warehouse".to_owned()),
        "project-1",
        3,
        "mission-1",
        5,
        "work-product-1",
        7,
        11,
    )
    .expect("valid Meltano scope")
}

fn secret(scope: &MeltanoPipelineResultScope) -> SecretReference {
    SecretReference::api_token("opaque-api-token-reference", scope, 1)
        .expect("opaque API-token reference")
}

fn response(
    scope: &MeltanoPipelineResultScope,
    request: &MeltanoPipelineReadRequest,
    status: MeltanoJobStatus,
) -> MeltanoPipelineResultResponse {
    let config_digest = Digest::from_text("config-v1");
    let state_digest = Digest::from_text("state-v1");
    let pipeline = MeltanoPipelineMetadata::new(
        scope,
        "daily-sales",
        MeltanoPipelineStatus::Ready,
        Some("@daily".to_owned()),
        900,
        2,
        NOW,
        NOW + 1,
        3,
        2,
        Some(config_digest.clone()),
        scope
            .state_id()
            .map(hartevo_meltano_pipeline_result_plugin::MeltanoStateId::digest),
    )
    .expect("pipeline metadata");
    let job = MeltanoJobMetadata::new(
        scope,
        MeltanoJobType::PipelineRun,
        status,
        Some(i32::from(status == MeltanoJobStatus::Error)),
        NOW,
        Some(NOW + 1),
        Some(NOW + 2),
        1,
        Some(state_digest.clone()),
        Some(config_digest.clone()),
        2,
    )
    .expect("job metadata");
    let state = MeltanoStateMetadata::new(
        scope.state_id().expect("state id"),
        state_digest,
        2,
        3,
        true,
        NOW + 2,
    )
    .expect("state metadata");
    let config = MeltanoConfigMetadata::new(
        config_digest,
        4,
        1,
        Some(scope.plugin().expect("plugin").digest()),
        Some(scope.state_id().expect("state id").digest()),
        NOW + 1,
    )
    .expect("config metadata");
    MeltanoPipelineResultResponse::new(
        request,
        Some(pipeline),
        Some(job),
        Some(state),
        Some(config),
        None,
        false,
        200,
        2_048,
        TransportProvenance::Recording,
    )
    .expect("response")
}

fn recording_service() -> MeltanoPipelineResultService<RecordingTransport> {
    let scope = scope();
    let provider = MeltanoProvider::new(RecordingTransport::default()).expect("provider");
    MeltanoPipelineResultService::new(scope.clone(), secret(&scope), provider, NOW)
        .expect("service")
}

#[test]
fn registration_secret_and_capabilities_are_redacted_and_non_native() {
    let service = recording_service();
    let serialized = to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.secret_reference());
    assert!(serialized.contains("secret_reference_digest"));
    assert!(!serialized.contains("opaque-api-token-reference"));
    assert!(!debug.contains("opaque-api-token-reference"));
    assert!(service.registration().validate().is_ok());
    let capabilities = service.describe_capabilities();
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.durable_provider_receipt);
    assert!(!capabilities.outcome_authority);
    assert!(!capabilities.work_product_authority);
    assert_eq!(capabilities.operations.len(), 6);
    assert!(
        capabilities
            .forbidden_operations
            .iter()
            .any(|operation| operation == "execute_pipeline")
    );
}

#[test]
fn complete_job_state_and_config_are_bounded_and_replay_safe() {
    let mut service = recording_service();
    let scope = service.scope().clone();
    let request = service.default_request("read-complete").expect("request");
    let response = response(&scope, &request, MeltanoJobStatus::Complete);
    service
        .provider_mut()
        .transport_mut()
        .push_response(response);
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, MeltanoEvidenceState::Success);
    assert_eq!(
        proposal.evidence.job.as_ref().expect("job").status,
        MeltanoJobStatus::Complete
    );
    assert_eq!(
        proposal
            .evidence
            .state_metadata
            .as_ref()
            .expect("state")
            .state_revision
            .get(),
        2
    );
    assert!(proposal.evidence.config.is_some());
    assert_eq!(proposal.evidence.transport, TransportProvenance::Recording);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.first_party);
    assert!(!proposal.evidence.durable_provider_receipt);
    assert!(proposal.validate_integrity(&scope).is_ok());
    assert!(service.verify(&proposal).valid);

    let mut consumer = MissionMeltanoPipelineConsumer::new(scope, service.registration().clone())
        .expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    assert!(!result.adopts_outcome);
    assert!(!result.adopts_work_product);
    let first = consumer.record(&proposal, "record-1").expect("record");
    let replay = consumer.record(&proposal, "record-1").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.recording_digest, replay.recording_digest);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn queued_running_error_and_stopped_are_typed_projections() {
    for (status, expected) in [
        (MeltanoJobStatus::Queued, MeltanoEvidenceState::Queued),
        (MeltanoJobStatus::Running, MeltanoEvidenceState::Running),
        (MeltanoJobStatus::Error, MeltanoEvidenceState::Error),
        (MeltanoJobStatus::Stopped, MeltanoEvidenceState::Stopped),
    ] {
        let mut service = recording_service();
        let scope = service.scope().clone();
        let request = service
            .default_request(format!("projection-{status:?}"))
            .expect("request");
        service
            .provider_mut()
            .transport_mut()
            .push_response(response(&scope, &request, status));
        let proposal = service.propose(request).expect("proposal");
        assert_eq!(proposal.state, expected);
        assert!(!service.verify(&proposal).valid);
    }
}

#[test]
fn blocked_env_partial_rate_expired_access_loss_and_stale_are_non_native_failures() {
    for (error, expected) in [
        (
            MeltanoTransportError::BlockedEnv,
            MeltanoEvidenceState::BlockedEnv,
        ),
        (
            MeltanoTransportError::Partial,
            MeltanoEvidenceState::Partial,
        ),
        (
            MeltanoTransportError::RateLimited {
                retry_after_seconds: Some(9),
            },
            MeltanoEvidenceState::RateLimited,
        ),
        (
            MeltanoTransportError::Expired,
            MeltanoEvidenceState::Expired,
        ),
        (
            MeltanoTransportError::AccessLost,
            MeltanoEvidenceState::AccessLoss,
        ),
        (MeltanoTransportError::Stale, MeltanoEvidenceState::Stale),
    ] {
        let scope = scope();
        let provider = MeltanoProvider::new({
            let mut transport = RecordingTransport::default();
            transport.push_error(error);
            transport
        })
        .expect("provider");
        let mut service =
            MeltanoPipelineResultService::new(scope.clone(), secret(&scope), provider, NOW)
                .expect("service");
        let proposal = service
            .propose(service.default_request("failure").expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.evidence.connected);
        assert!(!proposal.evidence.native);
        assert!(!proposal.evidence.first_party);
        if expected == MeltanoEvidenceState::RateLimited {
            assert!(proposal.evidence.retry.is_some());
            assert!(proposal.evidence.rate_limit.is_some());
        }
        assert!(!service.verify(&proposal).valid);
    }
}

#[test]
fn cursor_digest_is_opaque_and_scope_or_evidence_tamper_fails_closed() {
    let mut service = recording_service();
    let scope = service.scope().clone();
    let cursor = MeltanoCursor::from_handle("opaque-next-page-token", &scope, 2).expect("cursor");
    let serialized = to_string(&cursor).expect("cursor JSON");
    assert!(serialized.starts_with('"'));
    assert!(serialized.contains("cursor:"));
    assert!(!serialized.contains("opaque-next-page-token"));
    let request = MeltanoPipelineReadRequest::new(
        &scope,
        MeltanoReadOperation::ReadPipelineMetadata,
        20,
        2,
        Some(cursor),
        "cursor-read",
    )
    .expect("cursor request");
    service
        .provider_mut()
        .transport_mut()
        .push_response(response(&scope, &request, MeltanoJobStatus::Complete));
    let proposal = service.propose(request).expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.state = MeltanoEvidenceState::Tamper;
    assert!(tampered.validate_integrity(&scope).is_err());
    assert!(!service.verify(&tampered).valid);

    let changed_scope = MeltanoPipelineResultScope::from_values(
        "workspace-1",
        "cloud-project-1",
        "production",
        "sales-sync",
        Some("sales-job-1".to_owned()),
        Some("tap-salesforce".to_owned()),
        Some("prod:tap-salesforce-to-target-warehouse".to_owned()),
        "project-1",
        4,
        "mission-1",
        5,
        "work-product-1",
        7,
        11,
    )
    .expect("changed scope");
    assert_ne!(scope.digest(), changed_scope.digest());
    assert!(MeltanoCursor::from_handle("opaque-next-page-token", &changed_scope, 2).is_ok());
}

#[test]
fn registration_revoke_restore_reverse_and_config_entry_digest_are_reversible() {
    let mut service = recording_service();
    let request = service.default_request("revoked").expect("request");
    let active_digest = service.registration().registration_digest().clone();
    service.revoke_registration().expect("revoke");
    assert_ne!(active_digest, *service.registration().registration_digest());
    let revoked = service.propose(request).expect("revoked projection");
    assert_eq!(revoked.state, MeltanoEvidenceState::Revoked);
    assert!(!service.verify(&revoked).valid);
    service.restore_registration().expect("restore");
    service.reverse_registration().expect("reverse");
    let reversed = service
        .propose(service.default_request("reversed").expect("request"))
        .expect("reversed projection");
    assert_eq!(reversed.state, MeltanoEvidenceState::Revoked);
    assert!(service.restore_registration().is_err());

    let mut entries = BTreeMap::new();
    entries.insert(
        "tap-salesforce.client_id".to_owned(),
        Digest::from_text("client"),
    );
    entries.insert(
        "tap-salesforce.start_date".to_owned(),
        Digest::from_text("date"),
    );
    let config =
        MeltanoConfigMetadata::from_entries(&entries, 1, None, None, NOW).expect("config digest");
    assert_eq!(config.setting_count, 2);
    assert_ne!(config.config_digest, Digest::from_text("raw-config"));
}

#[test]
fn fixture_loopback_and_bounds_are_truthful() {
    let scope = scope();
    let request = MeltanoPipelineReadRequest::for_scope(&scope, "fixture").expect("request");
    let fixture_response = response(&scope, &request, MeltanoJobStatus::Complete);
    let fixture_provider =
        MeltanoProvider::new(FixtureTransport::new(fixture_response)).expect("fixture provider");
    let fixture_service =
        MeltanoPipelineResultService::new(scope.clone(), secret(&scope), fixture_provider, NOW)
            .expect("fixture service");
    assert_eq!(
        fixture_service.provider().provenance(),
        TransportProvenance::Fixture
    );
    assert!(!fixture_service.provider().connected());
    assert!(!fixture_service.provider().native());
    assert!(!fixture_service.provider().first_party());

    let loopback_provider = MeltanoProvider::new(LoopbackTransport::new()).expect("loopback");
    let mut loopback_service =
        MeltanoPipelineResultService::new(scope.clone(), secret(&scope), loopback_provider, NOW)
            .expect("loopback service");
    let loopback = loopback_service
        .propose(
            loopback_service
                .default_request("loopback")
                .expect("request"),
        )
        .expect("loopback proposal");
    assert_eq!(loopback.evidence.transport, TransportProvenance::Loopback);
    assert!(!loopback.evidence.connected);
    assert!(!loopback.evidence.native);
    assert!(!loopback.evidence.first_party);

    assert!(
        MeltanoPipelineResultResponse::new(
            &request,
            None,
            None,
            None,
            None,
            None,
            false,
            200,
            MAX_RESPONSE_BYTES + 1,
            TransportProvenance::Fixture,
        )
        .is_err()
    );
}

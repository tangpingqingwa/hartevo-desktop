use hartevo_dagger_pipeline_result_plugin::{
    BlockedEnvTransport, ConsentScope, DaggerArtifactId, DaggerArtifactKind,
    DaggerArtifactMetadata, DaggerEvidenceState, DaggerExecutionId, DaggerPipelineReadRequest,
    DaggerPipelineResultMetadata, DaggerPipelineResultResponse, DaggerPipelineResultService,
    DaggerPipelineScope, DaggerProvider, DaggerRunStatus, DaggerTransportError,
    MissionDaggerPipelineConsumer, RecordingTransport, SecretReference, TransportProvenance,
};
use serde_json::to_string;

const NOW: u64 = 1_787_000_000;

fn scope() -> DaggerPipelineScope {
    DaggerPipelineScope::from_values(
        "module-1",
        "pipeline-1",
        "build",
        "container-1",
        Some("0123456789abcdef".to_owned()),
        Some("artifact-1".to_owned()),
        "project-1",
        3,
        "mission-1",
        5,
        "work-product-1",
        7,
        11,
    )
    .expect("valid Dagger scope")
}

fn secret(scope: &DaggerPipelineScope) -> SecretReference {
    SecretReference::token("opaque-token-reference", scope, 1).expect("opaque token reference")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 1, NOW + 100).expect("consent")
}

fn response(
    scope: &DaggerPipelineScope,
    request: &DaggerPipelineReadRequest,
) -> DaggerPipelineResultResponse {
    let result = DaggerPipelineResultMetadata::new(
        scope,
        DaggerExecutionId::new("execution-1").expect("execution"),
        DaggerRunStatus::Succeeded,
        NOW,
        Some(120),
        Some(0),
        1,
    )
    .expect("result metadata");
    let artifact = DaggerArtifactMetadata::new(
        DaggerArtifactId::new("artifact-1").expect("artifact"),
        DaggerArtifactKind::OciImage,
        hartevo_dagger_pipeline_result_plugin::Digest::from_text("artifact-content").as_str(),
        2048,
        "application/vnd.oci.image.manifest.v1+json",
        NOW,
    )
    .expect("artifact metadata");
    DaggerPipelineResultResponse::new(
        request,
        result,
        vec![artifact],
        200,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
}

fn recording_service() -> DaggerPipelineResultService<RecordingTransport> {
    let scope = scope();
    let provider = DaggerProvider::new(RecordingTransport::default()).expect("provider");
    DaggerPipelineResultService::new(scope.clone(), secret(&scope), consent(), provider, NOW)
        .expect("service")
}

#[test]
fn registration_secret_and_capabilities_are_redacted_and_non_native() {
    let service = recording_service();
    let registration = service.registration();
    let serialized = to_string(registration).expect("registration JSON");
    let debug = format!("{:?}", service.secret_reference());
    assert!(serialized.contains("secret_reference_digest"));
    assert!(!serialized.contains("opaque-token-reference"));
    assert!(!debug.contains("opaque-token-reference"));
    assert!(registration.validate().is_ok());
    let capabilities = service.describe_capabilities();
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.durable_provider_receipt);
    assert!(!capabilities.outcome_authority);
    assert!(!capabilities.work_product_authority);
    assert_eq!(capabilities.operations.len(), 3);
    assert!(
        capabilities
            .forbidden_operations
            .iter()
            .any(|operation| operation == "execute_pipeline")
    );
}

#[test]
fn complete_result_is_bounded_recording_only_and_replay_safe() {
    let mut service = recording_service();
    let scope = service.scope().clone();
    let request = service.default_request("read-1").expect("request");
    let response = response(&scope, &request);
    service
        .provider_mut()
        .transport_mut()
        .push_response(response);
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, DaggerEvidenceState::Succeeded);
    assert_eq!(proposal.evidence.artifacts.len(), 1);
    assert_eq!(proposal.evidence.transport, TransportProvenance::Recording);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.evidence.durable_provider_receipt);
    assert!(proposal.validate_integrity(&scope).is_ok());
    assert!(service.verify(&proposal).valid);

    let mut consumer = MissionDaggerPipelineConsumer::new(scope, service.registration().clone())
        .expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    assert!(!result.adopts_outcome);
    let first = consumer.record(&proposal, "record-1").expect("record");
    let replay = consumer.record(&proposal, "record-1").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.recording_digest, replay.recording_digest);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn blocked_env_partial_rate_limit_and_access_loss_are_typed_failures() {
    let scope = scope();
    let blocked_provider = DaggerProvider::new(BlockedEnvTransport).expect("provider");
    let mut blocked = DaggerPipelineResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        blocked_provider,
        NOW,
    )
    .expect("service");
    let blocked_proposal = blocked
        .propose(blocked.default_request("blocked").expect("request"))
        .expect("blocked proposal");
    assert_eq!(blocked_proposal.state, DaggerEvidenceState::BlockedEnv);
    assert_eq!(
        blocked_proposal.evidence.transport,
        TransportProvenance::BlockedEnv
    );
    assert_eq!(
        blocked_proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "blocked_env"
    );
    assert!(!blocked.verify(&blocked_proposal).valid);
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);

    for (error, expected) in [
        (DaggerTransportError::Partial, DaggerEvidenceState::Partial),
        (
            DaggerTransportError::RateLimited {
                retry_after_seconds: Some(9),
            },
            DaggerEvidenceState::RateLimited,
        ),
        (
            DaggerTransportError::AccessLost,
            DaggerEvidenceState::AccessLoss,
        ),
    ] {
        let mut transport = RecordingTransport::default();
        transport.push_error(error);
        let provider = DaggerProvider::new(transport).expect("provider");
        let mut service = DaggerPipelineResultService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            provider,
            NOW,
        )
        .expect("service");
        let proposal = service
            .propose(service.default_request("failure").expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(!service.verify(&proposal).valid);
    }
}

#[test]
fn tamper_scope_revision_and_registration_transitions_fail_closed() {
    let mut service = recording_service();
    let scope = service.scope().clone();
    let request = service.default_request("read-tamper").expect("request");
    service
        .provider_mut()
        .transport_mut()
        .push_response(response(&scope, &request));
    let proposal = service.propose(request).expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.state = DaggerEvidenceState::Tampered;
    assert!(!service.verify(&tampered).valid);
    assert!(tampered.validate_integrity(&scope).is_err());

    let active_digest = service.registration().registration_digest().clone();
    service.revoke_registration().expect("revoke");
    assert_ne!(active_digest, *service.registration().registration_digest());
    assert!(service.default_request("revoked").is_ok());
    assert!(
        service
            .propose(service.default_request("revoked").expect("request"))
            .is_err()
    );
    service.restore_registration().expect("restore");
    service.reverse_registration().expect("reverse");
    assert!(service.restore_registration().is_err());

    let changed_scope = DaggerPipelineScope::from_values(
        "module-1",
        "pipeline-1",
        "build",
        "container-1",
        Some("0123456789abcdef".to_owned()),
        Some("artifact-1".to_owned()),
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
    assert!(SecretReference::oci("opaque-oci-reference", &changed_scope, 1).is_ok());
}

#[test]
fn bounded_metadata_rejects_oversized_response_and_raw_operation_surface() {
    let scope = scope();
    let request = DaggerPipelineReadRequest::for_scope(&scope, "bounds").expect("request");
    let result = DaggerPipelineResultMetadata::new(
        &scope,
        DaggerExecutionId::new("execution-1").expect("execution"),
        DaggerRunStatus::Succeeded,
        NOW,
        None,
        Some(0),
        0,
    )
    .expect("result");
    assert!(
        DaggerPipelineResultResponse::new(
            &request,
            result,
            Vec::new(),
            200,
            hartevo_dagger_pipeline_result_plugin::MAX_RESPONSE_BYTES + 1,
            TransportProvenance::Fixture,
        )
        .is_err()
    );
}

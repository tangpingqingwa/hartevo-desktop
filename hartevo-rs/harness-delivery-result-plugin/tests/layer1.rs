use chrono::{Duration, TimeZone, Utc};
use hartevo_harness_delivery_result_plugin::{
    BlockedEnvTransport, ConsentScope, DeploymentMetadata, ExecutionMetadata,
    HarnessDeliveryResultService, HarnessDeliveryScope, HarnessEvidenceState, HarnessExecutionId,
    HarnessProvider, HarnessRunStatus, ListExecutionsRequest, ListPipelinesRequest,
    ListServicesRequest, ListStagesRequest, OpaqueCursor, PipelineMetadata, PipelinePage,
    RecordingTransport, SecretReference, ServiceMetadata, StageMetadata, TransportProvenance,
};
use serde_json::to_string;

const NOW_SECONDS: i64 = 1_787_000_000;
const OPAQUE_API_KEY_REFERENCE: &str = "opaque-api-key-ref";

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> HarnessDeliveryScope {
    HarnessDeliveryScope::from_values(
        "account-1",
        "org-1",
        "project-1",
        "pipeline-1",
        Some("execution-1".to_owned()),
        Some("stage-1".to_owned()),
        Some("service-1".to_owned()),
        Some("environment-1".to_owned()),
        Some("0123456789abcdef".to_owned()),
        "mission-1",
        7,
        "project-1",
        11,
        "work-product-1",
        13,
    )
    .expect("valid Harness scope")
}

fn secret(scope: &HarnessDeliveryScope) -> SecretReference {
    SecretReference::api_key(OPAQUE_API_KEY_REFERENCE, scope, 1).expect("opaque API-key reference")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 4, now() + Duration::days(7)).expect("consent")
}

#[allow(clippy::too_many_lines)]
fn full_recording_service() -> HarnessDeliveryResultService<RecordingTransport> {
    let scope = scope();
    let pipeline_request = ListPipelinesRequest::for_scope(&scope).expect("pipeline request");
    let pipeline = PipelineMetadata::new(
        &scope,
        scope.pipeline().clone(),
        1,
        HarnessRunStatus::Succeeded,
        now(),
    )
    .expect("pipeline metadata");
    let pipeline_page = PipelinePage::new(
        &pipeline_request,
        vec![pipeline],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("pipeline page");

    let execution_request = ListExecutionsRequest::for_scope(&scope).expect("execution request");
    let execution = ExecutionMetadata::new(
        &scope,
        scope.execution().expect("execution").clone(),
        scope.pipeline().clone(),
        scope.commit().cloned(),
        HarnessRunStatus::Succeeded,
        now(),
    )
    .expect("execution metadata");
    let execution_page = hartevo_harness_delivery_result_plugin::ExecutionPage::new(
        &execution_request,
        vec![execution],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("execution page");

    let stage_request = ListStagesRequest::for_scope(&scope).expect("stage request");
    let stage = StageMetadata::new(
        &scope,
        scope.stage().expect("stage").clone(),
        scope.execution().expect("execution"),
        scope.service().cloned(),
        scope.environment().cloned(),
        HarnessRunStatus::Succeeded,
        now(),
    )
    .expect("stage metadata");
    let stage_page = hartevo_harness_delivery_result_plugin::StagePage::new(
        &stage_request,
        vec![stage],
        None,
        384,
        TransportProvenance::Recording,
    )
    .expect("stage page");

    let service_request = ListServicesRequest::for_scope(&scope).expect("service request");
    let service = ServiceMetadata::new(
        &scope,
        scope.service().expect("service").clone(),
        scope.environment().cloned(),
        Some(
            hartevo_harness_delivery_result_plugin::HarnessDeploymentId::new("deployment-1")
                .expect("deployment"),
        ),
        scope.commit().cloned(),
        HarnessRunStatus::Succeeded,
        now(),
    )
    .expect("service metadata");
    let service_page = hartevo_harness_delivery_result_plugin::ServicePage::new(
        &service_request,
        vec![service],
        None,
        384,
        TransportProvenance::Recording,
    )
    .expect("service page");

    let deployment_request =
        hartevo_harness_delivery_result_plugin::GetDeploymentRequest::for_scope(&scope)
            .expect("deployment request");
    let deployment = DeploymentMetadata::new(
        &scope,
        hartevo_harness_delivery_result_plugin::HarnessDeploymentId::new("deployment-1")
            .expect("deployment"),
        scope.service().expect("service").clone(),
        scope.environment().expect("environment").clone(),
        scope.commit().cloned(),
        HarnessRunStatus::Succeeded,
        now(),
    )
    .expect("deployment metadata");
    let deployment_response = hartevo_harness_delivery_result_plugin::DeploymentResponse::new(
        &deployment_request,
        Some(deployment),
        384,
        TransportProvenance::Recording,
    )
    .expect("deployment response");

    let mut transport = RecordingTransport::default();
    transport.push_pipeline_response(Ok(pipeline_page));
    transport.push_execution_response(Ok(execution_page));
    transport.push_stage_response(Ok(stage_page));
    transport.push_service_response(Ok(service_page));
    transport.push_deployment_response(Ok(deployment_response));
    let provider = HarnessProvider::new(transport).expect("provider");
    HarnessDeliveryResultService::new(scope.clone(), secret(&scope), consent(), provider, now())
        .expect("service")
}

#[test]
fn registration_and_secret_are_digest_bound_and_redacted() {
    let service = full_recording_service();
    let registration = service.registration();
    let serialized = to_string(registration).expect("registration JSON");
    let debug = format!("{registration:?}");
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(OPAQUE_API_KEY_REFERENCE));
    assert!(!debug.contains(OPAQUE_API_KEY_REFERENCE));
    assert!(registration.validate().is_ok());
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(
        !service
            .describe_capabilities()
            .operations
            .iter()
            .any(|operation| {
                operation.contains("execute")
                    || operation.contains("retry")
                    || operation.contains("approve")
                    || operation.contains("rollback")
                    || operation.contains("trigger")
            })
    );
}

#[test]
fn complete_evidence_is_bounded_and_recording_only() {
    let mut service = full_recording_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, HarnessEvidenceState::Succeeded);
    assert_eq!(proposal.evidence.stages.len(), 1);
    assert_eq!(proposal.evidence.services.len(), 1);
    assert_eq!(proposal.evidence.deployments.len(), 1);
    assert_eq!(proposal.provenance, TransportProvenance::Recording);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(
        proposal
            .evidence
            .validate_integrity(service.scope())
            .is_ok()
    );
    assert!(service.verify(&proposal).valid);

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let first = consumer.record(&proposal, "record-key-1").expect("record");
    let replay = consumer.record(&proposal, "record-key-1").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert_eq!(first.recording_digest, replay.recording_digest);
    assert!(first.validate_integrity().is_ok());
}

#[test]
fn blocked_env_is_honest_and_never_connected() {
    let scope = scope();
    let provider = HarnessProvider::new(BlockedEnvTransport).expect("provider");
    let mut service = HarnessDeliveryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, HarnessEvidenceState::BlockedEnv);
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!service.verify(&proposal).valid);
}

#[test]
fn cursor_and_execution_binding_are_opaque_and_fenced() {
    let scope = scope();
    let request = ListPipelinesRequest::for_scope(&scope).expect("request");
    let cursor = OpaqueCursor::new(
        "opaque-provider-page-token",
        &scope,
        request.request_digest().clone(),
        2,
    )
    .expect("cursor");
    let serialized = to_string(&cursor).expect("cursor JSON");
    let debug = format!("{cursor:?}");
    assert!(!serialized.contains("opaque-provider-page-token"));
    assert!(!debug.contains("opaque-provider-page-token"));
    assert!(serialized.contains("tokenDigest"));
    let changed_scope = scope
        .with_execution(
            HarnessExecutionId::new("execution-2").expect("execution"),
            scope.stage().cloned(),
            scope.service().cloned(),
            scope.environment().cloned(),
            scope.commit().cloned(),
        )
        .expect("changed scope");
    assert!(ListPipelinesRequest::new(&changed_scope, 30, Some(cursor)).is_err());
    let replaced_execution = ExecutionMetadata::new(
        &scope,
        HarnessExecutionId::new("execution-2").expect("execution"),
        scope.pipeline().clone(),
        scope.commit().cloned(),
        HarnessRunStatus::Succeeded,
        now(),
    );
    assert!(replaced_execution.is_err());
}

#[test]
fn rate_limit_exposes_backoff_without_repeating_the_read() {
    let scope = scope();
    let pipeline_request = ListPipelinesRequest::for_scope(&scope).expect("request");
    let mut transport = RecordingTransport::default();
    transport.push_pipeline_response(Err(
        hartevo_harness_delivery_result_plugin::HarnessTransportError::RateLimited {
            retry_after_seconds: Some(9),
        },
    ));
    let provider = HarnessProvider::new(transport).expect("provider");
    let mut service = HarnessDeliveryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, HarnessEvidenceState::RateLimited);
    assert_eq!(
        proposal
            .evidence
            .backoff
            .expect("backoff")
            .retry_after_seconds,
        Some(9)
    );
    assert_eq!(service.provider().transport().requests().len(), 1);
    assert_eq!(
        pipeline_request.request_digest(),
        service.provider().transport().requests()[0]
            .request_digest()
            .expect("request digest")
    );
}

#[test]
fn partial_access_loss_and_tamper_fail_closed() {
    let scope = scope();
    let mut partial_transport = RecordingTransport::default();
    partial_transport.push_pipeline_response(Err(
        hartevo_harness_delivery_result_plugin::HarnessTransportError::Partial,
    ));
    let partial_provider = HarnessProvider::new(partial_transport).expect("provider");
    let mut partial_service = HarnessDeliveryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        partial_provider,
        now(),
    )
    .expect("service");
    let partial = partial_service
        .propose(partial_service.default_request(now()).expect("request"))
        .expect("partial proposal");
    assert_eq!(partial.state, HarnessEvidenceState::Partial);
    assert!(!partial_service.verify(&partial).valid);

    let mut access_loss_transport = RecordingTransport::default();
    access_loss_transport.push_pipeline_response(Err(
        hartevo_harness_delivery_result_plugin::HarnessTransportError::AccessLost,
    ));
    let access_loss_provider = HarnessProvider::new(access_loss_transport).expect("provider");
    let mut access_loss_service = HarnessDeliveryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        access_loss_provider,
        now(),
    )
    .expect("service");
    let access_loss = access_loss_service
        .propose(access_loss_service.default_request(now()).expect("request"))
        .expect("access-loss proposal");
    assert_eq!(access_loss.state, HarnessEvidenceState::AccessLoss);
    assert!(!access_loss_service.verify(&access_loss).valid);

    let mut recording_service = full_recording_service();
    let proposal = recording_service
        .propose(recording_service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.state = HarnessEvidenceState::Tampered;
    assert!(tampered.validate_integrity().is_err());
    assert!(!recording_service.verify(&tampered).valid);
}

#[test]
fn registration_transitions_are_digest_bound_and_reversible() {
    let service = full_recording_service();
    let mut registration = service.registration().clone();
    let active_digest = registration.registration_digest().clone();
    let revoked = registration.revoke().expect("revoke");
    assert_eq!(
        revoked.new_status,
        hartevo_harness_delivery_result_plugin::RegistrationStatus::Revoked
    );
    assert_ne!(active_digest, *registration.registration_digest());
    registration.restore().expect("restore");
    registration.reverse().expect("reverse");
    assert!(registration.restore().is_err());
}

trait RequestDigestForTest {
    fn request_digest(&self) -> Option<&hartevo_harness_delivery_result_plugin::Digest>;
}

impl RequestDigestForTest for hartevo_harness_delivery_result_plugin::RecordedHarnessRequest {
    fn request_digest(&self) -> Option<&hartevo_harness_delivery_result_plugin::Digest> {
        match self {
            Self::ListPipelines { request_digest }
            | Self::ListExecutions { request_digest }
            | Self::ListStages { request_digest }
            | Self::ListServices { request_digest }
            | Self::GetDeploymentMetadata { request_digest } => Some(request_digest),
        }
    }
}

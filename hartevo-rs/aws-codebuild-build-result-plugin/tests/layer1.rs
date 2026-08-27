use std::fmt::Debug;

use hartevo_aws_codebuild_build_result_plugin as plugin;
use plugin::{
    ArtifactId, ArtifactKind, ArtifactMetadata, AwsAccountId, AwsCodeBuildError,
    AwsCodeBuildProvider, AwsCodeBuildReadRequest, AwsCodeBuildResultService, AwsCodeBuildScope,
    AwsCodeBuildTransport, AwsCodeBuildTransportError, BatchGetBuildsPage, BatchGetProjectsPage,
    BuildBatchMetadata, BuildId, BuildSummary, CodeBuildStatus, Digest, EvidenceStatus,
    FixtureAwsCodeBuildTransport, ListBuildsForProjectPage, ListBuildsForProjectRequest,
    MissionAwsCodeBuildConsumer, OpaquePageToken, ProjectId, ProjectSummary, ProviderProvenance,
    RecordingAwsCodeBuildTransport, Revision, SecretReference, SourceCommit, SourceRepository,
    Timestamp,
};

fn scope() -> AwsCodeBuildScope {
    AwsCodeBuildScope::new(
        AwsAccountId::new("123456789012").unwrap(),
        plugin::AwsRegion::new("us-east-1").unwrap(),
        plugin::CodeBuildProjectName::new("hartevo-build").unwrap(),
        BuildId::new("hartevo-build:00000000-0000-0000-0000-000000000001").unwrap(),
        plugin::MissionId::new("mission-581").unwrap(),
        ProjectId::new("project-581").unwrap(),
        plugin::WorkProductId::new("work-product-581").unwrap(),
    )
    .with_source_repository(SourceRepository::new("github.com/tangpingqingwa/hartevo").unwrap())
    .with_source_commit(SourceCommit::new("0123456789abcdef0123456789abcdef01234567").unwrap())
    .with_artifact_id(ArtifactId::new("artifact-581").unwrap())
    .with_revisions(
        Revision::new(2).unwrap(),
        Revision::new(3).unwrap(),
        Revision::new(4).unwrap(),
    )
}

fn build(scope: &AwsCodeBuildScope, status: CodeBuildStatus) -> BuildSummary {
    let artifact = ArtifactMetadata::new(
        ArtifactKind::S3,
        "s3://redacted-metadata-only/build.zip",
        Some(Digest::from_text("artifact-content-digest")),
        Some(4096),
    )
    .unwrap();
    BuildSummary::new(
        scope.build_id.clone(),
        scope.project_name.clone(),
        scope.source_repository.clone(),
        scope.source_commit.clone(),
        scope.artifact_id.clone(),
        status,
        Some(Timestamp::new(100)),
        Some(Timestamp::new(112)),
        vec![artifact],
        Some(BuildBatchMetadata::new("batch-581", status, 1).unwrap()),
    )
    .unwrap()
}

fn project(scope: &AwsCodeBuildScope, build: &BuildSummary) -> ProjectSummary {
    ProjectSummary::new(
        scope.project_name.clone(),
        scope.source_repository.clone(),
        scope.source_commit.clone(),
        Some(build.artifact_metadata_digest()),
        build
            .batch_metadata
            .as_ref()
            .map(|metadata| metadata.metadata_digest.clone()),
    )
    .unwrap()
}

fn registered_provider(
    scope: &AwsCodeBuildScope,
    transport: RecordingAwsCodeBuildTransport,
) -> (
    AwsCodeBuildProvider<RecordingAwsCodeBuildTransport>,
    MissionAwsCodeBuildConsumer,
) {
    let mut provider = AwsCodeBuildProvider::new(transport).unwrap();
    let secret = SecretReference::new("host-credential-alias", scope, 7).unwrap();
    let registration = provider.register_scope(scope.clone(), secret).unwrap();
    let consumer = MissionAwsCodeBuildConsumer::new(scope.clone(), registration).unwrap();
    (provider, consumer)
}

fn queue_complete_responses(
    request: &AwsCodeBuildReadRequest,
    build: &BuildSummary,
    project: &ProjectSummary,
    transport: &mut RecordingAwsCodeBuildTransport,
) {
    let list_request = request.list_request.as_ref().unwrap();
    transport.push_list_response(Ok(ListBuildsForProjectPage::new(
        list_request,
        vec![build.clone()],
        None,
    )
    .unwrap()));
    transport.push_build_response(Ok(BatchGetBuildsPage::new(
        &request.builds_request,
        vec![build.clone()],
        vec![],
    )
    .unwrap()));
    transport.push_project_response(Ok(BatchGetProjectsPage::new(
        &request.projects_request,
        vec![project.clone()],
        vec![],
    )
    .unwrap()));
}

#[test]
fn contract_capabilities_and_runtime_definition_are_layer1_read_only() {
    plugin::validate_contract_document().unwrap();
    let service = AwsCodeBuildResultService::new();
    assert!(service.read_only());
    assert!(!service.native_connected());
    assert_eq!(service.capabilities().len(), 9);
    assert!(
        service
            .capabilities()
            .iter()
            .all(|capability| !capability.native
                && !capability.connected
                && !capability.external_writes)
    );
    let project = hartevo_plugin_runtime::ProjectId::new("project-581").unwrap();
    let mission = hartevo_plugin_runtime::MissionId::new("mission-581").unwrap();
    let scope = hartevo_plugin_runtime::PluginScope::new(project, mission, 1).unwrap();
    let definition = service.runtime_definition(scope).unwrap();
    definition.validate().unwrap();
}

#[test]
fn secret_reference_is_opaque_and_non_serializing() {
    let scope = scope();
    let secret = SecretReference::new("raw-secret-alias-must-not-escape", &scope, 1).unwrap();
    let debug = format!("{secret:?}");
    let display = secret.to_string();
    assert!(!debug.contains("raw-secret-alias"));
    assert!(!display.contains("raw-secret-alias"));
    assert!(secret.is_for_scope(&scope));
    let other_scope = AwsCodeBuildScope::new(
        scope.account_id.clone(),
        scope.region.clone(),
        scope.project_name.clone(),
        BuildId::new("other-build").unwrap(),
        scope.mission_id.clone(),
        scope.project_id.clone(),
        scope.work_product_id.clone(),
    );
    assert!(!secret.is_for_scope(&other_scope));
}

#[test]
fn complete_read_propose_record_verify_has_all_digest_fences() {
    let scope = scope();
    let build = build(&scope, CodeBuildStatus::Succeeded);
    let project = project(&scope, &build);
    let request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    queue_complete_responses(&request, &build, &project, &mut transport);
    let (mut provider, consumer) = registered_provider(&scope, transport);

    let result = consumer.read(&mut provider, &request).unwrap();
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.provenance, ProviderProvenance::Recording);
    assert!(!result.evidence.is_native());
    assert!(!result.evidence.is_connected());
    result.validate(&scope).unwrap();

    let service = AwsCodeBuildResultService::new();
    let proposal = service.propose(result.evidence.clone()).unwrap();
    let record = service.record(&proposal).unwrap();
    let verification = service.verify(&record).unwrap();
    verification.validate().unwrap();
    assert_eq!(record.scope_digest, result.evidence.digests.scope_digest);
    assert_eq!(
        record.registration_digest,
        result.evidence.digests.registration_digest
    );
}

#[test]
fn fixture_and_loopback_are_never_native_or_connected() {
    let scope = scope();
    let build = build(&scope, CodeBuildStatus::Succeeded);
    let fixture = FixtureAwsCodeBuildTransport::new(vec![build.clone()]);
    assert_eq!(fixture.provenance(), ProviderProvenance::Fixture);
    assert!(!fixture.is_native());
    assert!(!fixture.is_connected());
    let mut loopback = plugin::LoopbackAwsCodeBuildTransport::new(vec![build]);
    assert_eq!(loopback.provenance(), ProviderProvenance::Loopback);
    assert!(!loopback.is_native());
    assert!(!loopback.is_connected());
    let request = plugin::ListBuildsForProjectRequest::new(&scope, 1).unwrap();
    let page = loopback.list_builds_for_project(&request).unwrap();
    assert_eq!(page.builds.len(), 1);
}

#[test]
fn pagination_is_opaque_bounded_and_truncated_without_complete_claim() {
    let scope = scope();
    let target = build(&scope, CodeBuildStatus::Succeeded);
    let mut other_scope = scope.clone();
    other_scope.build_id = BuildId::new("hartevo-build:other").unwrap();
    let other = build(&other_scope, CodeBuildStatus::Succeeded);
    let request = AwsCodeBuildReadRequest::list_only(&scope, 1).unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    let mut page_request = request.list_request.clone().unwrap();
    for page_number in 1..=3 {
        let next = OpaquePageToken::new(format!("page-{page_number}")).unwrap();
        let page = ListBuildsForProjectPage::new(
            &page_request,
            vec![if page_number == 1 {
                target.clone()
            } else {
                other.clone()
            }],
            Some(next.clone()),
        )
        .unwrap();
        transport.push_list_response(Ok(page));
        page_request = page_request.next_page(next).unwrap();
    }
    let final_token = OpaquePageToken::new("page-4").unwrap();
    transport.push_list_response(Ok(ListBuildsForProjectPage::new(
        &page_request,
        vec![other],
        Some(final_token),
    )
    .unwrap()));
    let request = request
        .with_list_request(&scope, ListBuildsForProjectRequest::new(&scope, 1).unwrap())
        .unwrap();
    let project = project(&scope, &target);
    transport.push_build_response(Ok(BatchGetBuildsPage::new(
        &request.builds_request,
        vec![target.clone()],
        vec![],
    )
    .unwrap()));
    transport.push_project_response(Ok(BatchGetProjectsPage::new(
        &request.projects_request,
        vec![project],
        vec![],
    )
    .unwrap()));
    let (mut provider, consumer) = registered_provider(&scope, transport);
    let result = consumer.read(&mut provider, &request).unwrap();
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(plugin::PartialReason::PageLimitReached)
    );
    let serialized = serde_json::to_string(&result.evidence).unwrap();
    assert!(!serialized.contains("page-1"));
}

#[test]
fn repeated_page_token_is_replay_rejected() {
    let scope = scope();
    let target = build(&scope, CodeBuildStatus::Succeeded);
    let request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    let list_request = request.list_request.as_ref().unwrap();
    let token = OpaquePageToken::new("repeat-me").unwrap();
    let first =
        ListBuildsForProjectPage::new(list_request, vec![target.clone()], Some(token.clone()))
            .unwrap();
    let second_request = list_request.next_page(token.clone()).unwrap();
    let second = ListBuildsForProjectPage::new(&second_request, vec![target], Some(token)).unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    transport.push_list_response(Ok(first));
    transport.push_list_response(Ok(second));
    let (mut provider, consumer) = registered_provider(&scope, transport);
    assert_eq!(
        consumer.read(&mut provider, &request),
        Err(AwsCodeBuildError::PageLoop)
    );
}

#[test]
fn unknown_status_is_partial_and_never_workload_authority() {
    let scope = scope();
    let build = build(&scope, CodeBuildStatus::Unknown);
    let project = project(&scope, &build);
    let request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    queue_complete_responses(&request, &build, &project, &mut transport);
    let (mut provider, consumer) = registered_provider(&scope, transport);
    let result = consumer.read(&mut provider, &request).unwrap();
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(plugin::PartialReason::UnknownStatus)
    );
    assert!(!result.observation.outcome_authority);
    assert!(!result.observation.work_product_adoption);
}

#[test]
fn source_commit_and_artifact_drift_fail_closed() {
    let scope = scope();
    let original = build(&scope, CodeBuildStatus::Succeeded);
    let drifted = BuildSummary::new(
        original.build_id.clone(),
        original.project_name.clone(),
        original.source_repository.clone(),
        Some(SourceCommit::new("ffffffffffffffffffffffffffffffffffffffff").unwrap()),
        original.artifact_id.clone(),
        original.status,
        original.started_at,
        original.finished_at,
        original.artifact_metadata.clone(),
        original.batch_metadata.clone(),
    )
    .unwrap();
    let request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    let list_request = request.list_request.as_ref().unwrap();
    let page = ListBuildsForProjectPage::new(list_request, vec![drifted], None).unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    transport.push_list_response(Ok(page));
    let (mut provider, consumer) = registered_provider(&scope, transport);
    assert_eq!(
        consumer.read(&mut provider, &request),
        Err(AwsCodeBuildError::SourceDrift)
    );

    let mut artifact_drift = build(&scope, CodeBuildStatus::Succeeded);
    artifact_drift.artifact_id = Some(ArtifactId::new("different-artifact").unwrap());
    assert!(artifact_drift.validate_against(&scope).is_err());
}

#[test]
fn access_loss_and_blocked_environment_are_explicit_not_connected() {
    let scope = scope();
    let build = build(&scope, CodeBuildStatus::Succeeded);
    let project = project(&scope, &build);
    let request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    transport.push_list_response(Err(AwsCodeBuildTransportError::AccessDenied));
    transport.push_build_response(Ok(BatchGetBuildsPage::new(
        &request.builds_request,
        vec![build.clone()],
        vec![],
    )
    .unwrap()));
    transport.push_project_response(Ok(BatchGetProjectsPage::new(
        &request.projects_request,
        vec![project],
        vec![],
    )
    .unwrap()));
    let (mut provider, consumer) = registered_provider(&scope, transport);
    let result = consumer.read(&mut provider, &request).unwrap();
    assert_eq!(result.evidence.status, EvidenceStatus::AccessLost);
    assert_eq!(
        result.evidence.access_loss.unwrap().kind,
        plugin::AccessLossKind::AccessDenied
    );
    assert!(!result.observation.connected);
    assert!(!result.observation.native);

    let mut blocked = AwsCodeBuildProvider::default();
    let secret = SecretReference::new("blocked-env-alias", &scope, 1).unwrap();
    let registration = blocked.register_scope(scope.clone(), secret).unwrap();
    let blocked_consumer = MissionAwsCodeBuildConsumer::new(scope.clone(), registration).unwrap();
    let blocked_result = blocked_consumer.read(&mut blocked, &request).unwrap();
    assert_eq!(blocked_result.evidence.status, EvidenceStatus::AccessLost);
    assert_eq!(
        blocked_result.evidence.access_loss.clone().unwrap().kind,
        plugin::AccessLossKind::BlockedEnv
    );
    assert!(!blocked_result.evidence.is_native());
}

#[test]
fn malformed_transport_error_is_access_lost_but_invalid_recording_is_an_error() {
    let scope = scope();
    let request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    let mut malformed = RecordingAwsCodeBuildTransport::new();
    malformed.push_list_response(Err(AwsCodeBuildTransportError::MalformedResponse));
    malformed.push_build_response(Ok(BatchGetBuildsPage::new(
        &request.builds_request,
        vec![],
        vec![scope.build_id.clone()],
    )
    .unwrap()));
    malformed.push_project_response(Ok(BatchGetProjectsPage::new(
        &request.projects_request,
        vec![],
        vec![scope.project_name.clone()],
    )
    .unwrap()));
    let (mut provider, consumer) = registered_provider(&scope, malformed);
    let result = consumer.read(&mut provider, &request).unwrap();
    assert_eq!(result.evidence.status, EvidenceStatus::AccessLost);
    assert_eq!(
        result.evidence.access_loss.unwrap().kind,
        plugin::AccessLossKind::MalformedResponse
    );

    let empty = RecordingAwsCodeBuildTransport::new();
    let (mut provider, consumer) = registered_provider(&scope, empty);
    assert!(matches!(
        consumer.read(&mut provider, &request),
        Err(AwsCodeBuildError::Transport(
            AwsCodeBuildTransportError::QueueExhausted
        ))
    ));
}

#[test]
fn optional_batch_metadata_truncation_is_partial() {
    let scope = scope();
    let build = build(&scope, CodeBuildStatus::Succeeded);
    let project = project(&scope, &build);
    let request = AwsCodeBuildReadRequest::new(&scope)
        .unwrap()
        .with_batch_metadata(&scope, true)
        .unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    transport.push_list_response(Ok(ListBuildsForProjectPage::new(
        request.list_request.as_ref().unwrap(),
        vec![build.clone()],
        None,
    )
    .unwrap()));
    transport.push_build_response(Ok(BatchGetBuildsPage::new(
        &request.builds_request,
        vec![build.clone()],
        vec![],
    )
    .unwrap()
    .with_batch_metadata_truncated()));
    transport.push_project_response(Ok(BatchGetProjectsPage::new(
        &request.projects_request,
        vec![project],
        vec![],
    )
    .unwrap()
    .with_batch_metadata_truncated()));
    let (mut provider, consumer) = registered_provider(&scope, transport);
    let result = consumer.read(&mut provider, &request).unwrap();
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(plugin::PartialReason::OptionalBatchMetadataTruncated)
    );
}

#[test]
fn tamper_replay_and_revocation_are_rejected() {
    let scope = scope();
    let build = build(&scope, CodeBuildStatus::Succeeded);
    let project = project(&scope, &build);
    let request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    queue_complete_responses(&request, &build, &project, &mut transport);
    let (mut provider, consumer) = registered_provider(&scope, transport);
    let result = consumer.read(&mut provider, &request).unwrap();
    let mut tampered = result.evidence.clone();
    tampered.digests.evidence_digest = Digest::from_text("tampered");
    assert_eq!(
        consumer.consume_evidence(tampered),
        Err(AwsCodeBuildError::TamperedEvidence)
    );
    consumer.consume_evidence(result.evidence.clone()).unwrap();
    assert_eq!(
        consumer.consume_evidence(result.evidence),
        Err(AwsCodeBuildError::ReplayDetected)
    );

    provider
        .revoke_registration(Revision::new(8).unwrap())
        .unwrap();
    assert_eq!(
        consumer.read(&mut provider, &request),
        Err(AwsCodeBuildError::RegistrationRevoked)
    );
}

#[test]
fn bounds_and_request_binding_reject_truncation_and_scope_replay() {
    let scope = scope();
    assert!(plugin::ListBuildsForProjectRequest::new(&scope, 0).is_err());
    assert!(plugin::ListBuildsForProjectRequest::new(&scope, 101).is_err());
    assert!(OpaquePageToken::new("").is_err());
    assert!(OpaquePageToken::new("bad\nvalue").is_err());

    let mut request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    request.request_digest = Digest::from_text("replayed-request");
    let mut provider = AwsCodeBuildProvider::default();
    let secret = SecretReference::new("binding-alias", &scope, 1).unwrap();
    let registration = provider.register_scope(scope.clone(), secret).unwrap();
    let consumer = MissionAwsCodeBuildConsumer::new(scope.clone(), registration).unwrap();
    assert_eq!(
        consumer.read(&mut provider, &request),
        Err(AwsCodeBuildError::ScopeMismatch)
    );
}

#[test]
fn transport_failure_mapping_is_bounded_and_explicit() {
    assert_eq!(
        AwsCodeBuildTransportError::from_http_status(403).access_loss_kind(),
        plugin::AccessLossKind::AccessDenied
    );
    assert_eq!(
        AwsCodeBuildTransportError::from_http_status(503).provider_code(),
        "HTTP_500"
    );
    assert!(AwsCodeBuildTransportError::Timeout.is_access_loss());
    assert!(!AwsCodeBuildTransportError::QueueExhausted.is_access_loss());
    assert!(!AwsCodeBuildTransportError::InvalidRequest("bad".to_owned()).is_access_loss());
}

#[test]
fn all_read_results_remain_below_kernel_authority() {
    let scope = scope();
    let build = build(&scope, CodeBuildStatus::Succeeded);
    let project = project(&scope, &build);
    let request = AwsCodeBuildReadRequest::new(&scope).unwrap();
    let mut transport = RecordingAwsCodeBuildTransport::new();
    queue_complete_responses(&request, &build, &project, &mut transport);
    let (mut provider, consumer) = registered_provider(&scope, transport);
    let result = consumer.read(&mut provider, &request).unwrap();
    assert!(!result.receipt.native);
    assert!(!result.receipt.connected);
    assert!(!result.receipt.durable_native_receipt);
    assert!(!result.receipt.independent_artifact_readback);
    assert!(!result.receipt.outcome_authority);
    assert!(!result.receipt.work_product_adoption);
    assert!(format!("{result:?}").contains("ArtifactMetadata"));
}

fn assert_debug<T: Debug>() {}

#[test]
fn public_boundary_types_have_debug_implementations() {
    assert_debug::<AwsCodeBuildScope>();
    assert_debug::<AwsCodeBuildProvider<RecordingAwsCodeBuildTransport>>();
    assert_debug::<MissionAwsCodeBuildConsumer>();
}

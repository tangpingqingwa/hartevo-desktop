use hartevo_aws_codepipeline_release_result_plugin::{
    ActionExecutionFilter, ActionExecutionPage, ActionExecutionRecord, ActionExecutionStatus,
    AwsCodePipelineRecordingLog, AwsCodePipelineRegistration, AwsCodePipelineReleaseError,
    AwsCodePipelineReleaseService, AwsCodePipelineScope, AwsCodePipelineTransport,
    AwsCodePipelineTransportError, BlockedEnvAwsCodePipelineTransport, CONTRACT_DIGEST,
    CONTRACT_JSON, CONTRACT_VERSION, Cursor, EvidenceState, FixtureAwsCodePipelineTransport,
    MAX_PAGE_SIZE, MissionAwsCodePipelineConsumer, PermissionSnapshot, PipelineExecutionFilter,
    PipelineExecutionPage, PipelineExecutionRecord, PipelineExecutionStatus, PipelineStateRecord,
    PipelineStateResponse, ProposalDisposition, ProviderIdentity, RedactionEvidence,
    RegistrationId, SecretReference, StageActionTransitionKind, TransportProvenance,
    contract_digest,
};

const OBSERVED_AT: u64 = 1_744_550_401;

fn scope() -> AwsCodePipelineScope {
    AwsCodePipelineScope::from_ids(
        "123456789012",
        1,
        "us-east-1",
        2,
        "release-pipeline",
        3,
        "execution-42",
        4,
        "Deploy",
        5,
        "Production",
        6,
        "mission-codepipeline-1",
        7,
        "project-codepipeline-1",
        8,
        "work-product-codepipeline-1",
        9,
    )
    .expect("scope")
}

fn registration(scope: AwsCodePipelineScope) -> AwsCodePipelineRegistration {
    AwsCodePipelineRegistration::new(
        RegistrationId::new("registration-codepipeline-1").expect("registration id"),
        scope,
        SecretReference::sigv4("opaque-sigv4-reference", 1).expect("secret reference"),
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "recording-r1").expect("provider"),
        1,
    )
    .expect("registration")
}

fn service(
    scope: &AwsCodePipelineScope,
    transport: FixtureAwsCodePipelineTransport,
) -> AwsCodePipelineReleaseService<FixtureAwsCodePipelineTransport> {
    AwsCodePipelineReleaseService::new(registration(scope.clone()), transport).expect("service")
}

fn proposal<T: AwsCodePipelineTransport>(
    service: &mut AwsCodePipelineReleaseService<T>,
) -> hartevo_aws_codepipeline_release_result_plugin::AwsCodePipelineReleaseProposal {
    let request = service.request(10, 1, OBSERVED_AT).expect("request");
    service.propose(request).expect("proposal")
}

#[test]
fn contract_is_exact_layer_one_and_bounded() {
    assert_eq!(contract_digest(), CONTRACT_DIGEST);
    assert_eq!(CONTRACT_VERSION, "EXT-AWS-CODEPIPELINE-01-L1/v1");
    assert!(CONTRACT_JSON.contains("GetPipelineState"));
    assert!(CONTRACT_JSON.contains("ListActionExecutions"));
    assert!(CONTRACT_JSON.contains("serialize_secret_material"));
    assert!(CONTRACT_JSON.contains("blocked_env"));
    assert!(!CONTRACT_JSON.contains("\"connected\": true"));

    let scope = scope();
    let service = service(&scope, FixtureAwsCodePipelineTransport::from_scope(&scope));
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.artifact_download);
    assert!(!capabilities.raw_logs);
    assert!(!capabilities.outcome_adoption);
}

#[test]
fn all_layer_one_provenances_never_claim_native_or_connected() {
    let scope = scope();
    let recording =
        hartevo_aws_codepipeline_release_result_plugin::RecordingTransport::from_scope(&scope);
    assert_eq!(recording.provenance(), TransportProvenance::Recording);
    assert!(!recording.provenance().is_native());
    assert!(!recording.provenance().claims_connected());

    let loopback =
        hartevo_aws_codepipeline_release_result_plugin::LoopbackTransport::from_scope(&scope);
    assert_eq!(loopback.provenance(), TransportProvenance::Loopback);

    let blocked = BlockedEnvAwsCodePipelineTransport;
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    let mut blocked_service =
        AwsCodePipelineReleaseService::new(registration(scope.clone()), blocked)
            .expect("blocked service");
    let evidence = proposal(&mut blocked_service);
    assert_eq!(evidence.state, EvidenceState::Unknown);
    assert_eq!(evidence.provenance, TransportProvenance::BlockedEnv);
    assert!(!evidence.connected);
    assert!(!evidence.native);
}

#[test]
fn bounded_success_has_four_reads_redacted_metadata_and_mission_recording() {
    let scope = scope();
    let mut service = service(&scope, FixtureAwsCodePipelineTransport::from_scope(&scope));
    let proposal = proposal(&mut service);
    assert_eq!(proposal.state, EvidenceState::Succeeded);
    assert!(!proposal.response_truncated);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    proposal.validate_integrity().expect("proposal integrity");
    assert_eq!(
        service.provider().provenance(),
        TransportProvenance::Fixture
    );

    let consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("consume");
    assert_eq!(mission_result.disposition, ProposalDisposition::Succeeded);
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    let mut log = AwsCodePipelineRecordingLog::default();
    let first = consumer
        .record(&mut log, &proposal, "release-recording-1")
        .expect("record");
    let replay = consumer
        .record(&mut log, &proposal, "release-recording-1")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);
}

#[test]
fn opaque_sigv4_reference_never_crosses_registration_serialization() {
    let registration = registration(scope());
    let debug = format!("{registration:?}");
    let serialized = serde_json::to_string(&registration).expect("registration serializes");
    assert!(!debug.contains("opaque-sigv4-reference"));
    assert!(!serialized.contains("opaque-sigv4-reference"));
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains("secretMaterial"));
}

#[test]
fn execution_replacement_is_typed_and_fail_closed() {
    let expected = scope();
    let replacement = AwsCodePipelineScope::from_ids(
        "123456789012",
        1,
        "us-east-1",
        2,
        "release-pipeline",
        3,
        "execution-42",
        99,
        "Deploy",
        5,
        "Production",
        6,
        "mission-codepipeline-1",
        7,
        "project-codepipeline-1",
        8,
        "work-product-codepipeline-1",
        9,
    )
    .expect("replacement scope");
    let transport = FixtureAwsCodePipelineTransport::new(
        [Ok(PipelineStateResponse::for_scope(&replacement))],
        [Ok(PipelineStateResponse::for_scope(&expected))],
        [Ok(PipelineExecutionPage::for_scope(&expected))],
        [Ok(ActionExecutionPage::for_scope(&expected))],
    );
    let mut service = service(&expected, transport);
    let proposal = proposal(&mut service);
    assert_eq!(proposal.state, EvidenceState::ExecutionReplaced);
    assert!(proposal.evidence.failure.is_some());
    assert!(!proposal.evidence.connected);
}

#[test]
fn stage_and_action_transitions_are_typed_without_adopting_outcome() {
    let scope = scope();
    let previous = PipelineStateRecord::new(
        &scope,
        PipelineExecutionStatus::InProgress,
        hartevo_aws_codepipeline_release_result_plugin::StageExecutionStatus::InProgress,
        ActionExecutionStatus::InProgress,
        Vec::new(),
        None,
        OBSERVED_AT,
    )
    .expect("previous state");
    let current = PipelineStateRecord::new(
        &scope,
        PipelineExecutionStatus::Succeeded,
        hartevo_aws_codepipeline_release_result_plugin::StageExecutionStatus::Succeeded,
        ActionExecutionStatus::Succeeded,
        Vec::new(),
        None,
        OBSERVED_AT + 1,
    )
    .expect("current state");
    let transition = current.transition_from(&previous).expect("transition");
    assert_eq!(transition.kind, StageActionTransitionKind::ActionAdvanced);

    let mut service = service(&scope, FixtureAwsCodePipelineTransport::from_scope(&scope));
    let proposal = proposal(&mut service);
    assert!(!proposal.outcome_adopted);
    assert!(!proposal.work_product_adopted);
}

#[test]
fn stale_mission_revision_cannot_consume_a_proposal() {
    let expected = scope();
    let stale = AwsCodePipelineScope::from_ids(
        "123456789012",
        1,
        "us-east-1",
        2,
        "release-pipeline",
        3,
        "execution-42",
        4,
        "Deploy",
        5,
        "Production",
        6,
        "mission-codepipeline-1",
        8,
        "project-codepipeline-1",
        8,
        "work-product-codepipeline-1",
        9,
    )
    .expect("stale scope");
    let registration = registration(expected.clone());
    let result = MissionAwsCodePipelineConsumer::new(stale, registration);
    assert_eq!(
        result.expect_err("stale Mission accepted"),
        AwsCodePipelineReleaseError::ScopeMismatch
    );
}

#[test]
fn cursor_filter_mismatch_is_rejected_before_transport() {
    let scope = scope();
    let filter = PipelineExecutionFilter::for_scope(&scope);
    let action_filter = ActionExecutionFilter::for_scope(&scope);
    let cursor =
        Cursor::new("cursor-for-action-filter", action_filter.digest().clone()).expect("cursor");
    let mut provider =
        hartevo_aws_codepipeline_release_result_plugin::AwsCodePipelineProvider::new(
            registration(scope.clone()),
            FixtureAwsCodePipelineTransport::from_scope(&scope),
        )
        .expect("provider");
    assert_eq!(
        provider
            .list_pipeline_executions_page(filter, MAX_PAGE_SIZE, Some(cursor))
            .expect_err("cursor/filter mismatch accepted"),
        AwsCodePipelineReleaseError::CursorMismatch
    );
}

#[test]
fn bounded_truncation_is_partial_and_non_adoptable() {
    let scope = scope();
    let pipeline_filter = PipelineExecutionFilter::for_scope(&scope);
    let action_filter = ActionExecutionFilter::for_scope(&scope);
    let next_pipeline =
        Cursor::new("pipeline-next", pipeline_filter.digest().clone()).expect("pipeline cursor");
    let next_action =
        Cursor::new("action-next", action_filter.digest().clone()).expect("action cursor");
    let transport = FixtureAwsCodePipelineTransport::new(
        [Ok(PipelineStateResponse::for_scope(&scope))],
        [Ok(PipelineStateResponse::for_scope(&scope))],
        [Ok(PipelineExecutionPage::new(
            1,
            vec![PipelineExecutionRecord::for_scope(&scope)],
            Some(next_pipeline),
            512,
        )
        .expect("pipeline page"))],
        [Ok(ActionExecutionPage::new(
            1,
            vec![ActionExecutionRecord::for_scope(&scope)],
            Some(next_action),
            512,
        )
        .expect("action page"))],
    );
    let mut service = service(&scope, transport);
    let proposal = proposal(&mut service);
    assert_eq!(proposal.state, EvidenceState::Partial);
    assert!(proposal.response_truncated);
    assert!(!proposal.can_be_adopted());
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn page_tamper_is_not_converted_to_honest_provider_unknown() {
    let scope = scope();
    let mut page = PipelineExecutionPage::for_scope(&scope);
    page.page_digest =
        hartevo_aws_codepipeline_release_result_plugin::Digest::from_text("tampered");
    let transport = FixtureAwsCodePipelineTransport::new(
        [Ok(PipelineStateResponse::for_scope(&scope))],
        [Ok(PipelineStateResponse::for_scope(&scope))],
        [Ok(page)],
        [Ok(ActionExecutionPage::for_scope(&scope))],
    );
    let mut service = service(&scope, transport);
    let request = service.request(10, 1, OBSERVED_AT).expect("request");
    assert_eq!(
        service
            .propose(request)
            .expect_err("tampered page accepted"),
        AwsCodePipelineReleaseError::PageTampered
    );
}

#[test]
fn revocation_blocks_provider_reads_and_recording() {
    let scope = scope();
    let mut service = service(&scope, FixtureAwsCodePipelineTransport::from_scope(&scope));
    service.revoke().expect("revoke");
    let request = service
        .request(10, 1, OBSERVED_AT)
        .expect("request remains bound");
    assert_eq!(
        service
            .propose(request)
            .expect_err("revoked registration read"),
        AwsCodePipelineReleaseError::RegistrationInactive
    );

    let mut secret = SecretReference::sigv4("opaque-revoked", 1).expect("secret");
    secret.revoke();
    let revoked_registration = AwsCodePipelineRegistration::new(
        RegistrationId::new("registration-revoked-secret").expect("id"),
        scope.clone(),
        secret,
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "recording-r1").expect("provider"),
        1,
    )
    .expect("registration");
    let mut provider =
        hartevo_aws_codepipeline_release_result_plugin::AwsCodePipelineProvider::new(
            revoked_registration,
            FixtureAwsCodePipelineTransport::from_scope(&scope),
        )
        .expect("provider");
    assert_eq!(
        provider
            .get_pipeline_state()
            .expect_err("revoked secret read"),
        AwsCodePipelineReleaseError::SecretRevoked
    );
}

#[test]
fn typed_4xx_429_5xx_and_timeout_states_remain_bounded() {
    let cases = [
        (
            AwsCodePipelineTransportError::BadRequest,
            EvidenceState::Unknown,
        ),
        (
            AwsCodePipelineTransportError::Unauthorized,
            EvidenceState::AccessLoss,
        ),
        (
            AwsCodePipelineTransportError::Forbidden,
            EvidenceState::AccessLoss,
        ),
        (
            AwsCodePipelineTransportError::NotFound,
            EvidenceState::Unknown,
        ),
        (
            AwsCodePipelineTransportError::RateLimited {
                retry_after_seconds: Some(3),
            },
            EvidenceState::Retryable,
        ),
        (
            AwsCodePipelineTransportError::ServerError { status: 503 },
            EvidenceState::Retryable,
        ),
        (
            AwsCodePipelineTransportError::Timeout,
            EvidenceState::Retryable,
        ),
    ];
    for (error, expected_state) in cases {
        let scope = scope();
        let transport = FixtureAwsCodePipelineTransport::new(
            [Err(error)],
            [Ok(PipelineStateResponse::for_scope(&scope))],
            [Ok(PipelineExecutionPage::for_scope(&scope))],
            [Ok(ActionExecutionPage::for_scope(&scope))],
        );
        let mut service = service(&scope, transport);
        let proposal = proposal(&mut service);
        assert_eq!(proposal.state, expected_state);
        assert!(!proposal.connected);
        assert!(!proposal.native);
        if expected_state == EvidenceState::Retryable {
            assert_eq!(
                proposal.evidence.retry.state,
                hartevo_aws_codepipeline_release_result_plugin::RetryState::Retryable
            );
        }
    }
}

#[test]
fn artifact_and_error_metadata_are_digest_only() {
    let artifact = hartevo_aws_codepipeline_release_result_plugin::ArtifactMetadata::from_values(
        "release-output.zip",
        Some("revision-1"),
        Some("s3://private-bucket/raw-location"),
        Some(42),
    )
    .expect("artifact metadata");
    let error = hartevo_aws_codepipeline_release_result_plugin::ErrorMetadata::from_values(
        hartevo_aws_codepipeline_release_result_plugin::ErrorCategory::Server,
        Some(503),
        Some("private provider error body"),
    )
    .expect("error metadata");
    artifact.validate_integrity().expect("artifact integrity");
    error.validate_integrity().expect("error integrity");
    let encoded = serde_json::to_string(&(artifact, error)).expect("metadata serializes");
    assert!(!encoded.contains("raw-location"));
    assert!(!encoded.contains("private provider error body"));
    assert!(!encoded.contains("artifactContent"));
    assert!(!encoded.contains("errorMessage"));
    assert!(RedactionEvidence::standard().validate().is_ok());
}

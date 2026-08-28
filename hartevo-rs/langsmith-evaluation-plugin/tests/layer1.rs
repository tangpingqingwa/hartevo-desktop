use hartevo_langsmith_evaluation_plugin::{
    ConflictReason, DatasetRevisionSummary, Digest, EvaluationCursor, EvaluatorKind,
    EvaluatorRevisionSummary, EvidenceSource, EvidenceStatus, FeedbackId, FeedbackScore,
    LangSmithEvaluationError, LangSmithEvaluationPage, LangSmithEvaluationReadRequest,
    LangSmithEvaluationScope, LangSmithEvaluationService, LangSmithPermission,
    LangSmithPermissionSnapshot, LangSmithPluginRegistration, LangSmithProvider,
    LangSmithProviderError, MissionEvaluationRequest, MissionLangSmithEvaluationConsumer,
    NativeStatus, Revision, RunStatus, RunSummary, SecretKind, SecretReference, canonical_digest,
};
use serde_json::Value;

fn scope() -> LangSmithEvaluationScope {
    LangSmithEvaluationScope::fixture("mission-langsmith").expect("fixture scope")
}

fn service() -> (
    LangSmithEvaluationService,
    LangSmithProvider,
    LangSmithEvaluationScope,
) {
    let scope = scope();
    let provider = LangSmithProvider::recording(scope.clone()).expect("recording provider");
    let service = LangSmithEvaluationService::new(provider.clone()).expect("service");
    (service, provider, scope)
}

fn request(scope: &LangSmithEvaluationScope) -> LangSmithEvaluationReadRequest {
    LangSmithEvaluationReadRequest::new(scope.clone(), 25, 10_000).expect("read request")
}

fn page(
    scope: &LangSmithEvaluationScope,
    page_number: u16,
    status: EvidenceStatus,
    partial: bool,
    runs: Vec<RunSummary>,
    next_cursor: Option<EvaluationCursor>,
) -> LangSmithEvaluationPage {
    let fixture = LangSmithEvaluationPage::fixture(scope).expect("fixture page");
    LangSmithEvaluationPage::new(
        scope.digest().clone(),
        page_number,
        runs,
        fixture.traces,
        fixture.dataset,
        fixture.evaluator,
        fixture.feedback,
        fixture.experiment,
        fixture.comparison,
        status,
        partial,
        next_cursor,
        1_000,
    )
    .expect("page")
}

#[test]
fn checked_contract_is_layer_one_and_honest_about_authority() {
    let contract: Value = serde_json::from_str(
        hartevo_langsmith_evaluation_plugin::LANGSMITH_EVALUATION_CONTRACT_JSON,
    )
    .expect("contract JSON");
    assert_eq!(
        contract["contractVersion"],
        hartevo_langsmith_evaluation_plugin::LANGSMITH_EVALUATION_CONTRACT_VERSION
    );
    assert_eq!(contract["layer"], "Layer-1");
    assert_eq!(contract["provider"]["nativeStatus"], "BLOCKED_ENV");
    assert_eq!(contract["provider"]["connected"], false);
    assert_eq!(contract["provider"]["native"], false);
    assert_eq!(contract["authority"]["externalWrites"], false);
    assert_eq!(contract["authority"]["traceExport"], false);
    assert_eq!(contract["authority"]["toolExecution"], false);
    assert_eq!(contract["authority"]["genericTelemetry"], false);
    assert_eq!(contract["authority"]["modelRegistry"], false);
    assert_eq!(
        contract["contractDigest"],
        hartevo_langsmith_evaluation_plugin::LANGSMITH_EVALUATION_CONTRACT_DIGEST
    );
}

#[test]
fn exact_scope_registration_permission_and_secret_reference_are_bound() {
    let scope = scope();
    let registration = LangSmithPluginRegistration::fixture(scope.clone()).expect("registration");
    registration.validate().expect("registration validates");
    assert_eq!(registration.scope.digest(), scope.digest());
    assert!(registration.permission.is_read_only());
    assert!(
        registration
            .permission
            .allows(LangSmithPermission::ReadExperiments)
    );

    let secret = SecretReference::with_kind(
        SecretKind::ApiKey,
        "raw-langsmith-api-key-must-not-escape",
        scope.digest().clone(),
        Revision::fixture(),
    )
    .expect("opaque API-key reference");
    let debug = format!("{secret:?}");
    let json = serde_json::to_string(&secret).expect("secret JSON");
    assert!(!debug.contains("raw-langsmith-api-key-must-not-escape"));
    assert!(!json.contains("raw-langsmith-api-key-must-not-escape"));
    assert_eq!(secret.kind, SecretKind::ApiKey);
    assert_ne!(secret.reference_digest, Digest::from_text(""));

    let oauth = SecretReference::oauth("oauth-handle", scope.digest().clone(), Revision::fixture())
        .expect("opaque OAuth reference");
    assert_eq!(oauth.kind, SecretKind::OAuth);

    let reissued = registration
        .reissue(LangSmithPermissionSnapshot::read_only(Revision::fixture()).expect("permission"))
        .expect("reissue");
    assert!(reissued.active);
    assert_eq!(reissued.scope.digest(), registration.scope.digest());
}

#[test]
fn service_and_mission_consumer_emit_redacted_non_native_evidence() {
    let (service, provider, scope) = service();
    let capabilities = service.describe_capabilities().expect("capabilities");
    assert_eq!(capabilities.native_status, NativeStatus::BlockedEnv);
    assert_eq!(capabilities.source, EvidenceSource::Recording);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.external_writes);
    assert!(!capabilities.arbitrary_trace_export);

    let read_proposal = service
        .compile_bounded_read_proposal(scope.clone(), 25, Some(10_000))
        .expect("read proposal");
    read_proposal
        .validate(&service.registration(), service.policy())
        .expect("read proposal validates");

    let proposal = service
        .propose(request(&scope))
        .expect("evaluation proposal");
    service
        .verify_proposal(&proposal)
        .expect("proposal verifies");
    assert!(proposal.is_redacted());
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.adopted);
    assert!(!proposal.durable_native_receipt);
    assert!(proposal.can_claim_current);
    let proposal_json = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!proposal_json.contains("fixture-input"));
    assert!(!proposal_json.contains("fixture-output"));
    assert!(!proposal_json.contains("raw-prompt"));
    assert!(!proposal_json.contains("raw-output"));
    assert!(proposal_json.contains("input_digest"));
    assert!(proposal_json.contains("output_digest"));

    let receipt = service
        .receipt_candidate(&proposal)
        .expect("receipt candidate");
    assert!(!receipt.durable);
    assert!(!receipt.native);
    assert!(!receipt.connected);
    assert!(!receipt.external_write_performed);

    provider.set_page(LangSmithEvaluationPage::fixture(&scope).expect("consumer fixture"));
    let consumer = MissionLangSmithEvaluationConsumer::new(service);
    let mission_request = MissionEvaluationRequest::fixture(scope).expect("Mission request");
    let result = consumer.consume(&mission_request).expect("Mission result");
    result.validate().expect("Mission result validates");
    assert!(!result.adopted);
    assert!(!result.durable);
    assert_eq!(result.proposal.evidence.status, EvidenceStatus::Present);
    assert_eq!(
        provider.state(),
        hartevo_langsmith_evaluation_plugin::ProviderState::Ready
    );
}

#[test]
fn fixture_recording_fake_loopback_and_blocked_env_never_claim_native() {
    let scope = scope();
    let providers = [
        LangSmithProvider::fixture(scope.clone()).expect("fixture"),
        LangSmithProvider::recording(scope.clone()).expect("recording"),
        LangSmithProvider::fake(scope.clone()).expect("fake"),
        LangSmithProvider::loopback(scope.clone()).expect("loopback"),
    ];
    for provider in providers {
        let manifest = provider.provider_manifest();
        assert_eq!(manifest.native_status, NativeStatus::BlockedEnv);
        assert!(!manifest.connected);
        assert!(!manifest.native);
        assert!(!provider.native_transport());
        assert!(!provider.native_connected());
        assert!(!provider.external_write_available());
    }
    let blocked = LangSmithProvider::blocked_env(scope.clone()).expect("blocked env");
    let service = LangSmithEvaluationService::new(blocked).expect("blocked service");
    assert!(matches!(
        service
            .read_page(&request(&scope))
            .expect_err("BLOCKED_ENV"),
        LangSmithEvaluationError::Provider(LangSmithProviderError::BlockedEnv)
    ));
}

#[test]
fn pagination_is_bounded_and_cursor_scope_is_exact() {
    let (service, provider, scope) = service();
    let first_without_cursor = page(
        &scope,
        1,
        EvidenceStatus::Present,
        false,
        vec![RunSummary::fixture(&scope).expect("run")],
        None,
    );
    let cursor = EvaluationCursor::new(
        2,
        scope.digest().clone(),
        first_without_cursor.response_digest.clone(),
    )
    .expect("cursor");
    let first = first_without_cursor
        .with_next_cursor(Some(cursor.clone()))
        .expect("first page");
    first
        .validate(service.policy())
        .expect("first page validates");
    let second = page(
        &scope,
        2,
        EvidenceStatus::Present,
        false,
        vec![RunSummary::fixture(&scope).expect("run")],
        None,
    );
    provider.set_responses([Ok(first), Ok(second)]);
    let evidence = service.paginate(request(&scope)).expect("pagination");
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.runs.len(), 2);
    assert_eq!(evidence.status, EvidenceStatus::Present);

    let other_scope = LangSmithEvaluationScope::fixture("other-mission").expect("other scope");
    let other_cursor = EvaluationCursor::new(
        2,
        other_scope.digest().clone(),
        Digest::from_text("previous"),
    )
    .expect("other cursor");
    assert_eq!(
        request(&scope)
            .next_page(other_cursor)
            .expect_err("cross-scope cursor")
            .to_string(),
        LangSmithEvaluationError::CursorMismatch.to_string()
    );
}

#[test]
fn run_status_partial_empty_and_experiment_evidence_are_typed() {
    let (service, provider, scope) = service();
    let run = RunSummary::new(
        scope.run.clone(),
        scope.trace.clone(),
        scope.project.clone(),
        scope.project_revision.clone(),
        scope.model_digest.clone(),
        RunStatus::Error,
        Some(Digest::from_text("provider-error")),
        None,
        None,
        None,
        None,
        None,
    )
    .expect("error run");
    let partial = page(&scope, 1, EvidenceStatus::Partial, true, vec![run], None);
    provider.set_page(partial);
    let evidence = service.paginate(request(&scope)).expect("partial evidence");
    assert_eq!(evidence.status, EvidenceStatus::Partial);
    assert!(evidence.partial);
    assert_eq!(evidence.runs[0].status, RunStatus::Error);
    assert!(evidence.runs[0].error_digest.is_some());
    assert_eq!(evidence.experiment.run_count, 1);

    let fixture = LangSmithEvaluationPage::fixture(&scope).expect("fixture");
    let empty = LangSmithEvaluationPage::new(
        scope.digest().clone(),
        1,
        Vec::new(),
        Vec::new(),
        fixture.dataset,
        fixture.evaluator,
        Vec::new(),
        fixture.experiment,
        None,
        EvidenceStatus::Empty,
        false,
        None,
        1_000,
    )
    .expect("empty page");
    provider.set_page(empty);
    let empty_evidence = service.paginate(request(&scope)).expect("empty evidence");
    assert_eq!(empty_evidence.status, EvidenceStatus::Empty);
    assert!(empty_evidence.runs.is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn dataset_evaluator_tamper_redaction_and_stale_results_fail_closed() {
    let (service, provider, scope) = service();
    let fixture = LangSmithEvaluationPage::fixture(&scope).expect("fixture");
    let drifted_dataset = DatasetRevisionSummary::new(
        scope.dataset.clone(),
        Revision::new("v2").expect("revision"),
        fixture.dataset.example_count,
        fixture.dataset.schema_digest.clone(),
        fixture.dataset.input_fields_digest.clone(),
        fixture.dataset.output_fields_digest.clone(),
    )
    .expect("drifted dataset");
    let dataset_drift = LangSmithEvaluationPage::new(
        scope.digest().clone(),
        1,
        fixture.runs.clone(),
        fixture.traces.clone(),
        drifted_dataset,
        fixture.evaluator.clone(),
        fixture.feedback.clone(),
        fixture.experiment.clone(),
        None,
        EvidenceStatus::Present,
        false,
        None,
        1_000,
    )
    .expect("dataset drift page");
    provider.set_page(dataset_drift);
    assert_eq!(
        service
            .read_page(&request(&scope))
            .expect_err("dataset drift")
            .to_string(),
        LangSmithEvaluationError::DatasetRevisionDrift.to_string()
    );

    let evaluator = EvaluatorRevisionSummary::new(
        scope.evaluator.clone(),
        Revision::new("v2").expect("revision"),
        EvaluatorKind::Code,
        hartevo_langsmith_evaluation_plugin::ScoreBounds::new(0.0, 1.0).expect("bounds"),
        Digest::from_text("criteria"),
    )
    .expect("drifted evaluator");
    let evaluator_drift = LangSmithEvaluationPage::new(
        scope.digest().clone(),
        1,
        fixture.runs.clone(),
        fixture.traces.clone(),
        fixture.dataset.clone(),
        evaluator,
        fixture.feedback.clone(),
        fixture.experiment,
        None,
        EvidenceStatus::Present,
        false,
        None,
        1_000,
    )
    .expect("evaluator drift page");
    provider.set_page(evaluator_drift);
    assert_eq!(
        service
            .read_page(&request(&scope))
            .expect_err("evaluator drift")
            .to_string(),
        LangSmithEvaluationError::EvaluatorMismatch.to_string()
    );

    let mut tampered = LangSmithEvaluationPage::fixture(&scope).expect("fixture");
    tampered.response_digest = Digest::from_text("tampered-response");
    provider.set_page(tampered);
    assert_eq!(
        service
            .read_page(&request(&scope))
            .expect_err("tampered response")
            .to_string(),
        LangSmithEvaluationError::ResponseTampered.to_string()
    );

    assert_eq!(
        FeedbackScore::new(
            FeedbackId::new("feedback-bad").expect("feedback"),
            scope.run.clone(),
            scope.trace.clone(),
            scope.evaluator.clone(),
            scope.evaluator_revision.clone(),
            1.01,
        )
        .expect_err("out-of-range score")
        .to_string(),
        LangSmithEvaluationError::FeedbackScoreOutOfBounds.to_string()
    );

    let stale = LangSmithEvaluationPage::fixture(&scope).expect("fixture");
    provider.set_page(stale);
    let stale_request =
        LangSmithEvaluationReadRequest::new(scope.clone(), 25, 100_000_000).expect("stale request");
    assert_eq!(
        service
            .read_page(&stale_request)
            .expect_err("stale result")
            .to_string(),
        LangSmithEvaluationError::StaleResult.to_string()
    );
}

#[test]
fn provider_http_errors_timeout_access_loss_and_revocation_are_typed() {
    let (service, provider, scope) = service();
    let statuses = [
        (LangSmithProviderError::Unauthorized401, 401),
        (LangSmithProviderError::Forbidden403, 403),
        (LangSmithProviderError::NotFound404, 404),
        (
            LangSmithProviderError::Conflict409 {
                reason: ConflictReason::DatasetRevisionDrift,
            },
            409,
        ),
        (
            LangSmithProviderError::RateLimited429 {
                retry_after_seconds: Some(5),
            },
            429,
        ),
        (LangSmithProviderError::Server5xx { status: 503 }, 503),
    ];
    for (error, status) in statuses {
        assert_eq!(error.status_code(), Some(status));
        provider.set_error(error.clone());
        let observed = service
            .read_page(&request(&scope))
            .expect_err("provider error");
        assert!(observed.to_string().contains(&status.to_string()));
    }
    provider.set_error(LangSmithProviderError::Timeout);
    assert!(service.read_page(&request(&scope)).is_err());
    provider.set_error(LangSmithProviderError::AccessLoss);
    assert!(service.read_page(&request(&scope)).is_err());
    assert!(LangSmithProviderError::AccessLoss.is_access_loss());

    service.revoke("test revocation").expect("revoke");
    assert_eq!(
        service
            .read_page(&request(&scope))
            .expect_err("revoked registration")
            .to_string(),
        LangSmithEvaluationError::RegistrationRevoked.to_string()
    );
}

#[test]
fn digest_helpers_are_canonical_and_scope_changes_are_visible() {
    let first = scope();
    let second = first
        .clone()
        .with_model_digest(Digest::from_text("model-revision"))
        .expect("model binding");
    assert_ne!(first.digest(), second.digest());
    assert_ne!(canonical_digest(&first), *first.digest());
}

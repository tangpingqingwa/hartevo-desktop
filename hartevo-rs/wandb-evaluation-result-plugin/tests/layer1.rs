use hartevo_wandb_evaluation_result_plugin::{
    ConflictReason, Digest, EvidenceSource, EvidenceStatus, MissionWandbEvaluationConsumer,
    MissionWandbEvaluationRequest, NativeStatus, ProviderState, Revision, RunState,
    SecretReference, WANDB_EVALUATION_RESULT_CONTRACT_JSON,
    WANDB_EVALUATION_RESULT_CONTRACT_VERSION, WANDB_EVALUATION_RESULT_SCHEMA_VERSION,
    WandbEvaluationError, WandbEvaluationPage, WandbEvaluationPolicy, WandbEvaluationReadRequest,
    WandbEvaluationResultService, WandbEvaluationScope, WandbProvider, WandbProviderError,
    canonical_digest,
};

fn scope() -> WandbEvaluationScope {
    WandbEvaluationScope::fixture("mission-wandb-406").expect("fixture scope")
}

fn make_service() -> (
    WandbEvaluationResultService,
    WandbProvider,
    WandbEvaluationScope,
) {
    let scope = scope();
    let provider = WandbProvider::fixture(scope.clone()).expect("fixture provider");
    let service = WandbEvaluationResultService::new(provider.clone()).expect("service");
    (service, provider, scope)
}

fn request(scope: &WandbEvaluationScope) -> WandbEvaluationReadRequest {
    WandbEvaluationReadRequest::fixture(scope.clone()).expect("read request")
}

#[test]
fn contract_scope_and_registration_pin_all_wandb_and_hartevo_dimensions() {
    let scope = scope();
    assert!(scope.digest().is_sha256());
    assert!(scope.api_digest.is_sha256());
    assert!(scope.permission_digest.is_sha256());
    assert!(scope.revision_digest.is_sha256());
    assert!(scope.metric_digest.is_sha256());
    assert!(scope.config.digest.is_sha256());
    assert!(scope.artifact_digest.is_sha256());
    assert!(scope.commit.digest.is_sha256());
    assert_eq!(scope.metric_allowlist.len(), 2);
    assert_eq!(scope.artifact_allowlist.len(), 1);

    let provider = WandbProvider::fixture(scope.clone()).expect("provider");
    let registration = provider.registration();
    assert!(registration.active);
    assert!(registration.reversible);
    assert!(registration.revocable);
    assert!(registration.provider_digest.is_sha256());
    assert!(registration.api_digest.is_sha256());
    assert!(registration.permission_digest.is_sha256());
    assert!(registration.scope_digest.is_sha256());
    assert!(registration.revision_digest.is_sha256());
    assert!(registration.metric_digest.is_sha256());
    assert!(registration.registration_digest.is_sha256());

    let contract: serde_json::Value =
        serde_json::from_str(WANDB_EVALUATION_RESULT_CONTRACT_JSON).expect("contract");
    assert_eq!(
        contract["schemaVersion"],
        WANDB_EVALUATION_RESULT_SCHEMA_VERSION
    );
    assert_eq!(
        contract["contractVersion"],
        WANDB_EVALUATION_RESULT_CONTRACT_VERSION
    );
    assert_eq!(contract["scope"]["oneRunOnly"], true);
    assert_eq!(contract["provider"]["nativeStatus"], "BLOCKED_ENV");
    assert_eq!(contract["provider"]["connected"], false);
    assert_eq!(contract["authentication"]["serialized"], false);
}

#[test]
fn opaque_api_token_reference_never_exposes_the_host_handle() {
    let scope = scope();
    let secret = SecretReference::api_token(
        "raw-wandb-api-token-must-not-escape",
        scope.digest().clone(),
        scope.permission_revision.clone(),
    )
    .expect("secret reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("raw-wandb-api-token-must-not-escape"));
    assert_eq!(
        secret.kind(),
        hartevo_wandb_evaluation_result_plugin::SecretKind::ApiToken
    );
    assert!(secret.reference_digest().is_sha256());
    assert!(secret.scope_digest().is_sha256());
    assert_eq!(secret.revision(), &scope.permission_revision);
}

#[test]
fn fixture_recording_loopback_and_blocked_env_never_claim_connected_or_native() {
    let scope = scope();
    let providers = [
        WandbProvider::fixture(scope.clone()).expect("fixture"),
        WandbProvider::recording(scope.clone()).expect("recording"),
        WandbProvider::loopback(scope.clone()).expect("loopback"),
    ];
    for provider in providers {
        let service = WandbEvaluationResultService::new(provider.clone()).expect("service");
        let capabilities = service.describe_capabilities().expect("capabilities");
        assert_eq!(capabilities.native_status, NativeStatus::BlockedEnv);
        assert!(!capabilities.source.native());
        assert!(!capabilities.connected);
        assert!(!capabilities.native);
        assert!(!capabilities.external_writes);
        assert!(!capabilities.metric_writes);
        assert!(!capabilities.artifact_upload);
        assert!(!capabilities.artifact_download);
        assert!(!provider.native_transport());
        assert!(!provider.native_connected());
        assert!(!provider.external_write_available());
    }

    let blocked = WandbProvider::blocked_env(scope.clone()).expect("blocked env provider");
    assert_eq!(blocked.state(), ProviderState::BlockedEnv);
    let blocked_service = WandbEvaluationResultService::new(blocked).expect("blocked service");
    assert!(matches!(
        blocked_service.read_page(&request(&scope)),
        Err(WandbEvaluationError::Provider(
            WandbProviderError::BlockedEnv
        ))
    ));
}

#[test]
fn bounded_read_projects_metrics_history_state_timestamps_and_metadata_only_artifacts() {
    let (service, provider, scope) = make_service();
    let proposal = service
        .compile_bounded_read_proposal(scope.clone(), 25, Some(10_000))
        .expect("read proposal");
    proposal
        .validate(&service.registration(), service.policy())
        .expect("proposal validates");

    let page = service.read_page(&request(&scope)).expect("bounded page");
    assert_eq!(page.status, EvidenceStatus::Present);
    assert_eq!(page.run.state, RunState::Finished);
    assert_eq!(page.run.timestamps.finished_at_ms, Some(1_250));
    assert_eq!(page.run.summary_metrics.len(), 2);
    assert_eq!(page.run.sampled_history.len(), 2);
    assert_eq!(page.run.artifacts.len(), 1);
    assert!(page.run.artifacts[0].metadata_only);
    assert!(page.run.artifacts[0].digest.is_sha256());
    let json = serde_json::to_string(&page).expect("page JSON");
    assert!(!json.contains("fixture-artifact-bytes"));
    assert!(!json.contains("raw-history"));
    assert!(json.contains("sampled_history"));
    assert_eq!(provider.calls().len(), 1);
}

#[test]
fn result_proposal_and_mission_consumer_are_redacted_and_proposal_only() {
    let (service, provider, scope) = make_service();
    let read = request(&scope);
    let result = service.propose(read.clone()).expect("result proposal");
    service.verify_proposal(&result).expect("proposal verifies");
    assert!(result.evidence.is_redacted());
    assert!(!result.evidence.connected);
    assert!(!result.evidence.native);
    assert!(!result.evidence.adopted);
    assert!(result.evidence.can_claim_current());
    let json = serde_json::to_string(&result).expect("proposal JSON");
    assert!(!json.contains("raw-wandb-api-token"));
    assert!(!json.contains("artifact-bytes"));
    assert!(json.contains("metric_digest"));
    assert!(json.contains("sampled_history"));

    let receipt = service.receipt_candidate(&result).expect("candidate");
    assert!(!receipt.durable);
    assert!(!receipt.native);
    assert!(!receipt.connected);
    assert!(!receipt.external_write_performed);

    provider.set_page(WandbEvaluationPage::fixture(&scope).expect("consumer fixture"));
    let consumer = MissionWandbEvaluationConsumer::new(service);
    let mission_request =
        MissionWandbEvaluationRequest::new(read, &scope).expect("mission request");
    let mission_result = consumer.consume(&mission_request).expect("mission result");
    assert!(mission_result.proposal_only());
    assert!(!mission_result.connected());
    assert!(!mission_result.native());
    assert!(!mission_result.adopted);
    assert!(!mission_result.durable_native_receipt);
    assert_eq!(mission_result.status, EvidenceStatus::Present);
}

#[test]
fn page_history_and_response_byte_caps_fail_closed() {
    let (service, _provider, scope) = make_service();
    let too_many_history = WandbEvaluationReadRequest::new(
        scope.clone(),
        1,
        1,
        hartevo_wandb_evaluation_result_plugin::MAX_RESPONSE_BYTES,
        10_000,
    )
    .expect("request with small history cap");
    assert!(matches!(
        service.read_page(&too_many_history),
        Err(WandbEvaluationError::Provider(
            WandbProviderError::InvalidResponse
        ))
    ));

    let (service, _provider, scope) = make_service();
    let too_small_bytes = WandbEvaluationReadRequest::new(scope, 1, 64, 128, 10_000)
        .expect("request with small byte cap");
    assert!(matches!(
        service.read_page(&too_small_bytes),
        Err(WandbEvaluationError::Provider(
            WandbProviderError::InvalidResponse
        ))
    ));
}

#[test]
fn stale_tampered_revision_and_access_loss_fences_are_typed() {
    let (service, _provider, scope) = make_service();
    let stale = WandbEvaluationReadRequest::new(
        scope.clone(),
        1,
        64,
        hartevo_wandb_evaluation_result_plugin::MAX_RESPONSE_BYTES,
        100_000_000,
    )
    .expect("stale request");
    assert_eq!(
        service
            .read_page(&stale)
            .expect_err("stale result")
            .to_string(),
        WandbEvaluationError::StaleResult.to_string()
    );

    let (service, provider, scope) = make_service();
    let mut tampered = WandbEvaluationPage::fixture(&scope).expect("page");
    tampered.response_digest = Digest::from_text("tampered-response");
    provider.set_responses([Ok(tampered)]);
    assert_eq!(
        service
            .read_page(&request(&scope))
            .expect_err("tampered response")
            .to_string(),
        WandbEvaluationError::ResponseTampered.to_string()
    );

    let (service, provider, scope) = make_service();
    provider.set_responses([Err(WandbProviderError::Conflict409 {
        reason: ConflictReason::RevisionDrift,
    })]);
    assert_eq!(
        service
            .read_page(&request(&scope))
            .expect_err("revision drift")
            .to_string(),
        "a provider error occurred: W&B returned HTTP 409 (RevisionDrift)"
    );
    provider.set_error(WandbProviderError::AccessLoss);
    assert!(service.read_page(&request(&scope)).is_err());
    assert!(WandbProviderError::AccessLoss.is_access_loss());
}

#[test]
fn registration_revocation_is_reversible_and_does_not_claim_native() {
    let (service, _provider, scope) = make_service();
    let original = service.registration().registration_digest.clone();
    let revocation = service.revoke("test revocation").expect("revoke");
    assert_eq!(revocation.previous_registration_digest, original);
    assert!(revocation.reversible);
    assert!(!service.is_active());
    assert_eq!(
        service
            .read_page(&request(&scope))
            .expect_err("revoked")
            .to_string(),
        WandbEvaluationError::RegistrationRevoked.to_string()
    );
    service.restore().expect("restore");
    assert!(service.is_active());
    let evidence = service
        .propose(request(&scope))
        .expect("proposal after restore");
    assert!(!evidence.evidence.native);
    assert!(!evidence.evidence.connected);
}

#[test]
fn digest_helpers_are_deterministic_and_scope_changes_are_visible() {
    let first = scope();
    let second = first
        .clone()
        .with_metric_allowlist(vec![
            hartevo_wandb_evaluation_result_plugin::MetricBinding::fixture("accuracy-2")
                .expect("metric"),
        ])
        .expect("changed scope");
    assert_ne!(first.digest(), second.digest());
    assert_ne!(canonical_digest(&first), *first.digest());
    assert_eq!(Digest::from_text("same"), Digest::from_text("same"));
    assert!(Revision::new("revision-2").expect("revision").as_str() == "revision-2");
}

#[test]
fn provider_http_status_projection_is_bounded() {
    let statuses = [
        (WandbProviderError::Unauthorized401, 401),
        (WandbProviderError::Forbidden403, 403),
        (WandbProviderError::NotFound404, 404),
        (
            WandbProviderError::Conflict409 {
                reason: ConflictReason::MetricDrift,
            },
            409,
        ),
        (
            WandbProviderError::RateLimited429 {
                retry_after_seconds: Some(5),
            },
            429,
        ),
        (WandbProviderError::Server5xx { status: 503 }, 503),
    ];
    for (error, status) in statuses {
        assert_eq!(error.status_code(), Some(status));
    }
    assert_eq!(WandbEvaluationPolicy::fixture().max_pages, 1);
    assert!(!EvidenceSource::BlockedEnv.connected());
}

use super::*;

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn scope_with(
    expected_status: StatusExpectation,
    output_url_expiry: OutputUrlExpiryScope,
) -> ReplicateScope {
    let model = ModelBinding::new(
        ModelTarget::version(
            ModelId::new("owner/model").expect("model"),
            ModelVersion::new("version-001").expect("version"),
        ),
        digest("model-digest"),
    )
    .expect("model binding");
    let prediction = PredictionScope::new(
        PredictionId::new("prediction-1").expect("prediction"),
        model,
        expected_status,
        MetricScope::new(
            Revision::new(1).expect("metric revision"),
            Some(5_000),
            Some(10_000),
        )
        .expect("metric scope"),
        output_url_expiry,
    );
    ReplicateScope::new(
        ApiHost::official(),
        AccountId::new("account-1").expect("account"),
        prediction,
        ProjectScope::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(2).expect("project revision"),
        ),
        MissionScope::new(
            MissionId::new("mission-1").expect("mission"),
            Revision::new(3).expect("mission revision"),
        ),
        WorkProductScope::new(
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(4).expect("work product revision"),
        ),
        PermissionScope::read_only_default(Revision::new(5).expect("permission revision"))
            .expect("permissions"),
        Revision::new(6).expect("scope revision"),
    )
}

fn default_scope() -> ReplicateScope {
    scope_with(
        StatusExpectation::Any,
        OutputUrlExpiryScope::new(false, None, 3_600, None).expect("output scope"),
    )
}

fn record(
    scope: &ReplicateScope,
    status: ProviderPredictionStatus,
    output: OutputEvidence,
    partial: bool,
) -> ReplicatePredictionRecord {
    ReplicatePredictionRecord::new(
        scope.account_id().clone(),
        scope.prediction().prediction_id().clone(),
        scope.prediction().model().clone(),
        status,
        RuntimeMetrics::new(Some(100), Some(200)).expect("metrics"),
        output,
        Timestamp::new(1_000),
        partial,
    )
}

fn service_with<T: ReplicateTransport>(
    scope: ReplicateScope,
    transport: T,
) -> (SecretReference, ReplicatePredictionResultService<T>) {
    let secret = SecretReference::new(
        "opaque-api-token-reference",
        &scope,
        Revision::new(7).expect("credential revision"),
    )
    .expect("secret reference");
    let service =
        ReplicatePredictionResultService::new(scope, secret.clone(), transport).expect("service");
    (secret, service)
}

#[test]
fn exact_scope_proposal_and_mission_result_are_read_only() {
    let scope = default_scope();
    let prediction = record(
        &scope,
        ProviderPredictionStatus::Succeeded,
        OutputEvidence::empty(false),
        false,
    );
    let transport = RecordingReplicateTransport::recording([Ok(prediction)]);
    let (_secret, mut service) = service_with(scope.clone(), transport);
    assert!(service.registration().verify_digest());
    assert_eq!(service.definition().service_id, SERVICE_ID);
    assert!(service.definition().read_only);
    assert!(service.definition().proposal_only);
    assert!(service.definition().recording_only);
    assert!(!service.definition().external_writes);
    assert!(!service.definition().kernel_authority);
    assert!(!service.definition().outcome_adoption);

    let proposal = service.get_prediction().expect("proposal");
    assert!(proposal.verify_digest());
    assert_eq!(proposal.status(), PredictionStatus::Succeeded);
    assert_eq!(proposal.evidence.account_id, *scope.account_id());
    assert_eq!(
        proposal.evidence.prediction_id,
        *scope.prediction().prediction_id()
    );
    assert_eq!(proposal.evidence.scope_digest, *scope.scope_digest());
    assert_eq!(proposal.evidence.revision_digest, *scope.revision_digest());
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.is_non_adoptable());

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert!(!serialized.contains("opaque-api-token-reference"));
    assert!(!serialized.contains("replicate.delivery"));

    let mut consumer = MissionReplicateResultConsumer::from_registration(service.registration())
        .expect("Mission consumer");
    let mission_result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(mission_result.project_id, *scope.project().project_id());
    assert_eq!(
        mission_result.project_revision,
        scope.project().project_revision()
    );
    assert_eq!(mission_result.mission_id, *scope.mission().mission_id());
    assert_eq!(
        mission_result.mission_revision,
        scope.mission().mission_revision()
    );
    assert_eq!(
        mission_result.work_product_id,
        *scope.work_product().work_product_id()
    );
    assert_eq!(
        mission_result.work_product_revision,
        scope.work_product().work_product_revision()
    );
    assert_eq!(mission_result.state, MissionResultState::PendingDecision);
    assert_eq!(
        mission_result.adoption,
        AdoptionAvailability::NotAdoptedLayer2
    );
    assert!(!mission_result.is_adopted());
    assert!(!mission_result.connected());
    assert!(!mission_result.native());
    assert!(!mission_result.durable_adoption);
    assert!(!mission_result.kernel_authority);
}

#[test]
fn all_recording_provenances_and_blocked_env_are_never_connected_or_native() {
    let scope = default_scope();
    let success = record(
        &scope,
        ProviderPredictionStatus::Succeeded,
        OutputEvidence::empty(false),
        false,
    );
    for transport in [
        RecordingReplicateTransport::fixture([Ok(success.clone())]),
        RecordingReplicateTransport::recording([Ok(success.clone())]),
        RecordingReplicateTransport::loopback([Ok(success.clone())]),
    ] {
        let (_secret, mut service) = service_with(scope.clone(), transport);
        let proposal = service.get_prediction().expect("recorded proposal");
        assert!(!proposal.evidence.connected);
        assert!(!proposal.evidence.native);
        assert!(!proposal.evidence.provider_provenance.is_connected());
        assert!(!proposal.evidence.provider_provenance.is_native());
    }

    let (_secret, mut blocked) = service_with(scope, BlockedEnvTransport);
    let proposal = blocked.get_prediction().expect("blocked proposal");
    assert_eq!(proposal.status(), PredictionStatus::ProviderUnknown);
    assert_eq!(
        proposal.evidence.provider_provenance,
        ProviderProvenance::BlockedEnv
    );
    assert_eq!(
        proposal.evidence.errors[0].kind,
        ProviderErrorKind::BlockedEnv
    );
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
}

#[test]
fn status_monotonicity_accepts_lifecycle_and_rejects_regression() {
    let scope = default_scope();
    let start = record(
        &scope,
        ProviderPredictionStatus::Starting,
        OutputEvidence::empty(false),
        false,
    );
    let processing = record(
        &scope,
        ProviderPredictionStatus::Processing,
        OutputEvidence::empty(false),
        false,
    );
    let succeeded = record(
        &scope,
        ProviderPredictionStatus::Succeeded,
        OutputEvidence::empty(false),
        false,
    );
    let regression = record(
        &scope,
        ProviderPredictionStatus::Processing,
        OutputEvidence::empty(false),
        false,
    );
    let transport = RecordingReplicateTransport::recording([
        Ok(start),
        Ok(processing),
        Ok(succeeded),
        Ok(regression),
    ]);
    let (_secret, mut service) = service_with(scope, transport);
    assert_eq!(
        service.get_prediction().expect("starting").status(),
        PredictionStatus::Starting
    );
    assert_eq!(
        service.get_prediction().expect("processing").status(),
        PredictionStatus::Processing
    );
    assert_eq!(
        service.get_prediction().expect("succeeded").status(),
        PredictionStatus::Succeeded
    );
    let regression = service.get_prediction().expect("recorded unknown proposal");
    assert_eq!(regression.status(), PredictionStatus::ProviderUnknown);
    assert_eq!(
        regression.evidence.errors[0].kind,
        ProviderErrorKind::StatusDrift
    );
}

#[test]
fn data_removed_and_expired_output_are_flagged_without_download() {
    let expired_scope = scope_with(
        StatusExpectation::Any,
        OutputUrlExpiryScope::new(true, None, 3_600, None).expect("expiry scope"),
    );
    let expired_url = OutputUrlEvidence::from_url(
        "https://replicate.delivery/private/output",
        Some(Timestamp::new(900)),
        Timestamp::new(1_000),
    )
    .expect("expired URL");
    let expired = record(
        &expired_scope,
        ProviderPredictionStatus::Succeeded,
        OutputEvidence::new(None, vec![expired_url], false).expect("output"),
        false,
    );
    let removed = record(
        &expired_scope,
        ProviderPredictionStatus::Succeeded,
        OutputEvidence::new(None, Vec::new(), true).expect("removed output"),
        false,
    );
    let transport = RecordingReplicateTransport::recording([Ok(expired), Ok(removed)]);
    let (_secret, mut service) = service_with(expired_scope.clone(), transport);
    let expired_proposal = service.get_prediction().expect("expired proposal");
    assert_eq!(expired_proposal.status(), PredictionStatus::Succeeded);
    assert!(expired_proposal.evidence.output.url_expired);
    assert!(expired_proposal.is_non_adoptable());
    let removed_proposal = service.get_prediction().expect("removed proposal");
    assert_eq!(removed_proposal.status(), PredictionStatus::DataRemoved);
    assert!(removed_proposal.evidence.output.data_removed);
    assert!(removed_proposal.is_non_adoptable());

    let mut consumer = MissionReplicateResultConsumer::from_registration(service.registration())
        .expect("consumer");
    assert_eq!(
        consumer
            .consume(&expired_proposal)
            .expect("expired result")
            .state,
        MissionResultState::Layer2AdoptionRequired
    );
    assert_eq!(
        consumer
            .consume(&removed_proposal)
            .expect("removed result")
            .state,
        MissionResultState::Layer2AdoptionRequired
    );
}

#[test]
fn model_version_and_output_content_digest_drift_fail_closed() {
    let expected_content = digest("expected-output-content");
    let scope = scope_with(
        StatusExpectation::Exact {
            status: PredictionStatus::Succeeded,
        },
        OutputUrlExpiryScope::new(false, None, 3_600, Some(expected_content.clone()))
            .expect("output scope"),
    );
    let wrong_content = record(
        &scope,
        ProviderPredictionStatus::Succeeded,
        OutputEvidence::new(Some(digest("different-output-content")), Vec::new(), false)
            .expect("output"),
        false,
    );
    let (_secret, mut service) = service_with(
        scope.clone(),
        RecordingReplicateTransport::recording([Ok(wrong_content)]),
    );
    let proposal = service.get_prediction().expect("digest drift proposal");
    assert_eq!(proposal.status(), PredictionStatus::ProviderUnknown);
    assert_eq!(
        proposal.evidence.errors[0].kind,
        ProviderErrorKind::OutputContentDigestMismatch
    );

    let alternate_model = ModelBinding::new(
        ModelTarget::version(
            ModelId::new("owner/other-model").expect("model"),
            ModelVersion::new("version-001").expect("version"),
        ),
        digest("other-model-digest"),
    )
    .expect("alternate model");
    let model_drift = ReplicatePredictionRecord::new(
        scope.account_id().clone(),
        scope.prediction().prediction_id().clone(),
        alternate_model,
        ProviderPredictionStatus::Succeeded,
        RuntimeMetrics::new(Some(100), Some(200)).expect("metrics"),
        OutputEvidence::new(Some(expected_content), Vec::new(), false).expect("output"),
        Timestamp::new(1_000),
        false,
    );
    let (_secret, mut service) = service_with(
        scope,
        RecordingReplicateTransport::recording([Ok(model_drift)]),
    );
    let proposal = service.get_prediction().expect("model drift proposal");
    assert_eq!(proposal.status(), PredictionStatus::ProviderUnknown);
    assert_eq!(
        proposal.evidence.errors[0].kind,
        ProviderErrorKind::ModelDrift
    );
}

#[test]
fn http_errors_are_typed_redacted_and_retryable_errors_record_backoff() {
    let statuses = [
        (401, ProviderErrorKind::Unauthorized),
        (403, ProviderErrorKind::Forbidden),
        (404, ProviderErrorKind::NotFound),
        (409, ProviderErrorKind::Conflict),
        (429, ProviderErrorKind::RateLimited),
    ];
    for (status_code, kind) in statuses {
        let policy = RetryPolicy::new(1, 1, 1).expect("one-attempt policy");
        let scope = default_scope();
        let secret = SecretReference::new(
            "another-opaque-reference",
            &scope,
            Revision::new(8).expect("revision"),
        )
        .expect("secret");
        let transport = RecordingReplicateTransport::recording([Err(TransportError::http(
            status_code,
            None,
            "Bearer r8_secret_token_must_not_escape",
        ))]);
        let mut service =
            ReplicatePredictionResultService::with_retry_policy(scope, secret, transport, policy)
                .expect("service");
        let proposal = service.get_prediction().expect("error proposal");
        assert_eq!(proposal.status(), PredictionStatus::ProviderUnknown);
        assert_eq!(proposal.evidence.errors[0].kind, kind);
        assert_eq!(proposal.evidence.errors[0].status_code, Some(status_code));
        assert_eq!(
            proposal.evidence.errors[0].message,
            "REDACTED_PROVIDER_ERROR"
        );
        assert!(!proposal.evidence.errors[0].message.contains("secret_token"));
        let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
        assert!(!serialized.contains("r8_secret_token_must_not_escape"));
    }

    let scope = default_scope();
    let success = record(
        &scope,
        ProviderPredictionStatus::Succeeded,
        OutputEvidence::empty(false),
        false,
    );
    let transport = RecordingReplicateTransport::recording([
        Err(TransportError::http(429, Some(10), "rate limit")),
        Err(TransportError::timeout("upstream timeout")),
        Ok(success),
    ]);
    let (_secret, mut service) = service_with(scope, transport);
    let proposal = service.get_prediction().expect("retried proposal");
    assert_eq!(proposal.status(), PredictionStatus::Succeeded);
    assert_eq!(proposal.evidence.retries.len(), 2);
    assert_eq!(
        proposal.evidence.retries[0].kind,
        ProviderErrorKind::RateLimited
    );
    assert_eq!(
        proposal.evidence.retries[1].kind,
        ProviderErrorKind::Timeout
    );
    assert!(
        proposal
            .evidence
            .retries
            .iter()
            .all(|retry| retry.backoff_millis > 0)
    );

    let scope = default_scope();
    let transport = RecordingReplicateTransport::recording([Err(TransportError::http(
        503,
        None,
        "server failed",
    ))]);
    let secret = SecretReference::new(
        "server-error-reference",
        &scope,
        Revision::new(9).expect("revision"),
    )
    .expect("secret");
    let mut service = ReplicatePredictionResultService::with_retry_policy(
        scope,
        secret,
        transport,
        RetryPolicy::new(1, 1, 1).expect("one attempt"),
    )
    .expect("service");
    let proposal = service.get_prediction().expect("server error proposal");
    assert_eq!(
        proposal.evidence.errors[0].kind,
        ProviderErrorKind::ServerError
    );
}

#[test]
fn malformed_and_partial_responses_are_provider_unknown() {
    for transport_error in [
        TransportError::malformed("raw prompt must not be retained"),
        TransportError::partial("raw logs must not be retained"),
    ] {
        let scope = default_scope();
        let secret = SecretReference::new(
            "malformed-reference",
            &scope,
            Revision::new(10).expect("revision"),
        )
        .expect("secret");
        let mut service = ReplicatePredictionResultService::with_retry_policy(
            scope,
            secret,
            RecordingReplicateTransport::recording([Err(transport_error)]),
            RetryPolicy::new(1, 1, 1).expect("one attempt"),
        )
        .expect("service");
        let proposal = service.get_prediction().expect("unknown proposal");
        assert_eq!(proposal.status(), PredictionStatus::ProviderUnknown);
        assert!(matches!(
            proposal.evidence.errors[0].kind,
            ProviderErrorKind::Malformed | ProviderErrorKind::Partial
        ));
        assert_eq!(proposal.evidence.redaction, RedactionState::Redacted);
        assert!(proposal.evidence.verify_digest());
    }
}

#[test]
fn bounded_listing_hides_tokens_and_rejects_pagination_loops() {
    let scope = default_scope();
    let first = record(
        &scope,
        ProviderPredictionStatus::Processing,
        OutputEvidence::empty(false),
        false,
    );
    let second = ReplicatePredictionRecord::new(
        scope.account_id().clone(),
        PredictionId::new("prediction-2").expect("prediction"),
        scope.prediction().model().clone(),
        ProviderPredictionStatus::Succeeded,
        RuntimeMetrics::new(Some(100), Some(200)).expect("metrics"),
        OutputEvidence::empty(false),
        Timestamp::new(1_001),
        false,
    );
    let token = OpaquePageToken::new("provider-cursor-with-sensitive-state").expect("token");
    let page_one = PredictionPage::new(vec![first], Some(token.clone()), 1, false).expect("page");
    let page_two = PredictionPage::new(vec![second], None, 2, false).expect("page");
    let mut transport = RecordingReplicateTransport::recording(Vec::<
        Result<ReplicatePredictionRecord, TransportError>,
    >::new());
    transport.push_list_response(Ok(page_one));
    transport.push_list_response(Ok(page_two));
    let (_secret, mut service) = service_with(scope, transport);
    let listing = service.list_predictions(2).expect("listing");
    assert!(listing.verify_digest());
    assert_eq!(listing.records.len(), 2);
    assert_eq!(listing.pages_observed, 2);
    assert_eq!(listing.page_token_digests, vec![token.digest()]);
    let serialized = serde_json::to_string(&listing).expect("listing serializes");
    assert!(!serialized.contains("provider-cursor-with-sensitive-state"));

    let scope = default_scope();
    let token = OpaquePageToken::new("loop-token").expect("token");
    let page = PredictionPage::new(
        vec![record(
            &scope,
            ProviderPredictionStatus::Processing,
            OutputEvidence::empty(false),
            false,
        )],
        Some(token),
        1,
        false,
    )
    .expect("page");
    let mut transport = RecordingReplicateTransport::recording(Vec::<
        Result<ReplicatePredictionRecord, TransportError>,
    >::new());
    transport.push_list_response(Ok(page.clone()));
    transport.push_list_response(Ok(page));
    let (_secret, mut service) = service_with(scope, transport);
    let listing = service.list_predictions(1).expect("loop listing proposal");
    assert!(listing.partial);
    assert_eq!(listing.records.len(), 0);
    assert!(!listing.connected);
    assert!(!listing.native);
}

#[test]
fn tampered_or_replayed_proposals_and_revocations_fail_closed() {
    let scope = default_scope();
    let success = record(
        &scope,
        ProviderPredictionStatus::Succeeded,
        OutputEvidence::empty(false),
        false,
    );
    let (secret, mut service) =
        service_with(scope, RecordingReplicateTransport::recording([Ok(success)]));
    let proposal = service.get_prediction().expect("proposal");
    let mut consumer = MissionReplicateResultConsumer::from_registration(service.registration())
        .expect("consumer");
    let first = consumer.consume(&proposal).expect("first consume");
    let replay = consumer.consume(&proposal).expect("idempotent replay");
    assert_eq!(first, replay);

    let mut tampered = proposal.clone();
    tampered.evidence.status = PredictionStatus::Failed;
    assert!(!tampered.verify_digest());
    assert_eq!(
        consumer.consume(&tampered),
        Err(ConsumerError::InvalidProposal)
    );

    assert!(service.revoke().is_ok());
    assert_eq!(
        service.get_prediction(),
        Err(ServiceError::RegistrationRevoked)
    );
    assert_eq!(consumer.consume(&proposal), Err(ConsumerError::Revoked));
    assert_eq!(secret.revoke(), Ok(()));
    assert_eq!(secret.revoke(), Err(ModelError::AlreadyRevoked));
}

#[test]
fn opaque_secret_debug_and_authority_markers_never_expose_token_material() {
    let scope = default_scope();
    let secret = SecretReference::new(
        "opaque-reference-never-serialized",
        &scope,
        Revision::new(11).expect("revision"),
    )
    .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-reference-never-serialized"));
    assert!(!ReadOnlyAuthority::connected());
    assert!(!ReadOnlyAuthority::native_provider());
    assert!(!ReadOnlyAuthority::external_writes());
    assert!(!ReadOnlyAuthority::output_download());
    assert!(!ReadOnlyAuthority::prompt_retention());
    assert!(!ReadOnlyAuthority::raw_log_retention());
    assert!(!ReadOnlyAuthority::model_registry());
    assert!(!ReadOnlyAuthority::kernel_authority());
    assert!(!ReadOnlyAuthority::outcome_adoption());
}

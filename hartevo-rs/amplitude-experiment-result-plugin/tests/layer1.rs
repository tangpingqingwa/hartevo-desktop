use chrono::{TimeZone, Utc};
use hartevo_amplitude_experiment_result_plugin as amplitude;

fn time(hour: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, hour, 0, 0)
        .single()
        .expect("valid fixture time")
}

fn scope() -> amplitude::AmplitudeExperimentScope {
    let binding = |id: &str| amplitude::IdentityBinding::new(id, 1).expect("binding");
    let metric = amplitude::MetricDefinition::new(
        "activation_rate",
        1,
        amplitude::MetricDirection::Increase,
        100,
    )
    .expect("metric");
    let window = amplitude::ExposureWindow::new(time(0), time(12), 1).expect("window");
    let spec = amplitude::AmplitudeExperimentScopeSpec::new(
        binding("project-1"),
        binding("experiment-1"),
        vec![binding("control"), binding("treatment")],
        metric,
        window,
        binding("all-users"),
        binding("mission-1"),
        binding("work-product-1"),
        amplitude::AmplitudeApiDefinition::layer1(),
        amplitude::AmplitudePermissionSnapshot::least_privilege(1).expect("permissions"),
        amplitude::SecretReference::api_credential("host-secret-handle", 1)
            .expect("opaque secret reference"),
    );
    amplitude::AmplitudeExperimentScope::new(spec).expect("scope")
}

fn page(variants: Vec<amplitude::AmplitudeVariantPage>) -> amplitude::AmplitudeResultPage {
    amplitude::AmplitudeResultPage {
        project_id: "project-1".into(),
        experiment_id: "experiment-1".into(),
        segment_id: "all-users".into(),
        segment_revision: 1,
        exposure_window_start: time(0),
        exposure_window_end: time(12),
        generated_at: time(11),
        page: 1,
        page_size: 100,
        total_pages: 1,
        partial: false,
        decision: amplitude::ProviderDecisionState::Significant,
        variants,
    }
}

fn significant_page() -> amplitude::AmplitudeResultPage {
    page(vec![
        amplitude::AmplitudeVariantPage {
            variant_id: "control".into(),
            variant_revision: 1,
            exposure_count: 120,
            metrics: vec![amplitude::AmplitudeMetricPage {
                metric_id: "activation_rate".into(),
                metric_revision: 1,
                value: Some(0.21),
                confidence: Some(
                    amplitude::ConfidenceMetadata::new(0.95, Some(0.19), Some(0.23))
                        .expect("confidence"),
                ),
                decision: amplitude::ProviderDecision::Inconclusive,
            }],
        },
        amplitude::AmplitudeVariantPage {
            variant_id: "treatment".into(),
            variant_revision: 1,
            exposure_count: 130,
            metrics: vec![amplitude::AmplitudeMetricPage {
                metric_id: "activation_rate".into(),
                metric_revision: 1,
                value: Some(0.31),
                confidence: Some(
                    amplitude::ConfidenceMetadata::new(0.95, Some(0.28), Some(0.34))
                        .expect("confidence"),
                ),
                decision: amplitude::ProviderDecision::Significant,
            }],
        },
    ])
}

fn response(page: &amplitude::AmplitudeResultPage) -> amplitude::AmplitudeHttpResponse {
    amplitude::AmplitudeHttpResponse::json(200, page, time(12), Some("fixture-request-1".into()), 3)
}

#[test]
fn fixture_read_normalizes_bounded_experiment_evidence_and_proposes_provider_reported_variant() {
    let provider = amplitude::AmplitudeProvider::new(
        scope(),
        amplitude::FixtureAmplitudeTransport::new(response(&significant_page())),
    )
    .expect("provider");
    let mut service = amplitude::AmplitudeExperimentResultService::new(provider).expect("service");
    let proposal = service
        .compile_experiment_result_proposal(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-1").expect("read"),
        )
        .expect("proposal");

    assert_eq!(
        proposal.result_state(),
        amplitude::AmplitudeResultState::Significant
    );
    assert_eq!(
        proposal
            .recommendation
            .recommended_variant
            .as_ref()
            .map(amplitude::IdentityBinding::id),
        Some("treatment")
    );
    assert!(proposal.recommendation.provider_reported_only);
    assert!(!proposal.recommendation.statistical_claim);
    assert!(proposal.proposal_only);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.adopts_outcome);
    assert_eq!(proposal.evidence.read_receipt.page, 1);
    assert_eq!(proposal.evidence.read_receipt.page_size, 100);
    assert_eq!(proposal.evidence.read_receipt.cost_units, 3);
    assert_eq!(
        proposal.evidence.recording.provenance,
        amplitude::TransportProvenance::Fixture
    );
    assert!(!proposal.evidence.recording.native);
    assert!(!proposal.evidence.recording.connected);

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert!(!serialized.contains("host-secret-handle"));
    assert!(!format!("{:?}", service.scope().secret_reference()).contains("host-secret-handle"));

    let second = service
        .compile_experiment_result_proposal(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-1").expect("read"),
        )
        .expect("deterministic second proposal");
    assert_eq!(proposal.evidence.digest(), second.evidence.digest());
    assert_eq!(proposal.digest(), second.digest());
}

#[test]
fn recording_and_loopback_transports_record_bounded_requests_without_native_claims() {
    let recorded_provider = amplitude::AmplitudeProvider::new(
        scope(),
        amplitude::RecordedAmplitudeTransport::new(response(&significant_page())),
    )
    .expect("recorded provider");
    let mut recorded_service = amplitude::AmplitudeExperimentResultService::new(recorded_provider)
        .expect("recorded service");
    let evidence = recorded_service
        .read_experiment_result(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-2").expect("read"),
        )
        .expect("recorded evidence");
    let request = &recorded_service.provider().transport().requests()[0];
    assert_eq!(request.method, amplitude::AmplitudeHttpMethod::Get);
    assert_eq!(request.path, "/api/3/chart/chart-2/csv");
    assert_eq!(request.page, 1);
    assert_eq!(request.page_size, 100);
    assert_eq!(
        evidence.recording.provenance,
        amplitude::TransportProvenance::Recording
    );
    assert!(!evidence.native && !evidence.connected);

    let loopback_provider = amplitude::AmplitudeProvider::new(
        scope(),
        amplitude::LoopbackAmplitudeTransport::new(response(&significant_page())),
    )
    .expect("loopback provider");
    let mut loopback_service = amplitude::AmplitudeExperimentResultService::new(loopback_provider)
        .expect("loopback service");
    let loopback_evidence = loopback_service
        .read_experiment_result(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-3").expect("read"),
        )
        .expect("loopback evidence");
    assert_eq!(
        loopback_evidence.recording.provenance,
        amplitude::TransportProvenance::Loopback
    );
    assert!(!loopback_evidence.recording.native);
    assert!(!loopback_evidence.recording.connected);
}

#[test]
fn blocked_env_is_explicit_access_lost_and_never_connected() {
    let provider =
        amplitude::AmplitudeProvider::new(scope(), amplitude::BlockedEnvAmplitudeTransport)
            .expect("provider");
    let mut service = amplitude::AmplitudeExperimentResultService::new(provider).expect("service");
    let evidence = service
        .read_experiment_result(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-blocked").expect("read"),
        )
        .expect("blocked evidence is typed");

    assert_eq!(evidence.state, amplitude::AmplitudeResultState::AccessLost);
    assert_eq!(
        evidence.classification,
        amplitude::EvidenceClassification::BlockedEnv
    );
    assert_eq!(
        evidence.read_receipt.transport_status,
        amplitude::TransportStatus::BlockedEnv
    );
    assert_eq!(
        evidence.recording.provenance,
        amplitude::TransportProvenance::BlockedEnv
    );
    assert!(!evidence.native && !evidence.connected);
    assert_eq!(
        evidence.effect_receipt.status,
        amplitude::AmplitudeEffectReceiptStatus::NotExecutedLayer1
    );
}

#[test]
fn empty_results_never_compile_as_success_or_recommendation() {
    let provider = amplitude::AmplitudeProvider::new(
        scope(),
        amplitude::FixtureAmplitudeTransport::new(response(&page(Vec::new()))),
    )
    .expect("provider");
    let mut service = amplitude::AmplitudeExperimentResultService::new(provider).expect("service");
    let proposal = service
        .compile_experiment_result_proposal(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-empty").expect("read"),
        )
        .expect("proposal");
    assert_eq!(
        proposal.result_state(),
        amplitude::AmplitudeResultState::Empty
    );
    assert_eq!(proposal.recommendation.recommended_variant, None);
    assert_eq!(
        proposal.recommendation.disposition,
        amplitude::ResultRecommendationDisposition::NoRecommendationEmpty
    );
}

#[test]
fn mission_and_work_product_revision_fences_reject_stale_consumption() {
    let provider = amplitude::AmplitudeProvider::new(
        scope(),
        amplitude::FixtureAmplitudeTransport::new(response(&significant_page())),
    )
    .expect("provider");
    let mut consumer =
        amplitude::MissionAmplitudeExperimentConsumer::new(provider).expect("consumer");
    let proposal = consumer
        .compile_experiment_result_proposal(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-fenced").expect("read"),
        )
        .expect("proposal");
    let stale_mission = amplitude::IdentityBinding::new("mission-1", 2).expect("stale mission");
    assert!(matches!(
        consumer.consume_at_mission(&proposal, &stale_mission),
        Err(amplitude::MissionAmplitudeExperimentConsumerError::StaleMission)
    ));
    let stale_work_product =
        amplitude::IdentityBinding::new("work-product-1", 2).expect("stale work product");
    let current_mission = consumer.scope().mission().clone();
    assert!(matches!(
        consumer.consume_at_revisions(&proposal, &current_mission, &stale_work_product),
        Err(amplitude::MissionAmplitudeExperimentConsumerError::StaleWorkProduct)
    ));
    let projection = consumer
        .consume(&proposal)
        .expect("current revisions consume");
    assert_eq!(
        projection.result_state,
        amplitude::AmplitudeResultState::Significant
    );
    assert!(projection.proposal_only && !projection.native && !projection.connected);
}

#[test]
fn registration_is_digest_bound_reversible_and_revocable() {
    let provider = amplitude::AmplitudeProvider::new(
        scope(),
        amplitude::FixtureAmplitudeTransport::new(response(&significant_page())),
    )
    .expect("provider");
    let mut service = amplitude::AmplitudeExperimentResultService::new(provider).expect("service");
    let original_digest = service.registration().registration_digest.clone();
    let revocation = service.revoke("test revocation").expect("revoke");
    assert_eq!(revocation.registration_digest, original_digest);
    assert!(matches!(
        service.read_experiment_result(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-revoked").expect("read")
        ),
        Err(amplitude::AmplitudeResultError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    let evidence = service
        .read_experiment_result(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-restored").expect("read"),
        )
        .expect("restored read");
    assert_eq!(evidence.state, amplitude::AmplitudeResultState::Significant);
}

#[test]
fn proposal_readback_and_effect_receipt_are_layer_one_only() {
    let provider = amplitude::AmplitudeProvider::new(
        scope(),
        amplitude::FixtureAmplitudeTransport::new(response(&significant_page())),
    )
    .expect("provider");
    let mut consumer =
        amplitude::MissionAmplitudeExperimentConsumer::new(provider).expect("consumer");
    let consent = consumer.issue_read_consent();
    let proposal = consumer
        .compile_with_consent(
            amplitude::AmplitudeExperimentResultRead::saved_chart("chart-receipt").expect("read"),
            &consent,
        )
        .expect("proposal");
    let receipt = consumer
        .service()
        .record_experiment_result_observation(&proposal)
        .expect("record");
    assert_eq!(
        receipt.status,
        amplitude::AmplitudeEffectReceiptStatus::ObservationRecorded
    );
    assert!(!receipt.native && !receipt.connected && !receipt.durable);
    let readback = consumer
        .verify_experiment_result(&proposal)
        .expect("readback");
    assert_eq!(
        readback.status,
        amplitude::ReadbackStatus::VerifiedAgainstProposal
    );
    assert!(!readback.native && !readback.connected);
}

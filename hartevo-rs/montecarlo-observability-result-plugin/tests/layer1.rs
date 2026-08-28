use std::error::Error;

use hartevo_montecarlo_observability_result_plugin::*;
use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

fn scope() -> MonteCarloObservabilityScope {
    let project = ProjectBinding::new(
        ProjectId::new("hartevo-project-760").expect("project id"),
        Revision::new(3).expect("project revision"),
    )
    .expect("project binding");
    let work_product = WorkProductBinding::new(
        WorkProductId::new("work-product-760").expect("work product id"),
        Revision::new(5).expect("work product revision"),
    )
    .expect("work product binding");
    let consent =
        ConsentBinding::read_only(Digest::from_text("read-only-consent-760")).expect("consent");
    let mission = MissionBinding::new(
        MissionId::new("mission-760").expect("mission id"),
        Revision::new(7).expect("mission revision"),
        &project,
        &work_product,
        &consent,
    )
    .expect("mission binding");
    MonteCarloObservabilityScope::new(
        OrganizationId::new("organization-760").expect("organization"),
        MonteCarloProjectReference::new(
            MonteCarloProjectId::new("mc-project-760").expect("Monte Carlo project"),
            "analytics-project",
        )
        .expect("Monte Carlo project reference"),
        WarehouseReference::new(
            WarehouseId::new("warehouse-760").expect("warehouse"),
            "warehouse-main",
        )
        .expect("warehouse reference"),
        TableReference::new(
            TableId::new("table-orders").expect("table"),
            "analytics.orders",
        )
        .expect("table reference"),
        IncidentReference::new(
            IncidentId::new("incident-760").expect("incident"),
            "incident-revision-9",
        )
        .expect("incident reference"),
        LineageReference::new(
            LineageId::new("lineage-760").expect("lineage"),
            "lineage-revision-4",
        )
        .expect("lineage reference"),
        MonitorReference::new(
            MonitorId::new("monitor-760").expect("monitor"),
            "monitor-revision-6",
        )
        .expect("monitor reference"),
        TimeWindow::new(1_700_000_000_000, 1_700_000_600_000).expect("time window"),
        mission,
        project,
        work_product,
        consent,
        PermissionSnapshot::new(
            vec![
                Permission::IncidentRead,
                Permission::FreshnessRead,
                Permission::LineageRead,
                Permission::MonitorRead,
            ],
            Revision::new(2).expect("permission revision"),
        )
        .expect("permissions"),
        QueryPolicy::bounded_default().expect("query policy"),
    )
    .expect("scope")
}

fn response_set() -> Vec<Result<ProviderResponse, TransportError>> {
    let incident = IncidentId::new("incident-760").expect("incident");
    let table = TableId::new("table-orders").expect("table");
    let lineage = LineageId::new("lineage-760").expect("lineage");
    let monitor = MonitorId::new("monitor-760").expect("monitor");
    vec![
        Ok(ProviderResponse::Incidents(
            IncidentPage::new(
                vec![
                    IncidentRecord::new(
                        &incident,
                        IncidentState::Open,
                        Severity::High,
                        &table,
                        "customer freshness incident",
                        Some(1_700_000_300_000),
                    )
                    .expect("incident record"),
                ],
                None,
                512,
            )
            .expect("incident page"),
        )),
        Ok(ProviderResponse::Freshness(
            FreshnessPage::new(
                vec![
                    FreshnessRecord::new(
                        &table,
                        FreshnessState::Stale,
                        Some(900),
                        Some(1_700_000_300_000),
                    )
                    .expect("freshness record"),
                ],
                None,
                384,
            )
            .expect("freshness page"),
        )),
        Ok(ProviderResponse::Lineage(
            LineagePage::new(
                vec![
                    LineageRecord::new(
                        &lineage,
                        &table,
                        2,
                        1,
                        Digest::from_text("lineage-graph-760"),
                        Some(1_700_000_300_000),
                    )
                    .expect("lineage record"),
                ],
                None,
                448,
            )
            .expect("lineage page"),
        )),
        Ok(ProviderResponse::Monitors(
            MonitorPage::new(
                vec![
                    MonitorRecord::new(
                        &monitor,
                        MonitorState::Firing,
                        Some(true),
                        Digest::from_text("monitor-revision-digest-760"),
                        Some(1_700_000_300_000),
                    )
                    .expect("monitor record"),
                ],
                None,
                320,
            )
            .expect("monitor page"),
        )),
    ]
}

fn fixture_service() -> MonteCarloObservabilityResultService<FixtureTransport> {
    let current_scope = scope();
    let secret =
        SecretReference::from_opaque_handle("opaque-montecarlo-handle-760", current_scope.digest())
            .expect("opaque secret reference");
    MonteCarloObservabilityResultService::new(
        current_scope,
        secret,
        MonteCarloProvider::fixture(FixtureTransport::new(response_set())),
    )
    .expect("service")
}

#[test]
fn scope_and_secret_are_digest_bound_and_redacted() -> TestResult {
    let first = scope();
    let second = scope();
    assert_eq!(first.digest(), second.digest());
    let secret =
        SecretReference::from_opaque_handle("opaque-secret-never-serialized", first.digest())?;
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-secret-never-serialized"));
    assert!(debug.contains("secret_digest"));
    assert!(secret.validate_for(&first).is_ok());
    assert!(SecretReference::from_opaque_handle("bad handle", first.digest()).is_err());
    Ok(())
}

#[test]
fn registration_is_reversible_and_revoke_is_fail_closed() -> TestResult {
    let mut service = fixture_service();
    let original_digest = service.registration().registration_digest.clone();
    service.reverse_registration()?;
    assert_eq!(service.registration().state, RegistrationState::Reversed);
    assert_ne!(service.registration().registration_digest, original_digest);
    assert!(matches!(
        service.propose(),
        Err(ServiceError::RegistrationReversed)
    ));
    service.restore_registration()?;
    assert_eq!(service.registration().state, RegistrationState::Active);
    service.revoke_registration()?;
    assert!(matches!(
        service.propose(),
        Err(ServiceError::RegistrationRevoked)
    ));
    Ok(())
}

#[test]
fn fixture_observation_is_bounded_redacted_and_consumable_as_a_proposal() -> TestResult {
    let mut service = fixture_service();
    let result = service.observe()?;
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.state, ObservationState::Open);
    assert!(result.evidence.is_adoptable());
    assert!(!result.evidence.raw_rows);
    assert!(!result.evidence.raw_lineage);
    assert!(!result.evidence.monitor_mutation);
    assert!(!result.proposal.native_execution);
    assert!(!result.evidence.provenance.connected());
    let serialized = serde_json::to_string(&result)?;
    assert!(!serialized.contains("customer freshness incident"));
    assert!(!serialized.contains("opaque-montecarlo-handle-760"));

    let receipt = service.record_observation_receipt(&result)?;
    let verification = service.verify_receipt(&receipt, &result)?;
    assert!(verification.verified);
    assert!(!verification.connected);
    assert!(!verification.native);
    assert!(verification.adoptable);

    let mut consumer = MissionMonteCarloObservabilityConsumer::new(service.scope());
    consumer.bind_registration(service.registration())?;
    let mission_result = consumer.consume(&result)?;
    assert_eq!(
        mission_result.decision,
        DataQualityDecision::InvestigateOpenIncident
    );
    assert!(!mission_result.adopted_outcome);
    assert!(!mission_result.adopted_work_product);
    assert!(!mission_result.truth_authority);
    Ok(())
}

#[test]
fn rate_limit_backoff_is_bounded_and_deterministic() -> TestResult {
    let mut responses = response_set();
    responses.insert(0, Err(TransportError::rate_limited(Some(600_000))));
    let current_scope = scope();
    let secret = SecretReference::from_opaque_handle("rate-limit-handle", current_scope.digest())?;
    let mut service = MonteCarloObservabilityResultService::new(
        current_scope,
        secret,
        MonteCarloProvider::recording(RecordingTransport::new(responses)),
    )?;
    let result = service.observe()?;
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.page_evidence[0].retry_count, 1);
    assert!(result.evidence.page_evidence[0].redacted);
    Ok(())
}

#[test]
fn access_loss_after_a_page_is_partial_and_non_adoptable() -> TestResult {
    let mut responses = response_set();
    responses[1] = Err(TransportError::access_lost());
    responses[2] = Err(TransportError::access_lost());
    responses[3] = Err(TransportError::access_lost());
    let current_scope = scope();
    let secret = SecretReference::from_opaque_handle("access-loss-handle", current_scope.digest())?;
    let mut service = MonteCarloObservabilityResultService::new(
        current_scope,
        secret,
        MonteCarloProvider::fake(FakeTransport::new(responses)),
    )?;
    let result = service.observe()?;
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(result.evidence.state, ObservationState::Partial);
    assert!(!result.evidence.is_adoptable());
    let mut consumer = MissionMonteCarloObservabilityConsumer::new(service.scope());
    consumer.bind_registration(service.registration())?;
    assert!(matches!(
        consumer.consume(&result),
        Err(ConsumerError::PartialEvidence)
    ));
    Ok(())
}

#[test]
fn provider_rejects_out_of_scope_record_without_adopting_it() -> TestResult {
    let other_incident = IncidentId::new("incident-out-of-scope").expect("other incident");
    let table = TableId::new("table-orders").expect("table");
    let mut responses = response_set();
    responses[0] = Ok(ProviderResponse::Incidents(
        IncidentPage::new(
            vec![
                IncidentRecord::new(
                    &other_incident,
                    IncidentState::Open,
                    Severity::Critical,
                    &table,
                    "out of scope",
                    Some(1_700_000_300_000),
                )
                .expect("out-of-scope incident"),
            ],
            None,
            256,
        )
        .expect("out-of-scope page"),
    ));
    let current_scope = scope();
    let secret = SecretReference::from_opaque_handle("scope-fence-handle", current_scope.digest())?;
    let mut service = MonteCarloObservabilityResultService::new(
        current_scope,
        secret,
        MonteCarloProvider::fixture(FixtureTransport::new(responses)),
    )?;
    let result = service.observe()?;
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(result.evidence.incidents.len(), 0);
    assert_eq!(
        result.evidence.failures[0].failure,
        TransportFailure::Malformed
    );
    Ok(())
}

#[test]
fn tamper_duplicate_and_replay_fences_fail_closed() -> TestResult {
    let mut service = fixture_service();
    let result = service.observe()?;
    let _receipt = service.record_observation_receipt(&result)?;
    assert!(matches!(
        service.record_observation_receipt(&result),
        Err(ServiceError::DuplicateReceipt)
    ));
    let mut tampered = result.clone();
    tampered.evidence.page_evidence[0].item_count += 1;
    assert!(matches!(
        service.record_observation_receipt(&tampered),
        Err(ServiceError::TamperedEvidence)
    ));
    Ok(())
}

#[test]
fn blocked_env_never_claims_connected_or_native() -> TestResult {
    let current_scope = scope();
    let secret = SecretReference::from_opaque_handle("blocked-env-handle", current_scope.digest())?;
    let mut service =
        MonteCarloObservabilityResultService::new(current_scope, secret, blocked_env_provider())?;
    let result = service.observe()?;
    assert_eq!(result.evidence.status, EvidenceStatus::ProviderUnknown);
    assert_eq!(result.evidence.state, ObservationState::ProviderUnknown);
    assert_eq!(result.evidence.provenance, TransportProvenance::BlockedEnv);
    assert!(!service.capabilities().connected);
    assert!(!service.capabilities().native);
    assert!(!result.evidence.authority.connected);
    assert!(!result.evidence.authority.native);
    Ok(())
}

#[test]
fn contract_is_valid_and_digest_pinned() -> TestResult {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../contracts/plugins/montecarlo-observability-result/montecarlo-observability-result.v1.json"
    ))?;
    assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
    assert_eq!(contract["contractDigest"], contract_digest().as_str());
    assert_eq!(
        contract["provider"]["allowedTransports"],
        serde_json::json!(["recording", "fixture", "fake", "loopback", "BLOCKED_ENV"])
    );
    assert_eq!(contract["honesty"]["connectedClaim"], false);
    assert_eq!(contract["honesty"]["nativeProviderClaim"], false);
    Ok(())
}

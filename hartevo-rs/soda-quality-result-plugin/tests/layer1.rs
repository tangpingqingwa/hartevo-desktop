use hartevo_soda_quality_result_plugin::{
    BLOCKED_ENV, BlockedEnvSodaTransport, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA,
    CONTRACT_VERSION, Digest, EVIDENCE_LEVEL, FakeSodaTransport, FixtureSodaTransport,
    MissionSodaQualityConsumer, PLUGIN_ID, PROVIDER_ID, RecordingSodaTransport, SERVICE_ID,
    SecretReference, SodaEvidenceState, SodaQualityResultService, SodaQualityScope,
    SodaQualityStatus, SodaTransportError, TransportProvenance, contract_digest,
};
use serde_json::Value;

const RAW_ORGANIZATION: &str = "org-raw-761";
const RAW_DATA_SOURCE: &str = "warehouse-raw-761";
const RAW_DATASET: &str = "analytics.orders_raw";
const RAW_CHECK: &str = "freshness_raw_761";
const RAW_SCAN: &str = "scan-raw-761";
const RAW_METRIC: &str = "quality_score_raw";
const RAW_TOKEN: &str = "soda-api-token-must-not-escape";

fn scope() -> SodaQualityScope {
    SodaQualityScope::from_identifiers(
        RAW_ORGANIZATION,
        RAW_DATA_SOURCE,
        RAW_DATASET,
        RAW_CHECK,
        RAW_SCAN,
        RAW_METRIC,
        "project-761",
        "mission-761",
        "work-product-761",
        7,
    )
    .expect("scope")
}

fn fixture_service() -> SodaQualityResultService<FixtureSodaTransport> {
    let scope = scope();
    let secret = SecretReference::api_token(RAW_TOKEN, &scope, 1).expect("secret");
    SodaQualityResultService::new(
        scope.clone(),
        secret,
        FixtureSodaTransport::for_scope(&scope),
    )
    .expect("service")
}

#[test]
fn contract_is_machine_readable_and_digest_bound() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["pluginId"], PLUGIN_ID);
    assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(document["service"]["id"], SERVICE_ID);
    assert_eq!(document["provider"]["id"], PROVIDER_ID);
    assert_eq!(document["provider"]["connected"], false);
    assert_eq!(document["provider"]["native"], false);
    assert_eq!(document["provider"]["firstParty"], false);
    assert_eq!(document["provider"]["transportProvenance"][4], BLOCKED_ENV);
    assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
}

#[test]
fn fixture_result_is_bounded_redacted_and_review_only() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request("idempotency-761").expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state(), SodaEvidenceState::Pass);
    assert!(proposal.evidence.dataset.is_some());
    assert!(proposal.evidence.check.is_some());
    assert!(proposal.evidence.scan.is_some());
    assert!(proposal.evidence.quality_health.is_some());
    assert_eq!(proposal.evidence.request_receipts.len(), 4);
    assert_eq!(proposal.evidence.cost_receipts.len(), 4);
    assert!(
        proposal
            .evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(
        proposal
            .evidence
            .cost_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!proposal.evidence.provider_receipt);
    assert!(!proposal.evidence.raw_rows);
    assert!(!proposal.evidence.data_correctness_claim);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());
    let verification = service.verify(&proposal);
    assert!(verification.valid);
    assert!(verification.review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_ORGANIZATION,
        RAW_DATA_SOURCE,
        RAW_DATASET,
        RAW_CHECK,
        RAW_SCAN,
        RAW_METRIC,
        RAW_TOKEN,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    let debug = format!("{service:?}");
    assert!(!debug.contains(RAW_TOKEN));
    assert!(!debug.contains(RAW_DATASET));

    let mut consumer: MissionSodaQualityConsumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    assert!(result.validate_integrity().is_ok());
    let recorded = consumer
        .record(&proposal, "idempotency-761")
        .expect("record");
    assert!(!recorded.replayed);
    let replay = consumer
        .record(&proposal, "idempotency-761")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn provider_reported_fail_and_warn_are_typed_review_states() {
    let base_scope = scope();
    let secret = SecretReference::api_token(RAW_TOKEN, &base_scope, 1).expect("secret");
    let transport = FixtureSodaTransport::for_scope(&base_scope)
        .with_check_status(SodaQualityStatus::Fail)
        .with_health_status(SodaQualityStatus::Warn);
    let mut service =
        SodaQualityResultService::new(base_scope, secret, transport).expect("service");
    let proposal = service
        .propose(service.default_request("fail-warn-761").expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state(), SodaEvidenceState::Fail);
    assert!(service.verify(&proposal).review_eligible);
    assert!(!proposal.can_be_adopted());
}

#[test]
fn blocked_env_is_provider_unknown_and_never_native() {
    let base_scope = scope();
    let secret = SecretReference::api_token(RAW_TOKEN, &base_scope, 1).expect("secret");
    let mut service = SodaQualityResultService::new(base_scope, secret, BlockedEnvSodaTransport)
        .expect("service");
    let proposal = service
        .propose(service.default_request("blocked-761").expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state(), SodaEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.evidence.failure.as_ref().expect("failure").kind,
        hartevo_soda_quality_result_plugin::SodaFailureKind::ProviderUnknown
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn rate_limit_partial_and_tamper_fail_closed() {
    let base_scope = scope();
    let secret = SecretReference::api_token(RAW_TOKEN, &base_scope, 1).expect("secret");
    let mut rate_limited = RecordingSodaTransport::for_scope(&base_scope);
    rate_limited.fail_next(SodaTransportError::RateLimited {
        retry_after_seconds: Some(3),
    });
    let mut service =
        SodaQualityResultService::new(base_scope.clone(), secret.clone(), rate_limited)
            .expect("rate service");
    let proposal = service
        .propose(service.default_request("rate-761").expect("request"))
        .expect("rate proposal");
    assert_eq!(proposal.state(), SodaEvidenceState::RateLimited);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .status_code,
        Some(429)
    );
    assert!(!service.verify(&proposal).review_eligible);

    let mut access_lost_transport = RecordingSodaTransport::for_scope(&base_scope);
    access_lost_transport.fail_next(SodaTransportError::AccessLost);
    let mut access_lost_service =
        SodaQualityResultService::new(base_scope.clone(), secret.clone(), access_lost_transport)
            .expect("access-loss service");
    let access_lost = access_lost_service
        .propose(
            access_lost_service
                .default_request("access-loss-761")
                .expect("request"),
        )
        .expect("access-loss proposal");
    assert_eq!(access_lost.state(), SodaEvidenceState::Unknown);
    assert!(!access_lost_service.verify(&access_lost).review_eligible);

    let mut partial_transport = RecordingSodaTransport::for_scope(&base_scope);
    partial_transport.partial_next();
    let mut partial_service =
        SodaQualityResultService::new(base_scope.clone(), secret.clone(), partial_transport)
            .expect("partial service");
    let partial = partial_service
        .propose(
            partial_service
                .default_request("partial-761")
                .expect("request"),
        )
        .expect("partial proposal");
    assert_eq!(partial.state(), SodaEvidenceState::Partial);

    let mut tamper_transport = RecordingSodaTransport::for_scope(&base_scope);
    tamper_transport.tamper_next();
    let mut tamper_service = SodaQualityResultService::new(base_scope, secret, tamper_transport)
        .expect("tamper service");
    let tampered = tamper_service
        .propose(
            tamper_service
                .default_request("tamper-761")
                .expect("request"),
        )
        .expect("tampered proposal");
    assert_eq!(tampered.state(), SodaEvidenceState::Tampered);
    assert!(tampered.validate_integrity().is_ok());
}

#[test]
fn registration_and_secret_revoke_are_reversible_and_scope_bound() {
    let mut service = fixture_service();
    let request = service.default_request("revoke-761").expect("request");
    let initial_digest = service.registration().digest().clone();
    let revoked = service.revoke().expect("revoke");
    assert_eq!(revoked.previous_registration_digest, initial_digest);
    assert!(!service.registration().is_active());
    assert!(service.propose(request.clone()).is_err());
    service
        .restore_registration()
        .expect("restore registration");
    assert!(service.registration().is_active());
    assert_ne!(service.registration().digest(), &initial_digest);

    service.revoke_secret().expect("revoke secret");
    assert!(service.propose(request).is_err());
    service.restore_secret().expect("restore secret");
    let proposal = service
        .propose(
            service
                .default_request("revoke-restored-761")
                .expect("request"),
        )
        .expect("restored proposal");
    assert_eq!(proposal.state(), SodaEvidenceState::Pass);

    let other_scope = SodaQualityScope::from_identifiers(
        "org-other",
        RAW_DATA_SOURCE,
        RAW_DATASET,
        RAW_CHECK,
        RAW_SCAN,
        RAW_METRIC,
        "project-761",
        "mission-761",
        "work-product-761",
        7,
    )
    .expect("other scope");
    assert!(SecretReference::api_token(RAW_TOKEN, &other_scope, 1).is_ok());
    assert_ne!(service.scope().digest(), other_scope.digest());
}

#[test]
fn stale_revision_and_idempotency_conflict_are_rejected() {
    let mut service = fixture_service();
    let stale = service.request(6, "stale-761").expect("stale request");
    assert!(matches!(
        service.propose(stale),
        Err(hartevo_soda_quality_result_plugin::SodaQualityResultError::StaleRevision)
    ));

    let first = service
        .propose(service.default_request("same-key-761").expect("request"))
        .expect("first proposal");
    let replay = service
        .propose(service.default_request("same-key-761").expect("request"))
        .expect("deterministic replay");
    assert_eq!(first.proposal_digest, replay.proposal_digest);
    let mut changed_transport = FakeSodaTransport::for_scope(service.scope());
    changed_transport = changed_transport.with_check_status(SodaQualityStatus::Fail);
    let secret = SecretReference::api_token(RAW_TOKEN, service.scope(), 1).expect("secret");
    let mut changed_service =
        SodaQualityResultService::new(service.scope().clone(), secret, changed_transport)
            .expect("changed service");
    let changed = changed_service
        .propose(
            changed_service
                .default_request("same-key-761")
                .expect("request"),
        )
        .expect("changed proposal");
    assert_eq!(changed.state(), SodaEvidenceState::Fail);
    assert_ne!(changed.proposal_digest, first.proposal_digest);
}

#[test]
fn all_transport_provenance_is_explicitly_non_native() {
    assert!(!TransportProvenance::Fixture.is_connected());
    assert!(!TransportProvenance::Recording.is_native());
    assert!(!TransportProvenance::Fake.is_first_party());
    assert!(!TransportProvenance::Loopback.is_connected());
    assert_eq!(TransportProvenance::BlockedEnv.as_str(), BLOCKED_ENV);
    assert_eq!(Digest::from_text("stable"), Digest::from_text("stable"));
}

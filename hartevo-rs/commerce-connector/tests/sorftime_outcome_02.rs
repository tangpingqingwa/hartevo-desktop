use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use chrono::{Duration, TimeZone, Utc};
use hartevo_commerce_connector::sorftime::{
    SorftimeAccountId, SorftimeCliRequest, SorftimeDataset, SorftimeMarket, SorftimeResponse,
};
use hartevo_commerce_connector::sorftime_outcome::{
    SorftimeEstimateAdoptionRequest, SorftimeEstimateOutcomeConsumer,
    SorftimeEstimateOutcomePacket, SorftimeEstimateWorkProduct, SorftimeMissionBinding,
    SorftimeOutcomeCheckpoint, SorftimeOutcomeCheckpointState, SorftimeOutcomeError,
    SorftimeOutcomePlan, commerce_connector_contract_digest,
};
use hartevo_commerce_connector::sorftime_plugin::{
    SorftimeCheckpointState, SorftimeDurableCheckpoint, SorftimeEstimateProvider,
    SorftimeEstimateService, SorftimeProviderError, SorftimeProviderResponse,
    SorftimeQuotaEvidence, SorftimeReadPlan, SorftimeTransportIdentity,
};
use hartevo_commerce_connector::{MarketId, SORFTIME_ADAPTER_ID, sorftime_adapter_identity};
use hartevo_connector_sdk::{
    ConnectorAuth, ConnectorScope, ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::{CurrencyCode, MissionId, ProjectId};
use serde_json::json;

#[derive(Clone, Debug)]
struct FakeProvider {
    calls: Rc<RefCell<u32>>,
    response: SorftimeResponse,
    observed_at: chrono::DateTime<Utc>,
    quota: SorftimeQuotaEvidence,
    transport: SorftimeTransportIdentity,
}

impl SorftimeEstimateProvider for FakeProvider {
    fn execute(
        &mut self,
        request: &SorftimeCliRequest,
        secret: &SecretReference,
        lease: &hartevo_connector_sdk::CredentialLease,
        scope: &ConnectorScope,
        _now: chrono::DateTime<Utc>,
    ) -> Result<SorftimeProviderResponse, SorftimeProviderError> {
        assert_eq!(request.account.as_str(), scope.account_id());
        assert_eq!(secret.scope(), scope);
        assert_eq!(lease.scope(), scope);
        *self.calls.borrow_mut() += 1;
        Ok(SorftimeProviderResponse {
            response: self.response.clone(),
            observed_at: self.observed_at,
            quota: self.quota.clone(),
            transport: self.transport.clone(),
        })
    }

    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ControlledProvider
    }

    fn transport_identity(&self) -> SorftimeTransportIdentity {
        self.transport.clone()
    }
}

fn fixture_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
        .single()
        .expect("fixture time")
}

fn fixture_scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-sorftime",
        "project-sorftime",
        "sorftime",
        "sorftime-fixture-account",
        BTreeSet::from(["read_estimates".to_owned()]),
    )
    .expect("scope")
}

fn fixture_request() -> SorftimeCliRequest {
    SorftimeCliRequest::new(
        SorftimeAccountId::parse("sorftime-fixture-account").expect("account"),
        SorftimeMarket::new(
            MarketId::parse("ATVPDKIKX0DER").expect("market"),
            "en-US",
            CurrencyCode::parse("USD").expect("currency"),
        )
        .expect("market"),
        SorftimeDataset::Product,
        "mission-sorftime-read-01",
        json!({"asin":"B0C0MERC01","trend":1}),
    )
    .expect("request")
}

fn fixture_service(calls: Rc<RefCell<u32>>) -> SorftimeEstimateService<FakeProvider> {
    let scope = fixture_scope();
    let secret = SecretReference::new("secret-ref-sorftime-fixture", scope.clone(), 1)
        .expect("secret reference");
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        sorftime_adapter_identity().expect("adapter"),
        "credential-lease-sorftime-fixture",
        1,
        fixture_time(),
        fixture_time() + Duration::minutes(5),
    )
    .expect("credential lease");
    let observed_at = fixture_time();
    let transport = SorftimeTransportIdentity::controlled("outcome-contract").expect("transport");
    let quota = SorftimeQuotaEvidence::new(997, "fixture-quota", observed_at).expect("quota");
    let provider = FakeProvider {
        calls,
        response: SorftimeResponse {
            status: 200,
            request_id: "provider-request-sorftime-outcome-01".into(),
            body: json!({
                "asin":"B0C0MERC01",
                "estimatedUnits":420,
                "estimatedRevenueMinor":42000,
                "currency":"USD"
            }),
            cost_units: 3,
            cost_currency: None,
            cost_source: "fixture-price-list/v1".into(),
        },
        observed_at,
        quota,
        transport,
    };
    SorftimeEstimateService::with_freshness(provider, secret, lease, scope, Duration::minutes(5))
        .expect("service")
}

fn committed_receipt(calls: Rc<RefCell<u32>>) -> SorftimeDurableCheckpoint {
    let mut service = fixture_service(calls);
    let now = fixture_time();
    let request = fixture_request();
    let plan = service
        .prepare(&request, SorftimeDurableCheckpoint::empty(), now)
        .expect("prepare");
    let prepared = match plan {
        SorftimeReadPlan::Execute(prepared) => prepared,
        SorftimeReadPlan::Replay(_) => panic!("new provider request replayed"),
    };
    let (_result, checkpoint) = service
        .execute_prepared(&prepared, now)
        .expect("controlled provider result");
    checkpoint
}

fn binding(generation: u64) -> SorftimeMissionBinding {
    SorftimeMissionBinding::new(
        ProjectId::from("project-sorftime"),
        MissionId::from("mission-sorftime-outcome-01"),
        generation,
        SORFTIME_ADAPTER_ID,
        "a".repeat(64),
        commerce_connector_contract_digest(),
    )
    .expect("binding")
}

fn adoption_request(
    checkpoint: SorftimeDurableCheckpoint,
    generation: u64,
) -> SorftimeEstimateAdoptionRequest {
    SorftimeEstimateAdoptionRequest::new(binding(generation), checkpoint)
}

#[test]
fn committed_receipt_becomes_complete_estimate_work_product_and_replays_without_duplication() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls.clone());
    assert_eq!(*calls.borrow(), 1);
    let request = adoption_request(receipt_checkpoint.clone(), 7);
    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");

    let plan = consumer
        .prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time())
        .expect("prepare adoption");
    let prepared = match plan {
        SorftimeOutcomePlan::Adopt(prepared) => prepared,
        SorftimeOutcomePlan::Replay(_) => panic!("empty adoption checkpoint replayed"),
    };
    assert_eq!(
        prepared.checkpoint().state,
        SorftimeOutcomeCheckpointState::InFlight
    );
    assert_eq!(
        prepared.work_product().account.as_str(),
        "sorftime-fixture-account"
    );
    assert_eq!(prepared.work_product().dataset, SorftimeDataset::Product);
    assert_eq!(prepared.work_product().cost.units, 3);
    assert_eq!(prepared.work_product().quota.request_left, 997);
    assert_eq!(prepared.work_product().counterevidence.len(), 3);
    assert_eq!(prepared.work_product().limitations.len(), 4);
    assert!(prepared.work_product().is_estimate_only());
    assert!(!prepared.work_product().is_connected());
    assert!(!prepared.work_product().is_first_party_amazon_fact());
    assert!(!prepared.work_product().has_effect_e4_authority());

    let durable_in_flight = serde_json::to_string(prepared.checkpoint()).expect("checkpoint JSON");
    assert!(!durable_in_flight.contains("fixture-account-secret"));
    let reopened_in_flight: SorftimeOutcomeCheckpoint =
        serde_json::from_str(&durable_in_flight).expect("reopen in-flight checkpoint");
    assert!(matches!(
        consumer.prepare_adoption(&request, reopened_in_flight, fixture_time()),
        Err(SorftimeOutcomeError::UnknownTerminal)
    ));

    let (outcome, committed) = consumer
        .commit_adoption(&prepared, fixture_time())
        .expect("commit adoption");
    assert!(outcome.is_estimate_only());
    assert!(!outcome.is_connected());
    assert!(!outcome.is_first_party_amazon_fact());
    assert!(!outcome.has_effect_e4_authority());
    assert!(!outcome.replayed);
    assert_eq!(committed.state, SorftimeOutcomeCheckpointState::Committed);
    assert_eq!(
        committed.receipt_digest,
        Some(outcome.receipt_digest.clone())
    );
    assert_eq!(*calls.borrow(), 1);

    let committed_json = serde_json::to_string(&committed).expect("committed JSON");
    let reopened_committed: SorftimeOutcomeCheckpoint =
        serde_json::from_str(&committed_json).expect("reopen committed checkpoint");
    let replay = consumer
        .prepare_adoption(
            &request,
            reopened_committed,
            fixture_time() + Duration::seconds(1),
        )
        .expect("replay outcome");
    let replayed = match replay {
        SorftimeOutcomePlan::Replay(outcome) => outcome,
        SorftimeOutcomePlan::Adopt(_) => panic!("committed adoption executed twice"),
    };
    assert!(replayed.replayed);
    assert_eq!(replayed.outcome_digest, outcome.outcome_digest);
    assert_eq!(
        replayed.work_product.work_product_digest,
        outcome.work_product.work_product_digest
    );
    assert_eq!(*calls.borrow(), 1);
}

#[test]
fn exact_binding_and_receipt_states_fail_closed() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls);
    let request = adoption_request(receipt_checkpoint.clone(), 7);
    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");

    let wrong_request =
        SorftimeEstimateAdoptionRequest::new(binding(8), receipt_checkpoint.clone());
    assert!(matches!(
        consumer.prepare_adoption(
            &wrong_request,
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::BindingMismatch)
    ));

    let mut in_flight_receipt = receipt_checkpoint.clone();
    in_flight_receipt.state = SorftimeCheckpointState::InFlight;
    assert!(matches!(
        consumer.prepare_adoption(
            &adoption_request(in_flight_receipt, 7),
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::ReceiptUnknownTerminal)
    ));

    let mut failed_receipt = receipt_checkpoint.clone();
    failed_receipt.state = SorftimeCheckpointState::FailedClosed;
    failed_receipt.result = None;
    failed_receipt.result_digest = None;
    assert!(matches!(
        consumer.prepare_adoption(
            &adoption_request(failed_receipt, 7),
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::ReceiptFailedClosed)
    ));

    let mut tampered_receipt = receipt_checkpoint;
    tampered_receipt.scope_digest = Some("b".repeat(64));
    assert!(matches!(
        consumer.prepare_adoption(
            &adoption_request(tampered_receipt, 7),
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::InvalidReceipt(_))
    ));

    let failed_outcome_checkpoint = SorftimeOutcomeCheckpoint::empty()
        .failed_closed(&SorftimeOutcomeError::UnknownTerminal, fixture_time());
    assert!(matches!(
        consumer.prepare_adoption(&request, failed_outcome_checkpoint, fixture_time()),
        Err(SorftimeOutcomeError::PreviouslyFailedClosed)
    ));
}

#[test]
fn revoke_unmount_rotation_and_freshness_never_adopt_an_old_packet() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls);
    let request = adoption_request(receipt_checkpoint, 7);
    let mut consumer =
        SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");

    consumer.unmount();
    assert!(matches!(
        consumer.prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time()),
        Err(SorftimeOutcomeError::Unmounted)
    ));

    let mut revoked_consumer =
        SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    revoked_consumer.revoke();
    assert!(matches!(
        revoked_consumer.prepare_adoption(
            &request,
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimeOutcomeError::Revoked)
    ));

    let mut rotating_consumer =
        SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    let prepared = match rotating_consumer
        .prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time())
        .expect("prepare before rotation")
    {
        SorftimeOutcomePlan::Adopt(prepared) => prepared,
        SorftimeOutcomePlan::Replay(_) => panic!("empty adoption checkpoint replayed"),
    };
    rotating_consumer
        .rotate_generation(8)
        .expect("rotate generation");
    assert!(matches!(
        rotating_consumer.commit_adoption(&prepared, fixture_time()),
        Err(SorftimeOutcomeError::CheckpointMismatch)
    ));

    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    assert!(matches!(
        consumer.prepare_adoption(
            &request,
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time() - Duration::seconds(1)
        ),
        Err(SorftimeOutcomeError::Stale)
    ));
    assert!(matches!(
        consumer.prepare_adoption(
            &request,
            SorftimeOutcomeCheckpoint::empty(),
            fixture_time() + Duration::minutes(5)
        ),
        Err(SorftimeOutcomeError::Expired)
    ));
}

#[test]
fn packet_tampering_cannot_promote_estimate_to_first_party_or_effect_authority() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls);
    let request = adoption_request(receipt_checkpoint, 7);
    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    let prepared = match consumer
        .prepare_adoption(&request, SorftimeOutcomeCheckpoint::empty(), fixture_time())
        .expect("prepare")
    {
        SorftimeOutcomePlan::Adopt(prepared) => prepared,
        SorftimeOutcomePlan::Replay(_) => panic!("empty adoption checkpoint replayed"),
    };
    let mut product = prepared.work_product().clone();
    product.classification = "amazon_first_party_fact".into();
    assert!(matches!(
        product.validate(),
        Err(SorftimeOutcomeError::InvalidWorkProduct(_) | SorftimeOutcomeError::InvalidReceipt(_))
    ));

    let (outcome, _) = consumer
        .commit_adoption(&prepared, fixture_time())
        .expect("commit");
    let mut tampered = outcome.clone();
    tampered.work_product.limitations.clear();
    assert!(matches!(
        tampered.validate(),
        Err(SorftimeOutcomeError::InvalidWorkProduct(_))
    ));
    assert!(outcome.is_estimate_only());
    assert!(!SorftimeEstimateOutcomePacket::is_connected(&outcome));
    assert!(!SorftimeEstimateOutcomePacket::is_first_party_amazon_fact(
        &outcome
    ));
    assert!(!SorftimeEstimateWorkProduct::has_effect_e4_authority(
        &outcome.work_product
    ));
}

#[test]
fn unsupported_outcome_checkpoint_is_unknown_not_replayable() {
    let calls = Rc::new(RefCell::new(0));
    let receipt_checkpoint = committed_receipt(calls);
    let request = adoption_request(receipt_checkpoint, 7);
    let consumer = SorftimeEstimateOutcomeConsumer::new(request.binding.clone()).expect("consumer");
    let mut checkpoint = SorftimeOutcomeCheckpoint::empty();
    checkpoint.checkpoint_version = "future-outcome-checkpoint/v9".into();
    assert!(matches!(
        consumer.prepare_adoption(&request, checkpoint, fixture_time()),
        Err(SorftimeOutcomeError::UnknownTerminal)
    ));
}

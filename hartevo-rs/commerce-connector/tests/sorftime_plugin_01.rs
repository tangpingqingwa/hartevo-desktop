use std::cell::RefCell;
use std::collections::BTreeSet;
use std::env;
use std::rc::Rc;

use chrono::{Duration, TimeZone, Utc};
use hartevo_commerce_connector::sorftime::{
    SorftimeAccountId, SorftimeCliRequest, SorftimeDataset, SorftimeMarket, SorftimeResponse,
};
use hartevo_commerce_connector::sorftime_plugin::{
    SORFTIME_ACCOUNT_SECRET_ENV, SORFTIME_ESTIMATE_BLOCKED_ENV_STATUS,
    SORFTIME_ESTIMATE_CLASSIFICATION, SORFTIME_ESTIMATE_LIVE_STATUS, SorftimeCredentialInjector,
    SorftimeDurableCheckpoint, SorftimeEstimateProvider, SorftimeEstimateService,
    SorftimePluginError, SorftimeProviderError, SorftimeProviderResponse, SorftimeQuotaEvidence,
    SorftimeReadPlan, SorftimeTransportIdentity,
};
use hartevo_commerce_connector::{MarketId, SORFTIME_ADAPTER_ID, sorftime_adapter_identity};
use hartevo_connector_sdk::{
    ConnectorAuth, ConnectorScope, ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::CurrencyCode;
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

fn fixture_secret_and_lease(
    scope: &ConnectorScope,
) -> (SecretReference, hartevo_connector_sdk::CredentialLease) {
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
    (secret, lease)
}

fn fixture_provider(calls: Rc<RefCell<u32>>) -> FakeProvider {
    let observed_at = fixture_time();
    let transport = SorftimeTransportIdentity::controlled("contract").expect("transport");
    let quota = SorftimeQuotaEvidence::new(997, "fixture-quota", observed_at).expect("quota");
    FakeProvider {
        calls,
        response: SorftimeResponse {
            status: 200,
            request_id: "provider-request-sorftime-01".into(),
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
    }
}

fn fixture_service(calls: Rc<RefCell<u32>>) -> SorftimeEstimateService<FakeProvider> {
    let scope = fixture_scope();
    let (secret, lease) = fixture_secret_and_lease(&scope);
    SorftimeEstimateService::with_freshness(
        fixture_provider(calls),
        secret,
        lease,
        scope,
        Duration::minutes(5),
    )
    .expect("service")
}

#[test]
fn prepare_persists_in_flight_and_restart_refuses_duplicate_billing() {
    let calls = Rc::new(RefCell::new(0));
    let mut service = fixture_service(calls.clone());
    let request = fixture_request();
    let plan = service
        .prepare(&request, SorftimeDurableCheckpoint::empty(), fixture_time())
        .expect("prepare");
    let prepared = match plan {
        SorftimeReadPlan::Execute(prepared) => prepared,
        SorftimeReadPlan::Replay(_) => panic!("new request replayed"),
    };

    let durable_in_flight = serde_json::to_string(prepared.checkpoint()).expect("checkpoint JSON");
    assert!(!durable_in_flight.contains("fixture-account-secret"));
    let reopened: SorftimeDurableCheckpoint =
        serde_json::from_str(&durable_in_flight).expect("reopen checkpoint");
    assert_eq!(
        reopened.state,
        hartevo_commerce_connector::sorftime_plugin::SorftimeCheckpointState::InFlight
    );
    assert!(matches!(
        service.prepare(&request, reopened, fixture_time() + Duration::seconds(1)),
        Err(SorftimePluginError::UnknownTerminal)
    ));
    assert_eq!(*calls.borrow(), 0);

    let (result, committed) = service
        .execute_prepared(&prepared, fixture_time())
        .expect("provider result");
    assert_eq!(*calls.borrow(), 1);
    assert!(result.is_estimate_only());
    assert_eq!(
        committed.state,
        hartevo_commerce_connector::sorftime_plugin::SorftimeCheckpointState::Committed
    );

    let committed_json = serde_json::to_string(&committed).expect("committed JSON");
    let reopened_committed: SorftimeDurableCheckpoint =
        serde_json::from_str(&committed_json).expect("reopen committed");
    let replay = service
        .prepare(
            &request,
            reopened_committed,
            fixture_time() + Duration::seconds(2),
        )
        .expect("replay");
    let replayed = match replay {
        SorftimeReadPlan::Replay(result) => result,
        SorftimeReadPlan::Execute(_) => panic!("committed request executed again"),
    };
    assert!(replayed.replayed);
    assert_eq!(replayed.result_digest, result.result_digest);
    assert_eq!(*calls.borrow(), 1);
}

#[test]
fn result_is_mission_adoptable_estimate_with_exact_provenance_and_no_first_party_authority() {
    let calls = Rc::new(RefCell::new(0));
    let mut service = fixture_service(calls.clone());
    let request = fixture_request();
    let plan = service
        .prepare(&request, SorftimeDurableCheckpoint::empty(), fixture_time())
        .expect("prepare");
    let prepared = match plan {
        SorftimeReadPlan::Execute(prepared) => prepared,
        SorftimeReadPlan::Replay(_) => panic!("new request replayed"),
    };
    let (result, _) = service
        .execute_prepared(&prepared, fixture_time())
        .expect("result");

    assert!(result.is_estimate_only());
    assert!(result.is_mission_adoptable());
    assert!(!result.is_connected());
    assert!(!result.is_first_party_amazon_fact());
    assert_eq!(result.classification, SORFTIME_ESTIMATE_CLASSIFICATION);
    assert_eq!(
        result.live_validation_status,
        SORFTIME_ESTIMATE_BLOCKED_ENV_STATUS
    );
    assert_eq!(result.provenance_class, "controlled_provider");
    assert_eq!(result.account.as_str(), request.account.as_str());
    assert_eq!(result.market, request.market);
    assert_eq!(result.dataset, request.dataset);
    assert_eq!(
        result.request_digest,
        request.request_digest().expect("digest")
    );
    assert_eq!(result.cost.units, 3);
    assert_eq!(result.quota.request_left, 997);
    assert_eq!(
        result.freshness.valid_until - result.freshness.observed_at,
        Duration::minutes(5)
    );
    assert_eq!(
        result.observation.provenance.transport,
        hartevo_commerce_connector::sorftime::SorftimeTransportKind::Cli
    );
    assert_eq!(*calls.borrow(), 1);
}

#[test]
fn revoke_scope_drift_and_unknown_terminal_all_fail_closed_without_provider_call() {
    let calls = Rc::new(RefCell::new(0));
    let mut service = fixture_service(calls.clone());
    let request = fixture_request();
    let plan = service
        .prepare(&request, SorftimeDurableCheckpoint::empty(), fixture_time())
        .expect("prepare");
    let prepared = match plan {
        SorftimeReadPlan::Execute(prepared) => prepared,
        SorftimeReadPlan::Replay(_) => panic!("new request replayed"),
    };
    service.revoke();
    let failure = service
        .execute_prepared(&prepared, fixture_time())
        .expect_err("revoked service executed");
    assert_eq!(
        failure.checkpoint.state,
        hartevo_commerce_connector::sorftime_plugin::SorftimeCheckpointState::FailedClosed
    );
    assert_eq!(*calls.borrow(), 0);
    assert!(matches!(
        service.prepare(&request, failure.checkpoint.clone(), fixture_time()),
        Err(SorftimePluginError::CredentialChain)
    ));

    let wrong_request = SorftimeCliRequest::new(
        SorftimeAccountId::parse("other-account").expect("account"),
        request.market.clone(),
        request.dataset,
        request.request_id.clone(),
        request.payload.clone(),
    )
    .expect("wrong request");
    assert!(matches!(
        service.prepare(
            &wrong_request,
            SorftimeDurableCheckpoint::empty(),
            fixture_time()
        ),
        Err(SorftimePluginError::CredentialChain)
    ));
    assert_eq!(SORFTIME_ADAPTER_ID, "commerce.sorftime.estimate-only");
}

#[test]
fn credential_rotation_invalidates_an_old_prepared_read_before_provider_execution() {
    let calls = Rc::new(RefCell::new(0));
    let mut service = fixture_service(calls.clone());
    let request = fixture_request();
    let plan = service
        .prepare(&request, SorftimeDurableCheckpoint::empty(), fixture_time())
        .expect("prepare");
    let prepared = match plan {
        SorftimeReadPlan::Execute(prepared) => prepared,
        SorftimeReadPlan::Replay(_) => panic!("new request replayed"),
    };
    let scope = fixture_scope();
    let rotated_secret =
        SecretReference::new("secret-ref-sorftime-rotated", scope.clone(), 2).expect("secret");
    let rotated_lease = ConnectorAuth::issue_credential_lease(
        &rotated_secret,
        sorftime_adapter_identity().expect("adapter"),
        "credential-lease-sorftime-rotated",
        2,
        fixture_time(),
        fixture_time() + Duration::minutes(5),
    )
    .expect("lease");
    service
        .rotate_credentials(rotated_secret, rotated_lease)
        .expect("rotate");

    let failure = service
        .execute_prepared(&prepared, fixture_time())
        .expect_err("old prepared read remained valid after rotation");
    assert_eq!(failure.detail, SorftimePluginError::CheckpointMismatch);
    assert_eq!(
        failure.checkpoint.state,
        hartevo_commerce_connector::sorftime_plugin::SorftimeCheckpointState::FailedClosed
    );
    assert_eq!(*calls.borrow(), 0);
}

struct TestInjector {
    account_sk: String,
}

impl SorftimeCredentialInjector for TestInjector {
    fn inject_account_secret(
        &mut self,
        command: &mut std::process::Command,
        _secret: &SecretReference,
        _lease: &hartevo_connector_sdk::CredentialLease,
        _now: chrono::DateTime<Utc>,
    ) -> Result<(), SorftimeProviderError> {
        command.env(SORFTIME_ACCOUNT_SECRET_ENV, &self.account_sk);
        Ok(())
    }
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("BLOCKED_ENV: missing {name}"))
}

#[test]
#[ignore = "requires a real pinned Sorftime CLI and credential environment"]
fn real_sorftime_cli_smoke_is_explicit_and_blocked_without_environment() {
    let binary = required_env("HARTEVO_TEST_SORFTIME_BINARY");
    let version = required_env("HARTEVO_TEST_SORFTIME_VERSION");
    let sha256 = required_env("HARTEVO_TEST_SORFTIME_SHA256");
    let account = required_env("HARTEVO_TEST_SORFTIME_ACCOUNT");
    let domain = required_env("HARTEVO_TEST_SORFTIME_DOMAIN");
    let asin = required_env("HARTEVO_TEST_SORFTIME_ASIN");
    let account_sk = required_env("HARTEVO_TEST_SORFTIME_ACCOUNT_SK");
    let cost_units = required_env("HARTEVO_TEST_SORFTIME_COST_UNITS")
        .parse::<u64>()
        .expect("HARTEVO_TEST_SORFTIME_COST_UNITS must be numeric");

    let limits = hartevo_commerce_connector::sorftime_plugin::SorftimeCommandLimits::default();
    let pin = hartevo_commerce_connector::sorftime_plugin::SorftimeExecutablePin::pin(
        binary, version, sha256, &limits,
    )
    .expect("pinned Sorftime executable");
    let cost = hartevo_commerce_connector::sorftime_plugin::SorftimeCliCostPolicy::new(
        cost_units,
        None,
        "HARTEVO_TEST_SORFTIME_PRICING_SOURCE",
    )
    .expect("cost policy");
    let transport = hartevo_commerce_connector::sorftime_plugin::SorftimeCliTransport::new(
        pin,
        TestInjector { account_sk },
        limits,
        cost,
    );
    let scope = ConnectorScope::new(
        "tenant-live",
        "project-live",
        "sorftime",
        account.clone(),
        BTreeSet::from(["read_estimates".to_owned()]),
    )
    .expect("live scope");
    let secret =
        SecretReference::new("secret-ref-sorftime-live", scope.clone(), 1).expect("live secret");
    let live_now = Utc::now();
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        sorftime_adapter_identity().expect("adapter"),
        "credential-lease-sorftime-live",
        1,
        live_now,
        live_now + Duration::minutes(5),
    )
    .expect("live lease");
    let request = SorftimeCliRequest::new(
        SorftimeAccountId::parse(account).expect("live account"),
        SorftimeMarket::new(
            MarketId::parse(domain).expect("live domain"),
            "en-US",
            CurrencyCode::parse("USD").expect("currency"),
        )
        .expect("live market"),
        SorftimeDataset::Product,
        "mission-sorftime-live-01",
        json!({"asin": asin, "trend": 1}),
    )
    .expect("live request");
    let mut service =
        SorftimeEstimateService::new(transport, secret, lease, scope).expect("live service");
    let plan = service
        .prepare(&request, SorftimeDurableCheckpoint::empty(), live_now)
        .expect("live prepare");
    let prepared = match plan {
        SorftimeReadPlan::Execute(prepared) => prepared,
        SorftimeReadPlan::Replay(_) => panic!("live request unexpectedly replayed"),
    };
    let (result, _) = service
        .execute_prepared(&prepared, live_now)
        .expect("live read");
    assert_eq!(result.live_validation_status, SORFTIME_ESTIMATE_LIVE_STATUS);
    assert!(result.is_estimate_only());
    assert!(!result.is_first_party_amazon_fact());
}

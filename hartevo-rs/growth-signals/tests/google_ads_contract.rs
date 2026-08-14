use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_connector_sdk::{
    ConnectorScope, DispatchBudget, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::{EvidenceStatus, MissionId, ProjectId, TenantId};
use hartevo_growth_signals::{
    FakeGoogleAdsTransport, GOOGLE_ADS_GAQL_ADAPTER_ID, GOOGLE_ADS_GAQL_ADAPTER_VERSION,
    GOOGLE_ADS_PROVIDER_ID, GOOGLE_ADS_READ_CAPABILITY, GOOGLE_ADS_READ_CONTRACT_JSON,
    GoogleAdsAdapter, GoogleAdsCostClass, GoogleAdsError, GoogleAdsEvidenceClassification,
    GoogleAdsGaqlRequest, GoogleAdsHttpRequest, GoogleAdsHttpResponse, GoogleAdsMissionConsumer,
    GoogleAdsOAuthCredentials, GoogleAdsRegistrationState, GoogleAdsReplayLedger, GoogleAdsService,
    GoogleAdsTimeoutRetryPolicy, GoogleAdsTransport, GoogleAdsWorld,
};

#[derive(Clone, Debug)]
struct SharedFakeTransport(Arc<Mutex<FakeGoogleAdsTransport>>);

impl GoogleAdsTransport for SharedFakeTransport {
    fn execute(
        &mut self,
        request: GoogleAdsHttpRequest,
    ) -> Result<GoogleAdsHttpResponse, GoogleAdsError> {
        self.0
            .lock()
            .expect("fixture transport lock")
            .execute(request)
    }

    fn revoke(&mut self) {
        self.0.lock().expect("fixture transport lock").revoke();
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
        .single()
        .expect("valid fixture time")
}

fn scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-google-ads-test",
        "project-google-ads-test",
        GOOGLE_ADS_PROVIDER_ID,
        "1234567890",
        [GOOGLE_ADS_READ_CAPABILITY.to_owned()],
    )
    .expect("valid fixture scope")
}

fn request(scope: ConnectorScope) -> GoogleAdsGaqlRequest {
    GoogleAdsGaqlRequest::new(
        scope,
        "123-456-7890",
        "SELECT campaign.id, campaign.name, campaign.status FROM campaign WHERE campaign.status = 'ENABLED' LIMIT 3",
        2,
        10,
    )
    .expect("valid fixture GAQL")
}

fn policy(scenario: GoogleAdsWorld) -> GoogleAdsTimeoutRetryPolicy {
    GoogleAdsTimeoutRetryPolicy::new(
        1_000,
        if scenario == GoogleAdsWorld::RetryOnce {
            2
        } else {
            1
        },
        0,
        0,
    )
    .expect("valid fixture policy")
}

fn controlled_adapter(
    scenario: GoogleAdsWorld,
) -> (
    GoogleAdsAdapter<SharedFakeTransport>,
    Arc<Mutex<FakeGoogleAdsTransport>>,
) {
    let recorder = Arc::new(Mutex::new(FakeGoogleAdsTransport::new(scenario)));
    let adapter = GoogleAdsAdapter::controlled(
        SharedFakeTransport(Arc::clone(&recorder)),
        "1234567890",
        policy(scenario),
    )
    .expect("controlled adapter");
    (adapter, recorder)
}

#[test]
fn contract_and_descriptor_register_only_google_ads_probe_and_read() {
    let registry = ProviderAdapterRegistry::from_contract_json(GOOGLE_ADS_READ_CONTRACT_JSON)
        .expect("valid Google Ads contract");
    assert_eq!(registry.registrations().len(), 2);
    assert_eq!(registry.registry_version(), "google-ads-read-2026-08-14/v1");

    let (adapter, _) = controlled_adapter(GoogleAdsWorld::EmptyResult);
    assert_eq!(
        adapter.descriptor().identity().adapter_id(),
        GOOGLE_ADS_GAQL_ADAPTER_ID
    );
    assert_eq!(
        adapter.descriptor().identity().adapter_version(),
        GOOGLE_ADS_GAQL_ADAPTER_VERSION
    );
    let probe_key =
        ProviderCapabilityKey::new(GOOGLE_ADS_PROVIDER_ID, "connection.probe").expect("probe key");
    let read_key = ProviderCapabilityKey::new(GOOGLE_ADS_PROVIDER_ID, GOOGLE_ADS_READ_CAPABILITY)
        .expect("read key");
    assert!(adapter.descriptor().supports(
        &probe_key,
        ProviderAdapterOperation::Probe,
        ProviderProvenanceClass::ControlledProvider
    ));
    assert!(adapter.descriptor().supports(
        &read_key,
        ProviderAdapterOperation::Read,
        ProviderProvenanceClass::ProductionProvider
    ));
    assert!(!adapter.descriptor().supports(
        &read_key,
        ProviderAdapterOperation::Execute,
        ProviderProvenanceClass::ControlledProvider
    ));
}

#[test]
fn controlled_gaql_read_is_typed_first_party_boundary_with_durable_page_token() {
    let at = now();
    let request = request(scope());
    let (mut adapter, recorder) = controlled_adapter(GoogleAdsWorld::PaginatedRows);

    let first = adapter
        .read_controlled(request.clone(), None, at)
        .expect("first Google Ads page");
    assert_eq!(
        first.classification(),
        GoogleAdsEvidenceClassification::ControlledFixture
    );
    assert!(!first.first_party());
    assert_eq!(first.account_probe().customer_id(), "1234567890");
    assert_eq!(first.account_probe().login_customer_id(), "1234567890");
    assert_eq!(
        first.account_probe().descriptive_name(),
        Some("Fixture account")
    );
    assert_eq!(first.account_probe().currency_code(), Some("USD"));
    assert_eq!(first.account_probe().time_zone(), Some("UTC"));
    assert_eq!(first.account_probe().request_id(), "fixture-request-probe");
    assert_eq!(
        first.account_probe().quota().reported_daily_limit(),
        Some(15_000)
    );
    assert!(first.account_probe().source_revision() > 0);
    assert_eq!(first.call().api_version(), "v25");
    assert!(first.call().endpoint().contains("customers/1234567890"));
    assert_eq!(first.call().request_id(), "fixture-request-page-1");
    assert_eq!(first.page().row_count(), 2);
    assert_eq!(
        first.page().rows()[0].resource_name(),
        Some("customers/1234567890/campaigns/1")
    );
    assert_eq!(first.page().field_mask().len(), 3);
    assert_eq!(
        first.read_observation().provenance_class(),
        ProviderProvenanceClass::ControlledProvider
    );
    assert_eq!(first.read_observation().page_sequence(), 1);
    assert_eq!(
        first.usage().cost_class(),
        GoogleAdsCostClass::ControlledFixture
    );
    assert!(!first.usage().charged());
    assert_eq!(first.usage().request_units(), 1);
    assert_eq!(first.usage().request_id(), "fixture-request-page-1");
    assert_eq!(first.usage().quota().local_used(), 1);

    let cursor = first.next_cursor().cloned().expect("next page cursor");
    assert_eq!(cursor.sequence(), 2);
    assert_eq!(cursor.page_token(), "fixture-page-token-2");
    assert!(!format!("{cursor:?}").contains("fixture-page-token-2"));

    let encoded = serde_json::to_vec(&first).expect("serialize signal");
    let decoded: hartevo_growth_signals::GoogleAdsGrowthSignal =
        serde_json::from_slice(&encoded).expect("deserialize signal");
    assert_eq!(decoded, first);

    let second = adapter
        .read_controlled(request, Some(cursor), at + Duration::seconds(1))
        .expect("second Google Ads page");
    assert_eq!(second.read_observation().page_sequence(), 2);
    assert_eq!(second.page().row_count(), 1);
    assert!(!second.page().has_next_page());
    assert_eq!(recorder.lock().expect("fixture lock").provider_calls(), 3);
}

#[test]
fn google_ads_failures_retry_and_read_only_boundary_are_explicit() {
    let at = now();
    let request = request(scope());

    let (mut retry_adapter, retry_recorder) = controlled_adapter(GoogleAdsWorld::RetryOnce);
    let retry_signal = retry_adapter
        .read_controlled(request.clone(), None, at)
        .expect("bounded retry should recover");
    assert_eq!(retry_signal.usage().attempts(), 1);
    assert_eq!(
        retry_recorder
            .lock()
            .expect("fixture lock")
            .provider_calls(),
        3
    );

    let (mut quota_adapter, quota_recorder) = controlled_adapter(GoogleAdsWorld::QuotaExhausted);
    assert_eq!(
        quota_adapter.read_controlled(request.clone(), None, at),
        Err(GoogleAdsError::QuotaExhausted)
    );
    assert_eq!(
        quota_recorder
            .lock()
            .expect("fixture lock")
            .provider_calls(),
        1
    );

    let (mut invalid_adapter, invalid_recorder) =
        controlled_adapter(GoogleAdsWorld::InvalidPageToken);
    let first = invalid_adapter
        .read_controlled(request.clone(), None, at)
        .expect("invalid-token first page");
    let cursor = first.next_cursor().cloned().expect("invalid-token cursor");
    assert_eq!(
        invalid_adapter.read_controlled(request, Some(cursor), at),
        Err(GoogleAdsError::InvalidPageToken)
    );
    assert_eq!(
        invalid_recorder
            .lock()
            .expect("fixture lock")
            .provider_calls(),
        3
    );

    let (mut write_adapter, _) = controlled_adapter(GoogleAdsWorld::ReadOnlyViolation);
    assert_eq!(
        write_adapter.read_controlled(
            GoogleAdsGaqlRequest::new(
                scope(),
                "1234567890",
                "SELECT campaign.id FROM campaign",
                1,
                10,
            )
            .expect("syntactically read-only selector"),
            None,
            at,
        ),
        Err(GoogleAdsError::InvalidQuery)
    );
}

#[test]
fn replay_ledger_is_durable_and_free() {
    let at = now();
    let request = request(scope());
    let (mut adapter, recorder) = controlled_adapter(GoogleAdsWorld::PaginatedRows);
    let signal = adapter
        .read_controlled(request.clone(), None, at)
        .expect("first page");
    assert_eq!(recorder.lock().expect("fixture lock").provider_calls(), 2);

    let mut ledger = GoogleAdsReplayLedger::default();
    ledger.record(signal.clone());
    let durable = serde_json::to_vec(&ledger).expect("serialize ledger");
    let restored: GoogleAdsReplayLedger =
        serde_json::from_slice(&durable).expect("deserialize ledger");
    let replay = restored
        .replay(
            &request.request_digest(),
            signal.read_observation().page_sequence(),
        )
        .expect("replay page");
    assert!(replay.replayed());
    assert!(!replay.charged());
    assert_eq!(replay.usage().cost_class(), GoogleAdsCostClass::Replay);
    assert_eq!(replay.usage().request_units(), 0);
    assert_eq!(replay.usage().attempts(), 0);
    assert_eq!(replay.call().request_id(), signal.call().request_id());
    assert_eq!(restored.page_count(), 1);
    assert_eq!(recorder.lock().expect("fixture lock").provider_calls(), 2);
}

#[test]
fn mission_consumer_keeps_controlled_fixture_candidate_and_first_party_contract() {
    let at = now();
    let request = request(scope());
    let (mut adapter, _) = controlled_adapter(GoogleAdsWorld::EmptyResult);
    let signal = adapter
        .read_controlled(request, None, at)
        .expect("controlled page");
    let consumer = GoogleAdsMissionConsumer::new(
        MissionId::from("mission-google-ads-test"),
        TenantId::from("tenant-google-ads-test"),
        ProjectId::from("project-google-ads-test"),
        "1234567890",
    )
    .expect("Mission consumer");
    let output = consumer.consume(&signal).expect("Mission output");
    assert_eq!(
        output.consumer_id(),
        "mission.consumer.google-ads.gaql.read"
    );
    assert_eq!(
        output.classification(),
        GoogleAdsEvidenceClassification::ControlledFixture
    );
    assert!(!output.first_party());
    assert_eq!(output.row_count(), 0);
    assert_eq!(output.evidence().status, EvidenceStatus::Candidate);
    assert!(output.evidence().confidence.abs() < f32::EPSILON);
    assert_eq!(output.request_id(), "fixture-request-page-1");
}

#[test]
fn oauth_material_and_secret_reference_debug_are_redacted() {
    let credentials =
        GoogleAdsOAuthCredentials::new("fixture-oauth-access-token", "fixture-developer-token")
            .expect("credentials");
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("fixture-oauth-access-token"));
    assert!(!debug.contains("fixture-developer-token"));

    let secret =
        SecretReference::new("secret-ref-google-ads-debug", scope(), 1).expect("secret reference");
    assert!(!format!("{secret:?}").contains("secret-ref-google-ads-debug"));
}

#[test]
fn service_mounts_probes_reads_mission_signal_and_revoke_is_terminal() {
    let at = now();
    let scope = scope();
    let request = request(scope.clone());
    let secret = SecretReference::new("secret-ref-google-ads-service", scope, 1)
        .expect("service secret reference");
    let recorder = Arc::new(Mutex::new(FakeGoogleAdsTransport::new(
        GoogleAdsWorld::PaginatedRows,
    )));
    let mut service = GoogleAdsService::new(
        secret,
        request,
        SharedFakeTransport(Arc::clone(&recorder)),
        policy(GoogleAdsWorld::PaginatedRows),
        at,
        GoogleAdsReplayLedger::default(),
    )
    .expect("Google Ads service");

    assert_eq!(
        service.registration().state(),
        GoogleAdsRegistrationState::Unmounted
    );
    assert!(service.definition().read_only());
    assert_eq!(
        service.read(
            None,
            at,
            DispatchBudget::new(100, at + Duration::minutes(1), 10, 0).expect("dispatch budget")
        ),
        Err(GoogleAdsError::NotMounted)
    );

    service.mount(at).expect("authenticated account probe");
    assert_eq!(
        service.registration().state(),
        GoogleAdsRegistrationState::Mounted
    );
    let signal = service
        .read(
            None,
            at,
            DispatchBudget::new(100, at + Duration::minutes(1), 10, 0).expect("dispatch budget"),
        )
        .expect("typed GAQL growth signal");
    assert_eq!(
        signal.classification(),
        GoogleAdsEvidenceClassification::FirstParty
    );
    assert!(signal.first_party());
    assert_eq!(signal.account_probe().customer_id(), "1234567890");
    assert_eq!(signal.call().request_id(), "fixture-request-page-1");
    assert_eq!(signal.page().row_count(), 2);
    assert!(signal.freshness().valid_until() > at);

    let mission = GoogleAdsMissionConsumer::new(
        MissionId::from("mission-google-ads-service"),
        TenantId::from("tenant-google-ads-test"),
        ProjectId::from("project-google-ads-test"),
        "1234567890",
    )
    .expect("Mission consumer")
    .consume(&signal)
    .expect("Mission output");
    assert_eq!(mission.evidence().status, EvidenceStatus::Confirmed);
    assert!((mission.evidence().confidence - 1.0).abs() < f32::EPSILON);

    let replay = service
        .read(
            None,
            at + Duration::seconds(1),
            DispatchBudget::new(100, at + Duration::minutes(1), 10, 0).expect("dispatch budget"),
        )
        .expect("durable replay");
    assert!(replay.replayed());
    assert!(!replay.charged());
    assert_eq!(recorder.lock().expect("fixture lock").provider_calls(), 2);

    service.unmount(at + Duration::seconds(2)).expect("unmount");
    assert_eq!(
        service.registration().state(),
        GoogleAdsRegistrationState::Unmounted
    );
    service
        .revoke("a".repeat(64), at + Duration::seconds(2))
        .expect("revoke");
    assert_eq!(
        service.registration().state(),
        GoogleAdsRegistrationState::Revoked
    );
    assert_eq!(
        service.mount(at + Duration::seconds(3)),
        Err(GoogleAdsError::Revoked)
    );
}

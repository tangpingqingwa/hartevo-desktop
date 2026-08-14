use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use hartevo_connector_sdk::{
    ConnectorScope, DispatchBudget, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::{EvidenceStatus, MissionId, ProjectId, TenantId};
use hartevo_growth_signals::{
    FakeGa4Transport, GA4_ADAPTER_ID, GA4_ADAPTER_VERSION, GA4_PROVIDER_ID, GA4_READ_CAPABILITY,
    GA4_READ_CONTRACT_JSON, Ga4Adapter, Ga4Error, Ga4GrowthSignal, Ga4HttpRequest, Ga4HttpResponse,
    Ga4SearchAnalyticsService, Ga4SearchRequest, Ga4TimeWindow, Ga4TimeoutRetryPolicy,
    Ga4Transport, Ga4World, SearchAnalyticsCostClass, SearchAnalyticsEvidenceClassification,
    SearchAnalyticsMissionError, SearchAnalyticsReadService, SearchAnalyticsSignal,
};

#[derive(Clone, Debug)]
struct SharedFake(Arc<Mutex<FakeGa4Transport>>);

impl Ga4Transport for SharedFake {
    fn execute(&mut self, request: Ga4HttpRequest) -> Result<Ga4HttpResponse, Ga4Error> {
        self.0
            .lock()
            .expect("GA4 fixture transport lock")
            .execute(request)
    }

    fn revoke(&mut self) {
        self.0.lock().expect("GA4 fixture transport lock").revoke();
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
        .single()
        .expect("valid fixture time")
}

fn scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-signal-test",
        "project-signal-test",
        GA4_PROVIDER_ID,
        "account-ga4-test",
        [GA4_READ_CAPABILITY.to_owned()],
    )
    .expect("valid GA4 fixture scope")
}

fn request(scope: ConnectorScope) -> Ga4SearchRequest {
    Ga4SearchRequest::new(
        scope,
        "123456789",
        vec!["date".to_owned()],
        vec!["activeUsers".to_owned()],
        Ga4TimeWindow::new(
            NaiveDate::from_ymd_opt(2026, 8, 1).expect("valid fixture date"),
            NaiveDate::from_ymd_opt(2026, 8, 14).expect("valid fixture date"),
        )
        .expect("valid fixture window"),
        2,
    )
    .expect("valid GA4 request")
}

fn policy(scenario: Ga4World) -> Ga4TimeoutRetryPolicy {
    Ga4TimeoutRetryPolicy::new(1_000, u8::from(scenario == Ga4World::RetryOnce) + 1, 0, 0)
        .expect("valid fixture retry policy")
}

fn controlled_adapter(
    scenario: Ga4World,
) -> (Ga4Adapter<SharedFake>, Arc<Mutex<FakeGa4Transport>>) {
    let recorder = Arc::new(Mutex::new(FakeGa4Transport::new(scenario)));
    let adapter = Ga4Adapter::controlled(SharedFake(Arc::clone(&recorder)), policy(scenario))
        .expect("controlled GA4 adapter");
    (adapter, recorder)
}

fn budget(at: DateTime<Utc>) -> DispatchBudget {
    DispatchBudget::new(100, at + Duration::minutes(1), 100, 0).expect("fixture budget")
}

#[test]
fn contract_descriptor_and_gaql_boundary_are_read_only() {
    let registry = ProviderAdapterRegistry::from_contract_json(GA4_READ_CONTRACT_JSON)
        .expect("valid GA4 contract");
    assert_eq!(registry.registrations().len(), 2);
    assert_eq!(
        registry.registry_version(),
        "google-analytics-4-read-2026-08-14/v1"
    );
    let (adapter, _) = controlled_adapter(Ga4World::Empty);
    assert_eq!(adapter.descriptor().identity().adapter_id(), GA4_ADAPTER_ID);
    assert_eq!(
        adapter.descriptor().identity().adapter_version(),
        GA4_ADAPTER_VERSION
    );
    let probe = ProviderCapabilityKey::new(GA4_PROVIDER_ID, "connection.probe").expect("probe key");
    let read = ProviderCapabilityKey::new(GA4_PROVIDER_ID, GA4_READ_CAPABILITY).expect("read key");
    assert!(adapter.descriptor().supports(
        &probe,
        ProviderAdapterOperation::Probe,
        ProviderProvenanceClass::ControlledProvider
    ));
    assert!(adapter.descriptor().supports(
        &read,
        ProviderAdapterOperation::Read,
        ProviderProvenanceClass::ControlledProvider
    ));
    assert!(!adapter.descriptor().supports(
        &read,
        ProviderAdapterOperation::Execute,
        ProviderProvenanceClass::ControlledProvider
    ));
}

#[test]
fn authenticated_report_read_has_property_window_quota_and_opaque_page_cursor() {
    let at = now();
    let request = request(scope());
    let (mut adapter, recorder) = controlled_adapter(Ga4World::Paginated);
    let first = adapter
        .read_controlled(request.clone(), None, at)
        .expect("first GA4 report page");
    assert_eq!(
        first.classification(),
        SearchAnalyticsEvidenceClassification::ControlledFixture
    );
    assert!(!first.first_party());
    assert_eq!(first.property_id(), "123456789");
    assert_eq!(first.scope(), request.scope());
    assert!(first.account_probe().property_access());
    assert_eq!(first.account_probe().scope(), request.scope());
    assert_eq!(first.receipt().provider().provider_id(), GA4_PROVIDER_ID);
    assert_eq!(first.receipt().api_version(), "v1beta");
    assert_eq!(
        first.receipt().cost_class(),
        SearchAnalyticsCostClass::ProviderReadFree
    );
    assert_eq!(first.quota().provider_request_id(), "ga4-fixture-request-1");
    assert_eq!(first.quota().quota_units(), 7);
    assert_eq!(first.quota().quota_remaining(), Some(39_993));
    assert_eq!(first.page().rows().len(), 2);
    assert_eq!(first.page().rows()[0].dimension_values(), &["2026-08-13"]);
    assert_eq!(first.page().rows()[0].metric_values(), &["12"]);
    let cursor = first
        .next_cursor()
        .cloned()
        .expect("durable GA4 page cursor");
    assert_eq!(cursor.sequence(), 2);
    assert!(cursor.has_page_token());
    assert!(!format!("{cursor:?}").contains("fixture-page-token-2"));
    let encoded = serde_json::to_vec(&first).expect("serialize GA4 result");
    let decoded: Ga4GrowthSignal =
        serde_json::from_slice(&encoded).expect("deserialize GA4 result");
    assert_eq!(decoded, first);
    let second = adapter
        .read_controlled(request, Some(cursor), at + Duration::seconds(1))
        .expect("second GA4 report page");
    assert_eq!(second.page_sequence(), 2);
    assert_eq!(second.page().rows().len(), 1);
    assert!(!second.page().has_more());
    let recorder = recorder.lock().expect("GA4 fixture lock");
    assert!(recorder.read_calls() >= 3);
    assert!(recorder.requests()[2].body_digest().is_some());
}

#[test]
fn replay_and_service_registration_never_repeat_a_read_or_cross_revoke() {
    let at = now();
    let read_request = request(scope());
    let (mut adapter, recorder) = controlled_adapter(Ga4World::Empty);
    let first = adapter
        .read_controlled(read_request.clone(), None, at)
        .expect("first GA4 read");
    let mut ledger = hartevo_growth_signals::Ga4ReplayLedger::default();
    ledger.record(first.clone());
    let durable = serde_json::to_vec(&ledger).expect("serialize GA4 replay ledger");
    let restored: hartevo_growth_signals::Ga4ReplayLedger =
        serde_json::from_slice(&durable).expect("deserialize GA4 replay ledger");
    let replay = restored
        .replay(&read_request.request_digest(), first.page_sequence())
        .expect("replay GA4 page");
    assert!(replay.replayed());
    assert!(!replay.charged());
    assert_eq!(restored.page_count(), 1);
    assert!(recorder.lock().expect("GA4 fixture lock").read_calls() >= 2);

    let service_scope = scope();
    let service_request = request(service_scope.clone());
    let secret = SecretReference::new("secret-ref-ga4-test", service_scope, 1)
        .expect("GA4 secret reference");
    let service_recorder = Arc::new(Mutex::new(FakeGa4Transport::new(Ga4World::Empty)));
    let mut service = Ga4SearchAnalyticsService::new(
        secret,
        service_request,
        SharedFake(Arc::clone(&service_recorder)),
        policy(Ga4World::Empty),
        at,
        hartevo_growth_signals::Ga4ReplayLedger::default(),
    )
    .expect("GA4 service");
    service.mount(at).expect("mount GA4 service");
    service
        .unmount(at + Duration::seconds(1))
        .expect("unmount GA4 service");
    assert_eq!(
        service.read(None, at, budget(at)),
        Err(Ga4Error::NotMounted)
    );
    service
        .mount(at + Duration::seconds(2))
        .expect("remount GA4 service");
    service
        .revoke(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            at + Duration::seconds(3),
        )
        .expect("revoke GA4 service");
    assert_eq!(service.read(None, at, budget(at)), Err(Ga4Error::Revoked));
}

#[test]
fn mission_consumer_emits_candidate_and_rejects_wrong_scope() {
    let at = now();
    let (mut adapter, _) = controlled_adapter(Ga4World::PartialAccess);
    let signal = adapter
        .read_controlled(request(scope()), None, at)
        .expect("GA4 partial-access observation");
    assert!(signal.account_probe().partial_access());
    let consumer = SearchAnalyticsReadService::new(
        MissionId::from("mission-ga4-test"),
        TenantId::from("tenant-signal-test"),
        ProjectId::from("project-signal-test"),
        "account-ga4-test",
    )
    .expect("Mission consumer");
    let output = consumer
        .consume(&SearchAnalyticsSignal::GoogleAnalytics4(signal.clone()))
        .expect("Mission GA4 output");
    assert_eq!(output.provider_id(), GA4_PROVIDER_ID);
    assert_eq!(output.property_id(), "123456789");
    assert_eq!(
        output.classification(),
        SearchAnalyticsEvidenceClassification::ControlledFixture
    );
    assert!(!output.first_party());
    assert_eq!(output.evidence().status, EvidenceStatus::Candidate);
    assert_eq!(
        output.evidence().content_digest,
        signal.raw_evidence_digest()
    );
    let wrong = SearchAnalyticsReadService::new(
        MissionId::from("mission-ga4-test"),
        TenantId::from("wrong-tenant"),
        ProjectId::from("project-signal-test"),
        "account-ga4-test",
    )
    .expect("wrong-scope consumer");
    assert_eq!(
        wrong.consume(&SearchAnalyticsSignal::GoogleAnalytics4(signal)),
        Err(SearchAnalyticsMissionError::ScopeMismatch)
    );
}

#[test]
fn retry_access_denied_and_secret_debug_are_fail_closed() {
    let at = now();
    let request = request(scope());
    let (mut retry_adapter, retry_recorder) = controlled_adapter(Ga4World::RetryOnce);
    let retry = retry_adapter
        .read_controlled(request.clone(), None, at)
        .expect("bounded GA4 retry");
    assert!(!retry.first_party());
    assert!(
        retry_recorder
            .lock()
            .expect("GA4 fixture lock")
            .requests()
            .len()
            >= 3
    );

    let (mut denied_adapter, _) = controlled_adapter(Ga4World::AccessDenied);
    assert_eq!(
        denied_adapter.read_controlled(request, None, at),
        Err(Ga4Error::PropertyAccessDenied)
    );
    let credentials = hartevo_growth_signals::Ga4OAuthCredentials::new("fixture-access-token")
        .expect("fixture credential");
    assert!(!format!("{credentials:?}").contains("fixture-access-token"));
    let secret = SecretReference::new("secret-ref-ga4-debug", scope(), 1).expect("secret ref");
    assert!(!format!("{secret:?}").contains("secret-ref-ga4-debug"));
}

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use hartevo_connector_sdk::{
    ConnectorScope, DispatchBudget, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::{EvidenceStatus, MissionId, ProjectId, TenantId};
use hartevo_growth_signals::{
    FakeGscTransport, GSC_ADAPTER_ID, GSC_ADAPTER_VERSION, GSC_PROVIDER_ID, GSC_READ_CAPABILITY,
    GSC_READ_CONTRACT_JSON, GscAdapter, GscError, GscGrowthSignal, GscHttpRequest, GscHttpResponse,
    GscReplayLedger, GscSearchAnalyticsService, GscSearchRequest, GscTimeWindow,
    GscTimeoutRetryPolicy, GscTransport, GscWorld, SearchAnalyticsCostClass,
    SearchAnalyticsEvidenceClassification, SearchAnalyticsMissionError, SearchAnalyticsReadService,
    SearchAnalyticsSignal,
};

#[derive(Clone, Debug)]
struct SharedFake(Arc<Mutex<FakeGscTransport>>);

impl GscTransport for SharedFake {
    fn execute(&mut self, request: GscHttpRequest) -> Result<GscHttpResponse, GscError> {
        self.0
            .lock()
            .expect("GSC fixture transport lock")
            .execute(request)
    }

    fn revoke(&mut self) {
        self.0.lock().expect("GSC fixture transport lock").revoke();
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
        GSC_PROVIDER_ID,
        "account-gsc-test",
        [GSC_READ_CAPABILITY.to_owned()],
    )
    .expect("valid GSC fixture scope")
}

fn request(scope: ConnectorScope) -> GscSearchRequest {
    GscSearchRequest::new(
        scope,
        "https://example.com/",
        vec!["query".to_owned()],
        GscTimeWindow::new(
            NaiveDate::from_ymd_opt(2026, 8, 1).expect("valid fixture date"),
            NaiveDate::from_ymd_opt(2026, 8, 14).expect("valid fixture date"),
        )
        .expect("valid fixture window"),
        2,
    )
    .expect("valid GSC request")
}

fn policy(scenario: GscWorld) -> GscTimeoutRetryPolicy {
    GscTimeoutRetryPolicy::new(1_000, u8::from(scenario == GscWorld::RetryOnce) + 1, 0, 0)
        .expect("valid fixture retry policy")
}

fn controlled_adapter(
    scenario: GscWorld,
) -> (GscAdapter<SharedFake>, Arc<Mutex<FakeGscTransport>>) {
    let recorder = Arc::new(Mutex::new(FakeGscTransport::new(scenario)));
    let adapter = GscAdapter::controlled(SharedFake(Arc::clone(&recorder)), policy(scenario))
        .expect("controlled GSC adapter");
    (adapter, recorder)
}

fn budget(at: DateTime<Utc>) -> DispatchBudget {
    DispatchBudget::new(100, at + Duration::minutes(1), 100, 0).expect("fixture budget")
}

#[test]
fn contract_descriptor_and_probe_are_read_only() {
    let registry = ProviderAdapterRegistry::from_contract_json(GSC_READ_CONTRACT_JSON)
        .expect("valid GSC contract");
    assert_eq!(registry.registrations().len(), 2);
    assert_eq!(
        registry.registry_version(),
        "google-search-console-read-2026-08-14/v1"
    );
    let (adapter, _) = controlled_adapter(GscWorld::Empty);
    assert_eq!(adapter.descriptor().identity().adapter_id(), GSC_ADAPTER_ID);
    assert_eq!(
        adapter.descriptor().identity().adapter_version(),
        GSC_ADAPTER_VERSION
    );
    let probe = ProviderCapabilityKey::new(GSC_PROVIDER_ID, "connection.probe").expect("probe key");
    let read = ProviderCapabilityKey::new(GSC_PROVIDER_ID, GSC_READ_CAPABILITY).expect("read key");
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
fn authenticated_fixture_read_has_scope_probe_receipt_and_durable_cursor() {
    let at = now();
    let request = request(scope());
    let (mut adapter, recorder) = controlled_adapter(GscWorld::Paginated);
    let first = adapter
        .read_controlled(request.clone(), None, at)
        .expect("first GSC page");
    assert_eq!(
        first.classification(),
        SearchAnalyticsEvidenceClassification::ControlledFixture
    );
    assert!(!first.first_party());
    assert_eq!(first.scope(), request.scope());
    assert!(first.account_probe().property_access());
    assert_eq!(first.account_probe().scope(), request.scope());
    assert_eq!(
        first.account_probe().quota().provider_request_id(),
        "gsc-fixture-request-1"
    );
    assert_eq!(
        first.receipt().provider().provider_id(),
        "google-search-console"
    );
    assert_eq!(
        first.receipt().provider_request_id(),
        "gsc-fixture-request-1"
    );
    assert_eq!(
        first.receipt().cost_class(),
        SearchAnalyticsCostClass::ProviderReadFree
    );
    assert_eq!(first.page().rows().len(), 2);
    assert!(first.freshness().valid_until() > at);
    assert_eq!(first.source_revision(), first.freshness().source_revision());
    let cursor = first.next_cursor().cloned().expect("durable GSC cursor");
    assert_eq!(cursor.sequence(), 2);
    let encoded = serde_json::to_vec(&first).expect("serialize GSC result");
    let decoded: GscGrowthSignal =
        serde_json::from_slice(&encoded).expect("deserialize GSC result");
    assert_eq!(decoded, first);
    let second = adapter
        .read_controlled(request, Some(cursor), at + Duration::seconds(1))
        .expect("second GSC page");
    assert_eq!(second.page_sequence(), 2);
    assert_eq!(second.page().rows().len(), 1);
    assert!(!second.page().has_more());
    assert_eq!(recorder.lock().expect("GSC fixture lock").read_calls(), 2);
}

#[test]
fn replay_ledger_and_service_lifecycle_are_free_and_fail_closed() {
    let at = now();
    let scope = scope();
    let request = request(scope.clone());
    let secret = SecretReference::new("secret-ref-gsc-test", scope, 1).expect("secret reference");
    let recorder = Arc::new(Mutex::new(FakeGscTransport::new(GscWorld::Empty)));
    let mut service = GscSearchAnalyticsService::new(
        secret,
        request,
        SharedFake(Arc::clone(&recorder)),
        policy(GscWorld::Empty),
        at,
        GscReplayLedger::default(),
    )
    .expect("GSC service");
    service.mount(at).expect("mount GSC service");
    service
        .unmount(at + Duration::seconds(1))
        .expect("unmount GSC service");
    assert_eq!(
        service.read(None, at, budget(at)),
        Err(GscError::NotMounted)
    );
    service
        .mount(at + Duration::seconds(2))
        .expect("remount GSC service");
    service
        .revoke(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            at + Duration::seconds(3),
        )
        .expect("revoke GSC service");
    assert_eq!(service.read(None, at, budget(at)), Err(GscError::Revoked));
}

#[test]
fn mission_consumer_preserves_first_party_boundary_and_receipt_digests() {
    let at = now();
    let request = request(scope());
    let (mut adapter, _) = controlled_adapter(GscWorld::Empty);
    let signal = adapter
        .read_controlled(request, None, at)
        .expect("GSC fixture observation");
    let consumer = SearchAnalyticsReadService::new(
        MissionId::from("mission-gsc-test"),
        TenantId::from("tenant-signal-test"),
        ProjectId::from("project-signal-test"),
        "account-gsc-test",
    )
    .expect("Mission search analytics consumer");
    let output = consumer
        .consume(&SearchAnalyticsSignal::GoogleSearchConsole(signal.clone()))
        .expect("Mission GSC output");
    assert_eq!(output.provider_id(), GSC_PROVIDER_ID);
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
    assert_eq!(
        output.consumer_id(),
        "mission.consumer.google.search-analytics.read"
    );
}

#[test]
fn retry_partial_access_denied_and_secret_debug_are_honest() {
    let at = now();
    let request = request(scope());
    let (mut retry_adapter, retry_recorder) = controlled_adapter(GscWorld::RetryOnce);
    let retry = retry_adapter
        .read_controlled(request.clone(), None, at)
        .expect("bounded GSC retry");
    assert!(!retry.first_party());
    assert!(
        retry_recorder
            .lock()
            .expect("GSC fixture lock")
            .requests()
            .len()
            >= 3
    );

    let (mut partial_adapter, _) = controlled_adapter(GscWorld::PartialAccess);
    let partial = partial_adapter
        .read_controlled(request.clone(), None, at)
        .expect("partial-access GSC read");
    assert!(partial.account_probe().partial_access());

    let (mut denied_adapter, _) = controlled_adapter(GscWorld::AccessDenied);
    assert_eq!(
        denied_adapter.read_controlled(request, None, at),
        Err(GscError::PropertyAccessDenied)
    );

    let credentials = hartevo_growth_signals::GscOAuthCredentials::new("fixture-access-token")
        .expect("fixture credential");
    assert!(!format!("{credentials:?}").contains("fixture-access-token"));
    let secret = SecretReference::new("secret-ref-gsc-debug", scope(), 1).expect("secret ref");
    assert!(!format!("{secret:?}").contains("secret-ref-gsc-debug"));
}

#[test]
fn mission_scope_mismatch_is_rejected() {
    let at = now();
    let (mut adapter, _) = controlled_adapter(GscWorld::Empty);
    let signal = adapter
        .read_controlled(request(scope()), None, at)
        .expect("fixture signal");
    let consumer = SearchAnalyticsReadService::new(
        MissionId::from("mission-gsc-test"),
        TenantId::from("wrong-tenant"),
        ProjectId::from("project-signal-test"),
        "account-gsc-test",
    )
    .expect("consumer");
    assert_eq!(
        consumer.consume(&SearchAnalyticsSignal::GoogleSearchConsole(signal)),
        Err(SearchAnalyticsMissionError::ScopeMismatch)
    );
}

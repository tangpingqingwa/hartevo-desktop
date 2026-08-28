use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use hartevo_connector_sdk::{
    ConnectorScope, DispatchBudget, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::{EvidenceStatus, MissionId, ProjectId, TenantId};
use hartevo_growth_signals::{
    DATAFORSEO_LABS_ADAPTER_ID, DATAFORSEO_LABS_ADAPTER_VERSION, DATAFORSEO_LABS_READ_CAPABILITY,
    DATAFORSEO_LABS_READ_CONTRACT_JSON, DATAFORSEO_PROVIDER_ID, DataForSeoCredentials,
    DataForSeoError, DataForSeoEvidenceClassification, DataForSeoKeywordRequest,
    DataForSeoLabsAdapter, DataForSeoLabsService, DataForSeoLabsTransport, DataForSeoLabsWorld,
    DataForSeoReplayLedger, DataForSeoTimeWindow, DataForSeoTimeoutRetryPolicy,
    FakeDataForSeoLabsTransport,
};

#[derive(Clone, Debug)]
struct SharedFakeTransport(Arc<Mutex<FakeDataForSeoLabsTransport>>);

impl DataForSeoLabsTransport for SharedFakeTransport {
    fn execute(
        &mut self,
        request: hartevo_growth_signals::DataForSeoHttpRequest,
    ) -> Result<hartevo_growth_signals::DataForSeoHttpResponse, DataForSeoError> {
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
        "tenant-signal-test",
        "project-signal-test",
        DATAFORSEO_PROVIDER_ID,
        "account-dataforseo-test",
        [DATAFORSEO_LABS_READ_CAPABILITY.to_owned()],
    )
    .expect("valid fixture scope")
}

fn request(scope: ConnectorScope) -> DataForSeoKeywordRequest {
    DataForSeoKeywordRequest::new(
        scope,
        "example.com",
        "us",
        2_840,
        "en",
        DataForSeoTimeWindow::new(
            NaiveDate::from_ymd_opt(2026, 8, 1).expect("valid fixture date"),
            NaiveDate::from_ymd_opt(2026, 8, 14).expect("valid fixture date"),
        )
        .expect("valid fixture window"),
        2,
        false,
        false,
        rust_decimal::Decimal::new(1, 2),
        rust_decimal::Decimal::new(10, 2),
    )
    .expect("valid fixture request")
}

fn policy(scenario: DataForSeoLabsWorld) -> DataForSeoTimeoutRetryPolicy {
    DataForSeoTimeoutRetryPolicy::new(
        1_000,
        if scenario == DataForSeoLabsWorld::RetryOnce {
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
    scenario: DataForSeoLabsWorld,
) -> (
    DataForSeoLabsAdapter<SharedFakeTransport>,
    Arc<Mutex<FakeDataForSeoLabsTransport>>,
) {
    let recorder = Arc::new(Mutex::new(FakeDataForSeoLabsTransport::new(scenario)));
    let adapter = DataForSeoLabsAdapter::controlled(
        SharedFakeTransport(Arc::clone(&recorder)),
        policy(scenario),
    )
    .expect("controlled adapter");
    (adapter, recorder)
}

fn budget(at: DateTime<Utc>) -> DispatchBudget {
    DispatchBudget::new(100, at + Duration::minutes(1), 100, 10).expect("fixture budget")
}

#[test]
fn contract_and_descriptor_register_only_typed_read_surfaces() {
    let registry = ProviderAdapterRegistry::from_contract_json(DATAFORSEO_LABS_READ_CONTRACT_JSON)
        .expect("valid DataForSEO contract");
    assert_eq!(registry.registrations().len(), 2);
    assert_eq!(
        registry.registry_version(),
        "dataforseo-labs-read-2026-08-14/v1"
    );

    let (adapter, _) = controlled_adapter(DataForSeoLabsWorld::EmptyResult);
    assert_eq!(
        adapter.descriptor().identity().adapter_id(),
        DATAFORSEO_LABS_ADAPTER_ID
    );
    assert_eq!(
        adapter.descriptor().identity().adapter_version(),
        DATAFORSEO_LABS_ADAPTER_VERSION
    );
    let probe_key =
        ProviderCapabilityKey::new(DATAFORSEO_PROVIDER_ID, "connection.probe").expect("probe key");
    let read_key =
        ProviderCapabilityKey::new(DATAFORSEO_PROVIDER_ID, DATAFORSEO_LABS_READ_CAPABILITY)
            .expect("read key");
    assert!(adapter.descriptor().supports(
        &probe_key,
        ProviderAdapterOperation::Probe,
        ProviderProvenanceClass::ControlledProvider
    ));
    assert!(adapter.descriptor().supports(
        &read_key,
        ProviderAdapterOperation::Read,
        ProviderProvenanceClass::ControlledProvider
    ));
    assert!(!adapter.descriptor().supports(
        &read_key,
        ProviderAdapterOperation::Execute,
        ProviderProvenanceClass::ControlledProvider
    ));
}

#[test]
fn controlled_paginated_read_is_typed_estimate_with_durable_cursor() {
    let at = now();
    let request = request(scope());
    let (mut adapter, recorder) = controlled_adapter(DataForSeoLabsWorld::PaginatedResults);

    let first = adapter
        .read_controlled(request.clone(), None, at)
        .expect("first keyword page");
    assert_eq!(
        first.classification(),
        DataForSeoEvidenceClassification::ProviderEstimate
    );
    assert!(!first.first_party());
    assert_eq!(first.account_probe().scope(), request.scope());
    assert_eq!(first.account_probe().account_login_digest().len(), 64);
    assert_eq!(
        first.account_probe().cost_usd(),
        rust_decimal::Decimal::ZERO
    );
    assert_eq!(
        first.account_probe().rate_limit().limit_per_minute(),
        Some(2_000)
    );
    assert_eq!(
        first
            .labs_status()
            .google_date_update()
            .unwrap()
            .to_string(),
        "2026-08-14"
    );
    assert_eq!(
        first.task().endpoint(),
        "/v3/dataforseo_labs/google/keywords_for_site/live"
    );
    assert_eq!(first.task().api_version(), "v3");
    assert_eq!(first.page().items().len(), 2);
    assert_eq!(first.page().items()[0].keyword(), "fixture growth keyword");
    assert_eq!(
        first.read_observation().provenance_class(),
        ProviderProvenanceClass::ControlledProvider
    );
    assert_eq!(first.read_observation().page_sequence(), 1);
    assert_eq!(
        first.usage().provider_cost_usd(),
        rust_decimal::Decimal::new(1, 2)
    );
    assert!(first.usage().charged());
    assert_eq!(first.usage().rate_limit().remaining(), Some(1_997));
    assert!(first.freshness().valid_until() > first.observed_at());
    assert_eq!(first.freshness().source_revision(), first.source_revision());

    let cursor = first.next_cursor().cloned().expect("next page cursor");
    assert_eq!(cursor.sequence(), 2);
    assert_eq!(cursor.offset(), 2);
    assert_eq!(cursor.offset_token(), Some("fixture-offset-token-2"));
    assert!(!format!("{cursor:?}").contains("fixture-offset-token-2"));

    let encoded = serde_json::to_vec(&first).expect("serialize durable signal");
    let decoded: hartevo_growth_signals::DataForSeoGrowthSignal =
        serde_json::from_slice(&encoded).expect("deserialize durable signal");
    assert_eq!(decoded, first);

    let second = adapter
        .read_controlled(request, Some(cursor), at + Duration::seconds(1))
        .expect("second keyword page");
    assert_eq!(second.read_observation().page_sequence(), 2);
    assert_eq!(second.page().items().len(), 1);
    assert!(!second.page().has_next_page());

    let recorder = recorder.lock().expect("fixture transport lock");
    assert_eq!(recorder.billable_calls(), 2);
    assert_eq!(recorder.requests().len(), 4);
    assert_eq!(
        recorder.requests()[2].path(),
        "/v3/dataforseo_labs/google/keywords_for_site/live"
    );
    assert!(recorder.requests()[2].body_digest().is_some());
}

#[test]
fn replay_ledger_round_trip_is_free_and_does_not_repeat_provider_read() {
    let at = now();
    let request = request(scope());
    let (mut adapter, recorder) = controlled_adapter(DataForSeoLabsWorld::PaginatedResults);
    let signal = adapter
        .read_controlled(request.clone(), None, at)
        .expect("keyword page");
    assert_eq!(recorder.lock().expect("fixture lock").billable_calls(), 1);

    let mut ledger = DataForSeoReplayLedger::default();
    ledger.record(signal.clone());
    let durable = serde_json::to_vec(&ledger).expect("serialize replay ledger");
    let restored: DataForSeoReplayLedger =
        serde_json::from_slice(&durable).expect("deserialize replay ledger");
    let replay = restored
        .replay(
            &request.request_digest(),
            signal.read_observation().page_sequence(),
        )
        .expect("replay first page");
    assert!(replay.replayed());
    assert!(!replay.charged());
    assert!(!replay.usage().charged());
    assert_eq!(
        replay.usage().provider_cost_usd(),
        rust_decimal::Decimal::ZERO
    );
    assert_eq!(replay.usage().attempts(), 0);
    assert_eq!(replay.raw_evidence_digest(), signal.raw_evidence_digest());
    assert_eq!(replay.page(), signal.page());
    assert_eq!(restored.page_count(), 1);
    assert_eq!(recorder.lock().expect("fixture lock").billable_calls(), 1);
}

#[test]
fn provider_failures_and_retry_are_fail_closed() {
    let at = now();
    let request = request(scope());

    let (mut retry_adapter, retry_recorder) = controlled_adapter(DataForSeoLabsWorld::RetryOnce);
    let retry_signal = retry_adapter
        .read_controlled(request.clone(), None, at)
        .expect("bounded retry should recover");
    assert!(!retry_signal.first_party());
    assert_eq!(
        retry_recorder
            .lock()
            .expect("fixture lock")
            .requests()
            .len(),
        4
    );

    let (mut quota_adapter, quota_recorder) =
        controlled_adapter(DataForSeoLabsWorld::QuotaExhausted);
    assert_eq!(
        quota_adapter.read_controlled(request.clone(), None, at),
        Err(DataForSeoError::QuotaExhausted)
    );
    assert_eq!(
        quota_recorder
            .lock()
            .expect("fixture lock")
            .billable_calls(),
        1
    );

    let (mut invalid_adapter, invalid_recorder) =
        controlled_adapter(DataForSeoLabsWorld::InvalidPageToken);
    let first = invalid_adapter
        .read_controlled(request.clone(), None, at)
        .expect("invalid-token first page");
    let cursor = first.next_cursor().cloned().expect("invalid-token cursor");
    assert_eq!(
        invalid_adapter.read_controlled(request, Some(cursor), at),
        Err(DataForSeoError::InvalidCursor)
    );
    assert_eq!(
        invalid_recorder
            .lock()
            .expect("fixture lock")
            .billable_calls(),
        2
    );
}

#[test]
fn sdk_service_registration_mount_unmount_and_revoke_are_scoped() {
    let at = now();
    let scope = scope();
    let request = request(scope.clone());
    let secret = SecretReference::new("secret-ref-dataforseo-test", scope, 1).expect("secret ref");
    let recorder = Arc::new(Mutex::new(FakeDataForSeoLabsTransport::new(
        DataForSeoLabsWorld::EmptyResult,
    )));
    let transport = SharedFakeTransport(Arc::clone(&recorder));
    let mut service = DataForSeoLabsService::new(
        secret,
        request,
        transport,
        policy(DataForSeoLabsWorld::EmptyResult),
        at,
        DataForSeoReplayLedger::default(),
    )
    .expect("service registration");
    assert_eq!(
        service.registration().state(),
        hartevo_growth_signals::DataForSeoRegistrationState::Unmounted
    );
    service.mount(at).expect("mount service");
    assert_eq!(
        service.registration().state(),
        hartevo_growth_signals::DataForSeoRegistrationState::Mounted
    );
    let signal = service.read(None, at, budget(at)).expect("service read");
    assert!(!signal.first_party());
    service
        .unmount(at + Duration::seconds(1))
        .expect("unmount service");
    assert_eq!(
        service.read(None, at, budget(at)),
        Err(DataForSeoError::NotMounted)
    );
    service
        .mount(at + Duration::seconds(2))
        .expect("remount service");
    service
        .revoke(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            at + Duration::seconds(3),
        )
        .expect("revoke service");
    assert_eq!(
        service.registration().state(),
        hartevo_growth_signals::DataForSeoRegistrationState::Revoked
    );
    assert_eq!(
        service.read(None, at, budget(at)),
        Err(DataForSeoError::Revoked)
    );
    assert!(recorder.lock().expect("fixture lock").billable_calls() >= 1);
}

#[test]
fn mission_consumer_emits_candidate_estimate_without_first_party_claim() {
    let at = now();
    let request = request(scope());
    let (mut adapter, _) = controlled_adapter(DataForSeoLabsWorld::EmptyResult);
    let signal = adapter
        .read_controlled(request, None, at)
        .expect("empty keyword observation");
    let consumer = hartevo_growth_signals::DataForSeoMissionConsumer::new(
        MissionId::from("mission-dataforseo-test"),
        TenantId::from("tenant-signal-test"),
        ProjectId::from("project-signal-test"),
        "account-dataforseo-test",
    )
    .expect("mission consumer");
    let output = consumer.consume(&signal).expect("Mission consumer output");
    assert_eq!(
        output.consumer_id(),
        "mission.consumer.dataforseo.labs.read"
    );
    assert_eq!(
        output.classification(),
        DataForSeoEvidenceClassification::ProviderEstimate
    );
    assert!(!output.first_party());
    assert_eq!(output.item_count(), 0);
    assert_eq!(output.evidence().status, EvidenceStatus::Candidate);
    assert!(output.evidence().confidence.abs() < f32::EPSILON);
    assert_eq!(
        output.evidence().content_digest,
        signal.raw_evidence_digest()
    );
}

#[test]
fn resolved_credentials_and_secret_references_never_debug_secret_bytes() {
    let credentials = DataForSeoCredentials::new("login@example.invalid", "fixture-password")
        .expect("credentials");
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("fixture-password"));
    assert!(!debug.contains("login@example.invalid"));

    let scope = scope();
    let secret = SecretReference::new("secret-ref-dataforseo-debug", scope, 1).expect("secret ref");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("secret-ref-dataforseo-debug"));
}

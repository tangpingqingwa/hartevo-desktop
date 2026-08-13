use chrono::{TimeZone, Utc};
use hartevo_connector_sdk::{
    ProviderAdapterOperation, ProviderAdapterRegistry, ProviderProvenanceClass,
};
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use hartevo_growth_signals::{
    CalendarDateRange, LanguageCode, MarketCode, ReadScope,
    dataforseo::DataForSeoDevice,
    dataforseo::DataForSeoMode,
    dataforseo::DataForSeoSearchRequest,
    dataforseo::DataForSeoWorldScenario,
    dataforseo::FakeDataForSeoTransport,
    dataforseo_canary::{DataForSeoCanaryConfig, run_with_transport},
    dataforseo_service::{
        DATAFORSEO_READ_CAPABILITY, DataForSeoConnectorService, DataForSeoMissionConsumer,
        DataForSeoReadProvider, DataForSeoRegistrationState,
    },
    parse_date,
};
use rust_decimal::Decimal;
use serde_json::Value;

const PROVIDER_CATALOG: &str = include_str!("../../../contracts/providers/catalog.v1.json");

#[test]
fn signal01_catalog_exposes_google_ads_and_dataforseo_probe() {
    let catalog: Value = serde_json::from_str(PROVIDER_CATALOG).expect("provider catalog");
    let providers = catalog["providers"].as_array().expect("providers");

    let google_ads = providers
        .iter()
        .find(|provider| provider["id"] == "google-ads")
        .expect("Google Ads catalog entry");
    assert_eq!(google_ads["authMode"], "oauth");
    assert_eq!(
        google_ads["capabilityIds"],
        serde_json::json!(["connection.probe", "ads.read"])
    );

    let dataforseo = providers
        .iter()
        .find(|provider| provider["id"] == "dataforseo")
        .expect("DataForSEO catalog entry");
    assert_eq!(dataforseo["authMode"], "secret");
    assert!(
        dataforseo["capabilityIds"]
            .as_array()
            .expect("DataForSEO capabilities")
            .iter()
            .any(|capability| capability == "connection.probe")
    );
}

#[test]
fn signal01_registry_is_e1_read_only_metadata_and_never_write_authority() {
    let registry = ProviderAdapterRegistry::contract_baseline().expect("E1 registry");
    assert_eq!(
        registry.registry_version(),
        "desktop-2026-08-13-signal01-a1"
    );

    for registration in registry.registrations() {
        assert!(matches!(
            registration.key().provider_id(),
            "dataforseo" | "google-ads" | "google-search-console" | "google-analytics"
        ));
        for support in registration.evidence_support() {
            assert!(matches!(
                support.operation(),
                ProviderAdapterOperation::Probe | ProviderAdapterOperation::Read
            ));
            assert!(matches!(
                support.provenance_class(),
                ProviderProvenanceClass::Fixture
                    | ProviderProvenanceClass::ComponentHarness
                    | ProviderProvenanceClass::ControlledProvider
                    | ProviderProvenanceClass::ProductionProvider
            ));
        }
    }
}

#[test]
fn signal02_canary_contract_binds_estimate_scope_evidence_and_replay_cost() {
    let scope = ReadScope::new(
        TenantId::from("tenant-contract"),
        ProjectId::from("project-contract"),
        MarketCode::new("DE").expect("market"),
        LanguageCode::new("de").expect("language"),
        CalendarDateRange::new(
            parse_date("2026-08-01").expect("date"),
            parse_date("2026-08-07").expect("date"),
        )
        .expect("window"),
    );
    let request = DataForSeoSearchRequest::new(
        scope.clone(),
        "contract canary",
        2276,
        DataForSeoDevice::Desktop,
        10,
        DataForSeoMode::Live,
        Decimal::new(10, 2),
        Some(Decimal::new(20, 2)),
    )
    .expect("request");
    let config = DataForSeoCanaryConfig::new(
        scope,
        "dataforseo-account",
        request,
        2,
        Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time"),
    )
    .expect("config");
    let report = run_with_transport(
        &config,
        FakeDataForSeoTransport::new(DataForSeoWorldScenario::PaginatedResults),
    )
    .expect("report");
    let value = serde_json::to_value(report).expect("report JSON");
    assert_eq!(value["providerId"], "dataforseo");
    assert_eq!(value["classification"], "provider_estimate");
    assert_eq!(value["firstParty"], false);
    assert_eq!(value["accountScope"]["accountId"], "dataforseo-account");
    assert_eq!(value["chargedPageCount"], 1);
    assert_eq!(value["pages"].as_array().expect("pages").len(), 2);
    assert_eq!(
        value["pages"][0]["rawEvidenceDigest"]
            .as_str()
            .map(str::len),
        Some(64)
    );
    assert!(
        value["pages"][0]["sourceRevision"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
}

#[test]
fn signal03_mission_consumer_contract_emits_scoped_read_result_envelope() {
    let scope = ReadScope::new(
        TenantId::from("tenant-mission-contract"),
        ProjectId::from("project-mission-contract"),
        MarketCode::new("DE").expect("market"),
        LanguageCode::new("de").expect("language"),
        CalendarDateRange::new(
            parse_date("2026-08-01").expect("date"),
            parse_date("2026-08-07").expect("date"),
        )
        .expect("window"),
    );
    let request = DataForSeoSearchRequest::new(
        scope.clone(),
        "mission contract keyword",
        2276,
        DataForSeoDevice::Desktop,
        10,
        DataForSeoMode::Live,
        Decimal::new(10, 2),
        Some(Decimal::new(20, 2)),
    )
    .expect("request");
    let config = DataForSeoCanaryConfig::new(
        scope.clone(),
        "dataforseo-mission-account",
        request.clone(),
        2,
        Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time"),
    )
    .expect("config");
    let client = hartevo_growth_signals::dataforseo::DataForSeoClient::new(
        config.secret_reference().expect("secret"),
        FakeDataForSeoTransport::new(DataForSeoWorldScenario::PaginatedResults),
    )
    .expect("client");
    let provider = DataForSeoReadProvider::new(
        client,
        request,
        2,
        config.observed_at(),
        ProviderProvenanceClass::ControlledProvider,
    )
    .expect("provider");
    let mut service = DataForSeoConnectorService::new(provider).expect("service");
    assert_eq!(
        service.registration().state(),
        DataForSeoRegistrationState::Unmounted
    );
    service.mount().expect("mount");
    let result = service.read_result().expect("read result");
    let consumer = DataForSeoMissionConsumer::new(
        MissionId::from_stable("mission-signal03-contract"),
        scope.tenant_id().clone(),
        scope.project_id().clone(),
        "dataforseo-mission-account",
        DATAFORSEO_READ_CAPABILITY,
    )
    .expect("consumer");
    let output = consumer.consume(&result).expect("mission output");
    let value = serde_json::to_value(output).expect("mission output JSON");
    assert_eq!(value["consumerId"], "hartevo.mission.growth-signal");
    assert_eq!(value["providerId"], "dataforseo");
    assert_eq!(value["accountId"], "dataforseo-mission-account");
    assert_eq!(value["classification"], "provider_estimate");
    assert_eq!(value["firstParty"], false);
    assert_eq!(value["probeStatus"], "reachable");
    assert_eq!(value["evidence"]["status"], "candidate");
    assert_eq!(value["evidence"]["confidence"], 0.0);
    assert_eq!(value["cursor"]["sequence"], 2);
    assert_eq!(
        value["readObservation"]["capability"]["capabilityId"],
        "search.measure"
    );
    assert_eq!(
        value["accountProbe"]["scope"]["projectId"],
        "project-mission-contract"
    );
}

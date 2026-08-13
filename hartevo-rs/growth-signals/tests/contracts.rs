use hartevo_connector_sdk::{
    ProviderAdapterOperation, ProviderAdapterRegistry, ProviderProvenanceClass,
};
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

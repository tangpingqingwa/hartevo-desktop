//! Bridges provider-specific evidence into the merged Connector SDK.
//!
//! The provider modules keep their wire-level request and response models,
//! while this module owns only the contract metadata and the SDK projection.
//! It deliberately does not introduce another connector lifecycle trait.

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::{
    ConnectorDescriptor, ConnectorError, Cursor, FreshnessWindow, ProviderAdapterIdentity,
    ProviderAdapterRegistry, ProviderCapabilityKey,
};

pub const ADAPTER_VERSION: u32 = 1;

pub fn descriptor_for(
    provider_id: &str,
    adapter_id: &str,
) -> Result<ConnectorDescriptor, ConnectorError> {
    let identity = ProviderAdapterIdentity::new(adapter_id, ADAPTER_VERSION)
        .map_err(|_| ConnectorError::InvalidAdapterMetadata)?;
    let registry = ProviderAdapterRegistry::contract_baseline()
        .map_err(|_| ConnectorError::InvalidRegistry)?;
    let registrations = registry
        .registrations()
        .iter()
        .filter(|registration| {
            registration.key().provider_id() == provider_id && registration.adapter() == &identity
        })
        .cloned()
        .collect::<Vec<_>>();
    ConnectorDescriptor::new(identity, registrations)
}

pub fn capability(
    provider_id: &str,
    capability_id: &str,
) -> Result<ProviderCapabilityKey, ConnectorError> {
    ProviderCapabilityKey::new(provider_id, capability_id)
        .map_err(|_| ConnectorError::InvalidCapability)
}

pub fn freshness(
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_revision: u64,
) -> Result<FreshnessWindow, ConnectorError> {
    FreshnessWindow::new(observed_at, valid_until, source_revision)
}

pub fn cursor(
    scope: &hartevo_connector_sdk::ConnectorScope,
    request_digest: &str,
    sequence: u64,
    token_digest: &str,
) -> Result<Cursor, ConnectorError> {
    Cursor::new(
        scope,
        request_digest.to_owned(),
        sequence,
        token_digest.to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_are_derived_from_the_provider_contract_baseline() {
        for (provider, adapter, capabilities) in [
            (
                "dataforseo",
                "hartevo.dataforseo",
                ["connection.probe", "search.measure", "research.discover"].as_slice(),
            ),
            (
                "google-ads",
                "hartevo.google-ads",
                ["connection.probe", "ads.read"].as_slice(),
            ),
            (
                "google-search-console",
                "hartevo.google-search-console",
                ["connection.probe", "search.measure"].as_slice(),
            ),
            (
                "google-analytics",
                "hartevo.google-analytics",
                ["connection.probe", "analytics.read"].as_slice(),
            ),
        ] {
            let descriptor = descriptor_for(provider, adapter).expect("descriptor");
            assert_eq!(descriptor.identity().adapter_id(), adapter);
            assert_eq!(
                descriptor
                    .registrations()
                    .iter()
                    .map(|registration| registration.key().capability_id())
                    .collect::<Vec<_>>(),
                capabilities
            );
        }
    }
}

//! Desktop host composition for the first native Shopify readback.
//!
//! Cordis continues to carry only its existing opaque one-shot bindings. The
//! provider object, OS-keyring reference, credential-use handle, token bytes,
//! and GraphQL request remain below the Desktop/Application boundary.

use chrono::{DateTime, Utc};
use hartevo_application::connectors::shopify_readback::{
    ShopifyBrokeredReadback, ShopifyReadbackMetadata,
};
use hartevo_application::connectors::{
    ShopifyFulfillmentReadbackRequest, ShopifyReadbackBridgeError, ShopifyReadbackCancellation,
    ShopifyReadbackCredentialBinding, ShopifySecretReadbackProvider,
    UreqShopifyAdminReadbackTransport, dispatch_shopify_readback,
};
use hartevo_effect_broker::{
    SecretBrokerConsumer, SecretBrokerService, SecretBrokerServiceDefinition,
};
use hartevo_storage::OsSecretStore;

pub const DESKTOP_SHOPIFY_SECRET_SERVICE: &str = "com.hartevo.desktop";
pub const DESKTOP_SHOPIFY_READBACK_CONSUMER_ID: &str = "secret-consumer-desktop-shopify-readback";

/// Mounts the call-local Secret Broker service for one exact Shopify scope.
/// The returned consumer/service contain references and lifecycle metadata only.
pub fn prepare_shopify_readback_broker(
    binding: &ShopifyReadbackCredentialBinding,
    now: DateTime<Utc>,
) -> Result<(SecretBrokerConsumer, SecretBrokerService), ShopifyReadbackBridgeError> {
    let definition = SecretBrokerServiceDefinition::production()?;
    let reference = binding.broker_reference(&definition)?;
    let mut service = SecretBrokerService::new(definition, reference)?;
    service.mount(now)?;
    let scope = binding.scope();
    let consumer = SecretBrokerConsumer::new(
        DESKTOP_SHOPIFY_READBACK_CONSUMER_ID,
        scope.tenant_id().clone(),
        scope.project_id().clone(),
        scope.mission_id().clone(),
    )?;
    Ok((consumer, service))
}

/// Selects the real Desktop dependencies for one already-authorized exact-ID
/// readback. Creating this call path does not mount a service, store a token,
/// register Connected, or authorize a provider write.
pub fn dispatch_os_keyring_shopify_readback(
    binding: ShopifyReadbackCredentialBinding,
    request: ShopifyFulfillmentReadbackRequest,
    cancellation: ShopifyReadbackCancellation,
    consumer: &SecretBrokerConsumer,
    service: &mut SecretBrokerService,
    now: DateTime<Utc>,
) -> Result<ShopifyBrokeredReadback, ShopifyReadbackBridgeError> {
    let secret_store = OsSecretStore::new(DESKTOP_SHOPIFY_SECRET_SERVICE)?;
    let transport = UreqShopifyAdminReadbackTransport::new();
    let mut provider = ShopifySecretReadbackProvider::new_native(
        &secret_store,
        binding,
        request,
        cancellation,
        transport,
    )?;
    dispatch_shopify_readback(consumer, service, &mut provider, now)
}

/// Production Desktop projection. Only typed readback metadata crosses this
/// boundary; the provider object and content-free Secret Broker receipt do not.
pub fn dispatch_os_keyring_shopify_readback_metadata(
    binding: ShopifyReadbackCredentialBinding,
    request: ShopifyFulfillmentReadbackRequest,
    cancellation: ShopifyReadbackCancellation,
    consumer: &SecretBrokerConsumer,
    service: &mut SecretBrokerService,
    now: DateTime<Utc>,
) -> Result<ShopifyReadbackMetadata, ShopifyReadbackBridgeError> {
    dispatch_os_keyring_shopify_readback(binding, request, cancellation, consumer, service, now)
        .map(|outcome| outcome.metadata())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_host_selects_the_existing_os_keyring_service() {
        assert_eq!(DESKTOP_SHOPIFY_SECRET_SERVICE, "com.hartevo.desktop");
        assert_ne!(DESKTOP_SHOPIFY_SECRET_SERVICE, "HARTEVO_SHOPIFY_TOKEN");
    }
}

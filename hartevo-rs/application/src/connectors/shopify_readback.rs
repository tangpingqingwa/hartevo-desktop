//! Application-owned bridge from one Secret Broker use lease to one Shopify
//! fulfillment readback.
//!
//! The checked-in provider registry remains empty. This module constructs a
//! one-call, metadata-only `Read` registry only after an actual native
//! transport provider exists. Secret bytes are resolved from the injected
//! secure store inside the final opaque-handle callback and are dropped before
//! the callback returns.

use std::fmt;

use chrono::{DateTime, Utc};
pub use hartevo_commerce_connector::shopify::{SHOPIFY_PROVIDER_ID, ShopDomain, ShopifyApiVersion};
pub use hartevo_commerce_connector::shopify_effect::{
    SHOPIFY_FULFILLMENT_CAPABILITY, ShopifyFulfillmentLineItem, ShopifyFulfillmentOrderGid,
    ShopifyOrderGid,
};
pub use hartevo_commerce_connector::shopify_transport::{
    ShopifyAdminReadbackTransport, ShopifyExpectedFulfillmentIdentity, ShopifyFulfillmentGid,
    ShopifyFulfillmentReadback, ShopifyFulfillmentReadbackRequest,
    ShopifyFulfillmentReceiptIdentity, ShopifyFulfillmentStatus, ShopifyNativeReadbackError,
    ShopifyReadbackCancellation, UreqShopifyAdminReadbackTransport,
};
use hartevo_connector_sdk::ProviderProvenanceClass;
use hartevo_effect_broker::secret_broker::SECRET_BROKER_DISPATCH_LEASE_TTL_SECONDS;
use hartevo_effect_broker::{
    MissionSecretReference as BrokerSecretReference, ProviderAdapterIdentity,
    ProviderAdapterOperation, ProviderAdapterRegistry, ProviderCapabilityKey,
    ProviderCapabilitySupport, ProviderContractError, ProviderEvidenceClass,
    ProviderEvidenceSupport, SecretBrokerConsumer, SecretBrokerError, SecretBrokerProvider,
    SecretBrokerService, SecretBrokerServiceDefinition, SecretProviderError, SecretScope,
    SecretUseHandle, SecretUseReceipt,
};
use hartevo_storage::{SecretReference as StorageSecretReference, SecretStore, SecretStoreError};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SHOPIFY_READBACK_ADAPTER_ID: &str = "application.shopify.fulfillment.readback";
pub const SHOPIFY_READBACK_ADAPTER_VERSION: u32 = 1;
pub const SHOPIFY_READBACK_REGISTRY_VERSION: &str = "cordis-shopify-readback-2026-07-v1";
pub const SHOPIFY_READBACK_SECRET_PURPOSE: &str = "admin-graphql-fulfillment-readback";

pub fn shopify_readback_adapter_identity() -> Result<ProviderAdapterIdentity, ProviderContractError>
{
    ProviderAdapterIdentity::new(
        SHOPIFY_READBACK_ADAPTER_ID,
        SHOPIFY_READBACK_ADAPTER_VERSION,
    )
}

/// Builds a call-local metadata registry. It grants no Connected, execution,
/// Receipt, Verification, or E4 authority.
pub fn shopify_readback_registry() -> Result<ProviderAdapterRegistry, ProviderContractError> {
    let support = ProviderEvidenceSupport::new(
        ProviderAdapterOperation::Read,
        ProviderEvidenceClass::ReadObservation,
        ProviderProvenanceClass::ProductionProvider,
    )?;
    let registration = ProviderCapabilitySupport::new(
        ProviderCapabilityKey::new(SHOPIFY_PROVIDER_ID, SHOPIFY_FULFILLMENT_CAPABILITY)?,
        shopify_readback_adapter_identity()?,
        [support],
    )?;
    ProviderAdapterRegistry::new(SHOPIFY_READBACK_REGISTRY_VERSION, [registration])
}

/// Exact metadata binding between the broker reference and the OS-keyring
/// entry. The reference ID is derived from the secure-store credential ID, so
/// swapping either side is rejected inside the final provider callback.
#[derive(Clone, Eq, PartialEq)]
pub struct ShopifyReadbackCredentialBinding {
    scope: SecretScope,
    shop: hartevo_commerce_connector::shopify::ShopDomain,
    storage_reference: StorageSecretReference,
    broker_reference_id: String,
}

impl ShopifyReadbackCredentialBinding {
    pub fn new(
        scope: SecretScope,
        shop: hartevo_commerce_connector::shopify::ShopDomain,
        credential_revision: u64,
    ) -> Result<Self, ShopifyReadbackBridgeError> {
        let validated_shop =
            hartevo_commerce_connector::shopify::ShopDomain::parse(shop.as_str().to_owned())
                .map_err(|_| ShopifyReadbackBridgeError::BindingMismatch)?;
        drop(shop);
        if scope.provider_id() != SHOPIFY_PROVIDER_ID
            || scope.capability_id() != SHOPIFY_FULFILLMENT_CAPABILITY
            || credential_revision == 0
        {
            return Err(ShopifyReadbackBridgeError::BindingMismatch);
        }
        let storage_reference = StorageSecretReference {
            tenant_id: scope.tenant_id().clone(),
            project_id: scope.project_id().clone(),
            provider: SHOPIFY_PROVIDER_ID.to_owned(),
            account_scope: format!(
                "{}@{}",
                scope.account_id().as_str(),
                validated_shop.as_str()
            ),
            purpose: SHOPIFY_READBACK_SECRET_PURPOSE.to_owned(),
            version: credential_revision,
        };
        let credential_id = storage_reference.credential_id()?;
        Ok(Self {
            scope,
            shop: validated_shop,
            storage_reference,
            broker_reference_id: format!("secret-ref-{credential_id}"),
        })
    }

    pub fn scope(&self) -> &SecretScope {
        &self.scope
    }

    pub fn shop(&self) -> &hartevo_commerce_connector::shopify::ShopDomain {
        &self.shop
    }

    pub fn storage_reference(&self) -> &StorageSecretReference {
        &self.storage_reference
    }

    pub fn broker_reference_id(&self) -> &str {
        &self.broker_reference_id
    }

    pub const fn credential_revision(&self) -> u64 {
        self.storage_reference.version
    }

    pub fn broker_reference(
        &self,
        service: &SecretBrokerServiceDefinition,
    ) -> Result<BrokerSecretReference, ShopifyReadbackBridgeError> {
        BrokerSecretReference::new(
            self.broker_reference_id.clone(),
            service,
            self.scope.clone(),
            self.credential_revision(),
        )
        .map_err(ShopifyReadbackBridgeError::from)
    }

    fn validate_handle(
        &self,
        handle: &SecretUseHandle,
    ) -> Result<(), ShopifyReadbackProviderError> {
        let max_expires_at = handle
            .issued_at()
            .checked_add_signed(chrono::Duration::seconds(
                i64::try_from(SECRET_BROKER_DISPATCH_LEASE_TTL_SECONDS)
                    .map_err(|_| ShopifyReadbackProviderError::BindingMismatch)?,
            ))
            .ok_or(ShopifyReadbackProviderError::BindingMismatch)?;
        if handle.reference_id() != self.broker_reference_id
            || handle.scope() != &self.scope
            || handle.credential_revision() != self.credential_revision()
            || handle.adapter()
                != &shopify_readback_adapter_identity()
                    .map_err(|_| ShopifyReadbackProviderError::BindingMismatch)?
            || handle.issued_at() >= handle.expires_at()
            || handle.expires_at() > max_expires_at
        {
            return Err(ShopifyReadbackProviderError::BindingMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ShopifyReadbackCredentialBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyReadbackCredentialBinding")
            .field("scope_digest", &"[DIGEST]")
            .field("shop", &"[REDACTED]")
            .field("storage_reference", &"[REDACTED]")
            .field("credential_revision", &self.credential_revision())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum ShopifyReadbackBridgeError {
    #[error("Shopify readback binding does not match the exact broker/keyring scope")]
    BindingMismatch,
    #[error("Shopify readback provider callback did not produce a typed outcome")]
    MissingProviderOutcome,
    #[error("Shopify readback did not contain an exact receipt identity")]
    MissingReceiptIdentity,
    #[error("Shopify receipt identity is stale, future-dated, or malformed")]
    InvalidReceiptIdentity,
    #[error(transparent)]
    ProviderContract(#[from] ProviderContractError),
    #[error(transparent)]
    SecretBroker(#[from] SecretBrokerError),
    #[error(transparent)]
    SecretStore(#[from] SecretStoreError),
    #[error(transparent)]
    Transport(#[from] ShopifyNativeReadbackError),
}

#[derive(Debug, Error)]
enum ShopifyReadbackProviderError {
    #[error("Shopify readback binding mismatch")]
    BindingMismatch,
    #[error(transparent)]
    SecretStore(#[from] SecretStoreError),
    #[error(transparent)]
    Transport(#[from] ShopifyNativeReadbackError),
}

/// Provider object that exists only below the Application boundary. It holds
/// no credential bytes; the secure store is read inside `use_opaque_credential`.
pub struct ShopifySecretReadbackProvider<'a, S, T> {
    secret_store: &'a S,
    binding: ShopifyReadbackCredentialBinding,
    request: ShopifyFulfillmentReadbackRequest,
    cancellation: ShopifyReadbackCancellation,
    transport: T,
    identity: ProviderAdapterIdentity,
    expected_provenance: ProviderProvenanceClass,
    outcome: Option<Result<ShopifyFulfillmentReadback, ShopifyReadbackProviderError>>,
}

impl<'a, S> ShopifySecretReadbackProvider<'a, S, UreqShopifyAdminReadbackTransport>
where
    S: SecretStore,
{
    /// The production constructor is intentionally sealed to the concrete
    /// native transport type; a custom trait implementation cannot self-claim
    /// production provenance.
    pub fn new_native(
        secret_store: &'a S,
        binding: ShopifyReadbackCredentialBinding,
        request: ShopifyFulfillmentReadbackRequest,
        cancellation: ShopifyReadbackCancellation,
        transport: UreqShopifyAdminReadbackTransport,
    ) -> Result<Self, ShopifyReadbackBridgeError> {
        Self::new(
            secret_store,
            binding,
            request,
            cancellation,
            transport,
            ProviderProvenanceClass::ProductionProvider,
        )
    }
}

impl<'a, S, T> ShopifySecretReadbackProvider<'a, S, T>
where
    S: SecretStore,
    T: ShopifyAdminReadbackTransport,
{
    fn new(
        secret_store: &'a S,
        binding: ShopifyReadbackCredentialBinding,
        request: ShopifyFulfillmentReadbackRequest,
        cancellation: ShopifyReadbackCancellation,
        transport: T,
        expected_provenance: ProviderProvenanceClass,
    ) -> Result<Self, ShopifyReadbackBridgeError> {
        if binding.shop() != request.shop() {
            return Err(ShopifyReadbackBridgeError::BindingMismatch);
        }
        Ok(Self {
            secret_store,
            binding,
            request,
            cancellation,
            transport,
            identity: shopify_readback_adapter_identity()?,
            expected_provenance,
            outcome: None,
        })
    }

    #[cfg(test)]
    fn fixture(
        secret_store: &'a S,
        binding: ShopifyReadbackCredentialBinding,
        request: ShopifyFulfillmentReadbackRequest,
        cancellation: ShopifyReadbackCancellation,
        transport: T,
    ) -> Result<Self, ShopifyReadbackBridgeError> {
        Self::new(
            secret_store,
            binding,
            request,
            cancellation,
            transport,
            ProviderProvenanceClass::Fixture,
        )
    }

    fn take_outcome(
        &mut self,
    ) -> Option<Result<ShopifyFulfillmentReadback, ShopifyReadbackProviderError>> {
        self.outcome.take()
    }
}

impl<S, T> fmt::Debug for ShopifySecretReadbackProvider<'_, S, T>
where
    S: SecretStore,
    T: ShopifyAdminReadbackTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifySecretReadbackProvider")
            .field("scope_digest", &"[DIGEST]")
            .field("credential_revision", &self.binding.credential_revision())
            .field("request_selector", &"[DIGEST]")
            .field(
                "has_expected_identity",
                &self.request.expected_identity().is_some(),
            )
            .field("expected_provenance", &self.expected_provenance)
            .field("has_outcome", &self.outcome.is_some())
            .finish_non_exhaustive()
    }
}

impl<S, T> SecretBrokerProvider for ShopifySecretReadbackProvider<'_, S, T>
where
    S: SecretStore,
    T: ShopifyAdminReadbackTransport,
{
    fn identity(&self) -> &ProviderAdapterIdentity {
        &self.identity
    }

    fn use_opaque_credential(
        &mut self,
        handle: &SecretUseHandle,
    ) -> Result<(), SecretProviderError> {
        self.outcome = None;
        let outcome = (|| {
            self.binding.validate_handle(handle)?;
            let secret = self.secret_store.get(self.binding.storage_reference())?;
            let readback =
                self.transport
                    .readback(secret.as_slice(), &self.request, &self.cancellation)?;
            if readback.provenance_class() != self.expected_provenance
                || readback.fulfillment_id() != self.request.fulfillment_id()
                || readback.api_version() != self.request.api_version()
            {
                return Err(ShopifyReadbackProviderError::BindingMismatch);
            }
            Ok(readback)
        })();
        let provider_error = outcome.as_ref().err().map(classify_provider_error);
        self.outcome = Some(outcome);
        provider_error.map_or(Ok(()), Err)
    }
}

fn classify_provider_error(error: &ShopifyReadbackProviderError) -> SecretProviderError {
    match error {
        ShopifyReadbackProviderError::SecretStore(SecretStoreError::BackendUnavailable)
        | ShopifyReadbackProviderError::Transport(
            ShopifyNativeReadbackError::TimedOut
            | ShopifyNativeReadbackError::RateLimited
            | ShopifyNativeReadbackError::TransportUnavailable
            | ShopifyNativeReadbackError::CancelledAfterDispatch,
        ) => SecretProviderError::Unavailable,
        ShopifyReadbackProviderError::BindingMismatch
        | ShopifyReadbackProviderError::SecretStore(_)
        | ShopifyReadbackProviderError::Transport(_) => SecretProviderError::Rejected,
    }
}

/// Readback plus the broker's content-free proof that the credential-use lease
/// was reclaimed before this value left Application.
pub struct ShopifyBrokeredReadback {
    readback: ShopifyFulfillmentReadback,
    credential_use: SecretUseReceipt,
}

impl fmt::Debug for ShopifyBrokeredReadback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyBrokeredReadback")
            .field("readback", &self.readback)
            .field("credential_use_digest", &"[DIGEST]")
            .field("lease_reclaimed", &self.credential_use.lease_reclaimed())
            .finish()
    }
}

/// Redacted metadata that may leave the Application/provider boundary. It is
/// an observation only: no provider Receipt, Verification, or Mission result
/// can be reconstructed from this value.
#[derive(Clone, Eq, PartialEq)]
pub struct ShopifyReadbackMetadata {
    pub fulfillment_id: ShopifyFulfillmentGid,
    pub status: ShopifyFulfillmentStatus,
    pub api_version: ShopifyApiVersion,
    pub request_id_digest: Option<String>,
    pub evidence_digest: String,
    pub credential_use_digest: String,
    pub lease_reclaimed: bool,
    pub provenance_class: ProviderProvenanceClass,
}

impl fmt::Debug for ShopifyReadbackMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyReadbackMetadata")
            .field("fulfillment_id", &"[REDACTED]")
            .field("status", &self.status)
            .field("api_version", &self.api_version)
            .field(
                "request_id_digest",
                &self.request_id_digest.as_ref().map(|_| "[DIGEST]"),
            )
            .field("evidence_digest", &"[DIGEST]")
            .field("credential_use_digest", &"[DIGEST]")
            .field("lease_reclaimed", &self.lease_reclaimed)
            .field("provenance_class", &self.provenance_class)
            .finish()
    }
}

/// Redacted, exact provider identity observation. This is sufficient for a
/// later reviewed Receipt mapper, but is not itself a Domain Receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct ShopifyReadbackIdentityMetadata {
    pub fulfillment_id: ShopifyFulfillmentGid,
    pub status: ShopifyFulfillmentStatus,
    pub api_version: ShopifyApiVersion,
    pub order_id: ShopifyOrderGid,
    pub fulfillment_order_id: ShopifyFulfillmentOrderGid,
    pub line_item_binding_digest: String,
    pub provider_created_at: DateTime<Utc>,
    pub provider_updated_at: DateTime<Utc>,
    pub request_id_digest: Option<String>,
    pub response_digest: String,
    pub evidence_digest: String,
    pub credential_use_digest: String,
    pub lease_reclaimed: bool,
    pub provenance_class: ProviderProvenanceClass,
}

impl fmt::Debug for ShopifyReadbackIdentityMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyReadbackIdentityMetadata")
            .field("identity", &"[REDACTED]")
            .field("line_item_binding_digest", &"[DIGEST]")
            .field(
                "request_id_digest",
                &self.request_id_digest.as_ref().map(|_| "[DIGEST]"),
            )
            .field("response_digest", &"[DIGEST]")
            .field("evidence_digest", &"[DIGEST]")
            .field("credential_use_digest", &"[DIGEST]")
            .field("lease_reclaimed", &self.lease_reclaimed)
            .field("provenance_class", &self.provenance_class)
            .finish_non_exhaustive()
    }
}

impl ShopifyBrokeredReadback {
    pub fn readback(&self) -> &ShopifyFulfillmentReadback {
        &self.readback
    }

    pub fn credential_use(&self) -> &SecretUseReceipt {
        &self.credential_use
    }

    /// Returns only typed provider metadata and content-free lease evidence.
    /// The full brokered value remains below the Desktop projection boundary.
    pub fn metadata(&self) -> ShopifyReadbackMetadata {
        ShopifyReadbackMetadata {
            fulfillment_id: self.readback.fulfillment_id().clone(),
            status: self.readback.status().clone(),
            api_version: self.readback.api_version().clone(),
            request_id_digest: self.readback.request_id_digest().map(str::to_owned),
            evidence_digest: self.readback.evidence_digest().to_owned(),
            credential_use_digest: self.credential_use.use_digest().to_owned(),
            lease_reclaimed: self.credential_use.lease_reclaimed(),
            provenance_class: self.readback.provenance_class(),
        }
    }

    /// Projects the exact identity only after provider timestamps and the
    /// reclaimed credential lease are checked at the Application boundary.
    pub fn identity_metadata(
        &self,
        now: DateTime<Utc>,
    ) -> Result<ShopifyReadbackIdentityMetadata, ShopifyReadbackBridgeError> {
        let identity = self
            .readback
            .receipt_identity()
            .ok_or(ShopifyReadbackBridgeError::MissingReceiptIdentity)?;
        if identity.provider_created_at() < identity.provider_created_at_not_before()
            || identity.provider_updated_at() < identity.provider_created_at()
            || identity.provider_created_at() > now
            || identity.provider_updated_at() > now
            || !self.credential_use.lease_reclaimed()
            || !is_sha256(identity.response_digest())
            || !is_sha256(self.readback.evidence_digest())
            || !is_sha256(self.credential_use.use_digest())
        {
            return Err(ShopifyReadbackBridgeError::InvalidReceiptIdentity);
        }
        Ok(ShopifyReadbackIdentityMetadata {
            fulfillment_id: self.readback.fulfillment_id().clone(),
            status: self.readback.status().clone(),
            api_version: self.readback.api_version().clone(),
            order_id: identity.order_id().clone(),
            fulfillment_order_id: identity.fulfillment_order_id().clone(),
            line_item_binding_digest: line_item_binding_digest(identity),
            provider_created_at: identity.provider_created_at(),
            provider_updated_at: identity.provider_updated_at(),
            request_id_digest: self.readback.request_id_digest().map(str::to_owned),
            response_digest: identity.response_digest().to_owned(),
            evidence_digest: self.readback.evidence_digest().to_owned(),
            credential_use_digest: self.credential_use.use_digest().to_owned(),
            lease_reclaimed: true,
            provenance_class: self.readback.provenance_class(),
        })
    }
}

fn line_item_binding_digest(identity: &ShopifyFulfillmentReceiptIdentity) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, "hartevo-shopify-readback-line-items/v1");
    for item in identity.line_items() {
        hash_field(&mut digest, item.line_item_gid.as_str());
        hash_field(&mut digest, &item.quantity.to_string());
    }
    format!("{:x}", digest.finalize())
}

pub(crate) fn approved_line_item_binding_digest(items: &[ShopifyFulfillmentLineItem]) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, "hartevo-shopify-readback-line-items/v1");
    for item in items {
        hash_field(&mut digest, item.line_item_gid.as_str());
        hash_field(&mut digest, &item.quantity.to_string());
    }
    format!("{:x}", digest.finalize())
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_be_bytes());
    digest.update(value.as_bytes());
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn dispatch_shopify_readback<S, T>(
    consumer: &SecretBrokerConsumer,
    service: &mut SecretBrokerService,
    provider: &mut ShopifySecretReadbackProvider<'_, S, T>,
    now: DateTime<Utc>,
) -> Result<ShopifyBrokeredReadback, ShopifyReadbackBridgeError>
where
    S: SecretStore,
    T: ShopifyAdminReadbackTransport,
{
    let registry = shopify_readback_registry()?;
    let dispatch = service.provider_dispatch()?;
    let broker_result =
        consumer.dispatch_with_provider(service, &registry, provider, &dispatch, now);
    let provider_outcome = provider.take_outcome();
    match (broker_result, provider_outcome) {
        (Ok(credential_use), Some(Ok(readback))) => Ok(ShopifyBrokeredReadback {
            readback,
            credential_use,
        }),
        (Err(SecretBrokerError::ProviderRejected(_)), Some(Err(error))) => match error {
            ShopifyReadbackProviderError::BindingMismatch => {
                Err(ShopifyReadbackBridgeError::BindingMismatch)
            }
            ShopifyReadbackProviderError::SecretStore(error) => {
                Err(ShopifyReadbackBridgeError::SecretStore(error))
            }
            ShopifyReadbackProviderError::Transport(error) => {
                Err(ShopifyReadbackBridgeError::Transport(error))
            }
        },
        (Err(error), _) => Err(ShopifyReadbackBridgeError::SecretBroker(error)),
        (Ok(_), _) => Err(ShopifyReadbackBridgeError::MissingProviderOutcome),
    }
}

#[cfg(test)]
#[derive(Debug)]
struct ExactFixtureReadbackTransport {
    provider_created_at: DateTime<Utc>,
    provider_updated_at: DateTime<Utc>,
}

#[cfg(test)]
impl ShopifyAdminReadbackTransport for ExactFixtureReadbackTransport {
    fn readback(
        &self,
        _access_token: &[u8],
        request: &ShopifyFulfillmentReadbackRequest,
        cancellation: &ShopifyReadbackCancellation,
    ) -> Result<ShopifyFulfillmentReadback, ShopifyNativeReadbackError> {
        if cancellation.is_cancelled() {
            return Err(ShopifyNativeReadbackError::CancelledBeforeDispatch);
        }
        ShopifyFulfillmentReadback::fixture_exact(
            request,
            "SUCCESS",
            self.provider_created_at,
            self.provider_updated_at,
        )
    }
}

/// Produces an unforgeable brokered fixture for Application boundary tests.
/// This helper is unavailable to production and downstream crates.
#[cfg(test)]
pub(crate) fn fixture_brokered_exact_readback(
    binding: ShopifyReadbackCredentialBinding,
    request: ShopifyFulfillmentReadbackRequest,
    provider_created_at: DateTime<Utc>,
    provider_updated_at: DateTime<Utc>,
    used_at: DateTime<Utc>,
) -> Result<ShopifyBrokeredReadback, ShopifyReadbackBridgeError> {
    let secret_store = hartevo_storage::MemorySecretStore::default();
    secret_store.put(
        binding.storage_reference(),
        &hartevo_storage::SecretBytes::new(b"fixture-only-shopify-readback".to_vec())?,
    )?;
    let definition = SecretBrokerServiceDefinition::production()?;
    let reference = binding.broker_reference(&definition)?;
    let mut service = SecretBrokerService::new(definition, reference)?;
    service.mount(used_at)?;
    let consumer = SecretBrokerConsumer::new(
        "secret-consumer-fixture-shopify-receipt",
        binding.scope().tenant_id().clone(),
        binding.scope().project_id().clone(),
        binding.scope().mission_id().clone(),
    )?;
    let mut provider = ShopifySecretReadbackProvider::fixture(
        &secret_store,
        binding,
        request,
        ShopifyReadbackCancellation::default(),
        ExactFixtureReadbackTransport {
            provider_created_at,
            provider_updated_at,
        },
    )?;
    dispatch_shopify_readback(&consumer, &mut service, &mut provider, used_at)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::{Duration, TimeZone};
    use hartevo_commerce_connector::shopify::{ShopDomain, ShopifyApiVersion};
    use hartevo_commerce_connector::shopify_effect::{
        ShopifyFulfillmentLineItem, ShopifyFulfillmentOrderGid, ShopifyFulfillmentOrderLineItemGid,
        ShopifyOrderGid,
    };
    use hartevo_commerce_connector::shopify_transport::ShopifyFulfillmentGid;
    use hartevo_domain_kernel::{AccountId, MissionId, ProjectId, TenantId};
    use hartevo_storage::{MemorySecretStore, SecretBytes};

    use super::*;

    #[derive(Debug)]
    struct FixtureTransport {
        calls: Arc<AtomicUsize>,
        failure: Option<ShopifyNativeReadbackError>,
    }

    impl ShopifyAdminReadbackTransport for FixtureTransport {
        fn readback(
            &self,
            _access_token: &[u8],
            request: &ShopifyFulfillmentReadbackRequest,
            cancellation: &ShopifyReadbackCancellation,
        ) -> Result<ShopifyFulfillmentReadback, ShopifyNativeReadbackError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if cancellation.is_cancelled() {
                return Err(ShopifyNativeReadbackError::CancelledBeforeDispatch);
            }
            if let Some(error) = self.failure {
                return Err(error);
            }
            if request.expected_identity().is_some() {
                ShopifyFulfillmentReadback::fixture_exact(
                    request,
                    "SUCCESS",
                    now() - Duration::minutes(1),
                    now(),
                )
            } else {
                ShopifyFulfillmentReadback::fixture(request, "SUCCESS")
            }
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 10, 0, 0).unwrap()
    }

    fn scope() -> SecretScope {
        SecretScope::new(
            TenantId::from_stable("tenant-shopify-n12c"),
            ProjectId::from_stable("project-shopify-n12c"),
            MissionId::from_stable("mission-shopify-n12c"),
            SHOPIFY_PROVIDER_ID,
            AccountId::from_stable("account-shopify-n12c"),
            SHOPIFY_FULFILLMENT_CAPABILITY,
        )
        .unwrap()
    }

    fn request(shop: ShopDomain) -> ShopifyFulfillmentReadbackRequest {
        ShopifyFulfillmentReadbackRequest::new(
            shop,
            ShopifyApiVersion::latest(),
            ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
        )
        .unwrap()
    }

    fn exact_request(shop: ShopDomain) -> ShopifyFulfillmentReadbackRequest {
        ShopifyFulfillmentReadbackRequest::new_exact(
            shop,
            ShopifyApiVersion::latest(),
            ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
            ShopifyExpectedFulfillmentIdentity::new(
                ShopifyOrderGid::parse("gid://shopify/Order/1001").unwrap(),
                ShopifyFulfillmentOrderGid::parse("gid://shopify/FulfillmentOrder/2001").unwrap(),
                vec![
                    ShopifyFulfillmentLineItem::new(
                        ShopifyFulfillmentOrderLineItemGid::parse(
                            "gid://shopify/FulfillmentOrderLineItem/4001",
                        )
                        .unwrap(),
                        2,
                    )
                    .unwrap(),
                ],
                now() - Duration::minutes(2),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn consumer(scope: &SecretScope) -> SecretBrokerConsumer {
        SecretBrokerConsumer::new(
            "secret-consumer-shopify-n12c",
            scope.tenant_id().clone(),
            scope.project_id().clone(),
            scope.mission_id().clone(),
        )
        .unwrap()
    }

    fn mounted_service(binding: &ShopifyReadbackCredentialBinding) -> SecretBrokerService {
        let definition = SecretBrokerServiceDefinition::production().unwrap();
        let reference = binding.broker_reference(&definition).unwrap();
        let mut service = SecretBrokerService::new(definition, reference).unwrap();
        service.mount(now()).unwrap();
        service
    }

    #[test]
    fn brokered_fixture_uses_keyring_only_inside_callback_and_reclaims_lease() {
        let scope = scope();
        let shop = ShopDomain::parse("n12c.myshopify.com").unwrap();
        let binding =
            ShopifyReadbackCredentialBinding::new(scope.clone(), shop.clone(), 7).unwrap();
        let secrets = MemorySecretStore::default();
        secrets
            .put(
                binding.storage_reference(),
                &SecretBytes::new(b"shpat_test-only-never-logged".to_vec()).unwrap(),
            )
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut provider = ShopifySecretReadbackProvider::fixture(
            &secrets,
            binding.clone(),
            request(shop),
            ShopifyReadbackCancellation::default(),
            FixtureTransport {
                calls: Arc::clone(&calls),
                failure: None,
            },
        )
        .unwrap();
        let mut service = mounted_service(&binding);
        let outcome = dispatch_shopify_readback(
            &consumer(&scope),
            &mut service,
            &mut provider,
            now() + Duration::seconds(1),
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.readback().status().as_str(), "SUCCESS");
        assert_eq!(
            outcome.readback().provenance_class(),
            ProviderProvenanceClass::Fixture
        );
        assert!(outcome.credential_use().lease_reclaimed());
        let metadata = outcome.metadata();
        assert_eq!(
            metadata.fulfillment_id.as_str(),
            "gid://shopify/Fulfillment/3001"
        );
        assert_eq!(metadata.status.as_str(), "SUCCESS");
        assert_eq!(metadata.provenance_class, ProviderProvenanceClass::Fixture);
        assert!(metadata.lease_reclaimed);
        assert_eq!(metadata.evidence_digest.len(), 64);
        assert_eq!(metadata.credential_use_digest.len(), 64);
        assert_eq!(service.active_lease_count(), 0);
        let debug = format!("{provider:?} {outcome:?} {binding:?}");
        assert!(!debug.contains("shpat_test"));
        assert!(!debug.contains("never-logged"));
    }

    #[test]
    fn exact_identity_projection_is_redacted_time_bounded_and_lease_reclaimed() {
        let scope = scope();
        let shop = ShopDomain::parse("n12c.myshopify.com").unwrap();
        let binding =
            ShopifyReadbackCredentialBinding::new(scope.clone(), shop.clone(), 7).unwrap();
        let secrets = MemorySecretStore::default();
        secrets
            .put(
                binding.storage_reference(),
                &SecretBytes::new(b"shpat_exact-test-only-never-logged".to_vec()).unwrap(),
            )
            .unwrap();
        let mut provider = ShopifySecretReadbackProvider::fixture(
            &secrets,
            binding.clone(),
            exact_request(shop),
            ShopifyReadbackCancellation::default(),
            FixtureTransport {
                calls: Arc::new(AtomicUsize::new(0)),
                failure: None,
            },
        )
        .unwrap();
        let mut service = mounted_service(&binding);
        let outcome = dispatch_shopify_readback(
            &consumer(&scope),
            &mut service,
            &mut provider,
            now() + Duration::seconds(1),
        )
        .unwrap();
        let metadata = outcome
            .identity_metadata(now() + Duration::seconds(1))
            .unwrap();
        let generic_metadata = outcome.metadata();
        assert_eq!(metadata.order_id.as_str(), "gid://shopify/Order/1001");
        assert_eq!(
            metadata.fulfillment_order_id.as_str(),
            "gid://shopify/FulfillmentOrder/2001"
        );
        assert_eq!(metadata.line_item_binding_digest.len(), 64);
        assert_eq!(metadata.response_digest.len(), 64);
        assert_eq!(metadata.evidence_digest.len(), 64);
        assert_eq!(metadata.credential_use_digest.len(), 64);
        assert!(metadata.lease_reclaimed);
        assert_eq!(service.active_lease_count(), 0);
        assert!(matches!(
            outcome.identity_metadata(now() - Duration::seconds(1)),
            Err(ShopifyReadbackBridgeError::InvalidReceiptIdentity)
        ));
        let debug =
            format!("{metadata:?} {generic_metadata:?} {provider:?} {outcome:?} {binding:?}");
        assert!(!debug.contains("shpat_exact"));
        assert!(!debug.contains("never-logged"));
        for private in [
            "n12c.myshopify.com",
            "gid://shopify/Fulfillment/3001",
            "gid://shopify/Order/1001",
            "gid://shopify/FulfillmentOrder/2001",
            "gid://shopify/FulfillmentOrderLineItem/4001",
            "line_items",
            "quantity",
            hartevo_commerce_connector::shopify_transport::SHOPIFY_RECEIPT_IDENTITY_QUERY,
            binding.broker_reference_id(),
        ] {
            assert!(!debug.contains(private), "Debug leaked {private}");
        }
        assert!(!debug.contains(&format!("{:?}", binding.storage_reference())));
    }

    #[test]
    fn callback_failure_reclaims_lease_and_does_not_become_connected() {
        let scope = scope();
        let shop = ShopDomain::parse("n12c.myshopify.com").unwrap();
        let binding =
            ShopifyReadbackCredentialBinding::new(scope.clone(), shop.clone(), 7).unwrap();
        let secrets = MemorySecretStore::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut provider = ShopifySecretReadbackProvider::fixture(
            &secrets,
            binding.clone(),
            request(shop),
            ShopifyReadbackCancellation::default(),
            FixtureTransport {
                calls: Arc::clone(&calls),
                failure: None,
            },
        )
        .unwrap();
        let mut service = mounted_service(&binding);
        assert!(matches!(
            dispatch_shopify_readback(
                &consumer(&scope),
                &mut service,
                &mut provider,
                now() + Duration::seconds(1),
            ),
            Err(ShopifyReadbackBridgeError::SecretStore(
                SecretStoreError::SecretNotFound
            ))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(service.active_lease_count(), 0);
        assert_eq!(
            shopify_readback_registry().unwrap().registrations().len(),
            1
        );
        assert_eq!(
            shopify_readback_registry().unwrap().authority(),
            hartevo_effect_broker::ProviderEvidenceAuthority::MetadataBindingOnly
        );
    }

    #[test]
    fn wrong_reference_and_cancellation_fail_closed_after_reclaim() {
        let scope = scope();
        let shop = ShopDomain::parse("n12c.myshopify.com").unwrap();
        let binding =
            ShopifyReadbackCredentialBinding::new(scope.clone(), shop.clone(), 7).unwrap();
        let secrets = MemorySecretStore::default();
        secrets
            .put(
                binding.storage_reference(),
                &SecretBytes::new(b"fixture-token".to_vec()).unwrap(),
            )
            .unwrap();
        let cancellation = ShopifyReadbackCancellation::default();
        cancellation.cancel();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut provider = ShopifySecretReadbackProvider::fixture(
            &secrets,
            binding.clone(),
            request(shop),
            cancellation,
            FixtureTransport {
                calls: Arc::clone(&calls),
                failure: None,
            },
        )
        .unwrap();
        let definition = SecretBrokerServiceDefinition::production().unwrap();
        let wrong =
            BrokerSecretReference::new("secret-ref-shopify-wrong", &definition, scope.clone(), 7)
                .unwrap();
        let mut service = SecretBrokerService::new(definition, wrong).unwrap();
        service.mount(now()).unwrap();
        assert!(matches!(
            dispatch_shopify_readback(
                &consumer(&scope),
                &mut service,
                &mut provider,
                now() + Duration::seconds(1),
            ),
            Err(ShopifyReadbackBridgeError::BindingMismatch)
        ));
        assert_eq!(service.active_lease_count(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn production_constructor_is_sealed_to_native_transport_and_shop_drift_fails() {
        let scope = scope();
        let bypassed_shop: ShopDomain =
            serde_json::from_str("\"safe.myshopify.com@attacker.example\"").unwrap();
        assert!(matches!(
            ShopifyReadbackCredentialBinding::new(scope.clone(), bypassed_shop, 7),
            Err(ShopifyReadbackBridgeError::BindingMismatch)
        ));
        let shop = ShopDomain::parse("n12c.myshopify.com").unwrap();
        let binding = ShopifyReadbackCredentialBinding::new(scope, shop.clone(), 7).unwrap();
        let secrets = MemorySecretStore::default();
        let native = ShopifySecretReadbackProvider::new_native(
            &secrets,
            binding.clone(),
            request(shop),
            ShopifyReadbackCancellation::default(),
            UreqShopifyAdminReadbackTransport::new(),
        )
        .unwrap();
        assert!(format!("{native:?}").contains("ProductionProvider"));
        assert!(matches!(
            ShopifySecretReadbackProvider::fixture(
                &secrets,
                binding,
                request(ShopDomain::parse("other.myshopify.com").unwrap()),
                ShopifyReadbackCancellation::default(),
                FixtureTransport {
                    calls: Arc::new(AtomicUsize::new(0)),
                    failure: None,
                },
            ),
            Err(ShopifyReadbackBridgeError::BindingMismatch)
        ));
    }

    #[test]
    fn revoked_service_never_issues_a_provider_callback() {
        let scope = scope();
        let shop = ShopDomain::parse("n12c.myshopify.com").unwrap();
        let binding =
            ShopifyReadbackCredentialBinding::new(scope.clone(), shop.clone(), 7).unwrap();
        let secrets = MemorySecretStore::default();
        secrets
            .put(
                binding.storage_reference(),
                &SecretBytes::new(b"fixture-token".to_vec()).unwrap(),
            )
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut provider = ShopifySecretReadbackProvider::fixture(
            &secrets,
            binding.clone(),
            request(shop),
            ShopifyReadbackCancellation::default(),
            FixtureTransport {
                calls: Arc::clone(&calls),
                failure: None,
            },
        )
        .unwrap();
        let mut service = mounted_service(&binding);
        service.revoke(now() + Duration::seconds(1)).unwrap();
        assert!(matches!(
            dispatch_shopify_readback(
                &consumer(&scope),
                &mut service,
                &mut provider,
                now() + Duration::seconds(2),
            ),
            Err(ShopifyReadbackBridgeError::SecretBroker(
                SecretBrokerError::ReferenceRevoked
            ))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(service.active_lease_count(), 0);
    }
}

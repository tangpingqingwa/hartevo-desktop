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
pub use hartevo_commerce_connector::shopify::SHOPIFY_PROVIDER_ID;
pub use hartevo_commerce_connector::shopify::ShopifyApiVersion;
pub use hartevo_commerce_connector::shopify_effect::SHOPIFY_FULFILLMENT_CAPABILITY;
pub use hartevo_commerce_connector::shopify_transport::{
    ShopifyAdminReadbackTransport, ShopifyFulfillmentGid, ShopifyFulfillmentReadback,
    ShopifyFulfillmentReadbackRequest, ShopifyFulfillmentStatus, ShopifyNativeReadbackError,
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
            .field("scope_digest", &self.scope.digest())
            .field("shop", &self.shop)
            .field("storage_reference", &self.storage_reference)
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
            .field("binding", &self.binding)
            .field("request", &self.request)
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
#[derive(Debug)]
pub struct ShopifyBrokeredReadback {
    readback: ShopifyFulfillmentReadback,
    credential_use: SecretUseReceipt,
}

/// Redacted metadata that may leave the Application/provider boundary. It is
/// an observation only: no provider Receipt, Verification, or Mission result
/// can be reconstructed from this value.
#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Naming alias for callers that describe the value as a projection.
pub type ShopifyReadbackMetadataProjection = ShopifyReadbackMetadata;

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
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::{Duration, TimeZone};
    use hartevo_commerce_connector::shopify::{ShopDomain, ShopifyApiVersion};
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
            ShopifyFulfillmentReadback::fixture(request, "SUCCESS")
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

//! Provider-specific Application compositions.
//!
//! These modules adapt a pre-validated provider capsule to the generic Effect
//! Broker ports.  They do not register live providers or own Effect authority.

pub mod shopify;
pub mod shopify_readback;
pub mod shopify_recovery;

pub use shopify::{
    ShopifyAdapterError, ShopifyEffectAdapter, ShopifyEffectAdapterHandles, ShopifyEffectExecutor,
    ShopifyEffectReconciler, ShopifyEffectVerifier, ShopifyProviderAdapter,
    compose_controlled_shopify_effect_adapter, compose_shopify_effect_adapter,
};
pub use shopify_readback::{
    SHOPIFY_INDEPENDENT_VERIFICATION_ADAPTER_ID, SHOPIFY_INDEPENDENT_VERIFICATION_ADAPTER_VERSION,
    SHOPIFY_INDEPENDENT_VERIFICATION_REGISTRY_VERSION, SHOPIFY_READBACK_ADAPTER_ID,
    SHOPIFY_READBACK_ADAPTER_VERSION, ShopifyBrokeredReadback, ShopifyFulfillmentReadbackRequest,
    ShopifyReadbackBridgeError, ShopifyReadbackCancellation, ShopifyReadbackCredentialBinding,
    ShopifySecretReadbackProvider, UreqShopifyAdminReadbackTransport, dispatch_shopify_readback,
    shopify_readback_adapter_identity, shopify_readback_registry,
};
pub use shopify_recovery::{
    ClaimedShopifyRecovery, ReopenedShopifyVerification, ShopifyIndependentVerificationSource,
    ShopifyRecoveryCapsuleRef, ShopifyRecoveryError, ShopifySecureRecovery,
};

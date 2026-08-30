//! Provider-specific Application compositions.
//!
//! These modules adapt a pre-validated provider capsule to the generic Effect
//! Broker ports.  They do not register live providers or own Effect authority.

pub mod shopify;
pub mod shopify_recovery;

pub use shopify::{
    ShopifyAdapterError, ShopifyEffectAdapter, ShopifyEffectAdapterHandles, ShopifyEffectExecutor,
    ShopifyEffectReconciler, ShopifyEffectVerifier, ShopifyProviderAdapter,
    compose_controlled_shopify_effect_adapter, compose_shopify_effect_adapter,
};
pub use shopify_recovery::{
    ClaimedShopifyRecovery, ShopifyRecoveryCapsuleRef, ShopifyRecoveryError, ShopifySecureRecovery,
};

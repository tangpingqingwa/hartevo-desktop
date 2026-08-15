//! Read-only commerce Connector Plane vertical slice.
//!
//! The crate deliberately stops at provider-specific typed boundaries.  It
//! does not define a replacement Connector SDK, register a provider as
//! Connected, execute an external write, manufacture a Receipt, or perform
//! business Verification.  Generic lifecycle and worker boundaries come from
//! `hartevo-connector-sdk`; this crate contributes only commerce provider
//! models, read transports, and deterministic test worlds.

pub mod amazon;
mod canonical;
pub mod shopify;
pub mod shopify_effect;
pub mod shopify_effect_reconcile;
pub mod sorftime;
pub mod sorftime_plugin;
pub mod world;

pub use canonical::{
    Asin, CanonicalIdentityError, CanonicalMoney, CanonicalSku, CanonicalTime, FirstPartyProvider,
    InventoryIdentity, ListingIdentity, ListingKey, MarketId, MarketIdentity, OrderIdentity,
    RefundIdentity,
};
pub use hartevo_connector_sdk::{ProviderAdapterIdentity, ProviderContractError};

pub const COMMERCE_CONNECTOR_CONTRACT_JSON: &str =
    include_str!("../../../contracts/providers/commerce-readonly.v1.json");
pub const COMMERCE_CONNECTOR_CONTRACT_VERSION: &str = "commerce-01-readonly/v1";
pub const COMMERCE_CONNECTOR_SCHEMA_VERSION: &str = "hartevo-commerce-connector-contract/v1";
pub const SHOPIFY_ADAPTER_ID: &str = "commerce.shopify.readonly";
pub const AMAZON_ADAPTER_ID: &str = "commerce.amazon-sp-api.readonly";
pub const SORFTIME_ADAPTER_ID: &str = "commerce.sorftime.estimate-only";

pub fn shopify_adapter_identity() -> Result<ProviderAdapterIdentity, ProviderContractError> {
    ProviderAdapterIdentity::new(SHOPIFY_ADAPTER_ID, 1)
}

pub fn amazon_adapter_identity() -> Result<ProviderAdapterIdentity, ProviderContractError> {
    ProviderAdapterIdentity::new(AMAZON_ADAPTER_ID, 1)
}

pub fn sorftime_adapter_identity() -> Result<ProviderAdapterIdentity, ProviderContractError> {
    ProviderAdapterIdentity::new(SORFTIME_ADAPTER_ID, 1)
}

/// A first PR is intentionally only an E1 read model and deterministic seam.
pub const EVIDENCE_LEVEL: &str = "E1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn provider_execution() -> bool {
        false
    }

    pub const fn provider_receipt() -> bool {
        false
    }

    pub const fn business_verification() -> bool {
        false
    }

    pub const fn e4() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        AMAZON_ADAPTER_ID, COMMERCE_CONNECTOR_CONTRACT_JSON, COMMERCE_CONNECTOR_CONTRACT_VERSION,
        COMMERCE_CONNECTOR_SCHEMA_VERSION, EVIDENCE_LEVEL, ReadOnlyAuthority, SHOPIFY_ADAPTER_ID,
        SORFTIME_ADAPTER_ID, amazon_adapter_identity, shopify_adapter_identity,
        sorftime_adapter_identity,
    };

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        evidence_level: String,
        read_only: bool,
        provider_ids: Vec<String>,
        first_party_provider_ids: Vec<String>,
        estimate_only_provider_ids: Vec<String>,
        mixing_forbidden: bool,
        connected: bool,
        provider_execution: bool,
        provider_receipt: bool,
        business_verification: bool,
        e4: bool,
    }

    #[test]
    fn checked_contract_is_read_only_and_source_separated() {
        let document = serde_json::from_str::<ContractDocument>(COMMERCE_CONNECTOR_CONTRACT_JSON)
            .expect("commerce connector contract JSON");
        assert_eq!(document.schema_version, COMMERCE_CONNECTOR_SCHEMA_VERSION);
        assert_eq!(
            document.contract_version,
            COMMERCE_CONNECTOR_CONTRACT_VERSION
        );
        assert_eq!(document.evidence_level, EVIDENCE_LEVEL);
        assert!(document.read_only);
        assert_eq!(
            document.provider_ids,
            vec!["amazon-sp-api", "shopify", "sorftime"]
        );
        assert_eq!(
            document.first_party_provider_ids,
            vec!["amazon-sp-api", "shopify"]
        );
        assert_eq!(document.estimate_only_provider_ids, vec!["sorftime"]);
        assert!(document.mixing_forbidden);
        assert!(!document.connected);
        assert!(!document.provider_execution);
        assert!(!document.provider_receipt);
        assert!(!document.business_verification);
        assert!(!document.e4);
        assert!(!ReadOnlyAuthority::connected());
        assert!(!ReadOnlyAuthority::provider_execution());
        assert!(!ReadOnlyAuthority::provider_receipt());
        assert!(!ReadOnlyAuthority::business_verification());
        assert!(!ReadOnlyAuthority::e4());
    }

    #[test]
    fn provider_adapter_identity_comes_from_connector_sdk() {
        assert_eq!(
            shopify_adapter_identity()
                .expect("Shopify adapter")
                .adapter_id(),
            SHOPIFY_ADAPTER_ID
        );
        assert_eq!(
            amazon_adapter_identity()
                .expect("Amazon adapter")
                .adapter_id(),
            AMAZON_ADAPTER_ID
        );
        assert_eq!(
            sorftime_adapter_identity()
                .expect("Sorftime adapter")
                .adapter_id(),
            SORFTIME_ADAPTER_ID
        );
    }
}

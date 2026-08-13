//! Deterministic VM-08 marketplace world for connector contract tests.
//!
//! The world has two physically separate projections: `first_party` holds
//! Shopify/Amazon account facts, while `estimate_only` holds Sorftime
//! observations.  The structure deliberately has no field through which a
//! Sorftime estimate can be inserted into the first-party collection.

use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use hartevo_domain_kernel::CurrencyCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::amazon::{
    AmazonAccountIdentity, AmazonAccountScope, AmazonMarketplace, AmazonRegion, AmazonRole,
};
use crate::canonical::{
    Asin, CanonicalIdentityError, CanonicalMoney, CanonicalSku, CanonicalTime, InventoryIdentity,
    ListingIdentity, MarketId, MarketIdentity, OrderIdentity, RefundIdentity,
};
use crate::shopify::{
    ShopDomain, ShopifyApiVersion, ShopifyScopeObservation, ShopifyScopeSet, ShopifyShopGid,
    ShopifyShopIdentity,
};
use crate::sorftime::{
    SorftimeAccountId, SorftimeDataset, SorftimeEstimateObservation, SorftimeEvidenceAuthority,
    SorftimeMarket, SorftimeRequestCost, SorftimeRequestProvenance, SorftimeTransportKind,
};

pub const MARKETPLACE_WORLD_SCHEMA_VERSION: &str = "hartevo-marketplace-world/v1";
pub const MARKETPLACE_WORLD_ID: &str = "VM08-COMMERCE-WORLD-01";
pub const MARKETPLACE_WORLD_VERSION: u32 = 1;
pub const MARKETPLACE_WORLD_SEED: &str = "commerce-01-shopify-amazon-sorftime-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFirstPartyConnection {
    pub identity: ShopifyShopIdentity,
    pub scopes: ShopifyScopeObservation,
    pub api_version: ShopifyApiVersion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonFirstPartyConnection {
    pub scope: AmazonAccountScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyProductFact {
    pub identity: ListingIdentity,
    pub title: String,
    pub observed_at: CanonicalTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonInventoryFact {
    pub identity: InventoryIdentity,
    pub quantity: u64,
    pub observed_at: CanonicalTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonOrderFact {
    pub identity: OrderIdentity,
    pub amount: CanonicalMoney,
    pub observed_at: CanonicalTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonRefundFact {
    pub identity: RefundIdentity,
    pub amount: CanonicalMoney,
    pub observed_at: CanonicalTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum FirstPartyCommerceFact {
    ShopifyProduct(ShopifyProductFact),
    AmazonInventory(AmazonInventoryFact),
    AmazonOrder(AmazonOrderFact),
    AmazonRefund(AmazonRefundFact),
}

impl FirstPartyCommerceFact {
    pub fn provider_id(&self) -> &'static str {
        match self {
            Self::ShopifyProduct(_) => "shopify",
            Self::AmazonInventory(_) | Self::AmazonOrder(_) | Self::AmazonRefund(_) => {
                "amazon-sp-api"
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirstPartyWorld {
    pub shopify: ShopifyFirstPartyConnection,
    pub amazon: AmazonFirstPartyConnection,
    pub facts: Vec<FirstPartyCommerceFact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EstimateOnlyWorld {
    pub provider_id: String,
    pub authority: SorftimeEvidenceAuthority,
    pub estimates: Vec<SorftimeEstimateObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeterministicMarketplaceWorld {
    pub schema_version: String,
    pub world_id: String,
    pub world_version: u32,
    pub deterministic_seed: String,
    pub initial_state_digest: String,
    pub virtual_clock: CanonicalTime,
    pub external_network_allowed: bool,
    pub credential_material_embedded: bool,
    pub write_effects_allowed: bool,
    pub first_party: FirstPartyWorld,
    pub estimate_only: EstimateOnlyWorld,
}

impl DeterministicMarketplaceWorld {
    #[allow(clippy::too_many_lines)]
    pub fn fixture() -> Result<Self, MarketplaceWorldError> {
        let observed_at = Utc
            .with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
            .single()
            .ok_or(MarketplaceWorldError::InvalidFixtureTime)?;
        let virtual_clock = CanonicalTime::from_datetime(observed_at);
        let usd = CurrencyCode::parse("USD")
            .map_err(|error| MarketplaceWorldError::InvalidFixture(error.to_string()))?;
        let market = MarketIdentity::new(MarketId::parse("ATVPDKIKX0DER")?, Some("en-US".into()))?;
        let sku = CanonicalSku::parse("MXZONE-FILTER-A")?;
        let asin = Asin::parse("B0C0MERC01")?;
        let shop_domain = ShopDomain::parse("mxzone-demo.myshopify.com")?;
        let shop_identity = ShopifyShopIdentity::new(
            ShopifyShopGid::parse("gid://shopify/Shop/123456789")?,
            shop_domain.clone(),
            "MXZone Demo Store",
        )?;
        let requested_scopes = ShopifyScopeSet::new(vec![
            "read_products".into(),
            "read_orders".into(),
            "read_inventory".into(),
        ])?;
        let granted_scopes = ShopifyScopeSet::new(vec![
            "read_products".into(),
            "read_orders".into(),
            "read_inventory".into(),
        ])?;
        let shopify_listing = ListingIdentity::shopify(
            shop_domain.as_str(),
            market.clone(),
            "gid://shopify/Product/987654321",
            Some(sku.clone()),
        )?;
        let amazon_marketplace =
            AmazonMarketplace::new("ATVPDKIKX0DER", "US", AmazonRegion::NorthAmerica)?;
        let amazon_account = AmazonAccountIdentity::seller("A1SELLER01")?;
        let amazon_scope = AmazonAccountScope::new(
            amazon_account.clone(),
            amazon_marketplace.clone(),
            BTreeSet::from([
                AmazonRole::inventory(),
                AmazonRole::notifications(),
                AmazonRole::product_listing(),
                AmazonRole::reports(),
            ]),
        )?;
        let amazon_listing = ListingIdentity::amazon(
            amazon_account.account_id(),
            market.clone(),
            Some(sku.clone()),
            Some(asin.clone()),
        )?;
        let inventory_identity = InventoryIdentity::new(amazon_listing, Some("PHX-01".into()))?;
        let order_identity = OrderIdentity::new(
            crate::canonical::FirstPartyProvider::AmazonSpApi,
            amazon_account.account_id(),
            market.clone(),
            "701-1234567-1234567",
        )?;
        let refund_identity = RefundIdentity::new(order_identity.clone(), "refund-1001")?;
        let sorftime_account = SorftimeAccountId::parse("sorftime-fixture-account")?;
        let sorftime_market =
            SorftimeMarket::new(MarketId::parse("ATVPDKIKX0DER")?, "en-US", usd.clone())?;
        let request_cost = SorftimeRequestCost::new(3, None, "fixture-price-list/v1", observed_at)?;
        let request_provenance = SorftimeRequestProvenance::new(
            "sorftime-request-1001".into(),
            sorftime_account,
            sorftime_market,
            SorftimeDataset::ProductTrend,
            SorftimeTransportKind::Api,
            "a".repeat(64),
            request_cost,
        )?;
        let estimate = SorftimeEstimateObservation {
            authority: SorftimeEvidenceAuthority::EstimateOnly,
            target_asin: Some(asin),
            estimated_units: Some(420),
            estimated_revenue: Some(CanonicalMoney::new(42_000, usd.clone())),
            observed_at: CanonicalTime::from_datetime(observed_at),
            provenance: request_provenance,
        };
        let first_party = FirstPartyWorld {
            shopify: ShopifyFirstPartyConnection {
                identity: shop_identity,
                scopes: ShopifyScopeObservation {
                    requested: requested_scopes,
                    granted: granted_scopes,
                    observed_at: virtual_clock.clone(),
                },
                api_version: ShopifyApiVersion::latest(),
            },
            amazon: AmazonFirstPartyConnection {
                scope: amazon_scope,
            },
            facts: vec![
                FirstPartyCommerceFact::ShopifyProduct(ShopifyProductFact {
                    identity: shopify_listing,
                    title: "Replacement filter".into(),
                    observed_at: virtual_clock.clone(),
                }),
                FirstPartyCommerceFact::AmazonInventory(AmazonInventoryFact {
                    identity: inventory_identity,
                    quantity: 17,
                    observed_at: virtual_clock.clone(),
                }),
                FirstPartyCommerceFact::AmazonOrder(AmazonOrderFact {
                    identity: order_identity,
                    amount: CanonicalMoney::new(12_999, usd.clone()),
                    observed_at: virtual_clock.clone(),
                }),
                FirstPartyCommerceFact::AmazonRefund(AmazonRefundFact {
                    identity: refund_identity,
                    amount: CanonicalMoney::new(3_000, usd),
                    observed_at: virtual_clock,
                }),
            ],
        };
        let mut world = Self {
            schema_version: MARKETPLACE_WORLD_SCHEMA_VERSION.into(),
            world_id: MARKETPLACE_WORLD_ID.into(),
            world_version: MARKETPLACE_WORLD_VERSION,
            deterministic_seed: MARKETPLACE_WORLD_SEED.into(),
            initial_state_digest: String::new(),
            virtual_clock: CanonicalTime::from_datetime(observed_at),
            external_network_allowed: false,
            credential_material_embedded: false,
            write_effects_allowed: false,
            first_party,
            estimate_only: EstimateOnlyWorld {
                provider_id: "sorftime".into(),
                authority: SorftimeEvidenceAuthority::EstimateOnly,
                estimates: vec![estimate],
            },
        };
        world.initial_state_digest = world.content_digest()?;
        world.validate()?;
        Ok(world)
    }

    pub fn content_digest(&self) -> Result<String, MarketplaceWorldError> {
        let mut snapshot = self.clone();
        snapshot.initial_state_digest.clear();
        let bytes = serde_json::to_vec(&snapshot)
            .map_err(|error| MarketplaceWorldError::Serialization(error.to_string()))?;
        let mut digest = Sha256::new();
        digest.update(bytes);
        Ok(format!("{:x}", digest.finalize()))
    }

    pub fn validate(&self) -> Result<(), MarketplaceWorldError> {
        if self.schema_version != MARKETPLACE_WORLD_SCHEMA_VERSION
            || self.world_id != MARKETPLACE_WORLD_ID
            || self.world_version != MARKETPLACE_WORLD_VERSION
            || self.deterministic_seed != MARKETPLACE_WORLD_SEED
            || self.external_network_allowed
            || self.credential_material_embedded
            || self.write_effects_allowed
        {
            return Err(MarketplaceWorldError::InvalidWorldBoundary);
        }
        if self.first_party.facts.is_empty() || self.estimate_only.estimates.is_empty() {
            return Err(MarketplaceWorldError::MissingFacts);
        }
        if self.estimate_only.provider_id != "sorftime"
            || self.estimate_only.authority != SorftimeEvidenceAuthority::EstimateOnly
            || self.estimate_only.estimates.iter().any(|estimate| {
                !estimate.is_estimate_only()
                    || estimate.provenance.provider_id != "sorftime"
                    || estimate.provenance.request_cost.units == 0
                    || estimate.provenance.request_digest.len() != 64
                    || !estimate
                        .provenance
                        .request_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(MarketplaceWorldError::EstimateAuthorityConflict);
        }
        if self
            .first_party
            .facts
            .iter()
            .any(|fact| fact.provider_id() == "sorftime")
        {
            return Err(MarketplaceWorldError::FirstPartyEstimateMixing);
        }
        let required_scopes = self
            .first_party
            .shopify
            .scopes
            .requested
            .missing_from(&self.first_party.shopify.scopes.granted);
        if !required_scopes.is_empty() {
            return Err(MarketplaceWorldError::MissingShopifyScopes(required_scopes));
        }
        if self
            .first_party
            .facts
            .iter()
            .any(|fact| fact.provider_id() != "shopify" && fact.provider_id() != "amazon-sp-api")
        {
            return Err(MarketplaceWorldError::UnknownFirstPartyProvider);
        }
        Ok(())
    }
}

pub fn marketplace_world() -> Result<DeterministicMarketplaceWorld, MarketplaceWorldError> {
    DeterministicMarketplaceWorld::fixture()
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MarketplaceWorldError {
    #[error("invalid deterministic marketplace fixture time")]
    InvalidFixtureTime,
    #[error("invalid marketplace fixture: {0}")]
    InvalidFixture(String),
    #[error("marketplace world serialization failed: {0}")]
    Serialization(String),
    #[error("canonical identity error: {0}")]
    CanonicalIdentity(#[from] CanonicalIdentityError),
    #[error("Shopify connector error: {0}")]
    Shopify(#[from] crate::shopify::ShopifyError),
    #[error("Amazon connector error: {0}")]
    Amazon(#[from] crate::amazon::AmazonError),
    #[error("Sorftime connector error: {0}")]
    Sorftime(#[from] crate::sorftime::SorftimeError),
    #[error("deterministic world boundary is invalid")]
    InvalidWorldBoundary,
    #[error("deterministic world is missing first-party or estimate facts")]
    MissingFacts,
    #[error("Sorftime estimate authority or provenance is invalid")]
    EstimateAuthorityConflict,
    #[error("first-party facts and Sorftime estimates are mixed")]
    FirstPartyEstimateMixing,
    #[error("required Shopify scope is missing: {0:?}")]
    MissingShopifyScopes(Vec<String>),
    #[error("unknown first-party provider in deterministic world")]
    UnknownFirstPartyProvider,
}

#[allow(dead_code)]
fn _currency_marker(currency: CurrencyCode) -> CurrencyCode {
    currency
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_is_deterministic_and_source_separated() {
        let first = marketplace_world().expect("fixture");
        let second = marketplace_world().expect("fixture");
        assert_eq!(
            first.content_digest().expect("digest"),
            second.content_digest().expect("digest")
        );
        assert_eq!(first.first_party.facts.len(), 4);
        assert_eq!(first.estimate_only.estimates.len(), 1);
        assert!(!first.external_network_allowed);
        assert!(!first.credential_material_embedded);
        assert!(!first.write_effects_allowed);
    }

    #[test]
    fn estimate_authority_mutation_fails_closed() {
        let mut world = marketplace_world().expect("fixture");
        world.estimate_only.provider_id = "amazon-sp-api".into();
        assert_eq!(
            world.validate(),
            Err(MarketplaceWorldError::EstimateAuthorityConflict)
        );
    }
}

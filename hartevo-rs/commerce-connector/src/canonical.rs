//! Canonical identities shared by the provider-specific commerce slices.
//!
//! These types intentionally contain no provider credentials and no authority
//! to create or complete an Effect.  They are stable joins for read evidence;
//! provider responses remain typed in their own modules until an Application
//! service explicitly maps them into a domain record.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::CurrencyCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_TOKEN_LENGTH: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirstPartyProvider {
    Shopify,
    AmazonSpApi,
}

impl FirstPartyProvider {
    pub const fn provider_id(&self) -> &'static str {
        match self {
            Self::Shopify => "shopify",
            Self::AmazonSpApi => "amazon-sp-api",
        }
    }
}

impl fmt::Display for FirstPartyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.provider_id())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CanonicalSku(String);

impl CanonicalSku {
    pub fn parse(value: impl Into<String>) -> Result<Self, CanonicalIdentityError> {
        let value = value.into();
        validate_token(&value, "SKU")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalSku {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for CanonicalSku {
    type Err = CanonicalIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Asin(String);

impl Asin {
    pub fn parse(value: impl Into<String>) -> Result<Self, CanonicalIdentityError> {
        let value = value.into().to_ascii_uppercase();
        if value.len() != 10 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(CanonicalIdentityError::InvalidAsin(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Asin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Asin {
    type Err = CanonicalIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MarketId(String);

impl MarketId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CanonicalIdentityError> {
        let value = value.into();
        validate_token(&value, "market")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MarketId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarketIdentity {
    pub market_id: MarketId,
    pub locale: Option<String>,
}

impl MarketIdentity {
    pub fn new(
        market_id: MarketId,
        locale: Option<String>,
    ) -> Result<Self, CanonicalIdentityError> {
        if let Some(locale) = locale.as_deref() {
            validate_locale(locale)?;
        }
        Ok(Self { market_id, locale })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ListingKey {
    ShopifyProduct {
        product_gid: String,
        variant_sku: Option<CanonicalSku>,
    },
    Amazon {
        sku: Option<CanonicalSku>,
        asin: Option<Asin>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListingIdentity {
    pub provider: FirstPartyProvider,
    pub account_id: String,
    pub market: MarketIdentity,
    pub key: ListingKey,
}

impl ListingIdentity {
    pub fn shopify(
        account_id: impl Into<String>,
        market: MarketIdentity,
        product_gid: impl Into<String>,
        variant_sku: Option<CanonicalSku>,
    ) -> Result<Self, CanonicalIdentityError> {
        let product_gid = product_gid.into();
        if !product_gid.starts_with("gid://shopify/Product/") {
            return Err(CanonicalIdentityError::InvalidExternalId(product_gid));
        }
        let account_id = account_id.into();
        validate_token(&account_id, "Shopify account")?;
        Ok(Self {
            provider: FirstPartyProvider::Shopify,
            account_id,
            market,
            key: ListingKey::ShopifyProduct {
                product_gid,
                variant_sku,
            },
        })
    }

    pub fn amazon(
        account_id: impl Into<String>,
        market: MarketIdentity,
        sku: Option<CanonicalSku>,
        asin: Option<Asin>,
    ) -> Result<Self, CanonicalIdentityError> {
        if sku.is_none() && asin.is_none() {
            return Err(CanonicalIdentityError::MissingListingKey);
        }
        let account_id = account_id.into();
        validate_token(&account_id, "Amazon account")?;
        Ok(Self {
            provider: FirstPartyProvider::AmazonSpApi,
            account_id,
            market,
            key: ListingKey::Amazon { sku, asin },
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryIdentity {
    pub listing: ListingIdentity,
    pub location_id: Option<String>,
}

impl InventoryIdentity {
    pub fn new(
        listing: ListingIdentity,
        location_id: Option<String>,
    ) -> Result<Self, CanonicalIdentityError> {
        if let Some(location_id) = location_id.as_deref() {
            validate_token(location_id, "inventory location")?;
        }
        Ok(Self {
            listing,
            location_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrderIdentity {
    pub provider: FirstPartyProvider,
    pub account_id: String,
    pub market: MarketIdentity,
    pub external_order_id: String,
}

impl OrderIdentity {
    pub fn new(
        provider: FirstPartyProvider,
        account_id: impl Into<String>,
        market: MarketIdentity,
        external_order_id: impl Into<String>,
    ) -> Result<Self, CanonicalIdentityError> {
        let account_id = account_id.into();
        let external_order_id = external_order_id.into();
        validate_token(&account_id, "order account")?;
        validate_token(&external_order_id, "order")?;
        Ok(Self {
            provider,
            account_id,
            market,
            external_order_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefundIdentity {
    pub order: OrderIdentity,
    pub external_refund_id: String,
}

impl RefundIdentity {
    pub fn new(
        order: OrderIdentity,
        external_refund_id: impl Into<String>,
    ) -> Result<Self, CanonicalIdentityError> {
        let external_refund_id = external_refund_id.into();
        validate_token(&external_refund_id, "refund")?;
        Ok(Self {
            order,
            external_refund_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CanonicalTime(DateTime<Utc>);

impl CanonicalTime {
    pub fn from_datetime(value: DateTime<Utc>) -> Self {
        Self(value)
    }

    pub fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalMoney {
    pub amount_minor: i64,
    pub currency: CurrencyCode,
}

impl CanonicalMoney {
    pub fn new(amount_minor: i64, currency: CurrencyCode) -> Self {
        Self {
            amount_minor,
            currency,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanonicalIdentityError {
    #[error("{kind} must be a non-empty bounded token")]
    InvalidToken { kind: &'static str },
    #[error("invalid ASIN {0}; expected ten ASCII alphanumeric characters")]
    InvalidAsin(String),
    #[error("invalid locale {0}")]
    InvalidLocale(String),
    #[error("invalid external id {0}")]
    InvalidExternalId(String),
    #[error("listing identity requires a SKU or ASIN")]
    MissingListingKey,
}

fn validate_token(value: &str, kind: &'static str) -> Result<(), CanonicalIdentityError> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_LENGTH
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CanonicalIdentityError::InvalidToken { kind });
    }
    Ok(())
}

fn validate_locale(value: &str) -> Result<(), CanonicalIdentityError> {
    if value.len() < 2
        || value.len() > 16
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CanonicalIdentityError::InvalidLocale(value.into()));
    }
    Ok(())
}

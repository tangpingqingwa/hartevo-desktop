//! Shopify Admin GraphQL read seam.
//!
//! The seam requires the caller to provide an implementation-specific
//! transport.  It builds exact Admin GraphQL requests, validates the shop and
//! granted scopes, supports cursor pagination and bulk-query observation, and
//! verifies HTTPS webhook signatures before a payload can be parsed.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Duration, Utc};
pub use hartevo_connector_sdk::{
    AuthSession, ConnectorAuth, ConnectorError, ConnectorScope, CredentialLease, Cursor,
    FreshnessWindow, ProviderAdapterIdentity, ProviderCapabilityKey, ProviderContractError,
    ProviderProvenanceClass, SecretReference,
};
use ring::hmac;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;
use url::Url;

use crate::canonical::{CanonicalIdentityError, CanonicalSku, CanonicalTime};

pub const SHOPIFY_PROVIDER_ID: &str = "shopify";
pub const SHOPIFY_LATEST_API_VERSION: &str = "2026-07";
pub const SHOPIFY_CURSOR_ADAPTER_ID: &str = "commerce.shopify.cursor.readonly";
pub const SHOPIFY_CURSOR_EVIDENCE_LEVEL: &str = "E1";
pub const SHOPIFY_CURSOR_LIVE_VALIDATION_STATUS: &str = "BLOCKED_ENV";
pub const SHOPIFY_ORDERS_READ_SCOPE: &str = "read_orders";
pub const SHOPIFY_PRODUCTS_READ_SCOPE: &str = "read_products";
pub const SHOPIFY_ORDERS_CURSOR_CAPABILITY: &str = "commerce.orders.incremental_read";
pub const SHOPIFY_PRODUCTS_CURSOR_CAPABILITY: &str = "commerce.products.incremental_read";
pub const SHOPIFY_RECONCILIATION_MAX_POLL_PAGES: u32 = 3;
pub const SHOPIFY_HMAC_HEADER: &str = "X-Shopify-Hmac-SHA256";
pub const SHOPIFY_WEBHOOK_ID_HEADER: &str = "X-Shopify-Webhook-Id";
pub const SHOPIFY_TOPIC_HEADER: &str = "X-Shopify-Topic";
pub const SHOPIFY_SHOP_DOMAIN_HEADER: &str = "X-Shopify-Shop-Domain";
pub const SHOPIFY_API_VERSION_HEADER: &str = "X-Shopify-API-Version";

pub const SHOP_IDENTITY_QUERY: &str = "query ShopifyShopIdentity { shop { id name myshopifyDomain } currentAppInstallation { accessScopes { handle } } }";
pub const PRODUCTS_PAGE_QUERY: &str = "query ShopifyProductsPage($first: Int!, $after: String) { products(first: $first, after: $after) { edges { cursor node { id title variants(first: 100) { nodes { id sku } pageInfo { hasNextPage endCursor } } } } pageInfo { hasNextPage endCursor } } }";
pub const CURSOR_PRODUCTS_PAGE_QUERY: &str = "query ShopifyCursorProductsPage($first: Int!, $after: String) { products(first: $first, after: $after) { edges { cursor node { id title updatedAt variants(first: 100) { nodes { id sku } pageInfo { hasNextPage endCursor } } } } pageInfo { hasNextPage endCursor } } }";
pub const CURSOR_ORDERS_PAGE_QUERY: &str = "query ShopifyCursorOrdersPage($first: Int!, $after: String) { orders(first: $first, after: $after, sortKey: UPDATED_AT) { edges { cursor node { id updatedAt } } pageInfo { hasNextPage endCursor } } }";
pub const BULK_PRODUCTS_MUTATION: &str = "mutation ShopifyBulkProducts { bulkOperationRunQuery(query: \"{ products { edges { node { id title variants { nodes { id sku } } } } } }\") { bulkOperation { id status } userErrors { field message } } }";
pub const BULK_OPERATION_QUERY: &str = "query ShopifyBulkOperation($id: ID!) { node(id: $id) { ... on BulkOperation { id status errorCode url objectCount completedAt } } }";

pub fn shopify_cursor_adapter_identity() -> Result<ProviderAdapterIdentity, ProviderContractError> {
    ProviderAdapterIdentity::new(SHOPIFY_CURSOR_ADAPTER_ID, 1)
}

pub fn shopify_cursor_capability(
    stream: ShopifyCursorStream,
) -> Result<ProviderCapabilityKey, ProviderContractError> {
    ProviderCapabilityKey::new(SHOPIFY_PROVIDER_ID, stream.capability_id())
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyApiVersion(String);

impl ShopifyApiVersion {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid = bytes.len() == 7
            && bytes[4] == b'-'
            && bytes[..4].iter().all(u8::is_ascii_digit)
            && bytes[5..].iter().all(u8::is_ascii_digit)
            && value[..4].parse::<u16>().is_ok_and(|year| year >= 2020)
            && value[5..]
                .parse::<u8>()
                .is_ok_and(|month| (1..=12).contains(&month));
        if !valid {
            return Err(ShopifyError::InvalidApiVersion(value));
        }
        Ok(Self(value))
    }

    pub fn latest() -> Self {
        Self(SHOPIFY_LATEST_API_VERSION.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShopifyApiVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopDomain(String);

impl ShopDomain {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyError> {
        let value = value.into();
        let candidate = if value.contains("://") {
            value.clone()
        } else {
            format!("https://{value}")
        };
        let url =
            Url::parse(&candidate).map_err(|_| ShopifyError::InvalidShopDomain(value.clone()))?;
        let host = url
            .host_str()
            .ok_or_else(|| ShopifyError::InvalidShopDomain(value.clone()))?
            .to_ascii_lowercase();
        if url.scheme() != "https"
            || url.port().is_some()
            || (url.path() != "/" && !url.path().is_empty())
            || url.query().is_some()
            || url.fragment().is_some()
            || !host.ends_with(".myshopify.com")
            || host.trim_end_matches(".myshopify.com").is_empty()
            || host.contains("..")
        {
            return Err(ShopifyError::InvalidShopDomain(value));
        }
        Ok(Self(host))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn admin_graphql_endpoint(&self, version: &ShopifyApiVersion) -> Url {
        Url::parse(&format!(
            "https://{}/admin/api/{}/graphql.json",
            self.0, version
        ))
        .expect("validated Shopify domain and API version produce a URL")
    }
}

impl fmt::Display for ShopDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyShopGid(String);

impl ShopifyShopGid {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyError> {
        let value = value.into();
        if !value.starts_with("gid://shopify/Shop/")
            || value["gid://shopify/Shop/".len()..].is_empty()
            || !value["gid://shopify/Shop/".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        {
            return Err(ShopifyError::InvalidShopGid(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyShopIdentity {
    pub shop_gid: ShopifyShopGid,
    pub domain: ShopDomain,
    pub name: String,
}

impl ShopifyShopIdentity {
    pub fn new(
        shop_gid: ShopifyShopGid,
        domain: ShopDomain,
        name: impl Into<String>,
    ) -> Result<Self, ShopifyError> {
        let name = name.into();
        if name.trim().is_empty() || name.chars().any(char::is_control) {
            return Err(ShopifyError::InvalidShopName);
        }
        Ok(Self {
            shop_gid,
            domain,
            name,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyScope(String);

impl ShopifyScope {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 96
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(ShopifyError::InvalidScope(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ShopifyScopeSet(BTreeSet<ShopifyScope>);

impl ShopifyScopeSet {
    pub fn new<I>(scopes: I) -> Result<Self, ShopifyError>
    where
        I: IntoIterator<Item = String>,
    {
        scopes
            .into_iter()
            .map(ShopifyScope::parse)
            .collect::<Result<BTreeSet<_>, _>>()
            .map(Self)
    }

    pub fn contains(&self, scope: &str) -> bool {
        self.0.iter().any(|candidate| candidate.as_str() == scope)
    }

    pub fn missing_from(&self, granted: &Self) -> Vec<String> {
        self.0
            .iter()
            .filter(|scope| !granted.0.contains(*scope))
            .map(|scope| scope.as_str().to_owned())
            .collect()
    }

    pub fn handles(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(ShopifyScope::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyScopeObservation {
    pub requested: ShopifyScopeSet,
    pub granted: ShopifyScopeSet,
    pub observed_at: CanonicalTime,
}

impl ShopifyScopeObservation {
    pub fn is_satisfied(&self) -> bool {
        self.requested.missing_from(&self.granted).is_empty()
    }

    pub fn missing_scopes(&self) -> Vec<String> {
        self.requested.missing_from(&self.granted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyCursorStream {
    Orders,
    Products,
}

impl ShopifyCursorStream {
    pub const fn required_scope(self) -> &'static str {
        match self {
            Self::Orders => SHOPIFY_ORDERS_READ_SCOPE,
            Self::Products => SHOPIFY_PRODUCTS_READ_SCOPE,
        }
    }

    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::Orders => SHOPIFY_ORDERS_CURSOR_CAPABILITY,
            Self::Products => SHOPIFY_PRODUCTS_CURSOR_CAPABILITY,
        }
    }

    pub const fn operation_name(self) -> &'static str {
        match self {
            Self::Orders => "ShopifyCursorOrdersPage",
            Self::Products => "ShopifyCursorProductsPage",
        }
    }

    pub const fn query(self) -> &'static str {
        match self {
            Self::Orders => CURSOR_ORDERS_PAGE_QUERY,
            Self::Products => CURSOR_PRODUCTS_PAGE_QUERY,
        }
    }

    pub fn accepts_webhook_topic(self, topic: &str) -> bool {
        match self {
            Self::Orders => topic.starts_with("orders/"),
            Self::Products => topic.starts_with("products/"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyTenantScope {
    scope: ConnectorScope,
    shop: ShopDomain,
}

impl ShopifyTenantScope {
    pub fn new(scope: ConnectorScope, shop: ShopDomain) -> Result<Self, ShopifyError> {
        if scope.provider_id() != SHOPIFY_PROVIDER_ID || scope.scopes().is_empty() {
            return Err(ShopifyError::InvalidTenantScope);
        }
        Ok(Self { scope, shop })
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn shop(&self) -> &ShopDomain {
        &self.shop
    }

    pub fn tenant_id(&self) -> &str {
        self.scope.tenant_id()
    }

    pub fn account_id(&self) -> &str {
        self.scope.account_id()
    }

    pub fn digest(&self) -> String {
        shopify_digest([
            self.scope.digest().as_str(),
            self.shop.as_str(),
            SHOPIFY_PROVIDER_ID,
        ])
    }

    fn ensure_stream_scope(&self, stream: ShopifyCursorStream) -> Result<(), ShopifyError> {
        if self.scope.scopes().contains(stream.required_scope()) {
            Ok(())
        } else {
            Err(ShopifyError::MissingRequiredScope(
                stream.required_scope().into(),
            ))
        }
    }
}

/// The SDK auth chain is carried by value, but its secret material is never
/// exposed or serialized by this Shopify adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShopifyAuthBinding {
    secret_reference: SecretReference,
    credential_lease: CredentialLease,
    session: AuthSession,
    scope: ConnectorScope,
    adapter: ProviderAdapterIdentity,
}

impl ShopifyAuthBinding {
    pub fn new(
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
        session: AuthSession,
    ) -> Result<Self, ShopifyError> {
        let scope = secret_reference.scope().clone();
        let adapter = shopify_cursor_adapter_identity()
            .map_err(|_| ShopifyError::Connector(ConnectorError::ProviderContract))?;
        if scope.provider_id() != SHOPIFY_PROVIDER_ID
            || credential_lease.scope() != &scope
            || credential_lease.adapter() != &adapter
            || credential_lease.credential_revision() != secret_reference.credential_revision()
            || session.scope() != &scope
            || session.adapter() != &adapter
            || session.credential_revision() != secret_reference.credential_revision()
            || session.lease_revision() != credential_lease.lease_revision()
            || session.auth_revision() == 0
        {
            return Err(ShopifyError::InvalidAuthBinding);
        }
        Ok(Self {
            secret_reference,
            credential_lease,
            session,
            scope,
            adapter,
        })
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn credential_lease(&self) -> &CredentialLease {
        &self.credential_lease
    }

    pub fn session(&self) -> &AuthSession {
        &self.session
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    /// Credential revisions are the SDK-owned monotonic generation boundary
    /// for this provider-specific read consumer.
    pub const fn generation(&self) -> u64 {
        self.secret_reference.credential_revision()
    }

    pub fn auth_digest(&self) -> String {
        shopify_digest([
            self.secret_reference.reference_id(),
            &self.secret_reference.credential_revision().to_string(),
            &self.credential_lease.lease_revision().to_string(),
            &self.session.auth_revision().to_string(),
            self.scope.digest().as_str(),
            self.adapter.adapter_id(),
            &self.adapter.adapter_version().to_string(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyGraphqlCost {
    pub requested_query_cost: u64,
    pub actual_query_cost: u64,
    pub maximum_available: u64,
    pub currently_available: u64,
    pub restore_rate_per_second: u64,
    pub observed_at: DateTime<Utc>,
}

impl ShopifyGraphqlCost {
    fn from_response(
        response: &ShopifyGraphqlResponse,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ShopifyError> {
        let cost = response
            .body
            .get("extensions")
            .and_then(|extensions| extensions.get("cost"))
            .ok_or(ShopifyError::MissingGraphqlCost)?;
        let throttle = cost
            .get("throttleStatus")
            .ok_or(ShopifyError::MissingGraphqlCost)?;
        let restore_rate_per_second = throttle
            .get("restoreRate")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
            .and_then(|value| value.to_string().parse::<u64>().ok())
            .ok_or(ShopifyError::InvalidGraphqlCost)?;
        let value = Self {
            requested_query_cost: required_u64(cost, "requestedQueryCost")?,
            actual_query_cost: required_u64(cost, "actualQueryCost")?,
            maximum_available: required_u64(throttle, "maximumAvailable")?,
            currently_available: required_u64(throttle, "currentlyAvailable")?,
            restore_rate_per_second,
            observed_at,
        };
        if value.actual_query_cost > value.requested_query_cost
            || value.currently_available > value.maximum_available
        {
            return Err(ShopifyError::InvalidGraphqlCost);
        }
        Ok(value)
    }

    pub fn digest(&self) -> String {
        let requested_query_cost = self.requested_query_cost.to_string();
        let actual_query_cost = self.actual_query_cost.to_string();
        let maximum_available = self.maximum_available.to_string();
        let currently_available = self.currently_available.to_string();
        let restore_rate_per_second = self.restore_rate_per_second.to_string();
        let observed_at = self.observed_at.to_rfc3339();
        shopify_digest([
            requested_query_cost.as_str(),
            actual_query_cost.as_str(),
            maximum_available.as_str(),
            currently_available.as_str(),
            restore_rate_per_second.as_str(),
            observed_at.as_str(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFreshnessWindow {
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub source_revision: u64,
}

impl ShopifyFreshnessWindow {
    fn new(
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        source_revision: u64,
    ) -> Result<Self, ShopifyError> {
        if valid_until <= observed_at || source_revision == 0 {
            return Err(ShopifyError::InvalidFreshness);
        }
        Ok(Self {
            observed_at,
            valid_until,
            source_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyCursorProduct {
    pub product_gid: String,
    pub title: String,
    pub updated_at: DateTime<Utc>,
    pub variant_skus: Vec<CanonicalSku>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyCursorOrder {
    pub order_gid: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ShopifyTypedItems {
    Products(Vec<ShopifyCursorProduct>),
    Orders(Vec<ShopifyCursorOrder>),
}

impl ShopifyTypedItems {
    pub fn stream(&self) -> ShopifyCursorStream {
        match self {
            Self::Products(_) => ShopifyCursorStream::Products,
            Self::Orders(_) => ShopifyCursorStream::Orders,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Products(items) => items.len(),
            Self::Orders(items) => items.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn content_digest(&self) -> Result<String, ShopifyError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ShopifyError::InvalidReadProvenance)?;
        Ok(sha256_bytes(&bytes))
    }

    fn contains_resource(&self, resource_id: &str, updated_at: DateTime<Utc>) -> bool {
        match self {
            Self::Products(items) => items
                .iter()
                .any(|item| item.product_gid == resource_id && item.updated_at == updated_at),
            Self::Orders(items) => items
                .iter()
                .any(|item| item.order_gid == resource_id && item.updated_at == updated_at),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyPollCursorBinding {
    pub generation: u64,
    pub query_digest: String,
    pub cursor: Option<String>,
    pub page_sequence: u64,
    pub cursor_digest: String,
}

impl ShopifyPollCursorBinding {
    fn unbound(generation: u64) -> Self {
        Self {
            generation,
            ..Self::default()
        }
    }

    pub fn is_bound(&self) -> bool {
        self.generation > 0 && is_sha256(&self.query_digest) && is_sha256(&self.cursor_digest)
    }

    fn same_cursor(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.query_digest == other.query_digest
            && self.cursor == other.cursor
            && self.page_sequence == other.page_sequence
            && self.cursor_digest == other.cursor_digest
    }

    fn compatible_with(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.query_digest == other.query_digest
            && self.is_bound()
            && other.is_bound()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyReadResultEnvelope {
    pub result_id: String,
    pub mission_id: String,
    pub stream: ShopifyCursorStream,
    pub tenant_scope: ShopifyTenantScope,
    pub api_version: ShopifyApiVersion,
    pub provider_digest: String,
    pub generation: u64,
    pub auth_digest: String,
    pub provenance_class: ProviderProvenanceClass,
    pub live_validation_status: String,
    pub request_digest: String,
    pub response_digest: String,
    pub content_digest: String,
    pub page_sequence: u64,
    pub page_cursor: Option<String>,
    pub poll_cursor_binding: ShopifyPollCursorBinding,
    pub next_cursor: Option<String>,
    pub page_digest: String,
    pub typed_items: ShopifyTypedItems,
    pub quota_cost: ShopifyGraphqlCost,
    pub freshness: ShopifyFreshnessWindow,
    pub checkpoint_before_digest: String,
    pub checkpoint_after: ShopifyCursorCheckpoint,
}

impl ShopifyReadResultEnvelope {
    pub fn is_first_party(&self) -> bool {
        false
    }

    pub fn sdk_next_cursor(&self) -> Result<Option<Cursor>, ShopifyError> {
        self.next_cursor
            .as_deref()
            .map(|token| {
                Cursor::new(
                    self.tenant_scope.scope(),
                    self.request_digest.clone(),
                    self.page_sequence.saturating_add(1),
                    sha256_string(token),
                )
                .map_err(ShopifyError::Connector)
            })
            .transpose()
    }

    pub fn reconcile_webhook(
        &self,
        webhook: &ShopifyWebhookCheckpoint,
    ) -> Result<ShopifyPollReconcile, ShopifyError> {
        if webhook.mission_id != self.mission_id {
            return Err(ShopifyError::WebhookCheckpointConflict);
        }
        if webhook.generation != self.generation
            || (webhook.poll_cursor_binding.is_bound()
                && !webhook
                    .poll_cursor_binding
                    .compatible_with(&self.poll_cursor_binding))
        {
            return Err(ShopifyError::WebhookGenerationMismatch);
        }
        webhook.validate_against_scope_digest(
            &self.tenant_scope.scope().digest(),
            self.tenant_scope.shop(),
            &self.api_version,
            self.stream,
            &self.provider_digest,
        )?;
        if self
            .typed_items
            .contains_resource(&webhook.resource_id, webhook.resource_updated_at)
        {
            Ok(ShopifyPollReconcile::Exact {
                delivery_id: webhook.delivery_id.clone(),
                resource_id: webhook.resource_id.clone(),
            })
        } else {
            Ok(ShopifyPollReconcile::NotObserved)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyShopRead {
    pub identity: ShopifyShopIdentity,
    pub scopes: ShopifyScopeObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyGraphqlRequest {
    pub shop: ShopDomain,
    pub api_version: ShopifyApiVersion,
    pub operation_name: String,
    pub query: String,
    pub variables: Value,
}

impl ShopifyGraphqlRequest {
    pub fn new(
        shop: ShopDomain,
        api_version: ShopifyApiVersion,
        operation_name: impl Into<String>,
        query: impl Into<String>,
        variables: Value,
    ) -> Result<Self, ShopifyError> {
        let operation_name = operation_name.into();
        let query = query.into();
        if operation_name.trim().is_empty() || query.trim().is_empty() {
            return Err(ShopifyError::InvalidRequest(
                "operation and query are required".into(),
            ));
        }
        Ok(Self {
            shop,
            api_version,
            operation_name,
            query,
            variables,
        })
    }

    pub fn endpoint(&self) -> Url {
        self.shop.admin_graphql_endpoint(&self.api_version)
    }

    pub fn json_body(&self) -> Value {
        json!({
            "operationName": self.operation_name,
            "query": self.query,
            "variables": self.variables,
        })
    }
}

pub trait ShopifyAdminTransport {
    fn execute(
        &mut self,
        request: ShopifyGraphqlRequest,
    ) -> Result<ShopifyGraphqlResponse, ShopifyTransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyGraphqlResponse {
    pub status: u16,
    pub body: Value,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
}

impl ShopifyGraphqlResponse {
    pub fn data<T: DeserializeOwned>(&self) -> Result<T, ShopifyError> {
        if !(200..300).contains(&self.status) {
            return Err(ShopifyError::HttpStatus(self.status));
        }
        if let Some(errors) = self.body.get("errors") {
            return Err(ShopifyError::GraphqlErrors(errors.to_string()));
        }
        let data = self
            .body
            .get("data")
            .ok_or(ShopifyError::MissingData)?
            .clone();
        serde_json::from_value(data)
            .map_err(|error| ShopifyError::MalformedResponse(error.to_string()))
    }

    fn body_digest(&self) -> Result<String, ShopifyError> {
        let bytes =
            serde_json::to_vec(&self.body).map_err(|_| ShopifyError::InvalidReadProvenance)?;
        Ok(sha256_bytes(&bytes))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyCursorCheckpoint {
    mission_id: String,
    stream: ShopifyCursorStream,
    scope_digest: String,
    shop: ShopDomain,
    api_version: ShopifyApiVersion,
    provider_digest: String,
    #[serde(default = "default_generation")]
    generation: u64,
    query_digest: String,
    page_size: u32,
    page_sequence: u64,
    next_cursor: Option<String>,
    last_page_digest: Option<String>,
    last_result_id: Option<String>,
    committed_result_ids: BTreeSet<String>,
    webhook_checkpoints: Vec<ShopifyWebhookCheckpoint>,
    reconciled_webhook_ids: BTreeSet<String>,
    #[serde(default)]
    reconciliation_receipts: Vec<ShopifyReconciliationReceipt>,
}

impl ShopifyCursorCheckpoint {
    pub fn new(
        mission_id: impl Into<String>,
        tenant_scope: &ShopifyTenantScope,
        api_version: ShopifyApiVersion,
        stream: ShopifyCursorStream,
        page_size: u32,
    ) -> Result<Self, ShopifyError> {
        Self::new_for_generation(mission_id, tenant_scope, api_version, stream, page_size, 1)
    }

    pub fn new_for_generation(
        mission_id: impl Into<String>,
        tenant_scope: &ShopifyTenantScope,
        api_version: ShopifyApiVersion,
        stream: ShopifyCursorStream,
        page_size: u32,
        generation: u64,
    ) -> Result<Self, ShopifyError> {
        let mission_id = mission_id.into();
        validate_mission_id(&mission_id)?;
        validate_page_size(page_size)?;
        validate_generation(generation)?;
        tenant_scope.ensure_stream_scope(stream)?;
        let provider_digest = shopify_provider_digest(tenant_scope, &api_version, stream);
        let query_digest = shopify_query_digest(tenant_scope, &api_version, stream, page_size);
        Ok(Self {
            mission_id,
            stream,
            scope_digest: tenant_scope.scope().digest(),
            shop: tenant_scope.shop().clone(),
            api_version,
            provider_digest,
            generation,
            query_digest,
            page_size,
            page_sequence: 0,
            next_cursor: None,
            last_page_digest: None,
            last_result_id: None,
            committed_result_ids: BTreeSet::new(),
            webhook_checkpoints: Vec::new(),
            reconciled_webhook_ids: BTreeSet::new(),
            reconciliation_receipts: Vec::new(),
        })
    }

    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    pub const fn stream(&self) -> ShopifyCursorStream {
        self.stream
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }

    pub const fn is_complete(&self) -> bool {
        self.page_sequence > 0 && self.next_cursor.is_none()
    }

    pub fn last_result_id(&self) -> Option<&str> {
        self.last_result_id.as_deref()
    }

    pub fn webhook_checkpoints(&self) -> &[ShopifyWebhookCheckpoint] {
        &self.webhook_checkpoints
    }

    pub fn reconciliation_receipts(&self) -> &[ShopifyReconciliationReceipt] {
        &self.reconciliation_receipts
    }

    pub fn reconciled_webhook_ids(&self) -> &BTreeSet<String> {
        &self.reconciled_webhook_ids
    }

    pub fn digest(&self) -> Result<String, ShopifyError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ShopifyError::InvalidCheckpoint)?;
        Ok(sha256_bytes(&bytes))
    }

    fn cursor_digest(&self) -> Result<String, ShopifyError> {
        let mut cursor_state = self.clone();
        cursor_state.webhook_checkpoints.clear();
        cursor_state.reconciled_webhook_ids.clear();
        cursor_state.reconciliation_receipts.clear();
        let bytes =
            serde_json::to_vec(&cursor_state).map_err(|_| ShopifyError::InvalidCheckpoint)?;
        Ok(sha256_bytes(&bytes))
    }

    pub fn poll_cursor_binding(&self) -> Result<ShopifyPollCursorBinding, ShopifyError> {
        Ok(ShopifyPollCursorBinding {
            generation: self.generation,
            query_digest: self.query_digest.clone(),
            cursor: self.next_cursor.clone(),
            page_sequence: self.page_sequence,
            cursor_digest: self.cursor_digest()?,
        })
    }

    pub fn sdk_cursor(&self, scope: &ConnectorScope) -> Result<Option<Cursor>, ShopifyError> {
        if self.scope_digest != scope.digest() {
            return Err(ShopifyError::CheckpointScopeMismatch);
        }
        self.next_cursor
            .as_deref()
            .map(|token| {
                Cursor::new(
                    scope,
                    self.query_digest.clone(),
                    self.page_sequence.saturating_add(1),
                    sha256_string(token),
                )
                .map_err(ShopifyError::Connector)
            })
            .transpose()
    }

    fn validate_against(
        &self,
        tenant_scope: &ShopifyTenantScope,
        api_version: &ShopifyApiVersion,
        stream: ShopifyCursorStream,
        generation: u64,
    ) -> Result<(), ShopifyError> {
        if self.scope_digest != tenant_scope.scope().digest()
            || self.shop != *tenant_scope.shop()
            || self.api_version != *api_version
            || self.stream != stream
            || self.generation != generation
            || self.provider_digest != shopify_provider_digest(tenant_scope, api_version, stream)
            || self.query_digest
                != shopify_query_digest(tenant_scope, api_version, stream, self.page_size)
        {
            return Err(ShopifyError::CheckpointScopeMismatch);
        }
        validate_mission_id(&self.mission_id)?;
        validate_page_size(self.page_size)
    }

    fn rotate_generation(&mut self, generation: u64) -> Result<(), ShopifyError> {
        validate_generation(generation)?;
        if generation <= self.generation {
            return Err(ShopifyError::CredentialRotationRejected);
        }
        self.generation = generation;
        self.webhook_checkpoints.clear();
        self.reconciled_webhook_ids.clear();
        self.reconciliation_receipts.clear();
        self.committed_result_ids.clear();
        self.last_page_digest = None;
        self.last_result_id = None;
        Ok(())
    }

    fn preview_result(
        &self,
        result_id: String,
        page_digest: String,
        next_cursor: Option<String>,
    ) -> Self {
        let mut next = self.clone();
        next.page_sequence = self.page_sequence.saturating_add(1);
        next.next_cursor = next_cursor;
        next.last_page_digest = Some(page_digest);
        next.last_result_id = Some(result_id.clone());
        next.committed_result_ids.insert(result_id);
        next
    }

    fn apply_result(
        &mut self,
        envelope: &ShopifyReadResultEnvelope,
    ) -> Result<ShopifyCommitOutcome, ShopifyError> {
        if self.committed_result_ids.contains(&envelope.result_id) {
            return Ok(ShopifyCommitOutcome::AlreadyCommitted);
        }
        let before = self.cursor_digest()?;
        let poll_cursor_binding = self.poll_cursor_binding()?;
        if before != envelope.checkpoint_before_digest
            || envelope.mission_id != self.mission_id
            || envelope.stream != self.stream
            || envelope.generation != self.generation
            || envelope.page_sequence != self.page_sequence.saturating_add(1)
            || envelope.page_cursor.as_deref() != self.next_cursor.as_deref()
            || !envelope
                .poll_cursor_binding
                .same_cursor(&poll_cursor_binding)
            || envelope.provider_digest != self.provider_digest
            || envelope.request_digest != self.query_digest
        {
            return Err(ShopifyError::CheckpointConflict);
        }
        let expected = self.preview_result(
            envelope.result_id.clone(),
            envelope.page_digest.clone(),
            envelope.next_cursor.clone(),
        );
        if expected.cursor_digest()? != envelope.checkpoint_after.cursor_digest()? {
            return Err(ShopifyError::CheckpointConflict);
        }
        if envelope.checkpoint_after.generation != self.generation {
            return Err(ShopifyError::CheckpointGenerationMismatch);
        }
        *self = expected;
        Ok(ShopifyCommitOutcome::Committed)
    }

    fn apply_webhook(
        &mut self,
        mut webhook: ShopifyWebhookCheckpoint,
    ) -> Result<ShopifyWebhookIngest, ShopifyError> {
        if webhook.generation != self.generation {
            return Err(ShopifyError::WebhookGenerationMismatch);
        }
        if !webhook.poll_cursor_binding.is_bound() {
            webhook.poll_cursor_binding = self.poll_cursor_binding()?;
        } else if !webhook
            .poll_cursor_binding
            .compatible_with(&self.poll_cursor_binding()?)
        {
            return Err(ShopifyError::WebhookCursorBindingMismatch);
        }
        webhook.validate_against_scope_digest(
            &self.scope_digest,
            &self.shop,
            &self.api_version,
            self.stream,
            &self.provider_digest,
        )?;
        if self
            .webhook_checkpoints
            .iter()
            .any(|existing| existing.delivery_id == webhook.delivery_id)
            || webhook.event_id.as_deref().is_some_and(|event_id| {
                self.webhook_checkpoints
                    .iter()
                    .any(|existing| existing.event_id.as_deref() == Some(event_id))
            })
            || self
                .webhook_checkpoints
                .iter()
                .any(|existing| existing.sequence == webhook.sequence)
        {
            let existing = self
                .webhook_checkpoints
                .iter()
                .find(|existing| {
                    existing.delivery_id == webhook.delivery_id
                        || existing.event_id.is_some() && existing.event_id == webhook.event_id
                        || existing.sequence == webhook.sequence
                })
                .cloned()
                .ok_or(ShopifyError::WebhookCheckpointMissing)?;
            return Ok(ShopifyWebhookIngest::AlreadyCommitted { existing });
        }
        let max_sequence = self
            .webhook_checkpoints
            .iter()
            .map(|existing| existing.sequence)
            .max();
        let out_of_order = max_sequence.is_some_and(|maximum| webhook.sequence < maximum);
        let delivery_id = webhook.delivery_id.clone();
        self.webhook_checkpoints.push(webhook);
        self.webhook_checkpoints.sort_by(|left, right| {
            left.sequence
                .cmp(&right.sequence)
                .then_with(|| left.delivery_id.cmp(&right.delivery_id))
        });
        let webhook = self
            .webhook_checkpoints
            .iter()
            .find(|existing| existing.delivery_id == delivery_id)
            .cloned()
            .ok_or(ShopifyError::InvalidWebhookCheckpoint)?;
        Ok(ShopifyWebhookIngest::Committed {
            webhook,
            gap: self.webhook_sequence_gap(),
            out_of_order,
        })
    }

    pub fn webhook_sequence_gap(&self) -> Option<ShopifySequenceGap> {
        let mut frontier: u64 = 0;
        loop {
            if self
                .webhook_checkpoints
                .iter()
                .any(|webhook| webhook.sequence == frontier.saturating_add(1))
            {
                frontier = frontier.saturating_add(1);
            } else {
                break;
            }
        }
        let observed = self
            .webhook_checkpoints
            .iter()
            .map(|webhook| webhook.sequence)
            .max()?;
        (observed > frontier.saturating_add(1)).then(|| ShopifySequenceGap {
            generation: self.generation,
            first_missing_sequence: frontier.saturating_add(1),
            last_missing_sequence: observed.saturating_sub(1),
            observed_sequence: observed,
        })
    }

    fn record_reconciliation_receipt(
        &mut self,
        receipt: ShopifyReconciliationReceipt,
    ) -> ShopifyReconciliationReceipt {
        if let Some(existing) = self
            .reconciliation_receipts
            .iter()
            .find(|existing| existing.receipt_id == receipt.receipt_id)
        {
            return existing.clone();
        }
        self.reconciliation_receipts.push(receipt.clone());
        self.reconciliation_receipts
            .sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
        receipt
    }

    fn receipt_for_delivery(&self, delivery_id: &str) -> Option<&ShopifyReconciliationReceipt> {
        self.reconciliation_receipts
            .iter()
            .find(|receipt| {
                receipt.delivery_id == delivery_id
                    && receipt.status == ShopifyReconciliationStatus::Exact
            })
            .or_else(|| {
                self.reconciliation_receipts
                    .iter()
                    .find(|receipt| receipt.delivery_id == delivery_id)
            })
    }

    fn mark_webhook_reconciled(
        &mut self,
        webhook: &ShopifyWebhookCheckpoint,
    ) -> Result<(), ShopifyError> {
        if !self
            .webhook_checkpoints
            .iter()
            .any(|existing| existing.delivery_id == webhook.delivery_id)
        {
            return Err(ShopifyError::WebhookCheckpointMissing);
        }
        self.reconciled_webhook_ids
            .insert(webhook.delivery_id.clone());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyCursorStoreLifecycle {
    #[default]
    Mounted,
    Revoked,
    Unmounted,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyCursorStore {
    lifecycle: ShopifyCursorStoreLifecycle,
    checkpoints: Vec<ShopifyCursorCheckpoint>,
}

impl ShopifyCursorStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn lifecycle(&self) -> ShopifyCursorStoreLifecycle {
        self.lifecycle
    }

    pub fn checkpoints(&self) -> &[ShopifyCursorCheckpoint] {
        &self.checkpoints
    }

    pub fn checkpoint(
        &self,
        mission_id: &str,
        stream: ShopifyCursorStream,
    ) -> Option<&ShopifyCursorCheckpoint> {
        self.checkpoints
            .iter()
            .find(|checkpoint| checkpoint.mission_id == mission_id && checkpoint.stream == stream)
    }

    fn ensure_checkpoint(
        &mut self,
        mission_id: &str,
        tenant_scope: &ShopifyTenantScope,
        api_version: &ShopifyApiVersion,
        stream: ShopifyCursorStream,
        page_size: u32,
        generation: u64,
    ) -> Result<&mut ShopifyCursorCheckpoint, ShopifyError> {
        if self.lifecycle != ShopifyCursorStoreLifecycle::Mounted {
            return Err(ShopifyError::ConsumerNotMounted);
        }
        if let Some(index) = self.checkpoints.iter().position(|checkpoint| {
            checkpoint.mission_id == mission_id && checkpoint.stream == stream
        }) {
            let checkpoint = &mut self.checkpoints[index];
            checkpoint.validate_against(tenant_scope, api_version, stream, generation)?;
            if checkpoint.page_size != page_size {
                return Err(ShopifyError::CheckpointPageSizeMismatch);
            }
            return Ok(checkpoint);
        }
        self.checkpoints
            .push(ShopifyCursorCheckpoint::new_for_generation(
                mission_id,
                tenant_scope,
                api_version.clone(),
                stream,
                page_size,
                generation,
            )?);
        self.checkpoints
            .last_mut()
            .ok_or(ShopifyError::InvalidCheckpoint)
    }

    fn checkpoint_mut(
        &mut self,
        mission_id: &str,
        stream: ShopifyCursorStream,
    ) -> Result<&mut ShopifyCursorCheckpoint, ShopifyError> {
        self.checkpoints
            .iter_mut()
            .find(|checkpoint| checkpoint.mission_id == mission_id && checkpoint.stream == stream)
            .ok_or(ShopifyError::CheckpointMissing)
    }

    pub fn revoke(&mut self) -> ShopifyUnmountReceipt {
        let cleared_checkpoints = self.checkpoints.len();
        self.checkpoints.clear();
        self.lifecycle = ShopifyCursorStoreLifecycle::Revoked;
        ShopifyUnmountReceipt {
            cleared_checkpoints,
            lifecycle: self.lifecycle,
        }
    }

    pub fn unmount(&mut self) -> ShopifyUnmountReceipt {
        let cleared_checkpoints = self.checkpoints.len();
        self.checkpoints.clear();
        self.lifecycle = ShopifyCursorStoreLifecycle::Unmounted;
        ShopifyUnmountReceipt {
            cleared_checkpoints,
            lifecycle: self.lifecycle,
        }
    }

    fn rotate_generation(&mut self, generation: u64) -> Result<(), ShopifyError> {
        if self.lifecycle != ShopifyCursorStoreLifecycle::Mounted {
            return Err(ShopifyError::ConsumerNotMounted);
        }
        for checkpoint in &mut self.checkpoints {
            checkpoint.rotate_generation(generation)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShopifyUnmountReceipt {
    pub cleared_checkpoints: usize,
    pub lifecycle: ShopifyCursorStoreLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShopifyCommitOutcome {
    Committed,
    AlreadyCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShopifyWebhookCommitOutcome {
    Committed,
    AlreadyCommitted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifySequenceGap {
    pub generation: u64,
    pub first_missing_sequence: u64,
    pub last_missing_sequence: u64,
    pub observed_sequence: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyReconciliationSource {
    Webhook,
    Poll,
    GapFill,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyReconciliationStatus {
    PendingPoll,
    Exact,
    Duplicate,
    Late,
    GapPending,
    NotObserved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyReconciliationReceipt {
    pub receipt_id: String,
    pub mission_id: String,
    pub stream: ShopifyCursorStream,
    pub delivery_id: String,
    pub event_id: Option<String>,
    pub topic: String,
    pub shop: ShopDomain,
    pub api_version: ShopifyApiVersion,
    pub provider_digest: String,
    pub generation: u64,
    pub source: ShopifyReconciliationSource,
    pub status: ShopifyReconciliationStatus,
    pub resource_id: String,
    pub resource_updated_at: DateTime<Utc>,
    pub poll_cursor_binding: ShopifyPollCursorBinding,
    pub poll_pages: u32,
    pub gap: Option<ShopifySequenceGap>,
    pub duplicate_of: Option<String>,
    pub provenance_class: ProviderProvenanceClass,
    pub live_validation_status: String,
}

impl ShopifyReconciliationReceipt {
    pub fn is_exact(&self) -> bool {
        self.status == ShopifyReconciliationStatus::Exact
    }

    pub fn is_first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ShopifyWebhookIngest {
    Committed {
        webhook: ShopifyWebhookCheckpoint,
        gap: Option<ShopifySequenceGap>,
        out_of_order: bool,
    },
    AlreadyCommitted {
        existing: ShopifyWebhookCheckpoint,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShopifyPollReconcile {
    Exact {
        delivery_id: String,
        resource_id: String,
    },
    NotObserved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyWebhookCheckpoint {
    pub mission_id: String,
    pub delivery_id: String,
    pub event_id: Option<String>,
    pub topic: String,
    pub stream: ShopifyCursorStream,
    pub scope_digest: String,
    pub shop: ShopDomain,
    pub api_version: ShopifyApiVersion,
    pub provider_digest: String,
    #[serde(default = "default_generation")]
    pub generation: u64,
    #[serde(default)]
    pub poll_cursor_binding: ShopifyPollCursorBinding,
    pub resource_id: String,
    pub resource_updated_at: DateTime<Utc>,
    pub payload_digest: String,
    pub sequence: u64,
    pub occurred_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

impl ShopifyWebhookCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified(
        verified: &VerifiedShopifyWebhook,
        tenant_scope: &ShopifyTenantScope,
        stream: ShopifyCursorStream,
        mission_id: impl Into<String>,
        sequence: u64,
        event_id: Option<String>,
        resource_id: impl Into<String>,
        resource_updated_at: DateTime<Utc>,
        occurred_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Result<Self, ShopifyError> {
        Self::from_verified_for_generation(
            verified,
            tenant_scope,
            stream,
            mission_id,
            sequence,
            event_id,
            resource_id,
            resource_updated_at,
            occurred_at,
            received_at,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_for_generation(
        verified: &VerifiedShopifyWebhook,
        tenant_scope: &ShopifyTenantScope,
        stream: ShopifyCursorStream,
        mission_id: impl Into<String>,
        sequence: u64,
        event_id: Option<String>,
        resource_id: impl Into<String>,
        resource_updated_at: DateTime<Utc>,
        occurred_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
        generation: u64,
    ) -> Result<Self, ShopifyError> {
        let resource_id = resource_id.into();
        let mission_id = mission_id.into();
        if sequence == 0
            || generation == 0
            || occurred_at > received_at
            || !stream.accepts_webhook_topic(&verified.headers.topic)
            || verified.headers.shop_domain != *tenant_scope.shop()
            || !valid_resource_id(stream, &resource_id)
        {
            return Err(ShopifyError::InvalidWebhookCheckpoint);
        }
        validate_mission_id(&mission_id)?;
        if let Some(event_id) = &event_id {
            validate_mission_id(event_id)?;
        }
        let api_version = verified.headers.api_version.clone();
        let provider_digest = shopify_provider_digest(tenant_scope, &api_version, stream);
        Ok(Self {
            mission_id,
            delivery_id: verified.headers.webhook_id.clone(),
            event_id,
            topic: verified.headers.topic.clone(),
            stream,
            scope_digest: tenant_scope.scope().digest(),
            shop: tenant_scope.shop().clone(),
            api_version,
            provider_digest,
            generation,
            poll_cursor_binding: ShopifyPollCursorBinding::unbound(generation),
            resource_id,
            resource_updated_at,
            payload_digest: verified.raw_body_sha256.clone(),
            sequence,
            occurred_at,
            received_at,
        })
    }

    fn validate_against_scope_digest(
        &self,
        scope_digest: &str,
        shop: &ShopDomain,
        api_version: &ShopifyApiVersion,
        stream: ShopifyCursorStream,
        provider_digest: &str,
    ) -> Result<(), ShopifyError> {
        if self.scope_digest != scope_digest
            || &self.shop != shop
            || &self.api_version != api_version
            || self.stream != stream
            || self.provider_digest != provider_digest
            || self.generation == 0
            || !stream.accepts_webhook_topic(&self.topic)
            || !valid_resource_id(stream, &self.resource_id)
            || self.sequence == 0
            || self.occurred_at > self.received_at
            || !is_sha256(&self.payload_digest)
        {
            return Err(ShopifyError::WebhookCheckpointConflict);
        }
        if self.poll_cursor_binding.generation != 0
            && self.poll_cursor_binding.generation != self.generation
        {
            return Err(ShopifyError::WebhookCursorBindingMismatch);
        }
        Ok(())
    }
}

pub struct ShopifyDurableCursorConsumer<T: ShopifyAdminTransport> {
    transport: T,
    tenant_scope: ShopifyTenantScope,
    api_version: ShopifyApiVersion,
    auth: Option<ShopifyAuthBinding>,
    provenance_class: ProviderProvenanceClass,
    store: ShopifyCursorStore,
}

impl<T: ShopifyAdminTransport> fmt::Debug for ShopifyDurableCursorConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyDurableCursorConsumer")
            .field("tenant_scope", &self.tenant_scope)
            .field("api_version", &self.api_version)
            .field("authenticated", &self.auth.is_some())
            .field("provenance_class", &self.provenance_class)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl<T: ShopifyAdminTransport> ShopifyDurableCursorConsumer<T> {
    pub fn new(
        transport: T,
        tenant_scope: ShopifyTenantScope,
        api_version: ShopifyApiVersion,
        auth: ShopifyAuthBinding,
        provenance_class: ProviderProvenanceClass,
        store: ShopifyCursorStore,
    ) -> Result<Self, ShopifyError> {
        if auth.scope() != tenant_scope.scope() || api_version.as_str().is_empty() {
            return Err(ShopifyError::InvalidAuthBinding);
        }
        Ok(Self {
            transport,
            tenant_scope,
            api_version,
            auth: Some(auth),
            provenance_class,
            store,
        })
    }

    pub fn store(&self) -> &ShopifyCursorStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut ShopifyCursorStore {
        &mut self.store
    }

    pub fn auth(&self) -> Option<&ShopifyAuthBinding> {
        self.auth.as_ref()
    }

    pub const fn live_validation_status(&self) -> &'static str {
        SHOPIFY_CURSOR_LIVE_VALIDATION_STATUS
    }

    pub const fn is_first_party(&self) -> bool {
        false
    }

    pub fn read_next(
        &mut self,
        mission_id: impl Into<String>,
        stream: ShopifyCursorStream,
        page_size: u32,
        at: DateTime<Utc>,
    ) -> Result<ShopifyReadResultEnvelope, ShopifyError> {
        if self.auth.is_none() {
            return Err(ShopifyError::AuthenticationUnavailable);
        }
        if self.provenance_class == ProviderProvenanceClass::ProductionProvider {
            return Err(ShopifyError::BlockedEnv);
        }
        self.tenant_scope.ensure_stream_scope(stream)?;
        let mission_id = mission_id.into();
        let generation = self
            .auth
            .as_ref()
            .ok_or(ShopifyError::AuthenticationUnavailable)?
            .generation();
        let checkpoint = self.store.ensure_checkpoint(
            &mission_id,
            &self.tenant_scope,
            &self.api_version,
            stream,
            page_size,
            generation,
        )?;
        if checkpoint.is_complete() {
            return Err(ShopifyError::CheckpointComplete);
        }
        let checkpoint = checkpoint.clone();
        let request = ShopifyGraphqlRequest::new(
            self.tenant_scope.shop().clone(),
            self.api_version.clone(),
            stream.operation_name(),
            stream.query(),
            json!({
                "first": page_size,
                "after": checkpoint.next_cursor.clone(),
            }),
        )?;
        let response = self
            .transport
            .execute(request.clone())
            .map_err(|error| ShopifyError::Transport(error.to_string()))?;
        let quota_cost = ShopifyGraphqlCost::from_response(&response, at)?;
        let (typed_items, next_cursor, has_next_page) = parse_cursor_items(&response, stream)?;
        if has_next_page && next_cursor.is_none() {
            return Err(ShopifyError::MissingPageCursor);
        }
        if !has_next_page && next_cursor.is_some() {
            return Err(ShopifyError::InvalidPageCursor);
        }
        let response_digest = response.body_digest()?;
        let content_digest = typed_items.content_digest()?;
        let poll_cursor_binding = checkpoint.poll_cursor_binding()?;
        let page_sequence = checkpoint.page_sequence.saturating_add(1);
        let provider_digest = checkpoint.provider_digest.clone();
        let page_digest = shopify_digest([
            mission_id.as_str(),
            stream.capability_id(),
            provider_digest.as_str(),
            &generation.to_string(),
            checkpoint.query_digest.as_str(),
            content_digest.as_str(),
            checkpoint.next_cursor.clone().unwrap_or_default().as_str(),
            next_cursor.as_deref().unwrap_or_default(),
            &page_sequence.to_string(),
        ]);
        let result_id = format!("shopify-read-result-{page_digest}");
        let freshness = ShopifyFreshnessWindow::new(at, at + Duration::minutes(5), page_sequence)?;
        let checkpoint_before_digest = checkpoint.cursor_digest()?;
        let checkpoint_after =
            checkpoint.preview_result(result_id.clone(), page_digest.clone(), next_cursor.clone());
        Ok(ShopifyReadResultEnvelope {
            result_id,
            mission_id,
            stream,
            tenant_scope: self.tenant_scope.clone(),
            api_version: self.api_version.clone(),
            provider_digest,
            generation,
            auth_digest: self
                .auth
                .as_ref()
                .ok_or(ShopifyError::AuthenticationUnavailable)?
                .auth_digest(),
            provenance_class: self.provenance_class,
            live_validation_status: SHOPIFY_CURSOR_LIVE_VALIDATION_STATUS.into(),
            request_digest: checkpoint.query_digest,
            response_digest,
            content_digest,
            page_sequence,
            page_cursor: checkpoint.next_cursor,
            poll_cursor_binding,
            next_cursor: if has_next_page { next_cursor } else { None },
            page_digest,
            typed_items,
            quota_cost,
            freshness,
            checkpoint_before_digest,
            checkpoint_after,
        })
    }

    pub fn commit(
        &mut self,
        envelope: &ShopifyReadResultEnvelope,
    ) -> Result<ShopifyCommitOutcome, ShopifyError> {
        let checkpoint = self
            .store
            .checkpoint_mut(&envelope.mission_id, envelope.stream)?;
        checkpoint.apply_result(envelope)
    }

    pub fn ingest_webhook(
        &mut self,
        webhook: ShopifyWebhookCheckpoint,
    ) -> Result<ShopifyWebhookCommitOutcome, ShopifyError> {
        let checkpoint = self
            .store
            .checkpoint_mut(&webhook.mission_id, webhook.stream)?;
        match checkpoint.apply_webhook(webhook)? {
            ShopifyWebhookIngest::Committed { .. } => Ok(ShopifyWebhookCommitOutcome::Committed),
            ShopifyWebhookIngest::AlreadyCommitted { .. } => {
                Ok(ShopifyWebhookCommitOutcome::AlreadyCommitted)
            }
        }
    }

    pub fn reconcile_webhook(
        &mut self,
        envelope: &ShopifyReadResultEnvelope,
        webhook: &ShopifyWebhookCheckpoint,
    ) -> Result<ShopifyPollReconcile, ShopifyError> {
        let durable_webhook = self.durable_webhook(webhook)?.clone();
        let result = envelope.reconcile_webhook(&durable_webhook)?;
        if matches!(result, ShopifyPollReconcile::Exact { .. }) {
            let checkpoint = self
                .store
                .checkpoint_mut(&envelope.mission_id, envelope.stream)?;
            checkpoint.mark_webhook_reconciled(&durable_webhook)?;
        }
        Ok(result)
    }

    /// Returns a typed, read-only reconciliation receipt for a poll page.  A
    /// page is never treated as a Mission result until its durable cursor is
    /// committed separately by `commit`.
    pub fn reconcile_poll_page(
        &mut self,
        envelope: &ShopifyReadResultEnvelope,
        webhook: &ShopifyWebhookCheckpoint,
    ) -> Result<ShopifyReconciliationReceipt, ShopifyError> {
        let durable_webhook = self.durable_webhook(webhook)?.clone();
        if let Some(receipt) = self.exact_receipt(&durable_webhook) {
            return Ok(receipt.clone());
        }
        let result = envelope.reconcile_webhook(&durable_webhook)?;
        let status = match result {
            ShopifyPollReconcile::Exact { .. } => ShopifyReconciliationStatus::Exact,
            ShopifyPollReconcile::NotObserved => ShopifyReconciliationStatus::NotObserved,
        };
        if status == ShopifyReconciliationStatus::Exact {
            let checkpoint = self
                .store
                .checkpoint_mut(&envelope.mission_id, envelope.stream)?;
            checkpoint.mark_webhook_reconciled(&durable_webhook)?;
        }
        let receipt = self.build_receipt(
            &durable_webhook,
            ShopifyReconciliationSource::Poll,
            status,
            envelope.poll_cursor_binding.clone(),
            1,
            None,
            None,
        );
        let checkpoint = self
            .store
            .checkpoint_mut(&envelope.mission_id, envelope.stream)?;
        Ok(checkpoint.record_reconciliation_receipt(receipt))
    }

    /// Ingests a webhook and, when its durable sequence has a gap, performs a
    /// bounded cursor poll fill.  The cursor and all receipts remain in the
    /// serializable checkpoint, so reopening the Mission resumes from the
    /// last committed page without replaying a result.
    pub fn reconcile_webhook_delivery(
        &mut self,
        webhook: ShopifyWebhookCheckpoint,
        page_size: u32,
        at: DateTime<Utc>,
    ) -> Result<ShopifyReconciliationReceipt, ShopifyError> {
        if self.auth.is_none() {
            return Err(ShopifyError::AuthenticationUnavailable);
        }
        if self.provenance_class == ProviderProvenanceClass::ProductionProvider {
            return Err(ShopifyError::BlockedEnv);
        }
        let generation = self
            .auth
            .as_ref()
            .ok_or(ShopifyError::AuthenticationUnavailable)?
            .generation();
        self.tenant_scope.ensure_stream_scope(webhook.stream)?;
        self.store.ensure_checkpoint(
            &webhook.mission_id,
            &self.tenant_scope,
            &self.api_version,
            webhook.stream,
            page_size,
            generation,
        )?;
        let ingest = {
            let checkpoint = self
                .store
                .checkpoint_mut(&webhook.mission_id, webhook.stream)?;
            checkpoint.apply_webhook(webhook)?
        };
        match ingest {
            ShopifyWebhookIngest::AlreadyCommitted { existing } => {
                let (prior_receipt, retry_gap) = {
                    let checkpoint = self
                        .store
                        .checkpoint(&existing.mission_id, existing.stream)
                        .ok_or(ShopifyError::CheckpointMissing)?;
                    (
                        checkpoint
                            .receipt_for_delivery(&existing.delivery_id)
                            .cloned(),
                        checkpoint.webhook_sequence_gap(),
                    )
                };
                if retry_gap.as_ref().is_some_and(|_| {
                    prior_receipt.as_ref().is_some_and(|receipt| {
                        receipt.status == ShopifyReconciliationStatus::GapPending
                    })
                }) {
                    return self.fill_webhook_gap(&existing, page_size, at, retry_gap);
                }
                let duplicate_of = prior_receipt.map(|receipt| receipt.receipt_id);
                let receipt = self.build_receipt(
                    &existing,
                    ShopifyReconciliationSource::Webhook,
                    ShopifyReconciliationStatus::Duplicate,
                    existing.poll_cursor_binding.clone(),
                    0,
                    None,
                    duplicate_of,
                );
                let checkpoint = self
                    .store
                    .checkpoint_mut(&existing.mission_id, existing.stream)?;
                Ok(checkpoint.record_reconciliation_receipt(receipt))
            }
            ShopifyWebhookIngest::Committed {
                webhook,
                gap,
                out_of_order,
            } => {
                if gap.is_some() {
                    return self.fill_webhook_gap(&webhook, page_size, at, gap);
                }
                let status = if out_of_order {
                    ShopifyReconciliationStatus::Late
                } else {
                    ShopifyReconciliationStatus::PendingPoll
                };
                let receipt = self.build_receipt(
                    &webhook,
                    ShopifyReconciliationSource::Webhook,
                    status,
                    webhook.poll_cursor_binding.clone(),
                    0,
                    None,
                    None,
                );
                let checkpoint = self
                    .store
                    .checkpoint_mut(&webhook.mission_id, webhook.stream)?;
                Ok(checkpoint.record_reconciliation_receipt(receipt))
            }
        }
    }

    fn durable_webhook(
        &self,
        webhook: &ShopifyWebhookCheckpoint,
    ) -> Result<&ShopifyWebhookCheckpoint, ShopifyError> {
        self.store
            .checkpoint(&webhook.mission_id, webhook.stream)
            .ok_or(ShopifyError::CheckpointMissing)?
            .webhook_checkpoints()
            .iter()
            .find(|existing| existing.delivery_id == webhook.delivery_id)
            .ok_or(ShopifyError::WebhookCheckpointMissing)
    }

    fn exact_receipt(
        &self,
        webhook: &ShopifyWebhookCheckpoint,
    ) -> Option<&ShopifyReconciliationReceipt> {
        self.store
            .checkpoint(&webhook.mission_id, webhook.stream)?
            .reconciliation_receipts()
            .iter()
            .find(|receipt| {
                receipt.delivery_id == webhook.delivery_id
                    && receipt.status == ShopifyReconciliationStatus::Exact
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_receipt(
        &self,
        webhook: &ShopifyWebhookCheckpoint,
        source: ShopifyReconciliationSource,
        status: ShopifyReconciliationStatus,
        poll_cursor_binding: ShopifyPollCursorBinding,
        poll_pages: u32,
        gap: Option<ShopifySequenceGap>,
        duplicate_of: Option<String>,
    ) -> ShopifyReconciliationReceipt {
        let source_tag = match source {
            ShopifyReconciliationSource::Webhook => "webhook",
            ShopifyReconciliationSource::Poll => "poll",
            ShopifyReconciliationSource::GapFill => "gap-fill",
        };
        let status_tag = match status {
            ShopifyReconciliationStatus::PendingPoll => "pending-poll",
            ShopifyReconciliationStatus::Exact => "exact",
            ShopifyReconciliationStatus::Duplicate => "duplicate",
            ShopifyReconciliationStatus::Late => "late",
            ShopifyReconciliationStatus::GapPending => "gap-pending",
            ShopifyReconciliationStatus::NotObserved => "not-observed",
        };
        let generation = webhook.generation.to_string();
        let poll_pages_string = poll_pages.to_string();
        let resource_updated_at = webhook.resource_updated_at.to_rfc3339();
        let receipt_id = shopify_digest([
            webhook.mission_id.as_str(),
            webhook.stream.capability_id(),
            webhook.delivery_id.as_str(),
            webhook.event_id.as_deref().unwrap_or_default(),
            generation.as_str(),
            source_tag,
            status_tag,
            webhook.resource_id.as_str(),
            resource_updated_at.as_str(),
            poll_cursor_binding.cursor_digest.as_str(),
            poll_pages_string.as_str(),
            duplicate_of.as_deref().unwrap_or_default(),
        ]);
        ShopifyReconciliationReceipt {
            receipt_id: format!("shopify-reconciliation-{receipt_id}"),
            mission_id: webhook.mission_id.clone(),
            stream: webhook.stream,
            delivery_id: webhook.delivery_id.clone(),
            event_id: webhook.event_id.clone(),
            topic: webhook.topic.clone(),
            shop: webhook.shop.clone(),
            api_version: webhook.api_version.clone(),
            provider_digest: webhook.provider_digest.clone(),
            generation: webhook.generation,
            source,
            status,
            resource_id: webhook.resource_id.clone(),
            resource_updated_at: webhook.resource_updated_at,
            poll_cursor_binding,
            poll_pages,
            gap,
            duplicate_of,
            provenance_class: self.provenance_class,
            live_validation_status: SHOPIFY_CURSOR_LIVE_VALIDATION_STATUS.into(),
        }
    }

    fn fill_webhook_gap(
        &mut self,
        webhook: &ShopifyWebhookCheckpoint,
        page_size: u32,
        at: DateTime<Utc>,
        gap: Option<ShopifySequenceGap>,
    ) -> Result<ShopifyReconciliationReceipt, ShopifyError> {
        let mut poll_pages: u32 = 0;
        let mut last_binding = webhook.poll_cursor_binding.clone();
        for offset in 0..SHOPIFY_RECONCILIATION_MAX_POLL_PAGES {
            let envelope = match self.read_next(
                webhook.mission_id.clone(),
                webhook.stream,
                page_size,
                at + Duration::seconds(i64::from(offset)),
            ) {
                Ok(envelope) => envelope,
                Err(ShopifyError::CheckpointComplete) => break,
                Err(error) => return Err(error),
            };
            poll_pages = poll_pages.saturating_add(1);
            last_binding = envelope.poll_cursor_binding.clone();
            let exact = matches!(
                envelope.reconcile_webhook(webhook)?,
                ShopifyPollReconcile::Exact { .. }
            );
            if exact {
                self.reconcile_webhook(&envelope, webhook)?;
                self.commit(&envelope)?;
                let receipt = self.build_receipt(
                    webhook,
                    ShopifyReconciliationSource::GapFill,
                    ShopifyReconciliationStatus::Exact,
                    last_binding,
                    poll_pages,
                    gap,
                    None,
                );
                let checkpoint = self
                    .store
                    .checkpoint_mut(&webhook.mission_id, webhook.stream)?;
                return Ok(checkpoint.record_reconciliation_receipt(receipt));
            }
            self.commit(&envelope)?;
            if envelope.next_cursor.is_none() {
                break;
            }
        }
        let complete = self
            .store
            .checkpoint(&webhook.mission_id, webhook.stream)
            .ok_or(ShopifyError::CheckpointMissing)?
            .is_complete();
        let status = if complete {
            ShopifyReconciliationStatus::NotObserved
        } else {
            ShopifyReconciliationStatus::GapPending
        };
        let receipt = self.build_receipt(
            webhook,
            ShopifyReconciliationSource::GapFill,
            status,
            last_binding,
            poll_pages,
            gap,
            None,
        );
        let checkpoint = self
            .store
            .checkpoint_mut(&webhook.mission_id, webhook.stream)?;
        Ok(checkpoint.record_reconciliation_receipt(receipt))
    }

    pub fn rotate_auth(&mut self, next: ShopifyAuthBinding) -> Result<(), ShopifyError> {
        if self.store.lifecycle != ShopifyCursorStoreLifecycle::Mounted
            || next.scope() != self.tenant_scope.scope()
            || self.auth.as_ref().is_some_and(|current| {
                next.secret_reference().credential_revision()
                    <= current.secret_reference().credential_revision()
            })
        {
            return Err(ShopifyError::CredentialRotationRejected);
        }
        self.store.rotate_generation(next.generation())?;
        self.auth = Some(next);
        Ok(())
    }

    pub fn revoke(&mut self) -> ShopifyUnmountReceipt {
        self.auth = None;
        self.store.revoke()
    }

    pub fn unmount(&mut self) -> ShopifyUnmountReceipt {
        self.auth = None;
        self.store.unmount()
    }
}

pub fn read_shop_identity<T: ShopifyAdminTransport>(
    transport: &mut T,
    shop: &ShopDomain,
    api_version: &ShopifyApiVersion,
    requested_scopes: ShopifyScopeSet,
) -> Result<ShopifyShopRead, ShopifyError> {
    let request = ShopifyGraphqlRequest::new(
        shop.clone(),
        api_version.clone(),
        "ShopifyShopIdentity",
        SHOP_IDENTITY_QUERY,
        Value::Object(serde_json::Map::new()),
    )?;
    let response = transport
        .execute(request)
        .map_err(|error| ShopifyError::Transport(error.to_string()))?;
    let payload = response.data::<ShopIdentityPayload>()?;
    let domain = ShopDomain::parse(payload.shop.myshopify_domain)?;
    if &domain != shop {
        return Err(ShopifyError::ShopIdentityMismatch {
            requested: shop.to_string(),
            observed: domain.to_string(),
        });
    }
    let identity = ShopifyShopIdentity::new(
        ShopifyShopGid::parse(payload.shop.id)?,
        domain,
        payload.shop.name,
    )?;
    let granted = ShopifyScopeSet::new(
        payload
            .current_app_installation
            .access_scopes
            .into_iter()
            .map(|scope| scope.handle)
            .collect::<Vec<_>>(),
    )?;
    Ok(ShopifyShopRead {
        identity,
        scopes: ShopifyScopeObservation {
            requested: requested_scopes,
            granted,
            observed_at: CanonicalTime::from_datetime(Utc::now()),
        },
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyProductRead {
    pub product_gid: String,
    pub title: String,
    pub variant_skus: Vec<CanonicalSku>,
}

pub fn read_products_paginated<T: ShopifyAdminTransport>(
    transport: &mut T,
    shop: &ShopDomain,
    api_version: &ShopifyApiVersion,
    page_size: u32,
) -> Result<Vec<ShopifyProductRead>, ShopifyError> {
    if !(1..=250).contains(&page_size) {
        return Err(ShopifyError::InvalidPageSize(page_size));
    }
    let mut products = Vec::new();
    let mut after: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    for _ in 0..1_000 {
        let variables = json!({"first": page_size, "after": after});
        let request = ShopifyGraphqlRequest::new(
            shop.clone(),
            api_version.clone(),
            "ShopifyProductsPage",
            PRODUCTS_PAGE_QUERY,
            variables,
        )?;
        let response = transport
            .execute(request)
            .map_err(|error| ShopifyError::Transport(error.to_string()))?;
        let payload = response.data::<ProductsPagePayload>()?;
        for edge in payload.products.edges {
            let product_gid = edge.node.id;
            if !product_gid.starts_with("gid://shopify/Product/") {
                return Err(ShopifyError::InvalidProductGid(product_gid));
            }
            let variant_skus = edge
                .node
                .variants
                .nodes
                .into_iter()
                .filter_map(|variant| variant.sku)
                .map(CanonicalSku::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ShopifyError::CanonicalIdentity)?;
            products.push(ShopifyProductRead {
                product_gid,
                title: edge.node.title,
                variant_skus,
            });
        }
        if !payload.products.page_info.has_next_page {
            return Ok(products);
        }
        let cursor = payload
            .products
            .page_info
            .end_cursor
            .ok_or(ShopifyError::MissingPageCursor)?;
        if !seen_cursors.insert(cursor.clone()) {
            return Err(ShopifyError::RepeatedPageCursor(cursor));
        }
        after = Some(cursor);
    }
    Err(ShopifyError::PaginationLimit)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShopifyBulkStatus {
    Created,
    Running,
    Completed,
    Failed,
    Canceled,
    Canceling,
}

impl ShopifyBulkStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Canceled)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyBulkOperation {
    pub id: String,
    pub status: ShopifyBulkStatus,
    pub error_code: Option<String>,
    pub result_url: Option<String>,
    pub object_count: Option<u64>,
}

impl ShopifyBulkOperation {
    fn from_payload(payload: BulkOperationPayload) -> Result<Self, ShopifyError> {
        let id = payload.id.ok_or(ShopifyError::MissingBulkOperation)?;
        if !id.starts_with("gid://shopify/BulkOperation/") {
            return Err(ShopifyError::InvalidBulkOperationId(id));
        }
        let result_url = payload
            .url
            .map(|url| {
                let parsed = Url::parse(&url)
                    .map_err(|_| ShopifyError::InvalidBulkResultUrl(url.clone()))?;
                if parsed.scheme() != "https" {
                    return Err(ShopifyError::InvalidBulkResultUrl(url));
                }
                Ok(url)
            })
            .transpose()?;
        Ok(Self {
            id,
            status: payload.status,
            error_code: payload.error_code,
            result_url,
            object_count: payload.object_count,
        })
    }
}

pub fn start_bulk_product_read<T: ShopifyAdminTransport>(
    transport: &mut T,
    shop: ShopDomain,
    api_version: ShopifyApiVersion,
) -> Result<ShopifyBulkOperation, ShopifyError> {
    let request = ShopifyGraphqlRequest::new(
        shop,
        api_version,
        "ShopifyBulkProducts",
        BULK_PRODUCTS_MUTATION,
        Value::Object(serde_json::Map::new()),
    )?;
    let response = transport
        .execute(request)
        .map_err(|error| ShopifyError::Transport(error.to_string()))?;
    let payload = response.data::<BulkRunPayload>()?;
    if !payload.bulk_operation_run_query.user_errors.is_empty() {
        return Err(ShopifyError::GraphqlUserErrors(
            payload
                .bulk_operation_run_query
                .user_errors
                .into_iter()
                .map(|error| error.message)
                .collect::<Vec<_>>(),
        ));
    }
    ShopifyBulkOperation::from_payload(
        payload
            .bulk_operation_run_query
            .bulk_operation
            .ok_or(ShopifyError::MissingBulkOperation)?,
    )
}

pub fn poll_bulk_operation<T: ShopifyAdminTransport>(
    transport: &mut T,
    shop: ShopDomain,
    api_version: ShopifyApiVersion,
    operation_id: impl Into<String>,
) -> Result<ShopifyBulkOperation, ShopifyError> {
    let operation_id = operation_id.into();
    if !operation_id.starts_with("gid://shopify/BulkOperation/") {
        return Err(ShopifyError::InvalidBulkOperationId(operation_id));
    }
    let request = ShopifyGraphqlRequest::new(
        shop,
        api_version,
        "ShopifyBulkOperation",
        BULK_OPERATION_QUERY,
        json!({"id": operation_id}),
    )?;
    let response = transport
        .execute(request)
        .map_err(|error| ShopifyError::Transport(error.to_string()))?;
    let payload = response.data::<BulkNodePayload>()?;
    ShopifyBulkOperation::from_payload(payload.node.ok_or(ShopifyError::MissingBulkOperation)?)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ShopifyWebhookHeaders {
    pub hmac_sha256: String,
    pub webhook_id: String,
    pub topic: String,
    pub shop_domain: ShopDomain,
    pub api_version: ShopifyApiVersion,
}

impl ShopifyWebhookHeaders {
    pub fn new(
        hmac_sha256: impl Into<String>,
        webhook_id: impl Into<String>,
        topic: impl Into<String>,
        shop_domain: ShopDomain,
        api_version: ShopifyApiVersion,
    ) -> Result<Self, ShopifyError> {
        let hmac_sha256 = hmac_sha256.into();
        let webhook_id = webhook_id.into();
        let topic = topic.into();
        if hmac_sha256.trim().is_empty() || webhook_id.trim().is_empty() || topic.trim().is_empty()
        {
            return Err(ShopifyError::InvalidWebhookHeaders);
        }
        Ok(Self {
            hmac_sha256,
            webhook_id,
            topic,
            shop_domain,
            api_version,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedShopifyWebhook {
    pub headers: ShopifyWebhookHeaders,
    pub raw_body_sha256: String,
}

impl VerifiedShopifyWebhook {
    pub fn dedupe_key(&self) -> &str {
        &self.headers.webhook_id
    }

    pub fn ensure_shop(&self, expected: &ShopDomain) -> Result<(), ShopifyError> {
        if &self.headers.shop_domain != expected {
            return Err(ShopifyError::WebhookShopMismatch {
                expected: expected.to_string(),
                observed: self.headers.shop_domain.to_string(),
            });
        }
        Ok(())
    }
}

pub fn verify_webhook_delivery(
    raw_body: &[u8],
    headers: ShopifyWebhookHeaders,
    client_secret: &[u8],
) -> Result<VerifiedShopifyWebhook, ShopifyError> {
    let signature = BASE64
        .decode(headers.hmac_sha256.as_bytes())
        .map_err(|_| ShopifyError::InvalidWebhookSignature)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, client_secret);
    hmac::verify(&key, raw_body, &signature).map_err(|_| ShopifyError::InvalidWebhookSignature)?;
    let mut digest = Sha256::new();
    digest.update(raw_body);
    Ok(VerifiedShopifyWebhook {
        headers,
        raw_body_sha256: format!("{:x}", digest.finalize()),
    })
}

/// Verifies a raw Shopify delivery and promotes it to a durable cursor
/// checkpoint only after its stream resource identity and update timestamp are
/// present.  The secret bytes are consumed at the boundary and never stored.
#[allow(clippy::too_many_arguments)]
pub fn verify_cursor_webhook_delivery(
    raw_body: &[u8],
    headers: ShopifyWebhookHeaders,
    client_secret: &[u8],
    tenant_scope: &ShopifyTenantScope,
    stream: ShopifyCursorStream,
    mission_id: impl Into<String>,
    sequence: u64,
    event_id: Option<String>,
    occurred_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
) -> Result<ShopifyWebhookCheckpoint, ShopifyError> {
    verify_cursor_webhook_delivery_for_generation(
        raw_body,
        headers,
        client_secret,
        tenant_scope,
        stream,
        mission_id,
        sequence,
        event_id,
        occurred_at,
        received_at,
        1,
    )
}

/// Verifies a Shopify delivery and binds it to an explicit auth generation.
/// The generation is supplied by the mounted connector, never inferred from
/// fixture data or from the webhook payload.
#[allow(clippy::too_many_arguments)]
pub fn verify_cursor_webhook_delivery_for_generation(
    raw_body: &[u8],
    headers: ShopifyWebhookHeaders,
    client_secret: &[u8],
    tenant_scope: &ShopifyTenantScope,
    stream: ShopifyCursorStream,
    mission_id: impl Into<String>,
    sequence: u64,
    event_id: Option<String>,
    occurred_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    generation: u64,
) -> Result<ShopifyWebhookCheckpoint, ShopifyError> {
    let verified = verify_webhook_delivery(raw_body, headers, client_secret)?;
    let payload = serde_json::from_slice::<Value>(raw_body)
        .map_err(|error| ShopifyError::MalformedWebhookPayload(error.to_string()))?;
    let raw_resource_id = payload
        .get("admin_graphql_api_id")
        .or_else(|| payload.get("adminGraphqlApiId"))
        .or_else(|| payload.get("id"))
        .and_then(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .or_else(|| value.as_u64().map(|id| id.to_string()))
        })
        .ok_or(ShopifyError::MissingWebhookResource)?;
    let resource_id = if raw_resource_id.starts_with("gid://shopify/") {
        raw_resource_id
    } else {
        let prefix = match stream {
            ShopifyCursorStream::Products => "gid://shopify/Product/",
            ShopifyCursorStream::Orders => "gid://shopify/Order/",
        };
        format!("{prefix}{raw_resource_id}")
    };
    let updated_at = payload
        .get("updated_at")
        .or_else(|| payload.get("updatedAt"))
        .and_then(Value::as_str)
        .ok_or(ShopifyError::MissingWebhookUpdatedAt)
        .and_then(parse_shopify_time)?;
    ShopifyWebhookCheckpoint::from_verified_for_generation(
        &verified,
        tenant_scope,
        stream,
        mission_id,
        sequence,
        event_id,
        resource_id,
        updated_at,
        occurred_at,
        received_at,
        generation,
    )
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ShopifyTransportError {
    #[error("Shopify transport failed: {0}")]
    Failed(String),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ShopifyError {
    #[error("invalid Shopify API version {0}")]
    InvalidApiVersion(String),
    #[error("invalid Shopify shop domain {0}")]
    InvalidShopDomain(String),
    #[error("invalid Shopify Shop GID {0}")]
    InvalidShopGid(String),
    #[error("invalid Shopify shop name")]
    InvalidShopName,
    #[error("invalid Shopify access scope {0}")]
    InvalidScope(String),
    #[error("invalid Shopify tenant scope")]
    InvalidTenantScope,
    #[error("Shopify read requires scope {0}")]
    MissingRequiredScope(String),
    #[error("invalid Shopify authenticated binding")]
    InvalidAuthBinding,
    #[error("Shopify authentication is unavailable")]
    AuthenticationUnavailable,
    #[error("Shopify live validation is BLOCKED_ENV")]
    BlockedEnv,
    #[error("Shopify connector is revoked or unmounted")]
    ConsumerNotMounted,
    #[error("Shopify credential rotation was rejected")]
    CredentialRotationRejected,
    #[error("invalid Shopify mission id")]
    InvalidMissionId,
    #[error("invalid Shopify auth generation")]
    InvalidGeneration,
    #[error("invalid Shopify request: {0}")]
    InvalidRequest(String),
    #[error("Shopify HTTP status {0}")]
    HttpStatus(u16),
    #[error("Shopify GraphQL errors: {0}")]
    GraphqlErrors(String),
    #[error("Shopify GraphQL user errors: {0:?}")]
    GraphqlUserErrors(Vec<String>),
    #[error("Shopify response has no data")]
    MissingData,
    #[error("malformed Shopify response: {0}")]
    MalformedResponse(String),
    #[error("Shopify GraphQL response does not contain cost/quota metadata")]
    MissingGraphqlCost,
    #[error("Shopify GraphQL cost/quota metadata is invalid")]
    InvalidGraphqlCost,
    #[error("Shopify read provenance is missing or invalid")]
    InvalidReadProvenance,
    #[error("Shopify freshness window is invalid")]
    InvalidFreshness,
    #[error("Shopify checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("Shopify checkpoint is missing")]
    CheckpointMissing,
    #[error("Shopify checkpoint scope/provider binding does not match")]
    CheckpointScopeMismatch,
    #[error("Shopify checkpoint generation does not match the mounted auth")]
    CheckpointGenerationMismatch,
    #[error("Shopify checkpoint page size does not match the mounted query")]
    CheckpointPageSizeMismatch,
    #[error("Shopify checkpoint has already reached the end")]
    CheckpointComplete,
    #[error("Shopify checkpoint commit conflicts with the durable state")]
    CheckpointConflict,
    #[error("Shopify page cursor is invalid")]
    InvalidPageCursor,
    #[error("Shopify GraphQL cursor read requires a page cursor")]
    InvalidCursorCheckpoint,
    #[error("Shopify webhook checkpoint is invalid")]
    InvalidWebhookCheckpoint,
    #[error("Shopify webhook payload has no resource identity")]
    MissingWebhookResource,
    #[error("Shopify webhook payload has no updated timestamp")]
    MissingWebhookUpdatedAt,
    #[error("malformed Shopify webhook payload: {0}")]
    MalformedWebhookPayload(String),
    #[error("Shopify webhook checkpoint conflicts with durable state")]
    WebhookCheckpointConflict,
    #[error("Shopify webhook belongs to an invalidated auth generation")]
    WebhookGenerationMismatch,
    #[error("Shopify webhook is not bound to a compatible poll cursor")]
    WebhookCursorBindingMismatch,
    #[error("Shopify webhook checkpoint is missing")]
    WebhookCheckpointMissing,
    #[error("Shopify webhook topic does not match the cursor stream")]
    WebhookStreamMismatch,
    #[error("Shopify resource id is invalid for the cursor stream")]
    InvalidWebhookResource,
    #[error("invalid Shopify timestamp {0}")]
    InvalidTimestamp(String),
    #[error("Shopify transport failed: {0}")]
    Transport(String),
    #[error("Shopify response belongs to {observed}, not requested {requested}")]
    ShopIdentityMismatch { requested: String, observed: String },
    #[error("invalid Shopify product GID {0}")]
    InvalidProductGid(String),
    #[error("invalid Shopify order GID {0}")]
    InvalidOrderGid(String),
    #[error("invalid Shopify page size {0}; expected 1..=250")]
    InvalidPageSize(u32),
    #[error("Shopify page reported a next page without an end cursor")]
    MissingPageCursor,
    #[error("Shopify pagination repeated cursor {0}")]
    RepeatedPageCursor(String),
    #[error("Shopify pagination exceeded the safety bound")]
    PaginationLimit,
    #[error("Shopify bulk operation is missing an id")]
    MissingBulkOperation,
    #[error("invalid Shopify bulk operation id {0}")]
    InvalidBulkOperationId(String),
    #[error("invalid Shopify bulk result URL {0}")]
    InvalidBulkResultUrl(String),
    #[error("invalid Shopify webhook headers")]
    InvalidWebhookHeaders,
    #[error("invalid Shopify webhook HMAC signature")]
    InvalidWebhookSignature,
    #[error("Shopify webhook belongs to {observed}, not expected {expected}")]
    WebhookShopMismatch { expected: String, observed: String },
    #[error("connector SDK boundary rejected the Shopify read: {0}")]
    Connector(#[from] ConnectorError),
    #[error("canonical identity error: {0}")]
    CanonicalIdentity(#[from] CanonicalIdentityError),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShopIdentityPayload {
    shop: ShopPayload,
    current_app_installation: AppInstallationPayload,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShopPayload {
    id: String,
    name: String,
    myshopify_domain: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppInstallationPayload {
    access_scopes: Vec<AccessScopePayload>,
}

#[derive(Clone, Debug, Deserialize)]
struct AccessScopePayload {
    handle: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProductsPagePayload {
    products: ShopifyConnection<ShopifyProductNode>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShopifyConnection<T> {
    edges: Vec<ShopifyEdge<T>>,
    page_info: ShopifyPageInfo,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShopifyEdge<T> {
    #[allow(dead_code)]
    cursor: String,
    node: T,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShopifyPageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShopifyProductNode {
    id: String,
    title: String,
    variants: ShopifyNodeConnection<ShopifyVariantNode>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShopifyNodeConnection<T> {
    nodes: Vec<T>,
    #[allow(dead_code)]
    page_info: ShopifyPageInfo,
}

#[derive(Clone, Debug, Deserialize)]
struct ShopifyVariantNode {
    #[allow(dead_code)]
    id: String,
    sku: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkRunPayload {
    bulk_operation_run_query: BulkRunResult,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkRunResult {
    bulk_operation: Option<BulkOperationPayload>,
    user_errors: Vec<UserErrorPayload>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserErrorPayload {
    #[allow(dead_code)]
    field: Option<Vec<String>>,
    message: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkNodePayload {
    node: Option<BulkOperationPayload>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkOperationPayload {
    id: Option<String>,
    status: ShopifyBulkStatus,
    error_code: Option<String>,
    url: Option<String>,
    object_count: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorProductsPagePayload {
    products: ShopifyConnection<CursorProductNode>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorOrdersPagePayload {
    orders: ShopifyConnection<CursorOrderNode>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorProductNode {
    id: String,
    title: String,
    updated_at: String,
    variants: ShopifyNodeConnection<ShopifyVariantNode>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorOrderNode {
    id: String,
    updated_at: String,
}

fn parse_cursor_items(
    response: &ShopifyGraphqlResponse,
    stream: ShopifyCursorStream,
) -> Result<(ShopifyTypedItems, Option<String>, bool), ShopifyError> {
    match stream {
        ShopifyCursorStream::Products => {
            let payload = response.data::<CursorProductsPagePayload>()?;
            let next_cursor = payload.products.page_info.end_cursor;
            let has_next_page = payload.products.page_info.has_next_page;
            let items = payload
                .products
                .edges
                .into_iter()
                .map(|edge| {
                    let product_gid = edge.node.id;
                    if !product_gid.starts_with("gid://shopify/Product/") {
                        return Err(ShopifyError::InvalidProductGid(product_gid));
                    }
                    let updated_at = parse_shopify_time(&edge.node.updated_at)?;
                    let variant_skus = edge
                        .node
                        .variants
                        .nodes
                        .into_iter()
                        .filter_map(|variant| variant.sku)
                        .map(CanonicalSku::parse)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(ShopifyError::CanonicalIdentity)?;
                    Ok(ShopifyCursorProduct {
                        product_gid,
                        title: edge.node.title,
                        updated_at,
                        variant_skus,
                    })
                })
                .collect::<Result<Vec<_>, ShopifyError>>()?;
            Ok((
                ShopifyTypedItems::Products(items),
                next_cursor,
                has_next_page,
            ))
        }
        ShopifyCursorStream::Orders => {
            let payload = response.data::<CursorOrdersPagePayload>()?;
            let next_cursor = payload.orders.page_info.end_cursor;
            let has_next_page = payload.orders.page_info.has_next_page;
            let items = payload
                .orders
                .edges
                .into_iter()
                .map(|edge| {
                    let order_gid = edge.node.id;
                    if !order_gid.starts_with("gid://shopify/Order/") {
                        return Err(ShopifyError::InvalidOrderGid(order_gid));
                    }
                    Ok(ShopifyCursorOrder {
                        order_gid,
                        updated_at: parse_shopify_time(&edge.node.updated_at)?,
                    })
                })
                .collect::<Result<Vec<_>, ShopifyError>>()?;
            Ok((ShopifyTypedItems::Orders(items), next_cursor, has_next_page))
        }
    }
}

fn parse_shopify_time(value: &str) -> Result<DateTime<Utc>, ShopifyError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| ShopifyError::InvalidTimestamp(value.into()))
}

const fn default_generation() -> u64 {
    1
}

fn validate_generation(generation: u64) -> Result<(), ShopifyError> {
    if generation == 0 {
        Err(ShopifyError::InvalidGeneration)
    } else {
        Ok(())
    }
}

fn required_u64(value: &Value, field: &str) -> Result<u64, ShopifyError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ShopifyError::InvalidGraphqlCost)
}

fn validate_page_size(page_size: u32) -> Result<(), ShopifyError> {
    if (1..=250).contains(&page_size) {
        Ok(())
    } else {
        Err(ShopifyError::InvalidPageSize(page_size))
    }
}

fn validate_mission_id(value: &str) -> Result<(), ShopifyError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ShopifyError::InvalidMissionId);
    }
    Ok(())
}

fn valid_resource_id(stream: ShopifyCursorStream, value: &str) -> bool {
    let prefix = match stream {
        ShopifyCursorStream::Products => "gid://shopify/Product/",
        ShopifyCursorStream::Orders => "gid://shopify/Order/",
    };
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn shopify_provider_digest(
    tenant_scope: &ShopifyTenantScope,
    api_version: &ShopifyApiVersion,
    stream: ShopifyCursorStream,
) -> String {
    shopify_digest([
        SHOPIFY_PROVIDER_ID,
        SHOPIFY_CURSOR_ADAPTER_ID,
        &tenant_scope.digest(),
        tenant_scope.shop().as_str(),
        api_version.as_str(),
        stream.capability_id(),
        SHOPIFY_CURSOR_EVIDENCE_LEVEL,
    ])
}

fn shopify_query_digest(
    tenant_scope: &ShopifyTenantScope,
    api_version: &ShopifyApiVersion,
    stream: ShopifyCursorStream,
    page_size: u32,
) -> String {
    shopify_digest([
        stream.query(),
        stream.operation_name(),
        &page_size.to_string(),
        tenant_scope.shop().as_str(),
        api_version.as_str(),
        &tenant_scope.scope().digest(),
    ])
}

fn shopify_digest<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let material = parts
        .into_iter()
        .map(|part| format!("{}:{}", part.len(), part))
        .collect::<Vec<_>>()
        .join("|");
    sha256_string(&material)
}

fn sha256_string(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn sha256_bytes(value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(value);
    format!("{:x}", digest.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shop_domain_and_endpoint_are_exact() {
        let domain = ShopDomain::parse("Demo-Shop.myshopify.com").expect("domain");
        assert_eq!(domain.as_str(), "demo-shop.myshopify.com");
        assert_eq!(
            domain
                .admin_graphql_endpoint(&ShopifyApiVersion::latest())
                .as_str(),
            "https://demo-shop.myshopify.com/admin/api/2026-07/graphql.json"
        );
        assert!(ShopDomain::parse("https://demo-shop.myshopify.com/path").is_err());
        assert!(ShopDomain::parse("demo-shop.example.com").is_err());
    }

    #[test]
    fn webhook_hmac_is_verified_over_raw_bytes() {
        let body = br#"{"topic":"orders/create"}"#;
        let secret = b"fixture-shopify-secret";
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let signature = BASE64.encode(hmac::sign(&key, body).as_ref());
        let headers = ShopifyWebhookHeaders::new(
            signature,
            "delivery-1",
            "orders/create",
            ShopDomain::parse("demo-shop.myshopify.com").expect("domain"),
            ShopifyApiVersion::latest(),
        )
        .expect("headers");
        let verified = verify_webhook_delivery(body, headers, secret).expect("valid HMAC");
        assert_eq!(verified.dedupe_key(), "delivery-1");
        assert!(verify_webhook_delivery(br"{}", verified.headers, secret).is_err());
    }
}

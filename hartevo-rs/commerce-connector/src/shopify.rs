//! Shopify Admin GraphQL read seam.
//!
//! The seam requires the caller to provide an implementation-specific
//! transport.  It builds exact Admin GraphQL requests, validates the shop and
//! granted scopes, supports cursor pagination and bulk-query observation, and
//! verifies HTTPS webhook signatures before a payload can be parsed.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
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
pub const SHOPIFY_READ_EVIDENCE_LEVEL: &str = "E1";
pub const SHOPIFY_LIVE_VALIDATION_STATUS: &str = "BLOCKED_ENV";
pub const SHOPIFY_HMAC_HEADER: &str = "X-Shopify-Hmac-SHA256";
pub const SHOPIFY_REQUEST_ID_HEADER: &str = "X-Request-ID";
pub const SHOPIFY_WEBHOOK_ID_HEADER: &str = "X-Shopify-Webhook-Id";
pub const SHOPIFY_TOPIC_HEADER: &str = "X-Shopify-Topic";
pub const SHOPIFY_SHOP_DOMAIN_HEADER: &str = "X-Shopify-Shop-Domain";
pub const SHOPIFY_API_VERSION_HEADER: &str = "X-Shopify-API-Version";

pub const SHOP_IDENTITY_QUERY: &str = "query ShopifyShopIdentity { shop { id name myshopifyDomain } currentAppInstallation { accessScopes { handle } } }";
pub const PRODUCTS_PAGE_QUERY: &str = "query ShopifyProductsPage($first: Int!, $after: String) { products(first: $first, after: $after) { edges { cursor node { id title variants(first: 100) { nodes { id sku } pageInfo { hasNextPage endCursor } } } } pageInfo { hasNextPage endCursor } } }";
pub const BULK_PRODUCTS_MUTATION: &str = "mutation ShopifyBulkProducts { bulkOperationRunQuery(query: \"{ products { edges { node { id title variants { nodes { id sku } } } } } }\") { bulkOperation { id status } userErrors { field message } } }";
pub const BULK_OPERATION_QUERY: &str = "query ShopifyBulkOperation($id: ID!) { bulkOperation(id: $id) { id status errorCode url objectCount completedAt } }";

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

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyCredentialReference(String);

impl ShopifyCredentialReference {
    /// Store only a vault/keychain reference; never put Shopify access tokens in this model.
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ShopifyError::InvalidCredentialReference(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyAuthStatus {
    Disconnected,
    BlockedEnv,
    CredentialReferenceOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyBlockedEnvReason {
    CredentialsUnavailable,
    NetworkUnavailable,
    ProviderUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ShopifyAuthState {
    Disconnected {
        observed_at: CanonicalTime,
    },
    BlockedEnv {
        observed_at: CanonicalTime,
        reason: ShopifyBlockedEnvReason,
    },
    CredentialReferenceOnly {
        observed_at: CanonicalTime,
        credential: ShopifyCredentialReference,
    },
}

impl ShopifyAuthState {
    pub fn disconnected(observed_at: DateTime<Utc>) -> Self {
        Self::Disconnected {
            observed_at: CanonicalTime::from_datetime(observed_at),
        }
    }

    pub fn no_credentials(observed_at: DateTime<Utc>) -> Self {
        Self::blocked_env(observed_at, ShopifyBlockedEnvReason::CredentialsUnavailable)
    }

    pub fn blocked_env(observed_at: DateTime<Utc>, reason: ShopifyBlockedEnvReason) -> Self {
        Self::BlockedEnv {
            observed_at: CanonicalTime::from_datetime(observed_at),
            reason,
        }
    }

    pub fn credential_reference_only(
        observed_at: DateTime<Utc>,
        credential: ShopifyCredentialReference,
    ) -> Self {
        Self::CredentialReferenceOnly {
            observed_at: CanonicalTime::from_datetime(observed_at),
            credential,
        }
    }

    pub fn status(&self) -> ShopifyAuthStatus {
        match self {
            Self::Disconnected { .. } => ShopifyAuthStatus::Disconnected,
            Self::BlockedEnv { .. } => ShopifyAuthStatus::BlockedEnv,
            Self::CredentialReferenceOnly { .. } => ShopifyAuthStatus::CredentialReferenceOnly,
        }
    }

    pub fn credential(&self) -> Option<&ShopifyCredentialReference> {
        match self {
            Self::CredentialReferenceOnly { credential, .. } => Some(credential),
            Self::Disconnected { .. } | Self::BlockedEnv { .. } => None,
        }
    }

    /// A reference alone is not a live credential and cannot establish a connected state.
    pub const fn can_issue_live_read(&self) -> bool {
        false
    }

    pub const fn grants_connected_authority(&self) -> bool {
        false
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFirstPartyProvenance {
    pub provider_id: String,
    pub evidence_level: String,
    pub shop: ShopDomain,
    pub api_version: ShopifyApiVersion,
    pub operation_name: String,
    pub response_status: u16,
    pub request_id: Option<String>,
    pub response_digest: String,
    pub observed_at: CanonicalTime,
}

impl ShopifyFirstPartyProvenance {
    pub fn from_response(
        request: &ShopifyGraphqlRequest,
        response: &ShopifyGraphqlResponse,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ShopifyError> {
        let response_digest = response.body_digest()?;
        let request_id = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(SHOPIFY_REQUEST_ID_HEADER))
            .map(|(_, value)| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let provenance = Self {
            provider_id: SHOPIFY_PROVIDER_ID.into(),
            evidence_level: SHOPIFY_READ_EVIDENCE_LEVEL.into(),
            shop: request.shop.clone(),
            api_version: request.api_version.clone(),
            operation_name: request.operation_name.clone(),
            response_status: response.status,
            request_id,
            response_digest,
            observed_at: CanonicalTime::from_datetime(observed_at),
        };
        provenance.validate()?;
        Ok(provenance)
    }

    pub fn validate(&self) -> Result<(), ShopifyError> {
        if self.provider_id != SHOPIFY_PROVIDER_ID
            || self.evidence_level != SHOPIFY_READ_EVIDENCE_LEVEL
            || self.operation_name.trim().is_empty()
            || self.response_digest.len() != 64
            || !self
                .response_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ShopifyError::InvalidReadProvenance);
        }
        Ok(())
    }

    pub const fn grants_connected_authority(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyShopRead {
    pub identity: ShopifyShopIdentity,
    pub scopes: ShopifyScopeObservation,
    pub provenance: ShopifyFirstPartyProvenance,
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
    pub fn first_party_provenance(
        &self,
        request: &ShopifyGraphqlRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<ShopifyFirstPartyProvenance, ShopifyError> {
        ShopifyFirstPartyProvenance::from_response(request, self, observed_at)
    }

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
        let mut digest = Sha256::new();
        digest.update(bytes);
        Ok(format!("{:x}", digest.finalize()))
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
        .execute(request.clone())
        .map_err(|error| ShopifyError::Transport(error.to_string()))?;
    let observed_at = Utc::now();
    let provenance = response.first_party_provenance(&request, observed_at)?;
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
            observed_at: CanonicalTime::from_datetime(observed_at),
        },
        provenance,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyProductRead {
    pub product_gid: String,
    pub title: String,
    pub variant_skus: Vec<CanonicalSku>,
    pub provenance: ShopifyFirstPartyProvenance,
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
            .execute(request.clone())
            .map_err(|error| ShopifyError::Transport(error.to_string()))?;
        let provenance = response.first_party_provenance(&request, Utc::now())?;
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
                provenance: provenance.clone(),
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
    pub completed_at: Option<CanonicalTime>,
    pub provenance: ShopifyFirstPartyProvenance,
}

impl ShopifyBulkOperation {
    fn from_payload(
        payload: BulkOperationPayload,
        provenance: ShopifyFirstPartyProvenance,
    ) -> Result<Self, ShopifyError> {
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
            completed_at: payload.completed_at,
            provenance,
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
        .execute(request.clone())
        .map_err(|error| ShopifyError::Transport(error.to_string()))?;
    let provenance = response.first_party_provenance(&request, Utc::now())?;
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
        provenance,
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
        .execute(request.clone())
        .map_err(|error| ShopifyError::Transport(error.to_string()))?;
    let provenance = response.first_party_provenance(&request, Utc::now())?;
    let payload = response.data::<BulkNodePayload>()?;
    ShopifyBulkOperation::from_payload(
        payload
            .bulk_operation
            .ok_or(ShopifyError::MissingBulkOperation)?,
        provenance,
    )
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
    #[error("invalid Shopify credential reference {0}")]
    InvalidCredentialReference(String),
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
    #[error("Shopify read provenance is missing or invalid")]
    InvalidReadProvenance,
    #[error("Shopify transport failed: {0}")]
    Transport(String),
    #[error("Shopify response belongs to {observed}, not requested {requested}")]
    ShopIdentityMismatch { requested: String, observed: String },
    #[error("invalid Shopify product GID {0}")]
    InvalidProductGid(String),
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
    bulk_operation: Option<BulkOperationPayload>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkOperationPayload {
    id: Option<String>,
    status: ShopifyBulkStatus,
    error_code: Option<String>,
    url: Option<String>,
    object_count: Option<u64>,
    completed_at: Option<CanonicalTime>,
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

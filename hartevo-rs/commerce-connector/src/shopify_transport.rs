//! Native, readback-only Shopify Admin GraphQL transport.
//!
//! The transport accepts exactly one operation: reading one known Shopify
//! Fulfillment GID. It cannot search, execute `fulfillmentCreate`, follow a
//! redirect, select an arbitrary host, or retain an access token. Credentials
//! are borrowed for one bounded call and never enter a request/response model.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use hartevo_connector_sdk::ProviderProvenanceClass;

use crate::shopify::{
    SHOPIFY_LATEST_API_VERSION, ShopDomain, ShopifyApiVersion, ShopifyGraphqlRequest,
};
use crate::shopify_effect::{
    FULFILLMENT_READBACK_QUERY, SHOPIFY_FULFILLMENT_MAX_LINE_ITEMS, ShopifyFulfillmentLineItem,
    ShopifyFulfillmentOrderGid, ShopifyFulfillmentOrderLineItemGid, ShopifyOrderGid,
};

pub const SHOPIFY_READBACK_OPERATION_NAME: &str = "ShopifyFulfillmentReadback";
pub const SHOPIFY_RECEIPT_IDENTITY_OPERATION_NAME: &str = "ShopifyFulfillmentReceiptIdentity";
pub const SHOPIFY_RECEIPT_IDENTITY_QUERY: &str = "query ShopifyFulfillmentReceiptIdentity($id: ID!) { fulfillment(id: $id) { id status createdAt updatedAt order { id } fulfillmentOrders(first: 2) { nodes { id lineItems(first: 101) { nodes { id lineItem { id } totalQuantity remainingQuantity } pageInfo { hasNextPage } } } pageInfo { hasNextPage } } fulfillmentLineItems(first: 101) { nodes { lineItem { id } quantity } pageInfo { hasNextPage } } } }";
pub const SHOPIFY_READBACK_MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const SHOPIFY_READBACK_MAX_RESPONSE_BYTES: u64 = 128 * 1024;
pub const SHOPIFY_READBACK_MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;
pub const SHOPIFY_READBACK_GLOBAL_TIMEOUT_SECONDS: u64 = 15;

const SHOPIFY_FULFILLMENT_GID_PREFIX: &str = "gid://shopify/Fulfillment/";
const SHOPIFY_LINE_ITEM_GID_PREFIX: &str = "gid://shopify/LineItem/";

/// Exact provider identifier required by the fixed readback query.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyFulfillmentGid(String);

impl ShopifyFulfillmentGid {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyNativeReadbackError> {
        let value = value.into();
        let suffix = value
            .strip_prefix(SHOPIFY_FULFILLMENT_GID_PREFIX)
            .unwrap_or_default();
        if suffix.is_empty()
            || suffix.len() > 32
            || !suffix.bytes().all(|byte| byte.is_ascii_digit())
            || suffix.starts_with('0')
        {
            return Err(ShopifyNativeReadbackError::InvalidFulfillmentId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ShopifyFulfillmentGid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Credential-free call model. Exact recovery requests may contain sealed
/// business identifiers in memory, so their `Debug` representation is always
/// redacted. Access-token bytes are deliberately absent.
#[derive(Clone, Eq, PartialEq)]
pub struct ShopifyFulfillmentReadbackRequest {
    shop: ShopDomain,
    api_version: ShopifyApiVersion,
    fulfillment_id: ShopifyFulfillmentGid,
    expected_identity: Option<ShopifyExpectedFulfillmentIdentity>,
}

/// Exact approved provider identity used only to validate a known fulfillment
/// object. It contains IDs and quantities, never customer or credential data.
#[derive(Clone, Eq, PartialEq)]
pub struct ShopifyExpectedFulfillmentIdentity {
    order_id: ShopifyOrderGid,
    fulfillment_order_id: ShopifyFulfillmentOrderGid,
    line_items: Vec<ShopifyFulfillmentLineItem>,
    provider_created_at_not_before: DateTime<Utc>,
}

impl ShopifyExpectedFulfillmentIdentity {
    pub fn new(
        order_id: ShopifyOrderGid,
        fulfillment_order_id: ShopifyFulfillmentOrderGid,
        mut line_items: Vec<ShopifyFulfillmentLineItem>,
        provider_created_at_not_before: DateTime<Utc>,
    ) -> Result<Self, ShopifyNativeReadbackError> {
        let validated_order_id = ShopifyOrderGid::parse(order_id.as_str().to_owned())
            .map_err(|_| ShopifyNativeReadbackError::InvalidRequest)?;
        let validated_fulfillment_order_id =
            ShopifyFulfillmentOrderGid::parse(fulfillment_order_id.as_str().to_owned())
                .map_err(|_| ShopifyNativeReadbackError::InvalidRequest)?;
        // Consume the potentially deserialized wrappers. Only the canonical
        // values reconstructed above may enter the exact provider request.
        drop(order_id);
        drop(fulfillment_order_id);
        if line_items.is_empty() || line_items.len() > SHOPIFY_FULFILLMENT_MAX_LINE_ITEMS {
            return Err(ShopifyNativeReadbackError::InvalidRequest);
        }
        for item in &mut line_items {
            item.line_item_gid =
                ShopifyFulfillmentOrderLineItemGid::parse(item.line_item_gid.as_str().to_owned())
                    .map_err(|_| ShopifyNativeReadbackError::InvalidRequest)?;
            if item.quantity == 0 {
                return Err(ShopifyNativeReadbackError::InvalidRequest);
            }
        }
        line_items.sort();
        if line_items
            .windows(2)
            .any(|items| items[0].line_item_gid == items[1].line_item_gid)
        {
            return Err(ShopifyNativeReadbackError::InvalidRequest);
        }
        Ok(Self {
            order_id: validated_order_id,
            fulfillment_order_id: validated_fulfillment_order_id,
            line_items,
            provider_created_at_not_before,
        })
    }

    pub fn order_id(&self) -> &ShopifyOrderGid {
        &self.order_id
    }

    pub fn fulfillment_order_id(&self) -> &ShopifyFulfillmentOrderGid {
        &self.fulfillment_order_id
    }

    pub fn line_items(&self) -> &[ShopifyFulfillmentLineItem] {
        &self.line_items
    }

    pub const fn provider_created_at_not_before(&self) -> DateTime<Utc> {
        self.provider_created_at_not_before
    }
}

impl fmt::Debug for ShopifyExpectedFulfillmentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyExpectedFulfillmentIdentity")
            .field("identity", &"[REDACTED]")
            .field("provider_time_fence", &"[REDACTED]")
            .finish()
    }
}

impl ShopifyFulfillmentReadbackRequest {
    pub fn new(
        shop: ShopDomain,
        api_version: ShopifyApiVersion,
        fulfillment_id: ShopifyFulfillmentGid,
    ) -> Result<Self, ShopifyNativeReadbackError> {
        // Existing Shopify value objects predate this native credential path
        // and may have been created through transparent deserialization.
        // Re-parse at the final request boundary so an invalid typed wrapper
        // can never steer an access token to an arbitrary host or node ID.
        let validated_shop = ShopDomain::parse(shop.as_str().to_owned())
            .map_err(|_| ShopifyNativeReadbackError::InvalidShopDomain)?;
        let validated_fulfillment_id =
            ShopifyFulfillmentGid::parse(fulfillment_id.as_str().to_owned())?;
        // Consume and discard both potentially deserialized wrappers. Only
        // the canonical values reconstructed above enter the request.
        drop(shop);
        drop(fulfillment_id);
        if api_version.as_str() != SHOPIFY_LATEST_API_VERSION {
            return Err(ShopifyNativeReadbackError::ApiVersionNotAllowed);
        }
        let request = Self {
            shop: validated_shop,
            api_version,
            fulfillment_id: validated_fulfillment_id,
            expected_identity: None,
        };
        let encoded = serde_json::to_vec(&request.graphql_body())
            .map_err(|_| ShopifyNativeReadbackError::InvalidRequest)?;
        if encoded.len() > SHOPIFY_READBACK_MAX_REQUEST_BYTES {
            return Err(ShopifyNativeReadbackError::InvalidRequest);
        }
        Ok(request)
    }

    pub fn new_exact(
        shop: ShopDomain,
        api_version: ShopifyApiVersion,
        fulfillment_id: ShopifyFulfillmentGid,
        expected_identity: ShopifyExpectedFulfillmentIdentity,
    ) -> Result<Self, ShopifyNativeReadbackError> {
        let mut request = Self::new(shop, api_version, fulfillment_id)?;
        request.expected_identity = Some(expected_identity);
        let encoded = serde_json::to_vec(&request.graphql_body())
            .map_err(|_| ShopifyNativeReadbackError::InvalidRequest)?;
        if encoded.len() > SHOPIFY_READBACK_MAX_REQUEST_BYTES {
            return Err(ShopifyNativeReadbackError::InvalidRequest);
        }
        Ok(request)
    }

    pub fn shop(&self) -> &ShopDomain {
        &self.shop
    }

    pub fn api_version(&self) -> &ShopifyApiVersion {
        &self.api_version
    }

    pub fn fulfillment_id(&self) -> &ShopifyFulfillmentGid {
        &self.fulfillment_id
    }

    pub fn expected_identity(&self) -> Option<&ShopifyExpectedFulfillmentIdentity> {
        self.expected_identity.as_ref()
    }

    /// Content-free selector binding used to tie a known fulfillment GID to
    /// one exact Cordis reconciliation permit. The digest is evidence, never
    /// provider or execution authority.
    pub fn selector_digest(&self) -> String {
        digest_fields([
            "hartevo-shopify-readback-selector/v1",
            self.shop.as_str(),
            self.api_version.as_str(),
            self.fulfillment_id.as_str(),
        ])
    }

    pub fn endpoint(&self) -> String {
        self.shop
            .admin_graphql_endpoint(&self.api_version)
            .to_string()
    }

    fn graphql_body(&self) -> Value {
        let (operation_name, query) = if self.expected_identity.is_some() {
            (
                SHOPIFY_RECEIPT_IDENTITY_OPERATION_NAME,
                SHOPIFY_RECEIPT_IDENTITY_QUERY,
            )
        } else {
            (SHOPIFY_READBACK_OPERATION_NAME, FULFILLMENT_READBACK_QUERY)
        };
        ShopifyGraphqlRequest::new(
            self.shop.clone(),
            self.api_version.clone(),
            operation_name,
            query,
            json!({ "id": self.fulfillment_id.as_str() }),
        )
        .expect("fixed Shopify readback request is valid")
        .json_body()
    }
}

impl fmt::Debug for ShopifyFulfillmentReadbackRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyFulfillmentReadbackRequest")
            .field("selector", &"[DIGEST]")
            .field("api_version", &self.api_version)
            .field("has_expected_identity", &self.expected_identity.is_some())
            .finish_non_exhaustive()
    }
}

/// Cooperative cancellation fence checked before network dispatch and again
/// before provider evidence is accepted. The native call itself is bounded by
/// a shorter global timeout than the Secret Broker's 60-second lease.
#[derive(Clone, Default)]
pub struct ShopifyReadbackCancellation {
    cancelled: Arc<AtomicBool>,
}

impl ShopifyReadbackCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl fmt::Debug for ShopifyReadbackCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyReadbackCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ShopifyFulfillmentStatus(String);

impl ShopifyFulfillmentStatus {
    fn parse(value: impl Into<String>) -> Result<Self, ShopifyNativeReadbackError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || value.starts_with('_')
            || value.ends_with('_')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        {
            return Err(ShopifyNativeReadbackError::MalformedResponse);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical provider response identity for one exact approved fulfillment.
/// The raw GraphQL body and order-line mapping never cross this boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct ShopifyFulfillmentReceiptIdentity {
    order_id: ShopifyOrderGid,
    fulfillment_order_id: ShopifyFulfillmentOrderGid,
    line_items: Vec<ShopifyFulfillmentLineItem>,
    provider_created_at_not_before: DateTime<Utc>,
    provider_created_at: DateTime<Utc>,
    provider_updated_at: DateTime<Utc>,
    response_digest: String,
}

impl ShopifyFulfillmentReceiptIdentity {
    pub fn order_id(&self) -> &ShopifyOrderGid {
        &self.order_id
    }

    pub fn fulfillment_order_id(&self) -> &ShopifyFulfillmentOrderGid {
        &self.fulfillment_order_id
    }

    pub fn line_items(&self) -> &[ShopifyFulfillmentLineItem] {
        &self.line_items
    }

    pub const fn provider_created_at_not_before(&self) -> DateTime<Utc> {
        self.provider_created_at_not_before
    }

    pub const fn provider_created_at(&self) -> DateTime<Utc> {
        self.provider_created_at
    }

    pub const fn provider_updated_at(&self) -> DateTime<Utc> {
        self.provider_updated_at
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }
}

impl fmt::Debug for ShopifyFulfillmentReceiptIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyFulfillmentReceiptIdentity")
            .field("identity", &"[REDACTED]")
            .field("provider_time_fence", &"[REDACTED]")
            .field("response_digest", &"[DIGEST]")
            .finish()
    }
}

/// Minimal provider metadata returned across the native transport boundary.
/// No response body, header value, token, or GraphQL error text is retained.
#[derive(Clone, Eq, PartialEq)]
pub struct ShopifyFulfillmentReadback {
    fulfillment_id: ShopifyFulfillmentGid,
    status: ShopifyFulfillmentStatus,
    api_version: ShopifyApiVersion,
    request_id_digest: Option<String>,
    evidence_digest: String,
    provenance_class: ProviderProvenanceClass,
    receipt_identity: Option<ShopifyFulfillmentReceiptIdentity>,
}

impl fmt::Debug for ShopifyFulfillmentReadback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyFulfillmentReadback")
            .field("fulfillment_id", &"[REDACTED]")
            .field("status", &self.status)
            .field("api_version", &self.api_version)
            .field(
                "request_id_digest",
                &self.request_id_digest.as_ref().map(|_| "[DIGEST]"),
            )
            .field("evidence_digest", &"[DIGEST]")
            .field("provenance_class", &self.provenance_class)
            .field("has_receipt_identity", &self.receipt_identity.is_some())
            .finish()
    }
}

impl ShopifyFulfillmentReadback {
    pub fn fulfillment_id(&self) -> &ShopifyFulfillmentGid {
        &self.fulfillment_id
    }

    pub fn status(&self) -> &ShopifyFulfillmentStatus {
        &self.status
    }

    pub fn api_version(&self) -> &ShopifyApiVersion {
        &self.api_version
    }

    pub fn request_id_digest(&self) -> Option<&str> {
        self.request_id_digest.as_deref()
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub fn receipt_identity(&self) -> Option<&ShopifyFulfillmentReceiptIdentity> {
        self.receipt_identity.as_ref()
    }

    /// Deterministic offline observation for host-composition tests. Runtime
    /// native providers reject this provenance before accepting evidence.
    pub fn fixture(
        request: &ShopifyFulfillmentReadbackRequest,
        status: impl Into<String>,
    ) -> Result<Self, ShopifyNativeReadbackError> {
        let status = ShopifyFulfillmentStatus::parse(status)?;
        let evidence_digest = digest_fields([
            "hartevo-shopify-fixture-readback/v1",
            request.shop().as_str(),
            request.api_version().as_str(),
            request.fulfillment_id().as_str(),
            status.as_str(),
        ]);
        Ok(Self {
            fulfillment_id: request.fulfillment_id().clone(),
            status,
            api_version: request.api_version().clone(),
            request_id_digest: None,
            evidence_digest,
            provenance_class: ProviderProvenanceClass::Fixture,
            receipt_identity: None,
        })
    }

    /// Deterministic exact-identity fixture. A production provider rejects its
    /// provenance, so tests cannot promote it into live evidence.
    pub fn fixture_exact(
        request: &ShopifyFulfillmentReadbackRequest,
        status: impl Into<String>,
        provider_created_at: DateTime<Utc>,
        provider_updated_at: DateTime<Utc>,
    ) -> Result<Self, ShopifyNativeReadbackError> {
        let expected = request
            .expected_identity()
            .ok_or(ShopifyNativeReadbackError::InvalidRequest)?;
        if provider_created_at < expected.provider_created_at_not_before()
            || provider_updated_at < provider_created_at
        {
            return Err(ShopifyNativeReadbackError::MalformedResponse);
        }
        let status = ShopifyFulfillmentStatus::parse(status)?;
        let response_digest = receipt_identity_digest(
            request,
            expected,
            status.as_str(),
            provider_created_at,
            provider_updated_at,
        );
        let evidence_digest = digest_fields([
            "hartevo-shopify-fixture-receipt-identity/v1",
            request.shop().as_str(),
            request.api_version().as_str(),
            request.fulfillment_id().as_str(),
            status.as_str(),
            response_digest.as_str(),
        ]);
        Ok(Self {
            fulfillment_id: request.fulfillment_id().clone(),
            status,
            api_version: request.api_version().clone(),
            request_id_digest: None,
            evidence_digest,
            provenance_class: ProviderProvenanceClass::Fixture,
            receipt_identity: Some(ShopifyFulfillmentReceiptIdentity {
                order_id: expected.order_id().clone(),
                fulfillment_order_id: expected.fulfillment_order_id().clone(),
                line_items: expected.line_items().to_vec(),
                provider_created_at_not_before: expected.provider_created_at_not_before(),
                provider_created_at,
                provider_updated_at,
                response_digest,
            }),
        })
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ShopifyNativeReadbackError {
    #[error("Shopify shop domain is invalid")]
    InvalidShopDomain,
    #[error("Shopify fulfillment ID is invalid")]
    InvalidFulfillmentId,
    #[error("Shopify API version is outside the fixed allowlist")]
    ApiVersionNotAllowed,
    #[error("Shopify readback request is invalid")]
    InvalidRequest,
    #[error("Shopify access token is unavailable or malformed")]
    CredentialUnavailable,
    #[error("Shopify readback was cancelled before dispatch")]
    CancelledBeforeDispatch,
    #[error("Shopify readback was cancelled after dispatch")]
    CancelledAfterDispatch,
    #[error("Shopify readback timed out")]
    TimedOut,
    #[error("Shopify returned HTTP 401")]
    Unauthorized,
    #[error("Shopify returned HTTP 403")]
    Forbidden,
    #[error("Shopify fulfillment was not found")]
    NotFound,
    #[error("Shopify rate limit is exhausted")]
    RateLimited,
    #[error("Shopify returned an unexpected HTTP status")]
    UnexpectedHttpStatus,
    #[error("Shopify rejected the fixed GraphQL readback")]
    GraphqlRejected,
    #[error("Shopify response exceeds the fixed bound")]
    ResponseTooLarge,
    #[error("Shopify response is malformed or has a mismatched identity")]
    MalformedResponse,
    #[error("Shopify HTTPS transport is unavailable")]
    TransportUnavailable,
}

/// Narrow authenticated HTTP seam. The credential is borrowed for one call.
pub trait ShopifyAdminReadbackTransport: fmt::Debug + Send + Sync {
    fn readback(
        &self,
        access_token: &[u8],
        request: &ShopifyFulfillmentReadbackRequest,
        cancellation: &ShopifyReadbackCancellation,
    ) -> Result<ShopifyFulfillmentReadback, ShopifyNativeReadbackError>;

    fn is_native(&self) -> bool {
        false
    }
}

pub struct UreqShopifyAdminReadbackTransport {
    agent: ureq::Agent,
}

impl UreqShopifyAdminReadbackTransport {
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-shopify-readback/1")
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(true)
            .max_response_header_size(SHOPIFY_READBACK_MAX_RESPONSE_HEADER_BYTES)
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_send_body(Some(Duration::from_secs(5)))
            .timeout_recv_body(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(
                SHOPIFY_READBACK_GLOBAL_TIMEOUT_SECONDS,
            )))
            .build()
            .into();
        Self { agent }
    }
}

impl Default for UreqShopifyAdminReadbackTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UreqShopifyAdminReadbackTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqShopifyAdminReadbackTransport")
            .field("https_only", &true)
            .field("redirects", &0)
            .field(
                "global_timeout_seconds",
                &SHOPIFY_READBACK_GLOBAL_TIMEOUT_SECONDS,
            )
            .field("max_response_bytes", &SHOPIFY_READBACK_MAX_RESPONSE_BYTES)
            .finish()
    }
}

impl ShopifyAdminReadbackTransport for UreqShopifyAdminReadbackTransport {
    fn readback(
        &self,
        access_token: &[u8],
        request: &ShopifyFulfillmentReadbackRequest,
        cancellation: &ShopifyReadbackCancellation,
    ) -> Result<ShopifyFulfillmentReadback, ShopifyNativeReadbackError> {
        if cancellation.is_cancelled() {
            return Err(ShopifyNativeReadbackError::CancelledBeforeDispatch);
        }
        let token = std::str::from_utf8(access_token)
            .ok()
            .filter(|token| {
                !token.is_empty()
                    && token.len() <= 4_096
                    && token == &token.trim()
                    && !token.chars().any(char::is_control)
            })
            .ok_or(ShopifyNativeReadbackError::CredentialUnavailable)?;
        let body = request.graphql_body();
        if serde_json::to_vec(&body)
            .map_err(|_| ShopifyNativeReadbackError::InvalidRequest)?
            .len()
            > SHOPIFY_READBACK_MAX_REQUEST_BYTES
        {
            return Err(ShopifyNativeReadbackError::InvalidRequest);
        }
        let mut response = self
            .agent
            .post(&request.endpoint())
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("X-Shopify-Access-Token", token)
            .send_json(&body)
            .map_err(|error| classify_transport_error(&error))?;
        if cancellation.is_cancelled() {
            return Err(ShopifyNativeReadbackError::CancelledAfterDispatch);
        }
        let response_api_version = bounded_header(&response, "x-shopify-api-version")?
            .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
        if response_api_version != request.api_version().as_str() {
            return Err(ShopifyNativeReadbackError::MalformedResponse);
        }
        let request_id_digest = bounded_header(&response, "x-request-id")?
            .map(|request_id| format!("{:x}", Sha256::digest(request_id.as_bytes())));
        let body = response
            .body_mut()
            .with_config()
            .limit(SHOPIFY_READBACK_MAX_RESPONSE_BYTES)
            .read_json::<Value>()
            .map_err(|error| classify_body_error(&error))?;
        if cancellation.is_cancelled() {
            return Err(ShopifyNativeReadbackError::CancelledAfterDispatch);
        }
        decode_readback(request, &body, request_id_digest)
    }

    fn is_native(&self) -> bool {
        true
    }
}

fn bounded_header(
    response: &ureq::http::Response<ureq::Body>,
    name: &'static str,
) -> Result<Option<String>, ShopifyNativeReadbackError> {
    response
        .headers()
        .get(name)
        .map(|value| {
            value
                .to_str()
                .ok()
                .filter(|value| {
                    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
                })
                .map(str::to_owned)
                .ok_or(ShopifyNativeReadbackError::MalformedResponse)
        })
        .transpose()
}

fn decode_readback(
    request: &ShopifyFulfillmentReadbackRequest,
    body: &Value,
    request_id_digest: Option<String>,
) -> Result<ShopifyFulfillmentReadback, ShopifyNativeReadbackError> {
    if let Some(errors) = body.get("errors") {
        let errors = errors
            .as_array()
            .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
        if !errors.is_empty() {
            return Err(ShopifyNativeReadbackError::GraphqlRejected);
        }
    }
    if request.expected_identity().is_some() {
        return decode_receipt_identity(request, body, request_id_digest);
    }
    let node = body
        .pointer("/data/node")
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
    if node.is_null() {
        return Err(ShopifyNativeReadbackError::NotFound);
    }
    let id = node
        .get("id")
        .and_then(Value::as_str)
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
    if id != request.fulfillment_id().as_str() {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }
    let status = ShopifyFulfillmentStatus::parse(
        node.get("status")
            .and_then(Value::as_str)
            .ok_or(ShopifyNativeReadbackError::MalformedResponse)?,
    )?;
    let evidence_digest = digest_fields([
        "hartevo-shopify-native-readback/v1",
        request.shop().as_str(),
        request.api_version().as_str(),
        id,
        status.as_str(),
        request_id_digest.as_deref().unwrap_or("none"),
    ]);
    Ok(ShopifyFulfillmentReadback {
        fulfillment_id: request.fulfillment_id().clone(),
        status,
        api_version: request.api_version().clone(),
        request_id_digest,
        evidence_digest,
        provenance_class: ProviderProvenanceClass::ProductionProvider,
        receipt_identity: None,
    })
}

#[allow(clippy::too_many_lines)]
fn decode_receipt_identity(
    request: &ShopifyFulfillmentReadbackRequest,
    body: &Value,
    request_id_digest: Option<String>,
) -> Result<ShopifyFulfillmentReadback, ShopifyNativeReadbackError> {
    let expected = request
        .expected_identity()
        .ok_or(ShopifyNativeReadbackError::InvalidRequest)?;
    let fulfillment = body
        .pointer("/data/fulfillment")
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
    if fulfillment.is_null() {
        return Err(ShopifyNativeReadbackError::NotFound);
    }
    let id = required_string(fulfillment, "id")?;
    if id != request.fulfillment_id().as_str() {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }
    let status = ShopifyFulfillmentStatus::parse(required_string(fulfillment, "status")?)?;
    let provider_created_at = required_timestamp(fulfillment, "createdAt")?;
    let provider_updated_at = required_timestamp(fulfillment, "updatedAt")?;
    if provider_created_at < expected.provider_created_at_not_before()
        || provider_updated_at < provider_created_at
    {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }
    let order_id = fulfillment
        .pointer("/order/id")
        .and_then(Value::as_str)
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
    if order_id != expected.order_id().as_str() {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }

    let fulfillment_orders = required_complete_nodes(fulfillment, "fulfillmentOrders", 1)?;
    let fulfillment_order = fulfillment_orders
        .first()
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
    let fulfillment_order_id = required_string(fulfillment_order, "id")?;
    if fulfillment_order_id != expected.fulfillment_order_id().as_str() {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }

    let order_line_nodes = required_complete_nodes(
        fulfillment_order,
        "lineItems",
        SHOPIFY_FULFILLMENT_MAX_LINE_ITEMS,
    )?;
    let mut order_line_ids = BTreeMap::new();
    for node in order_line_nodes {
        let line_item_id = required_string(node, "id")?;
        ShopifyFulfillmentOrderLineItemGid::parse(line_item_id.to_owned())
            .map_err(|_| ShopifyNativeReadbackError::MalformedResponse)?;
        let order_line_id = node
            .pointer("/lineItem/id")
            .and_then(Value::as_str)
            .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
        validate_numeric_gid(order_line_id, SHOPIFY_LINE_ITEM_GID_PREFIX)?;
        let total_quantity = required_positive_quantity(node, "totalQuantity")?;
        let remaining_quantity = required_nonnegative_quantity(node, "remainingQuantity")?;
        if remaining_quantity > total_quantity
            || order_line_ids
                .insert(
                    line_item_id.to_owned(),
                    (order_line_id.to_owned(), total_quantity),
                )
                .is_some()
        {
            return Err(ShopifyNativeReadbackError::MalformedResponse);
        }
    }

    let fulfillment_line_nodes = required_complete_nodes(
        fulfillment,
        "fulfillmentLineItems",
        SHOPIFY_FULFILLMENT_MAX_LINE_ITEMS,
    )?;
    let mut fulfilled_quantities = BTreeMap::new();
    for node in fulfillment_line_nodes {
        let order_line_id = node
            .pointer("/lineItem/id")
            .and_then(Value::as_str)
            .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
        validate_numeric_gid(order_line_id, SHOPIFY_LINE_ITEM_GID_PREFIX)?;
        let quantity = required_positive_quantity(node, "quantity")?;
        if fulfilled_quantities
            .insert(order_line_id.to_owned(), quantity)
            .is_some()
        {
            return Err(ShopifyNativeReadbackError::MalformedResponse);
        }
    }

    let mut expected_order_lines = BTreeSet::new();
    for item in expected.line_items() {
        let (order_line_id, total_quantity) = order_line_ids
            .get(item.line_item_gid.as_str())
            .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
        if item.quantity > *total_quantity
            || !expected_order_lines.insert(order_line_id.clone())
            || fulfilled_quantities.get(order_line_id) != Some(&item.quantity)
        {
            return Err(ShopifyNativeReadbackError::MalformedResponse);
        }
    }
    if fulfilled_quantities.len() != expected_order_lines.len()
        || fulfilled_quantities
            .keys()
            .any(|line_id| !expected_order_lines.contains(line_id))
    {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }

    let response_digest = receipt_identity_digest(
        request,
        expected,
        status.as_str(),
        provider_created_at,
        provider_updated_at,
    );
    let evidence_digest = digest_fields([
        "hartevo-shopify-native-receipt-identity/v1",
        request.shop().as_str(),
        request.api_version().as_str(),
        id,
        status.as_str(),
        response_digest.as_str(),
        request_id_digest.as_deref().unwrap_or("none"),
    ]);
    Ok(ShopifyFulfillmentReadback {
        fulfillment_id: request.fulfillment_id().clone(),
        status,
        api_version: request.api_version().clone(),
        request_id_digest,
        evidence_digest,
        provenance_class: ProviderProvenanceClass::ProductionProvider,
        receipt_identity: Some(ShopifyFulfillmentReceiptIdentity {
            order_id: expected.order_id().clone(),
            fulfillment_order_id: expected.fulfillment_order_id().clone(),
            line_items: expected.line_items().to_vec(),
            provider_created_at_not_before: expected.provider_created_at_not_before(),
            provider_created_at,
            provider_updated_at,
            response_digest,
        }),
    })
}

fn required_string<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a str, ShopifyNativeReadbackError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)
}

fn required_timestamp(
    value: &Value,
    field: &str,
) -> Result<DateTime<Utc>, ShopifyNativeReadbackError> {
    DateTime::parse_from_rfc3339(required_string(value, field)?)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| ShopifyNativeReadbackError::MalformedResponse)
}

fn required_complete_nodes<'a>(
    parent: &'a Value,
    field: &str,
    max_nodes: usize,
) -> Result<Vec<&'a Value>, ShopifyNativeReadbackError> {
    let connection = parent
        .get(field)
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
    if connection
        .pointer("/pageInfo/hasNextPage")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }
    let nodes = connection
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)?;
    if nodes.is_empty() || nodes.len() > max_nodes {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }
    Ok(nodes.iter().collect())
}

fn required_positive_quantity(
    value: &Value,
    field: &str,
) -> Result<u32, ShopifyNativeReadbackError> {
    let quantity = required_nonnegative_quantity(value, field)?;
    if quantity == 0 {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }
    Ok(quantity)
}

fn required_nonnegative_quantity(
    value: &Value,
    field: &str,
) -> Result<u32, ShopifyNativeReadbackError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|quantity| u32::try_from(quantity).ok())
        .ok_or(ShopifyNativeReadbackError::MalformedResponse)
}

fn validate_numeric_gid(value: &str, prefix: &str) -> Result<(), ShopifyNativeReadbackError> {
    let suffix = value.strip_prefix(prefix).unwrap_or_default();
    if suffix.is_empty()
        || suffix.len() > 32
        || suffix.starts_with('0')
        || !suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ShopifyNativeReadbackError::MalformedResponse);
    }
    Ok(())
}

fn receipt_identity_digest(
    request: &ShopifyFulfillmentReadbackRequest,
    expected: &ShopifyExpectedFulfillmentIdentity,
    status: &str,
    provider_created_at: DateTime<Utc>,
    provider_updated_at: DateTime<Utc>,
) -> String {
    let mut fields = vec![
        "hartevo-shopify-fulfillment-receipt-identity/v2".to_owned(),
        request.shop().as_str().to_owned(),
        request.api_version().as_str().to_owned(),
        request.fulfillment_id().as_str().to_owned(),
        expected.order_id().as_str().to_owned(),
        expected.fulfillment_order_id().as_str().to_owned(),
        status.to_owned(),
        expected.provider_created_at_not_before().to_rfc3339(),
        provider_created_at.to_rfc3339(),
        provider_updated_at.to_rfc3339(),
    ];
    fields.extend(expected.line_items().iter().flat_map(|item| {
        [
            item.line_item_gid.as_str().to_owned(),
            item.quantity.to_string(),
        ]
    }));
    digest_field_iter(fields.iter().map(String::as_str))
}

fn classify_transport_error(error: &ureq::Error) -> ShopifyNativeReadbackError {
    match error {
        ureq::Error::StatusCode(401) => ShopifyNativeReadbackError::Unauthorized,
        ureq::Error::StatusCode(403) => ShopifyNativeReadbackError::Forbidden,
        ureq::Error::StatusCode(404) => ShopifyNativeReadbackError::NotFound,
        ureq::Error::StatusCode(429) => ShopifyNativeReadbackError::RateLimited,
        ureq::Error::StatusCode(_) => ShopifyNativeReadbackError::UnexpectedHttpStatus,
        ureq::Error::Timeout(_) => ShopifyNativeReadbackError::TimedOut,
        ureq::Error::BodyExceedsLimit(_) => ShopifyNativeReadbackError::ResponseTooLarge,
        _ => ShopifyNativeReadbackError::TransportUnavailable,
    }
}

fn classify_body_error(error: &ureq::Error) -> ShopifyNativeReadbackError {
    match error {
        ureq::Error::BodyExceedsLimit(_) => ShopifyNativeReadbackError::ResponseTooLarge,
        ureq::Error::Timeout(_) => ShopifyNativeReadbackError::TimedOut,
        ureq::Error::Json(_) => ShopifyNativeReadbackError::MalformedResponse,
        _ => ShopifyNativeReadbackError::TransportUnavailable,
    }
}

fn digest_fields<const N: usize>(fields: [&str; N]) -> String {
    digest_field_iter(fields)
}

fn digest_field_iter<'a>(fields: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update(field.len().to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ShopifyFulfillmentReadbackRequest {
        ShopifyFulfillmentReadbackRequest::new(
            ShopDomain::parse("n12c.myshopify.com").unwrap(),
            ShopifyApiVersion::latest(),
            ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
        )
        .unwrap()
    }

    fn exact_request() -> ShopifyFulfillmentReadbackRequest {
        ShopifyFulfillmentReadbackRequest::new_exact(
            ShopDomain::parse("n12c.myshopify.com").unwrap(),
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
                DateTime::parse_from_rfc3339("2026-08-30T07:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn exact_body() -> Value {
        json!({
            "data": {
                "fulfillment": {
                    "id": "gid://shopify/Fulfillment/3001",
                    "status": "SUCCESS",
                    "createdAt": "2026-08-30T08:00:00Z",
                    "updatedAt": "2026-08-30T08:01:00Z",
                    "order": { "id": "gid://shopify/Order/1001" },
                    "fulfillmentOrders": {
                        "nodes": [{
                            "id": "gid://shopify/FulfillmentOrder/2001",
                            "lineItems": {
                                "nodes": [{
                                    "id": "gid://shopify/FulfillmentOrderLineItem/4001",
                                    "lineItem": { "id": "gid://shopify/LineItem/5001" },
                                    "totalQuantity": 3,
                                    "remainingQuantity": 1
                                }],
                                "pageInfo": { "hasNextPage": false }
                            }
                        }],
                        "pageInfo": { "hasNextPage": false }
                    },
                    "fulfillmentLineItems": {
                        "nodes": [{
                            "lineItem": { "id": "gid://shopify/LineItem/5001" },
                            "quantity": 2
                        }],
                        "pageInfo": { "hasNextPage": false }
                    }
                }
            }
        })
    }

    #[test]
    fn request_is_fixed_to_shopify_https_latest_and_exact_gid() {
        let request = request();
        assert_eq!(
            request.endpoint(),
            "https://n12c.myshopify.com/admin/api/2026-07/graphql.json"
        );
        assert_eq!(
            request.graphql_body(),
            json!({
                "operationName": SHOPIFY_READBACK_OPERATION_NAME,
                "query": FULFILLMENT_READBACK_QUERY,
                "variables": { "id": "gid://shopify/Fulfillment/3001" }
            })
        );
        assert_eq!(
            ShopifyFulfillmentReadbackRequest::new(
                ShopDomain::parse("n12c.myshopify.com").unwrap(),
                ShopifyApiVersion::parse("2026-04").unwrap(),
                ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
            ),
            Err(ShopifyNativeReadbackError::ApiVersionNotAllowed)
        );
        assert_eq!(
            ShopifyFulfillmentGid::parse("shopify-provider-op-3001"),
            Err(ShopifyNativeReadbackError::InvalidFulfillmentId)
        );
        let bypassed_shop: ShopDomain = serde_json::from_str("\"attacker.example\"").unwrap();
        assert_eq!(
            ShopifyFulfillmentReadbackRequest::new(
                bypassed_shop,
                ShopifyApiVersion::latest(),
                ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
            ),
            Err(ShopifyNativeReadbackError::InvalidShopDomain)
        );
        let bypassed_userinfo: ShopDomain =
            serde_json::from_str("\"safe.myshopify.com@attacker.example\"").unwrap();
        assert_eq!(
            ShopifyFulfillmentReadbackRequest::new(
                bypassed_userinfo,
                ShopifyApiVersion::latest(),
                ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").unwrap(),
            ),
            Err(ShopifyNativeReadbackError::InvalidShopDomain)
        );
        let bypassed_gid = ShopifyFulfillmentGid("gid://shopify/Fulfillment/0001".to_owned());
        assert_eq!(
            ShopifyFulfillmentReadbackRequest::new(
                ShopDomain::parse("n12c.myshopify.com").unwrap(),
                ShopifyApiVersion::latest(),
                bypassed_gid,
            ),
            Err(ShopifyNativeReadbackError::InvalidFulfillmentId)
        );
        assert!(
            serde_json::from_str::<ShopifyFulfillmentGid>("\"gid://shopify/Fulfillment/0001\"")
                .is_err()
        );
    }

    #[test]
    fn decode_keeps_only_exact_typed_metadata() {
        let request = request();
        let readback = decode_readback(
            &request,
            &json!({
                "data": {
                    "node": {
                        "id": "gid://shopify/Fulfillment/3001",
                        "status": "SUCCESS"
                    }
                }
            }),
            Some(digest_fields(["request-id"])),
        )
        .unwrap();
        assert_eq!(readback.fulfillment_id(), request.fulfillment_id());
        assert_eq!(readback.status().as_str(), "SUCCESS");
        assert_eq!(readback.api_version(), request.api_version());
        assert_eq!(readback.evidence_digest().len(), 64);
        let debug = format!("{readback:?}");
        assert!(!debug.contains("access-token"));
        assert!(!debug.contains("X-Shopify"));
    }

    #[test]
    fn exact_identity_query_binds_order_fulfillment_order_lines_and_time() {
        let request = exact_request();
        assert_eq!(
            request.graphql_body(),
            json!({
                "operationName": SHOPIFY_RECEIPT_IDENTITY_OPERATION_NAME,
                "query": SHOPIFY_RECEIPT_IDENTITY_QUERY,
                "variables": { "id": "gid://shopify/Fulfillment/3001" }
            })
        );
        let readback =
            decode_readback(&request, &exact_body(), Some(digest_fields(["request-id"]))).unwrap();
        let identity = readback.receipt_identity().expect("exact identity");
        assert_eq!(identity.order_id().as_str(), "gid://shopify/Order/1001");
        assert_eq!(
            identity.fulfillment_order_id().as_str(),
            "gid://shopify/FulfillmentOrder/2001"
        );
        assert_eq!(
            identity.line_items(),
            request.expected_identity().unwrap().line_items()
        );
        assert_eq!(identity.response_digest().len(), 64);
        assert_eq!(
            identity.provider_created_at().to_rfc3339(),
            "2026-08-30T08:00:00+00:00"
        );
        assert_eq!(
            identity.provider_created_at_not_before().to_rfc3339(),
            "2026-08-30T07:00:00+00:00"
        );
        let debug = format!(
            "{request:?} {:?} {readback:?} {identity:?}",
            request.expected_identity().unwrap()
        );
        for private in [
            "n12c.myshopify.com",
            "gid://shopify/Fulfillment/3001",
            "gid://shopify/Order/1001",
            "gid://shopify/FulfillmentOrder/2001",
            "gid://shopify/FulfillmentOrderLineItem/4001",
            "line_items",
            "quantity",
            SHOPIFY_RECEIPT_IDENTITY_QUERY,
        ] {
            assert!(!debug.contains(private), "Debug leaked {private}");
        }
    }

    #[test]
    fn exact_identity_rejects_partial_ambiguous_or_mismatched_provider_state() {
        let request = exact_request();
        let mut malformed_errors = exact_body();
        malformed_errors["errors"] = json!("private provider detail");
        assert_eq!(
            decode_readback(&request, &malformed_errors, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );
        let mut rejected = exact_body();
        rejected["errors"] = json!([{"message": "private provider detail"}]);
        assert_eq!(
            decode_readback(&request, &rejected, None),
            Err(ShopifyNativeReadbackError::GraphqlRejected)
        );

        let mut partial = exact_body();
        partial["data"]["fulfillment"]["fulfillmentLineItems"]["pageInfo"]["hasNextPage"] =
            json!(true);
        assert_eq!(
            decode_readback(&request, &partial, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );

        let mut wrong_quantity = exact_body();
        wrong_quantity["data"]["fulfillment"]["fulfillmentLineItems"]["nodes"][0]["quantity"] =
            json!(1);
        assert_eq!(
            decode_readback(&request, &wrong_quantity, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );

        let mut wrong_order = exact_body();
        wrong_order["data"]["fulfillment"]["order"]["id"] = json!("gid://shopify/Order/1002");
        assert_eq!(
            decode_readback(&request, &wrong_order, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );

        let mut wrong_fulfillment_order = exact_body();
        wrong_fulfillment_order["data"]["fulfillment"]["fulfillmentOrders"]["nodes"][0]["id"] =
            json!("gid://shopify/FulfillmentOrder/2002");
        assert_eq!(
            decode_readback(&request, &wrong_fulfillment_order, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );

        let mut wrong_line_item = exact_body();
        wrong_line_item["data"]["fulfillment"]["fulfillmentOrders"]["nodes"][0]["lineItems"]["nodes"]
            [0]["id"] = json!("gid://shopify/FulfillmentOrderLineItem/4002");
        assert_eq!(
            decode_readback(&request, &wrong_line_item, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );

        let mut ambiguous = exact_body();
        let duplicate = ambiguous["data"]["fulfillment"]["fulfillmentOrders"]["nodes"][0].clone();
        ambiguous["data"]["fulfillment"]["fulfillmentOrders"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert_eq!(
            decode_readback(&request, &ambiguous, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );

        let mut future_before_create = exact_body();
        future_before_create["data"]["fulfillment"]["updatedAt"] = json!("2026-08-30T07:59:59Z");
        assert_eq!(
            decode_readback(&request, &future_before_create, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );

        let mut before_approved_effect = exact_body();
        before_approved_effect["data"]["fulfillment"]["createdAt"] = json!("2026-08-30T06:59:00Z");
        before_approved_effect["data"]["fulfillment"]["updatedAt"] = json!("2026-08-30T06:59:30Z");
        assert_eq!(
            decode_readback(&request, &before_approved_effect, None),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );
    }

    #[test]
    fn graphql_and_identity_failures_are_redacted_and_typed() {
        let request = request();
        assert_eq!(
            decode_readback(
                &request,
                &json!({"errors": [{"message": "private provider detail"}]}),
                None,
            ),
            Err(ShopifyNativeReadbackError::GraphqlRejected)
        );
        assert_eq!(
            decode_readback(
                &request,
                &json!({"data": {"node": {"id": "gid://shopify/Fulfillment/9001", "status": "SUCCESS"}}}),
                None,
            ),
            Err(ShopifyNativeReadbackError::MalformedResponse)
        );
        assert!(
            !ShopifyNativeReadbackError::GraphqlRejected
                .to_string()
                .contains("private provider detail")
        );
    }

    #[test]
    fn native_transport_checks_cancel_and_token_before_network() {
        let transport = UreqShopifyAdminReadbackTransport::new();
        assert!(transport.is_native());
        let cancelled = ShopifyReadbackCancellation::default();
        cancelled.cancel();
        assert_eq!(
            transport.readback(b"not-used", &request(), &cancelled),
            Err(ShopifyNativeReadbackError::CancelledBeforeDispatch)
        );
        assert_eq!(
            transport.readback(
                b"bad\ntoken",
                &request(),
                &ShopifyReadbackCancellation::default(),
            ),
            Err(ShopifyNativeReadbackError::CredentialUnavailable)
        );
        let debug = format!("{transport:?}");
        assert!(!debug.contains("not-used"));
        assert!(!debug.contains("bad"));
    }

    #[test]
    fn response_bounds_and_timeout_keep_typed_failure_classes() {
        assert_eq!(
            classify_body_error(&ureq::Error::BodyExceedsLimit(
                SHOPIFY_READBACK_MAX_RESPONSE_BYTES + 1,
            )),
            ShopifyNativeReadbackError::ResponseTooLarge
        );
        assert_eq!(
            classify_transport_error(&ureq::Error::Timeout(ureq::Timeout::Global)),
            ShopifyNativeReadbackError::TimedOut
        );
    }
}

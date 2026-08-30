//! Native, readback-only Shopify Admin GraphQL transport.
//!
//! The transport accepts exactly one operation: reading one known Shopify
//! Fulfillment GID. It cannot search, execute `fulfillmentCreate`, follow a
//! redirect, select an arbitrary host, or retain an access token. Credentials
//! are borrowed for one bounded call and never enter a request/response model.

use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use hartevo_connector_sdk::ProviderProvenanceClass;

use crate::shopify::{
    SHOPIFY_LATEST_API_VERSION, ShopDomain, ShopifyApiVersion, ShopifyGraphqlRequest,
};
use crate::shopify_effect::FULFILLMENT_READBACK_QUERY;

pub const SHOPIFY_READBACK_OPERATION_NAME: &str = "ShopifyFulfillmentReadback";
pub const SHOPIFY_READBACK_MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const SHOPIFY_READBACK_MAX_RESPONSE_BYTES: u64 = 128 * 1024;
pub const SHOPIFY_READBACK_MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;
pub const SHOPIFY_READBACK_GLOBAL_TIMEOUT_SECONDS: u64 = 15;

const SHOPIFY_FULFILLMENT_GID_PREFIX: &str = "gid://shopify/Fulfillment/";

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

/// Content-free call model. Access-token bytes are deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShopifyFulfillmentReadbackRequest {
    shop: ShopDomain,
    api_version: ShopifyApiVersion,
    fulfillment_id: ShopifyFulfillmentGid,
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
        };
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

    pub fn endpoint(&self) -> String {
        self.shop
            .admin_graphql_endpoint(&self.api_version)
            .to_string()
    }

    fn graphql_body(&self) -> Value {
        ShopifyGraphqlRequest::new(
            self.shop.clone(),
            self.api_version.clone(),
            SHOPIFY_READBACK_OPERATION_NAME,
            FULFILLMENT_READBACK_QUERY,
            json!({ "id": self.fulfillment_id.as_str() }),
        )
        .expect("fixed Shopify readback request is valid")
        .json_body()
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

/// Minimal provider metadata returned across the native transport boundary.
/// No response body, header value, token, or GraphQL error text is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShopifyFulfillmentReadback {
    fulfillment_id: ShopifyFulfillmentGid,
    status: ShopifyFulfillmentStatus,
    api_version: ShopifyApiVersion,
    request_id_digest: Option<String>,
    evidence_digest: String,
    provenance_class: ProviderProvenanceClass,
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
    if body
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        return Err(ShopifyNativeReadbackError::GraphqlRejected);
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
    })
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

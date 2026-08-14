//! Shopify controlled-write seam for draft fulfillment effects.
//!
//! This module is deliberately a provider-specific plugin boundary.  It does
//! not import `hartevo-effect-broker`, construct a `ConnectedAuthorization`,
//! or obtain an Effect authority.  The Mission/Effect Broker layer owns
//! approval and dispatch authority; this module only binds a Mission draft to
//! an opaque Connector SDK authentication chain, probes Shopify scope again,
//! and reconciles a provider observation by exact idempotency key.
//!
//! The transport is a trait so that real credentials and network writes cannot
//! be accidentally introduced by this first layer.  The repository's
//! contract tests use a controlled provider only.  Until a real credential and
//! upstream Effect authority are supplied, every execution receipt remains
//! `BLOCKED_ENV` and is never first-party evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{
    AuthSession, ConnectorError, ConnectorScope, CredentialLease, ProviderAdapterIdentity,
    ProviderProvenanceClass, SecretReference,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::shopify::{ShopDomain, ShopifyApiVersion, ShopifyError};

pub const SHOPIFY_FULFILLMENT_ADAPTER_ID: &str = "commerce.shopify.fulfillment.effect";
pub const SHOPIFY_FULFILLMENT_CAPABILITY: &str = "commerce.fulfillment.draft";
pub const SHOPIFY_FULFILLMENT_READ_SCOPE: &str = "read_merchant_managed_fulfillment_orders";
pub const SHOPIFY_FULFILLMENT_WRITE_SCOPE: &str = "write_merchant_managed_fulfillment_orders";
pub const SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS: &str = "BLOCKED_ENV";
pub const SHOPIFY_FULFILLMENT_MAX_LINE_ITEMS: usize = 100;
pub const SHOPIFY_FULFILLMENT_REQUEST_TTL_SECONDS: i64 = 900;
pub const SHOPIFY_FULFILLMENT_PROBE_TTL_SECONDS: i64 = 120;

/// Shopify's Admin GraphQL mutation used by a future provider transport.
///
/// The mutation is only a typed provider seam here.  Calling it remains the
/// responsibility of an Effect Broker-authorized provider implementation in a
/// later layer.
pub const FULFILLMENT_CREATE_MUTATION: &str = "mutation ShopifyFulfillmentCreate($fulfillment: FulfillmentInput!) { fulfillmentCreate(fulfillment: $fulfillment) { fulfillment { id status } userErrors { field message } } }";

/// Shopify readback query used to reconcile an uncertain create operation.
pub const FULFILLMENT_READBACK_QUERY: &str = "query ShopifyFulfillmentReadback($id: ID!) { node(id: $id) { ... on Fulfillment { id status } } }";

pub fn shopify_fulfillment_adapter_identity() -> Result<ProviderAdapterIdentity, ConnectorError> {
    ProviderAdapterIdentity::new(SHOPIFY_FULFILLMENT_ADAPTER_ID, 1).map_err(ConnectorError::from)
}

/// The adapter digest is metadata for provider observations, not an authority
/// token.  It binds the API version and the exact plugin capability.
pub fn shopify_fulfillment_provider_digest(api_version: &ShopifyApiVersion) -> String {
    sha256_digest([
        SHOPIFY_FULFILLMENT_ADAPTER_ID.to_owned(),
        SHOPIFY_FULFILLMENT_CAPABILITY.to_owned(),
        api_version.as_str().to_owned(),
    ])
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentScope {
    connector_scope: ConnectorScope,
    shop: ShopDomain,
}

impl ShopifyFulfillmentScope {
    pub fn new(
        connector_scope: ConnectorScope,
        shop: ShopDomain,
    ) -> Result<Self, ShopifyFulfillmentEffectError> {
        if connector_scope.provider_id() != crate::shopify::SHOPIFY_PROVIDER_ID {
            return Err(ShopifyFulfillmentEffectError::InvalidProviderScope);
        }
        if connector_scope.scopes().is_empty() {
            return Err(ShopifyFulfillmentEffectError::InvalidProviderScope);
        }
        Ok(Self {
            connector_scope,
            shop,
        })
    }

    pub fn connector_scope(&self) -> &ConnectorScope {
        &self.connector_scope
    }

    pub fn shop(&self) -> &ShopDomain {
        &self.shop
    }

    pub fn digest(&self) -> String {
        sha256_digest([self.connector_scope.digest(), self.shop.as_str().to_owned()])
    }

    fn has_required_scopes(&self) -> bool {
        self.connector_scope
            .scopes()
            .contains(SHOPIFY_FULFILLMENT_READ_SCOPE)
            && self
                .connector_scope
                .scopes()
                .contains(SHOPIFY_FULFILLMENT_WRITE_SCOPE)
    }
}

/// A strict Shopify Order GID, kept separate from fulfillment-order IDs.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyOrderGid(String);

impl ShopifyOrderGid {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyFulfillmentEffectError> {
        parse_shopify_numeric_gid(value.into(), "Order").map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A strict Shopify FulfillmentOrder GID.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyFulfillmentOrderGid(String);

impl ShopifyFulfillmentOrderGid {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyFulfillmentEffectError> {
        parse_shopify_numeric_gid(value.into(), "FulfillmentOrder").map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A strict Shopify FulfillmentOrderLineItem GID.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyFulfillmentOrderLineItemGid(String);

impl ShopifyFulfillmentOrderLineItemGid {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyFulfillmentEffectError> {
        parse_shopify_numeric_gid(value.into(), "FulfillmentOrderLineItem").map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentLineItem {
    pub line_item_gid: ShopifyFulfillmentOrderLineItemGid,
    pub quantity: u32,
}

impl ShopifyFulfillmentLineItem {
    pub fn new(
        line_item_gid: ShopifyFulfillmentOrderLineItemGid,
        quantity: u32,
    ) -> Result<Self, ShopifyFulfillmentEffectError> {
        if quantity == 0 {
            return Err(ShopifyFulfillmentEffectError::InvalidLineItemQuantity);
        }
        Ok(Self {
            line_item_gid,
            quantity,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyApprovalRevision(u64);

impl ShopifyApprovalRevision {
    pub fn new(value: u64) -> Result<Self, ShopifyFulfillmentEffectError> {
        if value == 0 {
            return Err(ShopifyFulfillmentEffectError::InvalidApprovalRevision);
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopifyEffectIdempotencyKey(String);

impl ShopifyEffectIdempotencyKey {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShopifyFulfillmentEffectError> {
        let value = value.into();
        let prefix = "shopify-effect-idem-";
        let suffix = value.strip_prefix(prefix).unwrap_or_default();
        if suffix.is_empty()
            || value.len() > 160
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ShopifyFulfillmentEffectError::InvalidIdempotencyKey);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftFulfillmentRequest {
    request_id: String,
    mission_id: String,
    tenant_scope: ShopifyFulfillmentScope,
    api_version: ShopifyApiVersion,
    order_gid: ShopifyOrderGid,
    fulfillment_order_gid: ShopifyFulfillmentOrderGid,
    line_items: Vec<ShopifyFulfillmentLineItem>,
    provider_generation: u64,
    approval_revision: ShopifyApprovalRevision,
    idempotency_key: ShopifyEffectIdempotencyKey,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    request_digest: String,
}

impl DraftFulfillmentRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: impl Into<String>,
        mission_id: impl Into<String>,
        tenant_scope: ShopifyFulfillmentScope,
        api_version: ShopifyApiVersion,
        order_gid: ShopifyOrderGid,
        fulfillment_order_gid: ShopifyFulfillmentOrderGid,
        mut line_items: Vec<ShopifyFulfillmentLineItem>,
        provider_generation: u64,
        approval_revision: ShopifyApprovalRevision,
        idempotency_key: ShopifyEffectIdempotencyKey,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ShopifyFulfillmentEffectError> {
        let request_id = request_id.into();
        let mission_id = mission_id.into();
        validate_request_id(&request_id)?;
        validate_mission_id(&mission_id)?;
        if !tenant_scope.has_required_scopes() {
            return Err(ShopifyFulfillmentEffectError::MissingWriteOrReadScope);
        }
        if provider_generation == 0 {
            return Err(ShopifyFulfillmentEffectError::InvalidProviderGeneration);
        }
        if line_items.is_empty() || line_items.len() > SHOPIFY_FULFILLMENT_MAX_LINE_ITEMS {
            return Err(ShopifyFulfillmentEffectError::InvalidLineItems);
        }
        if line_items.iter().any(|item| item.quantity == 0) {
            return Err(ShopifyFulfillmentEffectError::InvalidLineItems);
        }
        line_items.sort();
        if line_items
            .windows(2)
            .any(|items| items[0].line_item_gid == items[1].line_item_gid)
        {
            return Err(ShopifyFulfillmentEffectError::DuplicateLineItem);
        }
        if expires_at <= created_at
            || expires_at - created_at > Duration::seconds(SHOPIFY_FULFILLMENT_REQUEST_TTL_SECONDS)
        {
            return Err(ShopifyFulfillmentEffectError::InvalidRequestWindow);
        }
        let request_digest = request_digest(
            &request_id,
            &mission_id,
            &tenant_scope,
            &api_version,
            &order_gid,
            &fulfillment_order_gid,
            &line_items,
            provider_generation,
            approval_revision,
            &idempotency_key,
            created_at,
            expires_at,
        );
        Ok(Self {
            request_id,
            mission_id,
            tenant_scope,
            api_version,
            order_gid,
            fulfillment_order_gid,
            line_items,
            provider_generation,
            approval_revision,
            idempotency_key,
            created_at,
            expires_at,
            request_digest,
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    pub fn tenant_scope(&self) -> &ShopifyFulfillmentScope {
        &self.tenant_scope
    }

    pub fn api_version(&self) -> &ShopifyApiVersion {
        &self.api_version
    }

    pub fn order_gid(&self) -> &ShopifyOrderGid {
        &self.order_gid
    }

    pub fn fulfillment_order_gid(&self) -> &ShopifyFulfillmentOrderGid {
        &self.fulfillment_order_gid
    }

    pub fn line_items(&self) -> &[ShopifyFulfillmentLineItem] {
        &self.line_items
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub const fn approval_revision(&self) -> ShopifyApprovalRevision {
        self.approval_revision
    }

    pub fn idempotency_key(&self) -> &ShopifyEffectIdempotencyKey {
        &self.idempotency_key
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    fn validate_digest(&self) -> Result<(), ShopifyFulfillmentEffectError> {
        validate_request_id(&self.request_id)?;
        validate_mission_id(&self.mission_id)?;
        ShopifyApiVersion::parse(self.api_version.as_str().to_owned())?;
        ShopifyFulfillmentScope::new(
            self.tenant_scope.connector_scope().clone(),
            self.tenant_scope.shop().clone(),
        )?;
        ShopifyOrderGid::parse(self.order_gid.as_str().to_owned())?;
        ShopifyFulfillmentOrderGid::parse(self.fulfillment_order_gid.as_str().to_owned())?;
        for item in &self.line_items {
            ShopifyFulfillmentOrderLineItemGid::parse(item.line_item_gid.as_str().to_owned())?;
        }
        if !self.tenant_scope.has_required_scopes()
            || self.provider_generation == 0
            || self.line_items.is_empty()
            || self.line_items.len() > SHOPIFY_FULFILLMENT_MAX_LINE_ITEMS
            || self.line_items.iter().any(|item| item.quantity == 0)
            || self
                .line_items
                .windows(2)
                .any(|items| items[0].line_item_gid >= items[1].line_item_gid)
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at
                > Duration::seconds(SHOPIFY_FULFILLMENT_REQUEST_TTL_SECONDS)
        {
            return Err(ShopifyFulfillmentEffectError::InvalidLineItems);
        }
        ShopifyApprovalRevision::new(self.approval_revision.value())?;
        ShopifyEffectIdempotencyKey::parse(self.idempotency_key.as_str().to_owned())?;
        let expected = request_digest(
            &self.request_id,
            &self.mission_id,
            &self.tenant_scope,
            &self.api_version,
            &self.order_gid,
            &self.fulfillment_order_gid,
            &self.line_items,
            self.provider_generation,
            self.approval_revision,
            &self.idempotency_key,
            self.created_at,
            self.expires_at,
        );
        if expected != self.request_digest {
            return Err(ShopifyFulfillmentEffectError::RequestDigestMismatch);
        }
        Ok(())
    }
}

/// Opaque auth metadata held only in memory by the provider service.  It is
/// intentionally not serializable, and contains no credential bytes.
pub struct ShopifyFulfillmentAuthBinding {
    secret_reference: SecretReference,
    credential_lease: CredentialLease,
    auth_session: AuthSession,
    adapter: ProviderAdapterIdentity,
}

impl fmt::Debug for ShopifyFulfillmentAuthBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyFulfillmentAuthBinding")
            .field("scope_digest", &self.secret_reference.scope().digest())
            .field("adapter", &self.adapter)
            .field("provider_generation", &self.provider_generation())
            .field("auth_revision", &self.auth_revision())
            .finish_non_exhaustive()
    }
}

impl ShopifyFulfillmentAuthBinding {
    pub fn new(
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
        auth_session: AuthSession,
        adapter: ProviderAdapterIdentity,
    ) -> Result<Self, ShopifyFulfillmentEffectError> {
        let expected_adapter = shopify_fulfillment_adapter_identity()?;
        if adapter != expected_adapter
            || credential_lease.adapter() != &adapter
            || auth_session.adapter() != &adapter
            || secret_reference.scope() != credential_lease.scope()
            || credential_lease.scope() != auth_session.scope()
            || secret_reference.credential_revision() != credential_lease.credential_revision()
            || credential_lease.credential_revision() != auth_session.credential_revision()
            || credential_lease.lease_revision() != auth_session.lease_revision()
            || auth_session.auth_revision() == 0
            || secret_reference.scope().provider_id() != crate::shopify::SHOPIFY_PROVIDER_ID
        {
            return Err(ShopifyFulfillmentEffectError::InvalidAuthBinding);
        }
        if !secret_reference
            .scope()
            .scopes()
            .contains(SHOPIFY_FULFILLMENT_READ_SCOPE)
            || !secret_reference
                .scope()
                .scopes()
                .contains(SHOPIFY_FULFILLMENT_WRITE_SCOPE)
        {
            return Err(ShopifyFulfillmentEffectError::MissingWriteOrReadScope);
        }
        if credential_lease.expires_at() <= credential_lease.issued_at()
            || auth_session.expires_at() <= auth_session.issued_at()
        {
            return Err(ShopifyFulfillmentEffectError::InvalidAuthBinding);
        }
        Ok(Self {
            secret_reference,
            credential_lease,
            auth_session,
            adapter,
        })
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn scope(&self) -> &ConnectorScope {
        self.secret_reference.scope()
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn provider_generation(&self) -> u64 {
        self.secret_reference.credential_revision()
    }

    pub const fn auth_revision(&self) -> u64 {
        self.auth_session.auth_revision()
    }

    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.credential_lease.issued_at()
            && now < self.credential_lease.expires_at()
            && now >= self.auth_session.issued_at()
            && now < self.auth_session.expires_at()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyProbeStatus {
    Reachable,
    Unreachable,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyScopeProbeRequest {
    pub scope: ShopifyFulfillmentScope,
    pub api_version: ShopifyApiVersion,
    pub provider_digest: String,
    pub provider_generation: u64,
    pub required_scopes: BTreeSet<String>,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyScopeProbe {
    pub status: ShopifyProbeStatus,
    pub scope_digest: String,
    pub shop: ShopDomain,
    pub provider_digest: String,
    pub provider_generation: u64,
    pub granted_scopes: BTreeSet<String>,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub provenance_class: ProviderProvenanceClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyProviderReceipt {
    pub receipt_id: String,
    pub provider_operation_id: String,
    pub request_digest: String,
    pub idempotency_key: ShopifyEffectIdempotencyKey,
    pub scope_digest: String,
    pub shop: ShopDomain,
    pub order_gid: ShopifyOrderGid,
    pub fulfillment_order_gid: ShopifyFulfillmentOrderGid,
    pub line_items: Vec<ShopifyFulfillmentLineItem>,
    pub provider_generation: u64,
    pub approval_revision: ShopifyApprovalRevision,
    pub provider_digest: String,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub provenance_class: ProviderProvenanceClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyReadbackLookup {
    pub idempotency_key: ShopifyEffectIdempotencyKey,
    pub provider_operation_id: Option<String>,
    pub request_digest: String,
}

impl ShopifyReadbackLookup {
    fn for_request(
        request: &DraftFulfillmentRequest,
        receipt: Option<&ShopifyProviderReceipt>,
    ) -> Self {
        Self {
            idempotency_key: request.idempotency_key.clone(),
            provider_operation_id: receipt.map(|value| value.provider_operation_id.clone()),
            request_digest: request.request_digest.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyReadbackStatus {
    Present,
    Fulfilled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyReadbackObservation {
    pub provider_receipt: ShopifyProviderReceipt,
    pub status: ShopifyReadbackStatus,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub provenance_class: ProviderProvenanceClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyReadbackVerification {
    pub verified: bool,
    pub request_digest: String,
    pub idempotency_key: ShopifyEffectIdempotencyKey,
    pub provider_receipt_id: String,
    pub provider_operation_id: String,
    pub observed_at: DateTime<Utc>,
    pub verification_digest: String,
    pub provenance_class: ProviderProvenanceClass,
}

impl ShopifyReadbackVerification {
    pub fn is_first_party(&self) -> bool {
        false
    }
}

/// A provider plugin supplies metadata-only probe, execute, and readback
/// operations.  The trait does not receive an Effect authority or secret
/// material; a real implementation belongs behind the upstream dispatch
/// boundary.
pub trait ShopifyFulfillmentProvider {
    fn probe_scope(
        &mut self,
        request: &ShopifyScopeProbeRequest,
    ) -> Result<ShopifyScopeProbe, ShopifyFulfillmentProviderError>;

    fn execute_draft_fulfillment(
        &mut self,
        request: &DraftFulfillmentRequest,
    ) -> Result<ShopifyProviderReceipt, ShopifyFulfillmentProviderError>;

    fn readback_fulfillment(
        &mut self,
        request: &DraftFulfillmentRequest,
        lookup: &ShopifyReadbackLookup,
    ) -> Result<Option<ShopifyReadbackObservation>, ShopifyFulfillmentProviderError>;
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ShopifyFulfillmentProviderError {
    #[error("Shopify provider call timed out")]
    Timeout,
    #[error("Shopify provider rejected the draft fulfillment: {0}")]
    Rejected(String),
    #[error("Shopify provider is unavailable: {0}")]
    Unavailable(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyEffectLifecycle {
    Mounted,
    Revoked,
    Unmounted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyFulfillmentRecordState {
    Prepared,
    InFlight,
    Uncertain,
    ReceiptObserved,
    Verified,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentEffectRecord {
    pub request: DraftFulfillmentRequest,
    pub state: ShopifyFulfillmentRecordState,
    pub attempts: u32,
    pub provider_receipt: Option<ShopifyProviderReceipt>,
    pub readback: Option<ShopifyReadbackObservation>,
    pub verification: Option<ShopifyReadbackVerification>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentEffectStore {
    lifecycle: ShopifyEffectLifecycle,
    provider_generation: u64,
    records: BTreeMap<String, ShopifyFulfillmentEffectRecord>,
}

impl ShopifyFulfillmentEffectStore {
    pub fn new(provider_generation: u64) -> Result<Self, ShopifyFulfillmentEffectError> {
        if provider_generation == 0 {
            return Err(ShopifyFulfillmentEffectError::InvalidProviderGeneration);
        }
        Ok(Self {
            lifecycle: ShopifyEffectLifecycle::Mounted,
            provider_generation,
            records: BTreeMap::new(),
        })
    }

    pub const fn lifecycle(&self) -> ShopifyEffectLifecycle {
        self.lifecycle
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub fn records(&self) -> &BTreeMap<String, ShopifyFulfillmentEffectRecord> {
        &self.records
    }

    fn record(&self, key: &str) -> Option<&ShopifyFulfillmentEffectRecord> {
        self.records.get(key)
    }

    fn record_mut(&mut self, key: &str) -> Option<&mut ShopifyFulfillmentEffectRecord> {
        self.records.get_mut(key)
    }

    fn insert_prepared(&mut self, request: DraftFulfillmentRequest) {
        self.records.insert(
            request.idempotency_key().as_str().to_owned(),
            ShopifyFulfillmentEffectRecord {
                request,
                state: ShopifyFulfillmentRecordState::Prepared,
                attempts: 1,
                provider_receipt: None,
                readback: None,
                verification: None,
            },
        );
    }

    fn rotate_generation(
        &mut self,
        provider_generation: u64,
    ) -> Result<(), ShopifyFulfillmentEffectError> {
        if provider_generation <= self.provider_generation {
            return Err(ShopifyFulfillmentEffectError::GenerationMustIncrease);
        }
        self.provider_generation = provider_generation;
        self.records.clear();
        self.lifecycle = ShopifyEffectLifecycle::Mounted;
        Ok(())
    }

    fn revoke(&mut self) {
        self.records.clear();
        self.lifecycle = ShopifyEffectLifecycle::Revoked;
    }

    fn unmount(&mut self) {
        self.records.clear();
        self.lifecycle = ShopifyEffectLifecycle::Unmounted;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyFulfillmentExecutionReceipt {
    pub request_digest: String,
    pub idempotency_key: ShopifyEffectIdempotencyKey,
    pub provider_generation: u64,
    pub approval_revision: ShopifyApprovalRevision,
    pub provider_receipt: ShopifyProviderReceipt,
    pub readback: ShopifyReadbackVerification,
    pub replayed: bool,
    pub provider_digest: String,
    pub provenance_class: ProviderProvenanceClass,
    pub live_validation_status: String,
}

impl ShopifyFulfillmentExecutionReceipt {
    pub fn is_first_party(&self) -> bool {
        false
    }

    pub fn is_verified(&self) -> bool {
        self.readback.verified
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyLifecycleTransition {
    Revoked,
    Unmounted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyLifecycleReceipt {
    pub transition: ShopifyLifecycleTransition,
    pub lifecycle: ShopifyEffectLifecycle,
    pub provider_generation: u64,
    pub at: DateTime<Utc>,
    pub live_validation_status: String,
}

/// Provider-specific orchestration for the controlled Shopify write seam.
///
/// The service owns only a durable intent/observation record.  It never turns
/// an approval revision into an Effect authority and never mutates a Mission.
#[derive(Debug)]
pub struct ShopifyFulfillmentEffectService<P> {
    provider: P,
    tenant_scope: ShopifyFulfillmentScope,
    api_version: ShopifyApiVersion,
    provenance_class: ProviderProvenanceClass,
    auth: Option<ShopifyFulfillmentAuthBinding>,
    store: ShopifyFulfillmentEffectStore,
}

impl<P> ShopifyFulfillmentEffectService<P>
where
    P: ShopifyFulfillmentProvider,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: P,
        tenant_scope: ShopifyFulfillmentScope,
        api_version: ShopifyApiVersion,
        provenance_class: ProviderProvenanceClass,
        store: ShopifyFulfillmentEffectStore,
        auth: Option<ShopifyFulfillmentAuthBinding>,
    ) -> Result<Self, ShopifyFulfillmentEffectError> {
        if !tenant_scope.has_required_scopes() {
            return Err(ShopifyFulfillmentEffectError::MissingWriteOrReadScope);
        }
        if let Some(binding) = auth.as_ref()
            && (binding.scope() != tenant_scope.connector_scope()
                || binding.provider_generation() != store.provider_generation())
        {
            return Err(ShopifyFulfillmentEffectError::InvalidAuthBinding);
        }
        Ok(Self {
            provider,
            tenant_scope,
            api_version,
            provenance_class,
            auth,
            store,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn store(&self) -> &ShopifyFulfillmentEffectStore {
        &self.store
    }

    pub fn tenant_scope(&self) -> &ShopifyFulfillmentScope {
        &self.tenant_scope
    }

    pub fn api_version(&self) -> &ShopifyApiVersion {
        &self.api_version
    }

    pub const fn lifecycle(&self) -> ShopifyEffectLifecycle {
        self.store.lifecycle()
    }

    pub const fn live_validation_status(&self) -> &'static str {
        SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS
    }

    pub const fn is_first_party(&self) -> bool {
        false
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub fn submit_draft(
        &mut self,
        request: &DraftFulfillmentRequest,
    ) -> Result<ShopifyFulfillmentExecutionReceipt, ShopifyFulfillmentEffectError> {
        self.submit_draft_at(request, Utc::now())
    }

    pub fn submit_draft_at(
        &mut self,
        request: &DraftFulfillmentRequest,
        now: DateTime<Utc>,
    ) -> Result<ShopifyFulfillmentExecutionReceipt, ShopifyFulfillmentEffectError> {
        request.validate_digest()?;
        self.ensure_request_binding(request, now)?;
        self.ensure_operable(now)?;

        let key = request.idempotency_key().as_str().to_owned();
        let existing = self.store.record(&key).cloned();
        if let Some(record) = existing.as_ref() {
            if record.request.request_digest() != request.request_digest() {
                return Err(ShopifyFulfillmentEffectError::IdempotencyConflict);
            }
            if record.state == ShopifyFulfillmentRecordState::Verified {
                return self.execution_from_record(record, true, now);
            }
            if record.state == ShopifyFulfillmentRecordState::Rejected {
                return Err(ShopifyFulfillmentEffectError::PreviouslyRejected);
            }
            if let Some(current) = self.store.record_mut(&key) {
                current.attempts = current.attempts.saturating_add(1);
            }
        } else {
            self.store.insert_prepared(request.clone());
        }

        let state = self
            .store
            .record(&key)
            .map(|record| record.state)
            .ok_or(ShopifyFulfillmentEffectError::DurableRecordMissing)?;
        match state {
            ShopifyFulfillmentRecordState::Prepared => {
                self.probe_before_execute(request, now)?;
                if let Some(record) = self.store.record_mut(&key) {
                    record.state = ShopifyFulfillmentRecordState::InFlight;
                }
                match self.provider.execute_draft_fulfillment(request) {
                    Ok(receipt) => {
                        self.validate_provider_receipt(request, &receipt, now)?;
                        if let Some(record) = self.store.record_mut(&key) {
                            record.provider_receipt = Some(receipt);
                            record.state = ShopifyFulfillmentRecordState::ReceiptObserved;
                        }
                        self.reconcile_record(request, now, false)
                    }
                    Err(ShopifyFulfillmentProviderError::Rejected(reason)) => {
                        if let Some(record) = self.store.record_mut(&key) {
                            record.state = ShopifyFulfillmentRecordState::Rejected;
                        }
                        Err(ShopifyFulfillmentEffectError::ProviderRejected(reason))
                    }
                    Err(
                        ShopifyFulfillmentProviderError::Timeout
                        | ShopifyFulfillmentProviderError::Unavailable(_),
                    ) => {
                        if let Some(record) = self.store.record_mut(&key) {
                            record.state = ShopifyFulfillmentRecordState::Uncertain;
                        }
                        Err(ShopifyFulfillmentEffectError::ExecutionUncertain)
                    }
                }
            }
            ShopifyFulfillmentRecordState::InFlight
            | ShopifyFulfillmentRecordState::Uncertain
            | ShopifyFulfillmentRecordState::ReceiptObserved => {
                self.probe_before_readback(request, now)?;
                self.reconcile_record(request, now, true)
            }
            ShopifyFulfillmentRecordState::Verified => {
                Err(ShopifyFulfillmentEffectError::DurableRecordMissing)
            }
            ShopifyFulfillmentRecordState::Rejected => {
                Err(ShopifyFulfillmentEffectError::PreviouslyRejected)
            }
        }
    }

    pub fn rotate_auth(
        &mut self,
        auth: ShopifyFulfillmentAuthBinding,
    ) -> Result<(), ShopifyFulfillmentEffectError> {
        if self.lifecycle() != ShopifyEffectLifecycle::Mounted {
            return Err(ShopifyFulfillmentEffectError::ConsumerNotMounted);
        }
        if auth.scope() != self.tenant_scope.connector_scope() {
            return Err(ShopifyFulfillmentEffectError::ScopeMismatch);
        }
        self.store.rotate_generation(auth.provider_generation())?;
        self.auth = Some(auth);
        Ok(())
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> ShopifyLifecycleReceipt {
        self.auth = None;
        self.store.revoke();
        ShopifyLifecycleReceipt {
            transition: ShopifyLifecycleTransition::Revoked,
            lifecycle: self.lifecycle(),
            provider_generation: self.store.provider_generation(),
            at,
            live_validation_status: SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS.to_owned(),
        }
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> ShopifyLifecycleReceipt {
        self.auth = None;
        self.store.unmount();
        ShopifyLifecycleReceipt {
            transition: ShopifyLifecycleTransition::Unmounted,
            lifecycle: self.lifecycle(),
            provider_generation: self.store.provider_generation(),
            at,
            live_validation_status: SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS.to_owned(),
        }
    }

    fn ensure_request_binding(
        &self,
        request: &DraftFulfillmentRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyFulfillmentEffectError> {
        if request.tenant_scope() != &self.tenant_scope
            || request.api_version() != &self.api_version
        {
            return Err(ShopifyFulfillmentEffectError::ScopeMismatch);
        }
        if request.provider_generation() != self.store.provider_generation() {
            return Err(ShopifyFulfillmentEffectError::GenerationMismatch);
        }
        if now < request.created_at() {
            return Err(ShopifyFulfillmentEffectError::RequestNotYetLive);
        }
        if now >= request.expires_at() {
            return Err(ShopifyFulfillmentEffectError::RequestExpired);
        }
        if !request.tenant_scope().has_required_scopes() {
            return Err(ShopifyFulfillmentEffectError::MissingWriteOrReadScope);
        }
        Ok(())
    }

    fn ensure_operable(&self, now: DateTime<Utc>) -> Result<(), ShopifyFulfillmentEffectError> {
        if self.lifecycle() != ShopifyEffectLifecycle::Mounted {
            return Err(ShopifyFulfillmentEffectError::ConsumerNotMounted);
        }
        if self.provenance_class == ProviderProvenanceClass::ProductionProvider {
            return Err(ShopifyFulfillmentEffectError::BlockedEnv);
        }
        let auth = self
            .auth
            .as_ref()
            .ok_or(ShopifyFulfillmentEffectError::BlockedEnv)?;
        if !auth.is_live_at(now) {
            return Err(ShopifyFulfillmentEffectError::AuthenticationUnavailable);
        }
        Ok(())
    }

    fn probe_before_execute(
        &mut self,
        request: &DraftFulfillmentRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyFulfillmentEffectError> {
        let probe_request = self.probe_request(request, now);
        let probe = self
            .provider
            .probe_scope(&probe_request)
            .map_err(ShopifyFulfillmentEffectError::ProbeProvider)?;
        self.validate_probe(&probe_request, &probe, now)
    }

    fn probe_before_readback(
        &mut self,
        request: &DraftFulfillmentRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyFulfillmentEffectError> {
        self.probe_before_execute(request, now)
    }

    fn probe_request(
        &self,
        request: &DraftFulfillmentRequest,
        now: DateTime<Utc>,
    ) -> ShopifyScopeProbeRequest {
        let required_scopes = [
            SHOPIFY_FULFILLMENT_READ_SCOPE.to_owned(),
            SHOPIFY_FULFILLMENT_WRITE_SCOPE.to_owned(),
        ]
        .into_iter()
        .collect();
        ShopifyScopeProbeRequest {
            scope: request.tenant_scope.clone(),
            api_version: self.api_version.clone(),
            provider_digest: shopify_fulfillment_provider_digest(&self.api_version),
            provider_generation: request.provider_generation(),
            required_scopes,
            at: now,
        }
    }

    fn validate_probe(
        &self,
        request: &ShopifyScopeProbeRequest,
        probe: &ShopifyScopeProbe,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyFulfillmentEffectError> {
        if probe.status != ShopifyProbeStatus::Reachable {
            return Err(ShopifyFulfillmentEffectError::ProbeRejected);
        }
        if probe.scope_digest != request.scope.digest()
            || probe.shop != *request.scope.shop()
            || probe.provider_generation != request.provider_generation
            || probe.provider_digest != request.provider_digest
            || probe.provenance_class != self.provenance_class
        {
            return Err(ShopifyFulfillmentEffectError::ProbeBindingMismatch);
        }
        if request
            .required_scopes
            .iter()
            .any(|scope| !probe.granted_scopes.contains(scope))
        {
            return Err(ShopifyFulfillmentEffectError::ProbeMissingScope);
        }
        if probe.expires_at <= probe.observed_at
            || probe.expires_at - probe.observed_at
                > Duration::seconds(SHOPIFY_FULFILLMENT_PROBE_TTL_SECONDS)
            || now < probe.observed_at
            || now >= probe.expires_at
            || !is_sha256(&probe.evidence_digest)
        {
            return Err(ShopifyFulfillmentEffectError::ProbeExpired);
        }
        Ok(())
    }

    fn validate_provider_receipt(
        &self,
        request: &DraftFulfillmentRequest,
        receipt: &ShopifyProviderReceipt,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyFulfillmentEffectError> {
        if !receipt.receipt_id.starts_with("shopify-provider-receipt-")
            || !receipt
                .provider_operation_id
                .starts_with("shopify-provider-op-")
            || receipt.request_digest != request.request_digest()
            || receipt.idempotency_key != *request.idempotency_key()
            || receipt.scope_digest != request.tenant_scope().digest()
            || receipt.shop != *request.tenant_scope().shop()
            || receipt.order_gid != *request.order_gid()
            || receipt.fulfillment_order_gid != *request.fulfillment_order_gid()
            || receipt.line_items != request.line_items()
            || receipt.provider_generation != request.provider_generation()
            || receipt.approval_revision != request.approval_revision()
            || receipt.provider_digest != shopify_fulfillment_provider_digest(&self.api_version)
            || receipt.provenance_class != self.provenance_class
            || receipt.observed_at > now
            || !is_sha256(&receipt.evidence_digest)
        {
            return Err(ShopifyFulfillmentEffectError::InvalidProviderReceipt);
        }
        Ok(())
    }

    fn reconcile_record(
        &mut self,
        request: &DraftFulfillmentRequest,
        now: DateTime<Utc>,
        replayed: bool,
    ) -> Result<ShopifyFulfillmentExecutionReceipt, ShopifyFulfillmentEffectError> {
        let key = request.idempotency_key().as_str().to_owned();
        let existing_receipt = self
            .store
            .record(&key)
            .and_then(|record| record.provider_receipt.as_ref())
            .cloned();
        let lookup = ShopifyReadbackLookup::for_request(request, existing_receipt.as_ref());
        let observation = self
            .provider
            .readback_fulfillment(request, &lookup)
            .map_err(|error| match error {
                ShopifyFulfillmentProviderError::Timeout
                | ShopifyFulfillmentProviderError::Unavailable(_) => {
                    ShopifyFulfillmentEffectError::ReadbackPending
                }
                ShopifyFulfillmentProviderError::Rejected(reason) => {
                    ShopifyFulfillmentEffectError::ProviderRejected(reason)
                }
            })?
            .ok_or(ShopifyFulfillmentEffectError::ReadbackPending)?;
        self.validate_readback(request, &observation, existing_receipt.as_ref(), now)?;
        let verification = Self::build_verification(request, &observation);
        if let Some(record) = self.store.record_mut(&key) {
            record.provider_receipt = Some(observation.provider_receipt.clone());
            record.readback = Some(observation.clone());
            record.verification = Some(verification);
            record.state = ShopifyFulfillmentRecordState::Verified;
        }
        let record = self
            .store
            .record(&key)
            .ok_or(ShopifyFulfillmentEffectError::DurableRecordMissing)?;
        self.execution_from_record(record, replayed, now)
    }

    fn validate_readback(
        &self,
        request: &DraftFulfillmentRequest,
        observation: &ShopifyReadbackObservation,
        expected_receipt: Option<&ShopifyProviderReceipt>,
        now: DateTime<Utc>,
    ) -> Result<(), ShopifyFulfillmentEffectError> {
        self.validate_provider_receipt(request, &observation.provider_receipt, now)?;
        if expected_receipt.is_some_and(|receipt| receipt != &observation.provider_receipt)
            || observation.observed_at < observation.provider_receipt.observed_at
            || observation.observed_at > now
            || !is_sha256(&observation.evidence_digest)
            || observation.provenance_class != self.provenance_class
        {
            return Err(ShopifyFulfillmentEffectError::ReadbackMismatch);
        }
        Ok(())
    }

    fn build_verification(
        request: &DraftFulfillmentRequest,
        observation: &ShopifyReadbackObservation,
    ) -> ShopifyReadbackVerification {
        let verification_digest = sha256_digest([
            request.request_digest().to_owned(),
            observation.provider_receipt.receipt_id.clone(),
            observation.provider_receipt.provider_operation_id.clone(),
            observation.evidence_digest.clone(),
            format!("{:?}", observation.status),
            observation.observed_at.to_rfc3339(),
        ]);
        ShopifyReadbackVerification {
            verified: true,
            request_digest: request.request_digest().to_owned(),
            idempotency_key: request.idempotency_key().clone(),
            provider_receipt_id: observation.provider_receipt.receipt_id.clone(),
            provider_operation_id: observation.provider_receipt.provider_operation_id.clone(),
            observed_at: observation.observed_at,
            verification_digest,
            provenance_class: observation.provenance_class,
        }
    }

    fn execution_from_record(
        &self,
        record: &ShopifyFulfillmentEffectRecord,
        replayed: bool,
        now: DateTime<Utc>,
    ) -> Result<ShopifyFulfillmentExecutionReceipt, ShopifyFulfillmentEffectError> {
        record.request.validate_digest()?;
        let provider_receipt = record
            .provider_receipt
            .clone()
            .ok_or(ShopifyFulfillmentEffectError::InvalidProviderReceipt)?;
        self.validate_provider_receipt(&record.request, &provider_receipt, now)?;
        let observation = record
            .readback
            .as_ref()
            .ok_or(ShopifyFulfillmentEffectError::ReadbackMismatch)?;
        self.validate_readback(&record.request, observation, Some(&provider_receipt), now)?;
        let readback = record
            .verification
            .clone()
            .ok_or(ShopifyFulfillmentEffectError::InvalidReadbackVerification)?;
        if readback != Self::build_verification(&record.request, observation) {
            return Err(ShopifyFulfillmentEffectError::InvalidReadbackVerification);
        }
        Ok(ShopifyFulfillmentExecutionReceipt {
            request_digest: record.request.request_digest().to_owned(),
            idempotency_key: record.request.idempotency_key().clone(),
            provider_generation: record.request.provider_generation(),
            approval_revision: record.request.approval_revision(),
            provider_digest: provider_receipt.provider_digest.clone(),
            provenance_class: provider_receipt.provenance_class,
            provider_receipt,
            readback,
            replayed,
            live_validation_status: SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS.to_owned(),
        })
    }
}

/// Consumer-facing wrapper.  Mission code receives only the typed receipt;
/// lifecycle and provider state remain behind the adapter service.
#[derive(Debug)]
pub struct ShopifyFulfillmentConsumer<P>
where
    P: ShopifyFulfillmentProvider,
{
    service: ShopifyFulfillmentEffectService<P>,
}

impl<P> ShopifyFulfillmentConsumer<P>
where
    P: ShopifyFulfillmentProvider,
{
    pub fn new(service: ShopifyFulfillmentEffectService<P>) -> Self {
        Self { service }
    }

    pub fn submit_draft(
        &mut self,
        request: &DraftFulfillmentRequest,
    ) -> Result<ShopifyFulfillmentExecutionReceipt, ShopifyFulfillmentEffectError> {
        self.service.submit_draft(request)
    }

    pub fn submit_draft_at(
        &mut self,
        request: &DraftFulfillmentRequest,
        now: DateTime<Utc>,
    ) -> Result<ShopifyFulfillmentExecutionReceipt, ShopifyFulfillmentEffectError> {
        self.service.submit_draft_at(request, now)
    }

    pub fn service(&self) -> &ShopifyFulfillmentEffectService<P> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut ShopifyFulfillmentEffectService<P> {
        &mut self.service
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ShopifyFulfillmentEffectError {
    #[error("Shopify connector scope belongs to another provider")]
    InvalidProviderScope,
    #[error("invalid Shopify Order, FulfillmentOrder, or line-item GID: {kind}")]
    InvalidShopifyGid { kind: &'static str, value: String },
    #[error("invalid Shopify fulfillment line-item quantity")]
    InvalidLineItemQuantity,
    #[error("invalid Shopify fulfillment line items")]
    InvalidLineItems,
    #[error("duplicate Shopify fulfillment line item")]
    DuplicateLineItem,
    #[error("invalid Mission identifier")]
    InvalidMissionId,
    #[error("invalid draft request identifier")]
    InvalidRequestId,
    #[error("invalid approval revision")]
    InvalidApprovalRevision,
    #[error("invalid provider generation")]
    InvalidProviderGeneration,
    #[error("invalid effect idempotency key")]
    InvalidIdempotencyKey,
    #[error("invalid draft request time window")]
    InvalidRequestWindow,
    #[error("draft request digest does not match its fields")]
    RequestDigestMismatch,
    #[error("required Shopify fulfillment read/write scope is absent")]
    MissingWriteOrReadScope,
    #[error("Shopify authentication binding is invalid")]
    InvalidAuthBinding,
    #[error("Shopify effect consumer is not mounted")]
    ConsumerNotMounted,
    #[error("Shopify authentication is unavailable or expired")]
    AuthenticationUnavailable,
    #[error("live Shopify credentials/effect authority are unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("draft request scope or API version does not match the mounted provider")]
    ScopeMismatch,
    #[error("draft request provider generation is stale")]
    GenerationMismatch,
    #[error("new Shopify auth generation must increase")]
    GenerationMustIncrease,
    #[error("draft request is not live yet")]
    RequestNotYetLive,
    #[error("draft request has expired")]
    RequestExpired,
    #[error("idempotency key conflicts with a different draft request")]
    IdempotencyConflict,
    #[error("durable Shopify fulfillment record is missing")]
    DurableRecordMissing,
    #[error("Shopify provider probe failed: {0}")]
    ProbeProvider(ShopifyFulfillmentProviderError),
    #[error("Shopify provider probe was rejected")]
    ProbeRejected,
    #[error("Shopify provider probe binding is not exact")]
    ProbeBindingMismatch,
    #[error("Shopify provider probe did not grant the required scope")]
    ProbeMissingScope,
    #[error("Shopify provider probe is expired or malformed")]
    ProbeExpired,
    #[error("Shopify provider receipt is invalid or does not match the draft")]
    InvalidProviderReceipt,
    #[error("Shopify provider readback does not match the draft")]
    ReadbackMismatch,
    #[error("Shopify provider readback is pending")]
    ReadbackPending,
    #[error("Shopify provider operation is uncertain; retry only by readback")]
    ExecutionUncertain,
    #[error("Shopify provider rejected the draft fulfillment: {0}")]
    ProviderRejected(String),
    #[error("a previously rejected Shopify draft cannot be replayed")]
    PreviouslyRejected,
    #[error("durable Shopify readback verification is invalid")]
    InvalidReadbackVerification,
    #[error("Connector SDK rejected the authentication chain: {0}")]
    Connector(#[from] ConnectorError),
    #[error("Shopify identity validation failed: {0}")]
    Shopify(#[from] ShopifyError),
}

fn parse_shopify_numeric_gid(
    value: String,
    kind: &'static str,
) -> Result<String, ShopifyFulfillmentEffectError> {
    let prefix = format!("gid://shopify/{kind}/");
    let suffix = value.strip_prefix(&prefix).unwrap_or_default();
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ShopifyFulfillmentEffectError::InvalidShopifyGid { kind, value });
    }
    Ok(value)
}

fn validate_request_id(value: &str) -> Result<(), ShopifyFulfillmentEffectError> {
    validate_prefixed_identifier(value, "shopify-draft-fulfillment-")
        .map_err(|()| ShopifyFulfillmentEffectError::InvalidRequestId)
}

fn validate_mission_id(value: &str) -> Result<(), ShopifyFulfillmentEffectError> {
    if value.is_empty()
        || value.len() > 160
        || value.chars().any(char::is_control)
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
    {
        return Err(ShopifyFulfillmentEffectError::InvalidMissionId);
    }
    Ok(())
}

fn validate_prefixed_identifier(value: &str, prefix: &str) -> Result<(), ()> {
    let suffix = value.strip_prefix(prefix).ok_or(())?;
    if suffix.is_empty()
        || value.len() > 160
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn request_digest(
    request_id: &str,
    mission_id: &str,
    tenant_scope: &ShopifyFulfillmentScope,
    api_version: &ShopifyApiVersion,
    order_gid: &ShopifyOrderGid,
    fulfillment_order_gid: &ShopifyFulfillmentOrderGid,
    line_items: &[ShopifyFulfillmentLineItem],
    provider_generation: u64,
    approval_revision: ShopifyApprovalRevision,
    idempotency_key: &ShopifyEffectIdempotencyKey,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> String {
    let line_items = line_items
        .iter()
        .map(|item| format!("{}:{}", item.line_item_gid.as_str(), item.quantity))
        .collect::<Vec<_>>()
        .join(",");
    sha256_digest([
        request_id.to_owned(),
        mission_id.to_owned(),
        tenant_scope.digest(),
        api_version.as_str().to_owned(),
        order_gid.as_str().to_owned(),
        fulfillment_order_gid.as_str().to_owned(),
        line_items,
        provider_generation.to_string(),
        approval_revision.value().to_string(),
        idempotency_key.as_str().to_owned(),
        created_at.to_rfc3339(),
        expires_at.to_rfc3339(),
    ])
}

fn sha256_digest<I>(parts: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(part.as_bytes());
        digest.update(b"|");
    }
    hex_encode(&digest.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

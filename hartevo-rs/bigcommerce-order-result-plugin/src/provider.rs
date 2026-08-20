use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use serde::Serialize;

use crate::error::{BigCommerceOrderResultError, BigCommerceTransportError, Result};
use crate::model::{
    BigCommerceOrderScope, BigCommerceOrderSnapshot, BigCommerceSecretReference, Digest,
    OrderListFilter, Revision, StoreId, TransportProvenance,
};
use crate::{
    API_REVISION, CONTRACT_SCHEMA, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, PLUGIN_VERSION, PROVIDER_ID,
};

pub type ProviderProvenance = TransportProvenance;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BigCommerceOrderOperation {
    ListOrders,
    GetOrder,
}

impl BigCommerceOrderOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListOrders => "GET /stores/{store_hash}/v2/orders",
            Self::GetOrder => "GET /stores/{store_hash}/v2/orders/{order_id}",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BigCommerceProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub provenance: TransportProvenance,
    pub list_orders: bool,
    pub get_order: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
}

impl BigCommerceProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() || provenance.connected() || provenance.native() {
            return Err(BigCommerceOrderResultError::InvalidProvider);
        }
        let definition = Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version,
            api_revision: API_REVISION.to_owned(),
            capability_digest: Digest::from_text("unsealed-bigcommerce-capability"),
            provenance,
            list_orders: true,
            get_order: true,
            live_execution: false,
            connected: false,
            native: false,
        };
        let mut definition = definition;
        definition.capability_digest = definition.calculate_capability_digest();
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.provider_id != PROVIDER_ID
            || self.provider_version.is_empty()
            || self.api_revision != API_REVISION
            || self.provenance.connected()
            || self.provenance.native()
            || !self.list_orders
            || !self.get_order
            || self.live_execution
            || self.connected
            || self.native
            || self.capability_digest != self.calculate_capability_digest()
        {
            Err(BigCommerceOrderResultError::InvalidProvider)
        } else {
            Ok(())
        }
    }

    fn calculate_capability_digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-provider-capability/v1",
            &[
                ("schema", self.schema_version.clone()),
                ("provider", self.provider_id.clone()),
                ("version", self.provider_version.clone()),
                ("api", self.api_revision.clone()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("list", "GET".to_owned()),
                ("get", "GET".to_owned()),
                ("writes", "false".to_owned()),
            ],
        )
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-provider-definition/v1",
            &[
                ("schema", self.schema_version.clone()),
                ("id", self.provider_id.clone()),
                ("version", self.provider_version.clone()),
                ("api", self.api_revision.clone()),
                ("capability", self.capability_digest.as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("list", self.list_orders.to_string()),
                ("get", self.get_order.to_string()),
                ("live", self.live_execution.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
            ],
        )
    }

    #[must_use]
    pub fn recording() -> Self {
        Self::new(PLUGIN_VERSION, TransportProvenance::Recording)
            .expect("fixed BigCommerce provider definition")
    }
}

/// The transport-backed provider contract exposes only bounded list/get order reads.
pub trait BigCommerceProviderContract: fmt::Debug {
    fn definition(&self) -> &BigCommerceProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn list_orders(
        &mut self,
        request: &ListOrdersRequest,
    ) -> std::result::Result<ListOrdersResponse, BigCommerceTransportError>;

    fn get_order(
        &mut self,
        request: &GetOrderRequest,
    ) -> std::result::Result<GetOrderResponse, BigCommerceTransportError>;
}

pub trait BigCommerceTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_orders(
        &mut self,
        request: &ListOrdersRequest,
    ) -> std::result::Result<ListOrdersResponse, BigCommerceTransportError>;

    fn get_order(
        &mut self,
        request: &GetOrderRequest,
    ) -> std::result::Result<GetOrderResponse, BigCommerceTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub credential_revision: Revision,
    pub secret_reference_digest: Digest,
}

impl RequestFence {
    fn from_scope(scope: &BigCommerceOrderScope, secret: &BigCommerceSecretReference) -> Self {
        Self {
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            work_product_revision: scope.work_product().revision(),
            credential_revision: secret.credential_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct Cursor {
    token_digest: Digest,
    page_number: u16,
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Cursor {
    pub fn new(token: impl AsRef<[u8]>, page_number: u16) -> Result<Self> {
        if token.as_ref().is_empty() || token.as_ref().len() > 4096 || page_number == 0 {
            return Err(BigCommerceOrderResultError::InvalidIdentifier);
        }
        Ok(Self {
            token_digest: Digest::from_text(token),
            page_number,
        })
    }

    pub fn from_digest(token_digest: Digest, page_number: u16) -> Result<Self> {
        if page_number == 0 {
            return Err(BigCommerceOrderResultError::InvalidIdentifier);
        }
        Ok(Self {
            token_digest,
            page_number,
        })
    }

    #[must_use]
    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOrdersRequest {
    pub store: StoreId,
    pub scope_digest: Digest,
    pub page_size: u16,
    pub cursor_digest: Option<Digest>,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub work_product_revision: Revision,
    pub filter: OrderListFilter,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    #[serde(skip)]
    cursor: Option<Cursor>,
}

impl ListOrdersRequest {
    pub fn new(
        scope: &BigCommerceOrderScope,
        secret: &BigCommerceSecretReference,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        Self::with_filter(
            scope,
            secret,
            page_size,
            cursor,
            OrderListFilter::for_scope(scope),
        )
    }

    pub fn with_filter(
        scope: &BigCommerceOrderScope,
        secret: &BigCommerceSecretReference,
        page_size: u16,
        cursor: Option<Cursor>,
        filter: OrderListFilter,
    ) -> Result<Self> {
        scope.validate()?;
        if secret.is_revoked() {
            return Err(BigCommerceOrderResultError::SecretRevoked);
        }
        secret.validate(scope)?;
        filter.validate_against(scope)?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(BigCommerceOrderResultError::InvalidScope);
        }
        let fence = RequestFence::from_scope(scope, secret);
        let cursor_digest = cursor.as_ref().map(|value| value.token_digest().clone());
        let request_digest = request_digest(
            BigCommerceOrderOperation::ListOrders,
            &scope.store,
            scope,
            &fence,
            page_size,
            cursor.as_ref(),
            None,
            &filter,
        );
        Ok(Self {
            store: scope.store().clone(),
            scope_digest: scope.scope_digest(),
            page_size,
            cursor_digest,
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            work_product_revision: scope.work_product().revision(),
            filter,
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            request_digest,
            cursor,
        })
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub fn fence(&self) -> RequestFence {
        RequestFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            work_product_revision: self.work_product_revision,
            credential_revision: self.credential_revision,
            secret_reference_digest: self.secret_reference_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetOrderRequest {
    pub store: StoreId,
    pub order_id: crate::OrderId,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
}

impl GetOrderRequest {
    pub fn new(
        scope: &BigCommerceOrderScope,
        secret: &BigCommerceSecretReference,
        order_id: crate::OrderId,
    ) -> Result<Self> {
        scope.validate()?;
        if secret.is_revoked() {
            return Err(BigCommerceOrderResultError::SecretRevoked);
        }
        secret.validate(scope)?;
        if !scope.order_ids().is_empty() && !scope.order_ids().contains(&order_id) {
            return Err(BigCommerceOrderResultError::ScopeMismatch);
        }
        let fence = RequestFence::from_scope(scope, secret);
        let request_digest = request_digest(
            BigCommerceOrderOperation::GetOrder,
            &scope.store,
            scope,
            &fence,
            1,
            None,
            Some(order_id),
            &OrderListFilter::default(),
        );
        Ok(Self {
            store: scope.store().clone(),
            order_id,
            scope_digest: scope.scope_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            work_product_revision: scope.work_product().revision(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            request_digest,
        })
    }

    #[must_use]
    pub fn fence(&self) -> RequestFence {
        RequestFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            work_product_revision: self.work_product_revision,
            credential_revision: self.credential_revision,
            secret_reference_digest: self.secret_reference_digest.clone(),
        }
    }
}

fn request_digest(
    operation: BigCommerceOrderOperation,
    store: &StoreId,
    scope: &BigCommerceOrderScope,
    fence: &RequestFence,
    page_size: u16,
    cursor: Option<&Cursor>,
    order_id: Option<crate::OrderId>,
    filter: &OrderListFilter,
) -> Digest {
    Digest::from_parts(
        "bigcommerce-request/v1",
        &[
            ("operation", operation.as_str().to_owned()),
            ("store", store.digest().as_str().to_owned()),
            ("scope", scope.scope_digest().as_str().to_owned()),
            ("fence", fence.scope_digest.as_str().to_owned()),
            ("permission", fence.permission_digest.as_str().to_owned()),
            ("consent", fence.consent_digest.as_str().to_owned()),
            ("credential", fence.credential_revision.get().to_string()),
            ("secret", fence.secret_reference_digest.as_str().to_owned()),
            (
                "work_product",
                fence.work_product_revision.get().to_string(),
            ),
            ("page_size", page_size.to_string()),
            (
                "cursor",
                cursor.map_or_else(String::new, |value| {
                    value.token_digest().as_str().to_owned()
                }),
            ),
            (
                "page",
                cursor.map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
            ),
            (
                "order",
                order_id.map_or_else(String::new, |value| value.get().to_string()),
            ),
            ("filter", filter.digest().as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOrdersResponse {
    pub orders: Vec<BigCommerceOrderSnapshot>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub observed_fence: RequestFence,
    pub response_digest: Digest,
}

impl ListOrdersResponse {
    #[must_use]
    pub fn new(
        orders: Vec<BigCommerceOrderSnapshot>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        observed_fence: RequestFence,
    ) -> Self {
        let response_digest = list_response_digest(
            &orders,
            next_cursor.as_ref(),
            response_bytes,
            &observed_fence,
        );
        Self {
            orders,
            next_cursor,
            response_bytes,
            observed_fence,
            response_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.orders.len() > MAX_PAGE_SIZE as usize
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.page_number() > crate::MAX_PAGES)
        {
            return Err(BigCommerceOrderResultError::ResponseBoundExceeded);
        }
        for order in &self.orders {
            order.validate()?;
        }
        if self.response_digest
            != list_response_digest(
                &self.orders,
                self.next_cursor.as_ref(),
                self.response_bytes,
                &self.observed_fence,
            )
        {
            Err(BigCommerceOrderResultError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

fn list_response_digest(
    orders: &[BigCommerceOrderSnapshot],
    next_cursor: Option<&Cursor>,
    response_bytes: u64,
    fence: &RequestFence,
) -> Digest {
    Digest::from_parts(
        "bigcommerce-list-orders-response/v1",
        &[
            (
                "orders",
                orders
                    .iter()
                    .map(|value| value.digest().as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "cursor",
                next_cursor.map_or_else(String::new, |value| {
                    value.token_digest().as_str().to_owned()
                }),
            ),
            ("bytes", response_bytes.to_string()),
            ("scope", fence.scope_digest.as_str().to_owned()),
            ("permission", fence.permission_digest.as_str().to_owned()),
            ("consent", fence.consent_digest.as_str().to_owned()),
            (
                "work_product",
                fence.work_product_revision.get().to_string(),
            ),
            ("credential", fence.credential_revision.get().to_string()),
            ("secret", fence.secret_reference_digest.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetOrderResponse {
    pub order: BigCommerceOrderSnapshot,
    pub response_bytes: u64,
    pub observed_fence: RequestFence,
    pub response_digest: Digest,
}

impl GetOrderResponse {
    #[must_use]
    pub fn new(
        order: BigCommerceOrderSnapshot,
        response_bytes: u64,
        observed_fence: RequestFence,
    ) -> Self {
        let response_digest = get_response_digest(&order, response_bytes, &observed_fence);
        Self {
            order,
            response_bytes,
            observed_fence,
            response_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(BigCommerceOrderResultError::ResponseBoundExceeded);
        }
        self.order.validate()?;
        if self.response_digest
            != get_response_digest(&self.order, self.response_bytes, &self.observed_fence)
        {
            Err(BigCommerceOrderResultError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

fn get_response_digest(
    order: &BigCommerceOrderSnapshot,
    response_bytes: u64,
    fence: &RequestFence,
) -> Digest {
    Digest::from_parts(
        "bigcommerce-get-order-response/v1",
        &[
            ("order", order.digest().as_str().to_owned()),
            ("bytes", response_bytes.to_string()),
            ("scope", fence.scope_digest.as_str().to_owned()),
            ("permission", fence.permission_digest.as_str().to_owned()),
            ("consent", fence.consent_digest.as_str().to_owned()),
            (
                "work_product",
                fence.work_product_revision.get().to_string(),
            ),
            ("credential", fence.credential_revision.get().to_string()),
            ("secret", fence.secret_reference_digest.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: BigCommerceOrderOperation,
    pub scope_digest: Digest,
    pub order_id: Option<crate::OrderId>,
    pub cursor_digest: Option<Digest>,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

impl RecordedRequest {
    fn list(request: &ListOrdersRequest) -> Self {
        Self {
            operation: BigCommerceOrderOperation::ListOrders,
            scope_digest: request.scope_digest.clone(),
            order_id: None,
            cursor_digest: request.cursor_digest.clone(),
            filter_digest: request.filter.digest(),
            request_digest: request.request_digest.clone(),
            path_digest: Digest::from_text(BigCommerceOrderOperation::ListOrders.as_str()),
        }
    }

    fn get(request: &GetOrderRequest) -> Self {
        Self {
            operation: BigCommerceOrderOperation::GetOrder,
            scope_digest: request.scope_digest.clone(),
            order_id: Some(request.order_id),
            cursor_digest: None,
            filter_digest: Digest::from_text("no-list-filter"),
            request_digest: request.request_digest.clone(),
            path_digest: Digest::from_parts(
                "bigcommerce-get-order-path/v1",
                &[(
                    "path",
                    BigCommerceOrderOperation::GetOrder.as_str().to_owned(),
                )],
            ),
        }
    }
}

#[derive(Debug)]
pub struct BigCommerceOrdersProvider<T> {
    transport: T,
    definition: BigCommerceProviderDefinition,
}

impl<T: BigCommerceTransport> BigCommerceOrdersProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        if transport.provenance() != provenance {
            return Err(BigCommerceOrderResultError::InvalidProvider);
        }
        Ok(Self {
            transport,
            definition: BigCommerceProviderDefinition::new(provider_version, provenance)?,
        })
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: BigCommerceTransport> BigCommerceProviderContract for BigCommerceOrdersProvider<T> {
    fn definition(&self) -> &BigCommerceProviderDefinition {
        &self.definition
    }

    fn list_orders(
        &mut self,
        request: &ListOrdersRequest,
    ) -> std::result::Result<ListOrdersResponse, BigCommerceTransportError> {
        self.transport.list_orders(request)
    }

    fn get_order(
        &mut self,
        request: &GetOrderRequest,
    ) -> std::result::Result<GetOrderResponse, BigCommerceTransportError> {
        self.transport.get_order(request)
    }
}

/// Constructible typed provider implementation for the Layer-1 contract.
pub type BigCommerceProvider<T> = BigCommerceOrdersProvider<T>;

#[derive(Debug, Default)]
pub struct FixtureTransport {
    list_responses: VecDeque<std::result::Result<ListOrdersResponse, BigCommerceTransportError>>,
    get_responses:
        BTreeMap<u64, VecDeque<std::result::Result<GetOrderResponse, BigCommerceTransportError>>>,
    requests: Vec<RecordedRequest>,
}

impl FixtureTransport {
    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListOrdersResponse, BigCommerceTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        order_id: crate::OrderId,
        response: std::result::Result<GetOrderResponse, BigCommerceTransportError>,
    ) {
        self.get_responses
            .entry(order_id.get())
            .or_default()
            .push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    #[must_use]
    pub fn list_calls(&self) -> usize {
        self.list_responses.len()
    }
}

impl BigCommerceTransport for FixtureTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn list_orders(
        &mut self,
        request: &ListOrdersRequest,
    ) -> std::result::Result<ListOrdersResponse, BigCommerceTransportError> {
        self.requests.push(RecordedRequest::list(request));
        self.list_responses
            .pop_front()
            .unwrap_or(Err(BigCommerceTransportError::InvalidResponse))
    }

    fn get_order(
        &mut self,
        request: &GetOrderRequest,
    ) -> std::result::Result<GetOrderResponse, BigCommerceTransportError> {
        self.requests.push(RecordedRequest::get(request));
        self.get_responses
            .get_mut(&request.order_id.get())
            .and_then(VecDeque::pop_front)
            .unwrap_or(Err(BigCommerceTransportError::NotFound))
    }
}

#[derive(Debug)]
pub struct RecordingTransport<T> {
    inner: T,
    requests: Vec<RecordedRequest>,
}

impl<T> RecordingTransport<T> {
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    #[must_use]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl<T: BigCommerceTransport> BigCommerceTransport for RecordingTransport<T> {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn list_orders(
        &mut self,
        request: &ListOrdersRequest,
    ) -> std::result::Result<ListOrdersResponse, BigCommerceTransportError> {
        self.requests.push(RecordedRequest::list(request));
        self.inner.list_orders(request)
    }

    fn get_order(
        &mut self,
        request: &GetOrderRequest,
    ) -> std::result::Result<GetOrderResponse, BigCommerceTransportError> {
        self.requests.push(RecordedRequest::get(request));
        self.inner.get_order(request)
    }
}

#[derive(Debug, Default)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListOrdersResponse, BigCommerceTransportError>,
    ) {
        self.inner.push_list_response(response);
    }

    pub fn push_get_response(
        &mut self,
        order_id: crate::OrderId,
        response: std::result::Result<GetOrderResponse, BigCommerceTransportError>,
    ) {
        self.inner.push_get_response(order_id, response);
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl BigCommerceTransport for LoopbackTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn list_orders(
        &mut self,
        request: &ListOrdersRequest,
    ) -> std::result::Result<ListOrdersResponse, BigCommerceTransportError> {
        self.inner.list_orders(request)
    }

    fn get_order(
        &mut self,
        request: &GetOrderRequest,
    ) -> std::result::Result<GetOrderResponse, BigCommerceTransportError> {
        self.inner.get_order(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl BigCommerceTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_orders(
        &mut self,
        _request: &ListOrdersRequest,
    ) -> std::result::Result<ListOrdersResponse, BigCommerceTransportError> {
        Err(BigCommerceTransportError::BlockedEnv)
    }

    fn get_order(
        &mut self,
        _request: &GetOrderRequest,
    ) -> std::result::Result<GetOrderResponse, BigCommerceTransportError> {
        Err(BigCommerceTransportError::BlockedEnv)
    }
}

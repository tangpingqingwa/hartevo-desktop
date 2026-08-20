//! Read-only Service Catalog provider and non-native transport seams.
//!
//! No AWS SDK, signer, credential resolver, HTTP client, or write operation is
//! present in this module. Transports are deliberately fixture/recording/
//! loopback/`BLOCKED_ENV` queues.

use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::{
    API_REVISION, CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_ID,
    error::{AwsServiceCatalogError, AwsServiceCatalogTransportError, Result},
    model::{
        AwsServiceCatalogScope, Digest, PageToken, ProvisionedProductProjection, RecordProjection,
        SearchQuery, TransportProvenance, digest_serializable, operation_binding_digest,
        sorted_projection_digests,
    },
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsServiceCatalogOperation {
    SearchProvisionedProducts,
    DescribeProvisionedProduct,
    ListRecordHistory,
    DescribeRecord,
}

impl AwsServiceCatalogOperation {
    pub const ALL: [Self; 4] = [
        Self::SearchProvisionedProducts,
        Self::DescribeProvisionedProduct,
        Self::ListRecordHistory,
        Self::DescribeRecord,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SearchProvisionedProducts => "SearchProvisionedProducts",
            Self::DescribeProvisionedProduct => "DescribeProvisionedProduct",
            Self::ListRecordHistory => "ListRecordHistory",
            Self::DescribeRecord => "DescribeRecord",
        }
    }

    pub const fn permission(self) -> &'static str {
        match self {
            Self::SearchProvisionedProducts => "servicecatalog:SearchProvisionedProducts",
            Self::DescribeProvisionedProduct => "servicecatalog:DescribeProvisionedProduct",
            Self::ListRecordHistory => "servicecatalog:ListRecordHistory",
            Self::DescribeRecord => "servicecatalog:DescribeRecord",
        }
    }
}

/// The only provider transport boundary available in Layer 1.
pub trait AwsServiceCatalogTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn search_provisioned_products(
        &mut self,
        request: &SearchProvisionedProductsRequest,
    ) -> std::result::Result<SearchProvisionedProductsResponse, AwsServiceCatalogTransportError>;

    fn describe_provisioned_product(
        &mut self,
        request: &DescribeProvisionedProductRequest,
    ) -> std::result::Result<DescribeProvisionedProductResponse, AwsServiceCatalogTransportError>;

    fn list_record_history(
        &mut self,
        request: &ListRecordHistoryRequest,
    ) -> std::result::Result<ListRecordHistoryResponse, AwsServiceCatalogTransportError>;

    fn describe_record(
        &mut self,
        request: &DescribeRecordRequest,
    ) -> std::result::Result<DescribeRecordResponse, AwsServiceCatalogTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsServiceCatalogOperation,
    pub scope_digest: Digest,
    pub query_digest: Option<Digest>,
    pub page_token_digest: Option<Digest>,
    pub page_number: u16,
    pub page_size: Option<u16>,
    pub request_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SearchProvisionedProductsRequest {
    scope: AwsServiceCatalogScope,
    query: SearchQuery,
    page_size: u16,
    page_token: Option<PageToken>,
    binding_digest: Digest,
    request_digest: Digest,
}

impl SearchProvisionedProductsRequest {
    pub fn new(
        scope: &AwsServiceCatalogScope,
        query: SearchQuery,
        page_size: u16,
        page_token: Option<PageToken>,
    ) -> Result<Self> {
        scope.validate()?;
        query.validate()?;
        if !(1..=crate::MAX_SEARCH_PAGE_SIZE).contains(&page_size) {
            return Err(AwsServiceCatalogError::InvalidSearchPageSize);
        }
        let page_number = page_token.as_ref().map_or(1, PageToken::page_number);
        let binding_digest = operation_binding_digest(
            AwsServiceCatalogOperation::SearchProvisionedProducts.as_str(),
            scope,
            Some(&query),
            page_size,
            page_number,
        );
        if let Some(token) = &page_token {
            token.validate_against(&binding_digest, page_number)?;
        }
        let request_digest = Digest::from_parts(
            "aws-service-catalog-search-request/v1",
            &[
                ("binding", binding_digest.to_string()),
                ("query", query.digest().to_string()),
                ("page", page_number.to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            query,
            page_size,
            page_token,
            binding_digest,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsServiceCatalogScope {
        &self.scope
    }

    pub fn query(&self) -> &SearchQuery {
        &self.query
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn page_token(&self) -> Option<&PageToken> {
        self.page_token.as_ref()
    }

    pub fn page_number(&self) -> u16 {
        match &self.page_token {
            Some(token) => token.page_number(),
            None => 1,
        }
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn next_page_token(&self) -> PageToken {
        PageToken::for_binding(
            &operation_binding_digest(
                AwsServiceCatalogOperation::SearchProvisionedProducts.as_str(),
                &self.scope,
                Some(&self.query),
                self.page_size,
                self.page_number() + 1,
            ),
            self.page_number() + 1,
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsServiceCatalogOperation::SearchProvisionedProducts,
            scope_digest: self.scope.digest(),
            query_digest: Some(self.query.digest()),
            page_token_digest: self.page_token.as_ref().map(PageToken::digest),
            page_number: self.page_number(),
            page_size: Some(self.page_size),
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for SearchProvisionedProductsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchProvisionedProductsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("query", &self.query)
            .field("page_size", &self.page_size)
            .field("page_token", &self.page_token)
            .field("binding_digest", &self.binding_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeProvisionedProductRequest {
    scope: AwsServiceCatalogScope,
    request_digest: Digest,
}

impl DescribeProvisionedProductRequest {
    pub fn new(scope: &AwsServiceCatalogScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-service-catalog-describe-provisioned-product-request/v1",
                &[("scope", scope.digest().to_string())],
            ),
        })
    }

    pub fn scope(&self) -> &AwsServiceCatalogScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsServiceCatalogOperation::DescribeProvisionedProduct,
            scope_digest: self.scope.digest(),
            query_digest: None,
            page_token_digest: None,
            page_number: 1,
            page_size: None,
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for DescribeProvisionedProductRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeProvisionedProductRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListRecordHistoryRequest {
    scope: AwsServiceCatalogScope,
    page_size: u16,
    page_token: Option<PageToken>,
    binding_digest: Digest,
    request_digest: Digest,
}

impl ListRecordHistoryRequest {
    pub fn new(
        scope: &AwsServiceCatalogScope,
        page_size: u16,
        page_token: Option<PageToken>,
    ) -> Result<Self> {
        scope.validate()?;
        if !(1..=crate::MAX_HISTORY_PAGE_SIZE).contains(&page_size) {
            return Err(AwsServiceCatalogError::InvalidHistoryPageSize);
        }
        let page_number = page_token.as_ref().map_or(1, PageToken::page_number);
        let binding_digest = operation_binding_digest(
            AwsServiceCatalogOperation::ListRecordHistory.as_str(),
            scope,
            None,
            page_size,
            page_number,
        );
        if let Some(token) = &page_token {
            token.validate_against(&binding_digest, page_number)?;
        }
        let request_digest = Digest::from_parts(
            "aws-service-catalog-list-record-history-request/v1",
            &[
                ("binding", binding_digest.to_string()),
                ("page", page_number.to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_token,
            binding_digest,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsServiceCatalogScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn page_token(&self) -> Option<&PageToken> {
        self.page_token.as_ref()
    }

    pub fn page_number(&self) -> u16 {
        match &self.page_token {
            Some(token) => token.page_number(),
            None => 1,
        }
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn next_page_token(&self) -> PageToken {
        PageToken::for_binding(
            &operation_binding_digest(
                AwsServiceCatalogOperation::ListRecordHistory.as_str(),
                &self.scope,
                None,
                self.page_size,
                self.page_number() + 1,
            ),
            self.page_number() + 1,
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsServiceCatalogOperation::ListRecordHistory,
            scope_digest: self.scope.digest(),
            query_digest: None,
            page_token_digest: self.page_token.as_ref().map(PageToken::digest),
            page_number: self.page_number(),
            page_size: Some(self.page_size),
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for ListRecordHistoryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListRecordHistoryRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_token", &self.page_token)
            .field("binding_digest", &self.binding_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeRecordRequest {
    scope: AwsServiceCatalogScope,
    request_digest: Digest,
}

impl DescribeRecordRequest {
    pub fn new(scope: &AwsServiceCatalogScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-service-catalog-describe-record-request/v1",
                &[("scope", scope.digest().to_string())],
            ),
        })
    }

    pub fn scope(&self) -> &AwsServiceCatalogScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsServiceCatalogOperation::DescribeRecord,
            scope_digest: self.scope.digest(),
            query_digest: None,
            page_token_digest: None,
            page_number: 1,
            page_size: None,
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for DescribeRecordRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeRecordRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchProvisionedProductsResponse {
    pub items: Vec<ProvisionedProductProjection>,
    pub next_page_token: Option<PageToken>,
    pub response_digest: Digest,
}

impl SearchProvisionedProductsResponse {
    pub fn new(
        items: Vec<ProvisionedProductProjection>,
        next_page_token: Option<PageToken>,
    ) -> Self {
        let mut response = Self {
            items,
            next_page_token,
            response_digest: Digest::from_text("unsealed-service-catalog-search-response"),
        };
        response.response_digest = response.calculate_digest();
        response
    }

    pub fn calculate_digest(&self) -> Digest {
        digest_serializable(&(&self.items, &self.next_page_token))
    }

    pub fn validate(&self) -> Result<()> {
        if self.items.len() > usize::from(crate::MAX_SEARCH_PAGE_SIZE)
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsServiceCatalogError::ResponseIntegrity);
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeProvisionedProductResponse {
    pub projection: ProvisionedProductProjection,
    pub response_digest: Digest,
}

impl DescribeProvisionedProductResponse {
    pub fn new(projection: ProvisionedProductProjection) -> Self {
        let response_digest = projection.digest();
        Self {
            projection,
            response_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.projection.validate()?;
        if self.response_digest != self.projection.digest() {
            return Err(AwsServiceCatalogError::ResponseIntegrity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRecordHistoryResponse {
    pub records: Vec<RecordProjection>,
    pub next_page_token: Option<PageToken>,
    pub response_digest: Digest,
}

impl ListRecordHistoryResponse {
    pub fn new(records: Vec<RecordProjection>, next_page_token: Option<PageToken>) -> Self {
        let mut response = Self {
            records,
            next_page_token,
            response_digest: Digest::from_text("unsealed-service-catalog-history-response"),
        };
        response.response_digest = response.calculate_digest();
        response
    }

    pub fn calculate_digest(&self) -> Digest {
        digest_serializable(&(&self.records, &self.next_page_token))
    }

    pub fn validate(&self) -> Result<()> {
        if self.records.len() > usize::from(crate::MAX_HISTORY_PAGE_SIZE)
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsServiceCatalogError::ResponseIntegrity);
        }
        for record in &self.records {
            record.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeRecordResponse {
    pub projection: RecordProjection,
    pub response_digest: Digest,
}

impl DescribeRecordResponse {
    pub fn new(projection: RecordProjection) -> Self {
        let response_digest = projection.digest();
        Self {
            projection,
            response_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.projection.validate()?;
        if self.response_digest != self.projection.digest() {
            return Err(AwsServiceCatalogError::ResponseIntegrity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsServiceCatalogProviderDefinition {
    pub provider_id: String,
    pub api_revision: String,
    pub provider_revision: u64,
    pub release: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
}

impl AwsServiceCatalogProviderDefinition {
    pub fn new(provider_revision: u64) -> Result<Self> {
        if provider_revision == 0 {
            return Err(AwsServiceCatalogError::Invalid {
                field: "provider revision",
            });
        }
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            provider_revision,
            release: CONTRACT_VERSION.to_owned(),
            provider_digest: Digest::from_text("unsealed-service-catalog-provider"),
            api_digest: Digest::from_text(API_REVISION),
        };
        definition.provider_digest = Digest::from_parts(
            "aws-service-catalog-provider/v1",
            &[
                ("id", definition.provider_id.clone()),
                ("api", definition.api_revision.clone()),
                ("revision", definition.provider_revision.to_string()),
                ("permissions", LAYER1_PERMISSIONS.join("\n")),
            ],
        );
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != API_REVISION
            || self.provider_revision == 0
            || self.release != CONTRACT_VERSION
            || self.api_digest != Digest::from_text(API_REVISION)
        {
            return Err(AwsServiceCatalogError::ProviderDefinitionMismatch);
        }
        self.provider_digest.validate()
    }
}

pub struct AwsServiceCatalogProvider<T: AwsServiceCatalogTransport> {
    definition: AwsServiceCatalogProviderDefinition,
    transport: T,
}

impl<T: AwsServiceCatalogTransport> fmt::Debug for AwsServiceCatalogProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsServiceCatalogProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsServiceCatalogTransport> AwsServiceCatalogProvider<T> {
    pub fn new(transport: T, provider_revision: u64) -> Result<Self> {
        let definition = AwsServiceCatalogProviderDefinition::new(provider_revision)?;
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &AwsServiceCatalogProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn search_provisioned_products(
        &mut self,
        request: &SearchProvisionedProductsRequest,
    ) -> std::result::Result<SearchProvisionedProductsResponse, AwsServiceCatalogTransportError>
    {
        self.transport.search_provisioned_products(request)
    }

    pub fn describe_provisioned_product(
        &mut self,
        request: &DescribeProvisionedProductRequest,
    ) -> std::result::Result<DescribeProvisionedProductResponse, AwsServiceCatalogTransportError>
    {
        self.transport.describe_provisioned_product(request)
    }

    pub fn list_record_history(
        &mut self,
        request: &ListRecordHistoryRequest,
    ) -> std::result::Result<ListRecordHistoryResponse, AwsServiceCatalogTransportError> {
        self.transport.list_record_history(request)
    }

    pub fn describe_record(
        &mut self,
        request: &DescribeRecordRequest,
    ) -> std::result::Result<DescribeRecordResponse, AwsServiceCatalogTransportError> {
        self.transport.describe_record(request)
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    search: VecDeque<
        std::result::Result<SearchProvisionedProductsResponse, AwsServiceCatalogTransportError>,
    >,
    describe_product: VecDeque<
        std::result::Result<DescribeProvisionedProductResponse, AwsServiceCatalogTransportError>,
    >,
    history:
        VecDeque<std::result::Result<ListRecordHistoryResponse, AwsServiceCatalogTransportError>>,
    describe_record:
        VecDeque<std::result::Result<DescribeRecordResponse, AwsServiceCatalogTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_search_response(&mut self, response: SearchProvisionedProductsResponse) {
        self.search.push_back(Ok(response));
    }

    pub fn push_search_error(&mut self, error: AwsServiceCatalogTransportError) {
        self.search.push_back(Err(error));
    }

    pub fn push_describe_provisioned_product_response(
        &mut self,
        response: DescribeProvisionedProductResponse,
    ) {
        self.describe_product.push_back(Ok(response));
    }

    pub fn push_describe_provisioned_product_error(
        &mut self,
        error: AwsServiceCatalogTransportError,
    ) {
        self.describe_product.push_back(Err(error));
    }

    pub fn push_history_response(&mut self, response: ListRecordHistoryResponse) {
        self.history.push_back(Ok(response));
    }

    pub fn push_history_error(&mut self, error: AwsServiceCatalogTransportError) {
        self.history.push_back(Err(error));
    }

    pub fn push_describe_record_response(&mut self, response: DescribeRecordResponse) {
        self.describe_record.push_back(Ok(response));
    }

    pub fn push_describe_record_error(&mut self, error: AwsServiceCatalogTransportError) {
        self.describe_record.push_back(Err(error));
    }

    pub fn recorded_requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn take<R>(
        queue: &mut VecDeque<std::result::Result<R, AwsServiceCatalogTransportError>>,
    ) -> std::result::Result<R, AwsServiceCatalogTransportError> {
        queue
            .pop_front()
            .unwrap_or(Err(AwsServiceCatalogTransportError::InvalidResponse))
    }
}

impl AwsServiceCatalogTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn search_provisioned_products(
        &mut self,
        request: &SearchProvisionedProductsRequest,
    ) -> std::result::Result<SearchProvisionedProductsResponse, AwsServiceCatalogTransportError>
    {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.search)
    }

    fn describe_provisioned_product(
        &mut self,
        request: &DescribeProvisionedProductRequest,
    ) -> std::result::Result<DescribeProvisionedProductResponse, AwsServiceCatalogTransportError>
    {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.describe_product)
    }

    fn list_record_history(
        &mut self,
        request: &ListRecordHistoryRequest,
    ) -> std::result::Result<ListRecordHistoryResponse, AwsServiceCatalogTransportError> {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.history)
    }

    fn describe_record(
        &mut self,
        request: &DescribeRecordRequest,
    ) -> std::result::Result<DescribeRecordResponse, AwsServiceCatalogTransportError> {
        self.requests.push(request.recorded_request());
        Self::take(&mut self.describe_record)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureTransport {
    inner: RecordingTransport,
}

impl FixtureTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_search_response(&mut self, response: SearchProvisionedProductsResponse) {
        self.inner.push_search_response(response);
    }

    pub fn push_describe_provisioned_product_response(
        &mut self,
        response: DescribeProvisionedProductResponse,
    ) {
        self.inner
            .push_describe_provisioned_product_response(response);
    }

    pub fn push_history_response(&mut self, response: ListRecordHistoryResponse) {
        self.inner.push_history_response(response);
    }

    pub fn push_describe_record_response(&mut self, response: DescribeRecordResponse) {
        self.inner.push_describe_record_response(response);
    }

    pub fn recorded_requests(&self) -> &[RecordedRequest] {
        self.inner.recorded_requests()
    }
}

impl AwsServiceCatalogTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn search_provisioned_products(
        &mut self,
        request: &SearchProvisionedProductsRequest,
    ) -> std::result::Result<SearchProvisionedProductsResponse, AwsServiceCatalogTransportError>
    {
        self.inner.search_provisioned_products(request)
    }

    fn describe_provisioned_product(
        &mut self,
        request: &DescribeProvisionedProductRequest,
    ) -> std::result::Result<DescribeProvisionedProductResponse, AwsServiceCatalogTransportError>
    {
        self.inner.describe_provisioned_product(request)
    }

    fn list_record_history(
        &mut self,
        request: &ListRecordHistoryRequest,
    ) -> std::result::Result<ListRecordHistoryResponse, AwsServiceCatalogTransportError> {
        self.inner.list_record_history(request)
    }

    fn describe_record(
        &mut self,
        request: &DescribeRecordRequest,
    ) -> std::result::Result<DescribeRecordResponse, AwsServiceCatalogTransportError> {
        self.inner.describe_record(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_search_response(&mut self, response: SearchProvisionedProductsResponse) {
        self.inner.push_search_response(response);
    }

    pub fn push_describe_provisioned_product_response(
        &mut self,
        response: DescribeProvisionedProductResponse,
    ) {
        self.inner
            .push_describe_provisioned_product_response(response);
    }

    pub fn push_history_response(&mut self, response: ListRecordHistoryResponse) {
        self.inner.push_history_response(response);
    }

    pub fn push_describe_record_response(&mut self, response: DescribeRecordResponse) {
        self.inner.push_describe_record_response(response);
    }
}

impl AwsServiceCatalogTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn search_provisioned_products(
        &mut self,
        request: &SearchProvisionedProductsRequest,
    ) -> std::result::Result<SearchProvisionedProductsResponse, AwsServiceCatalogTransportError>
    {
        self.inner.search_provisioned_products(request)
    }

    fn describe_provisioned_product(
        &mut self,
        request: &DescribeProvisionedProductRequest,
    ) -> std::result::Result<DescribeProvisionedProductResponse, AwsServiceCatalogTransportError>
    {
        self.inner.describe_provisioned_product(request)
    }

    fn list_record_history(
        &mut self,
        request: &ListRecordHistoryRequest,
    ) -> std::result::Result<ListRecordHistoryResponse, AwsServiceCatalogTransportError> {
        self.inner.list_record_history(request)
    }

    fn describe_record(
        &mut self,
        request: &DescribeRecordRequest,
    ) -> std::result::Result<DescribeRecordResponse, AwsServiceCatalogTransportError> {
        self.inner.describe_record(request)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl AwsServiceCatalogTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn search_provisioned_products(
        &mut self,
        _request: &SearchProvisionedProductsRequest,
    ) -> std::result::Result<SearchProvisionedProductsResponse, AwsServiceCatalogTransportError>
    {
        Err(AwsServiceCatalogTransportError::BlockedEnv)
    }

    fn describe_provisioned_product(
        &mut self,
        _request: &DescribeProvisionedProductRequest,
    ) -> std::result::Result<DescribeProvisionedProductResponse, AwsServiceCatalogTransportError>
    {
        Err(AwsServiceCatalogTransportError::BlockedEnv)
    }

    fn list_record_history(
        &mut self,
        _request: &ListRecordHistoryRequest,
    ) -> std::result::Result<ListRecordHistoryResponse, AwsServiceCatalogTransportError> {
        Err(AwsServiceCatalogTransportError::BlockedEnv)
    }

    fn describe_record(
        &mut self,
        _request: &DescribeRecordRequest,
    ) -> std::result::Result<DescribeRecordResponse, AwsServiceCatalogTransportError> {
        Err(AwsServiceCatalogTransportError::BlockedEnv)
    }
}

pub fn validate_response_scope(
    scope: &AwsServiceCatalogScope,
    products: &[ProvisionedProductProjection],
    records: &[RecordProjection],
) -> Result<()> {
    for product in products {
        if !product.matches_scope(scope) {
            return Err(AwsServiceCatalogError::ScopeViolation);
        }
    }
    for record in records {
        if record.record_digest != scope.record.record_id_digest
            || record.provisioned_product_digest
                != scope.provisioned_product.provisioned_product_id_digest
        {
            return Err(AwsServiceCatalogError::ScopeViolation);
        }
    }
    let _ = sorted_projection_digests(products, records);
    Ok(())
}

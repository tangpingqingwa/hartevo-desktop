use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    SAP_SALES_ORDER_RESULT_CONTRACT_JSON, SAP_SALES_ORDER_RESULT_IMPLEMENTATION,
    SAP_SALES_ORDER_RESULT_PROVIDER_ID,
    model::{
        BlockState, Digest, FulfillmentState, ModelError, OpaqueDocumentId, OpaqueEtag,
        OrderLifecycleState, PermissionLease, ProviderErrorEvidence, RedactionSummary,
        RegistrationState, Revision, SalesOrderDocumentFlowProjection, SalesOrderHeaderProjection,
        SalesOrderItemProjection, SapEntitySet, SapODataPage, SapODataVersion, SapObservationState,
        SapProviderErrorKind, SapRegistration, SapSalesOrderEvidence, SapSalesOrderObservation,
        SapSalesOrderScope, SapTransportProvenance, SecretReference, allowlisted_fields,
        digest_safe_fields, parse_opaque_document_id, parse_opaque_etag,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("the SAP S/4HANA Layer-1 provider definition is not read-only")]
    NotReadOnly,
    #[error("the SAP provider definition claims native, connected, or first-party authority")]
    AuthorityClaim,
    #[error("the provider definition has an invalid OData version or entity-set allowlist")]
    InvalidAllowlist,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapS4HanaProviderDefinition {
    pub id: String,
    pub implementation: String,
    pub api_basis: String,
    pub odata_version: SapODataVersion,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub allowed_entity_sets: Vec<SapEntitySet>,
}

pub type SapProviderDefinition = SapS4HanaProviderDefinition;
pub type BlockedEnvTransport = BlockedEnvSapODataTransport;
pub type FixtureTransport = FixtureSapODataTransport;
pub type RecordingTransport = RecordingSapODataTransport;
pub type LoopbackTransport = LoopbackSapODataTransport;

impl SapS4HanaProviderDefinition {
    pub fn layer1() -> Self {
        Self {
            id: SAP_SALES_ORDER_RESULT_PROVIDER_ID.to_owned(),
            implementation: SAP_SALES_ORDER_RESULT_IMPLEMENTATION.to_owned(),
            api_basis: crate::SAP_SALES_ORDER_RESULT_API_BASIS.to_owned(),
            odata_version: SapODataVersion::V2,
            read_only: true,
            native: false,
            connected: false,
            first_party: false,
            allowed_entity_sets: SapEntitySet::ALL.to_vec(),
        }
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if !self.read_only {
            return Err(ProviderDefinitionError::NotReadOnly);
        }
        if self.native || self.connected || self.first_party {
            return Err(ProviderDefinitionError::AuthorityClaim);
        }
        if self.odata_version != SapODataVersion::V2
            || self.allowed_entity_sets.is_empty()
            || self
                .allowed_entity_sets
                .iter()
                .any(|entity_set| !SapEntitySet::ALL.contains(entity_set))
        {
            return Err(ProviderDefinitionError::InvalidAllowlist);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(
            serde_json::to_vec(self).expect("SAP provider definition is serializable"),
        )
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum SapODataFilter {
    SalesOrderEquals(OpaqueDocumentId),
}

impl SapODataFilter {
    pub fn render(&self) -> String {
        match self {
            Self::SalesOrderEquals(sales_order_id) => {
                format!("SalesOrder eq '{}'", sales_order_id.as_str())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapODataRequest {
    pub entity_set: SapEntitySet,
    pub odata_version: SapODataVersion,
    pub select: Vec<String>,
    pub filter: SapODataFilter,
    pub top: u32,
    pub skip: u32,
    pub expand: Vec<String>,
    pub document_flow_depth: u8,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub expected_etag: Option<OpaqueEtag>,
    request_digest: Digest,
}

impl SapODataRequest {
    pub fn for_scope(
        scope: &SapSalesOrderScope,
        entity_set: SapEntitySet,
        skip: u32,
    ) -> Result<Self, ModelError> {
        if !scope.entity_sets().contains(&entity_set) {
            return Err(ModelError::UnallowlistedEntitySet);
        }
        let select = allowlisted_fields(entity_set)
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<Vec<_>>();
        let mut request = Self {
            entity_set,
            odata_version: scope.odata_version(),
            select,
            filter: SapODataFilter::SalesOrderEquals(scope.sales_order_id().clone()),
            top: scope.bounds().page_size(),
            skip,
            expand: Vec::new(),
            document_flow_depth: scope.bounds().max_document_flow_depth(),
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_lease().digest().clone(),
            expected_etag: scope.expected_etag().cloned(),
            request_digest: Digest::from_values("sap-sales-order-request/uninitialized", &[]),
        };
        request.recompute_digest();
        request.validate_against(scope)?;
        Ok(request)
    }

    pub fn with_select<I>(mut self, fields: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = String>,
    {
        self.select = fields.into_iter().collect();
        self.recompute_digest();
        if self.select.is_empty()
            || self
                .select
                .iter()
                .any(|field| !allowlisted_fields(self.entity_set).contains(&field.as_str()))
        {
            return Err(ModelError::UnallowlistedProjection);
        }
        Ok(self)
    }

    pub fn with_top(mut self, top: u32) -> Result<Self, ModelError> {
        if top == 0 || top > crate::model::MAX_PAGE_SIZE {
            return Err(ModelError::InvalidBounds);
        }
        self.top = top;
        self.recompute_digest();
        Ok(self)
    }

    pub fn validate_against(&self, scope: &SapSalesOrderScope) -> Result<(), ModelError> {
        if self.odata_version != scope.odata_version()
            || self.scope_digest != *scope.scope_digest()
            || self.permission_digest != *scope.permission_lease().digest()
            || self.filter != SapODataFilter::SalesOrderEquals(scope.sales_order_id().clone())
            || self.top == 0
            || self.top > scope.bounds().page_size()
            || self.expand.iter().any(|_| true)
            || self.select.is_empty()
            || self
                .select
                .iter()
                .any(|field| !allowlisted_fields(self.entity_set).contains(&field.as_str()))
        {
            return Err(ModelError::InvalidQuery);
        }
        if self.skip > u32::MAX.saturating_sub(self.top) {
            return Err(ModelError::InvalidQuery);
        }
        Ok(())
    }

    fn recompute_digest(&mut self) {
        self.request_digest = Digest::from_parts(
            "sap-sales-order-odata-request/v1",
            [
                self.entity_set.as_str().to_owned(),
                self.odata_version.as_str().to_owned(),
                self.select.join(","),
                self.filter.render(),
                self.top.to_string(),
                self.skip.to_string(),
                self.expand.join(","),
                self.document_flow_depth.to_string(),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.expected_etag.as_ref().map_or_else(
                    || "none".to_owned(),
                    |etag| etag.digest().as_str().to_owned(),
                ),
            ],
        );
    }

    pub fn render_query(&self) -> String {
        format!(
            "$select={}&$filter={}&$top={}&$skip={}",
            self.select.join(","),
            self.filter.render(),
            self.top,
            self.skip
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub const fn is_read_only(&self) -> bool {
        true
    }

    pub const fn has_external_write(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SapTransportError {
    #[error("BLOCKED_ENV: native SAP credentials and HTTPS transport are unavailable")]
    BlockedEnv,
    #[error("SAP OData transport timed out")]
    Timeout,
    #[error("SAP OData transport failed without a native request")]
    Transport,
    #[error("the scripted SAP OData transport has no response left")]
    ScriptExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SapODataResponse {
    request_digest: Digest,
    status: u16,
    page: Option<SapODataPage>,
    retry_after_seconds: Option<u32>,
    error_digest: Option<Digest>,
}

impl SapODataResponse {
    pub fn success(request: &SapODataRequest, page: SapODataPage) -> Self {
        Self {
            request_digest: request.digest().clone(),
            status: 200,
            page: Some(page),
            retry_after_seconds: None,
            error_digest: None,
        }
    }

    pub fn http_error(
        request: &SapODataRequest,
        status: u16,
        retry_after_seconds: Option<u32>,
    ) -> Self {
        Self {
            request_digest: request.digest().clone(),
            status,
            page: None,
            retry_after_seconds,
            error_digest: Some(Digest::from_values(
                "sap-sales-order-http-error/v1",
                &[&status.to_string()],
            )),
        }
    }

    pub fn tampered_request_digest(request_digest: Digest, status: u16) -> Self {
        Self {
            request_digest,
            status,
            page: None,
            retry_after_seconds: None,
            error_digest: Some(Digest::from_values(
                "sap-sales-order-http-error/v1",
                &[&status.to_string()],
            )),
        }
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page(&self) -> Option<&SapODataPage> {
        self.page.as_ref()
    }

    pub const fn retry_after_seconds(&self) -> Option<u32> {
        self.retry_after_seconds
    }

    pub fn error_digest(&self) -> Option<&Digest> {
        self.error_digest.as_ref()
    }
}

pub trait SapODataTransport: fmt::Debug + Send {
    fn provenance(&self) -> SapTransportProvenance;
    fn read(&mut self, request: &SapODataRequest) -> Result<SapODataResponse, SapTransportError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvSapODataTransport;

impl SapODataTransport for BlockedEnvSapODataTransport {
    fn provenance(&self) -> SapTransportProvenance {
        SapTransportProvenance::BlockedEnv
    }

    fn read(&mut self, _request: &SapODataRequest) -> Result<SapODataResponse, SapTransportError> {
        Err(SapTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug)]
enum ScriptedResponse {
    Page(SapODataPage),
    Response(SapODataResponse),
    Error(SapTransportError),
}

#[derive(Clone, Debug)]
struct ScriptedSapODataTransport {
    provenance: SapTransportProvenance,
    responses: VecDeque<ScriptedResponse>,
    requests: Vec<SapODataRequest>,
}

impl ScriptedSapODataTransport {
    fn new(provenance: SapTransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    fn from_pages(provenance: SapTransportProvenance, pages: Vec<SapODataPage>) -> Self {
        let mut transport = Self::new(provenance);
        transport
            .responses
            .extend(pages.into_iter().map(ScriptedResponse::Page));
        transport
    }

    fn push_page(&mut self, page: SapODataPage) {
        self.responses.push_back(ScriptedResponse::Page(page));
    }

    fn push_response(&mut self, response: SapODataResponse) {
        self.responses
            .push_back(ScriptedResponse::Response(response));
    }

    fn push_error(&mut self, error: SapTransportError) {
        self.responses.push_back(ScriptedResponse::Error(error));
    }

    fn requests(&self) -> &[SapODataRequest] {
        &self.requests
    }

    fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl SapODataTransport for ScriptedSapODataTransport {
    fn provenance(&self) -> SapTransportProvenance {
        self.provenance
    }

    fn read(&mut self, request: &SapODataRequest) -> Result<SapODataResponse, SapTransportError> {
        self.requests.push(request.clone());
        match self
            .responses
            .pop_front()
            .ok_or(SapTransportError::ScriptExhausted)?
        {
            ScriptedResponse::Page(page) => Ok(SapODataResponse::success(request, page)),
            ScriptedResponse::Response(response) => Ok(response),
            ScriptedResponse::Error(error) => Err(error),
        }
    }
}

impl Default for ScriptedSapODataTransport {
    fn default() -> Self {
        Self::new(SapTransportProvenance::Recording)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingSapODataTransport {
    inner: ScriptedSapODataTransport,
}

impl RecordingSapODataTransport {
    pub fn new() -> Self {
        Self {
            inner: ScriptedSapODataTransport::new(SapTransportProvenance::Recording),
        }
    }

    pub fn from_pages(pages: Vec<SapODataPage>) -> Self {
        Self {
            inner: ScriptedSapODataTransport::from_pages(SapTransportProvenance::Recording, pages),
        }
    }

    pub fn fixture(pages: Vec<SapODataPage>) -> Self {
        Self {
            inner: ScriptedSapODataTransport::from_pages(SapTransportProvenance::Fixture, pages),
        }
    }

    pub fn loopback(pages: Vec<SapODataPage>) -> Self {
        Self {
            inner: ScriptedSapODataTransport::from_pages(SapTransportProvenance::Loopback, pages),
        }
    }

    pub fn push_page(&mut self, page: SapODataPage) {
        self.inner.push_page(page);
    }

    pub fn push_response(&mut self, response: SapODataResponse) {
        self.inner.push_response(response);
    }

    pub fn push_error(&mut self, error: SapTransportError) {
        self.inner.push_error(error);
    }

    pub fn requests(&self) -> &[SapODataRequest] {
        self.inner.requests()
    }

    pub fn remaining_responses(&self) -> usize {
        self.inner.remaining_responses()
    }

    pub fn provenance(&self) -> SapTransportProvenance {
        self.inner.provenance
    }
}

impl SapODataTransport for RecordingSapODataTransport {
    fn provenance(&self) -> SapTransportProvenance {
        self.inner.provenance()
    }

    fn read(&mut self, request: &SapODataRequest) -> Result<SapODataResponse, SapTransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureSapODataTransport {
    inner: RecordingSapODataTransport,
}

impl FixtureSapODataTransport {
    pub fn new(pages: Vec<SapODataPage>) -> Self {
        Self {
            inner: RecordingSapODataTransport::fixture(pages),
        }
    }

    pub fn push_page(&mut self, page: SapODataPage) {
        self.inner.push_page(page);
    }

    pub fn requests(&self) -> &[SapODataRequest] {
        self.inner.requests()
    }
}

impl SapODataTransport for FixtureSapODataTransport {
    fn provenance(&self) -> SapTransportProvenance {
        SapTransportProvenance::Fixture
    }

    fn read(&mut self, request: &SapODataRequest) -> Result<SapODataResponse, SapTransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackSapODataTransport {
    inner: RecordingSapODataTransport,
}

impl LoopbackSapODataTransport {
    pub fn new(pages: Vec<SapODataPage>) -> Self {
        Self {
            inner: RecordingSapODataTransport::loopback(pages),
        }
    }

    pub fn push_page(&mut self, page: SapODataPage) {
        self.inner.push_page(page);
    }
}

impl SapODataTransport for LoopbackSapODataTransport {
    fn provenance(&self) -> SapTransportProvenance {
        SapTransportProvenance::Loopback
    }

    fn read(&mut self, request: &SapODataRequest) -> Result<SapODataResponse, SapTransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SapProviderError {
    #[error("SAP provider registration is revoked")]
    RegistrationRevoked,
    #[error("SAP SecretReference is revoked")]
    SecretRevoked,
    #[error("SAP provider scope or digest does not match")]
    ScopeMismatch,
    #[error("SAP provider permission lease does not match")]
    PermissionMismatch,
    #[error("SAP provider returned a missing sales order")]
    NotFound,
    #[error("SAP provider returned a tampered or invalid response")]
    InvalidResponse,
    #[error("SAP provider returned a repeated or regressing page token")]
    PageLoop,
    #[error("SAP provider ETag changed during one read")]
    EtagDrift,
    #[error("SAP provider source revision changed during one read")]
    RevisionDrift,
    #[error("SAP provider returned an HTTP error")]
    Http { evidence: ProviderErrorEvidence },
    #[error(transparent)]
    Transport(#[from] SapTransportError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Definition(#[from] ProviderDefinitionError),
}

impl SapProviderError {
    pub fn kind(&self) -> SapProviderErrorKind {
        match self {
            Self::RegistrationRevoked => SapProviderErrorKind::RegistrationRevoked,
            Self::SecretRevoked => SapProviderErrorKind::SecretRevoked,
            Self::ScopeMismatch => SapProviderErrorKind::ScopeMismatch,
            Self::PermissionMismatch => SapProviderErrorKind::PermissionMismatch,
            Self::NotFound => SapProviderErrorKind::NotFound,
            Self::InvalidResponse | Self::Model(_) | Self::Definition(_) => {
                SapProviderErrorKind::InvalidResponse
            }
            Self::PageLoop => SapProviderErrorKind::PageLoop,
            Self::EtagDrift => SapProviderErrorKind::EtagDrift,
            Self::RevisionDrift => SapProviderErrorKind::RevisionDrift,
            Self::Http { evidence } => evidence.kind,
            Self::Transport(SapTransportError::BlockedEnv) => {
                SapProviderErrorKind::BlockedEnvironment
            }
            Self::Transport(SapTransportError::Timeout) => SapProviderErrorKind::Timeout,
            Self::Transport(_) => SapProviderErrorKind::Transport,
        }
    }

    pub fn evidence(&self) -> ProviderErrorEvidence {
        match self {
            Self::Http { evidence } => evidence.clone(),
            Self::Transport(error) => {
                let kind = self.kind();
                ProviderErrorEvidence::new(kind, None, None, &error.to_string())
            }
            _ => {
                let kind = self.kind();
                ProviderErrorEvidence::new(kind, None, None, &self.to_string())
            }
        }
    }
}

#[derive(Clone, Debug)]
struct EntitySetCollection {
    rows: Vec<crate::model::SapODataRow>,
    etag: Option<OpaqueEtag>,
    source_revision: Revision,
    redaction: RedactionSummary,
    request_digests: Vec<Digest>,
    partial: bool,
}

#[derive(Clone, Debug)]
pub struct SapS4HanaProvider<T: SapODataTransport = BlockedEnvSapODataTransport> {
    definition: SapS4HanaProviderDefinition,
    scope: SapSalesOrderScope,
    secret_reference: SecretReference,
    registration: SapRegistration,
    transport: T,
}

impl SapS4HanaProvider<BlockedEnvSapODataTransport> {
    pub fn blocked(scope: SapSalesOrderScope) -> Result<Self, SapProviderError> {
        let secret_reference = SecretReference::oauth("blocked-env-secret-reference", &scope, 1)?;
        Self::new(scope, secret_reference, BlockedEnvSapODataTransport)
    }
}

impl<T: SapODataTransport> SapS4HanaProvider<T> {
    pub fn register(
        scope: SapSalesOrderScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, SapProviderError> {
        Self::new(scope, secret_reference, transport)
    }

    pub fn for_scope(scope: SapSalesOrderScope, transport: T) -> Result<Self, SapProviderError> {
        let secret_reference = SecretReference::oauth("layer1-opaque-secret-reference", &scope, 1)?;
        Self::new(scope, secret_reference, transport)
    }

    pub fn new(
        scope: SapSalesOrderScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, SapProviderError> {
        scope.validate()?;
        if secret_reference.is_revoked() || secret_reference.scope_digest() != scope.scope_digest()
        {
            return Err(SapProviderError::ScopeMismatch);
        }
        let definition = SapS4HanaProviderDefinition::layer1();
        definition.validate()?;
        let registration = SapRegistration::new(
            Digest::from_text(SAP_SALES_ORDER_RESULT_IMPLEMENTATION),
            Digest::from_text(SAP_SALES_ORDER_RESULT_CONTRACT_JSON),
            definition.digest(),
            &scope,
            &secret_reference,
        )?;
        Ok(Self {
            definition,
            scope,
            secret_reference,
            registration,
            transport,
        })
    }

    pub fn definition(&self) -> &SapS4HanaProviderDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &SapSalesOrderScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &SapRegistration {
        &self.registration
    }

    pub fn provider_digest(&self) -> &Digest {
        self.registration.provider_digest()
    }

    pub fn permission_digest(&self) -> &Digest {
        self.registration.permission_digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        self.registration.scope_digest()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> SapTransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub const fn is_registered(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke(&mut self) -> Result<(), SapProviderError> {
        self.registration.revoke()?;
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn unmount(&mut self) -> Result<(), SapProviderError> {
        self.revoke()
    }

    pub fn read_sales_order(&mut self) -> Result<SapSalesOrderEvidence, SapProviderError> {
        self.ensure_active()?;
        let header = self.collect_entity_set(SapEntitySet::SalesOrder)?;
        if header.rows.is_empty() {
            return Err(SapProviderError::NotFound);
        }
        if header.rows.len() != 1 {
            return Err(SapProviderError::InvalidResponse);
        }
        let items = if self
            .scope
            .entity_sets()
            .contains(&SapEntitySet::SalesOrderItem)
        {
            self.collect_entity_set(SapEntitySet::SalesOrderItem)?
        } else {
            empty_collection(header.source_revision, header.etag.clone())
        };
        ensure_same_revision(&header, &items)?;
        let document_flow = if self
            .scope
            .entity_sets()
            .contains(&SapEntitySet::SalesOrderDocumentFlow)
        {
            self.collect_entity_set(SapEntitySet::SalesOrderDocumentFlow)?
        } else {
            empty_collection(header.source_revision, header.etag.clone())
        };
        ensure_same_revision(&header, &document_flow)?;

        let header_row = &header.rows[0];
        let order = project_header(header_row, &self.scope, header.source_revision)?;
        let mut item_projections = items
            .rows
            .iter()
            .map(|row| project_item(row, &self.scope, items.source_revision))
            .collect::<Result<Vec<_>, _>>()?;
        let mut flow_projections = document_flow
            .rows
            .iter()
            .map(|row| {
                project_document_flow(
                    row,
                    document_flow.source_revision,
                    self.scope.bounds().max_document_flow_depth(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut partial = header.partial || items.partial || document_flow.partial;
        if item_projections.len() > self.scope.bounds().max_items() {
            item_projections.truncate(self.scope.bounds().max_items());
            partial = true;
        }
        if flow_projections.len() > self.scope.bounds().max_document_flow() {
            flow_projections.truncate(self.scope.bounds().max_document_flow());
            partial = true;
        }

        let mut redaction = header.redaction.clone();
        redaction.merge(&items.redaction);
        redaction.merge(&document_flow.redaction);
        let fulfillment_state = fulfillment_state(&order, &item_projections);
        let block_state = block_state(
            order.block_state,
            item_projections.iter().map(|item| item.block_state),
        );
        let request_digest = digest_safe_fields(
            header
                .request_digests
                .iter()
                .chain(items.request_digests.iter())
                .chain(document_flow.request_digests.iter())
                .map(|digest| digest.as_str().to_owned()),
        );
        let etag = header.etag.clone();
        let revision_fence = self
            .scope
            .revision_fence()
            .with_source(header.source_revision, etag.clone());
        let result_digest = Digest::from_parts(
            "sap-sales-order-result/v1",
            [
                self.scope.scope_digest().as_str().to_owned(),
                self.registration.registration_digest().as_str().to_owned(),
                order.document_id.as_str().to_owned(),
                header.source_revision.get().to_string(),
                etag.as_ref().map_or_else(
                    || "none".to_owned(),
                    |etag| etag.digest().as_str().to_owned(),
                ),
                item_projections.len().to_string(),
                flow_projections.len().to_string(),
                format!("{fulfillment_state:?}"),
                format!("{block_state:?}"),
                redaction.digest().as_str().to_owned(),
                partial.to_string(),
                request_digest.as_str().to_owned(),
            ],
        );
        Ok(SapSalesOrderEvidence {
            scope_digest: self.scope.scope_digest().clone(),
            permission_digest: self.scope.permission_lease().digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            order,
            items: item_projections,
            document_flow: flow_projections,
            fulfillment_state,
            block_state,
            source_revision: header.source_revision,
            etag,
            redaction,
            partial,
            request_digest,
            result_digest,
            provenance: self.provenance(),
            revision_fence,
        })
    }

    pub fn read(&mut self) -> Result<SapSalesOrderEvidence, SapProviderError> {
        self.read_sales_order()
    }

    pub fn read_observation(&mut self) -> SapSalesOrderObservation {
        let scope_digest = self.scope.scope_digest().clone();
        let permission_digest = self.scope.permission_lease().digest().clone();
        let registration_digest = self.registration.registration_digest().clone();
        let provenance = self.provenance();
        match self.read_sales_order() {
            Ok(evidence) => SapSalesOrderObservation::from_evidence(evidence),
            Err(error) => SapSalesOrderObservation::from_error(
                scope_digest,
                permission_digest,
                registration_digest,
                provenance,
                self.scope.revision_fence(),
                error.evidence(),
            ),
        }
    }

    fn ensure_active(&self) -> Result<(), SapProviderError> {
        if !self.registration.is_active() {
            return Err(SapProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(SapProviderError::SecretRevoked);
        }
        if self.registration.scope_digest() != self.scope.scope_digest()
            || self.registration.permission_digest() != self.scope.permission_lease().digest()
            || self.secret_reference.scope_digest() != self.scope.scope_digest()
        {
            return Err(SapProviderError::ScopeMismatch);
        }
        Ok(())
    }

    fn collect_entity_set(
        &mut self,
        entity_set: SapEntitySet,
    ) -> Result<EntitySetCollection, SapProviderError> {
        let mut rows = Vec::new();
        let mut request_digests = Vec::new();
        let mut redaction = RedactionSummary::new();
        let mut page_count = 0_u8;
        let mut skip = 0_u32;
        let mut seen_skips = BTreeSet::new();
        let mut source_revision = None;
        let mut etag = None;
        let mut partial = false;
        loop {
            if page_count >= self.scope.bounds().max_pages() {
                partial = true;
                break;
            }
            if !seen_skips.insert(skip) {
                return Err(SapProviderError::PageLoop);
            }
            let request = SapODataRequest::for_scope(&self.scope, entity_set, skip)?;
            let response = self.transport.read(&request)?;
            if response.request_digest() != request.digest() {
                return Err(SapProviderError::InvalidResponse);
            }
            if !(200..300).contains(&response.status()) {
                return Err(SapProviderError::Http {
                    evidence: http_error_evidence(&response),
                });
            }
            let page = response.page().ok_or(SapProviderError::InvalidResponse)?;
            if page.entity_set() != entity_set {
                return Err(SapProviderError::InvalidResponse);
            }
            if let Some(expected) = source_revision {
                if expected != page.source_revision() {
                    return Err(SapProviderError::RevisionDrift);
                }
            } else {
                source_revision = Some(page.source_revision());
            }
            if let Some(page_etag) = page.etag() {
                if let Some(expected) = &etag {
                    if expected != page_etag {
                        return Err(SapProviderError::EtagDrift);
                    }
                } else {
                    etag = Some(page_etag.clone());
                }
            }
            if let Some(expected) = self.scope.expected_source_revision()
                && expected != page.source_revision()
            {
                return Err(SapProviderError::RevisionDrift);
            }
            if let (Some(expected), Some(actual)) = (self.scope.expected_etag(), page.etag())
                && expected != actual
            {
                return Err(SapProviderError::EtagDrift);
            }
            rows.extend(page.rows().iter().cloned());
            redaction.merge(page.redaction());
            request_digests.push(request.digest().clone());
            page_count = page_count.saturating_add(1);
            match page.next_skip() {
                Some(next_skip) if next_skip > skip => skip = next_skip,
                Some(_) => return Err(SapProviderError::PageLoop),
                None => break,
            }
        }
        Ok(EntitySetCollection {
            rows,
            etag,
            source_revision: source_revision.ok_or(SapProviderError::InvalidResponse)?,
            redaction,
            request_digests,
            partial,
        })
    }
}

fn empty_collection(source_revision: Revision, etag: Option<OpaqueEtag>) -> EntitySetCollection {
    EntitySetCollection {
        rows: Vec::new(),
        etag,
        source_revision,
        redaction: RedactionSummary::new(),
        request_digests: Vec::new(),
        partial: false,
    }
}

fn ensure_same_revision(
    expected: &EntitySetCollection,
    actual: &EntitySetCollection,
) -> Result<(), SapProviderError> {
    if expected.source_revision != actual.source_revision {
        return Err(SapProviderError::RevisionDrift);
    }
    if let (Some(expected), Some(actual)) = (&expected.etag, &actual.etag)
        && expected != actual
    {
        return Err(SapProviderError::EtagDrift);
    }
    Ok(())
}

fn http_error_evidence(response: &SapODataResponse) -> ProviderErrorEvidence {
    let (kind, detail) = match response.status() {
        401 => (SapProviderErrorKind::Unauthorized, "401"),
        403 => (SapProviderErrorKind::Forbidden, "403"),
        404 => (SapProviderErrorKind::NotFound, "404"),
        409 => (SapProviderErrorKind::Conflict, "409"),
        429 => (SapProviderErrorKind::RateLimited, "429"),
        status if (500..600).contains(&status) => (SapProviderErrorKind::ServerFailure, "5xx"),
        _ => (SapProviderErrorKind::ProviderUnknown, "http"),
    };
    ProviderErrorEvidence::new(
        kind,
        Some(response.status()),
        response.retry_after_seconds(),
        detail,
    )
}

fn project_header(
    row: &crate::model::SapODataRow,
    scope: &SapSalesOrderScope,
    source_revision: Revision,
) -> Result<SalesOrderHeaderProjection, SapProviderError> {
    let document_id = parse_opaque_document_id(row.field("SalesOrder"), scope.sales_order_id());
    let currency = row.field("TransactionCurrency").map(str::to_owned);
    let amount = row.field("TotalNetAmount").map(str::to_owned);
    let money = crate::model::MoneySummary::new(currency, amount)?;
    let delivery_status = map_fulfillment(row.field("OverallDeliveryStatus"));
    let billing_status = map_fulfillment(row.field("OverallBillingStatus"));
    let block_state = block_state_from_reasons(
        row.field("DeliveryBlockReason"),
        row.field("BillingBlockReason"),
    );
    Ok(SalesOrderHeaderProjection {
        document_id,
        lifecycle: map_lifecycle(row.field("OverallSDProcessStatus")),
        order_type: row.field("SalesOrderType").map(str::to_owned),
        created_date: bounded_text(row.field("CreationDate")),
        last_changed_date: bounded_text(row.field("LastChangeDate")),
        money,
        delivery_status,
        billing_status,
        block_state,
        etag: parse_opaque_etag(row.field("ETag")),
        source_revision,
    })
}

fn project_item(
    row: &crate::model::SapODataRow,
    scope: &SapSalesOrderScope,
    source_revision: Revision,
) -> Result<SalesOrderItemProjection, SapProviderError> {
    let item_id = row
        .field("SalesOrderItem")
        .ok_or(SapProviderError::InvalidResponse)?
        .to_owned();
    let material_digest = row
        .field("Material")
        .map(|material| Digest::from_values("sap-material/v1", &[material]));
    let requested_quantity = row.field("RequestedQuantity").map(str::to_owned);
    if requested_quantity
        .as_deref()
        .is_some_and(|value| !is_bounded_decimal(value))
    {
        return Err(SapProviderError::InvalidResponse);
    }
    let money = crate::model::MoneySummary::new(
        row.field("TransactionCurrency").map(str::to_owned),
        row.field("NetAmount").map(str::to_owned),
    )?;
    let block_state = block_state_from_reasons(
        row.field("DeliveryBlockReason"),
        row.field("BillingBlockReason"),
    );
    let _ = parse_opaque_document_id(row.field("SalesOrder"), scope.sales_order_id());
    Ok(SalesOrderItemProjection {
        item_id,
        material_digest,
        requested_quantity,
        requested_quantity_unit: row.field("RequestedQuantityUnit").map(str::to_owned),
        money,
        delivery_status: map_fulfillment(row.field("DeliveryStatus")),
        billing_status: map_fulfillment(row.field("BillingStatus")),
        block_state,
        etag: parse_opaque_etag(row.field("ETag")),
        source_revision,
    })
}

fn project_document_flow(
    row: &crate::model::SapODataRow,
    source_revision: Revision,
    max_depth: u8,
) -> Result<SalesOrderDocumentFlowProjection, SapProviderError> {
    let depth = row.field("DocumentFlowDepth").map_or(Ok(1), |value| {
        value
            .parse::<u8>()
            .map_err(|_| SapProviderError::InvalidResponse)
    })?;
    if depth == 0 || depth > max_depth {
        return Err(SapProviderError::InvalidResponse);
    }
    Ok(SalesOrderDocumentFlowProjection {
        preceding_document_id: parse_optional_document_id(row.field("PrecedingDocument")),
        subsequent_document_id: parse_optional_document_id(row.field("SubsequentDocument")),
        delivery_document_id: parse_optional_document_id(row.field("DeliveryDocument")),
        billing_document_id: parse_optional_document_id(row.field("BillingDocument")),
        preceding_item_id: bounded_text(row.field("PrecedingDocumentItem")),
        subsequent_item_id: bounded_text(row.field("SubsequentDocumentItem")),
        document_category: bounded_text(row.field("DocumentCategory")),
        document_flow_status: bounded_text(row.field("DocumentFlowStatus")),
        depth,
        created_date: bounded_text(row.field("CreationDate")),
        last_changed_date: bounded_text(row.field("LastChangeDate")),
        etag: parse_opaque_etag(row.field("ETag")),
        source_revision,
    })
}

fn parse_optional_document_id(value: Option<&str>) -> Option<OpaqueDocumentId> {
    value
        .and_then(|value| Digest::parse(value.to_owned()).ok())
        .map(OpaqueDocumentId::from_digest)
}

fn bounded_text(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| !value.is_empty() && value.len() <= crate::model::MAX_FIELD_VALUE_BYTES)
        .map(str::to_owned)
}

fn is_bounded_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::model::MAX_FIELD_VALUE_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_digit() || byte == b'.' || (byte == b'-' && index == 0)
        })
        && value.bytes().any(|byte| byte.is_ascii_digit())
        && value.bytes().filter(|byte| *byte == b'.').count() <= 1
}

fn map_lifecycle(value: Option<&str>) -> OrderLifecycleState {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("a" | "created") => OrderLifecycleState::Open,
        Some("b" | "in_process" | "inprocess") => OrderLifecycleState::InProcess,
        Some("c" | "completed" | "complete") => OrderLifecycleState::Completed,
        Some("cancelled" | "canceled") => OrderLifecycleState::Cancelled,
        Some(value) if !value.is_empty() => OrderLifecycleState::Unknown,
        _ => OrderLifecycleState::Created,
    }
}

fn map_fulfillment(value: Option<&str>) -> FulfillmentState {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("a" | "not_started" | "notstarted") => FulfillmentState::NotStarted,
        Some("b" | "in_process" | "inprocess") => FulfillmentState::InProgress,
        Some("partial") => FulfillmentState::Partial,
        Some("c" | "complete" | "completed") => FulfillmentState::Complete,
        Some("blocked") => FulfillmentState::Blocked,
        Some(value) if !value.is_empty() => FulfillmentState::Unknown,
        _ => FulfillmentState::Unknown,
    }
}

fn block_state_from_reasons(
    delivery_reason: Option<&str>,
    billing_reason: Option<&str>,
) -> BlockState {
    let delivery = delivery_reason.is_some_and(|reason| !reason.is_empty());
    let billing = billing_reason.is_some_and(|reason| !reason.is_empty());
    match (delivery, billing) {
        (false, false) => BlockState::None,
        (true, false) => BlockState::Delivery,
        (false, true) => BlockState::Billing,
        (true, true) => BlockState::DeliveryAndBilling,
    }
}

fn block_state(
    header_state: BlockState,
    item_states: impl Iterator<Item = BlockState>,
) -> BlockState {
    item_states.fold(header_state, |state, item_state| {
        match (state, item_state) {
            (BlockState::DeliveryAndBilling, _) | (_, BlockState::DeliveryAndBilling) => {
                BlockState::DeliveryAndBilling
            }
            (BlockState::Unknown, _) | (_, BlockState::Unknown) => BlockState::Unknown,
            (BlockState::None, other) | (other, BlockState::None) => other,
            (BlockState::Delivery, BlockState::Billing)
            | (BlockState::Billing, BlockState::Delivery) => BlockState::DeliveryAndBilling,
            (current, _) => current,
        }
    })
}

fn fulfillment_state(
    header: &SalesOrderHeaderProjection,
    items: &[SalesOrderItemProjection],
) -> FulfillmentState {
    if matches!(
        header.block_state,
        BlockState::Delivery | BlockState::Billing | BlockState::DeliveryAndBilling
    ) || items.iter().any(|item| {
        matches!(
            item.block_state,
            BlockState::Delivery | BlockState::Billing | BlockState::DeliveryAndBilling
        )
    }) {
        return FulfillmentState::Blocked;
    }
    if items
        .iter()
        .any(|item| item.delivery_status == FulfillmentState::Partial)
    {
        return FulfillmentState::Partial;
    }
    if items
        .iter()
        .any(|item| item.delivery_status == FulfillmentState::InProgress)
    {
        return FulfillmentState::InProgress;
    }
    if header.delivery_status == FulfillmentState::Complete
        && items
            .iter()
            .all(|item| item.delivery_status == FulfillmentState::Complete)
    {
        return FulfillmentState::Complete;
    }
    header.delivery_status
}

#[allow(dead_code)]
fn _registration_state_is_active(state: RegistrationState) -> bool {
    matches!(state, RegistrationState::Active)
}

#[allow(dead_code)]
fn _permission_lease_is_read_only(_lease: &PermissionLease) -> bool {
    true
}

#[allow(dead_code)]
fn _observation_state_is_non_native(state: SapObservationState) -> bool {
    matches!(
        state,
        SapObservationState::Available
            | SapObservationState::Partial
            | SapObservationState::Deleted
            | SapObservationState::AccessLost
            | SapObservationState::RevisionConflict
            | SapObservationState::ProviderUnknown
    )
}

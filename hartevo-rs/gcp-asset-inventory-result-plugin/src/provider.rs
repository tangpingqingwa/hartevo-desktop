//! Bounded Cloud Asset Inventory `searchAllResources` provider seams.
//!
//! The provider accepts only a typed, digest-bound query and returns only
//! redacted asset projections. There is no Google HTTP client, credential
//! resolver, BigQuery export, resource mutator, or raw response retention in
//! this Layer-1 crate.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AssetInventoryQuery, AssetProjection, AssetType, Digest, ModelError, RedactedAsset, Revision,
};
use crate::{
    GCP_ASSET_INVENTORY_API_VERSION, GCP_ASSET_INVENTORY_PROVIDER_ID,
    GCP_ASSET_INVENTORY_PROVIDER_SCHEMA, GCP_ASSET_INVENTORY_SCHEMA_VERSION,
};

/// Opaque Cloud Asset Inventory continuation token. Its token value is kept
/// only inside the transport seam and is never serialized or displayed.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    value: String,
    digest: Digest,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.len() > crate::model::MAX_IDENTIFIER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        let digest = Digest::from_serializable(&("hartevo:gcp-cloud-asset-page-token:v1", &value));
        Ok(Self { value, digest })
    }

    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

pub type OpaqueCursor = OpaquePageToken;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    AccessDenied,
    CredentialRevoked,
    RateLimited,
    PartialResponse,
    BlockedEnv,
    ProviderUnknown,
    InvalidResponse,
    ReplayDetected,
}

impl ProviderFailureClass {
    pub const fn projection(self) -> AssetProjection {
        match self {
            Self::AccessDenied | Self::CredentialRevoked => AssetProjection::AccessLost,
            Self::RateLimited | Self::PartialResponse => {
                AssetProjection::Partial(crate::model::PartialReason::RateLimited)
            }
            Self::BlockedEnv
            | Self::ProviderUnknown
            | Self::InvalidResponse
            | Self::ReplayDetected => AssetProjection::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpAssetInventoryProviderError {
    #[error("Cloud Asset Inventory provider request is invalid")]
    InvalidRequest,
    #[error("Cloud Asset Inventory provider definition drifted")]
    DefinitionDrift,
    #[error("Cloud Asset Inventory provider returned a page bound to a different request")]
    RequestMismatch,
    #[error("Cloud Asset Inventory provider returned invalid safe metadata")]
    InvalidResponse,
    #[error("Cloud Asset Inventory provider replay was detected")]
    ReplayDetected,
    #[error("Cloud Asset Inventory provider failure: {class:?}")]
    Failure {
        class: ProviderFailureClass,
        status_code: Option<u16>,
        diagnostic_digest: Digest,
    },
}

impl GcpAssetInventoryProviderError {
    pub fn failure(class: ProviderFailureClass, status_code: Option<u16>) -> Self {
        Self::Failure {
            class,
            status_code,
            diagnostic_digest: Digest::from_text(format!(
                "hartevo:gcp-cloud-asset-provider-failure:{class:?}:{status_code:?}"
            )),
        }
    }

    pub const fn class(&self) -> ProviderFailureClass {
        match self {
            Self::InvalidRequest | Self::DefinitionDrift | Self::RequestMismatch => {
                ProviderFailureClass::InvalidResponse
            }
            Self::InvalidResponse => ProviderFailureClass::InvalidResponse,
            Self::ReplayDetected => ProviderFailureClass::ReplayDetected,
            Self::Failure { class, .. } => *class,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Failure { status_code, .. } => *status_code,
            _ => None,
        }
    }

    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::Failure {
                diagnostic_digest, ..
            } => diagnostic_digest.clone(),
            Self::InvalidRequest => Digest::from_text("gcp-cloud-asset-invalid-request"),
            Self::DefinitionDrift => Digest::from_text("gcp-cloud-asset-definition-drift"),
            Self::RequestMismatch => Digest::from_text("gcp-cloud-asset-request-mismatch"),
            Self::InvalidResponse => Digest::from_text("gcp-cloud-asset-invalid-response"),
            Self::ReplayDetected => Digest::from_text("gcp-cloud-asset-replay-detected"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("provider revision is empty")]
    EmptyRevision,
    #[error("native Cloud Asset Inventory providers are forbidden in Layer 1")]
    NativeProviderForbidden,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAssetInventoryProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub search_all_resources: bool,
    pub live_execution: bool,
    pub native: bool,
    pub bigquery_export: bool,
    pub resource_mutation: bool,
}

impl GcpAssetInventoryProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provider_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        let provider_revision = provider_revision.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provider_revision.is_empty() {
            return Err(ProviderDefinitionError::EmptyRevision);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_serializable(&(
            GCP_ASSET_INVENTORY_SCHEMA_VERSION,
            GCP_ASSET_INVENTORY_PROVIDER_ID,
            &provider_version,
            &provider_revision,
            provenance,
            GCP_ASSET_INVENTORY_API_VERSION,
            "cloudasset.assets.searchAllResources",
            false,
            false,
            false,
        ));
        Ok(Self {
            schema_version: GCP_ASSET_INVENTORY_PROVIDER_SCHEMA.to_owned(),
            provider_id: GCP_ASSET_INVENTORY_PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision,
            capability_digest,
            provenance,
            search_all_resources: true,
            live_execution: false,
            native: false,
            bigquery_export: false,
            resource_mutation: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Safe `searchAllResources` request. The exact scope, resource identity,
/// ancestry, read time, secret binding, and page are all digest-bound.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchAllResourcesRequest {
    pub api_version: String,
    pub query: AssetInventoryQuery,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub page_number: u16,
    pub max_results: u16,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
    #[serde(skip)]
    page_token: Option<OpaquePageToken>,
}

impl fmt::Debug for SearchAllResourcesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchAllResourcesRequest")
            .field("api_version", &self.api_version)
            .field("query", &self.query)
            .field("provider_digest", &self.provider_digest)
            .field("provider_revision", &self.provider_revision)
            .field("page_number", &self.page_number)
            .field("max_results", &self.max_results)
            .field("page_token_digest", &self.page_token_digest)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

impl SearchAllResourcesRequest {
    pub fn new(
        query: AssetInventoryQuery,
        provider_digest: Digest,
        provider_revision: impl Into<String>,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, GcpAssetInventoryProviderError> {
        if page_number == 0
            || page_number > query.bounds.max_pages
            || query.bounds.page_size == 0
            || query.bounds.page_size
                > u16::try_from(crate::model::MAX_ASSETS_PER_PAGE).expect("page bound fits u16")
        {
            return Err(GcpAssetInventoryProviderError::InvalidRequest);
        }
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty() {
            return Err(GcpAssetInventoryProviderError::InvalidRequest);
        }
        let page_token_digest = page_token.as_ref().map(OpaquePageToken::digest);
        let mut request = Self {
            api_version: GCP_ASSET_INVENTORY_API_VERSION.to_owned(),
            query,
            provider_digest,
            provider_revision,
            page_number,
            max_results: 0,
            page_token_digest,
            request_digest: Digest::from_text("placeholder"),
            page_token,
        };
        request.max_results = request.query.bounds.page_size;
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    fn canonical(
        &self,
    ) -> (
        &str,
        &AssetInventoryQuery,
        &Digest,
        &str,
        u16,
        u16,
        &Option<Digest>,
    ) {
        (
            &self.api_version,
            &self.query,
            &self.provider_digest,
            &self.provider_revision,
            self.page_number,
            self.max_results,
            &self.page_token_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_digest(&self) -> bool {
        self.request_digest == self.compute_digest()
            && self.page_token_digest == self.page_token.as_ref().map(OpaquePageToken::digest)
            && self.query.verify_digest()
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchResponseStatus {
    Complete,
    Partial,
    Warning,
}

/// Safe page result. There is no Cloud Asset Inventory resource body, tag,
/// label, additional attribute, or raw page token.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchAllResourcesPage {
    pub page_number: u16,
    pub request_digest: Digest,
    pub provider_revision: String,
    pub response_status: SearchResponseStatus,
    pub assets: Vec<RedactedAsset>,
    pub next_page_token_digest: Option<Digest>,
    pub response_digest: Digest,
    #[serde(skip)]
    next_page_token: Option<OpaquePageToken>,
}

impl fmt::Debug for SearchAllResourcesPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchAllResourcesPage")
            .field("page_number", &self.page_number)
            .field("request_digest", &self.request_digest)
            .field("provider_revision", &self.provider_revision)
            .field("response_status", &self.response_status)
            .field("asset_count", &self.assets.len())
            .field("next_page_token_digest", &self.next_page_token_digest)
            .field("response_digest", &self.response_digest)
            .finish_non_exhaustive()
    }
}

impl SearchAllResourcesPage {
    pub fn new(
        request: &SearchAllResourcesRequest,
        assets: Vec<RedactedAsset>,
        next_page_token: Option<OpaquePageToken>,
        response_status: SearchResponseStatus,
    ) -> Result<Self, GcpAssetInventoryProviderError> {
        if assets.len() > usize::from(request.max_results)
            || assets.iter().any(|asset| !asset.verify_digest())
        {
            return Err(GcpAssetInventoryProviderError::InvalidResponse);
        }
        let next_page_token_digest = next_page_token.as_ref().map(OpaquePageToken::digest);
        let mut page = Self {
            page_number: request.page_number,
            request_digest: request.request_digest.clone(),
            provider_revision: request.provider_revision.clone(),
            response_status,
            assets,
            next_page_token_digest,
            response_digest: Digest::from_text("placeholder"),
            next_page_token,
        };
        page.response_digest = page.compute_digest();
        Ok(page)
    }

    fn canonical(
        &self,
    ) -> (
        u16,
        &Digest,
        &str,
        SearchResponseStatus,
        &Vec<RedactedAsset>,
        &Option<Digest>,
    ) {
        (
            self.page_number,
            &self.request_digest,
            &self.provider_revision,
            self.response_status,
            &self.assets,
            &self.next_page_token_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_digest(&self, request: &SearchAllResourcesRequest) -> bool {
        self.request_digest == request.request_digest
            && self.page_number == request.page_number
            && self.provider_revision == request.provider_revision
            && self.next_page_token_digest
                == self.next_page_token.as_ref().map(OpaquePageToken::digest)
            && self.assets.iter().all(RedactedAsset::verify_digest)
            && self.response_digest == self.compute_digest()
    }

    pub fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page_token.as_ref()
    }
}

/// A proposal is the auditable bridge between a typed operation and a page
/// request. It binds registration, query, provider, and page token digests.
#[derive(Clone, Eq, PartialEq)]
pub struct SearchAllResourcesProposal {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub query: AssetInventoryQuery,
    pub request_digest: Digest,
    pub page_number: u16,
    pub page_token_digest: Option<Digest>,
    pub proposal_digest: Digest,
    request: SearchAllResourcesRequest,
}

impl fmt::Debug for SearchAllResourcesProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchAllResourcesProposal")
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field("provider_digest", &self.provider_digest)
            .field("provider_revision", &self.provider_revision)
            .field("query", &self.query)
            .field("request_digest", &self.request_digest)
            .field("page_number", &self.page_number)
            .field("page_token_digest", &self.page_token_digest)
            .field("proposal_digest", &self.proposal_digest)
            .finish_non_exhaustive()
    }
}

impl SearchAllResourcesProposal {
    pub fn new(
        registration_digest: Digest,
        registration_revision: Revision,
        request: SearchAllResourcesRequest,
    ) -> Self {
        let mut proposal = Self {
            registration_digest,
            registration_revision,
            provider_digest: request.provider_digest.clone(),
            provider_revision: request.provider_revision.clone(),
            query: request.query.clone(),
            request_digest: request.request_digest.clone(),
            page_number: request.page_number,
            page_token_digest: request.page_token_digest.clone(),
            proposal_digest: Digest::from_text("placeholder"),
            request,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn canonical(
        &self,
    ) -> (
        &Digest,
        Revision,
        &Digest,
        &str,
        &AssetInventoryQuery,
        &Digest,
        u16,
        &Option<Digest>,
    ) {
        (
            &self.registration_digest,
            self.registration_revision,
            &self.provider_digest,
            &self.provider_revision,
            &self.query,
            &self.request_digest,
            self.page_number,
            &self.page_token_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_digest(&self) -> bool {
        self.proposal_digest == self.compute_digest()
            && self.request.verify_digest()
            && self.request_digest == self.request.request_digest
            && self.page_token_digest == self.request.page_token_digest
    }

    pub fn request(&self) -> &SearchAllResourcesRequest {
        &self.request
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchAllResourcesRecord {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub page_number: u16,
    pub response_status: SearchResponseStatus,
    pub assets: Vec<RedactedAsset>,
    pub next_page_token_digest: Option<Digest>,
    pub record_digest: Digest,
}

impl SearchAllResourcesRecord {
    pub fn from_parts(
        proposal: &SearchAllResourcesProposal,
        page: &SearchAllResourcesPage,
    ) -> Result<Self, GcpAssetInventoryProviderError> {
        if !proposal.verify_digest()
            || !page.verify_digest(proposal.request())
            || page.request_digest != proposal.request_digest
        {
            return Err(GcpAssetInventoryProviderError::RequestMismatch);
        }
        let mut record = Self {
            registration_digest: proposal.registration_digest.clone(),
            registration_revision: proposal.registration_revision,
            provider_digest: proposal.provider_digest.clone(),
            provider_revision: proposal.provider_revision.clone(),
            query_digest: proposal.query.query_digest.clone(),
            scope_digest: proposal.query.scope_digest.clone(),
            permission_digest: proposal.query.permission_digest.clone(),
            secret_reference_digest: proposal.query.secret_reference_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            response_digest: page.response_digest.clone(),
            page_number: page.page_number,
            response_status: page.response_status,
            assets: page.assets.clone(),
            next_page_token_digest: page.next_page_token_digest.clone(),
            record_digest: Digest::from_text("placeholder"),
        };
        record.record_digest = record.compute_digest();
        Ok(record)
    }

    fn canonical(
        &self,
    ) -> (
        &Digest,
        Revision,
        &Digest,
        &str,
        &Digest,
        &Digest,
        &Digest,
        &Digest,
        &Digest,
        &Digest,
        u16,
        SearchResponseStatus,
        &Vec<RedactedAsset>,
        &Option<Digest>,
    ) {
        (
            &self.registration_digest,
            self.registration_revision,
            &self.provider_digest,
            &self.provider_revision,
            &self.query_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
            &self.request_digest,
            &self.response_digest,
            self.page_number,
            self.response_status,
            &self.assets,
            &self.next_page_token_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_integrity(&self) -> bool {
        self.assets.iter().all(RedactedAsset::verify_digest)
            && self.record_digest == self.compute_digest()
    }
}

pub trait GcpAssetInventoryTransport: fmt::Debug {
    fn search_all_resources(
        &mut self,
        request: &SearchAllResourcesRequest,
    ) -> Result<SearchAllResourcesPage, GcpAssetInventoryProviderError>;

    fn provenance(&self) -> ProviderProvenance;
}

/// Typed provider wrapper. Layer 1 never reports this provider as native.
pub struct GcpAssetInventoryProvider<T>
where
    T: GcpAssetInventoryTransport,
{
    transport: T,
    definition: GcpAssetInventoryProviderDefinition,
    seen_request_digests: BTreeSet<Digest>,
}

impl<T> fmt::Debug for GcpAssetInventoryProvider<T>
where
    T: GcpAssetInventoryTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpAssetInventoryProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .field("seen_request_count", &self.seen_request_digests.len())
            .finish_non_exhaustive()
    }
}

impl<T> GcpAssetInventoryProvider<T>
where
    T: GcpAssetInventoryTransport,
{
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        let provenance = transport.provenance();
        Ok(Self {
            transport,
            definition: GcpAssetInventoryProviderDefinition::new(
                provider_version,
                provider_revision,
                provenance,
            )?,
            seen_request_digests: BTreeSet::new(),
        })
    }

    pub fn definition(&self) -> &GcpAssetInventoryProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub fn read(
        &mut self,
        request: &SearchAllResourcesRequest,
    ) -> Result<SearchAllResourcesPage, GcpAssetInventoryProviderError> {
        if !request.verify_digest()
            || request.provider_digest != self.definition.provider_digest()
            || request.provider_revision != self.definition.provider_revision
            || request.api_version != GCP_ASSET_INVENTORY_API_VERSION
        {
            return Err(GcpAssetInventoryProviderError::DefinitionDrift);
        }
        if !self
            .seen_request_digests
            .insert(request.request_digest.clone())
        {
            return Err(GcpAssetInventoryProviderError::ReplayDetected);
        }
        let page = self.transport.search_all_resources(request)?;
        if !page.verify_digest(request) {
            return Err(GcpAssetInventoryProviderError::InvalidResponse);
        }
        Ok(page)
    }

    pub fn record(
        &self,
        proposal: &SearchAllResourcesProposal,
        page: &SearchAllResourcesPage,
    ) -> Result<SearchAllResourcesRecord, GcpAssetInventoryProviderError> {
        SearchAllResourcesRecord::from_parts(proposal, page)
    }

    pub fn verify(
        &self,
        proposal: &SearchAllResourcesProposal,
        record: &SearchAllResourcesRecord,
    ) -> Result<(), GcpAssetInventoryProviderError> {
        if !proposal.verify_digest()
            || !record.verify_integrity()
            || record.registration_digest != proposal.registration_digest
            || record.registration_revision != proposal.registration_revision
            || record.provider_digest != self.definition.provider_digest()
            || record.provider_revision != self.definition.provider_revision
            || record.request_digest != proposal.request_digest
            || record.query_digest != proposal.query.query_digest
        {
            return Err(GcpAssetInventoryProviderError::RequestMismatch);
        }
        Ok(())
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// Deterministic redacted fixture transport. It filters only exact safe
/// resource identity/type/ancestry/read-time projections and paginates them.
#[derive(Clone, Debug)]
pub struct FakeGcpAssetInventoryTransport {
    assets: Vec<RedactedAsset>,
    requests: Vec<SearchAllResourcesRequest>,
    next_failure: Option<GcpAssetInventoryProviderError>,
}

impl FakeGcpAssetInventoryTransport {
    pub fn new(assets: impl IntoIterator<Item = RedactedAsset>) -> Self {
        Self {
            assets: assets.into_iter().collect(),
            requests: Vec::new(),
            next_failure: None,
        }
    }

    pub fn push_failure(&mut self, error: GcpAssetInventoryProviderError) {
        self.next_failure = Some(error);
    }

    pub fn requests(&self) -> &[SearchAllResourcesRequest] {
        &self.requests
    }

    pub fn assets(&self) -> &[RedactedAsset] {
        &self.assets
    }
}

impl GcpAssetInventoryTransport for FakeGcpAssetInventoryTransport {
    fn search_all_resources(
        &mut self,
        request: &SearchAllResourcesRequest,
    ) -> Result<SearchAllResourcesPage, GcpAssetInventoryProviderError> {
        self.requests.push(request.clone());
        if let Some(error) = self.next_failure.take() {
            return Err(error);
        }
        let expected_token = if request.page_number == 1 {
            None
        } else {
            Some(
                fake_page_token_for_page(request.page_number)
                    .map_err(|_| GcpAssetInventoryProviderError::InvalidRequest)?,
            )
        };
        if request.page_token_digest != expected_token.as_ref().map(OpaquePageToken::digest) {
            return Err(GcpAssetInventoryProviderError::RequestMismatch);
        }
        let mut matches: Vec<_> = self
            .assets
            .iter()
            .filter(|asset| {
                asset.resource_name_digest == request.query.resource.resource_name_digest
                    && asset.asset_type == request.query.resource.asset_type
                    && asset.ancestry == request.query.resource.ancestry
                    && asset.read_time == request.query.read_time
            })
            .cloned()
            .collect();
        let page_size = usize::from(request.max_results);
        let page_start = usize::from(request.page_number.saturating_sub(1)) * page_size;
        if page_start > matches.len() {
            matches.clear();
        } else {
            matches = matches
                .into_iter()
                .skip(page_start)
                .take(page_size)
                .collect();
        }
        let total_matches = self
            .assets
            .iter()
            .filter(|asset| {
                asset.resource_name_digest == request.query.resource.resource_name_digest
                    && asset.asset_type == request.query.resource.asset_type
                    && asset.ancestry == request.query.resource.ancestry
                    && asset.read_time == request.query.read_time
            })
            .count();
        let has_more = page_start.saturating_add(matches.len()) < total_matches;
        let next_page_token = has_more
            .then(|| fake_page_token_for_page(request.page_number + 1))
            .transpose()
            .map_err(|_| GcpAssetInventoryProviderError::InvalidResponse)?;
        SearchAllResourcesPage::new(
            request,
            matches,
            next_page_token,
            SearchResponseStatus::Complete,
        )
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fake
    }
}

pub type LoopbackGcpAssetInventoryTransport = FakeGcpAssetInventoryTransport;

#[derive(Clone, Debug)]
pub struct RecordingGcpAssetInventoryTransport {
    responses: VecDeque<Result<SearchAllResourcesPage, GcpAssetInventoryProviderError>>,
    requests: Vec<SearchAllResourcesRequest>,
    provenance: ProviderProvenance,
}

impl RecordingGcpAssetInventoryTransport {
    pub fn new(
        responses: impl IntoIterator<
            Item = Result<SearchAllResourcesPage, GcpAssetInventoryProviderError>,
        >,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Recording,
        }
    }

    #[must_use]
    pub const fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(
        &mut self,
        response: Result<SearchAllResourcesPage, GcpAssetInventoryProviderError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[SearchAllResourcesRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl GcpAssetInventoryTransport for RecordingGcpAssetInventoryTransport {
    fn search_all_resources(
        &mut self,
        request: &SearchAllResourcesRequest,
    ) -> Result<SearchAllResourcesPage, GcpAssetInventoryProviderError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(GcpAssetInventoryProviderError::failure(
                ProviderFailureClass::ProviderUnknown,
                None,
            ))
        })
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpAssetInventoryTransport;

impl GcpAssetInventoryTransport for BlockedEnvGcpAssetInventoryTransport {
    fn search_all_resources(
        &mut self,
        _request: &SearchAllResourcesRequest,
    ) -> Result<SearchAllResourcesPage, GcpAssetInventoryProviderError> {
        Err(GcpAssetInventoryProviderError::failure(
            ProviderFailureClass::BlockedEnv,
            None,
        ))
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

pub type FakeGcpAssetInventoryProvider = GcpAssetInventoryProvider<FakeGcpAssetInventoryTransport>;

/// Test-only helper that creates a deterministic opaque token without
/// exposing its value to request serialization or Debug.
pub fn fake_page_token_for_page(page: u16) -> Result<OpaquePageToken, ModelError> {
    OpaquePageToken::new(format!("fake-page:{page}"))
}

pub fn provider_failure_projection(error: &GcpAssetInventoryProviderError) -> AssetProjection {
    error.class().projection()
}

#[allow(dead_code)]
fn _asset_type_is_bound(_: &AssetType) {}

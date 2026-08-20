//! Constrained AWS Resource Explorer provider and non-native transports.

use std::{collections::VecDeque, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AccountId, AwsRegion, AwsResourceExplorerOperation, AwsResourceExplorerScope, Digest,
    IndexInventoryItem, MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES, MAX_INDEXES, MAX_PAGES,
    MAX_PROPERTY_DIGESTS, MAX_RESOURCES, MAX_RESPONSE_BYTES, ModelError, PAGE_SIZE,
    PermissionAction, PropertyDigest, ResourceExplorerResource, ResourceInventoryItem,
    TransportProvenance, serialized_digest,
};

pub const AWS_RESOURCE_EXPLORER_PROVIDER_ID: &str = "aws.resource-explorer-2";
pub const AWS_RESOURCE_EXPLORER_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_RESOURCE_EXPLORER_API_REVISION: &str = "aws-resource-explorer-2-read-r1";
pub const AWS_RESOURCE_EXPLORER_PROVIDER_SCHEMA: &str =
    "hartevo.aws-resource-explorer-2-provider/v1";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider definition is invalid: {0}")]
    Invalid(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("provider rejected the bounded request")]
    InvalidRequest,
    #[error("provider authorization was unavailable")]
    Unauthorized,
    #[error("provider authorization was denied")]
    Forbidden,
    #[error("provider resource was not found")]
    NotFound,
    #[error("provider reported a conflicting revision")]
    Conflict,
    #[error("provider rate limited the bounded read")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("provider failed with a server response")]
    ServerFailure { status_code: Option<u16> },
    #[error("provider transport timed out")]
    Timeout,
    #[error("native transport is blocked in this environment")]
    BlockedEnv,
    #[error("provider response was malformed")]
    MalformedResponse,
}

impl TransportError {
    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let label = match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::ServerFailure { .. } => "server_failure",
            Self::Timeout => "timeout",
            Self::BlockedEnv => "blocked_env",
            Self::MalformedResponse => "malformed_response",
        };
        Digest::from_parts("aws-resource-explorer-provider-error/v1", [label])
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsResourceExplorerProviderError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("provider response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("provider response was invalid")]
    InvalidResponse,
    #[error("provider page does not match its bound request")]
    PageMismatch,
    #[error("provider operation is not allowlisted")]
    OperationNotAllowlisted,
}

impl AwsResourceExplorerProviderError {
    #[must_use]
    pub fn digest(&self) -> Digest {
        match self {
            Self::Transport(error) => error.digest(),
            Self::ResponseTooLarge => Digest::from_text("aws-resource-explorer-response-too-large"),
            Self::InvalidResponse => Digest::from_text("aws-resource-explorer-invalid-response"),
            Self::PageMismatch => Digest::from_text("aws-resource-explorer-page-mismatch"),
            Self::OperationNotAllowlisted => {
                Digest::from_text("aws-resource-explorer-operation-not-allowlisted")
            }
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::Transport(error) if error.is_access_loss())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerProviderDefinition {
    pub provider_id: String,
    pub version: String,
    pub api_revision: String,
    pub allowlisted_operations: Vec<String>,
    pub provenance: TransportProvenance,
    pub provider_digest: Digest,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub resolves_credentials: bool,
}

impl AwsResourceExplorerProviderDefinition {
    pub fn new(provenance: TransportProvenance) -> Result<Self, ProviderDefinitionError> {
        let definition_material = ProviderDigestMaterial {
            provider_id: AWS_RESOURCE_EXPLORER_PROVIDER_ID,
            version: AWS_RESOURCE_EXPLORER_PROVIDER_VERSION,
            api_revision: AWS_RESOURCE_EXPLORER_API_REVISION,
            allowlisted_operations: &["Search", "ListIndexes"],
        };
        Ok(Self {
            provider_id: AWS_RESOURCE_EXPLORER_PROVIDER_ID.to_owned(),
            version: AWS_RESOURCE_EXPLORER_PROVIDER_VERSION.to_owned(),
            api_revision: AWS_RESOURCE_EXPLORER_API_REVISION.to_owned(),
            allowlisted_operations: vec!["Search".to_owned(), "ListIndexes".to_owned()],
            provenance,
            provider_digest: serialized_digest(&definition_material),
            native: false,
            connected: false,
            external_writes: false,
            resolves_credentials: false,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.provider_id != AWS_RESOURCE_EXPLORER_PROVIDER_ID
            || self.version != AWS_RESOURCE_EXPLORER_PROVIDER_VERSION
            || self.api_revision != AWS_RESOURCE_EXPLORER_API_REVISION
            || self.allowlisted_operations != ["Search".to_owned(), "ListIndexes".to_owned()]
            || self.native
            || self.connected
            || self.external_writes
            || self.resolves_credentials
        {
            return Err(ProviderDefinitionError::Invalid(ModelError::Unsupported {
                field: "provider definition",
            }));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProviderDigestMaterial<'a> {
    provider_id: &'a str,
    version: &'a str,
    api_revision: &'a str,
    allowlisted_operations: &'a [&'a str],
}

/// An opaque page token retains only a digest and a request binding. Its
/// serializer emits a placeholder rather than the provider token.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    binding_digest: Digest,
}

impl OpaquePageToken {
    pub fn new(token: impl AsRef<str>, binding_digest: Digest) -> Result<Self, ModelError> {
        let token = token.as_ref();
        if token.is_empty() {
            return Err(ModelError::Empty {
                field: "page token",
            });
        }
        if token.len() > MAX_CURSOR_BYTES {
            return Err(ModelError::TooLong {
                field: "page token",
            });
        }
        if token.trim() != token || token.chars().any(char::is_control) {
            return Err(ModelError::ControlCharacter {
                field: "page token",
            });
        }
        if binding_digest != Digest::zero() {
            Digest::parse(binding_digest.as_str().to_owned(), "page binding")?;
        }
        Ok(Self {
            token_digest: Digest::from_parts("aws-resource-explorer-page-token/v1", [token]),
            binding_digest,
        })
    }

    pub fn from_digest(token_digest: Digest, binding_digest: Digest) -> Result<Self, ModelError> {
        Digest::parse(token_digest.as_str().to_owned(), "page token digest")?;
        Digest::parse(binding_digest.as_str().to_owned(), "page binding")?;
        Ok(Self {
            token_digest,
            binding_digest,
        })
    }

    pub fn bind(&self, binding_digest: Digest) -> Result<Self, ModelError> {
        Digest::parse(binding_digest.as_str().to_owned(), "page binding")?;
        if self.binding_digest != Digest::zero() && self.binding_digest != binding_digest {
            return Err(ModelError::ScopeMismatch {
                field: "page token binding",
            });
        }
        Ok(Self {
            token_digest: self.token_digest.clone(),
            binding_digest,
        })
    }

    #[must_use]
    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        self.token_digest()
    }

    #[must_use]
    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("OpaquePageToken", 1)
            .and_then(|mut state| {
                state.serialize_field("opaque", &true)?;
                state.end()
            })
    }
}

pub type OpaqueCursor = OpaquePageToken;
pub type AwsResourceExplorerOpaqueCursor = OpaquePageToken;
pub type OpaquePageTokenPlaceholder = OpaquePageToken;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchRequest {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub index_digest: Digest,
    pub view_digest: Digest,
    pub query_digest: Digest,
    pub resource_digests: Vec<Digest>,
    pub permission_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl SearchRequest {
    pub fn new(
        scope: &AwsResourceExplorerScope,
        page_size: u16,
        max_pages: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid { field: "max pages" });
        }
        let mut request = Self {
            account_id: scope.account_id().clone(),
            region: scope.region().clone(),
            index_digest: scope.index().index_digest().clone(),
            view_digest: scope.view().view_digest().clone(),
            query_digest: scope.query_digest().clone(),
            resource_digests: scope
                .resources()
                .iter()
                .map(ResourceExplorerResource::digest)
                .collect(),
            permission_digest: scope.permission_digest(),
            page_size,
            max_pages,
            page_token: None,
            request_digest: Digest::zero(),
        };
        let binding = request.pagination_binding_digest();
        request.page_token = page_token
            .map(|token| token.bind(binding.clone()))
            .transpose()?;
        request.request_digest = request.compute_request_digest();
        Ok(request)
    }

    pub fn with_page_token(&self, page_token: OpaquePageToken) -> Result<Self, ModelError> {
        let mut next = self.clone();
        next.page_token = Some(page_token.bind(self.pagination_binding_digest())?);
        next.request_digest = next.compute_request_digest();
        Ok(next)
    }

    #[must_use]
    pub fn pagination_binding_digest(&self) -> Digest {
        serialized_digest(&SearchRequestBindingMaterial {
            account_digest: self.account_id.digest(),
            region_digest: self.region.digest(),
            index_digest: self.index_digest.clone(),
            view_digest: self.view_digest.clone(),
            query_digest: self.query_digest.clone(),
            resource_digests: self.resource_digests.clone(),
            permission_digest: self.permission_digest.clone(),
            page_size: self.page_size,
            max_pages: self.max_pages,
        })
    }

    #[must_use]
    pub fn compute_request_digest(&self) -> Digest {
        serialized_digest(&SearchRequestDigestMaterial {
            binding_digest: self.pagination_binding_digest(),
            page_token_digest: self.page_token.as_ref().map(|token| token.digest().clone()),
        })
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn validate_against(&self, scope: &AwsResourceExplorerScope) -> Result<(), ModelError> {
        if self.account_id != *scope.account_id()
            || self.region != *scope.region()
            || self.index_digest != *scope.index().index_digest()
            || self.view_digest != *scope.view().view_digest()
            || self.query_digest != *scope.query_digest()
            || self.resource_digests
                != scope
                    .resources()
                    .iter()
                    .map(ResourceExplorerResource::digest)
                    .collect::<Vec<_>>()
            || self.permission_digest != scope.permission_digest()
            || self.request_digest != self.compute_request_digest()
            || self
                .page_token
                .as_ref()
                .is_some_and(|token| token.binding_digest() != &self.pagination_binding_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "Search request",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListIndexesRequest {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub permission_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl ListIndexesRequest {
    pub fn new(
        scope: &AwsResourceExplorerScope,
        page_size: u16,
        max_pages: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid { field: "max pages" });
        }
        let mut request = Self {
            account_id: scope.account_id().clone(),
            region: scope.region().clone(),
            permission_digest: scope.permission_digest(),
            page_size,
            max_pages,
            page_token: None,
            request_digest: Digest::zero(),
        };
        let binding = request.pagination_binding_digest();
        request.page_token = page_token
            .map(|token| token.bind(binding.clone()))
            .transpose()?;
        request.request_digest = request.compute_request_digest();
        Ok(request)
    }

    pub fn with_page_token(&self, page_token: OpaquePageToken) -> Result<Self, ModelError> {
        let mut next = self.clone();
        next.page_token = Some(page_token.bind(self.pagination_binding_digest())?);
        next.request_digest = next.compute_request_digest();
        Ok(next)
    }

    #[must_use]
    pub fn pagination_binding_digest(&self) -> Digest {
        serialized_digest(&ListIndexesRequestBindingMaterial {
            account_digest: self.account_id.digest(),
            region_digest: self.region.digest(),
            permission_digest: self.permission_digest.clone(),
            page_size: self.page_size,
            max_pages: self.max_pages,
        })
    }

    #[must_use]
    pub fn compute_request_digest(&self) -> Digest {
        serialized_digest(&SearchRequestDigestMaterial {
            binding_digest: self.pagination_binding_digest(),
            page_token_digest: self.page_token.as_ref().map(|token| token.digest().clone()),
        })
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn validate_against(&self, scope: &AwsResourceExplorerScope) -> Result<(), ModelError> {
        if self.account_id != *scope.account_id()
            || self.region != *scope.region()
            || self.permission_digest != scope.permission_digest()
            || self.request_digest != self.compute_request_digest()
            || self
                .page_token
                .as_ref()
                .is_some_and(|token| token.binding_digest() != &self.pagination_binding_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "ListIndexes request",
            });
        }
        Ok(())
    }
}

pub type AwsResourceExplorerSearchRequest = SearchRequest;
pub type AwsResourceExplorerListIndexesRequest = ListIndexesRequest;

#[derive(Serialize)]
struct SearchRequestBindingMaterial {
    account_digest: Digest,
    region_digest: Digest,
    index_digest: Digest,
    view_digest: Digest,
    query_digest: Digest,
    resource_digests: Vec<Digest>,
    permission_digest: Digest,
    page_size: u16,
    max_pages: u16,
}

#[derive(Serialize)]
struct ListIndexesRequestBindingMaterial {
    account_digest: Digest,
    region_digest: Digest,
    permission_digest: Digest,
    page_size: u16,
    max_pages: u16,
}

#[derive(Serialize)]
struct SearchRequestDigestMaterial {
    binding_digest: Digest,
    page_token_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchPage {
    pub page_number: u16,
    pub resources: Vec<ResourceInventoryItem>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub provider_revision: String,
    pub page_digest: Digest,
}

impl SearchPage {
    pub fn new(
        request: &SearchRequest,
        page_number: u16,
        resources: Vec<ResourceInventoryItem>,
        next_page_token: Option<OpaquePageToken>,
        response_bytes: usize,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "page number",
            });
        }
        if resources.len() > MAX_RESOURCES || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::TooMany {
                field: "Search page",
            });
        }
        let next_page_token = next_page_token
            .map(|token| token.bind(request.pagination_binding_digest()))
            .transpose()?;
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() || provider_revision.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::Invalid {
                field: "provider revision",
            });
        }
        let page_digest = serialized_digest(&PageDigestMaterial {
            operation: AwsResourceExplorerOperation::Search,
            page_number,
            item_digests: resources
                .iter()
                .map(ResourceInventoryItem::digest)
                .collect(),
            next_page_token_digest: next_page_token.as_ref().map(|token| token.digest().clone()),
            response_bytes,
            provider_revision: provider_revision.clone(),
        });
        Ok(Self {
            page_number,
            resources,
            next_page_token,
            response_bytes,
            provider_revision,
            page_digest,
        })
    }

    pub fn validate_for(
        &self,
        request: &SearchRequest,
    ) -> Result<(), AwsResourceExplorerProviderError> {
        if self.page_number == 0
            || self.page_number > request.max_pages
            || self.resources.len() > MAX_RESOURCES
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_page_token
                .as_ref()
                .is_some_and(|token| token.binding_digest() != &request.pagination_binding_digest())
            || self.page_digest
                != serialized_digest(&PageDigestMaterial {
                    operation: AwsResourceExplorerOperation::Search,
                    page_number: self.page_number,
                    item_digests: self
                        .resources
                        .iter()
                        .map(ResourceInventoryItem::digest)
                        .collect(),
                    next_page_token_digest: self
                        .next_page_token
                        .as_ref()
                        .map(|token| token.digest().clone()),
                    response_bytes: self.response_bytes,
                    provider_revision: self.provider_revision.clone(),
                })
        {
            return Err(AwsResourceExplorerProviderError::PageMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListIndexesPage {
    pub page_number: u16,
    pub indexes: Vec<IndexInventoryItem>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub provider_revision: String,
    pub page_digest: Digest,
}

impl ListIndexesPage {
    pub fn new(
        request: &ListIndexesRequest,
        page_number: u16,
        indexes: Vec<IndexInventoryItem>,
        next_page_token: Option<OpaquePageToken>,
        response_bytes: usize,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "page number",
            });
        }
        if indexes.len() > MAX_INDEXES || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::TooMany {
                field: "ListIndexes page",
            });
        }
        let next_page_token = next_page_token
            .map(|token| token.bind(request.pagination_binding_digest()))
            .transpose()?;
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() || provider_revision.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::Invalid {
                field: "provider revision",
            });
        }
        let page_digest = serialized_digest(&PageDigestMaterial {
            operation: AwsResourceExplorerOperation::ListIndexes,
            page_number,
            item_digests: indexes.iter().map(IndexInventoryItem::digest).collect(),
            next_page_token_digest: next_page_token.as_ref().map(|token| token.digest().clone()),
            response_bytes,
            provider_revision: provider_revision.clone(),
        });
        Ok(Self {
            page_number,
            indexes,
            next_page_token,
            response_bytes,
            provider_revision,
            page_digest,
        })
    }

    pub fn validate_for(
        &self,
        request: &ListIndexesRequest,
    ) -> Result<(), AwsResourceExplorerProviderError> {
        if self.page_number == 0
            || self.page_number > request.max_pages
            || self.indexes.len() > MAX_INDEXES
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_page_token
                .as_ref()
                .is_some_and(|token| token.binding_digest() != &request.pagination_binding_digest())
            || self.page_digest
                != serialized_digest(&PageDigestMaterial {
                    operation: AwsResourceExplorerOperation::ListIndexes,
                    page_number: self.page_number,
                    item_digests: self
                        .indexes
                        .iter()
                        .map(IndexInventoryItem::digest)
                        .collect(),
                    next_page_token_digest: self
                        .next_page_token
                        .as_ref()
                        .map(|token| token.digest().clone()),
                    response_bytes: self.response_bytes,
                    provider_revision: self.provider_revision.clone(),
                })
        {
            return Err(AwsResourceExplorerProviderError::PageMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PageDigestMaterial {
    operation: AwsResourceExplorerOperation,
    page_number: u16,
    item_digests: Vec<Digest>,
    next_page_token_digest: Option<Digest>,
    response_bytes: usize,
    provider_revision: String,
}

pub trait AwsResourceExplorerTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn search(&mut self, request: &SearchRequest) -> Result<SearchPage, TransportError>;

    fn list_indexes(
        &mut self,
        request: &ListIndexesRequest,
    ) -> Result<ListIndexesPage, TransportError>;
}

#[derive(Debug)]
pub struct AwsResourceExplorerProvider<T: AwsResourceExplorerTransport> {
    definition: AwsResourceExplorerProviderDefinition,
    transport: T,
}

impl<T: AwsResourceExplorerTransport> AwsResourceExplorerProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let definition = AwsResourceExplorerProviderDefinition::new(transport.provenance())?;
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &AwsResourceExplorerProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        self.definition.digest()
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn search(
        &mut self,
        request: &SearchRequest,
    ) -> Result<SearchPage, AwsResourceExplorerProviderError> {
        let page = self
            .transport
            .search(request)
            .map_err(AwsResourceExplorerProviderError::Transport)?;
        page.validate_for(request)?;
        Ok(page)
    }

    pub fn list_indexes(
        &mut self,
        request: &ListIndexesRequest,
    ) -> Result<ListIndexesPage, AwsResourceExplorerProviderError> {
        let page = self
            .transport
            .list_indexes(request)
            .map_err(AwsResourceExplorerProviderError::Transport)?;
        page.validate_for(request)?;
        Ok(page)
    }

    pub fn parse_search_page(
        request: &SearchRequest,
        page_number: u16,
        body: &[u8],
    ) -> Result<SearchPage, AwsResourceExplorerProviderError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(AwsResourceExplorerProviderError::ResponseTooLarge);
        }
        let parsed: Value = serde_json::from_slice(body)
            .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?;
        let resources = parsed
            .get("Resources")
            .and_then(Value::as_array)
            .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?
            .iter()
            .map(|resource| parse_resource(resource, request.region.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let next_page_token = parsed
            .get("NextToken")
            .and_then(Value::as_str)
            .map(|token| OpaquePageToken::new(token, request.pagination_binding_digest()))
            .transpose()
            .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?;
        SearchPage::new(
            request,
            page_number,
            resources,
            next_page_token,
            body.len(),
            AWS_RESOURCE_EXPLORER_API_REVISION,
        )
        .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)
    }

    pub fn parse_list_indexes_page(
        request: &ListIndexesRequest,
        page_number: u16,
        body: &[u8],
    ) -> Result<ListIndexesPage, AwsResourceExplorerProviderError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(AwsResourceExplorerProviderError::ResponseTooLarge);
        }
        let parsed: Value = serde_json::from_slice(body)
            .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?;
        let indexes = parsed
            .get("Indexes")
            .and_then(Value::as_array)
            .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?
            .iter()
            .map(|index| parse_index(index, request.region.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let next_page_token = parsed
            .get("NextToken")
            .and_then(Value::as_str)
            .map(|token| OpaquePageToken::new(token, request.pagination_binding_digest()))
            .transpose()
            .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?;
        ListIndexesPage::new(
            request,
            page_number,
            indexes,
            next_page_token,
            body.len(),
            AWS_RESOURCE_EXPLORER_API_REVISION,
        )
        .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)
    }
}

fn parse_resource(
    value: &Value,
    fallback_region: AwsRegion,
) -> Result<ResourceInventoryItem, AwsResourceExplorerProviderError> {
    let object = value
        .as_object()
        .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?;
    let resource_id = object
        .get("Arn")
        .and_then(Value::as_str)
        .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?;
    let resource_type = object
        .get("ResourceType")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let region = object
        .get("Region")
        .and_then(Value::as_str)
        .and_then(|value| AwsRegion::new(value).ok())
        .unwrap_or(fallback_region);
    let service = object
        .get("Service")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let scope = ResourceExplorerResource::new(
        resource_type.to_owned(),
        resource_id.to_owned(),
        region,
        crate::Revision::new(1).map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?,
    )
    .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?;
    let mut properties = Vec::new();
    if let Some(property_array) = object.get("Properties").and_then(Value::as_array) {
        if property_array.len() > MAX_PROPERTY_DIGESTS {
            return Err(AwsResourceExplorerProviderError::InvalidResponse);
        }
        for property in property_array {
            let property_object = property
                .as_object()
                .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?;
            let name = property_object
                .get("Name")
                .and_then(Value::as_str)
                .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?;
            let value = property_object
                .get("Data")
                .or_else(|| property_object.get("Value"))
                .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?;
            let value_bytes = serde_json::to_vec(value)
                .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?;
            properties.push(
                PropertyDigest::new(name, value_bytes)
                    .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?,
            );
        }
    }
    ResourceInventoryItem::from_scope(&scope, service.to_owned(), properties)
        .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)
}

fn parse_index(
    value: &Value,
    fallback_region: AwsRegion,
) -> Result<IndexInventoryItem, AwsResourceExplorerProviderError> {
    let object = value
        .as_object()
        .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?;
    let index_id = object
        .get("Arn")
        .and_then(Value::as_str)
        .ok_or(AwsResourceExplorerProviderError::InvalidResponse)?;
    let region = object
        .get("Region")
        .and_then(Value::as_str)
        .and_then(|value| AwsRegion::new(value).ok())
        .unwrap_or(fallback_region);
    let state = object
        .get("State")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let index_type = object
        .get("Type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    IndexInventoryItem::from_raw(
        index_id.to_owned(),
        region,
        state.to_owned(),
        index_type.to_owned(),
        crate::Revision::new(1).map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)?,
    )
    .map_err(|_| AwsResourceExplorerProviderError::InvalidResponse)
}

#[derive(Clone, Debug)]
pub struct RecordingAwsResourceExplorerTransport {
    provenance: TransportProvenance,
    search_responses: VecDeque<Result<SearchPage, TransportError>>,
    list_indexes_responses: VecDeque<Result<ListIndexesPage, TransportError>>,
    search_requests: Vec<SearchRequest>,
    list_indexes_requests: Vec<ListIndexesRequest>,
}

impl Default for RecordingAwsResourceExplorerTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl RecordingAwsResourceExplorerTransport {
    #[must_use]
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            search_responses: VecDeque::new(),
            list_indexes_responses: VecDeque::new(),
            search_requests: Vec::new(),
            list_indexes_requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self::new(TransportProvenance::Fixture)
    }

    pub fn push_search_response(&mut self, response: Result<SearchPage, TransportError>) {
        self.search_responses.push_back(response);
    }

    pub fn push_list_indexes_response(
        &mut self,
        response: Result<ListIndexesPage, TransportError>,
    ) {
        self.list_indexes_responses.push_back(response);
    }

    #[must_use]
    pub fn search_requests(&self) -> &[SearchRequest] {
        &self.search_requests
    }

    #[must_use]
    pub fn list_indexes_requests(&self) -> &[ListIndexesRequest] {
        &self.list_indexes_requests
    }

    #[must_use]
    pub fn remaining_search_responses(&self) -> usize {
        self.search_responses.len()
    }

    #[must_use]
    pub fn remaining_list_indexes_responses(&self) -> usize {
        self.list_indexes_responses.len()
    }
}

impl AwsResourceExplorerTransport for RecordingAwsResourceExplorerTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn search(&mut self, request: &SearchRequest) -> Result<SearchPage, TransportError> {
        self.search_requests.push(request.clone());
        self.search_responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }

    fn list_indexes(
        &mut self,
        request: &ListIndexesRequest,
    ) -> Result<ListIndexesPage, TransportError> {
        self.list_indexes_requests.push(request.clone());
        self.list_indexes_responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }
}

#[derive(Clone, Debug)]
pub struct FakeAwsResourceExplorerTransport {
    provenance: TransportProvenance,
    resources: Vec<ResourceInventoryItem>,
    indexes: Vec<IndexInventoryItem>,
    search_requests: Vec<SearchRequest>,
    list_indexes_requests: Vec<ListIndexesRequest>,
}

impl FakeAwsResourceExplorerTransport {
    #[must_use]
    pub fn new(
        resources: impl IntoIterator<Item = ResourceInventoryItem>,
        indexes: impl IntoIterator<Item = IndexInventoryItem>,
    ) -> Self {
        Self {
            provenance: TransportProvenance::Fixture,
            resources: resources.into_iter().collect(),
            indexes: indexes.into_iter().collect(),
            search_requests: Vec::new(),
            list_indexes_requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    #[must_use]
    pub fn search_requests(&self) -> &[SearchRequest] {
        &self.search_requests
    }

    #[must_use]
    pub fn list_indexes_requests(&self) -> &[ListIndexesRequest] {
        &self.list_indexes_requests
    }
}

impl AwsResourceExplorerTransport for FakeAwsResourceExplorerTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn search(&mut self, request: &SearchRequest) -> Result<SearchPage, TransportError> {
        self.search_requests.push(request.clone());
        SearchPage::new(
            request,
            1,
            self.resources.clone(),
            None,
            self.resources.len().saturating_mul(128),
            AWS_RESOURCE_EXPLORER_API_REVISION,
        )
        .map_err(|_| TransportError::MalformedResponse)
    }

    fn list_indexes(
        &mut self,
        request: &ListIndexesRequest,
    ) -> Result<ListIndexesPage, TransportError> {
        self.list_indexes_requests.push(request.clone());
        ListIndexesPage::new(
            request,
            1,
            self.indexes.clone(),
            None,
            self.indexes.len().saturating_mul(96),
            AWS_RESOURCE_EXPLORER_API_REVISION,
        )
        .map_err(|_| TransportError::MalformedResponse)
    }
}

pub type FixtureAwsResourceExplorerTransport = RecordingAwsResourceExplorerTransport;
pub type LoopbackAwsResourceExplorerTransport = FakeAwsResourceExplorerTransport;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvAwsResourceExplorerTransport;

impl AwsResourceExplorerTransport for BlockedEnvAwsResourceExplorerTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn search(&mut self, _request: &SearchRequest) -> Result<SearchPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn list_indexes(
        &mut self,
        _request: &ListIndexesRequest,
    ) -> Result<ListIndexesPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub type AwsResourceExplorerProviderErrorKind = TransportError;
pub type AwsResourceExplorerProviderIdentity = AwsResourceExplorerProviderDefinition;

/// Kept as a narrow helper for callers that need to state the operation's
/// required permission without introducing an arbitrary IAM role model.
#[must_use]
pub const fn required_permission(operation: AwsResourceExplorerOperation) -> PermissionAction {
    operation.permission()
}

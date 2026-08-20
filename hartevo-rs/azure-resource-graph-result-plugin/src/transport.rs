//! Bounded Azure Resource Graph transport seams.
//!
//! The public request contains only an allowlisted AST projection and
//! digests. It has no arbitrary KQL string and no mutation method. Fixture,
//! recording, loopback, and BLOCKED_ENV transports are deliberately explicit
//! about their provenance and never claim native or Connected authority.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::model::{
    AzureResourceGraphPagePayload, AzureResourceGraphQueryAst, AzureResourceGraphResourcePayload,
    AzureResourceGraphResponseReceipt, AzureResourceGraphScope, AzureResourceProperty,
    AzureResourceType, Digest, ProviderRevision, TransportProvenance, canonical_digest,
    sha256_digest,
};
use crate::provider::EntraAccessToken;
use crate::{
    AZURE_RESOURCE_GRAPH_API_ORIGIN, AZURE_RESOURCE_GRAPH_API_PATH,
    AZURE_RESOURCE_GRAPH_API_VERSION, AZURE_RESOURCE_GRAPH_PROVIDER_REVISION,
    AzureResourceGraphError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AzureResourceGraphHttpMethod {
    Post,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AzureResourceGraphEndpoint {
    Resources,
}

impl AzureResourceGraphEndpoint {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Resources => AZURE_RESOURCE_GRAPH_API_PATH,
        }
    }

    #[must_use]
    pub const fn path_and_query(self) -> &'static str {
        match self {
            Self::Resources => {
                "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ContinuationToken {
    value: String,
    binding_digest: Digest,
    page: u16,
}

impl ContinuationToken {
    pub fn new(
        value: impl Into<String>,
        binding_digest: Digest,
        page: u16,
    ) -> Result<Self, AzureResourceGraphError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
            return Err(AzureResourceGraphError::InvalidInput(
                "continuation token is empty, too long, or contains control characters".to_owned(),
            ));
        }
        if page == 0 || binding_digest.as_str().len() != 64 {
            return Err(AzureResourceGraphError::ContinuationRejected);
        }
        Ok(Self {
            value,
            binding_digest,
            page,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    #[must_use]
    pub const fn page(&self) -> u16 {
        self.page
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "azure-resource-graph-continuation/v1|{}|{}|{}",
                self.value, self.binding_digest, self.page
            )
            .as_bytes(),
        )
    }
}

impl fmt::Debug for ContinuationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuationToken")
            .field("value", &"<redacted>")
            .field("binding_digest", &self.binding_digest)
            .field("page", &self.page)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBounds {
    pub max_response_bytes: usize,
    pub max_resources: usize,
    pub max_pages: u16,
    pub page_size: u16,
}

impl Default for RequestBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: crate::MAX_RESPONSE_BYTES,
            max_resources: crate::MAX_RESOURCES,
            max_pages: crate::MAX_PAGES,
            page_size: crate::PAGE_SIZE,
        }
    }
}

impl RequestBounds {
    pub fn new(
        max_response_bytes: usize,
        max_resources: usize,
        max_pages: u16,
        page_size: u16,
    ) -> Result<Self, AzureResourceGraphError> {
        if max_response_bytes == 0
            || max_response_bytes > crate::MAX_RESPONSE_BYTES
            || max_resources == 0
            || max_resources > crate::MAX_RESOURCES
            || max_pages == 0
            || max_pages > crate::MAX_PAGES
            || page_size == 0
            || page_size > crate::PAGE_SIZE
        {
            return Err(AzureResourceGraphError::InvalidInput(
                "Azure Resource Graph request bounds exceed the Layer-1 maximum".to_owned(),
            ));
        }
        Ok(Self {
            max_response_bytes,
            max_resources,
            max_pages,
            page_size,
        })
    }
}

/// The safe provider request. Resource type and property codes are generated
/// from the typed AST; there is intentionally no query or KQL text field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureResourceGraphHttpRequest {
    pub method: AzureResourceGraphHttpMethod,
    pub endpoint: AzureResourceGraphEndpoint,
    pub api_version: String,
    pub scope: crate::AzureResourceGraphTarget,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub query_digest: Digest,
    pub resource_type_codes: Vec<String>,
    pub property_codes: Vec<String>,
    pub page: u16,
    pub page_size: u16,
    pub continuation_digest: Option<Digest>,
    pub max_response_bytes: usize,
    continuation: Option<ContinuationToken>,
}

impl AzureResourceGraphHttpRequest {
    pub fn new(
        scope: &AzureResourceGraphScope,
        registration_digest: Digest,
        query: &AzureResourceGraphQueryAst,
        page: u16,
        continuation: Option<ContinuationToken>,
        bounds: RequestBounds,
    ) -> Result<Self, AzureResourceGraphError> {
        if page == 0 || page > bounds.max_pages || query.page_size != bounds.page_size {
            return Err(AzureResourceGraphError::InvalidInput(
                "request page or page size is outside the registered bounds".to_owned(),
            ));
        }
        query.validate()?;
        scope.validate()?;
        if query.digest() != scope.query_digest() {
            return Err(AzureResourceGraphError::RegistrationDrift(
                "query AST does not match the registered scope".to_owned(),
            ));
        }
        let continuation_digest = continuation.as_ref().map(ContinuationToken::digest);
        let request = Self {
            method: AzureResourceGraphHttpMethod::Post,
            endpoint: AzureResourceGraphEndpoint::Resources,
            api_version: AZURE_RESOURCE_GRAPH_API_VERSION.to_owned(),
            scope: query.target.clone(),
            scope_digest: scope.scope_digest().clone(),
            registration_digest,
            query_digest: query.digest(),
            resource_type_codes: query.resource_type_codes(),
            property_codes: query.property_codes(),
            page,
            page_size: query.page_size,
            continuation_digest,
            max_response_bytes: bounds.max_response_bytes,
            continuation,
        };
        if !request.is_allowlisted() {
            return Err(AzureResourceGraphError::InvalidInput(
                "request is outside the Azure Resource Graph allowlist".to_owned(),
            ));
        }
        Ok(request)
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "{AZURE_RESOURCE_GRAPH_API_ORIGIN}{}",
            self.endpoint.path_and_query()
        )
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.method,
            self.endpoint,
            &self.api_version,
            &self.scope_digest,
            &self.registration_digest,
            &self.query_digest,
            &self.resource_type_codes,
            &self.property_codes,
            self.page,
            self.page_size,
            &self.continuation_digest,
            self.max_response_bytes,
        ))
    }

    #[must_use]
    pub fn continuation(&self) -> Option<&ContinuationToken> {
        self.continuation.as_ref()
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == AzureResourceGraphHttpMethod::Post
            && self.endpoint == AzureResourceGraphEndpoint::Resources
            && self.api_version == AZURE_RESOURCE_GRAPH_API_VERSION
            && self
                .path_and_query()
                .starts_with(AZURE_RESOURCE_GRAPH_API_ORIGIN)
            && self.page > 0
            && self.page_size > 0
            && self.page_size <= crate::PAGE_SIZE
            && self.resource_type_codes.iter().all(|value| {
                AzureResourceType::parse(value).is_ok()
                    && AzureResourceType::ALL
                        .iter()
                        .any(|kind| kind.code() == value)
            })
            && self.property_codes.iter().all(|value| {
                AzureResourceProperty::parse(value).is_ok()
                    && AzureResourceProperty::ALL
                        .iter()
                        .any(|property| property.code() == value)
            })
            && self
                .continuation_digest
                .as_ref()
                .is_none_or(|digest| digest.as_str().len() == 64)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureResourceGraphTransportError {
    #[error("Azure Resource Graph credential is unavailable")]
    CredentialUnavailable,
    #[error("BLOCKED_ENV: Azure Resource Graph native transport is disabled")]
    BlockedEnv,
    #[error("Azure Resource Graph request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Azure Resource Graph response could not be decoded: {0}")]
    Decode(String),
    #[error("Azure Resource Graph response exceeded the byte bound: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Azure Resource Graph transport timed out: {0}")]
    Timeout(String),
    #[error("Azure Resource Graph transport failed: {0}")]
    Transport(String),
}

/// Authenticated transport for exactly one bounded Resource Graph POST seam.
pub trait AzureResourceGraphTransport: fmt::Debug {
    fn execute(
        &mut self,
        token: &EntraAccessToken,
        request: &AzureResourceGraphHttpRequest,
    ) -> Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError>;

    fn provenance(&self) -> TransportProvenance;

    fn is_native(&self) -> bool {
        false
    }

    fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureResourceGraphHttpResponse {
    body: AzureResourceGraphPagePayload,
    receipt: AzureResourceGraphResponseReceipt,
    continuation: Option<ContinuationToken>,
}

impl fmt::Debug for AzureResourceGraphHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureResourceGraphHttpResponse")
            .field("status", &self.receipt.status)
            .field("response_size", &self.receipt.response_size)
            .field("response_digest", &self.receipt.response_digest)
            .field("resource_count", &self.body.resources.len())
            .field("continuation_present", &self.continuation.is_some())
            .finish()
    }
}

impl AzureResourceGraphHttpResponse {
    pub fn from_payloads(
        request: &AzureResourceGraphHttpRequest,
        status: u16,
        resources: Vec<AzureResourceGraphResourcePayload>,
        partial: bool,
        truncated: bool,
        total_count: Option<u64>,
        continuation: Option<ContinuationToken>,
    ) -> Result<Self, AzureResourceGraphTransportError> {
        let body = AzureResourceGraphPagePayload {
            resources,
            partial,
            truncated,
            total_count,
        };
        Self::new(request, status, body, continuation)
    }

    pub fn for_status(
        request: &AzureResourceGraphHttpRequest,
        status: u16,
    ) -> Result<Self, AzureResourceGraphTransportError> {
        Self::from_payloads(request, status, Vec::new(), false, false, None, None)
    }

    /// Decode the ordinary Resource Graph response shape used by fixtures.
    /// Raw JSON remains in this constructor's stack frame and is represented
    /// after construction only by typed payloads and a digest receipt.
    pub fn json(
        request: &AzureResourceGraphHttpRequest,
        status: u16,
        value: &Value,
    ) -> Result<Self, AzureResourceGraphTransportError> {
        let data = value
            .get("data")
            .or_else(|| value.get("resources"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let resources = data
            .iter()
            .map(parse_resource_payload)
            .collect::<Result<Vec<_>, _>>()?;
        let continuation = value
            .get("$skipToken")
            .or_else(|| value.get("skipToken"))
            .and_then(Value::as_str)
            .map(|token| {
                ContinuationToken::new(
                    token,
                    crate::provider::continuation_binding_digest(
                        &request.registration_digest,
                        &request.scope_digest,
                        &request.query_digest,
                        request.page + 1,
                    ),
                    request.page + 1,
                )
            })
            .transpose()
            .map_err(|error| AzureResourceGraphTransportError::InvalidRequest(error.to_string()))?;
        let partial = value
            .get("resultTruncated")
            .or_else(|| value.get("partial"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let total_count = value.get("count").and_then(Value::as_u64);
        Self::from_payloads(
            request,
            status,
            resources,
            partial,
            false,
            total_count,
            continuation,
        )
    }

    fn new(
        request: &AzureResourceGraphHttpRequest,
        status: u16,
        body: AzureResourceGraphPagePayload,
        continuation: Option<ContinuationToken>,
    ) -> Result<Self, AzureResourceGraphTransportError> {
        let raw = raw_page_json(&body, continuation.as_ref());
        let bytes = serde_json::to_vec(&raw)
            .map_err(|error| AzureResourceGraphTransportError::Decode(error.to_string()))?;
        if bytes.len() > request.max_response_bytes {
            return Err(AzureResourceGraphTransportError::ResponseTooLarge { size: bytes.len() });
        }
        let provider_revision = ProviderRevision::parse(AZURE_RESOURCE_GRAPH_PROVIDER_REVISION)
            .map_err(|error| AzureResourceGraphTransportError::InvalidRequest(error.to_string()))?;
        let receipt = AzureResourceGraphResponseReceipt {
            request_digest: request.digest(),
            response_digest: sha256_digest(&bytes),
            status,
            response_size: bytes.len(),
            provider_revision,
            page: request.page,
            continuation_digest: continuation.as_ref().map(ContinuationToken::digest),
            raw_provider_payload: false,
            raw_properties: false,
            raw_tags: false,
            raw_secrets: false,
            partial: body.partial,
            truncated: body.truncated,
        };
        Ok(Self {
            body,
            receipt,
            continuation,
        })
    }

    #[must_use]
    pub fn body(&self) -> &AzureResourceGraphPagePayload {
        &self.body
    }

    #[must_use]
    pub fn receipt(&self) -> &AzureResourceGraphResponseReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn continuation(&self) -> Option<&ContinuationToken> {
        self.continuation.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAzureResourceGraphTransport {
    responses: VecDeque<Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError>>,
    requests: Vec<AzureResourceGraphHttpRequest>,
    provenance: TransportProvenance,
}

impl RecordingAzureResourceGraphTransport {
    pub fn new(
        responses: impl IntoIterator<
            Item = Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError>,
        >,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Recording,
        }
    }

    pub fn recording(
        responses: impl IntoIterator<
            Item = Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError>,
        >,
    ) -> Self {
        Self::new(responses)
    }

    pub fn fixture(
        responses: impl IntoIterator<
            Item = Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError>,
        >,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Fixture,
        }
    }

    pub fn loopback(
        responses: impl IntoIterator<
            Item = Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError>,
        >,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Loopback,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(
        &mut self,
        response: Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError>,
    ) {
        self.responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[AzureResourceGraphHttpRequest] {
        &self.requests
    }

    #[must_use]
    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl AzureResourceGraphTransport for RecordingAzureResourceGraphTransport {
    fn execute(
        &mut self,
        token: &EntraAccessToken,
        request: &AzureResourceGraphHttpRequest,
    ) -> Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError> {
        if token.as_str().trim().is_empty() {
            return Err(AzureResourceGraphTransportError::CredentialUnavailable);
        }
        if !request.is_allowlisted() {
            return Err(AzureResourceGraphTransportError::InvalidRequest(
                "recording request is not allowlisted".to_owned(),
            ));
        }
        self.requests.push(request.clone());
        self.responses.pop_front().ok_or_else(|| {
            AzureResourceGraphTransportError::Transport(
                "recording response queue exhausted".to_owned(),
            )
        })?
    }

    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

pub type FakeAzureResourceGraphTransport = RecordingAzureResourceGraphTransport;
pub type LoopbackAzureResourceGraphTransport = RecordingAzureResourceGraphTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AzureResourceGraphTransport for BlockedEnvTransport {
    fn execute(
        &mut self,
        _token: &EntraAccessToken,
        _request: &AzureResourceGraphHttpRequest,
    ) -> Result<AzureResourceGraphHttpResponse, AzureResourceGraphTransportError> {
        Err(AzureResourceGraphTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

fn raw_page_json(
    body: &AzureResourceGraphPagePayload,
    continuation: Option<&ContinuationToken>,
) -> Value {
    let data = body
        .resources
        .iter()
        .map(|resource| {
            let properties = resource
                .properties
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Map<_, _>>();
            json!({
                "id": resource.id,
                "type": resource.resource_type,
                "location": resource.location,
                "subscriptionId": resource.subscription_id,
                "resourceGroup": resource.resource_group,
                "kind": resource.kind,
                "properties": properties,
            })
        })
        .collect::<Vec<_>>();
    let mut result = json!({
        "data": data,
        "count": body.total_count,
        "resultTruncated": body.partial || body.truncated,
    });
    if let Some(token) = continuation {
        result["$skipToken"] = Value::String(token.as_str().to_owned());
    }
    result
}

fn parse_resource_payload(
    value: &Value,
) -> Result<AzureResourceGraphResourcePayload, AzureResourceGraphTransportError> {
    let object = value.as_object().ok_or_else(|| {
        AzureResourceGraphTransportError::Decode("resource is not an object".to_owned())
    })?;
    let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
        AzureResourceGraphTransportError::Decode("resource id is missing".to_owned())
    })?;
    let resource_type = object.get("type").and_then(Value::as_str).ok_or_else(|| {
        AzureResourceGraphTransportError::Decode("resource type is missing".to_owned())
    })?;
    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    AzureResourceGraphResourcePayload::new(
        id,
        resource_type,
        optional_string(object.get("location")),
        optional_string(object.get("subscriptionId")),
        optional_string(object.get("resourceGroup")),
        optional_string(object.get("kind")),
        properties,
    )
    .map_err(|error| AzureResourceGraphTransportError::Decode(error.to_string()))
}

fn optional_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

#[allow(dead_code)]
fn _scope_is_typed(scope: &AzureResourceGraphScope) -> bool {
    scope.validate().is_ok()
}

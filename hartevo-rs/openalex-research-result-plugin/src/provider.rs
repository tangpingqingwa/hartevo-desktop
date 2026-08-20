use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Digest, MAX_DIAGNOSTIC_BYTES, MAX_RESPONSE_BYTES, MAX_RESULTS, ModelError,
    OpenAlexAuthorProjection, OpenAlexCitationProjection, OpenAlexConceptProjection,
    OpenAlexEntity, OpenAlexInstitutionProjection, OpenAlexOperation, OpenAlexPermission,
    OpenAlexRegistration, OpenAlexResearchScope, OpenAlexWorkProjection, RateLimitReceipt,
    SecretReference, TransportProvenance, canonical_digest, sha256_digest,
};

pub const OPENALEX_BASE_URL: &str = "https://api.openalex.org";
pub const OPENALEX_PROVIDER_ID: &str = "openalex.metadata.rest";
pub const OPENALEX_PROVIDER_VERSION: &str = "1.0.0";
pub const OPENALEX_API_REVISION: &str = "openalex-rest-api-v1";
pub const OPENALEX_METADATA_PERMISSION: &str = "metadata.read";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OpenAlexHttpMethod {
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub base_url: String,
    pub allowlisted_paths: Vec<String>,
    pub required_permission: String,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: usize,
    pub max_results: usize,
    pub native: bool,
    pub connected: bool,
}

impl Default for OpenAlexProviderDefinition {
    fn default() -> Self {
        Self {
            id: OPENALEX_PROVIDER_ID.to_owned(),
            version: OPENALEX_PROVIDER_VERSION.to_owned(),
            api_revision: OPENALEX_API_REVISION.to_owned(),
            base_url: OPENALEX_BASE_URL.to_owned(),
            allowlisted_paths: vec![
                "/works".to_owned(),
                "/works/{id}".to_owned(),
                "/authors".to_owned(),
                "/authors/{id}".to_owned(),
                "/institutions".to_owned(),
                "/institutions/{id}".to_owned(),
                "/concepts".to_owned(),
                "/concepts/{id}".to_owned(),
                "/works?filter=cites:{id}".to_owned(),
                "/works?filter=cited_by:{id}".to_owned(),
            ],
            required_permission: OPENALEX_METADATA_PERMISSION.to_owned(),
            max_requests_per_minute: crate::MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_results: MAX_RESULTS,
            native: false,
            connected: false,
        }
    }
}

impl OpenAlexProviderDefinition {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub(crate) fn validate(&self) -> Result<(), OpenAlexProviderError> {
        if self.id != OPENALEX_PROVIDER_ID
            || self.version != OPENALEX_PROVIDER_VERSION
            || self.api_revision != OPENALEX_API_REVISION
            || self.base_url != OPENALEX_BASE_URL
            || self.allowlisted_paths != OpenAlexProviderDefinition::default().allowlisted_paths
            || self.required_permission != OPENALEX_METADATA_PERMISSION
            || self.max_requests_per_minute != crate::MAX_REQUESTS_PER_MINUTE
            || self.max_response_bytes != MAX_RESPONSE_BYTES
            || self.max_results != MAX_RESULTS
            || self.native
            || self.connected
        {
            return Err(OpenAlexProviderError::ProviderDefinitionDrift);
        }
        Ok(())
    }
}

/// A request contains only fixed path templates and digests. It is a
/// planning/recording seam, not a native HTTP request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexRequest {
    pub method: OpenAlexHttpMethod,
    pub base_url: String,
    pub path_template: String,
    pub entity: OpenAlexEntity,
    pub operation: OpenAlexOperation,
    pub query_digest: Digest,
    pub selector_digest: Digest,
    pub filter_digest: Digest,
    pub page_size: usize,
    pub cursor_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub scope_revision: u64,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub idempotency_digest: Digest,
    pub request_digest: Digest,
}

impl OpenAlexRequest {
    pub(crate) fn new(
        scope: &OpenAlexResearchScope,
        consent: &crate::ConsentScope,
        secret_reference: &SecretReference,
        registration: &OpenAlexRegistration,
    ) -> Self {
        let query = scope.query();
        let cursor_digest = scope
            .cursor()
            .map(|cursor| cursor.cursor_digest().to_owned());
        let idempotency_digest = canonical_digest(&(
            scope.digest(),
            query.digest(),
            &cursor_digest,
            scope.revision(),
            consent.digest(),
            secret_reference.digest(),
            &registration.registration_digest,
        ));
        let mut request = Self {
            method: OpenAlexHttpMethod::Get,
            base_url: OPENALEX_BASE_URL.to_owned(),
            path_template: path_template(query.entity(), query.operation()),
            entity: query.entity(),
            operation: query.operation(),
            query_digest: query.digest(),
            selector_digest: query.selector_digest().to_owned(),
            filter_digest: query.filter_digest().to_owned(),
            page_size: scope.page_size(),
            cursor_digest,
            scope_digest: scope.digest(),
            scope_revision: scope.revision().get(),
            consent_digest: consent.digest(),
            secret_reference_digest: secret_reference.digest(),
            idempotency_digest,
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.method,
            &self.base_url,
            &self.path_template,
            self.entity,
            self.operation,
            &self.query_digest,
            &self.selector_digest,
            &self.filter_digest,
            self.page_size,
            &self.cursor_digest,
            &self.scope_digest,
            self.scope_revision,
            &self.consent_digest,
            &self.secret_reference_digest,
            &self.idempotency_digest,
        ))
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == OpenAlexHttpMethod::Get
            && self.base_url == OPENALEX_BASE_URL
            && path_is_allowlisted(self.entity, self.operation, &self.path_template)
            && (1..=MAX_RESULTS).contains(&self.page_size)
            && self.query_digest.len() == 64
            && self.selector_digest.len() == 64
            && self.filter_digest.len() == 64
            && self
                .cursor_digest
                .as_ref()
                .is_none_or(|value| value.len() == 64)
            && self.scope_digest.len() == 64
            && self.consent_digest.len() == 64
            && self.secret_reference_digest.len() == 64
            && self.idempotency_digest.len() == 64
    }
}

fn path_template(entity: OpenAlexEntity, operation: OpenAlexOperation) -> String {
    match operation {
        OpenAlexOperation::List => entity.path().to_owned(),
        OpenAlexOperation::Get => format!("{}/{{id}}", entity.path()),
        OpenAlexOperation::Cites => "/works?filter=cites:{id}".to_owned(),
        OpenAlexOperation::CitedBy => "/works?filter=cited_by:{id}".to_owned(),
    }
}

fn path_is_allowlisted(entity: OpenAlexEntity, operation: OpenAlexOperation, path: &str) -> bool {
    path == path_template(entity, operation)
        && match operation {
            OpenAlexOperation::List | OpenAlexOperation::Get => true,
            OpenAlexOperation::Cites | OpenAlexOperation::CitedBy => entity == OpenAlexEntity::Work,
        }
}

/// Raw JSON is retained only inside this provider response until parsing. Its
/// Debug and Serialize representations expose size/digest metadata, never
/// the body itself.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub rate_limit: RateLimitReceipt,
}

impl fmt::Debug for OpenAlexResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAlexResponse")
            .field("status", &self.status)
            .field("response_digest", &self.response_digest())
            .field("response_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl OpenAlexResponse {
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, RateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: RateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("OpenAlex fixture payload serializes");
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: RateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        sha256_digest(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OpenAlexTransportError {
    #[error("OpenAlex native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("OpenAlex transport timed out")]
    Timeout,
    #[error("OpenAlex transport failed without a native response")]
    ProviderUnknown,
}

/// Layer-1 transport seam. Implementations replay bounded data but this crate
/// never resolves a secret or opens native HTTPS.
pub trait OpenAlexTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &OpenAlexRequest,
    ) -> Result<OpenAlexResponse, OpenAlexTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureOpenAlexTransport {
    response: OpenAlexResponse,
}

impl FixtureOpenAlexTransport {
    #[must_use]
    pub fn new(response: OpenAlexResponse) -> Self {
        Self { response }
    }
}

impl OpenAlexTransport for FixtureOpenAlexTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &OpenAlexRequest,
    ) -> Result<OpenAlexResponse, OpenAlexTransportError> {
        Ok(self.response.clone())
    }
}

/// A named fake transport is kept as an alias for callers that use the
/// fixture seam as a unit-test fake. It has the same non-native provenance.
pub type FakeOpenAlexTransport = FixtureOpenAlexTransport;

#[derive(Clone, Debug)]
pub struct RecordingOpenAlexTransport {
    response: OpenAlexResponse,
    requests: Vec<OpenAlexRequest>,
}

impl RecordingOpenAlexTransport {
    #[must_use]
    pub fn new(response: OpenAlexResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[OpenAlexRequest] {
        &self.requests
    }
}

impl OpenAlexTransport for RecordingOpenAlexTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &OpenAlexRequest,
    ) -> Result<OpenAlexResponse, OpenAlexTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackOpenAlexTransport {
    response: OpenAlexResponse,
    requests: Vec<OpenAlexRequest>,
}

impl LoopbackOpenAlexTransport {
    #[must_use]
    pub fn new(response: OpenAlexResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[OpenAlexRequest] {
        &self.requests
    }
}

impl OpenAlexTransport for LoopbackOpenAlexTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &OpenAlexRequest,
    ) -> Result<OpenAlexResponse, OpenAlexTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvOpenAlexTransport;

impl OpenAlexTransport for BlockedEnvOpenAlexTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &OpenAlexRequest,
    ) -> Result<OpenAlexResponse, OpenAlexTransportError> {
        Err(OpenAlexTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OpenAlexProviderError {
    #[error("OpenAlex provider definition drifted")]
    ProviderDefinitionDrift,
    #[error("OpenAlex registration is revoked")]
    RegistrationRevoked,
    #[error("OpenAlex registration is stale or tampered")]
    RegistrationDrift,
    #[error("OpenAlex SecretReference is revoked")]
    SecretRevoked,
    #[error("OpenAlex metadata.read permission is missing")]
    MissingMetadataPermission,
    #[error("OpenAlex scope is stale or invalid")]
    ScopeMismatch,
    #[error("OpenAlex cursor is not bound to the query and revision")]
    CursorBindingMismatch,
    #[error("OpenAlex request is not allowlisted")]
    RequestNotAllowlisted,
    #[error("OpenAlex response exceeds the Layer-1 bound")]
    ResponseTooLarge {
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
    },
    #[error("OpenAlex response is malformed: {diagnostic}")]
    MalformedResponse {
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
        diagnostic: String,
    },
    #[error("OpenAlex transport is blocked by the environment")]
    BlockedEnv,
    #[error("OpenAlex transport timed out")]
    Timeout,
    #[error("OpenAlex provider is unavailable")]
    ProviderUnknown,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAlexProviderRead {
    pub status: u16,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
    pub rate_limit: RateLimitReceipt,
    pub provenance: TransportProvenance,
    pub entity: OpenAlexEntity,
    pub operation: OpenAlexOperation,
    pub query_digest: Digest,
    pub selector_digest: Digest,
    pub filter_digest: Digest,
    pub scope_revision: u64,
    pub cursor_digest: Option<Digest>,
    pub next_cursor: Option<crate::OpenAlexCursor>,
    pub total_results: Option<u64>,
    pub works: Vec<OpenAlexWorkProjection>,
    pub authors: Vec<OpenAlexAuthorProjection>,
    pub institutions: Vec<OpenAlexInstitutionProjection>,
    pub concepts: Vec<OpenAlexConceptProjection>,
    pub citations: Vec<OpenAlexCitationProjection>,
    pub partial: bool,
}

impl OpenAlexProviderRead {
    #[must_use]
    pub fn connected(&self) -> bool {
        self.provenance.connected()
    }

    #[must_use]
    pub fn native(&self) -> bool {
        self.provenance.native()
    }
}

#[derive(Clone, Debug)]
pub struct OpenAlexProvider<T: OpenAlexTransport> {
    transport: T,
    definition: OpenAlexProviderDefinition,
    scope: OpenAlexResearchScope,
    permission: OpenAlexPermission,
    secret_reference: SecretReference,
    registration: OpenAlexRegistration,
}

impl<T: OpenAlexTransport> OpenAlexProvider<T> {
    pub fn new(
        scope: OpenAlexResearchScope,
        permission: OpenAlexPermission,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, OpenAlexProviderError> {
        let definition = OpenAlexProviderDefinition::default();
        definition.validate()?;
        scope.validate()?;
        if !permission.allows_metadata_read() {
            return Err(OpenAlexProviderError::MissingMetadataPermission);
        }
        let registration =
            OpenAlexRegistration::new(&scope, &permission, &secret_reference, definition.digest());
        Ok(Self {
            transport,
            definition,
            scope,
            permission,
            secret_reference,
            registration,
        })
    }

    pub fn with_registration(
        scope: OpenAlexResearchScope,
        permission: OpenAlexPermission,
        secret_reference: SecretReference,
        registration: OpenAlexRegistration,
        transport: T,
    ) -> Result<Self, OpenAlexProviderError> {
        let mut provider = Self::new(scope, permission, secret_reference, transport)?;
        provider.registration = registration;
        provider.ensure_registration()?;
        Ok(provider)
    }

    #[must_use]
    pub fn definition(&self) -> &OpenAlexProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    #[must_use]
    pub fn scope(&self) -> &OpenAlexResearchScope {
        &self.scope
    }

    #[must_use]
    pub fn permission(&self) -> &OpenAlexPermission {
        &self.permission
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration(&self) -> &OpenAlexRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut OpenAlexRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn set_scope(&mut self, scope: OpenAlexResearchScope) -> Result<(), OpenAlexProviderError> {
        scope.validate()?;
        self.scope = scope;
        Ok(())
    }

    pub fn set_permission(
        &mut self,
        permission: OpenAlexPermission,
    ) -> Result<(), OpenAlexProviderError> {
        if !permission.allows_metadata_read() {
            return Err(OpenAlexProviderError::MissingMetadataPermission);
        }
        self.permission = permission;
        Ok(())
    }

    pub fn revoke_secret(&mut self) -> Result<(), OpenAlexProviderError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn restore_secret(&mut self) -> Result<(), OpenAlexProviderError> {
        self.secret_reference.restore()?;
        Ok(())
    }

    pub fn build_request(&self) -> Result<OpenAlexRequest, OpenAlexProviderError> {
        self.ensure_registration()?;
        if let Some(cursor) = self.scope.cursor()
            && (cursor.query_digest() != self.scope.query().digest()
                || cursor.scope_revision() != self.scope.revision())
        {
            return Err(OpenAlexProviderError::CursorBindingMismatch);
        }
        let request = OpenAlexRequest::new(
            &self.scope,
            self.scope.consent(),
            &self.secret_reference,
            &self.registration,
        );
        if !request.is_allowlisted() || request.request_digest != request.digest() {
            return Err(OpenAlexProviderError::RequestNotAllowlisted);
        }
        Ok(request)
    }

    pub fn read(&mut self) -> Result<OpenAlexProviderRead, OpenAlexProviderError> {
        let request = self.build_request()?;
        let provenance = self.transport.provenance();
        let response = match self.transport.execute(&request) {
            Ok(response) => response,
            Err(OpenAlexTransportError::BlockedEnv) => {
                return Err(OpenAlexProviderError::BlockedEnv);
            }
            Err(OpenAlexTransportError::Timeout) => return Err(OpenAlexProviderError::Timeout),
            Err(OpenAlexTransportError::ProviderUnknown) => {
                return Err(OpenAlexProviderError::ProviderUnknown);
            }
        };
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(OpenAlexProviderError::ResponseTooLarge {
                status: response.status,
                response_digest,
                response_bytes,
                rate_limit: response.rate_limit,
                provenance,
            });
        }
        let base = OpenAlexProviderRead {
            status: response.status,
            response_digest,
            response_bytes,
            request_digest: request.request_digest,
            idempotency_digest: request.idempotency_digest,
            rate_limit: response.rate_limit,
            provenance,
            entity: self.scope.query().entity(),
            operation: self.scope.query().operation(),
            query_digest: self.scope.query().digest(),
            selector_digest: self.scope.query().selector_digest().to_owned(),
            filter_digest: self.scope.query().filter_digest().to_owned(),
            scope_revision: self.scope.revision().get(),
            cursor_digest: self
                .scope
                .cursor()
                .map(|cursor| cursor.cursor_digest().to_owned()),
            next_cursor: None,
            total_results: None,
            works: Vec::new(),
            authors: Vec::new(),
            institutions: Vec::new(),
            concepts: Vec::new(),
            citations: Vec::new(),
            partial: false,
        };
        if !(200..300).contains(&response.status) {
            return Ok(OpenAlexProviderRead {
                total_results: (response.status == 404).then_some(0),
                ..base
            });
        }
        parse_success_response(response, base, self.scope.page_size())
    }

    fn ensure_registration(&self) -> Result<(), OpenAlexProviderError> {
        self.definition.validate()?;
        if !self.registration.state.is_active() {
            return Err(OpenAlexProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(OpenAlexProviderError::SecretRevoked);
        }
        if !self.permission.allows_metadata_read() {
            return Err(OpenAlexProviderError::MissingMetadataPermission);
        }
        self.scope
            .validate()
            .map_err(|_| OpenAlexProviderError::ScopeMismatch)?;
        if self.registration.scope_digest != self.scope.digest()
            || self.registration.consent_digest != self.scope.consent().digest()
        {
            return Err(OpenAlexProviderError::ScopeMismatch);
        }
        if self.registration.permission_digest != self.permission.digest() {
            return Err(OpenAlexProviderError::RegistrationDrift);
        }
        self.registration
            .validate(
                &self.scope,
                &self.permission,
                &self.secret_reference,
                &self.provider_digest(),
            )
            .map_err(|error| match error {
                ModelError::AlreadyRevoked => OpenAlexProviderError::RegistrationRevoked,
                ModelError::InvalidScope("secret reference revoked") => {
                    OpenAlexProviderError::SecretRevoked
                }
                _ => OpenAlexProviderError::RegistrationDrift,
            })
    }
}

#[allow(clippy::needless_pass_by_value)]
fn parse_success_response(
    response: OpenAlexResponse,
    mut base: OpenAlexProviderRead,
    page_size: usize,
) -> Result<OpenAlexProviderRead, OpenAlexProviderError> {
    let parsed: Value = serde_json::from_slice(&response.body)
        .map_err(|error| malformed(&response, &base, bounded_diagnostic(&error.to_string())))?;
    let (items, total_results, raw_next_cursor) = if base.operation == OpenAlexOperation::Get {
        if !parsed.is_object() || parsed.get("id").and_then(Value::as_str).is_none() {
            return Err(malformed(
                &response,
                &base,
                "singleton metadata item is missing id",
            ));
        }
        (vec![parsed], Some(1), None)
    } else {
        let items = parsed
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed(&response, &base, "missing results array"))?
            .clone();
        let meta = parsed
            .get("meta")
            .ok_or_else(|| malformed(&response, &base, "missing response meta"))?;
        let total_results = meta
            .get("count")
            .and_then(Value::as_u64)
            .unwrap_or(items.len() as u64);
        let raw_next_cursor = meta
            .get("next_cursor")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        (items, Some(total_results), raw_next_cursor)
    };

    let next_cursor = raw_next_cursor
        .map(|value| crate::OpenAlexCursor::new(value, &base.query_digest, base.scope_revision))
        .transpose()
        .map_err(|_| malformed(&response, &base, "next cursor exceeds the Layer-1 bound"))?;

    let mut partial = items.len() > page_size;
    let mut seen = BTreeSet::new();
    for item in items.iter().take(page_size) {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed(&response, &base, "metadata item is missing id"))?;
        let id_digest = sha256_digest(id.as_bytes());
        if !seen.insert(id_digest) {
            partial = true;
            continue;
        }
        match parse_item(&base, item) {
            Ok(ParsedItem::Work(work, citation)) => {
                base.works.push(work);
                if let Some(citation) = citation {
                    base.citations.push(citation);
                }
            }
            Ok(ParsedItem::Author(author)) => base.authors.push(author),
            Ok(ParsedItem::Institution(institution)) => base.institutions.push(institution),
            Ok(ParsedItem::Concept(concept)) => base.concepts.push(concept),
            Err(_) => partial = true,
        }
    }
    if !items.is_empty() && base_entity_count(&base) == 0 {
        return Err(malformed(
            &response,
            &base,
            "no bounded metadata item could be projected",
        ));
    }
    base.works
        .sort_by(|left, right| left.id_digest.cmp(&right.id_digest));
    base.authors
        .sort_by(|left, right| left.id_digest.cmp(&right.id_digest));
    base.institutions
        .sort_by(|left, right| left.id_digest.cmp(&right.id_digest));
    base.concepts
        .sort_by(|left, right| left.id_digest.cmp(&right.id_digest));
    base.citations.sort_by(|left, right| {
        (&left.citing_work_digest, &left.cited_work_digest)
            .cmp(&(&right.citing_work_digest, &right.cited_work_digest))
    });
    if total_results.is_some_and(|total| total > base_entity_count(&base) as u64) {
        partial = true;
    }
    if raw_next_cursor.is_some() && base_entity_count(&base) < page_size {
        partial = true;
    }
    base.response_digest = canonical_digest(&(
        base.status,
        total_results,
        &base.works,
        &base.authors,
        &base.institutions,
        &base.concepts,
        &base.citations,
        &next_cursor,
    ));
    base.total_results = total_results;
    base.next_cursor = next_cursor;
    base.partial = partial;
    Ok(base)
}

enum ParsedItem {
    Work(OpenAlexWorkProjection, Option<OpenAlexCitationProjection>),
    Author(OpenAlexAuthorProjection),
    Institution(OpenAlexInstitutionProjection),
    Concept(OpenAlexConceptProjection),
}

fn parse_item(base: &OpenAlexProviderRead, value: &Value) -> Result<ParsedItem, ModelError> {
    match base.entity {
        OpenAlexEntity::Work => {
            let work = parse_work_projection(value)?;
            let citation = if base.operation.is_citation() {
                let target = base.query_digest_for_selector();
                match base.operation {
                    OpenAlexOperation::Cites => Some(OpenAlexCitationProjection::from_digests(
                        work.id_digest.clone(),
                        target,
                    )?),
                    OpenAlexOperation::CitedBy => Some(OpenAlexCitationProjection::from_digests(
                        target,
                        work.id_digest.clone(),
                    )?),
                    _ => None,
                }
            } else {
                None
            };
            Ok(ParsedItem::Work(work, citation))
        }
        OpenAlexEntity::Author => Ok(ParsedItem::Author(parse_author_projection(value)?)),
        OpenAlexEntity::Institution => Ok(ParsedItem::Institution(parse_institution_projection(
            value,
        )?)),
        OpenAlexEntity::Concept => Ok(ParsedItem::Concept(parse_concept_projection(value)?)),
    }
}

impl OpenAlexProviderRead {
    fn query_digest_for_selector(&self) -> Digest {
        // The selector digest is the only target identity retained for a
        // citation query. The query digest itself also binds the operation.
        self.selector_digest.clone()
    }
}

fn parse_work_projection(value: &Value) -> Result<OpenAlexWorkProjection, ModelError> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or(ModelError::InvalidResponse)?;
    let doi = value.get("doi").and_then(Value::as_str);
    let title = value.get("title").and_then(Value::as_str);
    let work_type = value.get("type").and_then(Value::as_str);
    let publication_year = value
        .get("publication_year")
        .and_then(Value::as_u64)
        .and_then(|year| u16::try_from(year).ok());
    let cited_by_count = value.get("cited_by_count").and_then(Value::as_u64);
    let reference_count = value
        .get("referenced_works")
        .and_then(Value::as_array)
        .map(Vec::len)
        .map(|count| count as u64);
    let author_count = value
        .get("authorships")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let institution_count =
        value
            .get("authorships")
            .and_then(Value::as_array)
            .map_or(0, |authorships| {
                authorships
                    .iter()
                    .flat_map(|authorship| {
                        authorship
                            .get("institutions")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                    })
                    .count()
            });
    let concept_count = value
        .get("concepts")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    OpenAlexWorkProjection::from_metadata(
        id,
        doi,
        title,
        work_type,
        publication_year,
        cited_by_count,
        reference_count,
        author_count,
        institution_count,
        concept_count,
    )
}

fn parse_author_projection(value: &Value) -> Result<OpenAlexAuthorProjection, ModelError> {
    OpenAlexAuthorProjection::from_metadata(
        value
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ModelError::InvalidResponse)?,
        value.get("display_name").and_then(Value::as_str),
        value.get("works_count").and_then(Value::as_u64),
        value.get("cited_by_count").and_then(Value::as_u64),
        value
            .get("affiliations")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    )
}

fn parse_institution_projection(
    value: &Value,
) -> Result<OpenAlexInstitutionProjection, ModelError> {
    OpenAlexInstitutionProjection::from_metadata(
        value
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ModelError::InvalidResponse)?,
        value.get("display_name").and_then(Value::as_str),
        value.get("ror").and_then(Value::as_str),
        value.get("country_code").and_then(Value::as_str),
        value.get("works_count").and_then(Value::as_u64),
        value.get("cited_by_count").and_then(Value::as_u64),
    )
}

fn parse_concept_projection(value: &Value) -> Result<OpenAlexConceptProjection, ModelError> {
    OpenAlexConceptProjection::from_metadata(
        value
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ModelError::InvalidResponse)?,
        value.get("display_name").and_then(Value::as_str),
        value.get("works_count").and_then(Value::as_u64),
        value.get("cited_by_count").and_then(Value::as_u64),
        value
            .get("level")
            .and_then(Value::as_u64)
            .and_then(|level| u16::try_from(level).ok()),
    )
}

fn base_entity_count(base: &OpenAlexProviderRead) -> usize {
    if base.operation.is_citation() {
        base.citations.len()
    } else {
        match base.entity {
            OpenAlexEntity::Work => base.works.len(),
            OpenAlexEntity::Author => base.authors.len(),
            OpenAlexEntity::Institution => base.institutions.len(),
            OpenAlexEntity::Concept => base.concepts.len(),
        }
    }
}

fn malformed(
    response: &OpenAlexResponse,
    base: &OpenAlexProviderRead,
    diagnostic: impl Into<String>,
) -> OpenAlexProviderError {
    OpenAlexProviderError::MalformedResponse {
        status: response.status,
        response_digest: response.response_digest(),
        response_bytes: response.response_bytes(),
        rate_limit: response.rate_limit,
        provenance: base.provenance,
        diagnostic: bounded_diagnostic(&diagnostic.into()),
    }
}

fn bounded_diagnostic(value: &str) -> String {
    value.chars().take(MAX_DIAGNOSTIC_BYTES).collect()
}

/// Serializable fixture helpers keep test/recording construction separate
/// from the redacted evidence types.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexFixtureMeta {
    pub count: u64,
    #[serde(rename = "next_cursor")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexFixturePayload {
    pub meta: OpenAlexFixtureMeta,
    pub results: Vec<Value>,
}

impl OpenAlexFixturePayload {
    #[must_use]
    pub fn results(count: u64, results: Vec<Value>) -> Self {
        Self {
            meta: OpenAlexFixtureMeta {
                count,
                next_cursor: None,
            },
            results,
        }
    }

    #[must_use]
    pub fn with_next_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.meta.next_cursor = Some(cursor.into());
        self
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAlexFixtureSingleton {
    pub id: String,
    pub display_name: Option<String>,
}

impl RateLimitReceipt {
    #[must_use]
    pub fn throttled(retry_after_seconds: u32) -> Self {
        Self::throttled_for(retry_after_seconds)
    }
}

impl OpenAlexProviderError {
    #[must_use]
    pub fn diagnostic(&self) -> Option<&str> {
        match self {
            Self::MalformedResponse { diagnostic, .. } => Some(diagnostic),
            _ => None,
        }
    }
}

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    CrossrefOperation, CrossrefPermission, CrossrefRegistration, CrossrefResearchScope,
    CrossrefWorkProjection, Digest, MAX_DIAGNOSTIC_BYTES, MAX_RESPONSE_BYTES, MAX_RESULTS,
    MAX_RETRY_AFTER_SECONDS, ModelError, RateLimitReceipt, RegistrationState, SecretReference,
    TransportProvenance, canonical_digest, sha256_digest,
};

pub const CROSSREF_BASE_URL: &str = "https://api.crossref.org";
pub const CROSSREF_PROVIDER_ID: &str = "crossref.metadata.rest";
pub const CROSSREF_PROVIDER_VERSION: &str = "1.0.0";
pub const CROSSREF_API_REVISION: &str = "crossref-rest-api-v1";
pub const CROSSREF_METADATA_PERMISSION: &str = "metadata.read";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CrossrefHttpMethod {
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefProviderDefinition {
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
    pub first_party: bool,
}

impl Default for CrossrefProviderDefinition {
    fn default() -> Self {
        Self {
            id: CROSSREF_PROVIDER_ID.to_owned(),
            version: CROSSREF_PROVIDER_VERSION.to_owned(),
            api_revision: CROSSREF_API_REVISION.to_owned(),
            base_url: CROSSREF_BASE_URL.to_owned(),
            allowlisted_paths: vec!["/works".to_owned(), "/works/{doi}".to_owned()],
            required_permission: CROSSREF_METADATA_PERMISSION.to_owned(),
            max_requests_per_minute: crate::MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_results: MAX_RESULTS,
            native: false,
            connected: false,
            first_party: false,
        }
    }
}

impl CrossrefProviderDefinition {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub(crate) fn validate(&self) -> Result<(), CrossrefProviderError> {
        if self.id != CROSSREF_PROVIDER_ID
            || self.version != CROSSREF_PROVIDER_VERSION
            || self.api_revision != CROSSREF_API_REVISION
            || self.base_url != CROSSREF_BASE_URL
            || self.allowlisted_paths != ["/works".to_owned(), "/works/{doi}".to_owned()]
            || self.required_permission != CROSSREF_METADATA_PERMISSION
            || self.max_requests_per_minute != crate::MAX_REQUESTS_PER_MINUTE
            || self.max_response_bytes != MAX_RESPONSE_BYTES
            || self.max_results != MAX_RESULTS
            || self.native
            || self.connected
            || self.first_party
        {
            return Err(CrossrefProviderError::ProviderDefinitionDrift);
        }
        Ok(())
    }
}

/// A request contains only allowlisted path templates and digests. It is a
/// planning/recording seam, not a native HTTP request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefRequest {
    pub method: CrossrefHttpMethod,
    pub base_url: String,
    pub path_template: String,
    pub operation: CrossrefOperation,
    pub selector_digest: Digest,
    pub filter_digest: Digest,
    pub max_results: usize,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl CrossrefRequest {
    pub(crate) fn new(
        scope: &CrossrefResearchScope,
        consent: &crate::ConsentScope,
        secret_reference: &SecretReference,
    ) -> Self {
        let mut request = Self {
            method: CrossrefHttpMethod::Get,
            base_url: CROSSREF_BASE_URL.to_owned(),
            path_template: scope.query().operation().path_template().to_owned(),
            operation: scope.query().operation(),
            selector_digest: scope.query().selector_digest().to_owned(),
            filter_digest: scope.query().filter_digest().to_owned(),
            max_results: scope.max_results(),
            scope_digest: scope.digest(),
            consent_digest: consent.digest(),
            secret_reference_digest: secret_reference.digest(),
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
            self.operation,
            &self.selector_digest,
            &self.filter_digest,
            self.max_results,
            &self.scope_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
        ))
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == CrossrefHttpMethod::Get
            && self.base_url == CROSSREF_BASE_URL
            && ((self.operation == CrossrefOperation::SearchWorks
                && self.path_template == "/works")
                || (self.operation == CrossrefOperation::RetrieveWork
                    && self.path_template == "/works/{doi}"))
            && (1..=MAX_RESULTS).contains(&self.max_results)
            && self.selector_digest.len() == 64
            && self.filter_digest.len() == 64
            && self.scope_digest.len() == 64
            && self.consent_digest.len() == 64
            && self.secret_reference_digest.len() == 64
    }
}

/// Raw JSON is retained only inside this provider response until parsing. Its
/// Debug and Serialize representations expose size/digest metadata, never the
/// body itself.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub rate_limit: RateLimitReceipt,
}

impl fmt::Debug for CrossrefResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossrefResponse")
            .field("status", &self.status)
            .field("response_digest", &self.response_digest())
            .field("response_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl CrossrefResponse {
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
        let body = serde_json::to_vec(value).expect("Crossref fixture payload serializes");
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
pub enum CrossrefTransportError {
    #[error("Crossref native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Crossref transport timed out")]
    Timeout,
    #[error("Crossref transport failed without a native response")]
    ProviderUnknown,
}

/// Layer-1 transport seam. Implementations can replay bounded data but this
/// crate never resolves a secret or opens native HTTPS.
pub trait CrossrefTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &CrossrefRequest,
    ) -> Result<CrossrefResponse, CrossrefTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureCrossrefTransport {
    response: CrossrefResponse,
}

impl FixtureCrossrefTransport {
    #[must_use]
    pub fn new(response: CrossrefResponse) -> Self {
        Self { response }
    }
}

impl CrossrefTransport for FixtureCrossrefTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &CrossrefRequest,
    ) -> Result<CrossrefResponse, CrossrefTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingCrossrefTransport {
    response: CrossrefResponse,
    requests: Vec<CrossrefRequest>,
}

impl RecordingCrossrefTransport {
    #[must_use]
    pub fn new(response: CrossrefResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[CrossrefRequest] {
        &self.requests
    }
}

impl CrossrefTransport for RecordingCrossrefTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &CrossrefRequest,
    ) -> Result<CrossrefResponse, CrossrefTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackCrossrefTransport {
    response: CrossrefResponse,
    requests: Vec<CrossrefRequest>,
}

impl LoopbackCrossrefTransport {
    #[must_use]
    pub fn new(response: CrossrefResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[CrossrefRequest] {
        &self.requests
    }
}

impl CrossrefTransport for LoopbackCrossrefTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &CrossrefRequest,
    ) -> Result<CrossrefResponse, CrossrefTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCrossrefTransport;

impl CrossrefTransport for BlockedEnvCrossrefTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &CrossrefRequest,
    ) -> Result<CrossrefResponse, CrossrefTransportError> {
        Err(CrossrefTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CrossrefProviderError {
    #[error("Crossref provider definition drifted")]
    ProviderDefinitionDrift,
    #[error("Crossref registration is revoked")]
    RegistrationRevoked,
    #[error("Crossref registration is stale or tampered")]
    RegistrationDrift,
    #[error("Crossref SecretReference is revoked")]
    SecretRevoked,
    #[error("Crossref metadata.read permission is missing")]
    MissingMetadataPermission,
    #[error("Crossref scope is stale or invalid")]
    ScopeMismatch,
    #[error("Crossref request is not allowlisted")]
    RequestNotAllowlisted,
    #[error("Crossref response exceeds the Layer-1 bound")]
    ResponseTooLarge {
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
    },
    #[error("Crossref response is malformed: {diagnostic}")]
    MalformedResponse {
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
        diagnostic: String,
    },
    #[error("Crossref transport is blocked by the environment")]
    BlockedEnv,
    #[error("Crossref transport timed out")]
    Timeout,
    #[error("Crossref provider is unavailable")]
    ProviderUnknown,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossrefProviderRead {
    pub status: u16,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: RateLimitReceipt,
    pub provenance: TransportProvenance,
    pub operation: CrossrefOperation,
    pub query_digest: Digest,
    pub total_results: Option<u64>,
    pub works: Vec<CrossrefWorkProjection>,
    pub partial: bool,
}

impl CrossrefProviderRead {
    #[must_use]
    pub fn connected(&self) -> bool {
        self.provenance.connected()
    }

    #[must_use]
    pub fn native(&self) -> bool {
        self.provenance.native()
    }

    #[must_use]
    pub fn first_party(&self) -> bool {
        self.provenance.first_party()
    }
}

#[derive(Clone, Debug)]
pub struct CrossrefProvider<T: CrossrefTransport> {
    transport: T,
    definition: CrossrefProviderDefinition,
    scope: CrossrefResearchScope,
    permission: CrossrefPermission,
    secret_reference: SecretReference,
    registration: CrossrefRegistration,
}

impl<T: CrossrefTransport> CrossrefProvider<T> {
    pub fn new(
        scope: CrossrefResearchScope,
        permission: CrossrefPermission,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, CrossrefProviderError> {
        let definition = CrossrefProviderDefinition::default();
        definition.validate()?;
        scope.validate()?;
        if !permission.allows_metadata_read() {
            return Err(CrossrefProviderError::MissingMetadataPermission);
        }
        let registration =
            CrossrefRegistration::new(&scope, &permission, &secret_reference, definition.digest());
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
        scope: CrossrefResearchScope,
        permission: CrossrefPermission,
        secret_reference: SecretReference,
        registration: CrossrefRegistration,
        transport: T,
    ) -> Result<Self, CrossrefProviderError> {
        let mut provider = Self::new(scope, permission, secret_reference, transport)?;
        provider.registration = registration;
        provider.ensure_registration()?;
        Ok(provider)
    }

    #[must_use]
    pub fn definition(&self) -> &CrossrefProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    #[must_use]
    pub fn scope(&self) -> &CrossrefResearchScope {
        &self.scope
    }

    #[must_use]
    pub fn permission(&self) -> &CrossrefPermission {
        &self.permission
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration(&self) -> &CrossrefRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut CrossrefRegistration {
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

    pub fn set_scope(&mut self, scope: CrossrefResearchScope) -> Result<(), CrossrefProviderError> {
        scope.validate()?;
        self.scope = scope;
        Ok(())
    }

    pub fn set_permission(
        &mut self,
        permission: CrossrefPermission,
    ) -> Result<(), CrossrefProviderError> {
        if !permission.allows_metadata_read() {
            return Err(CrossrefProviderError::MissingMetadataPermission);
        }
        self.permission = permission;
        Ok(())
    }

    pub fn revoke_secret(&mut self) -> Result<(), CrossrefProviderError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn restore_secret(&mut self) -> Result<(), CrossrefProviderError> {
        self.secret_reference.restore()?;
        Ok(())
    }

    pub fn build_request(&self) -> Result<CrossrefRequest, CrossrefProviderError> {
        self.ensure_registration()?;
        let request =
            CrossrefRequest::new(&self.scope, self.scope.consent(), &self.secret_reference);
        if !request.is_allowlisted() || request.request_digest != request.digest() {
            return Err(CrossrefProviderError::RequestNotAllowlisted);
        }
        Ok(request)
    }

    pub fn read(&mut self) -> Result<CrossrefProviderRead, CrossrefProviderError> {
        let request = self.build_request()?;
        let provenance = self.transport.provenance();
        let response = match self.transport.execute(&request) {
            Ok(response) => response,
            Err(CrossrefTransportError::BlockedEnv) => {
                return Err(CrossrefProviderError::BlockedEnv);
            }
            Err(CrossrefTransportError::Timeout) => return Err(CrossrefProviderError::Timeout),
            Err(CrossrefTransportError::ProviderUnknown) => {
                return Err(CrossrefProviderError::ProviderUnknown);
            }
        };
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(CrossrefProviderError::ResponseTooLarge {
                status: response.status,
                response_digest,
                response_bytes,
                rate_limit: response.rate_limit,
                provenance,
            });
        }
        let base = CrossrefProviderRead {
            status: response.status,
            response_digest,
            response_bytes,
            rate_limit: response.rate_limit,
            provenance,
            operation: self.scope.query().operation(),
            query_digest: self.scope.query().selector_digest().to_owned(),
            total_results: None,
            works: Vec::new(),
            partial: false,
        };
        if !(200..300).contains(&response.status) {
            return Ok(CrossrefProviderRead {
                total_results: (response.status == 404).then_some(0),
                ..base
            });
        }
        parse_success_response(response, base, self.scope.max_results())
    }

    fn ensure_registration(&self) -> Result<(), CrossrefProviderError> {
        self.definition.validate()?;
        if !self.registration.state.is_active() {
            return Err(CrossrefProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(CrossrefProviderError::SecretRevoked);
        }
        if !self.permission.allows_metadata_read() {
            return Err(CrossrefProviderError::MissingMetadataPermission);
        }
        self.scope
            .validate()
            .map_err(|_| CrossrefProviderError::ScopeMismatch)?;
        if self.registration.scope_digest != self.scope.digest() {
            return Err(CrossrefProviderError::ScopeMismatch);
        }
        if self.registration.permission_digest != self.permission.digest() {
            return Err(CrossrefProviderError::RegistrationDrift);
        }
        self.registration
            .validate(
                &self.scope,
                &self.permission,
                &self.secret_reference,
                &self.provider_digest(),
            )
            .map_err(|error| match error {
                ModelError::AlreadyRevoked => CrossrefProviderError::RegistrationRevoked,
                ModelError::InvalidScope("secret reference revoked") => {
                    CrossrefProviderError::SecretRevoked
                }
                _ => CrossrefProviderError::RegistrationDrift,
            })
    }
}

#[allow(clippy::needless_pass_by_value)]
fn parse_success_response(
    response: CrossrefResponse,
    mut base: CrossrefProviderRead,
    max_results: usize,
) -> Result<CrossrefProviderRead, CrossrefProviderError> {
    let parsed: Value = serde_json::from_slice(&response.body).map_err(|error| {
        CrossrefProviderError::MalformedResponse {
            status: response.status,
            response_digest: response.response_digest(),
            response_bytes: response.response_bytes(),
            rate_limit: response.rate_limit,
            provenance: response_provenance(&base),
            diagnostic: bounded_diagnostic(&error.to_string()),
        }
    })?;
    let message =
        parsed
            .get("message")
            .ok_or_else(|| CrossrefProviderError::MalformedResponse {
                status: response.status,
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
                rate_limit: response.rate_limit,
                provenance: response_provenance(&base),
                diagnostic: "missing message".to_owned(),
            })?;
    let (items, total_results) = if let Some(items) = message.get("items").and_then(Value::as_array)
    {
        let total_results = message
            .get("total-results")
            .and_then(Value::as_u64)
            .unwrap_or(items.len() as u64);
        (items.clone(), total_results)
    } else if message.get("DOI").and_then(Value::as_str).is_some() {
        (vec![message.clone()], 1)
    } else {
        return Err(CrossrefProviderError::MalformedResponse {
            status: response.status,
            response_digest: response.response_digest(),
            response_bytes: response.response_bytes(),
            rate_limit: response.rate_limit,
            provenance: response_provenance(&base),
            diagnostic: "message is neither a work nor a work list".to_owned(),
        });
    };

    let mut works = Vec::new();
    let mut seen = BTreeSet::new();
    let mut partial = items.len() > max_results;
    for item in items.iter().take(max_results) {
        match parse_work_projection(item) {
            Ok(work) => {
                if seen.insert(work.doi_digest.clone()) {
                    works.push(work);
                } else {
                    partial = true;
                }
            }
            Err(_) => partial = true,
        }
    }
    if !items.is_empty() && works.is_empty() {
        return Err(CrossrefProviderError::MalformedResponse {
            status: response.status,
            response_digest: response.response_digest(),
            response_bytes: response.response_bytes(),
            rate_limit: response.rate_limit,
            provenance: response_provenance(&base),
            diagnostic: "no bounded metadata item could be projected".to_owned(),
        });
    }
    works.sort_by(|left, right| left.doi_digest.cmp(&right.doi_digest));
    if total_results > works.len() as u64 {
        partial = true;
    }
    base.response_digest = canonical_digest(&(base.status, total_results, &works));
    base.total_results = Some(total_results);
    base.works = works;
    base.partial = partial;
    Ok(base)
}

fn parse_work_projection(value: &Value) -> Result<CrossrefWorkProjection, ModelError> {
    let doi = value
        .get("DOI")
        .and_then(Value::as_str)
        .ok_or(ModelError::InvalidResponse)?;
    let title = value
        .get("title")
        .and_then(Value::as_array)
        .and_then(|titles| titles.first())
        .and_then(Value::as_str);
    let work_type = value.get("type").and_then(Value::as_str);
    let published_year = value
        .get("published")
        .or_else(|| value.get("published-print"))
        .or_else(|| value.get("published-online"))
        .and_then(|published| published.get("date-parts"))
        .and_then(Value::as_array)
        .and_then(|parts| parts.first())
        .and_then(Value::as_array)
        .and_then(|parts| parts.first())
        .and_then(Value::as_u64)
        .and_then(|year| u16::try_from(year).ok());
    let author_count = value
        .get("author")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let reference_count = value.get("reference-count").and_then(Value::as_u64);
    let cited_by_count = value.get("is-referenced-by-count").and_then(Value::as_u64);
    let container_title = value
        .get("container-title")
        .and_then(Value::as_array)
        .and_then(|titles| titles.first())
        .and_then(Value::as_str);
    CrossrefWorkProjection::from_metadata(
        doi,
        title,
        work_type,
        published_year,
        author_count,
        reference_count,
        cited_by_count,
        container_title,
    )
}

fn response_provenance(read: &CrossrefProviderRead) -> TransportProvenance {
    read.provenance
}

fn bounded_diagnostic(value: &str) -> String {
    value.chars().take(MAX_DIAGNOSTIC_BYTES).collect()
}

/// Serializable fixture helpers keep test/recording construction separate
/// from the redacted evidence types.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefFixturePayload {
    pub message: CrossrefFixtureMessage,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefFixtureMessage {
    #[serde(rename = "total-results")]
    pub total_results: u64,
    pub items: Vec<CrossrefFixtureWork>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefFixtureWork {
    #[serde(rename = "DOI")]
    pub doi: String,
    pub title: Vec<String>,
    #[serde(rename = "type")]
    pub work_type: String,
    pub published: Option<CrossrefFixturePublished>,
    pub author: Vec<CrossrefFixtureAuthor>,
    #[serde(rename = "reference-count")]
    pub reference_count: Option<u64>,
    #[serde(rename = "is-referenced-by-count")]
    pub cited_by_count: Option<u64>,
    #[serde(rename = "container-title")]
    pub container_title: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefFixturePublished {
    #[serde(rename = "date-parts")]
    pub date_parts: Vec<Vec<u16>>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossrefFixtureAuthor {
    pub given: Option<String>,
    pub family: Option<String>,
}

impl CrossrefFixturePayload {
    #[must_use]
    pub fn works(total_results: u64, items: Vec<CrossrefFixtureWork>) -> Self {
        Self {
            message: CrossrefFixtureMessage {
                total_results,
                items,
            },
        }
    }
}

impl CrossrefFixtureWork {
    #[must_use]
    pub fn minimal(doi: impl Into<String>) -> Self {
        Self {
            doi: doi.into(),
            title: Vec::new(),
            work_type: "journal-article".to_owned(),
            published: None,
            author: Vec::new(),
            reference_count: None,
            cited_by_count: None,
            container_title: Vec::new(),
        }
    }
}

impl RateLimitReceipt {
    #[must_use]
    pub fn throttled(retry_after_seconds: u32) -> Self {
        Self {
            limit_per_minute: Some(crate::MAX_REQUESTS_PER_MINUTE),
            remaining: Some(0),
            retry_after_seconds: Some(retry_after_seconds.min(MAX_RETRY_AFTER_SECONDS)),
            throttled: true,
        }
    }
}

impl CrossrefProviderError {
    #[must_use]
    pub fn diagnostic(&self) -> Option<&str> {
        match self {
            Self::MalformedResponse { diagnostic, .. } => Some(diagnostic),
            _ => None,
        }
    }
}

impl RegistrationState {
    #[must_use]
    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

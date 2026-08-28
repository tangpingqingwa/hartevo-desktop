use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Digest, MAX_DIAGNOSTIC_BYTES, MAX_RESPONSE_BYTES, MAX_RESULTS, ModelError, OpaqueCursor,
    OpaqueHistory, PubMedArticleProjection, PubMedDatabase, PubMedLinkProjection, PubMedOperation,
    PubMedPermission, PubMedRegistration, PubMedResearchScope, RateLimitReceipt, SecretReference,
    TransportProvenance, canonical_digest, sha256_digest,
};

pub const PUBMED_BASE_URL: &str = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils";
pub const NCBI_EUTILS_PROVIDER_ID: &str = "ncbi.eutils.pubmed";
pub const NCBI_EUTILS_PROVIDER_VERSION: &str = "1.0.0";
pub const NCBI_EUTILS_API_REVISION: &str = "ncbi-eutils-v1";
pub const PUBMED_METADATA_PERMISSION: &str = "metadata.read";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NcbiHttpMethod {
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NcbiEutilsProviderDefinition {
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

impl Default for NcbiEutilsProviderDefinition {
    fn default() -> Self {
        Self {
            id: NCBI_EUTILS_PROVIDER_ID.to_owned(),
            version: NCBI_EUTILS_PROVIDER_VERSION.to_owned(),
            api_revision: NCBI_EUTILS_API_REVISION.to_owned(),
            base_url: PUBMED_BASE_URL.to_owned(),
            allowlisted_paths: vec![
                "/esearch.fcgi".to_owned(),
                "/esummary.fcgi".to_owned(),
                "/efetch.fcgi".to_owned(),
                "/elink.fcgi".to_owned(),
            ],
            required_permission: PUBMED_METADATA_PERMISSION.to_owned(),
            max_requests_per_minute: crate::MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_results: MAX_RESULTS,
            native: false,
            connected: false,
            first_party: false,
        }
    }
}

impl NcbiEutilsProviderDefinition {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub(crate) fn validate(&self) -> Result<(), NcbiEutilsProviderError> {
        let expected = Self::default();
        if self != &expected {
            return Err(NcbiEutilsProviderError::ProviderDefinitionDrift);
        }
        Ok(())
    }
}

/// A request contains allowlisted operation metadata and digests only. It is
/// a planning/recording seam, not a native HTTP request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubMedRequest {
    pub method: NcbiHttpMethod,
    pub base_url: String,
    pub path_template: String,
    pub operation: PubMedOperation,
    pub database: PubMedDatabase,
    pub query_digest: Digest,
    pub pmid_digest: Option<Digest>,
    pub pmcid_digest: Option<Digest>,
    pub mesh_digest: Option<Digest>,
    pub max_results: usize,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub history_digest: Option<Digest>,
    pub scope_revision: u64,
    pub idempotency_digest: Digest,
    pub request_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestIdempotencyMaterial<'a> {
    method: NcbiHttpMethod,
    base_url: &'a str,
    path_template: &'a str,
    operation: PubMedOperation,
    database: PubMedDatabase,
    query_digest: &'a str,
    pmid_digest: &'a Option<Digest>,
    pmcid_digest: &'a Option<Digest>,
    mesh_digest: &'a Option<Digest>,
    max_results: usize,
    scope_digest: &'a str,
    consent_digest: &'a str,
    secret_reference_digest: &'a str,
    cursor_digest: &'a Option<Digest>,
    history_digest: &'a Option<Digest>,
    scope_revision: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestDigestMaterial<'a> {
    method: NcbiHttpMethod,
    base_url: &'a str,
    path_template: &'a str,
    operation: PubMedOperation,
    database: PubMedDatabase,
    query_digest: &'a str,
    pmid_digest: &'a Option<Digest>,
    pmcid_digest: &'a Option<Digest>,
    mesh_digest: &'a Option<Digest>,
    max_results: usize,
    scope_digest: &'a str,
    consent_digest: &'a str,
    secret_reference_digest: &'a str,
    cursor_digest: &'a Option<Digest>,
    history_digest: &'a Option<Digest>,
    scope_revision: u64,
    idempotency_digest: &'a str,
}

impl PubMedRequest {
    pub(crate) fn new(
        scope: &PubMedResearchScope,
        consent: &crate::ConsentScope,
        secret_reference: &SecretReference,
        cursor: Option<&OpaqueCursor>,
        history: Option<&OpaqueHistory>,
    ) -> Self {
        let scope_digest = scope.digest();
        let history_digest = history.map(OpaqueHistory::digest);
        let cursor_digest = cursor.map(|value| {
            value
                .bind_to(&scope_digest, history_digest.as_deref())
                .digest()
        });
        let mut request = Self {
            method: NcbiHttpMethod::Get,
            base_url: PUBMED_BASE_URL.to_owned(),
            path_template: scope.query().operation().path_template().to_owned(),
            operation: scope.query().operation(),
            database: scope.database(),
            query_digest: scope.query().selector_digest().to_owned(),
            pmid_digest: scope.query().pmid_digest().map(str::to_owned),
            pmcid_digest: scope.query().pmcid_digest().map(str::to_owned),
            mesh_digest: scope.query().mesh_digest().map(str::to_owned),
            max_results: scope.max_results(),
            scope_digest,
            consent_digest: consent.digest(),
            secret_reference_digest: secret_reference.digest(),
            cursor_digest,
            history_digest,
            scope_revision: scope.revision().get(),
            idempotency_digest: String::new(),
            request_digest: String::new(),
        };
        request.idempotency_digest = request.idempotency_digest();
        request.request_digest = request.digest();
        request
    }

    #[must_use]
    pub fn idempotency_digest(&self) -> Digest {
        canonical_digest(&RequestIdempotencyMaterial {
            method: self.method,
            base_url: &self.base_url,
            path_template: &self.path_template,
            operation: self.operation,
            database: self.database,
            query_digest: &self.query_digest,
            pmid_digest: &self.pmid_digest,
            pmcid_digest: &self.pmcid_digest,
            mesh_digest: &self.mesh_digest,
            max_results: self.max_results,
            scope_digest: &self.scope_digest,
            consent_digest: &self.consent_digest,
            secret_reference_digest: &self.secret_reference_digest,
            cursor_digest: &self.cursor_digest,
            history_digest: &self.history_digest,
            scope_revision: self.scope_revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&RequestDigestMaterial {
            method: self.method,
            base_url: &self.base_url,
            path_template: &self.path_template,
            operation: self.operation,
            database: self.database,
            query_digest: &self.query_digest,
            pmid_digest: &self.pmid_digest,
            pmcid_digest: &self.pmcid_digest,
            mesh_digest: &self.mesh_digest,
            max_results: self.max_results,
            scope_digest: &self.scope_digest,
            consent_digest: &self.consent_digest,
            secret_reference_digest: &self.secret_reference_digest,
            cursor_digest: &self.cursor_digest,
            history_digest: &self.history_digest,
            scope_revision: self.scope_revision,
            idempotency_digest: &self.idempotency_digest,
        })
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == NcbiHttpMethod::Get
            && self.base_url == PUBMED_BASE_URL
            && self.path_template == self.operation.path_template()
            && self.database.as_str().len() <= MAX_DIAGNOSTIC_BYTES
            && (1..=MAX_RESULTS).contains(&self.max_results)
            && self.query_digest.len() == 64
            && self.scope_digest.len() == 64
            && self.consent_digest.len() == 64
            && self.secret_reference_digest.len() == 64
            && self.idempotency_digest == self.idempotency_digest()
            && self.request_digest == self.digest()
            && [&self.pmid_digest, &self.pmcid_digest, &self.mesh_digest]
                .into_iter()
                .flatten()
                .all(|digest| digest.len() == 64)
            && self
                .cursor_digest
                .as_ref()
                .is_none_or(|digest| digest.len() == 64)
            && self
                .history_digest
                .as_ref()
                .is_none_or(|digest| digest.len() == 64)
    }
}

/// Raw JSON is retained only inside this provider response until parsing.
/// Debug and Serialize expose size/digest metadata, never the body itself.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PubMedResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub rate_limit: RateLimitReceipt,
}

impl fmt::Debug for PubMedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PubMedResponse")
            .field("status", &self.status)
            .field("response_digest", &self.response_digest())
            .field("response_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl PubMedResponse {
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
        let body = serde_json::to_vec(value).expect("PubMed fixture payload serializes");
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
pub enum NcbiEutilsTransportError {
    #[error("NCBI E-utilities native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("NCBI E-utilities transport timed out")]
    Timeout,
    #[error("NCBI E-utilities transport failed without a native response")]
    ProviderUnknown,
}

/// Layer-1 transport seam. Implementations replay bounded data but this
/// crate never resolves a secret or opens native HTTPS.
pub trait NcbiEutilsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &PubMedRequest,
    ) -> Result<PubMedResponse, NcbiEutilsTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureNcbiEutilsTransport {
    response: PubMedResponse,
}

impl FixtureNcbiEutilsTransport {
    #[must_use]
    pub fn new(response: PubMedResponse) -> Self {
        Self { response }
    }
}

impl NcbiEutilsTransport for FixtureNcbiEutilsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &PubMedRequest,
    ) -> Result<PubMedResponse, NcbiEutilsTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingNcbiEutilsTransport {
    response: PubMedResponse,
    requests: Vec<PubMedRequest>,
}

impl RecordingNcbiEutilsTransport {
    #[must_use]
    pub fn new(response: PubMedResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[PubMedRequest] {
        &self.requests
    }
}

impl NcbiEutilsTransport for RecordingNcbiEutilsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &PubMedRequest,
    ) -> Result<PubMedResponse, NcbiEutilsTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeNcbiEutilsTransport {
    responses: VecDeque<Result<PubMedResponse, NcbiEutilsTransportError>>,
    requests: Vec<PubMedRequest>,
}

impl FakeNcbiEutilsTransport {
    #[must_use]
    pub fn new(response: PubMedResponse) -> Self {
        Self {
            responses: VecDeque::from([Ok(response)]),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_results(
        responses: impl IntoIterator<Item = Result<PubMedResponse, NcbiEutilsTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: Result<PubMedResponse, NcbiEutilsTransportError>) {
        self.responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[PubMedRequest] {
        &self.requests
    }
}

impl NcbiEutilsTransport for FakeNcbiEutilsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn execute(
        &mut self,
        request: &PubMedRequest,
    ) -> Result<PubMedResponse, NcbiEutilsTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(NcbiEutilsTransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackNcbiEutilsTransport {
    response: PubMedResponse,
    requests: Vec<PubMedRequest>,
}

impl LoopbackNcbiEutilsTransport {
    #[must_use]
    pub fn new(response: PubMedResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[PubMedRequest] {
        &self.requests
    }
}

impl NcbiEutilsTransport for LoopbackNcbiEutilsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &PubMedRequest,
    ) -> Result<PubMedResponse, NcbiEutilsTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvNcbiEutilsTransport;

impl NcbiEutilsTransport for BlockedEnvNcbiEutilsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &PubMedRequest,
    ) -> Result<PubMedResponse, NcbiEutilsTransportError> {
        Err(NcbiEutilsTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NcbiEutilsProviderError {
    #[error("NCBI E-utilities provider definition drifted")]
    ProviderDefinitionDrift,
    #[error("PubMed registration is revoked")]
    RegistrationRevoked,
    #[error("PubMed registration is stale or tampered")]
    RegistrationDrift,
    #[error("PubMed SecretReference is revoked")]
    SecretRevoked,
    #[error("PubMed metadata.read permission is missing")]
    MissingMetadataPermission,
    #[error("PubMed scope is stale or invalid")]
    ScopeMismatch,
    #[error("PubMed request is not allowlisted")]
    RequestNotAllowlisted,
    #[error("PubMed cursor is bound to another query or history")]
    CursorMismatch,
    #[error("PubMed history binding is stale or mismatched")]
    HistoryMismatch,
    #[error("PubMed cursor replay was rejected")]
    CursorReplay,
    #[error("PubMed response exceeds the Layer-1 bound")]
    ResponseTooLarge {
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
    },
    #[error("PubMed response is malformed: {diagnostic}")]
    MalformedResponse {
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: RateLimitReceipt,
        provenance: TransportProvenance,
        diagnostic: String,
    },
    #[error("PubMed transport is blocked by the environment")]
    BlockedEnv,
    #[error("PubMed transport timed out")]
    Timeout,
    #[error("PubMed provider is unavailable")]
    ProviderUnknown,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NcbiEutilsProviderRead {
    pub status: u16,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: RateLimitReceipt,
    pub provenance: TransportProvenance,
    pub operation: PubMedOperation,
    pub database: PubMedDatabase,
    pub query_digest: Digest,
    pub pmid_digest: Option<Digest>,
    pub pmcid_digest: Option<Digest>,
    pub mesh_digest: Option<Digest>,
    pub total_results: Option<u64>,
    pub articles: Vec<PubMedArticleProjection>,
    pub links: Vec<PubMedLinkProjection>,
    pub partial: bool,
    pub next_cursor: Option<OpaqueCursor>,
    pub history: Option<OpaqueHistory>,
    pub page_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
}

impl NcbiEutilsProviderRead {
    #[must_use]
    pub fn returned_results(&self) -> usize {
        self.articles.len() + self.links.len()
    }

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
pub struct NcbiEutilsProvider<T: NcbiEutilsTransport> {
    transport: T,
    definition: NcbiEutilsProviderDefinition,
    scope: PubMedResearchScope,
    permission: PubMedPermission,
    secret_reference: SecretReference,
    registration: PubMedRegistration,
    consumed_cursors: BTreeSet<Digest>,
}

impl<T: NcbiEutilsTransport> NcbiEutilsProvider<T> {
    pub fn new(
        scope: PubMedResearchScope,
        permission: PubMedPermission,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, NcbiEutilsProviderError> {
        let definition = NcbiEutilsProviderDefinition::default();
        definition.validate()?;
        scope.validate()?;
        if !permission.allows_metadata_read() {
            return Err(NcbiEutilsProviderError::MissingMetadataPermission);
        }
        let registration =
            PubMedRegistration::new(&scope, &permission, &secret_reference, definition.digest());
        Ok(Self {
            transport,
            definition,
            scope,
            permission,
            secret_reference,
            registration,
            consumed_cursors: BTreeSet::new(),
        })
    }

    pub fn with_registration(
        scope: PubMedResearchScope,
        permission: PubMedPermission,
        secret_reference: SecretReference,
        registration: PubMedRegistration,
        transport: T,
    ) -> Result<Self, NcbiEutilsProviderError> {
        let mut provider = Self::new(scope, permission, secret_reference, transport)?;
        provider.registration = registration;
        provider.ensure_registration()?;
        Ok(provider)
    }

    #[must_use]
    pub fn definition(&self) -> &NcbiEutilsProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    #[must_use]
    pub fn scope(&self) -> &PubMedResearchScope {
        &self.scope
    }

    #[must_use]
    pub fn permission(&self) -> &PubMedPermission {
        &self.permission
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration(&self) -> &PubMedRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut PubMedRegistration {
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

    pub fn set_scope(&mut self, scope: PubMedResearchScope) -> Result<(), NcbiEutilsProviderError> {
        scope.validate()?;
        self.scope = scope;
        Ok(())
    }

    pub fn set_permission(
        &mut self,
        permission: PubMedPermission,
    ) -> Result<(), NcbiEutilsProviderError> {
        if !permission.allows_metadata_read() {
            return Err(NcbiEutilsProviderError::MissingMetadataPermission);
        }
        self.permission = permission;
        Ok(())
    }

    pub fn revoke_secret(&mut self) -> Result<(), NcbiEutilsProviderError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn restore_secret(&mut self) -> Result<(), NcbiEutilsProviderError> {
        self.secret_reference.restore()?;
        Ok(())
    }

    pub fn build_request(&self) -> Result<PubMedRequest, NcbiEutilsProviderError> {
        self.build_request_with_page(None, None)
    }

    pub fn build_request_with_page(
        &self,
        cursor: Option<OpaqueCursor>,
        history: Option<OpaqueHistory>,
    ) -> Result<PubMedRequest, NcbiEutilsProviderError> {
        self.ensure_registration()?;
        let scope_digest = self.scope.digest();
        if let Some(history) = &history
            && history
                .binding_digest()
                .is_some_and(|binding| binding != scope_digest)
        {
            return Err(NcbiEutilsProviderError::HistoryMismatch);
        }
        let history = history.map(|value| value.bind(&scope_digest));
        let history_digest = history.as_ref().map(OpaqueHistory::digest);
        if let Some(cursor) = &cursor {
            if cursor
                .binding_digest()
                .is_some_and(|binding| binding != scope_digest)
            {
                return Err(NcbiEutilsProviderError::CursorMismatch);
            }
            if cursor
                .history_digest()
                .is_some_and(|binding| Some(binding) != history_digest.as_deref())
            {
                return Err(NcbiEutilsProviderError::HistoryMismatch);
            }
        }
        let request = PubMedRequest::new(
            &self.scope,
            self.scope.consent(),
            &self.secret_reference,
            cursor.as_ref(),
            history.as_ref(),
        );
        if !request.is_allowlisted() {
            return Err(NcbiEutilsProviderError::RequestNotAllowlisted);
        }
        Ok(request)
    }

    pub fn read(&mut self) -> Result<NcbiEutilsProviderRead, NcbiEutilsProviderError> {
        self.read_with_page(None, None)
    }

    pub fn read_with_page(
        &mut self,
        cursor: Option<OpaqueCursor>,
        history: Option<OpaqueHistory>,
    ) -> Result<NcbiEutilsProviderRead, NcbiEutilsProviderError> {
        let request = self.build_request_with_page(cursor, history)?;
        self.read_request(request)
    }

    pub fn read_page(
        &mut self,
        cursor: Option<OpaqueCursor>,
        history: Option<OpaqueHistory>,
    ) -> Result<NcbiEutilsProviderRead, NcbiEutilsProviderError> {
        self.read_with_page(cursor, history)
    }

    pub fn read_request(
        &mut self,
        request: PubMedRequest,
    ) -> Result<NcbiEutilsProviderRead, NcbiEutilsProviderError> {
        self.ensure_registration()?;
        if !request.is_allowlisted()
            || request.scope_digest != self.scope.digest()
            || request.scope_revision != self.scope.revision().get()
            || request.consent_digest != self.scope.consent().digest()
            || request.secret_reference_digest != self.secret_reference.digest()
            || request.operation != self.scope.query().operation()
            || request.database != self.scope.database()
            || request.query_digest != self.scope.query().selector_digest()
            || request.pmid_digest.as_deref() != self.scope.query().pmid_digest()
            || request.pmcid_digest.as_deref() != self.scope.query().pmcid_digest()
            || request.mesh_digest.as_deref() != self.scope.query().mesh_digest()
            || request.max_results != self.scope.max_results()
        {
            return Err(NcbiEutilsProviderError::RequestNotAllowlisted);
        }
        if let Some(cursor_digest) = &request.cursor_digest
            && !self.consumed_cursors.insert(cursor_digest.clone())
        {
            return Err(NcbiEutilsProviderError::CursorReplay);
        }
        let provenance = self.transport.provenance();
        let response = match self.transport.execute(&request) {
            Ok(response) => response,
            Err(NcbiEutilsTransportError::BlockedEnv) => {
                return Err(NcbiEutilsProviderError::BlockedEnv);
            }
            Err(NcbiEutilsTransportError::Timeout) => return Err(NcbiEutilsProviderError::Timeout),
            Err(NcbiEutilsTransportError::ProviderUnknown) => {
                return Err(NcbiEutilsProviderError::ProviderUnknown);
            }
        };
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(NcbiEutilsProviderError::ResponseTooLarge {
                status: response.status,
                response_digest,
                response_bytes,
                rate_limit: response.rate_limit,
                provenance,
            });
        }
        let base = NcbiEutilsProviderRead {
            status: response.status,
            response_digest,
            response_bytes,
            rate_limit: response.rate_limit,
            provenance,
            operation: request.operation,
            database: request.database,
            query_digest: request.query_digest.clone(),
            pmid_digest: request.pmid_digest.clone(),
            pmcid_digest: request.pmcid_digest.clone(),
            mesh_digest: request.mesh_digest.clone(),
            total_results: None,
            articles: Vec::new(),
            links: Vec::new(),
            partial: false,
            next_cursor: None,
            history: None,
            page_digest: String::new(),
            request_digest: request.request_digest.clone(),
            idempotency_digest: request.idempotency_digest.clone(),
        };
        if !(200..300).contains(&response.status) {
            return Ok(with_page_digest(NcbiEutilsProviderRead {
                total_results: (response.status == 404).then_some(0),
                ..base
            }));
        }
        let mut read = parse_success_response(&response, base, self.scope.max_results())?;
        if let Some(history) = read.history.take() {
            read.history = Some(history.bind(&request.scope_digest));
        }
        let output_history_digest = read.history.as_ref().map(OpaqueHistory::digest);
        if let Some(cursor) = read.next_cursor.take() {
            read.next_cursor = Some(
                cursor.bind_to(
                    &request.scope_digest,
                    output_history_digest
                        .as_deref()
                        .or(request.history_digest.as_deref()),
                ),
            );
        }
        Ok(with_page_digest(read))
    }

    fn ensure_registration(&self) -> Result<(), NcbiEutilsProviderError> {
        self.definition.validate()?;
        if !self.registration.state.is_active() {
            return Err(NcbiEutilsProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(NcbiEutilsProviderError::SecretRevoked);
        }
        if !self.permission.allows_metadata_read() {
            return Err(NcbiEutilsProviderError::MissingMetadataPermission);
        }
        self.scope
            .validate()
            .map_err(|_| NcbiEutilsProviderError::ScopeMismatch)?;
        if self.registration.scope_digest != self.scope.digest() {
            return Err(NcbiEutilsProviderError::ScopeMismatch);
        }
        if self.registration.permission_digest != self.permission.digest() {
            return Err(NcbiEutilsProviderError::RegistrationDrift);
        }
        self.registration
            .validate(
                &self.scope,
                &self.permission,
                &self.secret_reference,
                &self.provider_digest(),
            )
            .map_err(|error| match error {
                ModelError::AlreadyRevoked => NcbiEutilsProviderError::RegistrationRevoked,
                ModelError::InvalidScope("secret reference revoked") => {
                    NcbiEutilsProviderError::SecretRevoked
                }
                _ => NcbiEutilsProviderError::RegistrationDrift,
            })
    }
}

type ParsedProviderResult = (
    Option<u64>,
    Vec<PubMedArticleProjection>,
    Vec<PubMedLinkProjection>,
    bool,
    Option<OpaqueHistory>,
    Option<OpaqueCursor>,
);

fn parse_success_response(
    response: &PubMedResponse,
    mut base: NcbiEutilsProviderRead,
    max_results: usize,
) -> Result<NcbiEutilsProviderRead, NcbiEutilsProviderError> {
    let parsed: Value = serde_json::from_slice(&response.body)
        .map_err(|_| malformed(response, base.provenance, "invalid_json"))?;
    let result = parsed
        .get("esearchresult")
        .or_else(|| parsed.get("result"))
        .unwrap_or(&parsed);
    let (total_results, articles, links, partial, history, next_cursor) = match base.operation {
        PubMedOperation::Search => parse_search(result, max_results, response, base.provenance)?,
        PubMedOperation::Summary => parse_summary(result, max_results, response, base.provenance)?,
        PubMedOperation::FetchMetadata => {
            parse_fetch(result, max_results, response, base.provenance)?
        }
        PubMedOperation::Link => parse_links(result, max_results, response, base.provenance)?,
    };
    base.total_results = total_results;
    base.articles = articles;
    base.links = links;
    base.partial = partial;
    base.history = history;
    base.next_cursor = next_cursor;
    Ok(with_page_digest(base))
}

fn parse_search(
    result: &Value,
    max_results: usize,
    response: &PubMedResponse,
    provenance: TransportProvenance,
) -> Result<ParsedProviderResult, NcbiEutilsProviderError> {
    let count = result.get("count").and_then(value_u64);
    let ids = result
        .get("idlist")
        .or_else(|| result.get("idList"))
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(response, provenance, "missing_esearch_idlist"))?;
    let mut articles = Vec::new();
    let mut seen = BTreeSet::new();
    let mut partial = ids.len() > max_results;
    for value in ids.iter().take(max_results) {
        let Some(id) = value_string(value) else {
            partial = true;
            continue;
        };
        match PubMedArticleProjection::minimal(id) {
            Ok(article) if seen.insert(article.pmid_digest.clone()) => articles.push(article),
            Ok(_) | Err(_) => partial = true,
        }
    }
    if count.is_some_and(|value| value > articles.len() as u64) {
        partial = true;
    }
    if count.is_none() && ids.is_empty() {
        return Err(malformed(response, provenance, "missing_esearch_count"));
    }
    let history = parse_history(result);
    let next_cursor = next_cursor(result, count, articles.len(), max_results)?;
    Ok((
        count.or(Some(articles.len() as u64)),
        articles,
        Vec::new(),
        partial,
        history,
        next_cursor,
    ))
}

fn parse_summary(
    result: &Value,
    max_results: usize,
    response: &PubMedResponse,
    provenance: TransportProvenance,
) -> Result<ParsedProviderResult, NcbiEutilsProviderError> {
    let uids = result
        .get("uids")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(response, provenance, "missing_esummary_uids"))?;
    let mut articles = Vec::new();
    let mut seen = BTreeSet::new();
    let mut partial = uids.len() > max_results;
    for uid in uids.iter().take(max_results) {
        let Some(uid) = value_string(uid) else {
            partial = true;
            continue;
        };
        let Some(document) = result.get(&uid) else {
            partial = true;
            continue;
        };
        match parse_article(document, Some(&uid)) {
            Ok(article) if seen.insert(article.pmid_digest.clone()) => articles.push(article),
            Ok(_) | Err(_) => partial = true,
        }
    }
    let count = result
        .get("count")
        .and_then(value_u64)
        .or_else(|| (!articles.is_empty()).then_some(articles.len() as u64));
    if count.is_some_and(|value| value > articles.len() as u64) {
        partial = true;
    }
    let history = parse_history(result);
    let next_cursor = next_cursor(result, count, articles.len(), max_results)?;
    Ok((count, articles, Vec::new(), partial, history, next_cursor))
}

fn parse_fetch(
    result: &Value,
    max_results: usize,
    response: &PubMedResponse,
    provenance: TransportProvenance,
) -> Result<ParsedProviderResult, NcbiEutilsProviderError> {
    let items = result
        .get("articles")
        .or_else(|| result.get("records"))
        .or_else(|| result.get("items"))
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(response, provenance, "missing_efetch_metadata"))?;
    let mut articles = Vec::new();
    let mut seen = BTreeSet::new();
    let mut partial = items.len() > max_results;
    for item in items.iter().take(max_results) {
        match parse_article(item, None) {
            Ok(article) if seen.insert(article.pmid_digest.clone()) => articles.push(article),
            Ok(_) | Err(_) => partial = true,
        }
    }
    let total = result
        .get("count")
        .and_then(value_u64)
        .or(Some(items.len() as u64));
    if total.is_some_and(|value| value > articles.len() as u64) {
        partial = true;
    }
    let history = parse_history(result);
    let next_cursor = next_cursor(result, total, articles.len(), max_results)?;
    Ok((total, articles, Vec::new(), partial, history, next_cursor))
}

fn parse_links(
    result: &Value,
    max_results: usize,
    response: &PubMedResponse,
    provenance: TransportProvenance,
) -> Result<ParsedProviderResult, NcbiEutilsProviderError> {
    let mut links = Vec::new();
    let mut partial = false;
    if let Some(items) = result.get("links").and_then(Value::as_array) {
        for item in items.iter().take(max_results) {
            let Some(source) = item.get("pmid").and_then(value_string) else {
                partial = true;
                continue;
            };
            let Some(target) = item
                .get("target")
                .or_else(|| item.get("target_id"))
                .and_then(value_string)
            else {
                partial = true;
                continue;
            };
            let database = item
                .get("target_database")
                .and_then(Value::as_str)
                .map(PubMedDatabase::parse)
                .transpose()
                .map_err(|_| malformed(response, provenance, "invalid_elink_database"))?
                .unwrap_or(PubMedDatabase::PubMed);
            let link_type = item
                .get("link_name")
                .or_else(|| item.get("link_type"))
                .and_then(Value::as_str)
                .unwrap_or("related");
            match PubMedLinkProjection::from_metadata(source, database, target, link_type) {
                Ok(link) => links.push(link),
                Err(_) => partial = true,
            }
        }
        partial |= items.len() > max_results;
    } else if let Some(linksets) = result.get("linksets").and_then(Value::as_array) {
        for linkset in linksets {
            let Some(source) = linkset
                .get("ids")
                .and_then(Value::as_array)
                .and_then(|ids| ids.first())
                .and_then(value_string)
            else {
                partial = true;
                continue;
            };
            let Some(groups) = linkset
                .get("linksetdbs")
                .or_else(|| linkset.get("linksetdb"))
                .and_then(Value::as_array)
            else {
                partial = true;
                continue;
            };
            for group in groups {
                let database = group
                    .get("dbto")
                    .and_then(Value::as_str)
                    .map(PubMedDatabase::parse)
                    .transpose()
                    .map_err(|_| malformed(response, provenance, "invalid_elink_database"))?
                    .unwrap_or(PubMedDatabase::PubMed);
                let link_type = group
                    .get("linkname")
                    .and_then(Value::as_str)
                    .unwrap_or("related");
                if let Some(targets) = group.get("links").and_then(Value::as_array) {
                    if links.len() >= max_results && !targets.is_empty() {
                        partial = true;
                    }
                    for target in targets.iter().take(max_results.saturating_sub(links.len())) {
                        let Some(target) = value_string(target) else {
                            partial = true;
                            continue;
                        };
                        match PubMedLinkProjection::from_metadata(
                            &source, database, target, link_type,
                        ) {
                            Ok(link) => links.push(link),
                            Err(_) => partial = true,
                        }
                    }
                }
            }
        }
    } else {
        return Err(malformed(response, provenance, "missing_elink_links"));
    }
    let total = result
        .get("count")
        .and_then(value_u64)
        .or(Some(links.len() as u64));
    if total.is_some_and(|value| value > links.len() as u64) {
        partial = true;
    }
    let history = parse_history(result);
    let next_cursor = next_cursor(result, total, links.len(), max_results)?;
    Ok((total, Vec::new(), links, partial, history, next_cursor))
}

fn parse_article(
    value: &Value,
    fallback_pmid: Option<&str>,
) -> Result<PubMedArticleProjection, ModelError> {
    let pmid = value
        .get("pmid")
        .or_else(|| value.get("uid"))
        .and_then(value_string)
        .or_else(|| fallback_pmid.map(str::to_owned))
        .ok_or(ModelError::InvalidResponse)?;
    let pmcid = value
        .get("pmcid")
        .or_else(|| value.get("pmc"))
        .and_then(Value::as_str);
    let title = value
        .get("title")
        .or_else(|| value.get("Title"))
        .and_then(Value::as_str);
    let journal = value
        .get("journal")
        .or_else(|| value.get("source"))
        .and_then(Value::as_str);
    let year = value
        .get("publication_year")
        .and_then(value_u64)
        .and_then(|year| u16::try_from(year).ok())
        .or_else(|| {
            value
                .get("pubdate")
                .or_else(|| value.get("sortpubdate"))
                .and_then(Value::as_str)
                .and_then(|date| date.get(..4))
                .and_then(|year| year.parse::<u16>().ok())
        });
    let author_count = value
        .get("author_count")
        .and_then(value_u64)
        .and_then(|count| usize::try_from(count).ok())
        .or_else(|| value.get("authors").and_then(Value::as_array).map(Vec::len));
    let mesh_values = value
        .get("mesh_terms")
        .and_then(Value::as_array)
        .map(|terms| {
            terms
                .iter()
                .filter_map(|term| {
                    term.as_str()
                        .or_else(|| term.get("meshheading").and_then(Value::as_str))
                })
                .collect::<Vec<_>>()
        })
        .or_else(|| {
            value
                .get("meshheadinglist")
                .and_then(Value::as_array)
                .map(|terms| {
                    terms
                        .iter()
                        .filter_map(|term| term.get("meshheading").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                })
        })
        .unwrap_or_default();
    PubMedArticleProjection::from_metadata(
        &pmid,
        pmcid,
        title,
        &mesh_values,
        year,
        journal,
        author_count,
    )
}

fn parse_history(value: &Value) -> Option<OpaqueHistory> {
    let web_env = value
        .get("webenv")
        .or_else(|| value.get("WebEnv"))
        .and_then(Value::as_str)?;
    let query_key = value
        .get("querykey")
        .or_else(|| value.get("query_key"))
        .and_then(value_string)?;
    OpaqueHistory::new(web_env, query_key).ok()
}

fn next_cursor(
    result: &Value,
    total: Option<u64>,
    returned: usize,
    max_results: usize,
) -> Result<Option<OpaqueCursor>, NcbiEutilsProviderError> {
    if let Some(value) = result
        .get("next_cursor")
        .or_else(|| result.get("nextCursor"))
        .and_then(Value::as_str)
    {
        return OpaqueCursor::new(value)
            .map(Some)
            .map_err(NcbiEutilsProviderError::Model);
    }
    let Some(total) = total else {
        return Ok(None);
    };
    let retstart = result.get("retstart").and_then(value_u64).unwrap_or(0);
    let retmax = result
        .get("retmax")
        .and_then(value_u64)
        .unwrap_or(max_results as u64);
    let next = retstart.saturating_add(retmax.max(returned as u64));
    if next < total {
        OpaqueCursor::new(format!("retstart:{next}"))
            .map(Some)
            .map_err(NcbiEutilsProviderError::Model)
    } else {
        Ok(None)
    }
}

fn value_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|number| number.to_string()))
}

fn value_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
}

fn malformed(
    response: &PubMedResponse,
    provenance: TransportProvenance,
    diagnostic: &str,
) -> NcbiEutilsProviderError {
    NcbiEutilsProviderError::MalformedResponse {
        status: response.status,
        response_digest: response.response_digest(),
        response_bytes: response.response_bytes(),
        rate_limit: response.rate_limit,
        provenance,
        diagnostic: diagnostic.chars().take(MAX_DIAGNOSTIC_BYTES).collect(),
    }
}

fn with_page_digest(mut read: NcbiEutilsProviderRead) -> NcbiEutilsProviderRead {
    read.articles
        .sort_by(|left, right| left.pmid_digest.cmp(&right.pmid_digest));
    read.links.sort_by_key(PubMedLinkProjection::digest);
    if (200..300).contains(&read.status) {
        read.response_digest = canonical_digest(&(
            read.operation,
            read.database,
            &read.total_results,
            &read.articles,
            &read.links,
            &read.partial,
        ));
    }
    read.page_digest = canonical_digest(&(
        read.operation,
        read.database,
        &read.query_digest,
        &read.total_results,
        &read.articles,
        &read.links,
        &read.partial,
        &read.next_cursor.as_ref().map(OpaqueCursor::digest),
        &read.history.as_ref().map(OpaqueHistory::digest),
        read.response_bytes,
        &read.request_digest,
        &read.idempotency_digest,
    ));
    read
}

impl NcbiEutilsProviderError {
    #[must_use]
    pub fn diagnostic(&self) -> Option<&str> {
        match self {
            Self::MalformedResponse { diagnostic, .. } => Some(diagnostic),
            _ => None,
        }
    }
}

pub type PubMedProvider<T> = NcbiEutilsProvider<T>;
pub type PubMedProviderDefinition = NcbiEutilsProviderDefinition;
pub type PubMedProviderRead = NcbiEutilsProviderRead;
pub use NcbiEutilsTransport as PubMedTransport;
pub use NcbiEutilsTransportError as PubMedTransportError;
pub type FixturePubMedTransport = FixtureNcbiEutilsTransport;
pub type RecordingPubMedTransport = RecordingNcbiEutilsTransport;
pub type FakePubMedTransport = FakeNcbiEutilsTransport;
pub type LoopbackPubMedTransport = LoopbackNcbiEutilsTransport;
pub type BlockedEnvPubMedTransport = BlockedEnvNcbiEutilsTransport;

// Keep the public error name next to the provider aliases for consumers that
// prefer the feature name over the NCBI implementation name.
#[allow(dead_code)]
type _ProviderErrorAlias = NcbiEutilsProviderError;

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Digest, EvidenceClassification, MAX_CELLS_PER_PAGE, MAX_PAGES, MAX_RESPONSE_BYTES,
    RegistrationState, Revision, SecretReference, SplunkAggregatePage, SplunkAggregateResult,
    SplunkEvidenceStatus, SplunkFieldDefinition, SplunkFieldType, SplunkJobPhase,
    SplunkRegistration, SplunkSavedSearchResultScope, SplunkTiming, TransportProvenance,
    canonical_digest, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SplunkHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SplunkProviderOperation {
    JobStatus,
    JobResults,
}

impl SplunkProviderOperation {
    #[must_use]
    pub const fn path_suffix(self) -> &'static str {
        match self {
            Self::JobStatus => "",
            Self::JobResults => "/results",
        }
    }
}

/// A safe read request. It contains a SID path and digests, but no SPL,
/// token, OAuth material, raw query, or event data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkProviderRequest {
    pub method: SplunkHttpMethod,
    pub host: String,
    pub path: String,
    pub operation: SplunkProviderOperation,
    pub page: Option<u16>,
    pub search_digest: Digest,
    pub sid_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl SplunkProviderRequest {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            "splunk-request/v1",
            self.method,
            &self.host,
            &self.path,
            self.operation,
            self.page,
            &self.search_digest,
            &self.sid_digest,
            &self.scope_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
        ))
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        if self.method != SplunkHttpMethod::Get
            || !self.host.starts_with("https://")
            || self.path.contains('?')
            || self.path.contains('#')
            || self.path.contains("search=")
            || self.path.contains("spl=")
            || self.path.contains("query=")
            || self.path.contains("_raw")
            || !self.path.contains("/services/search/jobs/")
        {
            return false;
        }
        let path_prefix = "/services/search/jobs/";
        let Some(suffix) = self.path.strip_prefix(path_prefix) else {
            return false;
        };
        let (sid, result_suffix) = suffix
            .strip_suffix("/results")
            .map_or((suffix, ""), |sid| (sid, "/results"));
        !sid.is_empty()
            && !sid.contains('/')
            && !sid.chars().any(char::is_control)
            && result_suffix == self.operation.path_suffix()
            && match self.operation {
                SplunkProviderOperation::JobStatus => self.page.is_none(),
                SplunkProviderOperation::JobResults => {
                    self.page.is_some_and(|page| page < MAX_PAGES)
                }
            }
    }
}

/// The raw response is private to the provider parser. Only its status,
/// length, and digest can cross the boundary.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkHttpResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
}

impl fmt::Debug for SplunkHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SplunkHttpResponse")
            .field("status", &self.status)
            .field("body_digest", &self.response_digest())
            .field("body_bytes", &self.response_bytes())
            .finish_non_exhaustive()
    }
}

impl SplunkHttpResponse {
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self {
            status,
            body: serde_json::to_vec(value).expect("Splunk fixture payload serializes"),
        }
    }

    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        crate::sha256_digest(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SplunkTransportError {
    #[error("Splunk native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Splunk transport timed out")]
    Timeout,
    #[error("Splunk fixture does not contain the requested page")]
    MissingFixturePage,
    #[error("Splunk transport failed without a native response")]
    ProviderUnknown,
}

/// Layer-1 transport seam. Every supplied implementation is offline and
/// reports non-native, non-connected, non-first-party provenance.
pub trait SplunkTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &SplunkProviderRequest,
    ) -> Result<SplunkHttpResponse, SplunkTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureSplunkTransport {
    status_response: SplunkHttpResponse,
    result_responses: Vec<SplunkHttpResponse>,
}

impl FixtureSplunkTransport {
    #[must_use]
    pub fn new(
        status_response: SplunkHttpResponse,
        result_responses: Vec<SplunkHttpResponse>,
    ) -> Self {
        Self {
            status_response,
            result_responses,
        }
    }

    fn response_for(
        &self,
        request: &SplunkProviderRequest,
    ) -> Result<SplunkHttpResponse, SplunkTransportError> {
        match request.operation {
            SplunkProviderOperation::JobStatus => Ok(self.status_response.clone()),
            SplunkProviderOperation::JobResults => request
                .page
                .and_then(|page| self.result_responses.get(usize::from(page)))
                .cloned()
                .ok_or(SplunkTransportError::MissingFixturePage),
        }
    }
}

impl SplunkTransport for FixtureSplunkTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &SplunkProviderRequest,
    ) -> Result<SplunkHttpResponse, SplunkTransportError> {
        self.response_for(request)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingSplunkTransport {
    fixture: FixtureSplunkTransport,
    requests: Vec<SplunkProviderRequest>,
}

impl RecordingSplunkTransport {
    #[must_use]
    pub fn new(
        status_response: SplunkHttpResponse,
        result_responses: Vec<SplunkHttpResponse>,
    ) -> Self {
        Self {
            fixture: FixtureSplunkTransport::new(status_response, result_responses),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[SplunkProviderRequest] {
        &self.requests
    }
}

impl SplunkTransport for RecordingSplunkTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &SplunkProviderRequest,
    ) -> Result<SplunkHttpResponse, SplunkTransportError> {
        self.requests.push(request.clone());
        self.fixture.response_for(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackSplunkTransport {
    fixture: FixtureSplunkTransport,
    requests: Vec<SplunkProviderRequest>,
}

impl LoopbackSplunkTransport {
    #[must_use]
    pub fn new(
        status_response: SplunkHttpResponse,
        result_responses: Vec<SplunkHttpResponse>,
    ) -> Self {
        Self {
            fixture: FixtureSplunkTransport::new(status_response, result_responses),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[SplunkProviderRequest] {
        &self.requests
    }
}

impl SplunkTransport for LoopbackSplunkTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &SplunkProviderRequest,
    ) -> Result<SplunkHttpResponse, SplunkTransportError> {
        self.requests.push(request.clone());
        self.fixture.response_for(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvSplunkTransport;

impl SplunkTransport for BlockedEnvSplunkTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &SplunkProviderRequest,
    ) -> Result<SplunkHttpResponse, SplunkTransportError> {
        Err(SplunkTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_name: String,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub provenance: TransportProvenance,
    pub max_response_bytes: usize,
    pub max_pages: u16,
    pub max_cells_per_page: usize,
    pub max_aggregate_cells: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl SplunkProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: TransportProvenance) -> Self {
        let capability_digest = canonical_digest(&(
            crate::SPLUNK_SEARCH_RESULT_SCHEMA_VERSION,
            crate::SPLUNK_PROVIDER_ID,
            crate::SPLUNK_API_REVISION,
            "GET",
            "/services/search/jobs/{sid}",
            "/services/search/jobs/{sid}/results",
            "preexisting_sid_only",
            "aggregate_projection_only",
        ));
        Self {
            schema_version: crate::SPLUNK_SEARCH_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: crate::SPLUNK_PROVIDER_ID.to_owned(),
            provider_name: crate::SPLUNK_PROVIDER_NAME.to_owned(),
            provider_version: crate::SPLUNK_PROVIDER_VERSION.to_owned(),
            api_revision: crate::SPLUNK_API_REVISION.to_owned(),
            capability_digest,
            provenance,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_pages: MAX_PAGES,
            max_cells_per_page: MAX_CELLS_PER_PAGE,
            max_aggregate_cells: crate::MAX_AGGREGATE_CELLS,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            first_party: false,
        }
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SplunkProviderError {
    #[error("Splunk registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Splunk SecretReference is revoked")]
    SecretRevoked,
    #[error("Splunk resource scope does not match the registered scope")]
    ScopeMismatch,
    #[error("arbitrary SPL is not accepted by the saved-search result seam")]
    ArbitrarySplRejected,
    #[error("Splunk HTTP status is {status_code}")]
    HttpStatus {
        request: SplunkProviderRequest,
        operation: SplunkProviderOperation,
        status_code: u16,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Splunk response exceeded the Layer-1 response bound")]
    ResponseTooLarge {
        request: SplunkProviderRequest,
        operation: SplunkProviderOperation,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Splunk response was malformed, raw, or outside the bounded projection")]
    MalformedResponse {
        request: SplunkProviderRequest,
        operation: SplunkProviderOperation,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Splunk pagination cursor was repeated or exceeded the bound")]
    PaginationReplay {
        request: SplunkProviderRequest,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Splunk result projection exceeded the Layer-1 bound")]
    ResultBoundExceeded {
        request: SplunkProviderRequest,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Splunk transport failed")]
    Transport {
        request: SplunkProviderRequest,
        error: SplunkTransportError,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error(transparent)]
    Model(#[from] crate::ModelError),
}

impl SplunkProviderError {
    #[must_use]
    pub fn request(&self) -> Option<&SplunkProviderRequest> {
        match self {
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::ScopeMismatch
            | Self::ArbitrarySplRejected
            | Self::Model(_) => None,
            Self::HttpStatus { request, .. }
            | Self::ResponseTooLarge { request, .. }
            | Self::MalformedResponse { request, .. }
            | Self::PaginationReplay { request, .. }
            | Self::ResultBoundExceeded { request, .. }
            | Self::Transport { request, .. } => Some(request),
        }
    }

    #[must_use]
    pub fn metadata(&self) -> Option<(Digest, usize, Option<u16>, SplunkProviderOperation)> {
        match self {
            Self::HttpStatus {
                operation,
                status_code,
                response_digest,
                response_bytes,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                Some(*status_code),
                *operation,
            )),
            Self::ResponseTooLarge {
                operation,
                response_digest,
                response_bytes,
                ..
            }
            | Self::MalformedResponse {
                operation,
                response_digest,
                response_bytes,
                ..
            } => Some((response_digest.clone(), *response_bytes, None, *operation)),
            Self::PaginationReplay {
                response_digest,
                response_bytes,
                request,
            }
            | Self::ResultBoundExceeded {
                response_digest,
                response_bytes,
                request,
            }
            | Self::Transport {
                response_digest,
                response_bytes,
                request,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                None,
                request.operation,
            )),
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::ScopeMismatch
            | Self::ArbitrarySplRejected
            | Self::Model(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SplunkProviderRead {
    pub status: SplunkEvidenceStatus,
    pub timing: SplunkTiming,
    pub result: SplunkAggregateResult,
    pub response_digest: Digest,
    pub status_response_digest: Digest,
    pub provenance: TransportProvenance,
}

/// Typed provider boundary for a bounded, read-only saved-search job read.
#[derive(Clone)]
pub struct SplunkProvider<T: SplunkTransport> {
    scope: SplunkSavedSearchResultScope,
    secret_reference: SecretReference,
    transport: T,
    definition: SplunkProviderDefinition,
    registration: SplunkRegistration,
}

impl<T: SplunkTransport> fmt::Debug for SplunkProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SplunkProvider")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("transport_provenance", &self.definition.provenance)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: SplunkTransport> SplunkProvider<T> {
    pub fn new(
        scope: SplunkSavedSearchResultScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, SplunkProviderError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(SplunkProviderError::SecretRevoked);
        }
        let definition = SplunkProviderDefinition::layer1(transport.provenance());
        let registration =
            SplunkRegistration::bind(&scope, &secret_reference, definition.provider_digest());
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
        })
    }

    pub fn with_registration(
        scope: SplunkSavedSearchResultScope,
        secret_reference: SecretReference,
        transport: T,
        registration: SplunkRegistration,
    ) -> Result<Self, SplunkProviderError> {
        scope.validate()?;
        let definition = SplunkProviderDefinition::layer1(transport.provenance());
        registration
            .validate(&scope, &secret_reference, &definition.provider_digest())
            .map_err(|_| SplunkProviderError::ScopeMismatch)?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &SplunkSavedSearchResultScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &SplunkProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &SplunkRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self) -> Result<SplunkProviderRead, SplunkProviderError> {
        self.ensure_ready()?;
        let status_request = self.build_request(SplunkProviderOperation::JobStatus, None);
        self.ensure_request(&status_request)?;
        let status_response = self.execute(&status_request)?;
        let status_response_digest = status_response.response_digest();
        let (sid, phase, timing) = self.parse_status(&status_request, &status_response)?;
        if sid != self.scope.resource().sid().as_str() {
            return Err(SplunkProviderError::MalformedResponse {
                request: status_request,
                operation: SplunkProviderOperation::JobStatus,
                response_digest: status_response_digest,
                response_bytes: status_response.response_bytes(),
            });
        }
        let provenance = self.definition.provenance;
        match phase {
            SplunkJobPhase::Queued
            | SplunkJobPhase::Running
            | SplunkJobPhase::Failed
            | SplunkJobPhase::Expired
            | SplunkJobPhase::Empty => Ok(SplunkProviderRead {
                status: phase.evidence_status(),
                timing,
                result: SplunkAggregateResult::empty(),
                response_digest: status_response_digest.clone(),
                status_response_digest,
                provenance,
            }),
            SplunkJobPhase::Done | SplunkJobPhase::Partial => {
                let (pages, _response_digests) = self.read_pages()?;
                let result = SplunkAggregateResult::from_pages(&pages).map_err(|error| {
                    let request = self.build_request(
                        SplunkProviderOperation::JobResults,
                        pages.last().map(|page| page.page),
                    );
                    let digest =
                        canonical_digest(&("splunk-result-bound-error/v1", error.to_string()));
                    match error {
                        crate::ModelError::ResultBoundExceeded => {
                            SplunkProviderError::ResultBoundExceeded {
                                request,
                                response_digest: digest,
                                response_bytes: 0,
                            }
                        }
                        _ => SplunkProviderError::MalformedResponse {
                            request,
                            operation: SplunkProviderOperation::JobResults,
                            response_digest: digest,
                            response_bytes: 0,
                        },
                    }
                })?;
                let status = if result.is_empty() {
                    if matches!(phase, SplunkJobPhase::Partial) || result.partial {
                        SplunkEvidenceStatus::Partial
                    } else {
                        SplunkEvidenceStatus::Empty
                    }
                } else if matches!(phase, SplunkJobPhase::Partial) || result.partial {
                    SplunkEvidenceStatus::Partial
                } else {
                    SplunkEvidenceStatus::Done
                };
                let response_digest =
                    canonical_digest(&("splunk-normalized-response/v1", &phase, &timing, &result));
                Ok(SplunkProviderRead {
                    status,
                    timing,
                    result,
                    response_digest,
                    status_response_digest,
                    provenance,
                })
            }
        }
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationChange, SplunkProviderError> {
        self.registration
            .revoke()
            .map_err(SplunkProviderError::Model)
    }

    pub fn restore(&mut self) -> Result<crate::RegistrationChange, SplunkProviderError> {
        self.registration
            .restore()
            .map_err(SplunkProviderError::Model)
    }

    pub fn revoke_secret(&mut self) -> Result<(), SplunkProviderError> {
        self.secret_reference
            .revoke()
            .map_err(SplunkProviderError::Model)
    }

    fn ensure_ready(&self) -> Result<(), SplunkProviderError> {
        if self.registration.state != RegistrationState::Active {
            return Err(SplunkProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(SplunkProviderError::SecretRevoked);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| SplunkProviderError::RegistrationRevoked)
    }

    fn ensure_request(&self, request: &SplunkProviderRequest) -> Result<(), SplunkProviderError> {
        if !request.is_allowlisted()
            || request.host != self.scope.resource().host().as_str()
            || request.search_digest != self.scope.search_digest()
            || request.sid_digest != self.scope.sid_digest()
            || request.scope_digest != self.scope.digest()
            || request.consent_digest != *self.scope.consent_digest()
            || request.secret_reference_digest != self.secret_reference.digest()
            || request.request_digest != request.digest()
        {
            if request.path.contains("search=")
                || request.path.contains("spl=")
                || request.path.contains("query=")
            {
                return Err(SplunkProviderError::ArbitrarySplRejected);
            }
            return Err(SplunkProviderError::ScopeMismatch);
        }
        Ok(())
    }

    fn execute(
        &mut self,
        request: &SplunkProviderRequest,
    ) -> Result<SplunkHttpResponse, SplunkProviderError> {
        let response =
            self.transport
                .execute(request)
                .map_err(|error| SplunkProviderError::Transport {
                    request: request.clone(),
                    error,
                    response_digest: crate::sha256_digest(b"splunk-no-response"),
                    response_bytes: 0,
                })?;
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        if !(200..=299).contains(&response.status) {
            return Err(SplunkProviderError::HttpStatus {
                request: request.clone(),
                operation: request.operation,
                status_code: response.status,
                response_digest,
                response_bytes,
            });
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(SplunkProviderError::ResponseTooLarge {
                request: request.clone(),
                operation: request.operation,
                response_digest,
                response_bytes,
            });
        }
        Ok(response)
    }

    fn read_pages(
        &mut self,
    ) -> Result<(Vec<SplunkAggregatePage>, Vec<Digest>), SplunkProviderError> {
        let mut pages = Vec::new();
        let mut response_digests = Vec::new();
        let mut seen_pages = BTreeSet::new();
        let mut page_number = 0_u16;
        loop {
            if pages.len() >= usize::from(MAX_PAGES) || !seen_pages.insert(page_number) {
                let request =
                    self.build_request(SplunkProviderOperation::JobResults, Some(page_number));
                return Err(SplunkProviderError::PaginationReplay {
                    request,
                    response_digest: canonical_digest(&("splunk-page-replay/v1", page_number)),
                    response_bytes: 0,
                });
            }
            let request =
                self.build_request(SplunkProviderOperation::JobResults, Some(page_number));
            self.ensure_request(&request)?;
            let response = self.execute(&request)?;
            let response_digest = response.response_digest();
            let page = self.parse_page(&request, &response, page_number)?;
            let next_page = page.next_page;
            pages.push(page);
            response_digests.push(response_digest);
            match next_page {
                Some(next) if next > page_number && next < MAX_PAGES => page_number = next,
                Some(_) => {
                    return Err(SplunkProviderError::PaginationReplay {
                        request,
                        response_digest: response_digests
                            .last()
                            .cloned()
                            .unwrap_or_else(|| crate::sha256_digest(b"splunk-page-replay")),
                        response_bytes: response.response_bytes(),
                    });
                }
                None => return Ok((pages, response_digests)),
            }
        }
    }

    fn parse_status(
        &self,
        request: &SplunkProviderRequest,
        response: &SplunkHttpResponse,
    ) -> Result<(String, SplunkJobPhase, SplunkTiming), SplunkProviderError> {
        let value = self.parse_json(request, response)?;
        let object = value
            .as_object()
            .ok_or_else(|| self.malformed(request, response))?;
        let sid = object
            .get("sid")
            .and_then(Value::as_str)
            .ok_or_else(|| self.malformed(request, response))?
            .to_owned();
        let status = object
            .get("status")
            .or_else(|| object.get("dispatchState"))
            .and_then(Value::as_str)
            .ok_or_else(|| self.malformed(request, response))?;
        let phase = SplunkJobPhase::parse(status).map_err(|_| self.malformed(request, response))?;
        let timing = timing_from_object(object).map_err(|_| self.malformed(request, response))?;
        Ok((sid, phase, timing))
    }

    fn parse_page(
        &self,
        request: &SplunkProviderRequest,
        response: &SplunkHttpResponse,
        expected_page: u16,
    ) -> Result<SplunkAggregatePage, SplunkProviderError> {
        let value = self.parse_json(request, response)?;
        let object = value
            .as_object()
            .ok_or_else(|| self.malformed(request, response))?;
        let page = object
            .get("page")
            .and_then(Value::as_u64)
            .and_then(|page| u16::try_from(page).ok())
            .ok_or_else(|| self.malformed(request, response))?;
        if page != expected_page {
            return Err(SplunkProviderError::PaginationReplay {
                request: request.clone(),
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
            });
        }
        let next_page = object
            .get("nextPage")
            .or_else(|| object.get("next_page"))
            .and_then(Value::as_u64)
            .map(u16::try_from)
            .transpose()
            .map_err(|_| self.malformed(request, response))?;
        let partial = object
            .get("partial")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let field_values = object
            .get("fields")
            .and_then(Value::as_array)
            .ok_or_else(|| self.malformed(request, response))?;
        if field_values.len() > crate::MAX_FIELDS || field_values.is_empty() {
            return Err(SplunkProviderError::ResultBoundExceeded {
                request: request.clone(),
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
            });
        }
        let field_schema = field_values
            .iter()
            .map(|field| {
                let object = field
                    .as_object()
                    .ok_or_else(|| self.malformed(request, response))?;
                let name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| self.malformed(request, response))?;
                let kind = object
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                SplunkFieldDefinition::new(name, SplunkFieldType::parse(kind))
                    .map_err(|_| self.malformed(request, response))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rows = object
            .get("cells")
            .and_then(Value::as_array)
            .ok_or_else(|| self.malformed(request, response))?;
        if rows.len() > MAX_CELLS_PER_PAGE {
            return Err(SplunkProviderError::ResultBoundExceeded {
                request: request.clone(),
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
            });
        }
        let field_types = field_schema
            .iter()
            .map(|field| (field.name.as_str(), field.field_type))
            .collect::<std::collections::BTreeMap<_, _>>();
        let cells = rows
            .iter()
            .map(|row| {
                let row = row
                    .as_object()
                    .ok_or_else(|| self.malformed(request, response))?;
                let mut projected = std::collections::BTreeMap::new();
                for (name, value) in row {
                    let field_type = field_types
                        .get(name.as_str())
                        .ok_or_else(|| self.malformed(request, response))?;
                    let cell = crate::SplunkAggregateCell::from_json(value, *field_type)
                        .map_err(|_| self.malformed(request, response))?;
                    projected.insert(name.clone(), cell);
                }
                crate::SplunkAggregateRow::new(projected)
                    .map_err(|_| self.malformed(request, response))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let timing = timing_from_object(object).map_err(|_| self.malformed(request, response))?;
        SplunkAggregatePage::new(page, next_page, field_schema, cells, partial, timing).map_err(
            |error| match error {
                crate::ModelError::ResultBoundExceeded => {
                    SplunkProviderError::ResultBoundExceeded {
                        request: request.clone(),
                        response_digest: response.response_digest(),
                        response_bytes: response.response_bytes(),
                    }
                }
                crate::ModelError::InvalidProviderPage => SplunkProviderError::PaginationReplay {
                    request: request.clone(),
                    response_digest: response.response_digest(),
                    response_bytes: response.response_bytes(),
                },
                _ => self.malformed(request, response),
            },
        )
    }

    fn parse_json(
        &self,
        request: &SplunkProviderRequest,
        response: &SplunkHttpResponse,
    ) -> Result<Value, SplunkProviderError> {
        let value = serde_json::from_slice::<Value>(&response.body)
            .map_err(|_| self.malformed(request, response))?;
        if contains_forbidden_key(&value) {
            return Err(self.malformed(request, response));
        }
        Ok(value)
    }

    #[allow(clippy::unused_self)]
    fn malformed(
        &self,
        request: &SplunkProviderRequest,
        response: &SplunkHttpResponse,
    ) -> SplunkProviderError {
        SplunkProviderError::MalformedResponse {
            request: request.clone(),
            operation: request.operation,
            response_digest: response.response_digest(),
            response_bytes: response.response_bytes(),
        }
    }

    fn build_request(
        &self,
        operation: SplunkProviderOperation,
        page: Option<u16>,
    ) -> SplunkProviderRequest {
        let resource = self.scope.resource();
        let path = format!(
            "/services/search/jobs/{}{}",
            resource.sid().as_str(),
            operation.path_suffix()
        );
        let mut request = SplunkProviderRequest {
            method: SplunkHttpMethod::Get,
            host: resource.host().as_str().to_owned(),
            path,
            operation,
            page,
            search_digest: self.scope.search_digest(),
            sid_digest: self.scope.sid_digest(),
            scope_digest: self.scope.digest(),
            consent_digest: self.scope.consent_digest().clone(),
            secret_reference_digest: self.secret_reference.digest(),
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    }
}

fn timing_from_object(
    object: &serde_json::Map<String, Value>,
) -> Result<SplunkTiming, crate::ModelError> {
    let queue = bounded_u64(
        object
            .get("queueMilliseconds")
            .or_else(|| object.get("queue_milliseconds")),
    )?;
    let duration = bounded_u64(
        object
            .get("durationMilliseconds")
            .or_else(|| object.get("duration_milliseconds")),
    )?;
    SplunkTiming::new(queue, duration)
}

fn bounded_u64(value: Option<&Value>) -> Result<Option<u64>, crate::ModelError> {
    value
        .map(|value| value.as_u64().ok_or(crate::ModelError::InvalidProviderPage))
        .transpose()
}

fn contains_forbidden_key(value: &Value) -> bool {
    const FORBIDDEN: &[&str] = &[
        "_raw",
        "source",
        "host",
        "sourcetype",
        "results",
        "events",
        "event",
        "search",
        "spl",
        "query",
        "token",
        "authorization",
        "pii",
    ];
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            FORBIDDEN.contains(&lower.as_str())
                || lower.contains("_raw")
                || lower.contains("source")
                || lower.starts_with("host")
                || lower.contains("search")
                || lower.contains("spl")
                || lower.contains("token")
                || contains_forbidden_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_key),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

#[allow(dead_code)]
fn _classification_for_status(status: SplunkEvidenceStatus) -> EvidenceClassification {
    match status {
        SplunkEvidenceStatus::Done
        | SplunkEvidenceStatus::Queued
        | SplunkEvidenceStatus::Running => EvidenceClassification::Normalized,
        SplunkEvidenceStatus::Failed | SplunkEvidenceStatus::ProviderUnknown => {
            EvidenceClassification::ProviderUnknown
        }
        SplunkEvidenceStatus::Expired | SplunkEvidenceStatus::AccessLost => {
            EvidenceClassification::AccessLost
        }
        SplunkEvidenceStatus::Partial => EvidenceClassification::Partial,
        SplunkEvidenceStatus::Empty => EvidenceClassification::Empty,
        SplunkEvidenceStatus::Tampered => EvidenceClassification::Tampered,
        SplunkEvidenceStatus::Revoked => EvidenceClassification::Revoked,
    }
}

#[allow(dead_code)]
fn _contract_digest_is_bound() -> Digest {
    contract_digest()
}

#[allow(dead_code)]
fn _revision_one() -> Revision {
    Revision::new(1).expect("revision one")
}

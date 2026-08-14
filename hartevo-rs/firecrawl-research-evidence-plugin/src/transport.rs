use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::{FirecrawlResearchEvidenceError, FirecrawlTransportError};
use crate::model::{
    CanonicalUrl, Digest, FirecrawlJobId, FirecrawlJobRequest, FirecrawlJobStatus,
    FirecrawlProvenance, MAX_MARKDOWN_BYTES, MAX_SNIPPET_BYTES, canonical_digest, digest_parts,
    sha256_digest, validate_text,
};

/// A transport operation is an inspectable local plan, never a live HTTP call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum FirecrawlTransportOperation {
    SubmitScrape { request: FirecrawlJobRequest },
    SubmitCrawl { request: FirecrawlJobRequest },
    ReadJob { request: FirecrawlJobRequest },
}

impl FirecrawlTransportOperation {
    pub fn request(&self) -> &FirecrawlJobRequest {
        match self {
            Self::SubmitScrape { request }
            | Self::SubmitCrawl { request }
            | Self::ReadJob { request } => request,
        }
    }
}

/// A bounded provider page projection. It contains no raw HTML, screenshots,
/// audio, video, base64 media, headers, or response body.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawFirecrawlPage {
    pub canonical_url: CanonicalUrl,
    pub title: String,
    pub status_code: u16,
    pub content_type: String,
    pub markdown: String,
    pub content_digest: Digest,
    pub snippet_digest: Digest,
    pub citation_digest: Digest,
    pub extraction_schema_digest: Digest,
    pub page_digest: Digest,
}

impl fmt::Debug for RawFirecrawlPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawFirecrawlPage")
            .field("canonical_url", &self.canonical_url)
            .field("title", &self.title)
            .field("status_code", &self.status_code)
            .field("content_type", &self.content_type)
            .field("content_digest", &self.content_digest)
            .field("snippet_digest", &self.snippet_digest)
            .field("citation_digest", &self.citation_digest)
            .field("extraction_schema_digest", &self.extraction_schema_digest)
            .field("page_digest", &self.page_digest)
            .finish()
    }
}

impl RawFirecrawlPage {
    pub fn new(
        canonical_url: CanonicalUrl,
        title: impl Into<String>,
        status_code: u16,
        content_type: impl Into<String>,
        markdown: impl Into<String>,
        extraction_schema_digest: Digest,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let title = title.into();
        let content_type = content_type.into();
        let markdown = markdown.into();
        validate_text(&title, "title", 512)?;
        validate_text(&content_type, "content_type", 128)?;
        if markdown.len() > MAX_MARKDOWN_BYTES {
            return Err(FirecrawlResearchEvidenceError::ContentTooLarge);
        }
        if markdown.contains(";base64,") || markdown.to_ascii_lowercase().contains("data:image/") {
            return Err(FirecrawlResearchEvidenceError::MediaRetentionRefused);
        }
        if extraction_schema_digest.len() != 64 {
            return Err(FirecrawlResearchEvidenceError::InvalidDigest {
                field: "extraction_schema_digest",
            });
        }
        let content_digest = sha256_digest(markdown.as_bytes());
        let snippet = markdown.chars().take(MAX_SNIPPET_BYTES).collect::<String>();
        let snippet_digest = sha256_digest(snippet.as_bytes());
        let citation_digest = digest_parts([
            canonical_url.as_str(),
            title.as_str(),
            snippet_digest.as_str(),
            content_digest.as_str(),
        ]);
        let page_digest = raw_page_digest(
            &canonical_url,
            &title,
            status_code,
            &content_type,
            &content_digest,
            &snippet_digest,
            &citation_digest,
            &extraction_schema_digest,
        );
        Ok(Self {
            canonical_url,
            title,
            status_code,
            content_type,
            markdown,
            content_digest,
            snippet_digest,
            citation_digest,
            extraction_schema_digest,
            page_digest,
        })
    }

    pub fn default_for(url: &CanonicalUrl) -> Self {
        Self::new(
            url.clone(),
            "Fixture public research page",
            200,
            "text/html",
            "Bounded fixture Markdown evidence.",
            sha256_digest(b"firecrawl-extraction-schema:none"),
        )
        .expect("default fixture page")
    }

    pub fn set_content_digest_tamper(&mut self, digest: Digest) {
        self.content_digest = digest;
    }

    pub fn set_snippet_digest_tamper(&mut self, digest: Digest) {
        self.snippet_digest = digest;
    }

    pub fn set_citation_digest_tamper(&mut self, digest: Digest) {
        self.citation_digest = digest;
    }

    pub fn set_page_digest_tamper(&mut self, digest: Digest) {
        self.page_digest = digest;
    }
}

fn raw_page_digest(
    url: &CanonicalUrl,
    title: &str,
    status_code: u16,
    content_type: &str,
    content_digest: &str,
    snippet_digest: &str,
    citation_digest: &str,
    extraction_schema_digest: &str,
) -> Digest {
    digest_parts([
        url.as_str(),
        title,
        &status_code.to_string(),
        content_type,
        content_digest,
        snippet_digest,
        citation_digest,
        extraction_schema_digest,
    ])
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawFirecrawlResponse {
    pub http_status: u16,
    pub success: bool,
    pub provider_job_id: FirecrawlJobId,
    pub status: String,
    pub pages: Vec<RawFirecrawlPage>,
    pub observed_at_ms: u64,
    pub cached_at_ms: Option<u64>,
    pub extraction_schema_digest: Digest,
    pub registration_digest: Digest,
    pub job_digest: Digest,
    pub response_digest: Digest,
    pub retry_after_seconds: Option<u64>,
    pub access_lost: bool,
    pub partial: bool,
    pub malformed: bool,
}

impl fmt::Debug for RawFirecrawlResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawFirecrawlResponse")
            .field("http_status", &self.http_status)
            .field("success", &self.success)
            .field("provider_job_id", &self.provider_job_id)
            .field("status", &self.status)
            .field("pages", &self.pages)
            .field("observed_at_ms", &self.observed_at_ms)
            .field("cached_at_ms", &self.cached_at_ms)
            .field("extraction_schema_digest", &self.extraction_schema_digest)
            .field("registration_digest", &self.registration_digest)
            .field("job_digest", &self.job_digest)
            .field("response_digest", &self.response_digest)
            .field("retry_after_seconds", &self.retry_after_seconds)
            .field("access_lost", &self.access_lost)
            .field("partial", &self.partial)
            .field("malformed", &self.malformed)
            .finish()
    }
}

impl RawFirecrawlResponse {
    pub fn for_request(
        request: &FirecrawlJobRequest,
        provider_job_id: FirecrawlJobId,
        status: FirecrawlJobStatus,
        pages: Vec<RawFirecrawlPage>,
        observed_at_ms: u64,
        cached_at_ms: Option<u64>,
        registration_digest: Digest,
    ) -> Self {
        let extraction_schema_digest = request.job.extraction_schema_digest().clone();
        let job_digest = raw_job_digest(
            request,
            &provider_job_id,
            status,
            &extraction_schema_digest,
            &pages,
        );
        let response_digest = raw_response_digest(
            request,
            &job_digest,
            &registration_digest,
            observed_at_ms,
            cached_at_ms,
        );
        Self {
            http_status: 200,
            success: true,
            provider_job_id,
            status: status.to_string(),
            pages,
            observed_at_ms,
            cached_at_ms,
            extraction_schema_digest,
            registration_digest,
            job_digest,
            response_digest,
            retry_after_seconds: None,
            access_lost: false,
            partial: false,
            malformed: false,
        }
    }

    pub fn queued_for(request: &FirecrawlJobRequest, registration_digest: Digest) -> Self {
        Self::for_request(
            request,
            provider_job_id_for(request),
            FirecrawlJobStatus::Queued,
            Vec::new(),
            request.requested_at_ms,
            None,
            registration_digest,
        )
    }

    pub fn with_http_status(mut self, http_status: u16) -> Self {
        self.http_status = http_status;
        self.success = false;
        self
    }

    pub fn with_status(mut self, status: FirecrawlJobStatus) -> Self {
        self.status = status.to_string();
        self
    }

    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self
    }

    pub fn with_malformed(mut self, malformed: bool) -> Self {
        self.malformed = malformed;
        self
    }

    pub fn set_job_digest_tamper(&mut self, digest: Digest) {
        self.job_digest = digest;
    }

    pub fn set_response_digest_tamper(&mut self, digest: Digest) {
        self.response_digest = digest;
    }

    pub fn set_registration_digest_tamper(&mut self, digest: Digest) {
        self.registration_digest = digest;
    }

    pub fn set_access_lost(&mut self, access_lost: bool) {
        self.access_lost = access_lost;
    }

    pub fn set_retry_after_seconds(&mut self, retry_after_seconds: Option<u64>) {
        self.retry_after_seconds = retry_after_seconds;
    }
}

fn provider_job_id_for(request: &FirecrawlJobRequest) -> FirecrawlJobId {
    let digest = request.request_digest();
    FirecrawlJobId::new(format!("fc-{}", &digest[..16])).expect("bounded fixture job id")
}

fn raw_job_digest(
    request: &FirecrawlJobRequest,
    provider_job_id: &FirecrawlJobId,
    status: FirecrawlJobStatus,
    extraction_schema_digest: &str,
    pages: &[RawFirecrawlPage],
) -> Digest {
    let page_digests = pages
        .iter()
        .map(|page| page.page_digest.as_str())
        .collect::<Vec<_>>();
    digest_parts([
        request.request_digest().as_str(),
        provider_job_id.as_str(),
        &status.to_string(),
        extraction_schema_digest,
        &page_digests.join("|"),
    ])
}

fn raw_response_digest(
    request: &FirecrawlJobRequest,
    job_digest: &str,
    registration_digest: &str,
    observed_at_ms: u64,
    cached_at_ms: Option<u64>,
) -> Digest {
    digest_parts([
        request.request_digest().as_str(),
        job_digest,
        registration_digest,
        &observed_at_ms.to_string(),
        &cached_at_ms.map_or_else(String::new, |value| value.to_string()),
    ])
}

/// A transport implementation is deliberately local and cloneable. The
/// provider never has an implementation that opens a socket in Layer 1.
pub trait FirecrawlTransport: Clone + fmt::Debug + Send + Sync + 'static {
    fn provenance(&self) -> FirecrawlProvenance;

    fn bind_registration_digest(&self, _registration_digest: &str) {}

    fn operations(&self) -> Vec<FirecrawlTransportOperation> {
        Vec::new()
    }

    fn execute(
        &self,
        operation: &FirecrawlTransportOperation,
    ) -> Result<RawFirecrawlResponse, FirecrawlTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureFailure {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited { retry_after_seconds: Option<u64> },
    ServerFailure { status: u16 },
    Timeout,
    Malformed,
    Partial,
    ContentType,
    CitationMismatch,
    ContentDigestMismatch,
    JobDigestMismatch,
    ResponseDigestMismatch,
    RegistrationDigestMismatch,
    CacheExpired,
    AccessLost,
    Duplicate,
    ProviderUnknown,
    Status(FirecrawlJobStatus),
}

#[derive(Clone, Debug)]
struct FixtureState {
    provenance: FirecrawlProvenance,
    pages: Vec<RawFirecrawlPage>,
    failure: Option<FixtureFailure>,
    response_override: Option<RawFirecrawlResponse>,
    operations: Vec<FirecrawlTransportOperation>,
    cached_at_ms: Option<u64>,
    observed_at_ms: Option<u64>,
    registration_digest: Option<Digest>,
}

/// Fixture/recording/fake/loopback transport. It records only typed
/// operations and bounded projections; it never performs network I/O.
#[derive(Clone)]
pub struct FixtureFirecrawlTransport {
    state: Arc<Mutex<FixtureState>>,
}

pub type RecordingFirecrawlTransport = FixtureFirecrawlTransport;
pub type FakeFirecrawlTransport = FixtureFirecrawlTransport;
pub type LoopbackFirecrawlTransport = FixtureFirecrawlTransport;

impl fmt::Debug for FixtureFirecrawlTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().map_err(|_| fmt::Error)?;
        formatter
            .debug_struct("FixtureFirecrawlTransport")
            .field("provenance", &state.provenance)
            .field("page_count", &state.pages.len())
            .field("failure", &state.failure)
            .field("operation_count", &state.operations.len())
            .finish()
    }
}

impl FixtureFirecrawlTransport {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FixtureState {
                provenance: FirecrawlProvenance::Fixture,
                pages: Vec::new(),
                failure: None,
                response_override: None,
                operations: Vec::new(),
                cached_at_ms: None,
                observed_at_ms: None,
                registration_digest: None,
            })),
        }
    }

    pub fn fixture(seed: impl Into<FirecrawlFixture>) -> Self {
        Self::from_fixture(seed.into(), FirecrawlProvenance::Fixture)
    }

    pub fn recording(seed: impl Into<FirecrawlFixture>) -> Self {
        Self::from_fixture(seed.into(), FirecrawlProvenance::Recording)
    }

    pub fn fake(seed: impl Into<FirecrawlFixture>) -> Self {
        Self::from_fixture(seed.into(), FirecrawlProvenance::Fake)
    }

    pub fn loopback(seed: impl Into<FirecrawlFixture>) -> Self {
        Self::from_fixture(seed.into(), FirecrawlProvenance::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new().with_provenance(FirecrawlProvenance::BlockedEnv)
    }

    fn with_provenance(self, provenance: FirecrawlProvenance) -> Self {
        self.state.lock().expect("fixture mutex").provenance = provenance;
        self
    }

    fn from_fixture(fixture: FirecrawlFixture, provenance: FirecrawlProvenance) -> Self {
        let transport = Self::new().with_provenance(provenance);
        transport.update_fixture(|current| {
            current.pages = fixture.pages;
            current.failure = fixture.failure;
            current.response_override = fixture.response_override;
            current.cached_at_ms = fixture.cached_at_ms;
            current.observed_at_ms = fixture.observed_at_ms;
        });
        transport
    }

    pub fn with_failure(self, failure: FixtureFailure) -> Self {
        self.state.lock().expect("fixture mutex").failure = Some(failure);
        self
    }

    pub fn clear_failure(&self) {
        self.state.lock().expect("fixture mutex").failure = None;
    }

    pub fn insert_page(&self, page: RawFirecrawlPage) {
        self.state.lock().expect("fixture mutex").pages.push(page);
    }

    pub fn set_pages(&self, pages: Vec<RawFirecrawlPage>) {
        self.state.lock().expect("fixture mutex").pages = pages;
    }

    pub fn set_cached_at_ms(&self, cached_at_ms: Option<u64>) {
        self.state.lock().expect("fixture mutex").cached_at_ms = cached_at_ms;
    }

    pub fn set_observed_at_ms(&self, observed_at_ms: Option<u64>) {
        self.state.lock().expect("fixture mutex").observed_at_ms = observed_at_ms;
    }

    pub fn set_response(&self, response: Option<RawFirecrawlResponse>) {
        self.state.lock().expect("fixture mutex").response_override = response;
    }

    pub fn update_fixture(&self, update: impl FnOnce(&mut FirecrawlFixture)) {
        let mut state = self.state.lock().expect("fixture mutex");
        let mut fixture = FirecrawlFixture {
            pages: state.pages.clone(),
            failure: state.failure.clone(),
            response_override: state.response_override.clone(),
            cached_at_ms: state.cached_at_ms,
            observed_at_ms: state.observed_at_ms,
        };
        update(&mut fixture);
        state.pages = fixture.pages;
        state.failure = fixture.failure;
        state.response_override = fixture.response_override;
        state.cached_at_ms = fixture.cached_at_ms;
        state.observed_at_ms = fixture.observed_at_ms;
    }

    pub fn operations(&self) -> Vec<FirecrawlTransportOperation> {
        self.state.lock().expect("fixture mutex").operations.clone()
    }
}

impl Default for FixtureFirecrawlTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct FirecrawlFixture {
    pub pages: Vec<RawFirecrawlPage>,
    pub failure: Option<FixtureFailure>,
    pub response_override: Option<RawFirecrawlResponse>,
    pub cached_at_ms: Option<u64>,
    pub observed_at_ms: Option<u64>,
}

impl FirecrawlFixture {
    pub fn new() -> Self {
        Self {
            pages: Vec::new(),
            failure: None,
            response_override: None,
            cached_at_ms: None,
            observed_at_ms: None,
        }
    }

    pub fn for_scope(_scope: crate::model::FirecrawlScope) -> Self {
        Self::new()
    }

    pub fn insert_page(&mut self, page: RawFirecrawlPage) {
        self.pages.push(page);
    }

    pub fn page_mut(&mut self, index: usize) -> Option<&mut RawFirecrawlPage> {
        self.pages.get_mut(index)
    }

    pub fn set_failure(&mut self, failure: Option<FixtureFailure>) {
        self.failure = failure;
    }
}

impl Default for FirecrawlFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl From<crate::model::FirecrawlScope> for FirecrawlFixture {
    fn from(scope: crate::model::FirecrawlScope) -> Self {
        Self::for_scope(scope)
    }
}

impl FirecrawlTransport for FixtureFirecrawlTransport {
    fn provenance(&self) -> FirecrawlProvenance {
        self.state.lock().expect("fixture mutex").provenance
    }

    fn bind_registration_digest(&self, registration_digest: &str) {
        self.state
            .lock()
            .expect("fixture mutex")
            .registration_digest = Some(registration_digest.to_owned());
    }

    fn operations(&self) -> Vec<FirecrawlTransportOperation> {
        FixtureFirecrawlTransport::operations(self)
    }

    fn execute(
        &self,
        operation: &FirecrawlTransportOperation,
    ) -> Result<RawFirecrawlResponse, FirecrawlTransportError> {
        let mut state = self.state.lock().expect("fixture mutex");
        state.operations.push(operation.clone());
        let request = operation.request();
        if let Some(failure) = &state.failure {
            return failure_response(
                request,
                failure,
                state.provenance,
                state.registration_digest.clone(),
            );
        }
        if let Some(response) = &state.response_override {
            return Ok(response.clone());
        }

        let pages = if state.pages.is_empty() {
            vec![RawFirecrawlPage::default_for(request.url())]
        } else if matches!(request.kind(), crate::model::FirecrawlJobKind::Scrape) {
            state.pages.iter().take(1).cloned().collect::<Vec<_>>()
        } else {
            state.pages.clone()
        };
        let status = match operation {
            FirecrawlTransportOperation::ReadJob { .. }
            | FirecrawlTransportOperation::SubmitCrawl { .. }
            | FirecrawlTransportOperation::SubmitScrape { .. } => FirecrawlJobStatus::Completed,
        };
        let registration_digest = state
            .registration_digest
            .clone()
            .unwrap_or_else(|| sha256_digest(b"fixture-registration-bound-at-provider"));
        let observed_at_ms = state
            .observed_at_ms
            .unwrap_or_else(|| request.requested_at_ms.saturating_add(1));
        Ok(RawFirecrawlResponse::for_request(
            request,
            provider_job_id_for(request),
            status,
            pages,
            observed_at_ms,
            state.cached_at_ms,
            registration_digest,
        ))
    }
}

fn failure_response(
    request: &FirecrawlJobRequest,
    failure: &FixtureFailure,
    provenance: FirecrawlProvenance,
    bound_registration_digest: Option<Digest>,
) -> Result<RawFirecrawlResponse, FirecrawlTransportError> {
    if matches!(failure, FixtureFailure::Timeout) {
        return Err(FirecrawlTransportError::Timeout);
    }
    let registration_digest = bound_registration_digest
        .unwrap_or_else(|| sha256_digest(b"fixture-registration-bound-at-provider"));
    let mut response = RawFirecrawlResponse::for_request(
        request,
        provider_job_id_for(request),
        FirecrawlJobStatus::ProviderUnknown,
        Vec::new(),
        request.requested_at_ms.saturating_add(1),
        None,
        registration_digest.clone(),
    );
    match failure {
        FixtureFailure::Unauthorized => response = response.with_http_status(401),
        FixtureFailure::Forbidden => response = response.with_http_status(403),
        FixtureFailure::AccessLost => {
            response = response.with_http_status(403);
            response.access_lost = true;
        }
        FixtureFailure::NotFound => response = response.with_http_status(404),
        FixtureFailure::Conflict | FixtureFailure::Duplicate => {
            response = response.with_http_status(409);
        }
        FixtureFailure::RateLimited {
            retry_after_seconds,
        } => {
            response = response.with_http_status(429);
            response.retry_after_seconds = *retry_after_seconds;
        }
        FixtureFailure::ServerFailure { status } => response = response.with_http_status(*status),
        FixtureFailure::Malformed => response = response.with_malformed(true),
        FixtureFailure::Partial => response = response.with_partial(true),
        FixtureFailure::ContentType => {
            let page = RawFirecrawlPage::new(
                request.url().clone(),
                "Fixture binary page",
                200,
                "application/pdf",
                "bounded text projection",
                request.job.extraction_schema_digest().clone(),
            )
            .expect("fixture content type response");
            response = RawFirecrawlResponse::for_request(
                request,
                provider_job_id_for(request),
                FirecrawlJobStatus::Completed,
                vec![page],
                request.requested_at_ms.saturating_add(1),
                None,
                registration_digest.clone(),
            );
        }
        FixtureFailure::CitationMismatch => {
            let mut page = RawFirecrawlPage::default_for(request.url());
            page.set_citation_digest_tamper(sha256_digest(b"citation-tamper"));
            response = RawFirecrawlResponse::for_request(
                request,
                provider_job_id_for(request),
                FirecrawlJobStatus::Completed,
                vec![page],
                request.requested_at_ms.saturating_add(1),
                None,
                registration_digest.clone(),
            );
        }
        FixtureFailure::ContentDigestMismatch => {
            let mut page = RawFirecrawlPage::default_for(request.url());
            page.set_content_digest_tamper(sha256_digest(b"content-tamper"));
            response = RawFirecrawlResponse::for_request(
                request,
                provider_job_id_for(request),
                FirecrawlJobStatus::Completed,
                vec![page],
                request.requested_at_ms.saturating_add(1),
                None,
                registration_digest.clone(),
            );
        }
        FixtureFailure::JobDigestMismatch => {
            response.set_job_digest_tamper(sha256_digest(b"job-tamper"));
        }
        FixtureFailure::ResponseDigestMismatch => {
            response.set_response_digest_tamper(sha256_digest(b"response-tamper"));
        }
        FixtureFailure::RegistrationDigestMismatch => {
            response.set_registration_digest_tamper(sha256_digest(b"registration-tamper"));
        }
        FixtureFailure::CacheExpired => {
            response.cached_at_ms = Some(request.requested_at_ms.saturating_sub(10 * 60 * 1_000));
            response.observed_at_ms = request.requested_at_ms;
        }
        FixtureFailure::ProviderUnknown => {
            response.status = String::from("future-provider-state");
        }
        FixtureFailure::Status(status) => {
            response = RawFirecrawlResponse::for_request(
                request,
                provider_job_id_for(request),
                *status,
                Vec::new(),
                request.requested_at_ms.saturating_add(1),
                None,
                registration_digest,
            );
        }
        FixtureFailure::Timeout => unreachable!("handled above"),
    }
    let _ = provenance;
    Ok(response)
}

/// Transport provenance helper for tests and diagnostics.
pub fn transport_digest(transport: &impl FirecrawlTransport) -> Digest {
    canonical_digest(&transport.provenance())
}

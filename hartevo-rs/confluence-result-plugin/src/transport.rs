use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::error::ConfluenceTransportError;
use crate::model::{
    BodyRepresentation, CloudId, ConfluenceContentId, ConfluencePageId, ConfluencePageReadRequest,
    ConfluenceScope, ConfluenceSearchRequest, ConfluenceSite, ConfluenceSpaceId, Digest, PageState,
    PageVersion, ProviderProvenance, sha256_digest,
};
use crate::provider::SecretMaterial;

/// Raw fixture values stay inside the provider seam. They are never copied to
/// Layer 1 evidence, receipts, or debug records; only their digests leave it.
#[derive(Clone)]
pub struct FixturePageLink {
    pub page_id: ConfluencePageId,
    pub content_id: ConfluenceContentId,
    pub title: String,
    pub position: u32,
}

impl fmt::Debug for FixturePageLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixturePageLink")
            .field("page_id", &self.page_id)
            .field("content_id", &self.content_id)
            .field("title_digest", &sha256_digest(self.title.as_bytes()))
            .field("position", &self.position)
            .finish()
    }
}

#[derive(Clone)]
pub struct FixturePage {
    pub site: ConfluenceSite,
    pub cloud_id: CloudId,
    pub account_id: crate::model::AtlassianAccountId,
    pub space_id: ConfluenceSpaceId,
    pub page_id: ConfluencePageId,
    pub content_id: ConfluenceContentId,
    pub title: String,
    pub body: String,
    pub body_representation: BodyRepresentation,
    pub labels: Vec<String>,
    pub ancestors: Vec<FixturePageLink>,
    pub children: Vec<FixturePageLink>,
    pub version: PageVersion,
    pub permission_digest: Digest,
    pub state: PageState,
    pub reported_body_digest: Option<Digest>,
    pub reported_metadata_digest: Option<Digest>,
    pub partial: bool,
    pub truncated: bool,
}

impl FixturePage {
    pub fn new(
        scope: &ConfluenceScope,
        title: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<Self, crate::error::ConfluenceKnowledgeResultError> {
        let title = title.into();
        let body = body.into();
        if title.trim().is_empty() || title.len() > 512 {
            return Err(crate::error::ConfluenceKnowledgeResultError::InvalidInput {
                field: "fixture title",
                reason: String::from("must be non-empty and bounded"),
            });
        }
        if body.len() > crate::model::MAX_BODY_BYTES {
            return Err(crate::error::ConfluenceKnowledgeResultError::InvalidInput {
                field: "fixture body",
                reason: String::from("exceeds the bounded body size"),
            });
        }
        Ok(Self {
            site: scope.site.clone(),
            cloud_id: scope.cloud_id.clone(),
            account_id: scope.account_id.clone(),
            space_id: scope.space_id.clone(),
            page_id: scope.page_id.clone(),
            content_id: scope.content_id.clone(),
            title,
            body,
            body_representation: scope.body_representation,
            labels: Vec::new(),
            ancestors: Vec::new(),
            children: Vec::new(),
            version: scope.page_version.clone(),
            permission_digest: scope.permission_digest.clone(),
            state: PageState::Current,
            reported_body_digest: None,
            reported_metadata_digest: None,
            partial: false,
            truncated: false,
        })
    }

    pub fn set_body_digest_tamper(&mut self, digest: Digest) {
        self.reported_body_digest = Some(digest);
    }

    pub fn set_metadata_digest_tamper(&mut self, digest: Digest) {
        self.reported_metadata_digest = Some(digest);
    }
}

impl fmt::Debug for FixturePage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixturePage")
            .field("site", &self.site)
            .field("cloud_id", &self.cloud_id)
            .field("account_id", &self.account_id)
            .field("space_id", &self.space_id)
            .field("page_id", &self.page_id)
            .field("content_id", &self.content_id)
            .field("title_digest", &sha256_digest(self.title.as_bytes()))
            .field("body_digest", &sha256_digest(self.body.as_bytes()))
            .field("body_byte_length", &self.body.len())
            .field("labels_count", &self.labels.len())
            .field("ancestors_count", &self.ancestors.len())
            .field("children_count", &self.children.len())
            .field("version", &self.version)
            .field("permission_digest", &self.permission_digest)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct ConfluenceFixture {
    pages: BTreeMap<String, FixturePage>,
}

impl fmt::Debug for ConfluenceFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfluenceFixture")
            .field("page_count", &self.pages.len())
            .field(
                "page_digests",
                &self
                    .pages
                    .keys()
                    .map(|page_id| sha256_digest(page_id.as_bytes()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ConfluenceFixture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_page(&mut self, page: FixturePage) {
        self.pages.insert(page.page_id.as_str().to_owned(), page);
    }

    pub fn page(&self, page_id: &ConfluencePageId) -> Option<&FixturePage> {
        self.pages.get(page_id.as_str())
    }

    pub fn page_mut(&mut self, page_id: &ConfluencePageId) -> Option<&mut FixturePage> {
        self.pages.get_mut(page_id.as_str())
    }

    pub(crate) fn pages(&self) -> impl Iterator<Item = &FixturePage> {
        self.pages.values()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureFailure {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited { retry_after_seconds: Option<u64> },
    Timeout,
    ServerFailure { status: u16 },
    Network,
    CqlRejected,
    InvalidCursor,
    PartialResponse,
    Truncated,
    Decode,
    Archived,
    Deleted,
    AccessLost,
}

impl From<FixtureFailure> for ConfluenceTransportError {
    fn from(failure: FixtureFailure) -> Self {
        match failure {
            FixtureFailure::Unauthorized => Self::Unauthorized,
            FixtureFailure::Forbidden => Self::Forbidden,
            FixtureFailure::NotFound => Self::NotFound,
            FixtureFailure::Conflict => Self::Conflict,
            FixtureFailure::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            FixtureFailure::Timeout => Self::Timeout,
            FixtureFailure::ServerFailure { status } => Self::ServerFailure { status },
            FixtureFailure::Network => Self::Network,
            FixtureFailure::CqlRejected => Self::CqlRejected,
            FixtureFailure::InvalidCursor => Self::InvalidCursor,
            FixtureFailure::PartialResponse => Self::PartialResponse,
            FixtureFailure::Truncated => Self::Truncated,
            FixtureFailure::Decode => Self::Decode,
            FixtureFailure::Archived | FixtureFailure::Deleted | FixtureFailure::AccessLost => {
                Self::NotFound
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfluenceTransportOperation {
    ReadPage {
        scope_digest: Digest,
    },
    Search {
        scope_digest: Digest,
        cql_digest: Digest,
        page: u32,
        cursor_digest: Option<Digest>,
    },
}

#[derive(Clone)]
pub struct RawPageResponse {
    pub page: FixturePage,
}

impl fmt::Debug for RawPageResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawPageResponse")
            .field("page", &self.page)
            .finish()
    }
}

#[derive(Clone)]
pub struct RawSearchHit {
    pub page: FixturePage,
    pub excerpt: String,
}

impl fmt::Debug for RawSearchHit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawSearchHit")
            .field("page", &self.page)
            .field("excerpt_digest", &sha256_digest(self.excerpt.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct RawSearchResponse {
    pub hits: Vec<RawSearchHit>,
    pub next_cursor: Option<String>,
    pub page: u32,
    pub total_count: usize,
    pub partial: bool,
    pub truncated: bool,
}

/// Layer 1 transport seam. Implementations are deliberately limited to
/// fixture, recording, loopback, and BLOCKED_ENV modes; no native HTTPS
/// implementation exists in this crate.
pub trait ConfluenceTransport: fmt::Debug + Send {
    fn read_page(
        &mut self,
        _secret: &SecretMaterial,
        request: &ConfluencePageReadRequest,
    ) -> Result<RawPageResponse, ConfluenceTransportError>;

    fn search_knowledge(
        &mut self,
        _secret: &SecretMaterial,
        request: &ConfluenceSearchRequest,
    ) -> Result<RawSearchResponse, ConfluenceTransportError>;

    fn provenance(&self) -> ProviderProvenance;
}

#[derive(Clone)]
pub struct FixtureConfluenceTransport {
    fixture: Arc<Mutex<ConfluenceFixture>>,
    provenance: ProviderProvenance,
    failure: Arc<Mutex<Option<FixtureFailure>>>,
    page_failures: Arc<Mutex<BTreeMap<String, FixtureFailure>>>,
    cursor_loop: Arc<Mutex<bool>>,
    operations: Arc<Mutex<Vec<ConfluenceTransportOperation>>>,
}

impl fmt::Debug for FixtureConfluenceTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureConfluenceTransport")
            .field("provenance", &self.provenance)
            .field("operations_count", &self.operations().len())
            .finish_non_exhaustive()
    }
}

#[allow(clippy::missing_panics_doc)]
impl FixtureConfluenceTransport {
    pub fn fixture(fixture: ConfluenceFixture) -> Self {
        Self::with_provenance(fixture, ProviderProvenance::Fixture)
    }

    pub fn recording(fixture: ConfluenceFixture) -> Self {
        Self::with_provenance(fixture, ProviderProvenance::Recording)
    }

    pub fn loopback(fixture: ConfluenceFixture) -> Self {
        Self::with_provenance(fixture, ProviderProvenance::Loopback)
    }

    fn with_provenance(fixture: ConfluenceFixture, provenance: ProviderProvenance) -> Self {
        Self {
            fixture: Arc::new(Mutex::new(fixture)),
            provenance,
            failure: Arc::new(Mutex::new(None)),
            page_failures: Arc::new(Mutex::new(BTreeMap::new())),
            cursor_loop: Arc::new(Mutex::new(false)),
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[must_use]
    pub fn with_failure(self, failure: FixtureFailure) -> Self {
        self.set_failure(failure);
        self
    }

    pub fn set_failure(&self, failure: FixtureFailure) {
        *self.failure.lock().expect("fixture failure lock") = Some(failure);
    }

    pub fn clear_failure(&self) {
        *self.failure.lock().expect("fixture failure lock") = None;
    }

    pub fn set_page_failure(&self, page_id: &ConfluencePageId, failure: FixtureFailure) {
        self.page_failures
            .lock()
            .expect("fixture page failure lock")
            .insert(page_id.as_str().to_owned(), failure);
    }

    pub fn set_cursor_loop(&self, enabled: bool) {
        *self.cursor_loop.lock().expect("fixture cursor loop lock") = enabled;
    }

    pub fn update_fixture<F>(&self, update: F)
    where
        F: FnOnce(&mut ConfluenceFixture),
    {
        update(&mut self.fixture.lock().expect("fixture lock"));
    }

    pub fn operations(&self) -> Vec<ConfluenceTransportOperation> {
        self.operations
            .lock()
            .expect("fixture operations lock")
            .clone()
    }

    fn configured_failure(&self, page_id: Option<&ConfluencePageId>) -> Option<FixtureFailure> {
        page_id
            .and_then(|page_id| {
                self.page_failures
                    .lock()
                    .expect("fixture page failure lock")
                    .get(page_id.as_str())
                    .cloned()
            })
            .or_else(|| self.failure.lock().expect("fixture failure lock").clone())
    }

    fn record(&self, operation: ConfluenceTransportOperation) {
        self.operations
            .lock()
            .expect("fixture operations lock")
            .push(operation);
    }
}

impl ConfluenceTransport for FixtureConfluenceTransport {
    fn read_page(
        &mut self,
        _secret: &SecretMaterial,
        request: &ConfluencePageReadRequest,
    ) -> Result<RawPageResponse, ConfluenceTransportError> {
        self.record(ConfluenceTransportOperation::ReadPage {
            scope_digest: request.scope.digest(),
        });
        if let Some(failure) = self.configured_failure(Some(&request.scope.page_id)) {
            match failure {
                FixtureFailure::Archived => {
                    let mut page = self
                        .fixture
                        .lock()
                        .expect("fixture lock")
                        .page(&request.scope.page_id)
                        .cloned()
                        .ok_or(ConfluenceTransportError::NotFound)?;
                    page.state = PageState::Archived;
                    return Ok(RawPageResponse { page });
                }
                FixtureFailure::Deleted => {
                    return Err(ConfluenceTransportError::NotFound);
                }
                FixtureFailure::AccessLost => {
                    return Err(ConfluenceTransportError::Forbidden);
                }
                other => return Err(other.into()),
            }
        }
        let page = self
            .fixture
            .lock()
            .expect("fixture lock")
            .page(&request.scope.page_id)
            .cloned()
            .ok_or(ConfluenceTransportError::NotFound)?;
        Ok(RawPageResponse { page })
    }

    fn search_knowledge(
        &mut self,
        _secret: &SecretMaterial,
        request: &ConfluenceSearchRequest,
    ) -> Result<RawSearchResponse, ConfluenceTransportError> {
        let page_number = request.cursor.as_ref().map_or(1, |cursor| cursor.page + 1);
        self.record(ConfluenceTransportOperation::Search {
            scope_digest: request.scope.digest(),
            cql_digest: request.cql_template.digest(),
            page: page_number,
            cursor_digest: request
                .cursor
                .as_ref()
                .map(crate::model::ConfluenceSearchCursor::digest),
        });
        if let Some(failure) = self.configured_failure(None) {
            return Err(failure.into());
        }
        let offset = if let Some(cursor) = &request.cursor {
            cursor
                .token()
                .strip_prefix("fixture-page-")
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(ConfluenceTransportError::InvalidCursor)?
        } else {
            0
        };
        let phrase = request.cql_template.phrase().to_ascii_lowercase();
        let mut hits = self
            .fixture
            .lock()
            .expect("fixture lock")
            .pages()
            .filter(|page| {
                page.space_id == request.scope.space_id
                    && page.state == PageState::Current
                    && (page.title.to_ascii_lowercase().contains(&phrase)
                        || page.body.to_ascii_lowercase().contains(&phrase))
            })
            .cloned()
            .collect::<Vec<_>>();
        hits.sort_by(|left, right| left.page_id.cmp(&right.page_id));
        if offset > hits.len() {
            return Err(ConfluenceTransportError::InvalidCursor);
        }
        let total_count = hits.len();
        let page_size = request.page_size as usize;
        let page_hits = hits
            .drain(offset..hits.len().min(offset + page_size))
            .collect::<Vec<_>>();
        let next_cursor = if offset + page_hits.len() < total_count {
            if *self.cursor_loop.lock().expect("fixture cursor loop lock") {
                request
                    .cursor
                    .as_ref()
                    .map(|cursor| cursor.token().to_owned())
                    .or_else(|| Some(String::from("fixture-page-0")))
            } else {
                Some(format!("fixture-page-{}", offset + page_hits.len()))
            }
        } else {
            None
        };
        let raw_hits = page_hits
            .into_iter()
            .map(|page| {
                let excerpt = page.body.chars().take(256).collect::<String>();
                RawSearchHit { page, excerpt }
            })
            .collect::<Vec<_>>();
        Ok(RawSearchResponse {
            hits: raw_hits,
            next_cursor,
            page: page_number,
            total_count,
            partial: false,
            truncated: false,
        })
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance.clone()
    }
}

pub type FakeConfluenceTransport = FixtureConfluenceTransport;
pub type RecordingConfluenceTransport = FixtureConfluenceTransport;
pub type LoopbackConfluenceTransport = FixtureConfluenceTransport;

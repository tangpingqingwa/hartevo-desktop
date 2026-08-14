use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::{
    FirecrawlCredentialError, FirecrawlProviderError, FirecrawlResearchEvidenceError,
    FirecrawlTransportError,
};
use crate::model::{
    CanonicalUrl, Digest, FirecrawlJobDescription, FirecrawlJobKind, FirecrawlJobRequest,
    FirecrawlJobStatus, FirecrawlPageEvidence, FirecrawlPluginRegistration, FirecrawlProvenance,
    FirecrawlProviderManifest, FirecrawlResearchEvidence, FirecrawlScope, FirecrawlUrlDescription,
    NativeStatus, SecretReference, content_type_is_allowed, validate_digest,
};
use crate::transport::{
    FirecrawlTransport, FirecrawlTransportOperation, FixtureFirecrawlTransport, RawFirecrawlPage,
    RawFirecrawlResponse,
};

/// Credential bytes are accepted only inside a local test resolver and are
/// never serializable or exposed by Debug. Layer 1 does not resolve native
/// credentials.
pub struct SecretMaterial(String);

impl SecretMaterial {
    pub fn new(value: impl Into<String>) -> Result<Self, FirecrawlCredentialError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(FirecrawlCredentialError::Unavailable);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(REDACTED)")
    }
}

pub trait FirecrawlCredentialResolver: Clone + fmt::Debug + Send + Sync + 'static {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, FirecrawlCredentialError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl FirecrawlCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, FirecrawlCredentialError> {
        Err(FirecrawlCredentialError::BlockedEnv)
    }
}

#[derive(Clone)]
pub struct StaticFirecrawlCredentialResolver {
    material: Arc<SecretMaterial>,
}

impl StaticFirecrawlCredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            material: Arc::new(SecretMaterial::new(value).expect("static fixture secret")),
        }
    }
}

impl fmt::Debug for StaticFirecrawlCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticFirecrawlCredentialResolver(REDACTED)")
    }
}

impl FirecrawlCredentialResolver for StaticFirecrawlCredentialResolver {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, FirecrawlCredentialError> {
        reference
            .validate()
            .map_err(|_| FirecrawlCredentialError::Unavailable)?;
        Ok(SecretMaterial(self.material.0.clone()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirecrawlProviderState {
    Active,
    Revoked,
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlProviderCall {
    pub operation: FirecrawlTransportOperation,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlRequestPlan {
    pub method: String,
    pub endpoint: String,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub secret_reference_required: bool,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body_digest: Digest,
    pub external_write: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone)]
pub struct FirecrawlProvider<
    T: FirecrawlTransport = FixtureFirecrawlTransport,
    R: FirecrawlCredentialResolver = BlockedEnvCredentialResolver,
> {
    manifest: FirecrawlProviderManifest,
    transport: T,
    credentials: R,
    state: FirecrawlProviderState,
    seen_request_digests: Arc<Mutex<BTreeSet<Digest>>>,
    seen_job_ids: Arc<Mutex<BTreeSet<crate::model::FirecrawlJobId>>>,
}

impl<T, R> fmt::Debug for FirecrawlProvider<T, R>
where
    T: FirecrawlTransport,
    R: FirecrawlCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirecrawlProvider")
            .field("provider_id", &self.manifest.provider_id)
            .field("provider_version", &self.manifest.provider_version)
            .field("scope_digest", &self.manifest.scope_digest)
            .field(
                "registration_digest",
                &self.manifest.registration.registration_digest,
            )
            .field("native_status", &self.manifest.native_status)
            .field("state", &self.state)
            .field("transport", &self.transport)
            .field("credentials", &self.credentials)
            .field("seen_request_digests", &"redacted")
            .field("seen_job_ids", &"redacted")
            .finish()
    }
}

impl<T, R> FirecrawlProvider<T, R>
where
    T: FirecrawlTransport,
    R: FirecrawlCredentialResolver,
{
    pub fn new(
        manifest: FirecrawlProviderManifest,
        transport: T,
        credentials: R,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        let scope_digest = manifest.scope_digest.clone();
        let registration_digest = manifest.registration.registration_digest.clone();
        validate_digest(&scope_digest, "scope_digest")?;
        validate_digest(&registration_digest, "registration_digest")?;
        let state = if manifest.registration.enabled {
            FirecrawlProviderState::Active
        } else {
            FirecrawlProviderState::Revoked
        };
        transport.bind_registration_digest(&registration_digest);
        Ok(Self {
            manifest,
            transport,
            credentials,
            state,
            seen_request_digests: Arc::new(Mutex::new(BTreeSet::new())),
            seen_job_ids: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    pub fn provider_manifest(&self) -> &FirecrawlProviderManifest {
        &self.manifest
    }

    pub fn manifest(&self) -> &FirecrawlProviderManifest {
        &self.manifest
    }

    pub fn registration(&self) -> &FirecrawlPluginRegistration {
        &self.manifest.registration
    }

    pub fn state(&self) -> &FirecrawlProviderState {
        &self.state
    }

    pub fn provenance(&self) -> FirecrawlProvenance {
        self.transport.provenance()
    }

    pub const fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
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

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn calls(&self) -> Vec<FirecrawlProviderCall> {
        self.transport
            .operations()
            .into_iter()
            .map(|operation| FirecrawlProviderCall {
                request_digest: operation.request().request_digest(),
                operation,
            })
            .collect()
    }

    pub fn revoke(
        &mut self,
    ) -> Result<FirecrawlRegistrationRevocation, FirecrawlResearchEvidenceError> {
        let previous = self.manifest.registration.registration_digest.clone();
        self.manifest = self.manifest.revoked()?;
        self.state = FirecrawlProviderState::Revoked;
        self.transport
            .bind_registration_digest(&self.manifest.registration.registration_digest);
        Ok(FirecrawlRegistrationRevocation {
            revoked: true,
            previous_registration_digest: previous,
            registration_digest: self.manifest.registration.registration_digest.clone(),
            revocation_revision: self.manifest.registration.registration_revision,
        })
    }

    pub fn reactivate(&mut self) -> Result<(), FirecrawlResearchEvidenceError> {
        self.manifest = self.manifest.reactivated()?;
        self.state = FirecrawlProviderState::Active;
        self.transport
            .bind_registration_digest(&self.manifest.registration.registration_digest);
        Ok(())
    }

    pub fn request_plan(
        &self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlRequestPlan, FirecrawlResearchEvidenceError> {
        request.validate()?;
        if request.scope.digest() != self.manifest.scope_digest {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        let endpoint = match request.kind() {
            FirecrawlJobKind::Scrape => format!(
                "{}{}",
                self.manifest.api_base_url,
                crate::model::FIRECRAWL_SCRAPE_PATH
            ),
            FirecrawlJobKind::Crawl => format!(
                "{}{}",
                self.manifest.api_base_url,
                crate::model::FIRECRAWL_CRAWL_PATH
            ),
        };
        let mut headers = std::collections::BTreeMap::new();
        headers.insert(
            String::from("Authorization"),
            String::from("Bearer <opaque-secret-reference>"),
        );
        headers.insert(
            String::from("Content-Type"),
            String::from("application/json"),
        );
        Ok(FirecrawlRequestPlan {
            method: String::from("POST"),
            endpoint,
            request_digest: request.request_digest(),
            scope_digest: request.scope.digest(),
            registration_digest: self.manifest.registration.registration_digest.clone(),
            permission_digest: self.manifest.registration.permission_digest.clone(),
            secret_reference_digest: self.manifest.secret_reference.digest(),
            secret_reference_required: true,
            headers,
            body_digest: crate::model::canonical_digest(request),
            external_write: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn describe_url(
        &self,
        url: CanonicalUrl,
        scope: &FirecrawlScope,
    ) -> Result<FirecrawlUrlDescription, FirecrawlResearchEvidenceError> {
        self.ensure_scope(scope)?;
        if !scope.permits(&url) {
            return Err(FirecrawlResearchEvidenceError::UrlNotAllowlisted {
                url: url.to_string(),
            });
        }
        FirecrawlUrlDescription::for_scope(url, scope)
    }

    pub fn describe_job(
        &self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlJobDescription, FirecrawlResearchEvidenceError> {
        self.ensure_scope(&request.scope)?;
        Ok(FirecrawlJobDescription::from_request(request))
    }

    pub fn read(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.execute(request)
    }

    pub fn scrape(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        if request.kind() != FirecrawlJobKind::Scrape {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "job_kind",
                reason: String::from("scrape requires a scrape job"),
            });
        }
        self.execute(request)
    }

    pub fn crawl(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        if request.kind() != FirecrawlJobKind::Crawl {
            return Err(FirecrawlResearchEvidenceError::InvalidInput {
                field: "job_kind",
                reason: String::from("crawl requires a crawl job"),
            });
        }
        self.execute(request)
    }

    pub fn poll(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.ensure_scope(&request.scope)?;
        request.validate()?;
        self.ensure_active()?;
        self.resolve_secret()?;
        let operation = FirecrawlTransportOperation::ReadJob {
            request: request.clone(),
        };
        let raw = self
            .transport
            .execute(&operation)
            .map_err(map_transport_error)?;
        self.project_response(request, raw)
    }

    fn execute(
        &mut self,
        request: &FirecrawlJobRequest,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        self.ensure_scope(&request.scope)?;
        request.validate()?;
        self.ensure_active()?;
        self.resolve_secret()?;
        let request_digest = request.request_digest();
        {
            let mut seen = self
                .seen_request_digests
                .lock()
                .map_err(|_| FirecrawlResearchEvidenceError::ReplayDetected)?;
            if !seen.insert(request_digest) {
                return Err(FirecrawlResearchEvidenceError::ReplayDetected);
            }
        }
        {
            let mut seen = self
                .seen_job_ids
                .lock()
                .map_err(|_| FirecrawlResearchEvidenceError::DuplicateJob)?;
            if !seen.insert(request.job_id.clone()) {
                return Err(FirecrawlResearchEvidenceError::DuplicateJob);
            }
        }
        let operation = match request.kind() {
            FirecrawlJobKind::Scrape => FirecrawlTransportOperation::SubmitScrape {
                request: request.clone(),
            },
            FirecrawlJobKind::Crawl => FirecrawlTransportOperation::SubmitCrawl {
                request: request.clone(),
            },
        };
        let raw = self
            .transport
            .execute(&operation)
            .map_err(map_transport_error)?;
        self.project_response(request, raw)
    }

    fn project_response(
        &self,
        request: &FirecrawlJobRequest,
        raw: RawFirecrawlResponse,
    ) -> Result<FirecrawlResearchEvidence, FirecrawlResearchEvidenceError> {
        if raw.http_status == 408 {
            return Err(FirecrawlResearchEvidenceError::Timeout);
        }
        if raw.http_status != 200 && raw.http_status != 202 {
            if raw.access_lost {
                return Err(FirecrawlResearchEvidenceError::AccessLost);
            }
            let error =
                FirecrawlProviderError::from_status(raw.http_status, raw.retry_after_seconds);
            return Err(FirecrawlResearchEvidenceError::Provider(error));
        }
        if raw.malformed {
            return Err(FirecrawlResearchEvidenceError::MalformedResponse);
        }
        if raw.partial {
            return Err(FirecrawlResearchEvidenceError::PartialResponse);
        }
        if !raw.success {
            return Err(FirecrawlResearchEvidenceError::MalformedResponse);
        }
        if raw.registration_digest != self.manifest.registration.registration_digest {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        if raw.extraction_schema_digest != *request.job.extraction_schema_digest() {
            return Err(FirecrawlResearchEvidenceError::ExtractionSchemaDigestMismatch);
        }
        self.validate_cache(request, raw.cached_at_ms, raw.observed_at_ms)?;
        if raw.pages.len() > request.job.max_pages() as usize {
            return Err(FirecrawlResearchEvidenceError::CrawlLimitExceeded {
                field: "response_pages",
            });
        }
        let status = FirecrawlJobStatus::parse(&raw.status);
        let mut pages = Vec::with_capacity(raw.pages.len());
        for raw_page in &raw.pages {
            if !request.scope.permits(&raw_page.canonical_url) {
                return Err(FirecrawlResearchEvidenceError::UrlNotAllowlisted {
                    url: raw_page.canonical_url.to_string(),
                });
            }
            let page = self.project_page(request, raw_page)?;
            pages.push(page);
        }
        if status.is_source_evidence() && pages.is_empty() {
            return Err(FirecrawlResearchEvidenceError::MalformedResponse);
        }
        if status.is_source_evidence()
            && request.kind() == FirecrawlJobKind::Scrape
            && pages.len() != 1
        {
            return Err(FirecrawlResearchEvidenceError::PartialResponse);
        }
        let evidence = FirecrawlResearchEvidence::from_parts(
            request,
            raw.provider_job_id,
            status,
            pages,
            raw.extraction_schema_digest,
            raw.observed_at_ms,
            raw.cached_at_ms,
            raw.registration_digest,
            self.provenance(),
        )?;
        if evidence.job_digest != raw.job_digest {
            return Err(FirecrawlResearchEvidenceError::JobDigestMismatch);
        }
        if evidence.response_digest != raw.response_digest {
            return Err(FirecrawlResearchEvidenceError::ContentDigestMismatch);
        }
        Ok(evidence)
    }

    fn project_page(
        &self,
        request: &FirecrawlJobRequest,
        raw: &RawFirecrawlPage,
    ) -> Result<FirecrawlPageEvidence, FirecrawlResearchEvidenceError> {
        if raw.markdown.len() > request.job.max_markdown_bytes() {
            return Err(FirecrawlResearchEvidenceError::ContentTooLarge);
        }
        if !content_type_is_allowed(&raw.content_type) {
            return Err(FirecrawlResearchEvidenceError::ContentTypeRefused {
                content_type: raw.content_type.clone(),
            });
        }
        let page = FirecrawlPageEvidence::new(
            raw.canonical_url.clone(),
            raw.title.clone(),
            raw.status_code,
            raw.content_type.clone(),
            raw.markdown.clone(),
            raw.extraction_schema_digest.clone(),
        )?;
        if raw.content_digest != page.content_digest {
            return Err(FirecrawlResearchEvidenceError::ContentDigestMismatch);
        }
        if raw.snippet_digest != page.snippet_digest
            || raw.citation_digest != page.citation.citation_digest
        {
            return Err(FirecrawlResearchEvidenceError::CitationMismatch);
        }
        if raw.page_digest != page.page_digest {
            return Err(FirecrawlResearchEvidenceError::PageDigestMismatch);
        }
        Ok(page)
    }

    fn validate_cache(
        &self,
        request: &FirecrawlJobRequest,
        cached_at_ms: Option<u64>,
        observed_at_ms: u64,
    ) -> Result<(), FirecrawlResearchEvidenceError> {
        let cache_mode = match &request.job {
            crate::model::FirecrawlJobSpec::Scrape { options, .. } => options.cache.mode,
            crate::model::FirecrawlJobSpec::Crawl { options, .. } => options.cache.mode,
        };
        match (cache_mode, cached_at_ms) {
            (crate::model::FirecrawlCacheMode::BypassCache, Some(_)) => {
                Err(FirecrawlResearchEvidenceError::CacheExpired)
            }
            (crate::model::FirecrawlCacheMode::RequireCache, None) => {
                Err(FirecrawlResearchEvidenceError::CacheMiss)
            }
            (_, Some(cached_at)) if cached_at > observed_at_ms => {
                Err(FirecrawlResearchEvidenceError::MalformedResponse)
            }
            (_, Some(cached_at))
                if observed_at_ms.saturating_sub(cached_at) > request.job.max_age_ms() =>
            {
                Err(FirecrawlResearchEvidenceError::CacheExpired)
            }
            _ => Ok(()),
        }
    }

    fn ensure_scope(&self, scope: &FirecrawlScope) -> Result<(), FirecrawlResearchEvidenceError> {
        scope.validate()?;
        if scope.digest() != self.manifest.scope_digest {
            return Err(FirecrawlResearchEvidenceError::RegistrationDigestMismatch);
        }
        if scope.permission_digest != self.manifest.registration.permission_digest
            || scope.permission_revision != self.manifest.registration.permission_revision
        {
            return Err(FirecrawlResearchEvidenceError::PermissionDigestMismatch);
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), FirecrawlResearchEvidenceError> {
        match self.state {
            FirecrawlProviderState::Active => Ok(()),
            FirecrawlProviderState::Revoked => Err(FirecrawlResearchEvidenceError::Provider(
                FirecrawlProviderError::RegistrationRevoked,
            )),
            FirecrawlProviderState::BlockedEnv => Err(FirecrawlResearchEvidenceError::Provider(
                FirecrawlProviderError::BlockedEnv,
            )),
        }
    }

    fn resolve_secret(&self) -> Result<SecretMaterial, FirecrawlResearchEvidenceError> {
        match self.credentials.resolve(&self.manifest.secret_reference) {
            Ok(material) => Ok(material),
            Err(FirecrawlCredentialError::BlockedEnv) => Err(
                FirecrawlResearchEvidenceError::Provider(FirecrawlProviderError::BlockedEnv),
            ),
            Err(error) => Err(FirecrawlResearchEvidenceError::Credential(error)),
        }
    }
}

impl<T, R> FirecrawlProvider<T, R>
where
    T: FirecrawlTransport,
    R: FirecrawlCredentialResolver,
{
    pub fn validate_manifest(
        &self,
        scope: &FirecrawlScope,
    ) -> Result<(), FirecrawlResearchEvidenceError> {
        self.manifest.validate(scope)
    }
}

impl FirecrawlProvider<FixtureFirecrawlTransport, BlockedEnvCredentialResolver> {
    pub fn from_manifest(
        manifest: FirecrawlProviderManifest,
    ) -> Result<Self, FirecrawlResearchEvidenceError> {
        Self::new(
            manifest,
            FixtureFirecrawlTransport::new(),
            BlockedEnvCredentialResolver,
        )
    }
}

impl FirecrawlProvider<FixtureFirecrawlTransport, StaticFirecrawlCredentialResolver> {
    pub fn fixture(scope: FirecrawlScope) -> Result<Self, FirecrawlResearchEvidenceError> {
        let manifest = FirecrawlProviderManifest::fixture(&scope)?;
        Self::new(
            manifest,
            FixtureFirecrawlTransport::fixture(scope),
            StaticFirecrawlCredentialResolver::new("fixture-api-key-not-for-logs"),
        )
    }

    pub fn recording(scope: FirecrawlScope) -> Result<Self, FirecrawlResearchEvidenceError> {
        let manifest = FirecrawlProviderManifest::fixture(&scope)?;
        Self::new(
            manifest,
            FixtureFirecrawlTransport::recording(scope),
            StaticFirecrawlCredentialResolver::new("recording-api-key-not-for-logs"),
        )
    }

    pub fn fake(scope: FirecrawlScope) -> Result<Self, FirecrawlResearchEvidenceError> {
        let manifest = FirecrawlProviderManifest::fixture(&scope)?;
        Self::new(
            manifest,
            FixtureFirecrawlTransport::fake(scope),
            StaticFirecrawlCredentialResolver::new("fake-api-key-not-for-logs"),
        )
    }

    pub fn loopback(scope: FirecrawlScope) -> Result<Self, FirecrawlResearchEvidenceError> {
        let manifest = FirecrawlProviderManifest::fixture(&scope)?;
        Self::new(
            manifest,
            FixtureFirecrawlTransport::loopback(scope),
            StaticFirecrawlCredentialResolver::new("loopback-api-key-not-for-logs"),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FirecrawlRegistrationRevocation {
    pub revoked: bool,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub revocation_revision: u64,
}

fn map_transport_error(error: FirecrawlTransportError) -> FirecrawlResearchEvidenceError {
    match error {
        FirecrawlTransportError::Timeout => FirecrawlResearchEvidenceError::Timeout,
        other => FirecrawlResearchEvidenceError::Transport(other),
    }
}

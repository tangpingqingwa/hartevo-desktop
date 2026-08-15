use serde::{Deserialize, Serialize};

use crate::error::{HerokuDeploymentError, HerokuTransportError, Result};
use crate::model::{
    BackoffReceipt, Digest, HerokuAppProjection, HerokuAppState, HerokuBuildProjection,
    HerokuBuildStatus, HerokuDeploymentScope, HerokuDynoProjection, HerokuDynoState,
    HerokuReleaseProjection, HerokuReleaseStatus, HerokuSlugProjection, HerokuSlugStatus,
    MAX_BACKOFF_SECONDS, MAX_PAGES, ProviderProvenance, Revision, SecretReference,
};
use crate::transport::{
    HerokuOperation, HerokuRequest, HerokuResponse, HerokuTransport, RetryPolicy,
};
use crate::{CONTRACT_DIGEST, CONTRACT_SCHEMA, CONTRACT_VERSION, PROVIDER_ID, PROVIDER_VERSION};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuProviderDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub base_url: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub live_external_io: bool,
    pub external_writes: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
}

impl Default for HerokuProviderDefinition {
    fn default() -> Self {
        let contract_digest = Digest::parse(CONTRACT_DIGEST).expect("static contract digest");
        let operations = vec![
            "GET /apps/{app_id_or_name}".to_owned(),
            "GET /apps/{app_id_or_name}/builds/{build_id}".to_owned(),
            "GET /apps/{app_id_or_name}/releases".to_owned(),
            "GET /apps/{app_id_or_name}/slugs/{slug_id}".to_owned(),
            "GET /apps/{app_id_or_name}/dynos/{dyno_id_or_name}".to_owned(),
        ];
        let provider_digest = Digest::from_parts(
            "heroku-provider-definition/v1",
            &[
                ("provider", PROVIDER_ID.to_owned()),
                ("version", PROVIDER_VERSION.to_owned()),
                ("api", HEROKU_PROVIDER_API_REVISION.to_owned()),
                ("base_url", HEROKU_API_BASE_URL.to_owned()),
                ("operations", operations.join("\u{1f}")),
                ("contract", contract_digest.as_str().to_owned()),
            ],
        );
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            api_revision: HEROKU_PROVIDER_API_REVISION.to_owned(),
            base_url: HEROKU_API_BASE_URL.to_owned(),
            operations,
            read_only: true,
            live_external_io: false,
            external_writes: false,
            native: false,
            connected: false,
            first_party: false,
            contract_digest,
            provider_digest,
        }
    }
}

impl HerokuProviderDefinition {
    #[must_use]
    pub fn is_layer_one_honest(&self) -> bool {
        self.read_only
            && !self.live_external_io
            && !self.external_writes
            && !self.native
            && !self.connected
            && !self.first_party
    }
}

pub const HEROKU_PROVIDER_API_REVISION: &str = "heroku-platform-api-v3-metadata-v1";
pub const HEROKU_API_BASE_URL: &str = "https://api.heroku.com";
pub const HEROKU_OFFICIAL_API_REFERENCE: &str =
    "https://devcenter.heroku.com/articles/platform-api-reference";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HerokuAppFixture {
    pub id: String,
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub team_id: String,
    pub region: String,
    pub state: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

impl HerokuAppFixture {
    #[must_use]
    pub fn released(scope: &HerokuDeploymentScope) -> Self {
        Self {
            id: scope.app_id().as_str().to_owned(),
            account_id: scope.account_id().as_str().to_owned(),
            team_id: scope.team_id().as_str().to_owned(),
            region: scope.region().as_str().to_owned(),
            state: "active".to_owned(),
            updated_at: "fixture-app-updated".to_owned(),
            revision: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HerokuBuildFixture {
    pub id: String,
    pub app_id: String,
    pub status: String,
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub output_digest: String,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

impl HerokuBuildFixture {
    #[must_use]
    pub fn succeeded(scope: &HerokuDeploymentScope) -> Self {
        Self {
            id: scope.build_id().as_str().to_owned(),
            app_id: scope.app_id().as_str().to_owned(),
            status: "succeeded".to_owned(),
            commit: scope.commit_digest().as_str().to_owned(),
            created_at: "fixture-build-created".to_owned(),
            output_digest: "fixture-build-output".to_owned(),
            revision: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HerokuReleaseFixture {
    pub id: String,
    pub app_id: String,
    pub version: u64,
    pub status: String,
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

impl HerokuReleaseFixture {
    #[must_use]
    pub fn released(scope: &HerokuDeploymentScope) -> Self {
        Self {
            id: scope.release_id().as_str().to_owned(),
            app_id: scope.app_id().as_str().to_owned(),
            version: 7,
            status: "released".to_owned(),
            commit: scope.commit_digest().as_str().to_owned(),
            created_at: "fixture-release-created".to_owned(),
            description: "fixture release metadata".to_owned(),
            revision: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HerokuReleasePageFixture {
    pub app_id: String,
    pub releases: Vec<HerokuReleaseFixture>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

impl HerokuReleasePageFixture {
    #[must_use]
    pub fn released(scope: &HerokuDeploymentScope) -> Self {
        Self {
            app_id: scope.app_id().as_str().to_owned(),
            releases: vec![HerokuReleaseFixture::released(scope)],
            next_cursor: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HerokuSlugFixture {
    pub id: String,
    pub app_id: String,
    pub checksum: String,
    pub size_bytes: u64,
    pub state: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

impl HerokuSlugFixture {
    #[must_use]
    pub fn ready(scope: &HerokuDeploymentScope) -> Self {
        Self {
            id: scope.slug_id().as_str().to_owned(),
            app_id: scope.app_id().as_str().to_owned(),
            checksum: "fixture-slug-checksum".to_owned(),
            size_bytes: 4096,
            state: "ready".to_owned(),
            created_at: "fixture-slug-created".to_owned(),
            revision: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HerokuDynoFixture {
    pub id: String,
    pub app_id: String,
    pub release_id: String,
    pub region: String,
    pub state: String,
    #[serde(default)]
    pub size: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

impl HerokuDynoFixture {
    #[must_use]
    pub fn up(scope: &HerokuDeploymentScope) -> Self {
        Self {
            id: scope.dyno_id().as_str().to_owned(),
            app_id: scope.app_id().as_str().to_owned(),
            release_id: scope.release_id().as_str().to_owned(),
            region: scope.region().as_str().to_owned(),
            state: "up".to_owned(),
            size: "standard-1x".to_owned(),
            updated_at: "fixture-dyno-updated".to_owned(),
            revision: 1,
        }
    }
}

fn default_revision() -> u64 {
    1
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuProviderSnapshot {
    pub app: HerokuAppProjection,
    pub build: HerokuBuildProjection,
    pub release: HerokuReleaseProjection,
    pub slug: HerokuSlugProjection,
    pub dyno: HerokuDynoProjection,
    pub page_count: u16,
    pub cursor_digests: Vec<Digest>,
    pub backoff: Option<BackoffReceipt>,
    pub provenance: ProviderProvenance,
}

impl HerokuProviderSnapshot {
    pub(crate) fn validate(&self) -> Result<()> {
        self.app.validate()?;
        self.build.validate()?;
        self.release.validate()?;
        self.slug.validate()?;
        self.dyno.validate()?;
        if self.page_count == 0 || self.page_count > MAX_PAGES {
            return Err(HerokuDeploymentError::PaginationBound);
        }
        Ok(())
    }
}

pub struct HerokuProvider<T: HerokuTransport> {
    transport: T,
    scope: HerokuDeploymentScope,
    secret_reference: SecretReference,
    definition: HerokuProviderDefinition,
    retry_policy: RetryPolicy,
    backoff: Option<BackoffReceipt>,
}

impl<T: HerokuTransport> std::fmt::Debug for HerokuProvider<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HerokuProvider")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("retry_policy", &self.retry_policy)
            .field("backoff", &self.backoff)
            .finish()
    }
}

impl<T: HerokuTransport> HerokuProvider<T> {
    pub fn new(
        transport: T,
        scope: HerokuDeploymentScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        secret_reference.validate(&scope)?;
        Ok(Self {
            transport,
            scope,
            secret_reference,
            definition: HerokuProviderDefinition::default(),
            retry_policy: RetryPolicy::default(),
            backoff: None,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &HerokuDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &HerokuProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
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

    pub fn set_retry_policy(&mut self, mut retry_policy: RetryPolicy) -> Result<()> {
        retry_policy.max_attempts = retry_policy
            .max_attempts
            .clamp(1, crate::model::MAX_RETRY_ATTEMPTS);
        retry_policy.max_backoff_seconds =
            retry_policy.max_backoff_seconds.min(MAX_BACKOFF_SECONDS);
        if retry_policy.base_backoff_seconds > retry_policy.max_backoff_seconds {
            return Err(HerokuDeploymentError::InvalidRequest);
        }
        self.retry_policy = retry_policy;
        Ok(())
    }

    pub fn take_backoff(&mut self) -> Option<BackoffReceipt> {
        self.backoff.take()
    }

    pub fn read_snapshot(&mut self) -> Result<HerokuProviderSnapshot> {
        self.secret_reference.validate(&self.scope)?;
        let app = self.read_app()?;
        let build = self.read_build()?;
        let (release, page_count, cursor_digests) = self.read_release_pages()?;
        let slug = self.read_slug()?;
        let dyno = self.read_dyno()?;
        let snapshot = HerokuProviderSnapshot {
            app,
            build,
            release,
            slug,
            dyno,
            page_count,
            cursor_digests,
            backoff: self.backoff.clone(),
            provenance: self.provenance(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read_app(&mut self) -> Result<HerokuAppProjection> {
        let response = self.execute(HerokuRequest::get_app(&self.scope)?)?;
        let fixture: HerokuAppFixture = parse_json(&response)?;
        let app_id = checked_id(&fixture.id, "app")?;
        if app_id != *self.scope.app_id() || !self.scope.app_is_allowed(&app_id) {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        let account = if fixture.account_id.is_empty() {
            self.scope.account_id().as_str()
        } else {
            fixture.account_id.as_str()
        };
        let team = if fixture.team_id.is_empty() {
            self.scope.team_id().as_str()
        } else {
            fixture.team_id.as_str()
        };
        if account != self.scope.account_id().as_str() || team != self.scope.team_id().as_str() {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        if fixture.region != self.scope.region().as_str() {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        let revision = revision_or_default(fixture.revision)?;
        let metadata_digest = Digest::from_parts(
            "heroku-app-metadata/v1",
            &[
                ("updated_at", fixture.updated_at),
                ("state", fixture.state.clone()),
                ("region", fixture.region.clone()),
            ],
        );
        Ok(HerokuAppProjection::new(
            Digest::from_text(account),
            Digest::from_text(team),
            app_id.digest(),
            Digest::from_text(fixture.region),
            HerokuAppState::from_wire(&fixture.state),
            metadata_digest,
            revision,
        ))
    }

    pub fn read_build(&mut self) -> Result<HerokuBuildProjection> {
        let response = self.execute(HerokuRequest::get_build(&self.scope)?)?;
        let fixture: HerokuBuildFixture = parse_json(&response)?;
        let app_id = checked_id(&fixture.app_id, "app")?;
        let build_id = checked_id(&fixture.id, "build")?;
        if app_id != *self.scope.app_id()
            || build_id != *self.scope.build_id()
            || !self.scope.build_is_allowed(&build_id)
        {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        let commit_digest = commit_digest_from_wire(&fixture.commit, self.scope.commit_digest());
        if commit_digest != *self.scope.commit_digest() {
            return Err(HerokuDeploymentError::StaleRevision);
        }
        let revision = revision_or_default(fixture.revision)?;
        let metadata_digest = Digest::from_parts(
            "heroku-build-metadata/v1",
            &[
                ("created_at", fixture.created_at),
                ("output", fixture.output_digest),
                ("status", fixture.status.clone()),
            ],
        );
        Ok(HerokuBuildProjection::new(
            app_id.digest(),
            build_id.digest(),
            HerokuBuildStatus::from_wire(&fixture.status),
            commit_digest,
            metadata_digest,
            revision,
        ))
    }

    pub fn read_release_pages(&mut self) -> Result<(HerokuReleaseProjection, u16, Vec<Digest>)> {
        let mut cursor: Option<String> = None;
        let mut seen_cursors = Vec::new();
        let mut cursor_digests = Vec::new();
        for page_number in 1..=MAX_PAGES {
            let request = HerokuRequest::list_releases(
                &self.scope,
                cursor.as_deref().map(|value| (value, page_number)),
            )?;
            let response = self.execute(request)?;
            let fixture: HerokuReleasePageFixture = parse_json(&response)?;
            let app_id = checked_id(&fixture.app_id, "app")?;
            if app_id != *self.scope.app_id() {
                return Err(HerokuDeploymentError::ScopeMismatch);
            }
            if let Some(release) = fixture
                .releases
                .into_iter()
                .find(|release| release.id == self.scope.release_id().as_str())
            {
                let projection = self.release_projection(release, &app_id)?;
                return Ok((projection, page_number, cursor_digests));
            }
            let Some(next_cursor) = fixture.next_cursor else {
                return Err(HerokuTransportError::NotFound.into());
            };
            if next_cursor.is_empty() || next_cursor.len() > crate::model::MAX_CURSOR_BYTES {
                return Err(HerokuDeploymentError::InvalidRequest);
            }
            if seen_cursors.iter().any(|value| value == &next_cursor) {
                return Err(HerokuDeploymentError::PaginationLoop);
            }
            if page_number == MAX_PAGES {
                return Err(HerokuDeploymentError::PaginationBound);
            }
            seen_cursors.push(next_cursor.clone());
            cursor_digests.push(Digest::from_parts(
                "heroku-pagination-cursor/v1",
                &[("token", next_cursor.clone())],
            ));
            cursor = Some(next_cursor);
        }
        Err(HerokuDeploymentError::PaginationBound)
    }

    pub fn read_slug(&mut self) -> Result<HerokuSlugProjection> {
        let response = self.execute(HerokuRequest::get_slug(&self.scope)?)?;
        let fixture: HerokuSlugFixture = parse_json(&response)?;
        let app_id = checked_id(&fixture.app_id, "app")?;
        let slug_id = checked_id(&fixture.id, "slug")?;
        if app_id != *self.scope.app_id()
            || slug_id != *self.scope.slug_id()
            || !self.scope.slug_is_allowed(&slug_id)
        {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        let revision = revision_or_default(fixture.revision)?;
        let checksum_digest = Digest::from_text(fixture.checksum);
        let metadata_digest = Digest::from_parts(
            "heroku-slug-metadata/v1",
            &[
                ("created_at", fixture.created_at),
                ("state", fixture.state.clone()),
                ("size", fixture.size_bytes.to_string()),
            ],
        );
        Ok(HerokuSlugProjection::new(
            app_id.digest(),
            slug_id.digest(),
            checksum_digest,
            fixture.size_bytes,
            HerokuSlugStatus::from_wire(&fixture.state),
            metadata_digest,
            revision,
        ))
    }

    pub fn read_dyno(&mut self) -> Result<HerokuDynoProjection> {
        let response = self.execute(HerokuRequest::get_dyno(&self.scope)?)?;
        let fixture: HerokuDynoFixture = parse_json(&response)?;
        let app_id = checked_id(&fixture.app_id, "app")?;
        let release_id = checked_id(&fixture.release_id, "release")?;
        let dyno_id = checked_id(&fixture.id, "dyno")?;
        if app_id != *self.scope.app_id()
            || release_id != *self.scope.release_id()
            || dyno_id != *self.scope.dyno_id()
            || fixture.region != self.scope.region().as_str()
            || !self.scope.dyno_is_allowed(&dyno_id)
        {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        let revision = revision_or_default(fixture.revision)?;
        let metadata_digest = Digest::from_parts(
            "heroku-dyno-metadata/v1",
            &[
                ("size", fixture.size),
                ("updated_at", fixture.updated_at),
                ("state", fixture.state.clone()),
            ],
        );
        Ok(HerokuDynoProjection::new(
            app_id.digest(),
            dyno_id.digest(),
            release_id.digest(),
            Digest::from_text(fixture.region),
            HerokuDynoState::from_wire(&fixture.state),
            metadata_digest,
            revision,
        ))
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(HerokuDeploymentError::MutationForbidden { operation })
    }

    fn release_projection(
        &self,
        fixture: HerokuReleaseFixture,
        app_id: &crate::model::AppId,
    ) -> Result<HerokuReleaseProjection> {
        let release_app_id = checked_id(&fixture.app_id, "app")?;
        if release_app_id != *app_id {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        let release_id = checked_id(&fixture.id, "release")?;
        if release_id != *self.scope.release_id() || !self.scope.release_is_allowed(&release_id) {
            return Err(HerokuDeploymentError::ScopeMismatch);
        }
        let commit_digest = commit_digest_from_wire(&fixture.commit, self.scope.commit_digest());
        if commit_digest != *self.scope.commit_digest() {
            return Err(HerokuDeploymentError::StaleRevision);
        }
        let revision = revision_or_default(fixture.revision)?;
        let metadata_digest = Digest::from_parts(
            "heroku-release-metadata/v1",
            &[
                ("created_at", fixture.created_at),
                ("description", fixture.description),
                ("status", fixture.status.clone()),
            ],
        );
        Ok(HerokuReleaseProjection::new(
            app_id.digest(),
            release_id.digest(),
            fixture.version,
            HerokuReleaseStatus::from_wire(&fixture.status),
            commit_digest,
            metadata_digest,
            revision,
        ))
    }

    fn execute(&mut self, request: HerokuRequest) -> Result<HerokuResponse> {
        if !request.is_allowlisted() {
            return Err(HerokuDeploymentError::InvalidRequest);
        }
        self.secret_reference.validate(&self.scope)?;
        let attempts = self.retry_policy.max_attempts.clamp(1, MAX_RETRY_ATTEMPTS);
        for attempt in 1..=attempts {
            let request = request.with_attempt(attempt);
            let response = match self.transport.execute(&request) {
                Ok(response) => response,
                Err(HerokuTransportError::RateLimited {
                    retry_after_seconds,
                }) => {
                    let retry_after = retry_after_seconds
                        .unwrap_or_else(|| self.retry_policy.backoff_seconds(attempt))
                        .min(MAX_BACKOFF_SECONDS);
                    self.backoff = Some(BackoffReceipt::new(attempt, retry_after));
                    if attempt < attempts {
                        continue;
                    }
                    return Err(HerokuTransportError::RateLimited {
                        retry_after_seconds: Some(retry_after),
                    }
                    .into());
                }
                Err(error) => return Err(error.into()),
            };
            match response.status() {
                200..=202 => {
                    response.validate_size_and_digest()?;
                    return Ok(response);
                }
                206 => return Err(HerokuTransportError::Partial.into()),
                401 | 402 | 403 | 406 | 410 | 422 => {
                    return Err(HerokuTransportError::AccessDenied.into());
                }
                404 => return Err(HerokuTransportError::NotFound.into()),
                409 | 412 => return Err(HerokuTransportError::Conflict.into()),
                429 => {
                    let retry_after = response
                        .retry_after_seconds()
                        .unwrap_or_else(|| self.retry_policy.backoff_seconds(attempt))
                        .min(MAX_BACKOFF_SECONDS);
                    self.backoff = Some(BackoffReceipt::new(attempt, retry_after));
                    if attempt < attempts {
                        continue;
                    }
                    return Err(HerokuTransportError::RateLimited {
                        retry_after_seconds: Some(retry_after),
                    }
                    .into());
                }
                408 | 504 => return Err(HerokuTransportError::Timeout.into()),
                _ => return Err(HerokuTransportError::ProviderUnknown.into()),
            }
        }
        Err(HerokuTransportError::Timeout.into())
    }
}

fn checked_id(value: &str, field: &'static str) -> Result<crate::model::Identifier> {
    crate::model::Identifier::new(value)
        .map_err(|_| HerokuDeploymentError::InvalidIdentifier { field })
}

fn revision_or_default(value: u64) -> Result<Revision> {
    Revision::new(if value == 0 { 1 } else { value })
}

fn commit_digest_from_wire(value: &str, fallback: &Digest) -> Digest {
    if value.is_empty() {
        fallback.clone()
    } else {
        Digest::parse(value.to_owned()).unwrap_or_else(|_| Digest::from_text(value))
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(response: &HerokuResponse) -> Result<T> {
    response.validate_size_and_digest()?;
    serde_json::from_slice(response.body()).map_err(|_| HerokuDeploymentError::InvalidResponse)
}

const MAX_RETRY_ATTEMPTS: u8 = crate::model::MAX_RETRY_ATTEMPTS;

#[allow(dead_code)]
const _: HerokuOperation = HerokuOperation::GetApp;

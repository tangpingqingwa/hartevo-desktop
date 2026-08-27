use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use serde::Serialize;
use thiserror::Error;

use crate::canonical::{canonical_digest, digest_parts};
use crate::model::{
    ConnectionRecord, Digest, DirectoryGroupRecord, DirectoryId, DirectoryRecord,
    DirectoryUserRecord, ModelError, PageCursor, PageOperation, ProviderProvenance,
    ProviderRevision, ReadBounds, WorkOsDirectoryScope,
};
use crate::{
    WORKOS_DIRECTORY_API_REVISION, WORKOS_DIRECTORY_PROVIDER_ID,
    WORKOS_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("WorkOS environment is blocked")]
    BlockedEnv,
    #[error("WorkOS API key was rejected with HTTP {status}")]
    Unauthorized { status: u16, error_digest: Digest },
    #[error("WorkOS permission was denied with HTTP {status}")]
    Forbidden { status: u16, error_digest: Digest },
    #[error("WorkOS resource was not found")]
    NotFound { status: u16, error_digest: Digest },
    #[error("WorkOS provider reported a conflict")]
    Conflict { status: u16, error_digest: Digest },
    #[error("WorkOS provider rate-limited the read")]
    RateLimited {
        status: u16,
        retry_after_seconds: Option<u64>,
        error_digest: Digest,
    },
    #[error("WorkOS provider returned server failure HTTP {status}")]
    ServerFailure { status: u16, error_digest: Digest },
    #[error("WorkOS provider read timed out")]
    Timeout { error_digest: Digest },
    #[error("WorkOS provider scope did not match the request")]
    ScopeMismatch,
    #[error("WorkOS provider revision changed during the read")]
    RevisionDrift,
    #[error("WorkOS provider page shape was not allowlisted")]
    SchemaDrift,
    #[error("WorkOS provider response exceeded the byte bound")]
    ResponseTooLarge { response_bytes: usize },
    #[error("WorkOS provider transport script was exhausted")]
    ScriptExhausted,
}

impl ProviderError {
    pub fn http_status(status: u16) -> Self {
        let error_digest = Digest::from_fields("workos-provider-error/v1", &[status.to_string()]);
        match status {
            401 => Self::Unauthorized {
                status,
                error_digest,
            },
            403 => Self::Forbidden {
                status,
                error_digest,
            },
            404 => Self::NotFound {
                status,
                error_digest,
            },
            409 => Self::Conflict {
                status,
                error_digest,
            },
            429 => Self::RateLimited {
                status,
                retry_after_seconds: None,
                error_digest,
            },
            500..=599 => Self::ServerFailure {
                status,
                error_digest,
            },
            _ => Self::SchemaDrift,
        }
    }

    pub fn timeout() -> Self {
        Self::Timeout {
            error_digest: Digest::from_text("workos-timeout"),
        }
    }

    pub fn blocked_env() -> Self {
        Self::BlockedEnv
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized { status, .. }
            | Self::Forbidden { status, .. }
            | Self::NotFound { status, .. }
            | Self::Conflict { status, .. }
            | Self::RateLimited { status, .. }
            | Self::ServerFailure { status, .. } => Some(*status),
            Self::BlockedEnv
            | Self::RevisionDrift
            | Self::SchemaDrift
            | Self::ResponseTooLarge { .. }
            | Self::Timeout { .. }
            | Self::ScopeMismatch
            | Self::ScriptExhausted => None,
        }
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerFailure { .. } | Self::Timeout { .. }
        )
    }

    pub fn error_digest(&self) -> Digest {
        match self {
            Self::Unauthorized { error_digest, .. }
            | Self::Forbidden { error_digest, .. }
            | Self::NotFound { error_digest, .. }
            | Self::Conflict { error_digest, .. }
            | Self::RateLimited { error_digest, .. }
            | Self::ServerFailure { error_digest, .. }
            | Self::Timeout { error_digest } => error_digest.clone(),
            Self::BlockedEnv => Digest::from_text("workos-blocked-env"),
            Self::ScopeMismatch => Digest::from_text("workos-scope-mismatch"),
            Self::RevisionDrift => Digest::from_text("workos-revision-drift"),
            Self::SchemaDrift => Digest::from_text("workos-schema-drift"),
            Self::ResponseTooLarge { response_bytes } => Digest::from_fields(
                "workos-response-too-large/v1",
                &[response_bytes.to_string()],
            ),
            Self::ScriptExhausted => Digest::from_text("workos-script-exhausted"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkOsDirectoryPage {
    pub operation: PageOperation,
    pub users: Vec<DirectoryUserRecord>,
    pub groups: Vec<DirectoryGroupRecord>,
    pub before: Option<PageCursor>,
    pub after: Option<PageCursor>,
    pub provider_revision: ProviderRevision,
    pub response_bytes: usize,
    pub complete: bool,
    pub page_digest: Digest,
}

impl WorkOsDirectoryPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: PageOperation,
        users: Vec<DirectoryUserRecord>,
        groups: Vec<DirectoryGroupRecord>,
        before: Option<PageCursor>,
        after: Option<PageCursor>,
        provider_revision: ProviderRevision,
        response_bytes: usize,
        complete: bool,
    ) -> Result<Self, ModelError> {
        if response_bytes == 0 {
            return Err(ModelError::Invalid {
                field: "response bytes".to_owned(),
                reason: "must be positive".to_owned(),
            });
        }
        let mut page = Self {
            operation,
            users,
            groups,
            before,
            after,
            provider_revision,
            response_bytes,
            complete,
            page_digest: Digest::from_text("unsealed-workos-page"),
        };
        page.page_digest = page.recompute_digest();
        Ok(page)
    }

    pub fn recompute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct PageDigest<'a> {
            operation: &'a PageOperation,
            users: &'a [DirectoryUserRecord],
            groups: &'a [DirectoryGroupRecord],
            before_digest: Option<&'a Digest>,
            after_digest: Option<&'a Digest>,
            provider_revision: &'a ProviderRevision,
            response_bytes: usize,
            complete: bool,
        }
        canonical_digest(
            "workos-directory-page/v1",
            &PageDigest {
                operation: &self.operation,
                users: &self.users,
                groups: &self.groups,
                before_digest: self.before.as_ref().map(PageCursor::digest),
                after_digest: self.after.as_ref().map(PageCursor::digest),
                provider_revision: &self.provider_revision,
                response_bytes: self.response_bytes,
                complete: self.complete,
            },
        )
    }

    pub fn verify_integrity(&self) -> Result<(), ProviderError> {
        if self.page_digest != self.recompute_digest() {
            Err(ProviderError::SchemaDrift)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkOsDirectoryPageRequest {
    scope: WorkOsDirectoryScope,
    pub operation: PageOperation,
    pub limit: u16,
    pub(crate) cursor: Option<PageCursor>,
    pub request_digest: Digest,
}

impl WorkOsDirectoryPageRequest {
    pub fn new(scope: &WorkOsDirectoryScope, bounds: &ReadBounds) -> Result<Self, ModelError> {
        bounds.validate()?;
        scope.validate()?;
        let operation = scope.membership_operation();
        if let Some(cursor) = &bounds.initial_cursor {
            cursor.validate_against(scope, &operation, bounds.now_epoch_seconds)?;
        }
        let request_digest = Digest::from_fields(
            "workos-directory-page-request/v1",
            &[
                scope.scope_digest().as_str().to_owned(),
                operation.name().to_owned(),
                operation.target_digest().as_str().to_owned(),
                bounds.limit.to_string(),
                bounds
                    .initial_cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                bounds
                    .initial_cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| format!("{:?}", cursor.direction())),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            operation,
            limit: bounds.limit,
            cursor: bounds.initial_cursor.clone(),
            request_digest,
        })
    }

    pub fn scope(&self) -> &WorkOsDirectoryScope {
        &self.scope
    }

    pub fn cursor(&self) -> Option<&PageCursor> {
        self.cursor.as_ref()
    }

    pub fn cursor_digest(&self) -> Option<&Digest> {
        self.cursor.as_ref().map(PageCursor::digest)
    }

    pub(crate) fn with_cursor(
        scope: &WorkOsDirectoryScope,
        bounds: &ReadBounds,
        cursor: PageCursor,
    ) -> Result<Self, ModelError> {
        let mut next_bounds = bounds.clone();
        next_bounds.initial_cursor = Some(cursor);
        Self::new(scope, &next_bounds)
    }
}

/// Layer-1 transport boundary. Implementations may provide fixtures,
/// recordings, or loopback replies; native API-key resolution and HTTPS are
/// intentionally outside this crate.
pub trait WorkOsDirectoryTransport: fmt::Debug + Send + Sync {
    fn read_connection(
        &self,
        scope: &WorkOsDirectoryScope,
    ) -> Result<ConnectionRecord, ProviderError>;

    fn read_directory(
        &self,
        scope: &WorkOsDirectoryScope,
    ) -> Result<DirectoryRecord, ProviderError>;

    fn read_membership_page(
        &self,
        request: &WorkOsDirectoryPageRequest,
    ) -> Result<WorkOsDirectoryPage, ProviderError>;
}

#[derive(Debug)]
pub struct ScriptedWorkOsDirectoryTransport {
    connection: Result<ConnectionRecord, ProviderError>,
    directory: Result<DirectoryRecord, ProviderError>,
    pages: Mutex<VecDeque<Result<WorkOsDirectoryPage, ProviderError>>>,
}

impl ScriptedWorkOsDirectoryTransport {
    pub fn new(
        connection: Result<ConnectionRecord, ProviderError>,
        directory: Result<DirectoryRecord, ProviderError>,
        pages: impl IntoIterator<Item = Result<WorkOsDirectoryPage, ProviderError>>,
    ) -> Self {
        Self {
            connection,
            directory,
            pages: Mutex::new(pages.into_iter().collect()),
        }
    }

    pub fn success(
        connection: ConnectionRecord,
        directory: DirectoryRecord,
        pages: impl IntoIterator<Item = WorkOsDirectoryPage>,
    ) -> Self {
        Self::new(Ok(connection), Ok(directory), pages.into_iter().map(Ok))
    }
}

impl WorkOsDirectoryTransport for ScriptedWorkOsDirectoryTransport {
    fn read_connection(
        &self,
        scope: &WorkOsDirectoryScope,
    ) -> Result<ConnectionRecord, ProviderError> {
        let record = self.connection.clone()?;
        if record.organization_id != scope.organization_id
            || record.connection_id != scope.connection_id
        {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(record)
    }

    fn read_directory(
        &self,
        scope: &WorkOsDirectoryScope,
    ) -> Result<DirectoryRecord, ProviderError> {
        let record = self.directory.clone()?;
        if record.organization_id != scope.organization_id
            || record.directory_id != scope.directory_id
        {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(record)
    }

    fn read_membership_page(
        &self,
        request: &WorkOsDirectoryPageRequest,
    ) -> Result<WorkOsDirectoryPage, ProviderError> {
        let mut pages = self
            .pages
            .lock()
            .map_err(|_| ProviderError::ScriptExhausted)?;
        let page = pages.pop_front().ok_or(ProviderError::ScriptExhausted)??;
        if page.operation != request.operation {
            return Err(ProviderError::ScopeMismatch);
        }
        Ok(page)
    }
}

#[derive(Debug)]
pub struct BlockedEnvWorkOsDirectoryTransport;

impl WorkOsDirectoryTransport for BlockedEnvWorkOsDirectoryTransport {
    fn read_connection(
        &self,
        _scope: &WorkOsDirectoryScope,
    ) -> Result<ConnectionRecord, ProviderError> {
        Err(ProviderError::BlockedEnv)
    }

    fn read_directory(
        &self,
        _scope: &WorkOsDirectoryScope,
    ) -> Result<DirectoryRecord, ProviderError> {
        Err(ProviderError::BlockedEnv)
    }

    fn read_membership_page(
        &self,
        _request: &WorkOsDirectoryPageRequest,
    ) -> Result<WorkOsDirectoryPage, ProviderError> {
        Err(ProviderError::BlockedEnv)
    }
}

#[derive(Debug)]
pub struct WorkOsDirectoryFixture {
    pub provider_revision: ProviderRevision,
    pub connection: ConnectionRecord,
    pub directory: DirectoryRecord,
    pub pages: Vec<Result<WorkOsDirectoryPage, ProviderError>>,
}

impl WorkOsDirectoryFixture {
    pub fn new(
        provider_revision: ProviderRevision,
        connection: ConnectionRecord,
        directory: DirectoryRecord,
        pages: impl IntoIterator<Item = Result<WorkOsDirectoryPage, ProviderError>>,
    ) -> Self {
        Self {
            provider_revision,
            connection,
            directory,
            pages: pages.into_iter().collect(),
        }
    }

    pub fn with_pages(
        provider_revision: ProviderRevision,
        connection: ConnectionRecord,
        directory: DirectoryRecord,
        pages: impl IntoIterator<Item = WorkOsDirectoryPage>,
    ) -> Self {
        Self::new(
            provider_revision,
            connection,
            directory,
            pages.into_iter().map(Ok),
        )
    }
}

#[derive(Clone)]
pub struct WorkOsDirectoryProvider {
    provenance: ProviderProvenance,
    provider_revision: ProviderRevision,
    transport: Arc<dyn WorkOsDirectoryTransport>,
    provider_digest: Digest,
}

impl fmt::Debug for WorkOsDirectoryProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkOsDirectoryProvider")
            .field("provider_id", &WORKOS_DIRECTORY_PROVIDER_ID)
            .field("provider_revision", &self.provider_revision)
            .field("provenance", &self.provenance)
            .field("provider_digest", &self.provider_digest)
            .finish_non_exhaustive()
    }
}

impl WorkOsDirectoryProvider {
    pub fn new(
        provenance: ProviderProvenance,
        provider_revision: ProviderRevision,
        transport: Arc<dyn WorkOsDirectoryTransport>,
    ) -> Self {
        let provider_digest = Self::compute_provider_digest(provenance, &provider_revision);
        Self {
            provenance,
            provider_revision,
            transport,
            provider_digest,
        }
    }

    pub fn with_transport<T>(
        provenance: ProviderProvenance,
        provider_revision: ProviderRevision,
        transport: T,
    ) -> Self
    where
        T: WorkOsDirectoryTransport + 'static,
    {
        Self::new(provenance, provider_revision, Arc::new(transport))
    }

    pub fn fixture(fixture: WorkOsDirectoryFixture) -> Self {
        let revision = fixture.provider_revision.clone();
        let transport = ScriptedWorkOsDirectoryTransport::new(
            Ok(fixture.connection),
            Ok(fixture.directory),
            fixture.pages,
        );
        Self::with_transport(ProviderProvenance::Fixture, revision, transport)
    }

    pub fn recording(fixture: WorkOsDirectoryFixture) -> Self {
        let revision = fixture.provider_revision.clone();
        let transport = ScriptedWorkOsDirectoryTransport::new(
            Ok(fixture.connection),
            Ok(fixture.directory),
            fixture.pages,
        );
        Self::with_transport(ProviderProvenance::Recording, revision, transport)
    }

    pub fn loopback(fixture: WorkOsDirectoryFixture) -> Self {
        let revision = fixture.provider_revision.clone();
        let transport = ScriptedWorkOsDirectoryTransport::new(
            Ok(fixture.connection),
            Ok(fixture.directory),
            fixture.pages,
        );
        Self::with_transport(ProviderProvenance::Loopback, revision, transport)
    }

    pub fn blocked_env() -> Self {
        let revision = ProviderRevision::new(WORKOS_DIRECTORY_API_REVISION)
            .expect("contract provider revision is valid");
        Self::with_transport(
            ProviderProvenance::BlockedEnv,
            revision,
            BlockedEnvWorkOsDirectoryTransport,
        )
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn read_connection(
        &self,
        scope: &WorkOsDirectoryScope,
    ) -> Result<ConnectionRecord, ProviderError> {
        self.ensure_test_provenance()?;
        let record = self.transport.read_connection(scope)?;
        if record.provider_revision != self.provider_revision {
            return Err(ProviderError::RevisionDrift);
        }
        Ok(record)
    }

    pub fn get_connection(
        &self,
        scope: &WorkOsDirectoryScope,
    ) -> Result<ConnectionRecord, ProviderError> {
        self.read_connection(scope)
    }

    pub fn read_directory(
        &self,
        scope: &WorkOsDirectoryScope,
    ) -> Result<DirectoryRecord, ProviderError> {
        self.ensure_test_provenance()?;
        let record = self.transport.read_directory(scope)?;
        if record.provider_revision != self.provider_revision {
            return Err(ProviderError::RevisionDrift);
        }
        Ok(record)
    }

    pub fn get_directory(
        &self,
        scope: &WorkOsDirectoryScope,
    ) -> Result<DirectoryRecord, ProviderError> {
        self.read_directory(scope)
    }

    pub fn read_membership_page(
        &self,
        request: &WorkOsDirectoryPageRequest,
    ) -> Result<WorkOsDirectoryPage, ProviderError> {
        self.ensure_test_provenance()?;
        let page = self.transport.read_membership_page(request)?;
        page.verify_integrity()?;
        if page.provider_revision != self.provider_revision {
            return Err(ProviderError::RevisionDrift);
        }
        if page.response_bytes > crate::model::MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge {
                response_bytes: page.response_bytes,
            });
        }
        Ok(page)
    }

    fn ensure_test_provenance(&self) -> Result<(), ProviderError> {
        if self.provenance == ProviderProvenance::BlockedEnv {
            Err(ProviderError::BlockedEnv)
        } else {
            Ok(())
        }
    }

    fn compute_provider_digest(
        provenance: ProviderProvenance,
        provider_revision: &ProviderRevision,
    ) -> Digest {
        digest_parts(
            "workos-directory-provider/v1",
            &[
                WORKOS_DIRECTORY_PROVIDER_ID.to_owned(),
                WORKOS_DIRECTORY_API_REVISION.to_owned(),
                WORKOS_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
                provider_revision.as_str().to_owned(),
                format!("{provenance:?}"),
                "GET-only".to_owned(),
                "native=false".to_owned(),
                "connected=false".to_owned(),
            ],
        )
    }
}

impl From<ModelError> for ProviderError {
    fn from(error: ModelError) -> Self {
        match error {
            ModelError::CursorExpired | ModelError::InvalidCursor => Self::SchemaDrift,
            ModelError::Invalid { .. }
            | ModelError::InvalidDigest
            | ModelError::SecretMaterial
            | ModelError::InvalidMembershipFilter => Self::ScopeMismatch,
        }
    }
}

#[allow(dead_code)]
fn _directory_id_is_intentionally_typed(_id: &DirectoryId) {}

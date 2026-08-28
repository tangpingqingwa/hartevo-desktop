//! Recording/fake/loopback provider seam for bounded Airbyte Cloud evidence.

use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AirbyteScope, AttemptIdentity, CatalogEntry, CatalogProjection, ConnectionIdentity,
    DestinationIdentity, Digest, JobIdentity, ProjectionCompleteness, SchemaFingerprint,
    SourceIdentity, StreamIdentity, SyncAttemptProjection, SyncAttemptStatus, TransportProvenance,
    WorkspaceIdentity,
};
use crate::{
    AirbyteRegistration, AirbyteSyncResultError, MAX_CATALOG_ENTRIES, MAX_CATALOG_PAGES,
    MAX_PAGE_SIZE, MAX_PAGE_TOKEN_BYTES, MAX_RESPONSE_BYTES, validate_text,
};

/// Transport failures are explicit and bounded. They never carry an OAuth
/// token, provider body, or arbitrary response text.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AirbyteTransportError {
    #[error("provider rejected the request with 400")]
    BadRequest,
    #[error("provider rejected the request with 401")]
    Unauthorized,
    #[error("provider rejected the request with 403")]
    Forbidden,
    #[error("provider returned 404")]
    NotFound,
    #[error("provider returned a conflicting revision with 409")]
    Conflict,
    #[error("provider rate limited the request with 429")]
    RateLimited { retry_after_seconds: u64 },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider returned a 5xx response")]
    ServerError { status: u16 },
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider credential was revoked")]
    Revoked,
    #[error("provider response was tampered")]
    Tampered,
    #[error("provider response was truncated")]
    Truncated,
    #[error("native Airbyte environment is unavailable")]
    BlockedEnv,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("provider transport is unavailable")]
    Unavailable,
}

/// Provider-level failures retain the semantic boundary the consumer must
/// inspect, without importing a general connector or kernel authority.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AirbyteProviderError {
    #[error("registration is not valid for the current contract")]
    InvalidRegistration,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration revision or binding drifted")]
    RegistrationDrift,
    #[error("opaque credential reference is revoked")]
    SecretRevoked,
    #[error("provider request scope does not match registration")]
    ScopeMismatch,
    #[error("workspace identity drifted")]
    WorkspaceDrift,
    #[error("source identity drifted")]
    SourceDrift,
    #[error("destination identity drifted")]
    DestinationDrift,
    #[error("connection identity drifted")]
    ConnectionDrift,
    #[error("stream identity drifted")]
    StreamDrift,
    #[error("job identity drifted")]
    JobDrift,
    #[error("attempt identity drifted")]
    AttemptDrift,
    #[error("source and destination schemas do not match")]
    SchemaMismatch,
    #[error("catalog entry was tampered")]
    CatalogTampered,
    #[error("attempt evidence was tampered")]
    AttemptTampered,
    #[error("provider returned an out-of-scope catalog entry")]
    OutOfScope,
    #[error("provider page token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("catalog exceeded its item bound")]
    CatalogLimit,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider returned no bounded catalog page")]
    EmptyCatalog,
    #[error("provider returned invalid attempt state evidence")]
    InvalidAttemptState,
    #[error("provider request and response idempotency binding differ")]
    IdempotencyMismatch,
    #[error("provider transport failure: {0}")]
    Transport(#[from] AirbyteTransportError),
}

/// Safe request for one bounded catalog page.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogReadRequest {
    pub scope_digest: Digest,
    pub workspace_id: String,
    pub page_size: usize,
    pub page_number: usize,
    pub page_token: Option<String>,
}

impl CatalogReadRequest {
    pub(crate) fn new(
        scope: &AirbyteScope,
        page_size: usize,
        page_number: usize,
        page_token: Option<String>,
    ) -> std::result::Result<Self, AirbyteProviderError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || page_number == 0 {
            return Err(AirbyteProviderError::PaginationLimit);
        }
        if page_token
            .as_ref()
            .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
        {
            return Err(AirbyteProviderError::PaginationLimit);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            workspace_id: scope.workspace().id().to_owned(),
            page_size,
            page_number,
            page_token,
        })
    }
}

/// Safe request for exactly one sync attempt. The original idempotency key is
/// hashed and never retained in the request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptReadRequest {
    pub scope_digest: Digest,
    pub job_id: String,
    pub attempt_id: String,
    pub idempotency_key_digest: Digest,
    pub request_digest: Digest,
}

impl AttemptReadRequest {
    pub(crate) fn new(
        scope: &AirbyteScope,
        idempotency_key: &str,
    ) -> std::result::Result<Self, AirbyteProviderError> {
        validate_text(idempotency_key, "idempotencyKey", 256)
            .map_err(|_| AirbyteProviderError::ScopeMismatch)?;
        let idempotency_key_digest = Digest::from_text(idempotency_key);
        let request_digest = Digest::from_parts(
            "airbyte-attempt-read-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("job", scope.job().id.clone()),
                ("attempt", scope.attempt().id.clone()),
                ("idempotency", idempotency_key_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            job_id: scope.job().id.clone(),
            attempt_id: scope.attempt().id.clone(),
            idempotency_key_digest,
            request_digest,
        })
    }
}

/// A bounded provider catalog page. Page tokens are opaque, bounded cursors;
/// only identity and schema metadata are retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogPage {
    pub page_number: usize,
    pub entries: Vec<CatalogEntry>,
    pub next_page_token: Option<String>,
    pub response_bytes: usize,
    pub page_digest: Digest,
}

impl CatalogPage {
    pub fn new(
        page_number: usize,
        entries: Vec<CatalogEntry>,
        next_page_token: Option<String>,
        response_bytes: usize,
    ) -> std::result::Result<Self, AirbyteProviderError> {
        if page_number == 0
            || entries.is_empty()
            || entries.len() > MAX_CATALOG_ENTRIES
            || response_bytes > MAX_RESPONSE_BYTES
            || next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
        {
            return Err(AirbyteProviderError::ResponseTooLarge);
        }
        let mut page = Self {
            page_number,
            entries,
            next_page_token,
            response_bytes,
            page_digest: Digest::from_text("unsealed-airbyte-catalog-page"),
        };
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn for_scope(scope: &AirbyteScope) -> Self {
        Self::new(1, vec![CatalogEntry::for_scope(scope)], None, 512)
            .expect("scope fixture is bounded")
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), AirbyteProviderError> {
        if self.page_number == 0
            || self.entries.is_empty()
            || self.entries.len() > MAX_CATALOG_ENTRIES
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
            || self.page_digest != self.calculate_digest()
        {
            return Err(AirbyteProviderError::CatalogTampered);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "airbyte-catalog-page/v1",
            &[
                ("number", self.page_number.to_string()),
                (
                    "entries",
                    self.entries
                        .iter()
                        .map(|entry| entry.entry_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_page_token
                        .as_deref()
                        .map_or_else(String::new, |token| Digest::from_text(token).to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
            ],
        )
    }
}

/// Typed sync-attempt evidence. No raw provider records are accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAttemptRecord {
    pub workspace: WorkspaceIdentity,
    pub source: SourceIdentity,
    pub destination: DestinationIdentity,
    pub connection: ConnectionIdentity,
    pub stream: StreamIdentity,
    pub job: JobIdentity,
    pub attempt: AttemptIdentity,
    pub status: SyncAttemptStatus,
    pub records_read: Option<u64>,
    pub records_written: Option<u64>,
    pub bytes_read: Option<u64>,
    pub bytes_written: Option<u64>,
    pub source_schema_digest: Option<SchemaFingerprint>,
    pub destination_schema_digest: Option<SchemaFingerprint>,
    pub response_truncated: bool,
    pub completeness: ProjectionCompleteness,
    pub provider_request_id_digest: Option<Digest>,
    pub observed_at_epoch_seconds: u64,
    pub response_bytes: u64,
    pub record_digest: Digest,
}

impl ProviderAttemptRecord {
    pub fn for_scope(
        scope: &AirbyteScope,
        status: SyncAttemptStatus,
        observed_at_epoch_seconds: u64,
    ) -> Self {
        Self::from_values(
            scope,
            status,
            Some(1),
            Some(1),
            Some(128),
            Some(128),
            Some(scope.stream().schema_digest.clone()),
            Some(scope.stream().schema_digest.clone()),
            false,
            ProjectionCompleteness::Complete,
            Some(Digest::from_text("airbyte-provider-request")),
            observed_at_epoch_seconds,
            512,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        scope: &AirbyteScope,
        status: SyncAttemptStatus,
        records_read: Option<u64>,
        records_written: Option<u64>,
        bytes_read: Option<u64>,
        bytes_written: Option<u64>,
        source_schema_digest: Option<SchemaFingerprint>,
        destination_schema_digest: Option<SchemaFingerprint>,
        response_truncated: bool,
        completeness: ProjectionCompleteness,
        provider_request_id_digest: Option<Digest>,
        observed_at_epoch_seconds: u64,
        response_bytes: u64,
    ) -> Self {
        let mut record = Self {
            workspace: scope.workspace().clone(),
            source: scope.source().clone(),
            destination: scope.destination().clone(),
            connection: scope.connection().clone(),
            stream: scope.stream().clone(),
            job: scope.job().clone(),
            attempt: scope.attempt().clone(),
            status,
            records_read,
            records_written,
            bytes_read,
            bytes_written,
            source_schema_digest,
            destination_schema_digest,
            response_truncated,
            completeness,
            provider_request_id_digest,
            observed_at_epoch_seconds,
            response_bytes,
            record_digest: Digest::from_text("unsealed-airbyte-attempt-record"),
        };
        record.record_digest = record.calculate_digest();
        record
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), AirbyteProviderError> {
        self.workspace
            .validate()
            .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        self.source
            .validate()
            .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        self.destination
            .validate()
            .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        self.connection
            .validate()
            .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        self.stream
            .validate()
            .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        self.job
            .validate()
            .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        self.attempt
            .validate()
            .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        for value in [self.records_read, self.records_written] {
            if value.is_some_and(|value| value > crate::MAX_RECORD_COUNT) {
                return Err(AirbyteProviderError::AttemptTampered);
            }
        }
        for value in [self.bytes_read, self.bytes_written] {
            if value.is_some_and(|value| value > crate::MAX_EVIDENCE_BYTES) {
                return Err(AirbyteProviderError::AttemptTampered);
            }
        }
        if self.response_bytes > MAX_RESPONSE_BYTES as u64
            || self.observed_at_epoch_seconds == 0
            || self.record_digest != self.calculate_digest()
        {
            return Err(AirbyteProviderError::AttemptTampered);
        }
        if let Some(digest) = &self.source_schema_digest {
            digest
                .validate()
                .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        }
        if let Some(digest) = &self.destination_schema_digest {
            digest
                .validate()
                .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        }
        if let Some(digest) = &self.provider_request_id_digest {
            digest
                .validate()
                .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        }
        if self.status == SyncAttemptStatus::Succeeded
            && (self.response_truncated || self.completeness != ProjectionCompleteness::Complete)
        {
            return Err(AirbyteProviderError::InvalidAttemptState);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "airbyte-provider-attempt-record/v1",
            &[
                (
                    "workspace",
                    serde_json::to_string(&self.workspace).expect("identity"),
                ),
                (
                    "source",
                    serde_json::to_string(&self.source).expect("identity"),
                ),
                (
                    "destination",
                    serde_json::to_string(&self.destination).expect("identity"),
                ),
                (
                    "connection",
                    serde_json::to_string(&self.connection).expect("identity"),
                ),
                (
                    "stream",
                    serde_json::to_string(&self.stream).expect("identity"),
                ),
                ("job", serde_json::to_string(&self.job).expect("identity")),
                (
                    "attempt",
                    serde_json::to_string(&self.attempt).expect("identity"),
                ),
                ("status", format!("{:?}", self.status)),
                ("records_read", format!("{:?}", self.records_read)),
                ("records_written", format!("{:?}", self.records_written)),
                ("bytes_read", format!("{:?}", self.bytes_read)),
                ("bytes_written", format!("{:?}", self.bytes_written)),
                (
                    "source_schema",
                    self.source_schema_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "destination_schema",
                    self.destination_schema_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("truncated", self.response_truncated.to_string()),
                ("completeness", format!("{:?}", self.completeness)),
                (
                    "provider_request",
                    self.provider_request_id_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("observed_at", self.observed_at_epoch_seconds.to_string()),
                ("response_bytes", self.response_bytes.to_string()),
            ],
        )
    }
}

/// Provider response binds the exact request digest and closed provenance to
/// one typed attempt record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptResponse {
    pub request_digest: Digest,
    pub record: ProviderAttemptRecord,
    pub provenance: TransportProvenance,
    pub response_bytes: usize,
}

impl AttemptResponse {
    pub fn for_scope(scope: &AirbyteScope, provenance: TransportProvenance) -> Self {
        Self {
            request_digest: Digest::from_text("airbyte-attempt-request-placeholder"),
            record: ProviderAttemptRecord::for_scope(
                scope,
                SyncAttemptStatus::Succeeded,
                1_744_550_400,
            ),
            provenance,
            response_bytes: 512,
        }
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), AirbyteProviderError> {
        self.request_digest
            .validate()
            .map_err(|_| AirbyteProviderError::AttemptTampered)?;
        self.record.validate_integrity()?;
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(AirbyteProviderError::ResponseTooLarge);
        }
        Ok(())
    }
}

/// Closed transport seam. No method can trigger or cancel a sync or mutate a
/// connection/credential.
pub trait AirbyteTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_catalog(
        &mut self,
        request: &CatalogReadRequest,
    ) -> std::result::Result<CatalogPage, AirbyteTransportError>;

    fn read_attempt(
        &mut self,
        request: &AttemptReadRequest,
    ) -> std::result::Result<AttemptResponse, AirbyteTransportError>;
}

/// Provider that can only perform the two Layer-1 read operations.
#[derive(Debug)]
pub struct AirbyteCloudProvider<T> {
    registration: AirbyteRegistration,
    transport: T,
}

impl<T: AirbyteTransport> AirbyteCloudProvider<T> {
    pub fn new(
        registration: AirbyteRegistration,
        transport: T,
    ) -> std::result::Result<Self, AirbyteProviderError> {
        registration
            .validate()
            .map_err(|_| AirbyteProviderError::InvalidRegistration)?;
        Ok(Self {
            registration,
            transport,
        })
    }

    pub fn registration(&self) -> &AirbyteRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AirbyteRegistration {
        &mut self.registration
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn ensure_ready(&self) -> std::result::Result<(), AirbyteProviderError> {
        self.registration
            .validate()
            .map_err(|_| AirbyteProviderError::RegistrationDrift)?;
        if self.registration.secret_reference().is_revoked() {
            return Err(AirbyteProviderError::SecretRevoked);
        }
        match self.registration.status() {
            crate::RegistrationStatus::Active => Ok(()),
            crate::RegistrationStatus::Revoked => Err(AirbyteProviderError::RegistrationRevoked),
            crate::RegistrationStatus::Reversed => Err(AirbyteProviderError::RegistrationReversed),
        }
    }

    pub fn read_catalog(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<CatalogProjection, AirbyteProviderError> {
        self.ensure_ready()?;
        let scope = self.registration.scope();
        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut entries = Vec::new();
        let mut pages_read = 0;
        let completeness;
        loop {
            pages_read += 1;
            if pages_read > MAX_CATALOG_PAGES {
                return Err(AirbyteProviderError::PaginationLimit);
            }
            let request =
                CatalogReadRequest::new(scope, page_size, pages_read, page_token.clone())?;
            let page = self
                .transport
                .read_catalog(&request)
                .map_err(AirbyteProviderError::Transport)?;
            page.validate_integrity()?;
            if page.page_number != pages_read || page.response_bytes > MAX_RESPONSE_BYTES {
                return Err(AirbyteProviderError::CatalogTampered);
            }
            if page
                .next_page_token
                .as_ref()
                .is_some_and(|token| seen_tokens.contains(token))
            {
                return Err(AirbyteProviderError::PaginationLoop);
            }
            for entry in &page.entries {
                self.validate_catalog_entry(entry)?;
                if entries
                    .iter()
                    .any(|existing: &CatalogEntry| existing.entry_digest == entry.entry_digest)
                {
                    return Err(AirbyteProviderError::CatalogTampered);
                }
                entries.push(entry.clone());
                if entries.len() > MAX_CATALOG_ENTRIES {
                    return Err(AirbyteProviderError::CatalogLimit);
                }
            }
            match page.next_page_token {
                None => {
                    completeness = ProjectionCompleteness::Complete;
                    break;
                }
                Some(next) => {
                    if !seen_tokens.insert(next.clone()) {
                        return Err(AirbyteProviderError::PaginationLoop);
                    }
                    page_token = Some(next);
                }
            }
        }
        CatalogProjection::new(scope, entries, pages_read, completeness, self.provenance())
            .map_err(|error| map_model_error(&error))
    }

    pub fn read_attempt(
        &mut self,
        idempotency_key: &str,
    ) -> std::result::Result<SyncAttemptProjection, AirbyteProviderError> {
        self.ensure_ready()?;
        let scope = self.registration.scope();
        let request = AttemptReadRequest::new(scope, idempotency_key)?;
        if request.scope_digest != scope.digest()
            || request.job_id != scope.job().id
            || request.attempt_id != scope.attempt().id
        {
            return Err(AirbyteProviderError::ScopeMismatch);
        }
        let response = self
            .transport
            .read_attempt(&request)
            .map_err(AirbyteProviderError::Transport)?;
        response.validate_integrity()?;
        if response.provenance != self.provenance() {
            return Err(AirbyteProviderError::AttemptTampered);
        }
        if response.request_digest != request.request_digest {
            return Err(AirbyteProviderError::IdempotencyMismatch);
        }
        self.validate_attempt_record(&response.record)?;
        SyncAttemptProjection::from_parts(
            scope,
            response.record.status,
            response.record.records_read,
            response.record.records_written,
            response.record.bytes_read,
            response.record.bytes_written,
            response.record.source_schema_digest.clone(),
            response.record.destination_schema_digest.clone(),
            response.record.completeness,
            response.record.response_truncated,
            response.record.provider_request_id_digest.clone(),
            response.record.observed_at_epoch_seconds,
            response.provenance,
        )
        .map_err(|error| map_model_error(&error))
    }

    fn validate_catalog_entry(
        &self,
        entry: &CatalogEntry,
    ) -> std::result::Result<(), AirbyteProviderError> {
        entry
            .validate_integrity()
            .map_err(|_| AirbyteProviderError::CatalogTampered)?;
        let scope = self.registration.scope();
        if entry.workspace.id != scope.workspace().id
            || entry.workspace.https_host != scope.workspace().https_host
            || entry.workspace.revision != scope.workspace().revision
        {
            return Err(AirbyteProviderError::WorkspaceDrift);
        }
        if entry.source != *scope.source() {
            return Err(AirbyteProviderError::SourceDrift);
        }
        if entry.destination != *scope.destination() {
            return Err(AirbyteProviderError::DestinationDrift);
        }
        if entry.connection != *scope.connection() {
            return Err(AirbyteProviderError::ConnectionDrift);
        }
        if entry.stream != *scope.stream() {
            return Err(AirbyteProviderError::StreamDrift);
        }
        if entry.schema_digest != scope.stream().schema_digest {
            return Err(AirbyteProviderError::SchemaMismatch);
        }
        Ok(())
    }

    fn validate_attempt_record(
        &self,
        record: &ProviderAttemptRecord,
    ) -> std::result::Result<(), AirbyteProviderError> {
        let scope = self.registration.scope();
        if record.workspace != *scope.workspace() {
            return Err(AirbyteProviderError::WorkspaceDrift);
        }
        if record.source != *scope.source() {
            return Err(AirbyteProviderError::SourceDrift);
        }
        if record.destination != *scope.destination() {
            return Err(AirbyteProviderError::DestinationDrift);
        }
        if record.connection != *scope.connection() {
            return Err(AirbyteProviderError::ConnectionDrift);
        }
        if record.stream != *scope.stream() {
            return Err(AirbyteProviderError::StreamDrift);
        }
        if record.job != *scope.job() {
            return Err(AirbyteProviderError::JobDrift);
        }
        if record.attempt != *scope.attempt() {
            return Err(AirbyteProviderError::AttemptDrift);
        }
        record.validate_integrity()?;
        if record.source_schema_digest.is_some()
            && record.destination_schema_digest.is_some()
            && record.source_schema_digest != record.destination_schema_digest
        {
            return Err(AirbyteProviderError::SchemaMismatch);
        }
        Ok(())
    }
}

fn map_model_error(error: &AirbyteSyncResultError) -> AirbyteProviderError {
    match error {
        AirbyteSyncResultError::SchemaMismatch => AirbyteProviderError::SchemaMismatch,
        AirbyteSyncResultError::OutOfScope => AirbyteProviderError::OutOfScope,
        AirbyteSyncResultError::PaginationLoop => AirbyteProviderError::PaginationLoop,
        AirbyteSyncResultError::PaginationLimit => AirbyteProviderError::PaginationLimit,
        AirbyteSyncResultError::ResponseTooLarge => AirbyteProviderError::ResponseTooLarge,
        _ => AirbyteProviderError::AttemptTampered,
    }
}

#[derive(Clone, Debug)]
struct FixtureState {
    pages: VecDeque<CatalogPage>,
    attempt: Option<AttemptResponse>,
    catalog_error: Option<AirbyteTransportError>,
    attempt_error: Option<AirbyteTransportError>,
}

impl FixtureState {
    fn new(pages: Vec<CatalogPage>, attempt: AttemptResponse) -> Self {
        Self {
            pages: pages.into_iter().collect(),
            attempt: Some(attempt),
            catalog_error: None,
            attempt_error: None,
        }
    }

    fn from_scope(scope: &AirbyteScope, provenance: TransportProvenance) -> Self {
        Self::new(
            vec![CatalogPage::for_scope(scope)],
            AttemptResponse::for_scope(scope, provenance),
        )
    }

    fn read_catalog(
        &mut self,
        _request: &CatalogReadRequest,
    ) -> std::result::Result<CatalogPage, AirbyteTransportError> {
        if let Some(error) = self.catalog_error.clone() {
            return Err(error);
        }
        self.pages
            .pop_front()
            .ok_or(AirbyteTransportError::NotFound)
    }

    fn read_attempt(
        &mut self,
        request: &AttemptReadRequest,
    ) -> std::result::Result<AttemptResponse, AirbyteTransportError> {
        if let Some(error) = self.attempt_error.clone() {
            return Err(error);
        }
        let mut response = self
            .attempt
            .clone()
            .ok_or(AirbyteTransportError::NotFound)?;
        response.request_digest = request.request_digest.clone();
        Ok(response)
    }
}

macro_rules! fixture_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            state: FixtureState,
        }

        impl $name {
            pub fn new(pages: Vec<CatalogPage>, attempt: AttemptResponse) -> Self {
                Self {
                    state: FixtureState::new(pages, attempt),
                }
            }

            pub fn from_scope(scope: &AirbyteScope) -> Self {
                Self {
                    state: FixtureState::from_scope(scope, $provenance),
                }
            }

            #[must_use]
            pub fn fail_catalog_with(mut self, error: AirbyteTransportError) -> Self {
                self.state.catalog_error = Some(error);
                self
            }

            #[must_use]
            pub fn fail_attempt_with(mut self, error: AirbyteTransportError) -> Self {
                self.state.attempt_error = Some(error);
                self
            }

            pub fn set_pages(&mut self, pages: Vec<CatalogPage>) {
                self.state.pages = pages.into_iter().collect();
            }

            pub fn set_attempt(&mut self, attempt: AttemptResponse) {
                self.state.attempt = Some(attempt);
            }
        }

        impl AirbyteTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn read_catalog(
                &mut self,
                request: &CatalogReadRequest,
            ) -> std::result::Result<CatalogPage, AirbyteTransportError> {
                self.state.read_catalog(request)
            }

            fn read_attempt(
                &mut self,
                request: &AttemptReadRequest,
            ) -> std::result::Result<AttemptResponse, AirbyteTransportError> {
                self.state.read_attempt(request)
            }
        }
    };
}

fixture_transport!(RecordingTransport, TransportProvenance::Recording);
fixture_transport!(FakeTransport, TransportProvenance::Fake);
fixture_transport!(LoopbackTransport, TransportProvenance::Loopback);

/// The honest native gap. It has no data path and can only return BLOCKED_ENV.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AirbyteTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_catalog(
        &mut self,
        _request: &CatalogReadRequest,
    ) -> std::result::Result<CatalogPage, AirbyteTransportError> {
        Err(AirbyteTransportError::BlockedEnv)
    }

    fn read_attempt(
        &mut self,
        _request: &AttemptReadRequest,
    ) -> std::result::Result<AttemptResponse, AirbyteTransportError> {
        Err(AirbyteTransportError::BlockedEnv)
    }
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use crate::model::{
        AttemptIdentity, PermissionSnapshot, ProjectId, RegistrationId, ResourceIdentity,
        SecretReference, StreamIdentity, WorkProductId, WorkspaceIdentity,
    };
    use crate::service::{AirbyteRegistration, ProviderIdentity};

    fn scope() -> AirbyteScope {
        AirbyteScope::new(
            WorkspaceIdentity::new("workspace-1", "https://api.airbyte.com", 1).expect("workspace"),
            ResourceIdentity::new("source-1", 1).expect("source"),
            ResourceIdentity::new("destination-1", 1).expect("destination"),
            ResourceIdentity::new("connection-1", 1).expect("connection"),
            StreamIdentity::new("public", "users", 1, "a".repeat(64)).expect("stream"),
            JobIdentity::new("job-1", 1).expect("job"),
            AttemptIdentity::new("attempt-1", 1).expect("attempt"),
            crate::MissionId::new("mission-1").expect("mission"),
            ProjectId::new("project-1").expect("project"),
            WorkProductId::new("work-product-1").expect("work product"),
        )
        .expect("scope")
    }

    fn registration(scope: AirbyteScope) -> AirbyteRegistration {
        AirbyteRegistration::new(
            RegistrationId::new("registration-1").expect("registration id"),
            scope,
            SecretReference::oauth("opaque-airbyte-oauth", 1).expect("secret"),
            PermissionSnapshot::read_only(1).expect("permissions"),
            ProviderIdentity::new(1, "airbyte-cloud-release-1").expect("provider"),
            1,
        )
        .expect("registration")
    }

    #[test]
    fn fake_transport_reads_one_bounded_attempt_without_native_claim() {
        let scope = scope();
        let registration = registration(scope.clone());
        let transport = FakeTransport::from_scope(&scope);
        let mut provider = AirbyteCloudProvider::new(registration, transport).expect("provider");
        assert!(!provider.connected());
        assert!(!provider.native());
        let catalog = provider.read_catalog(100).expect("catalog");
        assert!(catalog.is_complete());
        let attempt = provider.read_attempt("attempt-read-1").expect("attempt");
        assert_eq!(attempt.status, SyncAttemptStatus::Succeeded);
        assert!(attempt.is_complete());
        assert!(!attempt.connected);
        assert!(!attempt.native);
    }

    #[test]
    fn blocked_environment_is_never_reclassified_as_connected() {
        let scope = scope();
        let registration = registration(scope);
        let mut provider =
            AirbyteCloudProvider::new(registration, BlockedEnvTransport).expect("provider");
        assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
        assert_eq!(
            provider.read_catalog(100),
            Err(AirbyteProviderError::Transport(
                AirbyteTransportError::BlockedEnv,
            ))
        );
        assert!(!provider.connected());
        assert!(!provider.native());
    }
}

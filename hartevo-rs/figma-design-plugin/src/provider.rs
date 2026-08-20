use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::contract::FigmaDesignContract;
use crate::types::{
    ExportRequest, FigmaAuthMethod, FigmaDesignRegistration, FigmaEvidenceClass,
    FigmaExportPayload, FigmaFileMetadata, FigmaNodeMetadata, FigmaProviderMode, FigmaScope,
    FigmaTypeError, FigmaVersion, MAX_RETRY_ATTEMPTS, MAX_VERSION_PAGE_SIZE, ProviderVersion,
    RedactedText, SecretReference, Sha256Digest,
};

pub const FIGMA_PROVIDER_ID: &str = "figma";
pub const FIGMA_ADAPTER_ID: &str = "design.figma.readonly";
pub const FIGMA_PROVIDER_VERSION: &str = "figma-rest-layer1-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FigmaTransportErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    Timeout,
    Unavailable,
    InvalidResponse,
    StaleVersion,
    PartialExport,
    ProviderUnknown,
    BlockedEnv,
}

impl FigmaTransportErrorKind {
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Timeout | Self::Unavailable)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("Figma transport returned {kind:?}")]
pub struct FigmaTransportError {
    kind: FigmaTransportErrorKind,
    response_digest: Option<Sha256Digest>,
}

impl FigmaTransportError {
    #[must_use]
    pub const fn new(kind: FigmaTransportErrorKind) -> Self {
        Self {
            kind,
            response_digest: None,
        }
    }

    #[must_use]
    pub fn with_response_digest(
        kind: FigmaTransportErrorKind,
        response_digest: Sha256Digest,
    ) -> Self {
        Self {
            kind,
            response_digest: Some(response_digest),
        }
    }

    #[must_use]
    pub const fn blocked_env() -> Self {
        Self::new(FigmaTransportErrorKind::BlockedEnv)
    }

    #[must_use]
    pub const fn kind(&self) -> FigmaTransportErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn response_digest(&self) -> Option<&Sha256Digest> {
        self.response_digest.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FigmaProviderError {
    #[error("Figma registration is inactive")]
    RegistrationInactive,
    #[error("Figma registration binding is invalid")]
    RegistrationInvalid,
    #[error("Figma scope does not match the active registration")]
    ScopeMismatch,
    #[error("Figma SecretReference does not match the active scope")]
    SecretReferenceMismatch,
    #[error("Figma SecretReference is revoked")]
    SecretRevoked,
    #[error("Figma transport failed after {attempts} attempt(s): {kind:?}")]
    Transport {
        kind: FigmaTransportErrorKind,
        attempts: u8,
    },
    #[error("Figma provider response is invalid: {0}")]
    InvalidResponse(&'static str),
    #[error("Figma version page size is outside the contract bound")]
    InvalidPageSize,
    #[error("Figma export is outside the exact-byte fence")]
    ExportFence,
    #[error("Figma provider returned stale-version evidence")]
    StaleVersion,
    #[error("Figma type boundary failed: {0}")]
    Type(#[from] FigmaTypeError),
}

impl FigmaProviderError {
    #[must_use]
    pub const fn availability(&self) -> FigmaProviderAvailability {
        match self {
            Self::Transport {
                kind: FigmaTransportErrorKind::BlockedEnv,
                ..
            } => FigmaProviderAvailability::BlockedEnv,
            _ => FigmaProviderAvailability::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FigmaProviderAvailability {
    Recorded,
    BlockedEnv,
    ProviderUnknown,
}

impl FigmaProviderAvailability {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8) -> Result<Self, FigmaProviderError> {
        if max_attempts == 0 || max_attempts > MAX_RETRY_ATTEMPTS {
            return Err(FigmaProviderError::InvalidPageSize);
        }
        Ok(Self { max_attempts })
    }

    #[must_use]
    pub const fn default_layer1() -> Self {
        Self { max_attempts: 3 }
    }

    #[must_use]
    pub const fn max_attempts(&self) -> u8 {
        self.max_attempts
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor(String);

impl PageCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, FigmaProviderError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(FigmaProviderError::InvalidResponse("invalid page cursor"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn is_same_as(&self, other: &Self) -> bool {
        self == other
    }

    #[must_use]
    pub(crate) fn raw(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<opaque-cursor>")
    }
}

impl fmt::Display for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<opaque-cursor>")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMetadataResponse {
    pub metadata: FigmaFileMetadata,
    pub response_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionHistoryResponse {
    pub versions: Vec<FigmaVersion>,
    pub next_cursor: Option<PageCursor>,
    pub response_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeMetadataResponse {
    pub nodes: Vec<FigmaNodeMetadata>,
    pub response_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportResponse {
    pub payload: FigmaExportPayload,
    pub response_digest: Sha256Digest,
}

pub trait FigmaTransport: fmt::Debug {
    fn mode(&self) -> FigmaProviderMode;

    fn read_file_metadata(
        &mut self,
        scope: &FigmaScope,
    ) -> Result<FileMetadataResponse, FigmaTransportError>;

    fn list_versions(
        &mut self,
        scope: &FigmaScope,
        page_size: usize,
        cursor: Option<&PageCursor>,
    ) -> Result<VersionHistoryResponse, FigmaTransportError>;

    fn read_node_metadata(
        &mut self,
        scope: &FigmaScope,
    ) -> Result<NodeMetadataResponse, FigmaTransportError>;

    fn export(
        &mut self,
        scope: &FigmaScope,
        request: &ExportRequest,
    ) -> Result<ExportResponse, FigmaTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FigmaHttpsEndpoint(String);

impl FigmaHttpsEndpoint {
    pub fn new(value: impl Into<String>) -> Result<Self, FigmaTypeError> {
        let value = value.into();
        if !value.starts_with("https://")
            || value.len() > 256
            || value.chars().any(char::is_control)
            || value.chars().any(char::is_whitespace)
        {
            return Err(FigmaTypeError::InvalidIdentifier("HTTPS endpoint"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed live-transport seam. Layer 1 intentionally fails closed with
/// BLOCKED_ENV until a host supplies an independently reviewed HTTPS client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FigmaHttpsTransport {
    endpoint: FigmaHttpsEndpoint,
    auth_method: FigmaAuthMethod,
}

impl FigmaHttpsTransport {
    pub fn new(
        endpoint: FigmaHttpsEndpoint,
        auth_method: FigmaAuthMethod,
    ) -> Result<Self, FigmaProviderError> {
        Ok(Self {
            endpoint,
            auth_method,
        })
    }

    #[must_use]
    pub fn endpoint(&self) -> &FigmaHttpsEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub const fn auth_method(&self) -> &FigmaAuthMethod {
        &self.auth_method
    }
}

impl FigmaTransport for FigmaHttpsTransport {
    fn mode(&self) -> FigmaProviderMode {
        FigmaProviderMode::BlockedEnv
    }

    fn read_file_metadata(
        &mut self,
        _scope: &FigmaScope,
    ) -> Result<FileMetadataResponse, FigmaTransportError> {
        Err(FigmaTransportError::blocked_env())
    }

    fn list_versions(
        &mut self,
        _scope: &FigmaScope,
        _page_size: usize,
        _cursor: Option<&PageCursor>,
    ) -> Result<VersionHistoryResponse, FigmaTransportError> {
        Err(FigmaTransportError::blocked_env())
    }

    fn read_node_metadata(
        &mut self,
        _scope: &FigmaScope,
    ) -> Result<NodeMetadataResponse, FigmaTransportError> {
        Err(FigmaTransportError::blocked_env())
    }

    fn export(
        &mut self,
        _scope: &FigmaScope,
        _request: &ExportRequest,
    ) -> Result<ExportResponse, FigmaTransportError> {
        Err(FigmaTransportError::blocked_env())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaProviderEvidence {
    mode: FigmaProviderMode,
    evidence_class: FigmaEvidenceClass,
    scope_digest: Sha256Digest,
    registration_digest: Sha256Digest,
    provider_version: ProviderVersion,
    connected: bool,
    native: bool,
    evidence_digest: Sha256Digest,
}

#[derive(Serialize)]
struct EvidenceDigestMaterial<'a> {
    mode: FigmaProviderMode,
    evidence_class: FigmaEvidenceClass,
    scope_digest: &'a Sha256Digest,
    registration_digest: &'a Sha256Digest,
    provider_version: &'a ProviderVersion,
    connected: bool,
    native: bool,
}

impl FigmaProviderEvidence {
    fn new(
        mode: FigmaProviderMode,
        scope_digest: Sha256Digest,
        registration_digest: Sha256Digest,
        provider_version: ProviderVersion,
    ) -> Self {
        let evidence_class = FigmaEvidenceClass::for_mode(mode);
        let evidence_digest = Sha256Digest::from_serializable(&EvidenceDigestMaterial {
            mode,
            evidence_class,
            scope_digest: &scope_digest,
            registration_digest: &registration_digest,
            provider_version: &provider_version,
            connected: false,
            native: false,
        })
        .expect("provider evidence material is serializable");
        Self {
            mode,
            evidence_class,
            scope_digest,
            registration_digest,
            provider_version,
            connected: false,
            native: false,
            evidence_digest,
        }
    }

    #[must_use]
    pub const fn mode(&self) -> FigmaProviderMode {
        self.mode
    }

    #[must_use]
    pub const fn evidence_class(&self) -> FigmaEvidenceClass {
        self.evidence_class
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Sha256Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Sha256Digest {
        &self.registration_digest
    }

    #[must_use]
    pub fn provider_version(&self) -> &ProviderVersion {
        &self.provider_version
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &Sha256Digest {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderObservation<T> {
    pub value: T,
    pub response_digest: Sha256Digest,
    pub evidence: FigmaProviderEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FigmaDesignProvider<T> {
    transport: T,
    registration: FigmaDesignRegistration,
    secret_reference: SecretReference,
    auth_method: FigmaAuthMethod,
    retry_policy: RetryPolicy,
}

impl<T: FigmaTransport> FigmaDesignProvider<T> {
    pub fn new(
        transport: T,
        registration: FigmaDesignRegistration,
        secret_reference: SecretReference,
        auth_method: FigmaAuthMethod,
    ) -> Result<Self, FigmaProviderError> {
        registration
            .validate()
            .map_err(|_| FigmaProviderError::RegistrationInvalid)?;
        if !registration.is_active()
            || registration.binding().provider_id() != FIGMA_PROVIDER_ID
            || registration.binding().adapter_id().as_str() != FIGMA_ADAPTER_ID
            || registration.binding().provider_version().as_str() != FIGMA_PROVIDER_VERSION
            || registration.binding().contract_digest()
                != &FigmaDesignContract::baseline()
                    .map_err(|_| FigmaProviderError::RegistrationInvalid)?
                    .digest()
            || secret_reference.scope_digest() != &registration.scope().digest()
        {
            return Err(FigmaProviderError::ScopeMismatch);
        }
        Ok(Self {
            transport,
            registration,
            secret_reference,
            auth_method,
            retry_policy: RetryPolicy::default_layer1(),
        })
    }

    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    fn ensure_usable(&self) -> Result<(), FigmaProviderError> {
        if !self.registration.is_active() {
            return Err(FigmaProviderError::RegistrationInactive);
        }
        if self.secret_reference.is_revoked() {
            return Err(FigmaProviderError::SecretRevoked);
        }
        if self.secret_reference.scope_digest() != &self.registration.scope().digest() {
            return Err(FigmaProviderError::SecretReferenceMismatch);
        }
        Ok(())
    }

    fn evidence_for_response(&self) -> FigmaProviderEvidence {
        FigmaProviderEvidence::new(
            self.transport.mode(),
            self.registration.scope().digest(),
            self.registration.record_digest().clone(),
            self.registration.binding().provider_version().clone(),
        )
    }

    fn with_retry<R, F>(&mut self, mut operation: F) -> Result<R, FigmaProviderError>
    where
        F: FnMut(&mut T) -> Result<R, FigmaTransportError>,
    {
        let max_attempts = self.retry_policy.max_attempts;
        let transport = &mut self.transport;
        let mut attempts = 0;
        loop {
            attempts += 1;
            match operation(transport) {
                Ok(response) => return Ok(response),
                Err(error) if error.kind().retryable() && attempts < max_attempts => {}
                Err(error) => {
                    if error.kind() == FigmaTransportErrorKind::StaleVersion {
                        return Err(FigmaProviderError::StaleVersion);
                    }
                    return Err(FigmaProviderError::Transport {
                        kind: error.kind(),
                        attempts,
                    });
                }
            }
        }
    }

    pub fn read_file_metadata(
        &mut self,
    ) -> Result<ProviderObservation<FigmaFileMetadata>, FigmaProviderError> {
        self.ensure_usable()?;
        let scope = self.registration.scope().clone();
        let response = self.with_retry(|transport| transport.read_file_metadata(&scope))?;
        response
            .metadata
            .validate_for_scope(&scope)
            .map_err(|error| match error {
                FigmaTypeError::InvalidScope => FigmaProviderError::StaleVersion,
                _ => FigmaProviderError::InvalidResponse("file metadata integrity"),
            })?;
        Ok(ProviderObservation {
            value: response.metadata,
            response_digest: response.response_digest,
            evidence: self.evidence_for_response(),
        })
    }

    pub fn list_versions(
        &mut self,
        page_size: usize,
        cursor: Option<&PageCursor>,
    ) -> Result<ProviderObservation<VersionHistoryResponse>, FigmaProviderError> {
        self.ensure_usable()?;
        if page_size == 0 || page_size > MAX_VERSION_PAGE_SIZE {
            return Err(FigmaProviderError::InvalidPageSize);
        }
        let scope = self.registration.scope().clone();
        let response =
            self.with_retry(|transport| transport.list_versions(&scope, page_size, cursor))?;
        if response.versions.len() > page_size {
            return Err(FigmaProviderError::InvalidResponse(
                "version page exceeds requested bound",
            ));
        }
        let mut ids = BTreeSet::new();
        if response.versions.iter().any(|version| {
            version.validate_integrity().is_err() || !ids.insert(version.version_id().clone())
        }) {
            return Err(FigmaProviderError::InvalidResponse(
                "duplicate version in page",
            ));
        }
        Ok(ProviderObservation {
            value: response.clone(),
            response_digest: response.response_digest.clone(),
            evidence: self.evidence_for_response(),
        })
    }

    pub fn read_node_metadata(
        &mut self,
    ) -> Result<ProviderObservation<Vec<FigmaNodeMetadata>>, FigmaProviderError> {
        self.ensure_usable()?;
        let scope = self.registration.scope().clone();
        let response = self.with_retry(|transport| transport.read_node_metadata(&scope))?;
        let mut ids = BTreeSet::new();
        if response.nodes.len() != scope.node_ids().len()
            || response.nodes.iter().any(|node| {
                node.validate_for_scope(&scope).is_err() || !ids.insert(node.node_id().clone())
            })
        {
            return Err(FigmaProviderError::InvalidResponse(
                "node scope is incomplete or ambiguous",
            ));
        }
        Ok(ProviderObservation {
            value: response.nodes,
            response_digest: response.response_digest,
            evidence: self.evidence_for_response(),
        })
    }

    pub fn export(
        &mut self,
        request: &ExportRequest,
    ) -> Result<ProviderObservation<FigmaExportPayload>, FigmaProviderError> {
        self.ensure_usable()?;
        let scope = self.registration.scope().clone();
        if request.file_key() != scope.file_key()
            || request.version_id() != scope.version_id()
            || !scope.node_ids().contains(request.node_id())
        {
            return Err(FigmaProviderError::ScopeMismatch);
        }
        let response = self.with_retry(|transport| transport.export(&scope, request))?;
        response
            .payload
            .verify_exact(request)
            .map_err(|_| FigmaProviderError::ExportFence)?;
        Ok(ProviderObservation {
            value: response.payload,
            response_digest: response.response_digest,
            evidence: self.evidence_for_response(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &FigmaDesignRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &FigmaScope {
        self.registration.scope()
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub const fn auth_method(&self) -> &FigmaAuthMethod {
        &self.auth_method
    }

    #[must_use]
    pub fn provider_version(&self) -> &ProviderVersion {
        self.registration.binding().provider_version()
    }

    #[must_use]
    pub fn mode(&self) -> FigmaProviderMode {
        self.transport.mode()
    }

    #[must_use]
    pub fn evidence(&self) -> FigmaProviderEvidence {
        self.evidence_for_response()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FigmaTransportCall {
    FileMetadata,
    VersionHistory {
        page_size: usize,
        cursor_present: bool,
    },
    NodeMetadata,
    BoundedExport {
        request_digest: Sha256Digest,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingFigmaTransport {
    mode: FigmaProviderMode,
    file: FigmaFileMetadata,
    versions: Vec<FigmaVersion>,
    nodes: Vec<FigmaNodeMetadata>,
    exports: Vec<FigmaExportPayload>,
    calls: Vec<FigmaTransportCall>,
    failures: VecDeque<FigmaTransportError>,
}

impl RecordingFigmaTransport {
    pub fn new(
        mode: FigmaProviderMode,
        file: FigmaFileMetadata,
        versions: Vec<FigmaVersion>,
        nodes: Vec<FigmaNodeMetadata>,
        exports: Vec<FigmaExportPayload>,
    ) -> Result<Self, FigmaProviderError> {
        if mode == FigmaProviderMode::BlockedEnv {
            return Err(FigmaProviderError::InvalidResponse(
                "BLOCKED_ENV uses BlockedEnvTransport",
            ));
        }
        Ok(Self {
            mode,
            file,
            versions,
            nodes,
            exports,
            calls: Vec::new(),
            failures: VecDeque::new(),
        })
    }

    #[must_use]
    pub fn calls(&self) -> &[FigmaTransportCall] {
        &self.calls
    }

    pub fn fail_next(&mut self, error: FigmaTransportError) {
        self.failures.push_back(error);
    }

    fn maybe_fail(&mut self) -> Result<(), FigmaTransportError> {
        match self.failures.pop_front() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn page_response(
        &self,
        start: usize,
        end: usize,
    ) -> Result<VersionHistoryResponse, FigmaTransportError> {
        let versions = self.versions[start..end].to_vec();
        let next_cursor =
            if end < self.versions.len() {
                Some(PageCursor::new(format!("offset:{end}")).map_err(|_| {
                    FigmaTransportError::new(FigmaTransportErrorKind::InvalidResponse)
                })?)
            } else {
                None
            };
        let response_digest = Sha256Digest::from_serializable(&(
            &versions,
            end,
            next_cursor.as_ref().map(PageCursor::raw),
        ))
        .map_err(|_| FigmaTransportError::new(FigmaTransportErrorKind::InvalidResponse))?;
        Ok(VersionHistoryResponse {
            versions,
            next_cursor,
            response_digest,
        })
    }
}

impl FigmaTransport for RecordingFigmaTransport {
    fn mode(&self) -> FigmaProviderMode {
        self.mode
    }

    fn read_file_metadata(
        &mut self,
        _scope: &FigmaScope,
    ) -> Result<FileMetadataResponse, FigmaTransportError> {
        self.calls.push(FigmaTransportCall::FileMetadata);
        self.maybe_fail()?;
        Ok(FileMetadataResponse {
            metadata: self.file.clone(),
            response_digest: self.file.metadata_digest().clone(),
        })
    }

    fn list_versions(
        &mut self,
        _scope: &FigmaScope,
        page_size: usize,
        cursor: Option<&PageCursor>,
    ) -> Result<VersionHistoryResponse, FigmaTransportError> {
        self.calls.push(FigmaTransportCall::VersionHistory {
            page_size,
            cursor_present: cursor.is_some(),
        });
        self.maybe_fail()?;
        let start = cursor
            .map(|cursor| {
                cursor
                    .raw()
                    .strip_prefix("offset:")
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or_else(|| {
                        FigmaTransportError::new(FigmaTransportErrorKind::InvalidResponse)
                    })
            })
            .transpose()?
            .unwrap_or(0);
        let end = start.saturating_add(page_size).min(self.versions.len());
        if start > self.versions.len() {
            return Err(FigmaTransportError::new(
                FigmaTransportErrorKind::InvalidResponse,
            ));
        }
        self.page_response(start, end)
    }

    fn read_node_metadata(
        &mut self,
        _scope: &FigmaScope,
    ) -> Result<NodeMetadataResponse, FigmaTransportError> {
        self.calls.push(FigmaTransportCall::NodeMetadata);
        self.maybe_fail()?;
        let response_digest = Sha256Digest::from_serializable(&self.nodes)
            .map_err(|_| FigmaTransportError::new(FigmaTransportErrorKind::InvalidResponse))?;
        Ok(NodeMetadataResponse {
            nodes: self.nodes.clone(),
            response_digest,
        })
    }

    fn export(
        &mut self,
        _scope: &FigmaScope,
        request: &ExportRequest,
    ) -> Result<ExportResponse, FigmaTransportError> {
        self.calls.push(FigmaTransportCall::BoundedExport {
            request_digest: request.digest(),
        });
        self.maybe_fail()?;
        let payload = self
            .exports
            .iter()
            .find(|payload| {
                payload.metadata().file_key() == request.file_key()
                    && payload.metadata().version_id() == request.version_id()
                    && payload.metadata().node_id() == request.node_id()
                    && payload.metadata().format() == request.format()
                    && payload.metadata().scale() == request.scale()
            })
            .cloned()
            .ok_or_else(|| FigmaTransportError::new(FigmaTransportErrorKind::NotFound))?;
        let response_digest = Sha256Digest::from_serializable(payload.metadata())
            .map_err(|_| FigmaTransportError::new(FigmaTransportErrorKind::InvalidResponse))?;
        Ok(ExportResponse {
            payload,
            response_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl FigmaTransport for BlockedEnvTransport {
    fn mode(&self) -> FigmaProviderMode {
        FigmaProviderMode::BlockedEnv
    }

    fn read_file_metadata(
        &mut self,
        _scope: &FigmaScope,
    ) -> Result<FileMetadataResponse, FigmaTransportError> {
        Err(FigmaTransportError::blocked_env())
    }

    fn list_versions(
        &mut self,
        _scope: &FigmaScope,
        _page_size: usize,
        _cursor: Option<&PageCursor>,
    ) -> Result<VersionHistoryResponse, FigmaTransportError> {
        Err(FigmaTransportError::blocked_env())
    }

    fn read_node_metadata(
        &mut self,
        _scope: &FigmaScope,
    ) -> Result<NodeMetadataResponse, FigmaTransportError> {
        Err(FigmaTransportError::blocked_env())
    }

    fn export(
        &mut self,
        _scope: &FigmaScope,
        _request: &ExportRequest,
    ) -> Result<ExportResponse, FigmaTransportError> {
        Err(FigmaTransportError::blocked_env())
    }
}

#[must_use]
pub fn fixture_provider_version() -> ProviderVersion {
    ProviderVersion::new(FIGMA_PROVIDER_VERSION).expect("fixture provider version")
}

#[must_use]
pub fn fixture_file_metadata(scope: &FigmaScope) -> FigmaFileMetadata {
    FigmaFileMetadata::new(
        scope.file_key().clone(),
        scope.version_id().clone(),
        crate::types::FigmaTimestamp::new("2026-08-14T00:00:00Z").expect("fixture timestamp"),
        crate::types::FigmaTimestamp::new("2026-08-14T00:00:00Z").expect("fixture timestamp"),
        RedactedText::new("fixture design file").expect("fixture name"),
        scope,
    )
}

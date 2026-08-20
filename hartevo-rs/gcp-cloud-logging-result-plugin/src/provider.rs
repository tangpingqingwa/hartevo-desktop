use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GCP_CLOUD_LOGGING_RESULT_API_OPERATION, GCP_CLOUD_LOGGING_RESULT_API_VERSION,
    GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID, GCP_CLOUD_LOGGING_RESULT_PROVIDER_VERSION,
    model::{
        Digest, FilterAst, GcpCloudLoggingScope, LogEntryAggregate, MAX_PAGE_SIZE,
        MAX_RESULT_PAGES, ModelError, OpaquePageToken, PermissionFence, ProviderErrorEvidence,
        ProviderErrorKind,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpCloudLoggingApiVersion {
    V2,
}

impl GcpCloudLoggingApiVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2 => "v2",
        }
    }

    pub const fn entries_list_path(self) -> &'static str {
        match self {
            Self::V2 => "/v2/entries:list",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty, malformed, or too long")]
    InvalidVersion,
    #[error("the Layer-1 provider API must be v2")]
    ApiVersionMismatch,
    #[error("the Layer-1 provider must include logging.logEntries.list")]
    MissingPermission,
    #[error("Layer 1 cannot register a connected, native, or first-party provider")]
    NativeProviderForbidden,
    #[error("provider definition is tampered")]
    TamperedDefinition,
    #[error("provider scope does not match the request")]
    ScopeMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudLoggingProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_version: GcpCloudLoggingApiVersion,
    pub operation: String,
    pub permissions: Vec<crate::GcpLoggingPermission>,
    pub permission_digest: Digest,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_digest: Digest,
}

impl GcpCloudLoggingProviderDefinition {
    pub fn new(
        api_version: GcpCloudLoggingApiVersion,
        permissions: impl IntoIterator<Item = crate::GcpLoggingPermission>,
        provenance: ProviderProvenance,
        version: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        let version = version.into();
        if version.is_empty()
            || version.len() > 64
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        if api_version != GcpCloudLoggingApiVersion::V2 {
            return Err(ProviderDefinitionError::ApiVersionMismatch);
        }
        let permission_set = permissions
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        if !permission_set.contains(&crate::GcpLoggingPermission::LogEntriesList) {
            return Err(ProviderDefinitionError::MissingPermission);
        }
        if provenance.connected() || provenance.native() || provenance.first_party() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let permissions = permission_set.into_iter().collect::<Vec<_>>();
        let permission_digest = PermissionFence::new(permissions.iter().copied())
            .map_err(|_| ProviderDefinitionError::MissingPermission)?
            .digest()
            .clone();
        let provider_digest =
            Self::compute_digest(&version, api_version, &permission_digest, provenance);
        Ok(Self {
            id: GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID.to_owned(),
            version,
            api_version,
            operation: GCP_CLOUD_LOGGING_RESULT_API_OPERATION.to_owned(),
            permissions,
            permission_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_digest,
        })
    }

    pub fn layer1(provenance: ProviderProvenance) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            GcpCloudLoggingApiVersion::V2,
            [crate::GcpLoggingPermission::LogEntriesList],
            provenance,
            GCP_CLOUD_LOGGING_RESULT_PROVIDER_VERSION,
        )
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.id != GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID
            || self.operation != GCP_CLOUD_LOGGING_RESULT_API_OPERATION
            || self.api_version != GcpCloudLoggingApiVersion::V2
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ProviderDefinitionError::TamperedDefinition);
        }
        let permission_digest = PermissionFence::new(self.permissions.iter().copied())
            .map_err(|_| ProviderDefinitionError::TamperedDefinition)?
            .digest()
            .clone();
        let expected = Self::compute_digest(
            &self.version,
            self.api_version,
            &permission_digest,
            self.provenance,
        );
        if permission_digest != self.permission_digest || expected != self.provider_digest {
            Err(ProviderDefinitionError::TamperedDefinition)
        } else {
            Ok(())
        }
    }

    pub fn validate_scope(
        &self,
        scope: &GcpCloudLoggingScope,
    ) -> Result<(), ProviderDefinitionError> {
        self.validate()?;
        if self.permission_digest != *scope.permission_digest() {
            return Err(ProviderDefinitionError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }

    fn compute_digest(
        version: &str,
        api_version: GcpCloudLoggingApiVersion,
        permission_digest: &Digest,
        provenance: ProviderProvenance,
    ) -> Digest {
        Digest::from_fields(
            "gcp-cloud-logging-provider-definition/v1",
            &[
                GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID.to_owned(),
                version.to_owned(),
                api_version.as_str().to_owned(),
                GCP_CLOUD_LOGGING_RESULT_API_OPERATION.to_owned(),
                permission_digest.as_str().to_owned(),
                format!("{provenance:?}"),
                "connected=false".to_owned(),
                "native=false".to_owned(),
                "first_party=false".to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntriesListRequest {
    pub api_version: GcpCloudLoggingApiVersion,
    pub operation: String,
    pub resource_scope_digest: Digest,
    pub scope_digest: Digest,
    pub filter: FilterAst,
    pub view_resource_name: String,
    pub page_number: u8,
    pub page_size: u32,
    pub page_token_digest: Option<Digest>,
    pub page_binding_digest: Digest,
    pub request_digest: Digest,
    pub native_execution: bool,
}

impl EntriesListRequest {
    pub fn new(
        scope: &GcpCloudLoggingScope,
        page_number: u8,
        page_size: u32,
        page_token: Option<&OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || page_number >= MAX_RESULT_PAGES {
            return Err(ModelError::InvalidPageSize);
        }
        let filter = scope.filter_ast()?;
        let page_binding_digest = Self::compute_page_binding(scope, &filter, page_size);
        if let Some(token) = page_token
            && token.binding_digest() != Some(&page_binding_digest)
        {
            return Err(ModelError::InvalidPageToken);
        }
        let page_token_digest = page_token
            .as_ref()
            .map(|token| token.token_digest().clone());
        let request_digest = Self::compute_request_digest(
            scope,
            &filter,
            page_number,
            page_size,
            page_token_digest.as_ref(),
        );
        Ok(Self {
            api_version: GcpCloudLoggingApiVersion::V2,
            operation: GCP_CLOUD_LOGGING_RESULT_API_OPERATION.to_owned(),
            resource_scope_digest: scope.resource.digest().clone(),
            scope_digest: scope.digest(),
            filter,
            view_resource_name: scope.resource.view_resource_name(),
            page_number,
            page_size,
            page_token_digest,
            page_binding_digest,
            request_digest,
            native_execution: false,
        })
    }

    pub fn first(scope: &GcpCloudLoggingScope) -> Result<Self, ModelError> {
        Self::new(scope, 0, MAX_PAGE_SIZE, None)
    }

    pub fn next(
        scope: &GcpCloudLoggingScope,
        previous: &Self,
        token: &OpaquePageToken,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            previous.page_number.saturating_add(1),
            previous.page_size,
            Some(token),
        )
    }

    pub fn validate_for(&self, scope: &GcpCloudLoggingScope) -> Result<(), ModelError> {
        let filter = scope.filter_ast()?;
        let expected_binding = Self::compute_page_binding(scope, &filter, self.page_size);
        let expected_request = Self::compute_request_digest(
            scope,
            &filter,
            self.page_number,
            self.page_size,
            self.page_token_digest.as_ref(),
        );
        if expected_request != self.request_digest
            || expected_binding != self.page_binding_digest
            || self.scope_digest != scope.digest()
            || self.resource_scope_digest != *scope.provider_resource_digest()
            || self.filter != filter
            || self.native_execution
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn page_binding_digest(&self) -> &Digest {
        &self.page_binding_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    fn compute_page_binding(
        scope: &GcpCloudLoggingScope,
        filter: &FilterAst,
        page_size: u32,
    ) -> Digest {
        Digest::from_fields(
            "gcp-cloud-logging-page-binding/v1",
            &[
                scope.resource.digest().as_str().to_owned(),
                scope.digest().as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                filter.digest().as_str().to_owned(),
                page_size.to_string(),
                GCP_CLOUD_LOGGING_RESULT_API_VERSION.to_owned(),
                GCP_CLOUD_LOGGING_RESULT_API_OPERATION.to_owned(),
            ],
        )
    }

    fn compute_request_digest(
        scope: &GcpCloudLoggingScope,
        filter: &FilterAst,
        page_number: u8,
        page_size: u32,
        page_token_digest: Option<&Digest>,
    ) -> Digest {
        Digest::from_fields(
            "gcp-cloud-logging-entries-list-request/v1",
            &[
                GCP_CLOUD_LOGGING_RESULT_API_VERSION.to_owned(),
                GCP_CLOUD_LOGGING_RESULT_API_OPERATION.to_owned(),
                scope.resource.digest().as_str().to_owned(),
                scope.digest().as_str().to_owned(),
                filter.digest().as_str().to_owned(),
                scope.resource.view_resource_name(),
                page_number.to_string(),
                page_size.to_string(),
                page_token_digest
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                "native_execution=false".to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEntriesPage {
    pub request_digest: Digest,
    pub page_binding_digest: Digest,
    pub page_number: u8,
    pub entries: Vec<LogEntryAggregate>,
    pub next_page_token: Option<OpaquePageToken>,
    pub complete: bool,
    pub page_digest: Digest,
}

impl LogEntriesPage {
    pub fn new(
        scope: &GcpCloudLoggingScope,
        request: &EntriesListRequest,
        mut entries: Vec<LogEntryAggregate>,
        next_page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        request.filter.validate(scope)?;
        if entries.len() > request.page_size as usize {
            return Err(ModelError::InvalidPage);
        }
        for entry in &entries {
            entry.validate_for(scope)?;
        }
        entries.sort_by_key(|entry| {
            (
                entry.timestamp_seconds,
                entry.severity,
                entry.resource_type.as_str().to_owned(),
                entry.log_id.as_str().to_owned(),
                entry.metadata_digest.as_str().to_owned(),
            )
        });
        let next_page_token = match next_page_token {
            Some(token) => match token.binding_digest() {
                None => Some(token.bind(request.page_binding_digest())),
                Some(binding) if binding == request.page_binding_digest() => Some(token),
                Some(_) => return Err(ModelError::InvalidPageToken),
            },
            None => None,
        };
        let complete = next_page_token.is_none();
        let page_digest =
            Self::compute_digest(request, &entries, next_page_token.as_ref(), complete);
        Ok(Self {
            request_digest: request.request_digest.clone(),
            page_binding_digest: request.page_binding_digest.clone(),
            page_number: request.page_number,
            entries,
            next_page_token,
            complete,
            page_digest,
        })
    }

    pub fn empty(
        scope: &GcpCloudLoggingScope,
        request: &EntriesListRequest,
    ) -> Result<Self, ModelError> {
        Self::new(scope, request, Vec::new(), None)
    }

    pub fn validate_for(
        &self,
        scope: &GcpCloudLoggingScope,
        request: &EntriesListRequest,
    ) -> Result<(), ModelError> {
        if self.request_digest != *request.request_digest()
            || self.page_binding_digest != *request.page_binding_digest()
            || self.page_number != request.page_number
            || self.complete != self.next_page_token.is_none()
            || self.entries.len() > request.page_size as usize
        {
            return Err(ModelError::InvalidPage);
        }
        for entry in &self.entries {
            entry.validate_for(scope)?;
        }
        let expected = Self::compute_digest(
            request,
            &self.entries,
            self.next_page_token.as_ref(),
            self.complete,
        );
        if expected == self.page_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(
        request: &EntriesListRequest,
        entries: &[LogEntryAggregate],
        next_page_token: Option<&OpaquePageToken>,
        complete: bool,
    ) -> Digest {
        let entry_digests = entries
            .iter()
            .map(LogEntryAggregate::digest)
            .map(|digest| digest.as_str().to_owned())
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_fields(
            "gcp-cloud-logging-page/v1",
            &[
                request.request_digest.as_str().to_owned(),
                request.page_binding_digest.as_str().to_owned(),
                request.page_number.to_string(),
                entry_digests,
                next_page_token.map_or_else(
                    || "none".to_owned(),
                    |token| token.token_digest().to_string(),
                ),
                complete.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GCP Cloud Logging transport error")]
pub struct TransportError {
    evidence: ProviderErrorEvidence,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            evidence: ProviderErrorEvidence::new(kind, status_code, diagnostic),
        }
    }

    pub fn from_status(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        Self {
            evidence: ProviderErrorEvidence::from_status(status_code, diagnostic),
        }
    }

    pub fn timeout(diagnostic: impl AsRef<[u8]>) -> Self {
        Self {
            evidence: ProviderErrorEvidence::timeout(diagnostic),
        }
    }

    pub fn blocked_env() -> Self {
        Self {
            evidence: ProviderErrorEvidence::blocked_env(),
        }
    }

    pub fn evidence(&self) -> &ProviderErrorEvidence {
        &self.evidence
    }

    pub fn kind(&self) -> ProviderErrorKind {
        self.evidence.kind
    }

    pub fn status_code(&self) -> Option<u16> {
        self.evidence.status_code
    }
}

pub trait GcpCloudLoggingTransport: fmt::Debug {
    fn list_entries(
        &mut self,
        request: &EntriesListRequest,
    ) -> Result<LogEntriesPage, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportCall {
    pub operation: String,
    pub request_digest: Digest,
    pub page_number: u8,
    pub page_token_digest: Option<Digest>,
    pub native_execution: bool,
}

impl TransportCall {
    fn from_request(request: &EntriesListRequest) -> Self {
        Self {
            operation: GCP_CLOUD_LOGGING_RESULT_API_OPERATION.to_owned(),
            request_digest: request.request_digest.clone(),
            page_number: request.page_number,
            page_token_digest: request.page_token_digest.clone(),
            native_execution: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingGcpCloudLoggingTransport {
    responses: VecDeque<Result<LogEntriesPage, TransportError>>,
    calls: Vec<TransportCall>,
}

impl RecordingGcpCloudLoggingTransport {
    pub fn push_response(&mut self, response: Result<LogEntriesPage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    pub fn call_count(&self) -> usize {
        self.calls.len()
    }
}

impl GcpCloudLoggingTransport for RecordingGcpCloudLoggingTransport {
    fn list_entries(
        &mut self,
        request: &EntriesListRequest,
    ) -> Result<LogEntriesPage, TransportError> {
        self.calls.push(TransportCall::from_request(request));
        self.responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "recording transport exhausted",
            ))
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureGcpCloudLoggingTransport {
    inner: RecordingGcpCloudLoggingTransport,
}

impl FixtureGcpCloudLoggingTransport {
    pub fn push_response(&mut self, response: Result<LogEntriesPage, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }

    pub fn call_count(&self) -> usize {
        self.inner.call_count()
    }
}

impl GcpCloudLoggingTransport for FixtureGcpCloudLoggingTransport {
    fn list_entries(
        &mut self,
        request: &EntriesListRequest,
    ) -> Result<LogEntriesPage, TransportError> {
        self.inner.list_entries(request)
    }
}

pub type FakeGcpCloudLoggingTransport = FixtureGcpCloudLoggingTransport;

#[derive(Clone, Debug, Default)]
pub struct LoopbackGcpCloudLoggingTransport {
    inner: RecordingGcpCloudLoggingTransport,
}

impl LoopbackGcpCloudLoggingTransport {
    pub fn push_response(&mut self, response: Result<LogEntriesPage, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }
}

impl GcpCloudLoggingTransport for LoopbackGcpCloudLoggingTransport {
    fn list_entries(
        &mut self,
        request: &EntriesListRequest,
    ) -> Result<LogEntriesPage, TransportError> {
        self.inner.list_entries(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpCloudLoggingTransport;

pub type BlockedEnvTransport = BlockedEnvGcpCloudLoggingTransport;

impl GcpCloudLoggingTransport for BlockedEnvGcpCloudLoggingTransport {
    fn list_entries(
        &mut self,
        _request: &EntriesListRequest,
    ) -> Result<LogEntriesPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub struct GcpCloudLoggingProvider<T>
where
    T: GcpCloudLoggingTransport,
{
    definition: GcpCloudLoggingProviderDefinition,
    transport: T,
}

impl<T> fmt::Debug for GcpCloudLoggingProvider<T>
where
    T: GcpCloudLoggingTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudLoggingProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T> GcpCloudLoggingProvider<T>
where
    T: GcpCloudLoggingTransport,
{
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = GcpCloudLoggingProviderDefinition::new(
            GcpCloudLoggingApiVersion::V2,
            [crate::GcpLoggingPermission::LogEntriesList],
            provenance,
            provider_version,
        )?;
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn layer1(
        transport: T,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            transport,
            GCP_CLOUD_LOGGING_RESULT_PROVIDER_VERSION,
            provenance,
        )
    }

    pub fn definition(&self) -> &GcpCloudLoggingProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        self.definition.digest()
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_entries(
        &mut self,
        request: &EntriesListRequest,
    ) -> Result<LogEntriesPage, TransportError> {
        self.transport.list_entries(request)
    }
}

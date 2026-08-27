use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::model::{
    BambooHrDirectoryRequest, BambooHrDirectoryScope, BambooHrDirectorySnapshot,
    BambooHrEmployeeListRequest, Digest, DirectoryEmployeeProjection, ModelError, PageCursor,
    ProviderRevision,
};
use crate::{
    BAMBOOHR_DIRECTORY_API_BASE, BAMBOOHR_DIRECTORY_API_REVISION, BAMBOOHR_DIRECTORY_PROVIDER_ID,
    BAMBOOHR_DIRECTORY_PROVIDER_IMPLEMENTATION, BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION,
    api_digest, provider_digest,
};

pub use crate::model::{ProviderProvenance, TransportProvenance};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureClass {
    BlockedEnv,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Server,
    Timeout,
    Partial,
    Tampered,
    Unsupported,
    Transport,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("BambooHR provider is blocked by the environment")]
    BlockedEnv,
    #[error("BambooHR provider returned HTTP status {status_code}")]
    HttpStatus {
        status_code: u16,
        retry_after_seconds: Option<u64>,
        diagnostic_digest: Digest,
        provenance: TransportProvenance,
    },
    #[error("BambooHR provider timed out")]
    Timeout {
        diagnostic_digest: Digest,
        provenance: TransportProvenance,
    },
    #[error("BambooHR provider returned a partial directory response")]
    Partial {
        diagnostic_digest: Digest,
        provenance: TransportProvenance,
    },
    #[error("BambooHR provider response was tampered")]
    TamperedResponse,
    #[error("BambooHR provider request is invalid: {0}")]
    InvalidRequest(#[from] ModelError),
    #[error("BambooHR provider transport failed")]
    Transport {
        diagnostic_digest: Digest,
        provenance: TransportProvenance,
    },
    #[error("BambooHR provider transport provenance drifted")]
    ProvenanceMismatch,
    #[error("BambooHR provider operation is unsupported by this transport")]
    UnsupportedOperation,
}

impl ProviderError {
    #[must_use]
    pub fn http_status(status_code: u16) -> Self {
        Self::HttpStatus {
            status_code,
            retry_after_seconds: None,
            diagnostic_digest: Digest::from_fields(
                "bamboohr-provider-http-error/v1",
                &[status_code.to_string()],
            ),
            provenance: TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self::HttpStatus {
            status_code: 429,
            retry_after_seconds,
            diagnostic_digest: Digest::from_fields(
                "bamboohr-provider-http-error/v1",
                &[
                    "429".to_owned(),
                    retry_after_seconds.unwrap_or_default().to_string(),
                ],
            ),
            provenance: TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn timeout() -> Self {
        Self::Timeout {
            diagnostic_digest: Digest::from_text("bamboohr-provider-timeout"),
            provenance: TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn partial() -> Self {
        Self::Partial {
            diagnostic_digest: Digest::from_text("bamboohr-provider-partial"),
            provenance: TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub const fn class(&self) -> ProviderFailureClass {
        match self {
            Self::BlockedEnv => ProviderFailureClass::BlockedEnv,
            Self::HttpStatus { status_code, .. } => match status_code {
                401 => ProviderFailureClass::Unauthorized,
                403 => ProviderFailureClass::Forbidden,
                404 => ProviderFailureClass::NotFound,
                409 => ProviderFailureClass::Conflict,
                429 => ProviderFailureClass::RateLimited,
                500..=599 => ProviderFailureClass::Server,
                _ => ProviderFailureClass::Transport,
            },
            Self::Timeout { .. } => ProviderFailureClass::Timeout,
            Self::Partial { .. } => ProviderFailureClass::Partial,
            Self::TamperedResponse => ProviderFailureClass::Tampered,
            Self::UnsupportedOperation => ProviderFailureClass::Unsupported,
            Self::InvalidRequest(_) => ProviderFailureClass::Transport,
            Self::Transport { .. } | Self::ProvenanceMismatch => ProviderFailureClass::Transport,
        }
    }

    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status_code, .. } => Some(*status_code),
            Self::Timeout { .. } => Some(408),
            _ => None,
        }
    }

    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::HttpStatus {
                retry_after_seconds,
                ..
            } => *retry_after_seconds,
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self.class(),
            ProviderFailureClass::RateLimited
                | ProviderFailureClass::Server
                | ProviderFailureClass::Timeout
                | ProviderFailureClass::Transport
        )
    }

    #[must_use]
    pub const fn provenance(&self) -> TransportProvenance {
        match self {
            Self::BlockedEnv => TransportProvenance::BlockedEnv,
            Self::HttpStatus { provenance, .. }
            | Self::Timeout { provenance, .. }
            | Self::Partial { provenance, .. }
            | Self::Transport { provenance, .. } => *provenance,
            Self::TamperedResponse
            | Self::InvalidRequest(_)
            | Self::ProvenanceMismatch
            | Self::UnsupportedOperation => TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::BlockedEnv => Digest::from_text("bamboohr-blocked-env"),
            Self::HttpStatus {
                diagnostic_digest, ..
            }
            | Self::Timeout {
                diagnostic_digest, ..
            }
            | Self::Partial {
                diagnostic_digest, ..
            }
            | Self::Transport {
                diagnostic_digest, ..
            } => diagnostic_digest.clone(),
            Self::TamperedResponse => Digest::from_text("bamboohr-tampered-response"),
            Self::InvalidRequest(error) => Digest::from_text(error.to_string()),
            Self::ProvenanceMismatch => Digest::from_text("bamboohr-provenance-mismatch"),
            Self::UnsupportedOperation => Digest::from_text("bamboohr-unsupported-operation"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryResponse {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub snapshot: BambooHrDirectorySnapshot,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub complete: bool,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl BambooHrDirectoryResponse {
    pub fn new(
        request: &BambooHrDirectoryRequest,
        snapshot: BambooHrDirectorySnapshot,
        response_bytes: usize,
        provider_revision: ProviderRevision,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        Self::with_completeness(
            request,
            snapshot,
            response_bytes,
            provider_revision,
            provenance,
            true,
        )
    }

    pub fn partial(
        request: &BambooHrDirectoryRequest,
        snapshot: BambooHrDirectorySnapshot,
        response_bytes: usize,
        provider_revision: ProviderRevision,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        Self::with_completeness(
            request,
            snapshot,
            response_bytes,
            provider_revision,
            provenance,
            false,
        )
    }

    pub fn with_completeness(
        request: &BambooHrDirectoryRequest,
        snapshot: BambooHrDirectorySnapshot,
        response_bytes: usize,
        provider_revision: ProviderRevision,
        provenance: TransportProvenance,
        complete: bool,
    ) -> Result<Self, ModelError> {
        if response_bytes == 0 || response_bytes > crate::model::MAX_RESPONSE_BYTES {
            return Err(ModelError::InvalidResponse);
        }
        let mut response = Self {
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            snapshot,
            response_bytes,
            provider_revision,
            complete,
            provenance,
            response_digest: Digest::from_text("unsealed-bamboohr-response"),
        };
        response.response_digest = response.compute_digest();
        Ok(response)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-directory-response/v1",
            &[
                self.request_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.snapshot.snapshot_digest.as_str().to_owned(),
                self.response_bytes.to_string(),
                self.provider_revision.as_str().to_owned(),
                self.complete.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.snapshot.verify_integrity()
            && self.request_digest.is_valid()
            && self.scope_digest.is_valid()
            && self.response_digest == self.compute_digest()
            && self.response_bytes > 0
            && self.response_bytes <= crate::model::MAX_RESPONSE_BYTES
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(&self) -> bool {
        false
    }
}

/// One bounded page from BambooHR's cursor-based employee metadata endpoint.
/// The cursor itself stays in the provider seam; serialization exposes only
/// its digest binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BambooHrEmployeeListPage {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub field_selection_digest: Digest,
    pub employees: Vec<DirectoryEmployeeProjection>,
    pub total: usize,
    pub next_cursor: Option<PageCursor>,
    pub previous_cursor: Option<PageCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub change_fence_digest: Digest,
    pub complete: bool,
    pub provenance: TransportProvenance,
    pub page_digest: Digest,
}

impl BambooHrEmployeeListPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &BambooHrEmployeeListRequest,
        mut employees: Vec<DirectoryEmployeeProjection>,
        total: usize,
        next_cursor: Option<PageCursor>,
        previous_cursor: Option<PageCursor>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
        change_fence_digest: Digest,
        provenance: TransportProvenance,
        complete: bool,
    ) -> Result<Self, ModelError> {
        if response_bytes == 0
            || response_bytes > crate::model::MAX_RESPONSE_BYTES
            || employees.len() > crate::model::MAX_RECORDS
            || total > crate::model::MAX_RECORDS * 8
            || total < employees.len()
            || !change_fence_digest.is_valid()
        {
            return Err(ModelError::InvalidResponse);
        }
        employees.sort_by(|left, right| left.employee_id_digest.cmp(&right.employee_id_digest));
        if employees.windows(2).any(|pair| {
            pair[0].employee_id_digest == pair[1].employee_id_digest
                || !pair[0].verify_integrity()
                || !pair[1].verify_integrity()
        }) || employees
            .iter()
            .any(|employee| !employee.verify_integrity())
        {
            return Err(ModelError::DuplicateRecord);
        }
        for cursor in [next_cursor.as_ref(), previous_cursor.as_ref()]
            .into_iter()
            .flatten()
        {
            if cursor.scope_digest() != &request.scope_digest
                || cursor.field_selection_digest() != &request.field_selection_digest
            {
                return Err(ModelError::InvalidScope);
            }
        }
        let mut page = Self {
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            field_selection_digest: request.field_selection_digest.clone(),
            employees,
            total,
            next_cursor,
            previous_cursor,
            response_bytes,
            provider_revision,
            change_fence_digest,
            complete,
            provenance,
            page_digest: Digest::from_text("unsealed-bamboohr-employee-page"),
        };
        page.page_digest = page.compute_digest();
        Ok(page)
    }

    fn compute_digest(&self) -> Digest {
        let employee_digest = Digest::from_serializable(&self.employees);
        Digest::from_fields(
            "bamboohr-employee-list-page/v1",
            &[
                self.request_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.field_selection_digest.as_str().to_owned(),
                employee_digest.as_str().to_owned(),
                self.total.to_string(),
                self.next_cursor
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |cursor| cursor.digest().to_string()),
                self.previous_cursor
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |cursor| cursor.digest().to_string()),
                self.response_bytes.to_string(),
                self.provider_revision.as_str().to_owned(),
                self.change_fence_digest.as_str().to_owned(),
                self.complete.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.page_digest == self.compute_digest()
            && self.request_digest.is_valid()
            && self.scope_digest.is_valid()
            && self.field_selection_digest.is_valid()
            && self.change_fence_digest.is_valid()
            && self.response_bytes > 0
            && self.response_bytes <= crate::model::MAX_RESPONSE_BYTES
            && self.employees.len() <= crate::model::MAX_RECORDS
            && self.total <= crate::model::MAX_RECORDS * 8
            && self.total >= self.employees.len()
            && self
                .employees
                .iter()
                .all(DirectoryEmployeeProjection::verify_integrity)
    }
}

impl Serialize for BambooHrEmployeeListPage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("BambooHrEmployeeListPage", 13)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("fieldSelectionDigest", &self.field_selection_digest)?;
        state.serialize_field("employees", &self.employees)?;
        state.serialize_field("total", &self.total)?;
        state.serialize_field(
            "nextCursorDigest",
            &self.next_cursor.as_ref().map(PageCursor::digest),
        )?;
        state.serialize_field(
            "previousCursorDigest",
            &self.previous_cursor.as_ref().map(PageCursor::digest),
        )?;
        state.serialize_field("responseBytes", &self.response_bytes)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("changeFenceDigest", &self.change_fence_digest)?;
        state.serialize_field("complete", &self.complete)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.serialize_field("pageDigest", &self.page_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Default)]
pub struct BambooHrDirectoryFixture {
    responses: Vec<Result<BambooHrDirectoryResponse, ProviderError>>,
    employee_pages: Vec<Result<BambooHrEmployeeListPage, ProviderError>>,
}

impl BambooHrDirectoryFixture {
    #[must_use]
    pub fn new<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<BambooHrDirectoryResponse, ProviderError>>,
    {
        Self {
            responses: responses.into_iter().collect(),
            employee_pages: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_employee_pages<I, J>(responses: I, employee_pages: J) -> Self
    where
        I: IntoIterator<Item = Result<BambooHrDirectoryResponse, ProviderError>>,
        J: IntoIterator<Item = Result<BambooHrEmployeeListPage, ProviderError>>,
    {
        Self {
            responses: responses.into_iter().collect(),
            employee_pages: employee_pages.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn employee_pages<I>(employee_pages: I) -> Self
    where
        I: IntoIterator<Item = Result<BambooHrEmployeeListPage, ProviderError>>,
    {
        Self {
            responses: Vec::new(),
            employee_pages: employee_pages.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn single(response: BambooHrDirectoryResponse) -> Self {
        Self::new([Ok(response)])
    }

    #[must_use]
    pub fn error(error: ProviderError) -> Self {
        Self::new([Err(error)])
    }
}

impl From<BambooHrDirectoryResponse> for BambooHrDirectoryFixture {
    fn from(response: BambooHrDirectoryResponse) -> Self {
        Self::single(response)
    }
}

pub trait BambooHrDirectoryTransport: Send + Sync + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_employees_directory(
        &self,
        request: &BambooHrDirectoryRequest,
    ) -> Result<BambooHrDirectoryResponse, ProviderError>;

    fn list_employees(
        &self,
        _request: &BambooHrEmployeeListRequest,
    ) -> Result<BambooHrEmployeeListPage, ProviderError> {
        Err(ProviderError::UnsupportedOperation)
    }
}

#[derive(Clone, Debug)]
pub struct ScriptedBambooHrTransport {
    provenance: TransportProvenance,
    responses: Arc<Mutex<VecDeque<Result<BambooHrDirectoryResponse, ProviderError>>>>,
    employee_pages: Arc<Mutex<VecDeque<Result<BambooHrEmployeeListPage, ProviderError>>>>,
}

impl ScriptedBambooHrTransport {
    #[must_use]
    pub fn new<I>(provenance: TransportProvenance, responses: I) -> Self
    where
        I: IntoIterator<Item = Result<BambooHrDirectoryResponse, ProviderError>>,
    {
        Self {
            provenance,
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            employee_pages: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    #[must_use]
    pub fn from_fixture(
        provenance: TransportProvenance,
        fixture: BambooHrDirectoryFixture,
    ) -> Self {
        Self {
            provenance,
            responses: Arc::new(Mutex::new(fixture.responses.into_iter().collect())),
            employee_pages: Arc::new(Mutex::new(fixture.employee_pages.into_iter().collect())),
        }
    }

    pub fn push_response(
        &self,
        response: Result<BambooHrDirectoryResponse, ProviderError>,
    ) -> Result<(), ProviderError> {
        self.responses
            .lock()
            .map_err(|_| ProviderError::Transport {
                diagnostic_digest: Digest::from_text("bamboohr-scripted-transport-poisoned"),
                provenance: self.provenance,
            })?
            .push_back(response);
        Ok(())
    }

    pub fn push_employee_page(
        &self,
        page: Result<BambooHrEmployeeListPage, ProviderError>,
    ) -> Result<(), ProviderError> {
        self.employee_pages
            .lock()
            .map_err(|_| ProviderError::Transport {
                diagnostic_digest: Digest::from_text("bamboohr-scripted-transport-poisoned"),
                provenance: self.provenance,
            })?
            .push_back(page);
        Ok(())
    }
}

impl BambooHrDirectoryTransport for ScriptedBambooHrTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_employees_directory(
        &self,
        _request: &BambooHrDirectoryRequest,
    ) -> Result<BambooHrDirectoryResponse, ProviderError> {
        self.responses
            .lock()
            .map_err(|_| ProviderError::Transport {
                diagnostic_digest: Digest::from_text("bamboohr-scripted-transport-poisoned"),
                provenance: self.provenance,
            })?
            .pop_front()
            .unwrap_or_else(|| {
                Err(ProviderError::Transport {
                    diagnostic_digest: Digest::from_text("bamboohr-scripted-response-exhausted"),
                    provenance: self.provenance,
                })
            })
    }

    fn list_employees(
        &self,
        _request: &BambooHrEmployeeListRequest,
    ) -> Result<BambooHrEmployeeListPage, ProviderError> {
        self.employee_pages
            .lock()
            .map_err(|_| ProviderError::Transport {
                diagnostic_digest: Digest::from_text("bamboohr-scripted-transport-poisoned"),
                provenance: self.provenance,
            })?
            .pop_front()
            .unwrap_or(Err(ProviderError::Transport {
                diagnostic_digest: Digest::from_text("bamboohr-scripted-employee-page-exhausted"),
                provenance: self.provenance,
            }))
    }
}

pub type RecordingBambooHrTransport = ScriptedBambooHrTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvBambooHrTransport;

impl BambooHrDirectoryTransport for BlockedEnvBambooHrTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_employees_directory(
        &self,
        _request: &BambooHrDirectoryRequest,
    ) -> Result<BambooHrDirectoryResponse, ProviderError> {
        Err(ProviderError::BlockedEnv)
    }

    fn list_employees(
        &self,
        _request: &BambooHrEmployeeListRequest,
    ) -> Result<BambooHrEmployeeListPage, ProviderError> {
        Err(ProviderError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub implementation: String,
    pub api_base: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: TransportProvenance,
    pub get_employees_directory: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub list_employees: bool,
}

impl BambooHrProviderDefinition {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            schema_version: BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: BAMBOOHR_DIRECTORY_PROVIDER_ID.to_owned(),
            implementation: BAMBOOHR_DIRECTORY_PROVIDER_IMPLEMENTATION.to_owned(),
            api_base: BAMBOOHR_DIRECTORY_API_BASE.to_owned(),
            api_revision: BAMBOOHR_DIRECTORY_API_REVISION.to_owned(),
            api_digest: api_digest(),
            provider_digest: provider_digest(),
            permission_digest: crate::permission_digest(),
            provenance,
            get_employees_directory: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            list_employees: true,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.schema_version != BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION
            || self.provider_id != BAMBOOHR_DIRECTORY_PROVIDER_ID
            || self.implementation != BAMBOOHR_DIRECTORY_PROVIDER_IMPLEMENTATION
            || self.api_revision != BAMBOOHR_DIRECTORY_API_REVISION
            || self.api_digest != api_digest()
            || self.provider_digest != provider_digest()
            || self.permission_digest != crate::permission_digest()
            || !self.get_employees_directory
            || self.external_writes
            || self.connected
            || self.native
            || self.first_party
            || !self.list_employees
        {
            return Err(ProviderError::ProvenanceMismatch);
        }
        Ok(())
    }
}

pub struct BambooHrProvider {
    transport: Arc<dyn BambooHrDirectoryTransport>,
    definition: BambooHrProviderDefinition,
    provider_revision: ProviderRevision,
}

impl fmt::Debug for BambooHrProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BambooHrProvider")
            .field("definition", &self.definition)
            .field("provider_revision", &self.provider_revision)
            .finish_non_exhaustive()
    }
}

impl BambooHrProvider {
    pub fn new<T>(transport: T) -> Result<Self, ProviderError>
    where
        T: BambooHrDirectoryTransport + 'static,
    {
        let provenance = transport.provenance();
        let definition = BambooHrProviderDefinition::new(provenance);
        definition.validate()?;
        Ok(Self {
            transport: Arc::new(transport),
            definition,
            provider_revision: ProviderRevision::new(BAMBOOHR_DIRECTORY_API_REVISION)
                .map_err(ProviderError::InvalidRequest)?,
        })
    }

    pub fn fixture<T>(fixture: T) -> Self
    where
        T: Into<BambooHrDirectoryFixture>,
    {
        Self::new(ScriptedBambooHrTransport::from_fixture(
            TransportProvenance::Fixture,
            fixture.into(),
        ))
        .expect("the built-in BambooHR fixture provider is valid")
    }

    pub fn recording<T>(fixture: T) -> Self
    where
        T: Into<BambooHrDirectoryFixture>,
    {
        Self::new(ScriptedBambooHrTransport::from_fixture(
            TransportProvenance::Recording,
            fixture.into(),
        ))
        .expect("the built-in BambooHR recording provider is valid")
    }

    pub fn loopback<T>(fixture: T) -> Self
    where
        T: Into<BambooHrDirectoryFixture>,
    {
        Self::new(ScriptedBambooHrTransport::from_fixture(
            TransportProvenance::Loopback,
            fixture.into(),
        ))
        .expect("the built-in BambooHR loopback provider is valid")
    }

    pub fn blocked_env() -> Self {
        Self::new(BlockedEnvBambooHrTransport)
            .expect("the built-in BambooHR blocked provider is valid")
    }

    #[must_use]
    pub fn definition(&self) -> &BambooHrProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.definition.provider_id
    }

    #[must_use]
    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    #[must_use]
    pub fn api_digest(&self) -> &Digest {
        &self.definition.api_digest
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(&self) -> bool {
        false
    }

    pub fn read_directory(
        &self,
        request: &BambooHrDirectoryRequest,
    ) -> Result<BambooHrDirectoryResponse, ProviderError> {
        if request.method != "GET"
            || !request.accept_json
            || request.path_digest != Digest::from_text("GET /api/v1/employees/directory")
        {
            return Err(ProviderError::InvalidRequest(ModelError::InvalidResponse));
        }
        let response = self.transport.get_employees_directory(request)?;
        if response.provenance != self.provenance()
            || !response.verify_integrity()
            || response.request_digest != request.request_digest
            || response.scope_digest != request.scope_digest
        {
            return Err(ProviderError::TamperedResponse);
        }
        if !response.complete {
            return Err(ProviderError::Partial {
                diagnostic_digest: response.response_digest.clone(),
                provenance: self.provenance(),
            });
        }
        Ok(response)
    }

    pub fn list_employees(
        &self,
        request: &BambooHrEmployeeListRequest,
    ) -> Result<BambooHrEmployeeListPage, ProviderError> {
        if !request.verify_integrity()
            || request.method != "GET"
            || request.path_digest != Digest::from_text("GET /api/v1/employees")
        {
            return Err(ProviderError::InvalidRequest(ModelError::InvalidResponse));
        }
        let page = self.transport.list_employees(request)?;
        if page.provenance != self.provenance()
            || !page.verify_integrity()
            || page.request_digest != request.request_digest
            || page.scope_digest != request.scope_digest
            || page.field_selection_digest != request.field_selection_digest
            || page.provider_revision != *self.provider_revision()
        {
            return Err(ProviderError::TamperedResponse);
        }
        Ok(page)
    }

    pub fn read_directory_for_scope(
        &self,
        scope: &BambooHrDirectoryScope,
    ) -> Result<BambooHrDirectoryResponse, ProviderError> {
        let request =
            BambooHrDirectoryRequest::new(scope).map_err(ProviderError::InvalidRequest)?;
        self.read_directory(&request)
    }
}

pub type BambooHRProvider = BambooHrProvider;
pub type BambooHRDirectoryResponse = BambooHrDirectoryResponse;

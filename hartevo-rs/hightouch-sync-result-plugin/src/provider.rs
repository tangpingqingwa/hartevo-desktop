use std::{
    cell::RefCell,
    collections::{BTreeSet, VecDeque},
    fmt,
    rc::Rc,
};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::model::{
    Digest, HightouchBackoffReceipt, HightouchCursor, HightouchDestinationProjection,
    HightouchHttpMethod, HightouchModelProjection, HightouchOperation, HightouchRateLimitReceipt,
    HightouchReadReceipt, HightouchResourceStatus, HightouchRunProjection, HightouchRunStatus,
    HightouchSourceProjection, HightouchSyncProjection, HightouchSyncScope,
    HightouchWorkspaceProjection, MAX_BACKOFF_SECONDS, MAX_CURSOR_BYTES, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_RETRY_ATTEMPTS, MAX_RUNS_PER_PAGE, ModelError, TransportProvenance,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HightouchProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub base_url: String,
    pub read_only: bool,
    pub live_external_io: bool,
    pub external_writes: bool,
    pub operations: Vec<HightouchOperation>,
    pub max_pages: u16,
    pub max_runs_per_page: usize,
    pub max_response_bytes: usize,
    pub max_retry_attempts: u8,
    pub max_backoff_seconds: u32,
}

impl Default for HightouchProviderDefinition {
    fn default() -> Self {
        Self {
            id: crate::HIGHTOUCH_PROVIDER_ID.to_owned(),
            version: crate::HIGHTOUCH_PROVIDER_VERSION.to_owned(),
            api_revision: crate::HIGHTOUCH_PROVIDER_API_REVISION.to_owned(),
            base_url: crate::HIGHTOUCH_API_BASE_URL.to_owned(),
            read_only: true,
            live_external_io: false,
            external_writes: false,
            operations: vec![
                HightouchOperation::GetWorkspace,
                HightouchOperation::GetSource,
                HightouchOperation::GetModel,
                HightouchOperation::GetDestination,
                HightouchOperation::GetSync,
                HightouchOperation::ListRuns,
            ],
            max_pages: MAX_PAGES,
            max_runs_per_page: MAX_RUNS_PER_PAGE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_retry_attempts: MAX_RETRY_ATTEMPTS,
            max_backoff_seconds: MAX_BACKOFF_SECONDS,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HightouchRequest {
    pub operation: HightouchOperation,
    pub method: HightouchHttpMethod,
    path: String,
    path_digest: Digest,
    pub scope_digest: Digest,
    pub page: u16,
    pub attempt: u8,
    cursor_digest: Option<Digest>,
}

impl fmt::Debug for HightouchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HightouchRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("path_digest", &self.path_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page", &self.page)
            .field("attempt", &self.attempt)
            .field("cursor_digest", &self.cursor_digest)
            .finish()
    }
}

impl Serialize for HightouchRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HightouchRequest", 8)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("pathDigest", &self.path_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("page", &self.page)?;
        state.serialize_field("attempt", &self.attempt)?;
        state.serialize_field("cursorDigest", &self.cursor_digest)?;
        state.serialize_field("allowlisted", &self.is_allowlisted())?;
        state.end()
    }
}

impl HightouchRequest {
    fn new(
        operation: HightouchOperation,
        scope: &HightouchSyncScope,
        page: u16,
        attempt: u8,
        cursor: Option<&str>,
    ) -> Result<Self, HightouchProviderError> {
        if !(1..=MAX_PAGES).contains(&page) || attempt == 0 {
            return Err(HightouchProviderError::InvalidRequest);
        }
        if cursor.is_some_and(|value| value.is_empty() || value.len() > MAX_CURSOR_BYTES) {
            return Err(HightouchProviderError::InvalidRequest);
        }
        let path = match operation {
            HightouchOperation::GetWorkspace => {
                format!("/workspaces/{}", scope.workspace_id().as_str())
            }
            HightouchOperation::GetSource => format!("/sources/{}", scope.source_id().as_str()),
            HightouchOperation::GetModel => format!("/models/{}", scope.model_id().as_str()),
            HightouchOperation::GetDestination => {
                format!("/destinations/{}", scope.destination_id().as_str())
            }
            HightouchOperation::GetSync => format!("/syncs/{}", scope.sync_id().as_str()),
            HightouchOperation::ListRuns => {
                let mut path = format!(
                    "/syncs/{}/runs?limit={MAX_RUNS_PER_PAGE}",
                    scope.sync_id().as_str()
                );
                if let Some(cursor) = cursor {
                    path.push_str("&cursor=");
                    path.push_str(cursor);
                }
                path
            }
        };
        let cursor_digest =
            cursor.map(|value| HightouchCursor::from_token(value).map(|item| item.cursor_digest));
        let cursor_digest = cursor_digest
            .transpose()
            .map_err(HightouchProviderError::Model)?;
        Ok(Self {
            operation,
            method: HightouchHttpMethod::Get,
            path_digest: Digest::from_text(path.as_bytes()),
            path,
            scope_digest: scope.digest(),
            page,
            attempt,
            cursor_digest,
        })
    }

    #[must_use]
    pub fn path_digest(&self) -> &Digest {
        &self.path_digest
    }

    #[must_use]
    pub fn cursor_digest(&self) -> Option<&Digest> {
        self.cursor_digest.as_ref()
    }

    #[must_use]
    pub const fn page(&self) -> u16 {
        self.page
    }

    #[must_use]
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    #[must_use]
    pub const fn is_get(&self) -> bool {
        matches!(self.method, HightouchHttpMethod::Get)
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        if !self.is_get() || self.path.is_empty() {
            return false;
        }
        match self.operation {
            HightouchOperation::GetWorkspace => {
                self.path.starts_with("/workspaces/") && !self.path.contains('?')
            }
            HightouchOperation::GetSource => {
                self.path.starts_with("/sources/") && !self.path.contains('?')
            }
            HightouchOperation::GetModel => {
                self.path.starts_with("/models/") && !self.path.contains('?')
            }
            HightouchOperation::GetDestination => {
                self.path.starts_with("/destinations/") && !self.path.contains('?')
            }
            HightouchOperation::GetSync => {
                self.path.starts_with("/syncs/") && !self.path.contains("/runs")
            }
            HightouchOperation::ListRuns => {
                self.path.starts_with("/syncs/") && self.path.contains("/runs?limit=")
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HightouchResponse {
    status: u16,
    body: Vec<u8>,
    declared_response_digest: Option<Digest>,
}

impl fmt::Debug for HightouchResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HightouchResponse")
            .field("status", &self.status)
            .field("response_bytes", &self.body.len())
            .field("response_digest", &self.response_digest())
            .field("declared_response_digest", &self.declared_response_digest)
            .finish()
    }
}

impl Serialize for HightouchResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HightouchResponse", 4)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("responseBytes", &self.body.len())?;
        state.serialize_field("responseDigest", &self.response_digest())?;
        state.serialize_field("declaredResponseDigest", &self.declared_response_digest)?;
        state.end()
    }
}

impl HightouchResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            declared_response_digest: None,
        }
    }

    pub fn json<T: Serialize>(status: u16, value: &T) -> Result<Self, HightouchTransportError> {
        serde_json::to_vec(value)
            .map(|body| Self::new(status, body))
            .map_err(|_| HightouchTransportError::MalformedResponse)
    }

    #[must_use]
    pub fn with_declared_response_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = Some(digest);
        self
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        Digest::from_bytes(&self.body)
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn validate_size_and_digest(&self) -> Result<(), HightouchProviderError> {
        if self.body.len() > MAX_RESPONSE_BYTES {
            return Err(HightouchProviderError::ResponseTooLarge);
        }
        if self
            .declared_response_digest
            .as_ref()
            .is_some_and(|expected| expected != &self.response_digest())
        {
            return Err(HightouchProviderError::Tampered {
                diagnostic_digest: Digest::from_text("declared response digest mismatch"),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HightouchTransportError {
    #[error("native Hightouch credentials and network are unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("Hightouch transport timed out")]
    Timeout,
    #[error("Hightouch access was denied")]
    AccessLost,
    #[error("Hightouch transport rate limit")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Hightouch provider returned status {status_code}")]
    HttpStatus { status_code: u16 },
    #[error("Hightouch provider response is malformed")]
    MalformedResponse,
    #[error("Hightouch provider is unknown")]
    ProviderUnknown,
}

impl HightouchTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status_code } => Some(*status_code),
            Self::AccessLost => Some(403),
            Self::RateLimited { .. } => Some(429),
            _ => None,
        }
    }
}

pub trait HightouchTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &HightouchRequest,
    ) -> std::result::Result<HightouchResponse, HightouchTransportError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HightouchProviderError {
    #[error("Hightouch registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Hightouch opaque API-key reference is revoked")]
    SecretRevoked,
    #[error("Hightouch resource scope does not match the response")]
    ScopeMismatch,
    #[error("Hightouch cursor is not bound to the current scope revision")]
    CursorBindingMismatch,
    #[error("Hightouch run pagination exceeded the Layer-1 page bound")]
    PaginationBound,
    #[error("Hightouch run pagination repeated an opaque cursor")]
    PaginationLoop,
    #[error("Hightouch API rate limit remained after bounded retries")]
    RateLimited {
        retry_after_seconds: Option<u32>,
        attempts: u8,
    },
    #[error("Hightouch access denied")]
    Denied { status_code: Option<u16> },
    #[error("Hightouch response is tampered: {diagnostic_digest}")]
    Tampered { diagnostic_digest: Digest },
    #[error("Hightouch response is malformed: {diagnostic_digest}")]
    MalformedResponse { diagnostic_digest: Digest },
    #[error("Hightouch response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("Hightouch provider status is unknown")]
    ProviderUnknown { status_code: Option<u16> },
    #[error("Hightouch request is invalid")]
    InvalidRequest,
    #[error(transparent)]
    Transport(#[from] HightouchTransportError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl HightouchProviderError {
    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Denied { status_code } | Self::ProviderUnknown { status_code } => *status_code,
            Self::RateLimited { .. } => Some(429),
            Self::Transport(error) => error.status_code(),
            _ => None,
        }
    }

    #[must_use]
    pub fn retry_after_seconds(&self) -> Option<u32> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
                ..
            } => *retry_after_seconds,
            Self::Transport(HightouchTransportError::RateLimited {
                retry_after_seconds,
            }) => *retry_after_seconds,
            _ => None,
        }
    }

    #[must_use]
    pub fn is_blocked_env(&self) -> bool {
        matches!(self, Self::Transport(HightouchTransportError::BlockedEnv))
    }
}

#[derive(Clone, Debug)]
pub struct HightouchProviderRead {
    pub workspace: HightouchWorkspaceProjection,
    pub source: HightouchSourceProjection,
    pub model: HightouchModelProjection,
    pub sync: HightouchSyncProjection,
    pub destination: HightouchDestinationProjection,
    pub runs: Vec<HightouchRunProjection>,
    pub read_receipts: Vec<HightouchReadReceipt>,
    pub cursor_digests: Vec<Digest>,
    pub page_count: u16,
    pub listing_complete: bool,
    pub rate_limit: HightouchRateLimitReceipt,
    pub backoff: Option<HightouchBackoffReceipt>,
    pub commit_digest: Digest,
    pub provenance: TransportProvenance,
}

#[derive(Clone, Debug)]
pub struct HightouchProvider<T: HightouchTransport> {
    scope: HightouchSyncScope,
    secret: crate::SecretReference,
    transport: T,
    definition: HightouchProviderDefinition,
    provider_digest: Digest,
}

impl<T: HightouchTransport> HightouchProvider<T> {
    pub fn new(
        scope: HightouchSyncScope,
        secret: crate::SecretReference,
        transport: T,
    ) -> Result<Self, HightouchProviderError> {
        if secret.scope_digest() != &scope.digest() {
            return Err(HightouchProviderError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            secret,
            transport,
            definition: HightouchProviderDefinition::default(),
            provider_digest: crate::provider_digest(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &HightouchSyncScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &crate::SecretReference {
        &self.secret
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn definition(&self) -> &HightouchProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.provider_digest.clone()
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn validate_cursor(&self, cursor: &HightouchCursor) -> Result<(), HightouchProviderError> {
        cursor
            .validate_for_scope(&self.scope)
            .map_err(|_| HightouchProviderError::CursorBindingMismatch)
    }

    pub fn revoke_secret(&mut self) -> Result<(), HightouchProviderError> {
        self.secret.revoke().map_err(HightouchProviderError::Model)
    }

    pub fn read(&mut self) -> Result<HightouchProviderRead, HightouchProviderError> {
        if self.secret.is_revoked() {
            return Err(HightouchProviderError::SecretRevoked);
        }
        let scope = self.scope.clone();
        let mut receipts = Vec::new();
        let mut latest_rate_limit = HightouchRateLimitReceipt::default();
        let mut backoff = None;
        let workspace = self.read_resource(
            HightouchOperation::GetWorkspace,
            1,
            None,
            &mut receipts,
            &mut latest_rate_limit,
            &mut backoff,
            |value| parse_workspace(value, &scope),
        )?;
        let source = self.read_resource(
            HightouchOperation::GetSource,
            1,
            None,
            &mut receipts,
            &mut latest_rate_limit,
            &mut backoff,
            |value| parse_source(value, &scope),
        )?;
        let model = self.read_resource(
            HightouchOperation::GetModel,
            1,
            None,
            &mut receipts,
            &mut latest_rate_limit,
            &mut backoff,
            |value| parse_model(value, &scope),
        )?;
        let destination = self.read_resource(
            HightouchOperation::GetDestination,
            1,
            None,
            &mut receipts,
            &mut latest_rate_limit,
            &mut backoff,
            |value| parse_destination(value, &scope),
        )?;
        let sync = self.read_resource(
            HightouchOperation::GetSync,
            1,
            None,
            &mut receipts,
            &mut latest_rate_limit,
            &mut backoff,
            |value| parse_sync(value, &scope),
        )?;
        let mut runs = Vec::new();
        let mut cursor: Option<String> = None;
        let mut cursor_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut page_count: u16 = 0;
        let mut listing_complete = false;
        while !listing_complete {
            page_count = page_count.saturating_add(1);
            if page_count > self.definition.max_pages {
                return Err(HightouchProviderError::PaginationBound);
            }
            let page_cursor = cursor.as_deref();
            if let Some(value) = page_cursor {
                let cursor = HightouchCursor::for_scope(value, &scope)?;
                self.validate_cursor(&cursor)?;
                let digest = cursor.cursor_digest;
                if !seen_cursors.insert(digest.as_str().to_owned()) {
                    return Err(HightouchProviderError::PaginationLoop);
                }
                cursor_digests.push(digest);
            }
            let response = self.execute(
                HightouchOperation::ListRuns,
                page_count,
                page_cursor,
                &mut latest_rate_limit,
                &mut backoff,
            )?;
            let receipt = response.receipt.clone();
            let (page_runs, next_cursor) = parse_runs(response.value, &self.scope)?;
            runs.extend(page_runs);
            if runs.len() > self.definition.max_pages as usize * self.definition.max_runs_per_page {
                return Err(HightouchProviderError::PaginationBound);
            }
            receipts.push(receipt);
            match next_cursor {
                Some(next) => cursor = Some(next),
                None => listing_complete = true,
            }
        }
        if !runs
            .iter()
            .any(|run| run.id_digest == self.scope.run_id().digest())
        {
            return Err(HightouchProviderError::ScopeMismatch);
        }
        Ok(HightouchProviderRead {
            workspace,
            source,
            model,
            sync,
            destination,
            runs,
            read_receipts: receipts,
            cursor_digests,
            page_count,
            listing_complete,
            rate_limit: latest_rate_limit,
            backoff,
            commit_digest: self.scope.commit_digest().clone(),
            provenance: self.transport.provenance(),
        })
    }

    fn read_resource<U>(
        &mut self,
        operation: HightouchOperation,
        page: u16,
        cursor: Option<&str>,
        receipts: &mut Vec<HightouchReadReceipt>,
        rate_limit: &mut HightouchRateLimitReceipt,
        backoff: &mut Option<HightouchBackoffReceipt>,
        parser: impl FnOnce(&Value) -> Result<U, HightouchProviderError>,
    ) -> Result<U, HightouchProviderError> {
        let response = self.execute(operation, page, cursor, rate_limit, backoff)?;
        receipts.push(response.receipt);
        parser(&response.value)
    }

    fn execute(
        &mut self,
        operation: HightouchOperation,
        page: u16,
        cursor: Option<&str>,
        rate_limit: &mut HightouchRateLimitReceipt,
        backoff: &mut Option<HightouchBackoffReceipt>,
    ) -> Result<ExecutedResponse, HightouchProviderError> {
        let provenance = self.transport.provenance();
        let mut retry_after = None;
        for attempt in 1..=self.definition.max_retry_attempts {
            let request = HightouchRequest::new(operation, &self.scope, page, attempt, cursor)?;
            if !request.is_allowlisted() {
                return Err(HightouchProviderError::InvalidRequest);
            }
            let response = match self.transport.execute(&request) {
                Ok(response) => response,
                Err(HightouchTransportError::RateLimited {
                    retry_after_seconds,
                }) if attempt < self.definition.max_retry_attempts => {
                    retry_after = retry_after_seconds;
                    *backoff = Some(HightouchBackoffReceipt::new(
                        attempt,
                        retry_after_seconds,
                        backoff_seconds(attempt, retry_after_seconds),
                    ));
                    continue;
                }
                Err(HightouchTransportError::RateLimited {
                    retry_after_seconds,
                }) => {
                    *rate_limit =
                        HightouchRateLimitReceipt::new(None, Some(0), retry_after_seconds, true)?;
                    return Err(HightouchProviderError::RateLimited {
                        retry_after_seconds,
                        attempts: attempt,
                    });
                }
                Err(error) => return Err(map_transport_error(error)),
            };
            response.validate_size_and_digest()?;
            let status = response.status();
            if status == 429 {
                retry_after = response_retry_after(&response);
                if attempt < self.definition.max_retry_attempts {
                    *backoff = Some(HightouchBackoffReceipt::new(
                        attempt,
                        retry_after,
                        backoff_seconds(attempt, retry_after),
                    ));
                    continue;
                }
                *rate_limit = HightouchRateLimitReceipt::new(None, Some(0), retry_after, true)?;
                return Err(HightouchProviderError::RateLimited {
                    retry_after_seconds: retry_after,
                    attempts: attempt,
                });
            }
            if (200..300).contains(&status) {
                let value: Value = serde_json::from_slice(response.body()).map_err(|_| {
                    HightouchProviderError::MalformedResponse {
                        diagnostic_digest: Digest::from_text("malformed hightouch json"),
                    }
                })?;
                *rate_limit = rate_limit_from_value(&value)?;
                let receipt = HightouchReadReceipt {
                    operation,
                    method: HightouchHttpMethod::Get,
                    request_digest: request.path_digest().clone(),
                    response_digest: response.response_digest(),
                    status_code: Some(status),
                    response_bytes: response.response_bytes(),
                    page,
                    cursor_digest: request.cursor_digest().cloned(),
                    rate_limit_digest: rate_limit.digest(),
                    provenance: provenance.clone(),
                    connected: false,
                    native: false,
                };
                return Ok(ExecutedResponse { value, receipt });
            }
            if matches!(status, 401 | 403) {
                return Err(HightouchProviderError::Denied {
                    status_code: Some(status),
                });
            }
            return Err(HightouchProviderError::ProviderUnknown {
                status_code: Some(status),
            });
        }
        Err(HightouchProviderError::RateLimited {
            retry_after_seconds: retry_after,
            attempts: self.definition.max_retry_attempts,
        })
    }
}

#[derive(Debug)]
struct ExecutedResponse {
    value: Value,
    receipt: HightouchReadReceipt,
}

fn backoff_seconds(attempt: u8, retry_after: Option<u32>) -> u32 {
    let shift = attempt.saturating_sub(1).min(5);
    let exponential = 1u32 << shift;
    retry_after.unwrap_or(exponential).min(MAX_BACKOFF_SECONDS)
}

fn response_retry_after(response: &HightouchResponse) -> Option<u32> {
    serde_json::from_slice::<Value>(response.body())
        .ok()
        .and_then(|value| value.get("retryAfterSeconds").and_then(Value::as_u64))
        .and_then(|value| u32::try_from(value).ok())
}

fn map_transport_error(error: HightouchTransportError) -> HightouchProviderError {
    match error {
        HightouchTransportError::BlockedEnv => {
            HightouchProviderError::Transport(HightouchTransportError::BlockedEnv)
        }
        HightouchTransportError::AccessLost => HightouchProviderError::Denied {
            status_code: Some(403),
        },
        HightouchTransportError::MalformedResponse => HightouchProviderError::MalformedResponse {
            diagnostic_digest: Digest::from_text("malformed hightouch transport response"),
        },
        HightouchTransportError::Timeout | HightouchTransportError::ProviderUnknown => {
            HightouchProviderError::ProviderUnknown { status_code: None }
        }
        HightouchTransportError::HttpStatus { status_code } => {
            if matches!(status_code, 401 | 403) {
                HightouchProviderError::Denied {
                    status_code: Some(status_code),
                }
            } else {
                HightouchProviderError::ProviderUnknown {
                    status_code: Some(status_code),
                }
            }
        }
        HightouchTransportError::RateLimited {
            retry_after_seconds,
        } => HightouchProviderError::RateLimited {
            retry_after_seconds,
            attempts: 1,
        },
    }
}

#[derive(Clone, Debug)]
struct RecordingState {
    responses: VecDeque<HightouchResponse>,
    requests: Vec<HightouchRequest>,
}

#[derive(Clone)]
pub struct RecordingHightouchTransport {
    inner: Rc<RefCell<RecordingState>>,
}

impl fmt::Debug for RecordingHightouchTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.borrow();
        formatter
            .debug_struct("RecordingHightouchTransport")
            .field("queued_responses", &inner.responses.len())
            .field("request_count", &inner.requests.len())
            .finish()
    }
}

impl RecordingHightouchTransport {
    #[must_use]
    pub fn new(responses: impl IntoIterator<Item = HightouchResponse>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(RecordingState {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            })),
        }
    }

    #[must_use]
    pub fn requests(&self) -> Vec<HightouchRequest> {
        self.inner.borrow().requests.clone()
    }

    pub fn push_response(&self, response: HightouchResponse) {
        self.inner.borrow_mut().responses.push_back(response);
    }

    pub fn clear_requests(&self) {
        self.inner.borrow_mut().requests.clear();
    }
}

impl HightouchTransport for RecordingHightouchTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &HightouchRequest,
    ) -> std::result::Result<HightouchResponse, HightouchTransportError> {
        if !request.is_allowlisted() {
            return Err(HightouchTransportError::ProviderUnknown);
        }
        let mut inner = self.inner.borrow_mut();
        inner.requests.push(request.clone());
        inner
            .responses
            .pop_front()
            .ok_or(HightouchTransportError::Timeout)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureHightouchTransport {
    response: HightouchResponse,
}

impl FixtureHightouchTransport {
    #[must_use]
    pub fn new(response: HightouchResponse) -> Self {
        Self { response }
    }
}

impl HightouchTransport for FixtureHightouchTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &HightouchRequest,
    ) -> std::result::Result<HightouchResponse, HightouchTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeHightouchTransport {
    response: HightouchResponse,
}

impl FakeHightouchTransport {
    #[must_use]
    pub fn new(response: HightouchResponse) -> Self {
        Self { response }
    }
}

impl HightouchTransport for FakeHightouchTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn execute(
        &mut self,
        _request: &HightouchRequest,
    ) -> std::result::Result<HightouchResponse, HightouchTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackHightouchTransport {
    response: HightouchResponse,
}

impl LoopbackHightouchTransport {
    #[must_use]
    pub fn new(response: HightouchResponse) -> Self {
        Self { response }
    }
}

impl HightouchTransport for LoopbackHightouchTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &HightouchRequest,
    ) -> std::result::Result<HightouchResponse, HightouchTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvHightouchTransport;

impl HightouchTransport for BlockedEnvHightouchTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &HightouchRequest,
    ) -> std::result::Result<HightouchResponse, HightouchTransportError> {
        Err(HightouchTransportError::BlockedEnv)
    }
}

fn object_for<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a Map<String, Value>, HightouchProviderError> {
    match value.get(key) {
        Some(nested) => {
            nested
                .as_object()
                .ok_or_else(|| HightouchProviderError::MalformedResponse {
                    diagnostic_digest: Digest::from_text("metadata resource is not an object"),
                })
        }
        None => value
            .as_object()
            .ok_or_else(|| HightouchProviderError::MalformedResponse {
                diagnostic_digest: Digest::from_text("expected metadata object"),
            }),
    }
}

fn required_id(
    value: &Map<String, Value>,
    expected: &crate::Identifier,
) -> Result<(), HightouchProviderError> {
    let id = value.get("id").and_then(Value::as_str).ok_or_else(|| {
        HightouchProviderError::MalformedResponse {
            diagnostic_digest: Digest::from_text("metadata resource id is missing"),
        }
    })?;
    if id != expected.as_str() {
        return Err(HightouchProviderError::ScopeMismatch);
    }
    Ok(())
}

fn required_relation(
    value: &Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<(), HightouchProviderError> {
    let actual = value.get(key).and_then(Value::as_str).ok_or_else(|| {
        HightouchProviderError::MalformedResponse {
            diagnostic_digest: Digest::from_text("metadata relationship is missing"),
        }
    })?;
    if actual != expected {
        return Err(HightouchProviderError::ScopeMismatch);
    }
    Ok(())
}

fn text_digest(value: Option<&Value>) -> Option<Digest> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(Digest::from_text)
}

fn status(value: Option<&Value>) -> HightouchResourceStatus {
    match value
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("active" | "enabled" | "healthy" | "connected" | "succeeded") => {
            HightouchResourceStatus::Active
        }
        Some("inactive" | "disabled" | "paused" | "deleted") => HightouchResourceStatus::Inactive,
        _ => HightouchResourceStatus::Unknown,
    }
}

fn safe_metadata_digest(value: &Map<String, Value>, keys: &[&str]) -> Digest {
    let safe: Map<String, Value> = keys
        .iter()
        .filter_map(|key| {
            value
                .get(*key)
                .cloned()
                .map(|item| ((*key).to_owned(), item))
        })
        .collect();
    crate::canonical_digest(&safe)
}

fn parse_workspace(
    value: &Value,
    scope: &HightouchSyncScope,
) -> Result<HightouchWorkspaceProjection, HightouchProviderError> {
    let object = object_for(value, "workspace")?;
    required_id(object, scope.workspace_id())?;
    Ok(HightouchWorkspaceProjection::new(
        scope.workspace_id(),
        scope.workspace_revision(),
        status(object.get("status")),
        safe_metadata_digest(
            object,
            &["id", "status", "createdAt", "updatedAt", "region"],
        ),
    ))
}

fn parse_source(
    value: &Value,
    scope: &HightouchSyncScope,
) -> Result<HightouchSourceProjection, HightouchProviderError> {
    let object = object_for(value, "source")?;
    required_id(object, scope.source_id())?;
    Ok(HightouchSourceProjection::new(
        scope.source_id(),
        scope.source_revision(),
        text_digest(object.get("sourceType").or_else(|| object.get("type"))),
        status(object.get("status")),
        safe_metadata_digest(
            object,
            &[
                "id",
                "status",
                "sourceType",
                "type",
                "createdAt",
                "updatedAt",
            ],
        ),
    ))
}

fn parse_model(
    value: &Value,
    scope: &HightouchSyncScope,
) -> Result<HightouchModelProjection, HightouchProviderError> {
    let object = object_for(value, "model")?;
    required_id(object, scope.model_id())?;
    required_relation(object, "sourceId", scope.source_id().as_str())?;
    Ok(HightouchModelProjection::new(
        scope.model_id(),
        scope.source_id(),
        scope.model_revision(),
        text_digest(object.get("modelType").or_else(|| object.get("type"))),
        status(object.get("status")),
        safe_metadata_digest(
            object,
            &[
                "id",
                "sourceId",
                "status",
                "modelType",
                "type",
                "createdAt",
                "updatedAt",
            ],
        ),
    ))
}

fn parse_destination(
    value: &Value,
    scope: &HightouchSyncScope,
) -> Result<HightouchDestinationProjection, HightouchProviderError> {
    let object = object_for(value, "destination")?;
    required_id(object, scope.destination_id())?;
    Ok(HightouchDestinationProjection::new(
        scope.destination_id(),
        scope.destination_revision(),
        text_digest(object.get("destinationType").or_else(|| object.get("type"))),
        status(object.get("status")),
        safe_metadata_digest(
            object,
            &[
                "id",
                "status",
                "destinationType",
                "type",
                "createdAt",
                "updatedAt",
            ],
        ),
    ))
}

fn parse_sync(
    value: &Value,
    scope: &HightouchSyncScope,
) -> Result<HightouchSyncProjection, HightouchProviderError> {
    let object = object_for(value, "sync")?;
    required_id(object, scope.sync_id())?;
    required_relation(object, "modelId", scope.model_id().as_str())?;
    required_relation(object, "destinationId", scope.destination_id().as_str())?;
    Ok(HightouchSyncProjection::new(
        scope.sync_id(),
        scope.model_id(),
        scope.destination_id(),
        scope.sync_revision(),
        status(object.get("status")),
        object.get("enabled").and_then(Value::as_bool),
        safe_metadata_digest(
            object,
            &[
                "id",
                "modelId",
                "destinationId",
                "status",
                "enabled",
                "createdAt",
                "updatedAt",
            ],
        ),
    ))
}

fn parse_runs(
    value: Value,
    scope: &HightouchSyncScope,
) -> Result<(Vec<HightouchRunProjection>, Option<String>), HightouchProviderError> {
    let root = value
        .as_object()
        .ok_or_else(|| HightouchProviderError::MalformedResponse {
            diagnostic_digest: Digest::from_text("expected run list object"),
        })?;
    let values = root
        .get("runs")
        .or_else(|| root.get("data"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if values.len() > MAX_RUNS_PER_PAGE {
        return Err(HightouchProviderError::PaginationBound);
    }
    let mut runs = Vec::with_capacity(values.len());
    for value in values {
        let object =
            value
                .as_object()
                .ok_or_else(|| HightouchProviderError::MalformedResponse {
                    diagnostic_digest: Digest::from_text("run entry is not an object"),
                })?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ModelError::InvalidRun)?;
        let id = crate::Identifier::new(id).map_err(HightouchProviderError::Model)?;
        if !scope.run_is_allowed(&id) {
            continue;
        }
        let status = parse_run_status(object.get("status"));
        let started_at_digest =
            text_digest(object.get("startedAt").or_else(|| object.get("started_at")));
        let finished_at_digest = text_digest(
            object
                .get("finishedAt")
                .or_else(|| object.get("finished_at")),
        );
        let metadata_digest = safe_metadata_digest(
            object,
            &[
                "id",
                "status",
                "startedAt",
                "started_at",
                "finishedAt",
                "finished_at",
                "rowsQueried",
                "recordsQueried",
                "rowsAdded",
                "rowsChanged",
                "rowsRemoved",
                "rowsRejected",
                "errorCount",
            ],
        );
        runs.push(HightouchRunProjection::new(
            &id,
            scope.run_revision(),
            status,
            started_at_digest,
            finished_at_digest,
            numeric(object, &["rowsQueried", "recordsQueried"]),
            numeric(object, &["rowsAdded"]),
            numeric(object, &["rowsChanged"]),
            numeric(object, &["rowsRemoved"]),
            numeric(object, &["rowsRejected", "errorCount"]),
            metadata_digest,
        ));
    }
    let next_cursor = root
        .get("nextCursor")
        .or_else(|| root.get("next_cursor"))
        .or_else(|| {
            root.get("pagination")
                .and_then(|value| value.get("nextCursor"))
        })
        .and_then(Value::as_str)
        .map(str::to_owned);
    if next_cursor
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > MAX_CURSOR_BYTES)
    {
        return Err(HightouchProviderError::PaginationBound);
    }
    Ok((runs, next_cursor))
}

fn numeric(value: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
    })
}

fn parse_run_status(value: Option<&Value>) -> HightouchRunStatus {
    match value
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("queued" | "pending" | "scheduled") => HightouchRunStatus::Queued,
        Some("running" | "querying" | "processing" | "preparing" | "in_progress") => {
            HightouchRunStatus::Running
        }
        Some("succeeded" | "completed" | "success" | "healthy") => HightouchRunStatus::Succeeded,
        Some("partial" | "completed_with_errors" | "incomplete") => HightouchRunStatus::Partial,
        Some("failed" | "aborted" | "cancelled" | "canceled") => HightouchRunStatus::Failed,
        _ => HightouchRunStatus::Unknown,
    }
}

fn rate_limit_from_value(
    value: &Value,
) -> Result<HightouchRateLimitReceipt, HightouchProviderError> {
    let root = value.as_object();
    HightouchRateLimitReceipt::new(
        root.and_then(|object| object.get("limitPerMinute").and_then(Value::as_u64))
            .and_then(|value| u32::try_from(value).ok()),
        root.and_then(|object| object.get("remaining").and_then(Value::as_u64))
            .and_then(|value| u32::try_from(value).ok()),
        root.and_then(|object| object.get("retryAfterSeconds").and_then(Value::as_u64))
            .and_then(|value| u32::try_from(value).ok()),
        false,
    )
    .map_err(HightouchProviderError::Model)
}

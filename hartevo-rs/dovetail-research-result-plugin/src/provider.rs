use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::form_urlencoded;

use crate::error::{DovetailProviderError, DovetailTransportError};
use crate::model::{
    DOVETAIL_API_BASE_URL, DataContentKind, DataId, DataPointMetadata, Digest, DovetailReadBounds,
    DovetailReadOperation, DovetailResearchObservation, DovetailResearchReadRequest,
    DovetailResearchScope, FolderId, FolderMetadata, HighlightId, HighlightSummary, InsightId,
    InsightMetadata, MAX_BACKOFF_MS, MAX_CURSOR_BYTES, MAX_PAGE_SIZE, MAX_QUERY_VALUE_BYTES,
    MAX_RESPONSE_BYTES, MAX_RETRIES, ObservationCompleteness, ObservationCounts, ProjectMetadata,
    ResearchEvidenceState, RevisionDigests, TagId, ThemeSummary, TransportProvenance,
    bounded_timestamp, cap_u32, digest_optional_text, digest_values, validate_text,
};
use crate::service::DovetailRegistration;

const ALLOWED_QUERY_KEYS: [&str; 6] = [
    "page[limit]",
    "page[start_cursor]",
    "filter[project_id]",
    "filter[folder_id]",
    "filter[created_at][gte]",
    "filter[created_at][lte]",
];

/// The only HTTP method exposed by the Layer-1 provider plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DovetailHttpMethod {
    Get,
}

/// A redaction-safe GET plan. It contains a SecretReference digest, never a
/// Dovetail token or a host-owned credential handle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailGetRequest {
    pub operation: DovetailReadOperation,
    pub method: DovetailHttpMethod,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub attempt: u8,
    pub backoff_ms: u64,
    pub max_response_bytes: usize,
}

impl DovetailGetRequest {
    pub(crate) fn new(
        operation: DovetailReadOperation,
        scope: &DovetailResearchScope,
        secret_reference_digest: &Digest,
        bounds: &DovetailReadBounds,
        cursor: Option<&str>,
        attempt: u8,
        backoff_ms: u64,
    ) -> crate::Result<Self> {
        let mut query = BTreeMap::new();
        query.insert(String::from("page[limit]"), bounds.page_size.to_string());
        if let Some(cursor) = cursor {
            validate_text(cursor, "pageStartCursor", MAX_CURSOR_BYTES)?;
            query.insert(String::from("page[start_cursor]"), cursor.to_owned());
        }

        match operation {
            DovetailReadOperation::ListProjectMetadata => {
                if let Some(folder) = &scope.dovetail_folder {
                    query.insert(
                        String::from("filter[folder_id]"),
                        folder.id.as_str().to_owned(),
                    );
                }
            }
            DovetailReadOperation::ListFolderMetadata => {}
            DovetailReadOperation::ListDataPointMetadata
            | DovetailReadOperation::ListHighlightSummaries
            | DovetailReadOperation::ListThemeTagSummaries
            | DovetailReadOperation::ListInsightMetadata
            | DovetailReadOperation::ListDocumentMetadata => {
                query.insert(
                    String::from("filter[project_id]"),
                    scope.dovetail_project.id.as_str().to_owned(),
                );
                if let Some(folder) = &scope.dovetail_folder {
                    query.insert(
                        String::from("filter[folder_id]"),
                        folder.id.as_str().to_owned(),
                    );
                }
            }
        }
        if let Some(time_window) = &bounds.time_window {
            query.insert(
                String::from("filter[created_at][gte]"),
                time_window.start.clone(),
            );
            query.insert(
                String::from("filter[created_at][lte]"),
                time_window.end.clone(),
            );
        }
        let request = Self {
            operation,
            method: DovetailHttpMethod::Get,
            path: operation.path().to_owned(),
            query,
            scope_digest: scope.scope_digest.clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            attempt,
            backoff_ms,
            max_response_bytes: bounds.max_response_bytes,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn url(&self) -> String {
        let mut url = format!("{}{path}", DOVETAIL_API_BASE_URL, path = self.path);
        if !self.query.is_empty() {
            let mut serializer = form_urlencoded::Serializer::new(String::new());
            for (key, value) in &self.query {
                serializer.append_pair(key, value);
            }
            url.push('?');
            url.push_str(&serializer.finish());
        }
        url
    }

    pub fn query_value(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(String::as_str)
    }

    pub fn validate(&self) -> crate::Result<()> {
        if self.method != DovetailHttpMethod::Get
            || self.path != self.operation.path()
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.attempt > MAX_RETRIES
            || self.backoff_ms > MAX_BACKOFF_MS
        {
            return Err(crate::DovetailResearchResultError::InvalidInput {
                field: "dovetailGetRequest",
                reason: "only bounded allowlisted GET requests are permitted",
            });
        }
        self.scope_digest.validate("scopeDigest")?;
        self.secret_reference_digest
            .validate("secretReferenceDigest")?;
        for (key, value) in &self.query {
            if !ALLOWED_QUERY_KEYS.contains(&key.as_str()) {
                return Err(crate::DovetailResearchResultError::InvalidInput {
                    field: "queryKey",
                    reason: "query key is not allowlisted",
                });
            }
            validate_text(value, "queryValue", MAX_QUERY_VALUE_BYTES)?;
        }
        let page_limit = self
            .query
            .get("page[limit]")
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(crate::DovetailResearchResultError::InvalidInput {
                field: "pageLimit",
                reason: "page limit must be numeric and bounded",
            })?;
        if !(1..=MAX_PAGE_SIZE).contains(&page_limit) {
            return Err(crate::DovetailResearchResultError::InvalidInput {
                field: "pageLimit",
                reason: "page limit must be between one and the documented maximum",
            });
        }
        Ok(())
    }
}

/// An ephemeral response handed to the parser. Debug and serialization never
/// expose its body; the body is dropped after metadata-only parsing.
#[derive(Clone)]
pub struct DovetailTransportResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

impl DovetailTransportResponse {
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: body.into(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn json(status: u16, value: Value) -> Self {
        Self::new(status, value.to_string())
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl fmt::Debug for DovetailTransportResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DovetailTransportResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Transport seam for tests, recordings, and a later host-owned HTTP layer.
/// Implementations must only accept a validated GET plan.
pub trait DovetailTransport: Clone + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get(
        &mut self,
        request: &DovetailGetRequest,
    ) -> std::result::Result<DovetailTransportResponse, DovetailTransportError>;
}

#[derive(Clone, Debug)]
struct DovetailFixtureState {
    provenance: TransportProvenance,
    responses: BTreeMap<DovetailReadOperation, VecDeque<DovetailTransportResponse>>,
    requests: Vec<DovetailGetRequest>,
    failure: Option<DovetailTransportError>,
}

impl DovetailFixtureState {
    fn for_scope(scope: &DovetailResearchScope, provenance: TransportProvenance) -> Self {
        let mut responses = BTreeMap::new();
        for operation in DovetailReadOperation::ALL {
            responses.insert(
                operation,
                VecDeque::from([fixture_response(scope, operation)]),
            );
        }
        Self {
            provenance,
            responses,
            requests: Vec::new(),
            failure: None,
        }
    }

    fn get(
        &mut self,
        request: &DovetailGetRequest,
    ) -> std::result::Result<DovetailTransportResponse, DovetailTransportError> {
        request
            .validate()
            .map_err(|_| DovetailTransportError::PathNotAllowed)?;
        self.requests.push(request.clone());
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        self.responses
            .get_mut(&request.operation)
            .and_then(VecDeque::pop_front)
            .ok_or(DovetailTransportError::Unavailable)
    }
}

/// Deterministic fixture transport whose body is parsed and discarded.
#[derive(Clone, Debug)]
pub struct DovetailFixtureTransport {
    state: DovetailFixtureState,
}

impl DovetailFixtureTransport {
    pub fn from_scope(scope: &DovetailResearchScope) -> Self {
        Self {
            state: DovetailFixtureState::for_scope(scope, TransportProvenance::Fixture),
        }
    }

    pub fn with_response(
        mut self,
        operation: DovetailReadOperation,
        response: DovetailTransportResponse,
    ) -> Self {
        self.state
            .responses
            .insert(operation, VecDeque::from([response]));
        self
    }

    pub fn fail_with(mut self, error: DovetailTransportError) -> Self {
        self.state.failure = Some(error);
        self
    }

    pub fn requests(&self) -> &[DovetailGetRequest] {
        &self.state.requests
    }
}

impl DovetailTransport for DovetailFixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        self.state.provenance
    }

    fn get(
        &mut self,
        request: &DovetailGetRequest,
    ) -> std::result::Result<DovetailTransportResponse, DovetailTransportError> {
        self.state.get(request)
    }
}

/// Recorded response transport. It is deliberately not a native provider.
#[derive(Clone, Debug)]
pub struct DovetailRecordingTransport {
    state: DovetailFixtureState,
}

impl DovetailRecordingTransport {
    pub fn from_scope(scope: &DovetailResearchScope) -> Self {
        Self {
            state: DovetailFixtureState::for_scope(scope, TransportProvenance::Recording),
        }
    }

    pub fn requests(&self) -> &[DovetailGetRequest] {
        &self.state.requests
    }
}

impl DovetailTransport for DovetailRecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.state.provenance
    }

    fn get(
        &mut self,
        request: &DovetailGetRequest,
    ) -> std::result::Result<DovetailTransportResponse, DovetailTransportError> {
        self.state.get(request)
    }
}

/// Loopback response transport. Loopback is a test seam, not Connected.
#[derive(Clone, Debug)]
pub struct DovetailLoopbackTransport {
    state: DovetailFixtureState,
}

impl DovetailLoopbackTransport {
    pub fn from_scope(scope: &DovetailResearchScope) -> Self {
        Self {
            state: DovetailFixtureState::for_scope(scope, TransportProvenance::Loopback),
        }
    }

    pub fn requests(&self) -> &[DovetailGetRequest] {
        &self.state.requests
    }
}

impl DovetailTransport for DovetailLoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.state.provenance
    }

    fn get(
        &mut self,
        request: &DovetailGetRequest,
    ) -> std::result::Result<DovetailTransportResponse, DovetailTransportError> {
        self.state.get(request)
    }
}

/// Honest environment gap. It has no credential or network path and can only
/// produce a typed blocked-environment transport error.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvDovetailTransport;

impl DovetailTransport for BlockedEnvDovetailTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get(
        &mut self,
        _request: &DovetailGetRequest,
    ) -> std::result::Result<DovetailTransportResponse, DovetailTransportError> {
        Err(DovetailTransportError::BlockedEnv)
    }
}

pub type FixtureTransport = DovetailFixtureTransport;
pub type RecordingTransport = DovetailRecordingTransport;
pub type LoopbackTransport = DovetailLoopbackTransport;

/// Typed Dovetail provider over an explicitly injected, non-native transport.
#[derive(Clone, Debug)]
pub struct DovetailProvider<T: DovetailTransport = DovetailFixtureTransport> {
    registration: DovetailRegistration,
    transport: T,
}

impl<T> DovetailProvider<T>
where
    T: DovetailTransport,
{
    pub fn new(registration: DovetailRegistration, transport: T) -> crate::Result<Self> {
        registration.validate()?;
        if transport.provenance().is_connected() || transport.provenance().is_native() {
            return Err(crate::DovetailResearchResultError::InvalidContract);
        }
        Ok(Self {
            registration,
            transport,
        })
    }

    pub fn registration(&self) -> &DovetailRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut DovetailRegistration {
        &mut self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
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

    pub fn read(
        &mut self,
        request: &DovetailResearchReadRequest,
    ) -> crate::Result<DovetailResearchObservation> {
        request.validate_against(&self.registration.scope)?;
        self.registration.ensure_active()?;
        self.registration.permission_snapshot.validate()?;
        if self.registration.scope.permission_digest != self.registration.permission_snapshot.digest
        {
            return Err(crate::DovetailResearchResultError::PermissionMismatch);
        }
        if self.registration.secret_reference.is_revoked() {
            return Err(crate::DovetailResearchResultError::RegistrationRevoked);
        }

        let mut accumulator =
            ObservationAccumulator::new(&self.registration.scope, self.provenance());
        for operation in DovetailReadOperation::ALL {
            if !self
                .registration
                .permission_snapshot
                .allowed_operations
                .contains(&operation.permission())
            {
                accumulator.mark_failure(ReadFailure::ProviderUnknown);
                continue;
            }
            self.read_operation(operation, request, &mut accumulator)?;
        }
        Ok(accumulator.finish())
    }

    fn read_operation(
        &mut self,
        operation: DovetailReadOperation,
        request: &DovetailResearchReadRequest,
        accumulator: &mut ObservationAccumulator,
    ) -> crate::Result<()> {
        let mut cursor: Option<String> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut item_count = 0_usize;
        let mut pages_read = 0_u8;
        for page_index in 0..request.bounds.max_pages_per_operation {
            let retry_after = accumulator.retry_after_seconds;
            let backoff_ms = if retry_after.is_some() {
                request.bounds.backoff_ms(0, retry_after)
            } else {
                0
            };
            let get_request = crate::provider::DovetailGetRequest::new(
                operation,
                &self.registration.scope,
                self.registration.secret_reference.reference_digest(),
                &request.bounds,
                cursor.as_deref(),
                0,
                backoff_ms,
            )?;
            let response = match self.get_with_retry(get_request, &request.bounds, accumulator) {
                Ok(response) => response,
                Err(failure) => {
                    accumulator.mark_failure(failure);
                    break;
                }
            };
            if response.body_len() > request.bounds.max_response_bytes {
                accumulator.mark_failure(ReadFailure::ProviderUnknown);
                break;
            }
            let response_digest = Digest::from_text(response.body.as_bytes());
            accumulator.response_digests.insert(
                format!("{}:{page_index}", operation.path()),
                response_digest,
            );
            accumulator.page_count = accumulator.page_count.saturating_add(1);
            pages_read = pages_read.saturating_add(1);
            let Ok(page) = parse_page(&response.body, request.bounds.max_items_per_operation)
            else {
                accumulator.mark_failure(ReadFailure::ProviderUnknown);
                break;
            };
            item_count = item_count.saturating_add(page.items.len());
            if item_count > request.bounds.max_items_per_operation {
                accumulator.mark_failure(ReadFailure::Partial);
                break;
            }
            accumulator.processing_seen |= page
                .items
                .iter()
                .any(|item| value_string(item, &["status", "state"]) == Some("processing"));
            for item in &page.items {
                if let Err(error) = accumulator.accept(operation, item) {
                    match error {
                        DovetailProviderError::OutOfScope => {
                            accumulator.mark_failure(ReadFailure::ProviderUnknown);
                        }
                        DovetailProviderError::MalformedResponse => {
                            accumulator.mark_failure(ReadFailure::ProviderUnknown);
                        }
                        _ => return Err(crate::DovetailResearchResultError::Provider(error)),
                    }
                }
            }
            if page.has_more && page.next_cursor.is_none() {
                accumulator.mark_failure(ReadFailure::Partial);
                break;
            }
            if !page.has_more || page.next_cursor.is_none() {
                break;
            }
            let next_cursor = page.next_cursor.expect("checked next cursor");
            if !seen_cursors.insert(next_cursor.clone()) {
                accumulator.mark_failure(ReadFailure::ProviderUnknown);
                break;
            }
            cursor = Some(next_cursor);
        }
        if cursor.is_some() && pages_read == request.bounds.max_pages_per_operation {
            accumulator.mark_failure(ReadFailure::Partial);
        }
        Ok(())
    }

    fn get_with_retry(
        &mut self,
        mut request: DovetailGetRequest,
        bounds: &DovetailReadBounds,
        accumulator: &mut ObservationAccumulator,
    ) -> std::result::Result<DovetailTransportResponse, ReadFailure> {
        for attempt in 0..=bounds.max_retries {
            request.attempt = attempt;
            request.backoff_ms = if attempt == 0 {
                0
            } else {
                bounds.backoff_ms(attempt, accumulator.retry_after_seconds)
            };
            accumulator.request_count = accumulator.request_count.saturating_add(1);
            let response = self.transport.get(&request).map_err(ReadFailure::from)?;
            match response.status() {
                200 => {
                    accumulator.retry_after_seconds = None;
                    return Ok(response);
                }
                401 | 403 => return Err(ReadFailure::AccessLost),
                404 | 410 => return Err(ReadFailure::RetentionGap),
                429 | 500 | 502 | 503 | 504 if attempt < bounds.max_retries => {
                    accumulator.retry_count = accumulator.retry_count.saturating_add(1);
                    accumulator.retry_after_seconds = response
                        .header("retry-after")
                        .and_then(|value| value.parse::<u64>().ok());
                }
                429 | 500 | 502 | 503 | 504 => return Err(ReadFailure::ProviderUnknown),
                _ => return Err(ReadFailure::ProviderUnknown),
            }
        }
        Err(ReadFailure::ProviderUnknown)
    }
}

impl DovetailProvider<DovetailFixtureTransport> {
    pub fn fixture(scope: DovetailResearchScope) -> crate::Result<Self> {
        let transport = DovetailFixtureTransport::from_scope(&scope);
        let registration = DovetailRegistration::layer1(scope)?;
        Self::new(registration, transport)
    }
}

impl DovetailProvider<DovetailRecordingTransport> {
    pub fn recording(scope: DovetailResearchScope) -> crate::Result<Self> {
        let transport = DovetailRecordingTransport::from_scope(&scope);
        let registration = DovetailRegistration::layer1(scope)?;
        Self::new(registration, transport)
    }
}

impl DovetailProvider<DovetailLoopbackTransport> {
    pub fn loopback(scope: DovetailResearchScope) -> crate::Result<Self> {
        let transport = DovetailLoopbackTransport::from_scope(&scope);
        let registration = DovetailRegistration::layer1(scope)?;
        Self::new(registration, transport)
    }
}

impl DovetailProvider<BlockedEnvDovetailTransport> {
    pub fn blocked_env(scope: DovetailResearchScope) -> crate::Result<Self> {
        let registration = DovetailRegistration::layer1(scope)?;
        Self::new(registration, BlockedEnvDovetailTransport)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadFailure {
    BlockedEnv,
    Partial,
    AccessLost,
    RetentionGap,
    ProviderUnknown,
}

impl From<DovetailTransportError> for ReadFailure {
    fn from(error: DovetailTransportError) -> Self {
        match error {
            DovetailTransportError::BlockedEnv => Self::BlockedEnv,
            DovetailTransportError::Timeout
            | DovetailTransportError::MethodNotAllowed
            | DovetailTransportError::PathNotAllowed
            | DovetailTransportError::ResponseTooLarge
            | DovetailTransportError::Unavailable => Self::ProviderUnknown,
        }
    }
}

struct ParsedPage {
    items: Vec<Value>,
    next_cursor: Option<String>,
    has_more: bool,
}

fn parse_page(
    body: &str,
    max_items: usize,
) -> std::result::Result<ParsedPage, DovetailProviderError> {
    let document: Value =
        serde_json::from_str(body).map_err(|_| DovetailProviderError::MalformedResponse)?;
    let object = document
        .as_object()
        .ok_or(DovetailProviderError::MalformedResponse)?;
    let items = object
        .get("data")
        .and_then(Value::as_array)
        .ok_or(DovetailProviderError::MalformedResponse)?;
    if items.len() > max_items {
        return Err(DovetailProviderError::ResponseTooLarge);
    }
    let page = object.get("page").and_then(Value::as_object);
    let has_more = page
        .and_then(|page| page.get("has_more"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let next_cursor = page
        .and_then(|page| page.get("next_cursor"))
        .and_then(Value::as_str)
        .filter(|cursor| !cursor.is_empty())
        .map(str::to_owned);
    if let Some(cursor) = &next_cursor {
        validate_text(cursor, "pageNextCursor", MAX_CURSOR_BYTES)
            .map_err(|_| DovetailProviderError::MalformedResponse)?;
    }
    Ok(ParsedPage {
        items: items.clone(),
        next_cursor,
        has_more,
    })
}

fn value_string<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn nested_string<'a>(value: &'a Value, object_key: &str, keys: &[&str]) -> Option<&'a str> {
    value
        .get(object_key)
        .and_then(Value::as_object)
        .and_then(|nested| {
            keys.iter()
                .find_map(|key| nested.get(*key).and_then(Value::as_str))
        })
}

fn id_string(value: &Value) -> Option<&str> {
    value_string(value, &["id", "uuid", "key"])
}

fn project_id_string(value: &Value) -> Option<&str> {
    value_string(value, &["project_id", "projectId"])
        .or_else(|| nested_string(value, "project", &["id", "uuid"]))
}

fn folder_id_string(value: &Value) -> Option<&str> {
    value_string(value, &["folder_id", "folderId"])
        .or_else(|| nested_string(value, "folder", &["id", "uuid"]))
}

fn data_id_string(value: &Value) -> Option<&str> {
    value_string(
        value,
        &["data_id", "dataId", "data_point_id", "dataPointId"],
    )
    .or_else(|| nested_string(value, "data", &["id", "uuid"]))
    .or_else(|| nested_string(value, "data_point", &["id", "uuid"]))
}

fn tag_ids(value: &Value) -> Vec<TagId> {
    let mut ids = value
        .get("tag_ids")
        .or_else(|| value.get("tagIds"))
        .or_else(|| value.get("tags"))
        .and_then(Value::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(|tag| tag.as_str().or_else(|| id_string(tag)))
                .filter_map(|id| TagId::new(id.to_owned()).ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ids.sort();
    ids.dedup();
    ids
}

fn parse_project(value: &Value, scope: &DovetailResearchScope) -> Option<ProjectMetadata> {
    let id = id_string(value).and_then(|id| crate::model::DovetailProjectId::new(id).ok())?;
    if id != scope.dovetail_project.id {
        return None;
    }
    let folder_id = folder_id_string(value).and_then(|id| FolderId::new(id).ok());
    if scope
        .dovetail_folder
        .as_ref()
        .is_some_and(|folder| folder_id.as_ref() != Some(&folder.id))
    {
        return None;
    }
    let title_digest = digest_optional_text(value_string(value, &["title", "name"]));
    let created_at = bounded_timestamp(value_string(value, &["created_at", "createdAt"]));
    let updated_at = bounded_timestamp(value_string(value, &["updated_at", "updatedAt"]));
    let deleted = value
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let revision_digest = Digest::from_serialized(&(
        &id,
        &folder_id,
        &title_digest,
        &created_at,
        &updated_at,
        deleted,
    ));
    Some(ProjectMetadata {
        id,
        folder_id,
        title_digest,
        created_at,
        updated_at,
        deleted,
        revision_digest,
    })
}

fn parse_folder(value: &Value, scope: &DovetailResearchScope) -> Option<FolderMetadata> {
    let Some(expected) = &scope.dovetail_folder else {
        return None;
    };
    let id = id_string(value).and_then(|id| FolderId::new(id).ok())?;
    if id != expected.id {
        return None;
    }
    let parent_folder_id = value_string(value, &["parent_folder_id", "parentFolderId"])
        .and_then(|id| FolderId::new(id).ok());
    let title_digest = digest_optional_text(value_string(value, &["title", "name"]));
    let created_at = bounded_timestamp(value_string(value, &["created_at", "createdAt"]));
    let updated_at = bounded_timestamp(value_string(value, &["updated_at", "updatedAt"]));
    let deleted = value
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let revision_digest = Digest::from_serialized(&(
        &id,
        &parent_folder_id,
        &title_digest,
        &created_at,
        &updated_at,
        deleted,
    ));
    Some(FolderMetadata {
        id,
        parent_folder_id,
        title_digest,
        created_at,
        updated_at,
        deleted,
        revision_digest,
    })
}

fn parse_data(
    value: &Value,
    scope: &DovetailResearchScope,
) -> std::result::Result<Option<DataPointMetadata>, DovetailProviderError> {
    let Some(id) = id_string(value).and_then(|id| DataId::new(id).ok()) else {
        return Ok(None);
    };
    if !scope.dovetail_data.contains(&id) {
        return Ok(None);
    }
    let Some(project_id) =
        project_id_string(value).and_then(|id| crate::model::DovetailProjectId::new(id).ok())
    else {
        return Err(DovetailProviderError::MalformedResponse);
    };
    if project_id != scope.dovetail_project.id {
        return Err(DovetailProviderError::OutOfScope);
    }
    let folder_id = folder_id_string(value).and_then(|id| FolderId::new(id).ok());
    if scope
        .dovetail_folder
        .as_ref()
        .is_some_and(|folder| folder_id.as_ref() != Some(&folder.id))
    {
        return Ok(None);
    }
    let title_digest = digest_optional_text(value_string(value, &["title", "name"]));
    let created_at = bounded_timestamp(value_string(value, &["created_at", "createdAt"]));
    let updated_at = bounded_timestamp(value_string(value, &["updated_at", "updatedAt"]));
    let deleted = value
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let content_kind = content_kind(value);
    let revision_digest = Digest::from_serialized(&(
        &id,
        &project_id,
        &folder_id,
        &title_digest,
        &created_at,
        &updated_at,
        deleted,
        content_kind,
    ));
    Ok(Some(DataPointMetadata {
        id,
        project_id,
        folder_id,
        title_digest,
        created_at,
        updated_at,
        deleted,
        content_kind,
        raw_content_redacted: true,
        transcript_redacted: true,
        media_links_redacted: true,
        participant_pii_redacted: true,
        notes_and_comments_redacted: true,
        revision_digest,
    }))
}

fn content_kind(value: &Value) -> DataContentKind {
    match value_string(
        value,
        &["content_type", "contentType", "type", "media_type"],
    ) {
        Some(value) if value.to_ascii_lowercase().contains("audio") => DataContentKind::Audio,
        Some(value) if value.to_ascii_lowercase().contains("video") => DataContentKind::Video,
        Some(value) if value.to_ascii_lowercase().contains("file") => DataContentKind::File,
        Some(value) if value.to_ascii_lowercase().contains("text") => DataContentKind::Text,
        Some(value) if value.to_ascii_lowercase().contains("mixed") => DataContentKind::Mixed,
        None => DataContentKind::Unknown,
        Some(_) => DataContentKind::Unknown,
    }
}

fn parse_highlight(
    value: &Value,
    scope: &DovetailResearchScope,
) -> std::result::Result<Option<HighlightSummary>, DovetailProviderError> {
    let Some(id) = id_string(value).and_then(|id| HighlightId::new(id).ok()) else {
        return Ok(None);
    };
    let Some(data_id) = data_id_string(value).and_then(|id| DataId::new(id).ok()) else {
        return Ok(None);
    };
    if !scope.dovetail_data.contains(&data_id) {
        return Ok(None);
    }
    let Some(project_id) =
        project_id_string(value).and_then(|id| crate::model::DovetailProjectId::new(id).ok())
    else {
        return Ok(None);
    };
    if project_id != scope.dovetail_project.id {
        return Err(DovetailProviderError::OutOfScope);
    }
    let tag_ids = tag_ids(value);
    let created_at = bounded_timestamp(value_string(value, &["created_at", "createdAt"]));
    let updated_at = bounded_timestamp(value_string(value, &["updated_at", "updatedAt"]));
    let position_digest = value
        .get("position")
        .or_else(|| value.get("time_range"))
        .map(Digest::from_serialized);
    let revision_digest = Digest::from_serialized(&(
        &id,
        &project_id,
        &data_id,
        &tag_ids,
        &created_at,
        &updated_at,
        &position_digest,
    ));
    Ok(Some(HighlightSummary {
        id,
        project_id,
        data_id,
        tag_ids,
        created_at,
        updated_at,
        position_digest,
        transcript_and_quote_redacted: true,
        participant_pii_redacted: true,
        revision_digest,
    }))
}

fn parse_theme(value: &Value, scope: &DovetailResearchScope) -> Option<ThemeSummary> {
    let id = id_string(value).and_then(|id| TagId::new(id).ok())?;
    let project_id =
        project_id_string(value).and_then(|id| crate::model::DovetailProjectId::new(id).ok())?;
    if project_id != scope.dovetail_project.id {
        return None;
    }
    let label_digest = digest_optional_text(value_string(value, &["name", "title", "label"]));
    let highlight_count = value
        .get("highlight_count")
        .or_else(|| value.get("highlightCount"))
        .and_then(Value::as_u64)
        .and_then(|count| u32::try_from(count).ok())
        .unwrap_or_default();
    let data_count = value
        .get("data_count")
        .or_else(|| value.get("dataCount"))
        .and_then(Value::as_u64)
        .and_then(|count| u32::try_from(count).ok());
    let created_at = bounded_timestamp(value_string(value, &["created_at", "createdAt"]));
    let updated_at = bounded_timestamp(value_string(value, &["updated_at", "updatedAt"]));
    let revision_digest = Digest::from_serialized(&(
        &id,
        &project_id,
        &label_digest,
        highlight_count,
        data_count,
        &created_at,
        &updated_at,
    ));
    Some(ThemeSummary {
        id,
        project_id,
        label_digest,
        highlight_count,
        data_count,
        created_at,
        updated_at,
        revision_digest,
    })
}

fn parse_insight(value: &Value, scope: &DovetailResearchScope) -> Option<InsightMetadata> {
    let id = id_string(value).and_then(|id| InsightId::new(id).ok())?;
    let project_id =
        project_id_string(value).and_then(|id| crate::model::DovetailProjectId::new(id).ok());
    if project_id
        .as_ref()
        .is_some_and(|project_id| project_id != &scope.dovetail_project.id)
    {
        return None;
    }
    let folder_id = folder_id_string(value).and_then(|id| FolderId::new(id).ok());
    if scope
        .dovetail_folder
        .as_ref()
        .is_some_and(|folder| folder_id.as_ref() != Some(&folder.id))
    {
        return None;
    }
    let title_digest = digest_optional_text(value_string(value, &["title", "name"]));
    let body_digest = value_string(value, &["content", "body", "text"]).map(Digest::from_text);
    let created_at = bounded_timestamp(value_string(value, &["created_at", "createdAt"]));
    let updated_at = bounded_timestamp(value_string(value, &["updated_at", "updatedAt"]));
    let revision_digest = Digest::from_serialized(&(
        &id,
        &project_id,
        &folder_id,
        &title_digest,
        &body_digest,
        &created_at,
        &updated_at,
    ));
    Some(InsightMetadata {
        id,
        project_id,
        folder_id,
        title_digest,
        body_digest,
        created_at,
        updated_at,
        body_redacted: true,
        comments_redacted: true,
        participant_pii_redacted: true,
        revision_digest,
    })
}

fn parse_document(
    value: &Value,
    scope: &DovetailResearchScope,
) -> Option<crate::model::DocumentMetadata> {
    let id = id_string(value).and_then(|id| crate::model::DocId::new(id).ok())?;
    let project_id =
        project_id_string(value).and_then(|id| crate::model::DovetailProjectId::new(id).ok());
    if project_id
        .as_ref()
        .is_some_and(|project_id| project_id != &scope.dovetail_project.id)
    {
        return None;
    }
    let folder_id = folder_id_string(value).and_then(|id| FolderId::new(id).ok());
    if scope
        .dovetail_folder
        .as_ref()
        .is_some_and(|folder| folder_id.as_ref() != Some(&folder.id))
    {
        return None;
    }
    let title_digest = digest_optional_text(value_string(value, &["title", "name"]));
    let body_digest = value_string(value, &["content", "body", "text"]).map(Digest::from_text);
    let created_at = bounded_timestamp(value_string(value, &["created_at", "createdAt"]));
    let updated_at = bounded_timestamp(value_string(value, &["updated_at", "updatedAt"]));
    let revision_digest = Digest::from_serialized(&(
        &id,
        &project_id,
        &folder_id,
        &title_digest,
        &body_digest,
        &created_at,
        &updated_at,
    ));
    Some(crate::model::DocumentMetadata {
        id,
        project_id,
        folder_id,
        title_digest,
        body_digest,
        created_at,
        updated_at,
        body_redacted: true,
        comments_redacted: true,
        participant_pii_redacted: true,
        revision_digest,
    })
}

struct ObservationAccumulator {
    scope: DovetailResearchScope,
    scope_digest: Digest,
    provider_id: String,
    provider_digest: Digest,
    provenance: TransportProvenance,
    state: Option<ResearchEvidenceState>,
    completeness: ObservationCompleteness,
    projects: Vec<ProjectMetadata>,
    folders: Vec<FolderMetadata>,
    data_points: Vec<DataPointMetadata>,
    highlights: Vec<HighlightSummary>,
    themes: Vec<ThemeSummary>,
    insights: Vec<InsightMetadata>,
    documents: Vec<crate::model::DocumentMetadata>,
    response_digests: BTreeMap<String, Digest>,
    page_count: u16,
    request_count: u16,
    retry_count: u16,
    retry_after_seconds: Option<u64>,
    processing_seen: bool,
}

impl ObservationAccumulator {
    fn new(scope: &DovetailResearchScope, provenance: TransportProvenance) -> Self {
        Self {
            scope: scope.clone(),
            scope_digest: scope.scope_digest.clone(),
            provider_id: scope.provider.id.clone(),
            provider_digest: scope.provider.digest.clone(),
            provenance,
            state: None,
            completeness: ObservationCompleteness::Complete,
            projects: Vec::new(),
            folders: Vec::new(),
            data_points: Vec::new(),
            highlights: Vec::new(),
            themes: Vec::new(),
            insights: Vec::new(),
            documents: Vec::new(),
            response_digests: BTreeMap::new(),
            page_count: 0,
            request_count: 0,
            retry_count: 0,
            retry_after_seconds: None,
            processing_seen: false,
        }
    }

    fn mark_failure(&mut self, failure: ReadFailure) {
        self.completeness = if matches!(failure, ReadFailure::BlockedEnv) || self.request_count == 0
        {
            ObservationCompleteness::Unavailable
        } else {
            ObservationCompleteness::Partial
        };
        self.state = Some(match failure {
            ReadFailure::BlockedEnv => ResearchEvidenceState::ProviderUnknown,
            ReadFailure::Partial => ResearchEvidenceState::Partial,
            ReadFailure::AccessLost => ResearchEvidenceState::AccessLost,
            ReadFailure::RetentionGap => ResearchEvidenceState::RetentionGap,
            ReadFailure::ProviderUnknown => ResearchEvidenceState::ProviderUnknown,
        });
    }

    fn accept(
        &mut self,
        operation: DovetailReadOperation,
        value: &Value,
    ) -> std::result::Result<(), DovetailProviderError> {
        match operation {
            DovetailReadOperation::ListProjectMetadata => {
                if let Some(project) = parse_project(value, &self.scope) {
                    self.projects.push(project);
                }
            }
            DovetailReadOperation::ListFolderMetadata => {
                if let Some(folder) = parse_folder(value, &self.scope) {
                    self.folders.push(folder);
                }
            }
            DovetailReadOperation::ListDataPointMetadata => {
                if let Some(data) = parse_data(value, &self.scope)? {
                    self.data_points.push(data);
                }
            }
            DovetailReadOperation::ListHighlightSummaries => {
                if let Some(highlight) = parse_highlight(value, &self.scope)? {
                    self.highlights.push(highlight);
                }
            }
            DovetailReadOperation::ListThemeTagSummaries => {
                if let Some(theme) = parse_theme(value, &self.scope) {
                    self.themes.push(theme);
                }
            }
            DovetailReadOperation::ListInsightMetadata => {
                if let Some(insight) = parse_insight(value, &self.scope) {
                    self.insights.push(insight);
                }
            }
            DovetailReadOperation::ListDocumentMetadata => {
                if let Some(document) = parse_document(value, &self.scope) {
                    self.documents.push(document);
                }
            }
        }
        Ok(())
    }

    fn finish(mut self) -> DovetailResearchObservation {
        dedup_sort(&mut self.projects, |item| item.id.as_str());
        dedup_sort(&mut self.folders, |item| item.id.as_str());
        dedup_sort(&mut self.data_points, |item| item.id.as_str());
        dedup_sort(&mut self.highlights, |item| item.id.as_str());
        dedup_sort(&mut self.themes, |item| item.id.as_str());
        dedup_sort(&mut self.insights, |item| item.id.as_str());
        dedup_sort(&mut self.documents, |item| item.id.as_str());
        let state = self.state.unwrap_or_else(|| {
            if self.provenance == TransportProvenance::BlockedEnv {
                ResearchEvidenceState::ProviderUnknown
            } else if self.processing_seen {
                ResearchEvidenceState::Processing
            } else if self.data_points.is_empty() {
                ResearchEvidenceState::Indexed
            } else {
                ResearchEvidenceState::Present
            }
        });
        let counts = ObservationCounts {
            projects: cap_u32(self.projects.len()),
            folders: cap_u32(self.folders.len()),
            data_points: cap_u32(self.data_points.len()),
            highlights: cap_u32(self.highlights.len()),
            themes: cap_u32(self.themes.len()),
            insights: cap_u32(self.insights.len()),
            documents: cap_u32(self.documents.len()),
        };
        let revision_digests = RevisionDigests {
            project: digest_values(&self.projects),
            folder: if self.folders.is_empty() {
                None
            } else {
                Some(digest_values(&self.folders))
            },
            data: digest_values(&self.data_points),
            highlights: digest_values(&self.highlights),
            themes: digest_values(&self.themes),
            insights: digest_values(&self.insights),
            documents: digest_values(&self.documents),
        };
        let mut observation = DovetailResearchObservation {
            schema_version: String::from(crate::CONTRACT_SCHEMA),
            scope_digest: self.scope_digest,
            provider_id: self.provider_id,
            provider_digest: self.provider_digest,
            provenance: self.provenance,
            state,
            completeness: self.completeness,
            projects: self.projects,
            folders: self.folders,
            data_points: self.data_points,
            highlights: self.highlights,
            themes: self.themes,
            insights: self.insights,
            documents: self.documents,
            counts,
            revision_digests,
            response_digests: self.response_digests,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            raw_provider_payload_retained: false,
            transcripts_retained: false,
            media_retained: false,
            participant_pii_retained: false,
            raw_notes_or_comments_retained: false,
            free_form_bodies_retained: false,
            sentiment_claim: false,
            theme_absence_proves_completeness: false,
            result_digest: Digest::from_text("unsealed-dovetail-result"),
        };
        observation.result_digest = observation.calculate_result_digest();
        observation
    }
}

fn dedup_sort<T, F>(items: &mut Vec<T>, key: F)
where
    F: Fn(&T) -> &str,
{
    items.sort_by(|left, right| key(left).cmp(key(right)));
    items.dedup_by(|left, right| key(left) == key(right));
}

fn fixture_response(
    scope: &DovetailResearchScope,
    operation: DovetailReadOperation,
) -> DovetailTransportResponse {
    let project_id = scope.dovetail_project.id.as_str();
    let folder_id = scope
        .dovetail_folder
        .as_ref()
        .map_or("folder-fixture", |folder| folder.id.as_str());
    let data_id = scope
        .dovetail_data
        .data_ids
        .first()
        .map_or("data-fixture", DataId::as_str);
    let body = match operation {
        DovetailReadOperation::ListProjectMetadata => json!({
            "data": [{
                "id": project_id,
                "title": "Customer research project with participant context",
                "folder_id": folder_id,
                "created_at": "2026-08-01T00:00:00Z",
                "updated_at": "2026-08-14T00:00:00Z",
                "deleted": false
            }],
            "page": {"total_count": 1, "has_more": false, "next_cursor": null}
        }),
        DovetailReadOperation::ListFolderMetadata => json!({
            "data": [{
                "id": folder_id,
                "title": "Sensitive interview folder",
                "parent_folder_id": null,
                "created_at": "2026-08-01T00:00:00Z",
                "updated_at": "2026-08-14T00:00:00Z",
                "deleted": false
            }],
            "page": {"total_count": 1, "has_more": false, "next_cursor": null}
        }),
        DovetailReadOperation::ListDataPointMetadata => json!({
            "data": [{
                "id": data_id,
                "title": "Interview with Alice Example",
                "project_id": project_id,
                "folder_id": folder_id,
                "content_type": "audio",
                "created_at": "2026-08-02T00:00:00Z",
                "updated_at": "2026-08-13T00:00:00Z",
                "deleted": false,
                "transcript": "Alice said a sensitive free-form sentence",
                "media_url": "https://example.invalid/private/audio",
                "participant": {"name": "Alice Example", "email": "alice@example.invalid"},
                "notes": "Raw note and comment text must be redacted"
            }],
            "page": {"total_count": 1, "has_more": false, "next_cursor": null}
        }),
        DovetailReadOperation::ListHighlightSummaries => json!({
            "data": [{
                "id": "highlight-fixture",
                "project_id": project_id,
                "data_id": data_id,
                "tag_ids": ["tag-fixture"],
                "created_at": "2026-08-03T00:00:00Z",
                "updated_at": "2026-08-13T00:00:00Z",
                "position": {"start": 10, "end": 20},
                "quote": "Sensitive transcript quote",
                "comments": [{"body": "Private comment"}]
            }],
            "page": {"total_count": 1, "has_more": false, "next_cursor": null}
        }),
        DovetailReadOperation::ListThemeTagSummaries => json!({
            "data": [{
                "id": "tag-fixture",
                "project_id": project_id,
                "name": "Pricing concern theme",
                "highlight_count": 1,
                "data_count": 1,
                "created_at": "2026-08-03T00:00:00Z",
                "updated_at": "2026-08-13T00:00:00Z"
            }],
            "page": {"total_count": 1, "has_more": false, "next_cursor": null}
        }),
        DovetailReadOperation::ListInsightMetadata => json!({
            "data": [{
                "id": "insight-fixture",
                "project_id": project_id,
                "folder_id": folder_id,
                "title": "Research insight title",
                "content": "Unbounded free-form insight body must never be retained",
                "created_at": "2026-08-04T00:00:00Z",
                "updated_at": "2026-08-13T00:00:00Z",
                "comments": [{"body": "Insight comment"}]
            }],
            "page": {"total_count": 1, "has_more": false, "next_cursor": null}
        }),
        DovetailReadOperation::ListDocumentMetadata => json!({
            "data": [{
                "id": "doc-fixture",
                "project_id": project_id,
                "folder_id": folder_id,
                "title": "Research document title",
                "body": "Document body is free-form and must never be retained",
                "created_at": "2026-08-04T00:00:00Z",
                "updated_at": "2026-08-13T00:00:00Z",
                "comments": [{"body": "Document comment"}]
            }],
            "page": {"total_count": 1, "has_more": false, "next_cursor": null}
        }),
    };
    DovetailTransportResponse::json(200, body)
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use crate::model::{
        ConsentId, ConsentScope, DovetailDataScope, DovetailProjectBinding, DovetailProjectId,
        DovetailProviderIdentity, HartevoProjectBinding, MissionBinding, MissionId, PluginVersion,
        ProjectId, WorkProductBinding, WorkProductId, WorkspaceBinding, WorkspaceId,
    };

    fn scope() -> DovetailResearchScope {
        let provider = DovetailProviderIdentity::layer1().expect("provider");
        let permission = crate::DovetailPermissionSnapshot::read_only(1).expect("permission");
        let data = DovetailDataScope::new(
            vec![DataId::new("data-fixture").expect("data")],
            Digest::from_text("data-revision"),
        )
        .expect("data scope");
        DovetailResearchScope::new(
            PluginVersion::V1,
            crate::CONTRACT_VERSION,
            crate::contract_digest(),
            provider,
            WorkspaceBinding::new(WorkspaceId::new("workspace-1").expect("workspace"), 1)
                .expect("workspace binding"),
            DovetailProjectBinding::new(
                DovetailProjectId::new("project-dovetail").expect("Dovetail project"),
                1,
            )
            .expect("Dovetail project binding"),
            Some(
                crate::FolderBinding::new(FolderId::new("folder-fixture").expect("folder"), 1)
                    .expect("folder binding"),
            ),
            data,
            HartevoProjectBinding::new(ProjectId::new("project-hartevo").expect("project"), 1)
                .expect("project binding"),
            MissionBinding::new(MissionId::new("mission-1").expect("mission"), 1)
                .expect("mission binding"),
            WorkProductBinding::new(
                WorkProductId::new("work-product-1").expect("work product"),
                1,
            )
            .expect("Work Product binding"),
            ConsentScope::metadata_only(ConsentId::new("consent-1").expect("consent"), 1)
                .expect("consent"),
            permission.digest,
        )
        .expect("scope")
    }

    #[test]
    fn fixture_is_redacted_and_only_allowlisted_gets_are_sent() {
        let scope = scope();
        let mut provider = DovetailProvider::fixture(scope.clone()).expect("fixture provider");
        let request = DovetailResearchReadRequest::for_scope(&scope, DovetailReadBounds::default())
            .expect("read request");
        let observation = provider.read(&request).expect("observation");
        observation.validate_integrity().expect("integrity");
        assert_eq!(observation.state, ResearchEvidenceState::Present);
        assert_eq!(observation.provenance, TransportProvenance::Fixture);
        assert!(!observation.provenance.is_connected());
        assert!(!observation.provenance.is_native());
        assert_eq!(observation.data_points.len(), 1);
        assert!(observation.data_points[0].raw_content_redacted);
        assert!(observation.data_points[0].participant_pii_redacted);
        assert!(observation.highlights[0].transcript_and_quote_redacted);
        assert!(observation.insights[0].body_redacted);
        let serialized = serde_json::to_string(&observation).expect("observation JSON");
        for forbidden in [
            "Alice Example",
            "alice@example.invalid",
            "Sensitive transcript quote",
            "Private comment",
            "Unbounded free-form insight body",
            "https://example.invalid/private/audio",
        ] {
            assert!(!serialized.contains(forbidden), "found {forbidden}");
        }
        let requests = provider.transport().requests();
        assert_eq!(requests.len(), 7);
        assert!(requests.iter().all(|request| {
            request.method == DovetailHttpMethod::Get
                && request.path.starts_with('/')
                && request.secret_reference_digest.is_valid()
                && !request.url().contains("api.")
        }));
        assert!(requests.iter().all(|request| {
            matches!(
                request.operation,
                DovetailReadOperation::ListProjectMetadata
                    | DovetailReadOperation::ListFolderMetadata
                    | DovetailReadOperation::ListDataPointMetadata
                    | DovetailReadOperation::ListHighlightSummaries
                    | DovetailReadOperation::ListThemeTagSummaries
                    | DovetailReadOperation::ListInsightMetadata
                    | DovetailReadOperation::ListDocumentMetadata
            )
        }));
        let mut tampered_request = requests[0].clone();
        tampered_request
            .query
            .insert(String::from("filter[arbitrary]"), String::from("nope"));
        assert!(tampered_request.validate().is_err());
        assert!(requests[0].query_value("page[limit]").is_some());
        assert!(requests[0].url().contains("page%5Blimit%5D=100"));
    }

    #[test]
    fn blocked_environment_never_becomes_connected_or_native() {
        let scope = scope();
        let mut provider = DovetailProvider::blocked_env(scope.clone()).expect("blocked provider");
        let request = DovetailResearchReadRequest::for_scope(&scope, DovetailReadBounds::default())
            .expect("read request");
        let observation = provider.read(&request).expect("blocked observation");
        assert_eq!(observation.provenance, TransportProvenance::BlockedEnv);
        assert_eq!(observation.state, ResearchEvidenceState::ProviderUnknown);
        assert_eq!(
            observation.completeness,
            ObservationCompleteness::Unavailable
        );
        assert_eq!(
            serde_json::to_value(observation.provenance).expect("provenance JSON"),
            "BLOCKED_ENV"
        );
        assert!(!provider.connected());
        assert!(!provider.native());
    }

    #[test]
    fn rate_limit_retries_are_bounded_and_redaction_safe() {
        let scope = scope();
        let response = DovetailTransportResponse::new(429, "{\"not_retained\":\"body\"}")
            .with_header("Retry-After", "1");
        let transport = DovetailFixtureTransport::from_scope(&scope)
            .with_response(DovetailReadOperation::ListProjectMetadata, response.clone())
            .with_response(DovetailReadOperation::ListProjectMetadata, response);
        let registration = DovetailRegistration::layer1(scope.clone()).expect("registration");
        let mut provider = DovetailProvider::new(registration, transport).expect("provider");
        let bounds = DovetailReadBounds {
            max_retries: 1,
            ..DovetailReadBounds::default()
        };
        let request = DovetailResearchReadRequest::for_scope(&scope, bounds).expect("request");
        let observation = provider.read(&request).expect("observation");
        assert_eq!(observation.state, ResearchEvidenceState::ProviderUnknown);
        assert!(observation.retry_count >= 1);
        assert!(observation.retry_count <= 7);
        assert!(
            !serde_json::to_string(&observation)
                .expect("observation JSON")
                .contains("not_retained")
        );
    }

    #[test]
    fn cursor_bound_normalizes_to_partial_without_native_claim() {
        let scope = scope();
        let response = DovetailTransportResponse::json(
            200,
            json!({
                "data": [],
                "page": {"total_count": 2, "has_more": true, "next_cursor": "cursor-1"}
            }),
        );
        let transport = DovetailFixtureTransport::from_scope(&scope)
            .with_response(DovetailReadOperation::ListProjectMetadata, response);
        let registration = DovetailRegistration::layer1(scope.clone()).expect("registration");
        let mut provider = DovetailProvider::new(registration, transport).expect("provider");
        let bounds = DovetailReadBounds {
            max_pages_per_operation: 1,
            ..DovetailReadBounds::default()
        };
        let request = DovetailResearchReadRequest::for_scope(&scope, bounds).expect("request");
        let observation = provider.read(&request).expect("observation");
        assert_eq!(observation.state, ResearchEvidenceState::Partial);
        assert_eq!(observation.completeness, ObservationCompleteness::Partial);
        assert!(!observation.provenance.is_connected());
        assert!(!observation.provenance.is_native());
    }
}

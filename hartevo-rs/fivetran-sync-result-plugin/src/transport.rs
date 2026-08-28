//! Read-only transport seams for the four allowlisted Fivetran GET routes.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ConnectionListRequest, Digest, FivetranConnectionId, FivetranConnectionListPayload,
    FivetranConnectionPayload, FivetranConnectionStatePayload, FivetranError,
    FivetranSchemasPayload, TransportMode,
};
use crate::{FivetranScope, Result};

/// The complete Layer-1 route allowlist. There is no enum variant for a
/// mutating, webhook, generic-discovery, or destination-readback route.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FivetranEndpoint {
    GetConnection,
    GetConnectionState,
    ListConnections,
    GetConnectionSchemas,
}

impl FivetranEndpoint {
    pub const fn method(self) -> &'static str {
        "GET"
    }

    pub fn path(self, connection_id: Option<&FivetranConnectionId>) -> Result<String> {
        match self {
            Self::GetConnection => Ok(format!(
                "/v1/connections/{}",
                connection_id.ok_or(FivetranError::MalformedPayload)?
            )),
            Self::GetConnectionState => Ok(format!(
                "/v1/connections/{}/state",
                connection_id.ok_or(FivetranError::MalformedPayload)?
            )),
            Self::ListConnections => Ok("/v1/connections".to_owned()),
            Self::GetConnectionSchemas => Ok(format!(
                "/v1/connections/{}/schemas",
                connection_id.ok_or(FivetranError::MalformedPayload)?
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranRequest {
    pub method: String,
    pub endpoint: FivetranEndpoint,
    pub path: String,
    pub group_id: Option<crate::FivetranGroupId>,
    pub schema_name: Option<crate::FivetranSchemaName>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    pub request_digest: Digest,
}

impl FivetranRequest {
    pub fn connection(scope: &FivetranScope) -> Result<Self> {
        Self::new(FivetranEndpoint::GetConnection, scope, None)
    }

    pub fn connection_state(scope: &FivetranScope) -> Result<Self> {
        Self::new(FivetranEndpoint::GetConnectionState, scope, None)
    }

    pub fn schemas(scope: &FivetranScope) -> Result<Self> {
        Self::new(FivetranEndpoint::GetConnectionSchemas, scope, None)
    }

    pub fn list(scope: &FivetranScope, list: &ConnectionListRequest) -> Result<Self> {
        list.validate()?;
        if list.group_id != scope.group_id || list.schema_name != scope.schema_name {
            return Err(FivetranError::PaginationScopeDrift);
        }
        let mut request = Self::new(FivetranEndpoint::ListConnections, scope, None)?;
        request.group_id = Some(list.group_id.clone());
        request.schema_name = Some(list.schema_name.clone());
        request.cursor.clone_from(&list.cursor);
        request.limit = Some(list.limit);
        request.request_digest = Digest::from_serializable(&(
            &request.method,
            request.endpoint,
            &request.path,
            &request.group_id,
            &request.schema_name,
            &request.cursor,
            request.limit,
        ));
        Ok(request)
    }

    fn new(
        endpoint: FivetranEndpoint,
        scope: &FivetranScope,
        _list: Option<&ConnectionListRequest>,
    ) -> Result<Self> {
        let connection_id = match endpoint {
            FivetranEndpoint::GetConnection
            | FivetranEndpoint::GetConnectionState
            | FivetranEndpoint::GetConnectionSchemas => Some(&scope.connection_id),
            FivetranEndpoint::ListConnections => None,
        };
        let path = endpoint.path(connection_id)?;
        let request = Self {
            method: endpoint.method().to_owned(),
            endpoint,
            path,
            group_id: None,
            schema_name: None,
            cursor: None,
            limit: None,
            request_digest: Digest::pending(),
        };
        let mut request = request;
        request.request_digest = Digest::from_serializable(&(
            &request.method,
            request.endpoint,
            &request.path,
            &request.group_id,
            &request.schema_name,
            &request.cursor,
            request.limit,
        ));
        Ok(request)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FivetranResponsePayload {
    Connection(FivetranConnectionPayload),
    ConnectionState(FivetranConnectionStatePayload),
    ConnectionList(FivetranConnectionListPayload),
    Schemas(FivetranSchemasPayload),
}

impl FivetranResponsePayload {
    pub const fn endpoint(&self) -> FivetranEndpoint {
        match self {
            Self::Connection(_) => FivetranEndpoint::GetConnection,
            Self::ConnectionState(_) => FivetranEndpoint::GetConnectionState,
            Self::ConnectionList(_) => FivetranEndpoint::ListConnections,
            Self::Schemas(_) => FivetranEndpoint::GetConnectionSchemas,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranHttpResponse {
    pub status: u16,
    pub endpoint: FivetranEndpoint,
    #[serde(default)]
    pub payload: Option<FivetranResponsePayload>,
    #[serde(default)]
    pub request_id_digest: Option<Digest>,
    pub response_digest: Digest,
    #[serde(default)]
    pub retry_after_seconds: Option<u32>,
    #[serde(default)]
    pub partial: bool,
}

impl FivetranHttpResponse {
    pub fn success(
        endpoint: FivetranEndpoint,
        payload: FivetranResponsePayload,
        request_id_digest: Option<Digest>,
        partial: bool,
    ) -> Self {
        let response_digest = Digest::from_serializable(&(200_u16, endpoint, &payload, partial));
        Self {
            status: 200,
            endpoint,
            payload: Some(payload),
            request_id_digest,
            response_digest,
            retry_after_seconds: None,
            partial,
        }
    }

    pub fn error(
        endpoint: FivetranEndpoint,
        status: u16,
        retry_after_seconds: Option<u32>,
    ) -> Self {
        let response_digest = Digest::from_serializable(&(status, endpoint, retry_after_seconds));
        Self {
            status,
            endpoint,
            payload: None,
            request_id_digest: None,
            response_digest,
            retry_after_seconds,
            partial: false,
        }
    }

    pub fn timeout(endpoint: FivetranEndpoint) -> Self {
        Self::error(endpoint, 408, None)
    }

    pub fn validate(&self) -> Result<()> {
        self.response_digest.validate()?;
        if let Some(request_id_digest) = &self.request_id_digest {
            request_id_digest.validate()?;
        }
        if let Some(payload) = &self.payload
            && payload.endpoint() != self.endpoint
        {
            return Err(FivetranError::EndpointMismatch);
        }
        let expected = if (200..300).contains(&self.status) {
            let payload = self
                .payload
                .as_ref()
                .ok_or(FivetranError::MalformedPayload)?;
            Digest::from_serializable(&(200_u16, self.endpoint, payload, self.partial))
        } else {
            Digest::from_serializable(&(self.status, self.endpoint, self.retry_after_seconds))
        };
        if self.response_digest != expected {
            return Err(FivetranError::TamperDetected {
                subject: "provider response digest",
            });
        }
        Ok(())
    }
}

/// A transport error is intentionally narrower than a native HTTP client. A
/// Layer-2 host may implement this trait, but this crate ships only
/// recording/fixture/loopback and BLOCKED_ENV implementations.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FivetranTransportError {
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("timeout")]
    Timeout,
    #[error("malformed response")]
    MalformedResponse,
    #[error("transport: {0}")]
    Other(String),
}

impl From<FivetranTransportError> for FivetranError {
    fn from(error: FivetranTransportError) -> Self {
        match error {
            FivetranTransportError::BlockedEnv => Self::BlockedEnv,
            FivetranTransportError::Timeout => Self::Timeout,
            FivetranTransportError::MalformedResponse => Self::MalformedPayload,
            FivetranTransportError::Other(message) => Self::Transport(message),
        }
    }
}

pub trait FivetranTransport: fmt::Debug + Send {
    fn execute(
        &mut self,
        request: &FivetranRequest,
    ) -> std::result::Result<FivetranHttpResponse, FivetranTransportError>;

    fn mode(&self) -> TransportMode;
}

/// Deterministic response queue for tests, recordings, loopback and fixture
/// evidence. It never resolves credentials and never reports native state.
#[derive(Clone, Debug)]
pub struct RecordingFivetranTransport {
    mode: TransportMode,
    responses: VecDeque<FivetranHttpResponse>,
    requests: Vec<FivetranRequest>,
}

impl Default for RecordingFivetranTransport {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl RecordingFivetranTransport {
    pub fn new(responses: Vec<FivetranHttpResponse>) -> Self {
        Self {
            mode: TransportMode::Recording,
            responses: responses.into(),
            requests: Vec::new(),
        }
    }

    pub fn recording(responses: Vec<FivetranHttpResponse>) -> Self {
        Self::new(responses)
    }

    pub fn fixture(responses: Vec<FivetranHttpResponse>) -> Self {
        Self {
            mode: TransportMode::Fixture,
            responses: responses.into(),
            requests: Vec::new(),
        }
    }

    pub fn loopback(responses: Vec<FivetranHttpResponse>) -> Self {
        Self {
            mode: TransportMode::Loopback,
            responses: responses.into(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: FivetranHttpResponse) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[FivetranRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl FivetranTransport for RecordingFivetranTransport {
    fn execute(
        &mut self,
        request: &FivetranRequest,
    ) -> std::result::Result<FivetranHttpResponse, FivetranTransportError> {
        self.requests.push(request.clone());
        let response = self
            .responses
            .pop_front()
            .ok_or(FivetranTransportError::Other(
                "no recording response".to_owned(),
            ))?;
        if response.endpoint != request.endpoint {
            return Err(FivetranTransportError::Other(
                FivetranError::EndpointMismatch.to_string(),
            ));
        }
        Ok(response)
    }

    fn mode(&self) -> TransportMode {
        self.mode
    }
}

pub type FivetranFixtureTransport = RecordingFivetranTransport;
pub type FivetranLoopbackTransport = RecordingFivetranTransport;
pub type FivetranRecordingTransport = RecordingFivetranTransport;

/// Explicitly blocked native/environment transport. It is useful to make the
/// honest Layer-1 gap observable in tests without consulting process state.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvFivetranTransport;

impl FivetranTransport for BlockedEnvFivetranTransport {
    fn execute(
        &mut self,
        _request: &FivetranRequest,
    ) -> std::result::Result<FivetranHttpResponse, FivetranTransportError> {
        Err(FivetranTransportError::BlockedEnv)
    }

    fn mode(&self) -> TransportMode {
        TransportMode::BlockedEnv
    }
}

/// Converts a bounded JSON recording into a typed response without exposing
/// the wire envelope or retaining connector config. Unknown provider fields
/// (including `config`) are ignored by the wire structs and are never put in a
/// public payload.
pub fn response_from_json(
    endpoint: FivetranEndpoint,
    status: u16,
    json: &str,
    request_id_digest: Option<Digest>,
) -> Result<FivetranHttpResponse> {
    if json.len() > crate::MAX_RESPONSE_BYTES {
        return Err(FivetranError::BoundExceeded {
            field: "response bytes",
            limit: crate::MAX_RESPONSE_BYTES,
        });
    }
    if !(200..300).contains(&status) {
        return Ok(FivetranHttpResponse::error(endpoint, status, None));
    }
    let envelope: WireEnvelope<serde_json::Value> = serde_json::from_str(json)?;
    let data = envelope.data.ok_or(FivetranError::MalformedPayload)?;
    let payload = match endpoint {
        FivetranEndpoint::GetConnection => {
            FivetranResponsePayload::Connection(parse_connection_wire(&data)?)
        }
        FivetranEndpoint::GetConnectionState => {
            FivetranResponsePayload::ConnectionState(parse_state_wire(data)?)
        }
        FivetranEndpoint::ListConnections => {
            FivetranResponsePayload::ConnectionList(parse_list_wire(&data)?)
        }
        FivetranEndpoint::GetConnectionSchemas => {
            FivetranResponsePayload::Schemas(parse_schemas_wire(&data)?)
        }
    };
    Ok(FivetranHttpResponse::success(
        endpoint,
        payload,
        request_id_digest,
        false,
    ))
}

#[derive(Debug, Deserialize)]
struct WireEnvelope<T> {
    #[allow(dead_code)]
    code: Option<String>,
    data: Option<T>,
}

fn parse_connection_wire(data: &serde_json::Value) -> Result<FivetranConnectionPayload> {
    let mut object = data
        .as_object()
        .cloned()
        .ok_or(FivetranError::MalformedPayload)?;
    let schema = object
        .remove("schema")
        .ok_or(FivetranError::MalformedPayload)?;
    object.insert("schema_name".to_owned(), schema);
    let parsed: FivetranConnectionPayload =
        serde_json::from_value(serde_json::Value::Object(object))?;
    parsed.validate()?;
    Ok(parsed)
}

fn parse_state_wire(data: serde_json::Value) -> Result<FivetranConnectionStatePayload> {
    if let Some(state) = data.as_object().and_then(|object| object.get("state")) {
        let state_bytes = serde_json::to_vec(state)?;
        let state_field_count = state.as_object().map_or(1, serde_json::Map::len);
        return Ok(FivetranConnectionStatePayload::opaque_state(
            Digest::from_bytes(&state_bytes),
            state_field_count,
        ));
    }
    let parsed: FivetranConnectionStatePayload = serde_json::from_value(data)?;
    if let Some(id) = &parsed.id {
        id.validate()?;
    }
    if let Some(group_id) = &parsed.group_id {
        group_id.validate()?;
    }
    Ok(parsed)
}

fn parse_list_wire(data: &serde_json::Value) -> Result<FivetranConnectionListPayload> {
    let mut object = data
        .as_object()
        .cloned()
        .ok_or(FivetranError::MalformedPayload)?;
    let items = object
        .remove("items")
        .ok_or(FivetranError::MalformedPayload)?;
    let mut items = items
        .as_array()
        .cloned()
        .ok_or(FivetranError::MalformedPayload)?;
    for item in &mut items {
        if let Some(object) = item.as_object_mut()
            && let Some(schema) = object.remove("schema")
        {
            object.insert("schema_name".to_owned(), schema);
        }
    }
    object.insert("items".to_owned(), serde_json::Value::Array(items));
    let parsed: FivetranConnectionListPayload =
        serde_json::from_value(serde_json::Value::Object(object))?;
    if parsed.items.len() > crate::MAX_PAGE_ITEMS {
        return Err(FivetranError::BoundExceeded {
            field: "connection list items",
            limit: crate::MAX_PAGE_ITEMS,
        });
    }
    Ok(parsed)
}

fn parse_schemas_wire(data: &serde_json::Value) -> Result<FivetranSchemasPayload> {
    let mut object = data
        .as_object()
        .cloned()
        .ok_or(FivetranError::MalformedPayload)?;
    let schemas_value = object
        .remove("schemas")
        .ok_or(FivetranError::MalformedPayload)?;
    let parsed = if schemas_value.is_array() {
        object.insert("schemas".to_owned(), schemas_value);
        serde_json::from_value(serde_json::Value::Object(object))?
    } else {
        parse_schema_map(schemas_value, &object)?
    };
    parsed.validate_bounds()?;
    Ok(parsed)
}

fn parse_schema_map(
    schemas_value: serde_json::Value,
    parent: &serde_json::Map<String, serde_json::Value>,
) -> Result<FivetranSchemasPayload> {
    let schemas: BTreeMap<String, SchemaWire> = serde_json::from_value(schemas_value)?;
    let mut typed_schemas = Vec::with_capacity(schemas.len());
    for (schema_name, schema) in schemas {
        let name = crate::FivetranSchemaName::new(schema_name)?;
        let mut typed_tables = Vec::with_capacity(schema.tables.len());
        for (table_name, table) in schema.tables {
            let name = crate::FivetranTableName::new(table_name)?;
            let mut typed_columns = Vec::with_capacity(table.columns.len());
            for (column_name, column) in table.columns {
                typed_columns.push(crate::FivetranColumnMetadata {
                    name: crate::FivetranTableName::new(column_name)?,
                    name_in_destination: column.name_in_destination,
                    enabled: column.enabled,
                    hashed: column.hashed,
                    is_primary_key: column.is_primary_key,
                });
            }
            typed_tables.push(crate::FivetranTableMetadata {
                name,
                name_in_destination: table.name_in_destination,
                enabled: table.enabled,
                sync_mode: table.sync_mode,
                columns: typed_columns,
            });
        }
        typed_schemas.push(crate::FivetranSchemaMetadata {
            name,
            name_in_destination: schema.name_in_destination,
            enabled: schema.enabled,
            tables: typed_tables,
        });
    }
    let schema_change_handling = parent
        .get("schema_change_handling")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let revision = parent
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let partial = parent
        .get("partial")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Ok(FivetranSchemasPayload {
        schema_change_handling,
        schemas: typed_schemas,
        revision,
        partial,
    })
}

#[derive(Debug, Deserialize)]
struct SchemaWire {
    #[serde(default)]
    name_in_destination: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    tables: BTreeMap<String, TableWire>,
}

#[derive(Debug, Deserialize)]
struct TableWire {
    #[serde(default)]
    sync_mode: Option<crate::SyncMode>,
    #[serde(default)]
    name_in_destination: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    columns: BTreeMap<String, ColumnWire>,
}

#[derive(Debug, Deserialize)]
struct ColumnWire {
    #[serde(default)]
    name_in_destination: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    hashed: Option<bool>,
    #[serde(default)]
    is_primary_key: Option<bool>,
}

//! Bounded GET-only Boundary transport seams.
//!
//! `BoundaryJsonResponse` projects provider JSON into typed metadata and
//! drops the input bytes. The typed response retains only a digest and the
//! allowlisted result fields.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AccountId, AuthMethodId, BoundaryHttpResponse, BoundaryModelError, BoundaryReadOperation,
    BoundaryReadRequest, BoundaryResponseBody, BoundaryResponseType, BoundaryScopeId,
    BoundarySessionMetadata, BoundarySessionResultState, BoundaryTargetMetadata, Digest, HostId,
    OpaqueListToken, OrganizationId, ProjectId, Revision, SessionId, TargetId, TransportProvenance,
    sha256_digest,
};
use crate::{
    BOUNDARY_MAX_CONNECTIONS, BOUNDARY_MAX_RESPONSE_BYTES, BOUNDARY_MAX_SESSIONS_PER_PAGE,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BoundaryTransportError {
    #[error("Boundary transport is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("Boundary transport timed out")]
    Timeout,
    #[error("Boundary transport is unavailable")]
    TransportUnavailable,
    #[error("Boundary response was malformed")]
    MalformedResponse,
    #[error("Boundary response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("Boundary request was invalid")]
    InvalidRequest,
    #[error("Boundary returned HTTP status {0}")]
    HttpStatus(u16),
}

impl From<BoundaryModelError> for BoundaryTransportError {
    fn from(_: BoundaryModelError) -> Self {
        Self::MalformedResponse
    }
}

/// A transport has exactly one operation: a bounded metadata GET.
pub trait BoundaryTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get(
        &mut self,
        request: &BoundaryReadRequest,
    ) -> Result<BoundaryHttpResponse, BoundaryTransportError>;
}

/// Parse an already bounded provider body and immediately project away all
/// fields outside the Layer-1 allowlist.
#[derive(Clone, Copy, Debug, Default)]
pub struct BoundaryJsonResponse;

impl BoundaryJsonResponse {
    pub fn from_bytes(
        request: &BoundaryReadRequest,
        status: u16,
        bytes: &[u8],
    ) -> Result<BoundaryHttpResponse, BoundaryTransportError> {
        if bytes.len() > request.max_response_bytes || bytes.len() > BOUNDARY_MAX_RESPONSE_BYTES {
            return Err(BoundaryTransportError::ResponseTooLarge);
        }
        let response_digest = sha256_digest(bytes);
        if status != 200 {
            return Ok(BoundaryHttpResponse {
                status,
                response_bytes: bytes.len(),
                response_digest,
                body: BoundaryResponseBody::Empty,
            });
        }
        let value = serde_json::from_slice::<Value>(bytes)
            .map_err(|_| BoundaryTransportError::MalformedResponse)?;
        let body = match request.operation {
            BoundaryReadOperation::ListSessions => parse_session_list(&value)?,
            BoundaryReadOperation::ReadSession => {
                BoundaryResponseBody::Session(parse_session(&value)?)
            }
            BoundaryReadOperation::ReadTarget => {
                BoundaryResponseBody::Target(parse_target(&value)?)
            }
        };
        Ok(BoundaryHttpResponse {
            status,
            response_bytes: bytes.len(),
            response_digest,
            body,
        })
    }
}

pub fn response_from_json(
    request: &BoundaryReadRequest,
    status: u16,
    bytes: &[u8],
) -> Result<BoundaryHttpResponse, BoundaryTransportError> {
    BoundaryJsonResponse::from_bytes(request, status, bytes)
}

fn parse_session_list(value: &Value) -> Result<BoundaryResponseBody, BoundaryTransportError> {
    let items = value
        .get("items")
        .or_else(|| value.get("sessions"))
        .and_then(Value::as_array)
        .ok_or(BoundaryTransportError::MalformedResponse)?;
    if items.len() > BOUNDARY_MAX_SESSIONS_PER_PAGE {
        return Err(BoundaryTransportError::MalformedResponse);
    }
    let sessions = items
        .iter()
        .map(parse_session)
        .collect::<Result<Vec<_>, _>>()?;
    let next_list_token = optional_string(value, "list_token")
        .map(OpaqueListToken::new)
        .transpose()?;
    let response_type = match optional_string(value, "response_type")
        .unwrap_or_else(|| "complete".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "delta" => BoundaryResponseType::Delta,
        "complete" => BoundaryResponseType::Complete,
        _ => return Err(BoundaryTransportError::MalformedResponse),
    };
    let estimated_item_count = value
        .get("est_item_count")
        .or_else(|| value.get("estimated_item_count"))
        .and_then(Value::as_u64)
        .map(u32::try_from)
        .transpose()
        .map_err(|_| BoundaryTransportError::MalformedResponse)?;
    let removed_id_digests = value
        .get("removed_ids")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .map(|item| {
            item.as_str()
                .map(|id| Digest::from_fields(["boundary-removed-session", id]))
                .ok_or(BoundaryTransportError::MalformedResponse)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if removed_id_digests.len() > BOUNDARY_MAX_SESSIONS_PER_PAGE {
        return Err(BoundaryTransportError::MalformedResponse);
    }
    Ok(BoundaryResponseBody::SessionList {
        sessions,
        next_list_token,
        response_type,
        estimated_item_count,
        removed_id_digests,
    })
}

fn parse_session(value: &Value) -> Result<BoundarySessionMetadata, BoundaryTransportError> {
    let id = SessionId::new(required_string(value, "id")?)?;
    let target_id = TargetId::new(required_string(value, "target_id")?)?;
    let scope_id = BoundaryScopeId::new(
        optional_nested_string(value, "scope", "id")
            .or_else(|| optional_string(value, "scope_id"))
            .ok_or(BoundaryTransportError::MalformedResponse)?,
    )?;
    let revision = Revision::new(
        value
            .get("version")
            .and_then(Value::as_u64)
            .ok_or(BoundaryTransportError::MalformedResponse)?,
    )?;
    let state_text = optional_string(value, "status").or_else(|| {
        value
            .get("states")
            .and_then(Value::as_array)
            .and_then(|states| states.last())
            .and_then(|state| state.get("status"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let state = state_text.as_deref().map_or(
        BoundarySessionResultState::ProviderUnknown,
        BoundarySessionResultState::from_wire,
    );
    if !state.is_lifecycle() {
        return Err(BoundaryTransportError::MalformedResponse);
    }
    let connections = match value.get("connections") {
        None => &[][..],
        Some(Value::Array(connections)) => connections.as_slice(),
        Some(_) => return Err(BoundaryTransportError::MalformedResponse),
    };
    if connections.len() > usize::from(BOUNDARY_MAX_CONNECTIONS) {
        return Err(BoundaryTransportError::MalformedResponse);
    }
    let active_connection_count = connections
        .iter()
        .filter(|connection| connection.get("closed_reason").is_none())
        .count();
    let created_at = optional_timestamp(value, &["created_time", "created_at"])?;
    let updated_at = optional_timestamp(value, &["updated_time", "updated_at"])?;
    let expiration_at = optional_timestamp(value, &["expiration_time", "expiration_at"])?;
    let terminated_at = optional_timestamp(value, &["termination_time", "terminated_at"])?
        .or(state_end_time(value, "terminated")?);
    let mut session = BoundarySessionMetadata::new(
        id,
        target_id,
        scope_id,
        revision,
        state,
        created_at,
        updated_at,
        expiration_at,
        terminated_at,
        u16::try_from(connections.len()).map_err(|_| BoundaryTransportError::MalformedResponse)?,
        u16::try_from(active_connection_count)
            .map_err(|_| BoundaryTransportError::MalformedResponse)?,
    )?;
    session.host_id = optional_id(value, "host_id", HostId::new)?;
    session.organization_id =
        optional_id(value, "organization_id", OrganizationId::new)?.or_else(|| {
            optional_id(value, "org_id", OrganizationId::new)
                .ok()
                .flatten()
        });
    session.project_id = optional_id(value, "project_id", ProjectId::new)?;
    session.auth_method_id = optional_id(value, "auth_method_id", AuthMethodId::new)?;
    session.account_id = optional_id(value, "account_id", AccountId::new)?;
    session.principal_digest = optional_principal_digest(value)?;
    session.session_type_digest = optional_string(value, "type")
        .map(|value| Digest::from_fields(["boundary-session-type", value.as_str()]));
    session.lifecycle_digest = session.recompute_lifecycle_digest();
    Ok(session)
}

fn parse_target(value: &Value) -> Result<BoundaryTargetMetadata, BoundaryTransportError> {
    let id = TargetId::new(required_string(value, "id")?)?;
    let scope_id = BoundaryScopeId::new(
        optional_string(value, "scope_id")
            .or_else(|| optional_nested_string(value, "scope", "id"))
            .ok_or(BoundaryTransportError::MalformedResponse)?,
    )?;
    let revision = Revision::new(
        value
            .get("version")
            .and_then(Value::as_u64)
            .ok_or(BoundaryTransportError::MalformedResponse)?,
    )?;
    let target_type_digest = optional_string(value, "type")
        .map(|value| Digest::from_fields(["boundary-target-type", value.as_str()]));
    let name_digest = optional_string(value, "name")
        .map(|value| Digest::from_fields(["boundary-target-name", value.as_str()]));
    let description_digest = optional_string(value, "description")
        .map(|value| Digest::from_fields(["boundary-target-description", value.as_str()]));
    let address_digest = optional_string(value, "address")
        .map(|value| Digest::from_fields(["boundary-target-address", value.as_str()]));
    let session_max_seconds = optional_u64(value, "session_max_seconds")
        .map(u32::try_from)
        .transpose()
        .map_err(|_| BoundaryTransportError::MalformedResponse)?;
    let session_connection_limit = match value.get("session_connection_limit") {
        None => None,
        Some(Value::Number(value)) if value.as_i64() == Some(-1) => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(BoundaryTransportError::MalformedResponse)?,
        ),
    };
    let mut target = BoundaryTargetMetadata::new(
        id,
        scope_id,
        revision,
        target_type_digest,
        name_digest,
        description_digest,
        address_digest,
        session_max_seconds,
        session_connection_limit,
    );
    target.organization_id =
        optional_id(value, "organization_id", OrganizationId::new)?.or_else(|| {
            optional_id(value, "org_id", OrganizationId::new)
                .ok()
                .flatten()
        });
    target.project_id = optional_id(value, "project_id", ProjectId::new)?;
    target.target_digest = target.recompute_digest();
    Ok(target)
}

fn required_string<'a>(
    value: &'a Value,
    key: &'static str,
) -> Result<&'a str, BoundaryTransportError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(BoundaryTransportError::MalformedResponse)
}

fn optional_string(value: &Value, key: &'static str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn optional_nested_string(
    value: &Value,
    object_key: &'static str,
    key: &'static str,
) -> Option<String> {
    value
        .get(object_key)
        .and_then(Value::as_object)
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn optional_u64(value: &Value, key: &'static str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn optional_id<T>(
    value: &Value,
    key: &'static str,
    constructor: impl FnOnce(String) -> Result<T, BoundaryModelError>,
) -> Result<Option<T>, BoundaryTransportError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(|value| constructor(value.to_owned()).map_err(BoundaryTransportError::from))
        .transpose()
}

fn optional_principal_digest(value: &Value) -> Result<Option<Digest>, BoundaryTransportError> {
    if let Some(value) = optional_string(value, "principal_digest") {
        return Digest::parse(value)
            .map(Some)
            .map_err(BoundaryTransportError::from);
    }
    Ok(optional_string(value, "principal")
        .map(|value| Digest::from_fields(["boundary-principal", value.as_str()])))
}

fn optional_timestamp(
    value: &Value,
    keys: &[&'static str],
) -> Result<Option<DateTime<Utc>>, BoundaryTransportError> {
    for key in keys {
        if let Some(value) = optional_string(value, key) {
            if value.len() > crate::BOUNDARY_MAX_TIMESTAMP_BYTES {
                return Err(BoundaryTransportError::MalformedResponse);
            }
            return DateTime::parse_from_rfc3339(&value)
                .map(|value| Some(value.with_timezone(&Utc)))
                .map_err(|_| BoundaryTransportError::MalformedResponse);
        }
    }
    Ok(None)
}

fn state_end_time(
    value: &Value,
    wanted_state: &str,
) -> Result<Option<DateTime<Utc>>, BoundaryTransportError> {
    let Some(states) = value.get("states").and_then(Value::as_array) else {
        return Ok(None);
    };
    for state in states.iter().rev() {
        let Some(status) = state.get("status").and_then(Value::as_str) else {
            continue;
        };
        if !status.eq_ignore_ascii_case(wanted_state) {
            continue;
        }
        let Some(end_time) = state.get("end_time").and_then(Value::as_str) else {
            return Ok(None);
        };
        if end_time.len() > crate::BOUNDARY_MAX_TIMESTAMP_BYTES {
            return Err(BoundaryTransportError::MalformedResponse);
        }
        return DateTime::parse_from_rfc3339(end_time)
            .map(|value| Some(value.with_timezone(&Utc)))
            .map_err(|_| BoundaryTransportError::MalformedResponse);
    }
    Ok(None)
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            responses: VecDeque<Result<BoundaryHttpResponse, BoundaryTransportError>>,
            requests: Vec<BoundaryReadRequest>,
        }

        impl $name {
            pub fn new(
                responses: impl IntoIterator<
                    Item = Result<BoundaryHttpResponse, BoundaryTransportError>,
                >,
            ) -> Self {
                Self {
                    responses: responses.into_iter().collect(),
                    requests: Vec::new(),
                }
            }

            pub fn fixture(responses: impl IntoIterator<Item = BoundaryHttpResponse>) -> Self {
                Self::new(responses.into_iter().map(Ok))
            }

            pub fn push_response(
                &mut self,
                response: Result<BoundaryHttpResponse, BoundaryTransportError>,
            ) {
                self.responses.push_back(response);
            }

            pub fn requests(&self) -> &[BoundaryReadRequest] {
                &self.requests
            }
        }

        impl BoundaryTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn get(
                &mut self,
                request: &BoundaryReadRequest,
            ) -> Result<BoundaryHttpResponse, BoundaryTransportError> {
                self.requests.push(request.clone());
                self.responses
                    .pop_front()
                    .unwrap_or(Err(BoundaryTransportError::Timeout))
            }
        }
    };
}

queued_transport!(RecordingBoundaryTransport, TransportProvenance::Recording);
queued_transport!(FixtureBoundaryTransport, TransportProvenance::Fixture);
queued_transport!(FakeBoundaryTransport, TransportProvenance::Fake);
queued_transport!(LoopbackBoundaryTransport, TransportProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvBoundaryTransport;

impl BoundaryTransport for BlockedEnvBoundaryTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get(
        &mut self,
        _request: &BoundaryReadRequest,
    ) -> Result<BoundaryHttpResponse, BoundaryTransportError> {
        Err(BoundaryTransportError::BlockedEnv)
    }
}

pub type BoundaryHttpRequest = BoundaryReadRequest;
pub type BlockedEnvTransport = BlockedEnvBoundaryTransport;
pub type ProviderProvenance = TransportProvenance;

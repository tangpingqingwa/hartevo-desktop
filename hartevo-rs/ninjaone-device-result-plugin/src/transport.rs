//! Bounded allowlisted GET seams and non-native transports.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    ActivityKind, ActivityResult, ActivitySeverity, AlertKind, Digest, HealthStatus,
    NinjaOneActivityId, NinjaOneAgentId, NinjaOneAlertId, NinjaOneDeviceId, NinjaOneOrganizationId,
    NinjaOnePatchHealthId, NinjaOneRedactedReceipt, NinjaOneScope, NinjaOneSiteId, PatchStatus,
    Revision, SecretReference, TransportMode,
};
use crate::{MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, NinjaOneError, Result};

/// Exact Public API GET seams owned by this Layer-1 plugin.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NinjaOneEndpoint {
    Organizations,
    Devices,
    DeviceAlerts,
    DeviceHealth,
    DeviceOsPatches,
    DeviceSoftwarePatches,
    DeviceActivities,
}

impl NinjaOneEndpoint {
    pub const fn route(self) -> &'static str {
        match self {
            Self::Organizations => "GET /v2/organizations",
            Self::Devices => "GET /v2/devices",
            Self::DeviceAlerts => "GET /v2/device/{id}/alerts",
            Self::DeviceHealth => "GET /v2/queries/device-health",
            Self::DeviceOsPatches => "GET /v2/device/{id}/os-patches",
            Self::DeviceSoftwarePatches => "GET /v2/device/{id}/software-patches",
            Self::DeviceActivities => "GET /v2/device/{id}/activities",
        }
    }

    pub const fn is_allowlisted(self) -> bool {
        true
    }
}

/// A request contains only route identity, bounded paging, and digest fences;
/// it has no URL with a raw device ID and no authorization header.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneGetRequest {
    endpoint: NinjaOneEndpoint,
    page_size: usize,
    after: Option<u64>,
    scope_digest: Digest,
    secret_reference_digest: Digest,
    request_digest: Digest,
}

impl NinjaOneGetRequest {
    pub fn new(
        endpoint: NinjaOneEndpoint,
        scope: &NinjaOneScope,
        secret_reference: &SecretReference,
        page_size: usize,
        after: Option<u64>,
    ) -> Result<Self> {
        if !endpoint.is_allowlisted() || page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(NinjaOneError::BoundExceeded {
                kind: "GET request page size",
            });
        }
        let scope_digest = scope.scope_digest().clone();
        let secret_reference_digest = secret_reference.reference_digest().clone();
        let request_digest = Digest::from_serializable(&(
            "hartevo.ninjaone-get-request/v1",
            endpoint,
            page_size,
            after,
            &scope_digest,
            &secret_reference_digest,
        ));
        Ok(Self {
            endpoint,
            page_size,
            after,
            scope_digest,
            secret_reference_digest,
            request_digest,
        })
    }

    pub const fn endpoint(&self) -> NinjaOneEndpoint {
        self.endpoint
    }

    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    pub const fn after(&self) -> Option<u64> {
        self.after
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneOrganizationRecord {
    pub organization_id: NinjaOneOrganizationId,
    pub site_ids: Vec<NinjaOneSiteId>,
    pub revision: Revision,
    pub metadata_digest: Digest,
}

impl NinjaOneOrganizationRecord {
    pub fn new(
        organization_id: impl Into<String>,
        site_ids: impl IntoIterator<Item = impl Into<String>>,
        revision: u64,
        metadata: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let site_ids = site_ids
            .into_iter()
            .map(NinjaOneSiteId::new)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            organization_id: NinjaOneOrganizationId::new(organization_id)?,
            site_ids,
            revision: Revision::new(revision)?,
            metadata_digest: Digest::from_bytes(metadata.as_ref()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneDeviceRecord {
    pub organization_id: NinjaOneOrganizationId,
    pub site_id: NinjaOneSiteId,
    pub device_id: NinjaOneDeviceId,
    pub agent_id: NinjaOneAgentId,
    pub offline: bool,
    pub last_contact_at_millis: Option<u64>,
    pub revision: Revision,
    pub metadata_digest: Digest,
}

impl NinjaOneDeviceRecord {
    pub fn new(
        organization_id: impl Into<String>,
        site_id: impl Into<String>,
        device_id: impl Into<String>,
        agent_id: impl Into<String>,
        offline: bool,
        last_contact_at_millis: Option<u64>,
        revision: u64,
        metadata: impl AsRef<[u8]>,
    ) -> Result<Self> {
        Ok(Self {
            organization_id: NinjaOneOrganizationId::new(organization_id)?,
            site_id: NinjaOneSiteId::new(site_id)?,
            device_id: NinjaOneDeviceId::new(device_id)?,
            agent_id: NinjaOneAgentId::new(agent_id)?,
            offline,
            last_contact_at_millis,
            revision: Revision::new(revision)?,
            metadata_digest: Digest::from_bytes(metadata.as_ref()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneDeviceAlertRecord {
    pub alert_id: NinjaOneAlertId,
    pub device_id: NinjaOneDeviceId,
    pub kind: AlertKind,
    pub created_at_millis: Option<u64>,
    pub updated_at_millis: Option<u64>,
    pub revision: Revision,
    pub body_digest: Option<Digest>,
    pub metadata_digest: Digest,
    pub source_digest: Digest,
}

impl NinjaOneDeviceAlertRecord {
    pub fn new(
        alert_id: impl Into<String>,
        device_id: impl Into<String>,
        source_type: &str,
        created_at_millis: Option<u64>,
        updated_at_millis: Option<u64>,
        revision: u64,
        alert_body: Option<&str>,
    ) -> Result<Self> {
        let source_digest = Digest::from_text(source_type);
        Ok(Self {
            alert_id: NinjaOneAlertId::new(alert_id)?,
            device_id: NinjaOneDeviceId::new(device_id)?,
            kind: AlertKind::parse(source_type),
            created_at_millis,
            updated_at_millis,
            revision: Revision::new(revision)?,
            body_digest: alert_body.map(Digest::from_text),
            metadata_digest: Digest::from_serializable(&(
                "ninjaone-alert-metadata/v1",
                &source_digest,
                created_at_millis,
                updated_at_millis,
            )),
            source_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneDeviceHealthRecord {
    pub patch_health_id: NinjaOnePatchHealthId,
    pub device_id: NinjaOneDeviceId,
    pub health_status: HealthStatus,
    pub offline: bool,
    pub alert_count: usize,
    pub pending_os_patches: usize,
    pub failed_os_patches: usize,
    pub pending_software_patches: usize,
    pub failed_software_patches: usize,
    pub observed_at_millis: Option<u64>,
    pub revision: Revision,
    pub metadata_digest: Digest,
}

impl NinjaOneDeviceHealthRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_id: impl Into<String>,
        health_status: HealthStatus,
        offline: bool,
        alert_count: usize,
        pending_os_patches: usize,
        failed_os_patches: usize,
        pending_software_patches: usize,
        failed_software_patches: usize,
        observed_at_millis: Option<u64>,
        revision: u64,
        metadata: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let device_id = NinjaOneDeviceId::new(device_id)?;
        Ok(Self {
            patch_health_id: NinjaOnePatchHealthId::new(device_id.as_str())?,
            device_id,
            health_status,
            offline,
            alert_count,
            pending_os_patches,
            failed_os_patches,
            pending_software_patches,
            failed_software_patches,
            observed_at_millis,
            revision: Revision::new(revision)?,
            metadata_digest: Digest::from_bytes(metadata.as_ref()),
        })
    }

    pub fn with_patch_health_id(mut self, patch_health_id: impl Into<String>) -> Result<Self> {
        self.patch_health_id = NinjaOnePatchHealthId::new(patch_health_id)?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOnePatchRecord {
    pub patch_id: String,
    pub device_id: NinjaOneDeviceId,
    pub status: PatchStatus,
    pub observed_at_millis: Option<u64>,
    pub revision: Revision,
    pub metadata_digest: Digest,
}

impl NinjaOnePatchRecord {
    pub fn new(
        patch_id: impl Into<String>,
        device_id: impl Into<String>,
        status: PatchStatus,
        observed_at_millis: Option<u64>,
        revision: u64,
        metadata: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let patch_id = patch_id.into();
        if patch_id.is_empty() || patch_id.len() > 256 || patch_id.chars().any(char::is_control) {
            return Err(NinjaOneError::InvalidIdentifier { kind: "patch" });
        }
        Ok(Self {
            patch_id,
            device_id: NinjaOneDeviceId::new(device_id)?,
            status,
            observed_at_millis,
            revision: Revision::new(revision)?,
            metadata_digest: Digest::from_bytes(metadata.as_ref()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneDeviceActivityRecord {
    pub activity_id: NinjaOneActivityId,
    pub device_id: NinjaOneDeviceId,
    pub kind: ActivityKind,
    pub severity: ActivitySeverity,
    pub result: ActivityResult,
    pub activity_at_millis: Option<u64>,
    pub revision: Revision,
    pub metadata_digest: Digest,
    pub activity_type_digest: Digest,
}

impl NinjaOneDeviceActivityRecord {
    pub fn new(
        activity_id: impl Into<String>,
        device_id: impl Into<String>,
        activity_type: &str,
        severity: ActivitySeverity,
        result: ActivityResult,
        activity_at_millis: Option<u64>,
        revision: u64,
    ) -> Result<Self> {
        let activity_type_digest = Digest::from_text(activity_type);
        Ok(Self {
            activity_id: NinjaOneActivityId::new(activity_id)?,
            device_id: NinjaOneDeviceId::new(device_id)?,
            kind: ActivityKind::parse(activity_type),
            severity,
            result,
            activity_at_millis,
            revision: Revision::new(revision)?,
            metadata_digest: Digest::from_serializable(&(
                "ninjaone-activity-metadata/v1",
                &activity_type_digest,
                severity,
                result,
                activity_at_millis,
            )),
            activity_type_digest,
        })
    }
}

/// The safe, normalized payload vocabulary. There is no generic JSON value or
/// raw response body in this enum.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NinjaOnePayload {
    Organizations(Vec<NinjaOneOrganizationRecord>),
    Devices(Vec<NinjaOneDeviceRecord>),
    DeviceAlerts(Vec<NinjaOneDeviceAlertRecord>),
    DeviceHealth(Vec<NinjaOneDeviceHealthRecord>),
    OsPatches(Vec<NinjaOnePatchRecord>),
    SoftwarePatches(Vec<NinjaOnePatchRecord>),
    DeviceActivities(Vec<NinjaOneDeviceActivityRecord>),
}

impl NinjaOnePayload {
    pub(crate) fn endpoint(&self) -> NinjaOneEndpoint {
        match self {
            Self::Organizations(_) => NinjaOneEndpoint::Organizations,
            Self::Devices(_) => NinjaOneEndpoint::Devices,
            Self::DeviceAlerts(_) => NinjaOneEndpoint::DeviceAlerts,
            Self::DeviceHealth(_) => NinjaOneEndpoint::DeviceHealth,
            Self::OsPatches(_) => NinjaOneEndpoint::DeviceOsPatches,
            Self::SoftwarePatches(_) => NinjaOneEndpoint::DeviceSoftwarePatches,
            Self::DeviceActivities(_) => NinjaOneEndpoint::DeviceActivities,
        }
    }

    fn item_count(&self) -> usize {
        match self {
            Self::Organizations(items) => items.len(),
            Self::Devices(items) => items.len(),
            Self::DeviceAlerts(items) => items.len(),
            Self::DeviceHealth(items) => items.len(),
            Self::OsPatches(items) | Self::SoftwarePatches(items) => items.len(),
            Self::DeviceActivities(items) => items.len(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneResponse {
    status: u16,
    response_bytes: usize,
    response_digest: Digest,
    payload: Option<NinjaOnePayload>,
    next_after: Option<u64>,
}

impl NinjaOneResponse {
    pub fn success(
        endpoint: NinjaOneEndpoint,
        payload: NinjaOnePayload,
        response_bytes: usize,
        next_after: Option<u64>,
    ) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES || payload.endpoint() != endpoint {
            return Err(if response_bytes > MAX_RESPONSE_BYTES {
                NinjaOneError::ResponseTooLarge
            } else {
                NinjaOneError::MalformedPayload
            });
        }
        if payload.item_count() > MAX_PAGE_SIZE {
            return Err(NinjaOneError::BoundExceeded {
                kind: "provider response page",
            });
        }
        Ok(Self {
            status: 200,
            response_bytes,
            response_digest: Digest::from_serializable(&payload),
            payload: Some(payload),
            next_after,
        })
    }

    pub fn failure(status: u16, response_bytes: usize) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(NinjaOneError::ResponseTooLarge);
        }
        Ok(Self {
            status,
            response_bytes,
            response_digest: Digest::from_serializable(&(status, response_bytes)),
            payload: None,
            next_after: None,
        })
    }

    pub fn from_json(
        endpoint: NinjaOneEndpoint,
        body: &[u8],
        next_after: Option<u64>,
    ) -> std::result::Result<Self, NinjaOneTransportError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(NinjaOneTransportError::ResponseTooLarge);
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| NinjaOneTransportError::Malformed)?;
        let payload =
            parse_payload(endpoint, &value).map_err(|_| NinjaOneTransportError::Malformed)?;
        if payload.item_count() > MAX_PAGE_SIZE {
            return Err(NinjaOneTransportError::BoundExceeded);
        }
        Ok(Self {
            status: 200,
            response_bytes: body.len(),
            response_digest: Digest::from_bytes(body),
            payload: Some(payload),
            next_after,
        })
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn payload(&self) -> Option<&NinjaOnePayload> {
        self.payload.as_ref()
    }

    pub const fn next_after(&self) -> Option<u64> {
        self.next_after
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NinjaOneTransportError {
    #[error("unauthorized")]
    Unauthorized401,
    #[error("forbidden")]
    Forbidden403,
    #[error("not found")]
    NotFound404,
    #[error("conflict")]
    Conflict409,
    #[error("rate limited")]
    RateLimited429 { retry_after_seconds: Option<u32> },
    #[error("server failure")]
    Server5xx { status: u16 },
    #[error("timeout")]
    Timeout,
    #[error("blocked environment")]
    BlockedEnv,
    #[error("recording has no matching response")]
    MissingRecording,
    #[error("recording endpoint did not match request")]
    UnexpectedEndpoint,
    #[error("response is malformed")]
    Malformed,
    #[error("response exceeds byte bound")]
    ResponseTooLarge,
    #[error("response page exceeds item bound")]
    BoundExceeded,
    #[error("pagination cursor repeated")]
    PaginationLoop,
}

impl NinjaOneTransportError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized401 => "unauthorized",
            Self::Forbidden403 => "forbidden",
            Self::NotFound404 => "not_found",
            Self::Conflict409 => "conflict",
            Self::RateLimited429 { .. } => "rate_limited",
            Self::Server5xx { .. } => "server_failure",
            Self::Timeout => "timeout",
            Self::BlockedEnv => "blocked_env",
            Self::MissingRecording => "missing_recording",
            Self::UnexpectedEndpoint => "unexpected_endpoint",
            Self::Malformed => "malformed",
            Self::ResponseTooLarge => "response_too_large",
            Self::BoundExceeded => "bound_exceeded",
            Self::PaginationLoop => "pagination_loop",
        }
    }

    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Unauthorized401 => Some(401),
            Self::Forbidden403 => Some(403),
            Self::NotFound404 => Some(404),
            Self::Conflict409 => Some(409),
            Self::RateLimited429 { .. } => Some(429),
            Self::Server5xx { status } => Some(*status),
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited429 { .. }
                | Self::Server5xx { .. }
                | Self::Timeout
                | Self::BlockedEnv
                | Self::MissingRecording
        )
    }
}

pub trait NinjaOneTransport: fmt::Debug {
    fn mode(&self) -> TransportMode;

    fn get(
        &mut self,
        request: &NinjaOneGetRequest,
    ) -> std::result::Result<NinjaOneResponse, NinjaOneTransportError>;
}

/// A deterministic sequence transport for fixture, recording, and loopback
/// modes. It contains only already-normalized payloads.
#[derive(Clone, Debug)]
pub struct NinjaOneSequenceTransport {
    mode: TransportMode,
    responses: VecDeque<(NinjaOneEndpoint, NinjaOneResponse)>,
}

impl NinjaOneSequenceTransport {
    pub fn new(
        mode: TransportMode,
        responses: impl IntoIterator<Item = (NinjaOneEndpoint, NinjaOneResponse)>,
    ) -> Result<Self> {
        if mode == TransportMode::BlockedEnv {
            return Err(NinjaOneError::UnsupportedMode);
        }
        Ok(Self {
            mode,
            responses: responses.into_iter().collect(),
        })
    }

    pub fn recording(
        responses: impl IntoIterator<Item = (NinjaOneEndpoint, NinjaOneResponse)>,
    ) -> Result<Self> {
        Self::new(TransportMode::Recording, responses)
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = (NinjaOneEndpoint, NinjaOneResponse)>,
    ) -> Result<Self> {
        Self::new(TransportMode::Fixture, responses)
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = (NinjaOneEndpoint, NinjaOneResponse)>,
    ) -> Result<Self> {
        Self::new(TransportMode::Loopback, responses)
    }

    pub fn remaining(&self) -> usize {
        self.responses.len()
    }
}

impl NinjaOneTransport for NinjaOneSequenceTransport {
    fn mode(&self) -> TransportMode {
        self.mode
    }

    fn get(
        &mut self,
        request: &NinjaOneGetRequest,
    ) -> std::result::Result<NinjaOneResponse, NinjaOneTransportError> {
        let Some((endpoint, response)) = self.responses.pop_front() else {
            return Err(NinjaOneTransportError::MissingRecording);
        };
        if endpoint != request.endpoint() {
            return Err(NinjaOneTransportError::UnexpectedEndpoint);
        }
        if response.response_bytes() > MAX_RESPONSE_BYTES {
            return Err(NinjaOneTransportError::ResponseTooLarge);
        }
        Ok(response)
    }
}

pub type RecordingNinjaOneTransport = NinjaOneSequenceTransport;
pub type FixtureNinjaOneTransport = NinjaOneSequenceTransport;
pub type LoopbackNinjaOneTransport = NinjaOneSequenceTransport;

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvNinjaOneTransport;

impl NinjaOneTransport for BlockedEnvNinjaOneTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::BlockedEnv
    }

    fn get(
        &mut self,
        _request: &NinjaOneGetRequest,
    ) -> std::result::Result<NinjaOneResponse, NinjaOneTransportError> {
        Err(NinjaOneTransportError::BlockedEnv)
    }
}

/// A safe receipt constructor kept private to the provider boundary.
pub(crate) fn receipt_for(
    request: &NinjaOneGetRequest,
    response: &NinjaOneResponse,
) -> NinjaOneRedactedReceipt {
    NinjaOneRedactedReceipt {
        endpoint: request.endpoint().route().to_owned(),
        method: "GET".to_owned(),
        status: response.status(),
        response_bytes: response.response_bytes(),
        request_digest: request.request_digest().clone(),
        response_digest: response.response_digest().clone(),
        scope_digest: request.scope_digest().clone(),
        secret_reference_digest: request.secret_reference_digest().clone(),
        redacted_headers: vec!["Authorization".to_owned(), "Cookie".to_owned()],
    }
}

fn parse_payload(endpoint: NinjaOneEndpoint, value: &Value) -> Result<NinjaOnePayload> {
    match endpoint {
        NinjaOneEndpoint::Organizations => {
            let records = as_array(value)?
                .iter()
                .map(parse_organization)
                .collect::<Result<Vec<_>>>()?;
            Ok(NinjaOnePayload::Organizations(records))
        }
        NinjaOneEndpoint::Devices => {
            let records = as_array(value)?
                .iter()
                .map(parse_device)
                .collect::<Result<Vec<_>>>()?;
            Ok(NinjaOnePayload::Devices(records))
        }
        NinjaOneEndpoint::DeviceAlerts => {
            let records = as_array(value)?
                .iter()
                .map(parse_alert)
                .collect::<Result<Vec<_>>>()?;
            Ok(NinjaOnePayload::DeviceAlerts(records))
        }
        NinjaOneEndpoint::DeviceHealth => {
            let records = value
                .get("results")
                .and_then(Value::as_array)
                .or_else(|| value.as_array())
                .ok_or(NinjaOneError::MalformedPayload)?
                .iter()
                .map(parse_health)
                .collect::<Result<Vec<_>>>()?;
            Ok(NinjaOnePayload::DeviceHealth(records))
        }
        NinjaOneEndpoint::DeviceOsPatches => {
            let records = as_array(value)?
                .iter()
                .map(|item| parse_patch(item, PatchStatus::Unknown))
                .collect::<Result<Vec<_>>>()?;
            Ok(NinjaOnePayload::OsPatches(records))
        }
        NinjaOneEndpoint::DeviceSoftwarePatches => {
            let records = as_array(value)?
                .iter()
                .map(|item| parse_patch(item, PatchStatus::Unknown))
                .collect::<Result<Vec<_>>>()?;
            Ok(NinjaOnePayload::SoftwarePatches(records))
        }
        NinjaOneEndpoint::DeviceActivities => {
            let records = value
                .get("activities")
                .and_then(Value::as_array)
                .ok_or(NinjaOneError::MalformedPayload)?
                .iter()
                .map(parse_activity)
                .collect::<Result<Vec<_>>>()?;
            Ok(NinjaOnePayload::DeviceActivities(records))
        }
    }
}

fn as_array(value: &Value) -> Result<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(NinjaOneError::MalformedPayload)
}

fn string_field(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .or_else(|| item.as_u64().map(|number| number.to_string()))
        })
        .ok_or(NinjaOneError::MalformedPayload)
}

fn optional_string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(|item| {
        item.as_str()
            .map(ToOwned::to_owned)
            .or_else(|| item.as_u64().map(|number| number.to_string()))
    })
}

fn bool_field(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn number_field(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(|item| {
        item.as_u64().or_else(|| {
            item.as_f64().and_then(|number| {
                if number.is_finite() && number >= 0.0 {
                    Some(number as u64)
                } else {
                    None
                }
            })
        })
    })
}

fn revision_field(value: &Value, fallback: u64) -> Result<u64> {
    number_field(value, "revision")
        .or_else(|| number_field(value, "lastUpdate"))
        .or_else(|| number_field(value, "updateTime"))
        .or_else(|| number_field(value, "updatedOn"))
        .or_else(|| number_field(value, "id"))
        .filter(|revision| *revision > 0)
        .or(Some(fallback))
        .ok_or(NinjaOneError::InvalidRevision)
}

fn parse_organization(value: &Value) -> Result<NinjaOneOrganizationRecord> {
    let organization_id = string_field(value, "id")?;
    let site_ids = value
        .get("locations")
        .and_then(Value::as_array)
        .map(|locations| {
            locations
                .iter()
                .filter_map(|location| string_field(location, "id").ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    NinjaOneOrganizationRecord::new(
        organization_id,
        site_ids,
        revision_field(value, 1)?,
        b"redacted-organization-metadata",
    )
}

fn parse_device(value: &Value) -> Result<NinjaOneDeviceRecord> {
    let device_id = string_field(value, "id")?;
    let agent_id =
        optional_string_field(value, "uid").unwrap_or_else(|| format!("agent-{device_id}"));
    NinjaOneDeviceRecord::new(
        string_field(value, "organizationId")?,
        string_field(value, "locationId").unwrap_or_else(|_| "site-unknown".to_owned()),
        device_id,
        agent_id,
        bool_field(value, "offline"),
        number_field(value, "lastContact"),
        revision_field(value, 1)?,
        b"redacted-device-metadata",
    )
}

fn parse_alert(value: &Value) -> Result<NinjaOneDeviceAlertRecord> {
    let alert_body = optional_string_field(value, "message");
    NinjaOneDeviceAlertRecord::new(
        string_field(value, "uid").or_else(|_| string_field(value, "id"))?,
        string_field(value, "deviceId")?,
        &string_field(value, "sourceType").unwrap_or_else(|_| "UNKNOWN".to_owned()),
        number_field(value, "createTime"),
        number_field(value, "updateTime"),
        revision_field(value, 1)?,
        alert_body.as_deref(),
    )
}

fn parse_health(value: &Value) -> Result<NinjaOneDeviceHealthRecord> {
    let device_id = string_field(value, "deviceId")?;
    let pending_os = number_field(value, "pendingOSPatches").unwrap_or(0) as usize;
    let failed_os = number_field(value, "failedOSPatches").unwrap_or(0) as usize;
    let pending_software = number_field(value, "pendingSoftwarePatches").unwrap_or(0) as usize;
    let failed_software = number_field(value, "failedSoftwarePatches").unwrap_or(0) as usize;
    NinjaOneDeviceHealthRecord::new(
        device_id,
        value
            .get("healthStatus")
            .and_then(Value::as_str)
            .map_or(HealthStatus::Unknown, HealthStatus::parse),
        bool_field(value, "offline"),
        number_field(value, "alertCount").unwrap_or(0) as usize,
        pending_os,
        failed_os,
        pending_software,
        failed_software,
        number_field(value, "observedAt"),
        revision_field(value, 1)?,
        b"redacted-health-metadata",
    )
}

fn parse_patch(value: &Value, default_status: PatchStatus) -> Result<NinjaOnePatchRecord> {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map_or(default_status, PatchStatus::parse);
    NinjaOnePatchRecord::new(
        string_field(value, "id")?,
        optional_string_field(value, "deviceId").unwrap_or_else(|| "scoped-device".to_owned()),
        status,
        number_field(value, "installedAt"),
        revision_field(value, 1)?,
        b"redacted-patch-metadata",
    )
}

fn parse_activity(value: &Value) -> Result<NinjaOneDeviceActivityRecord> {
    let activity_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    NinjaOneDeviceActivityRecord::new(
        string_field(value, "id")?,
        string_field(value, "deviceId")?,
        activity_type,
        value
            .get("severity")
            .and_then(Value::as_str)
            .map_or(ActivitySeverity::Unknown, ActivitySeverity::parse),
        value
            .get("activityResult")
            .and_then(Value::as_str)
            .map_or(ActivityResult::Unknown, ActivityResult::parse),
        number_field(value, "activityTime"),
        revision_field(value, 1)?,
    )
}

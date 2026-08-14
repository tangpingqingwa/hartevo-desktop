//! Deterministic provider transport seams.
//!
//! There is intentionally no HTTPS client or credential resolver in this
//! crate.  Recording and fake transports make provider behavior testable;
//! `BlockedEnvTransport` makes the native environment gap explicit.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AccountId, ApiRegion, Digest, EscalationPolicyId, IncidentIdentity, PagerDutyScope, Provenance,
    RateLimitReceipt, RawIncidentPayload, RawTimelineEntryPayload, ServiceId, TeamId,
    TimelineBounds, canonical_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("native PagerDuty environment is blocked in Layer 1")]
    BlockedEnv,
    #[error("recording transport has no response for the requested operation")]
    MissingRecording,
    #[error("provider transport failed: {0}")]
    Failed(String),
    #[error("provider returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("provider permission scope was rejected")]
    PermissionDenied,
    #[error("provider API region did not match the request")]
    RegionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeRequest {
    pub scope_digest: Digest,
    pub api_region: ApiRegion,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub service_id: ServiceId,
    pub escalation_policy_id: EscalationPolicyId,
}

impl ProbeRequest {
    pub fn from_scope(scope: &PagerDutyScope) -> Self {
        Self {
            scope_digest: scope.digest(),
            api_region: scope.api_region,
            account_id: scope.account_id.clone(),
            team_id: scope.team_id.clone(),
            service_id: scope.service_id.clone(),
            escalation_policy_id: scope.escalation_policy_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IncidentRequest {
    pub scope_digest: Digest,
    pub api_region: ApiRegion,
    pub host: String,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub service_id: ServiceId,
    pub escalation_policy_id: EscalationPolicyId,
    pub incident: IncidentIdentity,
}

impl IncidentRequest {
    pub fn from_scope(scope: &PagerDutyScope) -> Self {
        Self {
            scope_digest: scope.digest(),
            api_region: scope.api_region,
            host: scope.api_region.host().to_owned(),
            account_id: scope.account_id.clone(),
            team_id: scope.team_id.clone(),
            service_id: scope.service_id.clone(),
            escalation_policy_id: scope.escalation_policy_id.clone(),
            incident: scope.incident.clone(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TimelinePageRequest {
    pub scope_digest: Digest,
    pub api_region: ApiRegion,
    pub host: String,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub service_id: ServiceId,
    pub escalation_policy_id: EscalationPolicyId,
    pub incident: IncidentIdentity,
    pub cursor: Option<String>,
    pub bounds: TimelineBounds,
}

impl TimelinePageRequest {
    pub fn new(scope: &PagerDutyScope, cursor: Option<String>, bounds: TimelineBounds) -> Self {
        Self {
            scope_digest: scope.digest(),
            api_region: scope.api_region,
            host: scope.api_region.host().to_owned(),
            account_id: scope.account_id.clone(),
            team_id: scope.team_id.clone(),
            service_id: scope.service_id.clone(),
            escalation_policy_id: scope.escalation_policy_id.clone(),
            incident: scope.incident.clone(),
            cursor,
            bounds,
        }
    }
}

impl fmt::Debug for TimelinePageRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimelinePageRequest")
            .field("scope_digest", &self.scope_digest)
            .field("api_region", &self.api_region)
            .field("host", &self.host)
            .field("account_id", &self.account_id)
            .field("team_id", &self.team_id)
            .field("service_id", &self.service_id)
            .field("escalation_policy_id", &self.escalation_policy_id)
            .field("incident", &self.incident)
            .field("cursor_digest", &self.cursor.as_ref().map(canonical_digest))
            .field("bounds", &self.bounds)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbePayload {
    pub api_region: ApiRegion,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub service_id: ServiceId,
    pub escalation_policy_id: EscalationPolicyId,
    pub provider_revision: u64,
    pub permission_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeResponse {
    pub payload: ProbePayload,
    pub rate_limit: RateLimitReceipt,
}

#[derive(Clone, Eq, PartialEq)]
pub struct IncidentPageResponse {
    pub items: Vec<RawIncidentPayload>,
    pub rate_limit: RateLimitReceipt,
}

impl fmt::Debug for IncidentPageResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentPageResponse")
            .field("item_count", &self.items.len())
            .field("items", &self.items)
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TimelinePageResponse {
    pub items: Vec<RawTimelineEntryPayload>,
    pub next_cursor: Option<String>,
    pub rate_limit: RateLimitReceipt,
}

impl fmt::Debug for TimelinePageResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimelinePageResponse")
            .field("item_count", &self.items.len())
            .field("items", &self.items)
            .field(
                "next_cursor_digest",
                &self.next_cursor.as_ref().map(canonical_digest),
            )
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

pub trait PagerDutyIncidentTransport: Send {
    fn provenance(&self) -> Provenance;

    fn probe(&mut self, request: &ProbeRequest) -> Result<ProbeResponse, TransportError>;

    fn read_incident(
        &mut self,
        request: &IncidentRequest,
    ) -> Result<IncidentPageResponse, TransportError>;

    fn read_timeline_page(
        &mut self,
        request: &TimelinePageRequest,
    ) -> Result<TimelinePageResponse, TransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedRequest {
    Probe,
    Incident,
    Timeline { cursor_digest: Option<Digest> },
}

/// A deterministic transport that records the typed requests it receives.
/// Its response payloads remain non-serializable and all debug rendering of
/// raw content is redacted by the payload types.
#[derive(Default)]
pub struct RecordingTransport {
    probe_response: Option<Result<ProbeResponse, TransportError>>,
    incident_responses: Vec<Result<IncidentPageResponse, TransportError>>,
    timeline_responses: BTreeMap<String, Result<TimelinePageResponse, TransportError>>,
    requests: Vec<RecordedRequest>,
}

impl fmt::Debug for RecordingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingTransport")
            .field("probe_configured", &self.probe_response.is_some())
            .field("incident_response_count", &self.incident_responses.len())
            .field("timeline_response_count", &self.timeline_responses.len())
            .field("requests", &self.requests)
            .finish()
    }
}

impl RecordingTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_probe_response(&mut self, response: Result<ProbeResponse, TransportError>) {
        self.probe_response = Some(response);
    }

    pub fn push_incident_response(
        &mut self,
        response: Result<IncidentPageResponse, TransportError>,
    ) {
        self.incident_responses.push(response);
    }

    pub fn insert_timeline_response(
        &mut self,
        cursor: Option<&str>,
        response: Result<TimelinePageResponse, TransportError>,
    ) {
        self.timeline_responses
            .insert(cursor.unwrap_or_default().to_owned(), response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn take_incident_response(&mut self) -> Result<IncidentPageResponse, TransportError> {
        if self.incident_responses.is_empty() {
            return Err(TransportError::MissingRecording);
        }
        self.incident_responses.remove(0)
    }

    fn take_timeline_response(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<TimelinePageResponse, TransportError> {
        self.timeline_responses
            .remove(cursor.unwrap_or_default())
            .ok_or(TransportError::MissingRecording)?
    }
}

impl PagerDutyIncidentTransport for RecordingTransport {
    fn provenance(&self) -> Provenance {
        Provenance::Recording
    }

    fn probe(&mut self, _request: &ProbeRequest) -> Result<ProbeResponse, TransportError> {
        self.requests.push(RecordedRequest::Probe);
        self.probe_response
            .take()
            .ok_or(TransportError::MissingRecording)?
    }

    fn read_incident(
        &mut self,
        _request: &IncidentRequest,
    ) -> Result<IncidentPageResponse, TransportError> {
        self.requests.push(RecordedRequest::Incident);
        self.take_incident_response()
    }

    fn read_timeline_page(
        &mut self,
        request: &TimelinePageRequest,
    ) -> Result<TimelinePageResponse, TransportError> {
        self.requests.push(RecordedRequest::Timeline {
            cursor_digest: request.cursor.as_ref().map(canonical_digest),
        });
        self.take_timeline_response(request.cursor.as_deref())
    }
}

/// A fake transport is a recording transport with fixture provenance.  The
/// separate type keeps fixture provenance from being confused with a native
/// first-party connection.
#[derive(Default)]
pub struct FakeTransport {
    inner: RecordingTransport,
}

impl fmt::Debug for FakeTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FakeTransport")
            .field(&self.inner)
            .finish()
    }
}

impl FakeTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_probe_response(&mut self, response: Result<ProbeResponse, TransportError>) {
        self.inner.set_probe_response(response);
    }

    pub fn push_incident_response(
        &mut self,
        response: Result<IncidentPageResponse, TransportError>,
    ) {
        self.inner.push_incident_response(response);
    }

    pub fn insert_timeline_response(
        &mut self,
        cursor: Option<&str>,
        response: Result<TimelinePageResponse, TransportError>,
    ) {
        self.inner.insert_timeline_response(cursor, response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl PagerDutyIncidentTransport for FakeTransport {
    fn provenance(&self) -> Provenance {
        Provenance::Fake
    }

    fn probe(&mut self, request: &ProbeRequest) -> Result<ProbeResponse, TransportError> {
        self.inner.probe(request)
    }

    fn read_incident(
        &mut self,
        request: &IncidentRequest,
    ) -> Result<IncidentPageResponse, TransportError> {
        self.inner.read_incident(request)
    }

    fn read_timeline_page(
        &mut self,
        request: &TimelinePageRequest,
    ) -> Result<TimelinePageResponse, TransportError> {
        self.inner.read_timeline_page(request)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl PagerDutyIncidentTransport for BlockedEnvTransport {
    fn provenance(&self) -> Provenance {
        Provenance::BlockedEnv
    }

    fn probe(&mut self, _request: &ProbeRequest) -> Result<ProbeResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn read_incident(
        &mut self,
        _request: &IncidentRequest,
    ) -> Result<IncidentPageResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn read_timeline_page(
        &mut self,
        _request: &TimelinePageRequest,
    ) -> Result<TimelinePageResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeReceipt {
    pub scope_digest: Digest,
    pub provider_revision: u64,
    pub rate_limit: RateLimitReceipt,
    pub provenance: Provenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

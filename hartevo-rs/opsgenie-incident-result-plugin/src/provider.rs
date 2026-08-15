//! Opsgenie provider definition and deterministic non-native transports.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Digest, MAX_ALERTS, MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES, MAX_TIMELINE_ITEMS,
    MAX_TIMELINE_PAGES, ModelError, OpsgenieAlertId, OpsgenieAlertObservation, OpsgenieAlertStatus,
    OpsgenieEscalationId, OpsgenieEscalationObservation, OpsgenieIncidentId,
    OpsgenieIncidentObservation, OpsgenieIncidentResult, OpsgenieIncidentResultRegistration,
    OpsgenieIncidentResultScope, OpsgenieIncidentStatus, OpsgeniePermission,
    OpsgenieRateLimitReceipt, OpsgenieReadSeam, OpsgenieRegion, OpsgenieRequestReceipt,
    OpsgenieScheduleId, OpsgenieScheduleObservation, OpsgenieTeamId, OpsgenieTimelineKind,
    OpsgenieTimelineObservation, Revision, SecretReference, TransportProvenance, canonical_digest,
    sha256_digest,
};

pub const OPSGENIE_API_REVISION: &str =
    "opsgenie-api-v2-alert-incident-schedule-escalation-timeline-1";
pub const GET_ALERT_PATH: &str = "/v2/alerts/{alertId}";
pub const GET_ALERT_TIMELINE_PATH: &str = "/v2/alerts/{alertId}/timeline";
pub const GET_INCIDENT_PATH: &str = "/v1/incidents/{incidentId}";
pub const GET_SCHEDULE_PATH: &str = "/v2/schedules/{scheduleId}";
pub const GET_ESCALATION_PATH: &str = "/v2/escalations/{escalationId}";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieRequest {
    pub method: crate::OpsgenieHttpMethod,
    pub region: OpsgenieRegion,
    pub seam: OpsgenieReadSeam,
    pub host: String,
    pub path: String,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub team_digest: Digest,
    pub service_digest: Digest,
    pub alert_digest: Digest,
    pub alias_digest: Digest,
    pub incident_digest: Digest,
    pub schedule_digest: Digest,
    pub escalation_digest: Digest,
    pub timeline_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl OpsgenieRequest {
    pub fn for_seam(
        scope: &OpsgenieIncidentResultScope,
        seam: OpsgenieReadSeam,
        page: usize,
    ) -> Self {
        let identifier = match seam {
            OpsgenieReadSeam::Alert | OpsgenieReadSeam::AlertTimeline => scope.alert().as_str(),
            OpsgenieReadSeam::Incident => scope.incident().as_str(),
            OpsgenieReadSeam::Schedule => scope.schedule().as_str(),
            OpsgenieReadSeam::Escalation => scope.escalation().as_str(),
        };
        let path = match seam {
            OpsgenieReadSeam::Alert => format!("/v2/alerts/{identifier}"),
            OpsgenieReadSeam::AlertTimeline => {
                format!("/v2/alerts/{identifier}/timeline?page={page}")
            }
            OpsgenieReadSeam::Incident => format!("/v1/incidents/{identifier}"),
            OpsgenieReadSeam::Schedule => format!("/v2/schedules/{identifier}"),
            OpsgenieReadSeam::Escalation => format!("/v2/escalations/{identifier}"),
        };
        let mut request = Self {
            method: crate::OpsgenieHttpMethod::Get,
            region: scope.region(),
            seam,
            host: scope.region().host().to_owned(),
            path,
            scope_digest: scope.digest(),
            account_digest: scope.account().digest(),
            team_digest: scope.team().digest(),
            service_digest: scope.service().digest(),
            alert_digest: scope.alert().digest(),
            alias_digest: scope.alias().digest(),
            incident_digest: scope.incident().digest(),
            schedule_digest: scope.schedule().digest(),
            escalation_digest: scope.escalation().digest(),
            timeline_digest: scope.timeline().digest(),
            consent_digest: scope.consent().digest().clone(),
            secret_reference_digest: Digest::from_text("unbound-secret-reference"),
            request_digest: Digest::from_text("unsealed-opsgenie-request"),
        };
        request.request_digest = canonical_digest(&serde_json::json!({
            "method": request.method,
            "region": request.region,
            "seam": request.seam,
            "host": &request.host,
            "path": &request.path,
            "scopeDigest": &request.scope_digest,
            "accountDigest": &request.account_digest,
            "teamDigest": &request.team_digest,
            "serviceDigest": &request.service_digest,
            "alertDigest": &request.alert_digest,
            "aliasDigest": &request.alias_digest,
            "incidentDigest": &request.incident_digest,
            "scheduleDigest": &request.schedule_digest,
            "escalationDigest": &request.escalation_digest,
            "timelineDigest": &request.timeline_digest,
            "consentDigest": &request.consent_digest,
        }));
        request
    }

    pub fn bind_secret(mut self, secret_reference: &SecretReference) -> Self {
        self.secret_reference_digest = secret_reference.digest();
        self.request_digest = canonical_digest(&serde_json::json!({
            "method": self.method,
            "region": self.region,
            "seam": self.seam,
            "host": &self.host,
            "path": &self.path,
            "scopeDigest": &self.scope_digest,
            "accountDigest": &self.account_digest,
            "teamDigest": &self.team_digest,
            "serviceDigest": &self.service_digest,
            "alertDigest": &self.alert_digest,
            "aliasDigest": &self.alias_digest,
            "incidentDigest": &self.incident_digest,
            "scheduleDigest": &self.schedule_digest,
            "escalationDigest": &self.escalation_digest,
            "timelineDigest": &self.timeline_digest,
            "consentDigest": &self.consent_digest,
            "secretReferenceDigest": &self.secret_reference_digest,
        }));
        self
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == crate::OpsgenieHttpMethod::Get
            && self.host == self.region.host()
            && match self.seam {
                OpsgenieReadSeam::Alert => {
                    self.path.starts_with("/v2/alerts/") && !self.path.contains("/timeline")
                }
                OpsgenieReadSeam::AlertTimeline => {
                    self.path.starts_with("/v2/alerts/") && self.path.contains("/timeline")
                }
                OpsgenieReadSeam::Incident => self.path.starts_with("/v1/incidents/"),
                OpsgenieReadSeam::Schedule => self.path.starts_with("/v2/schedules/"),
                OpsgenieReadSeam::Escalation => self.path.starts_with("/v2/escalations/"),
            }
    }

    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("{}{}", self.host, self.path)
    }
}

/// A private-body response envelope. Fixture JSON can be supplied to tests,
/// but the bytes are exposed only as a digest and bounded byte count.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub rate_limit: OpsgenieRateLimitReceipt,
}

impl fmt::Debug for OpsgenieResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpsgenieResponse")
            .field("status", &self.status)
            .field("body_digest", &self.response_digest())
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl OpsgenieResponse {
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, OpsgenieRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: OpsgenieRateLimitReceipt,
    ) -> Self {
        Self {
            status,
            body: serde_json::to_vec(value).expect("Opsgenie fixture payload serializes"),
            rate_limit,
        }
    }

    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: OpsgenieRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        sha256_digest(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    fn value(&self) -> std::result::Result<Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OpsgenieTransportError {
    #[error("Opsgenie native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Opsgenie transport timed out")]
    Timeout,
    #[error("Opsgenie transport failed without a native response")]
    ProviderUnknown,
}

/// Layer-1 transport seam. Implementations only replay bounded envelopes;
/// this crate supplies no native HTTPS or credential resolver.
pub trait OpsgenieTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn execute(
        &mut self,
        request: &OpsgenieRequest,
    ) -> Result<OpsgenieResponse, OpsgenieTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureOpsgenieTransport {
    default_response: OpsgenieResponse,
    responses: BTreeMap<OpsgenieReadSeam, VecDeque<OpsgenieResponse>>,
}

impl FixtureOpsgenieTransport {
    #[must_use]
    pub fn new(response: OpsgenieResponse) -> Self {
        Self {
            default_response: response,
            responses: BTreeMap::new(),
        }
    }

    pub fn push_response(&mut self, seam: OpsgenieReadSeam, response: OpsgenieResponse) {
        self.responses.entry(seam).or_default().push_back(response);
    }
}

impl OpsgenieTransport for FixtureOpsgenieTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &OpsgenieRequest,
    ) -> Result<OpsgenieResponse, OpsgenieTransportError> {
        Ok(self
            .responses
            .get_mut(&request.seam)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| self.default_response.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct RecordingOpsgenieTransport {
    default_response: OpsgenieResponse,
    responses: BTreeMap<OpsgenieReadSeam, VecDeque<OpsgenieResponse>>,
    requests: Vec<OpsgenieRequest>,
}

impl RecordingOpsgenieTransport {
    #[must_use]
    pub fn new(response: OpsgenieResponse) -> Self {
        Self {
            default_response: response,
            responses: BTreeMap::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, seam: OpsgenieReadSeam, response: OpsgenieResponse) {
        self.responses.entry(seam).or_default().push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[OpsgenieRequest] {
        &self.requests
    }
}

impl OpsgenieTransport for RecordingOpsgenieTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &OpsgenieRequest,
    ) -> Result<OpsgenieResponse, OpsgenieTransportError> {
        self.requests.push(request.clone());
        Ok(self
            .responses
            .get_mut(&request.seam)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| self.default_response.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackOpsgenieTransport {
    response: OpsgenieResponse,
    requests: Vec<OpsgenieRequest>,
}

impl LoopbackOpsgenieTransport {
    #[must_use]
    pub fn new(response: OpsgenieResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[OpsgenieRequest] {
        &self.requests
    }
}

impl OpsgenieTransport for LoopbackOpsgenieTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &OpsgenieRequest,
    ) -> Result<OpsgenieResponse, OpsgenieTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvOpsgenieTransport;

impl OpsgenieTransport for BlockedEnvOpsgenieTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &OpsgenieRequest,
    ) -> Result<OpsgenieResponse, OpsgenieTransportError> {
        Err(OpsgenieTransportError::BlockedEnv)
    }
}

pub type FixtureTransport = FixtureOpsgenieTransport;
pub type RecordingTransport = RecordingOpsgenieTransport;
pub type LoopbackTransport = LoopbackOpsgenieTransport;
pub type BlockedEnvTransport = BlockedEnvOpsgenieTransport;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsgenieProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub region: OpsgenieRegion,
    pub allowlisted_seams: Vec<OpsgenieReadSeam>,
    pub provenance: TransportProvenance,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: usize,
    pub max_timeline_pages: usize,
    pub max_timeline_items: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub provider_digest: Digest,
}

impl OpsgenieProviderDefinition {
    #[must_use]
    pub fn layer1(region: OpsgenieRegion, provenance: TransportProvenance) -> Self {
        let mut definition = Self {
            provider_id: crate::OPSGENIE_PROVIDER_ID.to_owned(),
            provider_version: crate::OPSGENIE_PROVIDER_VERSION.to_owned(),
            api_revision: OPSGENIE_API_REVISION.to_owned(),
            region,
            allowlisted_seams: vec![
                OpsgenieReadSeam::Alert,
                OpsgenieReadSeam::AlertTimeline,
                OpsgenieReadSeam::Incident,
                OpsgenieReadSeam::Schedule,
                OpsgenieReadSeam::Escalation,
            ],
            provenance,
            max_requests_per_minute: MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_timeline_pages: MAX_TIMELINE_PAGES,
            max_timeline_items: MAX_TIMELINE_ITEMS,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            first_party: false,
            provider_receipt: false,
            provider_digest: Digest::from_text("unsealed-opsgenie-provider"),
        };
        definition.provider_digest = canonical_digest(&serde_json::json!({
            "domain": "hartevo-opsgenie-provider/v1",
            "providerId": &definition.provider_id,
            "providerVersion": &definition.provider_version,
            "apiRevision": &definition.api_revision,
            "region": definition.region,
            "allowlistedSeams": &definition.allowlisted_seams,
            "provenance": definition.provenance,
            "maxRequestsPerMinute": definition.max_requests_per_minute,
            "maxResponseBytes": definition.max_response_bytes,
            "maxTimelinePages": definition.max_timeline_pages,
            "maxTimelineItems": definition.max_timeline_items,
            "readOnly": definition.read_only,
            "liveExecution": definition.live_execution,
            "native": definition.native,
            "connected": definition.connected,
            "firstParty": definition.first_party,
            "providerReceipt": definition.provider_receipt,
        }));
        definition
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::layer1(self.region, self.provenance);
        if self != &expected {
            Err(ModelError::InvalidScope("provider definition drift"))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.provider_digest.clone()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OpsgenieProviderError {
    #[error("Opsgenie registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Opsgenie SecretReference is revoked")]
    SecretRevoked,
    #[error("Opsgenie permission snapshot is missing a required read permission")]
    MissingPermission,
    #[error("Opsgenie request is outside the exact scope")]
    ScopeMismatch,
    #[error("Opsgenie response was rate limited")]
    RateLimited {
        request: OpsgenieRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: OpsgenieRateLimitReceipt,
    },
    #[error("Opsgenie provider returned HTTP status {status}")]
    HttpStatus {
        request: OpsgenieRequest,
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: OpsgenieRateLimitReceipt,
    },
    #[error("Opsgenie response exceeded the Layer-1 response bound")]
    ResponseTooLarge {
        request: OpsgenieRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: OpsgenieRateLimitReceipt,
    },
    #[error("Opsgenie response was malformed or outside the bounded projection")]
    MalformedResponse {
        request: OpsgenieRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: OpsgenieRateLimitReceipt,
    },
    #[error("Opsgenie timeline contains duplicate or unbounded entries")]
    InvalidTimeline,
    #[error("Opsgenie rate-limit receipt is invalid")]
    InvalidRateLimitReceipt,
    #[error("Opsgenie transport failed")]
    Transport {
        request: OpsgenieRequest,
        error: OpsgenieTransportError,
    },
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug)]
pub struct OpsgenieProviderRead {
    pub result: OpsgenieIncidentResult,
    pub request_receipts: Vec<OpsgenieRequestReceipt>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: OpsgenieRateLimitReceipt,
    pub provenance: TransportProvenance,
    pub timeline_complete: bool,
}

pub type OpsgenieIncidentResultProviderRead = OpsgenieProviderRead;

pub struct OpsgenieProvider<T: OpsgenieTransport> {
    scope: OpsgenieIncidentResultScope,
    secret_reference: SecretReference,
    definition: OpsgenieProviderDefinition,
    registration: OpsgenieIncidentResultRegistration,
    transport: T,
}

impl<T: OpsgenieTransport> fmt::Debug for OpsgenieProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpsgenieProvider")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: OpsgenieTransport> OpsgenieProvider<T> {
    pub fn new(
        scope: OpsgenieIncidentResultScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, OpsgenieProviderError> {
        scope.validate()?;
        ensure_permissions(&scope)?;
        let definition = OpsgenieProviderDefinition::layer1(scope.region(), transport.provenance());
        definition.validate()?;
        let registration = OpsgenieIncidentResultRegistration::bind(
            &scope,
            &secret_reference,
            definition.digest(),
        );
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
        })
    }

    pub fn with_registration(
        scope: OpsgenieIncidentResultScope,
        secret_reference: SecretReference,
        transport: T,
        registration: OpsgenieIncidentResultRegistration,
    ) -> Result<Self, OpsgenieProviderError> {
        scope.validate()?;
        ensure_permissions(&scope)?;
        let definition = OpsgenieProviderDefinition::layer1(scope.region(), transport.provenance());
        definition.validate()?;
        registration
            .validate(&scope, &secret_reference, &definition.digest())
            .map_err(|_| OpsgenieProviderError::RegistrationRevoked)?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &OpsgenieIncidentResultScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &OpsgenieProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    #[must_use]
    pub fn registration(&self) -> &OpsgenieIncidentResultRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self) -> Result<OpsgenieProviderRead, OpsgenieProviderError> {
        self.ensure_ready()?;
        let mut receipts = Vec::new();
        let mut response_digests = Vec::new();
        let mut response_bytes = 0_usize;
        let mut rate_limit = OpsgenieRateLimitReceipt::default();
        let alert_response = self.execute(
            OpsgenieReadSeam::Alert,
            1,
            &mut receipts,
            &mut response_digests,
            &mut response_bytes,
            &mut rate_limit,
        )?;
        let alert = self.parse_alert(&alert_response)?;
        let mut timeline_values = Vec::new();
        let mut timeline_complete = true;
        let mut timeline_page_count = 0_usize;
        let mut timeline_ids = BTreeSet::new();
        for page in 1..=MAX_TIMELINE_PAGES {
            let response = self.execute(
                OpsgenieReadSeam::AlertTimeline,
                page,
                &mut receipts,
                &mut response_digests,
                &mut response_bytes,
                &mut rate_limit,
            )?;
            let value = response.value().map_err(|_| self.malformed(&response))?;
            let (entries, has_more) = parse_timeline_page(&value, &self.scope, &response)?;
            timeline_page_count += 1;
            if entries
                .iter()
                .any(|(id, _, _)| !timeline_ids.insert(id.clone()))
            {
                return Err(OpsgenieProviderError::InvalidTimeline);
            }
            timeline_values.extend(entries);
            if timeline_values.len() > MAX_TIMELINE_ITEMS {
                return Err(OpsgenieProviderError::InvalidTimeline);
            }
            if !has_more {
                break;
            }
            if page == MAX_TIMELINE_PAGES {
                timeline_complete = false;
            }
        }
        let timeline = make_timeline_observation(
            &self.scope,
            timeline_values,
            timeline_page_count,
            timeline_complete,
            &response_digests,
        );
        let incident_response = self.execute(
            OpsgenieReadSeam::Incident,
            1,
            &mut receipts,
            &mut response_digests,
            &mut response_bytes,
            &mut rate_limit,
        )?;
        let incident = self.parse_incident(&incident_response)?;
        let schedule_response = self.execute(
            OpsgenieReadSeam::Schedule,
            1,
            &mut receipts,
            &mut response_digests,
            &mut response_bytes,
            &mut rate_limit,
        )?;
        let schedule = self.parse_schedule(&schedule_response)?;
        let escalation_response = self.execute(
            OpsgenieReadSeam::Escalation,
            1,
            &mut receipts,
            &mut response_digests,
            &mut response_bytes,
            &mut rate_limit,
        )?;
        let escalation = self.parse_escalation(&escalation_response)?;
        Ok(OpsgenieProviderRead {
            result: OpsgenieIncidentResult {
                alert: Some(alert),
                timeline: Some(timeline),
                incident: Some(incident),
                schedule: Some(schedule),
                escalation: Some(escalation),
            },
            request_receipts: receipts,
            response_digest: canonical_digest(&response_digests),
            response_bytes,
            rate_limit,
            provenance: self.transport.provenance(),
            timeline_complete,
        })
    }

    pub fn read_alert(&mut self) -> Result<OpsgenieAlertObservation, OpsgenieProviderError> {
        Ok(self.read()?.result.alert.expect("alert read is present"))
    }

    pub fn read_alert_timeline(
        &mut self,
    ) -> Result<OpsgenieTimelineObservation, OpsgenieProviderError> {
        Ok(self
            .read()?
            .result
            .timeline
            .expect("timeline read is present"))
    }

    pub fn read_incident(&mut self) -> Result<OpsgenieIncidentObservation, OpsgenieProviderError> {
        Ok(self
            .read()?
            .result
            .incident
            .expect("incident read is present"))
    }

    pub fn read_schedule(&mut self) -> Result<OpsgenieScheduleObservation, OpsgenieProviderError> {
        Ok(self
            .read()?
            .result
            .schedule
            .expect("schedule read is present"))
    }

    pub fn read_escalation(
        &mut self,
    ) -> Result<OpsgenieEscalationObservation, OpsgenieProviderError> {
        Ok(self
            .read()?
            .result
            .escalation
            .expect("escalation read is present"))
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, OpsgenieProviderError> {
        self.registration.revoke().map_err(Into::into)
    }

    pub fn restore(&mut self) -> Result<(), OpsgenieProviderError> {
        self.registration.restore().map_err(Into::into)
    }

    pub fn revoke_secret(&mut self) -> Result<(), OpsgenieProviderError> {
        self.secret_reference.revoke().map_err(Into::into)
    }

    pub fn restore_secret(&mut self) -> Result<(), OpsgenieProviderError> {
        self.secret_reference.restore().map_err(Into::into)
    }

    fn ensure_ready(&self) -> Result<(), OpsgenieProviderError> {
        if !self.registration.is_active() {
            return Err(OpsgenieProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(OpsgenieProviderError::SecretRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                &self.definition.digest(),
            )
            .map_err(|_| OpsgenieProviderError::RegistrationRevoked)
    }

    fn execute(
        &mut self,
        seam: OpsgenieReadSeam,
        page: usize,
        receipts: &mut Vec<OpsgenieRequestReceipt>,
        response_digests: &mut Vec<Digest>,
        response_bytes: &mut usize,
        rate_limit: &mut OpsgenieRateLimitReceipt,
    ) -> Result<OpsgenieResponse, OpsgenieProviderError> {
        let request =
            OpsgenieRequest::for_seam(&self.scope, seam, page).bind_secret(&self.secret_reference);
        if !request.is_allowlisted() {
            return Err(OpsgenieProviderError::ScopeMismatch);
        }
        let response =
            self.transport
                .execute(&request)
                .map_err(|error| OpsgenieProviderError::Transport {
                    request: request.clone(),
                    error,
                })?;
        response
            .rate_limit
            .validate()
            .map_err(|_| OpsgenieProviderError::InvalidRateLimitReceipt)?;
        let response_digest = response.response_digest();
        if response.response_bytes() > MAX_RESPONSE_BYTES {
            return Err(OpsgenieProviderError::ResponseTooLarge {
                request,
                response_digest,
                response_bytes: response.response_bytes(),
                rate_limit: response.rate_limit,
            });
        }
        if response.status == 429 {
            return Err(OpsgenieProviderError::RateLimited {
                request,
                response_digest,
                response_bytes: response.response_bytes(),
                rate_limit: response.rate_limit,
            });
        }
        if !(200..300).contains(&response.status) {
            return Err(OpsgenieProviderError::HttpStatus {
                request,
                status: response.status,
                response_digest,
                response_bytes: response.response_bytes(),
                rate_limit: response.rate_limit,
            });
        }
        *response_bytes = response_bytes.saturating_add(response.response_bytes());
        *rate_limit = response.rate_limit.clone();
        response_digests.push(response_digest.clone());
        receipts.push(OpsgenieRequestReceipt {
            method: request.method,
            seam,
            endpoint: request.endpoint(),
            request_digest: request.request_digest,
            response_digest,
            response_bytes: response.response_bytes(),
            rate_limit_digest: response.rate_limit.digest(),
        });
        Ok(response)
    }

    fn parse_alert(
        &self,
        response: &OpsgenieResponse,
    ) -> Result<OpsgenieAlertObservation, OpsgenieProviderError> {
        let value = response.value().map_err(|_| self.malformed(response))?;
        let object = unwrap_data(&value);
        let id =
            required_string(object, &["id", "alertId"]).map_err(|_| self.malformed(response))?;
        let alias = optional_string(object, &["alias"])
            .unwrap_or_else(|| self.scope.alias().as_str().to_owned());
        let status = optional_string(object, &["status"])
            .map_or(OpsgenieAlertStatus::Unknown, |value| {
                OpsgenieAlertStatus::parse(&value)
            });
        let alert_id = OpsgenieAlertId::new(id).map_err(|_| self.malformed(response))?;
        if alert_id != *self.scope.alert() || alias != self.scope.alias().as_str() {
            return Err(OpsgenieProviderError::ScopeMismatch);
        }
        let team = optional_string(object, &["teamId", "team_id"])
            .unwrap_or_else(|| self.scope.team().as_str().to_owned());
        let service = optional_string(object, &["serviceId", "service_id"])
            .unwrap_or_else(|| self.scope.service().as_str().to_owned());
        let revision = optional_u64(object, &["revision", "version"]).unwrap_or(1);
        Ok(OpsgenieAlertObservation {
            alert_id,
            alias_digest: self.scope.alias().digest(),
            status,
            priority: optional_string(object, &["priority"]),
            team_digest: OpsgenieTeamId::new(team)
                .map_err(|_| self.malformed(response))?
                .digest(),
            service_digest: crate::OpsgenieServiceId::new(service)
                .map_err(|_| self.malformed(response))?
                .digest(),
            incident_digest: optional_string(object, &["incidentId", "incident_id"])
                .map(|value| sha256_digest(value.as_bytes())),
            created_at: optional_string(object, &["createdAt", "created_at"]),
            updated_at: optional_string(object, &["updatedAt", "updated_at"]),
            revision: Revision::new(revision).map_err(|_| self.malformed(response))?,
        })
    }

    fn parse_incident(
        &self,
        response: &OpsgenieResponse,
    ) -> Result<OpsgenieIncidentObservation, OpsgenieProviderError> {
        let value = response.value().map_err(|_| self.malformed(response))?;
        let object = unwrap_data(&value);
        let id =
            required_string(object, &["id", "incidentId"]).map_err(|_| self.malformed(response))?;
        let incident_id = OpsgenieIncidentId::new(id).map_err(|_| self.malformed(response))?;
        if incident_id != *self.scope.incident() {
            return Err(OpsgenieProviderError::ScopeMismatch);
        }
        let team = optional_string(object, &["teamId", "team_id"])
            .unwrap_or_else(|| self.scope.team().as_str().to_owned());
        let service = optional_string(object, &["serviceId", "service_id"])
            .unwrap_or_else(|| self.scope.service().as_str().to_owned());
        let alert_count = optional_array_len(object, &["alerts", "alertIds", "alert_ids"]);
        if alert_count > MAX_ALERTS {
            return Err(self.malformed(response));
        }
        Ok(OpsgenieIncidentObservation {
            incident_id,
            status: optional_string(object, &["status"])
                .map_or(OpsgenieIncidentStatus::Unknown, |value| {
                    OpsgenieIncidentStatus::parse(&value)
                }),
            alert_count,
            team_digest: OpsgenieTeamId::new(team)
                .map_err(|_| self.malformed(response))?
                .digest(),
            service_digest: crate::OpsgenieServiceId::new(service)
                .map_err(|_| self.malformed(response))?
                .digest(),
            revision: Revision::new(optional_u64(object, &["revision", "version"]).unwrap_or(1))
                .map_err(|_| self.malformed(response))?,
        })
    }

    fn parse_schedule(
        &self,
        response: &OpsgenieResponse,
    ) -> Result<OpsgenieScheduleObservation, OpsgenieProviderError> {
        let value = response.value().map_err(|_| self.malformed(response))?;
        let object = unwrap_data(&value);
        let id =
            required_string(object, &["id", "scheduleId"]).map_err(|_| self.malformed(response))?;
        let schedule_id = OpsgenieScheduleId::new(id).map_err(|_| self.malformed(response))?;
        if schedule_id != *self.scope.schedule() {
            return Err(OpsgenieProviderError::ScopeMismatch);
        }
        let digest_value = canonical_digest(&(
            self.scope.schedule().digest(),
            optional_bool(object, &["enabled"]).unwrap_or(true),
            optional_array_len(object, &["teams", "escalations", "rotations"]),
            optional_u64(object, &["revision", "version"]).unwrap_or(1),
        ));
        Ok(OpsgenieScheduleObservation {
            schedule_id,
            enabled: optional_bool(object, &["enabled"]).unwrap_or(true),
            escalation_count: optional_array_len(object, &["escalations", "rotations"]),
            schedule_digest: digest_value,
            revision: Revision::new(optional_u64(object, &["revision", "version"]).unwrap_or(1))
                .map_err(|_| self.malformed(response))?,
        })
    }

    fn parse_escalation(
        &self,
        response: &OpsgenieResponse,
    ) -> Result<OpsgenieEscalationObservation, OpsgenieProviderError> {
        let value = response.value().map_err(|_| self.malformed(response))?;
        let object = unwrap_data(&value);
        let id = required_string(object, &["id", "escalationId"])
            .map_err(|_| self.malformed(response))?;
        let escalation_id = OpsgenieEscalationId::new(id).map_err(|_| self.malformed(response))?;
        if escalation_id != *self.scope.escalation() {
            return Err(OpsgenieProviderError::ScopeMismatch);
        }
        let schedule = optional_string(object, &["scheduleId", "schedule_id"])
            .unwrap_or_else(|| self.scope.schedule().as_str().to_owned());
        let level_count = optional_array_len(object, &["rules", "levels", "steps"]);
        Ok(OpsgenieEscalationObservation {
            escalation_id,
            schedule_digest: crate::OpsgenieScheduleId::new(schedule)
                .map_err(|_| self.malformed(response))?
                .digest(),
            level_count,
            escalation_digest: canonical_digest(&(
                self.scope.escalation().digest(),
                level_count,
                optional_u64(object, &["revision", "version"]).unwrap_or(1),
            )),
            revision: Revision::new(optional_u64(object, &["revision", "version"]).unwrap_or(1))
                .map_err(|_| self.malformed(response))?,
        })
    }

    fn malformed(&self, response: &OpsgenieResponse) -> OpsgenieProviderError {
        OpsgenieProviderError::MalformedResponse {
            request: OpsgenieRequest::for_seam(&self.scope, OpsgenieReadSeam::Alert, 1)
                .bind_secret(&self.secret_reference),
            response_digest: response.response_digest(),
            response_bytes: response.response_bytes(),
            rate_limit: response.rate_limit.clone(),
        }
    }
}

fn ensure_permissions(scope: &OpsgenieIncidentResultScope) -> Result<(), OpsgenieProviderError> {
    for permission in [
        OpsgeniePermission::AlertsRead,
        OpsgeniePermission::IncidentsRead,
        OpsgeniePermission::SchedulesRead,
        OpsgeniePermission::EscalationsRead,
    ] {
        if !scope.permission_snapshot().has(permission) {
            return Err(OpsgenieProviderError::MissingPermission);
        }
    }
    Ok(())
}

fn unwrap_data(value: &Value) -> &Value {
    value.get("data").unwrap_or(value)
}

fn required_string(value: &Value, keys: &[&str]) -> std::result::Result<String, ()> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
        .ok_or(())
}

fn optional_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
}

fn optional_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
}

fn optional_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
}

fn optional_array_len(value: &Value, keys: &[&str]) -> usize {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_array).map(Vec::len))
        .unwrap_or(0)
}

fn parse_timeline_page(
    value: &Value,
    scope: &OpsgenieIncidentResultScope,
    response: &OpsgenieResponse,
) -> Result<(Vec<(String, crate::OpsgenieTimelineKind, Digest)>, bool), OpsgenieProviderError> {
    let object = unwrap_data(value);
    let entries = object
        .get("timeline")
        .or_else(|| object.get("items"))
        .or_else(|| object.get("data"))
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
        .ok_or_else(|| OpsgenieProviderError::MalformedResponse {
            request: OpsgenieRequest::for_seam(scope, OpsgenieReadSeam::AlertTimeline, 1),
            response_digest: response.response_digest(),
            response_bytes: response.response_bytes(),
            rate_limit: response.rate_limit.clone(),
        })?;
    if entries.len() > MAX_TIMELINE_ITEMS {
        return Err(OpsgenieProviderError::InvalidTimeline);
    }
    let mut seen = BTreeSet::new();
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = required_string(entry, &["id", "timelineId", "eventId"])
            .map_err(|_| OpsgenieProviderError::InvalidTimeline)?;
        if !seen.insert(id.clone()) {
            return Err(OpsgenieProviderError::InvalidTimeline);
        }
        let kind = optional_string(entry, &["type", "kind", "eventType"])
            .map_or(crate::OpsgenieTimelineKind::Other, |value| {
                crate::OpsgenieTimelineKind::parse(&value)
            });
        let content_digest = optional_string(entry, &["contentDigest", "content_digest"])
            .map_or_else(|| canonical_digest(entry), |value| Digest::from_text(value));
        parsed.push((id, kind, content_digest));
    }
    let has_more = object
        .get("nextPage")
        .or_else(|| object.get("next_page"))
        .or_else(|| object.get("nextCursor"))
        .or_else(|| object.get("next_cursor"))
        .is_some_and(|value| {
            !value.is_null() && value.as_str().is_none_or(|text| !text.is_empty())
        });
    Ok((parsed, has_more))
}

fn make_timeline_observation(
    scope: &OpsgenieIncidentResultScope,
    entries: Vec<(String, OpsgenieTimelineKind, Digest)>,
    page_count: usize,
    complete: bool,
    response_digests: &[Digest],
) -> OpsgenieTimelineObservation {
    let item_digest = canonical_digest(&entries);
    OpsgenieTimelineObservation {
        timeline_id: scope.timeline().clone(),
        entry_count: entries.len(),
        page_count: page_count.min(MAX_TIMELINE_PAGES),
        complete,
        item_digest,
        response_digest: canonical_digest(response_digests),
    }
}

/// Safe fixture payload types used by tests and local recordings. They omit
/// raw alert messages, notes, recipients, and descriptions by construction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpsgenieAlertPayload {
    pub id: String,
    pub alias: String,
    pub status: String,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub incident_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpsgenieTimelineEntryPayload {
    pub id: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub content_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpsgenieTimelinePayload {
    pub timeline: Vec<OpsgenieTimelineEntryPayload>,
    #[serde(default)]
    pub next_page: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpsgenieIncidentPayload {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub alerts: Vec<String>,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpsgenieSchedulePayload {
    pub id: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub escalations: Vec<String>,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpsgenieEscalationPayload {
    pub id: String,
    #[serde(default)]
    pub schedule_id: Option<String>,
    #[serde(default)]
    pub levels: Vec<String>,
    #[serde(default = "default_revision")]
    pub revision: u64,
}

fn default_revision() -> u64 {
    1
}

fn default_enabled() -> bool {
    true
}

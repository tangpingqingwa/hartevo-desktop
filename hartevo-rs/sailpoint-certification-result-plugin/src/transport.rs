//! Redacting, bounded transport seams for SailPoint V3 GET operations.
//!
//! The recording and fixture transports retain typed requests and sanitized
//! responses only. from_json parses provider bytes into the allowlisted model
//! and then drops the original payload.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AccessSummary, AccessType, CampaignId, CampaignSnapshot, CampaignState, CertificationId,
    CertificationRecord, DecisionCounts, DecisionState, EntitlementId, IdentityId,
    ProviderRevision, ReviewerId, SailPointEndpoint, SailPointHttpRequest, SailPointHttpResponse,
    SailPointModelError, SailPointReadRequest, SailPointResponseBody, TransportProvenance,
};

/// Transport failures contain status and digest metadata only; raw provider
/// errors and response bytes are deliberately not retained.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SailPointTransportError {
    #[error("SailPoint request timed out")]
    Timeout,
    #[error("SailPoint provider returned HTTP {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
        response_digest: crate::Digest,
    },
    #[error("SailPoint provider rate limited the request")]
    RateLimited { retry_after_seconds: u64 },
    #[error("SailPoint access was lost")]
    AccessLost { status: u16 },
    #[error("SailPoint transport is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("SailPoint response could not be decoded: {0}")]
    Decode(String),
    #[error("SailPoint transport response did not match the request")]
    RequestMismatch,
    #[error("SailPoint fixture has no response for the bounded request")]
    FixtureExhausted,
}

impl From<SailPointModelError> for SailPointTransportError {
    fn from(error: SailPointModelError) -> Self {
        Self::Decode(error.to_string())
    }
}

/// The only transport capability exported by this Layer-1 root.
pub trait SailPointTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn send(
        &mut self,
        request: &SailPointHttpRequest,
    ) -> Result<SailPointHttpResponse, SailPointTransportError>;
}

#[derive(Clone)]
pub struct RecordingSailPointTransport {
    responses: VecDeque<Result<SailPointHttpResponse, SailPointTransportError>>,
    requests: Vec<SailPointHttpRequest>,
    provenance: TransportProvenance,
}

impl fmt::Debug for RecordingSailPointTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingSailPointTransport")
            .field("provenance", &self.provenance)
            .field("queued_responses", &self.responses.len())
            .field("request_count", &self.requests.len())
            .finish()
    }
}

impl RecordingSailPointTransport {
    pub fn new<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<SailPointHttpResponse, SailPointTransportError>>,
    {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Recording,
        }
    }

    pub fn fixture<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<SailPointHttpResponse, SailPointTransportError>>,
    {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Fixture,
        }
    }

    pub fn loopback<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<SailPointHttpResponse, SailPointTransportError>>,
    {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Loopback,
        }
    }

    pub fn requests(&self) -> &[SailPointHttpRequest] {
        &self.requests
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

impl SailPointTransport for RecordingSailPointTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn send(
        &mut self,
        request: &SailPointHttpRequest,
    ) -> Result<SailPointHttpResponse, SailPointTransportError> {
        self.requests.push(request.clone());
        let response = self
            .responses
            .pop_front()
            .ok_or(SailPointTransportError::FixtureExhausted)??;
        if response.receipt.request_digest != request.request_digest
            || response.endpoint != request.endpoint
        {
            return Err(SailPointTransportError::RequestMismatch);
        }
        Ok(response)
    }
}

pub type FixtureSailPointTransport = RecordingSailPointTransport;
pub type LoopbackSailPointTransport = RecordingSailPointTransport;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvSailPointTransport;

impl SailPointTransport for BlockedEnvSailPointTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn send(
        &mut self,
        _request: &SailPointHttpRequest,
    ) -> Result<SailPointHttpResponse, SailPointTransportError> {
        Err(SailPointTransportError::BlockedEnv)
    }
}

impl SailPointHttpResponse {
    /// Parse a provider response while retaining no raw JSON.
    pub fn from_json(
        request: &SailPointHttpRequest,
        status: u16,
        raw: &[u8],
        provider_revision: ProviderRevision,
        total_count: Option<u32>,
        retry_after_seconds: Option<u64>,
    ) -> Result<Self, SailPointTransportError> {
        if status != 200 {
            let response_digest = crate::sha256_digest(raw);
            if status == 401 || status == 403 {
                return Err(SailPointTransportError::AccessLost { status });
            }
            if status == 429 {
                return Err(SailPointTransportError::RateLimited {
                    retry_after_seconds: retry_after_seconds.unwrap_or(60),
                });
            }
            return Err(SailPointTransportError::HttpStatus {
                status,
                retry_after_seconds,
                response_digest,
            });
        }
        if raw.len() > crate::SAILPOINT_MAX_RESPONSE_BYTES {
            return Err(SailPointTransportError::Decode(
                "response exceeds the Layer-1 byte budget".to_owned(),
            ));
        }
        let value = serde_json::from_slice::<Value>(raw)
            .map_err(|error| SailPointTransportError::Decode(error.to_string()))?;
        let body = parse_body(&request.endpoint, &value, request)?;
        Self::from_body(request, body, provider_revision, total_count)
            .map_err(SailPointTransportError::from)
    }
}

fn parse_body(
    endpoint: &SailPointEndpoint,
    value: &Value,
    request: &SailPointHttpRequest,
) -> Result<SailPointResponseBody, SailPointTransportError> {
    match endpoint {
        SailPointEndpoint::Certification { .. } => Ok(SailPointResponseBody::Certification(
            parse_certification(value, request)?,
        )),
        SailPointEndpoint::Campaigns => {
            let records = value
                .as_array()
                .ok_or_else(|| {
                    SailPointTransportError::Decode("campaign response is not an array".to_owned())
                })?
                .iter()
                .map(|item| parse_certification(item, request))
                .collect::<Result<Vec<_>, _>>()?;
            SailPointResponseBody::campaigns(records).map_err(SailPointTransportError::from)
        }
        SailPointEndpoint::AccessSummaries { .. } => {
            let values = value.as_array().ok_or_else(|| {
                SailPointTransportError::Decode(
                    "access summary response is not an array".to_owned(),
                )
            })?;
            let records = values
                .iter()
                .map(|item| parse_access_summary(item, request))
                .collect::<Result<Vec<_>, _>>()?;
            SailPointResponseBody::access_summaries(records).map_err(SailPointTransportError::from)
        }
    }
}

fn required_string(
    value: &Value,
    keys: &[&str],
    field: &'static str,
) -> Result<String, SailPointTransportError> {
    for key in keys {
        if let Some(string) = value.get(*key).and_then(Value::as_str) {
            return Ok(string.to_owned());
        }
    }
    Err(SailPointTransportError::Decode(format!(
        "missing allowlisted field {field}"
    )))
}

fn nested_string(
    value: &Value,
    object_key: &str,
    keys: &[&str],
    field: &'static str,
) -> Result<String, SailPointTransportError> {
    if let Some(object) = value.get(object_key).and_then(Value::as_object) {
        for key in keys {
            if let Some(string) = object.get(*key).and_then(Value::as_str) {
                return Ok(string.to_owned());
            }
        }
    }
    required_string(value, keys, field)
}

fn optional_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
}

fn nested_optional_string(value: &Value, object_key: &str, keys: &[&str]) -> Option<String> {
    value
        .get(object_key)
        .and_then(Value::as_object)
        .and_then(|object| {
            keys.iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str).map(str::to_owned))
        })
        .or_else(|| optional_string(value, keys))
}

fn number(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
}

fn boolean(value: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
        .unwrap_or(false)
}

fn parse_time(
    value: &Value,
    keys: &[&str],
) -> Result<Option<DateTime<Utc>>, SailPointTransportError> {
    let Some(raw) = optional_string(value, keys) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(&raw)
        .map(|date| Some(date.with_timezone(&Utc)))
        .map_err(|_| SailPointTransportError::Decode("invalid timestamp".to_owned()))
}

fn parse_revision(
    value: &Value,
    keys: &[&str],
    fallback: u64,
) -> Result<crate::Revision, SailPointTransportError> {
    crate::Revision::new(number(value, keys).unwrap_or(fallback))
        .map_err(SailPointTransportError::from)
}

fn parse_counts(value: &Value) -> DecisionCounts {
    let source = value.get("decisionSummary").unwrap_or(value);
    DecisionCounts {
        approved: number(
            source,
            &["approved", "approvedCount", "entitlementsApproved"],
        )
        .unwrap_or(0) as u32,
        revoked: number(source, &["revoked", "revokedCount", "entitlementsRevoked"]).unwrap_or(0)
            as u32,
        pending: number(source, &["pending", "pendingCount"]).unwrap_or(0) as u32,
        partial: number(source, &["partial", "partialCount"]).unwrap_or(0) as u32,
        total: number(source, &["decisionsTotal", "total", "totalCount"]).unwrap_or(0) as u32,
    }
}

fn parse_certification(
    value: &Value,
    request: &SailPointHttpRequest,
) -> Result<CertificationRecord, SailPointTransportError> {
    let certification_id = CertificationId::new(required_string(
        value,
        &["id", "certificationId"],
        "certification id",
    )?)
    .map_err(SailPointTransportError::from)?;
    if let SailPointEndpoint::Certification {
        certification_id: expected,
    } = &request.endpoint
        && &certification_id != expected
    {
        return Err(SailPointTransportError::Decode(
            "certification id does not match the request".to_owned(),
        ));
    }
    let campaign_value = value.get("campaign").unwrap_or(value);
    let campaign_id = CampaignId::new(nested_string(
        value,
        "campaign",
        &["campaignId", "id"],
        "campaign id",
    )?)
    .map_err(SailPointTransportError::from)?;
    let campaign_revision = parse_revision(
        campaign_value,
        &["campaignRevision", "revision", "version"],
        request.expected_campaign_revision.get(),
    )?;
    let completed = boolean(value, &["completed", "complete", "closed"]);
    let remediation_required = boolean(value, &["remediation", "remediationRequired"]);
    let due_at = parse_time(value, &["due", "dueAt", "expiration"])?;
    let observed_at = request.observed_at;
    let state = CampaignState::from_wire(
        optional_string(campaign_value, &["state", "status", "campaignStatus"]).as_deref(),
        completed,
        remediation_required,
        due_at,
        observed_at,
    );
    let counts = parse_counts(value);
    let decision_state = optional_string(value, &["decision", "decisionState", "decisionStatus"])
        .as_deref()
        .map_or_else(
            || counts.decision_state(),
            |raw| DecisionState::from_wire(Some(raw), completed),
        );
    let reviewer_id = ReviewerId::new(nested_string(
        value,
        "reviewer",
        &["reviewerId", "ownerId", "id"],
        "reviewer id",
    )?)
    .map_err(SailPointTransportError::from)?;
    let identity_id = IdentityId::new(nested_string(
        value,
        "identity",
        &["identityId", "id"],
        "identity id",
    )?)
    .map_err(SailPointTransportError::from)?;
    let created_at = parse_time(value, &["created", "createdAt"])?;
    let modified_at = parse_time(value, &["modified", "modifiedAt"])?;
    let identities_completed = number(value, &["identitiesCompleted"]).unwrap_or(0) as u32;
    let identities_total = number(value, &["identitiesTotal"]).unwrap_or(0) as u32;
    Ok(CertificationRecord {
        id: certification_id,
        campaign: CampaignSnapshot {
            id: campaign_id,
            revision: campaign_revision,
            state,
            identities_completed,
            identities_total,
            decision_counts: counts.clone(),
            created_at,
            modified_at,
            due_at,
        },
        reviewer_id,
        identity_id,
        decision_state,
        decision_counts: counts,
        created_at,
        modified_at,
        due_at,
    })
}

fn parse_access_summary(
    value: &Value,
    request: &SailPointHttpRequest,
) -> Result<AccessSummary, SailPointTransportError> {
    let id = EntitlementId::new(nested_string(
        value,
        "access",
        &["id", "accessId"],
        "access id",
    )?)
    .map_err(SailPointTransportError::from)?;
    let access_type = AccessType::parse(&nested_string(
        value,
        "access",
        &["type", "accessType"],
        "access type",
    )?)
    .map_err(SailPointTransportError::from)?;
    if let SailPointEndpoint::AccessSummaries {
        access_type: expected,
        ..
    } = &request.endpoint
        && &access_type != expected
    {
        return Err(SailPointTransportError::Decode(
            "access type does not match the request".to_owned(),
        ));
    }
    let reviewer_id = ReviewerId::new(nested_string(
        value,
        "reviewer",
        &["reviewerId", "ownerId", "id"],
        "reviewer id",
    )?)
    .map_err(SailPointTransportError::from)?;
    let identity_id = IdentityId::new(nested_string(
        value,
        "identity",
        &["identityId", "id"],
        "identity id",
    )?)
    .map_err(SailPointTransportError::from)?;
    let entitlement_id = nested_optional_string(value, "entitlement", &["id", "entitlementId"])
        .or_else(|| optional_string(value, &["entitlementId"]))
        .map(EntitlementId::new)
        .transpose()
        .map_err(SailPointTransportError::from)?;
    let completed = boolean(value, &["completed", "complete"]);
    let decision_state = DecisionState::from_wire(
        optional_string(value, &["decision", "decisionState", "status"]).as_deref(),
        completed,
    );
    let campaign_revision = parse_revision(
        value,
        &["campaignRevision", "revision"],
        request.expected_campaign_revision.get(),
    )?;
    let entitlement_revision = number(value, &["entitlementRevision", "accessRevision"])
        .map(crate::Revision::new)
        .transpose()
        .map_err(SailPointTransportError::from)?;
    let privileged = boolean(value, &["privileged"])
        || value
            .get("access")
            .and_then(|access| access.get("privileged"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || value
            .get("entitlement")
            .and_then(|entitlement| entitlement.get("privileged"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let decision_at = parse_time(value, &["decisionAt", "decisionDate", "modified"])?;
    Ok(AccessSummary {
        id: id.clone(),
        access_type,
        reviewer_id,
        identity_id,
        entitlement_id: if matches!(access_type, AccessType::Entitlement) {
            Some(entitlement_id.unwrap_or(id))
        } else {
            entitlement_id
        },
        campaign_revision,
        entitlement_revision,
        decision_state,
        privileged,
        decision_at,
    })
}

/// Convert a typed read request into a sanitized response from a JSON body.
pub fn response_from_json(
    request: &SailPointReadRequest,
    status: u16,
    raw: &[u8],
    provider_revision: ProviderRevision,
    total_count: Option<u32>,
    retry_after_seconds: Option<u64>,
) -> Result<SailPointHttpResponse, SailPointTransportError> {
    SailPointHttpResponse::from_json(
        &request.http_request(),
        status,
        raw,
        provider_revision,
        total_count,
        retry_after_seconds,
    )
}

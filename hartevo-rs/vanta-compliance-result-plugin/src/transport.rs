//! Allowlisted GET transport seams for Vanta.
//!
//! The transport boundary never accepts an arbitrary URL or method. It can
//! only execute a typed `VantaEndpoint`, and it receives an opaque digest-only
//! secret reference. Fixture, recording, loopback, and BLOCKED_ENV are the
//! only Layer-1 transport implementations.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AuditId, ControlId, Digest, FrameworkId, InformationRequestId, IssueId, OpaqueCursor,
    ProviderRevision, Revision, SecretReference, TestId, TransportProvenance, VantaApiFamily,
    VantaAuditRecord, VantaComplianceState, VantaControlRecord, VantaEndpoint,
    VantaInformationRequestRecord, VantaIssueRecord, VantaModelError, VantaReadRequest,
    VantaRecordKind, VantaResponseBody, VantaResponseReceipt, VantaTestRecord, digest_serializable,
    sha256_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VantaTransportError {
    #[error("BLOCKED_ENV: native Vanta credential authority is unavailable")]
    BlockedEnv,
    #[error("Vanta transport request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Vanta transport response is too large")]
    ResponseTooLarge,
    #[error("Vanta transport returned an unexpected response")]
    UnexpectedResponse,
    #[error("Vanta transport response could not be decoded: {0}")]
    Decode(String),
    #[error("Vanta recording response queue is exhausted")]
    QueueExhausted,
    #[error("Vanta transport failed: {0}")]
    Transport(String),
}

impl From<VantaModelError> for VantaTransportError {
    fn from(error: VantaModelError) -> Self {
        Self::InvalidRequest(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VantaHttpRequest {
    pub method: &'static str,
    pub endpoint: VantaEndpoint,
    pub api_family: VantaApiFamily,
    pub path_and_query: String,
    pub scope_digest: Digest,
    pub page_size: u16,
    pub max_response_bytes: usize,
    pub cursor: Option<OpaqueCursor>,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl VantaHttpRequest {
    pub fn new(
        request: &VantaReadRequest,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, VantaTransportError> {
        let path_and_query = request
            .endpoint
            .path_and_query(request.page_size, cursor.as_ref())?;
        let request_digest = digest_serializable(&(
            "GET",
            &path_and_query,
            &request.scope_digest,
            request.page_size,
            request.max_response_bytes,
            request.observed_at,
        ))?;
        Ok(Self {
            method: "GET",
            endpoint: request.endpoint.clone(),
            api_family: request.endpoint.family(),
            path_and_query,
            scope_digest: request.scope_digest.clone(),
            page_size: request.page_size,
            max_response_bytes: request.max_response_bytes,
            cursor,
            observed_at: request.observed_at,
            request_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug)]
pub struct VantaHttpResponse {
    body: VantaResponseBody,
    receipt: VantaResponseReceipt,
    next_cursor: Option<OpaqueCursor>,
}

impl VantaHttpResponse {
    pub fn from_body(
        request: &VantaHttpRequest,
        status: u16,
        body: VantaResponseBody,
        provider_revision: ProviderRevision,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self, VantaTransportError> {
        body.validate()?;
        if body.len() > usize::from(request.page_size) {
            return Err(VantaTransportError::InvalidRequest(
                "Vanta response page exceeds the requested page size".to_owned(),
            ));
        }
        let normalized_bytes = serde_json::to_vec(&body)
            .map_err(|error| VantaTransportError::Decode(error.to_string()))?;
        Self::new(
            request,
            status,
            body,
            normalized_bytes.len(),
            sha256_digest(&normalized_bytes),
            sha256_digest(&normalized_bytes),
            provider_revision,
            next_cursor,
        )
    }

    /// Parse an untrusted provider body and immediately discard it. Only the
    /// normalized records and digests survive this function; owner fields,
    /// evidence URLs, comments, and document bodies are never represented.
    pub fn from_json(
        request: &VantaHttpRequest,
        status: u16,
        raw_body: &[u8],
        provider_revision: ProviderRevision,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self, VantaTransportError> {
        if raw_body.len() > request.max_response_bytes {
            return Err(VantaTransportError::ResponseTooLarge);
        }
        let value = serde_json::from_slice::<Value>(raw_body)
            .map_err(|error| VantaTransportError::Decode(error.to_string()))?;
        let body = decode_body(&request.endpoint, &value)?;
        body.validate()?;
        if body.len() > usize::from(request.page_size) {
            return Err(VantaTransportError::InvalidRequest(
                "Vanta response page exceeds the requested page size".to_owned(),
            ));
        }
        let normalized_bytes = serde_json::to_vec(&body)
            .map_err(|error| VantaTransportError::Decode(error.to_string()))?;
        Self::new(
            request,
            status,
            body,
            raw_body.len(),
            sha256_digest(raw_body),
            sha256_digest(&normalized_bytes),
            provider_revision,
            next_cursor,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        request: &VantaHttpRequest,
        status: u16,
        body: VantaResponseBody,
        response_size: usize,
        response_digest: Digest,
        normalized_body_digest: Digest,
        provider_revision: ProviderRevision,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self, VantaTransportError> {
        if response_size > request.max_response_bytes {
            return Err(VantaTransportError::ResponseTooLarge);
        }
        let receipt = VantaResponseReceipt {
            request_digest: request.request_digest.clone(),
            endpoint: request.endpoint.clone(),
            status,
            response_size,
            response_digest,
            normalized_body_digest,
            provider_revision,
            next_cursor_present: next_cursor.is_some(),
            raw_provider_payload_retained: false,
            owners_redacted: true,
            evidence_urls_redacted: true,
            comments_redacted: true,
            document_bodies_redacted: true,
            credential_material_retained: false,
            observed_at: request.observed_at,
        };
        Ok(Self {
            body,
            receipt,
            next_cursor,
        })
    }

    pub fn validate(&self, request: &VantaHttpRequest) -> Result<(), VantaTransportError> {
        self.body.validate()?;
        let normalized_body_digest = digest_serializable(&self.body)?;
        if self.receipt.request_digest != request.request_digest
            || self.receipt.endpoint != request.endpoint
            || self.receipt.status != 200
            || self.receipt.response_size > request.max_response_bytes
            || self.receipt.normalized_body_digest != normalized_body_digest
            || self.receipt.next_cursor_present != self.next_cursor.is_some()
            || self.receipt.raw_provider_payload_retained
            || !self.receipt.owners_redacted
            || !self.receipt.evidence_urls_redacted
            || !self.receipt.comments_redacted
            || !self.receipt.document_bodies_redacted
            || self.receipt.credential_material_retained
        {
            return Err(VantaTransportError::UnexpectedResponse);
        }
        Ok(())
    }

    pub fn body(&self) -> &VantaResponseBody {
        &self.body
    }

    pub fn receipt(&self) -> &VantaResponseReceipt {
        &self.receipt
    }

    pub fn next_cursor(&self) -> Option<&OpaqueCursor> {
        self.next_cursor.as_ref()
    }
}

impl fmt::Display for VantaHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "VantaHttpResponse(kind={:?})", self.body.kind())
    }
}

/// GET-only Vanta transport. It receives no raw credential material.
pub trait VantaTransport: fmt::Debug {
    fn execute(
        &mut self,
        secret_reference: &SecretReference,
        request: &VantaHttpRequest,
    ) -> Result<VantaHttpResponse, VantaTransportError>;

    fn provenance(&self) -> TransportProvenance;

    fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingVantaTransport {
    responses: VecDeque<Result<VantaHttpResponse, VantaTransportError>>,
    requests: Vec<VantaHttpRequest>,
    provenance: TransportProvenance,
}

impl RecordingVantaTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<VantaHttpResponse, VantaTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Recording,
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<VantaHttpResponse, VantaTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Fixture,
        }
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<VantaHttpResponse, VantaTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Loopback,
        }
    }

    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(&mut self, response: Result<VantaHttpResponse, VantaTransportError>) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[VantaHttpRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl VantaTransport for RecordingVantaTransport {
    fn execute(
        &mut self,
        secret_reference: &SecretReference,
        request: &VantaHttpRequest,
    ) -> Result<VantaHttpResponse, VantaTransportError> {
        if !secret_reference.is_opaque() || request.method != "GET" {
            return Err(VantaTransportError::InvalidRequest(
                "Layer-1 Vanta transport received a non-opaque secret or non-GET request"
                    .to_owned(),
            ));
        }
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .ok_or(VantaTransportError::QueueExhausted)?
    }

    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

pub type FakeVantaTransport = RecordingVantaTransport;
pub type FixtureVantaTransport = RecordingVantaTransport;
pub type LoopbackVantaTransport = RecordingVantaTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvVantaTransport;

impl VantaTransport for BlockedEnvVantaTransport {
    fn execute(
        &mut self,
        _secret_reference: &SecretReference,
        _request: &VantaHttpRequest,
    ) -> Result<VantaHttpResponse, VantaTransportError> {
        Err(VantaTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

fn decode_body(
    endpoint: &VantaEndpoint,
    value: &Value,
) -> Result<VantaResponseBody, VantaTransportError> {
    let items = value
        .as_array()
        .or_else(|| value.get("items").and_then(Value::as_array))
        .or_else(|| value.get("data").and_then(Value::as_array))
        .or_else(|| value.get("value").and_then(Value::as_array))
        .or_else(|| {
            value
                .get("results")
                .and_then(|results| results.get("data"))
                .and_then(Value::as_array)
        })
        .ok_or(VantaTransportError::UnexpectedResponse)?;
    match endpoint.kind() {
        VantaRecordKind::Audits => Ok(VantaResponseBody::Audits(
            items.iter().map(parse_audit).collect::<Result<_, _>>()?,
        )),
        VantaRecordKind::Controls => Ok(VantaResponseBody::Controls(
            items
                .iter()
                .map(|item| parse_control(item, endpoint.audit_id()))
                .collect::<Result<_, _>>()?,
        )),
        VantaRecordKind::Tests => Ok(VantaResponseBody::Tests(
            items
                .iter()
                .map(|item| parse_test(item, endpoint.audit_id()))
                .collect::<Result<_, _>>()?,
        )),
        VantaRecordKind::Issues => Ok(VantaResponseBody::Issues(
            items
                .iter()
                .map(|item| parse_issue(item, endpoint.audit_id()))
                .collect::<Result<_, _>>()?,
        )),
        VantaRecordKind::InformationRequests => Ok(VantaResponseBody::InformationRequests(
            items
                .iter()
                .map(|item| parse_information_request(item, endpoint.audit_id()))
                .collect::<Result<_, _>>()?,
        )),
    }
}

fn parse_audit(value: &Value) -> Result<VantaAuditRecord, VantaTransportError> {
    Ok(VantaAuditRecord::new(
        AuditId::new(required_string(value, &["auditId", "id"], "audit id")?)?,
        FrameworkId::new(required_string(
            value,
            &["frameworkId", "framework_id", "framework"],
            "framework id",
        )?)?,
        Revision::new(required_revision(value)?)?,
        parse_state(value),
    ))
}

fn parse_control(
    value: &Value,
    expected_audit_id: &AuditId,
) -> Result<VantaControlRecord, VantaTransportError> {
    Ok(VantaControlRecord::new(
        scoped_audit_id(value, expected_audit_id)?,
        ControlId::new(required_string(
            value,
            &["controlId", "control_id", "id"],
            "control id",
        )?)?,
        Revision::new(required_revision(value)?)?,
        parse_state(value),
    ))
}

fn parse_test(
    value: &Value,
    expected_audit_id: &AuditId,
) -> Result<VantaTestRecord, VantaTransportError> {
    Ok(VantaTestRecord::new(
        scoped_audit_id(value, expected_audit_id)?,
        TestId::new(required_string(
            value,
            &["testId", "test_id", "id"],
            "test id",
        )?)?,
        optional_id(value, &["controlId", "control_id"], ControlId::new)?,
        Revision::new(required_revision(value)?)?,
        parse_state(value),
    ))
}

fn parse_issue(
    value: &Value,
    expected_audit_id: &AuditId,
) -> Result<VantaIssueRecord, VantaTransportError> {
    Ok(VantaIssueRecord::new(
        scoped_audit_id(value, expected_audit_id)?,
        IssueId::new(required_string(
            value,
            &["issueId", "issue_id", "id"],
            "issue id",
        )?)?,
        optional_id(value, &["controlId", "control_id"], ControlId::new)?,
        Revision::new(required_revision(value)?)?,
        parse_state(value),
    ))
}

fn parse_information_request(
    value: &Value,
    expected_audit_id: &AuditId,
) -> Result<VantaInformationRequestRecord, VantaTransportError> {
    Ok(VantaInformationRequestRecord::new(
        scoped_audit_id(value, expected_audit_id)?,
        InformationRequestId::new(required_string(
            value,
            &["informationRequestId", "information_request_id", "id"],
            "information request id",
        )?)?,
        optional_id(value, &["controlId", "control_id"], ControlId::new)?,
        Revision::new(required_revision(value)?)?,
        parse_state(value),
    ))
}

fn scoped_audit_id(
    value: &Value,
    expected_audit_id: &AuditId,
) -> Result<AuditId, VantaTransportError> {
    let Some(raw) = ["auditId", "audit_id"]
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
    else {
        return Ok(expected_audit_id.clone());
    };
    let observed = AuditId::new(raw.to_owned())?;
    if observed != *expected_audit_id {
        return Err(VantaTransportError::Decode(
            "provider record crossed the audit scope fence".to_owned(),
        ));
    }
    Ok(observed)
}

fn required_string(
    value: &Value,
    keys: &[&str],
    field: &'static str,
) -> Result<String, VantaTransportError> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
        .ok_or_else(|| VantaTransportError::Decode(format!("missing {field}")))
}

fn optional_id<T>(
    value: &Value,
    keys: &[&str],
    parse: fn(String) -> Result<T, VantaModelError>,
) -> Result<Option<T>, VantaTransportError> {
    let Some(raw) = keys
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
    else {
        return Ok(None);
    };
    parse(raw.to_owned())
        .map(Some)
        .map_err(VantaTransportError::from)
}

fn required_revision(value: &Value) -> Result<u64, VantaTransportError> {
    value
        .get("revision")
        .or_else(|| value.get("version"))
        .and_then(Value::as_u64)
        .ok_or_else(|| VantaTransportError::Decode("missing revision".to_owned()))
}

fn parse_state(value: &Value) -> VantaComplianceState {
    if value.get("completed").and_then(Value::as_bool) == Some(true) {
        return VantaComplianceState::Complete;
    }
    let raw = value
        .get("state")
        .or_else(|| value.get("status"))
        .or_else(|| value.get("outcome"))
        .and_then(Value::as_str)
        .unwrap_or("provider_unknown")
        .to_ascii_lowercase();
    match raw.as_str() {
        "complete" | "completed" | "done" | "pass" | "passed" | "healthy" => {
            VantaComplianceState::Complete
        }
        "open" | "pending" | "in_progress" | "in-progress" => VantaComplianceState::Open,
        "overdue" | "past_due" | "past-due" => VantaComplianceState::Overdue,
        "blocked" | "failed" | "failure" => VantaComplianceState::Blocked,
        "retention_gap" | "retention-gap" => VantaComplianceState::RetentionGap,
        "access_loss" | "access-lost" | "forbidden" | "unauthorized" => {
            VantaComplianceState::AccessLoss
        }
        _ => VantaComplianceState::ProviderUnknown,
    }
}

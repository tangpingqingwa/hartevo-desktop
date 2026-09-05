use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde_json::Value;
use thiserror::Error;

use crate::{
    ComplianceRecord, ComplianceState, ComplianceSummary, Digest, EvidenceStatus, IntuneEvidence,
    IntuneReadRequest, IntuneScope, Layer1Authority, MAX_RECORDS, MAX_RESPONSE_BYTES, ModelError,
    OpaqueNextLink, Platform, PolicyMetadataProjection, PolicyStateSummary, ProviderErrorEvidence,
    ProviderErrorKind, ProviderProvenance, ReadSurface, SecretReference,
};

pub const INTUNE_GRAPH_API_VERSION: &str = "v1.0";
pub const INTUNE_GRAPH_PROVIDER_ID: &str = "microsoft.graph.intune.device-compliance";
pub const INTUNE_GRAPH_PROVIDER_VERSION: &str = "1.0.0";
pub const INTUNE_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IntuneTransportError {
    #[error("transport timed out")]
    Timeout,
    #[error("native transport is blocked by Layer-1")]
    BlockedEnv,
    #[error("transport failed")]
    Network,
    #[error("fixture response queue is exhausted")]
    FixtureExhausted,
    #[error("injected transport failure")]
    Injected(Digest),
}

#[derive(Clone, Eq, PartialEq)]
pub struct IntuneGraphResponse {
    status: u16,
    body: String,
}

impl IntuneGraphResponse {
    #[must_use]
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    #[must_use]
    pub fn ok(body: impl Into<String>) -> Self {
        Self::new(200, body)
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }
}

impl fmt::Debug for IntuneGraphResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntuneGraphResponse")
            .field("status", &self.status)
            .field("body_digest", &Digest::from_text(self.body.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntuneGraphRequest {
    pub method: &'static str,
    pub api_version: &'static str,
    pub host: &'static str,
    pub surface: ReadSurface,
    pub path: &'static str,
    pub select: Vec<String>,
    pub top: usize,
    pub scope_digest: Digest,
    pub revision_fence: Digest,
    pub next_link: Option<OpaqueNextLink>,
}

impl IntuneGraphRequest {
    fn new(
        scope: &IntuneScope,
        surface: ReadSurface,
        top: usize,
        next_link: Option<OpaqueNextLink>,
    ) -> Self {
        Self {
            method: "GET",
            api_version: INTUNE_GRAPH_API_VERSION,
            host: scope.national_cloud.graph_host(),
            surface,
            path: surface.endpoint_path(),
            select: surface
                .select_fields()
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
            top,
            scope_digest: scope.scope_digest(),
            revision_fence: scope.revision_fence(),
            next_link,
        }
    }

    #[must_use]
    pub fn query_string(&self) -> String {
        format!(
            "$select={}&$top={}&scopeDigest={}&revisionFence={}",
            self.select.join(","),
            self.top,
            self.scope_digest.as_str(),
            self.revision_fence.as_str()
        )
    }
}

pub trait IntuneGraphTransport: fmt::Debug {
    fn send(
        &mut self,
        request: IntuneGraphRequest,
    ) -> Result<IntuneGraphResponse, IntuneTransportError>;
}

#[derive(Debug, Default)]
pub struct FixtureIntuneGraphTransport {
    responses: VecDeque<Result<IntuneGraphResponse, IntuneTransportError>>,
    requests: Vec<IntuneGraphRequest>,
}

impl FixtureIntuneGraphTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: IntuneGraphResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: IntuneTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[IntuneGraphRequest] {
        &self.requests
    }

    #[must_use]
    pub fn call_count(&self) -> usize {
        self.requests.len()
    }
}

impl IntuneGraphTransport for FixtureIntuneGraphTransport {
    fn send(
        &mut self,
        request: IntuneGraphRequest,
    ) -> Result<IntuneGraphResponse, IntuneTransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .unwrap_or(Err(IntuneTransportError::FixtureExhausted))
    }
}

#[derive(Debug, Default)]
pub struct RecordingIntuneGraphTransport {
    responses: VecDeque<Result<IntuneGraphResponse, IntuneTransportError>>,
    requests: Vec<IntuneGraphRequest>,
}

impl RecordingIntuneGraphTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: IntuneGraphResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: IntuneTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[IntuneGraphRequest] {
        &self.requests
    }

    #[must_use]
    pub fn call_count(&self) -> usize {
        self.requests.len()
    }
}

impl IntuneGraphTransport for RecordingIntuneGraphTransport {
    fn send(
        &mut self,
        request: IntuneGraphRequest,
    ) -> Result<IntuneGraphResponse, IntuneTransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .unwrap_or(Err(IntuneTransportError::FixtureExhausted))
    }
}

#[derive(Debug, Default)]
pub struct LoopbackIntuneGraphTransport {
    responses: VecDeque<Result<IntuneGraphResponse, IntuneTransportError>>,
    requests: Vec<IntuneGraphRequest>,
}

impl LoopbackIntuneGraphTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: IntuneGraphResponse) {
        self.responses.push_back(Ok(response));
    }

    #[must_use]
    pub fn requests(&self) -> &[IntuneGraphRequest] {
        &self.requests
    }
}

impl IntuneGraphTransport for LoopbackIntuneGraphTransport {
    fn send(
        &mut self,
        request: IntuneGraphRequest,
    ) -> Result<IntuneGraphResponse, IntuneTransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .unwrap_or_else(|| Ok(IntuneGraphResponse::ok(r#"{"value":[]}"#)))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BlockedEnvIntuneGraphTransport;

impl IntuneGraphTransport for BlockedEnvIntuneGraphTransport {
    fn send(
        &mut self,
        _request: IntuneGraphRequest,
    ) -> Result<IntuneGraphResponse, IntuneTransportError> {
        Err(IntuneTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IntuneProviderDefinitionError {
    #[error("provider version is invalid")]
    InvalidVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntuneProviderDefinition {
    pub id: &'static str,
    pub version: String,
    pub api_version: &'static str,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub https_transport: bool,
    pub live_execution: bool,
}

impl IntuneProviderDefinition {
    pub fn new(
        version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, IntuneProviderDefinitionError> {
        let version = version.into();
        if version.trim().is_empty() || version.len() > 32 || version.chars().any(char::is_control)
        {
            return Err(IntuneProviderDefinitionError::InvalidVersion);
        }
        Ok(Self {
            id: INTUNE_GRAPH_PROVIDER_ID,
            version,
            api_version: INTUNE_GRAPH_API_VERSION,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            https_transport: false,
            live_execution: false,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "intune.provider.v1",
            &[
                self.id.to_owned(),
                self.version.clone(),
                self.api_version.to_owned(),
                format!("{:?}", self.provenance),
            ],
        )
    }
}

#[derive(Debug)]
pub struct IntuneProvider<T: IntuneGraphTransport> {
    scope: IntuneScope,
    secret: SecretReference,
    definition: IntuneProviderDefinition,
    transport: T,
}

impl<T: IntuneGraphTransport> IntuneProvider<T> {
    pub fn new(
        scope: IntuneScope,
        secret: SecretReference,
        transport: T,
        provenance: ProviderProvenance,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.scope_digest() {
            return Err(ModelError::ScopeMismatch);
        }
        let definition = IntuneProviderDefinition::new(INTUNE_GRAPH_PROVIDER_VERSION, provenance)
            .map_err(|_| ModelError::InvalidScope)?;
        Ok(Self {
            scope,
            secret,
            definition,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &IntuneScope {
        &self.scope
    }

    #[must_use]
    pub fn secret(&self) -> &SecretReference {
        &self.secret
    }

    #[must_use]
    pub fn definition(&self) -> &IntuneProviderDefinition {
        &self.definition
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
    pub fn authority(&self) -> Layer1Authority {
        Layer1Authority::layer1()
    }

    pub fn read(&mut self, request: &IntuneReadRequest) -> IntuneEvidence {
        let scope_digest = self.scope.scope_digest();
        if request.scope().scope_digest() != scope_digest {
            return self.fenced_evidence(
                EvidenceStatus::Tampered,
                ProviderErrorKind::ScopeMismatch,
                "request-scope-mismatch",
            );
        }
        let mut accumulator =
            EvidenceAccumulator::new(self.scope.clone(), self.definition.provenance);
        for surface in request.surfaces() {
            self.read_surface(*surface, request, &mut accumulator);
        }
        accumulator.finish()
    }

    fn read_surface(
        &mut self,
        surface: ReadSurface,
        request: &IntuneReadRequest,
        accumulator: &mut EvidenceAccumulator,
    ) {
        let mut next_link = None;
        let mut seen_next_links = BTreeSet::new();
        let mut page = 0_u8;
        loop {
            if page >= request.bounds().max_pages {
                accumulator.merge_status(EvidenceStatus::Partial);
                accumulator.error(ProviderErrorKind::PartialPage, "page-bound");
                break;
            }
            let graph_request = IntuneGraphRequest::new(
                &self.scope,
                surface,
                request.bounds().max_records_per_page,
                next_link.clone(),
            );
            let response = match self.transport.send(graph_request) {
                Ok(response) => response,
                Err(error) => {
                    accumulator.transport_error(error);
                    break;
                }
            };
            page = page.saturating_add(1);
            accumulator.pages_observed = accumulator.pages_observed.saturating_add(1);
            if response.body.len() > request.bounds().max_response_bytes
                || response.body.len() > MAX_RESPONSE_BYTES
            {
                accumulator.merge_status(EvidenceStatus::Tampered);
                accumulator.error(ProviderErrorKind::ResponseTooLarge, "response-too-large");
                break;
            }
            accumulator
                .response_digests
                .push(Digest::from_text(response.body.as_bytes()));
            if !(200..300).contains(&response.status) {
                accumulator.http_error(response.status);
                break;
            }
            let document: Value = if let Ok(document) = serde_json::from_str(&response.body) {
                document
            } else {
                accumulator.merge_status(EvidenceStatus::Tampered);
                accumulator.error(ProviderErrorKind::MalformedResponse, "invalid-json");
                break;
            };
            if let Some(revision) = document.get("scopeRevision").and_then(Value::as_str)
                && revision != self.scope.revision_fence().as_str()
            {
                accumulator.merge_status(EvidenceStatus::Tampered);
                accumulator.error(ProviderErrorKind::RevisionMismatch, "revision-fence");
                break;
            }
            if document.get("partial").and_then(Value::as_bool) == Some(true) {
                accumulator.merge_status(EvidenceStatus::Partial);
                accumulator.error(ProviderErrorKind::PartialPage, "partial-page");
                break;
            }
            let Some(values) = document.get("value").and_then(Value::as_array) else {
                accumulator.merge_status(EvidenceStatus::Tampered);
                accumulator.error(ProviderErrorKind::MalformedResponse, "missing-value-array");
                break;
            };
            if values.len() > request.bounds().max_records_per_page {
                accumulator.merge_status(EvidenceStatus::Tampered);
                accumulator.error(ProviderErrorKind::RecordLimit, "page-record-bound");
                break;
            }
            for value in values {
                if accumulator.record_count() >= request.bounds().max_records {
                    accumulator.merge_status(EvidenceStatus::Partial);
                    accumulator.error(ProviderErrorKind::RecordLimit, "record-bound");
                    break;
                }
                if let Err(error) = accumulator.accept(surface, value) {
                    accumulator.merge_status(error.status());
                    accumulator.error(error.kind(), error.detail());
                    break;
                }
            }
            let raw_next_link = document.get("@odata.nextLink").and_then(Value::as_str);
            let Some(raw_next_link) = raw_next_link else {
                break;
            };
            let link =
                if let Ok(link) = OpaqueNextLink::from_raw(raw_next_link, &self.scope, surface) {
                    link
                } else {
                    accumulator.merge_status(EvidenceStatus::Tampered);
                    accumulator.error(ProviderErrorKind::NextLinkScopeMismatch, "next-link-scope");
                    break;
                };
            if !seen_next_links.insert(link.digest().clone()) {
                accumulator.merge_status(EvidenceStatus::Tampered);
                accumulator.error(ProviderErrorKind::NextLinkReplay, "next-link-replay");
                break;
            }
            accumulator.next_link_digests.push(link.digest().clone());
            if page >= request.bounds().max_pages {
                accumulator.merge_status(EvidenceStatus::Partial);
                accumulator.error(ProviderErrorKind::PartialPage, "next-page-bound");
                break;
            }
            next_link = Some(link);
        }
    }

    fn fenced_evidence(
        &self,
        status: EvidenceStatus,
        kind: ProviderErrorKind,
        detail: &str,
    ) -> IntuneEvidence {
        let mut accumulator =
            EvidenceAccumulator::new(self.scope.clone(), self.definition.provenance);
        accumulator.merge_status(status);
        accumulator.error(kind, detail);
        accumulator.finish()
    }
}

struct EvidenceAccumulator {
    scope: IntuneScope,
    provenance: ProviderProvenance,
    status: EvidenceStatus,
    pages_observed: u8,
    records: Vec<ComplianceRecord>,
    policies: Vec<PolicyMetadataProjection>,
    policy_summaries: Vec<PolicyStateSummary>,
    response_digests: Vec<Digest>,
    next_link_digests: Vec<Digest>,
    provider_errors: Vec<ProviderErrorEvidence>,
}

impl EvidenceAccumulator {
    fn new(scope: IntuneScope, provenance: ProviderProvenance) -> Self {
        Self {
            scope,
            provenance,
            status: EvidenceStatus::Complete,
            pages_observed: 0,
            records: Vec::new(),
            policies: Vec::new(),
            policy_summaries: Vec::new(),
            response_digests: Vec::new(),
            next_link_digests: Vec::new(),
            provider_errors: Vec::new(),
        }
    }

    fn finish(self) -> IntuneEvidence {
        IntuneEvidence {
            scope_digest: self.scope.scope_digest(),
            revision_fence: self.scope.revision_fence(),
            provenance: self.provenance,
            status: self.status,
            summary: summarize(&self.records, &self.policy_summaries, self.status),
            pages_observed: self.pages_observed,
            records: self.records,
            policies: self.policies,
            policy_summaries: self.policy_summaries,
            response_digests: self.response_digests,
            next_link_digests: self.next_link_digests,
            provider_errors: self.provider_errors,
            authority: Layer1Authority::layer1(),
        }
    }

    fn record_count(&self) -> usize {
        self.records.len() + self.policies.len() + self.policy_summaries.len()
    }

    fn merge_status(&mut self, candidate: EvidenceStatus) {
        if candidate == EvidenceStatus::Tampered {
            self.records.clear();
            self.policies.clear();
            self.policy_summaries.clear();
        }
        self.status = merge_status(self.status, candidate);
    }

    fn error(&mut self, kind: ProviderErrorKind, detail: &str) {
        self.provider_errors.push(ProviderErrorEvidence {
            kind,
            detail_digest: Digest::from_text(detail),
        });
    }

    fn http_error(&mut self, status: u16) {
        let kind = match status {
            401 | 403 => {
                self.merge_status(EvidenceStatus::AccessLoss);
                ProviderErrorKind::AccessDenied
            }
            404 => {
                self.merge_status(EvidenceStatus::ProviderUnknown);
                ProviderErrorKind::NotFound
            }
            409 => {
                self.merge_status(EvidenceStatus::ProviderUnknown);
                ProviderErrorKind::Conflict
            }
            429 => {
                self.merge_status(EvidenceStatus::ProviderUnknown);
                ProviderErrorKind::RateLimited
            }
            400..=599 => {
                self.merge_status(EvidenceStatus::ProviderUnknown);
                ProviderErrorKind::HttpStatus(status)
            }
            _ => {
                self.merge_status(EvidenceStatus::ProviderUnknown);
                ProviderErrorKind::HttpStatus(status)
            }
        };
        self.error(kind, &format!("http-status-{status}"));
    }

    fn transport_error(&mut self, error: IntuneTransportError) {
        let (status, kind, detail) = match error {
            IntuneTransportError::Timeout => (
                EvidenceStatus::ProviderUnknown,
                ProviderErrorKind::Timeout,
                "timeout",
            ),
            IntuneTransportError::BlockedEnv => (
                EvidenceStatus::ProviderUnknown,
                ProviderErrorKind::BlockedEnv,
                INTUNE_BLOCKED_ENV,
            ),
            IntuneTransportError::Network
            | IntuneTransportError::FixtureExhausted
            | IntuneTransportError::Injected(_) => (
                EvidenceStatus::ProviderUnknown,
                ProviderErrorKind::Transport,
                "transport",
            ),
        };
        self.merge_status(status);
        self.error(kind, detail);
    }

    fn accept(&mut self, surface: ReadSurface, value: &Value) -> Result<(), ParseError> {
        match surface {
            ReadSurface::PolicyMetadata => self.accept_policy(value),
            ReadSurface::ManagedDeviceCompliance => self.accept_device(value),
            ReadSurface::PolicyStateSummary => self.accept_summary(value),
        }
    }

    fn accept_policy(&mut self, value: &Value) -> Result<(), ParseError> {
        let policy_digest = required_digest(value, "id")?;
        if !self.scope.policy_fingerprints.accepts(&policy_digest) {
            return Err(ParseError::scope("policy-fingerprint"));
        }
        let platforms = value
            .get("platforms")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(Platform::parse)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !platforms.is_empty()
            && self.scope.platform != Platform::Unknown
            && !platforms.contains(&self.scope.platform)
        {
            return Err(ParseError::scope("policy-platform"));
        }
        let created_at = optional_timestamp(value, "createdDateTime")?;
        let modified_at = optional_timestamp(value, "lastModifiedDateTime")?;
        let metadata_digest = Digest::from_text(serde_json::to_vec(value).unwrap_or_default());
        self.policies.push(PolicyMetadataProjection {
            policy_digest,
            platforms,
            created_at,
            modified_at,
            metadata_digest,
        });
        Ok(())
    }

    fn accept_device(&mut self, value: &Value) -> Result<(), ParseError> {
        let device_digest = required_digest(value, "id")?;
        if !self.scope.device_selector.accepts(&device_digest) {
            return Err(ParseError::scope("device-selector"));
        }
        let platform = value
            .get("operatingSystem")
            .and_then(Value::as_str)
            .map_or(Platform::Unknown, Platform::parse);
        if self.scope.platform != Platform::Unknown && platform != self.scope.platform {
            return Err(ParseError::scope("device-platform"));
        }
        let policy_digest = optional_digest(value, "policyId")?;
        if let Some(policy_digest) = &policy_digest
            && !self.scope.policy_fingerprints.accepts(policy_digest)
        {
            return Err(ParseError::scope("device-policy"));
        }
        let observed_at = optional_timestamp(value, "lastSyncDateTime")?;
        if let Some(timestamp) = &observed_at
            && !self.scope.compliance_window.contains(timestamp)
        {
            return Err(ParseError::scope("compliance-window"));
        }
        let state = value
            .get("complianceState")
            .and_then(Value::as_str)
            .map_or(ComplianceState::Unknown, ComplianceState::parse);
        self.records.push(ComplianceRecord {
            device_digest,
            policy_digest,
            platform,
            state,
            observed_at,
        });
        Ok(())
    }

    fn accept_summary(&mut self, value: &Value) -> Result<(), ParseError> {
        let policy_digest = optional_digest(value, "policyId")?;
        if let Some(policy_digest) = &policy_digest
            && !self.scope.policy_fingerprints.accepts(policy_digest)
        {
            return Err(ParseError::scope("summary-policy"));
        }
        let summary_digest = value
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| value.get("settingName").and_then(Value::as_str))
            .map_or_else(
                || Err(ParseError::malformed("summary-identity")),
                |identity| Ok(Digest::from_text(identity)),
            )?;
        self.policy_summaries.push(PolicyStateSummary {
            summary_digest,
            policy_digest,
            compliant_count: bounded_count(value, "compliantDeviceCount")?,
            non_compliant_count: bounded_count(value, "nonCompliantDeviceCount")?,
            error_count: bounded_count(value, "errorDeviceCount")?,
            conflict_count: bounded_count(value, "conflictDeviceCount")?,
            unknown_count: bounded_count(value, "unknownDeviceCount")?,
            retired_count: bounded_count(value, "retiredDeviceCount")?,
        });
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParseError {
    kind: ProviderErrorKind,
    detail: &'static str,
}

impl ParseError {
    const fn malformed(detail: &'static str) -> Self {
        Self {
            kind: ProviderErrorKind::MalformedResponse,
            detail,
        }
    }

    const fn scope(detail: &'static str) -> Self {
        Self {
            kind: ProviderErrorKind::ScopeMismatch,
            detail,
        }
    }

    const fn status(&self) -> EvidenceStatus {
        match self.kind {
            ProviderErrorKind::ScopeMismatch
            | ProviderErrorKind::NextLinkScopeMismatch
            | ProviderErrorKind::NextLinkReplay
            | ProviderErrorKind::PartialPage
            | ProviderErrorKind::RevisionMismatch
            | ProviderErrorKind::MalformedResponse
            | ProviderErrorKind::ResponseTooLarge
            | ProviderErrorKind::RecordLimit => EvidenceStatus::Tampered,
            _ => EvidenceStatus::ProviderUnknown,
        }
    }

    const fn kind(self) -> ProviderErrorKind {
        self.kind
    }

    const fn detail(self) -> &'static str {
        self.detail
    }
}

fn required_digest(value: &Value, field: &str) -> Result<Digest, ParseError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(Digest::from_text)
        .ok_or_else(|| ParseError::malformed("missing-identity"))
}

fn optional_digest(value: &Value, field: &str) -> Result<Option<Digest>, ParseError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|raw| Some(Digest::from_text(raw)))
            .ok_or_else(|| ParseError::malformed("invalid-digest-field")),
    }
}

fn optional_timestamp(value: &Value, field: &str) -> Result<Option<crate::Timestamp>, ParseError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .ok_or_else(|| ParseError::malformed("invalid-timestamp-field"))
            .and_then(|raw| {
                crate::Timestamp::new(raw).map_err(|_| ParseError::malformed("timestamp"))
            })
            .map(Some),
    }
}

fn bounded_count(value: &Value, field: &str) -> Result<u32, ParseError> {
    let Some(raw) = value.get(field) else {
        return Ok(0);
    };
    let Some(raw) = raw.as_u64() else {
        return Err(ParseError::malformed("invalid-count"));
    };
    if raw > MAX_RECORDS as u64 || raw > u64::from(u32::MAX) {
        return Err(ParseError {
            kind: ProviderErrorKind::RecordLimit,
            detail: "count-bound",
        });
    }
    Ok(raw as u32)
}

fn merge_status(current: EvidenceStatus, candidate: EvidenceStatus) -> EvidenceStatus {
    match (current, candidate) {
        (EvidenceStatus::Tampered, _) | (_, EvidenceStatus::Tampered) => EvidenceStatus::Tampered,
        (EvidenceStatus::Revoked, _) | (_, EvidenceStatus::Revoked) => EvidenceStatus::Revoked,
        (EvidenceStatus::AccessLoss, _) | (_, EvidenceStatus::AccessLoss) => {
            EvidenceStatus::AccessLoss
        }
        (EvidenceStatus::Partial, _) | (_, EvidenceStatus::Partial) => EvidenceStatus::Partial,
        (EvidenceStatus::ProviderUnknown, _) | (_, EvidenceStatus::ProviderUnknown) => {
            EvidenceStatus::ProviderUnknown
        }
        _ => EvidenceStatus::Complete,
    }
}

fn summarize(
    records: &[ComplianceRecord],
    summaries: &[PolicyStateSummary],
    status: EvidenceStatus,
) -> ComplianceSummary {
    if status == EvidenceStatus::Tampered {
        return ComplianceSummary::Unknown;
    }
    let mut states = BTreeSet::new();
    for record in records {
        states.insert(record.state);
    }
    for summary in summaries {
        if summary.compliant_count > 0 {
            states.insert(ComplianceState::Compliant);
        }
        if summary.non_compliant_count > 0 {
            states.insert(ComplianceState::NonCompliant);
        }
        if summary.error_count > 0 {
            states.insert(ComplianceState::Error);
        }
        if summary.conflict_count > 0 {
            states.insert(ComplianceState::Conflict);
        }
        if summary.unknown_count > 0 {
            states.insert(ComplianceState::Unknown);
        }
        if summary.retired_count > 0 {
            states.insert(ComplianceState::Retired);
        }
    }
    if states.is_empty() {
        return ComplianceSummary::Empty;
    }
    if states.contains(&ComplianceState::Conflict) {
        return ComplianceSummary::Conflict;
    }
    if states.contains(&ComplianceState::Error) {
        return ComplianceSummary::Error;
    }
    if states.contains(&ComplianceState::NonCompliant) {
        return ComplianceSummary::NonCompliant;
    }
    if states.contains(&ComplianceState::Retired) {
        return ComplianceSummary::Retired;
    }
    if states.contains(&ComplianceState::Unknown) {
        return ComplianceSummary::Unknown;
    }
    if states.len() > 1 {
        ComplianceSummary::Mixed
    } else {
        ComplianceSummary::Compliant
    }
}

impl From<ModelError> for IntuneProviderDefinitionError {
    fn from(_: ModelError) -> Self {
        Self::InvalidVersion
    }
}

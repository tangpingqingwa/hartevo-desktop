//! Bounded Grafana HTTP-shaped provider and non-native evidence transports.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::model::{normalize_labels, validate_bounded_text, validate_identifier};
use crate::{
    AlertInstanceObservation, AlertResultError, AlertResultProposal, AlertResultReadOperation,
    AlertRuleMetadata, AlertState, AllowlistedLabel, Digest, GrafanaAlertScope,
    GrafanaRegistration, GrafanaTransportError, IncidentState, MAX_ALERT_INSTANCES,
    MAX_IDENTIFIER_BYTES, MAX_LABEL_BYTES, MAX_LABELS, MAX_NUMERIC_EVIDENCE, MAX_PAGE_SIZE,
    MAX_PAGES, MAX_RESPONSE_BYTES, MAX_RULES, NumericEvidenceDigest, RuleGroupMetadata,
    TransportProvenance,
};
use crate::{canonical_digest, contract_digest, plugin_version, sha256_digest};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GrafanaHttpMethod {
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaHttpRequest {
    pub operation: AlertResultReadOperation,
    pub method: GrafanaHttpMethod,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub page: u16,
    pub page_size: u16,
    pub continuation_digest: Option<Digest>,
    pub request_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub secret_reference_digest: Digest,
}

impl GrafanaHttpRequest {
    fn new(
        scope: &GrafanaAlertScope,
        registration: &GrafanaRegistration,
        proposal: &AlertResultProposal,
        page: u16,
        continuation_digest: Option<Digest>,
    ) -> Result<Self, AlertResultError> {
        if page == 0
            || page > MAX_PAGES
            || proposal.page_size == 0
            || proposal.page_size > MAX_PAGE_SIZE
        {
            return Err(AlertResultError::InvalidPage);
        }
        let path = match proposal.operation {
            AlertResultReadOperation::DescribeAlertRule
            | AlertResultReadOperation::ReadAlertRuleMetadata => {
                format!("/api/v1/provisioning/alert-rules/{}", scope.rule().id())
            }
            AlertResultReadOperation::ReadRuleGroupMetadata => format!(
                "/api/v1/provisioning/folder/{}/rule-groups/{}",
                scope.folder().id(),
                scope.rule_group().id()
            ),
            AlertResultReadOperation::ReadAlertInstances => {
                "/api/alertmanager/grafana/api/v1/alerts".to_owned()
            }
        };
        let mut query = BTreeMap::from([
            ("limit".to_owned(), proposal.page_size.to_string()),
            ("page".to_owned(), page.to_string()),
        ]);
        match proposal.operation {
            AlertResultReadOperation::ReadAlertInstances => {
                query.insert("alertInstanceId".into(), scope.alert_instance().id().into());
                query.insert("folderUid".into(), scope.folder().id().into());
                query.insert("ruleGroup".into(), scope.rule_group().id().into());
                query.insert("ruleUid".into(), scope.rule().id().into());
            }
            AlertResultReadOperation::DescribeAlertRule
            | AlertResultReadOperation::ReadAlertRuleMetadata
            | AlertResultReadOperation::ReadRuleGroupMetadata => {}
        }
        if let Some(continuation_digest) = &continuation_digest {
            query.insert("pageTokenDigest".into(), continuation_digest.clone());
        }
        let mut request = Self {
            operation: proposal.operation,
            method: GrafanaHttpMethod::Get,
            path,
            query,
            page,
            page_size: proposal.page_size,
            continuation_digest,
            request_digest: String::new(),
            registration_digest: registration.registration_digest().to_owned(),
            provider_digest: scope.provider_digest(),
            api_digest: scope.api_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.digest(),
            revision_digest: scope.revision_digest(),
            secret_reference_digest: scope.secret_reference().digest(),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            self.operation,
            self.method,
            &self.path,
            &self.query,
            self.page,
            self.page_size,
            &self.continuation_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.secret_reference_digest,
        ))
    }

    pub fn verify_integrity(&self) -> Result<(), AlertResultError> {
        if self.method != GrafanaHttpMethod::Get
            || self.page == 0
            || self.page > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(AlertResultError::InvalidPage);
        }
        for (key, value) in &self.query {
            if !matches!(
                key.as_str(),
                "alertInstanceId"
                    | "folderUid"
                    | "limit"
                    | "page"
                    | "pageTokenDigest"
                    | "ruleGroup"
                    | "ruleUid"
            ) || value.len() > MAX_IDENTIFIER_BYTES
            {
                return Err(AlertResultError::ForbiddenOperation);
            }
        }
        if self.request_digest != self.compute_digest() {
            return Err(AlertResultError::RequestTampered);
        }
        Ok(())
    }
}

/// A bounded response frame. The body is held only by the test/recording
/// transport and is never copied into Layer-1 evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct GrafanaHttpResponse {
    status: u16,
    body: Vec<u8>,
    headers: BTreeMap<String, String>,
    request_digest: Digest,
    response_digest: Digest,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for GrafanaHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrafanaHttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("body_digest", &sha256_digest(&self.body))
            .field("request_digest", &self.request_digest)
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

impl GrafanaHttpResponse {
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: BTreeMap::new(),
            request_digest: String::new(),
            response_digest: String::new(),
            provider_digest: String::new(),
            api_digest: String::new(),
            permission_digest: String::new(),
            scope_digest: String::new(),
            revision_digest: String::new(),
        }
    }

    #[must_use]
    pub fn for_request(
        request: &GrafanaHttpRequest,
        status: u16,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(status, body).bind_to_request(request)
    }

    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn bind_to_request(mut self, request: &GrafanaHttpRequest) -> Self {
        self.request_digest.clone_from(&request.request_digest);
        self.provider_digest.clone_from(&request.provider_digest);
        self.api_digest.clone_from(&request.api_digest);
        self.permission_digest
            .clone_from(&request.permission_digest);
        self.scope_digest.clone_from(&request.scope_digest);
        self.revision_digest.clone_from(&request.revision_digest);
        self.response_digest = sha256_digest(&self.body);
        self
    }

    #[must_use]
    pub fn tampered(mut self) -> Self {
        self.response_digest = sha256_digest(b"grafana-response-tampered");
        self
    }

    #[must_use]
    pub fn tampered_request(mut self) -> Self {
        self.request_digest = sha256_digest(b"grafana-request-tampered");
        self
    }

    #[must_use]
    pub fn tampered_scope(mut self) -> Self {
        self.scope_digest = sha256_digest(b"grafana-scope-tampered");
        self
    }

    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

pub trait GrafanaTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> TransportProvenance;
    fn send(
        &self,
        request: &GrafanaHttpRequest,
    ) -> Result<GrafanaHttpResponse, GrafanaTransportError>;
}

#[derive(Clone, Debug)]
pub enum RecordedFault {
    Unauthorized401,
    Forbidden403,
    NotFound404,
    Conflict409,
    RateLimited429 { retry_after_seconds: Option<u64> },
    Timeout,
    Server5xx { status: u16 },
    MalformedResponse,
    PartialResponse,
    NotAllowlistedPath,
    RequestTampered,
    ResponseTampered,
    ScopeMismatch,
    TransportUnavailable,
}

impl RecordedFault {
    fn error(&self) -> GrafanaTransportError {
        match self {
            Self::Unauthorized401 => GrafanaTransportError::Unauthorized401,
            Self::Forbidden403 => GrafanaTransportError::Forbidden403,
            Self::NotFound404 => GrafanaTransportError::NotFound404,
            Self::Conflict409 => GrafanaTransportError::Conflict409,
            Self::RateLimited429 {
                retry_after_seconds,
            } => GrafanaTransportError::RateLimited429 {
                retry_after_seconds: *retry_after_seconds,
            },
            Self::Timeout => GrafanaTransportError::Timeout,
            Self::Server5xx { status } => GrafanaTransportError::Server5xx { status: *status },
            Self::MalformedResponse => GrafanaTransportError::MalformedResponse,
            Self::PartialResponse => GrafanaTransportError::PartialResponse,
            Self::NotAllowlistedPath => GrafanaTransportError::NotAllowlistedPath,
            Self::RequestTampered => GrafanaTransportError::RequestTampered,
            Self::ResponseTampered => GrafanaTransportError::ResponseTampered,
            Self::ScopeMismatch => GrafanaTransportError::ScopeMismatch,
            Self::TransportUnavailable => GrafanaTransportError::TransportUnavailable,
        }
    }
}

#[derive(Default)]
struct TransportBuffer {
    responses: VecDeque<Result<GrafanaHttpResponse, GrafanaTransportError>>,
    requests: Vec<GrafanaHttpRequest>,
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone)]
        pub struct $name {
            buffer: Arc<Mutex<TransportBuffer>>,
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("provenance", &$provenance)
                    .field("queued_requests", &self.requests().len())
                    .finish()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self {
                    buffer: Arc::new(Mutex::new(TransportBuffer::default())),
                }
            }

            #[must_use]
            pub fn with_response(response: GrafanaHttpResponse) -> Self {
                let transport = Self::new();
                transport.push_response(response);
                transport
            }

            #[must_use]
            pub fn with_json(status: u16, body: impl Into<Vec<u8>>) -> Self {
                Self::with_response(GrafanaHttpResponse::new(status, body))
            }

            pub fn push_response(&self, response: GrafanaHttpResponse) {
                if let Ok(mut buffer) = self.buffer.lock() {
                    buffer.responses.push_back(Ok(response));
                }
            }

            pub fn push_fault(&self, fault: RecordedFault) {
                if let Ok(mut buffer) = self.buffer.lock() {
                    buffer.responses.push_back(Err(fault.error()));
                }
            }

            #[must_use]
            pub fn requests(&self) -> Vec<GrafanaHttpRequest> {
                self.buffer
                    .lock()
                    .map(|buffer| buffer.requests.clone())
                    .unwrap_or_default()
            }
        }

        impl GrafanaTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn send(
                &self,
                request: &GrafanaHttpRequest,
            ) -> Result<GrafanaHttpResponse, GrafanaTransportError> {
                let mut buffer = self
                    .buffer
                    .lock()
                    .map_err(|_| GrafanaTransportError::TransportUnavailable)?;
                buffer.requests.push(request.clone());
                let response = buffer
                    .responses
                    .pop_front()
                    .ok_or(GrafanaTransportError::TransportUnavailable)??;
                if response.request_digest.is_empty() {
                    Ok(response.bind_to_request(request))
                } else {
                    Ok(response)
                }
            }
        }
    };
}

queued_transport!(RecordingGrafanaTransport, TransportProvenance::Recording);
queued_transport!(FakeGrafanaTransport, TransportProvenance::Fake);
queued_transport!(FixtureGrafanaTransport, TransportProvenance::Fixture);
queued_transport!(LoopbackGrafanaTransport, TransportProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGrafanaTransport;

impl GrafanaTransport for BlockedEnvGrafanaTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn send(
        &self,
        _request: &GrafanaHttpRequest,
    ) -> Result<GrafanaHttpResponse, GrafanaTransportError> {
        Err(GrafanaTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug)]
pub enum GrafanaPage {
    AlertRule {
        metadata: AlertRuleMetadata,
        partial: bool,
        next_page_digest: Option<Digest>,
        request_digest: Digest,
        response_digest: Digest,
        response_status: u16,
    },
    RuleGroup {
        metadata: RuleGroupMetadata,
        partial: bool,
        next_page_digest: Option<Digest>,
        request_digest: Digest,
        response_digest: Digest,
        response_status: u16,
    },
    AlertInstances {
        instances: Vec<AlertInstanceObservation>,
        partial: bool,
        next_page_digest: Option<Digest>,
        request_digest: Digest,
        response_digest: Digest,
        response_status: u16,
    },
}

impl GrafanaPage {
    #[must_use]
    pub fn partial(&self) -> bool {
        match self {
            Self::AlertRule { partial, .. }
            | Self::RuleGroup { partial, .. }
            | Self::AlertInstances { partial, .. } => *partial,
        }
    }

    #[must_use]
    pub fn next_page_digest(&self) -> Option<&str> {
        match self {
            Self::AlertRule {
                next_page_digest, ..
            }
            | Self::RuleGroup {
                next_page_digest, ..
            }
            | Self::AlertInstances {
                next_page_digest, ..
            } => next_page_digest.as_deref(),
        }
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        match self {
            Self::AlertRule { request_digest, .. }
            | Self::RuleGroup { request_digest, .. }
            | Self::AlertInstances { request_digest, .. } => request_digest,
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> &str {
        match self {
            Self::AlertRule {
                response_digest, ..
            }
            | Self::RuleGroup {
                response_digest, ..
            }
            | Self::AlertInstances {
                response_digest, ..
            } => response_digest,
        }
    }

    #[must_use]
    pub const fn response_status(&self) -> u16 {
        match self {
            Self::AlertRule {
                response_status, ..
            }
            | Self::RuleGroup {
                response_status, ..
            }
            | Self::AlertInstances {
                response_status, ..
            } => *response_status,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GrafanaProvider<T = BlockedEnvGrafanaTransport>
where
    T: GrafanaTransport,
{
    scope: GrafanaAlertScope,
    registration: GrafanaRegistration,
    transport: T,
}

impl<T> GrafanaProvider<T>
where
    T: GrafanaTransport,
{
    pub fn new(scope: GrafanaAlertScope, transport: T) -> Result<Self, AlertResultError> {
        scope.validate()?;
        let registration = GrafanaRegistration::new(&scope, contract_digest(), plugin_version())?;
        Ok(Self {
            scope,
            registration,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GrafanaAlertScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &GrafanaRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    pub fn compile_request(
        &self,
        proposal: &AlertResultProposal,
        page: u16,
        continuation_digest: Option<Digest>,
    ) -> Result<GrafanaHttpRequest, AlertResultError> {
        proposal.validate_against(&self.scope, &self.registration)?;
        self.registration
            .validate_against(&self.scope, &contract_digest(), plugin_version())?;
        GrafanaHttpRequest::new(
            &self.scope,
            &self.registration,
            proposal,
            page,
            continuation_digest,
        )
    }

    pub fn read_page(
        &self,
        proposal: &AlertResultProposal,
        page: u16,
        continuation_digest: Option<Digest>,
    ) -> Result<GrafanaPage, AlertResultError> {
        let request = self.compile_request(proposal, page, continuation_digest)?;
        let response = self.transport.send(&request)?;
        self.decode_response(&request, response)
    }

    pub fn decode_response(
        &self,
        request: &GrafanaHttpRequest,
        response: GrafanaHttpResponse,
    ) -> Result<GrafanaPage, AlertResultError> {
        request.verify_integrity()?;
        if response.status() < 200 || response.status() >= 300 {
            return Err(AlertResultError::Transport(status_error(&response)));
        }
        if response.body().len() > MAX_RESPONSE_BYTES {
            return Err(AlertResultError::Transport(
                GrafanaTransportError::MalformedResponse,
            ));
        }
        if response.request_digest != request.request_digest {
            return Err(AlertResultError::Transport(
                GrafanaTransportError::RequestTampered,
            ));
        }
        if response.response_digest != sha256_digest(response.body()) {
            return Err(AlertResultError::Transport(
                GrafanaTransportError::ResponseTampered,
            ));
        }
        if response.provider_digest != request.provider_digest
            || response.api_digest != request.api_digest
            || response.permission_digest != request.permission_digest
            || response.scope_digest != request.scope_digest
            || response.revision_digest != request.revision_digest
        {
            return Err(AlertResultError::Transport(
                GrafanaTransportError::ScopeMismatch,
            ));
        }
        let value: Value = serde_json::from_slice(response.body())
            .map_err(|_| AlertResultError::Transport(GrafanaTransportError::MalformedResponse))?;
        let partial = value
            .get("partial")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || response.status() == 206;
        let next_page_digest = next_page_digest(&value)?;
        match request.operation {
            AlertResultReadOperation::DescribeAlertRule
            | AlertResultReadOperation::ReadAlertRuleMetadata => {
                let (metadata, parsed_partial) = parse_rule(&self.scope, &value)?;
                Ok(GrafanaPage::AlertRule {
                    metadata,
                    partial: partial || parsed_partial,
                    next_page_digest,
                    request_digest: request.request_digest.clone(),
                    response_digest: response.response_digest.clone(),
                    response_status: response.status(),
                })
            }
            AlertResultReadOperation::ReadRuleGroupMetadata => {
                let (metadata, parsed_partial) = parse_rule_group(&self.scope, &value)?;
                Ok(GrafanaPage::RuleGroup {
                    metadata,
                    partial: partial || parsed_partial,
                    next_page_digest,
                    request_digest: request.request_digest.clone(),
                    response_digest: response.response_digest.clone(),
                    response_status: response.status(),
                })
            }
            AlertResultReadOperation::ReadAlertInstances => {
                let (instances, parsed_partial) = parse_alert_instances(&self.scope, &value)?;
                Ok(GrafanaPage::AlertInstances {
                    instances,
                    partial: partial || parsed_partial,
                    next_page_digest,
                    request_digest: request.request_digest.clone(),
                    response_digest: response.response_digest.clone(),
                    response_status: response.status(),
                })
            }
        }
    }
}

impl GrafanaProvider<BlockedEnvGrafanaTransport> {
    pub fn for_scope(scope: GrafanaAlertScope) -> Result<Self, AlertResultError> {
        Self::new(scope, BlockedEnvGrafanaTransport)
    }
}

fn status_error(response: &GrafanaHttpResponse) -> GrafanaTransportError {
    match response.status() {
        401 => GrafanaTransportError::Unauthorized401,
        403 => GrafanaTransportError::Forbidden403,
        404 => GrafanaTransportError::NotFound404,
        409 => GrafanaTransportError::Conflict409,
        429 => GrafanaTransportError::RateLimited429 {
            retry_after_seconds: response
                .header("Retry-After")
                .and_then(|value| value.parse::<u64>().ok()),
        },
        408 => GrafanaTransportError::Timeout,
        500..=599 => GrafanaTransportError::Server5xx {
            status: response.status(),
        },
        _ => GrafanaTransportError::MalformedResponse,
    }
}

fn object_value(value: &Value) -> Result<&Map<String, Value>, AlertResultError> {
    value.as_object().ok_or(AlertResultError::MalformedResponse)
}

fn payload_object(value: &Value) -> Result<&Map<String, Value>, AlertResultError> {
    if let Some(object) = value.as_object() {
        for key in ["data", "rule", "alertRule"] {
            if let Some(payload) = object.get(key)
                && let Some(payload) = payload.as_object()
            {
                return Ok(payload);
            }
        }
        return Ok(object);
    }
    Err(AlertResultError::MalformedResponse)
}

fn first_text<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
}

fn optional_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
        })
    })
}

fn optional_time(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Result<Option<DateTime<Utc>>, AlertResultError> {
    let Some(value) = first_text(object, keys) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| Some(parsed.with_timezone(&Utc)))
        .map_err(|_| AlertResultError::MalformedResponse)
}

fn validate_provider_identity(
    object: &Map<String, Value>,
    scope: &GrafanaAlertScope,
) -> Result<(), AlertResultError> {
    if let Some(value) = first_text(object, &["stackId", "stack_id", "cloudStackId"])
        && value != scope.cloud_stack().id()
    {
        return Err(AlertResultError::CloudStackMismatch);
    }
    if let Some(value) = first_text(object, &["organizationId", "organization_id", "orgId"])
        && value != scope.organization().id()
    {
        return Err(AlertResultError::OrganizationMismatch);
    }
    Ok(())
}

fn parse_rule(
    scope: &GrafanaAlertScope,
    value: &Value,
) -> Result<(AlertRuleMetadata, bool), AlertResultError> {
    let object = payload_object(value)?;
    validate_provider_identity(object, scope)?;
    let rule_uid = first_text(object, &["uid", "ruleUid", "rule_uid"])
        .ok_or(AlertResultError::MalformedResponse)?;
    if rule_uid != scope.rule().id() {
        return Err(AlertResultError::RuleMismatch);
    }
    let folder_id = first_text(object, &["folderUID", "folderUid", "folder_id"])
        .ok_or(AlertResultError::MalformedResponse)?;
    if folder_id != scope.folder().id() {
        return Err(AlertResultError::FolderMismatch);
    }
    let rule_group_id = first_text(object, &["ruleGroup", "ruleGroupName", "rule_group_id"])
        .ok_or(AlertResultError::MalformedResponse)?;
    if rule_group_id != scope.rule_group().id() {
        return Err(AlertResultError::RuleGroupMismatch);
    }
    let title =
        first_text(object, &["title", "name"]).ok_or(AlertResultError::MalformedResponse)?;
    validate_bounded_text(title, "alert rule title", MAX_IDENTIFIER_BYTES)?;
    let mut labels = Vec::new();
    let partial_labels = parse_labels(object.get("labels"), scope, &mut labels)?;
    let version = optional_u64(object, &["version", "revision"]);
    let updated_at = optional_time(object, &["updated", "updatedAt", "updated_at"])?;
    let mut metadata = AlertRuleMetadata {
        cloud_stack_id: scope.cloud_stack().id().to_owned(),
        organization_id: scope.organization().id().to_owned(),
        folder_id: folder_id.to_owned(),
        rule_uid: rule_uid.to_owned(),
        rule_group_id: rule_group_id.to_owned(),
        title: title.to_owned(),
        version,
        updated_at,
        labels,
        metadata_digest: String::new(),
    };
    metadata.metadata_digest = canonical_digest(&(
        &metadata.cloud_stack_id,
        &metadata.organization_id,
        &metadata.folder_id,
        &metadata.rule_uid,
        &metadata.rule_group_id,
        &metadata.title,
        metadata.version,
        metadata.updated_at,
        &metadata.labels,
    ));
    Ok((metadata, partial_labels))
}

fn parse_rule_group(
    scope: &GrafanaAlertScope,
    value: &Value,
) -> Result<(RuleGroupMetadata, bool), AlertResultError> {
    let object = payload_object(value)?;
    validate_provider_identity(object, scope)?;
    let folder_id = first_text(object, &["folderUID", "folderUid", "folder_id"])
        .unwrap_or_else(|| scope.folder().id());
    if folder_id != scope.folder().id() {
        return Err(AlertResultError::FolderMismatch);
    }
    let rule_group_id = first_text(object, &["name", "ruleGroup", "rule_group_id"])
        .unwrap_or_else(|| scope.rule_group().id());
    if rule_group_id != scope.rule_group().id() {
        return Err(AlertResultError::RuleGroupMismatch);
    }
    let mut partial = false;
    let mut rule_uids = Vec::new();
    if let Some(rules) = object
        .get("rules")
        .or_else(|| object.get("alertRules"))
        .and_then(Value::as_array)
    {
        if rules.len() > MAX_RULES {
            return Err(AlertResultError::BoundExceeded {
                label: "rules",
                maximum: MAX_RULES,
            });
        }
        for rule in rules {
            let Some(rule) = rule.as_object() else {
                partial = true;
                continue;
            };
            if let Some(uid) = first_text(rule, &["uid", "ruleUid", "rule_uid"]) {
                validate_identifier(uid, "rule UID")?;
                rule_uids.push(uid.to_owned());
            } else {
                partial = true;
            }
        }
    } else {
        partial = true;
    }
    rule_uids.sort_unstable();
    rule_uids.dedup();
    let interval_seconds = optional_u64(object, &["intervalSeconds", "interval_seconds"]);
    let version = optional_u64(object, &["version", "revision"]);
    let updated_at = optional_time(object, &["updated", "updatedAt", "updated_at"])?;
    let mut metadata = RuleGroupMetadata {
        cloud_stack_id: scope.cloud_stack().id().to_owned(),
        organization_id: scope.organization().id().to_owned(),
        folder_id: folder_id.to_owned(),
        rule_group_id: rule_group_id.to_owned(),
        rule_uids,
        interval_seconds,
        version,
        updated_at,
        metadata_digest: String::new(),
    };
    metadata.metadata_digest = canonical_digest(&(
        &metadata.cloud_stack_id,
        &metadata.organization_id,
        &metadata.folder_id,
        &metadata.rule_group_id,
        &metadata.rule_uids,
        metadata.interval_seconds,
        metadata.version,
        metadata.updated_at,
    ));
    Ok((metadata, partial))
}

fn parse_alert_instances(
    scope: &GrafanaAlertScope,
    value: &Value,
) -> Result<(Vec<AlertInstanceObservation>, bool), AlertResultError> {
    let (items, envelope) = if let Some(items) = value.as_array() {
        (items, None)
    } else {
        let object = object_value(value)?;
        let items = object
            .get("alerts")
            .or_else(|| object.get("instances"))
            .or_else(|| object.get("data"))
            .and_then(Value::as_array)
            .ok_or(AlertResultError::MalformedResponse)?;
        (items, Some(object))
    };
    if items.len() > MAX_ALERT_INSTANCES {
        return Err(AlertResultError::BoundExceeded {
            label: "alert instances",
            maximum: MAX_ALERT_INSTANCES,
        });
    }
    let mut partial = envelope
        .and_then(|object| object.get("partial").and_then(Value::as_bool))
        .unwrap_or(false);
    let mut observations = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or(AlertResultError::MalformedResponse)?;
        validate_provider_identity(object, scope)?;
        let labels_value = object.get("labels");
        let mut labels = Vec::new();
        if parse_labels(labels_value, scope, &mut labels)? {
            partial = true;
        }
        let alert_instance_id = first_text(object, &["id", "fingerprint", "alertInstanceId"])
            .or_else(|| {
                labels
                    .iter()
                    .find(|label| label.key == "alertname")
                    .map(|label| label.value.as_str())
            })
            .unwrap_or_else(|| scope.alert_instance().id());
        if alert_instance_id != scope.alert_instance().id() {
            return Err(AlertResultError::AlertInstanceMismatch);
        }
        let rule_uid = first_text(object, &["ruleUid", "rule_uid"])
            .or_else(|| {
                labels
                    .iter()
                    .find(|label| label.key == "rule_uid")
                    .map(|label| label.value.as_str())
            })
            .unwrap_or_else(|| scope.rule().id());
        if rule_uid != scope.rule().id() {
            return Err(AlertResultError::RuleMismatch);
        }
        let state = first_text(object, &["state", "status"]).map_or_else(
            || {
                partial = true;
                AlertState::Unknown
            },
            AlertState::parse,
        );
        let evaluation_at = optional_time(
            object,
            &[
                "evaluationTimestamp",
                "evaluation_timestamp",
                "activeAt",
                "startsAt",
                "lastEvaluation",
            ],
        )?;
        if evaluation_at.is_none() {
            partial = true;
        }
        let mut numeric_evidence = parse_numeric_evidence(object);
        if numeric_evidence.len() > MAX_NUMERIC_EVIDENCE {
            return Err(AlertResultError::BoundExceeded {
                label: "numeric evidence",
                maximum: MAX_NUMERIC_EVIDENCE,
            });
        }
        numeric_evidence.sort_by(|left, right| left.name.cmp(&right.name));
        let incident_state = first_text(object, &["incidentState", "incident_state"])
            .map_or_else(|| state.incident_state(), parse_incident_state);
        let mut observation = AlertInstanceObservation {
            cloud_stack_id: scope.cloud_stack().id().to_owned(),
            organization_id: scope.organization().id().to_owned(),
            folder_id: scope.folder().id().to_owned(),
            rule_uid: rule_uid.to_owned(),
            rule_group_id: scope.rule_group().id().to_owned(),
            alert_instance_id: alert_instance_id.to_owned(),
            state,
            incident_state,
            evaluation_at,
            labels,
            numeric_evidence,
            observation_digest: String::new(),
        };
        normalize_labels(&mut observation.labels);
        observation.observation_digest = canonical_digest(&(
            &observation.cloud_stack_id,
            &observation.organization_id,
            &observation.folder_id,
            &observation.rule_uid,
            &observation.rule_group_id,
            &observation.alert_instance_id,
            observation.state,
            observation.incident_state,
            observation.evaluation_at,
            &observation.labels,
            &observation.numeric_evidence,
        ));
        observations.push(observation);
    }
    Ok((observations, partial))
}

fn parse_labels(
    value: Option<&Value>,
    scope: &GrafanaAlertScope,
    output: &mut Vec<AllowlistedLabel>,
) -> Result<bool, AlertResultError> {
    let Some(value) = value else {
        return Ok(true);
    };
    let object = value
        .as_object()
        .ok_or(AlertResultError::MalformedResponse)?;
    if object.len() > MAX_LABELS {
        return Err(AlertResultError::BoundExceeded {
            label: "labels",
            maximum: MAX_LABELS,
        });
    }
    let mut partial = false;
    for (key, value) in object {
        if !scope.label_allowlist().contains(key) || scope.is_redacted_label_key(key) {
            partial = true;
            continue;
        }
        let Some(value) = value.as_str() else {
            partial = true;
            continue;
        };
        validate_bounded_text(value, "label value", MAX_LABEL_BYTES)?;
        output.push(AllowlistedLabel::new(key.clone(), value.to_owned())?);
    }
    normalize_labels(output);
    Ok(partial)
}

fn parse_numeric_evidence(object: &Map<String, Value>) -> Vec<NumericEvidenceDigest> {
    let keys = [
        ("value", "value"),
        ("evaluationValue", "evaluation_value"),
        ("pendingSeconds", "pending_seconds"),
        ("durationSeconds", "duration_seconds"),
        ("lastEvaluationValue", "last_evaluation_value"),
    ];
    let mut output = Vec::new();
    for (field, name) in keys {
        let Some(value) = object.get(field) else {
            continue;
        };
        let value = value
            .as_f64()
            .map(|value| value.to_string())
            .or_else(|| value.as_str().map(str::to_owned));
        if let Some(value) = value
            && let Ok(evidence) = NumericEvidenceDigest::from_value(name, &value)
        {
            output.push(evidence);
        }
    }
    output
}

fn parse_incident_state(value: &str) -> IncidentState {
    match value.to_ascii_lowercase().as_str() {
        "open" | "active" | "triggered" => IncidentState::Open,
        "closed" | "resolved" | "recovered" => IncidentState::Closed,
        _ => IncidentState::Unknown,
    }
}

fn next_page_digest(value: &Value) -> Result<Option<Digest>, AlertResultError> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(token) = first_text(
        object,
        &["nextPageToken", "next_page_token", "nextPage", "next_page"],
    ) else {
        return Ok(None);
    };
    if token.len() > MAX_IDENTIFIER_BYTES || token.trim() != token {
        return Err(AlertResultError::InvalidPage);
    }
    Ok((!token.is_empty()).then(|| sha256_digest(token.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CloudStack, GrafanaAlertScope, GrafanaAlertScopeSpec, GrafanaApiDefinition,
        GrafanaPermissionSnapshot, IdentityBinding, SecretReference,
    };

    #[test]
    fn unbound_recording_response_is_bound_without_retaining_raw_payload_in_debug() {
        let request = test_request();
        let response = GrafanaHttpResponse::new(200, br#"{"state":"Alerting"}"#.to_vec())
            .bind_to_request(&request);
        let debug = format!("{response:?}");
        assert!(debug.contains("body_digest"));
        assert!(!debug.contains("Alerting"));
        assert_eq!(response.status(), 200);
    }

    #[test]
    fn recorded_faults_cover_requested_http_and_environment_failures() {
        assert_eq!(
            RecordedFault::Unauthorized401.error(),
            GrafanaTransportError::Unauthorized401
        );
        assert_eq!(
            RecordedFault::Conflict409.error(),
            GrafanaTransportError::Conflict409
        );
        assert_eq!(
            RecordedFault::RateLimited429 {
                retry_after_seconds: Some(7)
            }
            .error(),
            GrafanaTransportError::RateLimited429 {
                retry_after_seconds: Some(7)
            }
        );
        assert_eq!(
            BlockedEnvGrafanaTransport
                .send(&test_request())
                .unwrap_err(),
            GrafanaTransportError::BlockedEnv
        );
    }

    fn test_request() -> GrafanaHttpRequest {
        let scope = test_scope();
        let provider = GrafanaProvider::new(scope, RecordingGrafanaTransport::new()).unwrap();
        let proposal = AlertResultProposal::new(
            provider.scope(),
            provider.registration(),
            AlertResultReadOperation::ReadAlertInstances,
            10,
        )
        .unwrap();
        provider.compile_request(&proposal, 1, None).unwrap()
    }

    fn test_scope() -> GrafanaAlertScope {
        let binding = |id: &str| IdentityBinding::new(id, 1).unwrap();
        GrafanaAlertScope::new(GrafanaAlertScopeSpec::new(
            CloudStack::new("stack-1", 1, "https://grafana.example.com").unwrap(),
            binding("org-1"),
            binding("folder-1"),
            binding("rule-1"),
            binding("group-1"),
            binding("instance-1"),
            binding("project-1"),
            binding("mission-1"),
            binding("deploy-1"),
            binding("release-1"),
            GrafanaApiDefinition::layer1(),
            GrafanaPermissionSnapshot::least_privilege(1).unwrap(),
            SecretReference::service_account_token("opaque", 1).unwrap(),
        ))
        .unwrap()
    }
}

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    CONTRACT_VERSION, MAX_AUDIT_LOGS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, PROVIDER_ID,
    PROVIDER_VERSION, contract_digest,
    error::{Result, TinesAutomationResultError},
    model::{
        ActionId, CaseId, Digest, EventId, EvidenceClassification, RegistrationRevocationReceipt,
        SecretReference, StoryId, StoryRunGuid, TinesActionSummary, TinesAuditLogSummary,
        TinesAutomationEvidence, TinesAutomationScope, TinesCaseSummary, TinesEventSummary,
        TinesEvidenceState, TinesHttpMethod, TinesPermissionSet, TinesRateLimitReceipt,
        TinesReadOperation, TinesRegistration, TinesStoryRunSummary, TinesStorySummary,
        TransportProvenance, canonical_digest,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TinesTransportError {
    #[error("Tines native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Tines transport timed out")]
    Timeout,
    #[error("Tines transport failed without a native response")]
    ProviderUnknown,
    #[error("Tines transport was rate limited")]
    RateLimited { retry_after_seconds: u32 },
}

/// A bounded provider response. The raw body is retained only inside the
/// provider parser and is never serialised, debug-printed, or put in a
/// proposal. Layer 1 exposes its digest and byte count instead.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub retry_after_seconds: Option<u32>,
}

impl fmt::Debug for TinesResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TinesResponse")
            .field("status", &self.status)
            .field("body_digest", &crate::sha256_hex(&self.body))
            .field("body_bytes", &self.body.len())
            .field("retry_after_seconds", &self.retry_after_seconds)
            .finish()
    }
}

impl TinesResponse {
    /// Builds a bounded fixture response from a serializable value.
    ///
    /// # Panics
    ///
    /// Panics if the fixture value cannot be serialized. The intended fixture
    /// values are closed JSON-compatible data.
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self {
            status,
            body: serde_json::to_vec(value).expect("Tines fixture payload serializes"),
            retry_after_seconds: None,
        }
    }

    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            retry_after_seconds: None,
        }
    }

    #[must_use]
    pub fn with_retry_after(mut self, retry_after_seconds: u32) -> Self {
        self.retry_after_seconds = Some(retry_after_seconds);
        self
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        crate::sha256_hex(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    fn json_value(&self) -> std::result::Result<Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TinesRequest {
    pub operation: TinesReadOperation,
    pub method: TinesHttpMethod,
    pub host: String,
    pub path: String,
    pub page: u16,
    pub per_page: u16,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl TinesRequest {
    pub fn new(
        scope: &TinesAutomationScope,
        secret: &SecretReference,
        operation: TinesReadOperation,
        page: u16,
    ) -> Result<Self> {
        scope.validate_integrity()?;
        if page == 0 || page > MAX_PAGES {
            return Err(TinesAutomationResultError::PaginationExceeded);
        }
        if scope.tenant().as_str().starts_with("http") {
            return Err(TinesAutomationResultError::InvalidIdentifier { label: "tenant" });
        }
        let per_page = MAX_PAGE_SIZE;
        let host = format!("https://{}", scope.tenant());
        let path = match operation {
            TinesReadOperation::GetStory => {
                format!("/api/v1/stories/{}", scope.story())
            }
            TinesReadOperation::GetStoryRunSummary => format!(
                "/api/v1/stories/{}/runs/{}/summary",
                scope.story(),
                scope
                    .story_run()
                    .ok_or(TinesAutomationResultError::ScopeMismatch)?
            ),
            TinesReadOperation::GetAction => format!(
                "/api/v1/actions/{}",
                scope
                    .action()
                    .ok_or(TinesAutomationResultError::ScopeMismatch)?
            ),
            TinesReadOperation::GetEvent => format!(
                "/api/v1/events/{}?exclude_previous_event_payloads=true",
                scope
                    .event()
                    .ok_or(TinesAutomationResultError::ScopeMismatch)?
            ),
            TinesReadOperation::GetCase => format!(
                "/api/v1/cases/{}",
                scope
                    .case_id()
                    .ok_or(TinesAutomationResultError::ScopeMismatch)?
            ),
            TinesReadOperation::ListAuditLogs => format!(
                "/api/v1/audit_logs?after={}&before={}&page={page}&per_page={per_page}",
                scope.time_window().start_rfc3339(),
                scope.time_window().end_rfc3339(),
            ),
        };
        let request_digest = canonical_digest(&(
            operation,
            TinesHttpMethod::Get,
            &host,
            &path,
            page,
            per_page,
            scope.digest(),
            scope.permissions().digest(),
            scope.consent().digest(),
            secret.digest(),
        ));
        Ok(Self {
            operation,
            method: TinesHttpMethod::Get,
            host,
            path,
            page,
            per_page,
            scope_digest: scope.digest(),
            permission_digest: scope.permissions().digest(),
            consent_digest: scope.consent().digest(),
            secret_reference_digest: secret.digest().clone(),
            request_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.request_digest.clone()
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        if self.method != TinesHttpMethod::Get
            || !self.host.starts_with("https://")
            || self.host.len() <= "https://".len()
            || self.page == 0
            || self.page > MAX_PAGES
            || self.per_page == 0
            || self.per_page > MAX_PAGE_SIZE
        {
            return false;
        }
        match self.operation {
            TinesReadOperation::GetStory => self.path.starts_with("/api/v1/stories/"),
            TinesReadOperation::GetStoryRunSummary => {
                self.path.starts_with("/api/v1/stories/") && self.path.ends_with("/summary")
            }
            TinesReadOperation::GetAction => self.path.starts_with("/api/v1/actions/"),
            TinesReadOperation::GetEvent => {
                self.path.starts_with("/api/v1/events/")
                    && self.path.contains("exclude_previous_event_payloads=true")
            }
            TinesReadOperation::GetCase => self.path.starts_with("/api/v1/cases/"),
            TinesReadOperation::ListAuditLogs => {
                self.path.starts_with("/api/v1/audit_logs?after=")
                    && self.path.contains("&before=")
                    && self.path.contains("&page=")
                    && self.path.contains("&per_page=")
            }
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        let expected = canonical_digest(&(
            self.operation,
            self.method,
            &self.host,
            &self.path,
            self.page,
            self.per_page,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
        ));
        if self.request_digest != expected || !self.is_allowlisted() {
            return Err(TinesAutomationResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TinesProviderDefinition {
    pub id: &'static str,
    pub version: &'static str,
    pub api_revision: &'static str,
    pub allowlisted_get_paths: &'static [&'static str],
    pub max_page_size: u16,
    pub max_pages: u16,
    pub max_response_bytes: usize,
}

impl TinesProviderDefinition {
    pub const fn current() -> Self {
        Self {
            id: PROVIDER_ID,
            version: PROVIDER_VERSION,
            api_revision: crate::PROVIDER_API_REVISION,
            allowlisted_get_paths: &[
                "/api/v1/stories/{story_id}",
                "/api/v1/stories/{story_id}/runs/{story_run_guid}/summary",
                "/api/v1/actions/{action_id}",
                "/api/v1/events/{event_id}",
                "/api/v1/cases/{case_id}",
                "/api/v1/audit_logs",
            ],
            max_page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }

    #[must_use]
    pub fn digest(&self, permissions: &TinesPermissionSet) -> Digest {
        canonical_digest(&(
            self.id,
            self.version,
            self.api_revision,
            self.allowlisted_get_paths,
            self.max_page_size,
            self.max_pages,
            self.max_response_bytes,
            permissions.digest(),
            contract_digest(),
        ))
    }
}

pub trait TinesTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &TinesRequest,
    ) -> std::result::Result<TinesResponse, TinesTransportError>;
}

#[derive(Clone, Debug, Default)]
pub struct FixtureTransport {
    responses: BTreeMap<TinesReadOperation, TinesResponse>,
    fallback: Option<TinesResponse>,
}

impl FixtureTransport {
    #[must_use]
    pub fn new(response: TinesResponse) -> Self {
        Self {
            responses: BTreeMap::new(),
            fallback: Some(response),
        }
    }

    #[must_use]
    pub fn from_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = (TinesReadOperation, TinesResponse)>,
    {
        Self {
            responses: responses.into_iter().collect(),
            fallback: None,
        }
    }

    pub fn insert(&mut self, operation: TinesReadOperation, response: TinesResponse) {
        self.responses.insert(operation, response);
    }
}

impl TinesTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &TinesRequest,
    ) -> std::result::Result<TinesResponse, TinesTransportError> {
        self.responses
            .get(&request.operation)
            .or(self.fallback.as_ref())
            .cloned()
            .ok_or(TinesTransportError::ProviderUnknown)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    responses: BTreeMap<TinesReadOperation, TinesResponse>,
    fallback: Option<TinesResponse>,
    requests: Vec<TinesRequest>,
}

impl RecordingTransport {
    #[must_use]
    pub fn new(response: TinesResponse) -> Self {
        Self {
            responses: BTreeMap::new(),
            fallback: Some(response),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = (TinesReadOperation, TinesResponse)>,
    {
        Self {
            responses: responses.into_iter().collect(),
            fallback: None,
            requests: Vec::new(),
        }
    }

    pub fn insert(&mut self, operation: TinesReadOperation, response: TinesResponse) {
        self.responses.insert(operation, response);
    }

    #[must_use]
    pub fn requests(&self) -> &[TinesRequest] {
        &self.requests
    }
}

impl TinesTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &TinesRequest,
    ) -> std::result::Result<TinesResponse, TinesTransportError> {
        self.requests.push(request.clone());
        self.responses
            .get(&request.operation)
            .or(self.fallback.as_ref())
            .cloned()
            .ok_or(TinesTransportError::ProviderUnknown)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    responses: BTreeMap<TinesReadOperation, TinesResponse>,
    fallback: Option<TinesResponse>,
    requests: Vec<TinesRequest>,
}

impl LoopbackTransport {
    #[must_use]
    pub fn new(response: TinesResponse) -> Self {
        Self {
            responses: BTreeMap::new(),
            fallback: Some(response),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = (TinesReadOperation, TinesResponse)>,
    {
        Self {
            responses: responses.into_iter().collect(),
            fallback: None,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[TinesRequest] {
        &self.requests
    }
}

impl TinesTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &TinesRequest,
    ) -> std::result::Result<TinesResponse, TinesTransportError> {
        self.requests.push(request.clone());
        self.responses
            .get(&request.operation)
            .or(self.fallback.as_ref())
            .cloned()
            .ok_or(TinesTransportError::ProviderUnknown)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl TinesTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &TinesRequest,
    ) -> std::result::Result<TinesResponse, TinesTransportError> {
        Err(TinesTransportError::BlockedEnv)
    }
}

pub struct TinesProvider<T> {
    scope: TinesAutomationScope,
    secret: SecretReference,
    permissions: TinesPermissionSet,
    provider_digest: Digest,
    registration: TinesRegistration,
    transport: T,
}

impl<T: fmt::Debug> fmt::Debug for TinesProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TinesProvider")
            .field("scope_digest", &self.scope.digest())
            .field("provider_digest", &self.provider_digest)
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: TinesTransport> TinesProvider<T> {
    pub fn new(scope: TinesAutomationScope, secret: SecretReference, transport: T) -> Result<Self> {
        let permissions = scope.permissions().clone();
        permissions.validate_for_scope(&scope)?;
        let definition = TinesProviderDefinition::current();
        let provider_digest = definition.digest(&permissions);
        let registration = TinesRegistration::new(
            CONTRACT_VERSION,
            &contract_digest(),
            PROVIDER_ID,
            PROVIDER_VERSION,
            &provider_digest,
            &scope,
            &secret,
        )?;
        Ok(Self {
            scope,
            secret,
            permissions,
            provider_digest,
            registration,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &TinesAutomationScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    #[must_use]
    pub fn permissions(&self) -> &TinesPermissionSet {
        &self.permissions
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn registration(&self) -> &TinesRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt> {
        self.registration
            .validate(&self.scope, &self.secret, &self.provider_digest)?;
        Ok(self.registration.revoke())
    }

    pub fn restore(&mut self) -> Result<RegistrationRevocationReceipt> {
        if self.registration.contract_digest != contract_digest()
            || self.registration.contract_version != CONTRACT_VERSION
            || self.registration.provider_digest != self.provider_digest
            || self.registration.provider_id != PROVIDER_ID
            || self.registration.provider_version != PROVIDER_VERSION
            || self.registration.scope_digest != self.scope.digest()
            || self.registration.permission_digest != self.permissions.digest()
            || self.registration.secret_reference_digest != *self.secret.digest()
            || self.registration.registration_digest != self.registration.calculate_digest()
        {
            return Err(TinesAutomationResultError::TamperedEvidence);
        }
        Ok(self.registration.restore())
    }

    pub fn read(&mut self) -> Result<TinesAutomationEvidence> {
        self.registration
            .validate(&self.scope, &self.secret, &self.provider_digest)?;
        self.scope.consent().validate_at(Utc::now())?;

        let mut request_digests = Vec::new();
        let mut response_digests = Vec::new();
        let provenance = self.transport.provenance();
        let mut story = None;
        let mut story_run = None;
        let mut action = None;
        let mut event = None;
        let mut case_summary = None;
        let mut audit_logs = Vec::new();
        let mut response_bytes = 0_usize;
        let mut pages_read = 0_u16;
        let mut partial = false;
        let mut state = TinesEvidenceState::Partial;
        let mut classification = EvidenceClassification::BoundedObservation;
        let mut rate_limit = None;

        let operations = [
            Some(TinesReadOperation::GetStory),
            self.scope
                .story_run()
                .map(|_| TinesReadOperation::GetStoryRunSummary),
            self.scope.action().map(|_| TinesReadOperation::GetAction),
            self.scope.event().map(|_| TinesReadOperation::GetEvent),
            self.scope.case_id().map(|_| TinesReadOperation::GetCase),
            Some(TinesReadOperation::ListAuditLogs),
        ];

        for operation in operations.into_iter().flatten() {
            let request = TinesRequest::new(&self.scope, &self.secret, operation, 1)?;
            request.validate_integrity().map_err(|error| {
                if matches!(error, TinesAutomationResultError::TamperedEvidence) {
                    TinesAutomationResultError::RequestNotAllowlisted
                } else {
                    error
                }
            })?;
            request_digests.push(request.digest());
            let response = match self.transport.execute(&request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.transport_failure_evidence(
                        request_digests,
                        response_digests,
                        provenance,
                        error,
                    ));
                }
            };
            response_bytes = response_bytes.saturating_add(response.response_bytes());
            if response_bytes > MAX_RESPONSE_BYTES {
                return Err(TinesAutomationResultError::ResponseTooLarge);
            }
            response_digests.push(response.response_digest());
            if response.status == 429 {
                if response
                    .retry_after_seconds
                    .is_some_and(|seconds| seconds > crate::MAX_RETRY_AFTER_SECONDS)
                {
                    let retry_after_seconds = response
                        .retry_after_seconds
                        .unwrap_or(crate::MAX_RETRY_AFTER_SECONDS)
                        .min(crate::MAX_RETRY_AFTER_SECONDS);
                    return Err(TinesAutomationResultError::RateLimited {
                        retry_after_seconds,
                    });
                }
                rate_limit = Some(TinesRateLimitReceipt {
                    status: response.status,
                    retry_after_seconds: response.retry_after_seconds,
                    response_bytes: response.response_bytes(),
                });
                state = TinesEvidenceState::RateLimited;
                classification = EvidenceClassification::RateLimited;
                break;
            }
            if (400..500).contains(&response.status) {
                state = TinesEvidenceState::AccessLost;
                classification = EvidenceClassification::AccessLost;
                break;
            }
            if response.status >= 500 {
                state = TinesEvidenceState::ProviderUnknown;
                classification = EvidenceClassification::ProviderUnknown;
                break;
            }
            if !(200..300).contains(&response.status) {
                state = TinesEvidenceState::ProviderUnknown;
                classification = EvidenceClassification::ProviderUnknown;
                break;
            }
            if response.status == 206 {
                partial = true;
            }
            let value = if let Ok(value) = response.json_value() {
                value
            } else {
                state = TinesEvidenceState::ProviderUnknown;
                classification = EvidenceClassification::ProviderUnknown;
                break;
            };
            match operation {
                TinesReadOperation::GetStory => {
                    story = Some(parse_story(
                        &value,
                        self.scope.story(),
                        &response.response_digest(),
                    )?);
                }
                TinesReadOperation::GetStoryRunSummary => {
                    story_run = Some(parse_story_run(
                        &value,
                        self.scope.story(),
                        self.scope
                            .story_run()
                            .ok_or(TinesAutomationResultError::ScopeMismatch)?,
                        &response.response_digest(),
                    )?);
                    state = story_run
                        .as_ref()
                        .map_or(TinesEvidenceState::Partial, |run| run.state);
                }
                TinesReadOperation::GetAction => {
                    action = Some(parse_action(
                        &value,
                        self.scope.story(),
                        self.scope
                            .action()
                            .ok_or(TinesAutomationResultError::ScopeMismatch)?,
                        &response.response_digest(),
                    )?);
                }
                TinesReadOperation::GetEvent => {
                    event = Some(parse_event(
                        &value,
                        self.scope
                            .event()
                            .ok_or(TinesAutomationResultError::ScopeMismatch)?,
                        self.scope.action(),
                        self.scope.story_run(),
                        &response.response_digest(),
                    )?);
                }
                TinesReadOperation::GetCase => {
                    case_summary = Some(parse_case(
                        &value,
                        self.scope
                            .case_id()
                            .ok_or(TinesAutomationResultError::ScopeMismatch)?,
                        &response.response_digest(),
                    )?);
                }
                TinesReadOperation::ListAuditLogs => {
                    let (logs, pages) = parse_audit_logs(
                        &value,
                        self.scope.story(),
                        &self.scope.time_window().start,
                        &self.scope.time_window().end,
                    )?;
                    audit_logs = logs;
                    pages_read = pages;
                    if pages > MAX_PAGES {
                        return Err(TinesAutomationResultError::PaginationExceeded);
                    }
                    if pages > 1 {
                        partial = true;
                    }
                }
            }
        }

        if audit_logs.len() > MAX_AUDIT_LOGS {
            return Err(TinesAutomationResultError::PartialEvidence);
        }
        if story_run.is_none() || story.is_none() {
            partial = true;
            if matches!(state, TinesEvidenceState::Partial) {
                state = TinesEvidenceState::Partial;
            }
        }
        if partial
            && matches!(
                classification,
                EvidenceClassification::BoundedObservation | EvidenceClassification::Partial
            )
        {
            state = TinesEvidenceState::Partial;
        }
        if partial {
            classification = EvidenceClassification::Partial;
        }
        let evidence = TinesAutomationEvidence {
            scope_digest: self.scope.digest(),
            provider_digest: self.provider_digest.clone(),
            request_digests,
            response_digests,
            story,
            story_run,
            action,
            event,
            case_summary,
            audit_logs,
            state,
            classification,
            partial,
            pages_read,
            response_bytes,
            rate_limit,
            provenance,
            evidence_digest: String::new(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
        .seal();
        evidence.validate_integrity(&self.scope, &self.provider_digest)?;
        Ok(evidence)
    }

    fn transport_failure_evidence(
        &self,
        request_digests: Vec<Digest>,
        response_digests: Vec<Digest>,
        provenance: TransportProvenance,
        error: TinesTransportError,
    ) -> TinesAutomationEvidence {
        let (state, classification, rate_limit) = match error {
            TinesTransportError::BlockedEnv => (
                TinesEvidenceState::AccessLost,
                EvidenceClassification::BlockedEnv,
                None,
            ),
            TinesTransportError::Timeout | TinesTransportError::ProviderUnknown => (
                TinesEvidenceState::ProviderUnknown,
                EvidenceClassification::ProviderUnknown,
                None,
            ),
            TinesTransportError::RateLimited {
                retry_after_seconds,
            } => (
                TinesEvidenceState::RateLimited,
                EvidenceClassification::RateLimited,
                Some(TinesRateLimitReceipt {
                    status: 429,
                    retry_after_seconds: Some(
                        retry_after_seconds.min(crate::MAX_RETRY_AFTER_SECONDS),
                    ),
                    response_bytes: 0,
                }),
            ),
        };
        TinesAutomationEvidence {
            scope_digest: self.scope.digest(),
            provider_digest: self.provider_digest.clone(),
            request_digests,
            response_digests,
            story: None,
            story_run: None,
            action: None,
            event: None,
            case_summary: None,
            audit_logs: Vec::new(),
            state,
            classification,
            partial: true,
            pages_read: 0,
            response_bytes: 0,
            rate_limit,
            provenance,
            evidence_digest: String::new(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
        .seal()
    }
}

fn value_object(value: &Value) -> Map<String, Value> {
    value
        .as_object()
        .and_then(|object| object.get("story_run").and_then(Value::as_object))
        .cloned()
        .unwrap_or_else(|| value.as_object().cloned().unwrap_or_default())
}

fn value_string(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| match object.get(*key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    })
}

fn value_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    let object = value.as_object()?;
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_u64))
}

fn value_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    let object = value.as_object()?;
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
}

fn value_time(value: &Value, keys: &[&str]) -> Option<DateTime<Utc>> {
    value_string(value, keys)?.parse::<DateTime<Utc>>().ok()
}

fn parse_story(
    value: &Value,
    expected: &StoryId,
    response_digest: &str,
) -> Result<TinesStorySummary> {
    let id =
        StoryId::new(value_string(value, &["id", "guid"]).unwrap_or_else(|| expected.to_string()))?;
    Ok(TinesStorySummary {
        id,
        revision: revision_for(value, response_digest),
        mode_digest: value_string(value, &["mode"]).map(|mode| crate::sha256_hex(mode.as_bytes())),
        published: value_bool(value, &["published"]),
        disabled: value_bool(value, &["disabled"]),
        observed_at: value_time(value, &["edited_at", "updated_at", "created_at"]),
    })
}

fn parse_story_run(
    value: &Value,
    expected_story: &StoryId,
    expected_run: &StoryRunGuid,
    response_digest: &str,
) -> Result<TinesStoryRunSummary> {
    let object = value_object(value);
    let guid = StoryRunGuid::new(
        value_string(&Value::Object(object.clone()), &["guid", "story_run_guid"])
            .unwrap_or_else(|| expected_run.to_string()),
    )?;
    let story_id = StoryId::new(
        value_string(&Value::Object(object.clone()), &["story_id"])
            .unwrap_or_else(|| expected_story.to_string()),
    )?;
    let state = parse_state(&Value::Object(object.clone()));
    Ok(TinesStoryRunSummary {
        guid,
        story_id,
        revision: revision_for(&Value::Object(object.clone()), response_digest),
        state,
        start_time: value_time(
            &Value::Object(object.clone()),
            &["start_time", "started_at"],
        ),
        end_time: value_time(&Value::Object(object.clone()), &["end_time", "finished_at"]),
        duration_seconds: value_u64(
            &Value::Object(object.clone()),
            &["duration", "duration_seconds"],
        ),
        action_count: value_u64(&Value::Object(object.clone()), &["action_count"]).unwrap_or(0),
        event_count: value_u64(&Value::Object(object), &["event_count"]).unwrap_or(0),
    })
}

fn parse_action(
    value: &Value,
    expected_story: &StoryId,
    expected_action: &ActionId,
    response_digest: &str,
) -> Result<TinesActionSummary> {
    let id = ActionId::new(
        value_string(value, &["id", "guid"]).unwrap_or_else(|| expected_action.to_string()),
    )?;
    let story_id = StoryId::new(
        value_string(value, &["story_id"]).unwrap_or_else(|| expected_story.to_string()),
    )?;
    Ok(TinesActionSummary {
        id,
        story_id,
        revision: revision_for(value, response_digest),
        disabled: value_bool(value, &["disabled"]),
        event_count: value_u64(value, &["blended_events_count", "events_count"]),
        last_event_at: value_time(value, &["last_event_at", "last_receive_at"]),
    })
}

fn parse_event(
    value: &Value,
    expected_event: &EventId,
    expected_action: Option<&ActionId>,
    expected_run: Option<&StoryRunGuid>,
    response_digest: &str,
) -> Result<TinesEventSummary> {
    let id =
        EventId::new(value_string(value, &["id"]).unwrap_or_else(|| expected_event.to_string()))?;
    let action_id = ActionId::new(
        value_string(value, &["agent_id", "action_id"])
            .or_else(|| expected_action.map(ToString::to_string))
            .unwrap_or_else(|| "unknown-action".to_owned()),
    )?;
    let story_run = value_string(value, &["story_run_guid", "story_run"])
        .or_else(|| expected_run.map(ToString::to_string))
        .map(StoryRunGuid::new)
        .transpose()?;
    let payload_digest = value
        .as_object()
        .and_then(|object| object.get("payload"))
        .map_or_else(|| response_digest.to_owned(), canonical_digest);
    Ok(TinesEventSummary {
        id,
        action_id,
        story_run,
        revision: revision_for(value, response_digest),
        observed_at: value_time(value, &["created_at", "updated_at"]),
        payload_digest,
        re_emitted: value_bool(value, &["re_emitted"]).unwrap_or(false),
    })
}

fn parse_case(
    value: &Value,
    expected_case: &CaseId,
    response_digest: &str,
) -> Result<TinesCaseSummary> {
    let object = value
        .as_object()
        .and_then(|object| object.get("case").and_then(Value::as_object))
        .cloned()
        .unwrap_or_else(|| value.as_object().cloned().unwrap_or_default());
    let wrapped = Value::Object(object.clone());
    Ok(TinesCaseSummary {
        id: CaseId::new(
            value_string(&wrapped, &["id", "guid"]).unwrap_or_else(|| expected_case.to_string()),
        )?,
        revision: revision_for(&wrapped, response_digest),
        state_digest: value_string(&wrapped, &["state", "status"])
            .map(|state| crate::sha256_hex(state.as_bytes())),
        opened_at: value_time(&wrapped, &["created_at", "opened_at"]),
        closed_at: value_time(&wrapped, &["closed_at", "updated_at"]),
        item_count: value_u64(&wrapped, &["items_count", "item_count"]),
    })
}

fn parse_audit_logs(
    value: &Value,
    expected_story: &StoryId,
    start: &DateTime<Utc>,
    end: &DateTime<Utc>,
) -> Result<(Vec<TinesAuditLogSummary>, u16)> {
    let Some(object) = value.as_object() else {
        return Err(TinesAutomationResultError::MalformedResponse);
    };
    let entries = object
        .get("audit_logs")
        .and_then(Value::as_array)
        .or_else(|| object.get("logs").and_then(Value::as_array))
        .cloned()
        .unwrap_or_default();
    let meta = object.get("meta");
    let pages = meta
        .and_then(|meta| meta.get("pages"))
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let pages = u16::try_from(pages).map_err(|_| TinesAutomationResultError::PaginationExceeded)?;
    let mut result = Vec::new();
    for (index, entry) in entries.into_iter().enumerate() {
        if result.len() == MAX_AUDIT_LOGS {
            return Err(TinesAutomationResultError::PartialEvidence);
        }
        let id = value_string(&entry, &["id"]).unwrap_or_else(|| format!("audit-{index}"));
        let created_at = value_time(&entry, &["created_at", "updated_at"]);
        if let Some(timestamp) = created_at {
            if timestamp < *start || timestamp > *end {
                return Err(TinesAutomationResultError::OutOfScopeTime);
            }
        }
        let story_id = value_string(&entry, &["story_id"])
            .map(StoryId::new)
            .transpose()?;
        if story_id
            .as_ref()
            .is_some_and(|story| story != expected_story)
        {
            return Err(TinesAutomationResultError::ScopeMismatch);
        }
        let operation_digest = value_string(&entry, &["operation_name"]).map_or_else(
            || crate::sha256_hex(b"tines-audit-operation-unknown"),
            |operation| crate::sha256_hex(operation.as_bytes()),
        );
        let actor_digest = value_string(&entry, &["user_id", "user_email", "user_name"])
            .map(|actor| crate::sha256_hex(actor.as_bytes()));
        let inputs_digest = entry
            .as_object()
            .and_then(|object| object.get("inputs"))
            .map(canonical_digest);
        let outputs_digest = entry
            .as_object()
            .and_then(|object| object.get("outputs"))
            .map(canonical_digest);
        let revision = revision_for(&entry, &canonical_digest(&entry));
        result.push(TinesAuditLogSummary {
            id,
            revision,
            story_id,
            created_at,
            operation_digest,
            actor_digest,
            inputs_digest,
            outputs_digest,
        });
    }
    Ok((result, pages))
}

fn revision_for(value: &Value, fallback: &str) -> crate::Revision {
    let digest = value
        .as_object()
        .and_then(|object| {
            [
                "edited_at",
                "updated_at",
                "created_at",
                "start_time",
                "end_time",
            ]
            .into_iter()
            .find_map(|key| object.get(key).and_then(Value::as_str))
        })
        .map_or_else(
            || fallback.to_owned(),
            |timestamp| crate::sha256_hex(timestamp.as_bytes()),
        );
    crate::Revision::from_digest(&digest)
}

fn parse_state(value: &Value) -> TinesEvidenceState {
    let raw = value_string(value, &["status", "state", "run_status", "result"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    match raw.as_str() {
        "queued" | "pending" => TinesEvidenceState::Queued,
        "running" | "in_progress" | "in-progress" => TinesEvidenceState::Running,
        "succeeded" | "success" | "completed" | "complete" => TinesEvidenceState::Succeeded,
        "failed" | "failure" | "error" => TinesEvidenceState::Failed,
        "cancelled" | "canceled" | "stopped" => TinesEvidenceState::Cancelled,
        "expired" | "timeout" | "timed_out" => TinesEvidenceState::Expired,
        _ => TinesEvidenceState::ProviderUnknown,
    }
}

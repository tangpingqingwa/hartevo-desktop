//! Bounded Sift read requests, redacted responses, and non-native transports.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Value, json};

use crate::error::{Result, SiftFraudResultError, SiftTransportError};
use crate::model::{
    Digest, SiftDecisionDisposition, SiftDecisionProjection, SiftFraudResultScope,
    SiftReviewProjection, SiftReviewState, SiftScoreProjection, SiftWorkflowProjection,
    SiftWorkflowState, TransportProvenance,
};
use crate::{MAX_DIAGNOSTIC_BYTES, MAX_RESPONSE_BYTES, PROVIDER_ID, PROVIDER_VERSION};

pub const SIFT_API_BASE_URL: &str = "https://api.sift.com";
pub const SIFT_PROVIDER_ID: &str = PROVIDER_ID;
pub const SIFT_PROVIDER_VERSION: &str = PROVIDER_VERSION;
pub const SIFT_API_REVISION: &str = "sift-decisions-score-workflow-status-r1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiftOperation {
    DecisionStatus,
    Score,
    WorkflowStatus,
}

impl SiftOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DecisionStatus => "decision_status",
            Self::Score => "score",
            Self::WorkflowStatus => "workflow_status",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub base_url: String,
    pub operations: Vec<String>,
    pub allowed_transports: Vec<TransportProvenance>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub external_writes: bool,
    pub event_ingestion: bool,
    pub decision_mutation: bool,
    pub workflow_mutation: bool,
}

impl Default for SiftProviderDefinition {
    fn default() -> Self {
        Self {
            id: SIFT_PROVIDER_ID.to_owned(),
            version: SIFT_PROVIDER_VERSION.to_owned(),
            api_revision: SIFT_API_REVISION.to_owned(),
            base_url: SIFT_API_BASE_URL.to_owned(),
            operations: vec![
                "GET /v3/accounts/{accountId}/users/{userId}/decisions".to_owned(),
                "GET /v3/accounts/{accountId}/orders/{orderId}/decisions".to_owned(),
                "GET /v205/users/{userId}/score".to_owned(),
                "RECORDED GET /v205/workflows/{workflowId}/status".to_owned(),
            ],
            allowed_transports: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fixture,
                TransportProvenance::Fake,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            external_writes: false,
            event_ingestion: false,
            decision_mutation: false,
            workflow_mutation: false,
        }
    }
}

impl SiftProviderDefinition {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "sift-provider/v1",
            &[
                ("id", self.id.clone()),
                ("version", self.version.clone()),
                ("api", self.api_revision.clone()),
                ("base_url", self.base_url.clone()),
                ("operations", self.operations.join("\n")),
                (
                    "transports",
                    self.allowed_transports
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("external_writes", self.external_writes.to_string()),
                ("event_ingestion", self.event_ingestion.to_string()),
                ("decision_mutation", self.decision_mutation.to_string()),
                ("workflow_mutation", self.workflow_mutation.to_string()),
            ],
        )
    }

    pub const fn is_layer_one_honest(&self) -> bool {
        !self.connected
            && !self.native
            && !self.first_party
            && !self.provider_receipt
            && !self.external_writes
            && !self.event_ingestion
            && !self.decision_mutation
            && !self.workflow_mutation
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SiftRequest {
    operation: SiftOperation,
    scope_digest: Digest,
    entity_digest: Digest,
    request_digest: Digest,
    path_digest: Digest,
    path_and_query: String,
}

impl SiftRequest {
    pub fn new(scope: &SiftFraudResultScope, operation: SiftOperation) -> Result<Self> {
        scope.validate()?;
        let path_and_query = match operation {
            SiftOperation::DecisionStatus => format!(
                "/v3/accounts/{}/entities/{}/decisions",
                digest_prefix(&scope.account().digest()),
                digest_prefix(&scope.entity_digest())
            ),
            SiftOperation::Score => format!(
                "/v205/entities/{}/score?abuse_type={}",
                digest_prefix(&scope.entity_digest()),
                digest_prefix(&scope.score().digest())
            ),
            SiftOperation::WorkflowStatus => format!(
                "/v205/workflows/{}/status",
                digest_prefix(&scope.review().digest())
            ),
        };
        let scope_digest = scope.digest();
        let entity_digest = scope.entity_digest();
        let request_digest = Digest::from_parts(
            "sift-request/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("entity", entity_digest.as_str().to_owned()),
                ("path", path_and_query.clone()),
            ],
        );
        let request = Self {
            operation,
            scope_digest,
            entity_digest,
            request_digest,
            path_digest: Digest::from_text(&path_and_query),
            path_and_query,
        };
        request.validate(scope)?;
        Ok(request)
    }

    pub fn operation(&self) -> SiftOperation {
        self.operation
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn entity_digest(&self) -> &Digest {
        &self.entity_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_digest(&self) -> &Digest {
        &self.path_digest
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    pub fn is_allowlisted(&self) -> bool {
        matches!(
            self.operation,
            SiftOperation::DecisionStatus | SiftOperation::Score | SiftOperation::WorkflowStatus
        )
    }

    fn validate(&self, scope: &SiftFraudResultScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.entity_digest != scope.entity_digest()
            || !self.is_allowlisted()
            || self.path_and_query.contains(scope.user().as_str())
            || self.path_and_query.contains(scope.order().as_str())
        {
            return Err(SiftFraudResultError::ScopeMismatch);
        }
        self.scope_digest.validate()?;
        self.entity_digest.validate()?;
        self.request_digest.validate()?;
        self.path_digest.validate()
    }
}

impl fmt::Debug for SiftRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiftRequest")
            .field("operation", &self.operation)
            .field("scope_digest", &self.scope_digest)
            .field("entity_digest", &self.entity_digest)
            .field("request_digest", &self.request_digest)
            .field("path_digest", &self.path_digest)
            .finish()
    }
}

impl Serialize for SiftRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SiftRequest", 6)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("entityDigest", &self.entity_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &self.path_digest)?;
        state.serialize_field("redacted", &true)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitReceipt {
    pub retry_after_seconds: u32,
    pub bounded: bool,
    pub digest: Digest,
}

impl RateLimitReceipt {
    pub fn new(retry_after_seconds: u32) -> Result<Self> {
        if retry_after_seconds > crate::MAX_RETRY_AFTER_SECONDS {
            return Err(SiftFraudResultError::InvalidRequest);
        }
        let mut receipt = Self {
            retry_after_seconds,
            bounded: true,
            digest: Digest::from_text("unsealed-sift-rate-limit"),
        };
        receipt.digest = receipt.calculate_digest();
        Ok(receipt)
    }

    pub fn throttled(retry_after_seconds: u32) -> Self {
        Self::new(retry_after_seconds.min(crate::MAX_RETRY_AFTER_SECONDS))
            .expect("bounded retry-after value")
    }

    pub fn validate(&self) -> Result<()> {
        if !self.bounded
            || self.retry_after_seconds > crate::MAX_RETRY_AFTER_SECONDS
            || self.digest != self.calculate_digest()
        {
            return Err(SiftFraudResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "sift-rate-limit/v1",
            &[
                ("retry_after_seconds", self.retry_after_seconds.to_string()),
                ("bounded", self.bounded.to_string()),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SiftResponse {
    status: u16,
    body: Vec<u8>,
    rate_limit: Option<RateLimitReceipt>,
}

impl SiftResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            rate_limit: None,
        }
    }

    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::new(
            status,
            serde_json::to_vec(value).expect("Sift fixture JSON serializes"),
        )
    }

    #[must_use]
    pub fn with_rate_limit(mut self, retry_after_seconds: u32) -> Self {
        self.rate_limit = Some(RateLimitReceipt::throttled(retry_after_seconds));
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    pub fn response_digest(&self) -> Digest {
        Digest::from_bytes(&self.body)
    }

    pub fn rate_limit(&self) -> Option<&RateLimitReceipt> {
        self.rate_limit.as_ref()
    }

    fn json_value(&self) -> std::result::Result<Value, SiftTransportError> {
        serde_json::from_slice(&self.body).map_err(|_| SiftTransportError::MalformedResponse)
    }
}

impl fmt::Debug for SiftResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiftResponse")
            .field("status", &self.status)
            .field("response_bytes", &self.response_bytes())
            .field("response_digest", &self.response_digest())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl Serialize for SiftResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SiftResponse", 5)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("responseBytes", &self.response_bytes())?;
        state.serialize_field("responseDigest", &self.response_digest())?;
        state.serialize_field("rateLimit", &self.rate_limit)?;
        state.serialize_field("redacted", &true)?;
        state.end()
    }
}

pub trait SiftTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn send(
        &mut self,
        request: &SiftRequest,
    ) -> std::result::Result<SiftResponse, SiftTransportError>;
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    responses: VecDeque<std::result::Result<SiftResponse, SiftTransportError>>,
    requests: Vec<SiftRequest>,
}

impl RecordingTransport {
    pub fn new(
        responses: impl IntoIterator<Item = std::result::Result<SiftResponse, SiftTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: SiftResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: SiftTransportError) {
        self.responses.push_back(Err(error));
    }

    pub fn requests(&self) -> &[SiftRequest] {
        &self.requests
    }
}

impl SiftTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn send(
        &mut self,
        request: &SiftRequest,
    ) -> std::result::Result<SiftResponse, SiftTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(SiftTransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    response: SiftResponse,
}

impl FixtureTransport {
    pub fn new(response: SiftResponse) -> Self {
        Self { response }
    }

    pub fn for_scope(_scope: &SiftFraudResultScope, _observed_at: DateTime<Utc>) -> Self {
        Self::new(SiftResponse::json(
            200,
            &json!({
                "decision": {"id": "fixture-decision", "category": "WATCH", "abuse_type": "payment_abuse", "time": 1_700_000_000_000_u64},
                "scores": {"payment_abuse": {"score": 0.50, "id": "fixture-score", "time": 1_700_000_000_000_u64}},
                "workflow_statuses": {"status": "running", "review": {"status": "pending", "queue_id": "fixture-review"}}
            }),
        ))
    }
}

impl SiftTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn send(
        &mut self,
        _request: &SiftRequest,
    ) -> std::result::Result<SiftResponse, SiftTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    response: SiftResponse,
}

impl FakeTransport {
    pub fn new(response: SiftResponse) -> Self {
        Self { response }
    }

    pub fn for_scope(scope: &SiftFraudResultScope, observed_at: DateTime<Utc>) -> Self {
        Self::new(FixtureTransport::for_scope(scope, observed_at).response)
    }
}

impl SiftTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn send(
        &mut self,
        _request: &SiftRequest,
    ) -> std::result::Result<SiftResponse, SiftTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    response: SiftResponse,
}

impl LoopbackTransport {
    pub fn new(response: SiftResponse) -> Self {
        Self { response }
    }

    pub fn for_scope(scope: &SiftFraudResultScope, observed_at: DateTime<Utc>) -> Self {
        Self::new(FixtureTransport::for_scope(scope, observed_at).response)
    }
}

impl SiftTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn send(
        &mut self,
        _request: &SiftRequest,
    ) -> std::result::Result<SiftResponse, SiftTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl SiftTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn send(
        &mut self,
        _request: &SiftRequest,
    ) -> std::result::Result<SiftResponse, SiftTransportError> {
        Err(SiftTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiftReadReceipt {
    pub operation: SiftOperation,
    pub scope_digest: Digest,
    pub entity_digest: Digest,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub status: Option<u16>,
    pub response_bytes: Option<usize>,
    pub response_digest: Option<Digest>,
    pub rate_limit: Option<RateLimitReceipt>,
    pub provenance: TransportProvenance,
    pub redacted: bool,
}

impl SiftReadReceipt {
    pub fn failure(request: &SiftRequest, provenance: TransportProvenance) -> Self {
        Self {
            operation: request.operation(),
            scope_digest: request.scope_digest().clone(),
            entity_digest: request.entity_digest().clone(),
            request_digest: request.request_digest().clone(),
            path_digest: request.path_digest().clone(),
            status: None,
            response_bytes: None,
            response_digest: None,
            rate_limit: None,
            provenance,
            redacted: true,
        }
    }

    pub fn success(
        request: &SiftRequest,
        response: &SiftResponse,
        provenance: TransportProvenance,
    ) -> Self {
        Self {
            operation: request.operation(),
            scope_digest: request.scope_digest().clone(),
            entity_digest: request.entity_digest().clone(),
            request_digest: request.request_digest().clone(),
            path_digest: request.path_digest().clone(),
            status: Some(response.status()),
            response_bytes: Some(response.response_bytes()),
            response_digest: Some(response.response_digest()),
            rate_limit: response.rate_limit().cloned(),
            provenance,
            redacted: true,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "sift-read-receipt/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("entity", self.entity_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("path", self.path_digest.as_str().to_owned()),
                (
                    "status",
                    self.status
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "bytes",
                    self.response_bytes
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "response",
                    self.response_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "rate_limit",
                    self.rate_limit
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest.as_str().to_owned()),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("redacted", self.redacted.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.scope_digest,
            &self.entity_digest,
            &self.request_digest,
            &self.path_digest,
        ] {
            digest.validate()?;
        }
        if let Some(response_digest) = &self.response_digest {
            response_digest.validate()?;
        }
        if let Some(rate_limit) = &self.rate_limit {
            rate_limit.validate()?;
        }
        if !self.redacted
            || self
                .response_bytes
                .is_some_and(|bytes| bytes > MAX_RESPONSE_BYTES)
        {
            return Err(SiftFraudResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SiftProviderRead {
    Decision {
        projection: SiftDecisionProjection,
        receipt: SiftReadReceipt,
    },
    Score {
        projection: SiftScoreProjection,
        receipt: SiftReadReceipt,
    },
    Workflow {
        workflow: SiftWorkflowProjection,
        review: SiftReviewProjection,
        receipt: SiftReadReceipt,
    },
}

pub struct SiftProvider<T: SiftTransport> {
    transport: T,
    definition: SiftProviderDefinition,
}

impl<T: SiftTransport> fmt::Debug for SiftProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiftProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .field("provider_digest", &self.provider_digest())
            .finish()
    }
}

impl<T: SiftTransport> SiftProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = SiftProviderDefinition::default();
        if !definition
            .allowed_transports
            .contains(&transport.provenance())
        {
            return Err(SiftFraudResultError::ProviderDefinitionDrift);
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &SiftProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        scope: &SiftFraudResultScope,
        operation: SiftOperation,
    ) -> Result<SiftProviderRead> {
        let request = SiftRequest::new(scope, operation)?;
        let provenance = self.provenance();
        let response = match self.transport.send(&request) {
            Ok(response) => response,
            Err(error) => return Err(SiftFraudResultError::Provider(error)),
        };
        if response.response_bytes() > MAX_RESPONSE_BYTES {
            return Err(SiftFraudResultError::Provider(
                SiftTransportError::ResponseTooLarge,
            ));
        }
        let status_error = status_error(&response);
        if let Some(error) = status_error {
            return Err(SiftFraudResultError::Provider(error));
        }
        let value = response
            .json_value()
            .map_err(SiftFraudResultError::Provider)?;
        let receipt = SiftReadReceipt::success(&request, &response, provenance);
        match operation {
            SiftOperation::DecisionStatus => Ok(SiftProviderRead::Decision {
                projection: parse_decision(&value, scope)?,
                receipt,
            }),
            SiftOperation::Score => Ok(SiftProviderRead::Score {
                projection: parse_score(&value, scope)?,
                receipt,
            }),
            SiftOperation::WorkflowStatus => {
                let (workflow, review) = parse_workflow(&value, scope)?;
                Ok(SiftProviderRead::Workflow {
                    workflow,
                    review,
                    receipt,
                })
            }
        }
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(SiftFraudResultError::UnsupportedMutation(operation))
    }
}

fn status_error(response: &SiftResponse) -> Option<SiftTransportError> {
    match response.status() {
        200..=299 => None,
        401 => Some(SiftTransportError::Unauthorized),
        403 => Some(SiftTransportError::Forbidden),
        404 => Some(SiftTransportError::NotFound),
        408 => Some(SiftTransportError::TimedOut),
        409 => Some(SiftTransportError::Conflict),
        429 => Some(SiftTransportError::RateLimited {
            retry_after_seconds: response
                .rate_limit()
                .map_or(60, |value| value.retry_after_seconds),
        }),
        400..=499 => Some(SiftTransportError::Denied),
        _ => Some(SiftTransportError::ProviderUnknown),
    }
}

fn parse_decision(value: &Value, scope: &SiftFraudResultScope) -> Result<SiftDecisionProjection> {
    let (object, abuse_type) = object_and_key(value, "decision", "latest_decisions")
        .ok_or(SiftFraudResultError::MalformedResponse)?;
    let decision_id = string_field(object, &["id", "decision_id"])
        .unwrap_or_else(|| scope.decision().as_str().to_owned());
    let category = string_field(object, &["category", "action", "status", "decision"])
        .unwrap_or_else(|| "UNKNOWN".to_owned());
    let abuse_type = abuse_type
        .or_else(|| string_field(object, &["abuse_type", "abuseType"]))
        .unwrap_or_else(|| "unknown".to_owned());
    let revision = integer_field(object, &["revision", "version"]).unwrap_or(1);
    Ok(SiftDecisionProjection {
        entity_digest: scope.entity_digest(),
        decision_digest: Digest::from_parts(
            "sift-decision-observation/v1",
            &[("id", decision_id), ("revision", revision.to_string())],
        ),
        abuse_type_digest: Digest::from_parts("sift-abuse-type/v1", &[("value", abuse_type)]),
        disposition: SiftDecisionDisposition::from_provider(&category),
        applied_at: time_field(object),
        revision,
    })
}

fn parse_score(value: &Value, scope: &SiftFraudResultScope) -> Result<SiftScoreProjection> {
    let (object, abuse_type) =
        object_and_key(value, "score", "scores").ok_or(SiftFraudResultError::MalformedResponse)?;
    let raw_score = object
        .get("score")
        .or_else(|| value.get("score"))
        .and_then(Value::as_f64)
        .ok_or(SiftFraudResultError::MalformedResponse)?;
    let normalized_score = if (0.0..=1.0).contains(&raw_score) {
        raw_score * 100.0
    } else {
        raw_score
    };
    if !(0.0..=100.0).contains(&normalized_score) {
        return Err(SiftFraudResultError::MalformedResponse);
    }
    let score = normalized_score.round() as u8;
    let abuse_type = abuse_type
        .or_else(|| string_field(object, &["abuse_type", "abuseType"]))
        .unwrap_or_else(|| scope.score().as_str().to_owned());
    let score_id = string_field(object, &["id", "score_id"])
        .unwrap_or_else(|| scope.score().as_str().to_owned());
    let revision = integer_field(object, &["revision", "version"]).unwrap_or(1);
    Ok(SiftScoreProjection {
        entity_digest: scope.entity_digest(),
        score_digest: Digest::from_parts(
            "sift-score-observation/v1",
            &[
                ("id", score_id),
                ("score", score.to_string()),
                ("revision", revision.to_string()),
            ],
        ),
        abuse_type_digest: Digest::from_parts("sift-abuse-type/v1", &[("value", abuse_type)]),
        score,
        observed_at: time_field(object),
        revision,
    })
}

fn parse_workflow(
    value: &Value,
    scope: &SiftFraudResultScope,
) -> Result<(SiftWorkflowProjection, SiftReviewProjection)> {
    let (object, _) = object_and_key(value, "workflow", "workflow_statuses")
        .or_else(|| value.as_object().map(|object| (object, None)))
        .ok_or(SiftFraudResultError::MalformedResponse)?;
    let status = string_field(object, &["status", "state", "workflow_status"])
        .or_else(|| {
            value
                .get("workflow_status")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let workflow_state = SiftWorkflowState::from_provider(&status);
    let decision_digest = object
        .get("decision")
        .and_then(|decision| decision.as_object())
        .and_then(|decision| string_field(decision, &["id", "decision_id"]))
        .map(|id| Digest::from_parts("sift-workflow-decision/v1", &[("id", id)]));
    let review_object = object
        .get("review")
        .and_then(Value::as_object)
        .or_else(|| value.get("review").and_then(Value::as_object));
    let review_status = review_object
        .and_then(|review| string_field(review, &["status", "state"]))
        .unwrap_or_else(|| {
            if matches!(workflow_state, SiftWorkflowState::Running) {
                "pending".to_owned()
            } else {
                "unknown".to_owned()
            }
        });
    let review_id = review_object
        .and_then(|review| {
            string_field(review, &["id", "review_id", "queue_id", "review_queue_id"])
        })
        .unwrap_or_else(|| scope.review().as_str().to_owned());
    let queue_id = review_object
        .and_then(|review| string_field(review, &["queue_id", "review_queue_id"]))
        .unwrap_or_else(|| review_id.clone());
    let revision = integer_field(object, &["revision", "version"]).unwrap_or(1);
    let review_digest = Digest::from_parts(
        "sift-review-observation/v1",
        &[("id", review_id), ("revision", revision.to_string())],
    );
    let review = SiftReviewProjection {
        review_digest: review_digest.clone(),
        queue_digest: Digest::from_parts("sift-review-queue/v1", &[("id", queue_id)]),
        state: SiftReviewState::from_provider(&review_status),
        revision,
    };
    let workflow_digest = Digest::from_parts(
        "sift-workflow-observation/v1",
        &[
            ("status", status.clone()),
            (
                "decision",
                decision_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("review", review_digest.as_str().to_owned()),
            ("revision", revision.to_string()),
        ],
    );
    Ok((
        SiftWorkflowProjection {
            workflow_digest,
            decision_digest,
            review_digest: Some(review_digest),
            state: workflow_state,
            revision,
        },
        review,
    ))
}

fn object_and_key<'a>(
    value: &'a Value,
    singular: &str,
    plural: &str,
) -> Option<(&'a serde_json::Map<String, Value>, Option<String>)> {
    if let Some(object) = value.get(singular).and_then(Value::as_object) {
        return Some((object, None));
    }
    let map = value.get(plural).and_then(Value::as_object)?;
    let (key, value) = map.iter().next()?;
    Some((value.as_object()?, Some(key.clone())))
}

fn string_field(object: &serde_json::Map<String, Value>, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str).map(str::to_owned))
}

fn integer_field(object: &serde_json::Map<String, Value>, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_u64))
}

fn time_field(object: &serde_json::Map<String, Value>) -> Option<DateTime<Utc>> {
    let millis = integer_field(object, &["time", "timestamp", "observed_at"])?;
    DateTime::from_timestamp_millis(i64::try_from(millis).ok()?)
}

fn digest_prefix(digest: &Digest) -> &str {
    &digest.as_str()[..16]
}

#[allow(dead_code)]
fn bounded_diagnostic(value: &str) -> String {
    value.chars().take(MAX_DIAGNOSTIC_BYTES).collect()
}

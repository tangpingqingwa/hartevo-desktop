use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{GreenhouseError, TransportError};
use crate::model::{
    ApplicationState, BoundedTimestamp, CandidateReference, CapabilitySet, Digest,
    EvidenceCompleteness, GreenhouseHiringEvidence, GreenhouseScope, OfferEvidence, OfferId,
    OfferState, ProviderRevision, RedactionSummary, RequestDigestInput, RequestReceipt, Revision,
    ScorecardAggregate, ScorecardId, SecretReference, StageId, StageTransition,
    TransportProvenance,
};
use crate::{
    MAX_OFFERS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_SCORECARDS,
    MAX_STAGE_TRANSITIONS, PROVIDER_API_REVISION, PROVIDER_ID, validate_identifier,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarvestEndpoint {
    Job,
    Application,
    ActivityFeed,
    Scorecards,
    Offers,
}

impl HarvestEndpoint {
    pub const fn operation(self) -> &'static str {
        match self {
            Self::Job => "get_job",
            Self::Application => "get_application",
            Self::ActivityFeed => "get_candidate_activity_feed",
            Self::Scorecards => "get_application_scorecards",
            Self::Offers => "get_application_offers",
        }
    }

    fn first_path(self, scope: &GreenhouseScope) -> String {
        self.first_path_for_candidate(scope, None)
    }

    fn first_path_for_candidate(
        self,
        scope: &GreenhouseScope,
        candidate_provider_id: Option<&str>,
    ) -> String {
        match self {
            Self::Job => format!("/v1/jobs/{}", scope.job_id),
            Self::Application => format!("/v1/applications/{}", scope.application_id),
            Self::ActivityFeed => format!(
                "/v1/candidates/{}/activity_feed",
                candidate_provider_id.unwrap_or_else(|| {
                    scope
                        .candidate_reference_id
                        .as_ref()
                        .map_or("redacted-candidate", |candidate| {
                            candidate.as_digest().as_str()
                        })
                })
            ),
            Self::Scorecards => {
                format!("/v1/applications/{}/scorecards", scope.application_id)
            }
            Self::Offers => format!("/v1/applications/{}/offers", scope.application_id),
        }
    }

    fn path_matches(
        self,
        scope: &GreenhouseScope,
        path: &str,
        candidate_provider_id: Option<&str>,
    ) -> bool {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        match self {
            Self::ActivityFeed => {
                let Some(candidate_provider_id) = candidate_provider_id else {
                    return false;
                };
                path == format!("/v1/candidates/{candidate_provider_id}/activity_feed")
            }
            _ => path == self.first_path(scope),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarvestHttpRequest {
    pub method: String,
    pub path: String,
}

impl HarvestHttpRequest {
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: String::from("GET"),
            path: path.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarvestHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl HarvestHttpResponse {
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            status,
            headers: headers.into_iter().collect(),
            body: body.into(),
        }
    }

    pub fn json<T: Serialize>(status: u16, body: &T) -> Self {
        Self::new(
            status,
            BTreeMap::new(),
            serde_json::to_string(body).expect("fixture body must serialize"),
        )
    }

    #[must_use]
    pub fn with_link(mut self, link: impl Into<String>) -> Self {
        self.headers.insert(String::from("Link"), link.into());
        self
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarvestExchange {
    pub path: String,
    pub response: HarvestHttpResponse,
}

impl HarvestExchange {
    pub fn new(path: impl Into<String>, response: HarvestHttpResponse) -> Self {
        Self {
            path: path.into(),
            response,
        }
    }
}

pub trait HarvestTransport {
    fn provenance(&self) -> TransportProvenance;

    fn send(&mut self, request: &HarvestHttpRequest)
    -> Result<HarvestHttpResponse, TransportError>;
}

#[derive(Clone, Debug)]
struct ScriptedTransport {
    provenance: TransportProvenance,
    routes: BTreeMap<String, VecDeque<HarvestHttpResponse>>,
    requests: Vec<HarvestHttpRequest>,
}

impl ScriptedTransport {
    fn new(
        provenance: TransportProvenance,
        routes: impl IntoIterator<Item = (String, Vec<HarvestHttpResponse>)>,
    ) -> Self {
        Self {
            provenance,
            routes: routes
                .into_iter()
                .map(|(path, responses)| (path, responses.into_iter().collect()))
                .collect(),
            requests: Vec::new(),
        }
    }

    fn requests(&self) -> &[HarvestHttpRequest] {
        &self.requests
    }
}

impl HarvestTransport for ScriptedTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn send(
        &mut self,
        request: &HarvestHttpRequest,
    ) -> Result<HarvestHttpResponse, TransportError> {
        if request.method != "GET" {
            return Err(TransportError::Unavailable(String::from(
                "Layer-1 Harvest transport only accepts GET",
            )));
        }
        self.requests.push(request.clone());
        self.routes
            .get_mut(&request.path)
            .and_then(VecDeque::pop_front)
            .ok_or_else(|| TransportError::Unavailable(format!("no fixture for {}", request.path)))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    inner: ScriptedTransport,
}

impl FixtureTransport {
    pub fn new(routes: impl IntoIterator<Item = (String, Vec<HarvestHttpResponse>)>) -> Self {
        Self {
            inner: ScriptedTransport::new(TransportProvenance::Fixture, routes),
        }
    }

    pub fn one(routes: impl IntoIterator<Item = (String, HarvestHttpResponse)>) -> Self {
        Self::new(
            routes
                .into_iter()
                .map(|(path, response)| (path, vec![response])),
        )
    }

    pub fn requests(&self) -> &[HarvestHttpRequest] {
        self.inner.requests()
    }
}

impl HarvestTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn send(
        &mut self,
        request: &HarvestHttpRequest,
    ) -> Result<HarvestHttpResponse, TransportError> {
        self.inner.send(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: ScriptedTransport,
}

impl LoopbackTransport {
    pub fn new(routes: impl IntoIterator<Item = (String, Vec<HarvestHttpResponse>)>) -> Self {
        Self {
            inner: ScriptedTransport::new(TransportProvenance::Loopback, routes),
        }
    }

    pub fn one(routes: impl IntoIterator<Item = (String, HarvestHttpResponse)>) -> Self {
        Self::new(
            routes
                .into_iter()
                .map(|(path, response)| (path, vec![response])),
        )
    }

    pub fn requests(&self) -> &[HarvestHttpRequest] {
        self.inner.requests()
    }
}

impl HarvestTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn send(
        &mut self,
        request: &HarvestHttpRequest,
    ) -> Result<HarvestHttpResponse, TransportError> {
        self.inner.send(request)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    inner: ScriptedTransport,
}

impl RecordingTransport {
    pub fn new(routes: impl IntoIterator<Item = (String, Vec<HarvestHttpResponse>)>) -> Self {
        Self {
            inner: ScriptedTransport::new(TransportProvenance::Recording, routes),
        }
    }

    pub fn from_exchanges(exchanges: impl IntoIterator<Item = HarvestExchange>) -> Self {
        let mut routes: BTreeMap<String, Vec<HarvestHttpResponse>> = BTreeMap::new();
        for exchange in exchanges {
            routes
                .entry(exchange.path)
                .or_default()
                .push(exchange.response);
        }
        Self::new(routes)
    }

    pub fn requests(&self) -> &[HarvestHttpRequest] {
        self.inner.requests()
    }
}

impl HarvestTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn send(
        &mut self,
        request: &HarvestHttpRequest,
    ) -> Result<HarvestHttpResponse, TransportError> {
        self.inner.send(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl HarvestTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn send(
        &mut self,
        _request: &HarvestHttpRequest,
    ) -> Result<HarvestHttpResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff_ms: 100,
            max_backoff_ms: 1_000,
        }
    }
}

pub type RateLimitPolicy = RetryPolicy;

impl RetryPolicy {
    fn validate(self) -> Result<(), GreenhouseError> {
        if self.max_attempts == 0
            || self.max_attempts > 8
            || self.base_backoff_ms > self.max_backoff_ms
        {
            Err(GreenhouseError::InvalidScope)
        } else {
            Ok(())
        }
    }

    fn backoff_ms(self, retry_index: u8) -> u64 {
        self.base_backoff_ms
            .saturating_mul(2_u64.saturating_pow(u32::from(retry_index)))
            .min(self.max_backoff_ms)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GreenhouseHarvestProviderDefinition {
    pub provider_type: String,
    pub provider_id: crate::model::ProviderId,
    pub api_revision: String,
    pub capabilities: CapabilitySet,
    pub capability_digest: Digest,
    pub allowed_endpoints: Vec<HarvestEndpoint>,
    pub native: bool,
}

impl Default for GreenhouseHarvestProviderDefinition {
    fn default() -> Self {
        let capabilities = CapabilitySet::read_only();
        Self {
            provider_type: String::from("GreenhouseHarvestProvider"),
            provider_id: crate::model::ProviderId::new(PROVIDER_ID).expect("provider ID"),
            api_revision: String::from(PROVIDER_API_REVISION),
            capability_digest: capabilities.digest().clone(),
            capabilities,
            allowed_endpoints: vec![
                HarvestEndpoint::Job,
                HarvestEndpoint::Application,
                HarvestEndpoint::ActivityFeed,
                HarvestEndpoint::Scorecards,
                HarvestEndpoint::Offers,
            ],
            native: false,
        }
    }
}

impl GreenhouseHarvestProviderDefinition {
    pub fn validate(&self) -> Result<(), GreenhouseError> {
        self.capabilities.validate()?;
        if self.provider_type != "GreenhouseHarvestProvider"
            || self.provider_id.as_str() != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.capability_digest != *self.capabilities.digest()
            || self.allowed_endpoints.len() != 5
            || self.allowed_endpoints
                != vec![
                    HarvestEndpoint::Job,
                    HarvestEndpoint::Application,
                    HarvestEndpoint::ActivityFeed,
                    HarvestEndpoint::Scorecards,
                    HarvestEndpoint::Offers,
                ]
            || self.native
        {
            Err(GreenhouseError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn provider_id(&self) -> &crate::model::ProviderId {
        &self.provider_id
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn capability_digest(&self) -> &Digest {
        &self.capability_digest
    }
}

pub struct GreenhouseHarvestProvider {
    definition: GreenhouseHarvestProviderDefinition,
    secret: SecretReference,
    transport: Box<dyn HarvestTransport>,
    retry_policy: RetryPolicy,
    request_receipts: Vec<RequestReceipt>,
}

impl std::fmt::Debug for GreenhouseHarvestProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GreenhouseHarvestProvider")
            .field("definition", &self.definition)
            .field("secret", &self.secret)
            .field("transport_provenance", &self.transport.provenance())
            .field("retry_policy", &self.retry_policy)
            .field("request_receipts", &self.request_receipts)
            .finish()
    }
}

impl GreenhouseHarvestProvider {
    pub fn new<T: HarvestTransport + 'static>(
        secret: SecretReference,
        transport: T,
    ) -> Result<Self, GreenhouseError> {
        Self::with_retry_policy(secret, transport, RetryPolicy::default())
    }

    pub fn with_retry_policy<T: HarvestTransport + 'static>(
        secret: SecretReference,
        transport: T,
        retry_policy: RetryPolicy,
    ) -> Result<Self, GreenhouseError> {
        retry_policy.validate()?;
        if secret.is_revoked() {
            return Err(GreenhouseError::SecretRevoked);
        }
        Ok(Self {
            definition: GreenhouseHarvestProviderDefinition::default(),
            secret,
            transport: Box::new(transport),
            retry_policy,
            request_receipts: Vec::new(),
        })
    }

    pub fn fixture(
        secret: SecretReference,
        routes: impl IntoIterator<Item = (String, Vec<HarvestHttpResponse>)>,
    ) -> Result<Self, GreenhouseError> {
        Self::new(secret, FixtureTransport::new(routes))
    }

    pub fn loopback(
        secret: SecretReference,
        routes: impl IntoIterator<Item = (String, Vec<HarvestHttpResponse>)>,
    ) -> Result<Self, GreenhouseError> {
        Self::new(secret, LoopbackTransport::new(routes))
    }

    pub fn recording(
        secret: SecretReference,
        exchanges: impl IntoIterator<Item = HarvestExchange>,
    ) -> Result<Self, GreenhouseError> {
        Self::new(secret, RecordingTransport::from_exchanges(exchanges))
    }

    pub fn blocked_env(secret: SecretReference) -> Result<Self, GreenhouseError> {
        Self::new(secret, BlockedEnvTransport)
    }

    pub fn definition(&self) -> &GreenhouseHarvestProviderDefinition {
        &self.definition
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn request_receipts(&self) -> &[RequestReceipt] {
        &self.request_receipts
    }

    pub fn revoke_secret(&mut self) {
        self.secret.revoke();
    }

    pub fn read_hiring_evidence(
        &mut self,
        scope: &GreenhouseScope,
    ) -> Result<ProviderReadResult, GreenhouseError> {
        scope.validate()?;
        self.definition.validate()?;
        if self.secret.is_revoked() {
            return Err(GreenhouseError::SecretRevoked);
        }
        self.request_receipts.clear();

        let result = self.read_inner(scope);
        match result {
            Ok(evidence) => Ok(ProviderReadResult { evidence }),
            Err(GreenhouseError::AccessLost { endpoint }) => Ok(ProviderReadResult {
                evidence: self.failure_evidence(scope, ApplicationState::AccessLost, &endpoint),
            }),
            Err(GreenhouseError::ProviderUnknown { endpoint }) => Ok(ProviderReadResult {
                evidence: self.failure_evidence(
                    scope,
                    ApplicationState::ProviderUnknown,
                    &endpoint,
                ),
            }),
            Err(error) => Err(error),
        }
    }

    pub fn read(
        &mut self,
        scope: &GreenhouseScope,
    ) -> Result<GreenhouseHiringEvidence, GreenhouseError> {
        Ok(self.read_hiring_evidence(scope)?.evidence)
    }

    fn read_inner(
        &mut self,
        scope: &GreenhouseScope,
    ) -> Result<GreenhouseHiringEvidence, GreenhouseError> {
        let job = self.fetch_object(scope, HarvestEndpoint::Job)?;
        validate_returned_id(&job, "id", scope.job_id.as_str(), "job")?;
        validate_scoped_id(&job, "organization_id", scope.organization_id.as_str())?;
        let application = self.fetch_object(scope, HarvestEndpoint::Application)?;
        validate_returned_id(
            &application,
            "id",
            scope.application_id.as_str(),
            "application",
        )?;
        validate_scoped_id(&application, "job_id", scope.job_id.as_str())?;
        validate_scoped_id(
            &application,
            "organization_id",
            scope.organization_id.as_str(),
        )?;

        let candidate_provider_id =
            identifier_field(&application, &["candidate_id", "candidateId"])
                .unwrap_or_else(|| scope.application_id.as_str().to_owned());
        validate_identifier(&candidate_provider_id, "candidateId")?;
        if let Some(expected) = &scope.candidate_reference_id
            && expected.as_digest()
                != CandidateReference::from_provider_id(&candidate_provider_id)
                    .candidate_reference_id
                    .as_digest()
        {
            return Err(GreenhouseError::ScopeMismatch);
        }
        let candidate_reference = scope.candidate_reference_id.clone().map_or_else(
            || CandidateReference::from_provider_id(&candidate_provider_id),
            |candidate_reference_id| CandidateReference {
                candidate_reference_id,
                redacted: true,
            },
        );
        let state = application_state(&application);
        let observed_at = string_field(&application, &["updated_at", "updatedAt", "created_at"])
            .map_or_else(
                || BoundedTimestamp::new("1970-01-01T00:00:00Z").expect("constant timestamp"),
                |value| {
                    BoundedTimestamp::new(value)
                        .unwrap_or_else(|_| BoundedTimestamp::new("unknown").expect("timestamp"))
                },
            );
        let provider_revision = application_revision(&application);
        let stage_values = self.fetch_candidate_collection(
            scope,
            HarvestEndpoint::ActivityFeed,
            &candidate_provider_id,
        )?;
        let scorecard_values = self.fetch_collection(scope, HarvestEndpoint::Scorecards)?;
        let offer_values = self.fetch_collection(scope, HarvestEndpoint::Offers)?;
        let stage_transitions = parse_stages(stage_values)?;
        let scorecard = parse_scorecards(scorecard_values)?;
        let offer = parse_offers(offer_values)?;
        if scope.stage_id.as_ref().is_some_and(|stage_id| {
            !stage_transitions
                .iter()
                .any(|stage| &stage.stage_id == stage_id)
        }) || scope.scorecard_id.as_ref().is_some_and(|scorecard_id| {
            scorecard
                .as_ref()
                .is_none_or(|item| &item.scorecard_id != scorecard_id)
        }) || scope
            .offer_id
            .as_ref()
            .is_some_and(|offer_id| offer.as_ref().is_none_or(|item| &item.offer_id != offer_id))
        {
            return Err(GreenhouseError::ScopeMismatch);
        }
        let completeness = EvidenceCompleteness::Complete;
        Ok(GreenhouseHiringEvidence {
            scope_digest: scope.digest(),
            organization_id: scope.organization_id.clone(),
            job_id: scope.job_id.clone(),
            application_id: scope.application_id.clone(),
            candidate_reference,
            stage_transitions,
            scorecard,
            offer,
            state,
            completeness,
            observed_at,
            provider_revision,
            redaction: RedactionSummary::strict(),
            request_receipts: self.request_receipts.clone(),
            evidence_digest: Digest::from_text("unsealed-greenhouse-evidence"),
            connected: false,
            native: false,
        }
        .seal())
    }

    fn failure_evidence(
        &self,
        scope: &GreenhouseScope,
        state: ApplicationState,
        _endpoint: &str,
    ) -> GreenhouseHiringEvidence {
        GreenhouseHiringEvidence {
            scope_digest: scope.digest(),
            organization_id: scope.organization_id.clone(),
            job_id: scope.job_id.clone(),
            application_id: scope.application_id.clone(),
            candidate_reference: scope.candidate_reference_id.clone().map_or_else(
                || CandidateReference::from_provider_id(scope.application_id.as_str()),
                |candidate_reference_id| CandidateReference {
                    candidate_reference_id,
                    redacted: true,
                },
            ),
            stage_transitions: Vec::new(),
            scorecard: None,
            offer: None,
            state,
            completeness: EvidenceCompleteness::Unavailable,
            observed_at: BoundedTimestamp::new("unknown").expect("constant timestamp"),
            provider_revision: Revision::new(1).expect("constant revision"),
            redaction: RedactionSummary::strict(),
            request_receipts: self.request_receipts.clone(),
            evidence_digest: Digest::from_text("unsealed-greenhouse-failure-evidence"),
            connected: false,
            native: false,
        }
        .seal()
    }

    fn fetch_object(
        &mut self,
        scope: &GreenhouseScope,
        endpoint: HarvestEndpoint,
    ) -> Result<Map<String, Value>, GreenhouseError> {
        let response =
            self.fetch_response(scope, endpoint, endpoint.first_path(scope), None, None)?;
        let value: Value = serde_json::from_str(&response.body).map_err(|error| {
            GreenhouseError::InvalidResponse {
                endpoint: endpoint.operation().to_owned(),
                message: error.to_string(),
            }
        })?;
        match value {
            Value::Object(object) => Ok(object),
            _ => Err(GreenhouseError::InvalidResponse {
                endpoint: endpoint.operation().to_owned(),
                message: String::from("expected object"),
            }),
        }
    }

    fn fetch_collection(
        &mut self,
        scope: &GreenhouseScope,
        endpoint: HarvestEndpoint,
    ) -> Result<Vec<Value>, GreenhouseError> {
        self.fetch_collection_from(scope, endpoint, endpoint.first_path(scope), None)
    }

    fn fetch_candidate_collection(
        &mut self,
        scope: &GreenhouseScope,
        endpoint: HarvestEndpoint,
        candidate_provider_id: &str,
    ) -> Result<Vec<Value>, GreenhouseError> {
        self.fetch_collection_from(
            scope,
            endpoint,
            endpoint.first_path_for_candidate(scope, Some(candidate_provider_id)),
            Some(candidate_provider_id),
        )
    }

    fn fetch_collection_from(
        &mut self,
        scope: &GreenhouseScope,
        endpoint: HarvestEndpoint,
        mut path: String,
        candidate_provider_id: Option<&str>,
    ) -> Result<Vec<Value>, GreenhouseError> {
        let mut seen = BTreeSet::new();
        let mut values = Vec::new();
        for _page in 0..MAX_PAGES {
            if !seen.insert(path.clone()) {
                return Err(GreenhouseError::PaginationLoop);
            }
            let receipt_path = candidate_provider_id
                .map(|candidate_provider_id| redacted_activity_path(&path, candidate_provider_id));
            let response = self.fetch_response(
                scope,
                endpoint,
                path.clone(),
                candidate_provider_id,
                receipt_path,
            )?;
            let value: Value = serde_json::from_str(&response.body).map_err(|error| {
                GreenhouseError::InvalidResponse {
                    endpoint: endpoint.operation().to_owned(),
                    message: error.to_string(),
                }
            })?;
            values.extend(collection_values(&value));
            let limit = match endpoint {
                HarvestEndpoint::ActivityFeed => MAX_STAGE_TRANSITIONS,
                HarvestEndpoint::Scorecards => MAX_SCORECARDS,
                HarvestEndpoint::Offers => MAX_OFFERS,
                _ => MAX_PAGE_SIZE,
            };
            if values.len() > limit {
                return Err(GreenhouseError::PaginationLimit);
            }
            match next_link(response.header("Link"))? {
                Some(next) => {
                    if !endpoint.path_matches(scope, &next, candidate_provider_id) {
                        return Err(GreenhouseError::EndpointNotAllowed { path: next });
                    }
                    path = next;
                }
                None => return Ok(values),
            }
        }
        Err(GreenhouseError::PaginationLimit)
    }

    fn fetch_response(
        &mut self,
        scope: &GreenhouseScope,
        endpoint: HarvestEndpoint,
        path: String,
        candidate_provider_id: Option<&str>,
        receipt_path: Option<String>,
    ) -> Result<HarvestHttpResponse, GreenhouseError> {
        if !endpoint.path_matches(scope, &path, candidate_provider_id) {
            return Err(GreenhouseError::EndpointNotAllowed { path });
        }
        let request = HarvestHttpRequest::get(path.clone());
        let receipt_endpoint = receipt_path.unwrap_or_else(|| path.clone());
        let request_digest = RequestDigestInput {
            endpoint: path.clone(),
            method: request.method.clone(),
        }
        .digest();
        let mut backoff_delays_ms = Vec::new();
        let mut attempt = 0_u8;
        loop {
            attempt = attempt.saturating_add(1);
            let response = match self.transport.send(&request) {
                Ok(response) => response,
                Err(TransportError::BlockedEnv) => return Err(GreenhouseError::BlockedEnv),
                Err(TransportError::Unavailable(message)) => {
                    return Err(GreenhouseError::Transport { message });
                }
            };
            if response.body.len() > MAX_RESPONSE_BYTES {
                return Err(GreenhouseError::ResponseTooLarge);
            }
            let response_digest = Digest::from_text(&response.body);
            let retryable_rate = response.status == 429;
            let retryable_server = (500..=599).contains(&response.status);
            if (retryable_rate || retryable_server) && attempt < self.retry_policy.max_attempts {
                backoff_delays_ms.push(self.retry_policy.backoff_ms(attempt - 1));
                continue;
            }
            self.request_receipts.push(RequestReceipt {
                endpoint: receipt_endpoint,
                method: request.method.clone(),
                request_digest,
                response_digest,
                status: response.status,
                attempts: attempt,
                backoff_delays_ms,
                provenance: self.transport.provenance(),
                connected: false,
                native: false,
            });
            return match response.status {
                200..=299 => Ok(response),
                401 | 403 => Err(GreenhouseError::AccessLost { endpoint: path }),
                404 => Err(GreenhouseError::ProviderUnknown { endpoint: path }),
                409 => Err(GreenhouseError::ProviderConflict { endpoint: path }),
                429 => Err(GreenhouseError::RateLimitExhausted),
                500..=599 => Err(GreenhouseError::ServerErrorExhausted),
                status => Err(GreenhouseError::InvalidResponse {
                    endpoint: path,
                    message: format!("unexpected HTTP status {status}"),
                }),
            };
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReadResult {
    pub evidence: GreenhouseHiringEvidence,
}

pub type HarvestRequestReceipt = RequestReceipt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkHeader {
    pub next: Option<String>,
}

fn next_link(header: Option<&str>) -> Result<Option<String>, GreenhouseError> {
    let Some(header) = header else {
        return Ok(None);
    };
    for segment in header.split(',') {
        if !segment.to_ascii_lowercase().contains("rel=\"next\"") {
            continue;
        }
        let start = segment.find('<').ok_or(GreenhouseError::InvalidResponse {
            endpoint: String::from("Link"),
            message: String::from("next link is missing <...>"),
        })? + 1;
        let end = segment[start..]
            .find('>')
            .map_or(segment.len(), |offset| start + offset);
        let raw = &segment[start..end];
        return Ok(Some(normalize_link_path(raw)?));
    }
    Ok(None)
}

fn normalize_link_path(raw: &str) -> Result<String, GreenhouseError> {
    let raw = raw.trim();
    let path = if let Some(after_scheme) = raw.split_once("://").map(|(_, rest)| rest) {
        after_scheme
            .find('/')
            .map_or("/".to_owned(), |index| after_scheme[index..].to_owned())
    } else {
        raw.to_owned()
    };
    if !path.starts_with("/v1/") || path.contains('#') || path.contains(' ') {
        return Err(GreenhouseError::EndpointNotAllowed { path });
    }
    Ok(path)
}

fn redacted_activity_path(path: &str, candidate_provider_id: &str) -> String {
    let digest = Digest::from_text(candidate_provider_id);
    let query = path.split_once('?').map(|(_, query)| query);
    let redacted = format!("/v1/candidates/{}/activity_feed", digest.as_str());
    query.map_or(redacted.clone(), |query| format!("{redacted}?{query}"))
}

fn collection_values(value: &Value) -> Vec<Value> {
    if let Value::Array(values) = value {
        return values.clone();
    }
    let Value::Object(object) = value else {
        return Vec::new();
    };
    for key in [
        "data",
        "items",
        "activities",
        "activity_feed",
        "scorecards",
        "offers",
    ] {
        if let Some(Value::Array(values)) = object.get(key) {
            return values.clone();
        }
    }
    vec![value.clone()]
}

fn validate_returned_id(
    object: &Map<String, Value>,
    key: &str,
    expected: &str,
    field: &'static str,
) -> Result<(), GreenhouseError> {
    if let Some(actual) = object.get(key).and_then(scalar_string)
        && actual != expected
    {
        return Err(GreenhouseError::StaleSnapshot);
    }
    validate_identifier(expected, field)
}

fn validate_scoped_id(
    object: &Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<(), GreenhouseError> {
    if let Some(actual) = object.get(key).and_then(scalar_string)
        && actual != expected
    {
        return Err(GreenhouseError::ScopeMismatch);
    }
    Ok(())
}

fn scalar_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|number| number.to_string()))
}

fn identifier_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_string))
}

fn string_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str).map(str::to_owned))
}

fn u64_field(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_u64))
}

fn bool_field(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
        .unwrap_or(false)
}

fn application_state(object: &Map<String, Value>) -> ApplicationState {
    if bool_field(object, &["incomplete"]) {
        return ApplicationState::Incomplete;
    }
    let status = string_field(
        object,
        &["status", "application_status", "applicationStatus"],
    )
    .unwrap_or_default()
    .to_ascii_lowercase();
    match status.as_str() {
        "active" | "open" | "in_progress" => ApplicationState::Active,
        "converted" => ApplicationState::Converted,
        "hired" | "offer_accepted" | "offer accepted" => ApplicationState::Hired,
        "rejected" | "declined" => ApplicationState::Rejected,
        "stalled" | "on_hold" | "on hold" => ApplicationState::Stalled,
        "incomplete" | "partial" => ApplicationState::Incomplete,
        _ => ApplicationState::ProviderUnknown,
    }
}

fn application_revision(object: &Map<String, Value>) -> ProviderRevision {
    if let Some(value) = u64_field(
        object,
        &["revision", "application_revision", "applicationRevision"],
    ) {
        return Revision::new(value.max(1)).expect("normalized revision");
    }
    let digest = Digest::from_text(
        string_field(object, &["updated_at", "updatedAt", "created_at"])
            .unwrap_or_else(|| String::from("unknown-application-revision")),
    );
    Revision::from_digest(&digest)
}

fn parse_stages(values: Vec<Value>) -> Result<Vec<StageTransition>, GreenhouseError> {
    let mut stages = Vec::new();
    for value in &values {
        let Some(object) = value.as_object() else {
            continue;
        };
        let nested = object.get("stage").and_then(Value::as_object);
        let Some(stage_id) = identifier_field(object, &["stage_id", "stageId"])
            .or_else(|| nested.and_then(|item| identifier_field(item, &["id", "stage_id"])))
        else {
            continue;
        };
        let stage_id = StageId::new(stage_id)?;
        let label = string_field(object, &["stage_name", "stageName", "name"])
            .or_else(|| nested.and_then(|item| string_field(item, &["name", "stage_name"])))
            .map(|value| value.chars().take(128).collect::<String>());
        let entered_at = string_field(object, &["entered_at", "enteredAt", "created_at"])
            .map(BoundedTimestamp::new)
            .transpose()?;
        let exited_at = string_field(object, &["exited_at", "exitedAt", "ended_at"])
            .map(BoundedTimestamp::new)
            .transpose()?;
        let revision = Revision::new(u64_field(object, &["revision"]).unwrap_or(1).max(1))?;
        stages.push(StageTransition::from_provider(
            stage_id,
            label.as_deref(),
            entered_at,
            exited_at,
            revision,
        ));
    }
    if stages.len() > MAX_STAGE_TRANSITIONS {
        Err(GreenhouseError::PaginationLimit)
    } else {
        Ok(stages)
    }
}

fn parse_scorecards(values: Vec<Value>) -> Result<Option<ScorecardAggregate>, GreenhouseError> {
    let Some(value) = values.first() else {
        return Ok(None);
    };
    let object = value.as_object().ok_or(GreenhouseError::InvalidResponse {
        endpoint: String::from("scorecards"),
        message: String::from("scorecard is not an object"),
    })?;
    let scorecard_id = ScorecardId::new(
        identifier_field(object, &["id", "scorecard_id", "scorecardId"])
            .unwrap_or_else(|| String::from("scorecard-unknown")),
    )?;
    let sections_total = u64_field(object, &["sections_total", "sectionsTotal"])
        .or_else(|| {
            object
                .get("sections")
                .and_then(Value::as_array)
                .map(|items| items.len() as u64)
        })
        .or_else(|| {
            object
                .get("attributes")
                .and_then(Value::as_array)
                .map(|items| items.len() as u64)
        })
        .unwrap_or(0)
        .min(u64::from(u16::MAX));
    let sections_completed = u64_field(object, &["sections_completed", "sectionsCompleted"])
        .unwrap_or_else(|| {
            let sections_completed =
                object
                    .get("sections")
                    .and_then(Value::as_array)
                    .map(|sections| {
                        sections
                            .iter()
                            .filter(|section| {
                                section
                                    .as_object()
                                    .and_then(|item| item.get("completed"))
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false)
                            })
                            .count() as u64
                    });
            let attributes_completed =
                object
                    .get("attributes")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter(|attribute| {
                                attribute
                                    .as_object()
                                    .and_then(|item| item.get("rating"))
                                    .and_then(Value::as_str)
                                    .is_some_and(|rating| rating != "no_decision")
                            })
                            .count() as u64
                    });
            sections_completed
                .or(attributes_completed)
                .unwrap_or_else(|| {
                    if object.get("submitted_at").is_some() {
                        sections_total
                    } else {
                        0
                    }
                })
        })
        .min(u64::from(u16::MAX)) as u16;
    let sections_total = sections_total.max(u64::from(sections_completed)) as u16;
    let average_score_bps = u64_field(object, &["average_score_bps", "averageScoreBps"])
        .or_else(|| {
            object
                .get("average_score")
                .and_then(Value::as_u64)
                .map(|score| score.saturating_mul(100))
        })
        .or_else(|| {
            string_field(object, &["overall_recommendation"]).and_then(|recommendation| {
                match recommendation.to_ascii_lowercase().as_str() {
                    "strong_yes" => Some(9_000),
                    "yes" => Some(7_500),
                    "mixed" => Some(5_000),
                    "no" => Some(2_500),
                    "definitely_not" => Some(0),
                    _ => None,
                }
            })
        })
        .map(|score| score.min(10_000) as u16);
    let submitted_at = string_field(object, &["submitted_at", "submittedAt"])
        .map(BoundedTimestamp::new)
        .transpose()?;
    Ok(Some(ScorecardAggregate {
        scorecard_id,
        sections_completed,
        sections_total,
        average_score_bps,
        submitted_at,
        answer_digest: Digest::from_text(
            serde_json::to_string(value).expect("fixture value serializes"),
        ),
        raw_answers_retained: false,
        interview_notes_retained: false,
    }))
}

fn parse_offers(values: Vec<Value>) -> Result<Option<OfferEvidence>, GreenhouseError> {
    let Some(value) = values.first() else {
        return Ok(None);
    };
    let object = value.as_object().ok_or(GreenhouseError::InvalidResponse {
        endpoint: String::from("offers"),
        message: String::from("offer is not an object"),
    })?;
    let offer_id = OfferId::new(
        identifier_field(object, &["id", "offer_id", "offerId"])
            .unwrap_or_else(|| String::from("offer-unknown")),
    )?;
    let state = match string_field(object, &["status", "state"])
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "draft" => OfferState::Draft,
        "sent" | "pending" => OfferState::Sent,
        "accepted" => OfferState::Accepted,
        "rejected" | "declined" => OfferState::Rejected,
        "withdrawn" => OfferState::Withdrawn,
        _ => OfferState::Unknown,
    };
    Ok(Some(OfferEvidence {
        offer_id,
        state,
        created_at: string_field(object, &["created_at", "createdAt"])
            .map(BoundedTimestamp::new)
            .transpose()?,
        sent_at: string_field(object, &["sent_at", "sentAt"])
            .map(BoundedTimestamp::new)
            .transpose()?,
        decided_at: string_field(object, &["decided_at", "decidedAt"])
            .map(BoundedTimestamp::new)
            .transpose()?,
        content_digest: Digest::from_text(
            serde_json::to_string(value).expect("fixture value serializes"),
        ),
    }))
}

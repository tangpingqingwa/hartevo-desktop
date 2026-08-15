use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::model::{
    AggregateBucket, AggregateSeries, DateWindow, Digest, EventName, MixpanelAnalyticsScope,
    ProviderErrorKind, ProviderProvenance, RedactionSummary, ResultStatus, SecretReference,
};
use crate::query::MixpanelAnalyticsResultRequest;
use crate::{
    MIXPANEL_ANALYTICS_RESULT_PLUGIN_VERSION_TEXT, MIXPANEL_ANALYTICS_RESULT_PROVIDER_ID,
    MIXPANEL_INSIGHTS_METHOD, MIXPANEL_INSIGHTS_PATH, MIXPANEL_MAX_BUCKETS_PER_SERIES,
    MIXPANEL_MAX_EVENT_SELECTORS, MIXPANEL_MAX_REQUESTS_PER_PROJECT_PER_UTC_HOUR,
    MIXPANEL_MAX_RESPONSE_BYTES, MIXPANEL_MAX_SERIES,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixpanelProviderDefinition {
    pub id: String,
    pub version: String,
    pub method: String,
    pub path: String,
    pub read_only: bool,
    pub native: bool,
    pub https_transport: bool,
    pub first_party: bool,
    pub readback: bool,
    pub max_event_selectors: usize,
    pub max_series: usize,
    pub max_buckets_per_series: usize,
    pub max_response_bytes: usize,
    pub max_requests_per_project_per_utc_hour: u8,
    pub max_concurrent_queries: u8,
    pub paginated: bool,
}

impl MixpanelProviderDefinition {
    pub fn new() -> Self {
        Self {
            id: MIXPANEL_ANALYTICS_RESULT_PROVIDER_ID.to_owned(),
            version: MIXPANEL_ANALYTICS_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            method: MIXPANEL_INSIGHTS_METHOD.to_owned(),
            path: MIXPANEL_INSIGHTS_PATH.to_owned(),
            read_only: true,
            native: false,
            https_transport: false,
            first_party: false,
            readback: false,
            max_event_selectors: MIXPANEL_MAX_EVENT_SELECTORS,
            max_series: MIXPANEL_MAX_SERIES,
            max_buckets_per_series: MIXPANEL_MAX_BUCKETS_PER_SERIES,
            max_response_bytes: MIXPANEL_MAX_RESPONSE_BYTES,
            max_requests_per_project_per_utc_hour: MIXPANEL_MAX_REQUESTS_PER_PROJECT_PER_UTC_HOUR,
            max_concurrent_queries: 5,
            paginated: false,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self == &Self::new() {
            Ok(())
        } else {
            Err(ProviderDefinitionError::DefinitionDrift)
        }
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-provider-definition/v1",
            &[
                self.id.clone(),
                self.version.clone(),
                self.method.clone(),
                self.path.clone(),
                self.read_only.to_string(),
                self.native.to_string(),
                self.https_transport.to_string(),
                self.first_party.to_string(),
                self.readback.to_string(),
                self.max_event_selectors.to_string(),
                self.max_series.to_string(),
                self.max_buckets_per_series.to_string(),
                self.max_response_bytes.to_string(),
                self.max_requests_per_project_per_utc_hour.to_string(),
                self.max_concurrent_queries.to_string(),
                self.paginated.to_string(),
            ],
        )
    }
}

impl Default for MixpanelProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Mixpanel provider definition drifted from the Layer-1 contract")]
    DefinitionDrift,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MixpanelTransportError {
    #[error("BLOCKED_ENV: native Mixpanel credentials or HTTPS transport are unavailable")]
    BlockedEnv,
    #[error("Mixpanel quota is exhausted")]
    QuotaExhausted,
    #[error("Mixpanel request was rate limited")]
    RateLimited,
    #[error("Mixpanel credentials were rejected")]
    Unauthorized,
    #[error("Mixpanel access was forbidden")]
    Forbidden,
    #[error("Mixpanel report was not found")]
    NotFound,
    #[error("Mixpanel report or credential expired")]
    Expired,
    #[error("Mixpanel response was partial")]
    Partial,
    #[error("Mixpanel response was a replay")]
    Replay,
    #[error("Mixpanel transport failed")]
    Transport,
}

#[derive(Clone, Eq, PartialEq)]
pub struct MixpanelHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl MixpanelHttpResponse {
    pub fn new(status: u16, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            body: body.as_ref().to_vec(),
        }
    }

    pub fn ok(body: impl AsRef<[u8]>) -> Self {
        Self::new(200, body)
    }

    pub fn partial(body: impl AsRef<[u8]>) -> Self {
        Self::new(206, body)
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub const fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl fmt::Debug for MixpanelHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MixpanelHttpResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

pub trait MixpanelTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn get_insights(
        &mut self,
        request: &MixpanelAnalyticsResultRequest,
    ) -> Result<MixpanelHttpResponse, MixpanelTransportError>;
}

#[derive(Clone, Debug)]
struct StaticTransportState {
    response: Result<MixpanelHttpResponse, MixpanelTransportError>,
    request_digests: Vec<Digest>,
}

impl StaticTransportState {
    fn new(response: Result<MixpanelHttpResponse, MixpanelTransportError>) -> Self {
        Self {
            response,
            request_digests: Vec::new(),
        }
    }

    fn get(
        &mut self,
        request: &MixpanelAnalyticsResultRequest,
    ) -> Result<MixpanelHttpResponse, MixpanelTransportError> {
        self.request_digests.push(request.request_digest().clone());
        self.response.clone()
    }

    fn request_count(&self) -> usize {
        self.request_digests.len()
    }
}

#[derive(Clone, Debug)]
pub struct FixtureMixpanelTransport {
    state: StaticTransportState,
}

impl FixtureMixpanelTransport {
    pub fn new(body: impl AsRef<[u8]>) -> Self {
        Self {
            state: StaticTransportState::new(Ok(MixpanelHttpResponse::ok(body))),
        }
    }

    pub fn from_error(error: MixpanelTransportError) -> Self {
        Self {
            state: StaticTransportState::new(Err(error)),
        }
    }

    pub fn request_count(&self) -> usize {
        self.state.request_count()
    }
}

impl MixpanelTransport for FixtureMixpanelTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn get_insights(
        &mut self,
        request: &MixpanelAnalyticsResultRequest,
    ) -> Result<MixpanelHttpResponse, MixpanelTransportError> {
        self.state.get(request)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingMixpanelTransport {
    state: StaticTransportState,
}

impl RecordingMixpanelTransport {
    pub fn new(body: impl AsRef<[u8]>) -> Self {
        Self {
            state: StaticTransportState::new(Ok(MixpanelHttpResponse::ok(body))),
        }
    }

    pub fn from_response(response: MixpanelHttpResponse) -> Self {
        Self {
            state: StaticTransportState::new(Ok(response)),
        }
    }

    pub fn from_error(error: MixpanelTransportError) -> Self {
        Self {
            state: StaticTransportState::new(Err(error)),
        }
    }

    pub fn request_count(&self) -> usize {
        self.state.request_count()
    }
}

impl MixpanelTransport for RecordingMixpanelTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn get_insights(
        &mut self,
        request: &MixpanelAnalyticsResultRequest,
    ) -> Result<MixpanelHttpResponse, MixpanelTransportError> {
        self.state.get(request)
    }
}

#[derive(Clone, Debug)]
pub struct FakeMixpanelTransport {
    state: StaticTransportState,
}

impl FakeMixpanelTransport {
    pub fn new(body: impl AsRef<[u8]>) -> Self {
        Self {
            state: StaticTransportState::new(Ok(MixpanelHttpResponse::ok(body))),
        }
    }

    pub fn from_error(error: MixpanelTransportError) -> Self {
        Self {
            state: StaticTransportState::new(Err(error)),
        }
    }
}

impl MixpanelTransport for FakeMixpanelTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fake
    }

    fn get_insights(
        &mut self,
        request: &MixpanelAnalyticsResultRequest,
    ) -> Result<MixpanelHttpResponse, MixpanelTransportError> {
        self.state.get(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackMixpanelTransport {
    state: StaticTransportState,
}

impl LoopbackMixpanelTransport {
    pub fn new(body: impl AsRef<[u8]>) -> Self {
        Self {
            state: StaticTransportState::new(Ok(MixpanelHttpResponse::ok(body))),
        }
    }

    pub fn from_error(error: MixpanelTransportError) -> Self {
        Self {
            state: StaticTransportState::new(Err(error)),
        }
    }
}

impl MixpanelTransport for LoopbackMixpanelTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn get_insights(
        &mut self,
        request: &MixpanelAnalyticsResultRequest,
    ) -> Result<MixpanelHttpResponse, MixpanelTransportError> {
        self.state.get(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvMixpanelTransport;

impl MixpanelTransport for BlockedEnvMixpanelTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn get_insights(
        &mut self,
        _request: &MixpanelAnalyticsResultRequest,
    ) -> Result<MixpanelHttpResponse, MixpanelTransportError> {
        Err(MixpanelTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MixpanelProviderError {
    #[error("Mixpanel provider definition drifted")]
    DefinitionDrift,
    #[error("Mixpanel request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Mixpanel request scope does not match the opaque SecretReference")]
    ScopeMismatch,
    #[error("Mixpanel SecretReference is revoked")]
    SecretRevoked,
    #[error("Mixpanel response could not be converted into bounded aggregate evidence")]
    InvalidResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixpanelProviderEvidence {
    pub request_digest: Digest,
    pub project_digest: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: crate::model::Revision,
    pub provenance: ProviderProvenance,
    pub status: ResultStatus,
    pub error: Option<ProviderErrorKind>,
    pub response_window: Option<DateWindow>,
    pub series: Vec<AggregateSeries>,
    pub headers_digest: Digest,
    pub computed_at_digest: Option<Digest>,
    pub redactions: RedactionSummary,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

impl MixpanelProviderEvidence {
    pub fn validate(
        &self,
        request: &MixpanelAnalyticsResultRequest,
        scope: &MixpanelAnalyticsScope,
        secret: &SecretReference,
        definition: &MixpanelProviderDefinition,
    ) -> bool {
        self.validate_without_secret(request, scope, definition)
            && self.secret_reference_digest == secret.digest()
            && self.credential_revision == secret.credential_revision()
    }

    pub fn validate_without_secret(
        &self,
        request: &MixpanelAnalyticsResultRequest,
        scope: &MixpanelAnalyticsScope,
        definition: &MixpanelProviderDefinition,
    ) -> bool {
        if request.validate_against(scope).is_err()
            || self.request_digest != *request.request_digest()
            || self.project_digest != request.project_id().digest()
            || self.scope_digest != *request.scope_digest()
            || self.provider_digest != definition.provider_digest()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || !self.redactions.is_strict()
            || self.series.len() > definition.max_series
            || self
                .series
                .iter()
                .any(|series| !request.event_selector().contains(&series.event))
        {
            return false;
        }
        if let Some(response_window) = &self.response_window {
            if response_window != scope.date_window()
                || response_window.from_date() > response_window.to_date()
            {
                return false;
            }
            if self.series.iter().any(|series| {
                series.buckets.len() > definition.max_buckets_per_series
                    || series
                        .buckets
                        .iter()
                        .any(|bucket| !response_window.contains(&bucket.date))
                    || series
                        .buckets
                        .windows(2)
                        .any(|pair| pair[0].date >= pair[1].date)
            }) {
                return false;
            }
        } else if !self.series.is_empty() {
            return false;
        }
        self.evidence_digest == compute_evidence_digest(self)
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

pub struct MixpanelProvider<T> {
    definition: MixpanelProviderDefinition,
    transport: T,
    quota: BTreeMap<(u64, i64), u8>,
}

impl<T> fmt::Debug for MixpanelProvider<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MixpanelProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .field("quota_entries", &self.quota.len())
            .finish()
    }
}

impl<T> MixpanelProvider<T>
where
    T: MixpanelTransport,
{
    pub fn new(transport: T) -> Result<Self, MixpanelProviderError> {
        let definition = MixpanelProviderDefinition::new();
        definition
            .validate()
            .map_err(|_| MixpanelProviderError::DefinitionDrift)?;
        Ok(Self {
            definition,
            transport,
            quota: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> &MixpanelProviderDefinition {
        &self.definition
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn read(
        &mut self,
        request: &MixpanelAnalyticsResultRequest,
        secret: &SecretReference,
    ) -> Result<MixpanelProviderEvidence, MixpanelProviderError> {
        self.definition
            .validate()
            .map_err(|_| MixpanelProviderError::DefinitionDrift)?;
        request
            .validate()
            .map_err(|error| MixpanelProviderError::InvalidRequest(error.to_string()))?;
        if secret.is_revoked() {
            return Err(MixpanelProviderError::SecretRevoked);
        }
        if secret.scope_digest() != request.scope_digest() {
            return Err(MixpanelProviderError::ScopeMismatch);
        }
        let quota_key = (
            request.project_id().get(),
            request.requested_at().utc_hour(),
        );
        let used = self.quota.entry(quota_key).or_default();
        if *used >= self.definition.max_requests_per_project_per_utc_hour {
            return Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                ResultStatus::RateLimited,
                Some(ProviderErrorKind::QuotaExhausted),
                Digest::from_text("quota-exhausted"),
            ));
        }
        *used = used.saturating_add(1);
        let response = self.transport.get_insights(request);
        match response {
            Ok(response) => self.normalize_response(request, secret, response),
            Err(error) => Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                status_for_transport_error(&error),
                Some(kind_for_transport_error(&error)),
                Digest::from_text(error.to_string()),
            )),
        }
    }

    fn normalize_response(
        &self,
        request: &MixpanelAnalyticsResultRequest,
        secret: &SecretReference,
        response: MixpanelHttpResponse,
    ) -> Result<MixpanelProviderEvidence, MixpanelProviderError> {
        let response_digest = Digest::from_bytes(&response.body);
        if response.body_len() > self.definition.max_response_bytes {
            return Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                ResultStatus::ProviderUnknown,
                Some(ProviderErrorKind::ResponseTooLarge),
                response_digest,
            ));
        }
        match response.status() {
            200 | 206 => match normalize_json_body(request, &response.body, &self.definition) {
                Ok((response_window, series, headers_digest, computed_at_digest)) => {
                    let status = if response.status() == 206 {
                        ResultStatus::Partial
                    } else if series.is_empty() {
                        ResultStatus::Empty
                    } else {
                        ResultStatus::Complete
                    };
                    Ok(build_evidence(
                        request,
                        secret,
                        &self.definition,
                        self.provenance(),
                        status,
                        None,
                        Some(response_window),
                        series,
                        headers_digest,
                        Some(computed_at_digest),
                        RedactionSummary::strict(),
                        response_digest,
                    ))
                }
                Err(error) => Ok(error_evidence(
                    request,
                    secret,
                    &self.definition,
                    self.provenance(),
                    ResultStatus::ProviderUnknown,
                    Some(error),
                    response_digest,
                )),
            },
            401 => Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                ResultStatus::AccessLost,
                Some(ProviderErrorKind::Unauthorized),
                response_digest,
            )),
            403 => Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                ResultStatus::AccessLost,
                Some(ProviderErrorKind::Forbidden),
                response_digest,
            )),
            404 => Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                ResultStatus::ProviderUnknown,
                Some(ProviderErrorKind::NotFound),
                response_digest,
            )),
            410 => Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                ResultStatus::Expired,
                Some(ProviderErrorKind::Expired),
                response_digest,
            )),
            429 => Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                ResultStatus::RateLimited,
                Some(ProviderErrorKind::RateLimited),
                response_digest,
            )),
            _ => Ok(error_evidence(
                request,
                secret,
                &self.definition,
                self.provenance(),
                ResultStatus::ProviderUnknown,
                Some(ProviderErrorKind::Unknown),
                response_digest,
            )),
        }
    }
}

impl MixpanelProvider<FixtureMixpanelTransport> {
    pub fn fixture(body: impl AsRef<[u8]>) -> Self {
        Self::new(FixtureMixpanelTransport::new(body)).expect("fixed provider definition")
    }
}

impl MixpanelProvider<RecordingMixpanelTransport> {
    pub fn recording(body: impl AsRef<[u8]>) -> Self {
        Self::new(RecordingMixpanelTransport::new(body)).expect("fixed provider definition")
    }
}

impl MixpanelProvider<FakeMixpanelTransport> {
    pub fn fake(body: impl AsRef<[u8]>) -> Self {
        Self::new(FakeMixpanelTransport::new(body)).expect("fixed provider definition")
    }
}

impl MixpanelProvider<LoopbackMixpanelTransport> {
    pub fn loopback(body: impl AsRef<[u8]>) -> Self {
        Self::new(LoopbackMixpanelTransport::new(body)).expect("fixed provider definition")
    }
}

impl MixpanelProvider<BlockedEnvMixpanelTransport> {
    pub fn blocked_env() -> Self {
        Self::new(BlockedEnvMixpanelTransport).expect("fixed provider definition")
    }
}

fn error_evidence(
    request: &MixpanelAnalyticsResultRequest,
    secret: &SecretReference,
    definition: &MixpanelProviderDefinition,
    provenance: ProviderProvenance,
    status: ResultStatus,
    error: Option<ProviderErrorKind>,
    response_digest: Digest,
) -> MixpanelProviderEvidence {
    build_evidence(
        request,
        secret,
        definition,
        provenance,
        status,
        error,
        None,
        Vec::new(),
        Digest::from_text("headers:none"),
        None,
        RedactionSummary::strict(),
        response_digest,
    )
}

fn build_evidence(
    request: &MixpanelAnalyticsResultRequest,
    secret: &SecretReference,
    definition: &MixpanelProviderDefinition,
    provenance: ProviderProvenance,
    status: ResultStatus,
    error: Option<ProviderErrorKind>,
    response_window: Option<DateWindow>,
    series: Vec<AggregateSeries>,
    headers_digest: Digest,
    computed_at_digest: Option<Digest>,
    redactions: RedactionSummary,
    response_digest: Digest,
) -> MixpanelProviderEvidence {
    let mut evidence = MixpanelProviderEvidence {
        request_digest: request.request_digest().clone(),
        project_digest: request.project_id().digest(),
        scope_digest: request.scope_digest().clone(),
        provider_digest: definition.provider_digest(),
        secret_reference_digest: secret.digest(),
        credential_revision: secret.credential_revision(),
        provenance,
        status,
        error,
        response_window,
        series,
        headers_digest,
        computed_at_digest,
        redactions,
        response_digest,
        evidence_digest: Digest::from_text("placeholder"),
    };
    evidence.evidence_digest = compute_evidence_digest(&evidence);
    evidence
}

fn compute_evidence_digest(evidence: &MixpanelProviderEvidence) -> Digest {
    let series_digest = Digest::from_fields(
        "mixpanel-series/v1",
        &evidence
            .series
            .iter()
            .flat_map(|series| {
                let mut fields = vec![series.event.as_str().to_owned()];
                fields.extend(series.buckets.iter().flat_map(|bucket| {
                    [bucket.date.as_str().to_owned(), bucket.count.to_string()]
                }));
                fields
            })
            .collect::<Vec<_>>(),
    );
    Digest::from_fields(
        "mixpanel-evidence/v1",
        &[
            evidence.request_digest.as_str().to_owned(),
            evidence.project_digest.as_str().to_owned(),
            evidence.scope_digest.as_str().to_owned(),
            evidence.provider_digest.as_str().to_owned(),
            evidence.secret_reference_digest.as_str().to_owned(),
            evidence.credential_revision.get().to_string(),
            format!("{:?}", evidence.provenance),
            format!("{:?}", evidence.status),
            evidence
                .error
                .map_or_else(|| "none".to_owned(), |error| format!("{error:?}")),
            evidence.response_window.as_ref().map_or_else(
                || "none".to_owned(),
                |window| window.digest().as_str().to_owned(),
            ),
            series_digest.as_str().to_owned(),
            evidence.headers_digest.as_str().to_owned(),
            evidence
                .computed_at_digest
                .as_ref()
                .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            evidence.redactions.raw_api_body_dropped.to_string(),
            evidence.redactions.raw_events_dropped.to_string(),
            evidence.redactions.user_pii_dropped.to_string(),
            evidence.redactions.event_properties_dropped.to_string(),
            evidence.redactions.auth_material_dropped.to_string(),
            evidence.response_digest.as_str().to_owned(),
        ],
    )
}

fn status_for_transport_error(error: &MixpanelTransportError) -> ResultStatus {
    match error {
        MixpanelTransportError::Unauthorized | MixpanelTransportError::Forbidden => {
            ResultStatus::AccessLost
        }
        MixpanelTransportError::QuotaExhausted | MixpanelTransportError::RateLimited => {
            ResultStatus::RateLimited
        }
        MixpanelTransportError::Expired => ResultStatus::Expired,
        MixpanelTransportError::Partial => ResultStatus::Partial,
        _ => ResultStatus::ProviderUnknown,
    }
}

fn kind_for_transport_error(error: &MixpanelTransportError) -> ProviderErrorKind {
    match error {
        MixpanelTransportError::BlockedEnv => ProviderErrorKind::BlockedEnv,
        MixpanelTransportError::QuotaExhausted => ProviderErrorKind::QuotaExhausted,
        MixpanelTransportError::RateLimited => ProviderErrorKind::RateLimited,
        MixpanelTransportError::Unauthorized => ProviderErrorKind::Unauthorized,
        MixpanelTransportError::Forbidden => ProviderErrorKind::Forbidden,
        MixpanelTransportError::NotFound => ProviderErrorKind::NotFound,
        MixpanelTransportError::Expired => ProviderErrorKind::Expired,
        MixpanelTransportError::Partial => ProviderErrorKind::Transport,
        MixpanelTransportError::Replay => ProviderErrorKind::Replay,
        MixpanelTransportError::Transport => ProviderErrorKind::Transport,
    }
}

fn normalize_json_body(
    request: &MixpanelAnalyticsResultRequest,
    body: &[u8],
    definition: &MixpanelProviderDefinition,
) -> Result<(DateWindow, Vec<AggregateSeries>, Digest, Digest), ProviderErrorKind> {
    let value =
        serde_json::from_slice::<Value>(body).map_err(|_| ProviderErrorKind::MalformedResponse)?;
    let root = value
        .as_object()
        .ok_or(ProviderErrorKind::MalformedResponse)?;
    require_exact_keys(root, &["computed_at", "date_range", "headers", "series"])?;
    let computed_at = root
        .get("computed_at")
        .and_then(Value::as_str)
        .ok_or(ProviderErrorKind::MalformedResponse)?;
    if computed_at.is_empty() || computed_at.len() > 128 {
        return Err(ProviderErrorKind::MalformedResponse);
    }
    let date_range = root
        .get("date_range")
        .and_then(Value::as_object)
        .ok_or(ProviderErrorKind::MalformedResponse)?;
    require_exact_keys(date_range, &["from_date", "to_date"])?;
    let from_date = date_range
        .get("from_date")
        .and_then(Value::as_str)
        .ok_or(ProviderErrorKind::MalformedResponse)?;
    let to_date = date_range
        .get("to_date")
        .and_then(Value::as_str)
        .ok_or(ProviderErrorKind::MalformedResponse)?;
    let response_window = DateWindow::new(
        crate::model::UtcDate::from_api_value(from_date)
            .map_err(|_| ProviderErrorKind::MalformedResponse)?,
        crate::model::UtcDate::from_api_value(to_date)
            .map_err(|_| ProviderErrorKind::MalformedResponse)?,
    )
    .map_err(|_| ProviderErrorKind::MalformedResponse)?;
    if response_window != *request.date_window() {
        return Err(ProviderErrorKind::ScopeDrift);
    }
    let headers = root
        .get("headers")
        .and_then(Value::as_array)
        .ok_or(ProviderErrorKind::MalformedResponse)?;
    if headers.is_empty()
        || headers.iter().any(|header| {
            !header
                .as_str()
                .is_some_and(|header| matches!(header, "$event" | "count"))
        })
    {
        return Err(ProviderErrorKind::RawEventOrPii);
    }
    let header_fields = headers
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let headers_digest = Digest::from_fields("mixpanel-response-headers/v1", &header_fields);
    let series_object = root
        .get("series")
        .and_then(Value::as_object)
        .ok_or(ProviderErrorKind::MalformedResponse)?;
    if series_object.len() > definition.max_series
        || series_object.len() > request.event_selector().len()
    {
        return Err(ProviderErrorKind::BoundExceeded);
    }
    let mut series = Vec::with_capacity(series_object.len());
    for (event_name, buckets_value) in series_object {
        let event =
            EventName::new(event_name.to_owned()).map_err(|_| ProviderErrorKind::RawEventOrPii)?;
        if !request.event_selector().contains(&event) {
            return Err(ProviderErrorKind::ScopeDrift);
        }
        let buckets_object = buckets_value
            .as_object()
            .ok_or(ProviderErrorKind::MalformedResponse)?;
        if buckets_object.len() > definition.max_buckets_per_series {
            return Err(ProviderErrorKind::BoundExceeded);
        }
        let mut buckets = Vec::with_capacity(buckets_object.len());
        for (date_label, count_value) in buckets_object {
            let date = crate::model::UtcDate::from_api_value(date_label)
                .map_err(|_| ProviderErrorKind::MalformedResponse)?;
            if !response_window.contains(&date) {
                return Err(ProviderErrorKind::ScopeDrift);
            }
            let count = count_value
                .as_u64()
                .ok_or(ProviderErrorKind::MalformedResponse)?;
            buckets.push(AggregateBucket { date, count });
        }
        buckets.sort_by(|left, right| left.date.cmp(&right.date));
        if buckets.windows(2).any(|pair| pair[0].date == pair[1].date) {
            return Err(ProviderErrorKind::MalformedResponse);
        }
        series.push(AggregateSeries { event, buckets });
    }
    series.sort_by(|left, right| left.event.cmp(&right.event));
    Ok((
        response_window,
        series,
        headers_digest,
        Digest::from_text(computed_at),
    ))
}

fn require_exact_keys(
    object: &Map<String, Value>,
    expected: &[&str],
) -> Result<(), ProviderErrorKind> {
    if object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)) {
        Ok(())
    } else {
        Err(ProviderErrorKind::RawEventOrPii)
    }
}

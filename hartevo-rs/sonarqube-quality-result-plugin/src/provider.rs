//! Bounded, allowlisted SonarQube read requests and non-native transports.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AnalysisIdentity, BranchOrPullRequest, Digest, Measure, MeasureSelector, ProjectionState,
    QualityGateCondition, QualityGateIdentity, QualityGateStatus, SecretReference, SonarProjectKey,
    SonarQubeQualityScope, TransportProvenance,
};
use crate::{
    MAX_ANALYSES, MAX_ANALYSIS_PAGES, MAX_CONDITIONS, MAX_MEASURES, MAX_METRIC_KEYS, MAX_PAGE_SIZE,
    MAX_RESPONSE_BYTES, Result, SonarQubeQualityResultError,
};

/// SonarQube Web API paths permitted by this Layer-1 contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SonarQubeEndpoint {
    ProjectAnalysesSearch,
    QualityGatesProjectStatus,
    MeasuresComponent,
}

impl SonarQubeEndpoint {
    pub const fn path(self) -> &'static str {
        match self {
            Self::ProjectAnalysesSearch => crate::PROJECT_ANALYSES_SEARCH_PATH,
            Self::QualityGatesProjectStatus => crate::QUALITY_GATE_STATUS_PATH,
            Self::MeasuresComponent => crate::MEASURES_COMPONENT_PATH,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadLimits {
    pub max_analysis_pages: usize,
    pub page_size: usize,
    pub max_response_bytes: usize,
    pub max_analyses: usize,
    pub max_conditions: usize,
    pub max_measures: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_analysis_pages: MAX_ANALYSIS_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_analyses: MAX_ANALYSES,
            max_conditions: MAX_CONDITIONS,
            max_measures: MAX_MEASURES,
        }
    }
}

impl ReadLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_analysis_pages == 0
            || self.max_analysis_pages > MAX_ANALYSIS_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_analyses == 0
            || self.max_analyses > MAX_ANALYSES
            || self.max_conditions == 0
            || self.max_conditions > MAX_CONDITIONS
            || self.max_measures == 0
            || self.max_measures > MAX_MEASURES
        {
            Err(SonarQubeQualityResultError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisSearchRequest {
    pub host_origin: String,
    pub scope_digest: Digest,
    pub project: SonarProjectKey,
    pub branch_or_pull_request: BranchOrPullRequest,
    pub page: usize,
    pub page_size: usize,
    pub secret_reference_digest: Digest,
}

impl AnalysisSearchRequest {
    pub fn new(
        scope: &SonarQubeQualityScope,
        page: usize,
        secret: &SecretReference,
    ) -> Result<Self> {
        let request = Self {
            host_origin: scope.host.origin.clone(),
            scope_digest: scope.digest(),
            project: scope.project.clone(),
            branch_or_pull_request: scope.branch_or_pull_request.clone(),
            page,
            page_size: MAX_PAGE_SIZE,
            secret_reference_digest: secret.reference_digest().clone(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.page == 0
            || self.page > MAX_ANALYSIS_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(SonarQubeQualityResultError::InvalidPage);
        }
        let host = crate::model::HostIdentity::new(self.host_origin.clone())?;
        host.validate()?;
        self.scope_digest.validate()?;
        self.project.validate()?;
        self.branch_or_pull_request.validate()?;
        self.secret_reference_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualityGateStatusRequest {
    pub host_origin: String,
    pub scope_digest: Digest,
    pub project: SonarProjectKey,
    pub analysis: AnalysisIdentity,
    pub secret_reference_digest: Digest,
}

impl QualityGateStatusRequest {
    pub fn new(scope: &SonarQubeQualityScope, secret: &SecretReference) -> Result<Self> {
        let request = Self {
            host_origin: scope.host.origin.clone(),
            scope_digest: scope.digest(),
            project: scope.project.clone(),
            analysis: scope.analysis.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        let host = crate::model::HostIdentity::new(self.host_origin.clone())?;
        host.validate()?;
        self.scope_digest.validate()?;
        self.project.validate()?;
        self.analysis.validate()?;
        self.secret_reference_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeasuresReadRequest {
    pub host_origin: String,
    pub scope_digest: Digest,
    pub project: SonarProjectKey,
    pub branch_or_pull_request: BranchOrPullRequest,
    pub analysis: AnalysisIdentity,
    pub selectors: Vec<MeasureSelector>,
    pub secret_reference_digest: Digest,
}

impl MeasuresReadRequest {
    pub fn new(scope: &SonarQubeQualityScope, secret: &SecretReference) -> Result<Self> {
        let request = Self {
            host_origin: scope.host.origin.clone(),
            scope_digest: scope.digest(),
            project: scope.project.clone(),
            branch_or_pull_request: scope.branch_or_pull_request.clone(),
            analysis: scope.analysis.clone(),
            selectors: scope.measures.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        let host = crate::model::HostIdentity::new(self.host_origin.clone())?;
        host.validate()?;
        self.scope_digest.validate()?;
        self.project.validate()?;
        self.branch_or_pull_request.validate()?;
        self.analysis.validate()?;
        if self.selectors.is_empty() || self.selectors.len() > MAX_METRIC_KEYS {
            return Err(SonarQubeQualityResultError::InvalidScope);
        }
        let mut keys = BTreeSet::new();
        for selector in &self.selectors {
            selector.validate()?;
            if !keys.insert(selector.api_key()) {
                return Err(SonarQubeQualityResultError::MeasureDrift);
            }
        }
        self.secret_reference_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SonarQubeReadRequest {
    ProjectAnalysesSearch(AnalysisSearchRequest),
    QualityGatesProjectStatus(QualityGateStatusRequest),
    MeasuresComponent(MeasuresReadRequest),
}

impl SonarQubeReadRequest {
    pub const fn endpoint(&self) -> SonarQubeEndpoint {
        match self {
            Self::ProjectAnalysesSearch(_) => SonarQubeEndpoint::ProjectAnalysesSearch,
            Self::QualityGatesProjectStatus(_) => SonarQubeEndpoint::QualityGatesProjectStatus,
            Self::MeasuresComponent(_) => SonarQubeEndpoint::MeasuresComponent,
        }
    }

    pub const fn path(&self) -> &'static str {
        self.endpoint().path()
    }

    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::ProjectAnalysesSearch(request) => &request.scope_digest,
            Self::QualityGatesProjectStatus(request) => &request.scope_digest,
            Self::MeasuresComponent(request) => &request.scope_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ProjectAnalysesSearch(request) => request.validate(),
            Self::QualityGatesProjectStatus(request) => request.validate(),
            Self::MeasuresComponent(request) => request.validate(),
        }
    }

    /// Only documented endpoint parameters are emitted; no arbitrary query
    /// string or provider DSL can enter the transport boundary.
    pub fn query_parameters(&self) -> Vec<(String, String)> {
        let mut parameters = match self {
            Self::ProjectAnalysesSearch(request) => vec![
                ("project".to_owned(), request.project.as_str().to_owned()),
                (
                    request.branch_or_pull_request.query_name().to_owned(),
                    request.branch_or_pull_request.key().to_owned(),
                ),
                ("p".to_owned(), request.page.to_string()),
                ("ps".to_owned(), request.page_size.to_string()),
            ],
            Self::QualityGatesProjectStatus(request) => vec![
                ("projectKey".to_owned(), request.project.as_str().to_owned()),
                (
                    "analysisId".to_owned(),
                    request.analysis.key.as_str().to_owned(),
                ),
            ],
            Self::MeasuresComponent(request) => vec![
                ("component".to_owned(), request.project.as_str().to_owned()),
                (
                    "metricKeys".to_owned(),
                    request
                        .selectors
                        .iter()
                        .map(MeasureSelector::api_key)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    request.branch_or_pull_request.query_name().to_owned(),
                    request.branch_or_pull_request.key().to_owned(),
                ),
            ],
        };
        parameters.sort_unstable();
        parameters
    }

    pub fn query_digest(&self) -> Digest {
        Digest::from_serialized(&self.query_parameters())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportRequestRecord {
    pub provenance: TransportProvenance,
    pub endpoint: SonarQubeEndpoint,
    pub path: String,
    pub query_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl TransportRequestRecord {
    fn from_request(request: &SonarQubeReadRequest, provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            endpoint: request.endpoint(),
            path: request.path().to_owned(),
            query_digest: request.query_digest(),
            connected: provenance.connected(),
            native: provenance.native(),
            first_party: provenance.first_party(),
        }
    }
}

/// Analysis history page returned by the typed recording/fixture boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisPage {
    pub scope_digest: Digest,
    pub project: SonarProjectKey,
    pub branch_or_pull_request: BranchOrPullRequest,
    pub page: usize,
    pub page_size: usize,
    pub analyses: Vec<AnalysisIdentity>,
    pub next_page: Option<usize>,
    pub partial: bool,
    pub truncated: bool,
    pub response_bytes: usize,
    pub redacted: bool,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl AnalysisPage {
    pub fn new(
        scope: &SonarQubeQualityScope,
        page: usize,
        analyses: Vec<AnalysisIdentity>,
        next_page: Option<usize>,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut response = Self {
            scope_digest: scope.digest(),
            project: scope.project.clone(),
            branch_or_pull_request: scope.branch_or_pull_request.clone(),
            page,
            page_size: MAX_PAGE_SIZE,
            analyses,
            next_page,
            partial: false,
            truncated: false,
            response_bytes: 512,
            redacted: true,
            provenance,
            response_digest: Digest::from_text("unsealed-sonarqube-analysis-page"),
        };
        response.seal();
        response.validate_shape(&ReadLimits::default())?;
        Ok(response)
    }

    #[must_use]
    pub fn with_page_size(mut self, page_size: usize) -> Self {
        self.page_size = page_size;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_redacted(mut self, redacted: bool) -> Self {
        self.redacted = redacted;
        self.seal();
        self
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.project,
            &self.branch_or_pull_request,
            self.page,
            self.page_size,
            &self.analyses,
            self.next_page,
            self.partial,
            self.truncated,
            self.response_bytes,
            self.redacted,
            self.provenance,
        ))
    }

    pub fn validate_shape(&self, limits: &ReadLimits) -> Result<()> {
        limits.validate()?;
        self.scope_digest.validate()?;
        self.project.validate()?;
        self.branch_or_pull_request.validate()?;
        if self.page == 0
            || self.page > limits.max_analysis_pages
            || self.page_size == 0
            || self.page_size > limits.page_size
            || self.analyses.len() > limits.max_analyses
            || self.response_bytes > limits.max_response_bytes
        {
            return Err(SonarQubeQualityResultError::ResponseTooLarge);
        }
        if let Some(next_page) = self.next_page
            && (next_page <= self.page || next_page > MAX_ANALYSIS_PAGES)
        {
            return Err(SonarQubeQualityResultError::PaginationLoop);
        }
        let mut identities = BTreeSet::new();
        for analysis in &self.analyses {
            analysis.validate()?;
            if !identities.insert(analysis) {
                return Err(SonarQubeQualityResultError::DuplicateAnalysis);
            }
        }
        if !self.redacted {
            return Err(SonarQubeQualityResultError::ResponseNotRedacted);
        }
        if self.response_digest != self.computed_digest() {
            return Err(SonarQubeQualityResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn seal(&mut self) {
        self.response_digest = self.computed_digest();
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualityGateStatusResponse {
    pub scope_digest: Digest,
    pub analysis: AnalysisIdentity,
    pub quality_gate: QualityGateIdentity,
    pub status: QualityGateStatus,
    pub conditions: Vec<QualityGateCondition>,
    pub ignored_conditions: bool,
    pub partial: bool,
    pub truncated: bool,
    pub response_bytes: usize,
    pub redacted: bool,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl QualityGateStatusResponse {
    pub fn new(
        scope: &SonarQubeQualityScope,
        analysis: AnalysisIdentity,
        quality_gate: QualityGateIdentity,
        status: QualityGateStatus,
        conditions: Vec<QualityGateCondition>,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut response = Self {
            scope_digest: scope.digest(),
            analysis,
            quality_gate,
            status,
            conditions,
            ignored_conditions: false,
            partial: false,
            truncated: false,
            response_bytes: 512,
            redacted: true,
            provenance,
            response_digest: Digest::from_text("unsealed-sonarqube-quality-gate-response"),
        };
        response.seal();
        response.validate_shape(&ReadLimits::default())?;
        Ok(response)
    }

    #[must_use]
    pub fn with_ignored_conditions(mut self, ignored: bool) -> Self {
        self.ignored_conditions = ignored;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_redacted(mut self, redacted: bool) -> Self {
        self.redacted = redacted;
        self.seal();
        self
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.analysis,
            &self.quality_gate,
            self.status,
            &self.conditions,
            self.ignored_conditions,
            self.partial,
            self.truncated,
            self.response_bytes,
            self.redacted,
            self.provenance,
        ))
    }

    pub fn validate_shape(&self, limits: &ReadLimits) -> Result<()> {
        limits.validate()?;
        self.scope_digest.validate()?;
        self.analysis.validate()?;
        self.quality_gate.validate()?;
        if self.conditions.len() > limits.max_conditions
            || self.response_bytes > limits.max_response_bytes
        {
            return Err(SonarQubeQualityResultError::ResponseTooLarge);
        }
        let mut selectors = BTreeSet::new();
        for condition in &self.conditions {
            condition.validate()?;
            if !selectors.insert(&condition.selector) {
                return Err(SonarQubeQualityResultError::MeasureDrift);
            }
        }
        if !self.redacted {
            return Err(SonarQubeQualityResultError::ResponseNotRedacted);
        }
        if self.response_digest != self.computed_digest() {
            return Err(SonarQubeQualityResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn seal(&mut self) {
        self.response_digest = self.computed_digest();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeasuresComponentResponse {
    pub scope_digest: Digest,
    pub project: SonarProjectKey,
    pub branch_or_pull_request: BranchOrPullRequest,
    pub analysis: AnalysisIdentity,
    pub measures: Vec<Measure>,
    pub partial: bool,
    pub truncated: bool,
    pub response_bytes: usize,
    pub redacted: bool,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl MeasuresComponentResponse {
    pub fn new(
        scope: &SonarQubeQualityScope,
        analysis: AnalysisIdentity,
        measures: Vec<Measure>,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut response = Self {
            scope_digest: scope.digest(),
            project: scope.project.clone(),
            branch_or_pull_request: scope.branch_or_pull_request.clone(),
            analysis,
            measures,
            partial: false,
            truncated: false,
            response_bytes: 512,
            redacted: true,
            provenance,
            response_digest: Digest::from_text("unsealed-sonarqube-measures-response"),
        };
        response.seal();
        response.validate_shape(&ReadLimits::default())?;
        Ok(response)
    }

    #[must_use]
    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self.seal();
        self
    }

    #[must_use]
    pub fn with_redacted(mut self, redacted: bool) -> Self {
        self.redacted = redacted;
        self.seal();
        self
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.project,
            &self.branch_or_pull_request,
            &self.analysis,
            &self.measures,
            self.partial,
            self.truncated,
            self.response_bytes,
            self.redacted,
            self.provenance,
        ))
    }

    pub fn validate_shape(&self, limits: &ReadLimits) -> Result<()> {
        limits.validate()?;
        self.scope_digest.validate()?;
        self.project.validate()?;
        self.branch_or_pull_request.validate()?;
        self.analysis.validate()?;
        if self.measures.len() > limits.max_measures
            || self.response_bytes > limits.max_response_bytes
        {
            return Err(SonarQubeQualityResultError::ResponseTooLarge);
        }
        let mut selectors = BTreeSet::new();
        for measure in &self.measures {
            measure.validate()?;
            if !selectors.insert(&measure.selector) {
                return Err(SonarQubeQualityResultError::MeasureDrift);
            }
        }
        if !self.redacted {
            return Err(SonarQubeQualityResultError::ResponseNotRedacted);
        }
        if self.response_digest != self.computed_digest() {
            return Err(SonarQubeQualityResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn seal(&mut self) {
        self.response_digest = self.computed_digest();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SonarQubeResponse {
    ProjectAnalysesSearch(AnalysisPage),
    QualityGatesProjectStatus(QualityGateStatusResponse),
    MeasuresComponent(MeasuresComponentResponse),
}

impl SonarQubeResponse {
    pub const fn endpoint(&self) -> SonarQubeEndpoint {
        match self {
            Self::ProjectAnalysesSearch(_) => SonarQubeEndpoint::ProjectAnalysesSearch,
            Self::QualityGatesProjectStatus(_) => SonarQubeEndpoint::QualityGatesProjectStatus,
            Self::MeasuresComponent(_) => SonarQubeEndpoint::MeasuresComponent,
        }
    }

    pub fn provenance(&self) -> TransportProvenance {
        match self {
            Self::ProjectAnalysesSearch(page) => page.provenance,
            Self::QualityGatesProjectStatus(response) => response.provenance,
            Self::MeasuresComponent(response) => response.provenance,
        }
    }
}

/// Typed transport failures do not retain raw provider responses, headers,
/// URLs, or credentials.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SonarQubeTransportError {
    #[error("environment is blocked for native SonarQube access")]
    BlockedEnv,
    #[error("SonarQube returned HTTP 401 Unauthorized")]
    Unauthorized401,
    #[error("SonarQube returned HTTP 403 Forbidden")]
    Forbidden403,
    #[error("SonarQube returned HTTP 404 Not Found")]
    NotFound404,
    #[error("SonarQube returned HTTP 409 Conflict")]
    Conflict409,
    #[error("SonarQube returned HTTP 429 Rate Limited")]
    RateLimited429,
    #[error("SonarQube request timed out")]
    Timeout,
    #[error("SonarQube returned server HTTP {status}")]
    Server5xx { status: u16 },
    #[error("SonarQube fixture has no queued response")]
    NoFixture,
    #[error("SonarQube response was malformed")]
    MalformedResponse,
}

/// Provider-bound failures retain classification only and fail closed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SonarQubeProviderError {
    #[error("provider input or registration is invalid: {0}")]
    Contract(#[from] SonarQubeQualityResultError),
    #[error("provider registration is inactive")]
    RegistrationInactive,
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("opaque provider SecretReference is revoked")]
    SecretRevoked,
    #[error("response was from an unexpected endpoint")]
    EndpointMismatch,
    #[error("response provenance was not the transport provenance")]
    ProvenanceMismatch,
    #[error("provider returned a response outside the exact scope")]
    ScopeMismatch,
    #[error("analysis revision drifted")]
    AnalysisDrift,
    #[error("quality-gate identity drifted")]
    QualityGateDrift,
    #[error("measure selection drifted")]
    MeasureDrift,
    #[error("provider transport failed: {0}")]
    Transport(#[from] SonarQubeTransportError),
}

/// A read-only transport sees a typed request and can only return one of the
/// three typed response variants. There is no mutation method and no secret
/// material parameter.
pub trait SonarQubeTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn read(
        &mut self,
        request: &SonarQubeReadRequest,
    ) -> std::result::Result<SonarQubeResponse, SonarQubeTransportError>;
    fn requests(&self) -> &[TransportRequestRecord];
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    responses: VecDeque<std::result::Result<SonarQubeResponse, SonarQubeTransportError>>,
    requests: Vec<TransportRequestRecord>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn fixture() -> Self {
        Self::new(TransportProvenance::Fixture)
    }

    pub fn recording() -> Self {
        Self::new(TransportProvenance::Recording)
    }

    pub fn loopback() -> Self {
        Self::new(TransportProvenance::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportProvenance::BlockedEnv)
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    pub fn push_response(&mut self, response: SonarQubeResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: SonarQubeTransportError) {
        self.responses.push_back(Err(error));
    }

    pub fn push_analysis_page(&mut self, page: AnalysisPage) {
        self.push_response(SonarQubeResponse::ProjectAnalysesSearch(page));
    }

    pub fn push_quality_gate(&mut self, response: QualityGateStatusResponse) {
        self.push_response(SonarQubeResponse::QualityGatesProjectStatus(response));
    }

    pub fn push_measures(&mut self, response: MeasuresComponentResponse) {
        self.push_response(SonarQubeResponse::MeasuresComponent(response));
    }

    pub fn requests(&self) -> &[TransportRequestRecord] {
        &self.requests
    }
}

impl SonarQubeTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read(
        &mut self,
        request: &SonarQubeReadRequest,
    ) -> std::result::Result<SonarQubeResponse, SonarQubeTransportError> {
        request
            .validate()
            .map_err(|_| SonarQubeTransportError::MalformedResponse)?;
        self.requests.push(TransportRequestRecord::from_request(
            request,
            self.provenance,
        ));
        if self.provenance == TransportProvenance::BlockedEnv {
            return Err(SonarQubeTransportError::BlockedEnv);
        }
        match self.responses.pop_front() {
            Some(response) => response,
            None => Err(SonarQubeTransportError::NoFixture),
        }
    }

    fn requests(&self) -> &[TransportRequestRecord] {
        &self.requests
    }
}

pub type FixtureTransport = RecordingTransport;
pub type LoopbackTransport = RecordingTransport;
pub type BlockedEnvTransport = RecordingTransport;

/// Provider state projected from the three typed API reads. It contains only
/// bounded metadata and digests; no raw SonarQube body is retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SonarQubeQualityProjection {
    pub scope: SonarQubeQualityScope,
    pub state: ProjectionState,
    pub analysis: Option<AnalysisIdentity>,
    pub quality_gate: Option<QualityGateIdentity>,
    pub quality_gate_status: Option<QualityGateStatus>,
    pub conditions: Vec<QualityGateCondition>,
    pub measures: Vec<Measure>,
    pub analysis_digest: Option<Digest>,
    pub quality_gate_digest: Option<Digest>,
    pub measure_digest: Option<Digest>,
    pub response_digests: Vec<Digest>,
    pub provenance: TransportProvenance,
    pub partial: bool,
    pub projection_digest: Digest,
}

impl SonarQubeQualityProjection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &SonarQubeQualityScope,
        state: ProjectionState,
        analysis: Option<AnalysisIdentity>,
        quality_gate: Option<QualityGateIdentity>,
        quality_gate_status: Option<QualityGateStatus>,
        conditions: Vec<QualityGateCondition>,
        measures: Vec<Measure>,
        response_digests: Vec<Digest>,
        provenance: TransportProvenance,
        partial: bool,
    ) -> Self {
        let mut projection = Self {
            scope: scope.clone(),
            state,
            analysis_digest: analysis.as_ref().map(AnalysisIdentity::digest),
            quality_gate_digest: quality_gate.as_ref().map(QualityGateIdentity::digest),
            measure_digest: (!measures.is_empty()).then(|| Digest::from_serialized(&measures)),
            analysis,
            quality_gate,
            quality_gate_status,
            conditions,
            measures,
            response_digests,
            provenance,
            partial,
            projection_digest: Digest::from_text("unsealed-sonarqube-quality-projection"),
        };
        projection.projection_digest = projection.computed_digest();
        projection
    }

    pub fn no_analysis(
        scope: &SonarQubeQualityScope,
        response_digests: Vec<Digest>,
        provenance: TransportProvenance,
    ) -> Self {
        Self::new(
            scope,
            ProjectionState::NoAnalysis,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            response_digests,
            provenance,
            false,
        )
    }

    pub fn stale(
        scope: &SonarQubeQualityScope,
        analysis: Option<AnalysisIdentity>,
        response_digests: Vec<Digest>,
        provenance: TransportProvenance,
    ) -> Self {
        Self::new(
            scope,
            ProjectionState::Stale,
            analysis,
            None,
            None,
            Vec::new(),
            Vec::new(),
            response_digests,
            provenance,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn partial(
        scope: &SonarQubeQualityScope,
        analysis: Option<AnalysisIdentity>,
        quality_gate: Option<QualityGateIdentity>,
        status: Option<QualityGateStatus>,
        conditions: Vec<QualityGateCondition>,
        measures: Vec<Measure>,
        response_digests: Vec<Digest>,
        provenance: TransportProvenance,
    ) -> Self {
        Self::new(
            scope,
            ProjectionState::Partial,
            analysis,
            quality_gate,
            status,
            conditions,
            measures,
            response_digests,
            provenance,
            true,
        )
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope,
            self.state,
            &self.analysis,
            &self.quality_gate,
            self.quality_gate_status,
            &self.conditions,
            &self.measures,
            &self.analysis_digest,
            &self.quality_gate_digest,
            &self.measure_digest,
            &self.response_digests,
            self.provenance,
            self.partial,
        ))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope.validate()?;
        if self.conditions.len() > MAX_CONDITIONS || self.measures.len() > MAX_MEASURES {
            return Err(SonarQubeQualityResultError::ResponseTooLarge);
        }
        if let Some(analysis) = &self.analysis {
            analysis.validate()?;
        }
        if let Some(gate) = &self.quality_gate {
            gate.validate()?;
        }
        for condition in &self.conditions {
            condition.validate()?;
        }
        for measure in &self.measures {
            measure.validate()?;
        }
        for digest in &self.response_digests {
            digest.validate()?;
        }
        if self.provenance.connected() || self.provenance.native() || self.provenance.first_party()
        {
            return Err(SonarQubeQualityResultError::TamperedEvidence);
        }
        if self.projection_digest != self.computed_digest() {
            return Err(SonarQubeQualityResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }
}

/// The typed SonarQube provider. Its only operation is the bounded read
/// sequence; it has no mutation or credential-resolution seam.
#[derive(Clone, Debug)]
pub struct SonarQubeProvider<T: SonarQubeTransport> {
    transport: T,
    limits: ReadLimits,
}

impl<T: SonarQubeTransport> SonarQubeProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            limits: ReadLimits::default(),
        }
    }

    pub fn with_limits(transport: T, limits: ReadLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self { transport, limits })
    }

    pub fn limits(&self) -> &ReadLimits {
        &self.limits
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn requests(&self) -> &[TransportRequestRecord] {
        self.transport.requests()
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_quality_result(
        &mut self,
        scope: &SonarQubeQualityScope,
        secret: &SecretReference,
    ) -> std::result::Result<SonarQubeQualityProjection, SonarQubeProviderError> {
        scope.validate()?;
        if secret.is_revoked() {
            return Err(SonarQubeProviderError::SecretRevoked);
        }
        secret.validate()?;
        let provenance = self.transport.provenance();
        let scope_digest = scope.digest();
        let mut response_digests = Vec::new();
        let mut page = 1;
        let mut seen_pages = BTreeSet::new();
        let mut seen_analyses = BTreeSet::new();
        let mut selected_analysis = None;
        let mut stale_analysis = None;
        let expected_analysis = &scope.analysis;

        for _ in 0..self.limits.max_analysis_pages {
            if !seen_pages.insert(page) {
                return Err(SonarQubeProviderError::Contract(
                    SonarQubeQualityResultError::PaginationLoop,
                ));
            }
            let request = SonarQubeReadRequest::ProjectAnalysesSearch(AnalysisSearchRequest {
                host_origin: scope.host.origin.clone(),
                scope_digest: scope_digest.clone(),
                project: scope.project.clone(),
                branch_or_pull_request: scope.branch_or_pull_request.clone(),
                page,
                page_size: self.limits.page_size,
                secret_reference_digest: secret.reference_digest().clone(),
            });
            let response = self.read(&request)?;
            let SonarQubeResponse::ProjectAnalysesSearch(page_response) = response else {
                return Err(SonarQubeProviderError::EndpointMismatch);
            };
            page_response.validate_shape(&self.limits)?;
            if page_response.page_size != self.limits.page_size {
                return Err(SonarQubeProviderError::Contract(
                    SonarQubeQualityResultError::InvalidPage,
                ));
            }
            self.validate_response_scope(
                &page_response.scope_digest,
                &scope_digest,
                page_response.provenance,
            )?;
            if page_response.project != scope.project
                || page_response.branch_or_pull_request != scope.branch_or_pull_request
                || page_response.page != page
            {
                return Err(SonarQubeProviderError::ScopeMismatch);
            }
            response_digests.push(page_response.response_digest.clone());
            for analysis in &page_response.analyses {
                if !seen_analyses.insert(analysis.clone()) {
                    return Err(SonarQubeProviderError::Contract(
                        SonarQubeQualityResultError::DuplicateAnalysis,
                    ));
                }
                if analysis.key == expected_analysis.key {
                    if analysis == expected_analysis {
                        selected_analysis = Some(analysis.clone());
                    } else {
                        stale_analysis = Some(analysis.clone());
                    }
                }
            }
            if page_response.partial || page_response.truncated {
                return Ok(SonarQubeQualityProjection::partial(
                    scope,
                    selected_analysis,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    response_digests,
                    provenance,
                ));
            }
            match page_response.next_page {
                Some(_next_page) if seen_pages.len() == self.limits.max_analysis_pages => {
                    return Err(SonarQubeProviderError::Contract(
                        SonarQubeQualityResultError::PaginationLoop,
                    ));
                }
                Some(next_page) => page = next_page,
                None => break,
            }
        }

        if let Some(analysis) = selected_analysis {
            self.read_selected_analysis(scope, secret, analysis, response_digests, provenance)
        } else if stale_analysis.is_some() {
            Ok(SonarQubeQualityProjection::stale(
                scope,
                stale_analysis,
                response_digests,
                provenance,
            ))
        } else {
            Ok(SonarQubeQualityProjection::no_analysis(
                scope,
                response_digests,
                provenance,
            ))
        }
    }

    #[allow(clippy::unnested_or_patterns)]
    pub fn projection_state_for_error(error: &SonarQubeProviderError) -> ProjectionState {
        match error {
            SonarQubeProviderError::Transport(SonarQubeTransportError::Unauthorized401)
            | SonarQubeProviderError::Transport(SonarQubeTransportError::Forbidden403) => {
                ProjectionState::AccessLoss
            }
            SonarQubeProviderError::Transport(SonarQubeTransportError::NotFound404)
            | SonarQubeProviderError::Transport(SonarQubeTransportError::Conflict409)
            | SonarQubeProviderError::Transport(SonarQubeTransportError::RateLimited429)
            | SonarQubeProviderError::Transport(SonarQubeTransportError::Timeout)
            | SonarQubeProviderError::Transport(SonarQubeTransportError::Server5xx { .. })
            | SonarQubeProviderError::Transport(SonarQubeTransportError::BlockedEnv)
            | SonarQubeProviderError::Transport(SonarQubeTransportError::NoFixture)
            | SonarQubeProviderError::Transport(SonarQubeTransportError::MalformedResponse)
            | SonarQubeProviderError::EndpointMismatch
            | SonarQubeProviderError::ProvenanceMismatch
            | SonarQubeProviderError::ScopeMismatch => ProjectionState::ProviderUnknown,
            SonarQubeProviderError::SecretRevoked
            | SonarQubeProviderError::RegistrationInactive
            | SonarQubeProviderError::RegistrationRevoked
            | SonarQubeProviderError::Contract(_)
            | SonarQubeProviderError::AnalysisDrift
            | SonarQubeProviderError::QualityGateDrift
            | SonarQubeProviderError::MeasureDrift => ProjectionState::Stale,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn read_selected_analysis(
        &mut self,
        scope: &SonarQubeQualityScope,
        secret: &SecretReference,
        analysis: AnalysisIdentity,
        mut response_digests: Vec<Digest>,
        provenance: TransportProvenance,
    ) -> std::result::Result<SonarQubeQualityProjection, SonarQubeProviderError> {
        let scope_digest = scope.digest();
        let gate_request =
            SonarQubeReadRequest::QualityGatesProjectStatus(QualityGateStatusRequest {
                host_origin: scope.host.origin.clone(),
                scope_digest: scope_digest.clone(),
                project: scope.project.clone(),
                analysis: analysis.clone(),
                secret_reference_digest: secret.reference_digest().clone(),
            });
        let gate_response = self.read(&gate_request)?;
        let SonarQubeResponse::QualityGatesProjectStatus(gate) = gate_response else {
            return Err(SonarQubeProviderError::EndpointMismatch);
        };
        gate.validate_shape(&self.limits)?;
        self.validate_response_scope(&gate.scope_digest, &scope_digest, gate.provenance)?;
        if gate.analysis != analysis {
            if gate.analysis.key == scope.analysis.key {
                return Ok(SonarQubeQualityProjection::stale(
                    scope,
                    Some(gate.analysis),
                    response_digests,
                    provenance,
                ));
            }
            return Err(SonarQubeProviderError::AnalysisDrift);
        }
        if gate.quality_gate != scope.quality_gate {
            return Err(SonarQubeProviderError::QualityGateDrift);
        }
        let expected_selectors: BTreeSet<_> = scope.measures.iter().collect();
        if gate
            .conditions
            .iter()
            .any(|condition| !expected_selectors.contains(&condition.selector))
        {
            return Err(SonarQubeProviderError::MeasureDrift);
        }
        response_digests.push(gate.response_digest.clone());
        if gate.partial || gate.truncated {
            return Ok(SonarQubeQualityProjection::partial(
                scope,
                Some(analysis),
                Some(gate.quality_gate),
                Some(gate.status),
                gate.conditions,
                Vec::new(),
                response_digests,
                provenance,
            ));
        }

        let measures_request = SonarQubeReadRequest::MeasuresComponent(MeasuresReadRequest {
            host_origin: scope.host.origin.clone(),
            scope_digest,
            project: scope.project.clone(),
            branch_or_pull_request: scope.branch_or_pull_request.clone(),
            analysis: analysis.clone(),
            selectors: scope.measures.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
        });
        let measures_response = self.read(&measures_request)?;
        let SonarQubeResponse::MeasuresComponent(measures_response) = measures_response else {
            return Err(SonarQubeProviderError::EndpointMismatch);
        };
        measures_response.validate_shape(&self.limits)?;
        self.validate_response_scope(
            &measures_response.scope_digest,
            &scope.digest(),
            measures_response.provenance,
        )?;
        if measures_response.project != scope.project
            || measures_response.branch_or_pull_request != scope.branch_or_pull_request
        {
            return Err(SonarQubeProviderError::ScopeMismatch);
        }
        if measures_response.analysis != analysis {
            if measures_response.analysis.key == scope.analysis.key {
                return Ok(SonarQubeQualityProjection::stale(
                    scope,
                    Some(measures_response.analysis),
                    response_digests,
                    provenance,
                ));
            }
            return Err(SonarQubeProviderError::AnalysisDrift);
        }
        response_digests.push(measures_response.response_digest.clone());

        let expected: BTreeSet<_> = scope.measures.iter().collect();
        let received: BTreeSet<_> = measures_response
            .measures
            .iter()
            .map(|measure| &measure.selector)
            .collect();
        if !received.is_subset(&expected) {
            return Err(SonarQubeProviderError::MeasureDrift);
        }
        if !measures_response.partial
            && !measures_response.truncated
            && received.len() != expected.len()
        {
            return Err(SonarQubeProviderError::Contract(
                SonarQubeQualityResultError::MeasureMissing,
            ));
        }
        if measures_response.partial || measures_response.truncated {
            return Ok(SonarQubeQualityProjection::partial(
                scope,
                Some(analysis),
                Some(gate.quality_gate),
                Some(gate.status),
                gate.conditions,
                measures_response.measures,
                response_digests,
                provenance,
            ));
        }
        let state = match gate.status {
            QualityGateStatus::Ok => ProjectionState::Pass,
            QualityGateStatus::Warn => ProjectionState::Warn,
            QualityGateStatus::Error => ProjectionState::Error,
            QualityGateStatus::None => ProjectionState::NoAnalysis,
        };
        Ok(SonarQubeQualityProjection::new(
            scope,
            state,
            Some(analysis),
            Some(gate.quality_gate),
            Some(gate.status),
            gate.conditions,
            measures_response.measures,
            response_digests,
            provenance,
            false,
        ))
    }

    fn read(
        &mut self,
        request: &SonarQubeReadRequest,
    ) -> std::result::Result<SonarQubeResponse, SonarQubeProviderError> {
        request.validate()?;
        let response = self.transport.read(request)?;
        if response.endpoint() != request.endpoint() {
            return Err(SonarQubeProviderError::EndpointMismatch);
        }
        if response.provenance() != self.transport.provenance() {
            return Err(SonarQubeProviderError::ProvenanceMismatch);
        }
        Ok(response)
    }

    fn validate_response_scope(
        &self,
        response_scope_digest: &Digest,
        expected_scope_digest: &Digest,
        provenance: TransportProvenance,
    ) -> std::result::Result<(), SonarQubeProviderError> {
        if response_scope_digest != expected_scope_digest {
            return Err(SonarQubeProviderError::ScopeMismatch);
        }
        if provenance != self.transport.provenance()
            || provenance.connected()
            || provenance.native()
            || provenance.first_party()
        {
            return Err(SonarQubeProviderError::ProvenanceMismatch);
        }
        Ok(())
    }
}

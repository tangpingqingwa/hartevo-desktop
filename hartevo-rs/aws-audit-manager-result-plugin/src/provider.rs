//! Provider and transport seams for AWS Audit Manager.
//!
//! No implementation in this module resolves credentials or opens a native
//! HTTPS connection.  Transports are explicit recording, fixture, loopback,
//! or `BLOCKED_ENV` seams and all provenance flags are hard-coded false for
//! connected/native/first-party/provider-receipt claims.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use crate::error::{AwsAuditManagerError, AwsAuditManagerTransportError};
use crate::model::{
    AssessmentDetail, AssessmentReportInput, AssessmentReportSummary, AssessmentStatus,
    AssessmentSummary, AssessmentSummaryInput, AuditManagerOperation, AwsAuditManagerReadResult,
    AwsAuditManagerScope, ControlSetSummary, EvidencePeriod, GetAssessmentRequest,
    GetAssessmentResponse, ListAssessmentReportsRequest, ListAssessmentReportsResponse,
    ListAssessmentsRequest, ListAssessmentsResponse, OpaqueCursor, ProviderProvenance,
    ReportStatus,
};
use crate::{AWS_AUDIT_MANAGER_API_REVISION, AWS_AUDIT_MANAGER_PLUGIN_VERSION, MAX_RESPONSE_BYTES};

pub use crate::model::AuditManagerOperation as AwsAuditManagerOperation;

pub type ProviderRead = AwsAuditManagerReadResult;
pub type AwsAuditManagerProviderError = ProviderError;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("AWS Audit Manager provider definition is invalid")]
    DefinitionInvalid,
    #[error("AWS Audit Manager provider definition drifted")]
    DefinitionDrift,
    #[error("AWS Audit Manager provider request is invalid")]
    InvalidRequest,
    #[error("AWS Audit Manager provider response was tampered or malformed")]
    InvalidResponse,
    #[error("AWS Audit Manager provider response did not match the request")]
    RequestMismatch,
    #[error("AWS Audit Manager provider transport failed: {0}")]
    Transport(#[from] AwsAuditManagerTransportError),
    #[error("AWS Audit Manager provider model failed: {0}")]
    Model(#[from] AwsAuditManagerError),
}

pub type AwsAuditManagerProviderDefinitionError = ProviderError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAuditManagerProviderDefinition {
    pub id: &'static str,
    pub version: &'static str,
    pub api_revision: &'static str,
    pub operations: Vec<AuditManagerOperation>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    provider_digest: crate::model::Digest,
}

impl Default for AwsAuditManagerProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsAuditManagerProviderDefinition {
    pub fn new() -> Self {
        let operations = vec![
            AuditManagerOperation::ListAssessments,
            AuditManagerOperation::GetAssessment,
            AuditManagerOperation::ListAssessmentReports,
        ];
        let provider_digest = crate::model::Digest::from_parts(
            "aws-audit-manager-provider-definition/v1",
            &[
                ("id", crate::PROVIDER_ID.to_owned()),
                ("version", AWS_AUDIT_MANAGER_PLUGIN_VERSION.to_owned()),
                ("api", AWS_AUDIT_MANAGER_API_REVISION.to_owned()),
                (
                    "operations",
                    operations
                        .iter()
                        .map(|operation| format!("{operation:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            id: crate::PROVIDER_ID,
            version: AWS_AUDIT_MANAGER_PLUGIN_VERSION,
            api_revision: AWS_AUDIT_MANAGER_API_REVISION,
            operations,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            provider_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        let expected = Self::new();
        if self.id != expected.id
            || self.version != expected.version
            || self.api_revision != expected.api_revision
            || self.operations != expected.operations
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provider_digest != expected.provider_digest
        {
            return Err(ProviderError::DefinitionDrift);
        }
        Ok(())
    }

    pub fn digest(&self) -> crate::model::Digest {
        self.provider_digest.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRequest {
    pub operation: AuditManagerOperation,
    pub request_digest: crate::model::Digest,
    pub cursor_digest: Option<crate::model::Digest>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecordedRequestKind {
    ListAssessments,
    GetAssessment,
    ListAssessmentReports,
}

#[derive(Debug)]
pub struct RecordingAwsAuditManagerTransport {
    provenance: ProviderProvenance,
    list_assessments:
        VecDeque<std::result::Result<ListAssessmentsResponse, AwsAuditManagerTransportError>>,
    get_assessment:
        VecDeque<std::result::Result<GetAssessmentResponse, AwsAuditManagerTransportError>>,
    list_assessment_reports:
        VecDeque<std::result::Result<ListAssessmentReportsResponse, AwsAuditManagerTransportError>>,
    calls: Vec<RecordedRequest>,
}

pub type RecordingTransport = RecordingAwsAuditManagerTransport;
pub type QueuedTransport = RecordingAwsAuditManagerTransport;
pub type FakeAwsAuditManagerTransport = RecordingAwsAuditManagerTransport;
pub type FakeTransport = RecordingAwsAuditManagerTransport;

impl Default for RecordingAwsAuditManagerTransport {
    fn default() -> Self {
        Self::new(ProviderProvenance::Recording)
    }
}

impl RecordingAwsAuditManagerTransport {
    pub fn new(provenance: ProviderProvenance) -> Self {
        Self {
            provenance,
            list_assessments: VecDeque::new(),
            get_assessment: VecDeque::new(),
            list_assessment_reports: VecDeque::new(),
            calls: Vec::new(),
        }
    }

    pub fn recording() -> Self {
        Self::new(ProviderProvenance::Recording)
    }

    pub fn fixture() -> Self {
        Self::new(ProviderProvenance::Fixture)
    }

    pub fn loopback() -> Self {
        Self::new(ProviderProvenance::Loopback)
    }

    pub fn push_list_assessments_response(
        &mut self,
        response: std::result::Result<ListAssessmentsResponse, AwsAuditManagerTransportError>,
    ) {
        self.list_assessments.push_back(response);
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListAssessmentsResponse, AwsAuditManagerTransportError>,
    ) {
        self.push_list_assessments_response(response);
    }

    pub fn push_get_assessment_response(
        &mut self,
        response: std::result::Result<GetAssessmentResponse, AwsAuditManagerTransportError>,
    ) {
        self.get_assessment.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        response: std::result::Result<GetAssessmentResponse, AwsAuditManagerTransportError>,
    ) {
        self.push_get_assessment_response(response);
    }

    pub fn push_list_assessment_reports_response(
        &mut self,
        response: std::result::Result<ListAssessmentReportsResponse, AwsAuditManagerTransportError>,
    ) {
        self.list_assessment_reports.push_back(response);
    }

    pub fn push_reports_response(
        &mut self,
        response: std::result::Result<ListAssessmentReportsResponse, AwsAuditManagerTransportError>,
    ) {
        self.push_list_assessment_reports_response(response);
    }

    pub fn calls(&self) -> &[RecordedRequest] {
        &self.calls
    }

    fn record(
        &mut self,
        operation: AuditManagerOperation,
        request_digest: crate::model::Digest,
        cursor: Option<&OpaqueCursor>,
    ) {
        self.calls.push(RecordedRequest {
            operation,
            request_digest,
            cursor_digest: cursor.map(OpaqueCursor::digest),
        });
    }

    fn missing() -> AwsAuditManagerTransportError {
        AwsAuditManagerTransportError::InvalidResponse
    }
}

impl AwsAuditManagerTransport for RecordingAwsAuditManagerTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn list_assessments(
        &mut self,
        request: &ListAssessmentsRequest,
    ) -> std::result::Result<ListAssessmentsResponse, AwsAuditManagerTransportError> {
        self.record(
            AuditManagerOperation::ListAssessments,
            request.request_digest.clone(),
            request.cursor.as_ref(),
        );
        self.list_assessments
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing()))
    }

    fn get_assessment(
        &mut self,
        request: &GetAssessmentRequest,
    ) -> std::result::Result<GetAssessmentResponse, AwsAuditManagerTransportError> {
        self.record(
            AuditManagerOperation::GetAssessment,
            request.request_digest.clone(),
            None,
        );
        self.get_assessment
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing()))
    }

    fn list_assessment_reports(
        &mut self,
        request: &ListAssessmentReportsRequest,
    ) -> std::result::Result<ListAssessmentReportsResponse, AwsAuditManagerTransportError> {
        self.record(
            AuditManagerOperation::ListAssessmentReports,
            request.request_digest.clone(),
            request.cursor.as_ref(),
        );
        self.list_assessment_reports
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing()))
    }
}

pub type FixtureTransport = FixtureAwsAuditManagerTransport;
pub type LoopbackTransport = LoopbackAwsAuditManagerTransport;

#[derive(Clone, Debug)]
pub struct FixtureAwsAuditManagerTransport {
    scope: AwsAuditManagerScope,
    observed_at: DateTime<Utc>,
}

impl FixtureAwsAuditManagerTransport {
    pub fn for_scope(scope: &AwsAuditManagerScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAwsAuditManagerTransport {
    scope: AwsAuditManagerScope,
    observed_at: DateTime<Utc>,
}

impl LoopbackAwsAuditManagerTransport {
    pub fn for_scope(scope: &AwsAuditManagerScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }
}

fn fixture_period(now: DateTime<Utc>) -> EvidencePeriod {
    EvidencePeriod::new(
        now - Duration::days(30),
        now - Duration::days(1),
        now + Duration::days(30),
    )
    .expect("fixture evidence period")
}

fn fixture_summary(scope: &AwsAuditManagerScope, now: DateTime<Utc>) -> AssessmentSummary {
    AssessmentSummary::new(
        scope,
        AssessmentSummaryInput::new(
            scope.assessment().clone(),
            AssessmentStatus::Active,
            scope.framework().clone(),
            scope.control_set().clone(),
            fixture_period(now),
            crate::model::Digest::from_text("fixture-control-results"),
            now,
        )
        .expect("fixture assessment input"),
    )
    .expect("fixture assessment")
}

fn fixture_detail(scope: &AwsAuditManagerScope, now: DateTime<Utc>) -> AssessmentDetail {
    let summary = fixture_summary(scope, now);
    let control_set = ControlSetSummary::new(
        scope,
        scope.control_set().clone(),
        3,
        crate::model::Digest::from_text("fixture-control-results"),
    )
    .expect("fixture control set");
    AssessmentDetail::new(scope, summary, vec![control_set]).expect("fixture assessment detail")
}

fn fixture_report(scope: &AwsAuditManagerScope, now: DateTime<Utc>) -> AssessmentReportSummary {
    AssessmentReportSummary::new(
        scope,
        AssessmentReportInput::from_report_bytes(
            scope.report().clone(),
            ReportStatus::Complete,
            scope.assessment().clone(),
            fixture_period(now),
            b"fixture-report-bytes-never-retained",
            now,
        )
        .expect("fixture report input"),
    )
    .expect("fixture report")
}

impl AwsAuditManagerTransport for FixtureAwsAuditManagerTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn list_assessments(
        &mut self,
        request: &ListAssessmentsRequest,
    ) -> std::result::Result<ListAssessmentsResponse, AwsAuditManagerTransportError> {
        ListAssessmentsResponse::new(
            request,
            vec![fixture_summary(&self.scope, self.observed_at)],
            None,
            512,
            ProviderProvenance::Fixture,
        )
        .map_err(|_| AwsAuditManagerTransportError::InvalidResponse)
    }

    fn get_assessment(
        &mut self,
        request: &GetAssessmentRequest,
    ) -> std::result::Result<GetAssessmentResponse, AwsAuditManagerTransportError> {
        GetAssessmentResponse::new(
            request,
            fixture_detail(&self.scope, self.observed_at),
            768,
            ProviderProvenance::Fixture,
        )
        .map_err(|_| AwsAuditManagerTransportError::InvalidResponse)
    }

    fn list_assessment_reports(
        &mut self,
        request: &ListAssessmentReportsRequest,
    ) -> std::result::Result<ListAssessmentReportsResponse, AwsAuditManagerTransportError> {
        ListAssessmentReportsResponse::new(
            request,
            vec![fixture_report(&self.scope, self.observed_at)],
            None,
            512,
            ProviderProvenance::Fixture,
        )
        .map_err(|_| AwsAuditManagerTransportError::InvalidResponse)
    }
}

impl AwsAuditManagerTransport for LoopbackAwsAuditManagerTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn list_assessments(
        &mut self,
        request: &ListAssessmentsRequest,
    ) -> std::result::Result<ListAssessmentsResponse, AwsAuditManagerTransportError> {
        ListAssessmentsResponse::new(
            request,
            vec![fixture_summary(&self.scope, self.observed_at)],
            None,
            512,
            ProviderProvenance::Loopback,
        )
        .map_err(|_| AwsAuditManagerTransportError::InvalidResponse)
    }

    fn get_assessment(
        &mut self,
        request: &GetAssessmentRequest,
    ) -> std::result::Result<GetAssessmentResponse, AwsAuditManagerTransportError> {
        GetAssessmentResponse::new(
            request,
            fixture_detail(&self.scope, self.observed_at),
            768,
            ProviderProvenance::Loopback,
        )
        .map_err(|_| AwsAuditManagerTransportError::InvalidResponse)
    }

    fn list_assessment_reports(
        &mut self,
        request: &ListAssessmentReportsRequest,
    ) -> std::result::Result<ListAssessmentReportsResponse, AwsAuditManagerTransportError> {
        ListAssessmentReportsResponse::new(
            request,
            vec![fixture_report(&self.scope, self.observed_at)],
            None,
            512,
            ProviderProvenance::Loopback,
        )
        .map_err(|_| AwsAuditManagerTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAwsAuditManagerTransport;

pub type BlockedEnvTransport = BlockedEnvAwsAuditManagerTransport;

impl AwsAuditManagerTransport for BlockedEnvAwsAuditManagerTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_assessments(
        &mut self,
        _request: &ListAssessmentsRequest,
    ) -> std::result::Result<ListAssessmentsResponse, AwsAuditManagerTransportError> {
        Err(AwsAuditManagerTransportError::BlockedEnv)
    }

    fn get_assessment(
        &mut self,
        _request: &GetAssessmentRequest,
    ) -> std::result::Result<GetAssessmentResponse, AwsAuditManagerTransportError> {
        Err(AwsAuditManagerTransportError::BlockedEnv)
    }

    fn list_assessment_reports(
        &mut self,
        _request: &ListAssessmentReportsRequest,
    ) -> std::result::Result<ListAssessmentReportsResponse, AwsAuditManagerTransportError> {
        Err(AwsAuditManagerTransportError::BlockedEnv)
    }
}

pub trait AwsAuditManagerTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_assessments(
        &mut self,
        request: &ListAssessmentsRequest,
    ) -> std::result::Result<ListAssessmentsResponse, AwsAuditManagerTransportError>;

    fn get_assessment(
        &mut self,
        request: &GetAssessmentRequest,
    ) -> std::result::Result<GetAssessmentResponse, AwsAuditManagerTransportError>;

    fn list_assessment_reports(
        &mut self,
        request: &ListAssessmentReportsRequest,
    ) -> std::result::Result<ListAssessmentReportsResponse, AwsAuditManagerTransportError>;
}

pub struct AwsAuditManagerProvider<T: AwsAuditManagerTransport = BlockedEnvAwsAuditManagerTransport>
{
    definition: AwsAuditManagerProviderDefinition,
    transport: T,
}

impl<T: AwsAuditManagerTransport> fmt::Debug for AwsAuditManagerProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAuditManagerProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .finish_non_exhaustive()
    }
}

impl Default for AwsAuditManagerProvider<BlockedEnvAwsAuditManagerTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvAwsAuditManagerTransport).expect("static provider definition")
    }
}

impl<T: AwsAuditManagerTransport> AwsAuditManagerProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderError> {
        let definition = AwsAuditManagerProviderDefinition::new();
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &AwsAuditManagerProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> crate::model::Digest {
        self.definition.digest()
    }

    pub fn provenance(&self) -> ProviderProvenance {
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
        request: &AwsAuditManagerReadRequest,
    ) -> std::result::Result<ProviderRead, ProviderError> {
        match request {
            AwsAuditManagerReadRequest::ListAssessments(request) => self
                .read_list_assessments(request)
                .map(ProviderRead::ListAssessments),
            AwsAuditManagerReadRequest::GetAssessment(request) => self
                .read_get_assessment(request)
                .map(ProviderRead::GetAssessment),
            AwsAuditManagerReadRequest::ListAssessmentReports(request) => self
                .read_list_assessment_reports(request)
                .map(ProviderRead::ListAssessmentReports),
        }
    }

    pub fn read_list_assessments(
        &mut self,
        request: &ListAssessmentsRequest,
    ) -> std::result::Result<ListAssessmentsResponse, ProviderError> {
        if request.recomputed_digest() != request.request_digest {
            return Err(ProviderError::InvalidRequest);
        }
        let response = self.transport.list_assessments(request)?;
        if response.request_digest != request.request_digest
            || response.response_bytes > MAX_RESPONSE_BYTES
            || response.assessments.len() > request.page_size as usize
        {
            return Err(ProviderError::RequestMismatch);
        }
        response.validate(request).map_err(ProviderError::from)?;
        Ok(response)
    }

    pub fn list_assessments(
        &mut self,
        request: &ListAssessmentsRequest,
    ) -> std::result::Result<ListAssessmentsResponse, ProviderError> {
        self.read_list_assessments(request)
    }

    pub fn read_get_assessment(
        &mut self,
        request: &GetAssessmentRequest,
    ) -> std::result::Result<GetAssessmentResponse, ProviderError> {
        if request.request_digest.as_str().is_empty() {
            return Err(ProviderError::InvalidRequest);
        }
        let response = self.transport.get_assessment(request)?;
        if response.request_digest != request.request_digest
            || response.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ProviderError::RequestMismatch);
        }
        response.validate(request).map_err(ProviderError::from)?;
        Ok(response)
    }

    pub fn get_assessment(
        &mut self,
        request: &GetAssessmentRequest,
    ) -> std::result::Result<GetAssessmentResponse, ProviderError> {
        self.read_get_assessment(request)
    }

    pub fn read_list_assessment_reports(
        &mut self,
        request: &ListAssessmentReportsRequest,
    ) -> std::result::Result<ListAssessmentReportsResponse, ProviderError> {
        if request.recomputed_digest() != request.request_digest {
            return Err(ProviderError::InvalidRequest);
        }
        let response = self.transport.list_assessment_reports(request)?;
        if response.request_digest != request.request_digest
            || response.response_bytes > MAX_RESPONSE_BYTES
            || response.reports.len() > request.page_size as usize
        {
            return Err(ProviderError::RequestMismatch);
        }
        response.validate(request).map_err(ProviderError::from)?;
        Ok(response)
    }

    pub fn list_assessment_reports(
        &mut self,
        request: &ListAssessmentReportsRequest,
    ) -> std::result::Result<ListAssessmentReportsResponse, ProviderError> {
        self.read_list_assessment_reports(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsAuditManagerReadRequest {
    ListAssessments(ListAssessmentsRequest),
    GetAssessment(GetAssessmentRequest),
    ListAssessmentReports(ListAssessmentReportsRequest),
}

pub fn is_access_loss(error: &AwsAuditManagerTransportError) -> bool {
    error.is_access_loss()
}

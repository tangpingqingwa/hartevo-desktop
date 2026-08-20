//! Bounded AWS Resilience Hub read requests, responses, and Layer-1 transports.

use std::{collections::VecDeque, fmt, fmt::Write};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsResilienceHubError, AwsResilienceHubTransportError, Result};
use crate::model::{
    ApplicationMetadata, ApplicationMetadataInput, AssessmentMetadata, AssessmentMetadataInput,
    AssessmentStatus, AwsResilienceHubScope, ComplianceStatus, Digest, DriftStatus, OpaqueCursor,
    PostureStatus, RiskCategory, RpoRtoPosture, TransportProvenance, bounded_page_size,
};
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_API_REVISION, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsResilienceHubOperation {
    ListApps,
    DescribeApp,
    ListAppAssessments,
    DescribeAppAssessment,
}

impl AwsResilienceHubOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListApps => "ListApps",
            Self::DescribeApp => "DescribeApp",
            Self::ListAppAssessments => "ListAppAssessments",
            Self::DescribeAppAssessment => "DescribeAppAssessment",
        }
    }

    pub const fn permission(self) -> &'static str {
        match self {
            Self::ListApps => "resiliencehub:ListApps",
            Self::DescribeApp => "resiliencehub:DescribeApp",
            Self::ListAppAssessments => "resiliencehub:ListAppAssessments",
            Self::DescribeAppAssessment => "resiliencehub:DescribeAppAssessment",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsResilienceHubOperation,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListAppsRequest {
    scope: AwsResilienceHubScope,
    max_results: u16,
    cursor: Option<OpaqueCursor>,
    page_number: u16,
    query_digest: Digest,
    request_digest: Digest,
}

impl ListAppsRequest {
    pub fn new(
        scope: &AwsResilienceHubScope,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        bounded_page_size(max_results)?;
        let query_digest = Digest::from_parts(
            "aws-resilience-hub-list-apps-query/v1",
            &[
                ("account", scope.account().digest().as_str().to_owned()),
                ("region", scope.region().digest().as_str().to_owned()),
                (
                    "application_allowlist",
                    scope.application_allowlist().digest().as_str().to_owned(),
                ),
            ],
        );
        let page_number = cursor.as_ref().map_or(1, OpaqueCursor::page_number);
        if let Some(cursor) = &cursor {
            cursor.validate_against(
                scope,
                AwsResilienceHubOperation::ListApps.as_str(),
                &query_digest,
                page_number,
            )?;
        }
        let request_digest = request_digest(
            AwsResilienceHubOperation::ListApps,
            scope,
            &query_digest,
            max_results,
            page_number,
            cursor.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            max_results,
            cursor,
            page_number,
            query_digest,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsResilienceHubScope {
        &self.scope
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        path_with_cursor(
            "/apps",
            self.max_results,
            self.cursor.as_ref(),
            self.query_digest.as_str(),
        )
    }

    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsResilienceHubOperation::ListApps,
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeAppRequest {
    scope: AwsResilienceHubScope,
    application_digest: Digest,
    request_digest: Digest,
}

impl DescribeAppRequest {
    pub fn for_scope(scope: &AwsResilienceHubScope) -> Result<Self> {
        let query_digest = Digest::from_parts(
            "aws-resilience-hub-describe-app-query/v1",
            &[(
                "application",
                scope.application().digest().as_str().to_owned(),
            )],
        );
        let request_digest = request_digest(
            AwsResilienceHubOperation::DescribeApp,
            scope,
            &query_digest,
            0,
            1,
            None,
        );
        Ok(Self {
            scope: scope.clone(),
            application_digest: scope.application().digest(),
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsResilienceHubScope {
        &self.scope
    }

    pub fn application_digest(&self) -> &Digest {
        &self.application_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/app?applicationDigest={}",
            self.application_digest.as_str()
        )
    }

    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsResilienceHubOperation::DescribeApp,
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListAppAssessmentsRequest {
    scope: AwsResilienceHubScope,
    max_results: u16,
    cursor: Option<OpaqueCursor>,
    page_number: u16,
    query_digest: Digest,
    request_digest: Digest,
}

impl ListAppAssessmentsRequest {
    pub fn new(
        scope: &AwsResilienceHubScope,
        max_results: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        bounded_page_size(max_results)?;
        let query_digest = Digest::from_parts(
            "aws-resilience-hub-list-app-assessments-query/v1",
            &[
                (
                    "application",
                    scope.application().digest().as_str().to_owned(),
                ),
                (
                    "assessment_allowlist",
                    scope.assessment_allowlist().digest().as_str().to_owned(),
                ),
            ],
        );
        let page_number = cursor.as_ref().map_or(1, OpaqueCursor::page_number);
        if let Some(cursor) = &cursor {
            cursor.validate_against(
                scope,
                AwsResilienceHubOperation::ListAppAssessments.as_str(),
                &query_digest,
                page_number,
            )?;
        }
        let request_digest = request_digest(
            AwsResilienceHubOperation::ListAppAssessments,
            scope,
            &query_digest,
            max_results,
            page_number,
            cursor.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            max_results,
            cursor,
            page_number,
            query_digest,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsResilienceHubScope {
        &self.scope
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        path_with_cursor(
            "/app-assessments",
            self.max_results,
            self.cursor.as_ref(),
            self.query_digest.as_str(),
        )
    }

    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsResilienceHubOperation::ListAppAssessments,
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeAppAssessmentRequest {
    scope: AwsResilienceHubScope,
    assessment_digest: Digest,
    request_digest: Digest,
}

impl DescribeAppAssessmentRequest {
    pub fn for_scope(scope: &AwsResilienceHubScope) -> Result<Self> {
        let query_digest = Digest::from_parts(
            "aws-resilience-hub-describe-app-assessment-query/v1",
            &[(
                "assessment",
                scope.assessment().digest().as_str().to_owned(),
            )],
        );
        let request_digest = request_digest(
            AwsResilienceHubOperation::DescribeAppAssessment,
            scope,
            &query_digest,
            0,
            1,
            None,
        );
        Ok(Self {
            scope: scope.clone(),
            assessment_digest: scope.assessment().digest(),
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsResilienceHubScope {
        &self.scope
    }

    pub fn assessment_digest(&self) -> &Digest {
        &self.assessment_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/app-assessment?assessmentDigest={}",
            self.assessment_digest.as_str()
        )
    }

    pub(crate) fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsResilienceHubOperation::DescribeAppAssessment,
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAppsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub applications: Vec<ApplicationMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListAppsResponse {
    pub fn new(
        request: &ListAppsRequest,
        applications: Vec<ApplicationMetadata>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            applications,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-resilience-hub-list-apps"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListAppsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.applications.len() > request.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::TamperedEvidence);
        }
        for application in &self.applications {
            if !request
                .scope()
                .application_allowlist()
                .allows_digest(application.application_digest())
            {
                return Err(AwsResilienceHubError::ApplicationNotAllowed);
            }
            if application.application_version_digest()
                != &request.scope().application_version().digest()
                || application.resiliency_policy_digest()
                    != &request.scope().resiliency_policy().digest()
            {
                return Err(AwsResilienceHubError::ApplicationVersionDrift);
            }
        }
        validate_cursor(
            self.next_cursor.as_ref(),
            request.scope(),
            AwsResilienceHubOperation::ListApps.as_str(),
            request.query_digest(),
            request.page_number().saturating_add(1),
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-list-apps-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "applications",
                    self.applications
                        .iter()
                        .map(|application| application.evidence_digest().as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAppResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub application: ApplicationMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeAppResponse {
    pub fn new(
        request: &DescribeAppRequest,
        application: ApplicationMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            application,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-resilience-hub-describe-app"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &DescribeAppRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.application.application_digest() != request.application_digest()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::TamperedEvidence);
        }
        self.application.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-describe-app-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "application",
                    self.application.evidence_digest().as_str().to_owned(),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAppAssessmentsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub assessments: Vec<AssessmentMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListAppAssessmentsResponse {
    pub fn new(
        request: &ListAppAssessmentsRequest,
        assessments: Vec<AssessmentMetadata>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            assessments,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-resilience-hub-list-assessments"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListAppAssessmentsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.assessments.len() > request.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::TamperedEvidence);
        }
        for assessment in &self.assessments {
            if !request
                .scope()
                .assessment_allowlist()
                .allows_digest(assessment.assessment_digest())
            {
                return Err(AwsResilienceHubError::AssessmentNotAllowed);
            }
            if assessment.application_digest() != &request.scope().application().digest()
                || assessment.application_version_digest()
                    != &request.scope().application_version().digest()
                || assessment.resiliency_policy_digest()
                    != &request.scope().resiliency_policy().digest()
            {
                return Err(AwsResilienceHubError::AssessmentDrift);
            }
        }
        validate_cursor(
            self.next_cursor.as_ref(),
            request.scope(),
            AwsResilienceHubOperation::ListAppAssessments.as_str(),
            request.query_digest(),
            request.page_number().saturating_add(1),
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-list-assessments-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "assessments",
                    self.assessments
                        .iter()
                        .map(|assessment| assessment.evidence_digest().as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAppAssessmentResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub assessment: AssessmentMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeAppAssessmentResponse {
    pub fn new(
        request: &DescribeAppAssessmentRequest,
        assessment: AssessmentMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            assessment,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-resilience-hub-describe-assessment"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &DescribeAppAssessmentRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.assessment.assessment_digest() != request.assessment_digest()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::TamperedEvidence);
        }
        self.assessment.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-describe-assessment-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "assessment",
                    self.assessment.evidence_digest().as_str().to_owned(),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct AwsResilienceHubProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsResilienceHubProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsResilienceHubError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-resilience-hub-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-resilience-hub-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.provider_revision, self.release.clone())?;
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.capability_digest != expected.capability_digest
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest != expected.provider_digest
        {
            Err(AwsResilienceHubError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsResilienceHubProviderDefinition {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsResilienceHubProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

pub trait AwsResilienceHubTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<ListAppsResponse, AwsResilienceHubTransportError>;
    fn describe_app(
        &mut self,
        request: &DescribeAppRequest,
    ) -> std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError>;
    fn list_app_assessments(
        &mut self,
        request: &ListAppAssessmentsRequest,
    ) -> std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError>;
    fn describe_app_assessment(
        &mut self,
        request: &DescribeAppAssessmentRequest,
    ) -> std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError>;
}

pub struct AwsResilienceHubProvider<T> {
    transport: T,
    definition: AwsResilienceHubProviderDefinition,
}

impl<T: AwsResilienceHubTransport> fmt::Debug for AwsResilienceHubProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsResilienceHubProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsResilienceHubTransport> AwsResilienceHubProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsResilienceHubProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsResilienceHubProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<ListAppsResponse, AwsResilienceHubTransportError> {
        let response = self.transport.list_apps(request)?;
        response
            .validate_integrity(request)
            .map_err(map_provider_validation_error)?;
        ensure_provenance(
            response.provenance.clone(),
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn describe_app(
        &mut self,
        request: &DescribeAppRequest,
    ) -> std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError> {
        let response = self.transport.describe_app(request)?;
        response
            .validate_integrity(request)
            .map_err(map_provider_validation_error)?;
        ensure_provenance(
            response.provenance.clone(),
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn list_app_assessments(
        &mut self,
        request: &ListAppAssessmentsRequest,
    ) -> std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError> {
        let response = self.transport.list_app_assessments(request)?;
        response
            .validate_integrity(request)
            .map_err(map_provider_validation_error)?;
        ensure_provenance(
            response.provenance.clone(),
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn describe_app_assessment(
        &mut self,
        request: &DescribeAppAssessmentRequest,
    ) -> std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError> {
        let response = self.transport.describe_app_assessment(request)?;
        response
            .validate_integrity(request)
            .map_err(map_provider_validation_error)?;
        ensure_provenance(
            response.provenance.clone(),
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl Default for AwsResilienceHubProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS Resilience Hub provider definition")
    }
}

impl<T: AwsResilienceHubTransport> AwsResilienceHubProvider<T> {
    pub fn from_registration(
        registration: &crate::service::AwsResilienceHubRegistration,
        transport: T,
    ) -> Result<Self> {
        registration.validate()?;
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsResilienceHubError::ProviderDrift);
        }
        Ok(provider)
    }
}

fn map_provider_validation_error(error: AwsResilienceHubError) -> AwsResilienceHubTransportError {
    match error {
        AwsResilienceHubError::ApplicationDrift
        | AwsResilienceHubError::ApplicationVersionDrift
        | AwsResilienceHubError::AssessmentDrift
        | AwsResilienceHubError::ResiliencyPolicyDrift
        | AwsResilienceHubError::ApplicationNotAllowed
        | AwsResilienceHubError::AssessmentNotAllowed => AwsResilienceHubTransportError::Drift,
        AwsResilienceHubError::PartialEvidence => AwsResilienceHubTransportError::Partial,
        AwsResilienceHubError::PaginationLoop => AwsResilienceHubTransportError::PaginationLoop,
        _ => AwsResilienceHubTransportError::InvalidResponse,
    }
}

fn request_digest(
    operation: AwsResilienceHubOperation,
    scope: &AwsResilienceHubScope,
    query_digest: &Digest,
    max_results: u16,
    page_number: u16,
    cursor: Option<&OpaqueCursor>,
) -> Digest {
    Digest::from_parts(
        "aws-resilience-hub-request/v1",
        &[
            ("operation", operation.as_str().to_owned()),
            ("scope", scope.digest().as_str().to_owned()),
            ("query", query_digest.as_str().to_owned()),
            ("max_results", max_results.to_string()),
            ("page", page_number.to_string()),
            (
                "cursor",
                cursor.map_or_else(String::new, |value| {
                    value.token_digest().as_str().to_owned()
                }),
            ),
        ],
    )
}

fn path_with_cursor(
    path: &str,
    max_results: u16,
    cursor: Option<&OpaqueCursor>,
    query_digest: &str,
) -> String {
    let mut path_and_query = format!("{path}?maxResults={max_results}&queryDigest={query_digest}");
    if let Some(cursor) = cursor {
        let _ = write!(
            path_and_query,
            "&nextTokenDigest={}",
            cursor.token_digest().as_str()
        );
    }
    path_and_query
}

fn validate_cursor(
    cursor: Option<&OpaqueCursor>,
    scope: &AwsResilienceHubScope,
    operation: &str,
    query_digest: &Digest,
    expected_page: u16,
) -> Result<()> {
    if let Some(cursor) = cursor {
        cursor.validate_against(scope, operation, query_digest, expected_page)?;
    }
    Ok(())
}

fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes == 0 || response_bytes > crate::MAX_RESPONSE_BYTES {
        Err(AwsResilienceHubError::PartialEvidence)
    } else {
        Ok(())
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn ensure_provenance(
    response_provenance: TransportProvenance,
    expected_provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
) -> std::result::Result<(), AwsResilienceHubTransportError> {
    if response_provenance != expected_provenance
        || connected
        || native
        || first_party
        || provider_receipt
    {
        Err(AwsResilienceHubTransportError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_apps_responses:
        VecDeque<std::result::Result<ListAppsResponse, AwsResilienceHubTransportError>>,
    describe_app_responses:
        VecDeque<std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError>>,
    list_assessments_responses:
        VecDeque<std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError>>,
    describe_assessment_responses: VecDeque<
        std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_apps_responses: VecDeque::new(),
            describe_app_responses: VecDeque::new(),
            list_assessments_responses: VecDeque::new(),
            describe_assessment_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_apps_response(
        &mut self,
        response: std::result::Result<ListAppsResponse, AwsResilienceHubTransportError>,
    ) {
        self.list_apps_responses.push_back(response);
    }

    pub fn push_describe_app_response(
        &mut self,
        response: std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError>,
    ) {
        self.describe_app_responses.push_back(response);
    }

    pub fn push_list_app_assessments_response(
        &mut self,
        response: std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError>,
    ) {
        self.list_assessments_responses.push_back(response);
    }

    pub fn push_describe_app_assessment_response(
        &mut self,
        response: std::result::Result<
            DescribeAppAssessmentResponse,
            AwsResilienceHubTransportError,
        >,
    ) {
        self.describe_assessment_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsResilienceHubTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance.clone()
    }

    fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<ListAppsResponse, AwsResilienceHubTransportError> {
        self.requests.push(request.recorded_request());
        self.list_apps_responses
            .pop_front()
            .unwrap_or(Err(AwsResilienceHubTransportError::InvalidResponse))
    }

    fn describe_app(
        &mut self,
        request: &DescribeAppRequest,
    ) -> std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_app_responses
            .pop_front()
            .unwrap_or(Err(AwsResilienceHubTransportError::InvalidResponse))
    }

    fn list_app_assessments(
        &mut self,
        request: &ListAppAssessmentsRequest,
    ) -> std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError> {
        self.requests.push(request.recorded_request());
        self.list_assessments_responses
            .pop_front()
            .unwrap_or(Err(AwsResilienceHubTransportError::InvalidResponse))
    }

    fn describe_app_assessment(
        &mut self,
        request: &DescribeAppAssessmentRequest,
    ) -> std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_assessment_responses
            .pop_front()
            .unwrap_or(Err(AwsResilienceHubTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
struct SyntheticTransport {
    scope: AwsResilienceHubScope,
    observed_at: DateTime<Utc>,
    provenance: TransportProvenance,
}

impl SyntheticTransport {
    fn new(
        scope: &AwsResilienceHubScope,
        observed_at: DateTime<Utc>,
        provenance: TransportProvenance,
    ) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
            provenance,
        }
    }

    fn application(&self) -> Result<ApplicationMetadata> {
        ApplicationMetadata::new(
            &self.scope,
            ApplicationMetadataInput {
                application_version: self.scope.application_version().clone(),
                resiliency_policy: self.scope.resiliency_policy().clone(),
                drift: DriftStatus::NotDetected,
                observed_at: self.observed_at,
                expires_at: Some(self.observed_at + Duration::hours(12)),
                status_message: Some("fixture provider message".to_owned()),
                resource_arns: vec![
                    "arn:aws:ec2:us-east-1:123456789012:instance/fixture".to_owned(),
                ],
                tags: vec!["environment=fixture".to_owned()],
            },
        )
    }

    fn assessment(&self) -> Result<AssessmentMetadata> {
        AssessmentMetadata::new(
            &self.scope,
            AssessmentMetadataInput {
                status: AssessmentStatus::Succeeded,
                compliance_status: ComplianceStatus::Compliant,
                resiliency_score: Some(92),
                rpo_rto: RpoRtoPosture::new(
                    PostureStatus::Met,
                    PostureStatus::Met,
                    Some(15),
                    Some(60),
                )?,
                drift: DriftStatus::NotDetected,
                risk_categories: vec![(RiskCategory::Availability, 0, self.observed_at)],
                observed_at: self.observed_at,
                assessed_at: Some(self.observed_at - Duration::minutes(10)),
                expires_at: Some(self.observed_at + Duration::hours(6)),
                status_message: Some("fixture assessment message".to_owned()),
                recommendation_text: Some("fixture recommendation text".to_owned()),
                resource_arns: vec!["arn:aws:rds:us-east-1:123456789012:db/fixture".to_owned()],
                tags: vec!["secret=fixture".to_owned()],
            },
        )
    }

    fn list_apps(
        &self,
        request: &ListAppsRequest,
    ) -> std::result::Result<ListAppsResponse, AwsResilienceHubTransportError> {
        ListAppsResponse::new(
            request,
            vec![
                self.application()
                    .map_err(|_| AwsResilienceHubTransportError::InvalidResponse)?,
            ],
            None,
            512,
            self.provenance.clone(),
        )
        .map_err(|_| AwsResilienceHubTransportError::InvalidResponse)
    }

    fn describe_app(
        &self,
        request: &DescribeAppRequest,
    ) -> std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError> {
        DescribeAppResponse::new(
            request,
            self.application()
                .map_err(|_| AwsResilienceHubTransportError::InvalidResponse)?,
            512,
            self.provenance.clone(),
        )
        .map_err(|_| AwsResilienceHubTransportError::InvalidResponse)
    }

    fn list_assessments(
        &self,
        request: &ListAppAssessmentsRequest,
    ) -> std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError> {
        ListAppAssessmentsResponse::new(
            request,
            vec![
                self.assessment()
                    .map_err(|_| AwsResilienceHubTransportError::InvalidResponse)?,
            ],
            None,
            512,
            self.provenance.clone(),
        )
        .map_err(|_| AwsResilienceHubTransportError::InvalidResponse)
    }

    fn describe_assessment(
        &self,
        request: &DescribeAppAssessmentRequest,
    ) -> std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError> {
        DescribeAppAssessmentResponse::new(
            request,
            self.assessment()
                .map_err(|_| AwsResilienceHubTransportError::InvalidResponse)?,
            512,
            self.provenance.clone(),
        )
        .map_err(|_| AwsResilienceHubTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    inner: SyntheticTransport,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsResilienceHubScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: SyntheticTransport::new(scope, observed_at, TransportProvenance::Fixture),
        }
    }
}

impl AwsResilienceHubTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<ListAppsResponse, AwsResilienceHubTransportError> {
        self.inner.list_apps(request)
    }

    fn describe_app(
        &mut self,
        request: &DescribeAppRequest,
    ) -> std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError> {
        self.inner.describe_app(request)
    }

    fn list_app_assessments(
        &mut self,
        request: &ListAppAssessmentsRequest,
    ) -> std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError> {
        self.inner.list_assessments(request)
    }

    fn describe_app_assessment(
        &mut self,
        request: &DescribeAppAssessmentRequest,
    ) -> std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError> {
        self.inner.describe_assessment(request)
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    inner: SyntheticTransport,
}

impl FakeTransport {
    pub fn for_scope(scope: &AwsResilienceHubScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: SyntheticTransport::new(scope, observed_at, TransportProvenance::Fake),
        }
    }
}

impl AwsResilienceHubTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<ListAppsResponse, AwsResilienceHubTransportError> {
        self.inner.list_apps(request)
    }

    fn describe_app(
        &mut self,
        request: &DescribeAppRequest,
    ) -> std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError> {
        self.inner.describe_app(request)
    }

    fn list_app_assessments(
        &mut self,
        request: &ListAppAssessmentsRequest,
    ) -> std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError> {
        self.inner.list_assessments(request)
    }

    fn describe_app_assessment(
        &mut self,
        request: &DescribeAppAssessmentRequest,
    ) -> std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError> {
        self.inner.describe_assessment(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: SyntheticTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsResilienceHubScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: SyntheticTransport::new(scope, observed_at, TransportProvenance::Loopback),
        }
    }
}

impl AwsResilienceHubTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<ListAppsResponse, AwsResilienceHubTransportError> {
        self.inner.list_apps(request)
    }

    fn describe_app(
        &mut self,
        request: &DescribeAppRequest,
    ) -> std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError> {
        self.inner.describe_app(request)
    }

    fn list_app_assessments(
        &mut self,
        request: &ListAppAssessmentsRequest,
    ) -> std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError> {
        self.inner.list_assessments(request)
    }

    fn describe_app_assessment(
        &mut self,
        request: &DescribeAppAssessmentRequest,
    ) -> std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError> {
        self.inner.describe_assessment(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsResilienceHubTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_apps(
        &mut self,
        _request: &ListAppsRequest,
    ) -> std::result::Result<ListAppsResponse, AwsResilienceHubTransportError> {
        Err(AwsResilienceHubTransportError::BlockedEnv)
    }

    fn describe_app(
        &mut self,
        _request: &DescribeAppRequest,
    ) -> std::result::Result<DescribeAppResponse, AwsResilienceHubTransportError> {
        Err(AwsResilienceHubTransportError::BlockedEnv)
    }

    fn list_app_assessments(
        &mut self,
        _request: &ListAppAssessmentsRequest,
    ) -> std::result::Result<ListAppAssessmentsResponse, AwsResilienceHubTransportError> {
        Err(AwsResilienceHubTransportError::BlockedEnv)
    }

    fn describe_app_assessment(
        &mut self,
        _request: &DescribeAppAssessmentRequest,
    ) -> std::result::Result<DescribeAppAssessmentResponse, AwsResilienceHubTransportError> {
        Err(AwsResilienceHubTransportError::BlockedEnv)
    }
}

pub type BlockedEnvAwsResilienceHubTransport = BlockedEnvTransport;
pub type FakeAwsResilienceHubTransport = FakeTransport;
pub type AwsResilienceHubListAppsRequest = ListAppsRequest;
pub type AwsResilienceHubListAppsResponse = ListAppsResponse;
pub type AwsResilienceHubDescribeAppRequest = DescribeAppRequest;
pub type AwsResilienceHubDescribeAppResponse = DescribeAppResponse;
pub type AwsResilienceHubListAppAssessmentsRequest = ListAppAssessmentsRequest;
pub type AwsResilienceHubListAppAssessmentsResponse = ListAppAssessmentsResponse;
pub type AwsResilienceHubDescribeAppAssessmentRequest = DescribeAppAssessmentRequest;
pub type AwsResilienceHubDescribeAppAssessmentResponse = DescribeAppAssessmentResponse;

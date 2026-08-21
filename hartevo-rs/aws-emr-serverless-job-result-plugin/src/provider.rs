//! Bounded provider and offline transport seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver, HTTP
//! client, application mutation, job start/cancel path, log path, artifact
//! path, or data-output path in this Layer-1 crate.

use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::error::{AwsEmrServerlessJobResultError, AwsEmrServerlessTransportError, Result};
use crate::model::{
    ApplicationRecord, AwsEmrServerlessJobResultScope, Digest, JobRunRecord, JobRunSummary,
    OpaqueNextToken, Revision, TransportProvenance, response_digest,
};
use crate::{
    CONTRACT_VERSION, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_SUMMARIES_PER_PAGE,
    PROVIDER_API_REVISION, PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsEmrServerlessOperation {
    GetApplication,
    GetJobRun,
    ListJobRuns,
}

impl AwsEmrServerlessOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetApplication => "GetApplication",
            Self::GetJobRun => "GetJobRun",
            Self::ListJobRuns => "ListJobRuns",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsEmrServerlessOperation,
    pub scope_digest: Digest,
    pub application_digest: Digest,
    pub job_run_digest: Option<Digest>,
    pub attempt: Option<u32>,
    pub next_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetApplicationRequest {
    scope_digest: Digest,
    application_id: crate::model::ApplicationId,
    request_digest: Digest,
}

impl GetApplicationRequest {
    pub fn new(scope: &AwsEmrServerlessJobResultScope) -> Self {
        let scope_digest = scope.scope_digest().clone();
        let application_id = scope.application_id().clone();
        let request_digest = response_digest(
            "aws-emr-serverless-get-application-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("application", application_id.as_str().to_owned()),
            ],
        );
        Self {
            scope_digest,
            application_id,
            request_digest,
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn application_id(&self) -> &crate::model::ApplicationId {
        &self.application_id
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsEmrServerlessOperation::GetApplication,
            scope_digest: self.scope_digest.clone(),
            application_digest: Digest::from_parts(
                "aws-emr-serverless-application-id/v1",
                &[("id", self.application_id.as_str().to_owned())],
            ),
            job_run_digest: None,
            attempt: None,
            next_token_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for GetApplicationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetApplicationRequest")
            .field("scope_digest", &self.scope_digest)
            .field("application_id", &self.application_id)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetJobRunRequest {
    scope_digest: Digest,
    application_id: crate::model::ApplicationId,
    job_run_id: crate::model::JobRunId,
    attempt: u32,
    request_digest: Digest,
}

impl GetJobRunRequest {
    pub fn new(scope: &AwsEmrServerlessJobResultScope) -> Self {
        let scope_digest = scope.scope_digest().clone();
        let application_id = scope.application_id().clone();
        let job_run_id = scope.job_run_id().clone();
        let attempt = scope.attempt();
        let request_digest = response_digest(
            "aws-emr-serverless-get-job-run-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("application", application_id.as_str().to_owned()),
                ("job_run", job_run_id.as_str().to_owned()),
                ("attempt", attempt.to_string()),
            ],
        );
        Self {
            scope_digest,
            application_id,
            job_run_id,
            attempt,
            request_digest,
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn application_id(&self) -> &crate::model::ApplicationId {
        &self.application_id
    }

    pub fn job_run_id(&self) -> &crate::model::JobRunId {
        &self.job_run_id
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsEmrServerlessOperation::GetJobRun,
            scope_digest: self.scope_digest.clone(),
            application_digest: Digest::from_parts(
                "aws-emr-serverless-application-id/v1",
                &[("id", self.application_id.as_str().to_owned())],
            ),
            job_run_digest: Some(Digest::from_parts(
                "aws-emr-serverless-job-run-id/v1",
                &[
                    ("application", self.application_id.as_str().to_owned()),
                    ("id", self.job_run_id.as_str().to_owned()),
                ],
            )),
            attempt: Some(self.attempt),
            next_token_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for GetJobRunRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetJobRunRequest")
            .field("scope_digest", &self.scope_digest)
            .field("application_id", &self.application_id)
            .field("job_run_id", &self.job_run_id)
            .field("attempt", &self.attempt)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListJobRunsRequest {
    scope_digest: Digest,
    application_id: crate::model::ApplicationId,
    max_results: u16,
    next_token: Option<OpaqueNextToken>,
    binding_digest: Digest,
    request_digest: Digest,
}

impl ListJobRunsRequest {
    pub fn new(
        scope: &AwsEmrServerlessJobResultScope,
        max_results: u16,
        next_token: Option<OpaqueNextToken>,
    ) -> Result<Self> {
        if max_results == 0 || max_results > MAX_PAGE_SIZE {
            return Err(AwsEmrServerlessJobResultError::InvalidRequest);
        }
        let scope_digest = scope.scope_digest().clone();
        let application_id = scope.application_id().clone();
        let binding_digest = Self::binding_digest_for(&scope_digest, &application_id, max_results);
        if next_token
            .as_ref()
            .is_some_and(|token| token.binding_digest() != &binding_digest)
        {
            return Err(AwsEmrServerlessJobResultError::ScopeMismatch);
        }
        let request_digest = response_digest(
            "aws-emr-serverless-list-job-runs-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("application", application_id.as_str().to_owned()),
                ("max_results", max_results.to_string()),
                (
                    "next_token",
                    next_token
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            scope_digest,
            application_id,
            max_results,
            next_token,
            binding_digest,
            request_digest,
        })
    }

    pub fn binding_digest_for(
        scope_digest: &Digest,
        application_id: &crate::model::ApplicationId,
        max_results: u16,
    ) -> Digest {
        response_digest(
            "aws-emr-serverless-list-job-runs-binding/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("application", application_id.as_str().to_owned()),
                ("max_results", max_results.to_string()),
            ],
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn application_id(&self) -> &crate::model::ApplicationId {
        &self.application_id
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn next_token(&self) -> Option<&OpaqueNextToken> {
        self.next_token.as_ref()
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsEmrServerlessOperation::ListJobRuns,
            scope_digest: self.scope_digest.clone(),
            application_digest: Digest::from_parts(
                "aws-emr-serverless-application-id/v1",
                &[("id", self.application_id.as_str().to_owned())],
            ),
            job_run_digest: None,
            attempt: None,
            next_token_digest: self.next_token.as_ref().map(OpaqueNextToken::digest),
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for ListJobRunsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListJobRunsRequest")
            .field("scope_digest", &self.scope_digest)
            .field("application_id", &self.application_id)
            .field("max_results", &self.max_results)
            .field("next_token", &self.next_token)
            .field("binding_digest", &self.binding_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetApplicationResponse {
    application: ApplicationRecord,
    scope_digest: Digest,
    credential_revision: Revision,
    payload_bytes: u64,
    response_digest: Digest,
}

impl GetApplicationResponse {
    pub fn new(
        scope_digest: Digest,
        credential_revision: Revision,
        application: ApplicationRecord,
    ) -> Self {
        let response_digest = response_digest(
            "aws-emr-serverless-get-application-response/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("credential_revision", credential_revision.get().to_string()),
                (
                    "application",
                    application.application_digest().as_str().to_owned(),
                ),
            ],
        );
        Self {
            application,
            scope_digest,
            credential_revision,
            payload_bytes: 512,
            response_digest,
        }
    }

    #[must_use]
    pub fn with_payload_bytes(mut self, payload_bytes: u64) -> Self {
        self.payload_bytes = payload_bytes;
        self
    }

    pub fn application(&self) -> &ApplicationRecord {
        &self.application
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.payload_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsEmrServerlessJobResultError::ResponseTooLarge);
        }
        self.application.validate()?;
        if self.response_digest
            != response_digest(
                "aws-emr-serverless-get-application-response/v1",
                &[
                    ("scope", self.scope_digest.as_str().to_owned()),
                    (
                        "credential_revision",
                        self.credential_revision.get().to_string(),
                    ),
                    (
                        "application",
                        self.application.application_digest().as_str().to_owned(),
                    ),
                ],
            )
        {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetJobRunResponse {
    job_run: JobRunRecord,
    scope_digest: Digest,
    credential_revision: Revision,
    payload_bytes: u64,
    response_digest: Digest,
}

impl GetJobRunResponse {
    pub fn new(scope_digest: Digest, credential_revision: Revision, job_run: JobRunRecord) -> Self {
        let response_digest = response_digest(
            "aws-emr-serverless-get-job-run-response/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("credential_revision", credential_revision.get().to_string()),
                ("job_run", job_run.job_run_digest().as_str().to_owned()),
            ],
        );
        Self {
            job_run,
            scope_digest,
            credential_revision,
            payload_bytes: 2_048,
            response_digest,
        }
    }

    #[must_use]
    pub fn with_payload_bytes(mut self, payload_bytes: u64) -> Self {
        self.payload_bytes = payload_bytes;
        self
    }

    pub fn job_run(&self) -> &JobRunRecord {
        &self.job_run
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.payload_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsEmrServerlessJobResultError::ResponseTooLarge);
        }
        self.job_run.validate()?;
        if self.response_digest
            != response_digest(
                "aws-emr-serverless-get-job-run-response/v1",
                &[
                    ("scope", self.scope_digest.as_str().to_owned()),
                    (
                        "credential_revision",
                        self.credential_revision.get().to_string(),
                    ),
                    ("job_run", self.job_run.job_run_digest().as_str().to_owned()),
                ],
            )
        {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListJobRunsResponse {
    summaries: Vec<JobRunSummary>,
    next_token: Option<OpaqueNextToken>,
    scope_digest: Digest,
    credential_revision: Revision,
    payload_bytes: u64,
    response_digest: Digest,
}

impl ListJobRunsResponse {
    pub fn new(
        scope_digest: Digest,
        credential_revision: Revision,
        summaries: Vec<JobRunSummary>,
        next_token: Option<OpaqueNextToken>,
    ) -> Result<Self> {
        if summaries.len() > MAX_SUMMARIES_PER_PAGE {
            return Err(AwsEmrServerlessJobResultError::SummaryCap);
        }
        for summary in &summaries {
            summary.validate()?;
        }
        let response_digest = response_digest(
            "aws-emr-serverless-list-job-runs-response/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("credential_revision", credential_revision.get().to_string()),
                (
                    "summaries",
                    summaries
                        .iter()
                        .map(|value| value.summary_digest().as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next_token",
                    next_token
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        );
        let payload_bytes = 256_u64.saturating_add((summaries.len() as u64).saturating_mul(256));
        Ok(Self {
            summaries,
            next_token,
            scope_digest,
            credential_revision,
            payload_bytes,
            response_digest,
        })
    }

    #[must_use]
    pub fn with_payload_bytes(mut self, payload_bytes: u64) -> Self {
        self.payload_bytes = payload_bytes;
        self
    }

    pub fn summaries(&self) -> &[JobRunSummary] {
        &self.summaries
    }

    pub fn next_token(&self) -> Option<&OpaqueNextToken> {
        self.next_token.as_ref()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.summaries.len() > MAX_SUMMARIES_PER_PAGE || self.payload_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsEmrServerlessJobResultError::ResponseTooLarge);
        }
        for summary in &self.summaries {
            summary.validate()?;
        }
        let expected = response_digest(
            "aws-emr-serverless-list-job-runs-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "credential_revision",
                    self.credential_revision.get().to_string(),
                ),
                (
                    "summaries",
                    self.summaries
                        .iter()
                        .map(|value| value.summary_digest().as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next_token",
                    self.next_token
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        );
        if self.response_digest != expected {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// The only provider transport trait exposed by Layer 1.
pub trait AwsEmrServerlessTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_application(
        &mut self,
        request: &GetApplicationRequest,
    ) -> std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError>;

    fn get_job_run(
        &mut self,
        request: &GetJobRunRequest,
    ) -> std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError>;

    fn list_job_runs(
        &mut self,
        request: &ListJobRunsRequest,
    ) -> std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsEmrServerlessProviderDefinition {
    provider_id: String,
    contract_version: String,
    api_revision: String,
    release: String,
    provenance: TransportProvenance,
    definition_digest: Digest,
}

impl AwsEmrServerlessProviderDefinition {
    pub fn new(provenance: TransportProvenance, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if release.is_empty() || release.len() > 64 || release.chars().any(char::is_control) {
            return Err(AwsEmrServerlessJobResultError::InvalidText {
                field: "provider-release",
            });
        }
        let mut value = Self {
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            release,
            provenance,
            definition_digest: Digest::from_text("unsealed-provider-definition"),
        };
        value.definition_digest = value.calculate_digest();
        Ok(value)
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    pub const fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    pub fn definition_digest(&self) -> &Digest {
        &self.definition_digest
    }

    fn calculate_digest(&self) -> Digest {
        response_digest(
            "aws-emr-serverless-provider-definition/v1",
            &[
                ("provider", self.provider_id.clone()),
                ("contract", self.contract_version.clone()),
                ("api", self.api_revision.clone()),
                ("release", self.release.clone()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.contract_version != CONTRACT_VERSION
            || self.api_revision != PROVIDER_API_REVISION
            || self.definition_digest != self.calculate_digest()
        {
            return Err(AwsEmrServerlessJobResultError::ProviderDrift);
        }
        Ok(())
    }
}

pub struct AwsEmrServerlessProvider<T> {
    transport: T,
    definition: AwsEmrServerlessProviderDefinition,
}

impl<T: AwsEmrServerlessTransport> AwsEmrServerlessProvider<T> {
    pub fn new(transport: T, release: impl Into<String>) -> Result<Self> {
        let definition = AwsEmrServerlessProviderDefinition::new(transport.provenance(), release)?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsEmrServerlessProviderDefinition {
        &self.definition
    }

    pub const fn provenance(&self) -> TransportProvenance {
        self.definition.provenance()
    }

    pub fn get_application(
        &mut self,
        request: &GetApplicationRequest,
    ) -> std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError> {
        self.transport.get_application(request)
    }

    pub fn get_job_run(
        &mut self,
        request: &GetJobRunRequest,
    ) -> std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError> {
        self.transport.get_job_run(request)
    }

    pub fn list_job_runs(
        &mut self,
        request: &ListJobRunsRequest,
    ) -> std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError> {
        self.transport.list_job_runs(request)
    }
}

impl<T: AwsEmrServerlessTransport + fmt::Debug> fmt::Debug for AwsEmrServerlessProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEmrServerlessProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
struct ScriptedResponses {
    applications:
        VecDeque<std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError>>,
    job_runs: VecDeque<std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError>>,
    lists: VecDeque<std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError>>,
}

impl ScriptedResponses {
    fn push_application(
        &mut self,
        response: std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError>,
    ) {
        self.applications.push_back(response);
    }

    fn push_job_run(
        &mut self,
        response: std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError>,
    ) {
        self.job_runs.push_back(response);
    }

    fn push_list(
        &mut self,
        response: std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError>,
    ) {
        self.lists.push_back(response);
    }

    fn application(
        &mut self,
    ) -> std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError> {
        self.applications
            .pop_front()
            .unwrap_or(Err(AwsEmrServerlessTransportError::InvalidResponse))
    }

    fn job_run(
        &mut self,
    ) -> std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError> {
        self.job_runs
            .pop_front()
            .unwrap_or(Err(AwsEmrServerlessTransportError::InvalidResponse))
    }

    fn list(&mut self) -> std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError> {
        self.lists
            .pop_front()
            .unwrap_or(Err(AwsEmrServerlessTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureTransport {
    responses: ScriptedResponses,
}

impl FixtureTransport {
    pub fn push_application_response(
        &mut self,
        response: std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_application(response);
    }

    pub fn push_job_run_response(
        &mut self,
        response: std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_job_run(response);
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_list(response);
    }
}

impl AwsEmrServerlessTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_application(
        &mut self,
        _request: &GetApplicationRequest,
    ) -> std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError> {
        self.responses.application()
    }

    fn get_job_run(
        &mut self,
        _request: &GetJobRunRequest,
    ) -> std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError> {
        self.responses.job_run()
    }

    fn list_job_runs(
        &mut self,
        _request: &ListJobRunsRequest,
    ) -> std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError> {
        self.responses.list()
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    responses: ScriptedResponses,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn push_application_response(
        &mut self,
        response: std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_application(response);
    }

    pub fn push_job_run_response(
        &mut self,
        response: std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_job_run(response);
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_list(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl AwsEmrServerlessTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn get_application(
        &mut self,
        request: &GetApplicationRequest,
    ) -> std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError> {
        self.requests.push(request.recorded_request());
        self.responses.application()
    }

    fn get_job_run(
        &mut self,
        request: &GetJobRunRequest,
    ) -> std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError> {
        self.requests.push(request.recorded_request());
        self.responses.job_run()
    }

    fn list_job_runs(
        &mut self,
        request: &ListJobRunsRequest,
    ) -> std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError> {
        self.requests.push(request.recorded_request());
        self.responses.list()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    responses: ScriptedResponses,
}

impl LoopbackTransport {
    pub fn push_application_response(
        &mut self,
        response: std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_application(response);
    }

    pub fn push_job_run_response(
        &mut self,
        response: std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_job_run(response);
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError>,
    ) {
        self.responses.push_list(response);
    }
}

impl AwsEmrServerlessTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_application(
        &mut self,
        _request: &GetApplicationRequest,
    ) -> std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError> {
        self.responses.application()
    }

    fn get_job_run(
        &mut self,
        _request: &GetJobRunRequest,
    ) -> std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError> {
        self.responses.job_run()
    }

    fn list_job_runs(
        &mut self,
        _request: &ListJobRunsRequest,
    ) -> std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError> {
        self.responses.list()
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsEmrServerlessTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_application(
        &mut self,
        _request: &GetApplicationRequest,
    ) -> std::result::Result<GetApplicationResponse, AwsEmrServerlessTransportError> {
        Err(AwsEmrServerlessTransportError::BlockedEnv)
    }

    fn get_job_run(
        &mut self,
        _request: &GetJobRunRequest,
    ) -> std::result::Result<GetJobRunResponse, AwsEmrServerlessTransportError> {
        Err(AwsEmrServerlessTransportError::BlockedEnv)
    }

    fn list_job_runs(
        &mut self,
        _request: &ListJobRunsRequest,
    ) -> std::result::Result<ListJobRunsResponse, AwsEmrServerlessTransportError> {
        Err(AwsEmrServerlessTransportError::BlockedEnv)
    }
}

pub const MAX_PROVIDER_PAGES: u16 = MAX_PAGES;

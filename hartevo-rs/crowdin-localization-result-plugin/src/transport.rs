//! Allowlisted GET transport and non-native recording seams.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    CrowdinLocalizationScope, CrowdinReadOperation, Digest, LanguageCode, ObservationWindow,
    ProjectMetadata, ReadBounds, ReadCursor, SourceFileMetadata, TranslationBuildStatus,
    TranslationProgress,
};
use crate::{CROWDIN_API_ORIGIN, MAX_RESPONSE_BYTES, MAX_RETRIES};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CrowdinHttpMethod {
    Get,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CrowdinTransportError {
    #[error("BLOCKED_ENV: Crowdin native credential and HTTP authority is unavailable")]
    BlockedEnv,
    #[error("Crowdin GET request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Crowdin response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Crowdin returned unexpected HTTP status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("Crowdin rate limit requested an unbounded backoff")]
    BackoffOutOfBounds,
    #[error("Crowdin rate limit response requested a retry after {retry_after_ms} ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("Crowdin rate limit retry budget was exhausted")]
    RetryBudgetExceeded,
    #[error("Crowdin recorded response queue is empty")]
    FixtureExhausted,
    #[error("Crowdin recorded response operation does not match the GET request")]
    OperationMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdinReadRequest {
    pub method: CrowdinHttpMethod,
    pub operation: CrowdinReadOperation,
    pub path_and_query: String,
    pub project_id: u64,
    pub branch_id: u64,
    pub file_id: u64,
    pub target_language: LanguageCode,
    pub observation_window: ObservationWindow,
    pub bounds: ReadBounds,
    pub cursor: ReadCursor,
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl CrowdinReadRequest {
    pub fn new(
        scope: &CrowdinLocalizationScope,
        operation: CrowdinReadOperation,
        observation_window: ObservationWindow,
        bounds: ReadBounds,
        cursor: ReadCursor,
    ) -> Result<Self, CrowdinTransportError> {
        bounds
            .validate()
            .map_err(|error| CrowdinTransportError::InvalidRequest(error.to_string()))?;
        cursor
            .validate(bounds)
            .map_err(|error| CrowdinTransportError::InvalidRequest(error.to_string()))?;
        let project_id = scope.crowdin_project.get();
        let branch_id = scope.source_branch.id.get();
        let file_id = scope.source_file.id.get();
        let path_and_query = match operation {
            CrowdinReadOperation::ProjectMetadata => {
                format!("/projects/{project_id}")
            }
            CrowdinReadOperation::LanguageCoverage => format!(
                "/projects/{project_id}/branches/{branch_id}/languages/progress?limit={}&offset={}",
                bounds.page_size, cursor.offset
            ),
            CrowdinReadOperation::SourceFileMetadata => {
                format!("/projects/{project_id}/files/{file_id}")
            }
            CrowdinReadOperation::TranslationProgress => format!(
                "/projects/{project_id}/files/{file_id}/languages/progress?limit={}&offset={}",
                bounds.page_size, cursor.offset
            ),
            CrowdinReadOperation::TranslationBuildStatus => format!(
                "/projects/{project_id}/bundles?limit={}&offset={}",
                bounds.page_size, cursor.offset
            ),
        };
        let scope_digest = scope.digest();
        let request_digest = Digest::from_fields(
            "crowdin-get-request/v1",
            &[
                CROWDIN_API_ORIGIN.to_owned(),
                operation.contract_name().to_owned(),
                path_and_query.clone(),
                scope_digest.to_string(),
                observation_window.from_epoch_seconds.to_string(),
                observation_window.until_epoch_seconds.to_string(),
                serde_json::to_string(&bounds)
                    .map_err(|error| CrowdinTransportError::InvalidRequest(error.to_string()))?,
                serde_json::to_string(&cursor)
                    .map_err(|error| CrowdinTransportError::InvalidRequest(error.to_string()))?,
            ],
        );
        Ok(Self {
            method: CrowdinHttpMethod::Get,
            operation,
            path_and_query,
            project_id,
            branch_id,
            file_id,
            target_language: scope.target_language.clone(),
            observation_window,
            bounds,
            cursor,
            scope_digest,
            request_digest,
        })
    }

    pub fn origin(&self) -> &'static str {
        CROWDIN_API_ORIGIN
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "operation", content = "value")]
pub enum CrowdinNormalizedResponse {
    ProjectMetadata(ProjectMetadata),
    LanguageCoverage(Vec<crate::LanguageCoverage>),
    SourceFileMetadata(SourceFileMetadata),
    TranslationProgress(Vec<TranslationProgress>),
    TranslationBuildStatus(Vec<TranslationBuildStatus>),
}

impl CrowdinNormalizedResponse {
    pub const fn operation(&self) -> CrowdinReadOperation {
        match self {
            Self::ProjectMetadata(_) => CrowdinReadOperation::ProjectMetadata,
            Self::LanguageCoverage(_) => CrowdinReadOperation::LanguageCoverage,
            Self::SourceFileMetadata(_) => CrowdinReadOperation::SourceFileMetadata,
            Self::TranslationProgress(_) => CrowdinReadOperation::TranslationProgress,
            Self::TranslationBuildStatus(_) => CrowdinReadOperation::TranslationBuildStatus,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "crowdin-normalized-response/v1",
            &[
                self.operation().contract_name().to_owned(),
                serde_json::to_string(self).expect("normalized response serializes"),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdinReadResponse {
    pub operation: CrowdinReadOperation,
    pub status: u16,
    pub response_bytes: usize,
    pub normalized: CrowdinNormalizedResponse,
    pub response_digest: Digest,
    pub retry_count: u8,
    pub raw_body_retained: bool,
    pub credential_material_retained: bool,
}

impl CrowdinReadResponse {
    pub fn new(
        operation: CrowdinReadOperation,
        status: u16,
        response_bytes: usize,
        normalized: CrowdinNormalizedResponse,
        retry_count: u8,
    ) -> Result<Self, CrowdinTransportError> {
        if status != 200 {
            return Err(CrowdinTransportError::UnexpectedStatus { status });
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(CrowdinTransportError::ResponseTooLarge {
                size: response_bytes,
            });
        }
        if retry_count > MAX_RETRIES || normalized.operation() != operation {
            return Err(CrowdinTransportError::InvalidRequest(
                "response operation or retry count is outside the Layer-1 bound".to_owned(),
            ));
        }
        Ok(Self {
            operation,
            status,
            response_bytes,
            response_digest: normalized.digest(),
            normalized,
            retry_count,
            raw_body_retained: false,
            credential_material_retained: false,
        })
    }

    pub fn project(metadata: ProjectMetadata, response_bytes: usize) -> Self {
        Self::new(
            CrowdinReadOperation::ProjectMetadata,
            200,
            response_bytes,
            CrowdinNormalizedResponse::ProjectMetadata(metadata),
            0,
        )
        .expect("valid recorded Crowdin project response")
    }

    pub fn language_coverage(
        coverage: Vec<crate::LanguageCoverage>,
        response_bytes: usize,
    ) -> Self {
        Self::new(
            CrowdinReadOperation::LanguageCoverage,
            200,
            response_bytes,
            CrowdinNormalizedResponse::LanguageCoverage(coverage),
            0,
        )
        .expect("valid recorded Crowdin language coverage response")
    }

    pub fn source_file(file: SourceFileMetadata, response_bytes: usize) -> Self {
        Self::new(
            CrowdinReadOperation::SourceFileMetadata,
            200,
            response_bytes,
            CrowdinNormalizedResponse::SourceFileMetadata(file),
            0,
        )
        .expect("valid recorded Crowdin source file response")
    }

    pub fn translation_progress(progress: Vec<TranslationProgress>, response_bytes: usize) -> Self {
        Self::new(
            CrowdinReadOperation::TranslationProgress,
            200,
            response_bytes,
            CrowdinNormalizedResponse::TranslationProgress(progress),
            0,
        )
        .expect("valid recorded Crowdin translation progress response")
    }

    pub fn build_status(builds: Vec<TranslationBuildStatus>, response_bytes: usize) -> Self {
        Self::new(
            CrowdinReadOperation::TranslationBuildStatus,
            200,
            response_bytes,
            CrowdinNormalizedResponse::TranslationBuildStatus(builds),
            0,
        )
        .expect("valid recorded Crowdin build response")
    }

    pub fn validate(&self, bounds: ReadBounds) -> Result<(), CrowdinTransportError> {
        if self.status != 200 {
            return Err(CrowdinTransportError::UnexpectedStatus {
                status: self.status,
            });
        }
        if self.response_bytes > bounds.max_response_bytes {
            return Err(CrowdinTransportError::ResponseTooLarge {
                size: self.response_bytes,
            });
        }
        if self.retry_count > bounds.max_retries
            || self.raw_body_retained
            || self.credential_material_retained
            || self.operation != self.normalized.operation()
            || self.response_digest != self.normalized.digest()
        {
            return Err(CrowdinTransportError::InvalidRequest(
                "Crowdin response failed redaction or digest validation".to_owned(),
            ));
        }
        let item_count = match &self.normalized {
            CrowdinNormalizedResponse::ProjectMetadata(_)
            | CrowdinNormalizedResponse::SourceFileMetadata(_) => 1,
            CrowdinNormalizedResponse::LanguageCoverage(values) => values.len(),
            CrowdinNormalizedResponse::TranslationProgress(values) => values.len(),
            CrowdinNormalizedResponse::TranslationBuildStatus(values) => values.len(),
        };
        if item_count > usize::from(bounds.page_size) {
            return Err(CrowdinTransportError::InvalidRequest(
                "Crowdin response exceeded its page-size bound".to_owned(),
            ));
        }
        Ok(())
    }
}

pub trait CrowdinReadTransport: fmt::Debug {
    fn get(
        &mut self,
        request: &CrowdinReadRequest,
    ) -> Result<CrowdinReadResponse, CrowdinTransportError>;

    fn provenance(&self) -> crate::TransportProvenance;

    fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingCrowdinTransport {
    responses: VecDeque<Result<CrowdinReadResponse, CrowdinTransportError>>,
    requests: Vec<CrowdinReadRequest>,
    provenance: crate::TransportProvenance,
}

impl RecordingCrowdinTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<CrowdinReadResponse, CrowdinTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: crate::TransportProvenance::Recording,
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<CrowdinReadResponse, CrowdinTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: crate::TransportProvenance::Fixture,
        }
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<CrowdinReadResponse, CrowdinTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: crate::TransportProvenance::Loopback,
        }
    }

    pub fn push_response(&mut self, response: Result<CrowdinReadResponse, CrowdinTransportError>) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[CrowdinReadRequest] {
        &self.requests
    }

    pub fn responses_remaining(&self) -> usize {
        self.responses.len()
    }
}

impl CrowdinReadTransport for RecordingCrowdinTransport {
    fn get(
        &mut self,
        request: &CrowdinReadRequest,
    ) -> Result<CrowdinReadResponse, CrowdinTransportError> {
        self.requests.push(request.clone());
        let response = self
            .responses
            .pop_front()
            .ok_or(CrowdinTransportError::FixtureExhausted)??;
        if response.operation != request.operation {
            return Err(CrowdinTransportError::OperationMismatch);
        }
        Ok(response)
    }

    fn provenance(&self) -> crate::TransportProvenance {
        self.provenance
    }
}

pub type FakeCrowdinTransport = RecordingCrowdinTransport;
pub type FixtureCrowdinTransport = RecordingCrowdinTransport;
pub type LoopbackCrowdinTransport = RecordingCrowdinTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCrowdinTransport;

pub type BlockedEnvTransport = BlockedEnvCrowdinTransport;

impl CrowdinReadTransport for BlockedEnvCrowdinTransport {
    fn get(
        &mut self,
        _request: &CrowdinReadRequest,
    ) -> Result<CrowdinReadResponse, CrowdinTransportError> {
        Err(CrowdinTransportError::BlockedEnv)
    }

    fn provenance(&self) -> crate::TransportProvenance {
        crate::TransportProvenance::BlockedEnv
    }
}

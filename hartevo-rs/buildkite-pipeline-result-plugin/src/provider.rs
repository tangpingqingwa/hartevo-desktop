//! Recording/fake/loopback/BLOCKED_ENV provider seam for bounded Buildkite
//! pipeline-result metadata.  The transport surface has read methods only.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AnnotationMetadata, AnnotationsProjection, ArtifactMetadata, ArtifactMetadataProjection,
    BuildRecord, BuildkitePipelineResultEvidence, BuildkiteScope, BuildsProjection, Digest,
    HostIdentity, JobRecord, JobsProjection, OrganizationIdentity, PipelineIdentity,
    ProjectionCompleteness, TransportProvenance,
};
use crate::{
    BuildkitePipelineResultError, BuildkiteRegistration, MAX_ANNOTATIONS, MAX_ARTIFACTS,
    MAX_BUILDS, MAX_JOBS, MAX_PAGE_SIZE, MAX_PAGE_TOKEN_BYTES, MAX_PAGES, MAX_RESPONSE_BYTES,
    validate_text,
};

/// Provider failures retain only bounded semantic status; provider bodies and
/// credentials are never carried in this enum.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum BuildkiteTransportError {
    #[error("provider rejected the request with 400")]
    BadRequest,
    #[error("provider rejected the request with 401")]
    Unauthorized,
    #[error("provider rejected the request with 403")]
    Forbidden,
    #[error("provider returned 404")]
    NotFound,
    #[error("provider returned a conflicting revision with 409")]
    Conflict,
    #[error("provider rate limited the request with 429")]
    RateLimited { retry_after_seconds: u64 },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider returned a 5xx response")]
    ServerError { status: u16 },
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider credential was revoked")]
    Revoked,
    #[error("provider response was tampered")]
    Tampered,
    #[error("provider response was truncated")]
    Truncated,
    #[error("BLOCKED_ENV: native Buildkite environment is unavailable")]
    BlockedEnv,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("provider transport is unavailable")]
    Unavailable,
}

/// Provider-level failures are fail-closed and do not expose raw response
/// material.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum BuildkiteProviderError {
    #[error("registration is not valid for the current contract")]
    InvalidRegistration,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration revision or binding drifted")]
    RegistrationDrift,
    #[error("opaque SecretReference is revoked")]
    SecretRevoked,
    #[error("provider request scope does not match registration")]
    ScopeMismatch,
    #[error("host identity drifted")]
    HostDrift,
    #[error("organization identity drifted")]
    OrganizationDrift,
    #[error("pipeline identity drifted")]
    PipelineDrift,
    #[error("build identity drifted")]
    BuildDrift,
    #[error("job identity drifted")]
    JobDrift,
    #[error("attempt identity drifted")]
    AttemptDrift,
    #[error("commit identity drifted")]
    CommitDrift,
    #[error("artifact identity drifted")]
    ArtifactDrift,
    #[error("annotation identity drifted")]
    AnnotationDrift,
    #[error("Mission scope drifted")]
    MissionDrift,
    #[error("build evidence was tampered")]
    BuildTampered,
    #[error("job evidence was tampered")]
    JobTampered,
    #[error("annotation evidence was tampered")]
    AnnotationTampered,
    #[error("artifact metadata was tampered")]
    ArtifactTampered,
    #[error("provider page was tampered")]
    PageTampered,
    #[error("provider evidence was tampered")]
    TamperedEvidence,
    #[error("provider returned an out-of-scope entry")]
    OutOfScope,
    #[error("provider page token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider returned no bounded page")]
    EmptyPage,
    #[error("provider request and response idempotency bindings differ")]
    IdempotencyMismatch,
    #[error("provider transport failure: {0}")]
    Transport(#[from] BuildkiteTransportError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadResource {
    Builds,
    Jobs,
    Annotations,
    ArtifactMetadata,
}

/// A bounded request carrying exact scope and a hashed caller idempotency key.
/// It contains no credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildkiteReadRequest {
    pub resource: ReadResource,
    pub scope_digest: Digest,
    pub host: HostIdentity,
    pub organization: OrganizationIdentity,
    pub pipeline: PipelineIdentity,
    pub build_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub page_size: usize,
    pub page_number: usize,
    pub page_token: Option<String>,
    pub idempotency_key_digest: Digest,
    pub request_digest: Digest,
}

impl BuildkiteReadRequest {
    pub fn new(
        scope: &BuildkiteScope,
        resource: ReadResource,
        page_size: usize,
        page_number: usize,
        page_token: Option<String>,
        idempotency_key: &str,
    ) -> std::result::Result<Self, BuildkiteProviderError> {
        if page_size == 0
            || page_size > MAX_PAGE_SIZE
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(BuildkiteProviderError::PaginationLimit);
        }
        if page_token
            .as_ref()
            .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
        {
            return Err(BuildkiteProviderError::PaginationLimit);
        }
        validate_text(idempotency_key, "idempotencyKey", 256, true)
            .map_err(|_| BuildkiteProviderError::ScopeMismatch)?;
        let idempotency_key_digest = Digest::from_text(idempotency_key);
        let request_digest = Digest::from_parts(
            "buildkite-read-request/v1",
            &[
                ("resource", format!("{resource:?}")),
                ("scope", scope.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "page_token",
                    page_token
                        .as_deref()
                        .map_or_else(String::new, |token| Digest::from_text(token).to_string()),
                ),
                ("idempotency", idempotency_key_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            resource,
            scope_digest: scope.digest(),
            host: scope.host.clone(),
            organization: scope.organization.clone(),
            pipeline: scope.pipeline.clone(),
            build_id: scope.build.id().to_owned(),
            job_id: scope.job.id().to_owned(),
            attempt_id: scope.attempt.id_str().to_owned(),
            page_size,
            page_number,
            page_token,
            idempotency_key_digest,
            request_digest,
        })
    }
}

pub type BuildsReadRequest = BuildkiteReadRequest;
pub type JobsReadRequest = BuildkiteReadRequest;
pub type AnnotationsReadRequest = BuildkiteReadRequest;
pub type ArtifactMetadataReadRequest = BuildkiteReadRequest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildPage {
    pub page_number: usize,
    pub builds: Vec<BuildRecord>,
    pub next_page_token: Option<String>,
    pub response_bytes: usize,
    pub request_digest: Option<Digest>,
    pub page_digest: Digest,
}

impl BuildPage {
    pub fn new(
        page_number: usize,
        builds: Vec<BuildRecord>,
        next_page_token: Option<String>,
        response_bytes: usize,
    ) -> std::result::Result<Self, BuildkiteProviderError> {
        if page_number == 0
            || builds.is_empty()
            || builds.len() > MAX_BUILDS
            || response_bytes > MAX_RESPONSE_BYTES
            || next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
        {
            return Err(BuildkiteProviderError::PageTampered);
        }
        let mut page = Self {
            page_number,
            builds,
            next_page_token,
            response_bytes,
            request_digest: None,
            page_digest: Digest::from_text("unsealed-buildkite-build-page"),
        };
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn for_scope(scope: &BuildkiteScope) -> Self {
        Self::new(
            1,
            vec![BuildRecord::for_scope(
                scope,
                crate::model::BuildState::Passed,
                1_744_550_400,
            )],
            None,
            512,
        )
        .expect("scope fixture is bounded")
    }

    pub fn bind_request(&mut self, request: &BuildkiteReadRequest) {
        self.request_digest = Some(request.request_digest.clone());
        self.page_digest = self.calculate_digest();
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), BuildkiteProviderError> {
        if self.page_number == 0
            || self.builds.is_empty()
            || self.builds.len() > MAX_BUILDS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
            || self
                .request_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self.page_digest != self.calculate_digest()
        {
            return Err(BuildkiteProviderError::PageTampered);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-build-page/v1",
            &[
                ("number", self.page_number.to_string()),
                (
                    "builds",
                    self.builds
                        .iter()
                        .map(|build| build.record_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_page_token
                        .as_deref()
                        .map_or_else(String::new, |token| Digest::from_text(token).to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                (
                    "request",
                    self.request_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobPage {
    pub page_number: usize,
    pub jobs: Vec<JobRecord>,
    pub next_page_token: Option<String>,
    pub response_bytes: usize,
    pub request_digest: Option<Digest>,
    pub page_digest: Digest,
}

impl JobPage {
    pub fn new(
        page_number: usize,
        jobs: Vec<JobRecord>,
        next_page_token: Option<String>,
        response_bytes: usize,
    ) -> std::result::Result<Self, BuildkiteProviderError> {
        if page_number == 0
            || jobs.is_empty()
            || jobs.len() > MAX_JOBS
            || response_bytes > MAX_RESPONSE_BYTES
            || next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
        {
            return Err(BuildkiteProviderError::PageTampered);
        }
        let mut page = Self {
            page_number,
            jobs,
            next_page_token,
            response_bytes,
            request_digest: None,
            page_digest: Digest::from_text("unsealed-buildkite-job-page"),
        };
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn for_scope(scope: &BuildkiteScope) -> Self {
        Self::new(
            1,
            vec![JobRecord::for_scope(
                scope,
                crate::model::JobState::Passed,
                1_744_550_400,
            )],
            None,
            512,
        )
        .expect("scope fixture is bounded")
    }

    pub fn bind_request(&mut self, request: &BuildkiteReadRequest) {
        self.request_digest = Some(request.request_digest.clone());
        self.page_digest = self.calculate_digest();
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), BuildkiteProviderError> {
        if self.page_number == 0
            || self.jobs.is_empty()
            || self.jobs.len() > MAX_JOBS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
            || self
                .request_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self.page_digest != self.calculate_digest()
        {
            return Err(BuildkiteProviderError::PageTampered);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-job-page/v1",
            &[
                ("number", self.page_number.to_string()),
                (
                    "jobs",
                    self.jobs
                        .iter()
                        .map(|job| job.record_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_page_token
                        .as_deref()
                        .map_or_else(String::new, |token| Digest::from_text(token).to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                (
                    "request",
                    self.request_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnotationPage {
    pub page_number: usize,
    pub annotations: Vec<AnnotationMetadata>,
    pub next_page_token: Option<String>,
    pub response_bytes: usize,
    pub request_digest: Option<Digest>,
    pub page_digest: Digest,
}

impl AnnotationPage {
    pub fn new(
        page_number: usize,
        annotations: Vec<AnnotationMetadata>,
        next_page_token: Option<String>,
        response_bytes: usize,
    ) -> std::result::Result<Self, BuildkiteProviderError> {
        if page_number == 0
            || annotations.is_empty()
            || annotations.len() > MAX_ANNOTATIONS
            || response_bytes > MAX_RESPONSE_BYTES
            || next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
        {
            return Err(BuildkiteProviderError::PageTampered);
        }
        let mut page = Self {
            page_number,
            annotations,
            next_page_token,
            response_bytes,
            request_digest: None,
            page_digest: Digest::from_text("unsealed-buildkite-annotation-page"),
        };
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn for_scope(scope: &BuildkiteScope) -> Self {
        Self::new(
            1,
            vec![AnnotationMetadata::for_scope(scope, 1_744_550_400)],
            None,
            512,
        )
        .expect("scope fixture is bounded")
    }

    pub fn bind_request(&mut self, request: &BuildkiteReadRequest) {
        self.request_digest = Some(request.request_digest.clone());
        self.page_digest = self.calculate_digest();
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), BuildkiteProviderError> {
        if self.page_number == 0
            || self.annotations.is_empty()
            || self.annotations.len() > MAX_ANNOTATIONS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
            || self
                .request_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self.page_digest != self.calculate_digest()
        {
            return Err(BuildkiteProviderError::PageTampered);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-annotation-page/v1",
            &[
                ("number", self.page_number.to_string()),
                (
                    "annotations",
                    self.annotations
                        .iter()
                        .map(|annotation| annotation.annotation_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_page_token
                        .as_deref()
                        .map_or_else(String::new, |token| Digest::from_text(token).to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                (
                    "request",
                    self.request_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadataPage {
    pub page_number: usize,
    pub artifacts: Vec<ArtifactMetadata>,
    pub next_page_token: Option<String>,
    pub response_bytes: usize,
    pub request_digest: Option<Digest>,
    pub page_digest: Digest,
}

impl ArtifactMetadataPage {
    pub fn new(
        page_number: usize,
        artifacts: Vec<ArtifactMetadata>,
        next_page_token: Option<String>,
        response_bytes: usize,
    ) -> std::result::Result<Self, BuildkiteProviderError> {
        if page_number == 0
            || artifacts.is_empty()
            || artifacts.len() > MAX_ARTIFACTS
            || response_bytes > MAX_RESPONSE_BYTES
            || next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
        {
            return Err(BuildkiteProviderError::PageTampered);
        }
        let mut page = Self {
            page_number,
            artifacts,
            next_page_token,
            response_bytes,
            request_digest: None,
            page_digest: Digest::from_text("unsealed-buildkite-artifact-page"),
        };
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn for_scope(scope: &BuildkiteScope) -> Self {
        Self::new(
            1,
            vec![ArtifactMetadata::for_scope(scope, 1_744_550_400)],
            None,
            512,
        )
        .expect("scope fixture is bounded")
    }

    pub fn bind_request(&mut self, request: &BuildkiteReadRequest) {
        self.request_digest = Some(request.request_digest.clone());
        self.page_digest = self.calculate_digest();
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), BuildkiteProviderError> {
        if self.page_number == 0
            || self.artifacts.is_empty()
            || self.artifacts.len() > MAX_ARTIFACTS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES)
            || self
                .request_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self.page_digest != self.calculate_digest()
        {
            return Err(BuildkiteProviderError::PageTampered);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-artifact-page/v1",
            &[
                ("number", self.page_number.to_string()),
                (
                    "artifacts",
                    self.artifacts
                        .iter()
                        .map(|artifact| artifact.artifact_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_page_token
                        .as_deref()
                        .map_or_else(String::new, |token| Digest::from_text(token).to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                (
                    "request",
                    self.request_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }
}

/// Read-only provider transport.  No method can create, rebuild, retry,
/// cancel, mutate an annotation, fetch logs, fetch artifact bytes, SSH, or
/// enter a debug session.
pub trait BuildkiteTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_builds(
        &mut self,
        request: &BuildsReadRequest,
    ) -> std::result::Result<BuildPage, BuildkiteTransportError>;

    fn read_jobs(
        &mut self,
        request: &JobsReadRequest,
    ) -> std::result::Result<JobPage, BuildkiteTransportError>;

    fn read_annotations(
        &mut self,
        request: &AnnotationsReadRequest,
    ) -> std::result::Result<AnnotationPage, BuildkiteTransportError>;

    fn read_artifact_metadata(
        &mut self,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<ArtifactMetadataPage, BuildkiteTransportError>;
}

#[derive(Clone, Debug)]
pub struct RecordingBuildkiteTransport {
    build_pages: VecDeque<std::result::Result<BuildPage, BuildkiteTransportError>>,
    job_pages: VecDeque<std::result::Result<JobPage, BuildkiteTransportError>>,
    annotation_pages: VecDeque<std::result::Result<AnnotationPage, BuildkiteTransportError>>,
    artifact_pages: VecDeque<std::result::Result<ArtifactMetadataPage, BuildkiteTransportError>>,
    requests: Vec<BuildkiteReadRequest>,
    provenance: TransportProvenance,
}

impl RecordingBuildkiteTransport {
    pub fn new(
        build_pages: impl IntoIterator<Item = std::result::Result<BuildPage, BuildkiteTransportError>>,
        job_pages: impl IntoIterator<Item = std::result::Result<JobPage, BuildkiteTransportError>>,
        annotation_pages: impl IntoIterator<
            Item = std::result::Result<AnnotationPage, BuildkiteTransportError>,
        >,
        artifact_pages: impl IntoIterator<
            Item = std::result::Result<ArtifactMetadataPage, BuildkiteTransportError>,
        >,
    ) -> Self {
        Self {
            build_pages: build_pages.into_iter().collect(),
            job_pages: job_pages.into_iter().collect(),
            annotation_pages: annotation_pages.into_iter().collect(),
            artifact_pages: artifact_pages.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Recording,
        }
    }

    pub fn from_scope(scope: &BuildkiteScope) -> Self {
        Self::new(
            [Ok(BuildPage::for_scope(scope))],
            [Ok(JobPage::for_scope(scope))],
            [Ok(AnnotationPage::for_scope(scope))],
            [Ok(ArtifactMetadataPage::for_scope(scope))],
        )
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_build_page(
        &mut self,
        page: std::result::Result<BuildPage, BuildkiteTransportError>,
    ) {
        self.build_pages.push_back(page);
    }

    pub fn push_job_page(&mut self, page: std::result::Result<JobPage, BuildkiteTransportError>) {
        self.job_pages.push_back(page);
    }

    pub fn push_annotation_page(
        &mut self,
        page: std::result::Result<AnnotationPage, BuildkiteTransportError>,
    ) {
        self.annotation_pages.push_back(page);
    }

    pub fn push_artifact_page(
        &mut self,
        page: std::result::Result<ArtifactMetadataPage, BuildkiteTransportError>,
    ) {
        self.artifact_pages.push_back(page);
    }

    pub fn requests(&self) -> &[BuildkiteReadRequest] {
        &self.requests
    }

    pub fn remaining_pages(&self) -> usize {
        self.build_pages.len()
            + self.job_pages.len()
            + self.annotation_pages.len()
            + self.artifact_pages.len()
    }

    fn record_request(&mut self, request: &BuildkiteReadRequest) {
        self.requests.push(request.clone());
    }
}

impl BuildkiteTransport for RecordingBuildkiteTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read_builds(
        &mut self,
        request: &BuildsReadRequest,
    ) -> std::result::Result<BuildPage, BuildkiteTransportError> {
        self.record_request(request);
        self.build_pages
            .pop_front()
            .unwrap_or(Err(BuildkiteTransportError::Unavailable))
    }

    fn read_jobs(
        &mut self,
        request: &JobsReadRequest,
    ) -> std::result::Result<JobPage, BuildkiteTransportError> {
        self.record_request(request);
        self.job_pages
            .pop_front()
            .unwrap_or(Err(BuildkiteTransportError::Unavailable))
    }

    fn read_annotations(
        &mut self,
        request: &AnnotationsReadRequest,
    ) -> std::result::Result<AnnotationPage, BuildkiteTransportError> {
        self.record_request(request);
        self.annotation_pages
            .pop_front()
            .unwrap_or(Err(BuildkiteTransportError::Unavailable))
    }

    fn read_artifact_metadata(
        &mut self,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<ArtifactMetadataPage, BuildkiteTransportError> {
        self.record_request(request);
        self.artifact_pages
            .pop_front()
            .unwrap_or(Err(BuildkiteTransportError::Unavailable))
    }
}

pub type RecordingTransport = RecordingBuildkiteTransport;

#[derive(Clone, Debug)]
pub struct FakeTransport {
    inner: RecordingBuildkiteTransport,
}

impl FakeTransport {
    pub fn new(
        build_pages: impl IntoIterator<Item = std::result::Result<BuildPage, BuildkiteTransportError>>,
        job_pages: impl IntoIterator<Item = std::result::Result<JobPage, BuildkiteTransportError>>,
        annotation_pages: impl IntoIterator<
            Item = std::result::Result<AnnotationPage, BuildkiteTransportError>,
        >,
        artifact_pages: impl IntoIterator<
            Item = std::result::Result<ArtifactMetadataPage, BuildkiteTransportError>,
        >,
    ) -> Self {
        Self {
            inner: RecordingBuildkiteTransport::new(
                build_pages,
                job_pages,
                annotation_pages,
                artifact_pages,
            )
            .with_provenance(TransportProvenance::Fake),
        }
    }

    pub fn from_scope(scope: &BuildkiteScope) -> Self {
        Self::new(
            [Ok(BuildPage::for_scope(scope))],
            [Ok(JobPage::for_scope(scope))],
            [Ok(AnnotationPage::for_scope(scope))],
            [Ok(ArtifactMetadataPage::for_scope(scope))],
        )
    }

    pub fn inner(&self) -> &RecordingBuildkiteTransport {
        &self.inner
    }
}

impl BuildkiteTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn read_builds(
        &mut self,
        request: &BuildsReadRequest,
    ) -> std::result::Result<BuildPage, BuildkiteTransportError> {
        self.inner.read_builds(request)
    }

    fn read_jobs(
        &mut self,
        request: &JobsReadRequest,
    ) -> std::result::Result<JobPage, BuildkiteTransportError> {
        self.inner.read_jobs(request)
    }

    fn read_annotations(
        &mut self,
        request: &AnnotationsReadRequest,
    ) -> std::result::Result<AnnotationPage, BuildkiteTransportError> {
        self.inner.read_annotations(request)
    }

    fn read_artifact_metadata(
        &mut self,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<ArtifactMetadataPage, BuildkiteTransportError> {
        self.inner.read_artifact_metadata(request)
    }
}

pub type FakeBuildkiteTransport = FakeTransport;

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: RecordingBuildkiteTransport,
}

impl LoopbackTransport {
    pub fn new(
        build_pages: impl IntoIterator<Item = std::result::Result<BuildPage, BuildkiteTransportError>>,
        job_pages: impl IntoIterator<Item = std::result::Result<JobPage, BuildkiteTransportError>>,
        annotation_pages: impl IntoIterator<
            Item = std::result::Result<AnnotationPage, BuildkiteTransportError>,
        >,
        artifact_pages: impl IntoIterator<
            Item = std::result::Result<ArtifactMetadataPage, BuildkiteTransportError>,
        >,
    ) -> Self {
        Self {
            inner: RecordingBuildkiteTransport::new(
                build_pages,
                job_pages,
                annotation_pages,
                artifact_pages,
            )
            .with_provenance(TransportProvenance::Loopback),
        }
    }

    pub fn from_scope(scope: &BuildkiteScope) -> Self {
        Self::new(
            [Ok(BuildPage::for_scope(scope))],
            [Ok(JobPage::for_scope(scope))],
            [Ok(AnnotationPage::for_scope(scope))],
            [Ok(ArtifactMetadataPage::for_scope(scope))],
        )
    }
}

impl BuildkiteTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn read_builds(
        &mut self,
        request: &BuildsReadRequest,
    ) -> std::result::Result<BuildPage, BuildkiteTransportError> {
        self.inner.read_builds(request)
    }

    fn read_jobs(
        &mut self,
        request: &JobsReadRequest,
    ) -> std::result::Result<JobPage, BuildkiteTransportError> {
        self.inner.read_jobs(request)
    }

    fn read_annotations(
        &mut self,
        request: &AnnotationsReadRequest,
    ) -> std::result::Result<AnnotationPage, BuildkiteTransportError> {
        self.inner.read_annotations(request)
    }

    fn read_artifact_metadata(
        &mut self,
        request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<ArtifactMetadataPage, BuildkiteTransportError> {
        self.inner.read_artifact_metadata(request)
    }
}

pub type LoopbackBuildkiteTransport = LoopbackTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl BuildkiteTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_builds(
        &mut self,
        _request: &BuildsReadRequest,
    ) -> std::result::Result<BuildPage, BuildkiteTransportError> {
        Err(BuildkiteTransportError::BlockedEnv)
    }

    fn read_jobs(
        &mut self,
        _request: &JobsReadRequest,
    ) -> std::result::Result<JobPage, BuildkiteTransportError> {
        Err(BuildkiteTransportError::BlockedEnv)
    }

    fn read_annotations(
        &mut self,
        _request: &AnnotationsReadRequest,
    ) -> std::result::Result<AnnotationPage, BuildkiteTransportError> {
        Err(BuildkiteTransportError::BlockedEnv)
    }

    fn read_artifact_metadata(
        &mut self,
        _request: &ArtifactMetadataReadRequest,
    ) -> std::result::Result<ArtifactMetadataPage, BuildkiteTransportError> {
        Err(BuildkiteTransportError::BlockedEnv)
    }
}

/// Typed Buildkite provider bound to one registration.  The provider only
/// creates bounded metadata projections and never returns provider payloads.
#[derive(Debug)]
pub struct BuildkiteProvider<T> {
    registration: BuildkiteRegistration,
    transport: T,
}

impl<T: BuildkiteTransport> BuildkiteProvider<T> {
    pub fn new(
        registration: BuildkiteRegistration,
        transport: T,
    ) -> std::result::Result<Self, BuildkiteProviderError> {
        registration
            .validate()
            .map_err(|_| BuildkiteProviderError::InvalidRegistration)?;
        Ok(Self {
            registration,
            transport,
        })
    }

    pub fn registration(&self) -> &BuildkiteRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut BuildkiteRegistration {
        &mut self.registration
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn ensure_ready(&self) -> std::result::Result<(), BuildkiteProviderError> {
        self.registration
            .validate()
            .map_err(|_| BuildkiteProviderError::RegistrationDrift)?;
        if self.registration.secret_reference().is_revoked() {
            return Err(BuildkiteProviderError::SecretRevoked);
        }
        match self.registration.status() {
            crate::RegistrationStatus::Active => Ok(()),
            crate::RegistrationStatus::Revoked => Err(BuildkiteProviderError::RegistrationRevoked),
            crate::RegistrationStatus::Reversed => {
                Err(BuildkiteProviderError::RegistrationReversed)
            }
        }
    }

    pub fn read_builds(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<BuildsProjection, BuildkiteProviderError> {
        self.read_builds_with_key(page_size, "buildkite-builds-read")
    }

    fn read_builds_with_key(
        &mut self,
        page_size: usize,
        idempotency_key: &str,
    ) -> std::result::Result<BuildsProjection, BuildkiteProviderError> {
        self.ensure_ready()?;
        let scope = self.registration.scope().clone();
        let mut token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut builds = Vec::new();
        let mut pages_read = 0;
        let mut response_bytes = 0_u64;
        loop {
            pages_read += 1;
            if pages_read > MAX_PAGES {
                return Err(BuildkiteProviderError::PaginationLimit);
            }
            let request = BuildkiteReadRequest::new(
                &scope,
                ReadResource::Builds,
                page_size,
                pages_read,
                token.clone(),
                idempotency_key,
            )?;
            let page = self.transport.read_builds(&request)?;
            Self::validate_request_binding(&request, page.request_digest.as_ref())?;
            page.validate_integrity()?;
            if page.page_number != pages_read {
                return Err(BuildkiteProviderError::PageTampered);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes as u64);
            if response_bytes > MAX_RESPONSE_BYTES as u64 {
                return Err(BuildkiteProviderError::ResponseTooLarge);
            }
            for build in page.builds {
                Self::validate_build(&scope, &build)?;
                builds.push(build);
                if builds.len() > MAX_BUILDS {
                    return Err(BuildkiteProviderError::PaginationLimit);
                }
            }
            token = page.next_page_token;
            match token.as_ref() {
                Some(next) => {
                    if !seen_tokens.insert(next.clone()) {
                        return Err(BuildkiteProviderError::PaginationLoop);
                    }
                }
                None => break,
            }
        }
        BuildsProjection::new(
            &scope,
            builds,
            pages_read,
            response_bytes,
            ProjectionCompleteness::Complete,
            false,
            self.provenance(),
        )
        .map_err(|error| map_model_error(&error))
    }

    pub fn read_jobs(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<JobsProjection, BuildkiteProviderError> {
        self.read_jobs_with_key(page_size, "buildkite-jobs-read")
    }

    fn read_jobs_with_key(
        &mut self,
        page_size: usize,
        idempotency_key: &str,
    ) -> std::result::Result<JobsProjection, BuildkiteProviderError> {
        self.ensure_ready()?;
        let scope = self.registration.scope().clone();
        let mut token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut jobs = Vec::new();
        let mut pages_read = 0;
        let mut response_bytes = 0_u64;
        loop {
            pages_read += 1;
            if pages_read > MAX_PAGES {
                return Err(BuildkiteProviderError::PaginationLimit);
            }
            let request = BuildkiteReadRequest::new(
                &scope,
                ReadResource::Jobs,
                page_size,
                pages_read,
                token.clone(),
                idempotency_key,
            )?;
            let page = self.transport.read_jobs(&request)?;
            Self::validate_request_binding(&request, page.request_digest.as_ref())?;
            page.validate_integrity()?;
            if page.page_number != pages_read {
                return Err(BuildkiteProviderError::PageTampered);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes as u64);
            if response_bytes > MAX_RESPONSE_BYTES as u64 {
                return Err(BuildkiteProviderError::ResponseTooLarge);
            }
            for job in page.jobs {
                Self::validate_job(&scope, &job)?;
                jobs.push(job);
                if jobs.len() > MAX_JOBS {
                    return Err(BuildkiteProviderError::PaginationLimit);
                }
            }
            token = page.next_page_token;
            match token.as_ref() {
                Some(next) => {
                    if !seen_tokens.insert(next.clone()) {
                        return Err(BuildkiteProviderError::PaginationLoop);
                    }
                }
                None => break,
            }
        }
        JobsProjection::new(
            &scope,
            jobs,
            pages_read,
            response_bytes,
            ProjectionCompleteness::Complete,
            false,
            self.provenance(),
        )
        .map_err(|error| map_model_error(&error))
    }

    pub fn read_annotations(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<AnnotationsProjection, BuildkiteProviderError> {
        self.read_annotations_with_key(page_size, "buildkite-annotations-read")
    }

    fn read_annotations_with_key(
        &mut self,
        page_size: usize,
        idempotency_key: &str,
    ) -> std::result::Result<AnnotationsProjection, BuildkiteProviderError> {
        self.ensure_ready()?;
        let scope = self.registration.scope().clone();
        let mut token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut annotations = Vec::new();
        let mut pages_read = 0;
        let mut response_bytes = 0_u64;
        loop {
            pages_read += 1;
            if pages_read > MAX_PAGES {
                return Err(BuildkiteProviderError::PaginationLimit);
            }
            let request = BuildkiteReadRequest::new(
                &scope,
                ReadResource::Annotations,
                page_size,
                pages_read,
                token.clone(),
                idempotency_key,
            )?;
            let page = self.transport.read_annotations(&request)?;
            Self::validate_request_binding(&request, page.request_digest.as_ref())?;
            page.validate_integrity()?;
            if page.page_number != pages_read {
                return Err(BuildkiteProviderError::PageTampered);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes as u64);
            if response_bytes > MAX_RESPONSE_BYTES as u64 {
                return Err(BuildkiteProviderError::ResponseTooLarge);
            }
            for annotation in page.annotations {
                Self::validate_annotation(&scope, &annotation)?;
                annotations.push(annotation);
                if annotations.len() > MAX_ANNOTATIONS {
                    return Err(BuildkiteProviderError::PaginationLimit);
                }
            }
            token = page.next_page_token;
            match token.as_ref() {
                Some(next) => {
                    if !seen_tokens.insert(next.clone()) {
                        return Err(BuildkiteProviderError::PaginationLoop);
                    }
                }
                None => break,
            }
        }
        AnnotationsProjection::new(
            &scope,
            annotations,
            pages_read,
            response_bytes,
            ProjectionCompleteness::Complete,
            false,
            self.provenance(),
        )
        .map_err(|error| map_model_error(&error))
    }

    pub fn read_artifact_metadata(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<ArtifactMetadataProjection, BuildkiteProviderError> {
        self.read_artifact_metadata_with_key(page_size, "buildkite-artifact-metadata-read")
    }

    fn read_artifact_metadata_with_key(
        &mut self,
        page_size: usize,
        idempotency_key: &str,
    ) -> std::result::Result<ArtifactMetadataProjection, BuildkiteProviderError> {
        self.ensure_ready()?;
        let scope = self.registration.scope().clone();
        let mut token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut artifacts = Vec::new();
        let mut pages_read = 0;
        let mut response_bytes = 0_u64;
        loop {
            pages_read += 1;
            if pages_read > MAX_PAGES {
                return Err(BuildkiteProviderError::PaginationLimit);
            }
            let request = BuildkiteReadRequest::new(
                &scope,
                ReadResource::ArtifactMetadata,
                page_size,
                pages_read,
                token.clone(),
                idempotency_key,
            )?;
            let page = self.transport.read_artifact_metadata(&request)?;
            Self::validate_request_binding(&request, page.request_digest.as_ref())?;
            page.validate_integrity()?;
            if page.page_number != pages_read {
                return Err(BuildkiteProviderError::PageTampered);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes as u64);
            if response_bytes > MAX_RESPONSE_BYTES as u64 {
                return Err(BuildkiteProviderError::ResponseTooLarge);
            }
            for artifact in page.artifacts {
                Self::validate_artifact(&scope, &artifact)?;
                artifacts.push(artifact);
                if artifacts.len() > MAX_ARTIFACTS {
                    return Err(BuildkiteProviderError::PaginationLimit);
                }
            }
            token = page.next_page_token;
            match token.as_ref() {
                Some(next) => {
                    if !seen_tokens.insert(next.clone()) {
                        return Err(BuildkiteProviderError::PaginationLoop);
                    }
                }
                None => break,
            }
        }
        ArtifactMetadataProjection::new(
            &scope,
            artifacts,
            pages_read,
            response_bytes,
            ProjectionCompleteness::Complete,
            false,
            self.provenance(),
        )
        .map_err(|error| map_model_error(&error))
    }

    pub fn read_artifacts(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<ArtifactMetadataProjection, BuildkiteProviderError> {
        self.read_artifact_metadata(page_size)
    }

    pub fn read_pipeline_result(
        &mut self,
        page_size: usize,
        idempotency_key: &str,
    ) -> std::result::Result<BuildkitePipelineResultEvidence, BuildkiteProviderError> {
        validate_text(idempotency_key, "idempotencyKey", 256, true)
            .map_err(|_| BuildkiteProviderError::ScopeMismatch)?;
        let builds = self.read_builds_with_key(page_size, &format!("{idempotency_key}:builds"))?;
        let jobs = self.read_jobs_with_key(page_size, &format!("{idempotency_key}:jobs"))?;
        let annotations =
            self.read_annotations_with_key(page_size, &format!("{idempotency_key}:annotations"))?;
        let artifacts = self
            .read_artifact_metadata_with_key(page_size, &format!("{idempotency_key}:artifacts"))?;
        BuildkitePipelineResultEvidence::new(
            self.registration.scope(),
            builds,
            jobs,
            annotations,
            artifacts,
        )
        .map_err(|error| map_model_error(&error))
    }

    pub fn read(
        &mut self,
        page_size: usize,
        idempotency_key: &str,
    ) -> std::result::Result<BuildkitePipelineResultEvidence, BuildkiteProviderError> {
        self.read_pipeline_result(page_size, idempotency_key)
    }

    fn validate_request_binding(
        request: &BuildkiteReadRequest,
        response_digest: Option<&Digest>,
    ) -> std::result::Result<(), BuildkiteProviderError> {
        if response_digest.is_some_and(|digest| digest != &request.request_digest) {
            Err(BuildkiteProviderError::IdempotencyMismatch)
        } else {
            Ok(())
        }
    }

    fn validate_build(
        scope: &BuildkiteScope,
        build: &BuildRecord,
    ) -> std::result::Result<(), BuildkiteProviderError> {
        build
            .validate_integrity()
            .map_err(|_| BuildkiteProviderError::BuildTampered)?;
        if build.host != scope.host {
            return Err(BuildkiteProviderError::HostDrift);
        }
        if build.organization != scope.organization {
            return Err(BuildkiteProviderError::OrganizationDrift);
        }
        if build.pipeline != scope.pipeline {
            return Err(BuildkiteProviderError::PipelineDrift);
        }
        if build.build != scope.build {
            return Err(BuildkiteProviderError::BuildDrift);
        }
        if build.commit != scope.commit {
            return Err(BuildkiteProviderError::CommitDrift);
        }
        if build.retry_identity.job_id != scope.job.id {
            return Err(BuildkiteProviderError::JobDrift);
        }
        if build.retry_identity.attempt_id != scope.attempt.id
            || build.retry_identity.attempt_number != scope.attempt.number
        {
            return Err(BuildkiteProviderError::AttemptDrift);
        }
        Ok(())
    }

    fn validate_job(
        scope: &BuildkiteScope,
        job: &JobRecord,
    ) -> std::result::Result<(), BuildkiteProviderError> {
        job.validate_integrity()
            .map_err(|_| BuildkiteProviderError::JobTampered)?;
        if job.host != scope.host {
            return Err(BuildkiteProviderError::HostDrift);
        }
        if job.organization != scope.organization {
            return Err(BuildkiteProviderError::OrganizationDrift);
        }
        if job.pipeline != scope.pipeline {
            return Err(BuildkiteProviderError::PipelineDrift);
        }
        if job.build != scope.build {
            return Err(BuildkiteProviderError::BuildDrift);
        }
        if job.job != scope.job {
            return Err(BuildkiteProviderError::JobDrift);
        }
        if job.attempt != scope.attempt {
            return Err(BuildkiteProviderError::AttemptDrift);
        }
        if job.commit != scope.commit {
            return Err(BuildkiteProviderError::CommitDrift);
        }
        Ok(())
    }

    fn validate_annotation(
        scope: &BuildkiteScope,
        annotation: &AnnotationMetadata,
    ) -> std::result::Result<(), BuildkiteProviderError> {
        annotation
            .validate_integrity()
            .map_err(|_| BuildkiteProviderError::AnnotationTampered)?;
        if annotation.host != scope.host {
            return Err(BuildkiteProviderError::HostDrift);
        }
        if annotation.organization != scope.organization {
            return Err(BuildkiteProviderError::OrganizationDrift);
        }
        if annotation.pipeline != scope.pipeline {
            return Err(BuildkiteProviderError::PipelineDrift);
        }
        if annotation.build != scope.build {
            return Err(BuildkiteProviderError::BuildDrift);
        }
        if annotation.job != scope.job {
            return Err(BuildkiteProviderError::JobDrift);
        }
        if annotation.attempt != scope.attempt {
            return Err(BuildkiteProviderError::AttemptDrift);
        }
        if annotation.commit != scope.commit {
            return Err(BuildkiteProviderError::CommitDrift);
        }
        if annotation.annotation != scope.annotation {
            return Err(BuildkiteProviderError::AnnotationDrift);
        }
        Ok(())
    }

    fn validate_artifact(
        scope: &BuildkiteScope,
        artifact: &ArtifactMetadata,
    ) -> std::result::Result<(), BuildkiteProviderError> {
        artifact
            .validate_integrity()
            .map_err(|_| BuildkiteProviderError::ArtifactTampered)?;
        if artifact.host != scope.host {
            return Err(BuildkiteProviderError::HostDrift);
        }
        if artifact.organization != scope.organization {
            return Err(BuildkiteProviderError::OrganizationDrift);
        }
        if artifact.pipeline != scope.pipeline {
            return Err(BuildkiteProviderError::PipelineDrift);
        }
        if artifact.build != scope.build {
            return Err(BuildkiteProviderError::BuildDrift);
        }
        if artifact.job != scope.job {
            return Err(BuildkiteProviderError::JobDrift);
        }
        if artifact.attempt != scope.attempt {
            return Err(BuildkiteProviderError::AttemptDrift);
        }
        if artifact.commit != scope.commit {
            return Err(BuildkiteProviderError::CommitDrift);
        }
        if artifact.artifact != scope.artifact {
            return Err(BuildkiteProviderError::ArtifactDrift);
        }
        Ok(())
    }
}

fn map_model_error(error: &BuildkitePipelineResultError) -> BuildkiteProviderError {
    match error {
        BuildkitePipelineResultError::PaginationLoop => BuildkiteProviderError::PaginationLoop,
        BuildkitePipelineResultError::PaginationLimit => BuildkiteProviderError::PaginationLimit,
        BuildkitePipelineResultError::ResponseTooLarge => BuildkiteProviderError::ResponseTooLarge,
        BuildkitePipelineResultError::OutOfScope => BuildkiteProviderError::OutOfScope,
        BuildkitePipelineResultError::TamperedEvidence
        | BuildkitePipelineResultError::RedactionViolation => {
            BuildkiteProviderError::TamperedEvidence
        }
        _ => BuildkiteProviderError::TamperedEvidence,
    }
}

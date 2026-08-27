//! Provider and transport seams for bounded AWS Glue job-run evidence.
//!
//! `AwsGlueProvider` is deliberately a Layer-1 provider wrapper. Its
//! transport implementations are fixture/recording/fake/loopback or
//! `BLOCKED_ENV`; none resolves a credential or performs native SigV4/HTTPS.

use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_GLUE_JOB_RESULT_API_REVISION, AWS_GLUE_JOB_RESULT_PROVIDER_ID,
    AWS_GLUE_JOB_RESULT_SCHEMA_VERSION,
    model::{
        AccountId, AttemptNumber, AwsGlueScope, AwsRegion, CatalogId, Digest,
        JobDefinitionMetadata, JobName, JobRunEvidence, ModelError, OpaquePageCursor,
        ProviderErrorKind, ProviderProvenance, ReadOperation, ResultBounds, Revision, RunId,
        SecretReference,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("provider API revision is empty")]
    EmptyApiRevision,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsGlueProviderDefinition {
    pub schema_version: String,
    pub provider_id: crate::ProviderId,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub get_job_run: bool,
    pub get_job_runs: bool,
    pub get_job_definition: bool,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
}

impl AwsGlueProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() || provenance.is_connected() || provenance.is_first_party() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let provider_id = crate::ProviderId::new(AWS_GLUE_JOB_RESULT_PROVIDER_ID)?;
        let api_revision = AWS_GLUE_JOB_RESULT_API_REVISION.to_owned();
        let capability_digest = Digest::from_fields(
            "aws-glue-provider-capability/v1",
            &[
                AWS_GLUE_JOB_RESULT_SCHEMA_VERSION.to_owned(),
                AWS_GLUE_JOB_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                api_revision.clone(),
                format!("{provenance:?}"),
                "GetJobRun".to_owned(),
                "GetJobRuns".to_owned(),
                "GetJob".to_owned(),
                "native=false".to_owned(),
                "connected=false".to_owned(),
                "external_writes=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: AWS_GLUE_JOB_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id,
            provider_version,
            api_revision,
            capability_digest,
            provenance,
            get_job_run: true,
            get_job_runs: true,
            get_job_definition: true,
            native: false,
            connected: false,
            external_writes: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-glue-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.api_revision.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.get_job_run.to_string(),
                self.get_job_runs.to_string(),
                self.get_job_definition.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.external_writes.to_string(),
            ],
        )
    }
}

/// The complete account/region/catalog/job and Mission permission fence that
/// every provider response must echo exactly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderFence {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub catalog_id: CatalogId,
    pub job_name: JobName,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_id: crate::MissionId,
    pub project_id: crate::ProjectId,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
}

impl ProviderFence {
    pub fn from_scope(
        scope: &AwsGlueScope,
        secret_reference: &SecretReference,
        job_name: JobName,
    ) -> Self {
        Self {
            account_id: scope.account_id().clone(),
            region: scope.region().clone(),
            catalog_id: scope.catalog_id().clone(),
            job_name,
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            mission_id: scope.mission_id().clone(),
            project_id: scope.project_id().clone(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: scope.work_product_revision(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            credential_revision: secret_reference.credential_revision(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-glue-provider-fence/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                self.catalog_id.as_str().to_owned(),
                self.job_name.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.mission_id.as_str().to_owned(),
                self.project_id.as_str().to_owned(),
                self.work_product_id.as_str().to_owned(),
                self.work_product_revision.get().to_string(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetJobRunRequest {
    pub fence: ProviderFence,
    pub run_id: RunId,
    pub expected_attempt: Option<AttemptNumber>,
    pub request_digest: Digest,
}

impl GetJobRunRequest {
    pub fn new(
        scope: &AwsGlueScope,
        secret_reference: &SecretReference,
        job_name: JobName,
        run_id: RunId,
        expected_attempt: Option<AttemptNumber>,
    ) -> Self {
        let fence = ProviderFence::from_scope(scope, secret_reference, job_name);
        let request_digest = Digest::from_fields(
            "aws-glue-get-job-run-request/v1",
            &[
                fence.digest().as_str().to_owned(),
                run_id.as_str().to_owned(),
                expected_attempt.map_or_else(|| "none".to_owned(), |value| value.get().to_string()),
            ],
        );
        Self {
            fence,
            run_id,
            expected_attempt,
            request_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetJobRunsRequest {
    pub fence: ProviderFence,
    pub bounds: ResultBounds,
    pub page_number: u8,
    pub cursor: Option<OpaquePageCursor>,
    pub cursor_binding_digest: Digest,
    pub request_digest: Digest,
}

impl GetJobRunsRequest {
    pub fn new(
        scope: &AwsGlueScope,
        secret_reference: &SecretReference,
        job_name: JobName,
        bounds: ResultBounds,
        page_number: u8,
        cursor: Option<OpaquePageCursor>,
    ) -> Self {
        let fence = ProviderFence::from_scope(scope, secret_reference, job_name);
        let cursor_binding_digest = Self::binding_digest(&fence, bounds);
        let request_digest = Digest::from_fields(
            "aws-glue-get-job-runs-request/v1",
            &[
                fence.digest().as_str().to_owned(),
                bounds.max_runs().to_string(),
                bounds.page_size().to_string(),
                bounds.max_pages().to_string(),
                bounds.timeout_seconds().to_string(),
                page_number.to_string(),
                cursor.as_ref().map_or_else(
                    || "none".to_owned(),
                    |value| value.token_digest().as_str().to_owned(),
                ),
                cursor_binding_digest.as_str().to_owned(),
            ],
        );
        Self {
            fence,
            bounds,
            page_number,
            cursor,
            cursor_binding_digest,
            request_digest,
        }
    }

    pub fn binding_digest(fence: &ProviderFence, bounds: ResultBounds) -> Digest {
        Digest::from_fields(
            "aws-glue-pagination-binding/v1",
            &[
                fence.digest().as_str().to_owned(),
                bounds.max_runs().to_string(),
                bounds.page_size().to_string(),
                bounds.max_pages().to_string(),
                bounds.timeout_seconds().to_string(),
                "newest_first=true".to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetJobDefinitionRequest {
    pub fence: ProviderFence,
    pub request_digest: Digest,
}

impl GetJobDefinitionRequest {
    pub fn new(
        scope: &AwsGlueScope,
        secret_reference: &SecretReference,
        job_name: JobName,
    ) -> Self {
        let fence = ProviderFence::from_scope(scope, secret_reference, job_name);
        let request_digest = Digest::from_fields(
            "aws-glue-get-job-definition-request/v1",
            &[fence.digest().as_str().to_owned()],
        );
        Self {
            fence,
            request_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetJobRunResponse {
    pub job_run: JobRunEvidence,
    pub job_definition: Option<JobDefinitionMetadata>,
    pub observed_fence: ProviderFence,
    pub response_digest: Digest,
}

impl GetJobRunResponse {
    pub fn new(
        request: &GetJobRunRequest,
        job_run: JobRunEvidence,
        job_definition: Option<JobDefinitionMetadata>,
    ) -> Self {
        let observed_fence = request.fence.clone();
        let response_digest = response_digest(
            "aws-glue-get-job-run-response/v1",
            &observed_fence,
            std::slice::from_ref(&job_run),
            job_definition.as_ref(),
            None,
            true,
        );
        Self {
            job_run,
            job_definition,
            observed_fence,
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.job_run.validate_digest()?;
        if let Some(definition) = &self.job_definition {
            definition.validate_digest()?;
        }
        let expected = response_digest(
            "aws-glue-get-job-run-response/v1",
            &self.observed_fence,
            std::slice::from_ref(&self.job_run),
            self.job_definition.as_ref(),
            None,
            true,
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetJobRunsResponse {
    pub job_runs: Vec<JobRunEvidence>,
    pub next_cursor: Option<OpaquePageCursor>,
    pub newest_first: bool,
    pub job_definition: Option<JobDefinitionMetadata>,
    pub observed_fence: ProviderFence,
    pub observed_cursor_binding_digest: Digest,
    pub response_digest: Digest,
}

impl GetJobRunsResponse {
    pub fn new(
        request: &GetJobRunsRequest,
        job_runs: Vec<JobRunEvidence>,
        next_cursor: Option<OpaquePageCursor>,
        newest_first: bool,
        job_definition: Option<JobDefinitionMetadata>,
    ) -> Self {
        let observed_fence = request.fence.clone();
        let next_cursor = next_cursor.map(|cursor| cursor.bind(&request.cursor_binding_digest));
        let observed_cursor_binding_digest = request.cursor_binding_digest.clone();
        let response_digest = response_digest(
            "aws-glue-get-job-runs-response/v1",
            &observed_fence,
            &job_runs,
            job_definition.as_ref(),
            next_cursor.as_ref(),
            newest_first,
        );
        Self {
            job_runs,
            next_cursor,
            newest_first,
            job_definition,
            observed_fence,
            observed_cursor_binding_digest,
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        for run in &self.job_runs {
            run.validate_digest()?;
        }
        if let Some(definition) = &self.job_definition {
            definition.validate_digest()?;
        }
        let expected = response_digest(
            "aws-glue-get-job-runs-response/v1",
            &self.observed_fence,
            &self.job_runs,
            self.job_definition.as_ref(),
            self.next_cursor.as_ref(),
            self.newest_first,
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetJobDefinitionResponse {
    pub job_definition: JobDefinitionMetadata,
    pub observed_fence: ProviderFence,
    pub response_digest: Digest,
}

impl GetJobDefinitionResponse {
    pub fn new(request: &GetJobDefinitionRequest, job_definition: JobDefinitionMetadata) -> Self {
        let observed_fence = request.fence.clone();
        let response_digest = response_digest(
            "aws-glue-get-job-definition-response/v1",
            &observed_fence,
            &[],
            Some(&job_definition),
            None,
            true,
        );
        Self {
            job_definition,
            observed_fence,
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.job_definition.validate_digest()?;
        let expected = response_digest(
            "aws-glue-get-job-definition-response/v1",
            &self.observed_fence,
            &[],
            Some(&self.job_definition),
            None,
            true,
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

fn response_digest(
    domain: &str,
    fence: &ProviderFence,
    job_runs: &[JobRunEvidence],
    job_definition: Option<&JobDefinitionMetadata>,
    next_cursor: Option<&OpaquePageCursor>,
    newest_first: bool,
) -> Digest {
    let mut fields = vec![
        fence.digest().as_str().to_owned(),
        newest_first.to_string(),
        job_definition.map_or_else(
            || "none".to_owned(),
            |value| value.definition_digest.as_str().to_owned(),
        ),
        next_cursor.map_or_else(
            || "none".to_owned(),
            |value| value.token_digest().as_str().to_owned(),
        ),
    ];
    fields.extend(
        job_runs
            .iter()
            .map(|run| run.run_digest.as_str().to_owned()),
    );
    Digest::from_fields(domain, &fields)
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("AWS Glue provider transport returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        Self {
            kind,
            status_code,
            retryable,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn from_status(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        let kind = match status_code {
            400 => ProviderErrorKind::BadRequest,
            401 => ProviderErrorKind::Unauthenticated,
            403 => ProviderErrorKind::PermissionDenied,
            404 => ProviderErrorKind::NotFound,
            409 => ProviderErrorKind::Conflict,
            429 => ProviderErrorKind::RateLimited,
            500..=599 => ProviderErrorKind::ServerFailure,
            _ => ProviderErrorKind::Unknown,
        };
        Self::new(kind, Some(status_code), diagnostic)
    }

    pub fn timeout(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(ProviderErrorKind::Timeout, None, diagnostic)
    }

    pub fn blocked_env() -> Self {
        Self::new(
            ProviderErrorKind::BlockedEnv,
            None,
            crate::AWS_GLUE_JOB_RESULT_BLOCKED_ENV,
        )
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

pub fn is_access_loss(kind: ProviderErrorKind) -> bool {
    matches!(
        kind,
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied
    )
}

pub trait AwsGlueProviderTransport: fmt::Debug {
    fn get_job_run(
        &mut self,
        request: &GetJobRunRequest,
    ) -> Result<GetJobRunResponse, TransportError>;

    fn get_job_runs(
        &mut self,
        request: &GetJobRunsRequest,
    ) -> Result<GetJobRunsResponse, TransportError>;

    fn get_job_definition(
        &mut self,
        request: &GetJobDefinitionRequest,
    ) -> Result<GetJobDefinitionResponse, TransportError>;
}

#[derive(Debug)]
pub struct AwsGlueProvider<T> {
    transport: T,
    definition: AwsGlueProviderDefinition,
}

impl<T: AwsGlueProviderTransport> AwsGlueProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            definition: AwsGlueProviderDefinition::new(provider_version, provenance)?,
        })
    }

    pub fn definition(&self) -> &AwsGlueProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn get_job_run(
        &mut self,
        request: &GetJobRunRequest,
    ) -> Result<GetJobRunResponse, TransportError> {
        self.transport.get_job_run(request)
    }

    pub fn get_job_runs(
        &mut self,
        request: &GetJobRunsRequest,
    ) -> Result<GetJobRunsResponse, TransportError> {
        self.transport.get_job_runs(request)
    }

    pub fn get_job_definition(
        &mut self,
        request: &GetJobDefinitionRequest,
    ) -> Result<GetJobDefinitionResponse, TransportError> {
        self.transport.get_job_definition(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum TransportCall {
    GetJobRun {
        job_name: JobName,
        run_id: RunId,
    },
    GetJobRuns {
        job_name: JobName,
        page_number: u8,
        cursor_digest: Option<Digest>,
    },
    GetJobDefinition {
        job_name: JobName,
    },
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAwsGlueTransport {
    get_job_run_responses: VecDeque<Result<GetJobRunResponse, TransportError>>,
    get_job_runs_responses: VecDeque<Result<GetJobRunsResponse, TransportError>>,
    get_job_definition_responses: VecDeque<Result<GetJobDefinitionResponse, TransportError>>,
    calls: Vec<TransportCall>,
}

impl RecordingAwsGlueTransport {
    pub fn push_job_run_response(&mut self, response: Result<GetJobRunResponse, TransportError>) {
        self.get_job_run_responses.push_back(response);
    }

    pub fn push_job_runs_response(&mut self, response: Result<GetJobRunsResponse, TransportError>) {
        self.get_job_runs_responses.push_back(response);
    }

    pub fn push_job_definition_response(
        &mut self,
        response: Result<GetJobDefinitionResponse, TransportError>,
    ) {
        self.get_job_definition_responses.push_back(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn missing_response(operation: ReadOperation) -> TransportError {
        TransportError::new(
            ProviderErrorKind::Unknown,
            None,
            format!("recording transport has no {operation:?} response"),
        )
    }
}

impl AwsGlueProviderTransport for RecordingAwsGlueTransport {
    fn get_job_run(
        &mut self,
        request: &GetJobRunRequest,
    ) -> Result<GetJobRunResponse, TransportError> {
        self.calls.push(TransportCall::GetJobRun {
            job_name: request.fence.job_name.clone(),
            run_id: request.run_id.clone(),
        });
        self.get_job_run_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response(ReadOperation::GetJobRun)))
    }

    fn get_job_runs(
        &mut self,
        request: &GetJobRunsRequest,
    ) -> Result<GetJobRunsResponse, TransportError> {
        self.calls.push(TransportCall::GetJobRuns {
            job_name: request.fence.job_name.clone(),
            page_number: request.page_number,
            cursor_digest: request.cursor.as_ref().map(OpaquePageCursor::digest),
        });
        self.get_job_runs_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response(ReadOperation::GetJobRuns)))
    }

    fn get_job_definition(
        &mut self,
        request: &GetJobDefinitionRequest,
    ) -> Result<GetJobDefinitionResponse, TransportError> {
        self.calls.push(TransportCall::GetJobDefinition {
            job_name: request.fence.job_name.clone(),
        });
        self.get_job_definition_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response(ReadOperation::GetJobDefinition)))
    }
}

pub type FakeAwsGlueTransport = RecordingAwsGlueTransport;
pub type FixtureAwsGlueTransport = RecordingAwsGlueTransport;

#[derive(Clone, Debug)]
pub struct LoopbackAwsGlueTransport {
    run: Option<JobRunEvidence>,
    runs: Vec<JobRunEvidence>,
    definition: Option<JobDefinitionMetadata>,
}

impl LoopbackAwsGlueTransport {
    pub fn new(
        job_run: Option<JobRunEvidence>,
        job_runs: Vec<JobRunEvidence>,
        job_definition: Option<JobDefinitionMetadata>,
    ) -> Self {
        Self {
            run: job_run,
            runs: job_runs,
            definition: job_definition,
        }
    }
}

impl AwsGlueProviderTransport for LoopbackAwsGlueTransport {
    fn get_job_run(
        &mut self,
        request: &GetJobRunRequest,
    ) -> Result<GetJobRunResponse, TransportError> {
        self.run
            .clone()
            .map(|run| GetJobRunResponse::new(request, run, self.definition.clone()))
            .ok_or_else(|| {
                TransportError::new(ProviderErrorKind::Unknown, None, "loopback has no job run")
            })
    }

    fn get_job_runs(
        &mut self,
        request: &GetJobRunsRequest,
    ) -> Result<GetJobRunsResponse, TransportError> {
        Ok(GetJobRunsResponse::new(
            request,
            self.runs.clone(),
            None,
            true,
            self.definition.clone(),
        ))
    }

    fn get_job_definition(
        &mut self,
        request: &GetJobDefinitionRequest,
    ) -> Result<GetJobDefinitionResponse, TransportError> {
        self.definition
            .clone()
            .map(|definition| GetJobDefinitionResponse::new(request, definition))
            .ok_or_else(|| {
                TransportError::new(
                    ProviderErrorKind::NotFound,
                    Some(404),
                    "loopback has no job definition",
                )
            })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsGlueTransport;

impl AwsGlueProviderTransport for BlockedEnvAwsGlueTransport {
    fn get_job_run(
        &mut self,
        _request: &GetJobRunRequest,
    ) -> Result<GetJobRunResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_job_runs(
        &mut self,
        _request: &GetJobRunsRequest,
    ) -> Result<GetJobRunsResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_job_definition(
        &mut self,
        _request: &GetJobDefinitionRequest,
    ) -> Result<GetJobDefinitionResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub type BlockedEnvTransport = BlockedEnvAwsGlueTransport;

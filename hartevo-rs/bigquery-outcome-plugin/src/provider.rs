use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BIGQUERY_OUTCOME_PROVIDER_ID, BIGQUERY_OUTCOME_SCHEMA_VERSION,
    model::{
        BigQueryScope, BoundedRow, Digest, JobMetadata, JobReference, Location, MissionId,
        ModelError, OpaquePageToken, PermissionFence, ProjectId, ProviderErrorKind, ProviderId,
        QueryErrorEvidence, QueryMode, QuerySchema, ResultBounds, Revision, SecretReference,
        WorkProductId,
    },
    query::BigQueryQueryProposal,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BigQueryProviderDefinition {
    pub schema_version: String,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub jobs_query: bool,
    pub jobs_get_query_results: bool,
    pub live_execution: bool,
}

impl BigQueryProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let provider_id = ProviderId::new(BIGQUERY_OUTCOME_PROVIDER_ID)?;
        let capability_digest = Digest::from_fields(
            "bigquery-provider-capability/v1",
            &[
                BIGQUERY_OUTCOME_SCHEMA_VERSION.to_owned(),
                BIGQUERY_OUTCOME_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                "jobs.query".to_owned(),
                "jobs.getQueryResults".to_owned(),
                "live_execution=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: BIGQUERY_OUTCOME_SCHEMA_VERSION.to_owned(),
            provider_id,
            provider_version,
            capability_digest,
            provenance,
            jobs_query: true,
            jobs_get_query_results: true,
            live_execution: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "bigquery-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.jobs_query.to_string(),
                self.jobs_get_query_results.to_string(),
                self.live_execution.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("BigQuery provider transport returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
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
            ProviderErrorKind::Quota
                | ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        let blocked_env = kind == ProviderErrorKind::BlockedEnv;
        Self {
            kind,
            status_code,
            retryable,
            blocked_env,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn quota() -> Self {
        Self::new(ProviderErrorKind::Quota, Some(403), "quota")
    }

    pub fn rate_limited() -> Self {
        Self::new(ProviderErrorKind::RateLimited, Some(429), "rate-limited")
    }

    pub fn server_failure() -> Self {
        Self::new(
            ProviderErrorKind::ServerFailure,
            Some(500),
            "server-failure",
        )
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn access_denied() -> Self {
        Self::new(
            ProviderErrorKind::PermissionDenied,
            Some(403),
            "access-denied",
        )
    }

    pub fn not_found() -> Self {
        Self::new(ProviderErrorKind::NotFound, Some(404), "not-found")
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub(crate) fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

/// Safe request metadata for a recorded jobs.query proposal. It contains
/// digests and scope identifiers, never SQL text or credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobsQueryRequest {
    pub project_id: ProjectId,
    pub location: Location,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub mode: QueryMode,
    pub bounds: ResultBounds,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub auth_kind: crate::GoogleAuthKind,
}

impl JobsQueryRequest {
    pub(crate) fn from_proposal(
        scope: &BigQueryScope,
        secret: &SecretReference,
        proposal: &BigQueryQueryProposal,
    ) -> Self {
        Self {
            project_id: scope.project_id().clone(),
            location: scope.location().clone(),
            mission_id: scope.mission_id().clone(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: proposal.work_product_revision(),
            scope_digest: proposal.scope_digest().clone(),
            query_digest: proposal.query_digest().clone(),
            config_digest: proposal.config_digest().clone(),
            mode: proposal.mode(),
            bounds: proposal.bounds(),
            secret_reference_digest: proposal.secret_reference_digest().clone(),
            credential_revision: proposal.credential_revision(),
            permission_digest: proposal.permission_digest().clone(),
            consent_digest: proposal.consent_digest().clone(),
            auth_kind: secret.auth_kind(),
        }
    }

    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            work_product_revision: self.work_product_revision,
        }
    }
}

/// Safe metadata for a recorded jobs.getQueryResults proposal. The token is
/// forwarded opaquely and only its digest is available to evidence consumers.
#[derive(Clone, Eq, PartialEq)]
pub struct JobsGetQueryResultsRequest {
    pub job: JobReference,
    pub location: Location,
    pub work_product_revision: Revision,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub bounds: ResultBounds,
    pub page_number: u8,
    pub page_token: Option<OpaquePageToken>,
    pub credential_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

impl fmt::Debug for JobsGetQueryResultsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobsGetQueryResultsRequest")
            .field("job", &self.job)
            .field("location", &self.location)
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("config_digest", &self.config_digest)
            .field("bounds", &self.bounds)
            .field("page_number", &self.page_number)
            .field(
                "page_token_digest",
                &self.page_token.as_ref().map(OpaquePageToken::digest),
            )
            .field("work_product_revision", &self.work_product_revision)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl JobsGetQueryResultsRequest {
    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }

    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            work_product_revision: self.work_product_revision,
        }
    }
}

pub trait BigQueryProvider: fmt::Debug {
    fn definition(&self) -> &BigQueryProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn jobs_query(
        &mut self,
        request: &JobsQueryRequest,
    ) -> Result<JobsQueryResponse, TransportError>;

    fn jobs_get_query_results(
        &mut self,
        request: &JobsGetQueryResultsRequest,
    ) -> Result<QueryResultPage, TransportError>;
}

pub trait BigQueryJobsTransport: fmt::Debug {
    fn jobs_query(
        &mut self,
        request: &JobsQueryRequest,
    ) -> Result<JobsQueryResponse, TransportError>;

    fn jobs_get_query_results(
        &mut self,
        request: &JobsGetQueryResultsRequest,
    ) -> Result<QueryResultPage, TransportError>;
}

#[derive(Debug)]
pub struct BigQueryJobsProvider<T> {
    transport: T,
    definition: BigQueryProviderDefinition,
}

impl<T: BigQueryJobsTransport> BigQueryJobsProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            definition: BigQueryProviderDefinition::new(provider_version, provenance)?,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: BigQueryJobsTransport> BigQueryProvider for BigQueryJobsProvider<T> {
    fn definition(&self) -> &BigQueryProviderDefinition {
        &self.definition
    }

    fn jobs_query(
        &mut self,
        request: &JobsQueryRequest,
    ) -> Result<JobsQueryResponse, TransportError> {
        self.transport.jobs_query(request)
    }

    fn jobs_get_query_results(
        &mut self,
        request: &JobsGetQueryResultsRequest,
    ) -> Result<QueryResultPage, TransportError> {
        self.transport.jobs_get_query_results(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobsQueryResponse {
    pub job: JobMetadata,
    pub job_complete: bool,
    pub schema: Option<QuerySchema>,
    pub rows: Vec<BoundedRow>,
    pub next_page_token: Option<OpaquePageToken>,
    pub total_rows: Option<u64>,
    pub total_bytes_processed: u64,
    pub cache_hit: Option<bool>,
    pub errors: Vec<QueryErrorEvidence>,
    pub observed_scope_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_work_product_revision: Revision,
    pub observed_credential_revision: Revision,
    pub response_digest: Digest,
}

impl JobsQueryResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: JobMetadata,
        job_complete: bool,
        schema: Option<QuerySchema>,
        rows: Vec<BoundedRow>,
        next_page_token: Option<OpaquePageToken>,
        total_rows: Option<u64>,
        total_bytes_processed: u64,
        cache_hit: Option<bool>,
        errors: Vec<QueryErrorEvidence>,
        fence: PermissionFence,
        observed_credential_revision: Revision,
    ) -> Self {
        let response_digest = compute_response_digest(
            "bigquery-jobs-query-response/v1",
            &job,
            job_complete,
            schema.as_ref(),
            &rows,
            next_page_token.as_ref(),
            total_rows,
            total_bytes_processed,
            cache_hit,
            &errors,
            &fence,
            observed_credential_revision,
        );
        Self {
            job,
            job_complete,
            schema,
            rows,
            next_page_token,
            total_rows,
            total_bytes_processed,
            cache_hit,
            errors,
            observed_scope_digest: fence.scope_digest,
            observed_permission_digest: fence.permission_digest,
            observed_consent_digest: fence.consent_digest,
            observed_work_product_revision: fence.work_product_revision,
            observed_credential_revision,
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.job.validate_digest()?;
        if let Some(schema) = &self.schema {
            schema.validate_digest()?;
        }
        for row in &self.rows {
            row.validate_digest()?;
        }
        let expected = compute_response_digest(
            "bigquery-jobs-query-response/v1",
            &self.job,
            self.job_complete,
            self.schema.as_ref(),
            &self.rows,
            self.next_page_token.as_ref(),
            self.total_rows,
            self.total_bytes_processed,
            self.cache_hit,
            &self.errors,
            &PermissionFence {
                scope_digest: self.observed_scope_digest.clone(),
                permission_digest: self.observed_permission_digest.clone(),
                consent_digest: self.observed_consent_digest.clone(),
                work_product_revision: self.observed_work_product_revision,
            },
            self.observed_credential_revision,
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryResultPage {
    pub job: JobMetadata,
    pub job_complete: bool,
    pub schema: Option<QuerySchema>,
    pub rows: Vec<BoundedRow>,
    pub next_page_token: Option<OpaquePageToken>,
    pub total_rows: Option<u64>,
    pub total_bytes_processed: u64,
    pub cache_hit: Option<bool>,
    pub errors: Vec<QueryErrorEvidence>,
    pub observed_scope_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_work_product_revision: Revision,
    pub observed_credential_revision: Revision,
    pub page_digest: Digest,
}

impl QueryResultPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: JobMetadata,
        job_complete: bool,
        schema: Option<QuerySchema>,
        rows: Vec<BoundedRow>,
        next_page_token: Option<OpaquePageToken>,
        total_rows: Option<u64>,
        total_bytes_processed: u64,
        cache_hit: Option<bool>,
        errors: Vec<QueryErrorEvidence>,
        fence: PermissionFence,
        observed_credential_revision: Revision,
    ) -> Self {
        let page_digest = compute_response_digest(
            "bigquery-query-result-page/v1",
            &job,
            job_complete,
            schema.as_ref(),
            &rows,
            next_page_token.as_ref(),
            total_rows,
            total_bytes_processed,
            cache_hit,
            &errors,
            &fence,
            observed_credential_revision,
        );
        Self {
            job,
            job_complete,
            schema,
            rows,
            next_page_token,
            total_rows,
            total_bytes_processed,
            cache_hit,
            errors,
            observed_scope_digest: fence.scope_digest,
            observed_permission_digest: fence.permission_digest,
            observed_consent_digest: fence.consent_digest,
            observed_work_product_revision: fence.work_product_revision,
            observed_credential_revision,
            page_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.job.validate_digest()?;
        if let Some(schema) = &self.schema {
            schema.validate_digest()?;
        }
        for row in &self.rows {
            row.validate_digest()?;
        }
        let expected = compute_response_digest(
            "bigquery-query-result-page/v1",
            &self.job,
            self.job_complete,
            self.schema.as_ref(),
            &self.rows,
            self.next_page_token.as_ref(),
            self.total_rows,
            self.total_bytes_processed,
            self.cache_hit,
            &self.errors,
            &PermissionFence {
                scope_digest: self.observed_scope_digest.clone(),
                permission_digest: self.observed_permission_digest.clone(),
                consent_digest: self.observed_consent_digest.clone(),
                work_product_revision: self.observed_work_product_revision,
            },
            self.observed_credential_revision,
        );
        if expected == self.page_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

fn compute_response_digest(
    domain: &str,
    job: &JobMetadata,
    job_complete: bool,
    schema: Option<&QuerySchema>,
    rows: &[BoundedRow],
    next_page_token: Option<&OpaquePageToken>,
    total_rows: Option<u64>,
    total_bytes_processed: u64,
    cache_hit: Option<bool>,
    errors: &[QueryErrorEvidence],
    fence: &PermissionFence,
    observed_credential_revision: Revision,
) -> Digest {
    let row_digest = Digest::from_fields(
        "bigquery-row-set/v1",
        &rows
            .iter()
            .enumerate()
            .map(|(index, row)| format!("{index}:{}", row.row_digest.as_str()))
            .collect::<Vec<_>>(),
    );
    let error_digest = Digest::from_fields(
        "bigquery-error-set/v1",
        &errors
            .iter()
            .map(|error| {
                format!(
                    "{:?}:{:?}:{}:{}",
                    error.kind,
                    error.severity,
                    error.status_code.map_or(0, u16::from),
                    error.error_digest.as_str()
                )
            })
            .collect::<Vec<_>>(),
    );
    Digest::from_fields(
        domain,
        &[
            job.job_digest.as_str().to_owned(),
            job_complete.to_string(),
            schema.map_or_else(
                || "none".to_owned(),
                |value| value.schema_digest.as_str().to_owned(),
            ),
            row_digest.as_str().to_owned(),
            next_page_token.map_or_else(
                || "none".to_owned(),
                |token| token.digest().as_str().to_owned(),
            ),
            total_rows.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            total_bytes_processed.to_string(),
            cache_hit.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            error_digest.as_str().to_owned(),
            fence.scope_digest.as_str().to_owned(),
            fence.permission_digest.as_str().to_owned(),
            fence.consent_digest.as_str().to_owned(),
            fence.work_product_revision.get().to_string(),
            observed_credential_revision.get().to_string(),
        ],
    )
}

#[derive(Debug, Default)]
pub struct RecordingBigQueryTransport {
    query_responses: VecDeque<Result<JobsQueryResponse, TransportError>>,
    page_responses: VecDeque<Result<QueryResultPage, TransportError>>,
    query_calls: usize,
    page_calls: usize,
}

impl RecordingBigQueryTransport {
    pub fn push_query_response(&mut self, response: Result<JobsQueryResponse, TransportError>) {
        self.query_responses.push_back(response);
    }

    pub fn push_page_response(&mut self, response: Result<QueryResultPage, TransportError>) {
        self.page_responses.push_back(response);
    }

    pub const fn query_calls(&self) -> usize {
        self.query_calls
    }

    pub const fn page_calls(&self) -> usize {
        self.page_calls
    }
}

impl BigQueryJobsTransport for RecordingBigQueryTransport {
    fn jobs_query(
        &mut self,
        _request: &JobsQueryRequest,
    ) -> Result<JobsQueryResponse, TransportError> {
        self.query_calls = self.query_calls.saturating_add(1);
        self.query_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }

    fn jobs_get_query_results(
        &mut self,
        _request: &JobsGetQueryResultsRequest,
    ) -> Result<QueryResultPage, TransportError> {
        self.page_calls = self.page_calls.saturating_add(1);
        self.page_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }
}

pub type FakeBigQueryTransport = RecordingBigQueryTransport;
pub type LoopbackTransport = RecordingBigQueryTransport;

#[derive(Debug, Default)]
pub struct BlockedEnvTransport;

impl BigQueryJobsTransport for BlockedEnvTransport {
    fn jobs_query(
        &mut self,
        _request: &JobsQueryRequest,
    ) -> Result<JobsQueryResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn jobs_get_query_results(
        &mut self,
        _request: &JobsGetQueryResultsRequest,
    ) -> Result<QueryResultPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

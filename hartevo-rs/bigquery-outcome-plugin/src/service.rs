use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    BIGQUERY_OUTCOME_CONSUMER_ID, BIGQUERY_OUTCOME_CONTRACT_VERSION, BIGQUERY_OUTCOME_PROVIDER_ID,
    BIGQUERY_OUTCOME_SCHEMA_VERSION, BIGQUERY_OUTCOME_SERVICE_ID,
    model::{
        AdoptionAvailability, AnalyticalResultAuthority, BigQueryRegistration, BigQueryScope,
        BoundedRow, ConsumerId, Digest, EvidenceDigests, JobMetadata, JobState, ModelError,
        OpaquePageToken, PermissionFence, ProviderErrorEvidence, ProviderErrorKind, ProviderId,
        QueryErrorEvidence, QuerySchema, ResultBounds, ResultStatus, Revision, SecretReference,
        ServiceId,
    },
    provider::{
        BigQueryProvider, BigQueryProviderDefinition, JobsGetQueryResultsRequest, JobsQueryRequest,
        JobsQueryResponse, ProviderDefinitionError, ProviderProvenance, QueryResultPage,
        TransportError,
    },
    query::{BigQueryQueryProposal, QueryCompileError, QueryProposalRequest},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BigQueryServiceError {
    #[error("BigQuery registration is revoked")]
    RegistrationRevoked,
    #[error("BigQuery SecretReference is revoked")]
    SecretRevoked,
    #[error("BigQuery provider or service scope does not match")]
    ScopeMismatch,
    #[error("provider evidence was tampered with or its digest is stale")]
    TamperedEvidence,
    #[error("provider returned a different query digest")]
    QueryDrift,
    #[error("provider returned a different query configuration digest")]
    ConfigDrift,
    #[error("provider returned a different project, location, or job binding")]
    LocationMismatch,
    #[error("provider permission or revision fence changed")]
    FenceViolation,
    #[error("provider schema changed between pages")]
    SchemaDrift,
    #[error("provider returned a repeated page token")]
    PageLoop,
    #[error("provider returned rows for a dry-run proposal")]
    DryRunRows,
    #[error("provider returned a response that exceeds the safe evidence shape")]
    InvalidResponseShape,
    #[error("provider definition is invalid")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error(transparent)]
    Query(#[from] QueryCompileError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RetryPolicyError {
    #[error("retry attempts must be between one and four")]
    InvalidAttempts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8) -> Result<Self, RetryPolicyError> {
        if !(1..=4).contains(&max_attempts) {
            Err(RetryPolicyError::InvalidAttempts)
        } else {
            Ok(Self { max_attempts })
        }
    }

    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryEvidence {
    pub operation: String,
    pub attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    JobNotComplete,
    MissingPageToken,
    PageCap,
    RowCap,
    ByteCap,
    Timeout,
    Warning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProjection {
    Complete,
    Partial(PartialReason),
    Expired,
    AccessLost,
    ProviderUnknown,
    FinalError,
}

impl ResultProjection {
    pub const fn status(self) -> ResultStatus {
        match self {
            Self::Complete => ResultStatus::Complete,
            Self::Partial(_) => ResultStatus::Partial,
            Self::Expired => ResultStatus::Expired,
            Self::AccessLost => ResultStatus::AccessLost,
            Self::ProviderUnknown => ResultStatus::ProviderUnknown,
            Self::FinalError => ResultStatus::FinalError,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultEvidence {
    pub status: ResultStatus,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub job: Option<JobMetadata>,
    pub schema: Option<QuerySchema>,
    pub rows: Vec<BoundedRow>,
    pub total_rows: Option<u64>,
    pub bytes_processed: u64,
    pub cache_hit: Option<bool>,
    pub pages_observed: u8,
    pub page_token_digests: Vec<Digest>,
    pub warnings: Vec<QueryErrorEvidence>,
    pub errors: Vec<QueryErrorEvidence>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub row_bound_exceeded: bool,
    pub byte_bound_exceeded: bool,
    pub digests: EvidenceDigests,
    pub provider_provenance: ProviderProvenance,
    pub authority: AnalyticalResultAuthority,
    pub adoption: AdoptionAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigQueryResultProposal {
    pub query: BigQueryQueryProposal,
    pub projection: ResultProjection,
    pub evidence: ResultEvidence,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl BigQueryResultProposal {
    pub fn status(&self) -> ResultStatus {
        self.projection.status()
    }

    pub fn is_adopted(&self) -> bool {
        false
    }

    pub fn authority(&self) -> AnalyticalResultAuthority {
        self.evidence.authority
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigQueryServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_outcome: bool,
}

impl BigQueryServiceDefinition {
    pub fn new() -> Self {
        Self {
            schema_version: BIGQUERY_OUTCOME_SCHEMA_VERSION.to_owned(),
            contract_version: BIGQUERY_OUTCOME_CONTRACT_VERSION.to_owned(),
            service_id: ServiceId::new(BIGQUERY_OUTCOME_SERVICE_ID)
                .expect("contract service identifier"),
            provider_id: ProviderId::new(BIGQUERY_OUTCOME_PROVIDER_ID)
                .expect("contract provider identifier"),
            consumer_id: ConsumerId::new(BIGQUERY_OUTCOME_CONSUMER_ID)
                .expect("contract consumer identifier"),
            contract_digest: Digest::from_text(crate::BIGQUERY_OUTCOME_CONTRACT_JSON),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
        }
    }
}

impl Default for BigQueryServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BigQueryResultService<P> {
    scope: BigQueryScope,
    secret_reference: SecretReference,
    provider: P,
    service_definition: BigQueryServiceDefinition,
    registration: BigQueryRegistration,
    retry_policy: RetryPolicy,
}

impl<P: BigQueryProvider> fmt::Debug for BigQueryResultService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BigQueryResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

pub type BigQueryOutcomeService<P> = BigQueryResultService<P>;

impl<P: BigQueryProvider> BigQueryResultService<P> {
    pub fn new(
        scope: BigQueryScope,
        secret_reference: SecretReference,
        provider: P,
        retry_policy: RetryPolicy,
    ) -> Result<Self, BigQueryServiceError> {
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(BigQueryServiceError::ScopeMismatch);
        }
        let service_definition = BigQueryServiceDefinition::new();
        let provider_definition = provider.definition();
        let provider_id = crate::ProviderId::new(provider_definition.provider_id.as_str())?;
        let registration = BigQueryRegistration::new(
            scope.scope_digest(),
            provider_id,
            provider_definition.provider_version.clone(),
            provider_definition.capability_digest.clone(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            service_definition,
            registration,
            retry_policy,
        })
    }

    pub fn service_definition(&self) -> &BigQueryServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &BigQueryProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &BigQueryRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &BigQueryScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::model::RegistrationRevocation, BigQueryServiceError> {
        self.registration
            .revoke()
            .map_err(BigQueryServiceError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), BigQueryServiceError> {
        self.secret_reference
            .revoke()
            .map_err(BigQueryServiceError::from)
    }

    pub fn propose(
        &mut self,
        request: QueryProposalRequest,
    ) -> Result<BigQueryResultProposal, BigQueryServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| BigQueryServiceError::RegistrationRevoked)?;
        if self.secret_reference.is_revoked() {
            return Err(BigQueryServiceError::SecretRevoked);
        }
        let query = BigQueryQueryProposal::compile(&self.scope, &self.secret_reference, request)?;
        let request = JobsQueryRequest::from_proposal(&self.scope, &self.secret_reference, &query);
        let provider_definition_digest = self.provider.definition().provider_digest();
        let mut accumulator = EvidenceAccumulator::new(
            &query,
            self.scope.fence(),
            self.provider.provenance(),
            self.retry_policy,
        );
        let query_response = match self.jobs_query_with_retry(&request, &mut accumulator) {
            Ok(response) => response,
            Err(failure) => {
                let projection = projection_for_provider_error(&failure.error);
                let evidence = accumulator.finish(projection);
                return Ok(self.finish_proposal(
                    query,
                    projection,
                    evidence,
                    provider_definition_digest,
                ));
            }
        };
        Self::validate_query_response(&request, &query_response)?;
        accumulator.add_query_response(&query_response, query.mode())?;

        let mut projection = projection_from_job(&query_response.job, &query_response.errors);
        if projection == ResultProjection::Complete && accumulator.row_bound_exceeded() {
            projection = ResultProjection::Partial(PartialReason::RowCap);
        }
        if projection == ResultProjection::Complete && accumulator.byte_bound_exceeded() {
            projection = ResultProjection::Partial(PartialReason::ByteCap);
        }
        let mut next_page_token = query_response.next_page_token.clone();
        let mut job_complete = query_response.job_complete;
        let mut page_number = 1_u8;
        let mut seen_tokens = BTreeSet::new();
        if let Some(token) = &next_page_token {
            seen_tokens.insert(token.digest());
            accumulator.record_token(token);
        }

        while projection == ResultProjection::Complete
            && (next_page_token.is_some() || !job_complete)
        {
            if page_number >= query.bounds().max_pages() {
                projection = ResultProjection::Partial(PartialReason::PageCap);
                break;
            }
            let Some(page_token) = next_page_token.take() else {
                projection = ResultProjection::Partial(PartialReason::MissingPageToken);
                break;
            };
            page_number = page_number.saturating_add(1);
            let page_request = JobsGetQueryResultsRequest {
                job: query_response.job.reference.clone(),
                location: self.scope.location().clone(),
                work_product_revision: query.work_product_revision(),
                scope_digest: query.scope_digest().clone(),
                query_digest: query.query_digest().clone(),
                config_digest: query.config_digest().clone(),
                bounds: query.bounds(),
                page_number,
                page_token: Some(page_token.clone()),
                credential_revision: query.credential_revision(),
                permission_digest: query.permission_digest().clone(),
                consent_digest: query.consent_digest().clone(),
            };
            let page = match self.jobs_get_query_results_with_retry(&page_request, &mut accumulator)
            {
                Ok(page) => page,
                Err(failure) => {
                    projection = projection_for_provider_error(&failure.error);
                    break;
                }
            };
            self.validate_result_page(&page_request, &page, &query_response.job)?;
            if let Some(next) = &page.next_page_token {
                if !seen_tokens.insert(next.digest()) {
                    return Err(BigQueryServiceError::PageLoop);
                }
                accumulator.record_token(next);
            }
            accumulator.add_result_page(&page)?;
            job_complete = page.job_complete;
            next_page_token.clone_from(&page.next_page_token);
            projection = projection_from_job(&page.job, &page.errors);
            if projection == ResultProjection::Complete
                && !job_complete
                && next_page_token.is_none()
            {
                projection = ResultProjection::Partial(PartialReason::MissingPageToken);
            }
            if projection == ResultProjection::Complete && accumulator.row_bound_exceeded() {
                projection = ResultProjection::Partial(PartialReason::RowCap);
            }
            if projection == ResultProjection::Complete && accumulator.byte_bound_exceeded() {
                projection = ResultProjection::Partial(PartialReason::ByteCap);
            }
        }

        if projection == ResultProjection::Complete && (!job_complete || next_page_token.is_some())
        {
            projection = ResultProjection::Partial(PartialReason::JobNotComplete);
        }
        if query.mode() == crate::QueryMode::DryRun && !accumulator.rows.is_empty() {
            return Err(BigQueryServiceError::DryRunRows);
        }
        let evidence = accumulator.finish(projection);
        Ok(self.finish_proposal(query, projection, evidence, provider_definition_digest))
    }

    fn finish_proposal(
        &self,
        query: BigQueryQueryProposal,
        projection: ResultProjection,
        evidence: ResultEvidence,
        provider_definition_digest: Digest,
    ) -> BigQueryResultProposal {
        let proposal_digest = Digest::from_fields(
            "bigquery-result-proposal/v1",
            &[
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                provider_definition_digest.as_str().to_owned(),
                query.scope_digest().as_str().to_owned(),
                query.query_digest().as_str().to_owned(),
                query.config_digest().as_str().to_owned(),
                format!("{projection:?}"),
                evidence.digests.result_digest.as_str().to_owned(),
            ],
        );
        BigQueryResultProposal {
            query,
            projection,
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_definition_digest,
            proposal_digest,
        }
    }

    fn jobs_query_with_retry(
        &mut self,
        request: &JobsQueryRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<JobsQueryResponse, CallFailure> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.provider.jobs_query(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    accumulator.record_retry("jobs.query", attempt, &error);
                }
                Err(error) => {
                    accumulator.record_provider_error(&error, attempt);
                    return Err(CallFailure { error });
                }
            }
        }
        unreachable!("retry loop always returns")
    }

    fn jobs_get_query_results_with_retry(
        &mut self,
        request: &JobsGetQueryResultsRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<QueryResultPage, CallFailure> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.provider.jobs_get_query_results(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    accumulator.record_retry("jobs.getQueryResults", attempt, &error);
                }
                Err(error) => {
                    accumulator.record_provider_error(&error, attempt);
                    return Err(CallFailure { error });
                }
            }
        }
        unreachable!("retry loop always returns")
    }

    fn validate_query_response(
        request: &JobsQueryRequest,
        response: &JobsQueryResponse,
    ) -> Result<(), BigQueryServiceError> {
        response
            .validate_digest()
            .map_err(|_| BigQueryServiceError::TamperedEvidence)?;
        validate_row_shape(response.schema.as_ref(), &response.rows)?;
        validate_job_and_fence(
            request,
            &response.job,
            &response.observed_scope_digest,
            &response.observed_permission_digest,
            &response.observed_consent_digest,
            response.observed_work_product_revision,
            response.observed_credential_revision,
        )?;
        if response.job.reference.location != request.location {
            return Err(BigQueryServiceError::LocationMismatch);
        }
        Ok(())
    }

    fn validate_result_page(
        &self,
        request: &JobsGetQueryResultsRequest,
        page: &QueryResultPage,
        initial_job: &JobMetadata,
    ) -> Result<(), BigQueryServiceError> {
        page.validate_digest()
            .map_err(|_| BigQueryServiceError::TamperedEvidence)?;
        validate_row_shape(page.schema.as_ref(), &page.rows)?;
        if page.job.reference != initial_job.reference {
            return Err(BigQueryServiceError::LocationMismatch);
        }
        if page.job.query_digest != request.query_digest {
            return Err(BigQueryServiceError::QueryDrift);
        }
        if page.job.config_digest != request.config_digest {
            return Err(BigQueryServiceError::ConfigDrift);
        }
        validate_job_and_fence(
            &JobsQueryRequest {
                project_id: page.job.reference.project_id.clone(),
                location: request.location.clone(),
                mission_id: self.scope.mission_id().clone(),
                work_product_id: self.scope.work_product_id().clone(),
                work_product_revision: request.work_product_revision,
                scope_digest: request.scope_digest.clone(),
                query_digest: request.query_digest.clone(),
                config_digest: request.config_digest.clone(),
                mode: crate::QueryMode::BoundedReadProposal,
                bounds: request.bounds,
                secret_reference_digest: self.secret_reference.reference_digest().clone(),
                credential_revision: request.credential_revision,
                permission_digest: request.permission_digest.clone(),
                consent_digest: request.consent_digest.clone(),
                auth_kind: self.secret_reference.auth_kind(),
            },
            &page.job,
            &page.observed_scope_digest,
            &page.observed_permission_digest,
            &page.observed_consent_digest,
            page.observed_work_product_revision,
            page.observed_credential_revision,
        )?;
        Ok(())
    }
}

struct CallFailure {
    error: TransportError,
}

fn validate_job_and_fence(
    request: &JobsQueryRequest,
    job: &JobMetadata,
    observed_scope_digest: &Digest,
    observed_permission_digest: &Digest,
    observed_consent_digest: &Digest,
    observed_work_product_revision: Revision,
    observed_credential_revision: Revision,
) -> Result<(), BigQueryServiceError> {
    if job.reference.project_id != request.project_id || job.reference.location != request.location
    {
        return Err(BigQueryServiceError::LocationMismatch);
    }
    if job.query_digest != request.query_digest {
        return Err(BigQueryServiceError::QueryDrift);
    }
    if job.config_digest != request.config_digest {
        return Err(BigQueryServiceError::ConfigDrift);
    }
    if job.scope_digest != request.scope_digest
        || observed_scope_digest != &request.scope_digest
        || job.permission_digest != request.permission_digest
        || observed_permission_digest != &request.permission_digest
        || observed_consent_digest != &request.consent_digest
        || observed_work_product_revision != request.work_product_revision
        || job.credential_revision != request.credential_revision
        || observed_credential_revision != request.credential_revision
    {
        return Err(BigQueryServiceError::FenceViolation);
    }
    Ok(())
}

fn projection_for_provider_error(error: &TransportError) -> ResultProjection {
    match error.kind {
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
            ResultProjection::AccessLost
        }
        ProviderErrorKind::NotFound => ResultProjection::Expired,
        ProviderErrorKind::BadRequest
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::Tampered
        | ProviderErrorKind::Truncated => ResultProjection::FinalError,
        ProviderErrorKind::Quota
        | ProviderErrorKind::RateLimited
        | ProviderErrorKind::ServerFailure
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::LocationMismatch
        | ProviderErrorKind::QueryDrift
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::Unknown => ResultProjection::ProviderUnknown,
    }
}

fn projection_from_query_errors(errors: &[QueryErrorEvidence]) -> ResultProjection {
    if errors
        .iter()
        .any(|error| error.severity == crate::ErrorSeverity::Final)
    {
        ResultProjection::FinalError
    } else if errors.is_empty() {
        ResultProjection::Complete
    } else {
        ResultProjection::Partial(PartialReason::Warning)
    }
}

fn projection_from_job(job: &JobMetadata, errors: &[QueryErrorEvidence]) -> ResultProjection {
    match job.state {
        JobState::Expired => ResultProjection::Expired,
        JobState::Unknown => ResultProjection::ProviderUnknown,
        _ if job.expired => ResultProjection::Expired,
        _ => projection_from_query_errors(errors),
    }
}

fn validate_row_shape(
    schema: Option<&QuerySchema>,
    rows: &[BoundedRow],
) -> Result<(), BigQueryServiceError> {
    if let Some(schema) = schema
        && rows
            .iter()
            .any(|row| row.cells.len() != schema.fields.len())
    {
        return Err(BigQueryServiceError::InvalidResponseShape);
    }
    Ok(())
}

struct EvidenceAccumulator {
    query_digest: Digest,
    config_digest: Digest,
    fence: PermissionFence,
    provider_provenance: ProviderProvenance,
    bounds: ResultBounds,
    job: Option<JobMetadata>,
    schema: Option<QuerySchema>,
    rows: Vec<BoundedRow>,
    total_rows: Option<u64>,
    bytes_processed: u64,
    cache_hit: Option<bool>,
    pages_observed: u8,
    page_token_digests: Vec<Digest>,
    warnings: Vec<QueryErrorEvidence>,
    errors: Vec<QueryErrorEvidence>,
    provider_errors: Vec<ProviderErrorEvidence>,
    retries: Vec<RetryEvidence>,
    row_bound_exceeded: bool,
    byte_bound_exceeded: bool,
}

impl EvidenceAccumulator {
    fn new(
        query: &BigQueryQueryProposal,
        fence: PermissionFence,
        provider_provenance: ProviderProvenance,
        retry_policy: RetryPolicy,
    ) -> Self {
        let _ = retry_policy;
        Self {
            query_digest: query.query_digest().clone(),
            config_digest: query.config_digest().clone(),
            fence,
            provider_provenance,
            bounds: query.bounds(),
            job: None,
            schema: None,
            rows: Vec::new(),
            total_rows: None,
            bytes_processed: 0,
            cache_hit: None,
            pages_observed: 0,
            page_token_digests: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            provider_errors: Vec::new(),
            retries: Vec::new(),
            row_bound_exceeded: false,
            byte_bound_exceeded: false,
        }
    }

    fn record_token(&mut self, token: &OpaquePageToken) {
        self.page_token_digests.push(token.digest());
    }

    fn record_retry(&mut self, operation: &str, attempt: u8, error: &TransportError) {
        self.retries.push(RetryEvidence {
            operation: operation.to_owned(),
            attempt,
            kind: error.kind,
            status_code: error.status_code,
            error_digest: error.diagnostic_digest().clone(),
        });
    }

    fn record_provider_error(&mut self, error: &TransportError, attempt: u8) {
        self.provider_errors.push(ProviderErrorEvidence::new(
            error.kind,
            error.status_code,
            error.retryable,
            attempt,
            error.blocked_env,
            error.diagnostic_digest(),
        ));
    }

    fn add_query_response(
        &mut self,
        response: &JobsQueryResponse,
        mode: crate::QueryMode,
    ) -> Result<(), BigQueryServiceError> {
        if mode == crate::QueryMode::DryRun && !response.rows.is_empty() {
            return Err(BigQueryServiceError::DryRunRows);
        }
        self.add_metadata(
            &response.job,
            response.schema.as_ref(),
            response.total_rows,
            response.total_bytes_processed,
            response.cache_hit,
            &response.errors,
        )?;
        self.add_rows(&response.rows);
        self.pages_observed = 1;
        Ok(())
    }

    fn add_result_page(&mut self, page: &QueryResultPage) -> Result<(), BigQueryServiceError> {
        if let Some(existing) = &self.schema
            && let Some(incoming) = &page.schema
            && existing.schema_digest != incoming.schema_digest
        {
            return Err(BigQueryServiceError::SchemaDrift);
        }
        self.add_metadata(
            &page.job,
            page.schema.as_ref(),
            page.total_rows,
            page.total_bytes_processed,
            page.cache_hit,
            &page.errors,
        )?;
        self.add_rows(&page.rows);
        self.pages_observed = self.pages_observed.saturating_add(1);
        Ok(())
    }

    fn add_metadata(
        &mut self,
        job: &JobMetadata,
        schema: Option<&QuerySchema>,
        total_rows: Option<u64>,
        bytes_processed: u64,
        cache_hit: Option<bool>,
        errors: &[QueryErrorEvidence],
    ) -> Result<(), BigQueryServiceError> {
        if self.job.is_none() {
            self.job = Some(job.clone());
        }
        if let Some(incoming) = schema {
            if let Some(existing) = &self.schema {
                if existing.schema_digest != incoming.schema_digest {
                    return Err(BigQueryServiceError::SchemaDrift);
                }
            } else {
                self.schema = Some(incoming.clone());
            }
        }
        self.total_rows = total_rows.or(self.total_rows);
        self.bytes_processed = self.bytes_processed.max(bytes_processed);
        if bytes_processed > self.bounds.max_bytes() {
            self.byte_bound_exceeded = true;
        }
        self.cache_hit = cache_hit.or(self.cache_hit);
        self.warnings.extend(
            errors
                .iter()
                .filter(|error| error.severity == crate::ErrorSeverity::Warning)
                .cloned(),
        );
        self.errors.extend(
            errors
                .iter()
                .filter(|error| error.severity == crate::ErrorSeverity::Final)
                .cloned(),
        );
        Ok(())
    }

    fn add_rows(&mut self, rows: &[BoundedRow]) {
        let remaining = self
            .bounds
            .max_rows()
            .saturating_sub(self.rows.len() as u32) as usize;
        if rows.len() > remaining {
            self.row_bound_exceeded = true;
        }
        self.rows.extend(rows.iter().take(remaining).cloned());
    }

    fn row_bound_exceeded(&self) -> bool {
        self.row_bound_exceeded
    }

    fn byte_bound_exceeded(&self) -> bool {
        self.byte_bound_exceeded
    }

    fn finish(self, projection: ResultProjection) -> ResultEvidence {
        let schema_digest = self.schema.as_ref().map_or_else(
            || Digest::from_text("schema-absent"),
            |schema| schema.schema_digest.clone(),
        );
        let job_digest = self.job.as_ref().map_or_else(
            || Digest::from_text("job-absent"),
            |job| job.job_digest.clone(),
        );
        let row_set_digest = Digest::from_fields(
            "bigquery-result-row-set/v1",
            &self
                .rows
                .iter()
                .enumerate()
                .map(|(index, row)| format!("{index}:{}", row.row_digest.as_str()))
                .collect::<Vec<_>>(),
        );
        let page_token_digest = Digest::from_fields(
            "bigquery-result-page-tokens/v1",
            &self
                .page_token_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let query_error_digest = Digest::from_fields(
            "bigquery-result-query-errors/v1",
            &self
                .warnings
                .iter()
                .chain(self.errors.iter())
                .map(|error| error.error_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let provider_error_digest = Digest::from_fields(
            "bigquery-result-provider-errors/v1",
            &self
                .provider_errors
                .iter()
                .map(|error| error.error_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let retry_digest = Digest::from_fields(
            "bigquery-result-retries/v1",
            &self
                .retries
                .iter()
                .map(|retry| {
                    format!(
                        "{}:{}:{:?}:{}:{}",
                        retry.operation,
                        retry.attempt,
                        retry.kind,
                        retry.status_code.map_or(0, u16::from),
                        retry.error_digest.as_str()
                    )
                })
                .collect::<Vec<_>>(),
        );
        let result_digest = Digest::from_fields(
            "bigquery-result-evidence/v1",
            &[
                self.query_digest.as_str().to_owned(),
                self.config_digest.as_str().to_owned(),
                schema_digest.as_str().to_owned(),
                row_set_digest.as_str().to_owned(),
                job_digest.as_str().to_owned(),
                format!("{:?}", projection.status()),
                format!("{projection:?}"),
                self.fence.scope_digest.as_str().to_owned(),
                self.fence.permission_digest.as_str().to_owned(),
                self.fence.consent_digest.as_str().to_owned(),
                self.fence.work_product_revision.get().to_string(),
                self.total_rows
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                self.bytes_processed.to_string(),
                self.cache_hit
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                self.rows.len().to_string(),
                self.pages_observed.to_string(),
                page_token_digest.as_str().to_owned(),
                query_error_digest.as_str().to_owned(),
                provider_error_digest.as_str().to_owned(),
                retry_digest.as_str().to_owned(),
                self.row_bound_exceeded.to_string(),
                self.byte_bound_exceeded.to_string(),
                format!("{:?}", self.provider_provenance),
            ],
        );
        ResultEvidence {
            status: projection.status(),
            scope_digest: self.fence.scope_digest,
            permission_digest: self.fence.permission_digest,
            consent_digest: self.fence.consent_digest,
            work_product_revision: self.fence.work_product_revision,
            job: self.job,
            schema: self.schema,
            rows: self.rows,
            total_rows: self.total_rows,
            bytes_processed: self.bytes_processed,
            cache_hit: self.cache_hit,
            pages_observed: self.pages_observed,
            page_token_digests: self.page_token_digests,
            warnings: self.warnings,
            errors: self.errors,
            provider_errors: self.provider_errors,
            retries: self.retries,
            row_bound_exceeded: self.row_bound_exceeded,
            byte_bound_exceeded: self.byte_bound_exceeded,
            digests: EvidenceDigests {
                query_digest: self.query_digest,
                config_digest: self.config_digest,
                schema_digest,
                row_set_digest,
                job_digest,
                result_digest,
            },
            provider_provenance: self.provider_provenance,
            authority: AnalyticalResultAuthority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        }
    }
}

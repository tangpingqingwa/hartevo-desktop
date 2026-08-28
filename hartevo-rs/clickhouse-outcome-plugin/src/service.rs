use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    CLICKHOUSE_OUTCOME_CONSUMER_ID, CLICKHOUSE_OUTCOME_CONTRACT_VERSION,
    CLICKHOUSE_OUTCOME_PROVIDER_ID, CLICKHOUSE_OUTCOME_SCHEMA_VERSION,
    CLICKHOUSE_OUTCOME_SERVICE_ID,
    model::{
        AdoptionAvailability, AnalyticalResultAuthority, BoundedRow, ClickHouseRegistration,
        ClickHouseScope, Digest, ErrorSeverity, EvidenceDigests, ModelError, PermissionFence,
        ProviderErrorEvidence, ProviderErrorKind, ProviderId, QueryErrorEvidence, QueryId,
        QueryMode, QueryProgress, QuerySchema, QueryStatistics, QueryStatus, QuerySummary,
        RegistrationRevocation, ResultBounds, ResultStatus, Revision, SecretReference, ServiceId,
    },
    provider::{
        ClickHouseProvider, ClickHouseProviderDefinition, ClickHouseQueryRequest,
        ClickHouseQueryResponse, ProviderDefinitionError, ProviderProvenance, TransportError,
    },
    query::{ClickHouseQueryProposal, QueryCompileError, QueryProposalRequest},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ClickHouseServiceError {
    #[error("ClickHouse registration is revoked")]
    RegistrationRevoked,
    #[error("ClickHouse SecretReference is revoked")]
    SecretRevoked,
    #[error("ClickHouse provider or service scope does not match")]
    ScopeMismatch,
    #[error("provider evidence was tampered with or its digest is stale")]
    TamperedEvidence,
    #[error("provider returned a different query digest")]
    QueryDrift,
    #[error("provider returned a different query configuration digest")]
    ConfigDrift,
    #[error("provider permission, consent, scope, or revision fence changed")]
    FenceViolation,
    #[error("provider schema or schema revision changed")]
    SchemaDrift,
    #[error("provider query identifier was duplicated or replayed")]
    DuplicateOrReplay,
    #[error("provider returned an invalid row/schema/statistics shape")]
    InvalidResponseShape,
    #[error("provider returned rows for a dry-run proposal")]
    DryRunRows,
    #[error("provider definition is invalid")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("provider definition no longer matches its registration")]
    ProviderRegistrationMismatch,
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
    ProviderPending,
    ProviderPartial,
    Timeout,
    Cancelled,
    Warning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProjection {
    Complete,
    Partial(PartialReason),
    Truncated,
    Cancelled,
    AccessLost,
    ProviderUnknown,
    FinalError,
}

impl ResultProjection {
    pub const fn status(self) -> ResultStatus {
        match self {
            Self::Complete => ResultStatus::Complete,
            Self::Partial(_) => ResultStatus::Partial,
            Self::Truncated => ResultStatus::Truncated,
            Self::Cancelled => ResultStatus::Cancelled,
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
    pub query_id: Option<QueryId>,
    pub schema: Option<QuerySchema>,
    pub rows: Vec<BoundedRow>,
    pub progress: Vec<QueryProgress>,
    pub statistics: QueryStatistics,
    pub summary: QuerySummary,
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

impl ResultEvidence {
    pub fn validate_digests(
        &self,
        expected_query_digest: &Digest,
        expected_registration_digest: &Digest,
    ) -> Result<(), ClickHouseServiceError> {
        if self.digests.query_digest != *expected_query_digest
            || self.digests.registration_digest != *expected_registration_digest
        {
            return Err(ClickHouseServiceError::TamperedEvidence);
        }
        if let Some(schema) = &self.schema {
            schema.validate_digest()?;
        }
        for row in &self.rows {
            row.validate_digest()?;
        }
        for progress in &self.progress {
            progress.validate_digest()?;
        }
        self.statistics.validate()?;
        self.summary.validate_against(&self.statistics)?;
        let expected = evidence_digests(
            self.status,
            self.scope_digest.clone(),
            self.permission_digest.clone(),
            self.consent_digest.clone(),
            self.work_product_revision,
            expected_query_digest.clone(),
            self.query_id.as_ref(),
            self.schema.as_ref(),
            &self.rows,
            &self.progress,
            &self.statistics,
            &self.summary,
            &self.warnings,
            &self.errors,
            &self.provider_errors,
            &self.retries,
            self.row_bound_exceeded,
            self.byte_bound_exceeded,
            expected_registration_digest.clone(),
            self.provider_provenance,
        );
        if expected.schema_digest != self.digests.schema_digest
            || expected.row_set_digest != self.digests.row_set_digest
            || expected.statistics_digest != self.digests.statistics_digest
            || expected.result_digest != self.digests.result_digest
        {
            return Err(ClickHouseServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClickHouseResultProposal {
    pub query: ClickHouseQueryProposal,
    pub projection: ResultProjection,
    pub evidence: ResultEvidence,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl ClickHouseResultProposal {
    pub fn status(&self) -> ResultStatus {
        self.projection.status()
    }

    pub fn is_adopted(&self) -> bool {
        false
    }

    pub fn authority(&self) -> AnalyticalResultAuthority {
        self.evidence.authority
    }

    pub fn validate_digests(&self) -> Result<(), ClickHouseServiceError> {
        if self.evidence.status != self.projection.status()
            || self.evidence.rows.len() > self.query.bounds().max_rows() as usize
            || self
                .evidence
                .rows
                .iter()
                .map(BoundedRow::encoded_bytes)
                .sum::<u64>()
                > self.query.bounds().max_bytes()
        {
            return Err(ClickHouseServiceError::TamperedEvidence);
        }
        self.evidence.validate_digests(
            &self.query.query_digest().clone(),
            &self.registration_digest,
        )?;
        let expected = Digest::from_fields(
            "clickhouse-result-proposal/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                self.provider_definition_digest.as_str().to_owned(),
                self.query.scope_digest().as_str().to_owned(),
                self.query.query_digest().as_str().to_owned(),
                self.query.config_digest().as_str().to_owned(),
                format!("{:?}", self.projection),
                self.evidence.digests.result_digest.as_str().to_owned(),
            ],
        );
        (expected == self.proposal_digest)
            .then_some(())
            .ok_or(ClickHouseServiceError::TamperedEvidence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClickHouseServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: crate::model::ConsumerId,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_outcome: bool,
}

impl ClickHouseServiceDefinition {
    pub fn new() -> Self {
        Self {
            schema_version: CLICKHOUSE_OUTCOME_SCHEMA_VERSION.to_owned(),
            contract_version: CLICKHOUSE_OUTCOME_CONTRACT_VERSION.to_owned(),
            service_id: ServiceId::new(CLICKHOUSE_OUTCOME_SERVICE_ID)
                .expect("contract service identifier"),
            provider_id: ProviderId::new(CLICKHOUSE_OUTCOME_PROVIDER_ID)
                .expect("contract provider identifier"),
            consumer_id: crate::model::ConsumerId::new(CLICKHOUSE_OUTCOME_CONSUMER_ID)
                .expect("contract consumer identifier"),
            contract_digest: Digest::from_text(crate::CLICKHOUSE_OUTCOME_CONTRACT_JSON),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
        }
    }
}

impl Default for ClickHouseServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ClickHouseOutcomeService<P> {
    scope: ClickHouseScope,
    secret_reference: SecretReference,
    provider: P,
    service_definition: ClickHouseServiceDefinition,
    registration: ClickHouseRegistration,
    retry_policy: RetryPolicy,
    seen_query_ids: BTreeSet<Digest>,
    seen_proposals: BTreeSet<Digest>,
}

pub type ClickHouseResultService<P> = ClickHouseOutcomeService<P>;

impl<P: ClickHouseProvider> fmt::Debug for ClickHouseOutcomeService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClickHouseOutcomeService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .field("seen_query_count", &self.seen_query_ids.len())
            .field("seen_proposal_count", &self.seen_proposals.len())
            .finish_non_exhaustive()
    }
}

impl<P: ClickHouseProvider> ClickHouseOutcomeService<P> {
    pub fn new(
        scope: ClickHouseScope,
        secret_reference: SecretReference,
        provider: P,
        retry_policy: RetryPolicy,
    ) -> Result<Self, ClickHouseServiceError> {
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(ClickHouseServiceError::ScopeMismatch);
        }
        let service_definition = ClickHouseServiceDefinition::new();
        let provider_definition = provider.definition();
        if !provider_definition_matches_contract(provider_definition) {
            return Err(ClickHouseServiceError::ScopeMismatch);
        }
        let provider_id = ProviderId::new(provider_definition.provider_id.clone())?;
        let registration = ClickHouseRegistration::new_with_permission(
            scope.scope_digest(),
            scope.permission_digest().clone(),
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
            seen_query_ids: BTreeSet::new(),
            seen_proposals: BTreeSet::new(),
        })
    }

    pub fn service_definition(&self) -> &ClickHouseServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &ClickHouseProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &ClickHouseRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &ClickHouseScope {
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
    ) -> Result<RegistrationRevocation, ClickHouseServiceError> {
        self.registration
            .revoke()
            .map_err(ClickHouseServiceError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), ClickHouseServiceError> {
        self.secret_reference
            .revoke()
            .map_err(ClickHouseServiceError::from)
    }

    pub fn propose(
        &mut self,
        request: QueryProposalRequest,
    ) -> Result<ClickHouseResultProposal, ClickHouseServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| ClickHouseServiceError::RegistrationRevoked)?;
        if !provider_definition_matches_registration(self.provider.definition(), &self.registration)
        {
            return Err(ClickHouseServiceError::ProviderRegistrationMismatch);
        }
        if self.secret_reference.is_revoked() {
            return Err(ClickHouseServiceError::SecretRevoked);
        }
        let query = ClickHouseQueryProposal::compile(&self.scope, &self.secret_reference, request)?;
        let provider_request =
            ClickHouseQueryRequest::from_proposal(&self.scope, &self.secret_reference, &query);
        let provider_definition_digest = self.provider.definition().provider_digest();
        let mut accumulator = EvidenceAccumulator::new(
            &query,
            self.scope.fence(),
            self.provider.provenance(),
            self.registration.registration_digest.clone(),
        );
        let response = match self.query_with_retry(&provider_request, &mut accumulator) {
            Ok(response) => response,
            Err(error) => {
                let projection = projection_for_transport_error(&error);
                let evidence = accumulator.finish(projection);
                return Ok(self.finish_proposal(
                    query,
                    projection,
                    evidence,
                    provider_definition_digest,
                ));
            }
        };
        validate_response(&provider_request, &response, &self.scope)?;
        let replay_key = Digest::from_fields(
            "clickhouse-proposal-replay/v1",
            &[
                self.registration.registration_digest.as_str().to_owned(),
                query.scope_digest().as_str().to_owned(),
                query.query_digest().as_str().to_owned(),
                query.config_digest().as_str().to_owned(),
            ],
        );
        if !self.seen_proposals.insert(replay_key) {
            return Err(ClickHouseServiceError::DuplicateOrReplay);
        }
        if !self.seen_query_ids.insert(response.query_id.digest()) {
            return Err(ClickHouseServiceError::DuplicateOrReplay);
        }
        if query.mode() == QueryMode::DryRun && !response.rows.is_empty() {
            return Err(ClickHouseServiceError::DryRunRows);
        }
        accumulator.add_response(&response)?;
        let mut projection = projection_from_response(&response);
        if response
            .errors
            .iter()
            .any(|error| error.severity == ErrorSeverity::Final)
        {
            projection = ResultProjection::FinalError;
        } else if projection == ResultProjection::Complete
            && (accumulator.row_bound_exceeded || accumulator.byte_bound_exceeded)
        {
            projection = ResultProjection::Truncated;
        }
        let evidence = accumulator.finish(projection);
        Ok(self.finish_proposal(query, projection, evidence, provider_definition_digest))
    }

    fn query_with_retry(
        &mut self,
        request: &ClickHouseQueryRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<ClickHouseQueryResponse, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.provider.query(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    accumulator.record_retry("query", attempt, &error);
                }
                Err(error) => {
                    accumulator.record_provider_error(&error, attempt);
                    return Err(error);
                }
            }
        }
        unreachable!("retry loop always returns")
    }

    fn finish_proposal(
        &self,
        query: ClickHouseQueryProposal,
        projection: ResultProjection,
        evidence: ResultEvidence,
        provider_definition_digest: Digest,
    ) -> ClickHouseResultProposal {
        let proposal_digest = Digest::from_fields(
            "clickhouse-result-proposal/v1",
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
        ClickHouseResultProposal {
            query,
            projection,
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_definition_digest,
            proposal_digest,
        }
    }
}

fn provider_definition_matches_contract(definition: &ClickHouseProviderDefinition) -> bool {
    definition.schema_version == CLICKHOUSE_OUTCOME_SCHEMA_VERSION
        && definition.provider_id == CLICKHOUSE_OUTCOME_PROVIDER_ID
        && definition.query
        && definition.explain_select
        && definition.https_only
        && !definition.live_execution
        && !definition.native
}

fn provider_definition_matches_registration(
    definition: &ClickHouseProviderDefinition,
    registration: &ClickHouseRegistration,
) -> bool {
    provider_definition_matches_contract(definition)
        && registration.provider_id.as_str() == definition.provider_id
        && registration.provider_version == definition.provider_version
        && registration.capability_digest == definition.capability_digest
}

fn validate_response(
    request: &ClickHouseQueryRequest,
    response: &ClickHouseQueryResponse,
    scope: &ClickHouseScope,
) -> Result<(), ClickHouseServiceError> {
    response
        .validate_digest()
        .map_err(|_| ClickHouseServiceError::TamperedEvidence)?;
    if response.observed_query_digest != request.query_digest {
        return Err(ClickHouseServiceError::QueryDrift);
    }
    if response.observed_config_digest != request.config_digest {
        return Err(ClickHouseServiceError::ConfigDrift);
    }
    if response.observed_scope_digest != request.scope_digest
        || response.observed_permission_digest != request.permission_digest
        || response.observed_consent_digest != request.consent_digest
        || response.observed_work_product_revision != request.work_product_revision
        || response.observed_credential_revision != request.credential_revision
    {
        return Err(ClickHouseServiceError::FenceViolation);
    }
    if let Some(schema) = &response.schema {
        if schema.schema_revision != scope.schema_revision() {
            return Err(ClickHouseServiceError::SchemaDrift);
        }
        for row in &response.rows {
            if row.cells.len() != schema.fields.len() {
                return Err(ClickHouseServiceError::InvalidResponseShape);
            }
            for (cell, field) in row.cells.iter().zip(&schema.fields) {
                if (cell.cell_type == crate::model::CellType::Null && !field.nullable)
                    || (cell.cell_type != crate::model::CellType::Null
                        && cell.cell_type != field.cell_type)
                {
                    return Err(ClickHouseServiceError::InvalidResponseShape);
                }
            }
        }
    } else if !response.rows.is_empty() {
        return Err(ClickHouseServiceError::InvalidResponseShape);
    }
    if response.progress.len() > crate::model::MAX_PROGRESS_EVENTS as usize {
        return Err(ClickHouseServiceError::InvalidResponseShape);
    }
    let mut prior_progress = (0_u64, 0_u64, 0_u64);
    for progress in &response.progress {
        if progress.read_rows < prior_progress.0
            || progress.read_bytes < prior_progress.1
            || progress.elapsed_ns < prior_progress.2
            || progress
                .total_rows_to_read
                .is_some_and(|total| total < progress.read_rows)
        {
            return Err(ClickHouseServiceError::InvalidResponseShape);
        }
        prior_progress = (progress.read_rows, progress.read_bytes, progress.elapsed_ns);
    }
    if response.statistics.result_rows < response.rows.len() as u64
        || response.statistics.result_bytes
            < response.rows.iter().map(BoundedRow::encoded_bytes).sum()
    {
        return Err(ClickHouseServiceError::InvalidResponseShape);
    }
    Ok(())
}

fn projection_for_transport_error(error: &TransportError) -> ResultProjection {
    match error.kind {
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
            ResultProjection::AccessLost
        }
        ProviderErrorKind::Cancelled => ResultProjection::Cancelled,
        ProviderErrorKind::BadRequest
        | ProviderErrorKind::Duplicate
        | ProviderErrorKind::Replay
        | ProviderErrorKind::Malformed
        | ProviderErrorKind::Tampered
        | ProviderErrorKind::QueryDrift
        | ProviderErrorKind::SchemaDrift => ResultProjection::FinalError,
        ProviderErrorKind::RateLimited
        | ProviderErrorKind::ServerFailure
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::NotFound
        | ProviderErrorKind::Truncated
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::Unknown => ResultProjection::ProviderUnknown,
    }
}

fn projection_from_response(response: &ClickHouseQueryResponse) -> ResultProjection {
    match response.status {
        QueryStatus::Complete => {
            if response
                .errors
                .iter()
                .any(|error| error.severity == ErrorSeverity::Warning)
            {
                ResultProjection::Partial(PartialReason::Warning)
            } else {
                ResultProjection::Complete
            }
        }
        QueryStatus::Pending | QueryStatus::Running => {
            ResultProjection::Partial(PartialReason::ProviderPending)
        }
        QueryStatus::Partial => ResultProjection::Partial(PartialReason::ProviderPartial),
        QueryStatus::Truncated => ResultProjection::Truncated,
        QueryStatus::Timeout => ResultProjection::Partial(PartialReason::Timeout),
        QueryStatus::Cancelled => ResultProjection::Cancelled,
        QueryStatus::Failed => ResultProjection::FinalError,
        QueryStatus::ProviderUnknown => ResultProjection::ProviderUnknown,
    }
}

struct EvidenceAccumulator {
    query_digest: Digest,
    fence: PermissionFence,
    provider_provenance: ProviderProvenance,
    registration_digest: Digest,
    bounds: ResultBounds,
    query_id: Option<QueryId>,
    schema: Option<QuerySchema>,
    rows: Vec<BoundedRow>,
    progress: Vec<QueryProgress>,
    statistics: QueryStatistics,
    summary: QuerySummary,
    warnings: Vec<QueryErrorEvidence>,
    errors: Vec<QueryErrorEvidence>,
    provider_errors: Vec<ProviderErrorEvidence>,
    retries: Vec<RetryEvidence>,
    row_bound_exceeded: bool,
    byte_bound_exceeded: bool,
}

impl EvidenceAccumulator {
    fn new(
        query: &ClickHouseQueryProposal,
        fence: PermissionFence,
        provider_provenance: ProviderProvenance,
        registration_digest: Digest,
    ) -> Self {
        let statistics = QueryStatistics::new(0, 0, 0, 0, 0, 0);
        Self {
            query_digest: query.query_digest().clone(),
            fence,
            provider_provenance,
            registration_digest,
            bounds: query.bounds(),
            query_id: None,
            schema: None,
            rows: Vec::new(),
            progress: Vec::new(),
            summary: QuerySummary::new(&statistics),
            statistics,
            warnings: Vec::new(),
            errors: Vec::new(),
            provider_errors: Vec::new(),
            retries: Vec::new(),
            row_bound_exceeded: false,
            byte_bound_exceeded: false,
        }
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

    fn add_response(
        &mut self,
        response: &ClickHouseQueryResponse,
    ) -> Result<(), ClickHouseServiceError> {
        self.query_id = Some(response.query_id.clone());
        self.schema.clone_from(&response.schema);
        self.progress.clone_from(&response.progress);
        self.statistics = response.statistics.clone();
        self.summary = response.summary.clone();
        self.warnings.extend(
            response
                .errors
                .iter()
                .filter(|error| error.severity == ErrorSeverity::Warning)
                .cloned(),
        );
        self.errors.extend(
            response
                .errors
                .iter()
                .filter(|error| error.severity == ErrorSeverity::Final)
                .cloned(),
        );
        let mut encoded_bytes = 0_u64;
        for row in &response.rows {
            if self.rows.len() >= self.bounds.max_rows() as usize {
                self.row_bound_exceeded = true;
                break;
            }
            let row_bytes = row.encoded_bytes();
            if encoded_bytes.saturating_add(row_bytes) > self.bounds.max_bytes() {
                self.byte_bound_exceeded = true;
                break;
            }
            encoded_bytes = encoded_bytes.saturating_add(row_bytes);
            self.rows.push(row.clone());
        }
        if response.rows.len() > self.rows.len()
            && !self.row_bound_exceeded
            && !self.byte_bound_exceeded
        {
            self.byte_bound_exceeded = true;
        }
        if response.statistics.result_rows > u64::from(self.bounds.max_rows()) {
            self.row_bound_exceeded = true;
        }
        if response.statistics.result_bytes > self.bounds.max_bytes() {
            self.byte_bound_exceeded = true;
        }
        Ok(())
    }

    fn finish(self, projection: ResultProjection) -> ResultEvidence {
        let digests = evidence_digests(
            projection.status(),
            self.fence.scope_digest.clone(),
            self.fence.permission_digest.clone(),
            self.fence.consent_digest.clone(),
            self.fence.work_product_revision,
            self.query_digest,
            self.query_id.as_ref(),
            self.schema.as_ref(),
            &self.rows,
            &self.progress,
            &self.statistics,
            &self.summary,
            &self.warnings,
            &self.errors,
            &self.provider_errors,
            &self.retries,
            self.row_bound_exceeded,
            self.byte_bound_exceeded,
            self.registration_digest,
            self.provider_provenance,
        );
        ResultEvidence {
            status: projection.status(),
            scope_digest: self.fence.scope_digest,
            permission_digest: self.fence.permission_digest,
            consent_digest: self.fence.consent_digest,
            work_product_revision: self.fence.work_product_revision,
            query_id: self.query_id,
            schema: self.schema,
            rows: self.rows,
            progress: self.progress,
            statistics: self.statistics,
            summary: self.summary,
            warnings: self.warnings,
            errors: self.errors,
            provider_errors: self.provider_errors,
            retries: self.retries,
            row_bound_exceeded: self.row_bound_exceeded,
            byte_bound_exceeded: self.byte_bound_exceeded,
            digests,
            provider_provenance: self.provider_provenance,
            authority: AnalyticalResultAuthority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence_digests(
    status: ResultStatus,
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    work_product_revision: Revision,
    query_digest: Digest,
    query_id: Option<&QueryId>,
    schema: Option<&QuerySchema>,
    rows: &[BoundedRow],
    progress: &[QueryProgress],
    statistics: &QueryStatistics,
    summary: &QuerySummary,
    warnings: &[QueryErrorEvidence],
    errors: &[QueryErrorEvidence],
    provider_errors: &[ProviderErrorEvidence],
    retries: &[RetryEvidence],
    row_bound_exceeded: bool,
    byte_bound_exceeded: bool,
    registration_digest: Digest,
    provider_provenance: ProviderProvenance,
) -> EvidenceDigests {
    let schema_digest = schema.map_or_else(
        || Digest::from_text("schema-absent"),
        |schema| schema.schema_digest.clone(),
    );
    let row_set_digest = Digest::from_fields(
        "clickhouse-result-row-set/v1",
        &rows
            .iter()
            .enumerate()
            .map(|(index, row)| format!("{index}:{}", row.row_digest.as_str()))
            .collect::<Vec<_>>(),
    );
    let statistics_digest = Digest::from_fields(
        "clickhouse-result-statistics/v1",
        &[
            statistics.statistics_digest.as_str().to_owned(),
            summary.summary_digest.as_str().to_owned(),
            progress
                .iter()
                .map(|item| item.progress_digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
        ],
    );
    let error_digest = Digest::from_fields(
        "clickhouse-result-errors/v1",
        &warnings
            .iter()
            .chain(errors.iter())
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
    let provider_error_digest = Digest::from_fields(
        "clickhouse-result-provider-errors/v1",
        &provider_errors
            .iter()
            .map(|error| {
                format!(
                    "{:?}:{}:{}:{}:{}:{}",
                    error.kind,
                    error.status_code.map_or(0, u16::from),
                    error.retryable,
                    error.attempt,
                    error.blocked_env,
                    error.error_digest.as_str()
                )
            })
            .collect::<Vec<_>>(),
    );
    let retry_digest = Digest::from_fields(
        "clickhouse-result-retries/v1",
        &retries
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
        "clickhouse-result-evidence/v1",
        &[
            query_id.map_or_else(|| "none".to_owned(), |id| id.digest().as_str().to_owned()),
            format!("{status:?}"),
            schema_digest.as_str().to_owned(),
            row_set_digest.as_str().to_owned(),
            statistics_digest.as_str().to_owned(),
            registration_digest.as_str().to_owned(),
            scope_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
            consent_digest.as_str().to_owned(),
            work_product_revision.get().to_string(),
            error_digest.as_str().to_owned(),
            provider_error_digest.as_str().to_owned(),
            retry_digest.as_str().to_owned(),
            row_bound_exceeded.to_string(),
            byte_bound_exceeded.to_string(),
            format!("{provider_provenance:?}"),
        ],
    );
    EvidenceDigests {
        query_digest,
        schema_digest,
        row_set_digest,
        statistics_digest,
        registration_digest,
        result_digest,
    }
}

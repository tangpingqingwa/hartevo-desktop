use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CLICKHOUSE_OUTCOME_PROVIDER_ID, CLICKHOUSE_OUTCOME_SCHEMA_VERSION,
    model::QueryMode,
    model::{
        BoundedRow, ClickHouseScope, Digest, ModelError, PermissionFence, ProviderErrorKind,
        QueryErrorEvidence, QueryId, QueryProgress, QuerySchema, QueryStatistics, QueryStatus,
        QuerySummary, ResultBounds, Revision, SecretReference,
    },
    query::{ClickHouseQueryKind, ClickHouseQueryProposal},
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
pub struct ClickHouseProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub query: bool,
    pub explain_select: bool,
    pub https_only: bool,
    pub live_execution: bool,
    pub native: bool,
}

impl ClickHouseProviderDefinition {
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
        let capability_digest = Digest::from_fields(
            "clickhouse-provider-capability/v1",
            &[
                CLICKHOUSE_OUTCOME_SCHEMA_VERSION.to_owned(),
                CLICKHOUSE_OUTCOME_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                "query=true".to_owned(),
                "explain_select=true".to_owned(),
                "https_only=true".to_owned(),
                "live_execution=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: CLICKHOUSE_OUTCOME_SCHEMA_VERSION.to_owned(),
            provider_id: CLICKHOUSE_OUTCOME_PROVIDER_ID.to_owned(),
            provider_version,
            capability_digest,
            provenance,
            query: true,
            explain_select: true,
            https_only: true,
            live_execution: false,
            native: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "clickhouse-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.query.to_string(),
                self.explain_select.to_string(),
                self.https_only.to_string(),
                self.live_execution.to_string(),
                self.native.to_string(),
            ],
        )
    }
}

/// Transport errors are coarse by design. Diagnostic text and response bodies
/// are reduced to a digest before entering evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("ClickHouse transport returned {kind:?} (HTTP {status_code:?})")]
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
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        Self {
            kind,
            status_code,
            retryable,
            blocked_env: kind == ProviderErrorKind::BlockedEnv,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn from_http(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        let kind = match status_code {
            400 => ProviderErrorKind::BadRequest,
            401 => ProviderErrorKind::Unauthenticated,
            403 => ProviderErrorKind::PermissionDenied,
            404 => ProviderErrorKind::NotFound,
            408 | 504 => ProviderErrorKind::Timeout,
            429 => ProviderErrorKind::RateLimited,
            500..=599 => ProviderErrorKind::ServerFailure,
            _ => ProviderErrorKind::Unknown,
        };
        Self::new(kind, Some(status_code), diagnostic)
    }

    pub fn bad_request() -> Self {
        Self::from_http(400, "bad-request")
    }

    pub fn unauthenticated() -> Self {
        Self::from_http(401, "unauthenticated")
    }

    pub fn access_denied() -> Self {
        Self::from_http(403, "access-denied")
    }

    pub fn not_found() -> Self {
        Self::from_http(404, "not-found")
    }

    pub fn rate_limited() -> Self {
        Self::from_http(429, "rate-limited")
    }

    pub fn server_failure() -> Self {
        Self::from_http(500, "server-failure")
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn cancelled() -> Self {
        Self::new(ProviderErrorKind::Cancelled, None, "cancelled")
    }

    pub fn malformed() -> Self {
        Self::new(ProviderErrorKind::Malformed, None, "malformed-response")
    }

    pub fn duplicate() -> Self {
        Self::new(
            ProviderErrorKind::Duplicate,
            Some(409),
            "duplicate-query-id",
        )
    }

    pub fn replay() -> Self {
        Self::new(ProviderErrorKind::Replay, Some(409), "replayed-query-id")
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub(crate) fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

/// Secret-free request metadata. Raw SQL and parameter values never cross the
/// provider boundary; the compiled proposal is represented by its digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClickHouseQueryRequest {
    pub https_host: String,
    pub cluster: String,
    pub database: String,
    pub table: String,
    pub schema: String,
    pub schema_revision: Revision,
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub work_product_revision: Revision,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub query_kind: ClickHouseQueryKind,
    pub mode: QueryMode,
    pub bounds: ResultBounds,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

impl ClickHouseQueryRequest {
    pub(crate) fn from_proposal(
        scope: &ClickHouseScope,
        _secret: &SecretReference,
        proposal: &ClickHouseQueryProposal,
    ) -> Self {
        Self {
            https_host: scope.https_host().as_str().to_owned(),
            cluster: scope.cluster().to_owned(),
            database: scope.database().as_str().to_owned(),
            table: scope.table().as_str().to_owned(),
            schema: scope.schema().as_str().to_owned(),
            schema_revision: scope.schema_revision(),
            project_id: scope.project_id().as_str().to_owned(),
            mission_id: scope.mission_id().as_str().to_owned(),
            work_product_id: scope.work_product_id().as_str().to_owned(),
            work_product_revision: proposal.work_product_revision(),
            scope_digest: proposal.scope_digest().clone(),
            query_digest: proposal.query_digest().clone(),
            config_digest: proposal.config_digest().clone(),
            query_kind: proposal.query_kind(),
            mode: proposal.mode(),
            bounds: proposal.bounds(),
            secret_reference_digest: proposal.secret_reference_digest().clone(),
            credential_revision: proposal.credential_revision(),
            permission_digest: proposal.permission_digest().clone(),
            consent_digest: proposal.consent_digest().clone(),
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

/// A typed read-only provider seam. Implementations are limited to recording,
/// fake, loopback, and BLOCKED_ENV provenance in this Layer-1 crate.
pub trait ClickHouseProvider: fmt::Debug {
    fn definition(&self) -> &ClickHouseProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn query(
        &mut self,
        request: &ClickHouseQueryRequest,
    ) -> Result<ClickHouseQueryResponse, TransportError>;
}

pub trait ClickHouseHttpTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn query(
        &mut self,
        request: &ClickHouseQueryRequest,
    ) -> Result<ClickHouseQueryResponse, TransportError>;
}

#[derive(Debug)]
pub struct ClickHouseProviderAdapter<T> {
    transport: T,
    definition: ClickHouseProviderDefinition,
}

pub type ClickHouseHttpProvider<T> = ClickHouseProviderAdapter<T>;

impl<T: ClickHouseHttpTransport> ClickHouseProviderAdapter<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        let provenance = transport.provenance();
        Ok(Self {
            transport,
            definition: ClickHouseProviderDefinition::new(provider_version, provenance)?,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: ClickHouseHttpTransport> ClickHouseProvider for ClickHouseProviderAdapter<T> {
    fn definition(&self) -> &ClickHouseProviderDefinition {
        &self.definition
    }

    fn query(
        &mut self,
        request: &ClickHouseQueryRequest,
    ) -> Result<ClickHouseQueryResponse, TransportError> {
        self.transport.query(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClickHouseQueryResponse {
    pub query_id: QueryId,
    pub status: QueryStatus,
    pub schema: Option<QuerySchema>,
    pub rows: Vec<BoundedRow>,
    pub progress: Vec<QueryProgress>,
    pub statistics: QueryStatistics,
    pub summary: QuerySummary,
    pub errors: Vec<QueryErrorEvidence>,
    pub observed_query_digest: Digest,
    pub observed_config_digest: Digest,
    pub observed_scope_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_work_product_revision: Revision,
    pub observed_credential_revision: Revision,
    pub response_digest: Digest,
}

impl ClickHouseQueryResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        query_id: QueryId,
        status: QueryStatus,
        schema: Option<QuerySchema>,
        rows: Vec<BoundedRow>,
        progress: Vec<QueryProgress>,
        statistics: QueryStatistics,
        summary: QuerySummary,
        errors: Vec<QueryErrorEvidence>,
        query_digest: Digest,
        config_digest: Digest,
        fence: PermissionFence,
        observed_credential_revision: Revision,
    ) -> Self {
        let response_digest = compute_response_digest(
            &query_id,
            status,
            schema.as_ref(),
            &rows,
            &progress,
            &statistics,
            &summary,
            &errors,
            &query_digest,
            &config_digest,
            &fence,
            observed_credential_revision,
        );
        Self {
            query_id,
            status,
            schema,
            rows,
            progress,
            statistics,
            summary,
            errors,
            observed_query_digest: query_digest,
            observed_config_digest: config_digest,
            observed_scope_digest: fence.scope_digest,
            observed_permission_digest: fence.permission_digest,
            observed_consent_digest: fence.consent_digest,
            observed_work_product_revision: fence.work_product_revision,
            observed_credential_revision,
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.query_id.as_str().is_empty() {
            return Err(ModelError::InvalidQueryId);
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
        let expected = compute_response_digest(
            &self.query_id,
            self.status,
            self.schema.as_ref(),
            &self.rows,
            &self.progress,
            &self.statistics,
            &self.summary,
            &self.errors,
            &self.observed_query_digest,
            &self.observed_config_digest,
            &PermissionFence {
                scope_digest: self.observed_scope_digest.clone(),
                permission_digest: self.observed_permission_digest.clone(),
                consent_digest: self.observed_consent_digest.clone(),
                work_product_revision: self.observed_work_product_revision,
            },
            self.observed_credential_revision,
        );
        (expected == self.response_digest)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }
}

fn compute_response_digest(
    query_id: &QueryId,
    status: QueryStatus,
    schema: Option<&QuerySchema>,
    rows: &[BoundedRow],
    progress: &[QueryProgress],
    statistics: &QueryStatistics,
    summary: &QuerySummary,
    errors: &[QueryErrorEvidence],
    query_digest: &Digest,
    config_digest: &Digest,
    fence: &PermissionFence,
    observed_credential_revision: Revision,
) -> Digest {
    let row_set_digest = Digest::from_fields(
        "clickhouse-row-set/v1",
        &rows
            .iter()
            .enumerate()
            .map(|(index, row)| format!("{index}:{}", row.row_digest.as_str()))
            .collect::<Vec<_>>(),
    );
    let progress_digest = Digest::from_fields(
        "clickhouse-progress-set/v1",
        &progress
            .iter()
            .map(|item| item.progress_digest.as_str().to_owned())
            .collect::<Vec<_>>(),
    );
    let error_digest = Digest::from_fields(
        "clickhouse-error-set/v1",
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
        "clickhouse-query-response/v1",
        &[
            query_id.digest().as_str().to_owned(),
            format!("{status:?}"),
            schema.map_or_else(
                || "none".to_owned(),
                |value| value.schema_digest.as_str().to_owned(),
            ),
            row_set_digest.as_str().to_owned(),
            progress_digest.as_str().to_owned(),
            statistics.statistics_digest.as_str().to_owned(),
            summary.summary_digest.as_str().to_owned(),
            error_digest.as_str().to_owned(),
            query_digest.as_str().to_owned(),
            config_digest.as_str().to_owned(),
            fence.scope_digest.as_str().to_owned(),
            fence.permission_digest.as_str().to_owned(),
            fence.consent_digest.as_str().to_owned(),
            fence.work_product_revision.get().to_string(),
            observed_credential_revision.get().to_string(),
        ],
    )
}

#[derive(Debug, Default)]
pub struct RecordingClickHouseTransport {
    responses: VecDeque<Result<ClickHouseQueryResponse, TransportError>>,
    requests: Vec<ClickHouseQueryRequest>,
}

impl RecordingClickHouseTransport {
    pub fn push_response(&mut self, response: Result<ClickHouseQueryResponse, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn push_query_response(&mut self, response: ClickHouseQueryResponse) {
        self.push_response(Ok(response));
    }

    pub fn push_error(&mut self, error: TransportError) {
        self.push_response(Err(error));
    }

    pub fn requests(&self) -> &[ClickHouseQueryRequest] {
        &self.requests
    }

    pub const fn query_calls(&self) -> usize {
        self.requests.len()
    }

    fn query(
        &mut self,
        request: &ClickHouseQueryRequest,
    ) -> Result<ClickHouseQueryResponse, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }
}

impl ClickHouseHttpTransport for RecordingClickHouseTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn query(
        &mut self,
        request: &ClickHouseQueryRequest,
    ) -> Result<ClickHouseQueryResponse, TransportError> {
        self.query(request)
    }
}

#[derive(Debug, Default)]
pub struct FakeClickHouseTransport {
    inner: RecordingClickHouseTransport,
}

impl FakeClickHouseTransport {
    pub fn push_response(&mut self, response: Result<ClickHouseQueryResponse, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn push_query_response(&mut self, response: ClickHouseQueryResponse) {
        self.inner.push_query_response(response);
    }

    pub fn push_error(&mut self, error: TransportError) {
        self.inner.push_error(error);
    }

    pub fn query_calls(&self) -> usize {
        self.inner.query_calls()
    }
}

impl ClickHouseHttpTransport for FakeClickHouseTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fake
    }

    fn query(
        &mut self,
        request: &ClickHouseQueryRequest,
    ) -> Result<ClickHouseQueryResponse, TransportError> {
        self.inner.query(request)
    }
}

#[derive(Debug, Default)]
pub struct LoopbackClickHouseTransport {
    inner: RecordingClickHouseTransport,
}

impl LoopbackClickHouseTransport {
    pub fn push_response(&mut self, response: Result<ClickHouseQueryResponse, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn push_query_response(&mut self, response: ClickHouseQueryResponse) {
        self.inner.push_query_response(response);
    }

    pub fn push_error(&mut self, error: TransportError) {
        self.inner.push_error(error);
    }

    pub fn query_calls(&self) -> usize {
        self.inner.query_calls()
    }
}

impl ClickHouseHttpTransport for LoopbackClickHouseTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn query(
        &mut self,
        request: &ClickHouseQueryRequest,
    ) -> Result<ClickHouseQueryResponse, TransportError> {
        self.inner.query(request)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl ClickHouseHttpTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn query(
        &mut self,
        _request: &ClickHouseQueryRequest,
    ) -> Result<ClickHouseQueryResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

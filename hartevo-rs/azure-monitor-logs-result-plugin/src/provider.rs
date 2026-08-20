use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AggregateRow, AggregateSchema, AzureMonitorLogsScope, Digest, ModelError, ProviderId,
    QueryBounds, ResultStatus, Revision, SecretReference, TimeWindow,
};
use crate::query::QueryPlan;
use crate::{
    AZURE_MONITOR_LOGS_API_REVISION, AZURE_MONITOR_LOGS_PROVIDER_ID,
    AZURE_MONITOR_LOGS_PROVIDER_VERSION, AZURE_MONITOR_LOGS_QUERY_PATH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_layer_one(self) -> bool {
        true
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version or API revision is invalid")]
    InvalidVersion,
    #[error("provider definition claims forbidden native or connected authority")]
    ForbiddenAuthority,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AzureMonitorLogsProviderDefinition {
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub api_revision: String,
    pub endpoint_path: String,
    pub operation: String,
    pub provenance: ProviderProvenance,
    pub capability_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AzureMonitorLogsProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.trim().is_empty()
            || provider_version.len() > 32
            || provider_version.chars().any(char::is_control)
        {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        let capability_digest = Digest::from_fields(
            "azure-monitor-logs-provider-capability/v1",
            &[
                AZURE_MONITOR_LOGS_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                AZURE_MONITOR_LOGS_API_REVISION.to_owned(),
                AZURE_MONITOR_LOGS_QUERY_PATH.to_owned(),
                format!("{provenance:?}"),
            ],
        );
        let definition = Self {
            provider_id: ProviderId::new(AZURE_MONITOR_LOGS_PROVIDER_ID)?,
            provider_version,
            api_revision: AZURE_MONITOR_LOGS_API_REVISION.to_owned(),
            endpoint_path: AZURE_MONITOR_LOGS_QUERY_PATH.to_owned(),
            operation: "query".to_owned(),
            provenance,
            capability_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.provider_id.as_str() != AZURE_MONITOR_LOGS_PROVIDER_ID
            || self.api_revision != AZURE_MONITOR_LOGS_API_REVISION
            || self.endpoint_path != AZURE_MONITOR_LOGS_QUERY_PATH
            || self.operation != "query"
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || !self.provenance.is_layer_one()
        {
            Err(ProviderDefinitionError::ForbiddenAuthority)
        } else {
            Ok(())
        }
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "azure-monitor-logs-provider/v1",
            &[
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.api_revision.clone(),
                self.endpoint_path.clone(),
                self.operation.clone(),
                format!("{:?}", self.provenance),
                self.capability_digest.as_str().to_owned(),
                self.connected.to_string(),
                self.native.to_string(),
                self.first_party.to_string(),
                self.provider_receipt.to_string(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Timeout,
    AccessLost,
    RateLimited,
    ServerFailure,
    BlockedEnv,
    Malformed,
    Unknown,
}

#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize)]
#[error("Azure Monitor Logs provider error: {kind:?}")]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl ProviderError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::Timeout
                | ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
        );
        Self {
            kind,
            status_code,
            retryable,
            diagnostic_digest: Digest::from_text(diagnostic),
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn access_lost() -> Self {
        Self::new(ProviderErrorKind::AccessLost, Some(403), "access-lost")
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

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn malformed() -> Self {
        Self::new(ProviderErrorKind::Malformed, None, "malformed-response")
    }

    pub fn unknown() -> Self {
        Self::new(ProviderErrorKind::Unknown, None, "provider-unknown")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderResultStatus {
    Complete,
    Empty,
    Partial,
    Truncated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AzureMonitorLogsRequest {
    pub method: String,
    pub endpoint_path: String,
    pub tenant_id: crate::TenantId,
    pub subscription_id: crate::SubscriptionId,
    pub workspace_id: crate::WorkspaceId,
    pub table: crate::TableName,
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub scope_digest: Digest,
    pub query_template_digest: Digest,
    pub query_digest: Digest,
    pub parameter_digest: Digest,
    pub time_window: TimeWindow,
    pub bounds: QueryBounds,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
}

impl AzureMonitorLogsRequest {
    pub(crate) fn from_plan(
        scope: &AzureMonitorLogsScope,
        secret: &SecretReference,
        plan: &QueryPlan,
        registration_digest: Digest,
        registration_revision: Revision,
    ) -> Self {
        Self {
            method: "POST".to_owned(),
            endpoint_path: AZURE_MONITOR_LOGS_QUERY_PATH.to_owned(),
            tenant_id: scope.tenant_id.clone(),
            subscription_id: scope.subscription_id.clone(),
            workspace_id: scope.workspace_id.clone(),
            table: scope.table.clone(),
            project_id: scope.project_id.clone(),
            project_revision: scope.project_revision,
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
            work_product_id: scope.work_product_id.clone(),
            work_product_revision: scope.work_product_revision,
            scope_digest: scope.scope_digest(),
            query_template_digest: plan.template().template_digest.clone(),
            query_digest: plan.query_digest().clone(),
            parameter_digest: plan.parameter_digest().clone(),
            time_window: plan.time_window().clone(),
            bounds: plan.bounds(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            registration_digest,
            registration_revision,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.method != "POST"
            || self.endpoint_path != AZURE_MONITOR_LOGS_QUERY_PATH
            || self.time_window.validate_digest().is_err()
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AzureMonitorLogsResponse {
    pub status: ProviderResultStatus,
    pub scope_digest: Digest,
    pub query_template_digest: Digest,
    pub query_digest: Digest,
    pub parameter_digest: Digest,
    pub time_window_digest: Digest,
    pub schema: AggregateSchema,
    pub rows: Vec<AggregateRow>,
    pub total_rows: Option<u64>,
    pub response_bytes: u64,
    pub duration_ms: u32,
    pub cost_microunits: u64,
    pub provider_revision: Revision,
    pub row_set_digest: Digest,
    pub response_digest: Digest,
}

impl AzureMonitorLogsResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn for_request(
        request: &AzureMonitorLogsRequest,
        status: ProviderResultStatus,
        schema: AggregateSchema,
        rows: Vec<AggregateRow>,
        total_rows: Option<u64>,
        response_bytes: u64,
        duration_ms: u32,
        cost_microunits: u64,
        provider_revision: Revision,
    ) -> Result<Self, ModelError> {
        schema.validate_digest()?;
        for row in &rows {
            row.validate_against(&schema)?;
        }
        if matches!(status, ProviderResultStatus::Empty) && !rows.is_empty() {
            return Err(ModelError::InvalidRow);
        }
        let row_set_digest = compute_row_set_digest(&schema, &rows);
        let response_digest = compute_response_digest(
            request,
            status,
            &schema,
            &row_set_digest,
            total_rows,
            response_bytes,
            duration_ms,
            cost_microunits,
            provider_revision,
        );
        Ok(Self {
            status,
            scope_digest: request.scope_digest.clone(),
            query_template_digest: request.query_template_digest.clone(),
            query_digest: request.query_digest.clone(),
            parameter_digest: request.parameter_digest.clone(),
            time_window_digest: request.time_window.digest.clone(),
            schema,
            rows,
            total_rows,
            response_bytes,
            duration_ms,
            cost_microunits,
            provider_revision,
            row_set_digest,
            response_digest,
        })
    }

    pub fn validate_integrity(&self, request: &AzureMonitorLogsRequest) -> Result<(), ModelError> {
        request.validate()?;
        if self.scope_digest != request.scope_digest
            || self.query_template_digest != request.query_template_digest
            || self.query_digest != request.query_digest
            || self.parameter_digest != request.parameter_digest
            || self.time_window_digest != request.time_window.digest
        {
            return Err(ModelError::DigestMismatch);
        }
        self.schema.validate_digest()?;
        for row in &self.rows {
            row.validate_against(&self.schema)?;
        }
        if matches!(self.status, ProviderResultStatus::Empty) && !self.rows.is_empty() {
            return Err(ModelError::InvalidRow);
        }
        let row_set_digest = compute_row_set_digest(&self.schema, &self.rows);
        if row_set_digest != self.row_set_digest {
            return Err(ModelError::DigestMismatch);
        }
        let response_digest = compute_response_digest(
            request,
            self.status,
            &self.schema,
            &self.row_set_digest,
            self.total_rows,
            self.response_bytes,
            self.duration_ms,
            self.cost_microunits,
            self.provider_revision,
        );
        if response_digest != self.response_digest {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn status(&self) -> ResultStatus {
        match self.status {
            ProviderResultStatus::Complete if self.rows.is_empty() => ResultStatus::Empty,
            ProviderResultStatus::Complete => ResultStatus::Complete,
            ProviderResultStatus::Empty => ResultStatus::Empty,
            ProviderResultStatus::Partial => ResultStatus::Partial,
            ProviderResultStatus::Truncated => ResultStatus::Truncated,
        }
    }
}

fn compute_row_set_digest(schema: &AggregateSchema, rows: &[AggregateRow]) -> Digest {
    let mut canonical = rows.iter().map(AggregateRow::canonical).collect::<Vec<_>>();
    canonical.sort();
    let mut fields = vec![schema.schema_digest.as_str().to_owned()];
    fields.extend(canonical);
    Digest::from_fields("azure-monitor-logs-row-set/v1", &fields)
}

#[allow(clippy::too_many_arguments)]
fn compute_response_digest(
    request: &AzureMonitorLogsRequest,
    status: ProviderResultStatus,
    schema: &AggregateSchema,
    row_set_digest: &Digest,
    total_rows: Option<u64>,
    response_bytes: u64,
    duration_ms: u32,
    cost_microunits: u64,
    provider_revision: Revision,
) -> Digest {
    Digest::from_fields(
        "azure-monitor-logs-response/v1",
        &[
            request.scope_digest.as_str().to_owned(),
            request.query_template_digest.as_str().to_owned(),
            request.query_digest.as_str().to_owned(),
            request.parameter_digest.as_str().to_owned(),
            request.time_window.digest.as_str().to_owned(),
            format!("{status:?}"),
            schema.schema_digest.as_str().to_owned(),
            row_set_digest.as_str().to_owned(),
            total_rows.map_or_else(|| "-".to_owned(), |value| value.to_string()),
            response_bytes.to_string(),
            duration_ms.to_string(),
            cost_microunits.to_string(),
            provider_revision.get().to_string(),
        ],
    )
}

pub trait AzureMonitorLogsTransport: fmt::Debug {
    fn query(
        &mut self,
        request: &AzureMonitorLogsRequest,
    ) -> Result<AzureMonitorLogsResponse, ProviderError>;
}

pub trait AzureMonitorLogsProviderPort: fmt::Debug {
    fn definition(&self) -> &AzureMonitorLogsProviderDefinition;

    fn query(
        &mut self,
        request: &AzureMonitorLogsRequest,
    ) -> Result<AzureMonitorLogsResponse, ProviderError>;
}

#[derive(Debug)]
pub struct AzureMonitorLogsProvider<T> {
    transport: T,
    definition: AzureMonitorLogsProviderDefinition,
}

impl<T: AzureMonitorLogsTransport> AzureMonitorLogsProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            definition: AzureMonitorLogsProviderDefinition::new(provider_version, provenance)?,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: AzureMonitorLogsTransport> AzureMonitorLogsProviderPort for AzureMonitorLogsProvider<T> {
    fn definition(&self) -> &AzureMonitorLogsProviderDefinition {
        &self.definition
    }

    fn query(
        &mut self,
        request: &AzureMonitorLogsRequest,
    ) -> Result<AzureMonitorLogsResponse, ProviderError> {
        self.transport.query(request)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAzureMonitorLogsTransport {
    result: Result<AzureMonitorLogsResponse, ProviderError>,
}

impl FixtureAzureMonitorLogsTransport {
    pub fn response(response: AzureMonitorLogsResponse) -> Self {
        Self {
            result: Ok(response),
        }
    }

    pub fn error(error: ProviderError) -> Self {
        Self { result: Err(error) }
    }
}

impl AzureMonitorLogsTransport for FixtureAzureMonitorLogsTransport {
    fn query(
        &mut self,
        _request: &AzureMonitorLogsRequest,
    ) -> Result<AzureMonitorLogsResponse, ProviderError> {
        self.result.clone()
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAzureMonitorLogsTransport {
    result: Result<AzureMonitorLogsResponse, ProviderError>,
}

impl RecordingAzureMonitorLogsTransport {
    pub fn response(response: AzureMonitorLogsResponse) -> Self {
        Self {
            result: Ok(response),
        }
    }

    pub fn error(error: ProviderError) -> Self {
        Self { result: Err(error) }
    }
}

impl AzureMonitorLogsTransport for RecordingAzureMonitorLogsTransport {
    fn query(
        &mut self,
        _request: &AzureMonitorLogsRequest,
    ) -> Result<AzureMonitorLogsResponse, ProviderError> {
        self.result.clone()
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAzureMonitorLogsTransport {
    result: Result<AzureMonitorLogsResponse, ProviderError>,
}

impl LoopbackAzureMonitorLogsTransport {
    pub fn response(response: AzureMonitorLogsResponse) -> Self {
        Self {
            result: Ok(response),
        }
    }

    pub fn error(error: ProviderError) -> Self {
        Self { result: Err(error) }
    }
}

impl AzureMonitorLogsTransport for LoopbackAzureMonitorLogsTransport {
    fn query(
        &mut self,
        _request: &AzureMonitorLogsRequest,
    ) -> Result<AzureMonitorLogsResponse, ProviderError> {
        self.result.clone()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAzureMonitorLogsTransport;

impl AzureMonitorLogsTransport for BlockedEnvAzureMonitorLogsTransport {
    fn query(
        &mut self,
        _request: &AzureMonitorLogsRequest,
    ) -> Result<AzureMonitorLogsResponse, ProviderError> {
        Err(ProviderError::blocked_env())
    }
}

pub type BlockedEnvTransport = BlockedEnvAzureMonitorLogsTransport;

impl AzureMonitorLogsProvider<FixtureAzureMonitorLogsTransport> {
    pub fn fixture(response: AzureMonitorLogsResponse) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            FixtureAzureMonitorLogsTransport::response(response),
            AZURE_MONITOR_LOGS_PROVIDER_VERSION,
            ProviderProvenance::Fixture,
        )
    }
}

impl AzureMonitorLogsProvider<RecordingAzureMonitorLogsTransport> {
    pub fn recording(response: AzureMonitorLogsResponse) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            RecordingAzureMonitorLogsTransport::response(response),
            AZURE_MONITOR_LOGS_PROVIDER_VERSION,
            ProviderProvenance::Recording,
        )
    }
}

impl AzureMonitorLogsProvider<LoopbackAzureMonitorLogsTransport> {
    pub fn loopback(response: AzureMonitorLogsResponse) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            LoopbackAzureMonitorLogsTransport::response(response),
            AZURE_MONITOR_LOGS_PROVIDER_VERSION,
            ProviderProvenance::Loopback,
        )
    }
}

impl AzureMonitorLogsProvider<BlockedEnvAzureMonitorLogsTransport> {
    pub fn blocked_env() -> Result<Self, ProviderDefinitionError> {
        Self::new(
            BlockedEnvAzureMonitorLogsTransport,
            AZURE_MONITOR_LOGS_PROVIDER_VERSION,
            ProviderProvenance::BlockedEnv,
        )
    }
}

pub fn provenance_flags(provenance: ProviderProvenance) -> (bool, bool, bool) {
    (
        provenance.connected(),
        provenance.native(),
        provenance.first_party(),
    )
}

pub fn result_status_for_error(error: &ProviderError) -> ResultStatus {
    match error.kind {
        ProviderErrorKind::Timeout => ResultStatus::Timeout,
        ProviderErrorKind::AccessLost => ResultStatus::AccessLost,
        ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::RateLimited
        | ProviderErrorKind::ServerFailure
        | ProviderErrorKind::Malformed
        | ProviderErrorKind::Unknown => ResultStatus::ProviderUnknown,
    }
}

pub fn empty_response_for_request(
    request: &AzureMonitorLogsRequest,
    schema: AggregateSchema,
) -> Result<AzureMonitorLogsResponse, ModelError> {
    AzureMonitorLogsResponse::for_request(
        request,
        ProviderResultStatus::Empty,
        schema,
        Vec::new(),
        Some(0),
        0,
        0,
        0,
        Revision::new(1)?,
    )
}

pub fn row_count(response: &AzureMonitorLogsResponse) -> usize {
    response.rows.len()
}

pub fn has_only_bounded_aggregate_cells(response: &AzureMonitorLogsResponse) -> bool {
    response
        .rows
        .iter()
        .all(|row| row.cells.iter().all(|cell| cell.estimated_size() <= 128))
}

pub fn response_contains_duplicate_rows(response: &AzureMonitorLogsResponse) -> bool {
    let mut rows = BTreeSet::new();
    response
        .rows
        .iter()
        .any(|row| !rows.insert(row.canonical()))
}

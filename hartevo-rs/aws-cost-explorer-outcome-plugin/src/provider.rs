use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AwsAccountBinding, AwsCostExplorerScope, AwsOperation, CostFilter, CostMetric, Digest,
    DimensionKey, DimensionValue, Granularity, GroupDefinition, MAX_GROUP_COUNT, MetricMap,
    MetricValue, MissionId, ModelError, OpaqueNextPageToken, PermissionFence, ProjectId,
    ProviderErrorKind, Revision, TimePeriod, WorkProductId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty or too long")]
    InvalidVersion,
    #[error("provider must expose at least one allowlisted read operation")]
    EmptyOperations,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsCostExplorerProviderDefinition {
    provider_id: String,
    provider_version: String,
    provenance: ProviderProvenance,
    operations: BTreeSet<AwsOperation>,
    provider_digest: Digest,
    native: bool,
    live_execution: bool,
}

impl AwsCostExplorerProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new_with_operations(
            provider_version,
            provenance,
            [
                AwsOperation::GetCostAndUsage,
                AwsOperation::GetUsageForecast,
                AwsOperation::GetDimensionValues,
            ],
        )
    }

    pub fn new_with_operations(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
        operations: impl IntoIterator<Item = AwsOperation>,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        let operations: BTreeSet<AwsOperation> = operations.into_iter().collect();
        if provider_version.is_empty() || provider_version.len() > 64 {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        if operations.is_empty() {
            return Err(ProviderDefinitionError::EmptyOperations);
        }
        let fields = vec![
            crate::AWS_COST_EXPLORER_PROVIDER_ID.to_owned(),
            provider_version.clone(),
            format!("{provenance:?}"),
            operations
                .iter()
                .map(|operation| operation.api_name())
                .collect::<Vec<_>>()
                .join(","),
            false.to_string(),
        ];
        Ok(Self {
            provider_id: crate::AWS_COST_EXPLORER_PROVIDER_ID.to_owned(),
            provider_version,
            provenance,
            operations,
            provider_digest: Digest::from_fields("aws-cost-provider/v1", &fields),
            native: false,
            live_execution: false,
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn operations(&self) -> &BTreeSet<AwsOperation> {
        &self.operations
    }

    pub fn supports(&self, operation: AwsOperation) -> bool {
        self.operations.contains(&operation)
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn live_execution(&self) -> bool {
        self.live_execution
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    diagnostic_digest: Digest,
}

impl fmt::Debug for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportError")
            .field("kind", &self.kind)
            .field("status_code", &self.status_code)
            .field("retryable", &self.retryable)
            .field("blocked_env", &self.blocked_env)
            .field("diagnostic_digest", &self.diagnostic_digest)
            .finish()
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "AWS Cost Explorer transport returned {:?}",
            self.kind
        )
    }
}

impl std::error::Error for TransportError {}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::Timeout
                | ProviderErrorKind::ServerFailure
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

    pub fn from_http(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        let kind = match status_code {
            429 => ProviderErrorKind::RateLimited,
            403 => ProviderErrorKind::AccessDenied,
            404 => ProviderErrorKind::NotFound,
            400..=499 => ProviderErrorKind::InvalidRequest,
            500..=599 => ProviderErrorKind::ServerFailure,
            _ => ProviderErrorKind::Unknown,
        };
        Self::new(kind, Some(status_code), diagnostic)
    }

    pub fn invalid_request() -> Self {
        Self::new(
            ProviderErrorKind::InvalidRequest,
            Some(400),
            "invalid-request",
        )
    }

    pub fn access_denied() -> Self {
        Self::new(ProviderErrorKind::AccessDenied, Some(403), "access-denied")
    }

    pub fn not_found() -> Self {
        Self::new(ProviderErrorKind::NotFound, Some(404), "not-found")
    }

    pub fn rate_limited() -> Self {
        Self::new(ProviderErrorKind::RateLimited, Some(429), "rate-limited")
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
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

    pub fn unknown() -> Self {
        Self::new(ProviderErrorKind::Unknown, None, "provider-unknown")
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceBinding {
    pub account_or_billing_view: AwsAccountBinding,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub query_digest: Digest,
}

impl EvidenceBinding {
    pub fn new(
        scope: &AwsCostExplorerScope,
        registration_digest: &Digest,
        query_digest: Digest,
    ) -> Self {
        Self {
            account_or_billing_view: scope.account_or_billing_view().clone(),
            project_id: scope.project_id().clone(),
            mission_id: scope.mission_id().clone(),
            work_product_id: scope.work_product_id().clone(),
            mission_revision: scope.mission_revision(),
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            registration_digest: registration_digest.clone(),
            query_digest,
        }
    }

    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            mission_revision: self.mission_revision,
        }
    }

    pub(crate) fn canonical_fields(&self) -> Vec<String> {
        vec![
            self.account_or_billing_view.canonical(),
            self.project_id.as_str().to_owned(),
            self.mission_id.as_str().to_owned(),
            self.work_product_id.as_str().to_owned(),
            self.mission_revision.get().to_string(),
            self.scope_digest.as_str().to_owned(),
            self.permission_digest.as_str().to_owned(),
            self.consent_digest.as_str().to_owned(),
            self.registration_digest.as_str().to_owned(),
            self.query_digest.as_str().to_owned(),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostAndUsageRequest {
    pub binding: EvidenceBinding,
    pub period: TimePeriod,
    pub granularity: Granularity,
    pub metrics: Vec<CostMetric>,
    pub filter: CostFilter,
    pub group_by: Vec<GroupDefinition>,
    pub page_number: u8,
    pub next_page_token: Option<OpaqueNextPageToken>,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub with_resources: bool,
}

impl CostAndUsageRequest {
    pub fn page_token_digest(&self) -> Option<Digest> {
        self.next_page_token
            .as_ref()
            .map(|token| token.digest().clone())
    }

    pub fn fence(&self) -> PermissionFence {
        self.binding.fence()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageForecastRequest {
    pub binding: EvidenceBinding,
    pub horizon: TimePeriod,
    pub granularity: Granularity,
    pub metric: CostMetric,
    pub filter: CostFilter,
    pub prediction_interval_level: Option<u8>,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
}

impl UsageForecastRequest {
    pub fn fence(&self) -> PermissionFence {
        self.binding.fence()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DimensionValuesRequest {
    pub binding: EvidenceBinding,
    pub period: TimePeriod,
    pub dimension: DimensionKey,
    pub filter: CostFilter,
    pub max_results: u32,
    pub search_string: Option<String>,
    pub page_number: u8,
    pub next_page_token: Option<OpaqueNextPageToken>,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
}

impl DimensionValuesRequest {
    pub fn page_token_digest(&self) -> Option<Digest> {
        self.next_page_token
            .as_ref()
            .map(|token| token.digest().clone())
    }

    pub fn fence(&self) -> PermissionFence {
        self.binding.fence()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostGroup {
    pub keys: Vec<String>,
    pub metrics: MetricMap,
}

impl CostGroup {
    pub fn new(keys: impl IntoIterator<Item = impl Into<String>>, metrics: MetricMap) -> Self {
        Self {
            keys: keys.into_iter().map(Into::into).collect(),
            metrics,
        }
    }

    fn canonical(&self) -> String {
        let metrics = self
            .metrics
            .iter()
            .map(|(metric, value)| format!("{}={}", metric.api_name(), value.canonical()))
            .collect::<Vec<_>>()
            .join(";");
        format!("{}|{metrics}", self.keys.join("|"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostResultByTime {
    pub time_period: TimePeriod,
    pub estimated: bool,
    pub total: MetricMap,
    pub groups: Vec<CostGroup>,
}

impl CostResultByTime {
    pub fn new(
        time_period: TimePeriod,
        estimated: bool,
        total: MetricMap,
        groups: Vec<CostGroup>,
    ) -> Self {
        Self {
            time_period,
            estimated,
            total,
            groups,
        }
    }

    fn canonical(&self) -> String {
        let total = self
            .total
            .iter()
            .map(|(metric, value)| format!("{}={}", metric.api_name(), value.canonical()))
            .collect::<Vec<_>>()
            .join(";");
        let groups = self
            .groups
            .iter()
            .map(CostGroup::canonical)
            .collect::<Vec<_>>()
            .join("~");
        format!(
            "{}:{}:{total}:{groups}",
            self.time_period.canonical(),
            self.estimated
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostUsagePage {
    pub binding: EvidenceBinding,
    pub page_number: u8,
    pub metrics: Vec<CostMetric>,
    pub group_by: Vec<GroupDefinition>,
    pub results_by_time: Vec<CostResultByTime>,
    pub next_page_token: Option<OpaqueNextPageToken>,
    pub estimated: bool,
    pub incomplete: bool,
    pub page_digest: Digest,
}

impl CostUsagePage {
    pub fn new(
        binding: EvidenceBinding,
        page_number: u8,
        metrics: Vec<CostMetric>,
        group_by: Vec<GroupDefinition>,
        results_by_time: Vec<CostResultByTime>,
        next_page_token: Option<OpaqueNextPageToken>,
        estimated: bool,
        incomplete: bool,
    ) -> Result<Self, ModelError> {
        if page_number == 0
            || metrics.is_empty()
            || metrics.len() > crate::model::MAX_METRICS
            || group_by.len() > crate::model::MAX_GROUPS
            || results_by_time.len() > 128
            || results_by_time
                .iter()
                .map(|result| result.groups.len())
                .sum::<usize>()
                > MAX_GROUP_COUNT as usize
        {
            return Err(ModelError::InvalidBounds);
        }
        let page_digest = cost_page_digest(
            &binding,
            page_number,
            &metrics,
            &group_by,
            &results_by_time,
            next_page_token.as_ref(),
            estimated,
            incomplete,
        );
        Ok(Self {
            binding,
            page_number,
            metrics,
            group_by,
            results_by_time,
            next_page_token,
            estimated,
            incomplete,
            page_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = cost_page_digest(
            &self.binding,
            self.page_number,
            &self.metrics,
            &self.group_by,
            &self.results_by_time,
            self.next_page_token.as_ref(),
            self.estimated,
            self.incomplete,
        );
        if expected == self.page_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn next_page_token_digest(&self) -> Option<Digest> {
        self.next_page_token
            .as_ref()
            .map(|token| token.digest().clone())
    }

    pub fn approximate_bytes(&self) -> u32 {
        self.results_by_time
            .iter()
            .map(|result| {
                let totals = result.total.len() as u32 * 64;
                let groups = result
                    .groups
                    .iter()
                    .map(|group| group.keys.iter().map(String::len).sum::<usize>() as u32 + 128)
                    .sum::<u32>();
                128 + totals + groups
            })
            .sum()
    }
}

fn cost_page_digest(
    binding: &EvidenceBinding,
    page_number: u8,
    metrics: &[CostMetric],
    group_by: &[GroupDefinition],
    results_by_time: &[CostResultByTime],
    next_page_token: Option<&OpaqueNextPageToken>,
    estimated: bool,
    incomplete: bool,
) -> Digest {
    let mut fields = binding.canonical_fields();
    fields.extend([
        page_number.to_string(),
        metrics
            .iter()
            .map(|metric| metric.api_name())
            .collect::<Vec<_>>()
            .join(","),
        group_by
            .iter()
            .map(GroupDefinition::canonical)
            .collect::<Vec<_>>()
            .join(","),
        results_by_time
            .iter()
            .map(CostResultByTime::canonical)
            .collect::<Vec<_>>()
            .join("~"),
        next_page_token.map_or_else(String::new, |token| token.digest().as_str().to_owned()),
        estimated.to_string(),
        incomplete.to_string(),
    ]);
    Digest::from_fields("aws-cost-page/v1", &fields)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForecastPoint {
    pub time_period: TimePeriod,
    pub mean: MetricValue,
    pub prediction_interval_lower_bound: Option<MetricValue>,
    pub prediction_interval_upper_bound: Option<MetricValue>,
}

impl ForecastPoint {
    pub fn new(
        time_period: TimePeriod,
        mean: MetricValue,
        prediction_interval_lower_bound: Option<MetricValue>,
        prediction_interval_upper_bound: Option<MetricValue>,
    ) -> Self {
        Self {
            time_period,
            mean,
            prediction_interval_lower_bound,
            prediction_interval_upper_bound,
        }
    }

    fn canonical(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.time_period.canonical(),
            self.mean.canonical(),
            self.prediction_interval_lower_bound
                .as_ref()
                .map_or_else(String::new, MetricValue::canonical),
            self.prediction_interval_upper_bound
                .as_ref()
                .map_or_else(String::new, MetricValue::canonical)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageForecastResponse {
    pub binding: EvidenceBinding,
    pub horizon: TimePeriod,
    pub granularity: Granularity,
    pub metric: CostMetric,
    pub forecast_results_by_time: Vec<ForecastPoint>,
    pub total: MetricValue,
    pub incomplete: bool,
    pub forecast_digest: Digest,
}

impl UsageForecastResponse {
    pub fn new(
        binding: EvidenceBinding,
        horizon: TimePeriod,
        granularity: Granularity,
        metric: CostMetric,
        forecast_results_by_time: Vec<ForecastPoint>,
        total: MetricValue,
        incomplete: bool,
    ) -> Result<Self, ModelError> {
        if forecast_results_by_time.len() > 548 {
            return Err(ModelError::InvalidBounds);
        }
        let forecast_digest = forecast_digest(
            &binding,
            &horizon,
            granularity,
            metric,
            &forecast_results_by_time,
            &total,
            incomplete,
        );
        Ok(Self {
            binding,
            horizon,
            granularity,
            metric,
            forecast_results_by_time,
            total,
            incomplete,
            forecast_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = forecast_digest(
            &self.binding,
            &self.horizon,
            self.granularity,
            self.metric,
            &self.forecast_results_by_time,
            &self.total,
            self.incomplete,
        );
        if expected == self.forecast_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

pub(crate) fn forecast_digest(
    binding: &EvidenceBinding,
    horizon: &TimePeriod,
    granularity: Granularity,
    metric: CostMetric,
    forecast_results_by_time: &[ForecastPoint],
    total: &MetricValue,
    incomplete: bool,
) -> Digest {
    let mut fields = binding.canonical_fields();
    fields.extend([
        horizon.canonical(),
        granularity.api_name().to_owned(),
        metric.api_name().to_owned(),
        forecast_results_by_time
            .iter()
            .map(ForecastPoint::canonical)
            .collect::<Vec<_>>()
            .join("~"),
        total.canonical(),
        incomplete.to_string(),
    ]);
    Digest::from_fields("aws-cost-forecast/v1", &fields)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DimensionValuesPage {
    pub binding: EvidenceBinding,
    pub period: TimePeriod,
    pub dimension: DimensionKey,
    pub values: Vec<DimensionValue>,
    pub next_page_token: Option<OpaqueNextPageToken>,
    pub return_size: u32,
    pub total_size: Option<u32>,
    pub page_digest: Digest,
}

impl DimensionValuesPage {
    pub fn new(
        binding: EvidenceBinding,
        period: TimePeriod,
        dimension: DimensionKey,
        values: Vec<DimensionValue>,
        next_page_token: Option<OpaqueNextPageToken>,
        total_size: Option<u32>,
    ) -> Result<Self, ModelError> {
        if values.len() > crate::model::MAX_DIMENSION_VALUE_COUNT as usize {
            return Err(ModelError::InvalidBounds);
        }
        let return_size = values.len() as u32;
        let page_digest = dimension_page_digest(
            &binding,
            &period,
            &dimension,
            &values,
            next_page_token.as_ref(),
            return_size,
            total_size,
        );
        Ok(Self {
            binding,
            period,
            dimension,
            values,
            next_page_token,
            return_size,
            total_size,
            page_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = dimension_page_digest(
            &self.binding,
            &self.period,
            &self.dimension,
            &self.values,
            self.next_page_token.as_ref(),
            self.return_size,
            self.total_size,
        );
        if expected == self.page_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn next_page_token_digest(&self) -> Option<Digest> {
        self.next_page_token
            .as_ref()
            .map(|token| token.digest().clone())
    }
}

fn dimension_page_digest(
    binding: &EvidenceBinding,
    period: &TimePeriod,
    dimension: &DimensionKey,
    values: &[DimensionValue],
    next_page_token: Option<&OpaqueNextPageToken>,
    return_size: u32,
    total_size: Option<u32>,
) -> Digest {
    let mut fields = binding.canonical_fields();
    fields.extend([
        period.canonical(),
        dimension.as_str().to_owned(),
        values
            .iter()
            .map(|value| {
                format!(
                    "{}:{}",
                    value.value,
                    value
                        .attributes
                        .iter()
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect::<Vec<_>>()
            .join("~"),
        next_page_token.map_or_else(String::new, |token| token.digest().as_str().to_owned()),
        return_size.to_string(),
        total_size.map_or_else(String::new, |value| value.to_string()),
    ]);
    Digest::from_fields("aws-dimension-page/v1", &fields)
}

pub trait CostExplorerProvider: fmt::Debug {
    fn definition(&self) -> &AwsCostExplorerProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance()
    }

    fn cost_and_usage(
        &mut self,
        request: &CostAndUsageRequest,
    ) -> Result<CostUsagePage, TransportError>;

    fn usage_forecast(
        &mut self,
        request: &UsageForecastRequest,
    ) -> Result<UsageForecastResponse, TransportError>;

    fn dimension_values(
        &mut self,
        request: &DimensionValuesRequest,
    ) -> Result<DimensionValuesPage, TransportError>;
}

pub trait AwsCostExplorerTransport: fmt::Debug {
    fn cost_and_usage(
        &mut self,
        request: &CostAndUsageRequest,
    ) -> Result<CostUsagePage, TransportError>;

    fn usage_forecast(
        &mut self,
        request: &UsageForecastRequest,
    ) -> Result<UsageForecastResponse, TransportError>;

    fn dimension_values(
        &mut self,
        request: &DimensionValuesRequest,
    ) -> Result<DimensionValuesPage, TransportError>;
}

#[derive(Debug)]
pub struct AwsCostExplorerProvider<T> {
    transport: T,
    definition: AwsCostExplorerProviderDefinition,
}

impl<T: AwsCostExplorerTransport> AwsCostExplorerProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            definition: AwsCostExplorerProviderDefinition::new(provider_version, provenance)?,
        })
    }

    pub fn new_with_operations(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
        operations: impl IntoIterator<Item = AwsOperation>,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            definition: AwsCostExplorerProviderDefinition::new_with_operations(
                provider_version,
                provenance,
                operations,
            )?,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: AwsCostExplorerTransport> CostExplorerProvider for AwsCostExplorerProvider<T> {
    fn definition(&self) -> &AwsCostExplorerProviderDefinition {
        &self.definition
    }

    fn cost_and_usage(
        &mut self,
        request: &CostAndUsageRequest,
    ) -> Result<CostUsagePage, TransportError> {
        self.transport.cost_and_usage(request)
    }

    fn usage_forecast(
        &mut self,
        request: &UsageForecastRequest,
    ) -> Result<UsageForecastResponse, TransportError> {
        self.transport.usage_forecast(request)
    }

    fn dimension_values(
        &mut self,
        request: &DimensionValuesRequest,
    ) -> Result<DimensionValuesPage, TransportError> {
        self.transport.dimension_values(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAwsCostExplorerTransport {
    cost_and_usage_responses: VecDeque<Result<CostUsagePage, TransportError>>,
    forecast_responses: VecDeque<Result<UsageForecastResponse, TransportError>>,
    dimension_responses: VecDeque<Result<DimensionValuesPage, TransportError>>,
    cost_and_usage_requests: Vec<CostAndUsageRequest>,
    forecast_requests: Vec<UsageForecastRequest>,
    dimension_requests: Vec<DimensionValuesRequest>,
}

impl RecordingAwsCostExplorerTransport {
    pub fn push_cost_and_usage_response(
        &mut self,
        response: Result<CostUsagePage, TransportError>,
    ) {
        self.cost_and_usage_responses.push_back(response);
    }

    pub fn push_usage_forecast_response(
        &mut self,
        response: Result<UsageForecastResponse, TransportError>,
    ) {
        self.forecast_responses.push_back(response);
    }

    pub fn push_dimension_values_response(
        &mut self,
        response: Result<DimensionValuesPage, TransportError>,
    ) {
        self.dimension_responses.push_back(response);
    }

    pub fn replay_cost_and_usage_last(&mut self) {
        if let Some(response) = self.cost_and_usage_responses.back().cloned() {
            self.cost_and_usage_responses.push_back(response);
        }
    }

    pub fn replay_usage_forecast_last(&mut self) {
        if let Some(response) = self.forecast_responses.back().cloned() {
            self.forecast_responses.push_back(response);
        }
    }

    pub fn replay_dimension_values_last(&mut self) {
        if let Some(response) = self.dimension_responses.back().cloned() {
            self.dimension_responses.push_back(response);
        }
    }

    pub fn cost_and_usage_requests(&self) -> &[CostAndUsageRequest] {
        &self.cost_and_usage_requests
    }

    pub fn forecast_requests(&self) -> &[UsageForecastRequest] {
        &self.forecast_requests
    }

    pub fn dimension_requests(&self) -> &[DimensionValuesRequest] {
        &self.dimension_requests
    }
}

impl AwsCostExplorerTransport for RecordingAwsCostExplorerTransport {
    fn cost_and_usage(
        &mut self,
        request: &CostAndUsageRequest,
    ) -> Result<CostUsagePage, TransportError> {
        self.cost_and_usage_requests.push(request.clone());
        self.cost_and_usage_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::unknown()))
    }

    fn usage_forecast(
        &mut self,
        request: &UsageForecastRequest,
    ) -> Result<UsageForecastResponse, TransportError> {
        self.forecast_requests.push(request.clone());
        self.forecast_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::unknown()))
    }

    fn dimension_values(
        &mut self,
        request: &DimensionValuesRequest,
    ) -> Result<DimensionValuesPage, TransportError> {
        self.dimension_requests.push(request.clone());
        self.dimension_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::unknown()))
    }
}

pub type FakeAwsCostExplorerTransport = RecordingAwsCostExplorerTransport;
pub type LoopbackAwsCostExplorerTransport = RecordingAwsCostExplorerTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsCostExplorerTransport;

impl AwsCostExplorerTransport for BlockedEnvAwsCostExplorerTransport {
    fn cost_and_usage(
        &mut self,
        _request: &CostAndUsageRequest,
    ) -> Result<CostUsagePage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn usage_forecast(
        &mut self,
        _request: &UsageForecastRequest,
    ) -> Result<UsageForecastResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn dimension_values(
        &mut self,
        _request: &DimensionValuesRequest,
    ) -> Result<DimensionValuesPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub type BlockedEnvTransport = BlockedEnvAwsCostExplorerTransport;

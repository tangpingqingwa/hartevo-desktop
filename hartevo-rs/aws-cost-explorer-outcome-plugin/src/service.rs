use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_COST_EXPLORER_CONSUMER_ID, AWS_COST_EXPLORER_CONTRACT_JSON,
    AWS_COST_EXPLORER_CONTRACT_VERSION, AWS_COST_EXPLORER_EVIDENCE_LEVEL,
    AWS_COST_EXPLORER_PROVIDER_ID, AWS_COST_EXPLORER_SCHEMA_VERSION, AWS_COST_EXPLORER_SERVICE_ID,
    model::{
        AwsCostExplorerRegistration, AwsCostExplorerScope, AwsOperation, CostControlObjective,
        CostFilter, CostMetric, Digest, DimensionKey, EvidenceBounds, EvidenceState,
        ForecastHorizon, Granularity, GroupDefinition, MetricMap, MetricValue, ModelError,
        PartialReason, PermissionRegistration, ProviderErrorEvidence, ProviderErrorKind, Revision,
        SecretReference, TimePeriod, normalize_grouping, normalize_metrics,
    },
    provider::{
        AwsCostExplorerProviderDefinition, CostAndUsageRequest, CostExplorerProvider,
        CostUsagePage, DimensionValuesPage, DimensionValuesRequest, EvidenceBinding, ForecastPoint,
        ProviderDefinitionError, ProviderProvenance, TransportError, UsageForecastRequest,
        UsageForecastResponse,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCostExplorerServiceError {
    #[error("AWS Cost Explorer registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Cost Explorer SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Cost Explorer scope does not match its SecretReference")]
    ScopeMismatch,
    #[error("permission registration does not authorize the requested operation")]
    PermissionDenied,
    #[error("provider definition does not expose the requested operation")]
    ProviderOperationUnavailable,
    #[error(
        "resource-level Cost Explorer reads require an explicit allowlist and ResourceId bound"
    )]
    ResourceOperationNotAllowlisted,
    #[error("query is outside the bounded Cost Explorer allowlist")]
    QueryTooBroad,
    #[error("provider response was tampered with or its digest is stale")]
    TamperedEvidence,
    #[error("provider returned a different query digest")]
    QueryDrift,
    #[error("provider returned a different registration digest")]
    RegistrationDrift,
    #[error("provider returned a different permission or consent fence")]
    FenceViolation,
    #[error("provider returned a different project binding")]
    ProjectDrift,
    #[error("provider returned a different Mission binding")]
    MissionDrift,
    #[error("provider returned a stale Mission revision")]
    MissionRevisionDrift,
    #[error("provider returned a different Work Product binding")]
    WorkProductDrift,
    #[error("provider returned a different AWS account")]
    AccountDrift,
    #[error("provider returned a different billing view")]
    BillingViewDrift,
    #[error("provider response shape is outside the requested bounds")]
    ResponseShape,
    #[error("forecast horizon is outside the daily/monthly bound")]
    ForecastHorizon,
    #[error("provider definition is invalid")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryEvidence {
    pub operation: AwsOperation,
    pub attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsCostExplorerServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub evidence_level: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_decision_proposal: bool,
    pub emits_outcome: bool,
}

impl AwsCostExplorerServiceDefinition {
    pub fn new() -> Self {
        Self {
            schema_version: AWS_COST_EXPLORER_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_COST_EXPLORER_CONTRACT_VERSION.to_owned(),
            evidence_level: AWS_COST_EXPLORER_EVIDENCE_LEVEL.to_owned(),
            service_id: AWS_COST_EXPLORER_SERVICE_ID.to_owned(),
            provider_id: AWS_COST_EXPLORER_PROVIDER_ID.to_owned(),
            consumer_id: AWS_COST_EXPLORER_CONSUMER_ID.to_owned(),
            contract_digest: Digest::from_text(AWS_COST_EXPLORER_CONTRACT_JSON),
            read_only: true,
            live_execution: false,
            emits_decision_proposal: true,
            emits_outcome: false,
        }
    }
}

impl Default for AwsCostExplorerServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostUsageProposalRequest {
    period: TimePeriod,
    granularity: Granularity,
    metrics: Vec<CostMetric>,
    filter: CostFilter,
    group_by: Vec<GroupDefinition>,
    objective: CostControlObjective,
    bounds: EvidenceBounds,
    with_resources: bool,
}

impl CostUsageProposalRequest {
    pub fn new(
        period: TimePeriod,
        granularity: Granularity,
        metrics: impl IntoIterator<Item = CostMetric>,
        filter: CostFilter,
        group_by: impl IntoIterator<Item = GroupDefinition>,
        objective: CostControlObjective,
    ) -> Result<Self, ModelError> {
        if period.span_days() > crate::model::MAX_COST_PERIOD_DAYS {
            return Err(ModelError::InvalidTimePeriod);
        }
        Ok(Self {
            period,
            granularity,
            metrics: normalize_metrics(metrics)?,
            filter,
            group_by: normalize_grouping(group_by)?,
            objective,
            bounds: EvidenceBounds::default(),
            with_resources: false,
        })
    }

    #[must_use]
    pub fn with_bounds(mut self, bounds: EvidenceBounds) -> Self {
        self.bounds = bounds;
        self
    }

    #[must_use]
    pub fn with_resource_detail(mut self) -> Self {
        self.with_resources = true;
        self
    }

    pub fn period(&self) -> &TimePeriod {
        &self.period
    }

    pub const fn granularity(&self) -> Granularity {
        self.granularity
    }

    pub fn metrics(&self) -> &[CostMetric] {
        &self.metrics
    }

    pub fn filter(&self) -> &CostFilter {
        &self.filter
    }

    pub fn group_by(&self) -> &[GroupDefinition] {
        &self.group_by
    }

    pub fn objective(&self) -> &CostControlObjective {
        &self.objective
    }

    pub fn bounds(&self) -> &EvidenceBounds {
        &self.bounds
    }

    pub const fn with_resources(&self) -> bool {
        self.with_resources
    }

    pub fn query_digest(&self, scope: &AwsCostExplorerScope) -> Digest {
        cost_query_digest(scope, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageForecastProposalRequest {
    horizon: TimePeriod,
    granularity: Granularity,
    metric: CostMetric,
    filter: CostFilter,
    prediction_interval_level: Option<u8>,
    objective: CostControlObjective,
    bounds: EvidenceBounds,
}

impl UsageForecastProposalRequest {
    pub fn new(
        horizon: TimePeriod,
        granularity: Granularity,
        metric: CostMetric,
        filter: CostFilter,
        prediction_interval_level: Option<u8>,
        objective: CostControlObjective,
    ) -> Result<Self, ModelError> {
        if let Some(level) = prediction_interval_level
            && !(51..=99).contains(&level)
        {
            return Err(ModelError::InvalidBounds);
        }
        ForecastHorizon::new(horizon.clone(), granularity)?;
        Ok(Self {
            horizon,
            granularity,
            metric,
            filter,
            prediction_interval_level,
            objective,
            bounds: EvidenceBounds::default(),
        })
    }

    #[must_use]
    pub fn with_bounds(mut self, bounds: EvidenceBounds) -> Self {
        self.bounds = bounds;
        self
    }

    pub fn horizon(&self) -> &TimePeriod {
        &self.horizon
    }

    pub const fn granularity(&self) -> Granularity {
        self.granularity
    }

    pub const fn metric(&self) -> CostMetric {
        self.metric
    }

    pub fn filter(&self) -> &CostFilter {
        &self.filter
    }

    pub const fn prediction_interval_level(&self) -> Option<u8> {
        self.prediction_interval_level
    }

    pub fn objective(&self) -> &CostControlObjective {
        &self.objective
    }

    pub fn bounds(&self) -> &EvidenceBounds {
        &self.bounds
    }

    pub fn query_digest(&self, scope: &AwsCostExplorerScope) -> Digest {
        forecast_query_digest(scope, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DimensionValuesProposalRequest {
    period: TimePeriod,
    dimension: DimensionKey,
    filter: CostFilter,
    max_results: u32,
    search_string: Option<String>,
    objective: CostControlObjective,
    bounds: EvidenceBounds,
}

impl DimensionValuesProposalRequest {
    pub fn new(
        period: TimePeriod,
        dimension: DimensionKey,
        filter: CostFilter,
        max_results: u32,
        search_string: Option<String>,
        objective: CostControlObjective,
    ) -> Result<Self, ModelError> {
        if period.span_days() > crate::model::MAX_COST_PERIOD_DAYS {
            return Err(ModelError::InvalidTimePeriod);
        }
        if max_results == 0 || max_results > crate::model::MAX_DIMENSION_VALUE_COUNT {
            return Err(ModelError::InvalidBounds);
        }
        if search_string
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > crate::model::MAX_TEXT_BYTES)
        {
            return Err(ModelError::InvalidFilter);
        }
        if dimension.is_resource_id() {
            return Err(ModelError::InvalidFilter);
        }
        Ok(Self {
            period,
            dimension,
            filter,
            max_results,
            search_string,
            objective,
            bounds: EvidenceBounds::default(),
        })
    }

    #[must_use]
    pub fn with_bounds(mut self, bounds: EvidenceBounds) -> Self {
        self.bounds = bounds;
        self
    }

    pub fn period(&self) -> &TimePeriod {
        &self.period
    }

    pub fn dimension(&self) -> &DimensionKey {
        &self.dimension
    }

    pub fn filter(&self) -> &CostFilter {
        &self.filter
    }

    pub const fn max_results(&self) -> u32 {
        self.max_results
    }

    pub fn search_string(&self) -> Option<&str> {
        self.search_string.as_deref()
    }

    pub fn objective(&self) -> &CostControlObjective {
        &self.objective
    }

    pub fn bounds(&self) -> &EvidenceBounds {
        &self.bounds
    }

    pub fn query_digest(&self, scope: &AwsCostExplorerScope) -> Digest {
        dimension_query_digest(scope, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsCostExplorerProposalRequest {
    CostAndUsage(CostUsageProposalRequest),
    UsageForecast(UsageForecastProposalRequest),
    DimensionValues(DimensionValuesProposalRequest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostUsageEvidence {
    pub binding: EvidenceBinding,
    pub state: EvidenceState,
    pub partial_reason: Option<PartialReason>,
    pub scope_digest: Digest,
    pub mission_revision: Revision,
    pub query_digest: Digest,
    pub registration_digest: Digest,
    pub provider_definition_digest: Digest,
    pub provider_provenance: ProviderProvenance,
    pub pages_observed: u8,
    pub page_digests: Vec<Digest>,
    pub next_page_token_digests: Vec<Digest>,
    pub results_by_time: Vec<crate::provider::CostResultByTime>,
    pub estimated: bool,
    pub incomplete: bool,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub truncated: bool,
    pub cost_digest: Digest,
}

impl CostUsageEvidence {
    pub fn validate_integrity(&self) -> Result<(), AwsCostExplorerServiceError> {
        let expected = evidence_digest(
            "aws-cost-evidence/v1",
            &self.binding,
            &self.page_digests,
            &self.next_page_token_digests,
            &self.results_by_time,
            self.state,
            self.estimated,
            self.incomplete,
            self.truncated,
        );
        if expected == self.cost_digest {
            Ok(())
        } else {
            Err(AwsCostExplorerServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostUsageProposal {
    pub request: CostUsageProposalRequest,
    pub evidence: CostUsageEvidence,
    pub objective: CostControlObjective,
    pub registration_digest: Digest,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl CostUsageProposal {
    pub fn state(&self) -> EvidenceState {
        self.evidence.state
    }

    pub fn cost_digest(&self) -> &Digest {
        &self.evidence.cost_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.evidence.query_digest
    }

    pub fn is_estimated(&self) -> bool {
        self.evidence.estimated
    }

    pub fn is_incomplete(&self) -> bool {
        self.evidence.incomplete
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_integrity(&self) -> Result<(), AwsCostExplorerServiceError> {
        self.evidence.validate_integrity()?;
        let expected = cost_proposal_digest(
            &self.evidence.query_digest,
            &self.evidence.cost_digest,
            &self.objective,
            &self.registration_digest,
            &self.provider_definition_digest,
        );
        if expected == self.proposal_digest {
            Ok(())
        } else {
            Err(AwsCostExplorerServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForecastEvidence {
    pub binding: EvidenceBinding,
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub mission_revision: Revision,
    pub query_digest: Digest,
    pub registration_digest: Digest,
    pub provider_definition_digest: Digest,
    pub provider_provenance: ProviderProvenance,
    pub horizon: TimePeriod,
    pub granularity: Granularity,
    pub metric: CostMetric,
    pub forecast_results_by_time: Vec<ForecastPoint>,
    pub total: MetricValue,
    pub estimated: bool,
    pub incomplete: bool,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub forecast_digest: Digest,
}

impl ForecastEvidence {
    pub fn validate_integrity(&self) -> Result<(), AwsCostExplorerServiceError> {
        let expected = crate::provider::forecast_digest(
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
            Err(AwsCostExplorerServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageForecastProposal {
    pub request: UsageForecastProposalRequest,
    pub evidence: ForecastEvidence,
    pub objective: CostControlObjective,
    pub registration_digest: Digest,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl UsageForecastProposal {
    pub fn state(&self) -> EvidenceState {
        self.evidence.state
    }

    pub fn forecast_digest(&self) -> &Digest {
        &self.evidence.forecast_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.evidence.query_digest
    }

    pub fn is_forecast_available(&self) -> bool {
        self.evidence.state != EvidenceState::ForecastUnavailable
            && self.evidence.state != EvidenceState::AccessLoss
            && self.evidence.state != EvidenceState::ProviderUnknown
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_integrity(&self) -> Result<(), AwsCostExplorerServiceError> {
        self.evidence.validate_integrity()?;
        let expected = forecast_proposal_digest(
            &self.evidence.query_digest,
            &self.evidence.forecast_digest,
            &self.objective,
            &self.registration_digest,
            &self.provider_definition_digest,
        );
        if expected == self.proposal_digest {
            Ok(())
        } else {
            Err(AwsCostExplorerServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DimensionValuesEvidence {
    pub binding: EvidenceBinding,
    pub state: EvidenceState,
    pub partial_reason: Option<PartialReason>,
    pub scope_digest: Digest,
    pub mission_revision: Revision,
    pub query_digest: Digest,
    pub registration_digest: Digest,
    pub provider_definition_digest: Digest,
    pub provider_provenance: ProviderProvenance,
    pub pages_observed: u8,
    pub page_digests: Vec<Digest>,
    pub next_page_token_digests: Vec<Digest>,
    pub dimension: DimensionKey,
    pub values: Vec<crate::model::DimensionValue>,
    pub truncated: bool,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub values_digest: Digest,
}

impl DimensionValuesEvidence {
    pub fn validate_integrity(&self) -> Result<(), AwsCostExplorerServiceError> {
        let expected = dimension_values_digest(
            &self.binding,
            &self.dimension,
            &self.values,
            &self.page_digests,
            self.state,
            self.truncated,
        );
        if expected == self.values_digest {
            Ok(())
        } else {
            Err(AwsCostExplorerServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DimensionValuesProposal {
    pub request: DimensionValuesProposalRequest,
    pub evidence: DimensionValuesEvidence,
    pub objective: CostControlObjective,
    pub registration_digest: Digest,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl DimensionValuesProposal {
    pub fn state(&self) -> EvidenceState {
        self.evidence.state
    }

    pub fn values_digest(&self) -> &Digest {
        &self.evidence.values_digest
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_integrity(&self) -> Result<(), AwsCostExplorerServiceError> {
        self.evidence.validate_integrity()?;
        let expected = dimension_proposal_digest(
            &self.evidence.query_digest,
            &self.evidence.values_digest,
            &self.objective,
            &self.registration_digest,
            &self.provider_definition_digest,
        );
        if expected == self.proposal_digest {
            Ok(())
        } else {
            Err(AwsCostExplorerServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsCostExplorerProposal {
    CostAndUsage(CostUsageProposal),
    UsageForecast(UsageForecastProposal),
    DimensionValues(DimensionValuesProposal),
}

impl AwsCostExplorerProposal {
    pub fn state(&self) -> EvidenceState {
        match self {
            Self::CostAndUsage(proposal) => proposal.state(),
            Self::UsageForecast(proposal) => proposal.state(),
            Self::DimensionValues(proposal) => proposal.state(),
        }
    }

    pub fn proposal_digest(&self) -> &Digest {
        match self {
            Self::CostAndUsage(proposal) => proposal.proposal_digest(),
            Self::UsageForecast(proposal) => proposal.proposal_digest(),
            Self::DimensionValues(proposal) => proposal.proposal_digest(),
        }
    }

    pub fn validate_integrity(&self) -> Result<(), AwsCostExplorerServiceError> {
        match self {
            Self::CostAndUsage(proposal) => proposal.validate_integrity(),
            Self::UsageForecast(proposal) => proposal.validate_integrity(),
            Self::DimensionValues(proposal) => proposal.validate_integrity(),
        }
    }
}

pub struct AwsCostExplorerService<P> {
    scope: AwsCostExplorerScope,
    secret_reference: SecretReference,
    permission_registration: PermissionRegistration,
    provider: P,
    service_definition: AwsCostExplorerServiceDefinition,
    registration: AwsCostExplorerRegistration,
}

impl<P: CostExplorerProvider> fmt::Debug for AwsCostExplorerService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCostExplorerService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("permission_registration", &self.permission_registration)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

pub type AwsCostExplorerOutcomeService<P> = AwsCostExplorerService<P>;

impl<P: CostExplorerProvider> AwsCostExplorerService<P> {
    pub fn new(
        scope: AwsCostExplorerScope,
        secret_reference: SecretReference,
        permission_registration: PermissionRegistration,
        provider: P,
    ) -> Result<Self, AwsCostExplorerServiceError> {
        if secret_reference.scope_digest() != scope.scope_digest()
            || permission_registration.permission_digest() != scope.permission_digest()
        {
            return Err(AwsCostExplorerServiceError::ScopeMismatch);
        }
        let provider_definition = provider.definition();
        let provider_id = crate::model::ProviderId::new(provider_definition.provider_id())?;
        let registration = AwsCostExplorerRegistration::new(
            &scope,
            provider_id,
            provider_definition.provider_version(),
            provider_definition.provider_digest().clone(),
            permission_registration.revision(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            permission_registration,
            provider,
            service_definition: AwsCostExplorerServiceDefinition::new(),
            registration,
        })
    }

    pub fn service_definition(&self) -> &AwsCostExplorerServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &AwsCostExplorerProviderDefinition {
        self.provider.definition()
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn scope(&self) -> &AwsCostExplorerScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission_registration(&self) -> &PermissionRegistration {
        &self.permission_registration
    }

    pub fn revoke_permission(&mut self) -> Result<(), AwsCostExplorerServiceError> {
        self.permission_registration
            .revoke()
            .map_err(AwsCostExplorerServiceError::from)
    }

    pub fn registration(&self) -> &AwsCostExplorerRegistration {
        &self.registration
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::model::RegistrationRevocation, AwsCostExplorerServiceError> {
        self.registration
            .revoke()
            .map_err(AwsCostExplorerServiceError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AwsCostExplorerServiceError> {
        self.secret_reference
            .revoke()
            .map_err(AwsCostExplorerServiceError::from)
    }

    pub fn propose(
        &mut self,
        request: AwsCostExplorerProposalRequest,
    ) -> Result<AwsCostExplorerProposal, AwsCostExplorerServiceError> {
        match request {
            AwsCostExplorerProposalRequest::CostAndUsage(request) => self
                .propose_cost_and_usage(request)
                .map(AwsCostExplorerProposal::CostAndUsage),
            AwsCostExplorerProposalRequest::UsageForecast(request) => self
                .propose_usage_forecast(request)
                .map(AwsCostExplorerProposal::UsageForecast),
            AwsCostExplorerProposalRequest::DimensionValues(request) => self
                .propose_dimension_values(request)
                .map(AwsCostExplorerProposal::DimensionValues),
        }
    }

    pub fn propose_cost_and_usage(
        &mut self,
        request: CostUsageProposalRequest,
    ) -> Result<CostUsageProposal, AwsCostExplorerServiceError> {
        self.ensure_operation(if request.with_resources() {
            AwsOperation::GetCostAndUsageWithResources
        } else {
            AwsOperation::GetCostAndUsage
        })?;
        if request.with_resources()
            && !(request
                .filter()
                .clauses()
                .iter()
                .any(crate::model::FilterClause::is_resource_id)
                || request
                    .group_by()
                    .iter()
                    .any(GroupDefinition::is_resource_id))
        {
            return Err(AwsCostExplorerServiceError::ResourceOperationNotAllowlisted);
        }
        if request.with_resources() && !has_ec2_resource_service_filter(request.filter()) {
            return Err(AwsCostExplorerServiceError::ResourceOperationNotAllowlisted);
        }
        if !request.with_resources()
            && (request
                .filter()
                .clauses()
                .iter()
                .any(crate::model::FilterClause::is_resource_id)
                || request
                    .group_by()
                    .iter()
                    .any(GroupDefinition::is_resource_id))
        {
            return Err(AwsCostExplorerServiceError::QueryTooBroad);
        }
        let query_digest = cost_query_digest(&self.scope, &request);
        let binding = EvidenceBinding::new(
            &self.scope,
            self.registration.registration_digest(),
            query_digest.clone(),
        );
        let mut pages = Vec::new();
        let mut page_digests = Vec::new();
        let mut next_page_token_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut retries = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut next_page_token = None;
        let mut page_number = 1_u8;
        let mut estimated = false;
        let mut incomplete = false;
        let mut truncated = false;
        let mut partial_reason = None;
        let mut group_count = 0_u32;
        let mut byte_count = 0_u32;
        let mut terminal_error = None;

        loop {
            if page_number > request.bounds().max_pages() {
                truncated = true;
                partial_reason = Some(PartialReason::PageCap);
                break;
            }
            let provider_request = CostAndUsageRequest {
                binding: binding.clone(),
                period: request.period().clone(),
                granularity: request.granularity(),
                metrics: request.metrics().to_vec(),
                filter: request.filter().clone(),
                group_by: request.group_by().to_vec(),
                page_number,
                next_page_token: next_page_token.clone(),
                secret_reference_digest: self.secret_reference.reference_digest().clone(),
                credential_revision: self.secret_reference.credential_revision(),
                with_resources: request.with_resources(),
            };
            match self.call_cost_and_usage(
                &provider_request,
                request.bounds().max_retries(),
                &mut provider_errors,
                &mut retries,
            ) {
                Ok(page) => {
                    Self::validate_cost_page(&page, &provider_request)?;
                    estimated |= page.estimated
                        || page.results_by_time.iter().any(|result| result.estimated);
                    incomplete |= page.incomplete;
                    if page.incomplete {
                        partial_reason.get_or_insert(PartialReason::IncompletePage);
                    }
                    page_digests.push(page.page_digest.clone());
                    if let Some(token) = page.next_page_token_digest() {
                        if !seen_tokens.insert(token.clone()) {
                            truncated = true;
                            partial_reason = Some(PartialReason::PaginationLoop);
                            next_page_token_digests.push(token);
                            break;
                        }
                        next_page_token_digests.push(token);
                    }
                    let mut bounded_page = page.results_by_time.clone();
                    for result in &mut bounded_page {
                        if group_count >= request.bounds().max_groups() {
                            result.groups.clear();
                            truncated = true;
                            partial_reason.get_or_insert(PartialReason::GroupCap);
                            continue;
                        }
                        let remaining = request.bounds().max_groups() - group_count;
                        if result.groups.len() as u32 > remaining {
                            result.groups.truncate(remaining as usize);
                            truncated = true;
                            partial_reason.get_or_insert(PartialReason::GroupCap);
                        }
                        group_count += result.groups.len() as u32;
                    }
                    byte_count = byte_count.saturating_add(page.approximate_bytes());
                    if byte_count > request.bounds().max_bytes() {
                        truncated = true;
                        partial_reason.get_or_insert(PartialReason::ByteCap);
                    } else {
                        pages.extend(bounded_page);
                    }
                    next_page_token = page.next_page_token;
                    if next_page_token.is_none() || truncated {
                        break;
                    }
                    page_number = page_number.saturating_add(1);
                }
                Err(error) => {
                    terminal_error = Some(error);
                    if pages.is_empty() {
                        partial_reason = Some(PartialReason::ProviderRejected);
                    } else {
                        truncated = true;
                        partial_reason.get_or_insert(PartialReason::ProviderRejected);
                    }
                    break;
                }
            }
        }

        let state = terminal_error.as_ref().map_or_else(
            || {
                if truncated || incomplete {
                    EvidenceState::Partial
                } else if estimated {
                    EvidenceState::Estimated
                } else {
                    EvidenceState::Complete
                }
            },
            |error| state_for_cost_error(error, !pages.is_empty()),
        );
        let cost_digest = evidence_digest(
            "aws-cost-evidence/v1",
            &binding,
            &page_digests,
            &next_page_token_digests,
            &pages,
            state,
            estimated,
            incomplete,
            truncated,
        );
        let evidence = CostUsageEvidence {
            binding: binding.clone(),
            state,
            partial_reason,
            scope_digest: self.scope.scope_digest().clone(),
            mission_revision: self.scope.mission_revision(),
            query_digest: query_digest.clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_definition_digest: self.provider_definition().provider_digest().clone(),
            provider_provenance: self.provider_definition().provenance(),
            pages_observed: page_digests.len() as u8,
            page_digests,
            next_page_token_digests,
            results_by_time: pages,
            estimated,
            incomplete,
            provider_errors,
            retries,
            truncated,
            cost_digest: cost_digest.clone(),
        };
        let proposal_digest = cost_proposal_digest(
            &query_digest,
            &cost_digest,
            request.objective(),
            self.registration.registration_digest(),
            self.provider_definition().provider_digest(),
        );
        let objective = request.objective().clone();
        Ok(CostUsageProposal {
            request,
            objective,
            evidence,
            registration_digest: self.registration.registration_digest().clone(),
            provider_definition_digest: self.provider_definition().provider_digest().clone(),
            proposal_digest,
        })
    }

    pub fn propose_usage_forecast(
        &mut self,
        request: UsageForecastProposalRequest,
    ) -> Result<UsageForecastProposal, AwsCostExplorerServiceError> {
        self.ensure_operation(AwsOperation::GetUsageForecast)?;
        let horizon = ForecastHorizon::new(request.horizon().clone(), request.granularity())
            .map_err(|_| AwsCostExplorerServiceError::ForecastHorizon)?;
        let query_digest = forecast_query_digest(&self.scope, &request);
        let binding = EvidenceBinding::new(
            &self.scope,
            self.registration.registration_digest(),
            query_digest.clone(),
        );
        let provider_request = UsageForecastRequest {
            binding,
            horizon: horizon.period().clone(),
            granularity: horizon.granularity(),
            metric: request.metric(),
            filter: request.filter().clone(),
            prediction_interval_level: request.prediction_interval_level(),
            secret_reference_digest: self.secret_reference.reference_digest().clone(),
            credential_revision: self.secret_reference.credential_revision(),
        };
        let mut provider_errors = Vec::new();
        let mut retries = Vec::new();
        let response = self.call_usage_forecast(
            &provider_request,
            request.bounds().max_retries(),
            &mut provider_errors,
            &mut retries,
        );
        let (state, response_data, forecast_digest) = match response {
            Ok(response) => {
                Self::validate_forecast_response(&response, &provider_request)?;
                let state = if response.incomplete {
                    EvidenceState::Partial
                } else {
                    EvidenceState::Estimated
                };
                (
                    state,
                    Some(response.clone()),
                    response.forecast_digest.clone(),
                )
            }
            Err(error) => (
                state_for_forecast_error(&error),
                None,
                Digest::from_fields(
                    "aws-forecast-unavailable/v1",
                    &[
                        query_digest.as_str().to_owned(),
                        error.diagnostic_digest().as_str().to_owned(),
                    ],
                ),
            ),
        };
        let (horizon, granularity, metric, points, total, incomplete) = response_data.map_or_else(
            || {
                (
                    request.horizon().clone(),
                    request.granularity(),
                    request.metric(),
                    Vec::new(),
                    MetricValue::default(),
                    false,
                )
            },
            |response| {
                (
                    response.horizon,
                    response.granularity,
                    response.metric,
                    response.forecast_results_by_time,
                    response.total,
                    response.incomplete,
                )
            },
        );
        let evidence = ForecastEvidence {
            binding: provider_request.binding.clone(),
            state,
            scope_digest: self.scope.scope_digest().clone(),
            mission_revision: self.scope.mission_revision(),
            query_digest: query_digest.clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_definition_digest: self.provider_definition().provider_digest().clone(),
            provider_provenance: self.provider_definition().provenance(),
            horizon,
            granularity,
            metric,
            forecast_results_by_time: points,
            total,
            estimated: true,
            incomplete,
            provider_errors,
            retries,
            forecast_digest: forecast_digest.clone(),
        };
        let proposal_digest = forecast_proposal_digest(
            &query_digest,
            &forecast_digest,
            request.objective(),
            self.registration.registration_digest(),
            self.provider_definition().provider_digest(),
        );
        let objective = request.objective().clone();
        Ok(UsageForecastProposal {
            request,
            objective,
            evidence,
            registration_digest: self.registration.registration_digest().clone(),
            provider_definition_digest: self.provider_definition().provider_digest().clone(),
            proposal_digest,
        })
    }

    pub fn propose_dimension_values(
        &mut self,
        request: DimensionValuesProposalRequest,
    ) -> Result<DimensionValuesProposal, AwsCostExplorerServiceError> {
        self.ensure_operation(AwsOperation::GetDimensionValues)?;
        let query_digest = dimension_query_digest(&self.scope, &request);
        let binding = EvidenceBinding::new(
            &self.scope,
            self.registration.registration_digest(),
            query_digest.clone(),
        );
        let mut pages = Vec::new();
        let mut page_digests = Vec::new();
        let mut next_page_token_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut retries = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut next_page_token = None;
        let mut page_number = 1_u8;
        let mut truncated = false;
        let mut partial_reason = None;
        let mut terminal_error = None;
        loop {
            if page_number > request.bounds().max_pages() {
                truncated = true;
                partial_reason = Some(PartialReason::PageCap);
                break;
            }
            let provider_request = DimensionValuesRequest {
                binding: binding.clone(),
                period: request.period().clone(),
                dimension: request.dimension().clone(),
                filter: request.filter().clone(),
                max_results: request.max_results(),
                search_string: request.search_string().map(str::to_owned),
                page_number,
                next_page_token: next_page_token.clone(),
                secret_reference_digest: self.secret_reference.reference_digest().clone(),
                credential_revision: self.secret_reference.credential_revision(),
            };
            match self.call_dimension_values(
                &provider_request,
                request.bounds().max_retries(),
                &mut provider_errors,
                &mut retries,
            ) {
                Ok(page) => {
                    Self::validate_dimension_page(&page, &provider_request)?;
                    page_digests.push(page.page_digest.clone());
                    if let Some(token) = page.next_page_token_digest() {
                        if !seen_tokens.insert(token.clone()) {
                            truncated = true;
                            partial_reason = Some(PartialReason::PaginationLoop);
                            next_page_token_digests.push(token);
                            break;
                        }
                        next_page_token_digests.push(token);
                    }
                    let remaining = request
                        .bounds()
                        .max_dimension_values()
                        .saturating_sub(pages.len() as u32);
                    let mut values = page.values.clone();
                    if values.len() as u32 > remaining {
                        values.truncate(remaining as usize);
                        truncated = true;
                        partial_reason.get_or_insert(PartialReason::DimensionValueCap);
                    }
                    pages.extend(values);
                    next_page_token = page.next_page_token;
                    if next_page_token.is_none() || truncated {
                        break;
                    }
                    page_number = page_number.saturating_add(1);
                }
                Err(error) => {
                    terminal_error = Some(error);
                    partial_reason = Some(PartialReason::ProviderRejected);
                    break;
                }
            }
        }
        let state = terminal_error.as_ref().map_or_else(
            || {
                if truncated {
                    EvidenceState::Partial
                } else {
                    EvidenceState::Complete
                }
            },
            |error| state_for_cost_error(error, !pages.is_empty()),
        );
        let values_digest = dimension_values_digest(
            &binding,
            &request.dimension,
            &pages,
            &page_digests,
            state,
            truncated,
        );
        let evidence = DimensionValuesEvidence {
            binding: binding.clone(),
            state,
            partial_reason,
            scope_digest: self.scope.scope_digest().clone(),
            mission_revision: self.scope.mission_revision(),
            query_digest: query_digest.clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_definition_digest: self.provider_definition().provider_digest().clone(),
            provider_provenance: self.provider_definition().provenance(),
            pages_observed: page_digests.len() as u8,
            page_digests,
            next_page_token_digests,
            dimension: request.dimension().clone(),
            values: pages,
            truncated,
            provider_errors,
            retries,
            values_digest: values_digest.clone(),
        };
        let proposal_digest = dimension_proposal_digest(
            &query_digest,
            &values_digest,
            request.objective(),
            self.registration.registration_digest(),
            self.provider_definition().provider_digest(),
        );
        let objective = request.objective().clone();
        Ok(DimensionValuesProposal {
            request,
            objective,
            evidence,
            registration_digest: self.registration.registration_digest().clone(),
            provider_definition_digest: self.provider_definition().provider_digest().clone(),
            proposal_digest,
        })
    }

    fn ensure_operation(&self, operation: AwsOperation) -> Result<(), AwsCostExplorerServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| AwsCostExplorerServiceError::RegistrationRevoked)?;
        if self.secret_reference.is_revoked() {
            return Err(AwsCostExplorerServiceError::SecretRevoked);
        }
        if !self.permission_registration.allows(operation) {
            return Err(AwsCostExplorerServiceError::PermissionDenied);
        }
        if !self.provider.definition().supports(operation) {
            return Err(AwsCostExplorerServiceError::ProviderOperationUnavailable);
        }
        Ok(())
    }

    fn call_cost_and_usage(
        &mut self,
        request: &CostAndUsageRequest,
        max_attempts: u8,
        provider_errors: &mut Vec<ProviderErrorEvidence>,
        retries: &mut Vec<RetryEvidence>,
    ) -> Result<CostUsagePage, TransportError> {
        for attempt in 1..=max_attempts {
            match self.provider.cost_and_usage(request) {
                Ok(page) => return Ok(page),
                Err(error) => {
                    provider_errors.push(ProviderErrorEvidence {
                        operation: AwsOperation::GetCostAndUsage,
                        kind: error.kind,
                        status_code: error.status_code,
                        attempt,
                        diagnostic_digest: error.diagnostic_digest().clone(),
                    });
                    if error.retryable && attempt < max_attempts {
                        retries.push(RetryEvidence {
                            operation: AwsOperation::GetCostAndUsage,
                            attempt,
                            kind: error.kind,
                            status_code: error.status_code,
                            error_digest: error.diagnostic_digest().clone(),
                        });
                        continue;
                    }
                    return Err(error);
                }
            }
        }
        Err(TransportError::unknown())
    }

    fn call_usage_forecast(
        &mut self,
        request: &UsageForecastRequest,
        max_attempts: u8,
        provider_errors: &mut Vec<ProviderErrorEvidence>,
        retries: &mut Vec<RetryEvidence>,
    ) -> Result<UsageForecastResponse, TransportError> {
        for attempt in 1..=max_attempts {
            match self.provider.usage_forecast(request) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    provider_errors.push(ProviderErrorEvidence {
                        operation: AwsOperation::GetUsageForecast,
                        kind: error.kind,
                        status_code: error.status_code,
                        attempt,
                        diagnostic_digest: error.diagnostic_digest().clone(),
                    });
                    if error.retryable && attempt < max_attempts {
                        retries.push(RetryEvidence {
                            operation: AwsOperation::GetUsageForecast,
                            attempt,
                            kind: error.kind,
                            status_code: error.status_code,
                            error_digest: error.diagnostic_digest().clone(),
                        });
                        continue;
                    }
                    return Err(error);
                }
            }
        }
        Err(TransportError::unknown())
    }

    fn call_dimension_values(
        &mut self,
        request: &DimensionValuesRequest,
        max_attempts: u8,
        provider_errors: &mut Vec<ProviderErrorEvidence>,
        retries: &mut Vec<RetryEvidence>,
    ) -> Result<DimensionValuesPage, TransportError> {
        for attempt in 1..=max_attempts {
            match self.provider.dimension_values(request) {
                Ok(page) => return Ok(page),
                Err(error) => {
                    provider_errors.push(ProviderErrorEvidence {
                        operation: AwsOperation::GetDimensionValues,
                        kind: error.kind,
                        status_code: error.status_code,
                        attempt,
                        diagnostic_digest: error.diagnostic_digest().clone(),
                    });
                    if error.retryable && attempt < max_attempts {
                        retries.push(RetryEvidence {
                            operation: AwsOperation::GetDimensionValues,
                            attempt,
                            kind: error.kind,
                            status_code: error.status_code,
                            error_digest: error.diagnostic_digest().clone(),
                        });
                        continue;
                    }
                    return Err(error);
                }
            }
        }
        Err(TransportError::unknown())
    }

    fn validate_cost_page(
        page: &CostUsagePage,
        request: &CostAndUsageRequest,
    ) -> Result<(), AwsCostExplorerServiceError> {
        page.validate_digest()
            .map_err(|_| AwsCostExplorerServiceError::TamperedEvidence)?;
        Self::validate_binding(&page.binding, &request.binding)?;
        if page.page_number != request.page_number
            || page.metrics != request.metrics
            || page.group_by != request.group_by
        {
            return Err(AwsCostExplorerServiceError::QueryDrift);
        }
        if page.results_by_time.iter().any(|result| {
            result.time_period.start() < request.period.start()
                || result.time_period.end() > request.period.end()
                || result.time_period.start() >= result.time_period.end()
        }) {
            return Err(AwsCostExplorerServiceError::ResponseShape);
        }
        for result in &page.results_by_time {
            validate_metric_map(&result.total)?;
            for group in &result.groups {
                if group.keys.len() != request.group_by.len()
                    || group
                        .metrics
                        .keys()
                        .any(|metric| !request.metrics.contains(metric))
                {
                    return Err(AwsCostExplorerServiceError::ResponseShape);
                }
                validate_metric_map(&group.metrics)?;
            }
        }
        Ok(())
    }

    fn validate_forecast_response(
        response: &UsageForecastResponse,
        request: &UsageForecastRequest,
    ) -> Result<(), AwsCostExplorerServiceError> {
        response
            .validate_digest()
            .map_err(|_| AwsCostExplorerServiceError::TamperedEvidence)?;
        Self::validate_binding(&response.binding, &request.binding)?;
        if response.horizon != request.horizon
            || response.granularity != request.granularity
            || response.metric != request.metric
        {
            return Err(AwsCostExplorerServiceError::QueryDrift);
        }
        validate_metric_value(response.metric, &response.total)?;
        for point in &response.forecast_results_by_time {
            if point.time_period.start() < request.horizon.start()
                || point.time_period.end() > request.horizon.end()
                || point.time_period.start() >= point.time_period.end()
            {
                return Err(AwsCostExplorerServiceError::ResponseShape);
            }
            validate_metric_value(response.metric, &point.mean)?;
            if let Some(value) = &point.prediction_interval_lower_bound {
                validate_metric_value(response.metric, value)?;
            }
            if let Some(value) = &point.prediction_interval_upper_bound {
                validate_metric_value(response.metric, value)?;
            }
        }
        Ok(())
    }

    fn validate_dimension_page(
        page: &DimensionValuesPage,
        request: &DimensionValuesRequest,
    ) -> Result<(), AwsCostExplorerServiceError> {
        page.validate_digest()
            .map_err(|_| AwsCostExplorerServiceError::TamperedEvidence)?;
        Self::validate_binding(&page.binding, &request.binding)?;
        if page.period != request.period
            || page.dimension != request.dimension
            || page.return_size != page.values.len() as u32
        {
            return Err(AwsCostExplorerServiceError::QueryDrift);
        }
        if page.values.iter().any(|value| value.value.is_empty()) {
            return Err(AwsCostExplorerServiceError::ResponseShape);
        }
        Ok(())
    }

    fn validate_binding(
        actual: &EvidenceBinding,
        expected: &EvidenceBinding,
    ) -> Result<(), AwsCostExplorerServiceError> {
        match (
            &actual.account_or_billing_view,
            &expected.account_or_billing_view,
        ) {
            (
                crate::model::AwsAccountBinding::Account { account_id: actual },
                crate::model::AwsAccountBinding::Account {
                    account_id: expected,
                },
            ) if actual != expected => return Err(AwsCostExplorerServiceError::AccountDrift),
            (
                crate::model::AwsAccountBinding::BillingView {
                    billing_view_arn: actual,
                },
                crate::model::AwsAccountBinding::BillingView {
                    billing_view_arn: expected,
                },
            ) if actual != expected => {
                return Err(AwsCostExplorerServiceError::BillingViewDrift);
            }
            (
                crate::model::AwsAccountBinding::Account { .. },
                crate::model::AwsAccountBinding::BillingView { .. },
            )
            | (
                crate::model::AwsAccountBinding::BillingView { .. },
                crate::model::AwsAccountBinding::Account { .. },
            ) => {
                return Err(AwsCostExplorerServiceError::ScopeMismatch);
            }
            _ => {}
        }
        if actual.project_id != expected.project_id {
            return Err(AwsCostExplorerServiceError::ProjectDrift);
        }
        if actual.mission_id != expected.mission_id {
            return Err(AwsCostExplorerServiceError::MissionDrift);
        }
        if actual.work_product_id != expected.work_product_id {
            return Err(AwsCostExplorerServiceError::WorkProductDrift);
        }
        if actual.mission_revision != expected.mission_revision {
            return Err(AwsCostExplorerServiceError::MissionRevisionDrift);
        }
        if actual.scope_digest != expected.scope_digest
            || actual.permission_digest != expected.permission_digest
            || actual.consent_digest != expected.consent_digest
        {
            return Err(AwsCostExplorerServiceError::FenceViolation);
        }
        if actual.registration_digest != expected.registration_digest {
            return Err(AwsCostExplorerServiceError::RegistrationDrift);
        }
        if actual.query_digest != expected.query_digest {
            return Err(AwsCostExplorerServiceError::QueryDrift);
        }
        Ok(())
    }
}

fn validate_metric_map(metrics: &MetricMap) -> Result<(), AwsCostExplorerServiceError> {
    for (metric, value) in metrics {
        validate_metric_value(*metric, value)?;
    }
    Ok(())
}

fn validate_metric_value(
    metric: CostMetric,
    value: &MetricValue,
) -> Result<(), AwsCostExplorerServiceError> {
    if metric.is_currency() && value.unit() != "USD" {
        Err(AwsCostExplorerServiceError::ResponseShape)
    } else {
        Ok(())
    }
}

fn has_ec2_resource_service_filter(filter: &CostFilter) -> bool {
    filter.clauses().iter().any(|clause| {
        matches!(
            clause,
            crate::model::FilterClause::Dimension {
                key,
                values,
                ..
            } if key.as_str() == "SERVICE"
                && values
                    .iter()
                    .any(|value| value == "Amazon Elastic Compute Cloud - Compute")
        )
    })
}

fn state_for_cost_error(error: &TransportError, has_data: bool) -> EvidenceState {
    match error.kind {
        ProviderErrorKind::AccessDenied | ProviderErrorKind::NotFound => EvidenceState::AccessLoss,
        _ if has_data => EvidenceState::Partial,
        _ => EvidenceState::ProviderUnknown,
    }
}

fn state_for_forecast_error(error: &TransportError) -> EvidenceState {
    match error.kind {
        ProviderErrorKind::InvalidRequest => EvidenceState::ForecastUnavailable,
        ProviderErrorKind::AccessDenied | ProviderErrorKind::NotFound => EvidenceState::AccessLoss,
        _ => EvidenceState::ProviderUnknown,
    }
}

fn bounds_digest_fields(bounds: &EvidenceBounds) -> Vec<String> {
    vec![
        bounds.max_pages().to_string(),
        bounds.max_groups().to_string(),
        bounds.max_dimension_values().to_string(),
        bounds.max_bytes().to_string(),
        bounds.max_retries().to_string(),
    ]
}

fn cost_query_digest(scope: &AwsCostExplorerScope, request: &CostUsageProposalRequest) -> Digest {
    let mut fields = vec![
        scope.scope_digest().as_str().to_owned(),
        request.period().canonical(),
        request.granularity().api_name().to_owned(),
        request
            .metrics()
            .iter()
            .map(|metric| metric.api_name())
            .collect::<Vec<_>>()
            .join(","),
        request.filter().canonical(),
        request
            .group_by()
            .iter()
            .map(GroupDefinition::canonical)
            .collect::<Vec<_>>()
            .join(","),
        request.objective().digest().as_str().to_owned(),
        request.with_resources().to_string(),
    ];
    fields.extend(bounds_digest_fields(request.bounds()));
    Digest::from_fields("aws-cost-query/v1", &fields)
}

fn forecast_query_digest(
    scope: &AwsCostExplorerScope,
    request: &UsageForecastProposalRequest,
) -> Digest {
    let mut fields = vec![
        scope.scope_digest().as_str().to_owned(),
        request.horizon().canonical(),
        request.granularity().api_name().to_owned(),
        request.metric().api_name().to_owned(),
        request.filter().canonical(),
        request
            .prediction_interval_level()
            .map_or_else(String::new, |value| value.to_string()),
        request.objective().digest().as_str().to_owned(),
    ];
    fields.extend(bounds_digest_fields(request.bounds()));
    Digest::from_fields("aws-forecast-query/v1", &fields)
}

fn dimension_query_digest(
    scope: &AwsCostExplorerScope,
    request: &DimensionValuesProposalRequest,
) -> Digest {
    let mut fields = vec![
        scope.scope_digest().as_str().to_owned(),
        request.period().canonical(),
        request.dimension().as_str().to_owned(),
        request.filter().canonical(),
        request.max_results().to_string(),
        request.search_string().unwrap_or_default().to_owned(),
        request.objective().digest().as_str().to_owned(),
    ];
    fields.extend(bounds_digest_fields(request.bounds()));
    Digest::from_fields("aws-dimension-query/v1", &fields)
}

fn evidence_digest(
    domain: &str,
    binding: &EvidenceBinding,
    page_digests: &[Digest],
    next_page_token_digests: &[Digest],
    pages: &[crate::provider::CostResultByTime],
    state: EvidenceState,
    estimated: bool,
    incomplete: bool,
    truncated: bool,
) -> Digest {
    let mut fields = binding.canonical_fields();
    fields.extend([
        page_digests
            .iter()
            .map(Digest::as_str)
            .collect::<Vec<_>>()
            .join(","),
        next_page_token_digests
            .iter()
            .map(Digest::as_str)
            .collect::<Vec<_>>()
            .join(","),
        pages.len().to_string(),
        state_string(state).to_owned(),
        estimated.to_string(),
        incomplete.to_string(),
        truncated.to_string(),
    ]);
    Digest::from_fields(domain, &fields)
}

fn cost_proposal_digest(
    query_digest: &Digest,
    cost_digest: &Digest,
    objective: &CostControlObjective,
    registration_digest: &Digest,
    provider_digest: &Digest,
) -> Digest {
    Digest::from_fields(
        "aws-cost-proposal/v1",
        &[
            query_digest.as_str().to_owned(),
            cost_digest.as_str().to_owned(),
            objective.digest().as_str().to_owned(),
            registration_digest.as_str().to_owned(),
            provider_digest.as_str().to_owned(),
        ],
    )
}

fn forecast_proposal_digest(
    query_digest: &Digest,
    forecast_digest: &Digest,
    objective: &CostControlObjective,
    registration_digest: &Digest,
    provider_digest: &Digest,
) -> Digest {
    Digest::from_fields(
        "aws-forecast-proposal/v1",
        &[
            query_digest.as_str().to_owned(),
            forecast_digest.as_str().to_owned(),
            objective.digest().as_str().to_owned(),
            registration_digest.as_str().to_owned(),
            provider_digest.as_str().to_owned(),
        ],
    )
}

fn dimension_values_digest(
    binding: &EvidenceBinding,
    dimension: &DimensionKey,
    values: &[crate::model::DimensionValue],
    page_digests: &[Digest],
    state: EvidenceState,
    truncated: bool,
) -> Digest {
    let mut fields = binding.canonical_fields();
    fields.extend([
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
        page_digests
            .iter()
            .map(Digest::as_str)
            .collect::<Vec<_>>()
            .join(","),
        state_string(state).to_owned(),
        truncated.to_string(),
    ]);
    Digest::from_fields("aws-dimension-values/v1", &fields)
}

fn dimension_proposal_digest(
    query_digest: &Digest,
    values_digest: &Digest,
    objective: &CostControlObjective,
    registration_digest: &Digest,
    provider_digest: &Digest,
) -> Digest {
    Digest::from_fields(
        "aws-dimension-proposal/v1",
        &[
            query_digest.as_str().to_owned(),
            values_digest.as_str().to_owned(),
            objective.digest().as_str().to_owned(),
            registration_digest.as_str().to_owned(),
            provider_digest.as_str().to_owned(),
        ],
    )
}

fn state_string(state: EvidenceState) -> &'static str {
    match state {
        EvidenceState::Complete => "complete",
        EvidenceState::Estimated => "estimated",
        EvidenceState::Partial => "partial",
        EvidenceState::ForecastUnavailable => "forecast_unavailable",
        EvidenceState::AccessLoss => "access_loss",
        EvidenceState::ProviderUnknown => "provider_unknown",
    }
}

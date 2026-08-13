//! A credentialed Meta Marketing read slice built on the paid-social SDK.
//!
//! This module is intentionally a connector-owned vertical boundary.  It wires
//! the existing Meta adapter into a small service and Mission-facing consumer,
//! while keeping the central provider registry empty and the connection state
//! disconnected.  The consumer returns an immutable read result and receipt;
//! it cannot mutate a Mission or obtain Effect authority.

use crate::paid_social::{MetaAdapter, PaidSocialProvider};
use crate::paid_social_types::{
    CausalStatus, ConnectorError, CredentialResolver, InsightsQuery, OpaqueCursor,
    PaidSocialReadAdapter, ProvenanceClass, ProviderAttribution, RateLimitObservation, ReadCommand,
    ReadObservation, ReadRequest, ReadSurface, ResourceKind, ReviewState, WritePolicy, WriteState,
    digest_bytes,
};
use crate::{ConnectorScope, DispatchBudget, FreshnessWindow, ProviderCapabilitySupport};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

pub const META_MARKETING_ADAPTER_ID: &str = "paid-social.meta";
pub const META_MARKETING_ADAPTER_VERSION: u32 = 1;
pub const META_MARKETING_READ_RECEIPT_SCHEMA: &str =
    "hartevo-paid-social-meta-marketing-read-receipt/v1";

/// Paid-social provider registrations stay empty until the Mission route and
/// reverse mapping are approved.  This is deliberately a slice-local constant,
/// not a second registry.
pub const META_MARKETING_REGISTRATIONS: &[ProviderCapabilitySupport] = &[];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginConnectionState {
    Disconnected,
}

/// The provider slice has no catalog registration and therefore remains
/// disconnected even when a caller supplies a valid credential lease.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetaMarketingReadPlugin;

impl MetaMarketingReadPlugin {
    pub const fn registrations() -> &'static [ProviderCapabilitySupport] {
        META_MARKETING_REGISTRATIONS
    }

    pub const fn connection_state() -> PluginConnectionState {
        PluginConnectionState::Disconnected
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaMarketingAccountScope {
    account_id: String,
    ad_account_id: String,
}

impl MetaMarketingAccountScope {
    pub fn new(
        account_id: impl Into<String>,
        ad_account_id: impl Into<String>,
    ) -> Result<Self, ConnectorError> {
        let account_id = account_id.into();
        let ad_account_id = normalize_meta_ad_account_id(&ad_account_id.into())?;
        if !valid_identifier(&account_id) {
            return Err(ConnectorError::InvalidRequest);
        }
        Ok(Self {
            account_id,
            ad_account_id,
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn ad_account_id(&self) -> &str {
        &self.ad_account_id
    }

    pub fn digest(&self, connector_scope: &ConnectorScope) -> String {
        digest_bytes(
            format!(
                "{}:{}:{}",
                connector_scope.digest(),
                self.account_id,
                self.ad_account_id
            )
            .as_bytes(),
        )
    }

    fn matches(&self, connector_scope: &ConnectorScope) -> Result<bool, ConnectorError> {
        Ok(self.ad_account_id == normalize_meta_ad_account_id(connector_scope.account_id())?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MetaMarketingCommand {
    Resource(ResourceKind),
    Insights { query: InsightsQuery },
}

impl MetaMarketingCommand {
    fn to_read_command(&self, cursor: Option<OpaqueCursor>) -> ReadCommand {
        match self {
            Self::Resource(kind) => ReadCommand::Resource(*kind),
            Self::Insights { query } => ReadCommand::Insights {
                query: query.clone(),
                cursor,
            },
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Resource(_) => "resource",
            Self::Insights { .. } => "insights",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaMarketingReadRequest {
    pub scope: ConnectorScope,
    pub account_scope: MetaMarketingAccountScope,
    pub connection_id: String,
    pub secret_reference: crate::SecretReference,
    pub lease: crate::CredentialLease,
    pub command: MetaMarketingCommand,
    pub provenance: ProvenanceClass,
    pub requested_at: DateTime<Utc>,
}

impl MetaMarketingReadRequest {
    fn validate(&self) -> Result<(), ConnectorError> {
        if self.scope.provider_id() != PaidSocialProvider::Meta.provider_id()
            || !self.account_scope.matches(&self.scope)?
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        if self.secret_reference.scope() != &self.scope
            || self.lease.scope() != &self.scope
            || self.lease.adapter().adapter_id() != META_MARKETING_ADAPTER_ID
            || self.lease.adapter().adapter_version() != META_MARKETING_ADAPTER_VERSION
        {
            return Err(ConnectorError::InvalidCredentialLease);
        }
        let adapter_request = self.adapter_request(None);
        adapter_request.validate()
    }

    fn adapter_request(&self, cursor: Option<OpaqueCursor>) -> ReadRequest {
        ReadRequest {
            scope: self.scope.clone(),
            connection_id: self.connection_id.clone(),
            secret_reference: self.secret_reference.clone(),
            lease: self.lease.clone(),
            surface: ReadSurface::MetaMarketing,
            command: self.command.to_read_command(cursor),
            provenance: self.provenance,
            requested_at: self.requested_at,
        }
    }

    fn scope_digest(&self) -> String {
        self.account_scope.digest(&self.scope)
    }
}

/// The provider object delegates to the existing bearer-token Meta adapter.
/// It has no write capability and carries no registry entry.
#[derive(Clone, Debug)]
pub struct MetaMarketingReadProvider {
    adapter: MetaAdapter,
}

impl MetaMarketingReadProvider {
    pub fn new(adapter: MetaAdapter) -> Self {
        Self { adapter }
    }

    pub fn adapter(&self) -> &MetaAdapter {
        &self.adapter
    }

    pub const fn connection_state(&self) -> PluginConnectionState {
        PluginConnectionState::Disconnected
    }

    pub const fn registrations(&self) -> &'static [ProviderCapabilitySupport] {
        META_MARKETING_REGISTRATIONS
    }
}

impl PaidSocialReadAdapter for MetaMarketingReadProvider {
    fn provider(&self) -> PaidSocialProvider {
        PaidSocialProvider::Meta
    }

    fn read(
        &self,
        request: ReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<ReadObservation, ConnectorError> {
        self.adapter.read(request, resolver)
    }

    fn prepare_effect(
        &self,
        operation: &str,
    ) -> Result<crate::paid_social_types::PreparedEffect, ConnectorError> {
        self.adapter.prepare_effect(operation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaMarketingReadPolicy {
    pub freshness_ttl: Duration,
    pub cost_minor: i64,
}

impl MetaMarketingReadPolicy {
    pub fn new(freshness_ttl: Duration, cost_minor: i64) -> Result<Self, ConnectorError> {
        if freshness_ttl <= Duration::zero() || cost_minor < 0 {
            return Err(ConnectorError::InvalidFreshness);
        }
        Ok(Self {
            freshness_ttl,
            cost_minor,
        })
    }
}

impl Default for MetaMarketingReadPolicy {
    fn default() -> Self {
        Self {
            freshness_ttl: Duration::minutes(15),
            cost_minor: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableCursor {
    scope_digest: String,
    command_digest: String,
    sequence: u64,
    next: Option<OpaqueCursor>,
    complete: bool,
    updated_at: DateTime<Utc>,
}

impl DurableCursor {
    fn new(
        scope_digest: String,
        command_digest: String,
        sequence: u64,
        next: Option<OpaqueCursor>,
        complete: bool,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, ConnectorError> {
        let cursor = Self {
            scope_digest,
            command_digest,
            sequence,
            next,
            complete,
            updated_at,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn command_digest(&self) -> &str {
        &self.command_digest
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn next(&self) -> Option<&OpaqueCursor> {
        self.next.as_ref()
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn next_digest(&self) -> Option<String> {
        self.next.as_ref().map(cursor_digest)
    }

    pub fn checkpoint(&self) -> Result<Vec<u8>, ConnectorError> {
        serde_json::to_vec(self).map_err(|_| ConnectorError::InvalidCursor)
    }

    pub fn from_checkpoint(bytes: &[u8]) -> Result<Self, ConnectorError> {
        let cursor: Self =
            serde_json::from_slice(bytes).map_err(|_| ConnectorError::InvalidCursor)?;
        cursor.validate()?;
        Ok(cursor)
    }

    fn matches(&self, scope_digest: &str, command_digest: &str) -> bool {
        self.scope_digest == scope_digest && self.command_digest == command_digest
    }

    fn validate(&self) -> Result<(), ConnectorError> {
        if !is_digest(&self.scope_digest)
            || !is_digest(&self.command_digest)
            || self.sequence == 0
            || (self.complete && self.next.is_some())
        {
            return Err(ConnectorError::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BudgetSnapshot {
    rate_remaining: u64,
    quota_limit: u64,
    quota_used: u64,
    cost_limit_minor: i64,
    cost_used_minor: i64,
}

impl BudgetSnapshot {
    fn capture(budget: &DispatchBudget) -> Self {
        Self {
            rate_remaining: budget.rate_limit.remaining(),
            quota_limit: budget.quota.limit(),
            quota_used: budget.quota.used(),
            cost_limit_minor: budget.cost.limit_minor(),
            cost_used_minor: budget.cost.used_minor(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceReceipt {
    pub provider: PaidSocialProvider,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub provider_request_id: Option<String>,
    pub query_digest: String,
    pub response_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreshnessReceipt {
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub ttl_seconds: i64,
    pub fresh_at_observation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuotaReceipt {
    pub configured_limit: u64,
    pub used_before: u64,
    pub used_after: u64,
    pub rate_remaining_before: u64,
    pub rate_remaining_after: u64,
    pub provider_rate_limit: RateLimitObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CostReceipt {
    pub configured_limit_minor: i64,
    pub charged_minor: i64,
    pub used_before_minor: i64,
    pub used_after_minor: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationKind {
    ProviderReportedResource,
    ProviderReportedMetric,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CursorReceipt {
    pub page_sequence: u64,
    pub current_digest: Option<String>,
    pub next_digest: Option<String>,
    pub durable_checkpoint_digest: String,
    pub provider_complete: bool,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DigestReceipt {
    pub observation_digest: String,
    pub records_digest: String,
    pub request_digest: String,
    pub response_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClassificationReceipt {
    pub kind: ClassificationKind,
    pub command_kind: String,
    pub provider_attribution_models: Vec<ProviderAttribution>,
    pub review_state: ReviewState,
    pub provenance: ProvenanceClass,
    pub causal_status: CausalStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaMarketingReadReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub mission_id: Option<String>,
    pub provider: PaidSocialProvider,
    pub connection_state: PluginConnectionState,
    pub connection_id: String,
    pub account_id: String,
    pub ad_account_id: String,
    pub account_scope_digest: String,
    pub requested_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub source: SourceReceipt,
    pub freshness: FreshnessReceipt,
    pub quota: QuotaReceipt,
    pub cost: CostReceipt,
    pub cursor: CursorReceipt,
    pub digests: DigestReceipt,
    pub classification: ClassificationReceipt,
    pub causal_status: CausalStatus,
    pub write_policy: WritePolicy,
}

impl MetaMarketingReadReceipt {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if self.schema_version != META_MARKETING_READ_RECEIPT_SCHEMA
            || self.provider != PaidSocialProvider::Meta
            || self.connection_state != PluginConnectionState::Disconnected
            || self.causal_status != CausalStatus::NotClaimed
            || self.classification.causal_status != CausalStatus::NotClaimed
            || self.write_policy.state != WriteState::Disabled
            || !is_digest(&self.account_scope_digest)
            || !is_digest(&self.source.query_digest)
            || !is_digest(&self.source.response_digest)
            || !is_digest(&self.digests.observation_digest)
            || !is_digest(&self.digests.records_digest)
            || !is_digest(&self.digests.request_digest)
            || !is_digest(&self.digests.response_digest)
            || self.source.status / 100 != 2
            || self.freshness.valid_until <= self.freshness.observed_at
            || self.freshness.observed_at != self.observed_at
        {
            return Err(ConnectorError::InvalidObservation);
        }
        if self
            .classification
            .provider_attribution_models
            .iter()
            .any(|attribution| attribution.causal_status != CausalStatus::NotClaimed)
        {
            return Err(ConnectorError::InvalidObservation);
        }
        if let Some(mission_id) = &self.mission_id
            && !valid_identifier(mission_id)
        {
            return Err(ConnectorError::InvalidMission);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaMarketingReadResult {
    pub observation: ReadObservation,
    pub receipt: MetaMarketingReadReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionReadResult {
    pub mission_id: String,
    pub observation: ReadObservation,
    pub receipt: MetaMarketingReadReceipt,
}

#[derive(Clone, Copy, Debug)]
struct ReceiptCursorContext<'a> {
    sent: Option<&'a OpaqueCursor>,
    next: Option<&'a OpaqueCursor>,
    page_sequence: u64,
    checkpoint_digest: &'a str,
}

#[derive(Clone, Copy, Debug)]
struct ReceiptBudgetContext {
    before: BudgetSnapshot,
    after: BudgetSnapshot,
}

#[derive(Debug)]
pub struct MetaMarketingReadService {
    provider: MetaMarketingReadProvider,
    budget: DispatchBudget,
    policy: MetaMarketingReadPolicy,
    durable_cursor: Option<DurableCursor>,
}

impl MetaMarketingReadService {
    pub fn new(
        provider: MetaMarketingReadProvider,
        budget: DispatchBudget,
        policy: MetaMarketingReadPolicy,
    ) -> Result<Self, ConnectorError> {
        if provider.provider() != PaidSocialProvider::Meta {
            return Err(ConnectorError::ScopeMismatch);
        }
        Ok(Self {
            provider,
            budget,
            policy,
            durable_cursor: None,
        })
    }

    pub fn provider(&self) -> &MetaMarketingReadProvider {
        &self.provider
    }

    pub fn budget(&self) -> &DispatchBudget {
        &self.budget
    }

    pub fn policy(&self) -> &MetaMarketingReadPolicy {
        &self.policy
    }

    pub fn durable_cursor(&self) -> Option<&DurableCursor> {
        self.durable_cursor.as_ref()
    }

    pub fn restore_cursor(&mut self, cursor: DurableCursor) -> Result<(), ConnectorError> {
        cursor.validate()?;
        self.durable_cursor = Some(cursor);
        Ok(())
    }

    pub fn restore_cursor_checkpoint(&mut self, bytes: &[u8]) -> Result<(), ConnectorError> {
        self.restore_cursor(DurableCursor::from_checkpoint(bytes)?)
    }

    pub fn cursor_checkpoint(&self) -> Result<Option<Vec<u8>>, ConnectorError> {
        self.durable_cursor
            .as_ref()
            .map(DurableCursor::checkpoint)
            .transpose()
    }

    pub fn clear_cursor(&mut self) {
        self.durable_cursor = None;
    }

    pub fn read(
        &mut self,
        request: &MetaMarketingReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<MetaMarketingReadResult, ConnectorError> {
        self.read_for_mission(None, request, resolver)
    }

    fn read_for_mission(
        &mut self,
        mission_id: Option<&str>,
        request: &MetaMarketingReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<MetaMarketingReadResult, ConnectorError> {
        if let Some(mission_id) = mission_id
            && !valid_identifier(mission_id)
        {
            return Err(ConnectorError::InvalidMission);
        }
        request.validate()?;
        if !request.scope.scopes().contains("ads_read") {
            return Err(ConnectorError::MissingPermission);
        }

        let command_digest = digest_serializable(&request.command)?;
        let scope_digest = request.scope_digest();
        let (sent_cursor, page_sequence) = self.cursor_for(&scope_digest, &command_digest)?;
        let adapter_request = request.adapter_request(sent_cursor.clone());
        let before = BudgetSnapshot::capture(&self.budget);
        self.budget
            .admit(request.requested_at, self.policy.cost_minor)
            .map_err(ConnectorError::Budget)?;
        let after = BudgetSnapshot::capture(&self.budget);

        let observation = self.provider.read(adapter_request, resolver)?;
        observation.validate()?;
        let next_cursor = observation.pagination.next.clone();
        let complete = next_cursor.is_none();
        let durable_cursor = DurableCursor::new(
            scope_digest,
            command_digest,
            page_sequence,
            next_cursor.clone(),
            complete,
            observation.observed_at,
        )?;
        let checkpoint_digest = digest_bytes(&durable_cursor.checkpoint()?);
        self.durable_cursor = Some(durable_cursor);
        let receipt = build_receipt(
            mission_id,
            request,
            &observation,
            ReceiptCursorContext {
                sent: sent_cursor.as_ref(),
                next: next_cursor.as_ref(),
                page_sequence,
                checkpoint_digest: &checkpoint_digest,
            },
            ReceiptBudgetContext { before, after },
            &self.policy,
        )?;
        receipt.validate()?;
        Ok(MetaMarketingReadResult {
            observation,
            receipt,
        })
    }

    fn cursor_for(
        &self,
        scope_digest: &str,
        command_digest: &str,
    ) -> Result<(Option<OpaqueCursor>, u64), ConnectorError> {
        match &self.durable_cursor {
            None => Ok((None, 1)),
            Some(cursor) if !cursor.matches(scope_digest, command_digest) => {
                Err(ConnectorError::CursorMismatch)
            }
            Some(cursor) if cursor.complete => Ok((None, 1)),
            Some(cursor) => Ok((
                cursor.next.clone(),
                cursor
                    .sequence
                    .checked_add(1)
                    .ok_or(ConnectorError::InvalidCursor)?,
            )),
        }
    }
}

/// A Mission-facing read consumer.  It only returns connector observations and
/// receipts; it has no Mission mutation or Effect Broker capability.
#[derive(Debug)]
pub struct MetaMarketingMissionConsumer {
    service: MetaMarketingReadService,
}

impl MetaMarketingMissionConsumer {
    pub fn new(service: MetaMarketingReadService) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &MetaMarketingReadService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut MetaMarketingReadService {
        &mut self.service
    }

    pub fn consume(
        &mut self,
        mission_id: impl Into<String>,
        request: &MetaMarketingReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<MissionReadResult, ConnectorError> {
        let mission_id = mission_id.into();
        if !valid_identifier(&mission_id) {
            return Err(ConnectorError::InvalidMission);
        }
        let result = self
            .service
            .read_for_mission(Some(&mission_id), request, resolver)?;
        Ok(MissionReadResult {
            mission_id,
            observation: result.observation,
            receipt: result.receipt,
        })
    }
}

fn build_receipt(
    mission_id: Option<&str>,
    request: &MetaMarketingReadRequest,
    observation: &ReadObservation,
    cursor_context: ReceiptCursorContext<'_>,
    budget_context: ReceiptBudgetContext,
    policy: &MetaMarketingReadPolicy,
) -> Result<MetaMarketingReadReceipt, ConnectorError> {
    let cursor = build_cursor_receipt(cursor_context, observation);
    let ReceiptCursorContext {
        page_sequence,
        checkpoint_digest,
        ..
    } = cursor_context;
    let ReceiptBudgetContext { before, after } = budget_context;
    let valid_until = observation
        .observed_at
        .checked_add_signed(policy.freshness_ttl)
        .ok_or(ConnectorError::InvalidFreshness)?;
    let freshness_window =
        FreshnessWindow::new(observation.observed_at, valid_until, page_sequence)
            .map_err(|_| ConnectorError::InvalidFreshness)?;
    freshness_window
        .validate_at(observation.observed_at)
        .map_err(|_| ConnectorError::InvalidFreshness)?;
    let records_digest = digest_serializable(&observation.records)?;
    let observation_digest = digest_serializable(observation)?;
    let account_scope_digest = request.scope_digest();
    let source = build_source_receipt(observation);
    let classification = build_classification_receipt(request, observation);
    let receipt_id = digest_bytes(
        format!(
            "{}:{}:{}:{}",
            mission_id.unwrap_or("mission-unspecified"),
            account_scope_digest,
            observation.observation_id,
            checkpoint_digest
        )
        .as_bytes(),
    );
    Ok(MetaMarketingReadReceipt {
        schema_version: META_MARKETING_READ_RECEIPT_SCHEMA.to_owned(),
        receipt_id: format!("paid-social-receipt-{receipt_id}"),
        mission_id: mission_id.map(str::to_owned),
        provider: PaidSocialProvider::Meta,
        connection_state: PluginConnectionState::Disconnected,
        connection_id: request.connection_id.clone(),
        account_id: request.account_scope.account_id.clone(),
        ad_account_id: request.account_scope.ad_account_id.clone(),
        account_scope_digest,
        requested_at: request.requested_at,
        observed_at: observation.observed_at,
        source,
        freshness: FreshnessReceipt {
            observed_at: observation.observed_at,
            valid_until,
            ttl_seconds: policy.freshness_ttl.num_seconds(),
            fresh_at_observation: true,
        },
        quota: QuotaReceipt {
            configured_limit: before.quota_limit,
            used_before: before.quota_used,
            used_after: after.quota_used,
            rate_remaining_before: before.rate_remaining,
            rate_remaining_after: after.rate_remaining,
            provider_rate_limit: observation.rate_limit.clone(),
        },
        cost: CostReceipt {
            configured_limit_minor: before.cost_limit_minor,
            charged_minor: policy.cost_minor,
            used_before_minor: before.cost_used_minor,
            used_after_minor: after.cost_used_minor,
        },
        cursor,
        digests: DigestReceipt {
            observation_digest,
            records_digest,
            request_digest: observation.request_evidence.query_digest.clone(),
            response_digest: observation.request_evidence.response_digest.clone(),
        },
        classification,
        causal_status: CausalStatus::NotClaimed,
        write_policy: WritePolicy::default(),
    })
}

fn build_source_receipt(observation: &ReadObservation) -> SourceReceipt {
    SourceReceipt {
        provider: PaidSocialProvider::Meta,
        method: observation.request_evidence.method.clone(),
        path: observation.request_evidence.path.clone(),
        status: observation.request_evidence.status,
        provider_request_id: observation.request_evidence.provider_request_id.clone(),
        query_digest: observation.request_evidence.query_digest.clone(),
        response_digest: observation.request_evidence.response_digest.clone(),
    }
}

fn build_classification_receipt(
    request: &MetaMarketingReadRequest,
    observation: &ReadObservation,
) -> ClassificationReceipt {
    ClassificationReceipt {
        kind: match request.command {
            MetaMarketingCommand::Resource(_) => ClassificationKind::ProviderReportedResource,
            MetaMarketingCommand::Insights { .. } => ClassificationKind::ProviderReportedMetric,
        },
        command_kind: observation.command_kind.clone(),
        provider_attribution_models: observation.provider_attribution_models.clone(),
        review_state: observation.review_state,
        provenance: observation.provenance,
        causal_status: observation.causal_status,
    }
}

fn build_cursor_receipt(
    context: ReceiptCursorContext<'_>,
    observation: &ReadObservation,
) -> CursorReceipt {
    CursorReceipt {
        page_sequence: context.page_sequence,
        current_digest: context.sent.map(cursor_digest),
        next_digest: context.next.map(cursor_digest),
        durable_checkpoint_digest: context.checkpoint_digest.to_owned(),
        provider_complete: observation.pagination.complete,
        complete: context.next.is_none(),
    }
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<String, ConnectorError> {
    serde_json::to_vec(value)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|_| ConnectorError::InvalidObservation)
}

fn cursor_digest(cursor: &OpaqueCursor) -> String {
    digest_bytes(format!("{:?}:{}", cursor.kind, cursor.value()).as_bytes())
}

fn normalize_meta_ad_account_id(value: &str) -> Result<String, ConnectorError> {
    let value = value.strip_prefix("act_").unwrap_or(value);
    if !valid_identifier(value) {
        return Err(ConnectorError::InvalidRequest);
    }
    Ok(format!("act_{value}"))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{
        HttpRequest, HttpResponse, HttpTransport, HttpTransportError, ReqwestTransport,
    };
    use crate::paid_social_types::{
        AttributionSelection, InMemoryCredentialResolver, InsightLevel,
    };
    use crate::{ConnectorAuth, MetaConfig, ProviderAdapterIdentity};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Debug)]
    struct StubTransport {
        response: HttpResponse,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl StubTransport {
        fn json(body: &str, headers: &[(&str, &str)]) -> Self {
            Self {
                response: HttpResponse {
                    status: 200,
                    headers: headers
                        .iter()
                        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                        .collect(),
                    body: body.as_bytes().to_vec(),
                    received_at: Utc::now(),
                },
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpTransport for StubTransport {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            Ok(self.response.clone())
        }
    }

    fn fixture(
        transport: Arc<dyn HttpTransport>,
        command: MetaMarketingCommand,
        scopes: &[&str],
    ) -> (
        MetaMarketingReadService,
        MetaMarketingReadRequest,
        InMemoryCredentialResolver,
    ) {
        let scope = ConnectorScope::new(
            "tenant-1",
            "project-1",
            "meta",
            "123",
            scopes.iter().map(|scope| (*scope).to_owned()),
        )
        .expect("scope");
        let reference = crate::SecretReference::new("secret-ref-1", scope.clone(), 1)
            .expect("secret reference");
        let adapter_identity =
            ProviderAdapterIdentity::new(META_MARKETING_ADAPTER_ID, META_MARKETING_ADAPTER_VERSION)
                .expect("adapter identity");
        let now = Utc::now();
        let lease = ConnectorAuth::issue_credential_lease(
            &reference,
            adapter_identity,
            "lease-1",
            1,
            now - Duration::seconds(1),
            now + Duration::minutes(5),
        )
        .expect("lease");
        let request = MetaMarketingReadRequest {
            scope,
            account_scope: MetaMarketingAccountScope::new("business-1", "act_123")
                .expect("account scope"),
            connection_id: "connection-1".to_owned(),
            secret_reference: reference.clone(),
            lease,
            command,
            provenance: ProvenanceClass::ComponentHarness,
            requested_at: now,
        };
        let mut resolver = InMemoryCredentialResolver::default();
        resolver.insert_bearer(&reference, "test-token");
        let adapter = MetaAdapter::new(
            MetaConfig {
                graph_base_url: "https://graph.example.test".to_owned(),
                api_version: "v1".to_owned(),
                ..MetaConfig::default()
            },
            transport,
        )
        .expect("adapter");
        let provider = MetaMarketingReadProvider::new(adapter);
        let budget = DispatchBudget::new(4, now + Duration::hours(1), 4, 100).expect("budget");
        let service = MetaMarketingReadService::new(
            provider,
            budget,
            MetaMarketingReadPolicy::new(Duration::minutes(10), 3).expect("policy"),
        )
        .expect("service");
        (service, request, resolver)
    }

    fn insights_command() -> MetaMarketingCommand {
        MetaMarketingCommand::Insights {
            query: InsightsQuery {
                since: Utc::now() - Duration::days(1),
                until: Utc::now(),
                level: InsightLevel::Campaign,
                granularity: crate::Granularity::Daily,
                fields: BTreeSet::from(["impressions".to_owned(), "clicks".to_owned()]),
                attribution: AttributionSelection::Explicit(BTreeSet::from(
                    ["7d_click".to_owned()],
                )),
                parameters: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn plugin_stays_disconnected_without_registry_registration() {
        assert!(MetaMarketingReadPlugin::registrations().is_empty());
        assert_eq!(
            MetaMarketingReadPlugin::connection_state(),
            PluginConnectionState::Disconnected
        );
        let provider = MetaMarketingReadProvider::new(
            MetaAdapter::new(
                MetaConfig::default(),
                Arc::new(StubTransport::json("{}", &[])),
            )
            .expect("adapter"),
        );
        assert!(provider.registrations().is_empty());
        assert_eq!(
            provider.connection_state(),
            PluginConnectionState::Disconnected
        );
    }

    #[test]
    fn mission_consumer_preserves_meta_attribution_and_emits_receipt() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"campaign_id":"c1","impressions":3,"actions":[{"action_type":"purchase","value":1}]}],"paging":{"cursors":{"after":"next"},"next":"https://graph.example.test/next"}}"#,
            &[
                ("x-fb-trace-id", "trace-1"),
                ("x-ad-account-usage", r#"{"act_123":{"call_count":2}}"#),
            ],
        ));
        let (service, request, resolver) = fixture(transport, insights_command(), &["ads_read"]);
        let mut consumer = MetaMarketingMissionConsumer::new(service);
        let result = consumer
            .consume("mission-paid-social-1", &request, &resolver)
            .expect("read");
        assert_eq!(result.mission_id, "mission-paid-social-1");
        assert_eq!(result.observation.records.len(), 1);
        assert_eq!(
            result.observation.provider_attribution_models[0].windows,
            vec!["7d_click"]
        );
        assert_eq!(
            result.receipt.classification.causal_status,
            CausalStatus::NotClaimed
        );
        assert_eq!(
            result.receipt.source.provider_request_id.as_deref(),
            Some("trace-1")
        );
        assert_eq!(result.receipt.quota.used_after, 1);
        assert_eq!(result.receipt.cost.charged_minor, 3);
        assert_eq!(result.receipt.freshness.ttl_seconds, 600);
        assert_eq!(result.receipt.ad_account_id, "act_123");
        assert_eq!(result.receipt.write_policy.state, WriteState::Disabled);
        assert_eq!(
            result.receipt.connection_state,
            PluginConnectionState::Disconnected
        );
        assert!(result.receipt.cursor.next_digest.is_some());
        assert!(!consumer.service().budget().quota.used().eq(&0));
    }

    #[test]
    fn durable_cursor_round_trips_and_advances_the_next_read() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"id":"campaign-1"}],"paging":{"cursors":{"after":"next"},"next":"https://graph.example.test/next"}}"#,
            &[],
        ));
        let command = insights_command();
        let (mut service, request, resolver) =
            fixture(transport.clone(), command.clone(), &["ads_read"]);
        let first = service.read(&request, &resolver).expect("first read");
        let checkpoint = service
            .cursor_checkpoint()
            .expect("checkpoint")
            .expect("cursor");
        let restored = DurableCursor::from_checkpoint(&checkpoint).expect("restore");
        assert_eq!(restored.sequence(), 1);
        assert!(!restored.complete());
        assert_eq!(
            restored.next().expect("next").kind,
            crate::paid_social_types::CursorKind::MetaGraphAfter
        );

        let mut second_service = fixture(transport.clone(), command, &["ads_read"]).0;
        second_service
            .restore_cursor(restored)
            .expect("restore service");
        let second = second_service
            .read(&request, &resolver)
            .expect("second read");
        assert_eq!(second.receipt.cursor.page_sequence, 2);
        assert_eq!(
            second.receipt.cursor.current_digest,
            first.receipt.cursor.next_digest
        );
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert!(
            requests[1]
                .query
                .iter()
                .any(|(name, value)| name == "after" && value == "next")
        );
    }

    #[test]
    fn budget_rejection_happens_before_transport() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"id":"must-not-read"}]}"#,
            &[],
        ));
        let (mut service, request, resolver) = fixture(
            transport.clone(),
            MetaMarketingCommand::Resource(ResourceKind::Account),
            &["ads_read"],
        );
        let now = request.requested_at;
        service = MetaMarketingReadService::new(
            service.provider.clone(),
            DispatchBudget::new(0, now + Duration::hours(1), 1, 1).expect("budget"),
            MetaMarketingReadPolicy::default(),
        )
        .expect("service");
        assert!(matches!(
            service.read(&request, &resolver),
            Err(ConnectorError::Budget(crate::ConnectorError::RateLimited))
        ));
        assert!(transport.requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn missing_scope_and_write_authority_fail_closed() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"id":"must-not-read"}]}"#,
            &[],
        ));
        let (mut service, request, resolver) = fixture(
            transport.clone(),
            MetaMarketingCommand::Resource(ResourceKind::Account),
            &["placeholder.scope"],
        );
        assert!(matches!(
            service.read(&request, &resolver),
            Err(ConnectorError::MissingPermission)
        ));
        assert!(transport.requests.lock().expect("requests").is_empty());
        assert!(matches!(
            service.provider().prepare_effect("campaign.create"),
            Err(ConnectorError::WritesDisabled {
                provider: PaidSocialProvider::Meta
            })
        ));
    }

    fn controlled_http_server() -> (
        std::net::SocketAddr,
        mpsc::Receiver<String>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let address = listener.local_addr().expect("address");
        let (request_tx, request_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let count = stream.read(&mut buffer).expect("read request");
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request_tx
                .send(String::from_utf8(bytes).expect("request utf8"))
                .expect("request capture");
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: application/json\r\n",
                "X-FB-Trace-ID: controlled-trace\r\n",
                "X-Ad-Account-Usage: {\"act_123\":{\"call_count\":1}}\r\n",
                "Content-Length: 30\r\n",
                "Connection: close\r\n\r\n",
                "{\"data\":[{\"id\":\"campaign-1\"}]}"
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        (address, request_rx, server)
    }

    #[test]
    fn real_reqwest_transport_sends_authenticated_meta_read_in_controlled_harness() {
        let (address, request_rx, server) = controlled_http_server();

        // The production constructor requires HTTPS.  This controlled-provider
        // harness uses the same ReqwestTransport and adapter read path over a
        // loopback HTTP endpoint without claiming production evidence.
        let adapter = MetaAdapter {
            config: MetaConfig {
                graph_base_url: format!("http://{address}"),
                api_version: "v1".to_owned(),
                ..MetaConfig::default()
            },
            transport: Arc::new(
                ReqwestTransport::new(std::time::Duration::from_secs(5)).expect("transport"),
            ),
        };
        let provider = MetaMarketingReadProvider::new(adapter);
        let now = Utc::now();
        let scope = ConnectorScope::new(
            "tenant-1",
            "project-1",
            "meta",
            "123",
            ["ads_read".to_owned()],
        )
        .expect("scope");
        let reference =
            crate::SecretReference::new("secret-ref-1", scope.clone(), 1).expect("reference");
        let lease = ConnectorAuth::issue_credential_lease(
            &reference,
            ProviderAdapterIdentity::new(META_MARKETING_ADAPTER_ID, META_MARKETING_ADAPTER_VERSION)
                .expect("identity"),
            "lease-1",
            1,
            now - Duration::seconds(1),
            now + Duration::minutes(5),
        )
        .expect("lease");
        let request = MetaMarketingReadRequest {
            scope,
            account_scope: MetaMarketingAccountScope::new("business-1", "123")
                .expect("account scope"),
            connection_id: "connection-1".to_owned(),
            secret_reference: reference.clone(),
            lease,
            command: MetaMarketingCommand::Resource(ResourceKind::Campaigns),
            provenance: ProvenanceClass::ControlledProvider,
            requested_at: now,
        };
        let mut resolver = InMemoryCredentialResolver::default();
        resolver.insert_bearer(&reference, "real-transport-test-token");
        let mut service = MetaMarketingReadService::new(
            provider,
            DispatchBudget::new(1, now + Duration::minutes(1), 1, 1).expect("budget"),
            MetaMarketingReadPolicy::default(),
        )
        .expect("service");
        let result = service.read(&request, &resolver).expect("read");
        let captured = request_rx.recv().expect("captured request");
        server.join().expect("server");
        assert!(
            captured
                .to_ascii_lowercase()
                .contains("authorization: bearer real-transport-test-token")
        );
        assert!(captured.contains("/v1/act_123/campaigns"));
        assert_eq!(
            result.receipt.source.provider_request_id.as_deref(),
            Some("controlled-trace")
        );
        assert_eq!(
            result.receipt.classification.provenance,
            ProvenanceClass::ControlledProvider
        );
    }

    #[test]
    fn scope_mismatch_rejects_cursor_reuse() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"id":"campaign-1"}],"paging":{"cursors":{"after":"next"},"next":"https://graph.example.test/next"}}"#,
            &[],
        ));
        let (mut service, request, resolver) = fixture(
            transport,
            MetaMarketingCommand::Resource(ResourceKind::Campaigns),
            &["ads_read"],
        );
        service.read(&request, &resolver).expect("first");
        let mut wrong_request = request;
        wrong_request.account_scope =
            MetaMarketingAccountScope::new("business-2", "999").expect("wrong scope");
        wrong_request.scope = ConnectorScope::new(
            "tenant-1",
            "project-1",
            "meta",
            "999",
            ["ads_read".to_owned()],
        )
        .expect("wrong connector scope");
        let reference = crate::SecretReference::new("secret-ref-2", wrong_request.scope.clone(), 1)
            .expect("wrong reference");
        wrong_request.secret_reference = reference.clone();
        let now = wrong_request.requested_at;
        wrong_request.lease = ConnectorAuth::issue_credential_lease(
            &reference,
            ProviderAdapterIdentity::new(META_MARKETING_ADAPTER_ID, META_MARKETING_ADAPTER_VERSION)
                .expect("identity"),
            "lease-2",
            1,
            now - Duration::seconds(1),
            now + Duration::minutes(5),
        )
        .expect("lease");
        let mut wrong_resolver = InMemoryCredentialResolver::default();
        wrong_resolver.insert_bearer(&reference, "token");
        assert!(matches!(
            service.read(&wrong_request, &wrong_resolver),
            Err(ConnectorError::CursorMismatch)
        ));
    }
}

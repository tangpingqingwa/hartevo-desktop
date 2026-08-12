use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use rust_decimal::RoundingStrategy;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AccountId, ActorId, ApprovalDecision, AttributionId, CampaignId, CommissionId, Company,
    CompanyId, ConnectionId, ConnectionSnapshot, CurrencyCode, Effect, EffectId, EffectStatus,
    IdentityLink, IdentityLinkId, IdentityLinkStatus, IdentitySubject, KpiContract, KpiDirection,
    Mission, MissionCheckpointCompletionPolicy, MissionCheckpointExecutor, MissionCheckpointStatus,
    MissionConversationId, MissionConversationMessageId, MissionId, MissionStage,
    MissionTerminalDisposition, Money, OperatingMode, Opportunity, OpportunityId, OrderId,
    OutcomeDecision, OutcomeEventId, Partner, PartnerId, PartnerSupplyClass, PayoutId, Person,
    PersonId, ProjectId, RefundId, TenantId, VerificationStatus,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeEventKind {
    LeadQualified,
    MeetingBooked,
    OpportunityStageChanged,
    OrderPlaced,
    RefundIssued,
    CommissionAccrued,
    CommissionReversed,
    PayoutCompleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeVerificationMethod {
    SignedWebhook,
    IndependentReadback,
    UserConfirmed,
    InternalDerived,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeSourceVerification {
    pub method: OutcomeVerificationMethod,
    pub verifier: String,
    pub independent: bool,
    pub verified_at: DateTime<Utc>,
    pub evidence_digest: String,
}

impl OutcomeSourceVerification {
    fn validate(&self, received_at: DateTime<Utc>) -> Result<(), OutcomeLedgerError> {
        if self.verifier.trim().is_empty()
            || self.verified_at < received_at
            || !is_sha256(&self.evidence_digest)
            || matches!(
                self.method,
                OutcomeVerificationMethod::SignedWebhook
                    | OutcomeVerificationMethod::IndependentReadback
            ) && !self.independent
        {
            return Err(OutcomeLedgerError::UnverifiedOutcomeSource);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeEvent {
    pub id: OutcomeEventId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub kind: OutcomeEventKind,
    pub provider: String,
    #[serde(default)]
    pub connection_id: Option<ConnectionId>,
    pub account_id: Option<AccountId>,
    pub source_event_id: String,
    pub identity_link_id: Option<IdentityLinkId>,
    pub opportunity_id: Option<OpportunityId>,
    pub campaign_id: Option<CampaignId>,
    pub order_id: Option<OrderId>,
    pub refund_id: Option<RefundId>,
    pub commission_id: Option<CommissionId>,
    pub payout_id: Option<PayoutId>,
    pub partner_id: Option<PartnerId>,
    /// Positive magnitude. Event kind determines whether it adds or reverses value.
    pub amount: Option<Money>,
    pub occurred_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub raw_payload_digest: String,
    /// None is accepted only when reading a pre-v17 local migration. New
    /// ingestion and encrypted sync require explicit source verification.
    #[serde(default)]
    pub source_verification: Option<OutcomeSourceVerification>,
}

impl OutcomeEvent {
    pub fn validate(&self) -> Result<(), OutcomeLedgerError> {
        self.validate_envelope()?;
        let verification = self
            .source_verification
            .as_ref()
            .ok_or(OutcomeLedgerError::UnverifiedOutcomeSource)?;
        verification.validate(self.received_at)?;
        let external = matches!(
            verification.method,
            OutcomeVerificationMethod::SignedWebhook
                | OutcomeVerificationMethod::IndependentReadback
        );
        if external != (self.connection_id.is_some() && self.account_id.is_some())
            || (!external && (self.connection_id.is_some() || self.account_id.is_some()))
            || matches!(
                self.kind,
                OutcomeEventKind::OrderPlaced
                    | OutcomeEventKind::RefundIssued
                    | OutcomeEventKind::PayoutCompleted
            ) && !external
            || self.kind == OutcomeEventKind::OrderPlaced && self.identity_link_id.is_none()
        {
            return Err(OutcomeLedgerError::UnverifiedOutcomeSource);
        }
        Ok(())
    }

    fn validate_persisted(&self) -> Result<(), OutcomeLedgerError> {
        self.validate_envelope()?;
        if let Some(verification) = &self.source_verification {
            verification.validate(self.received_at)?;
        }
        Ok(())
    }

    fn validate_envelope(&self) -> Result<(), OutcomeLedgerError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.provider.trim().is_empty()
            || self.source_event_id.trim().is_empty()
            || self.occurred_at > self.received_at
            || !is_sha256(&self.evidence_digest)
            || !is_sha256(&self.raw_payload_digest)
        {
            return Err(OutcomeLedgerError::InvalidEventEnvelope);
        }
        let amount_positive = self.amount.as_ref().is_some_and(Money::is_positive);
        let no_financial_references = self.order_id.is_none()
            && self.refund_id.is_none()
            && self.commission_id.is_none()
            && self.payout_id.is_none()
            && self.amount.is_none();
        let shape_valid = match self.kind {
            OutcomeEventKind::OrderPlaced => {
                self.order_id.is_some()
                    && self.refund_id.is_none()
                    && self.commission_id.is_none()
                    && self.payout_id.is_none()
                    && amount_positive
            }
            OutcomeEventKind::RefundIssued => {
                self.order_id.is_some()
                    && self.refund_id.is_some()
                    && self.commission_id.is_none()
                    && self.payout_id.is_none()
                    && amount_positive
            }
            OutcomeEventKind::CommissionAccrued | OutcomeEventKind::CommissionReversed => {
                self.order_id.is_some()
                    && self.refund_id.is_none()
                    && self.commission_id.is_some()
                    && self.payout_id.is_none()
                    && self.partner_id.is_some()
                    && amount_positive
            }
            OutcomeEventKind::PayoutCompleted => {
                self.order_id.is_none()
                    && self.refund_id.is_none()
                    && self.payout_id.is_some()
                    && self.partner_id.is_some()
                    && amount_positive
            }
            OutcomeEventKind::LeadQualified | OutcomeEventKind::MeetingBooked => {
                no_financial_references && self.identity_link_id.is_some()
            }
            OutcomeEventKind::OpportunityStageChanged => {
                no_financial_references && self.opportunity_id.is_some()
            }
        };
        if !shape_valid {
            return Err(OutcomeLedgerError::EventKindShapeMismatch);
        }
        Ok(())
    }

    pub fn is_revenue_event(&self) -> bool {
        self.kind == OutcomeEventKind::OrderPlaced
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeOrder {
    pub id: OrderId,
    pub source_event_id: OutcomeEventId,
    pub original_amount: Money,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeRefund {
    pub id: RefundId,
    pub order_id: OrderId,
    pub source_event_id: OutcomeEventId,
    pub amount: Money,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionModel {
    VerifiedIdentity,
    LastNonDirect,
    FirstTouch,
    Unattributed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionTrafficClass {
    Direct,
    NonDirect,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Touchpoint {
    pub mission_id: MissionId,
    pub source: String,
    /// Required when `VerifiedIdentity` relies on an external action. The
    /// VM-11 Oracle resolves this reference against the current Mission and
    /// independently confirmed Effect rather than trusting a caller digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<EffectId>,
    /// Legacy rows omit this field and remain audit-readable, but cannot enter
    /// a current deterministic attribution view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_class: Option<AttributionTrafficClass>,
    pub provider_identity_digest: Option<String>,
    pub verified_link_or_coupon_digest: Option<String>,
    pub occurred_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
    pub evidence_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_verification: Option<OutcomeSourceVerification>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionRecord {
    pub id: AttributionId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub order_id: OrderId,
    pub model: AttributionModel,
    pub touchpoint: Option<Touchpoint>,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub confidence: Decimal,
    /// Attribution views are operational correlation views, never causal
    /// claims. The only accepted value is false.
    #[serde(default)]
    pub causal_claim: bool,
    pub rationale: String,
    pub evidence_digest: String,
    pub recorded_at: DateTime<Utc>,
}

impl AttributionRecord {
    pub fn validate(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        order: &OutcomeOrder,
    ) -> Result<(), OutcomeLedgerError> {
        self.validate_shape(tenant_id, project_id, order, true)
    }

    fn validate_persisted(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        order: &OutcomeOrder,
    ) -> Result<(), OutcomeLedgerError> {
        self.validate_shape(tenant_id, project_id, order, false)
    }

    fn validate_shape(
        &self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        order: &OutcomeOrder,
        require_current_source_verification: bool,
    ) -> Result<(), OutcomeLedgerError> {
        if self.tenant_id != *tenant_id
            || self.project_id != *project_id
            || self.order_id != order.id
            || self.window_started_at >= self.window_ended_at
            || order.occurred_at < self.window_started_at
            || order.occurred_at > self.window_ended_at
            || self.recorded_at < order.occurred_at
            || self.confidence < Decimal::ZERO
            || self.confidence > Decimal::ONE
            || self.causal_claim
            || self.rationale.trim().is_empty()
            || !is_sha256(&self.evidence_digest)
        {
            return Err(OutcomeLedgerError::InvalidAttribution);
        }
        match self.model {
            AttributionModel::Unattributed
                if self.touchpoint.is_some() || self.confidence != Decimal::ZERO =>
            {
                return Err(OutcomeLedgerError::InvalidAttribution);
            }
            AttributionModel::Unattributed => {}
            _ => {
                let touchpoint = self
                    .touchpoint
                    .as_ref()
                    .ok_or(OutcomeLedgerError::InvalidAttribution)?;
                validate_touchpoint(
                    touchpoint,
                    order,
                    self.model,
                    self.window_started_at,
                    self.window_ended_at,
                    self.recorded_at,
                    require_current_source_verification,
                )?;
                if self.model == AttributionModel::VerifiedIdentity
                    && self.confidence != Decimal::ONE
                {
                    return Err(OutcomeLedgerError::InvalidAttribution);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommissionStatus {
    Current,
    RecalculationRequired,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommissionRecord {
    pub id: CommissionId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub order_id: OrderId,
    pub partner_id: PartnerId,
    pub rate: Decimal,
    pub eligible_net_amount: Money,
    pub commission_amount: Money,
    pub terms_digest: String,
    /// Digest of the exact refund set used in this calculation.
    pub refund_set_digest: String,
    pub supersedes: Option<CommissionId>,
    pub status: CommissionStatus,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeLedger {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub events: Vec<OutcomeEvent>,
    pub orders: Vec<OutcomeOrder>,
    pub refunds: Vec<OutcomeRefund>,
    pub attributions: Vec<AttributionRecord>,
    pub commissions: Vec<CommissionRecord>,
    pub revision: u64,
}

type SourceMissionOrderMap<'a> = BTreeMap<OrderId, (&'a OutcomeOrder, &'a OutcomeEvent)>;
type SourceMissionOrders<'a> = (DateTime<Utc>, DateTime<Utc>, SourceMissionOrderMap<'a>);

/// Content-free, deterministically recomputable proof that one exact Outcome
/// Ledger revision has a complete source-verification chain, contains no
/// duplicate provider/event identities, and can be projected into one stable
/// event/order/refund ordering. Raw provider identifiers and payloads stay in
/// the ledger; Mission evidence retains only this projection's digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeNormalizationProjection {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub source_ledger_revision: u64,
    pub event_count: u64,
    pub unique_event_id_count: u64,
    pub unique_provider_source_count: u64,
    pub order_count: u64,
    pub refund_count: u64,
    /// Number of append positions that differ from the canonical ordering by
    /// occurred time, receive time, provider source and stable event id.
    pub observed_reorder_count: u64,
    pub canonical_event_digest: String,
    pub order_refund_projection_digest: String,
}

/// Content-free proof that every normalized OutcomeEvent resolves through the
/// exact project-scoped identity support closure inspected by the VM-11
/// `identity_chain` Checkpoint. The source digest binds the immutable Outcome
/// projection plus every referenced Connection, IdentityLink, Person,
/// Company, Partner and Opportunity revision; none of those records are
/// copied into Mission evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeIdentityChainProjection {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub source_ledger_revision: u64,
    pub event_count: u64,
    pub identity_covered_event_count: u64,
    pub direct_identity_event_count: u64,
    pub inherited_order_identity_event_count: u64,
    pub external_account_match_count: u64,
    pub connection_count: u64,
    pub identity_link_count: u64,
    pub person_count: u64,
    pub company_count: u64,
    pub partner_count: u64,
    pub opportunity_count: u64,
    pub partner_policy_digest: String,
    pub source_support_digest: String,
}

/// Exact value observed for one parent Mission KPI. Financial values remain
/// typed minor-unit Money; counts never pass through `f64` or an LLM judge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum MissionKpiObservedValue {
    Count { value: u64 },
    Money { value: Money },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionKpiMeasurement {
    pub metric_id: String,
    pub source_event_count: u64,
    pub observed: MissionKpiObservedValue,
    pub baseline: Option<Decimal>,
    pub target: Decimal,
    pub unit: String,
    pub direction: KpiDirection,
    pub target_met: bool,
}

/// Content-free VM-11 `mission_specific_kpi` Oracle. The projection binds one
/// immutable parent Mission contract/revision, one verified ledger revision,
/// an explicit event-time/receive-time cutoff, and typed KPI measurements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionKpiProjection {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub source_mission_id: MissionId,
    pub source_mission_revision: u64,
    pub source_ledger_revision: u64,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub source_event_count: u64,
    pub measurement_count: u64,
    pub target_met_count: u64,
    pub source_contract_digest: String,
    pub source_event_digest: String,
    pub normalization_digest: String,
    pub identity_chain_digest: String,
    pub measurements: BTreeMap<String, MissionKpiMeasurement>,
}

/// One deterministic operational attribution view. `primary_model` is never a
/// causal conclusion: it is either a source-verified identity, the latest
/// source-verified non-direct touchpoint, or an explicit Unattributed result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderAttributionView {
    pub order_id: OrderId,
    pub primary_model: AttributionModel,
    pub primary_attribution_id: Option<AttributionId>,
    pub primary_touchpoint_digest: Option<String>,
    pub first_touch_attribution_id: Option<AttributionId>,
    pub first_touch_digest: Option<String>,
    pub last_non_direct_attribution_id: Option<AttributionId>,
    pub last_non_direct_digest: Option<String>,
    pub source_record_count: u64,
    pub eligible_touchpoint_count: u64,
    pub explicit_unattributed_record_count: u64,
    pub causal_claim: bool,
}

/// Content-free, replayable VM-11 attribution Oracle. The full order map is
/// kept in encrypted Domain state only while Application evidence persists its
/// digest and bounded counts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeAttributionProjection {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub source_mission_id: MissionId,
    pub source_mission_revision: u64,
    pub source_ledger_revision: u64,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub order_count: u64,
    pub source_record_count: u64,
    pub eligible_touchpoint_count: u64,
    pub verified_identity_order_count: u64,
    pub last_non_direct_order_count: u64,
    pub unattributed_order_count: u64,
    pub first_touch_order_count: u64,
    pub explicit_unattributed_record_count: u64,
    pub supporting_mission_count: u64,
    pub verified_effect_count: u64,
    pub causal_claim: bool,
    pub normalization_digest: String,
    pub identity_chain_digest: String,
    pub source_record_digest: String,
    pub effect_support_digest: String,
    pub orders: BTreeMap<OrderId, OrderAttributionView>,
}

/// Authority used for one payable settlement group. Official networks remain
/// authoritative for their own immutable commission/reversal facts; Hartevo
/// opt-in and tenant-private relationships use the locally recomputable
/// CommissionRecord chain. These bases must never be mixed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementCommissionBasis {
    OfficialNetworkFacts,
    HartevoCalculated,
    TenantPrivateCalculated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementGroupStatus {
    NoPaymentDue,
    Outstanding,
    Paid,
}

/// Immutable order/refund view at the explicit settlement cutoff. The
/// original order amount is retained; refunds are separate reverse events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderSettlementView {
    pub order_id: OrderId,
    pub original_amount: Money,
    pub refund_count: u64,
    pub refunded_amount: Money,
    pub eligible_net_amount: Money,
    pub calculated_commission_record_count: u64,
    pub network_commission_event_count: u64,
}

/// Reconciliation view for one exact partner/currency pair. Payout facts are
/// aggregated only after provider, supply-class, currency, and obligation
/// checks have succeeded; a provider acceptance is never synthesized here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartnerSettlementView {
    pub partner_id: PartnerId,
    pub supply_class: PartnerSupplyClass,
    pub basis: SettlementCommissionBasis,
    pub currency: CurrencyCode,
    pub source_order_count: u64,
    pub source_commission_count: u64,
    pub commission_amount: Money,
    pub payout_count: u64,
    pub payout_completed_amount: Money,
    pub outstanding_amount: Money,
    pub status: SettlementGroupStatus,
}

/// Replayable VM-11 `refund_commission_payout_recalc` Oracle. It binds the
/// parent Mission window, current source-verified Outcome/Identity state,
/// immutable order/refund projections, exact commission authority, and
/// independently verified payout facts without claiming payout approval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeSettlementProjection {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub source_mission_id: MissionId,
    pub source_mission_revision: u64,
    pub source_ledger_revision: u64,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub order_count: u64,
    pub refunded_order_count: u64,
    pub refund_count: u64,
    pub calculated_commission_count: u64,
    pub network_commission_event_count: u64,
    pub payout_count: u64,
    pub settlement_group_count: u64,
    pub paid_group_count: u64,
    pub outstanding_group_count: u64,
    pub no_payment_due_group_count: u64,
    pub official_network_group_count: u64,
    pub hartevo_managed_group_count: u64,
    pub tenant_private_group_count: u64,
    pub normalization_digest: String,
    pub identity_chain_digest: String,
    pub order_refund_digest: String,
    pub commission_source_digest: String,
    pub payout_source_digest: String,
    pub partner_policy_digest: String,
    pub orders: BTreeMap<OrderId, OrderSettlementView>,
    pub settlements: Vec<PartnerSettlementView>,
}

/// Exact per-currency economics used by `outcome_review`. Values from
/// different currencies remain in separate buckets; this projection never
/// invents an FX quote or a cross-currency ROI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeReviewMoneyView {
    pub currency: CurrencyCode,
    pub gross_revenue: Money,
    pub refunded_amount: Money,
    pub net_revenue: Money,
    pub commission_obligation: Money,
    pub commission_paid: Money,
    pub commission_outstanding: Money,
    pub verified_effect_outflow: Money,
    pub unresolved_effect_exposure: Money,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReviewCaveat {
    KpiTargetGap,
    UnattributedOrders,
    OutstandingSettlement,
    PendingEffect,
    UnresolvedEffectCost,
    BudgetExceeded,
    CrossCurrencyCostWithoutFx,
    ImplicitLoopForbidden,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReviewGateStatus {
    Satisfied,
    Blocked,
}

impl From<bool> for OutcomeReviewGateStatus {
    fn from(satisfied: bool) -> Self {
        if satisfied {
            Self::Satisfied
        } else {
            Self::Blocked
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReviewLoopPolicy {
    Eligible,
    Forbidden,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReviewCausalStatus {
    NotClaimed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReviewRoiStatus {
    NotCalculated,
}

/// Replayable, content-free decision input for VM-11 `outcome_review`.
/// This is deliberately not a recommendation: the following Human
/// Checkpoint owns Continue/Stop/Scale/Test. The projection only freezes the
/// exact KPI, attribution, settlement and verified-cost facts plus explicit
/// caveats at one observation cutoff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeReviewProjection {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub source_mission_id: MissionId,
    pub source_mission_revision: u64,
    pub source_ledger_revision: u64,
    pub window_started_at: DateTime<Utc>,
    pub outcome_window_ended_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub measurement_count: u64,
    pub target_met_count: u64,
    pub target_gap_count: u64,
    pub order_count: u64,
    pub attributed_order_count: u64,
    pub unattributed_order_count: u64,
    pub settlement_group_count: u64,
    pub paid_or_no_payment_due_group_count: u64,
    pub outstanding_settlement_group_count: u64,
    pub verified_effect_count: u64,
    pub pending_effect_count: u64,
    pub unresolved_cost_effect_count: u64,
    pub cross_currency_cost_effect_count: u64,
    pub budget: Money,
    pub budget_currency_verified_cost: Money,
    pub budget_remaining: Money,
    pub budget_overrun: Money,
    pub kpi_status: OutcomeReviewGateStatus,
    pub attribution_status: OutcomeReviewGateStatus,
    pub settlement_status: OutcomeReviewGateStatus,
    pub cost_status: OutcomeReviewGateStatus,
    pub budget_status: OutcomeReviewGateStatus,
    pub scale_evidence_status: OutcomeReviewGateStatus,
    pub loop_policy: OutcomeReviewLoopPolicy,
    pub causal_status: OutcomeReviewCausalStatus,
    pub roi_status: OutcomeReviewRoiStatus,
    pub caveats: BTreeSet<OutcomeReviewCaveat>,
    pub economics: BTreeMap<CurrencyCode, OutcomeReviewMoneyView>,
    pub source_contract_digest: String,
    pub normalization_digest: String,
    pub identity_chain_digest: String,
    pub kpi_projection_digest: String,
    pub attribution_projection_digest: String,
    pub settlement_projection_digest: String,
    pub effect_cost_source_digest: String,
}

/// The contract disposition implied by one explicit Human outcome decision.
/// It is deliberately derived from the action rather than supplied by the UI:
/// a Stop cannot retain scheduling authority, and Scale/Test can never silently
/// reuse the old contract as if its budget and experiment scope were unchanged.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReviewNextContractIntent {
    ValidTerminal,
    ContinueCurrentContract,
    ScaleWithRevisedContract,
    TestWithNewExperiment,
}

/// Deterministic availability of one explicit outcome-review action. The UI
/// renders this projection, while `OutcomeReviewDecision::decide` enforces the
/// same status again at the Domain authority boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeReviewDecisionGateStatus {
    Available,
    BlockedLoopPolicy,
    BlockedScaleEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeReviewActionGate {
    pub action: OutcomeDecision,
    pub next_contract_intent: OutcomeReviewNextContractIntent,
    pub status: OutcomeReviewDecisionGateStatus,
}

/// Content-free, replayable Human decision for VM-11
/// `continue_stop_scale_test`.
///
/// The private rationale stays in the encrypted Mission Conversation. This
/// record binds its digest, the exact frozen `outcome_review`, actor, action,
/// idempotency intent, and the Mission/Checkpoint CAS observed by the user.
/// It does not schedule a cycle, mutate the parent Mission, or execute an
/// external Effect; the following Application Checkpoint owns the legal next
/// contract or terminal transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeReviewDecision {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub cycle: u64,
    pub dispatch_mission_revision: u64,
    pub dispatch_checkpoint_revision: u64,
    pub source_review_checkpoint_revision: u64,
    pub source_review_completion_digest: String,
    pub source_review_projection_digest: String,
    pub source_mission_id: MissionId,
    pub source_mission_revision: u64,
    pub source_ledger_revision: u64,
    pub action: OutcomeDecision,
    pub next_contract_intent: OutcomeReviewNextContractIntent,
    pub decided_by: ActorId,
    pub conversation_id: MissionConversationId,
    pub conversation_revision: u64,
    pub message_id: MissionConversationMessageId,
    pub message_sequence: u64,
    pub rationale_digest: String,
    pub idempotency_key_digest: String,
    pub decided_at: DateTime<Utc>,
}

/// Deterministic, content-free output of VM-11
/// `next_contract_or_valid_terminal`.
///
/// The durable authority is the append-once Application Checkpoint completion
/// plus the immutable Human decision. This projection is reconstructed from
/// those records instead of adding an unversioned side channel to normalized
/// Mission storage. Continue may only reuse the exact frozen parent contract;
/// Stop may only produce the typed Completed terminal. Scale and Test require
/// a separate Human approval that binds the complete revised contract digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeReviewNextContractResolution {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub cycle: u64,
    pub decision_digest: String,
    pub action: OutcomeDecision,
    pub next_contract_intent: OutcomeReviewNextContractIntent,
    pub source_mission_id: MissionId,
    pub source_mission_revision: u64,
    pub source_contract_digest: String,
    pub continued_contract_digest: Option<String>,
    pub terminal_disposition: Option<MissionTerminalDisposition>,
    pub resolved_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct SettlementAccumulator {
    partner_id: PartnerId,
    supply_class: PartnerSupplyClass,
    basis: SettlementCommissionBasis,
    currency: CurrencyCode,
    source_orders: BTreeSet<OrderId>,
    source_commission_count: u64,
    commission_amount_minor: i64,
    payout_count: u64,
    payout_completed_minor: i64,
    authoritative_providers: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct NetworkCommissionAccumulator {
    partner_id: PartnerId,
    currency: CurrencyCode,
    provider: String,
    order_id: OrderId,
    accrued_minor: Option<i64>,
    reversed_minor: i64,
    event_count: u64,
}

impl OutcomeNormalizationProjection {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn digest(&self) -> String {
        let mut digest = Sha256::new();
        hash_projection_field(&mut digest, "hartevo-outcome-normalization/v1");
        hash_projection_field(&mut digest, &self.schema_version.to_string());
        hash_projection_field(&mut digest, self.tenant_id.as_str());
        hash_projection_field(&mut digest, self.project_id.as_str());
        hash_projection_field(&mut digest, &self.source_ledger_revision.to_string());
        hash_projection_field(&mut digest, &self.event_count.to_string());
        hash_projection_field(&mut digest, &self.unique_event_id_count.to_string());
        hash_projection_field(&mut digest, &self.unique_provider_source_count.to_string());
        hash_projection_field(&mut digest, &self.order_count.to_string());
        hash_projection_field(&mut digest, &self.refund_count.to_string());
        hash_projection_field(&mut digest, &self.observed_reorder_count.to_string());
        hash_projection_field(&mut digest, &self.canonical_event_digest);
        hash_projection_field(&mut digest, &self.order_refund_projection_digest);
        format!("{:x}", digest.finalize())
    }
}

impl OutcomeIdentityChainProjection {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn digest(&self) -> String {
        let mut digest = Sha256::new();
        hash_projection_field(&mut digest, "hartevo-outcome-identity-chain/v1");
        hash_projection_field(&mut digest, &self.schema_version.to_string());
        hash_projection_field(&mut digest, self.tenant_id.as_str());
        hash_projection_field(&mut digest, self.project_id.as_str());
        hash_projection_field(&mut digest, &self.source_ledger_revision.to_string());
        hash_projection_field(&mut digest, &self.event_count.to_string());
        hash_projection_field(&mut digest, &self.identity_covered_event_count.to_string());
        hash_projection_field(&mut digest, &self.direct_identity_event_count.to_string());
        hash_projection_field(
            &mut digest,
            &self.inherited_order_identity_event_count.to_string(),
        );
        hash_projection_field(&mut digest, &self.external_account_match_count.to_string());
        hash_projection_field(&mut digest, &self.connection_count.to_string());
        hash_projection_field(&mut digest, &self.identity_link_count.to_string());
        hash_projection_field(&mut digest, &self.person_count.to_string());
        hash_projection_field(&mut digest, &self.company_count.to_string());
        hash_projection_field(&mut digest, &self.partner_count.to_string());
        hash_projection_field(&mut digest, &self.opportunity_count.to_string());
        hash_projection_field(&mut digest, &self.partner_policy_digest);
        hash_projection_field(&mut digest, &self.source_support_digest);
        format!("{:x}", digest.finalize())
    }
}

impl MissionKpiProjection {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn digest(&self) -> Result<String, OutcomeLedgerError> {
        let canonical =
            serde_json::to_vec(self).map_err(|_| OutcomeLedgerError::ProjectionSerialization)?;
        Ok(format!("{:x}", Sha256::digest(canonical)))
    }
}

impl OutcomeAttributionProjection {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn digest(&self) -> Result<String, OutcomeLedgerError> {
        let canonical =
            serde_json::to_vec(self).map_err(|_| OutcomeLedgerError::ProjectionSerialization)?;
        Ok(format!("{:x}", Sha256::digest(canonical)))
    }
}

impl OutcomeSettlementProjection {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn digest(&self) -> Result<String, OutcomeLedgerError> {
        canonical_json_digest(self)
    }
}

impl OutcomeReviewProjection {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn digest(&self) -> Result<String, OutcomeLedgerError> {
        canonical_json_digest(self)
    }

    /// Returns the complete, user-visible gate for one action without making a
    /// recommendation. Stop and Test are always explicit choices; Continue
    /// requires a loop-eligible parent contract, while Scale additionally
    /// requires all frozen scale evidence gates to be satisfied.
    pub fn decision_gate(&self, action: OutcomeDecision) -> OutcomeReviewActionGate {
        let next_contract_intent = decision_contract_intent(&action);
        let status = match action {
            OutcomeDecision::Continue | OutcomeDecision::Scale
                if self.loop_policy != OutcomeReviewLoopPolicy::Eligible =>
            {
                OutcomeReviewDecisionGateStatus::BlockedLoopPolicy
            }
            OutcomeDecision::Scale
                if self.scale_evidence_status != OutcomeReviewGateStatus::Satisfied =>
            {
                OutcomeReviewDecisionGateStatus::BlockedScaleEvidence
            }
            OutcomeDecision::Continue
            | OutcomeDecision::Stop
            | OutcomeDecision::Scale
            | OutcomeDecision::Test => OutcomeReviewDecisionGateStatus::Available,
        };
        OutcomeReviewActionGate {
            action,
            next_contract_intent,
            status,
        }
    }
}

impl OutcomeReviewDecision {
    pub const SCHEMA_VERSION: u32 = 1;

    #[allow(
        clippy::too_many_arguments,
        reason = "the Human decision constructor binds every frozen review, CAS, actor, rationale, and replay dimension at one authority boundary"
    )]
    pub fn decide(
        mission: &Mission,
        review: &OutcomeReviewProjection,
        source_review_checkpoint_revision: u64,
        source_review_completion_digest: impl Into<String>,
        action: OutcomeDecision,
        decided_by: ActorId,
        conversation_id: MissionConversationId,
        conversation_revision: u64,
        message_id: MissionConversationMessageId,
        message_sequence: u64,
        rationale_digest: impl Into<String>,
        idempotency_key_digest: impl Into<String>,
        decided_at: DateTime<Utc>,
    ) -> Result<Self, OutcomeLedgerError> {
        let source_review_completion_digest = source_review_completion_digest.into();
        let rationale_digest = rationale_digest.into();
        let idempotency_key_digest = idempotency_key_digest.into();
        let (definition, checkpoint) = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .current_checkpoint()
                    .map(|checkpoint| (definition, checkpoint))
            })
            .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
        let route = checkpoint
            .route
            .as_ref()
            .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
        if definition.manifest_id != "VM-11"
            || definition.cycle == 0
            || checkpoint.id != "continue_stop_scale_test"
            || checkpoint.status != MissionCheckpointStatus::Running
            || route.executor != MissionCheckpointExecutor::Human
            || route.completion_policy != Some(MissionCheckpointCompletionPolicy::HumanConfirmation)
            || route.capability_id != "decision.evaluate"
            || mission.revision == 0
            || checkpoint.revision == 0
        {
            return Err(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch);
        }
        let next_contract_intent = decision_contract_intent(&action);
        let decision = Self {
            schema_version: Self::SCHEMA_VERSION,
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            cycle: definition.cycle,
            dispatch_mission_revision: mission.revision,
            dispatch_checkpoint_revision: checkpoint.revision,
            source_review_checkpoint_revision,
            source_review_completion_digest,
            source_review_projection_digest: review.digest()?,
            source_mission_id: review.source_mission_id.clone(),
            source_mission_revision: review.source_mission_revision,
            source_ledger_revision: review.source_ledger_revision,
            action,
            next_contract_intent,
            decided_by,
            conversation_id,
            conversation_revision,
            message_id,
            message_sequence,
            rationale_digest,
            idempotency_key_digest,
            decided_at,
        };
        decision.validate_source(mission, review, false)?;
        Ok(decision)
    }

    pub fn digest(&self) -> Result<String, OutcomeLedgerError> {
        canonical_json_digest(self)
    }

    /// Validates a record after the Human Checkpoint has completed and the
    /// next route may already be Running. This is used on every SQLCipher read
    /// so a projection/decision row cannot be detached from Mission authority.
    pub fn validate_persisted(
        &self,
        mission: &Mission,
        review: &OutcomeReviewProjection,
    ) -> Result<(), OutcomeLedgerError> {
        self.validate_source(mission, review, true)
    }

    fn validate_source(
        &self,
        mission: &Mission,
        review: &OutcomeReviewProjection,
        require_completed_decision: bool,
    ) -> Result<(), OutcomeLedgerError> {
        let definition = mission
            .definition
            .as_ref()
            .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
        let review_checkpoint = definition
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.id == "outcome_review")
            .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
        let review_completion = review_checkpoint
            .completion
            .as_ref()
            .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
        let review_source = review_completion
            .application_evidence
            .as_ref()
            .and_then(|evidence| {
                evidence
                    .sources
                    .iter()
                    .find(|source| source.source_kind == "outcome_review")
            })
            .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
        let decision_checkpoint = definition
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.id == "continue_stop_scale_test")
            .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
        let decision_route = decision_checkpoint
            .route
            .as_ref()
            .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
        let projection_digest = review.digest()?;
        if self.schema_version != Self::SCHEMA_VERSION
            || definition.manifest_id != "VM-11"
            || self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
            || self.cycle != definition.cycle
            || self.dispatch_mission_revision == 0
            || self.dispatch_checkpoint_revision == 0
            || self.source_review_checkpoint_revision != review_checkpoint.revision
            || self.source_review_completion_digest != review_completion.evidence_digest
            || self.source_review_projection_digest != projection_digest
            || review_source.projection_digest != projection_digest
            || review_source.source_revision != review.source_ledger_revision
            || review_checkpoint.status != MissionCheckpointStatus::Completed
            || decision_checkpoint.revision <= self.dispatch_checkpoint_revision
                && require_completed_decision
            || decision_route.executor != MissionCheckpointExecutor::Human
            || decision_route.completion_policy
                != Some(MissionCheckpointCompletionPolicy::HumanConfirmation)
            || decision_route.capability_id != "decision.evaluate"
            || mission.contract.parent_mission_id.as_ref() != Some(&review.source_mission_id)
            || review.tenant_id != mission.tenant_id
            || review.project_id != mission.project_id
            || self.source_mission_id != review.source_mission_id
            || self.source_mission_revision != review.source_mission_revision
            || self.source_ledger_revision != review.source_ledger_revision
            || review.source_mission_revision == 0
            || review.source_ledger_revision == 0
            || !is_sha256(&review.source_contract_digest)
            || !is_sha256(&self.source_review_completion_digest)
            || !is_sha256(&self.source_review_projection_digest)
            || !is_sha256(&self.rationale_digest)
            || !is_sha256(&self.idempotency_key_digest)
            || self.decided_by.as_str().trim().is_empty()
            || self.conversation_id.as_str().trim().is_empty()
            || self.conversation_revision == 0
            || self.message_id.as_str().trim().is_empty()
            || self.message_sequence == 0
            || self.message_sequence > self.conversation_revision
            || self.decided_at < review.observed_at
        {
            return Err(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch);
        }
        validate_outcome_review_action(review, &self.action, self.next_contract_intent)?;
        if require_completed_decision {
            let completion = decision_checkpoint
                .completion
                .as_ref()
                .ok_or(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)?;
            if decision_checkpoint.status != MissionCheckpointStatus::Completed
                || completion.evidence_digest != self.digest()?
                || completion.application_evidence.is_some()
                || !completion.work_product_ids.is_empty()
                || !completion.effect_ids.is_empty()
                || completion.oracle_ids != decision_route.oracle_ids
            {
                return Err(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch);
            }
        } else if mission.revision != self.dispatch_mission_revision
            || decision_checkpoint.revision != self.dispatch_checkpoint_revision
            || decision_checkpoint.status != MissionCheckpointStatus::Running
            || decision_checkpoint.completion.is_some()
        {
            return Err(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch);
        }
        Ok(())
    }
}

impl OutcomeReviewNextContractResolution {
    pub const SCHEMA_VERSION: u32 = 1;
    pub const HANDLER_ID: &'static str = "vm11.next-contract-or-valid-terminal/v1";

    pub fn validate_frozen_sources(
        mission: &Mission,
        parent_mission: &Mission,
        review: &OutcomeReviewProjection,
        decision: &OutcomeReviewDecision,
    ) -> Result<String, OutcomeLedgerError> {
        validate_next_contract_resolution_sources(mission, parent_mission, review, decision)
    }

    /// Resolves only the two actions whose complete authority already exists
    /// in the frozen Human decision. Scale and Test intentionally fail closed:
    /// the decision selected an intent, but did not approve a replacement
    /// budget, KPI set, experiment scope, validity window, or capability set.
    pub fn resolve(
        mission: &Mission,
        parent_mission: &Mission,
        review: &OutcomeReviewProjection,
        decision: &OutcomeReviewDecision,
        resolved_at: DateTime<Utc>,
    ) -> Result<Self, OutcomeLedgerError> {
        let source_contract_digest =
            validate_next_contract_resolution_sources(mission, parent_mission, review, decision)?;
        let (definition, checkpoint) = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .current_checkpoint()
                    .map(|checkpoint| (definition, checkpoint))
            })
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        let route = checkpoint
            .route
            .as_ref()
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        if definition.manifest_id != "VM-11"
            || definition.cycle != decision.cycle
            || mission.stage != MissionStage::Running
            || mission.block.is_some()
            || checkpoint.id != "next_contract_or_valid_terminal"
            || checkpoint.status != MissionCheckpointStatus::Running
            || checkpoint.completion.is_some()
            || route.executor != MissionCheckpointExecutor::Application
            || route.completion_policy
                != Some(MissionCheckpointCompletionPolicy::DeterministicEvidence)
            || route.capability_id != "automation.schedule"
            || route.oracle_ids
                != BTreeSet::from(["goal".into(), "operating_state".into(), "outcome".into()])
        {
            return Err(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch);
        }
        if resolved_at < decision.decided_at
            || resolved_at < review.observed_at
            || resolved_at < parent_mission.updated_at
            || resolved_at < mission.updated_at
        {
            return Err(OutcomeLedgerError::OutcomeReviewResolutionTimeInvalid);
        }

        let (continued_contract_digest, terminal_disposition) =
            match (decision.action.clone(), decision.next_contract_intent) {
                (OutcomeDecision::Stop, OutcomeReviewNextContractIntent::ValidTerminal) => {
                    (None, Some(MissionTerminalDisposition::Completed))
                }
                (
                    OutcomeDecision::Continue,
                    OutcomeReviewNextContractIntent::ContinueCurrentContract,
                ) => {
                    parent_mission
                        .contract
                        .validate(resolved_at)
                        .map_err(|_| OutcomeLedgerError::OutcomeReviewCurrentContractUnavailable)?;
                    (Some(source_contract_digest.clone()), None)
                }
                (
                    OutcomeDecision::Scale,
                    OutcomeReviewNextContractIntent::ScaleWithRevisedContract,
                ) => {
                    return Err(
                        OutcomeLedgerError::OutcomeReviewRevisedContractAuthorizationRequired,
                    );
                }
                (OutcomeDecision::Test, OutcomeReviewNextContractIntent::TestWithNewExperiment) => {
                    return Err(
                        OutcomeLedgerError::OutcomeReviewExperimentContractAuthorizationRequired,
                    );
                }
                _ => return Err(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch),
            };

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION,
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            cycle: decision.cycle,
            decision_digest: decision.digest()?,
            action: decision.action.clone(),
            next_contract_intent: decision.next_contract_intent,
            source_mission_id: parent_mission.id.clone(),
            source_mission_revision: parent_mission.revision,
            source_contract_digest,
            continued_contract_digest,
            terminal_disposition,
            resolved_at,
        })
    }

    /// Reconstructs the typed output from the append-once Checkpoint evidence
    /// and immutable Human decision. No serialized resolution side channel is
    /// trusted during replay.
    pub fn reconstruct_persisted(
        mission: &Mission,
        parent_mission: &Mission,
        review: &OutcomeReviewProjection,
        decision: &OutcomeReviewDecision,
        resolved_at: DateTime<Utc>,
    ) -> Result<Self, OutcomeLedgerError> {
        let source_contract_digest =
            validate_next_contract_resolution_sources(mission, parent_mission, review, decision)?;
        if resolved_at < decision.decided_at
            || resolved_at < review.observed_at
            || resolved_at < parent_mission.updated_at
            || resolved_at < mission.updated_at
        {
            return Err(OutcomeLedgerError::OutcomeReviewResolutionTimeInvalid);
        }
        let (continued_contract_digest, terminal_disposition) =
            match (decision.action.clone(), decision.next_contract_intent) {
                (OutcomeDecision::Stop, OutcomeReviewNextContractIntent::ValidTerminal) => {
                    (None, Some(MissionTerminalDisposition::Completed))
                }
                (
                    OutcomeDecision::Continue,
                    OutcomeReviewNextContractIntent::ContinueCurrentContract,
                ) => {
                    parent_mission
                        .contract
                        .validate(resolved_at)
                        .map_err(|_| OutcomeLedgerError::OutcomeReviewCurrentContractUnavailable)?;
                    (Some(source_contract_digest.clone()), None)
                }
                (
                    OutcomeDecision::Scale,
                    OutcomeReviewNextContractIntent::ScaleWithRevisedContract,
                ) => {
                    return Err(
                        OutcomeLedgerError::OutcomeReviewRevisedContractAuthorizationRequired,
                    );
                }
                (OutcomeDecision::Test, OutcomeReviewNextContractIntent::TestWithNewExperiment) => {
                    return Err(
                        OutcomeLedgerError::OutcomeReviewExperimentContractAuthorizationRequired,
                    );
                }
                _ => return Err(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch),
            };
        let resolution = Self {
            schema_version: Self::SCHEMA_VERSION,
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            cycle: decision.cycle,
            decision_digest: decision.digest()?,
            action: decision.action.clone(),
            next_contract_intent: decision.next_contract_intent,
            source_mission_id: parent_mission.id.clone(),
            source_mission_revision: parent_mission.revision,
            source_contract_digest,
            continued_contract_digest,
            terminal_disposition,
            resolved_at,
        };
        resolution.validate_persisted(mission, parent_mission, review, decision)?;
        Ok(resolution)
    }

    pub fn digest(&self) -> Result<String, OutcomeLedgerError> {
        canonical_json_digest(self)
    }

    pub fn decision_source_id(&self) -> String {
        format!(
            "{}:cycle:{}:{}:{}",
            self.mission_id,
            self.cycle,
            outcome_decision_name(&self.action),
            next_contract_intent_name(self.next_contract_intent)
        )
    }

    /// Revalidates the reconstructed resolution against normalized Mission
    /// state. This is called inside the SQLCipher transaction before the
    /// append-once Checkpoint completion becomes durable.
    pub fn validate_persisted(
        &self,
        mission: &Mission,
        parent_mission: &Mission,
        review: &OutcomeReviewProjection,
        decision: &OutcomeReviewDecision,
    ) -> Result<(), OutcomeLedgerError> {
        let source_contract_digest =
            validate_next_contract_resolution_sources(mission, parent_mission, review, decision)?;
        let definition = mission
            .definition
            .as_ref()
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        let checkpoint = definition
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.id == "next_contract_or_valid_terminal")
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        let completion = checkpoint
            .completion
            .as_ref()
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        let evidence = completion
            .application_evidence
            .as_ref()
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        let parent_source = evidence
            .sources
            .iter()
            .find(|source| source.source_kind == "parent_mission_contract")
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        let decision_source = evidence
            .sources
            .iter()
            .find(|source| source.source_kind == "outcome_review_decision")
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        let checkpoint_source = evidence
            .sources
            .iter()
            .find(|source| source.source_kind == "mission_checkpoint")
            .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
        let expected_sources = BTreeSet::from([
            "mission_checkpoint",
            "outcome_review_decision",
            "parent_mission_contract",
        ]);
        if self.schema_version != Self::SCHEMA_VERSION
            || self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
            || self.cycle != decision.cycle
            || self.decision_digest != decision.digest()?
            || self.action != decision.action
            || self.next_contract_intent != decision.next_contract_intent
            || self.source_mission_id != parent_mission.id
            || self.source_mission_revision != parent_mission.revision
            || self.source_contract_digest != source_contract_digest
            || self.resolved_at < decision.decided_at
            || self.resolved_at < review.observed_at
            || self.resolved_at < parent_mission.updated_at
            || self.resolved_at < mission.updated_at
            || definition.manifest_id != "VM-11"
            || definition.cycle != self.cycle
            || checkpoint.status != MissionCheckpointStatus::Completed
            || evidence.handler_id != Self::HANDLER_ID
            || evidence.observed_at != self.resolved_at
            || completion.verified_at != self.resolved_at
            || completion.evidence_digest != evidence.digest()
            || evidence
                .sources
                .iter()
                .map(|source| source.source_kind.as_str())
                .collect::<BTreeSet<_>>()
                != expected_sources
            || parent_source.source_id != parent_mission.id.as_str()
            || parent_source.source_revision != parent_mission.revision
            || parent_source.projection_digest != source_contract_digest
            || decision_source.source_id != self.decision_source_id()
            || decision_source.source_revision != decision.cycle
            || decision_source.projection_digest != self.decision_digest
            || checkpoint_source.source_id != format!("{}:{}", mission.id, checkpoint.id)
            || checkpoint_source.source_revision != evidence.dispatch_checkpoint_revision
        {
            return Err(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch);
        }

        validate_persisted_next_contract_closure(
            self,
            mission,
            parent_mission,
            &source_contract_digest,
        )
    }
}

fn validate_persisted_next_contract_closure(
    resolution: &OutcomeReviewNextContractResolution,
    mission: &Mission,
    parent_mission: &Mission,
    source_contract_digest: &str,
) -> Result<(), OutcomeLedgerError> {
    let candidate = mission
        .definition
        .as_ref()
        .and_then(|definition| {
            definition
                .checkpoints
                .iter()
                .find(|candidate| candidate.id == "candidate_learning")
        })
        .ok_or(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch)?;
    match (resolution.action.clone(), resolution.next_contract_intent) {
        (OutcomeDecision::Stop, OutcomeReviewNextContractIntent::ValidTerminal)
            if resolution.continued_contract_digest.is_none()
                && resolution.terminal_disposition
                    == Some(MissionTerminalDisposition::Completed)
                && mission.stage == MissionStage::Completed
                && candidate.status == MissionCheckpointStatus::Skipped => {}
        (OutcomeDecision::Continue, OutcomeReviewNextContractIntent::ContinueCurrentContract)
            if resolution.continued_contract_digest.as_deref() == Some(source_contract_digest)
                && resolution.terminal_disposition.is_none()
                && candidate.status != MissionCheckpointStatus::Skipped
                && !mission.stage.is_terminal() =>
        {
            parent_mission
                .contract
                .validate(resolution.resolved_at)
                .map_err(|_| OutcomeLedgerError::OutcomeReviewCurrentContractUnavailable)?;
        }
        _ => return Err(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch),
    }
    Ok(())
}

fn validate_next_contract_resolution_sources(
    mission: &Mission,
    parent_mission: &Mission,
    review: &OutcomeReviewProjection,
    decision: &OutcomeReviewDecision,
) -> Result<String, OutcomeLedgerError> {
    decision.validate_persisted(mission, review)?;
    let source_contract_digest = mission_kpi_contract_source_digest(parent_mission)?;
    if mission.tenant_id != parent_mission.tenant_id
        || mission.project_id != parent_mission.project_id
        || mission.id == parent_mission.id
        || mission.contract.parent_mission_id.as_ref() != Some(&parent_mission.id)
        || parent_mission.contract.parent_mission_id.is_some()
        || parent_mission
            .definition
            .as_ref()
            .is_none_or(|definition| definition.manifest_id == "VM-11")
        || parent_mission.id != review.source_mission_id
        || parent_mission.id != decision.source_mission_id
        || parent_mission.revision != review.source_mission_revision
        || parent_mission.revision != decision.source_mission_revision
        || review.source_contract_digest != source_contract_digest
        || mission.contract.mode != parent_mission.contract.mode
        || mission.contract.market != parent_mission.contract.market
        || mission.contract.language != parent_mission.contract.language
        || mission.contract.audience != parent_mission.contract.audience
        || mission.contract.timezone != parent_mission.contract.timezone
        || mission.contract.budget != parent_mission.contract.budget
        || mission.contract.kpis != parent_mission.contract.kpis
    {
        return Err(OutcomeLedgerError::OutcomeReviewNextContractSourceMismatch);
    }
    Ok(source_contract_digest)
}

fn outcome_decision_name(action: &OutcomeDecision) -> &'static str {
    match action {
        OutcomeDecision::Continue => "continue",
        OutcomeDecision::Stop => "stop",
        OutcomeDecision::Scale => "scale",
        OutcomeDecision::Test => "test",
    }
}

fn next_contract_intent_name(intent: OutcomeReviewNextContractIntent) -> &'static str {
    match intent {
        OutcomeReviewNextContractIntent::ValidTerminal => "valid_terminal",
        OutcomeReviewNextContractIntent::ContinueCurrentContract => "continue_current_contract",
        OutcomeReviewNextContractIntent::ScaleWithRevisedContract => "scale_with_revised_contract",
        OutcomeReviewNextContractIntent::TestWithNewExperiment => "test_with_new_experiment",
    }
}

fn decision_contract_intent(action: &OutcomeDecision) -> OutcomeReviewNextContractIntent {
    match action {
        OutcomeDecision::Stop => OutcomeReviewNextContractIntent::ValidTerminal,
        OutcomeDecision::Continue => OutcomeReviewNextContractIntent::ContinueCurrentContract,
        OutcomeDecision::Scale => OutcomeReviewNextContractIntent::ScaleWithRevisedContract,
        OutcomeDecision::Test => OutcomeReviewNextContractIntent::TestWithNewExperiment,
    }
}

fn validate_outcome_review_action(
    review: &OutcomeReviewProjection,
    action: &OutcomeDecision,
    intent: OutcomeReviewNextContractIntent,
) -> Result<(), OutcomeLedgerError> {
    if intent != decision_contract_intent(action) {
        return Err(OutcomeLedgerError::OutcomeReviewDecisionActionForbidden);
    }
    match (action, review.decision_gate(action.clone()).status) {
        (_, OutcomeReviewDecisionGateStatus::Available) => Ok(()),
        (
            OutcomeDecision::Scale,
            OutcomeReviewDecisionGateStatus::BlockedLoopPolicy
            | OutcomeReviewDecisionGateStatus::BlockedScaleEvidence,
        ) => Err(OutcomeLedgerError::OutcomeReviewDecisionScaleBlocked),
        (
            OutcomeDecision::Continue | OutcomeDecision::Stop | OutcomeDecision::Test,
            OutcomeReviewDecisionGateStatus::BlockedLoopPolicy
            | OutcomeReviewDecisionGateStatus::BlockedScaleEvidence,
        ) => Err(OutcomeLedgerError::OutcomeReviewDecisionActionForbidden),
    }
}

impl OutcomeLedger {
    pub fn new(tenant_id: TenantId, project_id: ProjectId) -> Result<Self, OutcomeLedgerError> {
        if tenant_id.as_str().trim().is_empty() || project_id.as_str().trim().is_empty() {
            return Err(OutcomeLedgerError::InvalidLedgerScope);
        }
        Ok(Self {
            tenant_id,
            project_id,
            events: Vec::new(),
            orders: Vec::new(),
            refunds: Vec::new(),
            attributions: Vec::new(),
            commissions: Vec::new(),
            revision: 1,
        })
    }

    /// Revalidates a normalized persisted projection without trusting serialized state.
    pub fn validate(&self) -> Result<(), OutcomeLedgerError> {
        if self.tenant_id.as_str().trim().is_empty() || self.project_id.as_str().trim().is_empty() {
            return Err(OutcomeLedgerError::InvalidLedgerScope);
        }
        let mutation_count = self
            .events
            .len()
            .checked_add(self.attributions.len())
            .and_then(|count| count.checked_add(self.commissions.len()))
            .ok_or(OutcomeLedgerError::RevisionOverflow)?;
        let expected_revision = u64::try_from(mutation_count)
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(OutcomeLedgerError::RevisionOverflow)?;
        if self.revision != expected_revision {
            return Err(OutcomeLedgerError::ProjectionRevisionMismatch {
                expected: expected_revision,
                actual: self.revision,
            });
        }

        let mut event_projection = Self::new(self.tenant_id.clone(), self.project_id.clone())?;
        for event in &self.events {
            event_projection.ingest_persisted(event.clone())?;
        }
        if event_projection.orders != self.orders || event_projection.refunds != self.refunds {
            return Err(OutcomeLedgerError::EventProjectionMismatch);
        }

        let mut attribution_ids = BTreeSet::new();
        for attribution in &self.attributions {
            if !attribution_ids.insert(attribution.id.clone()) {
                return Err(OutcomeLedgerError::DuplicateAttribution);
            }
            let order = self
                .orders
                .iter()
                .find(|order| order.id == attribution.order_id)
                .ok_or(OutcomeLedgerError::UnknownOrder)?;
            attribution.validate_persisted(&self.tenant_id, &self.project_id, order)?;
        }

        let mut commission_ids = BTreeSet::new();
        let mut active_by_order_partner = BTreeMap::new();
        for commission in &self.commissions {
            if !commission_ids.insert(commission.id.clone()) {
                return Err(OutcomeLedgerError::InvalidCommission);
            }
            self.validate_commission_record(commission)?;
            if commission.status != CommissionStatus::Superseded
                && active_by_order_partner
                    .insert(
                        (commission.order_id.clone(), commission.partner_id.clone()),
                        commission.id.clone(),
                    )
                    .is_some()
            {
                return Err(OutcomeLedgerError::CommissionInvariantViolation);
            }
        }
        Ok(())
    }

    pub fn ingest(&mut self, event: OutcomeEvent) -> Result<(), OutcomeLedgerError> {
        event.validate()?;
        self.ingest_validated(event)
    }

    fn ingest_persisted(&mut self, event: OutcomeEvent) -> Result<(), OutcomeLedgerError> {
        event.validate_persisted()?;
        self.ingest_validated(event)
    }

    fn ingest_validated(&mut self, event: OutcomeEvent) -> Result<(), OutcomeLedgerError> {
        if event.tenant_id != self.tenant_id || event.project_id != self.project_id {
            return Err(OutcomeLedgerError::ScopeMismatch);
        }
        if self.events.iter().any(|stored| {
            stored.id == event.id
                || (stored.provider == event.provider
                    && stored.source_event_id == event.source_event_id)
        }) {
            return Err(OutcomeLedgerError::DuplicateEvent);
        }
        let next_revision = self.next_revision()?;
        match event.kind {
            OutcomeEventKind::OrderPlaced => self.ingest_order(&event)?,
            OutcomeEventKind::RefundIssued => self.ingest_refund(&event)?,
            _ => {}
        }
        self.events.push(event);
        self.revision = next_revision;
        Ok(())
    }

    pub fn is_initial_snapshot(&self) -> Result<bool, OutcomeLedgerError> {
        self.validate()?;
        Ok(self.revision == 1
            && self.events.is_empty()
            && self.orders.is_empty()
            && self.refunds.is_empty()
            && self.attributions.is_empty()
            && self.commissions.is_empty())
    }

    /// Builds the VM-11 normalize/dedupe/order Oracle from the full immutable
    /// source. Unlike `validate`, which intentionally keeps pre-v17 snapshots
    /// readable for migration and reconciliation, this boundary requires every
    /// event to satisfy the current source-verification contract.
    pub fn verified_normalization_projection(
        &self,
    ) -> Result<OutcomeNormalizationProjection, OutcomeLedgerError> {
        self.validate()?;
        for event in &self.events {
            event.validate()?;
        }

        let event_count = u64::try_from(self.events.len())
            .map_err(|_| OutcomeLedgerError::ProjectionCountOverflow)?;
        let unique_event_ids = self
            .events
            .iter()
            .map(|event| event.id.as_str())
            .collect::<BTreeSet<_>>();
        let unique_provider_sources = self
            .events
            .iter()
            .map(|event| (event.provider.as_str(), event.source_event_id.as_str()))
            .collect::<BTreeSet<_>>();
        let unique_event_id_count = u64::try_from(unique_event_ids.len())
            .map_err(|_| OutcomeLedgerError::ProjectionCountOverflow)?;
        let unique_provider_source_count = u64::try_from(unique_provider_sources.len())
            .map_err(|_| OutcomeLedgerError::ProjectionCountOverflow)?;
        if unique_event_id_count != event_count || unique_provider_source_count != event_count {
            return Err(OutcomeLedgerError::DuplicateEvent);
        }

        let mut canonical_events = self.events.iter().collect::<Vec<_>>();
        canonical_events.sort_by(|left, right| {
            (
                left.occurred_at,
                left.received_at,
                left.provider.as_str(),
                left.source_event_id.as_str(),
                left.id.as_str(),
            )
                .cmp(&(
                    right.occurred_at,
                    right.received_at,
                    right.provider.as_str(),
                    right.source_event_id.as_str(),
                    right.id.as_str(),
                ))
        });
        let observed_reorder_count = u64::try_from(
            self.events
                .iter()
                .zip(&canonical_events)
                .filter(|(observed, canonical)| observed.id != canonical.id)
                .count(),
        )
        .map_err(|_| OutcomeLedgerError::ProjectionCountOverflow)?;

        let canonical_event_digest = canonical_outcome_event_digest(&canonical_events, event_count);
        let order_refund_projection_digest =
            canonical_order_refund_digest(&self.orders, &self.refunds);

        Ok(OutcomeNormalizationProjection {
            schema_version: OutcomeNormalizationProjection::SCHEMA_VERSION,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            source_ledger_revision: self.revision,
            event_count,
            unique_event_id_count,
            unique_provider_source_count,
            order_count: u64::try_from(self.orders.len())
                .map_err(|_| OutcomeLedgerError::ProjectionCountOverflow)?,
            refund_count: u64::try_from(self.refunds.len())
                .map_err(|_| OutcomeLedgerError::ProjectionCountOverflow)?,
            observed_reorder_count,
            canonical_event_digest,
            order_refund_projection_digest,
        })
    }

    /// Resolves the normalized ledger through one exact identity support
    /// closure. Callers must supply neither a partial graph nor unrelated
    /// records: exact closure equality is part of the Oracle so a convenient
    /// project-wide dump cannot accidentally mask a broken reference.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the identity Oracle deliberately validates every supported identity path and its exact transitive closure"
    )]
    pub fn verified_identity_chain_projection(
        &self,
        connections: &[ConnectionSnapshot],
        identity_links: &[IdentityLink],
        people: &[Person],
        companies: &[Company],
        partners: &[Partner],
        opportunities: &[Opportunity],
    ) -> Result<OutcomeIdentityChainProjection, OutcomeLedgerError> {
        let normalization = self.verified_normalization_projection()?;
        let connection_map = connections
            .iter()
            .map(|item| (item.id.clone(), item))
            .collect::<BTreeMap<_, _>>();
        let identity_map = identity_links
            .iter()
            .map(|item| (item.id.clone(), item))
            .collect::<BTreeMap<_, _>>();
        let person_map = people
            .iter()
            .map(|item| (item.id.clone(), item))
            .collect::<BTreeMap<_, _>>();
        let company_map = companies
            .iter()
            .map(|item| (item.id.clone(), item))
            .collect::<BTreeMap<_, _>>();
        let partner_map = partners
            .iter()
            .map(|item| (item.id.clone(), item))
            .collect::<BTreeMap<_, _>>();
        let opportunity_map = opportunities
            .iter()
            .map(|item| (item.id.clone(), item))
            .collect::<BTreeMap<_, _>>();
        if connection_map.len() != connections.len()
            || identity_map.len() != identity_links.len()
            || person_map.len() != people.len()
            || company_map.len() != companies.len()
            || partner_map.len() != partners.len()
            || opportunity_map.len() != opportunities.len()
        {
            return Err(OutcomeLedgerError::IdentityChainSupportClosureMismatch);
        }

        let in_scope = |tenant_id: &TenantId, project_id: &ProjectId| {
            tenant_id == &self.tenant_id && project_id == &self.project_id
        };
        for connection in connections {
            connection
                .validate()
                .map_err(|_| OutcomeLedgerError::IdentityRelationshipMismatch)?;
            if !in_scope(&connection.tenant_id, &connection.project_id) {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }
        for link in identity_links {
            link.validate()
                .map_err(|_| OutcomeLedgerError::IdentityRelationshipMismatch)?;
            if !in_scope(&link.tenant_id, &link.project_id) {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
            if link.status != IdentityLinkStatus::Confirmed {
                return Err(OutcomeLedgerError::IdentityLinkUnconfirmed);
            }
        }
        for person in people {
            person
                .validate()
                .map_err(|_| OutcomeLedgerError::IdentityRelationshipMismatch)?;
            if !in_scope(&person.tenant_id, &person.project_id) {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }
        for company in companies {
            company
                .validate()
                .map_err(|_| OutcomeLedgerError::IdentityRelationshipMismatch)?;
            if !in_scope(&company.tenant_id, &company.project_id) {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }
        for partner in partners {
            partner
                .validate()
                .map_err(|_| OutcomeLedgerError::IdentityRelationshipMismatch)?;
            if !in_scope(&partner.tenant_id, &partner.project_id) {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }
        for opportunity in opportunities {
            opportunity
                .validate()
                .map_err(|_| OutcomeLedgerError::IdentityRelationshipMismatch)?;
            if !in_scope(&opportunity.tenant_id, &opportunity.project_id) {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }

        let mut expected_connections = BTreeSet::new();
        let mut expected_identities = BTreeSet::new();
        let mut expected_opportunities = BTreeSet::new();
        let mut expected_partners = self
            .commissions
            .iter()
            .map(|record| record.partner_id.clone())
            .collect::<BTreeSet<_>>();
        let directly_linked_orders = self
            .events
            .iter()
            .filter(|event| event.kind == OutcomeEventKind::OrderPlaced)
            .map(|event| {
                if event.identity_link_id.is_none() {
                    return Err(OutcomeLedgerError::IdentityChainCoverageMismatch);
                }
                event
                    .order_id
                    .clone()
                    .ok_or(OutcomeLedgerError::IdentityChainCoverageMismatch)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut direct_identity_event_count = 0_u64;
        let mut inherited_order_identity_event_count = 0_u64;
        let mut external_account_match_count = 0_u64;
        let mut identity_covered_event_count = 0_u64;

        for event in &self.events {
            if let Some(connection_id) = &event.connection_id {
                expected_connections.insert(connection_id.clone());
                let connection = connection_map
                    .get(connection_id)
                    .ok_or(OutcomeLedgerError::IdentityChainSupportClosureMismatch)?;
                if connection.provider != event.provider
                    || Some(&connection.account_id) != event.account_id.as_ref()
                {
                    return Err(OutcomeLedgerError::IdentityProviderAccountMismatch);
                }
            }
            if let Some(link_id) = &event.identity_link_id {
                expected_identities.insert(link_id.clone());
                let link = identity_map
                    .get(link_id)
                    .ok_or(OutcomeLedgerError::IdentityChainSupportClosureMismatch)?;
                if let Some(account_id) = &event.account_id {
                    if !link.confirms_external_identity(&event.provider, account_id) {
                        return Err(OutcomeLedgerError::IdentityProviderAccountMismatch);
                    }
                    external_account_match_count = external_account_match_count
                        .checked_add(1)
                        .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                }
                direct_identity_event_count = direct_identity_event_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            }
            if let Some(opportunity_id) = &event.opportunity_id {
                expected_opportunities.insert(opportunity_id.clone());
            }
            if let Some(partner_id) = &event.partner_id {
                expected_partners.insert(partner_id.clone());
            }

            let covered = match event.kind {
                OutcomeEventKind::LeadQualified
                | OutcomeEventKind::MeetingBooked
                | OutcomeEventKind::OrderPlaced => event.identity_link_id.is_some(),
                OutcomeEventKind::RefundIssued
                | OutcomeEventKind::CommissionAccrued
                | OutcomeEventKind::CommissionReversed => {
                    let inherited = event
                        .order_id
                        .as_ref()
                        .is_some_and(|order_id| directly_linked_orders.contains(order_id));
                    if inherited {
                        inherited_order_identity_event_count = inherited_order_identity_event_count
                            .checked_add(1)
                            .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                    }
                    inherited
                        && (!matches!(
                            event.kind,
                            OutcomeEventKind::CommissionAccrued
                                | OutcomeEventKind::CommissionReversed
                        ) || event.partner_id.is_some())
                }
                OutcomeEventKind::OpportunityStageChanged => event.opportunity_id.is_some(),
                OutcomeEventKind::PayoutCompleted => event.partner_id.is_some(),
            };
            if !covered {
                return Err(OutcomeLedgerError::IdentityChainCoverageMismatch);
            }
            identity_covered_event_count = identity_covered_event_count
                .checked_add(1)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
        }

        if expected_connections != connection_map.keys().cloned().collect()
            || expected_identities != identity_map.keys().cloned().collect()
            || expected_opportunities != opportunity_map.keys().cloned().collect()
        {
            return Err(OutcomeLedgerError::IdentityChainSupportClosureMismatch);
        }

        let mut expected_people = BTreeSet::<PersonId>::new();
        let mut expected_companies = BTreeSet::<CompanyId>::new();
        for link in identity_links {
            match &link.subject {
                IdentitySubject::Person(id) => {
                    expected_people.insert(id.clone());
                }
                IdentitySubject::Company(id) => {
                    expected_companies.insert(id.clone());
                }
                IdentitySubject::Partner(id) => {
                    expected_partners.insert(id.clone());
                }
            }
        }
        for opportunity in opportunities {
            expected_companies.insert(opportunity.company_id.clone());
            expected_people.extend(
                opportunity
                    .buying_committee
                    .iter()
                    .map(|member| member.person_id.clone()),
            );
        }
        if expected_partners != partner_map.keys().cloned().collect() {
            return Err(OutcomeLedgerError::IdentityChainSupportClosureMismatch);
        }
        for partner in partners {
            if let Some(person_id) = &partner.person_id {
                expected_people.insert(person_id.clone());
            }
            if let Some(company_id) = &partner.company_id {
                expected_companies.insert(company_id.clone());
            }
        }
        if expected_people != person_map.keys().cloned().collect() {
            return Err(OutcomeLedgerError::IdentityChainSupportClosureMismatch);
        }
        for person in people {
            if let Some(company_id) = &person.company_id {
                expected_companies.insert(company_id.clone());
            }
        }
        if expected_companies != company_map.keys().cloned().collect() {
            return Err(OutcomeLedgerError::IdentityChainSupportClosureMismatch);
        }

        for link in identity_links {
            let subject_exists = match &link.subject {
                IdentitySubject::Person(id) => person_map.contains_key(id),
                IdentitySubject::Company(id) => company_map.contains_key(id),
                IdentitySubject::Partner(id) => partner_map.contains_key(id),
            };
            if !subject_exists {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }
        for person in people {
            if person
                .company_id
                .as_ref()
                .is_some_and(|id| !company_map.contains_key(id))
            {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }
        for partner in partners {
            let person = partner
                .person_id
                .as_ref()
                .map(|id| {
                    person_map
                        .get(id)
                        .copied()
                        .ok_or(OutcomeLedgerError::IdentityRelationshipMismatch)
                })
                .transpose()?;
            if partner
                .company_id
                .as_ref()
                .is_some_and(|id| !company_map.contains_key(id))
                || matches!(
                    (
                        partner.company_id.as_ref(),
                        person.and_then(|person| person.company_id.as_ref())
                    ),
                    (Some(partner_company), Some(person_company))
                        if partner_company != person_company
                )
            {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }
        for opportunity in opportunities {
            if !company_map.contains_key(&opportunity.company_id)
                || opportunity
                    .buying_committee
                    .iter()
                    .any(|member| !person_map.contains_key(&member.person_id))
            {
                return Err(OutcomeLedgerError::IdentityRelationshipMismatch);
            }
        }

        let event_count = u64::try_from(self.events.len())
            .map_err(|_| OutcomeLedgerError::ProjectionCountOverflow)?;
        if identity_covered_event_count != event_count {
            return Err(OutcomeLedgerError::IdentityChainCoverageMismatch);
        }
        let source_support = serde_json::json!({
            "schemaVersion": "hartevo-outcome-identity-support/v1",
            "normalizationDigest": normalization.digest(),
            "connections": connection_map.values().copied().collect::<Vec<_>>(),
            "identityLinks": identity_map.values().copied().collect::<Vec<_>>(),
            "people": person_map.values().copied().collect::<Vec<_>>(),
            "companies": company_map.values().copied().collect::<Vec<_>>(),
            "partners": partner_map.values().copied().collect::<Vec<_>>(),
            "opportunities": opportunity_map.values().copied().collect::<Vec<_>>(),
        });
        let source_support_digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&source_support)
                    .map_err(|_| OutcomeLedgerError::ProjectionSerialization)?
            )
        );
        let partner_policy_digest =
            canonical_json_digest(&partner_map.values().copied().collect::<Vec<_>>())?;

        Ok(OutcomeIdentityChainProjection {
            schema_version: OutcomeIdentityChainProjection::SCHEMA_VERSION,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            source_ledger_revision: self.revision,
            event_count,
            identity_covered_event_count,
            direct_identity_event_count,
            inherited_order_identity_event_count,
            external_account_match_count,
            connection_count: projection_count(connections.len())?,
            identity_link_count: projection_count(identity_links.len())?,
            person_count: projection_count(people.len())?,
            company_count: projection_count(companies.len())?,
            partner_count: projection_count(partners.len())?,
            opportunity_count: projection_count(opportunities.len())?,
            partner_policy_digest,
            source_support_digest,
        })
    }

    /// Recomputes the parent Mission's contracted KPI values from current,
    /// source-verified Outcome events. The event window is explicit and
    /// receive/verification timestamps are cut off at `observed_at`, so a
    /// future callback cannot leak into an earlier replay.
    #[allow(
        clippy::too_many_lines,
        reason = "the deterministic KPI Oracle keeps scope, current identity, event ownership/window, canonical ordering, contract evaluation, and all bound digests visible in one audit path"
    )]
    pub fn verified_mission_kpi_projection(
        &self,
        source_mission: &Mission,
        identity_chain: &OutcomeIdentityChainProjection,
        observed_at: DateTime<Utc>,
    ) -> Result<MissionKpiProjection, OutcomeLedgerError> {
        let normalization = self.verified_normalization_projection()?;
        if identity_chain.tenant_id != self.tenant_id
            || identity_chain.project_id != self.project_id
            || identity_chain.source_ledger_revision != self.revision
            || identity_chain.event_count != normalization.event_count
            || identity_chain.identity_covered_event_count != normalization.event_count
        {
            return Err(OutcomeLedgerError::KpiIdentityChainMismatch);
        }
        if source_mission.tenant_id != self.tenant_id
            || source_mission.project_id != self.project_id
            || source_mission.revision == 0
        {
            return Err(OutcomeLedgerError::KpiMissionScopeMismatch);
        }
        source_mission
            .contract
            .validate(source_mission.contract.valid_from)
            .map_err(|_| OutcomeLedgerError::InvalidKpiContract)?;
        if source_mission.contract.kpis.is_empty()
            || observed_at < source_mission.contract.valid_from
        {
            return Err(OutcomeLedgerError::InvalidKpiContract);
        }
        let window_started_at = source_mission.contract.valid_from;
        let window_ended_at = observed_at.min(source_mission.contract.valid_until);

        let order_missions = self
            .events
            .iter()
            .filter(|event| event.kind == OutcomeEventKind::OrderPlaced)
            .map(|event| {
                event
                    .order_id
                    .clone()
                    .map(|order_id| (order_id, event.mission_id.clone()))
                    .ok_or(OutcomeLedgerError::EventKindShapeMismatch)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        for event in &self.events {
            if matches!(
                event.kind,
                OutcomeEventKind::RefundIssued
                    | OutcomeEventKind::CommissionAccrued
                    | OutcomeEventKind::CommissionReversed
            ) && event
                .order_id
                .as_ref()
                .is_none_or(|order_id| !order_missions.contains_key(order_id))
            {
                return Err(OutcomeLedgerError::UnknownOrder);
            }
        }

        let mut scoped_events = self
            .events
            .iter()
            .filter(|event| {
                let owning_mission = match event.kind {
                    OutcomeEventKind::RefundIssued
                    | OutcomeEventKind::CommissionAccrued
                    | OutcomeEventKind::CommissionReversed => event
                        .order_id
                        .as_ref()
                        .and_then(|order_id| order_missions.get(order_id))
                        .unwrap_or(&event.mission_id),
                    _ => &event.mission_id,
                };
                owning_mission == &source_mission.id
                    && event.occurred_at >= window_started_at
                    && event.occurred_at <= window_ended_at
                    && event.received_at <= observed_at
                    && event
                        .source_verification
                        .as_ref()
                        .is_some_and(|verification| verification.verified_at <= observed_at)
            })
            .collect::<Vec<_>>();
        if scoped_events.is_empty() {
            return Err(OutcomeLedgerError::KpiSourceEventsUnavailable);
        }
        scoped_events.sort_by(|left, right| {
            (
                left.occurred_at,
                left.received_at,
                left.provider.as_str(),
                left.source_event_id.as_str(),
                left.id.as_str(),
            )
                .cmp(&(
                    right.occurred_at,
                    right.received_at,
                    right.provider.as_str(),
                    right.source_event_id.as_str(),
                    right.id.as_str(),
                ))
        });
        let source_event_count = projection_count(scoped_events.len())?;
        let source_event_digest =
            canonical_outcome_event_digest(&scoped_events, source_event_count);

        let mut measurements = BTreeMap::new();
        let mut target_met_count = 0_u64;
        for (metric_id, contract) in &source_mission.contract.kpis {
            let measurement = mission_kpi_measurement(metric_id, contract, &scoped_events)?;
            if measurement.target_met {
                target_met_count = target_met_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            }
            measurements.insert(metric_id.clone(), measurement);
        }
        let measurement_count = projection_count(measurements.len())?;
        let source_contract_digest = mission_kpi_contract_source_digest(source_mission)?;
        Ok(MissionKpiProjection {
            schema_version: MissionKpiProjection::SCHEMA_VERSION,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            source_mission_id: source_mission.id.clone(),
            source_mission_revision: source_mission.revision,
            source_ledger_revision: self.revision,
            window_started_at,
            window_ended_at,
            source_event_count,
            measurement_count,
            target_met_count,
            source_contract_digest,
            source_event_digest,
            normalization_digest: normalization.digest(),
            identity_chain_digest: identity_chain.digest(),
            measurements,
        })
    }

    /// Returns the exact Mission closure referenced by source records for the
    /// parent Mission's currently observable orders. Application loads and
    /// revision-fences this set before asking the Oracle to decide attribution.
    pub fn attribution_support_mission_ids(
        &self,
        source_mission: &Mission,
        observed_at: DateTime<Utc>,
    ) -> Result<BTreeSet<MissionId>, OutcomeLedgerError> {
        self.verified_normalization_projection()?;
        let (_, _, source_orders) = self.source_mission_orders(source_mission, observed_at)?;
        let order_ids = source_orders.keys().cloned().collect::<BTreeSet<_>>();
        let mut mission_ids = BTreeSet::new();
        for record in self.attributions.iter().filter(|record| {
            order_ids.contains(&record.order_id) && record.recorded_at <= observed_at
        }) {
            match record.model {
                AttributionModel::Unattributed => {
                    if record.touchpoint.is_some() {
                        return Err(OutcomeLedgerError::InvalidAttribution);
                    }
                }
                _ => {
                    mission_ids.insert(
                        record
                            .touchpoint
                            .as_ref()
                            .ok_or(OutcomeLedgerError::InvalidAttribution)?
                            .mission_id
                            .clone(),
                    );
                }
            }
        }
        Ok(mission_ids)
    }

    /// Computes the frozen operational attribution views for one parent
    /// Mission. Verified link/coupon/provider identity wins; otherwise the
    /// latest non-direct touchpoint is the primary operational view. First
    /// touch is retained separately and missing support remains Unattributed.
    /// No result is represented as causal.
    #[allow(
        clippy::too_many_lines,
        reason = "the deterministic attribution Oracle keeps source cutoff, exact Mission/Effect support closure, dispute handling, first/last views, Unattributed preservation, and every digest in one reviewable path"
    )]
    pub fn verified_attribution_projection(
        &self,
        source_mission: &Mission,
        identity_chain: &OutcomeIdentityChainProjection,
        supporting_missions: &[Mission],
        observed_at: DateTime<Utc>,
    ) -> Result<OutcomeAttributionProjection, OutcomeLedgerError> {
        let normalization = self.verified_normalization_projection()?;
        if identity_chain.tenant_id != self.tenant_id
            || identity_chain.project_id != self.project_id
            || identity_chain.source_ledger_revision != self.revision
            || identity_chain.event_count != normalization.event_count
            || identity_chain.identity_covered_event_count != normalization.event_count
        {
            return Err(OutcomeLedgerError::AttributionIdentityChainMismatch);
        }
        let (window_started_at, window_ended_at, source_orders) =
            self.source_mission_orders(source_mission, observed_at)?;
        let expected_mission_ids =
            self.attribution_support_mission_ids(source_mission, observed_at)?;
        let mut mission_support = BTreeMap::new();
        for mission in supporting_missions {
            if mission.tenant_id != self.tenant_id
                || mission.project_id != self.project_id
                || mission.revision == 0
                || mission_support
                    .insert(mission.id.clone(), mission)
                    .is_some()
            {
                return Err(OutcomeLedgerError::AttributionSupportClosureMismatch);
            }
            mission
                .contract
                .validate(mission.contract.valid_from)
                .map_err(|_| OutcomeLedgerError::AttributionSupportClosureMismatch)?;
        }
        if mission_support.keys().cloned().collect::<BTreeSet<_>>() != expected_mission_ids {
            return Err(OutcomeLedgerError::AttributionSupportClosureMismatch);
        }

        let mut order_views = BTreeMap::new();
        let mut source_records = Vec::new();
        let mut effect_support = BTreeMap::new();
        let mut source_record_count = 0_u64;
        let mut eligible_touchpoint_count = 0_u64;
        let mut verified_identity_order_count = 0_u64;
        let mut last_non_direct_order_count = 0_u64;
        let mut unattributed_order_count = 0_u64;
        let mut first_touch_order_count = 0_u64;
        let mut explicit_unattributed_record_count = 0_u64;

        for (order_id, (order, _order_event)) in &source_orders {
            let mut records = self
                .attributions
                .iter()
                .filter(|record| record.order_id == *order_id && record.recorded_at <= observed_at)
                .collect::<Vec<_>>();
            records.sort_by(|left, right| {
                (left.recorded_at, left.id.as_str()).cmp(&(right.recorded_at, right.id.as_str()))
            });
            source_record_count = source_record_count
                .checked_add(projection_count(records.len())?)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            source_records.extend(records.iter().copied());

            let mut eligible = Vec::new();
            let mut explicit_unattributed = 0_u64;
            let mut touchpoint_digests = BTreeSet::new();
            for record in records {
                record.validate(&self.tenant_id, &self.project_id, order)?;
                if record.model == AttributionModel::Unattributed {
                    explicit_unattributed = explicit_unattributed
                        .checked_add(1)
                        .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                    continue;
                }
                let touchpoint = record
                    .touchpoint
                    .as_ref()
                    .ok_or(OutcomeLedgerError::InvalidAttribution)?;
                let received_at = touchpoint
                    .received_at
                    .ok_or(OutcomeLedgerError::UnverifiedAttributionSource)?;
                let verification = touchpoint
                    .source_verification
                    .as_ref()
                    .ok_or(OutcomeLedgerError::UnverifiedAttributionSource)?;
                if touchpoint.occurred_at < window_started_at
                    || touchpoint.occurred_at > window_ended_at
                    || received_at > observed_at
                    || verification.verified_at > observed_at
                {
                    return Err(OutcomeLedgerError::AttributionWindowMismatch);
                }
                let support_mission = mission_support
                    .get(&touchpoint.mission_id)
                    .copied()
                    .ok_or(OutcomeLedgerError::AttributionSupportClosureMismatch)?;
                if support_mission.created_at > touchpoint.occurred_at
                    || touchpoint.occurred_at < support_mission.contract.valid_from
                    || touchpoint.occurred_at > support_mission.contract.valid_until
                {
                    return Err(OutcomeLedgerError::AttributionWindowMismatch);
                }
                let touchpoint_digest = attribution_touchpoint_digest(record)?;
                if !touchpoint_digests.insert(touchpoint_digest.clone()) {
                    return Err(OutcomeLedgerError::DuplicateAttributionTouchpoint);
                }
                if let Some(effect_id) = &touchpoint.effect_id {
                    let effect = support_mission
                        .effects
                        .iter()
                        .find(|effect| &effect.id == effect_id)
                        .ok_or(OutcomeLedgerError::AttributionEffectSupportInvalid)?;
                    let support = verified_attribution_effect_support(
                        record,
                        touchpoint,
                        support_mission,
                        effect,
                        order,
                        observed_at,
                    )?;
                    let key = (support_mission.id.clone(), effect.id.clone());
                    if let Some(existing) = effect_support.get(&key) {
                        if existing != &support {
                            return Err(OutcomeLedgerError::AttributionEffectSupportInvalid);
                        }
                    } else {
                        effect_support.insert(key, support);
                    }
                } else if record.model == AttributionModel::VerifiedIdentity {
                    return Err(OutcomeLedgerError::AttributionEffectSupportInvalid);
                }
                eligible.push(EligibleAttribution {
                    attribution_id: record.id.clone(),
                    model: record.model,
                    traffic_class: touchpoint
                        .traffic_class
                        .ok_or(OutcomeLedgerError::UnverifiedAttributionSource)?,
                    provider_identity_digest: touchpoint.provider_identity_digest.clone(),
                    verified_link_or_coupon_digest: touchpoint
                        .verified_link_or_coupon_digest
                        .clone(),
                    occurred_at: touchpoint.occurred_at,
                    recorded_at: record.recorded_at,
                    touchpoint_digest,
                });
            }

            eligible_touchpoint_count = eligible_touchpoint_count
                .checked_add(projection_count(eligible.len())?)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            explicit_unattributed_record_count = explicit_unattributed_record_count
                .checked_add(explicit_unattributed)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;

            let verified = eligible
                .iter()
                .filter(|candidate| candidate.model == AttributionModel::VerifiedIdentity)
                .collect::<Vec<_>>();
            let verified_identity_keys = verified
                .iter()
                .map(|candidate| {
                    (
                        candidate.provider_identity_digest.as_deref(),
                        candidate.verified_link_or_coupon_digest.as_deref(),
                    )
                })
                .collect::<BTreeSet<_>>();
            if verified_identity_keys.len() > 1 {
                return Err(OutcomeLedgerError::DisputedAttribution);
            }
            let verified_primary = unique_attribution_extreme(&verified, false)?;
            let non_direct = eligible
                .iter()
                .filter(|candidate| candidate.traffic_class == AttributionTrafficClass::NonDirect)
                .collect::<Vec<_>>();
            let last_non_direct = unique_attribution_extreme(&non_direct, false)?;
            let all_candidates = eligible.iter().collect::<Vec<_>>();
            let first_touch = unique_attribution_extreme(&all_candidates, true)?;

            let (primary_model, primary) = if let Some(primary) = verified_primary {
                verified_identity_order_count = verified_identity_order_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                (AttributionModel::VerifiedIdentity, Some(primary))
            } else if let Some(primary) = last_non_direct {
                last_non_direct_order_count = last_non_direct_order_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                (AttributionModel::LastNonDirect, Some(primary))
            } else {
                unattributed_order_count = unattributed_order_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                (AttributionModel::Unattributed, None)
            };
            if first_touch.is_some() {
                first_touch_order_count = first_touch_order_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            }
            order_views.insert(
                order_id.clone(),
                OrderAttributionView {
                    order_id: order_id.clone(),
                    primary_model,
                    primary_attribution_id: primary
                        .map(|candidate| candidate.attribution_id.clone()),
                    primary_touchpoint_digest: primary
                        .map(|candidate| candidate.touchpoint_digest.clone()),
                    first_touch_attribution_id: first_touch
                        .map(|candidate| candidate.attribution_id.clone()),
                    first_touch_digest: first_touch
                        .map(|candidate| candidate.touchpoint_digest.clone()),
                    last_non_direct_attribution_id: last_non_direct
                        .map(|candidate| candidate.attribution_id.clone()),
                    last_non_direct_digest: last_non_direct
                        .map(|candidate| candidate.touchpoint_digest.clone()),
                    source_record_count: projection_count(
                        self.attributions
                            .iter()
                            .filter(|record| {
                                record.order_id == *order_id && record.recorded_at <= observed_at
                            })
                            .count(),
                    )?,
                    eligible_touchpoint_count: projection_count(eligible.len())?,
                    explicit_unattributed_record_count: explicit_unattributed,
                    causal_claim: false,
                },
            );
        }

        source_records.sort_by(|left, right| {
            (left.order_id.as_str(), left.recorded_at, left.id.as_str()).cmp(&(
                right.order_id.as_str(),
                right.recorded_at,
                right.id.as_str(),
            ))
        });
        let source_record_digest = canonical_json_digest(&source_records)?;
        let effect_support_digest =
            canonical_json_digest(&effect_support.values().collect::<Vec<_>>())?;
        Ok(OutcomeAttributionProjection {
            schema_version: OutcomeAttributionProjection::SCHEMA_VERSION,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            source_mission_id: source_mission.id.clone(),
            source_mission_revision: source_mission.revision,
            source_ledger_revision: self.revision,
            window_started_at,
            window_ended_at,
            order_count: projection_count(order_views.len())?,
            source_record_count,
            eligible_touchpoint_count,
            verified_identity_order_count,
            last_non_direct_order_count,
            unattributed_order_count,
            first_touch_order_count,
            explicit_unattributed_record_count,
            supporting_mission_count: projection_count(expected_mission_ids.len())?,
            verified_effect_count: projection_count(effect_support.len())?,
            causal_claim: false,
            normalization_digest: normalization.digest(),
            identity_chain_digest: identity_chain.digest(),
            source_record_digest,
            effect_support_digest,
            orders: order_views,
        })
    }

    /// Recomputes refund, commission, and verified payout state for the exact
    /// parent Mission. Orders remain immutable, cross-period refunds are
    /// included through `observed_at`, and stale commission revisions fail
    /// closed until a replacement binds the current refund set.
    #[allow(
        clippy::too_many_lines,
        reason = "the settlement Oracle keeps authority boundaries, cross-period refunds, commission revision selection, payout reconciliation, and all canonical digests in one auditable path"
    )]
    pub fn verified_settlement_projection(
        &self,
        source_mission: &Mission,
        identity_chain: &OutcomeIdentityChainProjection,
        partners: &[Partner],
        observed_at: DateTime<Utc>,
    ) -> Result<OutcomeSettlementProjection, OutcomeLedgerError> {
        let normalization = self.verified_normalization_projection()?;
        if identity_chain.tenant_id != self.tenant_id
            || identity_chain.project_id != self.project_id
            || identity_chain.source_ledger_revision != self.revision
            || identity_chain.event_count != normalization.event_count
            || identity_chain.identity_covered_event_count != normalization.event_count
        {
            return Err(OutcomeLedgerError::SettlementIdentityChainMismatch);
        }
        let (window_started_at, _order_window_ended_at, source_orders) = self
            .source_mission_orders(source_mission, observed_at)
            .map_err(|error| match error {
                OutcomeLedgerError::AttributionMissionScopeMismatch => {
                    OutcomeLedgerError::SettlementMissionScopeMismatch
                }
                OutcomeLedgerError::AttributionWindowMismatch => {
                    OutcomeLedgerError::SettlementWindowMismatch
                }
                OutcomeLedgerError::AttributionSourceOrdersUnavailable => {
                    OutcomeLedgerError::SettlementSourceOrdersUnavailable
                }
                other => other,
            })?;
        let source_order_ids = source_orders.keys().cloned().collect::<BTreeSet<_>>();

        let mut partner_map = BTreeMap::new();
        for partner in partners {
            partner
                .validate()
                .map_err(|_| OutcomeLedgerError::SettlementPartnerPolicyMismatch)?;
            if partner.tenant_id != self.tenant_id
                || partner.project_id != self.project_id
                || partner_map.insert(partner.id.clone(), partner).is_some()
            {
                return Err(OutcomeLedgerError::SettlementPartnerPolicyMismatch);
            }
        }
        let expected_partner_ids = self
            .events
            .iter()
            .filter_map(|event| event.partner_id.clone())
            .chain(
                self.commissions
                    .iter()
                    .map(|record| record.partner_id.clone()),
            )
            .collect::<BTreeSet<_>>();
        if partner_map.keys().cloned().collect::<BTreeSet<_>>() != expected_partner_ids {
            return Err(OutcomeLedgerError::SettlementPartnerSupportClosureMismatch);
        }
        let partner_policy = partner_map.values().copied().collect::<Vec<_>>();
        let partner_policy_digest = canonical_json_digest(&partner_policy)?;
        if identity_chain.partner_count != projection_count(partner_map.len())?
            || identity_chain.partner_policy_digest != partner_policy_digest
        {
            return Err(OutcomeLedgerError::SettlementIdentityChainMismatch);
        }

        let mut order_views = BTreeMap::new();
        let mut scoped_refunds = Vec::new();
        let mut refunded_order_count = 0_u64;
        for (order_id, (order, _order_event)) in &source_orders {
            let mut refunds =
                self.refunds
                    .iter()
                    .filter_map(|refund| {
                        if refund.order_id != *order_id {
                            return None;
                        }
                        self.events
                            .iter()
                            .find(|event| event.id == refund.source_event_id)
                            .filter(|event| {
                                event.received_at <= observed_at
                                    && event.source_verification.as_ref().is_some_and(
                                        |verification| verification.verified_at <= observed_at,
                                    )
                            })
                            .map(|event| (refund, event))
                    })
                    .collect::<Vec<_>>();
            refunds.sort_by(|(left, left_event), (right, right_event)| {
                (left_event.received_at, left.occurred_at, left.id.as_str()).cmp(&(
                    right_event.received_at,
                    right.occurred_at,
                    right.id.as_str(),
                ))
            });
            let mut refunded = Money::zero(order.original_amount.currency.clone());
            for (refund, event) in &refunds {
                if event.occurred_at < order.occurred_at {
                    return Err(OutcomeLedgerError::SettlementWindowMismatch);
                }
                refunded = refunded
                    .checked_add(&refund.amount)
                    .map_err(|_| OutcomeLedgerError::SettlementMoneyMismatch)?;
                scoped_refunds.push((*refund, *event));
            }
            let eligible_net = order
                .original_amount
                .checked_sub(&refunded)
                .map_err(|_| OutcomeLedgerError::SettlementMoneyMismatch)?;
            if eligible_net.amount_minor < 0 {
                return Err(OutcomeLedgerError::SettlementMoneyMismatch);
            }
            if !refunds.is_empty() {
                refunded_order_count = refunded_order_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            }
            order_views.insert(
                order_id.clone(),
                OrderSettlementView {
                    order_id: order_id.clone(),
                    original_amount: order.original_amount.clone(),
                    refund_count: projection_count(refunds.len())?,
                    refunded_amount: refunded,
                    eligible_net_amount: eligible_net,
                    calculated_commission_record_count: 0,
                    network_commission_event_count: 0,
                },
            );
        }

        let mut latest_calculated = BTreeMap::<(OrderId, PartnerId), &CommissionRecord>::new();
        for record in self.commissions.iter().filter(|record| {
            source_order_ids.contains(&record.order_id) && record.calculated_at <= observed_at
        }) {
            let key = (record.order_id.clone(), record.partner_id.clone());
            if latest_calculated.get(&key).is_none_or(|current| {
                (record.calculated_at, record.id.as_str())
                    > (current.calculated_at, current.id.as_str())
            }) {
                latest_calculated.insert(key, record);
            }
        }

        let mut accumulators = BTreeMap::<(PartnerId, CurrencyCode), SettlementAccumulator>::new();
        let mut selected_calculated = Vec::new();
        for ((order_id, partner_id), record) in latest_calculated {
            let partner = partner_map
                .get(&partner_id)
                .copied()
                .ok_or(OutcomeLedgerError::SettlementPartnerSupportClosureMismatch)?;
            let basis = match partner.supply_class {
                PartnerSupplyClass::HartevoOptIn => SettlementCommissionBasis::HartevoCalculated,
                PartnerSupplyClass::TenantPrivate => {
                    SettlementCommissionBasis::TenantPrivateCalculated
                }
                PartnerSupplyClass::OfficialAuthorizedNetwork
                | PartnerSupplyClass::PublicCandidate => {
                    return Err(OutcomeLedgerError::SettlementCommissionAuthorityMismatch);
                }
            };
            let expected_refund_set = self.refund_set_digest_at(&order_id, observed_at)?;
            let expected_net = order_views
                .get(&order_id)
                .map(|view| &view.eligible_net_amount)
                .ok_or(OutcomeLedgerError::SettlementSourceOrdersUnavailable)?;
            let expected_commission_minor = (Decimal::from(expected_net.amount_minor)
                * record.rate)
                .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
                .to_i64()
                .ok_or(OutcomeLedgerError::SettlementMoneyMismatch)?;
            if record.refund_set_digest != expected_refund_set
                || record.eligible_net_amount != *expected_net
                || record.commission_amount
                    != Money::new(expected_commission_minor, expected_net.currency.clone())
            {
                return Err(OutcomeLedgerError::SettlementCommissionRecalculationRequired);
            }
            let order_view = order_views
                .get_mut(&order_id)
                .ok_or(OutcomeLedgerError::SettlementSourceOrdersUnavailable)?;
            order_view.calculated_commission_record_count = order_view
                .calculated_commission_record_count
                .checked_add(1)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            let currency = record.commission_amount.currency.clone();
            let accumulator = accumulators
                .entry((partner_id.clone(), currency.clone()))
                .or_insert_with(|| SettlementAccumulator {
                    partner_id: partner_id.clone(),
                    supply_class: partner.supply_class.clone(),
                    basis,
                    currency,
                    source_orders: BTreeSet::new(),
                    source_commission_count: 0,
                    commission_amount_minor: 0,
                    payout_count: 0,
                    payout_completed_minor: 0,
                    authoritative_providers: BTreeSet::from(["stripe-connect".into()]),
                });
            if accumulator.basis != basis {
                return Err(OutcomeLedgerError::SettlementCommissionAuthorityMismatch);
            }
            accumulator.source_orders.insert(order_id);
            accumulator.source_commission_count = accumulator
                .source_commission_count
                .checked_add(1)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            accumulator.commission_amount_minor = accumulator
                .commission_amount_minor
                .checked_add(record.commission_amount.amount_minor)
                .ok_or(OutcomeLedgerError::SettlementMoneyMismatch)?;
            selected_calculated.push(record);
        }

        let mut network_events = self
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    OutcomeEventKind::CommissionAccrued | OutcomeEventKind::CommissionReversed
                ) && event
                    .order_id
                    .as_ref()
                    .is_some_and(|order_id| source_order_ids.contains(order_id))
                    && event.received_at <= observed_at
                    && event
                        .source_verification
                        .as_ref()
                        .is_some_and(|verification| verification.verified_at <= observed_at)
            })
            .collect::<Vec<_>>();
        network_events.sort_by(|left, right| {
            (
                left.received_at,
                left.occurred_at,
                left.provider.as_str(),
                left.source_event_id.as_str(),
                left.id.as_str(),
            )
                .cmp(&(
                    right.received_at,
                    right.occurred_at,
                    right.provider.as_str(),
                    right.source_event_id.as_str(),
                    right.id.as_str(),
                ))
        });
        let mut network_commissions = BTreeMap::<CommissionId, NetworkCommissionAccumulator>::new();
        for event in &network_events {
            let order_id = event
                .order_id
                .as_ref()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
            let partner_id = event
                .partner_id
                .as_ref()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
            let commission_id = event
                .commission_id
                .as_ref()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
            let amount = event
                .amount
                .as_ref()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
            let partner = partner_map
                .get(partner_id)
                .copied()
                .ok_or(OutcomeLedgerError::SettlementPartnerSupportClosureMismatch)?;
            if partner.supply_class != PartnerSupplyClass::OfficialAuthorizedNetwork
                || !official_network_provider(&event.provider)
            {
                return Err(OutcomeLedgerError::SettlementCommissionAuthorityMismatch);
            }
            let order = source_orders
                .get(order_id)
                .map(|(order, _)| *order)
                .ok_or(OutcomeLedgerError::SettlementSourceOrdersUnavailable)?;
            if event.occurred_at < order.occurred_at {
                return Err(OutcomeLedgerError::SettlementWindowMismatch);
            }
            let commission = network_commissions
                .entry(commission_id.clone())
                .or_insert_with(|| NetworkCommissionAccumulator {
                    partner_id: partner_id.clone(),
                    currency: amount.currency.clone(),
                    provider: event.provider.clone(),
                    order_id: order_id.clone(),
                    accrued_minor: None,
                    reversed_minor: 0,
                    event_count: 0,
                });
            if commission.partner_id != *partner_id
                || commission.currency != amount.currency
                || commission.provider != event.provider
                || commission.order_id != *order_id
            {
                return Err(OutcomeLedgerError::SettlementCommissionAuthorityMismatch);
            }
            commission.event_count = commission
                .event_count
                .checked_add(1)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            if event.kind == OutcomeEventKind::CommissionAccrued {
                if commission
                    .accrued_minor
                    .replace(amount.amount_minor)
                    .is_some()
                {
                    return Err(OutcomeLedgerError::SettlementCommissionAuthorityMismatch);
                }
            } else {
                commission.reversed_minor = commission
                    .reversed_minor
                    .checked_add(amount.amount_minor)
                    .ok_or(OutcomeLedgerError::SettlementMoneyMismatch)?;
            }
        }
        for (_, commission) in network_commissions {
            let accrued_minor = commission
                .accrued_minor
                .ok_or(OutcomeLedgerError::SettlementCommissionAuthorityMismatch)?;
            let net_minor = accrued_minor
                .checked_sub(commission.reversed_minor)
                .ok_or(OutcomeLedgerError::SettlementMoneyMismatch)?;
            if net_minor < 0 {
                return Err(OutcomeLedgerError::SettlementMoneyMismatch);
            }
            let partner = partner_map
                .get(&commission.partner_id)
                .copied()
                .ok_or(OutcomeLedgerError::SettlementPartnerSupportClosureMismatch)?;
            let key = (commission.partner_id.clone(), commission.currency.clone());
            let accumulator = accumulators
                .entry(key)
                .or_insert_with(|| SettlementAccumulator {
                    partner_id: commission.partner_id.clone(),
                    supply_class: partner.supply_class.clone(),
                    basis: SettlementCommissionBasis::OfficialNetworkFacts,
                    currency: commission.currency.clone(),
                    source_orders: BTreeSet::new(),
                    source_commission_count: 0,
                    commission_amount_minor: 0,
                    payout_count: 0,
                    payout_completed_minor: 0,
                    authoritative_providers: BTreeSet::new(),
                });
            if accumulator.basis != SettlementCommissionBasis::OfficialNetworkFacts {
                return Err(OutcomeLedgerError::SettlementCommissionAuthorityMismatch);
            }
            accumulator
                .source_orders
                .insert(commission.order_id.clone());
            accumulator.source_commission_count = accumulator
                .source_commission_count
                .checked_add(1)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            accumulator
                .authoritative_providers
                .insert(commission.provider);
            accumulator.commission_amount_minor = accumulator
                .commission_amount_minor
                .checked_add(net_minor)
                .ok_or(OutcomeLedgerError::SettlementMoneyMismatch)?;
            let order_view = order_views
                .get_mut(&commission.order_id)
                .ok_or(OutcomeLedgerError::SettlementSourceOrdersUnavailable)?;
            order_view.network_commission_event_count = order_view
                .network_commission_event_count
                .checked_add(commission.event_count)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
        }

        let mut payout_events = self
            .events
            .iter()
            .filter(|event| {
                event.kind == OutcomeEventKind::PayoutCompleted
                    && event.mission_id == source_mission.id
                    && event.received_at <= observed_at
                    && event
                        .source_verification
                        .as_ref()
                        .is_some_and(|verification| verification.verified_at <= observed_at)
            })
            .collect::<Vec<_>>();
        payout_events.sort_by(|left, right| {
            (
                left.received_at,
                left.occurred_at,
                left.provider.as_str(),
                left.source_event_id.as_str(),
                left.id.as_str(),
            )
                .cmp(&(
                    right.received_at,
                    right.occurred_at,
                    right.provider.as_str(),
                    right.source_event_id.as_str(),
                    right.id.as_str(),
                ))
        });
        let mut payout_ids = BTreeSet::new();
        for event in &payout_events {
            let payout_id = event
                .payout_id
                .as_ref()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
            if !payout_ids.insert(payout_id.clone()) {
                return Err(OutcomeLedgerError::SettlementDuplicatePayout);
            }
            let partner_id = event
                .partner_id
                .as_ref()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
            let amount = event
                .amount
                .as_ref()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
            let accumulator = accumulators
                .get_mut(&(partner_id.clone(), amount.currency.clone()))
                .ok_or(OutcomeLedgerError::SettlementPayoutMismatch)?;
            let provider_allowed = match accumulator.basis {
                SettlementCommissionBasis::OfficialNetworkFacts => accumulator
                    .authoritative_providers
                    .contains(&event.provider),
                SettlementCommissionBasis::HartevoCalculated
                | SettlementCommissionBasis::TenantPrivateCalculated => {
                    matches!(event.provider.as_str(), "stripe" | "stripe-connect")
                }
            };
            if !provider_allowed {
                return Err(OutcomeLedgerError::SettlementPayoutMismatch);
            }
            accumulator.payout_count = accumulator
                .payout_count
                .checked_add(1)
                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            accumulator.payout_completed_minor = accumulator
                .payout_completed_minor
                .checked_add(amount.amount_minor)
                .ok_or(OutcomeLedgerError::SettlementMoneyMismatch)?;
            if accumulator.payout_completed_minor > accumulator.commission_amount_minor {
                return Err(OutcomeLedgerError::SettlementPayoutMismatch);
            }
        }

        let mut settlements = Vec::with_capacity(accumulators.len());
        let mut paid_group_count = 0_u64;
        let mut outstanding_group_count = 0_u64;
        let mut no_payment_due_group_count = 0_u64;
        let mut official_network_group_count = 0_u64;
        let mut hartevo_managed_group_count = 0_u64;
        let mut tenant_private_group_count = 0_u64;
        for (_, accumulator) in accumulators {
            let outstanding_minor = accumulator
                .commission_amount_minor
                .checked_sub(accumulator.payout_completed_minor)
                .ok_or(OutcomeLedgerError::SettlementMoneyMismatch)?;
            if outstanding_minor < 0 {
                return Err(OutcomeLedgerError::SettlementPayoutMismatch);
            }
            let status = if accumulator.commission_amount_minor == 0 {
                no_payment_due_group_count = no_payment_due_group_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                SettlementGroupStatus::NoPaymentDue
            } else if outstanding_minor == 0 {
                paid_group_count = paid_group_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                SettlementGroupStatus::Paid
            } else {
                outstanding_group_count = outstanding_group_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                SettlementGroupStatus::Outstanding
            };
            match accumulator.basis {
                SettlementCommissionBasis::OfficialNetworkFacts => {
                    official_network_group_count = official_network_group_count
                        .checked_add(1)
                        .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                }
                SettlementCommissionBasis::HartevoCalculated => {
                    hartevo_managed_group_count = hartevo_managed_group_count
                        .checked_add(1)
                        .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                }
                SettlementCommissionBasis::TenantPrivateCalculated => {
                    tenant_private_group_count = tenant_private_group_count
                        .checked_add(1)
                        .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                }
            }
            settlements.push(PartnerSettlementView {
                partner_id: accumulator.partner_id,
                supply_class: accumulator.supply_class,
                basis: accumulator.basis,
                currency: accumulator.currency.clone(),
                source_order_count: projection_count(accumulator.source_orders.len())?,
                source_commission_count: accumulator.source_commission_count,
                commission_amount: Money::new(
                    accumulator.commission_amount_minor,
                    accumulator.currency.clone(),
                ),
                payout_count: accumulator.payout_count,
                payout_completed_amount: Money::new(
                    accumulator.payout_completed_minor,
                    accumulator.currency.clone(),
                ),
                outstanding_amount: Money::new(outstanding_minor, accumulator.currency),
                status,
            });
        }
        settlements.sort_by(|left, right| {
            (left.partner_id.as_str(), left.currency.as_str())
                .cmp(&(right.partner_id.as_str(), right.currency.as_str()))
        });

        selected_calculated.sort_by(|left, right| {
            (
                left.order_id.as_str(),
                left.partner_id.as_str(),
                left.calculated_at,
                left.id.as_str(),
            )
                .cmp(&(
                    right.order_id.as_str(),
                    right.partner_id.as_str(),
                    right.calculated_at,
                    right.id.as_str(),
                ))
        });
        scoped_refunds.sort_by(|(left, left_event), (right, right_event)| {
            (
                left.order_id.as_str(),
                left_event.received_at,
                left.id.as_str(),
            )
                .cmp(&(
                    right.order_id.as_str(),
                    right_event.received_at,
                    right.id.as_str(),
                ))
        });
        Ok(OutcomeSettlementProjection {
            schema_version: OutcomeSettlementProjection::SCHEMA_VERSION,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            source_mission_id: source_mission.id.clone(),
            source_mission_revision: source_mission.revision,
            source_ledger_revision: self.revision,
            window_started_at,
            window_ended_at: observed_at,
            order_count: projection_count(order_views.len())?,
            refunded_order_count,
            refund_count: projection_count(scoped_refunds.len())?,
            calculated_commission_count: projection_count(selected_calculated.len())?,
            network_commission_event_count: projection_count(network_events.len())?,
            payout_count: projection_count(payout_events.len())?,
            settlement_group_count: projection_count(settlements.len())?,
            paid_group_count,
            outstanding_group_count,
            no_payment_due_group_count,
            official_network_group_count,
            hartevo_managed_group_count,
            tenant_private_group_count,
            normalization_digest: normalization.digest(),
            identity_chain_digest: identity_chain.digest(),
            order_refund_digest: canonical_json_digest(&order_views)?,
            commission_source_digest: canonical_json_digest(&serde_json::json!({
                "calculated": selected_calculated,
                "networkEvents": network_events,
            }))?,
            payout_source_digest: canonical_json_digest(&payout_events)?,
            partner_policy_digest,
            orders: order_views,
            settlements,
        })
    }

    /// Freezes the exact inputs shown to the following Human decision
    /// Checkpoint. It validates that KPI, attribution and settlement were all
    /// recomputed from the same ledger, parent Mission and cutoff, then adds a
    /// conservative verified-Effect cost view. It never selects an action,
    /// converts currencies, or claims causal ROI.
    #[allow(
        clippy::too_many_lines,
        reason = "the review Oracle keeps cross-projection equality, money buckets, effect terminality, budget arithmetic, and decision caveats explicit in one auditable boundary"
    )]
    pub fn verified_outcome_review_projection(
        &self,
        source_mission: &Mission,
        kpi: &MissionKpiProjection,
        attribution: &OutcomeAttributionProjection,
        settlement: &OutcomeSettlementProjection,
        observed_at: DateTime<Utc>,
    ) -> Result<OutcomeReviewProjection, OutcomeLedgerError> {
        let normalization = self.verified_normalization_projection()?;
        let source_matches = |tenant_id: &TenantId,
                              project_id: &ProjectId,
                              mission_id: &MissionId,
                              mission_revision: u64,
                              ledger_revision: u64| {
            tenant_id == &self.tenant_id
                && project_id == &self.project_id
                && mission_id == &source_mission.id
                && mission_revision == source_mission.revision
                && ledger_revision == self.revision
        };
        if source_mission.tenant_id != self.tenant_id
            || source_mission.project_id != self.project_id
            || source_mission.revision == 0
            || !source_matches(
                &kpi.tenant_id,
                &kpi.project_id,
                &kpi.source_mission_id,
                kpi.source_mission_revision,
                kpi.source_ledger_revision,
            )
            || !source_matches(
                &attribution.tenant_id,
                &attribution.project_id,
                &attribution.source_mission_id,
                attribution.source_mission_revision,
                attribution.source_ledger_revision,
            )
            || !source_matches(
                &settlement.tenant_id,
                &settlement.project_id,
                &settlement.source_mission_id,
                settlement.source_mission_revision,
                settlement.source_ledger_revision,
            )
        {
            return Err(OutcomeLedgerError::OutcomeReviewScopeMismatch);
        }
        source_mission
            .contract
            .validate(source_mission.contract.valid_from)
            .map_err(|_| OutcomeLedgerError::OutcomeReviewProjectionMismatch)?;
        let source_contract_digest = mission_kpi_contract_source_digest(source_mission)?;
        if observed_at < source_mission.contract.valid_from
            || kpi.schema_version != MissionKpiProjection::SCHEMA_VERSION
            || attribution.schema_version != OutcomeAttributionProjection::SCHEMA_VERSION
            || settlement.schema_version != OutcomeSettlementProjection::SCHEMA_VERSION
            || kpi.window_started_at != attribution.window_started_at
            || kpi.window_started_at != settlement.window_started_at
            || kpi.window_ended_at != attribution.window_ended_at
            || kpi.window_ended_at != observed_at.min(source_mission.contract.valid_until)
            || settlement.window_ended_at != observed_at
            || kpi.normalization_digest != normalization.digest()
            || attribution.normalization_digest != normalization.digest()
            || settlement.normalization_digest != normalization.digest()
            || kpi.identity_chain_digest != attribution.identity_chain_digest
            || kpi.identity_chain_digest != settlement.identity_chain_digest
            || kpi.source_contract_digest != source_contract_digest
            || kpi.measurement_count != projection_count(kpi.measurements.len())?
            || kpi.target_met_count
                != projection_count(
                    kpi.measurements
                        .values()
                        .filter(|measurement| measurement.target_met)
                        .count(),
                )?
            || attribution.order_count != projection_count(attribution.orders.len())?
            || settlement.order_count != projection_count(settlement.orders.len())?
            || attribution.orders.keys().collect::<BTreeSet<_>>()
                != settlement.orders.keys().collect::<BTreeSet<_>>()
            || attribution.causal_claim
            || attribution.orders.values().any(|order| order.causal_claim)
        {
            return Err(OutcomeLedgerError::OutcomeReviewProjectionMismatch);
        }
        let attributed_order_count = attribution
            .verified_identity_order_count
            .checked_add(attribution.last_non_direct_order_count)
            .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
        if attributed_order_count.checked_add(attribution.unattributed_order_count)
            != Some(attribution.order_count)
            || settlement
                .paid_group_count
                .checked_add(settlement.outstanding_group_count)
                .and_then(|count| count.checked_add(settlement.no_payment_due_group_count))
                != Some(settlement.settlement_group_count)
        {
            return Err(OutcomeLedgerError::OutcomeReviewProjectionMismatch);
        }

        let mut economics = BTreeMap::<CurrencyCode, OutcomeReviewMoneyView>::new();
        for order in settlement.orders.values() {
            let view = outcome_review_money_view(&mut economics, &order.original_amount.currency);
            add_review_money(&mut view.gross_revenue, &order.original_amount)?;
            add_review_money(&mut view.refunded_amount, &order.refunded_amount)?;
            add_review_money(&mut view.net_revenue, &order.eligible_net_amount)?;
        }
        for group in &settlement.settlements {
            let view = outcome_review_money_view(&mut economics, &group.currency);
            add_review_money(&mut view.commission_obligation, &group.commission_amount)?;
            add_review_money(&mut view.commission_paid, &group.payout_completed_amount)?;
            add_review_money(&mut view.commission_outstanding, &group.outstanding_amount)?;
        }

        let mut effects = source_mission.effects.iter().collect::<Vec<_>>();
        effects.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        if effects.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(OutcomeLedgerError::OutcomeReviewEffectStateMismatch);
        }
        let mut verified_effect_count = 0_u64;
        let mut pending_effect_count = 0_u64;
        let mut unresolved_cost_effect_count = 0_u64;
        let mut cross_currency_cost_effect_count = 0_u64;
        for effect in &effects {
            if effect.tenant_id != self.tenant_id
                || effect.project_id != self.project_id
                || effect.mission_id != source_mission.id
                || effect.amount.amount_minor < 0
            {
                return Err(OutcomeLedgerError::OutcomeReviewEffectStateMismatch);
            }
            let pending = matches!(
                effect.status,
                EffectStatus::Proposed
                    | EffectStatus::Approved
                    | EffectStatus::Executing
                    | EffectStatus::ReceiptRecorded
                    | EffectStatus::VerificationRequired
            );
            if pending {
                pending_effect_count = pending_effect_count
                    .checked_add(1)
                    .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
            }
            match effect.status {
                EffectStatus::Verified => {
                    validate_review_verified_effect(effect, observed_at)?;
                    verified_effect_count = verified_effect_count
                        .checked_add(1)
                        .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                    if effect.amount.is_positive() {
                        let view =
                            outcome_review_money_view(&mut economics, &effect.amount.currency);
                        add_review_money(&mut view.verified_effect_outflow, &effect.amount)?;
                        if effect.amount.currency != source_mission.contract.budget.currency {
                            cross_currency_cost_effect_count = cross_currency_cost_effect_count
                                .checked_add(1)
                                .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                        }
                    }
                }
                EffectStatus::Executing
                | EffectStatus::ReceiptRecorded
                | EffectStatus::VerificationRequired
                | EffectStatus::DeadLetter
                    if effect.amount.is_positive() =>
                {
                    let view = outcome_review_money_view(&mut economics, &effect.amount.currency);
                    add_review_money(&mut view.unresolved_effect_exposure, &effect.amount)?;
                    unresolved_cost_effect_count = unresolved_cost_effect_count
                        .checked_add(1)
                        .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                }
                EffectStatus::Failed
                    if effect.amount.is_positive()
                        && (effect.receipt.is_some() || effect.verification.is_some()) =>
                {
                    let view = outcome_review_money_view(&mut economics, &effect.amount.currency);
                    add_review_money(&mut view.unresolved_effect_exposure, &effect.amount)?;
                    unresolved_cost_effect_count = unresolved_cost_effect_count
                        .checked_add(1)
                        .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
                }
                EffectStatus::Proposed
                | EffectStatus::Approved
                | EffectStatus::Rejected
                | EffectStatus::Cancelled
                | EffectStatus::Expired
                | EffectStatus::Reconciled
                | EffectStatus::Failed
                | EffectStatus::Executing
                | EffectStatus::ReceiptRecorded
                | EffectStatus::VerificationRequired
                | EffectStatus::DeadLetter => {}
            }
            if matches!(
                effect.status,
                EffectStatus::Proposed
                    | EffectStatus::Approved
                    | EffectStatus::Rejected
                    | EffectStatus::Cancelled
                    | EffectStatus::Expired
                    | EffectStatus::Reconciled
            ) && (effect.receipt.is_some() || effect.verification.is_some())
            {
                return Err(OutcomeLedgerError::OutcomeReviewEffectStateMismatch);
            }
        }
        let effect_cost_source_digest = canonical_json_digest(&effects)?;

        let budget = source_mission.contract.budget.clone();
        let budget_view = outcome_review_money_view(&mut economics, &budget.currency);
        let budget_currency_verified_cost = budget_view.verified_effect_outflow.clone();
        let (remaining_minor, overrun_minor) =
            if budget_currency_verified_cost.amount_minor <= budget.amount_minor {
                (
                    budget
                        .amount_minor
                        .checked_sub(budget_currency_verified_cost.amount_minor)
                        .ok_or(OutcomeLedgerError::OutcomeReviewMoneyMismatch)?,
                    0,
                )
            } else {
                (
                    0,
                    budget_currency_verified_cost
                        .amount_minor
                        .checked_sub(budget.amount_minor)
                        .ok_or(OutcomeLedgerError::OutcomeReviewMoneyMismatch)?,
                )
            };
        let budget_remaining = Money::new(remaining_minor, budget.currency.clone());
        let budget_overrun = Money::new(overrun_minor, budget.currency.clone());

        let target_gap_count = kpi
            .measurement_count
            .checked_sub(kpi.target_met_count)
            .ok_or(OutcomeLedgerError::OutcomeReviewProjectionMismatch)?;
        let paid_or_no_payment_due_group_count = settlement
            .paid_group_count
            .checked_add(settlement.no_payment_due_group_count)
            .ok_or(OutcomeLedgerError::ProjectionCountOverflow)?;
        let all_kpis_met = target_gap_count == 0;
        let attribution_complete = attribution.unattributed_order_count == 0;
        let settlement_reconciled = settlement.outstanding_group_count == 0;
        let cost_complete =
            unresolved_cost_effect_count == 0 && cross_currency_cost_effect_count == 0;
        let budget_within_limit = budget_overrun.amount_minor == 0;
        let implicit_loop_forbidden = matches!(
            source_mission.contract.mode,
            OperatingMode::BuildOnce | OperatingMode::OneOffDecision
        );
        let scale_evidence_ready = matches!(
            source_mission.contract.mode,
            OperatingMode::Campaign
                | OperatingMode::ContinuousOperator
                | OperatingMode::ContinuousRelationship
        ) && all_kpis_met
            && attribution_complete
            && settlement_reconciled
            && pending_effect_count == 0
            && cost_complete
            && budget_within_limit;
        let mut caveats = BTreeSet::new();
        if !all_kpis_met {
            caveats.insert(OutcomeReviewCaveat::KpiTargetGap);
        }
        if !attribution_complete {
            caveats.insert(OutcomeReviewCaveat::UnattributedOrders);
        }
        if !settlement_reconciled {
            caveats.insert(OutcomeReviewCaveat::OutstandingSettlement);
        }
        if pending_effect_count != 0 {
            caveats.insert(OutcomeReviewCaveat::PendingEffect);
        }
        if unresolved_cost_effect_count != 0 {
            caveats.insert(OutcomeReviewCaveat::UnresolvedEffectCost);
        }
        if !budget_within_limit {
            caveats.insert(OutcomeReviewCaveat::BudgetExceeded);
        }
        if cross_currency_cost_effect_count != 0 {
            caveats.insert(OutcomeReviewCaveat::CrossCurrencyCostWithoutFx);
        }
        if implicit_loop_forbidden {
            caveats.insert(OutcomeReviewCaveat::ImplicitLoopForbidden);
        }

        Ok(OutcomeReviewProjection {
            schema_version: OutcomeReviewProjection::SCHEMA_VERSION,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            source_mission_id: source_mission.id.clone(),
            source_mission_revision: source_mission.revision,
            source_ledger_revision: self.revision,
            window_started_at: kpi.window_started_at,
            outcome_window_ended_at: kpi.window_ended_at,
            observed_at,
            measurement_count: kpi.measurement_count,
            target_met_count: kpi.target_met_count,
            target_gap_count,
            order_count: attribution.order_count,
            attributed_order_count,
            unattributed_order_count: attribution.unattributed_order_count,
            settlement_group_count: settlement.settlement_group_count,
            paid_or_no_payment_due_group_count,
            outstanding_settlement_group_count: settlement.outstanding_group_count,
            verified_effect_count,
            pending_effect_count,
            unresolved_cost_effect_count,
            cross_currency_cost_effect_count,
            budget,
            budget_currency_verified_cost,
            budget_remaining,
            budget_overrun,
            kpi_status: all_kpis_met.into(),
            attribution_status: attribution_complete.into(),
            settlement_status: settlement_reconciled.into(),
            cost_status: cost_complete.into(),
            budget_status: budget_within_limit.into(),
            scale_evidence_status: scale_evidence_ready.into(),
            loop_policy: if implicit_loop_forbidden {
                OutcomeReviewLoopPolicy::Forbidden
            } else {
                OutcomeReviewLoopPolicy::Eligible
            },
            causal_status: OutcomeReviewCausalStatus::NotClaimed,
            roi_status: OutcomeReviewRoiStatus::NotCalculated,
            caveats,
            economics,
            source_contract_digest,
            normalization_digest: normalization.digest(),
            identity_chain_digest: kpi.identity_chain_digest.clone(),
            kpi_projection_digest: kpi.digest()?,
            attribution_projection_digest: attribution.digest()?,
            settlement_projection_digest: settlement.digest()?,
            effect_cost_source_digest,
        })
    }

    fn source_mission_orders<'a>(
        &'a self,
        source_mission: &Mission,
        observed_at: DateTime<Utc>,
    ) -> Result<SourceMissionOrders<'a>, OutcomeLedgerError> {
        if source_mission.tenant_id != self.tenant_id
            || source_mission.project_id != self.project_id
            || source_mission.revision == 0
        {
            return Err(OutcomeLedgerError::AttributionMissionScopeMismatch);
        }
        source_mission
            .contract
            .validate(source_mission.contract.valid_from)
            .map_err(|_| OutcomeLedgerError::AttributionMissionScopeMismatch)?;
        if observed_at < source_mission.contract.valid_from {
            return Err(OutcomeLedgerError::AttributionWindowMismatch);
        }
        let window_started_at = source_mission.contract.valid_from;
        let window_ended_at = observed_at.min(source_mission.contract.valid_until);
        let mut source_orders = BTreeMap::new();
        for event in self.events.iter().filter(|event| {
            event.kind == OutcomeEventKind::OrderPlaced
                && event.mission_id == source_mission.id
                && event.occurred_at >= window_started_at
                && event.occurred_at <= window_ended_at
                && event.received_at <= observed_at
                && event
                    .source_verification
                    .as_ref()
                    .is_some_and(|verification| verification.verified_at <= observed_at)
        }) {
            let order_id = event
                .order_id
                .as_ref()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
            let order = self
                .orders
                .iter()
                .find(|order| order.id == *order_id && order.source_event_id == event.id)
                .ok_or(OutcomeLedgerError::EventProjectionMismatch)?;
            if source_orders
                .insert(order_id.clone(), (order, event))
                .is_some()
            {
                return Err(OutcomeLedgerError::DuplicateOrder);
            }
        }
        if source_orders.is_empty() {
            return Err(OutcomeLedgerError::AttributionSourceOrdersUnavailable);
        }
        Ok((window_started_at, window_ended_at, source_orders))
    }

    /// Proves that the snapshot is exactly one legal append/recalculation
    /// command after `previous`; list replacement, reorder, or revision jumps fail.
    pub fn follows(&self, previous: &Self) -> Result<bool, OutcomeLedgerError> {
        previous.validate()?;
        self.validate()?;
        if self.tenant_id != previous.tenant_id
            || self.project_id != previous.project_id
            || previous.revision.checked_add(1) != Some(self.revision)
        {
            return Ok(false);
        }

        if self.events.len() == previous.events.len() + 1
            && self.events.starts_with(&previous.events)
        {
            let mut candidate = previous.clone();
            if candidate
                .ingest(self.events.last().expect("length checked").clone())
                .is_ok()
                && candidate == *self
            {
                return Ok(true);
            }
        }
        if self.attributions.len() == previous.attributions.len() + 1
            && self.attributions.starts_with(&previous.attributions)
        {
            let mut candidate = previous.clone();
            if candidate
                .attribute(self.attributions.last().expect("length checked").clone())
                .is_ok()
                && candidate == *self
            {
                return Ok(true);
            }
        }
        if self.commissions.len() == previous.commissions.len() + 1 {
            let next = self.commissions.last().expect("length checked");
            let mut candidate = previous.clone();
            if candidate
                .calculate_commission(
                    next.id.clone(),
                    &next.order_id,
                    next.partner_id.clone(),
                    next.rate,
                    next.terms_digest.clone(),
                    next.calculated_at,
                )
                .is_ok()
                && candidate == *self
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn attribute(&mut self, record: AttributionRecord) -> Result<(), OutcomeLedgerError> {
        if self
            .attributions
            .iter()
            .any(|stored| stored.id == record.id)
        {
            return Err(OutcomeLedgerError::DuplicateAttribution);
        }
        let next_revision = self.next_revision()?;
        let order = self
            .orders
            .iter()
            .find(|order| order.id == record.order_id)
            .ok_or(OutcomeLedgerError::UnknownOrder)?;
        record.validate(&self.tenant_id, &self.project_id, order)?;
        self.attributions.push(record);
        self.revision = next_revision;
        Ok(())
    }

    pub fn calculate_commission(
        &mut self,
        id: CommissionId,
        order_id: &OrderId,
        partner_id: PartnerId,
        rate: Decimal,
        terms_digest: impl Into<String>,
        calculated_at: DateTime<Utc>,
    ) -> Result<CommissionRecord, OutcomeLedgerError> {
        let terms_digest = terms_digest.into();
        if id.as_str().trim().is_empty()
            || partner_id.as_str().trim().is_empty()
            || rate <= Decimal::ZERO
            || rate > Decimal::ONE
            || !is_sha256(&terms_digest)
            || self.commissions.iter().any(|record| record.id == id)
        {
            return Err(OutcomeLedgerError::InvalidCommission);
        }
        let next_revision = self.next_revision()?;
        let order = self
            .orders
            .iter()
            .find(|order| &order.id == order_id)
            .ok_or(OutcomeLedgerError::UnknownOrder)?;
        let latest_refund_observed_at = self
            .events
            .iter()
            .filter(|event| {
                event.kind == OutcomeEventKind::RefundIssued
                    && event.order_id.as_ref() == Some(order_id)
            })
            .map(|event| event.received_at)
            .max();
        if calculated_at < order.occurred_at
            || latest_refund_observed_at.is_some_and(|observed_at| calculated_at < observed_at)
        {
            return Err(OutcomeLedgerError::InvalidCommission);
        }
        let net = self.net_order_amount(order_id)?;
        let amount = (Decimal::from(net.amount_minor) * rate)
            .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
            .to_i64()
            .ok_or(OutcomeLedgerError::ArithmeticOverflow)?;
        let superseded_index = self.active_commission_index(order_id, &partner_id)?;
        let supersedes = superseded_index.map(|index| self.commissions[index].id.clone());
        let record = CommissionRecord {
            id,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            order_id: order_id.clone(),
            partner_id,
            rate,
            eligible_net_amount: net.clone(),
            commission_amount: Money::new(amount, net.currency),
            terms_digest,
            refund_set_digest: self.refund_set_digest_at(order_id, calculated_at)?,
            supersedes,
            status: CommissionStatus::Current,
            calculated_at,
        };
        if let Some(index) = superseded_index {
            self.commissions[index].status = CommissionStatus::Superseded;
        }
        self.commissions.push(record.clone());
        self.revision = next_revision;
        Ok(record)
    }

    pub fn commissions_requiring_recalculation(&self) -> Vec<&CommissionRecord> {
        self.commissions
            .iter()
            .filter(|record| record.status == CommissionStatus::RecalculationRequired)
            .collect()
    }

    pub fn net_order_amount(&self, order_id: &OrderId) -> Result<Money, OutcomeLedgerError> {
        let order = self
            .orders
            .iter()
            .find(|order| &order.id == order_id)
            .ok_or(OutcomeLedgerError::UnknownOrder)?;
        let mut net = order.original_amount.clone();
        for refund in self
            .refunds
            .iter()
            .filter(|refund| &refund.order_id == order_id)
        {
            net = net
                .checked_sub(&refund.amount)
                .map_err(|_| OutcomeLedgerError::CurrencyOrArithmeticMismatch)?;
        }
        Ok(net)
    }

    fn net_order_amount_at(
        &self,
        order_id: &OrderId,
        known_at: DateTime<Utc>,
    ) -> Result<Money, OutcomeLedgerError> {
        let order = self
            .orders
            .iter()
            .find(|order| &order.id == order_id)
            .ok_or(OutcomeLedgerError::UnknownOrder)?;
        let mut net = order.original_amount.clone();
        for refund in self.refunds.iter().filter(|refund| {
            &refund.order_id == order_id
                && self
                    .events
                    .iter()
                    .find(|event| event.id == refund.source_event_id)
                    .is_some_and(|event| event.received_at <= known_at)
        }) {
            net = net
                .checked_sub(&refund.amount)
                .map_err(|_| OutcomeLedgerError::CurrencyOrArithmeticMismatch)?;
        }
        Ok(net)
    }

    fn validate_commission_record(
        &self,
        record: &CommissionRecord,
    ) -> Result<(), OutcomeLedgerError> {
        if record.id.as_str().trim().is_empty()
            || record.tenant_id != self.tenant_id
            || record.project_id != self.project_id
            || record.partner_id.as_str().trim().is_empty()
            || record.rate <= Decimal::ZERO
            || record.rate > Decimal::ONE
            || !is_sha256(&record.terms_digest)
            || !is_sha256(&record.refund_set_digest)
            || record.eligible_net_amount.amount_minor < 0
            || record.commission_amount.amount_minor < 0
            || record.eligible_net_amount.currency != record.commission_amount.currency
        {
            return Err(OutcomeLedgerError::InvalidCommission);
        }
        let order = self
            .orders
            .iter()
            .find(|order| order.id == record.order_id)
            .ok_or(OutcomeLedgerError::UnknownOrder)?;
        if record.calculated_at < order.occurred_at {
            return Err(OutcomeLedgerError::InvalidCommission);
        }
        let expected_net = self.net_order_amount_at(&record.order_id, record.calculated_at)?;
        let expected_amount = (Decimal::from(expected_net.amount_minor) * record.rate)
            .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
            .to_i64()
            .ok_or(OutcomeLedgerError::ArithmeticOverflow)?;
        if record.eligible_net_amount != expected_net
            || record.commission_amount
                != Money::new(expected_amount, expected_net.currency.clone())
            || record.refund_set_digest
                != self.refund_set_digest_at(&record.order_id, record.calculated_at)?
        {
            return Err(OutcomeLedgerError::CommissionProjectionMismatch);
        }
        if let Some(previous_id) = &record.supersedes {
            let previous = self
                .commissions
                .iter()
                .find(|candidate| &candidate.id == previous_id)
                .ok_or(OutcomeLedgerError::CommissionProjectionMismatch)?;
            if previous.order_id != record.order_id
                || previous.partner_id != record.partner_id
                || previous.calculated_at > record.calculated_at
                || previous.status != CommissionStatus::Superseded
            {
                return Err(OutcomeLedgerError::CommissionProjectionMismatch);
            }
        }
        let later_refund_exists = self.events.iter().any(|event| {
            event.kind == OutcomeEventKind::RefundIssued
                && event.order_id.as_ref() == Some(&record.order_id)
                && event.received_at > record.calculated_at
        });
        match record.status {
            CommissionStatus::Current if later_refund_exists => {
                Err(OutcomeLedgerError::CommissionProjectionMismatch)
            }
            CommissionStatus::RecalculationRequired if !later_refund_exists => {
                Err(OutcomeLedgerError::CommissionProjectionMismatch)
            }
            _ => Ok(()),
        }
    }

    fn ingest_order(&mut self, event: &OutcomeEvent) -> Result<(), OutcomeLedgerError> {
        let order_id = event
            .order_id
            .as_ref()
            .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
        if self.orders.iter().any(|order| order.id == *order_id) {
            return Err(OutcomeLedgerError::DuplicateOrder);
        }
        self.orders.push(OutcomeOrder {
            id: order_id.clone(),
            source_event_id: event.id.clone(),
            original_amount: event
                .amount
                .clone()
                .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?,
            occurred_at: event.occurred_at,
        });
        Ok(())
    }

    fn ingest_refund(&mut self, event: &OutcomeEvent) -> Result<(), OutcomeLedgerError> {
        let order_id = event
            .order_id
            .as_ref()
            .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
        let refund_id = event
            .refund_id
            .as_ref()
            .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
        if self.refunds.iter().any(|refund| refund.id == *refund_id) {
            return Err(OutcomeLedgerError::DuplicateRefund);
        }
        let amount = event
            .amount
            .clone()
            .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
        let current_net = self.net_order_amount(order_id)?;
        let next_net = current_net
            .checked_sub(&amount)
            .map_err(|_| OutcomeLedgerError::CurrencyOrArithmeticMismatch)?;
        if next_net.amount_minor < 0 {
            return Err(OutcomeLedgerError::RefundExceedsOrder);
        }
        let order = self
            .orders
            .iter()
            .find(|order| order.id == *order_id)
            .ok_or(OutcomeLedgerError::UnknownOrder)?;
        if event.occurred_at < order.occurred_at {
            return Err(OutcomeLedgerError::RefundPredatesOrder);
        }
        self.refunds.push(OutcomeRefund {
            id: refund_id.clone(),
            order_id: order_id.clone(),
            source_event_id: event.id.clone(),
            amount,
            occurred_at: event.occurred_at,
        });
        for commission in self.commissions.iter_mut().filter(|commission| {
            commission.order_id == *order_id && commission.status == CommissionStatus::Current
        }) {
            commission.status = CommissionStatus::RecalculationRequired;
        }
        Ok(())
    }

    fn active_commission_index(
        &self,
        order_id: &OrderId,
        partner_id: &PartnerId,
    ) -> Result<Option<usize>, OutcomeLedgerError> {
        let active = self
            .commissions
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                &record.order_id == order_id
                    && &record.partner_id == partner_id
                    && record.status != CommissionStatus::Superseded
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        match active.as_slice() {
            [] => Ok(None),
            [index] => Ok(Some(*index)),
            _ => Err(OutcomeLedgerError::CommissionInvariantViolation),
        }
    }

    fn refund_set_digest_at(
        &self,
        order_id: &OrderId,
        known_at: DateTime<Utc>,
    ) -> Result<String, OutcomeLedgerError> {
        let refunds = self
            .refunds
            .iter()
            .filter(|refund| {
                &refund.order_id == order_id
                    && self
                        .events
                        .iter()
                        .find(|event| event.id == refund.source_event_id)
                        .is_some_and(|event| event.received_at <= known_at)
            })
            .map(|refund| {
                (
                    refund.id.as_str(),
                    refund.source_event_id.as_str(),
                    refund.amount.amount_minor,
                    refund.amount.currency.as_str(),
                    refund.occurred_at,
                )
            })
            .collect::<Vec<_>>();
        let canonical = serde_json::to_vec(&refunds)
            .map_err(|_| OutcomeLedgerError::CommissionInvariantViolation)?;
        Ok(format!("{:x}", Sha256::digest(canonical)))
    }

    fn next_revision(&self) -> Result<u64, OutcomeLedgerError> {
        self.revision
            .checked_add(1)
            .ok_or(OutcomeLedgerError::RevisionOverflow)
    }
}

#[derive(Clone)]
struct EligibleAttribution {
    attribution_id: AttributionId,
    model: AttributionModel,
    traffic_class: AttributionTrafficClass,
    provider_identity_digest: Option<String>,
    verified_link_or_coupon_digest: Option<String>,
    occurred_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
    touchpoint_digest: String,
}

fn unique_attribution_extreme<'a>(
    candidates: &[&'a EligibleAttribution],
    earliest: bool,
) -> Result<Option<&'a EligibleAttribution>, OutcomeLedgerError> {
    let Some(extreme_time) = candidates
        .iter()
        .map(|candidate| candidate.occurred_at)
        .reduce(|left, right| {
            if earliest {
                left.min(right)
            } else {
                left.max(right)
            }
        })
    else {
        return Ok(None);
    };
    let tied = candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.occurred_at == extreme_time)
        .collect::<Vec<_>>();
    if tied
        .iter()
        .map(|candidate| candidate.touchpoint_digest.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        > 1
    {
        return Err(OutcomeLedgerError::DisputedAttribution);
    }
    Ok(tied.into_iter().min_by(|left, right| {
        (left.recorded_at, left.attribution_id.as_str())
            .cmp(&(right.recorded_at, right.attribution_id.as_str()))
    }))
}

fn attribution_touchpoint_digest(record: &AttributionRecord) -> Result<String, OutcomeLedgerError> {
    canonical_json_digest(&serde_json::json!({
        "schemaVersion": "hartevo-attribution-touchpoint/v1",
        "orderId": record.order_id,
        "touchpoint": record.touchpoint,
    }))
}

fn canonical_json_digest(value: &impl Serialize) -> Result<String, OutcomeLedgerError> {
    let canonical =
        serde_json::to_vec(value).map_err(|_| OutcomeLedgerError::ProjectionSerialization)?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn mission_kpi_contract_source_digest(
    source_mission: &Mission,
) -> Result<String, OutcomeLedgerError> {
    canonical_json_digest(&serde_json::json!({
        "schemaVersion": "hartevo-mission-kpi-contract-source/v1",
        "missionId": source_mission.id,
        "missionRevision": source_mission.revision,
        "contract": source_mission.contract,
    }))
}

/// Canonical provider/account/receipt identity used by a VerifiedIdentity
/// attribution record. Raw external identifiers enter the hash but are never
/// returned or persisted in Checkpoint evidence.
pub fn attribution_effect_provider_identity_digest(
    effect: &Effect,
) -> Result<String, OutcomeLedgerError> {
    let receipt = effect
        .receipt
        .as_ref()
        .ok_or(OutcomeLedgerError::AttributionEffectSupportInvalid)?;
    canonical_json_digest(&serde_json::json!({
        "schemaVersion": "hartevo-attribution-effect-provider-identity/v1",
        "tenantId": effect.tenant_id,
        "projectId": effect.project_id,
        "missionId": effect.mission_id,
        "effectId": effect.id,
        "provider": effect.provider,
        "connectionId": effect.connection_id,
        "accountId": effect.account_id,
        "receiptId": receipt.id,
        "externalId": receipt.external_id,
        "requestDigest": receipt.request_digest,
        "responseDigest": receipt.response_digest,
    }))
}

fn verified_attribution_effect_support(
    record: &AttributionRecord,
    touchpoint: &Touchpoint,
    support_mission: &Mission,
    effect: &Effect,
    order: &OutcomeOrder,
    observed_at: DateTime<Utc>,
) -> Result<serde_json::Value, OutcomeLedgerError> {
    let approval = effect
        .approval
        .as_ref()
        .ok_or(OutcomeLedgerError::AttributionEffectSupportInvalid)?;
    let receipt = effect
        .receipt
        .as_ref()
        .ok_or(OutcomeLedgerError::AttributionEffectSupportInvalid)?;
    let verification = effect
        .verification
        .as_ref()
        .ok_or(OutcomeLedgerError::AttributionEffectSupportInvalid)?;
    let source_verification = touchpoint
        .source_verification
        .as_ref()
        .ok_or(OutcomeLedgerError::UnverifiedAttributionSource)?;
    if effect.tenant_id != support_mission.tenant_id
        || effect.project_id != support_mission.project_id
        || effect.mission_id != support_mission.id
        || touchpoint.effect_id.as_ref() != Some(&effect.id)
        || effect.status != EffectStatus::Verified
        || approval.decision != ApprovalDecision::Approved
        || approval.scope_digest != effect.approval_digest()
        || receipt.provider != effect.provider
        || receipt.request_digest != effect.approval_digest()
        || receipt.accepted_at < approval.decided_at
        || receipt.accepted_at >= effect.expires_at
        || verification.status != VerificationStatus::Confirmed
        || !verification.independent
        || verification.receipt_id != receipt.id
        || verification.observed_at < receipt.accepted_at
        || verification.observed_at > touchpoint.occurred_at
        || verification.observed_at > observed_at
        || touchpoint.occurred_at > order.occurred_at
        || record.causal_claim
        || !matches!(
            source_verification.method,
            OutcomeVerificationMethod::SignedWebhook
                | OutcomeVerificationMethod::IndependentReadback
        )
        || !source_verification.independent
    {
        return Err(OutcomeLedgerError::AttributionEffectSupportInvalid);
    }
    let provider_identity_digest = attribution_effect_provider_identity_digest(effect)?;
    if touchpoint
        .provider_identity_digest
        .as_ref()
        .is_some_and(|digest| digest != &provider_identity_digest)
        || touchpoint
            .verified_link_or_coupon_digest
            .as_ref()
            .is_some_and(|digest| digest != &effect.payload_digest)
        || touchpoint.provider_identity_digest.is_none()
            && touchpoint.verified_link_or_coupon_digest.is_none()
    {
        return Err(OutcomeLedgerError::AttributionEffectSupportInvalid);
    }
    Ok(serde_json::json!({
        "schemaVersion": "hartevo-attribution-effect-support/v1",
        "missionId": support_mission.id,
        "missionRevision": support_mission.revision,
        "effectId": effect.id,
        "effectApprovalDigest": effect.approval_digest(),
        "providerIdentityDigest": provider_identity_digest,
        "payloadDigest": effect.payload_digest,
        "receiptId": receipt.id,
        "receiptResponseDigest": receipt.response_digest,
        "verificationId": verification.id,
        "verificationEvidenceDigest": verification.evidence_digest,
        "touchpointEvidenceDigest": touchpoint.evidence_digest,
    }))
}

#[derive(Clone, Copy)]
enum MissionKpiMetric {
    EventCount(OutcomeEventKind),
    GrossRevenue,
    RefundTotal,
    NetRevenue,
    CommissionAccrued,
    CommissionReversed,
    PayoutCompleted,
}

fn mission_kpi_metric(metric_id: &str) -> Result<MissionKpiMetric, OutcomeLedgerError> {
    match metric_id {
        "lead_qualified_count" => Ok(MissionKpiMetric::EventCount(
            OutcomeEventKind::LeadQualified,
        )),
        "meeting_booked_count" => Ok(MissionKpiMetric::EventCount(
            OutcomeEventKind::MeetingBooked,
        )),
        "opportunity_stage_change_count" => Ok(MissionKpiMetric::EventCount(
            OutcomeEventKind::OpportunityStageChanged,
        )),
        "order_count" => Ok(MissionKpiMetric::EventCount(OutcomeEventKind::OrderPlaced)),
        "refund_count" => Ok(MissionKpiMetric::EventCount(OutcomeEventKind::RefundIssued)),
        "commission_accrued_count" => Ok(MissionKpiMetric::EventCount(
            OutcomeEventKind::CommissionAccrued,
        )),
        "commission_reversed_count" => Ok(MissionKpiMetric::EventCount(
            OutcomeEventKind::CommissionReversed,
        )),
        "payout_completed_count" => Ok(MissionKpiMetric::EventCount(
            OutcomeEventKind::PayoutCompleted,
        )),
        "gross_revenue_minor" => Ok(MissionKpiMetric::GrossRevenue),
        "refund_total_minor" => Ok(MissionKpiMetric::RefundTotal),
        "net_revenue_minor" => Ok(MissionKpiMetric::NetRevenue),
        "commission_accrued_minor" => Ok(MissionKpiMetric::CommissionAccrued),
        "commission_reversed_minor" => Ok(MissionKpiMetric::CommissionReversed),
        "payout_completed_minor" => Ok(MissionKpiMetric::PayoutCompleted),
        _ => Err(OutcomeLedgerError::UnsupportedKpiMetric),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive typed metric match keeps every supported count and minor-unit money semantic fail-closed in one reviewable function"
)]
fn mission_kpi_measurement(
    metric_id: &str,
    contract: &KpiContract,
    events: &[&OutcomeEvent],
) -> Result<MissionKpiMeasurement, OutcomeLedgerError> {
    let metric = mission_kpi_metric(metric_id)?;
    match metric {
        MissionKpiMetric::EventCount(kind) => {
            if contract.unit != "count"
                || contract.target < Decimal::ZERO
                || !contract.target.fract().is_zero()
                || contract.target.to_u64().is_none()
                || contract.baseline.is_some_and(|baseline| {
                    baseline < Decimal::ZERO
                        || !baseline.fract().is_zero()
                        || baseline.to_u64().is_none()
                })
            {
                return Err(OutcomeLedgerError::InvalidKpiContract);
            }
            let source_event_count =
                projection_count(events.iter().filter(|event| event.kind == kind).count())?;
            let observed = Decimal::from(source_event_count);
            Ok(MissionKpiMeasurement {
                metric_id: metric_id.into(),
                source_event_count,
                observed: MissionKpiObservedValue::Count {
                    value: source_event_count,
                },
                baseline: contract.baseline,
                target: contract.target,
                unit: contract.unit.clone(),
                direction: contract.direction,
                target_met: kpi_target_met(observed, contract),
            })
        }
        MissionKpiMetric::GrossRevenue
        | MissionKpiMetric::RefundTotal
        | MissionKpiMetric::NetRevenue
        | MissionKpiMetric::CommissionAccrued
        | MissionKpiMetric::CommissionReversed
        | MissionKpiMetric::PayoutCompleted => {
            let currency = contract
                .unit
                .strip_prefix("minor_units:")
                .ok_or(OutcomeLedgerError::InvalidKpiContract)
                .and_then(|value| {
                    CurrencyCode::parse(value).map_err(|_| OutcomeLedgerError::InvalidKpiContract)
                })?;
            if !contract.target.fract().is_zero()
                || contract.target.to_i64().is_none()
                || contract.baseline.is_some_and(|baseline| {
                    !baseline.fract().is_zero() || baseline.to_i64().is_none()
                })
            {
                return Err(OutcomeLedgerError::InvalidKpiContract);
            }
            let relevant = events
                .iter()
                .copied()
                .filter(|event| match metric {
                    MissionKpiMetric::GrossRevenue => event.kind == OutcomeEventKind::OrderPlaced,
                    MissionKpiMetric::RefundTotal => event.kind == OutcomeEventKind::RefundIssued,
                    MissionKpiMetric::NetRevenue => matches!(
                        event.kind,
                        OutcomeEventKind::OrderPlaced | OutcomeEventKind::RefundIssued
                    ),
                    MissionKpiMetric::CommissionAccrued => {
                        event.kind == OutcomeEventKind::CommissionAccrued
                    }
                    MissionKpiMetric::CommissionReversed => {
                        event.kind == OutcomeEventKind::CommissionReversed
                    }
                    MissionKpiMetric::PayoutCompleted => {
                        event.kind == OutcomeEventKind::PayoutCompleted
                    }
                    MissionKpiMetric::EventCount(_) => false,
                })
                .collect::<Vec<_>>();
            let mut amount = Money::zero(currency.clone());
            for event in &relevant {
                let event_amount = event
                    .amount
                    .as_ref()
                    .ok_or(OutcomeLedgerError::EventKindShapeMismatch)?;
                if event_amount.currency != currency {
                    return Err(OutcomeLedgerError::KpiCurrencyMismatch);
                }
                amount = if matches!(metric, MissionKpiMetric::NetRevenue)
                    && event.kind == OutcomeEventKind::RefundIssued
                {
                    amount.checked_sub(event_amount)
                } else {
                    amount.checked_add(event_amount)
                }
                .map_err(|_| OutcomeLedgerError::KpiArithmetic)?;
            }
            let observed = Decimal::from(amount.amount_minor);
            Ok(MissionKpiMeasurement {
                metric_id: metric_id.into(),
                source_event_count: projection_count(relevant.len())?,
                observed: MissionKpiObservedValue::Money { value: amount },
                baseline: contract.baseline,
                target: contract.target,
                unit: contract.unit.clone(),
                direction: contract.direction,
                target_met: kpi_target_met(observed, contract),
            })
        }
    }
}

fn kpi_target_met(observed: Decimal, contract: &KpiContract) -> bool {
    match contract.direction {
        KpiDirection::AtLeast => observed >= contract.target,
        KpiDirection::AtMost => observed <= contract.target,
    }
}

fn outcome_review_money_view<'a>(
    economics: &'a mut BTreeMap<CurrencyCode, OutcomeReviewMoneyView>,
    currency: &CurrencyCode,
) -> &'a mut OutcomeReviewMoneyView {
    economics
        .entry(currency.clone())
        .or_insert_with(|| OutcomeReviewMoneyView {
            currency: currency.clone(),
            gross_revenue: Money::zero(currency.clone()),
            refunded_amount: Money::zero(currency.clone()),
            net_revenue: Money::zero(currency.clone()),
            commission_obligation: Money::zero(currency.clone()),
            commission_paid: Money::zero(currency.clone()),
            commission_outstanding: Money::zero(currency.clone()),
            verified_effect_outflow: Money::zero(currency.clone()),
            unresolved_effect_exposure: Money::zero(currency.clone()),
        })
}

fn add_review_money(target: &mut Money, amount: &Money) -> Result<(), OutcomeLedgerError> {
    *target = target
        .checked_add(amount)
        .map_err(|_| OutcomeLedgerError::OutcomeReviewMoneyMismatch)?;
    Ok(())
}

fn validate_review_verified_effect(
    effect: &Effect,
    observed_at: DateTime<Utc>,
) -> Result<(), OutcomeLedgerError> {
    let approval = effect
        .approval
        .as_ref()
        .ok_or(OutcomeLedgerError::OutcomeReviewEffectStateMismatch)?;
    let receipt = effect
        .receipt
        .as_ref()
        .ok_or(OutcomeLedgerError::OutcomeReviewEffectStateMismatch)?;
    let verification = effect
        .verification
        .as_ref()
        .ok_or(OutcomeLedgerError::OutcomeReviewEffectStateMismatch)?;
    if effect.status != EffectStatus::Verified
        || approval.decision != ApprovalDecision::Approved
        || approval.scope_digest != effect.approval_digest()
        || !is_sha256(&approval.permission_digest)
        || receipt.provider != effect.provider
        || receipt.request_digest != effect.approval_digest()
        || receipt.external_id.trim().is_empty()
        || !is_sha256(&receipt.response_digest)
        || receipt.accepted_at < approval.decided_at
        || receipt.accepted_at >= approval.valid_until
        || receipt.accepted_at >= effect.expires_at
        || verification.status != VerificationStatus::Confirmed
        || !verification.independent
        || verification.verifier.trim().is_empty()
        || verification.receipt_id != receipt.id
        || verification.observed_at < receipt.accepted_at
        || verification.observed_at > observed_at
        || !is_sha256(&verification.evidence_digest)
    {
        return Err(OutcomeLedgerError::OutcomeReviewEffectStateMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OutcomeLedgerError {
    #[error("outcome ledger tenant or project scope is invalid")]
    InvalidLedgerScope,
    #[error("outcome event envelope, time, provider identity, or evidence is invalid")]
    InvalidEventEnvelope,
    #[error("outcome source lacks a signed webhook, independent readback, or explicit provenance")]
    UnverifiedOutcomeSource,
    #[error("outcome event fields do not match its event kind")]
    EventKindShapeMismatch,
    #[error("outcome event tenant or project does not match the ledger")]
    ScopeMismatch,
    #[error("outcome event ID or provider source event is duplicated")]
    DuplicateEvent,
    #[error("order is duplicated")]
    DuplicateOrder,
    #[error("refund is duplicated")]
    DuplicateRefund,
    #[error("referenced order does not exist")]
    UnknownOrder,
    #[error("refund exceeds the immutable original order amount")]
    RefundExceedsOrder,
    #[error("refund occurred before the immutable original order")]
    RefundPredatesOrder,
    #[error("currency or checked money arithmetic does not match")]
    CurrencyOrArithmeticMismatch,
    #[error("attribution scope, window, touchpoint, confidence, or evidence is invalid")]
    InvalidAttribution,
    #[error("attribution touchpoint source verification is missing or invalid")]
    UnverifiedAttributionSource,
    #[error("attribution record is duplicated")]
    DuplicateAttribution,
    #[error("commission rate, terms, identity, or duplicate ID is invalid")]
    InvalidCommission,
    #[error("commission projection contains more than one active revision")]
    CommissionInvariantViolation,
    #[error("commission projection does not reproduce its money or refund-set calculation")]
    CommissionProjectionMismatch,
    #[error("outcome events do not reproduce the stored immutable order/refund projections")]
    EventProjectionMismatch,
    #[error("outcome projection revision mismatch: expected {expected}, found {actual}")]
    ProjectionRevisionMismatch { expected: u64, actual: u64 },
    #[error("outcome normalization projection count overflow")]
    ProjectionCountOverflow,
    #[error("outcome identity support is not the exact referenced closure")]
    IdentityChainSupportClosureMismatch,
    #[error("an outcome identity link is not currently confirmed")]
    IdentityLinkUnconfirmed,
    #[error("an outcome provider/account does not match its connection or identity link")]
    IdentityProviderAccountMismatch,
    #[error("an outcome identity subject or relationship is inconsistent")]
    IdentityRelationshipMismatch,
    #[error("an outcome event has no direct or inherited identity path")]
    IdentityChainCoverageMismatch,
    #[error("the KPI source Mission does not match the Outcome Ledger scope")]
    KpiMissionScopeMismatch,
    #[error("the KPI projection does not bind the current complete identity chain")]
    KpiIdentityChainMismatch,
    #[error("the KPI contract, window, unit, baseline, or target is invalid")]
    InvalidKpiContract,
    #[error("the parent Mission has no verified Outcome events in the current KPI window")]
    KpiSourceEventsUnavailable,
    #[error("the KPI metric is not supported by the deterministic Outcome Oracle")]
    UnsupportedKpiMetric,
    #[error("the KPI source contains a currency outside its exact contract unit")]
    KpiCurrencyMismatch,
    #[error("KPI minor-unit arithmetic overflowed")]
    KpiArithmetic,
    #[error("the attribution source Mission does not match the Outcome Ledger scope")]
    AttributionMissionScopeMismatch,
    #[error(
        "the parent Mission has no verified orders addressable by the current attribution contract"
    )]
    AttributionSourceOrdersUnavailable,
    #[error("the attribution projection does not bind the current complete identity chain")]
    AttributionIdentityChainMismatch,
    #[error("the attribution Mission support is not the exact referenced closure")]
    AttributionSupportClosureMismatch,
    #[error("attribution touchpoint or order falls outside the frozen contract/cutoff window")]
    AttributionWindowMismatch,
    #[error("a VerifiedIdentity attribution is not bound to one independently verified Effect")]
    AttributionEffectSupportInvalid,
    #[error("the same attribution touchpoint was supplied more than once")]
    DuplicateAttributionTouchpoint,
    #[error("multiple equally authoritative attribution candidates disagree")]
    DisputedAttribution,
    #[error("the settlement source Mission does not match the Outcome Ledger scope")]
    SettlementMissionScopeMismatch,
    #[error("the parent Mission has no verified orders addressable by settlement")]
    SettlementSourceOrdersUnavailable,
    #[error("the settlement projection does not bind the current complete identity chain")]
    SettlementIdentityChainMismatch,
    #[error("the settlement cutoff or an order/refund time relationship is inconsistent")]
    SettlementWindowMismatch,
    #[error("the settlement Partner support is not the exact referenced closure")]
    SettlementPartnerSupportClosureMismatch,
    #[error("a Partner supply class or permission record is invalid for settlement")]
    SettlementPartnerPolicyMismatch,
    #[error("commission authority mixes network facts with Hartevo-calculated records")]
    SettlementCommissionAuthorityMismatch,
    #[error("a refund changed the eligible amount and the commission needs recalculation")]
    SettlementCommissionRecalculationRequired,
    #[error("a verified payout does not match its partner, currency, provider, or obligation")]
    SettlementPayoutMismatch,
    #[error("the same provider payout identity appears more than once")]
    SettlementDuplicatePayout,
    #[error("settlement money uses inconsistent currency or overflows minor units")]
    SettlementMoneyMismatch,
    #[error("the outcome review does not match its parent Mission or Outcome Ledger scope")]
    OutcomeReviewScopeMismatch,
    #[error(
        "the outcome review inputs are not the exact KPI, attribution, and settlement projections for one cutoff"
    )]
    OutcomeReviewProjectionMismatch,
    #[error("an Effect cost source has an impossible or unverified lifecycle state")]
    OutcomeReviewEffectStateMismatch,
    #[error("outcome review money uses inconsistent currency or overflows minor units")]
    OutcomeReviewMoneyMismatch,
    #[error("the Human outcome decision is detached from its exact VM-11 review or CAS")]
    OutcomeReviewDecisionSourceMismatch,
    #[error("the selected outcome action is forbidden by the frozen Mission mode or contract")]
    OutcomeReviewDecisionActionForbidden,
    #[error("Scale is forbidden until every deterministic scale-evidence gate is satisfied")]
    OutcomeReviewDecisionScaleBlocked,
    #[error(
        "the next-contract resolution is detached from its exact VM-11 decision, parent contract, or Checkpoint"
    )]
    OutcomeReviewNextContractSourceMismatch,
    #[error("the current frozen parent contract is expired or otherwise unavailable")]
    OutcomeReviewCurrentContractUnavailable,
    #[error("Scale requires a separately approved exact revised Operating Contract")]
    OutcomeReviewRevisedContractAuthorizationRequired,
    #[error("Test requires a separately approved exact experiment Operating Contract")]
    OutcomeReviewExperimentContractAuthorizationRequired,
    #[error("the next-contract resolution time precedes its frozen decision or source")]
    OutcomeReviewResolutionTimeInvalid,
    #[error("an outcome Oracle projection could not be canonically serialized")]
    ProjectionSerialization,
    #[error("decimal commission arithmetic overflowed minor units")]
    ArithmeticOverflow,
    #[error("outcome ledger revision overflow")]
    RevisionOverflow,
}

fn validate_touchpoint(
    touchpoint: &Touchpoint,
    order: &OutcomeOrder,
    model: AttributionModel,
    window_started_at: DateTime<Utc>,
    window_ended_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
    require_current_source_verification: bool,
) -> Result<(), OutcomeLedgerError> {
    let received_at = touchpoint.received_at;
    let source_verification = touchpoint.source_verification.as_ref();
    if touchpoint.mission_id.as_str().trim().is_empty()
        || touchpoint.source.trim().is_empty()
        || touchpoint.occurred_at < window_started_at
        || touchpoint.occurred_at > window_ended_at
        || touchpoint.occurred_at > order.occurred_at
        || !is_sha256(&touchpoint.evidence_digest)
        || touchpoint
            .provider_identity_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
        || touchpoint
            .verified_link_or_coupon_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
        || received_at.is_some_and(|received_at| {
            received_at < touchpoint.occurred_at || received_at > recorded_at
        })
    {
        return Err(OutcomeLedgerError::InvalidAttribution);
    }
    if require_current_source_verification
        && (touchpoint.traffic_class.is_none()
            || received_at.is_none()
            || source_verification.is_none())
    {
        return Err(OutcomeLedgerError::UnverifiedAttributionSource);
    }
    if let Some(verification) = source_verification {
        let received_at = received_at.ok_or(OutcomeLedgerError::UnverifiedAttributionSource)?;
        verification
            .validate(received_at)
            .map_err(|_| OutcomeLedgerError::UnverifiedAttributionSource)?;
        if verification.verified_at > recorded_at {
            return Err(OutcomeLedgerError::UnverifiedAttributionSource);
        }
        if require_current_source_verification
            && verification.evidence_digest != touchpoint.evidence_digest
        {
            return Err(OutcomeLedgerError::UnverifiedAttributionSource);
        }
    }
    if model == AttributionModel::VerifiedIdentity
        && (touchpoint.provider_identity_digest.is_none()
            && touchpoint.verified_link_or_coupon_digest.is_none()
            || require_current_source_verification && touchpoint.effect_id.is_none())
    {
        return Err(OutcomeLedgerError::InvalidAttribution);
    }
    if model == AttributionModel::LastNonDirect
        && (touchpoint.traffic_class == Some(AttributionTrafficClass::Direct)
            || require_current_source_verification
                && touchpoint.traffic_class != Some(AttributionTrafficClass::NonDirect))
    {
        return Err(OutcomeLedgerError::InvalidAttribution);
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn official_network_provider(provider: &str) -> bool {
    matches!(provider, "awin" | "impact" | "impact.com" | "cj")
}

fn projection_count(count: usize) -> Result<u64, OutcomeLedgerError> {
    u64::try_from(count).map_err(|_| OutcomeLedgerError::ProjectionCountOverflow)
}

fn hash_projection_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn hash_optional_projection_field(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_projection_field(digest, "some");
            hash_projection_field(digest, value);
        }
        None => hash_projection_field(digest, "none"),
    }
}

fn canonical_outcome_event_digest(events: &[&OutcomeEvent], event_count: u64) -> String {
    let mut digest = Sha256::new();
    hash_projection_field(&mut digest, "hartevo-outcome-canonical-events/v1");
    hash_projection_field(&mut digest, &event_count.to_string());
    for event in events {
        hash_outcome_event(&mut digest, event);
    }
    format!("{:x}", digest.finalize())
}

fn canonical_order_refund_digest(orders: &[OutcomeOrder], refunds: &[OutcomeRefund]) -> String {
    let mut canonical_orders = orders.iter().collect::<Vec<_>>();
    canonical_orders.sort_by(|left, right| left.id.cmp(&right.id));
    let mut canonical_refunds = refunds.iter().collect::<Vec<_>>();
    canonical_refunds
        .sort_by(|left, right| (&left.order_id, &left.id).cmp(&(&right.order_id, &right.id)));
    let mut digest = Sha256::new();
    hash_projection_field(&mut digest, "hartevo-outcome-order-refund-projection/v1");
    hash_projection_field(&mut digest, &canonical_orders.len().to_string());
    for order in canonical_orders {
        hash_projection_field(&mut digest, order.id.as_str());
        hash_projection_field(&mut digest, order.source_event_id.as_str());
        hash_projection_field(&mut digest, &order.original_amount.amount_minor.to_string());
        hash_projection_field(&mut digest, order.original_amount.currency.as_str());
        hash_projection_field(&mut digest, &order.occurred_at.to_rfc3339());
    }
    hash_projection_field(&mut digest, &canonical_refunds.len().to_string());
    for refund in canonical_refunds {
        hash_projection_field(&mut digest, refund.id.as_str());
        hash_projection_field(&mut digest, refund.order_id.as_str());
        hash_projection_field(&mut digest, refund.source_event_id.as_str());
        hash_projection_field(&mut digest, &refund.amount.amount_minor.to_string());
        hash_projection_field(&mut digest, refund.amount.currency.as_str());
        hash_projection_field(&mut digest, &refund.occurred_at.to_rfc3339());
    }
    format!("{:x}", digest.finalize())
}

#[allow(
    clippy::too_many_lines,
    reason = "the canonical event proof deliberately binds every immutable identity, money, timestamp and source-verification field"
)]
fn hash_outcome_event(digest: &mut Sha256, event: &OutcomeEvent) {
    hash_projection_field(digest, event.id.as_str());
    hash_projection_field(digest, event.tenant_id.as_str());
    hash_projection_field(digest, event.project_id.as_str());
    hash_projection_field(digest, event.mission_id.as_str());
    hash_projection_field(
        digest,
        match event.kind {
            OutcomeEventKind::LeadQualified => "lead_qualified",
            OutcomeEventKind::MeetingBooked => "meeting_booked",
            OutcomeEventKind::OpportunityStageChanged => "opportunity_stage_changed",
            OutcomeEventKind::OrderPlaced => "order_placed",
            OutcomeEventKind::RefundIssued => "refund_issued",
            OutcomeEventKind::CommissionAccrued => "commission_accrued",
            OutcomeEventKind::CommissionReversed => "commission_reversed",
            OutcomeEventKind::PayoutCompleted => "payout_completed",
        },
    );
    hash_projection_field(digest, &event.provider);
    hash_optional_projection_field(
        digest,
        event.connection_id.as_ref().map(ConnectionId::as_str),
    );
    hash_optional_projection_field(digest, event.account_id.as_ref().map(AccountId::as_str));
    hash_projection_field(digest, &event.source_event_id);
    hash_optional_projection_field(
        digest,
        event.identity_link_id.as_ref().map(IdentityLinkId::as_str),
    );
    hash_optional_projection_field(
        digest,
        event.opportunity_id.as_ref().map(OpportunityId::as_str),
    );
    hash_optional_projection_field(digest, event.campaign_id.as_ref().map(CampaignId::as_str));
    hash_optional_projection_field(digest, event.order_id.as_ref().map(OrderId::as_str));
    hash_optional_projection_field(digest, event.refund_id.as_ref().map(RefundId::as_str));
    hash_optional_projection_field(
        digest,
        event.commission_id.as_ref().map(CommissionId::as_str),
    );
    hash_optional_projection_field(digest, event.payout_id.as_ref().map(PayoutId::as_str));
    hash_optional_projection_field(digest, event.partner_id.as_ref().map(PartnerId::as_str));
    if let Some(amount) = &event.amount {
        hash_projection_field(digest, "some");
        hash_projection_field(digest, &amount.amount_minor.to_string());
        hash_projection_field(digest, amount.currency.as_str());
    } else {
        hash_projection_field(digest, "none");
    }
    hash_projection_field(digest, &event.occurred_at.to_rfc3339());
    hash_projection_field(digest, &event.received_at.to_rfc3339());
    hash_projection_field(digest, &event.evidence_digest);
    hash_projection_field(digest, &event.raw_payload_digest);
    if let Some(verification) = &event.source_verification {
        hash_projection_field(digest, "some");
        hash_projection_field(
            digest,
            match verification.method {
                OutcomeVerificationMethod::SignedWebhook => "signed_webhook",
                OutcomeVerificationMethod::IndependentReadback => "independent_readback",
                OutcomeVerificationMethod::UserConfirmed => "user_confirmed",
                OutcomeVerificationMethod::InternalDerived => "internal_derived",
            },
        );
        hash_projection_field(digest, &verification.verifier);
        hash_projection_field(digest, &verification.independent.to_string());
        hash_projection_field(digest, &verification.verified_at.to_rfc3339());
        hash_projection_field(digest, &verification.evidence_digest);
    } else {
        hash_projection_field(digest, "none");
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use proptest::prelude::*;

    use super::*;
    use crate::{
        ActorId, Approval, ApprovalDecision, ApprovalId, Cadence, CadenceTriggerKind, Connection,
        ConnectionProbe, ConsentState, ContactPermission, CurrencyCode, EffectClass, EffectRisk,
        ExternalIdentity, IdentitySubject, MissionCheckpointApplicationEvidence,
        MissionCheckpointCompletion, MissionCheckpointOracleSource, MissionCheckpointRoute,
        MissionContract, MissionDefinition, PartnerSupplyClass, ProbeOutcome, Receipt, ReceiptId,
        Task, TaskId, TaskStatus, Verification, VerificationId,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn event(kind: OutcomeEventKind, id: &str, amount: Option<i64>) -> OutcomeEvent {
        OutcomeEvent {
            id: OutcomeEventId::from(id),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: MissionId::from("mission-11"),
            kind,
            provider: "commerce-fixture".into(),
            connection_id: Some(ConnectionId::from("connection-1")),
            account_id: Some(AccountId::from("account-1")),
            source_event_id: format!("source-{id}"),
            identity_link_id: Some(IdentityLinkId::from("identity-1")),
            opportunity_id: None,
            campaign_id: None,
            order_id: Some(OrderId::from("order-1")),
            refund_id: None,
            commission_id: None,
            payout_id: None,
            partner_id: None,
            amount: amount
                .map(|amount| Money::new(amount, CurrencyCode::parse("USD").expect("USD"))),
            occurred_at: now(),
            received_at: now() + Duration::minutes(1),
            evidence_digest: "a".repeat(64),
            raw_payload_digest: "b".repeat(64),
            source_verification: Some(OutcomeSourceVerification {
                method: OutcomeVerificationMethod::SignedWebhook,
                verifier: "commerce-fixture-webhook".into(),
                independent: true,
                verified_at: now() + Duration::minutes(1),
                evidence_digest: "c".repeat(64),
            }),
        }
    }

    fn confirmed_identity_support() -> (ConnectionSnapshot, Person, IdentityLink) {
        let person = Person::create(
            PersonId::from("person-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Verified buyer",
            None,
            vec![],
        )
        .expect("person");
        let mut link = IdentityLink::propose(
            IdentityLinkId::from("identity-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            IdentitySubject::Person(person.id.clone()),
            [ExternalIdentity {
                provider: "commerce-fixture".into(),
                account_id: AccountId::from("account-1"),
                external_subject_digest: "d".repeat(64),
                encrypted_subject_ref: "ciphertext://buyer-1".into(),
                evidence_digest: "e".repeat(64),
            }],
            Decimal::ONE,
        )
        .expect("identity link");
        link.confirm(ActorId::from("identity-reviewer"), "f".repeat(64), now())
            .expect("confirmed identity link");

        let mut connection = Connection::register(
            ConnectionId::from("connection-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "commerce-fixture",
            AccountId::from("account-1"),
            "external-account-1",
            ["orders.read".into()],
            now(),
        )
        .expect("connection");
        connection.begin_probe(now()).expect("begin probe");
        connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "external-account-1".into(),
                    granted_scopes: BTreeSet::from(["orders.read".into()]),
                    probed_at: now(),
                    valid_until: now() + Duration::hours(1),
                    credential_expires_at: now() + Duration::hours(2),
                    evidence_digest: "1".repeat(64),
                },
                now(),
            )
            .expect("successful probe");
        (connection.snapshot(), person, link)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the test fixture constructs the exact routed Application/Human review boundary and its completion evidence"
    )]
    fn vm11_decision_mission(review: &OutcomeReviewProjection, mode: OperatingMode) -> Mission {
        let mut contract = MissionContract::bootstrap(
            "Choose one explicit action from the frozen outcome review",
            ["decision.evaluate".into()],
            now(),
        );
        contract.mode = mode.clone();
        contract.parent_mission_id = Some(review.source_mission_id.clone());
        if matches!(
            mode,
            OperatingMode::ContinuousOperator | OperatingMode::ContinuousRelationship
        ) {
            contract.cadence = Some(Cadence {
                interval_seconds: 7 * 24 * 60 * 60,
                anchor_at: now(),
                trigger: CadenceTriggerKind::Interval,
                event_topics: BTreeSet::new(),
            });
        }
        let review_oracles = BTreeSet::from([
            "decision".into(),
            "operating_state".into(),
            "outcome".into(),
        ]);
        let decision_oracles = BTreeSet::from([
            "goal".into(),
            "decision".into(),
            "operating_state".into(),
            "outcome".into(),
        ]);
        let definition = MissionDefinition::from_routed_linear_manifest(
            "VM-11",
            3,
            "8".repeat(64),
            mode,
            ["decision.evaluate".into()],
            ["next_decision".into()],
            decision_oracles.clone(),
            [
                (
                    "outcome_review".into(),
                    MissionCheckpointRoute::contracted(
                        "decision.evaluate",
                        MissionCheckpointExecutor::Application,
                        review_oracles.clone(),
                        MissionCheckpointCompletionPolicy::DeterministicEvidence,
                    )
                    .expect("review route"),
                ),
                (
                    "continue_stop_scale_test".into(),
                    MissionCheckpointRoute::contracted(
                        "decision.evaluate",
                        MissionCheckpointExecutor::Human,
                        decision_oracles,
                        MissionCheckpointCompletionPolicy::HumanConfirmation,
                    )
                    .expect("decision route"),
                ),
            ],
        )
        .expect("VM-11 decision definition");
        let mut mission = Mission::compile_catalog(
            review.tenant_id.clone(),
            MissionId::from("vm11-decision-mission"),
            review.project_id.clone(),
            "VM-11 decision",
            contract,
            definition,
            now(),
        )
        .expect("VM-11 Mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("vm11-review-task"),
                    title: "Freeze outcome review".into(),
                    status: TaskStatus::Running,
                    capability: "decision.evaluate".into(),
                }],
                now(),
            )
            .expect("start review");
        let dispatch_mission_revision = mission.revision;
        let dispatch_checkpoint_revision = mission
            .definition
            .as_ref()
            .and_then(MissionDefinition::current_checkpoint)
            .map(|checkpoint| checkpoint.revision)
            .expect("review checkpoint");
        mission
            .begin_checkpoint_verification("outcome_review", review.observed_at)
            .expect("verify review");
        let definition = mission.definition.as_ref().expect("definition");
        let checkpoint = definition.current_checkpoint().expect("review checkpoint");
        let route = checkpoint.route.as_ref().expect("review route");
        let evidence = MissionCheckpointApplicationEvidence {
            schema_version: MissionCheckpointApplicationEvidence::SCHEMA_VERSION,
            handler_id: "vm11.outcome-review/v1".into(),
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            manifest_id: definition.manifest_id.clone(),
            manifest_version: definition.manifest_version,
            catalog_digest: definition.catalog_digest.clone(),
            cycle: definition.cycle,
            checkpoint_id: checkpoint.id.clone(),
            dispatch_mission_revision,
            dispatch_checkpoint_revision,
            verification_mission_revision: mission.revision,
            verification_checkpoint_revision: checkpoint.revision,
            capability_id: route.capability_id.clone(),
            executor: route.executor,
            completion_policy: route.completion_policy.expect("policy"),
            sources: BTreeSet::from([
                MissionCheckpointOracleSource {
                    source_kind: "mission_checkpoint".into(),
                    source_id: format!("{}:outcome_review", mission.id),
                    source_revision: dispatch_checkpoint_revision,
                    projection_digest: "9".repeat(64),
                    oracle_ids: BTreeSet::from(["operating_state".into()]),
                },
                MissionCheckpointOracleSource {
                    source_kind: "parent_mission_review".into(),
                    source_id: review.source_mission_id.to_string(),
                    source_revision: review.source_mission_revision,
                    projection_digest: "a".repeat(64),
                    oracle_ids: BTreeSet::from(["decision".into()]),
                },
                MissionCheckpointOracleSource {
                    source_kind: "outcome_review".into(),
                    source_id: review.project_id.to_string(),
                    source_revision: review.source_ledger_revision,
                    projection_digest: review.digest().expect("review digest"),
                    oracle_ids: BTreeSet::from(["outcome".into()]),
                },
            ]),
            observed_at: review.observed_at,
        };
        let evidence_digest = evidence.digest();
        mission
            .complete_checkpoint(
                "outcome_review",
                MissionCheckpointCompletion {
                    oracle_ids: review_oracles,
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: Some(evidence),
                    evidence_digest,
                    verified_at: review.observed_at,
                },
            )
            .expect("complete review");
        mission
            .begin_checkpoint_with_task(
                "continue_stop_scale_test",
                Task {
                    id: TaskId::from("vm11-decision-task"),
                    title: "Choose Continue, Stop, Scale, or Test".into(),
                    status: TaskStatus::Running,
                    capability: "decision.evaluate".into(),
                },
                review.observed_at + Duration::seconds(1),
            )
            .expect("start Human decision");
        mission
    }

    fn verified_attribution_support_mission(
        mission_id: &str,
        effect_id: &str,
        payload_digest: &str,
    ) -> Mission {
        let mut mission = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from(mission_id),
            ProjectId::from("project-1"),
            "Verified channel touchpoint",
            MissionContract::bootstrap(
                "Publish and independently verify one attribution touchpoint",
                ["publication.publish".into()],
                now(),
            ),
            now(),
        )
        .expect("support Mission");
        let effect_id = EffectId::from(effect_id);
        let mut effect = Effect {
            id: effect_id.clone(),
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            actor_id: ActorId::from("channel-operator"),
            capability: "publication.publish".into(),
            provider: "channel-fixture".into(),
            connection_id: Some(ConnectionId::from("channel-connection")),
            account_id: Some(AccountId::from("channel-account")),
            required_scopes: BTreeSet::from(["publish".into()]),
            effect_class: EffectClass::ExternalWrite,
            description: "Publish exact verified campaign link".into(),
            target_resource: "channel://verified-post".into(),
            audience_digest: Some("1".repeat(64)),
            payload_digest: payload_digest.into(),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "policy-v1".into(),
            risk: EffectRisk::Low,
            idempotency_key: format!("publish-{effect_id}"),
            amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
            expires_at: now() + Duration::days(1),
            status: EffectStatus::Verified,
            approval: None,
            receipt: None,
            verification: None,
        };
        let approval_digest = effect.approval_digest();
        let approval_id = format!("approval-{effect_id}");
        effect.approval = Some(Approval {
            id: ApprovalId::from(approval_id.as_str()),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from("project-owner"),
            decided_at: now() + Duration::minutes(1),
            valid_until: now() + Duration::hours(1),
            scope_digest: approval_digest.clone(),
            permission_digest: "2".repeat(64),
        });
        let receipt_id = format!("receipt-{effect_id}");
        let receipt_id = ReceiptId::from(receipt_id.as_str());
        effect.receipt = Some(Receipt {
            id: receipt_id.clone(),
            provider: "channel-fixture".into(),
            external_id: format!("external-{effect_id}"),
            accepted_at: now() + Duration::minutes(2),
            request_digest: approval_digest,
            response_digest: "3".repeat(64),
        });
        let verification_id = format!("verification-{effect_id}");
        effect.verification = Some(Verification {
            id: VerificationId::from(verification_id.as_str()),
            status: VerificationStatus::Confirmed,
            verifier: "independent-channel-readback".into(),
            independent: true,
            observed_at: now() + Duration::minutes(3),
            evidence_digest: "4".repeat(64),
            receipt_id,
        });
        mission.effects.push(effect);
        mission.revision = 2;
        mission
    }

    #[test]
    fn crm_stage_can_never_be_ingested_as_revenue() {
        let mut stage = event(
            OutcomeEventKind::OpportunityStageChanged,
            "stage-1",
            Some(50_000),
        );
        stage.order_id = None;
        stage.opportunity_id = Some(OpportunityId::from("opportunity-1"));
        assert_eq!(
            stage.validate(),
            Err(OutcomeLedgerError::EventKindShapeMismatch)
        );
        stage.amount = None;
        assert!(stage.validate().is_ok());
        assert!(!stage.is_revenue_event());
    }

    #[test]
    fn provider_acceptance_without_independent_source_proof_never_becomes_revenue() {
        let mut order = event(
            OutcomeEventKind::OrderPlaced,
            "unverified-order",
            Some(10_000),
        );
        order.source_verification = None;
        assert_eq!(
            order.validate(),
            Err(OutcomeLedgerError::UnverifiedOutcomeSource)
        );
        // Legacy v16 data remains readable for migration/reconciliation, but
        // the strict ingestion and encrypted-sync boundary still reject it.
        assert!(order.validate_persisted().is_ok());

        order.source_verification = Some(OutcomeSourceVerification {
            method: OutcomeVerificationMethod::SignedWebhook,
            verifier: "provider-200-ok".into(),
            independent: false,
            verified_at: order.received_at,
            evidence_digest: "d".repeat(64),
        });
        assert_eq!(
            order.validate(),
            Err(OutcomeLedgerError::UnverifiedOutcomeSource)
        );
    }

    #[test]
    fn verified_normalization_is_canonical_and_rejects_legacy_unverified_sources() {
        let mut later = event(OutcomeEventKind::LeadQualified, "later", None);
        later.order_id = None;
        later.occurred_at = now() + Duration::minutes(2);
        later.received_at = now() + Duration::minutes(3);
        later
            .source_verification
            .as_mut()
            .expect("source verification")
            .verified_at = later.received_at;
        let mut earlier = event(OutcomeEventKind::LeadQualified, "earlier", None);
        earlier.order_id = None;
        earlier.occurred_at = now() + Duration::minutes(1);
        earlier.received_at = now() + Duration::minutes(4);
        earlier
            .source_verification
            .as_mut()
            .expect("source verification")
            .verified_at = earlier.received_at;

        let mut observed_out_of_order =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        observed_out_of_order
            .ingest(later.clone())
            .expect("later event first");
        observed_out_of_order
            .ingest(earlier.clone())
            .expect("earlier event arrives later");
        let projection = observed_out_of_order
            .verified_normalization_projection()
            .expect("strict normalization");
        assert_eq!(
            (
                projection.event_count,
                projection.unique_event_id_count,
                projection.unique_provider_source_count,
                projection.observed_reorder_count,
                projection.order_count,
                projection.refund_count,
            ),
            (2, 2, 2, 2, 0, 0)
        );
        assert!(is_sha256(&projection.digest()));

        let mut canonical_observation =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        canonical_observation
            .ingest(earlier)
            .expect("earlier event first");
        canonical_observation
            .ingest(later)
            .expect("later event second");
        let canonical_projection = canonical_observation
            .verified_normalization_projection()
            .expect("canonical normalization");
        assert_eq!(canonical_projection.observed_reorder_count, 0);
        assert_eq!(
            projection.canonical_event_digest,
            canonical_projection.canonical_event_digest
        );
        assert_eq!(
            projection.order_refund_projection_digest,
            canonical_projection.order_refund_projection_digest
        );

        let mut legacy_readable = canonical_observation;
        legacy_readable.events[0].source_verification = None;
        assert!(legacy_readable.validate().is_ok());
        assert_eq!(
            legacy_readable.verified_normalization_projection(),
            Err(OutcomeLedgerError::UnverifiedOutcomeSource)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one ordered Oracle regression compares success, identity conflict, provider mismatch, exact closure rejection and deterministic recomputation"
    )]
    fn identity_chain_oracle_requires_exact_confirmed_provider_scoped_support() {
        let (connection, person, link) = confirmed_identity_support();
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        ledger
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "identity-order",
                Some(10_000),
            ))
            .expect("order");
        let mut refund = event(
            OutcomeEventKind::RefundIssued,
            "identity-refund",
            Some(1_000),
        );
        refund.identity_link_id = None;
        refund.refund_id = Some(RefundId::from("refund-1"));
        refund.occurred_at = now() + Duration::minutes(2);
        refund.received_at = now() + Duration::minutes(3);
        refund
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = refund.received_at;
        ledger.ingest(refund).expect("refund");

        let projection = ledger
            .verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                &[],
                &[],
            )
            .expect("verified identity closure");
        assert_eq!(
            (
                projection.event_count,
                projection.identity_covered_event_count,
                projection.direct_identity_event_count,
                projection.inherited_order_identity_event_count,
                projection.external_account_match_count,
                projection.connection_count,
                projection.identity_link_count,
                projection.person_count,
            ),
            (2, 2, 1, 1, 1, 1, 1, 1)
        );
        assert!(is_sha256(&projection.source_support_digest));
        assert!(is_sha256(&projection.digest()));
        assert_eq!(
            projection,
            ledger
                .verified_identity_chain_projection(
                    std::slice::from_ref(&connection),
                    std::slice::from_ref(&link),
                    std::slice::from_ref(&person),
                    &[],
                    &[],
                    &[],
                )
                .expect("deterministic recomputation")
        );

        let partner = Partner::create(
            PartnerId::from("partner-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            None,
            None,
            "Verified partner",
            PartnerSupplyClass::TenantPrivate,
            ContactPermission::TenantOwnedRelationship,
            Some("6".repeat(64)),
        )
        .expect("partner");
        let mut out_of_order_commission =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        let mut commission_event = event(
            OutcomeEventKind::CommissionAccrued,
            "commission-before-order",
            Some(500),
        );
        commission_event.identity_link_id = None;
        commission_event.commission_id = Some(CommissionId::from("commission-event-1"));
        commission_event.partner_id = Some(partner.id.clone());
        out_of_order_commission
            .ingest(commission_event)
            .expect("commission can arrive before order callback");
        out_of_order_commission
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "late-order-callback",
                Some(10_000),
            ))
            .expect("late order callback");
        let out_of_order_projection = out_of_order_commission
            .verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                &[partner],
                &[],
            )
            .expect("order-insensitive identity inheritance");
        assert_eq!(
            (
                out_of_order_projection.event_count,
                out_of_order_projection.identity_covered_event_count,
                out_of_order_projection.direct_identity_event_count,
                out_of_order_projection.inherited_order_identity_event_count,
            ),
            (2, 2, 1, 1)
        );

        let mut conflicted = link.clone();
        conflicted
            .mark_conflicted(
                ActorId::from("identity-reviewer"),
                "2".repeat(64),
                now() + Duration::minutes(4),
            )
            .expect("conflict transition");
        assert_eq!(
            ledger.verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                &[conflicted],
                std::slice::from_ref(&person),
                &[],
                &[],
                &[],
            ),
            Err(OutcomeLedgerError::IdentityLinkUnconfirmed)
        );

        let mut wrong_provider_link = IdentityLink::propose(
            link.id.clone(),
            link.tenant_id.clone(),
            link.project_id.clone(),
            link.subject.clone(),
            [ExternalIdentity {
                provider: "wrong-provider".into(),
                account_id: AccountId::from("account-1"),
                external_subject_digest: "3".repeat(64),
                encrypted_subject_ref: "ciphertext://wrong-provider".into(),
                evidence_digest: "4".repeat(64),
            }],
            Decimal::ONE,
        )
        .expect("wrong provider link");
        wrong_provider_link
            .confirm(ActorId::from("identity-reviewer"), "5".repeat(64), now())
            .expect("confirmed wrong provider fixture");
        assert_eq!(
            ledger.verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                &[wrong_provider_link],
                std::slice::from_ref(&person),
                &[],
                &[],
                &[],
            ),
            Err(OutcomeLedgerError::IdentityProviderAccountMismatch)
        );

        let unrelated_company = Company::create(
            CompanyId::from("unrelated-company"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Unrelated Company",
            "US",
        )
        .expect("unrelated company");
        assert_eq!(
            ledger.verified_identity_chain_projection(
                &[connection],
                &[link],
                &[person],
                &[unrelated_company],
                &[],
                &[],
            ),
            Err(OutcomeLedgerError::IdentityChainSupportClosureMismatch)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Oracle contract test covers count, gross, refund, net, direction, currency conflict, unsupported CRM-as-revenue, deterministic digest, and parent isolation together"
    )]
    fn mission_kpi_oracle_binds_parent_window_direction_and_minor_unit_currency() {
        let mut contract = MissionContract::bootstrap(
            "Grow verified commerce outcomes",
            ["attribution.compute".into()],
            now(),
        );
        contract.kpis = BTreeMap::from([
            (
                "gross_revenue_minor".into(),
                KpiContract {
                    baseline: Some(Decimal::from(5_000)),
                    target: Decimal::from(10_000),
                    unit: "minor_units:USD".into(),
                    direction: KpiDirection::AtLeast,
                },
            ),
            (
                "lead_qualified_count".into(),
                KpiContract {
                    baseline: Some(Decimal::ZERO),
                    target: Decimal::ONE,
                    unit: "count".into(),
                    direction: KpiDirection::AtLeast,
                },
            ),
            (
                "net_revenue_minor".into(),
                KpiContract {
                    baseline: None,
                    target: Decimal::from(7_500),
                    unit: "minor_units:USD".into(),
                    direction: KpiDirection::AtLeast,
                },
            ),
            (
                "refund_total_minor".into(),
                KpiContract {
                    baseline: None,
                    target: Decimal::from(3_000),
                    unit: "minor_units:USD".into(),
                    direction: KpiDirection::AtMost,
                },
            ),
        ]);
        let parent = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-11"),
            ProjectId::from("project-1"),
            "Parent growth Mission",
            contract,
            now(),
        )
        .expect("parent Mission");

        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        ledger
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "kpi-order",
                Some(10_000),
            ))
            .expect("order");
        let mut lead = event(OutcomeEventKind::LeadQualified, "kpi-lead", None);
        lead.order_id = None;
        lead.occurred_at = now() + Duration::minutes(1);
        lead.received_at = now() + Duration::minutes(2);
        lead.source_verification
            .as_mut()
            .expect("verification")
            .verified_at = lead.received_at;
        ledger.ingest(lead).expect("lead");
        let mut refund = event(OutcomeEventKind::RefundIssued, "kpi-refund", Some(2_500));
        refund.refund_id = Some(RefundId::from("refund-1"));
        refund.identity_link_id = None;
        refund.occurred_at = now() + Duration::minutes(2);
        refund.received_at = now() + Duration::minutes(3);
        refund
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = refund.received_at;
        ledger.ingest(refund).expect("refund");

        let (connection, person, link) = confirmed_identity_support();
        let identity_chain = ledger
            .verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                &[],
                &[],
            )
            .expect("current identity chain");

        let projection = ledger
            .verified_mission_kpi_projection(&parent, &identity_chain, now() + Duration::minutes(4))
            .expect("typed KPI projection");
        assert_eq!(
            (
                projection.source_mission_id.as_str(),
                projection.source_mission_revision,
                projection.source_ledger_revision,
                projection.source_event_count,
                projection.measurement_count,
                projection.target_met_count,
            ),
            ("mission-11", 1, 4, 3, 4, 4)
        );
        assert_eq!(
            projection
                .measurements
                .get("lead_qualified_count")
                .map(|measurement| &measurement.observed),
            Some(&MissionKpiObservedValue::Count { value: 1 })
        );
        assert_eq!(
            projection
                .measurements
                .get("net_revenue_minor")
                .map(|measurement| &measurement.observed),
            Some(&MissionKpiObservedValue::Money {
                value: Money::new(7_500, CurrencyCode::parse("USD").expect("USD")),
            })
        );
        assert!(is_sha256(&projection.digest().expect("projection digest")));

        let mut mixed_currency = ledger.clone();
        let mut eur_order = event(OutcomeEventKind::OrderPlaced, "kpi-eur-order", Some(4_000));
        eur_order.order_id = Some(OrderId::from("order-2"));
        eur_order.amount = Some(Money::new(4_000, CurrencyCode::parse("EUR").expect("EUR")));
        eur_order.occurred_at = now() + Duration::minutes(3);
        eur_order.received_at = now() + Duration::minutes(4);
        eur_order
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = eur_order.received_at;
        mixed_currency.ingest(eur_order).expect("EUR order");
        let mixed_identity_chain = mixed_currency
            .verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                &[],
                &[],
            )
            .expect("mixed-currency identity chain");
        assert_eq!(
            mixed_currency.verified_mission_kpi_projection(
                &parent,
                &mixed_identity_chain,
                now() + Duration::minutes(5),
            ),
            Err(OutcomeLedgerError::KpiCurrencyMismatch)
        );

        let mut unsupported_parent = parent.clone();
        unsupported_parent.contract.kpis = BTreeMap::from([(
            "crm_stage_as_revenue".into(),
            KpiContract {
                baseline: None,
                target: Decimal::ONE,
                unit: "count".into(),
                direction: KpiDirection::AtLeast,
            },
        )]);
        assert_eq!(
            ledger.verified_mission_kpi_projection(
                &unsupported_parent,
                &identity_chain,
                now() + Duration::minutes(4),
            ),
            Err(OutcomeLedgerError::UnsupportedKpiMetric)
        );

        let mut unrelated_parent = parent;
        unrelated_parent.id = MissionId::from("unrelated-mission");
        assert_eq!(
            ledger.verified_mission_kpi_projection(
                &unrelated_parent,
                &identity_chain,
                now() + Duration::minutes(4),
            ),
            Err(OutcomeLedgerError::KpiSourceEventsUnavailable)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the attribution Oracle test proves verified-identity priority, first/last views, synthesized and explicit Unattributed preservation, effect support, dispute refusal, legacy quarantine, exact closure, and the no-causality invariant together"
    )]
    fn attribution_oracle_prioritizes_verified_identity_and_preserves_unattributed_without_causality()
     {
        let parent = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-11"),
            ProjectId::from("project-1"),
            "Parent commerce Mission",
            MissionContract::bootstrap(
                "Review verified commerce attribution",
                ["attribution.compute".into()],
                now(),
            ),
            now(),
        )
        .expect("parent Mission");
        let empty_ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("empty ledger");
        assert_eq!(
            empty_ledger.attribution_support_mission_ids(&parent, now() + Duration::minutes(40),),
            Err(OutcomeLedgerError::AttributionSourceOrdersUnavailable)
        );
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        for (index, minute) in [(1_i64, 10_i64), (2, 20), (3, 30)] {
            let mut order = event(
                OutcomeEventKind::OrderPlaced,
                &format!("attribution-order-event-{index}"),
                Some(index * 10_000),
            );
            let order_id = format!("attribution-order-{index}");
            order.order_id = Some(OrderId::from(order_id.as_str()));
            order.occurred_at = now() + Duration::minutes(minute);
            order.received_at = now() + Duration::minutes(minute + 1);
            order
                .source_verification
                .as_mut()
                .expect("verification")
                .verified_at = order.received_at;
            ledger.ingest(order).expect("verified order");
        }
        let (connection, person, link) = confirmed_identity_support();

        let support = verified_attribution_support_mission(
            "channel-mission",
            "verified-touch-effect",
            &"5".repeat(64),
        );
        let effect = support.effects.first().expect("verified support Effect");
        let provider_identity_digest =
            attribution_effect_provider_identity_digest(effect).expect("provider identity digest");

        let first_touch = AttributionRecord {
            id: AttributionId::from("first-touch-record"),
            tenant_id: ledger.tenant_id.clone(),
            project_id: ledger.project_id.clone(),
            order_id: OrderId::from("attribution-order-1"),
            model: AttributionModel::FirstTouch,
            touchpoint: Some(Touchpoint {
                mission_id: support.id.clone(),
                source: "search-readback".into(),
                effect_id: None,
                traffic_class: Some(AttributionTrafficClass::NonDirect),
                provider_identity_digest: None,
                verified_link_or_coupon_digest: None,
                occurred_at: now() + Duration::minutes(4),
                received_at: Some(now() + Duration::minutes(5)),
                evidence_digest: "6".repeat(64),
                source_verification: Some(OutcomeSourceVerification {
                    method: OutcomeVerificationMethod::IndependentReadback,
                    verifier: "analytics-readback".into(),
                    independent: true,
                    verified_at: now() + Duration::minutes(5),
                    evidence_digest: "6".repeat(64),
                }),
            }),
            window_started_at: now(),
            window_ended_at: now() + Duration::hours(1),
            confidence: "0.6".parse().expect("confidence"),
            causal_claim: false,
            rationale: "Operational first-touch view".into(),
            evidence_digest: "7".repeat(64),
            recorded_at: now() + Duration::minutes(12),
        };
        ledger.attribute(first_touch).expect("first touch");
        let verified_identity = AttributionRecord {
            id: AttributionId::from("verified-identity-record"),
            tenant_id: ledger.tenant_id.clone(),
            project_id: ledger.project_id.clone(),
            order_id: OrderId::from("attribution-order-1"),
            model: AttributionModel::VerifiedIdentity,
            touchpoint: Some(Touchpoint {
                mission_id: support.id.clone(),
                source: "verified-campaign-link".into(),
                effect_id: Some(effect.id.clone()),
                traffic_class: Some(AttributionTrafficClass::NonDirect),
                provider_identity_digest: Some(provider_identity_digest),
                verified_link_or_coupon_digest: Some(effect.payload_digest.clone()),
                occurred_at: now() + Duration::minutes(6),
                received_at: Some(now() + Duration::minutes(7)),
                evidence_digest: "8".repeat(64),
                source_verification: Some(OutcomeSourceVerification {
                    method: OutcomeVerificationMethod::SignedWebhook,
                    verifier: "commerce-link-webhook".into(),
                    independent: true,
                    verified_at: now() + Duration::minutes(7),
                    evidence_digest: "8".repeat(64),
                }),
            }),
            window_started_at: now(),
            window_ended_at: now() + Duration::hours(1),
            confidence: Decimal::ONE,
            causal_claim: false,
            rationale: "Verified link identity, reported only as operational attribution".into(),
            evidence_digest: "9".repeat(64),
            recorded_at: now() + Duration::minutes(12),
        };
        ledger
            .attribute(verified_identity)
            .expect("verified identity attribution");
        let last_non_direct = AttributionRecord {
            id: AttributionId::from("last-non-direct-record"),
            tenant_id: ledger.tenant_id.clone(),
            project_id: ledger.project_id.clone(),
            order_id: OrderId::from("attribution-order-2"),
            model: AttributionModel::LastNonDirect,
            touchpoint: Some(Touchpoint {
                mission_id: parent.id.clone(),
                source: "email-readback".into(),
                effect_id: None,
                traffic_class: Some(AttributionTrafficClass::NonDirect),
                provider_identity_digest: None,
                verified_link_or_coupon_digest: None,
                occurred_at: now() + Duration::minutes(15),
                received_at: Some(now() + Duration::minutes(16)),
                evidence_digest: "a".repeat(64),
                source_verification: Some(OutcomeSourceVerification {
                    method: OutcomeVerificationMethod::IndependentReadback,
                    verifier: "analytics-readback".into(),
                    independent: true,
                    verified_at: now() + Duration::minutes(16),
                    evidence_digest: "a".repeat(64),
                }),
            }),
            window_started_at: now(),
            window_ended_at: now() + Duration::hours(1),
            confidence: "0.7".parse().expect("confidence"),
            causal_claim: false,
            rationale: "Operational last-non-direct view".into(),
            evidence_digest: "b".repeat(64),
            recorded_at: now() + Duration::minutes(22),
        };
        ledger
            .attribute(last_non_direct.clone())
            .expect("last non-direct attribution");
        ledger
            .attribute(AttributionRecord {
                id: AttributionId::from("explicit-unattributed-record"),
                tenant_id: ledger.tenant_id.clone(),
                project_id: ledger.project_id.clone(),
                order_id: OrderId::from("attribution-order-3"),
                model: AttributionModel::Unattributed,
                touchpoint: None,
                window_started_at: now(),
                window_ended_at: now() + Duration::hours(1),
                confidence: Decimal::ZERO,
                causal_claim: false,
                rationale: "No source-verified touchpoint in the contract window".into(),
                evidence_digest: "c".repeat(64),
                recorded_at: now() + Duration::minutes(32),
            })
            .expect("explicit Unattributed record");

        let identity_chain = ledger
            .verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                &[],
                &[],
            )
            .expect("current identity chain after attribution records");

        let projection = ledger
            .verified_attribution_projection(
                &parent,
                &identity_chain,
                &[support.clone(), parent.clone()],
                now() + Duration::minutes(40),
            )
            .expect("deterministic attribution projection");
        assert_eq!(
            (
                projection.order_count,
                projection.source_record_count,
                projection.eligible_touchpoint_count,
                projection.verified_identity_order_count,
                projection.last_non_direct_order_count,
                projection.unattributed_order_count,
                projection.first_touch_order_count,
                projection.explicit_unattributed_record_count,
                projection.supporting_mission_count,
                projection.verified_effect_count,
                projection.causal_claim,
            ),
            (3, 4, 3, 1, 1, 1, 2, 1, 2, 1, false)
        );
        assert_eq!(
            projection
                .orders
                .get(&OrderId::from("attribution-order-1"))
                .map(|view| {
                    (
                        view.primary_model,
                        view.primary_attribution_id
                            .as_ref()
                            .map(AttributionId::as_str),
                        view.first_touch_attribution_id
                            .as_ref()
                            .map(AttributionId::as_str),
                        view.causal_claim,
                    )
                }),
            Some((
                AttributionModel::VerifiedIdentity,
                Some("verified-identity-record"),
                Some("first-touch-record"),
                false,
            ))
        );
        assert_eq!(
            projection
                .orders
                .get(&OrderId::from("attribution-order-3"))
                .map(|view| view.primary_model),
            Some(AttributionModel::Unattributed)
        );
        assert!(is_sha256(&projection.digest().expect("projection digest")));

        assert_eq!(
            ledger.verified_attribution_projection(
                &parent,
                &identity_chain,
                std::slice::from_ref(&parent),
                now() + Duration::minutes(40),
            ),
            Err(OutcomeLedgerError::AttributionSupportClosureMismatch)
        );

        let mut legacy_unverified = ledger.clone();
        let legacy_touchpoint = legacy_unverified.attributions[0]
            .touchpoint
            .as_mut()
            .expect("legacy touchpoint");
        legacy_touchpoint.traffic_class = None;
        legacy_touchpoint.received_at = None;
        legacy_touchpoint.source_verification = None;
        assert!(legacy_unverified.validate().is_ok());
        assert_eq!(
            legacy_unverified.verified_attribution_projection(
                &parent,
                &identity_chain,
                &[support.clone(), parent.clone()],
                now() + Duration::minutes(40),
            ),
            Err(OutcomeLedgerError::UnverifiedAttributionSource)
        );

        let mut disputed_ledger = ledger;
        let second_effect_mission = verified_attribution_support_mission(
            "channel-mission",
            "second-verified-touch-effect",
            &"d".repeat(64),
        );
        let second_effect = second_effect_mission.effects[0].clone();
        let second_provider_identity = attribution_effect_provider_identity_digest(&second_effect)
            .expect("second provider identity");
        let mut disputed_support = support;
        disputed_support.effects.push(second_effect.clone());
        disputed_support.revision = 3;
        disputed_ledger
            .attribute(AttributionRecord {
                id: AttributionId::from("disputed-verified-identity"),
                tenant_id: disputed_ledger.tenant_id.clone(),
                project_id: disputed_ledger.project_id.clone(),
                order_id: OrderId::from("attribution-order-1"),
                model: AttributionModel::VerifiedIdentity,
                touchpoint: Some(Touchpoint {
                    mission_id: disputed_support.id.clone(),
                    source: "second-verified-campaign-link".into(),
                    effect_id: Some(second_effect.id.clone()),
                    traffic_class: Some(AttributionTrafficClass::NonDirect),
                    provider_identity_digest: Some(second_provider_identity),
                    verified_link_or_coupon_digest: Some(second_effect.payload_digest.clone()),
                    occurred_at: now() + Duration::minutes(7),
                    received_at: Some(now() + Duration::minutes(8)),
                    evidence_digest: "e".repeat(64),
                    source_verification: Some(OutcomeSourceVerification {
                        method: OutcomeVerificationMethod::SignedWebhook,
                        verifier: "second-commerce-link-webhook".into(),
                        independent: true,
                        verified_at: now() + Duration::minutes(8),
                        evidence_digest: "e".repeat(64),
                    }),
                }),
                window_started_at: now(),
                window_ended_at: now() + Duration::hours(1),
                confidence: Decimal::ONE,
                causal_claim: false,
                rationale: "Conflicting verified identity must not be selected".into(),
                evidence_digest: "f".repeat(64),
                recorded_at: now() + Duration::minutes(13),
            })
            .expect("second verified record is individually valid");
        let disputed_identity_chain = disputed_ledger
            .verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                &[],
                &[],
            )
            .expect("disputed ledger identity chain");
        assert_eq!(
            disputed_ledger.verified_attribution_projection(
                &parent,
                &disputed_identity_chain,
                &[disputed_support, parent.clone()],
                now() + Duration::minutes(40),
            ),
            Err(OutcomeLedgerError::DisputedAttribution)
        );

        let mut causal_record = last_non_direct;
        causal_record.id = AttributionId::from("forbidden-causal-record");
        causal_record.causal_claim = true;
        assert_eq!(
            disputed_ledger.attribute(causal_record),
            Err(OutcomeLedgerError::InvalidAttribution)
        );
    }

    #[test]
    fn outcome_snapshot_follows_only_one_exact_immutable_command() {
        let mut previous =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        previous
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "order-event",
                Some(10_000),
            ))
            .expect("order");
        let mut next = previous.clone();
        let mut refund = event(OutcomeEventKind::RefundIssued, "refund-event", Some(2_500));
        refund.refund_id = Some(RefundId::from("refund-1"));
        next.ingest(refund).expect("refund");
        assert!(next.follows(&previous).expect("exact transition"));

        let mut rewritten = next.clone();
        rewritten.events[0].raw_payload_digest = "f".repeat(64);
        assert!(
            !rewritten
                .follows(&previous)
                .expect("valid but rewritten history")
        );

        let mut revision_jump = next;
        revision_jump.revision += 1;
        assert!(matches!(
            revision_jump.follows(&previous),
            Err(OutcomeLedgerError::ProjectionRevisionMismatch { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the settlement regression proves immutable order/refund history, cross-period commission recalculation, supply-class authority, exact minor-unit payout reconciliation, and deterministic replay together"
    )]
    fn settlement_oracle_recalculates_refunds_and_reconciles_only_verified_payout_facts() {
        let parent = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-11"),
            ProjectId::from("project-1"),
            "Parent partner Mission",
            MissionContract::bootstrap(
                "Reconcile immutable partner outcomes",
                ["settlement.compute".into()],
                now(),
            ),
            now(),
        )
        .expect("parent Mission");
        let partner = Partner::create(
            PartnerId::from("partner-settlement"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            None,
            None,
            "Opt-in creator",
            PartnerSupplyClass::HartevoOptIn,
            ContactPermission::ExplicitOptIn,
            Some("1".repeat(64)),
        )
        .expect("partner");
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        let order = event(
            OutcomeEventKind::OrderPlaced,
            "settlement-order",
            Some(10_000),
        );
        ledger.ingest(order).expect("order");
        let immutable_order = ledger.orders[0].clone();
        ledger
            .calculate_commission(
                CommissionId::from("commission-before-refund"),
                &OrderId::from("order-1"),
                partner.id.clone(),
                "0.15".parse().expect("rate"),
                "2".repeat(64),
                now() + Duration::minutes(2),
            )
            .expect("initial commission");
        let mut refund = event(
            OutcomeEventKind::RefundIssued,
            "settlement-refund",
            Some(2_500),
        );
        refund.identity_link_id = None;
        refund.refund_id = Some(RefundId::from("settlement-refund-1"));
        refund.occurred_at = now() + Duration::minutes(3);
        refund.received_at = now() + Duration::minutes(4);
        refund
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = refund.received_at;
        ledger.ingest(refund).expect("cross-period refund");
        assert_eq!(ledger.orders[0], immutable_order);

        let (commerce_connection, person, link) = confirmed_identity_support();
        let stale_identity = ledger
            .verified_identity_chain_projection(
                std::slice::from_ref(&commerce_connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                std::slice::from_ref(&partner),
                &[],
            )
            .expect("identity chain");
        assert_eq!(
            ledger.verified_settlement_projection(
                &parent,
                &stale_identity,
                std::slice::from_ref(&partner),
                now() + Duration::minutes(5),
            ),
            Err(OutcomeLedgerError::SettlementCommissionRecalculationRequired)
        );

        let adjusted = ledger
            .calculate_commission(
                CommissionId::from("commission-after-refund"),
                &OrderId::from("order-1"),
                partner.id.clone(),
                "0.15".parse().expect("rate"),
                "2".repeat(64),
                now() + Duration::minutes(5),
            )
            .expect("adjusted commission");
        assert_eq!(
            (
                adjusted.eligible_net_amount.amount_minor,
                adjusted.commission_amount.amount_minor,
            ),
            (7_500, 1_125)
        );
        let adjusted_identity = ledger
            .verified_identity_chain_projection(
                std::slice::from_ref(&commerce_connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                std::slice::from_ref(&partner),
                &[],
            )
            .expect("adjusted identity chain");
        let outstanding = ledger
            .verified_settlement_projection(
                &parent,
                &adjusted_identity,
                std::slice::from_ref(&partner),
                now() + Duration::minutes(6),
            )
            .expect("outstanding settlement");
        assert_eq!(
            (
                outstanding.order_count,
                outstanding.refunded_order_count,
                outstanding.refund_count,
                outstanding.calculated_commission_count,
                outstanding.settlement_group_count,
                outstanding.outstanding_group_count,
                outstanding.settlements[0].outstanding_amount.amount_minor,
            ),
            (1, 1, 1, 1, 1, 1, 1_125)
        );
        assert_eq!(
            outstanding.orders[&OrderId::from("order-1")].original_amount,
            immutable_order.original_amount
        );

        let official_partner = Partner::create(
            partner.id.clone(),
            partner.tenant_id.clone(),
            partner.project_id.clone(),
            None,
            None,
            "Official network creator",
            PartnerSupplyClass::OfficialAuthorizedNetwork,
            ContactPermission::NetworkAuthorized,
            Some("3".repeat(64)),
        )
        .expect("official partner");
        let official_identity = ledger
            .verified_identity_chain_projection(
                std::slice::from_ref(&commerce_connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                std::slice::from_ref(&official_partner),
                &[],
            )
            .expect("official identity chain");
        assert_eq!(
            ledger.verified_settlement_projection(
                &parent,
                &official_identity,
                std::slice::from_ref(&official_partner),
                now() + Duration::minutes(6),
            ),
            Err(OutcomeLedgerError::SettlementCommissionAuthorityMismatch)
        );

        let mut payout_connection = Connection::register(
            ConnectionId::from("payout-connection"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "stripe-connect",
            AccountId::from("payout-account"),
            "payout-account-external",
            ["payout.read".into()],
            now(),
        )
        .expect("payout connection");
        payout_connection.begin_probe(now()).expect("begin probe");
        payout_connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "payout-account-external".into(),
                    granted_scopes: BTreeSet::from(["payout.read".into()]),
                    probed_at: now(),
                    valid_until: now() + Duration::hours(1),
                    credential_expires_at: now() + Duration::hours(2),
                    evidence_digest: "4".repeat(64),
                },
                now(),
            )
            .expect("payout probe");
        let mut payout = event(
            OutcomeEventKind::PayoutCompleted,
            "settlement-payout",
            Some(1_125),
        );
        payout.provider = "stripe-connect".into();
        payout.connection_id = Some(payout_connection.id().clone());
        payout.account_id = Some(AccountId::from("payout-account"));
        payout.identity_link_id = None;
        payout.order_id = None;
        payout.payout_id = Some(PayoutId::from("settlement-payout-1"));
        payout.partner_id = Some(partner.id.clone());
        payout.occurred_at = now() + Duration::minutes(6);
        payout.received_at = now() + Duration::minutes(7);
        payout
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = payout.received_at;
        ledger.ingest(payout).expect("verified payout fact");
        let paid_identity = ledger
            .verified_identity_chain_projection(
                &[commerce_connection, payout_connection.snapshot()],
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                std::slice::from_ref(&partner),
                &[],
            )
            .expect("paid identity chain");
        let paid = ledger
            .verified_settlement_projection(
                &parent,
                &paid_identity,
                std::slice::from_ref(&partner),
                now() + Duration::minutes(8),
            )
            .expect("paid settlement");
        assert_eq!(
            (
                paid.payout_count,
                paid.paid_group_count,
                paid.outstanding_group_count,
                paid.settlements[0].payout_completed_amount.amount_minor,
                paid.settlements[0].outstanding_amount.amount_minor,
                paid.settlements[0].status,
            ),
            (1, 1, 0, 1_125, 0, SettlementGroupStatus::Paid)
        );
        assert_eq!(
            paid,
            ledger
                .verified_settlement_projection(
                    &parent,
                    &paid_identity,
                    std::slice::from_ref(&partner),
                    now() + Duration::minutes(8),
                )
                .expect("deterministic recomputation")
        );
        assert!(is_sha256(&paid.digest().expect("settlement digest")));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the outcome review regression binds KPI, attribution, settlement, verified and unresolved cost, budget, no-FX/no-causality, and tamper refusal in one deterministic proof"
    )]
    fn outcome_review_oracle_freezes_decision_inputs_without_selecting_an_action() {
        let mut parent = verified_attribution_support_mission(
            "mission-11",
            "review-verified-cost",
            &"5".repeat(64),
        );
        parent.contract.kpis = BTreeMap::from([(
            "gross_revenue_minor".into(),
            KpiContract {
                baseline: Some(Decimal::ZERO),
                target: Decimal::from(10_000),
                unit: "minor_units:USD".into(),
                direction: KpiDirection::AtLeast,
            },
        )]);
        parent.contract.budget = Money::new(500, CurrencyCode::parse("USD").expect("USD"));
        {
            let effect = parent.effects.first_mut().expect("verified cost Effect");
            effect.effect_class = EffectClass::Spend;
            effect.amount = Money::new(600, CurrencyCode::parse("USD").expect("USD"));
        }
        let verified_digest = parent.effects[0].approval_digest();
        parent.effects[0]
            .approval
            .as_mut()
            .expect("approval")
            .scope_digest = verified_digest.clone();
        parent.effects[0]
            .receipt
            .as_mut()
            .expect("receipt")
            .request_digest = verified_digest;
        let mut cross_currency = parent.effects[0].clone();
        cross_currency.id = EffectId::from("review-eur-verified-cost");
        cross_currency.idempotency_key = "review-eur-verified-cost".into();
        cross_currency.amount = Money::new(200, CurrencyCode::parse("EUR").expect("EUR"));
        let cross_currency_receipt_id = ReceiptId::from("review-eur-receipt");
        cross_currency
            .receipt
            .as_mut()
            .expect("cross-currency receipt")
            .id = cross_currency_receipt_id.clone();
        {
            let verification = cross_currency
                .verification
                .as_mut()
                .expect("cross-currency verification");
            verification.id = VerificationId::from("review-eur-verification");
            verification.receipt_id = cross_currency_receipt_id;
        }
        let cross_currency_digest = cross_currency.approval_digest();
        cross_currency
            .approval
            .as_mut()
            .expect("cross-currency approval")
            .scope_digest = cross_currency_digest.clone();
        cross_currency
            .receipt
            .as_mut()
            .expect("cross-currency receipt")
            .request_digest = cross_currency_digest;
        let mut unresolved = parent.effects[0].clone();
        unresolved.id = EffectId::from("review-unresolved-cost");
        unresolved.idempotency_key = "review-unresolved-cost".into();
        unresolved.amount = Money::new(300, CurrencyCode::parse("USD").expect("USD"));
        unresolved.status = EffectStatus::VerificationRequired;
        unresolved.receipt = None;
        unresolved.verification = None;
        let unresolved_digest = unresolved.approval_digest();
        unresolved
            .approval
            .as_mut()
            .expect("unresolved approval")
            .scope_digest = unresolved_digest;
        parent.effects.extend([cross_currency, unresolved]);
        parent.revision = 4;

        let partner = Partner::create(
            PartnerId::from("review-partner"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            None,
            None,
            "Review partner",
            PartnerSupplyClass::HartevoOptIn,
            ContactPermission::ExplicitOptIn,
            Some("6".repeat(64)),
        )
        .expect("partner");
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        ledger
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "review-order",
                Some(10_000),
            ))
            .expect("order");
        ledger
            .calculate_commission(
                CommissionId::from("review-commission"),
                &OrderId::from("order-1"),
                partner.id.clone(),
                "0.10".parse().expect("rate"),
                "7".repeat(64),
                now() + Duration::minutes(4),
            )
            .expect("commission");
        let (connection, person, link) = confirmed_identity_support();
        let identity = ledger
            .verified_identity_chain_projection(
                std::slice::from_ref(&connection),
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                std::slice::from_ref(&partner),
                &[],
            )
            .expect("identity");
        let observed_at = now() + Duration::minutes(10);
        let kpi = ledger
            .verified_mission_kpi_projection(&parent, &identity, observed_at)
            .expect("KPI");
        let attribution = ledger
            .verified_attribution_projection(&parent, &identity, &[], observed_at)
            .expect("explicit synthesized Unattributed");
        let settlement = ledger
            .verified_settlement_projection(
                &parent,
                &identity,
                std::slice::from_ref(&partner),
                observed_at,
            )
            .expect("outstanding settlement");
        let review = ledger
            .verified_outcome_review_projection(
                &parent,
                &kpi,
                &attribution,
                &settlement,
                observed_at,
            )
            .expect("deterministic outcome review");
        assert_eq!(
            (
                review.measurement_count,
                review.target_met_count,
                review.target_gap_count,
                review.order_count,
                review.attributed_order_count,
                review.unattributed_order_count,
                review.settlement_group_count,
                review.outstanding_settlement_group_count,
                review.verified_effect_count,
                review.pending_effect_count,
                review.unresolved_cost_effect_count,
                review.cross_currency_cost_effect_count,
            ),
            (1, 1, 0, 1, 0, 1, 1, 1, 2, 1, 1, 1)
        );
        assert_eq!(
            (
                review.budget_currency_verified_cost.amount_minor,
                review.budget_remaining.amount_minor,
                review.budget_overrun.amount_minor,
                review.scale_evidence_status,
                review.causal_status,
                review.roi_status,
            ),
            (
                600,
                0,
                100,
                OutcomeReviewGateStatus::Blocked,
                OutcomeReviewCausalStatus::NotClaimed,
                OutcomeReviewRoiStatus::NotCalculated,
            )
        );
        assert_eq!(
            review.caveats,
            BTreeSet::from([
                OutcomeReviewCaveat::UnattributedOrders,
                OutcomeReviewCaveat::OutstandingSettlement,
                OutcomeReviewCaveat::PendingEffect,
                OutcomeReviewCaveat::UnresolvedEffectCost,
                OutcomeReviewCaveat::BudgetExceeded,
                OutcomeReviewCaveat::CrossCurrencyCostWithoutFx,
                OutcomeReviewCaveat::ImplicitLoopForbidden,
            ])
        );
        let usd = &review.economics[&CurrencyCode::parse("USD").expect("USD")];
        assert_eq!(
            (
                usd.gross_revenue.amount_minor,
                usd.net_revenue.amount_minor,
                usd.commission_obligation.amount_minor,
                usd.commission_outstanding.amount_minor,
                usd.verified_effect_outflow.amount_minor,
                usd.unresolved_effect_exposure.amount_minor,
            ),
            (10_000, 10_000, 1_000, 1_000, 600, 300)
        );
        assert_eq!(
            review.economics[&CurrencyCode::parse("EUR").expect("EUR")]
                .verified_effect_outflow
                .amount_minor,
            200
        );
        assert_eq!(
            review,
            ledger
                .verified_outcome_review_projection(
                    &parent,
                    &kpi,
                    &attribution,
                    &settlement,
                    observed_at,
                )
                .expect("deterministic replay")
        );
        assert!(is_sha256(&review.digest().expect("review digest")));

        let mut tampered_contract_digest = kpi.clone();
        tampered_contract_digest.source_contract_digest = "0".repeat(64);
        assert_eq!(
            ledger.verified_outcome_review_projection(
                &parent,
                &tampered_contract_digest,
                &attribution,
                &settlement,
                observed_at,
            ),
            Err(OutcomeLedgerError::OutcomeReviewProjectionMismatch)
        );
        let mut tampered_kpi = kpi;
        tampered_kpi.target_met_count = 0;
        assert_eq!(
            ledger.verified_outcome_review_projection(
                &parent,
                &tampered_kpi,
                &attribution,
                &settlement,
                observed_at,
            ),
            Err(OutcomeLedgerError::OutcomeReviewProjectionMismatch)
        );
        let mut tampered_parent = parent;
        tampered_parent.effects[0].amount.amount_minor = 401;
        assert_eq!(
            ledger.verified_outcome_review_projection(
                &tampered_parent,
                &ledger
                    .verified_mission_kpi_projection(&tampered_parent, &identity, observed_at)
                    .expect("tampered parent KPI remains independently recomputable"),
                &ledger
                    .verified_attribution_projection(&tampered_parent, &identity, &[], observed_at)
                    .expect("tampered parent attribution"),
                &ledger
                    .verified_settlement_projection(
                        &tampered_parent,
                        &identity,
                        std::slice::from_ref(&partner),
                        observed_at,
                    )
                    .expect("tampered parent settlement"),
                observed_at,
            ),
            Err(OutcomeLedgerError::OutcomeReviewEffectStateMismatch)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression proves every action gate, mode boundary, scale gate, and persisted completion binding together"
    )]
    fn outcome_review_decision_is_structured_mode_gated_scale_gated_and_completion_bound() {
        let parent = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-11"),
            ProjectId::from("project-1"),
            "Parent",
            MissionContract::bootstrap(
                "Provide one reviewed business outcome",
                ["decision.evaluate".into()],
                now(),
            ),
            now(),
        )
        .expect("parent");
        let usd = CurrencyCode::parse("USD").expect("USD");
        let review = OutcomeReviewProjection {
            schema_version: OutcomeReviewProjection::SCHEMA_VERSION,
            tenant_id: parent.tenant_id.clone(),
            project_id: parent.project_id.clone(),
            source_mission_id: parent.id.clone(),
            source_mission_revision: parent.revision,
            source_ledger_revision: 1,
            window_started_at: now(),
            outcome_window_ended_at: now() + Duration::minutes(1),
            observed_at: now() + Duration::minutes(2),
            measurement_count: 1,
            target_met_count: 0,
            target_gap_count: 1,
            order_count: 1,
            attributed_order_count: 0,
            unattributed_order_count: 1,
            settlement_group_count: 1,
            paid_or_no_payment_due_group_count: 0,
            outstanding_settlement_group_count: 1,
            verified_effect_count: 0,
            pending_effect_count: 0,
            unresolved_cost_effect_count: 0,
            cross_currency_cost_effect_count: 0,
            budget: Money::new(500, usd.clone()),
            budget_currency_verified_cost: Money::zero(usd.clone()),
            budget_remaining: Money::new(500, usd.clone()),
            budget_overrun: Money::zero(usd.clone()),
            kpi_status: OutcomeReviewGateStatus::Blocked,
            attribution_status: OutcomeReviewGateStatus::Blocked,
            settlement_status: OutcomeReviewGateStatus::Blocked,
            cost_status: OutcomeReviewGateStatus::Satisfied,
            budget_status: OutcomeReviewGateStatus::Satisfied,
            scale_evidence_status: OutcomeReviewGateStatus::Blocked,
            loop_policy: OutcomeReviewLoopPolicy::Forbidden,
            causal_status: OutcomeReviewCausalStatus::NotClaimed,
            roi_status: OutcomeReviewRoiStatus::NotCalculated,
            caveats: BTreeSet::from([
                OutcomeReviewCaveat::KpiTargetGap,
                OutcomeReviewCaveat::UnattributedOrders,
                OutcomeReviewCaveat::OutstandingSettlement,
                OutcomeReviewCaveat::ImplicitLoopForbidden,
            ]),
            economics: BTreeMap::new(),
            source_contract_digest: "b".repeat(64),
            normalization_digest: "c".repeat(64),
            identity_chain_digest: "d".repeat(64),
            kpi_projection_digest: "e".repeat(64),
            attribution_projection_digest: "f".repeat(64),
            settlement_projection_digest: "1".repeat(64),
            effect_cost_source_digest: "2".repeat(64),
        };
        let mission = vm11_decision_mission(&review, OperatingMode::BuildOnce);
        assert_eq!(
            review.decision_gate(OutcomeDecision::Stop),
            OutcomeReviewActionGate {
                action: OutcomeDecision::Stop,
                next_contract_intent: OutcomeReviewNextContractIntent::ValidTerminal,
                status: OutcomeReviewDecisionGateStatus::Available,
            }
        );
        assert_eq!(
            review.decision_gate(OutcomeDecision::Continue).status,
            OutcomeReviewDecisionGateStatus::BlockedLoopPolicy
        );
        assert_eq!(
            review.decision_gate(OutcomeDecision::Scale).status,
            OutcomeReviewDecisionGateStatus::BlockedLoopPolicy
        );
        assert_eq!(
            review.decision_gate(OutcomeDecision::Test).status,
            OutcomeReviewDecisionGateStatus::Available
        );
        let review_checkpoint = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "outcome_review")
            })
            .expect("review checkpoint");
        let review_completion_digest = review_checkpoint
            .completion
            .as_ref()
            .expect("review completion")
            .evidence_digest
            .clone();
        let decide = |mission: &Mission, review: &OutcomeReviewProjection, action| {
            OutcomeReviewDecision::decide(
                mission,
                review,
                review_checkpoint.revision,
                review_completion_digest.clone(),
                action,
                ActorId::from("user-reviewer"),
                MissionConversationId::from("vm11-decision-conversation"),
                2,
                MissionConversationMessageId::from("vm11-decision-message"),
                2,
                "3".repeat(64),
                "4".repeat(64),
                review.observed_at + Duration::minutes(1),
            )
        };
        let stop = decide(&mission, &review, OutcomeDecision::Stop).expect("explicit Stop");
        assert_eq!(
            stop.next_contract_intent,
            OutcomeReviewNextContractIntent::ValidTerminal
        );
        assert_eq!(
            decide(&mission, &review, OutcomeDecision::Continue),
            Err(OutcomeLedgerError::OutcomeReviewDecisionActionForbidden)
        );
        assert_eq!(
            decide(&mission, &review, OutcomeDecision::Scale),
            Err(OutcomeLedgerError::OutcomeReviewDecisionScaleBlocked)
        );
        assert_eq!(
            decide(&mission, &review, OutcomeDecision::Test)
                .expect("one-off can explicitly request a new experiment")
                .next_contract_intent,
            OutcomeReviewNextContractIntent::TestWithNewExperiment
        );

        let mut eligible_review = review.clone();
        eligible_review.loop_policy = OutcomeReviewLoopPolicy::Eligible;
        eligible_review
            .caveats
            .remove(&OutcomeReviewCaveat::ImplicitLoopForbidden);
        assert_eq!(
            eligible_review
                .decision_gate(OutcomeDecision::Continue)
                .status,
            OutcomeReviewDecisionGateStatus::Available
        );
        assert_eq!(
            eligible_review.decision_gate(OutcomeDecision::Scale).status,
            OutcomeReviewDecisionGateStatus::BlockedScaleEvidence
        );
        let eligible_mission =
            vm11_decision_mission(&eligible_review, OperatingMode::ContinuousOperator);
        let eligible_review_checkpoint = eligible_mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "outcome_review")
            })
            .expect("eligible review checkpoint");
        let continued = OutcomeReviewDecision::decide(
            &eligible_mission,
            &eligible_review,
            eligible_review_checkpoint.revision,
            eligible_review_checkpoint
                .completion
                .as_ref()
                .expect("eligible review completion")
                .evidence_digest
                .clone(),
            OutcomeDecision::Continue,
            ActorId::from("user-reviewer"),
            MissionConversationId::from("vm11-decision-conversation"),
            2,
            MissionConversationMessageId::from("vm11-decision-message"),
            2,
            "5".repeat(64),
            "6".repeat(64),
            eligible_review.observed_at + Duration::minutes(1),
        )
        .expect("continuous Continue");
        assert_eq!(
            continued.next_contract_intent,
            OutcomeReviewNextContractIntent::ContinueCurrentContract
        );
        assert_eq!(
            OutcomeReviewDecision::decide(
                &eligible_mission,
                &eligible_review,
                eligible_review_checkpoint.revision,
                eligible_review_checkpoint
                    .completion
                    .as_ref()
                    .expect("eligible review completion")
                    .evidence_digest
                    .clone(),
                OutcomeDecision::Scale,
                ActorId::from("user-reviewer"),
                MissionConversationId::from("vm11-decision-conversation"),
                2,
                MissionConversationMessageId::from("vm11-decision-message"),
                2,
                "5".repeat(64),
                "7".repeat(64),
                eligible_review.observed_at + Duration::minutes(1),
            ),
            Err(OutcomeLedgerError::OutcomeReviewDecisionScaleBlocked)
        );

        let mut completed = mission;
        completed
            .begin_checkpoint_verification("continue_stop_scale_test", stop.decided_at)
            .expect("begin structured decision verification");
        completed
            .complete_checkpoint(
                "continue_stop_scale_test",
                MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from([
                        "goal".into(),
                        "decision".into(),
                        "operating_state".into(),
                        "outcome".into(),
                    ]),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: stop.digest().expect("decision digest"),
                    verified_at: stop.decided_at,
                },
            )
            .expect("complete structured decision");
        stop.validate_persisted(&completed, &review)
            .expect("persisted decision remains completion-bound");
        let mut swapped = stop;
        swapped.action = OutcomeDecision::Test;
        swapped.next_contract_intent = OutcomeReviewNextContractIntent::TestWithNewExperiment;
        assert_eq!(
            swapped.validate_persisted(&completed, &review),
            Err(OutcomeLedgerError::OutcomeReviewDecisionSourceMismatch)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the official-network regression keeps authoritative accrual/reversal, out-of-order callbacks, refund history, payout readback, and duplicate business identity rejection visible together"
    )]
    fn settlement_oracle_preserves_official_network_authority_and_order_independence() {
        let parent = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-11"),
            ProjectId::from("project-1"),
            "Official network Mission",
            MissionContract::bootstrap(
                "Reconcile network-owned settlement facts",
                ["settlement.compute".into()],
                now(),
            ),
            now(),
        )
        .expect("parent Mission");
        let partner = Partner::create(
            PartnerId::from("awin-partner"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            None,
            None,
            "Awin network partner",
            PartnerSupplyClass::OfficialAuthorizedNetwork,
            ContactPermission::NetworkAuthorized,
            Some("5".repeat(64)),
        )
        .expect("network partner");
        let (commerce_connection, person, link) = confirmed_identity_support();
        let mut network_connection = Connection::register(
            ConnectionId::from("awin-connection"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "awin",
            AccountId::from("awin-account"),
            "awin-account-external",
            ["transactions.read".into()],
            now(),
        )
        .expect("network connection");
        network_connection.begin_probe(now()).expect("begin probe");
        network_connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "awin-account-external".into(),
                    granted_scopes: BTreeSet::from(["transactions.read".into()]),
                    probed_at: now(),
                    valid_until: now() + Duration::hours(1),
                    credential_expires_at: now() + Duration::hours(2),
                    evidence_digest: "6".repeat(64),
                },
                now(),
            )
            .expect("network probe");

        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        ledger
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "network-order",
                Some(10_000),
            ))
            .expect("order");
        let mut refund = event(
            OutcomeEventKind::RefundIssued,
            "network-refund",
            Some(2_500),
        );
        refund.identity_link_id = None;
        refund.refund_id = Some(RefundId::from("network-refund-1"));
        refund.occurred_at = now() + Duration::minutes(1);
        refund.received_at = now() + Duration::minutes(2);
        refund
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = refund.received_at;
        ledger.ingest(refund).expect("refund");

        let mut reversal = event(
            OutcomeEventKind::CommissionReversed,
            "network-reversal",
            Some(375),
        );
        reversal.provider = "awin".into();
        reversal.connection_id = Some(network_connection.id().clone());
        reversal.account_id = Some(AccountId::from("awin-account"));
        reversal.identity_link_id = None;
        reversal.commission_id = Some(CommissionId::from("network-commission-1"));
        reversal.partner_id = Some(partner.id.clone());
        reversal.occurred_at = now() + Duration::minutes(3);
        reversal.received_at = now() + Duration::minutes(4);
        reversal
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = reversal.received_at;
        ledger.ingest(reversal).expect("reversal arrives first");
        let mut accrual = event(
            OutcomeEventKind::CommissionAccrued,
            "network-accrual",
            Some(1_500),
        );
        accrual.provider = "awin".into();
        accrual.connection_id = Some(network_connection.id().clone());
        accrual.account_id = Some(AccountId::from("awin-account"));
        accrual.identity_link_id = None;
        accrual.commission_id = Some(CommissionId::from("network-commission-1"));
        accrual.partner_id = Some(partner.id.clone());
        accrual.occurred_at = now() + Duration::minutes(2);
        accrual.received_at = now() + Duration::minutes(5);
        accrual
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = accrual.received_at;
        ledger.ingest(accrual).expect("accrual arrives later");
        let mut payout = event(
            OutcomeEventKind::PayoutCompleted,
            "network-payout",
            Some(1_125),
        );
        payout.provider = "awin".into();
        payout.connection_id = Some(network_connection.id().clone());
        payout.account_id = Some(AccountId::from("awin-account"));
        payout.identity_link_id = None;
        payout.order_id = None;
        payout.payout_id = Some(PayoutId::from("network-payout-1"));
        payout.partner_id = Some(partner.id.clone());
        payout.occurred_at = now() + Duration::minutes(6);
        payout.received_at = now() + Duration::minutes(7);
        payout
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = payout.received_at;
        ledger.ingest(payout).expect("network payout");

        let identity_chain = ledger
            .verified_identity_chain_projection(
                &[commerce_connection.clone(), network_connection.snapshot()],
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                std::slice::from_ref(&partner),
                &[],
            )
            .expect("network identity chain");
        let projection = ledger
            .verified_settlement_projection(
                &parent,
                &identity_chain,
                std::slice::from_ref(&partner),
                now() + Duration::minutes(8),
            )
            .expect("network settlement");
        assert_eq!(
            (
                projection.network_commission_event_count,
                projection.official_network_group_count,
                projection.paid_group_count,
                projection.settlements[0].source_commission_count,
                projection.settlements[0].commission_amount.amount_minor,
                projection.settlements[0]
                    .payout_completed_amount
                    .amount_minor,
                projection.settlements[0].basis,
            ),
            (
                2,
                1,
                1,
                1,
                1_125,
                1_125,
                SettlementCommissionBasis::OfficialNetworkFacts,
            )
        );

        let mut duplicated = ledger;
        let mut duplicate_accrual = event(
            OutcomeEventKind::CommissionAccrued,
            "network-duplicate-accrual",
            Some(1_500),
        );
        duplicate_accrual.provider = "awin".into();
        duplicate_accrual.connection_id = Some(network_connection.id().clone());
        duplicate_accrual.account_id = Some(AccountId::from("awin-account"));
        duplicate_accrual.identity_link_id = None;
        duplicate_accrual.commission_id = Some(CommissionId::from("network-commission-1"));
        duplicate_accrual.partner_id = Some(partner.id.clone());
        duplicate_accrual.occurred_at = now() + Duration::minutes(2);
        duplicate_accrual.received_at = now() + Duration::minutes(9);
        duplicate_accrual
            .source_verification
            .as_mut()
            .expect("verification")
            .verified_at = duplicate_accrual.received_at;
        duplicated
            .ingest(duplicate_accrual)
            .expect("distinct callback enters immutable ledger");
        let duplicate_identity = duplicated
            .verified_identity_chain_projection(
                &[commerce_connection, network_connection.snapshot()],
                std::slice::from_ref(&link),
                std::slice::from_ref(&person),
                &[],
                std::slice::from_ref(&partner),
                &[],
            )
            .expect("duplicate identity closure");
        assert_eq!(
            duplicated.verified_settlement_projection(
                &parent,
                &duplicate_identity,
                std::slice::from_ref(&partner),
                now() + Duration::minutes(10),
            ),
            Err(OutcomeLedgerError::SettlementCommissionAuthorityMismatch)
        );
    }

    #[test]
    fn refund_is_an_independent_reverse_event_and_never_rewrites_order() {
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        ledger
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "order-event",
                Some(10_000),
            ))
            .expect("order");
        let original = ledger.orders[0].clone();
        let mut refund = event(OutcomeEventKind::RefundIssued, "refund-event", Some(2_500));
        refund.refund_id = Some(RefundId::from("refund-1"));
        ledger.ingest(refund).expect("refund");

        assert_eq!(ledger.orders[0], original);
        assert_eq!(
            ledger
                .net_order_amount(&OrderId::from("order-1"))
                .expect("net")
                .amount_minor,
            7_500
        );
        assert_eq!(ledger.events.len(), 2);
    }

    #[test]
    fn refund_recalculates_commission_from_minor_units_and_decimal_rate() {
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        ledger
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "order-event",
                Some(10_000),
            ))
            .expect("order");
        let mut refund = event(OutcomeEventKind::RefundIssued, "refund-event", Some(2_500));
        refund.refund_id = Some(RefundId::from("refund-1"));
        ledger.ingest(refund).expect("refund");
        let commission = ledger
            .calculate_commission(
                CommissionId::from("commission-1"),
                &OrderId::from("order-1"),
                PartnerId::from("partner-1"),
                "0.15".parse().expect("decimal"),
                "c".repeat(64),
                now() + Duration::days(30),
            )
            .expect("commission");
        assert_eq!(commission.eligible_net_amount.amount_minor, 7_500);
        assert_eq!(commission.commission_amount.amount_minor, 1_125);
        assert_eq!(commission.status, CommissionStatus::Current);
    }

    #[test]
    fn late_refund_requires_a_new_commission_revision() {
        let mut ledger =
            OutcomeLedger::new(TenantId::from("tenant-1"), ProjectId::from("project-1"))
                .expect("ledger");
        ledger
            .ingest(event(
                OutcomeEventKind::OrderPlaced,
                "order-event",
                Some(10_000),
            ))
            .expect("order");
        ledger
            .calculate_commission(
                CommissionId::from("commission-1"),
                &OrderId::from("order-1"),
                PartnerId::from("partner-1"),
                "0.15".parse().expect("decimal"),
                "c".repeat(64),
                now() + Duration::days(1),
            )
            .expect("initial commission");

        let mut refund = event(OutcomeEventKind::RefundIssued, "refund-event", Some(2_500));
        refund.refund_id = Some(RefundId::from("refund-1"));
        refund.occurred_at = now() + Duration::days(2);
        refund.received_at = now() + Duration::days(3);
        refund
            .source_verification
            .as_mut()
            .expect("verified source")
            .verified_at = refund.received_at;
        ledger.ingest(refund).expect("late refund");
        assert_eq!(ledger.commissions_requiring_recalculation().len(), 1);

        let recalculated = ledger
            .calculate_commission(
                CommissionId::from("commission-2"),
                &OrderId::from("order-1"),
                PartnerId::from("partner-1"),
                "0.15".parse().expect("decimal"),
                "c".repeat(64),
                now() + Duration::days(4),
            )
            .expect("recalculated commission");
        assert_eq!(recalculated.commission_amount.amount_minor, 1_125);
        assert_eq!(
            recalculated.supersedes,
            Some(CommissionId::from("commission-1"))
        );
        assert_eq!(ledger.commissions[0].status, CommissionStatus::Superseded);
        assert!(ledger.commissions_requiring_recalculation().is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn arbitrary_outcome_refund_and_commission_sequences_preserve_money_and_history(
            order_amount in 1_i64..100_000,
            actions in prop::collection::vec((0_u8..5, 1_i64..150_000), 1..64),
        ) {
            let mut ledger = OutcomeLedger::new(
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
            ).expect("ledger");
            let mut order_event = event(
                OutcomeEventKind::OrderPlaced,
                "model-order-event",
                Some(order_amount),
            );
            order_event.order_id = Some(OrderId::from("model-order"));
            ledger.ingest(order_event).expect("order");
            let original_order = ledger.orders[0].clone();
            let mut expected_net = order_amount;
            let mut cursor = now() + Duration::minutes(2);

            for (index, (action, magnitude)) in actions.into_iter().enumerate() {
                cursor += Duration::minutes(1);
                let before = ledger.clone();
                let result = match action {
                    0 => {
                        let mut refund = event(
                            OutcomeEventKind::RefundIssued,
                            &format!("model-refund-event-{index}"),
                            Some(magnitude),
                        );
                        refund.order_id = Some(OrderId::from("model-order"));
                        refund.refund_id = Some(RefundId::from_stable(format!(
                            "model-refund-{index}"
                        )));
                        refund.occurred_at = cursor - Duration::seconds(1);
                        refund.received_at = cursor;
                        refund
                            .source_verification
                            .as_mut()
                            .expect("verification")
                            .verified_at = cursor;
                        let result = ledger.ingest(refund);
                        if result.is_ok() {
                            expected_net -= magnitude;
                        }
                        result
                    }
                    1 => ledger.ingest(ledger.events[0].clone()),
                    2 => {
                        let mut refund = event(
                            OutcomeEventKind::RefundIssued,
                            &format!("model-wrong-currency-{index}"),
                            Some(magnitude),
                        );
                        refund.order_id = Some(OrderId::from("model-order"));
                        refund.refund_id = Some(RefundId::from_stable(format!(
                            "model-wrong-currency-refund-{index}"
                        )));
                        refund.amount = Some(Money::new(
                            magnitude,
                            CurrencyCode::parse("EUR").expect("EUR"),
                        ));
                        refund.occurred_at = cursor - Duration::seconds(1);
                        refund.received_at = cursor;
                        refund
                            .source_verification
                            .as_mut()
                            .expect("verification")
                            .verified_at = cursor;
                        ledger.ingest(refund)
                    }
                    3 => ledger
                        .calculate_commission(
                            CommissionId::from_stable(format!("model-commission-{index}")),
                            &OrderId::from("model-order"),
                            PartnerId::from("partner-model"),
                            Decimal::new((magnitude % 100) + 1, 2),
                            "c".repeat(64),
                            cursor,
                        )
                        .map(|_| ()),
                    _ => {
                        let mut forged = event(
                            OutcomeEventKind::OrderPlaced,
                            &format!("model-forged-order-{index}"),
                            Some(magnitude),
                        );
                        forged.order_id = Some(OrderId::from_stable(format!(
                            "model-forged-order-id-{index}"
                        )));
                        forged
                            .source_verification
                            .as_mut()
                            .expect("verification")
                            .independent = false;
                        ledger.ingest(forged)
                    }
                };

                if result.is_ok() {
                    prop_assert_eq!(ledger.revision, before.revision + 1);
                    prop_assert!(ledger.events.starts_with(&before.events));
                } else {
                    prop_assert_eq!(ledger.clone(), before);
                }
                prop_assert!(expected_net >= 0);
                prop_assert_eq!(ledger.orders[0].clone(), original_order.clone());
                prop_assert_eq!(
                    ledger
                        .net_order_amount(&OrderId::from("model-order"))
                        .expect("net")
                        .amount_minor,
                    expected_net,
                );
                prop_assert!(ledger.validate().is_ok());
                let active_commissions = ledger
                    .commissions
                    .iter()
                    .filter(|commission| commission.status != CommissionStatus::Superseded)
                    .count();
                prop_assert!(active_commissions <= 1);
                let expected_revision = 1_u64
                    + u64::try_from(ledger.events.len()).expect("bounded")
                    + u64::try_from(ledger.attributions.len()).expect("bounded")
                    + u64::try_from(ledger.commissions.len()).expect("bounded");
                prop_assert_eq!(ledger.revision, expected_revision);
            }
        }
    }
}

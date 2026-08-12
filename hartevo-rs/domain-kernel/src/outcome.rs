use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use rust_decimal::RoundingStrategy;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AccountId, AttributionId, CampaignId, CommissionId, Company, CompanyId, ConnectionId,
    ConnectionSnapshot, IdentityLink, IdentityLinkId, IdentityLinkStatus, IdentitySubject,
    MissionId, Money, Opportunity, OpportunityId, OrderId, OutcomeEventId, Partner, PartnerId,
    PayoutId, Person, PersonId, ProjectId, RefundId, TenantId,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeEventKind {
    LeadQualified,
    MeetingBooked,
    OpportunityStageChanged,
    OrderPlaced,
    RefundIssued,
    CommissionAccrued,
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
            OutcomeEventKind::CommissionAccrued => {
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionModel {
    VerifiedIdentity,
    LastNonDirect,
    FirstTouch,
    Unattributed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Touchpoint {
    pub mission_id: MissionId,
    pub source: String,
    pub provider_identity_digest: Option<String>,
    pub verified_link_or_coupon_digest: Option<String>,
    pub occurred_at: DateTime<Utc>,
    pub evidence_digest: String,
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
        if self.tenant_id != *tenant_id
            || self.project_id != *project_id
            || self.order_id != order.id
            || self.window_started_at >= self.window_ended_at
            || order.occurred_at < self.window_started_at
            || order.occurred_at > self.window_ended_at
            || self.recorded_at < order.occurred_at
            || self.confidence < Decimal::ZERO
            || self.confidence > Decimal::ONE
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
            _ => validate_touchpoint(
                self.touchpoint
                    .as_ref()
                    .ok_or(OutcomeLedgerError::InvalidAttribution)?,
                order,
                &self.model,
                self.window_started_at,
                self.window_ended_at,
            )?,
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
    pub source_support_digest: String,
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
        hash_projection_field(&mut digest, &self.source_support_digest);
        format!("{:x}", digest.finalize())
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
            attribution.validate(&self.tenant_id, &self.project_id, order)?;
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
                OutcomeEventKind::RefundIssued | OutcomeEventKind::CommissionAccrued => {
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
                        && (event.kind != OutcomeEventKind::CommissionAccrued
                            || event.partner_id.is_some())
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
            source_support_digest,
        })
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
    model: &AttributionModel,
    window_started_at: DateTime<Utc>,
    window_ended_at: DateTime<Utc>,
) -> Result<(), OutcomeLedgerError> {
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
    {
        return Err(OutcomeLedgerError::InvalidAttribution);
    }
    if *model == AttributionModel::VerifiedIdentity
        && touchpoint.provider_identity_digest.is_none()
        && touchpoint.verified_link_or_coupon_digest.is_none()
    {
        return Err(OutcomeLedgerError::InvalidAttribution);
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
        ActorId, Connection, ConnectionProbe, ContactPermission, CurrencyCode, ExternalIdentity,
        IdentitySubject, PartnerSupplyClass, ProbeOutcome,
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

//! Cross-provider observation identity, attribution, and outcome ingestion.
//!
//! This module is deliberately an append-only, content-free kernel. Provider
//! adapters may supply observations through [`ConnectorObservationSource`],
//! but an observation is never promoted to a verified outcome merely because
//! a connector returned it. Attribution is an explicit correlation view; the
//! kernel never emits a causal claim.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use rust_decimal::RoundingStrategy;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{CurrencyCode, FxQuote, MissionId, Money, ProjectId, TenantId};

pub const ATTRIBUTION_SPINE_SCHEMA_VERSION: &str = "hartevo-attribution-spine/v1";
pub const ATTRIBUTION_SPINE_EVENT_TYPE: &str = "attribution-spine.observation-batch/v1";

macro_rules! spine_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(uuid::Uuid::now_v7().to_string())
            }

            pub fn from_stable(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::from_stable(value)
            }
        }
    };
}

spine_id!(SourceEventId);
spine_id!(OutcomeCandidateId);
spine_id!(VerifiedOutcomeId);

/// A provider-native event identity. The account is part of the identity so
/// the same provider event id in two seller/ad accounts cannot collide.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderEventIdentity {
    pub provider: String,
    pub account_id: String,
    pub event_namespace: String,
    pub external_event_id: String,
}

impl ProviderEventIdentity {
    pub fn new(
        provider: impl Into<String>,
        account_id: impl Into<String>,
        external_event_id: impl Into<String>,
    ) -> Result<Self, AttributionError> {
        let identity = Self {
            provider: provider.into(),
            account_id: account_id.into(),
            event_namespace: "provider".into(),
            external_event_id: external_event_id.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), AttributionError> {
        if self.provider.trim().is_empty()
            || self.account_id.trim().is_empty()
            || self.event_namespace.trim().is_empty()
            || self.external_event_id.trim().is_empty()
        {
            return Err(AttributionError::InvalidProviderIdentity);
        }
        Ok(())
    }

    pub fn dedupe_digest(&self, _kind: SourceEventKind) -> String {
        digest_parts(&[
            "hartevo-provider-event-identity/v1",
            &self.provider,
            &self.account_id,
            &self.event_namespace,
            &self.external_event_id,
        ])
    }
}

/// Typed entities used by the observation graph. A link is never inferred
/// from a shared string; it must carry the provider account and entity kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceEntityKind {
    Account,
    Campaign,
    Content,
    Click,
    Session,
    Order,
    Refund,
    Conversion,
    Commission,
    Payout,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderEntityRef {
    pub kind: SourceEntityKind,
    pub provider: String,
    pub account_id: String,
    pub external_id: String,
}

impl ProviderEntityRef {
    pub fn new(
        kind: SourceEntityKind,
        provider: impl Into<String>,
        account_id: impl Into<String>,
        external_id: impl Into<String>,
    ) -> Result<Self, AttributionError> {
        let value = Self {
            kind,
            provider: provider.into(),
            account_id: account_id.into(),
            external_id: external_id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), AttributionError> {
        if self.provider.trim().is_empty()
            || self.account_id.trim().is_empty()
            || self.external_id.trim().is_empty()
        {
            return Err(AttributionError::InvalidEntityLink);
        }
        Ok(())
    }
}

/// The complete graph is explicit. In particular, account is mandatory and
/// all other joins remain optional, so missing identity becomes Unattributed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceEventLinks {
    pub account: ProviderEntityRef,
    pub campaign: Option<ProviderEntityRef>,
    pub content: Option<ProviderEntityRef>,
    pub click: Option<ProviderEntityRef>,
    pub session: Option<ProviderEntityRef>,
    pub order: Option<ProviderEntityRef>,
    pub refund: Option<ProviderEntityRef>,
    pub conversion: Option<ProviderEntityRef>,
    pub commission: Option<ProviderEntityRef>,
    pub payout: Option<ProviderEntityRef>,
}

impl SourceEventLinks {
    pub fn new(account: ProviderEntityRef) -> Result<Self, AttributionError> {
        let links = Self {
            account,
            campaign: None,
            content: None,
            click: None,
            session: None,
            order: None,
            refund: None,
            conversion: None,
            commission: None,
            payout: None,
        };
        links.validate()?;
        Ok(links)
    }

    pub fn validate(&self) -> Result<(), AttributionError> {
        self.account.validate()?;
        if self.account.kind != SourceEntityKind::Account {
            return Err(AttributionError::InvalidEntityLink);
        }
        let refs = [
            (self.campaign.as_ref(), SourceEntityKind::Campaign),
            (self.content.as_ref(), SourceEntityKind::Content),
            (self.click.as_ref(), SourceEntityKind::Click),
            (self.session.as_ref(), SourceEntityKind::Session),
            (self.order.as_ref(), SourceEntityKind::Order),
            (self.refund.as_ref(), SourceEntityKind::Refund),
            (self.conversion.as_ref(), SourceEntityKind::Conversion),
            (self.commission.as_ref(), SourceEntityKind::Commission),
            (self.payout.as_ref(), SourceEntityKind::Payout),
        ];
        for (entity, expected_kind) in refs {
            if let Some(entity) = entity {
                if entity.kind != expected_kind {
                    return Err(AttributionError::InvalidEntityLink);
                }
                entity.validate()?;
            }
        }
        Ok(())
    }

    fn values(&self) -> [&Option<ProviderEntityRef>; 9] {
        [
            &self.campaign,
            &self.content,
            &self.click,
            &self.session,
            &self.order,
            &self.refund,
            &self.conversion,
            &self.commission,
            &self.payout,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceEventKind {
    Campaign,
    Content,
    Impression,
    Click,
    Session,
    Conversion,
    Order,
    Refund,
    Commission,
    Payout,
}

impl SourceEventKind {
    const fn outcome_kind(self) -> Option<OutcomeKind> {
        match self {
            Self::Conversion => Some(OutcomeKind::Conversion),
            Self::Order => Some(OutcomeKind::Order),
            Self::Refund => Some(OutcomeKind::Refund),
            Self::Commission => Some(OutcomeKind::Commission),
            Self::Payout => Some(OutcomeKind::Payout),
            Self::Campaign | Self::Content | Self::Impression | Self::Click | Self::Session => None,
        }
    }

    const fn is_touchpoint(self) -> bool {
        matches!(
            self,
            Self::Impression | Self::Click | Self::Session | Self::Campaign | Self::Content
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Conversion,
    Order,
    Refund,
    Commission,
    Payout,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOrigin {
    FirstParty,
    PartnerNetwork,
    BrowserSnapshot,
    Estimate,
    Fixture,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservationProvenance {
    pub origin: ObservationOrigin,
    pub request_digest: String,
    pub source_uri: Option<String>,
    pub quota_units: Option<u64>,
    pub cost: Option<Money>,
    pub fresh_until: Option<DateTime<Utc>>,
    pub captured_at: DateTime<Utc>,
}

impl ObservationProvenance {
    pub fn new(
        origin: ObservationOrigin,
        request_digest: impl Into<String>,
        captured_at: DateTime<Utc>,
    ) -> Result<Self, AttributionError> {
        let value = Self {
            origin,
            request_digest: request_digest.into(),
            source_uri: None,
            quota_units: None,
            cost: None,
            fresh_until: None,
            captured_at,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), AttributionError> {
        if !is_sha256(&self.request_digest) {
            return Err(AttributionError::InvalidProvenance);
        }
        if self
            .source_uri
            .as_ref()
            .is_some_and(|uri| uri.trim().is_empty())
        {
            return Err(AttributionError::InvalidProvenance);
        }
        if self
            .cost
            .as_ref()
            .is_some_and(|money| money.amount_minor < 0)
        {
            return Err(AttributionError::InvalidProvenance);
        }
        if self
            .fresh_until
            .is_some_and(|fresh_until| fresh_until < self.captured_at)
        {
            return Err(AttributionError::InvalidProvenance);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrectionKind {
    Original,
    Correction,
    Reversal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrectionLineage {
    pub kind: CorrectionKind,
    pub root_event_id: SourceEventId,
    pub supersedes: Option<SourceEventId>,
    pub reason: Option<String>,
}

impl CorrectionLineage {
    pub fn original(event_id: SourceEventId) -> Self {
        Self {
            kind: CorrectionKind::Original,
            root_event_id: event_id,
            supersedes: None,
            reason: None,
        }
    }

    fn validate(&self, event_id: &SourceEventId) -> Result<(), AttributionError> {
        if self.root_event_id.as_str().trim().is_empty() {
            return Err(AttributionError::InvalidCorrectionLineage);
        }
        match self.kind {
            CorrectionKind::Original => {
                if self.root_event_id != *event_id
                    || self.supersedes.is_some()
                    || self.reason.is_some()
                {
                    return Err(AttributionError::InvalidCorrectionLineage);
                }
            }
            CorrectionKind::Correction | CorrectionKind::Reversal => {
                if self.supersedes.is_none()
                    || self
                        .reason
                        .as_ref()
                        .is_none_or(|reason| reason.trim().is_empty())
                    || self.root_event_id == *event_id
                {
                    return Err(AttributionError::InvalidCorrectionLineage);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceEvent {
    pub id: SourceEventId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: Option<MissionId>,
    pub identity: ProviderEventIdentity,
    pub kind: SourceEventKind,
    pub links: SourceEventLinks,
    pub provider_occurred_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub ingested_at: DateTime<Utc>,
    pub amount: Option<Money>,
    pub fx_quote: Option<FxQuote>,
    pub provenance: ObservationProvenance,
    pub lineage: CorrectionLineage,
    pub payload_digest: String,
}

impl SourceEvent {
    pub fn validate(&self) -> Result<(), AttributionError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.provider_occurred_at > self.observed_at
            || self.observed_at > self.ingested_at
            || !is_sha256(&self.payload_digest)
        {
            return Err(AttributionError::InvalidSourceEvent);
        }
        self.identity.validate()?;
        self.links.validate()?;
        let required_link = match self.kind {
            SourceEventKind::Campaign => self.links.campaign.as_ref(),
            SourceEventKind::Content => self.links.content.as_ref(),
            SourceEventKind::Click => self.links.click.as_ref(),
            SourceEventKind::Session => self.links.session.as_ref(),
            SourceEventKind::Conversion => self.links.conversion.as_ref(),
            SourceEventKind::Order => self.links.order.as_ref(),
            SourceEventKind::Refund => self.links.refund.as_ref(),
            SourceEventKind::Commission => self.links.commission.as_ref(),
            SourceEventKind::Payout => self.links.payout.as_ref(),
            SourceEventKind::Impression => None,
        };
        if !matches!(self.kind, SourceEventKind::Impression) && required_link.is_none() {
            return Err(AttributionError::InvalidEntityLink);
        }
        if self.links.account.provider != self.identity.provider
            || self.links.account.account_id != self.identity.account_id
            || self.links.account.external_id != self.identity.account_id
        {
            return Err(AttributionError::InvalidEntityLink);
        }
        for entity in self
            .links
            .values()
            .iter()
            .filter_map(|value| value.as_ref())
        {
            if entity.provider != self.identity.provider
                || entity.account_id != self.identity.account_id
            {
                return Err(AttributionError::UnsupportedIdentityJoin);
            }
        }
        self.provenance.validate()?;
        if self.provenance.captured_at > self.ingested_at {
            return Err(AttributionError::InvalidProvenance);
        }
        self.lineage.validate(&self.id)?;
        if self
            .amount
            .as_ref()
            .is_some_and(|amount| amount.amount_minor < 0)
        {
            return Err(AttributionError::InvalidMoney);
        }
        if self.kind.outcome_kind().is_some_and(|_| {
            self.amount
                .as_ref()
                .is_none_or(|amount| !amount.is_positive())
        }) {
            return Err(AttributionError::OutcomeAmountRequired);
        }
        if let Some(quote) = &self.fx_quote {
            let amount = self
                .amount
                .as_ref()
                .ok_or(AttributionError::FxWithoutAmount)?;
            if quote.base != amount.currency || quote.observed_at > self.observed_at {
                return Err(AttributionError::InvalidFxQuote);
            }
        }
        Ok(())
    }

    pub fn dedupe_digest(&self) -> String {
        self.identity.dedupe_digest(self.kind)
    }

    pub fn canonical_digest(&self) -> Result<String, AttributionError> {
        canonical_digest(self)
    }

    pub fn outcome_candidate(&self) -> Result<OutcomeCandidate, AttributionError> {
        let kind = self
            .kind
            .outcome_kind()
            .ok_or(AttributionError::NotAnOutcomeEvent)?;
        self.validate()?;
        Ok(OutcomeCandidate {
            id: OutcomeCandidateId::from_stable(format!("candidate:{}", self.id)),
            source_event_id: self.id.clone(),
            kind,
            amount: self
                .amount
                .clone()
                .ok_or(AttributionError::OutcomeAmountRequired)?,
            provider: self.identity.provider.clone(),
            observed_at: self.observed_at,
            source_event_digest: self.canonical_digest()?,
            provenance: self.provenance.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeCandidate {
    pub id: OutcomeCandidateId,
    pub source_event_id: SourceEventId,
    pub kind: OutcomeKind,
    pub amount: Money,
    pub provider: String,
    pub observed_at: DateTime<Utc>,
    pub source_event_digest: String,
    pub provenance: ObservationProvenance,
}

impl OutcomeCandidate {
    fn validate(&self, event: &SourceEvent) -> Result<(), AttributionError> {
        if self.id.as_str().trim().is_empty()
            || self.source_event_id != event.id
            || self.provider != event.identity.provider
            || self.observed_at != event.observed_at
            || self.amount
                != event
                    .amount
                    .clone()
                    .ok_or(AttributionError::OutcomeAmountRequired)?
            || self.kind
                != event
                    .kind
                    .outcome_kind()
                    .ok_or(AttributionError::NotAnOutcomeEvent)?
            || self.source_event_digest != event.canonical_digest()?
        {
            return Err(AttributionError::CandidateSourceMismatch);
        }
        self.provenance.validate()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    SignedWebhook,
    IndependentReadback,
    HumanConfirmed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeVerification {
    pub method: VerificationMethod,
    pub verifier: String,
    pub independent: bool,
    pub verified_at: DateTime<Utc>,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedOutcome {
    pub id: VerifiedOutcomeId,
    pub candidate_id: OutcomeCandidateId,
    pub source_event_id: SourceEventId,
    pub candidate_digest: String,
    pub verification: OutcomeVerification,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionWindow {
    pub version: u32,
    pub click_lookback_seconds: u64,
    pub view_lookback_seconds: u64,
    pub effective_at: DateTime<Utc>,
}

impl AttributionWindow {
    pub fn validate(&self) -> Result<(), AttributionError> {
        if self.version == 0 {
            return Err(AttributionError::InvalidAttributionWindow);
        }
        Ok(())
    }

    fn max_age(&self, kind: SourceEventKind) -> Duration {
        if matches!(kind, SourceEventKind::Click) {
            Duration::seconds(i64::try_from(self.click_lookback_seconds).unwrap_or(i64::MAX))
        } else {
            Duration::seconds(i64::try_from(self.view_lookback_seconds).unwrap_or(i64::MAX))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCursor {
    pub provider: String,
    pub account_id: String,
    pub sequence: u64,
    pub token: String,
    pub observed_through: DateTime<Utc>,
    pub ingested_at: DateTime<Utc>,
    pub batch_digest: String,
}

impl ProviderCursor {
    fn validate(&self) -> Result<(), AttributionError> {
        if self.provider.trim().is_empty()
            || self.account_id.trim().is_empty()
            || self.token.trim().is_empty()
            || self.observed_through > self.ingested_at
            || !is_sha256(&self.batch_digest)
        {
            return Err(AttributionError::InvalidProviderCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceObservationBatch {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: Option<MissionId>,
    pub provider: String,
    pub account_id: String,
    pub cursor_before: Option<ProviderCursor>,
    pub cursor_after: ProviderCursor,
    pub events: Vec<SourceEvent>,
}

impl SourceObservationBatch {
    pub fn validate(&self) -> Result<(), AttributionError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.provider.trim().is_empty()
            || self.account_id.trim().is_empty()
        {
            return Err(AttributionError::InvalidObservationBatch);
        }
        self.cursor_after.validate()?;
        if self.cursor_after.provider != self.provider
            || self.cursor_after.account_id != self.account_id
        {
            return Err(AttributionError::CursorScopeMismatch);
        }
        if let Some(cursor) = &self.cursor_before {
            cursor.validate()?;
            if cursor.provider != self.provider || cursor.account_id != self.account_id {
                return Err(AttributionError::CursorScopeMismatch);
            }
            if cursor.sequence > self.cursor_after.sequence {
                return Err(AttributionError::CursorRegression);
            }
        }
        for event in &self.events {
            event.validate()?;
            if event.tenant_id != self.tenant_id
                || event.project_id != self.project_id
                || event.identity.provider != self.provider
                || event.identity.account_id != self.account_id
            {
                return Err(AttributionError::ObservationScopeMismatch);
            }
            if event.mission_id != self.mission_id {
                return Err(AttributionError::ObservationScopeMismatch);
            }
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String, AttributionError> {
        canonical_digest(self)
    }
}

/// Narrow adapter boundary for future Connector SDK implementations. The
/// connector owns authentication and pagination; the domain owns identity,
/// cursor fences, replay and truth promotion.
pub trait ConnectorObservationSource {
    type Error;

    fn read_observations(
        &mut self,
        cursor: Option<&ProviderCursor>,
    ) -> Result<SourceObservationBatch, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngestDisposition {
    Accepted(SourceEventId),
    Duplicate(SourceEventId),
    Corrected(SourceEventId),
    Reversed(SourceEventId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchIngestResult {
    pub accepted: usize,
    pub duplicates: usize,
    pub revision: u64,
    pub cursor_sequence: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionReason {
    CorrelatedClick,
    CorrelatedSession,
    CorrelatedCampaign,
    CorrelatedContent,
    UnattributedUnsupportedJoin,
    UnattributedOutsideWindow,
    UnattributedAmbiguous,
    UnattributedInactiveLineage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionAssignment {
    pub candidate_id: OutcomeCandidateId,
    pub source_event_id: SourceEventId,
    pub touchpoint_event_id: Option<SourceEventId>,
    pub reason: AttributionReason,
    pub window_version: u32,
    pub amount: Money,
    pub reporting_amount: Option<Money>,
    pub fx_observed_at: Option<DateTime<Utc>>,
    pub causal_claim: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionProjection {
    pub schema_version: String,
    pub ledger_revision: u64,
    pub window: AttributionWindow,
    pub candidate_count: u64,
    pub verified_outcome_count: u64,
    pub assignments: Vec<AttributionAssignment>,
    pub correlated_count: u64,
    pub unattributed_count: u64,
    pub event_order_digest: String,
    pub outcome_digest: String,
    pub causal_claim: bool,
}

impl AttributionProjection {
    pub fn digest(&self) -> Result<String, AttributionError> {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), AttributionError> {
        self.window.validate()?;
        if self.schema_version != ATTRIBUTION_SPINE_SCHEMA_VERSION
            || self.causal_claim
            || self
                .assignments
                .iter()
                .any(|assignment| assignment.causal_claim)
            || self.candidate_count < self.verified_outcome_count
            || self.verified_outcome_count
                != u64::try_from(self.assignments.len()).unwrap_or(u64::MAX)
            || self.correlated_count + self.unattributed_count
                != u64::try_from(self.assignments.len()).unwrap_or(u64::MAX)
        {
            return Err(AttributionError::InvalidAttributionProjection);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributionLedger {
    pub schema_version: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub reporting_currency: CurrencyCode,
    pub revision: u64,
    pub events: Vec<SourceEvent>,
    pub candidates: Vec<OutcomeCandidate>,
    pub verified_outcomes: Vec<VerifiedOutcome>,
    pub cursors: Vec<ProviderCursor>,
}

impl AttributionLedger {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        reporting_currency: CurrencyCode,
    ) -> Result<Self, AttributionError> {
        if tenant_id.as_str().trim().is_empty() || project_id.as_str().trim().is_empty() {
            return Err(AttributionError::InvalidLedgerScope);
        }
        Ok(Self {
            schema_version: ATTRIBUTION_SPINE_SCHEMA_VERSION.into(),
            tenant_id,
            project_id,
            reporting_currency,
            revision: 1,
            events: Vec::new(),
            candidates: Vec::new(),
            verified_outcomes: Vec::new(),
            cursors: Vec::new(),
        })
    }

    pub fn validate(&self) -> Result<(), AttributionError> {
        if self.schema_version != ATTRIBUTION_SPINE_SCHEMA_VERSION
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.reporting_currency.as_str().trim().is_empty()
            || self.revision == 0
        {
            return Err(AttributionError::InvalidLedgerScope);
        }
        let mut ids = BTreeSet::new();
        let mut dedupe = BTreeMap::new();
        let mut by_id: BTreeMap<SourceEventId, &SourceEvent> = BTreeMap::new();
        let mut superseded = BTreeSet::new();
        for event in &self.events {
            event.validate()?;
            if event.tenant_id != self.tenant_id || event.project_id != self.project_id {
                return Err(AttributionError::ObservationScopeMismatch);
            }
            if !ids.insert(event.id.clone()) {
                return Err(AttributionError::DuplicateSourceEvent);
            }
            let identity_digest = event.dedupe_digest();
            if let Some(previous_id) = dedupe.get(&identity_digest)
                && (event.lineage.kind == CorrectionKind::Original
                    || event.lineage.supersedes.as_ref() != Some(previous_id))
            {
                return Err(AttributionError::DuplicateProviderIdentity);
            }
            dedupe.insert(identity_digest, event.id.clone());
            if let Some(parent_id) = &event.lineage.supersedes {
                let parent = by_id
                    .get(parent_id)
                    .ok_or(AttributionError::InvalidCorrectionLineage)?;
                if parent.lineage.root_event_id != event.lineage.root_event_id
                    || !superseded.insert(parent_id.clone())
                {
                    return Err(AttributionError::InvalidCorrectionLineage);
                }
            }
            by_id.insert(event.id.clone(), event);
        }
        let mut candidate_ids = BTreeSet::new();
        for candidate in &self.candidates {
            if !candidate_ids.insert(candidate.id.clone()) {
                return Err(AttributionError::DuplicateOutcomeCandidate);
            }
            let event = by_id
                .get(&candidate.source_event_id)
                .copied()
                .ok_or(AttributionError::CandidateSourceMismatch)?;
            candidate.validate(event)?;
        }
        let candidate_map = self
            .candidates
            .iter()
            .map(|candidate| (candidate.id.clone(), candidate))
            .collect::<BTreeMap<_, _>>();
        let mut verified_ids = BTreeSet::new();
        for verified in &self.verified_outcomes {
            if !verified_ids.insert(verified.id.clone()) {
                return Err(AttributionError::DuplicateVerifiedOutcome);
            }
            let candidate = candidate_map
                .get(&verified.candidate_id)
                .copied()
                .ok_or(AttributionError::VerificationCandidateMismatch)?;
            if verified.source_event_id != candidate.source_event_id
                || verified.candidate_digest != candidate.source_event_digest
                || verified.verification.verifier.trim().is_empty()
                || !verified.verification.independent
                || !matches!(
                    verified.verification.method,
                    VerificationMethod::SignedWebhook | VerificationMethod::IndependentReadback
                )
                || !is_sha256(&verified.verification.evidence_digest)
                || verified.verification.verified_at < candidate.observed_at
            {
                return Err(AttributionError::InvalidOutcomeVerification);
            }
        }
        let mut cursor_keys = BTreeSet::new();
        for cursor in &self.cursors {
            cursor.validate()?;
            if !cursor_keys.insert((cursor.provider.clone(), cursor.account_id.clone())) {
                return Err(AttributionError::DuplicateProviderCursor);
            }
        }
        Ok(())
    }

    pub fn ingest_event(
        &mut self,
        event: SourceEvent,
    ) -> Result<IngestDisposition, AttributionError> {
        event.validate()?;
        if event.tenant_id != self.tenant_id || event.project_id != self.project_id {
            return Err(AttributionError::ObservationScopeMismatch);
        }
        if let Some(existing) = self
            .events
            .iter()
            .find(|current| current.dedupe_digest() == event.dedupe_digest())
        {
            if existing.canonical_digest()? == event.canonical_digest()? {
                return Ok(IngestDisposition::Duplicate(existing.id.clone()));
            }
            if event.lineage.kind == CorrectionKind::Original
                || event.lineage.supersedes.as_ref() != Some(&existing.id)
            {
                return Err(AttributionError::ConflictingDuplicateIdentity);
            }
        }
        if let Some(parent_id) = &event.lineage.supersedes {
            let parent = self
                .events
                .iter()
                .find(|current| current.id == *parent_id)
                .ok_or(AttributionError::InvalidCorrectionLineage)?;
            if parent.lineage.root_event_id != event.lineage.root_event_id
                || self
                    .events
                    .iter()
                    .any(|current| current.lineage.supersedes.as_ref() == Some(parent_id))
            {
                return Err(AttributionError::InvalidCorrectionLineage);
            }
        } else if event.lineage.kind != CorrectionKind::Original {
            return Err(AttributionError::InvalidCorrectionLineage);
        }
        let disposition = match event.lineage.kind {
            CorrectionKind::Original => IngestDisposition::Accepted(event.id.clone()),
            CorrectionKind::Correction => IngestDisposition::Corrected(event.id.clone()),
            CorrectionKind::Reversal => IngestDisposition::Reversed(event.id.clone()),
        };
        self.events.push(event);
        self.revision = self.revision.saturating_add(1);
        Ok(disposition)
    }

    pub fn ingest_batch(
        &mut self,
        batch: SourceObservationBatch,
    ) -> Result<BatchIngestResult, AttributionError> {
        batch.validate()?;
        if batch.tenant_id != self.tenant_id || batch.project_id != self.project_id {
            return Err(AttributionError::ObservationScopeMismatch);
        }
        let existing_cursor = self.cursors.iter().find(|cursor| {
            cursor.provider == batch.provider && cursor.account_id == batch.account_id
        });
        if let Some(existing) = existing_cursor {
            if batch.cursor_before.as_ref() != Some(existing) {
                if batch.cursor_after.sequence == existing.sequence
                    && batch.cursor_after.batch_digest == existing.batch_digest
                {
                    return Ok(BatchIngestResult {
                        accepted: 0,
                        duplicates: batch.events.len(),
                        revision: self.revision,
                        cursor_sequence: existing.sequence,
                    });
                }
                return Err(AttributionError::CursorFenceMismatch);
            }
            if batch.cursor_after.sequence < existing.sequence {
                return Err(AttributionError::CursorRegression);
            }
            if batch.cursor_after.sequence == existing.sequence
                && batch.cursor_after.batch_digest != existing.batch_digest
            {
                return Err(AttributionError::CursorFenceMismatch);
            }
        } else if batch.cursor_before.is_some() {
            return Err(AttributionError::CursorFenceMismatch);
        }
        let mut accepted = 0;
        let mut duplicates = 0;
        for event in batch.events {
            match self.ingest_event(event)? {
                IngestDisposition::Duplicate(_) => duplicates += 1,
                IngestDisposition::Accepted(_)
                | IngestDisposition::Corrected(_)
                | IngestDisposition::Reversed(_) => accepted += 1,
            }
        }
        if let Some(cursor) = self.cursors.iter_mut().find(|cursor| {
            cursor.provider == batch.provider && cursor.account_id == batch.account_id
        }) {
            *cursor = batch.cursor_after.clone();
        } else {
            self.cursors.push(batch.cursor_after.clone());
        }
        self.revision = self.revision.saturating_add(1);
        Ok(BatchIngestResult {
            accepted,
            duplicates,
            revision: self.revision,
            cursor_sequence: batch.cursor_after.sequence,
        })
    }

    pub fn register_candidate(
        &mut self,
        candidate: OutcomeCandidate,
    ) -> Result<(), AttributionError> {
        let event = self
            .events
            .iter()
            .find(|event| event.id == candidate.source_event_id)
            .ok_or(AttributionError::CandidateSourceMismatch)?;
        candidate.validate(event)?;
        if self
            .candidates
            .iter()
            .any(|current| current.id == candidate.id)
        {
            return Err(AttributionError::DuplicateOutcomeCandidate);
        }
        self.candidates.push(candidate);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    pub fn verify_candidate(
        &mut self,
        candidate_id: &OutcomeCandidateId,
        verification: OutcomeVerification,
    ) -> Result<VerifiedOutcome, AttributionError> {
        let candidate = self
            .candidates
            .iter()
            .find(|candidate| candidate.id == *candidate_id)
            .ok_or(AttributionError::VerificationCandidateMismatch)?;
        if verification.verifier.trim().is_empty()
            || !verification.independent
            || !matches!(
                verification.method,
                VerificationMethod::SignedWebhook | VerificationMethod::IndependentReadback
            )
            || !is_sha256(&verification.evidence_digest)
            || verification.verified_at < candidate.observed_at
        {
            return Err(AttributionError::InvalidOutcomeVerification);
        }
        if self
            .verified_outcomes
            .iter()
            .any(|verified| verified.candidate_id == *candidate_id)
        {
            return Err(AttributionError::DuplicateVerifiedOutcome);
        }
        let verified = VerifiedOutcome {
            id: VerifiedOutcomeId::from_stable(format!("verified:{}", candidate.id)),
            candidate_id: candidate.id.clone(),
            source_event_id: candidate.source_event_id.clone(),
            candidate_digest: candidate.source_event_digest.clone(),
            verification,
        };
        self.verified_outcomes.push(verified.clone());
        self.revision = self.revision.saturating_add(1);
        Ok(verified)
    }

    pub fn replay(
        &self,
        window: AttributionWindow,
    ) -> Result<AttributionProjection, AttributionError> {
        self.validate()?;
        window.validate()?;
        let active = self.active_events();
        let events_by_id = self
            .events
            .iter()
            .map(|event| (event.id.clone(), event))
            .collect::<BTreeMap<_, _>>();
        let candidates = self
            .candidates
            .iter()
            .map(|candidate| (candidate.id.clone(), candidate))
            .collect::<BTreeMap<_, _>>();
        let mut verified = self
            .verified_outcomes
            .iter()
            .filter_map(|outcome| {
                candidates
                    .get(&outcome.candidate_id)
                    .map(|candidate| (outcome, *candidate))
            })
            .collect::<Vec<_>>();
        verified.sort_by(|(_, left), (_, right)| {
            (left.observed_at, left.source_event_id.as_str())
                .cmp(&(right.observed_at, right.source_event_id.as_str()))
        });

        let mut assignments = Vec::with_capacity(verified.len());
        for (_, candidate) in verified {
            let source = events_by_id
                .get(&candidate.source_event_id)
                .copied()
                .ok_or(AttributionError::CandidateSourceMismatch)?;
            let source_is_current = active
                .get(&source.lineage.root_event_id)
                .is_some_and(|current| current.id == source.id);
            let (touchpoint_event_id, reason) = if source_is_current {
                Self::select_touchpoint(source, &active, &window)
            } else {
                (None, AttributionReason::UnattributedInactiveLineage)
            };
            let (reporting_amount, fx_observed_at) = convert_to_reporting_currency(
                &candidate.amount,
                source.fx_quote.as_ref(),
                &self.reporting_currency,
                source.observed_at,
            )?;
            assignments.push(AttributionAssignment {
                candidate_id: candidate.id.clone(),
                source_event_id: source.id.clone(),
                touchpoint_event_id,
                reason,
                window_version: window.version,
                amount: candidate.amount.clone(),
                reporting_amount,
                fx_observed_at,
                causal_claim: false,
            });
        }
        assignments.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
        let correlated_count = assignments
            .iter()
            .filter(|assignment| assignment.touchpoint_event_id.is_some())
            .count();
        let correlated_count =
            u64::try_from(correlated_count).map_err(|_| AttributionError::CountOverflow)?;
        let assignment_count =
            u64::try_from(assignments.len()).map_err(|_| AttributionError::CountOverflow)?;
        let candidate_count =
            u64::try_from(self.candidates.len()).map_err(|_| AttributionError::CountOverflow)?;
        let verified_outcome_count = u64::try_from(self.verified_outcomes.len())
            .map_err(|_| AttributionError::CountOverflow)?;
        let event_order_digest = canonical_digest(
            &active
                .values()
                .map(|event| event.id.clone())
                .collect::<Vec<_>>(),
        )?;
        let outcome_digest = canonical_digest(&self.verified_outcomes)?;
        let projection = AttributionProjection {
            schema_version: ATTRIBUTION_SPINE_SCHEMA_VERSION.into(),
            ledger_revision: self.revision,
            window,
            candidate_count,
            verified_outcome_count,
            assignments,
            correlated_count,
            unattributed_count: assignment_count.saturating_sub(correlated_count),
            event_order_digest,
            outcome_digest,
            causal_claim: false,
        };
        projection.validate()?;
        Ok(projection)
    }

    fn active_events(&self) -> BTreeMap<SourceEventId, &SourceEvent> {
        let mut active = BTreeMap::new();
        for event in &self.events {
            match event.lineage.kind {
                CorrectionKind::Original | CorrectionKind::Correction => {
                    active.insert(event.lineage.root_event_id.clone(), event);
                }
                CorrectionKind::Reversal => {
                    active.remove(&event.lineage.root_event_id);
                }
            }
        }
        active
    }

    fn select_touchpoint(
        outcome: &SourceEvent,
        active: &BTreeMap<SourceEventId, &SourceEvent>,
        window: &AttributionWindow,
    ) -> (Option<SourceEventId>, AttributionReason) {
        if outcome.provider_occurred_at < window.effective_at {
            return (None, AttributionReason::UnattributedOutsideWindow);
        }
        let mut matches = active
            .values()
            .filter(|event| {
                event.id != outcome.id
                    && event.kind.is_touchpoint()
                    && event.identity.provider == outcome.identity.provider
                    && event.identity.account_id == outcome.identity.account_id
                    && event.provider_occurred_at <= outcome.provider_occurred_at
            })
            .filter_map(|event| {
                let age = outcome.provider_occurred_at - event.provider_occurred_at;
                if event.provider_occurred_at < window.effective_at
                    || age < Duration::zero()
                    || age > window.max_age(event.kind)
                {
                    return None;
                }
                let (rank, reason) = shared_link(&outcome.links, &event.links)?;
                Some((rank, event.provider_occurred_at, event.id.clone(), reason))
            })
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            (left.0, std::cmp::Reverse(left.1), left.2.as_str()).cmp(&(
                right.0,
                std::cmp::Reverse(right.1),
                right.2.as_str(),
            ))
        });
        let Some(best) = matches.first() else {
            let has_link = active.values().any(|event| {
                event.kind.is_touchpoint()
                    && event.identity.provider == outcome.identity.provider
                    && event.identity.account_id == outcome.identity.account_id
            });
            return (
                None,
                if has_link {
                    AttributionReason::UnattributedOutsideWindow
                } else {
                    AttributionReason::UnattributedUnsupportedJoin
                },
            );
        };
        let tied = matches
            .iter()
            .filter(|candidate| candidate.0 == best.0 && candidate.1 == best.1)
            .count();
        if tied > 1 {
            return (None, AttributionReason::UnattributedAmbiguous);
        }
        (Some(best.2.clone()), best.3)
    }
}

fn shared_link(
    outcome: &SourceEventLinks,
    touchpoint: &SourceEventLinks,
) -> Option<(u8, AttributionReason)> {
    let links = [
        (
            &outcome.click,
            &touchpoint.click,
            0_u8,
            AttributionReason::CorrelatedClick,
        ),
        (
            &outcome.session,
            &touchpoint.session,
            1_u8,
            AttributionReason::CorrelatedSession,
        ),
        (
            &outcome.campaign,
            &touchpoint.campaign,
            2_u8,
            AttributionReason::CorrelatedCampaign,
        ),
        (
            &outcome.content,
            &touchpoint.content,
            3_u8,
            AttributionReason::CorrelatedContent,
        ),
    ];
    links.into_iter().find_map(|(left, right, rank, reason)| {
        (left.is_some() && left == right).then_some((rank, reason))
    })
}

fn convert_to_reporting_currency(
    amount: &Money,
    quote: Option<&FxQuote>,
    reporting_currency: &CurrencyCode,
    observed_at: DateTime<Utc>,
) -> Result<(Option<Money>, Option<DateTime<Utc>>), AttributionError> {
    if &amount.currency == reporting_currency {
        return Ok((Some(amount.clone()), None));
    }
    let Some(quote) = quote else {
        return Ok((None, None));
    };
    if quote.base != amount.currency
        || quote.quote != *reporting_currency
        || quote.observed_at > observed_at
    {
        return Ok((None, None));
    }
    let minor = (Decimal::from(amount.amount_minor) * quote.rate)
        .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
        .to_i64()
        .ok_or(AttributionError::MoneyOverflow)?;
    Ok((
        Some(Money::new(minor, reporting_currency.clone())),
        Some(quote.observed_at),
    ))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, AttributionError> {
    let bytes = serde_json::to_vec(value).map_err(AttributionError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn digest_parts(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update([0]);
        digest.update(part.as_bytes());
        digest.update([0xff]);
    }
    format!("{:x}", digest.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error)]
pub enum AttributionError {
    #[error("provider event identity is empty or incomplete")]
    InvalidProviderIdentity,
    #[error("provider entity link is empty or has the wrong typed kind")]
    InvalidEntityLink,
    #[error("source event envelope, timestamps, or payload digest is invalid")]
    InvalidSourceEvent,
    #[error("source event provenance is invalid")]
    InvalidProvenance,
    #[error("source event correction lineage is invalid or branched")]
    InvalidCorrectionLineage,
    #[error("source event money is invalid")]
    InvalidMoney,
    #[error("outcome source event requires a positive amount")]
    OutcomeAmountRequired,
    #[error("FX quote is missing an amount or has an invalid currency/timestamp")]
    InvalidFxQuote,
    #[error("FX quote cannot be supplied without an amount")]
    FxWithoutAmount,
    #[error("source event is not an outcome")]
    NotAnOutcomeEvent,
    #[error("outcome candidate is not bound to the exact source event")]
    CandidateSourceMismatch,
    #[error("outcome verification is not independent or is malformed")]
    InvalidOutcomeVerification,
    #[error("outcome candidate is not present for verification")]
    VerificationCandidateMismatch,
    #[error("attribution window version or bounds are invalid")]
    InvalidAttributionWindow,
    #[error("provider cursor is invalid")]
    InvalidProviderCursor,
    #[error("observation batch is invalid")]
    InvalidObservationBatch,
    #[error("observation batch cursor is outside its provider/account scope")]
    CursorScopeMismatch,
    #[error("observation batch cursor regressed")]
    CursorRegression,
    #[error("observation batch cursor fence does not match durable state")]
    CursorFenceMismatch,
    #[error("observation does not match the ledger project, mission, provider, or account scope")]
    ObservationScopeMismatch,
    #[error("unsupported identity join would be required")]
    UnsupportedIdentityJoin,
    #[error("ledger scope or schema is invalid")]
    InvalidLedgerScope,
    #[error("a source event id is duplicated")]
    DuplicateSourceEvent,
    #[error("a provider event identity is duplicated with different content")]
    DuplicateProviderIdentity,
    #[error("a provider event identity conflicts with existing immutable content")]
    ConflictingDuplicateIdentity,
    #[error("an outcome candidate id is duplicated")]
    DuplicateOutcomeCandidate,
    #[error("a verified outcome id is duplicated")]
    DuplicateVerifiedOutcome,
    #[error("a provider cursor is duplicated")]
    DuplicateProviderCursor,
    #[error("attribution projection is invalid or contains a causal claim")]
    InvalidAttributionProjection,
    #[error("projection count overflow")]
    CountOverflow,
    #[error("money conversion overflow")]
    MoneyOverflow,
    #[error("attribution state serialization failed: {0}")]
    Serialization(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn at(minute: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .expect("time")
            + Duration::minutes(minute)
    }

    fn account(provider: &str) -> ProviderEntityRef {
        ProviderEntityRef::new(SourceEntityKind::Account, provider, "acct-1", "acct-1")
            .expect("account")
    }

    fn link(kind: SourceEntityKind, provider: &str, id: &str) -> ProviderEntityRef {
        ProviderEntityRef::new(kind, provider, "acct-1", id).expect("link")
    }

    fn event(
        provider: &str,
        id: &str,
        kind: SourceEventKind,
        minute: i64,
        links: impl FnOnce(&mut SourceEventLinks),
    ) -> SourceEvent {
        let identity = ProviderEventIdentity::new(provider, "acct-1", id).expect("identity");
        let mut graph = SourceEventLinks::new(account(provider)).expect("graph");
        links(&mut graph);
        SourceEvent {
            id: SourceEventId::from_stable(id),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: Some(MissionId::from("mission-11")),
            identity,
            kind,
            links: graph,
            provider_occurred_at: at(minute),
            observed_at: at(minute + 1),
            ingested_at: at(minute + 2),
            amount: kind
                .outcome_kind()
                .map(|_| Money::new(10_000, CurrencyCode::parse("USD").expect("USD"))),
            fx_quote: None,
            provenance: ObservationProvenance::new(
                ObservationOrigin::FirstParty,
                "a".repeat(64),
                at(minute + 1),
            )
            .expect("provenance"),
            lineage: CorrectionLineage::original(SourceEventId::from_stable(id)),
            payload_digest: "b".repeat(64),
        }
    }

    fn ledger() -> AttributionLedger {
        AttributionLedger::new(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            CurrencyCode::parse("USD").expect("USD"),
        )
        .expect("ledger")
    }

    #[test]
    fn deterministic_table_replay_covers_ads_channel_commerce_and_partner() {
        let cases = [
            ("meta", SourceEventKind::Click),
            ("google-analytics", SourceEventKind::Session),
            ("shopify", SourceEventKind::Click),
            ("awin", SourceEventKind::Campaign),
        ];
        for (provider, touch_kind) in cases {
            let mut first = ledger();
            let touch_id = format!("{provider}-touch");
            let outcome_id = format!("{provider}-outcome");
            let campaign_id = format!("{provider}-campaign");
            let touch = event(provider, &touch_id, touch_kind, 1, |links| {
                links.campaign = Some(link(SourceEntityKind::Campaign, provider, &campaign_id));
                if touch_kind == SourceEventKind::Click {
                    links.click = Some(link(SourceEntityKind::Click, provider, &touch_id));
                }
                if touch_kind == SourceEventKind::Session {
                    links.session = Some(link(SourceEntityKind::Session, provider, &touch_id));
                }
            });
            let outcome = event(provider, &outcome_id, SourceEventKind::Order, 10, |links| {
                links.campaign = Some(link(SourceEntityKind::Campaign, provider, &campaign_id));
                if touch_kind == SourceEventKind::Click {
                    links.click = Some(link(SourceEntityKind::Click, provider, &touch_id));
                }
                if touch_kind == SourceEventKind::Session {
                    links.session = Some(link(SourceEntityKind::Session, provider, &touch_id));
                }
                links.order = Some(link(SourceEntityKind::Order, provider, &outcome_id));
            });
            first.ingest_event(touch).expect("touch");
            first.ingest_event(outcome.clone()).expect("outcome");
            let candidate = outcome.outcome_candidate().expect("candidate");
            let candidate_id = candidate.id.clone();
            first.register_candidate(candidate).expect("candidate");
            first
                .verify_candidate(
                    &candidate_id,
                    OutcomeVerification {
                        method: VerificationMethod::IndependentReadback,
                        verifier: format!("{provider}-readback"),
                        independent: true,
                        verified_at: at(12),
                        evidence_digest: "c".repeat(64),
                    },
                )
                .expect("verified");
            let projection = first
                .replay(AttributionWindow {
                    version: 1,
                    click_lookback_seconds: 86_400,
                    view_lookback_seconds: 172_800,
                    effective_at: at(0),
                })
                .expect("projection");
            assert_eq!(projection.correlated_count, 1, "{provider}");
            assert_eq!(projection.unattributed_count, 0, "{provider}");
            assert!(!projection.causal_claim);
        }
    }

    #[test]
    fn duplicate_and_out_of_order_replay_is_deterministic() {
        let mut ordered = ledger();
        let click = event("meta", "click", SourceEventKind::Click, 1, |links| {
            links.click = Some(link(SourceEntityKind::Click, "meta", "click"));
        });
        let mut order = event("meta", "order", SourceEventKind::Order, 5, |links| {
            links.click = Some(link(SourceEntityKind::Click, "meta", "click"));
            links.order = Some(link(SourceEntityKind::Order, "meta", "order"));
        });
        order.amount = Some(Money::new(1_000, CurrencyCode::parse("USD").expect("USD")));
        let replay_candidate = order.outcome_candidate().expect("replay candidate");
        ordered.ingest_event(click.clone()).expect("click");
        ordered.ingest_event(order.clone()).expect("order");
        assert!(matches!(
            ordered.ingest_event(order.clone()),
            Ok(IngestDisposition::Duplicate(_))
        ));
        let mut conflicting = order.clone();
        conflicting.payload_digest = "9".repeat(64);
        assert!(matches!(
            ordered.ingest_event(conflicting),
            Err(AttributionError::ConflictingDuplicateIdentity)
        ));
        let candidate = order.outcome_candidate().expect("candidate");
        let candidate_id = candidate.id.clone();
        ordered.register_candidate(candidate).expect("candidate");
        ordered
            .verify_candidate(
                &candidate_id,
                OutcomeVerification {
                    method: VerificationMethod::SignedWebhook,
                    verifier: "meta-webhook".into(),
                    independent: true,
                    verified_at: at(7),
                    evidence_digest: "d".repeat(64),
                },
            )
            .expect("verified");
        let expected = ordered
            .replay(AttributionWindow {
                version: 1,
                click_lookback_seconds: 3_600,
                view_lookback_seconds: 3_600,
                effective_at: at(0),
            })
            .expect("ordered replay");

        let mut out_of_order = ledger();
        out_of_order.ingest_event(order.clone()).expect("order");
        out_of_order
            .ingest_event(click.clone())
            .expect("late click");
        // Provider batches are the durable ordering boundary; events inside a
        // valid batch remain replayable by provider time, while correction
        // chains still require their parent.
        let mut replay = ledger();
        let batch = SourceObservationBatch {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            mission_id: Some(MissionId::from("mission-11")),
            provider: "meta".into(),
            account_id: "acct-1".into(),
            cursor_before: None,
            cursor_after: ProviderCursor {
                provider: "meta".into(),
                account_id: "acct-1".into(),
                sequence: 1,
                token: "cursor-1".into(),
                observed_through: at(7),
                ingested_at: at(8),
                batch_digest: "e".repeat(64),
            },
            events: vec![order, click],
        };
        // Batch transport may contain out-of-order events, but a correction
        // parent is still a hard invariant. Here both are originals.
        replay.ingest_batch(batch).expect("batch");
        let replay_candidate_id = replay_candidate.id.clone();
        replay
            .register_candidate(replay_candidate)
            .expect("batch candidate");
        replay
            .verify_candidate(
                &replay_candidate_id,
                OutcomeVerification {
                    method: VerificationMethod::IndependentReadback,
                    verifier: "meta-readback".into(),
                    independent: true,
                    verified_at: at(8),
                    evidence_digest: "e".repeat(64),
                },
            )
            .expect("batch verification");
        let replayed = replay
            .replay(AttributionWindow {
                version: 1,
                click_lookback_seconds: 3_600,
                view_lookback_seconds: 3_600,
                effective_at: at(0),
            })
            .expect("batch replay");
        assert_eq!(expected.assignments.len(), replayed.assignments.len());
        assert_eq!(expected.event_order_digest, replayed.event_order_digest);
    }

    #[test]
    fn corrections_and_reversals_are_immutable_and_force_reverification() {
        let mut ledger = ledger();
        let original = event(
            "shopify",
            "order-original",
            SourceEventKind::Order,
            2,
            |links| {
                links.order = Some(link(SourceEntityKind::Order, "shopify", "order-1"));
                links.campaign = Some(link(SourceEntityKind::Campaign, "shopify", "campaign-1"));
            },
        );
        let original_digest = original.canonical_digest().expect("digest");
        ledger.ingest_event(original.clone()).expect("original");
        let candidate = original.outcome_candidate().expect("candidate");
        let candidate_id = candidate.id.clone();
        ledger.register_candidate(candidate).expect("candidate");
        ledger
            .verify_candidate(
                &candidate_id,
                OutcomeVerification {
                    method: VerificationMethod::IndependentReadback,
                    verifier: "shopify-readback".into(),
                    independent: true,
                    verified_at: at(4),
                    evidence_digest: "f".repeat(64),
                },
            )
            .expect("verified");
        let mut correction = event(
            "shopify",
            "order-correction",
            SourceEventKind::Order,
            8,
            |links| {
                links.order = Some(link(SourceEntityKind::Order, "shopify", "order-1"));
                links.campaign = Some(link(SourceEntityKind::Campaign, "shopify", "campaign-2"));
            },
        );
        correction.identity.external_event_id = original.identity.external_event_id.clone();
        correction.lineage = CorrectionLineage {
            kind: CorrectionKind::Correction,
            root_event_id: original.id.clone(),
            supersedes: Some(original.id.clone()),
            reason: Some("provider correction".into()),
        };
        ledger.ingest_event(correction).expect("correction");
        assert_eq!(
            ledger.events[0].canonical_digest().expect("digest"),
            original_digest
        );
        let projection = ledger
            .replay(AttributionWindow {
                version: 1,
                click_lookback_seconds: 86_400,
                view_lookback_seconds: 86_400,
                effective_at: at(0),
            })
            .expect("projection");
        assert_eq!(projection.unattributed_count, 1);
        assert_eq!(
            projection.assignments[0].reason,
            AttributionReason::UnattributedInactiveLineage
        );

        let mut reversal = event(
            "shopify",
            "order-reversal",
            SourceEventKind::Order,
            9,
            |links| {
                links.order = Some(link(SourceEntityKind::Order, "shopify", "order-1"));
            },
        );
        reversal.lineage = CorrectionLineage {
            kind: CorrectionKind::Reversal,
            root_event_id: original.id.clone(),
            supersedes: Some(SourceEventId::from_stable("order-correction")),
            reason: Some("provider reversal".into()),
        };
        ledger.ingest_event(reversal).expect("reversal");
        assert_eq!(ledger.events.len(), 3);
        assert!(ledger.validate().is_ok());
    }

    #[test]
    fn unsupported_cross_provider_join_stays_unattributed_and_fx_keeps_timestamp() {
        let mut ledger = ledger();
        let click = event("meta", "click", SourceEventKind::Click, 1, |links| {
            links.click = Some(link(SourceEntityKind::Click, "meta", "click"));
        });
        ledger.ingest_event(click).expect("click");
        let mut order = event("shopify", "order", SourceEventKind::Order, 5, |links| {
            links.order = Some(link(SourceEntityKind::Order, "shopify", "order"));
            links.click = Some(link(SourceEntityKind::Click, "shopify", "click"));
        });
        order.amount = Some(Money::new(10_000, CurrencyCode::parse("EUR").expect("EUR")));
        order.fx_quote = Some(
            FxQuote::new(
                CurrencyCode::parse("EUR").expect("EUR"),
                CurrencyCode::parse("USD").expect("USD"),
                Decimal::new(11, 1),
                "fx-provider",
                at(4),
            )
            .expect("fx"),
        );
        let candidate = order.outcome_candidate().expect("candidate");
        let candidate_id = candidate.id.clone();
        ledger.ingest_event(order).expect("order");
        ledger.register_candidate(candidate).expect("candidate");
        ledger
            .verify_candidate(
                &candidate_id,
                OutcomeVerification {
                    method: VerificationMethod::IndependentReadback,
                    verifier: "shopify-readback".into(),
                    independent: true,
                    verified_at: at(7),
                    evidence_digest: "1".repeat(64),
                },
            )
            .expect("verified");
        let projection = ledger
            .replay(AttributionWindow {
                version: 1,
                click_lookback_seconds: 86_400,
                view_lookback_seconds: 86_400,
                effective_at: at(0),
            })
            .expect("projection");
        assert_eq!(
            projection.assignments[0].reason,
            AttributionReason::UnattributedUnsupportedJoin
        );
        assert_eq!(
            projection.assignments[0]
                .reporting_amount
                .as_ref()
                .expect("USD")
                .amount_minor,
            11_000
        );
        assert_eq!(projection.assignments[0].fx_observed_at, Some(at(4)));
        assert!(!projection.causal_claim);
    }

    #[test]
    fn candidate_requires_independent_verification() {
        let mut ledger = ledger();
        let order = event("stripe", "order", SourceEventKind::Order, 1, |links| {
            links.order = Some(link(SourceEntityKind::Order, "stripe", "order"));
        });
        let candidate = order.outcome_candidate().expect("candidate");
        let candidate_id = candidate.id.clone();
        ledger.ingest_event(order).expect("event");
        ledger.register_candidate(candidate).expect("candidate");
        assert!(matches!(
            ledger.verify_candidate(
                &candidate_id,
                OutcomeVerification {
                    method: VerificationMethod::HumanConfirmed,
                    verifier: "estimate".into(),
                    independent: false,
                    verified_at: at(3),
                    evidence_digest: "2".repeat(64),
                },
            ),
            Err(AttributionError::InvalidOutcomeVerification)
        ));
    }
}

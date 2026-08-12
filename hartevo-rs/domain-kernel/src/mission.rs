use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AccountId, ActorId, ApprovalId, ConnectionId, ConsentRecordId, ConsentRequirement,
    ConversationId, CreatorHiringId, CreatorId, EffectId, EvidenceId, MissionId, Money, PartnerId,
    ProjectId, ReceiptId, TaskId, TenantId, VerificationId, WorkProductId,
};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Read,
    LocalWrite,
    ExternalWrite,
    Outreach,
    Spend,
    Payment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Constraint {
    RequireApproval { effect_classes: Vec<EffectClass> },
    Budget { amount_minor: i64, currency: String },
    Market { value: String },
    StopCondition { description: String },
    UserInstruction { description: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingMode {
    BuildOnce,
    ContinuousOperator,
    Campaign,
    ContinuousRelationship,
    OneOffDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyLevel {
    Disabled,
    DraftOnly,
    ApprovalRequired,
    AutonomousLowRisk,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cadence {
    pub interval_seconds: u64,
    pub anchor_at: DateTime<Utc>,
    #[serde(default)]
    pub trigger: CadenceTriggerKind,
    #[serde(default)]
    pub event_topics: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CadenceTriggerKind {
    #[default]
    Interval,
    EventDriven,
    IntervalOrEvent,
}

pub(crate) fn next_interval_due_at(
    cadence: &Cadence,
    after: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if cadence.trigger == CadenceTriggerKind::EventDriven {
        return None;
    }
    let interval = i64::try_from(cadence.interval_seconds)
        .ok()
        .filter(|value| *value > 0)?;
    if cadence.anchor_at > after {
        return Some(cadence.anchor_at);
    }
    let elapsed = after.signed_duration_since(cadence.anchor_at).num_seconds();
    let steps = elapsed.checked_div(interval)?.checked_add(1)?;
    let seconds = interval.checked_mul(steps)?;
    cadence
        .anchor_at
        .checked_add_signed(chrono::Duration::seconds(seconds))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KpiContract {
    pub baseline: Option<Decimal>,
    pub target: Decimal,
    pub unit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalPolicy {
    pub required_effect_classes: BTreeSet<EffectClass>,
    pub validity_seconds: u64,
    pub exact_scope_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatingContract {
    pub version: u64,
    pub mode: OperatingMode,
    pub goal: String,
    pub non_goals: Vec<String>,
    pub market: String,
    pub language: String,
    pub audience: String,
    pub kpis: BTreeMap<String, KpiContract>,
    pub budget: Money,
    pub timezone: String,
    pub cadence: Option<Cadence>,
    pub autonomy_by_capability: BTreeMap<String, AutonomyLevel>,
    pub consent_requirements: BTreeSet<String>,
    pub approval_policy: ApprovalPolicy,
    pub stop_conditions: Vec<String>,
    pub completion_conditions: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub constraints: Vec<Constraint>,
    pub enabled_capabilities: BTreeSet<String>,
    pub forbidden_capabilities: BTreeSet<String>,
}

pub type MissionContract = OperatingContract;

impl OperatingContract {
    pub fn bootstrap(
        goal: impl Into<String>,
        enabled_capabilities: impl IntoIterator<Item = String>,
        now: DateTime<Utc>,
    ) -> Self {
        let enabled_capabilities = enabled_capabilities.into_iter().collect::<BTreeSet<_>>();
        let autonomy_by_capability = enabled_capabilities
            .iter()
            .map(|capability| (capability.clone(), AutonomyLevel::ApprovalRequired))
            .collect();
        Self {
            version: 1,
            mode: OperatingMode::BuildOnce,
            goal: goal.into(),
            non_goals: Vec::new(),
            market: "unspecified".into(),
            language: "und".into(),
            audience: "unspecified".into(),
            kpis: BTreeMap::new(),
            budget: Money::zero(
                crate::CurrencyCode::parse("USD").expect("static ISO currency is valid"),
            ),
            timezone: "UTC".into(),
            cadence: None,
            autonomy_by_capability,
            consent_requirements: BTreeSet::new(),
            approval_policy: ApprovalPolicy {
                required_effect_classes: BTreeSet::from([
                    EffectClass::ExternalWrite,
                    EffectClass::Outreach,
                    EffectClass::Spend,
                    EffectClass::Payment,
                ]),
                validity_seconds: 3_600,
                exact_scope_required: true,
            },
            stop_conditions: vec!["user_cancelled".into()],
            completion_conditions: vec!["mission_oracle_satisfied".into()],
            valid_from: now,
            valid_until: now + chrono::Duration::days(30),
            constraints: Vec::new(),
            enabled_capabilities,
            forbidden_capabilities: BTreeSet::new(),
        }
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), OperatingContractError> {
        if self.version == 0
            || self.goal.trim().is_empty()
            || self.market.trim().is_empty()
            || self.language.trim().is_empty()
            || self.audience.trim().is_empty()
            || self.timezone.trim().is_empty()
            || self
                .stop_conditions
                .iter()
                .all(|value| value.trim().is_empty())
            || self
                .completion_conditions
                .iter()
                .all(|value| value.trim().is_empty())
        {
            return Err(OperatingContractError::Incomplete);
        }
        if self.valid_from > now || self.valid_until <= now || self.valid_until <= self.valid_from {
            return Err(OperatingContractError::InvalidValidity);
        }
        if self.budget.amount_minor < 0 {
            return Err(OperatingContractError::NegativeBudget);
        }
        if self.approval_policy.validity_seconds == 0 || !self.approval_policy.exact_scope_required
        {
            return Err(OperatingContractError::UnsafeApprovalPolicy);
        }
        if matches!(
            self.mode,
            OperatingMode::ContinuousOperator | OperatingMode::ContinuousRelationship
        ) && self.cadence.is_none()
        {
            return Err(OperatingContractError::MissingCadence);
        }
        if self.cadence.as_ref().is_some_and(|cadence| {
            cadence
                .event_topics
                .iter()
                .any(|topic| topic.trim().is_empty())
                || match cadence.trigger {
                    CadenceTriggerKind::Interval => {
                        cadence.interval_seconds == 0 || !cadence.event_topics.is_empty()
                    }
                    CadenceTriggerKind::EventDriven => {
                        cadence.interval_seconds != 0 || cadence.event_topics.is_empty()
                    }
                    CadenceTriggerKind::IntervalOrEvent => {
                        cadence.interval_seconds == 0 || cadence.event_topics.is_empty()
                    }
                }
        }) {
            return Err(OperatingContractError::InvalidCadence);
        }
        if self
            .kpis
            .iter()
            .any(|(name, kpi)| name.trim().is_empty() || kpi.unit.trim().is_empty())
        {
            return Err(OperatingContractError::InvalidKpi);
        }
        if self
            .enabled_capabilities
            .iter()
            .any(|capability| capability.trim().is_empty())
            || !self
                .enabled_capabilities
                .is_disjoint(&self.forbidden_capabilities)
        {
            return Err(OperatingContractError::CapabilityConflict);
        }
        let autonomous_capabilities = self
            .autonomy_by_capability
            .iter()
            .filter(|(_, level)| **level != AutonomyLevel::Disabled)
            .map(|(capability, _)| capability)
            .collect::<BTreeSet<_>>();
        let enabled_refs = self.enabled_capabilities.iter().collect::<BTreeSet<_>>();
        if autonomous_capabilities != enabled_refs
            || self.forbidden_capabilities.iter().any(|capability| {
                self.autonomy_by_capability
                    .get(capability)
                    .is_some_and(|level| *level != AutonomyLevel::Disabled)
            })
        {
            return Err(OperatingContractError::AutonomyMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OperatingContractError {
    #[error("operating contract is incomplete")]
    Incomplete,
    #[error("operating contract validity window is invalid")]
    InvalidValidity,
    #[error("operating contract budget cannot be negative")]
    NegativeBudget,
    #[error("operating contract requires exact, time-bounded approvals")]
    UnsafeApprovalPolicy,
    #[error("continuous operating modes require a cadence trigger")]
    MissingCadence,
    #[error("cadence trigger, interval, and event topics are inconsistent")]
    InvalidCadence,
    #[error("operating contract KPI name or unit is invalid")]
    InvalidKpi,
    #[error("enabled and forbidden capabilities conflict")]
    CapabilityConflict,
    #[error("capability autonomy does not match the enabled and forbidden sets")]
    AutonomyMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionStage {
    Draft,
    #[serde(alias = "compiled")]
    Ready,
    #[serde(alias = "researching", alias = "executing")]
    Running,
    Blocked,
    #[serde(alias = "paused")]
    WaitingUser,
    #[serde(alias = "awaiting_approval")]
    WaitingApproval,
    #[serde(alias = "outcome_ready")]
    Verifying,
    CycleReviewed,
    Scheduled,
    Completed,
    Partial,
    ExpectedRefusal,
    Failed,
    Cancelled,
}

impl MissionStage {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Partial
                | Self::ExpectedRefusal
                | Self::Failed
                | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionTerminalDisposition {
    Completed,
    Partial,
    ExpectedRefusal,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBlock {
    pub code: String,
    pub detail: String,
    pub recoverable: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Ready,
    Running,
    Blocked,
    Completed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    pub id: TaskId,
    pub title: String,
    pub status: TaskStatus,
    pub capability: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Candidate,
    Confirmed,
    Conflicted,
    Invalidated,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub id: EvidenceId,
    pub title: String,
    pub source_uri: String,
    pub observed_at: DateTime<Utc>,
    pub confidence: f32,
    pub status: EvidenceStatus,
    pub content_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkProductStatus {
    Draft,
    ReadyForReview,
    Accepted,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProduct {
    pub id: WorkProductId,
    pub title: String,
    pub body: String,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub revision: u64,
    pub status: WorkProductStatus,
    pub content_digest: String,
}

impl WorkProduct {
    pub fn draft(
        id: WorkProductId,
        title: impl Into<String>,
        body: impl Into<String>,
        evidence_ids: impl IntoIterator<Item = EvidenceId>,
    ) -> Self {
        let title = title.into();
        let body = body.into();
        let content_digest = sha256(format!("{title}\n{body}").as_bytes());
        Self {
            id,
            title,
            body,
            evidence_ids: evidence_ids.into_iter().collect(),
            revision: 1,
            status: WorkProductStatus::Draft,
            content_digest,
        }
    }

    pub fn validate(&self) -> Result<(), MissionError> {
        if self.id.as_str().trim().is_empty()
            || self.title.trim().is_empty()
            || self.body.trim().is_empty()
            || self.revision == 0
            || self
                .evidence_ids
                .iter()
                .any(|evidence_id| evidence_id.as_str().trim().is_empty())
            || self.content_digest != sha256(format!("{}\n{}", self.title, self.body).as_bytes())
        {
            return Err(MissionError::InvalidWorkProduct(self.id.clone()));
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, MissionError> {
        self.validate()?;
        previous.validate()?;
        let transition_allowed = matches!(
            (&previous.status, &self.status),
            (
                WorkProductStatus::Draft,
                WorkProductStatus::Draft | WorkProductStatus::ReadyForReview
            ) | (
                WorkProductStatus::ReadyForReview,
                WorkProductStatus::ReadyForReview
                    | WorkProductStatus::Accepted
                    | WorkProductStatus::Superseded
            ) | (WorkProductStatus::Accepted, WorkProductStatus::Superseded)
        );
        Ok(self.id == previous.id
            && previous.revision.checked_add(1) == Some(self.revision)
            && transition_allowed)
    }

    pub fn revise_content(
        &self,
        title: impl Into<String>,
        body: impl Into<String>,
        evidence_ids: impl IntoIterator<Item = EvidenceId>,
    ) -> Result<Self, MissionError> {
        self.validate()?;
        if self.status != WorkProductStatus::ReadyForReview {
            return Err(MissionError::InvalidWorkProductTransition(self.id.clone()));
        }
        let title = title.into();
        let body = body.into();
        let revised = Self {
            id: self.id.clone(),
            content_digest: sha256(format!("{title}\n{body}").as_bytes()),
            title,
            body,
            evidence_ids: evidence_ids.into_iter().collect(),
            revision: self
                .revision
                .checked_add(1)
                .ok_or(MissionError::RevisionOverflow)?,
            status: WorkProductStatus::ReadyForReview,
        };
        if !revised.follows(self)? {
            return Err(MissionError::InvalidWorkProductTransition(self.id.clone()));
        }
        Ok(revised)
    }

    pub fn accept(&self) -> Result<Self, MissionError> {
        self.transition_to(WorkProductStatus::Accepted)
    }

    pub fn supersede(&self) -> Result<Self, MissionError> {
        self.transition_to(WorkProductStatus::Superseded)
    }

    fn transition_to(&self, status: WorkProductStatus) -> Result<Self, MissionError> {
        let transitioned = Self {
            revision: self
                .revision
                .checked_add(1)
                .ok_or(MissionError::RevisionOverflow)?,
            status,
            ..self.clone()
        };
        if !transitioned.follows(self)? {
            return Err(MissionError::InvalidWorkProductTransition(self.id.clone()));
        }
        Ok(transitioned)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectRisk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    NotRequired,
    Confirmed,
    Missing,
    Withdrawn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectStatus {
    Proposed,
    Approved,
    Rejected,
    Cancelled,
    Executing,
    ReceiptRecorded,
    VerificationRequired,
    Verified,
    Reconciled,
    DeadLetter,
    Failed,
    Expired,
}

/// A terminal or reconciliation-only Provider state that was committed to the
/// durable execution ledger before the Mission projection was persisted.
/// Neither variant grants a new Provider execution permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableProviderState {
    Rejected,
    Uncertain,
    ReconciledNotExecuted,
    DeadLetter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationEffectGuard {
    pub conversation_id: ConversationId,
    pub control_generation: u64,
    pub scope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatorContactEffectGuard {
    pub hiring_id: CreatorHiringId,
    pub creator_id: CreatorId,
    pub partner_id: PartnerId,
    pub scope_digest: String,
    pub permission_evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectSpec {
    pub id: EffectId,
    pub actor_id: ActorId,
    pub capability: String,
    pub provider: String,
    pub connection_id: Option<ConnectionId>,
    pub account_id: Option<AccountId>,
    #[serde(default)]
    pub required_scopes: BTreeSet<String>,
    pub effect_class: EffectClass,
    pub description: String,
    pub target_resource: String,
    pub audience_digest: Option<String>,
    pub payload_digest: String,
    pub asset_digests: BTreeSet<String>,
    pub scheduled_for: Option<DateTime<Utc>>,
    pub timezone: String,
    pub consent: ConsentState,
    pub consent_record_id: Option<ConsentRecordId>,
    #[serde(default)]
    pub consent_requirement: Option<ConsentRequirement>,
    #[serde(default)]
    pub conversation_guard: Option<ConversationEffectGuard>,
    #[serde(default)]
    pub creator_contact_guard: Option<CreatorContactEffectGuard>,
    pub policy_version: String,
    pub risk: EffectRisk,
    pub idempotency_key: String,
    pub amount: Money,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub id: ApprovalId,
    pub decision: ApprovalDecision,
    pub decided_by: ActorId,
    pub decided_at: DateTime<Utc>,
    /// Approval authorization is valid only for this bounded dispatch window.
    /// Legacy snapshots deserialize to an already-expired sentinel and must be
    /// approved again before any external execution.
    #[serde(default = "legacy_approval_valid_until")]
    pub valid_until: DateTime<Utc>,
    pub scope_digest: String,
    /// Canonical digest of the live permission evidence and exact broker policy
    /// configuration that were re-read when approval was granted.
    #[serde(default = "legacy_permission_digest")]
    pub permission_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub id: ReceiptId,
    pub provider: String,
    pub external_id: String,
    pub accepted_at: DateTime<Utc>,
    pub request_digest: String,
    pub response_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Confirmed,
    Rejected,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub id: VerificationId,
    pub status: VerificationStatus,
    pub verifier: String,
    pub independent: bool,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub receipt_id: ReceiptId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Effect {
    pub id: EffectId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub actor_id: ActorId,
    pub capability: String,
    pub provider: String,
    pub connection_id: Option<ConnectionId>,
    pub account_id: Option<AccountId>,
    pub required_scopes: BTreeSet<String>,
    pub effect_class: EffectClass,
    pub description: String,
    pub target_resource: String,
    pub audience_digest: Option<String>,
    pub payload_digest: String,
    pub asset_digests: BTreeSet<String>,
    pub scheduled_for: Option<DateTime<Utc>>,
    pub timezone: String,
    pub consent: ConsentState,
    pub consent_record_id: Option<ConsentRecordId>,
    pub consent_requirement: Option<ConsentRequirement>,
    #[serde(default)]
    pub conversation_guard: Option<ConversationEffectGuard>,
    #[serde(default)]
    pub creator_contact_guard: Option<CreatorContactEffectGuard>,
    pub policy_version: String,
    pub risk: EffectRisk,
    pub idempotency_key: String,
    pub amount: Money,
    pub expires_at: DateTime<Utc>,
    pub status: EffectStatus,
    pub approval: Option<Approval>,
    pub receipt: Option<Receipt>,
    pub verification: Option<Verification>,
}

impl Effect {
    pub fn approval_digest(&self) -> String {
        let mut digest = Sha256::new();
        hash_field(&mut digest, self.tenant_id.as_str());
        hash_field(&mut digest, self.project_id.as_str());
        hash_field(&mut digest, self.mission_id.as_str());
        hash_field(&mut digest, self.id.as_str());
        hash_field(&mut digest, self.actor_id.as_str());
        hash_field(&mut digest, &self.capability);
        hash_field(&mut digest, &self.provider);
        hash_optional(
            &mut digest,
            self.connection_id.as_ref().map(ConnectionId::as_str),
        );
        hash_optional(&mut digest, self.account_id.as_ref().map(AccountId::as_str));
        for scope in &self.required_scopes {
            hash_field(&mut digest, scope);
        }
        hash_field(&mut digest, effect_class_name(&self.effect_class));
        hash_field(&mut digest, &self.description);
        hash_field(&mut digest, &self.target_resource);
        hash_optional(&mut digest, self.audience_digest.as_deref());
        hash_field(&mut digest, &self.payload_digest);
        for asset_digest in &self.asset_digests {
            hash_field(&mut digest, asset_digest);
        }
        hash_optional(
            &mut digest,
            self.scheduled_for
                .as_ref()
                .map(chrono::DateTime::to_rfc3339)
                .as_deref(),
        );
        hash_field(&mut digest, &self.timezone);
        hash_field(&mut digest, consent_name(&self.consent));
        hash_optional(
            &mut digest,
            self.consent_record_id.as_ref().map(ConsentRecordId::as_str),
        );
        match &self.consent_requirement {
            Some(requirement) => {
                hash_field(&mut digest, "consent_requirement");
                hash_field(&mut digest, requirement.person_id.as_str());
                hash_field(
                    &mut digest,
                    serde_json::to_string(&requirement.purpose)
                        .expect("consent purpose is serializable")
                        .as_str(),
                );
                hash_field(
                    &mut digest,
                    serde_json::to_string(&requirement.channel)
                        .expect("contact channel is serializable")
                        .as_str(),
                );
                hash_field(&mut digest, &requirement.market);
            }
            None => hash_field(&mut digest, "no_consent_requirement"),
        }
        match &self.conversation_guard {
            Some(guard) => {
                hash_field(&mut digest, "conversation_guard");
                hash_field(&mut digest, guard.conversation_id.as_str());
                hash_field(&mut digest, &guard.control_generation.to_string());
                hash_field(&mut digest, &guard.scope_digest);
            }
            None => hash_field(&mut digest, "no_conversation_guard"),
        }
        match &self.creator_contact_guard {
            Some(guard) => {
                hash_field(&mut digest, "creator_contact_guard");
                hash_field(&mut digest, guard.hiring_id.as_str());
                hash_field(&mut digest, guard.creator_id.as_str());
                hash_field(&mut digest, guard.partner_id.as_str());
                hash_field(&mut digest, &guard.scope_digest);
                hash_field(&mut digest, &guard.permission_evidence_digest);
            }
            None => hash_field(&mut digest, "no_creator_contact_guard"),
        }
        hash_field(&mut digest, &self.policy_version);
        hash_field(&mut digest, risk_name(&self.risk));
        hash_field(&mut digest, &self.idempotency_key);
        hash_field(&mut digest, &self.amount.amount_minor.to_string());
        hash_field(&mut digest, self.amount.currency.as_str());
        hash_field(&mut digest, &self.expires_at.to_rfc3339());
        format!("{:x}", digest.finalize())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeDecision {
    Continue,
    Stop,
    Scale,
    Test,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub summary: String,
    pub decision: OutcomeDecision,
    pub metrics: BTreeMap<String, MetricValue>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum MetricValue {
    Count { value: i64 },
    Money { value: Money },
    Decimal { value: Decimal, unit: String },
}

/// Machine-readable identity and execution state for one Catalog Mission.
///
/// The definition is deliberately stored with the Mission instead of being
/// reconstructed from the current binary on every read. A later Catalog
/// release therefore cannot silently change the Checkpoint DAG, capability
/// authority, artifact obligations, or Oracle set of an already-running
/// Mission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionDefinition {
    pub manifest_id: String,
    pub manifest_version: u32,
    pub catalog_digest: String,
    pub operating_mode: OperatingMode,
    pub capability_ids: BTreeSet<String>,
    pub required_artifact_types: BTreeSet<String>,
    pub oracle_ids: BTreeSet<String>,
    pub checkpoints: Vec<MissionCheckpoint>,
    pub cycle: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionCheckpointStatus {
    Pending,
    Ready,
    Running,
    Blocked,
    WaitingUser,
    WaitingApproval,
    Verifying,
    Completed,
    Skipped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionCheckpointExecutor {
    Application,
    Runtime,
    EffectBroker,
    Human,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionCheckpointCompletionPolicy {
    DeterministicEvidence,
    WorkProduct,
    VerifiedEffect,
    HumanConfirmation,
}

impl TryFrom<&str> for MissionCheckpointCompletionPolicy {
    type Error = MissionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "deterministic_evidence" => Ok(Self::DeterministicEvidence),
            "work_product" => Ok(Self::WorkProduct),
            "verified_effect" => Ok(Self::VerifiedEffect),
            "human_confirmation" => Ok(Self::HumanConfirmation),
            _ => Err(MissionError::InvalidMissionDefinition),
        }
    }
}

impl TryFrom<&str> for MissionCheckpointExecutor {
    type Error = MissionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "application" => Ok(Self::Application),
            "runtime" => Ok(Self::Runtime),
            "effect_broker" => Ok(Self::EffectBroker),
            "human" => Ok(Self::Human),
            _ => Err(MissionError::InvalidMissionDefinition),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCheckpointRoute {
    pub capability_id: String,
    pub executor: MissionCheckpointExecutor,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub oracle_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_policy: Option<MissionCheckpointCompletionPolicy>,
}

impl MissionCheckpointRoute {
    /// Legacy v42 route constructor. These rows remain auditable but cannot
    /// complete a Checkpoint because they do not freeze Oracle or completion
    /// policy authority.
    pub fn new(
        capability_id: impl Into<String>,
        executor: MissionCheckpointExecutor,
    ) -> Result<Self, MissionError> {
        let route = Self {
            capability_id: capability_id.into(),
            executor,
            oracle_ids: BTreeSet::new(),
            completion_policy: None,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn contracted(
        capability_id: impl Into<String>,
        executor: MissionCheckpointExecutor,
        oracle_ids: impl IntoIterator<Item = String>,
        completion_policy: MissionCheckpointCompletionPolicy,
    ) -> Result<Self, MissionError> {
        let route = Self {
            capability_id: capability_id.into(),
            executor,
            oracle_ids: oracle_ids.into_iter().collect(),
            completion_policy: Some(completion_policy),
        };
        route.validate()?;
        Ok(route)
    }

    pub fn is_contracted(&self) -> bool {
        !self.oracle_ids.is_empty() && self.completion_policy.is_some()
    }

    fn validate(&self) -> Result<(), MissionError> {
        if self.capability_id.trim().is_empty()
            || self
                .oracle_ids
                .iter()
                .any(|oracle| oracle.trim().is_empty())
            || (self.oracle_ids.is_empty() != self.completion_policy.is_none())
            || self.completion_policy.is_some_and(|policy| {
                !matches!(
                    (self.executor, policy),
                    (
                        MissionCheckpointExecutor::Application,
                        MissionCheckpointCompletionPolicy::DeterministicEvidence
                    ) | (
                        MissionCheckpointExecutor::Runtime,
                        MissionCheckpointCompletionPolicy::WorkProduct
                    ) | (
                        MissionCheckpointExecutor::EffectBroker,
                        MissionCheckpointCompletionPolicy::VerifiedEffect
                    ) | (
                        MissionCheckpointExecutor::Human,
                        MissionCheckpointCompletionPolicy::HumanConfirmation
                    )
                )
            })
        {
            return Err(MissionError::InvalidMissionDefinition);
        }
        Ok(())
    }
}

impl MissionCheckpointStatus {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Running
                | Self::Blocked
                | Self::WaitingUser
                | Self::WaitingApproval
                | Self::Verifying
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Skipped)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCheckpoint {
    pub id: String,
    pub depends_on: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<MissionCheckpointRoute>,
    pub status: MissionCheckpointStatus,
    pub revision: u64,
    pub attempt: u32,
    pub started_at: Option<DateTime<Utc>>,
    pub block: Option<MissionBlock>,
    pub completion: Option<MissionCheckpointCompletion>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCheckpointCompletion {
    pub oracle_ids: BTreeSet<String>,
    pub work_product_ids: BTreeSet<WorkProductId>,
    pub effect_ids: BTreeSet<EffectId>,
    /// Required for contracted Application routes and forbidden for every
    /// other executor. It records only content-free, revision-fenced Oracle
    /// sources; private source records remain in their owning aggregate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_evidence: Option<MissionCheckpointApplicationEvidence>,
    pub evidence_digest: String,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCheckpointOracleSource {
    pub source_kind: String,
    pub source_id: String,
    pub source_revision: u64,
    pub projection_digest: String,
    pub oracle_ids: BTreeSet<String>,
}

/// Content-free proof produced by one named Application handler. Dispatch and
/// verification revisions are both retained so a lost response can be
/// replayed exactly without trusting the current (possibly advanced) source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCheckpointApplicationEvidence {
    pub schema_version: u32,
    pub handler_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub manifest_id: String,
    pub manifest_version: u32,
    pub catalog_digest: String,
    pub cycle: u64,
    pub checkpoint_id: String,
    pub dispatch_mission_revision: u64,
    pub dispatch_checkpoint_revision: u64,
    pub verification_mission_revision: u64,
    pub verification_checkpoint_revision: u64,
    pub capability_id: String,
    pub executor: MissionCheckpointExecutor,
    pub completion_policy: MissionCheckpointCompletionPolicy,
    pub sources: BTreeSet<MissionCheckpointOracleSource>,
    pub observed_at: DateTime<Utc>,
}

impl MissionCheckpointApplicationEvidence {
    pub const SCHEMA_VERSION: u32 = 1;

    /// Stable length-prefixed digest. No source payload, user text, provider
    /// identifier, or secret is included in this proof.
    pub fn digest(&self) -> String {
        let mut digest = Sha256::new();
        hash_field(&mut digest, "hartevo-application-checkpoint-evidence/v1");
        hash_field(&mut digest, &self.schema_version.to_string());
        hash_field(&mut digest, &self.handler_id);
        hash_field(&mut digest, self.tenant_id.as_str());
        hash_field(&mut digest, self.project_id.as_str());
        hash_field(&mut digest, self.mission_id.as_str());
        hash_field(&mut digest, &self.manifest_id);
        hash_field(&mut digest, &self.manifest_version.to_string());
        hash_field(&mut digest, &self.catalog_digest);
        hash_field(&mut digest, &self.cycle.to_string());
        hash_field(&mut digest, &self.checkpoint_id);
        hash_field(&mut digest, &self.dispatch_mission_revision.to_string());
        hash_field(&mut digest, &self.dispatch_checkpoint_revision.to_string());
        hash_field(&mut digest, &self.verification_mission_revision.to_string());
        hash_field(
            &mut digest,
            &self.verification_checkpoint_revision.to_string(),
        );
        hash_field(&mut digest, &self.capability_id);
        hash_field(&mut digest, checkpoint_executor_name(self.executor));
        hash_field(
            &mut digest,
            checkpoint_completion_policy_name(self.completion_policy),
        );
        hash_field(&mut digest, &self.sources.len().to_string());
        for source in &self.sources {
            hash_field(&mut digest, &source.source_kind);
            hash_field(&mut digest, &source.source_id);
            hash_field(&mut digest, &source.source_revision.to_string());
            hash_field(&mut digest, &source.projection_digest);
            hash_field(&mut digest, &source.oracle_ids.len().to_string());
            for oracle_id in &source.oracle_ids {
                hash_field(&mut digest, oracle_id);
            }
        }
        hash_field(&mut digest, &self.observed_at.to_rfc3339());
        format!("{:x}", digest.finalize())
    }
}

impl MissionDefinition {
    #[allow(
        clippy::too_many_arguments,
        reason = "the manifest compiler binds all signed Catalog identity, authority, artifact, oracle, and checkpoint dimensions at one boundary"
    )]
    pub fn from_linear_manifest(
        manifest_id: impl Into<String>,
        manifest_version: u32,
        catalog_digest: impl Into<String>,
        operating_mode: OperatingMode,
        capability_ids: impl IntoIterator<Item = String>,
        required_artifact_types: impl IntoIterator<Item = String>,
        oracle_ids: impl IntoIterator<Item = String>,
        checkpoint_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, MissionError> {
        let checkpoint_routes = checkpoint_ids
            .into_iter()
            .map(|checkpoint_id| (checkpoint_id, None))
            .collect::<Vec<_>>();
        Self::from_manifest_parts(
            manifest_id,
            manifest_version,
            catalog_digest,
            operating_mode,
            capability_ids,
            required_artifact_types,
            oracle_ids,
            checkpoint_routes,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the manifest compiler binds every Checkpoint to one minimal Capability and executor together with the frozen Catalog authority"
    )]
    pub fn from_routed_linear_manifest(
        manifest_id: impl Into<String>,
        manifest_version: u32,
        catalog_digest: impl Into<String>,
        operating_mode: OperatingMode,
        capability_ids: impl IntoIterator<Item = String>,
        required_artifact_types: impl IntoIterator<Item = String>,
        oracle_ids: impl IntoIterator<Item = String>,
        checkpoint_routes: impl IntoIterator<Item = (String, MissionCheckpointRoute)>,
    ) -> Result<Self, MissionError> {
        Self::from_manifest_parts(
            manifest_id,
            manifest_version,
            catalog_digest,
            operating_mode,
            capability_ids,
            required_artifact_types,
            oracle_ids,
            checkpoint_routes
                .into_iter()
                .map(|(checkpoint_id, route)| (checkpoint_id, Some(route)))
                .collect::<Vec<_>>(),
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one private constructor keeps legacy unbound definitions readable while new Catalog definitions are fully routed"
    )]
    fn from_manifest_parts(
        manifest_id: impl Into<String>,
        manifest_version: u32,
        catalog_digest: impl Into<String>,
        operating_mode: OperatingMode,
        capability_ids: impl IntoIterator<Item = String>,
        required_artifact_types: impl IntoIterator<Item = String>,
        oracle_ids: impl IntoIterator<Item = String>,
        checkpoint_routes: Vec<(String, Option<MissionCheckpointRoute>)>,
    ) -> Result<Self, MissionError> {
        let mut previous = None::<String>;
        let checkpoints = checkpoint_routes
            .into_iter()
            .enumerate()
            .map(|(index, (id, route))| {
                let depends_on = previous.iter().cloned().collect();
                previous = Some(id.clone());
                MissionCheckpoint {
                    id,
                    depends_on,
                    route,
                    status: if index == 0 {
                        MissionCheckpointStatus::Ready
                    } else {
                        MissionCheckpointStatus::Pending
                    },
                    revision: 1,
                    attempt: 0,
                    started_at: None,
                    block: None,
                    completion: None,
                }
            })
            .collect();
        let definition = Self {
            manifest_id: manifest_id.into(),
            manifest_version,
            catalog_digest: catalog_digest.into(),
            operating_mode,
            capability_ids: capability_ids.into_iter().collect(),
            required_artifact_types: required_artifact_types.into_iter().collect(),
            oracle_ids: oracle_ids.into_iter().collect(),
            checkpoints,
            cycle: 1,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), MissionError> {
        let ids = self
            .checkpoints
            .iter()
            .map(|checkpoint| checkpoint.id.as_str())
            .collect::<BTreeSet<_>>();
        if self.manifest_id.trim().is_empty()
            || self.manifest_version == 0
            || !is_sha256(&self.catalog_digest)
            || self.capability_ids.is_empty()
            || self.required_artifact_types.is_empty()
            || self.oracle_ids.is_empty()
            || self.checkpoints.is_empty()
            || self.cycle == 0
            || ids.len() != self.checkpoints.len()
            || self
                .capability_ids
                .iter()
                .chain(self.required_artifact_types.iter())
                .chain(self.oracle_ids.iter())
                .any(|value| value.trim().is_empty())
        {
            return Err(MissionError::InvalidMissionDefinition);
        }
        let mut seen = BTreeSet::new();
        let mut ready_count = 0_usize;
        let mut active_count = 0_usize;
        let routed_checkpoint_count = self
            .checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.route.is_some())
            .count();
        if routed_checkpoint_count != 0 && routed_checkpoint_count != self.checkpoints.len() {
            return Err(MissionError::InvalidMissionDefinition);
        }
        if routed_checkpoint_count == self.checkpoints.len() {
            let routes = self
                .checkpoints
                .iter()
                .filter_map(|checkpoint| checkpoint.route.as_ref())
                .collect::<Vec<_>>();
            let routed_capabilities = routes
                .iter()
                .map(|route| route.capability_id.clone())
                .collect::<BTreeSet<_>>();
            let contracted_count = routes.iter().filter(|route| route.is_contracted()).count();
            if routed_capabilities != self.capability_ids
                || (contracted_count != 0 && contracted_count != routes.len())
                || (contracted_count == routes.len()
                    && routes
                        .iter()
                        .flat_map(|route| route.oracle_ids.iter().cloned())
                        .collect::<BTreeSet<_>>()
                        != self.oracle_ids)
            {
                return Err(MissionError::InvalidMissionDefinition);
            }
        }
        for checkpoint in &self.checkpoints {
            if !self.checkpoint_is_valid(checkpoint, &seen) {
                return Err(MissionError::InvalidMissionDefinition);
            }
            ready_count += usize::from(checkpoint.status == MissionCheckpointStatus::Ready);
            active_count += usize::from(checkpoint.status.is_active());
            seen.insert(checkpoint.id.clone());
        }
        if ready_count > 1 || active_count > 1 {
            return Err(MissionError::InvalidMissionDefinition);
        }
        Ok(())
    }

    fn checkpoint_is_valid(&self, checkpoint: &MissionCheckpoint, seen: &BTreeSet<String>) -> bool {
        if checkpoint.id.trim().is_empty()
            || checkpoint.revision == 0
            || checkpoint.route.as_ref().is_some_and(|route| {
                route.validate().is_err()
                    || !self.capability_ids.contains(&route.capability_id)
                    || !route
                        .oracle_ids
                        .iter()
                        .all(|oracle| self.oracle_ids.contains(oracle))
            })
            || checkpoint.depends_on.contains(&checkpoint.id)
            || !checkpoint
                .depends_on
                .iter()
                .all(|dependency| seen.contains(dependency))
            || (checkpoint.attempt == 0 && checkpoint.started_at.is_some())
            || (checkpoint.status == MissionCheckpointStatus::Pending
                && (checkpoint.started_at.is_some()
                    || checkpoint.block.is_some()
                    || checkpoint.completion.is_some()))
            || (checkpoint.status == MissionCheckpointStatus::Ready
                && (checkpoint.block.is_some() || checkpoint.completion.is_some()))
            || (checkpoint.status == MissionCheckpointStatus::Completed
                && checkpoint.completion.is_none())
            || (checkpoint.status != MissionCheckpointStatus::Completed
                && checkpoint.completion.is_some())
            || (matches!(
                checkpoint.status,
                MissionCheckpointStatus::Blocked
                    | MissionCheckpointStatus::WaitingUser
                    | MissionCheckpointStatus::WaitingApproval
            ) != checkpoint.block.is_some())
        {
            return false;
        }
        checkpoint.completion.as_ref().is_none_or(|completion| {
            !completion.oracle_ids.is_empty()
                && completion
                    .oracle_ids
                    .iter()
                    .all(|oracle| self.oracle_ids.contains(oracle))
                && is_sha256(&completion.evidence_digest)
                && checkpoint
                    .started_at
                    .is_some_and(|started_at| completion.verified_at >= started_at)
                && checkpoint.route.as_ref().is_none_or(|route| {
                    route.is_contracted()
                        && completion.oracle_ids == route.oracle_ids
                        && valid_persisted_application_checkpoint_evidence(
                            self, checkpoint, route, completion,
                        )
                        && (!route.oracle_ids.contains("work_product")
                            || !completion.work_product_ids.is_empty())
                        && (!matches!(
                            route.completion_policy,
                            Some(MissionCheckpointCompletionPolicy::VerifiedEffect)
                        ) || !completion.effect_ids.is_empty())
                })
        })
    }

    pub fn active_checkpoint(&self) -> Option<&MissionCheckpoint> {
        self.checkpoints
            .iter()
            .find(|checkpoint| checkpoint.status.is_active())
    }

    pub fn current_checkpoint(&self) -> Option<&MissionCheckpoint> {
        self.active_checkpoint().or_else(|| {
            self.checkpoints
                .iter()
                .find(|checkpoint| checkpoint.status == MissionCheckpointStatus::Ready)
        })
    }

    fn validate_first_checkpoint_tasks(&self, tasks: &[Task]) -> Result<(), MissionError> {
        let Some(checkpoint) = self.checkpoints.first() else {
            return Err(MissionError::InvalidMissionDefinition);
        };
        let Some(route) = checkpoint.route.as_ref() else {
            return Ok(());
        };
        if tasks.is_empty()
            || tasks.iter().any(|task| {
                task.status != TaskStatus::Running
                    || task.title.trim().is_empty()
                    || task.capability != route.capability_id
            })
            || tasks
                .iter()
                .map(|task| &task.id)
                .collect::<BTreeSet<_>>()
                .len()
                != tasks.len()
        {
            return Err(MissionError::MissionCheckpointTaskMismatch {
                checkpoint_id: checkpoint.id.clone(),
                expected_capability: route.capability_id.clone(),
            });
        }
        Ok(())
    }

    fn start_first_checkpoint(&mut self, now: DateTime<Utc>) -> Result<(), MissionError> {
        let checkpoint = self
            .checkpoints
            .first_mut()
            .ok_or(MissionError::InvalidMissionDefinition)?;
        if checkpoint.status != MissionCheckpointStatus::Ready
            || checkpoint.attempt != 0
            || checkpoint.started_at.is_some()
        {
            return Err(MissionError::InvalidCheckpointTransition {
                checkpoint_id: checkpoint.id.clone(),
                from: checkpoint.status,
                to: MissionCheckpointStatus::Running,
            });
        }
        checkpoint.status = MissionCheckpointStatus::Running;
        checkpoint.attempt = 1;
        checkpoint.started_at = Some(now);
        checkpoint.revision += 1;
        Ok(())
    }

    fn reset_for_next_cycle(&mut self, cycle: u64) -> Result<(), MissionError> {
        if self.cycle.checked_add(1) != Some(cycle)
            || !self
                .checkpoints
                .iter()
                .all(|checkpoint| checkpoint.status.is_terminal())
        {
            return Err(MissionError::MissionCycleCheckpointIncomplete);
        }
        for (index, checkpoint) in self.checkpoints.iter_mut().enumerate() {
            checkpoint.status = if index == 0 {
                MissionCheckpointStatus::Ready
            } else {
                MissionCheckpointStatus::Pending
            };
            checkpoint.revision = checkpoint
                .revision
                .checked_add(1)
                .ok_or(MissionError::RevisionOverflow)?;
            checkpoint.attempt = 0;
            checkpoint.started_at = None;
            checkpoint.block = None;
            checkpoint.completion = None;
        }
        self.cycle = cycle;
        self.validate()
    }

    fn set_active_status(
        &mut self,
        status: MissionCheckpointStatus,
        block: Option<MissionBlock>,
    ) -> Result<(), MissionError> {
        let checkpoint = self
            .checkpoints
            .iter_mut()
            .find(|checkpoint| checkpoint.status.is_active())
            .ok_or(MissionError::InvalidMissionDefinition)?;
        checkpoint.status = status;
        checkpoint.block = block;
        checkpoint.revision = checkpoint
            .revision
            .checked_add(1)
            .ok_or(MissionError::RevisionOverflow)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Mission {
    #[serde(default = "legacy_tenant_id")]
    pub tenant_id: TenantId,
    pub id: MissionId,
    pub project_id: ProjectId,
    pub title: String,
    pub contract: MissionContract,
    #[serde(default)]
    pub definition: Option<MissionDefinition>,
    pub stage: MissionStage,
    pub tasks: Vec<Task>,
    pub evidence: Vec<Evidence>,
    pub work_products: Vec<WorkProduct>,
    pub effects: Vec<Effect>,
    /// Append-only cycle history. `outcome` remains the latest projection for clients.
    #[serde(default)]
    pub outcome_history: Vec<Outcome>,
    #[serde(default)]
    pub outcome: Option<Outcome>,
    #[serde(default)]
    pub block: Option<MissionBlock>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revision: u64,
}

impl Mission {
    pub fn compile(
        tenant_id: TenantId,
        id: MissionId,
        project_id: ProjectId,
        title: impl Into<String>,
        contract: MissionContract,
        now: DateTime<Utc>,
    ) -> Result<Self, MissionError> {
        let title = title.into().trim().to_owned();
        if title.is_empty() || contract.goal.trim().is_empty() {
            return Err(MissionError::EmptyMission);
        }
        contract.validate(now)?;

        Ok(Self {
            tenant_id,
            id,
            project_id,
            title,
            contract,
            definition: None,
            stage: MissionStage::Ready,
            tasks: Vec::new(),
            evidence: Vec::new(),
            work_products: Vec::new(),
            effects: Vec::new(),
            outcome_history: Vec::new(),
            outcome: None,
            block: None,
            created_at: now,
            updated_at: now,
            revision: 1,
        })
    }

    pub fn compile_catalog(
        tenant_id: TenantId,
        id: MissionId,
        project_id: ProjectId,
        title: impl Into<String>,
        contract: MissionContract,
        definition: MissionDefinition,
        now: DateTime<Utc>,
    ) -> Result<Self, MissionError> {
        definition.validate()?;
        if definition.operating_mode != contract.mode
            || definition.capability_ids != contract.enabled_capabilities
            || !definition
                .capability_ids
                .is_disjoint(&contract.forbidden_capabilities)
        {
            return Err(MissionError::MissionDefinitionContractMismatch);
        }
        let mut mission = Self::compile(tenant_id, id, project_id, title, contract, now)?;
        mission.definition = Some(definition);
        Ok(mission)
    }

    /// Revalidates persisted Application Checkpoint evidence against the
    /// owning aggregate scope. Storage and encrypted-sync decoders call this
    /// after reconstructing the normalized Mission, so projection tampering
    /// cannot swap tenant/project/Mission identity around an otherwise valid
    /// content-free proof.
    pub fn validate_checkpoint_evidence_scope(&self) -> Result<(), MissionError> {
        let Some(definition) = &self.definition else {
            return Ok(());
        };
        definition.validate()?;
        for checkpoint in &definition.checkpoints {
            let Some(evidence) = checkpoint
                .completion
                .as_ref()
                .and_then(|completion| completion.application_evidence.as_ref())
            else {
                continue;
            };
            if evidence.tenant_id != self.tenant_id
                || evidence.project_id != self.project_id
                || evidence.mission_id != self.id
                || evidence.verification_mission_revision >= self.revision
            {
                return Err(MissionError::InvalidCheckpointCompletion(
                    checkpoint.id.clone(),
                ));
            }
        }
        Ok(())
    }

    pub fn start_research(
        &mut self,
        tasks: impl IntoIterator<Item = Task>,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Ready])?;
        let tasks = tasks.into_iter().collect::<Vec<_>>();
        if let Some(definition) = &self.definition {
            definition.validate_first_checkpoint_tasks(&tasks)?;
        }
        self.ensure_touchable()?;
        if let Some(definition) = &mut self.definition {
            definition.start_first_checkpoint(now)?;
        }
        self.tasks.extend(tasks);
        self.stage = MissionStage::Running;
        self.block = None;
        self.touch(now);
        Ok(())
    }

    /// Starts one exact durable Scheduler-owned cycle.
    ///
    /// A caller cannot use this method for the first cycle or skip a cycle.
    /// Catalog Checkpoints are reset only after the previous DAG is entirely
    /// terminal, preserving each prior cycle through Outcome/trace evidence.
    pub fn start_scheduled_cycle(
        &mut self,
        cycle: u64,
        tasks: impl IntoIterator<Item = Task>,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Scheduled])?;
        self.contract.validate(now)?;
        let tasks = tasks.into_iter().collect::<Vec<_>>();
        let expected_cycle = u64::try_from(self.outcome_history.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(MissionError::RevisionOverflow)?;
        if cycle != expected_cycle || cycle < 2 {
            return Err(MissionError::InvalidMissionCycle {
                expected: expected_cycle,
                actual: cycle,
            });
        }
        if let Some(definition) = &self.definition {
            definition.validate_first_checkpoint_tasks(&tasks)?;
        }
        self.ensure_touchable()?;
        if let Some(definition) = &mut self.definition {
            definition.reset_for_next_cycle(cycle)?;
            definition.start_first_checkpoint(now)?;
        }
        self.tasks.extend(tasks);
        self.stage = MissionStage::Running;
        self.block = None;
        self.touch(now);
        Ok(())
    }

    pub fn record_evidence(
        &mut self,
        evidence: Evidence,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Running])?;
        if self.evidence.iter().any(|item| item.id == evidence.id) {
            return Err(MissionError::DuplicateEvidence(evidence.id));
        }
        self.ensure_touchable()?;
        self.evidence.push(evidence);
        self.touch(now);
        Ok(())
    }

    pub fn record_work_product(
        &mut self,
        mut work_product: WorkProduct,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Running])?;
        work_product.validate()?;
        if work_product.revision != 1 || work_product.status != WorkProductStatus::Draft {
            return Err(MissionError::InvalidWorkProduct(work_product.id));
        }
        if self
            .work_products
            .iter()
            .any(|item| item.id == work_product.id)
        {
            return Err(MissionError::DuplicateWorkProduct(work_product.id));
        }
        for evidence_id in &work_product.evidence_ids {
            if !self.evidence.iter().any(|item| &item.id == evidence_id) {
                return Err(MissionError::UnknownEvidence(evidence_id.clone()));
            }
        }
        self.ensure_touchable()?;
        work_product.status = WorkProductStatus::ReadyForReview;
        self.work_products.push(work_product);
        self.touch(now);
        Ok(())
    }

    pub fn revise_work_product(
        &mut self,
        work_product: WorkProduct,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.require_stage(&[
            MissionStage::Running,
            MissionStage::WaitingUser,
            MissionStage::WaitingApproval,
            MissionStage::Verifying,
        ])?;
        let index = self
            .work_products
            .iter()
            .position(|item| item.id == work_product.id)
            .ok_or_else(|| MissionError::UnknownWorkProduct(work_product.id.clone()))?;
        if !work_product.follows(&self.work_products[index])? {
            return Err(MissionError::InvalidWorkProductTransition(
                work_product.id.clone(),
            ));
        }
        for evidence_id in &work_product.evidence_ids {
            if !self.evidence.iter().any(|item| &item.id == evidence_id) {
                return Err(MissionError::UnknownEvidence(evidence_id.clone()));
            }
        }
        self.ensure_touchable()?;
        self.work_products[index] = work_product;
        self.touch(now);
        Ok(())
    }

    pub fn begin_checkpoint(
        &mut self,
        checkpoint_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        if let Some(route) = self
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == checkpoint_id)
            })
            .and_then(|checkpoint| checkpoint.route.as_ref())
        {
            return Err(MissionError::MissionCheckpointTaskMismatch {
                checkpoint_id: checkpoint_id.to_owned(),
                expected_capability: route.capability_id.clone(),
            });
        }
        self.begin_checkpoint_transition(checkpoint_id, now)
    }

    pub fn begin_checkpoint_with_task(
        &mut self,
        checkpoint_id: &str,
        task: Task,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        let route = self
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == checkpoint_id)
            })
            .and_then(|checkpoint| checkpoint.route.as_ref())
            .ok_or(MissionError::MissionDefinitionRequired)?;
        if task.status != TaskStatus::Running
            || task.title.trim().is_empty()
            || task.capability != route.capability_id
            || self.tasks.iter().any(|existing| existing.id == task.id)
        {
            return Err(MissionError::MissionCheckpointTaskMismatch {
                checkpoint_id: checkpoint_id.to_owned(),
                expected_capability: route.capability_id.clone(),
            });
        }
        self.begin_checkpoint_transition(checkpoint_id, now)?;
        self.tasks.push(task);
        Ok(())
    }

    fn begin_checkpoint_transition(
        &mut self,
        checkpoint_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Running])?;
        self.ensure_touchable()?;
        let definition = self
            .definition
            .as_mut()
            .ok_or(MissionError::MissionDefinitionRequired)?;
        let completed = definition
            .checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status == MissionCheckpointStatus::Completed)
            .map(|checkpoint| checkpoint.id.clone())
            .collect::<BTreeSet<_>>();
        let checkpoint = definition
            .checkpoints
            .iter_mut()
            .find(|checkpoint| checkpoint.id == checkpoint_id)
            .ok_or_else(|| MissionError::MissionCheckpointNotFound(checkpoint_id.to_owned()))?;
        if checkpoint.status != MissionCheckpointStatus::Ready {
            return Err(MissionError::InvalidCheckpointTransition {
                checkpoint_id: checkpoint.id.clone(),
                from: checkpoint.status,
                to: MissionCheckpointStatus::Running,
            });
        }
        if !checkpoint
            .depends_on
            .iter()
            .all(|dependency| completed.contains(dependency))
        {
            return Err(MissionError::CheckpointDependencyIncomplete(
                checkpoint.id.clone(),
            ));
        }
        checkpoint.status = MissionCheckpointStatus::Running;
        checkpoint.attempt = checkpoint
            .attempt
            .checked_add(1)
            .ok_or(MissionError::InvalidMissionDefinition)?;
        checkpoint.started_at = Some(now);
        checkpoint.block = None;
        checkpoint.revision = checkpoint
            .revision
            .checked_add(1)
            .ok_or(MissionError::RevisionOverflow)?;
        self.touch(now);
        Ok(())
    }

    pub fn begin_checkpoint_verification(
        &mut self,
        checkpoint_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Running])?;
        if self.effects.iter().any(|effect| {
            matches!(
                effect.status,
                EffectStatus::Proposed
                    | EffectStatus::Approved
                    | EffectStatus::Executing
                    | EffectStatus::ReceiptRecorded
                    | EffectStatus::VerificationRequired
            )
        }) {
            return Err(MissionError::JourneyContinuationNotReady);
        }
        self.ensure_touchable()?;
        let definition = self
            .definition
            .as_mut()
            .ok_or(MissionError::MissionDefinitionRequired)?;
        let checkpoint = definition
            .checkpoints
            .iter_mut()
            .find(|checkpoint| checkpoint.id == checkpoint_id)
            .ok_or_else(|| MissionError::MissionCheckpointNotFound(checkpoint_id.to_owned()))?;
        if checkpoint.status != MissionCheckpointStatus::Running {
            return Err(MissionError::InvalidCheckpointTransition {
                checkpoint_id: checkpoint.id.clone(),
                from: checkpoint.status,
                to: MissionCheckpointStatus::Verifying,
            });
        }
        checkpoint.status = MissionCheckpointStatus::Verifying;
        checkpoint.revision = checkpoint
            .revision
            .checked_add(1)
            .ok_or(MissionError::RevisionOverflow)?;
        self.stage = MissionStage::Verifying;
        self.touch(now);
        Ok(())
    }

    fn validated_checkpoint_completion_route(
        &self,
        checkpoint_id: &str,
        completion: &MissionCheckpointCompletion,
    ) -> Result<Option<MissionCheckpointRoute>, MissionError> {
        let definition = self
            .definition
            .as_ref()
            .ok_or(MissionError::MissionDefinitionRequired)?;
        let checkpoint = definition
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.id == checkpoint_id)
            .ok_or_else(|| MissionError::MissionCheckpointNotFound(checkpoint_id.to_owned()))?;
        let checkpoint_route = checkpoint.route.clone();
        let invalid = completion.oracle_ids.is_empty()
            || !completion
                .oracle_ids
                .iter()
                .all(|oracle_id| definition.oracle_ids.contains(oracle_id))
            || !is_sha256(&completion.evidence_digest)
            || !completion.work_product_ids.iter().all(|work_product_id| {
                self.work_products
                    .iter()
                    .any(|work_product| &work_product.id == work_product_id)
            })
            || !completion.effect_ids.iter().all(|effect_id| {
                self.effects.iter().any(|effect| {
                    &effect.id == effect_id && effect.status == EffectStatus::Verified
                })
            })
            || checkpoint_route.as_ref().is_some_and(|route| {
                !route.is_contracted()
                    || completion.oracle_ids != route.oracle_ids
                    || !valid_application_checkpoint_evidence(
                        self, definition, checkpoint, route, completion,
                    )
                    || route.oracle_ids.contains("work_product")
                        && completion.work_product_ids.is_empty()
                    || matches!(
                        route.completion_policy,
                        Some(MissionCheckpointCompletionPolicy::VerifiedEffect)
                    ) && completion.effect_ids.is_empty()
                    || !self.tasks.iter().any(|task| {
                        task.status == TaskStatus::Running && task.capability == route.capability_id
                    })
            });
        if invalid {
            return Err(MissionError::InvalidCheckpointCompletion(
                checkpoint_id.to_owned(),
            ));
        }
        Ok(checkpoint_route)
    }

    pub fn complete_checkpoint(
        &mut self,
        checkpoint_id: &str,
        completion: MissionCheckpointCompletion,
    ) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Verifying])?;
        let checkpoint_route =
            self.validated_checkpoint_completion_route(checkpoint_id, &completion)?;
        self.ensure_touchable()?;
        let definition = self
            .definition
            .as_mut()
            .ok_or(MissionError::MissionDefinitionRequired)?;
        let checkpoint = definition
            .checkpoints
            .iter_mut()
            .find(|checkpoint| checkpoint.id == checkpoint_id)
            .ok_or_else(|| MissionError::MissionCheckpointNotFound(checkpoint_id.to_owned()))?;
        if checkpoint.status != MissionCheckpointStatus::Verifying
            || checkpoint
                .started_at
                .is_none_or(|started_at| completion.verified_at < started_at)
        {
            return Err(MissionError::InvalidCheckpointTransition {
                checkpoint_id: checkpoint.id.clone(),
                from: checkpoint.status,
                to: MissionCheckpointStatus::Completed,
            });
        }
        let verified_at = completion.verified_at;
        checkpoint.status = MissionCheckpointStatus::Completed;
        checkpoint.completion = Some(completion);
        checkpoint.block = None;
        checkpoint.revision = checkpoint
            .revision
            .checked_add(1)
            .ok_or(MissionError::RevisionOverflow)?;

        if let Some(route) = checkpoint_route {
            for task in &mut self.tasks {
                if task.status == TaskStatus::Running && task.capability == route.capability_id {
                    task.status = TaskStatus::Completed;
                }
            }
        }

        let completed = definition
            .checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status == MissionCheckpointStatus::Completed)
            .map(|checkpoint| checkpoint.id.clone())
            .collect::<BTreeSet<_>>();
        let next = definition.checkpoints.iter_mut().find(|candidate| {
            candidate.status == MissionCheckpointStatus::Pending
                && candidate
                    .depends_on
                    .iter()
                    .all(|dependency| completed.contains(dependency))
        });
        if let Some(next) = next {
            next.status = MissionCheckpointStatus::Ready;
            next.revision = next
                .revision
                .checked_add(1)
                .ok_or(MissionError::RevisionOverflow)?;
            self.stage = MissionStage::Running;
        } else {
            self.stage = MissionStage::Verifying;
        }
        self.touch(verified_at);
        Ok(())
    }

    pub fn block_checkpoint(
        &mut self,
        checkpoint_id: &str,
        block: &MissionBlock,
        waiting_stage: MissionStage,
    ) -> Result<(), MissionError> {
        if !matches!(
            waiting_stage,
            MissionStage::Blocked | MissionStage::WaitingUser | MissionStage::WaitingApproval
        ) || block.code.trim().is_empty()
            || block.detail.trim().is_empty()
        {
            return Err(MissionError::InvalidBlock);
        }
        self.require_stage(&[MissionStage::Running, MissionStage::Verifying])?;
        self.ensure_touchable()?;
        let definition = self
            .definition
            .as_mut()
            .ok_or(MissionError::MissionDefinitionRequired)?;
        let checkpoint = definition
            .checkpoints
            .iter_mut()
            .find(|checkpoint| checkpoint.id == checkpoint_id)
            .ok_or_else(|| MissionError::MissionCheckpointNotFound(checkpoint_id.to_owned()))?;
        if !matches!(
            checkpoint.status,
            MissionCheckpointStatus::Running | MissionCheckpointStatus::Verifying
        ) {
            return Err(MissionError::InvalidCheckpointTransition {
                checkpoint_id: checkpoint.id.clone(),
                from: checkpoint.status,
                to: checkpoint_status_for_mission_stage(&waiting_stage)?,
            });
        }
        checkpoint.status = checkpoint_status_for_mission_stage(&waiting_stage)?;
        checkpoint.block = Some(block.clone());
        checkpoint.revision = checkpoint
            .revision
            .checked_add(1)
            .ok_or(MissionError::RevisionOverflow)?;
        self.block = Some(block.clone());
        self.stage = waiting_stage;
        self.touch(block.observed_at);
        Ok(())
    }

    pub fn propose_effect(
        &mut self,
        spec: EffectSpec,
        now: DateTime<Utc>,
    ) -> Result<EffectId, MissionError> {
        self.require_stage(&[MissionStage::Running, MissionStage::WaitingApproval])?;
        self.validate_effect_spec(&spec, now)?;
        self.ensure_touchable()?;
        let effect_id = spec.id.clone();
        self.effects.push(Effect {
            id: spec.id,
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            mission_id: self.id.clone(),
            actor_id: spec.actor_id,
            capability: spec.capability,
            provider: spec.provider,
            connection_id: spec.connection_id,
            account_id: spec.account_id,
            required_scopes: spec.required_scopes,
            effect_class: spec.effect_class,
            description: spec.description,
            target_resource: spec.target_resource,
            audience_digest: spec.audience_digest,
            payload_digest: spec.payload_digest,
            asset_digests: spec.asset_digests,
            scheduled_for: spec.scheduled_for,
            timezone: spec.timezone,
            consent: spec.consent,
            consent_record_id: spec.consent_record_id,
            consent_requirement: spec.consent_requirement,
            conversation_guard: spec.conversation_guard,
            creator_contact_guard: spec.creator_contact_guard,
            policy_version: spec.policy_version,
            risk: spec.risk,
            idempotency_key: spec.idempotency_key,
            amount: spec.amount,
            expires_at: spec.expires_at,
            status: EffectStatus::Proposed,
            approval: None,
            receipt: None,
            verification: None,
        });
        if self.definition.is_some() {
            let block = MissionBlock {
                code: "effect_approval_required".into(),
                detail: format!("effect {effect_id} requires an exact, time-bounded approval"),
                recoverable: true,
                observed_at: now,
            };
            self.set_catalog_checkpoint_status(
                MissionCheckpointStatus::WaitingApproval,
                Some(block.clone()),
            )?;
            self.block = Some(block);
        }
        self.stage = MissionStage::WaitingApproval;
        self.touch(now);
        Ok(effect_id)
    }

    fn validate_effect_spec(
        &self,
        spec: &EffectSpec,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        if self
            .contract
            .forbidden_capabilities
            .contains(&spec.capability)
            || !self
                .contract
                .enabled_capabilities
                .contains(&spec.capability)
        {
            return Err(MissionError::CapabilityNotEnabled(spec.capability.clone()));
        }
        if spec.idempotency_key.trim().is_empty() {
            return Err(MissionError::EmptyIdempotencyKey);
        }
        if spec.amount.amount_minor < 0 {
            return Err(MissionError::NegativeCostLimit);
        }
        if spec.effect_class == EffectClass::Payment && !spec.amount.is_positive() {
            return Err(MissionError::PaymentAmountNotPositive);
        }
        if spec.effect_class == EffectClass::Payment
            && (spec.connection_id.is_none() || spec.account_id.is_none())
        {
            return Err(MissionError::InvalidEffectScope);
        }
        validate_effect_connection_scope(spec)?;
        validate_effect_content_scope(spec, now)?;
        validate_effect_consent_scope(spec)?;
        if self
            .effects
            .iter()
            .any(|effect| effect.idempotency_key == spec.idempotency_key)
        {
            return Err(MissionError::DuplicateIdempotencyKey(
                spec.idempotency_key.clone(),
            ));
        }
        Ok(())
    }

    pub fn effect(&self, effect_id: &EffectId) -> Result<&Effect, MissionError> {
        self.effects
            .iter()
            .find(|effect| &effect.id == effect_id)
            .ok_or_else(|| MissionError::UnknownEffect(effect_id.clone()))
    }

    pub fn approve_effect(
        &mut self,
        effect_id: &EffectId,
        approval: Approval,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        let now = approval.decided_at;
        let expected_valid_until = self.approval_valid_until(effect_id, now)?;
        {
            let effect = self.effect_mut(effect_id)?;
            if effect.status != EffectStatus::Proposed {
                return Err(MissionError::InvalidEffectTransition {
                    from: effect.status.clone(),
                    to: EffectStatus::Approved,
                });
            }
            if approval.scope_digest != effect.approval_digest() {
                return Err(MissionError::ApprovalScopeChanged);
            }
            if approval.id.as_str().trim().is_empty()
                || !is_sha256(&approval.permission_digest)
                || approval.decided_at >= effect.expires_at
                || approval.valid_until != expected_valid_until
            {
                return Err(MissionError::InvalidApproval);
            }
            if approval.decision == ApprovalDecision::Rejected {
                effect.status = EffectStatus::Rejected;
            } else {
                effect.status = EffectStatus::Approved;
            }
            effect.approval = Some(approval);
        }
        self.stage = if self
            .effects
            .iter()
            .any(|effect| effect.status == EffectStatus::Proposed)
        {
            MissionStage::WaitingApproval
        } else {
            MissionStage::Running
        };
        if self.definition.is_some() && self.stage == MissionStage::Running {
            self.set_catalog_checkpoint_status(MissionCheckpointStatus::Running, None)?;
            self.block = None;
        }
        self.touch(now);
        Ok(())
    }

    pub fn approval_valid_until(
        &self,
        effect_id: &EffectId,
        decided_at: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, MissionError> {
        let effect = self.effect(effect_id)?;
        let validity_seconds = i64::try_from(self.contract.approval_policy.validity_seconds)
            .map_err(|_| MissionError::InvalidApproval)?;
        let policy_deadline = decided_at
            .checked_add_signed(chrono::Duration::seconds(validity_seconds))
            .ok_or(MissionError::InvalidApproval)?;
        let valid_until = policy_deadline
            .min(effect.expires_at)
            .min(self.contract.valid_until);
        if validity_seconds <= 0 || valid_until <= decided_at {
            return Err(MissionError::InvalidApproval);
        }
        Ok(valid_until)
    }

    pub fn cancel_effect(
        &mut self,
        effect_id: &EffectId,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        let effect = self.effect_mut(effect_id)?;
        if !matches!(
            effect.status,
            EffectStatus::Proposed | EffectStatus::Approved
        ) {
            return Err(MissionError::InvalidEffectTransition {
                from: effect.status.clone(),
                to: EffectStatus::Cancelled,
            });
        }
        effect.status = EffectStatus::Cancelled;
        self.stage = if self
            .effects
            .iter()
            .any(|candidate| candidate.status == EffectStatus::Proposed)
        {
            MissionStage::WaitingApproval
        } else {
            MissionStage::Running
        };
        if self.definition.is_some() && self.stage == MissionStage::Running {
            self.set_catalog_checkpoint_status(MissionCheckpointStatus::Running, None)?;
            self.block = None;
        }
        self.touch(now);
        Ok(())
    }

    pub fn begin_effect(
        &mut self,
        effect_id: &EffectId,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        let effect = self.effect_mut(effect_id)?;
        if effect.status != EffectStatus::Approved {
            return Err(MissionError::InvalidEffectTransition {
                from: effect.status.clone(),
                to: EffectStatus::Executing,
            });
        }
        let approval = effect
            .approval
            .as_ref()
            .ok_or(MissionError::MissingApproval)?;
        if approval.scope_digest != effect.approval_digest() {
            return Err(MissionError::ApprovalScopeChanged);
        }
        if now >= approval.valid_until {
            effect.status = EffectStatus::Expired;
            return Err(MissionError::ApprovalExpired);
        }
        if now >= effect.expires_at {
            effect.status = EffectStatus::Expired;
            return Err(MissionError::EffectExpired);
        }
        effect.status = EffectStatus::Executing;
        self.stage = MissionStage::Running;
        self.touch(now);
        Ok(())
    }

    pub fn record_receipt(
        &mut self,
        effect_id: &EffectId,
        receipt: Receipt,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        let now = receipt.accepted_at;
        {
            let effect = self.effect_mut(effect_id)?;
            if effect.status != EffectStatus::Executing {
                return Err(MissionError::InvalidEffectTransition {
                    from: effect.status.clone(),
                    to: EffectStatus::ReceiptRecorded,
                });
            }
            validate_receipt_scope(effect, &receipt)?;
            effect.receipt = Some(receipt);
            effect.status = EffectStatus::ReceiptRecorded;
        }
        self.stage = MissionStage::Verifying;
        self.set_catalog_checkpoint_status(MissionCheckpointStatus::Verifying, None)?;
        self.touch(now);
        Ok(())
    }

    /// Projects a Receipt that was already committed by the durable execution
    /// ledger before the Mission snapshot was persisted. This command never
    /// authorizes a Provider call: it requires the original execution start to
    /// fall inside the exact approval dispatch window.
    pub fn reconcile_durable_receipt(
        &mut self,
        effect_id: &EffectId,
        receipt: Receipt,
        execution_started_at: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        let now = receipt.accepted_at;
        {
            let effect = self.effect_mut(effect_id)?;
            if !matches!(
                effect.status,
                EffectStatus::Approved
                    | EffectStatus::Executing
                    | EffectStatus::ReceiptRecorded
                    | EffectStatus::VerificationRequired
            ) {
                return Err(MissionError::InvalidEffectTransition {
                    from: effect.status.clone(),
                    to: EffectStatus::ReceiptRecorded,
                });
            }
            let approval = effect
                .approval
                .as_ref()
                .ok_or(MissionError::MissingApproval)?;
            if !durable_execution_start_is_valid(effect, approval, execution_started_at)
                || receipt.accepted_at < execution_started_at
            {
                return Err(MissionError::DurableReceiptRecoveryMismatch);
            }
            validate_receipt_scope(effect, &receipt)?;
            if effect.status == EffectStatus::ReceiptRecorded {
                return if effect.receipt.as_ref() == Some(&receipt) {
                    Ok(())
                } else {
                    Err(MissionError::DurableReceiptRecoveryMismatch)
                };
            }
            effect.receipt = Some(receipt);
            effect.status = EffectStatus::ReceiptRecorded;
        }
        self.stage = MissionStage::Verifying;
        self.touch(now);
        Ok(())
    }

    /// Projects a Provider rejection or uncertain result that was already
    /// committed to the durable execution ledger. The original execution start
    /// must prove that dispatch happened inside the exact approval window; the
    /// current approval or Connection does not need to remain live because this
    /// command can never call the Provider.
    pub fn reconcile_durable_provider_state(
        &mut self,
        effect_id: &EffectId,
        durable_state: DurableProviderState,
        execution_started_at: DateTime<Utc>,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        let target = match durable_state {
            DurableProviderState::Rejected => EffectStatus::Failed,
            DurableProviderState::Uncertain => EffectStatus::VerificationRequired,
            DurableProviderState::ReconciledNotExecuted => EffectStatus::Reconciled,
            DurableProviderState::DeadLetter => EffectStatus::DeadLetter,
        };
        {
            let effect = self.effect_mut(effect_id)?;
            let transition_allowed = match durable_state {
                DurableProviderState::Rejected => matches!(
                    effect.status,
                    EffectStatus::Approved
                        | EffectStatus::Executing
                        | EffectStatus::VerificationRequired
                        | EffectStatus::Failed
                ),
                DurableProviderState::Uncertain => matches!(
                    effect.status,
                    EffectStatus::Approved
                        | EffectStatus::Executing
                        | EffectStatus::VerificationRequired
                ),
                DurableProviderState::ReconciledNotExecuted => matches!(
                    effect.status,
                    EffectStatus::Approved
                        | EffectStatus::Executing
                        | EffectStatus::VerificationRequired
                        | EffectStatus::Reconciled
                ),
                DurableProviderState::DeadLetter => matches!(
                    effect.status,
                    EffectStatus::VerificationRequired | EffectStatus::DeadLetter
                ),
            };
            if !transition_allowed {
                return Err(MissionError::InvalidEffectTransition {
                    from: effect.status.clone(),
                    to: target,
                });
            }
            let approval = effect
                .approval
                .as_ref()
                .ok_or(MissionError::MissingApproval)?;
            if !durable_execution_start_is_valid(effect, approval, execution_started_at)
                || recorded_at < execution_started_at
            {
                return Err(MissionError::DurableProviderRecoveryMismatch);
            }
            if effect.status == target {
                return Ok(());
            }
            effect.status = target;
        }
        match durable_state {
            DurableProviderState::Rejected => {
                self.stage = MissionStage::Blocked;
                self.block = Some(MissionBlock {
                    code: "effect_failed".into(),
                    detail: format!(
                        "effect {effect_id} requires recovery or an explicit terminal decision"
                    ),
                    recoverable: true,
                    observed_at: recorded_at,
                });
            }
            DurableProviderState::Uncertain => {
                self.stage = MissionStage::Verifying;
            }
            DurableProviderState::ReconciledNotExecuted => {
                self.stage = MissionStage::Blocked;
                self.block = Some(MissionBlock {
                    code: "effect_reconciled_not_executed".into(),
                    detail: format!(
                        "effect {effect_id} was independently reconciled as not executed; any retry requires a new exact effect and approval"
                    ),
                    recoverable: true,
                    observed_at: recorded_at,
                });
            }
            DurableProviderState::DeadLetter => {
                self.stage = MissionStage::Blocked;
                self.block = Some(MissionBlock {
                    code: "effect_reconciliation_dead_letter".into(),
                    detail: format!(
                        "effect {effect_id} exhausted bounded reconciliation and requires explicit support review"
                    ),
                    recoverable: true,
                    observed_at: recorded_at,
                });
            }
        }
        self.touch(recorded_at);
        Ok(())
    }

    pub fn mark_effect_uncertain(
        &mut self,
        effect_id: &EffectId,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        let effect = self.effect_mut(effect_id)?;
        if !matches!(
            effect.status,
            EffectStatus::Executing | EffectStatus::ReceiptRecorded
        ) {
            return Err(MissionError::InvalidEffectTransition {
                from: effect.status.clone(),
                to: EffectStatus::VerificationRequired,
            });
        }
        effect.status = EffectStatus::VerificationRequired;
        self.stage = MissionStage::Verifying;
        self.set_catalog_checkpoint_status(MissionCheckpointStatus::Verifying, None)?;
        self.touch(now);
        Ok(())
    }

    pub fn mark_effect_failed(
        &mut self,
        effect_id: &EffectId,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        {
            let effect = self.effect_mut(effect_id)?;
            if effect.status != EffectStatus::Executing {
                return Err(MissionError::InvalidEffectTransition {
                    from: effect.status.clone(),
                    to: EffectStatus::Failed,
                });
            }
            effect.status = EffectStatus::Failed;
        }
        self.stage = MissionStage::Blocked;
        let block = MissionBlock {
            code: "effect_failed".into(),
            detail: format!(
                "effect {effect_id} requires recovery or an explicit terminal decision"
            ),
            recoverable: true,
            observed_at: now,
        };
        self.set_catalog_checkpoint_status(MissionCheckpointStatus::Blocked, Some(block.clone()))?;
        self.block = Some(block);
        self.touch(now);
        Ok(())
    }

    pub fn record_verification(
        &mut self,
        effect_id: &EffectId,
        verification: Verification,
    ) -> Result<(), MissionError> {
        self.ensure_touchable()?;
        let now = verification.observed_at;
        {
            let effect = self.effect_mut(effect_id)?;
            if !matches!(
                effect.status,
                EffectStatus::ReceiptRecorded | EffectStatus::VerificationRequired
            ) {
                return Err(MissionError::InvalidEffectTransition {
                    from: effect.status.clone(),
                    to: EffectStatus::Verified,
                });
            }
            let receipt = effect
                .receipt
                .as_ref()
                .ok_or(MissionError::VerificationReceiptMismatch)?;
            if receipt.id != verification.receipt_id
                || verification.verifier.trim().is_empty()
                || !verification.independent
                || !is_sha256(&verification.evidence_digest)
                || verification.observed_at < receipt.accepted_at
            {
                return Err(MissionError::VerificationReceiptMismatch);
            }

            effect.status = match verification.status {
                VerificationStatus::Confirmed => EffectStatus::Verified,
                VerificationStatus::Rejected => EffectStatus::Failed,
                VerificationStatus::Inconclusive => EffectStatus::VerificationRequired,
            };
            effect.verification = Some(verification);
        }
        self.stage = if self
            .effects
            .iter()
            .any(|item| item.status == EffectStatus::Failed)
        {
            MissionStage::Blocked
        } else {
            MissionStage::Verifying
        };
        if self.stage == MissionStage::Blocked {
            let block = MissionBlock {
                code: "verification_rejected".into(),
                detail: "independent verification rejected at least one provider effect".into(),
                recoverable: true,
                observed_at: now,
            };
            self.set_catalog_checkpoint_status(
                MissionCheckpointStatus::Blocked,
                Some(block.clone()),
            )?;
            self.block = Some(block);
        } else {
            self.set_catalog_checkpoint_status(MissionCheckpointStatus::Verifying, None)?;
        }
        self.touch(now);
        Ok(())
    }

    /// Continue a multi-effect journey after an independently verified intermediate effect.
    ///
    /// This is deliberately explicit: verification does not complete a Mission and it does
    /// not create an Outcome. The caller must name the exact verified effect, and every other
    /// effect must already be terminal before the Mission may accept the next checkpoint effect.
    pub fn continue_after_verified_effect(
        &mut self,
        effect_id: &EffectId,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Verifying])?;
        if self.effect(effect_id)?.status != EffectStatus::Verified
            || self.effects.iter().any(|effect| {
                matches!(
                    effect.status,
                    EffectStatus::Proposed
                        | EffectStatus::Approved
                        | EffectStatus::Executing
                        | EffectStatus::ReceiptRecorded
                        | EffectStatus::VerificationRequired
                        | EffectStatus::Failed
                )
            })
        {
            return Err(MissionError::JourneyContinuationNotReady);
        }
        self.ensure_touchable()?;
        self.stage = MissionStage::Running;
        self.set_catalog_checkpoint_status(MissionCheckpointStatus::Running, None)?;
        self.touch(now);
        Ok(())
    }

    pub fn record_outcome(&mut self, outcome: Outcome) -> Result<(), MissionError> {
        self.require_stage(&[
            MissionStage::Running,
            MissionStage::Verifying,
            MissionStage::CycleReviewed,
        ])?;
        if outcome.summary.trim().is_empty()
            || self
                .outcome_history
                .last()
                .is_some_and(|previous| outcome.observed_at <= previous.observed_at)
            || self.effects.iter().any(|effect| {
                matches!(
                    effect.status,
                    EffectStatus::Proposed
                        | EffectStatus::Approved
                        | EffectStatus::Executing
                        | EffectStatus::ReceiptRecorded
                        | EffectStatus::VerificationRequired
                )
            })
            || self.definition.as_ref().is_some_and(|definition| {
                !definition
                    .checkpoints
                    .iter()
                    .all(|checkpoint| checkpoint.status.is_terminal())
            })
        {
            return Err(MissionError::InvalidOutcome);
        }
        self.ensure_touchable()?;
        let now = outcome.observed_at;
        let next_stage =
            next_stage_after_outcome(&self.contract, &outcome.decision, outcome.observed_at);
        self.outcome_history.push(outcome.clone());
        self.outcome = Some(outcome);
        self.stage = next_stage;
        self.block = None;
        for task in &mut self.tasks {
            if !matches!(task.status, TaskStatus::Cancelled) {
                task.status = TaskStatus::Completed;
            }
        }
        self.touch(now);
        Ok(())
    }

    pub fn block(
        &mut self,
        block: MissionBlock,
        waiting_stage: MissionStage,
    ) -> Result<(), MissionError> {
        if self.stage.is_terminal()
            || !matches!(
                waiting_stage,
                MissionStage::Blocked | MissionStage::WaitingUser | MissionStage::WaitingApproval
            )
            || block.code.trim().is_empty()
            || block.detail.trim().is_empty()
        {
            return Err(MissionError::InvalidBlock);
        }
        self.ensure_touchable()?;
        let observed_at = block.observed_at;
        if self.definition.is_some() {
            self.set_catalog_checkpoint_status(
                checkpoint_status_for_mission_stage(&waiting_stage)?,
                Some(block.clone()),
            )?;
        }
        self.block = Some(block);
        self.stage = waiting_stage;
        self.touch(observed_at);
        Ok(())
    }

    pub fn resume(&mut self, now: DateTime<Utc>) -> Result<(), MissionError> {
        self.require_stage(&[MissionStage::Blocked, MissionStage::WaitingUser])?;
        if self.block.as_ref().is_some_and(|block| !block.recoverable) {
            return Err(MissionError::BlockNotRecoverable);
        }
        self.ensure_touchable()?;
        self.set_catalog_checkpoint_status(MissionCheckpointStatus::Running, None)?;
        self.block = None;
        self.stage = MissionStage::Running;
        self.touch(now);
        Ok(())
    }

    pub fn terminate(
        &mut self,
        disposition: MissionTerminalDisposition,
        now: DateTime<Utc>,
    ) -> Result<(), MissionError> {
        if self.stage.is_terminal() {
            return Err(MissionError::AlreadyTerminal);
        }
        self.ensure_touchable()?;
        self.stage = match disposition {
            MissionTerminalDisposition::Completed => MissionStage::Completed,
            MissionTerminalDisposition::Partial => MissionStage::Partial,
            MissionTerminalDisposition::ExpectedRefusal => MissionStage::ExpectedRefusal,
            MissionTerminalDisposition::Failed => MissionStage::Failed,
            MissionTerminalDisposition::Cancelled => MissionStage::Cancelled,
        };
        self.block = None;
        for task in &mut self.tasks {
            task.status = if self.stage == MissionStage::Cancelled {
                TaskStatus::Cancelled
            } else {
                TaskStatus::Completed
            };
        }
        self.touch(now);
        Ok(())
    }

    fn effect_mut(&mut self, effect_id: &EffectId) -> Result<&mut Effect, MissionError> {
        self.effects
            .iter_mut()
            .find(|effect| &effect.id == effect_id)
            .ok_or_else(|| MissionError::UnknownEffect(effect_id.clone()))
    }

    fn set_catalog_checkpoint_status(
        &mut self,
        status: MissionCheckpointStatus,
        block: Option<MissionBlock>,
    ) -> Result<(), MissionError> {
        if let Some(definition) = &mut self.definition {
            definition.set_active_status(status, block)?;
        }
        Ok(())
    }

    fn require_stage(&self, expected: &[MissionStage]) -> Result<(), MissionError> {
        if expected.contains(&self.stage) {
            Ok(())
        } else {
            Err(MissionError::InvalidMissionStage {
                actual: self.stage.clone(),
                expected: expected.to_vec(),
            })
        }
    }

    fn ensure_touchable(&self) -> Result<(), MissionError> {
        self.revision
            .checked_add(1)
            .map(|_| ())
            .ok_or(MissionError::RevisionOverflow)
    }

    fn touch(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
        self.revision += 1;
    }
}

fn next_stage_after_outcome(
    contract: &OperatingContract,
    decision: &OutcomeDecision,
    observed_at: DateTime<Utc>,
) -> MissionStage {
    if *decision == OutcomeDecision::Stop {
        return MissionStage::Completed;
    }
    match contract.mode {
        OperatingMode::BuildOnce | OperatingMode::OneOffDecision => MissionStage::Completed,
        OperatingMode::ContinuousOperator
        | OperatingMode::ContinuousRelationship
        | OperatingMode::Campaign
            if cadence_has_future_authority(contract, observed_at) =>
        {
            MissionStage::Scheduled
        }
        OperatingMode::ContinuousOperator | OperatingMode::ContinuousRelationship => {
            MissionStage::Completed
        }
        OperatingMode::Campaign if contract.cadence.is_some() => MissionStage::Completed,
        OperatingMode::Campaign => MissionStage::CycleReviewed,
    }
}

fn cadence_has_future_authority(contract: &OperatingContract, observed_at: DateTime<Utc>) -> bool {
    if observed_at >= contract.valid_until {
        return false;
    }
    contract
        .cadence
        .as_ref()
        .is_some_and(|cadence| match cadence.trigger {
            CadenceTriggerKind::EventDriven | CadenceTriggerKind::IntervalOrEvent => true,
            CadenceTriggerKind::Interval => next_interval_due_at(cadence, observed_at)
                .is_some_and(|due_at| due_at < contract.valid_until),
        })
}

fn checkpoint_status_for_mission_stage(
    stage: &MissionStage,
) -> Result<MissionCheckpointStatus, MissionError> {
    match stage {
        MissionStage::Blocked => Ok(MissionCheckpointStatus::Blocked),
        MissionStage::WaitingUser => Ok(MissionCheckpointStatus::WaitingUser),
        MissionStage::WaitingApproval => Ok(MissionCheckpointStatus::WaitingApproval),
        _ => Err(MissionError::InvalidBlock),
    }
}

fn validate_effect_connection_scope(spec: &EffectSpec) -> Result<(), MissionError> {
    let has_connection = spec.connection_id.is_some() || spec.account_id.is_some();
    if (spec.connection_id.is_some() != spec.account_id.is_some())
        || (has_connection && spec.required_scopes.is_empty())
        || (!has_connection && !spec.required_scopes.is_empty())
        || spec
            .required_scopes
            .iter()
            .any(|scope| scope.trim().is_empty())
    {
        return Err(MissionError::InvalidEffectScope);
    }
    Ok(())
}

fn validate_effect_content_scope(
    spec: &EffectSpec,
    now: DateTime<Utc>,
) -> Result<(), MissionError> {
    if spec.capability.trim().is_empty()
        || spec.provider.trim().is_empty()
        || spec.description.trim().is_empty()
        || spec.target_resource.trim().is_empty()
        || spec.timezone.trim().is_empty()
        || spec.policy_version.trim().is_empty()
        || !is_sha256(&spec.payload_digest)
        || spec
            .audience_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
        || spec.asset_digests.iter().any(|digest| !is_sha256(digest))
        || spec.expires_at <= now
        || spec
            .scheduled_for
            .is_some_and(|scheduled| scheduled < now || scheduled >= spec.expires_at)
        || spec
            .connection_id
            .as_ref()
            .is_some_and(|value| value.as_str().trim().is_empty())
        || spec
            .account_id
            .as_ref()
            .is_some_and(|value| value.as_str().trim().is_empty())
        || spec.conversation_guard.as_ref().is_some_and(|guard| {
            guard.conversation_id.as_str().trim().is_empty()
                || guard.control_generation == 0
                || !is_sha256(&guard.scope_digest)
        })
        || spec.creator_contact_guard.as_ref().is_some_and(|guard| {
            guard.hiring_id.as_str().trim().is_empty()
                || guard.creator_id.as_str().trim().is_empty()
                || guard.partner_id.as_str().trim().is_empty()
                || !is_sha256(&guard.scope_digest)
                || !is_sha256(&guard.permission_evidence_digest)
                || guard.scope_digest != spec.payload_digest
        })
    {
        return Err(MissionError::InvalidEffectScope);
    }
    Ok(())
}

fn validate_effect_consent_scope(spec: &EffectSpec) -> Result<(), MissionError> {
    let valid = match spec.consent {
        ConsentState::NotRequired => {
            spec.consent_record_id.is_none() && spec.consent_requirement.is_none()
        }
        ConsentState::Confirmed | ConsentState::Withdrawn => {
            spec.consent_record_id.is_some()
                && spec
                    .consent_requirement
                    .as_ref()
                    .is_some_and(ConsentRequirement::validate)
        }
        ConsentState::Missing => {
            spec.consent_record_id.is_none()
                && spec
                    .consent_requirement
                    .as_ref()
                    .is_some_and(ConsentRequirement::validate)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(MissionError::ConsentRecordMismatch)
    }
}

fn validate_receipt_scope(effect: &Effect, receipt: &Receipt) -> Result<(), MissionError> {
    if receipt.provider != effect.provider
        || receipt.external_id.trim().is_empty()
        || receipt.request_digest != effect.approval_digest()
        || !is_sha256(&receipt.response_digest)
        || receipt.accepted_at >= effect.expires_at
        || effect
            .approval
            .as_ref()
            .is_none_or(|approval| receipt.accepted_at < approval.decided_at)
    {
        return Err(MissionError::ReceiptScopeMismatch);
    }
    Ok(())
}

fn legacy_tenant_id() -> TenantId {
    TenantId::from("legacy-local")
}

fn legacy_permission_digest() -> String {
    "0".repeat(64)
}

fn legacy_approval_valid_until() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH
}

fn durable_execution_start_is_valid(
    effect: &Effect,
    approval: &Approval,
    execution_started_at: DateTime<Utc>,
) -> bool {
    approval.scope_digest == effect.approval_digest()
        && execution_started_at >= approval.decided_at
        && execution_started_at < approval.valid_until
        && execution_started_at < effect.expires_at
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum MissionError {
    #[error(transparent)]
    OperatingContract(#[from] OperatingContractError),
    #[error("mission title and goal cannot be empty")]
    EmptyMission,
    #[error("Mission definition is incomplete, inconsistent, or not an acyclic ordered DAG")]
    InvalidMissionDefinition,
    #[error("Mission definition does not match the Operating Contract authority")]
    MissionDefinitionContractMismatch,
    #[error("Mission cycle mismatch: expected {expected}, found {actual}")]
    InvalidMissionCycle { expected: u64, actual: u64 },
    #[error("the previous Catalog Checkpoint DAG is not terminal for the next cycle")]
    MissionCycleCheckpointIncomplete,
    #[error("this operation requires a Catalog-bound Mission definition")]
    MissionDefinitionRequired,
    #[error("unknown Mission checkpoint {0}")]
    MissionCheckpointNotFound(String),
    #[error("checkpoint {checkpoint_id} cannot transition from {from:?} to {to:?}")]
    InvalidCheckpointTransition {
        checkpoint_id: String,
        from: MissionCheckpointStatus,
        to: MissionCheckpointStatus,
    },
    #[error("checkpoint dependencies are incomplete for {0}")]
    CheckpointDependencyIncomplete(String),
    #[error("checkpoint completion evidence is invalid for {0}")]
    InvalidCheckpointCompletion(String),
    #[error(
        "checkpoint {checkpoint_id} tasks must use only the routed capability {expected_capability}"
    )]
    MissionCheckpointTaskMismatch {
        checkpoint_id: String,
        expected_capability: String,
    },
    #[error("mission stage {actual:?} is invalid; expected one of {expected:?}")]
    InvalidMissionStage {
        actual: MissionStage,
        expected: Vec<MissionStage>,
    },
    #[error("duplicate evidence {0}")]
    DuplicateEvidence(EvidenceId),
    #[error("unknown evidence {0}")]
    UnknownEvidence(EvidenceId),
    #[error("work product {0} is invalid")]
    InvalidWorkProduct(WorkProductId),
    #[error("duplicate work product {0}")]
    DuplicateWorkProduct(WorkProductId),
    #[error("unknown work product {0}")]
    UnknownWorkProduct(WorkProductId),
    #[error("work product {0} has an invalid revision or adoption transition")]
    InvalidWorkProductTransition(WorkProductId),
    #[error("unknown effect {0}")]
    UnknownEffect(EffectId),
    #[error("idempotency key cannot be empty")]
    EmptyIdempotencyKey,
    #[error("duplicate idempotency key {0}")]
    DuplicateIdempotencyKey(String),
    #[error("effect capability is not enabled by the Mission contract: {0}")]
    CapabilityNotEnabled(String),
    #[error("effect cost limit cannot be negative")]
    NegativeCostLimit,
    #[error("payment effects require an exact positive amount")]
    PaymentAmountNotPositive,
    #[error("effect provider, target, payload, assets, schedule or policy scope is invalid")]
    InvalidEffectScope,
    #[error("confirmed consent must reference exactly one consent record")]
    ConsentRecordMismatch,
    #[error("invalid effect transition from {from:?} to {to:?}")]
    InvalidEffectTransition {
        from: EffectStatus,
        to: EffectStatus,
    },
    #[error("the effect scope changed after the approval was shown")]
    ApprovalScopeChanged,
    #[error("effect approval identity or validity is invalid")]
    InvalidApproval,
    #[error("approved effect is missing its approval grant")]
    MissingApproval,
    #[error("effect approval expired before execution")]
    EffectExpired,
    #[error("approval grant expired before effect dispatch")]
    ApprovalExpired,
    #[error("provider receipt does not match the exact approved effect scope")]
    ReceiptScopeMismatch,
    #[error("durable receipt does not prove an execution inside the approved dispatch window")]
    DurableReceiptRecoveryMismatch,
    #[error(
        "durable provider state does not prove an execution inside the approved dispatch window"
    )]
    DurableProviderRecoveryMismatch,
    #[error("verification does not refer to the stored receipt")]
    VerificationReceiptMismatch,
    #[error("outcome is empty, out of order, or recorded while an effect is still pending")]
    InvalidOutcome,
    #[error(
        "verified journey cannot continue while the named effect is unverified or another effect is pending/failed"
    )]
    JourneyContinuationNotReady,
    #[error("mission block state, code, or detail is invalid")]
    InvalidBlock,
    #[error("mission block requires an explicit terminal decision")]
    BlockNotRecoverable,
    #[error("mission already has a terminal business disposition")]
    AlreadyTerminal,
    #[error("mission revision overflow")]
    RevisionOverflow,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_be_bytes());
    digest.update(value.as_bytes());
}

fn hash_optional(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_field(digest, "some");
            hash_field(digest, value);
        }
        None => hash_field(digest, "none"),
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn checkpoint_executor_name(value: MissionCheckpointExecutor) -> &'static str {
    match value {
        MissionCheckpointExecutor::Application => "application",
        MissionCheckpointExecutor::Runtime => "runtime",
        MissionCheckpointExecutor::EffectBroker => "effect_broker",
        MissionCheckpointExecutor::Human => "human",
    }
}

fn checkpoint_completion_policy_name(value: MissionCheckpointCompletionPolicy) -> &'static str {
    match value {
        MissionCheckpointCompletionPolicy::DeterministicEvidence => "deterministic_evidence",
        MissionCheckpointCompletionPolicy::WorkProduct => "work_product",
        MissionCheckpointCompletionPolicy::VerifiedEffect => "verified_effect",
        MissionCheckpointCompletionPolicy::HumanConfirmation => "human_confirmation",
    }
}

fn valid_application_checkpoint_evidence(
    mission: &Mission,
    definition: &MissionDefinition,
    checkpoint: &MissionCheckpoint,
    route: &MissionCheckpointRoute,
    completion: &MissionCheckpointCompletion,
) -> bool {
    if route.executor != MissionCheckpointExecutor::Application {
        return completion.application_evidence.is_none();
    }
    let Some(evidence) = completion.application_evidence.as_ref() else {
        return false;
    };
    let oracle_union = evidence
        .sources
        .iter()
        .flat_map(|source| source.oracle_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    evidence.schema_version == MissionCheckpointApplicationEvidence::SCHEMA_VERSION
        && !evidence.handler_id.trim().is_empty()
        && evidence.tenant_id == mission.tenant_id
        && evidence.project_id == mission.project_id
        && evidence.mission_id == mission.id
        && evidence.manifest_id == definition.manifest_id
        && evidence.manifest_version == definition.manifest_version
        && evidence.catalog_digest == definition.catalog_digest
        && evidence.cycle == definition.cycle
        && evidence.checkpoint_id == checkpoint.id
        && evidence.dispatch_mission_revision > 0
        && evidence.dispatch_mission_revision <= evidence.verification_mission_revision
        && evidence.dispatch_checkpoint_revision > 0
        && evidence.dispatch_checkpoint_revision <= evidence.verification_checkpoint_revision
        && evidence.verification_mission_revision == mission.revision
        && evidence.verification_checkpoint_revision == checkpoint.revision
        && evidence.capability_id == route.capability_id
        && evidence.executor == route.executor
        && evidence.completion_policy == route.completion_policy.expect("contracted route")
        && evidence.observed_at == completion.verified_at
        && !evidence.sources.is_empty()
        && evidence.sources.iter().all(|source| {
            !source.source_kind.trim().is_empty()
                && !source.source_id.trim().is_empty()
                && source.source_revision > 0
                && is_sha256(&source.projection_digest)
                && !source.oracle_ids.is_empty()
                && source.oracle_ids.is_subset(&route.oracle_ids)
        })
        && oracle_union == route.oracle_ids
        && evidence.digest() == completion.evidence_digest
}

fn valid_persisted_application_checkpoint_evidence(
    definition: &MissionDefinition,
    checkpoint: &MissionCheckpoint,
    route: &MissionCheckpointRoute,
    completion: &MissionCheckpointCompletion,
) -> bool {
    if route.executor != MissionCheckpointExecutor::Application {
        return completion.application_evidence.is_none();
    }
    let Some(evidence) = completion.application_evidence.as_ref() else {
        return false;
    };
    let oracle_union = evidence
        .sources
        .iter()
        .flat_map(|source| source.oracle_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    evidence.schema_version == MissionCheckpointApplicationEvidence::SCHEMA_VERSION
        && !evidence.handler_id.trim().is_empty()
        && !evidence.tenant_id.as_str().trim().is_empty()
        && !evidence.project_id.as_str().trim().is_empty()
        && !evidence.mission_id.as_str().trim().is_empty()
        && evidence.manifest_id == definition.manifest_id
        && evidence.manifest_version == definition.manifest_version
        && evidence.catalog_digest == definition.catalog_digest
        && evidence.cycle == definition.cycle
        && evidence.checkpoint_id == checkpoint.id
        && evidence.dispatch_mission_revision > 0
        && evidence.dispatch_mission_revision <= evidence.verification_mission_revision
        && evidence.dispatch_checkpoint_revision > 0
        && evidence.dispatch_checkpoint_revision <= evidence.verification_checkpoint_revision
        && evidence.verification_checkpoint_revision.checked_add(1) == Some(checkpoint.revision)
        && evidence.capability_id == route.capability_id
        && evidence.executor == route.executor
        && evidence.completion_policy == route.completion_policy.expect("contracted route")
        && evidence.observed_at == completion.verified_at
        && !evidence.sources.is_empty()
        && evidence.sources.iter().all(|source| {
            !source.source_kind.trim().is_empty()
                && !source.source_id.trim().is_empty()
                && source.source_revision > 0
                && is_sha256(&source.projection_digest)
                && !source.oracle_ids.is_empty()
                && source.oracle_ids.is_subset(&route.oracle_ids)
        })
        && oracle_union == route.oracle_ids
        && evidence.digest() == completion.evidence_digest
}

fn effect_class_name(value: &EffectClass) -> &'static str {
    match value {
        EffectClass::Read => "read",
        EffectClass::LocalWrite => "local_write",
        EffectClass::ExternalWrite => "external_write",
        EffectClass::Outreach => "outreach",
        EffectClass::Spend => "spend",
        EffectClass::Payment => "payment",
    }
}

fn consent_name(value: &ConsentState) -> &'static str {
    match value {
        ConsentState::NotRequired => "not_required",
        ConsentState::Confirmed => "confirmed",
        ConsentState::Missing => "missing",
        ConsentState::Withdrawn => "withdrawn",
    }
}

fn risk_name(value: &EffectRisk) -> &'static str {
    match value {
        EffectRisk::Low => "low",
        EffectRisk::Medium => "medium",
        EffectRisk::High => "high",
        EffectRisk::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn mission() -> Mission {
        Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-1"),
            ProjectId::from("project-1"),
            "Validate launch",
            MissionContract::bootstrap(
                "Produce an evidence-backed launch brief",
                ["research.discover".into(), "channel.preview".into()],
                now(),
            ),
            now(),
        )
        .expect("valid mission")
    }

    fn catalog_mission() -> Mission {
        let contract = MissionContract::bootstrap(
            "Make a market decision without external writes",
            ["research.discover".into(), "decision.evaluate".into()],
            now(),
        );
        let definition = MissionDefinition::from_linear_manifest(
            "VM-07",
            1,
            "a".repeat(64),
            OperatingMode::BuildOnce,
            contract.enabled_capabilities.iter().cloned(),
            ["market_evidence_pack".into(), "market_decision".into()],
            ["truth".into(), "decision".into()],
            [
                "constraints_locked".into(),
                "evidence_ready".into(),
                "decision_ready".into(),
            ],
        )
        .expect("definition");
        Mission::compile_catalog(
            TenantId::from("tenant-catalog"),
            MissionId::from("mission-catalog"),
            ProjectId::from("project-catalog"),
            "Catalog mission",
            contract,
            definition,
            now(),
        )
        .expect("catalog mission")
    }

    #[test]
    fn catalog_checkpoint_dag_requires_ordered_oracle_evidence_and_never_self_completes() {
        let mut mission = catalog_mission();
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-catalog"),
                    title: "Lock constraints".into(),
                    status: TaskStatus::Running,
                    capability: "research.discover".into(),
                }],
                now(),
            )
            .expect("start first checkpoint");
        let definition = mission.definition.as_ref().expect("definition");
        assert_eq!(definition.manifest_id, "VM-07");
        assert_eq!(
            definition.current_checkpoint().map(|checkpoint| (
                checkpoint.id.as_str(),
                checkpoint.status,
                checkpoint.attempt
            )),
            Some(("constraints_locked", MissionCheckpointStatus::Running, 1))
        );
        assert!(matches!(
            mission.begin_checkpoint("evidence_ready", now()),
            Err(MissionError::InvalidCheckpointTransition { .. })
        ));

        let verified_at = now() + chrono::Duration::minutes(1);
        mission
            .begin_checkpoint_verification("constraints_locked", verified_at)
            .expect("verify first checkpoint");
        mission
            .complete_checkpoint(
                "constraints_locked",
                MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from(["truth".into()]),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: "b".repeat(64),
                    verified_at,
                },
            )
            .expect("complete first checkpoint");
        assert_eq!(mission.stage, MissionStage::Running);
        assert_eq!(
            mission
                .definition
                .as_ref()
                .and_then(MissionDefinition::current_checkpoint)
                .map(|checkpoint| (checkpoint.id.as_str(), checkpoint.status)),
            Some(("evidence_ready", MissionCheckpointStatus::Ready))
        );
        assert!(matches!(
            mission.complete_checkpoint(
                "evidence_ready",
                MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from(["not-an-oracle".into()]),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: "c".repeat(64),
                    verified_at,
                }
            ),
            Err(MissionError::InvalidMissionStage { .. })
        ));
        assert_ne!(mission.stage, MissionStage::Completed);
        assert!(mission.outcome.is_none());
    }

    #[test]
    fn catalog_definition_rejects_capability_drift_and_backward_dependencies() {
        let mut mission = catalog_mission();
        mission.definition.as_mut().expect("definition").checkpoints[0]
            .depends_on
            .insert("decision_ready".into());
        assert_eq!(
            mission.definition.as_ref().expect("definition").validate(),
            Err(MissionError::InvalidMissionDefinition)
        );

        let mut contract =
            MissionContract::bootstrap("Capability drift", ["research.discover".into()], now());
        contract
            .enabled_capabilities
            .insert("payment.execute".into());
        contract
            .autonomy_by_capability
            .insert("payment.execute".into(), AutonomyLevel::ApprovalRequired);
        let definition = MissionDefinition::from_linear_manifest(
            "VM-07",
            1,
            "d".repeat(64),
            OperatingMode::BuildOnce,
            ["research.discover".into()],
            ["market_decision".into()],
            ["decision".into()],
            ["decision_ready".into()],
        )
        .expect("definition");
        assert_eq!(
            Mission::compile_catalog(
                TenantId::from("tenant-drift"),
                MissionId::from("mission-drift"),
                ProjectId::from("project-drift"),
                "Drift",
                contract,
                definition,
                now(),
            ),
            Err(MissionError::MissionDefinitionContractMismatch)
        );
    }

    #[test]
    fn routed_catalog_checkpoint_rejects_capability_guessing_without_mutation() {
        let contract = MissionContract::bootstrap(
            "Route the exact Checkpoint capability",
            ["research.discover".into(), "decision.evaluate".into()],
            now(),
        );
        let definition = MissionDefinition::from_routed_linear_manifest(
            "VM-07",
            2,
            "e".repeat(64),
            OperatingMode::BuildOnce,
            contract.enabled_capabilities.iter().cloned(),
            ["market_evidence_pack".into(), "market_decision".into()],
            ["truth".into(), "decision".into()],
            [
                (
                    "evidence_plan".into(),
                    MissionCheckpointRoute::new(
                        "research.discover",
                        MissionCheckpointExecutor::Runtime,
                    )
                    .expect("route"),
                ),
                (
                    "decision_ready".into(),
                    MissionCheckpointRoute::new(
                        "decision.evaluate",
                        MissionCheckpointExecutor::Human,
                    )
                    .expect("route"),
                ),
            ],
        )
        .expect("routed definition");
        let mut mission = Mission::compile_catalog(
            TenantId::from("tenant-routed"),
            MissionId::from("mission-routed"),
            ProjectId::from("project-routed"),
            "Routed Mission",
            contract,
            definition,
            now(),
        )
        .expect("Mission");
        let revision = mission.revision;
        assert!(matches!(
            mission.start_research(
                [Task {
                    id: TaskId::from("task-wrong-route"),
                    title: "Do not guess".into(),
                    status: TaskStatus::Running,
                    capability: "decision.evaluate".into(),
                }],
                now(),
            ),
            Err(MissionError::MissionCheckpointTaskMismatch {
                expected_capability,
                ..
            }) if expected_capability == "research.discover"
        ));
        assert_eq!(
            (&mission.stage, mission.revision),
            (&MissionStage::Ready, revision)
        );
        assert!(mission.tasks.is_empty());
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-exact-route"),
                    title: "Use exact route".into(),
                    status: TaskStatus::Running,
                    capability: "research.discover".into(),
                }],
                now(),
            )
            .expect("exact route");
        assert_eq!(mission.stage, MissionStage::Running);

        assert!(matches!(
            MissionDefinition::from_routed_linear_manifest(
                "VM-07",
                2,
                "f".repeat(64),
                OperatingMode::BuildOnce,
                ["research.discover".into(), "decision.evaluate".into()],
                ["market_decision".into()],
                ["decision".into()],
                [(
                    "decision_ready".into(),
                    MissionCheckpointRoute::new(
                        "research.discover",
                        MissionCheckpointExecutor::Runtime,
                    )
                    .expect("route"),
                )],
            ),
            Err(MissionError::InvalidMissionDefinition)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one invariant test keeps the two fail-closed completion attempts and the exact successful WorkProduct-bound transition in a single auditable sequence"
    )]
    fn contracted_checkpoint_requires_the_exact_oracles_and_real_work_product() {
        let contract = MissionContract::bootstrap(
            "Produce one evidence-backed market plan",
            ["research.discover".into()],
            now(),
        );
        let route_oracles = BTreeSet::from([
            "goal".into(),
            "truth".into(),
            "work_product".into(),
            "operating_state".into(),
        ]);
        let definition = MissionDefinition::from_routed_linear_manifest(
            "VM-07",
            3,
            "9".repeat(64),
            OperatingMode::BuildOnce,
            contract.enabled_capabilities.iter().cloned(),
            ["market_evidence_pack".into()],
            route_oracles.iter().cloned(),
            [(
                "evidence_plan".into(),
                MissionCheckpointRoute::contracted(
                    "research.discover",
                    MissionCheckpointExecutor::Runtime,
                    route_oracles.iter().cloned(),
                    MissionCheckpointCompletionPolicy::WorkProduct,
                )
                .expect("contracted route"),
            )],
        )
        .expect("contracted definition");
        let mut mission = Mission::compile_catalog(
            TenantId::from("tenant-contracted"),
            MissionId::from("mission-contracted"),
            ProjectId::from("project-contracted"),
            "Contracted Mission",
            contract,
            definition,
            now(),
        )
        .expect("Mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-contracted"),
                    title: "Build evidence plan".into(),
                    status: TaskStatus::Running,
                    capability: "research.discover".into(),
                }],
                now(),
            )
            .expect("start");
        let evidence_id = EvidenceId::from("evidence-contracted");
        mission
            .record_evidence(
                Evidence {
                    id: evidence_id.clone(),
                    title: "Confirmed market constraint".into(),
                    source_uri: "fixture://truth/constraint".into(),
                    observed_at: now(),
                    confidence: 1.0,
                    status: EvidenceStatus::Confirmed,
                    content_digest: "1".repeat(64),
                },
                now(),
            )
            .expect("evidence");
        let work_product_id = WorkProductId::from("work-product-contracted");
        mission
            .record_work_product(
                WorkProduct::draft(
                    work_product_id.clone(),
                    "Market evidence plan",
                    "A source-bound plan with explicit uncertainty.",
                    [evidence_id],
                ),
                now(),
            )
            .expect("WorkProduct");
        let verified_at = now() + chrono::Duration::minutes(1);
        mission
            .begin_checkpoint_verification("evidence_plan", verified_at)
            .expect("verification");
        let before_rejection = mission.clone();
        assert!(matches!(
            mission.complete_checkpoint(
                "evidence_plan",
                MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from(["truth".into()]),
                    work_product_ids: BTreeSet::from([work_product_id.clone()]),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: "2".repeat(64),
                    verified_at,
                },
            ),
            Err(MissionError::InvalidCheckpointCompletion(_))
        ));
        assert_eq!(mission, before_rejection);
        assert!(matches!(
            mission.complete_checkpoint(
                "evidence_plan",
                MissionCheckpointCompletion {
                    oracle_ids: route_oracles.clone(),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: "3".repeat(64),
                    verified_at,
                },
            ),
            Err(MissionError::InvalidCheckpointCompletion(_))
        ));
        assert_eq!(mission, before_rejection);
        mission
            .complete_checkpoint(
                "evidence_plan",
                MissionCheckpointCompletion {
                    oracle_ids: route_oracles,
                    work_product_ids: BTreeSet::from([work_product_id]),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: "4".repeat(64),
                    verified_at,
                },
            )
            .expect("exact completion");
        assert_eq!(
            mission
                .definition
                .as_ref()
                .and_then(|definition| definition.checkpoints.first())
                .map(|checkpoint| checkpoint.status),
            Some(MissionCheckpointStatus::Completed)
        );
        assert_eq!(mission.stage, MissionStage::Verifying);
    }

    fn mission_with_preview_effect() -> (Mission, EffectId) {
        let mut mission = mission();
        mission.contract.approval_policy.validity_seconds = 60;
        mission.start_research([], now()).expect("start research");
        let effect_id = mission
            .propose_effect(
                EffectSpec {
                    id: EffectId::from("effect-1"),
                    actor_id: ActorId::from("user-1"),
                    capability: "channel.preview".into(),
                    provider: "fixture-provider".into(),
                    connection_id: None,
                    account_id: None,
                    required_scopes: BTreeSet::new(),
                    effect_class: EffectClass::ExternalWrite,
                    description: "Publish preview".into(),
                    target_resource: "preview.example/launch".into(),
                    audience_digest: None,
                    payload_digest: "a".repeat(64),
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
                    idempotency_key: "mission-1:preview:v1".into(),
                    amount: Money::zero(crate::CurrencyCode::parse("CNY").expect("CNY")),
                    expires_at: now() + chrono::Duration::hours(1),
                },
                now(),
            )
            .expect("propose effect");
        (mission, effect_id)
    }

    fn approved_preview_effect() -> (Mission, EffectId) {
        let (mut mission, effect_id) = mission_with_preview_effect();
        let scope_digest = mission
            .effect(&effect_id)
            .expect("effect")
            .approval_digest();
        mission
            .approve_effect(
                &effect_id,
                Approval {
                    id: ApprovalId::from("approval-recovery"),
                    decision: ApprovalDecision::Approved,
                    decided_by: ActorId::from("user-1"),
                    decided_at: now(),
                    valid_until: now() + chrono::Duration::seconds(60),
                    scope_digest,
                    permission_digest: "b".repeat(64),
                },
            )
            .expect("approve recovery fixture");
        (mission, effect_id)
    }

    fn durable_receipt(effect: &Effect, accepted_at: DateTime<Utc>) -> Receipt {
        Receipt {
            id: ReceiptId::from("durable-receipt"),
            provider: effect.provider.clone(),
            external_id: "durable-external-id".into(),
            accepted_at,
            request_digest: effect.approval_digest(),
            response_digest: "c".repeat(64),
        }
    }

    #[test]
    fn work_products_require_known_evidence() {
        let mut mission = mission();
        mission.start_research([], now()).expect("start research");
        let result = mission.record_work_product(
            WorkProduct::draft(
                WorkProductId::from("brief-1"),
                "Brief",
                "Body",
                [EvidenceId::from("missing")],
            ),
            now(),
        );

        assert_eq!(
            result,
            Err(MissionError::UnknownEvidence(EvidenceId::from("missing")))
        );
    }

    #[test]
    fn approval_is_bound_to_the_exact_effect_scope() {
        let (mut mission, effect_id) = mission_with_preview_effect();

        let result = mission.approve_effect(
            &effect_id,
            Approval {
                id: ApprovalId::from("approval-1"),
                decision: ApprovalDecision::Approved,
                decided_by: ActorId::from("user-1"),
                decided_at: now(),
                valid_until: now() + chrono::Duration::hours(1),
                scope_digest: "stale-digest".into(),
                permission_digest: "b".repeat(64),
            },
        );

        assert_eq!(result, Err(MissionError::ApprovalScopeChanged));
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Proposed
        );
    }

    #[test]
    fn approval_validity_is_exact_bounded_and_legacy_missing_expiry_fails_closed() {
        let (mut mission, effect_id) = mission_with_preview_effect();
        let scope_digest = mission
            .effect(&effect_id)
            .expect("effect")
            .approval_digest();
        let wrong_validity = mission.approve_effect(
            &effect_id,
            Approval {
                id: ApprovalId::from("approval-2"),
                decision: ApprovalDecision::Approved,
                decided_by: ActorId::from("user-1"),
                decided_at: now(),
                valid_until: now() + chrono::Duration::seconds(61),
                scope_digest: scope_digest.clone(),
                permission_digest: "b".repeat(64),
            },
        );
        assert_eq!(wrong_validity, Err(MissionError::InvalidApproval));
        mission
            .approve_effect(
                &effect_id,
                Approval {
                    id: ApprovalId::from("approval-3"),
                    decision: ApprovalDecision::Approved,
                    decided_by: ActorId::from("user-1"),
                    decided_at: now(),
                    valid_until: now() + chrono::Duration::seconds(60),
                    scope_digest,
                    permission_digest: "b".repeat(64),
                },
            )
            .expect("exact bounded approval");
        let mut legacy_json = serde_json::to_value(&mission).expect("mission json");
        legacy_json["effects"][0]["approval"]
            .as_object_mut()
            .expect("approval object")
            .remove("validUntil");
        let mut legacy_mission: Mission =
            serde_json::from_value(legacy_json).expect("legacy approval remains readable");
        assert_eq!(
            legacy_mission.begin_effect(&effect_id, now() + chrono::Duration::seconds(1)),
            Err(MissionError::ApprovalExpired)
        );
        assert_eq!(
            mission.begin_effect(&effect_id, now() + chrono::Duration::seconds(61)),
            Err(MissionError::ApprovalExpired)
        );
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Expired
        );
    }

    #[test]
    fn durable_receipt_recovery_rejects_execution_at_approval_expiry() {
        let (mut mission, effect_id) = approved_preview_effect();
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = durable_receipt(&effect, now() + chrono::Duration::seconds(61));

        assert_eq!(
            mission.reconcile_durable_receipt(
                &effect_id,
                receipt,
                now() + chrono::Duration::seconds(60),
            ),
            Err(MissionError::DurableReceiptRecoveryMismatch)
        );
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Approved
        );
    }

    #[test]
    fn durable_receipt_recovery_rejects_a_changed_receipt_after_projection() {
        let (mut mission, effect_id) = approved_preview_effect();
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = durable_receipt(&effect, now() + chrono::Duration::seconds(2));
        mission
            .reconcile_durable_receipt(
                &effect_id,
                receipt.clone(),
                now() + chrono::Duration::seconds(1),
            )
            .expect("first projection");
        let mut changed = receipt;
        changed.external_id = "substituted-external-id".into();

        assert_eq!(
            mission.reconcile_durable_receipt(
                &effect_id,
                changed,
                now() + chrono::Duration::seconds(1),
            ),
            Err(MissionError::DurableReceiptRecoveryMismatch)
        );
    }

    #[test]
    fn legacy_approval_sentinel_cannot_authorize_durable_receipt_recovery() {
        let (mission, effect_id) = approved_preview_effect();
        let mut legacy_json = serde_json::to_value(&mission).expect("mission json");
        legacy_json["effects"][0]["approval"]
            .as_object_mut()
            .expect("approval object")
            .remove("validUntil");
        let mut legacy_mission: Mission =
            serde_json::from_value(legacy_json).expect("legacy mission remains readable");
        let effect = legacy_mission.effect(&effect_id).expect("effect").clone();
        let receipt = durable_receipt(&effect, now() + chrono::Duration::seconds(2));

        assert_eq!(
            legacy_mission.reconcile_durable_receipt(
                &effect_id,
                receipt,
                now() + chrono::Duration::seconds(1),
            ),
            Err(MissionError::DurableReceiptRecoveryMismatch)
        );
    }

    #[test]
    fn durable_provider_state_requires_original_dispatch_window_and_is_idempotent() {
        let (mut mission, effect_id) = approved_preview_effect();
        assert_eq!(
            mission.reconcile_durable_provider_state(
                &effect_id,
                DurableProviderState::Uncertain,
                now() + chrono::Duration::seconds(60),
                now() + chrono::Duration::seconds(61),
            ),
            Err(MissionError::DurableProviderRecoveryMismatch)
        );
        mission
            .reconcile_durable_provider_state(
                &effect_id,
                DurableProviderState::Uncertain,
                now() + chrono::Duration::seconds(1),
                now() + chrono::Duration::seconds(61),
            )
            .expect("durable uncertainty");
        let revision = mission.revision;
        mission
            .reconcile_durable_provider_state(
                &effect_id,
                DurableProviderState::Uncertain,
                now() + chrono::Duration::seconds(1),
                now() + chrono::Duration::seconds(61),
            )
            .expect("idempotent durable uncertainty");
        assert_eq!(mission.revision, revision);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::VerificationRequired
        );
    }

    #[test]
    fn continuous_outcomes_are_append_only_cycles_and_do_not_false_complete() {
        let mut contract = MissionContract::bootstrap(
            "Operate a weekly verified growth loop",
            ["research.discover".into()],
            now(),
        );
        contract.mode = OperatingMode::ContinuousOperator;
        contract.cadence = Some(Cadence {
            interval_seconds: 7 * 24 * 60 * 60,
            anchor_at: now(),
            trigger: CadenceTriggerKind::Interval,
            event_topics: BTreeSet::new(),
        });
        let mut mission = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("continuous-1"),
            ProjectId::from("project-1"),
            "Weekly operator",
            contract,
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("cycle one");
        mission
            .record_outcome(Outcome {
                summary: "First cycle measured without false causal claims".into(),
                decision: OutcomeDecision::Test,
                metrics: BTreeMap::new(),
                observed_at: now() + chrono::Duration::days(7),
            })
            .expect("first outcome");
        assert_eq!(mission.stage, MissionStage::Scheduled);
        assert!(!mission.stage.is_terminal());

        mission
            .start_scheduled_cycle(2, [], now() + chrono::Duration::days(8))
            .expect("cycle two");
        mission
            .record_outcome(Outcome {
                summary: "User chose a valid stop after the second cycle".into(),
                decision: OutcomeDecision::Stop,
                metrics: BTreeMap::new(),
                observed_at: now() + chrono::Duration::days(14),
            })
            .expect("second outcome");
        assert_eq!(mission.stage, MissionStage::Completed);
        assert_eq!(mission.outcome_history.len(), 2);
        assert_eq!(
            mission.outcome.as_ref().map(|outcome| &outcome.decision),
            Some(&OutcomeDecision::Stop)
        );
    }

    #[test]
    fn catalog_next_cycle_resets_only_a_terminal_checkpoint_dag_in_exact_order() {
        let mut contract = MissionContract::bootstrap(
            "Operate a verified two-checkpoint loop",
            ["research.discover".into()],
            now(),
        );
        contract.mode = OperatingMode::ContinuousOperator;
        contract.cadence = Some(Cadence {
            interval_seconds: 7 * 24 * 60 * 60,
            anchor_at: now(),
            trigger: CadenceTriggerKind::Interval,
            event_topics: BTreeSet::new(),
        });
        contract.valid_until = now() + chrono::Duration::days(90);
        let definition = MissionDefinition::from_linear_manifest(
            "VM-TEST",
            1,
            "a".repeat(64),
            OperatingMode::ContinuousOperator,
            contract.enabled_capabilities.iter().cloned(),
            ["review_pack".into()],
            ["truth".into()],
            ["baseline".into(), "review".into()],
        )
        .expect("definition");
        let mut mission = Mission::compile_catalog(
            TenantId::from("tenant-cycle"),
            MissionId::from("mission-cycle"),
            ProjectId::from("project-cycle"),
            "Catalog cycle",
            contract,
            definition,
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("cycle one");
        for (offset, checkpoint_id) in [(1, "baseline"), (2, "review")] {
            if checkpoint_id == "review" {
                mission
                    .begin_checkpoint(checkpoint_id, now() + chrono::Duration::hours(offset))
                    .expect("begin next checkpoint");
            }
            mission
                .begin_checkpoint_verification(
                    checkpoint_id,
                    now() + chrono::Duration::hours(offset) + chrono::Duration::minutes(1),
                )
                .expect("begin verification");
            mission
                .complete_checkpoint(
                    checkpoint_id,
                    MissionCheckpointCompletion {
                        oracle_ids: BTreeSet::from(["truth".into()]),
                        work_product_ids: BTreeSet::new(),
                        effect_ids: BTreeSet::new(),
                        application_evidence: None,
                        evidence_digest: format!("{offset}").repeat(64),
                        verified_at: now()
                            + chrono::Duration::hours(offset)
                            + chrono::Duration::minutes(2),
                    },
                )
                .expect("complete checkpoint");
        }
        mission
            .record_outcome(Outcome {
                summary: "Cycle one DAG and Outcome verified".into(),
                decision: OutcomeDecision::Continue,
                metrics: BTreeMap::new(),
                observed_at: now() + chrono::Duration::days(1),
            })
            .expect("review cycle");
        assert_eq!(
            mission.start_scheduled_cycle(3, [], now() + chrono::Duration::days(7)),
            Err(MissionError::InvalidMissionCycle {
                expected: 2,
                actual: 3,
            })
        );
        mission
            .start_scheduled_cycle(2, [], now() + chrono::Duration::days(7))
            .expect("cycle two");
        let definition = mission.definition.as_ref().expect("definition");
        assert_eq!(definition.cycle, 2);
        assert_eq!(
            definition.checkpoints[0].status,
            MissionCheckpointStatus::Running
        );
        assert_eq!(definition.checkpoints[0].attempt, 1);
        assert!(definition.checkpoints[0].completion.is_none());
        assert_eq!(
            definition.checkpoints[1].status,
            MissionCheckpointStatus::Pending
        );
        assert_eq!(definition.checkpoints[1].attempt, 0);
        assert!(definition.checkpoints[1].completion.is_none());
    }

    #[test]
    fn interval_contract_boundary_is_a_legal_completion_not_a_stuck_schedule() {
        let mut contract = MissionContract::bootstrap(
            "Operate only inside the contracted window",
            ["research.discover".into()],
            now(),
        );
        contract.mode = OperatingMode::ContinuousOperator;
        contract.valid_until = now() + chrono::Duration::days(5);
        contract.cadence = Some(Cadence {
            interval_seconds: 7 * 24 * 60 * 60,
            anchor_at: now(),
            trigger: CadenceTriggerKind::Interval,
            event_topics: BTreeSet::new(),
        });
        let mut mission = Mission::compile(
            TenantId::from("tenant-window"),
            MissionId::from("mission-window"),
            ProjectId::from("project-window"),
            "Bounded operator",
            contract,
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("first cycle");
        mission
            .record_outcome(Outcome {
                summary: "The final in-window cycle was reviewed".into(),
                decision: OutcomeDecision::Continue,
                metrics: BTreeMap::new(),
                observed_at: now() + chrono::Duration::days(1),
            })
            .expect("outcome");
        assert_eq!(mission.stage, MissionStage::Completed);
        assert_eq!(mission.outcome_history.len(), 1);
    }

    #[test]
    fn expected_refusal_is_a_first_class_terminal_state() {
        let mut mission = mission();
        mission.start_research([], now()).expect("running");
        mission
            .terminate(
                MissionTerminalDisposition::ExpectedRefusal,
                now() + chrono::Duration::minutes(1),
            )
            .expect("expected refusal");
        assert_eq!(mission.stage, MissionStage::ExpectedRefusal);
        assert!(mission.stage.is_terminal());
        assert_eq!(
            mission.resume(now() + chrono::Duration::minutes(2)),
            Err(MissionError::InvalidMissionStage {
                actual: MissionStage::ExpectedRefusal,
                expected: vec![MissionStage::Blocked, MissionStage::WaitingUser],
            })
        );
    }
}

//! The only path from a proposed Hartevo business effect to a provider.

pub mod provider_contract;

pub use provider_contract::{
    PROVIDER_ADAPTER_BASELINE_REGISTRY_VERSION, PROVIDER_ADAPTER_CONTRACT_JSON,
    PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION, PROVIDER_ADAPTER_CONTRACT_VERSION,
    ProviderAdapterIdentity, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityEvidenceClaim, ProviderCapabilityKey, ProviderCapabilitySupport,
    ProviderContractError, ProviderEvidenceAuthority, ProviderEvidenceClass,
    ProviderEvidenceSupport, ProviderProvenanceClass, ValidatedProviderEvidenceBinding,
};

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, ConnectionId, ConsentRecordId,
    ConsentState, ConversationId, CreatorHiringId, CurrencyCode, DurableProviderState, Effect,
    EffectClass, EffectId, EffectStatus, ExecutionAttemptId, Mission, MissionError, PartnerId,
    Receipt, Verification, VerificationStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct EffectPolicy {
    pub version: String,
    pub allowed_capabilities: BTreeSet<String>,
    pub allowed_classes: BTreeSet<EffectClass>,
    pub max_amounts_minor: BTreeMap<CurrencyCode, i64>,
    pub rate_limits: Vec<EffectRateLimit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRateLimit {
    pub rule_id: String,
    pub provider: String,
    pub capability: String,
    pub max_executions: u64,
    pub window_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitRequest {
    pub rule_id: String,
    pub policy_version: String,
    pub policy_digest: String,
    pub tenant_id: hartevo_domain_kernel::TenantId,
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub provider: String,
    pub account_id: Option<AccountId>,
    pub capability: String,
    pub max_executions: u64,
    pub window_seconds: u64,
    pub scope_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionClaimContext {
    pub permission_evidence: PermissionEvidence,
    pub policy_digest: String,
    pub authorization_digest: String,
    pub rate_limit: RateLimitRequest,
}

impl ExecutionClaimContext {
    pub fn validate_for(&self, effect: &Effect) -> Result<(), LedgerError> {
        self.rate_limit.validate_for(effect)?;
        self.permission_evidence
            .validate_for_effect(effect)
            .map_err(|_| LedgerError::ScopeConflict)?;
        if !is_sha256(&self.policy_digest)
            || self.policy_digest != self.rate_limit.policy_digest
            || !is_sha256(&self.authorization_digest)
        {
            return Err(LedgerError::ScopeConflict);
        }
        let permission_digest = self
            .permission_evidence
            .digest(effect)
            .map_err(|error| LedgerError::Persistence(error.to_string()))?;
        let expected = authorization_digest(&permission_digest, &self.policy_digest);
        if self.authorization_digest != expected
            || effect
                .approval
                .as_ref()
                .is_none_or(|approval| approval.permission_digest != expected)
        {
            return Err(LedgerError::ScopeConflict);
        }
        Ok(())
    }

    pub fn validate_dispatch_at(
        &self,
        effect: &Effect,
        now: DateTime<Utc>,
    ) -> Result<(), LedgerError> {
        self.validate_for(effect)?;
        let approval = effect.approval.as_ref().ok_or(LedgerError::ScopeConflict)?;
        if effect.status != EffectStatus::Approved
            || approval.scope_digest != effect.approval_digest()
            || now >= approval.valid_until
            || now >= effect.expires_at
            || effect
                .scheduled_for
                .is_some_and(|scheduled| scheduled > now)
        {
            return Err(LedgerError::DispatchNotAuthorized);
        }
        Ok(())
    }
}

impl RateLimitRequest {
    pub fn validate_for(&self, effect: &Effect) -> Result<(), LedgerError> {
        let expected = Self::for_effect(
            effect,
            &EffectRateLimit {
                rule_id: self.rule_id.clone(),
                provider: self.provider.clone(),
                capability: self.capability.clone(),
                max_executions: self.max_executions,
                window_seconds: self.window_seconds,
            },
            &self.policy_digest,
        )
        .map_err(|error| LedgerError::Persistence(error.to_string()))?;
        if self.policy_version != effect.policy_version || expected != *self {
            return Err(LedgerError::ScopeConflict);
        }
        Ok(())
    }

    pub fn for_effect(
        effect: &Effect,
        rule: &EffectRateLimit,
        policy_digest: &str,
    ) -> Result<Self, BrokerError> {
        rule.validate()?;
        if rule.provider != effect.provider
            || rule.capability != effect.capability
            || !is_sha256(policy_digest)
        {
            return Err(BrokerError::RateLimitRuleMissing {
                provider: effect.provider.clone(),
                capability: effect.capability.clone(),
            });
        }
        let mut digest = Sha256::new();
        hash_field(&mut digest, "hartevo-effect-rate-limit-scope/v1");
        hash_field(&mut digest, effect.tenant_id.as_str());
        hash_field(&mut digest, effect.project_id.as_str());
        hash_field(&mut digest, &rule.rule_id);
        hash_field(&mut digest, &effect.policy_version);
        hash_field(&mut digest, policy_digest);
        hash_field(&mut digest, &effect.provider);
        hash_optional(
            &mut digest,
            effect.account_id.as_ref().map(AccountId::as_str),
        );
        hash_field(&mut digest, &effect.capability);
        hash_field(&mut digest, &rule.max_executions.to_string());
        hash_field(&mut digest, &rule.window_seconds.to_string());
        Ok(Self {
            rule_id: rule.rule_id.clone(),
            policy_version: effect.policy_version.clone(),
            policy_digest: policy_digest.into(),
            tenant_id: effect.tenant_id.clone(),
            project_id: effect.project_id.clone(),
            provider: effect.provider.clone(),
            account_id: effect.account_id.clone(),
            capability: effect.capability.clone(),
            max_executions: rule.max_executions,
            window_seconds: rule.window_seconds,
            scope_digest: format!("{:x}", digest.finalize()),
        })
    }
}

impl EffectRateLimit {
    fn validate(&self) -> Result<(), BrokerError> {
        if self.rule_id.trim().is_empty()
            || self.provider.trim().is_empty()
            || self.capability.trim().is_empty()
            || self.max_executions == 0
            || self.window_seconds == 0
            || self.window_seconds > i64::MAX as u64
        {
            return Err(BrokerError::InvalidPolicy(
                "rate-limit rules require a stable id, exact provider/capability, and positive bounded window/capacity"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl EffectPolicy {
    pub fn permits(&self, effect: &Effect) -> Result<(), BrokerError> {
        self.validate()?;
        if self.version != effect.policy_version {
            return Err(BrokerError::PolicyVersionMismatch {
                approved: effect.policy_version.clone(),
                active: self.version.clone(),
            });
        }
        if !self.allowed_capabilities.contains(&effect.capability) {
            return Err(BrokerError::CapabilityDenied(effect.capability.clone()));
        }
        if !self.allowed_classes.contains(&effect.effect_class) {
            return Err(BrokerError::EffectClassDenied(effect.effect_class.clone()));
        }
        let allowed = self
            .max_amounts_minor
            .get(&effect.amount.currency)
            .copied()
            .ok_or_else(|| BrokerError::CurrencyDenied(effect.amount.currency.clone()))?;
        if effect.amount.amount_minor > allowed {
            return Err(BrokerError::CostLimitExceeded {
                requested: effect.amount.amount_minor,
                allowed,
            });
        }
        if matches!(
            effect.consent,
            ConsentState::Missing | ConsentState::Withdrawn
        ) {
            return Err(BrokerError::ConsentMissing);
        }
        self.rate_limit_request(effect)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), BrokerError> {
        if self.version.trim().is_empty()
            || self.allowed_capabilities.is_empty()
            || self.allowed_classes.is_empty()
            || self.max_amounts_minor.is_empty()
            || self.max_amounts_minor.values().any(|amount| *amount < 0)
            || self.rate_limits.is_empty()
        {
            return Err(BrokerError::InvalidPolicy(
                "policy version, capability/class/currency limits, and rate-limit rules are required"
                    .into(),
            ));
        }
        let mut rule_ids = BTreeSet::new();
        let mut selectors = BTreeSet::new();
        for rule in &self.rate_limits {
            rule.validate()?;
            if !rule_ids.insert(rule.rule_id.clone())
                || !selectors.insert((rule.provider.clone(), rule.capability.clone()))
            {
                return Err(BrokerError::InvalidPolicy(
                    "rate-limit rule ids and provider/capability selectors must be unique".into(),
                ));
            }
        }
        Ok(())
    }

    fn rate_limit_request(&self, effect: &Effect) -> Result<RateLimitRequest, BrokerError> {
        let rule = self
            .rate_limits
            .iter()
            .find(|rule| rule.provider == effect.provider && rule.capability == effect.capability)
            .ok_or_else(|| BrokerError::RateLimitRuleMissing {
                provider: effect.provider.clone(),
                capability: effect.capability.clone(),
            })?;
        RateLimitRequest::for_effect(effect, rule, &self.canonical_digest())
    }

    pub fn authorization_digest(&self, permission_digest: &str) -> String {
        authorization_digest(permission_digest, &self.canonical_digest())
    }

    pub fn execution_claim_context(
        &self,
        effect: &Effect,
        permission_evidence: PermissionEvidence,
    ) -> Result<ExecutionClaimContext, BrokerError> {
        self.permits(effect)?;
        permission_evidence.validate_for_effect(effect)?;
        let policy_digest = self.canonical_digest();
        let permission_digest = permission_evidence.digest(effect)?;
        Ok(ExecutionClaimContext {
            permission_evidence,
            policy_digest: policy_digest.clone(),
            authorization_digest: authorization_digest(&permission_digest, &policy_digest),
            rate_limit: self.rate_limit_request(effect)?,
        })
    }

    fn canonical_digest(&self) -> String {
        let mut digest = Sha256::new();
        hash_field(&mut digest, "hartevo-effect-policy/v1");
        hash_field(&mut digest, &self.version);
        for capability in &self.allowed_capabilities {
            hash_field(&mut digest, capability);
        }
        for class in &self.allowed_classes {
            hash_field(&mut digest, effect_class_name(class));
        }
        for (currency, amount) in &self.max_amounts_minor {
            hash_field(&mut digest, currency.as_str());
            hash_field(&mut digest, &amount.to_string());
        }
        let mut rules = self.rate_limits.iter().collect::<Vec<_>>();
        rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        for rule in rules {
            hash_field(&mut digest, &rule.rule_id);
            hash_field(&mut digest, &rule.provider);
            hash_field(&mut digest, &rule.capability);
            hash_field(&mut digest, &rule.max_executions.to_string());
            hash_field(&mut digest, &rule.window_seconds.to_string());
        }
        format!("{:x}", digest.finalize())
    }
}

/// Fresh authorization evidence obtained from the authoritative Connection and
/// Consent records. This is deliberately separate from the Effect payload: a
/// caller cannot make a revoked credential valid by serializing `Connected` into
/// an Effect.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PermissionFence {
    Connection {
        connection_id: ConnectionId,
        revision: u64,
    },
    Consent {
        consent_record_id: ConsentRecordId,
        revision: u64,
    },
    Conversation {
        conversation_id: ConversationId,
        revision: u64,
        control_generation: u64,
    },
    CreatorContact {
        hiring_id: CreatorHiringId,
        hiring_revision: u64,
        partner_id: PartnerId,
        partner_revision: u64,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PermissionEvidence {
    pub connection_evidence_digest: Option<String>,
    pub consent_evidence_digest: Option<String>,
    pub conversation_evidence_digest: Option<String>,
    pub creator_contact_evidence_digest: Option<String>,
    pub fences: BTreeSet<PermissionFence>,
}

impl PermissionEvidence {
    pub fn validate_for_effect(&self, effect: &Effect) -> Result<(), PermissionFailure> {
        let expected = permission_fence_kinds_for_effect(effect);
        if expected != permission_fence_kinds_for_evidence_digests(self) {
            return Err(PermissionFailure::InvalidEvidence);
        }
        let mut seen = BTreeSet::new();
        for fence in &self.fences {
            let kind = match fence {
                PermissionFence::Connection { connection_id, .. }
                    if effect.connection_id.as_ref() == Some(connection_id) =>
                {
                    PermissionFenceKind::Connection
                }
                PermissionFence::Consent {
                    consent_record_id, ..
                } if effect.consent_record_id.as_ref() == Some(consent_record_id) => {
                    PermissionFenceKind::Consent
                }
                PermissionFence::Conversation {
                    conversation_id,
                    control_generation,
                    ..
                } if effect.conversation_guard.as_ref().is_some_and(|guard| {
                    &guard.conversation_id == conversation_id
                        && guard.control_generation == *control_generation
                }) =>
                {
                    PermissionFenceKind::Conversation
                }
                PermissionFence::CreatorContact {
                    hiring_id,
                    partner_id,
                    ..
                } if effect.creator_contact_guard.as_ref().is_some_and(|guard| {
                    &guard.hiring_id == hiring_id && &guard.partner_id == partner_id
                }) =>
                {
                    PermissionFenceKind::CreatorContact
                }
                _ => return Err(PermissionFailure::InvalidEvidence),
            };
            if !seen.insert(kind) {
                return Err(PermissionFailure::InvalidEvidence);
            }
        }
        if expected != seen {
            return Err(PermissionFailure::InvalidEvidence);
        }
        self.digest(effect).map(|_| ())
    }

    pub fn digest(&self, effect: &Effect) -> Result<String, PermissionFailure> {
        for value in [
            self.connection_evidence_digest.as_deref(),
            self.consent_evidence_digest.as_deref(),
            self.conversation_evidence_digest.as_deref(),
            self.creator_contact_evidence_digest.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !is_sha256(value) {
                return Err(PermissionFailure::InvalidEvidence);
            }
        }
        let mut digest = Sha256::new();
        hash_field(&mut digest, &effect.approval_digest());
        hash_optional(&mut digest, self.connection_evidence_digest.as_deref());
        hash_optional(&mut digest, self.consent_evidence_digest.as_deref());
        hash_optional(&mut digest, self.conversation_evidence_digest.as_deref());
        hash_optional(&mut digest, self.creator_contact_evidence_digest.as_deref());
        for fence in &self.fences {
            hash_permission_fence(&mut digest, fence)?;
        }
        Ok(format!("{:x}", digest.finalize()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PermissionFenceKind {
    Connection,
    Consent,
    Conversation,
    CreatorContact,
}

fn permission_fence_kinds_for_effect(effect: &Effect) -> BTreeSet<PermissionFenceKind> {
    let mut kinds = BTreeSet::new();
    if effect.connection_id.is_some() {
        kinds.insert(PermissionFenceKind::Connection);
    }
    if effect.consent_record_id.is_some() {
        kinds.insert(PermissionFenceKind::Consent);
    }
    if effect.conversation_guard.is_some() {
        kinds.insert(PermissionFenceKind::Conversation);
    }
    if effect.creator_contact_guard.is_some() {
        kinds.insert(PermissionFenceKind::CreatorContact);
    }
    kinds
}

fn permission_fence_kinds_for_evidence_digests(
    evidence: &PermissionEvidence,
) -> BTreeSet<PermissionFenceKind> {
    let mut kinds = BTreeSet::new();
    if evidence.connection_evidence_digest.is_some() {
        kinds.insert(PermissionFenceKind::Connection);
    }
    if evidence.consent_evidence_digest.is_some() {
        kinds.insert(PermissionFenceKind::Consent);
    }
    if evidence.conversation_evidence_digest.is_some() {
        kinds.insert(PermissionFenceKind::Conversation);
    }
    if evidence.creator_contact_evidence_digest.is_some() {
        kinds.insert(PermissionFenceKind::CreatorContact);
    }
    kinds
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PermissionFailure {
    #[error("the referenced provider connection is missing")]
    ConnectionMissing,
    #[error("the provider connection belongs to another tenant or project")]
    ConnectionScopeMismatch,
    #[error("the provider, account, or required scopes do not match the live connection")]
    ConnectionAccountOrScopeMismatch,
    #[error("the provider connection has no current successful probe")]
    ConnectionNotConnected,
    #[error("the required consent record is missing")]
    ConsentMissing,
    #[error("the consent record belongs to another tenant or project")]
    ConsentScopeMismatch,
    #[error(
        "the consent record does not authorize the exact person, purpose, channel, market, and time"
    )]
    ConsentNotPermitted,
    #[error("the conversation control guard is missing or belongs to another scope")]
    ConversationGuardMissingOrScopedElsewhere,
    #[error("the conversation is under human control or the prepared effect generation is stale")]
    ConversationControlLost,
    #[error("the creator contact guard is missing or belongs to another hiring scope")]
    CreatorContactGuardMissingOrScopedElsewhere,
    #[error(
        "creator contact permission was withdrawn or no longer matches the approved invitation"
    )]
    CreatorContactPermissionLost,
    #[error("permission evidence is not a SHA-256 digest")]
    InvalidEvidence,
    #[error("authorization storage failed closed: {0}")]
    Unavailable(String),
}

pub trait EffectPermissionResolver {
    fn authorize(
        &self,
        effect: &Effect,
        now: DateTime<Utc>,
    ) -> Result<PermissionEvidence, PermissionFailure>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionDisposition {
    Executed,
    ReusedIdempotentReceipt,
    AlreadyVerified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerResult {
    pub disposition: ExecutionDisposition,
    pub receipt: Receipt,
    pub verification: Verification,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderFailure {
    #[error("provider rejected the effect: {0}")]
    Rejected(String),
    #[error("provider state is uncertain and must be verified before any retry: {0}")]
    Uncertain(String),
}

pub trait EffectExecutor {
    fn execute(&mut self, effect: &Effect) -> Result<Receipt, ProviderFailure>;
}

pub trait EffectVerifier {
    fn verify(&mut self, effect: &Effect, receipt: &Receipt) -> Verification;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionLease {
    pub attempt_id: ExecutionAttemptId,
    pub owner: String,
    pub generation: u64,
    pub expires_at: DateTime<Utc>,
}

/// Bounded policy for read-only Provider reconciliation. This policy never
/// grants an execution permit and is durably bound on the first reconcile
/// claim so a later worker cannot silently increase retries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationPolicy {
    pub version: String,
    pub max_attempts: u32,
    pub retry_delay_seconds: u64,
}

impl ReconciliationPolicy {
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.version.trim().is_empty()
            || self.max_attempts == 0
            || self.max_attempts > 100
            || self.retry_delay_seconds == 0
            || self.retry_delay_seconds > 2_592_000
        {
            return Err(LedgerError::Persistence(
                "reconciliation policy requires a stable version, 1..=100 attempts, and a 1 second..=30 day retry delay"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String, LedgerError> {
        self.validate()?;
        let mut digest = Sha256::new();
        hash_field(&mut digest, "hartevo-effect-reconciliation-policy/v1");
        hash_field(&mut digest, &self.version);
        hash_field(&mut digest, &self.max_attempts.to_string());
        hash_field(&mut digest, &self.retry_delay_seconds.to_string());
        Ok(format!("{:x}", digest.finalize()))
    }
}

impl Default for ReconciliationPolicy {
    fn default() -> Self {
        Self {
            version: "effect-reconciliation-v1".into(),
            max_attempts: 3,
            retry_delay_seconds: 60,
        }
    }
}

/// A reconciliation lease is deliberately not an `ExecutionLease`: adapters
/// holding this value may perform read/reconcile operations only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationLease {
    pub attempt_id: ExecutionAttemptId,
    pub owner: String,
    pub generation: u64,
    pub attempt_no: u32,
    pub max_attempts: u32,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ReconciliationObservation {
    ReceiptFound {
        receipt: Receipt,
        evidence_digest: String,
        observed_at: DateTime<Utc>,
    },
    NotExecuted {
        evidence_digest: String,
        observed_at: DateTime<Utc>,
    },
    ProviderRejected {
        reason: String,
        evidence_digest: String,
        observed_at: DateTime<Utc>,
    },
    StillUncertain {
        reason: String,
        evidence_digest: String,
        observed_at: DateTime<Utc>,
    },
}

impl ReconciliationObservation {
    pub fn validate_for(
        &self,
        effect: &Effect,
        execution_started_at: DateTime<Utc>,
    ) -> Result<(), LedgerError> {
        let (evidence_digest, observed_at, reason) = match self {
            Self::ReceiptFound {
                receipt,
                evidence_digest,
                observed_at,
            } => {
                let dispatch_is_bound_to_original_approval =
                    effect.approval.as_ref().is_some_and(|approval| {
                        approval.scope_digest == effect.approval_digest()
                            && execution_started_at >= approval.decided_at
                            && execution_started_at < approval.valid_until
                            && execution_started_at < effect.expires_at
                    });
                if !dispatch_is_bound_to_original_approval
                    || receipt.provider != effect.provider
                    || receipt.external_id.trim().is_empty()
                    || receipt.request_digest != effect.approval_digest()
                    || !is_sha256(&receipt.response_digest)
                    || receipt.accepted_at < execution_started_at
                    || receipt.accepted_at >= effect.expires_at
                    || *observed_at < receipt.accepted_at
                {
                    return Err(LedgerError::ScopeConflict);
                }
                (evidence_digest, observed_at, None)
            }
            Self::NotExecuted {
                evidence_digest,
                observed_at,
            } => (evidence_digest, observed_at, None),
            Self::ProviderRejected {
                reason,
                evidence_digest,
                observed_at,
            }
            | Self::StillUncertain {
                reason,
                evidence_digest,
                observed_at,
            } => (evidence_digest, observed_at, Some(reason)),
        };
        if !is_sha256(evidence_digest)
            || *observed_at < execution_started_at
            || reason.is_some_and(|value| value.trim().is_empty())
        {
            return Err(LedgerError::ScopeConflict);
        }
        Ok(())
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &str {
        match self {
            Self::ReceiptFound {
                evidence_digest, ..
            }
            | Self::NotExecuted {
                evidence_digest, ..
            }
            | Self::ProviderRejected {
                evidence_digest, ..
            }
            | Self::StillUncertain {
                evidence_digest, ..
            } => evidence_digest,
        }
    }

    #[must_use]
    pub const fn observed_at(&self) -> DateTime<Utc> {
        match self {
            Self::ReceiptFound { observed_at, .. }
            | Self::NotExecuted { observed_at, .. }
            | Self::ProviderRejected { observed_at, .. }
            | Self::StillUncertain { observed_at, .. } => *observed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationClaim {
    Acquired {
        lease: ReconciliationLease,
        execution_started_at: DateTime<Utc>,
    },
    Resolved(LedgerClaim),
    NotReady {
        retry_at: DateTime<Utc>,
    },
    Busy,
    NotRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationDisposition {
    ReceiptReadyForVerification {
        lease: ExecutionLease,
        receipt: Receipt,
        execution_started_at: DateTime<Utc>,
    },
    ReconciledNotExecuted {
        evidence_digest: String,
        observed_at: DateTime<Utc>,
        execution_started_at: DateTime<Utc>,
    },
    ProviderRejected {
        reason: String,
        evidence_digest: String,
        observed_at: DateTime<Utc>,
        execution_started_at: DateTime<Utc>,
    },
    RetryScheduled {
        reason: String,
        evidence_digest: String,
        observed_at: DateTime<Utc>,
        retry_at: DateTime<Utc>,
        attempt_no: u32,
        execution_started_at: DateTime<Utc>,
    },
    DeadLetter {
        reason: String,
        evidence_digest: String,
        dead_lettered_at: DateTime<Utc>,
        attempts: u32,
        execution_started_at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerClaim {
    Acquired {
        lease: ExecutionLease,
        receipt: Option<Receipt>,
        execution_started_at: DateTime<Utc>,
    },
    AlreadyVerified {
        receipt: Receipt,
        verification: Verification,
        execution_started_at: DateTime<Utc>,
    },
    ProviderRejected {
        reason: String,
        execution_started_at: DateTime<Utc>,
        recorded_at: DateTime<Utc>,
    },
    Uncertain {
        reason: String,
        execution_started_at: DateTime<Utc>,
        recorded_at: DateTime<Utc>,
    },
    DurableVerification {
        receipt: Receipt,
        verification: Verification,
        execution_started_at: DateTime<Utc>,
    },
    ReconciledNotExecuted {
        evidence_digest: String,
        observed_at: DateTime<Utc>,
        execution_started_at: DateTime<Utc>,
    },
    DeadLetter {
        reason: String,
        evidence_digest: String,
        dead_lettered_at: DateTime<Utc>,
        attempts: u32,
        execution_started_at: DateTime<Utc>,
    },
    RateLimited {
        retry_at: DateTime<Utc>,
    },
    AuthorizationRequired,
    Busy,
}

enum ResolvedLedgerClaim {
    Acquired {
        lease: ExecutionLease,
        receipt: Option<Receipt>,
        execution_started_at: DateTime<Utc>,
    },
    Complete(BrokerResult),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableRateLimitDirective {
    Reserve { next_consumed: u64 },
    Deny,
}

#[must_use]
pub fn decide_durable_rate_limit(consumed: u64, max_executions: u64) -> DurableRateLimitDirective {
    match consumed.checked_add(1) {
        Some(next_consumed) if max_executions > 0 && next_consumed <= max_executions => {
            DurableRateLimitDirective::Reserve { next_consumed }
        }
        _ => DurableRateLimitDirective::Deny,
    }
}

/// Minimal persisted state used to make claim semantics deterministic across
/// SQLite/PostgreSQL implementations and concurrency-model tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistedClaimState {
    Executing,
    ReceiptRecorded,
    Verified,
    Uncertain,
    VerificationRequired,
    Failed,
}

impl PersistedClaimState {
    #[must_use]
    pub fn from_storage_name(value: &str) -> Option<Self> {
        match value {
            "executing" => Some(Self::Executing),
            "receipt_recorded" => Some(Self::ReceiptRecorded),
            "verified" => Some(Self::Verified),
            "uncertain" => Some(Self::Uncertain),
            "verification_required" => Some(Self::VerificationRequired),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableClaimDirective {
    BeginProviderExecution,
    ResumeVerificationFromReceipt,
    ReturnVerified,
    ReturnProviderFailed,
    ReturnUncertain,
    ReturnVerification,
    ReturnBusy,
    FreezeExpiredExecution,
}

/// Pure decision core for a durable effect claim. In particular, no persisted
/// state is ever allowed to return a second provider-execution permit.
#[must_use]
pub fn decide_durable_claim(
    state: Option<PersistedClaimState>,
    execution_lease_live: bool,
) -> DurableClaimDirective {
    match state {
        None => DurableClaimDirective::BeginProviderExecution,
        Some(PersistedClaimState::Executing) if execution_lease_live => {
            DurableClaimDirective::ReturnBusy
        }
        Some(PersistedClaimState::Executing) => DurableClaimDirective::FreezeExpiredExecution,
        Some(PersistedClaimState::ReceiptRecorded) => {
            DurableClaimDirective::ResumeVerificationFromReceipt
        }
        Some(PersistedClaimState::Verified) => DurableClaimDirective::ReturnVerified,
        Some(PersistedClaimState::Uncertain) => DurableClaimDirective::ReturnUncertain,
        Some(PersistedClaimState::VerificationRequired) => {
            DurableClaimDirective::ReturnVerification
        }
        Some(PersistedClaimState::Failed) => DurableClaimDirective::ReturnProviderFailed,
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LedgerError {
    #[error("effect ledger scope conflicts with the stored idempotency record")]
    ScopeConflict,
    #[error("effect execution lease is no longer current")]
    LeaseLost,
    #[error("effect dispatch is not currently authorized")]
    DispatchNotAuthorized,
    #[error("effect ledger persistence failed: {0}")]
    Persistence(String),
}

pub trait DurableEffectLedger {
    fn claim(
        &mut self,
        effect: &Effect,
        context: Option<&ExecutionClaimContext>,
        owner: &str,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<LedgerClaim, LedgerError>;

    fn record_receipt(
        &mut self,
        effect: &Effect,
        lease: &ExecutionLease,
        receipt: &Receipt,
        now: DateTime<Utc>,
    ) -> Result<(), LedgerError>;

    fn record_verification(
        &mut self,
        effect: &Effect,
        lease: &ExecutionLease,
        verification: &Verification,
        now: DateTime<Utc>,
    ) -> Result<(), LedgerError>;

    fn record_failed(
        &mut self,
        effect: &Effect,
        lease: &ExecutionLease,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<(), LedgerError>;

    fn record_uncertain(
        &mut self,
        effect: &Effect,
        lease: &ExecutionLease,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<(), LedgerError>;

    fn claim_reconciliation(
        &mut self,
        effect: &Effect,
        policy: &ReconciliationPolicy,
        owner: &str,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<ReconciliationClaim, LedgerError>;

    fn record_reconciliation(
        &mut self,
        effect: &Effect,
        lease: &ReconciliationLease,
        observation: &ReconciliationObservation,
        now: DateTime<Utc>,
    ) -> Result<ReconciliationDisposition, LedgerError>;
}

/// A single infrastructure object supplies both fresh authorization state and
/// durable execution state, avoiding a check/execute path that can accidentally
/// use an in-memory ledger.
pub trait EffectInfrastructure: DurableEffectLedger + EffectPermissionResolver {}

impl<T> EffectInfrastructure for T where T: DurableEffectLedger + EffectPermissionResolver {}

/// Provider adapters implement this as a read/reconcile operation. The method
/// receives no `ExecutionLease`, approval grant, or write capability.
pub trait EffectReconciler {
    fn reconcile(&mut self, effect: &Effect) -> ReconciliationObservation;
}

#[derive(Debug)]
pub struct EffectBroker {
    policy: EffectPolicy,
    worker_id: String,
    lease_for: chrono::Duration,
    reconciliation_policy: ReconciliationPolicy,
}

impl EffectBroker {
    pub fn new(policy: EffectPolicy, worker_id: impl Into<String>) -> Self {
        Self {
            policy,
            worker_id: worker_id.into(),
            lease_for: chrono::Duration::seconds(30),
            reconciliation_policy: ReconciliationPolicy::default(),
        }
    }

    #[must_use]
    pub fn with_lease_for(mut self, lease_for: chrono::Duration) -> Self {
        self.lease_for = lease_for;
        self
    }

    pub fn with_reconciliation_policy(
        mut self,
        policy: ReconciliationPolicy,
    ) -> Result<Self, BrokerError> {
        policy.validate()?;
        self.reconciliation_policy = policy;
        Ok(self)
    }

    pub fn approve(
        &self,
        mission: &mut Mission,
        effect_id: &EffectId,
        actor_id: ActorId,
        permissions: &impl EffectPermissionResolver,
        now: DateTime<Utc>,
    ) -> Result<(), BrokerError> {
        let approval_valid_until = mission.approval_valid_until(effect_id, now)?;
        let effect = mission.effect(effect_id)?;
        self.policy.permits(effect)?;
        if effect.expires_at <= now {
            return Err(BrokerError::Expired);
        }
        let scope_digest = effect.approval_digest();
        let permission_evidence = permissions.authorize(effect, now)?;
        permission_evidence.validate_for_effect(effect)?;
        let permission_digest = self
            .policy
            .authorization_digest(&permission_evidence.digest(effect)?);
        let approval = Approval {
            id: ApprovalId::from_stable(format!("approval-{scope_digest}")),
            decision: ApprovalDecision::Approved,
            decided_by: actor_id,
            decided_at: now,
            valid_until: approval_valid_until,
            scope_digest,
            permission_digest,
        };
        mission.approve_effect(effect_id, approval)?;
        Ok(())
    }

    pub fn execute_and_verify(
        &mut self,
        mission: &mut Mission,
        effect_id: &EffectId,
        infrastructure: &mut impl EffectInfrastructure,
        executor: &mut impl EffectExecutor,
        verifier: &mut impl EffectVerifier,
        now: DateTime<Utc>,
    ) -> Result<BrokerResult, BrokerError> {
        let effect = mission.effect(effect_id)?.clone();
        if effect.status == EffectStatus::Verified {
            return Ok(BrokerResult {
                disposition: ExecutionDisposition::AlreadyVerified,
                receipt: effect.receipt.ok_or(BrokerError::MissingReceipt)?,
                verification: effect
                    .verification
                    .ok_or(BrokerError::MissingVerification)?,
            });
        }
        if !matches!(
            effect.status,
            EffectStatus::Approved
                | EffectStatus::Executing
                | EffectStatus::ReceiptRecorded
                | EffectStatus::VerificationRequired
                | EffectStatus::Reconciled
                | EffectStatus::DeadLetter
                | EffectStatus::Failed
        ) {
            return Err(BrokerError::NotApproved(effect.status.clone()));
        }
        let claim = self.claim_recovery_or_fresh(&effect, infrastructure, now)?;
        let (lease, existing_receipt, execution_started_at) =
            match Self::resolve_ledger_claim(mission, effect_id, claim)? {
                ResolvedLedgerClaim::Acquired {
                    lease,
                    receipt,
                    execution_started_at,
                } => (lease, receipt, execution_started_at),
                ResolvedLedgerClaim::Complete(result) => return Ok(result),
            };

        let (receipt, disposition) = if let Some(receipt) = existing_receipt {
            mission.reconcile_durable_receipt(effect_id, receipt.clone(), execution_started_at)?;
            (receipt, ExecutionDisposition::ReusedIdempotentReceipt)
        } else {
            mission.begin_effect(effect_id, now)?;
            match executor.execute(&effect) {
                Ok(receipt) => {
                    let mut candidate = mission.clone();
                    candidate.record_receipt(effect_id, receipt.clone())?;
                    infrastructure.record_receipt(&effect, &lease, &receipt, now)?;
                    *mission = candidate;
                    (receipt, ExecutionDisposition::Executed)
                }
                Err(ProviderFailure::Rejected(reason)) => {
                    infrastructure.record_failed(&effect, &lease, &reason, now)?;
                    mission.mark_effect_failed(effect_id, now)?;
                    return Err(BrokerError::ProviderRejected(reason));
                }
                Err(ProviderFailure::Uncertain(reason)) => {
                    infrastructure.record_uncertain(&effect, &lease, &reason, now)?;
                    mission.mark_effect_uncertain(effect_id, now)?;
                    return Err(BrokerError::ProviderUncertain(reason));
                }
            }
        };

        let effect_with_receipt = mission.effect(effect_id)?.clone();
        let verification = verifier.verify(&effect_with_receipt, &receipt);
        let mut candidate = mission.clone();
        candidate.record_verification(effect_id, verification.clone())?;
        infrastructure.record_verification(&effect, &lease, &verification, now)?;
        *mission = candidate;
        match verification.status {
            VerificationStatus::Rejected => return Err(BrokerError::VerificationRejected),
            VerificationStatus::Inconclusive => {
                return Err(BrokerError::VerificationInconclusive);
            }
            VerificationStatus::Confirmed => {}
        }

        Ok(BrokerResult {
            disposition,
            receipt,
            verification,
        })
    }

    pub fn reconcile_uncertain(
        &mut self,
        mission: &mut Mission,
        effect_id: &EffectId,
        infrastructure: &mut impl EffectInfrastructure,
        reconciler: &mut impl EffectReconciler,
        verifier: &mut impl EffectVerifier,
        now: DateTime<Utc>,
    ) -> Result<BrokerResult, BrokerError> {
        let effect = mission.effect(effect_id)?.clone();
        if effect.status != EffectStatus::VerificationRequired {
            return Err(BrokerError::ReconciliationNotRequired);
        }
        let claim = infrastructure.claim_reconciliation(
            &effect,
            &self.reconciliation_policy,
            &self.worker_id,
            now,
            self.lease_expiry(now)?,
        )?;
        let (lease, execution_started_at) = match claim {
            ReconciliationClaim::Acquired {
                lease,
                execution_started_at,
            } => (lease, execution_started_at),
            ReconciliationClaim::Resolved(claim) => {
                return match Self::resolve_ledger_claim(mission, effect_id, claim)? {
                    ResolvedLedgerClaim::Complete(result) => Ok(result),
                    ResolvedLedgerClaim::Acquired { .. } => {
                        Err(BrokerError::ReconciliationNotRequired)
                    }
                };
            }
            ReconciliationClaim::NotReady { retry_at } => {
                return Err(BrokerError::ReconciliationNotReady { retry_at });
            }
            ReconciliationClaim::Busy => return Err(BrokerError::ReconciliationBusy),
            ReconciliationClaim::NotRequired => {
                return Err(BrokerError::ReconciliationNotRequired);
            }
        };
        let observation = reconciler.reconcile(&effect);
        observation.validate_for(&effect, execution_started_at)?;
        let disposition =
            infrastructure.record_reconciliation(&effect, &lease, &observation, now)?;
        Self::finish_reconciliation(
            mission,
            effect_id,
            &effect,
            infrastructure,
            verifier,
            disposition,
        )
    }

    fn finish_reconciliation(
        mission: &mut Mission,
        effect_id: &EffectId,
        effect: &Effect,
        infrastructure: &mut impl EffectInfrastructure,
        verifier: &mut impl EffectVerifier,
        disposition: ReconciliationDisposition,
    ) -> Result<BrokerResult, BrokerError> {
        match disposition {
            ReconciliationDisposition::ReceiptReadyForVerification {
                lease,
                receipt,
                execution_started_at,
            } => {
                mission.reconcile_durable_receipt(
                    effect_id,
                    receipt.clone(),
                    execution_started_at,
                )?;
                let effect_with_receipt = mission.effect(effect_id)?.clone();
                let verification = verifier.verify(&effect_with_receipt, &receipt);
                let mut candidate = mission.clone();
                candidate.record_verification(effect_id, verification.clone())?;
                infrastructure.record_verification(
                    effect,
                    &lease,
                    &verification,
                    verification.observed_at,
                )?;
                *mission = candidate;
                match verification.status {
                    VerificationStatus::Confirmed => Ok(BrokerResult {
                        disposition: ExecutionDisposition::ReusedIdempotentReceipt,
                        receipt,
                        verification,
                    }),
                    VerificationStatus::Rejected => Err(BrokerError::VerificationRejected),
                    VerificationStatus::Inconclusive => Err(BrokerError::VerificationInconclusive),
                }
            }
            ReconciliationDisposition::ReconciledNotExecuted {
                evidence_digest,
                observed_at,
                execution_started_at,
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::ReconciledNotExecuted,
                    execution_started_at,
                    observed_at,
                )?;
                Err(BrokerError::ProviderNotExecuted { evidence_digest })
            }
            ReconciliationDisposition::ProviderRejected {
                reason,
                evidence_digest: _,
                observed_at,
                execution_started_at,
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::Rejected,
                    execution_started_at,
                    observed_at,
                )?;
                Err(BrokerError::ProviderRejected(reason))
            }
            ReconciliationDisposition::RetryScheduled {
                reason,
                evidence_digest,
                observed_at,
                retry_at,
                attempt_no: _,
                execution_started_at,
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::Uncertain,
                    execution_started_at,
                    observed_at,
                )?;
                Err(BrokerError::ReconciliationStillUncertain {
                    reason,
                    evidence_digest,
                    retry_at,
                })
            }
            ReconciliationDisposition::DeadLetter {
                reason,
                evidence_digest,
                dead_lettered_at,
                attempts,
                execution_started_at,
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::DeadLetter,
                    execution_started_at,
                    dead_lettered_at,
                )?;
                Err(BrokerError::ReconciliationDeadLetter {
                    reason,
                    evidence_digest,
                    attempts,
                })
            }
        }
    }

    fn claim_recovery_or_fresh(
        &self,
        effect: &Effect,
        infrastructure: &mut impl EffectInfrastructure,
        now: DateTime<Utc>,
    ) -> Result<LedgerClaim, BrokerError> {
        let lease_expires_at = self.lease_expiry(now)?;
        let recovery_claim =
            infrastructure.claim(effect, None, &self.worker_id, now, lease_expires_at)?;
        if recovery_claim != LedgerClaim::AuthorizationRequired {
            return Ok(recovery_claim);
        }
        if effect.status != EffectStatus::Approved {
            return Err(BrokerError::MissingDurableRecovery);
        }
        let claim_context = self.preflight_execution(effect, infrastructure, now)?;
        Ok(infrastructure.claim(
            effect,
            Some(&claim_context),
            &self.worker_id,
            now,
            lease_expires_at,
        )?)
    }

    fn resolve_ledger_claim(
        mission: &mut Mission,
        effect_id: &EffectId,
        claim: LedgerClaim,
    ) -> Result<ResolvedLedgerClaim, BrokerError> {
        match claim {
            LedgerClaim::Acquired {
                lease,
                receipt,
                execution_started_at,
            } => Ok(ResolvedLedgerClaim::Acquired {
                lease,
                receipt,
                execution_started_at,
            }),
            LedgerClaim::AlreadyVerified {
                receipt,
                verification,
                execution_started_at,
            }
            | LedgerClaim::DurableVerification {
                receipt,
                verification,
                execution_started_at,
            } => Self::resolve_verification_claim(
                mission,
                effect_id,
                receipt,
                verification,
                execution_started_at,
            ),
            LedgerClaim::ProviderRejected {
                reason,
                execution_started_at,
                recorded_at,
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::Rejected,
                    execution_started_at,
                    recorded_at,
                )?;
                Err(BrokerError::ProviderRejected(reason))
            }
            LedgerClaim::Uncertain {
                reason,
                execution_started_at,
                recorded_at,
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::Uncertain,
                    execution_started_at,
                    recorded_at,
                )?;
                Err(BrokerError::ProviderUncertain(reason))
            }
            LedgerClaim::ReconciledNotExecuted {
                evidence_digest,
                observed_at,
                execution_started_at,
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::ReconciledNotExecuted,
                    execution_started_at,
                    observed_at,
                )?;
                Err(BrokerError::ProviderNotExecuted { evidence_digest })
            }
            LedgerClaim::DeadLetter {
                reason,
                evidence_digest,
                dead_lettered_at,
                attempts,
                execution_started_at,
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::DeadLetter,
                    execution_started_at,
                    dead_lettered_at,
                )?;
                Err(BrokerError::ReconciliationDeadLetter {
                    reason,
                    evidence_digest,
                    attempts,
                })
            }
            LedgerClaim::RateLimited { retry_at } => Err(BrokerError::RateLimited { retry_at }),
            LedgerClaim::AuthorizationRequired => {
                Err(BrokerError::Ledger(LedgerError::Persistence(
                    "authorized claim requested another authorization pass".into(),
                )))
            }
            LedgerClaim::Busy => Err(BrokerError::ExecutionBusy),
        }
    }

    fn resolve_verification_claim(
        mission: &mut Mission,
        effect_id: &EffectId,
        receipt: Receipt,
        verification: Verification,
        execution_started_at: DateTime<Utc>,
    ) -> Result<ResolvedLedgerClaim, BrokerError> {
        mission.reconcile_durable_receipt(effect_id, receipt.clone(), execution_started_at)?;
        mission.record_verification(effect_id, verification.clone())?;
        match verification.status {
            VerificationStatus::Confirmed => Ok(ResolvedLedgerClaim::Complete(BrokerResult {
                disposition: ExecutionDisposition::AlreadyVerified,
                receipt,
                verification,
            })),
            VerificationStatus::Rejected => Err(BrokerError::VerificationRejected),
            VerificationStatus::Inconclusive => Err(BrokerError::VerificationInconclusive),
        }
    }

    fn preflight_execution(
        &self,
        effect: &Effect,
        permissions: &impl EffectPermissionResolver,
        now: DateTime<Utc>,
    ) -> Result<ExecutionClaimContext, BrokerError> {
        let claim_context = self
            .policy
            .execution_claim_context(effect, permissions.authorize(effect, now)?)?;
        if effect.status != EffectStatus::Approved {
            return Err(BrokerError::NotApproved(effect.status.clone()));
        }
        if effect.expires_at <= now {
            return Err(BrokerError::Expired);
        }
        if effect
            .scheduled_for
            .is_some_and(|scheduled| scheduled > now)
        {
            return Err(BrokerError::NotScheduled);
        }
        let approval = effect
            .approval
            .as_ref()
            .ok_or(BrokerError::NotApproved(effect.status.clone()))?;
        if approval.valid_until <= now {
            return Err(BrokerError::ApprovalExpired);
        }
        if approval.scope_digest != effect.approval_digest() {
            return Err(BrokerError::ApprovalScopeChanged);
        }
        if approval.permission_digest != claim_context.authorization_digest {
            return Err(BrokerError::PermissionEvidenceChanged);
        }
        Ok(claim_context)
    }

    fn lease_expiry(&self, now: DateTime<Utc>) -> Result<DateTime<Utc>, BrokerError> {
        let expires_at = now
            .checked_add_signed(self.lease_for)
            .ok_or(BrokerError::InvalidLease)?;
        if self.worker_id.trim().is_empty() || expires_at <= now {
            return Err(BrokerError::InvalidLease);
        }
        Ok(expires_at)
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum BrokerError {
    #[error(transparent)]
    Domain(#[from] MissionError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Permission(#[from] PermissionFailure),
    #[error("effect capability is outside project policy: {0}")]
    CapabilityDenied(String),
    #[error("effect policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error("effect was prepared for policy version {approved}, but the active policy is {active}")]
    PolicyVersionMismatch { approved: String, active: String },
    #[error("no unique rate-limit rule exists for provider {provider} and capability {capability}")]
    RateLimitRuleMissing {
        provider: String,
        capability: String,
    },
    #[error("effect class is outside project policy: {0:?}")]
    EffectClassDenied(EffectClass),
    #[error("effect cost limit {requested} exceeds policy limit {allowed}")]
    CostLimitExceeded { requested: i64, allowed: i64 },
    #[error("effect currency is outside project policy: {0}")]
    CurrencyDenied(CurrencyCode),
    #[error("required consent is missing or withdrawn")]
    ConsentMissing,
    #[error("effect approval has expired")]
    Expired,
    #[error("approval grant has expired before effect dispatch")]
    ApprovalExpired,
    #[error("effect is scheduled for a later time")]
    NotScheduled,
    #[error("effect scope changed after approval")]
    ApprovalScopeChanged,
    #[error(
        "connection, consent, conversation, or creator permission evidence changed after approval"
    )]
    PermissionEvidenceChanged,
    #[error("effect execution worker or lease duration is invalid")]
    InvalidLease,
    #[error("effect execution is already leased by another current worker")]
    ExecutionBusy,
    #[error("mission requires durable effect recovery, but no matching ledger state exists")]
    MissingDurableRecovery,
    #[error("effect execution is rate limited until {retry_at}")]
    RateLimited { retry_at: DateTime<Utc> },
    #[error("effect has not been approved; current status is {0:?}")]
    NotApproved(EffectStatus),
    #[error("provider rejected the effect: {0}")]
    ProviderRejected(String),
    #[error("provider state is uncertain; the effect will not be retried: {0}")]
    ProviderUncertain(String),
    #[error("effect does not require Provider reconciliation")]
    ReconciliationNotRequired,
    #[error("effect reconciliation is leased by another current worker")]
    ReconciliationBusy,
    #[error("effect reconciliation cannot run before {retry_at}")]
    ReconciliationNotReady { retry_at: DateTime<Utc> },
    #[error(
        "Provider reconciliation remains uncertain until {retry_at}: {reason} ({evidence_digest})"
    )]
    ReconciliationStillUncertain {
        reason: String,
        evidence_digest: String,
        retry_at: DateTime<Utc>,
    },
    #[error("Provider reconciliation proved no external effect occurred ({evidence_digest})")]
    ProviderNotExecuted { evidence_digest: String },
    #[error(
        "Provider reconciliation entered dead letter after {attempts} attempts: {reason} ({evidence_digest})"
    )]
    ReconciliationDeadLetter {
        reason: String,
        evidence_digest: String,
        attempts: u32,
    },
    #[error("independent verification rejected the provider receipt")]
    VerificationRejected,
    #[error("independent verification was inconclusive; reconciliation is required")]
    VerificationInconclusive,
    #[error("verified effect has no receipt")]
    MissingReceipt,
    #[error("verified effect has no verification")]
    MissingVerification,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn authorization_digest(permission_digest: &str, policy_digest: &str) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, "hartevo-effect-authorization/v1");
    hash_field(&mut digest, permission_digest);
    hash_field(&mut digest, policy_digest);
    format!("{:x}", digest.finalize())
}

fn hash_permission_fence(
    digest: &mut Sha256,
    fence: &PermissionFence,
) -> Result<(), PermissionFailure> {
    match fence {
        PermissionFence::Connection {
            connection_id,
            revision,
        } if *revision > 0 && !connection_id.as_str().trim().is_empty() => {
            hash_field(digest, "connection");
            hash_field(digest, connection_id.as_str());
            hash_field(digest, &revision.to_string());
        }
        PermissionFence::Consent {
            consent_record_id,
            revision,
        } if *revision > 0 && !consent_record_id.as_str().trim().is_empty() => {
            hash_field(digest, "consent");
            hash_field(digest, consent_record_id.as_str());
            hash_field(digest, &revision.to_string());
        }
        PermissionFence::Conversation {
            conversation_id,
            revision,
            control_generation,
        } if *revision > 0
            && *control_generation > 0
            && !conversation_id.as_str().trim().is_empty() =>
        {
            hash_field(digest, "conversation");
            hash_field(digest, conversation_id.as_str());
            hash_field(digest, &revision.to_string());
            hash_field(digest, &control_generation.to_string());
        }
        PermissionFence::CreatorContact {
            hiring_id,
            hiring_revision,
            partner_id,
            partner_revision,
        } if *hiring_revision > 0
            && *partner_revision > 0
            && !hiring_id.as_str().trim().is_empty()
            && !partner_id.as_str().trim().is_empty() =>
        {
            hash_field(digest, "creator_contact");
            hash_field(digest, hiring_id.as_str());
            hash_field(digest, &hiring_revision.to_string());
            hash_field(digest, partner_id.as_str());
            hash_field(digest, &partner_revision.to_string());
        }
        _ => return Err(PermissionFailure::InvalidEvidence),
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        EffectRisk, EffectSpec, MissionContract, MissionId, Outcome, OutcomeDecision, ProjectId,
        ReceiptId, VerificationId,
    };
    use proptest::prelude::*;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn proposed_mission() -> (Mission, EffectId) {
        proposed_mission_fixture(false)
    }

    fn proposed_mission_with_connection() -> (Mission, EffectId) {
        proposed_mission_fixture(true)
    }

    fn proposed_mission_fixture(with_connection: bool) -> (Mission, EffectId) {
        let mut contract = MissionContract::bootstrap(
            "Publish a reviewed preview",
            ["channel.preview".into()],
            now(),
        );
        contract.approval_policy.validity_seconds = 60;
        let mut mission = Mission::compile(
            hartevo_domain_kernel::TenantId::from("tenant-1"),
            MissionId::from("mission-1"),
            ProjectId::from("project-1"),
            "Publish preview",
            contract,
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("start research");
        let effect_id = mission
            .propose_effect(
                EffectSpec {
                    id: EffectId::from("effect-1"),
                    actor_id: ActorId::from("user-1"),
                    capability: "channel.preview".into(),
                    provider: "fixture-provider".into(),
                    connection_id: with_connection.then(|| ConnectionId::from("connection-1")),
                    account_id: with_connection.then(|| AccountId::from("account-1")),
                    required_scopes: if with_connection {
                        BTreeSet::from(["preview.publish".into()])
                    } else {
                        BTreeSet::new()
                    },
                    effect_class: EffectClass::ExternalWrite,
                    description: "Publish preview".into(),
                    target_resource: "preview/launch".into(),
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
                    amount: hartevo_domain_kernel::Money::zero(
                        CurrencyCode::parse("CNY").expect("CNY"),
                    ),
                    expires_at: now() + Duration::hours(1),
                },
                now(),
            )
            .expect("effect");
        (mission, effect_id)
    }

    fn broker() -> EffectBroker {
        EffectBroker::new(
            EffectPolicy {
                version: "policy-v1".into(),
                allowed_capabilities: BTreeSet::from(["channel.preview".into()]),
                allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
                max_amounts_minor: BTreeMap::from([(CurrencyCode::parse("CNY").expect("CNY"), 0)]),
                rate_limits: vec![EffectRateLimit {
                    rule_id: "preview-publish-per-minute".into(),
                    provider: "fixture-provider".into(),
                    capability: "channel.preview".into(),
                    max_executions: 10,
                    window_seconds: 60,
                }],
            },
            "effect-broker-test-worker",
        )
    }

    #[derive(Debug, Default)]
    struct TestLedger {
        receipt: Option<Receipt>,
        verification: Option<Verification>,
        uncertain: Option<String>,
        rejected: Option<String>,
        permission_evidence_digest: Option<String>,
        permission_revision: u64,
        rate_limited_until: Option<DateTime<Utc>>,
        execution_started_at: Option<DateTime<Utc>>,
        recovery_probe_calls: usize,
        authorized_claim_calls: usize,
        reconciliation_policy: Option<ReconciliationPolicy>,
        reconciliation_attempts: u32,
        reconciliation_retry_at: Option<DateTime<Utc>>,
        reconciliation_terminal: Option<LedgerClaim>,
    }

    impl TestLedger {
        fn record_still_uncertain(
            &mut self,
            lease: &ReconciliationLease,
            reason: &str,
            evidence_digest: &str,
            observed_at: DateTime<Utc>,
            now: DateTime<Utc>,
            execution_started_at: DateTime<Utc>,
        ) -> Result<ReconciliationDisposition, LedgerError> {
            if lease.attempt_no >= lease.max_attempts {
                let claim = LedgerClaim::DeadLetter {
                    reason: reason.into(),
                    evidence_digest: evidence_digest.into(),
                    dead_lettered_at: now,
                    attempts: lease.attempt_no,
                    execution_started_at,
                };
                self.reconciliation_terminal = Some(claim);
                return Ok(ReconciliationDisposition::DeadLetter {
                    reason: reason.into(),
                    evidence_digest: evidence_digest.into(),
                    dead_lettered_at: now,
                    attempts: lease.attempt_no,
                    execution_started_at,
                });
            }
            let retry_delay = self
                .reconciliation_policy
                .as_ref()
                .ok_or(LedgerError::LeaseLost)?
                .retry_delay_seconds;
            let retry_at = now
                .checked_add_signed(chrono::Duration::seconds(
                    i64::try_from(retry_delay)
                        .map_err(|_| LedgerError::Persistence("retry delay overflow".into()))?,
                ))
                .ok_or_else(|| LedgerError::Persistence("retry time overflow".into()))?;
            self.reconciliation_retry_at = Some(retry_at);
            Ok(ReconciliationDisposition::RetryScheduled {
                reason: reason.into(),
                evidence_digest: evidence_digest.into(),
                observed_at,
                retry_at,
                attempt_no: lease.attempt_no,
                execution_started_at,
            })
        }
    }

    impl DurableEffectLedger for TestLedger {
        fn claim(
            &mut self,
            effect: &Effect,
            context: Option<&ExecutionClaimContext>,
            owner: &str,
            now: DateTime<Utc>,
            lease_expires_at: DateTime<Utc>,
        ) -> Result<LedgerClaim, LedgerError> {
            if context.is_some() {
                self.authorized_claim_calls += 1;
            } else {
                self.recovery_probe_calls += 1;
            }
            if let Some(claim) = &self.reconciliation_terminal {
                return Ok(claim.clone());
            }
            if let (Some(receipt), Some(verification)) = (&self.receipt, &self.verification) {
                return Ok(match verification.status {
                    VerificationStatus::Confirmed => LedgerClaim::AlreadyVerified {
                        receipt: receipt.clone(),
                        verification: verification.clone(),
                        execution_started_at: self.execution_started_at.unwrap_or(now),
                    },
                    VerificationStatus::Rejected | VerificationStatus::Inconclusive => {
                        LedgerClaim::DurableVerification {
                            receipt: receipt.clone(),
                            verification: verification.clone(),
                            execution_started_at: self.execution_started_at.unwrap_or(now),
                        }
                    }
                });
            }
            if let Some(reason) = &self.rejected {
                return Ok(LedgerClaim::ProviderRejected {
                    reason: reason.clone(),
                    execution_started_at: self.execution_started_at.unwrap_or(now),
                    recorded_at: now,
                });
            }
            if let Some(reason) = &self.uncertain {
                return Ok(LedgerClaim::Uncertain {
                    reason: reason.clone(),
                    execution_started_at: self.execution_started_at.unwrap_or(now),
                    recorded_at: now,
                });
            }
            if self.receipt.is_none() && context.is_none() {
                return Ok(LedgerClaim::AuthorizationRequired);
            }
            if self.receipt.is_none() {
                context
                    .ok_or(LedgerError::DispatchNotAuthorized)?
                    .validate_dispatch_at(effect, now)?;
                if let Some(retry_at) = self.rate_limited_until {
                    return Ok(LedgerClaim::RateLimited { retry_at });
                }
                self.execution_started_at = Some(now);
            }
            Ok(LedgerClaim::Acquired {
                lease: ExecutionLease {
                    attempt_id: ExecutionAttemptId::from("attempt-1"),
                    owner: owner.into(),
                    generation: 1,
                    expires_at: lease_expires_at,
                },
                receipt: self.receipt.clone(),
                execution_started_at: self.execution_started_at.unwrap_or(now),
            })
        }

        fn record_receipt(
            &mut self,
            _effect: &Effect,
            _lease: &ExecutionLease,
            receipt: &Receipt,
            _now: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.receipt = Some(receipt.clone());
            Ok(())
        }

        fn record_verification(
            &mut self,
            _effect: &Effect,
            _lease: &ExecutionLease,
            verification: &Verification,
            _now: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.verification = Some(verification.clone());
            Ok(())
        }

        fn record_failed(
            &mut self,
            _effect: &Effect,
            _lease: &ExecutionLease,
            reason: &str,
            _now: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.rejected = Some(reason.into());
            Ok(())
        }

        fn record_uncertain(
            &mut self,
            _effect: &Effect,
            _lease: &ExecutionLease,
            reason: &str,
            _now: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.uncertain = Some(reason.into());
            Ok(())
        }

        fn claim_reconciliation(
            &mut self,
            _effect: &Effect,
            policy: &ReconciliationPolicy,
            owner: &str,
            now: DateTime<Utc>,
            lease_expires_at: DateTime<Utc>,
        ) -> Result<ReconciliationClaim, LedgerError> {
            policy.validate()?;
            if let Some(claim) = &self.reconciliation_terminal {
                return Ok(ReconciliationClaim::Resolved(claim.clone()));
            }
            if self.uncertain.is_none() {
                return Ok(ReconciliationClaim::NotRequired);
            }
            if self
                .reconciliation_retry_at
                .is_some_and(|retry_at| retry_at > now)
            {
                return Ok(ReconciliationClaim::NotReady {
                    retry_at: self.reconciliation_retry_at.expect("retry at"),
                });
            }
            if self
                .reconciliation_policy
                .as_ref()
                .is_some_and(|stored| stored != policy)
            {
                return Err(LedgerError::ScopeConflict);
            }
            self.reconciliation_policy = Some(policy.clone());
            self.reconciliation_attempts = self
                .reconciliation_attempts
                .checked_add(1)
                .ok_or_else(|| LedgerError::Persistence("attempt overflow".into()))?;
            Ok(ReconciliationClaim::Acquired {
                lease: ReconciliationLease {
                    attempt_id: ExecutionAttemptId::from_stable(format!(
                        "reconciliation-attempt-{}",
                        self.reconciliation_attempts
                    )),
                    owner: owner.into(),
                    generation: u64::from(self.reconciliation_attempts),
                    attempt_no: self.reconciliation_attempts,
                    max_attempts: policy.max_attempts,
                    expires_at: lease_expires_at,
                },
                execution_started_at: self.execution_started_at.unwrap_or(now),
            })
        }

        fn record_reconciliation(
            &mut self,
            effect: &Effect,
            lease: &ReconciliationLease,
            observation: &ReconciliationObservation,
            now: DateTime<Utc>,
        ) -> Result<ReconciliationDisposition, LedgerError> {
            let execution_started_at = self.execution_started_at.unwrap_or(now);
            observation.validate_for(effect, execution_started_at)?;
            if observation.observed_at() > now {
                return Err(LedgerError::ScopeConflict);
            }
            if lease.attempt_no != self.reconciliation_attempts
                || lease.max_attempts
                    != self
                        .reconciliation_policy
                        .as_ref()
                        .ok_or(LedgerError::LeaseLost)?
                        .max_attempts
            {
                return Err(LedgerError::LeaseLost);
            }
            let disposition = match observation {
                ReconciliationObservation::ReceiptFound { receipt, .. } => {
                    self.receipt = Some(receipt.clone());
                    self.uncertain = None;
                    ReconciliationDisposition::ReceiptReadyForVerification {
                        lease: ExecutionLease {
                            attempt_id: ExecutionAttemptId::from_stable(format!(
                                "verification-after-reconciliation-{}",
                                lease.attempt_no
                            )),
                            owner: lease.owner.clone(),
                            generation: lease.generation + 1,
                            expires_at: lease.expires_at,
                        },
                        receipt: receipt.clone(),
                        execution_started_at,
                    }
                }
                ReconciliationObservation::NotExecuted {
                    evidence_digest,
                    observed_at,
                } => {
                    let claim = LedgerClaim::ReconciledNotExecuted {
                        evidence_digest: evidence_digest.clone(),
                        observed_at: *observed_at,
                        execution_started_at,
                    };
                    self.reconciliation_terminal = Some(claim);
                    ReconciliationDisposition::ReconciledNotExecuted {
                        evidence_digest: evidence_digest.clone(),
                        observed_at: *observed_at,
                        execution_started_at,
                    }
                }
                ReconciliationObservation::ProviderRejected {
                    reason,
                    evidence_digest,
                    observed_at,
                } => {
                    self.rejected = Some(reason.clone());
                    self.uncertain = None;
                    ReconciliationDisposition::ProviderRejected {
                        reason: reason.clone(),
                        evidence_digest: evidence_digest.clone(),
                        observed_at: *observed_at,
                        execution_started_at,
                    }
                }
                ReconciliationObservation::StillUncertain {
                    reason,
                    evidence_digest,
                    observed_at,
                } => {
                    return self.record_still_uncertain(
                        lease,
                        reason,
                        evidence_digest,
                        *observed_at,
                        now,
                        execution_started_at,
                    );
                }
            };
            Ok(disposition)
        }
    }

    impl EffectPermissionResolver for TestLedger {
        fn authorize(
            &self,
            effect: &Effect,
            _now: DateTime<Utc>,
        ) -> Result<PermissionEvidence, PermissionFailure> {
            if effect.consent_record_id.is_some() {
                return Err(PermissionFailure::Unavailable(
                    "fixture resolver has no external authorization records".into(),
                ));
            }
            let fences =
                effect
                    .connection_id
                    .as_ref()
                    .map_or_else(BTreeSet::new, |connection_id| {
                        BTreeSet::from([PermissionFence::Connection {
                            connection_id: connection_id.clone(),
                            revision: self.permission_revision,
                        }])
                    });
            Ok(PermissionEvidence {
                connection_evidence_digest: self.permission_evidence_digest.clone(),
                consent_evidence_digest: None,
                conversation_evidence_digest: None,
                creator_contact_evidence_digest: None,
                fences,
            })
        }
    }

    #[derive(Debug, Default)]
    struct CountingExecutor {
        calls: usize,
        uncertain: bool,
        rejected: bool,
    }

    impl EffectExecutor for CountingExecutor {
        fn execute(&mut self, effect: &Effect) -> Result<Receipt, ProviderFailure> {
            self.calls += 1;
            if self.uncertain {
                return Err(ProviderFailure::Uncertain("timeout after submit".into()));
            }
            if self.rejected {
                return Err(ProviderFailure::Rejected(
                    "provider validation rejected".into(),
                ));
            }
            Ok(Receipt {
                id: ReceiptId::from("receipt-1"),
                provider: "fixture-provider".into(),
                external_id: "publication-1".into(),
                accepted_at: now(),
                request_digest: effect.approval_digest(),
                response_digest: "b".repeat(64),
            })
        }
    }

    #[derive(Debug)]
    struct ConfirmingVerifier;

    impl EffectVerifier for ConfirmingVerifier {
        fn verify(&mut self, _effect: &Effect, receipt: &Receipt) -> Verification {
            Verification {
                id: VerificationId::from("verification-1"),
                status: VerificationStatus::Confirmed,
                verifier: "fixture-readback".into(),
                independent: true,
                observed_at: now(),
                evidence_digest: "c".repeat(64),
                receipt_id: receipt.id.clone(),
            }
        }
    }

    #[derive(Debug)]
    struct CountingVerifier {
        calls: usize,
        status: VerificationStatus,
    }

    impl EffectVerifier for CountingVerifier {
        fn verify(&mut self, _effect: &Effect, receipt: &Receipt) -> Verification {
            self.calls += 1;
            Verification {
                id: VerificationId::from("counting-verification"),
                status: self.status.clone(),
                verifier: "counting-readback".into(),
                independent: true,
                observed_at: now() + Duration::seconds(2),
                evidence_digest: "e".repeat(64),
                receipt_id: receipt.id.clone(),
            }
        }
    }

    #[derive(Debug)]
    struct CountingReconciler {
        calls: usize,
        observation: ReconciliationObservation,
    }

    impl EffectReconciler for CountingReconciler {
        fn reconcile(&mut self, _effect: &Effect) -> ReconciliationObservation {
            self.calls += 1;
            self.observation.clone()
        }
    }

    #[test]
    fn external_effect_cannot_execute_before_approval() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now(),
        );

        assert!(matches!(result, Err(BrokerError::NotApproved(_))));
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn changed_policy_version_invalidates_approval_before_claim_or_execution() {
        let (mut mission, effect_id) = proposed_mission();
        let mut ledger = TestLedger::default();
        let mut current = broker();
        current
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval under policy v1");
        current.policy.version = "policy-v2".into();
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = current.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now(),
        );

        assert_eq!(
            result,
            Err(BrokerError::PolicyVersionMismatch {
                approved: "policy-v1".into(),
                active: "policy-v2".into(),
            })
        );
        assert_eq!(executor.calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Approved
        );
    }

    #[test]
    fn same_version_policy_configuration_change_invalidates_approval() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval under immutable policy digest");
        broker.policy.rate_limits[0].max_executions = 11;
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now(),
        );

        assert_eq!(result, Err(BrokerError::PermissionEvidenceChanged));
        assert_eq!(executor.calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Approved
        );
    }

    #[test]
    fn changed_permission_evidence_invalidates_approval_before_claim_or_execution() {
        let (mut mission, effect_id) = proposed_mission_with_connection();
        let mut broker = broker();
        let mut ledger = TestLedger {
            permission_evidence_digest: Some("d".repeat(64)),
            permission_revision: 1,
            ..TestLedger::default()
        };
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval with permission evidence v1");
        ledger.permission_evidence_digest = Some("e".repeat(64));
        ledger.permission_revision = 2;
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now(),
        );

        assert_eq!(result, Err(BrokerError::PermissionEvidenceChanged));
        assert_eq!(executor.calls, 0);
        assert_eq!(ledger.receipt, None);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Approved
        );
    }

    #[test]
    fn permission_evidence_shape_rejects_missing_duplicate_and_extraneous_fences() {
        let (mission, effect_id) = proposed_mission_with_connection();
        let effect = mission.effect(&effect_id).expect("connected effect");
        let valid = PermissionEvidence {
            connection_evidence_digest: Some("d".repeat(64)),
            consent_evidence_digest: None,
            conversation_evidence_digest: None,
            creator_contact_evidence_digest: None,
            fences: BTreeSet::from([PermissionFence::Connection {
                connection_id: effect.connection_id.clone().expect("connection"),
                revision: 1,
            }]),
        };
        valid
            .validate_for_effect(effect)
            .expect("exact permission evidence");

        let mut missing_fence = valid.clone();
        missing_fence.fences.clear();
        assert_eq!(
            missing_fence.validate_for_effect(effect),
            Err(PermissionFailure::InvalidEvidence)
        );

        let mut duplicate_kind = valid.clone();
        duplicate_kind.fences.insert(PermissionFence::Connection {
            connection_id: effect.connection_id.clone().expect("connection"),
            revision: 2,
        });
        assert_eq!(
            duplicate_kind.validate_for_effect(effect),
            Err(PermissionFailure::InvalidEvidence)
        );

        let mut wrong_scope = valid.clone();
        wrong_scope.fences = BTreeSet::from([PermissionFence::Connection {
            connection_id: ConnectionId::from("other-connection"),
            revision: 1,
        }]);
        assert_eq!(
            wrong_scope.validate_for_effect(effect),
            Err(PermissionFailure::InvalidEvidence)
        );

        let (unconnected_mission, unconnected_effect_id) = proposed_mission();
        let unconnected = unconnected_mission
            .effect(&unconnected_effect_id)
            .expect("unconnected effect");
        assert_eq!(
            valid.validate_for_effect(unconnected),
            Err(PermissionFailure::InvalidEvidence)
        );
    }

    #[test]
    fn expired_approval_blocks_claim_while_the_effect_itself_is_still_live() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("short-lived approval");
        let effect = mission.effect(&effect_id).expect("effect");
        assert!(effect.expires_at > now() + Duration::seconds(61));
        assert_eq!(
            effect.approval.as_ref().expect("approval").valid_until,
            now() + Duration::seconds(60)
        );
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now() + Duration::seconds(61),
        );

        assert_eq!(result, Err(BrokerError::ApprovalExpired));
        assert_eq!(ledger.recovery_probe_calls, 1);
        assert_eq!(ledger.authorized_claim_calls, 0);
        assert_eq!(executor.calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Approved
        );
    }

    #[test]
    fn durable_receipt_recovers_verification_without_reauthorization_or_provider_replay() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let effect = mission.effect(&effect_id).expect("effect").clone();
        ledger.execution_started_at = Some(now());
        ledger.receipt = Some(Receipt {
            id: ReceiptId::from("recovered-receipt"),
            provider: effect.provider.clone(),
            external_id: "recovered-publication".into(),
            accepted_at: now(),
            request_digest: effect.approval_digest(),
            response_digest: "f".repeat(64),
        });
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker
            .execute_and_verify(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now() + Duration::seconds(61),
            )
            .expect("durable receipt resumes verification after approval expiry");

        assert_eq!(
            result.disposition,
            ExecutionDisposition::ReusedIdempotentReceipt
        );
        assert_eq!(executor.calls, 0);
        assert_eq!(ledger.recovery_probe_calls, 1);
        assert_eq!(ledger.authorized_claim_calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Verified
        );
    }

    #[test]
    fn durable_provider_rejection_projects_without_reauthorization_or_provider_replay() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger {
            execution_started_at: Some(now()),
            rejected: Some("durable provider validation rejection".into()),
            ..TestLedger::default()
        };
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now() + Duration::seconds(61),
        );

        assert_eq!(
            result,
            Err(BrokerError::ProviderRejected(
                "durable provider validation rejection".into()
            ))
        );
        assert_eq!(executor.calls, 0);
        assert_eq!(ledger.recovery_probe_calls, 1);
        assert_eq!(ledger.authorized_claim_calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Failed
        );
    }

    #[test]
    fn durable_rejected_verification_projects_exact_receipt_without_rerunning_verifier() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = Receipt {
            id: ReceiptId::from("durable-rejected-receipt"),
            provider: effect.provider.clone(),
            external_id: "durable-rejected-external".into(),
            accepted_at: now() + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "f".repeat(64),
        };
        ledger.execution_started_at = Some(now());
        ledger.receipt = Some(receipt.clone());
        ledger.verification = Some(Verification {
            id: VerificationId::from("durable-rejected-verification"),
            status: VerificationStatus::Rejected,
            verifier: "durable-readback".into(),
            independent: true,
            observed_at: now() + Duration::seconds(2),
            evidence_digest: "e".repeat(64),
            receipt_id: receipt.id.clone(),
        });
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now() + Duration::seconds(61),
        );

        assert_eq!(result, Err(BrokerError::VerificationRejected));
        assert_eq!(executor.calls, 0);
        assert_eq!(verifier.calls, 0);
        assert_eq!(ledger.authorized_claim_calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Failed
        );
        assert_eq!(
            mission.effect(&effect_id).expect("effect").receipt,
            Some(receipt)
        );
    }

    #[test]
    fn durable_inconclusive_verification_remains_reconcilable_without_provider_replay() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = Receipt {
            id: ReceiptId::from("durable-inconclusive-receipt"),
            provider: effect.provider.clone(),
            external_id: "durable-inconclusive-external".into(),
            accepted_at: now() + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "f".repeat(64),
        };
        ledger.execution_started_at = Some(now());
        ledger.receipt = Some(receipt.clone());
        ledger.verification = Some(Verification {
            id: VerificationId::from("durable-inconclusive-verification"),
            status: VerificationStatus::Inconclusive,
            verifier: "durable-readback".into(),
            independent: true,
            observed_at: now() + Duration::seconds(2),
            evidence_digest: "e".repeat(64),
            receipt_id: receipt.id,
        });
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now() + Duration::seconds(61),
        );

        assert_eq!(result, Err(BrokerError::VerificationInconclusive));
        assert_eq!(executor.calls, 0);
        assert_eq!(verifier.calls, 0);
        assert_eq!(ledger.authorized_claim_calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::VerificationRequired
        );
    }

    #[test]
    fn durable_rate_limit_denial_never_starts_the_mission_effect_or_provider() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let retry_at = now() + Duration::minutes(1);
        ledger.rate_limited_until = Some(retry_at);
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;

        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now(),
        );

        assert_eq!(result, Err(BrokerError::RateLimited { retry_at }));
        assert_eq!(executor.calls, 0);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Approved
        );
    }

    #[test]
    fn uncertain_writes_are_frozen_instead_of_retried() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let mut executor = CountingExecutor {
            uncertain: true,
            ..CountingExecutor::default()
        };
        let mut verifier = ConfirmingVerifier;

        let first = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now(),
        );
        let second = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now(),
        );

        assert!(matches!(first, Err(BrokerError::ProviderUncertain(_))));
        assert!(matches!(second, Err(BrokerError::ProviderUncertain(_))));
        assert_eq!(executor.calls, 1);
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::VerificationRequired
        );
    }

    #[test]
    fn uncertain_effect_reconciles_receipt_without_a_second_provider_execution() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let mut executor = CountingExecutor {
            uncertain: true,
            ..CountingExecutor::default()
        };
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };
        assert!(matches!(
            broker.execute_and_verify(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now(),
            ),
            Err(BrokerError::ProviderUncertain(_))
        ));
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = Receipt {
            id: ReceiptId::from("reconciled-receipt"),
            provider: effect.provider.clone(),
            external_id: "reconciled-external-id".into(),
            accepted_at: now() + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "d".repeat(64),
        };
        let mut reconciler = CountingReconciler {
            calls: 0,
            observation: ReconciliationObservation::ReceiptFound {
                receipt: receipt.clone(),
                evidence_digest: "f".repeat(64),
                observed_at: now() + Duration::seconds(2),
            },
        };
        let result = broker
            .reconcile_uncertain(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut reconciler,
                &mut verifier,
                now() + Duration::seconds(2),
            )
            .expect("reconcile Receipt and verify");
        assert_eq!(result.receipt, receipt);
        assert_eq!(
            result.disposition,
            ExecutionDisposition::ReusedIdempotentReceipt
        );
        assert_eq!(
            (executor.calls, reconciler.calls, verifier.calls),
            (1, 1, 1)
        );
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Verified
        );
    }

    #[test]
    fn reconciled_receipt_must_fit_original_approval_and_effect_window() {
        let (mut mission, effect_id) = proposed_mission();
        let broker = broker();
        let ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let effect = mission.effect(&effect_id).expect("effect");
        let observation = ReconciliationObservation::ReceiptFound {
            receipt: Receipt {
                id: ReceiptId::from("late-reconciled-receipt"),
                provider: effect.provider.clone(),
                external_id: "late-external-id".into(),
                accepted_at: effect.expires_at,
                request_digest: effect.approval_digest(),
                response_digest: "d".repeat(64),
            },
            evidence_digest: "f".repeat(64),
            observed_at: effect.expires_at,
        };
        assert_eq!(
            observation.validate_for(effect, now()),
            Err(LedgerError::ScopeConflict)
        );
        let timely_observation = ReconciliationObservation::ReceiptFound {
            receipt: Receipt {
                id: ReceiptId::from("timely-reconciled-receipt"),
                provider: effect.provider.clone(),
                external_id: "timely-external-id".into(),
                accepted_at: now() + Duration::seconds(1),
                request_digest: effect.approval_digest(),
                response_digest: "e".repeat(64),
            },
            evidence_digest: "a".repeat(64),
            observed_at: now() + Duration::seconds(2),
        };
        assert_eq!(
            timely_observation.validate_for(effect, now() - Duration::milliseconds(1)),
            Err(LedgerError::ScopeConflict)
        );
    }

    #[test]
    fn not_executed_reconciliation_is_terminal_and_never_replays_provider() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let mut executor = CountingExecutor {
            uncertain: true,
            ..CountingExecutor::default()
        };
        let mut verifier = ConfirmingVerifier;
        broker
            .execute_and_verify(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now(),
            )
            .expect_err("first write is uncertain");
        let mut stale_projection = mission.clone();
        let evidence_digest = "9".repeat(64);
        let mut reconciler = CountingReconciler {
            calls: 0,
            observation: ReconciliationObservation::NotExecuted {
                evidence_digest: evidence_digest.clone(),
                observed_at: now() + Duration::seconds(1),
            },
        };
        assert_eq!(
            broker.reconcile_uncertain(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut reconciler,
                &mut verifier,
                now() + Duration::seconds(1),
            ),
            Err(BrokerError::ProviderNotExecuted {
                evidence_digest: evidence_digest.clone()
            })
        );
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::Reconciled
        );
        assert_eq!(
            broker.execute_and_verify(
                &mut stale_projection,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now() + Duration::seconds(2),
            ),
            Err(BrokerError::ProviderNotExecuted { evidence_digest })
        );
        assert_eq!((executor.calls, reconciler.calls), (1, 1));
    }

    #[test]
    fn bounded_reconciliation_enters_dead_letter_without_provider_replay() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker()
            .with_reconciliation_policy(ReconciliationPolicy {
                version: "reconcile-test-v1".into(),
                max_attempts: 2,
                retry_delay_seconds: 10,
            })
            .expect("policy");
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let mut executor = CountingExecutor {
            uncertain: true,
            ..CountingExecutor::default()
        };
        let mut verifier = ConfirmingVerifier;
        broker
            .execute_and_verify(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now(),
            )
            .expect_err("first write is uncertain");
        let mut reconciler = CountingReconciler {
            calls: 0,
            observation: ReconciliationObservation::StillUncertain {
                reason: "Provider lookup is still ambiguous".into(),
                evidence_digest: "7".repeat(64),
                observed_at: now() + Duration::seconds(1),
            },
        };
        let retry_at = now() + Duration::seconds(11);
        assert!(matches!(
            broker.reconcile_uncertain(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut reconciler,
                &mut verifier,
                now() + Duration::seconds(1),
            ),
            Err(BrokerError::ReconciliationStillUncertain {
                retry_at: actual,
                ..
            }) if actual == retry_at
        ));
        assert_eq!(
            broker.reconcile_uncertain(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut reconciler,
                &mut verifier,
                now() + Duration::seconds(2),
            ),
            Err(BrokerError::ReconciliationNotReady { retry_at })
        );
        let mut stale_projection = mission.clone();
        assert!(matches!(
            broker.reconcile_uncertain(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut reconciler,
                &mut verifier,
                retry_at,
            ),
            Err(BrokerError::ReconciliationDeadLetter { attempts: 2, .. })
        ));
        assert_eq!(
            mission.effect(&effect_id).expect("effect").status,
            EffectStatus::DeadLetter
        );
        assert!(matches!(
            broker.execute_and_verify(
                &mut stale_projection,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                retry_at + Duration::seconds(1),
            ),
            Err(BrokerError::ReconciliationDeadLetter { attempts: 2, .. })
        ));
        assert_eq!((executor.calls, reconciler.calls), (1, 2));
    }

    #[test]
    fn receipt_and_verification_are_required_before_outcome() {
        let (mut mission, effect_id) = proposed_mission();
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("user-1"),
                &ledger,
                now(),
            )
            .expect("approval");
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;
        let result = broker
            .execute_and_verify(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now(),
            )
            .expect("execution");

        assert_eq!(result.disposition, ExecutionDisposition::Executed);
        assert_eq!(
            mission.stage,
            hartevo_domain_kernel::MissionStage::Verifying
        );
        mission
            .record_outcome(Outcome {
                summary: "Preview published and visible".into(),
                decision: OutcomeDecision::Test,
                metrics: BTreeMap::new(),
                observed_at: now(),
            })
            .expect("outcome");
        assert_eq!(
            mission.stage,
            hartevo_domain_kernel::MissionStage::Completed
        );
    }

    fn persisted_claim_state() -> impl Strategy<Value = PersistedClaimState> {
        prop_oneof![
            Just(PersistedClaimState::Executing),
            Just(PersistedClaimState::ReceiptRecorded),
            Just(PersistedClaimState::Verified),
            Just(PersistedClaimState::Uncertain),
            Just(PersistedClaimState::VerificationRequired),
            Just(PersistedClaimState::Failed),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn no_persisted_effect_state_can_grant_a_second_provider_execution(
            state in persisted_claim_state(),
            lease_live in any::<bool>(),
        ) {
            let directive = decide_durable_claim(Some(state), lease_live);
            prop_assert_ne!(directive, DurableClaimDirective::BeginProviderExecution);
        }

        #[test]
        fn repeated_claims_issue_at_most_one_provider_execution_permit(
            lease_observations in prop::collection::vec(any::<bool>(), 1..100),
        ) {
            let mut state = None;
            let mut execution_permits = 0_u8;
            for lease_live in lease_observations {
                match decide_durable_claim(state, lease_live) {
                    DurableClaimDirective::BeginProviderExecution => {
                        execution_permits += 1;
                        state = Some(PersistedClaimState::Executing);
                    }
                    DurableClaimDirective::FreezeExpiredExecution => {
                        state = Some(PersistedClaimState::Uncertain);
                    }
                    DurableClaimDirective::ResumeVerificationFromReceipt
                    | DurableClaimDirective::ReturnVerified
                    | DurableClaimDirective::ReturnProviderFailed
                    | DurableClaimDirective::ReturnUncertain
                    | DurableClaimDirective::ReturnVerification
                    | DurableClaimDirective::ReturnBusy => {}
                }
            }
            prop_assert!(execution_permits <= 1);
        }

        #[test]
        fn rate_limit_decision_never_reserves_beyond_the_configured_capacity(
            max_executions in 1_u64..1_000,
            attempts in 1_u64..2_000,
        ) {
            let mut consumed = 0_u64;
            let mut reservations = 0_u64;
            for _ in 0..attempts {
                match decide_durable_rate_limit(consumed, max_executions) {
                    DurableRateLimitDirective::Reserve { next_consumed } => {
                        prop_assert_eq!(next_consumed, consumed + 1);
                        consumed = next_consumed;
                        reservations += 1;
                    }
                    DurableRateLimitDirective::Deny => {
                        prop_assert_eq!(consumed, max_executions);
                    }
                }
            }
            prop_assert_eq!(reservations, attempts.min(max_executions));
            prop_assert!(consumed <= max_executions);
        }
    }

    #[test]
    fn loom_serialized_claims_have_exactly_one_execution_winner() {
        loom::model(|| {
            use loom::sync::atomic::{AtomicUsize, Ordering};
            use loom::sync::{Arc, Mutex};
            use loom::thread;

            let state = Arc::new(Mutex::new(None));
            let winners = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();
            for _ in 0..2 {
                let state = Arc::clone(&state);
                let winners = Arc::clone(&winners);
                handles.push(thread::spawn(move || {
                    let mut state = state.lock().expect("model mutex");
                    if decide_durable_claim(*state, true)
                        == DurableClaimDirective::BeginProviderExecution
                    {
                        *state = Some(PersistedClaimState::Executing);
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("model thread");
            }
            assert_eq!(winners.load(Ordering::SeqCst), 1);
            assert_eq!(
                *state.lock().expect("model mutex"),
                Some(PersistedClaimState::Executing)
            );
        });
    }

    #[test]
    fn loom_expired_execution_freezes_before_any_competing_retry() {
        loom::model(|| {
            use loom::sync::atomic::{AtomicUsize, Ordering};
            use loom::sync::{Arc, Mutex};
            use loom::thread;

            let state = Arc::new(Mutex::new(Some(PersistedClaimState::Executing)));
            let winners = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();
            for _ in 0..2 {
                let state = Arc::clone(&state);
                let winners = Arc::clone(&winners);
                handles.push(thread::spawn(move || {
                    let mut state = state.lock().expect("model mutex");
                    match decide_durable_claim(*state, false) {
                        DurableClaimDirective::BeginProviderExecution => {
                            winners.fetch_add(1, Ordering::SeqCst);
                        }
                        DurableClaimDirective::FreezeExpiredExecution => {
                            *state = Some(PersistedClaimState::Uncertain);
                        }
                        DurableClaimDirective::ResumeVerificationFromReceipt
                        | DurableClaimDirective::ReturnVerified
                        | DurableClaimDirective::ReturnProviderFailed
                        | DurableClaimDirective::ReturnUncertain
                        | DurableClaimDirective::ReturnVerification
                        | DurableClaimDirective::ReturnBusy => {}
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("model thread");
            }
            assert_eq!(winners.load(Ordering::SeqCst), 0);
            assert_eq!(
                *state.lock().expect("model mutex"),
                Some(PersistedClaimState::Uncertain)
            );
        });
    }
}

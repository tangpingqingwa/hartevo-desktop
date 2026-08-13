//! The only path from a proposed Hartevo business effect to a provider.

pub mod approval_authority;
pub mod github_pages;
pub mod provider_auth;
pub mod provider_contract;

pub use approval_authority::{
    ApprovalAuthority, ApprovalAuthorityError, ApprovalAuthorityKind, ApprovalRecordAuthorization,
    ApprovalRequest, HUMAN_OPERATION_AUTHORITY_CONTRACT_VERSION,
    HUMAN_OPERATION_AUTHORITY_SCHEMA_VERSION, HumanActorAuthorization, HumanActorSession,
    HumanApprovalIssuanceEvidence, HumanApprovalRequestEvidence, HumanAssuranceLevel,
    HumanAuthorityIssuerIdentity, HumanAuthoritySubject, HumanEvidenceWindow,
    HumanOperationDecision, HumanOperationKind, HumanSessionIdentity, HumanStepUpIntent,
    HumanStepUpIntentIdentity, HumanStepUpMethod, PROVIDER_APPROVAL_AUTHORITY_CONTRACT_JSON,
    PROVIDER_APPROVAL_AUTHORITY_CONTRACT_VERSION, PROVIDER_APPROVAL_AUTHORITY_SCHEMA_VERSION,
    ProviderApprovalAuthorityPolicy, ProviderApprovalEvidence, ProviderEffectApprovalContext,
    RequestBoundStepUpAssertion,
};

pub use provider_auth::{
    AuthSession, ConnectedAuthority, ConnectedAuthorization, CredentialLease,
    PROVIDER_AUTH_PROBE_CONTRACT_JSON, PROVIDER_AUTH_PROBE_CONTRACT_VERSION,
    PROVIDER_AUTH_PROBE_SCHEMA_VERSION, ProbeObservation, ProbeResult, ProbeStatus,
    ProviderAuthProbeError, ProviderAuthProbePolicy, ProviderAuthScope, SecretReference,
};

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

/// A trusted time source used only by [`EffectAuthorityClock`]. UI and Domain
/// callers never supply a completion `DateTime` or its wall-clock anchor.
trait EffectAuthorityTimeSource {
    fn sample(&mut self) -> Result<DateTime<Utc>, BrokerError>;
}

struct SystemEffectAuthorityTimeSource {
    authority_utc_anchor: DateTime<Utc>,
    monotonic_anchor: std::time::Instant,
}

impl EffectAuthorityTimeSource for SystemEffectAuthorityTimeSource {
    fn sample(&mut self) -> Result<DateTime<Utc>, BrokerError> {
        let elapsed_nanos = i64::try_from(self.monotonic_anchor.elapsed().as_nanos())
            .map_err(|_| BrokerError::InvalidAuthorityClock)?;
        self.authority_utc_anchor
            .checked_add_signed(chrono::Duration::nanoseconds(elapsed_nanos))
            .ok_or(BrokerError::InvalidAuthorityClock)
    }
}

/// Samples completion authority strictly after external Provider boundaries.
///
/// The source is intentionally hidden from `Debug`; it may contain a
/// deterministic test sequence or platform clock state. Production-compatible
/// entry points use [`Self::system`], which captures its own UTC/monotonic
/// anchors inside the Broker. The caller's entry time is only a not-before
/// fence for claim and business semantics.
struct EffectAuthorityClock {
    entry_at: DateTime<Utc>,
    source: Box<dyn EffectAuthorityTimeSource>,
    sample_count: u64,
}

impl std::fmt::Debug for EffectAuthorityClock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectAuthorityClock")
            .field("sample_count", &self.sample_count)
            .finish_non_exhaustive()
    }
}

impl EffectAuthorityClock {
    fn system(entry_at: DateTime<Utc>) -> Result<Self, BrokerError> {
        let monotonic_anchor = std::time::Instant::now();
        let authority_system_anchor = std::time::SystemTime::now();
        let authority_since_epoch = authority_system_anchor
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| BrokerError::InvalidAuthorityClock)?;
        let authority_seconds = i64::try_from(authority_since_epoch.as_secs())
            .map_err(|_| BrokerError::InvalidAuthorityClock)?;
        let authority_utc_anchor = DateTime::<Utc>::from_timestamp(
            authority_seconds,
            authority_since_epoch.subsec_nanos(),
        )
        .ok_or(BrokerError::InvalidAuthorityClock)?;
        if entry_at > authority_utc_anchor {
            return Err(BrokerError::InvalidAuthorityClock);
        }
        Ok(Self {
            entry_at,
            source: Box::new(SystemEffectAuthorityTimeSource {
                authority_utc_anchor,
                monotonic_anchor,
            }),
            sample_count: 0,
        })
    }

    #[cfg(test)]
    fn from_test_source(
        entry_at: DateTime<Utc>,
        source: impl EffectAuthorityTimeSource + 'static,
    ) -> Self {
        Self {
            entry_at,
            source: Box::new(source),
            sample_count: 0,
        }
    }

    #[must_use]
    const fn entry_at(&self) -> DateTime<Utc> {
        self.entry_at
    }

    #[must_use]
    #[cfg(test)]
    const fn sample_count(&self) -> u64 {
        self.sample_count
    }

    fn sample_post_external_call(
        &mut self,
        not_before: DateTime<Utc>,
    ) -> Result<EffectAuthoritySample, BrokerError> {
        self.sample_count = self
            .sample_count
            .checked_add(1)
            .ok_or(BrokerError::InvalidAuthorityClock)?;
        let operation_at = self.source.sample()?;
        if operation_at < self.entry_at || operation_at < not_before {
            return Err(BrokerError::InvalidAuthorityClock);
        }
        Ok(EffectAuthoritySample {
            sequence: self.sample_count,
            operation_at,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectAuthoritySample {
    sequence: u64,
    operation_at: DateTime<Utc>,
}

struct ReconciliationCompletionTiming<'a> {
    clock: &'a mut EffectAuthorityClock,
    authority: &'a mut EffectCompletionAuthority,
    reconciliation_at: DateTime<Utc>,
}

struct ExecuteAndVerifyFlow<'a, Infrastructure, Executor, Verifier> {
    mission: &'a mut Mission,
    effect_id: &'a EffectId,
    infrastructure: &'a mut Infrastructure,
    executor: &'a mut Executor,
    verifier: &'a mut Verifier,
    clock: &'a mut EffectAuthorityClock,
    authority: &'a mut EffectCompletionAuthority,
}

struct ExecutionReceiptCompletion {
    receipt: Receipt,
    disposition: ExecutionDisposition,
    recovered_receipt_candidate: Option<Mission>,
}

struct ReconcileUncertainFlow<'a, Infrastructure, Reconciler, Verifier> {
    mission: &'a mut Mission,
    effect_id: &'a EffectId,
    infrastructure: &'a mut Infrastructure,
    reconciler: &'a mut Reconciler,
    verifier: &'a mut Verifier,
    clock: &'a mut EffectAuthorityClock,
    authority: &'a mut EffectCompletionAuthority,
}

struct ReconciledReceiptVerification {
    lease: ExecutionLease,
    receipt: Receipt,
    execution_started_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectCompletionBoundary {
    Provider,
    Reconciliation,
    Verification,
}

/// Redacted completion timing accepted by the durable ledger. A sampled time
/// is recorded here only after its corresponding completion CAS succeeds.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EffectCompletionAuthority {
    entry_at: DateTime<Utc>,
    provider: Option<EffectCompletionPoint>,
    reconciliation: Option<EffectCompletionPoint>,
    verification: Option<EffectCompletionPoint>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EffectCompletionPoint {
    sequence: u64,
    operation_at: DateTime<Utc>,
}

impl EffectCompletionPoint {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn operation_at(self) -> DateTime<Utc> {
        self.operation_at
    }
}

impl std::fmt::Debug for EffectCompletionPoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectCompletionPoint")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for EffectCompletionAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectCompletionAuthority")
            .field(
                "provider_sequence",
                &self.provider.map(|point| point.sequence),
            )
            .field(
                "reconciliation_sequence",
                &self.reconciliation.map(|point| point.sequence),
            )
            .field(
                "verification_sequence",
                &self.verification.map(|point| point.sequence),
            )
            .finish_non_exhaustive()
    }
}

impl EffectCompletionAuthority {
    const fn new(entry_at: DateTime<Utc>) -> Self {
        Self {
            entry_at,
            provider: None,
            reconciliation: None,
            verification: None,
        }
    }

    fn accept(
        &mut self,
        boundary: EffectCompletionBoundary,
        sample: EffectAuthoritySample,
    ) -> Result<(), BrokerError> {
        if self.latest_accepted().is_some_and(|latest| {
            sample.sequence <= latest.sequence || sample.operation_at < latest.operation_at
        }) {
            return Err(BrokerError::InvalidAuthorityClock);
        }
        let slot = match boundary {
            EffectCompletionBoundary::Provider => &mut self.provider,
            EffectCompletionBoundary::Reconciliation => &mut self.reconciliation,
            EffectCompletionBoundary::Verification => &mut self.verification,
        };
        if slot.is_some() {
            return Err(BrokerError::InvalidAuthorityClock);
        }
        *slot = Some(EffectCompletionPoint {
            sequence: sample.sequence,
            operation_at: sample.operation_at,
        });
        Ok(())
    }

    #[must_use]
    pub const fn provider(&self) -> Option<EffectCompletionPoint> {
        self.provider
    }

    #[must_use]
    pub const fn reconciliation(&self) -> Option<EffectCompletionPoint> {
        self.reconciliation
    }

    #[must_use]
    pub const fn verification(&self) -> Option<EffectCompletionPoint> {
        self.verification
    }

    #[must_use]
    pub fn latest_accepted(&self) -> Option<EffectCompletionPoint> {
        let mut latest = self.provider;
        for candidate in [self.reconciliation, self.verification]
            .into_iter()
            .flatten()
        {
            if latest.is_none_or(|current| candidate.sequence > current.sequence) {
                latest = Some(candidate);
            }
        }
        latest
    }

    fn sampling_floor(&self) -> DateTime<Utc> {
        match self.latest_accepted() {
            Some(point) => point.operation_at,
            None => self.entry_at,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct AuthorityBoundBrokerResult {
    result: BrokerResult,
    authority: EffectCompletionAuthority,
}

impl std::fmt::Debug for AuthorityBoundBrokerResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityBoundBrokerResult")
            .field("disposition", &self.result.disposition)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl AuthorityBoundBrokerResult {
    #[must_use]
    pub const fn result(&self) -> &BrokerResult {
        &self.result
    }

    #[must_use]
    pub const fn authority(&self) -> &EffectCompletionAuthority {
        &self.authority
    }

    #[must_use]
    pub fn into_parts(self) -> (BrokerResult, EffectCompletionAuthority) {
        (self.result, self.authority)
    }
}

#[derive(PartialEq)]
pub struct AuthorityBoundBrokerError {
    inner: Box<AuthorityBoundBrokerErrorInner>,
}

#[derive(PartialEq)]
struct AuthorityBoundBrokerErrorInner {
    error: BrokerError,
    authority: EffectCompletionAuthority,
}

impl std::fmt::Debug for AuthorityBoundBrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityBoundBrokerError")
            .field("error_kind", &broker_error_kind(self.error()))
            .field("authority", self.authority())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for AuthorityBoundBrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error().fmt(formatter)
    }
}

impl std::error::Error for AuthorityBoundBrokerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error())
    }
}

impl AuthorityBoundBrokerError {
    fn new(error: BrokerError, authority: EffectCompletionAuthority) -> Self {
        Self {
            inner: Box::new(AuthorityBoundBrokerErrorInner { error, authority }),
        }
    }

    #[must_use]
    pub fn error(&self) -> &BrokerError {
        &self.inner.error
    }

    #[must_use]
    pub fn authority(&self) -> &EffectCompletionAuthority {
        &self.inner.authority
    }

    #[must_use]
    pub fn into_parts(self) -> (BrokerError, EffectCompletionAuthority) {
        let AuthorityBoundBrokerErrorInner { error, authority } = *self.inner;
        (error, authority)
    }
}

fn broker_error_kind(error: &BrokerError) -> &'static str {
    match error {
        BrokerError::Domain(_) => "domain",
        BrokerError::Ledger(_) => "ledger",
        BrokerError::Permission(_) => "permission",
        BrokerError::CapabilityDenied(_) => "capability_denied",
        BrokerError::InvalidPolicy(_) => "invalid_policy",
        BrokerError::PolicyVersionMismatch { .. } => "policy_version_mismatch",
        BrokerError::RateLimitRuleMissing { .. } => "rate_limit_rule_missing",
        BrokerError::EffectClassDenied(_) => "effect_class_denied",
        BrokerError::CostLimitExceeded { .. } => "cost_limit_exceeded",
        BrokerError::CurrencyDenied(_) => "currency_denied",
        BrokerError::ConsentMissing => "consent_missing",
        BrokerError::Expired => "expired",
        BrokerError::ApprovalExpired => "approval_expired",
        BrokerError::NotScheduled => "not_scheduled",
        BrokerError::ApprovalScopeChanged => "approval_scope_changed",
        BrokerError::PermissionEvidenceChanged => "permission_evidence_changed",
        BrokerError::InvalidLease => "invalid_lease",
        BrokerError::InvalidAuthorityClock => "invalid_authority_clock",
        BrokerError::ExecutionBusy => "execution_busy",
        BrokerError::MissingDurableRecovery => "missing_durable_recovery",
        BrokerError::DurableProjectionRecoveryRequired => "durable_projection_recovery_required",
        BrokerError::RateLimited { .. } => "rate_limited",
        BrokerError::NotApproved(_) => "not_approved",
        BrokerError::ProviderRejected(_) => "provider_rejected",
        BrokerError::ProviderUncertain(_) => "provider_uncertain",
        BrokerError::ReconciliationNotRequired => "reconciliation_not_required",
        BrokerError::ReconciliationBusy => "reconciliation_busy",
        BrokerError::ReconciliationNotReady { .. } => "reconciliation_not_ready",
        BrokerError::ReconciliationStillUncertain { .. } => "reconciliation_still_uncertain",
        BrokerError::ProviderNotExecuted { .. } => "provider_not_executed",
        BrokerError::ReconciliationDeadLetter { .. } => "reconciliation_dead_letter",
        BrokerError::VerificationRejected => "verification_rejected",
        BrokerError::VerificationInconclusive => "verification_inconclusive",
        BrokerError::MissingReceipt => "missing_receipt",
        BrokerError::MissingVerification => "missing_verification",
    }
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
        match self.execute_and_verify_authority_bound(
            mission,
            effect_id,
            infrastructure,
            executor,
            verifier,
            now,
        ) {
            Ok(bound) => Ok(bound.into_parts().0),
            Err(bound) => Err(bound.into_parts().0),
        }
    }

    /// Executes an effect while returning only ledger-accepted completion
    /// authority to the Application projection layer. The caller-provided
    /// `entry_at` remains the claim/business time; completion samples come
    /// exclusively from a Broker-owned system clock.
    pub fn execute_and_verify_authority_bound(
        &mut self,
        mission: &mut Mission,
        effect_id: &EffectId,
        infrastructure: &mut impl EffectInfrastructure,
        executor: &mut impl EffectExecutor,
        verifier: &mut impl EffectVerifier,
        entry_at: DateTime<Utc>,
    ) -> Result<AuthorityBoundBrokerResult, AuthorityBoundBrokerError> {
        let authority = EffectCompletionAuthority::new(entry_at);
        let mut clock = match EffectAuthorityClock::system(entry_at) {
            Ok(clock) => clock,
            Err(error) => return Err(AuthorityBoundBrokerError::new(error, authority)),
        };
        self.execute_and_verify_with_clock(
            mission,
            effect_id,
            infrastructure,
            executor,
            verifier,
            &mut clock,
        )
    }

    fn execute_and_verify_with_clock(
        &mut self,
        mission: &mut Mission,
        effect_id: &EffectId,
        infrastructure: &mut impl EffectInfrastructure,
        executor: &mut impl EffectExecutor,
        verifier: &mut impl EffectVerifier,
        clock: &mut EffectAuthorityClock,
    ) -> Result<AuthorityBoundBrokerResult, AuthorityBoundBrokerError> {
        let mut authority = EffectCompletionAuthority::new(clock.entry_at());
        match self.execute_and_verify_inner(ExecuteAndVerifyFlow {
            mission,
            effect_id,
            infrastructure,
            executor,
            verifier,
            clock,
            authority: &mut authority,
        }) {
            Ok(result) => Ok(AuthorityBoundBrokerResult { result, authority }),
            Err(error) => Err(AuthorityBoundBrokerError::new(error, authority)),
        }
    }

    fn execute_and_verify_inner<Infrastructure, Executor, Verifier>(
        &mut self,
        mut flow: ExecuteAndVerifyFlow<'_, Infrastructure, Executor, Verifier>,
    ) -> Result<BrokerResult, BrokerError>
    where
        Infrastructure: EffectInfrastructure,
        Executor: EffectExecutor,
        Verifier: EffectVerifier,
    {
        let now = flow.clock.entry_at();
        let effect = flow.mission.effect(flow.effect_id)?.clone();
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
        let claim = self.claim_recovery_or_fresh(&effect, flow.infrastructure, now)?;
        let ResolvedLedgerClaim::Acquired {
            lease,
            receipt: existing_receipt,
            execution_started_at,
        } = Self::resolve_ledger_claim(claim)?;

        let receipt_completion = Self::complete_provider_execution(
            &mut flow,
            &effect,
            &lease,
            existing_receipt,
            execution_started_at,
            now,
        )?;
        Self::complete_execution_verification(flow, &effect, &lease, receipt_completion)
    }

    fn complete_provider_execution<Infrastructure, Executor, Verifier>(
        flow: &mut ExecuteAndVerifyFlow<'_, Infrastructure, Executor, Verifier>,
        effect: &Effect,
        lease: &ExecutionLease,
        existing_receipt: Option<Receipt>,
        execution_started_at: DateTime<Utc>,
        entry_at: DateTime<Utc>,
    ) -> Result<ExecutionReceiptCompletion, BrokerError>
    where
        Infrastructure: EffectInfrastructure,
        Executor: EffectExecutor,
    {
        if let Some(receipt) = existing_receipt {
            if effect.conversation_guard.is_some() {
                return Err(BrokerError::DurableProjectionRecoveryRequired);
            }
            let mut candidate = flow.mission.clone();
            candidate.reconcile_durable_receipt(
                flow.effect_id,
                receipt.clone(),
                execution_started_at,
            )?;
            Ok(ExecutionReceiptCompletion {
                receipt,
                disposition: ExecutionDisposition::ReusedIdempotentReceipt,
                recovered_receipt_candidate: Some(candidate),
            })
        } else {
            flow.mission.begin_effect(flow.effect_id, entry_at)?;
            let provider_result = flow.executor.execute(effect);
            let provider_sample = flow
                .clock
                .sample_post_external_call(flow.authority.sampling_floor())?;
            match provider_result {
                Ok(receipt) => {
                    let mut candidate = flow.mission.clone();
                    candidate.record_receipt(flow.effect_id, receipt.clone())?;
                    flow.infrastructure.record_receipt(
                        effect,
                        lease,
                        &receipt,
                        provider_sample.operation_at,
                    )?;
                    flow.authority
                        .accept(EffectCompletionBoundary::Provider, provider_sample)?;
                    Self::bind_receipt_projection_at(&mut candidate, provider_sample.operation_at);
                    *flow.mission = candidate;
                    Ok(ExecutionReceiptCompletion {
                        receipt,
                        disposition: ExecutionDisposition::Executed,
                        recovered_receipt_candidate: None,
                    })
                }
                Err(ProviderFailure::Rejected(reason)) => {
                    flow.infrastructure.record_failed(
                        effect,
                        lease,
                        &reason,
                        provider_sample.operation_at,
                    )?;
                    flow.authority
                        .accept(EffectCompletionBoundary::Provider, provider_sample)?;
                    flow.mission
                        .mark_effect_failed(flow.effect_id, provider_sample.operation_at)?;
                    Err(BrokerError::ProviderRejected(reason))
                }
                Err(ProviderFailure::Uncertain(reason)) => {
                    flow.infrastructure.record_uncertain(
                        effect,
                        lease,
                        &reason,
                        provider_sample.operation_at,
                    )?;
                    flow.authority
                        .accept(EffectCompletionBoundary::Provider, provider_sample)?;
                    flow.mission
                        .mark_effect_uncertain(flow.effect_id, provider_sample.operation_at)?;
                    Err(BrokerError::ProviderUncertain(reason))
                }
            }
        }
    }

    fn complete_execution_verification<Infrastructure, Executor, Verifier>(
        flow: ExecuteAndVerifyFlow<'_, Infrastructure, Executor, Verifier>,
        effect: &Effect,
        lease: &ExecutionLease,
        completion: ExecutionReceiptCompletion,
    ) -> Result<BrokerResult, BrokerError>
    where
        Infrastructure: EffectInfrastructure,
        Verifier: EffectVerifier,
    {
        let ExecuteAndVerifyFlow {
            mission,
            effect_id,
            infrastructure,
            verifier,
            clock,
            authority,
            executor: _,
        } = flow;
        let ExecutionReceiptCompletion {
            receipt,
            disposition,
            recovered_receipt_candidate,
        } = completion;
        let mut candidate = match recovered_receipt_candidate {
            Some(candidate) => candidate,
            None => mission.clone(),
        };
        let effect_with_receipt = candidate.effect(effect_id)?.clone();
        let verification = verifier.verify(&effect_with_receipt, &receipt);
        let verification_sample = clock.sample_post_external_call(authority.sampling_floor())?;
        candidate.record_verification(effect_id, verification.clone())?;
        infrastructure.record_verification(
            effect,
            lease,
            &verification,
            verification_sample.operation_at,
        )?;
        authority.accept(EffectCompletionBoundary::Verification, verification_sample)?;
        Self::bind_verification_projection_at(&mut candidate, verification_sample.operation_at);
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
        match self.reconcile_uncertain_authority_bound(
            mission,
            effect_id,
            infrastructure,
            reconciler,
            verifier,
            now,
        ) {
            Ok(bound) => Ok(bound.into_parts().0),
            Err(bound) => Err(bound.into_parts().0),
        }
    }

    /// Reconciles an uncertain effect and returns the accepted completion
    /// authority needed by the Application projection layer.
    pub fn reconcile_uncertain_authority_bound(
        &mut self,
        mission: &mut Mission,
        effect_id: &EffectId,
        infrastructure: &mut impl EffectInfrastructure,
        reconciler: &mut impl EffectReconciler,
        verifier: &mut impl EffectVerifier,
        entry_at: DateTime<Utc>,
    ) -> Result<AuthorityBoundBrokerResult, AuthorityBoundBrokerError> {
        let authority = EffectCompletionAuthority::new(entry_at);
        let mut clock = match EffectAuthorityClock::system(entry_at) {
            Ok(clock) => clock,
            Err(error) => return Err(AuthorityBoundBrokerError::new(error, authority)),
        };
        self.reconcile_uncertain_with_clock(
            mission,
            effect_id,
            infrastructure,
            reconciler,
            verifier,
            &mut clock,
        )
    }

    fn reconcile_uncertain_with_clock(
        &mut self,
        mission: &mut Mission,
        effect_id: &EffectId,
        infrastructure: &mut impl EffectInfrastructure,
        reconciler: &mut impl EffectReconciler,
        verifier: &mut impl EffectVerifier,
        clock: &mut EffectAuthorityClock,
    ) -> Result<AuthorityBoundBrokerResult, AuthorityBoundBrokerError> {
        let mut authority = EffectCompletionAuthority::new(clock.entry_at());
        match self.reconcile_uncertain_inner(ReconcileUncertainFlow {
            mission,
            effect_id,
            infrastructure,
            reconciler,
            verifier,
            clock,
            authority: &mut authority,
        }) {
            Ok(result) => Ok(AuthorityBoundBrokerResult { result, authority }),
            Err(error) => Err(AuthorityBoundBrokerError::new(error, authority)),
        }
    }

    fn reconcile_uncertain_inner<Infrastructure, Reconciler, Verifier>(
        &mut self,
        flow: ReconcileUncertainFlow<'_, Infrastructure, Reconciler, Verifier>,
    ) -> Result<BrokerResult, BrokerError>
    where
        Infrastructure: EffectInfrastructure,
        Reconciler: EffectReconciler,
        Verifier: EffectVerifier,
    {
        let now = flow.clock.entry_at();
        let effect = flow.mission.effect(flow.effect_id)?.clone();
        if effect.status != EffectStatus::VerificationRequired {
            return Err(BrokerError::ReconciliationNotRequired);
        }
        let claim = flow.infrastructure.claim_reconciliation(
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
                let ResolvedLedgerClaim::Acquired { .. } = Self::resolve_ledger_claim(claim)?;
                return Err(BrokerError::ReconciliationNotRequired);
            }
            ReconciliationClaim::NotReady { retry_at } => {
                return Err(BrokerError::ReconciliationNotReady { retry_at });
            }
            ReconciliationClaim::Busy => return Err(BrokerError::ReconciliationBusy),
            ReconciliationClaim::NotRequired => {
                return Err(BrokerError::ReconciliationNotRequired);
            }
        };
        let observation = flow.reconciler.reconcile(&effect);
        let reconciliation_sample = flow
            .clock
            .sample_post_external_call(flow.authority.sampling_floor())?;
        observation.validate_for(&effect, execution_started_at)?;
        let disposition = flow.infrastructure.record_reconciliation(
            &effect,
            &lease,
            &observation,
            reconciliation_sample.operation_at,
        )?;
        flow.authority.accept(
            EffectCompletionBoundary::Reconciliation,
            reconciliation_sample,
        )?;
        let ReconcileUncertainFlow {
            mission,
            effect_id,
            infrastructure,
            verifier,
            clock,
            authority,
            reconciler: _,
        } = flow;
        let mut timing = ReconciliationCompletionTiming {
            clock,
            authority,
            reconciliation_at: reconciliation_sample.operation_at,
        };
        Self::finish_reconciliation(
            mission,
            effect_id,
            &effect,
            infrastructure,
            verifier,
            disposition,
            &mut timing,
        )
    }

    fn finish_reconciliation(
        mission: &mut Mission,
        effect_id: &EffectId,
        effect: &Effect,
        infrastructure: &mut impl EffectInfrastructure,
        verifier: &mut impl EffectVerifier,
        disposition: ReconciliationDisposition,
        timing: &mut ReconciliationCompletionTiming<'_>,
    ) -> Result<BrokerResult, BrokerError> {
        match disposition {
            ReconciliationDisposition::ReceiptReadyForVerification {
                lease,
                receipt,
                execution_started_at,
            } => Self::verify_reconciled_receipt(
                mission,
                effect_id,
                effect,
                infrastructure,
                verifier,
                ReconciledReceiptVerification {
                    lease,
                    receipt,
                    execution_started_at,
                },
                timing,
            ),
            ReconciliationDisposition::ReconciledNotExecuted {
                evidence_digest,
                execution_started_at,
                ..
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::ReconciledNotExecuted,
                    execution_started_at,
                    timing.reconciliation_at,
                )?;
                Err(BrokerError::ProviderNotExecuted { evidence_digest })
            }
            ReconciliationDisposition::ProviderRejected {
                reason,
                execution_started_at,
                ..
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::Rejected,
                    execution_started_at,
                    timing.reconciliation_at,
                )?;
                Err(BrokerError::ProviderRejected(reason))
            }
            ReconciliationDisposition::RetryScheduled {
                reason,
                evidence_digest,
                retry_at,
                execution_started_at,
                ..
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::Uncertain,
                    execution_started_at,
                    timing.reconciliation_at,
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
                attempts,
                execution_started_at,
                ..
            } => {
                mission.reconcile_durable_provider_state(
                    effect_id,
                    DurableProviderState::DeadLetter,
                    execution_started_at,
                    timing.reconciliation_at,
                )?;
                Err(BrokerError::ReconciliationDeadLetter {
                    reason,
                    evidence_digest,
                    attempts,
                })
            }
        }
    }

    fn verify_reconciled_receipt(
        mission: &mut Mission,
        effect_id: &EffectId,
        effect: &Effect,
        infrastructure: &mut impl EffectInfrastructure,
        verifier: &mut impl EffectVerifier,
        input: ReconciledReceiptVerification,
        timing: &mut ReconciliationCompletionTiming<'_>,
    ) -> Result<BrokerResult, BrokerError> {
        let ReconciledReceiptVerification {
            lease,
            receipt,
            execution_started_at,
        } = input;
        mission.reconcile_durable_receipt(effect_id, receipt.clone(), execution_started_at)?;
        Self::bind_receipt_projection_at(mission, timing.reconciliation_at);
        let effect_with_receipt = mission.effect(effect_id)?.clone();
        let verification = verifier.verify(&effect_with_receipt, &receipt);
        let verification_sample = timing
            .clock
            .sample_post_external_call(timing.authority.sampling_floor())?;
        let mut candidate = mission.clone();
        candidate.record_verification(effect_id, verification.clone())?;
        infrastructure.record_verification(
            effect,
            &lease,
            &verification,
            verification_sample.operation_at,
        )?;
        timing
            .authority
            .accept(EffectCompletionBoundary::Verification, verification_sample)?;
        Self::bind_verification_projection_at(&mut candidate, verification_sample.operation_at);
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

    fn bind_receipt_projection_at(mission: &mut Mission, operation_at: DateTime<Utc>) {
        mission.updated_at = operation_at;
    }

    fn bind_verification_projection_at(mission: &mut Mission, operation_at: DateTime<Utc>) {
        Self::bind_receipt_projection_at(mission, operation_at);
        if let Some(block) = &mut mission.block
            && block.code == "verification_rejected"
        {
            block.observed_at = operation_at;
        }
        if let Some(definition) = &mut mission.definition {
            for checkpoint in &mut definition.checkpoints {
                if let Some(block) = &mut checkpoint.block
                    && block.code == "verification_rejected"
                {
                    block.observed_at = operation_at;
                }
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

    fn resolve_ledger_claim(claim: LedgerClaim) -> Result<ResolvedLedgerClaim, BrokerError> {
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
            LedgerClaim::AlreadyVerified { .. }
            | LedgerClaim::DurableVerification { .. }
            | LedgerClaim::ProviderRejected { .. }
            | LedgerClaim::Uncertain { .. }
            | LedgerClaim::ReconciledNotExecuted { .. }
            | LedgerClaim::DeadLetter { .. } => Err(BrokerError::DurableProjectionRecoveryRequired),
            LedgerClaim::RateLimited { retry_at } => Err(BrokerError::RateLimited { retry_at }),
            LedgerClaim::AuthorizationRequired => {
                Err(BrokerError::Ledger(LedgerError::Persistence(
                    "authorized claim requested another authorization pass".into(),
                )))
            }
            LedgerClaim::Busy => Err(BrokerError::ExecutionBusy),
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
    #[error("effect authority clock is invalid, regressed, or exhausted")]
    InvalidAuthorityClock,
    #[error("effect execution is already leased by another current worker")]
    ExecutionBusy,
    #[error("mission requires durable effect recovery, but no matching ledger state exists")]
    MissingDurableRecovery,
    #[error("durable effect completion requires projection recovery")]
    DurableProjectionRecoveryRequired,
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
    use std::{
        cell::Cell,
        collections::{BTreeSet, VecDeque},
        rc::Rc,
    };

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ConversationEffectGuard, EffectRisk, EffectSpec, MissionContract, MissionId, Outcome,
        OutcomeDecision, ProjectId, ReceiptId, VerificationId,
    };
    use proptest::prelude::*;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn proposed_mission() -> (Mission, EffectId) {
        proposed_mission_fixture(false, None)
    }

    fn proposed_mission_with_connection() -> (Mission, EffectId) {
        proposed_mission_fixture(true, None)
    }

    fn proposed_mission_with_conversation() -> (Mission, EffectId) {
        proposed_mission_fixture(
            false,
            Some(ConversationEffectGuard {
                conversation_id: ConversationId::from("conversation-1"),
                control_generation: 1,
                scope_digest: "7".repeat(64),
            }),
        )
    }

    fn proposed_mission_fixture(
        with_connection: bool,
        conversation_guard: Option<ConversationEffectGuard>,
    ) -> (Mission, EffectId) {
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
                    conversation_guard,
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
        enforce_completion_fence: bool,
        receipt_operation_at: Option<DateTime<Utc>>,
        verification_operation_at: Option<DateTime<Utc>>,
        failed_operation_at: Option<DateTime<Utc>>,
        uncertain_operation_at: Option<DateTime<Utc>>,
        reconciliation_operation_at: Option<DateTime<Utc>>,
    }

    impl TestLedger {
        fn require_execution_completion_live(
            &self,
            lease: &ExecutionLease,
            operation_at: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            if self.enforce_completion_fence && lease.expires_at <= operation_at {
                return Err(LedgerError::LeaseLost);
            }
            Ok(())
        }

        fn require_reconciliation_completion_live(
            &self,
            lease: &ReconciliationLease,
            operation_at: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            if self.enforce_completion_fence && lease.expires_at <= operation_at {
                return Err(LedgerError::LeaseLost);
            }
            Ok(())
        }

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
            lease: &ExecutionLease,
            receipt: &Receipt,
            operation_at: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.require_execution_completion_live(lease, operation_at)?;
            self.receipt = Some(receipt.clone());
            self.receipt_operation_at = Some(operation_at);
            Ok(())
        }

        fn record_verification(
            &mut self,
            _effect: &Effect,
            lease: &ExecutionLease,
            verification: &Verification,
            operation_at: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.require_execution_completion_live(lease, operation_at)?;
            self.verification = Some(verification.clone());
            self.verification_operation_at = Some(operation_at);
            Ok(())
        }

        fn record_failed(
            &mut self,
            _effect: &Effect,
            lease: &ExecutionLease,
            reason: &str,
            operation_at: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.require_execution_completion_live(lease, operation_at)?;
            self.rejected = Some(reason.into());
            self.failed_operation_at = Some(operation_at);
            Ok(())
        }

        fn record_uncertain(
            &mut self,
            _effect: &Effect,
            lease: &ExecutionLease,
            reason: &str,
            operation_at: DateTime<Utc>,
        ) -> Result<(), LedgerError> {
            self.require_execution_completion_live(lease, operation_at)?;
            self.uncertain = Some(reason.into());
            self.uncertain_operation_at = Some(operation_at);
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
            self.require_reconciliation_completion_live(lease, now)?;
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
            self.reconciliation_operation_at = Some(now);
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
            let mut fences = BTreeSet::new();
            if let Some(connection_id) = &effect.connection_id {
                fences.insert(PermissionFence::Connection {
                    connection_id: connection_id.clone(),
                    revision: self.permission_revision,
                });
            }
            if let Some(guard) = &effect.conversation_guard {
                fences.insert(PermissionFence::Conversation {
                    conversation_id: guard.conversation_id.clone(),
                    revision: 1,
                    control_generation: guard.control_generation,
                });
            }
            Ok(PermissionEvidence {
                connection_evidence_digest: self.permission_evidence_digest.clone(),
                consent_evidence_digest: None,
                conversation_evidence_digest: effect
                    .conversation_guard
                    .as_ref()
                    .map(|guard| guard.scope_digest.clone()),
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

    struct ScriptedAuthorityTimeSource {
        samples: VecDeque<DateTime<Utc>>,
        calls: Rc<Cell<usize>>,
    }

    impl EffectAuthorityTimeSource for ScriptedAuthorityTimeSource {
        fn sample(&mut self) -> Result<DateTime<Utc>, BrokerError> {
            self.calls.set(self.calls.get() + 1);
            self.samples
                .pop_front()
                .ok_or(BrokerError::InvalidAuthorityClock)
        }
    }

    struct ProbeExecutor {
        sample_calls: Rc<Cell<usize>>,
        expected_sample_calls: usize,
        result: Result<Receipt, ProviderFailure>,
    }

    impl EffectExecutor for ProbeExecutor {
        fn execute(&mut self, _effect: &Effect) -> Result<Receipt, ProviderFailure> {
            assert_eq!(self.sample_calls.get(), self.expected_sample_calls);
            self.result.clone()
        }
    }

    struct ProbeVerifier {
        sample_calls: Rc<Cell<usize>>,
        expected_sample_calls: usize,
        verification: Verification,
    }

    impl EffectVerifier for ProbeVerifier {
        fn verify(&mut self, _effect: &Effect, _receipt: &Receipt) -> Verification {
            assert_eq!(self.sample_calls.get(), self.expected_sample_calls);
            self.verification.clone()
        }
    }

    struct ProbeReconciler {
        sample_calls: Rc<Cell<usize>>,
        expected_sample_calls: usize,
        observation: ReconciliationObservation,
    }

    impl EffectReconciler for ProbeReconciler {
        fn reconcile(&mut self, _effect: &Effect) -> ReconciliationObservation {
            assert_eq!(self.sample_calls.get(), self.expected_sample_calls);
            self.observation.clone()
        }
    }

    fn scripted_clock(
        entry_at: DateTime<Utc>,
        samples: impl IntoIterator<Item = DateTime<Utc>>,
        calls: Rc<Cell<usize>>,
    ) -> EffectAuthorityClock {
        EffectAuthorityClock::from_test_source(
            entry_at,
            ScriptedAuthorityTimeSource {
                samples: samples.into_iter().collect(),
                calls,
            },
        )
    }

    fn approved_mission() -> (Mission, EffectId, EffectBroker, TestLedger) {
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
        (mission, effect_id, broker, ledger)
    }

    fn durable_receipt(effect: &Effect, id: &str) -> Receipt {
        Receipt {
            id: ReceiptId::from_stable(id),
            provider: effect.provider.clone(),
            external_id: format!("external-{id}"),
            accepted_at: now() + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "a".repeat(64),
        }
    }

    fn durable_verification(
        receipt: &Receipt,
        id: &str,
        status: VerificationStatus,
    ) -> Verification {
        Verification {
            id: VerificationId::from_stable(id),
            status,
            verifier: "durable-readback".into(),
            independent: true,
            observed_at: now() + Duration::seconds(2),
            evidence_digest: "b".repeat(64),
            receipt_id: receipt.id.clone(),
        }
    }

    fn durable_terminal_claim(effect: &Effect, claim_index: usize, marker: &str) -> LedgerClaim {
        let receipt = durable_receipt(effect, marker);
        let verification = durable_verification(
            &receipt,
            marker,
            if claim_index == 1 {
                VerificationStatus::Rejected
            } else {
                VerificationStatus::Confirmed
            },
        );
        match claim_index {
            0 => LedgerClaim::AlreadyVerified {
                receipt,
                verification,
                execution_started_at: now(),
            },
            1 => LedgerClaim::DurableVerification {
                receipt,
                verification,
                execution_started_at: now(),
            },
            2 => LedgerClaim::ProviderRejected {
                reason: marker.into(),
                execution_started_at: now(),
                recorded_at: now() + Duration::seconds(1),
            },
            3 => LedgerClaim::Uncertain {
                reason: marker.into(),
                execution_started_at: now(),
                recorded_at: now() + Duration::seconds(1),
            },
            4 => LedgerClaim::ReconciledNotExecuted {
                evidence_digest: marker.into(),
                observed_at: now() + Duration::seconds(1),
                execution_started_at: now(),
            },
            5 => LedgerClaim::DeadLetter {
                reason: marker.into(),
                evidence_digest: marker.into(),
                dead_lettered_at: now() + Duration::seconds(1),
                attempts: 3,
                execution_started_at: now(),
            },
            _ => unreachable!("six durable terminal claim variants"),
        }
    }

    fn assert_durable_terminal_claim_requires_recovery(claim_index: usize) {
        let marker = "terminal-ledger-fact-must-not-leak";
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
        ledger.reconciliation_terminal = Some(durable_terminal_claim(&effect, claim_index, marker));
        let mission_before = mission.clone();
        let calls = Rc::new(Cell::new(0));
        let mut clock = scripted_clock(now(), [], Rc::clone(&calls));
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let error = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut clock,
            )
            .expect_err("durable terminal claim requires projection recovery");

        assert_eq!(
            error.error(),
            &BrokerError::DurableProjectionRecoveryRequired
        );
        assert!(error.authority().latest_accepted().is_none());
        assert_eq!(mission, mission_before);
        assert_eq!((executor.calls, verifier.calls, calls.get()), (0, 0, 0));
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
        assert!(!format!("{error:?}").contains("2026-08-10"));
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
    fn durable_provider_rejection_requires_projection_recovery_without_mission_mutation() {
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
        let mission_before = mission.clone();
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let error = broker
            .execute_and_verify_authority_bound(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now() + Duration::seconds(61),
            )
            .expect_err("durable rejection needs ledger-authoritative projection recovery");

        assert_eq!(
            error.error(),
            &BrokerError::DurableProjectionRecoveryRequired
        );
        assert!(error.authority().latest_accepted().is_none());
        assert_eq!((executor.calls, verifier.calls), (0, 0));
        assert_eq!(ledger.recovery_probe_calls, 1);
        assert_eq!(ledger.authorized_claim_calls, 0);
        assert_eq!(mission, mission_before);
        assert!(
            !error
                .to_string()
                .contains("durable provider validation rejection")
        );
        assert!(!format!("{error:?}").contains("durable provider validation rejection"));
    }

    #[test]
    fn durable_rejected_verification_requires_projection_recovery_without_mission_mutation() {
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
        let mission_before = mission.clone();
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let error = broker
            .execute_and_verify_authority_bound(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now() + Duration::seconds(61),
            )
            .expect_err("durable verification needs projection recovery");

        assert_eq!(
            error.error(),
            &BrokerError::DurableProjectionRecoveryRequired
        );
        assert!(error.authority().latest_accepted().is_none());
        assert_eq!(executor.calls, 0);
        assert_eq!(verifier.calls, 0);
        assert_eq!(ledger.authorized_claim_calls, 0);
        assert_eq!(mission, mission_before);
        assert!(!error.to_string().contains(receipt.id.as_str()));
        assert!(!format!("{error:?}").contains(receipt.id.as_str()));
    }

    #[test]
    fn durable_inconclusive_verification_requires_projection_recovery_without_mission_mutation() {
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
        let mission_before = mission.clone();
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let error = broker
            .execute_and_verify_authority_bound(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now() + Duration::seconds(61),
            )
            .expect_err("durable verification needs projection recovery");

        assert_eq!(
            error.error(),
            &BrokerError::DurableProjectionRecoveryRequired
        );
        assert!(error.authority().latest_accepted().is_none());
        assert_eq!(executor.calls, 0);
        assert_eq!(verifier.calls, 0);
        assert_eq!(ledger.authorized_claim_calls, 0);
        assert_eq!(mission, mission_before);
    }

    #[test]
    fn every_durable_terminal_claim_requires_typed_projection_recovery_before_mutation() {
        for claim_index in 0..6 {
            assert_durable_terminal_claim_requires_recovery(claim_index);
        }
    }

    #[test]
    fn existing_receipt_conversation_guard_requires_recovery_before_verifier_or_clock() {
        let (mut mission, effect_id) = proposed_mission_with_conversation();
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
            .expect("conversation-scoped approval");
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = durable_receipt(&effect, "conversation-recovery-receipt");
        ledger.execution_started_at = Some(now());
        ledger.receipt = Some(receipt.clone());
        let mission_before = mission.clone();
        let calls = Rc::new(Cell::new(0));
        let mut clock = scripted_clock(now(), [], Rc::clone(&calls));
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let error = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut clock,
            )
            .expect_err("conversation projection lacks ledger-native provider authority");

        assert_eq!(
            error.error(),
            &BrokerError::DurableProjectionRecoveryRequired
        );
        assert!(error.authority().latest_accepted().is_none());
        assert_eq!(mission, mission_before);
        assert_eq!((executor.calls, verifier.calls, calls.get()), (0, 0, 0));
        assert_eq!(ledger.receipt, Some(receipt.clone()));
        assert!(ledger.verification.is_none());
        assert!(!format!("{error:?}").contains(receipt.id.as_str()));
    }

    #[test]
    fn existing_receipt_resume_commits_only_after_verification_cas_and_authority_accept() {
        for status in [
            VerificationStatus::Confirmed,
            VerificationStatus::Rejected,
            VerificationStatus::Inconclusive,
        ] {
            let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
            let effect = mission.effect(&effect_id).expect("effect").clone();
            let receipt = durable_receipt(&effect, "resume-status-receipt");
            ledger.execution_started_at = Some(now());
            ledger.receipt = Some(receipt);
            ledger.enforce_completion_fence = true;
            let completion_at = now() + Duration::seconds(3);
            let calls = Rc::new(Cell::new(0));
            let mut clock = scripted_clock(now(), [completion_at], Rc::clone(&calls));
            let mut executor = CountingExecutor::default();
            let mut verifier = CountingVerifier {
                calls: 0,
                status: status.clone(),
            };

            let bound = broker.execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut clock,
            );
            let authority = match &status {
                VerificationStatus::Confirmed => bound.expect("confirmed resume").authority,
                VerificationStatus::Rejected => {
                    let error = bound.expect_err("rejected resume");
                    assert_eq!(error.error(), &BrokerError::VerificationRejected);
                    *error.authority()
                }
                VerificationStatus::Inconclusive => {
                    let error = bound.expect_err("inconclusive resume");
                    assert_eq!(error.error(), &BrokerError::VerificationInconclusive);
                    *error.authority()
                }
            };
            let expected_status = match status {
                VerificationStatus::Confirmed => EffectStatus::Verified,
                VerificationStatus::Rejected => EffectStatus::Failed,
                VerificationStatus::Inconclusive => EffectStatus::VerificationRequired,
            };

            assert_eq!(
                mission.effect(&effect_id).expect("effect").status,
                expected_status
            );
            assert_eq!(mission.updated_at, completion_at);
            assert!(authority.provider().is_none());
            assert_eq!(
                authority.verification().expect("verification authority"),
                EffectCompletionPoint {
                    sequence: 1,
                    operation_at: completion_at,
                }
            );
            assert_eq!(ledger.verification_operation_at, Some(completion_at));
            assert_eq!((executor.calls, verifier.calls, calls.get()), (0, 1, 1));
        }
    }

    fn assert_existing_receipt_sample_failure_preserves_mission() {
        let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
        let effect = mission.effect(&effect_id).expect("effect").clone();
        ledger.execution_started_at = Some(now());
        ledger.receipt = Some(durable_receipt(&effect, "resume-sample-failure"));
        let mission_before = mission.clone();
        let calls = Rc::new(Cell::new(0));
        let mut clock = scripted_clock(now(), [], Rc::clone(&calls));
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };
        let sample_error = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut clock,
            )
            .expect_err("missing post-verifier sample");

        assert_eq!(sample_error.error(), &BrokerError::InvalidAuthorityClock);
        assert!(sample_error.authority().latest_accepted().is_none());
        assert_eq!(mission, mission_before);
        assert_eq!((executor.calls, verifier.calls, calls.get()), (0, 1, 1));
        assert!(ledger.verification.is_none());
    }

    fn assert_existing_receipt_cas_failure_preserves_mission() {
        let (mut mission, effect_id, broker, mut ledger) = approved_mission();
        let mut broker = broker.with_lease_for(Duration::seconds(5));
        let effect = mission.effect(&effect_id).expect("effect").clone();
        ledger.execution_started_at = Some(now());
        ledger.receipt = Some(durable_receipt(&effect, "resume-cas-failure"));
        ledger.enforce_completion_fence = true;
        let mission_before = mission.clone();
        let calls = Rc::new(Cell::new(0));
        let mut clock = scripted_clock(now(), [now() + Duration::seconds(5)], Rc::clone(&calls));
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };
        let cas_error = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut clock,
            )
            .expect_err("strict lease equality rejects verification CAS");

        assert_eq!(
            cas_error.error(),
            &BrokerError::Ledger(LedgerError::LeaseLost)
        );
        assert!(cas_error.authority().latest_accepted().is_none());
        assert_eq!(mission, mission_before);
        assert_eq!((executor.calls, verifier.calls, calls.get()), (0, 1, 1));
        assert!(ledger.verification.is_none());
    }

    fn assert_existing_receipt_accept_failure_preserves_mission() {
        let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
        let effect = mission.effect(&effect_id).expect("effect").clone();
        ledger.execution_started_at = Some(now());
        ledger.receipt = Some(durable_receipt(&effect, "resume-accept-failure"));
        let mission_before = mission.clone();
        let calls = Rc::new(Cell::new(0));
        let mut clock = scripted_clock(now(), [now() + Duration::seconds(3)], Rc::clone(&calls));
        let mut authority = EffectCompletionAuthority::new(now());
        authority
            .accept(
                EffectCompletionBoundary::Provider,
                EffectAuthoritySample {
                    sequence: 1,
                    operation_at: now() + Duration::seconds(1),
                },
            )
            .expect("artificial previously accepted stage");
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };
        let accept_error = broker
            .execute_and_verify_inner(ExecuteAndVerifyFlow {
                mission: &mut mission,
                effect_id: &effect_id,
                infrastructure: &mut ledger,
                executor: &mut executor,
                verifier: &mut verifier,
                clock: &mut clock,
                authority: &mut authority,
            })
            .expect_err("duplicate accepted sequence must fail closed");

        assert_eq!(accept_error, BrokerError::InvalidAuthorityClock);
        assert_eq!(mission, mission_before);
        assert_eq!((executor.calls, verifier.calls, calls.get()), (0, 1, 1));
        assert!(ledger.verification.is_some());
        assert!(authority.verification().is_none());
    }

    #[test]
    fn existing_receipt_resume_preserves_mission_on_sample_cas_and_accept_failure() {
        assert_existing_receipt_sample_failure_preserves_mission();
        assert_existing_receipt_cas_failure_preserves_mission();
        assert_existing_receipt_accept_failure_preserves_mission();
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
        let mission_after_first = mission.clone();
        let second = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut ledger,
            &mut executor,
            &mut verifier,
            now(),
        );

        assert!(matches!(first, Err(BrokerError::ProviderUncertain(_))));
        assert_eq!(second, Err(BrokerError::DurableProjectionRecoveryRequired));
        assert_eq!(executor.calls, 1);
        assert_eq!(mission, mission_after_first);
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
        let stale_projection_before = stale_projection.clone();
        assert_eq!(
            broker.execute_and_verify(
                &mut stale_projection,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now() + Duration::seconds(2),
            ),
            Err(BrokerError::DurableProjectionRecoveryRequired)
        );
        assert_eq!(stale_projection, stale_projection_before);
        assert_eq!((executor.calls, reconciler.calls), (1, 1));
    }

    struct BoundedReconciliationTestFlow<'a> {
        broker: &'a mut EffectBroker,
        mission: &'a mut Mission,
        effect_id: &'a EffectId,
        ledger: &'a mut TestLedger,
        executor: &'a mut CountingExecutor,
        reconciler: &'a mut CountingReconciler,
        verifier: &'a mut ConfirmingVerifier,
    }

    fn first_bounded_reconciliation_retry_at(
        flow: &mut BoundedReconciliationTestFlow<'_>,
        reconciliation_entry_at: DateTime<Utc>,
        reconciliation_fact_at: DateTime<Utc>,
    ) -> DateTime<Utc> {
        let first = flow
            .broker
            .reconcile_uncertain_authority_bound(
                flow.mission,
                flow.effect_id,
                flow.ledger,
                flow.reconciler,
                flow.verifier,
                reconciliation_entry_at,
            )
            .expect_err("first reconciliation remains uncertain");
        let (first_error, first_authority) = first.into_parts();
        let first_reconciliation = first_authority
            .reconciliation()
            .expect("accepted reconciliation authority");
        assert!(first_authority.provider().is_none());
        assert!(first_authority.verification().is_none());
        assert_eq!(
            first_authority.latest_accepted(),
            Some(first_reconciliation)
        );
        assert_eq!(first_reconciliation.sequence(), 1);
        assert_ne!(first_reconciliation.operation_at(), reconciliation_entry_at);
        assert_ne!(first_reconciliation.operation_at(), reconciliation_fact_at);
        let expected_retry_at = first_reconciliation
            .operation_at()
            .checked_add_signed(Duration::seconds(10))
            .expect("bounded retry time");
        let BrokerError::ReconciliationStillUncertain { retry_at, .. } = first_error else {
            panic!("expected typed uncertain reconciliation result")
        };
        assert_eq!(retry_at, expected_retry_at);
        retry_at
    }

    fn assert_dead_letter_requires_projection_recovery(
        broker: &mut EffectBroker,
        stale_projection: &mut Mission,
        effect_id: &EffectId,
        ledger: &mut TestLedger,
        executor: &mut CountingExecutor,
        verifier: &mut ConfirmingVerifier,
        terminal_entry_at: DateTime<Utc>,
    ) {
        let stale_projection_before = stale_projection.clone();
        let terminal_calls = Rc::new(Cell::new(0));
        let mut terminal_clock = scripted_clock(terminal_entry_at, [], Rc::clone(&terminal_calls));
        let terminal = broker
            .execute_and_verify_with_clock(
                stale_projection,
                effect_id,
                ledger,
                executor,
                verifier,
                &mut terminal_clock,
            )
            .expect_err("dead-letter ledger requires projection recovery");
        assert_eq!(
            terminal.error(),
            &BrokerError::DurableProjectionRecoveryRequired
        );
        assert!(terminal.authority().latest_accepted().is_none());
        assert_eq!(terminal_calls.get(), 0);
        assert_eq!(*stale_projection, stale_projection_before);
    }

    fn assert_bounded_reconciliation_retries_then_dead_letters(
        flow: &mut BoundedReconciliationTestFlow<'_>,
        retry_at: DateTime<Utc>,
    ) {
        assert_eq!(
            flow.broker.reconcile_uncertain(
                flow.mission,
                flow.effect_id,
                flow.ledger,
                flow.reconciler,
                flow.verifier,
                now() + Duration::seconds(2),
            ),
            Err(BrokerError::ReconciliationNotReady { retry_at })
        );
        let mut stale_projection = flow.mission.clone();
        let retry_calls = Rc::new(Cell::new(0));
        let mut retry_clock = scripted_clock(retry_at, [retry_at], Rc::clone(&retry_calls));
        let dead_letter = flow
            .broker
            .reconcile_uncertain_with_clock(
                flow.mission,
                flow.effect_id,
                flow.ledger,
                flow.reconciler,
                flow.verifier,
                &mut retry_clock,
            )
            .expect_err("retry equality acquires and reaches the bounded dead letter");
        assert!(matches!(
            dead_letter.error(),
            BrokerError::ReconciliationDeadLetter { attempts: 2, .. }
        ));
        assert_eq!(retry_calls.get(), 1);
        assert_eq!(
            dead_letter
                .authority()
                .reconciliation()
                .expect("dead-letter reconciliation authority")
                .operation_at(),
            retry_at
        );
        assert_eq!(
            flow.mission.effect(flow.effect_id).expect("effect").status,
            EffectStatus::DeadLetter
        );
        let terminal_entry_at = retry_at
            .checked_add_signed(Duration::seconds(1))
            .expect("bounded terminal probe time");
        assert_dead_letter_requires_projection_recovery(
            flow.broker,
            &mut stale_projection,
            flow.effect_id,
            flow.ledger,
            flow.executor,
            flow.verifier,
            terminal_entry_at,
        );
        assert_eq!((flow.executor.calls, flow.reconciler.calls), (1, 2));
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
        let reconciliation_fact_at = now() + Duration::milliseconds(500);
        let reconciliation_entry_at = now() + Duration::seconds(1);
        let mut reconciler = CountingReconciler {
            calls: 0,
            observation: ReconciliationObservation::StillUncertain {
                reason: "Provider lookup is still ambiguous".into(),
                evidence_digest: "7".repeat(64),
                observed_at: reconciliation_fact_at,
            },
        };
        let mut flow = BoundedReconciliationTestFlow {
            broker: &mut broker,
            mission: &mut mission,
            effect_id: &effect_id,
            ledger: &mut ledger,
            executor: &mut executor,
            reconciler: &mut reconciler,
            verifier: &mut verifier,
        };
        let retry_at = first_bounded_reconciliation_retry_at(
            &mut flow,
            reconciliation_entry_at,
            reconciliation_fact_at,
        );
        assert_bounded_reconciliation_retries_then_dead_letters(&mut flow, retry_at);
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

    #[test]
    fn accepted_completion_trace_orders_by_sequence_and_allows_equal_times() {
        let entry_at = now();
        let accepted_at = entry_at + Duration::seconds(1);
        let mut authority = EffectCompletionAuthority::new(entry_at);

        authority
            .accept(
                EffectCompletionBoundary::Provider,
                EffectAuthoritySample {
                    sequence: 1,
                    operation_at: accepted_at,
                },
            )
            .expect("first accepted completion");
        assert_eq!(
            authority.accept(
                EffectCompletionBoundary::Reconciliation,
                EffectAuthoritySample {
                    sequence: 1,
                    operation_at: accepted_at,
                },
            ),
            Err(BrokerError::InvalidAuthorityClock)
        );
        assert_eq!(
            authority.accept(
                EffectCompletionBoundary::Reconciliation,
                EffectAuthoritySample {
                    sequence: 2,
                    operation_at: entry_at,
                },
            ),
            Err(BrokerError::InvalidAuthorityClock)
        );
        authority
            .accept(
                EffectCompletionBoundary::Verification,
                EffectAuthoritySample {
                    sequence: 2,
                    operation_at: accepted_at,
                },
            )
            .expect("equal timestamp with a later sequence is valid");
        authority
            .accept(
                EffectCompletionBoundary::Reconciliation,
                EffectAuthoritySample {
                    sequence: 3,
                    operation_at: accepted_at,
                },
            )
            .expect("latest stage is selected by sequence, not enum priority");

        assert_eq!(authority.latest_accepted(), authority.reconciliation());
        assert_eq!(authority.latest_accepted().expect("latest").sequence(), 3);
        let debug = format!("{authority:?}");
        assert!(debug.contains("provider_sequence: Some(1)"));
        assert!(debug.contains("reconciliation_sequence: Some(3)"));
        assert!(debug.contains("verification_sequence: Some(2)"));
        assert!(!debug.contains("2026"));
        assert!(!format!("{:?}", authority.verification().expect("point")).contains("2026"));
    }

    #[test]
    fn future_entry_fails_before_external_call_with_empty_authority() {
        let (mission, effect_id) = proposed_mission();
        let original = mission.clone();
        let mut mission = mission;
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };
        let future_entry = Utc::now() + Duration::hours(1);

        let error = broker
            .execute_and_verify_authority_bound(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                future_entry,
            )
            .expect_err("caller future time must fail closed");

        assert_eq!(error.error(), &BrokerError::InvalidAuthorityClock);
        assert!(error.authority().latest_accepted().is_none());
        assert!(!format!("{error:?}").contains(&future_entry.to_rfc3339()));
        assert_eq!(mission, original);
        assert_eq!((executor.calls, verifier.calls), (0, 0));
        assert_eq!(
            (ledger.recovery_probe_calls, ledger.authorized_claim_calls),
            (0, 0)
        );
        assert!(ledger.receipt.is_none());
        assert!(ledger.verification.is_none());
    }

    #[test]
    fn historical_entry_cannot_anchor_post_call_system_samples() {
        let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let bound = broker
            .execute_and_verify_authority_bound(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                now(),
            )
            .expect("test ledger permits inspection of the system authority sample");
        let provider = bound.authority().provider().expect("provider authority");
        let verification = bound
            .authority()
            .verification()
            .expect("verification authority");

        assert!(provider.operation_at() > now() + Duration::hours(1));
        assert!(verification.operation_at() >= provider.operation_at());
        assert_eq!(ledger.receipt_operation_at, Some(provider.operation_at()));
        assert_eq!(
            ledger.verification_operation_at,
            Some(verification.operation_at())
        );
        assert_eq!(mission.updated_at, verification.operation_at());
    }

    #[test]
    fn executor_and_verifier_are_sampled_once_after_each_return() {
        let entry_at = now();
        let provider_at = entry_at + Duration::seconds(1);
        let verification_at = entry_at + Duration::seconds(2);
        let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
        ledger.enforce_completion_fence = true;
        let calls = Rc::new(Cell::new(0));
        let mut clock = scripted_clock(entry_at, [provider_at, verification_at], Rc::clone(&calls));
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = Receipt {
            id: ReceiptId::from("authority-receipt"),
            provider: effect.provider.clone(),
            external_id: "authority-external".into(),
            accepted_at: entry_at,
            request_digest: effect.approval_digest(),
            response_digest: "a".repeat(64),
        };
        let mut executor = ProbeExecutor {
            sample_calls: Rc::clone(&calls),
            expected_sample_calls: 0,
            result: Ok(receipt.clone()),
        };
        let mut verifier = ProbeVerifier {
            sample_calls: Rc::clone(&calls),
            expected_sample_calls: 1,
            verification: Verification {
                id: VerificationId::from("authority-verification"),
                status: VerificationStatus::Confirmed,
                verifier: "authority-readback".into(),
                independent: true,
                observed_at: entry_at + Duration::seconds(1),
                evidence_digest: "b".repeat(64),
                receipt_id: receipt.id.clone(),
            },
        };

        let bound = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut clock,
            )
            .expect("authority-bound execution");

        assert_eq!(calls.get(), 2);
        assert_eq!(clock.sample_count(), 2);
        assert!(!format!("{clock:?}").contains("2026"));
        assert_eq!(
            bound.authority().provider().expect("provider").sequence(),
            1
        );
        assert_eq!(
            bound
                .authority()
                .verification()
                .expect("verification")
                .sequence(),
            2
        );
        assert_eq!(ledger.receipt_operation_at, Some(provider_at));
        assert_eq!(ledger.verification_operation_at, Some(verification_at));
        assert_eq!(mission.updated_at, verification_at);
        assert!(!format!("{bound:?}").contains("authority-external"));
    }

    #[test]
    fn completion_at_lease_expiry_is_rejected_without_accepted_authority() {
        let entry_at = now();
        let lease_for = Duration::seconds(5);
        let (mut mission, effect_id, broker, mut ledger) = approved_mission();
        let mut broker = broker.with_lease_for(lease_for);
        ledger.enforce_completion_fence = true;
        let calls = Rc::new(Cell::new(0));
        let mut clock = scripted_clock(entry_at, [entry_at + lease_for], Rc::clone(&calls));
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let mut executor = ProbeExecutor {
            sample_calls: Rc::clone(&calls),
            expected_sample_calls: 0,
            result: Ok(Receipt {
                id: ReceiptId::from("expiry-receipt"),
                provider: effect.provider.clone(),
                external_id: "expiry-external".into(),
                accepted_at: entry_at,
                request_digest: effect.approval_digest(),
                response_digest: "c".repeat(64),
            }),
        };
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };

        let error = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut clock,
            )
            .expect_err("strict expiry equality must lose the lease");

        assert_eq!(error.error(), &BrokerError::Ledger(LedgerError::LeaseLost));
        assert!(error.authority().latest_accepted().is_none());
        assert_eq!(calls.get(), 1);
        assert_eq!(verifier.calls, 0);
        assert!(ledger.receipt.is_none());
        assert!(ledger.receipt_operation_at.is_none());
    }

    fn assert_authority_clock_sample_overflow_fails_before_source(entry_at: DateTime<Utc>) {
        let overflow_calls = Rc::new(Cell::new(0));
        let mut overflow_clock = scripted_clock(entry_at, [entry_at], Rc::clone(&overflow_calls));
        overflow_clock.sample_count = u64::MAX;
        assert_eq!(
            overflow_clock.sample_post_external_call(entry_at),
            Err(BrokerError::InvalidAuthorityClock)
        );
        assert_eq!(overflow_calls.get(), 0);
    }

    fn assert_regressed_authority_sample_preserves_ledger(entry_at: DateTime<Utc>) {
        let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
        let calls = Rc::new(Cell::new(0));
        let mut regressed_clock = scripted_clock(
            entry_at,
            [entry_at - Duration::nanoseconds(1)],
            Rc::clone(&calls),
        );
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = Receipt {
            id: ReceiptId::from("clock-receipt"),
            provider: effect.provider.clone(),
            external_id: "clock-external".into(),
            accepted_at: entry_at,
            request_digest: effect.approval_digest(),
            response_digest: "d".repeat(64),
        };
        let mut executor = ProbeExecutor {
            sample_calls: Rc::clone(&calls),
            expected_sample_calls: 0,
            result: Ok(receipt.clone()),
        };
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };
        let regression = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut regressed_clock,
            )
            .expect_err("regression must fail closed");
        assert_eq!(regression.error(), &BrokerError::InvalidAuthorityClock);
        assert!(regression.authority().latest_accepted().is_none());
        assert!(ledger.receipt.is_none());
    }

    #[test]
    fn clock_regression_and_exhaustion_fail_closed_without_accepting_failed_samples() {
        let entry_at = now();
        assert_authority_clock_sample_overflow_fails_before_source(entry_at);
        assert_regressed_authority_sample_preserves_ledger(entry_at);

        let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
        ledger.enforce_completion_fence = true;
        let calls = Rc::new(Cell::new(0));
        let mut exhausted_clock = scripted_clock(
            entry_at,
            [entry_at + Duration::seconds(1)],
            Rc::clone(&calls),
        );
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = Receipt {
            id: ReceiptId::from("exhausted-receipt"),
            provider: effect.provider.clone(),
            external_id: "exhausted-external".into(),
            accepted_at: entry_at,
            request_digest: effect.approval_digest(),
            response_digest: "e".repeat(64),
        };
        let mut executor = ProbeExecutor {
            sample_calls: Rc::clone(&calls),
            expected_sample_calls: 0,
            result: Ok(receipt.clone()),
        };
        let mut verifier = ProbeVerifier {
            sample_calls: Rc::clone(&calls),
            expected_sample_calls: 1,
            verification: Verification {
                id: VerificationId::from("exhausted-verification"),
                status: VerificationStatus::Confirmed,
                verifier: "exhausted-readback".into(),
                independent: true,
                observed_at: entry_at + Duration::seconds(1),
                evidence_digest: "f".repeat(64),
                receipt_id: receipt.id,
            },
        };
        let exhaustion = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut exhausted_clock,
            )
            .expect_err("missing second sample must fail closed");
        assert_eq!(exhaustion.error(), &BrokerError::InvalidAuthorityClock);
        assert_eq!(calls.get(), 2);
        assert_eq!(
            exhaustion.authority().latest_accepted(),
            exhaustion.authority().provider()
        );
        assert_eq!(
            exhaustion
                .authority()
                .provider()
                .expect("accepted provider")
                .operation_at(),
            entry_at + Duration::seconds(1)
        );
        assert!(exhaustion.authority().verification().is_none());
        assert!(ledger.receipt.is_some());
        assert!(ledger.verification.is_none());
    }

    #[test]
    fn rejected_and_uncertain_provider_returns_use_one_post_call_sample() {
        for failure in [
            ProviderFailure::Rejected("rejected".into()),
            ProviderFailure::Uncertain("uncertain".into()),
        ] {
            let entry_at = now();
            let completion_at = entry_at + Duration::seconds(1);
            let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
            ledger.enforce_completion_fence = true;
            let calls = Rc::new(Cell::new(0));
            let mut clock = scripted_clock(entry_at, [completion_at], Rc::clone(&calls));
            let mut executor = ProbeExecutor {
                sample_calls: Rc::clone(&calls),
                expected_sample_calls: 0,
                result: Err(failure.clone()),
            };
            let mut verifier = CountingVerifier {
                calls: 0,
                status: VerificationStatus::Confirmed,
            };

            let error = broker
                .execute_and_verify_with_clock(
                    &mut mission,
                    &effect_id,
                    &mut ledger,
                    &mut executor,
                    &mut verifier,
                    &mut clock,
                )
                .expect_err("provider failure remains terminal for this call");

            assert_eq!(calls.get(), 1);
            assert_eq!(verifier.calls, 0);
            assert_eq!(
                error
                    .authority()
                    .provider()
                    .expect("provider completion")
                    .operation_at(),
                completion_at
            );
            assert_eq!(mission.updated_at, completion_at);
            match failure {
                ProviderFailure::Rejected(_) => {
                    assert_eq!(ledger.failed_operation_at, Some(completion_at));
                    assert!(ledger.uncertain_operation_at.is_none());
                }
                ProviderFailure::Uncertain(_) => {
                    assert_eq!(ledger.uncertain_operation_at, Some(completion_at));
                    assert!(ledger.failed_operation_at.is_none());
                }
            }
        }
    }

    #[test]
    fn reconciliation_and_verification_sample_after_their_own_external_returns() {
        let entry_at = now();
        let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
        let uncertain_calls = Rc::new(Cell::new(0));
        let mut uncertain_clock = scripted_clock(
            entry_at,
            [entry_at + Duration::seconds(1)],
            Rc::clone(&uncertain_calls),
        );
        let mut uncertain_executor = ProbeExecutor {
            sample_calls: Rc::clone(&uncertain_calls),
            expected_sample_calls: 0,
            result: Err(ProviderFailure::Uncertain("submitted".into())),
        };
        let mut unused_verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };
        broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut uncertain_executor,
                &mut unused_verifier,
                &mut uncertain_clock,
            )
            .expect_err("uncertain provider result");

        ledger.enforce_completion_fence = true;
        let calls = Rc::new(Cell::new(0));
        let reconciliation_at = entry_at + Duration::seconds(2);
        let verification_at = entry_at + Duration::seconds(3);
        let mut clock = scripted_clock(
            entry_at,
            [reconciliation_at, verification_at],
            Rc::clone(&calls),
        );
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let receipt = Receipt {
            id: ReceiptId::from("reconciliation-authority-receipt"),
            provider: effect.provider.clone(),
            external_id: "reconciliation-authority-external".into(),
            accepted_at: entry_at + Duration::seconds(1),
            request_digest: effect.approval_digest(),
            response_digest: "1".repeat(64),
        };
        let mut reconciler = ProbeReconciler {
            sample_calls: Rc::clone(&calls),
            expected_sample_calls: 0,
            observation: ReconciliationObservation::ReceiptFound {
                receipt: receipt.clone(),
                evidence_digest: "2".repeat(64),
                observed_at: reconciliation_at,
            },
        };
        let mut verifier = ProbeVerifier {
            sample_calls: Rc::clone(&calls),
            expected_sample_calls: 1,
            verification: Verification {
                id: VerificationId::from("reconciliation-authority-verification"),
                status: VerificationStatus::Confirmed,
                verifier: "reconciliation-authority-readback".into(),
                independent: true,
                observed_at: verification_at,
                evidence_digest: "3".repeat(64),
                receipt_id: receipt.id,
            },
        };

        let bound = broker
            .reconcile_uncertain_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut reconciler,
                &mut verifier,
                &mut clock,
            )
            .expect("reconciliation authority closure");

        assert_eq!(calls.get(), 2);
        assert_eq!(
            bound
                .authority()
                .reconciliation()
                .expect("reconciliation")
                .sequence(),
            1
        );
        assert_eq!(
            bound
                .authority()
                .verification()
                .expect("verification")
                .sequence(),
            2
        );
        assert_eq!(ledger.reconciliation_operation_at, Some(reconciliation_at));
        assert_eq!(ledger.verification_operation_at, Some(verification_at));
        assert_eq!(mission.updated_at, verification_at);
    }

    #[test]
    fn preflight_and_durable_terminal_returns_have_empty_authority() {
        let entry_at = now();
        let (mission, effect_id) = proposed_mission();
        let original = mission.clone();
        let mut mission = mission;
        let mut broker = broker();
        let mut ledger = TestLedger::default();
        let calls = Rc::new(Cell::new(0));
        let mut clock = scripted_clock(entry_at, [], Rc::clone(&calls));
        let mut executor = CountingExecutor::default();
        let mut verifier = CountingVerifier {
            calls: 0,
            status: VerificationStatus::Confirmed,
        };
        let preflight = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut clock,
            )
            .expect_err("unapproved effect");
        assert!(preflight.authority().latest_accepted().is_none());
        assert_eq!(calls.get(), 0);
        assert_eq!(mission, original);

        let (mut mission, effect_id, mut broker, mut ledger) = approved_mission();
        let calls = Rc::new(Cell::new(0));
        let mut execution_clock = scripted_clock(
            entry_at,
            [
                entry_at + Duration::seconds(1),
                entry_at + Duration::seconds(2),
            ],
            Rc::clone(&calls),
        );
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;
        broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut execution_clock,
            )
            .expect("initial verified state");
        let verified_snapshot = mission.clone();
        let calls = Rc::new(Cell::new(0));
        let mut terminal_clock = scripted_clock(entry_at, [], Rc::clone(&calls));
        let terminal = broker
            .execute_and_verify_with_clock(
                &mut mission,
                &effect_id,
                &mut ledger,
                &mut executor,
                &mut verifier,
                &mut terminal_clock,
            )
            .expect("durable terminal return");
        assert!(terminal.authority().latest_accepted().is_none());
        assert_eq!(calls.get(), 0);
        assert_eq!(mission, verified_snapshot);
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

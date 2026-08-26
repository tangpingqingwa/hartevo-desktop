//! Policy-bound capability degradation and provider fallback.
//!
//! This module composes already trusted plugin/provider bindings.  It does
//! not discover providers, execute a host operation, or carry a result
//! payload.  A fallback is a single, durable decision for one exact
//! Project/Mission invocation and is only selectable after a typed primary
//! provider outcome says `Unavailable`, `Revoked`, or `QuotaExceeded`.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::Error as DeError};
use thiserror::Error;

use super::{
    CapabilityClass, CostLimit, Digest, MissionScope, ProjectScope, digest_serialized, is_sha256,
};

pub const CAPABILITY_DEGRADATION_INVOCATION_SCHEMA: &str =
    "hartevo.capability-degradation-invocation/v1";
pub const CAPABILITY_PROVIDER_BINDING_SCHEMA: &str = "hartevo.capability-provider-binding/v1";
pub const CAPABILITY_FALLBACK_POLICY_SCHEMA: &str = "hartevo.capability-fallback-policy/v1";
pub const CAPABILITY_FALLBACK_COMPOSITION_SCHEMA: &str =
    "hartevo.capability-fallback-composition/v1";
pub const CAPABILITY_PROVIDER_OUTCOME_SCHEMA: &str = "hartevo.capability-provider-outcome/v1";
pub const CAPABILITY_FALLBACK_RESULT_SCHEMA: &str = "hartevo.capability-fallback-result/v1";
pub const CAPABILITY_FALLBACK_DECISION_SCHEMA: &str = "hartevo.capability-fallback-decision/v1";
pub const CAPABILITY_FALLBACK_LOG_SCHEMA: &str = "hartevo.capability-fallback-log/v1";
pub const MAX_FALLBACK_ATTEMPTS: u8 = 1;

/// A canonical, exact `major.minor.patch` version used by all fallback
/// bindings.  Provider identity is a digest; this value is only its explicit
/// version coordinate.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CapabilityVersion(String);

impl CapabilityVersion {
    #[must_use]
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self(format!("{major}.{minor}.{patch}"))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, CapabilityDegradationError> {
        let value = value.into();
        validate_version(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), CapabilityDegradationError> {
        validate_version(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapabilityVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        validate_version(&value).map_err(|_| D::Error::custom("invalid capability version"))?;
        Ok(Self(value))
    }
}

impl fmt::Debug for CapabilityVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CapabilityVersion")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for CapabilityVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycle {
    Active,
    Revoked,
}

/// The exact immutable identity of a Mission invocation being degraded.
/// `mission_revision` must equal the Mission contract revision, while
/// `invocation_revision` is the caller's revision for this invocation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DegradationInvocation {
    pub schema: String,
    pub capability_digest: Digest,
    pub service_digest: Digest,
    pub capability_version: CapabilityVersion,
    pub service_version: CapabilityVersion,
    pub class: CapabilityClass,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub authority_digest: Digest,
    pub policy_digest: Digest,
    pub mission_revision: u64,
    pub invocation_revision: u64,
    pub invocation_digest: Digest,
    pub idempotency_digest: Digest,
    pub cost_ceiling: CostLimit,
}

impl DegradationInvocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_digest: Digest,
        service_digest: Digest,
        capability_version: CapabilityVersion,
        service_version: CapabilityVersion,
        class: CapabilityClass,
        project: ProjectScope,
        mission: MissionScope,
        authority_digest: Digest,
        policy_digest: Digest,
        invocation_revision: u64,
        invocation_digest: Digest,
        idempotency_digest: Digest,
        cost_ceiling: CostLimit,
    ) -> Result<Self, CapabilityDegradationError> {
        let mission_revision = mission.contract_revision;
        let invocation = Self {
            schema: CAPABILITY_DEGRADATION_INVOCATION_SCHEMA.into(),
            capability_digest,
            service_digest,
            capability_version,
            service_version,
            class,
            project,
            mission,
            authority_digest,
            policy_digest,
            mission_revision,
            invocation_revision,
            invocation_digest,
            idempotency_digest,
            cost_ceiling,
        };
        let mut invocation = invocation;
        invocation.mission_revision = invocation.mission.contract_revision;
        invocation.validate()?;
        Ok(invocation)
    }

    pub fn validate(&self) -> Result<(), CapabilityDegradationError> {
        if self.schema != CAPABILITY_DEGRADATION_INVOCATION_SCHEMA
            || self.mission_revision == 0
            || self.invocation_revision == 0
            || self.mission_revision != self.mission.contract_revision
            || !is_sha256(self.capability_digest.as_str())
            || !is_sha256(self.service_digest.as_str())
            || !is_sha256(self.authority_digest.as_str())
            || !is_sha256(self.policy_digest.as_str())
            || !is_sha256(self.invocation_digest.as_str())
            || !is_sha256(self.idempotency_digest.as_str())
        {
            return Err(CapabilityDegradationError::InvalidInvocation);
        }
        self.capability_version.validate()?;
        self.service_version.validate()?;
        self.project
            .validate()
            .map_err(|_| CapabilityDegradationError::InvalidInvocation)?;
        self.mission
            .validate(&self.project)
            .map_err(|_| CapabilityDegradationError::InvalidInvocation)?;
        self.cost_ceiling
            .validate()
            .map_err(|_| CapabilityDegradationError::InvalidInvocation)
    }

    #[must_use]
    pub fn key(&self) -> FallbackInvocationKey {
        FallbackInvocationKey::from_invocation(self)
    }
}

impl fmt::Debug for DegradationInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DegradationInvocation")
            .field("schema", &self.schema)
            .field("capability_digest", &self.capability_digest)
            .field("service_digest", &self.service_digest)
            .field("capability_version", &self.capability_version)
            .field("service_version", &self.service_version)
            .field("class", &self.class)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("authority_digest", &self.authority_digest)
            .field("policy_digest", &self.policy_digest)
            .field("mission_revision", &self.mission_revision)
            .field("invocation_revision", &self.invocation_revision)
            .field("invocation_digest", &self.invocation_digest)
            .field("idempotency_digest", &self.idempotency_digest)
            .field("cost_ceiling", &self.cost_ceiling)
            .finish_non_exhaustive()
    }
}

/// Durable idempotency identity.  The key includes the scope and generation,
/// not just the invocation digest, so a replay with a new invocation revision
/// cannot create a second fallback effect for the same request.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackInvocationKey {
    pub tenant_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub generation: u64,
    pub idempotency_digest: Digest,
}

impl FallbackInvocationKey {
    #[must_use]
    pub fn from_invocation(invocation: &DegradationInvocation) -> Self {
        Self {
            tenant_digest: Digest::from_text(invocation.project.tenant_id.as_str()),
            project_digest: Digest::from_text(invocation.project.project_id.as_str()),
            mission_digest: Digest::from_text(invocation.mission.mission_id.as_str()),
            generation: invocation.mission.generation,
            idempotency_digest: invocation.idempotency_digest.clone(),
        }
    }
}

impl fmt::Debug for FallbackInvocationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FallbackInvocationKey")
            .field("tenant_digest", &self.tenant_digest)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("generation", &self.generation)
            .field("idempotency_digest", &self.idempotency_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityProviderBinding {
    pub schema: String,
    pub invocation: DegradationInvocation,
    pub provider_digest: Digest,
    pub provider_version: CapabilityVersion,
    pub implementation_digest: Digest,
    pub schema_digest: Digest,
    pub revocation_epoch: u64,
    pub revocation_digest: Digest,
    pub lifecycle: ProviderLifecycle,
}

impl CapabilityProviderBinding {
    pub fn new(
        invocation: DegradationInvocation,
        provider_digest: Digest,
        provider_version: CapabilityVersion,
        implementation_digest: Digest,
        schema_digest: Digest,
        revocation_epoch: u64,
        revocation_digest: Digest,
    ) -> Result<Self, CapabilityDegradationError> {
        let binding = Self {
            schema: CAPABILITY_PROVIDER_BINDING_SCHEMA.into(),
            invocation,
            provider_digest,
            provider_version,
            implementation_digest,
            schema_digest,
            revocation_epoch,
            revocation_digest,
            lifecycle: ProviderLifecycle::Active,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn with_lifecycle(
        mut self,
        lifecycle: ProviderLifecycle,
        revocation_digest: Digest,
    ) -> Result<Self, CapabilityDegradationError> {
        self.lifecycle = lifecycle;
        self.revocation_digest = revocation_digest;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), CapabilityDegradationError> {
        if self.schema != CAPABILITY_PROVIDER_BINDING_SCHEMA
            || !is_sha256(self.provider_digest.as_str())
            || !is_sha256(self.implementation_digest.as_str())
            || !is_sha256(self.schema_digest.as_str())
            || self.revocation_epoch == 0
            || !is_sha256(self.revocation_digest.as_str())
        {
            return Err(CapabilityDegradationError::InvalidProviderBinding);
        }
        self.invocation.validate()?;
        self.provider_version.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.lifecycle == ProviderLifecycle::Active
    }
}

impl fmt::Debug for CapabilityProviderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityProviderBinding")
            .field("binding_digest", &self.digest())
            .field("provider_digest", &self.provider_digest)
            .field("provider_version", &self.provider_version)
            .field("implementation_digest", &self.implementation_digest)
            .field("schema_digest", &self.schema_digest)
            .field("revocation_epoch", &self.revocation_epoch)
            .field("revocation_digest", &self.revocation_digest)
            .field("lifecycle", &self.lifecycle)
            .field("invocation", &self.invocation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFallbackPolicy {
    pub schema: String,
    pub policy_digest: Digest,
    pub authority_digest: Digest,
    pub allowed_provider_digests: BTreeSet<Digest>,
    pub cost_ceiling: CostLimit,
    pub max_fallback_attempts: u8,
}

impl CapabilityFallbackPolicy {
    pub fn new(
        policy_digest: Digest,
        authority_digest: Digest,
        allowed_provider_digests: BTreeSet<Digest>,
        cost_ceiling: CostLimit,
    ) -> Result<Self, CapabilityDegradationError> {
        let policy = Self {
            schema: CAPABILITY_FALLBACK_POLICY_SCHEMA.into(),
            policy_digest,
            authority_digest,
            allowed_provider_digests,
            cost_ceiling,
            max_fallback_attempts: MAX_FALLBACK_ATTEMPTS,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), CapabilityDegradationError> {
        if self.schema != CAPABILITY_FALLBACK_POLICY_SCHEMA
            || !is_sha256(self.policy_digest.as_str())
            || !is_sha256(self.authority_digest.as_str())
            || self.allowed_provider_digests.is_empty()
            || self
                .allowed_provider_digests
                .iter()
                .any(|digest| !is_sha256(digest.as_str()))
            || self.max_fallback_attempts != MAX_FALLBACK_ATTEMPTS
        {
            return Err(CapabilityDegradationError::InvalidPolicy);
        }
        self.cost_ceiling
            .validate()
            .map_err(|_| CapabilityDegradationError::InvalidPolicy)
    }

    pub fn validate_for(
        &self,
        invocation: &DegradationInvocation,
    ) -> Result<(), CapabilityDegradationError> {
        self.validate()?;
        if self.policy_digest != invocation.policy_digest
            || self.authority_digest != invocation.authority_digest
            || self.cost_ceiling != invocation.cost_ceiling
        {
            return Err(CapabilityDegradationError::PolicyMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn allows(&self, provider_digest: &Digest) -> bool {
        self.allowed_provider_digests.contains(provider_digest)
    }
}

impl fmt::Debug for CapabilityFallbackPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFallbackPolicy")
            .field("policy_digest", &self.policy_digest)
            .field("authority_digest", &self.authority_digest)
            .field(
                "allowed_provider_count",
                &self.allowed_provider_digests.len(),
            )
            .field(
                "allowed_provider_set_digest",
                &digest_serialized(&self.allowed_provider_digests),
            )
            .field("cost_ceiling", &self.cost_ceiling)
            .field("max_fallback_attempts", &self.max_fallback_attempts)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFallbackComposition {
    pub schema: String,
    pub primary: CapabilityProviderBinding,
    pub alternate: CapabilityProviderBinding,
    pub policy: CapabilityFallbackPolicy,
    pub composition_digest: Digest,
}

impl CapabilityFallbackComposition {
    pub fn new(
        primary: CapabilityProviderBinding,
        alternate: CapabilityProviderBinding,
        policy: CapabilityFallbackPolicy,
    ) -> Result<Self, CapabilityDegradationError> {
        let composition = Self {
            schema: CAPABILITY_FALLBACK_COMPOSITION_SCHEMA.into(),
            primary,
            alternate,
            policy,
            composition_digest: Digest::from_text("pending-fallback-composition-digest"),
        };
        composition.validate_without_digest()?;
        let composition_digest = composition.canonical_digest();
        Ok(Self {
            composition_digest,
            ..composition
        })
    }

    fn canonical_digest(&self) -> Digest {
        digest_serialized(&(&self.schema, &self.primary, &self.alternate, &self.policy))
    }

    fn validate_without_digest(&self) -> Result<(), CapabilityDegradationError> {
        if self.schema != CAPABILITY_FALLBACK_COMPOSITION_SCHEMA
            || self.primary.invocation != self.alternate.invocation
            || self.primary.provider_digest == self.alternate.provider_digest
            || !self.alternate.is_active()
        {
            return Err(CapabilityDegradationError::InvalidComposition);
        }
        self.primary.validate()?;
        self.alternate.validate()?;
        self.policy.validate_for(&self.primary.invocation)?;
        if !self.policy.allows(&self.alternate.provider_digest) {
            return Err(CapabilityDegradationError::AlternateProviderNotAllowed);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CapabilityDegradationError> {
        self.validate_without_digest()?;
        if self.composition_digest != self.canonical_digest() {
            return Err(CapabilityDegradationError::StaleFallback);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.canonical_digest()
    }
}

impl fmt::Debug for CapabilityFallbackComposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFallbackComposition")
            .field("composition_digest", &self.composition_digest)
            .field("primary_binding_digest", &self.primary.digest())
            .field("alternate_binding_digest", &self.alternate.digest())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOutcomeDisposition {
    Unavailable,
    Revoked,
    QuotaExceeded,
    Succeeded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEffectState {
    NoEffect,
    Verified,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDegradationReason {
    Unavailable,
    Revoked,
    QuotaExceeded,
}

impl ProviderOutcomeDisposition {
    fn fallback_reason(self) -> Option<ProviderDegradationReason> {
        match self {
            Self::Unavailable => Some(ProviderDegradationReason::Unavailable),
            Self::Revoked => Some(ProviderDegradationReason::Revoked),
            Self::QuotaExceeded => Some(ProviderDegradationReason::QuotaExceeded),
            Self::Succeeded => None,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderOutcome {
    pub schema: String,
    pub binding_digest: Digest,
    pub provider_digest: Digest,
    pub provider_version: CapabilityVersion,
    pub invocation: DegradationInvocation,
    pub disposition: ProviderOutcomeDisposition,
    pub effect_state: ProviderEffectState,
    pub result_digest: Digest,
    pub effect_digest: Option<Digest>,
    pub effect_receipt_digest: Option<Digest>,
    pub reconciliation_digest: Option<Digest>,
    pub cost_used: CostLimit,
    pub observed_at: DateTime<Utc>,
}

impl ProviderOutcome {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: &CapabilityProviderBinding,
        disposition: ProviderOutcomeDisposition,
        effect_state: ProviderEffectState,
        result_digest: Digest,
        effect_digest: Option<Digest>,
        effect_receipt_digest: Option<Digest>,
        reconciliation_digest: Option<Digest>,
        cost_used: CostLimit,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityDegradationError> {
        let outcome = Self {
            schema: CAPABILITY_PROVIDER_OUTCOME_SCHEMA.into(),
            binding_digest: binding.digest(),
            provider_digest: binding.provider_digest.clone(),
            provider_version: binding.provider_version.clone(),
            invocation: binding.invocation.clone(),
            disposition,
            effect_state,
            result_digest,
            effect_digest,
            effect_receipt_digest,
            reconciliation_digest,
            cost_used,
            observed_at,
        };
        outcome.validate_against(binding)?;
        Ok(outcome)
    }

    pub fn unavailable(
        binding: &CapabilityProviderBinding,
        result_digest: Digest,
        cost_used: CostLimit,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityDegradationError> {
        Self::new(
            binding,
            ProviderOutcomeDisposition::Unavailable,
            ProviderEffectState::NoEffect,
            result_digest,
            None,
            None,
            None,
            cost_used,
            observed_at,
        )
    }

    pub fn revoked(
        binding: &CapabilityProviderBinding,
        result_digest: Digest,
        cost_used: CostLimit,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityDegradationError> {
        Self::new(
            binding,
            ProviderOutcomeDisposition::Revoked,
            ProviderEffectState::NoEffect,
            result_digest,
            None,
            None,
            None,
            cost_used,
            observed_at,
        )
    }

    pub fn quota_exceeded(
        binding: &CapabilityProviderBinding,
        result_digest: Digest,
        cost_used: CostLimit,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityDegradationError> {
        Self::new(
            binding,
            ProviderOutcomeDisposition::QuotaExceeded,
            ProviderEffectState::NoEffect,
            result_digest,
            None,
            None,
            None,
            cost_used,
            observed_at,
        )
    }

    pub fn validate_against(
        &self,
        binding: &CapabilityProviderBinding,
    ) -> Result<(), CapabilityDegradationError> {
        if self.schema != CAPABILITY_PROVIDER_OUTCOME_SCHEMA
            || self.binding_digest != binding.digest()
            || self.provider_digest != binding.provider_digest
            || self.provider_version != binding.provider_version
            || self.invocation != binding.invocation
            || !is_sha256(self.result_digest.as_str())
        {
            return Err(CapabilityDegradationError::ProviderOutcomeMismatch);
        }
        self.cost_used
            .validate()
            .map_err(|_| CapabilityDegradationError::InvalidProviderOutcome)?;
        if !self
            .cost_used
            .is_subset_of(&binding.invocation.cost_ceiling)
        {
            return Err(CapabilityDegradationError::CostExceeded);
        }
        match self.disposition {
            ProviderOutcomeDisposition::Revoked
                if binding.lifecycle != ProviderLifecycle::Revoked =>
            {
                return Err(CapabilityDegradationError::ProviderOutcomeMismatch);
            }
            ProviderOutcomeDisposition::Unavailable
            | ProviderOutcomeDisposition::QuotaExceeded
            | ProviderOutcomeDisposition::Succeeded
                if binding.lifecycle != ProviderLifecycle::Active =>
            {
                return Err(CapabilityDegradationError::ProviderOutcomeMismatch);
            }
            _ => {}
        }
        validate_effect_state(
            binding.invocation.class,
            self.effect_state,
            self.effect_digest.as_ref(),
            self.effect_receipt_digest.as_ref(),
            self.reconciliation_digest.as_ref(),
        )
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    #[must_use]
    pub fn fallback_reason(&self) -> Option<ProviderDegradationReason> {
        self.disposition.fallback_reason()
    }
}

impl fmt::Debug for ProviderOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOutcome")
            .field("outcome_digest", &self.digest())
            .field("binding_digest", &self.binding_digest)
            .field("provider_digest", &self.provider_digest)
            .field("provider_version", &self.provider_version)
            .field("invocation", &self.invocation)
            .field("disposition", &self.disposition)
            .field("effect_state", &self.effect_state)
            .field("result_digest", &self.result_digest)
            .field("effect_digest", &self.effect_digest)
            .field("effect_receipt_digest", &self.effect_receipt_digest)
            .field("reconciliation_digest", &self.reconciliation_digest)
            .field("cost_used", &self.cost_used)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackResultDisposition {
    Completed,
    Unavailable,
    Revoked,
    QuotaExceeded,
    UncertainExternalEffect,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFallbackResult {
    pub schema: String,
    pub decision_digest: Digest,
    pub binding_digest: Digest,
    pub provider_digest: Digest,
    pub provider_version: CapabilityVersion,
    pub invocation: DegradationInvocation,
    pub disposition: FallbackResultDisposition,
    pub effect_state: ProviderEffectState,
    pub result_digest: Digest,
    pub effect_digest: Option<Digest>,
    pub effect_receipt_digest: Option<Digest>,
    pub reconciliation_digest: Option<Digest>,
    pub cost_used: CostLimit,
    pub observed_at: DateTime<Utc>,
}

impl CapabilityFallbackResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        decision_digest: Digest,
        binding: &CapabilityProviderBinding,
        disposition: FallbackResultDisposition,
        effect_state: ProviderEffectState,
        result_digest: Digest,
        effect_digest: Option<Digest>,
        effect_receipt_digest: Option<Digest>,
        reconciliation_digest: Option<Digest>,
        cost_used: CostLimit,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityDegradationError> {
        let result = Self {
            schema: CAPABILITY_FALLBACK_RESULT_SCHEMA.into(),
            decision_digest,
            binding_digest: binding.digest(),
            provider_digest: binding.provider_digest.clone(),
            provider_version: binding.provider_version.clone(),
            invocation: binding.invocation.clone(),
            disposition,
            effect_state,
            result_digest,
            effect_digest,
            effect_receipt_digest,
            reconciliation_digest,
            cost_used,
            observed_at,
        };
        result.validate_against(binding).map(|()| result)
    }

    pub fn validate_against(
        &self,
        binding: &CapabilityProviderBinding,
    ) -> Result<(), CapabilityDegradationError> {
        if self.schema != CAPABILITY_FALLBACK_RESULT_SCHEMA
            || self.binding_digest != binding.digest()
            || self.provider_digest != binding.provider_digest
            || self.provider_version != binding.provider_version
            || self.invocation != binding.invocation
            || !is_sha256(self.decision_digest.as_str())
            || !is_sha256(self.result_digest.as_str())
        {
            return Err(CapabilityDegradationError::StaleFallback);
        }
        self.cost_used
            .validate()
            .map_err(|_| CapabilityDegradationError::InvalidFallbackResult)?;
        if !self
            .cost_used
            .is_subset_of(&binding.invocation.cost_ceiling)
        {
            return Err(CapabilityDegradationError::CostExceeded);
        }
        if !binding.is_active() {
            return Err(CapabilityDegradationError::AlternateProviderRevoked);
        }
        match self.disposition {
            FallbackResultDisposition::Completed => {
                if self.effect_state == ProviderEffectState::Uncertain {
                    return Err(CapabilityDegradationError::InvalidFallbackResult);
                }
            }
            FallbackResultDisposition::UncertainExternalEffect => {
                if self.effect_state != ProviderEffectState::Uncertain {
                    return Err(CapabilityDegradationError::InvalidFallbackResult);
                }
            }
            FallbackResultDisposition::Unavailable
            | FallbackResultDisposition::Revoked
            | FallbackResultDisposition::QuotaExceeded => {
                if self.effect_state != ProviderEffectState::NoEffect {
                    return Err(CapabilityDegradationError::InvalidFallbackResult);
                }
            }
        }
        validate_effect_state(
            binding.invocation.class,
            self.effect_state,
            self.effect_digest.as_ref(),
            self.effect_receipt_digest.as_ref(),
            self.reconciliation_digest.as_ref(),
        )
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

impl fmt::Debug for CapabilityFallbackResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFallbackResult")
            .field("envelope_digest", &self.digest())
            .field("decision_digest", &self.decision_digest)
            .field("binding_digest", &self.binding_digest)
            .field("provider_digest", &self.provider_digest)
            .field("provider_version", &self.provider_version)
            .field("invocation", &self.invocation)
            .field("disposition", &self.disposition)
            .field("effect_state", &self.effect_state)
            .field("result_digest", &self.result_digest)
            .field("effect_digest", &self.effect_digest)
            .field("effect_receipt_digest", &self.effect_receipt_digest)
            .field("reconciliation_digest", &self.reconciliation_digest)
            .field("cost_used", &self.cost_used)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFallbackDecision {
    pub schema: String,
    pub composition_digest: Digest,
    pub invocation_digest: Digest,
    pub idempotency_digest: Digest,
    pub authority_digest: Digest,
    pub policy_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub mission_generation: u64,
    pub mission_revision: u64,
    pub invocation_revision: u64,
    pub primary_binding_digest: Digest,
    pub alternate_binding_digest: Digest,
    pub provider_outcome_digest: Digest,
    pub reason: ProviderDegradationReason,
    pub fallback_attempt: u8,
    pub cost_ceiling: CostLimit,
    pub decision_digest: Digest,
}

impl CapabilityFallbackDecision {
    fn new(
        composition: &CapabilityFallbackComposition,
        outcome: &ProviderOutcome,
        reason: ProviderDegradationReason,
    ) -> Self {
        let invocation = &composition.primary.invocation;
        let decision = Self {
            schema: CAPABILITY_FALLBACK_DECISION_SCHEMA.into(),
            composition_digest: composition.digest(),
            invocation_digest: invocation.invocation_digest.clone(),
            idempotency_digest: invocation.idempotency_digest.clone(),
            authority_digest: invocation.authority_digest.clone(),
            policy_digest: invocation.policy_digest.clone(),
            project_digest: Digest::from_text(invocation.project.project_id.as_str()),
            mission_digest: Digest::from_text(invocation.mission.mission_id.as_str()),
            mission_generation: invocation.mission.generation,
            mission_revision: invocation.mission_revision,
            invocation_revision: invocation.invocation_revision,
            primary_binding_digest: composition.primary.digest(),
            alternate_binding_digest: composition.alternate.digest(),
            provider_outcome_digest: outcome.digest(),
            reason,
            fallback_attempt: 1,
            cost_ceiling: invocation.cost_ceiling.clone(),
            decision_digest: Digest::from_text("pending-fallback-decision-digest"),
        };
        let decision_digest = decision.canonical_digest();
        Self {
            decision_digest,
            ..decision
        }
    }

    fn canonical_digest(&self) -> Digest {
        digest_serialized(&(
            (
                &self.schema,
                &self.composition_digest,
                &self.invocation_digest,
                &self.idempotency_digest,
                &self.authority_digest,
                &self.policy_digest,
                &self.project_digest,
                &self.mission_digest,
                self.mission_generation,
                self.mission_revision,
                self.invocation_revision,
                &self.primary_binding_digest,
                &self.alternate_binding_digest,
                &self.provider_outcome_digest,
                self.reason,
                self.fallback_attempt,
            ),
            &self.cost_ceiling,
        ))
    }

    fn validate_against(
        &self,
        composition: &CapabilityFallbackComposition,
        outcome: &ProviderOutcome,
    ) -> Result<(), CapabilityDegradationError> {
        composition.validate()?;
        outcome.validate_against(&composition.primary)?;
        if self.schema != CAPABILITY_FALLBACK_DECISION_SCHEMA
            || self.decision_digest != self.canonical_digest()
            || self.composition_digest != composition.digest()
            || self.invocation_digest != composition.primary.invocation.invocation_digest
            || self.idempotency_digest != composition.primary.invocation.idempotency_digest
            || self.authority_digest != composition.primary.invocation.authority_digest
            || self.policy_digest != composition.primary.invocation.policy_digest
            || self.project_digest
                != Digest::from_text(composition.primary.invocation.project.project_id.as_str())
            || self.mission_digest
                != Digest::from_text(composition.primary.invocation.mission.mission_id.as_str())
            || self.mission_generation != composition.primary.invocation.mission.generation
            || self.mission_revision != composition.primary.invocation.mission_revision
            || self.invocation_revision != composition.primary.invocation.invocation_revision
            || self.primary_binding_digest != composition.primary.digest()
            || self.alternate_binding_digest != composition.alternate.digest()
            || self.provider_outcome_digest != outcome.digest()
            || self.fallback_attempt != MAX_FALLBACK_ATTEMPTS
            || self.cost_ceiling != composition.primary.invocation.cost_ceiling
            || outcome.fallback_reason() != Some(self.reason)
        {
            return Err(CapabilityDegradationError::StaleFallback);
        }
        Ok(())
    }
}

impl fmt::Debug for CapabilityFallbackDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFallbackDecision")
            .field("decision_digest", &self.decision_digest)
            .field("composition_digest", &self.composition_digest)
            .field("invocation_digest", &self.invocation_digest)
            .field("idempotency_digest", &self.idempotency_digest)
            .field("authority_digest", &self.authority_digest)
            .field("policy_digest", &self.policy_digest)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("mission_generation", &self.mission_generation)
            .field("mission_revision", &self.mission_revision)
            .field("invocation_revision", &self.invocation_revision)
            .field("primary_binding_digest", &self.primary_binding_digest)
            .field("alternate_binding_digest", &self.alternate_binding_digest)
            .field("provider_outcome_digest", &self.provider_outcome_digest)
            .field("reason", &self.reason)
            .field("fallback_attempt", &self.fallback_attempt)
            .field("cost_ceiling", &self.cost_ceiling)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackLeaseStatus {
    Active,
    Completed,
    Exhausted,
    UncertainExternalEffect,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFallbackLease {
    pub schema: String,
    pub composition: CapabilityFallbackComposition,
    pub primary_outcome: ProviderOutcome,
    pub decision: CapabilityFallbackDecision,
    pub status: FallbackLeaseStatus,
}

impl CapabilityFallbackLease {
    fn new(
        composition: CapabilityFallbackComposition,
        primary_outcome: ProviderOutcome,
        decision: CapabilityFallbackDecision,
    ) -> Self {
        Self {
            schema: CAPABILITY_FALLBACK_DECISION_SCHEMA.into(),
            composition,
            primary_outcome,
            decision,
            status: FallbackLeaseStatus::Active,
        }
    }

    pub fn validate(&self) -> Result<(), CapabilityDegradationError> {
        if self.schema != CAPABILITY_FALLBACK_DECISION_SCHEMA {
            return Err(CapabilityDegradationError::StaleFallback);
        }
        self.decision
            .validate_against(&self.composition, &self.primary_outcome)
    }

    #[must_use]
    pub fn decision_digest(&self) -> &Digest {
        &self.decision.decision_digest
    }
}

impl fmt::Debug for CapabilityFallbackLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFallbackLease")
            .field("decision_digest", &self.decision.decision_digest)
            .field("composition_digest", &self.composition.composition_digest)
            .field("primary_outcome_digest", &self.primary_outcome.digest())
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackDecisionLogEventKind {
    Selected,
    Completed,
    Exhausted,
    UncertainExternalEffect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackDecisionState {
    Selected,
    Completed,
    Exhausted,
    UncertainExternalEffect,
}

impl From<FallbackDecisionLogEventKind> for FallbackDecisionState {
    fn from(kind: FallbackDecisionLogEventKind) -> Self {
        match kind {
            FallbackDecisionLogEventKind::Selected => Self::Selected,
            FallbackDecisionLogEventKind::Completed => Self::Completed,
            FallbackDecisionLogEventKind::Exhausted => Self::Exhausted,
            FallbackDecisionLogEventKind::UncertainExternalEffect => Self::UncertainExternalEffect,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFallbackLogEntry {
    pub schema: String,
    pub event_digest: Digest,
    pub kind: FallbackDecisionLogEventKind,
    pub decision_digest: Digest,
    pub composition_digest: Digest,
    pub invocation_digest: Digest,
    pub idempotency_digest: Digest,
    pub tenant_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub mission_generation: u64,
    pub mission_revision: u64,
    pub invocation_revision: u64,
    pub authority_digest: Digest,
    pub policy_digest: Digest,
    pub primary_binding_digest: Digest,
    pub alternate_binding_digest: Digest,
    pub primary_provider_digest: Digest,
    pub alternate_provider_digest: Digest,
    pub provider_outcome_digest: Digest,
    pub reason: ProviderDegradationReason,
    pub cost_ceiling: CostLimit,
    pub primary_cost_used: CostLimit,
    pub alternate_cost_used: Option<CostLimit>,
    pub result_digest: Option<Digest>,
    pub effect_digest: Option<Digest>,
    pub effect_receipt_digest: Option<Digest>,
    pub reconciliation_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
}

impl CapabilityFallbackLogEntry {
    fn selected(
        decision: &CapabilityFallbackDecision,
        composition: &CapabilityFallbackComposition,
        outcome: &ProviderOutcome,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityDegradationError> {
        Self::new(
            decision,
            composition,
            outcome,
            FallbackDecisionLogEventKind::Selected,
            None,
            None,
            None,
            None,
            outcome.cost_used.clone(),
            None,
            observed_at,
        )
    }

    fn terminal(
        lease: &CapabilityFallbackLease,
        result: &CapabilityFallbackResult,
        kind: FallbackDecisionLogEventKind,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityDegradationError> {
        Self::new(
            &lease.decision,
            &lease.composition,
            &lease.primary_outcome,
            kind,
            Some(result.result_digest.clone()),
            result.effect_digest.clone(),
            result.effect_receipt_digest.clone(),
            result.reconciliation_digest.clone(),
            lease.primary_outcome.cost_used.clone(),
            Some(result.cost_used.clone()),
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        decision: &CapabilityFallbackDecision,
        composition: &CapabilityFallbackComposition,
        outcome: &ProviderOutcome,
        kind: FallbackDecisionLogEventKind,
        result_digest: Option<Digest>,
        effect_digest: Option<Digest>,
        effect_receipt_digest: Option<Digest>,
        reconciliation_digest: Option<Digest>,
        primary_cost_used: CostLimit,
        alternate_cost_used: Option<CostLimit>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityDegradationError> {
        let invocation = &composition.primary.invocation;
        let entry = Self {
            schema: CAPABILITY_FALLBACK_LOG_SCHEMA.into(),
            event_digest: Digest::from_text("pending-fallback-event-digest"),
            kind,
            decision_digest: decision.decision_digest.clone(),
            composition_digest: composition.digest(),
            invocation_digest: invocation.invocation_digest.clone(),
            idempotency_digest: invocation.idempotency_digest.clone(),
            tenant_digest: Digest::from_text(invocation.project.tenant_id.as_str()),
            project_digest: Digest::from_text(invocation.project.project_id.as_str()),
            mission_digest: Digest::from_text(invocation.mission.mission_id.as_str()),
            mission_generation: invocation.mission.generation,
            mission_revision: invocation.mission_revision,
            invocation_revision: invocation.invocation_revision,
            authority_digest: invocation.authority_digest.clone(),
            policy_digest: invocation.policy_digest.clone(),
            primary_binding_digest: composition.primary.digest(),
            alternate_binding_digest: composition.alternate.digest(),
            primary_provider_digest: composition.primary.provider_digest.clone(),
            alternate_provider_digest: composition.alternate.provider_digest.clone(),
            provider_outcome_digest: outcome.digest(),
            reason: decision.reason,
            cost_ceiling: invocation.cost_ceiling.clone(),
            primary_cost_used,
            alternate_cost_used,
            result_digest,
            effect_digest,
            effect_receipt_digest,
            reconciliation_digest,
            observed_at,
        };
        entry.validate_without_event_digest()?;
        let event_digest = entry.canonical_digest();
        Ok(Self {
            event_digest,
            ..entry
        })
    }

    fn canonical_digest(&self) -> Digest {
        digest_serialized(&(
            (
                &self.schema,
                self.kind,
                &self.decision_digest,
                &self.composition_digest,
                &self.invocation_digest,
                &self.idempotency_digest,
                &self.tenant_digest,
                &self.project_digest,
                &self.mission_digest,
                self.mission_generation,
                self.mission_revision,
                self.invocation_revision,
                &self.authority_digest,
                &self.policy_digest,
            ),
            (
                &self.primary_binding_digest,
                &self.alternate_binding_digest,
                &self.primary_provider_digest,
                &self.alternate_provider_digest,
                &self.provider_outcome_digest,
                self.reason,
                &self.cost_ceiling,
                &self.primary_cost_used,
                &self.alternate_cost_used,
                &self.result_digest,
                &self.effect_digest,
                &self.effect_receipt_digest,
                &self.reconciliation_digest,
                &self.observed_at,
            ),
        ))
    }

    fn validate_without_event_digest(&self) -> Result<(), CapabilityDegradationError> {
        if self.schema != CAPABILITY_FALLBACK_LOG_SCHEMA
            || !is_sha256(self.decision_digest.as_str())
            || !is_sha256(self.composition_digest.as_str())
            || !is_sha256(self.invocation_digest.as_str())
            || !is_sha256(self.idempotency_digest.as_str())
            || !is_sha256(self.tenant_digest.as_str())
            || !is_sha256(self.project_digest.as_str())
            || !is_sha256(self.mission_digest.as_str())
            || self.mission_generation == 0
            || self.mission_revision == 0
            || self.invocation_revision == 0
            || !is_sha256(self.authority_digest.as_str())
            || !is_sha256(self.policy_digest.as_str())
            || !is_sha256(self.primary_binding_digest.as_str())
            || !is_sha256(self.alternate_binding_digest.as_str())
            || !is_sha256(self.primary_provider_digest.as_str())
            || !is_sha256(self.alternate_provider_digest.as_str())
            || !is_sha256(self.provider_outcome_digest.as_str())
        {
            return Err(CapabilityDegradationError::InvalidLogEntry);
        }
        self.cost_ceiling
            .validate()
            .map_err(|_| CapabilityDegradationError::InvalidLogEntry)?;
        self.primary_cost_used
            .validate()
            .map_err(|_| CapabilityDegradationError::InvalidLogEntry)?;
        if let Some(cost) = &self.alternate_cost_used {
            cost.validate()
                .map_err(|_| CapabilityDegradationError::InvalidLogEntry)?;
        }
        match self.kind {
            FallbackDecisionLogEventKind::Selected
                if self.result_digest.is_some()
                    || self.alternate_cost_used.is_some()
                    || self.effect_digest.is_some()
                    || self.effect_receipt_digest.is_some()
                    || self.reconciliation_digest.is_some() =>
            {
                return Err(CapabilityDegradationError::InvalidLogEntry);
            }
            FallbackDecisionLogEventKind::Completed
            | FallbackDecisionLogEventKind::Exhausted
            | FallbackDecisionLogEventKind::UncertainExternalEffect
                if self.result_digest.is_none() || self.alternate_cost_used.is_none() =>
            {
                return Err(CapabilityDegradationError::InvalidLogEntry);
            }
            _ => {}
        }
        if self.kind == FallbackDecisionLogEventKind::UncertainExternalEffect
            && (self.effect_digest.is_none() || self.reconciliation_digest.is_none())
        {
            return Err(CapabilityDegradationError::InvalidLogEntry);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CapabilityDegradationError> {
        self.validate_without_event_digest()?;
        if self.event_digest != self.canonical_digest() {
            return Err(CapabilityDegradationError::InvalidLogEntry);
        }
        Ok(())
    }

    fn key(&self) -> FallbackInvocationKey {
        FallbackInvocationKey {
            tenant_digest: self.tenant_digest.clone(),
            project_digest: self.project_digest.clone(),
            mission_digest: self.mission_digest.clone(),
            generation: self.mission_generation,
            idempotency_digest: self.idempotency_digest.clone(),
        }
    }
}

impl fmt::Debug for CapabilityFallbackLogEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFallbackLogEntry")
            .field("event_digest", &self.event_digest)
            .field("kind", &self.kind)
            .field("decision_digest", &self.decision_digest)
            .field("composition_digest", &self.composition_digest)
            .field("invocation_digest", &self.invocation_digest)
            .field("idempotency_digest", &self.idempotency_digest)
            .field("tenant_digest", &self.tenant_digest)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("mission_generation", &self.mission_generation)
            .field("mission_revision", &self.mission_revision)
            .field("invocation_revision", &self.invocation_revision)
            .field("authority_digest", &self.authority_digest)
            .field("policy_digest", &self.policy_digest)
            .field("primary_binding_digest", &self.primary_binding_digest)
            .field("alternate_binding_digest", &self.alternate_binding_digest)
            .field("primary_provider_digest", &self.primary_provider_digest)
            .field("alternate_provider_digest", &self.alternate_provider_digest)
            .field("provider_outcome_digest", &self.provider_outcome_digest)
            .field("reason", &self.reason)
            .field("cost_ceiling", &self.cost_ceiling)
            .field("primary_cost_used", &self.primary_cost_used)
            .field("alternate_cost_used", &self.alternate_cost_used)
            .field("result_digest", &self.result_digest)
            .field("effect_digest", &self.effect_digest)
            .field("effect_receipt_digest", &self.effect_receipt_digest)
            .field("reconciliation_digest", &self.reconciliation_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityFallbackLogError {
    #[error("fallback log event is invalid")]
    InvalidEvent,
    #[error("fallback log transition is invalid")]
    InvalidTransition,
    #[error("fallback decision already exists")]
    Conflict,
    #[error("fallback log is unavailable")]
    Unavailable,
}

pub trait CapabilityFallbackLog {
    fn state_for(
        &self,
        key: &FallbackInvocationKey,
    ) -> Result<Option<FallbackDecisionState>, CapabilityFallbackLogError>;

    fn append(
        &mut self,
        entry: CapabilityFallbackLogEntry,
    ) -> Result<(), CapabilityFallbackLogError>;
}

#[derive(Clone, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryCapabilityFallbackLog {
    entries: Vec<CapabilityFallbackLogEntry>,
}

impl MemoryCapabilityFallbackLog {
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn events_for(&self, key: &FallbackInvocationKey) -> Vec<CapabilityFallbackLogEntry> {
        self.entries
            .iter()
            .filter(|entry| &entry.key() == key)
            .cloned()
            .collect()
    }
}

impl<'de> Deserialize<'de> for MemoryCapabilityFallbackLog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            entries: Vec<CapabilityFallbackLogEntry>,
        }
        let wire = Wire::deserialize(deserializer)?;
        for entry in &wire.entries {
            entry
                .validate()
                .map_err(|_| D::Error::custom("invalid fallback log entry"))?;
        }
        Ok(Self {
            entries: wire.entries,
        })
    }
}

impl CapabilityFallbackLog for MemoryCapabilityFallbackLog {
    fn state_for(
        &self,
        key: &FallbackInvocationKey,
    ) -> Result<Option<FallbackDecisionState>, CapabilityFallbackLogError> {
        Ok(self
            .entries
            .iter()
            .rev()
            .find(|entry| &entry.key() == key)
            .map(|entry| entry.kind.into()))
    }

    fn append(
        &mut self,
        entry: CapabilityFallbackLogEntry,
    ) -> Result<(), CapabilityFallbackLogError> {
        entry
            .validate()
            .map_err(|_| CapabilityFallbackLogError::InvalidEvent)?;
        let key = entry.key();
        let previous = self
            .entries
            .iter()
            .rev()
            .find(|existing| existing.key() == key);
        match previous {
            None if entry.kind != FallbackDecisionLogEventKind::Selected => {
                return Err(CapabilityFallbackLogError::InvalidTransition);
            }
            Some(previous) if entry.kind == FallbackDecisionLogEventKind::Selected => {
                if previous.decision_digest == entry.decision_digest {
                    return Err(CapabilityFallbackLogError::Conflict);
                }
                return Err(CapabilityFallbackLogError::Conflict);
            }
            Some(previous)
                if previous.decision_digest != entry.decision_digest
                    || previous.composition_digest != entry.composition_digest =>
            {
                return Err(CapabilityFallbackLogError::InvalidTransition);
            }
            Some(previous) if previous.kind != FallbackDecisionLogEventKind::Selected => {
                return Err(CapabilityFallbackLogError::InvalidTransition);
            }
            _ => {}
        }
        self.entries.push(entry);
        Ok(())
    }
}

impl fmt::Debug for MemoryCapabilityFallbackLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryCapabilityFallbackLog")
            .field(
                "invocation_count",
                &self
                    .entries
                    .iter()
                    .map(CapabilityFallbackLogEntry::key)
                    .collect::<BTreeSet<_>>()
                    .len(),
            )
            .field("event_count", &self.len())
            .field(
                "key_set_digest",
                &digest_serialized(
                    &self
                        .entries
                        .iter()
                        .map(CapabilityFallbackLogEntry::key)
                        .collect::<BTreeSet<_>>(),
                ),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReceiptStatus {
    Completed,
    Exhausted,
    UncertainExternalEffect,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFallbackReceipt {
    pub schema: String,
    pub decision_digest: Digest,
    pub event_digest: Digest,
    pub result_digest: Digest,
    pub status: FallbackReceiptStatus,
    pub effect_receipt_digest: Option<Digest>,
}

impl fmt::Debug for CapabilityFallbackReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFallbackReceipt")
            .field("schema", &self.schema)
            .field("decision_digest", &self.decision_digest)
            .field("event_digest", &self.event_digest)
            .field("result_digest", &self.result_digest)
            .field("status", &self.status)
            .field("effect_receipt_digest", &self.effect_receipt_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FallbackRecoveryDisposition {
    FallbackExhausted {
        result_digest: Digest,
    },
    UncertainExternalEffect {
        effect_digest: Digest,
        reconciliation_digest: Digest,
    },
}

#[derive(Clone, Error, Eq, PartialEq)]
pub enum CapabilityDegradationError {
    #[error("invalid capability version")]
    InvalidVersion,
    #[error("invalid degradation invocation")]
    InvalidInvocation,
    #[error("invalid provider binding")]
    InvalidProviderBinding,
    #[error("invalid fallback policy")]
    InvalidPolicy,
    #[error("fallback policy does not match the invocation")]
    PolicyMismatch,
    #[error("invalid fallback composition")]
    InvalidComposition,
    #[error("alternate provider is not allowed by policy")]
    AlternateProviderNotAllowed,
    #[error("alternate provider is revoked")]
    AlternateProviderRevoked,
    #[error("provider outcome does not match its binding")]
    ProviderOutcomeMismatch,
    #[error("invalid provider outcome")]
    InvalidProviderOutcome,
    #[error("the primary outcome is not a typed fallback trigger")]
    PrimaryOutcomeNotFallbackable,
    #[error("the provider effect state is unsafe for fallback")]
    PrimaryEffectUncertain,
    #[error("invalid fallback result")]
    InvalidFallbackResult,
    #[error("fallback is stale or tampered")]
    StaleFallback,
    #[error("fallback decision already exists for this invocation")]
    DuplicateFallback,
    #[error("fallback lease is already terminal")]
    LeaseClosed,
    #[error("fallback cost exceeds the invocation ceiling")]
    CostExceeded,
    #[error("no further provider fallback is permitted")]
    NoFurtherFallback,
    #[error("fallback log entry is invalid")]
    InvalidLogEntry,
    #[error("durable fallback log operation failed")]
    Log(CapabilityFallbackLogError),
    #[error("durable fallback log commit gap")]
    LogCommitGap,
    #[error("typed fallback recovery requires explicit handling")]
    Recovery(FallbackRecoveryDisposition),
}

impl fmt::Debug for CapabilityDegradationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovery(disposition) => formatter
                .debug_struct("CapabilityDegradationError")
                .field("code", &"recovery")
                .field("disposition", disposition)
                .finish(),
            Self::Log(error) => formatter
                .debug_struct("CapabilityDegradationError")
                .field("code", &"log")
                .field("reason", error)
                .finish(),
            other => formatter
                .debug_struct("CapabilityDegradationError")
                .field("code", &other.code())
                .finish(),
        }
    }
}

impl CapabilityDegradationError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidVersion => "invalid_version",
            Self::InvalidInvocation => "invalid_invocation",
            Self::InvalidProviderBinding => "invalid_provider_binding",
            Self::InvalidPolicy => "invalid_policy",
            Self::PolicyMismatch => "policy_mismatch",
            Self::InvalidComposition => "invalid_composition",
            Self::AlternateProviderNotAllowed => "alternate_provider_not_allowed",
            Self::AlternateProviderRevoked => "alternate_provider_revoked",
            Self::ProviderOutcomeMismatch => "provider_outcome_mismatch",
            Self::InvalidProviderOutcome => "invalid_provider_outcome",
            Self::PrimaryOutcomeNotFallbackable => "primary_outcome_not_fallbackable",
            Self::PrimaryEffectUncertain => "primary_effect_uncertain",
            Self::InvalidFallbackResult => "invalid_fallback_result",
            Self::StaleFallback => "stale_fallback",
            Self::DuplicateFallback => "duplicate_fallback",
            Self::LeaseClosed => "lease_closed",
            Self::CostExceeded => "cost_exceeded",
            Self::NoFurtherFallback => "no_further_fallback",
            Self::InvalidLogEntry => "invalid_log_entry",
            Self::Log(_) => "log",
            Self::LogCommitGap => "log_commit_gap",
            Self::Recovery(_) => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilityDegradationService;

impl CapabilityDegradationService {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn select_fallback<L>(
        &self,
        composition: &CapabilityFallbackComposition,
        primary_outcome: &ProviderOutcome,
        log: &mut L,
        observed_at: DateTime<Utc>,
    ) -> Result<CapabilityFallbackLease, CapabilityDegradationError>
    where
        L: CapabilityFallbackLog,
    {
        composition.validate()?;
        primary_outcome.validate_against(&composition.primary)?;
        let reason = primary_outcome
            .fallback_reason()
            .ok_or(CapabilityDegradationError::PrimaryOutcomeNotFallbackable)?;
        if primary_outcome.effect_state != ProviderEffectState::NoEffect {
            return Err(recovery_for_uncertain(primary_outcome));
        }
        if !primary_outcome
            .cost_used
            .is_subset_of(&composition.primary.invocation.cost_ceiling)
        {
            return Err(CapabilityDegradationError::CostExceeded);
        }
        let key = composition.primary.invocation.key();
        if log
            .state_for(&key)
            .map_err(CapabilityDegradationError::Log)?
            .is_some()
        {
            return Err(CapabilityDegradationError::DuplicateFallback);
        }
        let decision = CapabilityFallbackDecision::new(composition, primary_outcome, reason);
        let entry = CapabilityFallbackLogEntry::selected(
            &decision,
            composition,
            primary_outcome,
            observed_at,
        )?;
        log.append(entry).map_err(CapabilityDegradationError::Log)?;
        Ok(CapabilityFallbackLease::new(
            composition.clone(),
            primary_outcome.clone(),
            decision,
        ))
    }

    pub fn complete_fallback<L>(
        &self,
        lease: &mut CapabilityFallbackLease,
        result: &CapabilityFallbackResult,
        log: &mut L,
        observed_at: DateTime<Utc>,
    ) -> Result<CapabilityFallbackReceipt, CapabilityDegradationError>
    where
        L: CapabilityFallbackLog,
    {
        lease.validate()?;
        if lease.status != FallbackLeaseStatus::Active {
            return Err(CapabilityDegradationError::LeaseClosed);
        }
        result.validate_against(&lease.composition.alternate)?;
        if result.decision_digest != lease.decision.decision_digest {
            return Err(CapabilityDegradationError::StaleFallback);
        }
        add_cost(
            &lease.primary_outcome.cost_used,
            &result.cost_used,
            &lease.composition.primary.invocation.cost_ceiling,
        )?;

        let (status, kind, recovery) = match result.disposition {
            FallbackResultDisposition::Completed => {
                validate_completed_result(&lease.composition.primary.invocation, result)?;
                (
                    FallbackLeaseStatus::Completed,
                    FallbackDecisionLogEventKind::Completed,
                    None,
                )
            }
            FallbackResultDisposition::Unavailable
            | FallbackResultDisposition::Revoked
            | FallbackResultDisposition::QuotaExceeded => (
                FallbackLeaseStatus::Exhausted,
                FallbackDecisionLogEventKind::Exhausted,
                Some(FallbackRecoveryDisposition::FallbackExhausted {
                    result_digest: result.result_digest.clone(),
                }),
            ),
            FallbackResultDisposition::UncertainExternalEffect => {
                let effect_digest = result
                    .effect_digest
                    .clone()
                    .ok_or(CapabilityDegradationError::InvalidFallbackResult)?;
                let reconciliation_digest = result
                    .reconciliation_digest
                    .clone()
                    .ok_or(CapabilityDegradationError::InvalidFallbackResult)?;
                (
                    FallbackLeaseStatus::UncertainExternalEffect,
                    FallbackDecisionLogEventKind::UncertainExternalEffect,
                    Some(FallbackRecoveryDisposition::UncertainExternalEffect {
                        effect_digest,
                        reconciliation_digest,
                    }),
                )
            }
        };

        let entry = CapabilityFallbackLogEntry::terminal(lease, result, kind, observed_at)?;
        let event_digest = entry.event_digest.clone();
        lease.status = status;
        if log.append(entry).is_err() {
            return Err(CapabilityDegradationError::LogCommitGap);
        }
        let receipt = CapabilityFallbackReceipt {
            schema: CAPABILITY_FALLBACK_LOG_SCHEMA.into(),
            decision_digest: lease.decision.decision_digest.clone(),
            event_digest,
            result_digest: result.result_digest.clone(),
            status: match status {
                FallbackLeaseStatus::Completed => FallbackReceiptStatus::Completed,
                FallbackLeaseStatus::Exhausted => FallbackReceiptStatus::Exhausted,
                FallbackLeaseStatus::UncertainExternalEffect => {
                    FallbackReceiptStatus::UncertainExternalEffect
                }
                FallbackLeaseStatus::Active => unreachable!("terminal status is selected above"),
            },
            effect_receipt_digest: result.effect_receipt_digest.clone(),
        };
        if let Some(recovery) = recovery {
            return Err(CapabilityDegradationError::Recovery(recovery));
        }
        Ok(receipt)
    }
}

fn validate_version(value: &str) -> Result<(), CapabilityDegradationError> {
    let mut parts = value.split('.');
    let valid = [parts.next(), parts.next(), parts.next()]
        .into_iter()
        .all(|part| {
            part.is_some_and(|part| {
                !part.is_empty()
                    && (part == "0" || !part.starts_with('0'))
                    && part.bytes().all(|byte| byte.is_ascii_digit())
                    && part.parse::<u16>().is_ok()
            })
        })
        && parts.next().is_none();
    if valid {
        Ok(())
    } else {
        Err(CapabilityDegradationError::InvalidVersion)
    }
}

fn validate_effect_state(
    class: CapabilityClass,
    state: ProviderEffectState,
    effect_digest: Option<&Digest>,
    receipt_digest: Option<&Digest>,
    reconciliation_digest: Option<&Digest>,
) -> Result<(), CapabilityDegradationError> {
    if effect_digest.is_some_and(|digest| !is_sha256(digest.as_str()))
        || receipt_digest.is_some_and(|digest| !is_sha256(digest.as_str()))
        || reconciliation_digest.is_some_and(|digest| !is_sha256(digest.as_str()))
    {
        return Err(CapabilityDegradationError::InvalidProviderOutcome);
    }
    match state {
        ProviderEffectState::NoEffect => {
            if effect_digest.is_some()
                || receipt_digest.is_some()
                || reconciliation_digest.is_some()
            {
                return Err(CapabilityDegradationError::InvalidProviderOutcome);
            }
        }
        ProviderEffectState::Verified => {
            if effect_digest.is_none()
                || receipt_digest.is_none()
                || reconciliation_digest.is_some()
            {
                return Err(CapabilityDegradationError::InvalidProviderOutcome);
            }
            if class != CapabilityClass::ExternalEffect {
                return Err(CapabilityDegradationError::InvalidProviderOutcome);
            }
        }
        ProviderEffectState::Uncertain => {
            if effect_digest.is_none() || reconciliation_digest.is_none() {
                return Err(CapabilityDegradationError::InvalidProviderOutcome);
            }
        }
    }
    Ok(())
}

fn validate_completed_result(
    invocation: &DegradationInvocation,
    result: &CapabilityFallbackResult,
) -> Result<(), CapabilityDegradationError> {
    match invocation.class {
        CapabilityClass::ExternalEffect => {
            if result.effect_state != ProviderEffectState::Verified {
                return Err(CapabilityDegradationError::PrimaryEffectUncertain);
            }
        }
        CapabilityClass::Read | CapabilityClass::LocalMutation => {
            if result.effect_state != ProviderEffectState::NoEffect {
                return Err(CapabilityDegradationError::InvalidFallbackResult);
            }
        }
    }
    Ok(())
}

fn recovery_for_uncertain(outcome: &ProviderOutcome) -> CapabilityDegradationError {
    match (&outcome.effect_digest, &outcome.reconciliation_digest) {
        (Some(effect_digest), Some(reconciliation_digest)) => CapabilityDegradationError::Recovery(
            FallbackRecoveryDisposition::UncertainExternalEffect {
                effect_digest: effect_digest.clone(),
                reconciliation_digest: reconciliation_digest.clone(),
            },
        ),
        _ => CapabilityDegradationError::PrimaryEffectUncertain,
    }
}

fn add_cost(
    primary: &CostLimit,
    alternate: &CostLimit,
    ceiling: &CostLimit,
) -> Result<CostLimit, CapabilityDegradationError> {
    if primary.currency != alternate.currency || alternate.currency != ceiling.currency {
        return Err(CapabilityDegradationError::CostExceeded);
    }
    let amount_minor = primary
        .amount_minor
        .checked_add(alternate.amount_minor)
        .ok_or(CapabilityDegradationError::CostExceeded)?;
    let total = CostLimit {
        amount_minor,
        currency: ceiling.currency.clone(),
    };
    if !total.is_subset_of(ceiling) {
        return Err(CapabilityDegradationError::CostExceeded);
    }
    Ok(total)
}

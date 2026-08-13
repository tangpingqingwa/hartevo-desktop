//! Single-dispatch consumer for a selected capability fallback.
//!
//! The consumer is intentionally narrower than a runtime or Effect Broker. It
//! claims an already-selected [`CapabilityFallbackLease`], carries no
//! `EffectAuthority`, and gives a dispatcher only a typed, exact binding. A
//! durable `DispatchStarted` marker is committed before the dispatcher is
//! called, so a crash or reopen cannot cause an automatic second dispatch.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::Error as DeError};
use thiserror::Error;

use super::degradation::CapabilityVersion as DegradationCapabilityVersion;
use super::{
    CapabilityClass, CapabilityFallbackLease, CapabilityFallbackResult, CostLimit,
    DegradationInvocation, Digest, FallbackLeaseStatus, ProviderDegradationReason,
    ProviderEffectState, ProviderOutcome, digest_serialized, is_sha256,
};

pub const CAPABILITY_FALLBACK_INVOCATION_SCHEMA: &str = "hartevo.capability-fallback-invocation/v1";
pub const CAPABILITY_FALLBACK_INVOCATION_LOG_SCHEMA: &str =
    "hartevo.capability-fallback-invocation-log/v1";
pub const CAPABILITY_FALLBACK_RECEIPT_SCHEMA: &str = "hartevo.capability-fallback-receipt/v1";

/// A caller-provided, typed snapshot of the quota and budget state used when
/// the fallback was claimed. It is deliberately a digest, never a database
/// handle or a provider credential.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackInvocationSnapshot {
    pub schema: String,
    pub quota_digest: Digest,
    pub budget_revision: u64,
    pub selection_digest: Digest,
    pub composition_digest: Digest,
    pub policy_digest: Digest,
    pub cost_ceiling: CostLimit,
    pub prior_outcome_digest: Digest,
    pub alternate_binding_digest: Digest,
}

impl FallbackInvocationSnapshot {
    pub fn new(
        selection: &CapabilityFallbackLease,
        quota_digest: Digest,
        budget_revision: u64,
    ) -> Result<Self, CapabilityFallbackInvocationError> {
        selection
            .validate()
            .map_err(|_| CapabilityFallbackInvocationError::StaleSelection)?;
        if selection.status != FallbackLeaseStatus::Active {
            return Err(CapabilityFallbackInvocationError::SelectionNotActive);
        }
        let snapshot = Self {
            schema: CAPABILITY_FALLBACK_INVOCATION_SCHEMA.into(),
            quota_digest,
            budget_revision,
            selection_digest: selection.decision.decision_digest.clone(),
            composition_digest: selection.composition.digest(),
            policy_digest: selection
                .composition
                .primary
                .invocation
                .policy_digest
                .clone(),
            cost_ceiling: selection
                .composition
                .primary
                .invocation
                .cost_ceiling
                .clone(),
            prior_outcome_digest: selection.primary_outcome.digest(),
            alternate_binding_digest: selection.composition.alternate.digest(),
        };
        snapshot.validate_against(selection)?;
        Ok(snapshot)
    }

    pub fn validate_against(
        &self,
        selection: &CapabilityFallbackLease,
    ) -> Result<(), CapabilityFallbackInvocationError> {
        if selection.status != FallbackLeaseStatus::Active {
            return Err(CapabilityFallbackInvocationError::SelectionNotActive);
        }
        selection
            .validate()
            .map_err(|_| CapabilityFallbackInvocationError::StaleSelection)?;
        if self.schema != CAPABILITY_FALLBACK_INVOCATION_SCHEMA
            || !is_sha256(self.quota_digest.as_str())
            || self.budget_revision == 0
            || self.selection_digest != selection.decision.decision_digest
            || self.composition_digest != selection.composition.digest()
            || self.policy_digest != selection.composition.primary.invocation.policy_digest
            || self.cost_ceiling != selection.composition.primary.invocation.cost_ceiling
            || self.prior_outcome_digest != selection.primary_outcome.digest()
            || self.alternate_binding_digest != selection.composition.alternate.digest()
        {
            return Err(CapabilityFallbackInvocationError::StaleSelection);
        }
        Ok(())
    }
}

impl fmt::Debug for FallbackInvocationSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FallbackInvocationSnapshot")
            .field("schema", &self.schema)
            .field("quota_digest", &self.quota_digest)
            .field("budget_revision", &self.budget_revision)
            .field("selection_digest", &self.selection_digest)
            .field("composition_digest", &self.composition_digest)
            .field("policy_digest", &self.policy_digest)
            .field("cost_ceiling", &self.cost_ceiling)
            .field("prior_outcome_digest", &self.prior_outcome_digest)
            .field("alternate_binding_digest", &self.alternate_binding_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackInvocationClaimStatus {
    Active,
    Terminal,
}

/// A single durable claim for one selected fallback. The selection is kept
/// intact so the claim cannot be widened to a different provider or policy.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackInvocationClaim {
    pub schema: String,
    pub selection: CapabilityFallbackLease,
    pub snapshot: FallbackInvocationSnapshot,
    pub claim_digest: Digest,
    pub status: FallbackInvocationClaimStatus,
}

impl FallbackInvocationClaim {
    fn new(
        selection: CapabilityFallbackLease,
        snapshot: FallbackInvocationSnapshot,
    ) -> Result<Self, CapabilityFallbackInvocationError> {
        snapshot.validate_against(&selection)?;
        let claim = Self {
            schema: CAPABILITY_FALLBACK_INVOCATION_SCHEMA.into(),
            selection,
            snapshot,
            claim_digest: Digest::from_text("pending-fallback-claim-digest"),
            status: FallbackInvocationClaimStatus::Active,
        };
        let claim_digest = claim.canonical_digest();
        Ok(Self {
            claim_digest,
            ..claim
        })
    }

    fn canonical_digest(&self) -> Digest {
        digest_serialized(&(
            &self.schema,
            &self.selection.decision.decision_digest,
            &self.snapshot,
        ))
    }

    pub fn validate(&self) -> Result<(), CapabilityFallbackInvocationError> {
        if self.schema != CAPABILITY_FALLBACK_INVOCATION_SCHEMA
            || self.claim_digest != self.canonical_digest()
        {
            return Err(CapabilityFallbackInvocationError::StaleClaim);
        }
        self.snapshot.validate_against(&self.selection)
    }

    #[must_use]
    pub fn claim_digest(&self) -> &Digest {
        &self.claim_digest
    }

    fn request(&self) -> Result<FallbackInvocationRequest, CapabilityFallbackInvocationError> {
        let request = FallbackInvocationRequest {
            schema: CAPABILITY_FALLBACK_INVOCATION_SCHEMA.into(),
            claim_digest: self.claim_digest.clone(),
            selection_digest: self.selection.decision.decision_digest.clone(),
            composition_digest: self.selection.composition.digest(),
            fallback_attempt: self.selection.decision.fallback_attempt,
            invocation: self.selection.composition.primary.invocation.clone(),
            idempotency_digest: self
                .selection
                .composition
                .primary
                .invocation
                .idempotency_digest
                .clone(),
            primary_binding_digest: self.selection.composition.primary.digest(),
            alternate: self.selection.composition.alternate.clone(),
            primary_outcome: self.selection.primary_outcome.clone(),
            snapshot: self.snapshot.clone(),
        };
        request.validate_against(self)?;
        Ok(request)
    }
}

impl fmt::Debug for FallbackInvocationClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FallbackInvocationClaim")
            .field("claim_digest", &self.claim_digest)
            .field("selection_digest", &self.selection.decision.decision_digest)
            .field("composition_digest", &self.selection.composition.digest())
            .field("snapshot", &self.snapshot)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// The only value handed to a provider dispatcher. It contains exact typed
/// identity and prior outcome references, but no EffectAuthority and no raw
/// payload or host execution surface.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackInvocationRequest {
    pub schema: String,
    pub claim_digest: Digest,
    pub selection_digest: Digest,
    pub composition_digest: Digest,
    pub fallback_attempt: u8,
    pub invocation: DegradationInvocation,
    pub idempotency_digest: Digest,
    pub primary_binding_digest: Digest,
    pub alternate: super::CapabilityProviderBinding,
    pub primary_outcome: ProviderOutcome,
    pub snapshot: FallbackInvocationSnapshot,
}

impl FallbackInvocationRequest {
    fn validate_against(
        &self,
        claim: &FallbackInvocationClaim,
    ) -> Result<(), CapabilityFallbackInvocationError> {
        if self.schema != CAPABILITY_FALLBACK_INVOCATION_SCHEMA
            || self.claim_digest != claim.claim_digest
            || self.selection_digest != claim.selection.decision.decision_digest
            || self.composition_digest != claim.selection.composition.digest()
            || self.fallback_attempt != claim.selection.decision.fallback_attempt
            || self.invocation != claim.selection.composition.primary.invocation
            || self.idempotency_digest != self.invocation.idempotency_digest
            || self.primary_binding_digest != claim.selection.composition.primary.digest()
            || self.alternate != claim.selection.composition.alternate
            || self.primary_outcome != claim.selection.primary_outcome
            || self.snapshot != claim.snapshot
        {
            return Err(CapabilityFallbackInvocationError::StaleClaim);
        }
        if !self.alternate.is_active() {
            return Err(CapabilityFallbackInvocationError::AlternateProviderRevoked);
        }
        Ok(())
    }
}

impl fmt::Debug for FallbackInvocationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FallbackInvocationRequest")
            .field("claim_digest", &self.claim_digest)
            .field("selection_digest", &self.selection_digest)
            .field("composition_digest", &self.composition_digest)
            .field("fallback_attempt", &self.fallback_attempt)
            .field("invocation", &self.invocation)
            .field("idempotency_digest", &self.idempotency_digest)
            .field("primary_binding_digest", &self.primary_binding_digest)
            .field("alternate", &self.alternate)
            .field("primary_outcome", &self.primary_outcome)
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

/// A trusted host/plugin adapter implements this typed hook. The gateway
/// consumer itself never invokes a process, database, browser, or Effect
/// Broker and never supplies an EffectAuthority.
pub trait FallbackInvocationDispatcher {
    fn dispatch(
        &mut self,
        request: &FallbackInvocationRequest,
    ) -> Result<CapabilityFallbackResult, FallbackDispatchError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FallbackDispatchError {
    Unavailable {
        failure_digest: Digest,
    },
    Revoked {
        failure_digest: Digest,
    },
    QuotaExceeded {
        failure_digest: Digest,
    },
    Rejected {
        failure_digest: Digest,
    },
    UncertainExternalEffect {
        effect_digest: Digest,
        reconciliation_digest: Digest,
    },
}

impl FallbackDispatchError {
    fn validate(&self) -> Result<(), CapabilityFallbackInvocationError> {
        match self {
            Self::Unavailable { failure_digest }
            | Self::Revoked { failure_digest }
            | Self::QuotaExceeded { failure_digest }
            | Self::Rejected { failure_digest }
                if !is_sha256(failure_digest.as_str()) =>
            {
                Err(CapabilityFallbackInvocationError::InvalidDispatchError)
            }
            Self::UncertainExternalEffect {
                effect_digest,
                reconciliation_digest,
            } if !is_sha256(effect_digest.as_str())
                || !is_sha256(reconciliation_digest.as_str()) =>
            {
                Err(CapabilityFallbackInvocationError::InvalidDispatchError)
            }
            _ => Ok(()),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackInvocationEventKind {
    Claimed,
    DispatchStarted,
    Completed,
    Failed,
    UncertainExternalEffect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackInvocationState {
    Claimed,
    DispatchStarted,
    Completed,
    Failed,
    UncertainExternalEffect,
}

impl From<FallbackInvocationEventKind> for FallbackInvocationState {
    fn from(kind: FallbackInvocationEventKind) -> Self {
        match kind {
            FallbackInvocationEventKind::Claimed => Self::Claimed,
            FallbackInvocationEventKind::DispatchStarted => Self::DispatchStarted,
            FallbackInvocationEventKind::Completed => Self::Completed,
            FallbackInvocationEventKind::Failed => Self::Failed,
            FallbackInvocationEventKind::UncertainExternalEffect => Self::UncertainExternalEffect,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackInvocationLogEntry {
    pub schema: String,
    pub event_digest: Digest,
    pub kind: FallbackInvocationEventKind,
    pub claim_digest: Digest,
    pub selection_digest: Digest,
    pub composition_digest: Digest,
    pub fallback_attempt: u8,
    pub invocation_digest: Digest,
    pub tenant_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub scope_digest: Digest,
    pub idempotency_digest: Digest,
    pub capability_digest: Digest,
    pub capability_version: DegradationCapabilityVersion,
    pub service_digest: Digest,
    pub service_version: DegradationCapabilityVersion,
    pub authority_digest: Digest,
    pub policy_digest: Digest,
    pub primary_binding_digest: Digest,
    pub primary_provider_digest: Digest,
    pub primary_provider_version: DegradationCapabilityVersion,
    pub alternate_binding_digest: Digest,
    pub alternate_provider_digest: Digest,
    pub alternate_provider_version: DegradationCapabilityVersion,
    pub mission_generation: u64,
    pub mission_revision: u64,
    pub invocation_revision: u64,
    pub cost_ceiling: CostLimit,
    pub quota_digest: Digest,
    pub budget_revision: u64,
    pub prior_outcome_digest: Digest,
    pub prior_result_digest: Digest,
    pub prior_reason: ProviderDegradationReason,
    pub result_digest: Option<Digest>,
    pub result_envelope_digest: Option<Digest>,
    pub failure_digest: Option<Digest>,
    pub effect_digest: Option<Digest>,
    pub effect_receipt_digest: Option<Digest>,
    pub reconciliation_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
}

impl FallbackInvocationLogEntry {
    #[allow(clippy::too_many_arguments)]
    fn new(
        claim: &FallbackInvocationClaim,
        kind: FallbackInvocationEventKind,
        result: Option<&CapabilityFallbackResult>,
        failure_digest: Option<Digest>,
        effect_digest: Option<Digest>,
        effect_receipt_digest: Option<Digest>,
        reconciliation_digest: Option<Digest>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, CapabilityFallbackInvocationError> {
        let selection = &claim.selection;
        let invocation = &selection.composition.primary.invocation;
        let entry = Self {
            schema: CAPABILITY_FALLBACK_INVOCATION_LOG_SCHEMA.into(),
            event_digest: Digest::from_text("pending-fallback-invocation-event-digest"),
            kind,
            claim_digest: claim.claim_digest.clone(),
            selection_digest: selection.decision.decision_digest.clone(),
            composition_digest: selection.composition.digest(),
            fallback_attempt: selection.decision.fallback_attempt,
            invocation_digest: invocation.invocation_digest.clone(),
            tenant_digest: Digest::from_text(invocation.project.tenant_id.as_str()),
            project_digest: Digest::from_text(invocation.project.project_id.as_str()),
            mission_digest: Digest::from_text(invocation.mission.mission_id.as_str()),
            scope_digest: invocation.mission.scope_digest.clone(),
            idempotency_digest: invocation.idempotency_digest.clone(),
            capability_digest: invocation.capability_digest.clone(),
            capability_version: invocation.capability_version.clone(),
            service_digest: invocation.service_digest.clone(),
            service_version: invocation.service_version.clone(),
            authority_digest: invocation.authority_digest.clone(),
            policy_digest: invocation.policy_digest.clone(),
            primary_binding_digest: selection.composition.primary.digest(),
            primary_provider_digest: selection.composition.primary.provider_digest.clone(),
            primary_provider_version: selection.composition.primary.provider_version.clone(),
            alternate_binding_digest: selection.composition.alternate.digest(),
            alternate_provider_digest: selection.composition.alternate.provider_digest.clone(),
            alternate_provider_version: selection.composition.alternate.provider_version.clone(),
            mission_generation: invocation.mission.generation,
            mission_revision: invocation.mission_revision,
            invocation_revision: invocation.invocation_revision,
            cost_ceiling: invocation.cost_ceiling.clone(),
            quota_digest: claim.snapshot.quota_digest.clone(),
            budget_revision: claim.snapshot.budget_revision,
            prior_outcome_digest: selection.primary_outcome.digest(),
            prior_result_digest: selection.primary_outcome.result_digest.clone(),
            prior_reason: selection.decision.reason,
            result_digest: result.map(|value| value.result_digest.clone()),
            result_envelope_digest: result.map(CapabilityFallbackResult::digest),
            failure_digest,
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
                &self.claim_digest,
                &self.selection_digest,
                &self.composition_digest,
                self.fallback_attempt,
                &self.invocation_digest,
                &self.tenant_digest,
                &self.project_digest,
            ),
            (
                &self.mission_digest,
                &self.scope_digest,
                &self.idempotency_digest,
                &self.capability_digest,
                &self.capability_version,
                &self.service_digest,
                &self.service_version,
                &self.authority_digest,
                &self.policy_digest,
            ),
            (
                &self.primary_binding_digest,
                &self.primary_provider_digest,
                &self.primary_provider_version,
            ),
            (
                &self.alternate_binding_digest,
                &self.alternate_provider_digest,
                &self.alternate_provider_version,
                self.mission_generation,
                self.mission_revision,
                self.invocation_revision,
                &self.cost_ceiling,
                &self.quota_digest,
                self.budget_revision,
                &self.prior_outcome_digest,
                &self.prior_result_digest,
                self.prior_reason,
                &self.result_digest,
                &self.result_envelope_digest,
                &self.failure_digest,
                &self.effect_digest,
            ),
            (
                &self.effect_receipt_digest,
                &self.reconciliation_digest,
                &self.observed_at,
            ),
        ))
    }

    fn validate_without_event_digest(&self) -> Result<(), CapabilityFallbackInvocationError> {
        if self.schema != CAPABILITY_FALLBACK_INVOCATION_LOG_SCHEMA
            || !is_sha256(self.claim_digest.as_str())
            || !is_sha256(self.selection_digest.as_str())
            || !is_sha256(self.composition_digest.as_str())
            || self.fallback_attempt != super::MAX_FALLBACK_ATTEMPTS
            || !is_sha256(self.invocation_digest.as_str())
            || !is_sha256(self.tenant_digest.as_str())
            || !is_sha256(self.project_digest.as_str())
            || !is_sha256(self.mission_digest.as_str())
            || !is_sha256(self.scope_digest.as_str())
            || !is_sha256(self.idempotency_digest.as_str())
            || !is_sha256(self.capability_digest.as_str())
            || !is_sha256(self.service_digest.as_str())
            || !is_sha256(self.authority_digest.as_str())
            || !is_sha256(self.policy_digest.as_str())
            || !is_sha256(self.primary_binding_digest.as_str())
            || !is_sha256(self.primary_provider_digest.as_str())
            || !is_sha256(self.alternate_binding_digest.as_str())
            || !is_sha256(self.alternate_provider_digest.as_str())
            || self.mission_generation == 0
            || self.mission_revision == 0
            || self.invocation_revision == 0
            || !is_sha256(self.quota_digest.as_str())
            || self.budget_revision == 0
            || !is_sha256(self.prior_outcome_digest.as_str())
            || !is_sha256(self.prior_result_digest.as_str())
        {
            return Err(CapabilityFallbackInvocationError::InvalidLogEntry);
        }
        DegradationCapabilityVersion::parse(self.capability_version.as_str().to_owned())
            .map_err(|_| CapabilityFallbackInvocationError::InvalidLogEntry)?;
        DegradationCapabilityVersion::parse(self.service_version.as_str().to_owned())
            .map_err(|_| CapabilityFallbackInvocationError::InvalidLogEntry)?;
        DegradationCapabilityVersion::parse(self.primary_provider_version.as_str().to_owned())
            .map_err(|_| CapabilityFallbackInvocationError::InvalidLogEntry)?;
        DegradationCapabilityVersion::parse(self.alternate_provider_version.as_str().to_owned())
            .map_err(|_| CapabilityFallbackInvocationError::InvalidLogEntry)?;
        self.cost_ceiling
            .validate()
            .map_err(|_| CapabilityFallbackInvocationError::InvalidLogEntry)?;
        for digest in [
            self.result_digest.as_ref(),
            self.result_envelope_digest.as_ref(),
            self.failure_digest.as_ref(),
            self.effect_digest.as_ref(),
            self.effect_receipt_digest.as_ref(),
            self.reconciliation_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !is_sha256(digest.as_str()) {
                return Err(CapabilityFallbackInvocationError::InvalidLogEntry);
            }
        }
        match self.kind {
            FallbackInvocationEventKind::Claimed | FallbackInvocationEventKind::DispatchStarted
                if self.result_digest.is_some()
                    || self.result_envelope_digest.is_some()
                    || self.failure_digest.is_some()
                    || self.effect_digest.is_some()
                    || self.effect_receipt_digest.is_some()
                    || self.reconciliation_digest.is_some() =>
            {
                return Err(CapabilityFallbackInvocationError::InvalidLogEntry);
            }
            FallbackInvocationEventKind::Completed
                if self.result_digest.is_none()
                    || self.result_envelope_digest.is_none()
                    || self.failure_digest.is_some() =>
            {
                return Err(CapabilityFallbackInvocationError::InvalidLogEntry);
            }
            FallbackInvocationEventKind::Failed
                if self.result_digest.is_none() && self.failure_digest.is_none() =>
            {
                return Err(CapabilityFallbackInvocationError::InvalidLogEntry);
            }
            FallbackInvocationEventKind::UncertainExternalEffect
                if (self.result_digest.is_none() && self.failure_digest.is_none())
                    || self.effect_digest.is_none()
                    || self.reconciliation_digest.is_none() =>
            {
                return Err(CapabilityFallbackInvocationError::InvalidLogEntry);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CapabilityFallbackInvocationError> {
        self.validate_without_event_digest()?;
        if self.event_digest != self.canonical_digest() {
            return Err(CapabilityFallbackInvocationError::InvalidLogEntry);
        }
        Ok(())
    }
}

impl fmt::Debug for FallbackInvocationLogEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FallbackInvocationLogEntry")
            .field("event_digest", &self.event_digest)
            .field("kind", &self.kind)
            .field("claim_digest", &self.claim_digest)
            .field("selection_digest", &self.selection_digest)
            .field("composition_digest", &self.composition_digest)
            .field("fallback_attempt", &self.fallback_attempt)
            .field("invocation_digest", &self.invocation_digest)
            .field("tenant_digest", &self.tenant_digest)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("idempotency_digest", &self.idempotency_digest)
            .field("capability_digest", &self.capability_digest)
            .field("capability_version", &self.capability_version)
            .field("service_digest", &self.service_digest)
            .field("service_version", &self.service_version)
            .field("authority_digest", &self.authority_digest)
            .field("policy_digest", &self.policy_digest)
            .field("primary_binding_digest", &self.primary_binding_digest)
            .field("primary_provider_digest", &self.primary_provider_digest)
            .field("primary_provider_version", &self.primary_provider_version)
            .field("alternate_binding_digest", &self.alternate_binding_digest)
            .field("alternate_provider_digest", &self.alternate_provider_digest)
            .field(
                "alternate_provider_version",
                &self.alternate_provider_version,
            )
            .field("mission_generation", &self.mission_generation)
            .field("mission_revision", &self.mission_revision)
            .field("invocation_revision", &self.invocation_revision)
            .field("cost_ceiling", &self.cost_ceiling)
            .field("quota_digest", &self.quota_digest)
            .field("budget_revision", &self.budget_revision)
            .field("prior_outcome_digest", &self.prior_outcome_digest)
            .field("prior_result_digest", &self.prior_result_digest)
            .field("prior_reason", &self.prior_reason)
            .field("result_digest", &self.result_digest)
            .field("result_envelope_digest", &self.result_envelope_digest)
            .field("failure_digest", &self.failure_digest)
            .field("effect_digest", &self.effect_digest)
            .field("effect_receipt_digest", &self.effect_receipt_digest)
            .field("reconciliation_digest", &self.reconciliation_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FallbackInvocationLedgerError {
    #[error("fallback invocation log entry is invalid")]
    InvalidEvent,
    #[error("fallback invocation log transition is invalid")]
    InvalidTransition,
    #[error("fallback invocation claim already exists")]
    Conflict,
    #[error("fallback invocation ledger is unavailable")]
    Unavailable,
}

pub trait FallbackInvocationLedger {
    fn state_for(
        &self,
        selection_digest: &Digest,
    ) -> Result<Option<FallbackInvocationState>, FallbackInvocationLedgerError>;

    fn append(
        &mut self,
        entry: FallbackInvocationLogEntry,
    ) -> Result<(), FallbackInvocationLedgerError>;
}

#[derive(Clone, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryFallbackInvocationLedger {
    entries: Vec<FallbackInvocationLogEntry>,
}

impl MemoryFallbackInvocationLedger {
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn events_for(&self, selection_digest: &Digest) -> Vec<FallbackInvocationLogEntry> {
        self.entries
            .iter()
            .filter(|entry| &entry.selection_digest == selection_digest)
            .cloned()
            .collect()
    }
}

impl<'de> Deserialize<'de> for MemoryFallbackInvocationLedger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            entries: Vec<FallbackInvocationLogEntry>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let mut ledger = Self::default();
        for entry in wire.entries {
            ledger
                .append(entry)
                .map_err(|_| D::Error::custom("invalid fallback invocation ledger"))?;
        }
        Ok(ledger)
    }
}

impl FallbackInvocationLedger for MemoryFallbackInvocationLedger {
    fn state_for(
        &self,
        selection_digest: &Digest,
    ) -> Result<Option<FallbackInvocationState>, FallbackInvocationLedgerError> {
        Ok(self
            .entries
            .iter()
            .rev()
            .find(|entry| &entry.selection_digest == selection_digest)
            .map(|entry| entry.kind.into()))
    }

    fn append(
        &mut self,
        entry: FallbackInvocationLogEntry,
    ) -> Result<(), FallbackInvocationLedgerError> {
        entry
            .validate()
            .map_err(|_| FallbackInvocationLedgerError::InvalidEvent)?;
        let previous = self
            .entries
            .iter()
            .rev()
            .find(|existing| existing.selection_digest == entry.selection_digest);
        match previous {
            None if entry.kind != FallbackInvocationEventKind::Claimed => {
                return Err(FallbackInvocationLedgerError::InvalidTransition);
            }
            Some(previous)
                if previous.claim_digest != entry.claim_digest
                    || previous.composition_digest != entry.composition_digest =>
            {
                return Err(FallbackInvocationLedgerError::InvalidTransition);
            }
            Some(previous)
                if previous.kind == FallbackInvocationEventKind::Claimed
                    && matches!(
                        entry.kind,
                        FallbackInvocationEventKind::DispatchStarted
                            | FallbackInvocationEventKind::Failed
                    ) => {}
            Some(previous)
                if previous.kind == FallbackInvocationEventKind::DispatchStarted
                    && matches!(
                        entry.kind,
                        FallbackInvocationEventKind::Completed
                            | FallbackInvocationEventKind::Failed
                            | FallbackInvocationEventKind::UncertainExternalEffect
                    ) => {}
            Some(_) => return Err(FallbackInvocationLedgerError::Conflict),
            _ => {}
        }
        self.entries.push(entry);
        Ok(())
    }
}

impl fmt::Debug for MemoryFallbackInvocationLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryFallbackInvocationLedger")
            .field("event_count", &self.entries.len())
            .field(
                "selection_set_digest",
                &digest_serialized(
                    &self
                        .entries
                        .iter()
                        .map(|entry| &entry.selection_digest)
                        .collect::<Vec<_>>(),
                ),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackInvocationReceiptStatus {
    Completed,
    Failed,
    UncertainExternalEffect,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFallbackInvocationReceipt {
    pub schema: String,
    pub status: FallbackInvocationReceiptStatus,
    pub claim_digest: Digest,
    pub selection_digest: Digest,
    pub event_digest: Digest,
    pub composition_digest: Digest,
    pub fallback_attempt: u8,
    pub invocation_digest: Digest,
    pub tenant_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub scope_digest: Digest,
    pub idempotency_digest: Digest,
    pub capability_digest: Digest,
    pub capability_version: DegradationCapabilityVersion,
    pub service_digest: Digest,
    pub service_version: DegradationCapabilityVersion,
    pub class: CapabilityClass,
    pub authority_digest: Digest,
    pub policy_digest: Digest,
    pub primary_binding_digest: Digest,
    pub primary_provider_digest: Digest,
    pub primary_provider_version: DegradationCapabilityVersion,
    pub alternate_binding_digest: Digest,
    pub alternate_provider_digest: Digest,
    pub alternate_provider_version: DegradationCapabilityVersion,
    pub mission_generation: u64,
    pub mission_revision: u64,
    pub invocation_revision: u64,
    pub cost_ceiling: CostLimit,
    pub quota_digest: Digest,
    pub budget_revision: u64,
    pub prior_outcome_digest: Digest,
    pub prior_result_digest: Digest,
    pub prior_reason: ProviderDegradationReason,
    pub result_digest: Digest,
    pub result_envelope_digest: Option<Digest>,
    pub effect_receipt_digest: Option<Digest>,
}

impl fmt::Debug for CapabilityFallbackInvocationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFallbackInvocationReceipt")
            .field("schema", &self.schema)
            .field("status", &self.status)
            .field("claim_digest", &self.claim_digest)
            .field("selection_digest", &self.selection_digest)
            .field("event_digest", &self.event_digest)
            .field("composition_digest", &self.composition_digest)
            .field("fallback_attempt", &self.fallback_attempt)
            .field("invocation_digest", &self.invocation_digest)
            .field("tenant_digest", &self.tenant_digest)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("idempotency_digest", &self.idempotency_digest)
            .field("capability_digest", &self.capability_digest)
            .field("capability_version", &self.capability_version)
            .field("service_digest", &self.service_digest)
            .field("service_version", &self.service_version)
            .field("class", &self.class)
            .field("authority_digest", &self.authority_digest)
            .field("policy_digest", &self.policy_digest)
            .field("primary_binding_digest", &self.primary_binding_digest)
            .field("primary_provider_digest", &self.primary_provider_digest)
            .field("primary_provider_version", &self.primary_provider_version)
            .field("alternate_binding_digest", &self.alternate_binding_digest)
            .field("alternate_provider_digest", &self.alternate_provider_digest)
            .field(
                "alternate_provider_version",
                &self.alternate_provider_version,
            )
            .field("mission_generation", &self.mission_generation)
            .field("mission_revision", &self.mission_revision)
            .field("invocation_revision", &self.invocation_revision)
            .field("cost_ceiling", &self.cost_ceiling)
            .field("quota_digest", &self.quota_digest)
            .field("budget_revision", &self.budget_revision)
            .field("prior_outcome_digest", &self.prior_outcome_digest)
            .field("prior_result_digest", &self.prior_result_digest)
            .field("prior_reason", &self.prior_reason)
            .field("result_digest", &self.result_digest)
            .field("result_envelope_digest", &self.result_envelope_digest)
            .field("effect_receipt_digest", &self.effect_receipt_digest)
            .finish_non_exhaustive()
    }
}

impl CapabilityFallbackInvocationReceipt {
    pub fn validate(&self) -> Result<(), CapabilityFallbackInvocationError> {
        if self.schema != CAPABILITY_FALLBACK_RECEIPT_SCHEMA
            || !is_sha256(self.claim_digest.as_str())
            || !is_sha256(self.selection_digest.as_str())
            || !is_sha256(self.event_digest.as_str())
            || !is_sha256(self.composition_digest.as_str())
            || self.fallback_attempt != super::MAX_FALLBACK_ATTEMPTS
            || !is_sha256(self.invocation_digest.as_str())
            || !is_sha256(self.tenant_digest.as_str())
            || !is_sha256(self.project_digest.as_str())
            || !is_sha256(self.mission_digest.as_str())
            || !is_sha256(self.scope_digest.as_str())
            || !is_sha256(self.idempotency_digest.as_str())
            || !is_sha256(self.capability_digest.as_str())
            || !is_sha256(self.service_digest.as_str())
            || !is_sha256(self.authority_digest.as_str())
            || !is_sha256(self.policy_digest.as_str())
            || !is_sha256(self.primary_binding_digest.as_str())
            || !is_sha256(self.primary_provider_digest.as_str())
            || !is_sha256(self.alternate_binding_digest.as_str())
            || !is_sha256(self.alternate_provider_digest.as_str())
            || self.mission_generation == 0
            || self.mission_revision == 0
            || self.invocation_revision == 0
            || !is_sha256(self.quota_digest.as_str())
            || self.budget_revision == 0
            || !is_sha256(self.prior_outcome_digest.as_str())
            || !is_sha256(self.prior_result_digest.as_str())
            || !is_sha256(self.result_digest.as_str())
            || self
                .result_envelope_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest.as_str()))
            || self
                .effect_receipt_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest.as_str()))
        {
            return Err(CapabilityFallbackInvocationError::InvalidReceipt);
        }
        DegradationCapabilityVersion::parse(self.capability_version.as_str().to_owned())
            .map_err(|_| CapabilityFallbackInvocationError::InvalidReceipt)?;
        DegradationCapabilityVersion::parse(self.service_version.as_str().to_owned())
            .map_err(|_| CapabilityFallbackInvocationError::InvalidReceipt)?;
        DegradationCapabilityVersion::parse(self.primary_provider_version.as_str().to_owned())
            .map_err(|_| CapabilityFallbackInvocationError::InvalidReceipt)?;
        DegradationCapabilityVersion::parse(self.alternate_provider_version.as_str().to_owned())
            .map_err(|_| CapabilityFallbackInvocationError::InvalidReceipt)?;
        self.cost_ceiling
            .validate()
            .map_err(|_| CapabilityFallbackInvocationError::InvalidReceipt)?;
        if self.status == FallbackInvocationReceiptStatus::Completed
            && self.result_envelope_digest.is_none()
        {
            return Err(CapabilityFallbackInvocationError::InvalidReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FallbackInvocationRecoveryDisposition {
    NoFurtherFallback {
        result_digest: Digest,
    },
    UncertainExternalEffect {
        effect_digest: Digest,
        reconciliation_digest: Digest,
    },
}

#[derive(Clone, Error, Eq, PartialEq)]
pub enum CapabilityFallbackInvocationError {
    #[error("fallback selection is not active")]
    SelectionNotActive,
    #[error("fallback selection or claim is stale")]
    StaleSelection,
    #[error("fallback claim is stale")]
    StaleClaim,
    #[error("fallback invocation snapshot is invalid")]
    InvalidSnapshot,
    #[error("fallback policy revision changed")]
    StalePolicy,
    #[error("fallback quota or budget revision changed")]
    QuotaDrift,
    #[error("fallback cost ceiling changed or was exceeded")]
    CostDrift,
    #[error("the original provider recovered before fallback dispatch")]
    RecoveredPrimaryProvider,
    #[error("the alternate provider was revoked")]
    AlternateProviderRevoked,
    #[error("fallback claim already exists")]
    DuplicateClaim,
    #[error("fallback invocation claim is terminal")]
    ClaimClosed,
    #[error("fallback dispatch was already started or completed")]
    DuplicateDispatch,
    #[error("fallback invocation request is invalid")]
    InvalidRequest,
    #[error("fallback provider result is invalid")]
    InvalidResult,
    #[error("fallback dispatch error is invalid")]
    InvalidDispatchError,
    #[error("fallback dispatcher failed")]
    DispatchFailed,
    #[error("fallback result did not carry a verified effect receipt")]
    EffectNotVerified,
    #[error("fallback invocation receipt is invalid")]
    InvalidReceipt,
    #[error("fallback durable log entry is invalid")]
    InvalidLogEntry,
    #[error("fallback invocation ledger operation failed")]
    Ledger(FallbackInvocationLedgerError),
    #[error("fallback invocation log commit gap")]
    LogCommitGap,
    #[error("typed fallback invocation recovery requires explicit handling")]
    Recovery(FallbackInvocationRecoveryDisposition),
}

impl fmt::Debug for CapabilityFallbackInvocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ledger(error) => formatter
                .debug_struct("CapabilityFallbackInvocationError")
                .field("code", &"ledger")
                .field("reason", error)
                .finish(),
            Self::Recovery(disposition) => formatter
                .debug_struct("CapabilityFallbackInvocationError")
                .field("code", &"recovery")
                .field("disposition", disposition)
                .finish(),
            other => formatter
                .debug_struct("CapabilityFallbackInvocationError")
                .field("code", &other.code())
                .finish(),
        }
    }
}

impl CapabilityFallbackInvocationError {
    fn code(&self) -> &'static str {
        match self {
            Self::SelectionNotActive => "selection_not_active",
            Self::StaleSelection => "stale_selection",
            Self::StaleClaim => "stale_claim",
            Self::InvalidSnapshot => "invalid_snapshot",
            Self::StalePolicy => "stale_policy",
            Self::QuotaDrift => "quota_drift",
            Self::CostDrift => "cost_drift",
            Self::RecoveredPrimaryProvider => "recovered_primary_provider",
            Self::AlternateProviderRevoked => "alternate_provider_revoked",
            Self::DuplicateClaim => "duplicate_claim",
            Self::ClaimClosed => "claim_closed",
            Self::DuplicateDispatch => "duplicate_dispatch",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidResult => "invalid_result",
            Self::InvalidDispatchError => "invalid_dispatch_error",
            Self::DispatchFailed => "dispatch_failed",
            Self::EffectNotVerified => "effect_not_verified",
            Self::InvalidReceipt => "invalid_receipt",
            Self::InvalidLogEntry => "invalid_log_entry",
            Self::Ledger(_) => "ledger",
            Self::LogCommitGap => "log_commit_gap",
            Self::Recovery(_) => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilityFallbackInvocationConsumer;

impl CapabilityFallbackInvocationConsumer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn claim<L>(
        &self,
        selection: &CapabilityFallbackLease,
        snapshot: &FallbackInvocationSnapshot,
        ledger: &mut L,
        observed_at: DateTime<Utc>,
    ) -> Result<FallbackInvocationClaim, CapabilityFallbackInvocationError>
    where
        L: FallbackInvocationLedger,
    {
        if selection.status != FallbackLeaseStatus::Active {
            return Err(CapabilityFallbackInvocationError::SelectionNotActive);
        }
        selection
            .validate()
            .map_err(|_| CapabilityFallbackInvocationError::StaleSelection)?;
        snapshot.validate_against(selection)?;
        if ledger
            .state_for(&selection.decision.decision_digest)
            .map_err(CapabilityFallbackInvocationError::Ledger)?
            .is_some()
        {
            return Err(CapabilityFallbackInvocationError::DuplicateClaim);
        }
        let claim = FallbackInvocationClaim::new(selection.clone(), snapshot.clone())?;
        let entry = FallbackInvocationLogEntry::new(
            &claim,
            FallbackInvocationEventKind::Claimed,
            None,
            None,
            None,
            None,
            None,
            observed_at,
        )?;
        ledger
            .append(entry)
            .map_err(CapabilityFallbackInvocationError::Ledger)?;
        Ok(claim)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn dispatch_once<D, L>(
        &self,
        claim: &mut FallbackInvocationClaim,
        current_primary: &ProviderOutcome,
        current_alternate: &super::CapabilityProviderBinding,
        current_snapshot: &FallbackInvocationSnapshot,
        dispatcher: &mut D,
        ledger: &mut L,
        observed_at: DateTime<Utc>,
    ) -> Result<CapabilityFallbackInvocationReceipt, CapabilityFallbackInvocationError>
    where
        D: FallbackInvocationDispatcher,
        L: FallbackInvocationLedger,
    {
        claim.validate()?;
        if claim.status != FallbackInvocationClaimStatus::Active {
            return Err(CapabilityFallbackInvocationError::ClaimClosed);
        }
        match ledger
            .state_for(&claim.selection.decision.decision_digest)
            .map_err(CapabilityFallbackInvocationError::Ledger)?
        {
            Some(FallbackInvocationState::Claimed) => {}
            Some(
                FallbackInvocationState::DispatchStarted
                | FallbackInvocationState::Completed
                | FallbackInvocationState::Failed
                | FallbackInvocationState::UncertainExternalEffect,
            ) => return Err(CapabilityFallbackInvocationError::DuplicateDispatch),
            None => return Err(CapabilityFallbackInvocationError::StaleClaim),
        }

        if current_snapshot.policy_digest != claim.snapshot.policy_digest {
            return Self::fail_before_dispatch(
                claim,
                ledger,
                CapabilityFallbackInvocationError::StalePolicy,
                "fallback-policy-drift",
                observed_at,
            );
        }
        if current_snapshot.quota_digest != claim.snapshot.quota_digest
            || current_snapshot.budget_revision != claim.snapshot.budget_revision
        {
            return Self::fail_before_dispatch(
                claim,
                ledger,
                CapabilityFallbackInvocationError::QuotaDrift,
                "fallback-quota-drift",
                observed_at,
            );
        }
        if current_snapshot.cost_ceiling != claim.snapshot.cost_ceiling {
            return Self::fail_before_dispatch(
                claim,
                ledger,
                CapabilityFallbackInvocationError::CostDrift,
                "fallback-cost-drift",
                observed_at,
            );
        }
        if current_snapshot.validate_against(&claim.selection).is_err() {
            return Self::fail_before_dispatch(
                claim,
                ledger,
                CapabilityFallbackInvocationError::StaleSelection,
                "fallback-selection-drift",
                observed_at,
            );
        }
        if current_primary != &claim.selection.primary_outcome {
            let error =
                if current_primary.disposition == super::ProviderOutcomeDisposition::Succeeded {
                    CapabilityFallbackInvocationError::RecoveredPrimaryProvider
                } else {
                    CapabilityFallbackInvocationError::StaleSelection
                };
            return Self::fail_before_dispatch(
                claim,
                ledger,
                error,
                "fallback-primary-outcome-drift",
                observed_at,
            );
        }
        if !current_alternate.is_active() {
            return Self::fail_before_dispatch(
                claim,
                ledger,
                CapabilityFallbackInvocationError::AlternateProviderRevoked,
                "fallback-alternate-revoked",
                observed_at,
            );
        }
        if current_alternate != &claim.selection.composition.alternate {
            return Self::fail_before_dispatch(
                claim,
                ledger,
                CapabilityFallbackInvocationError::StaleSelection,
                "fallback-alternate-drift",
                observed_at,
            );
        }

        let request = claim.request()?;
        let started = FallbackInvocationLogEntry::new(
            claim,
            FallbackInvocationEventKind::DispatchStarted,
            None,
            None,
            None,
            None,
            None,
            observed_at,
        )?;
        ledger
            .append(started)
            .map_err(CapabilityFallbackInvocationError::Ledger)?;

        match dispatcher.dispatch(&request) {
            Ok(result) => Self::finish_result(claim, &result, ledger, observed_at),
            Err(error) => Self::finish_dispatch_error(claim, error, ledger, observed_at),
        }
    }

    fn fail_before_dispatch<L>(
        claim: &mut FallbackInvocationClaim,
        ledger: &mut L,
        error: CapabilityFallbackInvocationError,
        failure_label: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<CapabilityFallbackInvocationReceipt, CapabilityFallbackInvocationError>
    where
        L: FallbackInvocationLedger,
    {
        let failure_digest = Digest::from_text(failure_label);
        let entry = FallbackInvocationLogEntry::new(
            claim,
            FallbackInvocationEventKind::Failed,
            None,
            Some(failure_digest.clone()),
            None,
            None,
            None,
            observed_at,
        )?;
        claim.status = FallbackInvocationClaimStatus::Terminal;
        if ledger.append(entry).is_err() {
            return Err(CapabilityFallbackInvocationError::LogCommitGap);
        }
        Err(error)
    }

    #[allow(clippy::too_many_lines)]
    fn finish_result<L>(
        claim: &mut FallbackInvocationClaim,
        result: &CapabilityFallbackResult,
        ledger: &mut L,
        observed_at: DateTime<Utc>,
    ) -> Result<CapabilityFallbackInvocationReceipt, CapabilityFallbackInvocationError>
    where
        L: FallbackInvocationLedger,
    {
        if result
            .validate_against(&claim.selection.composition.alternate)
            .is_err()
            || result.decision_digest != claim.selection.decision.decision_digest
        {
            let failure_digest = Digest::from_text("invalid-fallback-provider-result");
            let receipt = Self::finish_terminal(
                claim,
                ledger,
                FallbackInvocationEventKind::Failed,
                None,
                Some(failure_digest.clone()),
                None,
                None,
                observed_at,
            )?;
            let _ = receipt;
            return Err(CapabilityFallbackInvocationError::InvalidResult);
        }

        match result.disposition {
            super::FallbackResultDisposition::Completed => {
                if let Err(error) = validate_completed_result(
                    &claim.selection.composition.primary.invocation,
                    result,
                ) {
                    let failure_digest = Digest::from_text("unverified-fallback-effect");
                    let receipt = Self::finish_terminal(
                        claim,
                        ledger,
                        FallbackInvocationEventKind::Failed,
                        Some(result),
                        Some(failure_digest),
                        None,
                        None,
                        observed_at,
                    )?;
                    let _ = receipt;
                    return Err(error);
                }
                if add_cost(
                    &claim.selection.primary_outcome.cost_used,
                    &result.cost_used,
                    &claim.selection.composition.primary.invocation.cost_ceiling,
                )
                .is_err()
                {
                    let failure_digest = Digest::from_text("fallback-cost-drift");
                    let receipt = Self::finish_terminal(
                        claim,
                        ledger,
                        FallbackInvocationEventKind::Failed,
                        Some(result),
                        Some(failure_digest),
                        None,
                        None,
                        observed_at,
                    )?;
                    let _ = receipt;
                    return Err(CapabilityFallbackInvocationError::CostDrift);
                }
                Self::finish_terminal(
                    claim,
                    ledger,
                    FallbackInvocationEventKind::Completed,
                    Some(result),
                    None,
                    result.effect_digest.clone(),
                    result.effect_receipt_digest.clone(),
                    observed_at,
                )
            }
            super::FallbackResultDisposition::UncertainExternalEffect => {
                let effect_digest = result
                    .effect_digest
                    .clone()
                    .ok_or(CapabilityFallbackInvocationError::InvalidResult)?;
                let reconciliation_digest = result
                    .reconciliation_digest
                    .clone()
                    .ok_or(CapabilityFallbackInvocationError::InvalidResult)?;
                let receipt = Self::finish_terminal(
                    claim,
                    ledger,
                    FallbackInvocationEventKind::UncertainExternalEffect,
                    Some(result),
                    None,
                    Some(effect_digest.clone()),
                    Some(reconciliation_digest.clone()),
                    observed_at,
                )?;
                let _ = receipt;
                Err(CapabilityFallbackInvocationError::Recovery(
                    FallbackInvocationRecoveryDisposition::UncertainExternalEffect {
                        effect_digest,
                        reconciliation_digest,
                    },
                ))
            }
            super::FallbackResultDisposition::Unavailable
            | super::FallbackResultDisposition::Revoked
            | super::FallbackResultDisposition::QuotaExceeded => {
                let result_digest = result.result_digest.clone();
                let receipt = Self::finish_terminal(
                    claim,
                    ledger,
                    FallbackInvocationEventKind::Failed,
                    Some(result),
                    None,
                    None,
                    None,
                    observed_at,
                )?;
                let _ = receipt;
                Err(CapabilityFallbackInvocationError::Recovery(
                    FallbackInvocationRecoveryDisposition::NoFurtherFallback { result_digest },
                ))
            }
        }
    }

    fn finish_dispatch_error<L>(
        claim: &mut FallbackInvocationClaim,
        error: FallbackDispatchError,
        ledger: &mut L,
        observed_at: DateTime<Utc>,
    ) -> Result<CapabilityFallbackInvocationReceipt, CapabilityFallbackInvocationError>
    where
        L: FallbackInvocationLedger,
    {
        error.validate()?;
        let failure_digest = error.digest();
        match error {
            FallbackDispatchError::UncertainExternalEffect {
                effect_digest,
                reconciliation_digest,
            } => {
                let receipt = Self::finish_terminal(
                    claim,
                    ledger,
                    FallbackInvocationEventKind::UncertainExternalEffect,
                    None,
                    Some(failure_digest),
                    Some(effect_digest.clone()),
                    Some(reconciliation_digest.clone()),
                    observed_at,
                )?;
                let _ = receipt;
                Err(CapabilityFallbackInvocationError::Recovery(
                    FallbackInvocationRecoveryDisposition::UncertainExternalEffect {
                        effect_digest,
                        reconciliation_digest,
                    },
                ))
            }
            FallbackDispatchError::Unavailable { .. }
            | FallbackDispatchError::Revoked { .. }
            | FallbackDispatchError::QuotaExceeded { .. }
            | FallbackDispatchError::Rejected { .. } => {
                let receipt = Self::finish_terminal(
                    claim,
                    ledger,
                    FallbackInvocationEventKind::Failed,
                    None,
                    Some(failure_digest),
                    None,
                    None,
                    observed_at,
                )?;
                let _ = receipt;
                Err(CapabilityFallbackInvocationError::DispatchFailed)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_terminal<L>(
        claim: &mut FallbackInvocationClaim,
        ledger: &mut L,
        kind: FallbackInvocationEventKind,
        result: Option<&CapabilityFallbackResult>,
        failure_digest: Option<Digest>,
        effect_digest: Option<Digest>,
        reconciliation_digest: Option<Digest>,
        observed_at: DateTime<Utc>,
    ) -> Result<CapabilityFallbackInvocationReceipt, CapabilityFallbackInvocationError>
    where
        L: FallbackInvocationLedger,
    {
        let effect_receipt_digest = result.and_then(|value| value.effect_receipt_digest.clone());
        let entry = FallbackInvocationLogEntry::new(
            claim,
            kind,
            result,
            failure_digest.clone(),
            effect_digest,
            effect_receipt_digest.clone(),
            reconciliation_digest,
            observed_at,
        )?;
        let event_digest = entry.event_digest.clone();
        claim.status = FallbackInvocationClaimStatus::Terminal;
        if ledger.append(entry).is_err() {
            return Err(CapabilityFallbackInvocationError::LogCommitGap);
        }
        let result_digest = result
            .map(|value| value.result_digest.clone())
            .or(failure_digest)
            .ok_or(CapabilityFallbackInvocationError::InvalidLogEntry)?;
        let status = match kind {
            FallbackInvocationEventKind::Completed => FallbackInvocationReceiptStatus::Completed,
            FallbackInvocationEventKind::UncertainExternalEffect => {
                FallbackInvocationReceiptStatus::UncertainExternalEffect
            }
            FallbackInvocationEventKind::Failed => FallbackInvocationReceiptStatus::Failed,
            FallbackInvocationEventKind::Claimed | FallbackInvocationEventKind::DispatchStarted => {
                return Err(CapabilityFallbackInvocationError::InvalidLogEntry);
            }
        };
        Ok(Self::receipt(
            claim,
            status,
            event_digest,
            result_digest,
            result.map(CapabilityFallbackResult::digest),
            effect_receipt_digest,
        ))
    }

    #[allow(clippy::too_many_lines)]
    fn receipt(
        claim: &FallbackInvocationClaim,
        status: FallbackInvocationReceiptStatus,
        event_digest: Digest,
        result_digest: Digest,
        result_envelope_digest: Option<Digest>,
        effect_receipt_digest: Option<Digest>,
    ) -> CapabilityFallbackInvocationReceipt {
        CapabilityFallbackInvocationReceipt {
            schema: CAPABILITY_FALLBACK_RECEIPT_SCHEMA.into(),
            status,
            claim_digest: claim.claim_digest.clone(),
            selection_digest: claim.selection.decision.decision_digest.clone(),
            event_digest,
            composition_digest: claim.selection.composition.digest(),
            fallback_attempt: claim.selection.decision.fallback_attempt,
            invocation_digest: claim
                .selection
                .composition
                .primary
                .invocation
                .invocation_digest
                .clone(),
            tenant_digest: Digest::from_text(
                claim
                    .selection
                    .composition
                    .primary
                    .invocation
                    .project
                    .tenant_id
                    .as_str(),
            ),
            project_digest: Digest::from_text(
                claim
                    .selection
                    .composition
                    .primary
                    .invocation
                    .project
                    .project_id
                    .as_str(),
            ),
            mission_digest: Digest::from_text(
                claim
                    .selection
                    .composition
                    .primary
                    .invocation
                    .mission
                    .mission_id
                    .as_str(),
            ),
            scope_digest: claim
                .selection
                .composition
                .primary
                .invocation
                .mission
                .scope_digest
                .clone(),
            idempotency_digest: claim
                .selection
                .composition
                .primary
                .invocation
                .idempotency_digest
                .clone(),
            capability_digest: claim
                .selection
                .composition
                .primary
                .invocation
                .capability_digest
                .clone(),
            capability_version: claim
                .selection
                .composition
                .primary
                .invocation
                .capability_version
                .clone(),
            service_digest: claim
                .selection
                .composition
                .primary
                .invocation
                .service_digest
                .clone(),
            service_version: claim
                .selection
                .composition
                .primary
                .invocation
                .service_version
                .clone(),
            class: claim.selection.composition.primary.invocation.class,
            authority_digest: claim
                .selection
                .composition
                .primary
                .invocation
                .authority_digest
                .clone(),
            policy_digest: claim
                .selection
                .composition
                .primary
                .invocation
                .policy_digest
                .clone(),
            primary_binding_digest: claim.selection.composition.primary.digest(),
            primary_provider_digest: claim.selection.composition.primary.provider_digest.clone(),
            primary_provider_version: claim.selection.composition.primary.provider_version.clone(),
            alternate_binding_digest: claim.selection.composition.alternate.digest(),
            alternate_provider_digest: claim
                .selection
                .composition
                .alternate
                .provider_digest
                .clone(),
            alternate_provider_version: claim
                .selection
                .composition
                .alternate
                .provider_version
                .clone(),
            mission_generation: claim
                .selection
                .composition
                .primary
                .invocation
                .mission
                .generation,
            mission_revision: claim
                .selection
                .composition
                .primary
                .invocation
                .mission_revision,
            invocation_revision: claim
                .selection
                .composition
                .primary
                .invocation
                .invocation_revision,
            cost_ceiling: claim
                .selection
                .composition
                .primary
                .invocation
                .cost_ceiling
                .clone(),
            quota_digest: claim.snapshot.quota_digest.clone(),
            budget_revision: claim.snapshot.budget_revision,
            prior_outcome_digest: claim.selection.primary_outcome.digest(),
            prior_result_digest: claim.selection.primary_outcome.result_digest.clone(),
            prior_reason: claim.selection.decision.reason,
            result_digest,
            result_envelope_digest,
            effect_receipt_digest,
        }
    }
}

fn validate_completed_result(
    invocation: &DegradationInvocation,
    result: &CapabilityFallbackResult,
) -> Result<(), CapabilityFallbackInvocationError> {
    match invocation.class {
        CapabilityClass::ExternalEffect => {
            if result.effect_state != ProviderEffectState::Verified {
                return Err(CapabilityFallbackInvocationError::EffectNotVerified);
            }
        }
        CapabilityClass::Read | CapabilityClass::LocalMutation => {
            if result.effect_state != ProviderEffectState::NoEffect {
                return Err(CapabilityFallbackInvocationError::InvalidResult);
            }
        }
    }
    Ok(())
}

fn add_cost(
    primary: &CostLimit,
    alternate: &CostLimit,
    ceiling: &CostLimit,
) -> Result<CostLimit, CapabilityFallbackInvocationError> {
    if primary.currency != alternate.currency || alternate.currency != ceiling.currency {
        return Err(CapabilityFallbackInvocationError::CostDrift);
    }
    let amount_minor = primary
        .amount_minor
        .checked_add(alternate.amount_minor)
        .ok_or(CapabilityFallbackInvocationError::CostDrift)?;
    let total = CostLimit {
        amount_minor,
        currency: ceiling.currency.clone(),
    };
    if !total.is_subset_of(ceiling) {
        return Err(CapabilityFallbackInvocationError::CostDrift);
    }
    Ok(total)
}

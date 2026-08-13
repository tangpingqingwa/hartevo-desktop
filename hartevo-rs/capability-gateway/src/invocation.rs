//! Single-use invocation consumption for a resolved capability binding.
//!
//! This layer consumes the read-only resolution contract without introducing
//! a second provider registry or an execution surface. Every lifecycle change
//! is durably logged before the in-memory lease changes state; model-visible
//! invocations therefore always carry a content-free log reference.

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{MissionId, ProjectId};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use super::{
    CapabilityBinding, CapabilityClass, CapabilityCompositionSnapshot, CapabilityGateway,
    CapabilityReleaseReceipt, CapabilityRequest, CapabilityResolutionAuditLedger,
    CapabilityResolutionError, CapabilityResolutionLease, CapabilityResolutionReceipt,
    CapabilityResolutionSelector, CapabilityResult, Digest, EffectDisposition,
    ExternalEffectResult, GatewayError, InvocationPermit, ResultPayload, SignedCapabilityManifest,
    digest_serialized,
};
use super::{CapabilityResolver, is_sha256};

pub const CAPABILITY_INVOCATION_SCHEMA: &str = "hartevo.capability-invocation/v1";
pub const CAPABILITY_INVOCATION_RECEIPT_SCHEMA: &str = "hartevo.capability-invocation-receipt/v1";
pub const CAPABILITY_INVOCATION_LOG_SCHEMA: &str = "hartevo.capability-invocation-log/v1";
pub const MAX_INVOCATION_ATTEMPTS: u32 = 8;

/// The resolution lease is the immutable, already-authorized binding consumed
/// by invocation. This alias names the product boundary without duplicating
/// the service/provider/consumer registry or its receipt type.
pub type ResolvedCapabilityBinding = CapabilityResolutionLease;

/// Whether an invocation can become visible to the model. Both variants are
/// logged, while the model-visible variant exposes its durable reference on
/// the lease and every terminal receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityInvocationVisibility {
    ModelVisible,
    Internal,
}

/// The caller's immutable expectation for one invocation attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityInvocationContext {
    project_id: ProjectId,
    mission_id: MissionId,
    generation: u64,
    composition_revision: u64,
    provider_generation: u64,
    policy_digest: Digest,
    visibility: CapabilityInvocationVisibility,
}

impl CapabilityInvocationContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        generation: u64,
        composition_revision: u64,
        provider_generation: u64,
        policy_digest: Digest,
        visibility: CapabilityInvocationVisibility,
    ) -> Result<Self, CapabilityInvocationError> {
        let context = Self {
            project_id,
            mission_id,
            generation,
            composition_revision,
            provider_generation,
            policy_digest,
            visibility,
        };
        context.validate_storage()?;
        Ok(context)
    }

    pub fn from_binding(
        binding: &CapabilityBinding,
        visibility: CapabilityInvocationVisibility,
    ) -> Result<Self, CapabilityInvocationError> {
        Self::new(
            binding.scope().project_id.clone(),
            binding.scope().mission_id.clone(),
            binding.scope().generation,
            binding.composition_revision(),
            binding.provider_generation(),
            binding.policy_digest().clone(),
            visibility,
        )
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn composition_revision(&self) -> u64 {
        self.composition_revision
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub const fn visibility(&self) -> CapabilityInvocationVisibility {
        self.visibility
    }

    fn validate_storage(&self) -> Result<(), CapabilityInvocationError> {
        if self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.generation == 0
            || self.composition_revision == 0
            || self.provider_generation == 0
            || !is_sha256(self.policy_digest.as_str())
        {
            return Err(CapabilityInvocationError::InvalidContext);
        }
        Ok(())
    }

    fn validate_against(
        &self,
        binding: &CapabilityBinding,
    ) -> Result<(), CapabilityInvocationError> {
        self.validate_storage()?;
        if self.project_id != binding.scope().project_id
            || self.mission_id != binding.scope().mission_id
        {
            return Err(CapabilityInvocationError::MissionMismatch);
        }
        if self.generation != binding.scope().generation {
            return Err(CapabilityInvocationError::GenerationMismatch);
        }
        if self.composition_revision != binding.composition_revision() {
            return Err(CapabilityInvocationError::RevisionMismatch);
        }
        if self.provider_generation != binding.scope().generation {
            return Err(CapabilityInvocationError::ProviderGenerationMismatch);
        }
        if self.policy_digest != *binding.policy_digest() {
            return Err(CapabilityInvocationError::PolicyDrift);
        }
        Ok(())
    }
}

impl Serialize for CapabilityInvocationContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityInvocationContext", 7)?;
        state.serialize_field(
            "projectDigest",
            &Digest::from_text(self.project_id.as_str()),
        )?;
        state.serialize_field(
            "missionDigest",
            &Digest::from_text(self.mission_id.as_str()),
        )?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("compositionRevision", &self.composition_revision)?;
        state.serialize_field("providerGeneration", &self.provider_generation)?;
        state.serialize_field("policyDigest", &self.policy_digest)?;
        state.serialize_field("visibility", &self.visibility)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityInvocationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityInvocationContext")
            .field(
                "project_digest",
                &Digest::from_text(self.project_id.as_str()),
            )
            .field(
                "mission_digest",
                &Digest::from_text(self.mission_id.as_str()),
            )
            .field("generation", &self.generation)
            .field("composition_revision", &self.composition_revision)
            .field("provider_generation", &self.provider_generation)
            .field("policy_digest", &self.policy_digest)
            .field("visibility", &self.visibility)
            .finish()
    }
}

/// A digest-only effect receipt bound to a verified ExternalEffect result.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityInvocationEffectReceipt {
    effect: Digest,
    receipt: Digest,
    verification: Digest,
}

impl CapabilityInvocationEffectReceipt {
    pub fn verified(
        effect_digest: Digest,
        receipt_digest: Digest,
        verification_digest: Digest,
    ) -> Result<Self, CapabilityInvocationError> {
        let receipt = Self {
            effect: effect_digest,
            receipt: receipt_digest,
            verification: verification_digest,
        };
        if [&receipt.effect, &receipt.receipt, &receipt.verification]
            .iter()
            .all(|digest| is_sha256(digest.as_str()))
        {
            Ok(receipt)
        } else {
            Err(CapabilityInvocationError::InvalidEffectReceipt)
        }
    }

    pub fn effect_digest(&self) -> &Digest {
        &self.effect
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt
    }

    pub fn verification_digest(&self) -> &Digest {
        &self.verification
    }
}

impl Serialize for CapabilityInvocationEffectReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityInvocationEffectReceipt", 4)?;
        state.serialize_field("schema", CAPABILITY_INVOCATION_RECEIPT_SCHEMA)?;
        state.serialize_field("effectDigest", &self.effect)?;
        state.serialize_field("receiptDigest", &self.receipt)?;
        state.serialize_field("verificationDigest", &self.verification)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityInvocationEffectReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityInvocationEffectReceipt")
            .field("effect_digest", &self.effect)
            .field("receipt_digest", &self.receipt)
            .field("verification_digest", &self.verification)
            .finish()
    }
}

/// A content-free reference returned only after a lifecycle event is accepted
/// by the durable invocation log.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityInvocationLogReference {
    event_digest: Digest,
}

impl CapabilityInvocationLogReference {
    fn from_event(event: &CapabilityInvocationEvent) -> Self {
        Self {
            event_digest: event.event_digest.clone(),
        }
    }

    /// Construct the content-free reference returned by an external durable
    /// log implementation after it commits the event.
    pub fn try_from_digest(digest: Digest) -> Result<Self, CapabilityInvocationLogError> {
        if is_sha256(digest.as_str()) {
            Ok(Self {
                event_digest: digest,
            })
        } else {
            Err(CapabilityInvocationLogError::InvalidEvent)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.event_digest
    }
}

impl Serialize for CapabilityInvocationLogReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityInvocationLogReference", 2)?;
        state.serialize_field("schema", CAPABILITY_INVOCATION_LOG_SCHEMA)?;
        state.serialize_field("eventDigest", &self.event_digest)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityInvocationLogReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityInvocationLogReference")
            .field("event_digest", &self.event_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityInvocationEventKind {
    Began,
    Completed,
    TimedOut,
    Cancelled,
    Crashed,
    Invalidated,
    Reopened,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityInvocationCloseReason {
    Timeout,
    Cancelled,
    Crashed,
    ScopeDrift,
    GenerationStale,
    CompositionRevisionDrift,
    ProviderGenerationDrift,
    PolicyDrift,
    CompositionUnavailable,
    PluginRevoked,
    ProviderRevoked,
    ConsumerRevoked,
    AdapterRevoked,
    BindingDrift,
    ResultRejected,
    UncertainExternalEffect,
}

#[derive(Clone, Eq, PartialEq)]
struct InvocationDescriptor {
    invocation_digest: Digest,
    binding_digest: Digest,
    resolution_receipt_digest: Digest,
    request_digest: Digest,
    composition_digest: Digest,
    policy_digest: Digest,
    scope_digest: Digest,
    selector: CapabilityResolutionSelector,
    class: CapabilityClass,
    context: CapabilityInvocationContext,
    attempt: u32,
}

impl InvocationDescriptor {
    fn from_resolution(
        resolution: &CapabilityResolutionLease,
        request_digest: Digest,
        context: CapabilityInvocationContext,
        attempt: u32,
        invocation_digest: Option<Digest>,
    ) -> Result<Self, CapabilityInvocationError> {
        let binding = resolution.binding();
        let selector = CapabilityResolutionSelector::new(
            binding.consumer_id_digest().clone(),
            binding.service_id_digest().clone(),
            binding.version(),
        )
        .map_err(CapabilityInvocationError::Resolution)?;
        let invocation_digest = invocation_digest.unwrap_or_else(|| {
            digest_serialized(&(
                CAPABILITY_INVOCATION_SCHEMA,
                binding.digest(),
                resolution.receipt().digest(),
                &request_digest,
                &context,
            ))
        });
        Ok(Self {
            invocation_digest,
            binding_digest: binding.digest().clone(),
            resolution_receipt_digest: resolution.receipt().digest().clone(),
            request_digest,
            composition_digest: binding.composition_digest().clone(),
            policy_digest: binding.policy_digest().clone(),
            scope_digest: binding.scope().scope_digest.clone(),
            selector,
            class: resolution.invocation_permit().class,
            context,
            attempt,
        })
    }
}

/// A durable event envelope. It contains digests and authority metadata only;
/// request/result content never crosses this inspection boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityInvocationEvent {
    kind: CapabilityInvocationEventKind,
    event_digest: Digest,
    invocation_digest: Digest,
    binding_digest: Digest,
    resolution_receipt_digest: Digest,
    request_digest: Digest,
    composition_digest: Digest,
    policy_digest: Digest,
    scope_digest: Digest,
    selector: CapabilityResolutionSelector,
    class: CapabilityClass,
    context: CapabilityInvocationContext,
    attempt: u32,
    result_digest: Option<Digest>,
    effect_receipt_digest: Option<Digest>,
    reason: Option<CapabilityInvocationCloseReason>,
    prior_event_digest: Option<Digest>,
    observed_at: DateTime<Utc>,
}

impl CapabilityInvocationEvent {
    fn new(
        kind: CapabilityInvocationEventKind,
        descriptor: &InvocationDescriptor,
        result_digest: Option<Digest>,
        effect_receipt_digest: Option<Digest>,
        reason: Option<CapabilityInvocationCloseReason>,
        prior_event_digest: Option<Digest>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let mut event = Self {
            kind,
            event_digest: Digest::from_text("unsealed-capability-invocation-event"),
            invocation_digest: descriptor.invocation_digest.clone(),
            binding_digest: descriptor.binding_digest.clone(),
            resolution_receipt_digest: descriptor.resolution_receipt_digest.clone(),
            request_digest: descriptor.request_digest.clone(),
            composition_digest: descriptor.composition_digest.clone(),
            policy_digest: descriptor.policy_digest.clone(),
            scope_digest: descriptor.scope_digest.clone(),
            selector: descriptor.selector.clone(),
            class: descriptor.class,
            context: descriptor.context.clone(),
            attempt: descriptor.attempt,
            result_digest,
            effect_receipt_digest,
            reason,
            prior_event_digest,
            observed_at,
        };
        event.event_digest = event.computed_digest();
        event
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            CAPABILITY_INVOCATION_LOG_SCHEMA,
            (
                self.kind,
                &self.invocation_digest,
                &self.binding_digest,
                &self.resolution_receipt_digest,
                &self.request_digest,
                &self.composition_digest,
                &self.policy_digest,
                &self.scope_digest,
                &self.selector,
                self.class,
                &self.context,
            ),
            (
                self.attempt,
                &self.result_digest,
                &self.effect_receipt_digest,
                &self.reason,
                &self.prior_event_digest,
                self.observed_at,
            ),
        ))
    }

    fn validate(&self) -> Result<(), CapabilityInvocationLogError> {
        let digests = [
            &self.event_digest,
            &self.invocation_digest,
            &self.binding_digest,
            &self.resolution_receipt_digest,
            &self.request_digest,
            &self.composition_digest,
            &self.policy_digest,
            &self.scope_digest,
        ];
        if digests.iter().any(|digest| !is_sha256(digest.as_str()))
            || self.attempt == 0
            || self.event_digest != self.computed_digest()
        {
            return Err(CapabilityInvocationLogError::InvalidEvent);
        }
        self.context
            .validate_storage()
            .map_err(|_| CapabilityInvocationLogError::InvalidEvent)?;
        match self.kind {
            CapabilityInvocationEventKind::Began => {
                if self.attempt != 1
                    || self.result_digest.is_some()
                    || self.effect_receipt_digest.is_some()
                    || self.reason.is_some()
                    || self.prior_event_digest.is_some()
                {
                    return Err(CapabilityInvocationLogError::InvalidEvent);
                }
            }
            CapabilityInvocationEventKind::Reopened => {
                if self.attempt <= 1
                    || self.result_digest.is_some()
                    || self.effect_receipt_digest.is_some()
                    || self.reason.is_some()
                    || self.prior_event_digest.is_none()
                {
                    return Err(CapabilityInvocationLogError::InvalidEvent);
                }
            }
            CapabilityInvocationEventKind::Completed => {
                if self.result_digest.is_none()
                    || self.reason.is_some()
                    || self.prior_event_digest.is_some()
                    || (self.class == CapabilityClass::ExternalEffect
                        && self.effect_receipt_digest.is_none())
                {
                    return Err(CapabilityInvocationLogError::InvalidEvent);
                }
            }
            CapabilityInvocationEventKind::TimedOut => {
                self.validate_terminal(CapabilityInvocationCloseReason::Timeout)?;
            }
            CapabilityInvocationEventKind::Cancelled => {
                self.validate_terminal(CapabilityInvocationCloseReason::Cancelled)?;
            }
            CapabilityInvocationEventKind::Crashed => {
                self.validate_terminal(CapabilityInvocationCloseReason::Crashed)?;
            }
            CapabilityInvocationEventKind::Invalidated => {
                if self.prior_event_digest.is_some() || self.reason.is_none() {
                    return Err(CapabilityInvocationLogError::InvalidEvent);
                }
                if self.reason == Some(CapabilityInvocationCloseReason::ResultRejected)
                    && self.result_digest.is_some()
                {
                    return Err(CapabilityInvocationLogError::InvalidEvent);
                }
                if self.reason != Some(CapabilityInvocationCloseReason::UncertainExternalEffect)
                    && self.effect_receipt_digest.is_some()
                {
                    return Err(CapabilityInvocationLogError::InvalidEvent);
                }
            }
        }
        Ok(())
    }

    fn validate_terminal(
        &self,
        expected: CapabilityInvocationCloseReason,
    ) -> Result<(), CapabilityInvocationLogError> {
        if self.result_digest.is_some()
            || self.effect_receipt_digest.is_some()
            || self.reason != Some(expected)
            || self.prior_event_digest.is_some()
        {
            return Err(CapabilityInvocationLogError::InvalidEvent);
        }
        Ok(())
    }

    pub fn kind(&self) -> CapabilityInvocationEventKind {
        self.kind
    }

    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn invocation_digest(&self) -> &Digest {
        &self.invocation_digest
    }

    pub fn result_digest(&self) -> Option<&Digest> {
        self.result_digest.as_ref()
    }

    pub fn effect_receipt_digest(&self) -> Option<&Digest> {
        self.effect_receipt_digest.as_ref()
    }

    pub fn reason(&self) -> Option<CapabilityInvocationCloseReason> {
        self.reason
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl Serialize for CapabilityInvocationEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityInvocationEvent", 19)?;
        state.serialize_field("schema", CAPABILITY_INVOCATION_LOG_SCHEMA)?;
        state.serialize_field("eventDigest", &self.event_digest)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("invocationDigest", &self.invocation_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("resolutionReceiptDigest", &self.resolution_receipt_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("compositionDigest", &self.composition_digest)?;
        state.serialize_field("policyDigest", &self.policy_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("selector", &self.selector)?;
        state.serialize_field("class", &self.class)?;
        state.serialize_field("context", &self.context)?;
        state.serialize_field("attempt", &self.attempt)?;
        state.serialize_field("resultDigest", &self.result_digest)?;
        state.serialize_field("effectReceiptDigest", &self.effect_receipt_digest)?;
        state.serialize_field("reason", &self.reason)?;
        state.serialize_field("priorEventDigest", &self.prior_event_digest)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityInvocationEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityInvocationEvent")
            .field("kind", &self.kind)
            .field("event_digest", &self.event_digest)
            .field("invocation_digest", &self.invocation_digest)
            .field("binding_digest", &self.binding_digest)
            .field("resolution_receipt_digest", &self.resolution_receipt_digest)
            .field("request_digest", &self.request_digest)
            .field("composition_digest", &self.composition_digest)
            .field("policy_digest", &self.policy_digest)
            .field("scope_digest", &self.scope_digest)
            .field("selector", &self.selector)
            .field("class", &self.class)
            .field("context", &self.context)
            .field("attempt", &self.attempt)
            .field("result_digest", &self.result_digest)
            .field("effect_receipt_digest", &self.effect_receipt_digest)
            .field("reason", &self.reason)
            .field("prior_event_digest", &self.prior_event_digest)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

pub trait CapabilityInvocationLog {
    /// Append and durably commit one lifecycle event before returning its
    /// reference. Implementations must enforce the state transition encoded by
    /// the event and must not return a reference for an uncommitted event.
    fn append(
        &mut self,
        event: CapabilityInvocationEvent,
    ) -> Result<CapabilityInvocationLogReference, CapabilityInvocationLogError>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityInvocationLogError {
    #[error("invocation log is unavailable")]
    Unavailable,
    #[error("invocation log transition conflicts with durable state")]
    Conflict,
    #[error("invocation log transition is invalid")]
    InvalidTransition,
    #[error("invocation log event is invalid")]
    InvalidEvent,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct MemoryCapabilityInvocationLog {
    events: Vec<CapabilityInvocationEvent>,
    active: std::collections::BTreeSet<Digest>,
    closed: std::collections::BTreeSet<Digest>,
    last: std::collections::BTreeMap<Digest, (Digest, u32, CapabilityInvocationEventKind)>,
}

impl MemoryCapabilityInvocationLog {
    pub fn events(&self) -> &[CapabilityInvocationEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl CapabilityInvocationLog for MemoryCapabilityInvocationLog {
    fn append(
        &mut self,
        event: CapabilityInvocationEvent,
    ) -> Result<CapabilityInvocationLogReference, CapabilityInvocationLogError> {
        event.validate()?;
        let invocation = event.invocation_digest.clone();
        match event.kind {
            CapabilityInvocationEventKind::Began => {
                if self.active.contains(&invocation)
                    || self.closed.contains(&invocation)
                    || self.last.contains_key(&invocation)
                {
                    return Err(CapabilityInvocationLogError::Conflict);
                }
                self.active.insert(invocation);
            }
            CapabilityInvocationEventKind::Reopened => {
                if self.active.contains(&invocation) {
                    return Err(CapabilityInvocationLogError::Conflict);
                }
                if !self.closed.contains(&invocation) {
                    return Err(CapabilityInvocationLogError::InvalidTransition);
                }
                let Some((prior_digest, prior_attempt, prior_kind)) = self.last.get(&invocation)
                else {
                    return Err(CapabilityInvocationLogError::InvalidTransition);
                };
                if event.prior_event_digest.as_ref() != Some(prior_digest)
                    || event.attempt != prior_attempt.saturating_add(1)
                    || matches!(
                        prior_kind,
                        CapabilityInvocationEventKind::Began
                            | CapabilityInvocationEventKind::Reopened
                    )
                {
                    return Err(CapabilityInvocationLogError::InvalidTransition);
                }
                self.closed.remove(&invocation);
                self.active.insert(invocation);
            }
            CapabilityInvocationEventKind::Completed
            | CapabilityInvocationEventKind::TimedOut
            | CapabilityInvocationEventKind::Cancelled
            | CapabilityInvocationEventKind::Crashed
            | CapabilityInvocationEventKind::Invalidated => {
                if !self.active.contains(&invocation) {
                    return Err(CapabilityInvocationLogError::InvalidTransition);
                }
                let Some((_, prior_attempt, prior_kind)) = self.last.get(&invocation) else {
                    return Err(CapabilityInvocationLogError::InvalidTransition);
                };
                if event.attempt != *prior_attempt
                    || !matches!(
                        prior_kind,
                        CapabilityInvocationEventKind::Began
                            | CapabilityInvocationEventKind::Reopened
                    )
                {
                    return Err(CapabilityInvocationLogError::InvalidTransition);
                }
                self.active.remove(&invocation);
                if !self.closed.insert(invocation) {
                    return Err(CapabilityInvocationLogError::Conflict);
                }
            }
        }
        self.last.insert(
            event.invocation_digest.clone(),
            (event.event_digest.clone(), event.attempt, event.kind),
        );
        let reference = CapabilityInvocationLogReference::from_event(&event);
        self.events.push(event);
        Ok(reference)
    }
}

impl fmt::Debug for MemoryCapabilityInvocationLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryCapabilityInvocationLog")
            .field("event_count", &self.events.len())
            .field("active_count", &self.active.len())
            .field("closed_count", &self.closed.len())
            .field("last_count", &self.last.len())
            .field(
                "event_set_digest",
                &digest_serialized(
                    &self
                        .events
                        .iter()
                        .map(CapabilityInvocationEvent::event_digest)
                        .collect::<Vec<_>>(),
                ),
            )
            .finish()
    }
}

/// The durable reference returned after a Begin event is committed.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityInvocationReceipt {
    invocation_digest: Digest,
    binding_digest: Digest,
    resolution_receipt_digest: Digest,
    request_digest: Digest,
    selector: CapabilityResolutionSelector,
    context: CapabilityInvocationContext,
    attempt: u32,
    log_reference: CapabilityInvocationLogReference,
    receipt_digest: Digest,
}

impl CapabilityInvocationReceipt {
    fn new(
        descriptor: &InvocationDescriptor,
        log_reference: CapabilityInvocationLogReference,
    ) -> Self {
        let mut receipt = Self {
            invocation_digest: descriptor.invocation_digest.clone(),
            binding_digest: descriptor.binding_digest.clone(),
            resolution_receipt_digest: descriptor.resolution_receipt_digest.clone(),
            request_digest: descriptor.request_digest.clone(),
            selector: descriptor.selector.clone(),
            context: descriptor.context.clone(),
            attempt: descriptor.attempt,
            log_reference,
            receipt_digest: Digest::from_text("unsealed-capability-invocation-receipt"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            CAPABILITY_INVOCATION_RECEIPT_SCHEMA,
            &self.invocation_digest,
            &self.binding_digest,
            &self.resolution_receipt_digest,
            &self.request_digest,
            &self.selector,
            &self.context,
            self.attempt,
            &self.log_reference,
        ))
    }

    fn validate(&self) -> Result<(), CapabilityInvocationError> {
        if ![
            &self.invocation_digest,
            &self.binding_digest,
            &self.resolution_receipt_digest,
            &self.request_digest,
            &self.receipt_digest,
            self.log_reference.digest(),
        ]
        .iter()
        .all(|digest| is_sha256(digest.as_str()))
            || self.attempt == 0
            || self.receipt_digest != self.computed_digest()
        {
            return Err(CapabilityInvocationError::InvalidInvocationReceipt);
        }
        self.context.validate_storage()
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn invocation_digest(&self) -> &Digest {
        &self.invocation_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn resolution_receipt_digest(&self) -> &Digest {
        &self.resolution_receipt_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn log_reference(&self) -> &CapabilityInvocationLogReference {
        &self.log_reference
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn context(&self) -> &CapabilityInvocationContext {
        &self.context
    }
}

impl Serialize for CapabilityInvocationReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityInvocationReceipt", 10)?;
        state.serialize_field("schema", CAPABILITY_INVOCATION_RECEIPT_SCHEMA)?;
        state.serialize_field("receiptDigest", &self.receipt_digest)?;
        state.serialize_field("invocationDigest", &self.invocation_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("resolutionReceiptDigest", &self.resolution_receipt_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("selector", &self.selector)?;
        state.serialize_field("context", &self.context)?;
        state.serialize_field("attempt", &self.attempt)?;
        state.serialize_field("logReference", &self.log_reference)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityInvocationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityInvocationReceipt")
            .field("receipt_digest", &self.receipt_digest)
            .field("invocation_digest", &self.invocation_digest)
            .field("binding_digest", &self.binding_digest)
            .field("resolution_receipt_digest", &self.resolution_receipt_digest)
            .field("request_digest", &self.request_digest)
            .field("selector", &self.selector)
            .field("context", &self.context)
            .field("attempt", &self.attempt)
            .field("log_reference", &self.log_reference)
            .finish()
    }
}

/// A terminal invocation receipt. A successful completion binds the typed
/// result digest and, for ExternalEffect, the verified effect receipt digest.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityInvocationReleaseReceipt {
    invocation_digest: Digest,
    binding_digest: Digest,
    resolution_receipt_digest: Digest,
    request_digest: Digest,
    selector: CapabilityResolutionSelector,
    class: CapabilityClass,
    context: CapabilityInvocationContext,
    attempt: u32,
    kind: CapabilityInvocationEventKind,
    reason: Option<CapabilityInvocationCloseReason>,
    result_digest: Option<Digest>,
    effect_receipt_digest: Option<Digest>,
    log_reference: CapabilityInvocationLogReference,
    release_digest: Digest,
}

impl CapabilityInvocationReleaseReceipt {
    fn new(
        event: &CapabilityInvocationEvent,
        log_reference: CapabilityInvocationLogReference,
    ) -> Self {
        let mut receipt = Self {
            invocation_digest: event.invocation_digest.clone(),
            binding_digest: event.binding_digest.clone(),
            resolution_receipt_digest: event.resolution_receipt_digest.clone(),
            request_digest: event.request_digest.clone(),
            selector: event.selector.clone(),
            class: event.class,
            context: event.context.clone(),
            attempt: event.attempt,
            kind: event.kind,
            reason: event.reason,
            result_digest: event.result_digest.clone(),
            effect_receipt_digest: event.effect_receipt_digest.clone(),
            log_reference,
            release_digest: Digest::from_text("unsealed-capability-invocation-release"),
        };
        receipt.release_digest = receipt.computed_digest();
        receipt
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            CAPABILITY_INVOCATION_RECEIPT_SCHEMA,
            "release",
            (
                &self.invocation_digest,
                &self.binding_digest,
                &self.resolution_receipt_digest,
                &self.request_digest,
                &self.selector,
                self.class,
                &self.context,
            ),
            (
                self.attempt,
                self.kind,
                &self.reason,
                &self.result_digest,
                &self.effect_receipt_digest,
                &self.log_reference,
            ),
        ))
    }

    fn validate(&self) -> Result<(), CapabilityInvocationError> {
        let mut valid = vec![
            &self.invocation_digest,
            &self.binding_digest,
            &self.resolution_receipt_digest,
            &self.request_digest,
            self.log_reference.digest(),
            &self.release_digest,
        ];
        if let Some(result) = &self.result_digest {
            valid.push(result);
        }
        if let Some(effect) = &self.effect_receipt_digest {
            valid.push(effect);
        }
        if valid.iter().any(|digest| !is_sha256(digest.as_str()))
            || self.attempt == 0
            || matches!(
                self.kind,
                CapabilityInvocationEventKind::Began | CapabilityInvocationEventKind::Reopened
            )
            || self.release_digest != self.computed_digest()
        {
            return Err(CapabilityInvocationError::InvalidReleaseReceipt);
        }
        self.context.validate_storage()?;
        if self.kind == CapabilityInvocationEventKind::Completed && self.result_digest.is_none() {
            return Err(CapabilityInvocationError::InvalidReleaseReceipt);
        }
        if self.class == CapabilityClass::ExternalEffect
            && self.kind == CapabilityInvocationEventKind::Completed
            && self.effect_receipt_digest.is_none()
        {
            return Err(CapabilityInvocationError::InvalidReleaseReceipt);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.release_digest
    }

    pub fn invocation_digest(&self) -> &Digest {
        &self.invocation_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn resolution_receipt_digest(&self) -> &Digest {
        &self.resolution_receipt_digest
    }

    pub fn result_digest(&self) -> Option<&Digest> {
        self.result_digest.as_ref()
    }

    pub fn effect_receipt_digest(&self) -> Option<&Digest> {
        self.effect_receipt_digest.as_ref()
    }

    pub fn log_reference(&self) -> &CapabilityInvocationLogReference {
        &self.log_reference
    }

    pub fn kind(&self) -> CapabilityInvocationEventKind {
        self.kind
    }

    pub fn reason(&self) -> Option<CapabilityInvocationCloseReason> {
        self.reason
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn context(&self) -> &CapabilityInvocationContext {
        &self.context
    }
}

impl Serialize for CapabilityInvocationReleaseReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityInvocationReleaseReceipt", 16)?;
        state.serialize_field("schema", CAPABILITY_INVOCATION_RECEIPT_SCHEMA)?;
        state.serialize_field("releaseDigest", &self.release_digest)?;
        state.serialize_field("invocationDigest", &self.invocation_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("resolutionReceiptDigest", &self.resolution_receipt_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("selector", &self.selector)?;
        state.serialize_field("class", &self.class)?;
        state.serialize_field("context", &self.context)?;
        state.serialize_field("attempt", &self.attempt)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("reason", &self.reason)?;
        state.serialize_field("resultDigest", &self.result_digest)?;
        state.serialize_field("effectReceiptDigest", &self.effect_receipt_digest)?;
        state.serialize_field("logReference", &self.log_reference)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityInvocationReleaseReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityInvocationReleaseReceipt")
            .field("release_digest", &self.release_digest)
            .field("invocation_digest", &self.invocation_digest)
            .field("binding_digest", &self.binding_digest)
            .field("resolution_receipt_digest", &self.resolution_receipt_digest)
            .field("request_digest", &self.request_digest)
            .field("selector", &self.selector)
            .field("class", &self.class)
            .field("context", &self.context)
            .field("attempt", &self.attempt)
            .field("kind", &self.kind)
            .field("reason", &self.reason)
            .field("result_digest", &self.result_digest)
            .field("effect_receipt_digest", &self.effect_receipt_digest)
            .field("log_reference", &self.log_reference)
            .finish()
    }
}

pub type CapabilityInvocationResult = CapabilityInvocationReleaseReceipt;
pub type InvocationLease = CapabilityInvocationLease;

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityInvocationLease {
    resolution: CapabilityResolutionLease,
    descriptor: InvocationDescriptor,
    receipt: CapabilityInvocationReceipt,
    released: bool,
}

impl CapabilityInvocationLease {
    fn new(
        resolution: CapabilityResolutionLease,
        descriptor: InvocationDescriptor,
        receipt: CapabilityInvocationReceipt,
    ) -> Self {
        Self {
            resolution,
            descriptor,
            receipt,
            released: false,
        }
    }

    pub fn binding(&self) -> &CapabilityBinding {
        self.resolution.binding()
    }

    pub fn resolution_receipt(&self) -> &CapabilityResolutionReceipt {
        self.resolution.receipt()
    }

    pub fn invocation_permit(&self) -> &InvocationPermit {
        self.resolution.invocation_permit()
    }

    pub fn receipt(&self) -> &CapabilityInvocationReceipt {
        &self.receipt
    }

    pub fn log_reference(&self) -> &CapabilityInvocationLogReference {
        self.receipt.log_reference()
    }

    pub fn invocation_digest(&self) -> &Digest {
        &self.descriptor.invocation_digest
    }

    pub const fn attempt(&self) -> u32 {
        self.descriptor.attempt
    }

    pub const fn is_released(&self) -> bool {
        self.released
    }

    pub const fn visibility(&self) -> CapabilityInvocationVisibility {
        self.descriptor.context.visibility()
    }

    /// Release the underlying resolution lease after this invocation has
    /// reached a terminal state. The invocation log and resolution ledger are
    /// separate durable seams; callers should commit this receipt as part of
    /// the same application transaction when both stores support one.
    pub fn release_resolution<L: CapabilityResolutionAuditLedger>(
        &mut self,
        released_at: DateTime<Utc>,
        audit: &mut L,
    ) -> Result<CapabilityReleaseReceipt, CapabilityInvocationError> {
        if !self.released {
            return Err(CapabilityInvocationError::NotReleased);
        }
        self.resolution
            .release(released_at, audit)
            .map_err(CapabilityInvocationError::Resolution)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish<L: CapabilityInvocationLog>(
        &mut self,
        kind: CapabilityInvocationEventKind,
        reason: Option<CapabilityInvocationCloseReason>,
        result_digest: Option<Digest>,
        effect_receipt_digest: Option<Digest>,
        prior_event_digest: Option<Digest>,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<CapabilityInvocationReleaseReceipt, CapabilityInvocationError> {
        if self.released {
            return Err(CapabilityInvocationError::AlreadyReleased);
        }
        let event = CapabilityInvocationEvent::new(
            kind,
            &self.descriptor,
            result_digest,
            effect_receipt_digest,
            reason,
            prior_event_digest,
            observed_at,
        );
        let reference = log.append(event.clone())?;
        self.released = true;
        Ok(CapabilityInvocationReleaseReceipt::new(&event, reference))
    }

    pub fn timeout<L: CapabilityInvocationLog>(
        &mut self,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<CapabilityInvocationReleaseReceipt, CapabilityInvocationError> {
        self.finish(
            CapabilityInvocationEventKind::TimedOut,
            Some(CapabilityInvocationCloseReason::Timeout),
            None,
            None,
            None,
            observed_at,
            log,
        )
    }

    pub fn cancel<L: CapabilityInvocationLog>(
        &mut self,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<CapabilityInvocationReleaseReceipt, CapabilityInvocationError> {
        self.finish(
            CapabilityInvocationEventKind::Cancelled,
            Some(CapabilityInvocationCloseReason::Cancelled),
            None,
            None,
            None,
            observed_at,
            log,
        )
    }

    pub fn crash<L: CapabilityInvocationLog>(
        &mut self,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<CapabilityInvocationReleaseReceipt, CapabilityInvocationError> {
        self.finish(
            CapabilityInvocationEventKind::Crashed,
            Some(CapabilityInvocationCloseReason::Crashed),
            None,
            None,
            None,
            observed_at,
            log,
        )
    }
}

impl fmt::Debug for CapabilityInvocationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityInvocationLease")
            .field("resolution", &self.resolution)
            .field("binding", &self.binding())
            .field("resolution_receipt", &self.resolution_receipt())
            .field("receipt", &self.receipt)
            .field("invocation_permit", &self.invocation_permit())
            .field("attempt", &self.descriptor.attempt)
            .field("released", &self.released)
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CapabilityInvocationError {
    #[error("resolved capability binding has already been released")]
    AlreadyReleased,
    #[error("invocation must be terminal before resolution release")]
    NotReleased,
    #[error("invocation context is invalid")]
    InvalidContext,
    #[error("invocation Mission scope does not match the resolved binding")]
    MissionMismatch,
    #[error("invocation generation does not match the resolved binding")]
    GenerationMismatch,
    #[error("invocation composition revision does not match the resolved binding")]
    RevisionMismatch,
    #[error("invocation provider generation does not match the resolved binding")]
    ProviderGenerationMismatch,
    #[error("invocation policy digest drifted")]
    PolicyDrift,
    #[error("resolved binding drifted before invocation completion")]
    BindingDrift,
    #[error("capability resolution rejected the invocation")]
    Resolution(#[source] CapabilityResolutionError),
    #[error("gateway rejected the invocation result")]
    ResultRejected(#[source] GatewayError),
    #[error("verified effect receipt is required for ExternalEffect completion")]
    EffectReceiptRequired,
    #[error("effect receipt is not allowed for this capability class")]
    UnexpectedEffectReceipt,
    #[error("effect receipt does not match the result")]
    EffectReceiptMismatch,
    #[error("external effect is uncertain and cannot be reopened automatically")]
    UncertainExternalEffect,
    #[error("invocation was invalidated: {0:?}")]
    Invalidated(CapabilityInvocationCloseReason),
    #[error("invocation receipt is invalid")]
    InvalidInvocationReceipt,
    #[error("invocation release receipt is invalid")]
    InvalidReleaseReceipt,
    #[error("invocation cannot be reopened from this terminal state")]
    ReopenNotAllowed,
    #[error("invocation reopen attempt limit reached")]
    AttemptLimit,
    #[error("invocation log transition failed")]
    Log(#[from] CapabilityInvocationLogError),
    #[error("effect receipt digest is invalid")]
    InvalidEffectReceipt,
}

impl CapabilityResolver<'_> {
    #[allow(clippy::too_many_arguments)]
    pub fn begin_invocation<L: CapabilityInvocationLog>(
        &self,
        resolved: &ResolvedCapabilityBinding,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        context: &CapabilityInvocationContext,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<CapabilityInvocationLease, CapabilityInvocationError> {
        if resolved.is_released() {
            return Err(CapabilityInvocationError::AlreadyReleased);
        }
        context.validate_against(resolved.binding())?;
        let current = self
            .validate_binding_for_invocation(
                resolved.binding(),
                resolved.receipt(),
                composition,
                signed_manifest,
                request,
                observed_at,
            )
            .map_err(CapabilityInvocationError::Resolution)?;
        if current.invocation_permit() != resolved.invocation_permit() {
            return Err(CapabilityInvocationError::BindingDrift);
        }
        let descriptor = InvocationDescriptor::from_resolution(
            resolved,
            request.digest(),
            context.clone(),
            1,
            None,
        )?;
        let event = CapabilityInvocationEvent::new(
            CapabilityInvocationEventKind::Began,
            &descriptor,
            None,
            None,
            None,
            None,
            observed_at,
        );
        let reference = log.append(event)?;
        let receipt = CapabilityInvocationReceipt::new(&descriptor, reference);
        receipt.validate()?;
        Ok(CapabilityInvocationLease::new(
            resolved.clone(),
            descriptor,
            receipt,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn revalidate_invocation<L: CapabilityInvocationLog>(
        &self,
        lease: &mut CapabilityInvocationLease,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<(), CapabilityInvocationError> {
        if lease.released {
            return Err(CapabilityInvocationError::AlreadyReleased);
        }
        if let Err(error) =
            self.validate_live_invocation(lease, composition, signed_manifest, request, observed_at)
        {
            let reason = close_reason_for(&error);
            lease.finish(
                CapabilityInvocationEventKind::Invalidated,
                Some(reason),
                None,
                None,
                None,
                observed_at,
                log,
            )?;
            return Err(CapabilityInvocationError::Invalidated(reason));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_invocation<L: CapabilityInvocationLog>(
        &self,
        lease: &mut CapabilityInvocationLease,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        result: &CapabilityResult,
        effect_receipt: Option<&CapabilityInvocationEffectReceipt>,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<CapabilityInvocationReleaseReceipt, CapabilityInvocationError> {
        if lease.released {
            return Err(CapabilityInvocationError::AlreadyReleased);
        }
        if let Err(error) =
            self.validate_live_invocation(lease, composition, signed_manifest, request, observed_at)
        {
            return Self::invalidate_after_error(lease, &error, observed_at, log);
        }
        if let Err(error) = result.validate_against(request, &signed_manifest.manifest, observed_at)
        {
            let original = CapabilityInvocationError::ResultRejected(error);
            return Self::invalidate_after_error(lease, &original, observed_at, log);
        }
        let effect_receipt_digest = match validate_effect_receipt(request, result, effect_receipt) {
            Ok(digest) => digest,
            Err(error) => return Self::invalidate_after_error(lease, &error, observed_at, log),
        };
        lease.finish(
            CapabilityInvocationEventKind::Completed,
            None,
            Some(result.digest()),
            effect_receipt_digest,
            None,
            observed_at,
            log,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reopen_invocation<L: CapabilityInvocationLog>(
        &self,
        release: &CapabilityInvocationReleaseReceipt,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        context: &CapabilityInvocationContext,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<CapabilityInvocationLease, CapabilityInvocationError> {
        release.validate()?;
        if release.kind == CapabilityInvocationEventKind::Completed
            || release.reason == Some(CapabilityInvocationCloseReason::UncertainExternalEffect)
        {
            return Err(CapabilityInvocationError::ReopenNotAllowed);
        }
        if release.class == CapabilityClass::ExternalEffect {
            return Err(CapabilityInvocationError::UncertainExternalEffect);
        }
        if release.attempt >= MAX_INVOCATION_ATTEMPTS {
            return Err(CapabilityInvocationError::AttemptLimit);
        }
        if release.request_digest != request.digest() || release.context != *context {
            return Err(CapabilityInvocationError::BindingDrift);
        }
        context.validate_against_release(release)?;
        let current = self
            .rebuild_resolution_lease(
                composition,
                signed_manifest,
                request,
                &release.selector,
                observed_at,
            )
            .map_err(CapabilityInvocationError::Resolution)?;
        if current.binding().digest() != &release.binding_digest
            || current.receipt().digest() != &release.resolution_receipt_digest
            || current.invocation_permit().class != release.class
        {
            return Err(CapabilityInvocationError::BindingDrift);
        }
        let descriptor = InvocationDescriptor::from_resolution(
            &current,
            request.digest(),
            context.clone(),
            release.attempt + 1,
            Some(release.invocation_digest.clone()),
        )?;
        let event = CapabilityInvocationEvent::new(
            CapabilityInvocationEventKind::Reopened,
            &descriptor,
            None,
            None,
            None,
            Some(release.log_reference.digest().clone()),
            observed_at,
        );
        let reference = log.append(event)?;
        let receipt = CapabilityInvocationReceipt::new(&descriptor, reference);
        receipt.validate()?;
        Ok(CapabilityInvocationLease::new(current, descriptor, receipt))
    }

    fn validate_live_invocation(
        &self,
        lease: &CapabilityInvocationLease,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<(), CapabilityInvocationError> {
        lease.descriptor.context.validate_against(lease.binding())?;
        let current = self
            .validate_binding_for_invocation(
                lease.binding(),
                lease.resolution_receipt(),
                composition,
                signed_manifest,
                request,
                observed_at,
            )
            .map_err(CapabilityInvocationError::Resolution)?;
        if current.invocation_permit() != lease.invocation_permit() {
            return Err(CapabilityInvocationError::BindingDrift);
        }
        Ok(())
    }

    fn invalidate_after_error<L: CapabilityInvocationLog>(
        lease: &mut CapabilityInvocationLease,
        error: &CapabilityInvocationError,
        observed_at: DateTime<Utc>,
        log: &mut L,
    ) -> Result<CapabilityInvocationReleaseReceipt, CapabilityInvocationError> {
        let reason = close_reason_for(error);
        lease.finish(
            CapabilityInvocationEventKind::Invalidated,
            Some(reason),
            None,
            None,
            None,
            observed_at,
            log,
        )?;
        Err(CapabilityInvocationError::Invalidated(reason))
    }
}

impl CapabilityInvocationContext {
    fn validate_against_release(
        &self,
        release: &CapabilityInvocationReleaseReceipt,
    ) -> Result<(), CapabilityInvocationError> {
        if self.project_id != release.context.project_id
            || self.mission_id != release.context.mission_id
        {
            return Err(CapabilityInvocationError::MissionMismatch);
        }
        if self.generation != release.context.generation {
            return Err(CapabilityInvocationError::GenerationMismatch);
        }
        if self.composition_revision != release.context.composition_revision {
            return Err(CapabilityInvocationError::RevisionMismatch);
        }
        if self.provider_generation != release.context.provider_generation {
            return Err(CapabilityInvocationError::ProviderGenerationMismatch);
        }
        if self.policy_digest != release.context.policy_digest {
            return Err(CapabilityInvocationError::PolicyDrift);
        }
        Ok(())
    }
}

fn validate_effect_receipt(
    request: &CapabilityRequest,
    result: &CapabilityResult,
    receipt: Option<&CapabilityInvocationEffectReceipt>,
) -> Result<Option<Digest>, CapabilityInvocationError> {
    match request.class {
        CapabilityClass::ExternalEffect => {
            let ResultPayload::ExternalEffect(ExternalEffectResult {
                effect_digest,
                disposition,
                receipt_digest,
                verification_digest,
                ..
            }) = &result.payload
            else {
                return Err(CapabilityInvocationError::ResultRejected(
                    GatewayError::ResultScopeMismatch,
                ));
            };
            if *disposition == EffectDisposition::Uncertain {
                return Err(CapabilityInvocationError::UncertainExternalEffect);
            }
            if *disposition != EffectDisposition::Verified {
                return Err(CapabilityInvocationError::EffectReceiptRequired);
            }
            let receipt = receipt.ok_or(CapabilityInvocationError::EffectReceiptRequired)?;
            if receipt_digest.as_ref() != Some(receipt.receipt_digest())
                || verification_digest.as_ref() != Some(receipt.verification_digest())
                || effect_digest != receipt.effect_digest()
            {
                return Err(CapabilityInvocationError::EffectReceiptMismatch);
            }
            Ok(Some(receipt.receipt_digest().clone()))
        }
        CapabilityClass::Read | CapabilityClass::LocalMutation => {
            if receipt.is_some() {
                Err(CapabilityInvocationError::UnexpectedEffectReceipt)
            } else {
                Ok(None)
            }
        }
    }
}

fn close_reason_for(error: &CapabilityInvocationError) -> CapabilityInvocationCloseReason {
    match error {
        CapabilityInvocationError::MissionMismatch => CapabilityInvocationCloseReason::ScopeDrift,
        CapabilityInvocationError::GenerationMismatch => {
            CapabilityInvocationCloseReason::GenerationStale
        }
        CapabilityInvocationError::RevisionMismatch => {
            CapabilityInvocationCloseReason::CompositionRevisionDrift
        }
        CapabilityInvocationError::ProviderGenerationMismatch => {
            CapabilityInvocationCloseReason::ProviderGenerationDrift
        }
        CapabilityInvocationError::PolicyDrift => CapabilityInvocationCloseReason::PolicyDrift,
        CapabilityInvocationError::Resolution(error) => match error {
            CapabilityResolutionError::CompositionUnavailable => {
                CapabilityInvocationCloseReason::CompositionUnavailable
            }
            CapabilityResolutionError::PluginRevoked => {
                CapabilityInvocationCloseReason::PluginRevoked
            }
            CapabilityResolutionError::ProviderRevoked => {
                CapabilityInvocationCloseReason::ProviderRevoked
            }
            CapabilityResolutionError::ConsumerRevoked => {
                CapabilityInvocationCloseReason::ConsumerRevoked
            }
            CapabilityResolutionError::StaleGeneration => {
                CapabilityInvocationCloseReason::GenerationStale
            }
            CapabilityResolutionError::ScopeMismatch => CapabilityInvocationCloseReason::ScopeDrift,
            CapabilityResolutionError::PolicyMismatch => {
                CapabilityInvocationCloseReason::PolicyDrift
            }
            CapabilityResolutionError::Gateway(GatewayError::AdapterRevoked) => {
                CapabilityInvocationCloseReason::AdapterRevoked
            }
            _ => CapabilityInvocationCloseReason::BindingDrift,
        },
        CapabilityInvocationError::ResultRejected(_)
        | CapabilityInvocationError::EffectReceiptRequired
        | CapabilityInvocationError::UnexpectedEffectReceipt
        | CapabilityInvocationError::EffectReceiptMismatch => {
            CapabilityInvocationCloseReason::ResultRejected
        }
        CapabilityInvocationError::UncertainExternalEffect => {
            CapabilityInvocationCloseReason::UncertainExternalEffect
        }
        _ => CapabilityInvocationCloseReason::BindingDrift,
    }
}

impl CapabilityGateway {
    pub fn invocation_resolver(&self) -> CapabilityResolver<'_> {
        self.resolver()
    }
}

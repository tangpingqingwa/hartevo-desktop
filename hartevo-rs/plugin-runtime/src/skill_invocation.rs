//! Typed Skill Pack invocation closure over the existing Capability Gateway.
//!
//! A Skill Pack is a verified, scoped provider of model context. It is not an
//! execution host. This module only joins that provider to an already-resolved
//! Gateway binding and returns an opaque, typed proposal. A proposal can be
//! consumed exactly once through the Gateway invocation lease; read results
//! remain typed and bounded, while ExternalEffect results must already carry
//! the Effect Broker's verified receipt. No registry, database handle, Secret,
//! Browser Profile, or arbitrary host command is represented here.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use hartevo_capability_gateway::{
    CapabilityClass, CapabilityCompositionSnapshot, CapabilityGateway,
    CapabilityInvocationCloseReason, CapabilityInvocationContext,
    CapabilityInvocationEffectReceipt, CapabilityInvocationError, CapabilityInvocationLease,
    CapabilityInvocationLog, CapabilityInvocationLogReference, CapabilityInvocationReleaseReceipt,
    CapabilityInvocationVisibility, CapabilityReleaseReceipt, CapabilityRequest,
    CapabilityResolutionAuditLedger, CapabilityResolutionError, CapabilityResolutionLease,
    CapabilityResult, CapabilityVersion, Digest as GatewayDigest, SignedCapabilityManifest,
};
use serde::{
    Deserialize, Serialize, Serializer,
    ser::{Error as SerdeError, SerializeStruct},
};
use thiserror::Error;

use crate::skill::{
    SkillEffectClass, SkillItemId, SkillPackAuditLogError, SkillPackContextReceipt, SkillPackError,
    SkillPackHostAdapter, SkillPackMissionContext, SkillPackModelContext, SkillPackProvider,
    SkillToolRequirement,
};
use crate::{Digest, PluginRuntime, PluginVersion};

pub const SKILL_PACK_INVOCATION_SCHEMA: &str = "hartevo.skill-pack-invocation/v1";
pub const SKILL_PACK_INVOCATION_LOG_SCHEMA: &str = "hartevo.skill-pack-invocation-log/v1";
pub const SKILL_PACK_RESULT_SCHEMA: &str = "hartevo.skill-pack-result/v1";

/// The model-facing selector is deliberately digest-only when serialized.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackInvocationItemKind {
    Instruction,
    Recipe,
}

#[derive(Clone, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct SkillPackInvocationSelector {
    item_id: SkillItemId,
    item_kind: SkillPackInvocationItemKind,
    item_content_digest: Digest,
}

impl SkillPackInvocationSelector {
    pub fn new(
        item_id: SkillItemId,
        item_kind: SkillPackInvocationItemKind,
        item_content_digest: Digest,
    ) -> Result<Self, SkillPackInvocationError> {
        if !is_skill_digest(&item_content_digest) {
            return Err(SkillPackInvocationError::InvalidSelector);
        }
        Ok(Self {
            item_id,
            item_kind,
            item_content_digest,
        })
    }

    pub fn item_id(&self) -> &SkillItemId {
        &self.item_id
    }

    pub const fn item_kind(&self) -> SkillPackInvocationItemKind {
        self.item_kind
    }

    pub fn item_content_digest(&self) -> &Digest {
        &self.item_content_digest
    }

    fn id_digest(&self) -> Digest {
        Digest::from_text(self.item_id.as_str())
    }

    fn validate_against(
        &self,
        model: &SkillPackModelContext,
    ) -> Result<(), SkillPackInvocationError> {
        let found = match self.item_kind {
            SkillPackInvocationItemKind::Instruction => model.instructions().iter().any(|item| {
                item.id() == &self.item_id && item.content_digest() == self.item_content_digest
            }),
            SkillPackInvocationItemKind::Recipe => model.recipes().iter().any(|item| {
                item.id() == &self.item_id && item.content_digest() == self.item_content_digest
            }),
        };
        if found {
            Ok(())
        } else {
            Err(SkillPackInvocationError::ItemNotVisible)
        }
    }
}

impl Serialize for SkillPackInvocationSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SkillPackInvocationSelector", 4)?;
        state.serialize_field("itemIdDigest", &self.id_digest())?;
        state.serialize_field("itemKind", &self.item_kind)?;
        state.serialize_field("itemContentDigest", &self.item_content_digest)?;
        state.serialize_field("schema", SKILL_PACK_INVOCATION_SCHEMA)?;
        state.end()
    }
}

impl fmt::Debug for SkillPackInvocationSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationSelector")
            .field("item_id_digest", &self.id_digest())
            .field("item_kind", &self.item_kind)
            .field("item_content_digest", &self.item_content_digest)
            .finish_non_exhaustive()
    }
}

/// All Skill Pack and Gateway authority facts needed to audit one proposal.
/// It contains only identifiers, versions and digests; package text and
/// request/result bytes remain behind typed accessors on the execution path.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackInvocationBinding {
    package_digest: Digest,
    plugin_digest: Digest,
    package_id_digest: Digest,
    skill_id_digest: Digest,
    skill_version: PluginVersion,
    source_digest: Digest,
    manifest_digest: Digest,
    content_digest: Digest,
    verification_receipt_digest: Digest,
    host_api: PluginVersion,
    project_digest: Digest,
    mission_digest: Digest,
    scope_digest: Digest,
    generation: u64,
    skill_policy_digest: Digest,
    skill_context_receipt_digest: Digest,
    skill_resolution_digest: Digest,
    item_id_digest: Digest,
    item_content_digest: Digest,
    gateway_binding_digest: GatewayDigest,
    gateway_manifest_digest: GatewayDigest,
    gateway_authority_digest: GatewayDigest,
    gateway_provider_digest: GatewayDigest,
    gateway_policy_digest: GatewayDigest,
    gateway_request_digest: GatewayDigest,
    gateway_composition_digest: GatewayDigest,
    gateway_scope_digest: GatewayDigest,
    gateway_provider_generation: u64,
    gateway_composition_revision: u64,
    capability_class: CapabilityClass,
    provider_version: CapabilityVersion,
    item_kind: SkillPackInvocationItemKind,
}

impl SkillPackInvocationBinding {
    fn from_parts(
        provider: &impl SkillPackBindingView,
        context: &SkillPackMissionContext,
        model: &SkillPackModelContext,
        selector: &SkillPackInvocationSelector,
        resolved: &CapabilityResolutionLease,
        request: &CapabilityRequest,
    ) -> Self {
        let binding = resolved.binding();
        let receipt = model.receipt();
        Self {
            package_digest: provider.package_digest().clone(),
            plugin_digest: provider.plugin_digest().clone(),
            package_id_digest: provider.package_id_digest().clone(),
            skill_id_digest: provider.skill_id_digest().clone(),
            skill_version: provider.skill_version(),
            source_digest: provider.source_digest().clone(),
            manifest_digest: provider.manifest_digest().clone(),
            content_digest: provider.content_digest().clone(),
            verification_receipt_digest: provider.verification_receipt_digest().clone(),
            host_api: provider.host_api(),
            project_digest: Digest::from_text(context.scope().project_id().as_str()),
            mission_digest: Digest::from_text(context.scope().mission_id().as_str()),
            scope_digest: context.scope().digest(),
            generation: context.scope().generation(),
            skill_policy_digest: context.policy_digest().clone(),
            skill_context_receipt_digest: receipt.digest().clone(),
            skill_resolution_digest: model.resolution().digest().clone(),
            item_id_digest: selector.id_digest(),
            item_content_digest: selector.item_content_digest().clone(),
            gateway_binding_digest: binding.digest().clone(),
            gateway_manifest_digest: binding.manifest_digest().clone(),
            gateway_authority_digest: binding.authority_digest().clone(),
            gateway_provider_digest: binding.provider_digest().clone(),
            gateway_policy_digest: binding.policy_digest().clone(),
            gateway_request_digest: request.digest(),
            gateway_composition_digest: binding.composition_digest().clone(),
            gateway_scope_digest: binding.scope().scope_digest.clone(),
            gateway_provider_generation: binding.provider_generation(),
            gateway_composition_revision: binding.composition_revision(),
            capability_class: resolved.invocation_permit().class,
            provider_version: binding.version(),
            item_kind: selector.item_kind(),
        }
    }

    pub fn package_digest(&self) -> &Digest {
        &self.package_digest
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.plugin_digest
    }

    pub fn package_id_digest(&self) -> &Digest {
        &self.package_id_digest
    }

    pub fn skill_id_digest(&self) -> &Digest {
        &self.skill_id_digest
    }

    pub const fn skill_version(&self) -> PluginVersion {
        self.skill_version
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub fn verification_receipt_digest(&self) -> &Digest {
        &self.verification_receipt_digest
    }

    pub const fn host_api(&self) -> PluginVersion {
        self.host_api
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn skill_policy_digest(&self) -> &Digest {
        &self.skill_policy_digest
    }

    pub fn skill_context_receipt_digest(&self) -> &Digest {
        &self.skill_context_receipt_digest
    }

    pub fn skill_resolution_digest(&self) -> &Digest {
        &self.skill_resolution_digest
    }

    pub fn item_id_digest(&self) -> &Digest {
        &self.item_id_digest
    }

    pub fn item_content_digest(&self) -> &Digest {
        &self.item_content_digest
    }

    pub fn gateway_binding_digest(&self) -> &GatewayDigest {
        &self.gateway_binding_digest
    }

    pub fn gateway_manifest_digest(&self) -> &GatewayDigest {
        &self.gateway_manifest_digest
    }

    pub fn gateway_authority_digest(&self) -> &GatewayDigest {
        &self.gateway_authority_digest
    }

    pub fn gateway_provider_digest(&self) -> &GatewayDigest {
        &self.gateway_provider_digest
    }

    pub fn gateway_policy_digest(&self) -> &GatewayDigest {
        &self.gateway_policy_digest
    }

    pub fn gateway_request_digest(&self) -> &GatewayDigest {
        &self.gateway_request_digest
    }

    pub fn gateway_composition_digest(&self) -> &GatewayDigest {
        &self.gateway_composition_digest
    }

    pub fn gateway_scope_digest(&self) -> &GatewayDigest {
        &self.gateway_scope_digest
    }

    pub const fn gateway_provider_generation(&self) -> u64 {
        self.gateway_provider_generation
    }

    pub const fn gateway_composition_revision(&self) -> u64 {
        self.gateway_composition_revision
    }

    pub const fn capability_class(&self) -> CapabilityClass {
        self.capability_class
    }

    pub const fn provider_version(&self) -> CapabilityVersion {
        self.provider_version
    }

    pub const fn item_kind(&self) -> SkillPackInvocationItemKind {
        self.item_kind
    }
}

impl fmt::Debug for SkillPackInvocationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationBinding")
            .field("package_digest", &self.package_digest)
            .field("plugin_digest", &self.plugin_digest)
            .field("package_id_digest", &self.package_id_digest)
            .field("skill_id_digest", &self.skill_id_digest)
            .field("skill_version", &self.skill_version)
            .field("source_digest", &self.source_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("content_digest", &self.content_digest)
            .field(
                "verification_receipt_digest",
                &self.verification_receipt_digest,
            )
            .field("host_api", &self.host_api)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("skill_policy_digest", &self.skill_policy_digest)
            .field(
                "skill_context_receipt_digest",
                &self.skill_context_receipt_digest,
            )
            .field("skill_resolution_digest", &self.skill_resolution_digest)
            .field("item_id_digest", &self.item_id_digest)
            .field("item_content_digest", &self.item_content_digest)
            .field("gateway_binding_digest", &self.gateway_binding_digest)
            .field("gateway_manifest_digest", &self.gateway_manifest_digest)
            .field("gateway_authority_digest", &self.gateway_authority_digest)
            .field("gateway_provider_digest", &self.gateway_provider_digest)
            .field("gateway_policy_digest", &self.gateway_policy_digest)
            .field("gateway_request_digest", &self.gateway_request_digest)
            .field(
                "gateway_composition_digest",
                &self.gateway_composition_digest,
            )
            .field("gateway_scope_digest", &self.gateway_scope_digest)
            .field(
                "gateway_provider_generation",
                &self.gateway_provider_generation,
            )
            .field(
                "gateway_composition_revision",
                &self.gateway_composition_revision,
            )
            .field("capability_class", &self.capability_class)
            .field("provider_version", &self.provider_version)
            .field("item_kind", &self.item_kind)
            .finish_non_exhaustive()
    }
}

/// A content-free durable event for the Skill Pack side of the closure.
/// Capability Gateway has its own invocation log; this log joins the Gateway
/// event to the verified package/context without becoming another registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackInvocationEvent {
    schema: String,
    event_digest: Digest,
    kind: SkillPackInvocationEventKind,
    invocation_digest: GatewayDigest,
    binding: SkillPackInvocationBinding,
    prior_event_digest: Option<Digest>,
    result_digest: Option<GatewayDigest>,
    effect_receipt_digest: Option<GatewayDigest>,
    reason: Option<CapabilityInvocationCloseReason>,
    observed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackInvocationEventKind {
    Proposed,
    Completed,
    Invalidated,
}

impl SkillPackInvocationEvent {
    fn proposed(
        invocation_digest: GatewayDigest,
        binding: SkillPackInvocationBinding,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self::new(
            SkillPackInvocationEventKind::Proposed,
            invocation_digest,
            binding,
            None,
            None,
            None,
            None,
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn terminal(
        kind: SkillPackInvocationEventKind,
        invocation_digest: GatewayDigest,
        binding: SkillPackInvocationBinding,
        prior_event_digest: Digest,
        result_digest: Option<GatewayDigest>,
        effect_receipt_digest: Option<GatewayDigest>,
        reason: Option<CapabilityInvocationCloseReason>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self::new(
            kind,
            invocation_digest,
            binding,
            Some(prior_event_digest),
            result_digest,
            effect_receipt_digest,
            reason,
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        kind: SkillPackInvocationEventKind,
        invocation_digest: GatewayDigest,
        binding: SkillPackInvocationBinding,
        prior_event_digest: Option<Digest>,
        result_digest: Option<GatewayDigest>,
        effect_receipt_digest: Option<GatewayDigest>,
        reason: Option<CapabilityInvocationCloseReason>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let mut event = Self {
            schema: SKILL_PACK_INVOCATION_LOG_SCHEMA.into(),
            event_digest: Digest::from_text("pending-skill-invocation-event"),
            kind,
            invocation_digest,
            binding,
            prior_event_digest,
            result_digest,
            effect_receipt_digest,
            reason,
            observed_at,
        };
        event.event_digest = event.computed_digest();
        event
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.schema,
            self.kind,
            &self.invocation_digest,
            &self.binding,
            &self.prior_event_digest,
            &self.result_digest,
            &self.effect_receipt_digest,
            &self.reason,
            self.observed_at,
        ))
    }

    fn validate(&self) -> Result<(), SkillPackInvocationLogError> {
        if self.schema != SKILL_PACK_INVOCATION_LOG_SCHEMA
            || !is_skill_digest(&self.event_digest)
            || self.event_digest != self.computed_digest()
            || self.binding.generation == 0
            || self.binding.generation != self.binding.gateway_provider_generation
            || self.binding.scope_digest.as_str() != self.binding.gateway_scope_digest.as_str()
            || self.binding.gateway_provider_generation == 0
            || self.binding.gateway_composition_revision == 0
            || !is_gateway_digest(&self.invocation_digest)
            || self.observed_at.timestamp() < 0
            || [
                &self.binding.package_digest,
                &self.binding.plugin_digest,
                &self.binding.package_id_digest,
                &self.binding.skill_id_digest,
                &self.binding.source_digest,
                &self.binding.manifest_digest,
                &self.binding.content_digest,
                &self.binding.verification_receipt_digest,
                &self.binding.project_digest,
                &self.binding.mission_digest,
                &self.binding.scope_digest,
                &self.binding.skill_policy_digest,
                &self.binding.skill_context_receipt_digest,
                &self.binding.skill_resolution_digest,
                &self.binding.item_id_digest,
                &self.binding.item_content_digest,
            ]
            .iter()
            .any(|digest| !is_skill_digest(digest))
            || [
                &self.binding.gateway_binding_digest,
                &self.binding.gateway_manifest_digest,
                &self.binding.gateway_authority_digest,
                &self.binding.gateway_provider_digest,
                &self.binding.gateway_policy_digest,
                &self.binding.gateway_request_digest,
                &self.binding.gateway_composition_digest,
                &self.binding.gateway_scope_digest,
            ]
            .iter()
            .any(|digest| !is_gateway_digest(digest))
        {
            return Err(SkillPackInvocationLogError::InvalidEvent);
        }
        match self.kind {
            SkillPackInvocationEventKind::Proposed => {
                if self.prior_event_digest.is_some()
                    || self.result_digest.is_some()
                    || self.effect_receipt_digest.is_some()
                    || self.reason.is_some()
                {
                    return Err(SkillPackInvocationLogError::InvalidEvent);
                }
            }
            SkillPackInvocationEventKind::Completed => {
                if self.prior_event_digest.is_none()
                    || self.result_digest.is_none()
                    || self.reason.is_some()
                    || (self.binding.capability_class == CapabilityClass::ExternalEffect
                        && self.effect_receipt_digest.is_none())
                {
                    return Err(SkillPackInvocationLogError::InvalidEvent);
                }
            }
            SkillPackInvocationEventKind::Invalidated => {
                if self.prior_event_digest.is_none()
                    || self.result_digest.is_some()
                    || self.effect_receipt_digest.is_some()
                    || self.reason.is_none()
                {
                    return Err(SkillPackInvocationLogError::InvalidEvent);
                }
            }
        }
        if self
            .prior_event_digest
            .as_ref()
            .is_some_and(|digest| !is_skill_digest(digest))
            || self
                .result_digest
                .as_ref()
                .is_some_and(|digest| !is_gateway_digest(digest))
            || self
                .effect_receipt_digest
                .as_ref()
                .is_some_and(|digest| !is_gateway_digest(digest))
        {
            return Err(SkillPackInvocationLogError::InvalidEvent);
        }
        Ok(())
    }

    pub fn kind(&self) -> SkillPackInvocationEventKind {
        self.kind
    }

    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn invocation_digest(&self) -> &GatewayDigest {
        &self.invocation_digest
    }

    pub fn binding(&self) -> &SkillPackInvocationBinding {
        &self.binding
    }

    pub fn result_digest(&self) -> Option<&GatewayDigest> {
        self.result_digest.as_ref()
    }

    pub fn effect_receipt_digest(&self) -> Option<&GatewayDigest> {
        self.effect_receipt_digest.as_ref()
    }

    pub fn reason(&self) -> Option<CapabilityInvocationCloseReason> {
        self.reason
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SkillPackInvocationLogError {
    #[error("Skill Pack invocation log is unavailable")]
    Unavailable,
    #[error("Skill Pack invocation log transition conflicts with durable state")]
    Conflict,
    #[error("Skill Pack invocation log transition is invalid")]
    InvalidTransition,
    #[error("Skill Pack invocation log event is invalid")]
    InvalidEvent,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackInvocationLogReference {
    event_digest: Digest,
}

impl SkillPackInvocationLogReference {
    fn from_event(event: &SkillPackInvocationEvent) -> Self {
        Self {
            event_digest: event.event_digest.clone(),
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.event_digest
    }
}

impl fmt::Debug for SkillPackInvocationLogReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationLogReference")
            .field("event_digest", &self.event_digest)
            .finish()
    }
}

pub trait SkillPackInvocationLog {
    fn append(
        &mut self,
        event: SkillPackInvocationEvent,
    ) -> Result<SkillPackInvocationLogReference, SkillPackInvocationLogError>;
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct MemorySkillPackInvocationLog {
    events: Vec<SkillPackInvocationEvent>,
    active: BTreeSet<GatewayDigest>,
    closed: BTreeSet<GatewayDigest>,
    last: BTreeMap<GatewayDigest, (Digest, SkillPackInvocationEventKind)>,
}

impl MemorySkillPackInvocationLog {
    pub fn events(&self) -> &[SkillPackInvocationEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl SkillPackInvocationLog for MemorySkillPackInvocationLog {
    fn append(
        &mut self,
        event: SkillPackInvocationEvent,
    ) -> Result<SkillPackInvocationLogReference, SkillPackInvocationLogError> {
        event.validate()?;
        if self
            .events
            .iter()
            .any(|existing| existing.event_digest == event.event_digest)
        {
            return Err(SkillPackInvocationLogError::Conflict);
        }
        let invocation = event.invocation_digest.clone();
        match event.kind {
            SkillPackInvocationEventKind::Proposed => {
                if self.active.contains(&invocation)
                    || self.closed.contains(&invocation)
                    || self.last.contains_key(&invocation)
                {
                    return Err(SkillPackInvocationLogError::Conflict);
                }
                self.active.insert(invocation.clone());
            }
            SkillPackInvocationEventKind::Completed | SkillPackInvocationEventKind::Invalidated => {
                if !self.active.contains(&invocation) {
                    return Err(SkillPackInvocationLogError::InvalidTransition);
                }
                let Some((prior_digest, prior_kind)) = self.last.get(&invocation) else {
                    return Err(SkillPackInvocationLogError::InvalidTransition);
                };
                if event.prior_event_digest.as_ref() != Some(prior_digest)
                    || *prior_kind != SkillPackInvocationEventKind::Proposed
                {
                    return Err(SkillPackInvocationLogError::InvalidTransition);
                }
                self.active.remove(&invocation);
                if !self.closed.insert(invocation.clone()) {
                    return Err(SkillPackInvocationLogError::Conflict);
                }
            }
        }
        self.last
            .insert(invocation, (event.event_digest.clone(), event.kind));
        let reference = SkillPackInvocationLogReference::from_event(&event);
        self.events.push(event);
        Ok(reference)
    }
}

impl fmt::Debug for MemorySkillPackInvocationLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemorySkillPackInvocationLog")
            .field("event_count", &self.events.len())
            .field("active_count", &self.active.len())
            .field("closed_count", &self.closed.len())
            .field("event_set_digest", &Digest::from_serialized(&self.events))
            .finish_non_exhaustive()
    }
}

/// A proposal is single-use by ownership. Its request, signed manifest and
/// composition snapshot are private so the consumer cannot obtain an adapter
/// handle or turn the proposal into arbitrary host execution.
pub struct SkillPackInvocationProposal {
    binding: SkillPackInvocationBinding,
    selector: SkillPackInvocationSelector,
    requirement: SkillToolRequirement,
    context_receipt: SkillPackContextReceipt,
    resolved: CapabilityResolutionLease,
    composition: CapabilityCompositionSnapshot,
    manifest: SignedCapabilityManifest,
    request: CapabilityRequest,
    invocation_context: CapabilityInvocationContext,
    proposal_digest: GatewayDigest,
    log_reference: SkillPackInvocationLogReference,
}

impl SkillPackInvocationProposal {
    pub fn binding(&self) -> &SkillPackInvocationBinding {
        &self.binding
    }

    pub fn selector(&self) -> &SkillPackInvocationSelector {
        &self.selector
    }

    pub fn requirement(&self) -> &SkillToolRequirement {
        &self.requirement
    }

    pub fn proposal_digest(&self) -> &GatewayDigest {
        &self.proposal_digest
    }

    pub fn log_reference(&self) -> &SkillPackInvocationLogReference {
        &self.log_reference
    }

    pub fn invocation_context(&self) -> &CapabilityInvocationContext {
        &self.invocation_context
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin<H, L, R, S>(
        self,
        provider: &mut SkillPackProvider<H>,
        context: &SkillPackMissionContext,
        runtime: &PluginRuntime,
        gateway: &CapabilityGateway,
        invocation_log: &mut L,
        skill_log: &mut S,
        resolution_audit: &mut R,
        observed_at: DateTime<Utc>,
    ) -> Result<SkillPackInvocationLease, SkillPackInvocationError>
    where
        H: SkillPackHostAdapter,
        L: CapabilityInvocationLog,
        R: CapabilityResolutionAuditLedger,
        S: SkillPackInvocationLog,
    {
        let Self {
            binding,
            selector,
            requirement,
            context_receipt,
            resolved,
            composition,
            manifest,
            request,
            invocation_context,
            proposal_digest,
            log_reference,
        } = self;
        if let Err(error) = provider.validate_context_receipt(context, &context_receipt, runtime) {
            let error = SkillPackInvocationError::Provider(error);
            let reason = match &error {
                SkillPackInvocationError::Provider(error) => provider_close_reason(*error),
                _ => CapabilityInvocationCloseReason::Crashed,
            };
            return reject_proposal(
                resolved,
                binding,
                proposal_digest,
                &log_reference,
                reason,
                observed_at,
                resolution_audit,
                skill_log,
                error,
            );
        }
        let resolver = gateway.invocation_resolver();
        let invocation = match resolver.begin_invocation(
            &resolved,
            &composition,
            &manifest,
            &request,
            &invocation_context,
            observed_at,
            invocation_log,
        ) {
            Ok(invocation) => invocation,
            Err(error) => {
                return reject_proposal(
                    resolved,
                    binding,
                    proposal_digest,
                    &log_reference,
                    invocation_close_reason(&error),
                    observed_at,
                    resolution_audit,
                    skill_log,
                    SkillPackInvocationError::Invocation(error),
                );
            }
        };
        Ok(SkillPackInvocationLease {
            binding,
            selector,
            requirement,
            context_receipt,
            composition,
            manifest,
            request,
            invocation_context,
            proposal_digest,
            proposal_log_reference: log_reference,
            invocation,
            resolution_released: false,
        })
    }

    pub fn cancel<L, R>(
        self,
        resolution_audit: &mut R,
        invocation_log: &mut L,
        observed_at: DateTime<Utc>,
        reason: CapabilityInvocationCloseReason,
    ) -> Result<SkillPackInvocationCancellation, SkillPackInvocationError>
    where
        L: SkillPackInvocationLog,
        R: CapabilityResolutionAuditLedger,
    {
        let Self {
            binding,
            proposal_digest,
            log_reference,
            mut resolved,
            ..
        } = self;
        let event = SkillPackInvocationEvent::terminal(
            SkillPackInvocationEventKind::Invalidated,
            proposal_digest.clone(),
            binding.clone(),
            log_reference.digest().clone(),
            None,
            None,
            Some(reason),
            observed_at,
        );
        let skill_reference = invocation_log.append(event)?;
        let resolution_release = resolved
            .release(observed_at, resolution_audit)
            .map_err(SkillPackInvocationError::Resolution)?;
        Ok(SkillPackInvocationCancellation {
            proposal_digest,
            binding,
            reason,
            skill_reference,
            resolution_release,
        })
    }
}

impl fmt::Debug for SkillPackInvocationProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationProposal")
            .field("binding", &self.binding)
            .field("selector", &self.selector)
            .field(
                "requirement_digest",
                &Digest::from_serialized(&self.requirement),
            )
            .field("context_receipt_digest", self.context_receipt.digest())
            .field("resolved_binding_digest", self.resolved.binding().digest())
            .field("composition", &self.composition)
            .field("request_digest", &self.request.digest())
            .field("invocation_context", &self.invocation_context)
            .field("proposal_digest", &self.proposal_digest)
            .field("log_reference", &self.log_reference)
            .finish_non_exhaustive()
    }
}

impl Serialize for SkillPackInvocationProposal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let manifest_digest = self
            .manifest
            .digest()
            .map_err(|error| S::Error::custom(error.to_string()))?;
        let mut state = serializer.serialize_struct("SkillPackInvocationProposal", 18)?;
        state.serialize_field("schema", SKILL_PACK_INVOCATION_SCHEMA)?;
        state.serialize_field("binding", &self.binding)?;
        state.serialize_field("selector", &self.selector)?;
        state.serialize_field(
            "requirementDigest",
            &Digest::from_serialized(&self.requirement),
        )?;
        state.serialize_field("contextReceiptDigest", self.context_receipt.digest())?;
        state.serialize_field("resolvedBindingDigest", self.resolved.binding().digest())?;
        state.serialize_field("compositionDigest", self.composition.digest())?;
        state.serialize_field("manifestDigest", &manifest_digest)?;
        state.serialize_field("requestDigest", &self.request.digest())?;
        state.serialize_field(
            "invocationProjectIdDigest",
            &GatewayDigest::from_text(self.invocation_context.project_id().as_str()),
        )?;
        state.serialize_field(
            "invocationMissionIdDigest",
            &GatewayDigest::from_text(self.invocation_context.mission_id().as_str()),
        )?;
        state.serialize_field(
            "invocationGeneration",
            &self.invocation_context.generation(),
        )?;
        state.serialize_field(
            "invocationCompositionRevision",
            &self.invocation_context.composition_revision(),
        )?;
        state.serialize_field(
            "invocationProviderGeneration",
            &self.invocation_context.provider_generation(),
        )?;
        state.serialize_field(
            "invocationPolicyDigest",
            self.invocation_context.policy_digest(),
        )?;
        state.serialize_field(
            "invocationVisibility",
            &self.invocation_context.visibility(),
        )?;
        state.serialize_field("proposalDigest", &self.proposal_digest)?;
        state.serialize_field("logReference", &self.log_reference)?;
        state.end()
    }
}

pub struct SkillPackInvocationLease {
    binding: SkillPackInvocationBinding,
    selector: SkillPackInvocationSelector,
    requirement: SkillToolRequirement,
    context_receipt: SkillPackContextReceipt,
    composition: CapabilityCompositionSnapshot,
    manifest: SignedCapabilityManifest,
    request: CapabilityRequest,
    invocation_context: CapabilityInvocationContext,
    proposal_digest: GatewayDigest,
    proposal_log_reference: SkillPackInvocationLogReference,
    invocation: CapabilityInvocationLease,
    resolution_released: bool,
}

impl SkillPackInvocationLease {
    pub fn binding(&self) -> &SkillPackInvocationBinding {
        &self.binding
    }

    pub fn selector(&self) -> &SkillPackInvocationSelector {
        &self.selector
    }

    pub fn requirement(&self) -> &SkillToolRequirement {
        &self.requirement
    }

    pub fn proposal_digest(&self) -> &GatewayDigest {
        &self.proposal_digest
    }

    pub fn invocation_digest(&self) -> &GatewayDigest {
        self.invocation.invocation_digest()
    }

    pub fn log_reference(&self) -> &CapabilityInvocationLogReference {
        self.invocation.log_reference()
    }

    pub const fn is_released(&self) -> bool {
        self.invocation.is_released()
    }

    fn release_resolution<R>(
        &mut self,
        resolution_audit: &mut R,
        observed_at: DateTime<Utc>,
    ) -> Result<CapabilityReleaseReceipt, SkillPackInvocationError>
    where
        R: CapabilityResolutionAuditLedger,
    {
        if self.resolution_released {
            return Err(SkillPackInvocationError::ResolutionAlreadyReleased);
        }
        let release = self
            .invocation
            .release_resolution(observed_at, resolution_audit)
            .map_err(SkillPackInvocationError::Invocation)?;
        self.resolution_released = true;
        Ok(release)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete<H, L, R, S>(
        &mut self,
        provider: &mut SkillPackProvider<H>,
        context: &SkillPackMissionContext,
        runtime: &PluginRuntime,
        gateway: &CapabilityGateway,
        result: CapabilityResult,
        effect_receipt: Option<&CapabilityInvocationEffectReceipt>,
        invocation_log: &mut L,
        resolution_audit: &mut R,
        skill_log: &mut S,
        observed_at: DateTime<Utc>,
    ) -> Result<SkillPackInvocationResult, SkillPackInvocationError>
    where
        H: SkillPackHostAdapter,
        L: CapabilityInvocationLog,
        R: CapabilityResolutionAuditLedger,
        S: SkillPackInvocationLog,
    {
        if self.is_released() {
            return Err(SkillPackInvocationError::Invocation(
                CapabilityInvocationError::AlreadyReleased,
            ));
        }
        if let Err(error) =
            provider.validate_context_receipt(context, &self.context_receipt, runtime)
        {
            let reason = provider_close_reason(error);
            self.close_after_provider_error(
                reason,
                invocation_log,
                resolution_audit,
                skill_log,
                observed_at,
            )?;
            return Err(SkillPackInvocationError::Provider(error));
        }
        let resolver = gateway.invocation_resolver();
        let terminal = resolver.complete_invocation(
            &mut self.invocation,
            &self.composition,
            &self.manifest,
            &self.request,
            &result,
            effect_receipt,
            observed_at,
            invocation_log,
        );
        let release = match terminal {
            Ok(release) => release,
            Err(error) => {
                let reason = invocation_close_reason(&error);
                if !self.is_released() {
                    self.invocation
                        .crash(observed_at, invocation_log)
                        .map_err(SkillPackInvocationError::Invocation)?;
                }
                let _ = self.release_resolution(resolution_audit, observed_at)?;
                let event = SkillPackInvocationEvent::terminal(
                    SkillPackInvocationEventKind::Invalidated,
                    self.proposal_digest.clone(),
                    self.binding.clone(),
                    self.proposal_log_reference.digest().clone(),
                    None,
                    None,
                    Some(reason),
                    observed_at,
                );
                skill_log.append(event)?;
                return Err(SkillPackInvocationError::Invocation(error));
            }
        };
        let resolution_release = self.release_resolution(resolution_audit, observed_at)?;
        let effect_receipt_digest = effect_receipt.map(|receipt| receipt.receipt_digest().clone());
        let event = SkillPackInvocationEvent::terminal(
            SkillPackInvocationEventKind::Completed,
            self.proposal_digest.clone(),
            self.binding.clone(),
            self.proposal_log_reference.digest().clone(),
            Some(result.digest()),
            effect_receipt_digest,
            None,
            observed_at,
        );
        let skill_reference = skill_log.append(event)?;
        Ok(SkillPackInvocationResult {
            binding: self.binding.clone(),
            proposal_digest: self.proposal_digest.clone(),
            result_digest: result.digest(),
            result,
            gateway_release: release,
            resolution_release,
            skill_reference,
        })
    }

    pub fn timeout<L, R, S>(
        &mut self,
        invocation_log: &mut L,
        resolution_audit: &mut R,
        skill_log: &mut S,
        observed_at: DateTime<Utc>,
    ) -> Result<SkillPackInvocationTermination, SkillPackInvocationError>
    where
        L: CapabilityInvocationLog,
        R: CapabilityResolutionAuditLedger,
        S: SkillPackInvocationLog,
    {
        self.close(
            CapabilityInvocationCloseReason::Timeout,
            CapabilityInvocationLease::timeout,
            invocation_log,
            resolution_audit,
            skill_log,
            observed_at,
        )
    }

    pub fn cancel<L, R, S>(
        &mut self,
        invocation_log: &mut L,
        resolution_audit: &mut R,
        skill_log: &mut S,
        observed_at: DateTime<Utc>,
    ) -> Result<SkillPackInvocationTermination, SkillPackInvocationError>
    where
        L: CapabilityInvocationLog,
        R: CapabilityResolutionAuditLedger,
        S: SkillPackInvocationLog,
    {
        self.close(
            CapabilityInvocationCloseReason::Cancelled,
            CapabilityInvocationLease::cancel,
            invocation_log,
            resolution_audit,
            skill_log,
            observed_at,
        )
    }

    pub fn crash<L, R, S>(
        &mut self,
        invocation_log: &mut L,
        resolution_audit: &mut R,
        skill_log: &mut S,
        observed_at: DateTime<Utc>,
    ) -> Result<SkillPackInvocationTermination, SkillPackInvocationError>
    where
        L: CapabilityInvocationLog,
        R: CapabilityResolutionAuditLedger,
        S: SkillPackInvocationLog,
    {
        self.close(
            CapabilityInvocationCloseReason::Crashed,
            CapabilityInvocationLease::crash,
            invocation_log,
            resolution_audit,
            skill_log,
            observed_at,
        )
    }

    fn close<L, R, S, F>(
        &mut self,
        reason: CapabilityInvocationCloseReason,
        finish: F,
        invocation_log: &mut L,
        resolution_audit: &mut R,
        skill_log: &mut S,
        observed_at: DateTime<Utc>,
    ) -> Result<SkillPackInvocationTermination, SkillPackInvocationError>
    where
        L: CapabilityInvocationLog,
        R: CapabilityResolutionAuditLedger,
        S: SkillPackInvocationLog,
        F: FnOnce(
            &mut CapabilityInvocationLease,
            DateTime<Utc>,
            &mut L,
        ) -> Result<CapabilityInvocationReleaseReceipt, CapabilityInvocationError>,
    {
        if self.is_released() {
            return Err(SkillPackInvocationError::Invocation(
                CapabilityInvocationError::AlreadyReleased,
            ));
        }
        let gateway_release = finish(&mut self.invocation, observed_at, invocation_log)
            .map_err(SkillPackInvocationError::Invocation)?;
        let resolution_release = self.release_resolution(resolution_audit, observed_at)?;
        let event = SkillPackInvocationEvent::terminal(
            SkillPackInvocationEventKind::Invalidated,
            self.proposal_digest.clone(),
            self.binding.clone(),
            self.proposal_log_reference.digest().clone(),
            None,
            None,
            Some(reason),
            observed_at,
        );
        let skill_reference = skill_log.append(event)?;
        Ok(SkillPackInvocationTermination {
            binding: self.binding.clone(),
            proposal_digest: self.proposal_digest.clone(),
            reason,
            gateway_release,
            resolution_release,
            skill_reference,
        })
    }

    fn close_after_provider_error<L, R, S>(
        &mut self,
        reason: CapabilityInvocationCloseReason,
        invocation_log: &mut L,
        resolution_audit: &mut R,
        skill_log: &mut S,
        observed_at: DateTime<Utc>,
    ) -> Result<SkillPackInvocationTermination, SkillPackInvocationError>
    where
        L: CapabilityInvocationLog,
        R: CapabilityResolutionAuditLedger,
        S: SkillPackInvocationLog,
    {
        self.close(
            reason,
            |invocation, observed_at, log| invocation.invalidate(reason, observed_at, log),
            invocation_log,
            resolution_audit,
            skill_log,
            observed_at,
        )
    }
}

impl fmt::Debug for SkillPackInvocationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationLease")
            .field("binding", &self.binding)
            .field("selector", &self.selector)
            .field(
                "requirement_digest",
                &Digest::from_serialized(&self.requirement),
            )
            .field("context_receipt_digest", self.context_receipt.digest())
            .field("composition", &self.composition)
            .field("request_digest", &self.request.digest())
            .field("invocation_context", &self.invocation_context)
            .field("proposal_digest", &self.proposal_digest)
            .field("proposal_log_reference", &self.proposal_log_reference)
            .field("invocation", &self.invocation)
            .field("resolution_released", &self.resolution_released)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackInvocationResult {
    binding: SkillPackInvocationBinding,
    proposal_digest: GatewayDigest,
    result_digest: GatewayDigest,
    gateway_release: CapabilityInvocationReleaseReceipt,
    resolution_release: CapabilityReleaseReceipt,
    skill_reference: SkillPackInvocationLogReference,
    #[serde(rename = "typedResult")]
    result: CapabilityResult,
}

impl SkillPackInvocationResult {
    pub fn binding(&self) -> &SkillPackInvocationBinding {
        &self.binding
    }

    pub fn proposal_digest(&self) -> &GatewayDigest {
        &self.proposal_digest
    }

    pub fn result(&self) -> &CapabilityResult {
        &self.result
    }

    pub fn result_digest(&self) -> &GatewayDigest {
        &self.result_digest
    }

    pub fn gateway_release(&self) -> &CapabilityInvocationReleaseReceipt {
        &self.gateway_release
    }

    pub fn resolution_release(&self) -> &CapabilityReleaseReceipt {
        &self.resolution_release
    }

    pub fn skill_log_reference(&self) -> &SkillPackInvocationLogReference {
        &self.skill_reference
    }
}

impl fmt::Debug for SkillPackInvocationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationResult")
            .field("binding", &self.binding)
            .field("proposal_digest", &self.proposal_digest)
            .field("result_digest", &self.result_digest)
            .field("gateway_release", &self.gateway_release)
            .field("resolution_release", &self.resolution_release)
            .field("skill_reference", &self.skill_reference)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackInvocationTermination {
    binding: SkillPackInvocationBinding,
    proposal_digest: GatewayDigest,
    reason: CapabilityInvocationCloseReason,
    gateway_release: CapabilityInvocationReleaseReceipt,
    resolution_release: CapabilityReleaseReceipt,
    skill_reference: SkillPackInvocationLogReference,
}

impl SkillPackInvocationTermination {
    pub fn binding(&self) -> &SkillPackInvocationBinding {
        &self.binding
    }

    pub fn proposal_digest(&self) -> &GatewayDigest {
        &self.proposal_digest
    }

    pub const fn reason(&self) -> CapabilityInvocationCloseReason {
        self.reason
    }

    pub fn gateway_release(&self) -> &CapabilityInvocationReleaseReceipt {
        &self.gateway_release
    }

    pub fn resolution_release(&self) -> &CapabilityReleaseReceipt {
        &self.resolution_release
    }

    pub fn skill_log_reference(&self) -> &SkillPackInvocationLogReference {
        &self.skill_reference
    }
}

impl fmt::Debug for SkillPackInvocationTermination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationTermination")
            .field("binding", &self.binding)
            .field("proposal_digest", &self.proposal_digest)
            .field("reason", &self.reason)
            .field("gateway_release", &self.gateway_release)
            .field("resolution_release", &self.resolution_release)
            .field("skill_reference", &self.skill_reference)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackInvocationCancellation {
    proposal_digest: GatewayDigest,
    binding: SkillPackInvocationBinding,
    reason: CapabilityInvocationCloseReason,
    skill_reference: SkillPackInvocationLogReference,
    resolution_release: CapabilityReleaseReceipt,
}

impl SkillPackInvocationCancellation {
    pub fn proposal_digest(&self) -> &GatewayDigest {
        &self.proposal_digest
    }

    pub fn binding(&self) -> &SkillPackInvocationBinding {
        &self.binding
    }

    pub const fn reason(&self) -> CapabilityInvocationCloseReason {
        self.reason
    }

    pub fn skill_log_reference(&self) -> &SkillPackInvocationLogReference {
        &self.skill_reference
    }

    pub fn resolution_release(&self) -> &CapabilityReleaseReceipt {
        &self.resolution_release
    }
}

impl fmt::Debug for SkillPackInvocationCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationCancellation")
            .field("proposal_digest", &self.proposal_digest)
            .field("binding", &self.binding)
            .field("reason", &self.reason)
            .field("skill_reference", &self.skill_reference)
            .field("resolution_release", &self.resolution_release)
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SkillPackInvocationError {
    #[error("Skill Pack provider rejected the invocation context")]
    Provider(#[source] SkillPackError),
    #[error("Skill Pack invocation selector is invalid")]
    InvalidSelector,
    #[error("selected Skill Pack item is not model-visible")]
    ItemNotVisible,
    #[error("declared Skill Pack tool requirement is not present in the model context")]
    MissingCapability,
    #[error("Skill Pack tool effect class does not match the Gateway class")]
    CapabilityClassMismatch,
    #[error("Skill Pack invocation scope does not match the Gateway request")]
    ScopeMismatch,
    #[error("Skill Pack invocation policy or authority binding drifted")]
    PolicyMismatch,
    #[error("Skill Pack invocation generation drifted")]
    GenerationMismatch,
    #[error("Skill Pack invocation must be model-visible")]
    VisibilityRequired,
    #[error("Skill Pack invocation binding does not match the declared tool")]
    BindingMismatch,
    #[error("Skill Pack invocation request does not name the declared tool")]
    RequestMismatch,
    #[error("capability resolution rejected the Skill Pack invocation")]
    Resolution(#[source] CapabilityResolutionError),
    #[error("capability invocation rejected the Skill Pack result")]
    Invocation(#[source] CapabilityInvocationError),
    #[error("Skill Pack invocation log rejected the event")]
    Log(#[from] SkillPackInvocationLogError),
    #[error("Skill Pack capability audit rejected the event")]
    Audit(#[from] SkillPackAuditLogError),
    #[error("capability resolution release failed")]
    ResolutionRelease(#[source] CapabilityResolutionError),
    #[error("capability resolution lease was already released")]
    ResolutionAlreadyReleased,
}

pub struct SkillPackInvocationConsumer;

impl SkillPackInvocationConsumer {
    pub const fn new() -> Self {
        Self
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn propose<H, L, R>(
        &self,
        provider: &mut SkillPackProvider<H>,
        context: &SkillPackMissionContext,
        model: &SkillPackModelContext,
        selector: SkillPackInvocationSelector,
        requirement: SkillToolRequirement,
        resolved: CapabilityResolutionLease,
        composition: CapabilityCompositionSnapshot,
        manifest: SignedCapabilityManifest,
        request: CapabilityRequest,
        invocation_context: CapabilityInvocationContext,
        runtime: &PluginRuntime,
        resolution_audit: &mut R,
        invocation_log: &mut L,
        observed_at: DateTime<Utc>,
    ) -> Result<SkillPackInvocationProposal, SkillPackInvocationError>
    where
        H: SkillPackHostAdapter,
        L: SkillPackInvocationLog,
        R: CapabilityResolutionAuditLedger,
    {
        if let Err(error) = provider.validate_context(context, model, runtime) {
            return reject_resolution(
                resolved,
                observed_at,
                resolution_audit,
                SkillPackInvocationError::Provider(error),
            );
        }
        if let Err(error) = selector.validate_against(model) {
            return reject_resolution(resolved, observed_at, resolution_audit, error);
        }
        if !model
            .resolution()
            .tools()
            .iter()
            .any(|candidate| candidate == &requirement)
        {
            return reject_resolution(
                resolved,
                observed_at,
                resolution_audit,
                SkillPackInvocationError::MissingCapability,
            );
        }
        let expected_class = match requirement.effect_class() {
            SkillEffectClass::ReadOnly => CapabilityClass::Read,
            SkillEffectClass::EffectProposal => CapabilityClass::ExternalEffect,
        };
        if request.class != expected_class || resolved.invocation_permit().class != expected_class {
            return reject_resolution(
                resolved,
                observed_at,
                resolution_audit,
                SkillPackInvocationError::CapabilityClassMismatch,
            );
        }
        if invocation_context.visibility() != CapabilityInvocationVisibility::ModelVisible {
            return reject_resolution(
                resolved,
                observed_at,
                resolution_audit,
                SkillPackInvocationError::VisibilityRequired,
            );
        }
        if let Err(error) = validate_request_scope(context, &request, &invocation_context) {
            return reject_resolution(resolved, observed_at, resolution_audit, error);
        }
        if let Err(error) = validate_binding(
            &requirement,
            context,
            &resolved,
            &request,
            &invocation_context,
        ) {
            return reject_resolution(resolved, observed_at, resolution_audit, error);
        }
        let binding = SkillPackInvocationBinding::from_parts(
            &ProviderBindingView(provider),
            context,
            model,
            &selector,
            &resolved,
            &request,
        );
        let proposal_digest = gateway_digest(&(
            SKILL_PACK_INVOCATION_SCHEMA,
            &binding,
            &selector,
            &requirement,
            &request.digest(),
            &invocation_context,
            &composition,
            &manifest.manifest,
        ));
        let event = SkillPackInvocationEvent::proposed(
            proposal_digest.clone(),
            binding.clone(),
            observed_at,
        );
        let log_reference = match invocation_log.append(event) {
            Ok(reference) => reference,
            Err(error) => {
                return reject_resolution(
                    resolved,
                    observed_at,
                    resolution_audit,
                    SkillPackInvocationError::Log(error),
                );
            }
        };
        Ok(SkillPackInvocationProposal {
            binding,
            selector,
            requirement,
            context_receipt: model.receipt().clone(),
            resolved,
            composition,
            manifest,
            request,
            invocation_context,
            proposal_digest,
            log_reference,
        })
    }
}

impl Default for SkillPackInvocationConsumer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SkillPackInvocationConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackInvocationConsumer")
            .field("schema", &SKILL_PACK_INVOCATION_SCHEMA)
            .finish()
    }
}

trait SkillPackBindingView {
    fn package_digest(&self) -> &Digest;
    fn plugin_digest(&self) -> &Digest;
    fn package_id_digest(&self) -> &Digest;
    fn skill_id_digest(&self) -> &Digest;
    fn skill_version(&self) -> PluginVersion;
    fn source_digest(&self) -> &Digest;
    fn manifest_digest(&self) -> &Digest;
    fn content_digest(&self) -> &Digest;
    fn verification_receipt_digest(&self) -> &Digest;
    fn host_api(&self) -> PluginVersion;
}

struct ProviderBindingView<'a, H>(&'a SkillPackProvider<H>);

impl<H: SkillPackHostAdapter> SkillPackBindingView for ProviderBindingView<'_, H> {
    fn package_digest(&self) -> &Digest {
        self.0.package_digest()
    }

    fn plugin_digest(&self) -> &Digest {
        self.0.plugin_digest()
    }

    fn package_id_digest(&self) -> &Digest {
        self.0.metadata().package_id_digest()
    }

    fn skill_id_digest(&self) -> &Digest {
        self.0.metadata().skill_id_digest()
    }

    fn skill_version(&self) -> PluginVersion {
        self.0.metadata().version()
    }

    fn source_digest(&self) -> &Digest {
        self.0.metadata().source_digest()
    }

    fn manifest_digest(&self) -> &Digest {
        self.0.metadata().manifest_digest()
    }

    fn content_digest(&self) -> &Digest {
        self.0.metadata().content_digest()
    }

    fn verification_receipt_digest(&self) -> &Digest {
        self.0.verification_receipt_digest()
    }

    fn host_api(&self) -> PluginVersion {
        self.0.metadata().host_api()
    }
}

fn reject_resolution<T, R>(
    mut resolved: CapabilityResolutionLease,
    observed_at: DateTime<Utc>,
    resolution_audit: &mut R,
    error: SkillPackInvocationError,
) -> Result<T, SkillPackInvocationError>
where
    R: CapabilityResolutionAuditLedger,
{
    resolved
        .release(observed_at, resolution_audit)
        .map_err(SkillPackInvocationError::ResolutionRelease)?;
    Err(error)
}

#[allow(clippy::too_many_arguments)]
fn reject_proposal<T, R, S>(
    mut resolved: CapabilityResolutionLease,
    binding: SkillPackInvocationBinding,
    proposal_digest: GatewayDigest,
    proposal_log_reference: &SkillPackInvocationLogReference,
    reason: CapabilityInvocationCloseReason,
    observed_at: DateTime<Utc>,
    resolution_audit: &mut R,
    skill_log: &mut S,
    error: SkillPackInvocationError,
) -> Result<T, SkillPackInvocationError>
where
    R: CapabilityResolutionAuditLedger,
    S: SkillPackInvocationLog,
{
    let event = SkillPackInvocationEvent::terminal(
        SkillPackInvocationEventKind::Invalidated,
        proposal_digest,
        binding,
        proposal_log_reference.digest().clone(),
        None,
        None,
        Some(reason),
        observed_at,
    );
    let skill_result = skill_log.append(event);
    let resolution_result = resolved
        .release(observed_at, resolution_audit)
        .map_err(SkillPackInvocationError::ResolutionRelease);
    if let Err(error) = skill_result {
        let _ = resolution_result;
        return Err(SkillPackInvocationError::Log(error));
    }
    resolution_result?;
    Err(error)
}

fn validate_request_scope(
    context: &SkillPackMissionContext,
    request: &CapabilityRequest,
    invocation_context: &CapabilityInvocationContext,
) -> Result<(), SkillPackInvocationError> {
    if request.scope.project_id.as_str() != context.scope().project_id().as_str()
        || request.scope.mission_id.as_str() != context.scope().mission_id().as_str()
        || request.generation != context.scope().generation()
        || request.scope.generation != context.scope().generation()
        || request.scope.scope_digest.as_str() != context.scope().digest().as_str()
        || invocation_context.project_id().as_str() != context.scope().project_id().as_str()
        || invocation_context.mission_id().as_str() != context.scope().mission_id().as_str()
        || invocation_context.generation() != context.scope().generation()
        || invocation_context.provider_generation() != context.scope().generation()
    {
        return Err(SkillPackInvocationError::ScopeMismatch);
    }
    Ok(())
}

fn validate_binding(
    requirement: &SkillToolRequirement,
    context: &SkillPackMissionContext,
    resolved: &CapabilityResolutionLease,
    request: &CapabilityRequest,
    invocation_context: &CapabilityInvocationContext,
) -> Result<(), SkillPackInvocationError> {
    let binding = resolved.binding();
    let service_digest = GatewayDigest::from_text(requirement.service_id().as_str());
    let consumer_digest = GatewayDigest::from_text(requirement.tool_id().as_str());
    let required_version = CapabilityVersion::new(
        requirement.version().major(),
        requirement.version().minor(),
        requirement.version().patch(),
    );
    if binding.service_id_digest() != &service_digest
        || binding.consumer_id_digest() != &consumer_digest
        || binding.version() != required_version
        || binding.scope().project_id.as_str() != context.scope().project_id().as_str()
        || binding.scope().mission_id.as_str() != context.scope().mission_id().as_str()
        || binding.scope().generation != context.scope().generation()
        || binding.scope().scope_digest.as_str() != context.scope().digest().as_str()
        || binding.manifest_digest() != &request.manifest_digest
        || binding.provider_generation() != context.scope().generation()
        || invocation_context.policy_digest() != binding.policy_digest()
    {
        return Err(SkillPackInvocationError::BindingMismatch);
    }
    if request.capability_id.as_str() != requirement.tool_id().as_str() {
        return Err(SkillPackInvocationError::RequestMismatch);
    }
    if request.provenance.authority_digest != *binding.authority_digest()
        || request.provenance.manifest_digest != request.manifest_digest
    {
        return Err(SkillPackInvocationError::PolicyMismatch);
    }
    Ok(())
}

fn provider_close_reason(error: SkillPackError) -> CapabilityInvocationCloseReason {
    match error {
        SkillPackError::PluginRevoked => CapabilityInvocationCloseReason::PluginRevoked,
        SkillPackError::PluginUnmounted => CapabilityInvocationCloseReason::CompositionUnavailable,
        SkillPackError::GenerationMismatch => CapabilityInvocationCloseReason::GenerationStale,
        SkillPackError::ScopeMismatch => CapabilityInvocationCloseReason::ScopeDrift,
        SkillPackError::LateConsumer => CapabilityInvocationCloseReason::BindingDrift,
        _ => CapabilityInvocationCloseReason::Crashed,
    }
}

fn invocation_close_reason(error: &CapabilityInvocationError) -> CapabilityInvocationCloseReason {
    match error {
        CapabilityInvocationError::Invalidated(reason) => *reason,
        CapabilityInvocationError::UncertainExternalEffect => {
            CapabilityInvocationCloseReason::UncertainExternalEffect
        }
        CapabilityInvocationError::PolicyDrift => CapabilityInvocationCloseReason::PolicyDrift,
        CapabilityInvocationError::GenerationMismatch => {
            CapabilityInvocationCloseReason::GenerationStale
        }
        CapabilityInvocationError::RevisionMismatch => {
            CapabilityInvocationCloseReason::CompositionRevisionDrift
        }
        CapabilityInvocationError::MissionMismatch => CapabilityInvocationCloseReason::ScopeDrift,
        CapabilityInvocationError::ProviderGenerationMismatch => {
            CapabilityInvocationCloseReason::ProviderGenerationDrift
        }
        CapabilityInvocationError::ResultRejected(_)
        | CapabilityInvocationError::EffectReceiptRequired
        | CapabilityInvocationError::UnexpectedEffectReceipt
        | CapabilityInvocationError::EffectReceiptMismatch => {
            CapabilityInvocationCloseReason::ResultRejected
        }
        _ => CapabilityInvocationCloseReason::BindingDrift,
    }
}

fn gateway_digest<T: Serialize>(value: &T) -> GatewayDigest {
    GatewayDigest::from_bytes(
        &serde_json::to_vec(value).expect("typed Skill Pack values serialize deterministically"),
    )
}

fn is_gateway_digest(value: &GatewayDigest) -> bool {
    value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_skill_digest(value: &Digest) -> bool {
    value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

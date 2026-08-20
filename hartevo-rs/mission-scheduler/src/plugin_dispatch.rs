//! Exactly-once dispatch handoff for a scheduled plugin invocation.
//!
//! [`crate::plugin_invocation`] proves that an OS/Cell wake reached one exact
//! schedule and emits a [`TriggerReceipt`].  This module is the next,
//! scheduler-owned boundary: it consumes that exact wake token, mounts and
//! resolves the bound plugin session, then wins a final schedule/lease
//! revision CAS before asking a provider for one capability request.  The
//! provider seam has no Runtime, Browser, or Effect authority.
//!
//! The pending/dispatching/dispatched state is durable.  A crash after the
//! reservation or after the provider call therefore retries with the same
//! token and session binding; a provider must return the same acknowledgement
//! for that token rather than perform a second invocation.  Cancellation and
//! reschedule use the same exact CAS and can win while a dispatch is still in
//! preparation, but never after the dispatch reservation has been won.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plugin_invocation::{
    DispatchAuthority, DurablePluginWakeRequest, MissionScope, PluginComposition, PluginInvocation,
    PluginInvocationError, TriggerReceipt,
};
use crate::scheduler_digest;

const MAX_OWNER_DIGEST_BYTES: usize = 1_024;

/// The durable state of one schedule slot in the dispatch handoff.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchState {
    Pending,
    Dispatching,
    Dispatched,
    Cancelled,
}

/// The exact worker/Cell lease used to authorize one wake handoff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchLease {
    pub owner_digest: String,
    pub lease_revision: u64,
    pub generation: u64,
    pub expires_at: DateTime<Utc>,
    pub lease_digest: String,
}

impl DispatchLease {
    pub fn new(
        owner_digest: impl Into<String>,
        lease_revision: u64,
        generation: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, PluginDispatchError> {
        let mut lease = Self {
            owner_digest: owner_digest.into(),
            lease_revision,
            generation,
            expires_at,
            lease_digest: String::new(),
        };
        lease.lease_digest = lease.expected_digest()?;
        lease.validate()?;
        Ok(lease)
    }

    pub fn expected_digest(&self) -> Result<String, PluginDispatchError> {
        let mut material = self.clone();
        material.lease_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), PluginDispatchError> {
        if !is_digest(&self.owner_digest)
            || self.owner_digest.len() > MAX_OWNER_DIGEST_BYTES
            || self.lease_revision == 0
            || self.generation == 0
            || !is_digest(&self.lease_digest)
            || self.lease_digest != self.expected_digest()?
        {
            return Err(PluginDispatchError::InvalidLease);
        }
        Ok(())
    }

    fn is_live_at(&self, observed_at: DateTime<Utc>) -> bool {
        observed_at <= self.expires_at
    }
}

/// A single-use, digest-bound wake capability.  It names the exact durable
/// wake request and trigger receipt, rather than a schedule slot alone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchWakeToken {
    pub trigger_receipt_digest: String,
    pub request_id_digest: String,
    pub request_digest: String,
    pub wake_request_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub composition_digest: String,
    pub invocation_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub lease_generation: u64,
    pub lease_digest: String,
    pub issued_at: DateTime<Utc>,
    pub token_digest: String,
}

impl DispatchWakeToken {
    pub fn issue(
        request: &DurablePluginWakeRequest,
        trigger: &TriggerReceipt,
        lease: &DispatchLease,
        issued_at: DateTime<Utc>,
    ) -> Result<Self, PluginDispatchError> {
        request.validate()?;
        trigger.validate()?;
        lease.validate()?;
        ensure_trigger_matches_request(request, trigger)?;
        let wake_request_digest = request
            .wake
            .request_digest()
            .map_err(|error| PluginDispatchError::WakeContract(error.to_string()))?;
        let mut token = Self {
            trigger_receipt_digest: trigger.receipt_digest.clone(),
            request_id_digest: request.request_id_digest.clone(),
            request_digest: request.request_digest.clone(),
            wake_request_digest,
            objective_digest: request.objective_digest.clone(),
            scope: request.scope.clone(),
            schedule_id_digest: request.schedule.schedule_id_digest.clone(),
            schedule_revision: request.schedule.schedule_revision,
            composition_digest: request.composition.composition_digest.clone(),
            invocation_digest: request.invocation.digest()?,
            provider_id_digest: request.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            lease_revision: lease.lease_revision,
            lease_generation: lease.generation,
            lease_digest: lease.lease_digest.clone(),
            issued_at,
            token_digest: String::new(),
        };
        token.token_digest = token.expected_digest()?;
        token.validate_for(request, trigger, lease)?;
        Ok(token)
    }

    pub fn expected_digest(&self) -> Result<String, PluginDispatchError> {
        let mut material = self.clone();
        material.token_digest.clear();
        digest_json(&material)
    }

    pub fn validate_for(
        &self,
        request: &DurablePluginWakeRequest,
        trigger: &TriggerReceipt,
        lease: &DispatchLease,
    ) -> Result<(), PluginDispatchError> {
        request.validate()?;
        trigger.validate()?;
        lease.validate()?;
        ensure_trigger_matches_request(request, trigger)?;
        let wake_request_digest = request
            .wake
            .request_digest()
            .map_err(|error| PluginDispatchError::WakeContract(error.to_string()))?;
        let invocation_digest = request.invocation.digest()?;
        if self.trigger_receipt_digest != trigger.receipt_digest
            || self.request_id_digest != request.request_id_digest
            || self.request_digest != request.request_digest
            || self.wake_request_digest != wake_request_digest
            || self.objective_digest != request.objective_digest
            || self.scope != request.scope
            || self.schedule_id_digest != request.schedule.schedule_id_digest
            || self.schedule_revision != request.schedule.schedule_revision
            || self.composition_digest != request.composition.composition_digest
            || self.invocation_digest != invocation_digest
            || self.provider_id_digest != request.provider_id_digest
            || self.provider_epoch != request.provider_epoch
            || self.lease_revision != lease.lease_revision
            || self.lease_generation != lease.generation
            || self.lease_digest != lease.lease_digest
            || !is_digest(&self.token_digest)
            || self.token_digest != self.expected_digest()?
        {
            return Err(PluginDispatchError::InvalidWakeToken);
        }
        Ok(())
    }
}

/// The exact plugin composition/session binding selected by the wake request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSessionBinding {
    pub scope: MissionScope,
    pub project_id: String,
    pub mission_id: String,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub request_id_digest: String,
    pub request_digest: String,
    pub wake_request_digest: String,
    pub composition: PluginComposition,
    pub composition_digest: String,
    pub invocation: PluginInvocation,
    pub invocation_digest: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub lease_generation: u64,
    pub lease_digest: String,
    pub binding_digest: String,
}

impl PluginSessionBinding {
    pub fn from_exact(
        request: &DurablePluginWakeRequest,
        trigger: &TriggerReceipt,
        lease: &DispatchLease,
    ) -> Result<Self, PluginDispatchError> {
        request.validate()?;
        trigger.validate()?;
        lease.validate()?;
        ensure_trigger_matches_request(request, trigger)?;
        validate_invocation_for_composition(&request.invocation, &request.composition)?;
        let manifest = request
            .composition
            .plugin(&request.invocation.plugin_id)
            .ok_or(PluginDispatchError::PluginCompositionMismatch)?;
        let wake_request_digest = request
            .wake
            .request_digest()
            .map_err(|error| PluginDispatchError::WakeContract(error.to_string()))?;
        let mut binding = Self {
            scope: request.scope.clone(),
            project_id: request.scope.project_id.clone(),
            mission_id: request.scope.mission_id.clone(),
            schedule_id_digest: request.schedule.schedule_id_digest.clone(),
            schedule_revision: request.schedule.schedule_revision,
            request_id_digest: request.request_id_digest.clone(),
            request_digest: request.request_digest.clone(),
            wake_request_digest,
            composition: request.composition.clone(),
            composition_digest: request.composition.composition_digest.clone(),
            invocation: request.invocation.clone(),
            invocation_digest: request.invocation.digest()?,
            plugin_id: manifest.plugin_id.clone(),
            plugin_version: manifest.version.clone(),
            plugin_digest: manifest.plugin_digest.clone(),
            provider_id_digest: request.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            lease_revision: lease.lease_revision,
            lease_generation: lease.generation,
            lease_digest: lease.lease_digest.clone(),
            binding_digest: String::new(),
        };
        binding.binding_digest = binding.expected_digest()?;
        binding.validate()?;
        Ok(binding)
    }

    pub fn expected_digest(&self) -> Result<String, PluginDispatchError> {
        let mut material = self.clone();
        material.binding_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), PluginDispatchError> {
        self.scope.validate()?;
        self.composition.validate()?;
        validate_invocation_for_composition(&self.invocation, &self.composition)?;
        if self.project_id != self.scope.project_id
            || self.mission_id != self.scope.mission_id
            || !is_digest(&self.schedule_id_digest)
            || self.schedule_revision == 0
            || !is_digest(&self.request_id_digest)
            || !is_digest(&self.request_digest)
            || !is_digest(&self.wake_request_digest)
            || self.composition_digest != self.composition.composition_digest
            || self.invocation_digest != self.invocation.digest()?
            || !is_digest(&self.provider_id_digest)
            || self.provider_epoch == 0
            || self.lease_revision == 0
            || self.lease_generation == 0
            || !is_digest(&self.lease_digest)
            || !is_digest(&self.binding_digest)
            || self.binding_digest != self.expected_digest()?
            || self.composition.scope != self.scope
        {
            return Err(PluginDispatchError::InvalidSessionBinding);
        }
        let manifest = self
            .composition
            .plugin(&self.plugin_id)
            .ok_or(PluginDispatchError::PluginCompositionMismatch)?;
        if manifest.version != self.plugin_version || manifest.plugin_digest != self.plugin_digest {
            return Err(PluginDispatchError::PluginCompositionMismatch);
        }
        Ok(())
    }
}

/// Durable evidence that the provider mounted the exact bound plugin session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSessionMountReceipt {
    pub binding_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub mount_revision: u64,
    pub mounted_at: DateTime<Utc>,
    pub mount_receipt_digest: String,
}

impl PluginSessionMountReceipt {
    pub fn new(
        binding: &PluginSessionBinding,
        mount_revision: u64,
        mounted_at: DateTime<Utc>,
    ) -> Result<Self, PluginDispatchError> {
        binding.validate()?;
        let mut receipt = Self {
            binding_digest: binding.binding_digest.clone(),
            provider_id_digest: binding.provider_id_digest.clone(),
            provider_epoch: binding.provider_epoch,
            mount_revision,
            mounted_at,
            mount_receipt_digest: String::new(),
        };
        receipt.mount_receipt_digest = receipt.expected_digest()?;
        receipt.validate_for(binding).map(|()| receipt)
    }

    pub fn expected_digest(&self) -> Result<String, PluginDispatchError> {
        let mut material = self.clone();
        material.mount_receipt_digest.clear();
        digest_json(&material)
    }

    pub fn validate_for(&self, binding: &PluginSessionBinding) -> Result<(), PluginDispatchError> {
        binding.validate()?;
        if self.binding_digest != binding.binding_digest
            || self.provider_id_digest != binding.provider_id_digest
            || self.provider_epoch != binding.provider_epoch
            || self.mount_revision == 0
            || !is_digest(&self.mount_receipt_digest)
            || self.mount_receipt_digest != self.expected_digest()?
        {
            return Err(PluginDispatchError::InvalidSessionReceipt);
        }
        Ok(())
    }
}

/// A provider-resolved session that is still only a capability boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedPluginSession {
    pub binding_digest: String,
    pub mount_receipt_digest: String,
    pub session_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub resolution_revision: u64,
    pub resolved_at: DateTime<Utc>,
    pub resolution_digest: String,
}

impl ResolvedPluginSession {
    pub fn new(
        binding: &PluginSessionBinding,
        mount: &PluginSessionMountReceipt,
        resolution_revision: u64,
        resolved_at: DateTime<Utc>,
    ) -> Result<Self, PluginDispatchError> {
        binding.validate()?;
        mount.validate_for(binding)?;
        let session_digest = digest_json(&(
            binding.binding_digest.clone(),
            mount.mount_receipt_digest.clone(),
            resolution_revision,
        ))?;
        let mut session = Self {
            binding_digest: binding.binding_digest.clone(),
            mount_receipt_digest: mount.mount_receipt_digest.clone(),
            session_digest,
            provider_id_digest: binding.provider_id_digest.clone(),
            provider_epoch: binding.provider_epoch,
            resolution_revision,
            resolved_at,
            resolution_digest: String::new(),
        };
        session.resolution_digest = session.expected_digest()?;
        session.validate_for(binding, mount).map(|()| session)
    }

    pub fn expected_digest(&self) -> Result<String, PluginDispatchError> {
        let mut material = self.clone();
        material.resolution_digest.clear();
        digest_json(&material)
    }

    pub fn validate_for(
        &self,
        binding: &PluginSessionBinding,
        mount: &PluginSessionMountReceipt,
    ) -> Result<(), PluginDispatchError> {
        binding.validate()?;
        mount.validate_for(binding)?;
        let expected_session_digest = digest_json(&(
            binding.binding_digest.clone(),
            mount.mount_receipt_digest.clone(),
            self.resolution_revision,
        ))?;
        if self.binding_digest != binding.binding_digest
            || self.mount_receipt_digest != mount.mount_receipt_digest
            || self.session_digest != expected_session_digest
            || self.provider_id_digest != binding.provider_id_digest
            || self.provider_epoch != binding.provider_epoch
            || self.resolution_revision == 0
            || !is_digest(&self.resolution_digest)
            || self.resolution_digest != self.expected_digest()?
        {
            return Err(PluginDispatchError::InvalidResolvedSession);
        }
        Ok(())
    }
}

/// The provider acknowledgement for one capability-only dispatch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDispatchAck {
    pub token_digest: String,
    pub session_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub dispatched_at: DateTime<Utc>,
    pub authority: DispatchAuthority,
    pub ack_digest: String,
}

impl ProviderDispatchAck {
    pub fn new(
        token: &DispatchWakeToken,
        session: &ResolvedPluginSession,
        provider_id_digest: impl Into<String>,
        provider_epoch: u64,
        dispatched_at: DateTime<Utc>,
    ) -> Result<Self, PluginDispatchError> {
        let mut ack = Self {
            token_digest: token.token_digest.clone(),
            session_digest: session.session_digest.clone(),
            provider_id_digest: provider_id_digest.into(),
            provider_epoch,
            dispatched_at,
            authority: DispatchAuthority::CapabilityRequestOnly,
            ack_digest: String::new(),
        };
        ack.ack_digest = ack.expected_digest()?;
        ack.validate_for(token, session).map(|()| ack)
    }

    pub fn expected_digest(&self) -> Result<String, PluginDispatchError> {
        let mut material = self.clone();
        material.ack_digest.clear();
        digest_json(&material)
    }

    pub fn validate_for(
        &self,
        token: &DispatchWakeToken,
        session: &ResolvedPluginSession,
    ) -> Result<(), PluginDispatchError> {
        if self.token_digest != token.token_digest
            || self.session_digest != session.session_digest
            || self.provider_id_digest != token.provider_id_digest
            || self.provider_epoch != token.provider_epoch
            || self.authority != DispatchAuthority::CapabilityRequestOnly
            || !is_digest(&self.ack_digest)
            || self.ack_digest != self.expected_digest()?
        {
            return Err(PluginDispatchError::InvalidProviderAck);
        }
        Ok(())
    }
}

/// The durable exactly-once receipt for one scheduled plugin invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerDispatchReceipt {
    pub receipt_id_digest: String,
    pub trigger_receipt_digest: String,
    pub wake_token_digest: String,
    pub request_id_digest: String,
    pub request_digest: String,
    pub wake_request_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub project_id: String,
    pub mission_id: String,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub woke_at: DateTime<Utc>,
    pub coalesced_ticks: u64,
    pub composition: PluginComposition,
    pub composition_digest: String,
    pub invocation: PluginInvocation,
    pub invocation_digest: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub lease_generation: u64,
    pub lease_digest: String,
    pub lease_expires_at: DateTime<Utc>,
    pub session_binding_digest: String,
    pub mount_receipt_digest: String,
    pub mounted_at: DateTime<Utc>,
    pub mount_revision: u64,
    pub resolved_at: DateTime<Utc>,
    pub resolution_revision: u64,
    pub registered_at: DateTime<Utc>,
    pub dispatch_started_at: DateTime<Utc>,
    pub dispatched_at: DateTime<Utc>,
    pub dispatch_revision: u64,
    pub authority: DispatchAuthority,
    pub receipt_digest: String,
}

struct DispatchReceiptContext<'a> {
    request: &'a DurablePluginWakeRequest,
    trigger: &'a TriggerReceipt,
    token: &'a DispatchWakeToken,
    lease: &'a DispatchLease,
    binding: &'a PluginSessionBinding,
    mount: &'a PluginSessionMountReceipt,
    resolved: &'a ResolvedPluginSession,
    registered_at: DateTime<Utc>,
    dispatch_started_at: DateTime<Utc>,
}

impl TriggerDispatchReceipt {
    fn from_parts(
        context: &DispatchReceiptContext<'_>,
        dispatch_revision: u64,
        ack: &ProviderDispatchAck,
    ) -> Result<Self, PluginDispatchError> {
        let request = context.request;
        let trigger = context.trigger;
        let token = context.token;
        let lease = context.lease;
        let binding = context.binding;
        let mount = context.mount;
        let resolved = context.resolved;
        request.validate()?;
        trigger.validate()?;
        token.validate_for(request, trigger, lease)?;
        binding.validate()?;
        mount.validate_for(binding)?;
        resolved.validate_for(binding, mount)?;
        ack.validate_for(token, resolved)?;
        let manifest = request
            .composition
            .plugin(&request.invocation.plugin_id)
            .ok_or(PluginDispatchError::PluginCompositionMismatch)?;
        let receipt_id_digest = digest_json(&(
            token.token_digest.clone(),
            resolved.session_digest.clone(),
            dispatch_revision,
        ))?;
        let mut receipt = Self {
            receipt_id_digest,
            trigger_receipt_digest: trigger.receipt_digest.clone(),
            wake_token_digest: token.token_digest.clone(),
            request_id_digest: request.request_id_digest.clone(),
            request_digest: request.request_digest.clone(),
            wake_request_digest: token.wake_request_digest.clone(),
            objective_digest: request.objective_digest.clone(),
            scope: request.scope.clone(),
            project_id: request.scope.project_id.clone(),
            mission_id: request.scope.mission_id.clone(),
            schedule_id_digest: request.schedule.schedule_id_digest.clone(),
            schedule_revision: request.schedule.schedule_revision,
            planned_at: trigger.planned_at,
            woke_at: trigger.woke_at,
            coalesced_ticks: trigger.coalesced_ticks,
            composition: request.composition.clone(),
            composition_digest: request.composition.composition_digest.clone(),
            invocation: request.invocation.clone(),
            invocation_digest: request.invocation.digest()?,
            plugin_id: manifest.plugin_id.clone(),
            plugin_version: manifest.version.clone(),
            plugin_digest: manifest.plugin_digest.clone(),
            provider_id_digest: request.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            lease_revision: lease.lease_revision,
            lease_generation: lease.generation,
            lease_digest: lease.lease_digest.clone(),
            lease_expires_at: lease.expires_at,
            session_binding_digest: binding.binding_digest.clone(),
            mount_receipt_digest: mount.mount_receipt_digest.clone(),
            mounted_at: mount.mounted_at,
            mount_revision: mount.mount_revision,
            resolved_at: resolved.resolved_at,
            resolution_revision: resolved.resolution_revision,
            registered_at: context.registered_at,
            dispatch_started_at: context.dispatch_started_at,
            dispatched_at: ack.dispatched_at,
            dispatch_revision,
            authority: DispatchAuthority::CapabilityRequestOnly,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate_for(context)?;
        Ok(receipt)
    }

    pub fn expected_digest(&self) -> Result<String, PluginDispatchError> {
        let mut material = self.clone();
        material.receipt_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), PluginDispatchError> {
        if !is_digest(&self.receipt_id_digest)
            || !is_digest(&self.trigger_receipt_digest)
            || !is_digest(&self.wake_token_digest)
            || !is_digest(&self.request_id_digest)
            || !is_digest(&self.request_digest)
            || !is_digest(&self.wake_request_digest)
            || !is_digest(&self.objective_digest)
            || !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.composition_digest)
            || !is_digest(&self.invocation_digest)
            || !is_digest(&self.plugin_digest)
            || !is_digest(&self.provider_id_digest)
            || !is_digest(&self.lease_digest)
            || !is_digest(&self.session_binding_digest)
            || !is_digest(&self.mount_receipt_digest)
            || self.schedule_revision == 0
            || self.coalesced_ticks == 0
            || self.provider_epoch == 0
            || self.lease_revision == 0
            || self.lease_generation == 0
            || self.mount_revision == 0
            || self.resolution_revision == 0
            || self.dispatch_revision == 0
            || self.planned_at > self.woke_at
            || self.woke_at > self.mounted_at
            || self.mounted_at > self.resolved_at
            || self.resolved_at > self.dispatch_started_at
            || self.dispatch_started_at > self.dispatched_at
            || self.dispatched_at > self.lease_expires_at
            || self.authority != DispatchAuthority::CapabilityRequestOnly
            || self.receipt_digest != self.expected_digest()?
        {
            return Err(PluginDispatchError::InvalidDispatchReceipt);
        }
        self.scope.validate()?;
        self.composition.validate()?;
        validate_invocation_for_composition(&self.invocation, &self.composition)?;
        if self.project_id != self.scope.project_id
            || self.mission_id != self.scope.mission_id
            || self.composition.scope != self.scope
            || self.composition_digest != self.composition.composition_digest
            || self.invocation_digest != self.invocation.digest()?
        {
            return Err(PluginDispatchError::InvalidDispatchReceipt);
        }
        let manifest = self
            .composition
            .plugin(&self.plugin_id)
            .ok_or(PluginDispatchError::PluginCompositionMismatch)?;
        if manifest.version != self.plugin_version || manifest.plugin_digest != self.plugin_digest {
            return Err(PluginDispatchError::PluginCompositionMismatch);
        }
        Ok(())
    }

    fn validate_for(
        &self,
        context: &DispatchReceiptContext<'_>,
    ) -> Result<(), PluginDispatchError> {
        let request = context.request;
        let trigger = context.trigger;
        let token = context.token;
        let lease = context.lease;
        let binding = context.binding;
        let mount = context.mount;
        let resolved = context.resolved;
        self.validate()?;
        token.validate_for(request, trigger, lease)?;
        binding.validate()?;
        mount.validate_for(binding)?;
        resolved.validate_for(binding, mount)?;
        if self.trigger_receipt_digest != trigger.receipt_digest
            || self.wake_token_digest != token.token_digest
            || self.request_id_digest != request.request_id_digest
            || self.request_digest != request.request_digest
            || self.wake_request_digest != token.wake_request_digest
            || self.objective_digest != request.objective_digest
            || self.scope != request.scope
            || self.project_id != request.scope.project_id
            || self.mission_id != request.scope.mission_id
            || self.schedule_id_digest != request.schedule.schedule_id_digest
            || self.schedule_revision != request.schedule.schedule_revision
            || self.planned_at != trigger.planned_at
            || self.woke_at != trigger.woke_at
            || self.coalesced_ticks != trigger.coalesced_ticks
            || self.composition != request.composition
            || self.composition_digest != request.composition.composition_digest
            || self.invocation != request.invocation
            || self.invocation_digest != request.invocation.digest()?
            || self.provider_id_digest != request.provider_id_digest
            || self.provider_epoch != request.provider_epoch
            || self.lease_revision != lease.lease_revision
            || self.lease_generation != lease.generation
            || self.lease_digest != lease.lease_digest
            || self.lease_expires_at != lease.expires_at
            || self.session_binding_digest != binding.binding_digest
            || self.mount_receipt_digest != mount.mount_receipt_digest
            || self.mounted_at != mount.mounted_at
            || self.mount_revision != mount.mount_revision
            || self.resolved_at != resolved.resolved_at
            || self.resolution_revision != resolved.resolution_revision
            || self.registered_at != context.registered_at
            || self.dispatch_started_at != context.dispatch_started_at
        {
            return Err(PluginDispatchError::DispatchReceiptConflict);
        }
        Ok(())
    }
}

/// Durable CAS state for one schedule slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchHead {
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub lease_revision: u64,
    pub dispatch_revision: u64,
    pub state: DispatchState,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub dispatch_started_at: Option<DateTime<Utc>>,
}

/// One complete durable record, including the exact request and session
/// evidence needed to retry after a process crash.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchRecord {
    pub request: DurablePluginWakeRequest,
    pub trigger: Option<TriggerReceipt>,
    pub lease: DispatchLease,
    pub token: Option<DispatchWakeToken>,
    pub head: DispatchHead,
    pub binding: Option<PluginSessionBinding>,
    pub mount: Option<PluginSessionMountReceipt>,
    pub resolved: Option<ResolvedPluginSession>,
    pub receipt: Option<TriggerDispatchReceipt>,
}

impl DispatchRecord {
    fn validate(&self, provider_id_digest: &str) -> Result<(), PluginDispatchError> {
        self.request.validate()?;
        self.lease.validate()?;
        self.validate_identity(provider_id_digest)?;
        self.validate_trigger_and_token()?;
        self.validate_session()?;
        self.validate_receipt()?;
        self.validate_state()
    }

    fn validate_identity(&self, provider_id_digest: &str) -> Result<(), PluginDispatchError> {
        if self.request.provider_id_digest != provider_id_digest
            || self.head.scope != self.request.scope
            || self.head.schedule_id_digest != self.request.schedule.schedule_id_digest
            || self.head.schedule_revision != self.request.schedule.schedule_revision
            || self.head.lease_revision != self.lease.lease_revision
            || self.head.schedule_revision == 0
            || self.head.lease_revision == 0
        {
            return Err(PluginDispatchError::CorruptRecord);
        }
        Ok(())
    }

    fn validate_trigger_and_token(&self) -> Result<(), PluginDispatchError> {
        match (&self.trigger, &self.token) {
            (Some(trigger), Some(token)) => {
                token.validate_for(&self.request, trigger, &self.lease)?;
            }
            (None, None) => {}
            _ => return Err(PluginDispatchError::CorruptRecord),
        }
        Ok(())
    }

    fn validate_session(&self) -> Result<(), PluginDispatchError> {
        let expected_binding = self
            .trigger
            .as_ref()
            .map(|trigger| PluginSessionBinding::from_exact(&self.request, trigger, &self.lease))
            .transpose()?;
        if let Some(expected_binding) = expected_binding
            && let Some(binding) = &self.binding
            && binding != &expected_binding
        {
            return Err(PluginDispatchError::CorruptRecord);
        }
        match (&self.binding, &self.mount, &self.resolved) {
            (Some(binding), Some(mount), Some(resolved)) => {
                mount.validate_for(binding)?;
                resolved.validate_for(binding, mount)?;
            }
            (None, None, None) => {}
            _ => return Err(PluginDispatchError::CorruptRecord),
        }
        Ok(())
    }

    fn validate_receipt(&self) -> Result<(), PluginDispatchError> {
        if let (
            Some(receipt),
            Some(trigger),
            Some(token),
            Some(binding),
            Some(mount),
            Some(resolved),
        ) = (
            &self.receipt,
            self.trigger.as_ref(),
            self.token.as_ref(),
            self.binding.as_ref(),
            self.mount.as_ref(),
            self.resolved.as_ref(),
        ) {
            let context = DispatchReceiptContext {
                request: &self.request,
                trigger,
                token,
                lease: &self.lease,
                binding,
                mount,
                resolved,
                registered_at: self.head.registered_at,
                dispatch_started_at: self
                    .head
                    .dispatch_started_at
                    .ok_or(PluginDispatchError::CorruptRecord)?,
            };
            receipt.validate_for(&context)?;
        } else if self.receipt.is_some() {
            return Err(PluginDispatchError::CorruptRecord);
        }
        Ok(())
    }

    fn validate_state(&self) -> Result<(), PluginDispatchError> {
        match self.head.state {
            DispatchState::Pending => {
                if self.head.dispatch_revision != 0 || self.head.dispatch_started_at.is_some() {
                    return Err(PluginDispatchError::CorruptRecord);
                }
                if self.receipt.is_some() {
                    return Err(PluginDispatchError::CorruptRecord);
                }
            }
            DispatchState::Dispatching => {
                if self.head.dispatch_revision == 0
                    || self.head.dispatch_started_at.is_none()
                    || self.receipt.is_some()
                {
                    return Err(PluginDispatchError::CorruptRecord);
                }
            }
            DispatchState::Dispatched => {
                if self.head.dispatch_revision == 0
                    || self.head.dispatch_started_at.is_none()
                    || self.receipt.is_none()
                {
                    return Err(PluginDispatchError::CorruptRecord);
                }
            }
            DispatchState::Cancelled => {
                if self.head.dispatch_revision != 0
                    || self.head.dispatch_started_at.is_some()
                    || self.receipt.is_some()
                {
                    return Err(PluginDispatchError::CorruptRecord);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginDispatchSnapshot {
    pub records: Vec<DispatchRecord>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PluginDispatchStoreError {
    #[error("plugin dispatch snapshot serialization failed: {0}")]
    Serialization(String),
    #[error("plugin dispatch snapshot is corrupt")]
    Corrupt,
    #[error("plugin dispatch SQLite store failed: {0}")]
    Sqlite(String),
    #[error("plugin dispatch store rejected a write")]
    WriteRejected,
}

pub trait PluginDispatchStore: fmt::Debug {
    fn load(&self) -> Result<PluginDispatchSnapshot, PluginDispatchStoreError>;
    fn save(&mut self, snapshot: &PluginDispatchSnapshot) -> Result<(), PluginDispatchStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryPluginDispatchStore {
    snapshot: PluginDispatchSnapshot,
}

impl MemoryPluginDispatchStore {
    pub fn snapshot(&self) -> &PluginDispatchSnapshot {
        &self.snapshot
    }
}

impl PluginDispatchStore for MemoryPluginDispatchStore {
    fn load(&self) -> Result<PluginDispatchSnapshot, PluginDispatchStoreError> {
        Ok(self.snapshot.clone())
    }

    fn save(&mut self, snapshot: &PluginDispatchSnapshot) -> Result<(), PluginDispatchStoreError> {
        self.snapshot = snapshot.clone();
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqlitePluginDispatchStore {
    connection: Connection,
}

impl SqlitePluginDispatchStore {
    pub fn open_in_memory() -> Result<Self, PluginDispatchStoreError> {
        Self::new(Connection::open_in_memory().map_err(|error| sqlite_store_error(&error))?)
    }

    pub fn new(connection: Connection) -> Result<Self, PluginDispatchStoreError> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scheduler_plugin_dispatches (
                    snapshot_id INTEGER PRIMARY KEY CHECK (snapshot_id = 1),
                    snapshot_json TEXT NOT NULL
                )",
            )
            .map_err(|error| sqlite_store_error(&error))?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl PluginDispatchStore for SqlitePluginDispatchStore {
    fn load(&self) -> Result<PluginDispatchSnapshot, PluginDispatchStoreError> {
        let json = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM scheduler_plugin_dispatches WHERE snapshot_id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| sqlite_store_error(&error))?;
        json.map_or_else(
            || Ok(PluginDispatchSnapshot::default()),
            |value| {
                serde_json::from_str(&value)
                    .map_err(|error| PluginDispatchStoreError::Serialization(error.to_string()))
            },
        )
    }

    fn save(&mut self, snapshot: &PluginDispatchSnapshot) -> Result<(), PluginDispatchStoreError> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| PluginDispatchStoreError::Serialization(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO scheduler_plugin_dispatches(snapshot_id, snapshot_json)
                 VALUES (1, ?1)
                 ON CONFLICT(snapshot_id) DO UPDATE SET snapshot_json = excluded.snapshot_json",
                params![json],
            )
            .map_err(|error| sqlite_store_error(&error))?;
        Ok(())
    }
}

fn sqlite_store_error(error: &rusqlite::Error) -> PluginDispatchStoreError {
    PluginDispatchStoreError::Sqlite(error.to_string())
}

/// Provider boundary for mounting/resolving and issuing a capability request.
/// Implementations must make dispatch idempotent by `token_digest`; this
/// interface intentionally has no Effect executor or completion authority.
pub trait PluginDispatchProvider: fmt::Debug {
    fn provider_id_digest(&self) -> &str;
    fn mount_plugin_session(
        &mut self,
        binding: &PluginSessionBinding,
        mounted_at: DateTime<Utc>,
    ) -> Result<PluginSessionMountReceipt, PluginDispatchProviderError>;
    fn resolve_plugin_session(
        &mut self,
        binding: &PluginSessionBinding,
        mount: &PluginSessionMountReceipt,
        resolved_at: DateTime<Utc>,
    ) -> Result<ResolvedPluginSession, PluginDispatchProviderError>;
    fn dispatch_capability(
        &mut self,
        session: &ResolvedPluginSession,
        token: &DispatchWakeToken,
        dispatched_at: DateTime<Utc>,
    ) -> Result<ProviderDispatchAck, PluginDispatchProviderError>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PluginDispatchProviderError {
    #[error("plugin dispatch provider identity does not match the durable request")]
    IdentityMismatch,
    #[error("plugin dispatch provider cannot mount the exact session")]
    SessionUnavailable,
    #[error("plugin dispatch provider returned a conflicting session receipt")]
    SessionReceiptConflict,
    #[error("plugin dispatch provider returned a conflicting token acknowledgement")]
    TokenConflict,
    #[error("plugin dispatch provider backend failed")]
    Backend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchPreparation {
    pub token: DispatchWakeToken,
    pub binding: PluginSessionBinding,
    pub mount: PluginSessionMountReceipt,
    pub resolved: ResolvedPluginSession,
}

/// Outcome of an exactly-once dispatch attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginDispatchOutcome {
    Dispatched(TriggerDispatchReceipt),
    AlreadyDispatched(TriggerDispatchReceipt),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DispatchSlot {
    scope: MissionScope,
    schedule_id_digest: String,
}

impl DispatchSlot {
    fn new(scope: &MissionScope, schedule_id_digest: &str) -> Self {
        Self {
            scope: scope.clone(),
            schedule_id_digest: schedule_id_digest.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescheduleResult {
    pub schedule_revision: u64,
    pub lease_revision: u64,
    pub rescheduled_at: DateTime<Utc>,
}

/// Input for one exact schedule/lease revision CAS reschedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescheduleCommand {
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub expected_schedule_revision: u64,
    pub expected_lease_revision: u64,
    pub new_request: DurablePluginWakeRequest,
    pub new_lease: DispatchLease,
    pub rescheduled_at: DateTime<Utc>,
}

/// Scheduler-owned durable dispatch service.  It is intentionally generic
/// over both the provider and the persistence backend so deterministic tests
/// do not require PostgreSQL or an OS runtime.
#[derive(Debug)]
pub struct PluginDispatchService<P, S = MemoryPluginDispatchStore> {
    provider: P,
    store: S,
    provider_id_digest: String,
    records: BTreeMap<DispatchSlot, DispatchRecord>,
}

pub type ScheduledPluginDispatchService<P, S = MemoryPluginDispatchStore> =
    PluginDispatchService<P, S>;

impl<P> PluginDispatchService<P, MemoryPluginDispatchStore>
where
    P: PluginDispatchProvider,
{
    pub fn new(provider: P) -> Result<Self, PluginDispatchError> {
        Self::with_store(provider, MemoryPluginDispatchStore::default())
    }
}

impl<P, S> PluginDispatchService<P, S>
where
    P: PluginDispatchProvider,
    S: PluginDispatchStore,
{
    pub fn with_store(provider: P, store: S) -> Result<Self, PluginDispatchError> {
        let provider_id_digest = provider.provider_id_digest().to_owned();
        if !is_digest(&provider_id_digest) {
            return Err(PluginDispatchError::InvalidProvider);
        }
        let snapshot = store.load()?;
        let mut records = BTreeMap::new();
        for record in snapshot.records {
            record.validate(&provider_id_digest)?;
            let slot = DispatchSlot::new(
                &record.request.scope,
                &record.request.schedule.schedule_id_digest,
            );
            if records.insert(slot, record).is_some() {
                return Err(PluginDispatchError::CorruptRecord);
            }
        }
        Ok(Self {
            provider,
            store,
            provider_id_digest,
            records,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn snapshot(&self) -> PluginDispatchSnapshot {
        PluginDispatchSnapshot {
            records: self.records.values().cloned().collect(),
        }
    }

    pub fn record(
        &self,
        scope: &MissionScope,
        schedule_id_digest: &str,
    ) -> Option<&DispatchRecord> {
        self.records
            .get(&DispatchSlot::new(scope, schedule_id_digest))
    }

    /// Accept one exact trigger receipt and mint its single-use dispatch token.
    /// Repeating the same exact wake is idempotent; a different receipt for the
    /// same schedule revision is rejected.
    pub fn register_trigger(
        &mut self,
        request: &DurablePluginWakeRequest,
        trigger: TriggerReceipt,
        lease: &DispatchLease,
        registered_at: DateTime<Utc>,
    ) -> Result<DispatchWakeToken, PluginDispatchError> {
        request.validate()?;
        trigger.validate()?;
        lease.validate()?;
        ensure_trigger_matches_request(request, &trigger)?;
        if request.provider_id_digest != self.provider_id_digest {
            return Err(PluginDispatchError::InvalidProvider);
        }
        if !lease.is_live_at(registered_at) {
            return Err(PluginDispatchError::LeaseExpired);
        }
        let slot = DispatchSlot::new(&request.scope, &request.schedule.schedule_id_digest);
        let existing = self.records.get(&slot).cloned();
        if let Some(current) = &existing {
            if current.head.state == DispatchState::Cancelled {
                return Err(PluginDispatchError::ScheduleCancelled);
            }
            if current.request != *request {
                return Err(PluginDispatchError::StaleScheduleRevision);
            }
            if current.lease != *lease {
                return Err(PluginDispatchError::LeaseRevisionConflict);
            }
            if let (Some(current_trigger), Some(current_token)) = (&current.trigger, &current.token)
            {
                if current_trigger == &trigger {
                    return Ok(current_token.clone());
                }
                return Err(PluginDispatchError::TriggerConflict);
            }
            if current.trigger.is_some() || current.token.is_some() {
                return Err(PluginDispatchError::CorruptRecord);
            }
            if current.head.state != DispatchState::Pending {
                return Err(PluginDispatchError::DispatchReserved);
            }
        }
        let token = DispatchWakeToken::issue(request, &trigger, lease, registered_at)?;
        let mut record = existing.unwrap_or_else(|| DispatchRecord {
            request: request.clone(),
            trigger: None,
            lease: lease.clone(),
            token: None,
            head: DispatchHead {
                scope: request.scope.clone(),
                schedule_id_digest: request.schedule.schedule_id_digest.clone(),
                schedule_revision: request.schedule.schedule_revision,
                lease_revision: lease.lease_revision,
                dispatch_revision: 0,
                state: DispatchState::Pending,
                registered_at,
                updated_at: registered_at,
                dispatch_started_at: None,
            },
            binding: None,
            mount: None,
            resolved: None,
            receipt: None,
        });
        record.trigger = Some(trigger);
        record.token = Some(token.clone());
        record.head.updated_at = registered_at;
        self.replace_record(slot, record)?;
        Ok(token)
    }

    /// Mount and resolve the exact plugin session, but do not yet win the
    /// final dispatch CAS.  Keeping this phase public lets race tests model a
    /// cancellation/reschedule arriving between resolve and dispatch.
    pub fn prepare_dispatch(
        &mut self,
        token: &DispatchWakeToken,
        observed_at: DateTime<Utc>,
    ) -> Result<DispatchPreparation, PluginDispatchError> {
        let slot = DispatchSlot::new(&token.scope, &token.schedule_id_digest);
        let before = self
            .records
            .get(&slot)
            .cloned()
            .ok_or(PluginDispatchError::ScheduleNotFound)?;
        Self::validate_token_for_record(&before, token)?;
        match before.head.state {
            DispatchState::Cancelled => return Err(PluginDispatchError::ScheduleCancelled),
            DispatchState::Dispatched => return Err(PluginDispatchError::AlreadyDispatched),
            DispatchState::Pending | DispatchState::Dispatching => {}
        }
        if !before.lease.is_live_at(observed_at) {
            return Err(PluginDispatchError::LeaseExpired);
        }
        let trigger = before
            .trigger
            .as_ref()
            .ok_or(PluginDispatchError::WakeNotRegistered)?;
        let binding = PluginSessionBinding::from_exact(&before.request, trigger, &before.lease)?;
        if let Some(existing) = &before.binding
            && existing != &binding
        {
            return Err(PluginDispatchError::SessionBindingConflict);
        }
        let mount = self
            .provider
            .mount_plugin_session(&binding, observed_at)
            .map_err(|error| PluginDispatchError::Provider(error.to_string()))?;
        mount.validate_for(&binding)?;
        if before
            .mount
            .as_ref()
            .is_some_and(|existing| existing != &mount)
        {
            return Err(PluginDispatchError::SessionReceiptConflict);
        }
        let resolved = self
            .provider
            .resolve_plugin_session(&binding, &mount, observed_at)
            .map_err(|error| PluginDispatchError::Provider(error.to_string()))?;
        resolved.validate_for(&binding, &mount)?;
        if before
            .resolved
            .as_ref()
            .is_some_and(|existing| existing != &resolved)
        {
            return Err(PluginDispatchError::SessionReceiptConflict);
        }
        let mut after = before.clone();
        after.binding = Some(binding.clone());
        after.mount = Some(mount.clone());
        after.resolved = Some(resolved.clone());
        after.head.updated_at = observed_at;
        self.replace_record(slot, after)?;
        Ok(DispatchPreparation {
            token: token.clone(),
            binding,
            mount,
            resolved,
        })
    }

    /// Commit the final exact revision CAS and issue one provider capability
    /// request.  A persisted `Dispatching` state is retried with the same
    /// token after a crash; it cannot be cancelled or rescheduled afterward.
    pub fn commit_dispatch(
        &mut self,
        preparation: &DispatchPreparation,
        dispatched_at: DateTime<Utc>,
    ) -> Result<PluginDispatchOutcome, PluginDispatchError> {
        let token = &preparation.token;
        let slot = DispatchSlot::new(&token.scope, &token.schedule_id_digest);
        let current = self
            .records
            .get(&slot)
            .cloned()
            .ok_or(PluginDispatchError::ScheduleNotFound)?;
        Self::validate_token_for_record(&current, token)?;
        Self::validate_preparation_for_record(&current, preparation)?;
        if current.head.state == DispatchState::Cancelled {
            return Err(PluginDispatchError::ScheduleCancelled);
        }
        if current.head.state == DispatchState::Dispatched {
            return Ok(PluginDispatchOutcome::AlreadyDispatched(
                current.receipt.ok_or(PluginDispatchError::CorruptRecord)?,
            ));
        }
        let reserved = if current.head.state == DispatchState::Pending {
            let mut next = current.clone();
            next.head.state = DispatchState::Dispatching;
            next.head.dispatch_revision = 1;
            next.head.dispatch_started_at = Some(dispatched_at);
            next.head.updated_at = dispatched_at;
            self.replace_record(slot.clone(), next.clone())?;
            next
        } else {
            current.clone()
        };
        let session = reserved
            .resolved
            .as_ref()
            .ok_or(PluginDispatchError::CorruptRecord)?;
        let ack = self
            .provider
            .dispatch_capability(session, token, dispatched_at)
            .map_err(|error| PluginDispatchError::Provider(error.to_string()))?;
        ack.validate_for(token, session)?;
        if ack.dispatched_at
            < reserved
                .head
                .dispatch_started_at
                .ok_or(PluginDispatchError::CorruptRecord)?
        {
            return Err(PluginDispatchError::ProviderAckConflict);
        }
        let trigger = reserved
            .trigger
            .as_ref()
            .ok_or(PluginDispatchError::WakeNotRegistered)?;
        let binding = reserved
            .binding
            .as_ref()
            .ok_or(PluginDispatchError::CorruptRecord)?;
        let mount = reserved
            .mount
            .as_ref()
            .ok_or(PluginDispatchError::CorruptRecord)?;
        let resolved = reserved
            .resolved
            .as_ref()
            .ok_or(PluginDispatchError::CorruptRecord)?;
        let dispatch_started_at = reserved
            .head
            .dispatch_started_at
            .ok_or(PluginDispatchError::CorruptRecord)?;
        let context = DispatchReceiptContext {
            request: &reserved.request,
            trigger,
            token,
            lease: &reserved.lease,
            binding,
            mount,
            resolved,
            registered_at: reserved.head.registered_at,
            dispatch_started_at,
        };
        let receipt =
            TriggerDispatchReceipt::from_parts(&context, reserved.head.dispatch_revision, &ack)?;
        let mut completed = reserved.clone();
        completed.head.state = DispatchState::Dispatched;
        completed.head.updated_at = ack.dispatched_at;
        completed.receipt = Some(receipt.clone());
        if let Err(error) = self.replace_record(slot, completed) {
            // Keep the durable reservation in memory.  The provider call may
            // already have succeeded; the next retry uses the same token.
            self.records.insert(
                DispatchSlot::new(&reserved.request.scope, &reserved.head.schedule_id_digest),
                reserved,
            );
            return Err(error);
        }
        Ok(PluginDispatchOutcome::Dispatched(receipt))
    }

    /// Prepare and commit in one call for the normal wake path.
    pub fn dispatch_once(
        &mut self,
        token: &DispatchWakeToken,
        observed_at: DateTime<Utc>,
    ) -> Result<PluginDispatchOutcome, PluginDispatchError> {
        let slot = DispatchSlot::new(&token.scope, &token.schedule_id_digest);
        if let Some(record) = self.records.get(&slot) {
            Self::validate_token_for_record(record, token)?;
            if record.head.state == DispatchState::Dispatched {
                return Ok(PluginDispatchOutcome::AlreadyDispatched(
                    record
                        .receipt
                        .clone()
                        .ok_or(PluginDispatchError::CorruptRecord)?,
                ));
            }
        }
        let preparation = self.prepare_dispatch(token, observed_at)?;
        self.commit_dispatch(&preparation, observed_at)
    }

    /// Exact CAS cancellation.  It can win only while the record is pending;
    /// a persisted dispatch reservation is already the winner.
    pub fn cancel(
        &mut self,
        scope: &MissionScope,
        schedule_id_digest: &str,
        expected_schedule_revision: u64,
        expected_lease_revision: u64,
        cancelled_at: DateTime<Utc>,
    ) -> Result<(), PluginDispatchError> {
        let slot = DispatchSlot::new(scope, schedule_id_digest);
        let current = self
            .records
            .get(&slot)
            .cloned()
            .ok_or(PluginDispatchError::ScheduleNotFound)?;
        ensure_cas(
            &current,
            expected_schedule_revision,
            expected_lease_revision,
        )?;
        match current.head.state {
            DispatchState::Cancelled => Ok(()),
            DispatchState::Dispatching | DispatchState::Dispatched => {
                Err(PluginDispatchError::DispatchReserved)
            }
            DispatchState::Pending => {
                let mut next = current.clone();
                next.head.state = DispatchState::Cancelled;
                next.head.updated_at = cancelled_at;
                self.replace_record(slot, next)
            }
        }
    }

    /// Exact CAS reschedule.  The new request replaces the old pending wake,
    /// increments the lease revision by one, and requires a fresh trigger
    /// receipt before a new token can be minted.
    pub fn reschedule(
        &mut self,
        command: RescheduleCommand,
    ) -> Result<RescheduleResult, PluginDispatchError> {
        let RescheduleCommand {
            scope,
            schedule_id_digest,
            expected_schedule_revision,
            expected_lease_revision,
            new_request,
            new_lease,
            rescheduled_at,
        } = command;
        new_request.validate()?;
        new_lease.validate()?;
        if new_request.provider_id_digest != self.provider_id_digest
            || new_request.scope != scope
            || new_request.schedule.schedule_id_digest != schedule_id_digest
        {
            return Err(PluginDispatchError::ScopeOrScheduleMismatch);
        }
        let slot = DispatchSlot::new(&scope, &schedule_id_digest);
        let current = self
            .records
            .get(&slot)
            .cloned()
            .ok_or(PluginDispatchError::ScheduleNotFound)?;
        ensure_cas(
            &current,
            expected_schedule_revision,
            expected_lease_revision,
        )?;
        if current.head.state != DispatchState::Pending {
            return if current.head.state == DispatchState::Cancelled {
                Err(PluginDispatchError::ScheduleCancelled)
            } else {
                Err(PluginDispatchError::DispatchReserved)
            };
        }
        if new_request.schedule.schedule_revision <= expected_schedule_revision
            || new_lease.lease_revision != expected_lease_revision.saturating_add(1)
        {
            return Err(PluginDispatchError::StaleScheduleRevision);
        }
        let new_scope = new_request.scope.clone();
        let new_schedule_id_digest = new_request.schedule.schedule_id_digest.clone();
        let new_schedule_revision = new_request.schedule.schedule_revision;
        let new_lease_revision = new_lease.lease_revision;
        let next = DispatchRecord {
            request: new_request,
            trigger: None,
            lease: new_lease,
            token: None,
            head: DispatchHead {
                scope: new_scope,
                schedule_id_digest: new_schedule_id_digest,
                schedule_revision: new_schedule_revision,
                lease_revision: new_lease_revision,
                dispatch_revision: 0,
                state: DispatchState::Pending,
                registered_at: rescheduled_at,
                updated_at: rescheduled_at,
                dispatch_started_at: None,
            },
            binding: None,
            mount: None,
            resolved: None,
            receipt: None,
        };
        self.replace_record(slot, next)?;
        Ok(RescheduleResult {
            schedule_revision: new_schedule_revision,
            lease_revision: new_lease_revision,
            rescheduled_at,
        })
    }

    fn replace_record(
        &mut self,
        slot: DispatchSlot,
        record: DispatchRecord,
    ) -> Result<(), PluginDispatchError> {
        record.validate(&self.provider_id_digest)?;
        let before = self.records.insert(slot.clone(), record);
        if let Err(error) = self.sync_store() {
            match before {
                Some(previous) => {
                    self.records.insert(slot, previous);
                }
                None => {
                    self.records.remove(&slot);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn sync_store(&mut self) -> Result<(), PluginDispatchError> {
        self.store.save(&self.snapshot())?;
        Ok(())
    }

    fn validate_token_for_record(
        record: &DispatchRecord,
        token: &DispatchWakeToken,
    ) -> Result<(), PluginDispatchError> {
        let stored = record
            .token
            .as_ref()
            .ok_or(PluginDispatchError::WakeTokenStale)?;
        if stored != token {
            return Err(PluginDispatchError::WakeTokenStale);
        }
        let trigger = record
            .trigger
            .as_ref()
            .ok_or(PluginDispatchError::WakeNotRegistered)?;
        token.validate_for(&record.request, trigger, &record.lease)
    }

    fn validate_preparation_for_record(
        record: &DispatchRecord,
        preparation: &DispatchPreparation,
    ) -> Result<(), PluginDispatchError> {
        let stored = record
            .token
            .as_ref()
            .ok_or(PluginDispatchError::WakeTokenStale)?;
        if stored != &preparation.token {
            return Err(PluginDispatchError::WakeTokenStale);
        }
        let trigger = record
            .trigger
            .as_ref()
            .ok_or(PluginDispatchError::WakeNotRegistered)?;
        preparation
            .token
            .validate_for(&record.request, trigger, &record.lease)?;
        let binding = record
            .binding
            .as_ref()
            .ok_or(PluginDispatchError::SessionBindingConflict)?;
        let mount = record
            .mount
            .as_ref()
            .ok_or(PluginDispatchError::SessionReceiptConflict)?;
        let resolved = record
            .resolved
            .as_ref()
            .ok_or(PluginDispatchError::InvalidResolvedSession)?;
        if binding != &preparation.binding
            || mount != &preparation.mount
            || resolved != &preparation.resolved
        {
            return Err(PluginDispatchError::StalePreparation);
        }
        Ok(())
    }
}

fn ensure_cas(
    record: &DispatchRecord,
    expected_schedule_revision: u64,
    expected_lease_revision: u64,
) -> Result<(), PluginDispatchError> {
    if record.head.schedule_revision != expected_schedule_revision {
        return Err(PluginDispatchError::StaleScheduleRevision);
    }
    if record.head.lease_revision != expected_lease_revision {
        return Err(PluginDispatchError::LeaseRevisionConflict);
    }
    Ok(())
}

fn ensure_trigger_matches_request(
    request: &DurablePluginWakeRequest,
    trigger: &TriggerReceipt,
) -> Result<(), PluginDispatchError> {
    if trigger.request_id_digest != request.request_id_digest
        || trigger.request_digest != request.request_digest
        || trigger.objective_digest != request.objective_digest
        || trigger.scope != request.scope
        || trigger.schedule_id_digest != request.schedule.schedule_id_digest
        || trigger.schedule_revision != request.schedule.schedule_revision
        || trigger.planned_at != request.schedule.planned_at
        || trigger.coalesced_ticks != request.wake.coalesced_ticks
        || trigger.composition != request.composition
        || trigger.invocation != request.invocation
        || trigger.provider_id_digest != request.provider_id_digest
        || trigger.provider_epoch != request.provider_epoch
    {
        return Err(PluginDispatchError::TriggerConflict);
    }
    Ok(())
}

fn validate_invocation_for_composition(
    invocation: &PluginInvocation,
    composition: &PluginComposition,
) -> Result<(), PluginDispatchError> {
    let canonical =
        PluginInvocation::new(invocation.plugin_id.clone(), invocation.operation.clone())?;
    if canonical != *invocation || composition.plugin(&invocation.plugin_id).is_none() {
        return Err(PluginDispatchError::PluginCompositionMismatch);
    }
    Ok(())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, PluginDispatchError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PluginDispatchError::Serialization(error.to_string()))?;
    Ok(scheduler_digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PluginDispatchError {
    #[error("plugin invocation contract is invalid: {0}")]
    Invocation(#[from] PluginInvocationError),
    #[error("plugin dispatch provider is invalid")]
    InvalidProvider,
    #[error("plugin dispatch lease is invalid")]
    InvalidLease,
    #[error("plugin dispatch wake token is invalid")]
    InvalidWakeToken,
    #[error("plugin dispatch wake contract is invalid: {0}")]
    WakeContract(String),
    #[error("plugin dispatch trigger conflicts with the exact wake request")]
    TriggerConflict,
    #[error("plugin dispatch plugin composition is not exact")]
    PluginCompositionMismatch,
    #[error("plugin dispatch session binding is invalid")]
    InvalidSessionBinding,
    #[error("plugin dispatch session receipt is invalid")]
    InvalidSessionReceipt,
    #[error("plugin dispatch resolved session is invalid")]
    InvalidResolvedSession,
    #[error("plugin dispatch provider acknowledgement is invalid")]
    InvalidProviderAck,
    #[error("plugin dispatch provider acknowledgement conflicts with the reservation")]
    ProviderAckConflict,
    #[error("plugin dispatch receipt is invalid")]
    InvalidDispatchReceipt,
    #[error("plugin dispatch receipt conflicts with the exact record")]
    DispatchReceiptConflict,
    #[error("plugin dispatch session binding conflicts with the exact record")]
    SessionBindingConflict,
    #[error("plugin dispatch session receipt conflicts with the exact record")]
    SessionReceiptConflict,
    #[error("plugin dispatch preparation is stale")]
    StalePreparation,
    #[error("plugin dispatch schedule was not found")]
    ScheduleNotFound,
    #[error("plugin dispatch schedule revision lost the CAS")]
    StaleScheduleRevision,
    #[error("plugin dispatch lease revision lost the CAS")]
    LeaseRevisionConflict,
    #[error("plugin dispatch schedule is cancelled")]
    ScheduleCancelled,
    #[error("plugin dispatch reservation already won the CAS")]
    DispatchReserved,
    #[error("plugin dispatch receipt already exists")]
    AlreadyDispatched,
    #[error("plugin dispatch wake was not registered")]
    WakeNotRegistered,
    #[error("plugin dispatch wake token is stale")]
    WakeTokenStale,
    #[error("plugin dispatch lease has expired")]
    LeaseExpired,
    #[error("plugin dispatch scope or schedule does not match")]
    ScopeOrScheduleMismatch,
    #[error("plugin dispatch record is corrupt")]
    CorruptRecord,
    #[error("plugin dispatch provider failed: {0}")]
    Provider(String),
    #[error("plugin dispatch store failed: {0}")]
    Store(#[from] PluginDispatchStoreError),
    #[error("plugin dispatch serialization failed: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration, TimeZone};
    use hartevo_cloud_storage::DataCell;

    use super::*;
    use crate::plugin_invocation::{
        PluginInvocationInput, PluginInvocationProvider, PluginInvocationService, PluginManifest,
        ProviderLifecycleTransition, ProviderMountRequest, ProviderWakeReceipt,
        SchedulingProviderError,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("valid test time")
    }

    fn digest(byte: u8) -> String {
        scheduler_digest([byte])
    }

    fn scope(revision: u64) -> MissionScope {
        MissionScope::new(
            DataCell::Us,
            "tenant-dispatch",
            "project-dispatch",
            "mission-dispatch",
            revision,
        )
        .expect("scope")
    }

    fn composition(scope: &MissionScope, version: &str, plugin_byte: u8) -> PluginComposition {
        PluginComposition::new(
            scope.clone(),
            3,
            vec![
                PluginManifest::new("brief-plugin", version, digest(plugin_byte)).expect("plugin"),
            ],
        )
        .expect("composition")
    }

    fn invocation() -> PluginInvocation {
        PluginInvocation::new("brief-plugin", "generate").expect("invocation")
    }

    fn schedule(
        id_byte: u8,
        revision: u64,
        planned_at: DateTime<Utc>,
    ) -> crate::plugin_invocation::ScheduledPluginInvocation {
        crate::plugin_invocation::ScheduledPluginInvocation::new(
            digest(id_byte),
            revision,
            planned_at,
            60,
            now() + Duration::hours(8),
        )
        .expect("schedule")
    }

    #[derive(Debug, Default)]
    struct InvocationProvider {
        provider_id_digest: String,
        epoch: Option<u64>,
        armed: BTreeMap<String, ProviderWakeReceipt>,
    }

    impl InvocationProvider {
        fn new(provider_id_digest: String) -> Self {
            Self {
                provider_id_digest,
                ..Self::default()
            }
        }
    }

    impl PluginInvocationProvider for InvocationProvider {
        fn provider_id_digest(&self) -> &str {
            &self.provider_id_digest
        }

        fn resolve_composition(
            &mut self,
            scope: &MissionScope,
            composition: &PluginComposition,
            invocation: &PluginInvocation,
        ) -> Result<(), SchedulingProviderError> {
            if composition.scope != *scope || composition.plugin(&invocation.plugin_id).is_none() {
                return Err(SchedulingProviderError::CompositionUnavailable);
            }
            Ok(())
        }

        fn mount(&mut self, request: &ProviderMountRequest) -> Result<(), SchedulingProviderError> {
            if request.provider_id_digest != self.provider_id_digest || request.provider_epoch == 0
            {
                return Err(SchedulingProviderError::EpochLost);
            }
            self.epoch = Some(request.provider_epoch);
            Ok(())
        }

        fn unmount(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            if transition.provider_id_digest != self.provider_id_digest
                || self.epoch != Some(transition.previous_epoch)
            {
                return Err(SchedulingProviderError::EpochLost);
            }
            self.epoch = None;
            Ok(())
        }

        fn revoke(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.unmount(transition)
        }

        fn crash(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.unmount(transition)
        }

        fn on_sleep(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            if transition.provider_id_digest != self.provider_id_digest
                || self.epoch != Some(transition.previous_epoch)
            {
                return Err(SchedulingProviderError::EpochLost);
            }
            Ok(())
        }

        fn on_wake(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            if transition.provider_id_digest != self.provider_id_digest
                || self.epoch != Some(transition.previous_epoch)
            {
                return Err(SchedulingProviderError::EpochLost);
            }
            self.epoch = Some(transition.next_epoch);
            Ok(())
        }

        fn revoke_plugin(
            &mut self,
            _plugin: &PluginManifest,
        ) -> Result<(), SchedulingProviderError> {
            Ok(())
        }

        fn arm_wake(
            &mut self,
            request: &DurablePluginWakeRequest,
        ) -> Result<ProviderWakeReceipt, SchedulingProviderError> {
            if self.epoch != Some(request.provider_epoch)
                || request.provider_id_digest != self.provider_id_digest
            {
                return Err(SchedulingProviderError::EpochLost);
            }
            if let Some(existing) = self.armed.get(&request.request_id_digest) {
                if existing.request_digest != request.request_digest {
                    return Err(SchedulingProviderError::ReceiptConflict);
                }
                return Ok(existing.clone());
            }
            let receipt = ProviderWakeReceipt {
                request_id_digest: request.request_id_digest.clone(),
                request_digest: request.request_digest.clone(),
                provider_id_digest: self.provider_id_digest.clone(),
                provider_epoch: request.provider_epoch,
                lifecycle_receipt: None,
            };
            self.armed
                .insert(request.request_id_digest.clone(), receipt.clone());
            Ok(receipt)
        }

        fn disarm_wake(
            &mut self,
            receipt: &ProviderWakeReceipt,
        ) -> Result<(), SchedulingProviderError> {
            self.armed.remove(&receipt.request_id_digest);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Fixture {
        base: PluginInvocationService<InvocationProvider>,
        request: DurablePluginWakeRequest,
        trigger: TriggerReceipt,
        scope: MissionScope,
        composition: PluginComposition,
        invocation: PluginInvocation,
        provider_id_digest: String,
        trigger_time: DateTime<Utc>,
    }

    fn make_fixture() -> Fixture {
        make_fixture_with_scope(scope(11))
    }

    fn make_fixture_with_scope(scope: MissionScope) -> Fixture {
        let time = now();
        let composition = composition(&scope, "2.4.1", b'v');
        let invocation = invocation();
        let provider_id_digest = digest(b'p');
        let mut base =
            PluginInvocationService::new(InvocationProvider::new(provider_id_digest.clone()))
                .expect("base service");
        assert_eq!(base.mount_provider(scope.clone(), time).expect("mount"), 1);
        base.schedule_invocation(
            PluginInvocationInput {
                objective: "generate a project brief".to_owned(),
                scope: scope.clone(),
                schedule: schedule(b's', 7, time + Duration::minutes(1)),
                composition: composition.clone(),
                invocation: invocation.clone(),
            },
            time,
        )
        .expect("schedule");
        let trigger_time = time + Duration::minutes(2);
        let trigger = base
            .cell_wake(1, trigger_time)
            .expect("wake")
            .pop()
            .expect("trigger");
        let request = base
            .latest_request(&digest(b's'))
            .cloned()
            .expect("coalesced request");
        Fixture {
            base,
            request,
            trigger,
            scope,
            composition,
            invocation,
            provider_id_digest,
            trigger_time,
        }
    }

    #[derive(Debug)]
    struct RecordingDispatchProvider {
        provider_id_digest: String,
        mounts: BTreeMap<String, PluginSessionMountReceipt>,
        resolutions: BTreeMap<String, ResolvedPluginSession>,
        acknowledgements: BTreeMap<String, ProviderDispatchAck>,
        mount_calls: usize,
        resolve_calls: usize,
        dispatch_calls: usize,
    }

    impl RecordingDispatchProvider {
        fn new(provider_id_digest: String) -> Self {
            Self {
                provider_id_digest,
                mounts: BTreeMap::new(),
                resolutions: BTreeMap::new(),
                acknowledgements: BTreeMap::new(),
                mount_calls: 0,
                resolve_calls: 0,
                dispatch_calls: 0,
            }
        }
    }

    impl PluginDispatchProvider for RecordingDispatchProvider {
        fn provider_id_digest(&self) -> &str {
            &self.provider_id_digest
        }

        fn mount_plugin_session(
            &mut self,
            binding: &PluginSessionBinding,
            mounted_at: DateTime<Utc>,
        ) -> Result<PluginSessionMountReceipt, PluginDispatchProviderError> {
            if binding.provider_id_digest != self.provider_id_digest {
                return Err(PluginDispatchProviderError::IdentityMismatch);
            }
            if let Some(existing) = self.mounts.get(&binding.binding_digest) {
                return Ok(existing.clone());
            }
            self.mount_calls += 1;
            let receipt = PluginSessionMountReceipt::new(binding, 1, mounted_at)
                .map_err(|_| PluginDispatchProviderError::SessionUnavailable)?;
            self.mounts
                .insert(binding.binding_digest.clone(), receipt.clone());
            Ok(receipt)
        }

        fn resolve_plugin_session(
            &mut self,
            binding: &PluginSessionBinding,
            mount: &PluginSessionMountReceipt,
            resolved_at: DateTime<Utc>,
        ) -> Result<ResolvedPluginSession, PluginDispatchProviderError> {
            if binding.provider_id_digest != self.provider_id_digest {
                return Err(PluginDispatchProviderError::IdentityMismatch);
            }
            if let Some(existing) = self.resolutions.get(&binding.binding_digest) {
                return Ok(existing.clone());
            }
            self.resolve_calls += 1;
            let resolved = ResolvedPluginSession::new(binding, mount, 1, resolved_at)
                .map_err(|_| PluginDispatchProviderError::SessionUnavailable)?;
            self.resolutions
                .insert(binding.binding_digest.clone(), resolved.clone());
            Ok(resolved)
        }

        fn dispatch_capability(
            &mut self,
            session: &ResolvedPluginSession,
            token: &DispatchWakeToken,
            dispatched_at: DateTime<Utc>,
        ) -> Result<ProviderDispatchAck, PluginDispatchProviderError> {
            if token.provider_id_digest != self.provider_id_digest {
                return Err(PluginDispatchProviderError::IdentityMismatch);
            }
            if let Some(existing) = self.acknowledgements.get(&token.token_digest) {
                if existing.session_digest != session.session_digest {
                    return Err(PluginDispatchProviderError::TokenConflict);
                }
                return Ok(existing.clone());
            }
            self.dispatch_calls += 1;
            let ack = ProviderDispatchAck::new(
                token,
                session,
                self.provider_id_digest.clone(),
                token.provider_epoch,
                dispatched_at,
            )
            .map_err(|_| PluginDispatchProviderError::Backend)?;
            self.acknowledgements
                .insert(token.token_digest.clone(), ack.clone());
            Ok(ack)
        }
    }

    fn lease(revision: u64, generation: u64, expires_at: DateTime<Utc>) -> DispatchLease {
        DispatchLease::new(digest(b'l'), revision, generation, expires_at).expect("lease")
    }

    #[test]
    fn exact_wake_token_mounts_bound_plugin_and_persists_one_capability_receipt() {
        let fixture = make_fixture();
        let mut service = PluginDispatchService::new(RecordingDispatchProvider::new(
            fixture.provider_id_digest.clone(),
        ))
        .expect("dispatch service");
        let dispatch_time = fixture.trigger_time + Duration::minutes(1);
        let lease = lease(4, 9, dispatch_time + Duration::hours(1));
        let token = service
            .register_trigger(
                &fixture.request,
                fixture.trigger.clone(),
                &lease,
                fixture.trigger_time,
            )
            .expect("register exact trigger");

        let first = service
            .dispatch_once(&token, dispatch_time)
            .expect("first dispatch");
        let receipt = match first {
            PluginDispatchOutcome::Dispatched(receipt) => receipt,
            PluginDispatchOutcome::AlreadyDispatched(_) => panic!("first dispatch replayed"),
        };
        receipt.validate().expect("valid durable receipt");
        assert_eq!(receipt.scope, fixture.scope);
        assert_eq!(receipt.project_id, "project-dispatch");
        assert_eq!(receipt.mission_id, "mission-dispatch");
        assert_eq!(receipt.schedule_revision, 7);
        assert_eq!(receipt.composition, fixture.composition);
        assert_eq!(receipt.plugin_id, "brief-plugin");
        assert_eq!(receipt.plugin_version, "2.4.1");
        assert_eq!(receipt.plugin_digest, digest(b'v'));
        assert_eq!(receipt.invocation, fixture.invocation);
        assert_eq!(receipt.wake_token_digest, token.token_digest);
        assert_eq!(receipt.lease_revision, 4);
        assert_eq!(receipt.dispatch_revision, 1);
        assert_eq!(receipt.authority, DispatchAuthority::CapabilityRequestOnly);
        assert_eq!(service.provider().mount_calls, 1);
        assert_eq!(service.provider().resolve_calls, 1);
        assert_eq!(service.provider().dispatch_calls, 1);

        let replay = service
            .dispatch_once(&token, dispatch_time + Duration::minutes(1))
            .expect("exact replay");
        assert_eq!(replay, PluginDispatchOutcome::AlreadyDispatched(receipt));
        assert_eq!(service.provider().dispatch_calls, 1);
        assert_eq!(
            service
                .record(&fixture.scope, &fixture.request.schedule.schedule_id_digest)
                .expect("record")
                .head
                .state,
            DispatchState::Dispatched
        );
    }

    #[test]
    fn cancellation_wins_after_session_resolution_before_final_cas() {
        let fixture = make_fixture();
        let mut service = PluginDispatchService::new(RecordingDispatchProvider::new(
            fixture.provider_id_digest.clone(),
        ))
        .expect("dispatch service");
        let lease = lease(4, 9, fixture.trigger_time + Duration::hours(1));
        let token = service
            .register_trigger(
                &fixture.request,
                fixture.trigger.clone(),
                &lease,
                fixture.trigger_time,
            )
            .expect("register");
        let preparation = service
            .prepare_dispatch(&token, fixture.trigger_time + Duration::minutes(1))
            .expect("mount and resolve");
        service
            .cancel(
                &fixture.scope,
                &fixture.request.schedule.schedule_id_digest,
                fixture.request.schedule.schedule_revision,
                lease.lease_revision,
                fixture.trigger_time + Duration::minutes(1),
            )
            .expect("cancel CAS");
        assert_eq!(
            service.commit_dispatch(&preparation, fixture.trigger_time + Duration::minutes(1)),
            Err(PluginDispatchError::ScheduleCancelled)
        );
        assert_eq!(service.provider().dispatch_calls, 0);
        assert_eq!(
            service
                .record(&fixture.scope, &fixture.request.schedule.schedule_id_digest)
                .expect("record")
                .head
                .state,
            DispatchState::Cancelled
        );
    }

    #[test]
    fn reschedule_wins_cas_and_old_token_cannot_dispatch_new_revision() {
        let mut fixture = make_fixture();
        let mut service = PluginDispatchService::new(RecordingDispatchProvider::new(
            fixture.provider_id_digest.clone(),
        ))
        .expect("dispatch service");
        let first_lease = lease(4, 9, fixture.trigger_time + Duration::hours(1));
        let old_token = service
            .register_trigger(
                &fixture.request,
                fixture.trigger.clone(),
                &first_lease,
                fixture.trigger_time,
            )
            .expect("register old trigger");
        let old_preparation = service
            .prepare_dispatch(&old_token, fixture.trigger_time + Duration::minutes(1))
            .expect("prepare old trigger");

        let new_request = fixture
            .base
            .schedule_invocation(
                PluginInvocationInput {
                    objective: "generate a project brief".to_owned(),
                    scope: fixture.scope.clone(),
                    schedule: schedule(b's', 8, fixture.trigger_time + Duration::minutes(4)),
                    composition: fixture.composition.clone(),
                    invocation: fixture.invocation.clone(),
                },
                fixture.trigger_time,
            )
            .expect("new schedule revision");
        let new_lease = lease(5, 10, fixture.trigger_time + Duration::hours(2));
        let result = service
            .reschedule(RescheduleCommand {
                scope: fixture.scope.clone(),
                schedule_id_digest: fixture.request.schedule.schedule_id_digest.clone(),
                expected_schedule_revision: 7,
                expected_lease_revision: first_lease.lease_revision,
                new_request: new_request.clone(),
                new_lease: new_lease.clone(),
                rescheduled_at: fixture.trigger_time + Duration::minutes(1),
            })
            .expect("reschedule CAS");
        assert_eq!(result.schedule_revision, 8);
        assert_eq!(result.lease_revision, 5);
        assert_eq!(
            service.commit_dispatch(
                &old_preparation,
                fixture.trigger_time + Duration::minutes(1),
            ),
            Err(PluginDispatchError::WakeTokenStale)
        );
        assert_eq!(service.provider().dispatch_calls, 0);

        let new_trigger_time = fixture.trigger_time + Duration::minutes(4);
        let new_trigger = fixture
            .base
            .cell_wake(1, new_trigger_time)
            .expect("new wake")
            .pop()
            .expect("new trigger");
        let new_token = service
            .register_trigger(&new_request, new_trigger, &new_lease, new_trigger_time)
            .expect("register new trigger");
        assert!(matches!(
            service
                .dispatch_once(&new_token, new_trigger_time + Duration::minutes(1))
                .expect("new dispatch"),
            PluginDispatchOutcome::Dispatched(_)
        ));
        assert_eq!(service.provider().dispatch_calls, 1);
    }

    #[derive(Debug)]
    struct FailOnceStore {
        snapshot: PluginDispatchSnapshot,
        save_calls: usize,
        fail_on_save: usize,
    }

    impl FailOnceStore {
        fn failing_on(save_call: usize) -> Self {
            Self {
                snapshot: PluginDispatchSnapshot::default(),
                save_calls: 0,
                fail_on_save: save_call,
            }
        }
    }

    impl PluginDispatchStore for FailOnceStore {
        fn load(&self) -> Result<PluginDispatchSnapshot, PluginDispatchStoreError> {
            Ok(self.snapshot.clone())
        }

        fn save(
            &mut self,
            snapshot: &PluginDispatchSnapshot,
        ) -> Result<(), PluginDispatchStoreError> {
            self.save_calls += 1;
            if self.save_calls == self.fail_on_save {
                return Err(PluginDispatchStoreError::WriteRejected);
            }
            self.snapshot = snapshot.clone();
            Ok(())
        }
    }

    #[test]
    fn crash_after_provider_ack_retries_same_token_without_duplicate_dispatch() {
        let fixture = make_fixture();
        let provider_id_digest = fixture.provider_id_digest.clone();
        let mut service = PluginDispatchService::with_store(
            RecordingDispatchProvider::new(provider_id_digest),
            FailOnceStore::failing_on(4),
        )
        .expect("dispatch service");
        let dispatch_time = fixture.trigger_time + Duration::minutes(1);
        let token = service
            .register_trigger(
                &fixture.request,
                fixture.trigger,
                &lease(4, 9, dispatch_time + Duration::hours(1)),
                dispatch_time,
            )
            .expect("register");
        let preparation = service
            .prepare_dispatch(&token, dispatch_time)
            .expect("prepare");
        assert_eq!(
            service.commit_dispatch(&preparation, dispatch_time),
            Err(PluginDispatchError::Store(
                PluginDispatchStoreError::WriteRejected,
            ))
        );
        assert_eq!(service.provider().dispatch_calls, 1);
        assert_eq!(
            service
                .record(
                    &preparation.binding.scope,
                    &preparation.binding.schedule_id_digest
                )
                .expect("reserved record")
                .head
                .state,
            DispatchState::Dispatching
        );

        let retry = service
            .dispatch_once(&token, dispatch_time + Duration::minutes(1))
            .expect("retry");
        assert!(matches!(retry, PluginDispatchOutcome::Dispatched(_)));
        assert_eq!(service.provider().dispatch_calls, 1);
    }

    #[test]
    fn sqlite_restart_replays_durable_receipt_without_provider_dispatch() {
        let fixture = make_fixture();
        let provider_id_digest = fixture.provider_id_digest.clone();
        let store = SqlitePluginDispatchStore::open_in_memory().expect("sqlite store");
        let mut service = PluginDispatchService::with_store(
            RecordingDispatchProvider::new(provider_id_digest.clone()),
            store,
        )
        .expect("dispatch service");
        let dispatch_time = fixture.trigger_time + Duration::minutes(1);
        let token = service
            .register_trigger(
                &fixture.request,
                fixture.trigger,
                &lease(4, 9, dispatch_time + Duration::hours(1)),
                dispatch_time,
            )
            .expect("register");
        let first = service
            .dispatch_once(&token, dispatch_time)
            .expect("dispatch");
        let receipt = match first {
            PluginDispatchOutcome::Dispatched(receipt) => receipt,
            PluginDispatchOutcome::AlreadyDispatched(_) => panic!("first dispatch replayed"),
        };
        let store = service.into_store();
        let mut restarted = PluginDispatchService::with_store(
            RecordingDispatchProvider::new(provider_id_digest),
            store,
        )
        .expect("restart from sqlite");
        assert_eq!(
            restarted
                .dispatch_once(&token, dispatch_time + Duration::minutes(1))
                .expect("receipt replay"),
            PluginDispatchOutcome::AlreadyDispatched(receipt)
        );
        assert_eq!(restarted.provider().dispatch_calls, 0);
    }

    #[test]
    fn cross_scope_or_tampered_token_is_rejected_before_provider_dispatch() {
        let fixture = make_fixture();
        let mut service = PluginDispatchService::new(RecordingDispatchProvider::new(
            fixture.provider_id_digest.clone(),
        ))
        .expect("dispatch service");
        let dispatch_time = fixture.trigger_time + Duration::minutes(1);
        let token = service
            .register_trigger(
                &fixture.request,
                fixture.trigger,
                &lease(4, 9, dispatch_time + Duration::hours(1)),
                dispatch_time,
            )
            .expect("register");
        let mut tampered = token.clone();
        tampered.token_digest = digest(b'x');
        assert_eq!(
            service.dispatch_once(&tampered, dispatch_time),
            Err(PluginDispatchError::WakeTokenStale)
        );
        assert_eq!(service.provider().dispatch_calls, 0);

        let other_fixture = make_fixture_with_scope(
            MissionScope::new(
                DataCell::Us,
                "tenant-other",
                "project-other",
                "mission-other",
                1,
            )
            .expect("other scope"),
        );
        let mut other_service = PluginDispatchService::new(RecordingDispatchProvider::new(
            other_fixture.provider_id_digest.clone(),
        ))
        .expect("other dispatch service");
        let other_token = other_service
            .register_trigger(
                &other_fixture.request,
                other_fixture.trigger,
                &lease(4, 9, dispatch_time + Duration::hours(1)),
                dispatch_time,
            )
            .expect("other scope token");
        assert_eq!(
            service.dispatch_once(&other_token, dispatch_time),
            Err(PluginDispatchError::ScheduleNotFound)
        );
    }

    #[test]
    fn wrong_revision_cas_cannot_cancel_or_reschedule() {
        let fixture = make_fixture();
        let mut service = PluginDispatchService::new(RecordingDispatchProvider::new(
            fixture.provider_id_digest.clone(),
        ))
        .expect("dispatch service");
        let dispatch_time = fixture.trigger_time + Duration::minutes(1);
        let lease = lease(4, 9, dispatch_time + Duration::hours(1));
        service
            .register_trigger(&fixture.request, fixture.trigger, &lease, dispatch_time)
            .expect("register");
        assert_eq!(
            service.cancel(
                &fixture.scope,
                &digest(b's'),
                6,
                lease.lease_revision,
                dispatch_time,
            ),
            Err(PluginDispatchError::StaleScheduleRevision)
        );
        assert_eq!(
            service.cancel(&fixture.scope, &digest(b's'), 7, 3, dispatch_time,),
            Err(PluginDispatchError::LeaseRevisionConflict)
        );
    }
}

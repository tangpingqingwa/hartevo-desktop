//! Plugin-first scheduled invocation wake/resume contracts.
//!
//! This module is the scheduler-owned vertical slice between one scheduled
//! Mission and one exact plugin composition.  It persists only bounded,
//! digest-bound records, lets an OS/Cell provider arm one wake, emits one
//! [`TriggerReceipt`], and hands a capability-only request to a scope-pinned
//! consumer.  It deliberately contains no Runtime, Browser, or Effect
//! executor, so a wake cannot grant Effect authority or replay an uncertain
//! action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_cloud_storage::DataCell;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::os::{
    MacOsWakeSleepAdapter, MacOsWakeSleepBackend, OsWakeSleepAdapter, WakeReceipt, WakeRequest,
    WakeSleepError,
};
use crate::scheduler_digest;

pub const DEFAULT_MAX_COALESCED_TICKS: u64 = 1_024;
pub const MAX_OBJECTIVE_BYTES: usize = 16 * 1_024;
pub const MAX_IDENTIFIER_BYTES: usize = 1_024;
pub const MAX_INTERVAL_SECONDS: u64 = 366 * 24 * 60 * 60;

/// Exact Cell/tenant/Project/Mission scope for one plugin composition.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    pub cell: DataCell,
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub mission_revision: u64,
}

impl MissionScope {
    pub fn new(
        cell: DataCell,
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
    ) -> Result<Self, PluginInvocationError> {
        let scope = Self {
            cell,
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            mission_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), PluginInvocationError> {
        if !valid_identifier(&self.tenant_id)
            || !valid_identifier(&self.project_id)
            || !valid_identifier(&self.mission_id)
            || self.mission_revision == 0
        {
            return Err(PluginInvocationError::InvalidScope);
        }
        Ok(())
    }
}

/// One exact plugin manifest selected for a Mission composition.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    pub plugin_id: String,
    pub version: String,
    pub plugin_digest: String,
}

impl PluginManifest {
    pub fn new(
        plugin_id: impl Into<String>,
        version: impl Into<String>,
        plugin_digest: impl Into<String>,
    ) -> Result<Self, PluginInvocationError> {
        let manifest = Self {
            plugin_id: plugin_id.into(),
            version: version.into(),
            plugin_digest: plugin_digest.into(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), PluginInvocationError> {
        if !valid_identifier(&self.plugin_id)
            || !valid_identifier(&self.version)
            || !validate_digest(&self.plugin_digest)
        {
            return Err(PluginInvocationError::InvalidPluginManifest);
        }
        Ok(())
    }
}

/// Immutable composition resolved at schedule registration.  The digest
/// covers scope, composition revision, plugin IDs, versions and digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginComposition {
    pub scope: MissionScope,
    pub composition_revision: u64,
    pub plugins: Vec<PluginManifest>,
    pub composition_digest: String,
}

impl PluginComposition {
    pub fn new(
        scope: MissionScope,
        composition_revision: u64,
        mut plugins: Vec<PluginManifest>,
    ) -> Result<Self, PluginInvocationError> {
        scope.validate()?;
        if composition_revision == 0 || plugins.is_empty() {
            return Err(PluginInvocationError::InvalidPluginComposition);
        }
        for plugin in &plugins {
            plugin.validate()?;
        }
        plugins.sort();
        if plugins
            .windows(2)
            .any(|pair| pair[0].plugin_id == pair[1].plugin_id)
        {
            return Err(PluginInvocationError::DuplicatePlugin);
        }
        let mut composition = Self {
            scope,
            composition_revision,
            plugins,
            composition_digest: String::new(),
        };
        composition.composition_digest = composition.expected_digest()?;
        composition.validate()?;
        Ok(composition)
    }

    pub fn expected_digest(&self) -> Result<String, PluginInvocationError> {
        digest_json(&CompositionMaterial {
            scope: &self.scope,
            composition_revision: self.composition_revision,
            plugins: &self.plugins,
        })
    }

    pub fn contains(&self, plugin: &PluginManifest) -> bool {
        self.plugins.iter().any(|candidate| candidate == plugin)
    }

    pub fn plugin(&self, plugin_id: &str) -> Option<&PluginManifest> {
        self.plugins
            .iter()
            .find(|plugin| plugin.plugin_id == plugin_id)
    }

    pub fn validate(&self) -> Result<(), PluginInvocationError> {
        self.scope.validate()?;
        if self.composition_revision == 0
            || self.plugins.is_empty()
            || self.composition_digest != self.expected_digest()?
        {
            return Err(PluginInvocationError::InvalidPluginComposition);
        }
        for plugin in &self.plugins {
            plugin.validate()?;
        }
        if self
            .plugins
            .windows(2)
            .any(|pair| pair[0] >= pair[1] || pair[0].plugin_id == pair[1].plugin_id)
        {
            return Err(PluginInvocationError::InvalidPluginComposition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginInvocationInput {
    pub objective: String,
    pub scope: MissionScope,
    pub schedule: ScheduledPluginInvocation,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
}

impl PluginInvocationInput {
    pub fn validate(&self) -> Result<(), PluginInvocationError> {
        if self.objective.trim().is_empty() || self.objective.len() > MAX_OBJECTIVE_BYTES {
            return Err(PluginInvocationError::InvalidObjective);
        }
        self.scope.validate()?;
        self.schedule.validate()?;
        self.composition.validate()?;
        self.invocation.validate_for(&self.composition)?;
        if self.composition.scope != self.scope {
            return Err(PluginInvocationError::ScopeMismatch);
        }
        if self.schedule.state != ScheduleState::Pending {
            return Err(PluginInvocationError::ScheduleStateConflict);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleState {
    Pending,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledPluginInvocation {
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub interval_seconds: u64,
    pub contract_valid_until: DateTime<Utc>,
    pub state: ScheduleState,
}

impl ScheduledPluginInvocation {
    pub fn new(
        schedule_id_digest: impl Into<String>,
        schedule_revision: u64,
        planned_at: DateTime<Utc>,
        interval_seconds: u64,
        contract_valid_until: DateTime<Utc>,
    ) -> Result<Self, PluginInvocationError> {
        let schedule = Self {
            schedule_id_digest: schedule_id_digest.into(),
            schedule_revision,
            planned_at,
            interval_seconds,
            contract_valid_until,
            state: ScheduleState::Pending,
        };
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn validate(&self) -> Result<(), PluginInvocationError> {
        if !validate_digest(&self.schedule_id_digest)
            || self.schedule_revision == 0
            || self.interval_seconds > MAX_INTERVAL_SECONDS
            || self.planned_at >= self.contract_valid_until
        {
            return Err(PluginInvocationError::InvalidSchedule);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInvocation {
    pub plugin_id: String,
    pub operation: String,
}

impl PluginInvocation {
    pub fn new(
        plugin_id: impl Into<String>,
        operation: impl Into<String>,
    ) -> Result<Self, PluginInvocationError> {
        let invocation = Self {
            plugin_id: plugin_id.into(),
            operation: operation.into(),
        };
        if !valid_identifier(&invocation.plugin_id) || !valid_identifier(&invocation.operation) {
            return Err(PluginInvocationError::InvalidInvocation);
        }
        Ok(invocation)
    }

    pub fn digest(&self) -> Result<String, PluginInvocationError> {
        digest_json(self)
    }

    fn validate_for(&self, composition: &PluginComposition) -> Result<(), PluginInvocationError> {
        if !valid_identifier(&self.plugin_id) || !valid_identifier(&self.operation) {
            return Err(PluginInvocationError::InvalidInvocation);
        }
        if composition.plugin(&self.plugin_id).is_none() {
            return Err(PluginInvocationError::PluginNotInComposition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleRevisionKey {
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
}

impl ScheduleRevisionKey {
    fn new(
        scope: MissionScope,
        schedule_id_digest: impl Into<String>,
        schedule_revision: u64,
    ) -> Result<Self, PluginInvocationError> {
        let key = Self {
            scope,
            schedule_id_digest: schedule_id_digest.into(),
            schedule_revision,
        };
        key.scope.validate()?;
        if !validate_digest(&key.schedule_id_digest) || key.schedule_revision == 0 {
            return Err(PluginInvocationError::InvalidSchedule);
        }
        Ok(key)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInvocationKey {
    pub schedule: ScheduleRevisionKey,
    pub composition_digest: String,
    pub invocation_digest: String,
}

impl PluginInvocationKey {
    fn from_request(request: &DurablePluginWakeRequest) -> Result<Self, PluginInvocationError> {
        Self::new(
            request.scope.clone(),
            request.schedule.schedule_id_digest.clone(),
            request.schedule.schedule_revision,
            request.composition.composition_digest.clone(),
            request.invocation.digest()?,
        )
    }

    fn from_receipt(receipt: &TriggerReceipt) -> Result<Self, PluginInvocationError> {
        Self::new(
            receipt.scope.clone(),
            receipt.schedule_id_digest.clone(),
            receipt.schedule_revision,
            receipt.composition.composition_digest.clone(),
            receipt.invocation.digest()?,
        )
    }

    fn new(
        scope: MissionScope,
        schedule_id_digest: impl Into<String>,
        schedule_revision: u64,
        composition_digest: impl Into<String>,
        invocation_digest: impl Into<String>,
    ) -> Result<Self, PluginInvocationError> {
        let key = Self {
            schedule: ScheduleRevisionKey::new(scope, schedule_id_digest, schedule_revision)?,
            composition_digest: composition_digest.into(),
            invocation_digest: invocation_digest.into(),
        };
        if !validate_digest(&key.composition_digest) || !validate_digest(&key.invocation_digest) {
            return Err(PluginInvocationError::InvalidInvocationKey);
        }
        Ok(key)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScheduleSlot {
    scope: MissionScope,
    schedule_id_digest: String,
}

impl ScheduleSlot {
    fn new(scope: &MissionScope, schedule_id_digest: &str) -> Self {
        Self {
            scope: scope.clone(),
            schedule_id_digest: schedule_id_digest.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderState {
    Unmounted,
    Mounted,
    Sleeping,
    Crashed,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleEvent {
    Unmounted,
    Revoked,
    Crashed,
    Sleep,
    Wake,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMountRequest {
    pub provider_id_digest: String,
    pub scope: MissionScope,
    pub provider_epoch: u64,
    pub observed_at: DateTime<Utc>,
}

impl ProviderMountRequest {
    fn validate(&self) -> Result<(), PluginInvocationError> {
        if !validate_digest(&self.provider_id_digest) || self.provider_epoch == 0 {
            return Err(PluginInvocationError::InvalidProvider);
        }
        self.scope.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderLifecycleTransition {
    pub provider_id_digest: String,
    pub scope: MissionScope,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub event: ProviderLifecycleEvent,
    pub observed_at: DateTime<Utc>,
}

impl ProviderLifecycleTransition {
    fn validate(&self) -> Result<(), PluginInvocationError> {
        if !validate_digest(&self.provider_id_digest)
            || self.previous_epoch == 0
            || self.next_epoch == 0
            || (self.event != ProviderLifecycleEvent::Sleep
                && self.next_epoch <= self.previous_epoch)
        {
            return Err(PluginInvocationError::InvalidProviderEpoch);
        }
        self.scope.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderWakeReceipt {
    pub request_id_digest: String,
    pub request_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lifecycle_receipt: Option<WakeReceipt>,
}

impl ProviderWakeReceipt {
    fn validate_for(
        &self,
        request: &DurablePluginWakeRequest,
    ) -> Result<(), PluginInvocationError> {
        if self.request_id_digest != request.request_id_digest
            || self.request_digest != request.request_digest
            || self.provider_id_digest != request.provider_id_digest
            || self.provider_epoch != request.provider_epoch
        {
            return Err(PluginInvocationError::ProviderReceiptConflict);
        }
        if let Some(receipt) = &self.lifecycle_receipt
            && (receipt.request_digest
                != request
                    .wake
                    .request_digest()
                    .map_err(PluginInvocationError::Lifecycle)?
                || receipt.wake_at != request.wake.wake_at
                || receipt.lease_generation != request.provider_epoch)
        {
            return Err(PluginInvocationError::ProviderReceiptConflict);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SchedulingProviderError {
    #[error("provider lifecycle epoch is stale")]
    EpochLost,
    #[error("provider wake receipt conflicts with the exact request")]
    ReceiptConflict,
    #[error("provider cannot resolve the requested exact plugin composition")]
    CompositionUnavailable,
    #[error("provider lifecycle adapter rejected the operation")]
    Lifecycle(#[from] WakeSleepError),
    #[error("provider backend failed")]
    Backend,
}

/// Provider seam for OS/Cell lifecycle and exact plugin composition
/// resolution.  No method exposes an Effect executor or completion authority.
pub trait PluginInvocationProvider: fmt::Debug {
    fn provider_id_digest(&self) -> &str;
    fn resolve_composition(
        &mut self,
        scope: &MissionScope,
        composition: &PluginComposition,
        invocation: &PluginInvocation,
    ) -> Result<(), SchedulingProviderError>;
    fn mount(&mut self, request: &ProviderMountRequest) -> Result<(), SchedulingProviderError>;
    fn unmount(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn revoke(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn crash(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn on_sleep(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn on_wake(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn revoke_plugin(&mut self, plugin: &PluginManifest) -> Result<(), SchedulingProviderError>;
    fn arm_wake(
        &mut self,
        request: &DurablePluginWakeRequest,
    ) -> Result<ProviderWakeReceipt, SchedulingProviderError>;
    fn disarm_wake(&mut self, receipt: &ProviderWakeReceipt)
    -> Result<(), SchedulingProviderError>;
}

/// Durable wake request containing the resolved composition, exact target,
/// schedule revision and provider epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurablePluginWakeRequest {
    pub request_id_digest: String,
    pub request_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule: ScheduledPluginInvocation,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub wake: WakeRequest,
}

struct WakeRequestInput {
    objective_digest: String,
    scope: MissionScope,
    schedule: ScheduledPluginInvocation,
    composition: PluginComposition,
    invocation: PluginInvocation,
    provider_id_digest: String,
    provider_epoch: u64,
    coalesced_ticks: u64,
}

impl DurablePluginWakeRequest {
    fn new(input: WakeRequestInput) -> Result<Self, PluginInvocationError> {
        let WakeRequestInput {
            objective_digest,
            scope,
            schedule,
            composition,
            invocation,
            provider_id_digest,
            provider_epoch,
            coalesced_ticks,
        } = input;
        scope.validate()?;
        schedule.validate()?;
        composition.validate()?;
        invocation.validate_for(&composition)?;
        if composition.scope != scope
            || !validate_digest(&objective_digest)
            || !validate_digest(&provider_id_digest)
            || provider_epoch == 0
            || coalesced_ticks == 0
        {
            return Err(PluginInvocationError::InvalidWakeRequest);
        }
        let invocation_digest = invocation.digest()?;
        let request_id_digest = digest_json(&RequestIdMaterial {
            objective_digest: &objective_digest,
            scope: &scope,
            schedule_id_digest: &schedule.schedule_id_digest,
            schedule_revision: schedule.schedule_revision,
            composition_digest: &composition.composition_digest,
            invocation_digest: &invocation_digest,
            provider_id_digest: &provider_id_digest,
            provider_epoch,
        })?;
        let wake = WakeRequest {
            schedule_id_digest: schedule.schedule_id_digest.clone(),
            wake_at: schedule.planned_at,
            contract_valid_until: schedule.contract_valid_until,
            coalesced_ticks,
            lease_generation: provider_epoch,
        };
        let mut request = Self {
            request_id_digest,
            request_digest: String::new(),
            objective_digest,
            scope,
            schedule,
            composition,
            invocation,
            provider_id_digest,
            provider_epoch,
            wake,
        };
        request.request_digest = request.expected_request_digest()?;
        request.validate()?;
        Ok(request)
    }

    fn rebind_provider_epoch(&self, provider_epoch: u64) -> Result<Self, PluginInvocationError> {
        Self::new(WakeRequestInput {
            objective_digest: self.objective_digest.clone(),
            scope: self.scope.clone(),
            schedule: self.schedule.clone(),
            composition: self.composition.clone(),
            invocation: self.invocation.clone(),
            provider_id_digest: self.provider_id_digest.clone(),
            provider_epoch,
            coalesced_ticks: self.wake.coalesced_ticks,
        })
    }

    fn with_coalesced_ticks(&self, coalesced_ticks: u64) -> Result<Self, PluginInvocationError> {
        Self::new(WakeRequestInput {
            objective_digest: self.objective_digest.clone(),
            scope: self.scope.clone(),
            schedule: self.schedule.clone(),
            composition: self.composition.clone(),
            invocation: self.invocation.clone(),
            provider_id_digest: self.provider_id_digest.clone(),
            provider_epoch: self.provider_epoch,
            coalesced_ticks,
        })
    }

    fn key(&self) -> Result<PluginInvocationKey, PluginInvocationError> {
        PluginInvocationKey::from_request(self)
    }

    pub fn validate(&self) -> Result<(), PluginInvocationError> {
        if !validate_digest(&self.request_id_digest)
            || !validate_digest(&self.request_digest)
            || !validate_digest(&self.objective_digest)
            || !validate_digest(&self.provider_id_digest)
            || self.provider_epoch == 0
        {
            return Err(PluginInvocationError::InvalidWakeRequest);
        }
        self.scope.validate()?;
        self.schedule.validate()?;
        self.composition.validate()?;
        self.invocation.validate_for(&self.composition)?;
        self.wake
            .validate()
            .map_err(PluginInvocationError::Lifecycle)?;
        if self.composition.scope != self.scope
            || self.wake.schedule_id_digest != self.schedule.schedule_id_digest
            || self.wake.wake_at != self.schedule.planned_at
            || self.wake.contract_valid_until != self.schedule.contract_valid_until
            || self.wake.lease_generation != self.provider_epoch
            || self.expected_request_id_digest()? != self.request_id_digest
            || self.expected_request_digest()? != self.request_digest
        {
            return Err(PluginInvocationError::InvalidWakeRequest);
        }
        Ok(())
    }

    pub fn expected_request_id_digest(&self) -> Result<String, PluginInvocationError> {
        let invocation_digest = self.invocation.digest()?;
        digest_json(&RequestIdMaterial {
            objective_digest: &self.objective_digest,
            scope: &self.scope,
            schedule_id_digest: &self.schedule.schedule_id_digest,
            schedule_revision: self.schedule.schedule_revision,
            composition_digest: &self.composition.composition_digest,
            invocation_digest: &invocation_digest,
            provider_id_digest: &self.provider_id_digest,
            provider_epoch: self.provider_epoch,
        })
    }

    pub fn expected_request_digest(&self) -> Result<String, PluginInvocationError> {
        digest_json(&RequestDigestMaterial {
            request_id_digest: &self.request_id_digest,
            objective_digest: &self.objective_digest,
            scope: &self.scope,
            schedule: &self.schedule,
            composition: &self.composition,
            invocation: &self.invocation,
            provider_id_digest: &self.provider_id_digest,
            provider_epoch: self.provider_epoch,
            wake: &self.wake,
        })
    }
}

/// Durable, typed evidence that an OS/Cell wake reached one exact plugin
/// invocation schedule.  One logical key has one receipt forever.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerReceipt {
    pub trigger_id_digest: String,
    pub request_id_digest: String,
    pub request_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub woke_at: DateTime<Utc>,
    pub coalesced_ticks: u64,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub receipt_digest: String,
}

impl TriggerReceipt {
    fn from_request(
        request: &DurablePluginWakeRequest,
        woke_at: DateTime<Utc>,
    ) -> Result<Self, PluginInvocationError> {
        let invocation_digest = request.invocation.digest()?;
        let mut receipt = Self {
            trigger_id_digest: digest_json(&TriggerIdMaterial {
                scope: &request.scope,
                schedule_id_digest: &request.schedule.schedule_id_digest,
                schedule_revision: request.schedule.schedule_revision,
                composition_digest: &request.composition.composition_digest,
                invocation_digest: &invocation_digest,
            })?,
            request_id_digest: request.request_id_digest.clone(),
            request_digest: request.request_digest.clone(),
            objective_digest: request.objective_digest.clone(),
            scope: request.scope.clone(),
            schedule_id_digest: request.schedule.schedule_id_digest.clone(),
            schedule_revision: request.schedule.schedule_revision,
            planned_at: request.schedule.planned_at,
            woke_at,
            coalesced_ticks: request.wake.coalesced_ticks,
            composition: request.composition.clone(),
            invocation: request.invocation.clone(),
            provider_id_digest: request.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_receipt_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn key(&self) -> Result<PluginInvocationKey, PluginInvocationError> {
        PluginInvocationKey::from_receipt(self)
    }

    pub fn expected_receipt_digest(&self) -> Result<String, PluginInvocationError> {
        digest_json(&TriggerReceiptMaterial {
            trigger_id_digest: &self.trigger_id_digest,
            request_id_digest: &self.request_id_digest,
            request_digest: &self.request_digest,
            objective_digest: &self.objective_digest,
            scope: &self.scope,
            schedule_id_digest: &self.schedule_id_digest,
            schedule_revision: self.schedule_revision,
            planned_at: self.planned_at,
            woke_at: self.woke_at,
            coalesced_ticks: self.coalesced_ticks,
            composition: &self.composition,
            invocation: &self.invocation,
            provider_id_digest: &self.provider_id_digest,
            provider_epoch: self.provider_epoch,
        })
    }

    pub fn validate(&self) -> Result<(), PluginInvocationError> {
        if !validate_digest(&self.trigger_id_digest)
            || !validate_digest(&self.request_id_digest)
            || !validate_digest(&self.request_digest)
            || !validate_digest(&self.objective_digest)
            || !validate_digest(&self.schedule_id_digest)
            || !validate_digest(&self.provider_id_digest)
            || self.schedule_revision == 0
            || self.coalesced_ticks == 0
            || self.provider_epoch == 0
            || self.planned_at > self.woke_at
            || self.receipt_digest != self.expected_receipt_digest()?
        {
            return Err(PluginInvocationError::InvalidTriggerReceipt);
        }
        self.scope.validate()?;
        self.composition.validate()?;
        self.invocation.validate_for(&self.composition)?;
        if self.composition.scope != self.scope {
            return Err(PluginInvocationError::InvalidTriggerReceipt);
        }
        Ok(())
    }
}

/// The only value handed to the consumer.  It is a capability request, not an
/// Effect executor, browser action, runtime turn, or completion authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchAuthority {
    CapabilityRequestOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInvocationDispatch {
    pub dispatch_id_digest: String,
    pub trigger_receipt_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub woke_at: DateTime<Utc>,
    pub coalesced_ticks: u64,
    pub composition: PluginComposition,
    pub invocation: PluginInvocation,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub authority: DispatchAuthority,
}

impl PluginInvocationDispatch {
    fn from_receipt(receipt: &TriggerReceipt) -> Result<Self, PluginInvocationError> {
        let mut dispatch = Self {
            dispatch_id_digest: String::new(),
            trigger_receipt_digest: receipt.receipt_digest.clone(),
            objective_digest: receipt.objective_digest.clone(),
            scope: receipt.scope.clone(),
            schedule_id_digest: receipt.schedule_id_digest.clone(),
            schedule_revision: receipt.schedule_revision,
            planned_at: receipt.planned_at,
            woke_at: receipt.woke_at,
            coalesced_ticks: receipt.coalesced_ticks,
            composition: receipt.composition.clone(),
            invocation: receipt.invocation.clone(),
            provider_id_digest: receipt.provider_id_digest.clone(),
            provider_epoch: receipt.provider_epoch,
            authority: DispatchAuthority::CapabilityRequestOnly,
        };
        dispatch.dispatch_id_digest = dispatch.expected_dispatch_id_digest()?;
        dispatch.validate()?;
        Ok(dispatch)
    }

    fn expected_dispatch_id_digest(&self) -> Result<String, PluginInvocationError> {
        digest_json(&DispatchIdMaterial {
            trigger_receipt_digest: &self.trigger_receipt_digest,
            scope: &self.scope,
            schedule_id_digest: &self.schedule_id_digest,
            schedule_revision: self.schedule_revision,
            composition_digest: &self.composition.composition_digest,
            invocation: &self.invocation,
            authority: self.authority,
        })
    }

    pub fn validate(&self) -> Result<(), PluginInvocationError> {
        if !validate_digest(&self.dispatch_id_digest)
            || !validate_digest(&self.trigger_receipt_digest)
            || !validate_digest(&self.objective_digest)
            || !validate_digest(&self.schedule_id_digest)
            || !validate_digest(&self.provider_id_digest)
            || self.schedule_revision == 0
            || self.coalesced_ticks == 0
            || self.provider_epoch == 0
            || self.authority != DispatchAuthority::CapabilityRequestOnly
            || self.dispatch_id_digest != self.expected_dispatch_id_digest()?
        {
            return Err(PluginInvocationError::InvalidDispatch);
        }
        self.scope.validate()?;
        self.composition.validate()?;
        self.invocation.validate_for(&self.composition)?;
        if self.composition.scope != self.scope {
            return Err(PluginInvocationError::InvalidDispatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeResult {
    Started(PluginInvocationDispatch),
    AlreadyStarted(PluginInvocationDispatch),
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInvocationSnapshot {
    pub requests: Vec<DurablePluginWakeRequest>,
    pub cancelled: Vec<ScheduleRevisionKey>,
    pub revoked_plugins: Vec<PluginManifest>,
    pub receipts: Vec<TriggerReceipt>,
    pub dispatches: Vec<PluginInvocationDispatch>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PluginInvocationStoreError {
    #[error("plugin invocation snapshot serialization failed: {0}")]
    Serialization(String),
    #[error("plugin invocation snapshot is corrupt")]
    Corrupt,
    #[error("plugin invocation SQLite store failed: {0}")]
    Sqlite(String),
}

pub trait PluginInvocationStore: fmt::Debug {
    fn load(&self) -> Result<PluginInvocationSnapshot, PluginInvocationStoreError>;
    fn save(
        &mut self,
        snapshot: &PluginInvocationSnapshot,
    ) -> Result<(), PluginInvocationStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryPluginInvocationStore {
    snapshot: PluginInvocationSnapshot,
}

impl MemoryPluginInvocationStore {
    pub fn snapshot(&self) -> &PluginInvocationSnapshot {
        &self.snapshot
    }
}

impl PluginInvocationStore for MemoryPluginInvocationStore {
    fn load(&self) -> Result<PluginInvocationSnapshot, PluginInvocationStoreError> {
        Ok(self.snapshot.clone())
    }

    fn save(
        &mut self,
        snapshot: &PluginInvocationSnapshot,
    ) -> Result<(), PluginInvocationStoreError> {
        self.snapshot = snapshot.clone();
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqlitePluginInvocationStore {
    connection: Connection,
}

impl SqlitePluginInvocationStore {
    pub fn open_in_memory() -> Result<Self, PluginInvocationStoreError> {
        Self::new(Connection::open_in_memory().map_err(|error| sqlite_store_error(&error))?)
    }

    pub fn new(connection: Connection) -> Result<Self, PluginInvocationStoreError> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scheduler_plugin_invocations (
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

impl PluginInvocationStore for SqlitePluginInvocationStore {
    fn load(&self) -> Result<PluginInvocationSnapshot, PluginInvocationStoreError> {
        let json = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM scheduler_plugin_invocations WHERE snapshot_id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| sqlite_store_error(&error))?;
        json.map_or_else(
            || Ok(PluginInvocationSnapshot::default()),
            |value| {
                serde_json::from_str(&value)
                    .map_err(|error| PluginInvocationStoreError::Serialization(error.to_string()))
            },
        )
    }

    fn save(
        &mut self,
        snapshot: &PluginInvocationSnapshot,
    ) -> Result<(), PluginInvocationStoreError> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| PluginInvocationStoreError::Serialization(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO scheduler_plugin_invocations(snapshot_id, snapshot_json)
                 VALUES (1, ?1)
                 ON CONFLICT(snapshot_id) DO UPDATE SET snapshot_json = excluded.snapshot_json",
                params![json],
            )
            .map_err(|error| sqlite_store_error(&error))?;
        Ok(())
    }
}

fn sqlite_store_error(error: &rusqlite::Error) -> PluginInvocationStoreError {
    PluginInvocationStoreError::Sqlite(error.to_string())
}

pub trait PluginInvocationSchedulingService {
    fn provider_state(&self) -> ProviderState;
    fn provider_epoch(&self) -> u64;
    fn mount_provider(
        &mut self,
        scope: MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<u64, PluginInvocationError>;
    fn unmount_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError>;
    fn revoke_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError>;
    fn provider_crash(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError>;
    fn os_sleep(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError>;
    fn os_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, PluginInvocationError>;
    fn cell_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, PluginInvocationError>;
    fn schedule_invocation(
        &mut self,
        input: PluginInvocationInput,
        observed_at: DateTime<Utc>,
    ) -> Result<DurablePluginWakeRequest, PluginInvocationError>;
    fn coalesce_missed_ticks(
        &mut self,
        request: &DurablePluginWakeRequest,
        observed_at: DateTime<Utc>,
        max_coalesced_ticks: u64,
    ) -> Result<CoalescedWake, PluginInvocationError>;
    fn observe_wake(
        &mut self,
        request: &DurablePluginWakeRequest,
        woke_at: DateTime<Utc>,
    ) -> Result<TriggerReceipt, PluginInvocationError>;
    fn cancel_schedule(
        &mut self,
        schedule_id_digest: &str,
        schedule_revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError>;
    fn revoke_plugin(&mut self, plugin: &PluginManifest) -> Result<(), PluginInvocationError>;
    fn consume_trigger(
        &mut self,
        scope: &MissionScope,
        composition: &PluginComposition,
        invocation: &PluginInvocation,
        receipt: &TriggerReceipt,
    ) -> Result<ConsumeResult, PluginInvocationError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoalescedWake {
    pub request: DurablePluginWakeRequest,
    pub due_ticks: u64,
    pub coalesced_ticks: u64,
    pub dispatch_count: u8,
}

#[derive(Debug)]
pub struct PluginInvocationService<P, S = MemoryPluginInvocationStore> {
    provider: P,
    store: S,
    provider_id_digest: String,
    state: ProviderState,
    scope: Option<MissionScope>,
    provider_epoch: u64,
    requests: BTreeMap<String, DurablePluginWakeRequest>,
    latest_by_schedule: BTreeMap<ScheduleSlot, String>,
    armed: BTreeMap<String, ProviderWakeReceipt>,
    cancelled: BTreeSet<ScheduleRevisionKey>,
    revoked_plugins: BTreeSet<PluginManifest>,
    receipts: BTreeMap<PluginInvocationKey, TriggerReceipt>,
    dispatches: BTreeMap<PluginInvocationKey, PluginInvocationDispatch>,
}

pub type ScheduledPluginInvocationService<P, S = MemoryPluginInvocationStore> =
    PluginInvocationService<P, S>;

fn corrupt_store() -> PluginInvocationError {
    PluginInvocationError::Store(PluginInvocationStoreError::Corrupt)
}

fn load_requests(
    records: Vec<DurablePluginWakeRequest>,
    provider_id_digest: &str,
) -> Result<(BTreeMap<String, DurablePluginWakeRequest>, u64), PluginInvocationError> {
    let mut requests = BTreeMap::new();
    let mut provider_epoch = 0;
    for request in records {
        request.validate()?;
        if request.provider_id_digest != provider_id_digest
            || requests
                .insert(request.request_id_digest.clone(), request.clone())
                .is_some()
        {
            return Err(if request.provider_id_digest == provider_id_digest {
                corrupt_store()
            } else {
                PluginInvocationError::ProviderIdentityMismatch
            });
        }
        provider_epoch = provider_epoch.max(request.provider_epoch);
    }
    Ok((requests, provider_epoch))
}

fn load_cancelled(
    records: Vec<ScheduleRevisionKey>,
) -> Result<BTreeSet<ScheduleRevisionKey>, PluginInvocationError> {
    let mut cancelled = BTreeSet::new();
    for key in records {
        key.scope.validate()?;
        if !validate_digest(&key.schedule_id_digest) || key.schedule_revision == 0 {
            return Err(corrupt_store());
        }
        cancelled.insert(key);
    }
    Ok(cancelled)
}

fn load_revoked(
    records: Vec<PluginManifest>,
) -> Result<BTreeSet<PluginManifest>, PluginInvocationError> {
    let mut revoked = BTreeSet::new();
    for plugin in records {
        plugin.validate()?;
        revoked.insert(plugin);
    }
    Ok(revoked)
}

fn load_receipts(
    records: Vec<TriggerReceipt>,
    provider_id_digest: &str,
) -> Result<(BTreeMap<PluginInvocationKey, TriggerReceipt>, u64), PluginInvocationError> {
    let mut receipts = BTreeMap::new();
    let mut provider_epoch = 0;
    for receipt in records {
        receipt.validate()?;
        if receipt.provider_id_digest != provider_id_digest {
            return Err(PluginInvocationError::ProviderIdentityMismatch);
        }
        let key = receipt.key()?;
        if receipts.insert(key, receipt.clone()).is_some() {
            return Err(corrupt_store());
        }
        provider_epoch = provider_epoch.max(receipt.provider_epoch);
    }
    Ok((receipts, provider_epoch))
}

fn load_dispatches(
    records: Vec<PluginInvocationDispatch>,
    provider_id_digest: &str,
) -> Result<(BTreeMap<PluginInvocationKey, PluginInvocationDispatch>, u64), PluginInvocationError> {
    let mut dispatches = BTreeMap::new();
    let mut provider_epoch = 0;
    for dispatch in records {
        dispatch.validate()?;
        if dispatch.provider_id_digest != provider_id_digest {
            return Err(PluginInvocationError::ProviderIdentityMismatch);
        }
        let key = PluginInvocationKey::new(
            dispatch.scope.clone(),
            dispatch.schedule_id_digest.clone(),
            dispatch.schedule_revision,
            dispatch.composition.composition_digest.clone(),
            dispatch.invocation.digest()?,
        )?;
        if dispatches.insert(key, dispatch.clone()).is_some() {
            return Err(corrupt_store());
        }
        provider_epoch = provider_epoch.max(dispatch.provider_epoch);
    }
    Ok((dispatches, provider_epoch))
}

fn validate_dispatch_receipts(
    dispatches: &BTreeMap<PluginInvocationKey, PluginInvocationDispatch>,
    receipts: &BTreeMap<PluginInvocationKey, TriggerReceipt>,
) -> Result<(), PluginInvocationError> {
    for (key, dispatch) in dispatches {
        let receipt = receipts.get(key).ok_or_else(corrupt_store)?;
        if dispatch != &PluginInvocationDispatch::from_receipt(receipt)? {
            return Err(corrupt_store());
        }
    }
    Ok(())
}

fn latest_requests(
    requests: &BTreeMap<String, DurablePluginWakeRequest>,
) -> Result<BTreeMap<ScheduleSlot, String>, PluginInvocationError> {
    let mut latest = BTreeMap::new();
    for request in requests.values() {
        let slot = ScheduleSlot::new(&request.scope, &request.schedule.schedule_id_digest);
        if let Some(current_id) = latest.get(&slot) {
            let current = requests.get(current_id).ok_or_else(corrupt_store)?;
            if current.schedule.schedule_revision == request.schedule.schedule_revision {
                return Err(corrupt_store());
            }
            if request.schedule.schedule_revision > current.schedule.schedule_revision {
                latest.insert(slot, request.request_id_digest.clone());
            }
        } else {
            latest.insert(slot, request.request_id_digest.clone());
        }
    }
    Ok(latest)
}

impl<P> PluginInvocationService<P, MemoryPluginInvocationStore>
where
    P: PluginInvocationProvider,
{
    pub fn new(provider: P) -> Result<Self, PluginInvocationError> {
        Self::with_store(provider, MemoryPluginInvocationStore::default())
    }
}

impl<P, S> PluginInvocationService<P, S>
where
    P: PluginInvocationProvider,
    S: PluginInvocationStore,
{
    pub fn with_store(provider: P, store: S) -> Result<Self, PluginInvocationError> {
        let provider_id_digest = provider.provider_id_digest().to_owned();
        if !validate_digest(&provider_id_digest) {
            return Err(PluginInvocationError::InvalidProvider);
        }
        let snapshot = store.load().map_err(PluginInvocationError::Store)?;
        let (requests, request_epoch) = load_requests(snapshot.requests, &provider_id_digest)?;
        let cancelled = load_cancelled(snapshot.cancelled)?;
        let revoked_plugins = load_revoked(snapshot.revoked_plugins)?;
        let (receipts, receipt_epoch) = load_receipts(snapshot.receipts, &provider_id_digest)?;
        let (dispatches, dispatch_epoch) =
            load_dispatches(snapshot.dispatches, &provider_id_digest)?;
        validate_dispatch_receipts(&dispatches, &receipts)?;
        let provider_epoch = request_epoch.max(receipt_epoch).max(dispatch_epoch);
        let latest_by_schedule = latest_requests(&requests)?;

        Ok(Self {
            provider,
            store,
            provider_id_digest,
            state: ProviderState::Unmounted,
            scope: None,
            provider_epoch,
            requests,
            latest_by_schedule,
            armed: BTreeMap::new(),
            cancelled,
            revoked_plugins,
            receipts,
            dispatches,
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

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn snapshot(&self) -> PluginInvocationSnapshot {
        PluginInvocationSnapshot {
            requests: self.requests.values().cloned().collect(),
            cancelled: self.cancelled.iter().cloned().collect(),
            revoked_plugins: self.revoked_plugins.iter().cloned().collect(),
            receipts: self.receipts.values().cloned().collect(),
            dispatches: self.dispatches.values().cloned().collect(),
        }
    }

    pub fn latest_request(&self, schedule_id_digest: &str) -> Option<&DurablePluginWakeRequest> {
        self.latest_by_schedule
            .iter()
            .find(|(slot, _)| slot.schedule_id_digest == schedule_id_digest)
            .and_then(|(_, request_id)| self.requests.get(request_id))
    }

    pub fn receipt_for(
        &self,
        scope: &MissionScope,
        schedule_id_digest: &str,
        schedule_revision: u64,
        composition_digest: &str,
        invocation: &PluginInvocation,
    ) -> Option<&TriggerReceipt> {
        let key = PluginInvocationKey::new(
            scope.clone(),
            schedule_id_digest.to_owned(),
            schedule_revision,
            composition_digest.to_owned(),
            invocation.digest().ok()?,
        )
        .ok()?;
        self.receipts.get(&key)
    }

    pub fn dispatch_count(&self) -> usize {
        self.dispatches.len()
    }

    fn sync_store(&mut self) -> Result<(), PluginInvocationError> {
        let snapshot = self.snapshot();
        self.store
            .save(&snapshot)
            .map_err(PluginInvocationError::Store)
    }

    fn current_scope(&self) -> Result<&MissionScope, PluginInvocationError> {
        self.scope
            .as_ref()
            .ok_or(PluginInvocationError::ProviderNotMounted)
    }

    fn ensure_scope(&self, scope: &MissionScope) -> Result<(), PluginInvocationError> {
        if self.current_scope()? != scope {
            return Err(PluginInvocationError::ScopeMismatch);
        }
        Ok(())
    }

    fn ensure_epoch(&self, provider_epoch: u64) -> Result<(), PluginInvocationError> {
        if provider_epoch != self.provider_epoch {
            return Err(PluginInvocationError::ProviderEpochLost {
                expected: self.provider_epoch,
                actual: provider_epoch,
            });
        }
        Ok(())
    }

    fn ensure_mounted(&self, provider_epoch: u64) -> Result<(), PluginInvocationError> {
        match self.state {
            ProviderState::Mounted => self.ensure_epoch(provider_epoch),
            ProviderState::Sleeping => Err(PluginInvocationError::ProviderSleeping),
            ProviderState::Unmounted => Err(PluginInvocationError::ProviderNotMounted),
            ProviderState::Crashed => Err(PluginInvocationError::ProviderCrashed),
            ProviderState::Revoked => Err(PluginInvocationError::ProviderRevoked),
        }
    }

    fn next_epoch(&self) -> Result<u64, PluginInvocationError> {
        self.provider_epoch
            .checked_add(1)
            .filter(|epoch| *epoch != 0)
            .ok_or(PluginInvocationError::ProviderEpochExhausted)
    }

    fn state_error(&self) -> PluginInvocationError {
        match self.state {
            ProviderState::Mounted => PluginInvocationError::InvalidLifecycleState,
            ProviderState::Sleeping => PluginInvocationError::ProviderSleeping,
            ProviderState::Unmounted => PluginInvocationError::ProviderNotMounted,
            ProviderState::Crashed => PluginInvocationError::ProviderCrashed,
            ProviderState::Revoked => PluginInvocationError::ProviderRevoked,
        }
    }

    fn is_revoked(&self, composition: &PluginComposition) -> bool {
        composition
            .plugins
            .iter()
            .any(|plugin| self.revoked_plugins.contains(plugin))
    }

    fn transition(
        &mut self,
        event: ProviderLifecycleEvent,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
        next_state: ProviderState,
    ) -> Result<(), PluginInvocationError> {
        self.ensure_epoch(provider_epoch)?;
        let scope = self.current_scope()?.clone();
        let next_epoch = if event == ProviderLifecycleEvent::Sleep {
            provider_epoch
        } else {
            self.next_epoch()?
        };
        let transition = ProviderLifecycleTransition {
            provider_id_digest: self.provider_id_digest.clone(),
            scope,
            previous_epoch: provider_epoch,
            next_epoch,
            event,
            observed_at,
        };
        transition.validate()?;
        match event {
            ProviderLifecycleEvent::Unmounted => self.provider.unmount(&transition),
            ProviderLifecycleEvent::Revoked => self.provider.revoke(&transition),
            ProviderLifecycleEvent::Crashed => self.provider.crash(&transition),
            ProviderLifecycleEvent::Sleep => self.provider.on_sleep(&transition),
            ProviderLifecycleEvent::Wake => self.provider.on_wake(&transition),
        }
        .map_err(PluginInvocationError::Provider)?;
        self.provider_epoch = next_epoch;
        self.state = next_state;
        Ok(())
    }

    fn disarm_all(&mut self) -> Result<(), PluginInvocationError> {
        let armed = self
            .armed
            .iter()
            .map(|(request_id, receipt)| (request_id.clone(), receipt.clone()))
            .collect::<Vec<_>>();
        for (request_id, receipt) in armed {
            self.provider
                .disarm_wake(&receipt)
                .map_err(PluginInvocationError::Provider)?;
            self.armed.remove(&request_id);
        }
        Ok(())
    }

    fn arm_request(
        &mut self,
        request: &DurablePluginWakeRequest,
    ) -> Result<ProviderWakeReceipt, PluginInvocationError> {
        let receipt = self
            .provider
            .arm_wake(request)
            .map_err(PluginInvocationError::Provider)?;
        receipt.validate_for(request)?;
        Ok(receipt)
    }

    fn replace_armed_request(
        &mut self,
        old_request_id: &str,
        request: &DurablePluginWakeRequest,
    ) -> Result<(), PluginInvocationError> {
        if let Some(receipt) = self.armed.remove(old_request_id) {
            self.provider
                .disarm_wake(&receipt)
                .map_err(PluginInvocationError::Provider)?;
        }
        let receipt = self.arm_request(request)?;
        self.armed
            .insert(request.request_id_digest.clone(), receipt);
        Ok(())
    }

    fn request_for_exact_record(
        &self,
        request: &DurablePluginWakeRequest,
    ) -> Result<&DurablePluginWakeRequest, PluginInvocationError> {
        request.validate()?;
        let current = self
            .requests
            .get(&request.request_id_digest)
            .ok_or(PluginInvocationError::StaleWakeRequest)?;
        if current != request {
            return Err(PluginInvocationError::WakeRequestConflict);
        }
        self.ensure_scope(&request.scope)?;
        let key = request.key()?;
        if self.cancelled.contains(&key.schedule) {
            return Err(PluginInvocationError::ScheduleCancelled);
        }
        if self.is_revoked(&request.composition) {
            return Err(PluginInvocationError::PluginRevoked);
        }
        let slot = ScheduleSlot::new(&request.scope, &request.schedule.schedule_id_digest);
        if self.latest_by_schedule.get(&slot) != Some(&request.request_id_digest) {
            return Err(PluginInvocationError::StaleWakeRequest);
        }
        Ok(current)
    }

    fn due_ticks(
        schedule: &ScheduledPluginInvocation,
        observed_at: DateTime<Utc>,
    ) -> Result<u64, PluginInvocationError> {
        if schedule.planned_at > observed_at {
            return Ok(0);
        }
        if schedule.interval_seconds == 0 {
            return Ok(1);
        }
        let elapsed = (observed_at - schedule.planned_at).num_seconds().max(0);
        let interval = i64::try_from(schedule.interval_seconds)
            .map_err(|_| PluginInvocationError::InvalidSchedule)?;
        u64::try_from(elapsed / interval)
            .ok()
            .and_then(|ticks| ticks.checked_add(1))
            .ok_or(PluginInvocationError::InvalidSchedule)
    }

    fn refresh_pending_requests(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        let ids = self
            .latest_by_schedule
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for request_id in ids {
            let current = self
                .requests
                .get(&request_id)
                .ok_or(PluginInvocationError::StaleWakeRequest)?
                .clone();
            if self.scope.as_ref() != Some(&current.scope) {
                continue;
            }
            let key = current.key()?;
            if self.cancelled.contains(&key.schedule)
                || self.is_revoked(&current.composition)
                || self.receipts.contains_key(&key)
            {
                continue;
            }
            let mut next = if current.provider_epoch == self.provider_epoch {
                current.clone()
            } else {
                current.rebind_provider_epoch(self.provider_epoch)?
            };
            let due_ticks = Self::due_ticks(&next.schedule, observed_at)?;
            if due_ticks > 0 && next.wake.coalesced_ticks == 1 {
                next = next.with_coalesced_ticks(due_ticks.min(DEFAULT_MAX_COALESCED_TICKS))?;
            }
            if next != current || !self.armed.contains_key(&next.request_id_digest) {
                self.replace_armed_request(&request_id, &next)?;
                self.requests
                    .insert(next.request_id_digest.clone(), next.clone());
                let slot = ScheduleSlot::new(&next.scope, &next.schedule.schedule_id_digest);
                self.latest_by_schedule
                    .insert(slot, next.request_id_digest.clone());
            }
        }
        Ok(())
    }

    fn collect_due_triggers(
        &mut self,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, PluginInvocationError> {
        let ids = self
            .latest_by_schedule
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut receipts = Vec::new();
        for request_id in ids {
            let request = self
                .requests
                .get(&request_id)
                .ok_or(PluginInvocationError::StaleWakeRequest)?
                .clone();
            let key = request.key()?;
            if self.receipts.contains_key(&key)
                || self.cancelled.contains(&key.schedule)
                || self.is_revoked(&request.composition)
                || request.wake.wake_at > woke_at
            {
                continue;
            }
            receipts.push(self.observe_wake(&request, woke_at)?);
        }
        Ok(receipts)
    }

    pub fn mount_provider(
        &mut self,
        scope: MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<u64, PluginInvocationError> {
        scope.validate()?;
        if matches!(self.state, ProviderState::Mounted | ProviderState::Sleeping) {
            return Err(PluginInvocationError::ProviderAlreadyMounted);
        }
        if self.state == ProviderState::Revoked {
            return Err(PluginInvocationError::ProviderRevoked);
        }
        let provider_epoch = self.next_epoch()?;
        let request = ProviderMountRequest {
            provider_id_digest: self.provider_id_digest.clone(),
            scope: scope.clone(),
            provider_epoch,
            observed_at,
        };
        request.validate()?;
        self.provider
            .mount(&request)
            .map_err(PluginInvocationError::Provider)?;
        self.scope = Some(scope);
        self.provider_epoch = provider_epoch;
        self.state = ProviderState::Mounted;
        self.refresh_pending_requests(observed_at)?;
        self.sync_store()?;
        Ok(provider_epoch)
    }

    pub fn unmount_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        if !matches!(self.state, ProviderState::Mounted | ProviderState::Sleeping) {
            return Err(self.state_error());
        }
        self.disarm_all()?;
        self.transition(
            ProviderLifecycleEvent::Unmounted,
            provider_epoch,
            observed_at,
            ProviderState::Unmounted,
        )?;
        self.sync_store()
    }

    pub fn revoke_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        if self.state == ProviderState::Revoked {
            return Ok(());
        }
        if !matches!(self.state, ProviderState::Mounted | ProviderState::Sleeping) {
            return Err(self.state_error());
        }
        self.disarm_all()?;
        self.transition(
            ProviderLifecycleEvent::Revoked,
            provider_epoch,
            observed_at,
            ProviderState::Revoked,
        )?;
        self.sync_store()
    }

    pub fn provider_crash(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        if !matches!(self.state, ProviderState::Mounted | ProviderState::Sleeping) {
            return Err(self.state_error());
        }
        self.disarm_all()?;
        self.transition(
            ProviderLifecycleEvent::Crashed,
            provider_epoch,
            observed_at,
            ProviderState::Crashed,
        )?;
        self.sync_store()
    }

    pub fn os_sleep(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        if self.state != ProviderState::Mounted {
            return Err(self.state_error());
        }
        self.transition(
            ProviderLifecycleEvent::Sleep,
            provider_epoch,
            observed_at,
            ProviderState::Sleeping,
        )?;
        self.sync_store()
    }

    pub fn os_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, PluginInvocationError> {
        if self.state != ProviderState::Sleeping {
            return Err(self.state_error());
        }
        self.ensure_epoch(provider_epoch)?;
        self.disarm_all()?;
        self.transition(
            ProviderLifecycleEvent::Wake,
            provider_epoch,
            woke_at,
            ProviderState::Mounted,
        )?;
        self.refresh_pending_requests(woke_at)?;
        let receipts = self.collect_due_triggers(woke_at)?;
        self.sync_store()?;
        Ok(receipts)
    }

    pub fn cell_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, PluginInvocationError> {
        self.ensure_mounted(provider_epoch)?;
        self.refresh_pending_requests(woke_at)?;
        let receipts = self.collect_due_triggers(woke_at)?;
        self.sync_store()?;
        Ok(receipts)
    }

    pub fn schedule_invocation(
        &mut self,
        input: PluginInvocationInput,
        observed_at: DateTime<Utc>,
    ) -> Result<DurablePluginWakeRequest, PluginInvocationError> {
        input.validate()?;
        self.ensure_mounted(self.provider_epoch)?;
        self.ensure_scope(&input.scope)?;
        if input.schedule.contract_valid_until <= observed_at {
            return Err(PluginInvocationError::ScheduleExpired);
        }
        if self.is_revoked(&input.composition) {
            return Err(PluginInvocationError::PluginRevoked);
        }
        self.provider
            .resolve_composition(&input.scope, &input.composition, &input.invocation)
            .map_err(PluginInvocationError::Provider)?;
        let objective_digest = scheduler_digest(input.objective.as_bytes());
        let slot = ScheduleSlot::new(&input.scope, &input.schedule.schedule_id_digest);
        if let Some(existing_id) = self.latest_by_schedule.get(&slot).cloned() {
            let existing = self
                .requests
                .get(&existing_id)
                .ok_or(PluginInvocationError::StaleWakeRequest)?;
            if existing.schedule.schedule_revision > input.schedule.schedule_revision {
                return Err(PluginInvocationError::StaleSchedule);
            }
            if existing.schedule.schedule_revision == input.schedule.schedule_revision {
                if existing.objective_digest == objective_digest
                    && existing.schedule == input.schedule
                    && existing.composition == input.composition
                    && existing.invocation == input.invocation
                {
                    return Ok(existing.clone());
                }
                return Err(PluginInvocationError::ScheduleConflict);
            }
            if let Some(receipt) = self.armed.remove(&existing_id) {
                self.provider
                    .disarm_wake(&receipt)
                    .map_err(PluginInvocationError::Provider)?;
            }
        }
        let request = DurablePluginWakeRequest::new(WakeRequestInput {
            objective_digest,
            scope: input.scope,
            schedule: input.schedule,
            composition: input.composition,
            invocation: input.invocation,
            provider_id_digest: self.provider_id_digest.clone(),
            provider_epoch: self.provider_epoch,
            coalesced_ticks: 1,
        })?;
        let receipt = self.arm_request(&request)?;
        self.requests
            .insert(request.request_id_digest.clone(), request.clone());
        self.latest_by_schedule
            .insert(slot, request.request_id_digest.clone());
        self.armed
            .insert(request.request_id_digest.clone(), receipt);
        self.sync_store()?;
        Ok(request)
    }

    pub fn coalesce_missed_ticks(
        &mut self,
        request: &DurablePluginWakeRequest,
        observed_at: DateTime<Utc>,
        max_coalesced_ticks: u64,
    ) -> Result<CoalescedWake, PluginInvocationError> {
        if max_coalesced_ticks == 0 || max_coalesced_ticks > DEFAULT_MAX_COALESCED_TICKS {
            return Err(PluginInvocationError::InvalidCoalescingLimit);
        }
        let current = self.request_for_exact_record(request)?.clone();
        self.ensure_mounted(current.provider_epoch)?;
        let key = current.key()?;
        if self.receipts.contains_key(&key) {
            return Err(PluginInvocationError::AlreadyTriggered);
        }
        let due_ticks = Self::due_ticks(&current.schedule, observed_at)?;
        if due_ticks == 0 {
            return Err(PluginInvocationError::NoDueTicks);
        }
        let coalesced_ticks = due_ticks.min(max_coalesced_ticks);
        let next = current.with_coalesced_ticks(coalesced_ticks)?;
        self.replace_armed_request(&current.request_id_digest, &next)?;
        self.requests
            .insert(next.request_id_digest.clone(), next.clone());
        self.sync_store()?;
        Ok(CoalescedWake {
            request: next,
            due_ticks,
            coalesced_ticks,
            dispatch_count: 1,
        })
    }

    pub fn observe_wake(
        &mut self,
        request: &DurablePluginWakeRequest,
        woke_at: DateTime<Utc>,
    ) -> Result<TriggerReceipt, PluginInvocationError> {
        self.ensure_mounted(request.provider_epoch)?;
        let current = self.request_for_exact_record(request)?.clone();
        if current.wake.wake_at > woke_at {
            return Err(PluginInvocationError::WakeNotDue);
        }
        if current.schedule.contract_valid_until <= woke_at {
            return Err(PluginInvocationError::ScheduleExpired);
        }
        let key = current.key()?;
        if let Some(existing) = self.receipts.get(&key) {
            return Ok(existing.clone());
        }
        if let Some(armed) = self.armed.remove(&current.request_id_digest) {
            self.provider
                .disarm_wake(&armed)
                .map_err(PluginInvocationError::Provider)?;
        }
        let receipt = TriggerReceipt::from_request(&current, woke_at)?;
        self.receipts.insert(key, receipt.clone());
        self.sync_store()?;
        Ok(receipt)
    }

    pub fn cancel_schedule(
        &mut self,
        schedule_id_digest: &str,
        schedule_revision: u64,
        _observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        self.ensure_mounted(self.provider_epoch)?;
        let scope = self.current_scope()?.clone();
        let slot = ScheduleSlot::new(&scope, schedule_id_digest);
        let request_id = self
            .latest_by_schedule
            .get(&slot)
            .cloned()
            .ok_or(PluginInvocationError::ScheduleNotFound)?;
        let request = self
            .requests
            .get(&request_id)
            .ok_or(PluginInvocationError::ScheduleNotFound)?;
        if request.schedule.schedule_revision != schedule_revision {
            return Err(PluginInvocationError::StaleSchedule);
        }
        let key = request.key()?;
        if let Some(armed) = self.armed.remove(&request_id) {
            self.provider
                .disarm_wake(&armed)
                .map_err(PluginInvocationError::Provider)?;
        }
        self.cancelled.insert(key.schedule);
        self.sync_store()
    }

    pub fn revoke_plugin(&mut self, plugin: &PluginManifest) -> Result<(), PluginInvocationError> {
        plugin.validate()?;
        self.ensure_mounted(self.provider_epoch)?;
        self.provider
            .revoke_plugin(plugin)
            .map_err(PluginInvocationError::Provider)?;
        self.revoked_plugins.insert(plugin.clone());
        let ids = self
            .armed
            .keys()
            .filter_map(|request_id| {
                self.requests.get(request_id).and_then(|request| {
                    request
                        .composition
                        .contains(plugin)
                        .then_some(request_id.clone())
                })
            })
            .collect::<Vec<_>>();
        for request_id in ids {
            if let Some(armed) = self.armed.remove(&request_id) {
                self.provider
                    .disarm_wake(&armed)
                    .map_err(PluginInvocationError::Provider)?;
            }
        }
        self.sync_store()
    }

    pub fn consume_trigger(
        &mut self,
        scope: &MissionScope,
        composition: &PluginComposition,
        invocation: &PluginInvocation,
        receipt: &TriggerReceipt,
    ) -> Result<ConsumeResult, PluginInvocationError> {
        self.ensure_mounted(self.provider_epoch)?;
        receipt.validate()?;
        self.ensure_scope(scope)?;
        composition.validate()?;
        invocation.validate_for(composition)?;
        if receipt.scope != *scope
            || receipt.composition != *composition
            || receipt.invocation != *invocation
            || receipt.provider_id_digest != self.provider_id_digest
        {
            return Err(PluginInvocationError::ScopeOrCompositionMismatch);
        }
        let key = receipt.key()?;
        if self.cancelled.contains(&key.schedule) {
            return Err(PluginInvocationError::ScheduleCancelled);
        }
        if self.is_revoked(&receipt.composition) {
            return Err(PluginInvocationError::PluginRevoked);
        }
        if self.receipts.get(&key) != Some(receipt) {
            return Err(PluginInvocationError::StaleTriggerReceipt);
        }
        let slot = ScheduleSlot::new(scope, &receipt.schedule_id_digest);
        let request_id = self
            .latest_by_schedule
            .get(&slot)
            .ok_or(PluginInvocationError::StaleTriggerReceipt)?;
        let current = self
            .requests
            .get(request_id)
            .ok_or(PluginInvocationError::StaleTriggerReceipt)?;
        if current.schedule.schedule_revision != receipt.schedule_revision
            || current.objective_digest != receipt.objective_digest
            || current.composition != receipt.composition
            || current.invocation != receipt.invocation
        {
            return Err(PluginInvocationError::StaleTriggerReceipt);
        }
        if let Some(existing) = self.dispatches.get(&key) {
            return Ok(ConsumeResult::AlreadyStarted(existing.clone()));
        }
        let dispatch = PluginInvocationDispatch::from_receipt(receipt)?;
        self.dispatches.insert(key, dispatch.clone());
        self.sync_store()?;
        Ok(ConsumeResult::Started(dispatch))
    }
}

impl<P, S> PluginInvocationSchedulingService for PluginInvocationService<P, S>
where
    P: PluginInvocationProvider,
    S: PluginInvocationStore,
{
    fn provider_state(&self) -> ProviderState {
        self.state
    }

    fn provider_epoch(&self) -> u64 {
        self.provider_epoch
    }

    fn mount_provider(
        &mut self,
        scope: MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<u64, PluginInvocationError> {
        PluginInvocationService::mount_provider(self, scope, observed_at)
    }

    fn unmount_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        PluginInvocationService::unmount_provider(self, provider_epoch, observed_at)
    }

    fn revoke_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        PluginInvocationService::revoke_provider(self, provider_epoch, observed_at)
    }

    fn provider_crash(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        PluginInvocationService::provider_crash(self, provider_epoch, observed_at)
    }

    fn os_sleep(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        PluginInvocationService::os_sleep(self, provider_epoch, observed_at)
    }

    fn os_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, PluginInvocationError> {
        PluginInvocationService::os_wake(self, provider_epoch, woke_at)
    }

    fn cell_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, PluginInvocationError> {
        PluginInvocationService::cell_wake(self, provider_epoch, woke_at)
    }

    fn schedule_invocation(
        &mut self,
        input: PluginInvocationInput,
        observed_at: DateTime<Utc>,
    ) -> Result<DurablePluginWakeRequest, PluginInvocationError> {
        PluginInvocationService::schedule_invocation(self, input, observed_at)
    }

    fn coalesce_missed_ticks(
        &mut self,
        request: &DurablePluginWakeRequest,
        observed_at: DateTime<Utc>,
        max_coalesced_ticks: u64,
    ) -> Result<CoalescedWake, PluginInvocationError> {
        PluginInvocationService::coalesce_missed_ticks(
            self,
            request,
            observed_at,
            max_coalesced_ticks,
        )
    }

    fn observe_wake(
        &mut self,
        request: &DurablePluginWakeRequest,
        woke_at: DateTime<Utc>,
    ) -> Result<TriggerReceipt, PluginInvocationError> {
        PluginInvocationService::observe_wake(self, request, woke_at)
    }

    fn cancel_schedule(
        &mut self,
        schedule_id_digest: &str,
        schedule_revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PluginInvocationError> {
        PluginInvocationService::cancel_schedule(
            self,
            schedule_id_digest,
            schedule_revision,
            observed_at,
        )
    }

    fn revoke_plugin(&mut self, plugin: &PluginManifest) -> Result<(), PluginInvocationError> {
        PluginInvocationService::revoke_plugin(self, plugin)
    }

    fn consume_trigger(
        &mut self,
        scope: &MissionScope,
        composition: &PluginComposition,
        invocation: &PluginInvocation,
        receipt: &TriggerReceipt,
    ) -> Result<ConsumeResult, PluginInvocationError> {
        PluginInvocationService::consume_trigger(self, scope, composition, invocation, receipt)
    }
}

/// Scope/composition-pinned Mission consumer.  It can only receive a
/// capability request for the exact plugin composition it was constructed
/// with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginInvocationConsumer {
    scope: MissionScope,
    composition: PluginComposition,
    invocation: PluginInvocation,
}

impl PluginInvocationConsumer {
    pub fn new(
        scope: MissionScope,
        composition: PluginComposition,
        invocation: PluginInvocation,
    ) -> Result<Self, PluginInvocationError> {
        scope.validate()?;
        composition.validate()?;
        invocation.validate_for(&composition)?;
        if composition.scope != scope {
            return Err(PluginInvocationError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            composition,
            invocation,
        })
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn composition(&self) -> &PluginComposition {
        &self.composition
    }

    pub fn invocation(&self) -> &PluginInvocation {
        &self.invocation
    }

    pub fn schedule<P, S>(
        &self,
        service: &mut PluginInvocationService<P, S>,
        objective: impl Into<String>,
        schedule: ScheduledPluginInvocation,
        observed_at: DateTime<Utc>,
    ) -> Result<DurablePluginWakeRequest, PluginInvocationError>
    where
        P: PluginInvocationProvider,
        S: PluginInvocationStore,
    {
        service.schedule_invocation(
            PluginInvocationInput {
                objective: objective.into(),
                scope: self.scope.clone(),
                schedule,
                composition: self.composition.clone(),
                invocation: self.invocation.clone(),
            },
            observed_at,
        )
    }

    pub fn consume<P, S>(
        &self,
        service: &mut PluginInvocationService<P, S>,
        receipt: &TriggerReceipt,
    ) -> Result<ConsumeResult, PluginInvocationError>
    where
        P: PluginInvocationProvider,
        S: PluginInvocationStore,
    {
        if receipt.scope != self.scope
            || receipt.composition != self.composition
            || receipt.invocation != self.invocation
        {
            return Err(PluginInvocationError::ScopeOrCompositionMismatch);
        }
        service.consume_trigger(&self.scope, &self.composition, &self.invocation, receipt)
    }
}

/// macOS provider using the existing injected OS adapter.  `available_plugins`
/// is the provider's resolved composition catalog; no native platform calls
/// are made by the scheduler module.
#[derive(Debug)]
pub struct MacOsPluginInvocationProvider<B> {
    provider_id_digest: String,
    epoch: Option<u64>,
    adapter: MacOsWakeSleepAdapter<B>,
    available_plugins: BTreeSet<PluginManifest>,
    revoked_plugins: BTreeSet<PluginManifest>,
}

impl<B> MacOsPluginInvocationProvider<B>
where
    B: MacOsWakeSleepBackend,
{
    pub fn new(
        provider_id_digest: impl Into<String>,
        backend: B,
        available_plugins: Vec<PluginManifest>,
    ) -> Result<Self, PluginInvocationError> {
        let provider_id_digest = provider_id_digest.into();
        if !validate_digest(&provider_id_digest) {
            return Err(PluginInvocationError::InvalidProvider);
        }
        let mut available = BTreeSet::new();
        for plugin in available_plugins {
            plugin.validate()?;
            if !available.insert(plugin) {
                return Err(PluginInvocationError::DuplicatePlugin);
            }
        }
        Ok(Self {
            provider_id_digest,
            epoch: None,
            adapter: MacOsWakeSleepAdapter::new(backend),
            available_plugins: available,
            revoked_plugins: BTreeSet::new(),
        })
    }

    pub fn adapter(&self) -> &MacOsWakeSleepAdapter<B> {
        &self.adapter
    }

    fn ensure_epoch(&self, epoch: u64) -> Result<(), SchedulingProviderError> {
        if self.epoch != Some(epoch) {
            return Err(SchedulingProviderError::EpochLost);
        }
        Ok(())
    }

    fn ensure_transition(
        &self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        transition
            .validate()
            .map_err(|_| SchedulingProviderError::EpochLost)?;
        if transition.provider_id_digest != self.provider_id_digest
            || self.epoch != Some(transition.previous_epoch)
        {
            return Err(SchedulingProviderError::EpochLost);
        }
        Ok(())
    }
}

impl<B> PluginInvocationProvider for MacOsPluginInvocationProvider<B>
where
    B: MacOsWakeSleepBackend,
{
    fn provider_id_digest(&self) -> &str {
        &self.provider_id_digest
    }

    fn resolve_composition(
        &mut self,
        scope: &MissionScope,
        composition: &PluginComposition,
        invocation: &PluginInvocation,
    ) -> Result<(), SchedulingProviderError> {
        if composition.scope != *scope
            || invocation.validate_for(composition).is_err()
            || composition.plugins.iter().any(|plugin| {
                !self.available_plugins.contains(plugin) || self.revoked_plugins.contains(plugin)
            })
        {
            return Err(SchedulingProviderError::CompositionUnavailable);
        }
        Ok(())
    }

    fn mount(&mut self, request: &ProviderMountRequest) -> Result<(), SchedulingProviderError> {
        request
            .validate()
            .map_err(|_| SchedulingProviderError::EpochLost)?;
        if request.provider_id_digest != self.provider_id_digest || self.epoch.is_some() {
            return Err(SchedulingProviderError::EpochLost);
        }
        self.epoch = Some(request.provider_epoch);
        Ok(())
    }

    fn unmount(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.epoch = None;
        Ok(())
    }

    fn revoke(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.epoch = None;
        Ok(())
    }

    fn crash(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.epoch = None;
        Ok(())
    }

    fn on_sleep(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.adapter
            .record_sleep(transition.observed_at)
            .map_err(SchedulingProviderError::Lifecycle)?;
        Ok(())
    }

    fn on_wake(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.adapter
            .record_wake(transition.observed_at)
            .map_err(SchedulingProviderError::Lifecycle)?;
        self.epoch = Some(transition.next_epoch);
        Ok(())
    }

    fn revoke_plugin(&mut self, plugin: &PluginManifest) -> Result<(), SchedulingProviderError> {
        plugin
            .validate()
            .map_err(|_| SchedulingProviderError::CompositionUnavailable)?;
        self.revoked_plugins.insert(plugin.clone());
        Ok(())
    }

    fn arm_wake(
        &mut self,
        request: &DurablePluginWakeRequest,
    ) -> Result<ProviderWakeReceipt, SchedulingProviderError> {
        self.ensure_epoch(request.provider_epoch)?;
        if request.provider_id_digest != self.provider_id_digest {
            return Err(SchedulingProviderError::EpochLost);
        }
        self.resolve_composition(&request.scope, &request.composition, &request.invocation)?;
        let lifecycle_receipt = self
            .adapter
            .arm_wake(request.wake.clone())
            .map_err(SchedulingProviderError::Lifecycle)?;
        Ok(ProviderWakeReceipt {
            request_id_digest: request.request_id_digest.clone(),
            request_digest: request.request_digest.clone(),
            provider_id_digest: self.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            lifecycle_receipt: Some(lifecycle_receipt),
        })
    }

    fn disarm_wake(
        &mut self,
        receipt: &ProviderWakeReceipt,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_epoch(receipt.provider_epoch)?;
        if receipt.provider_id_digest != self.provider_id_digest {
            return Err(SchedulingProviderError::EpochLost);
        }
        if let Some(lifecycle_receipt) = &receipt.lifecycle_receipt {
            self.adapter
                .disarm_wake(lifecycle_receipt)
                .map_err(SchedulingProviderError::Lifecycle)?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CompositionMaterial<'a> {
    scope: &'a MissionScope,
    composition_revision: u64,
    plugins: &'a [PluginManifest],
}

#[derive(Serialize)]
struct RequestIdMaterial<'a> {
    objective_digest: &'a str,
    scope: &'a MissionScope,
    schedule_id_digest: &'a str,
    schedule_revision: u64,
    composition_digest: &'a str,
    invocation_digest: &'a str,
    provider_id_digest: &'a str,
    provider_epoch: u64,
}

#[derive(Serialize)]
struct RequestDigestMaterial<'a> {
    request_id_digest: &'a str,
    objective_digest: &'a str,
    scope: &'a MissionScope,
    schedule: &'a ScheduledPluginInvocation,
    composition: &'a PluginComposition,
    invocation: &'a PluginInvocation,
    provider_id_digest: &'a str,
    provider_epoch: u64,
    wake: &'a WakeRequest,
}

#[derive(Serialize)]
struct TriggerIdMaterial<'a> {
    scope: &'a MissionScope,
    schedule_id_digest: &'a str,
    schedule_revision: u64,
    composition_digest: &'a str,
    invocation_digest: &'a str,
}

#[derive(Serialize)]
struct TriggerReceiptMaterial<'a> {
    trigger_id_digest: &'a str,
    request_id_digest: &'a str,
    request_digest: &'a str,
    objective_digest: &'a str,
    scope: &'a MissionScope,
    schedule_id_digest: &'a str,
    schedule_revision: u64,
    planned_at: DateTime<Utc>,
    woke_at: DateTime<Utc>,
    coalesced_ticks: u64,
    composition: &'a PluginComposition,
    invocation: &'a PluginInvocation,
    provider_id_digest: &'a str,
    provider_epoch: u64,
}

#[derive(Serialize)]
struct DispatchIdMaterial<'a> {
    trigger_receipt_digest: &'a str,
    scope: &'a MissionScope,
    schedule_id_digest: &'a str,
    schedule_revision: u64,
    composition_digest: &'a str,
    invocation: &'a PluginInvocation,
    authority: DispatchAuthority,
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, PluginInvocationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PluginInvocationError::Serialization(error.to_string()))?;
    Ok(scheduler_digest(bytes))
}

fn validate_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PluginInvocationError {
    #[error("plugin invocation Mission scope is invalid")]
    InvalidScope,
    #[error("plugin objective is empty or exceeds the bounded input size")]
    InvalidObjective,
    #[error("plugin manifest ID, version or digest is invalid")]
    InvalidPluginManifest,
    #[error("plugin composition is empty, malformed or tampered")]
    InvalidPluginComposition,
    #[error("plugin composition contains duplicate plugin IDs")]
    DuplicatePlugin,
    #[error("plugin invocation target is invalid")]
    InvalidInvocation,
    #[error("plugin invocation target is not present in the exact composition")]
    PluginNotInComposition,
    #[error("plugin invocation schedule is invalid")]
    InvalidSchedule,
    #[error("plugin schedule state does not permit registration")]
    ScheduleStateConflict,
    #[error("plugin invocation scope does not match the composition")]
    ScopeMismatch,
    #[error("plugin invocation provider is invalid")]
    InvalidProvider,
    #[error("plugin invocation provider epoch is invalid")]
    InvalidProviderEpoch,
    #[error("plugin invocation provider epoch is exhausted")]
    ProviderEpochExhausted,
    #[error("plugin invocation provider is already mounted")]
    ProviderAlreadyMounted,
    #[error("plugin invocation provider is not mounted")]
    ProviderNotMounted,
    #[error("plugin invocation provider is sleeping")]
    ProviderSleeping,
    #[error("plugin invocation provider is not sleeping")]
    ProviderNotSleeping,
    #[error("plugin invocation provider crashed")]
    ProviderCrashed,
    #[error("plugin invocation provider was revoked")]
    ProviderRevoked,
    #[error("plugin invocation provider epoch is stale ({expected} != {actual})")]
    ProviderEpochLost { expected: u64, actual: u64 },
    #[error("plugin invocation provider identity does not match durable records")]
    ProviderIdentityMismatch,
    #[error("plugin invocation wake request is invalid or tampered")]
    InvalidWakeRequest,
    #[error("plugin invocation wake request is stale")]
    StaleWakeRequest,
    #[error("plugin invocation wake request conflicts with the immutable record")]
    WakeRequestConflict,
    #[error("plugin invocation schedule is stale")]
    StaleSchedule,
    #[error("plugin invocation schedule was not found")]
    ScheduleNotFound,
    #[error("plugin invocation schedule was cancelled")]
    ScheduleCancelled,
    #[error("plugin invocation schedule contract expired")]
    ScheduleExpired,
    #[error("plugin invocation plugin was revoked")]
    PluginRevoked,
    #[error("plugin invocation wake is not due")]
    WakeNotDue,
    #[error("plugin invocation trigger receipt is invalid or tampered")]
    InvalidTriggerReceipt,
    #[error("plugin invocation trigger receipt is stale")]
    StaleTriggerReceipt,
    #[error("plugin invocation scope or composition does not match the consumer")]
    ScopeOrCompositionMismatch,
    #[error("plugin invocation dispatch is invalid")]
    InvalidDispatch,
    #[error("plugin invocation key is invalid")]
    InvalidInvocationKey,
    #[error("plugin invocation already produced a trigger receipt")]
    AlreadyTriggered,
    #[error("plugin invocation coalescing limit is zero or exceeds the bounded contract")]
    InvalidCoalescingLimit,
    #[error("plugin invocation has no due ticks")]
    NoDueTicks,
    #[error("plugin invocation schedule is already bound to another exact composition")]
    ScheduleConflict,
    #[error("plugin invocation lifecycle state does not allow the operation")]
    InvalidLifecycleState,
    #[error("plugin invocation provider wake receipt conflicts with the request")]
    ProviderReceiptConflict,
    #[error("plugin invocation store failed")]
    Store(#[from] PluginInvocationStoreError),
    #[error("plugin invocation provider failed")]
    Provider(#[from] SchedulingProviderError),
    #[error("plugin invocation OS lifecycle failed")]
    Lifecycle(#[from] WakeSleepError),
    #[error("plugin invocation serialization failed: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("valid test time")
    }

    fn digest(byte: u8) -> String {
        scheduler_digest([byte])
    }

    fn scope(revision: u64) -> MissionScope {
        MissionScope::new(DataCell::Us, "tenant-1", "project-1", "mission-1", revision)
            .expect("scope")
    }

    fn plugin(id: &str, version: &str, digest_byte: u8) -> PluginManifest {
        PluginManifest::new(id, version, digest(digest_byte)).expect("plugin")
    }

    fn composition(scope: &MissionScope, version: &str, digest_byte: u8) -> PluginComposition {
        PluginComposition::new(
            scope.clone(),
            1,
            vec![plugin("brief-plugin", version, digest_byte)],
        )
        .expect("composition")
    }

    fn schedule(id: u8, revision: u64, planned_at: DateTime<Utc>) -> ScheduledPluginInvocation {
        ScheduledPluginInvocation::new(
            digest(id),
            revision,
            planned_at,
            60,
            now() + Duration::hours(8),
        )
        .expect("schedule")
    }

    fn invocation() -> PluginInvocation {
        PluginInvocation::new("brief-plugin", "generate").expect("invocation")
    }

    #[derive(Debug, Default)]
    struct RecordingProvider {
        provider_id_digest: String,
        epoch: Option<u64>,
        available: BTreeSet<PluginManifest>,
        revoked: BTreeSet<PluginManifest>,
        armed: BTreeMap<String, ProviderWakeReceipt>,
        arm_calls: usize,
        disarm_calls: usize,
    }

    impl RecordingProvider {
        fn new(provider_id_digest: String, available: Vec<PluginManifest>) -> Self {
            Self {
                provider_id_digest,
                available: available.into_iter().collect(),
                ..Self::default()
            }
        }

        fn transition_epoch(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            transition
                .validate()
                .map_err(|_| SchedulingProviderError::EpochLost)?;
            if transition.provider_id_digest != self.provider_id_digest
                || self.epoch != Some(transition.previous_epoch)
            {
                return Err(SchedulingProviderError::EpochLost);
            }
            Ok(())
        }
    }

    impl PluginInvocationProvider for RecordingProvider {
        fn provider_id_digest(&self) -> &str {
            &self.provider_id_digest
        }

        fn resolve_composition(
            &mut self,
            scope: &MissionScope,
            composition: &PluginComposition,
            invocation: &PluginInvocation,
        ) -> Result<(), SchedulingProviderError> {
            if composition.scope != *scope
                || invocation.validate_for(composition).is_err()
                || composition
                    .plugins
                    .iter()
                    .any(|plugin| !self.available.contains(plugin) || self.revoked.contains(plugin))
            {
                return Err(SchedulingProviderError::CompositionUnavailable);
            }
            Ok(())
        }

        fn mount(&mut self, request: &ProviderMountRequest) -> Result<(), SchedulingProviderError> {
            request
                .validate()
                .map_err(|_| SchedulingProviderError::EpochLost)?;
            self.epoch = Some(request.provider_epoch);
            Ok(())
        }

        fn unmount(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.transition_epoch(transition)?;
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
            self.transition_epoch(transition)
        }

        fn on_wake(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.transition_epoch(transition)?;
            self.epoch = Some(transition.next_epoch);
            Ok(())
        }

        fn revoke_plugin(
            &mut self,
            plugin: &PluginManifest,
        ) -> Result<(), SchedulingProviderError> {
            self.revoked.insert(plugin.clone());
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
                existing
                    .validate_for(request)
                    .map_err(|_| SchedulingProviderError::ReceiptConflict)?;
                return Ok(existing.clone());
            }
            self.arm_calls += 1;
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
            if self.epoch != Some(receipt.provider_epoch) {
                return Err(SchedulingProviderError::EpochLost);
            }
            self.disarm_calls += 1;
            self.armed.remove(&receipt.request_id_digest);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingBackend {
        arm_calls: usize,
        disarm_calls: usize,
    }

    impl MacOsWakeSleepBackend for RecordingBackend {
        fn arm(&mut self, _request: &WakeRequest) -> Result<(), WakeSleepError> {
            self.arm_calls += 1;
            Ok(())
        }

        fn disarm(&mut self, _receipt: &WakeReceipt) -> Result<(), WakeSleepError> {
            self.disarm_calls += 1;
            Ok(())
        }
    }

    fn mounted_service() -> (
        PluginInvocationService<RecordingProvider>,
        MissionScope,
        PluginComposition,
        PluginInvocation,
        DateTime<Utc>,
    ) {
        let scope = scope(7);
        let composition = composition(&scope, "1.2.0", b'c');
        let invocation = invocation();
        let plugin = composition.plugin("brief-plugin").expect("plugin").clone();
        let provider = RecordingProvider::new(digest(b'p'), vec![plugin]);
        let mut service = PluginInvocationService::new(provider).expect("service");
        assert_eq!(
            service.mount_provider(scope.clone(), now()).expect("mount"),
            1
        );
        (service, scope, composition, invocation, now())
    }

    #[test]
    fn exact_composition_wakes_once_and_consumer_starts_once_without_effect_authority() {
        let (mut service, scope, composition, invocation, time) = mounted_service();
        let consumer =
            PluginInvocationConsumer::new(scope.clone(), composition.clone(), invocation.clone())
                .expect("consumer");
        let request = consumer
            .schedule(
                &mut service,
                "generate weekly brief",
                schedule(b's', 4, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        let duplicate = consumer
            .schedule(
                &mut service,
                "generate weekly brief",
                schedule(b's', 4, time + Duration::minutes(1)),
                time,
            )
            .expect("exact schedule replay");
        assert_eq!(request, duplicate);
        assert_eq!(service.provider().arm_calls, 1);
        let receipt = service
            .cell_wake(1, time + Duration::minutes(2))
            .expect("wake")
            .pop()
            .expect("receipt");
        assert_eq!(receipt.schedule_revision, 4);
        assert_eq!(receipt.planned_at, request.schedule.planned_at);
        assert_eq!(receipt.woke_at, time + Duration::minutes(2));
        assert_eq!(receipt.coalesced_ticks, 2);
        assert_eq!(receipt.composition, composition);
        assert_eq!(receipt.provider_id_digest, digest(b'p'));
        receipt.validate().expect("valid receipt");

        let first = consumer.consume(&mut service, &receipt).expect("start");
        let second = consumer.consume(&mut service, &receipt).expect("replay");
        match first {
            ConsumeResult::Started(dispatch) => {
                assert_eq!(dispatch.authority, DispatchAuthority::CapabilityRequestOnly);
                assert_eq!(dispatch.invocation, invocation);
            }
            ConsumeResult::AlreadyStarted(_) => panic!("first consume was already started"),
        }
        assert!(matches!(second, ConsumeResult::AlreadyStarted(_)));
        assert_eq!(service.dispatch_count(), 1);
    }

    #[test]
    fn missed_ticks_are_bounded_to_one_plugin_dispatch() {
        let (mut service, scope, composition, invocation, time) = mounted_service();
        let consumer =
            PluginInvocationConsumer::new(scope, composition, invocation).expect("consumer");
        let request = consumer
            .schedule(
                &mut service,
                "coalesce plugin wake",
                schedule(b'm', 1, time),
                time,
            )
            .expect("schedule");
        let coalesced = service
            .coalesce_missed_ticks(&request, time + Duration::hours(1), 3)
            .expect("coalesce");
        assert_eq!(coalesced.due_ticks, 61);
        assert_eq!(coalesced.coalesced_ticks, 3);
        assert_eq!(coalesced.dispatch_count, 1);
        let receipts = service
            .cell_wake(1, time + Duration::hours(1))
            .expect("wake");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].coalesced_ticks, 3);
    }

    #[test]
    fn sleep_resume_changes_epoch_but_repeated_wake_has_no_duplicate_receipt() {
        let (mut service, scope, composition, invocation, time) = mounted_service();
        let consumer =
            PluginInvocationConsumer::new(scope, composition, invocation).expect("consumer");
        let request = consumer
            .schedule(
                &mut service,
                "resume plugin",
                schedule(b'r', 2, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        service.os_sleep(1, time).expect("sleep");
        let receipts = service
            .os_wake(1, time + Duration::minutes(2))
            .expect("resume");
        assert_eq!(receipts.len(), 1);
        assert_eq!(service.provider_epoch(), 2);
        assert_eq!(receipts[0].schedule_revision, 2);
        assert_eq!(
            service.observe_wake(&request, time + Duration::minutes(2)),
            Err(PluginInvocationError::ProviderEpochLost {
                expected: 2,
                actual: 1
            })
        );
        assert!(
            service
                .cell_wake(2, time + Duration::minutes(3))
                .expect("repeated wake")
                .is_empty()
        );
    }

    #[test]
    fn macos_provider_delegates_wake_resume_without_effect_authority() {
        let scope = scope(5);
        let composition = composition(&scope, "1.2.0", b'c');
        let invocation = invocation();
        let plugin = composition.plugin("brief-plugin").expect("plugin").clone();
        let provider = MacOsPluginInvocationProvider::new(
            digest(b'm'),
            RecordingBackend::default(),
            vec![plugin],
        )
        .expect("provider");
        let mut service = PluginInvocationService::new(provider).expect("service");
        assert_eq!(
            service.mount_provider(scope.clone(), now()).expect("mount"),
            1
        );
        let consumer =
            PluginInvocationConsumer::new(scope, composition, invocation).expect("consumer");
        consumer
            .schedule(
                &mut service,
                "macOS wake",
                schedule(b'o', 1, now() + Duration::minutes(1)),
                now(),
            )
            .expect("schedule");
        service.os_sleep(1, now()).expect("sleep");
        let receipts = service
            .os_wake(1, now() + Duration::minutes(2))
            .expect("wake");
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            service.provider().adapter().backend().arm_calls,
            2,
            "initial arm plus one post-resume arm"
        );
        assert_eq!(
            service.provider().adapter().backend().disarm_calls,
            2,
            "one disarm before resume plus receipt handoff disarm"
        );
    }

    #[test]
    fn sqlite_restart_preserves_receipt_and_consumer_idempotency() {
        let store = SqlitePluginInvocationStore::open_in_memory().expect("store");
        let scope = scope(3);
        let composition = composition(&scope, "2.0.0", b'j');
        let invocation = invocation();
        let consumer =
            PluginInvocationConsumer::new(scope.clone(), composition.clone(), invocation.clone())
                .expect("consumer");
        let provider_id = digest(b'p');
        let (receipt, store) = {
            let plugin = composition.plugin("brief-plugin").expect("plugin").clone();
            let mut service = PluginInvocationService::with_store(
                RecordingProvider::new(provider_id.clone(), vec![plugin]),
                store,
            )
            .expect("service");
            service.mount_provider(scope.clone(), now()).expect("mount");
            consumer
                .schedule(
                    &mut service,
                    "restart safe",
                    schedule(b'x', 8, now()),
                    now(),
                )
                .expect("schedule");
            let receipt = service
                .cell_wake(1, now() + Duration::minutes(1))
                .expect("wake")
                .pop()
                .expect("receipt")
                .clone();
            assert!(matches!(
                consumer.consume(&mut service, &receipt).expect("start"),
                ConsumeResult::Started(_)
            ));
            (receipt, service.into_store())
        };
        let plugin = composition.plugin("brief-plugin").expect("plugin").clone();
        let mut restarted = PluginInvocationService::with_store(
            RecordingProvider::new(provider_id, vec![plugin]),
            store,
        )
        .expect("restart");
        assert_eq!(
            restarted
                .mount_provider(scope.clone(), now())
                .expect("mount"),
            2
        );
        assert!(
            restarted
                .cell_wake(2, now() + Duration::minutes(2))
                .expect("repeated wake")
                .is_empty()
        );
        assert!(matches!(
            consumer.consume(&mut restarted, &receipt).expect("replay"),
            ConsumeResult::AlreadyStarted(_)
        ));
        assert_eq!(restarted.dispatch_count(), 1);
    }

    #[test]
    fn revision_version_digest_and_scope_fences_reject_stale_invocation() {
        let (mut service, scope, base_composition, invocation, time) = mounted_service();
        let consumer = PluginInvocationConsumer::new(
            scope.clone(),
            base_composition.clone(),
            invocation.clone(),
        )
        .expect("consumer");
        let old = consumer
            .schedule(
                &mut service,
                "old composition",
                schedule(b'z', 1, time),
                time,
            )
            .expect("old schedule");
        let conflicting_composition = composition(&scope, "9.0.0", b'w');
        service.provider_mut().available.insert(
            conflicting_composition
                .plugin("brief-plugin")
                .expect("plugin")
                .clone(),
        );
        let conflicting_consumer = PluginInvocationConsumer::new(
            scope.clone(),
            conflicting_composition,
            invocation.clone(),
        )
        .expect("conflicting consumer");
        assert_eq!(
            conflicting_consumer.schedule(
                &mut service,
                "different plugin version",
                schedule(b'z', 1, time),
                time,
            ),
            Err(PluginInvocationError::ScheduleConflict)
        );
        let newer_composition = composition(&scope, "2.0.0", b'v');
        service.provider_mut().available.insert(
            newer_composition
                .plugin("brief-plugin")
                .expect("plugin")
                .clone(),
        );
        let newer_consumer = PluginInvocationConsumer::new(
            scope.clone(),
            newer_composition.clone(),
            invocation.clone(),
        )
        .expect("new consumer");
        let current = newer_consumer
            .schedule(
                &mut service,
                "new composition",
                schedule(b'z', 2, time),
                time,
            )
            .expect("new schedule");
        assert_eq!(
            service.observe_wake(&old, time),
            Err(PluginInvocationError::StaleWakeRequest)
        );
        let mut tampered = current.clone();
        tampered.composition.plugins[0].version = "9.9.9".into();
        assert_eq!(
            service.observe_wake(&tampered, time),
            Err(PluginInvocationError::InvalidPluginComposition)
        );
        let wrong_scope = MissionScope::new(DataCell::Us, "tenant-2", "project-1", "mission-1", 7)
            .expect("wrong scope");
        assert_eq!(
            PluginInvocationConsumer::new(wrong_scope, newer_composition, invocation),
            Err(PluginInvocationError::ScopeMismatch)
        );
    }

    #[test]
    fn cancellation_and_plugin_revocation_disarm_before_wake() {
        let (mut service, scope, composition, invocation, time) = mounted_service();
        let consumer =
            PluginInvocationConsumer::new(scope.clone(), composition.clone(), invocation.clone())
                .expect("consumer");
        let cancelled = consumer
            .schedule(
                &mut service,
                "cancel",
                schedule(b'a', 1, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        service
            .cancel_schedule(&digest(b'a'), 1, time)
            .expect("cancel");
        assert!(
            service
                .cell_wake(1, time + Duration::minutes(2))
                .expect("cancelled wake")
                .is_empty()
        );
        assert_eq!(
            service.observe_wake(&cancelled, time + Duration::minutes(2)),
            Err(PluginInvocationError::ScheduleCancelled)
        );

        let revoked = consumer
            .schedule(
                &mut service,
                "revoke",
                schedule(b'v', 1, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        let plugin = composition.plugin("brief-plugin").expect("plugin").clone();
        service.revoke_plugin(&plugin).expect("revoke");
        assert!(
            service
                .cell_wake(1, time + Duration::minutes(2))
                .expect("revoked wake")
                .is_empty()
        );
        assert_eq!(
            service.observe_wake(&revoked, time + Duration::minutes(2)),
            Err(PluginInvocationError::PluginRevoked)
        );
    }

    #[test]
    fn provider_unmount_and_cross_scope_consumer_fail_closed() {
        let (mut service, scope, composition, invocation, time) = mounted_service();
        let consumer =
            PluginInvocationConsumer::new(scope.clone(), composition.clone(), invocation.clone())
                .expect("consumer");
        let request = consumer
            .schedule(
                &mut service,
                "unmount",
                schedule(b'u', 1, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        service.unmount_provider(1, time).expect("unmount");
        assert_eq!(
            service.observe_wake(&request, time + Duration::minutes(2)),
            Err(PluginInvocationError::ProviderNotMounted)
        );
        let other_scope =
            MissionScope::new(DataCell::Us, "tenant-1", "project-other", "mission-1", 7)
                .expect("other scope");
        assert_eq!(
            PluginInvocationConsumer::new(other_scope, composition, invocation),
            Err(PluginInvocationError::ScopeMismatch)
        );
    }
}

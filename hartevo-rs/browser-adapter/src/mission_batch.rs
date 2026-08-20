//! Mission-scoped, bounded Browser batch ownership.
//!
//! This module is deliberately narrower than the existing action and host
//! contracts.  It owns the lifecycle around one already-validated
//! [`BrowserActionBatch`]: a bounded claim, an exact result prefix, a
//! serializable cursor/receipt, and a provider/consumer seam.  It does not
//! persist application rows, create a Mission, or claim Provider/business
//! completion.  A caller persists the content-free receipt in its own durable
//! Mission result and supplies it again for explicit resume.

use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    BrowserActionBatchId, BrowserProfileId, BrowserSnapshotId, BrowserTabId, BrowserWorkspaceId,
    MissionId, ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};

use crate::workspace::{digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserAction, BrowserActionBatch, BrowserActionKind, BrowserError, BrowserLeaseProof,
    BrowserProfile, BrowserProfileSource, BrowserWorkspace,
};

#[cfg(unix)]
use crate::ManagedChromiumHost;

const BATCH_SCHEMA_VERSION: u32 = 1;
const MAX_BATCH_ACTIONS: usize = 64;
const MAX_SESSION_BATCH_CLAIMS: usize = 1_024;
const SERVICE_ID: &str = "hartevo.browser-workspace.mission-batch";

/// The immutable frame fence used by a Mission batch.  Frame/loader values are
/// stored only as digests; no URL, AX name, account or prompt text is retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBrowserFrameScope {
    pub tab_id: BrowserTabId,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub url_digest: String,
    pub origin_digest: String,
    pub document_generation: u64,
}

impl MissionBrowserFrameScope {
    pub fn validate(&self) -> Result<(), BrowserError> {
        if !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.frame_id_digest)
            || !is_sha256(&self.loader_id_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.origin_digest)
            || self.document_generation == 0
        {
            return Err(BrowserError::StaleSnapshot);
        }
        Ok(())
    }
}

/// Exact Project/Mission/Profile/Workspace/lease/frame authority for one
/// batch.  The lease and generation are intentionally part of the digest.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBrowserBatchScope {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub profile_id: BrowserProfileId,
    pub workspace_id: BrowserWorkspaceId,
    pub lease: BrowserLeaseProof,
    pub expected_identity_digest: String,
    pub policy_digest: String,
    pub frame: MissionBrowserFrameScope,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub scope_digest: String,
}

impl MissionBrowserBatchScope {
    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != BATCH_SCHEMA_VERSION
            || !is_bounded_identifier(self.tenant_id.as_str())
            || !is_bounded_identifier(self.project_id.as_str())
            || !is_bounded_identifier(self.mission_id.as_str())
            || !is_bounded_identifier(self.profile_id.as_str())
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_sha256(&self.expected_identity_digest)
            || !is_sha256(&self.policy_digest)
            || self.profile_revision == 0
            || self.workspace_revision == 0
            || self.lease.workspace_id != self.workspace_id
            || self.lease.generation == 0
            || self.frame.validate().is_err()
            || !is_sha256(&self.scope_digest)
            || self.scope_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn bind(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        lease: BrowserLeaseProof,
        frame: MissionBrowserFrameScope,
        policy_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        profile.validate()?;
        workspace.validate_agent_lease(&lease, now)?;
        frame.validate()?;
        if profile.source != BrowserProfileSource::Managed
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.id != workspace.profile_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
            || lease.workspace_id != workspace.id
            || !workspace.tabs.contains(&frame.tab_id)
            || !is_sha256(&policy_digest)
        {
            return Err(BrowserError::ScopeMismatch);
        }
        let mut scope = Self {
            schema_version: BATCH_SCHEMA_VERSION,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            profile_id: profile.id.clone(),
            workspace_id: workspace.id.clone(),
            lease,
            expected_identity_digest: profile.identity.identity_digest.clone(),
            policy_digest,
            frame,
            profile_revision: profile.revision,
            workspace_revision: workspace.revision,
            scope_digest: String::new(),
        };
        scope.scope_digest = scope.unsigned_digest()?;
        scope.validate_for(profile, workspace, now)?;
        Ok(scope)
    }

    pub fn validate_for(
        &self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        profile.validate()?;
        self.validate()?;
        workspace.validate_agent_lease(&self.lease, now)?;
        self.frame.validate()?;
        if self.schema_version != BATCH_SCHEMA_VERSION
            || profile.id != self.profile_id
            || profile.source != BrowserProfileSource::Managed
            || profile.tenant_id != self.tenant_id
            || profile.project_id != self.project_id
            || profile.identity.identity_digest != self.expected_identity_digest
            || workspace.id != self.workspace_id
            || workspace.tenant_id != self.tenant_id
            || workspace.project_id != self.project_id
            || workspace.mission_id != self.mission_id
            || workspace.profile_id != self.profile_id
            || workspace.expected_identity_digest != self.expected_identity_digest
            || workspace.revision != self.workspace_revision
            || profile.revision != self.profile_revision
            || self.lease.workspace_id != workspace.id
            || self.frame.document_generation == 0
            || !workspace.tabs.contains(&self.frame.tab_id)
            || !is_sha256(&self.expected_identity_digest)
            || !is_sha256(&self.policy_digest)
            || self.scope_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(())
    }

    /// Resume after explicit takeover/host replacement may use a new lease,
    /// but must remain the same Mission workspace, identity, policy and frame.
    pub fn same_resume_scope(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.project_id == other.project_id
            && self.mission_id == other.mission_id
            && self.profile_id == other.profile_id
            && self.workspace_id == other.workspace_id
            && self.expected_identity_digest == other.expected_identity_digest
            && self.policy_digest == other.policy_digest
            && self.frame == other.frame
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&(
            self.schema_version,
            SERVICE_ID,
            &self.tenant_id,
            &self.project_id,
            &self.mission_id,
            &self.profile_id,
            &self.workspace_id,
            &self.lease,
            &self.expected_identity_digest,
            &self.policy_digest,
            &self.frame,
            self.profile_revision,
            self.workspace_revision,
        ))
    }
}

impl fmt::Debug for MissionBrowserBatchScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrowserBatchScope")
            .field("schema_version", &self.schema_version)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("profile_id", &self.profile_id)
            .field("workspace_id", &self.workspace_id)
            .field("lease_generation", &self.lease.generation)
            .field("expected_identity_digest", &self.expected_identity_digest)
            .field("policy_digest", &self.policy_digest)
            .field("frame", &self.frame)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("scope_digest", &self.scope_digest)
            .finish_non_exhaustive()
    }
}

/// A validated immutable plan.  The underlying v1 action schema remains
/// unchanged; this wrapper only adds the Mission ownership fence.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBrowserBatchPlan {
    pub schema_version: u32,
    pub batch: BrowserActionBatch,
    pub scope: MissionBrowserBatchScope,
    pub batch_digest: String,
    pub plan_digest: String,
}

impl MissionBrowserBatchPlan {
    pub fn new(
        batch: BrowserActionBatch,
        scope: MissionBrowserBatchScope,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        scope.validate_for(profile, workspace, now)?;
        batch.validate_for(profile, workspace, now)?;
        if batch.tenant_id != scope.tenant_id
            || batch.project_id != scope.project_id
            || batch.mission_id != scope.mission_id
            || batch.workspace_id != scope.workspace_id
            || batch.lease != scope.lease
            || batch.expected_identity_digest != scope.expected_identity_digest
            || batch.policy_digest != scope.policy_digest
            || batch.actions.len() > MAX_BATCH_ACTIONS
            || batch.actions.iter().any(|action| {
                action.tab_id != scope.frame.tab_id
                    || action.target_origin_digest != scope.frame.origin_digest
            })
        {
            return Err(BrowserError::ScopeMismatch);
        }
        let plan_digest = batch.plan_digest.clone();
        let batch_digest = batch.digest()?;
        let plan = Self {
            schema_version: BATCH_SCHEMA_VERSION,
            batch,
            scope,
            batch_digest,
            plan_digest,
        };
        plan.validate_contract_at(now)?;
        plan.validate(profile, workspace, now)?;
        Ok(plan)
    }

    fn validate_contract_at(&self, now: DateTime<Utc>) -> Result<(), BrowserError> {
        if self.schema_version != BATCH_SCHEMA_VERSION
            || self.scope.validate().is_err()
            || self.batch.schema_version != BATCH_SCHEMA_VERSION
            || !is_bounded_identifier(self.batch.id.as_str())
            || self.batch.tenant_id != self.scope.tenant_id
            || self.batch.project_id != self.scope.project_id
            || self.batch.mission_id != self.scope.mission_id
            || self.batch.workspace_id != self.scope.workspace_id
            || self.batch.lease != self.scope.lease
            || self.batch.expected_identity_digest != self.scope.expected_identity_digest
            || self.batch.policy_digest != self.scope.policy_digest
            || self.batch.actions.is_empty()
            || self.batch.actions.len() > MAX_BATCH_ACTIONS
            || self.batch.actions.iter().any(|action| {
                action.validate().is_err()
                    || action.tab_id != self.scope.frame.tab_id
                    || action.target_origin_digest != self.scope.frame.origin_digest
            })
            || self.plan_digest != self.batch.plan_digest
            || self.batch_digest != self.batch.digest()?
            || self.batch.created_at > now
            || self.batch.expires_at <= now
            || self.batch.expires_at - self.batch.created_at > Duration::minutes(15)
        {
            return Err(BrowserError::InvalidBatch);
        }
        let expected_plan_digest = match self.batch.recipe_binding_digest.as_deref() {
            Some(recipe_digest) => {
                BrowserActionBatch::recipe_plan_digest(&self.batch.actions, recipe_digest)?
            }
            None => BrowserActionBatch::plan_digest(&self.batch.actions)?,
        };
        if self.plan_digest != expected_plan_digest {
            return Err(BrowserError::InvalidBatch);
        }
        Ok(())
    }

    pub fn validate(
        &self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_contract_at(now)?;
        self.scope.validate_for(profile, workspace, now)?;
        self.batch.validate_for(profile, workspace, now)
    }

    pub fn action_count(&self) -> usize {
        self.batch.actions.len()
    }
}

impl fmt::Debug for MissionBrowserBatchPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrowserBatchPlan")
            .field("schema_version", &self.schema_version)
            .field("batch_id", &self.batch.id)
            .field("scope_digest", &self.scope.scope_digest)
            .field("batch_digest", &self.batch_digest)
            .field("plan_digest", &self.plan_digest)
            .field("action_count", &self.batch.actions.len())
            .finish_non_exhaustive()
    }
}

/// Persistable bounded claim set.  Claims are never evicted: a duplicate id
/// must fail closed even when a later plan has a different digest.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBrowserBatchClaimSet {
    pub schema_version: u32,
    pub claimed_batch_ids: BTreeSet<BrowserActionBatchId>,
}

impl MissionBrowserBatchClaimSet {
    pub fn new() -> Self {
        Self {
            schema_version: BATCH_SCHEMA_VERSION,
            claimed_batch_ids: BTreeSet::new(),
        }
    }

    pub fn try_claim(&mut self, batch_id: BrowserActionBatchId) -> Result<(), BrowserError> {
        self.validate()?;
        if !is_bounded_identifier(batch_id.as_str())
            || self.claimed_batch_ids.len() >= MAX_SESSION_BATCH_CLAIMS
            || self.claimed_batch_ids.contains(&batch_id)
        {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        self.claimed_batch_ids.insert(batch_id);
        Ok(())
    }

    pub fn contains(&self, batch_id: &BrowserActionBatchId) -> bool {
        self.claimed_batch_ids.contains(batch_id)
    }

    pub fn len(&self) -> usize {
        self.claimed_batch_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claimed_batch_ids.is_empty()
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != BATCH_SCHEMA_VERSION
            || self.claimed_batch_ids.len() > MAX_SESSION_BATCH_CLAIMS
            || self
                .claimed_batch_ids
                .iter()
                .any(|id| !is_bounded_identifier(id.as_str()))
        {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionBrowserBatchState {
    Active,
    Completed,
    Cancelled,
    Takeover,
    Revoked,
    TimedOut,
    Failed,
    Uncertain,
    Unmounted,
}

impl MissionBrowserBatchState {
    fn is_terminal(self) -> bool {
        self != Self::Active
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionBrowserBatchTerminalReason {
    Completed,
    Cancelled,
    Takeover,
    LeaseLost,
    Revoked,
    TimedOut,
    HostRestarted,
    ProviderRejected,
    ConsumerRejected,
    ExternalInteractionUncertain,
    Unmounted,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBrowserBatchStepResult {
    pub schema_version: u32,
    pub batch_id: BrowserActionBatchId,
    pub action_sequence: u32,
    pub action_digest: String,
    pub observation_digest: String,
    pub host_receipt_digest: String,
    pub external_write_may_have_occurred: bool,
    pub business_verified: bool,
    pub result_digest: String,
}

impl MissionBrowserBatchStepResult {
    pub fn new(
        batch_id: BrowserActionBatchId,
        action: &BrowserAction,
        observation_digest: String,
        host_receipt_digest: String,
        external_write_may_have_occurred: bool,
    ) -> Result<Self, BrowserError> {
        action.validate()?;
        if !is_sha256(&observation_digest) || !is_sha256(&host_receipt_digest) {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        let mut result = Self {
            schema_version: BATCH_SCHEMA_VERSION,
            batch_id,
            action_sequence: action.sequence,
            action_digest: digest_json(action)?,
            observation_digest,
            host_receipt_digest,
            external_write_may_have_occurred,
            business_verified: false,
            result_digest: String::new(),
        };
        result.result_digest = result.unsigned_digest()?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != BATCH_SCHEMA_VERSION
            || !is_bounded_identifier(self.batch_id.as_str())
            || self.action_sequence == 0
            || !is_sha256(&self.action_digest)
            || !is_sha256(&self.observation_digest)
            || !is_sha256(&self.host_receipt_digest)
            || self.business_verified
            || self.result_digest != self.unsigned_digest()?
        {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        Ok(())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&(
            self.schema_version,
            &self.batch_id,
            self.action_sequence,
            &self.action_digest,
            &self.observation_digest,
            &self.host_receipt_digest,
            self.external_write_may_have_occurred,
            self.business_verified,
        ))
    }
}

impl fmt::Debug for MissionBrowserBatchStepResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrowserBatchStepResult")
            .field("schema_version", &self.schema_version)
            .field("batch_id", &self.batch_id)
            .field("action_sequence", &self.action_sequence)
            .field("action_digest", &self.action_digest)
            .field("observation_digest", &self.observation_digest)
            .field("host_receipt_digest", &self.host_receipt_digest)
            .field(
                "external_write_may_have_occurred",
                &self.external_write_may_have_occurred,
            )
            .field("business_verified", &self.business_verified)
            .field("result_digest", &self.result_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBrowserBatchReceipt {
    pub schema_version: u32,
    pub batch_id: BrowserActionBatchId,
    pub scope_digest: String,
    pub plan_digest: String,
    pub batch_digest: String,
    pub completed_action_count: u32,
    pub result_digests: Vec<String>,
    pub result_prefix_digest: String,
    pub last_observation_digest: Option<String>,
    pub state: MissionBrowserBatchState,
    pub terminal_reason: Option<MissionBrowserBatchTerminalReason>,
    pub requires_reconciliation: bool,
    pub external_write_may_have_occurred: bool,
    /// The attempted action that made the provider uncertain is never part of
    /// `result_digests`; it is retained only as a reconciliation fence.
    #[serde(default)]
    pub uncertain_action_sequence: Option<u32>,
    #[serde(default)]
    pub uncertain_action_digest: Option<String>,
    #[serde(default)]
    pub uncertain_result_digest: Option<String>,
    pub cursor_digest: String,
}

impl MissionBrowserBatchReceipt {
    fn validate_shape(&self, action_count: usize) -> Result<(), BrowserError> {
        let completed = usize::try_from(self.completed_action_count)
            .map_err(|_| BrowserError::CounterOverflow)?;
        if self.schema_version != BATCH_SCHEMA_VERSION
            || !is_bounded_identifier(self.batch_id.as_str())
            || !is_sha256(&self.scope_digest)
            || !is_sha256(&self.plan_digest)
            || !is_sha256(&self.batch_digest)
            || !is_sha256(&self.result_prefix_digest)
            || !is_sha256(&self.cursor_digest)
            || self.result_digests.len() != completed
            || completed > MAX_BATCH_ACTIONS
            || completed > action_count
            || self.result_digests.iter().any(|digest| !is_sha256(digest))
            || self
                .last_observation_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || (self.state == MissionBrowserBatchState::Active && self.terminal_reason.is_some())
            || (self.state != MissionBrowserBatchState::Active && self.terminal_reason.is_none())
            || (self.state == MissionBrowserBatchState::Completed && completed != action_count)
            || (self.state == MissionBrowserBatchState::Uncertain
                && !self.external_write_may_have_occurred)
            || (self.state != MissionBrowserBatchState::Uncertain
                && self.external_write_may_have_occurred)
            || (self.state == MissionBrowserBatchState::Uncertain
                && (self.uncertain_action_sequence.is_none()
                    || self.uncertain_action_digest.is_none()))
            || (self.state != MissionBrowserBatchState::Uncertain
                && (self.uncertain_action_sequence.is_some()
                    || self.uncertain_action_digest.is_some()
                    || self.uncertain_result_digest.is_some()))
            || self
                .uncertain_action_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .uncertain_result_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        Ok(())
    }

    pub fn validate_for_plan(
        &self,
        plan: &MissionBrowserBatchPlan,
        scope: &MissionBrowserBatchScope,
    ) -> Result<(), BrowserError> {
        self.validate_shape(plan.action_count())?;
        if self.batch_id != plan.batch.id
            || self.plan_digest != plan.plan_digest
            || self.result_prefix_digest != result_prefix_digest(&self.result_digests)?
            || !scope.same_resume_scope(&plan.scope)
            || (self.state == MissionBrowserBatchState::Active
                && self.scope_digest != scope.scope_digest)
        {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        let cursor_scope_digest = if self.state == MissionBrowserBatchState::Takeover {
            &self.scope_digest
        } else {
            &scope.scope_digest
        };
        let cursor_digest = cursor_digest(
            &self.batch_id,
            &plan.plan_digest,
            cursor_scope_digest,
            self.completed_action_count,
            &self.result_prefix_digest,
            self.state,
            MissionBrowserBatchUncertainFence {
                action_sequence: self.uncertain_action_sequence,
                action_digest: self.uncertain_action_digest.as_deref(),
                result_digest: self.uncertain_result_digest.as_deref(),
            },
        )?;
        if self.cursor_digest != cursor_digest {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        if self.state == MissionBrowserBatchState::Uncertain {
            let sequence = self
                .uncertain_action_sequence
                .ok_or(BrowserError::InvalidBatchReceipt)?;
            let index = usize::try_from(sequence.saturating_sub(1))
                .map_err(|_| BrowserError::CounterOverflow)?;
            let action = plan
                .batch
                .actions
                .get(index)
                .ok_or(BrowserError::InvalidBatchReceipt)?;
            let action_digest = digest_json(action)?;
            if sequence
                != self
                    .completed_action_count
                    .checked_add(1)
                    .ok_or(BrowserError::CounterOverflow)?
                || self.uncertain_action_digest.as_deref() != Some(action_digest.as_str())
            {
                return Err(BrowserError::InvalidBatchReceipt);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for MissionBrowserBatchReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrowserBatchReceipt")
            .field("schema_version", &self.schema_version)
            .field("batch_id", &self.batch_id)
            .field("scope_digest", &self.scope_digest)
            .field("plan_digest", &self.plan_digest)
            .field("batch_digest", &self.batch_digest)
            .field("completed_action_count", &self.completed_action_count)
            .field("result_count", &self.result_digests.len())
            .field("result_prefix_digest", &self.result_prefix_digest)
            .field(
                "has_last_observation_digest",
                &self.last_observation_digest.is_some(),
            )
            .field("state", &self.state)
            .field("terminal_reason", &self.terminal_reason)
            .field("requires_reconciliation", &self.requires_reconciliation)
            .field(
                "external_write_may_have_occurred",
                &self.external_write_may_have_occurred,
            )
            .field("uncertain_action_sequence", &self.uncertain_action_sequence)
            .field(
                "has_uncertain_action_digest",
                &self.uncertain_action_digest.is_some(),
            )
            .field(
                "has_uncertain_result_digest",
                &self.uncertain_result_digest.is_some(),
            )
            .field("cursor_digest", &self.cursor_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct MissionBrowserBatchProviderResult {
    pub observation_digest: String,
    pub host_receipt_digest: String,
    pub external_write_may_have_occurred: bool,
}

impl MissionBrowserBatchProviderResult {
    pub fn read_only(
        observation_digest: String,
        host_receipt_digest: String,
    ) -> Result<Self, BrowserError> {
        if !is_sha256(&observation_digest) || !is_sha256(&host_receipt_digest) {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        Ok(Self {
            observation_digest,
            host_receipt_digest,
            external_write_may_have_occurred: false,
        })
    }

    pub fn uncertain(
        observation_digest: String,
        host_receipt_digest: String,
    ) -> Result<Self, BrowserError> {
        if !is_sha256(&observation_digest) || !is_sha256(&host_receipt_digest) {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        Ok(Self {
            observation_digest,
            host_receipt_digest,
            external_write_may_have_occurred: true,
        })
    }
}

#[derive(Debug)]
pub struct MissionBrowserBatchProviderFailure {
    pub error: BrowserError,
    pub requires_reconciliation: bool,
    pub external_write_may_have_occurred: bool,
}

impl MissionBrowserBatchProviderFailure {
    pub fn rejected(error: BrowserError) -> Self {
        Self {
            error,
            requires_reconciliation: false,
            external_write_may_have_occurred: false,
        }
    }

    pub fn reconciliation(error: BrowserError, external_write_may_have_occurred: bool) -> Self {
        Self {
            error,
            requires_reconciliation: true,
            external_write_may_have_occurred,
        }
    }

    pub fn uncertain(error: BrowserError) -> Self {
        Self {
            error,
            requires_reconciliation: true,
            external_write_may_have_occurred: true,
        }
    }
}

/// Provider boundary.  `prepare` is validation/mount only; it must not claim
/// a batch id or dispatch an action.  Every step is expected to revalidate the
/// live managed lease and frame scope.
pub trait MissionBrowserBatchProvider {
    fn prepare(
        &mut self,
        plan: &MissionBrowserBatchPlan,
        resume: Option<&MissionBrowserBatchReceipt>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError>;

    fn execute_step(
        &mut self,
        plan: &MissionBrowserBatchPlan,
        action: &BrowserAction,
        now: DateTime<Utc>,
    ) -> Result<MissionBrowserBatchProviderResult, MissionBrowserBatchProviderFailure>;

    fn unmount(&mut self);
}

/// Mission execution/result consumer.  Implementations should persist the
/// receipt before acknowledging it to a caller.  The adapter never interprets
/// a consumer acknowledgement as Provider/business verification.
pub trait MissionBrowserBatchConsumer {
    fn on_step(
        &mut self,
        result: &MissionBrowserBatchStepResult,
        receipt: &MissionBrowserBatchReceipt,
    ) -> Result<(), BrowserError>;

    fn on_terminal(&mut self, receipt: &MissionBrowserBatchReceipt) -> Result<(), BrowserError>;

    fn cleanup(&mut self);
}

impl MissionBrowserBatchConsumer for () {
    fn on_step(
        &mut self,
        _result: &MissionBrowserBatchStepResult,
        _receipt: &MissionBrowserBatchReceipt,
    ) -> Result<(), BrowserError> {
        Ok(())
    }

    fn on_terminal(&mut self, _receipt: &MissionBrowserBatchReceipt) -> Result<(), BrowserError> {
        Ok(())
    }

    fn cleanup(&mut self) {}
}

#[derive(Clone, Debug)]
pub struct MissionBrowserBatchStepOutcome {
    pub result: MissionBrowserBatchStepResult,
    pub receipt: MissionBrowserBatchReceipt,
}

#[derive(Clone, Debug)]
struct MissionBrowserBatchCursor {
    plan: MissionBrowserBatchPlan,
    result_digests: Vec<String>,
    last_observation_digest: Option<String>,
    state: MissionBrowserBatchState,
    terminal_reason: Option<MissionBrowserBatchTerminalReason>,
    requires_reconciliation: bool,
    external_write_may_have_occurred: bool,
    uncertain_action_sequence: Option<u32>,
    uncertain_action_digest: Option<String>,
    uncertain_result_digest: Option<String>,
}

impl MissionBrowserBatchCursor {
    fn new(plan: MissionBrowserBatchPlan) -> Self {
        Self {
            plan,
            result_digests: Vec::new(),
            last_observation_digest: None,
            state: MissionBrowserBatchState::Active,
            terminal_reason: None,
            requires_reconciliation: false,
            external_write_may_have_occurred: false,
            uncertain_action_sequence: None,
            uncertain_action_digest: None,
            uncertain_result_digest: None,
        }
    }

    fn from_receipt(
        plan: MissionBrowserBatchPlan,
        receipt: &MissionBrowserBatchReceipt,
    ) -> Result<Self, BrowserError> {
        receipt.validate_for_plan(&plan, &plan.scope)?;
        if !matches!(
            receipt.state,
            MissionBrowserBatchState::Active | MissionBrowserBatchState::Takeover
        ) {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        Ok(Self {
            plan,
            result_digests: receipt.result_digests.clone(),
            last_observation_digest: receipt.last_observation_digest.clone(),
            state: MissionBrowserBatchState::Active,
            terminal_reason: None,
            requires_reconciliation: false,
            external_write_may_have_occurred: false,
            uncertain_action_sequence: None,
            uncertain_action_digest: None,
            uncertain_result_digest: None,
        })
    }

    fn completed_action_count(&self) -> usize {
        self.result_digests.len()
    }

    fn next_action(&self) -> Result<Option<&BrowserAction>, BrowserError> {
        self.plan
            .batch
            .action_for_cursor(self.completed_action_count())
    }

    fn apply_result(
        &mut self,
        action: &BrowserAction,
        provider_result: MissionBrowserBatchProviderResult,
    ) -> Result<MissionBrowserBatchStepResult, BrowserError> {
        if self.state != MissionBrowserBatchState::Active {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        let expected_sequence = u32::try_from(self.completed_action_count())
            .map_err(|_| BrowserError::CounterOverflow)?
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        if action.sequence != expected_sequence {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        let result = MissionBrowserBatchStepResult::new(
            self.plan.batch.id.clone(),
            action,
            provider_result.observation_digest,
            provider_result.host_receipt_digest,
            provider_result.external_write_may_have_occurred,
        )?;
        if result.external_write_may_have_occurred
            != provider_result.external_write_may_have_occurred
        {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        self.last_observation_digest = Some(result.observation_digest.clone());
        if result.external_write_may_have_occurred {
            self.uncertain_action_sequence = Some(result.action_sequence);
            self.uncertain_action_digest = Some(result.action_digest.clone());
            self.uncertain_result_digest = Some(result.result_digest.clone());
            self.terminate(
                MissionBrowserBatchState::Uncertain,
                MissionBrowserBatchTerminalReason::ExternalInteractionUncertain,
                true,
                true,
            );
        } else {
            self.result_digests.push(result.result_digest.clone());
            if self.completed_action_count() == self.plan.action_count() {
                self.terminate(
                    MissionBrowserBatchState::Completed,
                    MissionBrowserBatchTerminalReason::Completed,
                    false,
                    false,
                );
            }
        }
        Ok(result)
    }

    fn mark_uncertain_action(
        &mut self,
        action: &BrowserAction,
        result_digest: Option<String>,
    ) -> Result<(), BrowserError> {
        self.uncertain_action_sequence = Some(action.sequence);
        self.uncertain_action_digest = Some(digest_json(action)?);
        self.uncertain_result_digest = result_digest;
        Ok(())
    }

    fn terminate(
        &mut self,
        state: MissionBrowserBatchState,
        reason: MissionBrowserBatchTerminalReason,
        requires_reconciliation: bool,
        external_write_may_have_occurred: bool,
    ) {
        self.state = state;
        self.terminal_reason = Some(reason);
        self.requires_reconciliation = requires_reconciliation;
        self.external_write_may_have_occurred = external_write_may_have_occurred;
    }

    fn receipt(&self) -> Result<MissionBrowserBatchReceipt, BrowserError> {
        let completed_action_count = u32::try_from(self.completed_action_count())
            .map_err(|_| BrowserError::CounterOverflow)?;
        let result_prefix_digest = result_prefix_digest(&self.result_digests)?;
        let cursor_digest = cursor_digest(
            &self.plan.batch.id,
            &self.plan.plan_digest,
            &self.plan.scope.scope_digest,
            completed_action_count,
            &result_prefix_digest,
            self.state,
            MissionBrowserBatchUncertainFence {
                action_sequence: self.uncertain_action_sequence,
                action_digest: self.uncertain_action_digest.as_deref(),
                result_digest: self.uncertain_result_digest.as_deref(),
            },
        )?;
        let receipt = MissionBrowserBatchReceipt {
            schema_version: BATCH_SCHEMA_VERSION,
            batch_id: self.plan.batch.id.clone(),
            scope_digest: self.plan.scope.scope_digest.clone(),
            plan_digest: self.plan.plan_digest.clone(),
            batch_digest: self.plan.batch_digest.clone(),
            completed_action_count,
            result_digests: self.result_digests.clone(),
            result_prefix_digest,
            last_observation_digest: self.last_observation_digest.clone(),
            state: self.state,
            terminal_reason: self.terminal_reason,
            requires_reconciliation: self.requires_reconciliation,
            external_write_may_have_occurred: self.external_write_may_have_occurred,
            uncertain_action_sequence: self.uncertain_action_sequence,
            uncertain_action_digest: self.uncertain_action_digest.clone(),
            uncertain_result_digest: self.uncertain_result_digest.clone(),
            cursor_digest,
        };
        receipt.validate_shape(self.plan.action_count())?;
        Ok(receipt)
    }
}

/// Owns one bounded provider lease and one exact result prefix.
pub struct MissionBrowserBatchService<
    P: MissionBrowserBatchProvider,
    C: MissionBrowserBatchConsumer,
> {
    plan: MissionBrowserBatchPlan,
    cursor: MissionBrowserBatchCursor,
    provider: P,
    consumer: C,
    terminal_notified: bool,
    cleaned_up: bool,
}

impl<P, C> fmt::Debug for MissionBrowserBatchService<P, C>
where
    P: MissionBrowserBatchProvider,
    C: MissionBrowserBatchConsumer,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrowserBatchService")
            .field("batch_id", &self.plan.batch.id)
            .field("scope_digest", &self.plan.scope.scope_digest)
            .field("plan_digest", &self.plan.plan_digest)
            .field(
                "completed_action_count",
                &self.cursor.completed_action_count(),
            )
            .field("state", &self.cursor.state)
            .field("terminal_notified", &self.terminal_notified)
            .field("cleaned_up", &self.cleaned_up)
            .finish_non_exhaustive()
    }
}

impl<P, C> MissionBrowserBatchService<P, C>
where
    P: MissionBrowserBatchProvider,
    C: MissionBrowserBatchConsumer,
{
    pub fn begin(
        claims: &mut MissionBrowserBatchClaimSet,
        plan: MissionBrowserBatchPlan,
        mut provider: P,
        consumer: C,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        claims.validate()?;
        if claims.contains(&plan.batch.id) {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        plan.validate_contract_at(now)?;
        if let Err(error) = provider.prepare(&plan, None, now) {
            provider.unmount();
            return Err(error);
        }
        // The claim is the final mutation after every plan/provider check.
        if let Err(error) = claims.try_claim(plan.batch.id.clone()) {
            provider.unmount();
            return Err(error);
        }
        Ok(Self {
            cursor: MissionBrowserBatchCursor::new(plan.clone()),
            plan,
            provider,
            consumer,
            terminal_notified: false,
            cleaned_up: false,
        })
    }

    pub fn resume(
        claims: &MissionBrowserBatchClaimSet,
        plan: MissionBrowserBatchPlan,
        receipt: &MissionBrowserBatchReceipt,
        mut provider: P,
        consumer: C,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        claims.validate()?;
        if !claims.contains(&plan.batch.id) {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        plan.validate_contract_at(now)?;
        receipt.validate_for_plan(&plan, &plan.scope)?;
        if let Err(error) = provider.prepare(&plan, Some(receipt), now) {
            provider.unmount();
            return Err(error);
        }
        let cursor = MissionBrowserBatchCursor::from_receipt(plan.clone(), receipt)?;
        Ok(Self {
            plan,
            cursor,
            provider,
            consumer,
            terminal_notified: false,
            cleaned_up: false,
        })
    }

    pub fn plan(&self) -> &MissionBrowserBatchPlan {
        &self.plan
    }

    pub fn receipt(&self) -> Result<MissionBrowserBatchReceipt, BrowserError> {
        self.cursor.receipt()
    }

    pub fn is_terminal(&self) -> bool {
        self.cursor.state.is_terminal()
    }

    fn provider_rejection<T>(&mut self, error: BrowserError) -> Result<T, BrowserError> {
        self.terminate(
            MissionBrowserBatchState::Failed,
            MissionBrowserBatchTerminalReason::ProviderRejected,
            false,
            false,
        )?;
        Err(error)
    }

    fn provider_failure(
        &mut self,
        action: &BrowserAction,
        failure: MissionBrowserBatchProviderFailure,
    ) -> Result<MissionBrowserBatchProviderResult, BrowserError> {
        let (state, reason) = failure_terminal(&failure);
        let MissionBrowserBatchProviderFailure {
            error,
            requires_reconciliation,
            external_write_may_have_occurred,
        } = failure;
        if external_write_may_have_occurred
            && let Err(digest_error) = self.cursor.mark_uncertain_action(action, None)
        {
            self.cursor.terminate(
                MissionBrowserBatchState::Failed,
                MissionBrowserBatchTerminalReason::ProviderRejected,
                false,
                false,
            );
            let _ = self.notify_terminal();
            return Err(digest_error);
        }
        self.terminate(
            state,
            reason,
            requires_reconciliation,
            external_write_may_have_occurred,
        )?;
        Err(error)
    }

    fn consumer_failure<T>(&mut self, error: BrowserError) -> Result<T, BrowserError> {
        self.cursor.terminate(
            MissionBrowserBatchState::Failed,
            MissionBrowserBatchTerminalReason::ConsumerRejected,
            false,
            false,
        );
        let _ = self.notify_terminal();
        Err(error)
    }

    pub fn execute_next(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<MissionBrowserBatchStepOutcome, BrowserError> {
        if self.cursor.state != MissionBrowserBatchState::Active {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        if now >= self.plan.batch.expires_at {
            self.terminate(
                MissionBrowserBatchState::TimedOut,
                MissionBrowserBatchTerminalReason::TimedOut,
                false,
                false,
            )?;
            return Err(BrowserError::InvalidBatch);
        }
        let action = match self.cursor.next_action() {
            Ok(Some(action)) => action.clone(),
            Ok(None) => self.provider_rejection(BrowserError::InvalidBatchReceipt)?,
            Err(error) => self.provider_rejection(error)?,
        };
        let provider_result = self
            .provider
            .execute_step(&self.plan, &action, now)
            .or_else(|failure| self.provider_failure(&action, failure))?;
        let result = match self.cursor.apply_result(&action, provider_result) {
            Ok(result) => result,
            Err(error) => self.provider_rejection(error)?,
        };
        let receipt = self
            .cursor
            .receipt()
            .or_else(|error| self.provider_rejection(error))?;
        if let Err(error) = self.consumer.on_step(&result, &receipt) {
            return self.consumer_failure(error);
        }
        if self.cursor.state.is_terminal() {
            self.notify_terminal()?;
        }
        Ok(MissionBrowserBatchStepOutcome { result, receipt })
    }

    pub fn cancel(&mut self) -> Result<MissionBrowserBatchReceipt, BrowserError> {
        self.terminate(
            MissionBrowserBatchState::Cancelled,
            MissionBrowserBatchTerminalReason::Cancelled,
            false,
            false,
        )?;
        self.receipt()
    }

    pub fn takeover(&mut self) -> Result<MissionBrowserBatchReceipt, BrowserError> {
        self.terminate(
            MissionBrowserBatchState::Takeover,
            MissionBrowserBatchTerminalReason::Takeover,
            false,
            false,
        )?;
        self.receipt()
    }

    pub fn revoke(&mut self) -> Result<MissionBrowserBatchReceipt, BrowserError> {
        self.terminate(
            MissionBrowserBatchState::Revoked,
            MissionBrowserBatchTerminalReason::Revoked,
            true,
            false,
        )?;
        self.receipt()
    }

    pub fn unmount(&mut self) -> Result<MissionBrowserBatchReceipt, BrowserError> {
        if !self.cursor.state.is_terminal() {
            self.terminate(
                MissionBrowserBatchState::Unmounted,
                MissionBrowserBatchTerminalReason::Unmounted,
                true,
                false,
            )?;
        }
        self.provider.unmount();
        self.cleaned_up = true;
        self.receipt()
    }

    fn terminate(
        &mut self,
        state: MissionBrowserBatchState,
        reason: MissionBrowserBatchTerminalReason,
        requires_reconciliation: bool,
        external_write_may_have_occurred: bool,
    ) -> Result<(), BrowserError> {
        if self.cursor.state.is_terminal() {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        self.cursor.terminate(
            state,
            reason,
            requires_reconciliation,
            external_write_may_have_occurred,
        );
        self.notify_terminal()
    }

    fn notify_terminal(&mut self) -> Result<(), BrowserError> {
        if self.terminal_notified {
            return Ok(());
        }
        let receipt = self.cursor.receipt()?;
        self.consumer.on_terminal(&receipt)?;
        self.terminal_notified = true;
        Ok(())
    }
}

impl<P, C> Drop for MissionBrowserBatchService<P, C>
where
    P: MissionBrowserBatchProvider,
    C: MissionBrowserBatchConsumer,
{
    fn drop(&mut self) {
        if !self.cleaned_up {
            self.provider.unmount();
            self.consumer.cleanup();
            self.cleaned_up = true;
        }
    }
}

fn failure_terminal(
    failure: &MissionBrowserBatchProviderFailure,
) -> (MissionBrowserBatchState, MissionBrowserBatchTerminalReason) {
    if failure.external_write_may_have_occurred {
        return (
            MissionBrowserBatchState::Uncertain,
            MissionBrowserBatchTerminalReason::ExternalInteractionUncertain,
        );
    }
    if matches!(
        &failure.error,
        BrowserError::HostRestarted | BrowserError::HostExited
    ) {
        return (
            MissionBrowserBatchState::Failed,
            MissionBrowserBatchTerminalReason::HostRestarted,
        );
    }
    if matches!(&failure.error, BrowserError::ControlLeaseLost) {
        return (
            MissionBrowserBatchState::Revoked,
            MissionBrowserBatchTerminalReason::LeaseLost,
        );
    }
    (
        MissionBrowserBatchState::Failed,
        MissionBrowserBatchTerminalReason::ProviderRejected,
    )
}

fn result_prefix_digest(result_digests: &[String]) -> Result<String, BrowserError> {
    if result_digests.len() > MAX_BATCH_ACTIONS
        || result_digests.iter().any(|digest| !is_sha256(digest))
    {
        return Err(BrowserError::InvalidBatchReceipt);
    }
    digest_json(&(BATCH_SCHEMA_VERSION, SERVICE_ID, result_digests))
}

#[derive(Clone, Copy)]
struct MissionBrowserBatchUncertainFence<'a> {
    action_sequence: Option<u32>,
    action_digest: Option<&'a str>,
    result_digest: Option<&'a str>,
}

fn cursor_digest(
    batch_id: &BrowserActionBatchId,
    plan_digest: &str,
    scope_digest: &str,
    completed_action_count: u32,
    result_prefix_digest: &str,
    state: MissionBrowserBatchState,
    uncertain: MissionBrowserBatchUncertainFence<'_>,
) -> Result<String, BrowserError> {
    if !is_bounded_identifier(batch_id.as_str())
        || !is_sha256(plan_digest)
        || !is_sha256(scope_digest)
        || !is_sha256(result_prefix_digest)
        || uncertain
            .action_digest
            .is_some_and(|digest| !is_sha256(digest))
        || uncertain
            .result_digest
            .is_some_and(|digest| !is_sha256(digest))
    {
        return Err(BrowserError::InvalidBatchReceipt);
    }
    digest_json(&(
        BATCH_SCHEMA_VERSION,
        SERVICE_ID,
        batch_id,
        plan_digest,
        scope_digest,
        completed_action_count,
        result_prefix_digest,
        state,
        uncertain.action_sequence,
        uncertain.action_digest,
        uncertain.result_digest,
    ))
}

/// Managed Chromium adapter for the first layer.  It intentionally executes
/// only read-only Observe/Verify steps; typed interaction steps remain present
/// in the plan but fail closed until their existing Effect-bound executors are
/// explicitly wired by a later Mission consumer.
#[cfg(unix)]
pub struct ManagedChromiumBatchProvider<'a> {
    host: &'a mut ManagedChromiumHost,
    profile: BrowserProfile,
    workspace: BrowserWorkspace,
    unmounted: bool,
}

#[cfg(unix)]
impl fmt::Debug for ManagedChromiumBatchProvider<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedChromiumBatchProvider")
            .field("profile_id", &self.profile.id)
            .field("workspace_id", &self.workspace.id)
            .field("unmounted", &self.unmounted)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl<'a> ManagedChromiumBatchProvider<'a> {
    pub fn new(
        host: &'a mut ManagedChromiumHost,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
    ) -> Result<Self, BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        Ok(Self {
            host,
            profile,
            workspace,
            unmounted: false,
        })
    }
}

#[cfg(unix)]
impl MissionBrowserBatchProvider for ManagedChromiumBatchProvider<'_> {
    fn prepare(
        &mut self,
        plan: &MissionBrowserBatchPlan,
        _resume: Option<&MissionBrowserBatchReceipt>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.unmounted {
            return Err(BrowserError::WorkspaceNotRegistered);
        }
        plan.validate(&self.profile, &self.workspace, now)
    }

    fn execute_step(
        &mut self,
        plan: &MissionBrowserBatchPlan,
        action: &BrowserAction,
        now: DateTime<Utc>,
    ) -> Result<MissionBrowserBatchProviderResult, MissionBrowserBatchProviderFailure> {
        if self.unmounted {
            return Err(MissionBrowserBatchProviderFailure::rejected(
                BrowserError::WorkspaceNotRegistered,
            ));
        }
        let snapshot_id = action.snapshot_id.clone().unwrap_or_else(|| {
            BrowserSnapshotId::from_stable(format!(
                "mission-batch-{}-{}",
                plan.batch.id, action.sequence
            ))
        });
        let snapshot = match action.kind {
            BrowserActionKind::Observe | BrowserActionKind::Verify => self
                .host
                .observe_ax(&action.tab_id, &plan.batch.lease, snapshot_id, now)
                .map_err(|error| {
                    if matches!(
                        error,
                        BrowserError::HostExited
                            | BrowserError::HostRestarted
                            | BrowserError::ControlLeaseLost
                    ) {
                        MissionBrowserBatchProviderFailure::reconciliation(error, false)
                    } else {
                        MissionBrowserBatchProviderFailure::rejected(error)
                    }
                })?,
            _ => {
                return Err(MissionBrowserBatchProviderFailure::rejected(
                    BrowserError::RealActionRejected,
                ));
            }
        };
        let observation_digest = snapshot
            .digest()
            .map_err(MissionBrowserBatchProviderFailure::rejected)?;
        let action_digest =
            digest_json(action).map_err(MissionBrowserBatchProviderFailure::rejected)?;
        let host_receipt_digest = digest_json(&(
            SERVICE_ID,
            "managed_chromium",
            &plan.batch.id,
            action.sequence,
            &action_digest,
            &observation_digest,
        ))
        .map_err(MissionBrowserBatchProviderFailure::rejected)?;
        MissionBrowserBatchProviderResult::read_only(observation_digest, host_receipt_digest)
            .map_err(MissionBrowserBatchProviderFailure::rejected)
    }

    fn unmount(&mut self) {
        self.unmounted = true;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, Mission, MissionContract, Project,
        StorageMode,
    };

    use super::*;
    use crate::{BrowserActionRisk, BrowserActionSurface, BrowserIdentity};

    const NOW_YEAR: i32 = 2026;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(NOW_YEAR, 8, 14, 9, 0, 0)
            .single()
            .expect("valid time")
    }

    fn sha(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn fixture() -> (BrowserProfile, BrowserWorkspace, MissionBrowserBatchScope) {
        let now = now();
        let project = Project::create_local(
            TenantId::from("tenant-batch"),
            ProjectId::from("project-batch"),
            "Batch fixture",
            "",
            "/workspace/batch",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-batch"),
            project.id.clone(),
            "Batch mission",
            MissionContract::bootstrap("Read market evidence", ["research.discover".into()], now),
            now,
        )
        .expect("mission");
        let identity = BrowserIdentity::new(
            "fixture-provider",
            AccountId::from("account-batch"),
            sha('1'),
            sha('2'),
            now,
        )
        .expect("identity");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-batch"),
            &project,
            "keychain://browser/batch",
            identity,
            now,
        )
        .expect("profile");
        let tab_id = BrowserTabId::from("tab-batch");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-batch"),
            &project,
            &mission,
            &profile,
            tab_id.clone(),
            BrowserControlLeaseId::from("lease-batch"),
            now + Duration::hours(1),
            sha('3'),
            now,
        )
        .expect("workspace");
        let scope = MissionBrowserBatchScope::bind(
            &profile,
            &workspace,
            workspace.agent_lease_proof(now).expect("lease"),
            MissionBrowserFrameScope {
                tab_id,
                frame_id_digest: sha('4'),
                loader_id_digest: sha('5'),
                url_digest: sha('6'),
                origin_digest: sha('7'),
                document_generation: 1,
            },
            sha('8'),
            now,
        )
        .expect("scope");
        (profile, workspace, scope)
    }

    fn action(sequence: u32, tab_id: &BrowserTabId, risk: BrowserActionRisk) -> BrowserAction {
        BrowserAction {
            sequence,
            kind: BrowserActionKind::Observe,
            surface: BrowserActionSurface::Semantic,
            risk,
            tab_id: tab_id.clone(),
            snapshot_id: None,
            element_ref: None,
            target_origin_digest: sha('7'),
            payload_digest: sha(char::from_u32(96 + sequence).expect("digest char")),
        }
    }

    fn plan(action_count: u32) -> (BrowserProfile, BrowserWorkspace, MissionBrowserBatchPlan) {
        let (profile, workspace, scope) = fixture();
        let actions = (1..=action_count)
            .map(|sequence| action(sequence, &scope.frame.tab_id, BrowserActionRisk::ReadOnly))
            .collect::<Vec<_>>();
        let batch = BrowserActionBatch::read_only(
            BrowserActionBatchId::from("batch-plugin"),
            &profile,
            &workspace,
            workspace.agent_lease_proof(now()).expect("lease"),
            scope.policy_digest.clone(),
            actions,
            now(),
            now() + Duration::minutes(5),
        )
        .expect("batch");
        let plan =
            MissionBrowserBatchPlan::new(batch, scope, &profile, &workspace, now()).expect("plan");
        (profile, workspace, plan)
    }

    #[derive(Default)]
    struct Provider {
        calls: Vec<u32>,
        fail_at: Option<FailureMode>,
        uncertain_result: bool,
        unmounted: bool,
    }

    enum FailureMode {
        LeaseLost,
        HostRestarted,
        Uncertain,
    }

    impl MissionBrowserBatchProvider for Provider {
        fn prepare(
            &mut self,
            _plan: &MissionBrowserBatchPlan,
            _resume: Option<&MissionBrowserBatchReceipt>,
            _now: DateTime<Utc>,
        ) -> Result<(), BrowserError> {
            Ok(())
        }

        fn execute_step(
            &mut self,
            plan: &MissionBrowserBatchPlan,
            action: &BrowserAction,
            _now: DateTime<Utc>,
        ) -> Result<MissionBrowserBatchProviderResult, MissionBrowserBatchProviderFailure> {
            self.calls.push(action.sequence);
            if let Some(failure) = self.fail_at.take() {
                return Err(match failure {
                    FailureMode::LeaseLost => MissionBrowserBatchProviderFailure::reconciliation(
                        BrowserError::ControlLeaseLost,
                        false,
                    ),
                    FailureMode::HostRestarted => {
                        MissionBrowserBatchProviderFailure::reconciliation(
                            BrowserError::HostRestarted,
                            false,
                        )
                    }
                    FailureMode::Uncertain => {
                        MissionBrowserBatchProviderFailure::uncertain(BrowserError::HostExited)
                    }
                });
            }
            let action_digest = digest_json(action).expect("action digest");
            let observation_digest = digest_json(&(
                "fake-observation",
                &plan.scope.scope_digest,
                action.sequence,
                &action_digest,
            ))
            .expect("observation digest");
            let host_receipt_digest = digest_json(&(
                "fake-receipt",
                &plan.batch.id,
                action.sequence,
                &observation_digest,
            ))
            .expect("receipt digest");
            if self.uncertain_result {
                return MissionBrowserBatchProviderResult::uncertain(
                    observation_digest,
                    host_receipt_digest,
                )
                .map_err(MissionBrowserBatchProviderFailure::rejected);
            }
            MissionBrowserBatchProviderResult::read_only(observation_digest, host_receipt_digest)
                .map_err(MissionBrowserBatchProviderFailure::rejected)
        }

        fn unmount(&mut self) {
            self.unmounted = true;
        }
    }

    #[derive(Default)]
    struct Consumer {
        sequences: Vec<u32>,
        terminal: Option<MissionBrowserBatchState>,
        cleanup_count: Cell<u32>,
    }

    impl MissionBrowserBatchConsumer for Consumer {
        fn on_step(
            &mut self,
            result: &MissionBrowserBatchStepResult,
            _receipt: &MissionBrowserBatchReceipt,
        ) -> Result<(), BrowserError> {
            self.sequences.push(result.action_sequence);
            Ok(())
        }

        fn on_terminal(
            &mut self,
            receipt: &MissionBrowserBatchReceipt,
        ) -> Result<(), BrowserError> {
            self.terminal = Some(receipt.state);
            Ok(())
        }

        fn cleanup(&mut self) {
            self.cleanup_count.set(self.cleanup_count.get() + 1);
        }
    }

    #[test]
    fn begin_claims_only_after_validation_and_rejects_duplicate_without_plan_leak() {
        let (_profile, _workspace, batch_plan) = plan(1);
        let mut claims = MissionBrowserBatchClaimSet::new();
        let mut service = MissionBrowserBatchService::begin(
            &mut claims,
            batch_plan,
            Provider::default(),
            Consumer::default(),
            now(),
        )
        .expect("begin");
        assert_eq!(claims.len(), 1);
        assert!(service.cancel().is_ok());
        let different = {
            let (_profile, _workspace, mut different) = plan(1);
            different.batch.id = BrowserActionBatchId::from("batch-plugin");
            different.batch.policy_digest = sha('9');
            different
        };
        assert_eq!(
            MissionBrowserBatchService::begin(
                &mut claims,
                different,
                Provider::default(),
                Consumer::default(),
                now(),
            )
            .expect_err("duplicate id must fail closed")
            .code(),
            "BROWSER_INVALID_BATCH_RECEIPT"
        );
    }

    #[test]
    fn bounded_claims_never_evict_and_full_set_fails_closed() {
        let mut claims = MissionBrowserBatchClaimSet::new();
        assert!(claims.try_claim(BrowserActionBatchId::from(" ")).is_err());
        assert!(claims.is_empty());
        for index in 0..MAX_SESSION_BATCH_CLAIMS {
            claims
                .try_claim(BrowserActionBatchId::from_stable(format!("batch-{index}")))
                .expect("claim within bound");
        }
        assert_eq!(claims.len(), MAX_SESSION_BATCH_CLAIMS);
        assert!(
            claims
                .try_claim(BrowserActionBatchId::from("batch-overflow"))
                .is_err()
        );
        assert!(claims.contains(&BrowserActionBatchId::from("batch-0")));
    }

    #[test]
    fn execute_records_each_prefix_and_terminal_completion_without_replay() {
        let (_, _, batch_plan) = plan(3);
        let mut claims = MissionBrowserBatchClaimSet::new();
        let mut service = MissionBrowserBatchService::begin(
            &mut claims,
            batch_plan,
            Provider::default(),
            Consumer::default(),
            now(),
        )
        .expect("begin");
        for expected in 1..=3 {
            let outcome = service.execute_next(now()).expect("step");
            assert_eq!(outcome.result.action_sequence, expected);
            assert_eq!(outcome.receipt.completed_action_count, expected);
        }
        let receipt = service.receipt().expect("receipt");
        assert_eq!(receipt.state, MissionBrowserBatchState::Completed);
        assert_eq!(receipt.result_digests.len(), 3);
        assert!(service.execute_next(now()).is_err());
    }

    #[test]
    fn cancellation_and_takeover_stop_suffix_and_takeover_can_resume_exact_prefix() {
        let (_, _, batch_plan) = plan(3);
        let mut claims = MissionBrowserBatchClaimSet::new();
        let mut service = MissionBrowserBatchService::begin(
            &mut claims,
            batch_plan.clone(),
            Provider::default(),
            Consumer::default(),
            now(),
        )
        .expect("begin");
        service.execute_next(now()).expect("first");
        let takeover_receipt = service.takeover().expect("takeover");
        assert_eq!(takeover_receipt.completed_action_count, 1);
        assert!(service.execute_next(now()).is_err());

        let (_, _, resumed_plan) = plan(3);
        let mut resumed = MissionBrowserBatchService::resume(
            &claims,
            resumed_plan,
            &takeover_receipt,
            Provider::default(),
            Consumer::default(),
            now(),
        )
        .expect("explicit resume");
        resumed.execute_next(now()).expect("suffix first");
        resumed.execute_next(now()).expect("suffix second");
        assert_eq!(
            resumed.receipt().expect("receipt").state,
            MissionBrowserBatchState::Completed
        );
    }

    #[test]
    fn takeover_resume_accepts_only_a_new_lease_with_the_same_plan_and_prefix() {
        let (profile, workspace, batch_plan) = plan(2);
        let mut claims = MissionBrowserBatchClaimSet::new();
        let mut service = MissionBrowserBatchService::begin(
            &mut claims,
            batch_plan.clone(),
            Provider::default(),
            Consumer::default(),
            now(),
        )
        .expect("begin");
        service.execute_next(now()).expect("prefix");
        let takeover_receipt = service.takeover().expect("takeover");

        let takeover_at = now() + Duration::seconds(1);
        let mut resumed_workspace = workspace.clone();
        resumed_workspace
            .user_takeover(
                resumed_workspace.revision,
                resumed_workspace.lease_generation,
                BrowserControlLeaseId::from("lease-user-takeover"),
                sha('a'),
                takeover_at,
            )
            .expect("user takeover");
        let continue_at = takeover_at + Duration::seconds(1);
        resumed_workspace
            .continue_agent(
                resumed_workspace.revision,
                resumed_workspace.lease_generation,
                BrowserControlLeaseId::from("lease-resumed-agent"),
                continue_at + Duration::hours(1),
                sha('b'),
                continue_at,
            )
            .expect("agent takeover");
        let resumed_scope = MissionBrowserBatchScope::bind(
            &profile,
            &resumed_workspace,
            resumed_workspace
                .agent_lease_proof(continue_at)
                .expect("new lease"),
            batch_plan.scope.frame.clone(),
            batch_plan.scope.policy_digest.clone(),
            continue_at,
        )
        .expect("new scope");
        let resumed_batch = BrowserActionBatch::read_only(
            batch_plan.batch.id.clone(),
            &profile,
            &resumed_workspace,
            resumed_workspace
                .agent_lease_proof(continue_at)
                .expect("new lease"),
            resumed_scope.policy_digest.clone(),
            batch_plan.batch.actions.clone(),
            continue_at,
            continue_at + Duration::minutes(5),
        )
        .expect("new lease batch");
        let resumed_plan = MissionBrowserBatchPlan::new(
            resumed_batch,
            resumed_scope,
            &profile,
            &resumed_workspace,
            continue_at,
        )
        .expect("new lease plan");
        let mut resumed = MissionBrowserBatchService::resume(
            &claims,
            resumed_plan,
            &takeover_receipt,
            Provider::default(),
            Consumer::default(),
            continue_at,
        )
        .expect("resume after takeover");
        resumed.execute_next(continue_at).expect("suffix");
        assert_eq!(
            resumed.receipt().expect("receipt").state,
            MissionBrowserBatchState::Completed
        );
    }

    #[test]
    fn lease_loss_and_host_restart_are_terminal_without_claiming_business_write() {
        let (_, _, batch_plan) = plan(2);
        let mut claims = MissionBrowserBatchClaimSet::new();
        let provider = Provider {
            fail_at: Some(FailureMode::HostRestarted),
            ..Provider::default()
        };
        let mut service = MissionBrowserBatchService::begin(
            &mut claims,
            batch_plan,
            provider,
            Consumer::default(),
            now(),
        )
        .expect("begin");
        assert_eq!(
            service.execute_next(now()).expect_err("restart").code(),
            "BROWSER_HOST_RESTARTED"
        );
        let receipt = service.receipt().expect("receipt");
        assert_eq!(receipt.state, MissionBrowserBatchState::Failed);
        assert!(receipt.requires_reconciliation);
        assert!(!receipt.external_write_may_have_occurred);
        assert!(service.execute_next(now()).is_err());
    }

    #[test]
    fn lease_loss_revokes_batch_and_blocks_suffix() {
        let (_, _, batch_plan) = plan(2);
        let mut claims = MissionBrowserBatchClaimSet::new();
        let mut service = MissionBrowserBatchService::begin(
            &mut claims,
            batch_plan,
            Provider {
                fail_at: Some(FailureMode::LeaseLost),
                ..Provider::default()
            },
            Consumer::default(),
            now(),
        )
        .expect("begin");
        assert_eq!(
            service.execute_next(now()).expect_err("lease loss").code(),
            "BROWSER_CONTROL_LEASE_LOST"
        );
        let receipt = service.receipt().expect("receipt");
        assert_eq!(receipt.state, MissionBrowserBatchState::Revoked);
        assert!(receipt.requires_reconciliation);
        assert!(!receipt.external_write_may_have_occurred);
        assert!(service.execute_next(now()).is_err());
    }

    #[test]
    fn uncertain_external_interaction_is_not_replayable() {
        let (_, _, batch_plan) = plan(2);
        let mut claims = MissionBrowserBatchClaimSet::new();
        let mut service = MissionBrowserBatchService::begin(
            &mut claims,
            batch_plan.clone(),
            Provider {
                fail_at: Some(FailureMode::Uncertain),
                ..Provider::default()
            },
            Consumer::default(),
            now(),
        )
        .expect("begin");
        assert_eq!(
            service.execute_next(now()).expect_err("uncertain").code(),
            "BROWSER_HOST_EXITED"
        );
        let receipt = service.receipt().expect("receipt");
        assert_eq!(receipt.state, MissionBrowserBatchState::Uncertain);
        assert!(receipt.external_write_may_have_occurred);
        assert!(
            MissionBrowserBatchService::resume(
                &claims,
                batch_plan,
                &receipt,
                Provider::default(),
                Consumer::default(),
                now(),
            )
            .is_err()
        );
    }

    #[test]
    fn uncertain_result_does_not_extend_acknowledged_prefix() {
        let (_, _, batch_plan) = plan(2);
        let mut claims = MissionBrowserBatchClaimSet::new();
        let mut service = MissionBrowserBatchService::begin(
            &mut claims,
            batch_plan.clone(),
            Provider {
                uncertain_result: true,
                ..Provider::default()
            },
            Consumer::default(),
            now(),
        )
        .expect("begin");
        let outcome = service.execute_next(now()).expect("uncertain outcome");
        assert_eq!(outcome.receipt.state, MissionBrowserBatchState::Uncertain);
        assert_eq!(outcome.receipt.completed_action_count, 0);
        assert!(outcome.receipt.result_digests.is_empty());
        assert_eq!(outcome.receipt.uncertain_action_sequence, Some(1));
        assert!(service.execute_next(now()).is_err());
        assert!(
            MissionBrowserBatchService::resume(
                &claims,
                batch_plan,
                &outcome.receipt,
                Provider::default(),
                Consumer::default(),
                now(),
            )
            .is_err()
        );
    }

    #[test]
    fn drop_unmounts_provider_and_consumer_without_evicting_claim() {
        let (_, _, batch_plan) = plan(1);
        let mut claims = MissionBrowserBatchClaimSet::new();
        {
            let _service = MissionBrowserBatchService::begin(
                &mut claims,
                batch_plan,
                Provider::default(),
                Consumer::default(),
                now(),
            )
            .expect("begin");
        }
        assert_eq!(claims.len(), 1);
    }
}

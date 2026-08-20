use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BrowserActionBatchId, BrowserProfileId, BrowserRecipeId, BrowserWorkspaceId, EffectId,
};
use serde::{Deserialize, Serialize};

use crate::chromium_host::ChromiumClickDispatchEvidence;
use crate::workspace::{digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserActionBatch, BrowserError, BrowserProfile, BrowserRecipeExecutionAuthorization,
    BrowserRecipePreparedPlan, BrowserRecipeRegistry, BrowserRecipeTrustStore, BrowserWorkspace,
};

const RECIPE_RESUME_SCHEMA_VERSION: u32 = 1;
const RECIPE_RESUME_AUTHORITY_DOMAIN: &str = "hartevo-browser-recipe-resume-authority/v1";
const RECIPE_RESUME_STEP_DOMAIN: &str = "hartevo-browser-recipe-resume-step/v1";

/// Exact production inputs required to start, restore, or rebind one durable
/// signed-Recipe cursor. The root snapshot digest is supplied by the caller's
/// durable authority boundary; this type does not grant root lifecycle
/// admission or freshness authority.
#[derive(Clone, Copy)]
pub struct BrowserRecipeResumeContext<'a> {
    pub root_authority_snapshot_digest: &'a str,
    pub prepared_plan: &'a BrowserRecipePreparedPlan,
    pub registry: &'a BrowserRecipeRegistry,
    pub trust: &'a BrowserRecipeTrustStore,
    pub batch: &'a BrowserActionBatch,
    pub profile: &'a BrowserProfile,
    pub workspace: &'a BrowserWorkspace,
}

impl fmt::Debug for BrowserRecipeResumeContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRecipeResumeContext")
            .field("recipe_id", &self.prepared_plan.recipe_id)
            .field("recipe_version", &self.prepared_plan.recipe_version)
            .field("batch_id", &self.batch.id)
            .field("profile_id", &self.profile.id)
            .field("workspace_id", &self.workspace.id)
            .field(
                "root_authority_snapshot_digest",
                &self.root_authority_snapshot_digest,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserRecipeResumeStepBinding {
    sequence: u32,
    step_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserRecipeResumeExecutionBinding {
    generation: u64,
    batch_id: BrowserActionBatchId,
    effect_id: EffectId,
    batch_digest: String,
    prepared_plan_digest: String,
    bound_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserRecipeStepAcknowledgement {
    action_sequence: u32,
    step_digest: String,
    action_digest: String,
    execution_generation: u64,
    dispatch_evidence_digest: String,
    dispatch_evidence: ChromiumClickDispatchEvidence,
    acknowledged_at: DateTime<Utc>,
}

/// Caller-persisted, digest-addressed cursor for a signed multi-step Recipe.
///
/// A cursor can advance only after exact Chromium dispatch evidence is
/// acknowledged. Restoring requires both the serialized cursor and the
/// independently persisted cursor digest/revision, which makes a rolled-back
/// or edited snapshot fail before a host is borrowed. A restart may rebind
/// ephemeral locator resolutions, but never the rooted Recipe authority,
/// profile, workspace, release, activation, or logical step sequence.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserRecipeResumeCursor {
    schema_version: u32,
    recipe_id: BrowserRecipeId,
    recipe_version: u32,
    candidate_digest: String,
    release_digest: String,
    activation_digest: String,
    authority_digest: String,
    root_authority_snapshot_digest: String,
    profile_id: BrowserProfileId,
    profile_digest: String,
    identity_digest: String,
    workspace_id: BrowserWorkspaceId,
    workspace_digest: String,
    policy_digest: String,
    step_bindings: Vec<BrowserRecipeResumeStepBinding>,
    execution_bindings: Vec<BrowserRecipeResumeExecutionBinding>,
    acknowledgements: Vec<BrowserRecipeStepAcknowledgement>,
    next_action_index: usize,
    revision: u64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl BrowserRecipeResumeCursor {
    pub fn start(
        context: BrowserRecipeResumeContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let bindings = ResumeBindings::validate(context, now)?;
        let execution_binding = bindings.execution_binding(1, now);
        let cursor = Self {
            schema_version: RECIPE_RESUME_SCHEMA_VERSION,
            recipe_id: bindings.recipe_id,
            recipe_version: bindings.recipe_version,
            candidate_digest: bindings.candidate_digest,
            release_digest: bindings.release_digest,
            activation_digest: bindings.activation_digest,
            authority_digest: bindings.authority_digest,
            root_authority_snapshot_digest: bindings.root_authority_snapshot_digest,
            profile_id: bindings.profile_id,
            profile_digest: bindings.profile_digest,
            identity_digest: bindings.identity_digest,
            workspace_id: bindings.workspace_id,
            workspace_digest: bindings.workspace_digest,
            policy_digest: bindings.policy_digest,
            step_bindings: bindings.step_bindings,
            execution_bindings: vec![execution_binding],
            acknowledgements: Vec::new(),
            next_action_index: 0,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        cursor.validate_for(context, now)?;
        Ok(cursor)
    }

    pub fn restore_json(
        snapshot_json: &str,
        expected_cursor_digest: &str,
        expected_revision: u64,
        context: BrowserRecipeResumeContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        if !is_sha256(expected_cursor_digest) || expected_revision == 0 {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        let cursor = serde_json::from_str::<Self>(snapshot_json)
            .map_err(|_| BrowserError::RecipeScopeMismatch)?;
        if cursor.evidence_digest()? != expected_cursor_digest {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        if cursor.revision != expected_revision {
            return Err(BrowserError::RevisionMismatch {
                expected: expected_revision,
                actual: cursor.revision,
            });
        }
        cursor.validate_for(context, now)?;
        Ok(cursor)
    }

    pub fn rebind_after_restart(
        &mut self,
        context: BrowserRecipeResumeContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_structure(now)?;
        let bindings = ResumeBindings::validate(context, now)?;
        self.validate_immutable_bindings(&bindings)?;
        if self.acknowledgements.is_empty()
            || self.is_complete()
            || now < self.updated_at
            || self
                .execution_bindings
                .iter()
                .any(|binding| binding.batch_id == context.batch.id)
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        let generation = u64::try_from(self.execution_bindings.len())
            .map_err(|_| BrowserError::CounterOverflow)?
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        self.execution_bindings
            .push(bindings.execution_binding(generation, now));
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        self.updated_at = now;
        self.validate_for(context, now)
    }

    pub fn acknowledge_chromium_click(
        &mut self,
        context: BrowserRecipeResumeContext<'_>,
        evidence: ChromiumClickDispatchEvidence,
        acknowledged_at: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_for(context, acknowledged_at)?;
        let action = context
            .batch
            .actions
            .get(self.next_action_index)
            .ok_or(BrowserError::RecipeScopeMismatch)?;
        let step = self
            .step_bindings
            .get(self.next_action_index)
            .ok_or(BrowserError::RecipeScopeMismatch)?;
        let execution = self
            .execution_bindings
            .last()
            .ok_or(BrowserError::RecipeScopeMismatch)?;
        let effect_binding = context
            .batch
            .effect_binding
            .as_ref()
            .ok_or(BrowserError::EffectBrokerRequired)?;
        let action_digest = digest_json(action)?;
        let dispatch_evidence_digest = evidence.evidence_digest()?;
        if action.sequence != step.sequence
            || action_digest != evidence.action_digest
            || evidence.batch_id != execution.batch_id
            || evidence.effect_id != effect_binding.effect_id
            || evidence.workspace_id != self.workspace_id
            || evidence.tab_id != action.tab_id
            || action.snapshot_id.as_ref() != Some(&evidence.snapshot_id)
            || evidence.lease_generation != context.batch.lease.generation
            || evidence.locator_resolution_digest != action.payload_digest
            || evidence.origin_digest != action.target_origin_digest
            || evidence.policy_digest != self.policy_digest
            || evidence.dispatched_at < execution.bound_at
            || evidence.dispatched_at < self.updated_at
            || acknowledged_at < evidence.dispatched_at
            || acknowledged_at < self.updated_at
            || acknowledged_at >= context.batch.expires_at
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        self.acknowledgements
            .push(BrowserRecipeStepAcknowledgement {
                action_sequence: action.sequence,
                step_digest: step.step_digest.clone(),
                action_digest,
                execution_generation: execution.generation,
                dispatch_evidence_digest,
                dispatch_evidence: evidence,
                acknowledged_at,
            });
        self.next_action_index = self
            .next_action_index
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        self.updated_at = acknowledged_at;
        self.validate_for(context, acknowledged_at)
    }

    pub fn snapshot_json(&self) -> Result<String, BrowserError> {
        serde_json::to_string(self).map_err(|_| BrowserError::RecipeScopeMismatch)
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(self)
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn completed_action_count(&self) -> usize {
        self.next_action_index
    }

    pub fn next_action_sequence(&self) -> Option<u32> {
        self.step_bindings
            .get(self.next_action_index)
            .map(|step| step.sequence)
    }

    pub fn acknowledged_action_sequences(&self) -> Vec<u32> {
        self.acknowledgements
            .iter()
            .map(|acknowledgement| acknowledgement.action_sequence)
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.next_action_index == self.step_bindings.len()
    }

    pub fn authority_digest(&self) -> &str {
        &self.authority_digest
    }

    pub fn root_authority_snapshot_digest(&self) -> &str {
        &self.root_authority_snapshot_digest
    }

    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    pub fn release_digest(&self) -> &str {
        &self.release_digest
    }

    pub(crate) fn next_action_index(&self) -> usize {
        self.next_action_index
    }

    pub(crate) fn validate_for(
        &self,
        context: BrowserRecipeResumeContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_structure(now)?;
        let bindings = ResumeBindings::validate(context, now)?;
        self.validate_immutable_bindings(&bindings)?;
        let current = self
            .execution_bindings
            .last()
            .ok_or(BrowserError::RecipeScopeMismatch)?;
        if current.batch_id != context.batch.id
            || current.effect_id != bindings.effect_id
            || current.batch_digest != bindings.batch_digest
            || current.prepared_plan_digest != bindings.prepared_plan_digest
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        Ok(())
    }

    fn validate_immutable_bindings(&self, bindings: &ResumeBindings) -> Result<(), BrowserError> {
        if self.recipe_id != bindings.recipe_id
            || self.recipe_version != bindings.recipe_version
            || self.candidate_digest != bindings.candidate_digest
            || self.release_digest != bindings.release_digest
            || self.activation_digest != bindings.activation_digest
            || self.authority_digest != bindings.authority_digest
            || self.root_authority_snapshot_digest != bindings.root_authority_snapshot_digest
            || self.profile_id != bindings.profile_id
            || self.profile_digest != bindings.profile_digest
            || self.identity_digest != bindings.identity_digest
            || self.workspace_id != bindings.workspace_id
            || self.workspace_digest != bindings.workspace_digest
            || self.policy_digest != bindings.policy_digest
            || self.step_bindings != bindings.step_bindings
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        Ok(())
    }

    fn validate_structure(&self, now: DateTime<Utc>) -> Result<(), BrowserError> {
        let expected_revision = u64::try_from(
            1_usize
                .checked_add(self.acknowledgements.len())
                .and_then(|value| {
                    value.checked_add(self.execution_bindings.len().saturating_sub(1))
                })
                .ok_or(BrowserError::CounterOverflow)?,
        )
        .map_err(|_| BrowserError::CounterOverflow)?;
        if self.schema_version != RECIPE_RESUME_SCHEMA_VERSION
            || !is_bounded_identifier(self.recipe_id.as_str())
            || self.recipe_version == 0
            || !is_bounded_identifier(self.profile_id.as_str())
            || !is_bounded_identifier(self.workspace_id.as_str())
            || self.step_bindings.is_empty()
            || self.next_action_index != self.acknowledgements.len()
            || self.next_action_index > self.step_bindings.len()
            || self.revision != expected_revision
            || self.created_at > self.updated_at
            || self.updated_at > now
            || [
                &self.candidate_digest,
                &self.release_digest,
                &self.activation_digest,
                &self.authority_digest,
                &self.root_authority_snapshot_digest,
                &self.profile_digest,
                &self.identity_digest,
                &self.workspace_digest,
                &self.policy_digest,
            ]
            .into_iter()
            .any(|value| !is_sha256(value))
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        for (index, step) in self.step_bindings.iter().enumerate() {
            let sequence = u32::try_from(index)
                .map_err(|_| BrowserError::CounterOverflow)?
                .checked_add(1)
                .ok_or(BrowserError::CounterOverflow)?;
            if step.sequence != sequence || !is_sha256(&step.step_digest) {
                return Err(BrowserError::RecipeScopeMismatch);
            }
        }
        self.validate_execution_bindings()?;
        self.validate_acknowledgements()
    }

    fn validate_execution_bindings(&self) -> Result<(), BrowserError> {
        if self.execution_bindings.is_empty() {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        let mut batch_ids = BTreeSet::new();
        let mut previous_bound_at = None;
        for (index, binding) in self.execution_bindings.iter().enumerate() {
            let generation = u64::try_from(index)
                .map_err(|_| BrowserError::CounterOverflow)?
                .checked_add(1)
                .ok_or(BrowserError::CounterOverflow)?;
            if binding.generation != generation
                || !is_bounded_identifier(binding.batch_id.as_str())
                || !is_bounded_identifier(binding.effect_id.as_str())
                || !is_sha256(&binding.batch_digest)
                || !is_sha256(&binding.prepared_plan_digest)
                || !batch_ids.insert(binding.batch_id.clone())
                || binding.bound_at < self.created_at
                || binding.bound_at > self.updated_at
                || previous_bound_at.is_some_and(|previous| binding.bound_at < previous)
            {
                return Err(BrowserError::RecipeScopeMismatch);
            }
            previous_bound_at = Some(binding.bound_at);
        }
        Ok(())
    }

    fn validate_acknowledgements(&self) -> Result<(), BrowserError> {
        let mut previous_acknowledged_at = None;
        for (index, acknowledgement) in self.acknowledgements.iter().enumerate() {
            let step = self
                .step_bindings
                .get(index)
                .ok_or(BrowserError::RecipeScopeMismatch)?;
            let execution_index = usize::try_from(acknowledgement.execution_generation)
                .map_err(|_| BrowserError::CounterOverflow)?
                .checked_sub(1)
                .ok_or(BrowserError::RecipeScopeMismatch)?;
            let execution = self
                .execution_bindings
                .get(execution_index)
                .ok_or(BrowserError::RecipeScopeMismatch)?;
            if acknowledgement.action_sequence != step.sequence
                || acknowledgement.step_digest != step.step_digest
                || !is_sha256(&acknowledgement.action_digest)
                || acknowledgement.dispatch_evidence_digest
                    != acknowledgement.dispatch_evidence.evidence_digest()?
                || acknowledgement.dispatch_evidence.batch_id != execution.batch_id
                || acknowledgement.dispatch_evidence.effect_id != execution.effect_id
                || acknowledgement.dispatch_evidence.workspace_id != self.workspace_id
                || acknowledgement.dispatch_evidence.policy_digest != self.policy_digest
                || acknowledgement.dispatch_evidence.action_digest != acknowledgement.action_digest
                || acknowledgement.acknowledged_at < acknowledgement.dispatch_evidence.dispatched_at
                || acknowledgement.acknowledged_at > self.updated_at
                || previous_acknowledged_at
                    .is_some_and(|previous| acknowledgement.acknowledged_at < previous)
            {
                return Err(BrowserError::RecipeScopeMismatch);
            }
            previous_acknowledged_at = Some(acknowledgement.acknowledged_at);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserRecipeResumeCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRecipeResumeCursor")
            .field("schema_version", &self.schema_version)
            .field("recipe_id", &self.recipe_id)
            .field("recipe_version", &self.recipe_version)
            .field("release_digest", &self.release_digest)
            .field("authority_digest", &self.authority_digest)
            .field(
                "root_authority_snapshot_digest",
                &self.root_authority_snapshot_digest,
            )
            .field("profile_digest", &self.profile_digest)
            .field("workspace_digest", &self.workspace_digest)
            .field("execution_generation_count", &self.execution_bindings.len())
            .field("completed_action_count", &self.next_action_index)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

struct ResumeBindings {
    recipe_id: BrowserRecipeId,
    recipe_version: u32,
    candidate_digest: String,
    release_digest: String,
    activation_digest: String,
    authority_digest: String,
    root_authority_snapshot_digest: String,
    profile_id: BrowserProfileId,
    profile_digest: String,
    identity_digest: String,
    workspace_id: BrowserWorkspaceId,
    workspace_digest: String,
    policy_digest: String,
    step_bindings: Vec<BrowserRecipeResumeStepBinding>,
    batch_id: BrowserActionBatchId,
    effect_id: EffectId,
    batch_digest: String,
    prepared_plan_digest: String,
}

impl ResumeBindings {
    fn validate(
        context: BrowserRecipeResumeContext<'_>,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        if !is_sha256(context.root_authority_snapshot_digest) {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        let authorization = BrowserRecipeExecutionAuthorization::new(
            context.prepared_plan.clone(),
            context.registry,
            context.trust,
            context.batch,
            now,
        )?;
        authorization.validate_batch(context.batch, now)?;
        context.prepared_plan.validate_for(
            context.profile,
            context.workspace,
            &context.batch.actions,
            now,
        )?;
        context
            .batch
            .validate_for(context.profile, context.workspace, now)?;
        let release = context
            .registry
            .active_release(&context.prepared_plan.recipe_id)?;
        if release.candidate.manifest.version != context.prepared_plan.recipe_version
            || release.candidate.manifest.steps.len() != context.batch.actions.len()
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        let step_bindings = release
            .candidate
            .manifest
            .steps
            .iter()
            .map(|step| {
                Ok(BrowserRecipeResumeStepBinding {
                    sequence: step.sequence,
                    step_digest: digest_json(&(
                        RECIPE_RESUME_STEP_DOMAIN,
                        &context.prepared_plan.recipe_id,
                        context.prepared_plan.recipe_version,
                        step,
                    ))?,
                })
            })
            .collect::<Result<Vec<_>, BrowserError>>()?;
        let trust_digest = digest_json(&context.trust.snapshot())?;
        let authority_digest = digest_json(&(
            RECIPE_RESUME_AUTHORITY_DOMAIN,
            &context.prepared_plan.recipe_id,
            context.prepared_plan.recipe_version,
            &context.prepared_plan.candidate_digest,
            &context.prepared_plan.release_digest,
            &context.prepared_plan.activation_digest,
            &trust_digest,
        ))?;
        let effect_id = context
            .batch
            .effect_binding
            .as_ref()
            .ok_or(BrowserError::EffectBrokerRequired)?
            .effect_id
            .clone();
        Ok(Self {
            recipe_id: context.prepared_plan.recipe_id.clone(),
            recipe_version: context.prepared_plan.recipe_version,
            candidate_digest: context.prepared_plan.candidate_digest.clone(),
            release_digest: context.prepared_plan.release_digest.clone(),
            activation_digest: context.prepared_plan.activation_digest.clone(),
            authority_digest,
            root_authority_snapshot_digest: context.root_authority_snapshot_digest.to_owned(),
            profile_id: context.profile.id.clone(),
            profile_digest: context.profile.digest()?,
            identity_digest: context.profile.identity.identity_digest.clone(),
            workspace_id: context.workspace.id.clone(),
            workspace_digest: digest_json(context.workspace)?,
            policy_digest: context.prepared_plan.policy_digest.clone(),
            step_bindings,
            batch_id: context.batch.id.clone(),
            effect_id,
            batch_digest: context.batch.digest()?,
            prepared_plan_digest: digest_json(context.prepared_plan)?,
        })
    }

    fn execution_binding(
        &self,
        generation: u64,
        bound_at: DateTime<Utc>,
    ) -> BrowserRecipeResumeExecutionBinding {
        BrowserRecipeResumeExecutionBinding {
            generation,
            batch_id: self.batch_id.clone(),
            effect_id: self.effect_id.clone(),
            batch_digest: self.batch_digest.clone(),
            prepared_plan_digest: self.prepared_plan_digest.clone(),
            bound_at,
        }
    }
}

#[cfg(test)]
#[path = "real_chromium_recipe_crash_resume_test.rs"]
mod real_chromium_recipe_crash_resume_test;

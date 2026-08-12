use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    ApprovalDecision, BrowserActionBatchId, BrowserSnapshotId, BrowserTabId, BrowserWorkspaceId,
    Effect, EffectClass, EffectId, EffectStatus, MissionId, ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserError, BrowserLeaseProof, BrowserProfile, BrowserRecipePreparedPlan,
    BrowserRecipeRegistry, BrowserRecipeTrustStore, BrowserWorkspace,
};
use crate::{BrowserFileGrant, BrowserFileGrantState, BrowserLocatorResolution};

const ACTION_SCHEMA_VERSION: u32 = 1;
const MAX_BATCH_ACTIONS: usize = 64;
const MAX_BATCH_LIFETIME: Duration = Duration::minutes(15);
const MAX_ELEMENT_REFS: usize = 4_096;
const MAX_TEXT_INPUT_BYTES: usize = 32 * 1_024;
const TEXT_INPUT_SCHEMA_VERSION: u32 = 1;

/// Ephemeral text supplied to a managed browser input action. The cleartext is
/// intentionally neither serializable nor cloneable and is zeroized on drop.
/// Durable plans bind only the nested evidence digest.
pub struct BrowserTextInput {
    text: Zeroizing<String>,
    content_digest: String,
    byte_len: u32,
    utf16_len: u32,
}

impl BrowserTextInput {
    pub fn new(text: impl Into<String>) -> Result<Self, BrowserError> {
        let text = Zeroizing::new(text.into());
        if text.is_empty()
            || text.len() > MAX_TEXT_INPUT_BYTES
            || text
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err(BrowserError::InvalidTextInput);
        }
        let byte_len = u32::try_from(text.len()).map_err(|_| BrowserError::InvalidTextInput)?;
        let utf16_len = u32::try_from(text.encode_utf16().count())
            .map_err(|_| BrowserError::InvalidTextInput)?;
        Ok(Self {
            content_digest: digest(text.as_bytes()),
            text,
            byte_len,
            utf16_len,
        })
    }

    pub fn byte_len(&self) -> u32 {
        self.byte_len
    }

    pub fn utf16_len(&self) -> u32 {
        self.utf16_len
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(&(
            TEXT_INPUT_SCHEMA_VERSION,
            "hartevo-browser-text-input/v1",
            &self.content_digest,
            self.byte_len,
            self.utf16_len,
        ))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.text
    }

    pub(crate) fn content_digest(&self) -> &str {
        &self.content_digest
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if self.text.is_empty()
            || self.text.len() > MAX_TEXT_INPUT_BYTES
            || self.text.len() != self.byte_len as usize
            || self.text.encode_utf16().count() != self.utf16_len as usize
            || self
                .text
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
            || self.content_digest != digest(self.text.as_bytes())
        {
            return Err(BrowserError::InvalidTextInput);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserTextInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserTextInput")
            .field("redacted", &true)
            .field("byte_len", &self.byte_len)
            .field("utf16_len", &self.utf16_len)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserPromptRisk {
    None,
    SuspectedInjection,
    ConfirmedInjection,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserElementRef {
    pub reference: String,
    pub locator_digest: String,
    pub visible: bool,
    pub unique: bool,
}

impl fmt::Debug for BrowserElementRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserElementRef")
            .field("reference_digest", &digest(self.reference.as_bytes()))
            .field("locator_digest", &self.locator_digest)
            .field("visible", &self.visible)
            .field("unique", &self.unique)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticSnapshot {
    pub schema_version: u32,
    pub id: BrowserSnapshotId,
    pub workspace_id: BrowserWorkspaceId,
    pub tab_id: BrowserTabId,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub identity_digest: String,
    pub url_digest: String,
    pub content_digest: String,
    pub redaction_digest: String,
    pub prompt_risk: BrowserPromptRisk,
    pub element_refs: Vec<BrowserElementRef>,
    pub created_at: DateTime<Utc>,
}

impl SemanticSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: BrowserSnapshotId,
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
        document_generation: u64,
        identity_digest: String,
        url_digest: String,
        content_digest: String,
        redaction_digest: String,
        prompt_risk: BrowserPromptRisk,
        element_refs: Vec<BrowserElementRef>,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let snapshot = Self {
            schema_version: ACTION_SCHEMA_VERSION,
            id,
            workspace_id: workspace.id.clone(),
            tab_id,
            lease_generation: workspace.lease_generation,
            document_generation,
            identity_digest,
            url_digest,
            content_digest,
            redaction_digest,
            prompt_risk,
            element_refs,
            created_at: now,
        };
        snapshot.validate_for(workspace)?;
        Ok(snapshot)
    }

    pub fn validate_for(&self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        let mut refs = BTreeSet::new();
        if self.schema_version != ACTION_SCHEMA_VERSION
            || !is_bounded_identifier(self.id.as_str())
            || self.workspace_id != workspace.id
            || !workspace.tabs.contains(&self.tab_id)
            || self.lease_generation != workspace.lease_generation
            || self.document_generation == 0
            || self.identity_digest != workspace.expected_identity_digest
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.content_digest)
            || !is_sha256(&self.redaction_digest)
            || self.element_refs.len() > MAX_ELEMENT_REFS
            || self.element_refs.iter().any(|element| {
                !is_bounded_identifier(&element.reference)
                    || !is_sha256(&element.locator_digest)
                    || !refs.insert(element.reference.clone())
            })
        {
            return Err(BrowserError::InvalidSnapshot);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        if self.schema_version != ACTION_SCHEMA_VERSION {
            return Err(BrowserError::InvalidSnapshot);
        }
        digest_json(self)
    }
}

impl fmt::Debug for SemanticSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticSnapshot")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("workspace_id", &self.workspace_id)
            .field("tab_id", &self.tab_id)
            .field("lease_generation", &self.lease_generation)
            .field("document_generation", &self.document_generation)
            .field("identity_digest", &self.identity_digest)
            .field("url_digest", &self.url_digest)
            .field("content_digest", &self.content_digest)
            .field("redaction_digest", &self.redaction_digest)
            .field("prompt_risk", &self.prompt_risk)
            .field("element_ref_count", &self.element_refs.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserActionSurface {
    Semantic,
    Visual,
    FileBroker,
    AuthenticatedFetch,
    PageScript,
    Protocol,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserActionKind {
    Observe,
    Resolve,
    Navigate,
    Click,
    KeyboardInput,
    Upload,
    AuthenticatedFetch,
    PageScript,
    Protocol,
    Wait,
    Verify,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserActionRisk {
    ReadOnly,
    PotentialExternalWrite,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserAction {
    pub sequence: u32,
    pub kind: BrowserActionKind,
    pub surface: BrowserActionSurface,
    pub risk: BrowserActionRisk,
    pub tab_id: BrowserTabId,
    pub snapshot_id: Option<BrowserSnapshotId>,
    pub element_ref: Option<String>,
    pub target_origin_digest: String,
    pub payload_digest: String,
}

impl BrowserAction {
    /// Builds the only real-Chromium click shape accepted by the managed host:
    /// an exact, current semantic resolution whose evidence digest becomes part
    /// of the Effect-bound action plan. Geometry remains an execution-time
    /// detail and is revalidated immediately before input dispatch.
    pub fn semantic_click(
        sequence: u32,
        resolution: &BrowserLocatorResolution,
    ) -> Result<Self, BrowserError> {
        resolution.validate()?;
        let action = Self {
            sequence,
            kind: BrowserActionKind::Click,
            surface: BrowserActionSurface::Semantic,
            risk: BrowserActionRisk::PotentialExternalWrite,
            tab_id: resolution.tab_id.clone(),
            snapshot_id: Some(resolution.snapshot_id.clone()),
            element_ref: Some(resolution.element_ref.reference.clone()),
            target_origin_digest: resolution.origin_digest.clone(),
            payload_digest: resolution.evidence_digest()?,
        };
        action.validate()?;
        Ok(action)
    }

    /// Builds an exact semantic text-input action without retaining the
    /// cleartext in the action plan. The real host currently accepts this only
    /// for an empty, visible, editable text control on a script-disabled page.
    pub fn semantic_text_input(
        sequence: u32,
        resolution: &BrowserLocatorResolution,
        input: &BrowserTextInput,
    ) -> Result<Self, BrowserError> {
        resolution.validate()?;
        input.validate()?;
        let action = Self {
            sequence,
            kind: BrowserActionKind::KeyboardInput,
            surface: BrowserActionSurface::Semantic,
            risk: BrowserActionRisk::PotentialExternalWrite,
            tab_id: resolution.tab_id.clone(),
            snapshot_id: Some(resolution.snapshot_id.clone()),
            element_ref: Some(resolution.element_ref.reference.clone()),
            target_origin_digest: resolution.origin_digest.clone(),
            payload_digest: Self::semantic_text_input_payload_digest(resolution, input)?,
        };
        action.validate()?;
        Ok(action)
    }

    /// Builds the exact browser-side target for one already authorized File
    /// Broker grant. The Effect plan binds the snapshot/ref/origin while the
    /// action payload remains the grant digest required for a durable claim.
    pub fn semantic_file_upload(
        sequence: u32,
        resolution: &BrowserLocatorResolution,
        grant: &BrowserFileGrant,
    ) -> Result<Self, BrowserError> {
        resolution.validate()?;
        grant.validate()?;
        if grant.state != BrowserFileGrantState::Prepared
            || grant.workspace_id != resolution.workspace_id
            || grant.lease_generation != resolution.lease_generation
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        let action = Self {
            sequence,
            kind: BrowserActionKind::Upload,
            surface: BrowserActionSurface::FileBroker,
            risk: BrowserActionRisk::PotentialExternalWrite,
            tab_id: resolution.tab_id.clone(),
            snapshot_id: Some(resolution.snapshot_id.clone()),
            element_ref: Some(resolution.element_ref.reference.clone()),
            target_origin_digest: resolution.origin_digest.clone(),
            payload_digest: grant.upload_payload_digest.clone(),
        };
        action.validate()?;
        Ok(action)
    }

    pub(crate) fn semantic_text_input_payload_digest(
        resolution: &BrowserLocatorResolution,
        input: &BrowserTextInput,
    ) -> Result<String, BrowserError> {
        resolution.validate()?;
        input.validate()?;
        digest_json(&(
            ACTION_SCHEMA_VERSION,
            "hartevo-browser-semantic-text-input/v1",
            resolution.evidence_digest()?,
            input.evidence_digest()?,
        ))
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        let shape_matches = match self.kind {
            BrowserActionKind::Observe => {
                self.surface == BrowserActionSurface::Semantic
                    && self.risk == BrowserActionRisk::ReadOnly
                    && self.snapshot_id.is_none()
                    && self.element_ref.is_none()
            }
            BrowserActionKind::Resolve => {
                self.surface == BrowserActionSurface::Semantic
                    && self.risk == BrowserActionRisk::ReadOnly
                    && self.snapshot_id.is_some()
                    && self.element_ref.is_some()
            }
            BrowserActionKind::Navigate | BrowserActionKind::Wait => {
                self.surface == BrowserActionSurface::Semantic && self.element_ref.is_none()
            }
            BrowserActionKind::Click => {
                matches!(
                    self.surface,
                    BrowserActionSurface::Semantic | BrowserActionSurface::Visual
                ) && self.snapshot_id.is_some()
                    && self.element_ref.is_some()
                    && self.risk == BrowserActionRisk::PotentialExternalWrite
            }
            BrowserActionKind::KeyboardInput => {
                matches!(
                    self.surface,
                    BrowserActionSurface::Semantic | BrowserActionSurface::Visual
                ) && self.snapshot_id.is_some()
                    && self.element_ref.is_some()
                    && self.risk == BrowserActionRisk::PotentialExternalWrite
            }
            BrowserActionKind::Upload => {
                self.surface == BrowserActionSurface::FileBroker
                    && self.snapshot_id.is_some()
                    && self.element_ref.is_some()
                    && self.risk == BrowserActionRisk::PotentialExternalWrite
            }
            BrowserActionKind::AuthenticatedFetch => {
                self.surface == BrowserActionSurface::AuthenticatedFetch
                    && self.element_ref.is_none()
                    && self.risk == BrowserActionRisk::PotentialExternalWrite
            }
            BrowserActionKind::PageScript | BrowserActionKind::Protocol => false,
            BrowserActionKind::Verify => {
                matches!(
                    self.surface,
                    BrowserActionSurface::Semantic | BrowserActionSurface::Visual
                ) && self.snapshot_id.is_some()
                    && self.risk == BrowserActionRisk::ReadOnly
            }
        };
        if self.sequence == 0
            || !is_bounded_identifier(self.tab_id.as_str())
            || self
                .snapshot_id
                .as_ref()
                .is_some_and(|id| !is_bounded_identifier(id.as_str()))
            || self
                .element_ref
                .as_deref()
                .is_some_and(|value| !is_bounded_identifier(value))
            || !is_sha256(&self.target_origin_digest)
            || !is_sha256(&self.payload_digest)
            || !shape_matches
        {
            return Err(BrowserError::InvalidAction);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserAction")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("surface", &self.surface)
            .field("risk", &self.risk)
            .field("tab_id", &self.tab_id)
            .field("snapshot_id", &self.snapshot_id)
            .field(
                "element_ref_digest",
                &self
                    .element_ref
                    .as_ref()
                    .map(|value| digest(value.as_bytes())),
            )
            .field("target_origin_digest", &self.target_origin_digest)
            .field("payload_digest", &self.payload_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserEffectBinding {
    pub effect_id: EffectId,
    pub approval_digest: String,
    pub plan_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserActionBatch {
    pub schema_version: u32,
    pub id: BrowserActionBatchId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: BrowserWorkspaceId,
    pub lease: BrowserLeaseProof,
    pub expected_identity_digest: String,
    pub policy_digest: String,
    pub actions: Vec<BrowserAction>,
    #[serde(default)]
    pub recipe_binding_digest: Option<String>,
    pub plan_digest: String,
    pub effect_binding: Option<BrowserEffectBinding>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl BrowserActionBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn read_only(
        id: BrowserActionBatchId,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        lease: BrowserLeaseProof,
        policy_digest: String,
        actions: Vec<BrowserAction>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        if actions
            .iter()
            .any(|action| action.risk != BrowserActionRisk::ReadOnly)
        {
            return Err(BrowserError::EffectBrokerRequired);
        }
        Self::build(
            id,
            profile,
            workspace,
            lease,
            policy_digest,
            actions,
            None,
            None,
            created_at,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_effect(
        id: BrowserActionBatchId,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        lease: BrowserLeaseProof,
        policy_digest: String,
        actions: Vec<BrowserAction>,
        effect: &Effect,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let plan_digest = Self::plan_digest(&actions)?;
        validate_effect_scope(effect, profile, workspace, &plan_digest, created_at)?;
        Self::build(
            id,
            profile,
            workspace,
            lease,
            policy_digest,
            actions,
            None,
            Some(BrowserEffectBinding {
                effect_id: effect.id.clone(),
                approval_digest: effect.approval_digest(),
                plan_digest,
            }),
            created_at,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_recipe_effect(
        id: BrowserActionBatchId,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        lease: BrowserLeaseProof,
        policy_digest: String,
        actions: Vec<BrowserAction>,
        recipe_plan: &BrowserRecipePreparedPlan,
        recipe_registry: &BrowserRecipeRegistry,
        recipe_trust: &BrowserRecipeTrustStore,
        effect: &Effect,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        if policy_digest != recipe_plan.policy_digest || expires_at > recipe_plan.expires_at {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        recipe_plan.validate_active_release(recipe_registry, recipe_trust, &actions, created_at)?;
        recipe_plan.validate_for(profile, workspace, &actions, created_at)?;
        recipe_plan.validate_effect(effect, created_at)?;
        validate_effect_scope(
            effect,
            profile,
            workspace,
            &recipe_plan.effect_payload_digest,
            created_at,
        )?;
        let batch = Self::build(
            id,
            profile,
            workspace,
            lease,
            policy_digest,
            actions,
            Some(recipe_plan.binding_digest.clone()),
            Some(BrowserEffectBinding {
                effect_id: effect.id.clone(),
                approval_digest: effect.approval_digest(),
                plan_digest: recipe_plan.effect_payload_digest.clone(),
            }),
            created_at,
            expires_at,
        )?;
        if batch.plan_digest != recipe_plan.effect_payload_digest {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        Ok(batch)
    }

    pub fn plan_digest(actions: &[BrowserAction]) -> Result<String, BrowserError> {
        if actions.is_empty() || actions.len() > MAX_BATCH_ACTIONS {
            return Err(BrowserError::InvalidBatch);
        }
        for (index, action) in actions.iter().enumerate() {
            action.validate()?;
            let expected = u32::try_from(index)
                .map_err(|_| BrowserError::CounterOverflow)?
                .checked_add(1)
                .ok_or(BrowserError::CounterOverflow)?;
            if action.sequence != expected {
                return Err(BrowserError::InvalidBatch);
            }
        }
        digest_json(&actions)
    }

    pub fn recipe_plan_digest(
        actions: &[BrowserAction],
        recipe_binding_digest: &str,
    ) -> Result<String, BrowserError> {
        let action_plan_digest = Self::plan_digest(actions)?;
        if !is_sha256(recipe_binding_digest) {
            return Err(BrowserError::InvalidRecipe);
        }
        digest_json(&(
            ACTION_SCHEMA_VERSION,
            "hartevo-browser-recipe-effect-plan/v1",
            action_plan_digest,
            recipe_binding_digest,
        ))
    }

    pub fn validate_for(
        &self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        profile.validate()?;
        workspace.validate_agent_lease(&self.lease, now)?;
        let plan_digest = match self.recipe_binding_digest.as_deref() {
            Some(recipe_digest) => Self::recipe_plan_digest(&self.actions, recipe_digest)?,
            None => Self::plan_digest(&self.actions)?,
        };
        let contains_write = self
            .actions
            .iter()
            .any(|action| action.risk == BrowserActionRisk::PotentialExternalWrite);
        let effect_shape = match (&self.effect_binding, contains_write) {
            (None, false) => true,
            (Some(binding), true) => {
                binding.plan_digest == plan_digest
                    && binding.plan_digest == self.plan_digest
                    && is_sha256(&binding.approval_digest)
                    && is_bounded_identifier(binding.effect_id.as_str())
            }
            _ => false,
        };
        if self.schema_version != ACTION_SCHEMA_VERSION
            || !is_bounded_identifier(self.id.as_str())
            || self.tenant_id != profile.tenant_id
            || self.tenant_id != workspace.tenant_id
            || self.project_id != profile.project_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.workspace_id != workspace.id
            || workspace.profile_id != profile.id
            || profile.status != crate::BrowserProfileStatus::Active
            || self.expected_identity_digest != profile.identity.identity_digest
            || self.expected_identity_digest != workspace.expected_identity_digest
            || !is_sha256(&self.policy_digest)
            || self.plan_digest != plan_digest
            || self.created_at > now
            || self.expires_at <= now
            || self.expires_at - self.created_at > MAX_BATCH_LIFETIME
            || self
                .actions
                .iter()
                .any(|action| !workspace.tabs.contains(&action.tab_id))
            || !effect_shape
        {
            return Err(BrowserError::InvalidBatch);
        }
        Ok(())
    }

    pub fn validate_effect(&self, effect: &Effect, now: DateTime<Utc>) -> Result<(), BrowserError> {
        let binding = self
            .effect_binding
            .as_ref()
            .ok_or(BrowserError::EffectBrokerRequired)?;
        if binding.effect_id != effect.id
            || binding.approval_digest != effect.approval_digest()
            || binding.plan_digest != self.plan_digest
            || effect.payload_digest != self.plan_digest
            || effect.tenant_id != self.tenant_id
            || effect.project_id != self.project_id
            || effect.mission_id != self.mission_id
        {
            return Err(BrowserError::EffectScopeMismatch);
        }
        validate_effect_authorization(effect, now)
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        if self.schema_version != ACTION_SCHEMA_VERSION {
            return Err(BrowserError::InvalidBatch);
        }
        digest_json(self)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        id: BrowserActionBatchId,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        lease: BrowserLeaseProof,
        policy_digest: String,
        actions: Vec<BrowserAction>,
        recipe_binding_digest: Option<String>,
        effect_binding: Option<BrowserEffectBinding>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let plan_digest = match recipe_binding_digest.as_deref() {
            Some(recipe_digest) => Self::recipe_plan_digest(&actions, recipe_digest)?,
            None => Self::plan_digest(&actions)?,
        };
        let batch = Self {
            schema_version: ACTION_SCHEMA_VERSION,
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            lease,
            expected_identity_digest: profile.identity.identity_digest.clone(),
            policy_digest,
            actions,
            recipe_binding_digest,
            plan_digest,
            effect_binding,
            created_at,
            expires_at,
        };
        batch.validate_for(profile, workspace, created_at)?;
        Ok(batch)
    }
}

impl fmt::Debug for BrowserActionBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserActionBatch")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("workspace_id", &self.workspace_id)
            .field("lease_generation", &self.lease.generation)
            .field("expected_identity_digest", &self.expected_identity_digest)
            .field("policy_digest", &self.policy_digest)
            .field("action_count", &self.actions.len())
            .field("recipe_binding_digest", &self.recipe_binding_digest)
            .field("plan_digest", &self.plan_digest)
            .field(
                "effect_id_digest",
                &self
                    .effect_binding
                    .as_ref()
                    .map(|binding| digest(binding.effect_id.as_str().as_bytes())),
            )
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

fn validate_effect_scope(
    effect: &Effect,
    profile: &BrowserProfile,
    workspace: &BrowserWorkspace,
    plan_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), BrowserError> {
    validate_effect_authorization(effect, now)?;
    if effect.tenant_id != workspace.tenant_id
        || effect.project_id != workspace.project_id
        || effect.mission_id != workspace.mission_id
        || effect.provider != profile.identity.provider
        || effect.account_id.as_ref() != Some(&profile.identity.account_id)
        || effect.payload_digest != plan_digest
        || matches!(
            effect.effect_class,
            EffectClass::Read | EffectClass::LocalWrite
        )
    {
        return Err(BrowserError::EffectScopeMismatch);
    }
    Ok(())
}

fn validate_effect_authorization(effect: &Effect, now: DateTime<Utc>) -> Result<(), BrowserError> {
    let approval = effect
        .approval
        .as_ref()
        .ok_or(BrowserError::EffectBrokerRequired)?;
    if effect.status != EffectStatus::Approved
        || approval.decision != ApprovalDecision::Approved
        || approval.scope_digest != effect.approval_digest()
        || now >= approval.valid_until
        || now >= effect.expires_at
        || effect
            .scheduled_for
            .is_some_and(|scheduled_for| scheduled_for > now)
    {
        return Err(BrowserError::EffectBrokerRequired);
    }
    Ok(())
}

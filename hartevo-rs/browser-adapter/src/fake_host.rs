use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BrowserActionBatchId, BrowserSnapshotId, BrowserTabId, BrowserWorkspaceId, Effect, Receipt,
    ReceiptId,
};
use hartevo_effect_broker::{EffectExecutor, ProviderFailure};
use serde::{Deserialize, Serialize};

use crate::workspace::{digest, digest_json, is_sha256};
use crate::{
    BrowserAction, BrowserActionBatch, BrowserActionResult, BrowserActionRisk, BrowserBatchReceipt,
    BrowserBatchReceiptState, BrowserControlHost, BrowserElementRef, BrowserError,
    BrowserLeaseProof, BrowserLocatorResolution, BrowserNavigationPolicy, BrowserProfile,
    BrowserPromptRisk, BrowserRecipeExecutionAuthorization, BrowserRecipePreparedPlan,
    BrowserRecipeRegistry, BrowserRecipeTrustStore, BrowserStableLocator, BrowserWorkspace,
    SemanticSnapshot,
};

static HOST_SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
const MAX_SESSION_BATCH_CLAIMS: usize = 1_024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FakeBrowserPage {
    pub tab_id: BrowserTabId,
    pub identity_digest: String,
    pub url_digest: String,
    pub origin_digest: String,
    pub content_digest: String,
    pub redaction_digest: String,
    pub document_generation: u64,
    pub prompt_risk: BrowserPromptRisk,
    pub element_refs: Vec<BrowserElementRef>,
}

impl FakeBrowserPage {
    pub fn validate(&self) -> Result<(), BrowserError> {
        if !is_sha256(&self.identity_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.origin_digest)
            || !is_sha256(&self.content_digest)
            || !is_sha256(&self.redaction_digest)
            || self.document_generation == 0
        {
            return Err(BrowserError::InvalidSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct FakeBrowserWorkspaceState {
    profile: BrowserProfile,
    workspace: BrowserWorkspace,
    pages: BTreeMap<BrowserTabId, FakeBrowserPage>,
    latest_snapshots: BTreeMap<BrowserTabId, SemanticSnapshot>,
}

pub struct FakeBrowserHost {
    session_id: u64,
    workspaces: BTreeMap<BrowserWorkspaceId, FakeBrowserWorkspaceState>,
    claimed_batch_ids: BTreeSet<BrowserActionBatchId>,
    #[cfg(test)]
    fail_after_next_input: bool,
}

impl fmt::Debug for FakeBrowserHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeBrowserHost")
            .field("session_digest", &digest(&self.session_id.to_le_bytes()))
            .field("workspace_count", &self.workspaces.len())
            .field("claimed_batch_count", &self.claimed_batch_ids.len())
            .finish_non_exhaustive()
    }
}

impl Default for FakeBrowserHost {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeBrowserHost {
    pub fn new() -> Self {
        Self {
            session_id: HOST_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed),
            workspaces: BTreeMap::new(),
            claimed_batch_ids: BTreeSet::new(),
            #[cfg(test)]
            fail_after_next_input: false,
        }
    }

    pub fn register_workspace(
        &mut self,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        pages: Vec<FakeBrowserPage>,
    ) -> Result<(), BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        if profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.id != workspace.profile_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
            || self.workspaces.contains_key(&workspace.id)
        {
            return Err(BrowserError::ScopeMismatch);
        }
        let mut page_map = BTreeMap::new();
        for page in pages {
            page.validate()?;
            if !workspace.tabs.contains(&page.tab_id)
                || page_map.insert(page.tab_id.clone(), page).is_some()
            {
                return Err(BrowserError::ScopeMismatch);
            }
        }
        if page_map.len() != workspace.tabs.len() {
            return Err(BrowserError::ScopeMismatch);
        }
        self.workspaces.insert(
            workspace.id.clone(),
            FakeBrowserWorkspaceState {
                profile,
                workspace,
                pages: page_map,
                latest_snapshots: BTreeMap::new(),
            },
        );
        Ok(())
    }

    pub fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        let state = self
            .workspaces
            .get_mut(&workspace.id)
            .ok_or(BrowserError::WorkspaceNotRegistered)?;
        if *workspace == state.workspace {
            return Ok(());
        }
        if !workspace.is_valid_successor_of(&state.workspace)?
            || workspace.profile_id != state.profile.id
            || workspace.expected_identity_digest != state.profile.identity.identity_digest
            || !workspace
                .tabs
                .iter()
                .all(|tab_id| state.pages.contains_key(tab_id))
        {
            return Err(BrowserError::ScopeMismatch);
        }
        state.workspace = workspace.clone();
        state.latest_snapshots.clear();
        Ok(())
    }

    pub fn replace_page(
        &mut self,
        workspace_id: &BrowserWorkspaceId,
        page: FakeBrowserPage,
    ) -> Result<(), BrowserError> {
        page.validate()?;
        let state = self
            .workspaces
            .get_mut(workspace_id)
            .ok_or(BrowserError::WorkspaceNotRegistered)?;
        if !state.workspace.tabs.contains(&page.tab_id) {
            return Err(BrowserError::ScopeMismatch);
        }
        state.latest_snapshots.remove(&page.tab_id);
        state.pages.insert(page.tab_id.clone(), page);
        Ok(())
    }

    pub fn observe(
        &mut self,
        workspace_id: &BrowserWorkspaceId,
        proof: &BrowserLeaseProof,
        snapshot_id: BrowserSnapshotId,
        tab_id: &BrowserTabId,
        now: DateTime<Utc>,
    ) -> Result<SemanticSnapshot, BrowserError> {
        let state = self
            .workspaces
            .get_mut(workspace_id)
            .ok_or(BrowserError::WorkspaceNotRegistered)?;
        state.workspace.validate_agent_lease(proof, now)?;
        let page = state.pages.get(tab_id).ok_or(BrowserError::TabNotFound)?;
        if page.identity_digest != state.workspace.expected_identity_digest {
            return Err(BrowserError::AccountIdentityMismatch);
        }
        let snapshot = SemanticSnapshot::new(
            snapshot_id,
            &state.workspace,
            tab_id.clone(),
            page.document_generation,
            page.identity_digest.clone(),
            page.url_digest.clone(),
            page.content_digest.clone(),
            page.redaction_digest.clone(),
            page.prompt_risk,
            page.element_refs.clone(),
            now,
        )?;
        state
            .latest_snapshots
            .insert(tab_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_stable_locator(
        &mut self,
        workspace_id: &BrowserWorkspaceId,
        proof: &BrowserLeaseProof,
        snapshot_id: BrowserSnapshotId,
        tab_id: &BrowserTabId,
        policy: &BrowserNavigationPolicy,
        locator: &BrowserStableLocator,
        now: DateTime<Utc>,
    ) -> Result<BrowserLocatorResolution, BrowserError> {
        let snapshot = self.observe(workspace_id, proof, snapshot_id, tab_id, now)?;
        let state = self
            .workspaces
            .get(workspace_id)
            .ok_or(BrowserError::WorkspaceNotRegistered)?;
        let page = state.pages.get(tab_id).ok_or(BrowserError::TabNotFound)?;
        locator.validate_for(
            &state.workspace,
            tab_id,
            proof,
            policy,
            &page.origin_digest,
            now,
        )?;
        if snapshot.prompt_risk != BrowserPromptRisk::None {
            return Err(BrowserError::PromptInjectionDetected);
        }
        let matches = snapshot
            .element_refs
            .iter()
            .filter(|element| {
                element.locator_digest == locator.selector_digest()
                    && element.visible
                    && element.unique
            })
            .collect::<Vec<_>>();
        let element_ref = match matches.as_slice() {
            [] => return Err(BrowserError::StableLocatorNotFound),
            [element] => (*element).clone(),
            _ => return Err(BrowserError::StableLocatorAmbiguous),
        };
        BrowserLocatorResolution::new(
            state.workspace.id.clone(),
            tab_id.clone(),
            snapshot.id,
            snapshot.lease_generation,
            snapshot.document_generation,
            locator.evidence_digest().to_owned(),
            locator.selector_digest().to_owned(),
            snapshot.url_digest,
            page.origin_digest.clone(),
            policy.evidence_digest().to_owned(),
            element_ref,
            now,
        )
    }

    pub fn begin_read_only_batch(
        &mut self,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<BrowserBatchCursor, BrowserError> {
        self.ensure_batch_id_available(&batch.id)?;
        if batch.effect_binding.is_some()
            || batch
                .actions
                .iter()
                .any(|action| action.risk == BrowserActionRisk::PotentialExternalWrite)
        {
            return Err(BrowserError::EffectBrokerRequired);
        }
        self.begin_batch(batch, now)
    }

    pub fn resume_read_only_batch(
        &mut self,
        batch: &BrowserActionBatch,
        receipt: &BrowserBatchReceipt,
        now: DateTime<Utc>,
    ) -> Result<BrowserBatchCursor, BrowserError> {
        self.ensure_batch_id_available(&batch.id)?;
        if batch.effect_binding.is_some()
            || batch
                .actions
                .iter()
                .any(|action| action.risk == BrowserActionRisk::PotentialExternalWrite)
        {
            return Err(BrowserError::EffectBrokerRequired);
        }
        self.resume_batch(batch, receipt, now)
    }

    pub fn execute_next(
        &mut self,
        cursor: &mut BrowserBatchCursor,
        now: DateTime<Utc>,
    ) -> Result<Option<BrowserActionResult>, BrowserError> {
        if cursor.batch.effect_binding.is_some() {
            return Self::reject_active_cursor(cursor, BrowserError::EffectBrokerRequired);
        }
        self.execute_next_authorized(cursor, now)
    }

    pub fn begin_effect_batch(
        &mut self,
        batch: &BrowserActionBatch,
        effect: &Effect,
        recipe_authorization: Option<&BrowserRecipeExecutionAuthorization<'_>>,
        now: DateTime<Utc>,
    ) -> Result<BrowserBatchCursor, BrowserError> {
        self.ensure_batch_id_available(&batch.id)?;
        Self::validate_effect_dispatch(batch, effect, recipe_authorization, now)?;
        if batch.effect_binding.is_none()
            || !batch
                .actions
                .iter()
                .any(|action| action.risk == BrowserActionRisk::PotentialExternalWrite)
        {
            return Err(BrowserError::EffectBrokerRequired);
        }
        self.begin_batch(batch, now)
    }

    pub fn resume_effect_batch(
        &mut self,
        batch: &BrowserActionBatch,
        receipt: &BrowserBatchReceipt,
        effect: &Effect,
        recipe_authorization: Option<&BrowserRecipeExecutionAuthorization<'_>>,
        now: DateTime<Utc>,
    ) -> Result<BrowserBatchCursor, BrowserError> {
        self.ensure_batch_id_available(&batch.id)?;
        Self::validate_effect_dispatch(batch, effect, recipe_authorization, now)?;
        if batch.effect_binding.is_none()
            || !batch
                .actions
                .iter()
                .any(|action| action.risk == BrowserActionRisk::PotentialExternalWrite)
        {
            return Err(BrowserError::EffectBrokerRequired);
        }
        self.resume_batch(batch, receipt, now)
    }

    pub fn execute_next_effect(
        &mut self,
        cursor: &mut BrowserBatchCursor,
        effect: &Effect,
        recipe_authorization: Option<&BrowserRecipeExecutionAuthorization<'_>>,
        now: DateTime<Utc>,
    ) -> Result<Option<BrowserActionResult>, BrowserError> {
        if cursor.is_terminal() {
            return Err(BrowserError::RealActionRejected);
        }
        if let Err(error) =
            Self::validate_effect_dispatch(&cursor.batch, effect, recipe_authorization, now)
        {
            cursor.mark_failed(&error);
            return Err(error);
        }
        self.execute_next_authorized(cursor, now)
    }

    fn execute_next_authorized(
        &mut self,
        cursor: &mut BrowserBatchCursor,
        now: DateTime<Utc>,
    ) -> Result<Option<BrowserActionResult>, BrowserError> {
        if cursor.is_terminal() {
            return Err(BrowserError::RealActionRejected);
        }
        match self.execute_next_active(cursor, now) {
            Ok(Some(result)) => Ok(Some(result)),
            Ok(None) => {
                cursor.mark_completed();
                Ok(None)
            }
            Err(error) => {
                cursor.mark_failed(&error);
                Err(error)
            }
        }
    }

    fn reject_active_cursor<T>(
        cursor: &mut BrowserBatchCursor,
        error: BrowserError,
    ) -> Result<T, BrowserError> {
        if cursor.is_terminal() {
            return Err(BrowserError::RealActionRejected);
        }
        cursor.mark_failed(&error);
        Err(error)
    }

    fn execute_next_active(
        &mut self,
        cursor: &mut BrowserBatchCursor,
        now: DateTime<Utc>,
    ) -> Result<Option<BrowserActionResult>, BrowserError> {
        if cursor.host_session_id != self.session_id {
            return Err(BrowserError::HostRestarted);
        }
        let Some((action_sequence, dispatches_external_input, action_digest, observation_digest)) =
            self.observe_next_action(cursor, now)?
        else {
            return Ok(None);
        };
        cursor.record_observation(observation_digest.clone())?;
        if dispatches_external_input {
            cursor.mark_external_input_dispatched();
            #[cfg(test)]
            if std::mem::take(&mut self.fail_after_next_input) {
                return Err(BrowserError::HostExited);
            }
        }
        let host_receipt_digest = digest_json(&(
            "hartevo-fake-browser-action/v2",
            self.session_id,
            cursor.batch.id.as_str(),
            action_sequence,
            &action_digest,
            &observation_digest,
        ))?;
        let result = BrowserActionResult {
            batch_id: cursor.batch.id.clone(),
            action_sequence,
            action_digest,
            host_receipt_digest,
            external_write_may_have_occurred: cursor.external_write_may_have_occurred,
            business_verified: false,
        };
        cursor.acknowledge_result(result.clone())?;
        Ok(Some(result))
    }

    fn observe_next_action(
        &self,
        cursor: &BrowserBatchCursor,
        now: DateTime<Utc>,
    ) -> Result<Option<(u32, bool, String, String)>, BrowserError> {
        let state = self
            .workspaces
            .get(&cursor.batch.workspace_id)
            .ok_or(BrowserError::WorkspaceNotRegistered)?;
        cursor
            .batch
            .validate_for(&state.profile, &state.workspace, now)?;
        let Some(action) = cursor.batch.action_for_cursor(cursor.next_action)? else {
            return Ok(None);
        };
        let observation_sequence = u64::try_from(cursor.observation_count)
            .map_err(|_| BrowserError::CounterOverflow)?
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        let observation_digest =
            observe_action_against_live_page(state, action, observation_sequence)?;
        Ok(Some((
            action.sequence,
            action.dispatches_external_input(),
            digest_json(action)?,
            observation_digest,
        )))
    }

    fn begin_batch(
        &mut self,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<BrowserBatchCursor, BrowserError> {
        let state = self
            .workspaces
            .get(&batch.workspace_id)
            .ok_or(BrowserError::WorkspaceNotRegistered)?;
        batch.validate_for(&state.profile, &state.workspace, now)?;
        if state
            .pages
            .values()
            .any(|page| page.identity_digest != state.workspace.expected_identity_digest)
        {
            return Err(BrowserError::AccountIdentityMismatch);
        }
        let cursor = BrowserBatchCursor::new(batch.clone(), self.session_id);
        self.claim_validated_batch_id(&batch.id)?;
        Ok(cursor)
    }

    fn resume_batch(
        &mut self,
        batch: &BrowserActionBatch,
        receipt: &BrowserBatchReceipt,
        now: DateTime<Utc>,
    ) -> Result<BrowserBatchCursor, BrowserError> {
        let state = self
            .workspaces
            .get(&batch.workspace_id)
            .ok_or(BrowserError::WorkspaceNotRegistered)?;
        batch.validate_for(&state.profile, &state.workspace, now)?;
        receipt.validate_for(batch)?;
        if !receipt.is_resumable() {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        if state
            .pages
            .values()
            .any(|page| page.identity_digest != state.workspace.expected_identity_digest)
        {
            return Err(BrowserError::AccountIdentityMismatch);
        }
        let cursor = BrowserBatchCursor::resume(batch.clone(), receipt, self.session_id)?;
        self.claim_validated_batch_id(&batch.id)?;
        Ok(cursor)
    }

    fn validate_effect_dispatch(
        batch: &BrowserActionBatch,
        effect: &Effect,
        recipe_authorization: Option<&BrowserRecipeExecutionAuthorization<'_>>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        match (batch.recipe_binding_digest.as_ref(), recipe_authorization) {
            (Some(_), Some(authorization)) => authorization.validate_effect(batch, effect, now),
            (Some(_), None) => Err(BrowserError::RecipeRuntimeAuthorizationRequired),
            (None, None) => batch.validate_effect(effect, now),
            (None, Some(_)) => Err(BrowserError::RecipeScopeMismatch),
        }
    }

    fn ensure_batch_id_available(
        &self,
        batch_id: &BrowserActionBatchId,
    ) -> Result<(), BrowserError> {
        if self.claimed_batch_ids.contains(batch_id)
            || self.claimed_batch_ids.len() >= MAX_SESSION_BATCH_CLAIMS
        {
            return Err(BrowserError::RealActionRejected);
        }
        Ok(())
    }

    fn claim_validated_batch_id(
        &mut self,
        batch_id: &BrowserActionBatchId,
    ) -> Result<(), BrowserError> {
        if self.claimed_batch_ids.len() >= MAX_SESSION_BATCH_CLAIMS
            || !self.claimed_batch_ids.insert(batch_id.clone())
        {
            return Err(BrowserError::RealActionRejected);
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_after_next_external_input_for_test(&mut self) {
        self.fail_after_next_input = true;
    }
}

impl BrowserControlHost for FakeBrowserHost {
    fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        Self::sync_workspace(self, workspace)
    }
}

pub struct BrowserBatchCursor {
    batch: BrowserActionBatch,
    host_session_id: u64,
    next_action: usize,
    observation_count: usize,
    last_observation_digest: Option<String>,
    acknowledged_results: Vec<BrowserActionResult>,
    external_write_may_have_occurred: bool,
    state: BrowserBatchCursorState,
    terminal_reason_digest: Option<String>,
}

impl BrowserBatchCursor {
    fn new(batch: BrowserActionBatch, host_session_id: u64) -> Self {
        Self {
            batch,
            host_session_id,
            next_action: 0,
            observation_count: 0,
            last_observation_digest: None,
            acknowledged_results: Vec::new(),
            external_write_may_have_occurred: false,
            state: BrowserBatchCursorState::Active,
            terminal_reason_digest: None,
        }
    }

    fn resume(
        batch: BrowserActionBatch,
        receipt: &BrowserBatchReceipt,
        host_session_id: u64,
    ) -> Result<Self, BrowserError> {
        receipt.validate_for(&batch)?;
        if !receipt.is_resumable() {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        let next_action = usize::try_from(receipt.completed_action_count)
            .map_err(|_| BrowserError::CounterOverflow)?;
        Ok(Self {
            batch,
            host_session_id,
            next_action,
            observation_count: next_action,
            last_observation_digest: receipt.last_observation_digest.clone(),
            acknowledged_results: receipt.acknowledged_results.clone(),
            external_write_may_have_occurred: receipt.external_write_may_have_occurred,
            state: BrowserBatchCursorState::Active,
            terminal_reason_digest: None,
        })
    }

    pub fn completed_action_count(&self) -> usize {
        self.next_action
    }

    pub fn observed_action_count(&self) -> usize {
        self.observation_count
    }

    pub fn last_observation_digest(&self) -> Option<&str> {
        self.last_observation_digest.as_deref()
    }

    pub fn external_write_may_have_occurred(&self) -> bool {
        self.external_write_may_have_occurred
    }

    pub fn is_terminal(&self) -> bool {
        self.state != BrowserBatchCursorState::Active
    }

    pub fn receipt(&self) -> Result<BrowserBatchReceipt, BrowserError> {
        BrowserBatchReceipt::new(
            &self.batch,
            self.acknowledged_results.clone(),
            self.last_observation_digest.clone(),
            self.external_write_may_have_occurred,
            self.state.into(),
            self.terminal_reason_digest.clone(),
        )
    }

    pub fn cancel(&mut self, cancellation_evidence_digest: String) -> Result<(), BrowserError> {
        if self.is_terminal() || !is_sha256(&cancellation_evidence_digest) {
            return Err(BrowserError::RealActionRejected);
        }
        self.state = BrowserBatchCursorState::Cancelled;
        self.terminal_reason_digest = Some(cancellation_evidence_digest);
        Ok(())
    }

    pub fn requires_reconciliation(&self, error: &BrowserError) -> bool {
        matches!(error, BrowserError::HostRestarted) || self.external_write_may_have_occurred
    }

    fn record_observation(&mut self, observation_digest: String) -> Result<(), BrowserError> {
        if !is_sha256(&observation_digest) {
            return Err(BrowserError::InvalidSnapshot);
        }
        self.observation_count = self
            .observation_count
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        self.last_observation_digest = Some(observation_digest);
        Ok(())
    }

    fn mark_external_input_dispatched(&mut self) {
        self.external_write_may_have_occurred = true;
    }

    fn acknowledge_result(&mut self, result: BrowserActionResult) -> Result<(), BrowserError> {
        let expected_sequence = u32::try_from(self.next_action)
            .map_err(|_| BrowserError::CounterOverflow)?
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        if result.batch_id != self.batch.id || result.action_sequence != expected_sequence {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        result.digest()?;
        self.acknowledged_results.push(result);
        self.next_action = self
            .next_action
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        Ok(())
    }

    fn mark_completed(&mut self) {
        self.state = BrowserBatchCursorState::Completed;
        self.terminal_reason_digest = None;
    }

    fn mark_failed(&mut self, error: &BrowserError) {
        self.state = BrowserBatchCursorState::Failed;
        self.terminal_reason_digest = Some(digest(error.code().as_bytes()));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserBatchCursorState {
    Active,
    Completed,
    Cancelled,
    Failed,
}

impl From<BrowserBatchCursorState> for BrowserBatchReceiptState {
    fn from(value: BrowserBatchCursorState) -> Self {
        match value {
            BrowserBatchCursorState::Active => Self::Active,
            BrowserBatchCursorState::Completed => Self::Completed,
            BrowserBatchCursorState::Cancelled => Self::Cancelled,
            BrowserBatchCursorState::Failed => Self::Failed,
        }
    }
}

impl fmt::Debug for BrowserBatchCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserBatchCursor")
            .field("batch_id", &self.batch.id)
            .field(
                "host_session_digest",
                &digest(&self.host_session_id.to_le_bytes()),
            )
            .field("next_action", &self.next_action)
            .field("observation_count", &self.observation_count)
            .field(
                "acknowledged_result_count",
                &self.acknowledged_results.len(),
            )
            .field(
                "has_last_observation",
                &self.last_observation_digest.is_some(),
            )
            .field(
                "external_write_may_have_occurred",
                &self.external_write_may_have_occurred,
            )
            .field("state", &self.state)
            .field(
                "has_terminal_reason",
                &self.terminal_reason_digest.is_some(),
            )
            .finish()
    }
}

pub struct FakeBrowserEffectExecutor<'a> {
    host: &'a mut FakeBrowserHost,
    batch: BrowserActionBatch,
    recipe_authorization: Option<BrowserRecipeExecutionAuthorization<'a>>,
    now: DateTime<Utc>,
    consumed: bool,
}

impl<'a> FakeBrowserEffectExecutor<'a> {
    pub fn new(
        host: &'a mut FakeBrowserHost,
        batch: BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            host,
            batch,
            recipe_authorization: None,
            now,
            consumed: false,
        }
    }

    pub fn new_for_recipe(
        host: &'a mut FakeBrowserHost,
        batch: BrowserActionBatch,
        prepared_plan: BrowserRecipePreparedPlan,
        registry: &'a BrowserRecipeRegistry,
        trust: &'a BrowserRecipeTrustStore,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let recipe_authorization =
            BrowserRecipeExecutionAuthorization::new(prepared_plan, registry, trust, &batch, now)?;
        Ok(Self {
            host,
            batch,
            recipe_authorization: Some(recipe_authorization),
            now,
            consumed: false,
        })
    }
}

impl fmt::Debug for FakeBrowserEffectExecutor<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeBrowserEffectExecutor")
            .field("batch_id", &self.batch.id)
            .field("now", &self.now)
            .field("consumed", &self.consumed)
            .field(
                "has_recipe_runtime_authorization",
                &self.recipe_authorization.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl EffectExecutor for FakeBrowserEffectExecutor<'_> {
    fn execute(&mut self, effect: &Effect) -> Result<Receipt, ProviderFailure> {
        if self.consumed {
            return Err(ProviderFailure::Uncertain(
                "browser executor is single-use".into(),
            ));
        }
        self.consumed = true;
        let mut cursor = self
            .host
            .begin_effect_batch(
                &self.batch,
                effect,
                self.recipe_authorization.as_ref(),
                self.now,
            )
            .map_err(|error| ProviderFailure::Rejected(error.code().into()))?;
        let mut results = Vec::new();
        loop {
            match self.host.execute_next_effect(
                &mut cursor,
                effect,
                self.recipe_authorization.as_ref(),
                self.now,
            ) {
                Ok(Some(result)) => results.push(result),
                Ok(None) => break,
                Err(error) if cursor.requires_reconciliation(&error) => {
                    return Err(ProviderFailure::Uncertain(error.code().into()));
                }
                Err(error) => return Err(ProviderFailure::Rejected(error.code().into())),
            }
        }
        let response_digest = digest_json(&results)
            .map_err(|error| ProviderFailure::Uncertain(error.code().into()))?;
        Ok(Receipt {
            id: ReceiptId::from_stable(format!("browser-receipt-{}", self.batch.id)),
            provider: effect.provider.clone(),
            external_id: format!("browser-batch-{}", self.batch.id),
            accepted_at: self.now,
            request_digest: self.batch.plan_digest.clone(),
            response_digest,
        })
    }
}

fn observe_action_against_live_page(
    state: &FakeBrowserWorkspaceState,
    action: &BrowserAction,
    observation_sequence: u64,
) -> Result<String, BrowserError> {
    let page = state
        .pages
        .get(&action.tab_id)
        .ok_or(BrowserError::TabNotFound)?;
    page.validate()?;
    if page.identity_digest != state.workspace.expected_identity_digest {
        return Err(BrowserError::AccountIdentityMismatch);
    }
    if action.target_origin_digest != page.origin_digest {
        return Err(BrowserError::NavigationTargetRejected);
    }
    if page.prompt_risk != BrowserPromptRisk::None && !action.allows_prompt_risk() {
        return Err(BrowserError::PromptInjectionDetected);
    }
    let snapshot_digest = if action.requires_snapshot_fence() {
        let snapshot_id = action
            .snapshot_id
            .as_ref()
            .ok_or(BrowserError::InvalidAction)?;
        let snapshot = state
            .latest_snapshots
            .get(&action.tab_id)
            .ok_or(BrowserError::StaleSnapshot)?;
        snapshot.validate_for(&state.workspace)?;
        if snapshot.id != *snapshot_id
            || snapshot.tab_id != action.tab_id
            || snapshot.lease_generation != state.workspace.lease_generation
            || snapshot.document_generation != page.document_generation
            || snapshot.identity_digest != page.identity_digest
            || snapshot.url_digest != page.url_digest
            || snapshot.content_digest != page.content_digest
            || snapshot.redaction_digest != page.redaction_digest
            || snapshot.prompt_risk != page.prompt_risk
            || snapshot.element_refs != page.element_refs
        {
            return Err(BrowserError::StaleSnapshot);
        }
        if let Some(reference) = action.element_ref.as_deref()
            && !snapshot
                .element_refs
                .iter()
                .any(|element| element.reference == reference && element.visible && element.unique)
        {
            return Err(BrowserError::StaleElementRef);
        }
        Some(snapshot.digest()?)
    } else {
        None
    };
    digest_json(&(
        "hartevo-fake-browser-live-observation/v1",
        observation_sequence,
        action.sequence,
        digest(state.workspace.id.as_str().as_bytes()),
        digest(action.tab_id.as_str().as_bytes()),
        state.workspace.lease_generation,
        page.document_generation,
        &page.identity_digest,
        &page.url_digest,
        &page.origin_digest,
        &page.content_digest,
        &page.redaction_digest,
        page.prompt_risk,
        page.element_refs.len(),
        snapshot_digest,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, BrowserControlLeaseId,
        BrowserProfileId, ConsentState, CurrencyCode, EffectClass, EffectId, EffectRisk,
        EffectStatus, Mission, MissionContract, MissionId, Money, Project, ProjectId, StorageMode,
        TenantId,
    };
    use hartevo_effect_broker::{EffectExecutor, ProviderFailure};

    use super::*;
    use crate::{BrowserActionKind, BrowserActionSurface};

    const CREDENTIAL_REFERENCE: &str = "keychain://browser/profile-1";

    struct Fixture {
        now: DateTime<Utc>,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        host: FakeBrowserHost,
        tab_id: BrowserTabId,
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 8, 0, 0)
            .single()
            .expect("valid fixture time")
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture(prompt_risk: BrowserPromptRisk) -> Fixture {
        let now = now();
        let project = Project::create_local(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "Browser fixture",
            "",
            "/workspace/browser-fixture",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-1"),
            project.id.clone(),
            "Browser fixture mission",
            MissionContract::bootstrap(
                "Exercise browser control fencing",
                ["channel.publish".into()],
                now,
            ),
            now,
        )
        .expect("mission");
        let identity = crate::BrowserIdentity::new(
            "fixture-provider",
            AccountId::from("account-1"),
            sha('1'),
            sha('2'),
            now,
        )
        .expect("identity");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-1"),
            &project,
            CREDENTIAL_REFERENCE,
            identity,
            now,
        )
        .expect("profile");
        let tab_id = BrowserTabId::from("tab-1");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-1"),
            &project,
            &mission,
            &profile,
            tab_id.clone(),
            BrowserControlLeaseId::from("lease-1"),
            now + Duration::hours(1),
            sha('3'),
            now,
        )
        .expect("workspace");
        let page = FakeBrowserPage {
            tab_id: tab_id.clone(),
            identity_digest: sha('1'),
            url_digest: sha('4'),
            origin_digest: sha('8'),
            content_digest: sha('5'),
            redaction_digest: sha('6'),
            document_generation: 1,
            prompt_risk,
            element_refs: vec![BrowserElementRef {
                reference: "element-1".into(),
                locator_digest: sha('7'),
                visible: true,
                unique: true,
            }],
        };
        let mut host = FakeBrowserHost::new();
        host.register_workspace(profile.clone(), workspace.clone(), vec![page])
            .expect("register workspace");
        Fixture {
            now,
            profile,
            workspace,
            host,
            tab_id,
        }
    }

    fn observe(fixture: &mut Fixture) -> SemanticSnapshot {
        fixture
            .host
            .observe(
                &fixture.workspace.id,
                &fixture
                    .workspace
                    .agent_lease_proof(fixture.now)
                    .expect("lease"),
                BrowserSnapshotId::from("snapshot-1"),
                &fixture.tab_id,
                fixture.now,
            )
            .expect("observe")
    }

    fn action(
        sequence: u32,
        kind: BrowserActionKind,
        risk: BrowserActionRisk,
        tab_id: &BrowserTabId,
        snapshot_id: Option<BrowserSnapshotId>,
        element_ref: Option<&str>,
    ) -> BrowserAction {
        let surface = match kind {
            BrowserActionKind::Observe
            | BrowserActionKind::Resolve
            | BrowserActionKind::Navigate
            | BrowserActionKind::Click
            | BrowserActionKind::Wait
            | BrowserActionKind::Verify => BrowserActionSurface::Semantic,
            BrowserActionKind::KeyboardInput => BrowserActionSurface::Visual,
            BrowserActionKind::Upload => BrowserActionSurface::FileBroker,
            BrowserActionKind::AuthenticatedFetch => BrowserActionSurface::AuthenticatedFetch,
            BrowserActionKind::PageScript => BrowserActionSurface::PageScript,
            BrowserActionKind::Protocol => BrowserActionSurface::Protocol,
        };
        BrowserAction {
            sequence,
            kind,
            surface,
            risk,
            tab_id: tab_id.clone(),
            snapshot_id,
            element_ref: element_ref.map(str::to_owned),
            target_origin_digest: sha('8'),
            payload_digest: sha('9'),
        }
    }

    fn read_batch(
        fixture: &Fixture,
        actions: Vec<BrowserAction>,
    ) -> Result<BrowserActionBatch, BrowserError> {
        read_batch_with_id(fixture, "batch-read-1", actions)
    }

    fn read_batch_with_id(
        fixture: &Fixture,
        batch_id: &str,
        actions: Vec<BrowserAction>,
    ) -> Result<BrowserActionBatch, BrowserError> {
        BrowserActionBatch::read_only(
            BrowserActionBatchId::from(batch_id),
            &fixture.profile,
            &fixture.workspace,
            fixture.workspace.agent_lease_proof(fixture.now)?,
            sha('a'),
            actions,
            fixture.now,
            fixture.now + Duration::minutes(5),
        )
    }

    fn approved_effect(fixture: &Fixture, actions: &[BrowserAction]) -> Effect {
        let plan_digest = BrowserActionBatch::plan_digest(actions).expect("plan digest");
        let mut effect = Effect {
            id: EffectId::from("effect-browser-1"),
            tenant_id: fixture.workspace.tenant_id.clone(),
            project_id: fixture.workspace.project_id.clone(),
            mission_id: fixture.workspace.mission_id.clone(),
            actor_id: ActorId::from("user-1"),
            capability: "channel.publish".into(),
            provider: fixture.profile.identity.provider.clone(),
            connection_id: None,
            account_id: Some(fixture.profile.identity.account_id.clone()),
            required_scopes: BTreeSet::from(["content.publish".into()]),
            effect_class: EffectClass::ExternalWrite,
            description: "Publish exact browser plan".into(),
            target_resource: "fixture-resource".into(),
            audience_digest: Some(sha('b')),
            payload_digest: plan_digest,
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "browser-policy-v1".into(),
            risk: EffectRisk::High,
            idempotency_key: "mission-1:browser-plan:v1".into(),
            amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
            expires_at: fixture.now + Duration::hours(1),
            status: EffectStatus::Proposed,
            approval: None,
            receipt: None,
            verification: None,
        };
        let scope_digest = effect.approval_digest();
        effect.status = EffectStatus::Approved;
        effect.approval = Some(Approval {
            id: ApprovalId::from("approval-browser-1"),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from("approver-1"),
            decided_at: fixture.now,
            valid_until: fixture.now + Duration::minutes(30),
            scope_digest,
            permission_digest: sha('c'),
        });
        effect
    }

    fn effect_batch(
        fixture: &Fixture,
        actions: Vec<BrowserAction>,
        effect: &Effect,
    ) -> BrowserActionBatch {
        BrowserActionBatch::for_effect(
            BrowserActionBatchId::from("batch-effect-1"),
            &fixture.profile,
            &fixture.workspace,
            fixture
                .workspace
                .agent_lease_proof(fixture.now)
                .expect("lease"),
            sha('a'),
            actions,
            effect,
            fixture.now,
            fixture.now + Duration::minutes(5),
        )
        .expect("effect batch")
    }

    #[test]
    fn typed_multi_action_cursor_observes_each_step_once_in_order() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let actions = vec![
            action(
                1,
                BrowserActionKind::Observe,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                None,
                None,
            ),
            action(
                2,
                BrowserActionKind::Resolve,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(snapshot.id.clone()),
                Some("element-1"),
            ),
            action(
                3,
                BrowserActionKind::Verify,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(snapshot.id),
                None,
            ),
        ];
        let batch = read_batch(&fixture, actions).expect("typed read batch");
        let serialized_batch = serde_json::to_value(&batch).expect("v1 batch JSON");
        let plan_digest = batch.plan_digest.clone();
        assert_eq!(batch.schema_version, 1);
        let mut cursor = fixture
            .host
            .begin_read_only_batch(&batch, fixture.now)
            .expect("begin typed cursor");
        let mut observation_digests = BTreeSet::new();
        let mut receipt_digests = BTreeSet::new();

        for expected_sequence in 1_u32..=3 {
            let expected_count = usize::try_from(expected_sequence).expect("bounded sequence");
            let result = fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect("execute typed step")
                .expect("action result");
            assert_eq!(result.action_sequence, expected_sequence);
            assert_eq!(cursor.completed_action_count(), expected_count);
            assert_eq!(cursor.observed_action_count(), expected_count);
            assert!(!result.external_write_may_have_occurred);
            assert!(!result.business_verified);
            assert!(receipt_digests.insert(result.host_receipt_digest));
            assert!(
                observation_digests.insert(
                    cursor
                        .last_observation_digest()
                        .expect("content-free observation digest")
                        .to_owned(),
                )
            );
        }

        assert!(
            fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect("complete cursor")
                .is_none()
        );
        assert!(cursor.is_terminal());
        assert_eq!(cursor.completed_action_count(), 3);
        assert_eq!(cursor.observed_action_count(), 3);
        assert_eq!(observation_digests.len(), 3);
        assert_eq!(receipt_digests.len(), 3);
        assert_eq!(
            BrowserActionBatch::plan_digest(&batch.actions).expect("unchanged v1 action plan"),
            plan_digest
        );
        assert_eq!(
            serde_json::to_value(&batch).expect("unchanged v1 batch JSON"),
            serialized_batch
        );
        assert_eq!(
            fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect_err("completed cursor is single-use")
                .code(),
            "BROWSER_REAL_ACTION_REJECTED"
        );
    }

    #[test]
    fn invalid_begin_does_not_claim_batch_id() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let actions = vec![action(
            1,
            BrowserActionKind::Observe,
            BrowserActionRisk::ReadOnly,
            &fixture.tab_id,
            None,
            None,
        )];
        let valid = read_batch(&fixture, actions).expect("valid batch");
        let mut invalid = valid.clone();
        invalid.policy_digest = "not-a-policy-digest".into();

        assert_eq!(
            fixture
                .host
                .begin_read_only_batch(&invalid, fixture.now)
                .expect_err("invalid begin must fail before claim")
                .code(),
            "BROWSER_INVALID_BATCH"
        );
        assert!(!fixture.host.claimed_batch_ids.contains(&valid.id));
        fixture
            .host
            .begin_read_only_batch(&valid, fixture.now)
            .expect("same id remains available after failed validation");
        assert!(fixture.host.claimed_batch_ids.contains(&valid.id));
    }

    #[test]
    fn same_session_claim_rejects_same_id_without_inspecting_new_plan() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let first = read_batch_with_id(
            &fixture,
            "batch-shared-id",
            vec![action(
                1,
                BrowserActionKind::Observe,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                None,
                None,
            )],
        )
        .expect("first plan");
        let different_plan = read_batch_with_id(
            &fixture,
            "batch-shared-id",
            vec![action(
                1,
                BrowserActionKind::Wait,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                None,
                None,
            )],
        )
        .expect("different valid plan");
        assert_ne!(first.plan_digest, different_plan.plan_digest);
        let mut malformed_rebinding = different_plan.clone();
        malformed_rebinding.plan_digest = "not-a-plan-digest".into();

        let mut cursor = fixture
            .host
            .begin_read_only_batch(&first, fixture.now)
            .expect("first claim");
        for replay in [&first, &different_plan, &malformed_rebinding] {
            assert_eq!(
                fixture
                    .host
                    .begin_read_only_batch(replay, fixture.now)
                    .expect_err("same session batch id cannot be rebound or replayed")
                    .code(),
                "BROWSER_REAL_ACTION_REJECTED"
            );
        }
        assert_eq!(fixture.host.claimed_batch_ids.len(), 1);
        assert!(
            fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect("original claimed cursor remains valid")
                .is_some()
        );
    }

    #[test]
    fn session_claim_capacity_fails_closed_without_eviction() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let batch = read_batch(
            &fixture,
            vec![action(
                1,
                BrowserActionKind::Observe,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                None,
                None,
            )],
        )
        .expect("unclaimed batch");
        for index in 0..MAX_SESSION_BATCH_CLAIMS {
            assert!(
                fixture
                    .host
                    .claimed_batch_ids
                    .insert(BrowserActionBatchId::from_stable(format!(
                        "claimed-batch-{index}"
                    )),)
            );
        }
        let retained_claim = fixture
            .host
            .claimed_batch_ids
            .first()
            .cloned()
            .expect("retained claim");

        assert_eq!(
            fixture
                .host
                .begin_read_only_batch(&batch, fixture.now)
                .expect_err("saturated claim set must fail closed")
                .code(),
            "BROWSER_REAL_ACTION_REJECTED"
        );
        assert_eq!(
            fixture.host.claimed_batch_ids.len(),
            MAX_SESSION_BATCH_CLAIMS
        );
        assert!(fixture.host.claimed_batch_ids.contains(&retained_claim));
        assert!(!fixture.host.claimed_batch_ids.contains(&batch.id));
    }

    #[test]
    fn generic_effect_executor_rejects_recipe_batch_without_runtime_authorization() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let actions = vec![action(
            1,
            BrowserActionKind::Click,
            BrowserActionRisk::PotentialExternalWrite,
            &fixture.tab_id,
            Some(snapshot.id),
            Some("element-1"),
        )];
        let effect = approved_effect(&fixture, &actions);
        let mut batch = effect_batch(&fixture, actions, &effect);
        batch.recipe_binding_digest = Some(sha('d'));
        let mut executor = FakeBrowserEffectExecutor::new(&mut fixture.host, batch, fixture.now);
        let failure = executor
            .execute(&effect)
            .expect_err("generic executor must not dispatch a recovered Recipe batch");
        assert_eq!(
            failure,
            ProviderFailure::Rejected("BROWSER_RECIPE_RUNTIME_AUTHORIZATION_REQUIRED".into())
        );
    }

    #[test]
    fn user_takeover_hard_stops_every_queued_write_surface() {
        let write_kinds = [
            BrowserActionKind::Click,
            BrowserActionKind::KeyboardInput,
            BrowserActionKind::Upload,
            BrowserActionKind::AuthenticatedFetch,
        ];
        for (index, write_kind) in write_kinds.into_iter().enumerate() {
            let mut fixture = fixture(BrowserPromptRisk::None);
            let snapshot = observe(&mut fixture);
            let first = action(
                1,
                BrowserActionKind::Verify,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(snapshot.id.clone()),
                None,
            );
            let (snapshot_id, element_ref) = match write_kind {
                BrowserActionKind::Click | BrowserActionKind::KeyboardInput => {
                    (Some(snapshot.id.clone()), Some("element-1"))
                }
                BrowserActionKind::Upload => (Some(snapshot.id.clone()), Some("element-1")),
                BrowserActionKind::AuthenticatedFetch => (None, None),
                _ => unreachable!("bounded write variants"),
            };
            let second = action(
                2,
                write_kind,
                BrowserActionRisk::PotentialExternalWrite,
                &fixture.tab_id,
                snapshot_id,
                element_ref,
            );
            let actions = vec![first, second];
            let effect = approved_effect(&fixture, &actions);
            let batch = effect_batch(&fixture, actions, &effect);
            let mut cursor = fixture
                .host
                .begin_effect_batch(&batch, &effect, None, fixture.now)
                .expect("begin batch");
            assert!(
                fixture
                    .host
                    .execute_next_effect(&mut cursor, &effect, None, fixture.now)
                    .expect("first action")
                    .is_some()
            );
            let acknowledged = cursor.receipt().expect("first prefix receipt");
            assert_eq!(acknowledged.completed_action_count, 1);

            fixture
                .workspace
                .user_takeover(
                    fixture.workspace.revision,
                    fixture.workspace.lease_generation,
                    BrowserControlLeaseId::from_stable(format!("takeover-lease-{index}")),
                    sha('d'),
                    fixture.now + Duration::seconds(1),
                )
                .expect("takeover");
            fixture
                .host
                .sync_workspace(&fixture.workspace)
                .expect("sync hard stop");

            let failure = fixture
                .host
                .execute_next_effect(
                    &mut cursor,
                    &effect,
                    None,
                    fixture.now + Duration::seconds(1),
                )
                .expect_err("old batch must be stopped before queued write");
            assert_eq!(failure.code(), "BROWSER_CONTROL_LEASE_LOST");
            assert_eq!(cursor.completed_action_count(), 1);
            assert_eq!(cursor.observed_action_count(), 1);
            assert!(!cursor.external_write_may_have_occurred());
            assert!(!cursor.requires_reconciliation(&failure));
            assert!(cursor.is_terminal());
            let stopped = cursor.receipt().expect("lease-loss receipt");
            assert_eq!(stopped.completed_action_count, 1);
            assert_eq!(stopped.result_digest, acknowledged.result_digest);
            assert_eq!(stopped.state, BrowserBatchReceiptState::Failed);
            assert_eq!(
                fixture
                    .host
                    .execute_next_effect(
                        &mut cursor,
                        &effect,
                        None,
                        fixture.now + Duration::seconds(1),
                    )
                    .expect_err("failed cursor cannot retry queued write")
                    .code(),
                "BROWSER_REAL_ACTION_REJECTED"
            );
        }
    }

    #[test]
    fn fresh_continue_lease_works_but_old_lease_never_recovers() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let old_proof = fixture
            .workspace
            .agent_lease_proof(fixture.now)
            .expect("old proof");
        fixture
            .workspace
            .user_takeover(
                1,
                1,
                BrowserControlLeaseId::from("lease-2"),
                sha('d'),
                fixture.now + Duration::seconds(1),
            )
            .expect("takeover");
        fixture
            .host
            .sync_workspace(&fixture.workspace)
            .expect("sync takeover");
        fixture
            .workspace
            .continue_agent(
                2,
                2,
                BrowserControlLeaseId::from("lease-3"),
                fixture.now + Duration::hours(1),
                sha('e'),
                fixture.now + Duration::seconds(2),
            )
            .expect("continue");
        fixture
            .host
            .sync_workspace(&fixture.workspace)
            .expect("sync continue");

        assert_eq!(
            fixture
                .workspace
                .validate_agent_lease(&old_proof, fixture.now + Duration::seconds(2))
                .expect_err("old lease is permanently fenced")
                .code(),
            "BROWSER_CONTROL_LEASE_LOST"
        );
        let fresh = fixture
            .workspace
            .agent_lease_proof(fixture.now + Duration::seconds(2))
            .expect("fresh lease");
        assert_eq!(fresh.generation, 3);
        assert_eq!(fresh.lease_id, BrowserControlLeaseId::from("lease-3"));
    }

    #[test]
    fn prompt_injection_allows_observation_but_blocks_followup_action() {
        let mut fixture = fixture(BrowserPromptRisk::SuspectedInjection);
        let snapshot = observe(&mut fixture);
        let batch = read_batch(
            &fixture,
            vec![action(
                1,
                BrowserActionKind::Resolve,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(snapshot.id),
                Some("element-1"),
            )],
        )
        .expect("read batch");
        let mut cursor = fixture
            .host
            .begin_read_only_batch(&batch, fixture.now)
            .expect("begin read");

        assert_eq!(
            fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect_err("injected page must stop action")
                .code(),
            "BROWSER_PROMPT_INJECTION_DETECTED"
        );
    }

    #[test]
    fn live_account_origin_and_prompt_fences_recheck_between_steps() {
        for drift in ["account", "origin", "prompt"] {
            let mut fixture = fixture(BrowserPromptRisk::None);
            let snapshot = observe(&mut fixture);
            let batch = read_batch(
                &fixture,
                vec![
                    action(
                        1,
                        BrowserActionKind::Verify,
                        BrowserActionRisk::ReadOnly,
                        &fixture.tab_id,
                        Some(snapshot.id.clone()),
                        None,
                    ),
                    action(
                        2,
                        BrowserActionKind::Resolve,
                        BrowserActionRisk::ReadOnly,
                        &fixture.tab_id,
                        Some(snapshot.id),
                        Some("element-1"),
                    ),
                ],
            )
            .expect("two-step batch");
            let mut cursor = fixture
                .host
                .begin_read_only_batch(&batch, fixture.now)
                .expect("begin two-step batch");
            assert!(
                fixture
                    .host
                    .execute_next(&mut cursor, fixture.now)
                    .expect("first observed step")
                    .is_some()
            );

            let state = fixture
                .host
                .workspaces
                .get_mut(&fixture.workspace.id)
                .expect("registered workspace");
            let page = state
                .pages
                .get_mut(&fixture.tab_id)
                .expect("registered page");
            let expected_code = match drift {
                "account" => {
                    page.identity_digest = sha('0');
                    "BROWSER_ACCOUNT_IDENTITY_MISMATCH"
                }
                "origin" => {
                    page.origin_digest = sha('0');
                    "BROWSER_NAVIGATION_TARGET_REJECTED"
                }
                "prompt" => {
                    page.prompt_risk = BrowserPromptRisk::SuspectedInjection;
                    "BROWSER_PROMPT_INJECTION_DETECTED"
                }
                _ => unreachable!("bounded drift fixture"),
            };

            let failure = fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect_err("live drift must stop the second step");
            assert_eq!(failure.code(), expected_code);
            assert_eq!(cursor.completed_action_count(), 1);
            assert_eq!(cursor.observed_action_count(), 1);
            assert!(!cursor.external_write_may_have_occurred());
            assert!(!cursor.requires_reconciliation(&failure));
            assert!(cursor.is_terminal());
        }
    }

    #[test]
    fn full_snapshot_uses_existing_page_digests_and_element_refs_as_one_fence() {
        for drift in ["url", "content", "redaction", "document", "elements"] {
            let mut fixture = fixture(BrowserPromptRisk::None);
            let snapshot = observe(&mut fixture);
            let batch = read_batch(
                &fixture,
                vec![action(
                    1,
                    BrowserActionKind::Verify,
                    BrowserActionRisk::ReadOnly,
                    &fixture.tab_id,
                    Some(snapshot.id),
                    None,
                )],
            )
            .expect("snapshot-bound batch");
            let state = fixture
                .host
                .workspaces
                .get_mut(&fixture.workspace.id)
                .expect("registered workspace");
            let page = state
                .pages
                .get_mut(&fixture.tab_id)
                .expect("registered page");
            match drift {
                "url" => page.url_digest = sha('a'),
                "content" => page.content_digest = sha('b'),
                "redaction" => page.redaction_digest = sha('c'),
                "document" => page.document_generation = 2,
                "elements" => page.element_refs.clear(),
                _ => unreachable!("bounded snapshot fixture"),
            }
            let mut cursor = fixture
                .host
                .begin_read_only_batch(&batch, fixture.now)
                .expect("begin remains lease and account valid");

            let failure = fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect_err("canonical snapshot drift must fail closed");
            assert_eq!(failure.code(), "BROWSER_STALE_SNAPSHOT");
            assert_eq!(cursor.completed_action_count(), 0);
            assert_eq!(cursor.observed_action_count(), 0);
            assert!(!cursor.external_write_may_have_occurred());
            assert!(!cursor.requires_reconciliation(&failure));
            assert!(cursor.is_terminal());
        }
    }

    #[test]
    fn page_change_and_hidden_reference_are_independently_fenced() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let resolve = action(
            1,
            BrowserActionKind::Resolve,
            BrowserActionRisk::ReadOnly,
            &fixture.tab_id,
            Some(snapshot.id.clone()),
            Some("element-1"),
        );
        let batch = read_batch(&fixture, vec![resolve]).expect("read batch");
        let replacement = FakeBrowserPage {
            tab_id: fixture.tab_id.clone(),
            identity_digest: sha('1'),
            url_digest: sha('4'),
            origin_digest: sha('8'),
            content_digest: sha('f'),
            redaction_digest: sha('6'),
            document_generation: 2,
            prompt_risk: BrowserPromptRisk::None,
            element_refs: Vec::new(),
        };
        fixture
            .host
            .replace_page(&fixture.workspace.id, replacement)
            .expect("replace page");
        let mut cursor = fixture
            .host
            .begin_read_only_batch(&batch, fixture.now)
            .expect("begin remains lease-valid");
        assert_eq!(
            fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect_err("document replacement invalidates snapshot")
                .code(),
            "BROWSER_STALE_SNAPSHOT"
        );

        let fresh = fixture
            .host
            .observe(
                &fixture.workspace.id,
                &fixture
                    .workspace
                    .agent_lease_proof(fixture.now)
                    .expect("lease"),
                BrowserSnapshotId::from("snapshot-2"),
                &fixture.tab_id,
                fixture.now,
            )
            .expect("fresh observe");
        let bad_ref = read_batch_with_id(
            &fixture,
            "batch-read-2",
            vec![action(
                1,
                BrowserActionKind::Resolve,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(fresh.id),
                Some("missing-element"),
            )],
        )
        .expect("batch with unresolved temporary ref");
        let mut cursor = fixture
            .host
            .begin_read_only_batch(&bad_ref, fixture.now)
            .expect("begin bad-ref batch");
        assert_eq!(
            fixture
                .host
                .execute_next(&mut cursor, fixture.now)
                .expect_err("unknown ref is stale")
                .code(),
            "BROWSER_STALE_ELEMENT_REF"
        );
    }

    #[test]
    fn account_drift_is_detected_before_batch_execution() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let batch = read_batch(
            &fixture,
            vec![action(
                1,
                BrowserActionKind::Verify,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(snapshot.id),
                None,
            )],
        )
        .expect("read batch");
        fixture
            .host
            .replace_page(
                &fixture.workspace.id,
                FakeBrowserPage {
                    tab_id: fixture.tab_id.clone(),
                    identity_digest: sha('0'),
                    url_digest: sha('4'),
                    origin_digest: sha('8'),
                    content_digest: sha('5'),
                    redaction_digest: sha('6'),
                    document_generation: 2,
                    prompt_risk: BrowserPromptRisk::None,
                    element_refs: Vec::new(),
                },
            )
            .expect("replace with drifted account fixture");

        assert_eq!(
            fixture
                .host
                .begin_read_only_batch(&batch, fixture.now)
                .expect_err("identity drift must fail before actions")
                .code(),
            "BROWSER_ACCOUNT_IDENTITY_MISMATCH"
        );
    }

    #[test]
    fn read_only_api_refuses_writes_and_effect_binding_is_exact() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let click = action(
            1,
            BrowserActionKind::Click,
            BrowserActionRisk::PotentialExternalWrite,
            &fixture.tab_id,
            Some(snapshot.id),
            Some("element-1"),
        );
        assert_eq!(
            read_batch(&fixture, vec![click.clone()])
                .expect_err("read-only path cannot carry a write")
                .code(),
            "BROWSER_EFFECT_BROKER_REQUIRED"
        );

        let effect = approved_effect(&fixture, std::slice::from_ref(&click));
        let batch = effect_batch(&fixture, vec![click], &effect);
        let mut swapped = effect.clone();
        swapped.account_id = Some(AccountId::from("account-swapped"));
        let mut executor = FakeBrowserEffectExecutor::new(&mut fixture.host, batch, fixture.now);
        assert!(matches!(
            executor.execute(&swapped),
            Err(ProviderFailure::Rejected(reason))
                if reason == "BROWSER_EFFECT_SCOPE_MISMATCH"
        ));
    }

    #[test]
    fn caller_cannot_downgrade_click_risk_or_open_script_protocol_surfaces() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let disguised_click = action(
            1,
            BrowserActionKind::Click,
            BrowserActionRisk::ReadOnly,
            &fixture.tab_id,
            Some(snapshot.id.clone()),
            Some("element-1"),
        );
        assert_eq!(
            disguised_click
                .validate()
                .expect_err("click risk cannot be caller-downgraded")
                .code(),
            "BROWSER_INVALID_ACTION"
        );
        for kind in [BrowserActionKind::PageScript, BrowserActionKind::Protocol] {
            let forbidden = action(
                1,
                kind,
                BrowserActionRisk::PotentialExternalWrite,
                &fixture.tab_id,
                Some(snapshot.id.clone()),
                None,
            );
            assert_eq!(
                forbidden
                    .validate()
                    .expect_err("B0 has no signed script/protocol whitelist")
                    .code(),
                "BROWSER_INVALID_ACTION"
            );
        }
    }

    #[test]
    fn host_receipt_is_only_a_candidate_and_post_write_failure_is_uncertain() {
        let mut failure_fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut failure_fixture);
        let actions = vec![
            action(
                1,
                BrowserActionKind::Click,
                BrowserActionRisk::PotentialExternalWrite,
                &failure_fixture.tab_id,
                Some(snapshot.id.clone()),
                Some("element-1"),
            ),
            action(
                2,
                BrowserActionKind::Click,
                BrowserActionRisk::PotentialExternalWrite,
                &failure_fixture.tab_id,
                Some(snapshot.id),
                Some("stale-element"),
            ),
        ];
        let effect = approved_effect(&failure_fixture, &actions);
        let batch = effect_batch(&failure_fixture, actions, &effect);
        let replay_batch = batch.clone();
        {
            let mut executor = FakeBrowserEffectExecutor::new(
                &mut failure_fixture.host,
                batch,
                failure_fixture.now,
            );
            assert!(matches!(
                executor.execute(&effect),
                Err(ProviderFailure::Uncertain(reason))
                    if reason == "BROWSER_STALE_ELEMENT_REF"
            ));
        }
        let mut replay_executor = FakeBrowserEffectExecutor::new(
            &mut failure_fixture.host,
            replay_batch,
            failure_fixture.now,
        );
        assert!(matches!(
            replay_executor.execute(&effect),
            Err(ProviderFailure::Rejected(reason))
                if reason == "BROWSER_REAL_ACTION_REJECTED"
        ));

        let mut success_fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut success_fixture);
        let actions = vec![action(
            1,
            BrowserActionKind::Click,
            BrowserActionRisk::PotentialExternalWrite,
            &success_fixture.tab_id,
            Some(snapshot.id),
            Some("element-1"),
        )];
        let effect = approved_effect(&success_fixture, &actions);
        let batch = effect_batch(&success_fixture, actions, &effect);
        let mut executor =
            FakeBrowserEffectExecutor::new(&mut success_fixture.host, batch, success_fixture.now);
        let receipt = executor.execute(&effect).expect("candidate receipt");
        assert_eq!(receipt.request_digest, effect.payload_digest);
        assert!(effect.verification.is_none());
        assert_eq!(effect.status, EffectStatus::Approved);
    }

    #[test]
    fn pre_input_fence_is_rejected_without_claiming_a_business_write() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let mut click = action(
            1,
            BrowserActionKind::Click,
            BrowserActionRisk::PotentialExternalWrite,
            &fixture.tab_id,
            Some(snapshot.id),
            Some("element-1"),
        );
        click.target_origin_digest = sha('0');
        let actions = vec![click];
        let effect = approved_effect(&fixture, &actions);
        let batch = effect_batch(&fixture, actions, &effect);
        let mut executor = FakeBrowserEffectExecutor::new(&mut fixture.host, batch, fixture.now);

        assert!(matches!(
            executor.execute(&effect),
            Err(ProviderFailure::Rejected(reason))
                if reason == "BROWSER_NAVIGATION_TARGET_REJECTED"
        ));
    }

    #[test]
    fn post_input_failure_is_uncertain_and_same_session_batch_never_replays() {
        let mut executor_fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut executor_fixture);
        let actions = vec![action(
            1,
            BrowserActionKind::Click,
            BrowserActionRisk::PotentialExternalWrite,
            &executor_fixture.tab_id,
            Some(snapshot.id),
            Some("element-1"),
        )];
        let effect = approved_effect(&executor_fixture, &actions);
        let batch = effect_batch(&executor_fixture, actions, &effect);
        let replay_batch = batch.clone();
        executor_fixture
            .host
            .fail_after_next_external_input_for_test();
        {
            let mut executor = FakeBrowserEffectExecutor::new(
                &mut executor_fixture.host,
                batch,
                executor_fixture.now,
            );
            assert!(matches!(
                executor.execute(&effect),
                Err(ProviderFailure::Uncertain(reason)) if reason == "BROWSER_HOST_EXITED"
            ));
        }
        let mut replay_executor = FakeBrowserEffectExecutor::new(
            &mut executor_fixture.host,
            replay_batch,
            executor_fixture.now,
        );
        assert!(matches!(
            replay_executor.execute(&effect),
            Err(ProviderFailure::Rejected(reason))
                if reason == "BROWSER_REAL_ACTION_REJECTED"
        ));

        let mut cursor_fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut cursor_fixture);
        let actions = vec![action(
            1,
            BrowserActionKind::Click,
            BrowserActionRisk::PotentialExternalWrite,
            &cursor_fixture.tab_id,
            Some(snapshot.id),
            Some("element-1"),
        )];
        let effect = approved_effect(&cursor_fixture, &actions);
        let batch = effect_batch(&cursor_fixture, actions, &effect);
        cursor_fixture
            .host
            .fail_after_next_external_input_for_test();
        let mut cursor = cursor_fixture
            .host
            .begin_effect_batch(&batch, &effect, None, cursor_fixture.now)
            .expect("begin input cursor");
        let failure = cursor_fixture
            .host
            .execute_next_effect(&mut cursor, &effect, None, cursor_fixture.now)
            .expect_err("injected post-input host failure");
        assert_eq!(failure.code(), "BROWSER_HOST_EXITED");
        assert_eq!(cursor.completed_action_count(), 0);
        assert_eq!(cursor.observed_action_count(), 1);
        assert!(cursor.external_write_may_have_occurred());
        assert!(cursor.requires_reconciliation(&failure));
        assert!(cursor.is_terminal());
        assert_eq!(
            cursor_fixture
                .host
                .execute_next_effect(&mut cursor, &effect, None, cursor_fixture.now)
                .expect_err("failed input cursor cannot retry")
                .code(),
            "BROWSER_REAL_ACTION_REJECTED"
        );
    }

    #[test]
    fn host_restart_invalidates_inflight_cursor_and_requires_reobservation() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let batch = read_batch(
            &fixture,
            vec![action(
                1,
                BrowserActionKind::Verify,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(snapshot.id),
                None,
            )],
        )
        .expect("read batch");
        let mut cursor = fixture
            .host
            .begin_read_only_batch(&batch, fixture.now)
            .expect("cursor");
        let mut restarted = FakeBrowserHost::new();
        restarted
            .register_workspace(
                fixture.profile.clone(),
                fixture.workspace.clone(),
                vec![FakeBrowserPage {
                    tab_id: fixture.tab_id.clone(),
                    identity_digest: sha('1'),
                    url_digest: sha('4'),
                    origin_digest: sha('8'),
                    content_digest: sha('5'),
                    redaction_digest: sha('6'),
                    document_generation: 1,
                    prompt_risk: BrowserPromptRisk::None,
                    element_refs: vec![BrowserElementRef {
                        reference: "element-1".into(),
                        locator_digest: sha('7'),
                        visible: true,
                        unique: true,
                    }],
                }],
            )
            .expect("restart registration");

        let restart_failure = restarted
            .execute_next(&mut cursor, fixture.now)
            .expect_err("old cursor is bound to dead host session");
        assert_eq!(restart_failure.code(), "BROWSER_HOST_RESTARTED");
        assert!(cursor.is_terminal());
        assert!(cursor.requires_reconciliation(&restart_failure));
        assert!(!cursor.external_write_may_have_occurred());
        assert_eq!(cursor.completed_action_count(), 0);
        assert_eq!(cursor.observed_action_count(), 0);
        assert_eq!(
            restarted
                .execute_next(&mut cursor, fixture.now)
                .expect_err("restarted cursor is terminal and cannot replay")
                .code(),
            "BROWSER_REAL_ACTION_REJECTED"
        );
        let fresh_batch = read_batch(
            &fixture,
            vec![action(
                1,
                BrowserActionKind::Verify,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(BrowserSnapshotId::from("snapshot-1")),
                None,
            )],
        )
        .expect("fresh-shaped batch");
        let mut fresh_cursor = restarted
            .begin_read_only_batch(&fresh_batch, fixture.now)
            .expect("new host accepts lease-bound batch");
        let stale_failure = restarted
            .execute_next(&mut fresh_cursor, fixture.now)
            .expect_err("snapshot cache is intentionally not restored");
        assert_eq!(stale_failure.code(), "BROWSER_STALE_SNAPSHOT");
        assert!(fresh_cursor.is_terminal());
        assert!(!fresh_cursor.requires_reconciliation(&stale_failure));
        assert!(!fresh_cursor.external_write_may_have_occurred());
    }

    #[test]
    fn cancellation_and_authority_revocation_stop_before_the_next_host_action() {
        for revoke_approval in [false, true] {
            let mut fixture = fixture(BrowserPromptRisk::None);
            let snapshot = observe(&mut fixture);
            let actions = vec![
                action(
                    1,
                    BrowserActionKind::Click,
                    BrowserActionRisk::PotentialExternalWrite,
                    &fixture.tab_id,
                    Some(snapshot.id.clone()),
                    Some("element-1"),
                ),
                action(
                    2,
                    BrowserActionKind::Click,
                    BrowserActionRisk::PotentialExternalWrite,
                    &fixture.tab_id,
                    Some(snapshot.id.clone()),
                    Some("element-1"),
                ),
            ];
            let mut effect = approved_effect(&fixture, &actions);
            let batch = effect_batch(&fixture, actions, &effect);
            let mut cursor = fixture
                .host
                .begin_effect_batch(&batch, &effect, None, fixture.now)
                .expect("begin authorized batch");
            let first = fixture
                .host
                .execute_next_effect(&mut cursor, &effect, None, fixture.now)
                .expect("first authorized action")
                .expect("first result");
            assert_eq!(first.action_sequence, 1);
            let acknowledged = cursor.receipt().expect("acknowledged first prefix");
            assert_eq!(acknowledged.completed_action_count, 1);
            assert_eq!(acknowledged.state, BrowserBatchReceiptState::Active);

            if revoke_approval {
                effect.approval.as_mut().expect("approval").decision = ApprovalDecision::Rejected;
            } else {
                effect.status = EffectStatus::Cancelled;
            }
            let failure = fixture
                .host
                .execute_next_effect(
                    &mut cursor,
                    &effect,
                    None,
                    fixture.now + Duration::seconds(1),
                )
                .expect_err("changed authority must stop before action two");
            assert_eq!(failure.code(), "BROWSER_EFFECT_BROKER_REQUIRED");
            assert_eq!(cursor.completed_action_count(), 1);
            assert_eq!(cursor.observed_action_count(), 1);
            assert!(cursor.is_terminal());
            let failed = cursor.receipt().expect("terminal exact prefix");
            assert_eq!(failed.completed_action_count, 1);
            assert_eq!(failed.acknowledged_results, vec![first]);
            assert_eq!(failed.state, BrowserBatchReceiptState::Failed);
            assert_eq!(failed.result_digest, acknowledged.result_digest);
            assert_eq!(
                fixture
                    .host
                    .execute_next_effect(
                        &mut cursor,
                        &effect,
                        None,
                        fixture.now + Duration::seconds(1),
                    )
                    .expect_err("terminal cursor cannot dispatch action two")
                    .code(),
                "BROWSER_REAL_ACTION_REJECTED"
            );
        }
    }

    #[test]
    fn durable_prefix_replay_requires_exact_digests_and_skips_acknowledged_input() {
        let mut initial = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut initial);
        let actions = vec![
            action(
                1,
                BrowserActionKind::Click,
                BrowserActionRisk::PotentialExternalWrite,
                &initial.tab_id,
                Some(snapshot.id.clone()),
                Some("element-1"),
            ),
            action(
                2,
                BrowserActionKind::Click,
                BrowserActionRisk::PotentialExternalWrite,
                &initial.tab_id,
                Some(snapshot.id),
                Some("element-1"),
            ),
        ];
        let effect = approved_effect(&initial, &actions);
        let batch = effect_batch(&initial, actions, &effect);
        let mut cursor = initial
            .host
            .begin_effect_batch(&batch, &effect, None, initial.now)
            .expect("begin effect batch");
        let first = initial
            .host
            .execute_next_effect(&mut cursor, &effect, None, initial.now)
            .expect("first action")
            .expect("first result");
        assert_eq!(first.action_sequence, 1);
        let receipt = cursor.receipt().expect("durable prefix receipt");
        assert_eq!(receipt.completed_action_count, 1);

        cursor
            .cancel(sha('d'))
            .expect("explicit cursor cancellation");
        assert_eq!(
            initial
                .host
                .execute_next_effect(&mut cursor, &effect, None, initial.now)
                .expect_err("cancelled cursor cannot dispatch action two")
                .code(),
            "BROWSER_REAL_ACTION_REJECTED"
        );
        let cancelled = cursor.receipt().expect("cancelled receipt");
        assert_eq!(cancelled.completed_action_count, 1);
        assert_eq!(cancelled.acknowledged_results, vec![first]);
        assert_eq!(cancelled.state, BrowserBatchReceiptState::Cancelled);

        let mut replay = fixture(BrowserPromptRisk::None);
        observe(&mut replay);
        for tampered in [
            {
                let mut value = receipt.clone();
                value.plan_digest = sha('e');
                value
            },
            {
                let mut value = receipt.clone();
                value.cursor_digest = sha('e');
                value
            },
            {
                let mut value = receipt.clone();
                value.result_digest = sha('e');
                value
            },
        ] {
            assert_eq!(
                replay
                    .host
                    .resume_effect_batch(&batch, &tampered, &effect, None, replay.now)
                    .expect_err("tampered durable prefix must fail closed")
                    .code(),
                "BROWSER_INVALID_BATCH_RECEIPT"
            );
        }

        let mut resumed = replay
            .host
            .resume_effect_batch(&batch, &receipt, &effect, None, replay.now)
            .expect("resume exact acknowledged prefix");
        assert_eq!(resumed.completed_action_count(), 1);
        let second = replay
            .host
            .execute_next_effect(&mut resumed, &effect, None, replay.now)
            .expect("execute only unacknowledged suffix")
            .expect("second result");
        assert_eq!(second.action_sequence, 2);
        assert_eq!(resumed.completed_action_count(), 2);
        assert!(
            replay
                .host
                .execute_next_effect(&mut resumed, &effect, None, replay.now)
                .expect("complete resumed batch")
                .is_none()
        );
        assert_eq!(
            resumed.receipt().expect("completed receipt").state,
            BrowserBatchReceiptState::Completed
        );
    }

    #[test]
    fn debug_surfaces_redact_credential_and_temporary_element_reference() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let batch = read_batch(
            &fixture,
            vec![action(
                1,
                BrowserActionKind::Resolve,
                BrowserActionRisk::ReadOnly,
                &fixture.tab_id,
                Some(snapshot.id.clone()),
                Some("element-1"),
            )],
        )
        .expect("debug batch");
        let mut cursor = fixture
            .host
            .begin_read_only_batch(&batch, fixture.now)
            .expect("debug cursor");
        let result = fixture
            .host
            .execute_next(&mut cursor, fixture.now)
            .expect("debug action")
            .expect("debug result");
        let profile_debug = format!("{:?}", fixture.profile);
        let snapshot_debug = format!("{snapshot:?}");
        let host_debug = format!("{:?}", fixture.host);
        let cursor_debug = format!("{cursor:?}");
        let result_debug = format!("{result:?}");

        assert!(!profile_debug.contains(CREDENTIAL_REFERENCE));
        assert!(!snapshot_debug.contains("element-1"));
        assert!(!host_debug.contains(CREDENTIAL_REFERENCE));
        assert!(!host_debug.contains("element-1"));
        assert!(!cursor_debug.contains("element-1"));
        assert!(!result_debug.contains("element-1"));
        assert!(profile_debug.contains("credential_reference_digest"));
        assert!(snapshot_debug.contains("element_ref_count"));
        assert!(cursor_debug.contains("observation_count"));
    }
}

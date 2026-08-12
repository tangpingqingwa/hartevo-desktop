use std::collections::BTreeMap;
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
    BrowserAction, BrowserActionBatch, BrowserActionKind, BrowserActionRisk, BrowserControlHost,
    BrowserElementRef, BrowserError, BrowserLeaseProof, BrowserLocatorResolution,
    BrowserNavigationPolicy, BrowserProfile, BrowserPromptRisk,
    BrowserRecipeExecutionAuthorization, BrowserRecipePreparedPlan, BrowserRecipeRegistry,
    BrowserRecipeTrustStore, BrowserStableLocator, BrowserWorkspace, SemanticSnapshot,
};

static HOST_SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

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
}

impl fmt::Debug for FakeBrowserHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeBrowserHost")
            .field("session_digest", &digest(&self.session_id.to_le_bytes()))
            .field("workspace_count", &self.workspaces.len())
            .finish()
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
        &self,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<BrowserBatchCursor, BrowserError> {
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

    pub fn execute_next(
        &mut self,
        cursor: &mut BrowserBatchCursor,
        now: DateTime<Utc>,
    ) -> Result<Option<BrowserActionResult>, BrowserError> {
        if cursor.host_session_id != self.session_id {
            return Err(BrowserError::HostRestarted);
        }
        let state = self
            .workspaces
            .get(&cursor.batch.workspace_id)
            .ok_or(BrowserError::WorkspaceNotRegistered)?;
        cursor
            .batch
            .validate_for(&state.profile, &state.workspace, now)?;
        let Some(action) = cursor.batch.actions.get(cursor.next_action) else {
            return Ok(None);
        };
        validate_action_against_live_page(state, action)?;
        let action_digest = digest_json(action)?;
        let host_receipt_digest = digest_json(&(
            "hartevo-fake-browser-action/v1",
            self.session_id,
            cursor.batch.id.as_str(),
            action.sequence,
            &action_digest,
        ))?;
        cursor.next_action = cursor
            .next_action
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        if action.risk == BrowserActionRisk::PotentialExternalWrite {
            cursor.external_write_may_have_occurred = true;
        }
        Ok(Some(BrowserActionResult {
            batch_id: cursor.batch.id.clone(),
            action_sequence: action.sequence,
            action_digest,
            host_receipt_digest,
            external_write_may_have_occurred: cursor.external_write_may_have_occurred,
            business_verified: false,
        }))
    }

    fn begin_effect_batch(
        &self,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<BrowserBatchCursor, BrowserError> {
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

    fn begin_batch(
        &self,
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
        Ok(BrowserBatchCursor {
            batch: batch.clone(),
            host_session_id: self.session_id,
            next_action: 0,
            external_write_may_have_occurred: false,
        })
    }
}

impl BrowserControlHost for FakeBrowserHost {
    fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
        Self::sync_workspace(self, workspace)
    }
}

#[derive(Clone)]
pub struct BrowserBatchCursor {
    batch: BrowserActionBatch,
    host_session_id: u64,
    next_action: usize,
    external_write_may_have_occurred: bool,
}

impl BrowserBatchCursor {
    pub fn completed_action_count(&self) -> usize {
        self.next_action
    }

    pub fn external_write_may_have_occurred(&self) -> bool {
        self.external_write_may_have_occurred
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
            .field(
                "external_write_may_have_occurred",
                &self.external_write_may_have_occurred,
            )
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserActionResult {
    pub batch_id: BrowserActionBatchId,
    pub action_sequence: u32,
    pub action_digest: String,
    pub host_receipt_digest: String,
    pub external_write_may_have_occurred: bool,
    pub business_verified: bool,
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
        match self.recipe_authorization.as_ref() {
            Some(authorization) => authorization
                .validate_effect(&self.batch, effect, self.now)
                .map_err(|error| ProviderFailure::Rejected(error.code().into()))?,
            None if self.batch.recipe_binding_digest.is_some() => {
                return Err(ProviderFailure::Rejected(
                    BrowserError::RecipeRuntimeAuthorizationRequired
                        .code()
                        .into(),
                ));
            }
            None => self
                .batch
                .validate_effect(effect, self.now)
                .map_err(|error| ProviderFailure::Rejected(error.code().into()))?,
        }
        let mut cursor = self
            .host
            .begin_effect_batch(&self.batch, self.now)
            .map_err(|error| ProviderFailure::Rejected(error.code().into()))?;
        let mut results = Vec::new();
        loop {
            match self.host.execute_next(&mut cursor, self.now) {
                Ok(Some(result)) => results.push(result),
                Ok(None) => break,
                Err(error) if cursor.external_write_may_have_occurred() => {
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

fn validate_action_against_live_page(
    state: &FakeBrowserWorkspaceState,
    action: &BrowserAction,
) -> Result<(), BrowserError> {
    let page = state
        .pages
        .get(&action.tab_id)
        .ok_or(BrowserError::TabNotFound)?;
    if page.identity_digest != state.workspace.expected_identity_digest {
        return Err(BrowserError::AccountIdentityMismatch);
    }
    if page.prompt_risk != BrowserPromptRisk::None
        && !matches!(
            action.kind,
            BrowserActionKind::Observe | BrowserActionKind::Verify
        )
    {
        return Err(BrowserError::PromptInjectionDetected);
    }
    if let Some(snapshot_id) = action.snapshot_id.as_ref() {
        let snapshot = state
            .latest_snapshots
            .get(&action.tab_id)
            .ok_or(BrowserError::StaleSnapshot)?;
        if &snapshot.id != snapshot_id
            || snapshot.lease_generation != state.workspace.lease_generation
            || snapshot.document_generation != page.document_generation
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
    }
    Ok(())
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
    use crate::BrowserActionSurface;

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
        BrowserActionBatch::read_only(
            BrowserActionBatchId::from("batch-read-1"),
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
                .begin_effect_batch(&batch, fixture.now)
                .expect("begin batch");
            assert!(
                fixture
                    .host
                    .execute_next(&mut cursor, fixture.now)
                    .expect("first action")
                    .is_some()
            );

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
                .execute_next(&mut cursor, fixture.now + Duration::seconds(1))
                .expect_err("old batch must be stopped before queued write");
            assert_eq!(failure.code(), "BROWSER_CONTROL_LEASE_LOST");
            assert_eq!(cursor.completed_action_count(), 1);
            assert!(!cursor.external_write_may_have_occurred());
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
        let bad_ref = read_batch(
            &fixture,
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
        let mut executor =
            FakeBrowserEffectExecutor::new(&mut failure_fixture.host, batch, failure_fixture.now);

        assert!(matches!(
            executor.execute(&effect),
            Err(ProviderFailure::Uncertain(reason))
                if reason == "BROWSER_STALE_ELEMENT_REF"
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

        assert_eq!(
            restarted
                .execute_next(&mut cursor, fixture.now)
                .expect_err("old cursor is bound to dead host session")
                .code(),
            "BROWSER_HOST_RESTARTED"
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
        assert_eq!(
            restarted
                .execute_next(&mut fresh_cursor, fixture.now)
                .expect_err("snapshot cache is intentionally not restored")
                .code(),
            "BROWSER_STALE_SNAPSHOT"
        );
    }

    #[test]
    fn debug_surfaces_redact_credential_and_temporary_element_reference() {
        let mut fixture = fixture(BrowserPromptRisk::None);
        let snapshot = observe(&mut fixture);
        let profile_debug = format!("{:?}", fixture.profile);
        let snapshot_debug = format!("{snapshot:?}");
        let host_debug = format!("{:?}", fixture.host);

        assert!(!profile_debug.contains(CREDENTIAL_REFERENCE));
        assert!(!snapshot_debug.contains("element-1"));
        assert!(!host_debug.contains(CREDENTIAL_REFERENCE));
        assert!(profile_debug.contains("credential_reference_digest"));
        assert!(snapshot_debug.contains("element_ref_count"));
    }
}

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserSnapshotId, BrowserTabId, Mission};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use crate::ChromiumLaunchConfig;
use crate::workspace::{digest_json, is_bounded_identifier};
use crate::{
    AuthenticatedChromiumProvider, BrowserError, BrowserObservationObjectiveRequest,
    BrowserObservationResult, BrowserProfile, BrowserProfileSource, BrowserProfileStatus,
    BrowserProviderLifecycle, BrowserWorkspace, BrowserWorkspaceScope,
    BrowserWorkspaceServiceDefinition, DurableBrowserObservation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionBrowserWorkspaceState {
    Unselected,
    Selected,
    MountedAgent,
    TakenOverByUser,
    Unmounted,
    Revoked,
    Crashed,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserObservationResultLog {
    pub schema_version: u32,
    pub scope: BrowserWorkspaceScope,
    pub entries: Vec<BrowserObservationResult>,
    pub log_digest: String,
}

impl BrowserObservationResultLog {
    fn new(scope: BrowserWorkspaceScope) -> Result<Self, BrowserError> {
        scope.validate()?;
        let log = Self {
            schema_version: 1,
            scope,
            entries: Vec::new(),
            log_digest: String::new(),
        };
        let log_digest = log.unsigned_digest()?;
        Ok(Self { log_digest, ..log })
    }

    fn append(&mut self, result: BrowserObservationResult) -> Result<(), BrowserError> {
        result.validate()?;
        if result.observation.workspace_id != self.scope.workspace_id
            || result.observation.profile_id != self.scope.profile_id
            || result.observation.mission_id != self.scope.mission_id
            || result.observation.project_id != self.scope.project_id
            || result.observation.tenant_id != self.scope.tenant_id
        {
            return Err(BrowserError::ScopeMismatch);
        }
        if let Some(existing) = self.entries.iter().find(|existing| {
            existing.objective_id == result.objective_id
                || existing.cursor_id == result.cursor_id
                || existing.observation.observation_id == result.observation.observation_id
        }) {
            if existing == &result {
                return Ok(());
            }
            return Err(BrowserError::InvalidObservationObjective);
        }
        self.entries.push(result);
        self.log_digest = self.unsigned_digest()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        self.scope.validate()?;
        if self.schema_version != 1 || self.log_digest != self.unsigned_digest()? {
            return Err(BrowserError::InvalidObservationObjective);
        }
        let mut objectives = std::collections::BTreeSet::new();
        let mut cursors = std::collections::BTreeSet::new();
        for result in &self.entries {
            result.validate()?;
            if !objectives.insert(result.objective_id.clone())
                || !cursors.insert(result.cursor_id.clone())
            {
                return Err(BrowserError::InvalidObservationObjective);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        Ok(self.log_digest.clone())
    }

    fn unsigned_digest(&self) -> Result<String, BrowserError> {
        digest_json(&(&self.schema_version, &self.scope, &self.entries))
    }
}

impl fmt::Debug for BrowserObservationResultLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserObservationResultLog")
            .field("schema_version", &self.schema_version)
            .field("scope", &self.scope)
            .field("entry_count", &self.entries.len())
            .field("log_digest", &self.log_digest)
            .finish()
    }
}

pub struct MissionBrowserWorkspaceConsumer {
    tenant_id: hartevo_domain_kernel::TenantId,
    project_id: hartevo_domain_kernel::ProjectId,
    mission_id: hartevo_domain_kernel::MissionId,
    selected_profile: Option<BrowserProfile>,
    selected_workspace: Option<BrowserWorkspace>,
    provider: Option<AuthenticatedChromiumProvider>,
    result_log: Option<BrowserObservationResultLog>,
    state: MissionBrowserWorkspaceState,
}

impl MissionBrowserWorkspaceConsumer {
    pub fn new(mission: &Mission) -> Result<Self, BrowserError> {
        if !is_bounded_identifier(mission.tenant_id.as_str())
            || !is_bounded_identifier(mission.project_id.as_str())
            || !is_bounded_identifier(mission.id.as_str())
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            selected_profile: None,
            selected_workspace: None,
            provider: None,
            result_log: None,
            state: MissionBrowserWorkspaceState::Unselected,
        })
    }

    pub fn state(&self) -> MissionBrowserWorkspaceState {
        self.state
    }

    pub fn selected_profile(&self) -> Option<&BrowserProfile> {
        self.selected_profile.as_ref()
    }

    pub fn selected_workspace(&self) -> Option<&BrowserWorkspace> {
        self.selected_workspace.as_ref()
    }

    pub fn provider(&self) -> Option<&AuthenticatedChromiumProvider> {
        self.provider.as_ref()
    }

    pub fn select_profile(
        &mut self,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
    ) -> Result<(), BrowserError> {
        self.validate_selection(&profile, &workspace)?;
        if self.provider.is_some() {
            return Err(BrowserError::InvalidControlTransition);
        }
        let scope = BrowserWorkspaceScope::bind(&profile, &workspace)?;
        self.selected_profile = Some(profile);
        self.selected_workspace = Some(workspace);
        self.result_log = Some(BrowserObservationResultLog::new(scope)?);
        self.state = MissionBrowserWorkspaceState::Selected;
        Ok(())
    }

    pub fn reselect_profile(
        &mut self,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.provider.is_some() {
            self.unmount(evidence_digest, now)?;
        }
        self.select_profile(profile, workspace)
    }

    #[cfg(unix)]
    pub fn mount(
        &mut self,
        definition: BrowserWorkspaceServiceDefinition,
        config: &ChromiumLaunchConfig,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.mount_chromium(definition, config, now)
    }

    #[cfg(unix)]
    pub fn mount_chromium(
        &mut self,
        definition: BrowserWorkspaceServiceDefinition,
        config: &ChromiumLaunchConfig,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.provider.is_some()
            || !matches!(
                self.state,
                MissionBrowserWorkspaceState::Selected | MissionBrowserWorkspaceState::Unmounted
            )
        {
            return Err(BrowserError::InvalidControlTransition);
        }
        let profile = self
            .selected_profile
            .clone()
            .ok_or(BrowserError::ScopeMismatch)?;
        let workspace = self
            .selected_workspace
            .clone()
            .ok_or(BrowserError::ScopeMismatch)?;
        let request = definition.mount_request(&profile, &workspace, now)?;
        let provider = AuthenticatedChromiumProvider::mount_chromium(
            definition, request, profile, workspace, config, now,
        )?;
        self.provider = Some(provider);
        self.state = MissionBrowserWorkspaceState::MountedAgent;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn mount_contract_for_test(
        &mut self,
        definition: BrowserWorkspaceServiceDefinition,
        frame_scope: crate::BrowserFrameScope,
        snapshot: crate::SemanticSnapshot,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.provider.is_some()
            || !matches!(
                self.state,
                MissionBrowserWorkspaceState::Selected | MissionBrowserWorkspaceState::Unmounted
            )
        {
            return Err(BrowserError::InvalidControlTransition);
        }
        let profile = self
            .selected_profile
            .clone()
            .ok_or(BrowserError::ScopeMismatch)?;
        let workspace = self
            .selected_workspace
            .clone()
            .ok_or(BrowserError::ScopeMismatch)?;
        let request = definition.mount_request(&profile, &workspace, now)?;
        let provider = AuthenticatedChromiumProvider::mount_contract_for_test(
            definition,
            request,
            profile,
            workspace,
            frame_scope,
            snapshot,
            now,
        )?;
        self.provider = Some(provider);
        self.state = MissionBrowserWorkspaceState::MountedAgent;
        Ok(())
    }

    #[cfg(unix)]
    pub fn observe_public_source(
        &mut self,
        tab_id: &BrowserTabId,
        snapshot_id: BrowserSnapshotId,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        if self
            .provider
            .as_ref()
            .ok_or(BrowserError::ControlLeaseLost)?
            .workspace()
            .active_tab_id
            != *tab_id
        {
            return Err(BrowserError::ScopeMismatch);
        }
        let request =
            self.request_observation(snapshot_id.clone(), snapshot_id, source_uri, now)?;
        let result = self.observe_objective(&request, now)?;
        if result.observation.tab_id != *tab_id {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(result.observation)
    }

    #[cfg(test)]
    pub(crate) fn observe_contract_snapshot_for_test(
        &mut self,
        snapshot: &crate::SemanticSnapshot,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        let request =
            self.request_observation(snapshot.id.clone(), snapshot.id.clone(), source_uri, now)?;
        Ok(self.observe_objective(&request, now)?.observation)
    }

    pub fn request_observation(
        &mut self,
        objective_id: BrowserSnapshotId,
        observation_id: BrowserSnapshotId,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<BrowserObservationObjectiveRequest, BrowserError> {
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)?
            .request_observation(objective_id, observation_id, source_uri, now);
        self.propagate_provider_crash();
        result
    }

    pub fn observe_objective(
        &mut self,
        request: &BrowserObservationObjectiveRequest,
        now: DateTime<Utc>,
    ) -> Result<BrowserObservationResult, BrowserError> {
        let validation = self
            .provider
            .as_ref()
            .ok_or(BrowserError::ControlLeaseLost)?
            .validate_observation_request(request, now);
        if let Err(error) = validation {
            self.propagate_provider_crash();
            return Err(error);
        }
        if let Some(log) = self.result_log.as_ref()
            && let Some(existing) = log
                .entries
                .iter()
                .find(|result| result.objective_id == request.objective_id)
        {
            if existing.request_digest == request.request_digest {
                return Ok(existing.clone());
            }
            return Err(BrowserError::InvalidObservationObjective);
        }
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)?
            .observe_objective(request, now);
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                self.propagate_provider_crash();
                return Err(error);
            }
        };
        self.result_log
            .as_mut()
            .ok_or(BrowserError::ScopeMismatch)?
            .append(result.clone())?;
        Ok(result)
    }

    pub fn observation(&self, id: &BrowserSnapshotId) -> Option<&DurableBrowserObservation> {
        self.result_log.as_ref()?.entries.iter().find_map(|result| {
            (result.observation.observation_id == *id).then_some(&result.observation)
        })
    }

    pub fn observations(&self) -> impl Iterator<Item = &DurableBrowserObservation> {
        self.result_log
            .as_ref()
            .into_iter()
            .flat_map(|log| log.entries.iter().map(|result| &result.observation))
    }

    pub fn observation_digest(&self) -> Result<String, BrowserError> {
        self.result_log
            .as_ref()
            .ok_or(BrowserError::ScopeMismatch)?
            .digest()
    }

    pub fn result_log(&self) -> Option<&BrowserObservationResultLog> {
        self.result_log.as_ref()
    }

    pub fn takeover_user(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)?
            .takeover_user(evidence_digest, now)?;
        self.sync_selected_workspace_from_provider()?;
        self.state = MissionBrowserWorkspaceState::TakenOverByUser;
        Ok(())
    }

    pub fn return_to_agent(
        &mut self,
        lease_expires_at: DateTime<Utc>,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)?
            .return_to_agent(lease_expires_at, evidence_digest, now)?;
        self.sync_selected_workspace_from_provider()?;
        self.state = MissionBrowserWorkspaceState::MountedAgent;
        Ok(())
    }

    pub fn mark_host_crashed(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let result = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)
            .and_then(|provider| provider.mark_host_crashed(evidence_digest, now));
        if let Err(error) = result {
            self.propagate_provider_crash();
            return Err(error);
        }
        self.sync_selected_workspace_from_provider()?;
        self.provider = None;
        self.state = MissionBrowserWorkspaceState::Crashed;
        Ok(())
    }

    pub fn unmount(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.state == MissionBrowserWorkspaceState::Revoked {
            return Err(BrowserError::InvalidControlTransition);
        }
        let unmount_result = self
            .provider
            .as_mut()
            .map(|provider| provider.unmount(evidence_digest, now));
        if let Some(Err(error)) = unmount_result {
            self.propagate_provider_crash();
            return Err(error);
        }
        if let Some(provider) = self.provider.as_ref() {
            self.selected_workspace = Some(provider.workspace().clone());
        }
        self.provider = None;
        self.state = if self.selected_profile.is_some() {
            MissionBrowserWorkspaceState::Unmounted
        } else {
            MissionBrowserWorkspaceState::Unselected
        };
        Ok(())
    }

    pub fn revoke_selected_profile(
        &mut self,
        expected_revision: u64,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserProfile, BrowserError> {
        let revoked = if let Some(mut provider) = self.provider.take() {
            match provider.revoke(expected_revision, evidence_digest.clone(), now) {
                Ok(profile) => profile,
                Err(error) => {
                    if provider.lifecycle() == BrowserProviderLifecycle::Crashed {
                        self.selected_workspace = Some(provider.workspace().clone());
                        self.provider = None;
                        self.state = MissionBrowserWorkspaceState::Crashed;
                    } else {
                        self.provider = Some(provider);
                    }
                    return Err(error);
                }
            }
        } else {
            let mut profile = self
                .selected_profile
                .clone()
                .ok_or(BrowserError::ScopeMismatch)?;
            profile.revoke(expected_revision, evidence_digest, now)?;
            profile
        };
        self.selected_profile = None;
        self.selected_workspace = None;
        self.result_log = None;
        self.state = MissionBrowserWorkspaceState::Revoked;
        Ok(revoked)
    }

    fn validate_selection(
        &self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
    ) -> Result<(), BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        if profile.source != BrowserProfileSource::Managed
            || profile.status != BrowserProfileStatus::Active
            || profile.tenant_id != self.tenant_id
            || profile.project_id != self.project_id
            || profile.id != workspace.profile_id
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || workspace.mission_id != self.mission_id
            || workspace.expected_identity_digest != profile.identity.identity_digest
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(())
    }

    fn sync_selected_workspace_from_provider(&mut self) -> Result<(), BrowserError> {
        let workspace = self
            .provider
            .as_ref()
            .ok_or(BrowserError::ControlLeaseLost)?
            .workspace()
            .clone();
        self.selected_workspace = Some(workspace);
        Ok(())
    }

    fn propagate_provider_crash(&mut self) {
        if self
            .provider
            .as_ref()
            .is_some_and(|provider| provider.lifecycle() == BrowserProviderLifecycle::Crashed)
        {
            if let Some(provider) = self.provider.as_ref() {
                self.selected_workspace = Some(provider.workspace().clone());
            }
            self.provider = None;
            self.state = MissionBrowserWorkspaceState::Crashed;
        }
    }
}

impl fmt::Debug for MissionBrowserWorkspaceConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrowserWorkspaceConsumer")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("selected_profile", &self.selected_profile)
            .field("selected_workspace", &self.selected_workspace)
            .field("provider", &self.provider)
            .field(
                "observation_count",
                &self.result_log.as_ref().map_or(0, |log| log.entries.len()),
            )
            .field("observation_digest", &self.observation_digest())
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, BrowserSnapshotId, BrowserTabId,
        BrowserWorkspaceId, MissionContract, MissionId, Project, ProjectId, StorageMode, TenantId,
    };

    use super::*;
    use crate::workspace::digest;
    use crate::{BrowserIdentity, SemanticSnapshot};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture() -> (Mission, BrowserProfile, BrowserWorkspace) {
        let now = now();
        let project = Project::create_local(
            TenantId::from("tenant-service"),
            ProjectId::from("project-service"),
            "Service",
            "",
            "/workspace/service",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-service"),
            project.id.clone(),
            "Research",
            MissionContract::bootstrap("read-only research", ["browser.read".into()], now),
            now,
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-service"),
            &project,
            "credential-manager://service",
            BrowserIdentity::new(
                "chromium",
                AccountId::from("account-service"),
                sha('1'),
                sha('2'),
                now,
            )
            .expect("identity"),
            now,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-service"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-service"),
            BrowserControlLeaseId::from("lease-service-1"),
            now + Duration::hours(1),
            sha('3'),
            now,
        )
        .expect("workspace");
        (mission, profile, workspace)
    }

    fn snapshot(workspace: &BrowserWorkspace, id: &str) -> SemanticSnapshot {
        let source = "https://example.test/germany";
        SemanticSnapshot::new(
            BrowserSnapshotId::from(id),
            workspace,
            workspace.active_tab_id.clone(),
            1,
            workspace.expected_identity_digest.clone(),
            digest(source.as_bytes()),
            sha('4'),
            sha('5'),
            crate::BrowserPromptRisk::None,
            Vec::new(),
            now() + Duration::seconds(1),
        )
        .expect("snapshot")
    }

    fn frame_scope(workspace: &BrowserWorkspace) -> crate::BrowserFrameScope {
        crate::BrowserFrameScope::from_test_values(
            workspace.active_tab_id.clone(),
            "frame-root",
            "loader-root",
            "https://example.test/germany",
            1,
        )
        .expect("frame scope")
    }

    #[test]
    fn mount_observe_takeover_and_return_fence_the_old_generation() {
        let (mission, profile, workspace) = fixture();
        let mut consumer = MissionBrowserWorkspaceConsumer::new(&mission).expect("consumer");
        consumer
            .select_profile(profile, workspace.clone())
            .expect("select");
        let definition = BrowserWorkspaceServiceDefinition::authenticated_chromium("provider-test")
            .expect("service");
        consumer
            .mount_contract_for_test(
                definition,
                frame_scope(&workspace),
                snapshot(&workspace, "observation-1"),
                now(),
            )
            .expect("mount");
        let observation = consumer
            .observe_contract_snapshot_for_test(
                &snapshot(&workspace, "observation-1"),
                "https://example.test/germany",
                now() + Duration::seconds(2),
            )
            .expect("observe");
        assert!(observation.authenticated);
        let old_generation = consumer
            .provider()
            .expect("provider")
            .workspace()
            .lease_generation;

        consumer
            .takeover_user(sha('6'), now() + Duration::seconds(3))
            .expect("takeover");
        assert_eq!(
            consumer.state(),
            MissionBrowserWorkspaceState::TakenOverByUser
        );
        assert!(matches!(
            consumer
                .observe_contract_snapshot_for_test(
                    &snapshot(&workspace, "observation-after-takeover"),
                    "https://example.test/germany",
                    now() + Duration::seconds(4),
                )
                .expect_err("user owns the browser"),
            BrowserError::ControlLeaseLost
        ));

        consumer
            .return_to_agent(
                now() + Duration::hours(1),
                sha('7'),
                now() + Duration::seconds(5),
            )
            .expect("return");
        let new_generation = consumer
            .provider()
            .expect("provider")
            .workspace()
            .lease_generation;
        assert_eq!(new_generation, old_generation + 2);
        assert_eq!(consumer.state(), MissionBrowserWorkspaceState::MountedAgent);
    }

    #[test]
    fn objective_cursor_result_log_is_exact_and_restart_cancels_old_cursor() {
        let (mission, profile, workspace) = fixture();
        let mut consumer = MissionBrowserWorkspaceConsumer::new(&mission).expect("consumer");
        consumer
            .select_profile(profile, workspace.clone())
            .expect("select");
        consumer
            .mount_contract_for_test(
                BrowserWorkspaceServiceDefinition::authenticated_chromium("provider-test")
                    .expect("service"),
                frame_scope(&workspace),
                snapshot(&workspace, "objective-observation"),
                now(),
            )
            .expect("mount");
        let request = consumer
            .request_observation(
                BrowserSnapshotId::from("objective-1"),
                BrowserSnapshotId::from("objective-observation"),
                "https://example.test/germany",
                now() + Duration::seconds(1),
            )
            .expect("objective request");
        let result = consumer
            .observe_objective(&request, now() + Duration::seconds(2))
            .expect("observation result");
        assert_eq!(result.objective_id, BrowserSnapshotId::from("objective-1"));
        assert_eq!(consumer.result_log().expect("log").entries.len(), 1);
        consumer
            .observe_objective(&request, now() + Duration::seconds(3))
            .expect("idempotent same cursor");

        let mut tampered = request.clone();
        tampered.cursor.cursor_id = "tampered-cursor".into();
        assert!(matches!(
            consumer
                .observe_objective(&tampered, now() + Duration::seconds(3))
                .expect_err("tampered cursor must fail closed"),
            BrowserError::InvalidObservationObjective | BrowserError::ObservationCursorInvalid
        ));

        // A host restart is terminal for this mounted provider. The paused
        // workspace and incremented epoch make every pre-restart cursor stale.
        consumer
            .mark_host_crashed(sha('9'), now() + Duration::seconds(4))
            .expect("restart cancellation");
        assert_eq!(consumer.state(), MissionBrowserWorkspaceState::Crashed);
        assert!(matches!(
            consumer
                .observe_objective(&request, now() + Duration::seconds(5))
                .expect_err("old cursor after crash"),
            BrowserError::ControlLeaseLost
        ));
        assert_eq!(
            consumer
                .selected_workspace()
                .expect("cancelled workspace")
                .control_state,
            crate::BrowserControlState::PausedAgent
        );
    }

    #[test]
    fn reselect_cleans_provider_and_observations_while_unmount_retains_result() {
        let (mission, profile, workspace) = fixture();
        let mut consumer = MissionBrowserWorkspaceConsumer::new(&mission).expect("consumer");
        consumer
            .select_profile(profile.clone(), workspace.clone())
            .expect("select");
        consumer
            .mount_contract_for_test(
                BrowserWorkspaceServiceDefinition::authenticated_chromium("provider-test")
                    .expect("service"),
                frame_scope(&workspace),
                snapshot(&workspace, "observation-2"),
                now(),
            )
            .expect("mount");
        let old_cursor_request = consumer
            .request_observation(
                BrowserSnapshotId::from("objective-unmount"),
                BrowserSnapshotId::from("observation-2"),
                "https://example.test/germany",
                now() + Duration::seconds(1),
            )
            .expect("objective request");
        consumer
            .observe_objective(&old_cursor_request, now() + Duration::seconds(2))
            .expect("observe");
        let before = consumer.observation_digest().expect("digest");
        consumer
            .unmount(sha('6'), now() + Duration::seconds(3))
            .expect("unmount");
        assert_eq!(consumer.state(), MissionBrowserWorkspaceState::Unmounted);
        assert_eq!(consumer.observation_digest().expect("digest"), before);
        assert!(matches!(
            consumer
                .observe_objective(&old_cursor_request, now() + Duration::seconds(4))
                .expect_err("unmounted cursor must fail closed"),
            BrowserError::ControlLeaseLost
        ));

        consumer
            .reselect_profile(profile, workspace, sha('7'), now() + Duration::seconds(5))
            .expect("reselect");
        assert_eq!(consumer.state(), MissionBrowserWorkspaceState::Selected);
        assert_eq!(consumer.observations().count(), 0);
        assert!(consumer.provider().is_none());
    }

    #[test]
    fn revoke_cleans_selection_and_durable_results() {
        let (mission, profile, workspace) = fixture();
        let revision = profile.revision;
        let mut consumer = MissionBrowserWorkspaceConsumer::new(&mission).expect("consumer");
        consumer
            .select_profile(profile, workspace.clone())
            .expect("select");
        consumer
            .mount_contract_for_test(
                BrowserWorkspaceServiceDefinition::authenticated_chromium("provider-test")
                    .expect("service"),
                frame_scope(&workspace),
                snapshot(&workspace, "observation-3"),
                now(),
            )
            .expect("mount");
        let old_cursor_request = consumer
            .request_observation(
                BrowserSnapshotId::from("objective-revoke"),
                BrowserSnapshotId::from("observation-3"),
                "https://example.test/germany",
                now() + Duration::seconds(1),
            )
            .expect("objective request");
        let revoked = consumer
            .revoke_selected_profile(revision, sha('8'), now() + Duration::seconds(1))
            .expect("revoke");
        assert_eq!(revoked.status, BrowserProfileStatus::Revoked);
        assert_eq!(consumer.state(), MissionBrowserWorkspaceState::Revoked);
        assert!(consumer.selected_profile().is_none());
        assert_eq!(consumer.observations().count(), 0);
        assert!(matches!(
            consumer
                .observe_objective(&old_cursor_request, now() + Duration::seconds(2))
                .expect_err("revoked cursor must fail closed"),
            BrowserError::ControlLeaseLost
        ));
        assert!(matches!(
            consumer
                .revoke_selected_profile(revision + 1, sha('9'), now() + Duration::seconds(2))
                .expect_err("revoked selection is terminal"),
            BrowserError::ScopeMismatch
        ));
    }

    #[test]
    #[ignore = "requires macOS, HARTEVO_TEST_CHROME_BINARY, and an explicitly headless mock Keychain"]
    fn real_chromium_provider_mount_handoff_smoke() {
        #[cfg(target_os = "macos")]
        {
            use std::path::PathBuf;
            use tempfile::TempDir;

            let executable = std::env::var_os("HARTEVO_TEST_CHROME_BINARY").map_or_else(
                || panic!("BLOCKED_ENV: reason=chrome_env_missing"),
                PathBuf::from,
            );
            if !executable
                .try_exists()
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=chrome_path_unavailable"))
            {
                panic!("BLOCKED_ENV: reason=chrome_path_missing");
            }
            let private_root = TempDir::new()
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=private_temp_root_unavailable"));
            let config = crate::ChromiumLaunchConfig::new(
                &executable,
                private_root.path().to_path_buf(),
                true,
            )
            .and_then(crate::ChromiumLaunchConfig::with_macos_mock_keychain_for_test)
            .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=chromium_config_unavailable"));
            let (mission, profile, workspace) = fixture();
            let mut consumer = MissionBrowserWorkspaceConsumer::new(&mission).expect("consumer");
            consumer.select_profile(profile, workspace).expect("select");
            consumer
                .mount_chromium(
                    BrowserWorkspaceServiceDefinition::authenticated_chromium("provider-smoke")
                        .expect("service"),
                    &config,
                    now(),
                )
                .unwrap_or_else(|error| panic!("BLOCKED_ENV: reason=chromium_mount:{error}"));
            consumer
                .takeover_user(sha('6'), now() + Duration::seconds(1))
                .expect("takeover");
            consumer
                .return_to_agent(
                    now() + Duration::hours(1),
                    sha('7'),
                    now() + Duration::seconds(2),
                )
                .expect("return");
            consumer
                .unmount(sha('8'), now() + Duration::seconds(3))
                .expect("unmount");
        }
        #[cfg(not(target_os = "macos"))]
        panic!("BLOCKED_ENV: reason=macos_required");
    }
}

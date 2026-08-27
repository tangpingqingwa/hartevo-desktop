use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserSnapshotId, BrowserTabId, Mission};

use crate::workspace::{digest_json, is_bounded_identifier};
use crate::{
    AuthenticatedChromiumProvider, BrowserError, BrowserProfile, BrowserProfileSource,
    BrowserProfileStatus, BrowserWorkspace, BrowserWorkspaceServiceDefinition,
    DurableBrowserObservation,
};
#[cfg(unix)]
use crate::{
    BrowserNavigationPolicy, BrowserNavigationReceipt, BrowserNavigationTarget,
    ChromiumLaunchConfig,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionBrowserWorkspaceState {
    Unselected,
    Selected,
    MountedAgent,
    TakenOverByUser,
    Unmounted,
    Revoked,
}

pub struct MissionBrowserWorkspaceConsumer {
    tenant_id: hartevo_domain_kernel::TenantId,
    project_id: hartevo_domain_kernel::ProjectId,
    mission_id: hartevo_domain_kernel::MissionId,
    selected_profile: Option<BrowserProfile>,
    selected_workspace: Option<BrowserWorkspace>,
    provider: Option<AuthenticatedChromiumProvider>,
    observations: BTreeMap<BrowserSnapshotId, DurableBrowserObservation>,
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
            observations: BTreeMap::new(),
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
            self.unmount()?;
        }
        self.observations.clear();
        self.selected_profile = Some(profile);
        self.selected_workspace = Some(workspace);
        self.state = MissionBrowserWorkspaceState::Selected;
        Ok(())
    }

    pub fn reselect_profile(
        &mut self,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
    ) -> Result<(), BrowserError> {
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
            definition, request, profile, workspace, now,
        )?;
        self.provider = Some(provider);
        self.state = MissionBrowserWorkspaceState::MountedAgent;
        Ok(())
    }

    #[cfg(unix)]
    pub fn navigate_allowlisted(
        &mut self,
        tab_id: &BrowserTabId,
        policy: &BrowserNavigationPolicy,
        target: &BrowserNavigationTarget,
        now: DateTime<Utc>,
    ) -> Result<BrowserNavigationReceipt, BrowserError> {
        self.provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)?
            .navigate_allowlisted(tab_id, policy, target, now)
    }

    #[cfg(unix)]
    pub fn observe_public_source(
        &mut self,
        tab_id: &BrowserTabId,
        snapshot_id: BrowserSnapshotId,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        let observation = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)?
            .observe_public_source(tab_id, snapshot_id, source_uri, now)?;
        self.record_observation(observation)
    }

    #[cfg(test)]
    pub(crate) fn observe_contract_snapshot_for_test(
        &mut self,
        snapshot: &crate::SemanticSnapshot,
        source_uri: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        let observation = self
            .provider
            .as_mut()
            .ok_or(BrowserError::ControlLeaseLost)?
            .record_snapshot_for_test(snapshot, source_uri, now)?;
        self.record_observation(observation)
    }

    fn record_observation(
        &mut self,
        observation: DurableBrowserObservation,
    ) -> Result<DurableBrowserObservation, BrowserError> {
        if let Some(existing) = self.observations.get(&observation.observation_id) {
            if existing != &observation {
                return Err(BrowserError::RealActionRejected);
            }
            return Ok(existing.clone());
        }
        self.observations
            .insert(observation.observation_id.clone(), observation.clone());
        Ok(observation)
    }

    pub fn observation(&self, id: &BrowserSnapshotId) -> Option<&DurableBrowserObservation> {
        self.observations.get(id)
    }

    pub fn observations(&self) -> impl Iterator<Item = &DurableBrowserObservation> {
        self.observations.values()
    }

    pub fn observation_digest(&self) -> Result<String, BrowserError> {
        digest_json(&self.observations.values().collect::<Vec<_>>())
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
        self.state = MissionBrowserWorkspaceState::MountedAgent;
        Ok(())
    }

    pub fn unmount(&mut self) -> Result<(), BrowserError> {
        if self.state == MissionBrowserWorkspaceState::Revoked {
            return Err(BrowserError::InvalidControlTransition);
        }
        if let Some(provider) = self.provider.as_mut() {
            provider.unmount()?;
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
                    self.provider = Some(provider);
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
        self.observations.clear();
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
            .field("observation_count", &self.observations.len())
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
            .mount_contract_for_test(definition, now())
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
                now(),
            )
            .expect("mount");
        consumer
            .observe_contract_snapshot_for_test(
                &snapshot(&workspace, "observation-2"),
                "https://example.test/germany",
                now() + Duration::seconds(1),
            )
            .expect("observe");
        let before = consumer.observation_digest().expect("digest");
        consumer.unmount().expect("unmount");
        assert_eq!(consumer.state(), MissionBrowserWorkspaceState::Unmounted);
        assert_eq!(consumer.observation_digest().expect("digest"), before);

        consumer
            .reselect_profile(profile, workspace)
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
        consumer.select_profile(profile, workspace).expect("select");
        consumer
            .mount_contract_for_test(
                BrowserWorkspaceServiceDefinition::authenticated_chromium("provider-test")
                    .expect("service"),
                now(),
            )
            .expect("mount");
        let revoked = consumer
            .revoke_selected_profile(revision, sha('8'), now() + Duration::seconds(1))
            .expect("revoke");
        assert_eq!(revoked.status, BrowserProfileStatus::Revoked);
        assert_eq!(consumer.state(), MissionBrowserWorkspaceState::Revoked);
        assert!(consumer.selected_profile().is_none());
        assert_eq!(consumer.observations().count(), 0);
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
            consumer.unmount().expect("unmount");
        }
        #[cfg(not(target_os = "macos"))]
        panic!("BLOCKED_ENV: reason=macos_required");
    }
}

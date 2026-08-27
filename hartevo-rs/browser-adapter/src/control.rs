//! Browser Workspace control coordinator.
//!
//! `BrowserWorkspace` is the durable, append-only scope and lease record. This
//! module is the live adapter-side boundary around that record: it owns the
//! profile/workspace pairing, admits only batches carrying the current Agent
//! lease, and turns a User takeover into an immediate cancellation fence for
//! every queued batch. Returning control always uses a new lease generation;
//! an old batch can never become executable again.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{BrowserActionBatchId, BrowserControlLeaseId};
use serde::{Deserialize, Serialize};

use crate::{
    BrowserActionBatch, BrowserControlHost, BrowserControlState, BrowserError, BrowserLeaseProof,
    BrowserProfile, BrowserProfileSource, BrowserProfileStatus, BrowserWorkspace,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserQueuedBatchState {
    Queued,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserQueuedBatch {
    pub batch_id: BrowserActionBatchId,
    pub batch_digest: String,
    pub lease_id: BrowserControlLeaseId,
    pub lease_generation: u64,
    pub state: BrowserQueuedBatchState,
}

impl BrowserQueuedBatch {
    fn validate(&self) -> Result<(), BrowserError> {
        if !is_bounded_identifier(self.batch_id.as_str())
            || !is_sha256(&self.batch_digest)
            || !is_bounded_identifier(self.lease_id.as_str())
            || self.lease_generation == 0
        {
            return Err(BrowserError::InvalidBatch);
        }
        Ok(())
    }
}

/// Content-free result of one live control transition.
///
/// The digest binds the resulting workspace state. `cancelled_batches` counts
/// queued action plans that were fenced by a User takeover; it does not imply
/// that any external write happened.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserControlHandoff {
    pub workspace_id: hartevo_domain_kernel::BrowserWorkspaceId,
    pub from_state: BrowserControlState,
    pub to_state: BrowserControlState,
    pub from_generation: u64,
    pub to_generation: u64,
    pub cancelled_batches: u32,
    pub workspace_digest: String,
}

impl BrowserControlHandoff {
    fn from_transition(
        previous: &BrowserWorkspace,
        next: &BrowserWorkspace,
        cancelled_batches: usize,
    ) -> Result<Self, BrowserError> {
        let cancelled_batches =
            u32::try_from(cancelled_batches).map_err(|_| BrowserError::CounterOverflow)?;
        let handoff = Self {
            workspace_id: next.id.clone(),
            from_state: previous.control_state,
            to_state: next.control_state,
            from_generation: previous.lease_generation,
            to_generation: next.lease_generation,
            cancelled_batches,
            workspace_digest: next.digest()?,
        };
        if handoff.workspace_id != previous.id
            || handoff.from_generation == 0
            || handoff.to_generation != handoff.from_generation.saturating_add(1)
            || handoff.from_state == handoff.to_state
        {
            return Err(BrowserError::InvalidControlTransition);
        }
        Ok(handoff)
    }
}

/// Live adapter-side owner of one managed Project/Profile/Mission workspace.
///
/// The durable `BrowserWorkspace` remains the source of truth for CAS and
/// generation history. This coordinator deliberately stores only content-free
/// queue metadata, so an action plan cannot be recovered from a cancelled
/// queue entry after a takeover.
pub struct BrowserWorkspaceControl {
    profile: BrowserProfile,
    workspace: BrowserWorkspace,
    queued_batches: BTreeMap<BrowserActionBatchId, BrowserQueuedBatch>,
}

impl BrowserWorkspaceControl {
    pub fn new(profile: BrowserProfile, workspace: BrowserWorkspace) -> Result<Self, BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        if profile.source != BrowserProfileSource::Managed
            || profile.status != BrowserProfileStatus::Active
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.id != workspace.profile_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
        {
            return Err(BrowserError::ScopeMismatch);
        }
        Ok(Self {
            profile,
            workspace,
            queued_batches: BTreeMap::new(),
        })
    }

    pub fn profile(&self) -> &BrowserProfile {
        &self.profile
    }

    pub fn workspace(&self) -> &BrowserWorkspace {
        &self.workspace
    }

    pub fn agent_lease_proof(&self, now: DateTime<Utc>) -> Result<BrowserLeaseProof, BrowserError> {
        self.workspace.agent_lease_proof(now)
    }

    pub fn queued_batches(&self) -> impl Iterator<Item = &BrowserQueuedBatch> {
        self.queued_batches.values()
    }

    pub fn queued_batch(&self, batch_id: &BrowserActionBatchId) -> Option<&BrowserQueuedBatch> {
        self.queued_batches.get(batch_id)
    }

    /// Admit one exact batch under the current Agent lease.
    ///
    /// The batch digest is retained so a caller cannot replace the plan while
    /// it is queued. A batch id is single-use for this live workspace control,
    /// including after cancellation.
    pub fn enqueue_batch(
        &mut self,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<BrowserQueuedBatch, BrowserError> {
        if self.queued_batches.contains_key(&batch.id) {
            return Err(BrowserError::RealActionRejected);
        }
        batch.validate_for(&self.profile, &self.workspace, now)?;
        let queued = BrowserQueuedBatch {
            batch_id: batch.id.clone(),
            batch_digest: batch.digest()?,
            lease_id: batch.lease.lease_id.clone(),
            lease_generation: batch.lease.generation,
            state: BrowserQueuedBatchState::Queued,
        };
        queued.validate()?;
        self.queued_batches.insert(batch.id.clone(), queued.clone());
        Ok(queued)
    }

    /// Revalidate a queued plan immediately before host dispatch.
    pub fn validate_queued_batch(
        &self,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let queued = self
            .queued_batches
            .get(&batch.id)
            .ok_or(BrowserError::RealActionRejected)?;
        if queued.state != BrowserQueuedBatchState::Queued {
            return Err(BrowserError::ControlLeaseLost);
        }
        batch.validate_for(&self.profile, &self.workspace, now)?;
        if queued.batch_digest != batch.digest()?
            || queued.lease_id != batch.lease.lease_id
            || queued.lease_generation != batch.lease.generation
        {
            return Err(BrowserError::RealActionRejected);
        }
        Ok(())
    }

    /// Remove an exactly validated batch after its host-side cursor reaches a
    /// terminal result. A cancelled or missing batch cannot be acknowledged.
    pub fn complete_batch(
        &mut self,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_queued_batch(batch, now)?;
        self.queued_batches.remove(&batch.id);
        Ok(())
    }

    pub fn takeover_user(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserControlHandoff, BrowserError> {
        self.transition_user(
            expected_revision,
            expected_generation,
            new_lease_id,
            evidence_digest,
            now,
            None,
        )
    }

    /// Fence the live Host before committing the User takeover locally. This
    /// ensures queued host work cannot run even if the caller is racing a
    /// control transition.
    pub fn takeover_user_with_host(
        &mut self,
        host: &mut impl BrowserControlHost,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserControlHandoff, BrowserError> {
        self.transition_user(
            expected_revision,
            expected_generation,
            new_lease_id,
            evidence_digest,
            now,
            Some(host),
        )
    }

    pub fn return_to_agent(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        lease_expires_at: DateTime<Utc>,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserControlHandoff, BrowserError> {
        self.transition_agent(
            expected_revision,
            expected_generation,
            new_lease_id,
            lease_expires_at,
            evidence_digest,
            now,
            None,
        )
    }

    /// Return Agent control only with a fresh lease after the Host has accepted
    /// the successor workspace. Cancelled batches remain tombstoned and can
    /// never be replayed under the new generation.
    #[allow(
        clippy::too_many_arguments,
        reason = "the host handoff API keeps CAS, generation, lease, evidence, expiry, and clock explicit"
    )]
    pub fn return_to_agent_with_host(
        &mut self,
        host: &mut impl BrowserControlHost,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        lease_expires_at: DateTime<Utc>,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserControlHandoff, BrowserError> {
        self.transition_agent(
            expected_revision,
            expected_generation,
            new_lease_id,
            lease_expires_at,
            evidence_digest,
            now,
            Some(host),
        )
    }

    fn transition_user(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        evidence_digest: String,
        now: DateTime<Utc>,
        mut host: Option<&mut dyn BrowserControlHost>,
    ) -> Result<BrowserControlHandoff, BrowserError> {
        let previous = self.workspace.clone();
        let mut next = previous.clone();
        next.user_takeover(
            expected_revision,
            expected_generation,
            new_lease_id,
            evidence_digest,
            now,
        )?;
        if !next.is_valid_successor_of(&previous)? {
            return Err(BrowserError::InvalidControlTransition);
        }
        if let Some(host) = host.as_mut() {
            host.sync_workspace(&next)?;
        }
        let cancelled_batches = self
            .queued_batches
            .values_mut()
            .filter(|queued| queued.state == BrowserQueuedBatchState::Queued)
            .map(|queued| {
                queued.state = BrowserQueuedBatchState::Cancelled;
                1_usize
            })
            .sum();
        let handoff = BrowserControlHandoff::from_transition(&previous, &next, cancelled_batches)?;
        self.workspace = next;
        Ok(handoff)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the internal transition preserves the complete lease transition tuple"
    )]
    fn transition_agent(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        lease_expires_at: DateTime<Utc>,
        evidence_digest: String,
        now: DateTime<Utc>,
        mut host: Option<&mut dyn BrowserControlHost>,
    ) -> Result<BrowserControlHandoff, BrowserError> {
        let previous = self.workspace.clone();
        let mut next = previous.clone();
        next.continue_agent(
            expected_revision,
            expected_generation,
            new_lease_id,
            lease_expires_at,
            evidence_digest,
            now,
        )?;
        if !next.is_valid_successor_of(&previous)? {
            return Err(BrowserError::InvalidControlTransition);
        }
        if let Some(host) = host.as_mut() {
            host.sync_workspace(&next)?;
        }
        let handoff = BrowserControlHandoff::from_transition(&previous, &next, 0)?;
        self.workspace = next;
        Ok(handoff)
    }
}

impl fmt::Debug for BrowserWorkspaceControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserWorkspaceControl")
            .field("profile_id", &self.profile.id)
            .field("workspace_id", &self.workspace.id)
            .field("workspace_generation", &self.workspace.lease_generation)
            .field("control_state", &self.workspace.control_state)
            .field("queued_batch_count", &self.queued_batches.len())
            .finish()
    }
}

fn is_bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserActionBatchId, BrowserControlLeaseId, BrowserProfileId, BrowserTabId,
        BrowserWorkspaceId, Mission, MissionContract, MissionId, Project, ProjectId, StorageMode,
        TenantId,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        BrowserAction, BrowserActionBatch, BrowserActionKind, BrowserActionRisk,
        BrowserActionSurface, BrowserIdentity,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 16, 0, 0)
            .single()
            .expect("valid fixture time")
    }

    fn sha(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn fixture() -> (BrowserProfile, BrowserWorkspace, DateTime<Utc>) {
        let now = now();
        let project_root = TempDir::new().expect("project root");
        let project = Project::create_local(
            TenantId::from("tenant-control"),
            ProjectId::from("project-control"),
            "Browser Control",
            "",
            project_root.path().to_str().expect("UTF-8 project root"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-control"),
            project.id.clone(),
            "Observe a managed browser",
            MissionContract::bootstrap("Observe a managed browser", ["browser.read".into()], now),
            now,
        )
        .expect("mission");
        let identity = BrowserIdentity::new(
            "browser-workspace",
            AccountId::from("account-control"),
            sha('a'),
            sha('b'),
            now,
        )
        .expect("identity");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-control"),
            &project,
            "keyring://browser/control",
            identity,
            now,
        )
        .expect("managed profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-control"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-control"),
            BrowserControlLeaseId::from("lease-control-1"),
            now + Duration::hours(1),
            sha('c'),
            now,
        )
        .expect("workspace");
        (profile, workspace, now)
    }

    fn observe_batch(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        now: DateTime<Utc>,
        id: &str,
    ) -> BrowserActionBatch {
        BrowserActionBatch::read_only(
            BrowserActionBatchId::from(id),
            profile,
            workspace,
            workspace.agent_lease_proof(now).expect("lease"),
            sha('d'),
            vec![BrowserAction {
                sequence: 1,
                kind: BrowserActionKind::Observe,
                surface: BrowserActionSurface::Semantic,
                risk: BrowserActionRisk::ReadOnly,
                tab_id: BrowserTabId::from("tab-control"),
                snapshot_id: None,
                element_ref: None,
                target_origin_digest: sha('e'),
                payload_digest: sha('f'),
            }],
            now,
            now + Duration::minutes(5),
        )
        .expect("read-only batch")
    }

    #[test]
    fn constructor_requires_exact_managed_project_profile_mission_scope() {
        let (profile, workspace, _) = fixture();
        let control = BrowserWorkspaceControl::new(profile.clone(), workspace.clone())
            .expect("exact managed scope");
        assert_eq!(control.profile().id, profile.id);
        assert_eq!(control.workspace().mission_id, workspace.mission_id);

        let mut imported = profile;
        imported.source = BrowserProfileSource::ImportedCopy;
        assert_eq!(
            BrowserWorkspaceControl::new(imported, workspace)
                .expect_err("imported profiles cannot own a live control")
                .code(),
            "BROWSER_SCOPE_MISMATCH"
        );
    }

    #[test]
    fn takeover_cancels_queued_batches_and_return_uses_a_new_generation() {
        let (profile, workspace, now) = fixture();
        let mut control = BrowserWorkspaceControl::new(profile, workspace).expect("control");
        let batch = observe_batch(control.profile(), control.workspace(), now, "batch-control");
        let queued = control
            .enqueue_batch(&batch, now)
            .expect("queue under current Agent lease");
        assert_eq!(queued.state, BrowserQueuedBatchState::Queued);

        let first_handoff = control
            .takeover_user(
                control.workspace().revision,
                control.workspace().lease_generation,
                BrowserControlLeaseId::from("lease-control-user"),
                sha('1'),
                now + Duration::seconds(1),
            )
            .expect("User takeover");
        assert_eq!(first_handoff.from_generation, 1);
        assert_eq!(first_handoff.to_generation, 2);
        assert_eq!(first_handoff.cancelled_batches, 1);
        assert_eq!(
            control.queued_batch(&batch.id).expect("tombstone").state,
            BrowserQueuedBatchState::Cancelled
        );
        assert_eq!(
            control
                .validate_queued_batch(&batch, now + Duration::seconds(1))
                .expect_err("cancelled batch cannot dispatch")
                .code(),
            "BROWSER_CONTROL_LEASE_LOST"
        );

        let second_handoff = control
            .return_to_agent(
                control.workspace().revision,
                control.workspace().lease_generation,
                BrowserControlLeaseId::from("lease-control-agent-2"),
                now + Duration::hours(2),
                sha('2'),
                now + Duration::seconds(2),
            )
            .expect("return to Agent");
        assert_eq!(second_handoff.from_generation, 2);
        assert_eq!(second_handoff.to_generation, 3);
        assert_eq!(
            control.workspace().control_state,
            BrowserControlState::AgentControlled
        );
        assert_eq!(
            control
                .agent_lease_proof(now + Duration::seconds(2))
                .expect("fresh proof")
                .generation,
            3
        );
        assert_eq!(
            control
                .enqueue_batch(&batch, now + Duration::seconds(2))
                .expect_err("old batch id is single-use")
                .code(),
            "BROWSER_REAL_ACTION_REJECTED"
        );
    }

    #[test]
    fn tampered_batch_and_stale_transition_fail_without_state_mutation() {
        let (profile, workspace, now) = fixture();
        let mut control = BrowserWorkspaceControl::new(profile, workspace).expect("control");
        let batch = observe_batch(control.profile(), control.workspace(), now, "batch-tamper");
        control.enqueue_batch(&batch, now).expect("queue");
        let before = control.workspace().clone();
        let mut tampered = batch.clone();
        tampered.policy_digest = sha('9');
        assert_eq!(
            control
                .validate_queued_batch(&tampered, now)
                .expect_err("tampered plan")
                .code(),
            "BROWSER_REAL_ACTION_REJECTED"
        );
        assert_eq!(&before, control.workspace());
        assert_eq!(
            control
                .takeover_user(
                    before.revision.saturating_sub(1),
                    before.lease_generation,
                    BrowserControlLeaseId::from("lease-control-invalid"),
                    sha('3'),
                    now + Duration::seconds(1),
                )
                .expect_err("stale CAS")
                .code(),
            "BROWSER_REVISION_MISMATCH"
        );
        assert_eq!(&before, control.workspace());
        assert_eq!(
            control
                .queued_batch(&batch.id)
                .expect("queue remains")
                .state,
            BrowserQueuedBatchState::Queued
        );
    }

    #[test]
    fn debug_is_content_free_and_does_not_expose_queue_payload() {
        let (profile, workspace, now) = fixture();
        let mut control = BrowserWorkspaceControl::new(profile, workspace).expect("control");
        let batch = observe_batch(control.profile(), control.workspace(), now, "batch-debug");
        control.enqueue_batch(&batch, now).expect("queue");
        let debug = format!("{control:?}");
        assert!(debug.contains("queued_batch_count"));
        assert!(!debug.contains(&batch.plan_digest));
        assert!(!debug.contains("keyring://"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires HARTEVO_TEST_CHROME_BINARY and launches a real managed Chromium process"]
    fn real_chromium_control_takeover_return_smoke() {
        use std::os::unix::fs::PermissionsExt;

        let executable = std::env::var_os("HARTEVO_TEST_CHROME_BINARY").map_or_else(
            || panic!("BLOCKED_ENV: HARTEVO_TEST_CHROME_BINARY is required"),
            std::path::PathBuf::from,
        );
        let (profile, workspace, now) = fixture();
        let temp = TempDir::new().expect("profile root");
        let profile_root = temp.path().join("profiles");
        std::fs::create_dir(&profile_root).expect("profile root directory");
        std::fs::set_permissions(&profile_root, std::fs::Permissions::from_mode(0o700))
            .expect("private profile root");
        let config = crate::ChromiumLaunchConfig::new(&executable, profile_root, true)
            .expect("launch config")
            .with_macos_mock_keychain_for_test()
            .expect("explicit mock keychain");
        let mut host =
            crate::ManagedChromiumHost::spawn(profile.clone(), workspace.clone(), &config)
                .expect("managed Chromium");
        let mut control = BrowserWorkspaceControl::new(profile, workspace).expect("control");
        let takeover = control
            .takeover_user_with_host(
                &mut host,
                control.workspace().revision,
                control.workspace().lease_generation,
                BrowserControlLeaseId::from("lease-control-real-user"),
                sha('4'),
                now + Duration::seconds(1),
            )
            .expect("User takeover");
        assert_eq!(takeover.to_state, BrowserControlState::UserControlled);
        let returned = control
            .return_to_agent_with_host(
                &mut host,
                control.workspace().revision,
                control.workspace().lease_generation,
                BrowserControlLeaseId::from("lease-control-real-agent"),
                now + Duration::hours(1),
                sha('5'),
                now + Duration::seconds(2),
            )
            .expect("return to Agent");
        assert_eq!(returned.to_generation, takeover.to_generation + 1);
    }
}

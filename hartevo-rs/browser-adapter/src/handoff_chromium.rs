//! Managed Chromium transport for the Browser Workspace handoff contract.
//!
//! The generic handoff provider owns the control lease and all redacted
//! receipts. This façade binds that provider to a real `ManagedChromiumHost`
//! without exposing a second browser authority or any page/cookie material.

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::Mission;

use crate::{
    BrowserError, BrowserHandoffHost, BrowserHandoffLog, BrowserHandoffServiceDefinition,
    BrowserLeaseProof, BrowserProfile, BrowserResumeReceipt, BrowserTakeoverOffer,
    BrowserTakeoverReceipt, BrowserWorkspace, BrowserWorkspaceHandoffProvider,
    MissionBrowserHandoffConsumer,
};

#[cfg(unix)]
use crate::ManagedChromiumHost;

/// Mission-scoped Browser Workspace handoff service.
///
/// All lifecycle mutations are delegated to the existing consumer/provider
/// pair. The service deliberately exposes only typed offers, receipts, lease
/// proofs, and the content-free durable log; it never exposes CDP commands or
/// browser credentials.
pub struct BrowserWorkspaceHandoffService {
    consumer: MissionBrowserHandoffConsumer,
}

impl fmt::Debug for BrowserWorkspaceHandoffService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserWorkspaceHandoffService")
            .field("consumer", &self.consumer)
            .finish()
    }
}

impl BrowserWorkspaceHandoffService {
    pub fn new(mission: &Mission) -> Result<Self, BrowserError> {
        Ok(Self {
            consumer: MissionBrowserHandoffConsumer::new(mission)?,
        })
    }

    pub fn select_profile(
        &mut self,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
    ) -> Result<(), BrowserError> {
        self.consumer.select_profile(profile, workspace)
    }

    pub fn mount(
        &mut self,
        definition: BrowserHandoffServiceDefinition,
        host: Box<dyn BrowserHandoffHost>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.consumer.mount(definition, host, now)
    }

    /// Mount the authenticated managed Chromium CDP/window transport. The
    /// concrete host is consumed by the provider and cannot be reused after a
    /// crash, close, or revoke.
    #[cfg(unix)]
    pub fn mount_managed_chromium(
        &mut self,
        definition: BrowserHandoffServiceDefinition,
        host: ManagedChromiumHost,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.mount(definition, Box::new(host), now)
    }

    pub fn request_takeover_offer(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<BrowserTakeoverOffer, BrowserError> {
        self.consumer.request_takeover_offer(now)
    }

    pub fn authorize_agent_dispatch(
        &self,
        proof: &BrowserLeaseProof,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.consumer.authorize_agent_dispatch(proof, now)
    }

    pub fn takeover(
        &mut self,
        offer: &BrowserTakeoverOffer,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserTakeoverReceipt, BrowserError> {
        self.consumer.takeover(offer, evidence_digest, now)
    }

    pub fn prepare_resume_receipt(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserResumeReceipt, BrowserError> {
        self.consumer.prepare_resume_receipt(evidence_digest, now)
    }

    pub fn resume_agent(
        &mut self,
        receipt: &BrowserResumeReceipt,
        lease_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.consumer.resume_agent(receipt, lease_expires_at, now)
    }

    pub fn mark_host_crashed(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.consumer.mark_host_crashed(evidence_digest, now)
    }

    pub fn close(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.consumer.close(evidence_digest, now)
    }

    pub fn state(&self) -> crate::BrowserHandoffConsumerState {
        self.consumer.state()
    }

    pub fn selected_workspace(&self) -> Option<&BrowserWorkspace> {
        self.consumer.selected_workspace()
    }

    pub fn provider(&self) -> Option<&BrowserWorkspaceHandoffProvider> {
        self.consumer.provider()
    }

    /// The returned value is a typed, content-free journal suitable for
    /// durable Mission storage. It contains only scope, digests, revisions,
    /// generations, and timestamps—not cookies, passwords, or page content.
    pub fn durable_log(&self) -> Option<&BrowserHandoffLog> {
        self.consumer.log()
    }

    pub fn consumer(&self) -> &MissionBrowserHandoffConsumer {
        &self.consumer
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, BrowserSnapshotId, BrowserTabId,
        BrowserWorkspaceId, MissionContract, Project, ProjectId, StorageMode, TenantId,
    };
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::handoff::BrowserHandoffSnapshotInput;
    use crate::{
        BrowserControlState, BrowserHandoffFrameBinding, BrowserHandoffScope,
        BrowserHandoffSnapshot, BrowserIdentity, BrowserProfile, BrowserWorkspace,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture() -> (
        Mission,
        BrowserProfile,
        BrowserWorkspace,
        BrowserHandoffServiceDefinition,
    ) {
        let current = now();
        let project = Project::create_local(
            TenantId::from("tenant-handoff-transport"),
            ProjectId::from("project-handoff-transport"),
            "Handoff transport",
            "",
            "/tmp/handoff-transport",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            hartevo_domain_kernel::MissionId::from("mission-handoff-transport"),
            project.id.clone(),
            "Handoff transport",
            MissionContract::bootstrap("handoff transport", ["browser.read".into()], current),
            current,
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-handoff-transport"),
            &project,
            "credential-manager://handoff-transport",
            BrowserIdentity::new(
                "provider-handoff-transport",
                AccountId::from("account-handoff-transport"),
                sha('1'),
                sha('2'),
                current,
            )
            .expect("identity"),
            current,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-handoff-transport"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-handoff-transport"),
            BrowserControlLeaseId::from("lease-handoff-transport-1"),
            current + Duration::hours(1),
            sha('4'),
            current,
        )
        .expect("workspace");
        let definition = BrowserHandoffServiceDefinition::authenticated("handoff-transport")
            .expect("definition");
        (mission, profile, workspace, definition)
    }

    #[derive(Clone)]
    struct FakeTransport {
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        frame_id: String,
        loader_id: String,
        url: String,
        next_snapshot: u64,
        takeover_fences: Rc<RefCell<u32>>,
        resume_fences: Rc<RefCell<u32>>,
        fail_takeover: bool,
        fail_resume: bool,
    }

    impl FakeTransport {
        fn new(profile: BrowserProfile, workspace: BrowserWorkspace) -> Self {
            Self {
                profile,
                workspace,
                frame_id: "root-frame".into(),
                loader_id: "loader-1".into(),
                url: "https://example.test/login".into(),
                next_snapshot: 0,
                takeover_fences: Rc::new(RefCell::new(0)),
                resume_fences: Rc::new(RefCell::new(0)),
                fail_takeover: false,
                fail_resume: false,
            }
        }

        fn snapshot(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            now: DateTime<Utc>,
        ) -> Result<BrowserHandoffSnapshot, BrowserError> {
            if profile.id != self.profile.id
                || profile.revision != self.profile.revision
                || workspace.id != self.workspace.id
                || workspace.revision != self.workspace.revision
                || workspace.lease_generation != self.workspace.lease_generation
                || workspace.control_state != self.workspace.control_state
            {
                return Err(BrowserError::ScopeMismatch);
            }
            self.next_snapshot = self.next_snapshot.saturating_add(1);
            let scope = BrowserHandoffScope::bind(profile, workspace)?;
            let frame = BrowserHandoffFrameBinding::from_verified(
                workspace.active_tab_id.clone(),
                "session-handoff-transport",
                &self.frame_id,
                &self.loader_id,
                &self.url,
                1,
            )?;
            BrowserHandoffSnapshot::from_verified(BrowserHandoffSnapshotInput {
                snapshot_id: BrowserSnapshotId::from_stable(format!(
                    "transport-snapshot-{}",
                    self.next_snapshot
                )),
                scope,
                frame,
                profile_revision: profile.revision,
                workspace_revision: workspace.revision,
                lease_generation: workspace.lease_generation,
                control_state: workspace.control_state,
                observed_at: now,
            })
        }
    }

    impl BrowserHandoffHost for FakeTransport {
        fn observe_handoff_snapshot(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            now: DateTime<Utc>,
        ) -> Result<BrowserHandoffSnapshot, BrowserError> {
            self.snapshot(profile, workspace, now)
        }

        fn fence_for_takeover(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            frame: &BrowserHandoffFrameBinding,
            now: DateTime<Utc>,
        ) -> Result<(), BrowserError> {
            *self.takeover_fences.borrow_mut() += 1;
            if self.fail_takeover {
                return Err(BrowserError::HandoffHostUnavailable);
            }
            let snapshot = self.snapshot(profile, workspace, now)?;
            if snapshot.control_state != BrowserControlState::AgentControlled
                || snapshot.frame != *frame
            {
                return Err(BrowserError::StaleSnapshot);
            }
            Ok(())
        }

        fn fence_for_resume(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            frame: &BrowserHandoffFrameBinding,
            now: DateTime<Utc>,
        ) -> Result<(), BrowserError> {
            *self.resume_fences.borrow_mut() += 1;
            if self.fail_resume {
                return Err(BrowserError::HandoffHostUnavailable);
            }
            let snapshot = self.snapshot(profile, workspace, now)?;
            if snapshot.control_state != BrowserControlState::UserControlled
                || snapshot.frame != *frame
            {
                return Err(BrowserError::StaleSnapshot);
            }
            Ok(())
        }

        fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
            if !workspace.is_valid_successor_of(&self.workspace)? {
                return Err(BrowserError::ScopeMismatch);
            }
            self.workspace = workspace.clone();
            Ok(())
        }
    }

    #[test]
    fn service_fences_before_takeover_and_resume_and_rejects_replay() {
        let (mission, profile, workspace, definition) = fixture();
        let mut service = BrowserWorkspaceHandoffService::new(&mission).expect("service");
        service
            .select_profile(profile.clone(), workspace.clone())
            .expect("select");
        let transport = FakeTransport::new(profile, workspace.clone());
        let takeover_fences = transport.takeover_fences.clone();
        let resume_fences = transport.resume_fences.clone();
        service
            .mount(definition, Box::new(transport), now())
            .expect("mount");
        let old_proof = workspace.agent_lease_proof(now()).expect("old proof");
        let offer = service
            .request_takeover_offer(now() + Duration::seconds(1))
            .expect("offer");
        let takeover = service
            .takeover(&offer, sha('5'), now() + Duration::seconds(2))
            .expect("takeover");
        assert_eq!(*takeover_fences.borrow(), 1);
        assert!(matches!(
            service.authorize_agent_dispatch(&old_proof, now() + Duration::seconds(3)),
            Err(BrowserError::ControlLeaseLost)
        ));
        let resume = service
            .prepare_resume_receipt(sha('6'), now() + Duration::seconds(4))
            .expect("resume receipt");
        service
            .resume_agent(
                &resume,
                now() + Duration::minutes(10),
                now() + Duration::seconds(5),
            )
            .expect("resume");
        assert_eq!(*resume_fences.borrow(), 1);
        assert!(matches!(
            service.resume_agent(
                &resume,
                now() + Duration::minutes(10),
                now() + Duration::seconds(6),
            ),
            Err(BrowserError::InvalidHandoffReceipt)
        ));
        let serialized =
            serde_json::to_string(service.durable_log().expect("log")).expect("log json");
        assert!(!serialized.contains("cookie"));
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("page content"));
        let recovered =
            BrowserHandoffLog::restore(serde_json::from_str(&serialized).expect("recovered log"))
                .expect("log valid");
        assert_eq!(
            recovered.digest().expect("recovered digest"),
            service
                .durable_log()
                .expect("log")
                .digest()
                .expect("log digest")
        );
        assert_eq!(
            service.state(),
            crate::BrowserHandoffConsumerState::AgentResumed
        );
        let _ = takeover;
    }

    #[test]
    fn fence_failure_fails_closed_without_transition_or_log() {
        let (mission, profile, workspace, definition) = fixture();
        let mut service = BrowserWorkspaceHandoffService::new(&mission).expect("service");
        service
            .select_profile(profile.clone(), workspace.clone())
            .expect("select");
        let mut transport = FakeTransport::new(profile, workspace);
        transport.fail_takeover = true;
        service
            .mount(definition, Box::new(transport), now())
            .expect("mount");
        let offer = service
            .request_takeover_offer(now() + Duration::seconds(1))
            .expect("offer");
        assert!(matches!(
            service.takeover(&offer, sha('7'), now() + Duration::seconds(2)),
            Err(BrowserError::HandoffHostUnavailable)
        ));
        assert_eq!(service.state(), crate::BrowserHandoffConsumerState::Crashed);
        assert!(
            service
                .durable_log()
                .is_none_or(|log| log.events.is_empty())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires HARTEVO_TEST_CHROME_BINARY and visible window environment"]
    fn real_managed_chromium_handoff_resume_smoke() {
        let _ = std::env::var_os("HARTEVO_TEST_CHROME_BINARY")
            .expect("BLOCKED_ENV: HARTEVO_TEST_CHROME_BINARY is required");
        panic!("BLOCKED_ENV: real handoff fixture URL is not configured");
    }
}

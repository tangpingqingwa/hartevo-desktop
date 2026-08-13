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

    #[cfg(target_os = "macos")]
    use std::fs;
    #[cfg(target_os = "macos")]
    use std::io::{Read, Write};
    #[cfg(target_os = "macos")]
    use std::net::{SocketAddr, TcpListener, TcpStream};
    #[cfg(target_os = "macos")]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(target_os = "macos")]
    use std::path::PathBuf;
    #[cfg(target_os = "macos")]
    use std::sync::Arc;
    #[cfg(target_os = "macos")]
    use std::sync::atomic::{AtomicBool, Ordering};
    #[cfg(target_os = "macos")]
    use std::thread::{self, JoinHandle};
    #[cfg(target_os = "macos")]
    use std::time::Duration as StdDuration;
    #[cfg(target_os = "macos")]
    use tempfile::TempDir;

    use crate::handoff::BrowserHandoffSnapshotInput;
    #[cfg(target_os = "macos")]
    use crate::{
        BrowserControlHost, BrowserNavigationPolicy, ChromiumLaunchConfig, ManagedChromiumHost,
    };
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

    #[cfg(target_os = "macos")]
    struct SharedManagedHandoffHost(Rc<RefCell<ManagedChromiumHost>>);

    #[cfg(target_os = "macos")]
    impl BrowserHandoffHost for SharedManagedHandoffHost {
        fn observe_handoff_snapshot(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            now: DateTime<Utc>,
        ) -> Result<BrowserHandoffSnapshot, BrowserError> {
            self.0
                .borrow_mut()
                .observe_handoff_snapshot(profile, workspace, now)
        }

        fn fence_for_takeover(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            frame: &BrowserHandoffFrameBinding,
            now: DateTime<Utc>,
        ) -> Result<(), BrowserError> {
            self.0
                .borrow_mut()
                .fence_for_takeover(profile, workspace, frame, now)
        }

        fn fence_for_resume(
            &mut self,
            profile: &BrowserProfile,
            workspace: &BrowserWorkspace,
            frame: &BrowserHandoffFrameBinding,
            now: DateTime<Utc>,
        ) -> Result<(), BrowserError> {
            self.0
                .borrow_mut()
                .fence_for_resume(profile, workspace, frame, now)
        }

        fn sync_workspace(&mut self, workspace: &BrowserWorkspace) -> Result<(), BrowserError> {
            BrowserControlHost::sync_workspace(&mut *self.0.borrow_mut(), workspace)
        }
    }

    #[cfg(target_os = "macos")]
    struct LocalHttpServer {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    #[cfg(target_os = "macos")]
    impl LocalHttpServer {
        fn start() -> std::io::Result<Self> {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread = thread::Builder::new()
                .name("hartevo-handoff-http-test".to_owned())
                .spawn(move || {
                    while !thread_stop.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                let _ = serve_http_connection(stream);
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(StdDuration::from_millis(5));
                            }
                            Err(_) => return,
                        }
                    }
                })?;
            Ok(Self {
                address,
                stop,
                thread: Some(thread),
            })
        }

        fn origin(&self) -> String {
            format!("http://{}", self.address)
        }

        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.origin())
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for LocalHttpServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn serve_http_connection(mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(StdDuration::from_secs(2)))?;
        let mut request = [0_u8; 8 * 1_024];
        let byte_count = stream.read(&mut request)?;
        let request = String::from_utf8_lossy(&request[..byte_count]);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");
        let body = match path {
            "/changed" => "<html><body><h1>changed</h1></body></html>",
            _ => "<html><body><h1>managed handoff</h1></body></html>",
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()
    }

    #[cfg(target_os = "macos")]
    fn spawn_real_shared_host(
        executable: &std::path::Path,
        profile_root: PathBuf,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        now: DateTime<Utc>,
    ) -> Rc<RefCell<ManagedChromiumHost>> {
        let config = ChromiumLaunchConfig::new(executable, profile_root, false)
            .expect("CODE_FAILURE: visible managed Chromium launch config");
        let proof = workspace
            .agent_lease_proof(now)
            .expect("CODE_FAILURE: real handoff fixture lease");
        let tab_id = workspace.active_tab_id.clone();
        let mut host = ManagedChromiumHost::spawn(profile, workspace, &config)
            .expect("CODE_FAILURE: spawn managed Chromium");
        host.attach_about_blank_tab(&tab_id, &proof, now)
            .expect("CODE_FAILURE: attach managed Chromium tab");
        Rc::new(RefCell::new(host))
    }

    #[cfg(target_os = "macos")]
    fn prepare_real_page(
        shared: &Rc<RefCell<ManagedChromiumHost>>,
        workspace: &BrowserWorkspace,
        server: &LocalHttpServer,
        path: &str,
        now: DateTime<Utc>,
    ) {
        let policy = BrowserNavigationPolicy::with_loopback_http_for_test([server.origin()])
            .expect("CODE_FAILURE: loopback exact-origin policy");
        let target = policy
            .authorize(server.url(path))
            .expect("CODE_FAILURE: loopback navigation target");
        let proof = workspace
            .agent_lease_proof(now)
            .expect("CODE_FAILURE: real page lease");
        shared
            .borrow_mut()
            .navigate_allowlisted(&workspace.active_tab_id, &proof, &policy, &target, now)
            .expect("CODE_FAILURE: real managed navigation");
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
    fn real_profile_root(temp: &TempDir, name: &str) -> PathBuf {
        let root = temp.path().join(name);
        fs::create_dir(&root).expect("CODE_FAILURE: real profile root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("CODE_FAILURE: real profile permissions");
        root
    }

    #[cfg(target_os = "macos")]
    fn run_real_positive(executable: &std::path::Path, server: &LocalHttpServer, temp: &TempDir) {
        let (mission, profile, workspace, definition) = fixture();
        let at = now();
        let shared = spawn_real_shared_host(
            executable,
            real_profile_root(temp, "positive-profile"),
            profile.clone(),
            workspace.clone(),
            at + Duration::seconds(1),
        );
        prepare_real_page(
            &shared,
            &workspace,
            server,
            "/page",
            at + Duration::seconds(2),
        );
        let mut service = BrowserWorkspaceHandoffService::new(&mission)
            .expect("CODE_FAILURE: positive handoff service");
        service
            .select_profile(profile.clone(), workspace.clone())
            .expect("CODE_FAILURE: positive profile selection");
        service
            .mount(
                definition,
                Box::new(SharedManagedHandoffHost(shared.clone())),
                at + Duration::seconds(3),
            )
            .expect("CODE_FAILURE: positive managed handoff mount");
        let old_proof = workspace
            .agent_lease_proof(at + Duration::seconds(3))
            .expect("CODE_FAILURE: positive old lease");
        let offer = service
            .request_takeover_offer(at + Duration::seconds(4))
            .expect("CODE_FAILURE: positive offer");
        let takeover = service
            .takeover(&offer, sha('5'), at + Duration::seconds(5))
            .expect("CODE_FAILURE: positive takeover");
        assert_eq!(takeover.frame.tab_id, workspace.active_tab_id);
        assert_eq!(takeover.frame, offer.frame);
        assert_eq!(takeover.profile_revision, profile.revision);
        assert!(matches!(
            service.authorize_agent_dispatch(&old_proof, at + Duration::seconds(6)),
            Err(BrowserError::ControlLeaseLost)
        ));
        let resume = service
            .prepare_resume_receipt(sha('6'), at + Duration::seconds(7))
            .expect("CODE_FAILURE: positive resume receipt");
        assert_eq!(resume.frame, takeover.frame);
        assert_ne!(resume.snapshot_digest, takeover.pre_snapshot_digest);
        service
            .resume_agent(
                &resume,
                at + Duration::minutes(10),
                at + Duration::seconds(8),
            )
            .expect("CODE_FAILURE: positive explicit resume");
        let fresh_proof = service
            .provider()
            .expect("positive provider")
            .agent_lease_proof(at + Duration::seconds(9))
            .expect("CODE_FAILURE: fresh resumed lease");
        service
            .authorize_agent_dispatch(&fresh_proof, at + Duration::seconds(9))
            .expect("CODE_FAILURE: fresh continuation");
        let log = service.durable_log().expect("positive durable log");
        assert_eq!(log.events.len(), 2);
        log.validate()
            .expect("CODE_FAILURE: durable log validation");
        let log_json = serde_json::to_string(log).expect("CODE_FAILURE: durable log encoding");
        let receipt_json = serde_json::to_string(&resume).expect("CODE_FAILURE: receipt encoding");
        assert!(!log_json.contains("cookie"));
        assert!(!log_json.contains("password"));
        assert!(!receipt_json.contains("cookie"));
        assert!(!receipt_json.contains("password"));
        service
            .close(sha('7'), at + Duration::seconds(10))
            .expect("CODE_FAILURE: positive handoff close");
    }

    #[cfg(target_os = "macos")]
    fn run_real_navigation_negative(
        executable: &std::path::Path,
        server: &LocalHttpServer,
        temp: &TempDir,
    ) {
        let (mission, profile, workspace, definition) = fixture();
        let at = now();
        let shared = spawn_real_shared_host(
            executable,
            real_profile_root(temp, "navigation-profile"),
            profile.clone(),
            workspace.clone(),
            at + Duration::seconds(11),
        );
        prepare_real_page(
            &shared,
            &workspace,
            server,
            "/page",
            at + Duration::seconds(12),
        );
        let mut service = BrowserWorkspaceHandoffService::new(&mission)
            .expect("CODE_FAILURE: navigation handoff service");
        service
            .select_profile(profile, workspace.clone())
            .expect("CODE_FAILURE: navigation profile selection");
        service
            .mount(
                definition,
                Box::new(SharedManagedHandoffHost(shared.clone())),
                at + Duration::seconds(13),
            )
            .expect("CODE_FAILURE: navigation mount");
        let offer = service
            .request_takeover_offer(at + Duration::seconds(14))
            .expect("CODE_FAILURE: navigation offer");
        prepare_real_page(
            &shared,
            &workspace,
            server,
            "/changed",
            at + Duration::seconds(15),
        );
        let error = service
            .takeover(&offer, sha('8'), at + Duration::seconds(16))
            .expect_err("navigation drift must reject takeover");
        assert!(matches!(
            error,
            BrowserError::InvalidHandoffOffer | BrowserError::StaleSnapshot
        ));
        assert_eq!(
            service.state(),
            crate::BrowserHandoffConsumerState::AgentMounted
        );
        assert!(
            service
                .durable_log()
                .expect("navigation log")
                .events
                .is_empty()
        );
        service
            .close(sha('9'), at + Duration::seconds(17))
            .expect("CODE_FAILURE: navigation close");
    }

    #[cfg(target_os = "macos")]
    fn run_real_new_tab_negative(
        executable: &std::path::Path,
        server: &LocalHttpServer,
        temp: &TempDir,
    ) {
        let (mission, profile, workspace, definition) = fixture();
        let at = now();
        let shared = spawn_real_shared_host(
            executable,
            real_profile_root(temp, "new-tab-profile"),
            profile.clone(),
            workspace.clone(),
            at + Duration::seconds(18),
        );
        prepare_real_page(
            &shared,
            &workspace,
            server,
            "/page",
            at + Duration::seconds(19),
        );
        let mut service = BrowserWorkspaceHandoffService::new(&mission)
            .expect("CODE_FAILURE: new-tab handoff service");
        service
            .select_profile(profile, workspace.clone())
            .expect("CODE_FAILURE: new-tab profile selection");
        service
            .mount(
                definition,
                Box::new(SharedManagedHandoffHost(shared.clone())),
                at + Duration::seconds(20),
            )
            .expect("CODE_FAILURE: new-tab mount");
        let offer = service
            .request_takeover_offer(at + Duration::seconds(21))
            .expect("CODE_FAILURE: new-tab offer");
        shared
            .borrow_mut()
            .test_create_unmanaged_tab()
            .expect("CODE_FAILURE: create unmanaged target");
        let error = service
            .takeover(&offer, sha('a'), at + Duration::seconds(22))
            .expect_err("new tab must fail closed");
        assert!(matches!(error, BrowserError::StaleSnapshot));
        assert_eq!(service.state(), crate::BrowserHandoffConsumerState::Crashed);
        assert!(
            service
                .durable_log()
                .expect("new-tab log")
                .events
                .is_empty()
        );
    }

    #[cfg(target_os = "macos")]
    fn run_real_crash_negative(
        executable: &std::path::Path,
        server: &LocalHttpServer,
        temp: &TempDir,
    ) {
        let (mission, profile, workspace, definition) = fixture();
        let at = now();
        let shared = spawn_real_shared_host(
            executable,
            real_profile_root(temp, "crash-profile"),
            profile.clone(),
            workspace.clone(),
            at + Duration::seconds(23),
        );
        prepare_real_page(
            &shared,
            &workspace,
            server,
            "/page",
            at + Duration::seconds(24),
        );
        let mut service = BrowserWorkspaceHandoffService::new(&mission)
            .expect("CODE_FAILURE: crash handoff service");
        service
            .select_profile(profile, workspace.clone())
            .expect("CODE_FAILURE: crash profile selection");
        service
            .mount(
                definition,
                Box::new(SharedManagedHandoffHost(shared.clone())),
                at + Duration::seconds(25),
            )
            .expect("CODE_FAILURE: crash handoff mount");
        let offer = service
            .request_takeover_offer(at + Duration::seconds(26))
            .expect("CODE_FAILURE: crash offer");
        shared
            .borrow_mut()
            .test_terminate_process()
            .expect("CODE_FAILURE: terminate managed Chromium");
        let error = service
            .takeover(&offer, sha('b'), at + Duration::seconds(27))
            .expect_err("crashed host must fail closed");
        assert!(matches!(
            error,
            BrowserError::HostExited
                | BrowserError::Io(_)
                | BrowserError::ProtocolTimeout
                | BrowserError::ProtocolPoisoned
                | BrowserError::HandoffHostUnavailable
        ));
        assert_eq!(service.state(), crate::BrowserHandoffConsumerState::Crashed);
        assert!(service.durable_log().expect("crash log").events.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "BLOCKED_ENV: requires HARTEVO_TEST_CHROME_BINARY and visible window environment"]
    fn real_managed_chromium_handoff_resume_smoke() {
        let executable = std::env::var_os("HARTEVO_TEST_CHROME_BINARY")
            .map(PathBuf::from)
            .expect("BLOCKED_ENV: HARTEVO_TEST_CHROME_BINARY is required");
        assert!(
            executable.is_file(),
            "CODE_FAILURE: HARTEVO_TEST_CHROME_BINARY is not a regular file"
        );
        let server = LocalHttpServer::start().expect("CODE_FAILURE: local HTTP fixture");
        let temp = TempDir::new().expect("CODE_FAILURE: temporary handoff root");
        run_real_positive(&executable, &server, &temp);
        run_real_navigation_negative(&executable, &server, &temp);
        run_real_new_tab_negative(&executable, &server, &temp);
        run_real_crash_negative(&executable, &server, &temp);
    }
}
